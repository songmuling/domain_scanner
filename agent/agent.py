#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Agent - 分布式扫描集群客户端 (Nezha Agent 风格)
- 启动后向 Master 自动注册 (携带 Token 握手)
- 定时上报心跳、节点状态与扫描进度
- 接收 Master 下发的扫描指令 (START / STOP)
- 纯 Python 3 标准库打造，零外部依赖
"""

import os
import sys
import time
import json
import socket
import platform
import argparse
import urllib.request
import urllib.error
import threading
import queue
import signal
import uuid

# 客户端统一时间戳构建版本号 (yy.mmdd.hhmm 格式)
AGENT_VERSION = "26.1110.2240"

# 引入核心扫描器引擎 (优先同目录 scanner.py，保证 agent 独立自包含)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

def get_or_create_agent_uuid():
    """
    获取或持久化生成当前 Agent 的全局唯一机器物理指纹 (UUID)
    保存在 agent 同级目录下的 .agent_uuid 隐藏文件中，确保机器重启后身份永久固定
    """
    uuid_file = os.path.join(SCRIPT_DIR, ".agent_uuid")
    if os.path.exists(uuid_file):
        try:
            with open(uuid_file, "r", encoding="utf-8") as f:
                u = f.read().strip()
                if u and len(u) >= 8:
                    return u
        except Exception:
            pass

    new_uuid = f"node_{uuid.uuid4().hex[:12]}"
    try:
        with open(uuid_file, "w", encoding="utf-8") as f:
            f.write(new_uuid)
    except Exception as e:
        print(f"[!] 写入本地 .agent_uuid 失败: {e}")
    return new_uuid

try:
    from . import scanner
except ImportError:
    try:
        import scanner
    except ImportError:
        import domain_scanner as scanner

class ScanWorker:
    """受控的多线程扫描工作线程，支持随时被 Master 停止与监控"""
    def __init__(self, task_info, hub_client):
        self.task_info = task_info
        self.hub = hub_client
        self.task_id = task_info["task_id"]
        self.mode = task_info["mode"]
        self.suffix = task_info.get("suffix", "com")
        self.shard_num = task_info.get("shard_num", 1)
        self.shard_total = task_info.get("shard_total", 1)

        # 并发线程数控制：本地上限 MAX_THREADS 与 Hub 调度下发取最小值 (保护弱节点、让主力机满载)
        hub_threads = int(task_info.get("threads", 25))
        max_threads_env = os.environ.get("MAX_THREADS") or os.environ.get("SCAN_MAX_THREADS")
        cli_max = getattr(hub_client, "cli_max_threads", None) if hub_client else None

        if max_threads_env and max_threads_env.strip().isdigit():
            self.max_threads = int(max_threads_env.strip())
        elif cli_max and cli_max > 0:
            self.max_threads = cli_max
        else:
            self.max_threads = None

        if self.max_threads is not None and self.max_threads > 0:
            self.threads = min(hub_threads, self.max_threads)
            if self.threads < hub_threads:
                print(f"[*] 【安全限流】受本地 MAX_THREADS={self.max_threads} 约束，实际并发调整为 {self.threads} 线程 (Hub下发值: {hub_threads})")
            else:
                print(f"[*] 并发线程数: {self.threads} (Hub下发: {hub_threads}, 本地上限: {self.max_threads})")
        else:
            self.threads = hub_threads

        # 尾部援助分流字段 (Work-Stealing)
        self.is_aid = bool(task_info.get("is_aid", False))
        self.aid_for = task_info.get("aid_for", "")
        self.start_idx = task_info.get("start_idx")
        self.end_idx = task_info.get("end_idx")

        self.is_running = False
        self.is_completed = False
        self.stop_requested = False
        self.checked_count = 0
        self.found_count = 0
        self.total = 0
        self.speed = 0.0
        self.thread = None

        self._last_time = time.time()
        self._last_count = 0

    def update_end_idx(self, new_end_idx, new_total):
        """当 Master 告知尾部任务已被集群其他空闲节点接力援助时，动态缩减当前分片的截止线"""
        if new_total < self.total:
            old_total = self.total
            self.end_idx = new_end_idx
            self.total = new_total
            print(f"\n[🤝 尾部援助生效] 任务 {self.task_id} 尾部已被集群空闲算力接力分流！当前分片目标总量从 {old_total:,} 缩减至 {self.total:,}")

    def start(self):
        self.is_running = True
        self.stop_requested = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_requested = True

    def _run(self):
        # 解析任务规则 (支持全自定义规则与旧版模式名称)
        if "length" in self.task_info:
            length = int(self.task_info["length"])
            use_letters = bool(self.task_info.get("use_letters", True))
            use_digits = bool(self.task_info.get("use_digits", False))
            use_hyphen = bool(self.task_info.get("use_hyphen", False))
        else:
            length, use_letters, use_digits, use_hyphen = scanner.parse_mode_string(self.mode)

        total_all = scanner.calc_total(length, use_letters, use_digits, use_hyphen)

        if self.start_idx is not None and self.end_idx is not None:
            start_idx = self.start_idx
            end_idx = self.end_idx
            self.total = end_idx - start_idx
            canonical_shard = f"援助 {self.aid_for}" if self.is_aid else f"{start_idx}-{end_idx}"
        else:
            canonical_shard = f"{self.shard_num}/{self.shard_total}"
            shard_idx = self.shard_num - 1
            start_idx = (shard_idx * total_all) // self.shard_total
            end_idx = ((shard_idx + 1) * total_all) // self.shard_total
            self.start_idx = start_idx
            self.end_idx = end_idx
            self.total = end_idx - start_idx

        # 断点存盘与重跑逻辑
        if self.is_aid:
            clean_shard = f"aid_{self.task_id}_{start_idx}_{end_idx}"
        else:
            clean_shard = canonical_shard.replace("/", "_")
        ckpt_file = os.path.join(SCRIPT_DIR, f"checkpoint_{self.mode}_{clean_shard}.json")

        reset_ckpt = bool(self.task_info.get("reset_checkpoint", False))
        if reset_ckpt and os.path.exists(ckpt_file):
            try:
                os.remove(ckpt_file)
                print(f"\n[*] 收到强制从头重跑指令，已重置本地历史断点: {ckpt_file}")
            except Exception as e:
                print(f"[!] 清除断点失败: {e}")
            last_ckpt = ""
            self.checked_count = 0
            self.found_count = 0
            found_domains = []
        else:
            last_ckpt, self.checked_count, self.found_count, found_domains = scanner.load_checkpoint(ckpt_file)
            if self.checked_count > 0:
                print(f"[*] 发现历史断点：已核查 {self.checked_count:,} 个，命中可用 {self.found_count} 个，断点记录点: {last_ckpt or '起始'}")
            else:
                print(f"[*] 未检测到历史断点或断点为空，将从分片起始点开始扫描")
            # 容灾兜底：仅在少量断点残留（如上次进程被 kill 时队列中的未上报项）时补录，避免历史几十万全量重复刷库
            if found_domains and len(found_domains) <= 500:
                for item in found_domains:
                    if isinstance(item, (list, tuple)) and len(item) >= 2:
                        d, r = item[0], item[1]
                    else:
                        d, r = str(item), "404 未注册"
                    self.hub.report_domain(d, self.mode, r)

        generator = scanner.get_range_generator(length, use_letters, use_digits, use_hyphen, self.suffix, start_idx, end_idx)
        skipping = bool(last_ckpt)

        start_time = time.time()
        self._last_time = start_time
        self._last_count = self.checked_count

        import concurrent.futures

        last_dom = last_ckpt
        last_ckpt_save = time.time()
        in_flight = set()
        max_in_flight = self.threads * 2
        submitted_count = self.checked_count

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                for domain in generator:
                    if self.stop_requested:
                        break

                    # 动态截止检查：如果已提交或已核查数量达到目标总量，提前顺利收官！
                    if self.total > 0 and (submitted_count >= self.total or self.checked_count >= self.total):
                        print(f"\n[*] 当前分片已达到目标总量 ({self.checked_count:,} / {self.total:,})，提前顺利收官！")
                        break

                    if skipping:
                        if domain == last_ckpt:
                            skipping = False
                        continue

                    fut = executor.submit(scanner.check_single_domain, domain)
                    in_flight.add(fut)
                    submitted_count += 1

                    # 流式滑动窗口：当流水线达到容量上限时，等待最先完成的任务释放槽位并立即补入新域名（消除批次空转）
                    if len(in_flight) >= max_in_flight:
                        done, in_flight = concurrent.futures.wait(
                            in_flight, return_when=concurrent.futures.FIRST_COMPLETED
                        )
                        for f in done:
                            dom, is_free, reason = f.result()
                            self.checked_count += 1
                            if is_free:
                                self.found_count += 1
                                print(f"\n[√ 发现可用] {dom} -> {reason}")
                                self.hub.report_domain(dom, self.mode, reason)
                            last_dom = dom

                        now = time.time()
                        delta_t = now - self._last_time
                        if delta_t >= 2.0:
                            self.speed = round((self.checked_count - self._last_count) / delta_t, 1)
                            self._last_time = now
                            self._last_count = self.checked_count

                        # 定时存盘超轻量断点 (每 5 秒保存一次，仅 150 字节，零磁盘压力)
                        if now - last_ckpt_save >= 5.0 and last_dom:
                            scanner.save_checkpoint(ckpt_file, last_dom, self.checked_count, self.found_count)
                            last_ckpt_save = now

                # 消费流水线中剩余未结算的任务
                while in_flight and not self.stop_requested:
                    done, in_flight = concurrent.futures.wait(
                        in_flight, return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    for f in done:
                        dom, is_free, reason = f.result()
                        self.checked_count += 1
                        if is_free:
                            self.found_count += 1
                            print(f"\n[√ 发现可用] {dom} -> {reason}")
                            self.hub.report_domain(dom, self.mode, reason)
                        last_dom = dom

                if last_dom:
                    scanner.save_checkpoint(ckpt_file, last_dom, self.checked_count, self.found_count)

        except Exception as e:
            print(f"扫描异常: {e}")
        finally:
            self.is_running = False
            self.speed = 0.0
            if self.total > 0 and self.checked_count > self.total:
                self.checked_count = self.total
            if not self.stop_requested:
                self.is_completed = True
                print(f"\n[🎉 扫描完成] 任务 {self.task_id} 分片 {canonical_shard} 已全量扫描完毕！共核查 {self.checked_count:,} 个，命中可用域名 {self.found_count} 个")
            else:
                print(f"\n[*] 任务 {self.task_id} 工作线程已停止。当前核查进度 {self.checked_count:,} / {self.total:,}")

class HubClient:
    def __init__(self, hub_url, token, node_id, agent_uuid):
        self.hub_url = hub_url.rstrip("/")
        self.token = token
        self.node_id = node_id
        self.agent_uuid = agent_uuid
        self._report_queue = queue.Queue()
        self._stop_event = threading.Event()
        self._reporter_thread = threading.Thread(target=self._report_worker, daemon=True)
        self._reporter_thread.start()

    def _post(self, path, payload, timeout=4):
        url = f"{self.hub_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
                "X-Hub-Token": self.token
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def register(self):
        payload = {
            "agent_uuid": self.agent_uuid,
            "node_id": self.node_id,
            "os_info": f"{platform.system()} {platform.machine()}",
            "version": AGENT_VERSION
        }
        try:
            res = self._post("/api/agent/register", payload)
            if res.get("code") == 0:
                assigned = res.get("node_id")
                if assigned and assigned != self.node_id:
                    print(f"[*] 节点标识已由 Hub 确认/调整为: {assigned}")
                    self.node_id = assigned
                return True
            return False
        except Exception as e:
            print(f"[!] 注册到 Master 失败 ({self.hub_url}): {e}")
            return False

    def heartbeat(self, worker):
        if worker and worker.is_running:
            status = "running"
            task_id = worker.task_id
            mode = worker.mode
            shard = f"援助 {worker.aid_for}" if worker.is_aid else f"{worker.shard_num}/{worker.shard_total}"
            total = worker.total
            scanned = min(worker.checked_count, total) if total > 0 else worker.checked_count
            speed = worker.speed
            avail = worker.found_count
        elif worker and worker.is_completed:
            status = "completed"
            task_id = worker.task_id
            mode = worker.mode
            shard = f"援助 {worker.aid_for}" if worker.is_aid else f"{worker.shard_num}/{worker.shard_total}"
            total = worker.total
            scanned = min(worker.checked_count, total) if total > 0 else worker.checked_count
            speed = 0.0
            avail = worker.found_count
        else:
            status = "idle"
            task_id = ""
            mode = ""
            shard = ""
            scanned = 0
            total = 0
            speed = 0.0
            avail = 0

        payload = {
            "agent_uuid": self.agent_uuid,
            "node_id": self.node_id,
            "task_id": task_id,
            "mode": mode,
            "shard": shard,
            "scanned": scanned,
            "total": total,
            "speed": speed,
            "available": avail,
            "status": status,
            "version": AGENT_VERSION
        }
        try:
            resp = self._post("/api/agent/heartbeat", payload, timeout=3)
            if resp and resp.get("code") == 0:
                assigned = resp.get("assigned_node_id")
                if assigned and assigned != self.node_id:
                    print(f"[*] 节点标识已由 Hub 修正为: {assigned}")
                    self.node_id = assigned
            return resp
        except Exception as e:
            return None

    def report_domain(self, domain, mode, reason):
        """将发现的可用域名推入异步重试队列，防止任何由于 Hub 重启或网络抖动导致的丢数"""
        item = {
            "domain": domain,
            "mode": mode,
            "reason": reason
        }
        self._report_queue.put(item)

    def _report_worker(self):
        """后台高可靠批量上报与故障重试线程"""
        while not self._stop_event.is_set():
            batch = []
            try:
                first_item = self._report_queue.get(timeout=1.0)
                batch.append(first_item)
                while len(batch) < 50:
                    try:
                        batch.append(self._report_queue.get_nowait())
                    except queue.Empty:
                        break
            except queue.Empty:
                continue

            if not batch:
                continue

            payload = {
                "domains": batch,
                "node_id": self.node_id
            }

            # 持续重试直到 Hub 恢复并成功接收入库（绝不丢数）
            first_fail = True
            while not self._stop_event.is_set():
                try:
                    res = self._post("/api/agent/report", payload, timeout=4)
                    if res and res.get("code") == 0:
                        for _ in batch:
                            self._report_queue.task_done()
                        break
                    else:
                        print(f"[!] 上报可用域名到 Hub 异常: {res}，将在 2 秒后自动重试...")
                except Exception as e:
                    if first_fail:
                        print(f"[*] Hub 当前不可达或正在重启中 ({e})，可用域名已安全暂存本地队列，等待 Hub 恢复后自动补发...")
                        first_fail = False
                time.sleep(2.0)

    def flush_reports(self, timeout=5.0):
        """优雅退出前等待上报队列清空"""
        start_t = time.time()
        while not self._report_queue.empty() and (time.time() - start_t < timeout):
            time.sleep(0.2)

def auto_detect_node_id():
    hname = socket.gethostname().lower()
    if "jp" in hname: return "Oracle-JP"
    if "kr" in hname: return "Oracle-KR"
    if "us" in hname: return "Google-US"
    if "bl" in hname: return "BL"
    if "ld" in hname: return "LD"
    if "fn" in hname or "nas" in hname: return "FN"
    return socket.gethostname()

def main():
    parser = argparse.ArgumentParser(description="Domain Scanner 集群 Agent")
    parser.add_argument("--hub", default=os.environ.get("HUB_URL", "http://192.168.200.12:8088"),
                        help="Master 控制中心地址")
    parser.add_argument("--token", default=os.environ.get("HUB_TOKEN", ""),
                        help="集群通信鉴权 Token")
    parser.add_argument("--node", default=os.environ.get("NODE_ID", ""),
                        help="节点名称标识")
    parser.add_argument("--max-threads", type=int,
                        default=int(os.environ.get("MAX_THREADS") or os.environ.get("SCAN_MAX_THREADS") or 0),
                        help="本地最大并发线程数上限 (安全约束，取 min(Hub下发, max-threads))")
    args = parser.parse_args()

    node_id = args.node.strip() or auto_detect_node_id()
    token = args.token.strip()
    agent_uuid = get_or_create_agent_uuid()

    print(f"==================================================")
    print(f" ⚡ Domain Agent 集群客户端启动中...")
    print(f" 客户端版本: v{AGENT_VERSION}")
    print(f" 节点指纹: {agent_uuid}")
    print(f" 节点标识: {node_id}")
    print(f" Master Hub: {args.hub}")
    if args.max_threads > 0:
        print(f" 本地最大线程上限: {args.max_threads} (min模式生效)")
    else:
        print(f" 本地最大线程上限: 无限制 (完全跟随 Hub 调度)")
    print(f"==================================================")

    client = HubClient(args.hub, token, node_id, agent_uuid)
    client.cli_max_threads = args.max_threads if args.max_threads > 0 else None

    # 首次注册
    while not client.register():
        print("[*] 正在等待 Master 响应，5 秒后重试...")
        time.sleep(5)

    print("[√] Agent 注册成功！已进入待命状态，等待 Master 下发任务指令...")

    current_worker = None

    def graceful_exit(sig=None, frame=None):
        print(f"\n[!] 收到退出信号，正在安全停止并提交最终数据...")
        if current_worker and current_worker.is_running:
            current_worker.stop()
        client.flush_reports(timeout=4.0)
        sys.exit(0)

    try:
        signal.signal(signal.SIGTERM, graceful_exit)
        signal.signal(signal.SIGINT, graceful_exit)
    except Exception:
        pass

    try:
        while True:
            resp = client.heartbeat(current_worker)
            if resp and resp.get("code") == 0:
                # 检查 Master 是否下发了动态缩容/尾部援助截取通知
                if "trimmed_total" in resp and current_worker and current_worker.is_running:
                    trimmed_total = resp.get("trimmed_total")
                    trimmed_end_idx = resp.get("trimmed_end_idx")
                    if trimmed_total is not None and trimmed_total < current_worker.total:
                        current_worker.update_end_idx(trimmed_end_idx, trimmed_total)

                cmd = resp.get("command", "IDLE")
                task_data = resp.get("task")

                if cmd == "START" and task_data:
                    # 如果已经在跑相同的任务，不重复启动
                    if current_worker and current_worker.is_running and current_worker.task_id == task_data["task_id"]:
                        pass
                    # 如果当前 worker 已经把这个任务跑完了，绝不重复启动
                    elif current_worker and current_worker.is_completed and current_worker.task_id == task_data["task_id"]:
                        pass
                    else:
                        if current_worker and current_worker.is_running:
                            print(f"[*] 收到新任务，正在切换停止旧任务 {current_worker.task_id}...")
                            current_worker.stop()
                            client.flush_reports(timeout=3.0)
                        if task_data.get("is_aid"):
                            print(f"\n[🤝 收到 Master 尾部接力援助指令] 为节点 {task_data.get('aid_for')} 分流扫描区间 [{task_data.get('start_idx')}-{task_data.get('end_idx')}]，共 {task_data.get('total'):,} 个域名")
                        else:
                            print(f"\n[🚀 收到 Master 任务指令] 模式: {task_data['mode']}, 分片: {task_data['shard_num']}/{task_data['shard_total']}")
                        current_worker = ScanWorker(task_data, client)
                        current_worker.start()

                elif cmd == "STOP":
                    if current_worker and current_worker.is_running:
                        print(f"\n[⏹️ 收到 Master 停止指令] 正在停止任务...")
                        current_worker.stop()
                    client.flush_reports(timeout=3.0)
                    current_worker = None

            time.sleep(2.5)

    except KeyboardInterrupt:
        graceful_exit()

if __name__ == "__main__":
    main()

