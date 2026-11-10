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

# 引入核心扫描器引擎 (优先同目录 scanner.py，保证 agent 独立自包含)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

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
        self.shard_num = task_info["shard_num"]
        self.shard_total = task_info["shard_total"]
        self.threads = task_info.get("threads", 25)

        self.is_running = False
        self.stop_requested = False
        self.checked_count = 0
        self.found_count = 0
        self.total = 0
        self.speed = 0.0
        self.thread = None

        self._last_time = time.time()
        self._last_count = 0

    def start(self):
        self.is_running = True
        self.stop_requested = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_requested = True

    def _run(self):
        canonical_shard = f"{self.shard_num}/{self.shard_total}"
        shard_idx = self.shard_num - 1

        # 解析任务规则 (支持全自定义规则与旧版模式名称)
        if "length" in self.task_info:
            length = int(self.task_info["length"])
            use_letters = bool(self.task_info.get("use_letters", True))
            use_digits = bool(self.task_info.get("use_digits", False))
            use_hyphen = bool(self.task_info.get("use_hyphen", False))
        else:
            length, use_letters, use_digits, use_hyphen = scanner.parse_mode_string(self.mode)

        total_all = scanner.calc_total(length, use_letters, use_digits, use_hyphen)
        start_idx = (shard_idx * total_all) // self.shard_total
        end_idx = ((shard_idx + 1) * total_all) // self.shard_total
        self.total = end_idx - start_idx

        # 断点存盘与重跑逻辑
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

        generator = scanner.get_sharded_generator(length, use_letters, use_digits, use_hyphen, self.suffix, shard_idx, self.shard_total)
        skipping = bool(last_ckpt)

        start_time = time.time()
        self._last_time = start_time
        self._last_count = self.checked_count

        from concurrent.futures import ThreadPoolExecutor, as_completed

        batch = []
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for domain in generator:
                    if self.stop_requested:
                        break

                    if skipping:
                        if domain == last_ckpt:
                            skipping = False
                        continue

                    batch.append(domain)
                    if len(batch) >= self.threads * 2:
                        futures = [executor.submit(scanner.check_single_domain, d) for d in batch]
                        for fut in as_completed(futures):
                            dom, is_free, reason = fut.result()
                            self.checked_count += 1
                            if is_free:
                                self.found_count += 1
                                found_domains.append((dom, reason))
                                print(f"\n[√ 发现可用] {dom} -> {reason}")
                                self.hub.report_domain(dom, self.mode, reason)

                        last_dom = batch[-1]
                        scanner.save_checkpoint(ckpt_file, last_dom, self.checked_count, self.found_count, found_domains)

                        # 计算即时速度
                        now = time.time()
                        delta_t = now - self._last_time
                        if delta_t >= 2.0:
                            self.speed = round((self.checked_count - self._last_count) / delta_t, 1)
                            self._last_time = now
                            self._last_count = self.checked_count

                        batch = []

                if batch and not self.stop_requested:
                    futures = [executor.submit(scanner.check_single_domain, d) for d in batch]
                    for fut in as_completed(futures):
                        dom, is_free, reason = fut.result()
                        self.checked_count += 1
                        if is_free:
                            self.found_count += 1
                            found_domains.append((dom, reason))
                            self.hub.report_domain(dom, self.mode, reason)
                    last_dom = batch[-1]
                    scanner.save_checkpoint(ckpt_file, last_dom, self.checked_count, self.found_count, found_domains)

        except Exception as e:
            print(f"扫描异常: {e}")
        finally:
            self.is_running = False
            self.speed = 0.0
            print(f"\n[*] 任务 {self.task_id} 工作线程已停止。总计扫描 {self.checked_count:,} 个")

class HubClient:
    def __init__(self, hub_url, token, node_id):
        self.hub_url = hub_url.rstrip("/")
        self.token = token
        self.node_id = node_id

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
            "node_id": self.node_id,
            "os_info": f"{platform.system()} {platform.machine()}",
            "version": "2.0"
        }
        try:
            res = self._post("/api/agent/register", payload)
            return res.get("code") == 0
        except Exception as e:
            print(f"[!] 注册到 Master 失败 ({self.hub_url}): {e}")
            return False

    def heartbeat(self, worker):
        if worker and worker.is_running:
            status = "running"
            task_id = worker.task_id
            mode = worker.mode
            shard = f"{worker.shard_num}/{worker.shard_total}"
            scanned = worker.checked_count
            total = worker.total
            speed = worker.speed
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
            "node_id": self.node_id,
            "task_id": task_id,
            "mode": mode,
            "shard": shard,
            "scanned": scanned,
            "total": total,
            "speed": speed,
            "available": avail,
            "status": status
        }
        try:
            return self._post("/api/agent/heartbeat", payload, timeout=3)
        except Exception as e:
            return None

    def report_domain(self, domain, mode, reason):
        def _worker():
            try:
                self._post("/api/agent/report", {
                    "domain": domain,
                    "mode": mode,
                    "node_id": self.node_id,
                    "reason": reason
                }, timeout=3)
            except Exception:
                pass
        threading.Thread(target=_worker, daemon=True).start()

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
    args = parser.parse_args()

    node_id = args.node.strip() or auto_detect_node_id()
    token = args.token.strip()

    print(f"==================================================")
    print(f" ⚡ Domain Agent 集群客户端启动中...")
    print(f" 节点标识: {node_id}")
    print(f" Master Hub: {args.hub}")
    print(f"==================================================")

    client = HubClient(args.hub, token, node_id)

    # 首次注册
    while not client.register():
        print("[*] 正在等待 Master 响应，5 秒后重试...")
        time.sleep(5)

    print("[√] Agent 注册成功！已进入待命状态，等待 Master 下发任务指令...")

    current_worker = None
    try:
        while True:
            resp = client.heartbeat(current_worker)
            if resp and resp.get("code") == 0:
                cmd = resp.get("command", "IDLE")
                task_data = resp.get("task")

                if cmd == "START" and task_data:
                    # 启动新任务
                    if current_worker and current_worker.is_running:
                        if current_worker.task_id != task_data["task_id"]:
                            print(f"[*] 收到新任务，正在切换停止旧任务 {current_worker.task_id}...")
                            current_worker.stop()
                            current_worker = None

                    if not current_worker or not current_worker.is_running:
                        print(f"\n[🚀 收到 Master 任务指令] 模式: {task_data['mode']}, 分片: {task_data['shard_num']}/{task_data['shard_total']}")
                        current_worker = ScanWorker(task_data, client)
                        current_worker.start()

                elif cmd == "STOP":
                    if current_worker and current_worker.is_running:
                        print(f"\n[⏹️ 收到 Master 停止指令] 正在停止任务...")
                        current_worker.stop()

            time.sleep(2.5)

    except KeyboardInterrupt:
        print("\nAgent 退出中...")
        if current_worker and current_worker.is_running:
            current_worker.stop()

if __name__ == "__main__":
    main()

