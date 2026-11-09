#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  Domain Scanner - 多节点分布式极速域名扫描工具
  基于: DNS 极速初筛 + Verisign 官方权威 RDAP 协议终审 (404 即未注册)
  特性: 纯 Python 3 标准库打造，零外部依赖，支持多机分片并发
=============================================================================
用法示例:
  单机全量扫描:
    python3 domain_scanner.py 3all
    python3 domain_scanner.py 4letter
    python3 domain_scanner.py 4num

  3 台机器分布式切分扫描 (--shard 编号/总数):
    机器 1 (US):  python3 domain_scanner.py 4letter --shard 0/3
    机器 2 (JP):  python3 domain_scanner.py 4letter --shard 1/3
    机器 3 (KR):  python3 domain_scanner.py 4letter --shard 2/3
=============================================================================
"""

import sys
import os
import time
import json
import socket
import ssl
import string
import argparse
import itertools
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# 颜色控制
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# 脚本所在目录绝对路径，保证数据文件始终与脚本存放在同一目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "available_domains.txt")

ssl_context = ssl.create_default_context()


# ----------------- 字典与分片生成器 -----------------
def get_base_generator(mode, suffix="com"):
    letters = string.ascii_lowercase
    digits = string.digits
    alphanumeric = letters + digits

    if mode == "3all":
        for p in itertools.product(alphanumeric, repeat=3):
            yield f"{''.join(p)}.{suffix}"
    elif mode == "4num":
        for p in itertools.product(digits, repeat=4):
            yield f"{''.join(p)}.{suffix}"
    elif mode == "4letter":
        for p in itertools.product(letters, repeat=4):
            yield f"{''.join(p)}.{suffix}"
    elif mode == "4mix":
        for p in itertools.product(alphanumeric, repeat=4):
            yield f"{''.join(p)}.{suffix}"
    elif mode == "5num":
        for p in itertools.product(digits, repeat=5):
            yield f"{''.join(p)}.{suffix}"
    elif mode == "5letter":
        for p in itertools.product(letters, repeat=5):
            yield f"{''.join(p)}.{suffix}"
    else:
        raise ValueError(f"未知模式: {mode}")

def get_mode_total(mode):
    totals = {
        "3all": 36**3,
        "4num": 10**4,
        "4letter": 26**4,
        "4mix": 36**4,
        "5num": 10**5,
        "5letter": 26**5
    }
    return totals.get(mode, 0)

def get_sharded_generator(mode, suffix, shard_idx, shard_total):
    """根据分片编号均匀抽取属于本节点的域名"""
    base_gen = get_base_generator(mode, suffix)
    for idx, domain in enumerate(base_gen):
        if idx % shard_total == shard_idx:
            yield domain


# ----------------- 核心扫描引擎: DNS 初筛 + RDAP 终验 -----------------
def dns_has_record(domain):
    """步骤 1: DNS 初筛 (毫秒级过滤 85%~90% 已解析占用域名)"""
    try:
        socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
        return True  # 解析成功，必已注册
    except socket.gaierror:
        return False # 无解析，疑似未注册
    except Exception:
        return False

def check_rdap_availability(domain):
    """步骤 2: Verisign 官方权威 RDAP 终验"""
    url = f"https://rdap.verisign.com/com/v1/domain/{domain}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json"
        }
    )

    retries = 3
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
                if resp.status == 200:
                    return False  # 已注册
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return True       # 404 Not Found -> 权威确认未注册！
            elif e.code == 429:
                # 触发软限流，指数休眠退避
                time.sleep(2 * (attempt + 1))
                continue
            else:
                return False
        except Exception:
            time.sleep(1)
            continue

    return False

def check_single_domain(domain):
    # 1. DNS 先行初筛
    if dns_has_record(domain):
        return domain, False, "DNS解析已存在"

    # 2. 权威 RDAP 终审
    is_available = check_rdap_availability(domain)
    if is_available:
        return domain, True, "RDAP 权威确认 404 未注册"
    else:
        return domain, False, "RDAP 确认已占用"


# ----------------- 进度断点存盘 -----------------
def get_checkpoint_path(mode, shard_str):
    clean_shard = shard_str.replace("/", "_")
    return os.path.join(SCRIPT_DIR, f"checkpoint_{mode}_{clean_shard}.json")

def load_checkpoint(ckpt_path):
    if os.path.exists(ckpt_path):
        try:
            with open(ckpt_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("last_domain", ""), data.get("checked_count", 0), data.get("found_count", 0)
        except Exception:
            pass
    return "", 0, 0

def save_checkpoint(ckpt_path, last_domain, checked_count, found_count):
    try:
        with open(ckpt_path, "w", encoding="utf-8") as f:
            json.dump({
                "last_domain": last_domain,
                "checked_count": checked_count,
                "found_count": found_count,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }, f, indent=2)
    except Exception:
        pass


# ----------------- 扫描主循环 -----------------
def main():
    parser = argparse.ArgumentParser(
        description="多节点分布式域名极速扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python3 domain_scanner.py 3all
  python3 domain_scanner.py 4letter --shard 0/3
  python3 domain_scanner.py 4num --threads 25
"""
    )

    # 位置参数：直接写模式名称，无需 --mode
    parser.add_argument("mode", nargs="?", default="3all",
                        choices=["3all", "4num", "4letter", "4mix", "5num", "5letter"],
                        help="扫描模式: 3all(3位全量), 4num(4位纯数字), 4letter(4位纯字母), 4mix(4位混合), 5num(5位数字), 5letter(5位字母) (默认: 3all)")
    
    parser.add_argument("--shard", default="0/1",
                        help="分布式分片: 格式为 编号/总数 (例如 3台机器分别填: 0/3, 1/3, 2/3。单机请保持默认 0/1)")
    parser.add_argument("--suffix", default="com", help="域名后缀 (默认: com)")
    parser.add_argument("--threads", type=int, default=20, help="并发线程数 (默认: 20)")
    parser.add_argument("--verbose", action="store_true", help="打印所有已占用域名详情")

    args = parser.parse_args()

    # 解析分片信息
    try:
        parts = args.shard.split("/")
        shard_idx = int(parts[0])
        shard_total = int(parts[1])
        assert 0 <= shard_idx < shard_total and shard_total >= 1
    except Exception:
        print(f"{RED}[!] 分片参数错误: --shard 格式必须为 [编号]/[总数]，例如 0/3、1/3{RESET}")
        sys.exit(1)

    total_all = get_mode_total(args.mode)
    node_total = total_all // shard_total

    print(f"{CYAN}{BOLD}===================================================={RESET}")
    print(f" {BOLD}域名极速扫描器 (DNS初筛 + Verisign RDAP权威验证){RESET}")
    print(f"{CYAN}{BOLD}===================================================={RESET}")
    print(f"扫描模式: {YELLOW}{BOLD}{args.mode}{RESET} (.{args.suffix})")
    print(f"全库总量: {total_all:,} 个")
    if shard_total > 1:
        print(f"分布式分片: {GREEN}节点 {shard_idx + 1}/{shard_total}{RESET} (本节点负责约: {node_total:,} 个)")
    else:
        print(f"扫描模式: 单机全量扫描")
    print(f"并发线程: {args.threads} 线程")
    print(f"结果文件: {OUTPUT_FILE}")
    print(f"{CYAN}----------------------------------------------------{RESET}")

    ckpt_file = get_checkpoint_path(args.mode, args.shard)
    last_checkpoint, checked_count, found_count = load_checkpoint(ckpt_file)
    if last_checkpoint:
        print(f"{YELLOW}[*] 检测到断点记录，已累计扫描 {checked_count:,} 个，即将从 {last_checkpoint} 续扫...{RESET}")

    generator = get_sharded_generator(args.mode, args.suffix, shard_idx, shard_total)
    skipping = bool(last_checkpoint)

    batch = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for domain in generator:
            if skipping:
                if domain == last_checkpoint:
                    skipping = False
                continue

            batch.append(domain)
            if len(batch) >= args.threads * 2:
                futures = [executor.submit(check_single_domain, d) for d in batch]
                for fut in as_completed(futures):
                    dom, is_free, reason = fut.result()
                    checked_count += 1
                    if is_free:
                        found_count += 1
                        msg = f"\n{GREEN}{BOLD}[√ 发现未注册]{RESET} {dom} -> {reason}"
                        print(msg)
                        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                            f.write(f"{dom} ({reason})\n")
                    else:
                        if args.verbose:
                            print(f"{RED}[占用]{RESET} {dom}")

                last_dom = batch[-1]
                save_checkpoint(ckpt_file, last_dom, checked_count, found_count)
                pct = (checked_count / node_total * 100) if node_total else 0
                prefix_tag = f"[分片 {shard_idx+1}/{shard_total}] " if shard_total > 1 else ""
                print(f"-> {prefix_tag}进度: {checked_count:,}/{node_total:,} ({pct:.2f}%) | 发现可用: {found_count} 个", end="\r")
                batch = []

        # 处理剩余尾部
        if batch:
            futures = [executor.submit(check_single_domain, d) for d in batch]
            for fut in as_completed(futures):
                dom, is_free, reason = fut.result()
                checked_count += 1
                if is_free:
                    found_count += 1
                    msg = f"\n{GREEN}{BOLD}[√ 发现未注册]{RESET} {dom} -> {reason}"
                    print(msg)
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                        f.write(f"{dom} ({reason})\n")

    print(f"\n\n{GREEN}{BOLD}=== 扫描完毕！本节点共完成 {checked_count:,} 个，发现可用域名 {found_count} 个 ==={RESET}")
    print(f"可用域名清单已保存至: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
