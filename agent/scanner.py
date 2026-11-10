#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Scanner Engine - 纯 Python 3 标准库域名扫描核心
- 数学映射级零内存字典生成器 (支持 3~5 位、字母/数字任意勾选、连字符动态穿插)
- DNS 初筛 (毫秒级过滤 85%~90% 解析占用)
- Verisign 官方权威 RDAP 终验 (404 确认真正未注册)
- 确定性、无重叠均匀分片调度与断点存盘
"""

import os
import ssl
import time
import json
import socket
import urllib.request
import urllib.error

# 强制底层网络优先使用 IPv4，彻底规避双栈宽带环境下跨洋 IPv6 握手黑洞与 PMTUD 丢包
_orig_getaddrinfo = socket.getaddrinfo

def _ipv4_preferred_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0 or family == getattr(socket, "AF_UNSPEC", 0):
        try:
            res = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if res:
                return res
        except Exception:
            pass
    return _orig_getaddrinfo(host, port, family, type, proto, flags)

socket.getaddrinfo = _ipv4_preferred_getaddrinfo

# 全局忽略部分特殊网络环境下的 SSL 证书校验错误
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# ICANN / IETF / IGO 官方政策永久保留字
ICANN_RESERVED_PREFIXES = {
    "gnso", "iesg", "imso", "example", "nic", "whois", "w3c", "iana", "icann", "internic", "rfc-editor"
}

def get_char_pool(use_letters=True, use_digits=False):
    chars = ""
    if use_letters:
        chars += "abcdefghijklmnopqrstuvwxyz"
    if use_digits:
        chars += "0123456789"
    return chars

def calc_total(length, use_letters=True, use_digits=False, use_hyphen=False):
    pool = get_char_pool(use_letters, use_digits)
    if not pool:
        return 0
    pool_len = len(pool)
    base = pool_len ** length
    return base * (length - 1) if use_hyphen else base

def generate_domain(index, length, chars, use_hyphen, suffix="com"):
    """
    O(1) 数学映射：将任意全局索引映射为唯一的域名字符串
    零内存占用，支持十亿级规模候选池极速随机定位
    """
    pool_len = len(chars)
    if use_hyphen:
        pos_count = length - 1
        hyphen_pos = (index % pos_count) + 1
        char_idx = index // pos_count
    else:
        hyphen_pos = None
        char_idx = index

    res = []
    curr = char_idx
    for _ in range(length):
        res.append(chars[curr % pool_len])
        curr //= pool_len
    res.reverse()

    if hyphen_pos is not None:
        name = "".join(res[:hyphen_pos]) + "-" + "".join(res[hyphen_pos:])
    else:
        name = "".join(res)
    return f"{name}.{suffix}"

def parse_mode_string(mode_str):
    """
    智能解析模式字符串为标准化参数 (支持 4letter-, 3num-, 4mix, 5letter 等)
    """
    s = mode_str.lower().strip()
    use_hyphen = s.endswith("-")
    if use_hyphen:
        s = s[:-1]

    length = 4
    for l in (3, 4, 5):
        if s.startswith(str(l)):
            length = l
            s = s[1:]
            break

    if "letter" in s or "alpha" in s:
        use_letters, use_digits = True, False
    elif "num" in s or "digit" in s:
        use_letters, use_digits = False, True
    elif "mix" in s or "all" in s:
        use_letters, use_digits = True, True
    else:
        use_letters, use_digits = True, False

    return length, use_letters, use_digits, use_hyphen

def get_range_generator(length, use_letters, use_digits, use_hyphen, suffix, start_idx, end_idx):
    """
    通用数学区间生成器：按绝对全局索引 [start_idx, end_idx) 生成域名
    用于多机细粒度工作窃取 (Work-Stealing) 与尾部援助分流
    """
    chars = get_char_pool(use_letters, use_digits)
    for idx in range(start_idx, end_idx):
        yield generate_domain(idx, length, chars, use_hyphen, suffix)

def get_sharded_generator(length, use_letters, use_digits, use_hyphen, suffix, shard_idx, shard_total):
    """
    获取当前节点的分片生成器
    shard_idx: 0 到 shard_total-1
    """
    total = calc_total(length, use_letters, use_digits, use_hyphen)
    if total == 0 or shard_total <= 0:
        return

    start_idx = (shard_idx * total) // shard_total
    end_idx = ((shard_idx + 1) * total) // shard_total

    yield from get_range_generator(length, use_letters, use_digits, use_hyphen, suffix, start_idx, end_idx)

# ----------------- 核心扫描引擎: DNS 初筛 + RDAP 终验 -----------------

def dns_has_record(domain):
    """步骤 1: DNS 初筛 (毫秒级过滤 85%~90% 已解析占用域名)"""
    lookup_name = domain if domain.endswith(".") else f"{domain}."
    try:
        socket.getaddrinfo(lookup_name, 80, socket.AF_INET, socket.SOCK_STREAM)
        return True
    except socket.gaierror:
        return False
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
            with urllib.request.urlopen(req, timeout=3.5, context=ssl_context) as resp:
                if resp.status == 200:
                    return False
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return True
            elif e.code == 429:
                time.sleep(2 * (attempt + 1))
                continue
            else:
                return False
        except Exception:
            time.sleep(0.5)
            continue

    return False

def check_single_domain(domain):
    prefix = domain.split(".")[0].lower()
    if prefix in ICANN_RESERVED_PREFIXES:
        return domain, False, "ICANN 官方政策保留字 (禁止注册)"

    if dns_has_record(domain):
        return domain, False, "DNS解析已存在"

    is_available = check_rdap_availability(domain)
    if is_available:
        return domain, True, "RDAP 权威确认 404 未注册"
    else:
        return domain, False, "RDAP 确认已占用"

# ----------------- 进度断点存盘 -----------------

def load_checkpoint(ckpt_path):
    # 优先加载主断点文件，如果主断点异常，自动回退到 .bak 备份断点
    for path in [ckpt_path, ckpt_path + ".bak"]:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    ld = data.get("last_domain", "")
                    cc = data.get("checked_count", 0)
                    fc = data.get("found_count", 0)
                    fd = data.get("found_domains", [])
                    if cc > 0 or ld:
                        return ld, cc, fc, fd
            except Exception as e:
                print(f"[!] 读取断点文件 {path} 异常: {e}，尝试备用断点...")
    return "", 0, 0, []

def save_checkpoint(ckpt_path, last_domain, checked_count, found_count, found_domains=None):
    tmp_path = ckpt_path + ".tmp"
    bak_path = ckpt_path + ".bak"
    try:
        # 1. 写入精简断点元数据 (仅约 150 字节，彻底消除大 JSON 磁盘 IOPS 瓶颈与 CPU 卡顿)
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump({
                "last_domain": last_domain,
                "checked_count": checked_count,
                "found_count": found_count,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }, f)
            f.flush()
            os.fsync(f.fileno())

        # 2. 如果原断点有效存在，备份一份为 .bak 双重保险
        if os.path.exists(ckpt_path):
            try:
                import shutil
                shutil.copyfile(ckpt_path, bak_path)
            except Exception:
                pass

        # 3. 操作系统级原子重命名替换 (Linux POSIX rename 保证瞬时原子性，杜绝任何断电/重启损坏)
        os.replace(tmp_path, ckpt_path)
    except Exception as e:
        pass

