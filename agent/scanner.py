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
import re
import ssl
import time
import json
import socket
import threading
import urllib.request
import urllib.error

# ----------------- Verisign RDAP 自适应优选与 Anycast 极速选路 -----------------
_orig_getaddrinfo = socket.getaddrinfo
OPTIMAL_RDAP_IP = None
KNOWN_RDAP_IPS = ["192.68.130.30", "192.81.185.30"]
_fast_path_lock = threading.Lock()
_fast_path_initialized = False

def init_rdap_fast_path(force=False):
    """
    节点启动时自适应测速选路 (IP Racing):
    1. 解析并结合已知 Verisign RDAP Anycast 候选节点
    2. 并发探测 TCP 握手延时 (透明代理环境下自动使用 TLS 握手比对真实上游耗时)
    3. 自动锁定当前节点网络物理拓扑下延迟最低的 IP
    4. 进程内安全注入 getaddrinfo 钩子，标准保留 SNI 证书协商与 Host 头
    """
    global OPTIMAL_RDAP_IP, _fast_path_initialized
    with _fast_path_lock:
        if _fast_path_initialized and not force:
            return
        _fast_path_initialized = True

    candidates = set(KNOWN_RDAP_IPS)
    try:
        addr_info = _orig_getaddrinfo("rdap.verisign.com", 443, socket.AF_INET, socket.SOCK_STREAM)
        for item in addr_info:
            ip = item[4][0]
            if ip:
                candidates.add(ip)
    except Exception:
        pass

    results = {}
    res_lock = threading.Lock()

    def _probe_tcp(target_ip):
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect((target_ip, 443))
            rtt = (time.time() - t0) * 1000
            s.close()
            with res_lock:
                results[target_ip] = rtt
        except Exception:
            with res_lock:
                results[target_ip] = 999999.0

    threads = [threading.Thread(target=_probe_tcp, args=(ip,), daemon=True) for ip in candidates]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=2.0)

    # 若所有候选 IP 的 TCP 握手均 < 5ms，说明存在本地透明代理 (如软路由 PassWall/Clash 本地即时响应)
    all_fast_proxy = bool(results) and all(rtt < 5.0 for rtt in results.values())
    if all_fast_proxy:
        tls_results = {}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        def _probe_tls(target_ip):
            t0 = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            try:
                s.connect((target_ip, 443))
                ss = ctx.wrap_socket(s, server_hostname="rdap.verisign.com")
                ss.close()
                with res_lock:
                    tls_results[target_ip] = (time.time() - t0) * 1000
            except Exception:
                with res_lock:
                    tls_results[target_ip] = 999999.0

        threads = [threading.Thread(target=_probe_tls, args=(ip,), daemon=True) for ip in candidates]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=3.5)

        valid_tls = [item for item in tls_results.items() if item[1] < 999999.0]
        if valid_tls:
            valid_tls.sort(key=lambda x: x[1])
            OPTIMAL_RDAP_IP = valid_tls[0][0]
            print(f"[FastPath] 检测到软路由透明代理，TLS 上游测速选优: 锁定 {OPTIMAL_RDAP_IP} (耗时: {valid_tls[0][1]:.1f}ms)", flush=True)
            return
        else:
            OPTIMAL_RDAP_IP = "192.81.185.30"
            print(f"[FastPath] 透明代理探测超时，默认锁定亚洲 POP: {OPTIMAL_RDAP_IP}", flush=True)
            return

    valid_tcp = [item for item in results.items() if item[1] < 999999.0]
    if valid_tcp:
        valid_tcp.sort(key=lambda x: x[1])
        OPTIMAL_RDAP_IP = valid_tcp[0][0]
        print(f"[FastPath] RDAP Anycast 自适应选优完成: 锁定 {OPTIMAL_RDAP_IP} (TCP握手: {valid_tcp[0][1]:.1f}ms)", flush=True)
    else:
        _fast_path_initialized = False
        print("[FastPath] Anycast 测速暂未响应，保持系统默认 DNS 解析 (稍后自动重试)", flush=True)

def _adaptive_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    # 针对 RDAP 官方终验权威，优先重定向到自适应最优 Anycast IP
    if host and host.rstrip(".") == "rdap.verisign.com" and OPTIMAL_RDAP_IP:
        try:
            return _orig_getaddrinfo(OPTIMAL_RDAP_IP, port, socket.AF_INET, type, proto, flags)
        except Exception:
            pass

    # 强制底层优先使用 IPv4，彻底规避双栈宽带跨洋 IPv6 握手黑洞与 PMTUD 丢包
    if family == 0 or family == getattr(socket, "AF_UNSPEC", 0):
        try:
            res = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if res:
                return res
        except Exception:
            pass
    return _orig_getaddrinfo(host, port, family, type, proto, flags)

socket.getaddrinfo = _adaptive_getaddrinfo

# 启动自适应测速 (导入时即刻探测)
try:
    init_rdap_fast_path()
except Exception:
    pass

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
    if use_hyphen:
        if length < 3:
            return 0
        char_len = length - 1
        pos_count = length - 2
        return (pool_len ** char_len) * pos_count
    else:
        return pool_len ** length

def generate_domain(index, length, chars, use_hyphen, suffix="com"):
    """
    O(1) 数学映射：将任意全局索引映射为唯一的域名字符串
    零内存占用，支持十亿级规模候选池极速随机定位
    当 use_hyphen=True 时，域名主体总长度严格等于 length 位 (字母数字 length-1 位 + 1个 '-')
    """
    pool_len = len(chars)
    if use_hyphen:
        char_len = length - 1
        pos_count = length - 2
        hyphen_pos = (index % pos_count) + 1
        char_idx = index // pos_count
    else:
        char_len = length
        hyphen_pos = None
        char_idx = index

    res = []
    curr = char_idx
    for _ in range(char_len):
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
    for l in (3, 4, 5, 6):
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
    if not _fast_path_initialized:
        try:
            init_rdap_fast_path()
        except Exception:
            pass

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

# ----------------- 域名特征分析与前置精选过滤器 -----------------

VOWELS_SET = set("aeiou")
RARE_CONSONANTS_SET = set("qxzvy")

def clean_domain_name(s):
    if not s:
        return ""
    return s.split(".")[0].replace("-", "").lower()

def has_consecutive_same(s, n):
    name = clean_domain_name(s)
    if not name or not n:
        return False
    try:
        n = int(n)
    except Exception:
        return False
    if n < 2 or len(name) < n:
        return False
    pattern = r"([a-z0-9])\1{" + str(n - 1) + ",}"
    return bool(re.search(pattern, name))

def has_sequential(s, n=3, direction="any"):
    name = clean_domain_name(s)
    if not name or not n:
        return False
    try:
        n = int(n)
    except Exception:
        return False
    if n < 2 or len(name) < n:
        return False

    check_asc = direction in ("asc", "any")
    check_desc = direction in ("desc", "any")

    for i in range(len(name) - n + 1):
        sub = name[i:i + n]
        if check_asc and (sub.isalpha() or sub.isdigit()) and all(ord(sub[j]) + 1 == ord(sub[j + 1]) for j in range(n - 1)):
            return True
        if check_desc and (sub.isalpha() or sub.isdigit()) and all(ord(sub[j]) - 1 == ord(sub[j + 1]) for j in range(n - 1)):
            return True
    return False

def match_pattern(s, pat):
    name = clean_domain_name(s)
    if not name or not pat:
        return False
    pat = pat.lower()
    if pat == "palindrome":
        return len(name) >= 3 and name == name[::-1]

    plen = len(pat)
    if len(name) < plen:
        return False

    for i in range(len(name) - plen + 1):
        window = name[i:i + plen]
        m_pat2win = {}
        m_win2pat = {}
        matched = True
        for p_ch, w_ch in zip(pat, window):
            if p_ch in m_pat2win:
                if m_pat2win[p_ch] != w_ch:
                    matched = False
                    break
            elif w_ch in m_win2pat:
                matched = False
                break
            else:
                m_pat2win[p_ch] = w_ch
                m_win2pat[w_ch] = p_ch
        if matched:
            return True
    return False

def is_pronounceable(s):
    name = clean_domain_name(s)
    if not name.isalpha() or len(name) < 3:
        return False
    c_count = 0
    for ch in name:
        if ch in VOWELS_SET:
            c_count = 0
        else:
            c_count += 1
            if c_count >= 3:
                return False
    v_count = 0
    for ch in name:
        if ch in VOWELS_SET:
            v_count += 1
            if v_count >= 3:
                return False
        else:
            v_count = 0
    return any(ch in VOWELS_SET for ch in name)

def matches_filter(domain, filter_config):
    """
    前置精选规则判定引擎 (微秒级内存运算):
    返回 True 表示符合精选要求（送检网络），返回 False 表示不符合（本地直接跳过）
    """
    if not filter_config or not filter_config.get("enabled"):
        return True

    clean_name = clean_domain_name(domain)
    if not clean_name:
        return False

    # 1. 纯净度硬过滤 (排除生僻辅音 q, x, z, v, y)
    if filter_config.get("clean_only"):
        if any(ch in RARE_CONSONANTS_SET for ch in clean_name):
            return False

    # 2. 正则过滤 (如果配置了自定义正则)
    regex_pat = filter_config.get("regex")
    if regex_pat:
        try:
            if not re.search(regex_pat, clean_name, re.IGNORECASE):
                return False
        except Exception:
            pass

    # 3. 候选特征匹配（以下子规则命中任意一项即算符合，OR 逻辑）
    rules = filter_config.get("rules", filter_config)

    has_sub_rules = False

    # (a) 对称回文 (如 abba, 12321)
    if rules.get("palindrome"):
        has_sub_rules = True
        if len(clean_name) >= 3 and clean_name == clean_name[::-1]:
            return True

    # (b) 顺子 (升序/降序)
    if rules.get("seq") or rules.get("seq_asc") or rules.get("seq_desc"):
        has_sub_rules = True
        min_seq = int(rules.get("min_seq_len", 3))
        if rules.get("seq_asc") and has_sequential(clean_name, min_seq, "asc"):
            return True
        if rules.get("seq_desc") and has_sequential(clean_name, min_seq, "desc"):
            return True
        if rules.get("seq") and has_sequential(clean_name, min_seq, "any"):
            return True

    # (c) 经典叠字结构 (AABB / ABAB / ABBA / AAAB / AAAA 等)
    pats = rules.get("patterns", [])
    if pats:
        has_sub_rules = True
        for p in pats:
            if match_pattern(clean_name, p):
                return True

    # (d) 连号 / 豹子 (连续相同字符 >= N，如 AAA)
    min_repeat = rules.get("min_repeat")
    if min_repeat and int(min_repeat) >= 2:
        has_sub_rules = True
        if has_consecutive_same(clean_name, int(min_repeat)):
            return True

    # (e) 自然发音 / 可读品牌词
    if rules.get("pronounceable"):
        has_sub_rules = True
        if is_pronounceable(clean_name):
            return True

    # 如果没有勾选任何细分子规则，只要通过了 clean_only/regex 就允许放行
    if not has_sub_rules:
        return True

    return False

