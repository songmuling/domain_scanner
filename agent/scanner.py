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

# ICANN / IETF / IGO 官方政策永久法定保留字 (权威全量 ICANN Specification 5 规范库)
_SCANNER_DIR = os.path.dirname(os.path.abspath(__file__))
_RESERVED_JSON_PATH = os.path.join(_SCANNER_DIR, "icann_reserved.json")

ICANN_RESERVED_PREFIXES = {
    "gnso", "iesg", "imso", "example", "nic", "whois", "w3c", "iana", "icann", "internic", "rfc-editor",
    "wto", "spr", "nato", "unesco", "unicef", "unhcr", "undp", "unep", "opec", "interpol", "iaea", "imf",
    "bceao", "uemoa", "bstdp", "icglr", "puasp", "aripo", "cern", "asean", "ecb", "eib", "bis", "ioc"
}
if os.path.exists(_RESERVED_JSON_PATH):
    try:
        with open(_RESERVED_JSON_PATH, "r", encoding="utf-8") as _f:
            ICANN_RESERVED_PREFIXES.update(json.load(_f))
    except Exception as _e:
        pass

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

# ----------------- 智能模板与掩码定向生成引擎 (Targeted Pattern / Mask Engine) -----------------

VOWELS_LIST = list("aeiou")
CONSONANTS_LIST = list("bcdfghjklmnpqrstvwxyz")
LETTERS_LIST = list("abcdefghijklmnopqrstuvwxyz")
DIGITS_LIST = list("0123456789")
ALPHANUM_LIST = LETTERS_LIST + DIGITS_LIST

def parse_template(pattern_str):
    """
    将用户模板字符串解析为 slots 列表与笛卡尔积总数
    支持：
    1. 占位符: L/?l(字母26), D/?d(数字10), V/?v(元音5), C/?c(辅音21), */?*(任意36)
    2. 方括号集: [abc], [a-z], [0-9]
    3. 重复量词: L{2}, D{3}, [a-z]{2}
    4. 分支选择: (88|66|99|vip)
    5. 固定字面量: 888, vip, ai, - 等
    """
    s = pattern_str.strip()
    if not s:
        raise ValueError("模板表达式不能为空")

    slots = []
    i = 0
    n = len(s)

    while i < n:
        # 1. 括号多选分支: (88|66|99|vip|ai)
        if s[i] == '(':
            end = s.find(')', i)
            if end == -1:
                raise ValueError("括号未闭合: 缺少 ')'")
            options = [opt.strip().lower() for opt in s[i+1:end].split('|') if opt.strip()]
            if not options:
                raise ValueError("括号内选项不能为空")
            next_idx = end + 1
            repeat = 1
            if next_idx < n and s[next_idx] == '{':
                rep_end = s.find('}', next_idx)
                if rep_end != -1 and s[next_idx+1:rep_end].isdigit():
                    repeat = int(s[next_idx+1:rep_end])
                    next_idx = rep_end + 1
            for _ in range(repeat):
                slots.append(options)
            i = next_idx
            continue

        # 2. 方括号字符集: [a-z], [0-9], [abc], [a-z0-9]
        if s[i] == '[':
            end = s.find(']', i)
            if end == -1:
                raise ValueError("方括号未闭合: 缺少 ']'")
            inside = s[i+1:end].lower()
            chars = set()
            j = 0
            while j < len(inside):
                if j + 2 < len(inside) and inside[j+1] == '-':
                    c_start = inside[j]
                    c_end = inside[j+2]
                    for code in range(ord(c_start), ord(c_end) + 1):
                        chars.add(chr(code))
                    j += 3
                else:
                    chars.add(inside[j])
                    j += 1
            sorted_chars = sorted(list(chars))
            if not sorted_chars:
                raise ValueError("方括号字符集解析为空")
            next_idx = end + 1
            repeat = 1
            if next_idx < n and s[next_idx] == '{':
                rep_end = s.find('}', next_idx)
                if rep_end != -1 and s[next_idx+1:rep_end].isdigit():
                    repeat = int(s[next_idx+1:rep_end])
                    next_idx = rep_end + 1
            for _ in range(repeat):
                slots.append(sorted_chars)
            i = next_idx
            continue

        # 3. Hashcat 风格通配符: ?l, ?d, ?v, ?c, ?*
        if s[i] == '?':
            if i + 1 >= n:
                raise ValueError("问号后缺少占位符类型 (如 ?l, ?d, ?v, ?c, ?*)")
            t = s[i+1].lower()
            if t in ('l', 'a'):
                pool = LETTERS_LIST
            elif t == 'd':
                pool = DIGITS_LIST
            elif t == 'v':
                pool = VOWELS_LIST
            elif t == 'c':
                pool = CONSONANTS_LIST
            elif t == '*':
                pool = ALPHANUM_LIST
            else:
                raise ValueError(f"未知的通配占位符: ?{t}")
            next_idx = i + 2
            repeat = 1
            if next_idx < n and s[next_idx] == '{':
                rep_end = s.find('}', next_idx)
                if rep_end != -1 and s[next_idx+1:rep_end].isdigit():
                    repeat = int(s[next_idx+1:rep_end])
                    next_idx = rep_end + 1
            for _ in range(repeat):
                slots.append(pool)
            i = next_idx
            continue

        # 4. 单字符简写 L, D, V, C, *
        ch = s[i]
        next_idx = i + 1
        repeat = 1
        if next_idx < n and s[next_idx] == '{':
            rep_end = s.find('}', next_idx)
            if rep_end != -1 and s[next_idx+1:rep_end].isdigit():
                repeat = int(s[next_idx+1:rep_end])
                next_idx = rep_end + 1

        if ch == 'L':
            for _ in range(repeat): slots.append(LETTERS_LIST)
            i = next_idx
        elif ch == 'D':
            for _ in range(repeat): slots.append(DIGITS_LIST)
            i = next_idx
        elif ch == 'V':
            for _ in range(repeat): slots.append(VOWELS_LIST)
            i = next_idx
        elif ch == 'C':
            for _ in range(repeat): slots.append(CONSONANTS_LIST)
            i = next_idx
        elif ch == '*':
            for _ in range(repeat): slots.append(ALPHANUM_LIST)
            i = next_idx
        else:
            # 普通字面量 (如 888, vip, abc, -)
            lit = [ch.lower()]
            k = i + 1
            while k < n and s[k] not in ('(', '[', '?', 'L', 'D', 'V', 'C', '*'):
                lit.append(s[k].lower())
                k += 1
            lit_str = "".join(lit)
            slots.append([lit_str])
            i = k

    total = 1
    for slot in slots:
        total *= len(slot)
    return slots, total

def generate_template_domain(index, slots, suffix="com"):
    """
    O(1) 广义混合进制 (Mixed-Radix) 数学解码器：
    将任意全局索引映射为唯一的模板域名，零内存开销，瞬时随机定位
    """
    res = []
    curr = index
    for choices in reversed(slots):
        m = len(choices)
        res.append(choices[curr % m])
        curr //= m
    res.reverse()
    name = "".join(res)
    return f"{name}.{suffix}"

def get_template_range_generator(template_str, suffix, start_idx, end_idx):
    """
    模板分片生成器：支持多机分布式切片与工作窃取
    """
    slots, total = parse_template(template_str)
    for idx in range(start_idx, end_idx):
        yield generate_template_domain(idx, slots, suffix)

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

    tld = "net" if domain.lower().endswith(".net") else "com"
    url = f"https://rdap.verisign.com/{tld}/v1/domain/{domain}"
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

def has_consecutive_same(s, n=3, strict=True):
    name = clean_domain_name(s)
    if not name or not n:
        return False
    try:
        n = int(n)
    except Exception:
        return False
    L = len(name)
    if n < 2 or L < n:
        return False

    # 对于长词 (>=5)：若为 3 连号，必须在首部 (如 888xxx) 或尾部 (如 xxx888)；
    # 若在词中间出现，则要求至少连续 4 个相同 (如 x8888x) 才有收藏价值，避免 481119 这种乱码
    if strict and L >= 5 and n <= 3:
        if len(set(name[:3])) == 1 or len(set(name[-3:])) == 1:
            return True
        pattern = r"([a-z0-9])\1{3,}"
        return bool(re.search(pattern, name))

    pattern = r"([a-z0-9])\1{" + str(n - 1) + ",}"
    return bool(re.search(pattern, name))

def has_sequential(s, n=3, direction="any", strict=True):
    name = clean_domain_name(s)
    if not name or not n:
        return False
    try:
        n = int(n)
    except Exception:
        return False
    L = len(name)
    if n < 2 or L < n:
        return False

    req_len = n
    # 对于 5 位及以上较长域名，自适应提升顺子判定门槛，杜绝 812395 这种中间偶发 3 位小片段的乱码
    if strict and L >= 5 and req_len <= 3:
        req_len = 4

    check_asc = direction in ("asc", "any")
    check_desc = direction in ("desc", "any")

    if strict and L >= 5:
        # 首尾锚定或全词顺子 (例如 1234xx, xx1234, 123456)
        windows = [name[:req_len], name[-req_len:]]
    else:
        windows = [name[i:i + req_len] for i in range(L - req_len + 1)]

    for sub in windows:
        if check_asc and (sub.isalpha() or sub.isdigit()) and all(ord(sub[j]) + 1 == ord(sub[j + 1]) for j in range(len(sub) - 1)):
            return True
        if check_desc and (sub.isalpha() or sub.isdigit()) and all(ord(sub[j]) - 1 == ord(sub[j + 1]) for j in range(len(sub) - 1)):
            return True
    return False

def match_pattern(s, pat, strict=True):
    name = clean_domain_name(s)
    if not name or not pat:
        return False
    pat = pat.lower()
    if pat == "palindrome":
        return len(name) >= 3 and name == name[::-1]

    plen = len(pat)
    L = len(name)
    if L < plen:
        return False

    if L == plen:
        windows = [name]
    elif strict and L >= 5:
        # 5位以上精选词：必须是头部对子 (AABBxx) 或尾部对子 (xxAABB)，不能在内部游离匹配
        windows = [name[:plen], name[-plen:]]
    else:
        windows = [name[i:i + plen] for i in range(L - plen + 1)]

    for window in windows:
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
    strict = rules.get("strict", True)

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
        if rules.get("seq_asc") and has_sequential(clean_name, min_seq, "asc", strict=strict):
            return True
        if rules.get("seq_desc") and has_sequential(clean_name, min_seq, "desc", strict=strict):
            return True
        if rules.get("seq") and has_sequential(clean_name, min_seq, "any", strict=strict):
            return True

    # (c) 经典叠字结构 (AABB / ABAB / ABBA / AAAB / AAAA 等)
    pats = rules.get("patterns", [])
    if pats:
        has_sub_rules = True
        for p in pats:
            if match_pattern(clean_name, p, strict=strict):
                return True

    # (d) 连号 / 豹子 (连续相同字符 >= N，如 AAA)
    min_repeat = rules.get("min_repeat")
    if min_repeat and int(min_repeat) >= 2:
        has_sub_rules = True
        if has_consecutive_same(clean_name, int(min_repeat), strict=strict):
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

