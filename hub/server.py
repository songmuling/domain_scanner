#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Hub - 统一域名扫描集群 Master 控制中心 (Nezha 架构)
- 支持 Agent 自动发现与注册
- 支持 Token 安全握手鉴权
- 支持 Web 端多节点一键切片分发、启动、暂停、停止
- 支持实时多机进度条监控、扫速聚合、可用域名库与生命周期管理
- 纯 Python 3 标准库打造，零外部依赖
"""

import os
import sys
import ssl
import time
import re
import json
import sqlite3
import secrets
import urllib.request
import urllib.error
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone, timedelta
import threading

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
STATIC_DIR = os.path.join(BASE_DIR, "static")
DB_PATH = os.path.join(DATA_DIR, "domains.db")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

DB_LOCK = threading.Lock()

# 全局忽略部分特殊网络环境下的 SSL 证书校验错误
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def calc_domain_total(length, use_letters=True, use_digits=False, use_hyphen=False):
    """O(1) 计算任意规则下的候选域名空间全量"""
    chars = ""
    if use_letters:
        chars += "abcdefghijklmnopqrstuvwxyz"
    if use_digits:
        chars += "0123456789"
    if not chars:
        return 0
    pool_len = len(chars)
    base = pool_len ** length
    return base * (length - 1) if use_hyphen else base

def ensure_assignment_bounds(conn, row, task_row):
    """确保分片记录具备精准的 start_idx 和 end_idx 区间，无缝兼容历史运行中的旧任务"""
    if row["start_idx"] is not None and row["end_idx"] is not None:
        return row["start_idx"], row["end_idx"], row["total"]

    length = task_row["length"] if "length" in task_row.keys() and task_row["length"] is not None else 4
    use_letters = bool(task_row["use_letters"]) if "use_letters" in task_row.keys() and task_row["use_letters"] is not None else True
    use_digits = bool(task_row["use_digits"]) if "use_digits" in task_row.keys() and task_row["use_digits"] is not None else False
    use_hyphen = bool(task_row["use_hyphen"]) if "use_hyphen" in task_row.keys() and task_row["use_hyphen"] is not None else False

    total_all = calc_domain_total(length, use_letters, use_digits, use_hyphen)
    s_num = row["shard_num"]
    s_tot = row["shard_total"]
    if s_tot <= 0:
        s_tot = 1
    s_idx = ((s_num - 1) * total_all) // s_tot
    e_idx = (s_num * total_all) // s_tot
    tot = e_idx - s_idx

    conn.execute("""
    UPDATE task_assignments SET start_idx = ?, end_idx = ?, total = ?
    WHERE id = ?;
    """, (s_idx, e_idx, tot, row["id"]))
    conn.commit()
    return s_idx, e_idx, tot

def get_beijing_time_str():
    bj_tz = timezone(timedelta(hours=8))
    return datetime.now(bj_tz).strftime("%Y-%m-%d %H:%M:%S")

def clean_domain_name(s):
    if not s:
        return ""
    return s.split(".")[0].replace("-", "").lower()

VOWELS_SET = set("aeiou")
RARE_CONSONANTS_SET = set("qxzvy")

def analyze_domain_features(domain):
    clean_name = clean_domain_name(domain)
    if not clean_name:
        return {
            "max_repeat": 1, "max_seq": 1, "max_seq_asc": 1, "max_seq_desc": 1,
            "is_palindrome": 0, "patterns": "", "is_pronounceable": 0,
            "has_vowel": 0, "is_clean": 1
        }

    # 1. 最高连字 / 叠字 / 豹子
    max_rep = 1
    cur_rep = 1
    for i in range(1, len(clean_name)):
        if clean_name[i] == clean_name[i - 1]:
            cur_rep += 1
            if cur_rep > max_rep:
                max_rep = cur_rep
        else:
            cur_rep = 1

    # 2. 最高顺子 / 连号 (区分正序与倒序)
    max_asc = 1
    cur_asc = 1
    max_desc = 1
    cur_desc = 1
    for i in range(1, len(clean_name)):
        c1, c2 = clean_name[i - 1], clean_name[i]
        diff = ord(c2) - ord(c1)
        same_type = (c1.isalpha() and c2.isalpha()) or (c1.isdigit() and c2.isdigit())
        if same_type and diff == 1:
            cur_asc += 1
            if cur_asc > max_asc:
                max_asc = cur_asc
        else:
            cur_asc = 1

        if same_type and diff == -1:
            cur_desc += 1
            if cur_desc > max_desc:
                max_desc = cur_desc
        else:
            cur_desc = 1
    max_seq = max(max_asc, max_desc)

    # 3. 对称回文 (3字及以上)
    is_palindrome = 1 if (len(clean_name) >= 3 and clean_name == clean_name[::-1]) else 0

    # 4. 特殊形态结构 (AABB / ABAB / ABBA / AAAB / BAAA)
    matched_pats = []
    if len(clean_name) >= 4:
        for i in range(len(clean_name) - 3):
            w = clean_name[i:i + 4]
            c1, c2, c3, c4 = w[0], w[1], w[2], w[3]
            if c1 == c2 and c3 == c4 and c1 != c3 and "aabb" not in matched_pats:
                matched_pats.append("aabb")
            if c1 == c3 and c2 == c4 and c1 != c2 and "abab" not in matched_pats:
                matched_pats.append("abab")
            if c1 == c4 and c2 == c3 and c1 != c2 and "abba" not in matched_pats:
                matched_pats.append("abba")
            if c1 == c2 == c3 and c1 != c4 and "aaab" not in matched_pats:
                matched_pats.append("aaab")
            if c2 == c3 == c4 and c1 != c2 and "baaa" not in matched_pats:
                matched_pats.append("baaa")
    patterns_str = ",".join(matched_pats)

    # 5. 自然发音 / 易读双拼 (元辅交替，不连续出现>=3辅音或>=3元音)
    is_pron = 0
    if clean_name.isalpha() and len(clean_name) >= 3:
        is_pron = 1
        c_count = 0
        for ch in clean_name:
            if ch in VOWELS_SET:
                c_count = 0
            else:
                c_count += 1
                if c_count >= 3:
                    is_pron = 0
                    break
        if is_pron:
            v_count = 0
            for ch in clean_name:
                if ch in VOWELS_SET:
                    v_count += 1
                    if v_count >= 3:
                        is_pron = 0
                        break
                else:
                    v_count = 0
            if is_pron and not any(ch in VOWELS_SET for ch in clean_name):
                is_pron = 0

    # 6. 包含元音
    has_vowel = 1 if any(ch in VOWELS_SET for ch in clean_name) else 0

    # 7. 避冷门 (无生僻辅音 q, x, z, v, y)
    is_clean = 1 if not any(ch in RARE_CONSONANTS_SET for ch in clean_name) else 0

    return {
        "max_repeat": max_rep,
        "max_seq": max_seq,
        "max_seq_asc": max_asc,
        "max_seq_desc": max_desc,
        "is_palindrome": is_palindrome,
        "patterns": patterns_str,
        "is_pronounceable": is_pron,
        "has_vowel": has_vowel,
        "is_clean": is_clean
    }

def has_consecutive_same(s, n):
    name = clean_domain_name(s)
    if not name or not n:
        return 0
    try:
        n = int(n)
    except Exception:
        return 0
    if n < 2 or len(name) < n:
        return 0
    pattern = r"([a-z0-9])\1{" + str(n - 1) + ",}"
    return 1 if re.search(pattern, name) else 0

def has_sequential(s, n, direction="any"):
    name = clean_domain_name(s)
    if not name or not n:
        return 0
    try:
        n = int(n)
    except Exception:
        return 0
    if n < 2 or len(name) < n:
        return 0

    check_asc = direction in ("asc", "any")
    check_desc = direction in ("desc", "any")

    for i in range(len(name) - n + 1):
        sub = name[i:i + n]
        if check_asc and (sub.isalpha() or sub.isdigit()) and all(ord(sub[j]) + 1 == ord(sub[j + 1]) for j in range(n - 1)):
            return 1
        if check_desc and (sub.isalpha() or sub.isdigit()) and all(ord(sub[j]) - 1 == ord(sub[j + 1]) for j in range(n - 1)):
            return 1
    return 0

def match_pattern(s, pat):
    name = clean_domain_name(s)
    if not name or not pat:
        return 0
    pat = pat.lower()
    if pat == "palindrome":
        return 1 if len(name) >= 3 and name == name[::-1] else 0

    plen = len(pat)
    if len(name) < plen:
        return 0

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
            return 1
    return 0


def is_pronounceable(s):
    name = clean_domain_name(s)
    if not name.isalpha() or len(name) < 3:
        return 0
    c_count = 0
    for ch in name:
        if ch in VOWELS_SET:
            c_count = 0
        else:
            c_count += 1
            if c_count >= 3:
                return 0
    v_count = 0
    for ch in name:
        if ch in VOWELS_SET:
            v_count += 1
            if v_count >= 3:
                return 0
        else:
            v_count = 0
    return 1 if any(ch in VOWELS_SET for ch in name) else 0

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA cache_size = -65536;")      # 64MB 内存页缓存 (消除磁盘寻道，大幅加速百万级索引检索)
    conn.execute("PRAGMA mmap_size = 1073741824;")    # 1GB 虚拟内存零拷贝映射 (加速磁盘读取 5~10 倍)
    conn.execute("PRAGMA temp_store = MEMORY;")       # 临时表与中间排序放内存，杜绝临时磁盘 IO
    conn.execute("PRAGMA case_sensitive_like = ON;")  # 激活前缀 LIKE 命中主键 B-Tree 索引 (0.1ms 级极速前缀)
    conn.create_function("has_consecutive_same", 2, has_consecutive_same)
    conn.create_function("has_sequential", 3, has_sequential)
    conn.create_function("match_pattern", 2, match_pattern)
    conn.create_function("is_pronounceable", 1, is_pronounceable)
    return conn

def init_db_and_token():
    with DB_LOCK:
        with get_db() as conn:
            # 1. 域名资产表 (包含预计算特征索引字段)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS domains (
                domain TEXT PRIMARY KEY,
                mode TEXT,
                node_id TEXT,
                status TEXT DEFAULT 'available',
                is_starred INTEGER DEFAULT 0,
                reason TEXT,
                max_repeat INTEGER DEFAULT NULL,
                max_seq INTEGER DEFAULT NULL,
                max_seq_asc INTEGER DEFAULT NULL,
                max_seq_desc INTEGER DEFAULT NULL,
                is_palindrome INTEGER DEFAULT NULL,
                patterns TEXT DEFAULT NULL,
                is_pronounceable INTEGER DEFAULT NULL,
                has_vowel INTEGER DEFAULT NULL,
                is_clean INTEGER DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            # 2. 节点注册与心跳表
            conn.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                ip TEXT,
                os_info TEXT,
                agent_version TEXT,
                status TEXT DEFAULT 'idle',
                current_task_id TEXT,
                mode TEXT,
                shard TEXT,
                scanned INTEGER DEFAULT 0,
                total INTEGER DEFAULT 0,
                speed REAL DEFAULT 0.0,
                available_count INTEGER DEFAULT 0,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            # 3. 扫描任务表 (Master 下发任务)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                mode TEXT,
                suffix TEXT DEFAULT 'com',
                threads INTEGER DEFAULT 25,
                target_nodes TEXT,
                status TEXT DEFAULT 'running',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            # 4. 任务节点分片分配表
            conn.execute("""
            CREATE TABLE IF NOT EXISTS task_assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT,
                node_id TEXT,
                shard_num INTEGER,
                shard_total INTEGER,
                status TEXT DEFAULT 'pending',
                scanned INTEGER DEFAULT 0,
                total INTEGER DEFAULT 0,
                speed REAL DEFAULT 0.0,
                available_count INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(task_id, node_id)
            );
            """)

            # 5. 系统全局配置表 (存储自生成的安全 Token 等)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_mode ON domains(mode);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_created ON domains(created_at);")
            # 极速复合索引：直击高频列表与分页查询，彻底消除百万级全表排序
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_status_created ON domains(status, created_at DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_starred_created ON domains(is_starred, created_at DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_mode_status_created ON domains(mode, status, created_at DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_status_mode ON domains(status, mode);")

            # FTS5 Trigram 全文检索虚拟表 (外部内容表模式，仅存倒排三元索引，磁盘零冗余)
            conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS domains_fts USING fts5(
                domain,
                content='domains',
                content_rowid='rowid',
                tokenize='trigram'
            );
            """)
            conn.execute("""
            CREATE TRIGGER IF NOT EXISTS domains_ai AFTER INSERT ON domains BEGIN
                INSERT INTO domains_fts(rowid, domain) VALUES (new.rowid, new.domain);
            END;
            """)
            conn.execute("""
            CREATE TRIGGER IF NOT EXISTS domains_ad AFTER DELETE ON domains BEGIN
                INSERT INTO domains_fts(domains_fts, rowid, domain) VALUES('delete', old.rowid, old.domain);
            END;
            """)

            # 自动迁移 domains 表增加 is_starred 与特征预计算字段
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(domains);")
            domain_cols = {row["name"] for row in cur.fetchall()}
            if "is_starred" not in domain_cols:
                try:
                    conn.execute("ALTER TABLE domains ADD COLUMN is_starred INTEGER DEFAULT 0;")
                    conn.execute("UPDATE domains SET is_starred = 1, status = 'available' WHERE status = 'starred';")
                    conn.execute("UPDATE domains SET status = 'available' WHERE status IN ('purchased', 'discarded');")
                except Exception:
                    pass
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_starred ON domains(is_starred);")

            feature_cols = [
                ("max_repeat", "INTEGER DEFAULT NULL"),
                ("max_seq", "INTEGER DEFAULT NULL"),
                ("max_seq_asc", "INTEGER DEFAULT NULL"),
                ("max_seq_desc", "INTEGER DEFAULT NULL"),
                ("is_palindrome", "INTEGER DEFAULT NULL"),
                ("patterns", "TEXT DEFAULT NULL"),
                ("is_pronounceable", "INTEGER DEFAULT NULL"),
                ("has_vowel", "INTEGER DEFAULT NULL"),
                ("is_clean", "INTEGER DEFAULT NULL"),
            ]
            for col, col_type in feature_cols:
                if col not in domain_cols:
                    try:
                        conn.execute(f"ALTER TABLE domains ADD COLUMN {col} {col_type};")
                    except Exception:
                        pass

            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_repeat ON domains(max_repeat);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_seq ON domains(max_seq);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_seq_asc ON domains(max_seq_asc);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_seq_desc ON domains(max_seq_desc);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_pronounce ON domains(is_pronounceable);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_palindrome ON domains(is_palindrome);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_vowel ON domains(has_vowel);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_clean ON domains(is_clean);")

            # 自动迁移 nodes 旧表结构
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(nodes);")
            existing_cols = {row["name"] for row in cur.fetchall()}
            for col, col_type in [
                ("ip", "TEXT"), ("os_info", "TEXT"), ("agent_version", "TEXT"),
                ("current_task_id", "TEXT"), ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
                ("agent_uuid", "TEXT")
            ]:
                if col not in existing_cols:
                    try:
                        conn.execute(f"ALTER TABLE nodes ADD COLUMN {col} {col_type};")
                    except Exception:
                        pass

            try:
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_agent_uuid ON nodes(agent_uuid) WHERE agent_uuid IS NOT NULL;")
            except Exception:
                pass

            # 自动迁移 tasks 旧表结构
            cur.execute("PRAGMA table_info(tasks);")
            task_cols = {row["name"] for row in cur.fetchall()}
            for col, col_type in [
                ("length", "INTEGER DEFAULT 4"),
                ("use_letters", "BOOLEAN DEFAULT 1"),
                ("use_digits", "BOOLEAN DEFAULT 0"),
                ("use_hyphen", "BOOLEAN DEFAULT 0"),
                ("reset_checkpoint", "BOOLEAN DEFAULT 0"),
                ("is_aid", "INTEGER DEFAULT 0"),
                ("parent_task_id", "TEXT DEFAULT NULL")
            ]:
                if col not in task_cols:
                    try:
                        conn.execute(f"ALTER TABLE tasks ADD COLUMN {col} {col_type};")
                    except Exception:
                        pass

            # 自动迁移 task_assignments 旧表结构
            cur.execute("PRAGMA table_info(task_assignments);")
            assign_cols = {row["name"] for row in cur.fetchall()}
            for col, col_type in [
                ("start_idx", "INTEGER DEFAULT NULL"),
                ("end_idx", "INTEGER DEFAULT NULL"),
                ("is_aid", "INTEGER DEFAULT 0"),
                ("aid_for", "TEXT DEFAULT NULL"),
                ("parent_task_id", "TEXT DEFAULT NULL")
            ]:
                if col not in assign_cols:
                    try:
                        conn.execute(f"ALTER TABLE task_assignments ADD COLUMN {col} {col_type};")
                    except Exception:
                        pass

            # 自动校准被尾部窃取分片的 total (确保与 end_idx - start_idx 严格一致，防止被心跳冲刷覆盖)
            conn.execute("""
            UPDATE task_assignments
            SET total = (end_idx - start_idx)
            WHERE start_idx IS NOT NULL AND end_idx IS NOT NULL AND total != (end_idx - start_idx);
            """)

            # 确保 Master Token 存在
            env_token = os.environ.get("HUB_TOKEN", "").strip()
            cur = conn.cursor()
            cur.execute("SELECT value FROM system_config WHERE key = 'agent_token';")
            row = cur.fetchone()

            if env_token:
                final_token = env_token
                conn.execute("""
                INSERT INTO system_config (key, value, updated_at) VALUES ('agent_token', ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP;
                """, (final_token,))
            elif row and row[0]:
                final_token = row[0]
            else:
                final_token = secrets.token_hex(16)
                conn.execute("INSERT INTO system_config (key, value) VALUES ('agent_token', ?);", (final_token,))

            conn.commit()
            return final_token

def resolve_node_identity(conn, node_id, agent_uuid):
    """
    双轨节点物理身份决议 (UUID 指纹 + 可读别名绑定):
    1. 若未上报 agent_uuid，保持旧版逻辑直接返回 node_id
    2. 若提供 agent_uuid:
       - 查该 UUID 是否已绑定过某节点名:
         - 若存在，且旧名 != 当前请求 node_id:
           - 检查新名字是否被其他不同 UUID 的节点占用
           - 若未被占用，无缝热改名！同步更新 nodes 和 task_assignments，返回新 node_id
           - 若被占用，自动追加后缀保护: {node_id}_{agent_uuid[-4:]}
         - 若存在且名字未变: 直接返回该名字
       - 若数据库尚未记录该 UUID:
         - 检查当前请求的 node_id 是否已存在且 agent_uuid 为空 (升级平滑静默认领):
           - 绑定该 agent_uuid 到当前 node_id，返回当前 node_id
         - 检查当前请求的 node_id 是否已被其他 UUID 占用:
           - 若已被占用，分配安全别名: {node_id}_{agent_uuid[-4:]}
         - 若 node_id 完全不存在:
           - 正常接纳新节点
    返回: (effective_node_id, bound_agent_uuid)
    """
    if not agent_uuid:
        return node_id, None

    cur = conn.cursor()
    cur.execute("SELECT node_id, agent_uuid FROM nodes WHERE agent_uuid = ?;", (agent_uuid,))
    node_by_uuid = cur.fetchone()

    cur.execute("SELECT node_id, agent_uuid FROM nodes WHERE node_id = ?;", (node_id,))
    node_by_id = cur.fetchone()

    if node_by_uuid:
        old_name = node_by_uuid["node_id"]
        if old_name != node_id:
            # 节点改名场景
            if node_by_id and node_by_id["agent_uuid"] and node_by_id["agent_uuid"] != agent_uuid:
                assigned_name = f"{node_id}_{agent_uuid[-4:]}"
                conn.execute("UPDATE nodes SET node_id = ? WHERE agent_uuid = ?;", (assigned_name, agent_uuid))
                conn.execute("UPDATE task_assignments SET node_id = ? WHERE node_id = ?;", (assigned_name, old_name))
                return assigned_name, agent_uuid
            else:
                conn.execute("UPDATE nodes SET node_id = ? WHERE agent_uuid = ?;", (node_id, agent_uuid))
                conn.execute("UPDATE task_assignments SET node_id = ? WHERE node_id = ?;", (node_id, old_name))
                return node_id, agent_uuid
        return old_name, agent_uuid

    # 首次接入此 UUID
    if node_by_id:
        if not node_by_id["agent_uuid"]:
            # 初次升级静默认领绑定
            conn.execute("UPDATE nodes SET agent_uuid = ? WHERE node_id = ?;", (agent_uuid, node_id))
            return node_id, agent_uuid
        else:
            # 重名冲突，分配防碰撞后缀
            assigned_name = f"{node_id}_{agent_uuid[-4:]}"
            return assigned_name, agent_uuid

    return node_id, agent_uuid

def start_feature_backfill_worker():
    """后台异步计算并补齐存量历史资产的特征索引字段，毫秒级无锁分批，不阻塞主服务"""
    def _worker():
        time.sleep(1.0)
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM domains WHERE max_repeat IS NULL;")
                unindexed_cnt = cur.fetchone()[0]

            if unindexed_cnt == 0:
                return

            print(f"[{get_beijing_time_str()}] 正在后台为 {unindexed_cnt:,} 个存量资产预计算特征索引 (连字/顺子/回文/双拼/冷门)...")
            batch_size = 5000
            processed = 0
            t0 = time.time()

            while True:
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT domain FROM domains WHERE max_repeat IS NULL LIMIT ?;", (batch_size,))
                    rows = cur.fetchall()
                    if not rows:
                        break

                    updates = []
                    for r in rows:
                        d_name = r["domain"]
                        f = analyze_domain_features(d_name)
                        updates.append((
                            f["max_repeat"],
                            f["max_seq"],
                            f["max_seq_asc"],
                            f["max_seq_desc"],
                            f["is_palindrome"],
                            f["patterns"],
                            f["is_pronounceable"],
                            f["has_vowel"],
                            f["is_clean"],
                            d_name
                        ))

                    conn.executemany("""
                    UPDATE domains SET
                        max_repeat = ?,
                        max_seq = ?,
                        max_seq_asc = ?,
                        max_seq_desc = ?,
                        is_palindrome = ?,
                        patterns = ?,
                        is_pronounceable = ?,
                        has_vowel = ?,
                        is_clean = ?
                    WHERE domain = ?;
                    """, updates)
                    conn.commit()
                    processed += len(updates)
                    if processed % 50000 == 0 or processed >= unindexed_cnt:
                        pct = min(100, int((processed / unindexed_cnt) * 100))
                        print(f"[{get_beijing_time_str()}] 存量特征索引计算进度: {processed:,} / {unindexed_cnt:,} ({pct}%)")

                time.sleep(0.05)  # 每次微让出锁 50ms，确保节点扫描上报零等待

            cost = round(time.time() - t0, 2)
            print(f"[{get_beijing_time_str()}] 存量资产特征索引构建完成！共处理 {processed:,} 条记录，耗时 {cost} 秒。")
        except Exception as e:
            sys.stderr.write(f"[{get_beijing_time_str()}] 特征索引后台构建异常: {e}\n")

    threading.Thread(target=_worker, daemon=True).start()

def start_wal_checkpoint_worker():
    """定期后台异步平滑冲刷 WAL，防止日志文件无限膨胀（保持在几兆以内，极大消除读放大）"""
    def _checkpoint_loop():
        while True:
            time.sleep(30)
            try:
                with DB_LOCK:
                    with get_db() as conn:
                        conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
            except Exception:
                pass
    t = threading.Thread(target=_checkpoint_loop, daemon=True)
    t.start()

# 大屏与资产统计实时内存镜像缓存 (由后台轻量守护线程预计算，API 0 毫秒内存直出)
_STATS_LOCK = threading.Lock()
_CACHED_DOMAIN_STATS = {
    "total_available": 0,
    "total_starred": 0,
    "total_purchased": 0,
    "total_registered": 0,
    "today_found": 0,
    "mode_stats": {}
}

def start_stats_aggregator_worker():
    """后台轻量定时预计算全表大盘统计（每 4 秒刷新一次），彻底终结 HTTP 请求中的百万行锁竞争与等待"""
    def _loop():
        # 启动后微延时 0.5s 立即预热第一轮
        time.sleep(0.5)
        while True:
            try:
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT 
                            COUNT(CASE WHEN status = 'available' THEN 1 END),
                            COUNT(CASE WHEN is_starred = 1 THEN 1 END),
                            COUNT(CASE WHEN status = 'purchased' THEN 1 END),
                            COUNT(CASE WHEN status = 'registered' THEN 1 END)
                        FROM domains;
                    """)
                    c_row = cur.fetchone()

                    cur.execute("SELECT COUNT(*) FROM domains WHERE created_at >= datetime(date('now', '+8 hours'), '-8 hours');")
                    t_found = cur.fetchone()[0]

                    # 走 idx_domains_status_mode 覆盖索引快速分组
                    cur.execute("SELECT mode, COUNT(*) as cnt FROM domains WHERE status = 'available' GROUP BY mode;")
                    m_stats = {row["mode"] or "unknown": row["cnt"] for row in cur.fetchall()}

                    with _STATS_LOCK:
                        _CACHED_DOMAIN_STATS["total_available"] = c_row[0]
                        _CACHED_DOMAIN_STATS["total_starred"] = c_row[1]
                        _CACHED_DOMAIN_STATS["total_purchased"] = c_row[2]
                        _CACHED_DOMAIN_STATS["total_registered"] = c_row[3]
                        _CACHED_DOMAIN_STATS["today_found"] = t_found
                        _CACHED_DOMAIN_STATS["mode_stats"] = m_stats
            except Exception:
                pass
            time.sleep(4.0)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

def start_fts_backfill_worker():
    """后台异步为存量历史资产构建 FTS5 Trigram 全文检索索引，平滑分批，不阻塞主服务与节点扫描"""
    def _worker():
        time.sleep(2.0)
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM domains_fts;")
                indexed_cnt = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM domains;")
                total_cnt = cur.fetchone()[0]

            if indexed_cnt >= total_cnt and total_cnt > 0:
                return

            print(f"[{get_beijing_time_str()}] 正在后台初始化构建 FTS5 全文倒排索引 (存量 {total_cnt:,} 个域名)...")
            batch_size = 50000
            t0 = time.time()
            last_rowid = 0
            processed = indexed_cnt

            while True:
                with DB_LOCK:
                    with get_db() as conn:
                        cur = conn.cursor()
                        cur.execute("SELECT rowid, domain FROM domains WHERE rowid > ? ORDER BY rowid ASC LIMIT ?;", (last_rowid, batch_size))
                        rows = cur.fetchall()
                        if not rows:
                            break
                        last_rowid = rows[-1]["rowid"]
                        conn.executemany("INSERT OR IGNORE INTO domains_fts(rowid, domain) VALUES (?, ?);", [(r["rowid"], r["domain"]) for r in rows])
                        conn.commit()
                        processed += len(rows)
                        if processed % 200000 == 0 or processed >= total_cnt:
                            pct = min(100, int((processed / total_cnt) * 100)) if total_cnt > 0 else 100
                            print(f"[{get_beijing_time_str()}] FTS5 全文索引构建进度: {processed:,} / {total_cnt:,} ({pct}%)")

                time.sleep(0.05)  # 每次微让出锁 50ms，确保扫描节点入库零等待

            cost = round(time.time() - t0, 2)
            print(f"[{get_beijing_time_str()}] FTS5 全文检索索引构建完成！共处理 {processed:,} 条记录，耗时 {cost} 秒。")
        except Exception as e:
            sys.stderr.write(f"[{get_beijing_time_str()}] FTS索引后台构建异常: {e}\n")

    threading.Thread(target=_worker, daemon=True).start()

MASTER_TOKEN = init_db_and_token()
print(f"[{get_beijing_time_str()}] Domain Hub 核心数据库已就绪，当前集群通信 Token: {MASTER_TOKEN}")
start_feature_backfill_worker()
start_wal_checkpoint_worker()
start_stats_aggregator_worker()
start_fts_backfill_worker()

def get_current_token():
    env_token = os.environ.get("HUB_TOKEN", "").strip()
    if env_token:
        return env_token
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM system_config WHERE key = 'agent_token';")
        row = cur.fetchone()
        return row[0] if row else MASTER_TOKEN

def check_verisign_rdap(domain):
    """权威复检：查询 Verisign 官方 RDAP (携带 SSL 优化与快速超时)"""
    url = f"https://rdap.verisign.com/com/v1/domain/{domain.lower()}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "DomainHub-Verifier/1.0", "Accept": "application/rdap+json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=3.5, context=ssl_context) as resp:
            if resp.status == 200:
                return False, "已注册 (RDAP返回200)"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True, "未注册 (RDAP返回404)"
        return False, f"HTTP状态: {e.code}"
    except Exception as e:
        return False, f"网络错误: {str(e)}"
    return False, "未知状态"

def inspect_domain_rdap(domain):
    """单域名权威穿透深度查验 (Verisign RDAP 权威根库，支持详细注册商与时间节点解析)"""
    url = f"https://rdap.verisign.com/com/v1/domain/{domain.lower()}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "DomainHub-Inspector/2.0", "Accept": "application/rdap+json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0, context=ssl_context) as resp:
            if resp.status == 200:
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)

                # 解析注册商 Registrar
                registrar = "未知注册商"
                for ent in data.get("entities", []):
                    if "registrar" in ent.get("roles", []):
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if len(item) > 3 and item[0] == "fn":
                                    registrar = item[3]
                                    break

                # 解析关键时间节点 Events
                events = {}
                for ev in data.get("events", []):
                    action = ev.get("eventAction", "")
                    date_val = ev.get("eventDate", "")
                    if action and date_val:
                        clean_date = date_val.replace("T", " ").replace("Z", "").split(".")[0]
                        events[action] = clean_date

                # 解析 DNS Nameservers
                nameservers = []
                for ns in data.get("nameservers", []):
                    ns_name = ns.get("ldhName")
                    if ns_name:
                        nameservers.append(ns_name.lower())

                # 解析域名状态
                statuses = data.get("status", [])

                return {
                    "available": False,
                    "reason": f"已注册 · 注册商: {registrar}",
                    "rdap": {
                        "registrar": registrar,
                        "created_at": events.get("registration", ""),
                        "expires_at": events.get("expiration", ""),
                        "updated_at": events.get("last changed", ""),
                        "nameservers": nameservers,
                        "statuses": statuses
                    }
                }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "available": True,
                "reason": "404 权威未注册 (可立即抢注)",
                "rdap": None
            }
        elif e.code == 429:
            return {
                "available": None,
                "error": "Verisign RDAP 接口触发访问频率限制，请稍候重试",
                "reason": "429 访问受限"
            }
        return {
            "available": None,
            "error": f"RDAP 权威根服务器返回 HTTP {e.code}",
            "reason": f"HTTP {e.code}"
        }
    except Exception as e:
        return {
            "available": None,
            "error": f"网络连线异常: {str(e)}",
            "reason": "网络异常"
        }
    return {
        "available": None,
        "error": "未能获取权威状态",
        "reason": "未知异常"
    }

def resolve_candidate_modes(selected_lengths, chk_letter, chk_digit, chk_hyphen):
    """根据多选长度和字符组成，精准解析为数据库标准 mode 列表，直接命中复合覆盖索引"""
    all_or_none = (chk_letter and chk_digit and chk_hyphen) or (not chk_letter and not chk_digit and not chk_hyphen)

    if all_or_none:
        types = ["letter", "num", "mix", "letter-", "num-", "mix-"]
    else:
        bases = []
        if chk_letter and chk_digit:
            bases = ["letter", "num", "mix"]
        elif chk_letter:
            bases = ["letter"]
        elif chk_digit:
            bases = ["num"]
        else:
            bases = ["letter", "num", "mix"]

        if chk_hyphen:
            types = [f"{b}-" for b in bases]
        else:
            types = bases

    target_lengths = selected_lengths if selected_lengths else [3, 4, 5, 6, 7, 8]
    modes = []
    for l in target_lengths:
        for t in types:
            modes.append(f"{l}{t}")
    return modes

BATCH_RECHECK_STATE = {
    "is_running": False,
    "mode": "",
    "total": 0,
    "checked": 0,
    "taken": 0,
    "still_available": 0,
    "current_domain": "",
    "started_at": None,
    "finished_at": None
}

def start_batch_recheck(mode="all"):
    global BATCH_RECHECK_STATE
    if BATCH_RECHECK_STATE["is_running"]:
        return False, "已有正在执行的批量复验任务"

    with get_db() as conn:
        cur = conn.cursor()
        if mode and mode != "all":
            cur.execute("SELECT domain FROM domains WHERE status = 'available' AND mode = ?;", (mode,))
        else:
            cur.execute("SELECT domain FROM domains WHERE status = 'available';")
        target_domains = [row["domain"] for row in cur.fetchall()]

    if not target_domains:
        return False, "当前模式下没有可复核的未注册域名"

    BATCH_RECHECK_STATE = {
        "is_running": True,
        "mode": mode,
        "total": len(target_domains),
        "checked": 0,
        "taken": 0,
        "still_available": 0,
        "current_domain": "",
        "started_at": datetime.now().isoformat(),
        "finished_at": None
    }

    def _worker():
        global BATCH_RECHECK_STATE
        import concurrent.futures

        batch_buffer = []

        def flush_batch(items):
            if not items:
                return
            with get_db() as conn:
                for dom, is_avail, reason in items:
                    if not is_avail:
                        conn.execute("""
                        UPDATE domains SET status = 'registered', reason = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE domain = ?;
                        """, (reason, dom))
                    else:
                        conn.execute("""
                        UPDATE domains SET reason = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE domain = ?;
                        """, (reason, dom))
                conn.commit()

        try:
            max_workers = 15
            max_in_flight = 25
            in_flight = {}

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                for d in target_domains:
                    if not BATCH_RECHECK_STATE["is_running"]:
                        break

                    fut = executor.submit(check_verisign_rdap, d)
                    in_flight[fut] = d

                    if len(in_flight) >= max_in_flight:
                        done, _ = concurrent.futures.wait(
                            in_flight.keys(), return_when=concurrent.futures.FIRST_COMPLETED
                        )
                        for f in done:
                            dom = in_flight.pop(f)
                            BATCH_RECHECK_STATE["current_domain"] = dom
                            try:
                                is_avail, reason = f.result()
                            except Exception:
                                is_avail, reason = True, "复验异常跳过"

                            BATCH_RECHECK_STATE["checked"] += 1
                            if not is_avail:
                                BATCH_RECHECK_STATE["taken"] += 1
                            else:
                                BATCH_RECHECK_STATE["still_available"] += 1
                            batch_buffer.append((dom, is_avail, reason))

                            if len(batch_buffer) >= 50:
                                flush_batch(batch_buffer)
                                batch_buffer.clear()

                # 处理队列中剩余任务
                while in_flight:
                    done, _ = concurrent.futures.wait(
                        in_flight.keys(), return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    for f in done:
                        dom = in_flight.pop(f)
                        BATCH_RECHECK_STATE["current_domain"] = dom
                        try:
                            is_avail, reason = f.result()
                        except Exception:
                            is_avail, reason = True, "复验异常跳过"

                        BATCH_RECHECK_STATE["checked"] += 1
                        if not is_avail:
                            BATCH_RECHECK_STATE["taken"] += 1
                        else:
                            BATCH_RECHECK_STATE["still_available"] += 1
                        batch_buffer.append((dom, is_avail, reason))

                        if len(batch_buffer) >= 50:
                            flush_batch(batch_buffer)
                            batch_buffer.clear()

                if batch_buffer:
                    flush_batch(batch_buffer)
                    batch_buffer.clear()
        finally:
            BATCH_RECHECK_STATE["is_running"] = False
            BATCH_RECHECK_STATE["finished_at"] = datetime.now().isoformat()

    threading.Thread(target=_worker, daemon=True).start()
    return True, f"已启动对 {len(target_domains)} 个存量域名的权威复验"

def build_domain_filters(params):
    mode = params.get("mode", [""])[0]
    status = params.get("status", ["available"])[0]
    search = params.get("q", [""])[0].strip().lower()
    has_vowel = params.get("has_vowel", ["0"])[0] == "1"
    exclude_rare = params.get("exclude_rare", ["0"])[0] == "1"
    prefix = params.get("prefix", [""])[0].strip().lower()
    suffix = params.get("suffix", [""])[0].strip().lower()

    where_clauses = []
    bind_params = []

    # 1. 收藏过滤与基础状态
    only_starred = params.get("starred", ["0"])[0] in ("1", "true") or status == "starred"
    if only_starred:
        where_clauses.append("is_starred = 1")
    elif status != "all":
        where_clauses.append("status = ?")
        bind_params.append(status)

    # 2. 字符位数与字符组成联合维度优化 (直接映射到标准 mode 联合索引，杜绝千万行全表扫描与字符串计算)
    raw_lengths = params.get("lengths", []) + params.get("length", [])
    selected_lengths = []
    for item in raw_lengths:
        for part in str(item).split(","):
            part = part.strip()
            if part.isdigit():
                selected_lengths.append(int(part))
    selected_lengths = sorted(list(set(selected_lengths)))

    has_new_char_param = "letters" in params or "digits" in params or "hyphen" in params
    if has_new_char_param:
        chk_letter = params.get("letters", ["0"])[0] in ("1", "true")
        chk_digit = params.get("digits", ["0"])[0] in ("1", "true")
        chk_hyphen = params.get("hyphen", ["0"])[0] in ("1", "true")
    else:
        char_type_param = params.get("char_type", [""])[0].strip()
        leg_hyphen = params.get("has_hyphen", [""])[0].strip()
        chk_letter = char_type_param in ("letter", "mix")
        chk_digit = char_type_param in ("num", "mix")
        chk_hyphen = leg_hyphen == "1"

    all_or_none = (chk_letter and chk_digit and chk_hyphen) or (not chk_letter and not chk_digit and not chk_hyphen)

    if selected_lengths or not all_or_none:
        c_modes = resolve_candidate_modes(selected_lengths, chk_letter, chk_digit, chk_hyphen)
        if c_modes:
            placeholders = ",".join("?" for _ in c_modes)
            where_clauses.append(f"mode IN ({placeholders})")
            bind_params.extend(c_modes)
    elif mode and mode != "all":
        where_clauses.append("mode = ?")
        bind_params.append(mode)

    # 4. 关键字及前后缀
    if search:
        # FTS5 Trigram 全文检索极速通道：彻底消除百万级全表扫描，将模糊包含检索从数秒提速至毫秒级
        where_clauses.append("domains.rowid IN (SELECT rowid FROM domains_fts WHERE domain LIKE ?)")
        bind_params.append(f"%{search}%")

    if prefix:
        where_clauses.append("domains.rowid IN (SELECT rowid FROM domains_fts WHERE domain LIKE ?)")
        bind_params.append(f"{prefix}%")

    if suffix:
        where_clauses.append("domains.rowid IN (SELECT rowid FROM domains_fts WHERE domain LIKE ?)")
        bind_params.append(f"%{suffix}.com")

    # 5. 淘金规则：包含元音 / 剔除生僻声母 (利用预计算索引快速过滤)
    if has_vowel:
        where_clauses.append("has_vowel = 1")
    if exclude_rare:
        where_clauses.append("is_clean = 1")

    # 6. 靓号规则：连字 (豹子/叠字 N 连字，例如选 3 匹配 aaa, 888 等，直接命中 B-Tree 索引)
    repeat_count = params.get("repeat_count", [""])[0].strip()
    if repeat_count.isdigit() and int(repeat_count) >= 2:
        where_clauses.append("max_repeat >= ?")
        bind_params.append(int(repeat_count))

    # 7. 靓号规则：连号 (顺子 N 连号，支持正序/倒序/双向，例如选 3 匹配 123/abc/cba/321 等，直接命中 B-Tree 索引)
    seq_count = params.get("seq_count", [""])[0].strip()
    seq_dir = params.get("seq_dir", ["any"])[0].strip().lower()
    if seq_count.isdigit() and int(seq_count) >= 2:
        s_cnt = int(seq_count)
        if seq_dir == "asc":
            where_clauses.append("max_seq_asc >= ?")
            bind_params.append(s_cnt)
        elif seq_dir == "desc":
            where_clauses.append("max_seq_desc >= ?")
            bind_params.append(s_cnt)
        else:
            where_clauses.append("max_seq >= ?")
            bind_params.append(s_cnt)

    # 8. 靓号规则：形态结构 (回文 palindrome, AABB, ABAB, ABBA, AAAB, BAAA 等)
    pattern = params.get("pattern", [""])[0].strip().lower()
    if pattern:
        if pattern == "palindrome":
            where_clauses.append("is_palindrome = 1")
        else:
            where_clauses.append("patterns LIKE ?")
            bind_params.append(f"%{pattern}%")

    # 9. 靓号规则：自然发音 (易读元音辅音交替双拼)
    pronounceable = params.get("pronounceable", ["0"])[0] == "1"
    if pronounceable:
        where_clauses.append("is_pronounceable = 1")

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    return where_sql, bind_params

class HubHandler(BaseHTTPRequestHandler):
    server_version = "DomainHub-Master/2.0"

    def log_message(self, format, *args):
        if self.path.startswith("/api/agent/heartbeat"):
            return
        sys.stderr.write(f"[{get_beijing_time_str()}] {self.address_string()} - {format % args}\n")

    def send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Hub-Token")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Hub-Token")
        self.end_headers()

    def read_json_body(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                return {}
            body = self.rfile.read(content_length).decode("utf-8")
            return json.loads(body)
        except Exception as e:
            sys.stderr.write(f"JSON解析异常: {e}\n")
            return {}

    def verify_agent_token(self):
        """校验 Agent 携带的 Bearer Token 或 X-Hub-Token"""
        expected = get_current_token()
        auth_hdr = self.headers.get("Authorization", "").strip()
        custom_hdr = self.headers.get("X-Hub-Token", "").strip()

        token = ""
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
        elif custom_hdr:
            token = custom_hdr

        if not token or token != expected:
            return False
        return True

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # 1. 静态主页与资源文件服务 (全面支持本地化 js/css)
        clean_path = path.lstrip("/")
        if clean_path.startswith("static/"):
            clean_path = clean_path[len("static/"):]

        if path in ("", "/", "/index.html"):
            clean_path = "index.html"

        static_file = os.path.join(STATIC_DIR, clean_path)
        if os.path.isfile(static_file):
            content_type = "application/octet-stream"
            if static_file.endswith(".html"): content_type = "text/html; charset=utf-8"
            elif static_file.endswith(".js"): content_type = "application/javascript; charset=utf-8"
            elif static_file.endswith(".css"): content_type = "text/css; charset=utf-8"
            elif static_file.endswith(".json"): content_type = "application/json; charset=utf-8"
            elif static_file.endswith(".svg"): content_type = "image/svg+xml"

            with open(static_file, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            if static_file.endswith(".html"):
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            else:
                self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(content)
            return

        # 2. 统计概览 API
        if path == "/api/stats":
            with _STATS_LOCK:
                cached = dict(_CACHED_DOMAIN_STATS)
            total_available = cached["total_available"]
            total_starred = cached["total_starred"]
            total_purchased = cached["total_purchased"]
            total_registered = cached["total_registered"]
            today_found = cached["today_found"]
            mode_stats = cached["mode_stats"]

            with get_db() as conn:
                cur = conn.cursor()
                # 30秒内有心跳视为在线 (轻量 nodes 表)
                cur.execute("SELECT COUNT(*), COALESCE(SUM(speed), 0) FROM nodes WHERE (strftime('%s', 'now') - strftime('%s', last_seen)) <= 30 AND status = 'running';")
                active_row = cur.fetchone()
                active_nodes = active_row[0]
                total_speed = round(active_row[1], 1)

                # 全局活跃任务列表 (轻量 tasks 表)
                cur.execute("""
                SELECT t.task_id, t.mode, t.suffix, t.threads, t.status, datetime(t.created_at, '+8 hours') as created_at,
                       COUNT(DISTINCT a.id) as total_shards,
                       SUM(CASE WHEN a.status = 'running' THEN 1 ELSE 0 END) as running_shards,
                       SUM(CASE WHEN a.status = 'completed' THEN 1 ELSE 0 END) as completed_shards,
                       COALESCE(SUM(a.scanned), 0) as scanned,
                       COALESCE(SUM(a.total), 0) as total,
                       COALESCE(SUM(a.speed), 0) as speed,
                       COALESCE(SUM(a.available_count), 0) as available_count
                FROM tasks t
                LEFT JOIN task_assignments a ON (t.task_id = a.task_id OR t.task_id = a.parent_task_id)
                WHERE t.status = 'running' AND (t.is_aid = 0 OR t.is_aid IS NULL)
                GROUP BY t.task_id
                ORDER BY t.created_at DESC;
                """)
                active_tasks = []
                for row in cur.fetchall():
                    item = dict(row)
                    sc = item.get("scanned", 0) or 0
                    tt = item.get("total", 0) or 0
                    item["progress_pct"] = round((sc / tt * 100), 1) if tt > 0 else 0.0
                    item["speed"] = round(item.get("speed", 0.0) or 0.0, 1)
                    active_tasks.append(item)

                active_task = active_tasks[0] if active_tasks else None

            self.send_json({
                "code": 0,
                "data": {
                    "total_available": total_available,
                    "total_starred": total_starred,
                    "total_purchased": total_purchased,
                    "total_registered": total_registered,
                    "today_found": today_found,
                    "mode_stats": mode_stats,
                    "active_nodes": active_nodes,
                    "total_speed": total_speed,
                    "active_task": active_task,
                    "active_tasks": active_tasks
                }
            })
            return

        # 3. 节点列表 API
        if path == "/api/nodes":
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                SELECT 
                    node_id, ip, os_info, agent_version, agent_uuid, status, current_task_id,
                    mode, shard, scanned, total, speed, available_count,
                    last_seen,
                    (strftime('%s', 'now') - strftime('%s', last_seen)) as idle_sec
                FROM nodes
                ORDER BY node_id ASC;
                """)
                nodes = []
                for row in cur.fetchall():
                    idle = row["idle_sec"]
                    is_online = idle <= 35
                    effective_status = row["status"] if is_online else "offline"
                    nodes.append({
                        "node_id": row["node_id"],
                        "agent_uuid": row["agent_uuid"] or "",
                        "ip": row["ip"] or "",
                        "os_info": row["os_info"] or "",
                        "agent_version": row["agent_version"] or "1.0",
                        "status": effective_status,
                        "current_task_id": row["current_task_id"],
                        "mode": row["mode"],
                        "shard": row["shard"],
                        "scanned": row["scanned"],
                        "total": row["total"],
                        "speed": row["speed"] if is_online else 0.0,
                        "available_count": row["available_count"],
                        "idle_sec": idle,
                        "last_seen": row["last_seen"]
                    })
            self.send_json({"code": 0, "data": nodes})
            return

        # 4. 任务列表 API
        if path == "/api/tasks":
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                SELECT task_id, mode, suffix, threads, target_nodes, status, datetime(created_at, '+8 hours') as created_at, datetime(updated_at, '+8 hours') as updated_at
                FROM tasks
                WHERE (is_aid = 0 OR is_aid IS NULL)
                ORDER BY tasks.created_at DESC LIMIT 20;
                """)
                tasks = []
                for row in cur.fetchall():
                    t = dict(row)
                    cur.execute("""
                    SELECT node_id, shard_num, shard_total, status, scanned, total, speed, available_count, is_aid, aid_for
                    FROM task_assignments WHERE task_id = ? OR parent_task_id = ? ORDER BY id ASC;
                    """, (t["task_id"], t["task_id"]))
                    t["assignments"] = [dict(a) for a in cur.fetchall()]
                    tasks.append(t)
            self.send_json({"code": 0, "data": tasks})
            return

        # 5. Token 查询 API
        if path == "/api/token":
            tok = get_current_token()
            self.send_json({"code": 0, "data": {"token": tok}})
            return

        # 6. 域名分页与智能筛选 API
        if path == "/api/domains":
            where_sql, bind_params = build_domain_filters(params)

            page = max(1, int(params.get("page", ["1"])[0]))
            limit = min(200, max(10, int(params.get("limit", ["50"])[0])))
            offset = (page - 1) * limit

            has_complex_filters = bool(
                params.get("q", [""])[0].strip() or
                params.get("has_vowel", ["0"])[0] == "1" or
                params.get("exclude_rare", ["0"])[0] == "1" or
                params.get("prefix", [""])[0].strip() or
                params.get("suffix", [""])[0].strip() or
                params.get("repeat_count", [""])[0].strip() or
                params.get("seq_count", [""])[0].strip() or
                params.get("pattern", [""])[0].strip() or
                params.get("pronounceable", ["0"])[0] in ("1", "true")
            )

            with _STATS_LOCK:
                cached_data = dict(_CACHED_DOMAIN_STATS)
            with get_db() as conn:
                cur = conn.cursor()
                # 极速快显优化：当没有自定义复杂过滤、仅浏览"全部可用"、"收藏星标"或按模式维度多选时，直接命中内存统计缓存，杜绝千万行全表扫描 COUNT
                if (not where_sql or where_sql == "WHERE status = ?") and bind_params == ["available"]:
                    total_count = cached_data.get("total_available", 0)
                elif where_sql == "WHERE is_starred = 1" and not bind_params:
                    total_count = cached_data.get("total_starred", 0)
                elif not has_complex_filters and where_sql.startswith("WHERE status = ? AND mode IN (") and bind_params and bind_params[0] == "available":
                    modes_to_sum = bind_params[1:]
                    mode_stats = cached_data.get("mode_stats", {})
                    total_count = sum(mode_stats.get(m, 0) for m in modes_to_sum)
                elif not has_complex_filters and where_sql == "WHERE status = ? AND mode = ?" and bind_params and bind_params[0] == "available":
                    total_count = cached_data.get("mode_stats", {}).get(bind_params[1], 0)
                else:
                    cur.execute(f"SELECT COUNT(*) FROM domains {where_sql};", bind_params)
                    total_count = cur.fetchone()[0]

                cur.execute(f"""
                SELECT domain, mode, node_id, status, is_starred, reason, datetime(created_at, '+8 hours') as created_at
                FROM domains
                {where_sql}
                ORDER BY domains.created_at DESC
                LIMIT ? OFFSET ?;
                """, bind_params + [limit, offset])

                raw_domains = [dict(row) for row in cur.fetchall()]

            self.send_json({
                "code": 0,
                "data": {
                    "total": total_count,
                    "page": page,
                    "limit": limit,
                    "list": raw_domains
                }
            })
            return


        # 8. 存量资产批量复验状态 API
        if path == "/api/domain/batch_recheck/status":
            self.send_json({"code": 0, "data": BATCH_RECHECK_STATE})
            return

        self.send_error(404, "Endpoint Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # -------------------------------------------------------------
        # 一、 Agent 端专用接口 (必须经 Token 鉴权认证)
        # -------------------------------------------------------------
        if path.startswith("/api/agent/"):
            if not self.verify_agent_token():
                self.send_json({"code": 401, "msg": "Unauthorized: 无效或缺失 Token"}, 401)
                return

            # 1. Agent 自动注册 (握手)
            if path == "/api/agent/register":
                data = self.read_json_body()
                raw_node_id = data.get("node_id", "").strip()
                agent_uuid = data.get("agent_uuid", "").strip()
                if not raw_node_id and not agent_uuid:
                    self.send_json({"code": 1, "msg": "node_id or agent_uuid is required"}, 400)
                    return
                client_ip = self.client_address[0]
                os_info = data.get("os_info", "")
                version = data.get("version", "1.0")

                with get_db() as conn:
                    effective_node_id, bound_uuid = resolve_node_identity(conn, raw_node_id or f"node_{agent_uuid[-6:]}", agent_uuid)
                    conn.execute("""
                    INSERT INTO nodes (node_id, ip, os_info, agent_version, agent_uuid, status, last_seen)
                    VALUES (?, ?, ?, ?, ?, 'idle', CURRENT_TIMESTAMP)
                    ON CONFLICT(node_id) DO UPDATE SET
                        ip = excluded.ip,
                        os_info = excluded.os_info,
                        agent_version = excluded.agent_version,
                        agent_uuid = COALESCE(excluded.agent_uuid, nodes.agent_uuid),
                        last_seen = CURRENT_TIMESTAMP;
                    """, (effective_node_id, client_ip, os_info, version, bound_uuid))
                    conn.commit()

                self.send_json({"code": 0, "msg": "注册成功", "node_id": effective_node_id, "agent_uuid": bound_uuid})
                return

            # 2. Agent 心跳上报与任务指令获取
            if path == "/api/agent/heartbeat":
                data = self.read_json_body()
                raw_node_id = data.get("node_id", "").strip()
                agent_uuid = data.get("agent_uuid", "").strip()
                if not raw_node_id and not agent_uuid:
                    self.send_json({"code": 1, "msg": "node_id or agent_uuid is required"}, 400)
                    return

                task_id = data.get("task_id", "")
                mode = data.get("mode", "")
                shard = data.get("shard", "")
                scanned = int(data.get("scanned", 0))
                total = int(data.get("total", 0))
                speed = float(data.get("speed", 0.0))
                avail_cnt = int(data.get("available", 0))
                client_status = data.get("status", "idle")
                agent_ver = data.get("version")

                with get_db() as conn:
                    node_id, bound_uuid = resolve_node_identity(conn, raw_node_id or f"node_{agent_uuid[-6:]}", agent_uuid)

                    # 更新节点状态
                    conn.execute("""
                    INSERT INTO nodes (node_id, ip, status, current_task_id, mode, shard, scanned, total, speed, available_count, agent_version, agent_uuid, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, '1.0'), ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(node_id) DO UPDATE SET
                        ip = excluded.ip,
                        status = excluded.status,
                        current_task_id = excluded.current_task_id,
                        mode = excluded.mode,
                        shard = excluded.shard,
                        scanned = excluded.scanned,
                        total = CASE 
                            WHEN (SELECT total FROM task_assignments WHERE task_id = excluded.current_task_id AND node_id = excluded.node_id) IS NOT NULL 
                            THEN (SELECT total FROM task_assignments WHERE task_id = excluded.current_task_id AND node_id = excluded.node_id)
                            ELSE excluded.total 
                        END,
                        speed = excluded.speed,
                        available_count = excluded.available_count,
                        agent_version = CASE WHEN excluded.agent_version IS NOT NULL AND excluded.agent_version != '' THEN excluded.agent_version ELSE nodes.agent_version END,
                        agent_uuid = COALESCE(excluded.agent_uuid, nodes.agent_uuid),
                        last_seen = CURRENT_TIMESTAMP;
                    """, (node_id, self.client_address[0], client_status, task_id, mode, shard, scanned, total, speed, avail_cnt, agent_ver, bound_uuid))

                    # 如果在跑任务，同步更新任务分片进度
                    if task_id:
                        effective_assign_status = client_status
                        if client_status == "completed" or (total > 0 and scanned >= total):
                            effective_assign_status = "completed"

                        conn.execute("""
                        UPDATE task_assignments SET
                            scanned = ?, speed = ?, available_count = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE task_id = ? AND node_id = ?;
                        """, (scanned, speed, avail_cnt, effective_assign_status, task_id, node_id))

                        if effective_assign_status == "completed":
                            conn.execute("UPDATE tasks SET status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE task_id = ? AND is_aid = 1;", (task_id,))

                        # 检查当前主任务是否所有参与分片均已完成
                        p_id = task_id
                        cur = conn.cursor()
                        cur.execute("SELECT parent_task_id FROM tasks WHERE task_id = ?;", (task_id,))
                        p_row = cur.fetchone()
                        if p_row and p_row[0]:
                            p_id = p_row[0]

                        cur.execute("""
                        SELECT COUNT(*) as total_shards,
                               SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_shards,
                               SUM(CASE WHEN status IN ('pending', 'running') THEN 1 ELSE 0 END) as active_shards
                        FROM task_assignments WHERE task_id = ? OR parent_task_id = ?;
                        """, (p_id, p_id))
                        task_stat_row = cur.fetchone()
                        if task_stat_row and task_stat_row["active_shards"] == 0:
                            if task_stat_row["completed_shards"] > 0:
                                conn.execute("UPDATE tasks SET status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE (task_id = ? OR parent_task_id = ?) AND status = 'running';", (p_id, p_id))
                            else:
                                conn.execute("UPDATE tasks SET status = 'stopped', updated_at = CURRENT_TIMESTAMP WHERE (task_id = ? OR parent_task_id = ?) AND status = 'running';", (p_id, p_id))

                    # 检查 Master 是否有为该节点下发的新指令 (获取该节点的最新分配)
                    cur = conn.cursor()
                    cur.execute("""
                    SELECT a.id as assign_id, a.task_id, a.shard_num, a.shard_total, a.status as assign_status, a.scanned as assign_scanned,
                           a.start_idx, a.end_idx, a.total as assign_total, a.is_aid, a.aid_for, a.parent_task_id,
                           t.mode, t.length, t.use_letters, t.use_digits, t.use_hyphen, t.reset_checkpoint, t.suffix, t.threads, t.status as task_status
                    FROM task_assignments a
                    JOIN tasks t ON a.task_id = t.task_id
                    WHERE a.node_id = ?
                    ORDER BY t.created_at DESC, a.id DESC LIMIT 1;
                    """, (node_id,))
                    assign_row = cur.fetchone()
                    conn.commit()

                # 下发指令判定
                command = "IDLE"
                task_payload = None
                trimmed_total = None
                trimmed_end_idx = None

                if assign_row:
                    t_status = assign_row["task_status"]
                    assigned_task_id = assign_row["task_id"]
                    assign_status = assign_row["assign_status"]
                    assign_scanned = assign_row["assign_scanned"] or 0
                    row_keys = assign_row.keys() if hasattr(assign_row, "keys") else []

                    # 1. 任务或当前节点分片已被停止
                    if t_status == "stopped" or assign_status == "stopped":
                        if task_id == assigned_task_id and client_status not in ("idle", "completed", "stopped"):
                            command = "STOP"
                        else:
                            command = "IDLE"

                    # 2. 当前节点分片已处于 running 状态
                    elif t_status == "running" and assign_status == "running":
                        if task_id == assigned_task_id and client_status == "running":
                            command = "IDLE"
                            trimmed_total = assign_row["assign_total"]
                            trimmed_end_idx = assign_row["end_idx"]
                        elif client_status not in ("completed",):
                            command = "START"
                            should_reset_ckpt = False
                            task_payload = {
                                "task_id": assigned_task_id,
                                "parent_task_id": assign_row["parent_task_id"] if "parent_task_id" in row_keys else "",
                                "mode": assign_row["mode"],
                                "length": assign_row["length"] if "length" in row_keys and assign_row["length"] is not None else 4,
                                "use_letters": bool(assign_row["use_letters"]) if "use_letters" in row_keys and assign_row["use_letters"] is not None else True,
                                "use_digits": bool(assign_row["use_digits"]) if "use_digits" in row_keys and assign_row["use_digits"] is not None else False,
                                "use_hyphen": bool(assign_row["use_hyphen"]) if "use_hyphen" in row_keys and assign_row["use_hyphen"] is not None else False,
                                "reset_checkpoint": should_reset_ckpt,
                                "suffix": assign_row["suffix"],
                                "start_idx": assign_row["start_idx"] if "start_idx" in row_keys else None,
                                "end_idx": assign_row["end_idx"] if "end_idx" in row_keys else None,
                                "total": assign_row["assign_total"] if "assign_total" in row_keys and assign_row["assign_total"] is not None else 0,
                                "shard_num": assign_row["shard_num"],
                                "shard_total": assign_row["shard_total"],
                                "threads": assign_row["threads"],
                                "is_aid": bool(assign_row["is_aid"]) if "is_aid" in row_keys and assign_row["is_aid"] is not None else False,
                                "aid_for": assign_row["aid_for"] if "aid_for" in row_keys and assign_row["aid_for"] is not None else ""
                            }

                    # 3. 分片处于 pending 状态，立即下发 START
                    elif t_status == "running" and assign_status == "pending":
                        command = "START"
                        should_reset_ckpt = False
                        if assign_status == "pending" and assign_scanned == 0:
                            should_reset_ckpt = bool(assign_row["reset_checkpoint"]) if "reset_checkpoint" in row_keys and assign_row["reset_checkpoint"] is not None else False

                        task_payload = {
                            "task_id": assigned_task_id,
                            "parent_task_id": assign_row["parent_task_id"] if "parent_task_id" in row_keys else "",
                            "mode": assign_row["mode"],
                            "length": assign_row["length"] if "length" in row_keys and assign_row["length"] is not None else 4,
                            "use_letters": bool(assign_row["use_letters"]) if "use_letters" in row_keys and assign_row["use_letters"] is not None else True,
                            "use_digits": bool(assign_row["use_digits"]) if "use_digits" in row_keys and assign_row["use_digits"] is not None else False,
                            "use_hyphen": bool(assign_row["use_hyphen"]) if "use_hyphen" in row_keys and assign_row["use_hyphen"] is not None else False,
                            "reset_checkpoint": should_reset_ckpt,
                            "suffix": assign_row["suffix"],
                            "start_idx": assign_row["start_idx"] if "start_idx" in row_keys else None,
                            "end_idx": assign_row["end_idx"] if "end_idx" in row_keys else None,
                            "total": assign_row["assign_total"] if "assign_total" in row_keys and assign_row["assign_total"] is not None else 0,
                            "shard_num": assign_row["shard_num"],
                            "shard_total": assign_row["shard_total"],
                            "threads": assign_row["threads"],
                            "is_aid": bool(assign_row["is_aid"]) if "is_aid" in row_keys and assign_row["is_aid"] is not None else False,
                            "aid_for": assign_row["aid_for"] if "aid_for" in row_keys and assign_row["aid_for"] is not None else ""
                        }
                        with get_db() as conn:
                            conn.execute("UPDATE task_assignments SET status = 'running', updated_at = CURRENT_TIMESTAMP WHERE id = ?;", (assign_row["assign_id"],))
                            conn.commit()

                # 4. 尾部工作窃取 (Work-Stealing / 尾部援助接力)
                # 当节点空闲 (idle 或已跑完 completed)，自动从集群中最慢节点的未扫尾部切取任务接力加速
                is_node_free = (client_status in ("idle", "completed") or (total > 0 and scanned >= total))
                if command == "IDLE" and is_node_free:
                    with get_db() as conn:
                        cur = conn.cursor()
                        # 查找当前是否有正在运行的根主任务
                        cur.execute("""
                        SELECT task_id, mode, length, use_letters, use_digits, use_hyphen, suffix, threads
                        FROM tasks
                        WHERE status = 'running' AND (is_aid = 0 OR is_aid IS NULL)
                        ORDER BY created_at DESC LIMIT 1;
                        """)
                        parent_task = cur.fetchone()

                        if parent_task:
                            p_task_id = parent_task["task_id"]
                            # 1. 严格权限校验：只有被勾选且实际参与了本次任务初始分片的节点，才允许接力扫尾（绝不拉未被选中的其他空闲节点）
                            cur.execute("""
                            SELECT 1 FROM task_assignments
                            WHERE task_id = ? AND node_id = ? AND (is_aid = 0 OR is_aid IS NULL);
                            """, (p_task_id, node_id))
                            participated = cur.fetchone()

                            # 2. 确认当前节点在该主任务下没有其他未结算的活跃任务
                            cur.execute("""
                            SELECT id FROM task_assignments
                            WHERE (task_id = ? OR parent_task_id = ?) AND node_id = ? AND status IN ('pending', 'running');
                            """, (p_task_id, p_task_id, node_id))
                            active_on_node = cur.fetchall()

                            if participated and not active_on_node:
                                # 寻找当前主任务下剩余工作量最大且处于 running 的慢节点分片
                                cur.execute("""
                                SELECT a.id, a.task_id, a.node_id, a.shard_num, a.shard_total, a.scanned, a.total, a.start_idx, a.end_idx
                                FROM task_assignments a
                                WHERE (a.task_id = ? OR a.parent_task_id = ?)
                                  AND a.status = 'running'
                                  AND a.node_id != ?
                                ORDER BY (a.total - a.scanned) DESC;
                                """, (p_task_id, p_task_id, node_id))
                                candidates = cur.fetchall()

                                for cand in candidates:
                                    s_idx, e_idx, cur_tot = ensure_assignment_bounds(conn, cand, parent_task)
                                    c_scanned = cand["scanned"] or 0
                                    remaining = cur_tot - c_scanned
                                    if remaining > 5000:
                                        # 触发尾部工作窃取：从慢节点的未扫尾部切出最多 5 万（或剩余的一半）
                                        slice_size = min(50000, remaining // 2)
                                        slice_end = e_idx
                                        slice_start = slice_end - slice_size
                                        new_cand_end = slice_start
                                        new_cand_total = cur_tot - slice_size

                                        # 1. 动态缩减慢节点的截止线与总任务量
                                        conn.execute("""
                                        UPDATE task_assignments
                                        SET end_idx = ?, total = ?, updated_at = CURRENT_TIMESTAMP
                                        WHERE id = ?;
                                        """, (new_cand_end, new_cand_total, cand["id"]))

                                        # 2. 为当前空闲节点生成援助子任务
                                        aid_seq = int(time.time() * 1000) % 100000
                                        aid_task_id = f"{p_task_id}_aid_{node_id}_{aid_seq}"
                                        conn.execute("""
                                        INSERT INTO tasks (
                                            task_id, mode, length, use_letters, use_digits, use_hyphen,
                                            reset_checkpoint, suffix, threads, target_nodes, status,
                                            is_aid, parent_task_id
                                        ) VALUES (
                                            ?, ?, ?, ?, ?, ?,
                                            0, ?, ?, ?, 'running',
                                            1, ?
                                        );
                                        """, (
                                            aid_task_id, parent_task["mode"], parent_task["length"],
                                            parent_task["use_letters"], parent_task["use_digits"], parent_task["use_hyphen"],
                                            parent_task["suffix"], parent_task["threads"], json.dumps([node_id]),
                                            p_task_id
                                        ))

                                        # 3. 记录援助分片到 task_assignments
                                        conn.execute("""
                                        INSERT INTO task_assignments (
                                            task_id, node_id, shard_num, shard_total, status,
                                            scanned, total, start_idx, end_idx,
                                            is_aid, aid_for, parent_task_id
                                        ) VALUES (
                                            ?, ?, 0, ?, 'running',
                                            0, ?, ?, ?,
                                            1, ?, ?
                                        );
                                        """, (
                                            aid_task_id, node_id, cand["shard_total"],
                                            slice_size, slice_start, slice_end,
                                            cand["node_id"], p_task_id
                                        ))
                                        conn.commit()

                                        command = "START"
                                        task_payload = {
                                            "task_id": aid_task_id,
                                            "parent_task_id": p_task_id,
                                            "mode": parent_task["mode"],
                                            "length": parent_task["length"],
                                            "use_letters": bool(parent_task["use_letters"]),
                                            "use_digits": bool(parent_task["use_digits"]),
                                            "use_hyphen": bool(parent_task["use_hyphen"]),
                                            "reset_checkpoint": False,
                                            "suffix": parent_task["suffix"],
                                            "start_idx": slice_start,
                                            "end_idx": slice_end,
                                            "total": slice_size,
                                            "shard_num": 0,
                                            "shard_total": cand["shard_total"],
                                            "threads": parent_task["threads"],
                                            "is_aid": True,
                                            "aid_for": cand["node_id"]
                                        }
                                        print(f"[{get_beijing_time_str()}] ⚡ 触发尾部工作窃取：空闲节点 【{node_id}】 接力援助慢节点 【{cand['node_id']}】，分流尾部区间 [{slice_start:,} ~ {slice_end:,}] (共 {slice_size:,} 个域名)")
                                        break

                resp_payload = {
                    "code": 0,
                    "command": command,
                    "task": task_payload,
                    "assigned_node_id": node_id
                }
                if trimmed_total is not None and trimmed_end_idx is not None:
                    resp_payload["trimmed_total"] = trimmed_total
                    resp_payload["trimmed_end_idx"] = trimmed_end_idx
                self.send_json(resp_payload)
                return

            # 3. Agent 发现可用域名实时入库
            if path == "/api/agent/report":
                data = self.read_json_body()
                domains_to_add = []
                if "domains" in data and isinstance(data["domains"], list):
                    domains_to_add = data["domains"]
                elif "domain" in data:
                    domains_to_add = [data]

                node_id = data.get("node_id", "unknown")
                mode = data.get("mode", "")

                added = 0
                with get_db() as conn:
                    for item in domains_to_add:
                        if isinstance(item, str):
                            d_name = item.strip().lower()
                            d_mode = mode
                            d_reason = "404 未注册"
                        else:
                            d_name = item.get("domain", "").strip().lower()
                            d_mode = item.get("mode", mode)
                            d_reason = item.get("reason", "404 未注册")

                        if not d_name:
                            continue
                        feats = analyze_domain_features(d_name)
                        try:
                            conn.execute("""
                            INSERT INTO domains (
                                domain, mode, node_id, status, reason,
                                max_repeat, max_seq, max_seq_asc, max_seq_desc,
                                is_palindrome, patterns, is_pronounceable, has_vowel, is_clean,
                                created_at, updated_at
                            )
                            VALUES (?, ?, ?, 'available', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            ON CONFLICT(domain) DO UPDATE SET
                                node_id = excluded.node_id,
                                reason = excluded.reason,
                                max_repeat = excluded.max_repeat,
                                max_seq = excluded.max_seq,
                                max_seq_asc = excluded.max_seq_asc,
                                max_seq_desc = excluded.max_seq_desc,
                                is_palindrome = excluded.is_palindrome,
                                patterns = excluded.patterns,
                                is_pronounceable = excluded.is_pronounceable,
                                has_vowel = excluded.has_vowel,
                                is_clean = excluded.is_clean,
                                updated_at = CURRENT_TIMESTAMP;
                            """, (
                                d_name, d_mode, node_id, d_reason,
                                feats["max_repeat"], feats["max_seq"], feats["max_seq_asc"], feats["max_seq_desc"],
                                feats["is_palindrome"], feats["patterns"], feats["is_pronounceable"],
                                feats["has_vowel"], feats["is_clean"]
                            ))
                            added += 1
                        except Exception:
                            pass
                    conn.commit()

                self.send_json({"code": 0, "msg": f"成功保存 {added} 个域名"})
                return

        # -------------------------------------------------------------
        # 二、 Web 控制台调度与管理接口
        # -------------------------------------------------------------

        # 1. 一键分发扫描任务到选中的节点 (支持 3~5 位自由组合)
        if path == "/api/task/dispatch":
            data = self.read_json_body()
            length = int(data.get("length", 4))
            use_letters = bool(data.get("use_letters", True))
            use_digits = bool(data.get("use_digits", False))
            use_hyphen = bool(data.get("use_hyphen", False))
            reset_checkpoint = bool(data.get("reset_checkpoint", False))
            suffix = data.get("suffix", "com").strip().lower()
            threads = int(data.get("threads", 25))
            selected_nodes = data.get("nodes", [])

            if length not in (3, 4, 5, 6):
                self.send_json({"code": 1, "msg": "字符长度仅支持 3 ~ 6 位"}, 400)
                return
            if not use_letters and not use_digits:
                self.send_json({"code": 1, "msg": "必须勾选字母或数字其中一种"}, 400)
                return
            if not selected_nodes:
                self.send_json({"code": 1, "msg": "必须至少勾选一个在线节点"}, 400)
                return

            # 严格校验：选中的节点必须均处于在线状态 (35 秒内有心跳)
            with get_db() as conn:
                cur = conn.cursor()
                placeholders = ",".join("?" * len(selected_nodes))
                cur.execute(f"""
                SELECT node_id, (strftime('%s', 'now') - strftime('%s', last_seen)) as idle_sec
                FROM nodes WHERE node_id IN ({placeholders});
                """, selected_nodes)
                node_map = {row["node_id"]: (row["idle_sec"] if row["idle_sec"] is not None else 999999) for row in cur.fetchall()}

            offline_nodes = [nid for nid in selected_nodes if nid not in node_map or node_map[nid] > 35]
            if offline_nodes:
                self.send_json({
                    "code": 1,
                    "msg": f"下发失败：节点 【{', '.join(offline_nodes)}】 当前处于离线状态！请先启动其 Agent 或取消勾选该节点。"
                }, 400)
                return

            # 推导标准模式名称，与资产库展示完全统一
            if use_letters and use_digits:
                type_name = "mix"
            elif use_digits:
                type_name = "num"
            else:
                type_name = "letter"
            hyphen_suffix = "-" if use_hyphen else ""
            mode = f"{length}{type_name}{hyphen_suffix}"

            task_id = f"task_{int(datetime.now().timestamp())}_{mode}"
            shard_total = len(selected_nodes)

            with get_db() as conn:
                # 仅针对本次被勾选的节点，停止它们在此前正在执行的分片任务 (绝不影响未被勾选的其他节点继续扫描)
                placeholders = ",".join("?" * len(selected_nodes))
                conn.execute(f"""
                UPDATE task_assignments
                SET status = 'stopped', updated_at = CURRENT_TIMESTAMP
                WHERE node_id IN ({placeholders}) AND status IN ('pending', 'running');
                """, selected_nodes)

                # 对于历史任务，若已没有任何活跃分片 (无 pending 或 running 分片)，自动标记该历史任务为 stopped
                conn.execute("""
                UPDATE tasks
                SET status = 'stopped', updated_at = CURRENT_TIMESTAMP
                WHERE status = 'running'
                  AND NOT EXISTS (
                      SELECT 1 FROM task_assignments a
                      WHERE a.task_id = tasks.task_id AND a.status IN ('pending', 'running')
                  );
                """)

                # 创建新任务
                conn.execute("""
                INSERT INTO tasks (task_id, mode, length, use_letters, use_digits, use_hyphen, reset_checkpoint, suffix, threads, target_nodes, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running');
                """, (task_id, mode, length, 1 if use_letters else 0, 1 if use_digits else 0, 1 if use_hyphen else 0, 1 if reset_checkpoint else 0, suffix, threads, json.dumps(selected_nodes)))

                total_all = calc_domain_total(length, use_letters, use_digits, use_hyphen)
                # 自动为每个勾选的节点分配对应分片 (1/N ... N/N)
                for idx, n_id in enumerate(selected_nodes, start=1):
                    start_idx = ((idx - 1) * total_all) // shard_total
                    end_idx = (idx * total_all) // shard_total
                    total_count = end_idx - start_idx
                    conn.execute("""
                    INSERT INTO task_assignments (task_id, node_id, shard_num, shard_total, status, start_idx, end_idx, total)
                    VALUES (?, ?, ?, ?, 'pending', ?, ?, ?);
                    """, (task_id, n_id, idx, shard_total, start_idx, end_idx, total_count))

                conn.commit()

            self.send_json({
                "code": 0,
                "msg": f"任务已创建！已自动切为 {shard_total} 分片并下发到选中的节点",
                "task_id": task_id,
                "mode": mode
            })
            return

        # 1.1 修改/更新集群通信 Token
        if path == "/api/token/update":
            data = self.read_json_body()
            new_token = data.get("token", "").strip()
            if not new_token or len(new_token) < 8:
                self.send_json({"code": 1, "msg": "Token 长度不能少于 8 位"}, 400)
                return
            with get_db() as conn:
                conn.execute("""
                INSERT INTO system_config (key, value, updated_at) VALUES ('agent_token', ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP;
                """, (new_token,))
                conn.commit()
            global MASTER_TOKEN
            MASTER_TOKEN = new_token
            self.send_json({"code": 0, "msg": "集群通信 Token 已成功更新！", "token": new_token})
            return

        # 2. 停止集群任务
        if path == "/api/task/stop":
            data = self.read_json_body()
            task_id = data.get("task_id", "")
            with get_db() as conn:
                if task_id:
                    conn.execute("UPDATE tasks SET status = 'stopped', updated_at = CURRENT_TIMESTAMP WHERE task_id = ? OR parent_task_id = ?;", (task_id, task_id))
                    conn.execute("UPDATE task_assignments SET status = 'stopped', updated_at = CURRENT_TIMESTAMP WHERE task_id = ? OR parent_task_id = ?;", (task_id, task_id))
                else:
                    conn.execute("UPDATE tasks SET status = 'stopped', updated_at = CURRENT_TIMESTAMP WHERE status = 'running';")
                    conn.execute("UPDATE task_assignments SET status = 'stopped', updated_at = CURRENT_TIMESTAMP WHERE status = 'running';")
                conn.commit()

            self.send_json({"code": 0, "msg": "任务停止指令已广播给所有 Agent"})
            return

        # 3. 移除离线节点
        if path == "/api/nodes/delete":
            data = self.read_json_body()
            node_id = data.get("node_id", "")
            if node_id:
                with get_db() as conn:
                    conn.execute("DELETE FROM nodes WHERE node_id = ?;", (node_id,))
                    conn.commit()
            self.send_json({"code": 0, "msg": "节点记录已清理"})
            return

        # 3.1 一键清理所有离线节点记录
        if path == "/api/nodes/clean_offline":
            with get_db() as conn:
                conn.execute("DELETE FROM nodes WHERE (strftime('%s', 'now') - strftime('%s', last_seen)) > 35;")
                conn.commit()
            self.send_json({"code": 0, "msg": "已清理所有离线节点历史记录"})
            return

        # 4. 重置 / 生成新 Token
        if path == "/api/token/regenerate":
            new_tok = secrets.token_hex(16)
            with get_db() as conn:
                conn.execute("""
                INSERT INTO system_config (key, value, updated_at) VALUES ('agent_token', ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP;
                """, (new_tok,))
                conn.commit()
            self.send_json({"code": 0, "msg": "通信 Token 已更新", "data": {"token": new_tok}})
            return

        # 5. 更改域名状态与收藏标记 (收藏与可用性解耦)
        if path == "/api/domain/status":
            data = self.read_json_body()
            domain = data.get("domain", "").strip().lower()
            if not domain:
                self.send_json({"code": 1, "msg": "Domain is required"}, 400)
                return

            with get_db() as conn:
                cur = conn.cursor()
                if "starred" in data:
                    is_s = 1 if data["starred"] else 0
                    conn.execute("""
                    UPDATE domains SET is_starred = ?, updated_at = CURRENT_TIMESTAMP WHERE domain = ?;
                    """, (is_s, domain))
                    final_starred = is_s
                elif data.get("status") == "starred":
                    conn.execute("""
                    UPDATE domains SET is_starred = 1, updated_at = CURRENT_TIMESTAMP WHERE domain = ?;
                    """, (domain,))
                    final_starred = 1
                elif data.get("status") == "unstarred":
                    conn.execute("""
                    UPDATE domains SET is_starred = 0, updated_at = CURRENT_TIMESTAMP WHERE domain = ?;
                    """, (domain,))
                    final_starred = 0
                else:
                    new_status = data.get("status", "available")
                    conn.execute("""
                    UPDATE domains SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE domain = ?;
                    """, (new_status, domain))
                    cur.execute("SELECT is_starred FROM domains WHERE domain = ?;", (domain,))
                    r = cur.fetchone()
                    final_starred = r[0] if r else 0
                conn.commit()

            self.send_json({"code": 0, "msg": "更新成功", "is_starred": final_starred})
            return

        # 6. 实时权威复检 (Verisign RDAP)
        if path == "/api/domain/recheck":
            data = self.read_json_body()
            domain = data.get("domain", "").strip().lower()
            is_avail, reason = check_verisign_rdap(domain)

            with get_db() as conn:
                if not is_avail:
                    conn.execute("UPDATE domains SET status = 'registered', reason = ? WHERE domain = ?;", (reason, domain))
                else:
                    conn.execute("UPDATE domains SET reason = ? WHERE domain = ?;", (reason, domain))
                conn.commit()

            self.send_json({
                "code": 0,
                "data": {
                    "domain": domain,
                    "available": is_avail,
                    "reason": reason
                }
            })
            return

        # 6.1 存量可用资产批量复验
        if path == "/api/domain/batch_recheck":
            data = self.read_json_body()
            mode = data.get("mode", "all")
            ok, msg = start_batch_recheck(mode)
            self.send_json({"code": 0 if ok else 1, "msg": msg, "data": BATCH_RECHECK_STATE})
            return

        # 6.2 停止批量复验
        if path == "/api/domain/batch_recheck/stop":
            BATCH_RECHECK_STATE["is_running"] = False
            self.send_json({"code": 0, "msg": "批量复验任务已请求停止"})
            return

        # 7. 单域名权威深度即验 API (形态 A)
        if path == "/api/domain/inspect":
            data = self.read_json_body()
            raw_d = data.get("domain", "").strip().lower()
            # 协议与格式清洗
            raw_d = re.sub(r"^https?://", "", raw_d)
            raw_d = re.sub(r"^//", "", raw_d)
            raw_d = raw_d.split("/")[0].split(":")[0].strip()

            if not raw_d:
                self.send_json({"code": 1, "msg": "请输入待查域名或字符前缀"}, 400)
                return

            if "." not in raw_d:
                target_domain = f"{raw_d}.com"
            else:
                target_domain = raw_d

            # 1. 查询本地数据库收录情况
            local_record = None
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                SELECT domain, mode, node_id, status, is_starred, reason, datetime(created_at, '+8 hours') as created_at
                FROM domains WHERE domain = ?;
                """, (target_domain,))
                row = cur.fetchone()
                if row:
                    local_record = dict(row)

            # 2. 实时穿透 Verisign RDAP 权威根库
            inspect_res = inspect_domain_rdap(target_domain)

            self.send_json({
                "code": 0,
                "data": {
                    "domain": target_domain,
                    "available": inspect_res.get("available"),
                    "reason": inspect_res.get("reason"),
                    "error": inspect_res.get("error"),
                    "rdap": inspect_res.get("rdap"),
                    "local": local_record
                }
            })
            return

        # 7.1 单域名立即加入/取消星标收藏 (若不存在于本地库则自动按标准模式收录入库)
        if path == "/api/domain/star_direct":
            data = self.read_json_body()
            target_domain = data.get("domain", "").strip().lower()
            target_domain = re.sub(r"^https?://", "", target_domain)
            target_domain = re.sub(r"^//", "", target_domain)
            target_domain = target_domain.split("/")[0].split(":")[0].strip()
            if not target_domain:
                self.send_json({"code": 1, "msg": "域名不能为空"}, 400)
                return
            if "." not in target_domain:
                target_domain = f"{target_domain}.com"

            is_starred = 1 if data.get("starred", 1) in (1, "1", True) else 0

            # 推导标准特征与 mode
            clean_name = clean_domain_name(target_domain)
            c_type = "num" if clean_name.isdigit() else ("letter" if clean_name.isalpha() else "mix")
            c_hyphen = "-" if "-" in clean_name else ""
            mode_val = f"{len(clean_name)}{c_type}{c_hyphen}"
            feats = analyze_domain_features(target_domain)

            with DB_LOCK:
                with get_db() as conn:
                    conn.execute("""
                    INSERT INTO domains (
                        domain, mode, node_id, status, is_starred, reason,
                        max_repeat, max_seq, max_seq_asc, max_seq_desc,
                        is_palindrome, patterns, is_pronounceable, has_vowel, is_clean,
                        created_at, updated_at
                    )
                    VALUES (?, ?, 'inspector', 'available', ?, '手动查验收藏', ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ON CONFLICT(domain) DO UPDATE SET
                        is_starred = excluded.is_starred,
                        status = CASE WHEN domains.status = 'registered' THEN 'available' ELSE domains.status END,
                        updated_at = CURRENT_TIMESTAMP;
                    """, (
                        target_domain, mode_val, is_starred,
                        feats["max_repeat"], feats["max_seq"], feats["max_seq_asc"], feats["max_seq_desc"],
                        feats["is_palindrome"], feats["patterns"], feats["is_pronounceable"], feats["has_vowel"], feats["is_clean"]
                    ))
                    conn.commit()

            # 刷新内存缓存统计
            with _STATS_LOCK:
                if is_starred:
                    _CACHED_DOMAIN_STATS["total_starred"] = _CACHED_DOMAIN_STATS.get("total_starred", 0) + 1
                else:
                    _CACHED_DOMAIN_STATS["total_starred"] = max(0, _CACHED_DOMAIN_STATS.get("total_starred", 0) - 1)

            msg = "已成功加入星标收藏！" if is_starred else "已取消星标收藏"
            self.send_json({"code": 0, "msg": msg, "domain": target_domain, "is_starred": is_starred})
            return

        # 7.2 同步域名状态为已注册
        if path == "/api/domain/sync_registered":
            data = self.read_json_body()
            target_domain = data.get("domain", "").strip().lower()
            reason = data.get("reason", "RDAP权威证实已被注册")
            with DB_LOCK:
                with get_db() as conn:
                    conn.execute("UPDATE domains SET status = 'registered', reason = ?, updated_at = CURRENT_TIMESTAMP WHERE domain = ?;", (reason, target_domain))
                    conn.commit()
            self.send_json({"code": 0, "msg": "本地状态已同步为已注册", "domain": target_domain})
            return

        self.send_error(404, "Endpoint Not Found")

def run(port=8088):
    server = ThreadingHTTPServer(("0.0.0.0", port), HubHandler)
    print(f"[{get_beijing_time_str()}] Domain Hub Master 正在监听 0.0.0.0:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDomain Hub 正在安全关闭...")
        server.server_close()

if __name__ == "__main__":
    p = 8088
    if len(sys.argv) > 1:
        p = int(sys.argv[1])
    run(p)
