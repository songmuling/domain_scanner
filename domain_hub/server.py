#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Hub - 统一域名扫描中心控制台与实时监控服务
支持多节点心跳监控、可用域名集中存储、实时状态管理、智能筛选与直达注册。
纯 Python 标准库实现，零外部依赖。
"""

import os
import sys
import json
import sqlite3
import urllib.request
import urllib.error
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone, timedelta
import threading

# 基础目录与数据库配置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
STATIC_DIR = os.path.join(BASE_DIR, "static")
DB_PATH = os.path.join(DATA_DIR, "domains.db")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# 线程锁保障 SQLite 迁移与初始化的安全
DB_LOCK = threading.Lock()

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db():
    with DB_LOCK:
        with get_db() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS domains (
                domain TEXT PRIMARY KEY,
                mode TEXT,
                node_id TEXT,
                status TEXT DEFAULT 'available',
                reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                mode TEXT,
                shard TEXT,
                scanned INTEGER DEFAULT 0,
                total INTEGER DEFAULT 0,
                speed REAL DEFAULT 0.0,
                available_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running',
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_mode ON domains(mode);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_created ON domains(created_at);")
            conn.commit()

init_db()

def get_beijing_time_str():
    bj_tz = timezone(timedelta(hours=8))
    return datetime.now(bj_tz).strftime("%Y-%m-%d %H:%M:%S")

def check_verisign_rdap(domain):
    """权威复检：查询 Verisign 官方 RDAP"""
    url = f"https://rdap.verisign.com/com/v1/domain/{domain.lower()}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "DomainHub-Verifier/1.0", "Accept": "application/rdap+json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            if resp.status == 200:
                return False, "已注册 (RDAP返回200)"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True, "未注册 (RDAP返回404)"
        return False, f"HTTP状态: {e.code}"
    except Exception as e:
        return False, f"网络错误: {str(e)}"
    return False, "未知状态"

class HubHandler(BaseHTTPRequestHandler):
    server_version = "DomainHub/1.0"

    def log_message(self, format, *args):
        # 简化日志输出，避免高频刷屏
        if self.path.startswith("/api/heartbeat"):
            return
        sys.stderr.write(f"[{get_beijing_time_str()}] {self.address_string()} - {format % args}\n")

    def send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def read_json_body(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        body = self.rfile.read(content_length).decode("utf-8")
        return json.loads(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # 1. 静态主页
        if path in ("", "/", "/index.html"):
            index_file = os.path.join(STATIC_DIR, "index.html")
            if os.path.exists(index_file):
                with open(index_file, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                self.send_error(404, "Static index.html not found")
                return

        # 2. 统计概览 API
        if path == "/api/stats":
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM domains WHERE status = 'available';")
                total_available = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM domains WHERE status = 'starred';")
                total_starred = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM domains WHERE status = 'purchased';")
                total_purchased = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM domains WHERE date(created_at, '+8 hours') = date('now', '+8 hours');")
                today_found = cur.fetchone()[0]

                # 分模式统计
                cur.execute("SELECT mode, COUNT(*) as cnt FROM domains WHERE status = 'available' GROUP BY mode;")
                mode_stats = {row["mode"] or "unknown": row["cnt"] for row in cur.fetchall()}

                # 活跃节点与总速度 (30秒内有心跳视为在线)
                cur.execute("SELECT COUNT(*), COALESCE(SUM(speed), 0) FROM nodes WHERE (strftime('%s', 'now') - strftime('%s', last_seen)) <= 30;")
                active_row = cur.fetchone()
                active_nodes = active_row[0]
                total_speed = round(active_row[1], 1)

            self.send_json({
                "code": 0,
                "data": {
                    "total_available": total_available,
                    "total_starred": total_starred,
                    "total_purchased": total_purchased,
                    "today_found": today_found,
                    "active_nodes": active_nodes,
                    "total_speed": total_speed,
                    "mode_stats": mode_stats
                }
            })
            return

        # 3. 节点列表 API
        if path == "/api/nodes":
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("""
                SELECT 
                    node_id, mode, shard, scanned, total, speed, available_count, status,
                    last_seen,
                    (strftime('%s', 'now') - strftime('%s', last_seen)) as idle_sec
                FROM nodes
                ORDER BY node_id ASC;
                """)
                nodes = []
                for row in cur.fetchall():
                    idle = row["idle_sec"]
                    is_online = idle <= 30
                    nodes.append({
                        "node_id": row["node_id"],
                        "mode": row["mode"],
                        "shard": row["shard"],
                        "scanned": row["scanned"],
                        "total": row["total"],
                        "speed": row["speed"],
                        "available_count": row["available_count"],
                        "status": "running" if is_online else "offline",
                        "idle_sec": idle,
                        "last_seen": row["last_seen"]
                    })
            self.send_json({"code": 0, "data": nodes})
            return

        # 4. 域名分页与智能筛选 API
        if path == "/api/domains":
            mode = params.get("mode", [""])[0]
            status = params.get("status", ["available"])[0]
            search = params.get("q", [""])[0].strip().lower()
            has_vowel = params.get("has_vowel", ["0"])[0] == "1"
            exclude_rare = params.get("exclude_rare", ["0"])[0] == "1" # 排除 q, x, z, v
            prefix = params.get("prefix", [""])[0].strip().lower()
            suffix = params.get("suffix", [""])[0].strip().lower()

            page = max(1, int(params.get("page", ["1"])[0]))
            limit = min(200, max(10, int(params.get("limit", ["50"])[0])))
            offset = (page - 1) * limit

            where_clauses = []
            bind_params = []

            if status != "all":
                where_clauses.append("status = ?")
                bind_params.append(status)

            if mode and mode != "all":
                where_clauses.append("mode = ?")
                bind_params.append(mode)

            if search:
                where_clauses.append("domain LIKE ?")
                bind_params.append(f"%{search}%")

            if prefix:
                where_clauses.append("domain LIKE ?")
                bind_params.append(f"{prefix}%")

            if suffix:
                where_clauses.append("domain LIKE ?")
                bind_params.append(f"%{suffix}.com")

            where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

            # 元音与生僻字母过滤在 Python 中处理或 SQL 扩展
            with get_db() as conn:
                cur = conn.cursor()
                # 统计总数 (快速估算或精准计数)
                cur.execute(f"SELECT COUNT(*) FROM domains {where_sql};", bind_params)
                total_count = cur.fetchone()[0]

                # 查询列表
                cur.execute(f"""
                SELECT domain, mode, node_id, status, reason, created_at
                FROM domains
                {where_sql}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?;
                """, bind_params + [limit, offset])

                raw_domains = [dict(row) for row in cur.fetchall()]

            # 内存级特征过滤 (若开启)
            filtered = []
            vowels = set("aeiou")
            rare_letters = set("qxzvy")
            for item in raw_domains:
                name_prefix = item["domain"].split(".")[0].replace("-", "")
                if has_vowel and not any(c in vowels for c in name_prefix):
                    continue
                if exclude_rare and any(c in rare_letters for c in name_prefix):
                    continue
                filtered.append(item)

            self.send_json({
                "code": 0,
                "data": {
                    "total": total_count,
                    "page": page,
                    "limit": limit,
                    "list": filtered
                }
            })
            return

        # 5. 导出 API
        if path == "/api/export":
            mode = params.get("mode", ["all"])[0]
            status = params.get("status", ["available"])[0]
            where = []
            args = []
            if mode != "all":
                where.append("mode = ?")
                args.append(mode)
            if status != "all":
                where.append("status = ?")
                args.append(status)

            w_sql = ("WHERE " + " AND ".join(where)) if where else ""
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute(f"SELECT domain FROM domains {w_sql} ORDER BY domain ASC;", args)
                lines = [r[0] for r in cur.fetchall()]

            content = "\n".join(lines).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="export_{mode}_{status}.txt"')
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        self.send_error(404, "Endpoint Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. 节点心跳上报
        if path == "/api/heartbeat":
            data = self.read_json_body()
            node_id = data.get("node_id", "unknown")
            mode = data.get("mode", "")
            shard = data.get("shard", "")
            scanned = int(data.get("scanned", 0))
            total = int(data.get("total", 0))
            speed = float(data.get("speed", 0.0))
            available_count = int(data.get("available", 0))
            status = data.get("status", "running")

            with get_db() as conn:
                conn.execute("""
                INSERT INTO nodes (node_id, mode, shard, scanned, total, speed, available_count, status, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(node_id) DO UPDATE SET
                    mode = excluded.mode,
                    shard = excluded.shard,
                    scanned = excluded.scanned,
                    total = excluded.total,
                    speed = excluded.speed,
                    available_count = excluded.available_count,
                    status = excluded.status,
                    last_seen = CURRENT_TIMESTAMP;
                """, (node_id, mode, shard, scanned, total, speed, available_count, status))
                conn.commit()

            self.send_json({"code": 0, "msg": "heartbeat ok"})
            return

        # 2. 单个可用域名实时上报
        if path == "/api/report":
            data = self.read_json_body()
            domain = data.get("domain", "").strip().lower()
            if not domain:
                self.send_json({"code": 1, "msg": "domain is required"}, 400)
                return

            mode = data.get("mode", "")
            node_id = data.get("node_id", "unknown")
            reason = data.get("reason", "404 未注册")

            with get_db() as conn:
                conn.execute("""
                INSERT INTO domains (domain, mode, node_id, status, reason, created_at, updated_at)
                VALUES (?, ?, ?, 'available', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(domain) DO UPDATE SET
                    node_id = excluded.node_id,
                    reason = excluded.reason,
                    updated_at = CURRENT_TIMESTAMP;
                """, (domain, mode, node_id, reason))
                conn.commit()

            self.send_json({"code": 0, "msg": "domain saved"})
            return

        # 3. 批量导入历史数据 (TXT内容或数组)
        if path == "/api/import":
            data = self.read_json_body()
            raw_text = data.get("text", "")
            domains_list = data.get("domains", [])
            node_id = data.get("node_id", "manual_import")
            mode = data.get("mode", "")

            if raw_text:
                domains_list.extend([line.strip().lower() for line in raw_text.splitlines() if line.strip()])

            added = 0
            with get_db() as conn:
                for d in domains_list:
                    if "." not in d:
                        d = f"{d}.com"
                    # 自动推断 mode
                    m = mode
                    if not m:
                        clean_name = d.split(".")[0]
                        has_h = "-" in clean_name
                        l = len(clean_name)
                        m = f"{l}letter-" if has_h else f"{l}letter"

                    try:
                        conn.execute("""
                        INSERT OR IGNORE INTO domains (domain, mode, node_id, status, reason)
                        VALUES (?, ?, ?, 'available', '历史数据导入');
                        """, (d, m, node_id))
                        added += 1
                    except Exception:
                        pass
                conn.commit()

            self.send_json({"code": 0, "msg": f"成功导入 {added} 个域名"})
            return

        # 4. 更改域名状态 (收藏 / 购买 / 垃圾桶)
        if path == "/api/domain/status":
            data = self.read_json_body()
            domain = data.get("domain", "").strip().lower()
            new_status = data.get("status", "available")
            if new_status not in ("available", "starred", "purchased", "discarded"):
                self.send_json({"code": 1, "msg": "Invalid status"}, 400)
                return

            with get_db() as conn:
                conn.execute("""
                UPDATE domains SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE domain = ?;
                """, (new_status, domain))
                conn.commit()

            self.send_json({"code": 0, "msg": f"状态已更新为 {new_status}"})
            return

        # 5. 实时权威复检 (Verisign RDAP)
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

        self.send_error(404, "Endpoint Not Found")

def run(port=8088):
    server = ThreadingHTTPServer(("0.0.0.0", port), HubHandler)
    print(f"[{get_beijing_time_str()}] Domain Hub 启动成功! 正在监听 0.0.0.0:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDomain Hub 正在关闭...")
        server.server_close()

if __name__ == "__main__":
    p = 8088
    if len(sys.argv) > 1:
        p = int(sys.argv[1])
    run(p)
