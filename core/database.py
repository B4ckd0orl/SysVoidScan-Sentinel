import json
import os
import sqlite3
import time
import logging


class Database:
    def __init__(self, db_path=None):
        if db_path is None:
            reports_dir = os.path.join(os.getcwd(), "reports")
            os.makedirs(reports_dir, exist_ok=True)
            db_path = os.path.join(reports_dir, "sysvoidscan.db")
        self.db_path = db_path
        self.conn = None

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.init_db()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def init_db(self):
        c = self.conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                status TEXT DEFAULT 'running'
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                module TEXT,
                severity TEXT,
                title TEXT,
                detail TEXT,
                evidence TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS technologies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                name TEXT,
                version TEXT,
                detail TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                port INTEGER,
                protocol TEXT,
                service TEXT,
                version TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                subdomain TEXT,
                ip TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                url TEXT,
                status_code INTEGER,
                tech TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool TEXT NOT NULL,
                target TEXT NOT NULL,
                result_hash TEXT NOT NULL,
                result_data TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                UNIQUE(tool, target, result_hash)
            );
        """)
        self.conn.commit()

    def create_scan(self, target, start_time=None):
        if start_time is None:
            start_time = time.strftime('%Y-%m-%d %H:%M:%S')
        c = self.conn.cursor()
        c.execute("INSERT INTO scans (target, start_time) VALUES (?, ?)", (target, start_time))
        self.conn.commit()
        return c.lastrowid

    def update_scan(self, scan_id, end_time=None, status=None):
        if end_time is None:
            end_time = time.strftime('%Y-%m-%d %H:%M:%S')
        if status is None:
            status = "completed"
        self.conn.execute(
            "UPDATE scans SET end_time=?, status=? WHERE id=?",
            (end_time, status, scan_id),
        )
        self.conn.commit()

    def add_finding(self, scan_id, module, severity, title, detail, evidence=None):
        self.conn.execute(
            "INSERT INTO findings (scan_id, module, severity, title, detail, evidence) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, module, severity, title, detail, evidence),
        )
        self.conn.commit()

    def add_technology(self, scan_id, name, version, detail):
        self.conn.execute(
            "INSERT INTO technologies (scan_id, name, version, detail) VALUES (?, ?, ?, ?)",
            (scan_id, name, version, detail),
        )
        self.conn.commit()

    def add_service(self, scan_id, port, protocol, service, version):
        self.conn.execute(
            "INSERT INTO services (scan_id, port, protocol, service, version) VALUES (?, ?, ?, ?, ?)",
            (scan_id, port, protocol, service, version),
        )
        self.conn.commit()

    def add_subdomain(self, scan_id, subdomain, ip):
        self.conn.execute(
            "INSERT INTO subdomains (scan_id, subdomain, ip) VALUES (?, ?, ?)",
            (scan_id, subdomain, ip),
        )
        self.conn.commit()

    def add_url(self, scan_id, url, status_code, tech):
        self.conn.execute(
            "INSERT INTO urls (scan_id, url, status_code, tech) VALUES (?, ?, ?, ?)",
            (scan_id, url, status_code, tech),
        )
        self.conn.commit()

    def get_scan(self, scan_id):
        row = self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            return None
        return dict(row)

    def get_findings(self, scan_id, severity=None):
        if severity:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE scan_id=? AND severity=?",
                (scan_id, severity),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE scan_id=?",
                (scan_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scans(self, target=None):
        if target:
            rows = self.conn.execute(
                "SELECT * FROM scans WHERE target=? ORDER BY id DESC",
                (target,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM scans ORDER BY id DESC",
            ).fetchall()
        return [dict(r) for r in rows]

    def compare_scans(self, scan_id1, scan_id2):
        f1 = {r["title"]: r for r in self.get_findings(scan_id1)}
        f2 = {r["title"]: r for r in self.get_findings(scan_id2)}
        new_findings = [f2[t] for t in f2 if t not in f1]
        removed_findings = [f1[t] for t in f1 if t not in f2]
        changed_findings = []
        for title in f1:
            if title in f2:
                if f1[title].get("severity") != f2[title].get("severity"):
                    changed_findings.append({
                        "title": title,
                        "old_severity": f1[title].get("severity"),
                        "new_severity": f2[title].get("severity"),
                    })
        return {
            "new": new_findings,
            "removed": removed_findings,
            "changed": changed_findings,
        }

    def cache_result(self, tool, target, result_hash, result_data):
        data_json = json.dumps(result_data, ensure_ascii=False) if not isinstance(result_data, str) else result_data
        self.conn.execute(
            "INSERT OR REPLACE INTO cache (tool, target, result_hash, result_data) VALUES (?, ?, ?, ?)",
            (tool, target, result_hash, data_json),
        )
        self.conn.commit()

    def get_cached_result(self, tool, target, result_hash):
        row = self.conn.execute(
            "SELECT result_data FROM cache WHERE tool=? AND target=? AND result_hash=?",
            (tool, target, result_hash),
        ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["result_data"])
        except (json.JSONDecodeError, TypeError):
            return row["result_data"]

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                logging.exception("Database.close: failed to close connection")
            self.conn = None
