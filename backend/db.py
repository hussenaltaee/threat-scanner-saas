import sqlite3
import hashlib
import json
import os

DB_NAME = "database.db"

# TEMP FIX FOR RENDER FREE PLAN:
# This removes the old broken SQLite database once after deploy.
# IMPORTANT: After the first successful deploy/register/scan, remove this block.
if os.path.exists(DB_NAME):
    os.remove(DB_NAME)


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def init_db():
    conn = get_connection()
    c = conn.cursor()

    c.execute("PRAGMA foreign_keys = ON")

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target TEXT NOT NULL,
        risk TEXT,
        score INTEGER,
        alerts TEXT,
        report TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS scan_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        title TEXT,
        severity TEXT,
        category TEXT,
        description TEXT,
        evidence TEXT,
        fix TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS scan_subdomains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        subdomain TEXT,
        ips TEXT,
        http INTEGER DEFAULT 0,
        https INTEGER DEFAULT 0,
        status_code INTEGER,
        final_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS scan_ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        port INTEGER,
        service TEXT,
        banner TEXT,
        risk TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS scan_cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        technology TEXT,
        cve_id TEXT,
        severity TEXT,
        score REAL,
        published TEXT,
        description TEXT,
        url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )
    """)

    c.execute("PRAGMA table_info(scans)")
    columns = [row["name"] for row in c.fetchall()]

    if "user" in columns and "user_id" not in columns:
        c.execute("ALTER TABLE scans RENAME TO scans_old")

        c.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target TEXT NOT NULL,
            risk TEXT,
            score INTEGER,
            alerts TEXT,
            report TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        c.execute("""
        INSERT INTO scans (id, target, risk, score, alerts, report, created_at)
        SELECT id, target, risk, score, alerts, report, created_at
        FROM scans_old
        """)

        c.execute("DROP TABLE scans_old")

    c.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON scan_findings(scan_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_subdomains_scan_id ON scan_subdomains(scan_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ports_scan_id ON scan_ports(scan_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_cves_scan_id ON scan_cves(scan_id)")

    conn.commit()
    conn.close()


def create_user(username, password):
    conn = get_connection()
    c = conn.cursor()

    try:
        c.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hash_password(password))
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def verify_user(username, password):
    conn = get_connection()
    c = conn.cursor()

    c.execute(
        "SELECT id, username FROM users WHERE username=? AND password=?",
        (username, hash_password(password))
    )

    user = c.fetchone()
    conn.close()

    if user:
        return {
            "id": user["id"],
            "username": user["username"]
        }

    return None


def get_user_by_username(username):
    conn = get_connection()
    c = conn.cursor()

    c.execute(
        "SELECT id, username FROM users WHERE username=?",
        (username,)
    )

    user = c.fetchone()
    conn.close()

    if user:
        return {
            "id": user["id"],
            "username": user["username"]
        }

    return None


def save_scan(user_id, target, risk, score, alerts, report=None):
    conn = get_connection()
    c = conn.cursor()

    try:
        c.execute("PRAGMA foreign_keys = ON")

        c.execute("""
        INSERT INTO scans (user_id, target, risk, score, alerts, report)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, target, risk, score, alerts, report))

        scan_id = c.lastrowid

        report_data = {}
        if report:
            try:
                report_data = json.loads(report) if isinstance(report, str) else report
            except Exception:
                report_data = {}

        structured = report_data.get("structured", {}) if isinstance(report_data, dict) else {}

        findings = structured.get("scan_findings", [])
        subdomains = structured.get("scan_subdomains", [])
        ports = structured.get("scan_ports", [])
        cves = structured.get("scan_cves", [])

        for item in findings:
            c.execute("""
            INSERT INTO scan_findings
            (scan_id, title, severity, category, description, evidence, fix)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                item.get("title"),
                item.get("severity"),
                item.get("category"),
                item.get("description"),
                item.get("evidence"),
                item.get("fix")
            ))

        for item in subdomains:
            c.execute("""
            INSERT INTO scan_subdomains
            (scan_id, subdomain, ips, http, https, status_code, final_url)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                item.get("subdomain"),
                json.dumps(item.get("ips", [])),
                1 if item.get("http") else 0,
                1 if item.get("https") else 0,
                item.get("status_code"),
                item.get("final_url")
            ))

        for item in ports:
            c.execute("""
            INSERT INTO scan_ports
            (scan_id, port, service, banner, risk)
            VALUES (?, ?, ?, ?, ?)
            """, (
                scan_id,
                item.get("port"),
                item.get("service"),
                item.get("banner"),
                item.get("risk")
            ))

        for item in cves:
            c.execute("""
            INSERT INTO scan_cves
            (scan_id, technology, cve_id, severity, score, published, description, url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                item.get("technology"),
                item.get("cve_id"),
                item.get("severity"),
                item.get("score"),
                item.get("published"),
                item.get("description"),
                item.get("url")
            ))

        conn.commit()
        return scan_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_user_scans(user_id):
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    SELECT id, target, risk, score, alerts, report, created_at
    FROM scans
    WHERE user_id=?
    ORDER BY created_at DESC
    """, (user_id,))

    rows = c.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def get_scan_details(scan_id, user_id):
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    SELECT id, target, risk, score, alerts, report, created_at
    FROM scans
    WHERE id=? AND user_id=?
    """, (scan_id, user_id))

    scan = c.fetchone()

    if not scan:
        conn.close()
        return None

    c.execute("SELECT title, severity, category, description, evidence, fix FROM scan_findings WHERE scan_id=?", (scan_id,))
    findings = [dict(row) for row in c.fetchall()]

    c.execute("SELECT subdomain, ips, http, https, status_code, final_url FROM scan_subdomains WHERE scan_id=?", (scan_id,))
    subdomains = []
    for row in c.fetchall():
        item = dict(row)
        try:
            item["ips"] = json.loads(item["ips"]) if item["ips"] else []
        except Exception:
            item["ips"] = []
        item["http"] = bool(item["http"])
        item["https"] = bool(item["https"])
        subdomains.append(item)

    c.execute("SELECT port, service, banner, risk FROM scan_ports WHERE scan_id=?", (scan_id,))
    ports = [dict(row) for row in c.fetchall()]

    c.execute("SELECT technology, cve_id, severity, score, published, description, url FROM scan_cves WHERE scan_id=?", (scan_id,))
    cves = [dict(row) for row in c.fetchall()]

    conn.close()

    result = dict(scan)

    try:
        report_data = json.loads(result["report"]) if result.get("report") else {}
    except Exception:
        report_data = {}

    report_data["structured"] = {
        "scan_findings": findings,
        "scan_subdomains": subdomains,
        "scan_ports": ports,
        "scan_cves": cves
    }

    return report_data


def delete_scan(scan_id, user_id):
    conn = get_connection()
    c = conn.cursor()

    try:
        c.execute("PRAGMA foreign_keys = ON")

        c.execute(
            "SELECT id FROM scans WHERE id=? AND user_id=?",
            (scan_id, user_id)
        )

        row = c.fetchone()

        if not row:
            return False

        c.execute(
            "DELETE FROM scans WHERE id=? AND user_id=?",
            (scan_id, user_id)
        )

        conn.commit()
        return True

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()
