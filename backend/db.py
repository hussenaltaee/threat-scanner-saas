import sqlite3
import hashlib

DB_NAME = "database.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def init_db():
    conn = get_connection()
    c = conn.cursor()

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
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Migration: إذا جدول scans القديم كان يحتوي user بدل user_id
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
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """)

        c.execute("""
        INSERT INTO scans (id, target, risk, score, alerts, report, created_at)
        SELECT id, target, risk, score, alerts, report, created_at
        FROM scans_old
        """)

        c.execute("DROP TABLE scans_old")

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

    c.execute("""
    INSERT INTO scans (user_id, target, risk, score, alerts, report)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, target, risk, score, alerts, report))

    conn.commit()
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