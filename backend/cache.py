"""
Simple TTL cache backed by SQLite.

Avoids repeating slow external lookups (WHOIS, SSL handshakes, Safe
Browsing calls, feed downloads) on every page scan.
"""

import json
from datetime import datetime, timedelta
from typing import Optional

import models


def _ensure_table():
    conn = models.get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_cache (
            cache_key TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


_ensure_table()


def get_cached(key: str, ttl_seconds: int) -> Optional[dict]:
    """Return cached data for key if present and younger than ttl_seconds, else None."""
    conn = models.get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT data, created_at FROM scan_cache WHERE cache_key = ?', (key,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    created_at = datetime.fromisoformat(row['created_at'])
    if datetime.now() - created_at > timedelta(seconds=ttl_seconds):
        return None

    return json.loads(row['data'])


def set_cached(key: str, data: dict) -> None:
    conn = models.get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_cache (cache_key, data, created_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(cache_key) DO UPDATE SET
            data = excluded.data,
            created_at = CURRENT_TIMESTAMP
    ''', (key, json.dumps(data)))
    conn.commit()
    conn.close()
