"""
Database manager.
Handles all SQLite operations for the vault.
"""

import sqlite3
from pathlib import Path
from src.database.models import CREATE_VAULT_TABLE, CREATE_CONFIG_TABLE


DB_PATH = Path.home() / ".secure_pm" / "vault.db"


class DatabaseManager:

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._initialize_tables()

    def _initialize_tables(self):
        with self.conn:
            self.conn.execute(CREATE_VAULT_TABLE)
            self.conn.execute(CREATE_CONFIG_TABLE)

    def save_entry(self, site: str, username: str, password: bytes,
                   iv: bytes, tag: bytes, notes: str = "") -> int:
        sql = """
            INSERT INTO vault (site, username, password, iv, tag, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        with self.conn:
            cursor = self.conn.execute(sql, (site, username, password, iv, tag, notes))
            return cursor.lastrowid

    def get_all_entries(self) -> list:
        sql = "SELECT id, site, username, password, iv, tag, notes FROM vault ORDER BY site"
        return self.conn.execute(sql).fetchall()

    def get_entry_by_id(self, entry_id: int):
        sql = "SELECT * FROM vault WHERE id = ?"
        return self.conn.execute(sql, (entry_id,)).fetchone()

    def delete_entry(self, entry_id: int):
        with self.conn:
            self.conn.execute("DELETE FROM vault WHERE id = ?", (entry_id,))

    def set_config(self, key: str, value: bytes):
        sql = "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)"
        with self.conn:
            self.conn.execute(sql, (key, value))

    def get_config(self, key: str) -> bytes | None:
        row = self.conn.execute(
            "SELECT value FROM config WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def close(self):
        if self.conn:
            self.conn.close()