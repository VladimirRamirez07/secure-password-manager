"""
Database schema definitions.
Defines the structure of the vault tables.
"""

CREATE_VAULT_TABLE = """
CREATE TABLE IF NOT EXISTS vault (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site        TEXT    NOT NULL,
    username    TEXT    NOT NULL,
    password    BLOB    NOT NULL,
    iv          BLOB    NOT NULL,
    tag         BLOB    NOT NULL,
    notes       TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""

CREATE_CONFIG_TABLE = """
CREATE TABLE IF NOT EXISTS config (
    key         TEXT PRIMARY KEY,
    value       BLOB NOT NULL
);
"""