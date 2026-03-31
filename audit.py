"""SQLite audit log for Credential Gate."""

import json
import sqlite3
import time
from pathlib import Path


_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    credential_name TEXT NOT NULL,
    fields_requested TEXT,
    purpose TEXT,
    status TEXT NOT NULL,
    ip_address TEXT,
    response_time_ms INTEGER,
    policy_checks TEXT
);
"""

_MIGRATE_POLICY_CHECKS = """\
ALTER TABLE audit_log ADD COLUMN policy_checks TEXT;
"""


class AuditLog:
    def __init__(self, db_path: str):
        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_CREATE_TABLE)
        self._conn.commit()
        # Migrate existing DBs: add policy_checks column if missing
        self._migrate()

    def _migrate(self):
        """Add columns introduced in later phases (idempotent)."""
        cursor = self._conn.execute("PRAGMA table_info(audit_log)")
        columns = {row[1] for row in cursor.fetchall()}
        if "policy_checks" not in columns:
            self._conn.execute(_MIGRATE_POLICY_CHECKS)
            self._conn.commit()

    def log(
        self,
        agent_id: str,
        credential_name: str,
        status: str,
        fields_requested: list[str] | None = None,
        purpose: str | None = None,
        ip_address: str | None = None,
        response_time_ms: int | None = None,
        policy_checks: list[dict] | None = None,
    ) -> int:
        """Insert an audit record. Returns the row id."""
        cur = self._conn.execute(
            """\
            INSERT INTO audit_log
                (timestamp, agent_id, credential_name, fields_requested,
                 purpose, status, ip_address, response_time_ms, policy_checks)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                agent_id,
                credential_name,
                json.dumps(fields_requested) if fields_requested else None,
                purpose,
                status,
                ip_address,
                response_time_ms,
                json.dumps(policy_checks) if policy_checks else None,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def recent(self, limit: int = 50) -> list[dict]:
        """Return the most recent audit entries."""
        rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        self._conn.close()
