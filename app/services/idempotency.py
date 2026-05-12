import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional


class IdempotencyStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sign_requests (
                    request_hash TEXT PRIMARY KEY,
                    cert_type TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    principals TEXT NOT NULL,
                    ttl TEXT NOT NULL,
                    certificate TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def build_hash(payload: dict) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def get(self, request_hash: str) -> Optional[Dict]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT request_hash, cert_type, key_id, principals, ttl, certificate, created_at
                FROM sign_requests
                WHERE request_hash = ?
                """,
                (request_hash,),
            ).fetchone()
        return dict(row) if row else None

    def put(
        self,
        *,
        request_hash: str,
        cert_type: str,
        key_id: str,
        principals: List[str],
        ttl: str,
        certificate: str,
        created_at: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO sign_requests (
                    request_hash, cert_type, key_id, principals, ttl, certificate, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_hash,
                    cert_type,
                    key_id,
                    ",".join(principals),
                    ttl,
                    certificate,
                    created_at,
                ),
            )
