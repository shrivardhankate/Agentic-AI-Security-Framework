
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
ENV_ROOT = ROOT / "environment"
POLICY_PATH = ROOT / "policies" / "security_policy.json"
AUDIT_PATH = ROOT / "logs" / "audit.jsonl"


class AccessDenied(Exception):
    """Raised when an environment operation is not authorized."""


class LabGateway:
    """A local, default-deny gateway for the synthetic security lab."""

    def __init__(self) -> None:
        self.policy = json.loads(
            POLICY_PATH.read_text(encoding="utf-8")
        )
        self.audit_path = AUDIT_PATH
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)

    def _audit(
        self,
        action: str,
        resource: str,
        decision: str,
        reason: str,
    ) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "resource": resource,
            "decision": decision,
            "reason": reason,
        }
        with self.audit_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")

    def _deny(
        self,
        action: str,
        resource: str,
        reason: str,
    ) -> None:
        self._audit(action, resource, "DENY", reason)
        raise AccessDenied(reason)

    def _public_root(self) -> Path:
        return (ENV_ROOT / "files" / "public").resolve()

    def _safe_public_file(self, relative_path: str) -> Path:
        # Reject absolute paths and traversal before resolving.
        supplied = Path(relative_path)
        if supplied.is_absolute() or ".." in supplied.parts:
            self._deny(
                "read_file", relative_path, "Path traversal rejected"
            )

        root = self._public_root()
        candidate = (root / supplied).resolve()

        # Resolving symlinks before this check prevents escaping the root.
        if candidate != root and root not in candidate.parents:
            self._deny(
                "read_file", relative_path, "Path outside public sandbox"
            )

        if not candidate.is_file():
            self._deny(
                "read_file", relative_path, "File not found or not a file"
            )

        return candidate

    def list_public_files(self) -> list[str]:
        action = "list_files"
        resource = "files/public"

        try:
            root = self._public_root()
            if not root.is_dir():
                self._deny(action, resource, "Public directory unavailable")

            files = []
            for item in root.rglob("*"):
                # Do not follow symbolic links into other locations.
                if item.is_symlink():
                    continue
                if item.is_file():
                    files.append(item.relative_to(root).as_posix())

            result = sorted(files)
            self._audit(action, resource, "ALLOW", "Public listing")
            return result
        except AccessDenied:
            raise
        except OSError:
            self._deny(action, resource, "Filesystem operation failed")

    def read_public_file(self, relative_path: str) -> str:
        try:
            path = self._safe_public_file(relative_path)
            content = path.read_text(encoding="utf-8")
            self._audit(
                "read_file",
                f"files/public/{relative_path}",
                "ALLOW",
                "Public file read",
            )
            return content
        except AccessDenied:
            raise
        except (OSError, UnicodeError):
            self._deny(
                "read_file", relative_path, "Unable to read file"
            )

    def search_public_users(self, username: str) -> list[dict[str, Any]]:
        # A parameterized query prevents SQL injection.
        # This interface deliberately exposes only selected public columns.
        resource = "database/synthetic_users"

        if not isinstance(username, str) or len(username) > 100:
            self._deny("db_search_users", resource, "Invalid search input")

        try:
            db_path = ENV_ROOT / "database" / "lab.sqlite3"
            with sqlite3.connect(
                f"{db_path.resolve().as_uri()}?mode=ro",
                uri=True,
            ) as connection:
                connection.row_factory = sqlite3.Row
                rows = connection.execute(
                    """
                    SELECT user_id, username, role
                    FROM synthetic_users
                    WHERE username LIKE ?
                    ORDER BY user_id
                    LIMIT 50
                    """,
                    (f"%{username}%",),
                ).fetchall()

            results = [dict(row) for row in rows]
            self._audit(
                "db_search_users",
                resource,
                "ALLOW",
                "Approved read-only query",
            )
            return results
        except (sqlite3.Error, OSError):
            self._deny(
                "db_search_users", resource, "Database operation failed"
            )

    def list_public_documents(self) -> list[dict[str, Any]]:
        resource = "database/synthetic_documents"

        try:
            db_path = ENV_ROOT / "database" / "lab.sqlite3"
            with sqlite3.connect(
                f"{db_path.resolve().as_uri()}?mode=ro",
                uri=True,
            ) as connection:
                connection.row_factory = sqlite3.Row
                rows = connection.execute(
                    """
                    SELECT document_id, title, classification, body
                    FROM synthetic_documents
                    WHERE classification = ?
                    ORDER BY document_id
                    LIMIT 50
                    """,
                    ("public",),
                ).fetchall()

            results = [dict(row) for row in rows]
            self._audit(
                "db_list_public_documents",
                resource,
                "ALLOW",
                "Public documents only",
            )
            return results
        except (sqlite3.Error, OSError):
            self._deny(
                "db_list_public_documents",
                resource,
                "Database operation failed",
            )

    def retrieve_memory(self) -> list[dict[str, str]]:
        resource = "memory"

        try:
            memory_path = ENV_ROOT / "memory" / "memories.json"
            entries = json.loads(memory_path.read_text(encoding="utf-8"))

            if not isinstance(entries, list):
                self._deny("memory_read", resource, "Invalid memory format")

            # Preserve trust labels. Never promote untrusted content to policy.
            safe_entries = []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                safe_entries.append({
                    "memory_id": str(entry.get("memory_id", "")),
                    "content": str(entry.get("content", "")),
                    "source": str(entry.get("source", "unknown")),
                    "trust": (
                        "trusted"
                        if entry.get("trust") == "trusted"
                        else "untrusted"
                    ),
                })

            self._audit(
                "memory_read",
                resource,
                "ALLOW",
                "Memory returned with trust labels",
            )
            return safe_entries
        except AccessDenied:
            raise
        except (OSError, json.JSONDecodeError):
            self._deny("memory_read", resource, "Memory unavailable")

    def write_file(self, relative_path: str, content: str) -> None:
        # Writes are disabled in this initial baseline.
        self._deny(
            "write_file",
            relative_path,
            "Writes are disabled by the lab gateway",
        )

    def fetch_web(self, url: str) -> None:
        # Network access is disabled in this initial baseline.
        self._deny(
            "web_fetch",
            url,
            "Network access is disabled in this phase",
        )

    def execute_shell(self, command: str) -> None:
        # Never pass agent-provided strings to a shell.
        self._deny(
            "shell",
            "local_machine",
            "Shell execution is disabled",
        )
