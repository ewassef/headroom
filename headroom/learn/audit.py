"""Persistent audit records for ``headroom learn``."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from headroom import paths


def _content_sha(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def append_learn_audit_event(
    *,
    agent: str,
    project_path: Path,
    model: str,
    status: str,
    dry_run: bool,
    total_sessions: int = 0,
    total_calls: int = 0,
    total_failures: int = 0,
    recommendation_sections: list[str] | None = None,
    files: dict[Path, str] | None = None,
    warnings: list[str] | None = None,
    analysis_error: str | None = None,
    write_error: str | None = None,
) -> None:
    """Append one best-effort audit event for a learn outcome."""

    if paths.process_is_stateless():
        return
    record: dict[str, Any] = {
        "event": "headroom_learn_audit",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": agent,
        "project_path": str(project_path),
        "model": model,
        "status": status,
        "dry_run": dry_run,
        "total_sessions": total_sessions,
        "total_calls": total_calls,
        "total_failures": total_failures,
        "recommendation_sections": recommendation_sections or [],
        "warnings": warnings or [],
    }
    if analysis_error:
        record["analysis_error"] = analysis_error
    if write_error:
        record["write_error"] = write_error
    if files:
        record["files"] = [
            {
                "path": str(path),
                "content_sha256": _content_sha(content),
                "bytes": len(content.encode("utf-8")),
            }
            for path, content in sorted(files.items(), key=lambda item: str(item[0]))
        ]
    try:
        target = paths.learn_audit_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        return
