from __future__ import annotations

import json
import os
import signal
import tempfile
import time
from pathlib import Path
from typing import Any

TERMINAL = {"completed", "failed", "rejected", "cancelled", "timed_out", "orphaned", "delivery_failed"}


class JobStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path(self, request_id: str) -> Path:
        if not request_id or not all(char.isalnum() or char in "_-" for char in request_id):
            raise ValueError("invalid request identifier")
        return self.root / f"{request_id}.json"

    def _write(self, record: dict[str, Any]) -> None:
        path = self._path(str(record["request_id"]))
        fd, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=self.root)
        try:
            os.fchmod(fd, 0o600)
            payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
            with os.fdopen(fd, "wb", closefd=False) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, path)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass

    def get(self, request_id: str) -> dict[str, Any]:
        value = json.loads(self._path(request_id).read_text())
        if not isinstance(value, dict) or value.get("request_id") != request_id:
            raise ValueError("invalid job record")
        return value

    def create(self, request_id: str, *, task_id: str, repository: str, caller: str) -> None:
        path = self._path(request_id)
        if path.exists():
            raise ValueError("request identifier already exists")
        now = int(time.time())
        self._write({"version": 1, "request_id": request_id, "task_id": task_id, "repository": repository, "caller": caller, "status": "pending", "process_group": None, "result": None, "created_at": now, "updated_at": now})

    def _transition(self, request_id: str, status: str, *, process_group: int | None = None, result: dict[str, Any] | None = None) -> None:
        record = self.get(request_id)
        record.update(status=status, process_group=process_group, updated_at=int(time.time()))
        if result is not None:
            record["result"] = result
        self._write(record)

    def running(self, request_id: str, *, process_group: int) -> None:
        self._transition(request_id, "running", process_group=process_group)

    def finish(self, request_id: str, status: str, result: dict[str, Any]) -> None:
        if status not in TERMINAL:
            raise ValueError("invalid terminal status")
        self._transition(request_id, status, result=result)

    def delivery_failed(self, request_id: str) -> None:
        record = self.get(request_id)
        self._transition(request_id, "delivery_failed", result=record.get("result"))

    def recover_orphans(self) -> None:
        for path in self.root.glob("*.json"):
            record = self.get(path.stem)
            if record.get("status") in {"pending", "running"}:
                self._transition(path.stem, "orphaned", result=record.get("result"))

    def cancel(self, request_id: str) -> bool:
        record = self.get(request_id)
        if record.get("status") != "running" or not isinstance(record.get("process_group"), int):
            return False
        try:
            os.killpg(record["process_group"], signal.SIGTERM)
        except ProcessLookupError:
            pass
        self._transition(request_id, "cancelled", result=record.get("result"))
        return True
