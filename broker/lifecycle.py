from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import signal
import tempfile
import stat
import time
from typing import Any

TERMINAL = {"completed", "failed", "rejected", "cancelled", "timed_out", "orphaned", "delivery_failed"}

LEASE_UNAVAILABLE = "job unavailable"

# A consumed lease's status window is bounded by its own timeout; past this age
# the tombstoned issued record is only scan ballast for issue().
TOMBSTONE_RETIREMENT_AGE = 24 * 60 * 60


class LeaseUnavailable(RuntimeError):
    pass


class LeaseStore:
    """Immutable issued capabilities plus broker-owned consumed tombstones."""

    def __init__(
        self,
        root: Path,
        *,
        issuer_uid: int,
        issuer_gid: int,
        broker_uid: int,
        broker_gid: int,
    ) -> None:
        self.root = root
        self.issued = root / "issued"
        self.consumed = root / "consumed"
        self._lock_path = root / ".lease-store.lock"
        self.issuer_uid = issuer_uid
        self.issuer_gid = issuer_gid
        self.broker_uid = broker_uid
        self.broker_gid = broker_gid
        if any(
            not path.is_dir() or path.is_symlink()
            for path in (root, self.issued, self.consumed)
        ):
            raise ValueError("lease store directories must preexist")

    @staticmethod
    def _handle_hash(lease_id: str) -> str:
        if not isinstance(lease_id, str) or not lease_id:
            raise LeaseUnavailable(LEASE_UNAVAILABLE)
        return hashlib.sha256(lease_id.encode()).hexdigest()

    def _path(self, lease_id: str) -> Path:
        return self.issued / f"{self._handle_hash(lease_id)}.json"

    def _consumed_path(self, lease_id: str) -> Path:
        return self.consumed / f"{self._handle_hash(lease_id)}.json"

    @staticmethod
    def _validate_inode(
        fd: int, *, mode: int, uid: int, gid: int, label: str,
    ) -> None:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != uid
            or metadata.st_gid != gid
        ):
            raise PermissionError(f"{label} ownership or mode is invalid")

    def _locked(self):
        fd = os.open(
            self._lock_path,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            self._validate_inode(
                fd, mode=0o660, uid=self.broker_uid,
                gid=self.issuer_gid, label="lease store lock",
            )
        except BaseException:
            os.close(fd)
            raise
        handle = os.fdopen(fd, "r+b")
        fcntl.flock(handle, fcntl.LOCK_EX)
        return handle

    @staticmethod
    def _digest_prompt(fixed_request: dict[str, Any]) -> str:
        prompt = fixed_request.get("prompt")
        if not isinstance(prompt, str):
            raise ValueError("fixed request prompt is invalid")
        return "sha256:" + hashlib.sha256(prompt.encode()).hexdigest()

    @staticmethod
    def _record_digest(record: dict[str, Any]) -> str:
        fields = (
            "version", "lease_handle_hash", "endpoint", "peer_uid", "request_id",
            "task_id", "fixed_request", "prompt_digest", "artifact_digest",
            "policy_version", "template_version", "issued_at", "expires_at",
        )
        canonical = {field: record[field] for field in fields}
        payload = json.dumps(
            canonical, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _tombstone_digest(record: dict[str, Any]) -> str:
        fields = (
            "version", "lease_handle_hash", "request_id", "task_id",
            "issued_record_digest", "consumed_at",
        )
        canonical = {field: record[field] for field in fields}
        payload = json.dumps(
            canonical, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _read_json_fd(fd: int) -> object:
        with os.fdopen(os.dup(fd), "rb") as handle:
            return json.loads(handle.read())

    def _read_issued_path(self, path: Path) -> dict[str, Any]:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            self._validate_inode(
                fd, mode=0o640, uid=self.issuer_uid,
                gid=self.broker_gid, label="issued lease",
            )
            record = self._read_json_fd(fd)
        finally:
            os.close(fd)
        if (
            not isinstance(record, dict)
            or path.stem != record.get("lease_handle_hash")
            or record.get("record_digest") != self._record_digest(record)
        ):
            raise ValueError("invalid issued lease record")
        return record

    def _write_issued(self, path: Path, record: dict[str, Any]) -> None:
        fd, temporary_name = tempfile.mkstemp(
            prefix=path.name + ".", dir=self.issued)
        try:
            os.fchmod(fd, 0o640)
            self._validate_inode(
                fd, mode=0o640, uid=self.issuer_uid,
                gid=self.broker_gid, label="issued lease",
            )
            payload = (
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
            with os.fdopen(fd, "wb", closefd=False) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, path)
            directory_fd = os.open(self.issued, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass

    def issue(
        self,
        *,
        fixed_request: dict[str, Any],
        endpoint: str,
        peer_uid: int,
        artifact_digest: str,
        policy_version: str,
        template_version: str,
        expires_at: int,
    ) -> str:
        required = {
            "request_id", "task_id", "repository", "caller", "workspace", "sandbox",
            "model", "prompt", "timeout",
        }
        string_fields = (
            "request_id", "task_id", "repository", "caller", "workspace", "sandbox",
            "model", "prompt",
        )
        timeout = fixed_request.get("timeout")
        if (
            set(fixed_request) != required
            or not all(
                isinstance(fixed_request.get(field), str) and fixed_request[field]
                for field in string_fields
            )
            or not isinstance(endpoint, str)
            or not endpoint
            or isinstance(peer_uid, bool)
            or not isinstance(peer_uid, int)
            or peer_uid < 0
            or not all(
                isinstance(value, str) and value
                for value in (artifact_digest, policy_version, template_version)
            )
            or isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
        ):
            raise ValueError("invalid fixed lease request")
        request_id = fixed_request["request_id"]
        task_id = fixed_request["task_id"]
        handle = secrets.token_urlsafe(32)
        handle_hash = self._handle_hash(handle)
        path = self._path(handle)
        with self._locked():
            if os.path.lexists(path):
                raise ValueError("lease identifier already exists")
            for candidate in self.issued.glob("*.json"):
                try:
                    prior = self._read_issued_path(candidate)
                except (OSError, KeyError, TypeError, ValueError):
                    raise ValueError("invalid existing lease record") from None
                if (
                    prior.get("request_id") == request_id
                    or prior.get("task_id") == task_id
                ):
                    raise ValueError("task or request already has a lease")
            record = {
                "version": 2,
                "lease_handle_hash": handle_hash,
                "endpoint": endpoint,
                "peer_uid": peer_uid,
                "request_id": request_id,
                "task_id": task_id,
                "fixed_request": dict(fixed_request),
                "prompt_digest": self._digest_prompt(fixed_request),
                "artifact_digest": artifact_digest,
                "policy_version": policy_version,
                "template_version": template_version,
                "issued_at": int(time.time()),
                "expires_at": expires_at,
            }
            record["record_digest"] = self._record_digest(record)
            self._write_issued(path, record)
        return handle

    def _read_bound(
        self, lease_id: str, *, endpoint: str, peer_uid: int,
    ) -> dict[str, Any]:
        try:
            record = self._read_issued_path(self._path(lease_id))
            fixed = record["fixed_request"]
            valid = (
                record.get("version") == 2
                and record.get("lease_handle_hash") == self._handle_hash(lease_id)
                and record.get("endpoint") == endpoint
                and record.get("peer_uid") == peer_uid
                and isinstance(fixed, dict)
                and record.get("request_id") == fixed.get("request_id")
                and record.get("task_id") == fixed.get("task_id")
                and record.get("prompt_digest") == self._digest_prompt(fixed)
            )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            valid = False
            record = {}
        if not valid:
            raise LeaseUnavailable(LEASE_UNAVAILABLE)
        return record

    def _create_tombstone(
        self, lease_id: str, issued_record: dict[str, Any],
    ) -> None:
        path = self._consumed_path(lease_id)
        try:
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError:
            raise LeaseUnavailable(LEASE_UNAVAILABLE) from None
        try:
            os.fchmod(fd, 0o600)
            self._validate_inode(
                fd, mode=0o600, uid=self.broker_uid,
                gid=self.broker_gid, label="consumed lease",
            )
            record = {
                "version": 2,
                "lease_handle_hash": self._handle_hash(lease_id),
                "request_id": issued_record["request_id"],
                "task_id": issued_record["task_id"],
                "issued_record_digest": issued_record["record_digest"],
                "consumed_at": int(time.time()),
            }
            record["record_digest"] = self._tombstone_digest(record)
            payload = (
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
            with os.fdopen(fd, "wb", closefd=False) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            directory_fd = os.open(self.consumed, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            os.close(fd)

    def _read_tombstone(
        self, path: Path, issued_record: dict[str, Any],
    ) -> dict[str, Any]:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            self._validate_inode(
                fd, mode=0o600, uid=self.broker_uid,
                gid=self.broker_gid, label="consumed lease",
            )
            record = self._read_json_fd(fd)
        finally:
            os.close(fd)
        if (
            not isinstance(record, dict)
            or path.stem != record.get("lease_handle_hash")
            or record.get("request_id") != issued_record.get("request_id")
            or record.get("task_id") != issued_record.get("task_id")
            or record.get("issued_record_digest") != issued_record.get("record_digest")
            or record.get("record_digest") != self._tombstone_digest(record)
        ):
            raise LeaseUnavailable(LEASE_UNAVAILABLE)
        return record

    def peek(self, lease_id: str, *, endpoint: str, peer_uid: int) -> dict[str, Any]:
        """The bound fixed request, read without consuming: policy validation
        runs on it before the identity is spent."""
        with self._locked():
            record = self._read_bound(
                lease_id, endpoint=endpoint, peer_uid=peer_uid)
            return dict(record["fixed_request"])

    def consume(self, lease_id: str, *, endpoint: str, peer_uid: int) -> dict[str, Any]:
        """Create the durable tombstone before any credential or job side effect."""
        with self._locked():
            record = self._read_bound(
                lease_id, endpoint=endpoint, peer_uid=peer_uid)
            expires_at = record.get("expires_at")
            if (
                os.path.lexists(self._consumed_path(lease_id))
                or isinstance(expires_at, bool)
                or not isinstance(expires_at, int)
                or expires_at <= int(time.time())
            ):
                raise LeaseUnavailable(LEASE_UNAVAILABLE)
            self._create_tombstone(lease_id, record)
            return dict(record["fixed_request"])

    def resolve(self, lease_id: str, *, endpoint: str, peer_uid: int) -> dict[str, Any]:
        with self._locked():
            record = self._read_bound(
                lease_id, endpoint=endpoint, peer_uid=peer_uid)
            try:
                self._read_tombstone(self._consumed_path(lease_id), record)
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                raise LeaseUnavailable(LEASE_UNAVAILABLE) from None
            return dict(record["fixed_request"])

    def resolve_for_reexecution(
        self, lease_id: str, *, endpoint: str, peer_uid: int,
    ) -> dict[str, Any]:
        """Resolve a consumed lease only while its execution deadline remains open."""
        with self._locked():
            record = self._read_bound(
                lease_id, endpoint=endpoint, peer_uid=peer_uid)
            try:
                tombstone = self._read_tombstone(
                    self._consumed_path(lease_id), record)
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                raise LeaseUnavailable(LEASE_UNAVAILABLE) from None
            consumed_at = tombstone.get("consumed_at")
            expires_at = record.get("expires_at")
            if (
                isinstance(consumed_at, bool)
                or not isinstance(consumed_at, int)
                or consumed_at > int(time.time())
                or isinstance(expires_at, bool)
                or not isinstance(expires_at, int)
                or expires_at <= int(time.time())
            ):
                raise LeaseUnavailable(LEASE_UNAVAILABLE)
            return dict(record["fixed_request"])

    def retire_consumed(self, *, protected_request_ids: tuple[str, ...] = ()) -> int:
        """Retire issued records proven consumed by a matching, over-age tombstone."""
        protected = set(protected_request_ids)
        retired = 0
        with self._locked():
            for candidate in list(self.issued.glob("*.json")):
                try:
                    record = self._read_issued_path(candidate)
                except (OSError, KeyError, TypeError, ValueError):
                    continue
                if record.get("request_id") in protected:
                    continue
                try:
                    tombstone = self._read_tombstone(
                        self.consumed / f"{candidate.stem}.json", record)
                except (LeaseUnavailable, OSError, KeyError, TypeError, ValueError):
                    continue
                consumed_at = tombstone.get("consumed_at")
                if (
                    isinstance(consumed_at, bool)
                    or not isinstance(consumed_at, int)
                    or consumed_at > int(time.time()) - TOMBSTONE_RETIREMENT_AGE
                ):
                    continue
                os.unlink(candidate)
                retired += 1
        return retired



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
        self._write({"version": 1, "request_id": request_id, "task_id": task_id,
                     "repository": repository, "caller": caller, "status": "pending",
                     "process_group": None, "result": None, "created_at": now,
                     "updated_at": now})

    def arm_reexecution(
        self, request_id: str, *, task_id: str, repository: str, caller: str,
    ) -> None:
        record = self.get(request_id)
        status = record.get("status")
        result = record.get("result")
        has_outcome = result is not None
        # A cancellation is re-runnable only when the child died without an
        # outcome. The broker ranks `cancelled` above `completed` when it
        # detects the hang-up, so a record can be cancelled *after* the child
        # wrote a final; re-running that one would discard the only durable
        # copy of a successful outcome.
        cancellation = (
            status == "cancelled"
            and (not has_outcome
                 or (isinstance(result, dict) and result.get("final") is None)))
        if (
            record.get("reexecuted")
            or (has_outcome and not cancellation)
            or status not in {"pending", "orphaned", "cancelled"}
            or record.get("process_group") is not None
            or record.get("task_id") != task_id
            or record.get("repository") != repository
            or record.get("caller") != caller
        ):
            raise ValueError("job record does not admit re-execution")
        record.update(status="pending", process_group=None, result=None,
                      reexecuted=True, updated_at=int(time.time()))
        self._write(record)

    def _transition(self, request_id: str, status: str, *,
                    process_group: int | None = None,
                    result: dict[str, Any] | None = None) -> None:
        record = self.get(request_id)
        record.update(status=status, process_group=process_group,
                      updated_at=int(time.time()))
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
