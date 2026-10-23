#!/usr/bin/env python3
"""Fixed-policy OMP worker broker for authenticated local callers."""

from __future__ import annotations

import dataclasses
import datetime
import fcntl
import hashlib
import json
import os
import pwd
import queue
import select
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Mapping

try:
    from broker import lifecycle as _lifecycle
except ModuleNotFoundError:
    import lifecycle as _lifecycle

JobStore = _lifecycle.JobStore
LeaseStore = _lifecycle.LeaseStore
LeaseUnavailable = _lifecycle.LeaseUnavailable


POLICY_FILE = Path(os.environ.get("HERMES_OMP_POLICY", "policy.json"))
OMP_BIN = Path(os.environ.get("HERMES_OMP_BIN", "omp"))
OMP_TOKEN_BIN = Path(os.environ.get("HERMES_OMP_TOKEN_BIN", str(OMP_BIN)))
OMP_CREDENTIAL_AGENT_DIR = Path(os.environ.get("HERMES_OMP_CREDENTIAL_DIR", "credentials"))
OMP_AGENT_DIR = Path(os.environ.get("HERMES_OMP_AGENT_DIR", "state/agent"))
EXTENSION = Path(os.environ.get("HERMES_OMP_EXTENSION", "extension/omp-delegate-extension.ts"))
LOCK_DIR = Path(os.environ.get("HERMES_OMP_LOCK_DIR", "state/locks"))
AUDIT_LOG = Path(os.environ.get("HERMES_OMP_AUDIT_LOG", "state/audit.jsonl"))
MODEL = os.environ.get("HERMES_OMP_MODEL", "provider/model")
MAX_REQUEST_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 8_000_000
MAX_CAPTURE_BYTES = 1_000_000
MAX_PROMPT_CHARS = 500_000
MAX_TIMEOUT = 810.0
ABSOLUTE_MAX_TIMEOUT = 3600.0
FRAME_TIMEOUT = 5.0
MAX_CONTROL_CONNECTIONS = 8
MAX_WAITING_EXECUTIONS = 16
WORKER_SOCKET = os.environ.get("HERMES_OMP_WORKER_SOCKET", "")
WORKER_USER = os.environ.get("HERMES_OMP_WORKER_USER", "omp-delegate-worker")
CREDENTIAL_SOURCE = os.environ.get("HERMES_OMP_CREDENTIAL_SOURCE", "omp-token")
JOB_STORE = JobStore(Path(os.environ.get("HERMES_OMP_JOB_DIR", "state/jobs")))


# Inside the state directory the unit admits writes to through its
# ReadWritePaths entry. This service runs ProtectHome=read-only with
# ProtectSystem=strict, so the natural "state root" spot one level up answers
# EROFS and the stamp is never written at all (measured 2026-09-12).
BROKER_POLICY_STAMP = Path(os.environ.get(
    "HERMES_OMP_POLICY_STAMP",
    str(Path(os.environ.get(
        "HERMES_OMP_AGENT_DIR", "state/agent")) / "broker-policy.json"),
))


def policy_pair_digest(script_bytes: bytes, policy_bytes: bytes) -> str:
    """SHA-256 digest of the (script, policy) pair.

    The reporter computes the same value from the deployed files.
    """
    script_row = "sha256:" + hashlib.sha256(script_bytes).hexdigest()
    policy_row = "sha256:" + hashlib.sha256(policy_bytes).hexdigest()
    payload = f"{script_row}\n{policy_row}"
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_policy_stamp(
    *,
    script_file: str | None = None,
    policy_file: str | None = None,
    stamp_file: Path | None = None,
    script_bytes: bytes | None = None,
    policy_bytes: bytes | None = None,
) -> dict[str, object] | None:
    """Write the broker policy-pair stamp, failing soft on reporting errors."""
    stamp_file = stamp_file if stamp_file is not None else BROKER_POLICY_STAMP
    script_is_loaded = script_file is None
    policy_is_loaded = policy_file is None
    script_path = Path(script_file if script_file is not None else _LOADED_SCRIPT_PATH)
    policy_path = Path(policy_file if policy_file is not None else _LOADED_POLICY_PATH)
    script_path = Path(os.path.abspath(script_path))
    policy_path = Path(os.path.abspath(policy_path))
    try:
        if (
            not _LOADED_SCRIPT_VERIFIED
            or not getattr(_lifecycle, "_LOADED_SOURCE_VERIFIED", False)
            or _LOADED_POLICY_BYTES is None
        ):
            raise OSError("loaded artifact provenance is unavailable")
        if script_bytes is None:
            script_bytes = _LOADED_SCRIPT_BYTES if script_is_loaded else script_path.read_bytes()
        if policy_bytes is None:
            policy_bytes = _LOADED_POLICY_BYTES if policy_is_loaded else policy_path.read_bytes()
        if script_bytes is None or policy_bytes is None:
            raise OSError("loaded policy pair is unavailable")
    except OSError as exc:
        print(f"omp-delegate-broker: cannot read policy pair for stamp: {exc}",
              file=sys.stderr)
        return None
    stamp = {
        "pid": os.getpid(),
        "start_monotonic_usec": time.monotonic_ns() // 1000,
        "policy_file": str(policy_path),
        "script_file": str(script_path),
        "policy_pair_digest": policy_pair_digest(script_bytes, policy_bytes),
        "loaded_artifacts": {
            "script": {
                "path": str(_LOADED_SCRIPT_PATH),
                "sha256": "sha256:" + hashlib.sha256(_LOADED_SCRIPT_BYTES).hexdigest(),
            },
            "policy": {
                "path": str(_LOADED_POLICY_PATH),
                "sha256": "sha256:" + hashlib.sha256(_LOADED_POLICY_BYTES).hexdigest(),
            },
            "lifecycle": {
                "path": _lifecycle._LOADED_SOURCE_PATH,
                "sha256": "sha256:" + hashlib.sha256(_lifecycle._LOADED_SOURCE_BYTES).hexdigest(),
            },
        },
        "written_at": datetime.datetime.now(datetime.timezone.utc)
                      .isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    stamp_bytes = (json.dumps(stamp, sort_keys=True) + "\n").encode()
    try:
        stamp_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary_name = tempfile.mkstemp(
            prefix=stamp_file.name + ".", dir=stamp_file.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(stamp_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, stamp_file)
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
    except OSError as exc:
        print(f"omp-delegate-broker: stamp write failed: {exc}", file=sys.stderr)
        return None
    return stamp


def _load_lease_stores() -> dict[str, LeaseStore]:
    raw = os.environ.get("HERMES_OMP_LEASE_DIRS", "")
    if not raw:
        return {}
    stores: dict[str, LeaseStore] = {}
    for item in raw.split(","):
        endpoint, separator, directory = item.partition("=")
        path = Path(directory)
        if (
            not separator
            or not endpoint
            or not all(char.isalnum() or char in "_-" for char in endpoint)
            or endpoint in stores
            or not path.is_absolute()
            or not path.is_dir()
            or path.is_symlink()
        ):
            raise SystemExit(
                "omp-delegate-broker: invalid HERMES_OMP_LEASE_DIRS mapping")
        identity = ENDPOINT_IDENTITIES.get(endpoint)
        if identity is None:
            raise SystemExit(
                "omp-delegate-broker: lease store has no endpoint user")
        stores[endpoint] = LeaseStore(
            path,
            issuer_uid=identity[0],
            issuer_gid=identity[1],
            broker_uid=os.geteuid(),
            broker_gid=os.getegid(),
        )
    return stores


def _load_endpoint_identities(raw: str) -> dict[str, tuple[int, int]]:
    if not raw:
        return {}
    resolved: dict[str, tuple[int, int]] = {}
    for item in raw.split(","):
        endpoint, separator, username = item.partition("=")
        if (
            not separator
            or not endpoint
            or not username
            or not all(char.isalnum() or char in "_-" for char in endpoint)
            or endpoint in resolved
        ):
            raise SystemExit(
                "omp-delegate-broker: invalid HERMES_OMP_ENDPOINT_USERS mapping")
        try:
            account = pwd.getpwnam(username)
        except KeyError:
            raise SystemExit(
                "omp-delegate-broker: endpoint user does not exist") from None
        resolved[endpoint] = (account.pw_uid, account.pw_gid)
    return resolved


def _load_endpoint_uids(raw: str) -> dict[str, int]:
    return {
        endpoint: identity[0]
        for endpoint, identity in _load_endpoint_identities(raw).items()
    }


def _load_endpoint_callers(raw: str) -> dict[str, str]:
    """Bind a private named endpoint to one trusted caller policy."""
    if not raw:
        return {}
    callers: dict[str, str] = {}
    for item in raw.split(","):
        endpoint, separator, caller = item.partition("=")
        if (
            not separator
            or not endpoint
            or not caller
            or not all(char.isalnum() or char in "_-" for char in endpoint)
            or not all(char.isalnum() or char in "_-" for char in caller)
            or endpoint in callers
        ):
            raise SystemExit(
                "omp-delegate-broker: invalid HERMES_OMP_ENDPOINT_CALLERS mapping")
        callers[endpoint] = caller
    return callers


ENDPOINT_IDENTITIES = _load_endpoint_identities(
    os.environ.get("HERMES_OMP_ENDPOINT_USERS", ""))
ENDPOINT_UIDS = {
    endpoint: identity[0]
    for endpoint, identity in ENDPOINT_IDENTITIES.items()
}
ENDPOINT_CALLERS = _load_endpoint_callers(
    os.environ.get("HERMES_OMP_ENDPOINT_CALLERS", ""))


LEASE_STORES = _load_lease_stores()
_ACTIVE_PROCESS_GROUP: int | None = None


_LOADED_POLICY_BYTES: bytes | None = None
_LOADED_SCRIPT_BYTES: bytes | None = None
_LOADED_SCRIPT_PATH = Path(os.path.abspath(__file__))
_LOADED_POLICY_PATH = Path(os.path.abspath(POLICY_FILE))
_LOADED_SCRIPT_VERIFIED = False
try:
    _LOADED_SCRIPT_BYTES = _LOADED_SCRIPT_PATH.read_bytes()
    _LOADED_SCRIPT_VERIFIED = sys._getframe().f_code == compile(
        _LOADED_SCRIPT_BYTES, __file__, "exec",
        dont_inherit=True, optimize=sys.flags.optimize)
except (OSError, SyntaxError, ValueError):
    pass

def _load_policy() -> tuple[
    dict[str, set[Path]], dict[str, str], dict[str, Path],
    dict[str, dict[str, object]], frozenset[str] | None,
]:
    global _LOADED_POLICY_BYTES
    try:
        _LOADED_POLICY_BYTES = POLICY_FILE.read_bytes()
        value = json.loads(_LOADED_POLICY_BYTES)
        repositories = value.get("repositories", {})
        repository_paths = {
            str(name): Path(entry["path"]).resolve()
            for name, entry in repositories.items()
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
        }
        raw_callers = value.get("callers")
        if not isinstance(raw_callers, dict):
            raw_callers = {"delegate_to_omp": {
                "repositories": list(repository_paths), "sandbox": "workspace-write"}}
        callers = {str(name): entry for name, entry in raw_callers.items()
                   if isinstance(entry, dict)}
        workspaces: dict[str, set[Path]] = {}
        sandboxes: dict[str, str] = {}
        for name, entry in callers.items():
            repository_names, sandbox = entry.get("repositories", []), entry.get("sandbox")
            if (isinstance(repository_names, list)
                    and all(isinstance(item, str) for item in repository_names)
                    and isinstance(sandbox, str)):
                workspaces[name] = {repository_paths[item] for item in repository_names
                                    if item in repository_paths}
                sandboxes[name] = sandbox
        raw_safe = value.get("replay_safe_models")
        safe_models = (
            frozenset(raw_safe) if isinstance(raw_safe, list)
            and raw_safe and all(
                isinstance(item, str)
                and item == item.strip()
                and item
                and not any(char.isspace() for char in item)
                and not any(char in item for char in "*?[]")
                and "/" in item
                and bool(item.partition("/")[0])
                and bool(item.partition("/")[2])
                for item in raw_safe)
            else None)
        return workspaces, sandboxes, repository_paths, callers, safe_models
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        _LOADED_POLICY_BYTES = None
        return {}, {}, {}, {}, None
ALLOWED_WORKSPACES, ALLOWED_SANDBOXES, REPOSITORY_PATHS, CALLER_POLICIES, REPLAY_SAFE_MODELS = _load_policy()
REQUEST_FIELDS = {"version", "request_id", "task_id", "repository", "caller", "workspace", "sandbox", "model", "prompt", "timeout"}
STATUS_REQUEST_FIELDS = {"version", "op", "request_id", "caller", "repository"}
V2_REQUEST_FIELDS = {"version", "op", "lease_id"}
HEALTH_REQUEST_FIELDS = {"version", "op"}
STATUS_JOB_FIELDS = (
    "request_id", "task_id", "repository", "caller", "status", "result",
    "created_at", "updated_at",
)
RESPONSE_FIELDS = {
    "version", "exit_code", "stdout", "stderr", "timed_out",
    "process_group_clear", "final", "request_id",
}
FINAL_FIELDS = {"summary", "verification", "gaps", "verdict"}
OPTIONAL_FINAL_FIELDS = {"served_model"}
FINDING_FIELDS = {"file", "lines", "severity", "issue", "fix"}
FINDING_SEVERITIES = {"low", "medium", "high", "critical"}
REVIEW_CALLER = "review-agent"
FINAL_VERDICTS = {"MET", "PARTIALLY MET", "NOT MET"}
SYSTEM_APPEND = (
    "You are an admitted OMP worker behind a fixed Hermes delegation boundary. "
    "Work only in the current workspace. Call broker_finalize exactly once after all edits "
    "and honest verification. Do not confuse it with xd://finalize. Do not continue using "
    "tools after broker_finalize."
)


class ProtocolError(RuntimeError):
    def __init__(self, message: str, *, version: int = 1, operation: str = "execute") -> None:
        super().__init__(message)
        self.version = version
        self.operation = operation


def effective_model(caller: str) -> str:
    """The caller's pinned model, or the global one. Never caller-supplied."""
    value = CALLER_POLICIES.get(caller, {}).get("model")
    return value if isinstance(value, str) and value else MODEL


def effective_max_timeout(caller: str) -> float:
    """The caller's timeout ceiling, bounded by the broker's absolute cap.

    Policy-side only, like the model pin: a caller that could raise its own
    ceiling could hold the single-writer workspace lock indefinitely.
    """
    value = CALLER_POLICIES.get(caller, {}).get("max_timeout")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return MAX_TIMEOUT
    return min(float(value), ABSOLUTE_MAX_TIMEOUT)


def caller_allows_structured_result(caller: str) -> bool:
    """Whether policy admits one bounded project-owned JSON result."""
    return CALLER_POLICIES.get(caller, {}).get("structured_result") is True


@dataclasses.dataclass(frozen=True)
class Request:
    request_id: str
    task_id: str
    repository: str
    caller: str
    workspace: Path
    sandbox: str
    model: str
    prompt: str
    timeout: float
    read_paths: tuple[str, ...]
    write_patterns: tuple[str, ...]
    git_mode: str
    skills: tuple[str, ...]
    create_only: bool
    hookless_commit: bool = False
    structured_result: bool = False
    fallback_models: tuple[str, ...] | None = None
    fallback_selectors: tuple[str, ...] = ()
    protocol_version: int = 1
    reexecuted: bool = False


@dataclasses.dataclass(frozen=True)
class StatusRequest:
    request_id: str
    caller: str
    repository: str
    protocol_version: int = 1


@dataclasses.dataclass(frozen=True)
class ListenerEndpoint:
    endpoint: str
    socket: socket.socket

@dataclasses.dataclass(frozen=True)
class HealthRequest:
    endpoint: str
    peer_uid: int


@dataclasses.dataclass(frozen=True)
class DeferredExecution:
    value: dict[str, object]
    peer_uid: int
    endpoint: str

def git_common_dir(path: Path) -> Path | None:
    """The shared .git of a checkout or worktree, or None if it is not git."""
    try:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={path.resolve()}", "-C", str(path),
             "rev-parse", "--git-common-dir"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    common = Path(result.stdout.strip())
    if not common.is_absolute():
        common = path / common
    try:
        return common.resolve()
    except OSError:
        return None


def git_toplevel(path: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={path.resolve()}", "-C", str(path),
             "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return Path(result.stdout.strip()).resolve()
    except OSError:
        return None


def is_worktree_of(candidate: Path, admitted: Path) -> bool:
    """True when candidate is an already-created worktree root of admitted.

    The broker never creates worktrees. A nested directory of the admitted
    checkout is not a worktree: its toplevel is the checkout, not itself.
    """
    if not candidate.is_dir() or not admitted.is_dir():
        return False
    cand, adm = candidate.resolve(), admitted.resolve()
    if cand == adm:
        return False
    if git_toplevel(cand) != cand:
        return False
    left, right = git_common_dir(cand), git_common_dir(adm)
    return left is not None and left == right

def git_remote_identity(path: Path) -> str | None:
    """Canonical remote identity for a trusted checkout or isolated mirror."""
    try:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={path.resolve()}", "-C", str(path),
             "config", "--get", "remote.origin.url"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    raw = result.stdout.strip().removesuffix("/")
    for prefix in (
        "git@github.com:", "https://github.com/", "http://github.com/",
        "ssh://git@github.com/",
    ):
        if raw.startswith(prefix):
            return "github.com/" + raw.removeprefix(prefix).removesuffix(".git")
    return raw


def caller_workspace_root_membership(
    caller_policy: dict[str, object],
    repository: str,
    requested_workspace: Path,
    admitted: Path | None,
) -> tuple[bool, bool]:
    """(under an admitted caller root, mapped to the canonical repository)."""
    raw = caller_policy.get("workspace_roots", {})
    repository_names = caller_policy.get("repositories", [])
    if (
        not isinstance(raw, dict)
        or not isinstance(repository_names, list)
        or not all(isinstance(name, str) for name in repository_names)
    ):
        raise ProtocolError("caller workspace_roots policy is invalid")
    for key, values in raw.items():
        if (
            not isinstance(key, str)
            or key not in repository_names
            or key not in REPOSITORY_PATHS
            or not isinstance(values, list)
            or not all(isinstance(value, str) for value in values)
        ):
            raise ProtocolError("caller workspace_roots policy is invalid")
    roots = raw.get(repository, [])
    if not isinstance(roots, list):
        raise ProtocolError("caller workspace_roots policy is invalid")
    workspace = requested_workspace.resolve()
    workspace_remote = git_remote_identity(workspace)
    admitted_remote = (
        git_remote_identity(admitted) if admitted is not None else None)
    under_root = False
    mapped = False
    for value in roots:
        root = Path(value)
        if not root.is_absolute():
            raise ProtocolError("caller workspace_roots policy is invalid")
        resolved = root.resolve()
        try:
            relative = workspace.relative_to(resolved)
        except ValueError:
            continue
        if (
            relative == Path()
            or root.is_symlink()
            or not root.is_dir()
            or requested_workspace.is_symlink()
            or not workspace.is_dir()
            or git_toplevel(workspace) != workspace
        ):
            continue
        under_root = True
        if (
            admitted_remote is not None
            and workspace_remote is not None
            and workspace_remote == admitted_remote
        ):
            mapped = True
    return under_root, mapped



def _validate_peer_uid(peer_uid: int) -> None:
    allowed_uid = int(os.environ.get("HERMES_OMP_CALLER_UID", str(os.getuid())))
    if peer_uid != allowed_uid:
        raise ProtocolError("peer uid is not the admitted local identity")


def validate_status_request(value: object, *, peer_uid: int) -> StatusRequest:
    _validate_peer_uid(peer_uid)
    if not isinstance(value, dict) or set(value) != STATUS_REQUEST_FIELDS:
        raise ProtocolError("status request fields do not match protocol v1")
    if value.get("version") != 1 or value.get("op") != "status":
        raise ProtocolError("unsupported protocol operation or version")
    if not all(
        isinstance(value.get(name), str) and bool(value[name])
        for name in ("request_id", "caller", "repository")
    ):
        raise ProtocolError("status request string field is empty or has the wrong type")
    return StatusRequest(value["request_id"], value["caller"], value["repository"])


def _lane_is_replay_safe(request: Request) -> bool:
    """Require every effective model and fallback to be explicitly safe."""
    if REPLAY_SAFE_MODELS is None:
        return False
    return all(model in REPLAY_SAFE_MODELS
               for model in (request.model, *fallback_models(request)))

def _arm_resultless_reexecution(
    store: LeaseStore, lease_id: str, request: Request, *,
    endpoint: str, peer_uid: int,
) -> None:
    if not _lane_is_replay_safe(request):
        raise ProtocolError("job unavailable", version=2, operation="execute")
    try:
        fixed = store.resolve_for_reexecution(
            lease_id, endpoint=endpoint, peer_uid=peer_uid)
        JOB_STORE.arm_reexecution(
            str(fixed["request_id"]), task_id=str(fixed["task_id"]),
            repository=str(fixed["repository"]), caller=str(fixed["caller"]))
    except (LeaseUnavailable, OSError, ValueError) as exc:
        print(f"omp-delegate-broker: v2 execute re-execution denied: {exc!r}",
              file=sys.stderr)
        raise ProtocolError(
            "job unavailable", version=2, operation="execute") from None


def parse_request(
    value: object, *, peer_uid: int, endpoint: str | None = None,
) -> Request | StatusRequest | HealthRequest:
    if isinstance(value, dict) and value.get("op") == "health":
        unavailable = ProtocolError(
            "endpoint unavailable", version=2, operation="health")
        if (
            set(value) != HEALTH_REQUEST_FIELDS
            or value.get("version") != 2
            or not endpoint
            or endpoint not in LEASE_STORES
            or ENDPOINT_UIDS.get(endpoint) != peer_uid
        ):
            raise unavailable
        return HealthRequest(endpoint, peer_uid)
    if isinstance(value, dict) and value.get("version") == 2:
        operation = value.get("op")
        unavailable = ProtocolError(
            "job unavailable", version=2,
            operation=operation if operation in {"execute", "status"} else "execute",
        )
        if (
            set(value) != V2_REQUEST_FIELDS
            or operation not in {"execute", "status"}
            or not isinstance(value.get("lease_id"), str)
            or not value["lease_id"]
            or not endpoint
            or endpoint not in LEASE_STORES
        ):
            raise unavailable
        store = LEASE_STORES[endpoint]
        try:
            if operation == "execute":
                request = validate_request(
                    {"version": 1,
                     **store.peek(
                         value["lease_id"], endpoint=endpoint, peer_uid=peer_uid)},
                    peer_uid=None)
                bound_caller = ENDPOINT_CALLERS.get(endpoint)
                if bound_caller is not None and request.caller != bound_caller:
                    raise LeaseUnavailable(_lifecycle.LEASE_UNAVAILABLE)
                try:
                    store.consume(
                        value["lease_id"], endpoint=endpoint, peer_uid=peer_uid)
                except LeaseUnavailable:
                    # B3 (2026-09-12): the identity is spent. Re-admit the job
                    # exactly once when its record holds no result row and the
                    # caller's entire model chain is explicitly replay-safe;
                    # every other shape stays unavailable instead of looping
                    # the authority.
                    _arm_resultless_reexecution(
                        store, value["lease_id"], request,
                        endpoint=endpoint, peer_uid=peer_uid)
                    return dataclasses.replace(
                        request, protocol_version=2, reexecuted=True)
                return dataclasses.replace(request, protocol_version=2)
            fixed = store.resolve(
                value["lease_id"], endpoint=endpoint, peer_uid=peer_uid)
            bound_caller = ENDPOINT_CALLERS.get(endpoint)
            if bound_caller is not None and fixed["caller"] != bound_caller:
                raise LeaseUnavailable(_lifecycle.LEASE_UNAVAILABLE)
            return StatusRequest(
                str(fixed["request_id"]), str(fixed["caller"]),
                str(fixed["repository"]), 2,
            )
        except (LeaseUnavailable, ProtocolError, KeyError, OSError, TypeError, ValueError) as exc:
            # The wire deliberately stays generic for lease-bound callers,
            # but the journal must carry the true reason (2026-08-26: this
            # collapse hid a consumed-lease rejection for hours).
            print(f"omp-delegate-broker: v2 {operation} rejected: {exc!r}",
                  file=sys.stderr)
            raise unavailable from None
    if isinstance(value, dict) and "op" in value:
        if value.get("op") != "status":
            raise ProtocolError("unsupported protocol operation")
        return validate_status_request(value, peer_uid=peer_uid)
    return validate_request(value, peer_uid=peer_uid)


def validate_request(value: object, *, peer_uid: int | None) -> Request:
    if peer_uid is not None:
        _validate_peer_uid(peer_uid)
    if not isinstance(value, dict) or set(value) != REQUEST_FIELDS:
        raise ProtocolError("request fields do not match protocol v1")
    if value.get("version") != 1:
        raise ProtocolError("unsupported protocol version")
    if not all(isinstance(value.get(name), str) for name in ("request_id", "task_id", "repository", "caller", "workspace", "sandbox", "model", "prompt")):
        raise ProtocolError("request string field has the wrong type")
    if not value["request_id"] or not value["task_id"] or not value["repository"]:
        raise ProtocolError("request correlation fields are empty")
    caller = value["caller"]
    if caller not in ALLOWED_WORKSPACES:
        raise ProtocolError("caller is not allowlisted")
    requested_workspace = Path(value["workspace"])
    if requested_workspace.is_symlink():
        raise ProtocolError("workspace is not allowlisted for caller")
    workspace = requested_workspace.resolve()
    admitted = REPOSITORY_PATHS.get(value["repository"])
    caller_policy = CALLER_POLICIES[caller]
    rooted, root_mapped = caller_workspace_root_membership(
        caller_policy, value["repository"], requested_workspace, admitted)
    allowed = {path.resolve() for path in ALLOWED_WORKSPACES[caller]}
    linked = admitted is not None and is_worktree_of(workspace, admitted)
    mapped = admitted is not None and (
        workspace == admitted.resolve() or linked or root_mapped
    )
    if workspace not in allowed and not linked and not rooted:
        raise ProtocolError("workspace is not allowlisted for caller")
    if not mapped:
        raise ProtocolError("repository key does not map to requested workspace")
    if value["sandbox"] != ALLOWED_SANDBOXES[caller]:
        raise ProtocolError("sandbox is not fixed for caller")
    if value["model"] != effective_model(caller):
        raise ProtocolError("model does not match broker policy")
    prompt = value["prompt"]
    if not prompt or len(prompt) > MAX_PROMPT_CHARS:
        raise ProtocolError("prompt is empty or exceeds the broker bound")
    timeout = value["timeout"]
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ProtocolError("timeout is not numeric")
    timeout = float(timeout)
    if timeout <= 0 or timeout > effective_max_timeout(caller):
        raise ProtocolError("timeout is outside the broker bound")

    def _string_tuple(field: str) -> tuple[str, ...]:
        raw = caller_policy.get(field, [])
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            raise ProtocolError(f"caller {field} policy is invalid")
        return tuple(raw)

    git_mode = caller_policy.get("git_mode", "none")
    if git_mode not in {"none", "scoped"}:
        raise ProtocolError("caller git mode is invalid")
    create_only = caller_policy.get("create_only", False)
    if not isinstance(create_only, bool):
        raise ProtocolError("caller create-only policy is invalid")
    # Repositories whose git hooks cannot execute inside the delegated bash
    # sandbox mounts mark the caller hookless; the extension admits one
    # trailing --no-verify on the commit contract form for them alone.
    hookless_commit = caller_policy.get("hookless_commit", False)
    if not isinstance(hookless_commit, bool):
        raise ProtocolError("caller hookless-commit policy is invalid")
    structured_result = caller_policy.get("structured_result", False)
    if not isinstance(structured_result, bool):
        raise ProtocolError("caller structured-result policy is invalid")
    fallback_selectors = _string_tuple("fallback_selectors")
    if any(not _valid_fallback_model(item) for item in fallback_selectors):
        raise ProtocolError("caller fallback_selectors policy is invalid")
    return Request(
        value["request_id"], value["task_id"], value["repository"], caller, workspace,
        value["sandbox"], value["model"], prompt, timeout,
        _string_tuple("read_paths"), _string_tuple("write_patterns"),
        str(git_mode), _string_tuple("skills"), create_only,
        hookless_commit, structured_result,
        _caller_fallback_models(caller_policy), fallback_selectors,
    )


def write_retry_overlay(request: Request, directory: Path) -> Path:
    """Write a private per-request overlay: the exact model chain, speculative
    launch off, and web search pinned to the SearXNG role with an empty web
    fallback chain.

    omp_argv launches the child with --no-project-settings and
    --replace-fallback-chains, so the retry.fallbackChains record written here
    replaces the effective global/project record wholesale instead of
    deep-merging with it: no shared or workspace setting can widen, add or
    keep a chain of its own. Every key the resolver can still select on — the
    pinned model, each validated rung, each caller selector — carries the same
    broker-validated chain, and the catch-all default and web keys are empty,
    so effort-exact, wildcard and default lookups land inside the validated
    chain or nowhere."""
    chain = list(fallback_models(request))
    pinned = list(dict.fromkeys(
        (request.model, *chain, *request.fallback_selectors)
    ))
    path = directory / "retry-overlay.json"
    value = {
        "task": {"speculativeLaunch": False},
        "modelRoles": {"web": "web/searxng"},
        "retry": {
            "fallbackChains": {
                **{selector: chain for selector in pinned},
                "default": [],
                "web": [],
            },
        },
    }
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def omp_argv(request: Request, credential_fd: int,
             *, config_path: Path | None = None) -> list[str]:
    skill_args = (
        ["--skills", ",".join(request.skills)]
        if request.skills
        else ["--no-skills"]
    )
    # Per-job isolation contract: workspace project settings are skipped
    # entirely, and the retry overlay's fallbackChains record replaces the
    # lower layers instead of deep-merging with them. The replacement flag
    # fails closed without the explicit --config overlay it follows.
    config_args = (
        ["--config", str(config_path), "--no-project-settings",
         "--replace-fallback-chains"]
        if config_path is not None
        else []
    )
    return [
        str(OMP_BIN),
        "-p",
        "--no-session",
        "--no-title",
        "--no-prewalk",
        "--no-extensions",
        "--no-mcp",
        "--trusted-extension", str(EXTENSION),
        *skill_args,
        *config_args,
        "--no-rules",
        "--approval-mode=yolo",
        "--provider-api-keys-fd", str(credential_fd),
        "--model", request.model,
        "--cwd", str(request.workspace),
        "--append-system-prompt", SYSTEM_APPEND,
        f"--max-time={max(1, int(request.timeout - 5))}",
        request.prompt,
    ]


def omp_environment(
    base: Mapping[str, str],
    *,
    final_path: Path,
    request: Request,
) -> dict[str, str]:
    env = {
        "HOME": os.environ.get("HERMES_OMP_HOME", str(Path.home())),
        "PATH": os.environ.get("HERMES_OMP_PATH", os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")),
        "LANG": base.get("LANG", "C.UTF-8"),
        "LC_ALL": base.get("LC_ALL", "C.UTF-8"),
        "PI_CODING_AGENT_DIR": str(OMP_AGENT_DIR),
        "OMP_DELEGATE_FINAL_PATH": str(final_path),
        "OMP_DELEGATE_SANDBOX": request.sandbox,
        "OMP_DELEGATE_READ_PATHS": json.dumps(request.read_paths),
        "OMP_DELEGATE_WRITE_PATTERNS": json.dumps(request.write_patterns),
        "OMP_DELEGATE_GIT_MODE": request.git_mode,
        "OMP_DELEGATE_CREATE_ONLY": "1" if request.create_only else "0",
        "OMP_DELEGATE_HOOKLESS_COMMIT": "1" if request.hookless_commit else "0",
        "OMP_DELEGATE_CALLER": request.caller,
        "OMP_DELEGATE_STRUCTURED_RESULT": "1" if request.structured_result else "0",
    }
    if request.git_mode == "scoped":
        env.update({
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": str(request.workspace.resolve()),
        })
    return env


def _fallback_models() -> tuple[str, ...]:
    """Fixed extra rungs the child may retry on, as broker policy.

    Read from the environment the unit owns, never from the request: a caller that
    could name a fallback could name a provider whose credential it wanted minted.
    Used only when the caller entry does not carry `fallback_models`.
    """
    raw = os.environ.get("HERMES_OMP_FALLBACK_MODELS", "")
    return tuple(value for value in (part.strip() for part in raw.split(",")) if value)


FALLBACK_MODELS = _fallback_models()


def _valid_fallback_model(value: str) -> bool:
    provider, sep, rest = value.partition("/")
    return bool(sep and provider.strip() and rest.strip() and value == value.strip())


def _caller_fallback_models(caller_policy: Mapping[str, object]) -> tuple[str, ...] | None:
    if "fallback_models" not in caller_policy:
        return None
    raw = caller_policy["fallback_models"]
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ProtocolError("caller fallback_models policy is invalid")
    parsed: list[str] = []
    for item in raw:
        if not _valid_fallback_model(item):
            raise ProtocolError("caller fallback_models policy is invalid")
        parsed.append(item)
    return tuple(parsed)


def fallback_models(request: Request) -> tuple[str, ...]:
    """Caller-policy rungs when present; otherwise the service-wide default chain."""
    if request.fallback_models is not None:
        return request.fallback_models
    return FALLBACK_MODELS


def credential_providers(request: Request) -> tuple[str, ...]:
    """The pinned model's provider first, then each admitted fallback rung's, deduplicated."""
    providers = [request.model.partition("/")[0]]
    for model in fallback_models(request):
        provider = model.partition("/")[0]
        if provider and provider not in providers:
            providers.append(provider)
    return tuple(providers)


def worker_gateway_key() -> str:
    """Validate the worker-only credential without sending it over the broker socket."""
    if CREDENTIAL_SOURCE != "systemd":
        raise ProtocolError("worker credential source is unavailable")
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory or not Path(directory).is_absolute():
        raise ProtocolError("worker credential directory is unavailable")
    path = Path(directory) / "gateway-key"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 4096:
                raise ProtocolError("worker credential is invalid")
            token = os.read(fd, 4097).rstrip(b"\r\n")
        finally:
            os.close(fd)
    except OSError as exc:
        raise ProtocolError("worker credential is unavailable") from exc
    if not token or b"\x00" in token or any(chr(c).isspace() for c in token):
        raise ProtocolError("worker credential is invalid")
    try:
        return token.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("worker credential has invalid encoding") from exc


def resolve_provider_api_keys(request: Request) -> dict[str, str]:
    if CREDENTIAL_SOURCE == "systemd":
        if credential_providers(request) != ("gateway",):
            raise ProtocolError("worker credential is scoped to the gateway provider")
        return {"gateway": worker_gateway_key()}
    if CREDENTIAL_SOURCE != "omp-token":
        raise ProtocolError("credential source is not configured")
    env = {
        "HOME": os.environ.get("HERMES_OMP_HOME", str(Path.home())),
        "PATH": os.environ.get("HERMES_OMP_PATH", os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "PI_CODING_AGENT_DIR": str(OMP_CREDENTIAL_AGENT_DIR),
    }
    resolved: dict[str, str] = {}
    for provider in credential_providers(request):
        try:
            completed = subprocess.run(
                [str(OMP_TOKEN_BIN), "token", provider, "--raw"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=30,
                env=env,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProtocolError("pinned OMP provider credential could not be resolved") from exc
        value = completed.stdout.rstrip(b"\r\n")
        if (
            completed.returncode != 0
            or not value
            or len(value) > MAX_REQUEST_BYTES
            or b"\x00" in value
        ):
            raise ProtocolError("pinned OMP provider credential is unavailable")
        try:
            resolved[provider] = value.decode()
        except UnicodeDecodeError as exc:
            raise ProtocolError("pinned OMP provider credential has invalid encoding") from exc
    return resolved


def start_omp_process(
    request: Request,
    final_path: Path,
    provider_api_keys: Mapping[str, str],
) -> subprocess.Popen[bytes]:
    if CREDENTIAL_SOURCE == "systemd":
        # The worker's model catalog is root-owned; the worker cannot chmod it.
        if not OMP_AGENT_DIR.is_dir():
            raise OSError("worker model catalog directory is unavailable")
    else:
        OMP_AGENT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(OMP_AGENT_DIR, 0o700)
    payload = json.dumps(provider_api_keys, separators=(",", ":")).encode()
    credential_fd = os.memfd_create("omp-provider-api-keys", os.MFD_CLOEXEC)
    try:
        os.fchmod(credential_fd, 0o600)
        os.write(credential_fd, payload)
        os.lseek(credential_fd, 0, os.SEEK_SET)
        config_path = write_retry_overlay(request, final_path.parent)
        return subprocess.Popen(
            omp_argv(request, credential_fd, config_path=config_path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=request.workspace,
            env=omp_environment(
                os.environ, final_path=final_path, request=request,
            ),
            start_new_session=True,
            pass_fds=(credential_fd,),
            # The unit's own UMask=0077 protects broker state, but a
            # restricted-write child inheriting it writes 0600 files into the
            # setgid group-shared wiki — the first live wiki job (2026-08-21)
            # produced a triage note the hermes-side projector could not read.
            # Scoped to restricted-write: those callers exist precisely to
            # produce group-consumed artefacts; workspace-write children keep
            # the inherited umask. Credentials stay 0600 explicitly.
            # A scoped-git child (2026-08-24) joins that exception: it works a
            # linked worktree whose refs, index and logs the hermes worker
            # must read and advance next, so its git metadata has to stay
            # group-accessible across the two uids.
            umask=0o002 if (
                request.sandbox == "restricted-write"
                or request.git_mode == "scoped") else -1,
        )
    finally:
        os.close(credential_fd)


def _lock_path(workspace: Path) -> Path:
    digest = hashlib.sha256(str(workspace.resolve()).encode()).hexdigest()[:20]
    return LOCK_DIR / f"workspace-{digest}.lock"


def acquire_workspace_lock(workspace: Path):
    LOCK_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(LOCK_DIR, 0o700)
    path = _lock_path(workspace)
    handle = path.open("a+")
    os.chmod(path, 0o600)
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise ProtocolError("workspace writer lock is busy") from exc
    return handle


def _process_group_exists(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _child_exited(pid: int) -> bool:
    # WNOWAIT keeps the direct child's PID and session pinned through cleanup.
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def _running_process_group_exists(pid: int) -> bool:
    """Observe executing members while an unreaped child pins the group ID."""
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                # comm is arbitrary bytes and can contain spaces or parentheses.
                fields = (entry / "stat").read_bytes().rsplit(b")", 1)[1].split()
                if int(fields[2]) == pid:
                    # A zombie leader can still have executing sibling threads.
                    if fields[0] not in {b"Z", b"X"} or int(fields[17]) != 1:
                        return True
            except (FileNotFoundError, ProcessLookupError):
                continue
            except (OSError, ValueError, IndexError):
                return True  # Unknown state is not proof that the group stopped.
    except OSError:
        return True
    return False


def _close_process_pipes(process, *, suppress_errors=False) -> None:
    error = None
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except BaseException as exc:
                if error is None:
                    error = exc
    if error is not None and not suppress_errors:
        raise error


def _kill_process_group(pid: int) -> None:
    # The owner keeps its direct child unreaped until the watcher and group stop.
    try:
        os.killpg(pid, signal.SIGTERM)
    except OSError:
        pass
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if not _running_process_group_exists(pid):
            break
        if _child_exited(pid):
            break
        time.sleep(0.02)
    # A grace census can miss a concurrent fork. Linux serializes group SIGKILL
    # with fork publication, so establish that barrier before observing clearance.
    while True:
        try:
            os.killpg(pid, signal.SIGKILL)
            break
        except ProcessLookupError:
            return
        except OSError:
            time.sleep(0.02)  # Retain ownership until termination can be established.
    # A signal is not clearance. Keep the workspace and PID pin through cleanup.
    while _running_process_group_exists(pid):
        time.sleep(0.02)


def _valid_findings(value: object) -> bool:
    if not isinstance(value, list) or len(value) > 32:
        return False
    for finding in value:
        if not isinstance(finding, dict) or set(finding) != FINDING_FIELDS:
            return False
        file = finding.get("file")
        path = Path(file) if isinstance(file, str) else None
        if (
            not isinstance(file, str)
            or not file
            or len(file) > 1_000
            or "\\" in file
            or "\n" in file
            or path is None
            or path.is_absolute()
            or path.as_posix() != file
            or any(part in ("", ".", "..") for part in path.parts)
        ):
            return False
        lines = finding.get("lines")
        if (
            not isinstance(lines, list)
            or not 1 <= len(lines) <= 20
            or any(
                not isinstance(line, int)
                or isinstance(line, bool)
                or not 1 <= line <= 10_000_000
                for line in lines
            )
            or lines != sorted(set(lines))
        ):
            return False
        if finding.get("severity") not in FINDING_SEVERITIES:
            return False
        for field in ("issue", "fix"):
            text = finding.get(field)
            if (
                not isinstance(text, str)
                or not 4 <= len(text.strip()) <= 2_000
                or text != text.strip()
            ):
                return False
    return True


def _valid_structured_result(value: object) -> bool:
    if not isinstance(value, str) or len(value.encode()) > 500_000:
        return False
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return False
    return isinstance(parsed, dict)


def _valid_final(path: Path, *, caller: str) -> dict[str, object] | None:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return _valid_final_value(value, caller=caller)


def _valid_final_value(value: object, *, caller: str) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    keys = set(value)
    allowed = FINAL_FIELDS | OPTIONAL_FINAL_FIELDS
    if caller == REVIEW_CALLER:
        allowed |= {"findings"}
    if caller_allows_structured_result(caller):
        allowed |= {"structured_result"}
    if not FINAL_FIELDS <= keys or not keys <= allowed:
        return None
    if caller == REVIEW_CALLER:
        if not _valid_findings(value.get("findings")):
            return None
    elif "findings" in value:
        return None
    if caller_allows_structured_result(caller):
        if not _valid_structured_result(value.get("structured_result")):
            return None
    elif "structured_result" in value:
        return None
    if not isinstance(value.get("summary"), str) or not value["summary"]:
        return None
    if not all(
        isinstance(value.get(name), list) and all(isinstance(item, str) for item in value[name])
        for name in ("verification", "gaps")
    ):
        return None
    if value.get("verdict") not in FINAL_VERDICTS:
        return None
    if "served_model" in value:
        served = value["served_model"]
        if not isinstance(served, str) or not served or len(served) > 512:
            return None
    return value


def audit_outcome(
    exit_code: int, timed_out: bool, group_clear: bool,
    final: dict[str, object] | None, disconnected: bool = False,
) -> str:
    if timed_out:
        return "timeout"
    if disconnected:
        return "client_disconnected"
    if exit_code != 0 or not group_clear or final is None:
        return "failure"
    return str(final["verdict"]).lower().replace(" ", "_")


def record_audit(
    *, request_id: str, caller: str, workspace: Path,
    outcome: str, usage: Mapping[str, int],
) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(AUDIT_LOG.parent, 0o700)
    row = {
        "timestamp": int(time.time()),
        "request_id": request_id,
        "caller": caller,
        "workspace": str(workspace),
        "outcome": outcome,
        "usage": dict(usage),
    }
    fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(row, sort_keys=True) + "\n").encode())
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _audit_safely(**kwargs) -> None:
    """Audit rows are evidence, never prerequisites: a failed write must not
    orphan a job or kill the serial serve loop (2026-08-26 zombie class)."""
    try:
        record_audit(**kwargs)
    except OSError as exc:
        print(f"omp-delegate-broker: audit write failed: {exc}",
              file=sys.stderr)


def _watch_client_lifetime(
    conn: socket.socket,
    process_group: int,
    stop: threading.Event,
    disconnected: threading.Event,
    request_id: str = "",
) -> None:
    poller = select.poll()
    control = select.POLLIN if CREDENTIAL_SOURCE == "systemd" else 0
    poller.register(
        conn.fileno(),
        select.POLLHUP | select.POLLERR | select.POLLNVAL
        | getattr(select, "POLLRDHUP", 0) | control,
    )
    while not stop.is_set():
        for _, mask in poller.poll(50):
            fatal = bool(mask & (select.POLLHUP | select.POLLERR | select.POLLNVAL))
            if mask & control and not fatal:
                try:
                    deadline = time.monotonic() + FRAME_TIMEOUT
                    size = struct.unpack("!I", _recv_exact(conn, 4, deadline))[0]
                    if not 0 < size <= 256:
                        raise ProtocolError("worker cancellation exceeds size bound")
                    value = json.loads(_recv_exact(conn, size, deadline))
                    if (not isinstance(value, dict)
                            or value != {"version": 1, "op": "cancel",
                                         "request_id": request_id}):
                        raise ProtocolError("worker cancellation does not match request")
                except (OSError, ValueError, ProtocolError, struct.error, json.JSONDecodeError):
                    fatal = True
                else:
                    fatal = True
            if fatal:
                disconnected.set()
                _kill_process_group(process_group)
                return
        stop.wait(0.05)


def _error_response(
    message: str, *, request_id: str = "", version: int = 1,
) -> dict[str, object]:
    return {
        "version": version,
        "exit_code": 69,
        "stdout": "",
        "stderr": f"omp-delegate-broker: {message}\n",
        "timed_out": False,
        "process_group_clear": True,
        "final": None,
        "request_id": request_id,
    }


def _status_error_response(*, version: int = 1) -> dict[str, object]:
    return {
        "version": version,
        "op": "status",
        "ok": False,
        "error": "job unavailable",
    }

def _v2_error_response(operation: str, error: str) -> dict[str, object]:
    return {"version": 2, "op": operation, "ok": False, "error": error}

def _health_error_response() -> dict[str, object]:
    return {
        "version": 2,
        "op": "health",
        "ok": False,
        "error": "endpoint unavailable",
    }


def read_health(_request: HealthRequest) -> dict[str, object]:
    if not WORKER_SOCKET:
        return {"version": 2, "op": "health", "ok": True}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as worker:
            _connect_worker(worker)
            payload = b'{"version":1,"op":"health"}'
            worker.sendall(struct.pack("!I", len(payload)) + payload)
            deadline = time.monotonic() + FRAME_TIMEOUT
            size = struct.unpack("!I", _recv_exact(worker, 4, deadline))[0]
            if not 0 < size <= 1024:
                raise ProtocolError("worker health response is outside size bound")
            value = json.loads(_recv_exact(worker, size, deadline))
            if value == {"version": 1, "op": "health", "ok": True}:
                return {"version": 2, "op": "health", "ok": True}
    except (OSError, ValueError, ProtocolError, struct.error, json.JSONDecodeError) as exc:
        print(f"omp-delegate-broker: worker health unavailable: {exc!r}",
              file=sys.stderr)
    return _health_error_response()


def read_status(request: StatusRequest) -> dict[str, object]:
    caller_policy = CALLER_POLICIES.get(request.caller)
    repositories = caller_policy.get("repositories") if caller_policy else None
    if (
        not isinstance(repositories, list)
        or request.repository not in repositories
        or request.repository not in REPOSITORY_PATHS
    ):
        return _status_error_response(version=request.protocol_version)
    try:
        record = JOB_STORE.get(request.request_id)
        if (
            record.get("caller") != request.caller
            or record.get("repository") != request.repository
        ):
            return _status_error_response(version=request.protocol_version)
        job = {name: record[name] for name in STATUS_JOB_FIELDS}
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return _status_error_response(version=request.protocol_version)
    return {
        "version": request.protocol_version,
        "op": "status",
        "ok": True,
        "job": job,
    }


def run_request(request: Request, conn: socket.socket) -> dict[str, object]:
    """Exception-safe shell: the job record and the serial serve loop must
    both survive ANY fault. On 2026-08-26 a sandboxed TemporaryDirectory
    EROFS escaped the inner handlers and froze two production jobs at
    pending with no audit row while the client saw only a masked error."""
    request_id = request.request_id
    if not request.reexecuted:
        # A re-execution reuses the record parse_request re-armed; create
        # would refuse the already-existing identifier.
        JOB_STORE.create(
            request_id,
            task_id=request.task_id,
            repository=request.repository,
            caller=request.caller,
        )
    try:
        return _run_request_inner(request, conn)
    except Exception as exc:  # noqa: BLE001 — deliberate last-resort boundary
        traceback.print_exc(file=sys.stderr)
        _audit_safely(
            request_id=request_id, caller=request.caller,
            workspace=request.workspace, outcome="failure", usage={},
        )
        response = _error_response(
            f"broker execution fault: {type(exc).__name__}: {exc}",
            request_id=request_id, version=request.protocol_version,
        )
        # An exception is not proof of clearance, even when cleanup was attempted.
        response["process_group_clear"] = False
        try:
            # Never demote an already-terminal job (a fault after a
            # successful finish must not overwrite completed with failed).
            if JOB_STORE.get(request_id).get("status") in (
                    "pending", "running"):
                JOB_STORE.finish(request_id, "failed", response)
        except (OSError, ValueError) as finish_exc:
            print("omp-delegate-broker: job finalization failed: "
                  f"{finish_exc}", file=sys.stderr)
        return response


def _worker_request_value(request: Request) -> dict[str, object]:
    raw = {
        "version": 1, "request_id": request.request_id,
        "task_id": request.task_id, "repository": request.repository,
        "caller": request.caller, "workspace": str(request.workspace),
        "sandbox": request.sandbox, "model": request.model,
        "prompt": request.prompt, "timeout": request.timeout,
    }
    derived = dataclasses.asdict(request)
    for key in (*REQUEST_FIELDS, "protocol_version", "reexecuted"):
        derived.pop(key, None)
    derived.pop("workspace", None)
    return {"version": 1, "op": "execute", "request": raw,
            "constraints": derived, "reexecuted": request.reexecuted}


def _valid_worker_response(value: object, request: Request) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != RESPONSE_FIELDS:
        raise ProtocolError("worker response fields do not match the protocol")
    if value["version"] != request.protocol_version or value["request_id"] != request.request_id:
        raise ProtocolError("worker response correlation does not match")
    if (isinstance(value["exit_code"], bool)
            or not isinstance(value["exit_code"], int)
            or not -255 <= value["exit_code"] <= 255
            or not isinstance(value["stdout"], str)
            or not isinstance(value["stderr"], str)
            or not isinstance(value["timed_out"], bool)
            or not isinstance(value["process_group_clear"], bool)):
        raise ProtocolError("worker response types do not match the protocol")
    if (value["final"] is not None
            and _valid_final_value(value["final"], caller=request.caller) is None):
        raise ProtocolError("worker final is not valid for the caller")
    return value


def _trusted_worker_socket() -> None:
    """Systemd owns the listener; SO_PEERCRED on a client sees PID 1, not accept()."""
    path = Path(WORKER_SOCKET)
    if not path.is_absolute():
        raise ProtocolError("worker socket path is not absolute")
    parent = os.lstat(path.parent)
    if (not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != 0 or parent.st_gid != 0
            or stat.S_IMODE(parent.st_mode) != 0o755
            or "system.posix_acl_access" in os.listxattr(path.parent, follow_symlinks=False)):
        raise ProtocolError("worker socket directory is not root-controlled")
    node = os.lstat(path)
    try:
        worker_uid = pwd.getpwnam(WORKER_USER).pw_uid
    except KeyError as exc:
        raise ProtocolError("worker identity is unavailable") from exc
    if (not stat.S_ISSOCK(node.st_mode)
            or node.st_uid != worker_uid
            or node.st_gid != os.getegid()
            or stat.S_IMODE(node.st_mode) != 0o660):
        raise ProtocolError("worker socket node ownership does not match")


def _connect_worker(worker: socket.socket) -> None:
    worker.settimeout(FRAME_TIMEOUT)
    _trusted_worker_socket()
    worker.connect(WORKER_SOCKET)
    # Client SO_PEERCRED sees systemd, the root listener creator; the
    # worker's UID is checked on the root-controlled socket node above.
    if _peer_uid(worker) != 0:
        raise ProtocolError("worker endpoint identity does not match")


def _run_isolated_request(request: Request, upstream: socket.socket) -> dict[str, object]:
    """Broker keeps its own receipt; only the worker can start/stop OMP."""
    request_id = request.request_id
    JOB_STORE.launching(request_id)
    # No local PID can establish that a remote child died. Preserve launch
    # uncertainty across disconnects/restarts so a spent lease cannot replay.
    JOB_STORE.running_external(request_id)
    disconnected = threading.Event()
    stop = threading.Event()
    worker = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    watcher: threading.Thread | None = None
    try:
        _connect_worker(worker)
        payload = json.dumps(_worker_request_value(request), separators=(",", ":")).encode()
        if not 0 < len(payload) <= MAX_REQUEST_BYTES:
            raise ProtocolError("worker request exceeds size bound")
        worker.sendall(struct.pack("!I", len(payload)) + payload)


        def watch_upstream() -> None:
            poller = select.poll()
            poller.register(upstream, select.POLLHUP | select.POLLERR | select.POLLNVAL)
            while not stop.is_set():
                if poller.poll(50):
                    disconnected.set()
                    try:
                        frame = json.dumps(
                            {"version": 1, "op": "cancel",
                             "request_id": request_id}, separators=(",", ":")).encode()
                        worker.sendall(struct.pack("!I", len(frame)) + frame)
                    except OSError:
                        try:
                            worker.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    return

        watcher = threading.Thread(
            target=watch_upstream, name=f"omp-worker-{request_id}", daemon=True)
        watcher.start()
        deadline = time.monotonic() + request.timeout + 20
        size = struct.unpack("!I", _recv_exact(worker, 4, deadline))[0]
        if not 0 < size <= MAX_RESPONSE_BYTES:
            raise ProtocolError("worker response exceeds size bound")
        response = _valid_worker_response(
            json.loads(_recv_exact(worker, size, deadline)), request)
    except (OSError, ValueError, ProtocolError, struct.error, json.JSONDecodeError) as exc:
        print(f"omp-delegate-broker: isolated worker unavailable: {exc!r}",
              file=sys.stderr)
        response = _error_response(
            "isolated worker unavailable", request_id=request_id,
            version=request.protocol_version)
        response["process_group_clear"] = False
        status = "orphaned"
    else:
        status = (
            "timed_out" if response["timed_out"]
            else "cancelled" if disconnected.is_set()
            else "completed" if response["exit_code"] == 0
            and response["process_group_clear"] and response["final"] is not None
            else "failed")
    finally:
        stop.set()
        try:
            worker.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if watcher is not None:
            watcher.join(timeout=2)
        # If the sender is still blocked, its thread retains the socket object.
        # Closing it here could recycle its fd into an unrelated connection.
        if watcher is None or not watcher.is_alive():
            worker.close()
    _audit_safely(
        request_id=request_id, caller=request.caller, workspace=request.workspace,
        outcome=status, usage={})
    JOB_STORE.finish(request_id, status, response)
    return response


def _run_request_inner(request: Request, conn: socket.socket) -> dict[str, object]:
    request_id = request.request_id
    try:
        lock = acquire_workspace_lock(request.workspace)
    except ProtocolError as exc:
        _audit_safely(
            request_id=request_id, caller=request.caller, workspace=request.workspace,
            outcome="lock_busy", usage={},
        )
        response = _error_response(
            str(exc), request_id=request_id, version=request.protocol_version)
        JOB_STORE.finish(request_id, "rejected", response)
        return response
    if WORKER_SOCKET:
        try:
            return _run_isolated_request(request, conn)
        finally:
            lock.close()


    try:
        provider_api_keys = resolve_provider_api_keys(request)
    except ProtocolError as exc:
        _audit_safely(
            request_id=request_id, caller=request.caller, workspace=request.workspace,
            outcome="credential_error", usage={},
        )
        response = _error_response(
            str(exc), request_id=request_id, version=request.protocol_version)
        JOB_STORE.finish(request_id, "failed", response)
        lock.close()
        return response

    global _ACTIVE_PROCESS_GROUP
    try:
        with tempfile.TemporaryDirectory(prefix="omp-delegate-broker-") as td:
            final_path = Path(td) / "final.json"
            # Persist uncertainty before spawning. A failed birth-record write
            # must never turn consumed work into a replayable pending job.
            JOB_STORE.launching(request_id)
            try:
                process = start_omp_process(request, final_path, provider_api_keys)
            except OSError as exc:
                _audit_safely(
                    request_id=request_id, caller=request.caller, workspace=request.workspace,
                    outcome="start_error", usage={},
                )
                response = _error_response(
                    f"OMP could not start: {exc}", request_id=request_id,
                    version=request.protocol_version,
                )
                JOB_STORE.finish(request_id, "failed", response)
                return response

            watcher = None
            stop_watcher = None
            identity = None
            try:
                identity = _lifecycle.capture_process_identity(process.pid)
                _ACTIVE_PROCESS_GROUP = process.pid
                if process.stdin is not None:
                    process.stdin.close()
                stop_watcher = threading.Event()
                disconnected = threading.Event()
                JOB_STORE.running(request_id, process_group=process.pid)
                watcher = threading.Thread(
                    target=_watch_client_lifetime,
                    args=(conn, process.pid, stop_watcher, disconnected, request_id),
                    name=f"omp-client-{request_id}",
                    daemon=True,
                )
                watcher.start()
                deadline = time.monotonic() + request.timeout
                buffers = {"stdout": bytearray(), "stderr": bytearray()}
                timed_out = False
                exceeded = False
                with selectors.DefaultSelector() as selector:
                    for name, stream in (("stdout", process.stdout),
                                         ("stderr", process.stderr)):
                        assert stream is not None
                        selector.register(stream, selectors.EVENT_READ, name)
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            if timed_out:
                                break
                            if not _child_exited(process.pid):
                                timed_out = True
                                _kill_process_group(process.pid)
                                deadline = time.monotonic() + 1.0
                                continue
                            ready = selector.select(0)
                            if not ready:
                                break
                        else:
                            ready = selector.select(
                                0 if _child_exited(process.pid) else min(remaining, 0.05))
                            if not ready and _child_exited(process.pid):
                                ready = selector.select(0)
                                if not ready:
                                    break
                        for key, _ in ready:
                            chunk = os.read(key.fileobj.fileno(), 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            if (len(buffers["stdout"]) + len(buffers["stderr"])
                                    + len(chunk) > MAX_CAPTURE_BYTES):
                                exceeded = True
                                break
                            buffers[key.data].extend(chunk)
                        if exceeded:
                            break
                if exceeded:
                    _kill_process_group(process.pid)
                elif not timed_out:
                    while not _child_exited(process.pid):
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            timed_out = True
                            _kill_process_group(process.pid)
                            break
                        time.sleep(min(remaining, 0.02))
                _close_process_pipes(process)
                stop_watcher.set()
                watcher.join()
                if watcher.is_alive():
                    raise RuntimeError("client watcher did not stop")
                _kill_process_group(process.pid)
                _ACTIVE_PROCESS_GROUP = None
                process.wait()
                group_clear = True
                if exceeded:
                    response = _error_response(
                        "OMP output exceeds capture limit", request_id=request_id,
                        version=request.protocol_version)
                    response["timed_out"] = timed_out
                    response["process_group_clear"] = group_clear
                    _audit_safely(
                        request_id=request_id, caller=request.caller,
                        workspace=request.workspace,
                        outcome="timeout" if timed_out else "failure", usage={},
                    )
                    JOB_STORE.finish(
                        request_id, "timed_out" if timed_out else "failed", response)
                    return response
                stdout = buffers["stdout"].decode(errors="replace")
                stderr = buffers["stderr"].decode(errors="replace")
                final = _valid_final(final_path, caller=request.caller)
                exit_code = process.returncode if process.returncode is not None else 1
                outcome = audit_outcome(
                    exit_code, timed_out, group_clear, final, disconnected.is_set(),
                )
                _audit_safely(
                    request_id=request_id, caller=request.caller, workspace=request.workspace,
                    outcome=outcome, usage={},
                )
                response = {
                    "version": request.protocol_version,
                    "exit_code": exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                    "timed_out": timed_out,
                    "process_group_clear": group_clear,
                    "final": final,
                    "request_id": request_id,
                }
                status = (
                    "timed_out" if timed_out
                    else "cancelled" if disconnected.is_set()
                    else "completed" if exit_code == 0 and group_clear and final is not None
                    else "failed"
                )
                JOB_STORE.finish(request_id, status, response)
                return response
            except BaseException:
                if stop_watcher is not None:
                    stop_watcher.set()
                _close_process_pipes(process, suppress_errors=True)
                if watcher is not None and watcher.ident is not None:
                    watcher.join()
                if process.returncode is None:
                    # waitid also establishes that this remains our unreaped child.
                    _child_exited(process.pid)
                    if identity is not None:
                        try:
                            child = _lifecycle.process_snapshot(process.pid)
                            if all(child[key] == identity[key] for key in
                                   ("pid", "ppid", "pgid", "sid", "start_ticks", "uid")):
                                _lifecycle.terminate_process_tree(
                                    identity, authorize=lambda: True)
                        except (OSError, KeyError, ValueError, IndexError):
                            pass
                    # Popen ownership, not optional lifecycle metadata, pins this ID.
                    _kill_process_group(process.pid)
                _ACTIVE_PROCESS_GROUP = None
                process.wait()
                raise
    finally:
        _ACTIVE_PROCESS_GROUP = None
        lock.close()


def _recv_exact(conn: socket.socket, size: int, deadline: float) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("request frame deadline exceeded")
        conn.settimeout(remaining)
        chunk = conn.recv(size - len(chunks))
        if not chunk:
            raise OSError("connection closed before frame completed")
        chunks.extend(chunk)
    return bytes(chunks)


def _peer_uid(conn: socket.socket) -> int:
    size = struct.calcsize("3i")
    credentials = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
    _pid, uid, _gid = struct.unpack("3i", credentials)
    return uid


def _send_frame(conn: socket.socket, value: dict[str, object]) -> None:
    conn.settimeout(FRAME_TIMEOUT)
    payload = json.dumps(value, separators=(",", ":")).encode()
    if len(payload) > MAX_RESPONSE_BYTES:
        version = value.get("version")
        response_version = version if version in {1, 2} else 1
        operation = value.get("op")
        if operation is None and response_version == 2 and "exit_code" in value:
            operation = "execute"
        if response_version == 2 and operation in {"execute", "status"}:
            fallback = _v2_error_response(
                operation, "response exceeded size bound")
        else:
            fallback = (
                _health_error_response()
                if operation == "health"
                else _status_error_response(version=response_version)
                if operation == "status"
                else _error_response(
                    "response exceeded size bound", version=response_version)
            )
        payload = json.dumps(fallback, separators=(",", ":")).encode()
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def receive_request(
    conn: socket.socket, *, endpoint: str | None = None, allow_v1: bool = True,
    defer_execution: bool = False,
) -> Request | StatusRequest | HealthRequest | DeferredExecution:
    deadline = time.monotonic() + FRAME_TIMEOUT
    size = struct.unpack("!I", _recv_exact(conn, 4, deadline))[0]
    if size <= 0 or size > MAX_REQUEST_BYTES:
        raise ProtocolError("request frame is outside size bound")
    value = json.loads(_recv_exact(conn, size, deadline))
    if not allow_v1 and (
        not isinstance(value, dict) or value.get("version") != 2
    ):
        if isinstance(value, dict) and value.get("op") == "health":
            raise ProtocolError(
                "endpoint unavailable", version=2, operation="health")
        operation = (
            "status"
            if isinstance(value, dict) and value.get("op") == "status"
            else "execute"
        )
        raise ProtocolError(
            "job unavailable", version=2, operation=operation)
    peer_uid = _peer_uid(conn)
    if defer_execution and isinstance(value, dict) and value.get("op") == "execute":
        # Authenticate and bound the envelope before queueing. Lease validation
        # and consumption stay together on the single execution thread.
        if (
            set(value) != V2_REQUEST_FIELDS
            or value.get("version") != 2
            or not isinstance(value.get("lease_id"), str)
            or not value["lease_id"]
            or not endpoint
            or endpoint not in LEASE_STORES
            or ENDPOINT_UIDS.get(endpoint) != peer_uid
        ):
            raise ProtocolError("job unavailable", version=2)
        conn.settimeout(None)
        return DeferredExecution(value, peer_uid, endpoint)
    request = parse_request(value, peer_uid=peer_uid, endpoint=endpoint)
    if (
        not allow_v1
        and not isinstance(request, HealthRequest)
        and request.protocol_version != 2
    ):
        raise ProtocolError("job unavailable", version=2)
    conn.settimeout(None)
    return request


def _serve_connection(
    conn: socket.socket, *, endpoint: str | None, allow_v1: bool,
    enqueue=None, deferred: DeferredExecution | None = None,
) -> bool:
    """Return true only when ownership of the connection moved to the queue."""
    request_id = ""
    invocation = False
    try:
        if deferred is not None:
            request = parse_request(
                deferred.value, peer_uid=deferred.peer_uid, endpoint=deferred.endpoint)
        else:
            request = receive_request(
                conn, endpoint=endpoint, allow_v1=allow_v1,
                defer_execution=enqueue is not None)
        if isinstance(request, DeferredExecution):
            try:
                enqueue(conn, request)
            except queue.Full:
                raise ProtocolError("job unavailable", version=2) from None
            return True
        if isinstance(request, HealthRequest):
            response = read_health(request)
        else:
            request_id = request.request_id
            if isinstance(request, StatusRequest):
                response = read_status(request)
            else:
                invocation = True
                response = run_request(request, conn)
    except (OSError, ProtocolError, json.JSONDecodeError, struct.error, ValueError) as exc:
        # The wire response stays generic for lease-bound callers, but the
        # journal must carry the true reason: on 2026-08-26 this masking
        # reduced three distinct root causes to "job unavailable" and cost
        # hours of blind diagnosis.
        print(f"omp-delegate-broker: request failed: {exc!r}", file=sys.stderr)
        if not allow_v1:
            version = 2
            operation = exc.operation if isinstance(exc, ProtocolError) else "execute"
            if operation == "health":
                response = _health_error_response()
            elif operation == "status":
                response = _status_error_response(version=2)
            else:
                response = _v2_error_response("execute", "job unavailable")
        else:
            version = exc.version if isinstance(exc, ProtocolError) else 1
            operation = exc.operation if isinstance(exc, ProtocolError) else "execute"
            response = _error_response(
                str(exc), request_id=request_id, version=version)
    try:
        _send_frame(conn, response)
    except OSError:
        if invocation and request_id:
            try:
                JOB_STORE.delivery_failed(request_id)
            except (OSError, ValueError):
                pass
    return False


def serve(listener: socket.socket) -> None:
    """Protocol-v1 compatibility entry point; never selected by main()."""
    JOB_STORE.recover_orphans()
    while True:
        conn, _ = listener.accept()
        with conn:
            _serve_connection(conn, endpoint=None, allow_v1=True)


def systemd_listeners() -> list[ListenerEndpoint]:
    if int(os.environ.get("LISTEN_PID", "0")) != os.getpid():
        raise SystemExit("omp-delegate-broker: systemd listener pid does not match")
    count = int(os.environ.get("LISTEN_FDS", "0"))
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    if (
        count <= 0
        or len(names) != count
        or any(not name for name in names)
        or len(set(names)) != count
    ):
        raise SystemExit(
            "omp-delegate-broker: every systemd listener requires a unique FileDescriptorName")
    if any(name not in LEASE_STORES for name in names):
        raise SystemExit(
            "omp-delegate-broker: every named listener requires a private lease store")
    if any(name not in ENDPOINT_UIDS for name in names):
        raise SystemExit(
            "omp-delegate-broker: every named listener requires an endpoint user")
    if "delegate" in names and ENDPOINT_CALLERS.get("delegate") != "delegate_to_omp":
        raise SystemExit(
            "omp-delegate-broker: delegate listener requires a fixed caller binding")
    return [
        ListenerEndpoint(name, socket.socket(fileno=3 + offset))
        for offset, name in enumerate(names)
    ]


def serve_named(listeners: list[ListenerEndpoint]) -> None:
    """Serve bounded controls concurrently; admit and execute only on this thread."""
    by_fd = {item.socket.fileno(): item for item in listeners}
    # Recovery precedes both controls and admissions, including status-only lanes.
    JOB_STORE.recover_orphans()
    executions = queue.Queue(maxsize=MAX_WAITING_EXECUTIONS)
    control_slots = threading.BoundedSemaphore(MAX_CONTROL_CONNECTIONS)
    stopping = threading.Event()
    connection_lock = threading.Lock()
    control_connections: set[socket.socket] = set()
    failures: list[BaseException] = []

    def enqueue(conn: socket.socket, request: DeferredExecution) -> None:
        with connection_lock:
            if stopping.is_set():
                raise queue.Full
            executions.put_nowait((conn, request))

    def control(conn: socket.socket, endpoint: str) -> None:
        transferred = False
        try:
            transferred = _serve_connection(
                conn, endpoint=endpoint, allow_v1=False, enqueue=enqueue)
        finally:
            with connection_lock:
                control_connections.discard(conn)
            if not transferred:
                conn.close()
            control_slots.release()

    def dispatch() -> None:
        try:
            while not stopping.is_set():
                readable, _, _ = select.select(
                    [item.socket for item in listeners], [], [], 0.1)
                for listener in readable:
                    conn, _ = listener.accept()
                    if not control_slots.acquire(blocking=False):
                        # Transport refusal, before parsing or consuming a lease.
                        conn.close()
                        continue
                    with connection_lock:
                        control_connections.add(conn)
                    try:
                        threading.Thread(
                            target=control, args=(conn, by_fd[listener.fileno()].endpoint),
                            name="omp-control", daemon=True,
                        ).start()
                    except BaseException:
                        with connection_lock:
                            control_connections.discard(conn)
                        conn.close()
                        control_slots.release()
                        raise
        except BaseException as exc:
            failures.append(exc)
            stopping.set()

    dispatcher = threading.Thread(target=dispatch, name="omp-dispatch", daemon=True)
    dispatcher.start()
    try:
        while not stopping.is_set():
            try:
                conn, request = executions.get(timeout=0.1)
            except queue.Empty:
                continue
            with conn:
                # A queued client that went away must not spend a lease. A
                # write-half shutdown is not a disconnect in the framed protocol.
                poller = select.poll()
                poller.register(conn, select.POLLHUP | select.POLLERR | select.POLLNVAL)
                if poller.poll(0):
                    continue
                _serve_connection(
                    conn, endpoint=request.endpoint, allow_v1=False, deferred=request)
        if failures:
            raise failures[0]
    finally:
        with connection_lock:
            stopping.set()
        dispatcher.join()
        with connection_lock:
            for conn in control_connections:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            while True:
                try:
                    conn, _ = executions.get_nowait()
                except queue.Empty:
                    break
                conn.close()


def _terminate(signum: int, _frame: object) -> None:
    if _ACTIVE_PROCESS_GROUP is not None:
        _kill_process_group(_ACTIVE_PROCESS_GROUP)
    raise SystemExit(128 + signum)
def main() -> int:
    write_policy_stamp()
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, _terminate)
    serve_named(systemd_listeners())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
