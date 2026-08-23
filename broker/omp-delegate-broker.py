#!/usr/bin/env python3
"""Fixed-policy OMP worker broker for authenticated local callers."""

from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import json
import os
import pwd
import select
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Mapping

try:
    from broker.lifecycle import JobStore
except ModuleNotFoundError:
    from lifecycle import JobStore


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
MAX_PROMPT_CHARS = 500_000
MAX_TIMEOUT = 810.0
ABSOLUTE_MAX_TIMEOUT = 3600.0
FRAME_TIMEOUT = 5.0
JOB_STORE = JobStore(Path(os.environ.get("HERMES_OMP_JOB_DIR", "state/jobs")))
_ACTIVE_PROCESS_GROUP: int | None = None


def _load_policy() -> tuple[
    dict[str, set[Path]],
    dict[str, str],
    dict[str, Path],
    dict[str, dict[str, object]],
]:
    try:
        value = json.loads(POLICY_FILE.read_text())
        repositories = value.get("repositories", {})
        repository_paths = {
            str(name): Path(entry["path"]).resolve()
            for name, entry in repositories.items()
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
        }
        raw_callers = value.get("callers")
        if not isinstance(raw_callers, dict):
            raw_callers = {
                "delegate_to_omp": {
                    "repositories": list(repository_paths),
                    "sandbox": "workspace-write",
                }
            }
        callers = {
            str(name): entry
            for name, entry in raw_callers.items()
            if isinstance(entry, dict)
        }
        workspaces: dict[str, set[Path]] = {}
        sandboxes: dict[str, str] = {}
        for name, entry in callers.items():
            repository_names = entry.get("repositories", [])
            sandbox = entry.get("sandbox")
            if (
                isinstance(repository_names, list)
                and all(isinstance(item, str) for item in repository_names)
                and isinstance(sandbox, str)
            ):
                workspaces[name] = {
                    repository_paths[item]
                    for item in repository_names
                    if item in repository_paths
                }
                sandboxes[name] = sandbox
        return workspaces, sandboxes, repository_paths, callers
    except (OSError, ValueError, TypeError):
        return {}, {}, {}, {}


ALLOWED_WORKSPACES, ALLOWED_SANDBOXES, REPOSITORY_PATHS, CALLER_POLICIES = _load_policy()
REQUEST_FIELDS = {"version", "request_id", "task_id", "repository", "caller", "workspace", "sandbox", "model", "prompt", "timeout"}
STATUS_REQUEST_FIELDS = {"version", "op", "request_id", "caller", "repository"}
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
FINAL_VERDICTS = {"MET", "PARTIALLY MET", "NOT MET"}
SYSTEM_APPEND = (
    "You are an admitted OMP worker behind a fixed Hermes delegation boundary. "
    "Work only in the current workspace. Call broker_finalize exactly once after all edits "
    "and honest verification. Do not confuse it with xd://finalize. Do not continue using "
    "tools after broker_finalize."
)


class ProtocolError(RuntimeError):
    pass


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
    fallback_models: tuple[str, ...] | None = None
    fallback_selectors: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class StatusRequest:
    request_id: str
    caller: str
    repository: str


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


def parse_request(value: object, *, peer_uid: int) -> Request | StatusRequest:
    if isinstance(value, dict) and "op" in value:
        if value.get("op") != "status":
            raise ProtocolError("unsupported protocol operation")
        return validate_status_request(value, peer_uid=peer_uid)
    return validate_request(value, peer_uid=peer_uid)


def validate_request(value: object, *, peer_uid: int) -> Request:
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
    workspace = Path(value["workspace"]).resolve()
    admitted = REPOSITORY_PATHS.get(value["repository"])
    allowed = {path.resolve() for path in ALLOWED_WORKSPACES[caller]}
    mapped = admitted is not None and (
        workspace == admitted.resolve() or is_worktree_of(workspace, admitted)
    )
    if workspace not in allowed and not (
        admitted is not None and is_worktree_of(workspace, admitted)
    ):
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
    caller_policy = CALLER_POLICIES[caller]

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
    fallback_selectors = _string_tuple("fallback_selectors")
    if any(not _valid_fallback_model(item) for item in fallback_selectors):
        raise ProtocolError("caller fallback_selectors policy is invalid")
    return Request(
        value["request_id"], value["task_id"], value["repository"], caller, workspace,
        value["sandbox"], value["model"], prompt, timeout,
        _string_tuple("read_paths"), _string_tuple("write_patterns"),
        str(git_mode), _string_tuple("skills"), create_only,
        _caller_fallback_models(caller_policy), fallback_selectors,
    )


def write_retry_overlay(request: Request, directory: Path) -> Path:
    """Write a private per-request exact-model chain; shared config cannot widen it."""
    chain = list(fallback_models(request))
    selectors = list(dict.fromkeys((request.model, *request.fallback_selectors)))
    path = directory / "retry-overlay.json"
    value = {
        "retry": {
            "fallbackChains": {
                selector: chain for selector in selectors
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
    config_args = ["--config", str(config_path)] if config_path is not None else []
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
        "OMP_DELEGATE_CALLER": request.caller,
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


def resolve_provider_api_keys(request: Request) -> dict[str, str]:
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


def _kill_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if not _process_group_exists(pid):
            return
        time.sleep(0.02)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _valid_final(path: Path) -> dict[str, object] | None:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    keys = set(value)
    if not FINAL_FIELDS <= keys or not keys <= FINAL_FIELDS | OPTIONAL_FINAL_FIELDS:
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
    if disconnected:
        return "client_disconnected"
    if exit_code != 0 or timed_out or not group_clear or final is None:
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


def _watch_client_lifetime(
    conn: socket.socket,
    process_group: int,
    stop: threading.Event,
    disconnected: threading.Event,
) -> None:
    poller = select.poll()
    poller.register(
        conn.fileno(),
        select.POLLHUP | select.POLLERR | select.POLLNVAL | getattr(select, "POLLRDHUP", 0),
    )
    while not stop.is_set():
        events = poller.poll(50)
        if not events:
            continue
        fatal = any(mask & (select.POLLHUP | select.POLLERR | select.POLLNVAL) for _, mask in events)
        if fatal:
            disconnected.set()
            _kill_process_group(process_group)
            return
        stop.wait(0.05)


def _error_response(message: str, *, request_id: str = "") -> dict[str, object]:
    return {
        "version": 1,
        "exit_code": 69,
        "stdout": "",
        "stderr": f"omp-delegate-broker: {message}\n",
        "timed_out": False,
        "process_group_clear": True,
        "final": None,
        "request_id": request_id,
    }


def _status_error_response() -> dict[str, object]:
    return {
        "version": 1,
        "op": "status",
        "ok": False,
        "error": "job unavailable",
    }


def read_status(request: StatusRequest) -> dict[str, object]:
    caller_policy = CALLER_POLICIES.get(request.caller)
    repositories = caller_policy.get("repositories") if caller_policy else None
    if (
        not isinstance(repositories, list)
        or request.repository not in repositories
        or request.repository not in REPOSITORY_PATHS
    ):
        return _status_error_response()
    try:
        record = JOB_STORE.get(request.request_id)
        if (
            record.get("caller") != request.caller
            or record.get("repository") != request.repository
        ):
            return _status_error_response()
        job = {name: record[name] for name in STATUS_JOB_FIELDS}
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return _status_error_response()
    return {
        "version": 1,
        "op": "status",
        "ok": True,
        "job": job,
    }


def run_request(request: Request, conn: socket.socket) -> dict[str, object]:
    request_id = request.request_id
    JOB_STORE.create(
        request_id,
        task_id=request.task_id,
        repository=request.repository,
        caller=request.caller,
    )
    try:
        lock = acquire_workspace_lock(request.workspace)
    except ProtocolError as exc:
        record_audit(
            request_id=request_id, caller=request.caller, workspace=request.workspace,
            outcome="lock_busy", usage={},
        )
        JOB_STORE.finish(request_id, "rejected", _error_response(str(exc), request_id=request_id))
        return _error_response(str(exc), request_id=request_id)

    try:
        provider_api_keys = resolve_provider_api_keys(request)
    except ProtocolError as exc:
        record_audit(
            request_id=request_id, caller=request.caller, workspace=request.workspace,
            outcome="credential_error", usage={},
        )
        response = _error_response(str(exc), request_id=request_id)
        JOB_STORE.finish(request_id, "failed", response)
        lock.close()
        return response

    global _ACTIVE_PROCESS_GROUP
    try:
        with tempfile.TemporaryDirectory(prefix="omp-delegate-broker-") as td:
            final_path = Path(td) / "final.json"
            try:
                process = start_omp_process(request, final_path, provider_api_keys)
            except OSError as exc:
                record_audit(
                    request_id=request_id, caller=request.caller, workspace=request.workspace,
                    outcome="start_error", usage={},
                )
                JOB_STORE.finish(
                    request_id,
                    "failed",
                    _error_response(f"OMP could not start: {exc}", request_id=request_id),
                )
                return _error_response(f"OMP could not start: {exc}", request_id=request_id)

            JOB_STORE.running(request_id, process_group=process.pid)
            _ACTIVE_PROCESS_GROUP = process.pid
            stop_watcher = threading.Event()
            disconnected = threading.Event()
            watcher = threading.Thread(
                target=_watch_client_lifetime,
                args=(conn, process.pid, stop_watcher, disconnected),
                name=f"omp-client-{request_id}",
                daemon=True,
            )
            watcher.start()
            timed_out = False
            try:
                stdout_b, stderr_b = process.communicate(timeout=request.timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_process_group(process.pid)
                stdout_b, stderr_b = process.communicate()
            finally:
                stop_watcher.set()
                watcher.join(timeout=3)
                if watcher.is_alive():
                    _kill_process_group(process.pid)
                    watcher.join(timeout=1)

            group_clear = not _process_group_exists(process.pid)
            if not group_clear:
                _kill_process_group(process.pid)
                group_clear = not _process_group_exists(process.pid)
            _ACTIVE_PROCESS_GROUP = None
            stdout = stdout_b.decode(errors="replace")
            stderr = stderr_b.decode(errors="replace")
            final = _valid_final(final_path)
            exit_code = process.returncode if process.returncode is not None else 1
            outcome = audit_outcome(
                exit_code, timed_out, group_clear, final, disconnected.is_set(),
            )
            record_audit(
                request_id=request_id, caller=request.caller, workspace=request.workspace,
                outcome=outcome, usage={},
            )
            response = {
                "version": 1,
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
        fallback = (
            _status_error_response()
            if value.get("op") == "status"
            else _error_response("response exceeded size bound")
        )
        payload = json.dumps(fallback, separators=(",", ":")).encode()
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def receive_request(conn: socket.socket) -> Request | StatusRequest:
    deadline = time.monotonic() + FRAME_TIMEOUT
    size = struct.unpack("!I", _recv_exact(conn, 4, deadline))[0]
    if size <= 0 or size > MAX_REQUEST_BYTES:
        raise ProtocolError("request frame is outside size bound")
    value = json.loads(_recv_exact(conn, size, deadline))
    request = parse_request(value, peer_uid=_peer_uid(conn))
    conn.settimeout(None)
    return request


def serve(listener: socket.socket) -> None:
    recovered_orphans = False
    while True:
        conn, _ = listener.accept()
        with conn:
            request_id = ""
            invocation = False
            try:
                request = receive_request(conn)
                request_id = request.request_id
                if isinstance(request, StatusRequest):
                    response = read_status(request)
                else:
                    invocation = True
                    if not recovered_orphans:
                        JOB_STORE.recover_orphans()
                        recovered_orphans = True
                    response = run_request(request, conn)
            except (OSError, ProtocolError, json.JSONDecodeError, struct.error, ValueError) as exc:
                response = _error_response(str(exc), request_id=request_id)
            try:
                _send_frame(conn, response)
            except OSError:
                if invocation and request_id:
                    try:
                        JOB_STORE.delivery_failed(request_id)
                    except (OSError, ValueError):
                        pass


def _terminate(signum: int, _frame: object) -> None:
    if _ACTIVE_PROCESS_GROUP is not None:
        _kill_process_group(_ACTIVE_PROCESS_GROUP)
    raise SystemExit(128 + signum)


def main() -> int:
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, _terminate)
    if int(os.environ.get("LISTEN_PID", "0")) != os.getpid() or int(os.environ.get("LISTEN_FDS", "0")) != 1:
        raise SystemExit("omp-delegate-broker: exactly one systemd socket is required")
    listener = socket.socket(fileno=3)
    serve(listener)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
