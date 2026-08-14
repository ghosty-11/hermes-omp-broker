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
RESPONSE_FIELDS = {
    "version", "exit_code", "stdout", "stderr", "timed_out",
    "process_group_clear", "final", "request_id",
}
FINAL_FIELDS = {"summary", "verification", "gaps", "verdict"}
FINAL_VERDICTS = {"MET", "PARTIALLY MET", "NOT MET"}
SYSTEM_APPEND = (
    "You are an admitted OMP worker behind a fixed Hermes delegation boundary. "
    "Work only in the current workspace. Call broker_finalize exactly once after all edits "
    "and honest verification. Do not confuse it with xd://finalize. Do not continue using "
    "tools after broker_finalize."
)


class ProtocolError(RuntimeError):
    pass


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


def validate_request(value: object, *, peer_uid: int) -> Request:
    allowed_uid = int(os.environ.get("HERMES_OMP_CALLER_UID", str(os.getuid())))
    if peer_uid != allowed_uid:
        raise ProtocolError("peer uid is not the admitted local identity")
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
    allowed = {path.resolve() for path in ALLOWED_WORKSPACES[caller]}
    if workspace not in allowed:
        raise ProtocolError("workspace is not allowlisted for caller")
    if REPOSITORY_PATHS.get(value["repository"]) != workspace:
        raise ProtocolError("repository key does not map to requested workspace")
    if value["sandbox"] != ALLOWED_SANDBOXES[caller]:
        raise ProtocolError("sandbox is not fixed for caller")
    if value["model"] != MODEL:
        raise ProtocolError("model does not match broker policy")
    prompt = value["prompt"]
    if not prompt or len(prompt) > MAX_PROMPT_CHARS:
        raise ProtocolError("prompt is empty or exceeds the broker bound")
    timeout = value["timeout"]
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ProtocolError("timeout is not numeric")
    timeout = float(timeout)
    if timeout <= 0 or timeout > MAX_TIMEOUT:
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
    return Request(
        value["request_id"], value["task_id"], value["repository"], caller, workspace,
        value["sandbox"], value["model"], prompt, timeout,
        _string_tuple("read_paths"), _string_tuple("write_patterns"),
        str(git_mode), _string_tuple("skills"), create_only,
    )


def omp_argv(request: Request, credential_path: str) -> list[str]:
    skill_args = (
        ["--skills", ",".join(request.skills)]
        if request.skills
        else ["--no-skills"]
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
        "--no-rules",
        "--approval-mode=yolo",
        "--provider-api-keys", credential_path,
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
    return {
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
    }


def resolve_provider_api_keys(request: Request) -> dict[str, str]:
    provider = request.model.partition("/")[0]
    env = {
        "HOME": os.environ.get("HERMES_OMP_HOME", str(Path.home())),
        "PATH": os.environ.get("HERMES_OMP_PATH", os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "PI_CODING_AGENT_DIR": str(OMP_CREDENTIAL_AGENT_DIR),
    }
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
        return {provider: value.decode()}
    except UnicodeDecodeError as exc:
        raise ProtocolError("pinned OMP provider credential has invalid encoding") from exc


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
        return subprocess.Popen(
            omp_argv(request, f"/proc/self/fd/{credential_fd}"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=request.workspace,
            env=omp_environment(
                os.environ, final_path=final_path, request=request,
            ),
            start_new_session=True,
            pass_fds=(credential_fd,),
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
    if not isinstance(value, dict) or set(value) != FINAL_FIELDS:
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
        payload = json.dumps(_error_response("response exceeded size bound"), separators=(",", ":")).encode()
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def receive_request(conn: socket.socket) -> Request:
    deadline = time.monotonic() + FRAME_TIMEOUT
    size = struct.unpack("!I", _recv_exact(conn, 4, deadline))[0]
    if size <= 0 or size > MAX_REQUEST_BYTES:
        raise ProtocolError("request frame is outside size bound")
    value = json.loads(_recv_exact(conn, size, deadline))
    request = validate_request(value, peer_uid=_peer_uid(conn))
    conn.settimeout(None)
    return request


def serve(listener: socket.socket) -> None:
    JOB_STORE.recover_orphans()
    while True:
        conn, _ = listener.accept()
        with conn:
            request_id = ""
            try:
                request = receive_request(conn)
                request_id = request.request_id
                response = run_request(request, conn)
            except (OSError, ProtocolError, json.JSONDecodeError, struct.error, ValueError) as exc:
                response = _error_response(str(exc), request_id=request_id)
            try:
                _send_frame(conn, response)
            except OSError:
                if request_id:
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
