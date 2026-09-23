#!/usr/bin/env python3
"""Root-installed, worker-UID OMP executor for the private delegation socket."""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import stat
import struct
import sys
import time


def _load_broker():
    for name in (
        "HERMES_OMP_POLICY", "HERMES_OMP_JOB_DIR", "HERMES_OMP_LOCK_DIR",
        "HERMES_OMP_AUDIT_LOG", "HERMES_OMP_AGENT_DIR", "HERMES_OMP_BIN",
        "HERMES_OMP_EXTENSION", "HERMES_OMP_HOME",
        "HERMES_OMP_WORKER_LISTENER", "HERMES_OMP_WORKER_DB_TARGET",
    ):
        value = os.environ.get(name, "")
        if not value or not Path(value).is_absolute():
            raise SystemExit(f"omp-delegation-worker: {name} must be absolute")
    for name in ("HERMES_OMP_WORKER_BROKER_USER", "HERMES_OMP_WORKER_USER"):
        value = os.environ.get(name, "")
        if not value or "/" in value or any(char.isspace() for char in value):
            raise SystemExit(f"omp-delegation-worker: {name} is invalid")
    if (os.environ.get("HERMES_OMP_CREDENTIAL_SOURCE") != "systemd"
            or os.environ.get("HERMES_OMP_WORKER_SOCKET")
            or os.environ.get("HERMES_OMP_FALLBACK_MODELS") != ""):
        raise SystemExit("omp-delegation-worker: unsafe worker execution environment")
    path = Path(__file__).with_name("omp-delegate-broker.py")
    spec = importlib.util.spec_from_file_location("omp_delegation_worker_broker", path)
    if spec is None or spec.loader is None:
        raise SystemExit("omp-delegation-worker: broker runtime is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BROKER = _load_broker()


def _read_request(conn: socket.socket):
    if BROKER._peer_uid(conn) != pwd.getpwnam(
            os.environ["HERMES_OMP_WORKER_BROKER_USER"]).pw_uid:
        raise BROKER.ProtocolError("worker peer is not the delegated broker")
    deadline = time.monotonic() + BROKER.FRAME_TIMEOUT
    size = struct.unpack("!I", BROKER._recv_exact(conn, 4, deadline))[0]
    if not 0 < size <= BROKER.MAX_REQUEST_BYTES:
        raise BROKER.ProtocolError("worker request exceeds size bound")
    value = json.loads(BROKER._recv_exact(conn, size, deadline))
    if value == {"version": 1, "op": "health"}:
        return None
    if (not isinstance(value, dict)
            or set(value) != {"version", "op", "request", "constraints", "reexecuted"}
            or value["version"] != 1 or value["op"] != "execute"
            or not isinstance(value["constraints"], dict)
            or not isinstance(value["reexecuted"], bool)):
        raise BROKER.ProtocolError("worker request fields do not match protocol")
    request = BROKER.validate_request(value["request"], peer_uid=None)
    derived = dataclasses.asdict(request)
    for key in (*BROKER.REQUEST_FIELDS, "protocol_version", "reexecuted"):
        derived.pop(key, None)
    derived.pop("workspace", None)
    derived = {
        key: list(item) if isinstance(item, tuple) else item
        for key, item in derived.items()
    }
    if derived != value["constraints"]:
        raise BROKER.ProtocolError("worker constraints disagree with root policy")
    if value["reexecuted"]:
        if not BROKER._lane_is_replay_safe(request):
            raise BROKER.ProtocolError("worker replay is not admitted by policy")
        BROKER.JOB_STORE.arm_reexecution(
            request.request_id, task_id=request.task_id,
            repository=request.repository, caller=request.caller)
    return dataclasses.replace(
        request, protocol_version=2, reexecuted=value["reexecuted"])


def handle_connection(conn: socket.socket) -> None:
    try:
        request = _read_request(conn)
        conn.settimeout(None)
        if request is None:
            BROKER.worker_gateway_key()
            response = {"version": 1, "op": "health", "ok": True}
        else:
            BROKER.JOB_STORE.recover_orphans()
            response = BROKER.run_request(request, conn)
    except (BROKER.ProtocolError, OSError, ValueError, KeyError,
            json.JSONDecodeError, struct.error) as exc:
        print(f"omp-delegation-worker: rejected request: {exc!r}", file=sys.stderr)
        response = BROKER._error_response("worker request unavailable", version=2)
    try:
        BROKER._send_frame(conn, response)
    except OSError:
        if response.get("request_id"):
            try:
                BROKER.JOB_STORE.delivery_failed(str(response["request_id"]))
            except (OSError, ValueError):
                pass


def _root_runtime() -> None:
    # Systemd's User and the protected release are both required. A source
    # checkout or broker-writable executable is not an isolated worker.
    if (os.geteuid() != pwd.getpwnam(BROKER.WORKER_USER).pw_uid
            or BROKER.CREDENTIAL_SOURCE != "systemd"
            or BROKER.WORKER_SOCKET):
        raise SystemExit("omp-delegation-worker: identity or credential source is unsafe")
    for path in (
        Path(__file__), Path(BROKER.__file__), Path(BROKER._lifecycle.__file__),
        BROKER.POLICY_FILE, BROKER.OMP_BIN, BROKER.EXTENSION,
        BROKER.OMP_AGENT_DIR / "models.yml",
    ):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise SystemExit(f"omp-delegation-worker: runtime is not root-owned: {path}")
        for ancestor in path.parents:
            parent = ancestor.lstat()
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
                    or parent.st_mode & 0o022):
                raise SystemExit(f"omp-delegation-worker: runtime ancestor is unsafe: {ancestor}")
    db_link = BROKER.OMP_AGENT_DIR / "agent.db"
    info = db_link.lstat()
    if (not stat.S_ISLNK(info.st_mode) or info.st_uid != 0
            or os.readlink(db_link) != os.environ["HERMES_OMP_WORKER_DB_TARGET"]):
        raise SystemExit("omp-delegation-worker: database link is not worker-scoped")
    if not os.environ.get("CREDENTIALS_DIRECTORY"):
        raise SystemExit("omp-delegation-worker: credential mount is unavailable")


def main() -> int:
    _root_runtime()
    if (int(os.environ.get("LISTEN_PID", "0")) != os.getpid()
            or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != "worker"):
        raise SystemExit("omp-delegation-worker: exactly one named listener is required")
    listener = socket.socket(fileno=3)
    if (listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM
            or listener.getsockname() != os.environ["HERMES_OMP_WORKER_LISTENER"]):
        raise SystemExit("omp-delegation-worker: listener is not the private worker socket")
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, BROKER._terminate)
    # One request per service lifetime. On exit, systemd's control-group kill
    # reaps detached descendants that escaped the child's original process group.
    conn, _ = listener.accept()
    with conn:
        handle_connection(conn)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
