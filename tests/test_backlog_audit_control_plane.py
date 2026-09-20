from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pwd
import py_compile
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENDPOINTS = ("audit", "planner", "code")
CONTROL_TIMEOUT = 5.0
WAIT_TIMEOUT = 8.0
HOLD_TIMEOUT = 45.0


def _publish(path: Path, value: object) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


def _load_broker(root: Path):
    # A separate interpreter and private package prevent a cached real lifecycle
    # module (or another test's import) from becoming the provenance fixture.
    sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location(
        "broker_control_fixture", root / "broker/omp-delegate-broker.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _fixed(root: Path, request_id: str, repository: str = "first") -> dict:
    return {
        "request_id": request_id,
        "task_id": "task-" + request_id,
        "repository": repository,
        "caller": "audit",
        "workspace": str(root / repository),
        "sandbox": "restricted-write",
        "model": "provider/fixed",
        "prompt": "disposable scheduling fixture",
        "timeout": HOLD_TIMEOUT,
    }


def _fixture_process(root: Path, mode: str, slot: str) -> None:
    # No provider work is launched. Disposable children block on a pipe whose
    # EOF also releases them if this broker fixture dies unexpectedly.
    signal.alarm(90)
    module = _load_broker(root)
    if mode == "stamp":
        lifecycle = sys.modules[module.LeaseStore.__module__]
        for sequence in range(3):
            if sequence:
                deadline = time.monotonic() + HOLD_TIMEOUT
                while not (root / f"{slot}-request-{sequence}").exists():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("stamp command never arrived")
                    time.sleep(0.01)
            stamp = module.write_policy_stamp()
            _publish(root / f"{slot}-report-{sequence}.json", {
                "stamp": stamp,
                "loaded_lifecycle": lifecycle.LEASE_UNAVAILABLE,
                "lifecycle_file": str(Path(lifecycle.__file__).resolve()),
            })
        return

    def forbidden(*_args, **_kwargs):
        raise AssertionError("fixture must not resolve credentials or launch OMP")

    module.resolve_provider_api_keys = forbidden
    module.start_omp_process = forbidden

    def controlled_execution(request, _conn):
        # Only the expensive execution body is replaced. Admission, durable job
        # creation, dispatch, framing, peer credentials and status stay real.
        marker = root / "execution-active"
        owns_marker = False
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
            stdin=subprocess.PIPE, start_new_session=True)
        try:
            try:
                fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
                owns_marker = True
            except FileExistsError:
                _publish(root / "overlap.json", {"request_id": request.request_id})
            module.JOB_STORE.running(request.request_id, process_group=child.pid)
            _publish(root / f"entered-{request.request_id}.json", {
                "at": time.monotonic_ns(), "repository": request.repository,
                "process": module.JOB_STORE.get(request.request_id)["process"],
            })
            if request.request_id == "first":
                deadline = time.monotonic() + HOLD_TIMEOUT
                while not (root / "release-first").exists():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("execution release never arrived")
                    time.sleep(0.01)
            child.stdin.close()
            child.wait(timeout=CONTROL_TIMEOUT)
            response = {
                "version": 2, "request_id": request.request_id,
                "exit_code": 0, "stdout": "fixture-only", "stderr": "",
                "timed_out": False, "process_group_clear": True,
                "final": {"summary": "fixture", "verification": "controlled seam",
                          "gaps": "no inference", "verdict": "MET"},
            }
            module.JOB_STORE.finish(request.request_id, "completed", response)
            return response
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=CONTROL_TIMEOUT)
            child.stdin.close()
            _publish(root / f"exited-{request.request_id}.json", {
                "at": time.monotonic_ns(), "pid": child.pid,
                "returncode": child.returncode,
            })
            if owns_marker:
                marker.unlink()

    module._run_request_inner = controlled_execution
    leases = {}
    for endpoint in ENDPOINTS:
        store = module.LEASE_STORES[endpoint]
        leases[endpoint] = {}
        for name in ("first", "second", "seed", "foreign-peer"):
            request_id = name if endpoint == "audit" else f"{endpoint}-{name}"
            fixed = _fixed(root, request_id, "second" if name == "second" else "first")
            lease = store.issue(
                fixed_request=fixed, endpoint=endpoint,
                peer_uid=os.getuid() + (1 if name == "foreign-peer" else 0),
                artifact_digest="sha256:fixture", policy_version="fixture-v1",
                template_version="fixture-v1", expires_at=int(time.time()) + 120,
            )
            leases[endpoint][name] = lease
            if name == "seed":
                store.consume(lease, endpoint=endpoint, peer_uid=os.getuid())
                module.JOB_STORE.create(
                    request_id, task_id=fixed["task_id"], repository="first", caller="audit")
                module.JOB_STORE.finish(request_id, "completed", {"fixture": True})
    listeners = []
    try:
        for endpoint in ENDPOINTS:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(root / f"{endpoint}.sock"))
            listener.listen(16)
            listeners.append(module.ListenerEndpoint(endpoint, listener))
        _publish(root / f"{slot}-report-0.json", {"leases": leases})
        module.serve_named(listeners)
    finally:
        for listener in listeners:
            listener.socket.close()


class BrokerControlPlaneAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        # AF_UNIX paths must fit sun_path even when pytest's base temp path is long.
        self.temporary = tempfile.TemporaryDirectory(prefix="broker-control-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        package = self.root / "broker"
        package.mkdir()
        (package / "__init__.py").write_text("")
        for name in ("omp-delegate-broker.py", "lifecycle.py"):
            shutil.copyfile(ROOT / "broker" / name, package / name)
        for name in ("first", "second", "home", "tmp", "credentials"):
            (self.root / name).mkdir()
        (self.root / "policy.json").write_text(json.dumps({
            "version": 1,
            "repositories": {
                name: {"path": str(self.root / name)} for name in ("first", "second")
            },
            "callers": {"audit": {
                "repositories": ["first", "second"], "sandbox": "restricted-write",
                "read_paths": [], "write_patterns": ["backlog/**"], "git_mode": "none",
                "skills": [], "model": "provider/fixed", "max_timeout": 60,
            }},
        }))
        for endpoint in ENDPOINTS:
            lease_root = self.root / "leases" / endpoint
            (lease_root / "issued").mkdir(parents=True, mode=0o750)
            (lease_root / "consumed").mkdir(mode=0o700)
            fd = os.open(lease_root / ".lease-store.lock", os.O_RDWR | os.O_CREAT, 0o660)
            try:
                os.fchmod(fd, 0o660)
                os.fchown(fd, -1, pwd.getpwuid(os.getuid()).pw_gid)
            finally:
                os.close(fd)
        self.processes = []
        self.clients = []
        self.addCleanup(self._cleanup_owned)

    def _cleanup_owned(self) -> None:
        (self.root / "release-first").touch()
        for client in self.clients:
            client.close()
        for process, log in self.processes:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            finally:
                log.close()

    def _launch(self, mode: str = "serve", slot: str = "server"):
        username = pwd.getpwuid(os.getuid()).pw_name
        env = {
            "PATH": os.defpath, "HOME": str(self.root / "home"),
            "TMPDIR": str(self.root / "tmp"), "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "HERMES_OMP_POLICY": str(self.root / "policy.json"),
            "HERMES_OMP_POLICY_STAMP": str(self.root / f"{slot}-stamp.json"),
            "HERMES_OMP_JOB_DIR": str(self.root / f"{slot}-jobs"),
            "HERMES_OMP_LOCK_DIR": str(self.root / "locks"),
            "HERMES_OMP_AUDIT_LOG": str(self.root / "audit.jsonl"),
            "HERMES_OMP_AGENT_DIR": str(self.root / "agent"),
            "HERMES_OMP_CREDENTIAL_DIR": str(self.root / "credentials"),
            "HERMES_OMP_BIN": str(self.root / "no-omp-executable"),
            "HERMES_OMP_TOKEN_BIN": str(self.root / "no-token-executable"),
            "HERMES_OMP_ENDPOINT_USERS": ",".join(
                f"{name}={username}" for name in ENDPOINTS),
            "HERMES_OMP_LEASE_DIRS": ",".join(
                f"{name}={self.root / 'leases' / name}" for name in ENDPOINTS),
        }
        log = (self.root / f"{slot}.log").open("wb")
        try:
            process = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--fixture",
                 str(self.root), mode, slot],
                cwd=self.root, env=env, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT,
            )
        except BaseException:
            log.close()
            raise
        self.processes.append((process, log))
        report = self._wait_json(f"{slot}-report-0.json", process)
        return process, report

    def _wait_json(self, name: str, process, timeout: float = WAIT_TIMEOUT):
        deadline = time.monotonic() + timeout
        path = self.root / name
        while not path.exists():
            if process.poll() is not None:
                logs = "\n".join(p.read_text() for p in self.root.glob("*.log"))
                self.fail(f"fixture exited {process.returncode} awaiting {name}: {logs}")
            if time.monotonic() >= deadline:
                self.fail(f"fixture did not publish {name} within {timeout}s")
            time.sleep(0.01)
        return json.loads(path.read_text())

    def _send(self, endpoint: str, request: dict) -> socket.socket:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.clients.append(client)
        client.settimeout(CONTROL_TIMEOUT)
        client.connect(str(self.root / f"{endpoint}.sock"))
        payload = json.dumps(request).encode()
        client.sendall(struct.pack("!I", len(payload)) + payload)
        return client

    def _receive(self, client: socket.socket, timeout: float = CONTROL_TIMEOUT):
        deadline = time.monotonic() + timeout

        def exact(size: int) -> bytes:
            result = bytearray()
            while len(result) < size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.fail("framed broker response exceeded its control deadline")
                client.settimeout(remaining)
                try:
                    chunk = client.recv(size - len(result))
                except socket.timeout:
                    self.fail("framed broker response exceeded its control deadline")
                self.assertTrue(chunk, "broker closed without a complete response frame")
                result.extend(chunk)
            return bytes(result)

        size = struct.unpack("!I", exact(4))[0]
        self.assertGreater(size, 0)
        self.assertLessEqual(size, 8_000_000)
        return json.loads(exact(size))

    def _rpc(self, endpoint: str, request: dict):
        client = self._send(endpoint, request)
        try:
            return self._receive(client)
        finally:
            client.close()

    @staticmethod
    def _request(op: str, lease: str) -> dict:
        return {"version": 2, "op": op, "lease_id": lease}

    def _health(self, endpoint: str) -> None:
        self.assertEqual(
            {"version": 2, "op": "health", "ok": True},
            self._rpc(endpoint, {"version": 2, "op": "health"}),
        )

    def _status(self, endpoint: str, lease: str, request_id: str, status: str) -> None:
        response = self._rpc(endpoint, self._request("status", lease))
        self.assertTrue(response["ok"], response)
        self.assertEqual((2, "status"), (response["version"], response["op"]))
        self.assertEqual(request_id, response["job"]["request_id"])
        self.assertEqual(status, response["job"]["status"])

    def _hold_first(self):
        process, report = self._launch()
        leases = report["leases"]
        # Positive controls before creating the contested scheduling state.
        for endpoint in ENDPOINTS:
            self._health(endpoint)
            request_id = "seed" if endpoint == "audit" else f"{endpoint}-seed"
            self._status(endpoint, leases[endpoint]["seed"], request_id, "completed")
        client = self._send("audit", self._request("execute", leases["audit"]["first"]))
        self._wait_json("entered-first.json", process)
        return process, leases, client

    def test_framed_health_responds_while_execution_is_held(self) -> None:
        process, leases, first = self._hold_first()
        # Pending execution must not consume all control dispatch capacity.
        second = self._send("code", self._request("execute", leases["code"]["second"]))
        for endpoint in ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                self._health(endpoint)
        self.assertFalse((self.root / "exited-first.json").exists())
        (self.root / "release-first").touch()
        self.assertEqual(0, self._receive(first)["exit_code"])
        self.assertEqual(0, self._receive(second)["exit_code"])
        self.assertIsNone(process.poll())

    def test_framed_status_responds_while_execution_is_held(self) -> None:
        _process, leases, first = self._hold_first()
        for endpoint in ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                if endpoint == "audit":
                    self._status(endpoint, leases[endpoint]["first"], "first", "running")
                else:
                    self._status(endpoint, leases[endpoint]["seed"],
                                 f"{endpoint}-seed", "completed")
        self.assertFalse((self.root / "exited-first.json").exists())
        (self.root / "release-first").touch()
        self.assertEqual(0, self._receive(first)["exit_code"])

    def test_second_execution_on_another_workspace_never_overlaps(self) -> None:
        process, leases, first = self._hold_first()
        second = self._send("code", self._request("execute", leases["code"]["second"]))
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            self.assertFalse((self.root / "entered-code-second.json").exists(),
                             "second execution entered before the first was released")
            self.assertIsNone(process.poll())
            time.sleep(0.01)
        (self.root / "release-first").touch()
        self.assertEqual("first", self._receive(first)["request_id"])
        response = self._receive(second)
        self.assertEqual(("code-second", 0), (response["request_id"], response["exit_code"]))
        entered = self._wait_json("entered-code-second.json", process)
        exited = self._wait_json("exited-first.json", process)
        self.assertEqual("second", entered["repository"])
        self.assertGreaterEqual(entered["at"], exited["at"])
        self.assertFalse((self.root / "overlap.json").exists())

    def test_framed_authority_refusals_preserve_valid_lease(self) -> None:
        _process, report = self._launch()
        leases = report["leases"]
        valid = leases["audit"]["second"]
        for endpoint, request in (
            ("code", self._request("execute", valid)),
            ("audit", self._request("execute", leases["audit"]["foreign-peer"])),
            ("audit", {**self._request("execute", valid), "caller": "audit"}),
        ):
            with self.subTest(endpoint=endpoint, request=request):
                self.assertEqual(
                    {"version": 2, "op": "execute", "ok": False, "error": "job unavailable"},
                    self._rpc(endpoint, request),
                )
        self.assertFalse((self.root / "entered-second.json").exists())
        for endpoint in ENDPOINTS:
            self._health(endpoint)
        result = self._rpc("audit", self._request("execute", valid))
        self.assertEqual(("second", 0), (result["request_id"], result["exit_code"]))
        self._status("audit", valid, "second", "completed")

    def test_disconnected_waiter_does_not_consume_its_lease(self) -> None:
        _process, leases, first = self._hold_first()
        lease = leases["code"]["second"]
        second = self._send("code", self._request("execute", lease))
        second.close()
        self._health("code")
        (self.root / "release-first").touch()
        self.assertEqual(0, self._receive(first)["exit_code"])
        response = self._rpc("code", self._request("execute", lease))
        self.assertEqual(("code-second", 0), (response["request_id"], response["exit_code"]))

    def test_incomplete_frame_does_not_block_other_controls(self) -> None:
        _process, _leases, first = self._hold_first()
        stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.clients.append(stalled)
        stalled.connect(str(self.root / "audit.sock"))
        stalled.sendall(b"\x00")
        for endpoint in ENDPOINTS:
            self._health(endpoint)
        stalled.close()
        (self.root / "release-first").touch()
        self.assertEqual(0, self._receive(first)["exit_code"])


    @staticmethod
    def _provenance(report: dict) -> dict:
        # Existing writer surface, not a speculative new stamp API. Compare all
        # non-clock/process evidence so an additive dependency field also works.
        stamp = report["stamp"]
        if not isinstance(stamp, dict):
            raise AssertionError("valid loaded policy must produce a stamp")
        return {key: value for key, value in stamp.items()
                if key not in {"pid", "start_monotonic_usec", "written_at"}}

    def test_lifecycle_replacement_cannot_attest_old_process_as_fresh(self) -> None:
        old_process, before = self._launch("stamp", "old")
        _control_process, control = self._launch("stamp", "unchanged")
        expected_path = str(self.root / "broker/lifecycle.py")
        self.assertEqual(expected_path, before["lifecycle_file"])
        self.assertEqual("job unavailable", before["loaded_lifecycle"])
        self.assertEqual(self._provenance(before), self._provenance(control),
                         "unchanged loaded bytes must have the same provenance")

        lifecycle = Path(expected_path)
        original = lifecycle.read_bytes()
        old_literal = b'LEASE_UNAVAILABLE = "job unavailable"'
        replacement = b'LEASE_UNAVAILABLE = "fixture lifecycle replacement"'
        self.assertEqual(1, original.count(old_literal),
                         "source-bound fixture must replace the real lifecycle constant")
        changed = lifecycle.with_suffix(".replacement")
        changed.write_bytes(original.replace(old_literal, replacement))
        changed.replace(lifecycle)

        (self.root / "old-request-1").touch()
        after = self._wait_json("old-report-1.json", old_process)
        self.assertEqual("job unavailable", after["loaded_lifecycle"])
        self.assertEqual(self._provenance(before), self._provenance(after),
                         "reporting must retain loaded bytes, not reread lifecycle on disk")
        self.assertEqual(
            {"path": expected_path, "sha256": "sha256:" + hashlib.sha256(original).hexdigest()},
            after["stamp"]["loaded_artifacts"]["lifecycle"],
        )

        _fresh_process, fresh = self._launch("stamp", "fresh")
        self.assertEqual(expected_path, fresh["lifecycle_file"])
        self.assertEqual("fixture lifecycle replacement", fresh["loaded_lifecycle"])
        self.assertEqual(
            {"path": expected_path,
             "sha256": "sha256:" + hashlib.sha256(original.replace(old_literal, replacement)).hexdigest()},
            fresh["stamp"]["loaded_artifacts"]["lifecycle"],
        )
        self.assertNotEqual(
            self._provenance(after), self._provenance(fresh),
            "old and fresh processes certify different loaded lifecycle bytes identically; "
            "script/policy-only stamps cannot establish runtime freshness",
        )
        # The external freshness reporter and old/missing-stamp rejection are
        # outside this module's API. Main must freeze that migration with its
        # consumers; this test deliberately does not invent reporter methods.

    def test_stale_lifecycle_bytecode_cannot_earn_a_source_stamp(self) -> None:
        lifecycle = self.root / "broker/lifecycle.py"
        original = lifecycle.read_bytes()
        metadata = lifecycle.stat()
        cache = Path(py_compile.compile(str(lifecycle), doraise=True))
        replacement = original.replace(
            b'LEASE_UNAVAILABLE = "job unavailable"',
            b'LEASE_UNAVAILABLE = "new unavailable"')
        self.assertNotEqual(original, replacement)
        self.assertEqual(len(original), len(replacement))
        lifecycle.write_bytes(replacement)
        os.utime(lifecycle, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        _process, stale = self._launch("stamp", "stale-cache")
        self.assertEqual("job unavailable", stale["loaded_lifecycle"])
        self.assertIsNone(stale["stamp"],
                          "source differing from executed bytecode must not earn provenance")
        cache.unlink()
        _process, fresh = self._launch("stamp", "source-only")
        self.assertEqual("new unavailable", fresh["loaded_lifecycle"])
        self.assertEqual(
            {"path": str(lifecycle),
             "sha256": "sha256:" + hashlib.sha256(replacement).hexdigest()},
            fresh["stamp"]["loaded_artifacts"]["lifecycle"],
        )


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--fixture":
        _fixture_process(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    else:
        unittest.main()
