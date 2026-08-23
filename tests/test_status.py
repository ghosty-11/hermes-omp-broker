"""Fail-first contracts for read-only broker status retrieval."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "broker" / "omp-delegate-broker.py"
CLIENT = ROOT / "client" / "omp-invoke.py"


class _StopServing(Exception):
    pass


class _OneConnectionListener:
    def __init__(self, connection: socket.socket) -> None:
        self.connection = connection
        self.accepted = False

    def accept(self) -> tuple[socket.socket, None]:
        if self.accepted:
            raise _StopServing
        self.accepted = True
        return self.connection, None


class _UnreadableInput:
    def read(self, *_args: object, **_kwargs: object) -> str:
        raise AssertionError("status must not read a prompt from stdin")


class _FramedStatusSocket:
    def __init__(self, response: dict[str, object]) -> None:
        body = json.dumps(response, separators=(",", ":")).encode()
        self.response = bytearray(struct.pack("!I", len(body)) + body)
        self.connected_to: str | None = None
        self.sent = b""
        self.write_half_closed = False
        self.timeout: float | None = None

    def __enter__(self) -> _FramedStatusSocket:
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def connect(self, path: str) -> None:
        self.connected_to = path

    def sendall(self, payload: bytes) -> None:
        self.sent += payload

    def shutdown(self, how: int) -> None:
        if how != socket.SHUT_WR:
            raise AssertionError("client must close only its write half")
        self.write_half_closed = True

    def recv(self, size: int) -> bytes:
        chunk = bytes(self.response[:size])
        del self.response[:size]
        return chunk

    def request(self) -> dict[str, object]:
        size = struct.unpack("!I", self.sent[:4])[0]
        if size != len(self.sent) - 4:
            raise AssertionError("status request was not one bounded frame")
        return json.loads(self.sent[4:])


class StatusServerProtocolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.repo = root / "repo"
        self.other_repo = root / "other"
        self.repo.mkdir()
        self.other_repo.mkdir()
        self.jobs = root / "jobs"
        self.audit = root / "audit.jsonl"
        self.audit.write_text('{"event":"existing"}\n', encoding="utf-8")
        policy = root / "policy.json"
        policy.write_text(json.dumps({
            "repositories": {
                "repo": {"path": str(self.repo)},
                "other": {"path": str(self.other_repo)},
            },
            "callers": {
                "planner": {
                    "repositories": ["repo", "other"],
                    "sandbox": "workspace-write",
                },
                "reviewer": {
                    "repositories": ["repo"],
                    "sandbox": "read-only",
                },
            },
        }), encoding="utf-8")
        with mock.patch.dict(os.environ, {
            "HERMES_OMP_POLICY": str(policy),
            "HERMES_OMP_CALLER_UID": str(os.getuid()),
            "HERMES_OMP_JOB_DIR": str(self.jobs),
            "HERMES_OMP_AUDIT_LOG": str(self.audit),
        }):
            name = f"broker_status_{os.urandom(4).hex()}"
            spec = importlib.util.spec_from_file_location(name, BROKER)
            assert spec and spec.loader
            self.module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = self.module
            spec.loader.exec_module(self.module)

    def _exchange(self, request: dict[str, object]) -> dict[str, object]:
        before_jobs = {
            path.name: path.read_bytes()
            for path in self.jobs.glob("*.json")
        }
        before_audit = self.audit.read_bytes()
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        payload = json.dumps(request, separators=(",", ":")).encode()
        client.sendall(struct.pack("!I", len(payload)) + payload)
        client.shutdown(socket.SHUT_WR)

        listener = _OneConnectionListener(server)
        with (
            mock.patch.object(self.module.JOB_STORE, "recover_orphans"),
            mock.patch.object(self.module, "start_omp_process") as start,
            mock.patch.object(self.module, "record_audit") as audit,
            self.assertRaises(_StopServing),
        ):
            self.module.serve(listener)

        start.assert_not_called()
        audit.assert_not_called()
        self.assertEqual(before_audit, self.audit.read_bytes())
        self.assertEqual(before_jobs, {
            path.name: path.read_bytes()
            for path in self.jobs.glob("*.json")
        })
        size = struct.unpack("!I", self._recv_exact(client, 4))[0]
        return json.loads(self._recv_exact(client, size))

    @staticmethod
    def _recv_exact(connection: socket.socket, size: int) -> bytes:
        payload = bytearray()
        while len(payload) < size:
            chunk = connection.recv(size - len(payload))
            if not chunk:
                raise AssertionError("server closed before completing its response frame")
            payload.extend(chunk)
        return bytes(payload)

    @staticmethod
    def _request(request_id: str, *, caller: str = "planner",
                 repository: str = "repo") -> dict[str, object]:
        return {
            "version": 1,
            "op": "status",
            "request_id": request_id,
            "caller": caller,
            "repository": repository,
        }

    def _expected_job(self, request_id: str) -> dict[str, object]:
        record = self.module.JOB_STORE.get(request_id)
        return {
            name: record[name]
            for name in (
                "request_id", "task_id", "repository", "caller", "status",
                "result", "created_at", "updated_at",
            )
        }

    def test_completed_result_is_retrieved_without_starting_work(self) -> None:
        result = {
            "version": 1,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "process_group_clear": True,
            "final": {
                "summary": "plan complete",
                "verification": ["commit inspected"],
                "gaps": [],
                "verdict": "MET",
            },
            "request_id": "completed",
        }
        self.module.JOB_STORE.create(
            "completed", task_id="task-completed", repository="repo", caller="planner",
        )
        self.module.JOB_STORE.finish("completed", "completed", result)

        self.assertEqual({
            "version": 1,
            "op": "status",
            "ok": True,
            "job": self._expected_job("completed"),
        }, self._exchange(self._request("completed")))

    def test_status_shapes_preserve_orphaned_and_failed_terminal_state(self) -> None:
        failed_result = {
            "version": 1,
            "exit_code": 1,
            "stdout": "",
            "stderr": "worker failed\n",
            "timed_out": False,
            "process_group_clear": True,
            "final": None,
            "request_id": "failed",
        }
        self.module.JOB_STORE.create(
            "orphaned", task_id="task-orphaned", repository="repo", caller="planner",
        )
        self.module.JOB_STORE.recover_orphans()
        self.module.JOB_STORE.create(
            "failed", task_id="task-failed", repository="repo", caller="planner",
        )
        self.module.JOB_STORE.finish("failed", "failed", failed_result)

        for request_id, status, result in (
            ("orphaned", "orphaned", None),
            ("failed", "failed", failed_result),
        ):
            with self.subTest(status=status, request_id=request_id):
                response = self._exchange(self._request(request_id))
                self.assertEqual({
                    "version": 1,
                    "op": "status",
                    "ok": True,
                    "job": self._expected_job(request_id),
                }, response)
                self.assertEqual(status, response["job"]["status"])
                self.assertEqual(result, response["job"]["result"])
                self.assertNotIn("process_group", response["job"])

    def test_pending_and_running_are_reported_without_startup_recovery(self) -> None:
        self.module.JOB_STORE.create(
            "pending", task_id="task-pending", repository="repo", caller="planner",
        )
        self.module.JOB_STORE.create(
            "running", task_id="task-running", repository="repo", caller="planner",
        )
        self.module.JOB_STORE.running("running", process_group=4321)

        for request_id, status in (("pending", "pending"), ("running", "running")):
            with self.subTest(status=status):
                response = self._exchange(self._request(request_id))
                self.assertEqual({
                    "version": 1,
                    "op": "status",
                    "ok": True,
                    "job": self._expected_job(request_id),
                }, response)
                self.assertEqual(status, response["job"]["status"])
                self.assertIsNone(response["job"]["result"])
                self.assertNotIn("process_group", response["job"])

    def test_unknown_request_is_generically_unavailable(self) -> None:
        self.assertEqual({
            "version": 1,
            "op": "status",
            "ok": False,
            "error": "job unavailable",
        }, self._exchange(self._request("unknown")))

    def test_caller_and_repository_mismatches_are_generically_unavailable(self) -> None:
        self.module.JOB_STORE.create(
            "private", task_id="task-private", repository="repo", caller="planner",
        )
        for request in (
            self._request("private", caller="reviewer"),
            self._request("private", repository="other"),
        ):
            with self.subTest(request=request):
                self.assertEqual({
                    "version": 1,
                    "op": "status",
                    "ok": False,
                    "error": "job unavailable",
                }, self._exchange(request))


class StatusClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        repo = root / "repo"
        other = root / "other"
        repo.mkdir()
        other.mkdir()
        self.policy = root / "policy.json"
        self.policy.write_text(json.dumps({
            "socket": str(root / "broker.sock"),
            "repositories": {
                "repo": {"path": str(repo)},
                "other": {"path": str(other)},
            },
            "callers": {
                "planner": {
                    "repositories": ["repo"],
                    "sandbox": "workspace-write",
                },
            },
        }), encoding="utf-8")
        self.environment = {
            "HERMES_OMP_POLICY": str(self.policy),
            "OMP_INVOKED_BY": "planner",
            "OMP_REPOSITORY": "repo",
        }
        with mock.patch.dict(os.environ, self.environment):
            name = f"omp_invoke_status_{os.urandom(4).hex()}"
            spec = importlib.util.spec_from_file_location(name, CLIENT)
            assert spec and spec.loader
            self.module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = self.module
            spec.loader.exec_module(self.module)

    @staticmethod
    def _job() -> dict[str, object]:
        return {
            "request_id": "request-17",
            "task_id": "task-17",
            "repository": "repo",
            "caller": "planner",
            "status": "completed",
            "result": {
                "version": 1,
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
                "process_group_clear": True,
                "final": {
                    "summary": "complete",
                    "verification": ["checked"],
                    "gaps": [],
                    "verdict": "MET",
                },
                "request_id": "request-17",
            },
            "created_at": 1_777_000_000,
            "updated_at": 1_777_000_001,
        }

    def _run(self, args: list[str], *, repository: str = "repo") -> tuple[
            int, str, str, _FramedStatusSocket, mock.Mock]:
        response = {
            "version": 1,
            "op": "status",
            "ok": True,
            "job": self._job(),
        }
        connection = _FramedStatusSocket(response)
        factory = mock.Mock(return_value=connection)
        stdout = io.StringIO()
        stderr = io.StringIO()
        environment = dict(self.environment, OMP_REPOSITORY=repository)
        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(sys, "argv", [str(CLIENT), *args]),
            mock.patch.object(sys, "stdin", _UnreadableInput()),
            mock.patch.object(self.module.socket, "socket", factory),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            code = self.module.main()
        return code, stdout.getvalue(), stderr.getvalue(), connection, factory

    def test_json_status_uses_exact_framed_request_and_prints_job(self) -> None:
        for args in (
            ["--json", "--status", "request-17"],
            ["--status", "request-17", "--json"],
        ):
            with self.subTest(args=args):
                code, stdout, stderr, connection, factory = self._run(args)
                self.assertEqual(0, code)
                self.assertEqual("", stderr)
                self.assertEqual(self._job(), json.loads(stdout))
                factory.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
                self.assertTrue(connection.write_half_closed)
                self.assertEqual({
                    "version": 1,
                    "op": "status",
                    "request_id": "request-17",
                    "caller": "planner",
                    "repository": "repo",
                }, connection.request())

    def test_human_status_output_is_compact_and_does_not_read_a_prompt(self) -> None:
        code, stdout, stderr, connection, factory = self._run(
            ["--status", "request-17"],
        )
        self.assertEqual(0, code)
        self.assertEqual("", stderr)
        self.assertEqual(
            "request=request-17 task=task-17 status=completed\n",
            stdout,
        )
        factory.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        self.assertEqual({
            "version": 1,
            "op": "status",
            "request_id": "request-17",
            "caller": "planner",
            "repository": "repo",
        }, connection.request())

    def test_status_refuses_repository_outside_the_callers_policy(self) -> None:
        code, _stdout, _stderr, _connection, factory = self._run(
            ["--status", "request-17"], repository="other",
        )
        self.assertNotEqual(0, code)
        factory.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
