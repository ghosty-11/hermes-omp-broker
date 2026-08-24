"""Contracts for the Hermes-to-OMP broker client."""

from __future__ import annotations

import importlib.util
import json
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "client" / "omp-invoke.py"


def load_client():
    spec = importlib.util.spec_from_file_location("omp_invoke", CLIENT)
    if spec is None or spec.loader is None:
        raise RuntimeError("client could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestOmpInvoke(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_client()

    def test_policy_is_fixed_by_attributed_caller(self) -> None:
        workspace = Path("repositories/example").resolve()
        policy = self.module.resolve_policy(
            {"OMP_INVOKED_BY": "delegate_to_omp"}, workspace
        )
        self.assertEqual("delegate_to_omp", policy.caller)
        self.assertEqual(workspace, policy.workspace)
        self.assertEqual("workspace-write", policy.sandbox)
        self.assertEqual("provider/model", policy.model)
        with self.assertRaises(self.module.InvocationError):
            self.module.resolve_policy({"OMP_INVOKED_BY": "unknown"}, Path.cwd())

    def test_non_delegate_caller_is_resolved_from_deployment_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td) / "wiki"
            workspace.mkdir()
            policy_file = Path(td) / "policy.json"
            policy_file.write_text(json.dumps({
                "repositories": {"wiki": {"path": str(workspace)}},
                "callers": {
                    "audit": {
                        "repositories": ["wiki"],
                        "sandbox": "restricted-write",
                    }
                },
            }))
            policy = self.module.resolve_policy(
                {
                    "OMP_INVOKED_BY": "audit",
                    "HERMES_OMP_POLICY": str(policy_file),
                },
                Path("/tmp/ignored"),
            )
            self.assertEqual("audit", policy.caller)
            self.assertEqual("wiki", policy.repository)
            self.assertEqual(workspace.resolve(), policy.workspace)
            self.assertEqual("restricted-write", policy.sandbox)

    def test_socket_path_comes_from_deployment_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy_file = Path(td) / "policy.json"
            policy_file.write_text(json.dumps({
                "socket": "/run/hermes/omp.sock",
                "repositories": {},
            }))
            self.assertEqual(
                Path("/run/hermes/omp.sock"),
                self.module._policy_socket({"HERMES_OMP_POLICY": str(policy_file)}),
            )

    def test_client_sends_one_bounded_frame_and_write_half_closes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "broker.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            listener.listen(1)
            observed: dict[str, object] = {}
            final = {
                "summary": "fixture complete",
                "verification": ["fixture passed"],
                "gaps": [],
                "verdict": "MET",
            }

            def serve() -> None:
                conn, _ = listener.accept()
                with conn:
                    size = struct.unpack("!I", conn.recv(4))[0]
                    payload = bytearray()
                    while len(payload) < size:
                        payload.extend(conn.recv(size - len(payload)))
                    observed.update(json.loads(payload))
                    observed["write_half_closed"] = conn.recv(1) == b""
                    response = {
                        "version": 1,
                        "exit_code": 0,
                        "stdout": "",
                        "stderr": "",
                        "timed_out": False,
                        "process_group_clear": True,
                        "final": final,
                        "request_id": "fixture-id",
                    }
                    body = json.dumps(response).encode()
                    conn.sendall(struct.pack("!I", len(body)) + body)

            worker = threading.Thread(target=serve)
            worker.start()
            policy = self.module.Policy(
                "fixture-request", "fixture-task", "fixture-repository",
                "delegate_to_omp", Path("/tmp/workspace"), "workspace-write",
                "provider/model", 120.0,
            )
            response = self.module.invoke_broker(socket_path, policy, "bounded prompt")
            worker.join(timeout=2)
            listener.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual("delegate_to_omp", observed["caller"])
            self.assertEqual("bounded prompt", observed["prompt"])
            self.assertTrue(observed["write_half_closed"])
            self.assertEqual(final, response["final"])

    def test_response_must_be_completed_group_clear_and_typed(self) -> None:
        base = {
            "version": 1,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "process_group_clear": True,
            "final": {
                "summary": "done",
                "verification": [],
                "gaps": [],
                "verdict": "MET",
            },
            "request_id": "id",
        }
        self.assertEqual(base["final"], self.module.validate_response(base)["final"])
        for changed in (
            {**base, "exit_code": 1},
            {**base, "timed_out": True},
            {**base, "process_group_clear": False},
            {**base, "final": None},
            {**base, "extra": True},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(self.module.InvocationError):
                    self.module.validate_response(changed)

    def test_caller_output_contains_structured_evidence(self) -> None:
        response = {
            "final": {
                "summary": "implemented",
                "verification": ["8 tests passed"],
                "gaps": ["live deployment pending"],
                "verdict": "PARTIALLY MET",
            },
            "request_id": "abc123",
        }
        text = self.module.format_response(response, caller="delegate_to_omp")
        self.assertIn("implemented", text)
        self.assertIn("OMP · caller=delegate_to_omp · verdict=PARTIALLY MET", text)
        self.assertIn("verification: 8 tests passed", text)
        self.assertIn("gaps: live deployment pending", text)
        self.assertIn("request=abc123", text)

    def test_json_output_exposes_only_typed_final_metadata(self) -> None:
        response = {
            "final": {
                "summary": "implemented",
                "verification": ["8 tests passed"],
                "gaps": [],
                "verdict": "MET",
            },
            "request_id": "abc123",
            "stdout": "must not escape",
            "stderr": "must not escape",
        }
        value = json.loads(
            self.module.format_json_response(response, caller="optmem-consolidate")
        )
        self.assertEqual("MET", value["verdict"])
        self.assertEqual("implemented", value["summary"])
        self.assertEqual("optmem-consolidate", value["caller"])
        self.assertEqual("abc123", value["request_id"])
        self.assertNotIn("stdout", value)
        self.assertNotIn("stderr", value)



    def test_trusted_fake_v2_success_sends_only_opaque_lease_and_spends_nothing_client_side(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "broker.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            listener.listen(1)
            observed: dict[str, object] = {}

            def serve() -> None:
                conn, _ = listener.accept()
                with conn:
                    size = struct.unpack("!I", conn.recv(4))[0]
                    payload = bytearray()
                    while len(payload) < size:
                        payload.extend(conn.recv(size - len(payload)))
                    observed.update(json.loads(payload))
                    response = {
                        "version": 2,
                        "exit_code": 0,
                        "stdout": "",
                        "stderr": "",
                        "timed_out": False,
                        "process_group_clear": True,
                        "final": {
                            "summary": "trusted fixture complete",
                            "verification": ["fake broker exercised"],
                            "gaps": [],
                            "verdict": "MET",
                        },
                        "request_id": "server-fixed-request",
                    }
                    body = json.dumps(response).encode()
                    conn.sendall(struct.pack("!I", len(body)) + body)

            worker = threading.Thread(target=serve)
            worker.start()
            response = self.module.invoke_broker_v2(
                socket_path, "opaque-lease-handle", "execute")
            worker.join(timeout=2)
            listener.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual({
                "version": 2,
                "op": "execute",
                "lease_id": "opaque-lease-handle",
            }, observed)
            self.assertEqual("server-fixed-request", response["request_id"])

    def test_v2_status_uses_the_same_minimal_schema(self) -> None:
        sent: list[dict[str, object]] = []

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def connect(self, _path):
                return None

            def settimeout(self, _timeout):
                return None

            def sendall(self, frame):
                size = struct.unpack("!I", frame[:4])[0]
                sent.append(json.loads(frame[4:4 + size]))

            def shutdown(self, _how):
                return None

            def recv(self, size):
                response = json.dumps({
                    "version": 2, "op": "status", "ok": False,
                    "error": "job unavailable",
                }).encode()
                frame = struct.pack("!I", len(response)) + response
                chunk, self.buffer = frame[:size], frame[size:]
                self.recv = lambda count: self._next(count)
                return chunk

            def _next(self, size):
                chunk, self.buffer = self.buffer[:size], self.buffer[size:]
                return chunk
        with mock.patch.object(self.module.socket, "socket", return_value=FakeSocket()):
            with self.assertRaises(self.module.InvocationError) as raised:
                self.module.invoke_broker_v2(Path("/fixed.sock"), "lease", "status")
        self.assertEqual("job unavailable", str(raised.exception))
        self.assertEqual(
            [{"version": 2, "op": "status", "lease_id": "lease"}], sent)


    def test_v2_health_sends_exact_no_spend_canary_and_validates_exact_response(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "broker.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            listener.listen(1)
            observed: dict[str, object] = {}

            def serve() -> None:
                conn, _ = listener.accept()
                with conn:
                    size = struct.unpack("!I", conn.recv(4))[0]
                    payload = bytearray()
                    while len(payload) < size:
                        payload.extend(conn.recv(size - len(payload)))
                    observed.update(json.loads(payload))
                    response = {"version": 2, "op": "health", "ok": True}
                    body = json.dumps(response).encode()
                    conn.sendall(struct.pack("!I", len(body)) + body)

            worker = threading.Thread(target=serve)
            worker.start()
            self.assertEqual(
                {"version": 2, "op": "health", "ok": True},
                self.module.health_broker_v2(socket_path),
            )
            worker.join(timeout=2)
            listener.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual({"version": 2, "op": "health"}, observed)

            with self.assertRaises(self.module.InvocationError) as unavailable:
                self.module.validate_health_response({
                    "version": 2, "op": "health", "ok": False,
                    "error": "endpoint unavailable",
                })
            self.assertEqual("endpoint unavailable", str(unavailable.exception))
            for invalid in (
                {"version": 2, "op": "health", "ok": True, "extra": True},
                {"version": 2, "op": "health"},
                {"version": 1, "op": "health", "ok": True},
            ):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(self.module.InvocationError):
                        self.module.validate_health_response(invalid)
if __name__ == "__main__":
    unittest.main(verbosity=2)
