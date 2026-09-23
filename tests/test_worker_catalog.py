"""OMP 18.2.8 must use the worker FD key, not its catalog sentinel."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkerCatalogTest(unittest.TestCase):
    def test_provider_fd_overrides_catalog_and_missing_fd_fails_closed(self) -> None:
        binary_path = os.environ.get("OMP_WORKER_TEST_BINARY")
        if not binary_path:
            self.skipTest("set OMP_WORKER_TEST_BINARY to the pinned OMP binary")
        binary = Path(binary_path)
        self.assertTrue(binary.is_file(), binary)
        requests: list[str | None] = []

        class Gateway(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:
                pass

            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                auth = self.headers.get("Authorization")
                requests.append(auth)
                if auth != "Bearer synthetic-fd-key":
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'{"error":{"message":"synthetic unauthorized","type":"invalid_request_error"}}')
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for event in (
                    '{"id":"probe","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"MOCK_OK"},"finish_reason":null}]}',
                    '{"id":"probe","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}',
                    "[DONE]",
                ):
                    self.wfile.write(("data: " + event + "\n\n").encode())
                    self.wfile.flush()

        with tempfile.TemporaryDirectory() as td, ThreadingHTTPServer(("127.0.0.1", 0), Gateway) as server:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            agent = root / "agent"
            agent.mkdir()
            catalog = (ROOT / "broker/worker-models.yml").read_text()
            (agent / "models.yml").write_text(catalog.replace(
                "127.0.0.1:4000", f"127.0.0.1:{server.server_port}"))
            (agent / "agent.db").symlink_to(home / "agent.db")
            (agent / "models.yml").chmod(0o444)
            agent.chmod(0o555)
            home.chmod(0o700)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                env = {"HOME": str(home), "PI_CODING_AGENT_DIR": str(agent),
                       "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
                       "LC_ALL": "C.UTF-8"}
                argv = [str(binary), "-p", "--no-session", "--no-title",
                        "--no-prewalk", "--no-extensions", "--no-mcp",
                        "--no-skills", "--no-rules", "--approval-mode=yolo",
                        "--model", "gateway/bb-plan-glm", "--cwd", str(root),
                        "--max-time=10", "Say probe."]
                fd = os.memfd_create("synthetic-provider-key", os.MFD_CLOEXEC)
                try:
                    os.write(fd, json.dumps({"gateway": "synthetic-fd-key"}).encode())
                    os.lseek(fd, 0, os.SEEK_SET)
                    with_key = subprocess.run(
                        [*argv[:-1], "--provider-api-keys-fd", str(fd), argv[-1]],
                        env=env, pass_fds=(fd,), stdin=subprocess.DEVNULL,
                        capture_output=True, text=True, timeout=16)
                finally:
                    os.close(fd)
                self.assertEqual(0, with_key.returncode, with_key.stderr)
                self.assertIn("MOCK_OK", with_key.stdout)
                without_key = subprocess.run(
                    argv, env=env, stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=16)
                self.assertNotEqual(0, without_key.returncode)
                self.assertEqual(2, len(requests), requests)
                self.assertEqual("Bearer synthetic-fd-key", requests[0])
                self.assertEqual("invalid-without-worker-fd",
                                 requests[1].split(" ", 1)[1])
            finally:
                server.shutdown()
                thread.join(timeout=3)
                agent.chmod(0o755)
                home.chmod(0o755)
