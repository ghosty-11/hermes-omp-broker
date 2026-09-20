from __future__ import annotations

import contextlib
import io
import os
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from broker import lifecycle
from test_run_request_resilience import ResilienceHarness


class ProcessIdentityTests(unittest.TestCase):
    def child(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 start_new_session=True)
        self.addCleanup(self.clear, child)
        return child

    @staticmethod
    def clear(child):
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)

    def test_terminal_record_retires_current_birth_but_keeps_history(self):
        with tempfile.TemporaryDirectory() as raw:
            store = lifecycle.JobStore(Path(raw))
            store.create("req", task_id="task", repository="wiki", caller="writer")
            child = self.child()
            store.launching("req")
            store.running("req", process_group=child.pid)
            record = store.get("req")
            self.assertTrue(lifecycle.process_identity_matches(record["process"], os.getpid()))
            self.assertEqual(child.pid, record["process"]["pid"])
            store.finish("req", "failed", {"final": None})
            restarted = lifecycle.JobStore(Path(raw)).get("req")
            self.assertIsNone(restarted["process"])
            self.assertIsNone(restarted["process_group"])
            self.assertEqual(record["process"], restarted["process_history"][0]["identity"])

    def test_uncertain_launch_survives_restart_without_replay(self):
        with tempfile.TemporaryDirectory() as raw:
            store = lifecycle.JobStore(Path(raw))
            store.create("req", task_id="task", repository="wiki", caller="writer")
            store.launching("req")
            restarted = lifecycle.JobStore(Path(raw))
            restarted.recover_orphans()
            with self.assertRaises(ValueError):
                restarted.arm_reexecution("req", task_id="task", repository="wiki", caller="writer")

    def test_recycled_birth_and_wrong_broker_are_inert(self):
        child = self.child()
        identity = lifecycle.capture_process_identity(child.pid)
        for changed in ({**identity, "start_ticks": identity["start_ticks"] + 1},
                        {**identity, "boot_id": "previous-boot"}):
            self.assertFalse(lifecycle.process_identity_matches(changed, os.getpid()))
            with mock.patch.object(signal, "pidfd_send_signal") as send:
                self.assertFalse(lifecycle.terminate_process_tree(changed, authorize=lambda: True))
                send.assert_not_called()
        self.assertFalse(lifecycle.process_identity_matches(identity, child.pid))
        self.assertIsNone(child.poll())

    def test_matched_tree_clears_detached_descendant_not_unrelated_child(self):
        tree = subprocess.Popen([
            sys.executable, "-c",
            "import subprocess,sys,time; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); "
            "print(p.pid,flush=True); time.sleep(60)",
        ], stdout=subprocess.PIPE, text=True, start_new_session=True)
        self.addCleanup(self.clear, tree)
        descendant = int(tree.stdout.readline())
        self.addCleanup(tree.stdout.close)
        def clear_descendant():
            try:
                os.kill(descendant, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.addCleanup(clear_descendant)
        unrelated = self.child()
        identity = lifecycle.capture_process_identity(tree.pid)
        self.assertTrue(lifecycle.terminate_process_tree(identity, authorize=lambda: True))
        tree.wait(timeout=5)
        self.assertIsNone(unrelated.poll())
        try:
            state = Path(f"/proc/{descendant}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except FileNotFoundError:
            state = "gone"
        self.assertIn(state, {"gone", "Z", "X"})

    def test_maintenance_denial_leaves_child_running(self):
        child = self.child()
        identity = lifecycle.capture_process_identity(child.pid)
        with mock.patch.object(signal, "pidfd_send_signal") as send:
            self.assertFalse(lifecycle.terminate_process_tree(identity, authorize=lambda: False))
        send.assert_not_called()
        self.assertIsNone(child.poll())


class ProcessPersistenceFailureTests(ResilienceHarness):
    def test_running_record_failure_cleans_child_and_refuses_replay(self):
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            spawned = []
            def spawn(*args):
                child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         start_new_session=True)
                spawned.append(child)
                self.addCleanup(ProcessIdentityTests.clear, child)
                return child
            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            with (mock.patch.object(module, "resolve_provider_api_keys", return_value={}),
                  mock.patch.object(module, "start_omp_process", side_effect=spawn),
                  mock.patch.object(module.JOB_STORE, "running", side_effect=OSError("disk full")),
                  contextlib.redirect_stderr(io.StringIO())):
                response = module.run_request(request, connection)
            self.assertNotEqual(0, response["exit_code"])
            self.assertIsNotNone(spawned[0].poll())
            record = module.JOB_STORE.get(request.request_id)
            self.assertEqual("failed", record["status"])
            self.assertTrue(record["launch_uncertain"])
            with self.assertRaises(ValueError):
                module.JOB_STORE.arm_reexecution(request.request_id, task_id=request.task_id,
                                                repository=request.repository, caller=request.caller)

    def test_launch_intent_failure_never_spawns(self):
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            with (mock.patch.object(module, "resolve_provider_api_keys", return_value={}),
                  mock.patch.object(module, "start_omp_process") as spawn,
                  mock.patch.object(module.JOB_STORE, "launching", side_effect=OSError("disk full")),
                  contextlib.redirect_stderr(io.StringIO())):
                response = module.run_request(request, connection)
            spawn.assert_not_called()
            self.assertNotEqual(0, response["exit_code"])

    def test_all_postspawn_writes_fail_without_losing_consumed_intent(self):
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            spawned = []
            write = module.JOB_STORE._write
            def failing_write(record):
                if spawned:
                    raise OSError("durable store unavailable")
                write(record)
            def spawn(*args):
                child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         start_new_session=True)
                spawned.append(child)
                self.addCleanup(ProcessIdentityTests.clear, child)
                return child
            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            with (mock.patch.object(module, "resolve_provider_api_keys", return_value={}),
                  mock.patch.object(module, "start_omp_process", side_effect=spawn),
                  mock.patch.object(module.JOB_STORE, "_write", side_effect=failing_write),
                  contextlib.redirect_stderr(io.StringIO())):
                response = module.run_request(request, connection)
            self.assertNotEqual(0, response["exit_code"])
            self.assertFalse(response["process_group_clear"])
            self.assertIsNotNone(spawned[0].poll())
            restarted = lifecycle.JobStore(Path(raw) / "jobs")
            restarted.recover_orphans()
            self.assertTrue(restarted.get(request.request_id)["launch_uncertain"])
            with self.assertRaises(ValueError):
                restarted.arm_reexecution(request.request_id, task_id=request.task_id,
                                          repository=request.repository, caller=request.caller)
