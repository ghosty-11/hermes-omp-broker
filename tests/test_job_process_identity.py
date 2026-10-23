from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
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

    @staticmethod
    def observe_exit(child):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                return
            time.sleep(.001)
        raise AssertionError("fixture worker did not exit")

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
    @staticmethod
    def alive(pid):
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except FileNotFoundError:
            return False
        return state not in {"Z", "X"}

    @staticmethod
    def stop_fixture(child, pid_file):
        if pid_file.exists():
            for pid in json.loads(pid_file.read_text()):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        ProcessIdentityTests.clear(child)
        for stream in (child.stdout, child.stderr):
            if stream is not None:
                stream.close()

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

    def test_watcher_start_failure_reaps_worker_before_unlock(self):
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            spawned = []
            def spawn(*args):
                child = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
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
                  mock.patch.object(module.threading.Thread, "start",
                                    side_effect=RuntimeError("watcher start failed")),
                  contextlib.redirect_stderr(io.StringIO())):
                response = module.run_request(request, connection)
            self.assertEqual("failed", module.JOB_STORE.get(request.request_id)["status"])
            self.assertFalse(response["process_group_clear"])
            self.assertIsNotNone(spawned[0].poll())
            lock = module.acquire_workspace_lock(request.workspace)
            lock.close()

    def test_pipe_read_failure_reaps_worker_before_unlock(self):
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            spawned = []
            read_patch = None
            def spawn(*args):
                nonlocal read_patch
                child = subprocess.Popen(
                    [sys.executable, "-c",
                     "import sys,time; sys.stdout.write('ready'); "
                     "sys.stdout.flush(); time.sleep(30)"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                spawned.append(child)
                self.addCleanup(ProcessIdentityTests.clear, child)
                read_patch = mock.patch.object(
                    module.os, "read", side_effect=OSError("pipe read failed"))
                read_patch.start()
                return child
            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            try:
                with (mock.patch.object(module, "resolve_provider_api_keys",
                                        return_value={}),
                      mock.patch.object(module, "start_omp_process", side_effect=spawn),
                      contextlib.redirect_stderr(io.StringIO())):
                    response = module.run_request(request, connection)
            finally:
                if read_patch is not None:
                    read_patch.stop()
            self.assertEqual("failed", module.JOB_STORE.get(request.request_id)["status"])
            self.assertFalse(response["process_group_clear"])
            self.assertIsNotNone(spawned[0].poll())
            lock = module.acquire_workspace_lock(request.workspace)
            lock.close()

    def test_exited_worker_completes_with_detached_pipe_holder(self):
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            request = dataclasses.replace(request, timeout=2.0)
            holder_pid = Path(raw) / "holder.pid"
            spawned = []

            def spawn(_request, final_path, _keys):
                child = subprocess.Popen(
                    [sys.executable, "-c",
                     "import json,pathlib,subprocess,sys; "
                     "holder=subprocess.Popen("
                     "[sys.executable,'-c','import time; time.sleep(15)'],"
                     "stdout=sys.stdout,stderr=sys.stderr,start_new_session=True); "
                     "pathlib.Path(sys.argv[2]).write_text(str(holder.pid)); "
                     "pathlib.Path(sys.argv[1]).write_text(json.dumps("
                     "{'summary':'done','verification':[],'gaps':[],'verdict':'MET'})); "
                     "print('done',flush=True)",
                     str(final_path), str(holder_pid)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                spawned.append(child)
                self.addCleanup(ProcessIdentityTests.clear, child)
                return child

            parent, connection = socket.socketpair()
            try:
                with (mock.patch.object(module, "resolve_provider_api_keys",
                                        return_value={}),
                      mock.patch.object(module, "start_omp_process", side_effect=spawn),
                      mock.patch.object(module, "record_audit")):
                    response = module.run_request(request, connection)
                self.assertEqual(0, response["exit_code"])
                self.assertEqual("done\n", response["stdout"])
                self.assertFalse(response["timed_out"])
                self.assertTrue(response["process_group_clear"])
                self.assertEqual("completed",
                                 module.JOB_STORE.get(request.request_id)["status"])
            finally:
                if holder_pid.exists():
                    try:
                        os.kill(int(holder_pid.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                parent.close()
                connection.close()

    def test_combined_pipe_output_limit_discards_streams_and_reaps_worker(self):
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            spawned = []
            def spawn(*args):
                child = subprocess.Popen(
                    [sys.executable, "-c",
                     "import sys; "
                     "sys.stdout.buffer.write(b'a' * 600000); "
                     "sys.stdout.buffer.flush(); "
                     "sys.stderr.buffer.write(b'b' * 600000)"],
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
                  contextlib.redirect_stderr(io.StringIO())):
                response = module.run_request(request, connection)
            self.assertNotEqual(0, response["exit_code"])
            self.assertEqual("", response["stdout"])
            self.assertEqual(
                "omp-delegate-broker: OMP output exceeds capture limit\n",
                response["stderr"])
            self.assertFalse(response["timed_out"])
            self.assertIsNotNone(spawned[0].poll())
            record = module.JOB_STORE.get(request.request_id)
            self.assertEqual("failed", record["status"])
            self.assertEqual("", record["result"]["stdout"])
            self.assertEqual(
                "omp-delegate-broker: OMP output exceeds capture limit\n",
                record["result"]["stderr"])

    def test_exited_leader_stays_unreaped_through_fault_cleanup_before_unlock(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            module, request = self._load(td)
            descendant_pids = td / "descendants.json"
            spawned = []
            observed_unreaped = []
            reaped_at_unlock = []
            closed_states = []
            acquire = module.acquire_workspace_lock

            def alive(pid):
                try:
                    state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                except FileNotFoundError:
                    return False
                return state not in {"Z", "X"}

            def spawn(*args):
                child = subprocess.Popen(
                    [sys.executable, "-c",
                     "import json,pathlib,subprocess,sys; "
                     "children=[subprocess.Popen([sys.executable,'-c',"
                     "'import time; time.sleep(30)']) for _ in range(2)]; "
                     "pathlib.Path(sys.argv[1]).write_text(json.dumps([p.pid for p in children]))",
                     str(descendant_pids)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                spawned.append(child)
                return child

            class ObservedLock:
                def __init__(self, handle):
                    self.handle = handle

                def close(self):
                    reaped_at_unlock.append(spawned[0].returncode is not None)
                    closed_states.extend(alive(pid) for pid in json.loads(descendant_pids.read_text()))
                    self.handle.close()

            def select_fault(_selector, _timeout=None):
                if not descendant_pids.exists():
                    deadline = time.monotonic() + 5
                    while not descendant_pids.exists() and time.monotonic() < deadline:
                        time.sleep(.001)
                self.assertTrue(descendant_pids.exists())
                if not observed_unreaped:
                    ProcessIdentityTests.observe_exit(spawned[0])
                    observed_unreaped.append(spawned[0].returncode is None)
                    return []
                observed_unreaped.append(spawned[0].returncode is None)
                raise OSError("selector failed after leader exit")

            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            try:
                with (mock.patch.object(module, "resolve_provider_api_keys", return_value={}),
                      mock.patch.object(module, "start_omp_process", side_effect=spawn),
                      mock.patch.object(module, "acquire_workspace_lock",
                                        side_effect=lambda workspace: ObservedLock(acquire(workspace))),
                      mock.patch.object(module.selectors.EpollSelector, "select", select_fault),
                      contextlib.redirect_stderr(io.StringIO())):
                    response = module.run_request(request, connection)
                self.assertFalse(response["process_group_clear"])
                self.assertEqual([True, True], observed_unreaped)
                self.assertEqual([False, False], closed_states)
                self.assertEqual([True], reaped_at_unlock)
            finally:
                if descendant_pids.exists():
                    for pid in json.loads(descendant_pids.read_text()):
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                if spawned:
                    ProcessIdentityTests.clear(spawned[0])

    def test_capture_failure_clears_descendants_before_unlock(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            module, request = self._load(td)
            pid_file = td / "children.json"
            spawned = []
            at_unlock = []
            acquire = module.acquire_workspace_lock

            def spawn(*args):
                child = subprocess.Popen(
                    [sys.executable, "-c",
                     "import json,pathlib,subprocess,sys,time; "
                     "children=[subprocess.Popen([sys.executable,'-c',"
                     "'import time; time.sleep(30)']) for _ in range(2)]; "
                     "pathlib.Path(sys.argv[1]).write_text(json.dumps([p.pid for p in children])); "
                     "time.sleep(30)", str(pid_file)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                spawned.append(child)
                deadline = time.monotonic() + 5
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(.001)
                self.assertTrue(pid_file.exists())
                return child

            class ObservedLock:
                def __init__(self, handle):
                    self.handle = handle

                def close(self):
                    at_unlock.append((
                        [ProcessPersistenceFailureTests.alive(pid)
                         for pid in json.loads(pid_file.read_text())],
                        spawned[0].returncode is not None,
                        spawned[0].stdout.closed,
                        spawned[0].stderr.closed,
                    ))
                    self.handle.close()

            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            try:
                with (mock.patch.object(module, "resolve_provider_api_keys", return_value={}),
                      mock.patch.object(module, "start_omp_process", side_effect=spawn),
                      mock.patch.object(module._lifecycle, "capture_process_identity",
                                        side_effect=OSError("identity unavailable")),
                      mock.patch.object(module, "acquire_workspace_lock",
                                        side_effect=lambda workspace: ObservedLock(acquire(workspace))),
                      contextlib.redirect_stderr(io.StringIO())):
                    response = module.run_request(request, connection)
                self.assertIn("identity unavailable", response["stderr"])
                self.assertEqual([([False, False], True, True, True)], at_unlock)
            finally:
                if spawned:
                    self.stop_fixture(spawned[0], pid_file)

    def test_delayed_group_kill_keeps_lock_until_descendants_stop(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            module, request = self._load(td)
            request = dataclasses.replace(request, timeout=0.1)
            pid_file = td / "children.json"
            ready = td / "ready"
            spawned = []
            at_unlock = []
            pending_kills = []
            release = threading.Event()
            real_killpg = os.killpg
            acquire = module.acquire_workspace_lock

            def spawn(*args):
                child = subprocess.Popen(
                    [sys.executable, "-c",
                     "import json,pathlib,subprocess,sys,time\n"
                     "p=subprocess.Popen([sys.executable,'-c',"
                     "'import pathlib,signal,sys,time; "
                     "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                     "pathlib.Path(sys.argv[1]).touch(); time.sleep(30)',"
                     "sys.argv[2]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                     "ready=pathlib.Path(sys.argv[2])\n"
                     "while not ready.exists(): time.sleep(.001)\n"
                     "pathlib.Path(sys.argv[1]).write_text(json.dumps([p.pid]))\n"
                     "time.sleep(30)", str(pid_file), str(ready)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                spawned.append(child)
                deadline = time.monotonic() + 5
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(.001)
                self.assertTrue(pid_file.exists())
                return child

            def delayed_kill(group, signum):
                if spawned and group == spawned[0].pid and signum == signal.SIGKILL:
                    def send():
                        release.wait(.5)
                        try:
                            real_killpg(group, signum)
                        except ProcessLookupError:
                            pass
                    pending = threading.Thread(target=send, daemon=True)
                    pending_kills.append(pending)
                    pending.start()
                else:
                    real_killpg(group, signum)

            class ObservedLock:
                def __init__(self, handle):
                    self.handle = handle

                def close(self):
                    at_unlock.append((
                        [ProcessPersistenceFailureTests.alive(pid)
                         for pid in json.loads(pid_file.read_text())],
                        spawned[0].returncode is not None,
                    ))
                    self.handle.close()

            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            try:
                with (mock.patch.object(module, "resolve_provider_api_keys", return_value={}),
                      mock.patch.object(module, "start_omp_process", side_effect=spawn),
                      mock.patch.object(module.os, "killpg", side_effect=delayed_kill),
                      mock.patch.object(module, "acquire_workspace_lock",
                                        side_effect=lambda workspace: ObservedLock(acquire(workspace))),
                      contextlib.redirect_stderr(io.StringIO())):
                    response = module.run_request(request, connection)
                self.assertTrue(response["timed_out"])
                self.assertTrue(pending_kills)
                self.assertEqual([([False], True)], at_unlock)
            finally:
                release.set()
                for pending in pending_kills:
                    pending.join(timeout=2)
                if spawned:
                    self.stop_fixture(spawned[0], pid_file)

    def test_stdout_close_failure_still_closes_stderr_and_preserves_read_error(self):
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            spawned = []
            at_unlock = []
            read_patch = None
            acquire = module.acquire_workspace_lock

            class FailingClose:
                def __init__(self, stream):
                    self.stream = stream

                def fileno(self):
                    return self.stream.fileno()

                @property
                def closed(self):
                    return self.stream.closed

                def close(self):
                    if not self.stream.closed:
                        self.stream.close()
                        raise RuntimeError("stdout close failed")

            def spawn(*args):
                nonlocal read_patch
                child = subprocess.Popen(
                    [sys.executable, "-c",
                     "import sys,time; print('ready',flush=True); time.sleep(30)"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                child.stdout = FailingClose(child.stdout)
                spawned.append(child)
                read_patch = mock.patch.object(
                    module.os, "read", side_effect=OSError("pipe read failed"))
                read_patch.start()
                return child

            class ObservedLock:
                def __init__(self, handle):
                    self.handle = handle

                def close(self):
                    at_unlock.append((
                        spawned[0].returncode is not None,
                        spawned[0].stdout.closed,
                        spawned[0].stderr.closed,
                    ))
                    self.handle.close()

            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            try:
                with (mock.patch.object(module, "resolve_provider_api_keys", return_value={}),
                      mock.patch.object(module, "start_omp_process", side_effect=spawn),
                      mock.patch.object(module, "acquire_workspace_lock",
                                        side_effect=lambda workspace: ObservedLock(acquire(workspace))),
                      contextlib.redirect_stderr(io.StringIO())):
                    response = module.run_request(request, connection)
                self.assertIn("pipe read failed", response["stderr"])
                self.assertNotIn("stdout close failed", response["stderr"])
                self.assertEqual([(True, True, True)], at_unlock)
            finally:
                if read_patch is not None:
                    read_patch.stop()
                if spawned:
                    ProcessIdentityTests.clear(spawned[0])
                    with contextlib.suppress(RuntimeError):
                        spawned[0].stdout.close()
                    spawned[0].stderr.close()

    def test_watcher_exits_before_reap_and_unlock_after_fault(self):
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            spawned = []
            watchers = []
            at_exit = []
            at_unlock = []
            started = threading.Event()
            release = threading.Event()
            timer = None
            acquire = module.acquire_workspace_lock

            def spawn(*args):
                child = subprocess.Popen(
                    [sys.executable, "-c", "import sys; print('ready',flush=True)"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                spawned.append(child)
                return child

            def watch(*_args):
                watchers.append(threading.current_thread())
                started.set()
                release.wait(5)
                at_exit.append(spawned[0].returncode is None)

            def select_fault(_selector, _timeout=None):
                nonlocal timer
                self.assertTrue(started.wait(2))
                ProcessIdentityTests.observe_exit(spawned[0])
                timer = threading.Timer(3.4, release.set)
                timer.start()
                raise OSError("selector fault")

            class ObservedLock:
                def __init__(self, handle):
                    self.handle = handle

                def close(self):
                    at_unlock.append((
                        watchers[0].is_alive(),
                        spawned[0].returncode is not None,
                        spawned[0].stdout.closed,
                        spawned[0].stderr.closed,
                    ))
                    self.handle.close()

            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            try:
                with (mock.patch.object(module, "resolve_provider_api_keys", return_value={}),
                      mock.patch.object(module, "start_omp_process", side_effect=spawn),
                      mock.patch.object(module, "_watch_client_lifetime", side_effect=watch),
                      mock.patch.object(module.selectors.EpollSelector, "select", select_fault),
                      mock.patch.object(module, "FRAME_TIMEOUT", .01),
                      mock.patch.object(module, "acquire_workspace_lock",
                                        side_effect=lambda workspace: ObservedLock(acquire(workspace))),
                      contextlib.redirect_stderr(io.StringIO())):
                    response = module.run_request(request, connection)
                self.assertIn("selector fault", response["stderr"])
                self.assertEqual([True], at_exit)
                self.assertEqual([(False, True, True, True)], at_unlock)
            finally:
                release.set()
                if timer is not None:
                    timer.cancel()
                    timer.join(timeout=2)
                for watcher in watchers:
                    watcher.join(timeout=2)
                if spawned:
                    ProcessIdentityTests.clear(spawned[0])
                    spawned[0].stdout.close()
                    spawned[0].stderr.close()

    def test_stale_birth_cannot_signal_live_group(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            module, request = self._load(td)
            descendant_pid = td / "descendant.pid"
            spawned = []
            closed_states = []
            acquire = module.acquire_workspace_lock
            capture = module._lifecycle.capture_process_identity
            unrelated = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                start_new_session=True)
            self.addCleanup(ProcessIdentityTests.clear, unrelated)

            def spawn(*args):
                child = subprocess.Popen(
                    [sys.executable, "-c",
                     "import pathlib,subprocess,sys,time; "
                     "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                     "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(.2)",
                     str(descendant_pid)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                spawned.append(child)
                deadline = time.monotonic() + 5
                while not descendant_pid.exists() and time.monotonic() < deadline:
                    time.sleep(.001)
                self.assertTrue(descendant_pid.exists())
                return child

            class ObservedLock:
                def __init__(self, handle):
                    self.handle = handle

                def close(self):
                    closed_states.append((
                        ProcessPersistenceFailureTests.alive(int(descendant_pid.read_text())),
                        unrelated.poll() is None,
                        spawned[0].returncode is not None,
                    ))
                    self.handle.close()

            def stale(_pid):
                identity = capture(unrelated.pid)
                return {**identity, "start_ticks": identity["start_ticks"] + 1_000_000}

            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            try:
                with (mock.patch.object(module, "resolve_provider_api_keys", return_value={}),
                      mock.patch.object(module, "start_omp_process", side_effect=spawn),
                      mock.patch.object(module._lifecycle, "capture_process_identity",
                                        side_effect=stale),
                      mock.patch.object(module.threading.Thread, "start",
                                        side_effect=RuntimeError("watcher start failed")),
                      mock.patch.object(module, "acquire_workspace_lock",
                                        side_effect=lambda workspace: ObservedLock(acquire(workspace))),
                      contextlib.redirect_stderr(io.StringIO())):
                    response = module.run_request(request, connection)
                self.assertIn("watcher start failed", response["stderr"])
                self.assertEqual([(False, True, True)], closed_states)
                self.assertIsNone(unrelated.poll())
            finally:
                if descendant_pid.exists():
                    try:
                        os.kill(int(descendant_pid.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if spawned:
                    ProcessIdentityTests.clear(spawned[0])

    def test_exit_after_empty_select_retains_final_output(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            module, request = self._load(td)
            release = td / "release"
            spawned = []
            select = module.selectors.EpollSelector.select

            def spawn(_request, final_path, _keys):
                child = subprocess.Popen(
                    [sys.executable, "-c",
                     "import json,pathlib,sys,time\n"
                     "p=pathlib.Path(sys.argv[1])\n"
                     "while not p.exists(): time.sleep(.001)\n"
                     "sys.stdout.write('last stdout'); sys.stdout.flush()\n"
                     "sys.stderr.write('last stderr'); sys.stderr.flush()\n"
                     "pathlib.Path(sys.argv[2]).write_text(json.dumps("
                     "{'summary':'done','verification':[],'gaps':[],'verdict':'MET'}))",
                     str(release), str(final_path)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                spawned.append(child)
                self.addCleanup(ProcessIdentityTests.clear, child)
                return child

            first = True

            def after_select(selector, timeout=None):
                nonlocal first
                if first:
                    first = False
                    release.touch()
                    ProcessIdentityTests.observe_exit(spawned[0])
                    return []
                return select(selector, timeout)

            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            with (mock.patch.object(module, "resolve_provider_api_keys", return_value={}),
                  mock.patch.object(module, "start_omp_process", side_effect=spawn),
                  mock.patch.object(module.selectors.EpollSelector, "select", after_select)):
                response = module.run_request(request, connection)
            self.assertEqual("last stdout", response["stdout"])
            self.assertEqual("last stderr", response["stderr"])
            self.assertEqual("completed", module.JOB_STORE.get(request.request_id)["status"])

    def test_timeout_then_capture_limit_retains_timeout_outcome(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            module, request = self._load(td)
            request = dataclasses.replace(request, timeout=0.1)
            spawned = []

            def spawn(*args):
                child = subprocess.Popen(
                    [sys.executable, "-c",
                     "import signal,sys,time\n"
                     "def done(*_):\n"
                     " sys.stdout.buffer.write(b'a'*600000); sys.stdout.buffer.flush()\n"
                     " sys.stderr.buffer.write(b'b'*600000); sys.stderr.buffer.flush()\n"
                     " sys.exit(0)\n"
                     "signal.signal(signal.SIGTERM,done)\n"
                     "sys.stdout.buffer.write(b'R'); sys.stdout.buffer.flush()\n"
                     "time.sleep(30)"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                spawned.append(child)
                self.assertEqual(b"R", child.stdout.read(1))
                self.addCleanup(ProcessIdentityTests.clear, child)
                return child

            sent_term = False

            def terminate(pid):
                nonlocal sent_term
                signum = signal.SIGKILL if sent_term else signal.SIGTERM
                sent_term = True
                try:
                    os.killpg(pid, signum)
                except ProcessLookupError:
                    pass

            parent, connection = socket.socketpair()
            self.addCleanup(parent.close)
            self.addCleanup(connection.close)
            with (mock.patch.object(module, "resolve_provider_api_keys", return_value={}),
                  mock.patch.object(module, "start_omp_process", side_effect=spawn),
                  mock.patch.object(module, "_kill_process_group", side_effect=terminate)):
                response = module.run_request(request, connection)
            self.assertTrue(response["timed_out"])
            self.assertEqual("", response["stdout"])
            self.assertEqual(
                "omp-delegate-broker: OMP output exceeds capture limit\n",
                response["stderr"])
            record = module.JOB_STORE.get(request.request_id)
            self.assertEqual("timed_out", record["status"])
            self.assertTrue(record["result"]["timed_out"])
            self.assertIn("timeout", self._audit_outcomes(td))

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
