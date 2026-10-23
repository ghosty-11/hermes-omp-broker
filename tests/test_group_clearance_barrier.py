from __future__ import annotations

import contextlib
import fcntl
import io
import json
import os
import select
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

import test_job_process_identity as identity_tests
from test_run_request_resilience import ResilienceHarness


# The leader exits on SIGTERM; its separate group member does not. A direct
# child remains unreaped while the broker decides whether the group is clear.
_LEADER = """
import os, subprocess, sys, time
ack_read, ack_write = os.pipe()
member = subprocess.Popen([sys.executable, '-c',
    'import os,signal,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
    'os.write(int(sys.argv[1]), b\"R\"); time.sleep(60)',
    str(ack_write)], pass_fds=(ack_write,),
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.close(ack_write)
if os.read(ack_read, 1) != b'R':
    os._exit(2)
os.close(ack_read)
os.write(int(sys.argv[1]), str(member.pid).encode() + b'\\n')
os.close(int(sys.argv[1]))
time.sleep(60)
"""

# On a command from the test, the group member forks, reports the grandchild,
# and exits. The grandchild closes the report pipe before sleeping, so EOF
# proves the entry being read belongs to an exited member.
_FORKING_LEADER = """
import os, subprocess, sys, time
member_code = '''
import os, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
command, report = map(int, sys.argv[1:])
os.write(report, b'R')
if os.read(command, 1) == b'F':
    pid = os.fork()
    if pid == 0:
        os.close(report)
        os.close(command)
        time.sleep(60)
        os._exit(0)
    os.write(report, str(pid).encode() + b'\\\\n')
os._exit(0)
'''
member = subprocess.Popen([sys.executable, '-c', member_code,
    sys.argv[2], sys.argv[3]], pass_fds=(int(sys.argv[2]), int(sys.argv[3])),
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.write(int(sys.argv[1]), str(member.pid).encode() + b'\\n')
os.close(int(sys.argv[1]))
time.sleep(60)
"""

_BAD_COMM = """
import ctypes, os, sys, time
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(15, ctypes.c_char_p(b'\\xffbad-comm'), 0, 0, 0):
    os._exit(2)
os.write(int(sys.argv[1]), b'R')
time.sleep(60)
"""


class GroupClearanceBarrierTests(ResilienceHarness):
    @staticmethod
    def _message(fd: int) -> bytes:
        readable, _, _ = select.select([fd], [], [], 5)
        if not readable:
            raise AssertionError('fixture did not acknowledge its command')
        return os.read(fd, 64)

    def _worker(self, script: str, *fds: int) -> subprocess.Popen:
        worker = subprocess.Popen(
            [sys.executable, '-c', script, *(str(fd) for fd in fds)],
            pass_fds=fds, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        self.addCleanup(self._stop_worker, worker)
        return worker

    @staticmethod
    def _stop_worker(worker: subprocess.Popen) -> None:
        try:
            os.killpg(worker.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        worker.wait(timeout=5)
        for stream in (worker.stdout, worker.stderr):
            if stream is not None:
                stream.close()

    @staticmethod
    def _locked(path: Path) -> bool:
        with path.open('a+') as contender:
            try:
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(contender, fcntl.LOCK_UN)
            return False

    def _observed_lock(self, module, request, snapshot, before_close=None):
        acquire = module.acquire_workspace_lock
        test = self

        class ObservedLock:
            def __init__(self, handle):
                self.handle = handle

            def close(self):
                if before_close is not None:
                    before_close()
                snapshot.append({
                    'locked': test._locked(module._lock_path(request.workspace)),
                    'worker_reaped': test.worker.returncode is not None,
                    'stdout_closed': test.worker.stdout.closed,
                    'stderr_closed': test.worker.stderr.closed,
                    'members_running': [identity_tests.ProcessPersistenceFailureTests.alive(pid)
                                        for pid in test.members],
                    'watcher_alive': any(t.is_alive() for t in test.watchers),
                })
                self.handle.close()

        return mock.patch.object(module, 'acquire_workspace_lock',
                                 side_effect=lambda workspace: ObservedLock(acquire(workspace)))

    def _run_fault(self, module, request):
        parent, connection = socket.socketpair()
        self.addCleanup(parent.close)
        self.addCleanup(connection.close)
        self.watchers = []
        real_watch = module._watch_client_lifetime

        def watch(*args):
            self.watchers.append(threading.current_thread())
            return real_watch(*args)

        with (mock.patch.object(module, 'resolve_provider_api_keys', return_value={}),
              mock.patch.object(module, 'start_omp_process', return_value=self.worker),
              mock.patch.object(module, '_watch_client_lifetime', side_effect=watch),
              mock.patch.object(module._lifecycle, 'terminate_process_tree', return_value=False),
              mock.patch.object(module.selectors.EpollSelector, 'select',
                                side_effect=OSError('execution read failed')),
              contextlib.redirect_stderr(io.StringIO())):
            return module.run_request(request, connection)

    def test_unrelated_non_utf8_comm_does_not_release_running_descendant(self):
        if sys.platform != 'linux':
            self.skipTest('requires Linux /proc and prctl')
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            ready_read, ready_write = os.pipe()
            try:
                unrelated = subprocess.Popen(
                    [sys.executable, '-c', _BAD_COMM, str(ready_write)],
                    pass_fds=(ready_write,), start_new_session=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.addCleanup(identity_tests.ProcessIdentityTests.clear, unrelated)
                os.close(ready_write)
                ready_write = -1
                self.assertEqual(b'R', self._message(ready_read))
                self.assertIn(b'\xffbad-comm',
                              Path(f'/proc/{unrelated.pid}/stat').read_bytes())
            finally:
                os.close(ready_read)
                if ready_write != -1:
                    os.close(ready_write)
            report_read, report_write = os.pipe()
            try:
                self.worker = self._worker(_LEADER, report_write, report_write)
                os.close(report_write)
                report_write = -1
                self.members = [int(self._message(report_read))]
            finally:
                os.close(report_read)
                if report_write != -1:
                    os.close(report_write)
            self.addCleanup(self._kill_members)
            at_unlock = []
            with self._observed_lock(module, request, at_unlock):
                response = self._run_fault(module, request)
            self.assertIn('execution read failed', response['stderr'])
            self.assertEqual([False], at_unlock[0]['members_running'])
            self.assertTrue(at_unlock[0]['locked'])
            self.assertFalse(at_unlock[0]['watcher_alive'])
            self.assertTrue(at_unlock[0]['stdout_closed'])
            self.assertTrue(at_unlock[0]['stderr_closed'])
            self.assertFalse(self._locked(module._lock_path(request.workspace)))
            self.assertIsNone(unrelated.poll())

    def _kill_members(self):
        for pid in self.members:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_transient_stat_failure_preserves_error_and_independent_cleanup(self):
        if sys.platform != 'linux':
            self.skipTest('requires Linux /proc')
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            report_read, report_write = os.pipe()
            try:
                self.worker = self._worker(_LEADER, report_write, report_write)
                os.close(report_write)
                report_write = -1
                self.members = [int(self._message(report_read))]
            finally:
                os.close(report_read)
                if report_write != -1:
                    os.close(report_write)
            self.addCleanup(self._kill_members)
            original_open = Path.open
            original_killpg = os.killpg
            term_sent = False
            injected = []
            observing = True

            def signal_group(pgid, sig):
                nonlocal term_sent
                result = original_killpg(pgid, sig)
                if pgid == self.worker.pid and sig == signal.SIGTERM:
                    term_sent = True
                    os.waitid(os.P_PID, pgid, os.WEXITED | os.WNOWAIT)
                return result

            def stat_open(path, *args, **kwargs):
                if (not injected and observing and term_sent and
                        str(path) == f'/proc/{self.members[0]}/stat'):
                    injected.append({
                        'stdout_closed': self.worker.stdout.closed,
                        'stderr_closed': self.worker.stderr.closed,
                        'watcher_stopped': not any(t.is_alive() for t in self.watchers),
                        'workspace_locked': self._locked(module._lock_path(request.workspace)),
                    })
                    raise PermissionError('transient stat unreadable')
                return original_open(path, *args, **kwargs)

            def stop_observing():
                nonlocal observing
                observing = False

            at_unlock = []
            with (self._observed_lock(module, request, at_unlock, stop_observing),
                  mock.patch.object(module.os, 'killpg', side_effect=signal_group),
                  mock.patch.object(Path, 'open', stat_open)):
                response = self._run_fault(module, request)
            self.assertTrue(injected, 'the group stat was not observed after SIGTERM')
            self.assertTrue(all(injected[0].values()), injected)
            self.assertIn('execution read failed', response['stderr'])
            self.assertNotIn('transient stat unreadable', response['stderr'])
            self.assertEqual('failed', module.JOB_STORE.get(request.request_id)['status'])
            self.assertEqual([False], at_unlock[0]['members_running'])
            self.assertTrue(at_unlock[0]['locked'])
            self.assertFalse(at_unlock[0]['watcher_alive'])
            self.assertTrue(at_unlock[0]['stdout_closed'])
            self.assertTrue(at_unlock[0]['stderr_closed'])
            self.assertFalse(self._locked(module._lock_path(request.workspace)))

    def test_zombie_descendant_leader_does_not_hide_a_live_thread_at_unlock(self):
        if sys.platform != 'linux':
            self.skipTest('requires Linux pthread_exit and /proc')
        member_code = (
            "import ctypes,json,os,signal,sys,threading,time\n"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "def run():\n"
            " os.write(int(sys.argv[1]),json.dumps({'pid':os.getpid(),"
            "'tid':threading.get_native_id()}).encode())\n"
            " while True: time.sleep(.1)\n"
            "threading.Thread(target=run).start()\n"
            "ctypes.CDLL(None).pthread_exit(None)\n"
        )
        leader_code = (
            "import subprocess,sys,time\n"
            f"subprocess.Popen([sys.executable,'-c',{member_code!r},sys.argv[1]],"
            "pass_fds=(int(sys.argv[1]),),stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL)\n"
            "time.sleep(60)\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            report_read, report_write = os.pipe()
            try:
                self.worker = self._worker(leader_code, report_write)
                ids = json.loads(self._message(report_read))
            finally:
                os.close(report_read)
                os.close(report_write)
            self.members = [ids['pid']]
            self.addCleanup(self._kill_members)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                leader_state = Path(f"/proc/{ids['pid']}/stat").read_bytes().rsplit(b')', 1)[1].split()[0]
                if leader_state == b'Z':
                    break
                time.sleep(.001)
            self.assertEqual(leader_state, b'Z')

            def thread_alive():
                try:
                    state = Path(f"/proc/{ids['tid']}/stat").read_bytes().rsplit(b')', 1)[1].split()[0]
                except FileNotFoundError:
                    return False
                return state not in {b'Z', b'X'}

            self.assertTrue(thread_alive())
            real_killpg = os.killpg
            real_census = module._running_process_group_exists
            release = threading.Event()
            kill_requested = threading.Event()
            observed = threading.Event()
            pending = []
            census_states = []
            at_unlock = []
            thread_at_unlock = []
            responses = []
            errors = []

            def signal_group(pgid, sig):
                if pgid == self.worker.pid and sig == signal.SIGKILL:
                    if not kill_requested.is_set():
                        kill_requested.set()
                        def deliver():
                            release.wait()
                            try:
                                real_killpg(pgid, sig)
                            except ProcessLookupError:
                                pass
                        task = threading.Thread(target=deliver)
                        pending.append(task)
                        task.start()
                    return
                return real_killpg(pgid, sig)

            def census(pgid):
                running = real_census(pgid)
                if kill_requested.is_set() and not observed.is_set():
                    census_states.append((running, thread_alive()))
                    observed.set()
                return running

            def request_thread():
                try:
                    responses.append(self._run_fault(module, request))
                except BaseException as exc:
                    errors.append(exc)

            task = threading.Thread(target=request_thread)
            try:
                with (self._observed_lock(module, request, at_unlock,
                                         lambda: thread_at_unlock.append(thread_alive())),
                      mock.patch.object(module.os, 'killpg', side_effect=signal_group),
                      mock.patch.object(module, '_running_process_group_exists', side_effect=census)):
                    task.start()
                    self.assertTrue(observed.wait(5))
                    try:
                        self.assertEqual(census_states, [(True, True)])
                        self.assertTrue(self._locked(module._lock_path(request.workspace)))
                    finally:
                        release.set()
                        task.join(timeout=5)
                self.assertFalse(task.is_alive())
                self.assertEqual(errors, [])
                self.assertIn('execution read failed', responses[0]['stderr'])
                self.assertEqual(thread_at_unlock, [False])
            finally:
                release.set()
                task.join(timeout=5)
                for pending_task in pending:
                    pending_task.join(timeout=5)

    def test_fork_during_grace_census_cannot_escape_sigkill_barrier(self):
        if sys.platform != 'linux':
            self.skipTest('requires Linux /proc and fork')
        with tempfile.TemporaryDirectory() as raw:
            module, request = self._load(Path(raw))
            ready_read, ready_write = os.pipe()
            command_read, command_write = os.pipe()
            report_read, report_write = os.pipe()
            try:
                self.worker = self._worker(_FORKING_LEADER, ready_write,
                                           command_read, report_write)
                for fd in (ready_write, command_read, report_write):
                    os.close(fd)
                ready_write = command_read = report_write = -1
                member = int(self._message(ready_read))
                self.assertEqual(b'R', self._message(report_read))
                self.members = [member]
            finally:
                for fd in (ready_read, ready_write, command_read, report_write):
                    if fd != -1:
                        os.close(fd)
            self.addCleanup(self._kill_members)
            original_iterdir = Path.iterdir
            original_killpg = os.killpg
            term_sent = False
            killed = []
            forked = []

            def signal_group(pgid, sig):
                nonlocal term_sent
                if pgid == self.worker.pid and sig == signal.SIGKILL:
                    killed.append(True)
                result = original_killpg(pgid, sig)
                if pgid == self.worker.pid and sig == signal.SIGTERM:
                    term_sent = True
                    os.waitid(os.P_PID, pgid, os.WEXITED | os.WNOWAIT)
                return result

            def census(path):
                entries = original_iterdir(path)
                if str(path) != '/proc' or not term_sent or killed or forked:
                    return entries
                # Snapshot first. The new child cannot appear in this iterator.
                captured = list(entries)

                def during_snapshot():
                    for entry in captured:
                        if entry.name == str(member):
                            os.write(command_write, b'F')
                            pid = int(self._message(report_read))
                            self.members.append(pid)
                            # EOF follows the member's exit; the grandchild
                            # closed its copy of the reporting descriptor.
                            self.assertEqual(b'', self._message(report_read))
                            forked.append(pid)
                        yield entry

                return during_snapshot()

            at_unlock = []
            kill_at_unlock = []
            try:
                with (self._observed_lock(
                          module, request, at_unlock,
                          lambda: kill_at_unlock.append(bool(killed))),
                      mock.patch.object(module.os, 'killpg', side_effect=signal_group),
                      mock.patch.object(Path, 'iterdir', census)):
                    response = self._run_fault(module, request)
                self.assertIn('execution read failed', response['stderr'])
                self.assertTrue(killed, 'SIGKILL must precede clearance')
                self.assertEqual([True], kill_at_unlock)
                self.assertTrue(at_unlock[0]['locked'])
                self.assertEqual([False] * len(self.members),
                                 at_unlock[0]['members_running'])
                self.assertFalse(at_unlock[0]['watcher_alive'])
                self.assertFalse(self._locked(module._lock_path(request.workspace)))
            finally:
                os.close(command_write)
                os.close(report_read)


if __name__ == '__main__':
    unittest.main()
