from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from broker.lifecycle import JobStore, LeaseStore, TOMBSTONE_RETIREMENT_AGE


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = JobStore(Path(self.temp.name))

    def child(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
            stdin=subprocess.PIPE, start_new_session=True)
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdin.close()
        self.addCleanup(cleanup)
        return process

    def test_prelaunch_record_survives_and_completed_result_is_retrievable(self) -> None:
        self.store.create("req-1", task_id="task-1", repository="repo", caller="caller")
        self.assertEqual("pending", self.store.get("req-1")["status"])
        self.store.running("req-1", process_group=self.child().pid)
        response = {"version": 1, "request_id": "req-1", "final": {"verdict": "MET"}}
        self.store.finish("req-1", "completed", response)
        record = self.store.get("req-1")
        self.assertEqual("completed", record["status"])
        self.assertEqual(response, record["result"])

    def test_recovery_classifies_pending_and_running_jobs_as_orphaned(self) -> None:
        self.store.create("pending", task_id="task", repository="repo", caller="caller")
        self.store.create("running", task_id="task", repository="repo", caller="caller")
        self.store.running("running", process_group=self.child().pid)
        self.store.recover_orphans()
        self.assertEqual("orphaned", self.store.get("pending")["status"])
        self.assertEqual("orphaned", self.store.get("running")["status"])

    def test_cancel_kills_recorded_group_and_records_cancelled(self) -> None:
        self.store.create("req", task_id="task", repository="repo", caller="caller")
        child = self.child()
        self.store.running("req", process_group=child.pid)
        self.assertTrue(self.store.cancel("req"))
        self.assertIn(child.wait(timeout=5), (-signal.SIGTERM, -signal.SIGKILL))
        self.assertEqual("cancelled", self.store.get("req")["status"])

    def test_delivery_failure_preserves_result_for_retrieval(self) -> None:
        self.store.create("req", task_id="task", repository="repo", caller="caller")
        response = {"request_id": "req", "final": {"verdict": "MET"}}
        self.store.finish("req", "completed", response)
        self.store.delivery_failed("req")
        record = self.store.get("req")
        self.assertEqual("delivery_failed", record["status"])
        self.assertEqual(response, record["result"])

    def test_arm_reexecution_rearms_an_orphaned_result_less_record_once(self) -> None:
        self.store.create("req", task_id="task-1", repository="repo", caller="caller")
        self.store.recover_orphans()
        self.assertEqual("orphaned", self.store.get("req")["status"])
        self.store.arm_reexecution(
            "req", task_id="task-1", repository="repo", caller="caller")
        record = self.store.get("req")
        self.assertTrue(record["reexecuted"])
        self.assertEqual("pending", record["status"])
        self.assertIsNone(record["result"])

    def test_arm_reexecution_refuses_spent_answered_and_foreign_records(self) -> None:
        self.store.create("req", task_id="task-1", repository="repo", caller="caller")
        self.store.arm_reexecution(
            "req", task_id="task-1", repository="repo", caller="caller")
        with self.assertRaises(ValueError):
            self.store.arm_reexecution(
                "req", task_id="task-1", repository="repo", caller="caller")
        self.store.finish("req", "completed", {"request_id": "req"})
        with self.assertRaises(ValueError):
            self.store.arm_reexecution(
                "req", task_id="task-1", repository="repo", caller="caller")
        self.store.create("other", task_id="task-2", repository="repo", caller="caller")
        with self.assertRaises(ValueError):
            self.store.arm_reexecution(
                "other", task_id="task-9", repository="repo", caller="caller")
        with self.assertRaises(OSError):
            self.store.arm_reexecution(
                "missing", task_id="task-2", repository="repo", caller="caller")
    def test_reexecution_mark_survives_new_store_instance(self) -> None:
        self.store.create("req", task_id="task", repository="repo", caller="caller")
        self.store.recover_orphans()
        self.store.arm_reexecution(
            "req", task_id="task", repository="repo", caller="caller")
        restarted = JobStore(Path(self.temp.name))
        with self.assertRaises(ValueError):
            restarted.arm_reexecution(
                "req", task_id="task", repository="repo", caller="caller")
        self.assertTrue(restarted.get("req")["reexecuted"])

    def test_reexecution_rejects_live_failed_and_missing_records(self) -> None:
        self.store.create("live", task_id="task", repository="repo", caller="caller")
        self.store.running("live", process_group=self.child().pid)
        self.store.create("failed", task_id="task", repository="repo", caller="caller")
        self.store.finish("failed", "failed", {})
        for request_id in ("live", "failed"):
            with self.subTest(request_id=request_id):
                with self.assertRaises(ValueError):
                    self.store.arm_reexecution(
                        request_id, task_id="task", repository="repo", caller="caller")
        with self.assertRaises(OSError):
            self.store.arm_reexecution(
                "missing", task_id="task", repository="repo", caller="caller")

    def test_arm_reexecution_allows_client_disconnect_cancellation_only(self) -> None:
        self.store.create("cancelled", task_id="task", repository="repo", caller="caller")
        cancellation = {"request_id": "cancelled", "timed_out": False, "final": None}
        self.store.finish("cancelled", "cancelled", cancellation)
        self.store.arm_reexecution(
            "cancelled", task_id="task", repository="repo", caller="caller")
        record = self.store.get("cancelled")
        self.assertEqual("pending", record["status"])
        self.assertTrue(record["reexecuted"])
        self.assertIsNone(record["result"])

    def test_arm_reexecution_refuses_a_cancellation_that_carries_a_final(self) -> None:
        """The broker ranks `cancelled` above `completed` on a hang-up, so a
        record can be cancelled *after* the child wrote a final; re-running it
        would discard the only durable copy of a successful outcome."""
        self.store.create("late", task_id="task", repository="repo", caller="caller")
        self.store.finish(
            "late", "cancelled",
            {"request_id": "late", "timed_out": False, "final": {"verdict": "MET"}})
        with self.assertRaises(ValueError):
            self.store.arm_reexecution(
                "late", task_id="task", repository="repo", caller="caller")

    def test_arm_reexecution_refuses_completed_running_and_reexecuted_records(self) -> None:
        self.store.create("completed", task_id="task", repository="repo", caller="caller")
        self.store.finish("completed", "completed", {"request_id": "completed"})
        self.store.create("running", task_id="task", repository="repo", caller="caller")
        self.store.running("running", process_group=self.child().pid)
        self.store.create("reexecuted", task_id="task", repository="repo", caller="caller")
        self.store.arm_reexecution(
            "reexecuted", task_id="task", repository="repo", caller="caller")
        for request_id in ("completed", "running", "reexecuted"):
            with self.subTest(request_id=request_id):
                with self.assertRaises(ValueError):
                    self.store.arm_reexecution(
                        request_id, task_id="task", repository="repo", caller="caller")

    def test_uncertain_launch_and_recovered_running_work_never_replay(self) -> None:
        for request_id in ("launching", "running"):
            with self.subTest(request_id=request_id):
                self.store.create(request_id, task_id="task", repository="repo", caller="caller")
                self.store.launching(request_id)
                if request_id == "running":
                    self.store.running(request_id, process_group=self.child().pid)
                self.store.recover_orphans()
                with self.assertRaises(ValueError):
                    self.store.arm_reexecution(
                        request_id, task_id="task", repository="repo", caller="caller")



class LeaseRetirementTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "issued").mkdir(mode=0o750)
        (self.root / "consumed").mkdir(mode=0o700)
        lock_fd = os.open(
            self.root / ".lease-store.lock", os.O_RDWR | os.O_CREAT, 0o660)
        os.fchmod(lock_fd, 0o660)
        os.close(lock_fd)
        self.store = LeaseStore(
            self.root,
            issuer_uid=os.geteuid(),
            issuer_gid=os.getegid(),
            broker_uid=os.geteuid(),
            broker_gid=os.getegid(),
        )

    def _issue(self, *, request_id: str = "request-1", task_id: str = "task-1",
               expires_at: int | None = None) -> str:
        return self.store.issue(
            fixed_request={
                "request_id": request_id,
                "task_id": task_id,
                "repository": "repo",
                "caller": "audit",
                "workspace": str(self.root / "workspace"),
                "sandbox": "restricted-write",
                "model": "provider/fixed",
                "prompt": "fixed prompt",
                "timeout": 30,
            },
            endpoint="audit",
            peer_uid=997,
            artifact_digest="sha256:artifact",
            policy_version="policy-v1",
            template_version="template-v1",
            expires_at=expires_at or int(time.time()) + 3600,
        )

    def _backdate_tombstone(self, lease_id: str, *, seconds: int) -> None:
        path = self.store._consumed_path(lease_id)
        tombstone = json.loads(path.read_text())
        tombstone["consumed_at"] -= seconds
        tombstone["record_digest"] = self.store._tombstone_digest(tombstone)
        path.write_text(
            json.dumps(tombstone, sort_keys=True, separators=(",", ":")) + "\n")

    def _rewrite_issued(self, lease_id: str, **changes) -> None:
        path = self.store._path(lease_id)
        record = json.loads(path.read_text())
        record.update(changes)
        record["record_digest"] = self.store._record_digest(record)
        path.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    def test_tombstone_past_retirement_age_frees_the_identity_for_reissue(self) -> None:
        lease_id = self._issue()
        self.store.consume(lease_id, endpoint="audit", peer_uid=997)
        self._backdate_tombstone(lease_id, seconds=TOMBSTONE_RETIREMENT_AGE + 1)
        self.assertEqual(1, self.store.retire_consumed())
        reissued = self._issue()
        self.assertNotEqual(lease_id, reissued)
        self.assertFalse(self.store._path(lease_id).exists())
        # The tombstone is the durable proof of consumption; only the issued
        # record leaves issue()'s scan.
        self.assertTrue(self.store._consumed_path(lease_id).exists())
        self.assertEqual(1, len(list(self.store.issued.glob("*.json"))))

    def test_recent_tombstone_keeps_the_record_and_the_refusal(self) -> None:
        lease_id = self._issue()
        self.store.consume(lease_id, endpoint="audit", peer_uid=997)
        self.store.retire_consumed()
        with self.assertRaises(ValueError) as raised:
            self._issue()
        self.assertEqual(
            "task or request already has a lease", str(raised.exception))
        self.assertTrue(self.store._path(lease_id).exists())

    def test_unconsumed_identity_is_never_retired_even_when_dead(self) -> None:
        lease_id = self._issue(expires_at=int(time.time()) + 60)
        self._rewrite_issued(
            lease_id,
            issued_at=int(time.time()) - 10 * TOMBSTONE_RETIREMENT_AGE,
            expires_at=int(time.time()) - 1,
        )
        self.store.retire_consumed()
        with self.assertRaises(ValueError) as raised:
            self._issue()
        self.assertEqual(
            "task or request already has a lease", str(raised.exception))
        self.assertTrue(self.store._path(lease_id).exists())

    def test_a_tombstone_that_fails_validation_proves_nothing(self) -> None:
        lease_id = self._issue()
        self.store.consume(lease_id, endpoint="audit", peer_uid=997)
        self._backdate_tombstone(lease_id, seconds=TOMBSTONE_RETIREMENT_AGE + 1)
        self.store._consumed_path(lease_id).write_text("{}\n")
        self.store.retire_consumed()
        with self.assertRaises(ValueError) as raised:
            self._issue()
        self.assertEqual(
            "task or request already has a lease", str(raised.exception))
        self.assertTrue(self.store._path(lease_id).exists())
    def test_protected_request_id_survives_proven_consumed_retirement(self) -> None:
        lease_id = self._issue(request_id="request-1")
        protected_id = self._issue(request_id="request-2", task_id="task-2")
        self.store.consume(lease_id, endpoint="audit", peer_uid=997)
        self.store.consume(protected_id, endpoint="audit", peer_uid=997)
        self._backdate_tombstone(lease_id, seconds=TOMBSTONE_RETIREMENT_AGE + 1)
        self._backdate_tombstone(protected_id, seconds=TOMBSTONE_RETIREMENT_AGE + 1)
        self.assertEqual(
            1, self.store.retire_consumed(protected_request_ids=("request-2",)))
        self.assertFalse(self.store._path(lease_id).exists())
        self.assertTrue(self.store._path(protected_id).exists())


if __name__ == "__main__":
    unittest.main()
