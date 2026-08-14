from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from broker.lifecycle import JobStore


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = JobStore(Path(self.temp.name))

    def test_prelaunch_record_survives_and_completed_result_is_retrievable(self) -> None:
        self.store.create("req-1", task_id="task-1", repository="repo", caller="caller")
        self.assertEqual("pending", self.store.get("req-1")["status"])
        self.store.running("req-1", process_group=123)
        response = {"version": 1, "request_id": "req-1", "final": {"verdict": "MET"}}
        self.store.finish("req-1", "completed", response)
        record = self.store.get("req-1")
        self.assertEqual("completed", record["status"])
        self.assertEqual(response, record["result"])

    def test_recovery_classifies_pending_and_running_jobs_as_orphaned(self) -> None:
        self.store.create("pending", task_id="task", repository="repo", caller="caller")
        self.store.create("running", task_id="task", repository="repo", caller="caller")
        self.store.running("running", process_group=456)
        self.store.recover_orphans()
        self.assertEqual("orphaned", self.store.get("pending")["status"])
        self.assertEqual("orphaned", self.store.get("running")["status"])

    def test_cancel_kills_recorded_group_and_records_cancelled(self) -> None:
        self.store.create("req", task_id="task", repository="repo", caller="caller")
        self.store.running("req", process_group=789)
        with mock.patch("broker.lifecycle.os.killpg") as kill:
            self.assertTrue(self.store.cancel("req"))
        kill.assert_called_once_with(789, 15)
        self.assertEqual("cancelled", self.store.get("req")["status"])

    def test_delivery_failure_preserves_result_for_retrieval(self) -> None:
        self.store.create("req", task_id="task", repository="repo", caller="caller")
        response = {"request_id": "req", "final": {"verdict": "MET"}}
        self.store.finish("req", "completed", response)
        self.store.delivery_failed("req")
        record = self.store.get("req")
        self.assertEqual("delivery_failed", record["status"])
        self.assertEqual(response, record["result"])


if __name__ == "__main__":
    unittest.main()
