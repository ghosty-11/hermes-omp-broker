from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "broker/omp-delegate-broker.py"


def _load_broker(env: dict[str, str]) -> type[object]:
    """Import the broker module with the given env overrides."""
    with tempfile.TemporaryDirectory() as jobs, mock.patch.dict(
        os.environ, {"HERMES_OMP_JOB_DIR": jobs, **env}, clear=True,
    ):
        spec = importlib.util.spec_from_file_location(
            f"broker_stamp_{os.urandom(4).hex()}", BROKER)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


def _compute_expected_digest(script_bytes: bytes, policy_bytes: bytes) -> str:
    """Mirror the contract's digest formula for verification."""
    script_row = "sha256:" + hashlib.sha256(script_bytes).hexdigest()
    policy_row = "sha256:" + hashlib.sha256(policy_bytes).hexdigest()
    payload = f"{script_row}\n{policy_row}"
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


class PolicyStampDigestTest(unittest.TestCase):
    """The digest function reproduces the contract formula on arbitrary input."""

    def test_digest_reproducible_formula(self) -> None:
        """Fixture bytes → digest equals independent computation."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            script = td_path / "script.py"
            policy = td_path / "policy.json"
            script_bytes = b"#! /usr/bin/env python3\nprint('hello')\n"
            policy_bytes = b'{"repositories": {}}\n'
            script.write_bytes(script_bytes)
            policy.write_bytes(policy_bytes)

            broker_mod = _load_broker({"HERMES_OMP_POLICY": str(policy)})
            stamp = broker_mod.write_policy_stamp(
                script_file=str(script),
                policy_file=str(policy),
                # Isolation: without this the writer falls back to the
                # deployed path and a test run stamps production state.
                stamp_file=td_path / "stamp.json",
            )

            self.assertIsNotNone(stamp)
            digest_in_stamp = stamp["policy_pair_digest"]
            expected = _compute_expected_digest(script_bytes, policy_bytes)
            self.assertEqual(digest_in_stamp, expected)


class PolicyStampWritePathTest(unittest.TestCase):
    """A stamp writer targets the env-controlled path; import never writes."""

    def test_import_does_not_write_stamp(self) -> None:
        """Importing with stamp path pointing at a tmpdir creates nothing."""
        with tempfile.TemporaryDirectory() as td:
            stamp_path = Path(td) / "broker-policy.json"
            env = {
                "HERMES_OMP_POLICY": "/dev/null",
                "HERMES_OMP_POLICY_STAMP": str(stamp_path),
            }
            _load_broker(env)
            self.assertFalse(stamp_path.exists())

    def test_server_start_writes_stamp(self) -> None:
        """Calling main() writes the stamp; system-listeners exit early."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            policy = td_path / "policy.json"
            policy.write_text(json.dumps({
                "repositories": {},
                "callers": {},
            }))
            stamp_path = td_path / "broker-policy.json"
            env = {
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_POLICY_STAMP": str(stamp_path),
                "HERMES_OMP_JOB_DIR": str(td_path / "jobs"),
            }
            broker_mod = _load_broker(env)
            # main() writes the stamp then hits systemd_listeners which
            # raises SystemExit because LISTEN_PID != os.getpid().
            with mock.patch.object(broker_mod.signal, "signal"):
                with self.assertRaises(SystemExit):
                    broker_mod.main()
            self.assertTrue(stamp_path.exists())
    def test_main_uses_policy_bytes_captured_at_load(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy = root / "policy.json"
            first = b'{"repositories":{"a":{"path":"/tmp/a"}}}\n'
            second = b'{"repositories":{"b":{"path":"/tmp/b"}}}\n'
            policy.write_bytes(first)
            stamp_path = root / "stamp.json"
            broker_mod = _load_broker({
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_POLICY_STAMP": str(stamp_path),
                "HERMES_OMP_JOB_DIR": str(root / "jobs"),
            })
            policy.write_bytes(second)
            with (
                mock.patch.object(broker_mod, "systemd_listeners", side_effect=SystemExit),
                mock.patch.object(broker_mod.signal, "signal"),
            ):
                with self.assertRaises(SystemExit):
                    broker_mod.main()
            stamp = json.loads(stamp_path.read_text())
            self.assertEqual(
                _compute_expected_digest(broker_mod._LOADED_SCRIPT_BYTES, first),
                stamp["policy_pair_digest"],
            )
            self.assertEqual(
                {"path": str(policy), "sha256": "sha256:" + hashlib.sha256(first).hexdigest()},
                stamp["loaded_artifacts"]["policy"],
            )
            self.assertEqual(stamp["loaded_artifacts"],
                             broker_mod.write_policy_stamp()["loaded_artifacts"])

    def test_invalid_loaded_policy_does_not_produce_stamp(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy = root / "policy.json"
            policy.write_text("{invalid")
            stamp_path = root / "stamp.json"
            broker_mod = _load_broker({
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_POLICY_STAMP": str(stamp_path),
                "HERMES_OMP_JOB_DIR": str(root / "jobs"),
            })
            with (
                mock.patch.object(broker_mod, "systemd_listeners", side_effect=SystemExit),
                mock.patch.object(broker_mod.signal, "signal"),
            ):
                with self.assertRaises(SystemExit):
                    broker_mod.main()
            self.assertFalse(stamp_path.exists())

    def test_failed_stamp_replacement_preserves_previous_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy = root / "policy.json"
            policy.write_text('{"repositories": {}}')
            stamp_path = root / "stamp.json"
            broker_mod = _load_broker({
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_POLICY_STAMP": str(stamp_path),
            })
            first = broker_mod.write_policy_stamp()
            self.assertIsNotNone(first)
            previous = stamp_path.read_bytes()
            with mock.patch.object(broker_mod.os, "replace", side_effect=PermissionError):
                self.assertIsNone(broker_mod.write_policy_stamp())
            self.assertEqual(previous, stamp_path.read_bytes())


class LoadedArtifactTest(unittest.TestCase):
    def test_pair_overrides_cannot_relabel_loaded_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy = root / "policy.json"
            policy.write_text('{"repositories": {}}')
            broker_mod = _load_broker({"HERMES_OMP_POLICY": str(policy)})
            first = broker_mod.write_policy_stamp(stamp_file=root / "first.json")
            changed = broker_mod.write_policy_stamp(
                script_file=str(root / "other.py"), script_bytes=b"other script",
                policy_file=str(root / "other.json"), policy_bytes=b"other policy",
                stamp_file=root / "second.json",
            )
            self.assertNotEqual(first["policy_pair_digest"], changed["policy_pair_digest"])
            self.assertEqual(first["loaded_artifacts"], changed["loaded_artifacts"])
            self.assertEqual(str(BROKER), changed["loaded_artifacts"]["script"]["path"])
            self.assertEqual(str(policy), changed["loaded_artifacts"]["policy"]["path"])


