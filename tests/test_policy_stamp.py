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
    with mock.patch.dict(os.environ, env, clear=True):
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

            # The function doesn't exist yet — this must fail red.
            broker_mod = _load_broker({"HERMES_OMP_POLICY": str(policy)})
            stamp = broker_mod.write_policy_stamp(
                script_file=str(script),
                policy_file=str(policy),
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
            with self.assertRaises(SystemExit):
                broker_mod.main()
            self.assertTrue(stamp_path.exists())

    def test_unwritable_stamp_path_prints_diagnostic(self) -> None:
        """An absolute-readonly directory does not raise — just stderr."""
        broker_mod = _load_broker({"HERMES_OMP_POLICY": "/dev/null"})
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            # /proc/sys is typically root-only; on CI it might be writable.
            # Fallback: a nonexistent absolute path is writable (no mkdir
            # parent fails), so we create a non-writable directory and point
            # the stamp inside it.
            td = tempfile.mkdtemp()
            try:
                stamp_dir = Path(td) / "noperm"
                stamp_dir.mkdir(mode=0o000)
                stamp_file = stamp_dir / "broker-policy.json"
                stamp_path = str(stamp_file)
                result = broker_mod.write_policy_stamp(
                    script_file="/some/script.py",
                    policy_file="/some/policy.json",
                    stamp_file=Path(stamp_path),
                )
                # Either returns None (failed soft) or we check stderr.
                # The key assertion: no exception was raised.
                stderr_output = buf.getvalue()
                self.assertIn("omp-delegate-broker", stderr_output)
            finally:
                # Restore mode so cleanup can remove it.
                import stat
                try:
                    stamp_dir.chmod(0o755)
                except OSError:
                    pass


class PolicyStampFieldTest(unittest.TestCase):
    """The stamp contains all required fields with correct types."""

    def test_stamp_fields_and_types(self) -> None:
        """Every required field present; types match contract."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            script = td_path / "script.py"
            policy = td_path / "policy.json"
            script.write_bytes(b"#!/usr/bin/env python3\n")
            policy.write_text(json.dumps({"repositories": {}}))

            broker_mod = _load_broker({"HERMES_OMP_POLICY": str(policy)})
            stamp = broker_mod.write_policy_stamp(
                script_file=str(script),
                policy_file=str(policy),
                stamp_file=Path(td) / "broker-policy.json",
            )

        self.assertIsNotNone(stamp)
        self.assertIsInstance(stamp["pid"], int)
        self.assertGreater(stamp["pid"], 0)
        self.assertEqual(stamp["pid"], os.getpid())
        self.assertIsInstance(stamp["start_monotonic_usec"], int)
        self.assertGreater(stamp["start_monotonic_usec"], 0)
        self.assertEqual(stamp["script_file"], str(script))
        self.assertEqual(stamp["policy_file"], str(policy))
        self.assertIsInstance(stamp["policy_pair_digest"], str)
        self.assertTrue(stamp["policy_pair_digest"].startswith("sha256:"))
        self.assertIsInstance(stamp["written_at"], str)
        # written_at is ISO8601 — parseable by dateutil or basic check.
        from datetime import datetime, timezone
        # Accept Z or +00:00 suffix.
        ts = stamp["written_at"].replace("Z", "+00:00")
        datetime.fromisoformat(ts)


class PolicyStampForeignPathTest(unittest.TestCase):
    """A stamp writer never produces a stamp with foreign paths."""

    def test_stamp_paths_match_input(self) -> None:
        """Paths in the stamp equal exactly what we passed in."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            script = td_path / "script.py"
            policy = td_path / "policy.json"
            script.write_bytes(b"#!/usr/bin/env python3\n")
            policy.write_text(json.dumps({"repositories": {}}))

            # Use distinct paths (with absolute form) and verify the stamp.
            script_abs = str(script.resolve())
            policy_abs = str(policy.resolve())
            broker_mod = _load_broker({"HERMES_OMP_POLICY": policy_abs})
            stamp = broker_mod.write_policy_stamp(
                script_file=script_abs,
                policy_file=policy_abs,
                stamp_file=td_path / "stamp.json",
            )

        self.assertIsNotNone(stamp)
        self.assertEqual(stamp["script_file"], script_abs)
        self.assertEqual(stamp["policy_file"], policy_abs)
