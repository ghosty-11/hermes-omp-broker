"""Behavioral admission tests for the OMP implementation delegate."""

from __future__ import annotations

import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin" / "__init__.py"
BRIEF = (
    "Implement the bounded fixture change in seed.txt, preserve every other path, "
    "verify the resulting Git state, and do not modify configuration or credentials."
)


def load_plugin():
    spec = importlib.util.spec_from_file_location("hermes_omp_delegate", PLUGIN)
    if spec is None or spec.loader is None:
        raise RuntimeError("delegate plugin could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestOmpDelegateAdmission(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_plugin()

    @staticmethod
    def _git(repo: Path, *args: str) -> None:
        subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
        )

    def _fixture(self, root: Path, *, committed: bool) -> tuple[Path, Path, Path]:
        repo = root / "repo"
        repo.mkdir()
        self._git(repo, "init", "-q")
        self._git(repo, "config", "user.name", "Fixture")
        self._git(repo, "config", "user.email", "fixture@example.invalid")
        seed = repo / "seed.txt"
        seed.write_text("baseline\n")
        self._git(repo, "add", "seed.txt")
        if committed:
            self._git(repo, "commit", "-qm", "fixture baseline")

        marker = root / "delegate-ran"
        invoke = root / "fake-invoke.py"
        invoke.write_text(
            "#!/usr/bin/env python3\n"
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "if os.environ.get('OMP_INVOKED_BY') != 'delegate_to_omp' or len(sys.argv) != 2:\n"
            "    raise SystemExit(64)\n"
            f"Path({str(marker)!r}).write_text('yes')\n"
            "p = Path('seed.txt')\n"
            "p.write_text(p.read_text() + 'delegate edit\\n')\n"
            "print('fixture claimed completion')\n"
        )
        invoke.chmod(0o755)
        return repo, seed, marker

    def _invoke(self, repo: Path, invoke: Path) -> str:
        with (
            mock.patch.object(self.module, "ALLOWED_REPOS", {"fixture": str(repo)}),
            mock.patch.object(self.module, "INVOKE", str(invoke)),
        ):
            return self.module._handle(
                {"repo": "fixture", "brief": BRIEF, "task_id": "fixture-task"}
            )

    def test_availability_requires_the_client_and_a_connectable_broker_socket(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            invoke = root / "omp-invoke.py"
            broker_socket = root / "omp.sock"
            invoke.write_text("#!/bin/sh\n")
            invoke.chmod(0o755)
            with (
                mock.patch.object(self.module, "INVOKE", str(invoke)),
                mock.patch.object(self.module, "BROKER_SOCKET", str(broker_socket)),
            ):
                self.assertFalse(
                    self.module._available(),
                    "advertised delegation with no socket present",
                )

                broker_socket.touch()
                self.assertFalse(
                    self.module._available(),
                    "a regular file at the socket path advertised a broker that cannot accept",
                )
                broker_socket.unlink()

                stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.addCleanup(stale.close)
                stale.bind(str(broker_socket))
                self.assertFalse(
                    self.module._available(),
                    "a bound but unlistening socket advertised a broker that cannot accept",
                )
                stale.close()
                broker_socket.unlink()

                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.addCleanup(listener.close)
                listener.bind(str(broker_socket))
                listener.listen(1)
                self.assertTrue(
                    self.module._available(),
                    "refused delegation while a real broker was listening",
                )

    def test_availability_probe_leaves_the_broker_unmutated(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            invoke = root / "omp-invoke.py"
            broker_socket = root / "omp.sock"
            invoke.write_text("#!/bin/sh\n")
            invoke.chmod(0o755)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(listener.close)
            listener.bind(str(broker_socket))
            listener.listen(1)
            listener.settimeout(5)
            with (
                mock.patch.object(self.module, "INVOKE", str(invoke)),
                mock.patch.object(self.module, "BROKER_SOCKET", str(broker_socket)),
            ):
                self.assertTrue(self.module._available())

            try:
                accepted, _ = listener.accept()
            except socket.timeout:
                self.fail("the probe never connected, so availability was not proven")
            self.addCleanup(accepted.close)
            accepted.settimeout(5)
            self.assertEqual(
                b"",
                accepted.recv(64),
                "the probe sent request bytes instead of closing immediately",
            )

    def test_dirty_repository_is_refused_before_the_writer_runs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, seed, marker = self._fixture(root, committed=True)
            seed.write_text("baseline\noperator edit\n")
            invoke = root / "fake-invoke.py"

            result = self._invoke(repo, invoke)

            self.assertFalse(marker.exists(), "delegate ran despite a dirty pre-state")
            self.assertEqual("baseline\noperator edit\n", seed.read_text())
            self.assertIn("refused", result.lower())
            self.assertIn("clean", result.lower())

    def test_repository_without_a_valid_head_is_refused_before_the_writer_runs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, seed, marker = self._fixture(root, committed=False)
            invoke = root / "fake-invoke.py"

            result = self._invoke(repo, invoke)

            self.assertFalse(marker.exists(), "delegate ran without an attributable baseline")
            self.assertEqual("baseline\n", seed.read_text())
            self.assertIn("refused", result.lower())
            self.assertIn("head", result.lower())

    def test_repo_config_cannot_hide_an_untracked_file_from_admission(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, seed, marker = self._fixture(root, committed=True)
            (repo / "hidden-by-config.txt").write_text("operator work\n")
            self._git(repo, "config", "status.showUntrackedFiles", "no")
            invoke = root / "fake-invoke.py"

            result = self._invoke(repo, invoke)

            self.assertFalse(marker.exists(), "delegate ran with a config-hidden untracked file")
            self.assertEqual("baseline\n", seed.read_text())
            self.assertIn("refused", result.lower())
            self.assertIn("clean", result.lower())

    def test_clean_committed_repository_still_admits_the_writer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, seed, marker = self._fixture(root, committed=True)
            invoke = root / "fake-invoke.py"

            result = self._invoke(repo, invoke)

            self.assertTrue(marker.exists(), "clean repository was incorrectly refused")
            self.assertEqual("baseline\ndelegate edit\n", seed.read_text())
            self.assertIn("exit code: 0", result.lower())


class TestRepositoryContainment(TestOmpDelegateAdmission):
    """The repository key is a capability boundary, so the refusals need proving.

    `_handle` rejects anything outside `ALLOWED_REPOS`, but until now only the accepting
    path was exercised. The schema `enum` is advisory — a model can send any string, and a
    tool whose containment is asserted nowhere is a boundary held by inspection alone.

    Each case asserts the writer never ran, not merely that the reply says no.
    """

    def _attempt(self, repo: Path, invoke: Path, requested: str) -> str:
        with (
            mock.patch.object(self.module, "ALLOWED_REPOS", {"fixture": str(repo)}),
            mock.patch.object(self.module, "INVOKE", str(invoke)),
        ):
            return self.module._handle(
                {"repo": requested, "brief": BRIEF, "task_id": "fixture-task"}
            )

    def _refuses(self, requested: str, *, expect: str = "unknown repo") -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, seed, marker = self._fixture(root, committed=True)
            invoke = root / "fake-invoke.py"

            result = self._attempt(repo, invoke, requested)

            self.assertFalse(marker.exists(), f"writer ran for repo={requested!r}")
            self.assertEqual("baseline\n", seed.read_text(), "repository was modified")
            self.assertIn(expect, result.lower())

    def test_a_key_outside_the_policy_is_refused(self) -> None:
        self._refuses("some-other-project")

    def test_an_absolute_path_is_not_accepted_as_a_key(self) -> None:
        self._refuses("/etc")

    def test_a_traversal_key_is_refused(self) -> None:
        self._refuses("../fixture")

    def test_an_empty_key_is_refused(self) -> None:
        self._refuses("")

    def test_the_refusal_names_the_permitted_keys(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, _seed, _marker = self._fixture(root, committed=True)
            result = self._attempt(repo, root / "fake-invoke.py", "some-other-project")
            self.assertIn("fixture", result)
            self.assertIn("paths are not accepted", result.lower())

    def test_a_missing_task_id_stops_the_writer(self) -> None:
        """Correlation is what ties a delegated run to the ledger entry that authorised it."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, seed, marker = self._fixture(root, committed=True)
            invoke = root / "fake-invoke.py"
            with (
                mock.patch.object(self.module, "ALLOWED_REPOS", {"fixture": str(repo)}),
                mock.patch.object(self.module, "INVOKE", str(invoke)),
            ):
                result = self.module._handle({"repo": "fixture", "brief": BRIEF})

            self.assertFalse(marker.exists(), "writer ran without a task id")
            self.assertEqual("baseline\n", seed.read_text())
            self.assertIn("task_id", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
