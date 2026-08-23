"""A restricted-write child's files must be group-readable; others inherit.

The broker unit runs with UMask=0077 to protect its own state and credential
handling. A restricted-write child (the wiki callers) inheriting that umask
writes 0600 files into a setgid group-shared vault — proven live 2026-08-21,
when the first backlog-maturation run created a triage note the hermes-side
projector could not read (Errno 13). Those callers exist to produce
group-consumed artefacts, so they get umask 0o002. Workspace-write children
keep the inherited umask: their artefacts follow the owning identity's own
posture, and widening them was rejected during review.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "broker/omp-delegate-broker.py"


class ChildUmaskTest(unittest.TestCase):
    def _run_child(self, sandbox: str, *, git_mode: str = "none") -> int:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = root / "repo"
            workspace.mkdir()
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "repositories": {"repo": {"path": str(workspace)}},
                "callers": {"delegate_to_omp": {
                    "repositories": ["repo"], "sandbox": sandbox,
                    "read_paths": [], "write_patterns": ["**"],
                    "git_mode": git_mode, "skills": [],
                }},
            }))
            fake_omp = root / "fake-omp"
            fake_omp.write_text("#!/bin/sh\ntouch \"$PWD/child-made.txt\"\n")
            fake_omp.chmod(0o700)
            env = {
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_CALLER_UID": str(os.getuid()),
                "HERMES_OMP_JOB_DIR": str(root / "jobs"),
                "HERMES_OMP_BIN": str(fake_omp),
                "HERMES_OMP_AGENT_DIR": str(root / "agent"),
            }
            with mock.patch.dict(os.environ, env):
                spec = importlib.util.spec_from_file_location("broker_umask", BROKER)
                assert spec and spec.loader
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
            request = module.validate_request({
                "version": 1, "request_id": "req", "task_id": "task",
                "repository": "repo", "caller": "delegate_to_omp",
                "workspace": str(workspace), "sandbox": sandbox,
                "model": module.MODEL, "prompt": "bounded", "timeout": 10,
            }, peer_uid=os.getuid())
            old_umask = os.umask(0o077)  # simulate the unit's restrictive umask
            try:
                process = module.start_omp_process(request, root / "final.json", {})
                process.wait(timeout=10)
            finally:
                os.umask(old_umask)
            made = workspace / "child-made.txt"
            self.assertTrue(made.exists(), "fake child did not run")
            return stat.S_IMODE(made.stat().st_mode)

    def test_restricted_write_child_writes_group_readable_files(self) -> None:
        mode = self._run_child("restricted-write", git_mode="scoped")
        self.assertTrue(mode & stat.S_IRGRP,
                        f"restricted-write child file is not group-readable: {oct(mode)}")

    def test_scoped_git_workspace_write_child_writes_group_readable_files(self) -> None:
        # A scoped-git child works a linked worktree whose refs and index the
        # hermes worker must read next (proven live 2026-08-24: a 600 branch
        # ref broke the worker's evidence read on the same worktree).
        mode = self._run_child("workspace-write", git_mode="scoped")
        self.assertTrue(mode & stat.S_IRGRP,
                        f"scoped-git child file is not group-readable: {oct(mode)}")

    def test_plain_workspace_write_child_keeps_the_inherited_umask(self) -> None:
        mode = self._run_child("workspace-write", git_mode="none")
        self.assertFalse(mode & stat.S_IRGRP,
                         f"plain workspace-write child unexpectedly widened: {oct(mode)}")
if __name__ == "__main__":
    unittest.main(verbosity=2)
