from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "extension/omp-delegate-extension.ts"


class ExtensionTest(unittest.TestCase):
    def exercise(
        self,
        events: list[dict[str, object]],
        sandbox: str = "workspace-write",
        write_patterns: list[str] | None = None,
        git_mode: str = "none",
        create_only: bool = False,
        existing_paths: list[str] | None = None,
    ) -> list[object]:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = root / "workspace"
            workspace.mkdir()
            for path in existing_paths or []:
                target = workspace / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("existing")
            final = root / "final.json"
            runner = root / "runner.ts"
            runner.write_text(f'''import {{ readFileSync }} from "node:fs";
import extension from {json.dumps(EXTENSION.as_uri())};
const handlers = new Map<string, Function>(); const tools = new Map<string, unknown>();
const scalar = {{ optional() {{ return this; }}, describe() {{ return this; }} }};
const pi = {{ zod: {{ string: () => scalar, number: () => scalar, array: (_v: unknown) => scalar, enum: (_v: unknown) => scalar, object: (_v: unknown) => scalar }}, on: (n: string, h: Function) => handlers.set(n,h), registerTool: (t: {{name:string}}) => tools.set(t.name,t) }};
extension(pi);
const output: unknown[] = []; const ctx = {{cwd:{json.dumps(str(workspace))}}};
for (const event of {json.dumps(events)}) {{
  if (event.kind === "tool_definition") output.push(tools.get(String(event.name)));
  else if (event.kind === "broker_finalize") output.push(await (tools.get("broker_finalize") as any).execute("id", event.input));
  else if (event.kind === "final_file") output.push(JSON.parse(readFileSync({json.dumps(str(final))}, "utf8")));
  else output.push(await handlers.get("tool_call")!(event,ctx));
}}
console.log(JSON.stringify(output));''')
            env = {
                **os.environ,
                "OMP_DELEGATE_FINAL_PATH": str(final),
                "OMP_DELEGATE_SANDBOX": sandbox,
                "OMP_DELEGATE_READ_PATHS": "[]",
                "OMP_DELEGATE_WRITE_PATTERNS": json.dumps(write_patterns or []),
                "OMP_DELEGATE_GIT_MODE": git_mode,
                "OMP_DELEGATE_CREATE_ONLY": "1" if create_only else "0",
            }
            result = subprocess.run(["node", str(runner)], env=env, text=True, capture_output=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def sandbox_argv(
        self,
        workspace: Path,
        *,
        git_mode: str,
        command: str = "git status --short",
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as td:
            runner = Path(td) / "runner.ts"
            runner.write_text(f'''import {{ buildSandboxArgv }} from {json.dumps(EXTENSION.as_uri())};
console.log(JSON.stringify(buildSandboxArgv({json.dumps(command)}, {json.dumps(str(workspace))})));''')
            env = {
                **os.environ,
                "OMP_DELEGATE_SANDBOX": "restricted-write",
                "OMP_DELEGATE_GIT_MODE": git_mode,
            }
            result = subprocess.run(
                ["node", str(runner)], env=env, text=True,
                capture_output=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def test_workspace_paths_pass_and_escapes_fail(self) -> None:
        results = self.exercise([
            {"toolName": "read", "input": {"path": "inside.txt"}},
            {"toolName": "write", "input": {"path": "../outside.txt", "content": "x"}},
            {"toolName": "browser", "input": {}},
        ])
        self.assertIsNone(results[0])
        self.assertTrue(results[1]["block"])
        self.assertTrue(results[2]["block"])

    def test_read_only_blocks_write_and_bash(self) -> None:
        results = self.exercise([
            {"toolName": "write", "input": {"path": "inside.txt", "content": "x"}},
            {"toolName": "bash", "input": {"command": "touch inside.txt"}},
        ], sandbox="read-only")
        self.assertTrue(all(result["block"] for result in results))

    def test_restricted_write_uses_configured_relative_patterns(self) -> None:
        results = self.exercise([
            {"toolName": "write", "input": {"path": "inbox/report.md", "content": "x"}},
            {"toolName": "write", "input": {"path": "private.md", "content": "x"}},
            {"toolName": "bash", "input": {"command": "touch inbox/report.md"}},
        ], sandbox="restricted-write", write_patterns=["inbox/*.md"])
        self.assertIsNone(results[0])
        self.assertTrue(results[1]["block"])
        self.assertTrue(results[2]["block"])

    def test_restricted_create_only_refuses_existing_path(self) -> None:
        results = self.exercise([
            {"toolName": "write", "input": {"path": "new.md", "content": "x"}},
            {"toolName": "write", "input": {"path": "existing.md", "content": "x"}},
        ], sandbox="restricted-write", write_patterns=["*.md"], create_only=True,
            existing_paths=["existing.md"])
        self.assertIsNone(results[0])
        self.assertTrue(results[1]["block"])

    def test_restricted_git_mode_allows_only_scoped_paths(self) -> None:
        results = self.exercise([
            {"toolName": "bash", "input": {"command": "git status --short"}},
            {"toolName": "bash", "input": {"command": "git add docs/journal/note.md"}},
            {"toolName": "bash", "input": {"command": "git add src/code.py"}},
            {"toolName": "bash", "input": {"command": "git push"}},
        ], sandbox="restricted-write", write_patterns=["ROADMAP.md", "docs/journal/*"], git_mode="scoped")
        self.assertIsNone(results[0])
        self.assertIsNone(results[1])
        self.assertTrue(results[2]["block"])
        self.assertTrue(results[3]["block"])

    def test_globstar_write_pattern_admits_nested_paths(self) -> None:
        """`backlog/**` must admit the whole subtree, not one path segment.

        The first translation mapped every `*` to `[^/]*`, so `backlog/**`
        silently admitted only `backlog/<file>` — a wiki caller could not
        write a triage note two levels down while the policy read as if it
        could. Nested paths are the entire point of a `**` pattern.
        """
        results = self.exercise([
            {"toolName": "write", "input": {"path": "backlog/triage/note.md", "content": "x"}},
            {"toolName": "write", "input": {"path": "backlog/a/b/c.md", "content": "x"}},
            {"toolName": "write", "input": {"path": "outside/note.md", "content": "x"}},
            {"toolName": "write", "input": {"path": "backlogged/nope.md", "content": "x"}},
        ], sandbox="restricted-write", write_patterns=["backlog/**", "log.md"])
        self.assertIsNone(results[0])
        self.assertIsNone(results[1])
        self.assertTrue(results[2]["block"])
        self.assertTrue(results[3]["block"])

    def test_scoped_git_mv_requires_both_paths_inside_patterns(self) -> None:
        """Stage promotion is a `git mv`; both ends must sit inside the boundary."""
        results = self.exercise([
            {"toolName": "bash", "input": {"command": "git mv backlog/ideas/a.md backlog/_archive/a.md"}},
            {"toolName": "bash", "input": {"command": "git mv backlog/ideas/a.md ../outside.md"}},
            {"toolName": "bash", "input": {"command": "git mv secret.md backlog/_archive/secret.md"}},
            {"toolName": "bash", "input": {"command": "git mv backlog/ideas/a.md"}},
        ], sandbox="restricted-write", write_patterns=["backlog/**"], git_mode="scoped",
            existing_paths=["backlog/ideas/a.md", "secret.md"])
        self.assertIsNone(results[0])
        self.assertTrue(results[1]["block"])
        self.assertTrue(results[2]["block"])
        self.assertTrue(results[3]["block"])

    def test_scoped_git_accepts_quoted_paths_with_spaces(self) -> None:
        """Wiki filenames carry spaces; an unquotable path is an unusable boundary.

        The first live maturation run (2026-08-21) created
        `backlog/triage/Market Oracle Agentic Upgrade Research.md` and could not
        `git add` or `git mv` it: the token splitter broke the path at each space,
        checked the fragments, and refused. The child left the whole run
        uncommitted, which the wrapper correctly reported as disagreement.
        """
        results = self.exercise([
            {"toolName": "bash", "input": {"command": "git add 'backlog/triage/A B.md'"}},
            {"toolName": "bash", "input": {"command": 'git mv "backlog/triage/A B.md" "backlog/_archive/A B.md"'}},
            {"toolName": "bash", "input": {"command": "git add 'secret file.md'"}},
            {"toolName": "bash", "input": {"command": "git add 'backlog/unclosed"}},
        ], sandbox="restricted-write", write_patterns=["backlog/**"], git_mode="scoped",
            existing_paths=["backlog/triage/A B.md", "secret file.md"])
        self.assertIsNone(results[0])
        self.assertIsNone(results[1])
        self.assertTrue(results[2]["block"])
        self.assertTrue(results[3]["block"])

    def test_broker_finalizer_records_meaningful_scalar_result(self) -> None:
        result, recorded = self.exercise([
            {
                "kind": "broker_finalize",
                "input": {
                    "summary": "The requested bounded change is complete.",
                    "verification": "git status --short returned empty",
                    "gaps": "",
                    "verdict": "MET",
                },
            },
            {"kind": "final_file"},
        ])
        self.assertIn("recorded", result["content"][0]["text"].lower())
        self.assertFalse(result.get("isError", False))
        self.assertEqual(["git status --short returned empty"], recorded["verification"])
        self.assertEqual([], recorded["gaps"])

    def test_placeholder_finalize_is_rejected_without_locking_the_turn(self) -> None:
        results = self.exercise([
            {
                "kind": "broker_finalize",
                "input": {
                    "summary": "test summary",
                    "verification": "a\\nb",
                    "gaps": "c",
                    "verdict": "NOT MET",
                },
            },
            {"toolName": "read", "input": {"path": "inside.txt"}},
        ])
        self.assertTrue(results[0]["isError"])
        self.assertIsNone(results[1])

    def test_scoped_git_binds_only_the_linked_common_directory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
            (repo / "seed").write_text("s\\n")
            subprocess.run(["git", "add", "seed"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "seed"], cwd=repo, check=True)
            worktree = root / "worktree"
            subprocess.run(["git", "worktree", "add", "-q", str(worktree)], cwd=repo, check=True)

            scoped = self.sandbox_argv(worktree, git_mode="scoped")
            common = str((repo / ".git").resolve())
            self.assertTrue(any(
                scoped[index:index + 3] == ["--bind", common, common]
                for index in range(len(scoped) - 2)
            ))
            self.assertTrue(any(
                scoped[index:index + 3] == [
                    "--setenv", "GIT_CONFIG_VALUE_0", str(worktree.resolve())
                ]
                for index in range(len(scoped) - 2)
            ))

            unscoped = self.sandbox_argv(worktree, git_mode="none")
            self.assertFalse(any(
                unscoped[index:index + 3] == ["--bind", common, common]
                for index in range(len(unscoped) - 2)
            ))

    def test_scoped_sandbox_commits_through_linked_worktree_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
            (repo / "seed").write_text("s\n")
            subprocess.run(["git", "add", "seed"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "seed"], cwd=repo, check=True)
            worktree = root / "worktree"
            subprocess.run(["git", "worktree", "add", "-q", str(worktree)], cwd=repo, check=True)
            note = worktree / "backlog" / "triage" / "note.md"
            note.parent.mkdir(parents=True)
            note.write_text("accepted\n")

            for command in (
                "git status --short",
                "git add 'backlog/triage/note.md'",
                "git commit -m 'accept linked worktree'",
                "git status --short",
            ):
                result = subprocess.run(
                    self.sandbox_argv(
                        worktree, git_mode="scoped", command=command),
                    capture_output=True, text=True, check=False)
                self.assertEqual(0, result.returncode, f"{command}\n{result.stderr}")
                self.assertNotIn("Failed to create stream fd", result.stderr)
            self.assertFalse(subprocess.run(
                ["git", "-C", str(worktree), "status", "--porcelain"],
                capture_output=True, text=True, check=True,
            ).stdout.strip())

    def test_restricted_bash_definition_advertises_scoped_git_only(self) -> None:
        [definition] = self.exercise(
            [{"kind": "tool_definition", "name": "bash"}],
            sandbox="restricted-write",
            write_patterns=["backlog/**"],
            git_mode="scoped",
        )
        self.assertEqual("Scoped Git", definition["label"])
        for command in ("git status", "git log", "git diff", "git add", "git mv", "git commit"):
            self.assertIn(command, definition["description"])
        self.assertIn("General shell commands are denied", definition["description"])

    def test_boundary_tools_are_always_visible_to_the_model(self) -> None:
        definitions = self.exercise([
            {"kind": "tool_definition", "name": "bash"},
            {"kind": "tool_definition", "name": "broker_finalize"},
        ])
        self.assertTrue(all(definition["loadMode"] == "essential" for definition in definitions))


if __name__ == "__main__":
    unittest.main()
