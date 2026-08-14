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
            runner.write_text(f'''import extension from {json.dumps(EXTENSION.as_uri())};
const handlers = new Map<string, Function>(); const tools = new Map<string, unknown>();
const scalar = {{ optional() {{ return this; }}, describe() {{ return this; }} }};
const pi = {{ zod: {{ string: () => scalar, number: () => scalar, array: (_v: unknown) => scalar, enum: (_v: unknown) => scalar, object: (_v: unknown) => scalar }}, on: (n: string, h: Function) => handlers.set(n,h), registerTool: (t: {{name:string}}) => tools.set(t.name,t) }};
extension(pi);
const output: unknown[] = []; const ctx = {{cwd:{json.dumps(str(workspace))}}};
for (const event of {json.dumps(events)}) {{
  if (event.kind === "tool_definition") output.push(tools.get(String(event.name)));
  else if (event.kind === "broker_finalize") output.push(await (tools.get("broker_finalize") as any).execute("id", event.input));
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

    def test_broker_finalizer_records_typed_result(self) -> None:
        [result] = self.exercise([{
            "kind": "broker_finalize",
            "input": {
                "summary": "read-only smoke complete",
                "verification": ["git status --short returned empty"],
                "gaps": [],
                "verdict": "MET",
            },
        }])
        self.assertIn("recorded", result["content"][0]["text"].lower())

    def test_boundary_tools_are_always_visible_to_the_model(self) -> None:
        definitions = self.exercise([
            {"kind": "tool_definition", "name": "bash"},
            {"kind": "tool_definition", "name": "broker_finalize"},
        ])
        self.assertTrue(all(definition["loadMode"] == "essential" for definition in definitions))


if __name__ == "__main__":
    unittest.main()
