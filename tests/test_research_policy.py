"""Two-stage maturation tool and fallback contracts (v3).

`backlog-maturation-research` is the Opus staging orchestrator: caller identity
must reach the trusted extension, which then admits only `task`,
`backlog_search`, `backlog_fetch`, plus read/write inside the staging workspace.
`backlog-maturation` is the Opus Wiki writer and must not receive those
network/spawn surfaces. Task input is structural: the three named agents, at
most five children (four Sonnet + one Fable), no caller-supplied model, no
async/background, no nested spawn. Fallback rungs and minted credentials are
per-caller policy, not one global chain. The wire schema must admit the 3600 s
policy ceiling.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "broker/omp-delegate-broker.py"
EXTENSION = ROOT / "extension/omp-delegate-extension.ts"
SCHEMA = ROOT / "schemas/coding-job.schema.json"

WRITER = "backlog-maturation"
RESEARCH = "backlog-maturation-research"
FABLE_AGENT = "backlog-researcher-max"
OPUS = "anthropic/claude-opus-5"


def load_broker(policy: dict, td: str):
    policy_path = Path(td) / "policy.json"
    policy_path.write_text(json.dumps(policy))
    with mock.patch.dict(os.environ, {
        "HERMES_OMP_POLICY": str(policy_path),
        "HERMES_OMP_CALLER_UID": str(os.getuid()),
        "HERMES_OMP_JOB_DIR": str(Path(td) / "jobs"),
        "HERMES_OMP_MODEL": "provider/model",
        "HERMES_OMP_FALLBACK_MODELS": "openai-codex/gpt-5.6-luna",
    }):
        spec = importlib.util.spec_from_file_location(
            f"broker_research_{os.urandom(4).hex()}", BROKER)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


def _policy(td: str) -> dict:
    wiki = Path(td) / "wiki"
    staging = Path(td) / "staging"
    wiki.mkdir()
    staging.mkdir()
    return {
        "version": 1,
        "model": "provider/model",
        "repositories": {
            "wiki": {"path": str(wiki)},
            "staging": {"path": str(staging)},
        },
        "callers": {
            WRITER: {
                "repositories": ["wiki"],
                "sandbox": "restricted-write",
                "read_paths": [],
                "write_patterns": ["backlog/**", "raw/**", "concepts/**", "log.md"],
                "git_mode": "scoped",
                "skills": [],
                "model": OPUS,
                "max_timeout": 3600,
                "fallback_models": [
                    "xai-oauth/grok-4.6",
                    "openai-codex/gpt-5.6-sol",
                ],
            },
            RESEARCH: {
                "repositories": ["staging"],
                "sandbox": "workspace-write",
                "read_paths": [str(wiki)],
                "write_patterns": [],
                "git_mode": "none",
                "skills": [],
                "model": OPUS,
                "max_timeout": 3600,
                "fallback_models": ["xai-oauth/grok-4.6"],
                "fallback_selectors": [
                    OPUS,
                    "anthropic/claude-sonnet-5",
                    "anthropic/claude-fable-5",
                ],
            },
        },
    }


def _request(td: str, *, caller: str, timeout: float = 10) -> dict:
    repo = "wiki" if caller == WRITER else "staging"
    sandbox = "restricted-write" if caller == WRITER else "workspace-write"
    return {
        "version": 1,
        "request_id": "req",
        "task_id": "task",
        "repository": repo,
        "caller": caller,
        "workspace": str(Path(td) / repo),
        "sandbox": sandbox,
        "model": OPUS,
        "prompt": "bounded",
        "timeout": timeout,
    }


def _task_item(agent: str, name: str, **extra: object) -> dict[str, object]:
    item: dict[str, object] = {
        "name": name,
        "agent": agent,
        "task": f"extract claims for {name}",
    }
    item.update(extra)
    return item


def _batch(*items: dict[str, object], **extra: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "context": "selected idea group",
        "tasks": list(items),
    }
    payload.update(extra)
    return payload


def _valid_batch() -> dict[str, object]:
    return _batch(
        _task_item("backlog-researcher", "r1"),
        _task_item("backlog-vision", "v1"),
        _task_item(FABLE_AGENT, "m1"),
    )


class ResearchPolicyExtensionTest(unittest.TestCase):
    def exercise(
        self,
        events: list[dict[str, object]],
        *,
        caller: str,
        sandbox: str = "workspace-write",
        write_patterns: list[str] | None = None,
        git_mode: str = "none",
    ) -> list[object]:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = root / "workspace"
            workspace.mkdir()
            runner = root / "runner.ts"
            runner.write_text(f'''import extension from {json.dumps(EXTENSION.as_uri())};
const handlers = new Map<string, Function>();
const scalar = {{ optional() {{ return this; }}, describe() {{ return this; }} }};
const pi = {{
  zod: {{
    string: () => scalar, number: () => scalar, array: (_v: unknown) => scalar,
    enum: (_v: unknown) => scalar, object: (_v: unknown) => scalar,
  }},
  on: (n: string, h: Function) => handlers.set(n, h),
  registerTool: (_t: {{name:string}}) => {{}},
}};
extension(pi);
const output: unknown[] = [];
const ctx = {{cwd:{json.dumps(str(workspace))}}};
for (const event of {json.dumps(events)}) {{
  output.push(await handlers.get("tool_call")!(event, ctx));
}}
console.log(JSON.stringify(output));''')
            env = {
                **os.environ,
                "OMP_DELEGATE_FINAL_PATH": str(root / "final.json"),
                "OMP_DELEGATE_SANDBOX": sandbox,
                "OMP_DELEGATE_READ_PATHS": "[]",
                "OMP_DELEGATE_WRITE_PATTERNS": json.dumps(write_patterns or []),
                "OMP_DELEGATE_GIT_MODE": git_mode,
                "OMP_DELEGATE_CREATE_ONLY": "0",
                "OMP_DELEGATE_CALLER": caller,
            }
            result = subprocess.run(
                ["node", str(runner)], env=env, text=True,
                capture_output=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def test_writer_blocks_task_search_and_fetch(self) -> None:
        results = self.exercise([
            {"toolName": "task", "input": _valid_batch()},
            {"toolName": "backlog_search", "input": {"query": "gap"}},
            {"toolName": "backlog_fetch", "input": {"url": "https://example.com"}},
        ], caller=WRITER, sandbox="restricted-write",
            write_patterns=["backlog/**", "raw/**", "concepts/**", "log.md"],
            git_mode="scoped")
        self.assertTrue(all(
            isinstance(result, dict) and result.get("block") for result in results
        ))

    def test_research_allows_custom_surfaces_and_staging_io(self) -> None:
        results = self.exercise([
            {"toolName": "task", "input": _valid_batch()},
            {"toolName": "backlog_search", "input": {"query": "gap"}},
            {"toolName": "backlog_fetch", "input": {"url": "https://example.com"}},
            {"toolName": "read", "input": {"path": "runs/manifest.json"}},
            {"toolName": "write", "input": {"path": "runs/manifest.json", "content": "{}"}},
            {"toolName": "hub", "input": {"op": "list"}},
            {"toolName": "web_search", "input": {"query": "unbounded"}},
        ], caller=RESEARCH, sandbox="restricted-write",
            write_patterns=["runs/**"])
        self.assertIsNone(results[0])
        self.assertIsNone(results[1])
        self.assertIsNone(results[2])
        self.assertIsNone(results[3])
        self.assertIsNone(results[4])
        self.assertTrue(results[5]["block"])
        self.assertTrue(results[6]["block"])

    def test_research_caller_cannot_shadow_agents_even_if_sandbox_drifts(self) -> None:
        [result] = self.exercise([
            {"toolName": "write",
             "input": {"path": ".omp/agents/backlog-researcher.md",
                       "content": "---\ntools: bash\n---\n"}},
        ], caller=RESEARCH, sandbox="workspace-write",
            write_patterns=["runs/**"])
        self.assertTrue(result["block"])

    def test_prompt_text_does_not_grant_research_tools_to_the_writer(self) -> None:
        [result] = self.exercise(
            [{"toolName": "task", "input": _valid_batch()}],
            caller=WRITER,
            sandbox="restricted-write",
            write_patterns=["backlog/**"],
            git_mode="scoped",
        )
        self.assertTrue(result["block"])

    def test_research_task_admits_only_the_named_agents(self) -> None:
        allowed, unknown, bundled = self.exercise([
            {"toolName": "task", "input": _valid_batch()},
            {"toolName": "task", "input": _batch(_task_item("scout", "s1"))},
            {"toolName": "task", "input": _batch(_task_item("task", "nested"))},
        ], caller=RESEARCH)
        self.assertIsNone(allowed)
        self.assertTrue(unknown["block"])
        self.assertTrue(bundled["block"])
        self.assertIn("agent", unknown["reason"].lower())

    def test_research_task_caps_five_children_four_sonnet_one_fable(self) -> None:
        four_sonnet_one_fable = _batch(
            *(_task_item("backlog-researcher", f"r{i}") for i in range(4)),
            _task_item(FABLE_AGENT, "m1"),
        )
        five_sonnet = _batch(
            *(_task_item("backlog-researcher", f"r{i}") for i in range(4)),
            _task_item("backlog-vision", "v1"),
        )
        two_fable = _batch(
            _task_item(FABLE_AGENT, "m1"),
            _task_item(FABLE_AGENT, "m2"),
        )
        six_total = _batch(
            *(_task_item("backlog-researcher", f"r{i}") for i in range(4)),
            _task_item("backlog-vision", "v1"),
            _task_item(FABLE_AGENT, "m1"),
        )
        results = self.exercise([
            {"toolName": "task", "input": four_sonnet_one_fable},
            {"toolName": "task", "input": five_sonnet},
            {"toolName": "task", "input": two_fable},
            {"toolName": "task", "input": six_total},
        ], caller=RESEARCH)
        self.assertIsNone(results[0])
        self.assertTrue(results[1]["block"])
        self.assertTrue(results[2]["block"])
        self.assertTrue(results[3]["block"])

    def test_research_task_rejects_model_async_and_nested_spawn(self) -> None:
        results = self.exercise([
            {"toolName": "task", "input": _batch(
                _task_item("backlog-researcher", "r1", model=OPUS),
            )},
            {"toolName": "task", "input": _batch(
                _task_item("backlog-researcher", "r1"),
                **{"async": True},
            )},
            {"toolName": "task", "input": _batch(
                _task_item("backlog-researcher", "r1"),
                background=True,
            )},
            {"toolName": "task", "input": _batch(
                _task_item("backlog-researcher", "r1", isolated=True),
            )},
            {"toolName": "hub", "input": {"op": "send", "to": "child"}},
        ], caller=RESEARCH)
        self.assertTrue(all(
            isinstance(result, dict) and result.get("block") for result in results
        ))


class ResearchPolicyBrokerTest(unittest.TestCase):
    def test_policy_caller_identity_reaches_extension_env(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module = load_broker(_policy(td), td)
            admitted = module.validate_request(
                _request(td, caller=RESEARCH), peer_uid=os.getuid())
            env = module.omp_environment(
                os.environ, final_path=Path(td) / "final.json", request=admitted)
            self.assertEqual(RESEARCH, env["OMP_DELEGATE_CALLER"])
            writer = module.validate_request(
                _request(td, caller=WRITER), peer_uid=os.getuid())
            writer_env = module.omp_environment(
                os.environ, final_path=Path(td) / "final.json", request=writer)
            self.assertEqual(WRITER, writer_env["OMP_DELEGATE_CALLER"])

    def test_fallback_models_are_caller_policy_specific(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module = load_broker(_policy(td), td)
            research = module.validate_request(
                _request(td, caller=RESEARCH), peer_uid=os.getuid())
            writer = module.validate_request(
                _request(td, caller=WRITER), peer_uid=os.getuid())
            self.assertEqual(
                ("xai-oauth/grok-4.6",),
                module.fallback_models(research),
            )
            self.assertEqual(
                ("xai-oauth/grok-4.6", "openai-codex/gpt-5.6-sol"),
                module.fallback_models(writer),
            )
            self.assertNotIn("gpt-5.6-luna", module.fallback_models(research))
            self.assertNotIn("gpt-5.6-luna", module.fallback_models(writer))

    def test_credential_providers_follow_only_the_caller_chain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module = load_broker(_policy(td), td)
            research = module.validate_request(
                _request(td, caller=RESEARCH), peer_uid=os.getuid())
            writer = module.validate_request(
                _request(td, caller=WRITER), peer_uid=os.getuid())
            self.assertEqual(
                ("anthropic", "xai-oauth"),
                module.credential_providers(research),
            )
            self.assertEqual(
                ("anthropic", "xai-oauth", "openai-codex"),
                module.credential_providers(writer),
            )
            calls: list[str] = []

            def fake_run(argv, **_kwargs):
                calls.append(argv[2])
                return subprocess.CompletedProcess(
                    argv, 0, f"key-{argv[2]}".encode(), b"")

            with mock.patch.object(module.subprocess, "run", fake_run):
                resolved = module.resolve_provider_api_keys(research)
            self.assertEqual(["anthropic", "xai-oauth"], calls)
            self.assertEqual(
                {"anthropic": "key-anthropic", "xai-oauth": "key-xai-oauth"},
                resolved,
            )
            self.assertNotIn("openai-codex", resolved)

    def test_retry_overlay_pins_only_the_request_model_chain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module = load_broker(_policy(td), td)
            request = module.validate_request(
                _request(td, caller=RESEARCH), peer_uid=os.getuid())
            path = module.write_retry_overlay(request, Path(td))
            value = json.loads(path.read_text())
            chain = ["xai-oauth/grok-4.6"]
            self.assertEqual(value, {"retry": {"fallbackChains": {
                OPUS: chain,
                "anthropic/claude-sonnet-5": chain,
                "anthropic/claude-fable-5": chain,
            }}})
            argv = module.omp_argv(request, 9, config_path=path)
            self.assertEqual(argv[argv.index("--config") + 1], str(path))


class ResearchFetchSecurityTest(unittest.TestCase):
    def test_private_targets_are_rejected_before_firecrawl(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = root / "runner.ts"
            runner.write_text(f'''import extension from {json.dumps(EXTENSION.as_uri())};
const tools = new Map<string, any>();
const handlers = new Map<string, Function>();
const scalar = {{ optional() {{ return this; }}, describe() {{ return this; }} }};
let calls = 0;
globalThis.fetch = async () => {{
  calls += 1;
  return new Response(JSON.stringify({{success:true,data:{{markdown:"private"}}}}),
                      {{status:200,headers:{{"content-type":"application/json"}}}});
}};
const pi = {{
  zod: {{string:()=>scalar,number:()=>scalar,array:()=>scalar,enum:()=>scalar,object:()=>scalar}},
  on: (n:string,h:Function) => handlers.set(n,h),
  registerTool: (t:any) => tools.set(t.name,t),
}};
extension(pi);
const tool = tools.get("backlog_fetch");
const a = await tool.execute("a", {{url:"http://127.0.0.1:8000/private"}});
const b = await tool.execute("b", {{url:"http://10.0.0.1/private"}});
console.log(JSON.stringify({{calls,results:[a,b]}}));''', encoding="utf-8")
            env = {**os.environ, "OMP_DELEGATE_CALLER": RESEARCH,
                   "OMP_DELEGATE_SANDBOX": "restricted-write",
                   "OMP_DELEGATE_READ_PATHS": "[]",
                   "OMP_DELEGATE_WRITE_PATTERNS": '["runs/**"]',
                   "OMP_DELEGATE_GIT_MODE": "none"}
            result = subprocess.run(
                ["node", str(runner)], env=env, text=True,
                capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["calls"], 0)
        self.assertTrue(all(row["isError"] for row in value["results"]))
        self.assertTrue(all("invalid url" in row["content"][0]["text"]
                            for row in value["results"]))


class ResearchPolicySchemaTest(unittest.TestCase):
    def test_schema_admits_policy_max_timeout_3600(self) -> None:
        schema = json.loads(SCHEMA.read_text())
        timeout = schema["$defs"]["request"]["properties"]["timeout"]
        self.assertEqual(3600, timeout["maximum"])


if __name__ == "__main__":
    unittest.main()
