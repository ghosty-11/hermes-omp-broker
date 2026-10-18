"""Two-stage maturation tool and fallback contracts (v4).

`backlog-maturation-research` is the Opus staged-only orchestrator: caller
identity must reach the trusted extension, which then admits only `task`,
read/grep/glob-style staging IO, `todo`, `yield`, and `broker_finalize`.
Outbound research moved to the deterministic egress launcher, so the caller
has no `backlog_search`, no `backlog_fetch`, and no generic outbound web
tool; the extension must not even register those tools for it.
`backlog-maturation` is the Opus Wiki writer and must not receive task/spawn
surfaces. Task input is structural: the three named agents, at most five
children (four Sonnet + one Fable), no caller-supplied model, no
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
        "HERMES_OMP_LOCK_DIR": str(Path(td) / "locks"),
        "HERMES_OMP_AUDIT_LOG": str(Path(td) / "audit" / "audit.jsonl"),
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
        expected_model: str | None = None,
        served_model: dict[str, str] | None = None,
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
const ctx = {{cwd:{json.dumps(str(workspace))}, model:{json.dumps(served_model)}}};
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
            env.pop("OMP_DELEGATE_NO_CHILDREN", None)
            env.pop("OMP_DELEGATE_EXPECTED_MODEL", None)
            if expected_model is not None:
                env["OMP_DELEGATE_NO_CHILDREN"] = "1"
                env["OMP_DELEGATE_EXPECTED_MODEL"] = expected_model
            result = subprocess.run(
                ["node", str(runner)], env=env, text=True,
                capture_output=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def test_restricted_research_rejects_children_and_mismatched_tool_context(self) -> None:
        model = "openai-codex/gpt-6-sol"
        events = [
            {"toolName": "task", "input": _valid_batch()},
            {"toolName": "spawn", "input": {}},
            {"toolName": "read", "input": {"path": "runs/manifest.json"}},
            {"toolName": "broker_finalize", "input": {}},
        ]
        approved = self.exercise(events, caller=RESEARCH, expected_model=model,
                                 served_model={"provider": "openai-codex", "id": "gpt-6-sol"})
        self.assertTrue(approved[0]["block"])
        self.assertTrue(approved[1]["block"])
        self.assertIsNone(approved[2])
        self.assertIsNone(approved[3])
        for served in (None, {"provider": "gateway", "id": "other"}):
            results = self.exercise(events, caller=RESEARCH, expected_model=model,
                                    served_model=served)
            self.assertTrue(all(result["block"] for result in results))
        normal = self.exercise([events[0]], caller=RESEARCH)
        self.assertIsNone(normal[0])

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

    def test_research_is_staged_only_with_no_outbound_tool_surface(self) -> None:
        results = self.exercise([
            {"toolName": "task", "input": _valid_batch()},
            {"toolName": "read", "input": {"path": "runs/manifest.json"}},
            {"toolName": "write", "input": {"path": "runs/manifest.json", "content": "{}"}},
            {"toolName": "grep", "input": {"pattern": "claim", "path": "runs"}},
            {"toolName": "glob", "input": {"path": "runs/**"}},
            {"toolName": "yield", "input": {"summary": "worker result"}},
            {"toolName": "backlog_search", "input": {"query": "gap"}},
            {"toolName": "backlog_fetch", "input": {"url": "https://example.com"}},
            {"toolName": "web_search", "input": {"query": "unbounded"}},
            {"toolName": "web_fetch", "input": {"url": "https://example.com"}},
            {"toolName": "fetch", "input": {"url": "https://example.com"}},
            {"toolName": "browser", "input": {"url": "https://example.com"}},
            {"toolName": "curl", "input": {"url": "https://example.com"}},
            {"toolName": "hub", "input": {"op": "list"}},
        ], caller=RESEARCH, sandbox="restricted-write",
            write_patterns=["runs/**"])
        for index in range(6):
            self.assertIsNone(results[index], results[index])
        for index in range(6, len(results)):
            self.assertTrue(
                isinstance(results[index], dict) and results[index]["block"],
                results[index],
            )
            self.assertEqual(
                "Tool is outside the OMP delegation workspace policy",
                results[index]["reason"],
            )

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
    def test_restricted_model_disables_auxiliary_inference_and_retains_trace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td)
            entry = policy["callers"][RESEARCH]
            entry.update(model="openai-codex/gpt-6-sol", fallback_models=[],
                         fallback_selectors=[], restricted_model=True)
            module = load_broker(policy, td)
            payload = _request(td, caller=RESEARCH)
            payload["model"] = entry["model"]
            admitted = module.validate_request(payload, peer_uid=os.getuid())
            overlay_path = module.write_retry_overlay(admitted, Path(td))
            overlay = json.loads(overlay_path.read_text())
            self.assertIs(overlay["retry"].get("modelFallback"), False)
            self.assertIs(overlay["advisor"]["enabled"], False)
            self.assertEqual((), module.fallback_models(admitted))
            environment = module.omp_environment(
                os.environ, final_path=Path(td) / "final.json", request=admitted)
            self.assertEqual("1", environment["OMP_DELEGATE_NO_CHILDREN"])
            self.assertEqual(entry["model"], environment["OMP_DELEGATE_EXPECTED_MODEL"])
            argv = module.omp_argv(admitted, 9, config_path=overlay_path)
            self.assertNotIn("--no-session", argv)
            self.assertIn("--session-dir", argv)
            with self.assertRaises(module.ProtocolError):
                module.omp_argv(admitted, 9)

    def test_restricted_policy_refuses_implicit_or_cross_model_routes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td)
            entry = policy["callers"][RESEARCH]
            entry.update(model="openai-codex/gpt-6-sol", fallback_models=[],
                         fallback_selectors=[], restricted_model=True)
            module = load_broker(policy, td)
            payload = _request(td, caller=RESEARCH)
            payload["model"] = entry["model"]
            self.assertTrue(module.validate_request(payload, peer_uid=os.getuid()).restricted_model)
            for change in (
                {"restricted_model": "true"},
                {"model": None},
                {"fallback_models": None},
                {"fallback_models": ["gateway/other"]},
                {"fallback_selectors": ["gateway/other"]},
            ):
                with self.subTest(change=change):
                    saved = dict(entry)
                    entry.update(change)
                    with mock.patch.dict(module.CALLER_POLICIES, {RESEARCH: dict(entry)}):
                        with self.assertRaises(module.ProtocolError):
                            module.validate_request(payload, peer_uid=os.getuid())
                    entry.clear()
                    entry.update(saved)
            payload["restricted_model"] = False
            with self.assertRaises(module.ProtocolError):
                module.validate_request(payload, peer_uid=os.getuid())

    def test_unmarked_caller_keeps_session_and_env_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module = load_broker(_policy(td), td)
            request = module.validate_request(
                _request(td, caller=WRITER), peer_uid=os.getuid())
            with mock.patch.dict(os.environ, {
                "OMP_DELEGATE_NO_CHILDREN": "1",
                "OMP_DELEGATE_EXPECTED_MODEL": "untrusted/model",
            }):
                env = module.omp_environment(
                    os.environ, final_path=Path(td) / "final.json", request=request)
            self.assertNotIn("OMP_DELEGATE_NO_CHILDREN", env)
            self.assertNotIn("OMP_DELEGATE_EXPECTED_MODEL", env)
            overlay = module.write_retry_overlay(request, Path(td))
            self.assertNotIn("modelFallback", json.loads(overlay.read_text())["retry"])
            argv = module.omp_argv(request, 9, config_path=overlay)
            self.assertIn("--no-session", argv)
            self.assertNotIn("--session-dir", argv)

    def test_restricted_trace_validates_entire_session_tree(self) -> None:
        expected = "openai-codex/gpt-6-sol"
        primary = {"type": "model_change", "model": expected}
        assistant = {"type": "message", "message": {
            "role": "assistant", "provider": "openai-codex", "model": "gpt-6-sol"}}
        cases = {
            "approved": ([{"type": "session"}, primary, assistant], False),
            "missing_trace": (None, True),
            "missing_assistant_identity": ([{"type": "session"}, primary, {
                "type": "message", "message": {"role": "assistant", "model": "gpt-6-sol"}}], True),
            "offprimary_transition": ([{"type": "session"}, primary,
                {"type": "model_change", "model": "gateway/other"}, assistant,
                primary, assistant], True),
            "offprimary_assistant": ([{"type": "session"}, primary, {
                "type": "message", "message": {"role": "assistant", "provider": "gateway",
                                              "model": "other"}}, assistant], True),
            "incomplete_transition": ([{"type": "session"}, {
                "type": "model_change", "model": "gpt-6-sol"}, assistant], True),
        }
        with tempfile.TemporaryDirectory() as td:
            module = load_broker(_policy(td), td)
            for name, (rows, refused) in cases.items():
                with self.subTest(case=name):
                    directory = Path(td) / name
                    directory.mkdir()
                    if rows is not None:
                        (directory / "primary.jsonl").write_text(
                            "".join(json.dumps(row) + "\n" for row in rows))
                    self.assertEqual(refused, module.validate_restricted_trace(
                        directory, expected) is not None)
            extra = Path(td) / "auxiliary"
            extra.mkdir()
            for name in ("primary.jsonl", "child.jsonl"):
                (extra / name).write_text(
                    "".join(json.dumps(row) + "\n" for row in cases["approved"][0]))
            self.assertIn("exactly one", module.validate_restricted_trace(extra, expected))
            corrupt = Path(td) / "corrupt"
            corrupt.mkdir()
            (corrupt / "primary.jsonl").write_text("{not json}\n")
            self.assertIsNotNone(module.validate_restricted_trace(corrupt, expected))
            nested = Path(td) / "nested"
            (nested / "child").mkdir(parents=True)
            (nested / "primary.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in cases["approved"][0]))
            (nested / "child" / "aux.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in cases["approved"][0]))
            self.assertIn("exactly one", module.validate_restricted_trace(nested, expected))

    def test_fake_omp_restricted_run_accepts_only_verified_trace(self) -> None:
        expected = "openai-codex/gpt-6-sol"
        primary = [{"type": "session"}, {"type": "model_change", "model": expected},
                   {"type": "message", "message": {
                       "role": "assistant", "provider": "openai-codex", "model": "gpt-6-sol"}}]
        scenarios = {
            "approved": primary,
            "missing": None,
            "missing_assistant_identity": [
                *primary[:2], {"type": "message", "message": {
                    "role": "assistant", "model": "gpt-6-sol"}}],
            "offprimary_assistant": [
                *primary, {"type": "message", "message": {
                    "role": "assistant", "provider": "gateway", "model": "other"}},
                primary[-1]],
            "offprimary_then_return": [
                *primary, {"type": "model_change", "model": "gateway/other"},
                {"type": "model_change", "model": expected}, primary[-1]],
            "auxiliary": [primary, primary],
            "final_mismatch": primary,
            "final_missing_identity": primary,
        }
        for name, rows in scenarios.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                policy = _policy(td)
                policy["callers"][RESEARCH].update(
                    model=expected, fallback_models=[], fallback_selectors=[],
                    restricted_model=True)
                module = load_broker(policy, td)
                payload = _request(td, caller=RESEARCH)
                payload["model"] = expected
                request = module.validate_request(payload, peer_uid=os.getuid())
                fake = Path(td) / "fake-omp"
                fake.write_text(f'''#!{sys.executable}
import json, os, sys
from pathlib import Path
args = sys.argv
sessions = Path(args[args.index("--session-dir") + 1])
sessions.mkdir()
rows = {rows!r}
if rows is not None:
    traces = rows if {name == "auxiliary"!r} else [rows]
    for index, trace in enumerate(traces):
        (sessions / f"{{index}}.jsonl").write_text(
            "".join(json.dumps(item) + "\\n" for item in trace))
Path(os.environ["OMP_DELEGATE_FINAL_PATH"]).write_text(json.dumps({{
    "summary": "Fake run with a typed outcome", "verification": ["fixture"],
    "gaps": [], "verdict": "MET",
    **({{}} if {name == "final_missing_identity"!r} else
       {{"served_model": {"gateway/other" if name == "final_mismatch" else expected!r}}})
}}))
''')
                fake.chmod(0o700)
                with mock.patch.object(module, "OMP_BIN", fake), mock.patch.object(
                    module, "WORKER_SOCKET", ""), mock.patch.object(
                    module, "resolve_provider_api_keys", return_value={}
                ), mock.patch.object(module, "_process_group_exists", return_value=False):
                    import socket
                    parent, child = socket.socketpair()
                    with parent, child:
                        response = module.run_request(request, child)
                self.assertEqual(name == "approved", response["final"] is not None)
                self.assertEqual(name == "approved", response["exit_code"] == 0)
                self.assertEqual(
                    "completed" if name == "approved" else "failed",
                    module.JOB_STORE.get("req")["status"])
                [retained] = list(module.JOB_STORE.root.glob("restricted-*"))
                self.assertTrue((retained / "final.json").exists())
                self.assertTrue((retained / "sessions").is_dir())

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

    def test_hookless_commit_flag_flows_from_caller_policy_only(self) -> None:
        """hookless_commit is policy authority, never request authority: the
        delegated bash sandbox cannot run repository git hooks whose runtimes
        resolve through the user's home, so policy marks such callers
        hookless and the flag alone widens the scoped-git commit grammar
        with one trailing --no-verify."""
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td)
            policy["callers"][WRITER]["hookless_commit"] = True
            module = load_broker(policy, td)
            marked = module.validate_request(
                _request(td, caller=WRITER), peer_uid=os.getuid())
            env = module.omp_environment(
                os.environ, final_path=Path(td) / "final.json", request=marked)
            self.assertEqual("1", env["OMP_DELEGATE_HOOKLESS_COMMIT"])

        with tempfile.TemporaryDirectory() as td:
            module = load_broker(_policy(td), td)
            unmarked = module.validate_request(
                _request(td, caller=WRITER), peer_uid=os.getuid())
            env = module.omp_environment(
                os.environ, final_path=Path(td) / "final.json", request=unmarked)
            self.assertEqual("0", env["OMP_DELEGATE_HOOKLESS_COMMIT"])

        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td)
            policy["callers"][WRITER]["hookless_commit"] = "yes"
            module = load_broker(policy, td)
            with self.assertRaisesRegex(module.ProtocolError, "hookless"):
                module.validate_request(
                    _request(td, caller=WRITER), peer_uid=os.getuid())

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


class ResearchOutboundSurfaceRemovedTest(unittest.TestCase):
    """The extension must register no outbound tool for the research caller."""

    def test_no_outbound_tool_is_registered_and_nothing_reaches_fetch(self) -> None:
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
  return new Response("{{}}", {{status:200}});
}};
const pi = {{
  zod: {{string:()=>scalar,number:()=>scalar,array:()=>scalar,enum:()=>scalar,object:()=>scalar}},
  on: (n:string,h:Function) => handlers.set(n,h),
  registerTool: (t:any) => tools.set(t.name,t),
}};
extension(pi);
const decisions = [];
const ctx = {{cwd:{json.dumps(str(root))}}};
for (const name of ["backlog_search","backlog_fetch","web_search","web_fetch","fetch","browser"]) {{
  decisions.push(await handlers.get("tool_call")!({{toolName:name,input:{{query:"q",url:"https://example.com"}}}}, ctx));
}}
console.log(JSON.stringify({{
  calls,
  registered: Array.from(tools.keys()).sort(),
  decisions,
}}));''', encoding="utf-8")
            env = {**os.environ, "OMP_DELEGATE_CALLER": RESEARCH,
                   "OMP_DELEGATE_SANDBOX": "restricted-write",
                   "OMP_DELEGATE_READ_PATHS": "[]",
                   "OMP_DELEGATE_WRITE_PATTERNS": '["runs/**"]',
                   "OMP_DELEGATE_GIT_MODE": "none",
                   "OMP_DELEGATE_FINAL_PATH": str(root / "final.json"),
                   "OMP_DELEGATE_CREATE_ONLY": "0"}
            result = subprocess.run(
                ["node", str(runner)], env=env, text=True,
                capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(0, value["calls"])
        self.assertEqual(["broker_finalize"], value["registered"])
        for decision in value["decisions"]:
            self.assertTrue(
                isinstance(decision, dict) and decision.get("block"), decision)


class ResearchPolicySchemaTest(unittest.TestCase):
    def test_schema_admits_policy_max_timeout_3600(self) -> None:
        schema = json.loads(SCHEMA.read_text())
        timeout = schema["$defs"]["request"]["properties"]["timeout"]
        self.assertEqual(3600, timeout["maximum"])


if __name__ == "__main__":
    unittest.main()
