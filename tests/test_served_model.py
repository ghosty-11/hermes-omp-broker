"""Fail-first contract: fallback results identify the model that actually served them."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "extension/omp-delegate-extension.ts"
CLIENT = ROOT / "client/omp-invoke.py"


class ExtensionServedModelTests(unittest.TestCase):
    def test_finalize_records_context_model_not_requested_model(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            final = root / "final.json"
            runner = root / "runner.ts"
            runner.write_text(f'''import extension from {json.dumps(EXTENSION.as_uri())};
const tools = new Map<string, any>();
const handlers = new Map<string, Function>();
const scalar = {{ optional() {{ return this; }}, describe() {{ return this; }} }};
const pi = {{zod:{{string:()=>scalar,number:()=>scalar,array:()=>scalar,enum:()=>scalar,object:()=>scalar}},on:(n:string,h:Function)=>handlers.set(n,h),registerTool:(t:any)=>tools.set(t.name,t)}};
extension(pi);
const ctx = {{cwd:{json.dumps(str(root))},model:{{provider:"xai-oauth",id:"grok-4.6"}}}};
await tools.get("broker_finalize").execute("id", {{summary:"Research completed with grounded evidence",verification:"manifest validated",gaps:"",verdict:"MET"}}, undefined, undefined, ctx);
console.log("ok");''', encoding="utf-8")
            env = {**os.environ, "OMP_DELEGATE_FINAL_PATH": str(final), "OMP_DELEGATE_SANDBOX": "workspace-write", "OMP_DELEGATE_CALLER": "backlog-maturation-research"}
            result = subprocess.run(["node", str(runner)], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(final.read_text(encoding="utf-8"))
            self.assertEqual(value["served_model"], "xai-oauth/grok-4.6")


class ClientServedModelTests(unittest.TestCase):
    def test_json_output_names_requested_and_served_models(self):
        spec = importlib.util.spec_from_file_location("omp_invoke_served", CLIENT)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        response = {"request_id": "r1", "final": {"summary": "Research completed with grounded evidence", "verification": ["manifest validated"], "gaps": [], "verdict": "MET", "served_model": "xai-oauth/grok-4.6"}}
        value = json.loads(mod.format_json_response(response, caller="backlog-maturation-research", requested_model="anthropic/claude-opus-5"))
        self.assertEqual(value["requested_model"], "anthropic/claude-opus-5")
        self.assertEqual(value["served_model"], "xai-oauth/grok-4.6")


if __name__ == "__main__":
    unittest.main()
