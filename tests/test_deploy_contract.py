from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DeployContractTest(unittest.TestCase):
    def test_manifest_packages_portable_broker_surfaces(self) -> None:
        manifest = json.loads((ROOT / "deploy" / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual("hermes-omp-broker", manifest["module"])
        self.assertEqual(
            [
                {"source": "plugin", "destination": "plugins/hermes-omp-delegate", "kind": "tree"},
                {"source": "client/omp-invoke.py", "destination": "scripts/omp-invoke.py", "kind": "file"},
                {"source": "extension/omp-delegate-extension.ts", "destination": "omp-delegate-broker/extension.ts", "kind": "file"},
                {"source": "broker", "destination": "omp-delegate-broker/broker", "kind": "tree"},
                {"source": "skills/hermes-omp-delegation", "destination": "skills/hermes-omp-delegation", "kind": "tree"},
                {"source": "systemd", "destination": "omp-delegate-broker/systemd", "kind": "tree"},
            ],
            manifest["artifacts"],
        )


if __name__ == "__main__":
    unittest.main()
