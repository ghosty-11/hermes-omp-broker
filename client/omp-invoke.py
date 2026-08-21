#!/usr/bin/env python3
"""Invoke the fixed OMP delegation broker on behalf of an attributed Hermes caller."""

from __future__ import annotations

import dataclasses
import json
import os
import socket
import struct
import sys
import subprocess
from pathlib import Path
from typing import Mapping


BROKER_SOCKET = Path(os.environ.get("HERMES_OMP_BROKER_SOCKET", "run/omp-broker.sock"))
MODEL = os.environ.get("HERMES_OMP_MODEL", "provider/model")
MAX_PROMPT_CHARS = 500_000
MAX_RESPONSE_BYTES = 8_000_000
RESPONSE_FIELDS = {
    "version", "exit_code", "stdout", "stderr", "timed_out",
    "process_group_clear", "final", "request_id",
}
FINAL_FIELDS = {"summary", "verification", "gaps", "verdict"}
OPTIONAL_FINAL_FIELDS = {"served_model"}
FINAL_VERDICTS = {"MET", "PARTIALLY MET", "NOT MET"}


class InvocationError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class Policy:
    request_id: str
    task_id: str
    repository: str
    caller: str
    workspace: Path
    sandbox: str
    model: str
    timeout: float


def _git_common_dir(path: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--git-common-dir"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    common = Path(result.stdout.strip())
    if not common.is_absolute():
        common = path / common
    try:
        return common.resolve()
    except OSError:
        return None


def _git_toplevel(path: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return Path(result.stdout.strip()).resolve()
    except OSError:
        return None


def _is_worktree_of(candidate: Path, admitted: Path) -> bool:
    if not candidate.is_dir() or not admitted.is_dir():
        return False
    cand, adm = candidate.resolve(), admitted.resolve()
    if cand == adm:
        return False
    if _git_toplevel(cand) != cand:
        return False
    left, right = _git_common_dir(cand), _git_common_dir(adm)
    return left is not None and left == right


def _load_policy(env: Mapping[str, str]) -> tuple[dict[str, Path], dict[str, dict[str, object]]]:
    policy_path = Path(env.get(
        "HERMES_OMP_POLICY",
        str(Path(__file__).with_name("policy.json")),
    ))
    try:
        value = json.loads(policy_path.read_text())
        repositories = {
            str(name): Path(entry["path"]).resolve()
            for name, entry in value.get("repositories", {}).items()
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
        }
        callers = value.get("callers")
        if not isinstance(callers, dict):
            callers = {
                "delegate_to_omp": {
                    "repositories": list(repositories),
                    "sandbox": "workspace-write",
                }
            }
        return repositories, {
            str(name): entry
            for name, entry in callers.items()
            if isinstance(entry, dict)
        }
    except (OSError, ValueError, TypeError):
        return {}, {}

def _policy_model(env: Mapping[str, str], caller: str = "delegate_to_omp") -> str:
    """Per-caller pin first, then the global policy model, then the environment."""
    policy_path = Path(env.get(
        "HERMES_OMP_POLICY",
        str(Path(__file__).with_name("policy.json")),
    ))
    try:
        value = json.loads(policy_path.read_text())
    except (OSError, ValueError, TypeError):
        return env.get("HERMES_OMP_MODEL", MODEL)
    if not isinstance(value, dict):
        return env.get("HERMES_OMP_MODEL", MODEL)
    callers = value.get("callers")
    entry = callers.get(caller) if isinstance(callers, dict) else None
    pinned = entry.get("model") if isinstance(entry, dict) else None
    if isinstance(pinned, str) and pinned:
        return pinned
    model = value.get("model")
    if isinstance(model, str) and model:
        return model
    return env.get("HERMES_OMP_MODEL", MODEL)


def _caller_max_timeout(callers: Mapping[str, dict[str, object]], caller: str) -> float:
    """The caller's admitted ceiling — mirrors the broker's bound exactly."""
    entry = callers.get(caller)
    value = entry.get("max_timeout") if isinstance(entry, dict) else None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 810.0
    return min(float(value), 3600.0)


def _policy_socket(env: Mapping[str, str]) -> Path:
    policy_path = Path(env.get(
        "HERMES_OMP_POLICY",
        str(Path(__file__).with_name("policy.json")),
    ))
    try:
        value = json.loads(policy_path.read_text())
    except (OSError, ValueError, TypeError):
        return BROKER_SOCKET
    socket_path = value.get("socket") if isinstance(value, dict) else None
    return Path(socket_path) if isinstance(socket_path, str) and socket_path else BROKER_SOCKET


def _repository_for_caller(
    caller: str,
    cwd: Path,
    env: Mapping[str, str],
    repositories: Mapping[str, Path],
    callers: Mapping[str, dict[str, object]],
) -> tuple[str, Path, str]:
    caller_policy = callers.get(caller)
    if caller_policy is None:
        raise InvocationError(f"caller is not admitted: {caller}")
    allowed = caller_policy.get("repositories")
    if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
        raise InvocationError(f"caller policy is invalid: {caller}")
    selected = env.get("OMP_REPOSITORY")
    if selected is None:
        matches = [name for name in allowed if repositories.get(name) == cwd.resolve()]
        if len(matches) == 1:
            selected = matches[0]
        elif len(allowed) == 1:
            selected = allowed[0]
    if selected not in allowed or selected not in repositories:
        raise InvocationError(f"repository is not admitted for caller: {caller}")
    workspace = repositories[selected]
    sandbox = caller_policy.get("sandbox")
    if not isinstance(sandbox, str) or not sandbox:
        raise InvocationError(f"caller sandbox is invalid: {caller}")
    return selected, workspace, sandbox


POLICY_REPOSITORIES, CALLER_POLICIES = _load_policy(os.environ)

def resolve_policy(env: Mapping[str, str], cwd: Path) -> Policy:
    caller = env.get("OMP_INVOKED_BY", "delegate_to_omp")
    repositories, callers = _load_policy(env)
    if not repositories:
        if caller != "delegate_to_omp":
            raise InvocationError(f"caller is not admitted: {caller}")
        repositories = {cwd.name: cwd.resolve()}
        callers = {
            caller: {
                "repositories": [cwd.name],
                "sandbox": "workspace-write",
            }
        }
    repository, workspace, sandbox = _repository_for_caller(
        caller, cwd, env, repositories, callers,
    )
    request_id = env.get("OMP_REQUEST_ID") or os.urandom(8).hex()
    task_id = env.get("OMP_TASK_ID") or request_id
    requested = env.get("OMP_DELEGATE_WORKSPACE")
    if requested:
        req = Path(requested).resolve()
        if req != workspace and not _is_worktree_of(req, workspace):
            raise InvocationError("requested workspace does not match the caller policy")
        workspace = req
    try:
        timeout = float(env.get("OMP_DELEGATE_TIMEOUT", "780"))
    except ValueError as exc:
        raise InvocationError("timeout is not numeric") from exc
    if timeout <= 0 or timeout > _caller_max_timeout(callers, caller):
        raise InvocationError("timeout is outside the broker bound")
    model = _policy_model(env, caller)
    return Policy(
        request_id, task_id, repository, caller, workspace, sandbox, model, timeout,
    )


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = conn.recv(size - len(chunks))
        if not chunk:
            raise InvocationError("broker connection closed before response completed")
        chunks.extend(chunk)
    return bytes(chunks)


def _valid_final(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    keys = set(value)
    if not FINAL_FIELDS <= keys or not keys <= FINAL_FIELDS | OPTIONAL_FINAL_FIELDS:
        return False
    if not isinstance(value.get("summary"), str) or not value["summary"]:
        return False
    if not all(
        isinstance(value.get(name), list) and all(isinstance(item, str) for item in value[name])
        for name in ("verification", "gaps")
    ):
        return False
    if value.get("verdict") not in FINAL_VERDICTS:
        return False
    if "served_model" in value:
        served = value["served_model"]
        if not isinstance(served, str) or not served or len(served) > 512:
            return False
    return True


def validate_response(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != RESPONSE_FIELDS or value.get("version") != 1:
        raise InvocationError("broker returned an invalid response contract")
    if not isinstance(value.get("exit_code"), int):
        raise InvocationError("broker returned an invalid exit code")
    if not all(isinstance(value.get(name), str) for name in ("stdout", "stderr", "request_id")):
        raise InvocationError("broker returned invalid text fields")
    if not all(isinstance(value.get(name), bool) for name in ("timed_out", "process_group_clear")):
        raise InvocationError("broker returned invalid lifecycle fields")
    if value["exit_code"] != 0 or value["timed_out"] or not value["process_group_clear"]:
        detail = value["stderr"].strip() or "OMP worker did not complete cleanly"
        raise InvocationError(detail)
    if not _valid_final(value.get("final")):
        raise InvocationError("OMP worker did not produce a typed final result")
    return value


def invoke_broker(socket_path: Path, policy: Policy, prompt: str) -> dict[str, object]:
    if not prompt or len(prompt) > MAX_PROMPT_CHARS:
        raise InvocationError("prompt is empty or exceeds the broker bound")
    request = {
        "version": 1,
        "request_id": policy.request_id,
        "task_id": policy.task_id,
        "repository": policy.repository,
        "caller": policy.caller,
        "workspace": str(policy.workspace.resolve()),
        "sandbox": policy.sandbox,
        "model": policy.model,
        "prompt": prompt,
        "timeout": policy.timeout,
    }
    payload = json.dumps(request, separators=(",", ":")).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(policy.timeout + 30)
            conn.connect(str(socket_path))
            conn.sendall(struct.pack("!I", len(payload)) + payload)
            conn.shutdown(socket.SHUT_WR)
            size = struct.unpack("!I", _recv_exact(conn, 4))[0]
            if size <= 0 or size > MAX_RESPONSE_BYTES:
                raise InvocationError("broker response is outside the size bound")
            response = json.loads(_recv_exact(conn, size))
    except (OSError, json.JSONDecodeError, struct.error) as exc:
        raise InvocationError(f"OMP broker request failed: {exc}") from exc
    return validate_response(response)


def format_response(response: Mapping[str, object], *, caller: str) -> str:
    final = response["final"]
    if not isinstance(final, dict):
        raise InvocationError("typed final result is missing")
    lines = [
        str(final["summary"]),
        f"worker: OMP · caller={caller} · verdict={final['verdict']} · request={response['request_id']}",
    ]
    verification = final["verification"]
    gaps = final["gaps"]
    if verification:
        lines.append("verification: " + "; ".join(verification))
    if gaps:
        lines.append("gaps: " + "; ".join(gaps))
    return "\n".join(lines) + "\n"

def format_json_response(
    response: Mapping[str, object],
    *,
    caller: str,
    requested_model: str = "",
) -> str:
    final = response["final"]
    if not isinstance(final, dict):
        raise InvocationError("typed final result is missing")
    served = final.get("served_model")
    value = {
        "caller": caller,
        "request_id": response["request_id"],
        "summary": final["summary"],
        "verification": final["verification"],
        "gaps": final["gaps"],
        "verdict": final["verdict"],
        "requested_model": requested_model,
        "served_model": served if isinstance(served, str) else "",
    }
    return json.dumps(value, separators=(",", ":")) + "\n"


def main() -> int:
    args = sys.argv[1:]
    json_output = bool(args and args[0] == "--json")
    if json_output:
        args.pop(0)
    if len(args) > 1:
        print("omp-invoke: expected one prompt argument or stdin", file=sys.stderr)
        return 2
    prompt = args[0] if args else sys.stdin.read()
    try:
        policy = resolve_policy(os.environ, Path.cwd())
        socket_path = Path(os.environ.get(
            "OMP_DELEGATE_BROKER_SOCKET",
            str(_policy_socket(os.environ)),
        ))
        response = invoke_broker(socket_path, policy, prompt)
        output = (
            format_json_response(
                response, caller=policy.caller, requested_model=policy.model,
            )
            if json_output
            else format_response(response, caller=policy.caller)
        )
        sys.stdout.write(output)
    except InvocationError as exc:
        print(f"omp-invoke: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
