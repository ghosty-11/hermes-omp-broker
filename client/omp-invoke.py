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
ABSOLUTE_V2_TIMEOUT = 3630.0
RESPONSE_FIELDS = {
    "version", "exit_code", "stdout", "stderr", "timed_out",
    "process_group_clear", "final", "request_id",
}
STATUS_JOB_FIELDS = {
    "request_id", "task_id", "repository", "caller", "status", "result",
    "created_at", "updated_at",
}
STATUS_SUCCESS_FIELDS = {"version", "op", "ok", "job"}
STATUS_ERROR_FIELDS = {"version", "op", "ok", "error"}
FINAL_FIELDS = {"summary", "verification", "gaps", "verdict"}
OPTIONAL_FINAL_FIELDS = {"served_model", "findings", "structured_result"}
FINDING_FIELDS = {"file", "lines", "severity", "issue", "fix"}
FINDING_SEVERITIES = {"low", "medium", "high", "critical"}
FINAL_VERDICTS = {"MET", "PARTIALLY MET", "NOT MET"}
HEALTH_SUCCESS_FIELDS = {"version", "op", "ok"}
HEALTH_ERROR_FIELDS = {"version", "op", "ok", "error"}


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


def resolve_status_identity(env: Mapping[str, str]) -> tuple[str, str]:
    caller = env.get("OMP_INVOKED_BY", "delegate_to_omp")
    repository = env.get("OMP_REPOSITORY")
    policy_path = Path(env.get(
        "HERMES_OMP_POLICY",
        str(Path(__file__).with_name("policy.json")),
    ))
    try:
        value = json.loads(policy_path.read_text())
    except (OSError, ValueError, TypeError) as exc:
        raise InvocationError("status policy is unavailable") from exc
    repositories = value.get("repositories") if isinstance(value, dict) else None
    callers = value.get("callers") if isinstance(value, dict) else None
    caller_policy = callers.get(caller) if isinstance(callers, dict) else None
    allowed = caller_policy.get("repositories") if isinstance(caller_policy, dict) else None
    if (
        not isinstance(repository, str)
        or not repository
        or not isinstance(repositories, dict)
        or not isinstance(repositories.get(repository), dict)
        or not isinstance(repositories.get(repository, {}).get("path"), str)
        or not isinstance(allowed, list)
        or not all(isinstance(item, str) for item in allowed)
        or repository not in allowed
    ):
        raise InvocationError("status caller or repository is not admitted")
    return caller, repository


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = conn.recv(size - len(chunks))
        if not chunk:
            raise InvocationError("broker connection closed before response completed")
        chunks.extend(chunk)
    return bytes(chunks)


def _valid_findings(value: object) -> bool:
    if not isinstance(value, list) or len(value) > 32:
        return False
    for finding in value:
        if not isinstance(finding, dict) or set(finding) != FINDING_FIELDS:
            return False
        file = finding.get("file")
        path = Path(file) if isinstance(file, str) else None
        if (
            not isinstance(file, str)
            or not file
            or len(file) > 1_000
            or "\\" in file
            or "\n" in file
            or path is None
            or path.is_absolute()
            or path.as_posix() != file
            or any(part in ("", ".", "..") for part in path.parts)
        ):
            return False
        lines = finding.get("lines")
        if (
            not isinstance(lines, list)
            or not 1 <= len(lines) <= 20
            or any(
                not isinstance(line, int)
                or isinstance(line, bool)
                or not 1 <= line <= 10_000_000
                for line in lines
            )
            or lines != sorted(set(lines))
        ):
            return False
        if finding.get("severity") not in FINDING_SEVERITIES:
            return False
        for field in ("issue", "fix"):
            text = finding.get(field)
            if (
                not isinstance(text, str)
                or not 4 <= len(text.strip()) <= 2_000
                or text != text.strip()
            ):
                return False
    return True


def _valid_structured_result(value: object) -> bool:
    if not isinstance(value, str) or len(value.encode()) > 500_000:
        return False
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return False
    return isinstance(parsed, dict)


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
    if "findings" in value and not _valid_findings(value["findings"]):
        return False
    if "structured_result" in value and not _valid_structured_result(
        value["structured_result"]
    ):
        return False
    return True


def validate_response(
    value: object, *, version: int = 1,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != RESPONSE_FIELDS or value.get("version") != version:
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


def validate_status_response(
    value: object,
    *,
    request_id: str,
    caller: str,
    repository: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("version") != 1 or value.get("op") != "status":
        raise InvocationError("broker returned an invalid status response contract")
    if set(value) == STATUS_ERROR_FIELDS:
        if value.get("ok") is not False or value.get("error") != "job unavailable":
            raise InvocationError("broker returned an invalid status response contract")
        raise InvocationError("job unavailable")
    if set(value) != STATUS_SUCCESS_FIELDS or value.get("ok") is not True:
        raise InvocationError("broker returned an invalid status response contract")
    job = value.get("job")
    if not isinstance(job, dict) or set(job) != STATUS_JOB_FIELDS:
        raise InvocationError("broker returned an invalid status job")
    if not all(
        isinstance(job.get(name), str) and bool(job[name])
        for name in ("request_id", "task_id", "repository", "caller", "status")
    ):
        raise InvocationError("broker returned invalid status job text fields")
    if (
        job["request_id"] != request_id
        or job["caller"] != caller
        or job["repository"] != repository
    ):
        raise InvocationError("broker returned a mismatched status job")
    if not all(
        isinstance(job.get(name), int) and not isinstance(job[name], bool)
        for name in ("created_at", "updated_at")
    ):
        raise InvocationError("broker returned invalid status job timestamps")
    result = job.get("result")
    if result is not None and not isinstance(result, dict):
        raise InvocationError("broker returned an invalid status job result")
    return job


def request_status(
    socket_path: Path,
    *,
    request_id: str,
    caller: str,
    repository: str,
) -> dict[str, object]:
    if not request_id:
        raise InvocationError("status request identifier is empty")
    request = {
        "version": 1,
        "op": "status",
        "request_id": request_id,
        "caller": caller,
        "repository": repository,
    }
    payload = json.dumps(request, separators=(",", ":")).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(30)
            conn.connect(str(socket_path))
            conn.sendall(struct.pack("!I", len(payload)) + payload)
            conn.shutdown(socket.SHUT_WR)
            size = struct.unpack("!I", _recv_exact(conn, 4))[0]
            if size <= 0 or size > MAX_RESPONSE_BYTES:
                raise InvocationError("broker response is outside the size bound")
            response = json.loads(_recv_exact(conn, size))
    except (OSError, json.JSONDecodeError, struct.error) as exc:
        raise InvocationError(f"OMP broker request failed: {exc}") from exc
    return validate_status_response(
        response,
        request_id=request_id,
        caller=caller,
        repository=repository,
    )


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

def validate_health_response(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise InvocationError("broker returned an invalid health response contract")
    if set(value) == HEALTH_SUCCESS_FIELDS:
        if (
            value.get("version") == 2
            and value.get("op") == "health"
            and value.get("ok") is True
        ):
            return value
        raise InvocationError("broker returned an invalid health response contract")
    if set(value) == HEALTH_ERROR_FIELDS:
        if (
            value.get("version") == 2
            and value.get("op") == "health"
            and value.get("ok") is False
            and value.get("error") == "endpoint unavailable"
        ):
            raise InvocationError("endpoint unavailable")
    raise InvocationError("broker returned an invalid health response contract")


def health_broker_v2(socket_path: Path) -> dict[str, object]:
    payload = json.dumps(
        {"version": 2, "op": "health"}, separators=(",", ":")).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(30)
            conn.connect(str(socket_path))
            conn.sendall(struct.pack("!I", len(payload)) + payload)
            conn.shutdown(socket.SHUT_WR)
            size = struct.unpack("!I", _recv_exact(conn, 4))[0]
            if size <= 0 or size > MAX_RESPONSE_BYTES:
                raise InvocationError("broker response is outside the size bound")
            response = json.loads(_recv_exact(conn, size))
    except (OSError, json.JSONDecodeError, struct.error) as exc:
        raise InvocationError(f"OMP broker request failed: {exc}") from exc
    return validate_health_response(response)


def invoke_broker_v2(
    socket_path: Path, lease_id: str, op: str,
) -> dict[str, object]:
    """Redeem or inspect a server-fixed lease without sending authority text."""
    if not isinstance(lease_id, str) or not lease_id or op not in {"execute", "status"}:
        raise InvocationError("invalid protocol v2 lease request")
    request = {"version": 2, "op": op, "lease_id": lease_id}
    payload = json.dumps(request, separators=(",", ":")).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(ABSOLUTE_V2_TIMEOUT)
            conn.connect(str(socket_path))
            conn.sendall(struct.pack("!I", len(payload)) + payload)
            conn.shutdown(socket.SHUT_WR)
            size = struct.unpack("!I", _recv_exact(conn, 4))[0]
            if size <= 0 or size > MAX_RESPONSE_BYTES:
                raise InvocationError("broker response is outside the size bound")
            response = json.loads(_recv_exact(conn, size))
    except (OSError, json.JSONDecodeError, struct.error) as exc:
        raise InvocationError(f"OMP broker request failed: {exc}") from exc
    if op == "execute":
        return validate_response(response, version=2)
    if (
        not isinstance(response, dict)
        or response.get("version") != 2
        or response.get("op") != "status"
    ):
        raise InvocationError("broker returned an invalid status response contract")
    if set(response) == STATUS_ERROR_FIELDS:
        if response.get("ok") is False and response.get("error") == "job unavailable":
            raise InvocationError("job unavailable")
        raise InvocationError("broker returned an invalid status response contract")
    if set(response) != STATUS_SUCCESS_FIELDS or response.get("ok") is not True:
        raise InvocationError("broker returned an invalid status response contract")
    job = response.get("job")
    if not isinstance(job, dict) or set(job) != STATUS_JOB_FIELDS:
        raise InvocationError("broker returned an invalid status job")
    if not all(
        isinstance(job.get(name), str) and bool(job[name])
        for name in ("request_id", "task_id", "repository", "caller", "status")
    ):
        raise InvocationError("broker returned invalid status job text fields")
    if not all(
        isinstance(job.get(name), int) and not isinstance(job[name], bool)
        for name in ("created_at", "updated_at")
    ):
        raise InvocationError("broker returned invalid status job timestamps")
    if job.get("result") is not None and not isinstance(job["result"], dict):
        raise InvocationError("broker returned an invalid status job result")
    return job


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
    if "findings" in final:
        value["findings"] = final["findings"]
    return json.dumps(value, separators=(",", ":")) + "\n"


def main() -> int:
    args = sys.argv[1:]
    if "--status" in args:
        if args.count("--status") != 1:
            print("omp-invoke: expected --status REQUEST_ID and optional --json", file=sys.stderr)
            return 2
        status_index = args.index("--status")
        if status_index + 1 >= len(args):
            print("omp-invoke: expected --status REQUEST_ID and optional --json", file=sys.stderr)
            return 2
        request_id = args[status_index + 1]
        remaining = args[:status_index] + args[status_index + 2:]
        if remaining not in ([], ["--json"]):
            print("omp-invoke: expected --status REQUEST_ID and optional --json", file=sys.stderr)
            return 2
        try:
            caller, repository = resolve_status_identity(os.environ)
            socket_path = Path(os.environ.get(
                "OMP_DELEGATE_BROKER_SOCKET",
                str(_policy_socket(os.environ)),
            ))
            job = request_status(
                socket_path,
                request_id=request_id,
                caller=caller,
                repository=repository,
            )
            output = (
                json.dumps(job, separators=(",", ":")) + "\n"
                if remaining
                else (
                    f"request={job['request_id']} task={job['task_id']} "
                    f"status={job['status']}\n"
                )
            )
            sys.stdout.write(output)
        except InvocationError as exc:
            print(f"omp-invoke: {exc}", file=sys.stderr)
            return 1
        return 0

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
