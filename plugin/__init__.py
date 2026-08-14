"""Narrow Hermes tool adapter for an operator-owned OMP broker.

Repository paths and execution policy are deployment-owned. The model chooses a repository
key and supplies a bounded standalone brief; post-run Git evidence is observed rather than
trusted from model prose.
"""
from __future__ import annotations

import logging
import os
import socket
import stat
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

POLICY_FILE = os.environ.get(
    "HERMES_OMP_POLICY",
    os.path.join(os.path.dirname(__file__), "policy.json"),
)


def _load_policy() -> dict[str, Any]:
    if not POLICY_FILE:
        return {}
    import json
    try:
        with open(POLICY_FILE, encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


POLICY = _load_policy()
INVOKE = os.environ.get("HERMES_OMP_INVOKE", str(POLICY.get("client", "omp-invoke")))
BROKER_SOCKET = os.environ.get(
    "HERMES_OMP_BROKER_SOCKET",
    str(POLICY.get("socket", "run/omp-broker.sock")),
)


def _allowed_repos() -> dict[str, str]:
    repositories = POLICY.get("repositories", {})
    callers = POLICY.get("callers", {})
    delegate = callers.get("delegate_to_omp", {}) if isinstance(callers, dict) else {}
    allowed = delegate.get("repositories", []) if isinstance(delegate, dict) else []
    if not isinstance(repositories, dict) or not isinstance(allowed, list):
        return {}
    return {
        str(name): str(value["path"])
        for name, value in repositories.items()
        if name in allowed
        and isinstance(value, dict)
        and isinstance(value.get("path"), str)
    }


ALLOWED_REPOS = _allowed_repos()

# Set here, not by the caller: a delegating agent must not be able to widen its own reach.
TIMEOUT_S = 780
BRIEF_MIN_CHARS = 60
BRIEF_MAX_CHARS = 8000
OUTPUT_MAX_CHARS = 4000
BROKER_PROBE_TIMEOUT_S = 2.0


def _broker_reachable(path: str) -> bool:
    """A socket that cannot accept must never advertise the tool.

    Existence is not availability: a stale or unrelated file at the socket path would
    offer a delegating agent its only write path and then fail at call time. The probe
    connects and closes without sending a frame, so the broker records no job.
    """
    try:
        if not stat.S_ISSOCK(os.stat(path).st_mode):
            return False
    except OSError:
        return False
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(BROKER_PROBE_TIMEOUT_S)
        probe.connect(path)
    except OSError:
        return False
    finally:
        probe.close()
    return True


def _available() -> bool:
    return (
        os.path.isfile(INVOKE)
        and os.access(INVOKE, os.X_OK)
        and _broker_reachable(BROKER_SOCKET)
    )


def _git(repo: str, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True, text=True, timeout=60, shell=False,
        )
        return (proc.stdout or "").strip()
    except Exception as e:
        return f"(git {' '.join(args)} failed: {type(e).__name__})"


def _git_porcelain(repo: str, *args: str) -> str:
    """Return porcelain output without stripping its significant leading status space."""
    try:
        proc = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True, text=True, timeout=60, shell=False,
        )
        return proc.stdout or ""
    except Exception:
        return ""


def _clean_write_baseline(repo: str) -> tuple[str, str] | tuple[None, str]:
    """Return an attributable Git baseline, or a fail-closed refusal reason."""
    try:
        head = subprocess.run(
            ["git", "-C", repo, "rev-parse", "--verify", "HEAD^{commit}"],
            capture_output=True, text=True, timeout=60, shell=False,
        )
        if head.returncode != 0 or not (head.stdout or "").strip():
            return None, "the repository does not have a valid Git HEAD"
        status = subprocess.run(
            [
                "git", "-C", repo, "status", "--porcelain=v1",
                "--untracked-files=all", "--ignore-submodules=none",
            ],
            capture_output=True, text=True, timeout=60, shell=False,
        )
        if status.returncode != 0:
            return None, "the repository's clean state could not be verified"
    except Exception as exc:
        logger.warning("delegate_to_omp: Git preflight failed: %s", type(exc).__name__)
        return None, "the repository's clean state could not be verified"
    if status.stdout:
        return None, "the repository is not clean"
    return (head.stdout or "").strip(), status.stdout or ""


def _handle(args: dict, **_kwargs: Any) -> str:
    brief = str((args or {}).get("brief") or "").strip()
    repo_name = str((args or {}).get("repo") or "").strip()
    task_id = str((args or {}).get("task_id") or "").strip()
    if not task_id:
        return "delegate_to_omp: 'task_id' is required for request/result correlation."

    if len(brief) < BRIEF_MIN_CHARS:
        return (
            f"delegate_to_omp: 'brief' is too short ({len(brief)} chars). A brief needs a "
            "goal, constraints, files in scope, a definition of done, and what NOT to touch. "
            "Write the brief; that is the job this tool exists to receive."
        )
    if len(brief) > BRIEF_MAX_CHARS:
        return f"delegate_to_omp: 'brief' is too long (max {BRIEF_MAX_CHARS} chars). Split the work."
    if repo_name not in ALLOWED_REPOS:
        return (
            f"delegate_to_omp: unknown repo {repo_name!r}. Choose one of: "
            f"{', '.join(sorted(ALLOWED_REPOS))}. Paths are not accepted."
        )
    repo = ALLOWED_REPOS[repo_name]

    # A path-set diff cannot attribute edits to a file that was already dirty. Refuse
    # before starting the writer unless Git can provide a clean, committed baseline.
    # Intentional work on existing changes belongs in a dedicated commit or worktree.
    before, dirty_before = _clean_write_baseline(repo)
    if before is None:
        return (
            "delegate_to_omp: refused to start a writing delegation because "
            f"{dirty_before}. Preserve the existing work, then use a clean committed "
            "worktree so post-run evidence can be attributed."
        )

    env = dict(os.environ)
    env["OMP_INVOKED_BY"] = "delegate_to_omp"
    env["OMP_DELEGATE_TIMEOUT"] = str(TIMEOUT_S)
    env["OMP_TASK_ID"] = task_id
    env["OMP_REPOSITORY"] = repo_name
    try:
        proc = subprocess.run(
            [INVOKE, brief],
            cwd=repo, env=env, capture_output=True, text=True,
            shell=False,
        )
        summary = (proc.stdout or "").strip()
        rc = proc.returncode
    except Exception as e:
        logger.exception("delegate_to_omp: invocation failed")
        return f"delegate_to_omp: could not start the run ({type(e).__name__}). Nothing was changed."

    after = _git(repo, "rev-parse", "HEAD")
    dirty_after = _git_porcelain(repo, "status", "--porcelain")
    committed = _git(repo, "log", "--oneline", f"{before}..{after}") if before != after else ""

    # Attribute honestly. `git diff --stat` shows EVERY uncommitted change, including work
    # that was already in the tree before this run — so reporting it raw makes the delegated
    # run look responsible for someone else's edits. That is not a cosmetic issue: on the
    # first real use (2026-08-08) it produced a false accusation, with the caller correctly
    # reporting that OMP had "also modified" a file it never touched. A tool whose
    # evidence over-reports is worse than one with no evidence, because it gets believed.
    def _paths(porcelain: str) -> set:
        # Tolerant of both the raw form (" M path") and a stripped first line ("M path"),
        # so this cannot silently regress if a caller strips again. Renames ("R  a -> b")
        # keep the destination, which is the file that now exists.
        out = set()
        for ln in porcelain.splitlines():
            if len(ln) < 4:
                continue
            path = ln[2:].strip() if ln[:2].strip() != ln[:1].strip() or ln[0] == " " \
                else ln.strip().split(None, 1)[-1]
            path = path.split(" -> ")[-1].strip().strip('"')
            if path:
                out.add(path)
        return out

    pre_existing = _paths(dirty_before)
    now_dirty = _paths(dirty_after)
    touched_here = sorted(now_dirty - pre_existing)
    already_dirty = sorted(now_dirty & pre_existing)
    diffstat = "\n".join(
        f"  {line}" for line in _git(repo, "diff", "--stat", "--", *touched_here).splitlines()
    ) if touched_here else ""

    if len(summary) > OUTPUT_MAX_CHARS:
        summary = summary[:OUTPUT_MAX_CHARS] + "\n… (truncated)"

    changed = bool(committed) or bool(touched_here)

    lines = [
        f"DELEGATED RUN — repository: {repo_name}, exit code: {rc}",
        "",
        "MODEL SUMMARY (a claim, not evidence):",
        summary or "(no output)",
        "",
        "OBSERVED EVIDENCE — attributable to THIS run:",
        f"  files changed: {', '.join(touched_here) if touched_here else 'none'}",
        diffstat,
        f"  new commits:   {committed or 'none'}",
    ]
    if already_dirty:
        lines += [
            "",
            "ALREADY MODIFIED BEFORE THIS RUN (not caused by it, do not report as such): "
            + ", ".join(already_dirty),
        ]
    if not changed:
        lines += [
            "",
            "NOTHING CHANGED IN THE REPO. If the summary above claims work was done, the "
            "claim is wrong — report the discrepancy rather than repeating it.",
        ]
    else:
        lines += [
            "",
            "Check the evidence against your definition of done before reporting success. "
            "A summary saying 'done' is not the same as the work being done.",
        ]
    return "\n".join(lines)


_SCHEMA = {
    "name": "delegate_to_omp",
    "description": (
        "Hand a bounded implementation or review brief to OMP through an operator-owned "
        "broker. Repository keys and execution policy are server-owned. Returns the model "
        "outcome with observed Git evidence so the caller can verify the result."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "brief": {
                "type": "string",
                "description": (
                    "The implementation brief. Must include: goal, constraints, files in "
                    "scope, definition of done, and what NOT to touch. OMP has no context "
                    "from this conversation, so the brief must stand alone."
                ),
            },
            "repo": {
                "type": "string",
                "enum": sorted(ALLOWED_REPOS),
                "description": "Which repository to work in. Names only; paths are rejected.",
            },
            "task_id": {
                "type": "string",
                "description": "Existing task-ledger identifier used to correlate request and result.",
            },
        },
        "required": ["brief", "repo", "task_id"],
    },
}


def register(ctx) -> None:
    try:
        ctx.register_tool(
            name=_SCHEMA["name"],
            toolset="omp_delegate",
            schema=_SCHEMA,
            handler=_handle,
            check_fn=_available,
            description=_SCHEMA["description"],
        )
        logger.info("hermes-omp-delegate: registered delegate_to_omp (%d repositories)", len(ALLOWED_REPOS))
    except Exception:
        logger.exception("hermes-omp-delegate: failed to register delegate_to_omp")
