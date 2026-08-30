# Policy

Policy is server-owned configuration. Repository keys map to paths. Caller entries select repository keys, sandbox mode, extra read roots, restricted-write patterns, scoped Git mode, and optional skills. The request schema never authorizes a filesystem path or widens a caller entry.

One `model` admits jobs globally. A caller entry may pin its own `model`, which then
replaces the global one for that caller only — this is per-caller pinning, not a role
system; the request still names the model explicitly and a mismatch is rejected before
OMP starts. A caller entry may also raise its own `max_timeout` ceiling in seconds; the
broker bounds it at 3600 regardless of policy, and callers without one keep the 810
default. A caller entry may list `fallback_models` as `provider/model` ids. The broker mints
credentials only for the pinned model and those rungs, then writes a mode-0600 per-request
`--config` overlay keyed by the exact primary model. Optional server-owned
`fallback_selectors` apply that same chain to named child models; this is how a bounded
research caller covers Sonnet/Fable workers without installing a global `anthropic/*`
chain that other callers could inherit. Callers without `fallback_models` keep the
service-wide default. Invalid entries fail before OMP starts. The request cannot supply or
widen model, timeout, selectors, or fallback chain.

The broker copies the admitted caller name into the child as `OMP_DELEGATE_CALLER`. The
trusted extension uses that name to choose the tool surface. Callers that do not name a
research surface keep the existing workspace tools. `backlog-maturation` stays
restricted-write and cannot call `task`, `backlog_search`, or `backlog_fetch`.
`backlog-maturation-research` may read admitted staging/Wiki/media roots, write only its
restricted staging patterns, call `todo` and `broker_finalize`, and invoke at most five
allowlisted research agents (`backlog-researcher`, `backlog-vision`, and at most one
`backlog-researcher-max`). Their operator-owned definitions must carry `blocking: true`;
the task input cannot override model, tools, isolation or spawn behavior. The extension
enforces restricted writes for this caller even if sandbox configuration drifts, preventing
project `.omp/agents` from shadowing those names.

The broker-owned adapters contact only loopback SearXNG and Firecrawl. `backlog_fetch`
accepts only default-port public HTTP(S) targets whose resolved addresses are all public;
loopback, private, link-local, reserved, credential-bearing and alternate-port URLs fail
before Firecrawl. Adapter bodies and deadlines are bounded. Results return as labelled
untrusted data or explicit failures. Research cannot use bash, hub, `web_search`, browser,
or MCP. Caller and model authority remain server policy.

`workspace-write` permits the admitted repository. `read-only` denies writes and shell. `restricted-write` admits only relative paths matching configured patterns; shell stays denied unless `git_mode` is `scoped`, which permits bounded status, log, diff, add, and commit operations on those paths. Deployment overlays may add local repositories, identities, and values without modifying reusable package code.

## Caller-specific workspace roots

Use `workspace_roots` when a caller must work in an isolated mirror that does not
share Git metadata with the repository's canonical path. The field maps an admitted
repository key to a list of absolute root directories:

```json
{
  "repositories": ["wiki"],
  "workspace_roots": {
    "wiki": ["/srv/review/worktrees/wiki"]
  }
}
```

The broker accepts an existing workspace only when all of the following conditions
hold:

- The requested path is a nonsymlink Git toplevel strictly beneath an exact configured
  root.
- The root belongs to the caller and an admitted repository key.
- The workspace and canonical repository have the same normalized Git remote identity.

The broker does not create roots, mirrors, or worktrees. Deployment code owns the
precreated stage parent and its permissions. The trusted launcher creates only the
exact final root declared by its root-owned manifest, then creates task worktrees
beneath that root. A request cannot add or widen a workspace root.

A dirty shared checkout fails closed unless an isolated worktree policy is selected. Public or untrusted profiles receive no broker tool. Caller and coding credentials remain separate.
