# Policy

Policy is server-owned configuration. Repository keys map to paths. Caller entries select repository keys, sandbox mode, extra read roots, restricted-write patterns, scoped Git mode, and optional skills. The request schema never authorizes a filesystem path or widens a caller entry.

One `model` admits jobs globally. A caller entry may pin its own `model`, which then
replaces the global one for that caller only — this is per-caller pinning, not a role
system; the request still names the model explicitly and a mismatch is rejected before
OMP starts. A caller entry may also raise its own `max_timeout` ceiling in seconds; the
broker bounds it at 3600 regardless of policy, and callers without one keep the 810
default. Both values are policy-side only: a request can never supply or widen either.

`workspace-write` permits the admitted repository. `read-only` denies writes and shell. `restricted-write` admits only relative paths matching configured patterns; shell stays denied unless `git_mode` is `scoped`, which permits bounded status, log, diff, add, and commit operations on those paths. Deployment overlays may add local repositories, identities, and values without modifying reusable package code.

A dirty shared checkout fails closed unless an isolated worktree policy is selected. Public or untrusted profiles receive no broker tool. Caller and coding credentials remain separate.
