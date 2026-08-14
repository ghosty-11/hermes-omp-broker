# Policy

Policy is server-owned configuration. Repository keys map to paths. Caller entries select repository keys, sandbox mode, extra read roots, restricted-write patterns, scoped Git mode, and optional skills. The request schema never authorizes a filesystem path or widens a caller entry.

`workspace-write` permits the admitted repository. `read-only` denies writes and shell. `restricted-write` admits only relative paths matching configured patterns; shell stays denied unless `git_mode` is `scoped`, which permits bounded status, log, diff, add, and commit operations on those paths. Deployment overlays may add local repositories, identities, and values without modifying reusable package code.

A dirty shared checkout fails closed unless an isolated worktree policy is selected. Public or untrusted profiles receive no broker tool. Caller and coding credentials remain separate.
