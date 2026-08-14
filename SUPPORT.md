# Issue reports and support

Questions, corrections, compatibility reports, and bounded implementation defects are
welcome through [GitHub issues](https://github.com/ghosty-11/hermes-omp-broker/issues).
Read [SECURITY.md](SECURITY.md) first for anything that could expose credentials,
repositories, identities, policy, logs, tasks, or private topology.

## Before opening an issue

1. Search existing issues and read the relevant specification, policy, installation, and
   operations sections.
2. Pin the repository revision and record current Hermes, OMP, Python, OS, and service
   manager versions.
3. Re-run the deterministic suite and the smallest disposable-repository scenario that
   demonstrates the problem.
4. Remove credentials, private repository names, paths, identities, task contents, logs,
   account IDs, and third-party personal data.

A useful report includes the observed result, expected contract, exact public-safe
reproduction, bounded command output, and what remains uncertain. Use fictional repository
keys and paths under a disposable directory. Never attach credential files, provider tokens,
private policy, complete environment dumps, unbounded transcripts, or production audit/job
records.

Issues are reviewed as time permits; there is no support SLA. This repository owns the
reference broker implementation, wire protocol, policy, operations, and tests. Stack-level
module selection belongs to Hermes Stackbook, mailbox transport belongs to hermes-mailbox,
and product-specific defects may belong to the Hermes or OMP upstream projects.
