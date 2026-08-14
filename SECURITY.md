# Security policy

This package is a local privilege and credential boundary between Hermes and OMP. Reports
about caller authentication, repository admission, path confinement, credential isolation,
process cleanup, result integrity, or unsafe installation guidance are security-relevant.

## Report privately

Use GitHub private vulnerability reporting for this repository when available. If it is not
enabled, open a minimal issue requesting a private reporting channel. Do not put exploit
details, credentials, private repository names, deployment paths, identities, policy files,
logs, task contents, or third-party personal data in a public issue.

## Include

- affected revision and file or component;
- the violated trust boundary and observable result;
- Hermes, OMP, Python, OS, and service-manager versions that materially affect it;
- a minimal reproduction using fictional repository keys and disposable identities;
- whether credentials, repositories, current state, or Git history may already be exposed;
- the narrowest safe mitigation known.

Revoke or isolate exposed credentials before reporting. Preserve evidence privately and use
the upstream security channel when the defect belongs to
[Hermes Agent](https://github.com/NousResearch/hermes-agent) or
[OMP](https://github.com/can1357/oh-my-pi/blob/main/.github/SECURITY.md).

Only the current default branch is maintained. Deployment policy, credentials, runtime
state, and operator authorization remain outside this repository.
