# hermes-omp-broker

[![Support this work](https://img.shields.io/badge/Support-EVM-6f42c1?logo=ethereum&logoColor=white)](#support-development)

`hermes-omp-broker` lets an always-on [Hermes Agent](https://github.com/NousResearch/hermes-agent) use [Oh My Pi (OMP)](https://github.com/can1357/oh-my-pi) for substantial repository work without giving the Hermes process coding credentials, arbitrary paths, or an unrestricted engineering shell. It turns delegation into a local, typed policy boundary rather than a prose request: callers submit a repository key and complete standalone brief; operator-owned policy selects the workspace, model, sandbox, timeout, output, concurrency, and credentials.

The package combines a narrow Hermes delegate tool and client with an authenticated Unix-socket service, durable job records, one-writer admission, cancellation and timeout handling, orphan recovery, a restricted OMP extension, and typed final results. The result includes broker-observed Git and verification evidence alongside the model's claim, so operators can use a dedicated engineering harness while keeping admission, impact, and recovery inspectable.

This package was developed to support the optional coding-delegation boundary in the overall agent architecture outlined by [Hermes Stackbook](https://github.com/ghosty-11/hermes-stackbook). The Stackbook owns system-level composition and module-selection guidance; this repository owns the broker implementation, protocol, policy, operations, and tests.

The broker installs independently of [`hermes-mailbox`](https://github.com/ghosty-11/hermes-mailbox). Mailbox messages cannot grant broker authority, and broker availability never depends on mailbox delivery.

## Status

Reference implementation extracted from a deployed private system. The deterministic suite covers client framing and typed finals, clean-baseline admission, repository-key rejection, bounded tool policy, workspace escapes, networkless bash, typed finalization, durable pre-launch records, cancellation state, orphan recovery, delivery-failure result retention, and package metadata. Live clean-install, disposable cancellation/restart, and retained-result scenarios remain unexercised by this reusable package; run them against each deployment before relying on those paths.

## Boundary

Callers provide a repository key and complete standalone brief. Deployment policy owns paths, admitted local identity, model, sandbox, timeout, output, concurrency, and credentials. OMP receives only bounded tools through the extension. Model summaries are claims; the caller compares them with broker-observed Git and verification evidence.

The broker must never push, publish, merge, restart services, spend money, or perform destructive history operations unless separately authorized by the operator and supported by deployment policy.

## Layout

- `plugin/`: Hermes `delegate_to_omp` adapter and manifest.
- `client/`: framed local client.
- `broker/`: authenticated socket service and OMP process lifecycle.
- `extension/`: workspace and tool policy plus typed `broker_finalize` tool.
- `schemas/`: normative request/result envelope.
- `skills/hermes-omp-delegation/`: discoverable caller workflow.
- `systemd/`: generic user-service templates.
- `docs/`: specification and operational guidance.

## Documentation

- [Protocol specification](docs/specification.md)
- [Deployment policy](docs/policy.md)
- [Installation](docs/installation.md)
- [Operations and rollback](docs/operations.md)
- [Compatibility](docs/compatibility.md)
- [Normative wire schema](schemas/coding-job.schema.json)

## Verification

```sh
python3 -m unittest discover -s tests -v
python3 /path/to/skills/skills/skill-creator/scripts/quick_validate.py skills/hermes-omp-delegation
```

Deployment acceptance should also compile the JSON Schema, install into disposable local identities, run read-only and write jobs in a disposable Git repository, prove credential denial from the caller identity, cancel descendants, time out a dirty job, restart over an in-flight job, and retrieve a result after simulated delivery failure. The skill validator is the `quick_validate.py` script distributed with the [Agent Skills skill-creator](https://github.com/anthropics/skills/tree/main/skills/skill-creator).

## Support and security

Read [Support](SUPPORT.md) before filing an issue and report vulnerabilities through [Security](SECURITY.md). Do not publish credentials, private repository names, paths, identities, task contents, logs, or policy files in either channel.

## Support development

If this package saves you time, you find it useful, or you want to help me cover the token costs of continued development, you can support the work with an EVM donation:

```text
0x9600c9bc632175941608a1b551cb0f018f0f40b4
```

Networks: Ethereum, Base, Polygon, and other EVM-compatible networks. Verify the address and selected network before sending; unsupported assets or networks may be unrecoverable.

## Provenance

The private extraction ledger records exact source revisions and paths. This public-ready tree contains no deployment paths, identities, repository allowlists, credentials, logs, audit rows, task contents, or runtime state.

Licensed under the [MIT License](LICENSE).

<sub>Made with love, with help from AI agents.</sub>
