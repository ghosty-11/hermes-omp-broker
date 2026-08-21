# Compatibility

Reference seams: Hermes standalone plugin `register_tool`; OMP one-shot CLI, provider API
key bundle, extension hooks, restricted tools, and typed `broker_finalize`; POSIX peer
credentials and process groups.

Source and deterministic parity tests were reviewed on 2026-08-13. The reusable package
does not claim deployment-specific clean-install, disposable cancellation/restart, or
retained-result acceptance; run those scenarios against exact installed Hermes and OMP
revisions before each deployment or upgrade. The shipped broker uses one-shot OMP; RPC,
the Node SDK, and ACP are documented alternatives rather than tested package seams.

The reference broker requires three OMP CLI seams: `--no-mcp`,
`--provider-api-keys-fd`, and `--trusted-extension`. They are present in reviewed OMP
commit
[`2039ea608dd55714abb30f07984c6a5add62a4a2`](https://github.com/ghosty-11/oh-my-pi/commit/2039ea608dd55714abb30f07984c6a5add62a4a2).
They are broker-facing containment and credential seams rather than portable assumptions
about older OMP releases. Pin an OMP revision containing all three and run the disposable
credential-denial and extension-isolation scenarios before enabling the service.
