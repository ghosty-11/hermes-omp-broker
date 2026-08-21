# Installation

## Prerequisites and identities

Use Python 3.11 or newer on a POSIX host with Unix peer credentials and process groups.
Install OMP first and verify `omp --help`.

The broker requires OMP support for `--no-mcp`, `--provider-api-keys-fd`, and
`--trusted-extension`; see [Compatibility](compatibility.md). Do not deploy against an OMP
revision that lacks any of those seams.
Choose two identities:

- a restricted Hermes caller that owns only the plugin and client and may connect to the
  broker socket;
- an operator-owned coding identity that owns OMP credentials, approved repositories,
  broker policy, extension, state, and user service.

Do not continue if the caller can read the coding identity's credential store.

## Coding-identity installation

From a pinned checkout, as the coding identity:

```sh
umask 077
install -d -m 0700 \
  "$HOME/.local/libexec/hermes-omp-broker" \
  "$HOME/.config/hermes-omp-broker" \
  "$HOME/.config/systemd/user"
install -m 0700 broker/omp-delegate-broker.py \
  "$HOME/.local/libexec/hermes-omp-broker/omp-delegate-broker.py"
install -m 0600 broker/lifecycle.py \
  "$HOME/.local/libexec/hermes-omp-broker/lifecycle.py"
install -m 0600 extension/omp-delegate-extension.ts \
  "$HOME/.local/libexec/hermes-omp-broker/omp-delegate-extension.ts"
install -m 0644 systemd/omp-delegate-broker.service \
  systemd/omp-delegate-broker.socket \
  "$HOME/.config/systemd/user/"
```

Create a mode-`0600` policy from `examples/policy.json`. Use absolute repository paths;
set `model` to the exact provider/model admitted by the broker; keep caller repository
lists and sandbox modes narrow. Create
`$HOME/.config/hermes-omp-broker/environment` mode `0600` with absolute values:

```text
HERMES_OMP_POLICY=/absolute/path/to/policy.json
HERMES_OMP_BIN=/absolute/path/to/omp
HERMES_OMP_TOKEN_BIN=/absolute/path/to/omp
HERMES_OMP_CREDENTIAL_DIR=/absolute/private/credential-agent
HERMES_OMP_AGENT_DIR=/absolute/private/worker-agent
HERMES_OMP_EXTENSION=/absolute/path/to/omp-delegate-extension.ts
HERMES_OMP_LOCK_DIR=/absolute/private/state/locks
HERMES_OMP_AUDIT_LOG=/absolute/private/state/audit.jsonl
HERMES_OMP_JOB_DIR=/absolute/private/state/jobs
HERMES_OMP_MODEL=provider/model
HERMES_OMP_CALLER_UID=12345
HERMES_OMP_HOME=/absolute/private/home
HERMES_OMP_PATH=/usr/local/bin:/usr/bin:/bin
```

Replace the example UID values; never copy a real UID into public documentation.
`HERMES_OMP_CALLER_UID=12345` identifies the restricted caller. Give that identity socket
access through the operator-selected group without granting it read access to the
environment, policy, credentials, state, or repositories beyond its admitted working
paths.

Enable the socket only after reviewing both unit files:

```sh
systemctl --user daemon-reload
systemctl --user enable --now omp-delegate-broker.socket
systemctl --user status omp-delegate-broker.socket
```

## Caller installation

As the restricted Hermes identity, copy `client/omp-invoke.py` to a private executable path
and install `plugin/` through the installed Hermes standalone-plugin discovery seam. Install
`skills/hermes-omp-delegation/` as one discoverable Agent Skill from this canonical source.
Configure these caller-side values:

```text
HERMES_OMP_POLICY=/absolute/caller-readable/policy.json
HERMES_OMP_INVOKE=/absolute/path/to/omp-invoke.py
HERMES_OMP_BROKER_SOCKET=/run/user/23456/hermes-omp-broker/omp.sock
HERMES_OMP_MODEL=provider/model
```

The socket path's numeric directory is the coding identity's UID, not the caller UID.

The caller-readable policy supplies only the fixed client path, socket, model, repository
map, and caller entries needed for admission. It must not contain credentials. Confirm the
plugin exposes exactly `delegate_to_omp` only on profiles authorized to delegate.

## Pre-enable verification

```sh
python3 -m unittest discover -s tests -v
python3 -m json.tool schemas/coding-job.schema.json >/dev/null
python3 /path/to/skills/skills/skill-creator/scripts/quick_validate.py \
  skills/hermes-omp-delegation
```

Then use disposable identities and a disposable Git repository to prove: an unknown key,
caller-supplied path, environment, executable, or model is rejected before OMP starts;
the caller cannot read credentials; read-only and write jobs stay within policy; descendant
cancellation, timeout, restart/orphan classification, and retained-result retrieval behave
as documented.

## Upgrade and removal

Stop admission by disabling the Hermes tool, then stop the socket and service. Back up the
current package bytes, policy, environment, and state outside the install paths. Install the
new pinned bytes, run the deterministic suite and disposable acceptance scenarios, then
re-enable the socket and tool. To roll back, disable the tool, restore the previous pinned
bytes and policy, run `systemctl --user daemon-reload`, restart the socket, and repeat
admission plus one bounded disposable-repository smoke.

For removal, disable the Hermes tool first, then:

```sh
systemctl --user disable --now omp-delegate-broker.socket
systemctl --user stop omp-delegate-broker.service
```

Retain job and audit state until the deployment's retention policy authorizes deletion.
