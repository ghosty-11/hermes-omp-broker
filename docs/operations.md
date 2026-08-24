# Operations

## Observe

Start the socket before admitting the Hermes tool. Verify the caller sees only the socket
and cannot read coding credentials, policy, environment, audit, or job state.

```sh
systemctl --user status omp-delegate-broker.socket
systemctl --user status omp-delegate-broker.service
journalctl --user-unit omp-delegate-broker.service --since today
```

For each request, correlate the request ID with its existing task ID, policy decision,
durable job record, process group, typed final, Git evidence, verification exits, cleanup,
and bounded redacted output. A model summary or `MET` verdict is not broker evidence.

## Cancellation, timeout, and restart

Cancellation and timeout must terminate descendants and wait for process-group clearance.
Preserve dirty repository evidence. On service restart, the broker classifies persisted
`pending` and `running` records as `orphaned` before admitting new work; it does not resume
or clean their checkouts automatically. A completed result whose socket delivery fails is
retained as `delivery_failed` for operator retrieval from the private job store.

Do not delete an orphan or retry against the same checkout until the operator has inspected
the repository, process tree, job record, and audit entry. A deterministic cancellation
control should confirm the recorded process group is gone before cleanup.

The signal handler terminates an active child process group before it exits. `SIGTERM`
therefore produces exit status `143` (`128 + 15`). Treat `143` as an intentional service
termination only when the service manager or operator sent `SIGTERM`; the persisted job and
process-group evidence remains authoritative.

## Protocol v2 source staging

Protocol v2 is source-only until the dedicated launchers, socket access controls, and policy
artefacts are reviewed and installed together. Do not point a live Hermes caller at these
source files.

The broker requires one unique systemd `FileDescriptorName` for each listener. The accepted
listener name fixes the endpoint, and Unix `SO_PEERCRED` supplies the exact peer UID. The
`HERMES_OMP_LEASE_DIRS` environment variable maps each endpoint to one absolute private
directory as comma-separated `endpoint=/path` entries. The
`HERMES_OMP_ENDPOINT_USERS` environment variable maps the same endpoints to dedicated
launcher user names. The broker resolves those names to exact UIDs during startup. Every
listener name must have exactly one lease-directory and launcher-user mapping.

The trusted dedicated launcher mints each opaque lease in its mapped store and redeems that
lease through its mapped endpoint under the same launcher UID. The opaque lease never leaves
the launcher. UID 997 receives neither an endpoint path nor a lease ID and cannot mint,
redeem, or read lease, job, policy, template, credential, or audit state.

Each endpoint store separates immutable `issued/` records from broker-owned `consumed/`
tombstones. An issued record contains the complete fixed request, endpoint, peer UID, task
ID, request ID, prompt digest, artifact digest, policy version, template version, issue time,
and expiry. The broker atomically creates the consumed tombstone with `O_EXCL` before
credential resolution, job creation, audit output, or child-process creation; it never
rewrites the issued record. A torn tombstone remains a replay denial. Completion, failure,
timeout, disconnect, delivery failure, and broker restart do not make the capability
reusable. Status joins the immutable issued record with its valid consumed tombstone.

Protocol v2 health is a no-spend live canary. The launcher sends exactly
`{"version":2,"op":"health"}` through its mapped endpoint. The broker verifies the endpoint
and `SO_PEERCRED` UID against `HERMES_OMP_ENDPOINT_USERS`, then returns exactly
`{"version":2,"op":"health","ok":true}`. Health does not read or write leases, jobs, audit
records, credentials, workspace state, or OMP state. A mismatched or malformed health
request returns only `{"version":2,"op":"health","ok":false,"error":"endpoint unavailable"}`.

The service units that activate protocol v2 must provide all of the following dependencies:

- Multiple named Unix listeners passed to one broker service process.
- Static, non-login launchers separated by authority.
- Socket and directory access controls that prevent UID 997 from crossing endpoints or
  reading the lease store.
- One durable lease root per endpoint on the same host as the broker. Each root contains
  precreated `issued/` and `consumed/` directories plus `.lease-store.lock`.
- Immutable `issued/*.json` records owned by the launcher UID and broker primary group with
  mode `0640`.
- `consumed/*.json` tombstones owned by the broker UID and primary group with mode `0600`.
- A regular `.lease-store.lock` inode owned by the broker UID and launcher primary group
  with mode `0660`. The broker opens the lock with `O_NOFOLLOW` and without `O_CREAT`, then
  validates its type, owner, group, and mode before use.
- A trusted lease issuer that calls the local `LeaseStore.issue(...)` API against only its
  mapped endpoint store and never exposes a network mint operation.
- One broker process for all named endpoints so that global and workspace locks remain
  shared.

Roll out protocol v2 by replacing the client, broker, launchers, policy, and service units as
one pinned set after full disposable-host validation. Do not activate the retained protocol
v1 compatibility functions. To roll back during source staging, discard the source changes;
no live state requires migration. After a protocol v2 deployment, disable every launcher and
socket before restoring the complete pinned protocol v1 set. Retain protocol v2 lease and job
records for reconciliation, and do not translate an existing lease into a protocol v1
request.

## Upgrade

1. Disable `delegate_to_omp` on every Hermes profile that can call it.
2. Stop the socket and service; confirm no broker-owned process group remains.
3. Back up installed package bytes, policy, environment, audit, and job records outside the
   install paths.
4. Install the new pinned client, broker, extension, plugin, skill, and units.
5. Run `systemctl --user daemon-reload`, enable the socket, and run the deterministic suite.
6. Exercise unknown-key denial, one read-only job, one write job, descendant cancellation,
   timeout, restart/orphan classification, and retained-result retrieval in a disposable
   repository.
7. Re-enable the Hermes tool only after the evidence agrees with policy.

## Rollback

Disable the Hermes tool and stop the socket/service. Restore the previous pinned
client/broker/extension/plugin/skill/unit bytes plus the compatible policy and environment.
A policy that lists `fallback_models` or admits `backlog-maturation-research` is not
compatible with a broker or extension from before those fields. Restore the matching
policy with the matching bytes; do not leave a research caller pointed at an older
extension. Do not roll job state backward over newer records; retain the pre-rollback
copy for reconciliation. Run:

```sh
systemctl --user daemon-reload
systemctl --user enable --now omp-delegate-broker.socket
systemctl --user status omp-delegate-broker.socket
```

Repeat admission denial and one bounded disposable-repository smoke before re-enabling the
Hermes tool. Publication, repository deletion, credential changes, and history rewriting
remain separate operator-authorized actions.

