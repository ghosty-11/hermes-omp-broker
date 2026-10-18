# Operations

## Observe

Start the socket before admitting the Hermes tool. Verify the caller sees only the socket
and cannot read coding credentials, policy, environment, audit, or job state.

These commands apply to generic protocol-v1 user-unit deployments. Protocol-v2
deployments use their owner's named endpoint units. Never activate the generic
protocol-v1 units as a fallback for a protocol-v2 deployment. Source equality
does not prove that a release is installed or loaded.

```sh
systemctl --user status omp-delegate-broker.socket
```

```sh
systemctl --user status omp-delegate-broker.service
```

```sh
journalctl --user-unit omp-delegate-broker.service --since today
```

For each request, correlate the request ID with its existing task ID, policy decision,
durable job record, captured process birth identity, typed final, Git evidence,
verification exits, cleanup, and bounded redacted output. A model summary or `MET`
verdict is not broker evidence. At startup, `main()` writes an atomic stamp in the
writable agent directory from the three artifacts actually loaded into the process:
policy bytes, broker script bytes, and lifecycle source bytes. The stamp records
each loaded path and SHA-256, the policy-pair digest of the script and policy bytes
used for that field, and process identity (`pid` and `start_monotonic_usec`). It
does not reread later files on disk. Importing the module does not write a stamp,
and a reporting failure is fail-soft. Boundary freshness compares those captured
loaded bytes and process identity with the deployed artifacts; a matching pair
digest alone is not a complete stamp.

For an isolated worker, the broker records a delegated running job without a
local process identifier. A caller disconnect sends a bounded cancellation frame;
the broker keeps the worker socket open until it receives and persists the
terminal result, including a final written just before cancellation. The worker
kills its own child process group. A broker restart marks an uncertain external
run `orphaned` and does not replay it without an operator reconciliation. The
worker's private job records do not grant lease or status authority.

The worker handles one connection, then exits. Its service declares
`KillMode=control-group`; verify the service control group has no detached
child after a live cancellation. Installed OMP 18.2.8 writes native add-ons
under `HOME` and opens `agent.db` beside `models.yml`. Keep the catalog
directory root-owned and read-only to the worker; a root-owned database
symlink points into the worker service's fresh `PrivateTmp` namespace. Point
OMP's `HOME` into that namespace too, so an earlier job cannot poison a
later job's add-on or database. A precreated database in a read-only catalog
directory failed schema initialization in the local mock check.

## Cancellation, timeout, and restart

Cancellation and timeout must terminate confirmed descendants of the recorded
process birth identity and wait for clearance. Do not guess ownership from a
parent PID. Preserve dirty repository evidence. On service restart, the broker
classifies persisted `pending` and `running` records as `orphaned` before
admitting new work; it does not resume or clean their checkouts automatically. A
completed result whose socket delivery fails is retained as `delivery_failed` for
operator retrieval from the private job store. Terminal results remain durable
across launcher retries and model repinning; a launcher must replay the validated
result rather than dispatching a replacement job.

Do not delete an orphan or retry against the same checkout until the operator has
inspected the repository, process tree, job record, and audit entry. A
deterministic cancellation control joins the exact task ID, request ID, and
captured process birth identity, then terminates only birth-checked descendants.
It must confirm those processes are gone before cleanup.

The service `SIGTERM` handler terminates an active child process group before it
exits and therefore produces exit status `143` (`128 + 15`). Treat `143` as an
intentional service termination only when the service manager or operator sent
`SIGTERM`; the persisted job and process-birth evidence remains authoritative.

## Protocol v2 source staging

Protocol v2 requires dedicated launchers, named sockets, endpoint users, socket access
controls, and one private lease store per endpoint. For `delegate_to_omp`, the
`omp-invoke.py` command sends only a bounded brief, repository key, and task reference to
the dedicated issuer's ingress socket. The reference is correlation, not authority.
The issuer generates request and task IDs and redeems a v2 lease on a different socket.
Generic protocol-v1 user-service templates and other v1 CLI callers cannot use a named
v2 endpoint. Do not activate the generic socket as a fallback.

The broker requires one unique systemd `FileDescriptorName` for each listener. The accepted
listener name fixes the endpoint, and Unix `SO_PEERCRED` supplies the exact peer UID. The
`HERMES_OMP_LEASE_DIRS` environment variable maps each endpoint to one absolute private
directory as comma-separated `endpoint=/path` entries. The
`HERMES_OMP_ENDPOINT_USERS` environment variable maps the same endpoints to dedicated
launcher user names. The broker resolves those names to exact UIDs during startup. Every
listener name must have exactly one lease-directory and launcher-user mapping.

The separate coding broker uses `HERMES_OMP_ENDPOINT_CALLERS=delegate=delegate_to_omp`
to bind its private endpoint before consuming a lease or exposing status. It reads the
root-owned `/etc/omp-delegation-broker/broker-policy.json`; the dedicated issuer reads
`/etc/omp-delegation-broker/ingress.json`. These policies admit one disposable canary
repository. The backlog broker keeps its distinct policy and six endpoint identities.

The trusted dedicated launcher mints each opaque lease in its mapped store and redeems that
lease through its mapped endpoint under the same launcher UID. The opaque lease never leaves
the launcher. UID 997 receives neither an endpoint path nor a lease ID and cannot mint,
redeem, or read lease, job, policy, template, credential, or audit state.

Each endpoint store separates immutable `issued/` records from broker-owned `consumed/`
tombstones. An issued record contains the complete fixed request, endpoint, peer UID, task
ID, request ID, prompt digest, artifact digest, policy version, template version, issue time,
and expiry. The broker validates the redeemed request against policy before it
atomically creates the consumed tombstone with `O_EXCL`, and the tombstone still
precedes credential resolution, job creation, audit output, or child-process
creation; the broker never rewrites the issued record, so a policy rejection
leaves the lease unconsumed. A torn tombstone remains a replay denial.
Completion, failure, timeout, disconnect, and delivery failure do not make the
capability reusable. For an in-broker execution, a resultless pending job or
client-disconnect cancellation can admit one re-execution when the job is
not launch-uncertain and the caller's pinned model and every fallback rung
appear in the policy's exact `replay_safe_models` list. An isolated worker
launch stays uncertain until its terminal receipt. If that receipt is lost,
the broker keeps the job orphaned and refuses automatic re-execution.
Missing, empty, malformed, wildcard, or unknown entries deny re-execution; there
is no compatibility alias for the former `metered_models` field. Status joins the
immutable issued record with its valid consumed tombstone. The execution deadline
controls whether re-execution may be armed; status remains readable after expiry,
and a terminal job whose result carries a final never re-executes.
The launcher replays a validated durable terminal result before checking current
dispatch-model admission. A validated `orphaned` resultless status or typed
`job unavailable` status error can cause one execute attempt. The broker still
refuses that attempt when an isolated worker launch is uncertain. Pending or
running statuses remain pending. Malformed, corrupt or phase-less records
block with their path and parser cause rather than reading as absent.

Protocol-v2 errors use exact four-field envelopes:
`{"version":2,"op":"execute"|"status","ok":false,"error":...}`. A pre-admission
execute refusal uses `error:"job unavailable"` and maps to
`execution-rejected`. Oversized execute or status replies use
`error:"response exceeded size bound"` and map to `response-too-large`; the
durable broker record and child result remain untouched, and launchers do not
reexecute. Ordinary child failures, malformed envelopes, transport failures,
and post-processing failures remain generic. Protocol-v1 responses retain their
existing format and behavior.

Protocol-v2 health is a no-model, no-lease readiness probe. The launcher sends
`{"version":2,"op":"health"}` through its mapped endpoint. The broker binds the
endpoint and peer identity without creating a job. For a separate worker, it
checks the root-controlled socket, then asks the worker to validate its
root-installed runtime and scoped credential file without launching OMP.
Missing or invalid worker credentials make health unavailable before a lease is
issued. No credential content crosses the broker socket. Other endpoints retain
their local health check. An unavailable endpoint returns only
`{"version":2,"op":"health","ok":false,"error":"endpoint unavailable"}`.

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
one pinned set after disposable-host validation. Do not activate the retained protocol-v1
compatibility functions as an ad hoc fallback. During source-only staging, no live state
requires migration. After deployment, quiesce every launcher and socket before restoring
the last reviewed, mutually compatible broker/client/policy set. Retain lease and job
records for reconciliation; never translate an existing v2 lease into a protocol-v1
request.

## Upgrade

1. Disable `delegate_to_omp` on every Hermes profile that can call it.
2. Stop the socket and service; confirm no broker-owned process birth identity remains.
3. Back up installed package bytes, policy, environment, audit, and job records outside the
   install paths.
4. Install the new pinned client, broker, extension, plugin, skill, and units.
5. For a generic protocol-v1 user-unit deployment, reload systemd and enable the socket,
   then run the deterministic suite. Protocol-v2 operators use their deployment owner's
   named endpoint units and must not enable the generic v1 socket as a fallback.

```sh
systemctl --user daemon-reload
```

```sh
systemctl --user enable --now omp-delegate-broker.socket
```
6. Exercise unknown-key denial, one read-only job, one write job, descendant cancellation,
   timeout, restart/orphan classification, and retained-result retrieval in a disposable
   repository.
7. Re-enable the Hermes tool only after the evidence agrees with policy.

## Rollback

Disable the Hermes tool and stop the socket/service. Restore the previous pinned
client/broker/extension/plugin/skill/unit bytes plus the compatible policy and environment.
A policy that admits `backlog-maturation-research` or uses the exact
`replay_safe_models` replay contract is not compatible with a broker or extension from
before those fields. Restore the matching policy with the matching bytes; do not leave a
research caller pointed at an older extension. Do not roll job state backward over newer
records; retain the pre-rollback copy for reconciliation. The following commands are
generic protocol-v1 user-unit examples, not a live v2 rollback.

A policy using `restricted_model` requires matching broker and trusted-extension
support. Restore those bytes and the caller policy together; an older broker
must not silently ignore the restriction. Preserve restricted-run session
directories with the job records. Source checks and fixture runs do not prove
that the executing identity can use a provider. Verify provider eligibility
under that identity before admitting work; credential expansion needs separate
authorization.

```sh
systemctl --user daemon-reload
```

```sh
systemctl --user enable --now omp-delegate-broker.socket
```

```sh
systemctl --user status omp-delegate-broker.socket
```

Repeat admission denial and one bounded disposable-repository smoke before re-enabling the
Hermes tool. Publication, repository deletion, credential changes, and history rewriting
remain separate operator-authorized actions.

