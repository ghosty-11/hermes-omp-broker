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
Do not roll job state backward over newer records; retain the pre-rollback copy for
reconciliation. Run:

```sh
systemctl --user daemon-reload
systemctl --user enable --now omp-delegate-broker.socket
systemctl --user status omp-delegate-broker.socket
```

Repeat admission denial and one bounded disposable-repository smoke before re-enabling the
Hermes tool. Publication, repository deletion, credential changes, and history rewriting
remain separate operator-authorized actions.
