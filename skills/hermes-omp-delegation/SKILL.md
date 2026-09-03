---
name: hermes-omp-delegation
description: Use when delegating a bounded repo implementation or review from Hermes to OMP. Not for ordinary advice, task tracking, mailbox messages, publication, or host administration.
---

# Hermes to OMP Delegation

The broker is an execution boundary, not a general message channel. It accepts server-owned repository keys and policy; never invent paths, credentials, executables, environments, models, or sandbox settings.

## Before delegating

- Confirm the task ledger identifier and the repository key admitted by deployment policy.
- Use native Hermes coding only when that is the authorized surface. Use the broker when a bounded OMP implementation/review is selected or the caller intentionally has no write tools.
- Start writing work only from a clean attributable Git baseline. Preserve existing work in a commit or separate worktree.

## Brief contract

State the goal, files or subsystem in scope, constraints, observable definition of done, required verification, and explicit non-goals. OMP receives no surrounding conversation. Do not authorize push, publication, merge, service restart, spending, credentials, or destructive history unless the operator separately granted that action.

## Interpret the result

Treat the model summary as a claim. Prefer broker-observed status, changed paths, commits, verification exits, policy decisions, and cleanup evidence. Report disagreements rather than smoothing them over.

- `completed`: compare evidence to every acceptance criterion.
- `rejected`: correct the request only if policy permits; never widen policy from the caller.
- `failed` or `timed_out`: preserve dirty evidence and identify the failed criterion.
- `cancelled`: confirm descendants ended and cleanup state is recorded.
- `orphaned`: stop automatic retries; operator reviews preserved state.
- `delivery_failed`: retrieve the durable result rather than launching duplicate work.

Escalate after a dirty failure, evidence disagreement, policy ambiguity, orphan, credential boundary failure, or an action needing operator authority.
