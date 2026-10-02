# cfyr

**Foyer: the member half of cvld; sign in, handle, lobby, gate steps, credential renewal, devices.**

Part of `cvld`, the permanent door of the cmtymeet trust stack. Status: in
development; interfaces may change.

## Scope

### Purpose

`cfyr` is the member-side half of the `cvld` door: every member, admin, and root action reaches `cvld` through passkeys, the lobby journey, and the generated `cvld` client.

### Owns

| Area | What `cfyr` does |
|---|---|
| `cvld` client | Owns the generated client, bound separately to the global wallet origin, the community origin, and the admin/root origins, with distinct sessions. |
| Action forwarding | Forwards member, admin, and root actions with `cvld` role, scope, and effect metadata. |
| Lobby and credentials | Hands lobby and credential outputs to the vault side and the board side. |
| Account actions | Forwards account actions once the balance flow exists. |

### Never

- Never bypasses the lobby: every sign-in goes through it before reaching the forum.
- Never sends a global identity to a community.
- Never reaches `cfrm` directly.
- Never adds a second action table, policy evaluator, or passkey protocol implementation.
- Never holds or forwards the PRF secret.

### States

Derived sign-in state only: signed out, in the lobby, admitted with a current credential, needing renewal, or refused return. `cfyr` keeps no authority of its own; admission decisions belong to `cvld`.

### Test obligations

- End-to-end paths from the member API through `cfyr` to real `cvld` services, including admin and root paths and holder proofs.
- Wrong roles, origins, and scopes are refused through every projection.
- Credentials reach the board side only after local verification and encrypted save.
- Uncertain post-dispatch results are reconciled, never blindly retried.
- Common bar for all parts: Rust core on stable, native and WebAssembly builds with identical test vectors; explicit state machines with injected clock, randomness, storage, and network; thin facade wiring only; full line and branch coverage over real round trips with injected faults; atomic commit before any externally visible effect; strict per-community isolation; bounded inputs with no secrets in errors.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under the [Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md).
