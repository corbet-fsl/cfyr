# cfyr — Foyer

The thin device facade for cvld's generated client contract. Frontends reach it
through cmsg. Member, admin and root calls retain the same owner schemas, errors
and server authority checks.

## Scope

Foyer composes the device half of the permanent door behind cmsg. It forwards
member, admin and root actions through cvld's generated contract, using separate
origins and sessions for wallet, community and operator roles. Passkeys owns
WebAuthn; Journey owns the lobby, enrolment and credential lifecycle. Foyer hands
their verified outputs to Vault and Board and forwards account actions when the
accounting owner provides them.

It never evaluates admission, skips the lobby, sends a global identity to a
community, reaches cfrm or carries PRF/root secrets. Signed-out, lobby, current
credential, renewal and no-return states are derived from those owners. Real door
round trips must verify roles, scopes, origins and uncertain outcomes. Credential
handoff requires local verification and encrypted save; forwarding alone does not
establish that lifecycle or production CLI passkey custody.

The implementation reuses cvld's owner-generated OpenAPI projection and its
maintained reqwest adapter. A second action table, custom HTTP protocol, policy
evaluator or WebAuthn implementation would duplicate an existing owner, so none
is introduced. Portable runtimes implement the owner's Transport port; `http`
selects the native adapter and `browser` selects its Fetch/Streams adapter.
See [the contract](docs/CONTRACT.md).

This work is not yet accepted. Real door integration, browser transport and full
coverage are tracked independently from the forwarding implementation. No package
is published to a registry.
