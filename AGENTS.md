# Agent instructions

Write code comments and documentation in English. Foyer is the device forwarding
facade behind cmsg. It consumes cvld's generated owner client; it must not create a
second registry, HTTP protocol, policy evaluator, membership store or server.
Member, admin and root use the same owner forwarding boundary. cpky alone talks
to WebAuthn and strips PRF; cjry owns enrolment and credential lifecycle.

Reuse maintained upstream libraries and existing owner code before adding a new
adapter. No cryptographic primitives, secret getters, PRF/root JSON, activity
records, hidden mutable defaults or permissive authority. Runtime errors stay
coarse and redact all request/session data. No GPL/AGPL dependency in this FSL
facade. LICENSE.md defines FSL-1.1-ALv2.

No workstation Cargo, including formatting/metadata. Use bounded public CI for
public native and actual browser tests; expensive scale/load belongs on Crow.
First-party dependencies declare branch main and resolve one revision per crate.
Preserve reproducible Cargo.lock and refresh once per CI run for all jobs.
Enforce complete reachable line and branch coverage, with only documented,
source-specific justified exclusions. Native compilation is not wasm evidence.

Commit small plain-English changes and stage explicit paths. Never publish to a
registry. Do not add AI attribution or secret data. Require independent review
of exact green backend commits; a scaffold or forwarding-only implementation
is not enrolment, credential, restoration or product acceptance.
