# Retained session observations

`Foyer::live_membership` lends the trusted custody composer a weak read port.
The one original CVLD client remains inside Foyer; Charter and its public
Envoy transport are neither cloned nor shared. `observe` sends the original
`lobby` and `device_keys` operations under one session lock, checks the actual
login deadline after network waits, and returns the lobby pseudonym and live
passkey-authorized device keys. It exports no bearer or arbitrary request path.
A constructor-supplied token has no verified deadline in this port; original
`authenticate` must complete first. Closing the Foyer aborts a pending read.
Cancelling a read drops the original transport future and releases its slot.

These are live server observations, not full G3 authority. The custody composer
must independently establish authenticated current record lineage, current
root/epoch and exact local signing intent. A self-signed checkpoint, public
device key, session UUID, or this observation alone cannot authorize Keys.
The port keeps no cached roster and does not perform lineage publication or
create custody on missing storage.

Native tests use the original CVLD server, passport, membership, passkey login
and revocation. The existing browser fixture exercises the original Wasm client
from its vault frame over HTTPS, after the separate public-trust assertions.
Execution, feature resolution, browser qualification and full coverage remain
pending; source changes do not establish runtime acceptance.

`Foyer::current_policy` separately lends a weak synchronous callback into that
same Foyer's single original Trust. `with_current(now, callback)` invokes the
original Charter/Follower currentness checks every time; the callback cannot
retain their borrowed policy reference. Reentrant access or an in-flight refresh
returns Busy. Closing Foyer during the callback discards the callback result.
`Foyer::current` uses the same scoped callback, and `trust()` returns a checked
mutable borrow of the original follower for maintenance. Custody must reborrow
current policy after authority waits and again before returning authorization;
neither port produces a stored approval or full G3 verdict.
