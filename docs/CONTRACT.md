# Foyer contract

cfyr is the device forwarding facade behind cmsg. It depends on cvld's optional
portable client and original generated OpenAPI contract. It neither creates an
independent action registry nor reimplements role, membership, gate or credential
rules. Member, admin and root operations follow the same call path; cvld checks
the authenticated session and exact service scope on every request.

Foyer consumes an owner Transport and passes action JSON through the owner
Client. Unknown operations are refused before transport. Native HTTP uses the
owner HttpClient: pinned HTTPS origin (literal loopback HTTP for local tests),
no redirects or proxies, bounded response and deadline, zeroizing bearer storage.
No session getter, root, PRF output, custody seed or local secret transport is
provided. Native HTTP success still requires a live server and real authority.

The `browser` feature exposes the owner's `BrowserClient` over maintained browser
Fetch and ReadableStream bindings. It pins the exact origin, refuses redirects,
omits ambient credentials, cache and referrer, bounds streamed replies, and aborts
after 30 seconds or cancellation. It is used from a browser Window. Foyer keeps
the original uncertain-result error after a dispatched mutation; it never retries
an ambiguous commit. The browser controls its own network routing.

cpky owns device ceremonies; cjry owns the enrolment and credential lifecycle.
They compose through this facade. WebAuthn PRF outputs must already be stripped
before any server call. Frontends only use cmsg, including admin/root tools.

The client contract is generated and verified in cvld. First-party declarations
track main with one revision per crate in Cargo.lock. CI resolves once, runs the
actual integration, then gates complete reachable line and branch coverage.
Coverage configuration and a compilable forwarding surface are not service or
lifecycle acceptance.

Native and browser CI share one resolved server lock and a separately resolved
browser consumer lock. The independent consumer executes this exact Foyer source
and the original portable door adapter. A real native Keyhole/door service, real
passkey sessions and an ephemeral HTTPS endpoint exercise successful calls, role
refusals, and damaged replies after actual logout commits. The three browser
coverage reports come from that same actual execution; every emitted reachable
Foyer line and branch is required. This does not qualify the Wallet proof engine
or the encrypted Vault/Board credential handoff.

`Foyer::call`, `action` and `contract` use the owner's forwarding projection:
only explicitly `x-client-access=forward` operations are exposed. A raw
login-finish response cannot leave the facade. Trusted composition calls
`Foyer::authenticate` with the public assertion from cpky; the owner client
installs the bearer in the same pinned transport and returns only
`SessionInfo { user, role, expires }`. No server bearer is returned to the shell,
and absent visibility metadata fails closed. This does not admit a member or
replace Journey's lobby. Raw JSON duplicate keys must be rejected before the
embedding converts its input to Value.
