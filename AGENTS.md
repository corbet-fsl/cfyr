# cfyr agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `bash .ci/import-owner-tests.sh` first: generates gitignored `tests/owner/`
  from the resolved cvld checkout (byte-identical to `cvld/tests/support`)
- `~/agents/scratch/cbuild <lane> test -p cfyr` — lib `91`, `door` `5`,
  `trust` `3`, doc `1` passed, exit 0; long, background it
- `~/agents/scratch/cbuild <lane> fmt -p cfyr -- --check` — must be clean
- Full gate (clippy `--locked`, wasm vectors, coverage, fixture sync) runs
  in CI; see `.ci/` and `docs/COVERAGE.md`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- One owner registry; admin uses the same path and cannot become root
  -> `tests/it/door.rs::community_admin_uses_the_same_registry_and_cannot_become_root`
- Login installs a session exporting only safe identity fields
  -> `tests/it/door.rs::trusted_login_installs_a_session_and_exports_only_safe_identity_fields`
- One resend of the identical first request after failure; a different second
  enrollment is refused per lease
  -> `src/membership/accounting.rs::one_resend_of_the_identical_first_request_after_a_failure`,
  `a_different_second_enrollment_is_refused_per_lease`
- Foreign-foyer receipts refused; continuation needs the exact first login
  -> `tests/cases/registration.rs::receipt_refused_for_foreign_foyer`,
  `continuation_requires_the_exact_first_login_before_binding`
- Completion never installs expired authority or hides connection failure
  -> `tests/it/trust.rs::network_completion_cannot_install_expired_authority_or_hide_connection_failure`
- Exactly one real charter retained; follows carry no session identifiers
  -> `tests/it/trust.rs::foyer_retains_one_real_charter_and_follows_without_session_identifiers`
- Browser requests keep the owner's public options; no second HTTP protocol
  -> `tests/it/door.rs::discoverable_browser_request_keeps_original_public_owner_options`

Pointers: `src/device_session.rs`, `src/registration/`, `src/membership/`,
`docs/CONTRACT.md`, `docs/LIVE-MEMBERSHIP.md`, `.ci/import-owner-tests.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; FSL-1.1-ALv2; no GPL/AGPL-only deps; never publish to a registry.
