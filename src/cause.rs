//! Device-side cause logging for flattened errors.
//!
//! The foyer flattens many owner-client failures into a coarse [`Error`](super::Error)
//! (`Unavailable`, `Reconcile`, `Unauthorized`, ...). That keeps the contract coarse on
//! purpose, but it drops the underlying cause, which slows debugging of journey rows.
//! These helpers re-attach the cause on stderr in development/test builds only.
//!
//! Privacy: only the source error's TYPE or variant name is printed (the leading
//! alphanumeric run of its `Debug`), never its `Display` text, fields, keys, tokens,
//! payloads or identifiers. A default build contains no such print: both helpers compile
//! to the identity. The e2e device build enables the print through the `development-gate`
//! feature (never enabled in production), wired from the embedding `cmsg` build.

/// Flatten `source` into `target`, printing the source's kind on stderr when the
/// development/test feature is enabled. Behaviour is identical either way.
#[allow(unused_variables)]
pub(crate) fn emit<T: std::fmt::Debug, U>(
    file: &'static str,
    line: u32,
    what: &'static str,
    target: U,
    source: &T,
) -> U {
    #[cfg(feature = "development-gate")]
    eprintln!("cause: {file}:{line} {what} -> {}", kind_of(source));
    target
}

/// Print the source's kind on stderr when the development/test feature is enabled,
/// for sites that cannot route through [`emit`] (a diverging arm body, an early return).
/// No such site exists in cfyr today; the helper stays for uniformity with cmsg/ckmg.
#[allow(unused_variables)]
#[allow(dead_code)]
pub(crate) fn print<T: std::fmt::Debug>(
    file: &'static str,
    line: u32,
    what: &'static str,
    source: &T,
) {
    #[cfg(feature = "development-gate")]
    eprintln!("cause: {file}:{line} {what} -> {}", kind_of(source));
}

/// The source error's type or variant name only: the leading alphanumeric run of its
/// `Debug`. A value-only `Debug` (a string, bytes, a number) yields an empty kind, so no
/// field value, key, token, payload or identifier is ever printed.
#[cfg(feature = "development-gate")]
fn kind_of<T: std::fmt::Debug>(source: &T) -> String {
    format!("{source:?}")
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
        .collect()
}

#[cfg(test)]
mod tests {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Secret {
        token: String,
    }

    /// The child half of `cause_print_only_with_the_development_gate`.
    #[test]
    fn cause_print_child() {
        if std::env::var_os("CFYR_CAUSE_CHILD").is_none() {
            return;
        }
        let _ = super::emit(
            "probe.rs",
            7,
            "ProbeTarget",
            0u8,
            &Secret {
                token: "hunter2-secret".into(),
            },
        );
        super::print(
            "probe.rs",
            9,
            "NoneTarget",
            &Secret {
                token: "hunter2-secret".into(),
            },
        );
    }

    /// The cause print exists exactly in a `development-gate` build (the feature the e2e
    /// device build enables) and a default build stays silent; field values never print.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn cause_print_only_with_the_development_gate() {
        let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", "cause::tests::cause_print_child", "--nocapture"])
            .env("CFYR_CAUSE_CHILD", "1")
            .output()
            .expect("run the child test");
        assert!(out.status.success());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!err.contains("hunter2"), "a field value was printed: {err}");
        assert_eq!(
            err.contains("cause: probe.rs:7 ProbeTarget -> Secret"),
            cfg!(feature = "development-gate"),
            "the emit print must exist exactly in a development-gate build: {err}"
        );
        assert_eq!(
            err.contains("cause: probe.rs:9 NoneTarget -> Secret"),
            cfg!(feature = "development-gate"),
            "the print must exist exactly in a development-gate build: {err}"
        );
    }
}

/// Why a lease attempt found its session lifetime unusable (a cause kind for [`emit`]).
#[derive(Debug, Clone, Copy)]
pub(crate) enum LeaseLifetime {
    OwnerDropped,
    Closed,
    NoPending,
    Generation,
}
