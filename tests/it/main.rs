//! Both cfyr integration suites in ONE test binary (one link of the dependency tree instead of two).
//! Each former `tests/<name>.rs` is the module `<name>`; its feature and platform gate stays the inner
//! `#![cfg(..)]` of that file. `tests/browser/` is a separate consumer workspace and stays untouched.

mod door;
mod trust;
