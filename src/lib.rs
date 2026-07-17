//! Reusable parsers for linked game and mod artifacts.

#![allow(dead_code)]

/// Compile-time assertion used by the binary record parsers.
#[macro_export]
macro_rules! static_assert {
    ($condition:expr) => {
        const _: () = core::assert!($condition);
    };
}

#[path = "util/macho.rs"]
mod macho;
#[path = "util/modmeta.rs"]
mod modmeta;
#[path = "util/msvc.rs"]
mod msvc;

pub use modmeta::{Export, HookTarget, Import, MetaFile, check_agreement, parse_library};
