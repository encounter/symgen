pub mod arm64;
pub mod embed;
pub mod file;
pub mod macho;
pub mod manifest;
pub mod modmeta;
pub mod msvc;

/// Compile-time assertion.
#[macro_export]
macro_rules! static_assert {
    ($condition:expr) => {
        const _: () = core::assert!($condition);
    };
}
