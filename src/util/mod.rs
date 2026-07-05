pub mod manifest;

/// Compile-time assertion.
#[macro_export]
macro_rules! static_assert {
    ($condition:expr) => {
        const _: () = core::assert!($condition);
    };
}
