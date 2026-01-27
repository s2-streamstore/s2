#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::match_same_arms,
    clippy::tests_outside_test_module,
    clippy::multiple_crate_versions,
    clippy::manual_let_else,
    clippy::struct_field_names,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value
)]

pub mod bash;
pub mod caps;
pub mod deep_size;
pub mod http;
pub mod maybe;
pub mod read_extent;
pub mod record;
pub mod types;
