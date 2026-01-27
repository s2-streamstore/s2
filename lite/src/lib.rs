#![allow(
    clippy::tests_outside_test_module,
    clippy::mixed_read_write_in_expression,
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value,
    clippy::missing_assert_message,
    clippy::too_many_lines,
    clippy::struct_field_names,
    clippy::similar_names,
    clippy::multiple_crate_versions,
    clippy::significant_drop_tightening,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::single_match_else,
    clippy::needless_for_each,
    clippy::missing_fields_in_debug,
    clippy::multiple_inherent_impl
)]

pub mod backend;
pub mod handlers;
pub mod metrics;
