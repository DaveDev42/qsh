//! The single integration-test binary of `qsh-core`: every former `tests/<name>.rs` is
//! a module here, so the workspace links one test executable per crate instead of
//! one per file. Run one former file with `-E 'test(/^<name>::/)'`.

mod acl_docs;
mod acl_registry;
mod admission_docs;
mod audit_query_classification;
mod broker_ops_corpus;
mod cli_md_header;
mod doctor_docs;
mod failure_text_discipline;
mod host_stale_docs;
mod op_registration_completeness;
mod quota_docs;
mod quota_registry;
mod schema_commands_registry;
mod service_docs;
mod setup;
mod tunnel_docs;

#[path = "support/docs.rs"]
mod docs;
#[path = "support/broker_ops_harness.rs"]
mod harness;
