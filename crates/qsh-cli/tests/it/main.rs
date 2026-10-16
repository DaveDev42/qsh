//! The single integration-test binary of `qsh-cli`: every former `tests/<name>.rs` is
//! a module here, so the workspace links one test executable per crate instead of
//! one per file. Run one former file with `-E 'test(/^<name>::/)'`.

mod acl_check_equivalence;
mod acl_check_path;
mod acl_enforcement;
mod adversarial_load;
mod attach_ops;
mod attach_recovery;
mod audit_query;
mod auto_bootstrap;
mod cert_e2e;
mod cert_file_exchange;
mod console_probe;
mod cp_cancel;
mod cp_e2e;
mod cp_recursive;
mod doctor_fail_on;
mod dynamic_forward;
mod echo_host;
mod exec_e2e;
mod exit_code_matrix;
mod fixtures;
mod hosts_reverse;
mod hosts_toml;
mod identity_move_key;
mod init_trust;
mod jsonl_purity;
mod lifecycle_lines;
mod localctl_perms;
mod release_smoke;
mod reverse_blackout;
mod reverse_e2e;
mod reverse_unreachable_diagnostic;
#[cfg(windows)]
mod route_cases;
mod serve_sigterm_drain;
mod service_run;
mod session_follow;
mod session_kill9;
mod sessions_filter;
mod setup;
mod soak;
mod socks_curl;
mod ssh_bootstrap;
mod trust_alias_order;
mod trust_lifecycle_live;
mod trust_pairing_live;
mod trust_ssh_preview;
mod tui_expect;
mod tunnel_e2e;
mod tunnel_supervise;
mod tunnel_supervise_cli;
mod version;
#[cfg(windows)]
mod windows_attach;
#[cfg(windows)]
mod windows_forward_e2e;
#[cfg(windows)]
mod windows_reverse_e2e;

mod common;
mod ssh_golden;
