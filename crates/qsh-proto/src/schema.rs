//! The single source of the JSON Schemas `crates/qsh-cli/tests/fixtures.rs`
//! validates every golden fixture against and `qsh schema --json` serves
//! (`docs/design/testing.md` L6, `docs/CLI.md` §10, §6.10). One function
//! each side calls, so the fixture validator and the CLI surface cannot
//! independently drift the way two hand-maintained tables would
//! (`PLAN.md` M7 Step 1 (b)).

use schemars::{Schema, schema_for};

use crate::types::{
    AclCheckData, CapabilitiesData, CliEnvelope, ExecRunData, Host, HostListData, IdentityInitData,
    SchemaData, Session, SessionCloseData, SessionListData, SessionOpenData, SessionReadData,
    SessionResizeData, SessionWriteData, TrustAddData, TrustListData, TrustRemoveData,
    TunnelCloseData, TunnelListData, TunnelOpenData, VersionData,
};

/// Every `docs/CLI.md` §2.4 dotted command name [`cli_v1_data_schema`] has
/// a schema for, sorted. Not just [`cli_v1_data_schema`]'s `match` arms —
/// callers that need to *enumerate* the registered set (`Ops::schema`,
/// `fixtures.rs`'s own coverage tests) read this instead of guessing at it
/// from the match.
pub const CLI_V1_SCHEMA_COMMANDS: &[&str] = &[
    "acl.check",
    "capabilities.get",
    "exec.run",
    "host.get",
    "host.list",
    "identity.init",
    "schema.get",
    "session.close",
    "session.get",
    "session.list",
    "session.open",
    "session.read",
    "session.resize",
    "session.write",
    "trust.add",
    "trust.list",
    "trust.remove",
    "tunnel.close",
    "tunnel.list",
    "tunnel.open",
    "version.get",
];

/// The JSON Schema (schemars, draft 2020-12) of one command's `data`
/// payload, or `None` if `command` has none registered — mirror
/// [`CLI_V1_SCHEMA_COMMANDS`] when adding an arm here; a mismatch between
/// the two is a bug in this module, not in a caller.
///
/// Pure: `schema_for!` is a pure function of the type (schemars' own derive
/// determinism), so two calls for the same `command` always produce the
/// same value — this is what lets `qsh schema --json`'s output and
/// `fixtures.rs`'s validator be proven identical by construction rather
/// than by copying bytes around.
pub fn cli_v1_data_schema(command: &str) -> Option<Schema> {
    Some(match command {
        "acl.check" => schema_for!(AclCheckData),
        "capabilities.get" => schema_for!(CapabilitiesData),
        "exec.run" => schema_for!(ExecRunData),
        "host.get" => schema_for!(Host),
        "host.list" => schema_for!(HostListData),
        "identity.init" => schema_for!(IdentityInitData),
        "schema.get" => schema_for!(SchemaData),
        "session.close" => schema_for!(SessionCloseData),
        "session.get" => schema_for!(Session),
        "session.list" => schema_for!(SessionListData),
        "session.open" => schema_for!(SessionOpenData),
        "session.read" => schema_for!(SessionReadData),
        "session.resize" => schema_for!(SessionResizeData),
        "session.write" => schema_for!(SessionWriteData),
        "trust.add" => schema_for!(TrustAddData),
        "trust.list" => schema_for!(TrustListData),
        "trust.remove" => schema_for!(TrustRemoveData),
        "tunnel.close" => schema_for!(TunnelCloseData),
        "tunnel.list" => schema_for!(TunnelListData),
        "tunnel.open" => schema_for!(TunnelOpenData),
        "version.get" => schema_for!(VersionData),
        _ => return None,
    })
}

/// The JSON Schema of the `qsh.cli/v1` envelope itself ([`CliEnvelope`]).
pub fn cli_v1_envelope_schema() -> Schema {
    schema_for!(CliEnvelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_command_has_a_schema() {
        for command in CLI_V1_SCHEMA_COMMANDS {
            assert!(
                cli_v1_data_schema(command).is_some(),
                "{command} is in CLI_V1_SCHEMA_COMMANDS but cli_v1_data_schema has no arm for it"
            );
        }
    }

    #[test]
    fn cli_v1_schema_commands_is_sorted_and_deduplicated() {
        let mut sorted = CLI_V1_SCHEMA_COMMANDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted, CLI_V1_SCHEMA_COMMANDS,
            "CLI_V1_SCHEMA_COMMANDS must be sorted with no duplicates"
        );
    }

    #[test]
    fn unknown_command_has_no_schema() {
        assert!(cli_v1_data_schema("nonexistent.op").is_none());
    }

    #[test]
    fn schema_generation_is_deterministic() {
        let a = cli_v1_data_schema("version.get").unwrap().to_value();
        let b = cli_v1_data_schema("version.get").unwrap().to_value();
        assert_eq!(a, b);
        assert_eq!(
            cli_v1_envelope_schema().to_value(),
            cli_v1_envelope_schema().to_value()
        );
    }
}
