//! `pair.ssh` request and data types (`docs/CLI.md` §6.11, ADR-0044).

use super::*;

// ---------------------------------------------------------------------------
// pair.ssh (`docs/CLI.md` §6.11, ADR-0044 결정 1·17)
// ---------------------------------------------------------------------------

/// Request for `pair.ssh`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PairSshReq {
    /// `[user@]host`, exactly as `ssh` should receive it (ADR-0044 결정 7).
    /// The host half is the default name this machine pins the remote under.
    pub dest: String,
    /// `--as`: the name this machine pins the remote under, instead of the
    /// host half of `dest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
    /// `--remote-as`: the name the remote pins this machine under. Absent
    /// means the first label of this machine's host name, then `device_id`
    /// (ADR-0044 결정 8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_as: Option<String>,
    /// `--role`: the trust role of the pin written on the remote, one of
    /// `full`, `exec`, `tunnel`, `read-only`, `reverse`, `none`. An open
    /// string on the wire. Absent means `full` (ADR-0044 결정 8). The role
    /// of this machine's own pin is not chosen here (결정 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// `--address`: the `host[:port]` this machine records for the remote,
    /// instead of `<ssh hostname>:<remote serve port>` (ADR-0044 결정 5).
    /// Not allowed with `reverse`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// `--reverse`: the remote dials this machine instead of the other way
    /// round (ADR-0044 결정 22). Goes with `to`: one without the other is
    /// `INVALID_ARGUMENT` before ssh runs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reverse: bool,
    /// `--to`: the `host[:port]` the remote dials to reach this machine's
    /// `qsh listen`, written on the remote's pin of this machine. Needs
    /// `reverse`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// `--remote-qsh`: the `qsh` executable to run on the remote. Absent
    /// means `[ssh].remote_qsh`, then `qsh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_qsh: Option<String>,
}

/// Which way the new pins point (ADR-0044 결정 22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PairSshDirection {
    /// This machine dials the remote.
    Forward,
    /// The remote dials this machine's `qsh listen` (`qsh serve --to`).
    Reverse,
}

/// What the remote reported about the pin it holds for this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PairSshRemote {
    /// The name the remote pins this machine under. For a pin that already
    /// existed, the name it already had.
    pub name: String,
    /// The remote pin's role as the remote reported it. For a pin that
    /// already existed this can differ from the requested role: the
    /// bootstrap never changes an existing pin's role (ADR-0044 결정 12).
    /// Omitted when the remote pin has no `role` key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// `true` if the remote wrote a new pin; `false` if this machine was
    /// already pinned there.
    pub created: bool,
}

/// Data payload of `pair.ssh` (ADR-0044 결정 17).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PairSshData {
    /// Which way the pins point.
    pub direction: PairSshDirection,
    /// The pin this machine holds for the remote after the call.
    pub peer: TrustPeer,
    /// `true` if this machine wrote a new pin for the remote.
    pub created: bool,
    /// The remote's side of the exchange.
    pub remote: PairSshRemote,
    /// The command to run on the remote to finish a reverse setup (ADR-0044
    /// 결정 17, 22). Absent in the forward direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_command: Option<String>,
    /// `true` if this call created this machine's device identity first
    /// (ADR-0044 결정 18).
    pub identity_created: bool,
    /// `true` if ssh reached the remote through `ProxyJump` or
    /// `ProxyCommand`, which the QUIC dial does not use (결정 6).
    pub ssh_proxied: bool,
    /// `true` if a QUIC handshake with mutual pin verification to the
    /// recorded address succeeded (결정 13). No session is opened. Always
    /// `false` in the reverse direction, which has no dial to make.
    pub verified: bool,
    /// Why `verified` is `false`, when the check failed. Absent when it
    /// passed, and absent in the reverse direction (nothing was skipped). The pins stand either way, so the call still succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_error: Option<CliError>,
}
