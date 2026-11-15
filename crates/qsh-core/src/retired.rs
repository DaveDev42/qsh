//! Entry points ADR-0068 retired in v0.9.0: reverse connections and qsh's own
//! hole punching.
//!
//! Every retired command and flag still parses (ADR-0012 decision 4 promised
//! that for the whole of `qsh.cli/v1`) and answers `UNSUPPORTED`, exit 255,
//! `retryable: false`, with `details.reason = "reverse_retired"` and one
//! alternative in the message. The wording lives here, in `qsh-core`, so a
//! renderer never composes it (`CLAUDE.md`'s crate boundary).
//!
//! `--no-punch`, `[punch].mode` and `qsh trust rendezvous` are not entry
//! points: the punch is already off, so they parse and do nothing.

use qsh_proto::ErrorCode;

use crate::config::Config;
use crate::ops::OpError;

/// The `details.reason` every retired entry point reports.
pub const REASON: &str = "reverse_retired";

/// The dotted config keys (`qsh config set`/`unset` spelling) that belong to
/// the retired reverse machinery. They still parse and `config unset` still
/// removes them; `config set` refuses them.
pub const RETIRED_CONFIG_KEYS: &[&str] = &[
    "serve.to",
    "listen.bind",
    "listen.allow_advertised_names",
    "listen.stale_retention",
    "listen.serve",
    "reverse.controller",
    "reverse.offered_name",
    "reverse.backoff_initial_ms",
    "reverse.backoff_max_ms",
    "reverse.backoff_jitter_pct",
    "recovery.reverse_min_dead_after_ms",
    "recovery.reverse_strikes",
];

/// Whether `path` (a dotted `qsh config` key) is one of
/// [`RETIRED_CONFIG_KEYS`].
pub fn is_retired_config_key(path: &str) -> bool {
    RETIRED_CONFIG_KEYS.contains(&path)
}

/// The shared alternative: serve on the target, pin its key on the client.
const ALTERNATIVE: &str = "대상에서 `qsh serve`를 돌리고 이 장비에 그 키를 pin하면(`qsh trust add <name> --key …`) 열린 포트 없이 iroh route로 닿는다. `-R` 터널은 그대로다.";

/// One retired entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetiredEntry {
    /// `qsh listen`.
    Listen,
    /// `qsh listen --serve`.
    ListenServe,
    /// `qsh serve --to`.
    ServeTo,
    /// `qsh serve --name`.
    ServeName,
    /// The hidden `qsh reverse`.
    Reverse,
    /// `qsh service run listen`.
    ServiceRunListen,
    /// `qsh service run reverse`.
    ServiceRunReverse,
    /// `qsh service install --to` (or `--name`).
    ServiceInstallTo,
    /// `qsh service install` on a machine whose config still infers the
    /// `listen` or `reverse` mode.
    ServiceInstallMode,
    /// `qsh setup listener`.
    SetupListener,
    /// `qsh setup host --to`.
    SetupHostTo,
    /// `qsh pair ssh --reverse`.
    PairSshReverse,
    /// `--rendezvous`.
    Rendezvous,
    /// `qsh serve` with `[serve].to` or `[reverse].controller` in the config.
    ServeConfig,
}

impl RetiredEntry {
    /// The `UNSUPPORTED` this entry point answers with.
    pub fn error(self) -> OpError {
        OpError::new(ErrorCode::Unsupported, self.message())
            .with_retryable(false)
            .with_details(serde_json::json!({ "reason": REASON }))
    }

    /// The message: what was retired, then one alternative.
    pub fn message(self) -> String {
        match self {
            RetiredEntry::Listen => {
                format!("`qsh listen`은 v0.9.0에서 걷혔다(ADR-0068). {ALTERNATIVE}")
            }
            RetiredEntry::ListenServe => format!(
                "`qsh listen --serve`는 v0.9.0에서 걷혔다(ADR-0068). {ALTERNATIVE} \
                 `[listen].bind`는 `[serve].bind`로 옮긴다."
            ),
            RetiredEntry::ServeTo => {
                "`qsh serve --to`는 v0.9.0에서 걷혔다(ADR-0068). 밖으로 거는 대신 인자 없이 \
                 `qsh serve`를 돌리고 상대 장비에서 이 장비의 키를 pin하면(`qsh trust add <name> \
                 --key …`) 열린 포트 없이 iroh route로 닿는다. `-R` 터널은 그대로다."
                    .to_string()
            }
            RetiredEntry::ServeName => {
                "`qsh serve --name`은 v0.9.0에서 걷혔다(ADR-0068). 이름은 역방향 등록에만 \
                 쓰였다. 인자 없이 `qsh serve`를 돌리고 상대 장비가 이 장비를 pin할 때 \
                 이름을 정한다(`qsh trust add <name> --key …`). `-R` 터널은 그대로다."
                    .to_string()
            }
            RetiredEntry::Reverse => {
                "`qsh reverse`는 v0.9.0에서 걷혔다(ADR-0068). 이 장비에서 `qsh serve`를 \
                 돌리고 상대 장비에 이 장비의 키를 pin하면(`qsh trust add <name> --key …`) \
                 열린 포트 없이 iroh route로 닿는다. `-R` 터널은 그대로다."
                    .to_string()
            }
            RetiredEntry::ServiceRunListen => format!(
                "`qsh service run listen`은 v0.9.0에서 걷혔다(ADR-0068). 유닛은 \
                 `qsh service uninstall`로 지우고 `qsh service install`로 `qsh serve` 유닛을 \
                 설치한다. {ALTERNATIVE}"
            ),
            RetiredEntry::ServiceRunReverse => format!(
                "`qsh service run reverse`는 v0.9.0에서 걷혔다(ADR-0068). 유닛은 \
                 `qsh service uninstall`로 지우고 `qsh service install`로 `qsh serve` 유닛을 \
                 설치한다. {ALTERNATIVE}"
            ),
            RetiredEntry::ServiceInstallTo => format!(
                "`qsh service install --to`는 v0.9.0에서 걷혔다(ADR-0068). `--to` 없이 \
                 `qsh service install`을 하면 `qsh serve` 유닛이 설치된다. {ALTERNATIVE}"
            ),
            RetiredEntry::ServiceInstallMode => format!(
                "이 장비의 설정이 걷힌 `listen`·`reverse` 모드를 가리켜 유닛을 설치하지 않는다\
                 (ADR-0068, v0.9.0). `qsh doctor`의 `reverse_config_retired`가 남은 키를 \
                 말한다. `qsh config unset`으로 지우면 `qsh serve` 유닛이 설치된다. {ALTERNATIVE}"
            ),
            RetiredEntry::SetupListener => format!(
                "`qsh setup listener`는 v0.9.0에서 걷혔다(ADR-0068). `qsh setup host`로 이 장비를 \
                 서버로 준비하고 client 장비에 그 키를 pin한다. {ALTERNATIVE}"
            ),
            RetiredEntry::SetupHostTo => format!(
                "`qsh setup host --to`는 v0.9.0에서 걷혔다(ADR-0068). `--to` 없이 \
                 `qsh setup host`로 이 장비를 서버로 준비한다. {ALTERNATIVE}"
            ),
            RetiredEntry::PairSshReverse => format!(
                "`qsh pair ssh --reverse`는 v0.9.0에서 걷혔다(ADR-0068). `--reverse`와 `--to` \
                 없이 `qsh pair ssh <dest>`를 하면 원격이 `qsh serve`를 돌리고 이 장비가 그 \
                 키를 pin한다. {ALTERNATIVE}"
            ),
            RetiredEntry::Rendezvous => "`--rendezvous`는 v0.9.0에서 걷혔다(ADR-0068). qsh 자체 \
                 홀펀칭이 꺼졌고 NAT 통과는 iroh route가 맡는다. 플래그를 빼고 다시 실행한다. \
                 `-R` 터널은 그대로다."
                .to_string(),
            RetiredEntry::ServeConfig => "설정에 `[serve].to` 또는 `[reverse].controller`가 남아 \
                 있어 `qsh serve`를 띄우지 않는다. 역방향 연결은 v0.9.0에서 걷혔고(ADR-0068) \
                 밖으로만 걸던 장비가 말없이 `[::]:4433`을 여는 일을 막는다. \
                 `qsh config unset serve.to`와 `qsh config unset reverse.controller`로 지우고 \
                 다시 띄운다. `qsh doctor`의 `reverse_config_retired`가 남은 키를 모두 \
                 말한다."
                .to_string(),
        }
    }
}

/// `UNSUPPORTED` for `qsh config set` on a retired key.
pub fn config_set_error(path: &str) -> OpError {
    OpError::new(
        ErrorCode::Unsupported,
        format!(
            "설정 키 `{path}`는 역방향 연결에 쓰였고 v0.9.0에서 걷혔다(ADR-0068). 값을 \
             쓰지 않는다. 남은 값은 `qsh config unset {path}`로 지운다."
        ),
    )
    .with_retryable(false)
    .with_details(serde_json::json!({ "reason": REASON, "key": path }))
}

/// The retired `qsh setup` roles: `listener` and `host --to`.
pub fn check_setup_role(role: qsh_proto::SetupRole) -> Result<(), OpError> {
    match role {
        qsh_proto::SetupRole::Listener => Err(RetiredEntry::SetupListener.error()),
        qsh_proto::SetupRole::HostTo => Err(RetiredEntry::SetupHostTo.error()),
        qsh_proto::SetupRole::Host | qsh_proto::SetupRole::Client => Ok(()),
    }
}

/// `--rendezvous` check shared by every command.
pub fn check_rendezvous(rendezvous: Option<&str>) -> Result<(), OpError> {
    match rendezvous {
        Some(_) => Err(RetiredEntry::Rendezvous.error()),
        None => Ok(()),
    }
}

/// Refuse a `qsh serve` whose config still points it outward.
pub fn check_serve_config(config: &Config) -> Result<(), OpError> {
    if config.serve.to.is_some() || config.reverse.controller.is_some() {
        return Err(RetiredEntry::ServeConfig.error());
    }
    Ok(())
}

/// The retired config keys `config` still carries, in the order
/// `reverse_config_retired` names them. A section with every key at its
/// default (or absent) is not reported: the file cannot tell the two apart.
pub fn leftover_config_keys(config: &Config) -> Vec<&'static str> {
    let mut keys = Vec::new();
    if config.listen != crate::config::ListenConfig::default() {
        keys.push("[listen]");
    }
    if config.serve.to.is_some() {
        keys.push("[serve].to");
    }
    if config.reverse != crate::config::ReverseConfig::default() {
        keys.push("[reverse]");
    }
    if config.recovery.reverse_min_dead_after_ms.is_some() {
        keys.push("[recovery].reverse_min_dead_after_ms");
    }
    if config.recovery.reverse_strikes.is_some() {
        keys.push("[recovery].reverse_strikes");
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_entry_is_unsupported_with_the_reason_and_not_retryable() {
        for entry in [
            RetiredEntry::Listen,
            RetiredEntry::ListenServe,
            RetiredEntry::ServeTo,
            RetiredEntry::ServeName,
            RetiredEntry::Reverse,
            RetiredEntry::ServiceRunListen,
            RetiredEntry::ServiceRunReverse,
            RetiredEntry::ServiceInstallTo,
            RetiredEntry::ServiceInstallMode,
            RetiredEntry::SetupListener,
            RetiredEntry::SetupHostTo,
            RetiredEntry::PairSshReverse,
            RetiredEntry::Rendezvous,
            RetiredEntry::ServeConfig,
        ] {
            let err = entry.error();
            assert_eq!(err.code, ErrorCode::Unsupported, "{entry:?}");
            assert!(!err.retryable, "{entry:?}");
            assert_eq!(err.details["reason"], REASON, "{entry:?}");
            assert!(err.message.contains("ADR-0068"), "{entry:?}");
        }
    }

    #[test]
    fn listen_serve_says_where_the_bind_moves() {
        assert!(
            RetiredEntry::ListenServe
                .message()
                .contains("`[listen].bind`는 `[serve].bind`로 옮긴다")
        );
        assert!(
            !RetiredEntry::Listen
                .message()
                .contains("`[listen].bind`는 `[serve].bind`로")
        );
    }

    #[test]
    fn retired_config_keys_are_known_config_keys() {
        for key in RETIRED_CONFIG_KEYS {
            crate::config_edit::lookup(key).unwrap_or_else(|_| panic!("{key} is not a config key"));
        }
    }

    #[test]
    fn a_default_config_has_no_leftover_keys() {
        assert!(leftover_config_keys(&Config::default()).is_empty());
        assert!(check_serve_config(&Config::default()).is_ok());
    }
}
