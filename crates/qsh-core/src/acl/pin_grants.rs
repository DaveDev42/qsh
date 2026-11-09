//! Per-pin grants (ADR-0051 결정 12): the optional `grants`, `paths` and
//! `scope` keys of a `[[peer]]` entry in `trust.toml`, written by `qsh trust
//! allow` / `qsh trust deny`.
//!
//! This is the "pin grant stage" of the evaluation order, between the trust
//! role and the `[[acl]]` rows (`docs/design/architecture.md` §6). Everything
//! that makes a grant count is the same as for a role: the requester must be
//! a `device:<name>` principal over [`AuthPath::Pin`] whose connection
//! fingerprint equals the pin's current fingerprint
//! ([`crate::trust::SharedTrustStore::resolve_standing`]), and a store whose
//! last reload failed grants nothing (ADR-0045 결정 4).
//!
//! The vocabulary is [`Action::ALL`] minus the always-denied gate: a
//! `forward.socks` grant can neither be written nor loaded. Trailing `.*`
//! families are accepted on input and expanded to exact actions, so a file
//! written by the CLI only ever holds exact names.

use super::paths::{PathStyle, validate_entry};
use super::{Action, Scope};

/// Most `paths` entries one pin may carry, the cap an `[[acl]]` row has.
pub const MAX_PIN_PATHS: usize = 64;

/// Why a set of pin grants is refused. Each variant has a fixed reason; the
/// message never echoes an entry's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PinGrantsError {
    /// `forward.socks` named explicitly (the always-deny gate: it can never
    /// be granted).
    #[error("forward.socks can never be granted: it is always denied")]
    Socks,
    /// An action that is not in the vocabulary, or a `.*` family with no
    /// action in it.
    #[error("unknown action: expected an action name or a trailing `.*` family")]
    UnknownAction,
    /// No action at all was named.
    #[error("no action given")]
    NoAction,
    /// A file grant with no `paths`.
    #[error("file.read and file.write need --path: a file grant is limited to paths")]
    FileGrantNeedsPaths,
    /// `paths` with no file grant to limit.
    #[error("--path applies only to file.read and file.write grants")]
    PathsWithoutFileGrant,
    /// More `paths` entries than the cap.
    #[error("too many paths: at most {MAX_PIN_PATHS}")]
    TooManyPaths,
    /// A `paths` entry that is not an absolute, normalized path.
    #[error("a path {0}")]
    BadPath(&'static str),
    /// `scope` is neither `owned` nor `any`.
    #[error("scope must be `owned` or `any`")]
    BadScope,
    /// `paths` or `scope` without any `grants`.
    #[error("paths or scope without grants")]
    OrphanKeys,
}

/// The validated grants of one pin. Never empty, never holds an
/// always-denied action, and has `paths` exactly when it holds a file action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinGrants {
    actions: Vec<Action>,
    paths: Option<Vec<String>>,
    scope: Scope,
}

/// The keys of a pin entry, in canonical form: what `trust.toml` holds after
/// a write.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PinGrantKeys {
    /// The `grants` key.
    pub grants: Option<Vec<String>>,
    /// The `paths` key.
    pub paths: Option<Vec<String>>,
    /// The `scope` key.
    pub scope: Option<String>,
}

/// Expand action names and trailing `.*` families into exact actions, in
/// [`Action::ALL`] order without repeats. A family never reaches an
/// always-denied action (`forward.*` stops short of `forward.socks`); naming
/// one exactly is [`PinGrantsError::Socks`].
pub fn expand_actions(raw: &[String]) -> Result<Vec<Action>, PinGrantsError> {
    if raw.is_empty() {
        return Err(PinGrantsError::NoAction);
    }
    let mut picked = [false; Action::ALL.len()];
    for item in raw {
        if let Some(stem) = item.strip_suffix(".*") {
            if stem.is_empty() {
                return Err(PinGrantsError::UnknownAction);
            }
            let prefix = format!("{stem}.");
            let mut any = false;
            for (slot, action) in Action::ALL.into_iter().enumerate() {
                if action.as_str().starts_with(&prefix) {
                    any = true;
                    if !action.is_always_denied() {
                        picked[slot] = true;
                    }
                }
            }
            if !any {
                return Err(PinGrantsError::UnknownAction);
            }
        } else {
            let action = item
                .parse::<Action>()
                .map_err(|_| PinGrantsError::UnknownAction)?;
            if action.is_always_denied() {
                return Err(PinGrantsError::Socks);
            }
            let slot = Action::ALL
                .iter()
                .position(|&a| a == action)
                .expect("a parsed action is in Action::ALL");
            picked[slot] = true;
        }
    }
    Ok(Action::ALL
        .into_iter()
        .zip(picked)
        .filter_map(|(action, on)| on.then_some(action))
        .collect())
}

fn parse_scope(raw: &str) -> Result<Scope, PinGrantsError> {
    match raw {
        "owned" => Ok(Scope::Owned),
        "any" => Ok(Scope::Any),
        _ => Err(PinGrantsError::BadScope),
    }
}

/// Validate and de-duplicate a `paths` list, keeping first-seen order.
fn clean_paths(raw: &[String]) -> Result<Vec<String>, PinGrantsError> {
    if raw.len() > MAX_PIN_PATHS {
        return Err(PinGrantsError::TooManyPaths);
    }
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for entry in raw {
        validate_entry(entry, PathStyle::HOST)
            .map_err(|why| PinGrantsError::BadPath(why.reason()))?;
        if !out.contains(entry) {
            out.push(entry.clone());
        }
    }
    Ok(out)
}

impl PinGrants {
    /// Build the grants of a pin from its three keys. `Ok(None)` when the pin
    /// has none (no keys at all, or an empty `grants` list with no `paths`
    /// and no `scope`); keys that cannot stand alone are errors.
    pub fn parse(
        grants: Option<&[String]>,
        paths: Option<&[String]>,
        scope: Option<&str>,
    ) -> Result<Option<Self>, PinGrantsError> {
        let grants = grants.filter(|g| !g.is_empty());
        let Some(grants) = grants else {
            return if paths.is_some() || scope.is_some() {
                Err(PinGrantsError::OrphanKeys)
            } else {
                Ok(None)
            };
        };
        let actions = expand_actions(grants)?;
        let has_file = actions.iter().any(|a| a.is_file());
        let paths = match (has_file, paths) {
            (true, Some(raw)) if !raw.is_empty() => Some(clean_paths(raw)?),
            (true, _) => return Err(PinGrantsError::FileGrantNeedsPaths),
            (false, Some(raw)) if !raw.is_empty() => {
                return Err(PinGrantsError::PathsWithoutFileGrant);
            }
            (false, _) => None,
        };
        let scope = scope.map(parse_scope).transpose()?.unwrap_or_default();
        Ok(Some(Self {
            actions,
            paths,
            scope,
        }))
    }

    /// The granted actions, in [`Action::ALL`] order.
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// The `paths` the file grants are limited to; `Some` exactly when
    /// [`Self::actions`] holds a file action.
    pub fn paths(&self) -> Option<&[String]> {
        self.paths.as_deref()
    }

    /// The ownership scope of the grants.
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// Whether `action` is granted (the always-denied gate is the
    /// evaluator's business and runs first; this set never holds it).
    pub fn contains(&self, action: Action) -> bool {
        self.actions.contains(&action)
    }

    /// The canonical `trust.toml` keys for these grants: exact action names,
    /// `scope` written only when it is not the default.
    pub fn keys(&self) -> PinGrantKeys {
        PinGrantKeys {
            grants: Some(
                self.actions
                    .iter()
                    .map(|a| a.as_str().to_string())
                    .collect(),
            ),
            paths: self.paths.clone(),
            scope: match self.scope {
                Scope::Owned => None,
                Scope::Any => Some("any".to_string()),
            },
        }
    }
}

/// The result of applying `trust allow` to a pin's current keys.
pub fn apply_allow(
    current: &PinGrantKeys,
    actions: &[String],
    paths: &[String],
    scope: Option<&str>,
) -> Result<PinGrantKeys, PinGrantsError> {
    let added = expand_actions(actions)?;
    let existing = PinGrants::parse(
        current.grants.as_deref(),
        current.paths.as_deref(),
        current.scope.as_deref(),
    )?;
    let mut names: Vec<String> = existing
        .as_ref()
        .map(|g| g.actions.iter().map(|a| a.as_str().to_string()).collect())
        .unwrap_or_default();
    for action in &added {
        let name = action.as_str().to_string();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let mut merged_paths: Vec<String> = existing
        .as_ref()
        .and_then(|g| g.paths.clone())
        .unwrap_or_default();
    for entry in paths {
        if !merged_paths.contains(entry) {
            merged_paths.push(entry.clone());
        }
    }
    let scope = match scope {
        Some(word) => Some(word.to_string()),
        None => current.scope.clone(),
    };
    let merged = PinGrants::parse(
        Some(&names),
        (!merged_paths.is_empty()).then_some(merged_paths.as_slice()),
        scope.as_deref(),
    )?
    .expect("a non-empty grants list parses to Some");
    Ok(merged.keys())
}

/// The result of applying `trust deny` to a pin's current keys: the named
/// actions leave `grants`; when no file action is left `paths` goes too, and
/// when nothing is left every key goes.
pub fn apply_deny(
    current: &PinGrantKeys,
    actions: &[String],
) -> Result<PinGrantKeys, PinGrantsError> {
    let removed = expand_actions(actions)?;
    let existing = PinGrants::parse(
        current.grants.as_deref(),
        current.paths.as_deref(),
        current.scope.as_deref(),
    )?;
    let Some(existing) = existing else {
        return Ok(PinGrantKeys::default());
    };
    let kept: Vec<String> = existing
        .actions
        .iter()
        .filter(|a| !removed.contains(a))
        .map(|a| a.as_str().to_string())
        .collect();
    if kept.is_empty() {
        return Ok(PinGrantKeys::default());
    }
    let keeps_file = kept.iter().any(|n| n == "file.read" || n == "file.write");
    let paths = if keeps_file {
        existing.paths.clone()
    } else {
        None
    };
    let scope = current.scope.clone();
    Ok(
        PinGrants::parse(Some(&kept), paths.as_deref(), scope.as_deref())?
            .expect("a non-empty grants list parses to Some")
            .keys(),
    )
}

/// Whether `child` is `parent` or lies below it, compared as text, component
/// by component. This is the covering relation the connection watch uses to
/// tell a widened `paths` list from a narrowed one; the request-time match
/// normalizes through the filesystem instead ([`super::paths::entries_cover`]).
pub(crate) fn entry_within(parent: &str, child: &str) -> bool {
    if parent == child {
        return true;
    }
    match child.strip_prefix(parent) {
        Some(rest) => parent.ends_with('/') || rest.starts_with('/'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| i.to_string()).collect()
    }

    #[test]
    fn families_expand_and_stop_short_of_socks() {
        let all = expand_actions(&s(&["forward.*"])).unwrap();
        assert_eq!(
            all,
            vec![
                Action::ForwardLocal,
                Action::ForwardRemote,
                Action::ForwardAgent,
                Action::ForwardJump
            ]
        );
        assert_eq!(
            expand_actions(&s(&["forward.socks"])),
            Err(PinGrantsError::Socks)
        );
        assert_eq!(
            expand_actions(&s(&["nope.*"])),
            Err(PinGrantsError::UnknownAction)
        );
        assert_eq!(
            expand_actions(&s(&["exec"])),
            Err(PinGrantsError::UnknownAction)
        );
        assert_eq!(expand_actions(&[]), Err(PinGrantsError::NoAction));
        // Order and de-duplication follow Action::ALL.
        assert_eq!(
            expand_actions(&s(&["session.list", "exec.run", "session.list"])).unwrap(),
            vec![Action::ExecRun, Action::SessionList]
        );
    }

    #[test]
    fn file_grants_need_paths_and_paths_need_file_grants() {
        assert_eq!(
            PinGrants::parse(Some(&s(&["file.read"])), None, None),
            Err(PinGrantsError::FileGrantNeedsPaths)
        );
        assert_eq!(
            PinGrants::parse(
                Some(&s(&["exec.run"])),
                Some(&s(&[abs_path!("/srv")])),
                None
            ),
            Err(PinGrantsError::PathsWithoutFileGrant)
        );
        assert_eq!(
            PinGrants::parse(None, Some(&s(&[abs_path!("/srv")])), None),
            Err(PinGrantsError::OrphanKeys)
        );
        assert_eq!(PinGrants::parse(None, None, None), Ok(None));
        assert_eq!(
            PinGrants::parse(Some(&s(&["exec.run"])), None, Some("sideways")),
            Err(PinGrantsError::BadScope)
        );
        let ok = PinGrants::parse(
            Some(&s(&["file.read"])),
            Some(&s(&[abs_path!("/srv")])),
            Some("any"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(ok.scope(), Scope::Any);
        assert_eq!(ok.paths(), Some(&s(&[abs_path!("/srv")])[..]));
        assert!(
            PinGrants::parse(Some(&s(&["file.read"])), Some(&s(&["relative/dir"])), None).is_err()
        );
    }

    #[test]
    fn allow_unions_and_deny_clears_what_it_orphans() {
        let none = PinGrantKeys::default();
        let a = apply_allow(&none, &s(&["exec.run"]), &[], None).unwrap();
        assert_eq!(a.grants, Some(s(&["exec.run"])));
        let b = apply_allow(
            &a,
            &s(&["file.read"]),
            &s(&[abs_path!("/srv")]),
            Some("any"),
        )
        .unwrap();
        assert_eq!(b.grants, Some(s(&["exec.run", "file.read"])));
        assert_eq!(b.paths, Some(s(&[abs_path!("/srv")])));
        assert_eq!(b.scope.as_deref(), Some("any"));
        let c = apply_deny(&b, &s(&["file.*"])).unwrap();
        assert_eq!(c.grants, Some(s(&["exec.run"])));
        assert_eq!(c.paths, None, "no file grant left: paths go");
        let d = apply_deny(&c, &s(&["exec.run"])).unwrap();
        assert_eq!(d, PinGrantKeys::default(), "nothing left: every key goes");
        // Denying what is not held is a no-op.
        assert_eq!(apply_deny(&a, &s(&["session.list"])).unwrap(), a);
    }

    fn keys(grants: &[&str], paths: &[&str], scope: Option<&str>) -> PinGrantKeys {
        PinGrantKeys {
            grants: Some(s(grants)),
            paths: (!paths.is_empty()).then(|| s(paths)),
            scope: scope.map(str::to_string),
        }
    }

    /// ADR-0031 결정 5 applied to pin grants: a change narrows exactly when
    /// the new set does not cover the old one. An action dropped, an `any`
    /// scope that became `owned` and a path no longer contained narrow;
    /// the reverse of each, and an unchanged set, do not. An action the role
    /// also grants is not lost by dropping it from the pin.
    #[test]
    fn grant_changes_narrow_by_the_covering_relation() {
        use crate::acl::pin_grants_change_narrows as narrows;
        let none = PinGrantKeys::default();
        let exec = keys(&["exec.run"], &[], None);
        let exec_list = keys(&["exec.run", "session.list"], &[], None);
        assert!(narrows(None, &exec_list, &exec), "an action dropped");
        assert!(!narrows(None, &exec, &exec_list), "an action added");
        assert!(!narrows(None, &exec, &exec), "unchanged");
        assert!(narrows(None, &exec, &none), "everything withdrawn");
        assert!(!narrows(None, &none, &exec));

        let any = keys(&["forward.local"], &[], Some("any"));
        let owned = keys(&["forward.local"], &[], None);
        assert!(narrows(None, &any, &owned), "any became owned");
        assert!(!narrows(None, &owned, &any));

        let wide = keys(&["file.read"], &[abs_path!("/srv")], None);
        let deep = keys(&["file.read"], &[abs_path!("/srv/share")], None);
        let other = keys(&["file.read"], &[abs_path!("/var")], None);
        assert!(narrows(None, &wide, &deep), "paths narrowed");
        assert!(!narrows(None, &deep, &wide), "paths widened");
        assert!(narrows(None, &wide, &other), "paths replaced");
        let both = keys(
            &["file.read"],
            &[abs_path!("/srv"), abs_path!("/var")],
            None,
        );
        assert!(narrows(None, &both, &wide), "a path entry dropped");

        // The role keeps granting `exec.run`, so dropping the pin's copy
        // takes nothing away.
        assert!(!narrows(Some("exec"), &exec, &none));
        assert!(narrows(Some("read-only"), &exec, &none));
    }

    #[test]
    fn entry_within_is_component_wise() {
        assert!(entry_within("/srv", "/srv"));
        assert!(entry_within("/srv", "/srv/a"));
        assert!(!entry_within("/srv", "/srvx"));
        assert!(entry_within("/", "/srv"));
        assert!(!entry_within("/srv/a", "/srv"));
    }
}
