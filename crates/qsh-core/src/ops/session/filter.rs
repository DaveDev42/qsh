//! Client-side `qsh sessions` filters (ADR-0033 decisions 1-3).
//!
//! The filter runs in the client [`Ops`](crate::ops::Ops) *after* the host
//! has answered. `SessionListReq` and the wire `SessionList` message carry
//! no filter field, so the host cannot tell a filtered call from an
//! unfiltered one, and a filter can only narrow what the caller's
//! `session.list` ACL scope already returned. It lives here rather than in
//! `qsh-proto` because it is an argument of the client, not a contract type.

use std::collections::HashSet;

use qsh_proto::Session;

/// The reserved `--writer` value that selects sessions nobody holds the
/// writer lease of (`writer: null`).
pub const WRITER_NONE: &str = "none";

/// Which sessions `qsh sessions` keeps. Every set field must match (AND);
/// the default keeps everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionFilter {
    /// Keep sessions whose `state` equals this string exactly. An unknown
    /// value is not an error: it matches nothing (ADR-0033 decision 1).
    pub state: Option<String>,
    /// Keep sessions held by this writer principal, or with no writer when
    /// the value is [`WRITER_NONE`].
    pub writer: Option<String>,
    /// Keep only sessions this device holds a resume credential for, i.e.
    /// the ones `qsh attach` will not refuse with `no_resume_token`.
    pub attachable: bool,
}

impl SessionFilter {
    /// Whether no filter is set, in which case [`Self::apply`] is the
    /// identity and the resume state file is never read.
    pub fn is_empty(&self) -> bool {
        self.state.is_none() && self.writer.is_none() && !self.attachable
    }

    /// Keep the sessions of `sessions` this filter accepts, in order.
    ///
    /// `held` is the set of `session_ref`s this device has a credential
    /// for; it is only consulted when [`Self::attachable`] is set, so the
    /// caller reads the state file lazily (see [`Self::needs_resume_state`]).
    pub fn apply(&self, sessions: Vec<Session>, held: &HashSet<String>) -> Vec<Session> {
        sessions
            .into_iter()
            .filter(|s| self.accepts(s, held))
            .collect()
    }

    /// Whether [`Self::apply`] needs the set of held credentials.
    pub fn needs_resume_state(&self) -> bool {
        self.attachable
    }

    fn accepts(&self, session: &Session, held: &HashSet<String>) -> bool {
        if self.state.as_deref().is_some_and(|s| s != session.state) {
            return false;
        }
        if let Some(want) = self.writer.as_deref() {
            let matches = if want == WRITER_NONE {
                session.writer.is_none()
            } else {
                session.writer.as_deref() == Some(want)
            };
            if !matches {
                return false;
            }
        }
        !self.attachable || held.contains(&session.session_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: &str, state: &str, writer: Option<&str>) -> Session {
        Session {
            session_ref: format!("box/{id}"),
            host: "box".into(),
            session_id: id.into(),
            state: state.into(),
            writer: writer.map(str::to_string),
            created_at: "2026-10-15T00:00:00Z".into(),
            last_sequence: 0,
        }
    }

    fn corpus() -> Vec<Session> {
        vec![
            session("a", "running", Some("fp:aa")),
            session("b", "running", None),
            session("c", "exited", None),
            session("d", "exited", Some("fp:bb")),
        ]
    }

    fn ids(sessions: &[Session]) -> Vec<&str> {
        sessions.iter().map(|s| s.session_id.as_str()).collect()
    }

    fn held(refs: &[&str]) -> HashSet<String> {
        refs.iter().map(|r| (*r).to_string()).collect()
    }

    #[test]
    fn the_default_filter_keeps_everything_in_order() {
        let filter = SessionFilter::default();
        assert!(filter.is_empty());
        assert!(!filter.needs_resume_state());
        let out = filter.apply(corpus(), &HashSet::new());
        assert_eq!(ids(&out), ["a", "b", "c", "d"]);
    }

    #[test]
    fn state_is_an_exact_match_and_an_unknown_state_is_empty() {
        let running = SessionFilter {
            state: Some("running".into()),
            ..Default::default()
        };
        assert_eq!(ids(&running.apply(corpus(), &HashSet::new())), ["a", "b"]);
        for near_miss in ["Running", "run", "running ", ""] {
            let filter = SessionFilter {
                state: Some(near_miss.into()),
                ..Default::default()
            };
            assert!(
                filter.apply(corpus(), &HashSet::new()).is_empty(),
                "{near_miss:?} is not an exact state"
            );
        }
    }

    #[test]
    fn writer_none_selects_null_and_a_principal_selects_its_own() {
        let none = SessionFilter {
            writer: Some(WRITER_NONE.into()),
            ..Default::default()
        };
        assert_eq!(ids(&none.apply(corpus(), &HashSet::new())), ["b", "c"]);
        let one = SessionFilter {
            writer: Some("fp:aa".into()),
            ..Default::default()
        };
        assert_eq!(ids(&one.apply(corpus(), &HashSet::new())), ["a"]);
        let nobody = SessionFilter {
            writer: Some("fp:zz".into()),
            ..Default::default()
        };
        assert!(nobody.apply(corpus(), &HashSet::new()).is_empty());
    }

    #[test]
    fn attachable_keeps_only_sessions_with_a_held_credential() {
        let filter = SessionFilter {
            attachable: true,
            ..Default::default()
        };
        assert!(filter.needs_resume_state());
        let out = filter.apply(corpus(), &held(&["box/b", "box/d", "box/unrelated"]));
        assert_eq!(ids(&out), ["b", "d"]);
        assert!(filter.apply(corpus(), &HashSet::new()).is_empty());
    }

    #[test]
    fn several_filters_are_and_combined() {
        let filter = SessionFilter {
            state: Some("exited".into()),
            writer: Some(WRITER_NONE.into()),
            attachable: true,
        };
        // `b` is attachable and writer-less but running; `d` is exited and
        // attachable but has a writer; only `c` passes all three.
        let out = filter.apply(corpus(), &held(&["box/b", "box/c", "box/d"]));
        assert_eq!(ids(&out), ["c"]);
    }
}
