//! The live-connection table [`ConnTable`] that [`Listen`] publishes registrations into.

use super::*;

/// The live-connection table [`Listen::finish_registration`] publishes into
/// and [`Listen::drive_registered_session`] retires from — keyed by `name`
/// alone, generation carried in the value, generic over `T` so the
/// race-freedom argument below is unit-testable without a real
/// [`Connection`] (this module's tests use a small mock).
///
/// **`PLAN.md` M3 Step 4 (4) — the Step 3 race debt this fixes.** The old
/// shape keyed `conns` by `(name, generation)` and published a new
/// connection with a separate insert-then-remove sequence: insert
/// `(name, new_generation)`, then — if [`Registry::admit`]'s
/// `replaced_generation` said so — remove `(name, old_generation)` and
/// close what came back. Two concurrent same-fingerprint registrations
/// whose `admit()` calls land in one order but whose `finish_registration`
/// continuations resume in the *other* order could each publish under a
/// distinct `(name, generation)` key with no relationship enforced between
/// them — the second continuation's `remove` could find nothing (the first
/// hadn't inserted yet) and close nothing, leaving that generation's
/// connection permanently unreferenced: never the table's current entry,
/// never closed by anyone.
///
/// Keying by `name` alone removes the two-step gap entirely: publishing is
/// one `HashMap::insert`, so whichever call actually lands second
/// necessarily sees what the first one left behind, in the same critical
/// section it installs its own value in. [`ConnTable::publish`]'s
/// generation guard is what makes that safe to rely on regardless of
/// *which* call happens to run second — see its own doc comment for the
/// two-registration replay this was built against.
pub(super) struct ConnTable<T> {
    inner: Mutex<HashMap<String, (u64, T)>>,
}

/// What a caller of [`ConnTable::publish`] must do with the result.
pub(super) enum Published<T> {
    /// This call's value is now `name`'s occupant. `Some` is whatever it
    /// replaced — the caller closes that (never its own value).
    Installed(Option<T>),
    /// A `generation` at least as new was already published under `name`
    /// before this call ran, so this call's value never became the
    /// occupant. The caller must close *its own* value instead — nothing
    /// else references it, so leaving it open would leak exactly the
    /// connection [`ConnTable`]'s own doc comment describes.
    Superseded(T),
}

impl<T> ConnTable<T> {
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (u64, T)>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Publish `(generation, value)` under `name` — installing it only if
    /// `generation` is strictly newer than whatever is currently there (or
    /// nothing is). One `HashMap::insert` under this table's own lock: no
    /// read-then-write gap for a second concurrent caller to land inside
    /// ([`ConnTable`]'s own doc comment).
    ///
    /// **Replay of the race this fixes**, both possible continuation
    /// orders, starting from a pre-existing occupant at generation `0` and
    /// two concurrent same-fingerprint registrations whose `admit()` calls
    /// (elsewhere, strictly ordered by [`Registry`]'s own lock) produced
    /// generations `1` then `2`:
    ///
    /// - Continuations run in `admit()` order (`1` then `2`): `1` finds `0`
    ///   installs, hands back `0` to close. `2` finds `1`, installs, hands
    ///   back `1` to close. Final occupant: `2`. Closed: `0`, `1`.
    /// - Continuations run in the *other* order (`2` then `1`, the bug
    ///   scenario): `2` finds `0`, installs, hands back `0` to close. `1`
    ///   finds `2` — not newer than its own `1` — so it does **not**
    ///   install; it gets its own value back as [`Published::Superseded`]
    ///   and must close *that*. Final occupant: `2`. Closed: `0`, `1`.
    ///
    /// Both orders converge on the same end state — the highest generation
    /// open, every other value closed exactly once, nothing leaked.
    pub(super) fn publish(&self, name: String, generation: u64, value: T) -> Published<T> {
        let mut table = self.lock();
        match table.get(&name) {
            Some((existing, _)) if *existing >= generation => Published::Superseded(value),
            _ => Published::Installed(table.insert(name, (generation, value)).map(|(_, v)| v)),
        }
    }

    /// Remove `name`'s entry iff it is still exactly `generation` — the
    /// same "only touch what I still believe is mine" guard
    /// [`Registry::mark_stale`]/[`Registry::rollback`] apply registry-side.
    /// Returns whether it was removed: `false` means a newer registration
    /// already superseded this one (which already got its own `"replaced"`
    /// event — the caller must not also treat this as a fresh loss).
    pub(super) fn remove_if(&self, name: &str, generation: u64) -> bool {
        let mut table = self.lock();
        let matches = matches!(table.get(name), Some((g, _)) if *g == generation);
        if matches {
            table.remove(name);
        }
        matches
    }

    pub(super) fn len(&self) -> usize {
        self.lock().len()
    }

    /// The generation currently published under `name`, if any. A
    /// non-mutating peek — used only to check whether a connection is
    /// still actually the live occupant before restoring metadata that
    /// describes it (see [`rollback_target`]).
    fn occupant_generation(&self, name: &str) -> Option<u64> {
        self.lock().get(name).map(|(g, _)| *g)
    }
}

impl<T: Clone> ConnTable<T> {
    /// `name`'s current occupant, whatever generation it happens to be —
    /// [`Listen::control_hub`]'s lookup: a caller outside this file that
    /// just wants "the live one, if any" rather than a specific
    /// generation (see [`Self::get_matching`] for that).
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) fn get(&self, name: &str) -> Option<T> {
        self.lock().get(name).map(|(_, v)| v.clone())
    }

    /// `name`'s current occupant iff it is still exactly `generation` — a
    /// non-mutating peek, the read-side counterpart to
    /// [`ConnTable::remove_if`]'s generation guard. `M3 Step 6`'s
    /// [`Listen::hubs`] table uses this to hand `daemon.rs` a
    /// [`ControlHub`] only when it is genuinely still that host's live
    /// one, never a generation a newer registration has already
    /// superseded.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) fn get_matching(&self, name: &str, generation: u64) -> Option<T> {
        match self.lock().get(name) {
            Some((g, v)) if *g == generation => Some(v.clone()),
            _ => None,
        }
    }

    /// Every current occupant, by name — [`Listen::hubs_snapshot`]'s own
    /// use (`PLAN.md` M4 Step 5 PR 5b's `LocalTunnelList`/admin
    /// `tunnel.close`): unlike [`Self::get`]/[`Self::get_matching`], which
    /// answer "the one host I already know the name of", these two admin
    /// requests carry no host at all and must consider every live
    /// registration this controller currently holds, the same "no host
    /// named, consider everything live" shape [`Registry::snapshot`]
    /// already has for [`LocalHostList`](qsh_proto::local::LocalHostList).
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) fn snapshot(&self) -> Vec<(String, T)> {
        self.lock()
            .iter()
            .map(|(name, (_, v))| (name.clone(), v.clone()))
            .collect()
    }
}

/// Decide what [`Registry::rollback`] should actually restore.
/// [`RegisterOutcome::replaced_entry`] is a *snapshot* taken at `admit()`
/// time — by the time a failed `Hello` reply triggers a rollback
/// (`Listen::register_connection`'s error branch), the connection that
/// snapshot describes may have already died on its own and removed itself
/// from `conns` (its watchdog declared the path dead and
/// [`Listen::drive_registered_session`] ran `conns.remove_if`), or a
/// further registration may have replaced it again. Restoring the
/// snapshot verbatim in either case would put a `Live` registry row back
/// with no connection behind it — and nothing would ever mark it stale,
/// since `mark_stale` needs a drive loop to call it, and that loop already
/// exited (adversarial review finding: "a permanent phantom host").
///
/// So the snapshot is only trustworthy while `conns` still shows it as
/// `name`'s current occupant — otherwise the rollback must free the name,
/// exactly like a rollback of a *fresh* (non-replacing) registration
/// already does for `replaced: None`.
pub(super) fn rollback_target<T>(
    conns: &ConnTable<T>,
    name: &str,
    replaced: Option<registry::ReverseEntry>,
) -> Option<registry::ReverseEntry> {
    replaced.filter(|prev| conns.occupant_generation(name) == Some(prev.generation))
}
