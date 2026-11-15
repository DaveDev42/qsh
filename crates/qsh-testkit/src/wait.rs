//! Bounded polling for assertions that have no channel to await.

use std::time::Duration;

use qsh_core::audit::{AuditRecord, MemoryAuditSink};

/// Poll `f` until it returns `Some`, or panic after `timeout`. A bounded,
/// event-driven substitute for a fixed `sleep()`
/// (`docs/design/testing.md`: "sleep() 전면 금지") for the assertions that
/// have no dedicated notification channel to await instead.
pub async fn wait_for<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(v) = f() {
                return v;
            }
            // A poll interval inside a `tokio::time::timeout`-bounded loop,
            // not the unconditioned fixed delay `docs/design/testing.md`
            // bans — same distinction `qsh-cli/tests/it/common/mod.rs`'s
            // `wait_for_audit` draws for its own deadline-bounded poll.
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("condition not observed within {timeout:?}"))
}

/// [`wait_for`] specialized to "at least `n` audit records exist yet".
pub async fn wait_for_audit_records(
    audit: &MemoryAuditSink,
    n: usize,
    timeout: Duration,
) -> Vec<AuditRecord> {
    wait_for(timeout, || {
        let records = audit.records();
        (records.len() >= n).then_some(records)
    })
    .await
}
