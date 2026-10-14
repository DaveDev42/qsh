//! M15 plan Step 3 (1a4af3b)'s measurement row: what resolving the requester's trust
//! role on every decision costs (ADR-0045 결정 4 "판정마다 읽기", 근거 절).
//!
//! The decision that happens most often is the inline `forward.local` gate
//! of a `-L` forward: one `Authorizer::check` per `TCP_CONNECT`. This test
//! opens short `-L` connections back to back through two hosts that differ
//! in one thing only:
//!
//! - **arm A** runs a bare [`Policy`] with one `[[acl]]` row that allows the
//!   client `forward.local`: rows only, no `trust.toml` involved.
//! - **arm B** runs [`RoleResolvingAuthorizer`] over a policy with no rows,
//!   which on every check refreshes a `trust.toml` holding 100 pins, looks
//!   the requester's pin up and allows `forward.local` through its `full`
//!   role. This is the production wiring (`acl::load_or_deny`).
//!
//! The decision is allow in both arms; only the lookup differs. (Step 3
//! measured the lookup alone, with the role discarded; since Step 4 the
//! role is the grant, so arm B pays for both the lookup and the role
//! stage.) The two
//! hosts stay up for the whole run and take turns in batches, so machine
//! drift hits both alike. The test prints per-connection median and p95 for
//! each arm and their ratio.
//!
//! **Gating.** The numbers are always printed. The 10% budget on the median
//! (M15 plan §7.1 #2 (1a4af3b): above it, `SharedTrustStore::refresh` switches to the
//! stat pre-check named in ADR-0045's rationale) is asserted only under
//! `QSH_ACCEPTANCE_STRICT`, like the other latency gates; a latency
//! assertion is run without competing load.

use std::sync::Arc;
use std::time::Instant;

use qsh_core::acl::{
    Action, ActionPattern, Authorizer, Policy, RoleResolvingAuthorizer, Rule, Scope,
};
use qsh_core::trust::SharedTrustStore;
use qsh_testkit::loopback::make_identity;
use qsh_testkit::tunnel::TunnelHarness;
use qsh_transport::{AuthPath, Fingerprint, Principal, StaticTrust};

/// Pins in `trust.toml`, the client's own among them (M15 plan §7.1 #2 (1a4af3b)).
const PINS: usize = 100;
/// Connections each arm is timed over.
const CONNECTIONS_PER_ARM: usize = 1000;
/// Connections per turn before the other arm takes over.
const BATCH: usize = 50;
/// Untimed connections each arm opens first.
const WARMUP: usize = 100;
/// M15 plan §7.1 #2 (1a4af3b): a difference within 10% keeps the full read per decision.
const MAX_MEDIAN_RATIO: f64 = 1.10;

fn env_flag(name: &str) -> bool {
    let Some(value) = std::env::var_os(name) else {
        return false;
    };
    let value = value.to_string_lossy().to_lowercase();
    let value = value.trim().to_string();
    !(value.is_empty() || value == "0")
}

/// Nearest-rank percentile (`p` in `[0, 1]`) over `samples`.
fn percentile(samples: &[f64], p: f64) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let idx = ((sorted.len() as f64) * p).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

/// A `trust.toml` with [`PINS`] pins, the last one `laptop` (the harness
/// client's name) carrying `role = "full"`.
fn trust_toml(client: &Fingerprint) -> String {
    let mut text = String::new();
    for i in 0..PINS - 1 {
        text.push_str(&format!(
            "[[peer]]\nname = \"filler-{i}\"\nfingerprint = \"{}\"\naddress = \"\"\n\
             added_at = \"2026-10-14T00:00:00Z\"\nrole = \"none\"\n\n",
            Fingerprint::of_spki_der(format!("filler-{i}").as_bytes())
        ));
    }
    text.push_str(&format!(
        "[[peer]]\nname = \"laptop\"\nfingerprint = \"{client}\"\naddress = \"\"\n\
         added_at = \"2026-10-14T00:00:00Z\"\nrole = \"full\"\n"
    ));
    text
}

/// Arm A's rows: the harness client may open local forwards, nothing else.
fn rows_only_policy() -> Policy {
    Policy {
        rules: vec![Rule {
            paths: None,
            principal: "device:laptop".to_string(),
            auth_path: AuthPath::Pin,
            allow: vec![ActionPattern::Exact(Action::ForwardLocal)],
            scope: Scope::Any,
        }],
    }
}

struct Arm {
    harness: TunnelHarness,
    forward: qsh_core::tunnel::LocalForwardHandle,
    samples_ms: Vec<f64>,
}

impl Arm {
    async fn start(
        authorizer: Arc<dyn Authorizer>,
        client: qsh_testkit::loopback::TestIdentity,
    ) -> Self {
        let server_trust =
            StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
        let harness = TunnelHarness::start_custom(authorizer, client, server_trust).await;
        let forward = harness
            .local_forward("127.0.0.1", harness.echo.port())
            .await;
        Self {
            harness,
            forward,
            samples_ms: Vec::with_capacity(CONNECTIONS_PER_ARM),
        }
    }

    async fn connect_once(&self) -> f64 {
        let started = Instant::now();
        let got = TunnelHarness::round_trip(self.forward.local_addr(), b"x".to_vec())
            .await
            .expect("short -L round trip");
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(got, b"x");
        elapsed
    }

    async fn run_batch(&mut self, n: usize) {
        for _ in 0..n {
            let ms = self.connect_once().await;
            self.samples_ms.push(ms);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn role_resolution_per_decision_costs_within_ten_percent_on_short_local_forwards() {
    let dir = tempfile::tempdir().unwrap();
    let trust_path = dir.path().join("trust.toml");

    let client_a = make_identity();
    let client_b = make_identity();
    // The pin in `trust.toml` is arm B's client, so every arm-B decision
    // finds its pin (the lookup's longest path) and parses its role.
    std::fs::write(&trust_path, trust_toml(&client_b.fingerprint)).unwrap();
    let trust = SharedTrustStore::open(&trust_path).expect("open trust.toml");

    let mut a = Arm::start(Arc::new(rows_only_policy()), client_a).await;
    let mut b = Arm::start(
        Arc::new(RoleResolvingAuthorizer::new(
            Policy::default(),
            Arc::clone(&trust),
        )),
        client_b,
    )
    .await;

    // Warm-up: both arms, untimed, so connection setup costs paid once
    // (page faults, allocator growth) are not charged to the first batch.
    for _ in 0..WARMUP {
        a.connect_once().await;
        b.connect_once().await;
    }

    let mut done = 0;
    while done < CONNECTIONS_PER_ARM {
        a.run_batch(BATCH).await;
        b.run_batch(BATCH).await;
        done += BATCH;
    }

    let (a_med, a_p95) = (
        percentile(&a.samples_ms, 0.5),
        percentile(&a.samples_ms, 0.95),
    );
    let (b_med, b_p95) = (
        percentile(&b.samples_ms, 0.5),
        percentile(&b.samples_ms, 0.95),
    );
    let ratio = b_med / a_med;
    eprintln!(
        "role_resolution_per_decision_costs_within_ten_percent_on_short_local_forwards: \
         pins={PINS} connections={CONNECTIONS_PER_ARM} per arm; \
         A (no role lookup) median={a_med:.4}ms p95={a_p95:.4}ms; \
         B (role lookup per decision) median={b_med:.4}ms p95={b_p95:.4}ms; \
         median ratio B/A={ratio:.3} (budget <= {MAX_MEDIAN_RATIO})"
    );

    drop(a.forward);
    drop(b.forward);
    a.harness.shutdown().await;
    b.harness.shutdown().await;

    if env_flag("QSH_ACCEPTANCE_STRICT") {
        assert!(
            ratio <= MAX_MEDIAN_RATIO,
            "resolving the role on every decision slowed the median short -L connection by \
             {:.1}% (A {a_med:.4}ms, B {b_med:.4}ms); above the 10% budget the plan's \
             pre-decided fallback applies: SharedTrustStore::refresh checks \
             (size, mtime ns, dev/inode) before reading the file",
            (ratio - 1.0) * 100.0
        );
    }
}
