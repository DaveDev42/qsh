//! `jump_stream_carrier` (ADR-0056 decision 22), kept apart from `doctor.rs`
//! because it dials a whole chain.

use super::*;

impl Ops {
    /// `jump_stream_carrier` (ADR-0056 decision 22): builds the chain to
    /// `host` once, waits a moment for the first datagram room to open, and
    /// names every step that carries its inner connection on the stream. No
    /// chain, a chain that does not come up (the reachability findings and
    /// the transport probe say why), or a chain of datagram steps is silence.
    pub(super) fn doctor_jump_carrier_finding(&self, host: &str) -> Option<DoctorFinding> {
        use crate::jump::carrier::Carrier;
        use std::sync::atomic::Ordering;

        const SETTLE: Duration = Duration::from_millis(1500);
        let hops = self.jump_hops_for(host).ok().flatten()?;
        let PeerRoute::Forward(target) = self.resolve_route(host).ok()? else {
            return None;
        };
        let plan = target.jump.clone()?;
        let runtime = self.connect_runtime().ok()?;
        let dialer = qsh_transport::Dialer::new(
            target.identity.local.clone(),
            target.trust.clone() as std::sync::Arc<dyn qsh_transport::TrustEvaluator>,
        );
        let first = plan.step(0).clone();
        let chain = runtime.block_on(async {
            let server_name = crate::ops::server_name_for(&first.address);
            let routed = crate::ops::route::dial_routed(
                &dialer,
                &first.address,
                &server_name,
                plan.first_punch.as_ref(),
                None,
                TransportTuning::default(),
                &crate::ops::SystemResolver,
                crate::ops::route::Dial::Command,
            )
            .await
            .ok()?;
            let deadline = tokio::time::Instant::now() + TRANSPORT_PROBE_DIAL_BUDGET;
            let chain = crate::jump::dial_chain(
                &plan,
                &dialer,
                (routed.connection, routed.endpoint),
                deadline,
            )
            .await
            .ok()?;
            tokio::time::sleep(SETTLE).await;
            Some(chain)
        })?;
        let total = hops.len() + 1;
        let mut stream_steps = Vec::new();
        for (index, channel) in chain.info.channels.iter().enumerate() {
            if channel.carrier() == Carrier::Stream {
                // Channel `index` carries the connection to step `index + 1`.
                let reason = if channel.silence_fallbacks.load(Ordering::Relaxed) > 0 {
                    "datagrams stopped arriving"
                } else if channel.oversize_dropped.load(Ordering::Relaxed) > 0 {
                    "packets were larger than the datagram room"
                } else {
                    "datagram.v1 is not offered or the link leaves no room for a datagram"
                };
                stream_steps.push(format!(
                    "step {}/{} ({}): {}",
                    index + 2,
                    total,
                    plan.step(index + 1).name,
                    reason
                ));
            }
        }
        chain.connection.close(0, b"done");
        runtime.block_on(async {
            let _ =
                tokio::time::timeout(Duration::from_millis(300), chain.endpoint.wait_idle()).await;
        });
        if stream_steps.is_empty() {
            return None;
        }
        let diag = &crate::doctor::JUMP_STREAM_CARRIER;
        Some(DoctorFinding {
            code: diag.code.to_string(),
            status: "info".to_string(),
            detail: format!("{} ({})", diag.message, stream_steps.join("; ")),
            remedy: Some(diag.remedy.to_string()),
        })
    }
}
