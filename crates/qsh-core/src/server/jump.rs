//! The host side of a `JUMP` stream: admission for an intermediate peer
//! (ADR-0056 decisions 7 to 9, `docs/design/protocol.md` §21.3).
//!
//! Like `TCP_CONNECT`, a `JUMP` stream carries no ticket: the `forward.jump`
//! decision is made inline, at the moment the stream is opened, and nothing
//! exists before it is allowed and recorded. The order is fixed and a step
//! that fails stops the ones after it:
//!
//! 1. shape: `jump_channel` is 16 bytes and not in use on this connection,
//!    `host` and `port` have the `TCP_CONNECT` shape. `INVALID_ARGUMENT`, no
//!    ACL, no audit.
//! 2. `forward.jump` through [`check_jump`], which records the decision. A
//!    denial and a failed audit write both answer the uniform
//!    `PERMISSION_DENIED`.
//! 3. bounds: the connection's channel cap and the tunnel-stream quota
//!    (`RESOURCE_EXHAUSTED`).
//! 4. one name resolution, 5 s. `CONNECTION_FAILED`.
//! 5. host-local addresses are dropped from the answer, always. When nothing
//!    is left the answer is `PERMISSION_DENIED` and one more audit line.
//! 6. a UDP socket of the first remaining address's family, bound to the
//!    unspecified address and a kernel-chosen port, `connect`ed to it.
//! 7. `ConnectResult{ok}`, and [`crate::jump::middle::run`] takes over.
//!
//! The resolved address reaches neither a log nor the audit nor the reply.

use qsh_proto::datagram::ChannelId;
use qsh_proto::wire::{self, StreamHeader};
use qsh_transport::{Connection, FramedStream};
use tokio::net::UdpSocket;

use super::tunnels::{destination_shape, refuse_connect};
use super::{ConnCtx, Server, connect_rejected};
use crate::acl::{JumpVerdict, check_jump};
use crate::datagram::DatagramHub;
use crate::jump::middle::{self, ChannelGuard, JumpOptions, JumpStats, Relay};
use crate::tunnel::dial::is_host_local;
use qsh_proto::ErrorCode;

/// What admission leaves behind for the relay.
struct Admitted {
    socket: UdpSocket,
    guard: ChannelGuard,
    /// Held for the channel's whole life: a `JUMP` stream counts as a
    /// tunnel stream (ADR-0056 decision 9, ADR-0010).
    _permit: crate::quota::TunnelStreamPermit,
}

impl Server {
    /// Make this host's intermediate-peer timers and filter other than the
    /// defaults. For tests (a shortened idle, a loopback target); production
    /// never calls it. First call wins.
    pub fn set_jump_options(&self, options: JumpOptions) {
        let _ = self.jump_options.set(options);
    }

    /// Make the path eat this host's kind 14 datagrams toward the client:
    /// they are accepted and silently dropped, as a middlebox that discards
    /// only UDP payloads of that shape would, while every other datagram and
    /// every stream keeps working. For the silence-fallback test
    /// (ADR-0058); production never calls it. Takes effect for every
    /// channel, including running ones.
    pub fn blackhole_jump_datagrams(&self, on: bool) {
        self.jump_datagram_blackhole
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// This host's jump counters.
    pub fn jump_stats(&self) -> &std::sync::Arc<JumpStats> {
        &self.jump_stats
    }

    fn jump_options(&self) -> JumpOptions {
        self.jump_options.get().copied().unwrap_or_default()
    }

    /// Serve one `JUMP` stream as an intermediate peer.
    pub(super) async fn handle_jump(
        &self,
        ctx: &ConnCtx,
        stream: FramedStream,
        header: &StreamHeader,
        conn: &Connection,
    ) {
        // The packets J carries are the inner connection's, whatever it
        // carries: they ride the session band (decision 9).
        stream.send.set_priority(wire::PRIORITY_SESSION_DATA);
        let options = self.jump_options();
        let admitted = match self.admit_jump(ctx, header, &options).await {
            Ok(admitted) => admitted,
            Err(rejection) => {
                refuse_connect(stream, &rejection).await;
                return;
            }
        };
        let Admitted {
            socket,
            guard,
            _permit,
        } = admitted;
        let Some(channel) = header.jump_channel() else {
            // Checked in `admit_jump`; kept as a refusal, not a panic.
            return;
        };
        // Registered before the reply, so a datagram that follows the
        // client's reading of `ok` finds its channel.
        let datagrams = DatagramHub::of(conn).register(ChannelId(channel));
        let mut stream = stream;
        let ok = wire::ConnectResult {
            ok: true,
            code: String::new(),
            message: String::new(),
        };
        if stream.send.send(&ok).await.is_err() {
            return;
        }
        let (send, recv) = stream.split();
        let (recv, residue) = recv.into_raw();
        let reason = middle::run(Relay {
            socket,
            send: send.into_raw(),
            recv,
            residue,
            datagrams,
            both_datagram: ctx.has_capability(wire::CAP_DATAGRAM_V1),
            options,
            stats: std::sync::Arc::clone(&self.jump_stats),
            guard,
            blackhole: std::sync::Arc::clone(&self.jump_datagram_blackhole),
        })
        .await;
        tracing::debug!(
            principal = %ctx.principal,
            reason = reason.as_str(),
            "jump channel closed"
        );
    }

    /// Steps 1 to 6 of the processing order. `Err` is the `ConnectResult` to
    /// hand the requester.
    async fn admit_jump(
        &self,
        ctx: &ConnCtx,
        header: &StreamHeader,
        options: &JumpOptions,
    ) -> Result<Admitted, wire::ConnectResult> {
        // (1) Shape.
        let Some(channel) = header.jump_channel() else {
            return Err(connect_rejected(
                ErrorCode::InvalidArgument,
                "jump channel must be exactly 16 bytes",
            ));
        };
        let Some(mut guard) = self.jump.claim(ctx.conn_id, channel, &self.jump_stats) else {
            return Err(connect_rejected(
                ErrorCode::InvalidArgument,
                "jump channel already in use on this connection",
            ));
        };
        let (port, resource) = destination_shape(header)?;

        // (2) `forward.jump`, decided and recorded before anything exists.
        match check_jump(
            self.authorizer.as_ref(),
            self.audit.as_ref(),
            None,
            &resource,
            &ctx.requester(),
            &ctx.peer_addr,
        ) {
            JumpVerdict::Allowed => {}
            JumpVerdict::Denied | JumpVerdict::AuditFailed => {
                return Err(connect_rejected(
                    ErrorCode::PermissionDenied,
                    crate::acl::PERMISSION_DENIED_MESSAGE,
                ));
            }
        }

        // (3) Bounds. After the decision, so an unauthorized peer never
        // learns where a bound sits.
        if !guard.reserve(options.max_channels_per_conn) {
            return Err(connect_rejected(
                ErrorCode::ResourceExhausted,
                "too many jump channels on this connection",
            ));
        }
        let opener = crate::acl::opener_key(&ctx.principal, ctx.auth_path);
        let permit = match self.quotas.reserve_tunnel_stream(&opener, &resource) {
            Ok(permit) => permit,
            Err(kind) => {
                let records = self.quotas.record_rejection(
                    kind,
                    &opener,
                    &ctx.peer_addr,
                    self.quotas.now(),
                    None,
                    ctx.auth_path,
                );
                crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                return Err(connect_rejected(
                    ErrorCode::ResourceExhausted,
                    kind.wire_message(),
                ));
            }
        };

        // (4) One resolution. The result is never logged.
        let resolved = tokio::time::timeout(
            options.resolve_timeout,
            tokio::net::lookup_host((header.host.as_str(), port)),
        )
        .await;
        let addrs: Vec<std::net::SocketAddr> = match resolved {
            Ok(Ok(addrs)) => addrs.collect(),
            _ => Vec::new(),
        };
        if addrs.is_empty() {
            tracing::debug!(principal = %ctx.principal, %resource, "jump target did not resolve");
            return Err(connect_rejected(
                ErrorCode::ConnectionFailed,
                "destination could not be resolved",
            ));
        }

        // (5) Host-local addresses are never a jump target.
        let target = addrs
            .into_iter()
            .find(|addr| options.allow_host_local || !is_host_local(addr.ip()));
        let Some(target) = target else {
            if !crate::acl::record_host_local_deny(
                self.audit.as_ref(),
                &resource,
                &ctx.requester(),
                &ctx.peer_addr,
            ) {
                tracing::warn!(
                    principal = %ctx.principal,
                    %resource,
                    "jump: host-local deny audit record failed to write"
                );
            }
            return Err(connect_rejected(
                ErrorCode::PermissionDenied,
                crate::acl::PERMISSION_DENIED_MESSAGE,
            ));
        };

        // (6) The socket. Its family is the target's; it is `connect`ed, so
        // the kernel drops datagrams from any other source and reports the
        // target's ICMP refusal on this socket.
        let local: std::net::SocketAddr = if target.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = match UdpSocket::bind(local).await {
            Ok(socket) => socket,
            Err(err) => {
                tracing::debug!(principal = %ctx.principal, %err, "jump socket bind failed");
                return Err(connect_rejected(
                    ErrorCode::ConnectionFailed,
                    "destination is not reachable from this host",
                ));
            }
        };
        if let Err(err) = socket.connect(target).await {
            tracing::debug!(principal = %ctx.principal, %err, "jump socket connect failed");
            return Err(connect_rejected(
                ErrorCode::ConnectionFailed,
                "destination is not reachable from this host",
            ));
        }
        Ok(Admitted {
            socket,
            guard,
            _permit: permit,
        })
    }
}
