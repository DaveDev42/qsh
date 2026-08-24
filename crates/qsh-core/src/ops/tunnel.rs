//! `tunnel.*` operations (`docs/CLI.md` §6.9, §6.14; `PLAN.md` M4 Step 3,
//! Step 4).
//!
//! M4 Step 3 landed `tunnel.open` in `"local"` mode — the standalone twin
//! of the interactive `qsh [user@]host -L spec` form (whose entry point is
//! [`crate::ops::SessionAttachStream::open_local_forwards`], because that
//! form's forwards ride the attach's own connection). M4 Step 4 (this
//! addition) lands `"remote"` mode the same way, with
//! [`Ops::session_attach`]'s `remote_forward_specs` parameter as its
//! interactive twin. `tunnel.list`/`tunnel.close` belong to Step 5 and are
//! absent rather than stubbed.
//!
//! **Holder model** (`PLAN.md` M4 §4.1 #1, `docs/CLI.md` §6.14).
//! `tunnel.open` is a *value* operation that returns one envelope
//! immediately — and then the process that called it has to stay alive,
//! because it *is* the tunnel. [`TunnelHold`] is that obligation made
//! into a type: it owns the connection and the forward (a local listener,
//! or — Step 4 — a remote forward's peer-side registration plus this
//! side's `TCP_ACCEPTED` acceptor), hands the frontend the [`Tunnel`] DTO
//! to render, and then blocks in [`TunnelHold::hold`] until the forward or
//! the connection dies. Dropping it instead is a complete teardown. There
//! is no resident client daemon and no tunnel registry anywhere in this
//! design.
//!
//! **Where the authorization is.** Nowhere here, on *either* mode. A local
//! forward's ACL check (`forward.local`) happens on the peer, inline at
//! every `TCP_CONNECT` stream open, before the peer dials anything
//! (`docs/design/protocol.md` §7's sole ticket exception;
//! `crate::server::Server::authorize_and_dial_tunnel`) — this side binds a
//! loopback listener, which grants nothing and creates nothing remote. A
//! remote forward's ACL check (`forward.remote`) and its loopback-only
//! bind enforcement both happen on the peer too, at `RemoteForwardOpen`
//! (`crate::server::Server::authorize_and_bind_remote_forward`) — this
//! side sends the request and, only on success, starts dialing whatever
//! `TCP_ACCEPTED` streams come back.

use qsh_proto::wire::{self, ForwardDirection, ForwardSpec, parse_forward_spec};
use qsh_proto::{ErrorCode, Tunnel, TunnelOpenReq};

use crate::ops::session::Connected;
use crate::ops::{OpError, Operation, Ops};
use crate::tunnel::remote::RemoteForwardAcceptor;
use crate::tunnel::{LocalForwardError, LocalForwardHandle};

/// The `tunnel.open` operation (`docs/CLI.md` §6.9).
pub struct TunnelOpenOp;
impl Operation for TunnelOpenOp {
    const COMMAND: &'static str = "tunnel.open";
}

/// Parse `-L` spec strings into [`ForwardSpec`]s, refusing anything that
/// could not be bound, **before** any resource — local or remote —
/// exists.
///
/// This is the frontend's pre-flight: `docs/CLI.md` §6.9's grammar is
/// checked by [`parse_forward_spec`] (sans-IO, shape only), and this then
/// applies the one policy that is not shape — a `-L` listener binds
/// loopback (`PLAN.md` M4 §4.1 #3) — so `qsh host -L 0.0.0.0:8080:…`
/// fails with `INVALID_ARGUMENT` before a session is opened rather than
/// after. Both failure modes carry a `docs/CLI.md` §3.3 code; M4 adds no
/// new one (§4.1 #9).
///
/// Kept in `qsh-core` rather than in the CLI on purpose: the mapping from
/// a spec string to a typed error code is contract behavior, and a
/// frontend that re-derived it would be the second place it could drift
/// (`docs/CLI.md` §11).
pub fn parse_local_forwards(specs: &[String]) -> Result<Vec<ForwardSpec>, OpError> {
    let mut parsed = Vec::with_capacity(specs.len());
    for spec in specs {
        let mut forward = parse_forward_spec(spec)
            .map_err(|err| OpError::new(err.error_code(), format!("-L {spec}: {}", err.message)))?;
        // `parse_forward_spec` cannot know which flag it came from
        // (`ForwardDirection`'s own doc) — this one did.
        forward.direction = ForwardDirection::Local;
        // Refuse a bind this side would reject anyway, here, where nothing
        // has been created yet.
        crate::tunnel::local::check_bind(&forward)
            .map_err(|err| OpError::new(err.code(), format!("-L {spec}: {err}")))?;
        parsed.push(forward);
    }
    Ok(parsed)
}

/// Parse `-R` spec strings into [`ForwardSpec`]s (`PLAN.md` M4 Step 4).
///
/// Shape only, like [`parse_local_forwards`] — but unlike that function,
/// this one applies **no** loopback pre-check: a `-R` bind is validated on
/// the *peer*, after its `forward.remote` ACL gate
/// (`crate::server::Server::authorize_and_bind_remote_forward`), because
/// loopback-only is a constraint the peer enforces on every principal
/// alike, not something this side can decide in advance
/// (`crate::acl::Action::ForwardRemote`'s own doc). A non-loopback `-R`
/// therefore parses `Ok` here and fails later, on the peer's
/// `RemoteForwardOpened`/`Error` reply, with the same
/// [`ErrorCode::InvalidArgument`] it would have gotten from a client-side
/// check — just one control round trip later.
pub fn parse_remote_forwards(specs: &[String]) -> Result<Vec<ForwardSpec>, OpError> {
    let mut parsed = Vec::with_capacity(specs.len());
    for spec in specs {
        let mut forward = parse_forward_spec(spec)
            .map_err(|err| OpError::new(err.error_code(), format!("-R {spec}: {}", err.message)))?;
        forward.direction = ForwardDirection::Remote;
        parsed.push(forward);
    }
    Ok(parsed)
}

/// Build the wire request a `-R` spec becomes (`docs/design/protocol.md`
/// §7): the `[bind:]` half is what the *peer* should bind, the `host:port`
/// half is where *this* side dials each `TCP_ACCEPTED` it gets back — the
/// same [`ForwardSpec`] field mapping [`spec_from_request`] already uses
/// for `"remote"` mode, exposed here so [`Ops::session_attach`]'s `-R`
/// handling (a different `ops` submodule) does not have to re-derive it.
pub(crate) fn remote_forward_open_from_spec(spec: &ForwardSpec) -> wire::RemoteForwardOpen {
    wire::RemoteForwardOpen {
        bind_host: spec.bind.clone().unwrap_or_default(),
        bind_port: u32::from(spec.listen_port),
        forward_host: spec.host.clone(),
        forward_port: u32::from(spec.host_port),
    }
}

/// The `qsh.cli/v1` [`Tunnel`] DTO for a `"remote"`-mode forward
/// (`docs/CLI.md` §6.9). Mirrors [`LocalForwardHandle::tunnel`]'s shape
/// with the two sides swapped: `bind` is where the *peer* bound (this side
/// never learns more than the port the peer's `RemoteForwardOpened`
/// reports, so an unspecified `bind_host` is displayed as the same
/// `127.0.0.1` default `crate::tunnel::remote::resolve_loopback_bind_addr`
/// actually yields), and `forward_to` is this side's own local dial target.
///
/// `tunnel_id` is the peer's `forward_id` verbatim, not a second ID minted
/// here — the same "no parallel ID space" choice `Session.host`/
/// `session_ref` makes (ADR-0007), and the one that lets a future
/// `tunnel.close <id>` (`PLAN.md` M4 Step 5) turn straight into
/// `RemoteForwardClose{forward_id: id}` with no lookup table in between.
pub(crate) fn remote_tunnel_dto(
    spec: &ForwardSpec,
    opened: &wire::RemoteForwardOpened,
    host: &str,
) -> Tunnel {
    let bind_host = spec.bind.as_deref().unwrap_or("127.0.0.1");
    let actual_port = u16::try_from(opened.actual_port).unwrap_or(u16::MAX);
    Tunnel {
        tunnel_id: opened.forward_id.clone(),
        mode: "remote".to_string(),
        bind: wire::format_host_port(bind_host, actual_port),
        forward_to: wire::format_host_port(&spec.host, spec.host_port),
        actual_port: Some(opened.actual_port),
        host: host.to_string(),
    }
}

/// Map a [`LocalForwardError`] onto the shared error vocabulary. The
/// code comes from the error itself (`LocalForwardError::code`), never
/// from a string invented here.
pub(crate) fn map_local_forward_error(err: LocalForwardError) -> OpError {
    OpError::new(err.code(), err.to_string())
}

/// The resource one held tunnel owns on *this* side — a `"local"` mode's
/// listener, or a `"remote"` mode's `TCP_ACCEPTED` dispatcher plus the
/// `forward_id` it dispatches for.
///
/// Both variants are symmetric in the one way that matters for teardown:
/// dropping either aborts the task backing it (`LocalForwardHandle`'s own
/// `Drop`; `RemoteForwardAcceptor`'s own `Drop`), so [`TunnelHold`] does
/// not need to know which variant it holds to tear down correctly — only
/// [`TunnelHold::close`]'s peer-side `RemoteForwardClose` notification
/// needs to match on it.
enum ForwardResource {
    Local(LocalForwardHandle),
    Remote {
        acceptor: RemoteForwardAcceptor,
        forward_id: String,
    },
}

/// A tunnel this process is holding open (`docs/CLI.md` §6.14).
///
/// Owns the peer connection and the forward resource. See this module's
/// doc for why a value operation hands back something that has to be
/// held.
pub struct TunnelHold {
    /// Declared before `conn`: dropping the handle aborts its accept/
    /// dispatch task on `conn`'s runtime, so it must go while that runtime
    /// still exists (same ordering rule as
    /// `SessionAttachStream::forwards`/`remote_acceptor`). Rust drops
    /// struct fields in declaration order, so this ordering *is* the
    /// mechanism, not a comment about one — moving `forward` below `conn`
    /// would abort the task on a runtime that has already gone (this is
    /// the exact bug M4 §4.1 flags as a hazard `TunnelHold` must not
    /// reintroduce).
    forward: ForwardResource,
    conn: Connected,
    connection: qsh_transport::Connection,
    tunnel: Tunnel,
}

impl TunnelHold {
    /// The envelope payload for this tunnel — what the frontend renders
    /// and then stops caring about.
    pub fn tunnel(&self) -> &Tunnel {
        &self.tunnel
    }

    /// Block until this tunnel is over, and say why.
    ///
    /// Two things end it (`docs/CLI.md` §6.14: "그 프로세스가 끝나거나 …
    /// 밑에 깔린 QUIC connection이 죽으면, 그 프로세스가 쥔 모든 터널이
    /// 함께 끝난다"): a `"local"` mode's listener failing fatally, or the
    /// connection carrying the tunnel closing (the only signal a
    /// `"remote"` mode has on this side — the listener lives on the peer,
    /// which has no fatal-error channel back to this side other than the
    /// connection itself, `PLAN.md` M4 Step 5's `tunnel.list`/close being
    /// what eventually gives that a name). Neither is a normal end — a
    /// deliberate end is the process exiting or this value being dropped,
    /// which never reaches here — so this always returns an error.
    ///
    /// Individual forwarded connections failing (a refusal, a dead
    /// destination, a broken pipe) do **not** end the tunnel; they are
    /// logged structurally and accepting continues.
    pub fn hold(mut self) -> OpError {
        let err = {
            let runtime = self.conn.runtime();
            let forward = &mut self.forward;
            let connection = &self.connection;
            runtime.block_on(async move {
                match forward {
                    ForwardResource::Local(handle) => {
                        tokio::select! {
                            err = handle.wait() => OpError::new(
                                ErrorCode::ConnectionFailed,
                                format!("the local forward's listener failed: {err}"),
                            ),
                            err = connection.closed() => OpError::new(
                                ErrorCode::ConnectionFailed,
                                format!("the connection carrying this tunnel closed: {err}"),
                            ),
                        }
                    }
                    ForwardResource::Remote { .. } => {
                        let err = connection.closed().await;
                        OpError::new(
                            ErrorCode::ConnectionFailed,
                            format!("the connection carrying this tunnel closed: {err}"),
                        )
                    }
                }
            })
        };
        self.close();
        err
    }

    /// Tear the tunnel down: for `"remote"` mode, best-effort ask the peer
    /// to close its listener first (its accept loop, not just this side's
    /// dispatcher registration, must stop — dropping `forward` alone would
    /// leave the peer's listener bound with nobody left to dial its
    /// `TCP_ACCEPTED` streams, the same reasoning [`Ops::session_attach`]'s
    /// own `-R` handling gives); then drop the forward resource, then
    /// close the connection.
    pub fn close(mut self) {
        if let ForwardResource::Remote {
            acceptor,
            forward_id,
        } = &self.forward
        {
            acceptor.unregister(forward_id);
            let close_req = wire::RemoteForwardClose {
                forward_id: forward_id.clone(),
            };
            let _ = self.conn.run(move |s| Box::pin(s.rfwd_close(close_req)));
        }
        // Field order does this already; spelled out so the sequence is
        // not an accident of declaration order in a later edit.
        drop(self.forward);
        self.conn.close();
    }
}

impl Ops {
    /// `tunnel.open` (`docs/CLI.md` §6.9, `-L`/`-R`).
    ///
    /// Sends no `SessionOpen`: this form opens a tunnel and no shell
    /// (`docs/CLI.md` §7, §4.1 #10). `"local"` mode sends no control
    /// message at all — a local forward's only wire traffic is one
    /// `TCP_CONNECT` stream per forwarded TCP connection, each authorized
    /// by the peer at open (protocol.md §7). `"remote"` mode sends exactly
    /// one `RemoteForwardOpen` control round trip before anything exists
    /// (this module's own doc, "where the authorization is").
    ///
    /// The returned [`TunnelHold`] is the tunnel: the caller renders
    /// [`TunnelHold::tunnel`] once and then [`TunnelHold::hold`]s it.
    pub fn tunnel_open(&self, req: TunnelOpenReq) -> Result<TunnelHold, OpError> {
        let spec = spec_from_request(&req)?;
        let mut conn = self.connect(&req.host)?;
        let Some(connection) = conn.connection() else {
            conn.close();
            return Err(OpError::new(
                ErrorCode::Unsupported,
                "tunnels over a reverse connection are not implemented yet",
            ));
        };
        match spec.direction {
            ForwardDirection::Local => {
                let forward = match conn
                    .runtime()
                    .block_on(LocalForwardHandle::start(&spec, connection.clone()))
                {
                    Ok(forward) => forward,
                    Err(err) => {
                        conn.close();
                        return Err(map_local_forward_error(err));
                    }
                };
                let tunnel = forward.tunnel(&req.host);
                Ok(TunnelHold {
                    conn,
                    connection,
                    forward: ForwardResource::Local(forward),
                    tunnel,
                })
            }
            ForwardDirection::Remote => {
                let acceptor = conn
                    .runtime()
                    .block_on(RemoteForwardAcceptor::spawn(connection.clone()));
                let open_req = remote_forward_open_from_spec(&spec);
                let opened = match conn.run(move |s| Box::pin(s.rfwd_open(open_req))) {
                    Ok(opened) => opened,
                    Err(err) => {
                        conn.close();
                        return Err(err);
                    }
                };
                acceptor.register(opened.forward_id.clone(), spec.host.clone(), spec.host_port);
                let tunnel = remote_tunnel_dto(&spec, &opened, &req.host);
                Ok(TunnelHold {
                    conn,
                    connection,
                    forward: ForwardResource::Remote {
                        acceptor,
                        forward_id: opened.forward_id,
                    },
                    tunnel,
                })
            }
        }
    }
}

/// Rebuild the [`ForwardSpec`] a [`TunnelOpenReq`] carries in pieces
/// (`docs/CLI.md` §6.9: the request holds the already-parsed halves, never
/// the raw string), for either mode.
///
/// The field mapping is the same [`remote_forward_open_from_spec`] and
/// [`parse_local_forwards`]/[`parse_remote_forwards`] use: `listen_port` is
/// the port bound (locally for `"local"`, on the peer for `"remote"`), and
/// `forward_host`/`forward_port` is where connections end up dialed
/// (on the peer for `"local"`, locally for `"remote"`).
fn spec_from_request(req: &TunnelOpenReq) -> Result<ForwardSpec, OpError> {
    // `mode` is an open string (`docs/CLI.md` §6.9) — an unknown value is
    // `INVALID_ARGUMENT`, the distinction §3.3 draws from a
    // known-but-unimplemented one (M4 has none left here as of Step 4).
    let direction = match req.mode.as_str() {
        "local" => ForwardDirection::Local,
        "remote" => ForwardDirection::Remote,
        other => {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                format!("tunnel mode {other:?} is not one of \"local\", \"remote\""),
            ));
        }
    };
    let listen_port = port(req.listen_port, "listen_port")?;
    let forward_port = port(req.forward_port, "forward_port")?;
    let spec = ForwardSpec {
        direction,
        bind: req.bind.clone(),
        listen_port,
        host: req.forward_host.clone(),
        host_port: forward_port,
    };
    if spec.host.is_empty() {
        return Err(OpError::new(
            ErrorCode::InvalidArgument,
            "tunnel forward_host is empty",
        ));
    }
    // The loopback pre-check applies to `"local"` only — a `"remote"`
    // bind is validated on the peer, never here
    // ([`parse_remote_forwards`]'s own doc on why).
    if direction == ForwardDirection::Local {
        crate::tunnel::local::check_bind(&spec).map_err(map_local_forward_error)?;
    }
    Ok(spec)
}

/// A JSON `uint32` port narrowed to the `1..=65535` the grammar allows
/// (`docs/CLI.md` §6.9). The wire/JSON types are `u32`, so this is where a
/// request that skipped the CLI parser is caught.
fn port(value: u32, field: &str) -> Result<u16, OpError> {
    match u16::try_from(value) {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(OpError::new(
            ErrorCode::InvalidArgument,
            format!("tunnel {field} {value} is outside 1..=65535"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(mode: &str, bind: Option<&str>, listen_port: u32) -> TunnelOpenReq {
        TunnelOpenReq {
            host: "box".to_string(),
            mode: mode.to_string(),
            bind: bind.map(str::to_string),
            listen_port,
            forward_host: "db.internal".to_string(),
            forward_port: 5432,
        }
    }

    /// A `-R` request is refused as unimplemented, not as malformed, and
    /// an unknown mode the other way round (`docs/CLI.md` §3.3).
    #[test]
    fn both_modes_parse_and_an_unknown_mode_is_invalid_argument() {
        assert_eq!(
            spec_from_request(&req("socks", None, 9000))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        let spec = spec_from_request(&req("local", None, 8080)).unwrap();
        assert_eq!(spec.direction, ForwardDirection::Local);
        assert_eq!(spec.listen_port, 8080);
        assert_eq!((spec.host.as_str(), spec.host_port), ("db.internal", 5432));

        let spec = spec_from_request(&req("remote", None, 9000)).unwrap();
        assert_eq!(spec.direction, ForwardDirection::Remote);
        assert_eq!(spec.listen_port, 9000);
        assert_eq!((spec.host.as_str(), spec.host_port), ("db.internal", 5432));
    }

    /// A request that never went through the CLI parser still cannot
    /// smuggle a port outside the grammar, or (in `"local"` mode) a
    /// non-loopback bind past §4.1 #3. `"remote"` mode applies no such
    /// pre-check (`spec_from_request`'s own doc) — a non-loopback `-R`
    /// bind parses here and is caught on the peer instead.
    #[test]
    fn a_hand_built_request_is_still_held_to_the_grammar_and_the_local_loopback_rule() {
        for mode in ["local", "remote"] {
            for bad in [0, 65_536, u32::MAX] {
                assert_eq!(
                    spec_from_request(&req(mode, None, bad)).unwrap_err().code,
                    ErrorCode::InvalidArgument,
                    "{mode} listen_port {bad}"
                );
            }
        }
        assert_eq!(
            spec_from_request(&req("local", Some("0.0.0.0"), 8080))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert!(spec_from_request(&req("local", Some("127.0.0.9"), 8080)).is_ok());
        assert!(spec_from_request(&req("local", Some("::1"), 8080)).is_ok());
        // `"remote"` mode: a non-loopback bind is not rejected here — the
        // peer decides (`crate::server::Server::authorize_and_bind_remote_forward`).
        assert!(spec_from_request(&req("remote", Some("0.0.0.0"), 8080)).is_ok());
    }

    /// The frontend pre-flight: the grammar's code and the loopback
    /// rule's code both come back as `INVALID_ARGUMENT`, with the
    /// offending spec named, and nothing is created.
    #[test]
    fn the_preflight_reports_bad_specs_before_anything_binds() {
        let ok = parse_local_forwards(&["8080:localhost:3000".to_string()]).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].direction, ForwardDirection::Local);
        assert_eq!(ok[0].listen_port, 8080);

        for bad in [
            "not-a-spec",
            "0:localhost:3000",
            "70000:localhost:3000",
            "8080::3000",
            "203.0.113.5:8080:localhost:3000",
        ] {
            let err = parse_local_forwards(&[bad.to_string()]).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad}");
            assert!(err.message.contains(bad), "{bad}: {}", err.message);
        }
    }

    /// An empty `-L` list is not an error — it is the ordinary
    /// `qsh [user@]host` form with no forwards.
    #[test]
    fn no_specs_parse_to_no_forwards() {
        assert!(parse_local_forwards(&[]).unwrap().is_empty());
    }
}
