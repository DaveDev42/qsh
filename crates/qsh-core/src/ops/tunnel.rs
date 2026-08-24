//! `tunnel.*` operations (`docs/CLI.md` §6.9, §6.14; `PLAN.md` M4 Step 3).
//!
//! M4 Step 3 lands exactly one of them, `tunnel.open` in `"local"` mode —
//! the standalone twin of the interactive `qsh [user@]host -L spec` form
//! (whose entry point is [`crate::ops::SessionAttachStream::open_local_forwards`],
//! because that form's forwards ride the attach's own connection).
//! `tunnel.list`/`tunnel.close` and `"remote"` mode belong to later steps
//! and are absent rather than stubbed.
//!
//! **Holder model** (`PLAN.md` M4 §4.1 #1, `docs/CLI.md` §6.14).
//! `tunnel.open` is a *value* operation that returns one envelope
//! immediately — and then the process that called it has to stay alive,
//! because it *is* the tunnel. [`TunnelHold`] is that obligation made
//! into a type: it owns the connection and the listener, hands the
//! frontend the [`Tunnel`] DTO to render, and then blocks in
//! [`TunnelHold::hold`] until the forward or the connection dies.
//! Dropping it instead is a complete teardown. There is no resident client
//! daemon and no tunnel registry anywhere in this design.
//!
//! **Where the authorization is.** Nowhere here. A local forward's ACL
//! check (`forward.local`) happens on the *peer*, inline at every
//! `TCP_CONNECT` stream open, before the peer dials anything
//! (`docs/design/protocol.md` §7's sole ticket exception;
//! `crate::server::Server::authorize_and_dial_tunnel`). This side binds a
//! loopback listener, which grants nothing and creates nothing remote.

use qsh_proto::wire::{ForwardDirection, ForwardSpec, parse_forward_spec};
use qsh_proto::{ErrorCode, Tunnel, TunnelOpenReq};

use crate::ops::session::Connected;
use crate::ops::{OpError, Operation, Ops};
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

/// Map a [`LocalForwardError`] onto the shared error vocabulary. The
/// code comes from the error itself (`LocalForwardError::code`), never
/// from a string invented here.
pub(crate) fn map_local_forward_error(err: LocalForwardError) -> OpError {
    OpError::new(err.code(), err.to_string())
}

/// A tunnel this process is holding open (`docs/CLI.md` §6.14).
///
/// Owns the peer connection and the local listener. See this module's doc
/// for why a value operation hands back something that has to be held.
pub struct TunnelHold {
    /// Declared before `conn`: dropping the handle aborts its accept loop
    /// on `conn`'s runtime, so it must go while that runtime still exists
    /// (same ordering rule as `SessionAttachStream::forwards`). Rust drops
    /// struct fields in declaration order, so this ordering *is* the
    /// mechanism, not a comment about one — moving `forward` below `conn`
    /// would abort the accept loop on a runtime that has already gone.
    forward: LocalForwardHandle,
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
    /// 함께 끝난다"): the local listener failing fatally, or the
    /// connection carrying it closing. Neither is a normal end — a
    /// deliberate end is the process exiting or this value being dropped,
    /// which never reaches here — so this always returns an error.
    ///
    /// Individual forwarded connections failing (a refusal, a dead
    /// destination, a broken pipe) do **not** end the tunnel; they are
    /// logged structurally and the listener keeps accepting.
    pub fn hold(mut self) -> OpError {
        let err = {
            let runtime = self.conn.runtime();
            let forward = &mut self.forward;
            let connection = &self.connection;
            runtime.block_on(async move {
                tokio::select! {
                    err = forward.wait() => OpError::new(
                        ErrorCode::ConnectionFailed,
                        format!("the local forward's listener failed: {err}"),
                    ),
                    err = connection.closed() => OpError::new(
                        ErrorCode::ConnectionFailed,
                        format!("the connection carrying this tunnel closed: {err}"),
                    ),
                }
            })
        };
        self.close();
        err
    }

    /// Tear the tunnel down: close the listener, then the connection.
    pub fn close(self) {
        // Field order does this already; spelled out so the sequence is
        // not an accident of declaration order in a later edit.
        drop(self.forward);
        self.conn.close();
    }
}

impl Ops {
    /// `tunnel.open` in `"local"` mode — bind a loopback listener that
    /// forwards each connection to `forward_host:forward_port` **on the
    /// peer** (`docs/CLI.md` §6.9, `-L`).
    ///
    /// Sends no `SessionOpen`: this form opens a tunnel and no shell
    /// (`docs/CLI.md` §7, §4.1 #10). In fact it sends no control message
    /// at all — a local forward's only wire traffic is one `TCP_CONNECT`
    /// stream per forwarded TCP connection, each authorized by the peer at
    /// open (protocol.md §7).
    ///
    /// The returned [`TunnelHold`] is the tunnel: the caller renders
    /// [`TunnelHold::tunnel`] once and then [`TunnelHold::hold`]s it.
    pub fn tunnel_open(&self, req: TunnelOpenReq) -> Result<TunnelHold, OpError> {
        let spec = spec_from_request(&req)?;
        let conn = self.connect(&req.host)?;
        let Some(connection) = conn.connection() else {
            conn.close();
            return Err(OpError::new(
                ErrorCode::Unsupported,
                "local forwards over a reverse connection are not implemented yet",
            ));
        };
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
            forward,
            tunnel,
        })
    }
}

/// Rebuild the [`ForwardSpec`] a [`TunnelOpenReq`] carries in pieces
/// (`docs/CLI.md` §6.9: the request holds the already-parsed halves, never
/// the raw string), and reject what M4 Step 3 does not implement.
fn spec_from_request(req: &TunnelOpenReq) -> Result<ForwardSpec, OpError> {
    // `mode` is an open string (`docs/CLI.md` §6.9) — an unknown value is
    // `INVALID_ARGUMENT`, while the one known-but-unimplemented value is
    // `UNSUPPORTED`, which is the distinction §3.3 draws.
    match req.mode.as_str() {
        "local" => {}
        "remote" => {
            return Err(OpError::new(
                ErrorCode::Unsupported,
                "remote forwards (-R) are not implemented yet",
            ));
        }
        other => {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                format!("tunnel mode {other:?} is not one of \"local\", \"remote\""),
            ));
        }
    }
    let listen_port = port(req.listen_port, "listen_port")?;
    let forward_port = port(req.forward_port, "forward_port")?;
    let spec = ForwardSpec {
        direction: ForwardDirection::Local,
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
    crate::tunnel::local::check_bind(&spec).map_err(map_local_forward_error)?;
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
    fn only_local_mode_is_implemented() {
        assert_eq!(
            spec_from_request(&req("remote", None, 9000))
                .unwrap_err()
                .code,
            ErrorCode::Unsupported
        );
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
    }

    /// A request that never went through the CLI parser still cannot
    /// smuggle a port outside the grammar, or a non-loopback bind past
    /// §4.1 #3.
    #[test]
    fn a_hand_built_request_is_still_held_to_the_grammar_and_the_loopback_rule() {
        for bad in [0, 65_536, u32::MAX] {
            assert_eq!(
                spec_from_request(&req("local", None, bad))
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument,
                "listen_port {bad}"
            );
        }
        assert_eq!(
            spec_from_request(&req("local", Some("0.0.0.0"), 8080))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert!(spec_from_request(&req("local", Some("127.0.0.9"), 8080)).is_ok());
        assert!(spec_from_request(&req("local", Some("::1"), 8080)).is_ok());
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
