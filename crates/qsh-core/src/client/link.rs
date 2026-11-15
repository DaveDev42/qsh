//! The carriers a `Session`'s streams run over: the control stream, the
//! per-attach data stream, and the borrowed handle that opens a fresh data
//! stream. Each wraps the QUIC stream dialed straight to the peer
//! (`docs/design/protocol.md` §11-3 described a second, daemon-relayed
//! carrier for the reverse route; ADR-0068 retired it, and these types keep
//! their shape so call sites do not name the transport stream types).
//!
//! Only the surface [`crate::client::Session`] actually uses is exposed:
//! send one message, receive the next one, and a best-effort half-close.
//! Nothing here decides *when* to reconnect or *what* a
//! session_open/get/list/read/write/resize/close request looks like — that
//! stays entirely in `crate::ops::session`.

use prost::Message;
use qsh_proto::wire::{ControlMessage, StreamHeader};
use qsh_transport::{Connection, FramedRecv, FramedSend, FramedStream};

use super::ClientError;

/// A `Session`'s control channel: both halves of the QUIC control stream
/// dialed straight to the peer.
pub(crate) struct ControlLink(FramedStream);

impl ControlLink {
    pub(crate) fn new(stream: FramedStream) -> Self {
        Self(stream)
    }

    /// Encode + send one `ControlMessage`.
    pub(crate) async fn send(&mut self, msg: &ControlMessage) -> Result<(), ClientError> {
        Ok(self.0.send.send(msg).await?)
    }

    /// Read the next `ControlMessage`. `Ok(None)` on a clean end of the
    /// link — a QUIC stream FIN at a frame boundary.
    pub(crate) async fn recv(&mut self) -> Result<Option<ControlMessage>, ClientError> {
        Ok(self.0.recv.recv::<ControlMessage>().await?)
    }

    /// Best-effort half-close of the send side (`Session::close`'s
    /// "finish, then close the connection" sequence). Errors are ignored
    /// here exactly as [`qsh_transport::control::FramedSend::finish`]'s own
    /// doc allows ("a second call errors with `ClosedStream`, which
    /// callers may ignore").
    pub(crate) fn finish(&mut self) {
        let _ = self.0.send.finish();
    }
}

/// The send half of a `Session`'s attach data channel
/// (`docs/design/protocol.md` §9): a `SESSION_DATA`/`EXEC_DATA`/... QUIC
/// stream dialed straight to the peer.
pub(crate) struct DataSend(FramedSend);

impl DataSend {
    /// Encode + send one frame.
    pub(crate) async fn send<M: Message>(&mut self, msg: &M) -> Result<(), ClientError> {
        Ok(self.0.send(msg).await?)
    }

    /// Finish our send half (`crate::client::AttachWriter::finish`'s own
    /// doc: "only queues the FIN"). Swallows its own error: a second
    /// finish is not this caller's problem to report.
    pub(crate) fn finish(&mut self) {
        let _ = self.0.finish();
    }

    /// Abandon this send half: reset the QUIC stream with `code`. The peer
    /// sees a truncated stream, never a clean end.
    pub(crate) fn abort(&mut self, code: u32) {
        self.0.reset(code);
    }

    /// The stream's quinn send priority, for tests of the open seam.
    #[cfg(test)]
    pub(crate) fn priority(&self) -> Result<i32, qsh_transport::ClosedStream> {
        self.0.priority()
    }

    /// End this stream's framed phase and surrender the raw QUIC send
    /// stream, for the one caller that needs an unframed byte pipe: a
    /// tunnel stream past its handshake (`docs/design/protocol.md` §5, §7,
    /// [`crate::tunnel::splice`]).
    pub(crate) fn into_raw(self) -> qsh_transport::SendStream {
        self.0.into_raw()
    }
}

/// See [`DataSend`]'s own doc — this is its receive-half sibling.
pub(crate) struct DataRecv(FramedRecv);

impl DataRecv {
    /// Read the next frame. `Ok(None)` on a clean end of the stream.
    pub(crate) async fn recv<M: Message + Default>(&mut self) -> Result<Option<M>, ClientError> {
        Ok(self.0.recv::<M>().await?)
    }

    /// Stop receiving further data on this stream — e.g. a client that
    /// refuses to keep buffering output past a cap
    /// ([`crate::client::EXEC_OUTPUT_MAX`]). Resets the QUIC receive stream
    /// with `code`, a real `STOP_SENDING` the peer notices.
    pub(crate) fn abort(&mut self, code: u32) {
        self.0.stop(code);
    }

    /// The receive-half sibling of [`DataSend::into_raw`], returning the
    /// raw QUIC stream **and** the handshake residue behind it — bytes the
    /// peer pipelined after its last framed message, which
    /// [`qsh_transport::FramedRecv::into_raw`]'s own doc explains must be
    /// delivered ahead of everything read from the stream afterwards.
    pub(crate) fn into_raw(self) -> (qsh_transport::RecvStream, Vec<u8>) {
        self.0.into_raw()
    }
}

/// A live connection this process can open a **fresh** data stream on: it
/// borrows what opening *another* stream needs, so more than one call site
/// can open data streams the same way ([`crate::tunnel::open_stream`] is
/// the first such second call site; [`crate::client::Session::open_data_link`]
/// opens its own inline).
pub(crate) struct DataLink<'a>(&'a Connection);

impl<'a> DataLink<'a> {
    pub(crate) fn new(conn: &'a Connection) -> Self {
        Self(conn)
    }

    /// Open a fresh data stream and send `header` as its first frame,
    /// applying quinn's per-stream `priority` (`docs/design/protocol.md`
    /// §12).
    pub(crate) async fn open_stream(
        &self,
        header: &StreamHeader,
        priority: i32,
    ) -> Result<(DataSend, DataRecv), ClientError> {
        let (send, recv) = self.0.open_bi().await?;
        let mut data = FramedStream::data(send, recv);
        data.send.set_priority(priority);
        data.send.send(header).await?;
        let (send, recv) = data.split();
        Ok((DataSend(send), DataRecv(recv)))
    }
}

impl From<FramedSend> for DataSend {
    fn from(send: FramedSend) -> Self {
        Self(send)
    }
}

impl From<FramedRecv> for DataRecv {
    fn from(recv: FramedRecv) -> Self {
        Self(recv)
    }
}
