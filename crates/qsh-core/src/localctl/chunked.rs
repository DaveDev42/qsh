//! The chunk framing a localctl conduit uses for its raw byte phase on
//! platforms whose local stream cannot half-close (Windows named pipes,
//! ADR-0035 decision 14). It is platform-neutral code so that every OS
//! compiles and tests it; only the Windows transport applies it
//! (`super::transport::raw_reader` and friends).
//!
//! Once a conduit stops speaking framed `qsh.local.v1` messages and becomes a
//! raw byte relay (`SESSION_DATA`, `TCP_CONNECT`, `TCP_ACCEPTED`,
//! `EXEC_DATA`, `FILE_DATA`), each direction carries a sequence of chunks:
//!
//! ```text
//! chunk := length (4 bytes, big-endian u32) || length bytes
//! ```
//!
//! - A length of `0` is the end chunk: the writer has ended its direction
//!   (the half-close a byte-mode pipe cannot express by itself). The reader
//!   reports end-of-stream, and the other direction keeps flowing.
//! - A length above [`MAX_CHUNK`] is a protocol error and tears the conduit
//!   down as an abort, exactly like an I/O error.
//! - Any byte after the end chunk is a protocol error.
//! - The stream ending between chunks without an end chunk reads as a plain
//!   end-of-stream (the peer dropped the conduit), the same signal a socket
//!   gives; ending inside a chunk header or body is
//!   [`io::ErrorKind::UnexpectedEof`].
//!
//! The framed phase before the hand-off is not chunked.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The largest payload one chunk may carry.
pub const MAX_CHUNK: usize = 65536;

/// The end chunk: a zero length and nothing else.
pub const END_CHUNK: [u8; 4] = [0; 4];

/// How much a reader pulls from its source per read.
const FILL_LEN: usize = 16 * 1024;

/// Append `data` to `out` as chunks of at most [`MAX_CHUNK`] bytes each.
/// Empty `data` appends nothing: an empty chunk would be the end chunk.
pub fn encode_into(data: &[u8], out: &mut Vec<u8>) {
    for part in data.chunks(MAX_CHUNK) {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
}

/// [`encode_into`] into a fresh vector.
pub fn encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    encode_into(data, &mut out);
    out
}

fn protocol_error(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("localctl chunk framing: {what}"),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Between chunks, collecting the 4 length bytes.
    Header,
    /// Inside a chunk body.
    Body,
    /// The end chunk arrived.
    Ended,
    /// A protocol error was reported; every later read reports it again.
    Failed,
}

/// Decodes the chunk stream of one direction. `prefix` is bytes the caller
/// already read off the stream (the framed phase's read-ahead); they are
/// consumed before anything else is read.
#[derive(Debug)]
pub struct ChunkedReader<R> {
    inner: R,
    /// Undecoded input: `inbuf[start..]`.
    inbuf: Vec<u8>,
    start: usize,
    phase: Phase,
    header: [u8; 4],
    header_len: usize,
    remaining: usize,
}

impl<R> ChunkedReader<R> {
    /// Decode `inner`, starting with `prefix` as already-read input.
    pub fn new(inner: R, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            inbuf: prefix,
            start: 0,
            phase: Phase::Header,
            header: [0; 4],
            header_len: 0,
            remaining: 0,
        }
    }

    /// The stream underneath, for a caller that has to watch it directly.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    fn available(&self) -> usize {
        self.inbuf.len() - self.start
    }
}

impl<R: AsyncRead + Unpin> ChunkedReader<R> {
    /// Pull more input from the stream. `Ok(0)` is its end.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if self.start == self.inbuf.len() {
            self.inbuf.clear();
            self.start = 0;
        }
        let mut chunk = [0u8; FILL_LEN];
        let mut buf = ReadBuf::new(&mut chunk);
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
        let n = buf.filled().len();
        self.inbuf.extend_from_slice(buf.filled());
        Poll::Ready(Ok(n))
    }

    fn fail(&mut self, what: &str) -> Poll<io::Result<()>> {
        self.phase = Phase::Failed;
        Poll::Ready(Err(protocol_error(what)))
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ChunkedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match this.phase {
                Phase::Failed => return this.fail("an earlier chunk was invalid"),
                Phase::Ended => {
                    if this.available() > 0 {
                        return this.fail("bytes after the end chunk");
                    }
                    // Report the end promptly, but notice bytes that already
                    // arrived behind it. Pending is not a reason to wait: the
                    // writer is allowed to keep its side open and silent.
                    return match this.poll_fill(cx) {
                        Poll::Ready(Ok(n)) if n > 0 => this.fail("bytes after the end chunk"),
                        _ => Poll::Ready(Ok(())),
                    };
                }
                Phase::Header => {
                    while this.header_len < 4 && this.available() > 0 {
                        this.header[this.header_len] = this.inbuf[this.start];
                        this.header_len += 1;
                        this.start += 1;
                    }
                    if this.header_len == 4 {
                        this.header_len = 0;
                        let len = u32::from_be_bytes(this.header) as usize;
                        if len == 0 {
                            this.phase = Phase::Ended;
                        } else if len > MAX_CHUNK {
                            return this.fail("chunk length above the maximum");
                        } else {
                            this.remaining = len;
                            this.phase = Phase::Body;
                        }
                        continue;
                    }
                    match ready!(this.poll_fill(cx)) {
                        Err(err) => return Poll::Ready(Err(err)),
                        Ok(0) if this.header_len == 0 => return Poll::Ready(Ok(())),
                        Ok(0) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "localctl chunk framing: stream ended inside a chunk header",
                            )));
                        }
                        Ok(_) => {}
                    }
                }
                Phase::Body => {
                    let avail = this.available();
                    if avail > 0 {
                        let n = avail.min(this.remaining).min(out.remaining());
                        out.put_slice(&this.inbuf[this.start..this.start + n]);
                        this.start += n;
                        this.remaining -= n;
                        if this.remaining == 0 {
                            this.phase = Phase::Header;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    match ready!(this.poll_fill(cx)) {
                        Err(err) => return Poll::Ready(Err(err)),
                        Ok(0) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "localctl chunk framing: stream ended inside a chunk",
                            )));
                        }
                        Ok(_) => {}
                    }
                }
            }
        }
    }
}

/// Encodes one direction as chunks. A write returns only once the chunk that
/// carries it has been handed to the stream, so nothing sits unflushed after
/// the caller moves on. `poll_shutdown` writes the end chunk and flushes; it
/// does not shut the underlying stream, which cannot half-close.
#[derive(Debug)]
pub struct ChunkedWriter<W> {
    inner: W,
    /// The encoded bytes being handed to `inner`: `pending[pos..]`.
    pending: Vec<u8>,
    pos: usize,
    /// How many caller bytes `pending` carries, owed as the result of the
    /// in-flight `poll_write`.
    accepted: usize,
    end_queued: bool,
}

impl<W> ChunkedWriter<W> {
    /// Encode onto `inner`.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            pos: 0,
            accepted: 0,
            end_queued: false,
        }
    }

    /// The stream underneath.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }
}

impl<W: AsyncWrite + Unpin> ChunkedWriter<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pos < self.pending.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pos += n;
        }
        self.pending.clear();
        self.pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ChunkedWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.end_queued {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "localctl chunk framing: write after the end chunk",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.accepted == 0 {
            ready!(this.poll_drain(cx))?;
            let n = buf.len().min(MAX_CHUNK);
            encode_into(&buf[..n], &mut this.pending);
            this.accepted = n;
        }
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(std::mem::take(&mut this.accepted)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if !this.end_queued {
            this.pending.extend_from_slice(&END_CHUNK);
            this.end_queued = true;
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    async fn read_all<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        r.read_to_end(&mut out).await?;
        Ok(out)
    }

    #[tokio::test]
    async fn round_trip_with_half_close_and_the_other_direction_still_flowing() {
        let (a, b) = tokio::io::duplex(1024);
        let (a_read, a_write) = tokio::io::split(a);
        let (b_read, b_write) = tokio::io::split(b);
        let (mut a_read, mut a_write) = (
            ChunkedReader::new(a_read, vec![]),
            ChunkedWriter::new(a_write),
        );
        let (mut b_read, mut b_write) = (
            ChunkedReader::new(b_read, vec![]),
            ChunkedWriter::new(b_write),
        );

        a_write.write_all(b"request").await.unwrap();
        a_write.shutdown().await.unwrap();
        assert_eq!(read_all(&mut b_read).await.unwrap(), b"request");

        // `a` ended its direction; `b` can still answer.
        b_write.write_all(b"reply").await.unwrap();
        b_write.shutdown().await.unwrap();
        assert_eq!(read_all(&mut a_read).await.unwrap(), b"reply");
    }

    #[tokio::test]
    async fn large_writes_split_at_the_maximum_and_come_back_whole() {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let mut w = ChunkedWriter::new(a);
        let mut r = ChunkedReader::new(b, vec![]);
        let data: Vec<u8> = (0..(MAX_CHUNK * 2 + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        w.write_all(&data).await.unwrap();
        w.shutdown().await.unwrap();
        assert_eq!(read_all(&mut r).await.unwrap(), data);
    }

    #[test]
    fn encode_splits_and_skips_empty() {
        assert!(encode(&[]).is_empty());
        let wire = encode(&vec![7u8; MAX_CHUNK + 1]);
        assert_eq!(&wire[..4], &(MAX_CHUNK as u32).to_be_bytes());
        let second = 4 + MAX_CHUNK;
        assert_eq!(&wire[second..second + 4], &1u32.to_be_bytes());
        assert_eq!(wire.len(), second + 5);
    }

    #[tokio::test]
    async fn oversize_length_is_a_protocol_error() {
        let wire = ((MAX_CHUNK as u32) + 1).to_be_bytes().to_vec();
        let mut r = ChunkedReader::new(&wire[..], vec![]);
        let err = read_all(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // And it stays an error.
        let mut one = [0u8; 1];
        assert!(r.read(&mut one).await.is_err());
    }

    #[tokio::test]
    async fn bytes_after_the_end_chunk_are_a_protocol_error() {
        let mut wire = encode(b"data");
        wire.extend_from_slice(&END_CHUNK);
        wire.push(b'x');
        let mut r = ChunkedReader::new(&wire[..], vec![]);
        let err = read_all(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn bytes_arriving_after_the_end_was_reported_fail_the_next_read() {
        let (mut a, b) = tokio::io::duplex(64);
        let mut r = ChunkedReader::new(b, vec![]);
        a.write_all(&END_CHUNK).await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(r.read(&mut buf).await.unwrap(), 0);
        // Nothing more yet: the end is still reported without waiting.
        assert_eq!(r.read(&mut buf).await.unwrap(), 0);
        a.write_all(b"late").await.unwrap();
        let err = r.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_partial_header_at_eof_is_unexpected_eof() {
        let mut r = ChunkedReader::new(&[0u8, 0, 1][..], vec![]);
        let err = read_all(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_truncated_body_at_eof_is_unexpected_eof() {
        let mut wire = 5u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"abc");
        let mut r = ChunkedReader::new(&wire[..], vec![]);
        let err = read_all(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn eof_between_chunks_without_an_end_chunk_is_a_plain_end() {
        let wire = encode(b"abc");
        let mut r = ChunkedReader::new(&wire[..], vec![]);
        assert_eq!(read_all(&mut r).await.unwrap(), b"abc");
    }

    #[tokio::test]
    async fn chunks_split_across_reads_and_a_prefix_decode() {
        let mut wire = encode(b"hello ");
        wire.extend_from_slice(&encode(b"world"));
        wire.extend_from_slice(&END_CHUNK);
        // The prefix cuts the first header in half; the rest trickles in one
        // byte at a time.
        let (prefix, rest) = wire.split_at(2);
        let (mut a, b) = tokio::io::duplex(1);
        let rest = rest.to_vec();
        let feeder = tokio::spawn(async move {
            for byte in rest {
                a.write_all(&[byte]).await.unwrap();
            }
        });
        let mut r = ChunkedReader::new(b, prefix.to_vec());
        assert_eq!(read_all(&mut r).await.unwrap(), b"hello world");
        feeder.await.unwrap();
    }

    #[tokio::test]
    async fn writes_after_shutdown_fail() {
        let (a, _b) = tokio::io::duplex(64);
        let mut w = ChunkedWriter::new(a);
        w.shutdown().await.unwrap();
        assert!(w.write_all(b"x").await.is_err());
    }
}
