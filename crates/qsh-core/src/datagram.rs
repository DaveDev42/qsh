//! The QUIC DATAGRAM carrier's plumbing (ADR-0052 decisions 6 to 9,
//! `docs/design/protocol.md` §18.9).
//!
//! One [`DatagramHub`] per connection owns the connection's single datagram
//! reader and hands each [`DatagramFrame`] to the attach that registered its
//! channel id. A datagram for a channel nobody registered is dropped and
//! counted, so nothing is created by a datagram: the channel id is issued by
//! the host after the ACL admitted the attach (decision 7), and a datagram
//! only ever reaches an attach that already exists.
//!
//! Both ends use it: the host registers the attach's `screen_channel`
//! when it starts the data stream, the client when it opens it. The hub does
//! no policy. Which carrier an update takes is `adapt`'s decision.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use qsh_proto::datagram::{CHANNEL_ID_LEN, ChannelId, DatagramFrame};
use qsh_transport::{Connection, DatagramError};
use tokio::sync::mpsc;

/// Frames queued per channel before further ones are dropped. A datagram
/// reader that falls behind loses the oldest information anyway; the stream
/// twin carries what matters.
pub const CHANNEL_QUEUE: usize = 256;

/// Bytes of a prost-encoded `ScreenUpdate` part besides its `data`: the
/// varints for `new_num` (up to 10), `part` and `parts` (up to 5 each, 1 for
/// the 64 parts a datagram update may have), and the tag and length of
/// `data`. Rounded up.
const PART_OVERHEAD: usize = 24;

/// Smallest payload per part worth sending as a datagram.
const MIN_PART_PAYLOAD: usize = 64;

/// The `data` budget of one `ScreenUpdate` datagram part when the transport
/// allows `max_datagram_size` bytes: the whole datagram (our header
/// included) must fit in `max_datagram_size`, which already excludes QUIC's
/// own framing (the netbench found 38 bytes of QUIC frame overhead on top
/// of what the transport reports, so the budget is that value and no more).
/// `None` when the path is too small to carry useful parts.
pub fn part_budget(max_datagram_size: usize) -> Option<usize> {
    let budget = max_datagram_size.checked_sub(DatagramFrame::HEADER_LEN + PART_OVERHEAD)?;
    (budget >= MIN_PART_PAYLOAD).then_some(budget)
}

/// Why a datagram did not go out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFailure {
    /// The transport cannot carry it now (no peer support, too large). The
    /// caller uses the stream twin.
    Unavailable,
    /// The connection is gone.
    Closed,
}

/// Counters, for tests and `qsh doctor`.
#[derive(Debug, Default)]
pub struct HubCounters {
    /// Datagrams that did not decode.
    pub malformed: AtomicU64,
    /// Datagrams for a channel nobody registered.
    pub unknown_channel: AtomicU64,
    /// Datagrams dropped because the channel's queue was full.
    pub overflow: AtomicU64,
    /// Datagrams handed to a channel.
    pub delivered: AtomicU64,
}

/// The per-connection datagram reader and channel table.
pub struct DatagramHub {
    conn: Connection,
    channels: Mutex<HashMap<[u8; CHANNEL_ID_LEN], mpsc::Sender<DatagramFrame>>>,
    counters: HubCounters,
}

type Registry = Mutex<HashMap<usize, Arc<DatagramHub>>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

impl DatagramHub {
    /// The hub of `conn`, started on first use. Must run inside a tokio
    /// runtime. The reader ends, and the hub leaves the table, when the
    /// connection closes.
    pub fn of(conn: &Connection) -> Arc<Self> {
        let id = conn.stable_id();
        let mut table = registry().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hub) = table.get(&id) {
            return Arc::clone(hub);
        }
        let hub = Arc::new(Self {
            conn: conn.clone(),
            channels: Mutex::new(HashMap::new()),
            counters: HubCounters::default(),
        });
        table.insert(id, Arc::clone(&hub));
        let reader = Arc::clone(&hub);
        tokio::spawn(async move {
            reader.read_loop().await;
            registry()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
        });
        hub
    }

    /// Receive frames for `channel` until the returned handle drops.
    pub fn register(self: &Arc<Self>, channel: ChannelId) -> DatagramRx {
        let (tx, rx) = mpsc::channel(CHANNEL_QUEUE);
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(channel.0, tx);
        DatagramRx {
            hub: Arc::clone(self),
            channel,
            rx,
        }
    }

    /// The hub's counters.
    pub fn counters(&self) -> &HubCounters {
        &self.counters
    }

    /// The connection's current `max_datagram_size()`.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// Send one frame. Never waits.
    pub fn send(&self, frame: &DatagramFrame) -> Result<(), SendFailure> {
        match self.conn.send_datagram(Bytes::from(frame.encode())) {
            Ok(()) => Ok(()),
            Err(
                DatagramError::UnsupportedByPeer
                | DatagramError::Disabled
                | DatagramError::TooLarge,
            ) => Err(SendFailure::Unavailable),
            Err(DatagramError::ConnectionLost(_)) => Err(SendFailure::Closed),
        }
    }

    async fn read_loop(&self) {
        while let Ok(bytes) = self.conn.read_datagram().await {
            let Ok(frame) = DatagramFrame::decode(&bytes) else {
                self.counters.malformed.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let tx = self
                .channels
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&frame.channel.0)
                .cloned();
            let Some(tx) = tx else {
                self.counters
                    .unknown_channel
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            };
            match tx.try_send(frame) {
                Ok(()) => {
                    self.counters.delivered.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    self.counters.overflow.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

/// The receive side of one registered channel. Dropping it unregisters.
pub struct DatagramRx {
    hub: Arc<DatagramHub>,
    channel: ChannelId,
    rx: mpsc::Receiver<DatagramFrame>,
}

impl DatagramRx {
    /// The next frame for this channel; `None` once the hub is gone.
    pub async fn recv(&mut self) -> Option<DatagramFrame> {
        self.rx.recv().await
    }

    /// The hub, for sending.
    pub fn hub(&self) -> &Arc<DatagramHub> {
        &self.hub
    }

    /// This channel's id.
    pub fn channel(&self) -> ChannelId {
        self.channel
    }
}

impl Drop for DatagramRx {
    fn drop(&mut self) {
        self.hub
            .channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.channel.0);
    }
}

/// The datagram copy of one `Input` chunk (ADR-0052 decision 8): the same
/// `{input_seq, data}` the stream frame carries, `input_seq` being the
/// cumulative offset after the chunk.
pub fn input_copy(channel: ChannelId, input_seq: u64, data: &[u8]) -> DatagramFrame {
    use prost::Message as _;
    DatagramFrame {
        channel,
        kind: qsh_proto::datagram::DatagramKind::Input,
        payload: qsh_proto::wire::Input {
            input_seq,
            data: data.to_vec(),
        }
        .encode_to_vec(),
    }
}

/// A channel id from the 16 bytes of `screen_channel`; `None` if the length
/// is wrong.
pub fn channel_from(bytes: &[u8]) -> Option<ChannelId> {
    <[u8; CHANNEL_ID_LEN]>::try_from(bytes).ok().map(ChannelId)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_leaves_room_for_both_headers() {
        // 1452 (a 1500 link) minus the frame header and part overhead.
        let b = part_budget(1452).unwrap();
        assert_eq!(b + DatagramFrame::HEADER_LEN + PART_OVERHEAD, 1452);
        // A prost part with a full budget of data really fits.
        let part = qsh_proto::wire::ScreenUpdate {
            new_num: u64::MAX,
            part: 63,
            parts: 64,
            data: vec![0; b],
        };
        let size = prost::Message::encoded_len(&part) + DatagramFrame::HEADER_LEN;
        assert!(size <= 1452, "{size}");
        assert_eq!(part_budget(1230).map(|b| b > 1000), Some(true));
        assert_eq!(part_budget(60), None);
        assert_eq!(part_budget(100), None, "too little room is not worth it");
    }

    #[test]
    fn channel_ids_are_sixteen_bytes() {
        assert!(channel_from(&[1; 16]).is_some());
        assert!(channel_from(&[1; 15]).is_none());
        assert!(channel_from(&[]).is_none());
    }
}
