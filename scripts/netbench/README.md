# netbench

Reproducible network bench for ADR-0052 (decision 18, item 8). It re-measures
the six questions in the ADR's context section on a shaped link, rootless, and
prints one JSON line per profile. It is a tool an agent runs, not a CI gate:
CI runners that block user namespaces cannot run it, and its numbers are for
choosing defaults and recording trends, not for pass/fail.

## Run

```sh
scripts/netbench/run.sh                         # every profile, ~13 minutes
scripts/netbench/run.sh q5                      # every profile named q5-*
scripts/netbench/run.sh q1-datagram-loss3 --out results/mine.jsonl
```

Needs `unshare`, `nsenter`, `ip`, `tc` (iproute2) and a kernel with
`sch_netem` and `sch_tbf`, with unprivileged user namespaces allowed. `run.sh`
checks all of that first and exits with status 2 and a one-line reason if
something is missing. Dave-Windows-WSL (kernel 6.18 WSL2) has all of it.

Unit tests (profile parser, result schema, staleness math) live in the
standalone crate and are not part of the workspace gates:

```sh
cargo test --release --manifest-path scripts/netbench/Cargo.toml
```

The crate also passes the repository policy:
`cargo deny --manifest-path scripts/netbench/Cargo.toml check --config deny.toml`.

## How a run is built

For each profile `run.sh` does the following inside `unshare -rn` (a user and
network namespace in which the caller is mapped to root, so no real root and no
touch of the host network):

1. A second network namespace is created for the client; a veth pair
   (`10.99.0.1` host side, `10.99.0.2` client side) joins the two, both ends at
   the profile's MTU.
2. Each end's egress gets `netem` (half the RTT as delay, the loss rate) with a
   large `limit`, and with a rate, a `tbf` child whose backlog is `queue_ms` of
   drain time. Delay and loss therefore apply before the queue, and the queue
   depth is the one the profile names.
3. `netbench serve` runs in the host namespace, `netbench client` in the client
   namespace. Both bind ephemeral UDP ports (`netbench` refuses a fixed port),
   in namespaces of their own, so a qsh serve on UDP 4433 is never touched.
4. The client prints one JSON line. Everything else goes to stderr.

## The traffic generator

`scripts/netbench` is a standalone crate (empty `[workspace]`, like `fuzz/`)
with its own `Cargo.lock` seeded from the workspace lock. It talks to quinn,
rustls and tokio directly. That keeps the shipped crates, the workspace lock,
`cargo deny check` and `cargo xtask arch` untouched, which an xtask subcommand
would not: it would add quinn and tokio to a workspace member. It mirrors the
production transport settings of `crates/qsh-transport/src/endpoint.rs` (BBR,
send fairness, 2 MiB stream window, 8 MiB connection window), but it does not
link qsh code, so it measures the transport stack and not qsh's own framing.
State sizes and key records are synthetic.

## Profiles

One TOML file per run in `profiles/`; the file name is the profile name.

```toml
name = "q5-shallow-priority"
question = "q5"                  # q1..q6
[link]
rtt_ms = 50                      # round trip; each direction gets half
loss_pct = 0                     # per direction
rate_mbit = 20                   # 0 or absent = unshaped
queue_ms = 20                    # drain time of the bottleneck queue; required with rate_mbit
mtu = 1500
[workload]
kind = "bulk_echo"               # screen | echo | bulk_echo
carrier = "stream"               # screen only: datagram | stream
path = "direct"                  # direct | nested_datagram | nested_stream
cc = "bbr"                       # bbr | cubic
isolation = "priority"           # bulk_echo only: same_conn | priority | separate_conn
duration_s = 20
warmup_s = 2
frame_interval_ms = 20           # screen state cadence
state_bytes = 800                # one screen state
key_interval_ms = 50             # one key every 50 ms
datagram_send_buffer_kib = 64    # optional; outer quinn datagram send buffer (default 1024)
```

| Question | Profiles |
|---|---|
| q1 DATAGRAM vs stream staleness | `q1-{datagram,stream}-loss{3,5}`: RTT 150 ms |
| q2 BBR vs Cubic | `q2-{bbr,cubic}-{stream,datagram}`: RTT 150 ms, 3% loss |
| q3 MTU and max datagram | `q3-mtu1500`, `q3-mtu1280` |
| q4 key echo tail under loss | `q4-echo-loss{0,3,5}`: RTT 150 ms |
| q5 bulk with interactive on a shared bottleneck | `q5-{deep,shallow}-{echo-alone,same-conn,priority,separate-conn}`: 20 Mbit, RTT 50 ms, queue 600 ms (deep) or 20 ms (shallow) |
| q6 nested transport | `q6-direct`, `q6-nested-outer-{datagram,stream}`, `q6-nested-outer-datagram-buf64`: RTT 80 ms, 1% loss |

The ADR's original numbers came from a lost harness, so the q-numbers here are
re-derived choices where the ADR did not say (loss per direction, 20 Mbit with
a 100 ms queue for q1, q2, q4 and q6; RTT 80 ms and 1% loss for q6).

## Result line

`qsh.netbench/v1`, one JSON object per line: `schema`, `profile`, `question`,
the `link` and `workload` echoed back, and `metrics`, in which absent
measurements are left out rather than null:

| Field | Meaning |
|---|---|
| `staleness_ms` | `{n,min,p50,p95,p99,max}`, see below |
| `states_produced`, `states_applied`, `states_unresolved` | screen states made, applied by the receiver, and counted states for which nothing at or after them ever arrived |
| `datagram_loss_pct` | datagram frames that never arrived |
| `echo_ms` | key echo round trip, raw (includes the link RTT) |
| `echo_missing` | counted keys never echoed |
| `bulk_mb_s` | bulk goodput host to client, MB/s (1e6 bytes) over `duration_s` |
| `max_datagram_bytes` | `Connection::max_datagram_size()` at the end (client side, outer connection) |
| `conn_rtt_ms`, `lost_packets` | the client's QUIC stack's own view at the end |

`max_datagram_bytes` is the datagram payload quinn allows; add the QUIC and
datagram framing (38 bytes in the runs so far) to compare with a UDP payload
size such as the ADR's 1452 and 1230.

## Staleness

State `k` is produced by the host at `t0 + k * frame_interval`, `t0` being the
host's monotonic clock reading when production started (carried in every state
so the client needs no other channel). The host sends each state whole, as a
QUIC DATAGRAM or appended to one unidirectional stream. The client applies a
state the moment it receives it, except that a datagram state older than one
already applied is dropped.

The staleness of state `k` is the time from `t0 + k * frame_interval` until
the client first applied state `k` or any newer state, minus the link's
one-way propagation delay (`rtt_ms / 2`). A state that is lost, or arrives
after a newer one, is covered by the newer state, so datagram staleness stays
low under loss while a stream's head-of-line blocking raises it for every state
behind a lost packet. Serialisation and queue time at the bottleneck stay in
the number; propagation does not. Both processes read `CLOCK_MONOTONIC` through
`clock_gettime`, which is shared across network namespaces, so no clock
offset exists.

Samples are all states produced after `warmup_s`. A counted state with nothing
applied at or after it by the end of the grace period (3 s) is not sampled but
counted in `states_unresolved`; a high value there means the percentiles are
flattering.

Limits to keep in mind when comparing with a real session: the stream carrier
does not coalesce states while blocked (a real sender could), and the screen
states are full-state replacements of fixed size.

## Echo and bulk

The client sends a 16-byte key record every `key_interval_ms` on one bidi
stream; the host echoes it. `echo_ms` is send-to-echo time on the client, raw.
For `bulk_echo` the host also writes a saturating unidirectional stream to the
client (the direction in which echoes share the queue). `isolation` picks
whether echo and bulk share one connection at equal priority, share one with
the echo stream at higher quinn priority, or use two connections.

## Nested

`path = "nested_datagram"` or `"nested_stream"` opens an outer QUIC connection
over the shaped link, then an inner QUIC endpoint on a virtual UDP socket
whose packets travel on the outer connection, as DATAGRAMs or length-prefixed
on one bidi stream. The inner connection runs the workload. Inner packets are
at most 1200 bytes with no inner MTU discovery. The outer keep-alive is 100 ms
instead of 15 s so path MTU discovery finishes before the inner handshake.
