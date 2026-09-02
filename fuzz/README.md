# qsh-proto fuzz targets

`crates/qsh-proto` is the project's designated fuzz surface (`CLAUDE.md`,
`crates/qsh-proto/src/lib.rs`) — it is the sans-IO contract layer every
attacker-controlled byte stream and CLI-adjacent string runs through before
anything else touches it. This crate holds the `cargo-fuzz` harnesses over
that surface, plus two string parsers in `qsh-transport` (`Fingerprint`/
`Principal`) that are reached from the same untrusted-input paths (trust
store files, ACL principal text).

## Why this lives outside the workspace

`rust-toolchain.toml` pins the whole `qsh` workspace to **stable 1.97.1**.
`cargo-fuzz` requires **nightly** (it builds with `-Z sanitizer=address`
and friends, which are `-Z` unstable-only flags). `fuzz/Cargo.toml` has its
own empty `[workspace]` table and `fuzz/` is deliberately **not** listed in
the root `Cargo.toml`'s `members`, so:

- the six stable-toolchain gates (`cargo fmt`, `cargo clippy`, `cargo run -p
  xtask -- arch`, `cargo deny check`, the Windows cross-checks, `cargo
  nextest run --workspace`) never see this crate, and are unaffected by it;
- `xtask arch` iterates workspace members only, so this crate (and its
  `qsh-proto`/`qsh-transport` path dependencies, added the ordinary way) is
  invisible to the dependency-direction lint;
- you need a nightly toolchain installed to build or run anything under
  `fuzz/`, but not to build, lint, or test the rest of the repo.

Install what's missing:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

`cargo-fuzz` invokes `cargo` for the nightly toolchain itself, so if `cargo`
on your `PATH` is pinned to something other than nightly's rustup shim (as
it is on machines where `PATH` hardcodes a toolchain's `bin/` directory
ahead of rustup's proxy), prepend the nightly toolchain's `bin/` directory
explicitly rather than relying on `rustup run` / `cargo +nightly`:

```sh
export PATH="$(rustc +nightly --print sysroot 2>/dev/null || rustup which --toolchain nightly rustc | xargs dirname)":$PATH
# or, if that toolchain path is already known:
export PATH=~/.rustup/toolchains/nightly-<host-triple>/bin:$PATH
```

Everything below assumes `cargo` on `PATH` resolves to the nightly
toolchain's `cargo` (verify with `cargo --version`).

## Target list

Run from `fuzz/`:

| target | file | covers |
|---|---|---|
| `frame_decoder` | `crates/qsh-proto/src/frame.rs` | `FrameDecoder::push`/`next_frame`/`take_remaining`, driven as an arbitrary interleaved sequence (models a peer trickling bytes and a caller draining/splicing mid-stream). Asserts no panic, no allocation-before-cap-check on an oversize header, and full byte conservation. |
| `decode_control` | `crates/qsh-proto/src/wire.rs` | `decode_msg::<ControlMessage>` — the whole control-stream oneof (Hello, Session*, ExecStart, Rfwd*, Ping/Pong, SessionEvent, PairingProof/Accepted, Response{...,Error}). Chains `SessionWrite::validate`/`SessionAttach::attach_mode`+`wants_write`/`SessionReadResult::validate`/`Error::error_code` on the relevant decoded variant. |
| `decode_hello` | `wire.rs` | `decode_msg::<Hello>` alone — the very first control-stream message, narrower target than `decode_control` for coverage-guided mutation to focus on. |
| `decode_exec_frame` | `wire.rs` | `decode_msg::<ExecFrame>` — the EXEC_DATA stream oneof (Stdout/Stderr/Stdin/StdinEof/ExecExit), independent grammar/cap from the control stream. |
| `decode_session_frame` | `wire.rs` | `decode_msg::<SessionFrame>` + `.validate()` chained — the SESSION_DATA stream oneof the PTY/replay-ring pump calls on every decoded frame. |
| `decode_stream_header` | `wire.rs` | `decode_msg::<StreamHeader>` + `.stream_kind()` chained — the first message on every newly-opened QUIC stream, before kind-based dispatch. |
| `decode_connect_result` | `wire.rs` | `decode_msg::<ConnectResult>` + `sanitize_peer_text` on `code`/`message` chained — the reply a `-L` local-forward dial reads off the `TCP_CONNECT` stream (`crates/qsh-core/src/tunnel/local.rs`), the sole top-level `decode_msg` message reached with no ticket in front of it. |
| `decode_local_hello` | `crates/qsh-proto/src/local.rs` | `decode_local::<LocalHello>` — first frame of every localctl conduit (separate `qsh.local.v1` package from `qsh.wire.v1`). |
| `decode_local_admin_request` | `local.rs` | `decode_local::<LocalAdminRequest>` — the `LOCAL_ADMIN` conduit's second frame (`LocalHostList`/`LocalTunnelList`/`LocalTunnelClose` oneof). |
| `sanitize_peer_text` | `wire.rs` | `sanitize_peer_text` — the ANSI/OSC-hostile control-character stripper for any peer-authored prose this side displays. Asserts no un-replaced control byte (other than `\t`) and no dropped/merged characters. |
| `valid_host_name` | `wire.rs` | `valid_host_name` — shape check on a reverse target's offered name, run before it can become an ACL resource/audit field. |
| `valid_forward_id` | `wire.rs` | `valid_forward_id` — shape check on an opaque host-issued forward token a peer echoes back. |
| `parse_invite_code` | `crates/qsh-proto/src/pairing.rs` | `parse_invite_code` — Crockford Base32 invite-code decode (case-fold, hyphen-agnostic, `i`/`l`/`o` remap, `u` rejected), reached from `qsh trust accept`. Transitively exercises the private per-`char` `decode_symbol` over the full Unicode domain. |
| `parse_forward_spec` | `wire.rs` | `parse_forward_spec` — the `-L`/`-R` forward-spec grammar (`[bind:]listen_port:host:host_port`, IPv6 bracket tokenizing). Local-CLI-origin text, included because it's part of qsh-proto's sans-IO parser surface. |
| `fingerprint_principal` | `crates/qsh-transport/src/identity.rs` | `Fingerprint::from_str` and `Principal::from_str`, selected by a leading byte. Fingerprint text is reached from `trust.toml` on disk and `qsh trust add`; Principal text from `qsh acl check --principal` (and composes `Fingerprint::from_str` for its `fp:` branch). |
| `json_request_types` | `crates/qsh-proto/src/types.rs` | `serde_json::from_slice` into each `qsh_proto::types` request type the MCP adapter deserializes an external client's tool-call `arguments` into (`crates/qsh-cli/src/mcp/mod.rs`, `run_tool`), selected by a leading byte. |

Each target's doc comment (top of its `fuzz_targets/*.rs` file) has the
fuller "why this is the right target boundary" rationale.

## Running one target

```sh
cd fuzz
cargo fuzz run <target>                      # runs until killed (Ctrl-C)
cargo fuzz run <target> -- -max_total_time=60  # bounded by wall time
cargo fuzz run <target> -- -runs=100000        # bounded by iteration count
```

`cargo fuzz run` builds in release with ASan instrumentation, seeds from
`corpus/<target>/`, and **writes new coverage-expanding inputs back into
that same directory** — that's expected corpus growth, not a bug. A crash
(panic, ASan abort, OOM) writes a reproducer to `artifacts/<target>/` and
stops that run; reproduce and minimize it with:

```sh
cargo fuzz run <target> artifacts/<target>/<crash-file>
cargo fuzz tmin <target> artifacts/<target>/<crash-file>
```

`artifacts/` is gitignored (crash reproducers are a local debugging
artifact, not something to commit as part of standing up the harness) —
copy one out of the tree if you need to hand it to someone else.

## The 72-hour accumulation (M8 DoD)

The M8 Definition of Done requires **≥72 cumulative fuzz-hours per target
with zero crashes** — wall-clock time, not compressible, and counted **per
target** (that's why the target list above is a fixed contract: don't fold
targets together or split them apart without updating what "72 hours"
means for the merged/split result). Run each target for its own 72+ hours,
independently — they don't share a clock:

```sh
cd fuzz
mkdir -p /var/fuzz/grown
for t in $(cargo fuzz list); do
  # scratch/grown dir FIRST, checked-in seed dir second — see "Corpus"
  # below for why the order matters.
  cargo fuzz run "$t" /var/fuzz/grown/"$t" corpus/"$t" -- -max_total_time=259200 &
done
wait
```

Driving the target list from `cargo fuzz list` instead of a hard-coded
name list means a newly added target picks up its 72-hour run
automatically — nothing to remember to update here when the target count
changes.

Running the full target list in parallel needs one core per target to
actually get independent 72-hour clocks in 72 wall-clock hours; on fewer
cores, run them in batches (sequential `-max_total_time=259200` per batch)
and the wall-clock cost multiplies accordingly. `libFuzzer` reports total
execs and any crash to stderr as it runs; a clean `-max_total_time` run
that exits without a "crash" or "SUMMARY: *Sanitizer" line satisfies that
target's 72 hours.

## Corpus

**The checked-in `corpus/<target>/` is the curated seed set only, and
nothing else ever writes to it.** libFuzzer writes every newly discovered
coverage-expanding input into the *first* corpus directory argument on its
command line — so any run longer than a one-off smoke check must pass a
writable scratch/grown directory first and `corpus/<target>` second, e.g.:

```sh
cargo fuzz run <target> /var/fuzz/grown/<target> corpus/<target> -- -max_total_time=259200
```

Omitting the scratch directory (`cargo fuzz run <target>` with no
explicit corpus args) makes `corpus/<target>` itself the first — and
only — directory, and libFuzzer will grow it in place. That's fine for a
quick `-runs=N` smoke check you don't intend to keep, but never do it for
a long or measurement run.

The grown corpus lives on the fuzz host, under a scratch directory such as
`/var/fuzz/grown/<target>` — it is periodically `cargo fuzz cmin`-able
there, but it is **not committed**. Only the hand-curated seeds below are
checked in.

`corpus/<target>/` is seeded from real values pulled from this repo's own
tests and fixtures — not random bytes — per target:

- `frame_decoder`: raw framed-byte fixtures shaped like `frame.rs`'s own
  unit tests (`roundtrip_encode_decode`, `take_remaining_drains_bytes_...`,
  the `u32::MAX` oversize-header case, the empty-frame and
  back-to-back-frames cases).
- `decode_control` / `decode_hello` / `decode_exec_frame` /
  `decode_session_frame` / `decode_stream_header`: protobuf-encoded
  messages built with the exact same field values `wire.rs`'s
  `arb_hello`/`arb_control_body`/etc. proptest strategies and golden-vector
  tests use (e.g. `device_name: "hermes"`, a `SessionAttach` with an
  out-of-range `mode`, an `Output` chunk exactly at and one byte over
  `SESSION_CHUNK_MAX`), encoded via `prost::Message::encode_to_vec` (the
  same bytes `decode_msg` is handed in production, i.e. *not*
  frame-wrapped).
- `decode_local_hello` / `decode_local_admin_request`: the same treatment
  for `qsh.local.v1`, covering each `LocalStreamKind` variant and each
  `LocalAdminRequest` oneof arm plus the `body: None` discriminator case
  the message's own doc comment calls out.
- `sanitize_peer_text`: plain prose, an ESC/CSI cursor-move sequence, an
  OSC title-set sequence, tab-preservation, and multi-byte UTF-8 — the
  ANSI/OSC injection threat model the function's own doc names explicitly.
- `valid_host_name` / `valid_forward_id`: boundary lengths (63/64/65 bytes)
  and multi-byte UTF-8 at the cap, since the existing regex-based proptest
  strategies never emit invalid bytes and can't probe the byte-vs-char-count
  boundary the way raw fuzzing can.
- `parse_invite_code`: every case `pairing.rs`'s own test module has a
  named test for — all-zero/all-`f` secrets, the `i`/`l`/`o`/`u` alphabet
  special cases, wrong length, invalid alphabet characters, and the
  100,000-character overlong-input regression case.
- `parse_forward_spec`: the three-part/four-part/IPv6-bracketed/
  port-boundary/garbage cases named in `wire.rs`'s
  `parse_forward_spec_*` test functions.
- `fingerprint_principal`: valid and case-variant fingerprints, wrong
  base64 length, a multi-byte character straight after the `sha256:`
  prefix, and all four `Principal` shapes (`device:`/`user:`/`fp:`/
  `pairing`) plus their `_invalid`/`_empty` variants, from
  `identity.rs`'s own test module.
- `decode_connect_result`: an `ok: true` result, an `ok: false` result with
  a real `ErrorCode` string (`PERMISSION_DENIED`, `CONNECTION_FAILED`) and
  a realistic message, and an `ok: false` result whose message carries an
  OSC-title-set-plus-CSI-color ANSI escape sequence — same injection
  threat model as `sanitize_peer_text`, since this target chains straight
  into it.
- `json_request_types`: one selector-byte-prefixed valid JSON object per
  `qsh_proto::types` request type covered, pulled from the MCP
  conformance test's own tool-call `arguments` (`crates/qsh-cli/tests/
  mcp_conformance.rs`), plus one malformed-JSON seed and one
  wrong-JSON-shape (array where an object is expected) seed.

The generator that produced the protobuf-encoded seeds above (a throwaway `prost`-based binary, not
checked in — it isn't part of the repo, just the tool that wrote the files
under `corpus/`) built each message with the crate's own public
constructors/struct literals and `encode_to_vec()`, so the seed bytes are
guaranteed-valid encodings, not hand-typed hex.

## CI

`.github/workflows/fuzz-smoke.yml` runs a short, deterministic
`-runs=<N>` smoke build-and-run of every target on every push/PR — a
build-and-crash-check gate, not the 72-hour accumulation (which has no
place in CI; it's a standing local/background job). It's a separate job
from the existing `ci.yml` gates so a nightly-toolchain install or a slow
fuzz build can never slow down or block the stable six-gate CI, and it's
marked non-blocking (`continue-on-error: true`) for now: this is the
harness's first day, the parser surface is large, and a red PR check on a
brand-new nightly-only job before anyone has triaged what "normal" looks
like here would train people to ignore it. Flip it to blocking once it's
been green for a while.
