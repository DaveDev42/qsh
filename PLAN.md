# PLAN.md — M2 실행 계획

이 문서는 **현재 마일스톤(M2 — 세션 broker + PTY + resume)의 실행 계획**이다. 마일스톤 정의(범위·수용 기준·크기)의 정본은 항상 [`docs/ROADMAP.md`](docs/ROADMAP.md)이며, 이 문서는 그 정의를 바꾸지 않고 실행 순서로 분해한다. **M2가 Done 처리되면 이 문서는 다음 마일스톤(M3)의 계획으로 전면 교체된다** — living doc이며 과거 마일스톤의 실행 기록으로 남기지 않는다.

## 1. M2 목표 요약

`docs/ROADMAP.md` "M2 — 세션 broker + PTY + resume" 절 인용:

> (a) headless broker — 세션 registry, ReplayRing(누적 byte offset sequence), writer lease, resume TTL, gap 산출 + `session.open/get/read/write/resize/close`·`session.list` op, (b) POSIX PTY(setsid, controlling tty, resize, signal, reaping, login shell env) + 대화형 TUI(`qsh user@host`, `qsh attach`, detach key), (c) connection migration(`rebind`) + resume(`session.attach` + resume token + last_seq) + replay/dedup + `session.gap` 이벤트. **chaos proxy 하네스**(`docs/design/testing.md` L4)와 recovery 텔레메트리(`recovery ∈ {migrated,resumed,failed}` + time-to-recovery)를 같이 구축.

### DoD 체크리스트 (`docs/ROADMAP.md` M2 "수용 기준" 인용)

- [ ] Property test: 임의의 append/read interleaving에서 gap 이벤트가 없는 한 반환 바이트 연결 == 원본 stream suffix (byte-identical, 무손실·무중복) — SC4의 property 표현.
- [ ] `qsh user@host`로 실제 셸 사용 가능 — bash/zsh, vim, tmux, `claude`가 동작하고 resize 전파.
- [ ] **클라이언트를 `yes` 실행 중 `kill -9` → reattach → last_seq부터 이어붙인 결과가 기준 stream과 byte-identical** (SC4). remote PTY와 자식 프로세스는 클라이언트 사망에 생존 (SC5).
- [x] Chaos proxy `repath()` → connection migration으로 세션 무중단; `sever()` → 2초 내 재dial + resume. (Step 7: `crates/qsh-testkit/tests/resume_chaos.rs` — 클럭은 `sever()` 직전 시작, 첫 replay 바이트에서 정지, 옛 연결의 idle timeout 아님을 함께 단언)
- [ ] 실기기 Wi-Fi↔테더링 전환 20회 수동 캠페인, recovery 필드 기록 (SC3 조기 측정).

M2 크기: 5ew (`docs/ROADMAP.md` M2 "크기").

## 2. 작업 분해 (Step 1..9)

원칙: **모든 step은 완료 시점에 `cargo fmt --all` / `cargo clippy --workspace --all-targets -- -D warnings` / `cargo test`(또는 `cargo nextest run`) / `cargo run -p xtask -- arch` 전부 green을 유지해야 한다.** 이 게이트를 통과하지 못한 상태로 다음 step으로 넘어가지 않는다 (`CLAUDE.md` "Before committing").

각 step은 독립적으로 리뷰 가능한 PR 하나 크기다. 순서는 의존 순 — wire/JSON 계약 → 순수 broker → dispatch 배선(headless 검증) → PTY → session data 스트림 → TUI → resume/migration → chaos 회귀 → 실기기 캠페인. `docs/ROADMAP.md` 시퀀싱 원칙 3번("PTY 세션 모델은 headless로 먼저 검증 … TUI는 이미 검증된 broker의 얇은 소비자로 나중에 얹는다")이 Step 2–3과 Step 4·6의 분리 근거다.

전 step 공통 계약 규율: `qsh.cli/v1`·`qsh.event/v1`은 **additive-only**(optional 필드 추가만, 삭제·의미 변경은 `/v2`), `crates/qsh-cli/tests/fixtures/cli-v1/`의 fixture는 **append-only**(기존 파일 편집·삭제 금지, 새 파일 추가만) — `docs/CLI.md` §10, `docs/design/testing.md` L6, `CLAUDE.md` "Contract stability rules".

---

### Step 1 — Wire·JSON 계약 확장: session control message + `SessionFrame` + 계약 타입

**(a) 범위:** M1이 의도적으로 비워 둔 세션 영역을 `.proto`에 채운다. `ControlMessage.body`에 주석으로만 예약돼 있던 번호를 실제로 점유한다: `session_open=20`, `session_attach=21`, `session_list=22`, `session_get=23`, `session_resize=24`, `session_close=26`(optional `signal`), `session_read=27`, `session_write=28`, `session_event=60`; **25(구 `SessionSignal`)는 `reserved`만**(수신 시 `UNSUPPORTED`, CLI.md §2.4). `Response.body`에 `session_opened=1`, `session_attached=2`, `session_read_result=5`, `session_list_result=6`, `session_info=7`. 신규 메시지 `SessionOpen(optional user)/SessionOpened(+expires_at)/SessionAttach/SessionAttached(+expires_at)/SessionList/SessionGet/SessionResize/SessionClose/SessionRead/SessionWrite/SessionInfo(wire — `session_ref`·`host` 없음, ADR-0007)/SessionEvent(WriterChanged{optional new_writer, seq}, Closed{reason, seq})`와 data 스트림용 `SessionFrame{Output|Input|InputAck|Gap|Resize|Exit}`를 `docs/design/protocol.md` §9 스케치 그대로 정의한다. 현재 `.proto`에는 컴파일러가 강제하는 `reserved` 선언이 없고 주석 관례뿐이므로, 이 step에서 M3/M4용 번호(`Hello.reverse=4`, `ControlMessage` 40–41, `Response` 4)에 **실제 `reserved` 선언을 넣어** 번호 도용을 기계적으로 막는다. `qsh-proto::types`에 `SessionOpenReq/SessionOpenData`, `SessionReadReq/SessionReadData`, `SessionWriteReq/SessionWriteData`, `SessionResizeReq/SessionResizeData`, `SessionCloseReq/SessionCloseData`, `SessionListReq/SessionListData`, `SessionGetReq`, `SessionAttachReq`를 CLI.md §5·§6.2–6.7 field-for-field로 추가하고, 이미 placeholder로 존재하는 `types::Session`(`session_ref`/`host`/`session_id`/`state`/`writer`/`created_at`/`last_sequence`)을 실사용 타입으로 승격한다 — 단 `writer`는 `Option<String>`(principal 문자열, lease 없으면 `null`; CLI.md §5, placeholder라 fixture 없음). `event.rs`의 `SessionEvent::{Output,Gap,Exit}`는 M1에 이미 정의돼 있고 producer만 없다 — 이 step에서 `WriterChanged{session_ref, sequence, writer: Option<String>}`/`Closed{session_ref, sequence, reason: String}` variant와 unknown-type fallback variant를 추가한다(CLI.md §6.4·§10, architecture.md §2 "Event 타입의 전방 호환").

**(b) crate/모듈/파일:**
- `crates/qsh-proto/proto/qsh/wire/v1.proto` (확장 — 위 message/oneof/`reserved`)
- `crates/qsh-proto/src/wire.rs` (확장 — `encode_session_frame()`(`DATA_FRAME_MAX`), `StreamHeader::session_data(ticket)`, `SessionFrame` 생성자 sugar, `CAP_SESSION = "session"`·`CAP_RESUME_V1 = "resume.v1"`를 `LOCAL_CAPABILITIES`에 추가, `SESSION_CHUNK_MAX = 16 KiB`)
- `crates/qsh-proto/src/types.rs` (확장 — 위 JSON 계약 타입, 기존 타입 수정 금지)
- `crates/qsh-proto/src/event.rs` (확장 — `WriterChanged`/`Closed` variant + unknown-type fallback; 모듈 doc의 "output/gap/exit" 갱신)

**(c) 빚지는 테스트 (`docs/design/testing.md` L0):** 신규 message 전부 `decode(encode(m)) == m` roundtrip(proptest), 모든 prefix가 `Ok(None)`(=incomplete)로 처리되는 truncation 테스트, `SessionFrame` chunk가 `SESSION_CHUNK_MAX`를 넘으면 인코딩 단계에서 거부, golden vector 1개 이상 체크인. `Response.Error.code` 어휘가 `ErrorCode`와 동일함을 단언하는 기존 테스트에 세션 코드(`SESSION_NOT_FOUND`/`SESSION_CONFLICT`/`RESUME_GAP` — 셋 다 `error.rs`에 이미 존재)를 포함시킨다.

**(d) 완료 판정:** 신규 메시지 L0 green. `qsh version --json`의 `schemas` 배열과 fixture가 깨지지 않음(추가만 발생). `xtask arch` green(`qsh-proto`는 여전히 무의존).

**(e) 인용:** `docs/design/protocol.md` §5(frame 상한), §7(스트림 배치 표 "Session data" 행), §8(sequence = 누적 output byte offset), §9(.proto 스케치 — 이 step의 정본), §10(resume 필드), `docs/CLI.md` §2.3(sequence 시맨틱), §5(Session 타입), §6.2–6.7(session op 계약), §10(additive-only).

---

### Step 2 — Broker core: `ReplayRing` + `SessionBackend` seam + 주입 가능한 clock (순수 로직)

**(a) 범위:** 네트워크도 PTY도 없는 순수 broker. `ReplayStore` trait 뒤의 `ReplayRing`(기본 8 MB, chunk ring, eviction은 whole-chunk·gap 계산과 replay 절단은 byte 정확), 세션 registry(`SessionId → SessionHandle`, 단일 lock), `SessionActor`(세션당 tokio task, mpsc 인박스: Write/Resize/Signal/Pull/Subscribe/TakeLease/Close), writer lease 규칙(steal 기본 / `no_steal` → `SESSION_CONFLICT` / 소유 connection 사망 시 자동 해제 / 읽기는 lease 불요), resume TTL reaper(30s tick, SIGHUP→TERM→KILL), `pull(session, after, max_bytes, wait)` cursor-pull primitive와 gap 산출. **바이트는 생성 지점에서 누적 offset이 붙는다** — ring push가 offset을 확정하는 유일한 지점이고 그 아래(네트워크·렌더러)에서는 재계산하지 않는다. 시간은 전부 주입된 `Clock` trait 경유(`tokio::time::pause()` 및 M8 stateful fuzzer 전제). 바이트 생산자는 `SessionSource` trait(spawn → reader/writer/resize/signal/wait) 뒤에 두고 이 step에서는 pipe 기반 `PipeSource`(비-PTY)만 구현한다 — PTY는 Step 4.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/broker/mod.rs` (신규 — `SessionBackend` trait + in-process `Broker` 구현, registry, TTL reaper)
- `crates/qsh-core/src/broker/ring.rs` (신규 — `ReplayStore` trait, `ReplayRing`)
- `crates/qsh-core/src/broker/session.rs` (신규 — `SessionActor`, `SessionHandle`, `SessionState`, `SessionSource` trait + `PipeSource`)
- `crates/qsh-core/src/broker/lease.rs` (신규 — writer lease)
- `crates/qsh-core/src/broker/clock.rs` (신규 — `Clock` trait, `SystemClock`, `TestClock`)
- `crates/qsh-core/src/config.rs` (확장 — `[serve].replay_bytes`(기본 8 MiB), `[serve].resume_ttl`(기본 24h), `[serve].close_grace_ms`(기본 5000, CLI.md §6.7))
- 네이밍 주의: `qsh_core::client::Session`(연결 수준)과 `qsh_proto::types::Session`(JSON DTO)이 이미 있으므로 broker 타입은 `SessionHandle`/`SessionId`/`SessionActor`로 명명한다.

**(c) 빚지는 테스트 (`docs/design/testing.md` L2):** naive `Vec` oracle 대조 property test(임의 append/pull interleaving → gap 없으면 반환 바이트 연결 == 원본 suffix, byte-identical) — **DoD 1번 항목이 여기서 통과한다**. buffer 초과 시 정확한 `available_from`을 가진 gap 산출(silent truncation 금지). lease: 획득/steal/`no_steal` → `SESSION_CONFLICT`/connection 사망 시 해제/TTL 만료. UTF-8 멀티바이트가 chunk 경계에 걸쳐도 손상 없음. **전 테스트 `sleep()` 금지** — `TestClock` + `tokio::time::pause()` + 이벤트 통지.

**(d) 완료 판정:** DoD 1번 항목 green. `broker/` 모듈의 어떤 파일도 `qsh_transport::`를 import하지 않음(ADR-0003 seam — `xtask arch`는 manifest 수준이라 이걸 못 잡으므로 **Step 2에서 `xtask arch`에 모듈 경로 기반 import 금지 규칙을 추가**한다; `docs/design/architecture.md` §9-2가 이미 "arch-lint 확장 후보"로 지목). 세션당 메모리가 ring 예산 + 소비자별 소량으로 유계임을 테스트로 단언.

**(e) 인용:** `docs/design/architecture.md` §3(Broker 구조도 전체 — registry/TTL reaper/SessionActor/ReplayRing/cursor-pull/writer lease/child 종료/Supervisor seam), §9-1(resume·replay 정합성 리스크), `docs/design/testing.md` L2 전체(특히 "주입 가능한 clock을 M2 설계 시점부터"), `docs/design/protocol.md` §8(누적 byte offset), §12(replay ring = 만능 decoupler), ADR-0003(SessionBackend trait은 transport 타입 import 금지), ADR-0004(memory-only ring, `ReplayStore` trait 격리, gap이 overflow의 유일한 신호), `docs/PRD.md` §8(세션 모델), §13(세션당 8MB·resume TTL 24h), `docs/ROADMAP.md` 시퀀싱 원칙 7(a).

---

### Step 3 — 세션 op를 `dispatch`에 배선: `Action` 확장 + ticket + headless `qsh session *`

**(a) 범위:** `Server`에 broker를 주입하고 `dispatch`에서 세션 control message를 처리한다. `acl::Action`에 `SessionOpen`/`SessionList`/`SessionAttach`/`SessionControl` 4종을 추가하고(CLI.md §2.5 매핑표 그대로), **리소스(세션·PTY·ticket) 생성 이전에** `Authorizer::check` + `AuditRecord::now`를 호출하는 기존 `handle_exec_start` 패턴을 그대로 복제한다. `resource` 문자열은 세션 id(신규 세션은 `"session"`). `SessionOpen.user` hint는 ACL 통과 **후**에만 serve 계정 login name(`getpwuid`)과 비교해 `UNSUPPORTED`를 내고, 미인가 peer는 항상 `PERMISSION_DENIED`다(architecture.md §4). `SessionRead`(27)/`SessionWrite`(28)는 control 스트림 value op로 배선하고(토큰 불요, ACL `session.attach`/`session.control`), 번호 25 수신은 `UNSUPPORTED`. `SessionRead`의 cursor는 **(output offset, control entry id) 쌍**이다 — 제어 엔트리는 zero-length라 offset을 증가시키지 않으므로 `after`만으로는 "offset N의 제어 엔트리는 이미 받았다"를 표현할 수 없다. wire에 additive `ctl_after`(요청)와 `next_after`/`next_ctl_after`(응답)를, JSON에 같은 이름의 additive field와 CLI `--ctl-after`를 둔다(CLI.md §6.4, protocol.md §9). peer가 보낸 `session_id`는 ACL/audit에 닿기 전에 `1..=64` URL-safe 형태를 검사하고, `wait_ms`는 `SESSION_READ_MAX_WAIT`(60 s)로 clamp한다(거부 아님). ticket 발급/redeem은 기존 `issue_ticket`/`redeem_ticket`(16-byte, 30s TTL, 연결 결합, 단회용)을 `SESSION_DATA`용으로 일반화하고, `handle_data_stream`이 `StreamKind::SessionData`를 받도록 확장한다. `purge_connection`은 lease 해제까지 수행하되 **세션은 살려 둔다**. ~~`dispatch`는 sync 시그니처(`fn dispatch(&self, ctx, msg) -> Option<ControlMessage>`)를 유지한다~~ — **정정(구현 중 확정):** `SessionRead`의 long-poll과 `SessionClose`의 escalation은 broker를 `await`해야 하므로 `dispatch`는 `async fn`이다. 대신 **순서 계약을 명시적으로 지킨다**: control 메시지는 도착 순서대로 **인라인** 처리하고(pipelining된 두 `SessionWrite`는 보낸 순서대로 적용된다), 오래 블록될 수 있는 `SessionRead`/`SessionClose`만 연결 소유의 `JoinSet` task로 떼어낸다. 그 task는 연결 루프가 반환할 때 함께 취소되므로 `purge_connection`보다 오래 살지 않는다(죽은 연결 이름으로 lease가 다시 잡히는 창 없음). 동시 실행은 연결당 `MAX_INFLIGHT_REQUESTS_PER_CONN`(64)로 제한하고 초과분은 dispatch 없이 `RESOURCE_EXHAUSTED`(audit 없음)로 답한다. 이 계약은 `docs/design/protocol.md` §9에 기록했다. 클라이언트 측은 `client::Session::request()` 헬퍼 위에 세션 RPC를 얹고, `Ops`에 `session_open/get/list/read/write/resize/close` 메서드 + `ops/session.rs`의 `Operation` 마커를 추가한다. CLI에 `qsh session open|get|read|write|resize|close`, `qsh sessions [host]` 서브커맨드와 human/JSON 렌더러를 붙인다. **이 step까지 PTY 코드는 0줄** — 서버는 `PipeSource`로 세션을 연다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/server/mod.rs` (확장 — broker 필드, session dispatch arm, `StreamKind::SessionData` 수용, `purge_connection` 확장)
- `crates/qsh-core/src/acl/mod.rs` (확장 — `Action` 4종 + `as_str()`)
- `crates/qsh-core/src/ops/session.rs` (신규 — `SessionOpenOp`/`SessionGetOp`/`SessionListOp`/`SessionReadOp`/`SessionWriteOp`/`SessionResizeOp`/`SessionCloseOp` 마커 + `Ops` 메서드)
- `crates/qsh-core/src/client/mod.rs` (확장 — 세션 control RPC)
- `crates/qsh-core/src/serve.rs` (확장 — `Broker` 구성·주입, config의 replay/TTL 값 전달)
- `crates/qsh-cli/src/cli.rs`, `src/main.rs`, `src/render/{human,json}.rs` (확장)

**(c) 빚지는 테스트:** `qsh-core` 유닛 — 세션 op 전부가 ACL choke point를 통과하고, `DenyAll` 하에서 **세션·ticket이 하나도 생성되지 않음**을 단언(기존 `denied_exec_returns_permission_denied_and_creates_nothing` 패턴). L3 loopback — `crates/qsh-testkit/tests/session_loopback.rs` 신규, `LoopbackHarness::start()`/`session()` 위에서 open→write→read(`--after`)→resize→close 전 경로. 미인가 peer가 세션 존재 여부를 알아내지 못함(non-distinguishing 오류)을 단언.

**(d) 완료 판정:** `qsh session open <host> --json`부터 `close`까지 전 시퀀스가 loopback에서 JSON 계약대로 동작하고, audit에 op별 라인이 남는다. `--` 뒤 argv가 shell 재해석 없이 전달됨. 세션 op 4종 모두 `Action` enum을 경유(문자열 하드코딩 0건). Step 1이 남긴 `Server::dispatch`의 임시 "`session_*` → `UNSUPPORTED`" arm과 `wire.rs`의 `LOCAL_CAPABILITIES` TODO 메모를 제거해 광고 capability와 실제 구현이 다시 일치한다(Step 1→3 사이에만 허용된 불일치 창). **정정:** 일치시키는 방법은 `session`을 구현하는 것 **과** `resume.v1`을 `LOCAL_CAPABILITIES`에서 **빼는 것**이다 — `SessionAttach`는 Step 7까지 `UNSUPPORTED`이므로 광고만 남기면 불일치 창이 Step 7까지 열려 있게 된다. `CAP_RESUME_V1`은 Step 7이 되돌려 넣는다(`local_capabilities_advertise_exactly_what_is_implemented`가 이를 강제한다). 호스트는 `SessionAttach.attach_mode() == None`(미설정/미지/RO)을 `INVALID_ARGUMENT`로 답하고 `wants_write()`가 참일 때만 lease를 다룬다; `SessionWrite::validate()`/`SessionReadResult::validate()`를 세션에 손대기 전에 호출하며 `SessionRead.max_bytes`를 `SESSION_READ_MAX_BYTES`로 clamp한다.

**(e) 인용:** `docs/CLI.md` §2.4(dotted operation 이름), §2.5(operation→ACL action 매핑표), §6.2–6.7(session 조회/생성/읽기/쓰기/resize/종료 계약과 예시 envelope), `docs/design/architecture.md` §2(typed op layer 확장 패턴 — `Operation::COMMAND`, `OpError`), §6(단일 choke point: 리소스 생성 이전 `Authorizer::check`), `docs/design/protocol.md` §7(ticket은 ACL 통과 후에만 발급, 단회용 30s), `docs/PRD.md` §9(인증 전 PTY/exec/tunnel 리소스 생성 금지), `docs/ROADMAP.md` 시퀀싱 원칙 3번·7(b).

---

### Step 4 — POSIX PTY backend

**(a) 범위:** `SessionSource`의 PTY 구현. `portable-pty` 0.9로 spawn, `setsid` + controlling tty를 가진 process group leader, master fd를 `tokio::io::unix::AsyncFd`로 감싼 비동기 read/write, `TIOCSWINSZ` resize, signal 전달과 세션 정리의 **`killpg`(leader가 아니라 process group 전체)**, waitpid reaping, login shell 환경 구성(`TERM`/`SHELL`/`$HOME`/`argv[0] = "-zsh"`/macOS `path_helper`). utmp/wtmp는 기록하지 않는다(결정 사항, 문서화만). 전 PTY 코드는 `#![cfg(unix)]` 게이트.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/pty/mod.rs` (신규 — `PtySource: SessionSource`, spawn/resize/signal/wait)
- `crates/qsh-core/src/broker/session.rs` (확장 — `PtySource` 배선, child 종료를 ring에 기록 후 `exited` 상태 유지)
- `crates/qsh-core/Cargo.toml` (portable-pty 0.9 추가; unix 전용 target 의존)

**(c) 빚지는 테스트 (`docs/design/testing.md` L5):** macOS/Linux master-fd EOF 시맨틱 차이(`sh -c 'printf x; exit 0'`의 `x`가 exit 이벤트 **전에** 양 플랫폼에서 도착 — 고전적 "마지막 한 줄 손실" 버그, SC4 직격), 순서 불변식(1MB 출력 후 즉시 exit → 모든 출력이 ring에 들어간 뒤에야 `session.exit` append), UTF-8 chunk 경계, macOS/Linux backpressure 차이, `setsid`+controlling tty에서 job control 동작 및 close가 process group 전체 종료, 순차 세션 100회 후 zombie 0·fd 증가 0, login shell 환경 변수 단언.

**(d) 완료 판정:** 위 L5 테스트가 macOS·Linux 양쪽 CI 타깃에서 green. `PipeSource` 기반 Step 2–3 테스트는 그대로 유지(회귀 감시용으로 남긴다). clippy가 4개 타깃 전부에서 green(`cfg(target_os)` 블록 누락 방지).

**(e) 인용:** `docs/design/architecture.md` §4(PTY — portable-pty/AsyncFd/setsid/killpg/login shell env/utmp 미기록), `docs/design/testing.md` L5 전체, `docs/PRD.md` §7 P0 표(PTY: POSIX PTY, resize, signal, attach와 detach), `docs/ROADMAP.md` §4 일정 리스크 2번(PTY long tail — 명명된 수용 세트로 timebox), §3 유예 가드레일(Windows: PTY 코드 `#![cfg(unix)]`, Windows CI 없음).

---

### Step 5 — `SESSION_DATA` 스트림 + `session.attach` stream op + `--follow --jsonl`

**(a) 범위:** attach당 bidi 스트림 1개: `StreamHeader{SESSION_DATA, ticket}` 후 framed `SessionFrame`. 서버→클라이언트 `Output{sequence, data}`(chunk ≤ 16 KiB, quinn `set_priority(100)`), 클라이언트→서버 `Input{input_seq, data}`/`Resize`, 서버의 `InputAck{acked_input_seq}`와 `input_seq ≤ 적용 offset` input 폐기(무손실·무중복), 종료 시 `Exit{final_seq, exit_code, signal}`. `Ops`에 유일한 stream operation `session.attach`를 typed event `Stream` 반환 형태로 추가하고, `session read --follow --jsonl`과 `session read --wait`이 **같은 cursor-pull primitive**를 소비하도록 배선한다(M6 MCP long-poll이 얹힐 자리). JSONL 렌더러는 `qsh.event/v1`의 `session.output`/`session.gap`/`session.exit`를 그대로 한 줄씩 출력한다 — 이 step이 `event.rs`의 첫 producer다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/session_stream.rs` 또는 `crates/qsh-core/src/broker/stream.rs` (신규 — 서버측 SESSION_DATA 펌프: ring cursor → `Output` 프레이밍, input dedup/ack)
- `crates/qsh-core/src/client/mod.rs` (확장 — `Session::attach()`: ticket으로 data 스트림 open, send/recv 분리 펌프)
- `crates/qsh-core/src/ops/session.rs` (확장 — `SessionAttachOp` stream op, `session.read --follow` 소스 공유)
- `crates/qsh-cli/src/render/json.rs` (확장 — JSONL event 렌더)
- `crates/qsh-transport/src/control.rs` (필요 시 확장 — 우선순위 설정 헬퍼는 이미 `FramedSend::set_priority` 존재)

**(c) 빚지는 테스트:** L3 loopback — attach 스트림 위에서 output 순서·sequence 단조성, input ack/dedup(같은 `input_seq` 2회 전송 → 1회만 적용), 느린 소비자가 ring 밖으로 밀리면 `session.gap` 수신 후 전진(pty_reader가 절대 블록되지 않음을 별도 단언). L6 — `-vv --jsonl`로 시끄러운 세션 실행 후 stdout 전 줄이 완전한 JSON object(`jsonl_purity.rs` 확장).

**(d) 완료 판정:** `qsh session read <ref> --after N --follow --jsonl`이 무손실 event stream을 내고, 동일 세션에 대한 `--wait` 1회 pull과 `--follow` 루프가 같은 코드 경로임을 테스트로 증명. control 스트림 우선순위 200 > session data 100 설정이 코드에 존재.

**(e) 인용:** `docs/design/protocol.md` §7(Session data 행), §8(sequence/input_seq 시맨틱), §9(`SessionFrame` 정의), §10-5(input 무손실·무중복, 64 KiB 미-ack 버퍼 상한), §12(우선순위 band, replay ring decoupler), `docs/CLI.md` §6.4(read/follow/gap/exit event 계약과 `available_from` 의미), §7.1(value op vs stream op — `session.attach`가 유일한 stream op이며 attach와 read/write 사이에 별도 business logic 없음), `docs/design/architecture.md` §2(streaming op), §3(cursor-pull 단일 primitive), §9-5(느린 소비자 backpressure 리스크).

---

### Step 6 — 대화형 TUI: `qsh user@host` / `qsh attach` / detach key / resize / signal

**(a) 범위:** Step 5의 stream op 위에 얹는 **얇은** 소비자. 로컬 터미널 raw mode 진입/복원(패닉·시그널 경로 포함), `SIGWINCH` → `SessionResize` 전파, SIGINT는 기본적으로 원격 PTY로 전달, 행 시작 tilde escape(`~d`/`~.` detach, `~~`, `~?`; `--escape-char <c>|none`; TTY stdin일 때만 활성 — CLI.md §7)로 세션을 살린 채 로컬만 이탈, 종료 시 원격 exit code 반영(CLI.md §4: `qsh exec`와 같은 clamp 규칙, detach는 `0`). clap에 bare positional 형태(`qsh dave@personal-mac`)를 도입한다 — 현재 `Command` enum에는 `user@host` 파서가 전혀 없으므로 신규 value-parser + 기본 서브커맨드 배치가 필요하다. `qsh attach <session-ref>`도 같은 경로. **DoD 2번 항목의 수용 세트(bash/zsh, vim, tmux, `claude`)를 이 step의 명명된 timebox로 고정**하고, 그 밖의 터미널 quirk는 마일스톤 밖 백로그로 보낸다.

**(b) crate/모듈/파일:**
- `crates/qsh-cli/src/tui/mod.rs` (신규 — raw mode 관리, 입력 펌프, detach key 처리, resize 감시)
- `crates/qsh-cli/src/cli.rs` (확장 — `user@host` positional + `Command::Attach { session_ref }`)
- `crates/qsh-cli/src/main.rs` (확장 — TUI 경로는 envelope를 stdout에 내지 않음; 진단은 stderr 전용)
- `crates/qsh-cli/Cargo.toml` (`nix` 0.29+ features `term`/`ioctl`/`poll`/`signal` — `[target.'cfg(unix)'.dependencies]`로 선언, architecture.md §8)

**(c) 빚지는 테스트 (`docs/design/testing.md` L5 마지막 항목):** `expectrl` 기반 expect 하네스 — **클라이언트 자체를 pty 아래에서 실행**해 termios raw mode 경로가 실제로 돌게 한다. 수용 세트 스크립트: bash/zsh 프롬프트 왕복, `vim` 진입/편집/종료, `tmux` 안에서의 resize 전파, `claude` 기동. resize는 `--cols/--rows` 변경 후 원격 `stty size`가 일치함으로 단언. detach key 후 세션이 `running` 상태로 남고 재attach 가능함을 단언.

**(d) 완료 판정:** DoD 2번 항목 green(수용 세트 4종 + resize 전파). 터미널 상태가 어떤 종료 경로(정상/에러/패닉/시그널)에서도 복원됨. `qsh-cli`에 인증·ACL·세션 로직이 0줄임을 리뷰로 확인(`CLAUDE.md` 하드 아키텍처 규칙 — 필요해 보이면 `Ops`로 옮긴다).

**(e) 인용:** `docs/CLI.md` §7(human interactive mode — `qsh dave@personal-mac`, `qsh attach <session-ref>`, raw mode·resize·signal forwarding), §7.1(interactive attach는 `session.attach` 하나 위에 구현), §9(SIGINT 전달과 detach key), §2.2(stdout/stderr 분리), §11(frontend 제약), `docs/design/testing.md` L5("클라이언트도 pty 아래에서 테스트"), `docs/ROADMAP.md` §4 일정 리스크 2번(수용 세트 timebox + expect 하네스 조기 구축), 시퀀싱 원칙 3번.

---

### Step 7 — Resume + connection migration + recovery 텔레메트리

**(a) 범위:** Step 3이 `LOCAL_CAPABILITIES`에서 뺀 `CAP_RESUME_V1`을 되돌려 넣는다(광고 = 구현). `SessionOpened`가 32-byte CSPRNG `resume_token`을 반환하고 호스트는 `blake3(token)`만 `(session_id, peer_spki_sha256, expires_at)`과 저장한다. 클라이언트는 `$XDG_STATE_HOME/qsh/resume.json`(0600)에 보관 — 항목에 `peer_spki_sha256`·`expires_at` 포함, `flock` + tmp+`rename` 원자 교체, 새 토큰을 durable하게 기록한 뒤에야 data 스트림 진행, 정리 규칙은 ADR-0007 결과 절. `SessionAttach{session_id, resume_token, last_output_seq, mode, no_steal}` 처리 순서를 프로토콜 그대로 구현: 토큰 해시 일치·미만료(`subtle::ConstantTimeEq`) → peer fingerprint가 세션 결합 identity와 일치 → ACL `session.attach` → **전부 통과 후에만** ticket + `new_resume_token` 발급(제시 토큰 즉시 무효화, 단일 세대). 실패는 fail-closed·non-distinguishing(`AUTH_FAILED`/`PERMISSION_DENIED`; `SESSION_NOT_FOUND`는 identity 검사 통과 후에만). 데이터 경로: ring이 `L` 이후를 보존하면 정확히 `L`부터 재전송 후 live 전환, 클라이언트는 방어적으로 `sequence ≤ L` frame 폐기; 보존 최소 offset `G > L`이면 첫 frame으로 `Gap{requested_after:L, available_from:G}`. 클라이언트 재접속 루프: path 사망 감지 → **2초 내** 재dial + resume, 인터페이스 변화 시에는 그 전에 `Endpoint::rebind()`로 active migration 시도(`Dialed.endpoint`/`Listener::endpoint()`로 이미 접근 가능). **migration은 지연 최적화일 뿐이며 실패해도 correctness는 resume이 보장한다 — migration 성공에 의존하는 코드를 쓰지 않는다.** recovery 텔레메트리(`recovery ∈ {migrated, resumed, failed}` + time-to-recovery ms)를 계측한다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/broker/resume.rs` (신규 — 토큰 발급/해시 저장/rotation/검증, TTL)
- `crates/qsh-core/src/server/mod.rs` (확장 — `SessionAttach` dispatch arm, 검사 순서)
- `crates/qsh-core/src/client/reconnect.rs` (신규 — 재dial 루프, rebind 시도, 미-ack input 재전송(64 KiB 상한, 초과 시 조용히 쌓지 않고 오류))
- `crates/qsh-core/src/config.rs` (확장 — `Paths::resume_file()`, 0600 쓰기는 기존 `write_private_file` 재사용)
- `crates/qsh-core/src/telemetry.rs` (신규 — recovery 결과/소요시간 기록. **stderr 구조화 진단만**: tracing target `qsh::recovery`, INFO, 한 줄 JSON, 필드 `recovery`/`time_to_recovery_ms`/`session_ref` — CLI.md §6.4, testing.md L4; stdout은 §2.2에 따라 계약 전용)
- `crates/qsh-core/Cargo.toml` (blake3, subtle 추가)

**(c) 빚지는 테스트:** L2 — 토큰 단회성(같은 토큰 2회 사용 → 두 번째 거부), 만료, 다른 peer fingerprint의 상환 시도 → non-distinguishing 오류, lease steal/`no_steal` 경합이 broker 단일 락 안에서 결정됨. L3 loopback — 연결을 끊고 새 연결로 attach하여 `last_seq`부터 이어붙인 바이트가 기준 stream과 byte-identical, ring 밖 요청 시 `Gap` 후 `available_from`부터 재개. 미-ack input 재전송이 중복 적용되지 않음.

**(d) 완료 판정:** 재dial→resume 경로가 loopback에서 결정적으로 green이고, `recovery`/time-to-recovery가 기록된다. resume 토큰이 로그·audit·JSON envelope 어디에도 나타나지 않음(audit 레코드 타입에 payload 필드 자체가 없음 — 기존 `record_has_only_structural_fields` 테스트로 유지).

**(e) 인용:** `docs/design/protocol.md` §2(migration은 지연 최적화, correctness는 resume), §10 전체(토큰·rotation·reattach 4단계·gap·input 무손실·writer lease), `docs/design/architecture.md` §3(writer lease 규칙 a/b/c, child 종료 후 `exited` 상태), §7(state 경로), §8(blake3/subtle/zeroize), `docs/CLI.md` §6.4(gap event 계약), `docs/PRD.md` §8(세션 모델), §9(resume credential은 session과 peer identity에 결합), §13(30분 단절 후에도 TTL 내 복구), `docs/design/testing.md` L4(recovery 텔레메트리를 M2부터 계측), `docs/ROADMAP.md` §4 일정 리스크 1번.

---

### Step 8 — Chaos proxy(L4) 하네스 + `repath()`/`sever()` 회귀 + SC4/SC5 마감

**(a) 범위:** `qsh-testkit`에 in-process UDP chaos proxy를 만든다 — `UdpSocket` 2개를 쥔 tokio task + seed 가능한 `ChaosPolicy`. 클라이언트가 proxy로 dial하고 proxy가 서버로 중계한다. fault: `drop(p)`, `delay(dist)`, `reorder`, `duplicate`, `corrupt(p)`(AEAD positive control), `blackhole(dur)` 후 복구, **`repath()`**(client 소켓을 새 포트로 rebind — NAT rebind/Wi-Fi→LTE가 서버에게 보이는 모습), **`sever()`**(client 소켓 완전 폐쇄 → 재dial + resume 강제). 실패 메시지에 seed 출력. 이 위에서 DoD 3·4번 항목을 마감한다: `yes` 실행 중 클라이언트 `kill -9` → reattach → `last_seq`부터의 결과가 기준 stream과 byte-identical(SC4), remote PTY와 자식 프로세스 생존(SC5), `repath()` → 세션 무중단(migration), `sever()` → 2초 내 재dial + resume. **통과 기준은 사전 정의대로** — idle timeout이 뒤늦게 터져 복구되는 것은 통과가 아니다. 세션 op fixture(append-only)와 exit-code matrix도 여기서 마감한다.

**(b) crate/모듈/파일:**
- `crates/qsh-testkit/src/chaos.rs` (신규 — proxy + `ChaosPolicy::seeded(u64)`, `repath()`, `sever()`)
- `crates/qsh-testkit/src/loopback.rs` (확장 — chaos proxy를 경유해 dial하는 harness 변형)
- `crates/qsh-testkit/tests/chaos_proxy.rs` (신규 — 하네스 자체의 회귀 게이트: 이미 존재하는 `exec.run`·세션 value op이 `drop`/`delay`/`reorder`/`duplicate` 아래에서 byte-identical, `corrupt()` positive control, `blackhole()` 복구, `repath()` → migration, `sever()` → 재dial. resume은 다루지 않는다)
- `crates/qsh-testkit/tests/chaos_relay.rs` (신규 — fault 자체의 negative control: QUIC 없이 순수 `UdpSocket` 사이에서 drop/delay/reorder/duplicate/blackhole이 **실제로 wire에 일어나는지** 직접 관찰. counter만 올리고 아무 일도 안 하는 fault는 여기서 잡힌다. multi-flow 중계·`sever_client`도 여기서 고정)
- `crates/qsh-testkit/tests/resume_chaos.rs` (신규 — Step 7의 resume/attach 시나리오를 위 하네스 위에 얹는다)
- `crates/qsh-testkit/tests/session_kill9.rs` (신규 — SC4/SC5: 클라이언트 프로세스 `kill -9`, 기준 stream 대조)
- `crates/qsh-cli/tests/fixtures/cli-v1/{session.open,session.get,session.list,session.read,session.write,session.resize,session.close}.json` (신규, append-only)
- `crates/qsh-cli/tests/exit_code_matrix.rs`, `tests/jsonl_purity.rs` (확장 — 세션 시나리오 행 추가)

**(c) 빚지는 테스트:** 위 파일들이 곧 테스트다. 추가로 L6 — 신규 fixture 전부가 schemars 생성 스키마를 통과하고 기존 fixture도 계속 유효(append-only CI job), `ErrorCode` 전수 도달성 재확인(M2가 새로 생성 가능해진 `SESSION_NOT_FOUND`/`SESSION_CONFLICT` 커버; `RESUME_GAP`은 event 전용이라 오류로 도달 불가 — CLI.md §3.3 — DEFERRED 사유를 갱신해 유지).

**(d) 완료 판정:** DoD 3·4번 항목 green. chaos 테스트는 seeded로 재현 가능하며 `sleep()`을 쓰지 않는다. 2초 재dial 기준이 assertion으로 코드에 박혀 있다(주석이 아니라).

> **DoD 4번은 Step 7과 함께 닫힌다.** `chaos_proxy.rs`의 `REDIAL_DEADLINE` assertion은 *시나리오*만 묶는다 — 클럭이 테스트가 고른 지점에서 시작하고, path 사망 감지도 resume도 아직 없다(감지기가 없으므로 M2 Step 8 단독으로는 더 잘 할 수 없다; quinn idle timeout은 45 s). 실제 기준(“path 사망 감지 후 2초 내 재dial + resume”)은 Step 7이 `resume_chaos.rs`에 심는다: 클럭을 `sever()` 직전에 시작하고, 옛 세션을 손으로 `close()`하지 않으며, `session.attach` 후 첫 replay 바이트에서 멈추고, 옛 연결이 idle timeout으로 닫히지 않았음을 함께 단언한다. recovery 텔레메트리(`recovery`/`time_to_recovery_ms`)는 Step 7 (b)의 `crates/qsh-core/src/telemetry.rs`가 소유한다 — Step 9 (c)의 “텔레메트리 필드 파싱은 Step 8의 chaos 테스트가 이미 커버한다”는 Step 8의 나머지 절반(`resume_chaos.rs`)을 가리키며, `chaos_proxy.rs`/`chaos_relay.rs`는 텔레메트리를 다루지 않는다.

**(e) 인용:** `docs/design/testing.md` L4 전체(설계·fault 표·대안 기각 근거·"chaos proxy는 PR 회귀 게이트이고 SC3 실측은 실기기 캠페인"·2초 기준), L6(fixture append-only, ErrorCode 전수 도달성, exit-code matrix, JSONL 순수성), CI 규율(port 0, seeded chaos, `sleep()` 금지), `docs/ROADMAP.md` M2 DoD 3·4번, 시퀀싱 원칙 6번("Chaos 하네스는 M2에서 resume과 함께 구축 … 측정 도구는 측정 대상과 같이 만든다"), `docs/PRD.md` §15 SC4·SC5.

---

### Step 9 — 실기기 Wi-Fi↔테더링 20회 수동 캠페인 + 기록 템플릿

**(a) 범위:** DoD 5번 항목 전용 step. macOS(`networksetup -setairportpower`)와 Linux(`nmcli`) 전환 보조 스크립트를 만들고, 실제 노트북 ↔ 실제 `qsh serve` 호스트 사이에서 대화형 세션을 유지한 채 Wi-Fi↔테더링을 **20회** 전환하며 매 회차의 `recovery ∈ {migrated, resumed, failed}`와 time-to-recovery를 기록한다. 산출물은 (i) 재실행 가능한 스크립트, (ii) 회차별 기록 템플릿(회차·플랫폼·전환 방향·recovery 분류·time-to-recovery ms·gap 발생 여부·비고)과 채워진 20행, (iii) migrated/resumed/failed 분해 요약. 이 캠페인은 **SC3의 조기 측정**이며 합격/불합격 게이트가 아니다 — 본 캠페인(N≥60, ≥95%)은 M8이다. 실패 사례는 마일스톤을 막지 않고 M8용 백로그 항목으로 남긴다.

**(b) crate/모듈/파일:**
- `scripts/mobility/switch-macos.sh`, `scripts/mobility/switch-linux.sh` (신규 — 전환 보조, root 불요 경로 우선)
- `docs/campaigns/m2-mobility.md` (신규 — 기록 템플릿 + 20행 결과 + 분해 요약. M8이 같은 템플릿을 N≥60으로 재사용한다. 새 문서이므로 `CLAUDE.md`의 document map에 한 줄 추가)
- `crates/qsh-core/src/telemetry.rs` (필요 시 확장 — 캠페인 기록에 필요한 최소 필드만)

**(c) 빚지는 테스트:** 자동화 테스트 없음(정의상 CI 불가). 대신 스크립트가 dry-run 모드에서 인터페이스를 건드리지 않고 동작함을 수동 확인하고, 텔레메트리 필드 파싱은 Step 8의 chaos 테스트가 이미 커버한다.

**(d) 완료 판정:** 20행이 채워진 기록 문서가 체크인되고, migrated/resumed/failed 분해와 time-to-recovery 분포가 요약돼 있다. idle timeout에 기대어 늦게 복구된 회차는 **failed로 분류**한다(사전 정의 기준).

**(e) 인용:** `docs/design/testing.md` L4("SC3용 실측: … 실기기 스크립트로 N≥60회 전환 시험 … 통과 기준은 사전 정의"), `docs/ROADMAP.md` M2 DoD 5번, M8 수용 기준(≥60회 본 캠페인 — 이 step의 산출물을 재사용), §4 일정 리스크 1번("M2 말 실기기 20회 조기 측정"), `docs/PRD.md` §15 SC3.

---

## 3. 명시적 non-goals (M3+ 유예)

`docs/ROADMAP.md` M2 절 "명시적 out" 인용: **reverse, 터널, ACL 정책 파일, multi-attach, local echo prediction.**

추가로 M2 범위에 넣지 않는 항목(같은 문서의 다른 조항에서 파생):

- **역방향(M3)** — `Hello.reverse`/`ReverseRegistration`, `host.reverse` action, `qsh listen`/`qsh reverse`. Step 1에서 `.proto` 번호만 `reserved`로 못 박고 메시지는 정의하지 않는다.
- **터널(M4)** — `-L`/`-R`/`tunnel.*`. `StreamKind::TCP_CONNECT`/`TCP_ACCEPTED`는 M1에 이미 enum 값만 존재하며 M2는 이를 수용하지 않는다(`handle_data_stream`에서 reset).
- **ACL 정책 엔진(M5)** — M2의 `Authorizer`는 여전히 `AllowAllPinned`이고, 이 step에서 추가하는 것은 `Action` variant와 호출 지점뿐이다.
- **Multi-attach observer 개념** — `docs/ROADMAP.md` §3 유예 가드레일: "**관찰자(observer) 개념 자체를 만들지 않는다.** writer lease는 P0 필수, 두 번째 attach 정책은 lease 규칙만 따름." 두 번째 attach는 steal 또는 `SESSION_CONFLICT`이며 read-only 관찰자 타입을 만들지 않는다.
- **Local echo prediction(P2)** — 대신 실제 PTY 지연을 측정·공개한다(PRD §13의 10ms 예산; perf 게이트 자체는 M4/M8).
- **Windows** — client P1 / host P2. PTY 코드는 `#![cfg(unix)]`, Windows CI 없음.
- **Encrypted disk spool** — ADR-0004에 따라 P1. `ReplayStore` trait 뒤 격리만 유지한다.
- **별도 supervisor 프로세스** — ADR-0003에 따라 P1. M2는 seam(`SessionBackend` + transport 타입 import 금지)만 순수하게 유지한다.
- **MCP adapter(M6)·`schema.get`/`doctor.run`/hosts.toml(M7)** — M2는 `read_session` long-poll이 Step 5의 cursor-pull primitive를 1:1로 소비할 수 있게 형태만 맞춰 두고 adapter는 만들지 않는다.

## 4. 리스크와 감시 항목

`docs/ROADMAP.md` §4 "일정 리스크 5건" 중 M2와 직결되는 항목:

> 1. **SC3(≥95% mobility)은 CI로 측정 불가능한 측정 문제이고, 통과 기준이 미정의면 그 자체가 리스크.** 대응: chaos proxy + recovery 텔레메트리를 M2에 구축, M2 말 실기기 20회 조기 측정, "idle timeout이 늦게 터져서 기술적으로 통과"를 배제하는 기준(재dial 2초)을 지금 명문화, M8에 ≥60회 본 캠페인.

→ **Step 7·8·9**에 매핑. 감시 지점: 2초 기준이 assertion으로 존재하는가, `recovery` 분류가 migrated/resumed/failed로 실제 분해되는가.

> 2. **PTY/터미널 정확성은 추정을 거부하는 long tail.** 대응: M2b를 명명된 수용 세트(bash/zsh+vim+tmux+claude)로 timebox, "terminal quirks" 백로그를 마일스톤 밖에 유지, expect 하네스를 초기에 구축해 수정마다 회귀 테스트가 싸게 남게.

→ **Step 4·6**. 수용 세트 밖의 터미널 이슈는 발견 즉시 백로그로 보내고 M2를 늘리지 않는다.

> 4. **In-listener 세션과 listener 재시작/업그레이드의 충돌은 구조적.** 대응: ADR-0003의 `SessionBackend` seam을 처음부터 순수하게 유지(CI로 transport import 금지 확인) …

→ **Step 2·3**. 현재 `xtask arch`는 **manifest 수준 검사**라 `qsh-core` 내부 모듈의 import를 보지 못한다 — Step 2에서 모듈 경로 기반 규칙을 추가하지 않으면 이 대응책은 "CI로 확인"이 아니라 구두 약속으로 남는다.

`docs/design/architecture.md` §9 리스크 중 M2가 직접 지는 항목:

> 1. **Resume/replay 정합성** — byte offset 경계·gap 계산·lease 경합 버그는 제품의 핵심 약속을 깬다.

→ **Step 2(oracle property test)·7(단절 지점 시뮬레이션)·8(fault 주입)**. resume 정확성은 fault 주입 없이는 검증 불가이므로 Step 8 이전에 "resume 완료" 선언을 하지 않는다.

> 5. **느린 소비자 backpressure vs PTY 생존성** — cursor-pull + 유계 구독자 버퍼 + gap 재동기화가 설계 답이지만 QUIC flow control과의 상호작용은 soak test로 실증해야 한다.

→ **Step 5**에서 "pty_reader가 네트워크·소비자에 절대 블록되지 않음"을 단언하고, 본 soak(24h/100세션)은 M8.

추가 감시 항목 — `docs/ROADMAP.md` §4 리스크 3번의 M2판: **macOS 미서명 바이너리의 Keychain 재프롬프트가 dev loop을 괴롭힌다.** M2는 재dial·재attach를 반복하는 마일스톤이라 프롬프트 빈도가 M1보다 훨씬 높다. 대응: 모든 자동 테스트와 chaos/expect 하네스는 `$QSH_CONFIG_DIR` 격리 프로필 + `key_store = "file"`로 고정하고, platform keystore 경로는 Step 4·6의 수동 확인에서만 쓴다.

### 4.1 미해결 질문 — 해소됨 (2026-08-18)

아래 9건은 문서 갱신으로 모두 확정되었다(CLI.md v0.5, PRD v0.5, ADR-0007). 구현은 괄호 안 정본을 따른다.

| # | 질문 | 결정 | 정본 |
|---|---|---|---|
| 1 | detach key | 행 시작 tilde escape: `~d`/`~.` detach(세션 유지), `~~` 리터럴, `~?` 도움말(stderr); 미지 `~x`는 둘 다 전달; TTY stdin에서만 활성; `--escape-char <c>\|none`(`qsh [user@]host`·`qsh attach` 전용) | CLI.md §7, §9, §4 |
| 2 | `user@` 시맨틱 | user switching 없음 — 원격 셸은 항상 serve 계정; `user@`는 `SessionOpen.user` hint이며 login name 불일치 시 `UNSUPPORTED`. 검사 순서 ACL → hint → spawn(미인가는 항상 `PERMISSION_DENIED`), login name은 `getpwuid` | CLI.md §7, PRD §6·§17, architecture.md §4, protocol.md §9 |
| 3 | `session_ref` 조립 | 클라이언트 `Ops`가 `<host-alias>/<session_id>` 조립·파싱(마지막 `/` 기준, `session_id`=ULID); wire `SessionInfo`에는 `session_ref`·`host` 없음 | ADR-0007, CLI.md §5, architecture.md §2, protocol.md §9 |
| 4 | `resume_token` 노출 | JSON 비노출; `resume.json`(0600, `session_ref` key, peer SPKI·`expires_at` 포함, flock+원자 교체)에만; 토큰이 필요한 op는 `session.attach`뿐(read/write 등은 ACL만); 토큰 없음/peer 불일치 → 로컬 `SESSION_NOT_FOUND`(`no_resume_token`/`peer_mismatch`) | ADR-0007, CLI.md §6.2·§6.3, PRD §6·§8, protocol.md §10 |
| 5 | `WriterChanged`/`Closed` event | `session.writer_changed{writer: principal\|null}`(broadcast), `session.closed{reason: closed\|exit\|ttl_expired}`(제거 주체 기준); ring 제어 엔트리로 전순서 전달; 미지 `type`/`reason` 무시; `--follow`는 `session.exit`에서 종료 | CLI.md §6.4·§10, architecture.md §2·§3, protocol.md §9 |
| 6 | `SessionSignal` | 별도 op 없음(P1); `session close --signal`은 `SessionClose.signal`(HUP\|INT\|QUIT\|TERM\|USR1\|USR2\|KILL, 그 외 `INVALID_ARGUMENT`); wire 25는 `reserved`(수신 시 `UNSUPPORTED`); `close_grace_ms` 5s, KILL 즉시, `exited`에는 무신호 | CLI.md §2.4·§6.7, protocol.md §9, architecture.md §4·§7 |
| 7 | recovery 텔레메트리 | stderr 전용 — tracing `qsh::recovery`, INFO, 한 줄 JSON(`recovery`/`time_to_recovery_ms`/`session_ref`); event 승격은 P1 | testing.md L4, CLI.md §6.4 |
| 8 | `localctl` 시점 | M2 아님 — **M3**(첫 소비자: 역방향 `qsh attach`의 UDS IPC, protocol.md §11-3); M2는 `SessionBackend` seam 순수성만 | ADR-0003 추기, architecture.md §3·§7 |
| 9 | raw-mode crate | `nix`(`term`/`ioctl`/`poll`/`signal`; host 측 `user`) 직접 termios + `TIOCGWINSZ`, SIGWINCH는 `tokio::signal::unix`; crossterm 기각; `cfg(unix)` target 의존 | architecture.md §8 |

## 5. 완료 절차

1. §1의 DoD 체크리스트 5항목 전건 통과를 실제 테스트 실행 로그(및 Step 9의 캠페인 기록)로 확인한다(체크박스는 근거가 green일 때만 표시).
2. `docs/ROADMAP.md`의 "현재 위치" 줄과 M2 절 상태 표기를 "M2 완료"로 갱신한다(로드맵 자체는 이 계획 문서가 아니라 로드맵 문서 소유자가 갱신 — PLAN.md는 이 절차를 지시만 하고 ROADMAP.md를 대신 수정하지 않는다).
3. 이 PLAN.md를 M3("역방향") 실행 계획으로 전면 교체한다 — 과거 M2 계획은 git 이력에만 남긴다.
