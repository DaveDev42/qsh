# QSH 아키텍처 설계

**상태:** 설계 확정 (2026-08-17)
**규칙:** 구현이 이 문서와 어긋나게 되는 변경은 문서를 먼저 갱신한 뒤 진행한다. 계약(JSON/MCP)은 [CLI.md](../CLI.md), wire 상세는 [protocol.md](protocol.md), 마일스톤별 범위·수용 기준은 [ROADMAP.md](../ROADMAP.md)가 각각 단일 출처다 — 이 문서는 그 내용을 중복하지 않는다.

## 1. Crate 그래프와 책임

```
qsh-cli (bin: qsh) ──► qsh-core ──► qsh-transport ──► qsh-proto
        └────────────────────────────────────────────► qsh-proto
qsh-testkit (테스트 하네스, 의존 무제한)
xtask (arch-lint — workspace 멤버, 위 매트릭스를 빌드 실패로 강제)
```

허용 의존은 `xtask/src/arch.rs`의 매트릭스가 정본이다: `qsh-proto` → 없음, `qsh-transport` → {qsh-proto}, `qsh-core` → {qsh-proto, qsh-transport}, `qsh-cli` → {qsh-core, qsh-proto}(계약 타입 직접 사용 목적), `qsh-testkit` → 무제한.

| Crate | 책임 | 금지 사항 |
|---|---|---|
| `qsh-proto` | 계약 계층: frame codec(`frame.rs`), `ErrorCode`(`error.rs`), JSON 계약 타입(`types.rs`), `qsh.event/v1` 이벤트(`event.rs`), prost wire 메시지(M1부터 `proto/qsh/wire/v1.proto`). sans-IO, async 없음 — fuzz 표면 | I/O, async, 상위 crate 의존 |
| `qsh-transport` | quinn/rustls glue: endpoint 구성, ALPN, `QshPeerVerifier`, keep-alive/rebind, `Transport` trait 구현 | 세션·ACL·비즈니스 로직 |
| `qsh-core` | 모든 비즈니스 로직: typed `Ops` façade, `server::dispatch`(ACL choke point), session broker, PTY, exec/tunnel, identity/trust/pairing, ACL/audit, config, doctor, localctl | 렌더링, 프로토콜 프레임 파싱(qsh-proto 위임) |
| `qsh-cli` | 패키지 `qsh-cli`, 바이너리 `qsh`. 얇은 frontend만: clap, human/JSON/JSONL 렌더러, interactive TUI, MCP adapter(M6) | 인증·ACL·세션 로직 일체 (CLI.md §11) |
| `qsh-testkit` | 통합 하네스, chaos proxy, fixture 도구 ([testing.md](testing.md)) | — |

**확장 기준 패턴:** 새 operation은 `crates/qsh-core/src/ops/mod.rs`의 기존 패턴을 따른다 — `Operation` trait(`COMMAND: &'static str` = dotted 이름, envelope·audit·ACL의 join key), `OpError { code: ErrorCode, message, retryable, details }`, `Ops` façade의 메서드 하나. `version.get`(`VersionOp`)이 살아 있는 예시다.

## 2. Typed operation layer

세 frontend(human/JSON/MCP)가 공유하는 유일한 API. CLI.md §11의 "renderer/adapter에 로직 금지"를 코드 구조로 강제한다.

- **Req/Data 타입 공유:** 각 op의 `*Req`/`*Data` 구조체는 `qsh-proto`에 두고 `Serialize + Deserialize + JsonSchema`(schemars)를 파생한다. clap은 플래그에서 `*Req`를 채우고, MCP는 tool input을 같은 타입으로 역직렬화하며(rmcp가 schemars로 tool schema 생성), JSON 렌더러는 `*Data`를 그대로 `envelope.data`에 넣는다.
- **Streaming op:** 값 반환 op와 달리 `session.attach`(및 `--follow`)는 typed event의 `Stream`(cursor-pull 기반, §3)을 반환한다. JSONL 렌더러는 이 stream을 한 줄씩 출력하고, MCP `read_session` long-poll은 동일 소스를 1회 pull로 소비한다.
- **오류 경로:** 모든 op는 `Result<*Data, OpError>`. `OpError.code`는 `qsh-proto`의 단일 `ErrorCode` enum(미지 코드 pass-through 포함)이며, exit code 매핑은 `qsh-cli`에만 존재한다: 성공 0 / clap 인자 오류 2 / `OpError` 255. `exec.run`은 remote exit `0..=254`를 그대로 프로세스 exit로 반환하되 **remote 255는 254로 clamp**하고 JSON `remote_exit_code`가 참값을 가진다 (CLI.md §4).
- **`session_ref`는 서버 발급 opaque 값**이다. frontend와 호출자는 조합·파싱하지 않고, `Ops`가 내부에서 (connection, session_id)로 해석한다.

## 3. Session broker

세션 수명을 transport 수명과 분리하는 핵심 서브시스템. `qsh serve` 프로세스 내부에 산다 ([ADR-0003](../adr/0003-sessions-in-listener.md)).

```
Broker
├── registry: SessionId → SessionHandle (단일 lock, 저경합)
├── TTL reaper task (30s tick; resume TTL 초과 세션을 SIGHUP→TERM→KILL로 정리)
└── SessionActor  ← 세션당 tokio task 하나
    ├── 소유: PTY master, child handle, ReplayRing, writer lease, output 알림
    ├── mpsc 인박스: Write / Resize / Signal / Pull / Subscribe / TakeLease / Close
    └── pty_reader task: PTY read → ReplayRing.push → 누적 offset 증가 → 구독자 알림
```

- **ReplayRing:** 세션당 8 MB(기본, 설정 가능) byte 예산의 chunk ring. `sequence`는 누적 output **byte offset**(CLI.md §2.3) — eviction은 whole-chunk 단위로 하되 gap 계산·replay 절단은 byte 단위로 정확하다. 서버는 chunk를 자유로이 분할·병합할 수 있으므로 `--after N` 재개는 항상 정확히 N에서 시작한다. 저장은 memory-only, `ReplayStore` trait 뒤에 격리 ([ADR-0004](../adr/0004-replay-buffer-memory-only.md)).
- **cursor-pull 단일 primitive:** `pull(session, after, max_bytes, wait)` 하나가 `session read --wait --json`(1회 pull), `session read --follow --jsonl`(pull 루프), MCP long-poll(동일 호출 1:1)을 전부 구동한다. 각 소비자는 ring 위의 cursor일 뿐이며, 느린 소비자의 cursor가 ring에서 밀려나면 `session.gap` 이벤트로 재동기화한다. **pty_reader는 절대 네트워크·소비자에 블록되지 않는다** — 세션당 메모리 상한은 ring + cursor 소량으로 유계다.
- **Writer lease:** 세션당 하나. (a) 대화형 attach는 기본 **steal** — 절전 후 같은 사람이 재접속하는 지배적 경우를 무마찰로 처리하고, 기존 보유자(살아 있다면)는 lease 회수 통지 후 read-only로 강등된다. (b) 프로그램적 write/attach는 타 principal이 살아 있는 lease를 쥐고 있으면 `SESSION_CONFLICT` — 명시적 `takeover: true`가 필요하다. (c) lease는 소유 connection이 죽으면 자동 해제되지만 **세션과 child process는 유지**된다. 읽기는 lease가 필요 없다.
- **Child 종료:** waitpid 관찰 → 종료 이벤트를 ring에 기록 → 세션은 `exited` 상태로 남아 늦게 온 reader도 `session.exit` 이벤트를 수신한 뒤 TTL로 정리된다.
- **Supervisor seam:** broker는 `SessionBackend` trait(open/attach/pull/write/resize/close/list) 뒤에 있고 transport 타입을 import하지 않는다. per-process UDS 제어 소켓 계층(`localctl`, M2에서 broker와 함께 도입 — `$XDG_RUNTIME_DIR/qsh/<pid>.sock`, 동일 frame layer)이 `qsh tunnels` 류의 프로세스 간 조회를 담당하며, P1에서 별도 supervisor 프로세스가 같은 trait를 UDS 너머로 제공하면 drop-in 교체된다.

## 4. PTY

- **crate:** `portable-pty` 0.9 — macOS+Linux에서 검증된 spawn/resize(TIOCSWINSZ)/controlling-terminal 처리, Windows host(P2)로의 문 유지. 동기 I/O이므로 master fd를 `tokio::io::unix::AsyncFd`로 감싼다.
- child는 `setsid` + controlling tty를 가진 process group leader로 spawn한다. `session close --signal`과 세션 정리는 leader가 아니라 **process group 전체에 `killpg`** 한다.
- login shell 환경(`TERM`, `SHELL`, `$HOME`, macOS path_helper)을 구성하고, utmp/wtmp는 MVP에서 기록하지 않는다. 플랫폼별 EOF/버퍼 quirk와 테스트 요구는 [testing.md](testing.md) 참조.

## 5. Identity와 trust

- **`qsh init`:** Ed25519 키쌍 생성 → `rcgen`으로 장기(10y) self-signed X.509 device cert 발급. fingerprint는 SPKI SHA-256, 표기는 `sha256:BASE64`. 공개 cert는 `identity/device.pem`.
- **개인키 저장 3-mode** (`identity.key_store = auto | platform | file`): `platform`은 keyring 3.x(macOS Keychain / Linux Secret Service). headless Linux는 Secret Service가 없으므로 `auto`가 `identity/device.key`(0600, 디렉터리 0700 — sshd host key와 같은 태세)로 fallback하고, `qsh init`과 `qsh doctor`가 **어느 저장소가 실제 사용 중인지 명시 보고**한다. 키 바이트는 메모리에서 `zeroize::Zeroizing`으로 감싸고 절대 로그에 남기지 않는다.
- **Trust store** (`trust.toml`): pinned peer(이름+fingerprint)와 private CA 두 종류. 검증 로직(`QshPeerVerifier`: pin 일치 → 허용, CA 체인 → 허용, 그 외 거부, web PKI 절대 미적재)은 `qsh-transport`에 살되 신뢰 평가는 `qsh-core::trust`가 `TrustEvaluator` trait로 주입한다. 검증 결과는 connection에 부착되는 `Principal`(`fp:…` / `user:…` / `device:…`) 하나로 환원되며 — principal은 **항상 인증서에서만** 나오고 Hello 등 wire 필드에서 나오지 않는다.
- **Pairing:** 기본 UX는 일회용 invite code(10분 TTL) + TLS exporter 기반 channel binding으로 양방향 pin을 한 번에 설정, fingerprint 방식은 스크립트/프로비저닝용 일급 fallback — 프로토콜 상세와 근거는 [ADR-0002](../adr/0002-pairing-invite-code.md).

## 6. ACL 엔진과 audit

- 정책은 `acl.toml`(PRD §9 형태). principal은 정확 일치(연결의 `Principal`과 대조), action은 정확 일치 또는 **trailing `.*` wildcard만** 허용한다(중간 glob 금지 — 평가와 `qsh acl check` 설명 가능성 유지).
- **Default deny, fail closed:** 매칭 allow 없음 → `PERMISSION_DENIED`; acl.toml이 없거나 파싱 불가 → 전부 deny + 운영자에게 `CONFIG_ERROR` 노출. "오류 시 개방"은 존재하지 않는다.
- **단일 choke point:** 호스트 측 `server::dispatch`가 디코딩된 모든 요청에 대해 `Authorizer::check(principal, action, resource)`를 **리소스 생성(PTY spawn/exec fork/socket bind/ticket 발급) 이전에** 호출한다. 클라이언트 측 코드와 렌더러에는 ACL 로직이 0이며, MCP는 같은 dispatch를 타므로 자동 상속된다. op → 필요 ACL action 매핑은 CLI.md의 매핑 표가 정본이다.
- **Audit:** 결정당 한 줄 JSONL(`$XDG_STATE_HOME/qsh/audit.log`) — ts, request_id, principal, action, resource, decision, rule index, peer_addr. 레코드 타입에 argv·PTY 내용·키를 담을 **필드 자체가 없어** "내용 무기록"이 규율이 아니라 타입 수준 속성이다(opt-in `audit.log_argv`만 예외).

## 7. Config·state·runtime 경로

macOS/Linux 동일 (ssh 스타일 예측 가능성; `~/Library/…` 미사용):

```
~/.config/qsh/            # $QSH_CONFIG_DIR → $XDG_CONFIG_HOME/qsh → 이 경로
├── config.toml           # [serve] bind·replay_bytes·resume_ttl / [identity] key_store / [audit]
├── hosts.toml            # [[host]] name·address·user  → host.list (M7 도입; 그 전까지 host 해석은 trust.toml의 pinned peer가 단일 출처)
├── trust.toml            # pinned peers + CAs
├── acl.toml              # serve/listen 역할만 읽음
└── identity/             # device.pem (+ file-mode일 때 device.key 0600)
~/.local/state/qsh/       # $XDG_STATE_HOME: audit.log, resume 토큰 상태(0600)
$XDG_RUNTIME_DIR/qsh/     # (없으면 state 하위 run/, 0700) per-process UDS: <pid>.sock
```

## 8. Crate 선정 (버전은 lock 시점 재확인)

| Crate | 버전 | 근거 |
|---|---|---|
| quinn | 0.11.x, **≥ 0.11.14** | 원격 DoS 수정 포함. per-stream priority + fair queuing, `Endpoint::rebind()` migration |
| rustls | 0.23 (aws-lc-rs) | 커스텀 `danger` verifier trait로 pin+CA 이중 모드 구현 |
| rcgen | 0.14 | 디바이스 cert / private CA 발급 |
| prost / prost-build | 0.14 | control 메시지 직렬화 — unknown-field 무시 네이티브, `.proto`가 리뷰·fuzz 문법 ([ADR-0001](../adr/0001-custom-quic-protocol.md)) |
| tokio | 1.x | 런타임 |
| portable-pty | 0.9 | §4 |
| keyring | **3.x 고정** | 4.0은 beta이며 내장 store 제거 — 회피 |
| rmcp | 3.x **정확히 pin** | 공식 Rust MCP SDK, 연내 0.14→3.x로 API 격변 — minor까지 고정, adapter는 ~300줄로 격리 |
| schemars | rmcp 요구 버전 (1.x) | `*Req`에서 tool schema 생성 |
| blake3 / subtle / zeroize | 1 / 2 / 1 | resume token 해시 / 상수시간 비교 / 키 위생 |
| clap 4.5 · serde 1 · tracing 0.1 · toml 0.8 · ulid 1 · bytes 1 · base64 0.22 | | M0에 이미 고정된 것 포함, frontend·계약·진단 |

## 9. 아키텍처 리스크 5건

1. **Resume/replay 정합성** — byte offset 경계·gap 계산·lease 경합 버그는 제품의 핵심 약속을 깬다. 대응: ReplayRing property test(oracle 대조), 단절 지점 전수 시뮬레이션, sans-IO 상태 기계 fuzz ([testing.md](testing.md)).
2. **In-listener 세션 vs listener 재시작** — seam(`SessionBackend`+UDS)이 오염되면 supervisor 전환이 재작성이 된다. 대응: broker의 transport 타입 import 금지를 유지(arch-lint 확장 후보), 제한은 README에 명시.
3. **Headless Linux 키 저장** — platform store 부재 시 file fallback이 조용히 일어나면 보안 태세 공백. 대응: init/doctor의 명시 보고를 계약으로 유지.
4. **rmcp API 변동** — 정확 pin + adapter 격리(≤300줄, `Ops` 직접 호출)로 폭발 반경 제한.
5. **느린 소비자 backpressure vs PTY 생존성** — cursor-pull + 유계 구독자 버퍼 + gap 재동기화가 설계 답이지만 QUIC flow control과의 상호작용은 soak test로 실증해야 한다 (testing.md의 frozen-consumer soak).
