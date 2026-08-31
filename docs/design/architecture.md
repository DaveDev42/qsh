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
| `qsh-proto` | 계약 계층: frame codec(`frame.rs`), `ErrorCode`(`error.rs`), JSON 계약 타입(`types.rs` — `Tunnel`/`TunnelOpenReq`/…, M4부터), `qsh.event/v1` 이벤트(`event.rs`), prost wire 메시지(M1부터 `proto/qsh/wire/v1.proto`, M4부터 `RemoteForwardOpen`/`Opened`/`Close`·`ConnectResult`), forward-spec 파서(`wire.rs::parse_forward_spec`, M4부터). sans-IO, async 없음 — fuzz 표면 | I/O, async, 상위 crate 의존 |
| `qsh-transport` | quinn/rustls glue: endpoint 구성, ALPN, `QshPeerVerifier`, keep-alive/rebind, `Transport` trait 구현 | 세션·ACL·비즈니스 로직 |
| `qsh-core` | 모든 비즈니스 로직: typed `Ops` façade, `server::dispatch`(ACL choke point), session broker, PTY, exec/tunnel(`tunnel/` 모듈, §3), identity/trust/pairing, ACL/audit, config, doctor, localctl | 렌더링, 프로토콜 프레임 파싱(qsh-proto 위임) |
| `qsh-cli` | 패키지 `qsh-cli`, 바이너리 `qsh`. 얇은 frontend만: clap, human/JSON/JSONL 렌더러, interactive TUI, MCP adapter(M6) | 인증·ACL·세션 로직 일체 (CLI.md §11) |
| `qsh-testkit` | 통합 하네스, chaos proxy, fixture 도구 ([testing.md](testing.md)) | — |

**확장 기준 패턴:** 새 operation은 `crates/qsh-core/src/ops/mod.rs`의 기존 패턴을 따른다 — `Operation` trait(`COMMAND: &'static str` = dotted 이름, envelope·audit·ACL의 join key), `OpError { code: ErrorCode, message, retryable, details }`, `Ops` façade의 메서드 하나. `version.get`(`VersionOp`)이 살아 있는 예시다.

## 2. Typed operation layer

세 frontend(human/JSON/MCP)가 공유하는 유일한 API. CLI.md §11의 "renderer/adapter에 로직 금지"를 코드 구조로 강제한다.

- **Req/Data 타입 공유:** 각 op의 `*Req`/`*Data` 구조체는 `qsh-proto`에 두고 `Serialize + Deserialize + JsonSchema`(schemars)를 파생한다. clap은 플래그에서 `*Req`를 채우고, MCP는 tool input을 같은 타입으로 역직렬화하며(rmcp가 schemars로 tool schema 생성), JSON 렌더러는 `*Data`를 그대로 `envelope.data`에 넣는다.
- **Streaming op:** 값 반환 op와 달리 `session.attach`(및 `--follow`)는 typed event의 `Stream`(cursor-pull 기반, §3)을 반환한다. JSONL 렌더러는 이 stream을 한 줄씩 출력하고, MCP `read_session` long-poll은 동일 소스를 1회 pull로 소비한다. wire 수준에서 `--follow`는 control 스트림 `SessionRead`(protocol.md §9) pull 루프이며 attach(`SessionAttach` + data 스트림, resume token 필요)가 아니다 — 토큰이 필요한 op는 `session.attach`뿐이다(CLI.md §6.3).
- **Event 타입의 전방 호환:** `qsh-proto`의 `SessionEvent`(qsh.event/v1)는 알 수 없는 `type`을 오류 없이 받아넘기는 fallback variant(`Unknown(serde_json::Value)` 등, `#[serde(untagged)]` 계열)를 갖고, `session.closed.reason`·`Session.state`처럼 값 집합이 열린 field는 enum이 아니라 open string으로 모델링한다(CLI.md §6.4·§10). `Session.writer`는 `Option<String>`(principal 문자열, lease 없으면 `None`).
- **오류 경로:** 모든 op는 `Result<*Data, OpError>`. `OpError.code`는 `qsh-proto`의 단일 `ErrorCode` enum(미지 코드 pass-through 포함)이며, exit code 매핑은 `qsh-cli`에만 존재한다: 성공 0 / clap 인자 오류 2 / `OpError` 255. `exec.run`은 remote exit `0..=254`를 그대로 프로세스 exit로 반환하되 **remote 255는 254로 clamp**하고 JSON `remote_exit_code`가 참값을 가진다 (CLI.md §4).
- **`session_ref`는 클라이언트 `Ops`가 조립하는 opaque 값**이다 ([ADR-0007](../adr/0007-session-ref-and-resume-token-custody.md)). 서버는 opaque·URL-safe한 `session_id`만 발급한다(자기 로컬 alias를 모른다); `Ops`가 `<host-alias>/<session_id>`로 조립해 반환하고, 입력으로 받은 `session_ref`를 (host → connection, session_id)로 해석한다. frontend와 호출자는 조합·파싱하지 않는다(CLI.md §5). wire의 `SessionInfo`(proto: `session_id/state/writer/created_at/last_sequence`)와 JSON DTO `qsh_proto::types::Session`(여기에 `session_ref`·`host` 추가)은 별개 타입이며 `Ops`가 변환한다. resume token도 같은 계층이 소유한다: `$XDG_STATE_HOME/qsh/resume.json`(0600)에 `session_ref` → 항목으로 저장·rotation하고 attach 시 내부에서 제시하며 어떤 `*Data`에도 싣지 않는다(CLI.md §6.3; 항목 형태·원자적 쓰기·프로세스 간 락·정리 규칙은 ADR-0007 결과 절). `session_ref` 문법·파싱 규칙(마지막 `/` 기준, `session_id`는 ULID)도 ADR-0007이 정본이다.

## 3. Session broker

세션 수명을 transport 수명과 분리하는 핵심 서브시스템. `qsh serve` 프로세스 내부에 산다 ([ADR-0003](../adr/0003-sessions-in-listener.md)).

```
Broker
├── registry: SessionId → SessionHandle (단일 lock, 저경합)
├── TTL reaper task (30s tick; resume TTL 초과 세션을 SIGHUP→TERM→KILL로 정리)
└── SessionActor  ← 세션당 tokio task 하나
    ├── 소유: PTY master, child handle, ReplayRing, writer lease, output 알림
    ├── mpsc 인박스: Write / Resize / Signal / TakeLease / ReleaseConnection / Close
    ├── input writer task: 유계 큐 → PTY write (child가 입력을 안 읽어도 actor·pump는 안 막힘; 큐 가득 차면 RESOURCE_EXHAUSTED)
    └── pty_reader task: PTY read → ReplayRing.push → 누적 offset 증가 → 구독자 알림
```

> **구현 주석(M2 Step 2):** `Pull`/`Subscribe`는 인박스 메시지가 아니다 — 읽기는 actor를 거치지 않고 `SessionHandle::pull`이 ring(mutex) 위 cursor를 직접 읽는다. 그래야 소비자가 pty_reader와 actor 어느 쪽도 블록하지 못한다. 세션당 task는 actor·pty_reader·input writer 셋이며, `Close`는 actor가 CLI.md §6.7 escalation(첫 신호 → `close_grace_ms` → TERM → KILL → 강제 정리)을 주입된 clock 위에서 구동하고 child 종료·output drain 후 `session.closed`를 마지막 엔트리로 append한다. `session.closed`가 append된 세션은 `get`/`list`/`write`/`close`에는 즉시 `SESSION_NOT_FOUND`지만 `pull`에는 짧은 보존창(`CLOSED_RETENTION`, 60s) 동안 남아 진행 중이던 follower가 마지막 event를 받아 갈 수 있다.

- **ReplayRing:** 세션당 8 MB(기본, 설정 가능) byte 예산의 chunk ring. `sequence`는 누적 output **byte offset**(CLI.md §2.3) — eviction은 whole-chunk 단위로 하되 gap 계산·replay 절단은 byte 단위로 정확하다. 서버는 chunk를 자유로이 분할·병합할 수 있으므로 `--after N` 재개는 항상 정확히 N에서 시작한다. 저장은 memory-only, `ReplayStore` trait 뒤에 격리 ([ADR-0004](../adr/0004-replay-buffer-memory-only.md)).
- **cursor-pull 단일 primitive:** `pull(session, after, max_bytes, wait)` 하나가 `session read --wait --json`(1회 pull), `session read --follow --jsonl`(pull 루프), MCP long-poll(동일 호출 1:1)을 전부 구동한다. 각 소비자는 ring 위의 cursor일 뿐이며, 느린 소비자의 cursor가 ring에서 밀려나면 `session.gap` 이벤트로 재동기화한다. **pty_reader는 절대 네트워크·소비자에 블록되지 않는다** — 세션당 메모리 상한은 ring + cursor 소량으로 유계다.
- **Writer lease:** 세션당 하나. (a) 대화형 attach는 기본 **steal** — 절전 후 같은 사람이 재접속하는 지배적 경우를 무마찰로 처리하고, 기존 보유자(살아 있다면)는 lease 회수 통지 후 read-only로 강등된다. (b) 프로그램적 write/attach는 타 principal이 살아 있는 lease를 쥐고 있으면 `SESSION_CONFLICT` — 명시적 `takeover: true`가 필요하다. **`session.write`는 이 규칙을 `no_steal: true` 고정으로 무조건 적용한다** — ACL이 그 호출자를 통과시켰는지와 무관하게, 그 시점에 lease를 쥔 principal이 자신과 다르면 항상 `SESSION_CONFLICT`다(`Server::prepare_session_write`). `scope = "owned"` 기본값(M3 P0 재현) 아래서는 `session.control`의 opener 결합(CLI.md §6.3, M3 Step 3.5 PR②)이 이보다 먼저 걸려 이 지점에 도달하는 호출자를 이미 opener principal 하나로 좁혀 두므로, 실제로 `타 principal`이 살아 있는 lease를 쥔 채 이 지점에 도달하는 경로는 없다 — opener만 도달하고 그 lease의 보유자도 (attach가 여는 resume credential이 같은 이유로 opener에 묶여 있으므로) 항상 opener 자신이기 때문이다. `scope = "any"`를 명시적으로 부여하면(M5 Step 5) 이 좁힘이 풀려 타 principal도 `session.write`의 ACL 게이트를 통과할 수 있게 된다. 그 타 principal이 **살아 있는 lease**에 도달하면(즉 누군가 이미 write/attach로 lease를 쥔 뒤라면) `no_steal: true` 고정 때문에 여전히 `SESSION_CONFLICT`로 막힌다 — `scope`는 ACL 어휘일 뿐 writer lease 어휘를 우회하지 않는다(두 게이트는 독립이고, 후자가 방어선을 재확인한다). 다만 이 방어선은 **lease가 이미 살아 있을 때만** 작동한다(F3, M5 Step 5 adversarial review) — `session.open` 직후 lease는 비어 있고(`WriterLease::new()`, 아직 아무도 attach/write하지 않았다), `no_steal`은 살아 있는 *타 principal* 보유자에게만 걸리므로(`lease.rs`의 `no_steal_conflicts_with_a_live_holder_of_another_principal`), 빈 lease에 대해서는 `scope = "any"`로 도달한 타 principal도 그냥 첫 취득자가 될 뿐이다 — 세션의 opener가 아직 한 번도 쓰지 않은 채로 타 principal이 먼저 `session.write`를 보내면 그 타 principal이 lease를 가져가고, 그 뒤에는 오히려 **opener 자신의** write가 `SESSION_CONFLICT`를 맞는다. 이 잔여 창(residual window)은 문서화된 트레이드오프이지 버그가 아니다 — `scope`는 누가 lease에 *도달할 수 있는지*만 정할 뿐 빈 lease를 향한 경쟁의 승자를 정하지 않는다(`session_write_scope_any_lets_a_foreign_first_writer_take_the_free_lease`, `crates/qsh-testkit/tests/session_loopback.rs`). `SESSION_CONFLICT`는 `takeover: true` 없는 명시적 attach 등 이 lease 규칙의 다른 소비자에는 여전히 유효하다. (c) lease는 소유 connection이 죽으면 자동 해제되지만 **세션과 child process는 유지**된다. 읽기는 lease가 필요 없다.
- **Child 종료:** waitpid 관찰 → 종료 이벤트를 ring에 기록 → 세션은 `exited` 상태로 남아 늦게 온 reader도 `session.exit` 이벤트를 수신한 뒤 TTL(같은 `[serve].resume_ttl`, exit 시점 기준)로 정리된다(`session.closed{reason:"exit"}`).
- **제어 event의 전달:** `session.exit`/`session.writer_changed`/`session.closed`는 ring에 **zero-length 제어 엔트리**로 append되어 `pull()`이 output과 전순서로 섞어 반환한다(`sequence` = append 시점 offset, offset 증가 없음) — 단발 pull·`--follow`·MCP long-poll이 모두 같은 순서를 본다. attach 중인 connection에는 같은 event를 control 스트림 `SessionEvent`로도 보낸다. `writer_changed`는 모든 read 소비자에게 broadcast된다(CLI.md §6.4).
- **Supervisor seam:** broker는 `SessionBackend` trait(open/attach/pull/write/resize/close/list) 뒤에 있고 transport 타입을 import하지 않는다. per-process UDS 제어 소켓 계층(`localctl` — `$XDG_RUNTIME_DIR/qsh/<pid>.sock`, 동일 frame layer)이 `qsh tunnels` 류의 프로세스 간 조회를 담당하며, P1에서 별도 supervisor 프로세스가 같은 trait를 UDS 너머로 제공하면 drop-in 교체된다. **`localctl`은 M2가 아니라 첫 소비자가 있는 M3(역방향)에서 도입한다** — M3의 첫 소비자는 **2종**이다: controller의 `qsh hosts`가 상주 `qsh listen` 데몬의 live 역방향 등록을 `LOCAL_ADMIN` conduit(`LocalHostList`)로 조회하는 경로와, `qsh <name>`(신규 세션)/`qsh attach <name>/<session_id>`(재attach)가 `LOCAL_CONTROL` conduit로 데몬이 쥔 역방향 연결 위에 `SessionOpen`/`SessionAttach`를 보내는 경로(protocol.md §11-3)다. `qsh tunnels`(M4)는 그 다음 소비자다. M2에서는 소비자 없는 IPC 계층을 깔지 않고 `SessionBackend` seam의 순수성(transport import 0)만 지킨다 ([ADR-0003](../adr/0003-sessions-in-listener.md) 결과 절 2026-08-18 추기).

- **터널 로직의 위치 (M4):** `qsh tunnels`가 실제로 소비하는 코드는 새 `crates/qsh-core/src/tunnel/` 모듈에 산다 — session broker와 나란히 있는 별도 서브시스템이며 broker의 `SessionBackend` seam을 재사용하지 않는다(터널은 broker가 관리하는 재개형 리소스가 아니라 CLI 프로세스 수명에 결합된 리소스, CLI.md §6.14). 하위 구성은 `local`(local forward: 로컬 TCP listener → host에 `TCP_CONNECT` 요청 → `ConnectResult` 수신), `remote`(remote forward: host 쪽 loopback bind → `TCP_ACCEPTED` accept → controller/opener에 relay), `splice`(두 방향 공통의 raw byte pump, `tokio::io::copy_bidirectional` 계열 — protocol.md §12의 우선순위 band `tunnel/file: 0`과 `send_fairness(true)` 아래에서 돈다)로 나뉜다. M4 Step 1(contract layer)은 이 모듈이 소비할 wire/JSON 계약(`qsh-proto`)만 확정했고, listener/dial/splice 자체의 구현은 이후 Step 2–7이 마쳤다 — forward/reverse 양쪽 route의 `-L`/`-R`, `qsh tunnel open/close`·`qsh tunnels`, `forward_id`→conduit 등록표(protocol.md §11-3), 우선순위 band와 window/depth-cap 튜닝(protocol.md §12)까지 M4 종료 시점 기준 전부 구현·테스트됐다(`docs/ROADMAP.md` M4 DoD).

## 4. PTY

- **crate:** `portable-pty` 0.9 — macOS+Linux에서 검증된 spawn/resize(TIOCSWINSZ)/controlling-terminal 처리, Windows host(P2)로의 문 유지. 동기 I/O이므로 master fd를 `tokio::io::unix::AsyncFd`로 감싼다.
- child는 항상 **`qsh serve`를 실행한 OS 계정**으로 spawn한다 — MVP에 user switching은 없고, `SessionOpen`의 `user` hint가 serve 계정의 login name과 다르면 spawn 없이 `UNSUPPORTED`다(CLI.md §7, PRD §6). 검사 순서는 **`Authorizer::check(session.open)` → `user` hint → spawn**이다: ACL 거부는 hint 값과 무관하게 `PERMISSION_DENIED`로 audit되고, hint 검증은 인가 통과 후에만 수행된다(미인가 peer에게 계정명 oracle을 주지 않는다 — protocol.md §10 step 2와 같은 규율). login name은 `getpwuid_r(geteuid()).pw_name`(`libc` 직접 호출, 프로세스 수명 동안 1회 조회 후 캐시)으로 얻고 `$USER`/`$LOGNAME` 환경변수는 쓰지 않는다(서비스 매니저 아래에서 비어 있거나 틀릴 수 있다). hint 불일치는 `io::ErrorKind::Unsupported` → `BrokerError::Unsupported` → `UNSUPPORTED`(message `user switching is not supported`)로 흐르며 spawn 실패(`INTERNAL`)와 구분된다. child는 `setsid` + controlling tty를 가진 process group leader로 spawn한다. `session close --signal`과 세션 정리는 leader가 아니라 **process group 전체에 `killpg`** 한다. escalation 단계별 유예는 `[serve].close_grace_ms`(기본 5000); 허용 신호·`KILL`의 즉시 정리·`exited` 세션에는 신호를 보내지 않는 규칙은 CLI.md §6.7.
- login shell 환경: child는 `qsh serve` 프로세스 환경을 **상속하지 않는다**(`env_clear`). 구성은 (1) `HOME`/`USER`/`LOGNAME` = passwd, `SHELL` = passwd shell(실행 불가면 `/bin/sh`), `PATH` = 플랫폼 baseline(macOS `/usr/bin:/bin:/usr/sbin:/sbin` — `/etc/zprofile`/`/etc/profile`의 `path_helper`가 확장; 그 외 unix는 OpenSSH 기본 `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`), `TERM` = `SessionOpen.term`(없으면 `xterm-256color`); (2) serve 프로세스에서 **locale/timezone만 pass-through**(`LANG`, `LANGUAGE`, `TZ`, `LC_*`); (3) client `SessionOpen.env` overlay; (4) **pinned key 재적용** — `HOME`/`USER`/`LOGNAME`/`SHELL`/`PATH`는 client가 덮어쓸 수 없다(`PATH`는 `argv[0]` 해석을 결정하므로 client 통제 시 M5 정책의 command 매칭이 우회된다). 빈 `argv`는 login shell(`argv[0] = "-<basename>"`, cwd = `$HOME`)이고, 비어 있지 않은 `argv`는 shell 없이 baseline `PATH`에서 직접 exec된다. **Step 6 TUI 계약:** `TERM`은 `SessionSpec.term`으로, locale은 `SessionSpec.env`(`LANG`/`LC_*`)로 보낸다. utmp/wtmp/lastlog는 MVP에서 기록하지 않는다. `session.open`/`session.resize`의 `cols`/`rows` `0`은 80×24로 정규화한다. 플랫폼별 EOF/버퍼 quirk와 테스트 요구는 [testing.md](testing.md) 참조.
- 알려진 upstream 위험(수용, M9 soak 감시 항목): portable-pty의 `pre_exec`는 `/dev/fd`를 읽어 fd ≥ 3을 닫는데 이는 `fork`와 `exec` 사이의 heap 할당이다 — 멀티스레드 `qsh serve`에서 child가 allocator lock에 걸리면 "열리긴 했으나 출력이 영원히 없는 세션"으로 나타날 수 있다. 같은 sweep이 std의 CLOEXEC exec-status pipe도 닫으므로 `exec` 실패는 spawn 성공 + 즉시 exit로 보인다. `PtySource::spawn`은 동기(`openpty` + `fork`/`exec`, ms 단위)이며 호출 task 위에서 돈다 — passwd 조회는 캐시된다.

## 5. Identity와 trust

- **`qsh init`:** Ed25519 키쌍 생성 → `rcgen`으로 장기(10y) self-signed X.509 device cert 발급. fingerprint는 SPKI SHA-256, 표기는 `sha256:BASE64`. 공개 cert는 `identity/device.pem`.
- **개인키 저장 3-mode** (`identity.key_store = auto | platform | file`): `platform`은 keyring 3.x(macOS Keychain / Linux Secret Service). headless Linux는 Secret Service가 없으므로 `auto`가 `identity/device.key`(0600, 디렉터리 0700 — sshd host key와 같은 태세)로 fallback하고, `qsh init`과 `qsh doctor`가 **어느 저장소가 실제 사용 중인지 명시 보고**한다. 키 바이트는 메모리에서 `zeroize::Zeroizing`으로 감싸고 절대 로그에 남기지 않는다. resume token(ADR-0007)도 같은 위생을 적용한다: `Zeroizing<[u8; 32]>`로 다루고, 토큰을 담는 타입(`SessionOpened`/`SessionAttached` 래퍼, `resume.json` 항목)은 `Debug`를 수동 구현해 `<redacted>`로 렌더하며, control message 전문을 `?msg`로 로깅하는 것은 어떤 verbosity에서도 금지한다.
- **Trust store** (`trust.toml`): pinned peer(이름+fingerprint)와 private CA 두 종류. 검증 로직(`QshPeerVerifier`: pin 일치 → 허용, CA 체인 → 허용, 그 외 거부, web PKI 절대 미적재)은 `qsh-transport`에 살되 신뢰 평가는 `qsh-core::trust`가 `TrustEvaluator` trait로 주입한다. 검증 결과는 connection에 부착되는 `Principal`(`fp:…` / `user:…` / `device:…`) 하나로 환원되며 — principal은 **항상 인증서에서만** 나오고 Hello 등 wire 필드에서 나오지 않는다.
- **Pairing:** 기본 UX는 일회용 invite code(10분 TTL) + TLS exporter 기반 channel binding으로 양방향 pin을 한 번에 설정, fingerprint 방식은 스크립트/프로비저닝용 일급 fallback — 프로토콜 상세와 근거는 [ADR-0002](../adr/0002-pairing-invite-code.md).

## 6. ACL 엔진과 audit

- 정책은 `acl.toml`(PRD §9 형태, `[[acl]] principal · auth_path? · allow · scope?` — 문법 정본은 `PLAN.md` M5 Step 1). action 어휘는 PRD §9의 닫힌 11종(`qsh_core::acl::Action::ALL`)이며, 그중 `forward.socks`·`file.read`·`file.write`는 **정의는 되어 있으나 항상 deny**다(`docs/ROADMAP.md` §3 유예 가드레일 표, `Action::is_always_denied`). principal은 정확 일치(연결의 `Principal`과 대조), action은 정확 일치 또는 **trailing `.*` wildcard만** 허용한다(중간 glob 금지 — 평가와 `qsh acl check` 설명 가능성 유지).
- **평가 순서(정본):** ① 항상-deny action 게이트(`Action::is_always_denied`) — **wildcard 매칭보다 먼저** 적용된다, 그렇지 않으면 `allow = ["forward.*"]`가 `forward.socks`까지 삼킨다. ② principal 정확 일치 + `auth_path` 일치. ③ action 패턴 매칭(정확 일치 또는 trailing `.*`). ④ `scope` 판정(소유자 개념이 있는 action에만 적용). 이 중 하나라도 매칭에 실패하면 다음 rule로 넘어가고, 끝까지 아무 rule도 매칭하지 않으면 **Deny**다. rule은 **첫 매칭이 이긴다**(allow-only 문법이므로 순서 의존 충돌은 존재하지 않는다) — 매칭된 rule의 배열 index가 `AuditRecord.rule`과 `acl check`의 `rule`이 된다.
- **`auth_path` 키:** 정책 행이 pin 경로로 인증한 peer에만 적용되는지 CA 경로도 포함하는지(`"pin"` | `"ca"`). 생략 시 `"pin"`(`PLAN.md` M5 §4.1 #2) — `Principal` 모양만으로는 pin/CA를 구별할 수 없고(CA 발급 leaf도 `qsh://device/…` SAN으로 `Device` principal을 낼 수 있다), 기본을 `"pin"`으로 두면 M1–M4가 실제로 허용하던 경계가 그대로 보존된다.
- **`scope` 키:** 소유자 개념이 있는 리소스(세션·remote forward)에 대한 action을 소유자에게만 허용할지(`"owned"`, 기본) 임의 소유자에게 허용할지(`"any"`). 소유자 개념이 없는 action(`exec.run`·`host.reverse`·`forward.local`)에는 무의미하며 무시된다. 기본 `"owned"`가 M3의 opener-principal 소유권 P0를 그대로 재현한다. **파싱은 M5 Step 2부터, 평가는 M5 Step 5부터**(`PLAN.md`) — Step 2는 이 키를 `Rule`에 실어 보존만 했고, ④ 단계에서 실제로 소비하기 시작한 것은 Step 5다. `owner`는 `ResourceRef`의 필드로, choke point가 리소스별로 채운다: 세션은 broker의 `SessionInfo.opener`(broker가 `session.open` 성공 시 기록하는 `crate::acl::opener_key(principal, auth_path)`의 출력), remote forward는 `RemoteForwardOpen` 성공 시 `Server::remote_forwards`에 등록되는 요청 principal의 같은 `opener_key`다 — 둘 다 principal 축이지 `conn_id` 축이 아니다(같은 principal이 다른 connection으로 재접속해도 소유는 유지된다, `docs/design/protocol.md` §7의 `RemoteForwardClose` 인가 순서 문단). owner 없는 리소스(`exec.run`·`host.reverse`·`forward.local`)의 `ResourceRef.owner`는 항상 `None`이고, `scope`는 `owner: None`을 `"owned"`·`"any"` 어느 쪽이든 절대 걸러내지 않는다.
- **`session.control`의 예외 — `close`(F1, M5 Step 5 adversarial review):** 위 문단은 "소유자 개념이 있는 리소스에 대한 action"이라고만 말하므로 `session.control`(write·resize·close 세 operation이 매핑되는 하나의 action, CLI.md §2.5) 전체가 `scope`를 보는 것처럼 읽히기 쉽지만, `close`는 의도적으로 이 결합 밖에 있다. `Server::handle_session_close`는 `write`/`resize`가 쓰는 `authorize_session_control`(owner를 채워 `authorize_owned`로 넘기는 경로)이 아니라 owner 없는 `Self::authorize`를 그대로 쓴다 — 그래서 `scope = "owned"`가 걸린 rule 아래에서도 그 principal이 열지 않은 세션을 닫을 수 있다. 이는 PRD §6("다른 장비에서는 … 조회·읽기·종료는 ACL 범위에서 가능하다")이 요구하는 교차 기기 종료를 M3 그대로 재현한 것이고, 오늘 이를 제한하는 정책 어휘는 없다 — `close`를 `write`/`resize`처럼 소유자로 좁히고 싶다면 `scope` 재해석이 아니라 새 action(예: `session.control`을 쪼갠 별도 이름)과 그 결정을 담을 ADR이 필요하다.
- **Default deny, fail closed:** 매칭 allow 없음 → `PERMISSION_DENIED`; acl.toml이 없거나 파싱 불가 → 전부 deny + 운영자에게 `CONFIG_ERROR` 노출(원격 peer에게는 절대 노출되지 않는다 — 노출하면 그 자체가 host 설정 상태 oracle이다, `PLAN.md` M5 §4.1 #4). "오류 시 개방"은 존재하지 않는다. 정책은 **프로세스 시작 시 1회** 로드한다 — lazy load는 하지 않는다: 첫 요청 시점의 로드는 "판정 불가" 창을 만들고, 그 창에서 fail-open하면 인증 전 리소스 금지 불변식이 깨진다.
- **단일 choke point:** 호스트 측 `server::dispatch`가 디코딩된 모든 요청에 대해 `Authorizer::check(principal, auth_path, action, resource)`를 **리소스 생성(PTY spawn/exec fork/socket bind/ticket 발급) 이전에** 호출한다. `auth_path`(`Pin`|`Ca`)는 transport가 principal과 함께 connection에 부착하는 "어떤 신뢰 경로로 인증됐는가"이며, principal 모양으로는 복원할 수 없다(CA 발급 leaf도 `qsh://device/…` SAN으로 `device:` principal을 낼 수 있다) — M1 임시 정책 allow-all-**pinned**는 이 값으로만 판정한다. 클라이언트 측 코드와 렌더러에는 ACL 로직이 0이며, MCP는 같은 dispatch를 타므로 자동 상속된다. op → 필요 ACL action 매핑은 CLI.md의 매핑 표가 정본이다.
- **거부 문면 균일성:** 네 인가 지점(`Server::authorize`·`authorize_stream`·`authorize_owned`·`reverse::admit::admit`)과 그 감사-쓰기-실패 fail-closed 분기가 원격 peer에게 내려보내는 `PERMISSION_DENIED`는 정책 거부·소유권 거부·fail-closed 거부를 가리지 않고 단일 상수 `qsh_core::acl::PERMISSION_DENIED_MESSAGE`("peer is not allowed to perform this operation on this host")를 그대로 쓴다 — action/capability/resource/principal을 노출하면 그 자체가 정책 열거 oracle이 되기 때문이다(`PLAN.md` M5 Step 4 §4.2). `authorize_owned`(M5 Step 5)는 `authorize`의 owner-aware 자매 함수다 — `ResourceRef.owner`를 채운 채로 `Authorizer::check` + 단일 terminal audit record를 수행하는 같은 헬퍼가, 세션 소유권 게이트(`authorize_session_control` — 얇아진 `require_opener`로 owner를 조회한 뒤 위임)와 remote forward 소유권 게이트(`handle_rfwd_close`)에서 각각 쓰인다. `authorize_stream`은 프로덕션 호출자가 둘이다: `forward.local` 인라인 `TCP_CONNECT` 게이트(거부를 `ConnectResult`에 이 상수 그대로 실어 보낸 뒤 매칭되는 코드로 스트림을 정리한다)와 `SessionData` 재접속 인라인 게이트(`Server::handle_data_stream`, 실을 응답 자체가 없어 `RESET_CODE_FORBIDDEN` 스트림 reset이 거부 그 자체다 — 이 seam의 균일성 의무는 문면 동일성이 아니라 reset 코드와 실제 audit deny 레코드다). 이 seam들의 정본 목록은 `qsh_core::acl::DENY_SEAMS`다. `localctl`의 `NotOwner` 거부("this forward is owned by another client on this host")는 **이 상수를 쓰지 않는다** — 한 호스트 위 두 로컬 클라이언트 사이의 same-uid 신뢰 경계이지 원격 peer 인가 계층이 아니기 때문이다(`docs/design/protocol.md` §11-3, "localctl은 인가 계층이 아니다").
- **Audit:** 결정당 한 줄 JSONL(`$XDG_STATE_HOME/qsh/audit.log`) — ts, request_id, principal, action, resource, decision, rule index, `auth_path`, peer_addr. 레코드 타입에 argv·PTY 내용·키를 담을 **필드 자체가 없어** "내용 무기록"이 규율이 아니라 타입 수준 속성이다(opt-in `audit.log_argv`만 예외, M5에서는 구현하지 않는다). **Audit은 fail-closed다:** 쓰기가 실패하면(디스크 만실 등) 그 뒤의 인가 판정은 감사 없이 조용히 허용되지 않는다 — 감사 없는 서비스보다 서비스 없는 감사가 낫다는 트레이드오프이며, `[audit]`의 회전·retention(§7)이 상시 디스크 예산을 유계로 만들어 이 fail-closed 자체가 자기 유발 서비스 거부가 되는 폭을 줄인다(단, 레코드 하나가 `max_bytes`보다 크면 분할·재시도 없이 그 레코드 하나만 담은 파일이 되므로, 파일당 실제 상한은 `max_bytes`가 아니라 `max(max_bytes, 레코드 1개 크기)`다 — `PLAN.md` M5 Step 3 F8). 수명주기(회전·비동기 쓰기·이 fail-closed 동작 자체)의 구현은 `PLAN.md` M5 Step 3.

## 7. Config·state·runtime 경로

macOS/Linux 동일 (ssh 스타일 예측 가능성; `~/Library/…` 미사용):

```
~/.config/qsh/            # $QSH_CONFIG_DIR → $XDG_CONFIG_HOME/qsh → 이 경로
├── config.toml           # [serve] bind·replay_bytes·resume_ttl·close_grace_ms / [identity] key_store / [audit] path·max_bytes(64MiB)·retain(5)·queue_depth(1024) / [listen] bind·allow_advertised_names(기본 false)·stale_retention(기본 120s) / [reverse] controller·offered_name·backoff_initial_ms(500)·backoff_max_ms(30000)·backoff_jitter_pct(±20)
├── hosts.toml            # [[host]] name·address·user → host.list/host.get/exec/session.open/reverse의 단일 주소 해석 choke point (`crate::ops::host::resolve_forward`, M7 Step 3). hosts.toml 우선, 없으면 trust.toml의 pinned peer로 폴백 — 같은 이름이 양쪽에 있으면 hosts.toml의 address가 이긴다. trust/identity는 항상 trust.toml/fingerprint만으로 결정 — hosts.toml은 순수 주소록이며 trust에 절대 관여하지 않는다. 파일 부재는 빈 디렉터리(에러 아님), 파싱 실패는 CONFIG_ERROR(trust.toml과 동일 실패 형태). M7에서는 read-only — 이 파일을 쓰는 CLI 명령 없음(수동 편집 전용). `user`는 계정 선택이 아니라 CLI.md §7의 assertion hint(명시적 힌트가 항상 우선, hosts.toml은 기본값만 채움) — 서버 측 계정과 불일치 시 UNSUPPORTED. `serve` 쪽은 hosts.toml을 읽지 않는다 — 위 choke point는 전부 클라이언트 쪽(dial하는 프로세스) 경로다
├── trust.toml            # pinned peers + CAs
├── acl.toml              # serve/listen 역할만 읽음
└── identity/             # device.pem (+ file-mode일 때 device.key 0600)
~/.local/state/qsh/       # $XDG_STATE_HOME: audit.log, resume.json(0600; session_ref → {token, peer_spki_sha256, expires_at, …}; flock + tmp+rename 원자 교체, ADR-0007)
$XDG_RUNTIME_DIR/qsh/     # (없으면 state 하위 run/, 0700) per-process UDS: <pid>.sock (localctl, M3 도입 — 첫 소비자 2종은 `qsh hosts`와 역방향 attach, protocol.md §11-3)
```

**런타임 소켓 discovery.** 한 머신에 `qsh listen` 데몬이 여러 개 떠 있을 수 있으므로(프로세스마다 `<pid>.sock`), CLI는 `$XDG_RUNTIME_DIR/qsh/*.sock`을 pid 오름차순으로 순서대로 시도한다: connect가 거부되는 stale 소켓은 unlink하고 다음으로 넘어가며, 요청한 host를 모르는 데몬은 `HOST_NOT_FOUND`로 답해 다음 소켓으로 넘어가게 한다. 전부 실패하면 `HOST_NOT_FOUND`다(구현은 M3 Step 5).

## 8. Crate 선정 (버전은 lock 시점 재확인)

| Crate | 버전 | 근거 |
|---|---|---|
| quinn-proto | 0.11.x, **≥ 0.11.14** | 원격 DoS 수정 포함(RUSTSEC-2026-0037; advisory 대상은 파사드 `quinn`이 아니라 `quinn-proto`). per-stream priority + fair queuing, `Endpoint::rebind()` migration |
| rustls | 0.23 (aws-lc-rs) | 커스텀 `danger` verifier trait로 pin+CA 이중 모드 구현 |
| rcgen | 0.14 | 디바이스 cert / private CA 발급 |
| prost / prost-build | 0.14 | control 메시지 직렬화 — unknown-field 무시 네이티브, `.proto`가 리뷰·fuzz 문법 ([ADR-0001](../adr/0001-custom-quic-protocol.md)) |
| tokio | 1.x | 런타임 |
| portable-pty | 0.9 | §4 (host 측 PTY) |
| nix | 0.29+ (features `term`, `ioctl`, `signal`) | **client 측 raw-mode 터미널**(host 측 PTY backend는 nix를 쓰지 않는다 — `getpwuid_r`은 `libc` 직접 호출, §4) — termios(`tcgetattr`/`tcsetattr`, cfmakeraw + 복원)와 `TIOCGWINSZ`를 직접 호출한다. crossterm 계열은 **채택하지 않는다**: TUI는 키 이벤트를 파싱하지 않고 stdin raw byte를 원격 PTY로 그대로 흘려야 하는데(escape 시퀀스 처리는 행 시작의 `~` 접두만 본다, CLI.md §7) crossterm의 이벤트 루프/키 파서·alternate screen 관리는 이 경로와 충돌하고 불필요한 의존성 표면(Windows API 등)을 끌고 온다. SIGWINCH는 `tokio::signal::unix`, 창 크기는 `TIOCGWINSZ` ioctl로 읽어 `session.resize`로 전파한다. (`signal`은 치명 시그널 수신 시 터미널을 복원한 뒤 기본 disposition으로 재-raise하는 데만 쓴다. `poll`/`user`는 쓰지 않는다 — 입력은 blocking `read(2)`이고 시그널 대기는 tokio가, 계정 조회는 host 측 `libc`가 한다.) 치명 시그널 집합은 `SIGTERM`/`SIGHUP`/`SIGQUIT`이며, 이 셋의 disposition을 tokio가 가져간 뒤로 **시그널 pump는 세션 큐에서 절대 block하지 않는다** — resize/`^C` 전송은 non-blocking send로 하고 큐가 차면 버린다(resize는 다음 `SIGWINCH`가, `^C`는 사용자가 다시 보낸다). block하면 치명 시그널이 dispatch되지 않아 클라이언트가 kill 불가 상태로 터미널을 raw로 남기는데, 이는 복원 장치가 막으려는 바로 그 결과다. 같은 이유로 시그널 handler는 raw mode 진입 **전에** 설치한다. `#![cfg(unix)]`(Windows client는 P1). 의존성은 `[target.'cfg(unix)'.dependencies]`로 선언한다 — `qsh-cli`는 CI clippy matrix와 release workflow에서 `x86_64-pc-windows-msvc`로도 빌드되므로 무조건 의존은 Windows leg를 깨뜨린다(nix는 unix 전용 crate) |
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
