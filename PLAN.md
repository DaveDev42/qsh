# PLAN.md — M4 실행 계획

> **main 세션이 M4 플래닝 에이전트의 초안을 검토·확정한 실행 계획이다(2026-08-24).** ROADMAP M4 범위·수용 기준을 실행 순서로 분해했고, 이 문서가 완료된 M3용 계획을 전면 교체한다. §4.1의 열린 결정 두 건은 보수적(범위 확대 없는) 기본값으로 채택했다 — **#1(holder 수명):** interactive foreground form이 DoD 1/2를 마감하고 새 client 상주 데몬은 만들지 않는다(상주 holder 채택은 별도 범위 승격이 필요 — silent addition 금지). **#7(perf 게이트):** 두 perf DoD를 M3 `acceptance` job 선례대로 상시 게이트하며, 이를 위한 `docs/design/testing.md` L10 개정은 **Step 7에서** 적용한다 — 그 전(Step 1–6)까지 이 개정은 veto 가능하다.

이 문서는 **현재 마일스톤(M4 — 터널)의 실행 계획**이다. 마일스톤 정의(범위·수용 기준·크기)의 정본은 항상 [`docs/ROADMAP.md`](docs/ROADMAP.md)이며, 이 문서는 그 정의를 바꾸지 않고 실행 순서로 분해한다. **M4가 Done 처리되면 이 문서는 다음 마일스톤(M5 — ACL 정책 + audit)의 계획으로 전면 교체된다** — living doc이며 과거 마일스톤의 실행 기록으로 남기지 않는다.

## 1. M4 목표 요약

`docs/ROADMAP.md` "M4 — 터널" 절 인용:

> - **범위:** `-L`/`-R`, `qsh tunnel open/close`, `qsh tunnels`. TCP 연결당 QUIC stream 1개, stream 우선순위로 PTY 보호, remote forward는 loopback bind만(§9). forward/reverse 연결 양쪽에서 동작.
> - **명시적 out:** SOCKS `-D`(P1), file copy, UDP forwarding.
> - **수용 기준 (DoD):** `-L 8080:localhost:3000` 후 `curl localhost:8080` 도달. `-R` non-loopback bind 요청이 **거부**되는 명시적 테스트. Throughput ≥ 동일 프로세스에서 측정한 raw-quinn 기준의 80%. **1GB 포화 터널과 병행한 PTY echo p95 < RTT + 10ms** (§13). `-D 1080` → `UNSUPPORTED` + "P1" 메시지.
> - **크기:** 2ew

### DoD 체크리스트 (`docs/ROADMAP.md` M4 "수용 기준" 인용)

- [ ] **DoD 1** — `-L 8080:localhost:3000` 후 `curl localhost:8080`이 원격 `:3000`에 도달(실프로세스 e2e).
- [ ] **DoD 2** — `-R`의 non-loopback bind 요청이 **거부**됨을 단언하는 명시적 테스트(loopback-only 강제, §9).
- [ ] **DoD 3** — 터널 throughput ≥ **동일 프로세스·동일 실행**에서 측정한 raw-quinn 기준의 80%(비율 게이트, `docs/design/testing.md` L10).
- [ ] **DoD 4** — **1GB 포화 터널과 병행한 PTY echo p95 < 측정 loopback RTT + 10 ms**(통합 벤치마크, `docs/design/protocol.md` §12·`docs/PRD.md` §13).
- [ ] **DoD 5** — `-D 1080` → `UNSUPPORTED` + "P1" 메시지(flag는 parsing되되 리소스 생성 0).

M4 크기: 2ew (`docs/ROADMAP.md` M4 "크기").

### 이 마일스톤이 새로 만드는 것 / 이미 있는 것

**M4가 새로 만드는 것은 "raw byte 파이프 = QUIC bidi 스트림"이라는 두 번째 데이터-스트림 종류와, 그것을 role/방향과 무관하게 여는 대칭 스트림-오픈 경로뿐이다.** 아래는 이미 있어 M4가 **발명하지 않는다**:

- **우선순위 band 상수** — `PRIORITY_CONTROL(200) > PRIORITY_SESSION_DATA(100) > PRIORITY_EXEC_DATA(50) > PRIORITY_TUNNEL(0)`이 `crates/qsh-proto/src/wire.rs`에 이미 있고(§12, `send_priority_band_matches_protocol_md_12` 테스트가 순서를 고정), `qsh_transport::control`의 `set_priority(i32)`도 이미 있다. M4는 이 상수를 **터널 스트림에 실제로 적용**하고 `send_fairness`·비대칭 receive window·BBR를 transport 설정에 켠다.
- **`StreamKind::TCP_CONNECT(3)`·`TCP_ACCEPTED(4)`와 `StreamHeader{kind, ticket, host, port}`** — proto에 이미 정의돼 있다(`crates/qsh-proto/proto/qsh/wire/v1.proto`). M4는 이 kind에 **의미를 붙일 뿐** 새 enum 값을 만들지 않는다.
- **역방향 role 축·localctl seam·`ControlLink`/`DataLink` enum·`resolve_host_route`** — M3가 깔았다. `-R over reverse`(연결 방향 ⊥ 세션 역할, M3의 핵심 불변식)가 재작업 없이 얹히는 것이 M3 시퀀싱의 존재 이유(`docs/ROADMAP.md` §1 원칙 4번)다. M4는 localctl에 **터널 conduit(세 번째 소비자)** 을 더한다.
- **세션 broker·replay ring·writer lease** — 터널은 이 중 어느 것도 쓰지 않는다. 터널 스트림은 replay 대상이 아니다(ADR-0004는 세션 output ring 전용) — 그 사실이 §3(resume 거동)의 설계 전제다.
- **ErrorCode 전 어휘** — `UNSUPPORTED`·`PERMISSION_DENIED`·`INVALID_ARGUMENT`·`RESOURCE_EXHAUSTED`·`CONNECTION_FAILED`·`HOST_NOT_FOUND`가 전부 `docs/CLI.md` §3.3에 이미 있다. **M4는 새 `ErrorCode`를 만들지 않는다**(`CLAUDE.md` "never invent an ad hoc error string").

M4가 실제로 지는 것은 (i) 두 방향의 forward(`-L` local→remote / `-R` remote→local)를 forward·reverse **연결 양쪽**에서 동작시키기, (ii) 새 ACL action 2종(`forward.local`·`forward.remote`)과 그 두 개의 **서로 다른** 인가 지점(remote=choke point / local=스트림-오픈 inline), (iii) 포화 터널이 PTY를 굶기지 않음을 스케줄러+벤치로 증명, (iv) 연결 손실·migration 하 터널의 정의된 거동 — 넷이다.

## 2. 작업 분해 (Step 1..8)

원칙: **모든 step은 완료 시점에 `cargo fmt --all` / `cargo clippy --workspace --all-targets -- -D warnings` / `cargo test`(또는 `cargo nextest run`) / `cargo run -p xtask -- arch` / `cargo deny check` 전부 green을 유지해야 한다.** 이 게이트를 통과하지 못한 상태로 다음 step으로 넘어가지 않는다(`CLAUDE.md` "Before committing"). clippy는 CI 5개 runner의 모든 타깃에서 green이어야 하고, **Windows leg는 clippy뿐 아니라 전체 `cargo nextest run --workspace` + doc-test가 돈다**(`docs/design/testing.md` "현재 상태") — M4가 도입하는 로컬 TCP 리스너·splice·localctl 터널 conduit은 전부 `cfg(unix)`이므로 `cfg` 게이트를 빠뜨리면 컴파일이 아니라 **테스트 단계**에서 Windows leg가 조용히 깨진다. 각 step의 완료 판정은 Windows leg의 nextest green을 포함한다.

각 step은 독립적으로 리뷰 가능한 PR 하나 크기다(예외는 Step 5 — 두 PR로 나누는 경계를 명시한다). 순서는 **계약 → 우선순위·대칭 스트림 배선 → local forward → remote forward → reverse 위 양방향 + `qsh tunnels`/`close` → `-D` stub·계약 표면 마감 → perf 게이트 → resume/chaos 거동·문서**이며, 그 안에서 위험한 미지수를 앞으로 당겼다:

1. **Step 1이 계약을 종이로 먼저 확정한다.** M4의 진짜 미지수 — (a) `reserved` 태그(`ControlMessage` 40·41, `Response` 4)를 어떤 메시지로 채우는가, (b) 로컬 forward의 인가가 왜 choke point가 아니라 스트림-오픈 inline인가(§7 ticket 예외), (c) `ConnectResult`가 아직 proto에 없다(§7 표에만 산문으로 존재), (d) **`tunnel.open`이 operation(즉시 envelope 반환)인가 foreground blocking인가** — 이 터널 holder 수명 모델이 M4 전체 모양을 가른다(§4.1 #1 — foreground form 채택), (e) `-R over reverse`의 스트림 방향 매핑 — 을 `.proto`와 정본 문서에 못박아 구현이 계약을 발명하지 못하게 한다.
2. **위험한 novel 케이스(`-R over reverse`)를 마지막에 처음 생각하지 않는다.** M3 시퀀싱 원칙 4번이 "`-R over reverse connection`이 진짜 흥미로운 케이스"라고 지목한 그 조합(연결 방향과 세션 역할의 독립)을 Step 1이 **설계로 확정**하고 Step 2가 **스트림-오픈을 대칭으로 배선**한 뒤, Step 5가 실물화한다. Step 3–4의 forward-전용 코드가 role에 결합되면 Step 5가 재작업이 되므로, Step 2에서 "터널 스트림은 어느 role이든 열 수 있다"를 구조로 고정한다.
3. **ACL 두 지점을 Step 3·4가 각각 최초로 실물화한다.** `forward.remote`는 리소스(remote listener bind) 생성 **이전** choke point(Step 4), `forward.local`은 per-connection RPC 왕복을 피하려 **스트림-오픈 시점 inline**(Step 3, §7의 유일한 ticket 예외). 두 지점 모두 "인가 전 리소스 생성 금지"(PRD §9)를 지키는지가 각 step의 보안 게이트다.
4. **Perf 게이트(Step 7)는 DoD 3·4를 닫지만 그 설계는 Step 1·2에서 확정한다** — 우선순위 band·비대칭 window가 Step 2에 없으면 Step 7의 echo-under-load가 통과할 수 없고, testing.md L10의 "perf는 PR 게이트 금지"와 ROADMAP M4 DoD·protocol.md §12의 "CI 조기 도입"의 긴장을 Step 1이 **acceptance job 게이트로** 해소한다(§4.1 #7, M3의 60초 blackout 선례 그대로).

`docs/ROADMAP.md` 시퀀싱 원칙 4번("역방향(M3)이 터널(M4)보다 먼저 — 터널은 role 모델 위에 얹힌다")이 이 마일스톤이 M3 뒤에 오는 이유이고, 원칙 5번("인가 **지점**은 M1부터, 정책 **엔진**은 M5")이 Step 3·4가 `forward.local`/`forward.remote` **검사 지점**만 넣고 정책 파일은 M5로 미루는 근거다.

### 전 step 공통 계약 규율

- `qsh.cli/v1`·`qsh.event/v1`은 **additive-only**(optional 필드·새 event type·열린 문자열의 새 값만; 삭제·type 변경·의미 변경은 `/v2`), `crates/qsh-cli/tests/fixtures/cli-v1/`의 fixture는 **append-only**(기존 파일 편집·삭제 금지) — `docs/CLI.md` §10, `docs/design/testing.md` L6, `CLAUDE.md` "Contract stability rules". M4의 신규 fixture는 `tunnel.open.json`·`tunnel.list.json`·`tunnel.close.json`(append-only 신규)이며, `error.UNSUPPORTED.json`·`error.PERMISSION_DENIED.json`·`error.INVALID_ARGUMENT.json`·`error.RESOURCE_EXHAUSTED.json`가 이 마일스톤에서 처음 **CLI 바이너리 envelope 경로**를 얻는다면 append-only로 추가하고 `crates/qsh-cli/tests/fixtures.rs`의 `DEFERRED`에서 제거해 `REQUIRED_FIXTURES`에 등록한다(각 step의 (d)가 어느 코드가 어느 경로를 얻는지 §2 DEFERRED 규율(M3 H1과 동형)로 명시한다).
- wire(`qsh.wire.v1`)는 "additive only within v1 — never renumber or reuse a field/tag"(`v1.proto` 머리말). **`reserved` 태그를 그 태그가 예약된 바로 그 메시지로 채우는 것은 위반이 아니다** — 머리말이 "Tunnel (M4) and reverse (M3) tags are `reserved` here so a later milestone cannot accidentally take them"라고 용도를 명시했고, `ControlMessage.reserved 40, 41`·`Response.reserved 4`는 각각 그 자리의 주석이 이미 "RemoteForwardOpen/Close (M4)"·"RemoteForwardOpened rfwd_opened (M4)"라고 이름을 박아 두었다. Step 1이 예약된 의미를 실현할 뿐이다(M3 Step 1이 `Hello.reverse`로 한 것과 동형).
- **M4는 새 `ErrorCode`를 만들지 않는다.** loopback 아닌 remote bind = `INVALID_ARGUMENT`(요청 모양/제약 위반; 같은 principal이 `forward.remote`를 가져도 통과 못 함 — ACL 판정이 아니다), `forward.local`/`forward.remote` 거부 = `PERMISSION_DENIED`, `-D`/SOCKS = `UNSUPPORTED`, 미해석 host = `HOST_NOT_FOUND`, dial 실패·remote 연결 실패 = `CONNECTION_FAILED`, 터널 in-flight/리스너 상한 초과 = `RESOURCE_EXHAUSTED`, 미지 `forward_id`로의 `TCP_ACCEPTED`·만료 ticket = `INVALID_ARGUMENT`. 전부 `docs/CLI.md` §3.3 어휘다.
- 기계 모드 stdout은 순수 JSON만(`docs/CLI.md` §2.2). M4가 새로 만드는 진단(`qsh::tunnel`)은 전부 **stderr 한 줄 JSON**이며 payload(터널을 흐르는 바이트)·host:port 이외의 내용을 갖지 않는다 — **터널 payload는 어디에도 로그하지 않는다**(splice는 파싱도 로그도 하지 않는 순수 파이프, `CLAUDE.md` "Never log ... PTY/command contents"의 터널 판).
- 테스트는 `sleep()` 금지, chaos는 seeded(실패 메시지에 seed 출력), 포트는 0 바인딩(`docs/design/testing.md` CI 규율). Step 7의 perf 게이트만 벽시계/처리량을 쓰며 그 격리 방법(같은-프로세스 비율·acceptance job)을 그 step이 명시한다.
- **리소스는 인가 후에만 생성한다** — 로컬 리스너 bind, remote 리스너 bind, target dial, ticket 발급 전부 해당 ACL 통과 뒤에만(`docs/PRD.md` §9 "인증 전에는 PTY, exec 또는 tunnel resource를 생성하지 않는다", `docs/design/protocol.md` §7, `CLAUDE.md` "Never create a resource ... before authorization succeeds"). local forward는 `TCP_CONNECT` 스트림 오픈 시점에 `forward.local`을 inline 검사하고 **거부 시 아무것도 dial하지 않고 스트림을 종단**시킨다(§7 "거부 teardown").
- **Windows leg.** 로컬 TCP 리스너·splice·localctl(UDS) 터널 conduit·remote bind는 host 역할 경로이고 M3의 `cfg(unix)` 경계 위에 선다. Windows에서 `qsh tunnel open`/`qsh tunnels`/`qsh tunnel close`와 `-L`/`-R`가 실제로 리스너를 세우는 host/relay 경로는 unix 전용이다 — client-측 `-L` 로컬 bind가 Windows에서 가능한지는 §4.1 #1의 holder 모델 결정에 종속되며, 그 전까지 Windows에서 관련 서브커맨드는 리소스 생성 없이 `UNSUPPORTED` + exit 255다(M3 `qsh listen`/`qsh reverse`와 같은 규율). `-D`는 플랫폼 무관하게 `UNSUPPORTED`다.

---

### Step 1 — 계약 확정: 터널 wire 메시지(`reserved` 실현) + `ConnectResult` + forward-spec 파서 + JSON `Tunnel` 타입 + localctl 터널 conduit + 정본 문서 갱신

**(a) 범위:** M4가 구현 중에 발명하면 안 되는 것을 전부 이 step에서 계약으로 고정한다. 코드는 `qsh-proto`(sans-IO)와 문서만 건드린다.

*wire (`crates/qsh-proto/proto/qsh/wire/v1.proto`)*:
- `ControlMessage`의 `reserved 40, 41;`에서 40·41을 꺼내 `RemoteForwardOpen rfwd_open = 40;`·`RemoteForwardClose rfwd_close = 41;`로 정의(25는 `SessionSignal` P1로 **남긴다** — 이 예약은 건드리지 않는다). `Response`의 `reserved 4;`를 `RemoteForwardOpened rfwd_opened = 4;`로 정의.
- 신규 메시지: `RemoteForwardOpen { string bind_host = 1; uint32 bind_port = 2; string forward_host = 3; uint32 forward_port = 4; }`(§7·§9의 산문을 실제 정의로 승격 — `bind_host`는 host가 bind할 주소, 기본·강제 loopback; `forward_host:forward_port`는 요청자 측으로 되돌릴 목적지), `RemoteForwardOpened { string forward_id = 1; uint32 actual_port = 2; }`, `RemoteForwardClose { string forward_id = 1; }`.
- **`ConnectResult` 신규**(§7 표가 `StreamHeader{TCP_CONNECT} → ConnectResult → raw bytes`라고 산문으로만 정한 것을 proto에 실물화): local forward 스트림에서 host가 target dial 결과를 요청자에게 알리는 data-스트림 메시지 `ConnectResult { bool ok = 1; string code = 2; string message = 3; }`(`code`는 `docs/CLI.md` §3.3 어휘 — dial 실패=`CONNECTION_FAILED`, inline ACL 거부=`PERMISSION_DENIED`). frame layer는 §5 재사용(u32-BE + prost, `DATA_FRAME_MAX`); ok 이후로는 frame 없이 raw bytes.
- **`forward_id`의 모양·정체**: host가 발급하는 opaque·URL-safe 문자열(session_id와 같은 규율 — peer가 audit field로 만들기 전에 크기를 묶는다). `TCP_ACCEPTED` 스트림의 `StreamHeader.ticket`에 이 `forward_id`가 실린다(§9 주석대로).

*forward-spec 파서(`crates/qsh-proto`의 순수 함수)*: `wire::parse_forward_spec(&str) -> Result<ForwardSpec, wire::Error>`를 계약 계층에 둔다 — `-L`/`-R`가 받는 `[bind:]listen_port:host:host_port` 문법(예 `8080:localhost:3000`, `[::1]:8080:localhost:3000`)을 파싱하는 **순수** 함수. `L8` fuzz 타깃이 이미 이 파서를 지목("`-L 8080:host:3000` 파싱")하므로 sans-IO여야 한다. 포트 범위·host 모양·IPv6 대괄호를 검증하고, non-loopback `bind`는 파서가 **거부하지 않는다**(모양은 유효; loopback-only **정책** 강제는 host 측 Step 4의 몫 — 파서는 정책을 모른다). remote(`-R`)와 local(`-L`)은 host가 dial하는 쪽이 반대이므로 방향 enum을 결과에 담는다.

*JSON 계약 (`crates/qsh-proto/src/types.rs`)*: `Tunnel` DTO 신규 — `{ tunnel_id, mode: "local"|"remote", bind, forward_to, actual_port: Option<u32>, host }`(`host`는 클라이언트 `Ops`가 채우는 alias, wire에 없음 — ADR-0007 규율). `TunnelOpenReq`·`TunnelOpenData(Tunnel)`·`TunnelListReq{}`·`TunnelListData{ tunnels: Vec<Tunnel> }`·`TunnelCloseReq{ tunnel_id }`·`TunnelCloseData{ tunnel_id, closed: bool }`. 값 어휘: `mode ∈ {"local","remote"}`(열린 문자열, `connection_mode`와 동형). **`-D`(SOCKS)는 이 타입에 값을 만들지 않는다** — 파싱 후 항상 `UNSUPPORTED`이므로 envelope의 `data`에 도달하지 못한다(Step 6).

*IPC (`crates/qsh-proto/proto/qsh/local/v1.proto`, `qsh.local.v1` 확장)*: `qsh tunnels`(localctl 세 번째 소비자, architecture.md §3이 "`qsh tunnels` 류의 프로세스 간 조회"라고 이미 이름 지은 그 경로)와 터널 스트림 relay를 위한 additive 메시지 — `LocalTunnelList{}` / `LocalTunnelListResult{ repeated LocalTunnel tunnels }` / `LocalTunnel{ tunnel_id, mode, bind, forward_to, actual_port, host }`, 그리고 `LocalResponse{oneof body}`에 `tunnel_list_result` variant 추가(M3의 응답 envelope 단일화 규율 그대로). **터널 데이터 conduit**은 새 `LocalStreamKind`를 만들지 않는다 — M3의 `LOCAL_STREAM`이 이미 "다음 frame이 wire `StreamHeader`인 data 스트림"이므로 `StreamHeader{TCP_CONNECT|TCP_ACCEPTED}`도 같은 conduit kind로 흐른다(§4.1 #6의 "`StreamKind`에 UDS 전용 값 추가 금지"를 로컬 계층에도 적용). 이 해석을 `local/v1.proto` 머리말과 protocol.md §11-3에 한 문장으로 명문화한다.

*정본 문서 갱신(구현 전에)*:
- `docs/CLI.md` — §6.9(Tunnel): 지금은 명령 예시뿐이므로 `tunnel.open`/`tunnels`/`tunnel.close`의 **JSON envelope `data` 형태**(위 `Tunnel` DTO), `-L`/`-R` spec 문법, `-D`가 파싱되되 `UNSUPPORTED`+"P1"임을, 그리고 **holder 수명 모델**(§4.1 #1 결정)을 확정. §2.5 — `tunnel.open`(local)→`forward.local`, `tunnel.open`(remote)→`forward.remote`, `tunnel.close`/`tunnel.list`→"소유 peer이면 허용" 매핑은 **이미 있으므로 건드리지 않는다**(M4는 이 계약을 이행). §4/§7.1 — `qsh [user@]host`의 `-L`/`-R` 동반 형(§6 line 634의 "모두 `SessionOpen`을 보낸다"의 실현)과, `-L`/`-R`가 세션까지 여는지 터널만 여는지 확정. 신규 §6.14(또는 §6.9 확장) "장기 실행/holder 거동" — 터널 리스너의 수명이 무엇에 결합되는지(holder 프로세스/데몬 연결), 연결 손실 시 거동(§3).
- `docs/design/protocol.md` — §7 표의 `ConnectResult`를 실제 메시지 참조로, `forward_id` 발급·모양 규칙 명문화. §9 스케치를 `RemoteForwardOpen/Close/Opened`·`ConnectResult` 실제 정의와 일치. §11-3에 **터널 conduit이 `LOCAL_STREAM`을 재사용**함과 `-R over reverse`의 스트림 방향 매핑(아래 §4.1 #4)을 추가. §12 — 비대칭 receive window·`send_fairness(true)`·BBR가 Step 2의 구현 대상임을 명시(현재 산문은 "대응 (a)(b)(c)"로만 있음).
- `docs/design/architecture.md` — §3 "`qsh tunnels`(M4)는 그 다음 소비자다"를 실현으로 갱신, 터널 로직이 `qsh-core`의 어디에 사는지(신규 `crates/qsh-core/src/tunnel/` 모듈 — local/remote/splice) 기술. §1 crate 책임 표의 "exec/tunnel"이 실제 코드로 채워짐을 반영.
- `docs/design/testing.md` — L3에 터널 loopback 하네스 행, L4에 터널 chaos(migration 하 생존·sever 하 정리) 행, **L9/L10 perf 게이트와 M4 DoD의 긴장 해소를 명문화**(§4.1 #7: 비율 throughput은 same-process 결정적 테스트로 acceptance job에서 strict, echo-under-load p95는 acceptance job 게이트 — PR 유닛 스위트에는 넣지 않는다), L8 fuzz에 `parse_forward_spec` 타깃 확인.

**(b) crate/모듈/파일:**
- `crates/qsh-proto/proto/qsh/wire/v1.proto` (확장 — `RemoteForwardOpen/Close/Opened`, `ConnectResult`, `reserved 40/41/4` 실현)
- `crates/qsh-proto/proto/qsh/local/v1.proto` (확장 — `LocalTunnelList`/`LocalTunnelListResult`/`LocalTunnel`, `LocalResponse`에 variant)
- `crates/qsh-proto/src/wire.rs` (확장 — `parse_forward_spec`, `ForwardSpec`, `valid_forward_id` 또는 기존 `valid_host_name` 재사용 판단; `PRIORITY_TUNNEL`은 무변경)
- `crates/qsh-proto/src/types.rs` (확장 — `Tunnel` DTO + 6개 req/data 타입)
- `docs/CLI.md`, `docs/design/protocol.md`, `docs/design/architecture.md`, `docs/design/testing.md` (갱신)
- **(구현 중 확인된 필연적 파급, 계획 반영):** `oneof` variant를 실현하면 하위 crate의 **exhaustive `match`가 컴파일 에러**가 된다(`E0004`) — 계약만 바꿔도 workspace가 빌드되려면 이 arm들을 함께 채워야 한다. Step 1은 따라서 다음 최소 arm을 포함한다(동작 무변화 — 터널 핸들러는 Step 3–5): `crates/qsh-core/src/server/mod.rs`(`dispatch`: `RfwdOpen`/`RfwdClose` → `UNSUPPORTED`, 실현 전 `body:None`이 내던 것과 같은 응답, 리소스·audit 0), `crates/qsh-core/src/localctl/mux.rs`(`classify`: 두 메시지를 `Request`군에 — CLI→host relay 대상), `crates/qsh-core/src/client/mod.rs`(`response_kind`: `RfwdOpened` 진단 라벨). 아울러 `server::tests::reserved_and_unknown_control_numbers_are_unsupported` 유닛 테스트는 "40/41이 `None`으로 디코드된다"는 이제-거짓인 가정을 갱신한다(40/41은 실현됐으므로 실제 empty body로 디코드되고 전용 arm이 `UNSUPPORTED`로 답함을 별도 커버 — golden 바이트-불변 vector는 무변경). M3 `Hello.reverse` 실현도 같은 파급을 가졌다.

**(c) 빚지는 테스트 (`docs/design/testing.md` L0):** `RemoteForwardOpen/Close/Opened`·`ConnectResult`·`LocalTunnel*` 전 메시지의 `decode(encode(m)) == m` roundtrip(proptest), canonical encoding, truncation·allocation-bound·bit-flip(§13 fuzz 계획), `parse_forward_spec` 경계 표(3-part/4-part/IPv6 대괄호/포트 0·65536/빈 host/non-loopback bind는 **파싱 성공**(정책은 파서 밖)/쓰레기 입력은 `Error`), `forward_id` 모양 검사. **golden vector**: 기존 `Hello`·`Response`·`ControlMessage` 인코딩이 40·41·4 태그를 채운 뒤에도 **기존 필드는 바이트 단위 불변**(additive의 기계적 증거) + `reserved`가 채워진 새 메시지 golden 1종씩.

**(d) 완료 판정:** L0 green. 기존 fixture·golden 전부 바이트 단위 불변. `xtask arch` green(`qsh-proto`는 여전히 무의존). 위 문서 갱신이 같은 PR에 포함(각 문서 머리말의 "구현이 어긋나면 문서를 먼저 갱신" 규칙). Windows leg의 nextest green(신규 코드는 `qsh-proto`뿐이라 unix 분기 없음 — 이후 step의 기준선). **DEFERRED 판정:** 이 step은 계약만 깔고 어떤 `ErrorCode`도 새 CLI envelope 경로를 얻지 않으므로 `fixtures.rs`의 `DEFERRED`는 무변경.

**(e) 인용:** `docs/design/protocol.md` §5(frame layer 상한·raw byte 예외), §7(스트림 배치·ticket 규율·`TCP_CONNECT` inline ACL 예외), §9(proto 스케치의 40·41·4·`StreamHeader`), §11-3(localctl conduit), §12(우선순위), §13(fuzz 계획), §14(transport 불가지), `docs/CLI.md` §2.2·§2.4·§2.5·§3.3·§6.9·§10, `docs/PRD.md` §9(action 목록·인증 전 리소스 금지)·§13(포트 포워딩)·§15, `docs/design/architecture.md` §1·§2·§3, ADR-0004(replay는 세션 전용 → 터널 비대상), ADR-0005(transport 불가지·`StreamMux`), ADR-0007(`Tunnel.host`는 `Ops`가 조립).

---

### Step 2 — 우선순위 band·비대칭 window 적용 + 대칭 터널 스트림-오픈 seam (동작 변화 최소 리팩터)

**(a) 범위:** 터널 코드를 한 줄도 넣기 전에 (i) 우선순위/backpressure 설정을 실물화하고 (ii) "터널 스트림은 어느 role이든 연다"는 대칭성을 seam으로 고정한다. 이 두 가지가 없으면 Step 5(`-R over reverse`)와 Step 7(echo-under-load)이 재작업 또는 실패가 된다.

**우선순위·backpressure(§12 대응 (a)(b)(c)의 실물화).** transport 설정에서: (a) per-stream 비대칭 receive window — 터널 스트림 ~2–4 MB, PTY(세션 data) ~256 KiB(`crates/qsh-transport`의 `TransportConfig`), (b) BBR congestion control 선택, (c) 터널 스트림에 `set_priority(PRIORITY_TUNNEL=0)` 적용 + `TransportConfig::send_fairness(true)`로 터널 간 round-robin. 세션/exec 스트림의 우선순위는 **기존 값 그대로**(이 리팩터는 관찰 가능한 세션 거동을 바꾸지 않는다). 근거: `docs/design/protocol.md` §12 "포화 터널이 PTY chunk를 지연시키지 못한다"는 **큐 순서(priority)와 큐 깊이(window/BBR) 둘 다** 있어야 성립한다.

**대칭 스트림-오픈 seam.** 현재 비-control 스트림 오픈은 role에 결합돼 있을 수 있으므로(session data는 attach하는 쪽이 연다), 터널 스트림을 여는 `open_stream(conn_or_link, StreamHeader) -> FramedThenRaw` 진입점을 M3의 `ControlLink`/`DataLink` enum(QUIC vs 로컬 IPC) 위에 두어 **어느 role이든** `TCP_CONNECT`(요청자 측이 연다)·`TCP_ACCEPTED`(bind한 측이 연다)를 열 수 있게 한다. 여기서 갈라지는 코드가 생기면 Step 5의 `-R over reverse`가 즉시 재작업이 된다 — M3 Step 2가 control 핸드셰이크에 한 것과 동형의 "축 분리".

**이 step은 터널 비즈니스 로직을 넣지 않는다** — 리스너도 splice도 ACL도 없다. 우선순위 설정과 스트림-오픈 seam만 깐다.

**(b) crate/모듈/파일:**
- `crates/qsh-transport/src/*.rs` (확장 — 비대칭 window·BBR·`send_fairness`; 터널 스트림에 `set_priority` 적용 지점)
- `crates/qsh-core/src/client/link.rs` (확장 — `DataLink`에 raw-byte 파이프 오픈 진입점; M3의 enum 재사용, generic화 금지 — M3 Step 6 규율)
- `crates/qsh-core/src/tunnel/mod.rs` (신규 — 빈 모듈 + `open_stream` seam 시그니처만; 구현은 Step 3–4)

**(c) 빚지는 테스트 (`docs/design/testing.md` L3):** 기존 loopback 스위트 전부 **무수정 green**(우선순위/window 조정이 세션 거동을 바꾸지 않음). 우선순위 band이 스트림에 실제로 적용됨을 `set_priority` 호출 지점 유닛으로 단언(값이 `PRIORITY_TUNNEL`). `send_fairness`·window 설정이 `TransportConfig`에 존재함을 단언. 대칭 seam이 forward·reverse `DataLink` 양쪽에서 컴파일·동작(빈 파이프 오픈 → 즉시 닫기).

**(d) 완료 판정:** **관찰 가능한 세션 동작 변화 0** — 기존 테스트가 하나도 수정되지 않고 green, golden·`version --json` fixture 바이트 단위 불변. 터널 스트림이 열리면 priority 0으로 열림을 단언. `xtask arch` green. Windows leg nextest green.

**(e) 인용:** `docs/design/protocol.md` §2(quinn `set_priority`·`send_fairness` 근거), §12(우선순위 band·bufferbloat·비대칭 window·BBR), §14(transport 불가지), `docs/design/architecture.md` §8(quinn-proto per-stream priority + fair queuing), `docs/design/testing.md` L3, ADR-0005.

---

### Step 3 — Local forward (`-L`): 로컬 리스너 + `TCP_CONNECT` 스트림 + **inline `forward.local` ACL** + splice — **DoD 1(local leg)**

**(a) 범위:** forward 연결 위의 `-L`을 완성한다. reverse 위의 `-L`은 Step 5, remote(`-R`)는 Step 4다.

**ACL.** `acl::Action`에 `ForwardLocal`(`as_str() == "forward.local"`)을 추가하고 `Action::ALL`을 (M3의 6종 + 이 step) 늘린다(`docs/PRD.md` §9 최소 action, `docs/CLI.md` §2.5). 정책은 여전히 interim `AllowAllPinned`(M5가 TOML 엔진).

**요청자(client) 측.** `-L [bind:]lport:host:hport`를 `parse_forward_spec`(Step 1)로 파싱해 로컬 TCP 리스너를 bind한다(기본 loopback bind — client 로컬 리스너의 non-loopback bind 정책은 §4.1 #3, 기본 loopback). 리스너에 들어온 TCP 연결마다 QUIC bidi 스트림을 `open_stream(link, StreamHeader{TCP_CONNECT, host, port})`로 열고, host의 `ConnectResult`를 읽어 `ok`면 이후 양방향 raw-byte splice(`copy_bidirectional` — frame 없음, 파싱·로그 없음), `ok=false`면 로컬 TCP 소켓을 그 `code`에 맞게 정리한다. 스트림 우선순위 `PRIORITY_TUNNEL`(Step 2).

**host 측 — inline ACL(§7의 유일한 ticket 예외).** `TCP_CONNECT` 스트림을 받으면 **아무것도 dial하기 전에** `Authorizer::check(principal, auth_path, Action::ForwardLocal, resource = "host:port")` + `AuditRecord::now`를 호출한다. deny면 `ConnectResult{ok:false, code:"PERMISSION_DENIED"}`를 쓴 뒤 스트림을 종단시키고, **dial 0**이다(teardown 상세는 `docs/design/protocol.md` §7 "거부 teardown" — 방금 쓴 frame의 전달을 파괴하지 않도록 송신 half는 `finish()`, 수신 half는 사유별 코드로 `stop()`). allow면 `host:port`를 dial(loopback 목적지가 지배적이지만 목적지 제약은 local forward엔 없다 — 목적지는 요청자가 정한다), 성공 시 `ConnectResult{ok:true}` 후 splice, 실패 시 `ConnectResult{ok:false, code:"CONNECTION_FAILED"}`. **이것이 이 마일스톤이 지는 SC6 지분의 절반**(모든 privileged op에 audit 라인). per-connection RPC 왕복을 피하려 choke point가 아니라 스트림-오픈 inline인 이유를 코드 주석에 §7 인용으로 남긴다.

**CLI 표면.** 두 표면 중 이 step이 여는 것은 §4.1 #1의 holder 결정에 종속된다(§4.1 #1 — foreground form 채택). 기본 계획: (i) `qsh [user@]host -L spec`(interactive form — PRD §131-135의 `qsh -L 8080:localhost:3000 dave@personal-mac` 그대로) — 세션 TUI가 살아 있는 동안 리스너가 살고 프로세스와 함께 죽는다(foreground, 새 데몬 불요). 이 form이 **DoD 1의 마감 도구**다. (ii) `qsh tunnel open host --local spec [--json]` — envelope를 반환하는 operation; holder 모델이 확정되면(§4.1 #1) 이 step 또는 Step 5가 실물화한다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/acl/mod.rs` (확장 — `Action::ForwardLocal`, `ALL`, `as_str`)
- `crates/qsh-core/src/tunnel/local.rs` (신규 — 로컬 리스너 accept 루프, `TCP_CONNECT` 오픈, splice)
- `crates/qsh-core/src/tunnel/splice.rs` (신규 — `copy_bidirectional` 래퍼, 우선순위·에러 정리)
- `crates/qsh-core/src/server/mod.rs` 또는 dispatch (확장 — `TCP_CONNECT` 스트림의 inline `forward.local` 검사 + dial)
- `crates/qsh-cli/src/cli.rs`, `src/main.rs` (확장 — `InteractiveArgs`에 `-L`(반복 가능) 추가; `Command::Tunnel(TunnelCmd::Open)` 얇은 진입점)
- `crates/qsh-testkit/src/tunnel.rs` (신규 — loopback 터널 하네스: 한 프로세스에 host + client + 로컬 echo 서버)
- **(구현 중 확인된 계약 표면 미결, Step 6 귀속):** `qsh tunnel open --json`의 exit code가 envelope와 어긋난다 — 이 명령은 `ok: true` envelope를 먼저 찍고 foreground로 터널을 쥔 뒤, hold가 끝나면 기계가 읽을 수 있는 종료 사유 없이 `EXIT_RUNTIME_FAILURE`(255)로 빠진다(`crates/qsh-cli/src/main.rs` 643행 부근). envelope와 exit code를 정합시키는 일은 Step 6의 exit-code matrix 몫이고 그 step의 범위가 이미 "계약 표면 마감(exit-code matrix·jsonl 순수성)"이므로, Step 3은 이 어긋남을 고치지 않고 **명시 유예**로 기록한다.
- **(구현 중 확인된 fixture 미결, Step 6 귀속):** `tunnel.open.json` golden fixture가 없다. `tunnel open --json`이 이제 진짜 envelope를 내지만, fixture를 뜨려면 `crates/qsh-testkit/src/fixtures.rs`의 `normalize`에 volatile field 세 개(`tunnel_id`는 ULID, `bind`·`forward_to`는 ephemeral 포트를 담는다)를 위한 arm이 새로 필요하다. fixture는 append-only라 나중에 추가해도 비용이 0이고 L5 e2e가 이미 그 envelope를 필드 단위로 단언하므로, 이 fixture는 계약 표면을 마감하는 Step 6에 귀속한다.
- **(구현 중 확정된 판정 2건, 계획 반영):** (1) workspace `tokio` floor를 `1`에서 `1.53`으로 올렸다 — splice의 RST teardown이 쓰는 비-deprecated `TcpStream::set_zero_linger`가 그 버전에서 온다. 새 의존은 없고(`tokio`는 이미 workspace 의존), `Cargo.lock`은 이미 1.53.1이며 `cargo deny check` green이다. **채택.** (2) `SystemDialer`가 resolve와 connect를 나누면서 `CONNECTION_FAILED` 외에 `HOST_NOT_FOUND`도 낼 수 있다 — 둘 다 이 마일스톤의 오류 어휘에 이미 있는 `ErrorCode` 값이고(`docs/CLI.md` §3.3) 새 코드는 만들지 않았다. **채택.**

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L3·L5):** L2 — inline ACL 유닛: `DenyAll` 하에서 `TCP_CONNECT`이 dial을 **한 번도** 호출하지 않고 §7의 거부 teardown으로 스트림을 종단(계측 mock으로 "dial 0건" 단언 — `fuzz_stream_header`의 "ACL 미통과 경로에서 socket 생성 0건" 불변식의 실물, §13), audit에 `action="forward.local"` allow/deny 라인. L3 — `crates/qsh-testkit/tests/tunnel_loopback.rs`: 로컬 echo 서버를 띄우고 client가 `-L`로 bind한 로컬 포트에 쓰면 echo가 왕복함, 목적지 dial 실패 시 `ConnectResult{ok:false, CONNECTION_FAILED}`. L5 — `crates/qsh-cli/tests/tunnel_e2e.rs`(DoD 1 마감): 실프로세스 `qsh serve` host + `qsh host -L 8080:127.0.0.1:<echo>` interactive client(pty 아래 `expectrl`) + host 측 echo 서버 → 로컬 8080에 `curl`/TCP write가 원격 echo에 도달. **port 0 bind로 실제 포트를 얻어** DoD의 `8080`은 예시일 뿐임을 하네스가 파라미터화.

**(d) 완료 판정:** **DoD 1(local leg) green** — forward 연결 위 `-L`로 로컬 포트가 원격 목적지에 도달. inline ACL이 dial 이전이고 거부 시 리소스 0. `Action::ALL`에 `forward.local` 포함·문자열 하드코딩 0. 렌더러/CLI에 인가·splice 로직 0줄(splice는 `qsh-core`). Windows leg nextest green(`tunnel/`은 `cfg(unix)` — Windows에서 컴파일만). **DEFERRED 판정:** `PERMISSION_DENIED`가 inline forward.local deny로 **producer**를 얻는다 — (c)의 테스트가 CLI 바이너리 `--json` envelope 캡처면 fixture 추가 + `DEFERRED` 제거, testkit 레벨뿐이면 사유 문자열만 갱신(M3 H1 규율).

**(e) 인용:** `docs/design/protocol.md` §7(`TCP_CONNECT` inline `forward.local` 예외·`ConnectResult`), §5(raw byte 파이프), §12(우선순위), `docs/CLI.md` §2.5(`tunnel.open` local→`forward.local`)·§4·§6.9·§7, `docs/PRD.md` §9(인증 전 리소스 금지·action 목록), §13, `docs/design/architecture.md` §6(단일 choke point·`auth_path`)·§3, `docs/ROADMAP.md` M4 DoD 1·§1 원칙 5.

---

### Step 4 — Remote forward (`-R`): `RemoteForwardOpen` choke-point + **loopback-only bind** + `TCP_ACCEPTED` 스트림 — **DoD 2**

**(a) 범위:** forward 연결 위의 `-R`을 완성한다. reverse 위의 `-R`(진짜 novel 케이스)은 Step 5다.

**ACL.** `acl::Action`에 `ForwardRemote`(`"forward.remote"`) 추가, `ALL` 늘림.

**요청자(client) 측.** `-R [bind:]rport:host:hport`를 파싱해 `RemoteForwardOpen{bind_host, bind_port=rport, forward_host=host, forward_port=hport}`를 control 스트림으로 보낸다. host의 `RemoteForwardOpened{forward_id, actual_port}` 또는 `Error`를 받는다. 이후 host가 여는 `TCP_ACCEPTED{forward_id}` 스트림을 accept해 `host:hport`(요청자 로컬)로 dial하고 splice — **요청자가 이 leg에선 목적지를 dial하는 쪽**이다.

**host 측 — choke point ACL + loopback 강제.** `RemoteForwardOpen`을 받으면 **리스너 bind 이전** `Authorizer::check(principal, auth_path, Action::ForwardRemote, resource = "bind_host:bind_port")` + audit(`server::dispatch`의 기존 choke point 패턴 복제 — session/exec op와 같은 자리). deny면 `Error{PERMISSION_DENIED}`, **bind 0**. 통과 후 **loopback 강제**: `bind_host`가 loopback(`127.0.0.0/8`·`::1`)이 아니면 `Error{INVALID_ARGUMENT, "remote forward binds loopback only"}` — **bind 0**(`docs/PRD.md` §9 "Remote forwarding은 기본적으로 loopback에만 bind한다", **DoD 2**). loopback이면 bind하고 `forward_id` 발급, `RemoteForwardOpened{forward_id, actual_port}` 반환(`actual_port`는 bind_port 0 요청 시 커널 배정 포트). bind한 리스너에 들어온 연결마다 `open_stream(link, StreamHeader{TCP_ACCEPTED, forward_id})`로 요청자에게 스트림을 **연다**(host가 여는 쪽). `RemoteForwardClose{forward_id}` 또는 연결 종료 시 리스너를 닫는다(연결-결합 수명, §3).

**loopback-only가 ACL이 아니라 `INVALID_ARGUMENT`인 이유**를 주석·문서에 못박는다: 같은 principal이 `forward.remote`를 **가져도** non-loopback bind는 통과 못 한다 — 이것은 principal 판정(ACL)이 아니라 요청 제약(host 하드코딩)이다. non-loopback bind(ssh `GatewayPorts` 류)는 §3 명시적 non-goal(P1). **DoD 2의 명시적 거부 테스트**가 이 지점을 단언한다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/acl/mod.rs` (확장 — `Action::ForwardRemote`)
- `crates/qsh-core/src/tunnel/remote.rs` (신규 — `RemoteForwardOpen` 처리, loopback 강제, remote 리스너 accept, `TCP_ACCEPTED` 오픈)
- `crates/qsh-core/src/server/mod.rs`/dispatch (확장 — `RemoteForwardOpen/Close` 라우팅, choke point)
- `crates/qsh-core/src/client/mod.rs` (확장 — `RemoteForwardOpened` 수신 + `TCP_ACCEPTED` accept + 요청자 측 dial)
- `crates/qsh-cli/src/cli.rs`, `src/main.rs` (확장 — `-R`, `qsh tunnel open --remote`)

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L3·L5):** L2 — choke point 유닛: `DenyAll` 하 `RemoteForwardOpen`이 리스너를 **한 번도 bind하지 않음**(mock으로 "bind 0" 단언), audit `action="forward.remote"` allow/deny. **loopback 강제 표**: `127.0.0.1`/`::1`/`localhost`(해석 후 loopback) → 허용; `0.0.0.0`/`::`/공인 IP/실제 인터페이스 주소 → `INVALID_ARGUMENT` + **bind 0**(**DoD 2**). L3 — `crates/qsh-testkit/tests/tunnel_remote_loopback.rs`: host가 loopback 포트를 bind하고, host 측에서 그 포트에 연결하면 요청자 측 echo에 도달, `RemoteForwardClose`로 리스너가 닫힘. L5 — `qsh serve` host + `qsh host -R <rport>:127.0.0.1:<echo>` client의 실프로세스 왕복.

**(d) 완료 판정:** **DoD 2 green**(non-loopback `-R` bind가 `INVALID_ARGUMENT`로 거부되고 bind 0을 단언하는 명시적 테스트). forward 연결 위 `-R`로 host 측 loopback 포트가 요청자 목적지에 도달. choke point가 bind 이전. `Action::ALL`에 `forward.remote` 포함. Windows leg nextest green. **DEFERRED 판정:** `PERMISSION_DENIED`(forward.remote deny)·`INVALID_ARGUMENT`(non-loopback)가 producer를 얻음 — CLI envelope 캡처 여부로 fixture/DEFERRED 처리(H1).

**(e) 인용:** `docs/design/protocol.md` §7(`TCP_ACCEPTED`·`RemoteForwardOpen`), §9, §11 머리말(대칭 — 요청 수신자가 자기 ACL 평가), `docs/CLI.md` §2.5(`tunnel.open` remote→`forward.remote`)·§6.9, `docs/PRD.md` §9(loopback bind·인증 전 리소스 금지), §13, `docs/design/architecture.md` §6(choke point는 리소스 생성 이전), `docs/ROADMAP.md` M4 DoD 2·범위(§9 loopback).

---

### Step 5 — reverse 연결 위 `-L`/`-R` + localctl 터널 conduit + `qsh tunnels`/`qsh tunnel close` — **"forward/reverse 양쪽" 범위 마감**

> **이 step은 두 PR로 올린다.** (i) **PR 5a — reverse 위 터널 데이터 경로**: localctl `LOCAL_STREAM` conduit이 `TCP_CONNECT`/`TCP_ACCEPTED`를 relay, `-R over reverse`의 스트림 방향(host=target이 여는 `TCP_ACCEPTED`가 데몬을 거쳐 controller CLI로) 실물화. 완료 판정 = reverse 하네스 위에서 `-L`·`-R` 양방향 splice green. (ii) **PR 5b — 관리 op**: `Ops::tunnel_open`/`tunnel_list`/`tunnel_close`, `LocalTunnelList` admin, `qsh tunnels`/`qsh tunnel close`, 렌더러, fixture. 완료 판정 = 아래 (d). 두 PR 모두 §2 공통 게이트를 각각 통과.

**(a) 범위:** M4의 **진짜 흥미로운 케이스**(ROADMAP §1 원칙 4번). M3가 깐 role 축(연결 방향 ⊥ 세션 역할)과 localctl seam 위에 터널을 얹어 **forward·reverse 연결 양쪽에서** 동작시킨다.

**`-R over reverse`가 왜 novel인가.** reverse 토폴로지에서 **target = host(dialer)**, **controller = client(responder)**다. controller에서 `-R`을 걸면 "**host(=target)** 측에 포트를 bind하고 **client(=controller)** 측으로 되돌린다"는 뜻이다. §11 대칭 원칙상 controller(client role)가 `RemoteForwardOpen`을 target(host role)에게 보내고, target이 loopback 포트를 bind해 `TCP_ACCEPTED{forward_id}` 스트림을 **controller 쪽으로 연다** — 그런데 그 스트림은 target→controller **reverse** QUIC 연결 위를 흐르고, controller의 CLI 프로세스는 TLS endpoint가 아니라 상주 `qsh listen` 데몬을 거친다. 따라서 데몬은 target이 연 `TCP_ACCEPTED` 스트림을 받아 **해당 `forward_id`를 등록한 CLI conduit으로** relay해야 한다. 이것이 M3 Step 6의 request_id 재매핑·event 라우팅과 동형의 **세 번째 다중화 상태**다. `-L over reverse`는 대칭: controller(client)가 자기 로컬 포트를 bind하고 연결마다 `TCP_CONNECT`을 target(host)에게 데몬 relay로 보낸다.

**localctl 터널 conduit(PR 5a).** M3의 `LOCAL_STREAM` conduit(다음 frame이 wire `StreamHeader`인 data 스트림)을 재사용 — `StreamHeader{TCP_CONNECT}`/`{TCP_ACCEPTED}`도 같은 conduit으로 흐른다(Step 1이 명문화). 데몬은 (i) CLI가 `LOCAL_STREAM`+`TCP_CONNECT`을 열면 host QUIC 연결 위에 새 bidi를 열어 byte splice, (ii) target이 reverse 연결 위에서 `TCP_ACCEPTED{forward_id}` 스트림을 열면 그 `forward_id`를 `RemoteForwardOpen 시 등록해 둔 CLI conduit`으로 splice. **데몬은 터널 payload를 파싱·로그하지 않는다**(M3의 세션 splice와 같은 순수성). in-flight 터널 스트림 총량은 `MAX_INFLIGHT_LONG_POLL_PER_HUB`와 동형의 hub 상한(`MAX_TUNNEL_STREAMS_PER_HUB`)으로 묶어 한 CLI가 공유 reverse 연결을 소진하지 못하게 한다.

**관리 op(PR 5b).** `Ops::tunnel_open`(route-aware — `resolve_host_route`로 forward/reverse 갈라짐, M3 Step 6의 `Ops::connect` 패턴 그대로)·`tunnel_list`·`tunnel_close`. `qsh tunnels`는 localctl `LocalTunnelList`로 상주 데몬이 쥔 터널을 조회(architecture.md §3의 "`qsh tunnels`는 그 다음 소비자"). `qsh tunnel close <id>`는 소유 검사("해당 tunnel의 소유 peer이면 허용", §2.5) 후 local forward면 로컬 리스너 close, remote forward면 `RemoteForwardClose{forward_id}` 송신. **holder 수명 모델(§4.1 #1, foreground 채택)이 이 op들의 정확한 의미를 정한다** — reverse 경로는 상주 `qsh listen` 데몬이 자연스러운 holder이고, forward 경로의 standalone `qsh tunnel open` holder는 §4.1 #1 결정에 종속된다.

**writer lease/소유 불변식(M3 Step 6에서 상속).** 터널은 writer lease를 쓰지 않지만(세션 전용), reverse 경로에서 터널 리스너의 수명이 **데몬의 reverse 연결**에 결합된다는 성질은 세션과 같다(CLI가 죽어도 데몬 연결이 살아 있으면 리스너 유지; reverse 연결이 죽으면 §3대로 정리). 이 관찰 가능한 차이를 `docs/CLI.md` §6.13/§6.9에 문서화한다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/localctl/daemon.rs`, `client.rs` (확장 — 터널 conduit relay, `forward_id`↔conduit 등록표, `LocalTunnelList`)
- `crates/qsh-core/src/tunnel/{local,remote}.rs` (확장 — link 경유로 route-aware)
- `crates/qsh-core/src/ops/tunnel.rs` (신규 — `TunnelOpenOp`/`TunnelListOp`/`TunnelCloseOp` 마커 + `Ops::tunnel_*`; `ops/host.rs`가 템플릿)
- `crates/qsh-core/src/ops/mod.rs` (확장 — `pub mod tunnel;`, `Ops` 메서드)
- `crates/qsh-cli/src/cli.rs`, `src/main.rs`, `src/render/{human,json}.rs` (확장 — `Command::Tunnel(TunnelCmd)`, `Command::Tunnels`)
- `crates/qsh-cli/tests/fixtures/cli-v1/{tunnel.open,tunnel.list,tunnel.close}.json` (신규 append-only)
- `crates/qsh-testkit/src/tunnel.rs` (확장 — reverse 하네스 위 터널: target(host) ← 데몬 ← CLI 3자)
- `docs/CLI.md` §6.9/§6.13, `docs/design/protocol.md` §11-3 (갱신 — 규칙이 Step 1 기술과 어긋나면 문서 먼저)

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L3·L6):** L2 — 터널 relay **적대적** 유닛(M3 mux 규율 상속): 두 CLI conduit이 각자의 `forward_id` 스트림을 받고 **교차 splice 0건**(잘못된 conduit으로 새지 않음), conduit 사망 시 대응 QUIC 스트림 reset + `forward_id` 등록표 전량 정리, hub 상한 초과 시 `RESOURCE_EXHAUSTED`. L3 — `crates/qsh-testkit/tests/reverse_tunnel.rs`: `ReverseHarness` 위에서 (i) `-L over reverse`(controller 로컬 포트 → target host echo), (ii) **`-R over reverse`**(controller가 `RemoteForwardOpen` → target이 loopback bind → `TCP_ACCEPTED`가 데몬 거쳐 controller CLI로 → controller 목적지 echo 왕복), (iii) target이 여는 `TCP_ACCEPTED` 스트림이 **올바른 conduit으로만** 도착. **role 축 독립성의 기계적 증명**: forward/reverse 두 route로 **같은 시나리오 함수**를 파라미터화. L6 — 신규 fixture 3종이 schemars 스키마 통과 + 기존 fixture 전부 유효(append-only), 생성 스키마·fixture·localctl 프레임에 payload/토큰 문자열 부재.

**(d) 완료 판정:** **"forward/reverse 연결 양쪽에서 동작" 범위 마감** — `-L`·`-R`가 두 route로 결정적 green. `qsh tunnels`가 데몬이 쥔 터널을 조회하고 `qsh tunnel close`가 소유 검사 후 닫음. `qsh-cli`에 인가·splice·소켓 로직 0줄(arch-lint 강제 — M3의 UDS ban을 터널 relay에도 확장). Windows leg nextest green(터널 relay·host 경로는 `cfg(unix)`). **DEFERRED 판정:** `RESOURCE_EXHAUSTED`(hub 상한)·`PERMISSION_DENIED`가 producer를 얻음 — CLI envelope 캡처 여부로 처리(H1).

**(e) 인용:** `docs/design/protocol.md` §7·§11 머리말(대칭·요청 수신자가 자기 ACL 평가)·§11-3(localctl conduit·다중화·`LOCAL_STREAM`), §12, `docs/CLI.md` §2.5(`tunnel.close`/`tunnel.list` 소유 peer)·§6.9·§6.13·§11(frontend 제약), `docs/design/architecture.md` §2·§3(`qsh tunnels`는 다음 소비자·Supervisor seam), `docs/ROADMAP.md` M4 범위(forward/reverse 양쪽)·§1 원칙 4·5, ADR-0005·ADR-0007.

---

### Step 6 — `-D`(SOCKS) UNSUPPORTED stub + 계약 표면 마감(exit-code matrix·jsonl 순수성) — **DoD 5**

**(a) 범위:** P1 유예 표면을 계약대로 닫고, M4가 새로 낸 오류 경로를 exit-code/jsonl 게이트에 등록한다.

**`-D` stub.** `-D [bind:]port`를 `InteractiveArgs`(및 `qsh tunnel open`의 해당 flag)에 clap으로 추가해 **파싱은 되되**, 실행 시 항상 `UNSUPPORTED` + "SOCKS dynamic forwarding (-D) is a P1 feature" 메시지를 내고 **리소스 생성 0**(리스너 bind 없음) — §4.2에서 확정한 문구이며 `qsh-core`의 `DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE` 상수가 정본이다. `forward.socks` ACL action은 M4가 만들지 않는다 — `-D`는 ACL 이전 CLI/negotiation 계층에서 `UNSUPPORTED`이고, `forward.socks` 어휘는 M5가 "정의하되 항상 deny"로 승격한다(`docs/ROADMAP.md` M5 범위). `docs/CLI.md` §6.9의 "`-D`는 parsing되되 P0에서 `UNSUPPORTED`" 문장의 이행. 대화형 form 한정으로 우선순위가 하나 더 있다: `--json`/`--jsonl`이 동반되면 `-D`의 `UNSUPPORTED`보다 §7의 `INVALID_ARGUMENT`가 우선한다 — 대화형 form에는 애초에 machine mode가 없기 때문이다(adversarial review 결정, `docs/CLI.md` §6.9 갱신 반영).

**계약 표면 마감.** exit-code matrix(`exit_code_matrix.rs`)에 envelope를 내는 터널 op 행 추가(미해석 host `tunnel open` → 255/`HOST_NOT_FOUND`, non-loopback `-R` → 255/`INVALID_ARGUMENT`, `-D` → 255/`UNSUPPORTED`, 존재하지 않는 `tunnel close <id>` → 0/`ok:true, data.closed:false` — `docs/CLI.md` §6.9의 멱등 계약; 초안에 적어 두었던 255는 CLI.md가 확정한 계약에 밀려 폐기한다). `--jsonl` 순수성 스위트에 터널 진행 중(`qsh::tunnel` stderr 진단이 도는) 세션 행 추가 — stdout이 여전히 순수 JSON. §2 DEFERRED 규율(H1)에 따라 이 step에서 `UNSUPPORTED` 등이 처음 CLI 바이너리 envelope를 얻으면 fixture 추가 + `DEFERRED` 제거.

**(b) crate/모듈/파일:**
- `crates/qsh-cli/src/cli.rs` (확장 — `-D` flag, 반복 가능; `InteractiveArgs`·`TunnelOpenArgs`)
- `crates/qsh-cli/src/main.rs` 또는 `qsh-core` (확장 — `-D` → `UNSUPPORTED` 경로, 리소스 0)
- `crates/qsh-cli/tests/exit_code_matrix.rs`, `tests/jsonl_purity.rs` (확장)
- `crates/qsh-cli/tests/fixtures/cli-v1/error.UNSUPPORTED.json` 등 (신규 append-only, 필요 시)

**(c) 빚지는 테스트 (`docs/design/testing.md` L6):** `-D 1080` → exit 255 + `ok:false` + `error.code == "UNSUPPORTED"` + 메시지에 "P1", **리스너 bind 0**(mock/포트 미점유 단언). exit-code matrix가 human/JSON 두 모드에서 같은 exit code. jsonl 순수성이 터널 진행 중에도 유지.

**(d) 완료 판정:** **DoD 5 green**(`-D 1080` → `UNSUPPORTED` + "P1", 리소스 0). exit-code matrix·jsonl 게이트에 터널 행이 들어감. `forward.socks` Action이 M4에 생기지 않음(M5 몫). Windows leg nextest green(`-D` stub은 플랫폼 무관 — Windows에서도 실행됨). **DEFERRED 판정:** `UNSUPPORTED`가 CLI envelope producer를 얻으면 fixture 등록.

**(e) 인용:** `docs/CLI.md` §2.4(long-running vs operation)·§3.3(`UNSUPPORTED`)·§4(exit code)·§6.9(`-D` parsing되되 UNSUPPORTED)·§7(flag scope), `docs/PRD.md` §11(`-D` P1)·§9(`forward.socks`는 M5 어휘), `docs/design/testing.md` L6, `docs/ROADMAP.md` M4 DoD 5·명시적 out(SOCKS P1)·M5 범위(`forward.socks` 항상 deny).

---

### Step 7 — Perf 게이트: throughput ≥ raw-quinn 80%(same-process) + 1GB 포화 터널 병행 PTY echo p95 — **DoD 3·4**

**(a) 범위:** M4의 두 성능 DoD를 닫는다. testing.md L10("perf는 PR 게이트 금지")과 ROADMAP M4 DoD·protocol.md §12("CI 조기 도입, M4 수용 기준")의 긴장을 **M3의 60초 blackout 이중 게이트 선례**로 해소한다(§4.1 #7).

**DoD 3 — throughput 비율(same-process, 결정적).** 같은 프로세스·같은 실행에서 (i) raw-quinn bidi 스트림으로 N바이트, (ii) 터널 스트림으로 같은 N바이트를 전송해 처리량 비율을 재고 **터널 ≥ raw-quinn × 0.80**을 단언. testing.md L10이 "runner 무관하므로 실제로 CI 가능"이라 명시한 유일한 CI-able perf 형태 — 절대값이 아니라 비율이라 공유 runner에서도 안정적. GHA macOS runner의 작은 UDP 소켓 버퍼는 `SO_RCVBUF` 명시 설정으로 보정(testing.md CI 규율).

**DoD 4 — 포화 터널 병행 PTY echo p95(통합 벤치).** 1GB(또는 시간-유계 등가) 포화 터널 전송과 **동시에** PTY echo 왕복을 반복 측정해 **p95 < 측정 loopback RTT + 10 ms**를 단언. 산식은 testing.md L10 그대로: `(client 수신 시각 − pty write 시각 − 측정된 loopback RTT) < 10 ms`. loopback RTT를 측정값으로 빼므로 runner 절대속도에 관대하다. 이 벤치가 Step 2의 우선순위 band·비대칭 window·BBR·`send_fairness`가 실제로 PTY를 보호함을 증명한다(§12 bufferbloat 대응의 검증).

**게이트 배치(§4.1 #7).** 두 측정 모두 **PR 유닛 스위트에 넣지 않는다**(testing.md L10 "PR 게이트 금지"). 대신 M3의 `acceptance` job(= `ci-ok`가 `needs`로 요구) 위에 `QSH_ACCEPTANCE_SLOW`/`QSH_ACCEPTANCE_STRICT`로 게이트한다 — 상시 게이트이되 매 PR의 유닛 시간을 태우지 않는다. **이것은 testing.md L10 "perf는 nightly only"에 대한 명시적 개정**이므로 그 문장을 "비율 throughput과 echo-under-load p95는 M4 수용 기준으로 `acceptance` job에서 상시 게이트; 절대 throughput 추세는 여전히 nightly"로 고친다(§4.1 #7, 문서 먼저). PR 유닛에는 우선순위·window 설정이 존재함을 확인하는 **저비용 smoke**(Step 2가 이미 가진 것)만 둔다.

**(b) crate/모듈/파일:**
- `crates/qsh-testkit/tests/tunnel_throughput.rs` (신규 — same-process raw-quinn vs 터널 비율, DoD 3)
- `crates/qsh-cli/tests/tunnel_echo_under_load.rs` 또는 `qsh-testkit` (신규 — 포화 터널 병행 PTY echo p95, DoD 4)
- `.github/workflows/ci.yml` (확장 — `acceptance` job에 두 게이트 추가)
- `docs/design/testing.md` L10 (개정 — 위 게이트 배치)

**(c) 빚지는 테스트 (`docs/design/testing.md` L9/L10):** 위 두 게이트. 비율 게이트는 seed·반복으로 flake 방어, echo 게이트는 loopback RTT 측정을 테스트 내에서 수행(외부 상수 금지). 두 게이트 모두 실패 메시지에 실측 수치·비율을 출력.

**(d) 완료 판정:** **DoD 3·4 green** — `acceptance` job 로그가 두 수용 기준의 정본. 비율 부등식·p95 부등식이 주석이 아니라 assertion. testing.md L10 개정이 같은 PR에 포함. Windows leg nextest green(perf 하네스가 unix 전용이면 컴파일만; 가능하면 throughput 비율은 플랫폼 무관하게 실행).

**(e) 인용:** `docs/design/protocol.md` §12(우선순위·bufferbloat·"CI 조기 도입, M4 수용 기준"), §2(BBR·fairness), `docs/PRD.md` §13(느린 터널이 PTY를 block하지 않음·throughput ≥80%)·§15(idle listener·perf 목표), `docs/design/testing.md` L9/L10(비율 게이트·p95 산식·"perf PR 게이트 금지"의 개정)·CI 규율(`SO_RCVBUF`), `docs/ROADMAP.md` M4 DoD 3·4.

**(a)-추기 — 실측 및 최종값 (2026-08-27, adversarial review 반영).**
- **상수 최종값.** `TUNNEL_STREAM_RECEIVE_WINDOW = 2 MiB`(§12 대역 2–4 MB 내, quinn 기본 STREAM_RWND 1,250,000 초과) — Step 2 잠정치 4 MiB에서 하향. 첫 구현이 골랐던 128 KiB는 기각: connection-wide라 연결 위 모든 스트림(PTY/exec/replay 포함)의 처리량 상한(≈2.6 MB/s@50ms)이 되고, loopback 기준 DoD 3 게이트는 기준선과 터널 다리가 같은 window를 공유해 이 리그레션을 구조적으로 못 본다 — 그래서 `qsh-transport`에 floor assertion(quinn 기본값 1,250,000 이상)을 별도로 뒀다. UDP 소켓 버퍼는 window와 분리, OS 기본값을 절대 낮추지 않는 하향 ladder(8/4/2/1 MiB, `bind_tuned_udp_socket`) — dial·listen·migration rebind(`qsh-core::client::reconnect`) 세 경로 통일(첫 구현의 고정 128 KiB는 macOS 기본 768 KiB를 6배 축소하는 역방향이었음). `SEND_DEPTH_CAP_BYTES = 128 KiB`(`qsh_core::tunnel::splice`) — §12 비대칭의 실제 구현체(송신측 큐 깊이/양보 주기).
- **DoD 3 게이트를 실패 가능하게.** raw-quinn 기준선을 qsh 자체 `transport_config()`가 아닌 stock quinn(`TransportConfig::default()`, 신규 `dial_stock_transport`/`bind_stock_transport`)으로 교체하고 trial을 raw/tunnel 교대 실행으로 바꿔 runner drift를 상쇄. 최종 상수 기준 STRICT 6회 ratio {0.899, 0.927, 0.942, 0.945, 0.909, 0.938} — strict 0.80 유지(§4.2 초안 그대로), smoke 0.50 유지.
- **DoD 4 방향/지표 수정 + 실측.** 포화 방향을 host→client로 교정(신규 `FloodServer` — PTY 출력과 실제로 경쟁하는 곳은 호스트의 송신 스케줄러), 지표를 client 기점 진짜 왕복(`margin = (recv−send) − rtt`)으로 교체(구 지표는 편도 leg에서 왕복 RTT를 빼는 차원 오류 — min=0.000ms가 그 지문). cap 없이 2 MiB에서 p95=30.579ms로 우선순위 band 단독 부족이 실측 확인 → cap 256 KiB p95=10.085ms(미달), 64 KiB p95=5.480ms이나 DoD 3 ratio 0.799 이탈, **128 KiB 채택**: 6회 p95 {7.919, 7.621, 7.672, 7.766, 7.146, 7.589}ms, 같은 실행의 DoD 3 ratio 전부 floor 상회. 1GB 고정 바이트 대신 **15s 시간-유계 + MIN_SAMPLES=200 floor** 채택(CI 시간 예산, M3 60s blackout 선례 아래).

---

### Step 8 — 터널의 resume/chaos 거동 확정 + 문서·README 동기화 + M4 마감

**(a) 범위:** 연결 손실·migration 하 열린 터널의 **정의된 거동**을 테스트로 못박고, 문서·README를 M4 실태에 맞춘다. "마일스톤 마감 공통 절차"(ROADMAP §2)의 이행이다.

**터널의 resume 거동(정의 + 테스트).** 터널은 세션과 **다르게** 산다 — replay ring이 없으므로(ADR-0004는 세션 output 전용) byte-exact resume이 **불가능**하다. 정의:
- **migration(QUIC path rebind, chaos `repath()`)**: 같은 QUIC 연결이므로 터널 스트림이 **투명하게 생존**한다 — 진행 중 전송이 path 전환을 넘어 이어진다. 이것이 quinn migration의 이득이며 별도 코드 불요. 테스트로 단언한다.
- **연결 손실 → 재dial/resume(chaos `sever()`)**: PTY 세션은 §10으로 resume하지만 **터널 스트림은 resume하지 않는다** — in-flight 터널 TCP 연결은 로컬 소켓을 정리해 **깨끗하게 종료**(hang·panic 금지, 명확한 종료). 리스너 수명: local forward 리스너는 holder(§4.1 #1)가 살아 있으면 유지되어 재연결 후 새 TCP 연결이 새 스트림을 연다; remote forward 리스너는 연결에 결합되므로 연결 손실 시 host가 정리하고, 요청자는 재연결 후 `RemoteForwardOpen`을 재발행해야 한다(자동 재발행 여부는 §4.2에서 확정). reverse 경로에선 데몬의 reverse 연결이 죽으면 그 host의 모든 터널 conduit이 명확한 typed error로 함께 끝난다(M3 Step 6의 conduit-사망 규율 상속).
- **PTY와의 공존**: 같은 연결 위 세션이 resume하는 동안 터널이 깨끗이 정리되고, 세션 resume이 터널 정리에 막히지 않음을 단언(우선순위·독립 스트림의 성질).

**문서·README.** `README.md` 기능 목록에 터널(`-L`/`-R`, loopback-only remote, `-D` P1) 추가·Known limitations(비-loopback remote bind 없음·SOCKS 없음·UDP forwarding 없음·터널은 resume 안 됨, migration은 생존) 갱신. `docs/CLI.md`·`docs/design/protocol.md`·`docs/design/architecture.md`가 Step 1–7에서 갱신된 것과 최종 구현 사이 어긋남 없는지 마감 대조. **구속 문서 태그 대조**(ROADMAP §2 절차 1): `docs/CLI.md`·`docs/PRD.md`·`docs/adr/`에서 M4로 태그됐거나 M4가 계약으로 확정한 문장이 전부 DoD로 검증됐거나 후속 마일스톤에 명시 귀속된 유예인지 확인.

**(b) crate/모듈/파일:**
- `crates/qsh-testkit/tests/tunnel_chaos.rs` (신규 — `repath()` 생존·`sever()` 정리, seeded)
- `crates/qsh-testkit/src/tunnel.rs`, `src/reverse.rs` (확장 — 터널 다리에 chaos proxy)
- `README.md`, `docs/CLI.md`, `docs/design/{protocol,architecture,testing}.md` (마감 대조·갱신)

**(c) 빚지는 테스트 (`docs/design/testing.md` L4·L6):** L4 — chaos: `repath()` 중 터널 전송이 byte-loss 0으로 이어짐(migration 생존), `sever()` 후 in-flight 터널이 명확히 종료되고 **같은 연결의 PTY 세션은 §10으로 resume**함(공존), reverse 연결 사망 시 그 host의 터널 conduit 전량 typed error 종료. L6 — README/문서 문구와 코드 상수(예: `-D`의 "P1" 메시지, loopback-only 메시지)가 일치(M3 Step 9의 doctor-docs 게이트와 동형; 갈라짐 방지).

**(d) 완료 판정:** 터널 resume/chaos 거동이 assertion으로 고정(migration 생존·sever 정리·PTY 공존). README·구속 문서가 M4 실태와 일치(태그 대조 통과). Windows leg nextest green. **DEFERRED 최종 판정:** M4 종료 시점의 `fixtures.rs` `DEFERRED` 상태를 §2 규율로 확정(어느 코드가 CLI envelope를 얻었고 어느 것이 유예인지).

**(e) 인용:** `docs/design/protocol.md` §2(migration은 지연 최적화)·§10(세션 resume은 터널 비대상)·§11-3(conduit 사망), ADR-0004(replay 세션 전용), `docs/design/testing.md` L4(chaos `repath`/`sever`)·L6, `docs/CLI.md` §6.9·§6.13, `docs/ROADMAP.md` M4 범위·§2 마일스톤 마감 공통 절차, `docs/PRD.md` §13.

---

## 3. 명시적 non-goals (M5+ / P1 유예)

`docs/ROADMAP.md` M4 절 "명시적 out" 인용: **SOCKS `-D`(P1), file copy, UDP forwarding.**

추가로 M4 범위에 넣지 않는 항목(같은 문서의 다른 조항에서 파생):

- **SOCKS5 dynamic forwarding(`-D`, P1)** — flag는 parsing되되 항상 `UNSUPPORTED`(Step 6). `forward.socks` ACL action은 M4가 만들지 않고 **M5가 "정의하되 항상 deny"로 승격**한다(`docs/ROADMAP.md` M5 범위). 리스너 bind·SOCKS 상태 기계 0줄.
- **file copy(`file.read`/`file.write`)·UDP forwarding** — P1/P2. `file.*` 어휘도 M5가 "정의하되 항상 deny"로만 넣는다.
- **non-loopback remote bind(ssh `GatewayPorts` 류)** — remote forward는 loopback-only(§9, DoD 2). 공인 인터페이스 bind는 P1 이상; M4는 non-loopback 요청을 `INVALID_ARGUMENT`로 **거부**만 한다.
- **agent forwarding·X11 forwarding** — `docs/PRD.md` 명시적 out.
- **ACL 정책 엔진(M5)** — `acl.toml` 로더·wildcard·`qsh acl check`. M4가 추가하는 것은 `Action::ForwardLocal`·`ForwardRemote` variant와 그 두 검사 지점뿐이고 정책은 여전히 `AllowAllPinned`.
- **client-측 상주 터널 데몬(미확정)** — §4.1 #1이 forward 경로의 standalone `qsh tunnel open` holder를 foreground로 확정하면 M4는 새 client 데몬을 만들지 않는다. resident holder 모델(B안)이 채택되면 그것은 별도 범위로 명시 승격해야 하며 **silent addition 금지**.
- **background service 설치·자동 시작** — M7 이후(`docs/PRD.md` 명시적 out).
- **`ControlLink`/`DataLink` enum → `Transport`/`StreamMux` trait 전환(ADR-0005 P0 부채)** — M3가 남긴 미이행 부채. M4는 터널 스트림을 이 enum 위에 얹되 trait 전환을 **트리거하지 않는다**(P1 TCP가 세 번째 구현으로 올 때). 이 부채의 존재를 여기 재기록해 M5/P1의 입력으로 넘긴다.
- **`session.signal`(wire 25)** — 그대로 P1 유예. Step 1은 `reserved 25`를 건드리지 않는다.
- **실기기 mobility 캠페인의 터널 leg** — M8. M4의 chaos·perf 게이트는 기능적 정확성/비율 검증이지 SC3의 통계 측정이 아니다.

**M5에 넘기는 것(지금 기록해 둔다):** (i) `forward.socks`·`file.*` 어휘의 "정의하되 항상 deny" 승격, (ii) `forward.local`/`forward.remote`의 TOML 정책 매칭(현재 검사 지점만 존재), (iii) 터널 관련 op 전수의 audit 완전성(SC6)이 M5의 op-registry 열거 테스트에 포함되는지 확인, (iv) reverse 경로 터널의 소유권 축(M3가 넣은 opener-principal 결합을 터널 `forward_id` 소유로 확장할지 — `tunnel.close`의 "소유 peer" 판정).

## 4. 리스크와 감시 항목

`docs/ROADMAP.md` §4 "일정 리스크" 및 architecture.md §9 중 M4 직결 항목 + M4 고유 감시:

- **인가 전 리소스 생성(가장 값비싼 오류).** 터널은 리소스 생성 지점이 **둘**(remote bind=choke point / local dial=스트림 inline)이라 M3보다 표면이 넓다. 감시: (a) `DenyAll` 하에서 `RemoteForwardOpen`이 bind 0·`TCP_CONNECT`이 dial 0임을 **계측 mock으로 단언**하는 테스트가 살아 있는가(구두 약속이면 지켜지지 않는다), (b) local forward의 inline 검사가 `ConnectResult` 이전이고 거부 시 dial 0이고 §7의 거부 teardown으로 종단되는가, (c) `fuzz_stream_header`의 "ACL 미통과 경로에서 리소스 생성 0" 불변식에 터널 socket이 포함되는가.
- **loopback-only 우회.** DoD 2의 핵심. 감시: `bind_host` 해석 후 loopback 판정이 문자열 비교가 아니라 실제 주소 분류인가(`localhost`→`127.0.0.1`, `0.0.0.0`/`::` 거부), 그리고 `forward.remote`를 가진 principal도 non-loopback을 통과 못 하는가(ACL과 제약의 분리).
- **remote forward 리스너 개수가 M4에서 무제한이다.** `forward.remote`를 가진 principal이 `RemoteForwardOpen`을 반복해서 보내면 매번 새 TCP listener·fd·`serve_remote_forward` task가 뜬다. `docs/design/protocol.md` §7의 "동시성 상한"(`MAX_CONCURRENT_BIDI_STREAMS = 1024`)은 concurrent `TCP_CONNECT`/`TCP_ACCEPTED` **스트림** 수만 묶을 뿐 listener 개수에는 적용되지 않는다 — 확인 완료(§7 본문에 이 구분을 명문화했다). principal별·forward별 할당량은 M5 정책 엔진 범위(§3 non-goals)이고 M4는 만들지 않는다. 감시: M5 착수 시 이 갭이 실제로 할당량 설계 입력에 들어가는가, 그 전까지 이 무제한이 CHANGELOG/보안 노트 등 사용자 대면 문서에서 조용히 "완료"로 읽히지 않는가.
- **터널 relay의 조용한 오배송(reverse 경로).** M3 mux와 같은 종류 — 한 CLI의 `forward_id` 스트림이 다른 CLI conduit으로 splice되면 **터널 내용이 잘못된 프로세스로 새는 보안 사건**이다. 감시: Step 5의 "두 conduit 교차 splice 0건" 적대적 테스트가 살아 있는가, conduit 사망 시 `forward_id` 등록표가 전량 정리되는가(누수 금지). 이 코드는 M8 stateful fuzzer 후보로 백로그에 남긴다.
- **`-R over reverse`의 스트림 방향 혼동.** target(host)이 여는 `TCP_ACCEPTED`가 reverse 연결 위를 흘러 데몬을 거쳐 CLI로 가는 경로가 정확한가. 감시: Step 1이 이 매핑을 protocol.md §11-3에 명문화했는가, Step 5의 `-R over reverse` L3 테스트가 실제로 존재하고 forward/reverse 파라미터화로 role 독립성을 증명하는가.
- **터널 payload 로그 금지.** splice는 순수 파이프 — 파싱도 로그도 하지 않는다. 감시: `qsh::tunnel` 진단이 host:port·forward_id·이벤트만 담고 payload byte를 담을 **필드 자체가 없는가**(M3 audit의 타입 수준 속성과 동형).
- **perf 게이트의 flake와 CI 시간.** DoD 3·4는 `acceptance` job에만 있고 PR 유닛에는 없다(testing.md L10). 감시: 비율 게이트가 절대값이 아니라 비율인가(runner 무관), echo 게이트가 loopback RTT를 실측하는가(외부 상수 금지), PR 유닛 총시간이 M3 대비 유의미하게 늘지 않는가.
- **우선순위/window 튜닝이 세션을 해치지 않는가.** Step 2가 비대칭 window·BBR를 켜면서 세션 backpressure·resume 거동이 바뀌면 M2/M3의 자산을 깨는 것이다. 감시: Step 2 완료 판정의 "기존 테스트 무수정 green".
- **Windows leg.** 터널 host/relay 경로는 `cfg(unix)` 위에 선다. 감시: 전 타깃 clippy green과 **Windows leg의 nextest green**이 매 step 완료 조건에 있는가, client-측 `-L` 로컬 bind의 Windows 가능 여부가 §4.1 #1 결정과 일관되게 처리됐는가.
- **holder 수명 모델(§4.1 #1)의 파급.** foreground form으로 확정됐으므로 Step 3·5의 CLI 표면·Windows 거동·`tunnel close`/`tunnels` 의미가 이 결정에 정합해야 한다. 감시: Step 1이 이 결정을 `.proto`·정본 문서에 **실제로 못박는가**(구현이 뒤에서 resident holder를 발명하지 않기).
- **M3 자산의 flake가 M4 step 완료를 막는 경우(Step 3에서 실측).** `qsh-cli::attach_ops a_teardown_waits_out_a_detach_that_is_still_flushing`이 Step 3 CI의 `ubuntu-24.04-arm` leg만 red로 만들었다. Step 3 회귀가 아니라 M3 테스트 자체의 결함이다. 원인은 `waited >= 1s`라는 벽시계 단언인데, detach의 flush가 2초(`DETACH_FLUSH`)를 쓰는 것은 드라이버가 detach 마커를 실제로 읽었을 때뿐이고, 드라이버가 이미 반환한 뒤라면 ack 채널이 끊겨 `recv_timeout`이 즉시 `Disconnected`를 준다. 이것도 정상 detach다. 단언을 시간이 아니라 순서로 바꿔 고쳤다(close는 detach가 gate를 놓은 뒤에만 반환한다). 남은 감시: 같은 드라이버-부재 상황에서 사전조건 루프의 `!detacher.is_finished()` 단언이 대신 터질 수 있다. CI에 나타나면 degenerate한 setup을 실패로 처리하지 말고 그 자체를 다뤄야 한다.
- **audit 기록이 '요청한 주소'지 '실제로 bind한 주소'가 아니다(Step 4 적대적 검토 잔여).** `forward.remote` 인가는 `bind_host:bind_port`를 요청 그대로 평가한다. 이건 맞다 — 커널이 배정한 ephemeral 포트를 알려면 먼저 bind해야 하고, 그건 '인가 전 리소스 생성 금지'를 정면으로 어긴다. 문제는 판정이 아니라 흔적이다. `RemoteForwardOpen{bind_host:"localhost", bind_port:0}`은 audit에 `localhost:0`으로 남지만 실제로 뜬 소켓은 `127.0.0.1:<ephemeral>`이라, 사고 조사에서 기록만 보고는 무엇이 열렸는지 알 수 없다. 인가 기록은 지금 형태를 유지하고, bind 성공 시점의 실제 주소를 남기는 구조적 기록을 Step 5에서 더한다(`qsh tunnels`가 bind된 주소를 사용자에게 보여주기 시작하는 지점이라 같은 정보가 어차피 필요하다). payload는 여전히 남기지 않는다.

- **PR 5a 최종 회귀 검사의 잔여 findings — 전부 가용성, isolation 아님(기록 확정).** 세 라운드의 적대적 검증 끝에 격리 불변식 4개(같은 lock 안의 admits_claim+pop, sealed ClaimSeat, 양방향 owner-checked close, 단일 forwards map)는 유지가 확인됐다. 남은 것들:
  - **per-conduit share가 principal이 아니라 conduit 단위다(F1).** 한 CLI 프로세스가 LOCAL_CONTROL conduit을 여러 개 열면(상한 256) share를 우회해 hub pool 전체를 채울 수 있다. protocol.md §11-3의 "conduit(=CLI 프로세스)" 괄호는 코드가 강제하지 않는 등식이다. principal 단위 할당량은 M5 정책 엔진의 입력 — 리스너 무제한 항목과 같은 설계 회의에서 다룬다.
  - **동시 `-R` 8개 상한과 그 너머의 조용한 실패(F3), tunnel-stream pool의 share 부재(F4).** 둘 다 M5 할당량 설계 입력. F3은 9번째 forward가 경합에서 계속 지는 동안 사용자에게 warn 로그 외 아무 신호가 없다는 UX 문제를 포함한다 — 5b의 `qsh tunnels`가 상태를 보여주기 시작하면 재평가.
  - **unregister가 pending_rfwd_open_claim_tokens를 즉시 안 지운다(F6, 위생).** 성장 누수는 아니고 (target 응답 시 정리) 토큰 바이트가 쓸모없어진 뒤에도 잠시 상주하는 문제.
  - **NotOwner 응답이 forward_id 존재 oracle이 될 수 있다(F7, 정보성).** forward_id가 128-bit ULID라 지금은 무해. 5b가 `LocalTunnelList`로 id를 노출하기 시작하면 permit 과금이 owner 기준이라는 점과 함께 재검토할 것.
  잔여 중 즉시 수정 대상 2건(F5 registration 스쿼팅 가드, F2 고아 parked claim의 permit 누수)은 5a 후속 커밋으로 처리한다 — 기록만 하고 넘어가기엔 상주 데몬의 수명에 직접 닿는다.
- **PR 5b 처리 기록과 신규 백로그(2026-08-25).** F5·F2는 후속 커밋으로 수정 완료(48fc38f). F7은 5b가 `LocalTunnelList`로 same-uid 조회 경로를 정식 제공하면서 무의미해졌다(코드 주석에 기록). F3은 여전히 열려 있다 — `LocalTunnel`에 liveness field가 없어 listing만으로는 기아 상태를 못 보인다(M5 할당량 설계에서 wire field 추가와 함께). 신규 백로그 1건: **죽은 claim conduit의 재수립 op이 없다(P1).** reverse `-R`의 CLI가 죽으면 listener는 데몬에 살아남지만 claim conduit이 없어 이후 `TCP_ACCEPTED`는 전부 즉시 reset된다. 같은 `forward_id`를 다시 claim하려면 `RemoteForwardOpen`이 기존 id를 받아들이는 새 wire 의미가 필요해 5b 범위 밖이었다(CLI.md §6.14가 "그런 op은 아직 없다"로 명문화). 현재 유일한 회복 경로는 `tunnel close` 후 새 `-R`. P1에서 wire 설계와 함께 다룬다.

### 4.1 이 계획이 확정한 결정 (Step 1이 정본 문서에 기록한다)

| # | 질문 | 초안 결정 | 정본 | 확정도 |
|---|---|---|---|---|
| 1 | `qsh tunnel open`이 operation(즉시 envelope)인가 foreground blocking인가 / forward 경로에 client 상주 데몬이 필요한가 | **초안:** DoD 1/2는 **interactive `qsh [user@]host -L/-R` foreground form**(PRD §131-135)이 마감(새 데몬 불요). standalone `qsh tunnel open`은 foreground blocking(envelope 1줄 출력 후 hold), reverse 경로는 상주 `qsh listen` 데몬이 holder. `qsh tunnels`/`tunnel close`는 데몬 있는 경우(reverse)에 완전, forward foreground는 SIGTERM/close로 종료 | CLI.md §6.9·§2.4, PRD §11·§13 | **확정**(main 채택: foreground form이 DoD 1/2 마감, 새 client 데몬 불요; 상주 holder는 별도 범위 승격 필요) |
| 2 | `reserved` 태그를 채우는 것이 additive 위반인가 | 아니다 — `ControlMessage 40/41`·`Response 4`는 주석이 이미 "(M4)"로 이름을 박아 둔 예약의 실현(M3 `Hello.reverse`와 동형) | wire/v1.proto 머리말, protocol.md §9 | 확정 |
| 3 | local forward 리스너의 client-측 bind 기본값 | 기본 loopback bind. non-loopback local bind(다른 기기가 이 로컬 포트를 쓰게)의 정책은 M4 범위 밖(loopback 고정, 필요 시 P1) | CLI.md §6.9, PRD §13 | 확정(main 채택: loopback 기본) |
| 4 | `-R over reverse`의 스트림 방향 매핑 | controller(client role)가 `RemoteForwardOpen`을 target(host)에게 보냄 → target이 loopback bind → target이 `TCP_ACCEPTED{forward_id}`를 **reverse 연결 위로** 열고 데몬이 등록한 CLI conduit으로 relay. `-L over reverse`는 대칭(controller가 로컬 bind, `TCP_CONNECT`을 데몬 relay로 target에) | protocol.md §11-3, §7 | 확정(문서화 필요) |
| 5 | loopback 아닌 remote bind의 오류 코드 | `INVALID_ARGUMENT`(요청 제약 위반 — 같은 principal이 `forward.remote`를 가져도 통과 못 함; ACL 판정이 아니다). `UNSUPPORTED`가 아닌 이유: 기능 미구현이 아니라 정책상 금지 | CLI.md §3.3, PRD §9 | 확정(main 채택: `INVALID_ARGUMENT` — 정책상 금지이지 미구현 아님) |
| 6 | 터널 데이터 conduit의 localctl kind | 새 `LocalStreamKind` 없음 — M3의 `LOCAL_STREAM`(다음 frame이 wire `StreamHeader`)을 재사용(`TCP_CONNECT`/`TCP_ACCEPTED`도 같은 conduit). `StreamKind`에 UDS 전용 값 추가 금지(§4.1 #6 M3 규율 상속) | protocol.md §11-3, local/v1.proto | 확정 |
| 7 | perf DoD를 무엇이 게이트하나 (testing.md L10 "PR 게이트 금지" vs protocol.md §12 "CI 조기 도입" vs ROADMAP M4 DoD) | **비율 throughput(same-process)과 echo-under-load p95 모두 `acceptance` job 상시 게이트**(M3 60초 blackout 선례), PR 유닛에는 저비용 smoke만. testing.md L10을 이 취지로 **개정**(문서 먼저) — 절대 throughput 추세만 nightly | testing.md L10, protocol.md §12, ROADMAP M4 DoD 3·4 | 확정(main 채택; testing.md L10 개정은 Step 7 적용 — Step 1–6 동안 veto 가능) |
| 8 | `ConnectResult`가 proto에 없다 | Step 1이 신규 정의(§7 표가 산문으로만 참조하던 것). frame layer §5 재사용, ok 이후 raw bytes | protocol.md §7, wire/v1.proto | 확정 |
| 9 | 새 ErrorCode가 필요한가 | 아니다 — `UNSUPPORTED`·`PERMISSION_DENIED`·`INVALID_ARGUMENT`·`RESOURCE_EXHAUSTED`·`CONNECTION_FAILED`·`HOST_NOT_FOUND` 전부 §3.3에 이미 있음 | CLI.md §3.3, error.rs | 확정 |
| 10 | `-L`/`-R`가 세션까지 여는가 | interactive `qsh [user@]host -L/-R`는 `SessionOpen`을 보냄(CLI.md §6 line 634 — 세션 + 터널). standalone `qsh tunnel open`은 bare host(세션 없음, 터널만) | CLI.md §7·§6.9 line 634 | 확정 |

### 4.2 구현 중 확정할 값 (측정 후 상수화)

문서가 값을 정하지 않았고 계약도 아닌 것들. 구현 시 정하고 **해당 step의 (a)에 실측 근거와 함께 추기**한다: 터널 스트림 receive window(**확정**: connection-wide 2 MiB + splice 송신측 depth cap 128 KiB — 수신측 per-kind 비대칭은 quinn 0.11에 API가 없어 불가, Step 7 (a)-추기와 `protocol.md` §12 참조), `MAX_TUNNEL_STREAMS_PER_HUB`(reverse relay 상한, 초안 M3 `MAX_INFLIGHT_LONG_POLL_PER_HUB`과 정합), `-D`의 정확한 "P1" 메시지 문구(**확정**: "SOCKS dynamic forwarding (-D) is a P1 feature", `qsh-core`의 `DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE` — Step 6), non-loopback `-R` 거부 메시지 문구, remote forward 리스너의 연결-손실 시 자동 재발행 여부(초안: 요청자가 재연결 후 재발행 — 자동 아님), DoD 3의 80% 마진에 대한 flake 여유(**확정**: strict 0.80·smoke 0.50 초안 그대로 — 최종 상수 실측 ratio 0.90±0.03, Step 7), DoD 4의 1GB를 시간-유계로 대체(**확정**: 15s 시간-유계 + MIN_SAMPLES=200 floor — Step 7).

## 5. 완료 절차

1. §1의 DoD 체크리스트 5항목 전건 통과를 **실제 테스트 실행 로그**로 확인한다(체크박스는 근거가 green일 때만; 각 항목에 "어느 Step이 심고 어느 테스트가 무엇을 단언하는지"를 M3본과 같은 상세도로 적는다). DoD 3·4의 perf 게이트는 `acceptance` job 성공 로그가 정본.
2. **구속 문서 태그 대조**(ROADMAP §2 절차 1): `docs/CLI.md`·`docs/PRD.md`·`docs/adr/`에서 M4로 태그됐거나 M4가 계약으로 확정한 문장이 전부 DoD로 검증됐거나 후속(M5) 유예로 명시 귀속됐는지 전수 대조. 어느 쪽도 아닌 문장이 하나라도 있으면 M4를 닫지 않는다.
3. **README 동기화**(ROADMAP §2 절차 2): 기능 목록·Known limitations·인터임 위험 고지를 M4 실태와 일치. 인터임 고지가 실제 권한보다 좁으면 그 자체가 결함.
4. `docs/ROADMAP.md`의 "현재 위치" 줄과 M4 절 상태 표기를 "M4 완료"로 갱신(로드맵 문서 소유자의 몫 — PLAN.md는 지시만 하고 대신 수정하지 않는다).
5. Step 1·7·8이 갱신한 정본 문서와 최종 구현 사이 어긋남 최종 대조 — 어긋나면 **문서를 먼저 고치고** 코드를 맞춘다(각 문서 머리말 규칙).
6. 이 PLAN.md를 M5("ACL 정책 + audit") 실행 계획으로 전면 교체 — 과거 M4 계획은 git 이력에만. §3의 "M5에 넘기는 것" 네 항목을 그 계획의 입력으로 옮긴다.
