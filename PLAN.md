# PLAN.md — M3 실행 계획

이 문서는 **현재 마일스톤(M3 — 역방향)의 실행 계획**이다. 마일스톤 정의(범위·수용 기준·크기)의 정본은 항상 [`docs/ROADMAP.md`](docs/ROADMAP.md)이며, 이 문서는 그 정의를 바꾸지 않고 실행 순서로 분해한다. **M3가 Done 처리되면 이 문서는 다음 마일스톤(M4 — 터널)의 계획으로 전면 교체된다** — living doc이며 과거 마일스톤의 실행 기록으로 남기지 않는다.

## 1. M3 목표 요약

`docs/ROADMAP.md` "M3 — 역방향" 절 인용:

> - **범위:** `qsh listen`(controller), `qsh reverse controller`(target, 등록 + heartbeat + 백오프 재접속), `host.reverse` ACL action 검사 지점, reverse host가 `hosts`에 `connection_mode:"reverse"`로 표시, `qsh attach <name>`이 역방향 연결 위에서 동작. 연결 방향/세션 역할 축 실사용.
> - **감사 개정 (2026-08-21) 추가 범위:** ① **M2 계약 부채 상환** — `qsh serve`(및 M3의 두 상주 모드) SIGTERM graceful drain(`docs/CLI.md` §6.12 문장의 이행)과 `exec.run` 환경 위생(`env_clear` + 호스트 고정 key 재적용). ② **세션 소유권 P0** — `session.control` action(write/resize)을 세션 opener principal에 결합.
> - **명시적 out:** relay, NAT traversal, discovery.

### DoD 체크리스트 (`docs/ROADMAP.md` M3 "수용 기준" 인용)

- [ ] NAT 뒤 target이 `qsh reverse` → controller에서 `qsh attach`로 target의 셸 획득.
- [ ] target 네트워크를 60초 차단 → 재등록되고 **같은 세션**이 resume.
- [ ] `qsh hosts --json`이 forward/reverse를 함께 반환(§6.1).
- [ ] controller reachability 요구가 docs와 doctor 메시지에 명시.
- [ ] **(감사 개정)** 자식 셸이 살아 있는 `qsh serve`에 SIGTERM → 전 세션 close 절차 → `session.closed{reason:"closed"}` 송신 → drain 완료 후 잔존 자식 process group 0 (L5 실프로세스 테스트). `exec.run` 자식에서 serve 환경 마커가 보이지 않고 client의 `PATH` 지정이 무시됨.
- [ ] **(감사 개정)** 타 principal 세션에 대한 `session.write/resize`가 거부되고 audit에 deny가 남음(소유권 P0). 병렬 동시 등록(같은/다른 fingerprint)·병렬 다중 세션 경합 테스트가 존재.

M3 크기: 2ew + 0.5ew(감사 개정분) (`docs/ROADMAP.md` M3 "크기").

**DoD 1의 마감 도구를 미리 못박는다.** 낡은 `qsh attach <host-name>` 산문은 이 계획 밖에 **5곳** 남아 있다 — `docs/PRD.md:102`(`qsh attach company-mac`), `docs/ROADMAP.md:66`(M3 범위 줄의 `qsh attach <name>`), `docs/design/protocol.md` §11-3(`qsh attach company-mac`), `docs/design/architecture.md` §3(`qsh attach <reverse-host>`), `docs/adr/0003-sessions-in-listener.md`의 2026-08-18 추기(`qsh attach <reverse-host>`). 전부 `docs/CLI.md` §7 확정 **이전**의 산문이다. 현재 계약에서 `qsh attach`의 인자는 `session_ref`이고(§7, §7.1, PRD §11의 `qsh attach <session-ref>`), 슬래시 없는 host 이름으로 새 셸을 얻는 form은 `qsh [user@]<host>`다. M3는 **새 CLI form을 만들지 않는다**(§4.1 #1) — `<name>`이 forward든 reverse든 같은 host alias가 되게 만드는 것이 이 마일스톤의 일이고, DoD 1은 `qsh <name>`(신규 세션) + `qsh attach <name>/<session_id>`(재attach) 두 실프로세스 시나리오가 Step 7에서 마감한다. 위 5곳 중 Step 1이 `protocol.md` §11-3·`architecture.md` §3의 예시를 이 두 form으로 교체하고, Step 9가 `PRD.md` §6을 교체하며, ADR-0003 추기에는 결정을 재론하지 않고 표기만 정정하는 한 줄을 더한다. `ROADMAP.md:66`의 범위 줄 정정은 코드가 아니라 로드맵 문서 소유자의 몫이므로 §5 완료 절차 2번이 마감 조건으로 남긴다.

**M3가 새로 만드는 것은 방향뿐이다.** 세션 broker·PTY·resume·writer lease·replay ring·recovery 텔레메트리는 M2가 끝냈고, `docs/design/protocol.md` §11-4가 "target의 세션들은 재등록과 무관하게 유지되고 §10으로 resume된다"고 못박았으므로 **M3에 새 resume 로직은 없다**. M3가 지는 것은 (i) 연결 방향(initiator/responder)과 세션 역할(host/client)의 분리를 구조에서 실사용으로 바꾸는 일, (ii) 등록·인가·이름 배정·재등록 루프, (iii) 상주 `qsh listen` 데몬과 CLI 프로세스 사이의 `localctl` IPC — 세 가지다.

## 2. 작업 분해 (Step 1..9)

원칙: **모든 step은 완료 시점에 `cargo fmt --all` / `cargo clippy --workspace --all-targets -- -D warnings` / `cargo test`(또는 `cargo nextest run`) / `cargo run -p xtask -- arch` 전부 green을 유지해야 한다.** 이 게이트를 통과하지 못한 상태로 다음 step으로 넘어가지 않는다 (`CLAUDE.md` "Before committing"). clippy는 CI 5개 runner의 모든 타깃에서 green이어야 한다 — M3가 도입하는 UDS·PTY 코드는 전부 `cfg(unix)`이므로 Windows leg가 조용히 깨지기 쉬운 마일스톤이다(`docs/design/testing.md` CI 규율 "clippy는 **모든 타깃에서**").

각 step은 독립적으로 리뷰 가능한 PR 하나 크기다(예외는 Step 3·5 — 아래에 두 PR로 나누는 경계를 각각 명시한다). 순서는 **계약 → 축 분리 → headless 등록 → 재접속 루프 → localctl과 그 첫 소비자 → 다중화 → attach 마감 → resume → 문서·진단**이며, 그 안에서 위험한 미지수를 앞으로 당겼다:

1. **Step 1이 계약을 종이로 먼저 확정한다.** M3의 진짜 미지수 세 개 — localctl 메시지 집합(§11-3은 "§5와 동일한 frame layer"만 말하고 메시지가 비어 있다), heartbeat의 정체(ROADMAP만 그 단어를 쓴다), 역방향에서 §10 Reattach 절차(1–5단계)의 주체 — 를 `.proto`와 정본 문서에 못박아 구현이 계약을 발명하지 못하게 한다.
2. **Step 2가 축을 코드에 배선한다.** `docs/ROADMAP.md` §1 원칙 7(c)("connection 방향(initiator/responder)과 세션 역할(controller/target)을 독립 축으로 유지 (M3 reverse의 전제)")는 M1부터 지켜야 할 불변식이었지만 **코드에는 배선된 적이 없다**: `Server::serve_connection_inner`는 `conn.accept_bi()`(`crates/qsh-core/src/server/mod.rs:1303`), `client::Session::negotiate`는 `conn.open_bi()`(`crates/qsh-core/src/client/mod.rs:86`)로 연결 방향이 세션 역할에 붙어 있다. 역방향은 정확히 그 반대 조합(target = dialer이면서 host, controller = responder이면서 client)을 요구하므로, 이 분리 없이는 Step 3 이후 모든 코드가 우회로가 된다. M3에서 이 원칙의 매핑은 **controller = client role, target = host role**이다.
3. **재접속 루프(Step 4)를 localctl/attach보다 앞에 둔다.** NAT 뒤 장수명 연결이 M3의 진짜 제품 리스크이고, attach 없이도 register → lost → re-register 사이클을 관찰·게이트할 수 있다.
4. **역방향 resume(Step 8)은 attach(Step 7)에 의존해 마지막이지만 그 설계는 Step 1에서 확정한다** — §10 Reattach 절차(1–5단계)를 "target이 재dial하고 controller의 attach driver는 새 세대 등록을 기다린다"로 매핑한 문장을 `docs/design/protocol.md` §11에 기록하는 것이 Step 1의 산출물이다. 마지막 step에서 처음 생각하는 것을 금지한다.

`docs/ROADMAP.md` 시퀀싱 원칙 4번("역방향(M3)이 터널(M4)보다 먼저 — 터널은 role 모델 위에 얹힌다")이 이 마일스톤의 존재 이유이고, 원칙 5번("인가 **지점**은 M1부터, 정책 **엔진**은 M5")이 Step 3의 `host.reverse` 검사 지점을 M5의 정책 파일과 분리하는 근거다. 원칙 3번("headless로 먼저 검증 … 소비자는 얇게 나중에")이 Step 3–4 ↔ Step 6–7의 분리 근거다.

### 전 step 공통 계약 규율

- `qsh.cli/v1`·`qsh.event/v1`은 **additive-only**(optional 필드·새 event type·열린 문자열의 새 값만; 삭제·type 변경·의미 변경은 `/v2`), `crates/qsh-cli/tests/fixtures/cli-v1/`의 fixture는 **append-only**(기존 파일 편집·삭제 금지) — `docs/CLI.md` §10, `docs/design/testing.md` L6, `CLAUDE.md` "Contract stability rules". **이미 존재하는 fixture를 "신규"로 적지 않는다**: `error.HOST_NOT_FOUND.json`·`error.CONNECTION_FAILED.json`·`error.INVALID_ARGUMENT.json` 3개는 M1/M2에 이미 체크인돼 있으므로 M3는 그 파일을 건드리지 않는다. `PERMISSION_DENIED`·`UNSUPPORTED`·`RESOURCE_EXHAUSTED`는 fixture가 **없다** — `crates/qsh-cli/tests/fixtures.rs`의 `DEFERRED` 목록에 사유와 함께 등재돼 있을 뿐이다(fixture 없음 ≠ 코드에서 도달 불가). M3는 이 세 코드가 닿는 경로를 바꾸므로, (a) envelope를 내는 경로가 새로 생기면 append-only로 새 `error.<CODE>.json`을 추가하고 `DEFERRED`에서 제거해 `REQUIRED_FIXTURES`에 등록하고, (b) 여전히 envelope 없는 경로(장기 실행 모드, §2.4)뿐이면 `DEFERRED`의 사유 문자열만 M3 실태로 갱신한다. 어느 경로인지는 Step 5·6·7의 (d)가 각각 명시한다.
- wire(`qsh.wire.v1`)는 "additive only within v1 — never renumber or reuse a field/tag"(`crates/qsh-proto/proto/qsh/wire/v1.proto` 머리말). **`reserved` 태그를 그 태그가 예약된 바로 그 메시지로 채우는 것은 이 규칙 위반이 아니다** — 같은 머리말이 "Tunnel (M4) and reverse (M3) tags are `reserved` here so a later milestone cannot accidentally take them for something else"라고 용도를 명시했고, 재사용(다른 의미로의 전용)이 아니라 예약된 의미의 실현이기 때문이다. Step 1이 이 해석을 머리말에 한 줄로 명문화한다.
- **M3는 새 `ErrorCode`를 만들지 않는다.** 등록 거부 = `PERMISSION_DENIED`, 이름 충돌·모양 위반·미지 `LocalStreamKind` = `INVALID_ARGUMENT`, 미등록/미해석 host = `HOST_NOT_FOUND`, controller 도달 실패 = `CONNECTION_FAILED`, 역방향 등록을 지원하지 않는 peer·Windows의 `qsh listen`/`qsh reverse` = `UNSUPPORTED`, localctl in-flight 상한 초과 = `RESOURCE_EXHAUSTED`. 전부 `docs/CLI.md` §3.3에 이미 있는 어휘다(`CLAUDE.md` "never invent an ad hoc error string").
- 기계 모드 stdout은 순수 JSON만(`docs/CLI.md` §2.2). M3가 새로 만드는 진단(`qsh::reverse`, 확장된 `qsh::recovery`)은 전부 **stderr 한 줄 JSON**이며 payload·토큰 필드를 갖지 않는다.
- 테스트는 `sleep()` 금지, chaos는 seeded(실패 메시지에 seed 출력), 포트는 0 바인딩(`docs/design/testing.md` CI 규율). Step 8의 60초 수용 게이트만 벽시계를 쓰며 그 격리 방법을 그 step이 명시한다.
- **리소스는 인가 후에만 생성한다** — 역방향 등록(registry entry)도 예외가 아니다(`docs/PRD.md` §9 "인증 전에는 PTY, exec 또는 tunnel resource를 생성하지 않는다", `docs/design/architecture.md` §6, `CLAUDE.md` "Security defaults").
- **Windows leg.** localctl(UDS)과 host 역할(PTY)은 `cfg(unix)`이므로 M3 신규 코드의 실행 경로는 전부 unix 전용이다. Windows에서 `qsh listen`/`qsh reverse`는 리소스 생성 없이 `UNSUPPORTED` + exit 255이고, `qsh hosts`는 forward host만 반환하며(데몬 개념 없음) 오류가 아니다. **Windows CI leg는 clippy뿐 아니라 전체 `cargo nextest run --workspace` + doc-test가 돈다**(`.github/workflows/ci.yml`의 `test` job matrix, `docs/design/testing.md` "현재 상태") — M3가 새로 넣는 UDS·PTY 의존 테스트는 `cfg(unix)` 게이트를 빠뜨리면 **컴파일이 아니라 테스트 단계**에서 조용히 깨진다. 각 step의 완료 판정은 Windows leg의 nextest green을 포함한다.

---

### Step 1 — 계약 확정: `ReverseRegistration` wire 정의 + `qsh.local/v1` IPC 계약 + `host.*` JSON 타입 + 정본 문서 갱신

**(a) 범위:** M3가 구현 중에 발명하면 안 되는 것을 전부 이 step에서 계약으로 고정한다. 코드는 `qsh-proto`(sans-IO)와 문서만 건드린다.

*wire (`crates/qsh-proto/proto/qsh/wire/v1.proto`)*: `Hello`의 `reserved 4;`를 제거하고 `ReverseRegistration reverse = 4;`를 정의한다 — `message ReverseRegistration { string offered_name = 1; repeated string capabilities = 2; }`(`docs/design/protocol.md` §9의 `Hello` 정의·§11-2 그대로). `offered_name`은 **인증에 절대 쓰이지 않는 자기 신고 값**이며 그 사실을 `.proto` 주석에 못박는다. `capabilities`는 "이 target이 **이 등록에서 host 역할로 제공할** 기능 문자열 집합"이고(비어 있으면 `Hello.capabilities`와 동일), 미지 문자열은 controller가 무시하며, **인가·identity 입력이 절대 아니다** — M3는 registry에 기록만 하고 JSON에 노출하지 않는다. 첫 소비자는 M4(§4.1 #4).

**신규 capability 문자열을 만들지 않는다.** 역방향의 신호는 `Hello.reverse` 필드의 **존재**이고, 등록을 지원하지 않는 수신자는 `UNSUPPORTED`로 답한다. dialer가 `Hello`를 먼저 보내므로 capability 교집합은 등록 시점에 이미 늦으며, 문자열을 하나 더 만들면 `LOCAL_CAPABILITIES`와 실제 구현 사이에 불일치 창만 생긴다. 따라서 `crates/qsh-proto/src/wire.rs`의 `LOCAL_CAPABILITIES`와 `local_capabilities_advertise_exactly_what_is_implemented` 테스트는 **M3 내내 불변**이다.

*이름 모양 검사*: `wire::valid_host_name(&str) -> bool`(`1..=64` 바이트, `[A-Za-z0-9._-]`)을 `qsh-proto`의 **순수 함수**로 둔다. `offered_name`에 적용되는 규칙은 `name.is_empty() || valid_host_name(name)`이다 — 빈 문자열은 검사에서 면제되며(이름 결정을 controller에 위임한다는 뜻; 어차피 등록 이름은 controller가 정한다) 비어 있지 않으면 만족해야 한다(Step 1 검증이 확정한 명문화, protocol.md §9·§11-2와 `.proto` 주석에 동일하게 기록됨). 이 함수 자체는 빈 문자열에 `false`를 반환한다 — controller가 **정하는** 등록 이름의 검사에는 면제가 없다. — `server::valid_session_id`(`crates/qsh-core/src/server/mod.rs:1683`)와 같은 규율이며(`docs/design/protocol.md` §9 "세션 id는 모양부터 검사한다": peer가 준 문자열이 audit field가 되기 전에 크기를 묶는다), Step 3이 ACL choke point **이전에** 부를 수 있어야 하므로 `qsh-core`가 아니라 계약 계층에 산다.

*IPC (`crates/qsh-proto/proto/qsh/local/v1.proto`, 신규 package `qsh.local.v1`)*: localctl은 `docs/design/protocol.md` §11-3이 "§5와 동일한 frame layer — 파서 하나로 통일"이라고만 정한 채 메시지 집합이 비어 있었다. 여기서 채운다.

- **wire와 별도 파일·별도 package인 이유**: `docs/ROADMAP.md` M8이 freeze하는 것은 `qsh.wire.v1`(원격 계약, 외부 보안 리뷰 산출물)이고 `v1.proto` 머리말은 자신을 "QUIC 스트림에 올리는 모든 메시지의 문법"으로 정의한다. 같은 바이너리의 두 프로세스 사이 IPC를 거기에 얹으면 freeze가 로컬 리팩터링까지 묶는다. **"§5와 동일한 frame layer"는 파서 재사용을 뜻하지 파일 공유를 뜻하지 않는다** — `qsh_proto::frame`(u32-BE + prost, `CONTROL_FRAME_MAX`)을 `tokio::net::UnixStream` 위에서 그대로 쓴다. `qsh-transport`의 quinn 래퍼는 재사용하지 않는다(quinn 타입에 결합돼 있고 localctl은 transport 계층이 아니다).
- 메시지: `LocalHello{uint32 version=1; LocalStreamKind kind=2; string host=3; uint32 wait_ms=4;}`, `enum LocalStreamKind{LOCAL_UNSPECIFIED=0; LOCAL_CONTROL=1; LOCAL_STREAM=2; LOCAL_ADMIN=3;}`, `LocalHelloAck{string host=1; string peer_fingerprint=2; uint64 generation=3; repeated string capabilities=4;}`, `LocalError{string code=1; string message=2;}`(`code`는 `docs/CLI.md` §3.3 어휘 그대로 — 어휘 단일화), `LocalHostList{}` / `LocalHostListResult{repeated LocalHost hosts=1;}`, `LocalHost{string name=1; string address=2; string state=3; string fingerprint=4; repeated string capabilities=5; uint64 generation=6; string registered_at=7;}`, 그리고 **응답 envelope `LocalResponse{oneof body{LocalHelloAck hello_ack=1; LocalHostListResult host_list_result=2; LocalError error=15;}}`** — 데몬→클라이언트 방향의 모든 frame은 예외 없이 `LocalResponse` 하나다(Step 1 검증이 확정한 추가: `LocalHelloAck`와 `LocalError`는 필드 shape(tag 1·2 모두 string)상 wire에서 구별 불가능하므로 wire `Response{oneof body}`와 같은 판별자가 필요하다; protocol.md §11-3에 명문화됨). Step 5·6의 데몬·클라이언트 구현은 bare 응답 메시지를 절대 쓰지 않는다.
- **연결당 스트림 1개 모델**: UDS 연결 하나가 논리 스트림(conduit) 하나이고 첫 프레임 `LocalHello`가 그 정체를 정한다 — `LOCAL_CONTROL`(그 host의 control 세션: 이후 QUIC 위와 **완전히 같은** `ControlMessage`/`Response`가 흐른다), `LOCAL_STREAM`(다음 프레임이 wire `StreamHeader{SESSION_DATA, ticket}`인 data 스트림), `LOCAL_ADMIN`(데몬 자신에 대한 조회). 별도 mux를 만들지 않는다 — 스트림 정체성은 언제나 in-band 헤더라는 ADR-0005 제약을 그대로 지키면서 mux 구현을 회피하는 것이 이 선택의 값이다. `StreamKind` enum에는 **UDS 전용 값을 추가하지 않는다**(QUIC wire 어휘 비오염).
- **`LocalHelloAck.peer_fingerprint`가 계약인 이유**: ADR-0007 결과 절은 "`Ops`는 연결된 peer의 SPKI fingerprint가 항목의 `peer_spki_sha256`과 일치할 때만 토큰을 보낸다. 불일치는 로컬 `SESSION_NOT_FOUND`(`peer_mismatch`)로 fail closed"를 계약으로 못박았다. 역방향에서 CLI 프로세스는 TLS endpoint가 **아니므로** 그 fingerprint를 스스로 알 수 없다 — 아는 것은 데몬뿐이다. `LocalHelloAck`가 그 값을 되돌려 주지 않으면 이 fail-closed 검사가 말없이 사라진다. `Ops::connect`가 반환하는 `Connected`의 `peer_fingerprint()`(`crates/qsh-core/src/ops/session.rs`의 심볼)가 역방향에서 이 값을 소비한다.
- `wait_ms`는 `LOCAL_WAIT_MAX`(60 s, `SESSION_READ_MAX_WAIT`과 같은 clamp 규율)로 상한이 걸린다 — 거부가 아니라 상한이며, `docs/CLI.md` §9의 전체 command `--timeout`은 이와 별개로 CLI가 강제한다(무경계 블록 금지).

*JSON 계약 (`crates/qsh-proto/src/types.rs`)*: `HostListReq{}`·`HostListData{hosts: Vec<Host>}`·`HostGetReq{name}`를 추가하고, placeholder였던 `types::Host`(`types.rs:72`)를 실사용 타입으로 승격한다. **필드 shape는 그대로**(추가·삭제·type 변경 없음) — 값 어휘만 확정한다:

- `connection_mode ∈ {"forward","reverse"}`.
- `state ∈ {"reachable","stale","unknown"}`(열린 문자열, §10). forward host는 M3에서 도달성을 probe하지 않으므로 항상 `"unknown"`이다 — 확인하지 않은 것을 `"reachable"`로 보고하지 않는다. live 역방향 등록은 `"reachable"`(인증된 연결을 실제로 쥐고 있다), 죽은 등록은 보존 창 동안 `"stale"`.
- `device_id` = **peer의 SPKI SHA-256 fingerprint 문자열**(`sha256:BASE64`, `docs/design/architecture.md` §5의 표기). forward host는 trust store에 **핀된** fingerprint, reverse host는 데몬이 **TLS로 검증한** peer fingerprint다. `Hello.device_name` 같은 wire 표시 이름은 어떤 경우에도 쓰지 않는다(`docs/design/protocol.md` §3 "`Hello`의 `device_name` 등 wire 데이터에서 identity를 취하지 않는다"). 이 값의 근거는 `crates/qsh-proto/src/types.rs:82`의 doc comment("Stable per-device identifier the peer presented")이며 — `docs/CLI.md` §5 본문에는 이 문장이 없다 — Step 1이 **CLI.md §5의 예시(`"device_id": "device_01K0EXAMPLE"`)와 `types.rs`의 doc comment 예시를 함께 `sha256:…` 형태로 교체**한다. `Host`는 지금까지 어떤 op도 emit한 적 없는 placeholder이고 fixture도 없으므로 이것은 field의 **정의**이지 §10이 금지하는 의미 변경이 아니다 — 그 사실을 §5에 한 문장으로 남긴다.

*정본 문서 갱신(구현 전에)*:

- `docs/CLI.md` — §2.5의 "향후 예약" 줄에서 `역방향 host 등록 → host.reverse`를 제거하고 매핑 표 **아래에 문단으로** 추가한다(표는 operation→action 매핑이고 §2.4가 "`qsh listen`, `qsh reverse`는 operation이 아니라 장기 실행 모드"라고 못박았으므로 표에 행을 만들지 않는다): 역방향 등록은 operation이 아니라 **연결 수립 시점의 검사**이며 ACL action `host.reverse`를 요구한다. §5 — `Host`의 `state`/`device_id` 값 어휘와 예시 교체. §6.1 — `data` 형태를 `{"hosts":[Host, …]}`로, `host.get`의 `data`는 `Host` 객체 하나로 확정 + 두 데이터 소스 + "**`host.list`는 dial하지 않는다**" + 같은 이름이 forward·reverse 두 항목으로 나타날 수 있음 + 라우팅 우선순위(live reverse 등록 우선). 신규 §6.13 "장기 실행 모드: `qsh listen` / `qsh reverse`"(§6.12와 같은 형식 — controller reachability 요구, bind 우선순위와 `qsh serve`와의 기본값 충돌, writer lease가 데몬 연결에 결합된다는 관찰 가능한 차이, Windows `UNSUPPORTED`). §6.4 — recovery 진단의 additive 필드 `registration_wait_ms`(Step 8이 채우지만 필드 집합의 정본은 여기다). §6.11 — `doctor.run` 계약이 M7임을 유지하되, M3가 만드는 진단 항목 상수를 M7의 doctor가 **그대로 소비한다**는 한 줄.
- `docs/design/protocol.md` — §9: `ReverseRegistration`을 산문에서 실제 메시지 정의로 승격, `offered_name` 모양 규칙 명문화. §11-2: 이름 확정 규칙 상세와 충돌 처리, `qsh serve`가 등록 Hello를 받는 경우, peer credential 검사 요구(UDS `SO_PEERCRED`/`getpeereid`, Step 5). §11-3: localctl 메시지 집합·conduit 모델(연결당 1 스트림)·request_id 재매핑·peer credential 검사·**localctl은 인가 계층이 아니다**, `qsh attach company-mac` 예시를 `qsh <name>`(신규 세션)/`qsh attach <name>/<session_id>`(재attach)로 교체. §11-4: heartbeat의 정체(신규 메시지 없음 — 15 s keep-alive + control 스트림 `Ping`/`Pong` probe), backoff 파라미터, stale 창, **역방향에서의 §10 매핑**(재dial 주체는 target, controller 측 attach driver는 "새 `generation`의 등록을 기다렸다가 `SessionAttach{last_output_seq}`"; 이 leg에 migration/rebind은 없다).
- `docs/design/architecture.md` — §3 localctl 문장을 "M3 도입, 첫 소비자 2종(`qsh hosts`·역방향 attach), `qsh tunnels`는 M4"로 갱신하고 그 예시 `qsh attach <reverse-host>`를 `qsh <name>`/`qsh attach <name>/<session_id>`로 교체. §7에 `[listen]`/`[reverse]` config 섹션과 런타임 소켓 discovery 규칙. (action 목록은 §6에 없다 — §6은 CLI.md 매핑 표에 위임하는 산문이고 정본은 `docs/PRD.md` §9이며 거기엔 이미 `host.reverse`가 있다. op→action 매핑의 정본 `docs/CLI.md` §2.5는 위 문단에서 이미 갱신한다.)
- `docs/adr/0003-sessions-in-listener.md` — 2026-08-18 추기의 예시 `qsh attach <reverse-host>`를 같은 두 form으로 정정하는 한 줄만 더한다. **결정 자체(localctl 도입 시점, seam 2종)는 재론하지 않는다** — 표기 정정이지 새 ADR이 아니다.
- `docs/design/testing.md` — L1 handshake matrix에 "reverse dial, 비신뢰 target" 행, L3/L4에 역방향 하네스와 fault 행, L4 recovery 필드에 `registration_wait_ms`와 "60초는 이중 게이트" 규율, 낡은 "**`crates/qsh-testkit`은 빈 골격** — chaos proxy는 M2에서 구현" 문단을 M2 실제 상태로 정정.

**(b) crate/모듈/파일:**
- `crates/qsh-proto/proto/qsh/wire/v1.proto` (확장 — `ReverseRegistration`, `Hello.reverse = 4`, 머리말의 reserved 해석 주석)
- `crates/qsh-proto/proto/qsh/local/v1.proto` (신규), `crates/qsh-proto/build.rs`·`crates/qsh-proto/src/local.rs` (신규 — prost 생성 모듈 + `LOCAL_WAIT_MAX` 등 상수)
- `crates/qsh-proto/src/wire.rs` (확장 — `valid_host_name()`; `LOCAL_CAPABILITIES`는 **무변경**)
- `crates/qsh-proto/src/types.rs` (확장 — `HostListReq`/`HostListData`/`HostGetReq`, `Host` 주석 승격과 예시 교체)
- `docs/CLI.md`, `docs/design/protocol.md`, `docs/design/architecture.md`, `docs/design/testing.md` (갱신)
- `docs/adr/0003-sessions-in-listener.md` (표기 정정 한 줄만 — 결정 재론 아님)

**(c) 빚지는 테스트 (`docs/design/testing.md` L0 — 6종 전부):** `ReverseRegistration`을 포함한 `Hello`와 `qsh.local/v1` 전 메시지의 `decode(encode(m)) == m` roundtrip(proptest), 유효한 바이트열 `b`에 대한 `encode(decode(b)) == b` canonical encoding, 모든 prefix가 incomplete로 처리되는 truncation, 4 GiB를 주장하는 length prefix가 **할당 전에** 거부됨(allocation-bound), 임의 변조 입력에 panic/OOM이 없는 bit-flip, `valid_host_name` 경계 표(빈 문자열 / 65바이트 / `../` / 유니코드 / 허용 문자 전수). **`LocalStreamKind` 분류는 `qsh-proto`의 순수 함수 단언으로 좁힌다** — 미지 값(`LOCAL_UNSPECIFIED` 포함)을 `ErrorCode::InvalidArgument`로 매핑하는 함수 자체를 여기서 단언하고, 그 값을 실제로 `INVALID_ARGUMENT` envelope로 내보내는 것은 데몬이 있는 Step 5의 소관이다. `LocalError.code`가 `ErrorCode` 어휘와 동일함을 단언. **golden vector 2종**: `reverse`가 있는 `Hello` 1개(신규)와 — 결정적으로 — **`reverse`가 없는 기존 `Hello` 인코딩이 바이트 단위로 불변**임을 단언하는 기존 golden 유지(additive의 기계적 증거).

**(d) 완료 판정:** L0 green. 기존 fixture 전부 바이트 단위로 불변. `qsh.local/v1`은 로컬 IPC 패키지이므로 `qsh version --json`의 `schemas` 배열에 **추가하지 않는다** — `version.json` fixture는 바이트 단위로 그대로다(배열이 append-only 규율의 대상이 아니라 fixture 파일 자체가 append-only 대상이므로, "추가만"은 자기모순이다). `xtask arch` green(`qsh-proto`는 여전히 무의존). `LOCAL_CAPABILITIES`가 이 step에서 바뀌지 않는다. 위 문서 갱신이 같은 PR에 포함된다 — 각 문서 머리말의 "구현이 어긋나면 문서를 먼저 갱신한다" 규칙의 이행이다. Windows leg의 nextest green(신규 코드는 `qsh-proto`뿐이라 unix 전용 분기가 없다 — 이 step에서는 자명하지만 이후 step의 기준선이다).

**(e) 인용:** `docs/design/protocol.md` §5(frame layer 상한), §9(`Hello.reverse`·모양 검사 규율), §11 전체(대칭 원칙·4단계), §14(transport 불가지·in-band `StreamHeader`), `docs/CLI.md` §2.2·§2.4·§2.5·§5·§6.1·§6.4·§6.11·§10, `docs/PRD.md` §6(역방향 접속·직접 경로 요구), §9(action 목록의 `host.reverse`), `docs/design/architecture.md` §2(계약 타입 공유), §3(localctl seam), §5(fingerprint 표기), §7(경로), ADR-0003 추기, ADR-0005, ADR-0007.

---

### Step 2 — 연결 방향과 세션 역할의 분리 (동작 변화 0 리팩터)

**(a) 범위:** 동작을 바꾸지 않고 축을 배선한다. `docs/design/protocol.md` §7이 정의한 것은 "**dialer가** handshake 후 첫 bidi"이므로 방향(initiator/responder)과 역할(host/client)은 직교해야 하는데, 현재는 host가 `accept_bi` + Hello 수신 후 응답, client가 `open_bi` + Hello 선송신으로 붙어 있다.

control 핸드셰이크를 `crates/qsh-core/src/handshake.rs`로 추출한다:

- `initiate(conn, local_hello) -> (FramedStream, Hello)` — `open_bi` + `PRIORITY_CONTROL` 설정 + Hello 선송신 + 응답 대기.
- `respond(conn, make_local_hello: FnOnce(&Hello) -> Result<Hello, wire::Error>) -> (FramedStream, Hello)` — `accept_bi` + Hello 수신 + 응답. 콜백 형태인 이유는 responder의 `Hello`가 peer의 `Hello`에 의존하기 때문이다(capability·minor version 교집합, 그리고 Step 3에서 등록 거부 판정).

두 함수 모두 `HELLO_TIMEOUT`, minor version 교집합, capability 교집합 규칙을 **한 곳에서** 수행한다. 버전 불일치의 표면은 role별 **기존 동작 그대로**다(이 step은 동작 변화 0이다): responder는 `UNSUPPORTED` error frame을 보내고 자기 `Hello` 없이 종료(현 `server/mod.rs`), initiator는 frame 전송 없이 로컬 `UNSUPPORTED` 에러로 종료(현 `client/mod.rs:128-135` — 대칭 구현끼리는 responder가 먼저 잡아 error frame으로 답하므로, initiator의 이 검사는 자기 교집합 규칙을 지키지 않는 비대칭 peer에 대한 방어다. `docs/design/protocol.md` §4는 교집합 협상만 정의하며 initiator 측 error frame을 요구하지 않는다). `Server`는 `serve_control(conn, ctl, ctx)`(이미 수립된 control 스트림 위에서 dispatch 루프를 도는 진입점)를 노출하고 기존 `serve_connection(conn)`은 `respond` + `serve_control`의 얇은 wrapper가 되며, `accept_and_serve(incoming, on_accept)`는 그 위의 accept/audit 래퍼로 **그대로 남는다**(`qsh-testkit`의 L4 하네스가 이미 이 seam을 쓴다 — `crates/qsh-core/src/server/mod.rs:1254`의 doc comment). `client::Session`은 `from_control(conn, ctl, peer_hello)`를 노출하고 `negotiate`는 `initiate` + `from_control`의 wrapper가 된다.

이 네 조합 중 M3가 새로 쓰는 것은 **initiator + host role**(target의 `qsh reverse`)과 **responder + client role**(controller의 `qsh listen`)이다. `ConnRole`이 결정하는 것은 딱 두 가지 — control 스트림을 `accept_bi`로 받는지 `open_bi`로 여는지, 그리고 `Hello`를 먼저 보내는지 받고 보내는지 — 이며, 그 아래(principal·`auth_path`·`ConnCtx`·`Authorizer::check` 지점·ticket 발급·broker 접근·`purge_connection`)는 role에 **완전히 무관하게 동일 경로**다. 여기서 갈라지는 코드가 생기면 M4의 `-R over reverse`가 즉시 재작업이 된다.

**이 step은 controller 측 reverse 시맨틱을 넣지 않는다** — 아직 아무도 `Hello.reverse`를 읽지 않는다. `Server::local_hello()`에 `Option<ReverseRegistration>` 인자를 받는 형태만 추가하고 값은 Step 4가 채운다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/handshake.rs` (신규 — `initiate`/`respond`, `HelloError`, 버전·capability 교집합)
- `crates/qsh-core/src/server/mod.rs` (리팩터 — `serve_connection` = `respond` + `serve_control`; 핸드셰이크 코드 삭제, dispatch 루프 무변경, `local_hello(reverse)`)
- `crates/qsh-core/src/client/mod.rs` (리팩터 — `negotiate` = `initiate` + `from_control`)

**(c) 빚지는 테스트 (`docs/design/testing.md` L0·L3):** `handshake.rs` 유닛 — initiator↔responder 조합 4종(host/client × initiate/respond)이 duplex pipe 위에서 Hello를 교환하고 **같은** 교집합을 계산함, 공통 minor version 없음 → responder가 `UNSUPPORTED` error frame 후 자기 `Hello` 없이 종료함(비대칭 케이스: responder가 잡지 못하고 `Hello`를 보내온 경우 initiator가 frame 전송 없이 로컬 `UNSUPPORTED`로 종료 — 이쪽은 duplex에서 "0바이트 전송"까지 직접 증명한다), `HELLO_TIMEOUT` 경로. **initiator가 responder의 `UNSUPPORTED` frame을 실제로 원격 에러로 수신하는지는 이 L0 단언 범위 밖이다** — duplex 하네스에는 `Connection` 객체가 없어 `server::serve_connection`이 `respond()` 실패 직후 호출하는 `conn.close()`가 아직 flush되지 않은 프레임을 걷어차는 레이스(HEAD에도 이미 있는, 이 step이 만들지 않은 결함)를 재현할 수 없기 때문이다. 이 부분은 L3 실전 transport 테스트로 남는 빚이며, 이번 step에서 새로 갚지 않는다. L3 — 기존 loopback 스위트(`exec_loopback`·`session_loopback`·`attach_loopback`·`resume_loopback`)와 `crates/qsh-transport/tests/handshake_matrix.rs`가 **무수정으로** green.

**(d) 완료 판정:** 이 step은 **관찰 가능한 동작 변화가 0이어야 한다** — 기존 테스트가 **하나도 수정되지 않고** green이고, golden frame·`qsh version --json` fixture가 바이트 단위로 그대로다. 핸드셰이크 코드가 `server/mod.rs`와 `client/mod.rs`에 중복으로 남아 있지 않음을 grep으로 확인한다(`accept_bi`/`open_bi` + Hello 처리는 `handshake.rs`에만). `qsh-cli` 변경 0줄, wire 변경 0(Step 1이 계약을 이미 깔았다). `xtask arch` green. Windows leg의 nextest green(동작 변화 0인 리팩터이므로 Windows에서도 기존 스위트가 그대로 통과해야 한다).

**(e) 인용:** `docs/design/protocol.md` §7(스트림 배치 — "Control | dialer가 handshake 후 첫 bidi"), §11 머리말(대칭 원칙: TLS 역할과 QSH 역할의 분리, "요청 수신자가 자기 ACL을 평가" — §11의 번호 있는 1.부터는 다른 내용이라 이 원칙 자체는 번호 없는 머리말이다), §14(ADR-0005 제약), `docs/ROADMAP.md` §1 원칙 7(c), `docs/design/architecture.md` §1(crate 책임), §6(단일 choke point).

---

### Step 3 — controller `qsh listen` + target `qsh reverse`(등록 1회) + `host.reverse` 인가 지점 + reverse registry

> **이 step도 두 PR로 올린다** (Step 5와 같은 형식). (i) **PR 3a — 인가·registry·공용 팩토리**: `Action::HostReverse` + `ALL` 6종, `reverse/registry.rs`의 이름 확정·충돌·`generation`, `serve.rs`의 `host_runtime()` 추출, `[listen]`/`[reverse]` config. 완료 판정 = L2 유닛(이름 확정 표, `DenyAll` 하 생성물 0, audit 라인) green, **동작 변화 0**(아직 아무 CLI 표면도 바뀌지 않는다). (ii) **PR 3b — 실제 두 모드와 하네스**: `reverse/listen.rs`·`reverse/target.rs`, `Command::Listen`/`Command::Reverse`, `ReverseHarness`, `reverse_loopback.rs`, L1 matrix 행, 기존 loopback 3종의 양방향 파라미터화. 완료 판정 = 아래 (d). 두 PR 모두 §2 공통 게이트를 각각 통과한다.

**(a) 범위:** headless 등록 경로 전부. 소비자(localctl·attach·hosts)는 아직 없고 재접속 루프는 Step 4다.

**ACL.** `acl::Action`에 `HostReverse`(`as_str() == "host.reverse"`)를 추가하고 `Action::ALL`을 6종으로 늘린다(`crates/qsh-core/src/acl/mod.rs`; `docs/PRD.md` §9 최소 action 목록, `docs/CLI.md` §2.5). 정책은 여전히 interim `AllowAllPinned`이며 `host.reverse`에 예외를 만들지 않는다(§4.1 #6). 정책 **엔진**(TOML·wildcard·`qsh acl check`)은 M5다.

**Controller(`qsh listen`).** QUIC listener를 bind하고(`--bind` > `[listen].bind` > `[::]:4433`) 수락한 연결마다 Step 2의 `respond`로 control 스트림을 세운다. peer의 `Hello.reverse`가 **없으면** `UNSUPPORTED`("this endpoint only accepts reverse registrations") error frame 후 연결 종료 — 리소스 0, audit 없음(ACL 판정이 아니다). 있으면 순서대로:

1. **`valid_host_name(offered_name)` 모양 검사** — 비어 있는 것은 허용한다(이름은 controller가 정한다). ACL/audit에 닿기 전이며 존재 여부와 무관하므로 정보를 누설하지 않는다. 위반은 `INVALID_ARGUMENT` + 연결 종료, **audit 없음**(choke point 이전).
2. **등록 이름 확정** — (i) 그 fingerprint의 **trust-store alias 우선**(= `AuthPath::Pin`), (ii) alias가 없고 `[listen].allow_advertised_names = true`일 때만 `offered_name`, (iii) 둘 다 없으면 `PERMISSION_DENIED` + 연결 종료. **`offered_name`은 어떤 경우에도 인증에 쓰이지 않는다** — name-squatting 방지(`docs/design/protocol.md` §11-2). 이 단계는 trust store를 **읽기만** 하고 아무것도 만들지 않으므로 check 이전에 와도 되며, `resource` 문자열이 있어야 audit이 의미를 갖기 때문에 check 이전이어야 한다.
3. **리소스(registry entry) 생성 이전에** `Authorizer::check(principal, auth_path, Action::HostReverse, resource = <확정 이름>)` + `AuditRecord::now`를 호출한다 — `handle_exec_start`/세션 op와 **같은 choke point 패턴**의 복제이며 이것이 이 마일스톤이 지는 SC6 지분이다. deny면 audit(`decision=deny`) + error frame + 연결 종료, **등록물 0**.
4. 통과 후에만 registry에 `ReverseEntry{name, fingerprint, principal, address, capabilities, registered_at, generation, state}`를 넣는다 — **메타데이터만**이다. 살아 있는 `client::Session`(connection을 쥔 값)은 registry가 아니라 `reverse/listen.rs`의 연결 표(`generation`을 키로)가 소유하고, registry는 그 키만 든다 — `client::Session`을 registry entry에 직접 넣으면 registry가 `qsh_transport`의 `Connection`을 간접으로 쥐게 되어, 아래 §4/Step 5가 요구하는 "`reverse/registry.rs`는 transport를 참조하지 않는다"는 arch-lint가 거짓 안심이 된다(모듈 스코프 grep은 `client::Session`이라는 타입 이름을 안 걸면 그 결합을 못 잡는다). 충돌 규칙: 같은 이름의 live 등록이 **다른 fingerprint**면 신규를 `INVALID_ARGUMENT` + 종료(조용한 덮어쓰기 금지), **같은 fingerprint**면 기존을 대체하고 옛 연결을 닫으며 `generation`을 1 증가시킨다(NAT rebind로 인한 중복 등록이 지배적 경로이고, Step 4 재접속 루프의 정상 경로다).

**controller는 등록된 연결 위에서 client role이다**(Step 2의 `from_control`) — 요청을 보내는 쪽이고, 요청을 받는 쪽인 target이 자기 ACL을 평가한다(`docs/design/protocol.md` §11-3 "역방향 등록은 도달성만 부여하고 권한은 부여하지 않는다"). 따라서 **controller는 broker를 갖지 않는다**: 역방향 연결로 target이 `SessionOpen`/`ExecStart` 등을 보내오면 리소스 생성 없이 `UNSUPPORTED`로 답한다(controller는 셸을 제공하지 않는다). `Ping`에는 답한다 — liveness는 양방향이고 Step 4가 target 쪽에서 그것을 쓴다. 진단은 stderr 구조화 로그 tracing target `qsh::reverse`(한 줄 JSON, 필드 `event`(`registered|denied|replaced|lost|expired|retry`)·`host`·`fingerprint`·`generation`; payload·토큰 필드 없음).

**Target(`qsh reverse <controller>`, 등록 1회).** positional `<controller>`는 **trust store alias**다 — hosts.toml 기반 host directory는 M7이며 그 전까지 host→주소 해석의 단일 출처는 trust.toml pinned peer다(`docs/CLI.md` §6.8, `docs/design/architecture.md` §7). `Ops::resolve_peer`로 해석해 dial하고 Step 2의 `initiate`로 `Hello{reverse: Some(ReverseRegistration{offered_name, capabilities})}`를 보낸 뒤, **같은 연결 위에서 `Server::serve_control`을 돈다** — `qsh reverse`는 dial하는 host mode이며 broker·PTY·audit 구성은 `serve.rs::run_serve`의 것을 그대로 재사용한다(`host_runtime()` 공용 팩토리로 추출). 이 step에서는 연결이 죽으면 진단을 남기고 종료한다. optional `--offered-name <name>`(기본: `[reverse].offered_name`, 그 다음 이 장비의 `device_name`).

**음성 경로 2건을 명시적으로 닫는다**(테스트 포함): ① **`qsh serve`(정방향 host)가 `Hello.reverse`를 받으면** 등록하지 않고 `UNSUPPORTED`로 답한다 — §11 머리말의 대칭성 하에서 실제로 발생 가능한 입력이다. ② `Hello.reverse` 없는 peer가 `qsh listen`에 붙으면 `UNSUPPORTED` 후 종료.

**거부 error frame의 전달 보장(Step 2 검증이 발굴한 선재 결함의 상환).** 현재 `serve_connection`은 `respond()`가 Err를 반환하면 즉시 `conn.close(...)`를 호출하므로, 방금 쓴 error frame이 flush/전달되기 전에 연결이 닫혀 peer가 `UNSUPPORTED`/`INVALID_ARGUMENT`/`PERMISSION_DENIED` 대신 `ApplicationClosed`만 보는 레이스가 있다(HEAD 기준 raw-QUIC 프로브로 실증 — Step 2가 만든 결함이 아니라 그 이전부터 있던 것). 정방향에서는 관찰 표면이 좁았지만 이 step의 거부 경로는 §11-2가 error frame 도달을 계약으로 삼으므로 여기서 갚는다: 거부 시 종료 순서를 "error frame 송신 → 스트림 `finish()` → 전달 대기(짧은 상한) → `conn.close()`"로 고치고, L3(`reverse_loopback.rs`)에서 위 음성 경로들과 name-squatting/deny 거부의 error frame이 **실제로 peer에 수신됨**을 단언한다(Step 2 (c)가 L3로 이월한 "initiator가 responder의 version-mismatch `UNSUPPORTED`를 원격 에러로 수신" 단언도 이때 함께 갚는다).

**Config·CLI.** `[listen] bind · allow_advertised_names(기본 false)`, `[reverse] controller · offered_name`. CLI는 `qsh listen [--bind IP:PORT]`, `qsh reverse <controller> [--offered-name NAME]`. 둘 다 `docs/CLI.md` §2.4가 정의한 **장기 실행 모드**이므로 envelope도 dotted operation 이름도 갖지 않는다 — 진단은 전부 stderr(§2.2), stdout에는 한 바이트도 쓰지 않는다. `qsh listen`과 `qsh serve`의 기본 bind가 같으므로(`[::]:4433`) 한 머신에서 두 역할을 겸하려면 명시적 `--bind`가 필요하고, 충돌은 **조용한 오작동이 아니라 즉시·명시적 실패**(stderr 진단 + exit 255)다. 두 번째 매직 포트 번호는 M7(host profile)이 필요해질 때 정한다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/acl/mod.rs` (확장 — `Action::HostReverse`, `ALL` 6종, `as_str`)
- `crates/qsh-core/src/client/mod.rs` (확장 — inbound 요청 거절 경로 신규: `ControlIn`은 현재 `Event`/`Ping`/`Pong` 3종뿐이라 요청을 표현하지도 error frame을 되돌리지도 못한다. Step 4의 host-role 비용 정정과 대칭인 신규 배선이며, 리소스 생성 0 + `UNSUPPORTED` 응답만 한다.)
- `crates/qsh-core/src/reverse/registry.rs` (신규 — 메타데이터만 든다: `Registry`, `ReverseEntry{name, fingerprint, principal, address, capabilities, registered_at, generation, state}`, 이름 확정·충돌·`generation`, 주입된 `Clock`. 살아 있는 `client::Session`은 여기에 두지 않는다 — 아래 참고.)
- `crates/qsh-core/src/reverse/listen.rs` (신규 — `run_listen`: bind + accept + `respond` + 인가 + 등록 + `qsh::reverse` 진단. `serve.rs`와 대칭)
- `crates/qsh-core/src/reverse/target.rs` (신규 — `run_reverse`: dial + `initiate` + `serve_control`)
- `crates/qsh-core/src/serve.rs` (리팩터 — broker/`Server` 구성을 `host_runtime()` 공용 팩토리로 추출)
- `crates/qsh-core/src/config.rs` (확장 — `[listen]`·`[reverse]` 섹션)
- `crates/qsh-cli/src/cli.rs`, `src/main.rs` (확장 — `Command::Listen`, `Command::Reverse`; 얇은 진입점, 로직 0)
- `crates/qsh-testkit/src/reverse.rs` (신규 — `ReverseHarness`: 한 프로세스 안에서 controller listener + target dialer, `127.0.0.1:0`)

**(c) 빚지는 테스트 (`docs/design/testing.md` L1·L2·L3):** L2 유닛 — 이름 확정 우선순위 표(alias 있음 / alias 없음 + `allow_advertised_names=false` → deny / true → `offered_name` / 충돌 다른 fp → `INVALID_ARGUMENT` / 충돌 같은 fp → 대체 + `generation` +1 / 모양 위반 → `INVALID_ARGUMENT`이며 **audit 없음**), **`DenyAll` 하에서 registry entry·연결·ticket이 하나도 생성되지 않음**(기존 `denied_exec_returns_permission_denied_and_creates_nothing` 패턴 복제), audit에 `action="host.reverse"` allow/deny 라인이 각각 남음, unpinned principal은 deny. L1 — handshake matrix에 "reverse dial, 비신뢰 target" 행 추가(인증 실패는 등록 **이전**이므로 `host.reverse` audit이 아니라 handshake deny로 기록된다). L3 — `crates/qsh-testkit/tests/reverse_loopback.rs` 신규: 실제 QUIC 위에서 target이 dial → 등록 → registry에 이름으로 보임, 위 음성 경로 2건, controller가 역방향 연결에서 session/exec를 서비스하지 않고 `Ping`에만 답함. **그리고 role 축 독립성의 기계적 증명**: 기존 `session_loopback`·`attach_loopback`·`resume_loopback` 시나리오를 **정방향/역방향 dial 두 방향으로 파라미터화**해 그대로 통과시킨다(역방향에서는 target이 broker를 쥐고 controller가 client role이므로 같은 `Ops` 코드 경로가 그대로 돈다).

**(d) 완료 판정:** in-process 하네스에서 등록이 성공하고 거부 경로가 아무것도 만들지 않는다. `Action::ALL`이 6종이고 action 문자열 하드코딩 0건. 파라미터화한 loopback 스위트가 양방향 green. `qsh listen`이 bind 주소와 등록 이벤트를 stderr로 보고하고 stdout에는 한 바이트도 쓰지 않는다. `qsh reverse`가 controller 도달 실패 시 `CONNECTION_FAILED` 진단 + exit 255. Windows leg의 nextest green(`reverse/`의 unix 전용 코드가 `cfg(unix)`로 빠지고 나머지가 컴파일·통과).

**(e) 인용:** `docs/design/protocol.md` §11 머리말(대칭 원칙)·§11-2(인증서로만 인증, `host.reverse` 검사, 이름 배정과 name-squatting 방지, audit), §11-3(등록은 도달성만), §3(principal은 항상 인증서에서), §9(형태 검사 규율), `docs/CLI.md` §2.2·§2.4·§2.5·§6.8·§6.12(장기 실행 모드 계약의 형식)·§6.13, `docs/PRD.md` §9(action 목록·인증 전 리소스 생성 금지), §11(명령 체계), `docs/design/architecture.md` §6(단일 choke point·default deny·`auth_path`), `docs/ROADMAP.md` §1 원칙 5번, §2 M5 범위.

---

### Step 3.5 — 감사 개정분: M2 계약 부채 상환 + 세션 소유권 P0 (`docs/ROADMAP.md` 2026-08-21 개정)

**(a) 범위:** 2026-08-21 프로덕션 준비도 감사(HEAD `1d5d1b0`)가 M3에 귀속시킨 작업. **실행 순서는 Step 3 직후, Step 4 착수 전이다** — A1의 drain 경로는 Step 4가 완성하는 `qsh listen`/`qsh reverse` 상주 프로세스가 그대로 상속해야 하고(뒤에 넣으면 세 상주 모드를 두 번 고친다), 소유권 P0는 M5 정책 어휘의 선행 결정이라 M5 설계가 시작되기 전에 코드에 존재해야 한다. 두 PR로 올린다.

**PR ① — 계약 부채 상환.**

- **SIGTERM graceful drain** (`docs/CLI.md` §6.12 "(M2, ADR-0003)" 문장의 이행): `qsh serve` SIGTERM 수신 → 신규 attach·open 거부 → 전 세션에 §6.7 close 절차(SIGHUP→TERM→KILL, `close_grace_ms`, reaping) → 붙어 있는 소비자에 `session.closed{reason:"closed"}`(§6.4) → endpoint 상한부 drain → 종료. `qsh listen`/`qsh reverse`의 shutdown 경로도 같은 절차를 태운다(Step 3의 shutdown future가 그 자리다). **L5 실프로세스 테스트**: 자식 셸(process group)이 살아 있는 serve에 SIGTERM → drain 후 잔존 process group 0 단언 — 현재 HEAD는 PTY 자식이 고아로 살아남음이 실측돼 있다(감사 A1).
- **`exec.run` 환경 위생** (`docs/CLI.md` "…클라이언트 프로세스의 환경을 암묵적으로 상속시키지 않는다. `HOME`/`USER`/`LOGNAME`/`SHELL`/`PATH`는 어느 경로에서도 호스트가 고정한다"의 이행): spawn 전 `env_clear()` 후 호스트 고정 key 재적용, caller `--env`는 그 위 overlay이되 고정 5종은 덮어쓸 수 없다. 테스트: serve 프로세스에 심은 마커 env가 exec 자식에 보이지 않음 + `--env PATH=...`가 무시됨(고정 key 우선).
- **README 동기화(A8)**: 기능 목록·Known limitations·인터임 위험 고지를 현 HEAD와 일치. "마일스톤 마감 공통 절차" 2번의 소급 적용이다.
- **quinn 플로어 문서 정정**(감사 기각 심의 1): `docs/design/protocol.md` 2곳과 `docs/design/architecture.md` 1곳이 버전 플로어(≥ 0.11.14)의 대상 크레이트를 파사드 `quinn`으로 잘못 지목 — 실제 advisory(RUSTSEC-2026-0037) 대상은 `quinn-proto`이고 lock은 0.11.16(패치됨)이다. 대상 크레이트명만 정정한다(구속 문서이므로 방치 불가 — 미래 유지보수자가 파사드 버전만 보고 오판한다).
- **CI 위생(A13)**: `.config/nextest.toml`에 slow-timeout — 진짜 deadlock 시 CI가 job timeout까지 매달리는 것을 방지.
- **선재 결함 정리**: `qsh serve --json`의 early-failure(`Ops::from_env()`)가 stdout envelope을 오염하는 버그를 PR 3b가 listen/reverse에 깐 stderr-only 경로로 통일(§2.2·§6.12 — 장기 실행 모드의 stdout은 0바이트).

**PR ② — 세션 소유권 P0 (감사 A2).** broker 세션에 opener principal을 기록하고 `session.control` action(write/resize)의 인가를 opener와 대조 — 불일치는 `PERMISSION_DENIED`(admit.rs 선례의 균일 문면, 어떤 세션이 누구 소유인지 비노출). 경계는 PRD §6이 긋는다: 조회·읽기·종료는 교차 기기 ACL 범위로 명시 허용이므로 결합 대상이 **아니다**. `docs/CLI.md` §6.3에 소유권 결합을 한 줄로 명시(additive, 계약 문서 먼저). 테스트: 두 principal loopback에서 타인 세션 write/resize 거부 + audit deny, 소유자 통과, read/close는 종전대로 ACL만.

**(c) 빚지는 테스트:** 위 각 항목에 병기. 추가로 ROADMAP M3 DoD 감사 개정 2번째 항목의 **병렬 경합 테스트**(동시 등록 same/different fingerprint, 동시 다중 세션)는 Step 4가 재접속 루프와 함께 소유한다 — replace 경로의 실제 생산자가 Step 4에서 생기기 때문이다(Step 3이 이월한 race 부채 2건과 같은 자리).

**(d) 완료 판정:** 두 PR 각각 §2 공통 게이트 green. L5 drain 테스트·env 위생 테스트·소유권 테스트 green. ROADMAP M3 DoD의 감사 개정 1번째 항목이 닫힌다(2번째 항목의 경합 테스트는 Step 4 완료 판정으로 이월).

**(e) 인용:** `docs/CLI.md` §2.2·§6.3·§6.4·§6.7·§6.12, `docs/PRD.md` §6(기기 결합·교차 기기 허용 범위)·§9, ADR-0003, ADR-0007, `docs/ROADMAP.md` M2 사후 감사·M3 감사 개정·마일스톤 마감 공통 절차.

---

### Step 4 — target 재접속: heartbeat · 지수 backoff + jitter · controller stale 처리

**(a) 범위:** ROADMAP 범위 줄의 "등록 + heartbeat + 백오프 재접속"을 완성한다.

**heartbeat의 정체(§4.1 #3): 신규 wire 메시지는 없다.** (i) 연결 유지는 `docs/design/protocol.md` §2의 QUIC keep-alive 15 s — 그 값의 근거가 정확히 "일반적인 30s UDP NAT binding timeout보다 짧아 **역방향 target의 장수명 연결**을 NAT 뒤에서 유지한다"이다. (ii) 사망 **감지**는 §10의 애플리케이션 `Ping`/`Pong` probe다. 프로토콜이 control 스트림 수립 후 대칭이므로(§11 머리말) M2가 만든 `client/pathwatch.rs`의 정책(active 250 ms / idle 5 s 두 cadence, `max(1 s, RTT × 8)` deadline, 3-strike, "소비자 정체는 사망이 아니다")을 **양쪽에서** 재사용한다: target은 자기가 dial한 연결이 죽었는지 알아야 재접속 루프를 돌 수 있다. **controller 쪽은 "이미 client role이므로 기존 코드 그대로"가 아니다** — `PathWatch`/`PathWatchConfig`는 지금 `ops/session.rs`의 attach/recovery driver에만 배선돼 있고 맨 `client::Session`에는 없다. controller 측 probe는 `reverse/listen.rs`에 `PathWatchConfig`를 재사용하는 소형 드라이버를 새로 둔다(판정 정책은 무변경, 배선만 신규).

> **비용 정정 — 이것은 "노출 정리"가 아니라 서버측 신규 배선이다.** 현재 `Server`는 요청 **수신·응답** 루프뿐이고(`crates/qsh-core/src/server/mod.rs`), `Ping`에 `Pong`으로 답하기만 하며 **자기가 보낸 `Ping`의 `Pong`을 상관시키는 경로가 없다** — 들어온 `Pong`은 unsolicited로 드롭된다(server/mod.rs:320). 따라서 이 step은 host 역할에 (a) control 스트림으로 요청을 **발신**하는 경로, (b) `request_id` 상관과 무응답 판정, (c) 그 판정을 `PathWatch`에 먹이는 어댑터를 새로 만든다. `PathWatchConfig`와 판정 정책은 그대로 재사용하되 배선은 신규다 — 이 step의 실작업 대부분이 여기에 있다.

**Target 재접속 루프.** 사망 판정 → 지수 backoff + jitter로 재dial → `Hello.reverse` 재전송 → 재등록. 파라미터는 상수가 아니라 config다: `[reverse].backoff_initial_ms`(기본 500), `backoff_max_ms`(기본 30000), `backoff_jitter_pct`(기본 ±20), 배수 2, **등록 성공 시 초기값으로 리셋**, 무한 재시도(등록은 target의 유일한 도달 경로이므로 포기하지 않는다). **세션은 재접속과 무관하게 살아 있다** — broker는 `qsh reverse` 프로세스 안에 있고 연결과 수명이 분리돼 있다(ADR-0003); 연결 사망 시 `purge_connection`은 ticket 폐기와 writer lease 해제만 하고 broker의 세션·PTY·자식은 그대로 둔다(M2가 이미 보장하는 성질이며 이 step의 요구사항은 **그것을 깨지 않는 것**이다). identity는 **재시도 루프 밖에서 한 번** 로드해 재접속마다 keystore를 다시 열지 않는다(§4의 macOS Keychain 감시 항목).

**Controller stale 처리.** 연결이 죽으면 엔트리를 즉시 삭제하지 않고 `state = "stale"`로 표시했다가 `[listen].stale_retention` 후 제거한다 — `docs/design/protocol.md` §11-4의 "host 목록에서 stale 처리"의 구현이며, 사라진 host를 조용히 없애는 대신 "있었다가 끊겼다"를 보여 준다. **기본값은 target의 backoff 상한에 종속된다**: 재등록 최악 지연 ≈ `backoff_max_ms`(30 s) + jitter이므로 그보다 확실히 커야 재attach 대기(Step 8)가 의미를 갖는다. 기본 **120 s**로 두고 그 결합(`stale_retention > backoff_max_ms × 3`)을 config 검증과 주석으로 고정한다(§4.2).

**Step 3에서 넘어온 race 부채, 이 step이 반드시 해소한다.** ① `reverse/listen.rs`의 `Listen::finish_registration`(동시 same-fingerprint 재등록 시 `admit()` 순서와 `conns` 테이블 publish 순서가 어긋나 대체된 연결이 close되지 않고 영구히 leak될 수 있음), ② `reverse/target.rs`의 `run_reverse`가 `serve_control` 종료 후 `purge_connection`을 호출하지 않는 것. (원래 ②에 묶여 있던 "shutdown 분기가 `serve_control`을 mid-flight에 취소" 절반은 Step 3.5의 SIGTERM drain 배선이 `serve_control`을 `tokio::spawn` + drain 후 join하는 구조로 바꾸며 이미 해소했다 — 남은 것은 purge 호출 자체다.) Step 3에서는 단발 등록 + 프로세스 종료로 가려지지만 이 step의 재접속 루프가 그 가림을 없앤다(두 자리 모두 코드에 주석으로 표시돼 있다).

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/reverse/target.rs` (확장 — 재접속 루프, backoff+jitter, liveness probe 배선)
- `crates/qsh-core/src/reverse/listen.rs` (확장 — controller 측 소형 probe 드라이버 신규: `PathWatchConfig`를 재사용해 등록된 각 연결을 감시. `client::Session`에는 없던 배선이다.)
- `crates/qsh-core/src/server/mod.rs` (확장 — host 역할의 control 요청 발신 + `Ping`/`Pong` 상관)
- `crates/qsh-core/src/client/pathwatch.rs` (확장 — host 역할에서도 쓸 수 있게 probe 소스를 trait 뒤로; 판정 로직 무변경)
- `crates/qsh-core/src/reverse/registry.rs` (확장 — stale 상태·retention 제거·재등록 교체·`generation` 단조성)
- `crates/qsh-core/src/config.rs` (확장 — `[reverse]` backoff 3종, `[listen].stale_retention`)
- `crates/qsh-testkit/src/reverse.rs` (확장 — target 다리에 chaos proxy를 끼우는 변형)

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L4):** L2 — backoff 수열 property(단조 증가·상한 준수·jitter가 선언 범위 안·성공 시 리셋), stale 전이·retention 만료·제거가 `TestClock` + `tokio::time::pause()` 위에서 결정적(`sleep()` 금지), `generation` 단조성. L4 — `crates/qsh-testkit/tests/reverse_chaos.rs` 신규: chaos proxy로 target→controller path를 `sever()`한 뒤 자동 재등록되고 registry `generation`이 정확히 1 증가함(주입된 짧은 backoff로 수 초 내 완료, seeded). 재등록 사이에 target의 세션이 살아 있고 `session.list`가 같은 `session_id`를 계속 보고함(SC5의 역방향 판).

**(d) 완료 판정:** 실제 두 프로세스(`qsh listen` + `qsh reverse`)가 로컬에서 등록되고, path를 끊으면 backoff를 밟아 자동 재등록된다. 재등록 중 target의 세션·자식 프로세스가 죽지 않음을 단언. controller 부재 상태에서 재접속 루프가 CPU를 태우지 않음(상한 도달 후 30 s 간격). `qsh::reverse` 레코드가 stderr 한 줄 JSON으로 파싱된다. `sleep()` 사용 0. Windows leg의 nextest green(재접속 루프·probe 배선은 전부 `cfg(unix)` 대상 밖의 코드에 영향을 주지 않는다).

**(e) 인용:** `docs/design/protocol.md` §2(keep-alive 15s의 근거가 곧 역방향 target; migration은 지연 최적화), §10 "Path 사망 감지"(두 cadence·RTT 비례 deadline·3-strike·소비자 정체), §11 머리말(대칭), §11-4(지수 backoff + jitter, 세션은 재등록과 무관, stale), `docs/design/architecture.md` §3(세션은 연결과 수명 분리), §7, `docs/CLI.md` §2.4·§6.13, `docs/PRD.md` §8(세션 모델), §13, `docs/design/testing.md` L2·L4, ADR-0003.

---

### Step 5 — `localctl`(UDS) + `host.list`/`host.get` + `qsh hosts` — **DoD 3**

> **이 step은 두 PR로 올린다.** (i) **PR 5a — localctl 전송·보안 계층**: UDS 데몬/클라이언트, 소켓 수명·권한, peer credential, discovery, `LOCAL_ADMIN` + `LocalHostList`, arch-lint 규칙. 완료 판정 = 데몬↔CLI 프로세스 사이에서 registry가 IPC로 조회되고 권한·discovery 테스트가 green. (ii) **PR 5b — op와 CLI 표면**: `Ops::host_list`/`host_get`, forward+reverse 병합, `qsh hosts`/`qsh host get`, 렌더러, fixture. 완료 판정 = DoD 3. 두 PR 모두 §2 공통 게이트를 각각 통과한다.

**(a) 범위:** ADR-0003 추기와 `docs/design/architecture.md` §3이 M3로 못박은 `localctl`을 **그 첫 소비자와 함께** 도입한다(소비자 없는 IPC 계층은 깔지 않는다는 추기의 취지를 지킨다).

*소켓과 신뢰 경계.* 상주 `qsh listen` 데몬이 `$XDG_RUNTIME_DIR/qsh/<pid>.sock`(없으면 state 하위 `run/`)에 UDS를 열고, 디렉터리 0700 · 소켓 0600 · 전 코드 `cfg(unix)`. 종료 시 소켓을 unlink한다.

- **peer credential 검사** — `SO_PEERCRED`(Linux) / `getpeereid`(macOS)로 접속자 euid가 데몬과 같지 않으면 즉시 거부. 소켓 권한과 이중 방어이며, 권한 비트가 잘못 설정된 런타임 디렉터리에서도 fail closed다. (`docs/design/protocol.md` §11-3에 없던 요구이므로 Step 1이 그 문서에 추가한다.)
- **localctl은 인가 계층이 아니다.** 데몬은 conduit에 대해 `Authorizer::check`를 부르지 않는다 — 부르면 **잘못된** principal(자기 자신)을 평가하게 된다. 실제 인가는 target이 자기 ACL로 controller principal을 평가하는 것이다(§11-3). localctl에 붙을 수 있는 것은 같은 OS 사용자뿐이고 그 사용자는 이미 이 장비의 device key를 쓸 수 있으므로, **localctl은 새 권한을 부여하지 않는다.** 데몬은 CLI가 보낸 어떤 principal 유사 정보도 신뢰하지 않는다.
- **discovery** — CLI는 런타임 디렉터리의 `*.sock`을 pid 오름차순으로 시도한다. connect가 거부되는 stale 소켓은 unlink하고 넘어가며, 요청한 host를 모르는 데몬은 `HOST_NOT_FOUND`로 답해 다음 소켓으로 넘어가게 한다. 전부 실패하면 `HOST_NOT_FOUND`.

*조회 op.* `Ops`에 `host_list`/`host_get`을 구현한다(`docs/CLI.md` §2.4의 dotted 이름은 M0부터 예약돼 있었고 구현이 없었다; §2.5에 따라 **인가 불요 local operation**이다). 데이터 소스 둘:

- **forward** — trust.toml pinned peer 중 address가 있는 것. `connection_mode:"forward"`, `state:"unknown"`(probe하지 않음), `device_id` = **핀된** fingerprint. M7의 hosts.toml host directory를 앞당기지 않는다.
- **reverse** — 이 머신의 localctl 데몬들에 등록된 엔트리의 합집합(`LocalHostList`). `connection_mode:"reverse"`, `state` = `"reachable"`/`"stale"`, `address` = 마지막 관측 remote addr, `device_id` = 데몬이 **TLS로 검증한** peer fingerprint.

**`host.list`는 dial하지 않는다** — 잠든 노트북 한 대가 목록을 느리게 만들지 않는다(`docs/CLI.md` §6.2의 fan-out과 달리 순수 로컬 조회다). 같은 이름이 forward와 reverse 양쪽에 있으면 **두 항목**으로 반환한다(숨기지 않는다). 같은 이름을 **두 데몬**이 live로 들고 있어도 목록은 두 항목을 그대로 반환한다 — 조회를 죽이지 않는 것이 `docs/CLI.md` §6.2가 확립한 규율("잠든 노트북 한 대가 다른 host의 목록을 통째로 숨겨서는 안 된다")이다. **fail closed는 라우팅에서 한다**(아래).

*병합과 라우팅은 같은 함수를 공유한다.* `resolve_host_route(name) -> HostRoute`가 (a) `Ops::connect`의 경로 선택(Step 6), (b) `host.get`이 반환할 단일 항목, (c) human 렌더러가 표시하는 "사용될 경로"를 **한 곳에서** 결정한다. 규칙: live reverse 등록 > forward pin > `HOST_NOT_FOUND`(메시지에 두 경로를 모두 안내). live 등록을 우선하는 이유는 그것이 **증명된 도달 가능 경로**이고 trust store의 주소는 추정이기 때문이다. 두 데몬이 같은 이름을 live로 들고 있으면 라우팅은 `INVALID_ARGUMENT`(`details`에 pid 목록)로 **fail closed**하고, `host.get`도 같은 오류를 낸다 — 어느 쪽으로 조용히 라우팅하는 것보다 낫다. 이 함수를 하나로 두지 않으면 목록·단건·라우팅이 각자 규칙을 기른다.

*모듈 분리와 arch-lint.* `localctl/client.rs`(CLI 프로세스 측)와 `localctl/frame.rs`는 **`qsh_transport`를 절대 참조하지 않는다**; `localctl/daemon.rs`는 QUIC로의 bridge라 transport 사용이 **정상**이다. 규칙을 daemon까지 걸면 통과시키려고 bridge를 client 쪽으로 옮기는 왜곡이 생기므로 금지는 `localctl/{frame,client}.rs`와 `reverse/registry.rs`에만 건다. `reverse/registry.rs`는 Step 3에서 이미 메타데이터 전용으로 좁혔으므로(살아 있는 `client::Session`은 `reverse/listen.rs`가 쥔다) 여기에는 broker와 **같은 토큰 집합**을 걸 수 있다: `qsh_transport`·`quinn`·`rustls`·`crate::client`·`crate::Principal`·`crate::Fingerprint`(`xtask/src/arch.rs`의 `BROKER_DIR` 규칙과 동일한 6개 토큰, `crate::client` 금지가 바로 Step 3의 `ReverseEntry`가 `client::Session`을 갖지 않는다는 것의 기계적 증거가 된다). 현재 `xtask/src/arch.rs`의 `ModuleBan`은 **디렉터리 스코프**(`BROKER_DIR`, arch.rs:137, doc comment가 "the lint is directory-scoped"라고 명시)이므로 **파일 스코프 지정을 지원하도록 확장**해야 한다. 추가로 `qsh-cli`에 UDS/소켓 API(`UnixStream`/`UnixListener`) 사용 금지 규칙을 건다 — **ban 범위는 `crates/qsh-cli/src`로 한정한다**(`crates/qsh-cli/tests`는 대상이 아니다): `check_module_bans`는 `dir` 아래를 재귀 스캔하므로, 범위를 크레이트 루트로 잡으면 이 step이 같은 PR에 추가하는 `crates/qsh-cli/tests/localctl_perms.rs`(UDS 권한을 직접 찔러야 하므로 `UnixStream`이 필요하다)가 스스로 위반을 낸다. 규칙마다 위반 주입 테스트를 붙인다(기존 `module_ban_flags_a_transport_import_under_broker` 패턴).

*CLI.* `qsh hosts [--json]`, `qsh host get <name> [--json]`. human 렌더러는 name / mode / state / address 표이고, 같은 이름의 두 항목은 두 행으로 보인다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/localctl/mod.rs`, `frame.rs`, `daemon.rs`, `client.rs` (신규)
- `crates/qsh-core/src/reverse/listen.rs` (확장 — 데몬에 localctl 서버 부착, 종료 시 unlink)
- `crates/qsh-core/src/config.rs` (확장 — `Paths::runtime_dir()`/`localctl_socket(pid)`)
- `crates/qsh-core/src/ops/host.rs` (신규 — `HostListOp`/`HostGetOp` 마커 + `Ops::host_list`/`host_get` + `resolve_host_route`)
- `crates/qsh-cli/src/cli.rs`, `src/main.rs`, `src/render/{human,json}.rs` (확장 — `Hosts`, `Host(HostCmd)`)
- `xtask/src/arch.rs` (확장 — `ModuleBan`에 파일 스코프 지원 + 위 3개 규칙)
- `crates/qsh-cli/tests/fixtures/cli-v1/{host.list.json,host.get.json}` (신규, append-only — `error.HOST_NOT_FOUND.json`은 **이미 존재**하므로 건드리지 않는다)
- `crates/qsh-cli/tests/localctl_perms.rs` (신규)

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L3·L6):** L2 — 소켓 0600·디렉터리 0700 단언, 다른 euid의 connect 거부(가능한 CI에서만, 아니면 권한 비트 단언), stale 소켓 unlink 후 다음 소켓으로 진행, host를 모르는 데몬이 `HOST_NOT_FOUND`로 답함, 병합 규칙 표(forward만 / reverse만 / 같은 이름 양쪽 → **두 항목** / stale 포함 / 데몬 없음 → forward만, 오류 아님), 라우팅 표(live reverse 우선 / forward fallback / 미등록 → `HOST_NOT_FOUND` / 두 데몬 중복 → `INVALID_ARGUMENT`). L3 — `ReverseHarness` 위에서 `qsh hosts --json`이 forward+reverse를 한 배열로 반환하고, 연결을 끊으면 그 항목이 `"stale"`로 바뀜. **`qsh hosts`가 네트워크를 건드리지 않음**을 단언(도달 불가 주소만 있는 trust store에서도 즉시 반환). L6 — 신규 fixture 2종이 schemars 스키마를 통과하고 기존 fixture 전부가 계속 유효(append-only job), 생성 스키마·fixture·localctl 프레임 어디에도 `resume_token` 문자열이 없음(`resume_secrecy.rs`를 새 표면으로 확장).

**(d) 완료 판정:** **DoD 3 green.** `xtask arch`에 새 규칙 3건이 들어가고 위반 주입 테스트로 실제 실패함을 확인. 렌더러에 인가·세션 로직 0줄. Windows에서 `qsh hosts`가 forward만 반환하고 clippy green이며, **`qsh-cli`의 나머지 nextest도 green**(UDS 전용 테스트만 `cfg(unix)`로 빠진다 — clippy만으로는 부족하다, §2 Windows leg 규율). **DEFERRED 판정(§2 규율, H1):** 이 step은 `host.list`/`host.get`(인가 불요 local op)과 localctl 첫 소비자를 도입하지만, `PERMISSION_DENIED`·`UNSUPPORTED`·`RESOURCE_EXHAUSTED` 중 어느 것도 새 envelope 경로를 얻지 않는다 — 세 코드 모두 `crates/qsh-cli/tests/fixtures.rs`의 `DEFERRED`에 그대로 남고 사유 문자열도 이 step에서는 바뀌지 않는다(경로 b는 Step 6부터 적용된다).

**(e) 인용:** ADR-0003(결과 절 + 2026-08-18 추기), `docs/design/architecture.md` §3(Supervisor seam·localctl 첫 소비자), §7(런타임 경로 `$XDG_RUNTIME_DIR/qsh/<pid>.sock`), §9-2(seam 오염 리스크·arch-lint 확장 후보), `docs/design/protocol.md` §5(frame layer 재사용), §11-3, `docs/CLI.md` §2.4·§2.5(host.list/get은 인가 불요)·§5·§6.1·§6.2(부분 실패를 감추지 않는 조회 규율)·§6.8·§10, `docs/design/testing.md` L6, `docs/ROADMAP.md` §4 리스크 4번.

---

### Step 6 — localctl control 다중화 + 라우팅: 역방향 위의 headless session op

**(a) 범위:** localctl의 두 번째 소비자. 데몬이 **reverse 연결 하나 위에서 여러 CLI 프로세스를 다중화**한다. 이것이 M3의 **유일한 신규 상태 기계**이므로 attach 스트림·e2e와 같은 PR에 묶지 않는다.

- `LOCAL_CONTROL` conduit마다 **독립된 `request_id` 공간**을 준다: 데몬이 (conduit, peer_request_id) ↔ daemon_request_id 재매핑 표를 유지하고 `Response`를 원 요청자에게만 되돌린다. 표는 conduit당 상한(`MAX_INFLIGHT_REQUESTS_PER_CONN`과 같은 64)을 갖고 초과 시 `RESOURCE_EXHAUSTED`, conduit 종료 시 그 항목을 **전량** 정리한다(누수 금지).
- 비동기 `SessionEvent`(`request_id = 0`)는 그 `session_id`를 구독 중인 conduit들에 라우팅한다. `session.writer_changed`는 "모든 read 소비자에게 broadcast"라는 `docs/CLI.md` §6.4 계약 그대로 그 host의 모든 control conduit에 전달하고, 모르는 `session_id`의 event는 클라이언트가 무시한다.
- `Ping`은 데몬이 직접 `Pong`으로 답한다 — liveness는 연결 소유자의 몫이며 CLI로 새어 나가지 않는다.
- conduit이 죽으면 대응 QUIC 스트림을 reset하고, QUIC 연결이 죽으면 그 host의 모든 conduit을 명확한 오류로 끝낸다.

*라우팅 배선.* `Ops::connect`/`connect_target`(`crates/qsh-core/src/ops/session.rs`의 심볼)이 `resolve_host_route`(Step 5)를 통해 `PeerRoute::{Forward(PeerTarget), Reverse(LocalRoute)}`로 갈라지도록 확장하고, `Connected`가 두 링크를 모두 표현하게 한다. `Connected::peer_fingerprint()`(`ops/session.rs`의 심볼)는 역방향에서 `LocalHelloAck.peer_fingerprint`를 반환한다 — 이것이 ADR-0007의 "제시 조건"(peer SPKI 일치 시에만 토큰 전송, 불일치는 `peer_mismatch`로 fail closed)이 역방향에서도 살아 있게 하는 유일한 방법이다. 링크 추상화는 **generic이 아니라 enum**으로 한다(`ControlLink::{Quic, Local}`): generic화하면 `Session`/`Attached`/`AttachWriter`/recovery driver 전부에 타입 파라미터가 번지는데, enum은 호출부 시그니처를 하나도 바꾸지 않고 두 번째 구현을 준다. **이 enum은 ADR-0005의 trait이 아니다.** ADR-0005가 P0 산출물로 요구한 `Transport`/`StreamMux` trait의 축은 QUIC vs TCP이고, `ControlLink`의 축은 QUIC vs 로컬 IPC로 서로 다르다 — 그 trait은 코드베이스 어디에도 아직 없는 미이행 P0 부채이며(§3 유예 항목), M3는 그것을 갚지도 대체하지도 않는다. `ControlLink`를 두는 이유는 순전히 위 세 번째 문장(호출부 무변경)이고, 세 번째 구현(P1 TCP)이 오는 시점이 `Transport`/`StreamMux` trait 전환의 자연스러운 트리거로 남는다.

**결과: `session_open/get/list/read/write/resize/close`의 본문은 한 줄도 바뀌지 않는다** — 링크만 다르다. 역방향 전용 비즈니스 로직 0. `session_ref`의 host alias는 등록 이름이며 조립·해석은 ADR-0007 그대로다.

> **불변식(다음 step이 깨면 안 됨).** writer lease는 broker에서 **connection**에 결합돼 있으므로(`purge_connection`), 역방향에서는 CLI 프로세스가 아니라 **데몬의 연결**에 묶인다. CLI가 죽어도 lease는 데몬 연결이 살아 있는 동안 남고, 다음 대화형 attach가 기본 steal로 회수한다(정상 경로). `no_steal` 자동화는 그동안 `SESSION_CONFLICT`를 본다 — 정방향과 다른 **관찰 가능한 차이**이므로 §4의 감시 항목이자 `docs/CLI.md` §6.13의 문서화 대상이다. conduit 단위 lease 정체성은 broker 상태 모델을 건드리므로 M4/M5로 이관한다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/localctl/daemon.rs` (확장 — control 다중화, event 라우팅, `Ping` 응답)
- `crates/qsh-core/src/localctl/client.rs` (확장 — control conduit 클라이언트)
- `crates/qsh-core/src/client/link.rs` (신규 — `ControlLink` enum)
- `crates/qsh-core/src/client/mod.rs`, `src/ops/mod.rs`, `src/ops/session.rs` (확장 — link 경유, `PeerRoute`, `peer_fingerprint`)
- `docs/design/protocol.md` §11-3 (개정 — 다중화 규칙이 Step 1의 기술과 어긋나면 문서를 먼저 고친다)

**(c) 빚지는 테스트 (`docs/design/testing.md` L3):** 멀티플렉서 **적대적** 유닛 — 두 conduit이 **같은 peer_request_id**를 써도 응답이 뒤바뀌지 않음(교차 응답 0건을 property로 단언), event가 잘못된 conduit으로 새지 않음, conduit 사망 시 대응 QUIC 스트림 reset + 표 항목 전량 정리, 상한 초과 시 `RESOURCE_EXHAUSTED`. L3 — `crates/qsh-testkit/tests/reverse_session_ops.rs` 신규: target(broker 보유) ← controller 데몬 ← CLI 3자를 in-process로 세우고 `session.open → get → list → read → write → resize → close` 전 경로가 **정방향과 같은 시나리오 함수**를 두 route로 파라미터화해 통과. **미인가 principal의 `session.open`이 target에서 `PERMISSION_DENIED`로 거부됨** — "역방향 등록은 도달성만 부여하고 권한은 부여하지 않는다"(§11-3)의 기계적 단언이며 이 마일스톤의 가장 중요한 보안 테스트다. `resume.json`의 `peer_spki_sha256`이 `LocalHelloAck.peer_fingerprint`에서 오고, 불일치 시 토큰을 보내지 않고 로컬 `SESSION_NOT_FOUND`(`peer_mismatch`)로 실패함.

**(d) 완료 판정:** 역방향 위에서 headless session op 전 경로가 결정적으로 green. `qsh-cli`에 UDS·소켓·인가·세션 로직 0줄(arch-lint가 기계적으로 강제). 데몬을 죽이면 CLI가 명확한 오류로 끝나고 target의 세션은 살아 있음. Windows leg의 nextest green(다중화·라우팅 코드는 `localctl`/`reverse` 아래 `cfg(unix)` 전용이라 나머지 `qsh-cli` 스위트에 영향이 없다). **DEFERRED 판정(§2 규율, H1):** `PERMISSION_DENIED`(미인가 principal의 `session.open` 거부)와 `RESOURCE_EXHAUSTED`(conduit in-flight 상한 초과)가 이 step에서 처음 **producer**를 얻는다 — 그러나 (c)의 테스트는 `qsh-testkit` in-process 하네스 레벨이고 `CARGO_BIN_EXE_qsh`를 통한 `--json` envelope 캡처가 아니므로, `fixtures.rs`의 `DEFERRED`에서는 아직 제거하지 않는다(경로 b): 두 코드의 사유 문자열을 "테스트키트 레벨 producer는 있으나 CLI 바이너리 envelope 캡처가 없음(M3 Step 6)"으로 갱신한다. `UNSUPPORTED`는 이 step에서 변화 없음.

**(e) 인용:** `docs/design/protocol.md` §7(ticket은 ACL 통과 후에만·단회용 30 s), §9(control 스트림 순서 계약·`MAX_INFLIGHT_REQUESTS_PER_CONN`), §11-3, `docs/CLI.md` §6.2·§6.3·§6.4(event broadcast·토큰 커스터디)·§11(frontend 제약), ADR-0005(프로토콜 코드는 transport 추상화에 대해), ADR-0007(제시 조건·`session_ref` 조립), `docs/design/architecture.md` §2·§3.

---

### Step 7 — data 스트림 splice + 역방향 위 대화형 attach + 실프로세스 e2e — **DoD 1**

**(a) 범위:** `LOCAL_STREAM` conduit은 `LocalHello` 다음에 오는 wire `StreamHeader{SESSION_DATA, ticket}`를 그대로 QUIC bidi 스트림으로 열어 양방향 프레임 펌프가 된다(내용을 해석하지 않는다; `PRIORITY_SESSION_DATA` 100 유지, `docs/design/protocol.md` §12). `DataLink` enum이 `Attached`/`AttachWriter`/`AttachReader`를 두 링크 위에서 동작하게 한다. **TUI는 한 줄도 바뀌지 않는다** — Step 5–7이 만든 것은 `Ops` 아래의 경로뿐이다.

*DoD 1 마감.* `qsh listen` / `qsh reverse` / 대화형 클라이언트 세 프로세스를 실제로 띄운다. `CARGO_BIN_EXE_qsh`가 필요하므로 테스트는 `crates/qsh-cli/tests/`에 둔다(M2의 `session_kill9.rs`·`attach_recovery.rs`가 같은 이유로 그 위치다). controller와 target은 각각 격리된 `$QSH_CONFIG_DIR` + `key_store = "file"` 프로필로 서로를 pin하고, target은 `127.0.0.1`의 controller에 등록하며, 세 번째 프로세스가 pty 아래에서(`expectrl`, M2 `tui_expect.rs` 하네스 재사용) `qsh <name>`으로 셸을 잡아 프롬프트 왕복 → `~d` detach → `qsh attach <name>/<session_id>`로 재attach까지 확인한다.

**"NAT 뒤"는 CI에서 재현 불가이므로 구조로 대신한다**: target 프로세스는 **어떤 포트도 listen하지 않는다**(`qsh serve`를 띄우지 않는다). controller만 bind한다 — 도달성이 오직 역방향 등록에서 온다는 것이 곧 NAT 뒤의 본질이며, 이것을 테스트의 통과 조건으로 단언한다(target 프로세스가 listen 소켓을 갖지 않음을 확인).

*마감 정리.* exit-code matrix(`exit_code_matrix.rs`)는 envelope를 내는 op에만 행을 추가한다(미등록 host attach → 255/`HOST_NOT_FOUND`, 이름 중복 라우팅 → 255/`INVALID_ARGUMENT`) — `qsh reverse`/`qsh listen`은 §2.4의 장기 실행 모드라 JSON envelope가 없고, matrix의 `check()`는 `--json` 실행에서 envelope를 읽어 단언하므로 이 둘은 애초에 표에 들어갈 수 없다. `qsh reverse` 등록 거부와 `qsh listen` bind 충돌은 matrix가 아니라 **별도 단언**으로 고정한다: stderr 진단 1줄 + exit 255 + stdout 0바이트. 이 두 실패의 오류 코드가 `DEFERRED`에 남는지는 §2 규율(H1)을 따른다. `--jsonl` 순수성에 역방향 세션 행 추가.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/localctl/daemon.rs`, `client.rs` (확장 — data conduit splice)
- `crates/qsh-core/src/client/link.rs` (확장 — `DataLink`)
- `crates/qsh-cli/tests/reverse_e2e.rs` (신규 — 3-프로세스 e2e, DoD 1 마감)
- `crates/qsh-cli/tests/exit_code_matrix.rs`, `tests/jsonl_purity.rs` (확장)

**(c) 빚지는 테스트 (`docs/design/testing.md` L3·L5·L6):** L3 — `crates/qsh-testkit/tests/reverse_attach.rs`: 역방향 attach 스트림 위 output 순서·sequence 단조성, input ack/dedup, 두 CLI가 동시에 붙었을 때 `request_id` 격리와 event broadcast, 두 번째 attach의 기본 steal / `no_steal` → `SESSION_CONFLICT`. L5 — 위 3-프로세스 e2e(클라이언트를 pty 아래에서 실행해 raw mode 경로가 실제로 돌게 한다). L6 — exit-code matrix가 human/JSON 두 모드에서 같은 exit code를 냄.

**(d) 완료 판정:** **DoD 1 green**(실 프로세스 3개, target은 listen 소켓 0개). `qsh-cli`에 인증·ACL·세션 로직 0줄 재확인. detach 후 세션이 `running`으로 남고 재attach 가능. Windows leg의 nextest green(`reverse_e2e.rs`를 포함해 이 step의 신규 테스트는 전부 `cfg(unix)` — PTY host가 없는 Windows에서는 컴파일만 되고 실행되지 않는다). **DEFERRED 판정(§2 규율, H1):** DoD 1의 e2e 시나리오는 happy path(등록 → attach → detach → reattach)만 다뤄 미인가 principal·in-flight 초과를 CLI 바이너리로 재현하지 않는다 — 따라서 `PERMISSION_DENIED`·`UNSUPPORTED`·`RESOURCE_EXHAUSTED`는 M3 종료 시점까지 `DEFERRED`로 남는다(경로 b 유지). `HOST_NOT_FOUND`·`INVALID_ARGUMENT`·`CONNECTION_FAILED`는 이미 fixture가 있는 3종이므로 그대로다.

**(e) 인용:** `docs/design/protocol.md` §7(스트림 배치 — Session data 행), §11-3, §12(우선순위 band), `docs/CLI.md` §4(exit code)·§7(대화형 form·detach)·§7.1(대화형 attach는 `session.attach` 하나 위에)·§9·§11, `docs/PRD.md` §6·§11·§15 SC2, `docs/design/testing.md` L5, `docs/ROADMAP.md` M3 DoD 1번.

---

### Step 8 — 역방향 위 resume: 재등록 후 **같은 세션** 이어붙이기 + 60초 차단 게이트 — **DoD 2**

**(a) 범위:** M2가 만든 §10 resume을 역방향 토폴로지에 매핑한다. **새 resume 로직을 만들지 않는다** — 토큰 발급·rotation·해시 저장·peer 결합·gap·input dedup·`sequence ≤ L` 폐기·미-ack input 재적용은 전부 그대로다(target의 인증서가 그대로이므로 `resume.json`의 `peer_spki_sha256` 결합도 그대로 성립하고, 그 값은 Step 6이 `LocalHelloAck.peer_fingerprint`에서 얻는다). 바뀌는 것은 **"재연결을 누가 하는가"** 뿐이다.

M2의 attach driver는 "감지 → rebind → 재dial → `SessionAttach`"를 한 덩어리로 쥐고 있는데, 역방향에서는 **재dial할 path가 CLI에 없다** — 재연결의 주체는 target이다. 그래서 driver의 **재연결 단계만** seam으로 뽑는다(`trait Reconnect`, 두 구현: `DialReconnect`(정방향, 기존 로직 그대로) / `LocalReconnect`(역방향)). 감지(`client/pathwatch.rs`)·resume(§10 Reattach 절차 1–5단계)·텔레메트리는 **한 줄도 바뀌지 않는다** — M2가 가장 비싸게 만든 자산이 전부 재사용된다.

`LocalReconnect`는 데몬에 **새 `generation`의 live 등록을 기다렸다가**(`LocalHello.wait_ms`, `LOCAL_WAIT_MAX`로 clamp; stale 창 안이면 대기하고 창이 지나면 `HOST_NOT_FOUND`) 새 control/stream conduit을 얻어 `SessionAttach{session_id, resume_token, last_output_seq = L}`로 §10 Reattach 절차(1–5단계)를 그대로 수행한다. **이 leg에는 migration/rebind이 없다** — 로컬 UDS는 migration 대상이 아니고 QUIC 재수립은 target이 한다. 따라서 **역방향에서는 `recovery == "migrated"`가 나올 수 없고**, 나오면 존재하지 않는 경로가 돈 것이므로 테스트가 이를 단언한다. 데몬이 stale 엔트리에 대한 요청을 즉시 죽이지 않고 창 안에서 기다린다는 것도 단언한다 — 단, 옛 연결로 조용히 흘러가지 않는다(`generation`이 증가해야 진행).

**텔레메트리와 예산 계약.** 기존 `qsh::recovery` 레코드에 additive 필드 `registration_wait_ms`(재등록을 기다린 시간)를 추가한다 — `recovery ∈ {migrated, resumed, failed}` 값 집합은 **바뀌지 않는다**(stderr 진단이며 계약 변경 아님). 정방향의 기준("path 사망 감지 후 2초 내 재dial + resume")을 역방향에 그대로 옮기면 target의 backoff까지 qsh의 예산으로 세게 되므로, 역방향 기준은 **재등록 시점부터 resume 완료까지 2초**다: `time_to_recovery_ms - registration_wait_ms <= 2000`. 이 분해가 없으면 "네트워크가 빨라서 통과"와 "우리가 빨라서 통과"를 구분할 수 없고, M8 캠페인이 migrated/resumed 분해를 역방향 토폴로지로 확장할 수 없다(시퀀싱 원칙 6번: 측정 도구는 측정 대상과 같이 만든다). **필드 집합의 정본은 `docs/CLI.md` §6.4와 `docs/design/testing.md` L4이므로 이 step의 PR이 두 문서를 함께 갱신한다.**

**두 게이트.** `docs/design/testing.md`의 "`sleep()` 금지 / chaos는 PR 게이트" 규율과 "60초"라는 문자 그대로의 DoD를 M2의 `QSH_ACCEPTANCE_STRICT` + `acceptance` job 선례로 푼다.

- (i) **PR 상시 게이트**(`crates/qsh-testkit/tests/reverse_resume_chaos.rs`) — chaos proxy로 target→controller path를 `sever()`하고(감지 + backoff ≥2회를 태울 만큼) 복구시켜, 사전 정의 통과 기준 5개를 단언한다: ① 차단 중 세션이 살아 있고 output이 ring에 계속 쌓인다, ② 재등록이 관측되고 `generation`이 증가한다, ③ 같은 `session_id`에 대한 `SessionAttach`가 성공한다, ④ 차단 전후 이어붙인 output이 기준 stream과 **byte-identical**이고 gap 0이다(생산량이 8 MB ring 안에 머문다), ⑤ 복구가 idle timeout이 뒤늦게 터진 결과가 **아니다** — `qsh::recovery` 레코드가 정확히 1건, `recovery != "migrated"`, 예산 부등식 `time_to_recovery_ms - registration_wait_ms <= 2000`이 성립, 그리고 테스트가 독립적으로 잰 벽시계가 **`PathWatchConfig`에서 유도한 감지 예산 + backoff 상한 + 2 s** 안에 들며 그 감지 예산 자체가 테스트가 적어 둔 상한(`DETECTION_CEILING`) 아래다. 마지막 조건이 없으면 cadence·strike를 늘렸을 때 예산도 같이 늘어 그냥 통과한다 — M2 `crates/qsh-cli/tests/attach_recovery.rs`의 `DETECTION_CEILING` 규율 그대로다. seeded, `sleep()` 없음, 수 초.
- (ii) **수용 게이트**(`crates/qsh-cli/tests/reverse_blackout.rs`) — DoD 문구를 문자 그대로 마감하는 **실제 60초 차단**. `QSH_ACCEPTANCE_SLOW`가 설정된 경우에만 실행하고, `.github/workflows/ci.yml`의 기존 `acceptance` job(= `ci-ok`가 `needs`로 요구하는 job)에 추가해 **상시 게이트**로 만든다 — `#[ignore]` + 수동 1회 certify로 두면 60초짜리 결정적 테스트를 상시 게이트로 만들 인프라가 이미 있는데 쓰지 않는 것이 된다. 60 s는 45 s idle timeout보다 길어 QUIC 연결이 확실히 죽고, target의 backoff 루프가 복구를 담당하며, `[serve].resume_ttl`(기본 24 h)에는 한참 못 미치므로 세션·credential 모두 살아 있어야 한다 — 그렇지 않으면 그것이 곧 버그다. 통과 기준은 (i)과 동일한 5개를 쓴다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/client/reconnect.rs` (리팩터 — `trait Reconnect` + `DialReconnect`/`LocalReconnect`)
- `crates/qsh-core/src/ops/session.rs` (확장 — driver의 재연결 단계를 seam 경유로, `RecoveryConfig`에 `registration_wait` 상한)
- `crates/qsh-core/src/localctl/{daemon,client}.rs` (확장 — `LocalHello.wait_ms` 대기 시맨틱, `generation` 보고)
- `crates/qsh-core/src/telemetry.rs` (확장 — `registration_wait_ms` additive 필드)
- `crates/qsh-testkit/tests/reverse_resume_chaos.rs` (신규 — PR 상시 게이트)
- `crates/qsh-cli/tests/reverse_blackout.rs` (신규 — 60초 수용 게이트), `.github/workflows/ci.yml` (확장 — `acceptance` job에 추가)
- `docs/CLI.md` §6.4, `docs/design/testing.md` L4 (갱신 — 진단 필드 집합)

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L4):** L2 — `LocalReconnect`의 대기·타임아웃·`generation` 단조성 단위 테스트(`TestClock`), 옛 `generation`의 등록으로는 진행하지 않음. L4 — 위 두 게이트.

**(d) 완료 판정:** **DoD 2 green.** 두 게이트 모두 체크인되고 예산 부등식이 주석이 아니라 assertion으로 존재한다. `acceptance` job 로그가 60초 게이트의 정본이다. resume 토큰이 로그·audit·JSON·localctl 프레임 어디에도 나타나지 않음(`resume_secrecy.rs` 확장으로 재확인). Windows leg의 nextest green(두 게이트 모두 unix 전용 reverse 하네스 위에 있다 — Windows에서는 컴파일만 확인된다).

**(e) 인용:** `docs/design/protocol.md` §10 전체(토큰·rotation·Reattach 절차 1–5단계·gap·input 무손실·"자격증명 임계 구역은 취소 불가"), §11-4("target의 세션들은 재등록과 무관하게 유지되고 §10으로 resume된다"), §2(migration은 지연 최적화, correctness는 resume), `docs/CLI.md` §6.4(recovery 텔레메트리는 stderr 전용), `docs/PRD.md` §8·§9·§13·§15 SC3·SC4·SC5, `docs/design/testing.md` L4(2초 기준·"통과 기준은 사전 정의"·seeded), `docs/ROADMAP.md` M3 DoD 2번, §4 일정 리스크 1번, ADR-0007.

---

### Step 9 — controller reachability: 문서 + doctor 진단 항목 — **DoD 4**

**(a) 범위:** DoD 4는 "docs와 doctor 메시지에 명시"를 요구하지만 **`doctor.run`의 계약 확정은 M7이다**(`docs/CLI.md` §6.11 "`doctor.run`은 operation 이름만 예약되어 있으며 계약은 M7에서 확정한다"). 한 마일스톤이 다른 마일스톤의 계약을 선점하면 M7의 스톱워치 DoD가 대신 갚아야 할 빚이 된다. 그래서 이 step이 만드는 것은 `doctor.run` op도 `qsh doctor` 서브커맨드도 아니라 **진단 *항목* 하나**다.

`crates/qsh-core/src/doctor.rs`에 `Diagnostic { id: DiagnosticId::ControllerUnreachable, code: "controller_unreachable", message, remedy }`를 정의한다(안정된 code 문자열 + 사람이 읽는 메시지 + 조치). 문안이 곧 계약이다: *"역방향 접속에는 target에서 controller까지 **직접** 도달 가능한 UDP 경로가 필요하다. QSH는 relay·NAT traversal·discovery를 제공하지 않는다(P0 범위 밖) — controller를 공인 주소/포트포워딩/기존 overlay(예: WireGuard·Tailscale) 위에 두어라. controller가 NAT 뒤에 있으면 M3에는 답이 없다."*

**오늘 렌더하는 표면 2곳**: (i) `qsh reverse`의 연결 실패 경로 — dial 실패·handshake 도달 실패 시 stderr에 **정확히 한 번**(백오프 루프가 매 시도마다 반복하지 않는다), (ii) `qsh listen` 시작 배너(어떤 주소로 도달 가능해야 하는지). M7의 `doctor.run`은 **같은 상수를 소비**하므로 문안의 정본이 두 벌 생기지 않고 재작업이 없다.

**문서 3곳**: `README.md` Known limitations(역방향 사용법 + relay/NAT traversal 부재), `docs/CLI.md` §6.13(Step 1이 만든 절에 reachability 요구 명시), `docs/PRD.md` §6의 기존 한 문장("역방향 접속에도 target에서 controller까지 직접 연결 가능한 경로가 필요하다")을 M3에서 그대로 유효한 제약으로 보강 — **같은 편집에서** §6의 예시 `qsh attach company-mac`(§1의 5곳 중 하나)을 `qsh <name>`/`qsh attach <name>/<session_id>`로 교체한다. `docs/ROADMAP.md`는 이 step에서 건드리지 않는다 — §5의 마감 절차가 소유한다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/doctor.rs` (신규 — 진단 항목 정의만. `doctor.run` op·CLI·JSON 계약은 M7)
- `crates/qsh-core/src/reverse/{target,listen}.rs` (확장 — 항목 렌더 지점 2곳)
- `README.md`, `docs/CLI.md` §6.11·§6.13, `docs/PRD.md` §6 (갱신)
- `docs/design/testing.md` (갱신 — "현재 상태" 절을 M3 이후로)

**(c) 빚지는 테스트 (`docs/design/testing.md` L6):** **문서 문구 == 코드 상수 단언** — 위 문서 3곳의 문장이 `qsh-core::doctor`의 상수와 **같은 텍스트**임을 테스트가 확인한다(문서와 메시지가 갈라지지 않게; M2의 fixture 규율과 같은 발상이며 코드 문안만 고정하는 회귀 게이트보다 한 단계 강하다). 도달 불가 controller를 향한 `qsh reverse`가 그 항목을 stderr에 **정확히 한 번** 내고 stdout에는 아무것도 쓰지 않음(§2.2).

**(d) 완료 판정:** **DoD 4 green.** `doctor.run` operation·`qsh doctor` CLI·UDP probe는 여전히 존재하지 않는다(M7 범위 침범 0). README만 보고도 "controller는 도달 가능해야 한다"를 알 수 있다. Windows leg의 nextest green(진단 항목은 순수 데이터이므로 unix 게이트가 없다 — 이 step은 Windows에서도 전체가 실행돼야 한다).

**(e) 인용:** `docs/ROADMAP.md` M3 DoD 4번·M3 명시적 out(relay/NAT traversal/discovery)·§3 유예 가드레일("`--relay` flag는 stub조차 없음")·M7 범위(doctor), `docs/PRD.md` §6, §15 SC1, `docs/CLI.md` §2.2·§6.11(doctor.run 계약은 M7)·§6.13, `docs/design/protocol.md` §14(doctor의 UDP probe는 P0 의무 — 그 probe 자체는 M7이 구현한다), ADR-0005.

---

## 3. 명시적 non-goals (M4+ 유예)

`docs/ROADMAP.md` M3 절 "명시적 out" 인용: **relay, NAT traversal, discovery.**

추가로 M3 범위에 넣지 않는 항목(같은 문서의 다른 조항에서 파생):

- **터널(M4)** — `-L`/`-R`, `tunnel.*`, `RemoteForwardOpen/Close`. wire `ControlMessage` 40–41과 `Response` 4는 계속 `reserved`. `docs/ROADMAP.md` §1 원칙 4번대로 터널은 M3의 role 모델 **위에** 얹히며 "`-R` over reverse"가 M4의 진짜 흥미로운 케이스다 — M3는 터널 코드를 0줄 쓰고 role 축·localctl seam·링크 enum만 깐다. `qsh tunnels`(localctl의 세 번째 소비자)도 M4다.
- **ACL 정책 엔진(M5)** — `acl.toml` 로더·principal/wildcard 매칭·`qsh acl check`. M3가 추가하는 것은 `Action::HostReverse` variant와 그 호출 지점뿐이고 정책은 여전히 `AllowAllPinned`다.
- **`doctor.run` op·`qsh doctor` CLI·UDP reachability probe(M7)** — Step 9는 진단 *항목*만 만든다.
- **hosts.toml 기반 host directory(M7)** — M3의 forward host 출처는 여전히 trust.toml pinned peer 하나다. `qsh hosts`가 구현된다고 해서 host directory 파일 포맷을 만들지 않는다.
- **invite code pairing·private CA(M7)·MCP adapter(M6)** — 역방향을 위한 새 pairing UX를 만들지 않는다. 양쪽 pin은 기존 `qsh trust add --fingerprint`로 설정한다.
- **별도 supervisor 프로세스(P1)** — ADR-0003. M3는 localctl seam을 도입하되 세션은 여전히 host 프로세스(`qsh reverse`/`qsh serve`) 안에 있다.
- **P1 TCP fallback** — ADR-0005. 역방향도 QUIC 전용이며 M3가 지는 의무는 wire가 QUIC 고유 개념에 의존하지 않게 유지하는 것뿐이다. **`Transport`/`StreamMux` trait은 ADR-0005의 미이행 P0 항목으로 남으며 M3 범위 밖이다** — 코드베이스 어디에도 아직 없고, Step 6의 `ControlLink` enum(QUIC vs 로컬 IPC)은 그 trait(QUIC vs TCP)과 축이 달라 갚지도 대체하지도 않는다. 세 번째 구현(P1 TCP)이 와야 trait 전환이 트리거된다.
- **ADR-0005 `Transport`/`StreamMux` trait(P0 산출물, 미이행)** — M3는 이 부채를 갚지 않는다. Step 6의 `ControlLink`/`DataLink` enum은 그 대체물이 아니다(위 항목 참고). 이 부채의 존재를 여기 명시적으로 기록해 M4/P1 계획의 입력으로 넘긴다.
- **`session.signal`(wire 25)·SOCKS `-D`·file copy·relay flag stub** — 전부 그대로 P1 유예. 역방향 세션에도 예외 없이 `UNSUPPORTED`.
- **Multi-attach observer(P2)** — 역방향 attach도 writer lease 규칙만 따른다. 데몬이 여러 CLI를 다중화하는 것은 **연결 다중화**이지 관찰자 개념이 아니다(두 번째 attach는 여전히 steal 또는 `SESSION_CONFLICT`).
- **역방향 전용 resume 변형** — 만들지 않는다. §10을 그대로 쓴다(Step 8).
- **실기기 mobility 캠페인의 역방향 leg** — M8. M3의 60초 게이트는 기능적 정확성 검증이지 SC3의 통계적 측정이 아니다(SC3 판정은 M8 N≥60이 정본).
- **Windows(client P1 / host P2)** — localctl(UDS)과 host 역할(PTY)은 `cfg(unix)`이므로 M3가 이 플랫폼에 새 기능을 얹지 않는다는 뜻이다. **CI Windows leg 자체는 clippy만 도는 것이 아니라 전체 `cargo nextest run --workspace` + doc-test까지 돈다**(§2, `.github/workflows/ci.yml`) — unix 전용 코드가 `cfg(unix)`로 정확히 빠졌는지를 매 step이 그 nextest green으로 확인한다.

**M4에 넘기는 것(지금 기록해 둔다):** (i) `ReverseRegistration.capabilities`의 첫 소비자 — 역방향 host가 `tunnel.remote`를 제공하는지 판단할 곳은 M4다(M3는 registry에 기록만 한다), (ii) writer lease가 데몬 연결에 결합되는 성질(Step 6 불변식) — conduit 단위 lease 정체성이 필요해지면 M4/M5가 broker 상태 모델과 함께 다룬다, (iii) `qsh tunnels`가 요구할 localctl 요청/응답 확장, (iv) `ControlLink`/`DataLink` enum → trait 전환(P1 TCP가 세 번째 구현으로 올 때).

## 4. 리스크와 감시 항목

`docs/ROADMAP.md` §4 "일정 리스크 5건" 중 M3와 직결되는 항목:

> 4. **In-listener 세션과 listener 재시작/업그레이드의 충돌은 구조적.** 대응: ADR-0003의 `SessionBackend` seam을 처음부터 순수하게 유지(CI로 transport import 금지 확인), graceful re-exec(fd 보존 handoff)을 M8 stretch로 비용 산정.

→ **Step 3·5·6**에 매핑. M3는 이 대응책의 두 번째 절반(localctl)을 **처음으로 실물화**하는 마일스톤이므로, seam이 오염되면 P1 supervisor 전환이 재작성이 된다. 감시 지점: (a) `localctl/{frame,client}.rs`와 `reverse/registry.rs`가 broker와 같은 토큰 집합(`qsh_transport`·`quinn`·`rustls`·`crate::client`·`crate::Principal`·`crate::Fingerprint`)을 참조하지 않는다는 **arch-lint 규칙이 실제로 존재하고 위반 주입에 실패하는가**(구두 약속이면 지켜지지 않는다 — M2 Step 2가 `broker/`에서 배운 것; `crate::client` 금지가 특히 중요하다 — `reverse/registry.rs`의 `ReverseEntry`가 살아 있는 `client::Session`을 직접 쥐면 이 규칙이 통과해도 거짓 안심이다, Step 3), (b) **규칙을 daemon까지 잘못 걸지 않았는가** — daemon은 QUIC로의 bridge라 transport 사용이 정상이고, 잘못 걸면 통과시키려고 bridge를 client 쪽으로 옮기는 왜곡이 생긴다, (c) localctl이 나르는 것이 **wire 메시지**(`ControlMessage`/`SessionFrame`/`StreamHeader`)뿐이고 broker 내부 타입이 아닌가.

> 1. **SC3(≥95% mobility)은 CI로 측정 불가능한 측정 문제이고, 통과 기준이 미정의면 그 자체가 리스크.**

→ **Step 8**. 역방향은 SC3에 **두 번째 복구 토폴로지**를 추가한다(감지 주체와 재연결 주체가 서로 다른 프로세스다). 감시 지점: 통과 기준 5개가 사전 정의돼 있는가, idle timeout에 기댄 복구를 배제하는 단언(`DETECTION_CEILING`)이 코드에 있는가, 역방향에서 `migrated`가 나오지 않는다는 사실이 단언으로 고정돼 있는가, `time_to_recovery_ms`를 `registration_wait_ms`로 분해하지 않으면 M8 캠페인이 "qsh가 느린 것"과 "target이 아직 안 돌아온 것"을 영원히 구분할 수 없다는 점. M8 실기기 캠페인(N≥60)에 역방향 행을 추가할지는 M8이 결정하되 **분해 필드는 M3에서 심는다**(시퀀싱 원칙 6번).

> 3. **Identity·keystore·pairing이 SC1(간판 숫자)의 critical path.**

→ M3판: `qsh listen`/`qsh reverse`는 **상주 프로세스**이고 M3는 프로세스를 3개 띄우는 마일스톤이라 macOS 미서명 바이너리의 Keychain 프롬프트 빈도가 M2보다 높다. 대응: 전 자동 테스트와 하네스는 `$QSH_CONFIG_DIR` 격리 프로필 + `key_store = "file"`로 고정하고, 재접속 루프는 identity를 **루프 밖에서 한 번** 로드한다(Step 4의 명시 요구).

`docs/design/architecture.md` §9 리스크 중 M3가 직접 지는 항목:

> 2. **In-listener 세션 vs listener 재시작** — seam(`SessionBackend`+UDS)이 오염되면 supervisor 전환이 재작성이 된다.

→ **Step 5**(모듈 분리 + arch-lint 파일 스코프 확장).

> 1. **Resume/replay 정합성** — byte offset 경계·gap 계산·lease 경합 버그는 제품의 핵심 약속을 깬다.

→ **Step 8**. 역방향에서 새로 생기는 경합: target이 재등록한 직후 **옛 연결의 lease가 아직 정리되지 않은 창**. 연결 사망 → task 취소 → `purge_connection`(ticket 폐기 + lease 해제)의 순서가 §9의 계약대로 유지되는지, 재attach가 `SESSION_CONFLICT`로 튕기지 않는지를 테스트로 고정한다.

추가 감시 항목 (M3 고유):

- **데몬 멀티플렉서가 M3의 유일한 신규 상태 기계다.** request_id 재매핑·event 라우팅·conduit 수명은 버그가 **조용한 오배송**으로 나타나는 종류의 코드이고, 응답이 다른 CLI에게 가면 세션 내용이 잘못된 프로세스로 새는 보안 사건이다. 그래서 Step 6을 attach·e2e와 분리했고, 유닛 테스트를 "두 conduit이 같은 peer_request_id를 쓴다"는 **적대적** 케이스로 쓴다. 이 코드는 M8 stateful fuzzer 후보로 백로그에 남긴다.
- **"등록 = 권한"의 혼동.** 이 마일스톤에서 가장 값비싼 오해다. 감시: `PERMISSION_DENIED`를 내는 주체가 **target**임을 단언하는 Step 6의 테스트가 살아 있는가(§11-3).
- **Name-squatting.** 등록 이름은 controller의 통제 하에 있어야 한다. 감시: `offered_name`이 인증·이름 확정 어느 경로에도 기본으로 들어가지 않는가, `allow_advertised_names=false`가 기본인가, 이름 충돌이 조용한 덮어쓰기가 아닌가. **알려진 latent gap(Step 3 검증이 발굴, 의도적 유예):** `allow_advertised_names=true`일 때 `offered_name`을 trust-store alias 네임스페이스와 대조하지 않는다 — registry는 설계상 trust store를 쥐지 않으므로 오프라인 pinned peer의 alias를 CA-path peer가 선점하는 것을 충돌 검사(live 등록만 봄)가 막지 못한다. interim `AllowAllPinned`가 모든 비-Pin peer를 choke point에서 거부하므로 M1–M4에서는 도달 불가이며, **M5 정책 엔진이 CA principal을 허용할 수 있게 되는 시점**(또는 Step 5 `resolve_host_route`가 이름 우선순위를 정의하는 시점)에 이름 네임스페이스 통합 검사로 갚는다. `reverse/registry.rs`의 advertised-name 분기 주석에도 동일 내용을 기록했다.
- **localctl의 신뢰 경계.** 소켓 권한 + peer credential 이중 방어, "localctl은 새 권한을 부여하지 않는다"는 문서 문장, 그리고 데몬이 CLI가 보낸 principal 유사 정보를 **어디에서도 신뢰하지 않는가**(principal은 항상 TLS에서 — §3).
- **데몬 다중성.** 조회는 감추지 않고(두 항목 반환), 라우팅은 fail closed(`INVALID_ARGUMENT`). 감시: 조용한 임의 선택이 코드에 생기지 않는가, 그리고 목록·단건·라우팅이 **같은 함수**를 공유하는가.
- **writer lease의 결합 대상이 데몬 연결이라는 관찰 가능한 차이.** CLI 사망이 lease를 즉시 풀지 않고 `no_steal` 자동화가 정방향과 다르게 `SESSION_CONFLICT`를 본다. 감추지 않고 CLI.md §6.13에 문서화하고 여기서 감시한다.
- **`registration_wait_ms` 추가가 진단 필드 집합의 정본(CLI.md §6.4, testing.md L4)과 함께 갱신됐는가.** 문서를 먼저 고치는 규율의 이행이며, 빠지면 산문과 구현이 갈라진다.
- **doctor 진단 code 어휘의 M7 재설계 여지.** M3가 `controller_unreachable`을 안정 code로 확정하고 회귀 테스트로 고정하면, M7이 "안정된 JSON code" 어휘를 재설계하려 할 때 M3의 테스트가 그것을 막는다. 의도된 결합이지만 **M7이 어휘를 바꾸려면 M3의 테스트도 함께 고치는 것이 정상 경로**임을 여기 기록해 둔다.
- **keep-alive 15 s가 실제 NAT binding을 유지하는지는 실측 대상이다.** M3는 이 값을 튜닝하지 않는다(§2가 "idle timeout을 키워 절전 생존을 추구하지 않는다"고 못박았다). 실기기에서 NAT가 15 s보다 짧은 binding timeout을 쓰면 재접속 루프가 대신 흡수하며, 관측되면 M8 백로그.
- **CI 시간 예산.** Step 8의 60초 게이트는 `acceptance` job에만 있고 PR 유닛 스위트에는 없다. 감시: PR 스위트 총 시간이 M2 대비 유의미하게 늘지 않는가.
- **Windows leg.** M2에서 한 번 깨졌던 표면(`cfg(unix)` 의존)이 UDS로 다시 커진다. Windows CI leg는 clippy만이 아니라 전체 nextest·doc-test가 돈다(`.github/workflows/ci.yml`) — 빠뜨린 `cfg(unix)` 게이트는 컴파일이 아니라 테스트 단계에서 조용히 깨진다. 감시: 전 타깃 clippy green과 **Windows leg의 nextest green**이 매 step의 완료 조건에 포함돼 있는가.

### 4.1 이 계획이 확정한 결정 (Step 1이 정본 문서에 기록한다)

조사 단계에서 문서가 답하지 않던 항목들이다. 아래 결정은 **Step 1에서 "정본" 칸의 문서에 반영된 뒤**에 구현이 시작된다 — 구현이 계약을 발명하지 않게 하는 것이 이 표의 목적이다.

| # | 질문 | 결정 | 정본 |
|---|---|---|---|
| 1 | ROADMAP/PRD의 `qsh attach <name>`이 새 CLI form인가 | **아니다 — 새 form을 만들지 않는다.** `<name>`은 forward든 reverse든 동일한 host alias이며, 셸 획득은 `qsh [user@]<name>`(신규 세션)과 `qsh attach <name>/<session_id>`(재attach)다. PRD §6의 `qsh attach company-mac`은 CLI.md §7 확정 이전의 예시 산문이다. DoD 1은 이 두 form으로 마감한다(§1) | CLI.md §7·§7.1, 신설 §6.13, PRD §11, ADR-0007 |
| 2 | `reserved` 태그를 채우는 것이 additive 규칙 위반인가 | 아니다 — 그 태그가 예약된 바로 그 메시지(`Hello.reverse = ReverseRegistration`)로 채우는 것은 재사용이 아니라 예약의 실현. `.proto` 머리말에 명문화 | `wire/v1.proto` 머리말, protocol.md §9 |
| 3 | "heartbeat"의 실체 | 신규 wire 메시지 없음. 연결 유지 = QUIC keep-alive 15 s(§2), 사망 감지 = control 스트림의 애플리케이션 `Ping`/`Pong`(§10, §11 머리말의 대칭 원칙이므로 target도 보낸다), 재등록 = 지수 backoff + jitter 루프. **단, host 역할의 요청 발신·`Pong` 상관은 신규 배선이다**(현재 `Server`는 수신·응답 루프뿐이고 unsolicited `Pong`을 드롭한다) | protocol.md §2·§10·§11 머리말·§11-4 |
| 4 | `ReverseRegistration.capabilities`의 의미 | 이 등록에서 target이 **host 역할로** 제공하는 기능 집합(비면 `Hello.capabilities`와 동일), 미지 문자열은 무시. **인가·identity 입력이 절대 아니다.** M3는 registry에 기록만 하고 JSON에 노출하지 않으며 첫 소비자는 M4 | protocol.md §9·§11-2 |
| 5 | 역방향에 새 capability 문자열이 필요한가 | 아니다 — 신호는 `Hello.reverse`의 **존재**이고 미지원 수신자는 `UNSUPPORTED`로 답한다. `LOCAL_CAPABILITIES`와 `local_capabilities_advertise_exactly_what_is_implemented`는 M3 내내 불변 | protocol.md §4·§11-2, wire.rs |
| 6 | localctl 메시지 집합과 mux 모델 | 별도 package `qsh.local/v1`(M8의 wire freeze와 분리 — `v1.proto`는 자신을 "QUIC 스트림 위 메시지의 문법"으로 정의한다), **UDS 연결 1개 = conduit 1개**, 첫 프레임 `LocalHello`가 정체를 정함, 이후 QUIC 위와 동일한 메시지, 데몬은 request_id 재매핑 멀티플렉서. frame **파서**는 §5 재사용, `StreamKind`에 UDS 전용 값 추가 금지 | protocol.md §11-3, 신규 `proto/qsh/local/v1.proto` |
| 7 | 역방향에서 resume token의 peer 결합은 어떻게 유지되나 | `LocalHelloAck.peer_fingerprint` — CLI 프로세스는 TLS endpoint가 아니므로 데몬이 검증한 peer fingerprint를 IPC로 되돌려 주고 `Connected::peer_fingerprint()`가 그것을 반환한다. 이것이 없으면 ADR-0007의 fail-closed 제시 조건이 말없이 사라진다 | ADR-0007 결과 절, protocol.md §10 |
| 8 | 소켓 discovery와 접근 통제 | 런타임 디렉터리의 `*.sock`을 pid 오름차순 probe, 죽은 소켓 unlink, host를 모르는 데몬은 `HOST_NOT_FOUND` → 다음 소켓. 디렉터리 0700 · 소켓 0600 · `SO_PEERCRED`/`getpeereid` euid 일치(이중 방어). localctl은 인가 계층이 아니며 **새 권한을 부여하지 않는다** | protocol.md §11-3, architecture.md §7 |
| 9 | `host.reverse`의 M3 시점 정책 | 모순이 아니다. §11-2의 "기본 deny"는 **매칭 allow가 없으면 거부**라는 `Authorizer`의 default-deny·fail-closed 성질이고, M1–M4 interim `AllowAllPinned`가 그 성질의 현재 구현이다. `host.reverse`에 예외를 만들지 않으며 M3는 `acl.toml`을 읽지 않는다 | ROADMAP §1 원칙 5, architecture.md §6, protocol.md §11-2 |
| 10 | `allow_advertised_names`의 위치·기본값 | `[listen].allow_advertised_names`, 기본 `false`. interim ACL에서 인가되는 peer는 항상 pin이므로 trust alias가 존재하고 이 경로는 사실상 도달 불가 — 구현하되 그 사실을 주석·테스트로 고정한다(이름 확정 규칙을 나중에 소급 삽입하면 이미 등록된 이름의 의미가 바뀐다) | protocol.md §11-2, architecture.md §7 |
| 11 | `qsh hosts`의 forward 출처(M7 이전) | trust.toml pinned peer 중 address가 있는 것. hosts.toml은 M7 그대로 | CLI.md §5·§6.1·§6.8, architecture.md §7 |
| 12 | `Host.state` / `device_id` 값 어휘 | 타입 변경 없음. `state ∈ {reachable, stale, unknown}`(열린 문자열; forward = `unknown`, live 등록 = `reachable`, 죽은 등록 = `stale`). `device_id` = **SPKI fingerprint 문자열**(`sha256:…`) — forward는 핀된 값, reverse는 데몬이 검증한 값. `Hello.device_name`은 쓰지 않는다. `Host`는 emit된 적 없는 placeholder이므로 §5 예시와 `types.rs` doc comment를 함께 교체하는 것은 정의이지 의미 변경이 아니다 | CLI.md §5·§10, protocol.md §3, types.rs:72–85 |
| 13 | 같은 이름이 forward·reverse 양쪽/두 데몬에 있을 때 | **조회는 감추지 않는다** — `hosts`는 두 항목을 그대로 반환한다(§6.2의 "부분 실패를 감추지 않는다" 규율). **라우팅과 `host.get`은 fail closed** — live reverse 우선, 두 데몬 중복은 `INVALID_ARGUMENT`(`details`에 pid). 목록·단건·라우팅은 `resolve_host_route` 한 함수를 공유한다 | CLI.md §6.1·§6.2 |
| 14 | 역방향에서 §10 Reattach 절차(1–5단계)의 매핑 | target이 재dial(backoff)하고, controller의 attach driver는 **새 `generation`의 등록을 기다렸다가** `SessionAttach{last_output_seq}`. 이 leg에 migration/rebind 없음 → `recovery == "migrated"`가 나오면 버그 | protocol.md §10·§11-4 |
| 15 | 역방향 복구 예산 | "재등록 후 2초 내 resume": `time_to_recovery_ms - registration_wait_ms <= 2000`. `registration_wait_ms`는 additive 진단 필드이며 `recovery` 값 집합은 불변. 벽시계 상한은 `PathWatchConfig`에서 유도하고 `DETECTION_CEILING`으로 순환 참조를 끊는다 | testing.md L4, CLI.md §6.4, attach_recovery.rs 선례 |
| 16 | DoD 2의 "60초 차단"을 무엇이 마감하는가 | **이중 게이트** — PR 상시(chaos, 수 초, seeded, 통과 기준 5개) + `acceptance` job의 실제 60초 차단(`QSH_ACCEPTANCE_SLOW`). `#[ignore]` 수동 certify로 두지 않는다: `ci-ok`가 `needs`로 요구하는 `acceptance` job이 이미 있다 | testing.md L4·CI 규율, `.github/workflows/ci.yml`, ROADMAP M3 DoD 2 |
| 17 | DoD 4의 "doctor 메시지" | `doctor.run` op/CLI/UDP probe는 M7 그대로. M3는 진단 *항목*(안정 code + 문안)만 만들고 `qsh reverse` 실패 경로와 `qsh listen` 배너가 렌더하며, 문서 3곳의 문장이 코드 상수와 같은 텍스트임을 테스트가 단언한다. M7의 doctor가 같은 상수를 소비한다 | CLI.md §6.11, ROADMAP M3 DoD 4·M7 |
| 18 | `qsh listen`의 기본 bind | `--bind` > `[listen].bind` > `[::]:4433`(= `qsh serve`와 같은 기본값). 한 호스트에서 둘 다 돌리려면 명시적 `--bind`이며 충돌은 조용한 오작동이 아니라 즉시·명시적 실패(stderr + exit 255). 두 번째 매직 포트는 M7(host profile)이 필요해질 때 정한다 | CLI.md §6.12·§6.13, architecture.md §7 |
| 19 | 역방향에서 writer lease의 결합 대상 | 데몬의 **연결**이다(broker의 lease는 connection 결합). CLI 사망이 lease를 즉시 풀지 않으며 다음 대화형 attach가 기본 steal로 회수한다. 관찰 가능한 차이이므로 §6.13에 문서화하고 감시 항목으로 남긴다. conduit 단위 lease 정체성은 M4/M5 | architecture.md §3, protocol.md §10, CLI.md §6.13 |

### 4.2 구현 중 확정할 값 (측정 후 상수화)

문서가 값을 정하지 않았고 계약도 아닌 것들. 구현 시 정하고 **해당 step의 (a)에 실측 근거와 함께 추기**한다: backoff 3종의 실제 기본값(초안 500 ms / ×2 / 30 s / jitter ±20 %), `[listen].stale_retention`(초안 120 s — `backoff_max_ms`와의 결합 `stale_retention > backoff_max_ms × 3`을 config 검증으로 고정), `LOCAL_WAIT_MAX`(초안 60 s)와 `LocalHello.wait_ms` 기본값, localctl conduit당 in-flight 상한(초안 64), target 측 `PathWatch` idle cadence의 배터리 영향(노트북 target에서 5 s cadence가 과한지), host 역할 `Ping` 발신의 오버헤드.

## 5. 완료 절차

1. §1의 DoD 체크리스트 4항목 전건 통과를 **실제 테스트 실행 로그**로 확인한다(체크박스는 근거가 green일 때만 표시하고, 각 항목에 "어느 Step이 심고 어느 테스트가 무엇을 단언하는지"를 M2본과 같은 상세도로 적는다). DoD 2의 60초 게이트는 `acceptance` job의 성공 로그가 정본이다.
2. `docs/ROADMAP.md`의 "현재 위치" 줄과 M3 절 상태 표기를 "M3 완료"로 갱신하고, 같은 편집에서 M3 범위 줄의 `qsh attach <name>`(`ROADMAP.md:66`, §1이 지적한 5곳 중 하나)을 `qsh <name>`/`qsh attach <name>/<session_id>`로 정정한다(로드맵 자체는 이 계획 문서가 아니라 로드맵 문서 소유자가 갱신 — PLAN.md는 이 절차를 지시만 하고 ROADMAP.md를 대신 수정하지 않는다).
3. Step 1·8·9가 갱신한 정본 문서(`docs/CLI.md`, `docs/design/protocol.md`, `docs/design/architecture.md`, `docs/design/testing.md`, `docs/PRD.md`, `README.md`)와 최종 구현 사이에 어긋남이 남아 있지 않은지 마감 전에 한 번 대조한다 — 어긋나면 **문서를 먼저 고치고** 코드를 맞춘다(각 문서 머리말의 규칙).
4. 이 PLAN.md를 M4("터널") 실행 계획으로 전면 교체한다 — 과거 M3 계획은 git 이력에만 남긴다. §3의 "M4에 넘기는 것" 네 항목을 그 계획의 입력으로 옮긴다.
