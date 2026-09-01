# QSH 테스트 전략

**상태:** 확정 (구현과 어긋나는 내용을 발견하면 이 문서를 먼저 갱신한다)
**작성일:** 2026-08-17
**적용 범위:** P0 전체 (마일스톤별 도입 시점은 각 절에 표기)

핵심 원칙: 정확성 커버리지의 대부분은 **네트워크 없는 순수 로직 계층(L0, L2)** 에 둔다 — 밀리초 단위로 돌기 때문이다. 네트워크·PTY·프로세스가 개입하는 계층은 수는 적어도 결정적(deterministic)이어야 한다. 산문으로 된 아키텍처 제약은 가능한 한 CI 검사로 변환한다 (arch-lint가 선례).

## L0 — 프로토콜 (`qsh-proto`)

시간 대비 버그 검출 비율이 가장 높은 계층. `cargo-fuzz` 이전에 proptest로 시작한다.

- **Roundtrip:** 모든 메시지에 대해 `decode(encode(m)) == m` (proptest + `arbitrary`).
- **Canonical encoding:** 유효한 바이트열 `b`에 대해 `encode(decode(b)) == b`. 인코딩 위에 MAC을 씌우게 될 경우를 대비한 비정규 인코딩 검출.
- **Truncation:** 유효 인코딩의 **모든 prefix**는 `Err(Incomplete)` — panic도 `Ok`도 금지.
- **Allocation-bound:** 4GiB를 주장하는 length prefix는 **할당 전에** 거부됨을 명시적으로 테스트 (우연히 되는 것이 아니라).
- **Bit-flip:** 임의 변조 입력에 panic/OOM 없음.
- **Golden vectors:** checked-in hex frame + 기대 디코딩. 크로스버전 호환성 게이트 — 이 파일을 깨는 변경은 의도적 버전 bump를 요구한다.

## L1 — Crypto/identity

대부분 negative test다. 표 기반 **handshake matrix**: (client cert, server cert, client trust store, server trust store, 모드[pin/CA]) → 기대 결과. 필수 케이스: fingerprint 불일치, 만료 cert, 다른 CA 서명, pin-only 모드에 CA 서명 cert, CA 모드에 self-signed, client cert 부재, 정상 pin, 정상 CA, **reverse dial, 비신뢰 target**(target이 `qsh listen`에 dial하지만 controller trust store에 없는 경우 — 인증 실패는 `host.reverse` 등록 판정 **이전**이므로 audit이 아니라 handshake deny로 기록된다, M3). M1의 수용 기준인 16종 조합이 여기서 나온다.

Keystore는 trait 뒤에: 유닛 테스트는 in-memory 구현, 플랫폼별로 게이트된 통합 테스트 각 1개 — macOS Keychain, Linux Secret Service, **headless Linux file fallback** (실전에서 가장 중요한 경로 — `qsh serve`는 headless 박스에 산다).

## L2 — Session broker (순수 로직, 네트워크 없음)

- **중심 property test:** 임의의 append/read(`--after` cursor) interleaving에서, gap 이벤트가 없는 한 반환된 바이트의 연결은 원본 stream의 해당 suffix와 **byte-identical** — SC4(무손실 resume)의 property 표현. naive Vec 모델을 oracle로 사용.
- Buffer 초과는 올바른 `available_from`을 가진 `session.gap`을 산출 — silent truncation 금지 (PRD §8).
- Writer lease: 획득 / 재attach 시 steal·`SESSION_CONFLICT` 규칙 / connection 사망 시 해제 / TTL 만료.
- **TTL·시간 관련 테스트는 전부 `tokio::time::pause()`.** **테스트 스위트 전체에서 `sleep()` 전면 금지** — 이벤트 통지 + `timeout`으로 대체한다. 네트워크 프로젝트의 flaky 스위트는 팀이 빨간불을 무시하게 훈련시킨다.
- Fuzz를 위해 broker에 **주입 가능한 clock**을 M2 설계 시점부터 넣는다 (L8의 stateful fuzzer 전제).
- **정책 평가기 property(M5, `PLAN.md` Step 2 — DoD 3):** default-deny(임의 정책에서 어떤 rule도 커버하지 않는 action은 반드시 Deny), wildcard(trailing `.*`만 매칭 — 중간 glob이나 항상-deny 3종을 삼키지 않음), principal 정확 일치(`user:dave`는 `user:dave2`에 매칭되지 않음)를 순수 함수 위의 property test로 검증한다. 정책이 `acl.toml` 로더가 만든 순수 평가기(네트워크·I/O 없음)인 동안에만 이 계층에서 값싸게 돈다.
- **Audit 수명주기(M5, `PLAN.md` Step 3 — DoD 5):** 회전 트리거(`max_bytes` 초과 시 실제로 회전)·retention 준수(`retain` 개수만 남음)·쓰기 실패 fail-closed(주입형 실패 sink로 디스크 만실을 시뮬레이션 — 실디스크를 채우지 않는다, CI 규율 참고)를 순수 로직으로 검증한다. tempdir + 주입 가능한 clock/sink로 결정적이며 `sleep()` 없음.

## L3 — Transport (in-process loopback QUIC)

한 프로세스 안에 quinn endpoint 두 개, `127.0.0.1:0`. 실제 QUIC, subprocess 없음, 일반 `cargo test`에서 실행. 여기서 verifier·keep-alive·stream 우선순위의 통합 동작을 검증한다.

M3부터는 같은 계층에 역방향 하네스(`qsh-testkit::reverse::ReverseHarness` — 한 프로세스 안에 controller listener + target dialer, `127.0.0.1:0`)가 더해져 등록·role 축 독립성(정방향/역방향 파라미터화된 loopback)·headless session op를 검증한다.

**M4 터널 loopback 하네스.** 같은 계층에 터널 전용 harness가 더해진다 — 한 프로세스 안에서 실제 TCP listener(`127.0.0.1:0`)를 열고, 실제 QUIC connection 위에서 `RemoteForwardOpen`/`Close`·`TCP_CONNECT`→`ConnectResult`→raw splice 전체 경로(local/remote 양방향)를 subprocess 없이 구동한다. `-L`/`-R` 각각에 대해 실제 바이트 왕복(echo 서버로 round-trip)을 단언하고, `ConnectResult{ok:false}` 경로(dial 실패 → `CONNECTION_FAILED`, inline ACL 거부 → `PERMISSION_DENIED`)도 이 계층에서 커버한다. 실제 listener/splice 구현은 M4 이후 Step에서 채워지므로, M4 Step 1에서는 이 harness가 `qsh-proto`의 `ConnectResult`/`RemoteForwardOpen`/`RemoteForwardOpened`/`RemoteForwardClose` 타입과 `parse_forward_spec`을 대상으로 encode/decode·grammar 테스트만 갖는다.

## L4 — Network fault injection: in-process UDP chaos proxy (`qsh-testkit`)

**설계:** `UdpSocket` 2개를 쥔 tokio task + seed 가능한 `ChaosPolicy`. 클라이언트는 proxy로 dial하고 proxy가 서버로 중계한다.

| Fault | 검증 대상 |
|---|---|
| `drop(p)`, `delay(dist)`, `reorder`, `duplicate` | 손실 복구, ack, dedup |
| `corrupt(p)` | AEAD가 항상 잡아야 함 — positive control |
| `blackhole(dur)` 후 복구 | PTO/keep-alive 튜닝, idle timeout 동작 |
| **`repath()`** — client측 소켓을 새 포트로 rebind | **NAT rebind / Wi-Fi→LTE 전환이 서버에게 보이는 모습 그대로.** 실제 인터페이스를 건드리지 않고 QUIC path validation을 구동 |
| **`sever()`** — client측 소켓 완전 폐쇄 | 재dial + session resume 강제 (또 하나의 복구 경로) |
| **`sever()`** — target→controller leg (`ReverseHarness`의 chaos 변형, M3) | target의 재등록 backoff 루프, controller의 stale 처리·`generation` 단조 증가 (`docs/design/protocol.md` §11-4) |
| **`repath()`/`sever()`(M4, 터널)** — 터널이 열려 있는 QUIC connection에 동일 fault 적용 | **터널은 migration 아래에서 생존해야 한다**(connection이 살아남는 한 splice된 TCP 연결도 살아남음, §12 receive window/BBR 튜닝의 대상 그 자체)와 **`sever()` 아래에서는 깨끗이 teardown돼야 한다**(CLI.md §6.14 holder lifetime — 재수립 없이 local listener/remote 등록이 닫히고, 열려 있던 개별 TCP 연결이 좀비로 남지 않음)를 함께 검증. splice/재연결 구현 자체는 M4 이후 Step 몫이므로 이 행은 그 Step에서 채워진다 |

**대안 대비 선택 근거:** `iptables`/`pfctl`은 root 필요·플랫폼 분기·GHA macOS에서 불안정. 실제 인터페이스 전환은 CI 자동화 불가. transport trait mock은 mock을 테스트하는 것 — migration은 실제 path validation의 속성이다. proxy는 `seeded(u64)`로 재현 가능하며 실패 메시지에 seed를 출력한다.

**핵심 구분: chaos proxy는 PR 회귀 게이트이고, SC3의 실측치는 실기기 캠페인이다.** SC3용 실측: `recovery ∈ {migrated, resumed, failed}` + time-to-recovery 텔레메트리를 **M2부터** 계측하고(노출 표면은 M2에서 **stderr 구조화 진단만** — tracing target `qsh::recovery`, level `INFO`, **한 줄 JSON**(`tracing_subscriber` JSON layer)으로 고정, 필드 `recovery`·`time_to_recovery_ms`·`session_ref`(PTY 내용·토큰 field 없음); stdout 순수성 규칙(CLI.md §2.2) 때문에 `qsh.event/v1` event로의 승격은 P1에서 결정, CLI.md §6.4. 캠페인 스크립트와 chaos 테스트는 기본 verbosity(`--quiet` 없이)로 실행해 stderr의 JSON 줄을 파싱한다), 실기기(macOS `networksetup -setairportpower`, Linux `nmcli`) 스크립트로 N≥60회 전환 시험. 95% vs 90%를 구분하려면 ~60회 이상이 필요하다. **통과 기준은 사전 정의:** idle timeout이 뒤늦게 터져서 복구되는 것은 통과가 아니다 — path 사망 감지 후 **2초 내 재dial + resume**이 목표이며, migrated/resumed 비율을 분해 보고한다.

**M3 역방향 확장.** 같은 텔레메트리에 additive 필드 `registration_wait_ms`(재등록을 기다린 시간, ms)가 더해진다 — `recovery ∈ {migrated, resumed, failed}` 값 집합은 바뀌지 않으며, 역방향에서는 `migrated`가 나올 수 없다(로컬 UDS는 migration 대상이 아니고 재수립은 target이 한다, `docs/design/protocol.md` §11-4). 예산은 재등록 시점부터 분리한다: `time_to_recovery_ms - registration_wait_ms <= 2000`. **60초 DoD는 이중 게이트다** — (i) `crates/qsh-testkit/tests/reverse_resume_chaos.rs`가 PR마다 seeded chaos(수 초)로 상시 검증하고, (ii) `crates/qsh-cli/tests/reverse_blackout.rs`가 `QSH_ACCEPTANCE_SLOW` 하에서만 도는 실제 60초 차단을 기존 `acceptance` job(`ci-ok`가 `needs`로 요구하는 job)에 추가해 상시 게이트로 돌린다 — 60초 자체를 매 PR마다 태우지 않으면서도 DoD 문구를 문자 그대로 검증한다.

## L5 — PTY end-to-end (플랫폼 quirk 명세)

이름 붙은 테스트가 필요한 알려진 함정들:

- **macOS/Linux master-fd EOF 시맨틱 차이** (Linux는 마지막 slave close 후 `EIO`, macOS는 0 반환) — 고전적 "마지막 출력 한 줄 손실" 버그이며 SC4를 직격한다. 테스트: `sh -c 'printf x; exit 0'`의 `x`가 exit 이벤트 **전에** 양 플랫폼에서 도착.
- **순서 불변식:** 모든 출력이 replay buffer에 들어간 뒤에야 `session.exit`가 append된다. 1MB를 쓰고 즉시 exit하는 프로세스로 테스트.
- **UTF-8 chunk 경계:** 멀티바이트 문자가 두 chunk에 걸쳐도 무손상 (sequence가 byte offset이므로 자유 분할이 가능해야 정상).
- macOS의 PTY 커널 버퍼는 Linux보다 작다 — backpressure 동작이 다르므로 양쪽 테스트.
- `setsid` + controlling tty: signal/job control이 동작하고, 세션 close가 shell만이 아닌 **process group 전체**를 종료.
- Zombie/fd 누수: 순차 세션 100회 후 zombie 0, fd 증가 0.
- Login shell 환경: `TERM`, `SHELL`, `argv[0] = "-zsh"`, `$HOME`, macOS `path_helper`. **utmp/wtmp는 MVP에서 기록하지 않는다** (결정 사항 — 문서화만).
- **클라이언트도 pty 아래에서 테스트** (`expectrl`): termios raw mode 경로가 실제로 실행되게.

## L6 — CLI/JSON 계약

CLI.md §11이 명시적으로 초대하는, 레버리지가 가장 큰 계층.

- **Golden fixture** `crates/qsh-cli/tests/fixtures/cli-v1/<op>.json` — `request_id`/timestamp/duration은 정규화. **fixture는 v1에서 append-only**: 과거 fixture 전부가 현재 스키마에 대해 계속 유효해야 한다는 CI job이 CLI.md §10의 호환성 정책을 기계적으로 만든다.
- Rust 타입에서 `schemars`로 JSON Schema 생성 → 모든 fixture와 테스트 산출 envelope를 스키마 검증 → 같은 스키마를 `qsh schema --json`이 서빙 (한 소스).
- **ErrorCode 전수 도달성:** 모든 `ErrorCode` variant가 ≥1개 fixture에 등장해야 한다. 존재하지만 생성 불가능한 코드를 죽인다(예외: `RESUME_GAP`은 event 전용으로 오류 envelope에 도달 불가 — CLI.md §3.3 — 이므로 사유와 함께 DEFERRED에 유지).
- **노출 금지 field:** 생성된 JSON Schema와 모든 fixture·테스트 산출 envelope·JSONL event에 `resume_token`(및 토큰류 key 이름) 문자열이 존재하지 않음을 단언한다 — ADR-0007 결정 2의 기계적 게이트.
- **Exit-code matrix:** (시나리오 → exit code, `ok`, `error.code`) 표를 human/JSON **양 모드에서** 실행, exit code가 모드와 무관하게 동일함을 단언 — §4의 "output mode에 따라 exit code 의미가 달라져서는 안 된다"의 문자 그대로의 테스트.
- **JSONL 순수성:** 시끄러운 세션을 `-vv --jsonl`로 실행, stdout의 모든 줄이 완전한 JSON object로 파싱됨을 단언.
- **`acl check` fixture + 거부 문면 상수-문서 일치 게이트(M5):** `acl.check.allow.json`·`acl.check.deny.json`(신규 fixture, `PLAN.md` M5 Step 1 공통 계약 규율)이 `acl check`가 실제 enforcement와 같은 코드 경로임을 값으로 보여준다. 거부 문면(Step 4의 균일 상수)이 `README.md`/`docs/CLI.md`에 축자 인용되는지는 `tunnel_docs.rs`/`doctor_docs.rs` 선례와 동형인 anti-drift 테스트가 고정한다 — `crates/qsh-core/tests/acl_docs.rs`(M5 Step 1)는 이미 같은 원리로 `Action::ALL` ↔ PRD §9 action 목록의 드리프트를 잡는다.
- **값-보유(value-bearing) golden fixture는 append-only의 예외, diff 리뷰가 필수다(M7):** `capabilities.json`(M7 DoD 3 scope-creep tripwire)과 L7의 `tools_list.json`은 파일의 존재가 아니라 안에 든 값 자체가 계약 단언이므로, 보통의 append-only 규율을 따르지 않는다 — `wire::LOCAL_CAPABILITIES`나 MCP tool 목록이 바뀌면 `QSH_UPDATE_FIXTURES=1`로 재생성하고 그 diff를 계약 변경과 같은 무게로 리뷰해야 한다(`fixtures.rs`의 `golden_local_fixtures` 자체 문서). 반대로 `schema.get`은 golden fixture를 두지 않는다: payload가 스텝마다 command 하나씩 자라는 전체 registry dump라 append-only와 정면충돌하기 때문이며, 대신 `every_fixture_payload_validates_against_its_command_schema`의 스키마 검증과 `qsh-cli/tests/fixtures.rs`의 `schema_command_output_matches_the_single_source_generator`(구조 동등성)가 생성기 정확성을 지킨다는 채택 기록이다.

## L7 — MCP conformance

바이너리를 spawn해 stdio로 JSON-RPC 2.0 대화 — **`rmcp` client가 아니라 raw JSON-RPC**(stdin/stdout 직접, PLAN.md M6판 §4.1 #5 — git 이력): 서버가 SDK가 아니라 계약 자체를 지키는지 보는 것이므로. 하네스는 `crates/qsh-cli/tests/mcp_conformance.rs` 한 파일이다.

- **fixture 고정:** `initialize` → `tools/list` == checked-in fixture(`crates/qsh-cli/tests/fixtures/mcp/tools_list.json`, 정규화 0의 원시 응답 — request id는 하네스가 pin하고 protocol version은 `"2025-11-25"`로 고정, 정렬은 tool 이름 사전순). 각 tool의 output schema가 대응 CLI 타입의 schema와 **동일 객체**임을 단언(손 복사본 금지) — `schema_for!(Data)`를 그대로 rmcp `Tool::with_output_schema::<T>()`에 통과시킨다. tool 삭제·이름 변경·schema 변경은 fixture diff로 가시화된다(scope-creep tripwire — 단 L6 fixture와 달리 append-only가 아니라 diff 리뷰 필수 규율, PLAN.md M6판 §4 리스크 항목 — git 이력).
- **stdout 순수성(DoD 5):** 기본 verbosity와 `-vv` 양쪽에서 stdout의 모든 바이트가 JSON-RPC frame임을 단언. handshake 이전 `tools/call` 도착, PTY 입출력 b64, exec argv 같은 payload가 `-vv`의 **stderr**에도 새지 않음을 별도 검증 — M6 Step 3 검증 라운드가 잡은 rmcp `serve_inner` debug 스팬 노출 결함(수정: 필터 스펙 `rmcp=warn` 고정)의 회귀 게이트다.
- **오류 표면:** `OpError`가 `isError:true` + content의 §3.2 error object(JSON)로 나가고 `structuredContent`는 생략됨을 단언 — 성공 결과의 outputSchema 적합 의무와 오류 결과를 섞지 않기 위함(PLAN.md M6판 Step 3 검증 라운드 판정 ⑤ — git 이력). deny 정책 하에서 `open_session` → `PERMISSION_DENIED`가 M5 균일 문면 그대로 MCP 표면에 보존됨도 이 절에서 확인한다.
- **취소 의미론(DoD 3, §8.4·§9):** `read_session` long-poll 대기 중 `notifications/cancelled` → `get_session`으로 세션이 `running` 유지·쓰기 가능함을 확인. 어댑터에는 취소 관련 코드가 없다 — rmcp 자체의 `local_ct_pool`(취소된 요청 id의 응답을 조용히 버리고 핸들러 태스크는 abort하지 않음)이 취소 무결성을 구조적으로 보장하며, 이 절이 그 부재-증명이다. `next_after`/`next_ctl_after` 되먹임 루프로 output/제어 이벤트 전순서 보존(양 커서 모두)도 같은 절에서 검증한다.
- **터널 truthful-close E2E:** `open_tunnel`로 실제 바이트를 왕복시킨 뒤 `close_tunnel`이 `closed:true`를 반환하고 리스너가 실제로 해제됨(같은 포트로 재open 성공)을 단언 — Step 3 검증 라운드가 잡은 "close 응답은 항상 `closed:false`인데 리스너·포워딩은 살아 있는" 결함의 회귀 게이트.
- **Windows-ungated 성공 경로:** `list_hosts`/`list_sessions`는 PTY도 dial도 필요 없어 `#[cfg(unix)]` 게이트 없이 성공해야 정상이다 — 이 절이 그 두 tool의 성공 경로를 플랫폼 분기 없이 구동한다.
- **fixture 세트 등가성:** `crates/qsh-cli/tests/fixtures/mcp/` 아래 실존 파일 집합과 테스트가 등록한 fixture 이름 집합이 양방향 일치함을 단언 — L6 `REQUIRED_FIXTURES` 규율과 동형.

§8.2의 "command string 생성·CLI output 재파싱 금지"(DoD 4)는 `xtask arch`의 `ModuleBan`(scope `crates/qsh-cli/src/mcp/`, 금지 토큰 `std::process`/`Command::new`/`Stdio::piped`)으로 정적 강제한다 — 컴파일 이전 소스 스캔이며 unit test로 xtask 자신의 스위트에 산다. 이 conformance 하네스는 이 ban의 스코프 밖이라 예외가 아니라 애초에 적용 대상이 아니다: 하네스가 사는 `crates/qsh-cli/tests/`는 `crates/qsh-cli/src/mcp/`가 아니고, 하네스가 쓰는 `std::process::Command`는 실 `qsh mcp` 바이너리를 spawn해 wire를 관찰하는 것이지 어댑터가 자기 자신을 shell out하는 것이 아니다.

## L8 — Fuzzing (`cargo-fuzz`, 본격 가동은 M8)

| 타깃 | 내용 | 비고 |
|---|---|---|
| `frame_decode` | raw bytes → frame splitter | 최우선 |
| `control_message` | frame → 시맨틱 파싱 | |
| `roundtrip` | structure-aware `Arbitrary` → encode → decode → eq | 시간당 버그 최저가 |
| 문자열 파서류 | `session_ref`, `parse_forward_spec`(`-L`/`-R` grammar, `qsh-proto::wire`, M4) 파싱 | sans-IO 순수 함수라 이 계층에 바로 얹힌다 — port 범위(`1..=65535`)·IPv6 대괄호·`bind` 유무 조합을 구조 인지(arbitrary) 변형으로 커버 |
| `json_envelope` | MCP tool 인자 (agent가 주는 입력) | |
| `broker_ops` | **stateful**: byte열 → op 시퀀스(append/read/attach/detach/tick) vs 모델 oracle | **M2에서 주입 가능한 clock을 설계해야 가능** |

ACL glob 평가기는 fuzz보다 property test가 적합하다(위 L2 "정책 평가기 property" 행이 M5 Step 2의 실현 지점) — action 어휘가 PRD §9의 닫힌 11종(`Action::ALL`)이고 wildcard가 trailing `.*`만 허용되도록 M5 Step 1이 못박았으므로(`docs/design/architecture.md` §6), `session.control.escalate` 같은 가상의 깊은 이름 문제는 애초에 발생하지 않는다 — 로더가 `Action::ALL`의 어느 것에도 매칭되지 않는 패턴을 로드 시점 `CONFIG_ERROR`로 거부한다. property로 직접 표현할 질문은: `session.*`가 `session.control`에 매칭되는가? `forward.*`를 가진 정책에서도 `forward.socks`는 여전히 deny인가(항상-deny 게이트가 wildcard 매칭보다 먼저 적용)? `user:dave`가 `user:dave2`에 매칭되지 않는가?

**Corpus는 checked-in하고 일반 유닛 테스트로 전 플랫폼에서 상시 replay** — fuzzing이 돌지 않는 동안에도 발견된 crash가 고정된 상태로 유지된다. 공개 beta 전 타깃당 누적 72시간 + OSS-Fuzz 제출 (무료이며 SC7 리뷰의 신뢰 신호).

## L9/L10 — Soak·Perf

- Soak: 24h 수다스러운 세션(메모리 유계), 100 동시 세션(listener RSS ≤ 30MB idle 목표), 10k connect/disconnect 사이클(fd·세션 누수 0), Linux ASAN/LSAN으로 통합 스위트 1회.
- **Perf는 절대값이 아니라 비율로 게이트:** raw-quinn 기준 throughput을 **같은 프로세스, 같은 실행에서** 측정한 뒤 터널 ≥ 80%를 단언 — runner 무관하므로 실제로 CI 가능. PTY p95 산식: (client 수신 시각 − pty write 시각 − 측정된 loopback RTT) < 10ms. **비율 throughput과 echo-under-load p95는 M4 수용 기준으로 acceptance job에서 상시 게이트; 절대 throughput 추세는 여전히 nightly** (공유 runner의 flake가 무시 습관을 만든다).

**M4 perf-gate 긴장의 해소(PLAN.md §4.1 #7, M4 Step 7에서 반영 완료).** 구 "PR 게이트 금지"라는 일반 원칙과 `docs/design/protocol.md` §12가 M4 수용 기준으로 요구하는 "포화 터널 + PTY echo p95 < 10ms" CI 조기 도입은 문면상 충돌했다. M4에서 결정된 해소 방향은 두 지표를 분리하는 것이다: **비율 throughput**(raw-quinn 대비 터널 ≥ 80%)은 같은 프로세스·같은 실행의 결정적 측정이므로 runner flake에 노출되지 않는다 — 이 지표는 **acceptance job**(`crates/qsh-testkit/tests/tunnel_throughput.rs`, `ci-ok`가 `needs`로 요구하는 그 job)에서 **strict 게이트**로 돈다. **echo-under-load p95**(포화 터널 아래에서의 PTY echo 지연, `crates/qsh-testkit/tests/tunnel_echo_under_load.rs`)는 공유 runner의 wall-clock 변동에 노출되므로 nightly 추세 기록에 남되, **acceptance job에도 게이트**를 하나 추가했다 — 이 둘 다 **PR 단위 테스트 스위트(일반 `cargo test`/`cargo nextest run`)에는 넣지 않는다.** 이는 L4의 "60초 DoD 이중 게이트"(`reverse_blackout.rs` — `QSH_ACCEPTANCE_SLOW` 하 acceptance job)와 같은 패턴이다: PR마다 태우지 않으면서도 DoD 문구를 실측으로 검증한다.

## CI 규율

- 모든 테스트는 port 0 바인딩, 테스트별 고유 tempdir.
- `sleep()` 금지 — `tokio::time::pause()` 또는 이벤트 통지 + `timeout`.
- Chaos는 seeded, 실패 시 seed를 단언 메시지에 출력.
- `Swatinem/rust-cache`, concurrency group으로 구식 run 취소.
- GHA macOS runner는 UDP 소켓 버퍼 기본값이 작다 — `SO_RCVBUF`를 명시 설정하거나 throughput 수치 저하를 예상할 것.
- clippy는 **모든 타깃에서** 실행 — Linux 전용 clippy는 `cfg(target_os = "macos")` 블록 전체를 놓친다. 이 프로젝트처럼 플랫폼 분기가 많으면 실질적 구멍이다. Windows도 포함: 지원 플랫폼은 아니지만 `cfg(unix)`/`cfg(not(unix))` 분기가 계속 컴파일되는지는 CI만이 보증한다.
- `cargo-nextest` **필수**, `cargo test`는 게이트가 아니다: 테스트별 프로세스 격리(전역 상태를 바꾸는 PTY/termios 테스트에 필수), 실 timeout, flake 재시도, JUnit 출력이 이유의 절반이고, 나머지 절반은 이 repo의 실측이다 — `cargo test`는 전역 상태를 공유하는 동일 바이너리 실행 때문에 M7 기준 baseline부터 이미 빨간불(`acl::load`·`localctl::daemon` 계열이 프로세스 안에서 서로 간섭)이고, CI(`.github/workflows/ci.yml`)도 nextest만 돈다. 커밋 전 게이트는 `TMPDIR=<격리 디렉터리> cargo nextest run --workspace`이며, `cargo test`로 빨간불이 뜨는 것은 회귀 신호가 아니다 — nextest로 같은 스위트를 돌려 실제로 깨졌는지 확인한다.

**현재 상태 (M1 이후):** `.github/workflows/ci.yml`이 push(main)/PR마다 fmt / clippy / test(nextest + doc-test) / arch-lint / cargo-deny를 5개 runner(ubuntu-24.04, ubuntu-24.04-arm, macos-14, macos-15-intel, windows-latest)에서 돌리고, 단일 required check `ci-ok`로 합친다. Windows에서는 POSIX 시그널·process-group·`$$` 의존 테스트가 `cfg(unix)`로 빠지고 나머지(`sh -c` 기반 DoD 테스트 포함 — runner의 Git for Windows `sh`에 의존)는 그대로 돈다. fuzz-smoke·nightly-fuzz·soak·perf job은 M8에서 추가한다. `crates/qsh-testkit`은 M2에서 chaos proxy(`chaos.rs`, L4)·loopback 하네스(`loopback.rs`, L3)를 구현했고 M2 attach recovery 스위트(`crates/qsh-cli/tests/attach_recovery.rs`)가 그 위에 서 있다 — 더 이상 빈 골격이 아니다. M3는 여기에 역방향 하네스(`reverse.rs` — controller listener + target dialer, `ReverseHarness`)를 더했고, 그 위에 역방향 resume 게이트 두 개(`reverse_resume_chaos.rs` PR 상시 + `reverse_blackout.rs` 60초 수용, L4)와 controller 도달성 진단 항목 및 문서-상수 일치 게이트(`crates/qsh-core/src/doctor.rs` + `crates/qsh-core/tests/doctor_docs.rs`, L6)가 서 있다. M5는 L2에 정책 평가기 property test(`crates/qsh-core/src/acl/policy.rs`, default-deny·wildcard·principal 정확 일치, DoD 3)와 audit 수명주기 테스트(회전·retention·쓰기 실패 fail-closed, `crates/qsh-core/src/audit/writer.rs`, DoD 5)를 심었다. L6에는 문서-상수 일치 게이트가 두 벌 섰다. `crates/qsh-core/tests/acl_docs.rs`는 `Action::ALL`·`PERMISSION_DENIED_MESSAGE`·시작 진단 문면이 PRD·CLI.md·README와 어긋나지 않는지 보고, Step 8이 마감한 `crates/qsh-core/tests/acl_registry.rs`는 `OP_REGISTRY`와 CLI.md §2.5 매핑 표를 양방향으로 대조하면서 `Server::dispatch`의 `control_message::Body` variant를 전수 분류하고 registry 10개 항목의 DoD 2 audit 완전성을 구동한다. 항상-deny 3종(`forward.socks`·`file.read`·`file.write`)은 구동 가능한 wire op이 아직 없어 이 열거에서 빠지며, 나머지 14개 인가 seam의 거부 문면 균일성은 `crates/qsh-testkit/tests/acl_uniformity.rs`가 맡는다. `OP_REGISTRY`가 `Server::dispatch`만으로는 구동할 수 없는 `forward.local`·`forward.remote`·`host.reverse` 세 seam의 DoD 2 구동은 `crates/qsh-testkit/tests/acl_registry_audit.rs`가 이어받는다. M6는 L7을 처음 채웠다: `qsh mcp`(`crates/qsh-cli/src/mcp/mod.rs`, rmcp `=3.1.4` stdio 서버)에 대해 `crates/qsh-cli/tests/mcp_conformance.rs`가 fixture 고정·stdout 순수성(DoD 5)·오류 표면·취소 의미론(DoD 3)·터널 truthful-close·Windows-ungated 성공 경로·fixture 세트 등가성을 실 바이너리 spawn으로 구동하고, `xtask`의 `ModuleBan`이 `crates/qsh-cli/src/mcp/` 스코프에서 `std::process`/`Command::new`/`Stdio::piped` 세 토큰을 금지해 DoD 4(subprocess·CLI 재파싱 ban)를 기계로 강제한다. DoD 2(Claude Code 실접속)는 이 계층의 자동 게이트가 아니라 `docs/campaigns/m6-mcp.md`의 수동 캠페인 기록이다 — M2 mobility 캠페인과 같은 지위.

**M7.** L1에 CA 인증 경로가 더해졌다: `qsh cert init`/`qsh cert issue`(§6.16, `crates/qsh-core/src/ca.rs`)가 만드는 self-signed root + device leaf 승격을 `crates/qsh-core/tests/cert_e2e.rs`가 실 handshake로 검증하고, CA-vs-pin `auth_path` 분기가 ACL 판정과 audit 기록(`auth_path:"ca"`) 양쪽에서 load-bearing임을 mutation으로 확인했다(pin 전용 규칙에 CA principal이 매칭하도록 뒤집으면 FAIL). L2는 Step 7-2의 공유 런타임 정리 과정에서 `OP_REGISTRY`의 키를 `&'static str`에서 `Op` enum으로 바꿨다 — `declare_ops!` 매크로 하나가 `Op`·`Op::as_str`·`Op::spec`·`OP_REGISTRY`를 전부 같은 선언에서 뽑아내고(`crates/qsh-core/src/acl/registry.rs`), `action_of("sesion.open")`처럼 오타가 컴파일된 뒤 런타임에 패닉하던 구멍은 `Op` 타입 자체가 닫는다 — 없는 variant는 이름을 쓰는 순간 컴파일이 안 되고, `Op::spec()`의 match에는 wildcard arm이 없어 등록 없는 variant도 컴파일되지 않는다. `tests/acl_registry.rs`의 소스텍스트 매칭 게이트 두 벌(`authorize_stream_has_exactly_two_production_call_sites`·`action_variant_literals_are_pinned_to_the_one_documented_exception`)은 대체되지 않고 새 호출 형태에 맞춰 갱신된 채 남았다. 리팩터가 그런 게이트를 무증상으로 무력화하는 일이 흔해서 검증 라운드가 따로 확인했고, 둘 다 검출력을 유지했다. L6은 두 갈래로 자랐다. Step 1이 `qsh schema --json`·`qsh capabilities`를 CLI 표면으로 확정하면서 `CLI_V1_SCHEMA_COMMANDS` 완전성 게이트를 단방향 const→arm 대조에서 `Operation` impl 전수 양방향 set-equality로 다시 짰다 — mutation으로 등록 누락을 흉내 냈을 때 옛 게이트가 못 잡는다는 게 이 재작업의 계기였다. Step 6은 `qsh doctor`(§6.17, `ops/doctor.rs` + `doctor/probe.rs`)의 findings 코드 13종을 `EXPECTED_DOCTOR_CODES` 동결 set-equality로 고정하고(golden fixture는 byte-freeze하지 않는다 — `schema.get`과 같은 이유로 환경 의존), 시각 임계값 세 곳의 경계 테스트와 `classify_io_error`의 errno 분류를 유닛 테스트로 확정했다 — CLI.md에 축자 인용된 진단 문면은 `doctor_docs.rs` 계열 게이트가 지키고, README는 서사 산문이라 축자 인용 대상에서 의도적으로 뺐다(PLAN.md Step 6 결정). Step 4의 `trust.invite`/`trust.accept`(ADR-0002)는 channel binding(TLS exporter 변조 시 교환 실패)·상수시간 비교(`ct_eq`)·단일사용·secret 비영속을 mutation으로 검증했고, Step 3의 `hosts.toml`은 주소 우선순위(hosts.toml이 trust.toml을 덮되 신뢰는 trust.toml 단독 판정)를 실 QUIC 연결 테스트로 고정했다. M7 구간 전체의 최종 nextest baseline은 **1334 passed / 2 skipped**다(Step 1의 1172에서 단계마다 누적, Step 8의 man page 재생성 대조 1건 포함) — `cargo test`는 이미 이 baseline부터 빨간불이라(위 CI 규율 항목) 게이트로 쓰지 않는다.
