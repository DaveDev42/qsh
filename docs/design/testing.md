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
- Fuzz를 위해 broker에 **주입 가능한 clock**을 M2 설계 시점부터 넣는다 (L8의 stateful fuzzer 전제). M8 Step 7b가 그 전제를 실제로 쓴다 — `broker_ops` 하네스와 reaper가 같은 `TestClock`/`Clock` trait 위에서 돌고, `TickSmall`/`TickLarge`/`Reap` op이 `TtlWindow::deadline`/`reap_reason`을 실시간 대기 없이 흔든다.
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
- **값-보유(value-bearing) golden fixture는 append-only의 예외, diff 리뷰가 필수다(M7):** `capabilities.json`(M7 DoD 3 scope-creep tripwire)은 파일의 존재가 아니라 안에 든 값 자체가 계약 단언이므로, 보통의 append-only 규율을 따르지 않는다 — `wire::LOCAL_CAPABILITIES`가 바뀌면 `QSH_UPDATE_FIXTURES=1`로 재생성하고 그 diff를 계약 변경과 같은 무게로 리뷰해야 한다(`fixtures.rs`의 `golden_local_fixtures` 자체 문서). 이전에는 옛 L7의 `tools_list.json`도 같은 예외에 속했다 — 그 fixture는 `crates/qsh-cli/tests/fixtures/mcp/`에 append-only로 남아 있지만(같은 디렉터리의 `README.md` 참고), 이를 검증하던 conformance 하네스 자체가 M8 Step 6에서 철회됐다(ADR-0011). 반대로 `schema.get`은 golden fixture를 두지 않는다: payload가 스텝마다 command 하나씩 자라는 전체 registry dump라 append-only와 정면충돌하기 때문이며, 대신 `every_fixture_payload_validates_against_its_command_schema`의 스키마 검증과 `qsh-cli/tests/fixtures.rs`의 `schema_command_output_matches_the_single_source_generator`(구조 동등성)가 생성기 정확성을 지킨다는 채택 기록이다.

## L7 — MCP conformance (철회, ADR-0011)

M6가 채웠던 이 계층(내장 `qsh mcp` stdio adapter를 raw JSON-RPC로 구동하는 conformance 하네스, `crates/qsh-cli/tests/mcp_conformance.rs`)은 M8 Step 6에서 adapter 자체와 함께 철회했다. 그 하네스가 지키던 계약(fixture 고정·stdout 순수성·오류 표면·취소 의미론·터널 truthful-close·fixture 세트 등가성)은 이제 CLI 표면에서 직접 구동한다 — long-poll cursor 정순서와 취소 무결성은 §6.4의 `session read --wait`/`--follow` 경로가, 터널 truthful-close는 §6.9의 `tunnel open`/`tunnel close` 경로가 각각 같은 값을 검증한다. 근거는 ADR-0011.

## L8 — Fuzzing (`cargo-fuzz`, 본격 가동은 M8)

M8 Step 1(커밋 `d87e76b`, 2026-09-02)에 cargo-fuzz 파서 타깃 **16종**이 `fuzz/fuzz_targets/`에 착륙했고, M8 Step 7b가 stateful 타깃 `broker_ops`를 더해 **17종**이 됐다. 아래 표는 `fuzz/Cargo.toml`의 `[[bin]]` 이름 그대로다 — 이 절이 원래 계획했던 이름(`frame_decode`/`control_message`/`roundtrip`/`json_envelope`/`broker_ops`)은 착륙 시점에 다시 갈라졌다(`docs/design/protocol.md` §13).

| 타깃 | 내용 | 상태 |
|---|---|---|
| `frame_decoder` | 길이 프리픽스 framing에 적대적 부분 청크를 흘리고 `push`/`next_frame`/`take_remaining`을 임의 순서로 인터리브 | 착륙 (구 `frame_decode`) |
| `decode_control` | `decode_msg::<ControlMessage>` — 루트 oneof | 착륙 (구 `control_message`) |
| `decode_hello` | `decode_msg::<Hello>` — handshake 최초 파싱 | 착륙 |
| `decode_stream_header` | `decode_msg::<StreamHeader>` + `StreamKind::try_from`(unknown i32 포함) | 착륙 |
| `decode_session_frame` | `decode_msg::<SessionFrame>` + `validate()` 체인 | 착륙 |
| `decode_exec_frame` | `decode_msg::<ExecFrame>` — EXEC_DATA 경로 | 착륙 |
| `decode_connect_result` | `decode_msg::<ConnectResult>` — ticket/ACL 게이트가 없는 유일한 decode 경로 | 착륙 |
| `decode_local_hello` | `decode_local::<LocalHello>` — localctl 첫 메시지 (`qsh.local.v1`) | 착륙 |
| `decode_local_admin_request` | `decode_local::<LocalAdminRequest>` — localctl 두 번째 프레임 | 착륙 |
| `valid_host_name` | `Hello.reverse.offered_name` 모양 검사 | 착륙 |
| `valid_forward_id` | `forward_id`/`ticket` 모양 검사 | 착륙 |
| `parse_invite_code` | Crockford Base32 invite code 디코드 | 착륙 |
| `parse_forward_spec` | `-L`/`-R` grammar (`[bind:]listen_port:host:host_port`) | 착륙 (구 "문자열 파서류") |
| `sanitize_peer_text` | 화면에 뿌릴 peer 문자열의 제어문자 제거 | 착륙 |
| `fingerprint_principal` | `Fingerprint`/`Principal`의 `from_str` | 착륙 |
| `json_request_types` | `serde_json::from_slice` → `qsh_proto::types::*Req` | 착륙 (구 `json_envelope`) |
| `broker_ops` | **stateful**: byte열 → 19종 op 어휘(NewSession/Append/AppendControl/ReadAt/ReadBeyond/ReadFollow/TakeLease/DropConnection/Attach/Detach/SetExited/SetClosing/IssueResume/VerifyResume/RotateResume/ForgetResume/TickSmall/TickLarge/Reap) 시퀀스를 `ModelSession` oracle(naive Vec + 독립 재구현한 `predict_reap_reason`/`predict_verify`)과 대조 — sequence·control id·gap·byte-identity·메모리 예산·writer lease·resume 토큰·TTL/reap 전부. default deny 축은 `acl/policy.rs`의 proptest(§13-5)가 담당하고, `broker_ops`는 그 대신 상태 부재·불일치 → `Err(ResumeDenied)`·`Conflict`·`CursorBeyondEnd`의 fail-closed 성질을 잰다. **착륙 (M8 Step 7b)** — 하네스는 `crates/qsh-core/tests/support/broker_ops_harness.rs`, fuzz 타깃은 `fuzz/fuzz_targets/broker_ops.rs`(같은 파일을 `#[path]`로 include), 회귀 재생은 `crates/qsh-core/tests/broker_ops_corpus.rs`(`fuzz/corpus/broker_ops/` seed 15개를 일반 nextest로 상시 재생, 디렉터리 0개면 FAIL) |

구 `roundtrip` 행(structure-aware `Arbitrary` → encode → decode → eq)도 별도 타깃으로는 착륙하지 않았다. 그 자리를 대신 메운 것이 proptest 다섯 종이고(§L2 및 `protocol.md` §13-5), 두 방식이 재는 것이 달라 등가 교체는 아니다 — 위 표의 decode 타깃들은 임의 바이트를, proptest는 타입 수준 모델을 흔든다.

캠페인 기록(배치별 run-id·누적 fuzz-hours·DoD 1 판정)은 [`docs/campaigns/m8-fuzz.md`](../campaigns/m8-fuzz.md)가 canonical이다.

ACL glob 평가기는 fuzz보다 property test가 적합하다(위 L2 "정책 평가기 property" 행이 M5 Step 2의 실현 지점) — action 어휘가 PRD §9의 닫힌 11종(`Action::ALL`)이고 wildcard가 trailing `.*`만 허용되도록 M5 Step 1이 못박았으므로(`docs/design/architecture.md` §6), `session.control.escalate` 같은 가상의 깊은 이름 문제는 애초에 발생하지 않는다 — 로더가 `Action::ALL`의 어느 것에도 매칭되지 않는 패턴을 로드 시점 `CONFIG_ERROR`로 거부한다. property로 직접 표현할 질문은: `session.*`가 `session.control`에 매칭되는가? `forward.*`를 가진 정책에서도 `forward.socks`는 여전히 deny인가(항상-deny 게이트가 wildcard 매칭보다 먼저 적용)? `user:dave`가 `user:dave2`에 매칭되지 않는가?

**Corpus는 checked-in하고, 그중 `broker_ops`는 일반 유닛 테스트로 전 플랫폼에서 상시 replay된다**(`crates/qsh-core/tests/broker_ops_corpus.rs`) — 파서 16종의 상시 replay는 아직 선언이고 현재는 `fuzz-smoke.yml`의 짧은 결정적 스모크가 그 자리다. fuzzing이 돌지 않는 동안에도 발견된 crash는 seed로 고정된다. 공개 beta 전 타깃당 누적 72시간 + OSS-Fuzz 제출 (무료이며 SC7 리뷰의 신뢰 신호).

## L9/L10 — Soak·Perf

- Soak: 24h 수다스러운 세션(메모리 유계), 100 동시 세션(listener RSS ≤ 30MB idle 목표), 10k connect/disconnect 사이클(fd·세션 누수 0), Linux ASAN/LSAN으로 통합 스위트 1회. **구현(M8 Step 5).** 하나의 시나리오 `crates/qsh-cli/tests/soak.rs`가 두 속도로 돈다 — 짧은 모드(기본 120s/8세션, `QSH_SOAK_*` env로 조절)는 `[profile.load]`로 `load.yml`이 push(main)마다 도는 회귀 감시자이고, 24h/100세션 모드는 `[profile.soak]`(`.config/nextest.toml` — `test-threads=1`, `slow-timeout={period="3600s"}`, `terminate-after` 없음, 실측 확인상 kill하지 않고 SLOW 경고만 반복한다)로 GHA 6h 상한 밖에서 `scripts/soak/run.sh`가 기동하고 사람이 `docs/campaigns/m8-soak.md`에 기록한다 — M2 mobility·adversarial-load 캠페인과 같은 지위, PR을 막지 않는다. 판정식(idle RSS ≤ 30MiB, 세션당 buffer ≤ 8MiB, RSS 추세 < 1MiB/h, listener/self fd 성장 ≤ +2, echo p95 spike 비율 ≤ 10%(`ECHO_SPIKE_FRACTION_MAX`, steady 창 중 bound `max(3 × ramp 직후 baseline p95, 50ms)`를 넘는 창의 비율, ARBITRATION-5), TTL reap)은 짧은 모드에서 판단 가능한 축은 테스트가 직접 assert하고, 표본이 많이 필요한 두 축(세션당 buffer의 24h 형태·RSS 추세 회귀선)은 `scripts/soak/summarize.py`(stdlib만, CSV를 읽어 위반 시 exit 1)가 24h CSV로 마저 판단한다 — 두 판정이 같은 임계를 공유하는 것은 CSV 헤더 상수(`SOAK_CSV_HEADER`)가 양쪽에 핀으로 박혀 있어서다. self fd 축은 listener fd의 두 번째 검사와 같은 형태로 판단한다 — steady 구간의 fd 표본을 4등분해 마지막 1/4의 최댓값이 첫 1/4의 최댓값+2를 넘는지만 본다(사이클링 "도중"의 증가), boot baseline과 drain idle_end를 직접 비교하지는 않는다: 그 전체 생애주기 비교는 ramp의 세션 open/attach 자체가 남기는 일회성 fd 비용(런타임 warm-up)까지 같이 잡혀 버려 (iii)이 실제로 재는 대상과 다르기 때문이다 — 그 boot→idle_end 델타는 soak.rs와 summarize.py 양쪽에 정보성 줄로만 남고 위반으로 세지 않는다. 위반은 `FD_GROWTH_CLIENT`로 태그되는데, 이는 M7 carryover (iii)(pull마다 새 UDS conduit을 여는 `Ops::connect_target` 경로, PROGRESS-5.md S0 Q10-2)가 실측으로 재현됐다는 뜻이며 이 축만은 strict 실패로 다룬다. ramp의 세션 open과 사이클 교체 open은 재시도 가능한(`retryable: true`) `ConnectionFailed`/`Timeout` `OpError`를 1초 간격으로 최대 3회까지 재시도한다(fuzz로 포화된 호스트가 qsh-core 자체의 10초 dial 타임아웃을 이따금 못 맞추는 것을 흡수하기 위해서다 — 그 10초 타임아웃 자체는 건드리지 않는다) — 재시도 횟수는 verdict에 정보성으로만 찍히고, 3회를 모두 쓰고서야 실패로 집계된다. 10k connect/disconnect 사이클은 24h 런의 부수적 결과로 기록만 하고(24h × 10세션/60s ≈ 14,400회로 자연히 넘는다), Linux ASAN/LSAN 통합 스위트 1회는 이 Step의 범위 밖으로 남아 별도 1회 항목이다.
- **Perf는 절대값이 아니라 비율로 게이트:** raw-quinn 기준 throughput을 **같은 프로세스, 같은 실행에서** 측정한 뒤 터널 ≥ 80%를 단언 — runner 무관하므로 실제로 CI 가능. PTY p95 산식: (client 수신 시각 − pty write 시각 − 측정된 loopback RTT) < 10ms. **비율 throughput과 echo-under-load p95는 M4 수용 기준으로 acceptance job에서 상시 게이트; 절대 throughput 추세는 여전히 nightly** (공유 runner의 flake가 무시 습관을 만든다).

**M4 perf-gate 긴장의 해소(PLAN.md §4.1 #7, M4 Step 7에서 반영 완료).** 구 "PR 게이트 금지"라는 일반 원칙과 `docs/design/protocol.md` §12가 M4 수용 기준으로 요구하는 "포화 터널 + PTY echo p95 < 10ms" CI 조기 도입은 문면상 충돌했다. M4에서 결정된 해소 방향은 두 지표를 분리하는 것이다: **비율 throughput**(raw-quinn 대비 터널 ≥ 80%)은 같은 프로세스·같은 실행의 결정적 측정이므로 runner flake에 노출되지 않는다 — 이 지표는 **acceptance job**(`crates/qsh-testkit/tests/tunnel_throughput.rs`, `ci-ok`가 `needs`로 요구하는 그 job)에서 **strict 게이트**로 돈다. **echo-under-load p95**(포화 터널 아래에서의 PTY echo 지연, `crates/qsh-testkit/tests/tunnel_echo_under_load.rs`)는 공유 runner의 wall-clock 변동에 노출되므로 nightly 추세 기록에 남되, **acceptance job에도 게이트**를 하나 추가했다 — 이 둘 다 **PR 단위 테스트 스위트(일반 `cargo test`/`cargo nextest run`)에는 넣지 않는다.** 이는 L4의 "60초 DoD 이중 게이트"(`reverse_blackout.rs` — `QSH_ACCEPTANCE_SLOW` 하 acceptance job)와 같은 패턴이다: PR마다 태우지 않으면서도 DoD 문구를 실측으로 검증한다.

**M8 DoD 5 T2(적대적 부하, `crates/qsh-cli/tests/adversarial_load.rs`).** 위 M4 perf-gate와 다른 자리를 쓴다 — acceptance job이 아니라 별도 워크플로 `.github/workflows/load.yml`이다. 근거는 같은 절 위쪽의 "절대 throughput 추세는 여전히 nightly" 규율 그대로다: DoD 5가 재는 RSS(MB)·fd 개수·echo p95(ms)는 비율이 아니라 절대 수치이고, acceptance job은 `ci-ok`의 `needs`에 있어 PR 필수 경로다. `load.yml`은 push(main)·`workflow_dispatch`뿐이고 PR을 막지 않는 회귀 감시자다. idle listener RSS 30 MB는 `docs/PRD.md:305`가 "목표"로, `docs/ROADMAP.md:112`가 soak(DoD 2)의 bound로 적은 수치를 DoD 5가 그대로 재사용한 것이며, 재는 대상은 **release 빌드**의 `qsh serve`다(`BRIEF-4c.md` §3.2/J2 — debug 바이너리는 이 30 MB가 애초에 겨냥한 수치가 아니라 `load_bin()`이 `QSH_LOAD_BIN` 미설정을 조용히 넘기지 않고 패닉한다). T2 이전에는 한 번도 실측된 적이 없었다 — 실패 시 코드가 아니라 이 임계 자체를 의심할 여지가 있다는 뜻이고, 진단은 baseline·peak·idle 세 값을 항상 함께 남긴다. 부하 중 상한(`30 MB + 8 MB × 살아 있는 세션 수`)의 8 MB는 `PRD.md:306`의 세션당 replay buffer 설정값에서 빌린 것이지 실측된 RSS 증분이 아니다. echo 임계도 M4와 다르다 — M4는 절대 10ms 고정이고, T2는 **같은 실행 baseline p95의 3배 또는 50ms 중 큰 값**이다(부하 시나리오가 M4처럼 "포화 터널"을 만드는 협조적 부하가 아니라 적대적 flood라 baseline 자체가 실행마다 달라질 수 있기 때문). T1(`crates/qsh-testkit/tests/quota.rs`의 flood-survival 테스트들)의 echo는 `PipeFactory` 기반이라 "pipe echo"이고, T2가 처음으로 서브프로세스 `qsh serve`의 실제 PTY를 재는 "PTY echo"다 — DoD 5 문면의 PTY echo는 T2의 몫이다. RSS/fd 측정은 `/proc` 기반이라 Linux 전용이고, `/proc`이 없는 플랫폼(macOS)에서는 `QSH_LOAD_STRICT`가 아닌 한 그 시나리오 자체가 skip이다.

## CI 규율

- 모든 테스트는 port 0 바인딩, 테스트별 고유 tempdir.
- `sleep()` 금지 — `tokio::time::pause()` 또는 이벤트 통지 + `timeout`. T2의 RSS/fd 안정화(`crates/qsh-cli/tests/common/mod.rs`)는 폴링을 `tokio::time::sleep`으로 한다 — 고정 대기가 아니라 200ms 간격 *조건* 폴링(연속 3회 상대 변동 1% 미만을 안정으로 본다)이라는 점에서 이 규율이 금지하는 고정 대기와는 다르지만, 벽시계를 쓴다는 사실 자체는 남는다(4c 적대 검토 A13).
- Chaos는 seeded, 실패 시 seed를 단언 메시지에 출력.
- `Swatinem/rust-cache`, concurrency group으로 구식 run 취소.
- GHA macOS runner는 UDP 소켓 버퍼 기본값이 작다 — `SO_RCVBUF`를 명시 설정하거나 throughput 수치 저하를 예상할 것.
- clippy는 **모든 타깃에서** 실행 — Linux 전용 clippy는 `cfg(target_os = "macos")` 블록 전체를 놓친다. 이 프로젝트처럼 플랫폼 분기가 많으면 실질적 구멍이다. Windows도 포함: 지원 플랫폼은 아니지만 `cfg(unix)`/`cfg(not(unix))` 분기가 계속 컴파일되는지는 CI만이 보증한다.
- 어느 테스트가 어느 위협을 갚고 있는지의 인덱스는 [threat-model.md](threat-model.md) §4가 canonical이다. 이 문서는 계층별로 무엇을 갚아야 하는지를 적고, 그쪽은 위협별로 무엇이 그것을 갚고 있는지를 적는다. 통제를 지키는 테스트의 이름이 바뀌면 그 표도 같은 커밋에서 바뀐다.
- `cargo-nextest` **필수**, `cargo test`는 게이트가 아니다: 테스트별 프로세스 격리(전역 상태를 바꾸는 PTY/termios 테스트에 필수), 실 timeout, flake 재시도, JUnit 출력이 이유의 절반이고, 나머지 절반은 이 repo의 실측이다 — `cargo test`는 전역 상태를 공유하는 동일 바이너리 실행 때문에 M7 기준 baseline부터 이미 빨간불(`acl::load`·`localctl::daemon` 계열이 프로세스 안에서 서로 간섭)이고, CI(`.github/workflows/ci.yml`)도 nextest만 돈다. 커밋 전 게이트는 `TMPDIR=<격리 디렉터리> cargo nextest run --workspace`이며, `cargo test`로 빨간불이 뜨는 것은 회귀 신호가 아니다 — nextest로 같은 스위트를 돌려 실제로 깨졌는지 확인한다.

**현재 상태 (M1 이후):** `.github/workflows/ci.yml`이 push(main)/PR마다 fmt / clippy / test(nextest + doc-test + `RUSTDOCFLAGS=-D warnings` doc, M8 Step 6부터) / arch-lint / cargo-deny를 4개 runner(ubuntu-24.04, ubuntu-24.04-arm, macos-14, windows-latest)에서 돌리고(macos-15-intel은 2026-08-27에 커버리지가 macos-14와 겹쳐 매트릭스에서 빠졌다 — `ci.yml`의 매트릭스 상단 주석 참고), 단일 required check `ci-ok`로 합친다. Windows에서는 POSIX 시그널·process-group·`$$` 의존 테스트가 `cfg(unix)`로 빠지고 나머지(`sh -c` 기반 DoD 테스트 포함 — runner의 Git for Windows `sh`에 의존)는 그대로 돈다. fuzz-smoke·nightly-fuzz·soak·perf job은 M8에서 추가한다 — fuzz-smoke와 T2 적대적 부하(`.github/workflows/load.yml`)는 이미 섰고, 같은 워크플로가 이제 짧은 soak 시나리오(`cargo nextest run --profile load -p qsh-cli --test soak`)도 T2 스텝 뒤에 돈다. 24h/100세션 soak은 CI job이 아니라 `docs/campaigns/m8-soak.md`의 사람 캠페인이다(위 L4 "구현(M8 Step 5)" 참고) — nightly-fuzz·perf는 아직이다. `crates/qsh-testkit`은 M2에서 chaos proxy(`chaos.rs`, L4)·loopback 하네스(`loopback.rs`, L3)를 구현했고 M2 attach recovery 스위트(`crates/qsh-cli/tests/attach_recovery.rs`)가 그 위에 서 있다 — 더 이상 빈 골격이 아니다. M3는 여기에 역방향 하네스(`reverse.rs` — controller listener + target dialer, `ReverseHarness`)를 더했고, 그 위에 역방향 resume 게이트 두 개(`reverse_resume_chaos.rs` PR 상시 + `reverse_blackout.rs` 60초 수용, L4)와 controller 도달성 진단 항목 및 문서-상수 일치 게이트(`crates/qsh-core/src/doctor.rs` + `crates/qsh-core/tests/doctor_docs.rs`, L6)가 서 있다. M5는 L2에 정책 평가기 property test(`crates/qsh-core/src/acl/policy.rs`, default-deny·wildcard·principal 정확 일치, DoD 3)와 audit 수명주기 테스트(회전·retention·쓰기 실패 fail-closed, `crates/qsh-core/src/audit/writer.rs`, DoD 5)를 심었다. L6에는 문서-상수 일치 게이트가 두 벌 섰다. `crates/qsh-core/tests/acl_docs.rs`는 `Action::ALL`·`PERMISSION_DENIED_MESSAGE`·시작 진단 문면이 PRD·CLI.md·README와 어긋나지 않는지 보고, Step 8이 마감한 `crates/qsh-core/tests/acl_registry.rs`는 `OP_REGISTRY`와 CLI.md §2.5 매핑 표를 양방향으로 대조하면서 `Server::dispatch`의 `control_message::Body` variant를 전수 분류하고 registry 10개 항목의 DoD 2 audit 완전성을 구동한다. 항상-deny 3종(`forward.socks`·`file.read`·`file.write`)은 구동 가능한 wire op이 아직 없어 이 열거에서 빠지며, 나머지 14개 인가 seam의 거부 문면 균일성은 `crates/qsh-testkit/tests/acl_uniformity.rs`가 맡는다. `OP_REGISTRY`가 `Server::dispatch`만으로는 구동할 수 없는 `forward.local`·`forward.remote`·`host.reverse` 세 seam의 DoD 2 구동은 `crates/qsh-testkit/tests/acl_registry_audit.rs`가 이어받는다. M6는 L7을 처음 채웠다: `qsh mcp`(`crates/qsh-cli/src/mcp/mod.rs`, rmcp `=3.1.4` stdio 서버)에 대해 `crates/qsh-cli/tests/mcp_conformance.rs`가 fixture 고정·stdout 순수성(DoD 5)·오류 표면·취소 의미론(DoD 3)·터널 truthful-close·Windows-ungated 성공 경로·fixture 세트 등가성을 실 바이너리 spawn으로 구동하고, `xtask`의 `ModuleBan`이 `crates/qsh-cli/src/mcp/` 스코프에서 `std::process`/`Command::new`/`Stdio::piped` 세 토큰을 금지해 DoD 4(subprocess·CLI 재파싱 ban)를 기계로 강제했다. DoD 2(Claude Code 실접속)는 이 계층의 자동 게이트가 아니라 `docs/campaigns/m6-mcp.md`의 수동 캠페인 기록이었다 — M2 mobility 캠페인과 같은 지위. 이 어댑터와 L7 하네스 전체는 M8 Step 6에서 철회했다(ADR-0011, 위 "L7 — MCP conformance (철회, ADR-0011)" 참고).

**M7.** L1에 CA 인증 경로가 더해졌다: `qsh cert init`/`qsh cert issue`(§6.16, `crates/qsh-core/src/ca.rs`)가 만드는 self-signed root + device leaf 승격을 `crates/qsh-core/tests/cert_e2e.rs`가 실 handshake로 검증하고, CA-vs-pin `auth_path` 분기가 ACL 판정과 audit 기록(`auth_path:"ca"`) 양쪽에서 load-bearing임을 mutation으로 확인했다(pin 전용 규칙에 CA principal이 매칭하도록 뒤집으면 FAIL). L2는 Step 7-2의 공유 런타임 정리 과정에서 `OP_REGISTRY`의 키를 `&'static str`에서 `Op` enum으로 바꿨다 — `declare_ops!` 매크로 하나가 `Op`·`Op::as_str`·`Op::spec`·`OP_REGISTRY`를 전부 같은 선언에서 뽑아내고(`crates/qsh-core/src/acl/registry.rs`), `action_of("sesion.open")`처럼 오타가 컴파일된 뒤 런타임에 패닉하던 구멍은 `Op` 타입 자체가 닫는다 — 없는 variant는 이름을 쓰는 순간 컴파일이 안 되고, `Op::spec()`의 match에는 wildcard arm이 없어 등록 없는 variant도 컴파일되지 않는다. `tests/acl_registry.rs`의 소스텍스트 매칭 게이트 두 벌(`authorize_stream_has_exactly_two_production_call_sites`·`action_variant_literals_are_pinned_to_the_one_documented_exception`)은 대체되지 않고 새 호출 형태에 맞춰 갱신된 채 남았다. 리팩터가 그런 게이트를 무증상으로 무력화하는 일이 흔해서 검증 라운드가 따로 확인했고, 둘 다 검출력을 유지했다. L6은 두 갈래로 자랐다. Step 1이 `qsh schema --json`·`qsh capabilities`를 CLI 표면으로 확정하면서 `CLI_V1_SCHEMA_COMMANDS` 완전성 게이트를 단방향 const→arm 대조에서 `Operation` impl 전수 양방향 set-equality로 다시 짰다 — mutation으로 등록 누락을 흉내 냈을 때 옛 게이트가 못 잡는다는 게 이 재작업의 계기였다. Step 6은 `qsh doctor`(§6.17, `ops/doctor.rs` + `doctor/probe.rs`)의 findings 코드 13종을 `EXPECTED_DOCTOR_CODES` 동결 set-equality로 고정하고(golden fixture는 byte-freeze하지 않는다 — `schema.get`과 같은 이유로 환경 의존), 시각 임계값 세 곳의 경계 테스트와 `classify_io_error`의 errno 분류를 유닛 테스트로 확정했다 — CLI.md에 축자 인용된 진단 문면은 `doctor_docs.rs` 계열 게이트가 지키고, README는 서사 산문이라 축자 인용 대상에서 의도적으로 뺐다(PLAN.md Step 6 결정). Step 4의 `trust.invite`/`trust.accept`(ADR-0002)는 channel binding(TLS exporter 변조 시 교환 실패)·상수시간 비교(`ct_eq`)·단일사용·secret 비영속을 mutation으로 검증했고, Step 3의 `hosts.toml`은 주소 우선순위(hosts.toml이 trust.toml을 덮되 신뢰는 trust.toml 단독 판정)를 실 QUIC 연결 테스트로 고정했다. M7 구간 전체의 최종 nextest baseline은 **1334 passed / 2 skipped**다(Step 1의 1172에서 단계마다 누적, Step 8의 man page 재생성 대조 1건 포함) — `cargo test`는 이미 이 baseline부터 빨간불이라(위 CI 규율 항목) 게이트로 쓰지 않는다.

**M8.** Step 4는 세 축을 닫았다. 강제 공백 둘을 in-process/서브프로세스 양쪽에서 채웠고(`-R` accept의 터널 스트림 permit, `qsh doctor`의 `config_unknown_key`), doctor `EXPECTED_DOCTOR_CODES`가 이제 **14종**이다(§6.17, `docs/CLI.md` §6.11·§6.17의 산문 숫자도 14로 맞췄다 — 위 M7 문단의 "13종"은 그 시점의 회고이므로 그대로 둔다). L9/L10에는 위 문단이 적은 T2 적대적 부하 하네스(`crates/qsh-cli/tests/adversarial_load.rs`, 6개 시나리오 — 1/2/3/13에 더해 감사 부피 시나리오가 12a 집계·12b 회전·보존 둘로 나뉜다(4c 적대 검토 A4/A5/A6). 12c 회전 실패 fail-closed(A17)는 시도됐으나 4c-F2에서 뺐다 — `chmod 500`으로 디렉터리 쓰기 권한만 없애는 구성은 `audit/writer.rs`의 `rotate()`가 rename 실패를 의도적으로 non-fatal로 다뤄(F6 규율) 이미 열린 파일 핸들로 계속 append하므로 애초에 degraded 래치에 닿지 않는다 — 이미 열린 fd에는 디렉터리 권한이 적용되지 않기 때문이다. 실측은 예상과 달리 세션 open/attach/close 반복이 `Server::MAX_PENDING_TICKETS_PER_CONN`(32, 감사 상태와 무관한 커넥션당 티켓 상한)에 먼저 걸렸다. 필수 판정(4a의 in-crate fail-closed 유닛 테스트)은 이 축소와 무관하게 그대로 선다)가 서고, `.config/nextest.toml`의 `[profile.load]`(`test-threads = 1`, 서브프로세스끼리 포트·audit 디렉터리를 밟지 않도록 직렬화)와 `--profile load`로 돈다. `load.yml`이 그 회귀 감시자로 붙었다 — 큰 N의 수동 실측은 `docs/campaigns/m8-adversarial-load.md`가 담당한다(M2 mobility 캠페인과 같은 지위). `crates/qsh-core/tests/quota_docs.rs`가 §6.12의 audit 부피 상계 문장(`[audit].max_bytes × (retain + 1)`)을 `AuditConfig::default()`와 대조해 고정한다.
