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

## L3 — Transport (in-process loopback QUIC)

한 프로세스 안에 quinn endpoint 두 개, `127.0.0.1:0`. 실제 QUIC, subprocess 없음, 일반 `cargo test`에서 실행. 여기서 verifier·keep-alive·stream 우선순위의 통합 동작을 검증한다.

M3부터는 같은 계층에 역방향 하네스(`qsh-testkit::reverse::ReverseHarness` — 한 프로세스 안에 controller listener + target dialer, `127.0.0.1:0`)가 더해져 등록·role 축 독립성(정방향/역방향 파라미터화된 loopback)·headless session op를 검증한다.

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

## L7 — MCP conformance

바이너리를 spawn해 stdio로 JSON-RPC 2.0 대화. `tools/list` == checked-in fixture (이름 변경이 diff로 가시화). 각 tool의 output schema가 대응 CLI 타입의 schema와 **동일 객체**임을 단언 (손 복사본 금지). §8.2의 "command string 생성·CLI output 재파싱 금지"는 의존성 ban(arch-lint)으로 정적 강제. 취소 테스트: `read_session` long-poll 취소 후 세션이 `running` 유지 (§8.4).

## L8 — Fuzzing (`cargo-fuzz`, 본격 가동은 M8)

| 타깃 | 내용 | 비고 |
|---|---|---|
| `frame_decode` | raw bytes → frame splitter | 최우선 |
| `control_message` | frame → 시맨틱 파싱 | |
| `roundtrip` | structure-aware `Arbitrary` → encode → decode → eq | 시간당 버그 최저가 |
| 문자열 파서류 | `session_ref`, `-L 8080:host:3000` 파싱 | |
| `json_envelope` | MCP tool 인자 (agent가 주는 입력) | |
| `broker_ops` | **stateful**: byte열 → op 시퀀스(append/read/attach/detach/tick) vs 모델 oracle | **M2에서 주입 가능한 clock을 설계해야 가능** |

ACL glob 평가기는 fuzz보다 property test가 적합 (`session.*`가 `session.control.escalate`에 매칭되는가? `user:dave`가 `user:dave2`에 매칭되지 않는가?).

**Corpus는 checked-in하고 일반 유닛 테스트로 전 플랫폼에서 상시 replay** — fuzzing이 돌지 않는 동안에도 발견된 crash가 고정된 상태로 유지된다. 공개 beta 전 타깃당 누적 72시간 + OSS-Fuzz 제출 (무료이며 SC7 리뷰의 신뢰 신호).

## L9/L10 — Soak·Perf

- Soak: 24h 수다스러운 세션(메모리 유계), 100 동시 세션(listener RSS ≤ 30MB idle 목표), 10k connect/disconnect 사이클(fd·세션 누수 0), Linux ASAN/LSAN으로 통합 스위트 1회.
- **Perf는 절대값이 아니라 비율로 게이트:** raw-quinn 기준 throughput을 **같은 프로세스, 같은 실행에서** 측정한 뒤 터널 ≥ 80%를 단언 — runner 무관하므로 실제로 CI 가능. PTY p95 산식: (client 수신 시각 − pty write 시각 − 측정된 loopback RTT) < 10ms. **Perf는 nightly + 추세 기록 + 관대한 임계치로만 — PR 게이트 금지** (공유 runner의 flake가 무시 습관을 만든다).

## CI 규율

- 모든 테스트는 port 0 바인딩, 테스트별 고유 tempdir.
- `sleep()` 금지 — `tokio::time::pause()` 또는 이벤트 통지 + `timeout`.
- Chaos는 seeded, 실패 시 seed를 단언 메시지에 출력.
- `Swatinem/rust-cache`, concurrency group으로 구식 run 취소.
- GHA macOS runner는 UDP 소켓 버퍼 기본값이 작다 — `SO_RCVBUF`를 명시 설정하거나 throughput 수치 저하를 예상할 것.
- clippy는 **모든 타깃에서** 실행 — Linux 전용 clippy는 `cfg(target_os = "macos")` 블록 전체를 놓친다. 이 프로젝트처럼 플랫폼 분기가 많으면 실질적 구멍이다. Windows도 포함: 지원 플랫폼은 아니지만 `cfg(unix)`/`cfg(not(unix))` 분기가 계속 컴파일되는지는 CI만이 보증한다.
- `cargo-nextest` 권장: 테스트별 프로세스 격리(전역 상태를 바꾸는 PTY/termios 테스트에 필수), 실 timeout, flake 재시도, JUnit 출력.

**현재 상태 (M1 이후):** `.github/workflows/ci.yml`이 push(main)/PR마다 fmt / clippy / test(nextest + doc-test) / arch-lint / cargo-deny를 5개 runner(ubuntu-24.04, ubuntu-24.04-arm, macos-14, macos-15-intel, windows-latest)에서 돌리고, 단일 required check `ci-ok`로 합친다. Windows에서는 POSIX 시그널·process-group·`$$` 의존 테스트가 `cfg(unix)`로 빠지고 나머지(`sh -c` 기반 DoD 테스트 포함 — runner의 Git for Windows `sh`에 의존)는 그대로 돈다. fuzz-smoke·nightly-fuzz·soak·perf job은 M8에서 추가한다. `crates/qsh-testkit`은 M2에서 chaos proxy(`chaos.rs`, L4)·loopback 하네스(`loopback.rs`, L3)를 구현했고 M2 attach recovery 스위트(`crates/qsh-cli/tests/attach_recovery.rs`)가 그 위에 서 있다 — 더 이상 빈 골격이 아니다. M3는 여기에 역방향 하네스(`reverse.rs` — controller listener + target dialer, `ReverseHarness`)를 더한다.
