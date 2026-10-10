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
- **OpenSSH 키 파서(ADR-0026).** 손으로 쓴 파서(`crates/qsh-proto/src/openssh/`)에 위 항목을 그대로 건다. golden vector는 `ssh-keygen -t ed25519 -N ''`로 한 번 만든 테스트 전용 키를 hex 텍스트로 둔 `crates/qsh-proto/testdata/openssh/ed25519_golden.hex`이고(`parse_openssh_private_key_reads_an_unencrypted_ed25519_golden_vector`), 절단 전수(`parse_openssh_private_key_rejects_every_truncation_of_the_golden_vector`), 길이 접두 상한(`parse_openssh_private_key_rejects_a_length_prefix_larger_than_the_input_before_allocating`), 거절 표(`parse_openssh_private_key_rejection_table`), bit-flip와 임의 바이트 proptest(`parse_openssh_private_key_never_panics_on_a_bitflipped_golden_vector`, `parse_openssh_key_body_never_panics_on_arbitrary_bytes`), 줄별 독립 분류(`parse_authorized_keys_classifies_each_line_independently`), seed의 `Debug`가 키 바이트를 싣지 않음(`openssh_seed_debug_output_never_contains_key_bytes`)을 고정한다. 외부 파서 크레이트를 쓰지 않으므로 이 층이 유일한 검증이고, L8의 `parse_openssh_key` 타깃이 뒤를 받친다.

## L1 — Crypto/identity

대부분 negative test다. 표 기반 **handshake matrix**: (client cert, server cert, client trust store, server trust store, 모드[pin/CA]) → 기대 결과. 필수 케이스: fingerprint 불일치, 만료 cert, 다른 CA 서명, pin-only 모드에 CA 서명 cert, CA 모드에 self-signed, client cert 부재, 정상 pin, 정상 CA, **reverse dial, 비신뢰 target**(target이 `qsh listen`에 dial하지만 controller trust store에 없는 경우 — 인증 실패는 `host.reverse` 등록 판정 **이전**이므로 audit이 아니라 handshake deny로 기록된다, M3). M1의 수용 기준인 16종 조합이 여기서 나온다.

Keystore는 trait 뒤에: 유닛 테스트는 in-memory 구현, 플랫폼별로 게이트된 통합 테스트 각 1개 — macOS Keychain, Linux Secret Service, **headless Linux file fallback** (실전에서 가장 중요한 경로 — `qsh serve`는 headless 박스에 산다).

**플랫폼 키스토어 릴리스 전 수동 단계.** keyring-core 1.x와 플랫폼별 store crate(`apple-native-keyring-store`, `zbus-secret-service-keyring-store`)는 CI가 실제 저장소를 못 만나므로 키스토어 코드나 이 의존성을 건드린 릴리스 전에 사람이 한 번 돌린다. 테스트는 `platform_store_round_trips`(`crates/qsh-core/src/identity/keystore.rs`)이고, `QSH_TEST_PLATFORM_KEYSTORE=1`과 `--run-ignored only`가 있어야 돈다. 계정은 `device_test_<ulid>`라 실제 `qsh` 항목을 건드리지 않고, 테스트가 끝에 자기 항목을 지운다.

- macOS: 로그인된 데스크톱 세션(Keychain 잠금 해제)에서 `QSH_TEST_PLATFORM_KEYSTORE=1 cargo nextest run -p qsh-core --run-ignored only -E 'test(platform_store_round_trips)'`.
- Linux: Secret Service 데몬이 있는 세션이 필요하다. 데스크톱이 없는 박스는 `gnome-keyring`과 `dbus`를 설치하고 일회용 세션 버스에 로그인 키링을 띄워 돌린다. 키링 비밀번호는 아무 값이나 되고, 데이터·런타임 디렉터리는 임시로 둔다.

```sh
export XDG_DATA_HOME=$(mktemp -d) XDG_RUNTIME_DIR=$(mktemp -d)
dbus-run-session -- sh -c '
  printf testpw | gnome-keyring-daemon --login --components=secrets >/dev/null
  gnome-keyring-daemon --start --components=secrets >/dev/null
  sleep 1
  QSH_TEST_PLATFORM_KEYSTORE=1 cargo nextest run -p qsh-core \
    --run-ignored only -E "test(platform_store_round_trips)"'
```

- 저장 형식 호환은 같은 세션 안에서 이전 릴리스 바이너리로 `QSH_CONFIG_DIR`을 격리해 `qsh init --key-store platform`을 한 뒤 새 바이너리의 `qsh doctor --json`과 `qsh init`이 같은 fingerprint를 보는지, 반대 방향도 같은지로 확인한다. 2026-10-09 keyring 3.6에서 옮길 때 이 왕복을 Linux에서 양방향으로 확인했다.
- Secret Service가 없는 박스에서는 `auto`가 파일 저장소로 내려가고 `platform` 명시는 `Unavailable`로 실패해야 한다(옛 바이너리와 같은 동작).

## L2 — Session broker (순수 로직, 네트워크 없음)

- **중심 property test:** 임의의 append/read(`--after` cursor) interleaving에서, gap 이벤트가 없는 한 반환된 바이트의 연결은 원본 stream의 해당 suffix와 **byte-identical** — SC4(무손실 resume)의 property 표현. naive Vec 모델을 oracle로 사용.
- Buffer 초과는 올바른 `available_from`을 가진 `session.gap`을 산출 — silent truncation 금지 (PRD §8).
- Writer lease: 획득 / 재attach 시 steal·`SESSION_CONFLICT` 규칙 / connection 사망 시 해제 / TTL 만료.
- **TTL·시간 관련 테스트는 전부 `tokio::time::pause()`.** **테스트 스위트 전체에서 `sleep()` 전면 금지** — 이벤트 통지 + `timeout`으로 대체한다. 벽시계를 실제로 기다리는 의도적 예외는 `QSH_ACCEPTANCE_SLOW` 뒤의 `reverse_blackout`, `idle_timeout` 통합 테스트 둘, `supervised_dynamic_listener_stays_bound_through_a_50_second_blackhole_and_connects_after_it`(L4)과, 게이트 없이 도는 약 10초짜리 `supervised_forward_carrier_is_declared_lost_within_two_seconds_of_an_injected_wake`(L4, 활성 창이 지나가기를 기다린다)뿐이고, 그 안에서도 대기는 이벤트 통지와 `timeout`이다. 네트워크 프로젝트의 flaky 스위트는 팀이 빨간불을 무시하게 훈련시킨다.
- Fuzz를 위해 broker에 **주입 가능한 clock**을 처음부터 넣는다 (L8의 stateful fuzzer 전제). `broker_ops` 하네스와 reaper가 같은 `TestClock`/`Clock` trait 위에서 돌고, `TickSmall`/`TickLarge`/`Reap` op이 `TtlWindow::deadline`/`reap_reason`을 실시간 대기 없이 흔든다.
- **정책 평가기 property(DoD 3):** default-deny(임의 정책에서 어떤 rule도 커버하지 않는 action은 반드시 Deny), wildcard(trailing `.*`만 매칭 — 중간 glob이나 항상-deny 3종을 삼키지 않음), principal 정확 일치(`user:dave`는 `user:dave2`에 매칭되지 않음)를 순수 함수 위의 property test로 검증한다. 정책이 `acl.toml` 로더가 만든 순수 평가기(네트워크·I/O 없음)인 동안에만 이 계층에서 값싸게 돈다.
- **`acl show` 실효 집합의 독립 모델(ADR-0025 결정 3).** `effective_actions_equals_an_independent_model_over_arbitrary_policies`(`crates/qsh-core/src/acl/policy/tests.rs`)가 임의 정책·principal·auth path에서 `Policy::effective_actions`를 `decide`를 부르지 않는 모델과 대조한다. 모델은 principal과 `auth_path`가 맞는 행의 `allow` 패턴 합집합을 `Action::ALL` 위로 펼치고 항상-deny 셋(`forward.socks`·`file.read`·`file.write`)을 뺀 것이다. 같은 코드로 판정한다는 사실과 결과가 맞다는 사실을 따로 증명하려는 것이다. 표 기반의 `acl check` 대조는 L6이 맡는다.
- **Audit 수명주기(DoD 5):** 회전 트리거(`max_bytes` 초과 시 실제로 회전)·retention 준수(`retain` 개수만 남음)·쓰기 실패 fail-closed(주입형 실패 sink로 디스크 만실을 시뮬레이션 — 실디스크를 채우지 않는다, CI 규율 참고)를 순수 로직으로 검증한다. tempdir + 주입 가능한 clock/sink로 결정적이며 `sleep()` 없음.

## L3 — Transport (in-process loopback QUIC)

한 프로세스 안에 quinn endpoint 두 개, `127.0.0.1:0`. 실제 QUIC, subprocess 없음, 일반 `cargo test`에서 실행. 여기서 verifier·keep-alive·stream 우선순위의 통합 동작을 검증한다.

같은 계층에 역방향 하네스(`qsh-testkit::reverse::ReverseHarness` — 한 프로세스 안에 controller listener + target dialer, `127.0.0.1:0`)가 더해져 등록·role 축 독립성(정방향/역방향 파라미터화된 loopback)·headless session op를 검증한다.

**터널 loopback 하네스.** 같은 계층에 터널 전용 harness가 있다 — 한 프로세스 안에서 실제 TCP listener(`127.0.0.1:0`)를 열고, 실제 QUIC connection 위에서 `RemoteForwardOpen`/`Close`·`TCP_CONNECT`→`ConnectResult`→raw splice 전체 경로(local/remote 양방향)를 subprocess 없이 구동한다. `-L`/`-R` 각각에 대해 실제 바이트 왕복(echo 서버로 round-trip)을 단언하고, `ConnectResult{ok:false}` 경로(dial 실패 → `CONNECTION_FAILED`, inline ACL 거부 → `PERMISSION_DENIED`)도 이 계층에서 커버한다.

## L4 — Network fault injection: in-process UDP chaos proxy (`qsh-testkit`)

**설계:** `UdpSocket` 2개를 쥔 tokio task + seed 가능한 `ChaosPolicy`. 클라이언트는 proxy로 dial하고 proxy가 서버로 중계한다.

| Fault | 검증 대상 |
|---|---|
| `drop(p)`, `delay(dist)`, `reorder`, `duplicate` | 손실 복구, ack, dedup |
| `corrupt(p)` | AEAD가 항상 잡아야 함 — positive control |
| `blackhole(dur)` 후 복구 | PTO/keep-alive 튜닝, idle timeout 동작 |
| **`repath()`** — client측 소켓을 새 포트로 rebind | **NAT rebind / Wi-Fi→LTE 전환이 서버에게 보이는 모습 그대로.** 실제 인터페이스를 건드리지 않고 QUIC path validation을 구동 |
| **`sever()`** — client측 소켓 완전 폐쇄 | 재dial + session resume 강제 (또 하나의 복구 경로) |
| **`sever()`** — target→controller leg (`ReverseHarness`의 chaos 변형) | target의 재등록 backoff 루프, controller의 stale 처리·`generation` 단조 증가 (`docs/design/protocol.md` §11-4) |
| **`repath()`/`sever()`(터널)** — 터널이 열려 있는 QUIC connection에 동일 fault 적용 | **터널은 migration 아래에서 생존해야 한다**(connection이 살아남는 한 splice된 TCP 연결도 살아남음, §12 receive window/BBR 튜닝의 대상 그 자체)와 **`sever()` 아래에서는 깨끗이 teardown돼야 한다**(CLI.md §6.14 holder lifetime — 재수립 없이 local listener/remote 등록이 닫히고, 열려 있던 개별 TCP 연결이 좀비로 남지 않음)를 함께 검증. |

**대안 대비 선택 근거:** `iptables`/`pfctl`은 root 필요·플랫폼 분기·GHA macOS에서 불안정. 실제 인터페이스 전환은 CI 자동화 불가. transport trait mock은 mock을 테스트하는 것 — migration은 실제 path validation의 속성이다. proxy는 `seeded(u64)`로 재현 가능하며 실패 메시지에 seed를 출력한다.

**핵심 구분: chaos proxy는 PR 회귀 게이트이고, SC3의 실측치는 실기기 캠페인이다.** SC3용 실측: `recovery ∈ {migrated, resumed, failed}` + time-to-recovery 텔레메트리를 **M2부터** 계측하고(노출 표면은 M2에서 **stderr 구조화 진단만** — tracing target `qsh::recovery`, level `INFO`, **한 줄 JSON**(`tracing_subscriber` JSON layer)으로 고정, 필드 `recovery`·`time_to_recovery_ms`·`session_ref`(PTY 내용·토큰 field 없음); stdout 순수성 규칙(CLI.md §2.2) 때문에 `qsh.event/v1` event로의 승격은 P1에서 결정, CLI.md §6.4. 캠페인 스크립트와 chaos 테스트는 기본 verbosity(`--quiet` 없이)로 실행해 stderr의 JSON 줄을 파싱한다), 실기기(macOS `networksetup -setairportpower`, Linux `nmcli`) 스크립트로 N≥60회 전환 시험. 95% vs 90%를 구분하려면 ~60회 이상이 필요하다. **통과 기준은 사전 정의:** idle timeout이 뒤늦게 터져서 복구되는 것은 통과가 아니다 — path 사망 감지 후 **2초 내 재dial + resume**이 목표이며, migrated/resumed 비율을 분해 보고한다.

**역방향 확장.** 같은 텔레메트리에 additive 필드 `registration_wait_ms`(재등록을 기다린 시간, ms)가 더해진다 — `recovery ∈ {migrated, resumed, failed}` 값 집합은 바뀌지 않으며, 역방향에서는 `migrated`가 나올 수 없다(로컬 UDS는 migration 대상이 아니고 재수립은 target이 한다, `docs/design/protocol.md` §11-4). 예산은 재등록 시점부터 분리한다: `time_to_recovery_ms - registration_wait_ms <= 2000`. 사망 감지 자체의 예산 `detection_budget = P×S+D`는 연결 종류별 상한을 갖는다. 두 역방향 테스트는 역방향 등록 연결의 상한 5000ms(ADR-0041)를 리터럴로 보고 실제 역방향 watch 설정에서 예산을 계산하며, `attach_recovery.rs`는 2000ms를 그대로 본다. 이 예산은 watch가 자기 tick 지연을 침묵에서 덜어낸 뒤의 값이다(ADR-0042). 굶은 watchdog이 깨어난 tick에서 사망을 선언하지 않고, 응답이 없으면 한 정시 tick 뒤에 선언하며, 모든 tick이 늦어도 판정에 닿는다는 세 성질을 `crates/qsh-core/src/client/pathwatch/tests.rs`가 `tokio::time::advance`로 지연을 흉내 내어 고정한다. **60초 DoD는 이중 게이트다** — (i) `crates/qsh-testkit/tests/reverse_resume_chaos.rs`가 PR마다 seeded chaos(수 초)로 상시 검증하고, (ii) `crates/qsh-cli/tests/reverse_blackout.rs`가 `QSH_ACCEPTANCE_SLOW` 하에서만 도는 실제 60초 차단을 기존 `acceptance` job(`ci-ok`가 `needs`로 요구하는 job)에 추가해 상시 게이트로 돌린다 — 60초 자체를 매 PR마다 태우지 않으면서도 DoD 문구를 문자 그대로 검증한다.

**idle timeout 회차.** `cause` 어휘에서 quinn의 idle timeout 만료(`idle_timeout`)와 `PathWatch`의 판정(`path_dead`)을 가르는 증거는 실제로 45초를 기다리는 통합 테스트 둘이다. `run_target_lost_and_retry_lines_report_a_quinn_idle_timeout_as_idle_timeout`(`crates/qsh-core/src/reverse/target/tests.rs`, target의 `lost`·`retry` 줄)과 `controller_lost_line_reports_a_quinn_idle_timeout_as_idle_timeout`(`crates/qsh-core/src/reverse/listen/tests.rs`, controller의 `lost` 줄)다. 둘 다 `QSH_ACCEPTANCE_SLOW`가 없으면 skip 줄을 찍고 끝나고, `ci.yml` acceptance job이 `cargo nextest run -p qsh-core --lib -E 'test(/quinn_idle_timeout_as_idle_timeout/)'` 한 스텝으로 켠다(PR 필수 경로. `docs/ROADMAP.md` M11 결정 기록의 `--profile load` 대안은 쓰지 않았다. 어휘를 가르는 증거가 merge 뒤에만 돌면 회귀가 main에 한 번은 들어가기 때문이다). 실제 경로에서는 `PathWatch`가 약 1초 안에 먼저 판정하므로(`run_target_lost_and_retry_lines_report_a_silent_path_as_path_dead`가 그 쪽을 고정한다) idle timeout을 보려면 판정 하한을 45초 뒤로 밀어야 한다. 역방향 두 자리의 `PathWatchConfig`를 `#[cfg(test)]` 전용 주입(`reverse::path_watch_config`의 task-local, `Listen::set_test_path_watch`)으로 바꿔 `min_dead_after`를 120초로 올린다. `cfg(test)` 코드라 바이너리에 들어가지 않고 ADR-0021 결정 4의 `[recovery]` 개방이 아니며, cargo feature는 워크스페이스 feature 통합으로 바이너리에 켜질 수 있어 쓰지 않는다. 하네스는 `qsh-testkit`이 아니라 `crates/qsh-core/src/reverse/test_harness.rs`다. `qsh-testkit`은 `qsh-core`에 의존하므로 dev 의존으로 끌어오면 `qsh-core`가 두 벌 링크되어 `cfg(test)` 주입이 그쪽에 닿지 않는다. 하네스는 끊기 스위치가 있는 작은 UDP 중계로 target과 controller를 잇고, 끊으면 두 끝이 순수한 침묵만 본다. 벽시계를 쓰지만 대기는 `qsh::reverse` 줄 캡처의 이벤트 통지와 `timeout`이다.

**supervise 회차.** `--supervise`의 타이밍 증거는 둘이다. (i) `supervised_forward_carrier_is_declared_lost_within_two_seconds_of_an_injected_wake`(`crates/qsh-core/src/ops/tunnel/supervise/tests.rs`)는 process-wide wake 감지기(`client/wake.rs`)에 `#[cfg(test)]` 전용 주입 자리(`install_process_detector_for_test`)로 가짜 벽시계를 꽂고, 유휴 cadence를 60초로 늘린 supervisor 아래에서 peer가 `Ping`에 답을 멈춘 뒤 시계를 10초 앞으로 민다. wake 이후 10초 안에, 그 전이 아니라 그 뒤에 `cause: path_dead`인 `lost` 줄이 나와야 하고 측정한 지연을 stderr에 찍는다(실측 1초 안팎). PR 게이트에서 그대로 돈다. (ii) `supervised_dynamic_listener_stays_bound_through_a_50_second_blackhole_and_connects_after_it`(`crates/qsh-testkit/tests/supervised_dynamic_blackhole.rs`)은 `ChaosProxy::blackhole`로 실제 50초 동안 경로를 막는 동안 1초 간격 TCP 연결 probe가 한 번도 connection-refused를 보지 않아야 하고(listener가 놓였다는 신호다), 차단이 걷힌 뒤 SOCKS `CONNECT`가 `FAST_CAP + REDIAL_DEADLINE + 4초` 안에 성공해야 한다. `-D`는 loopback 목적지를 거르므로 비loopback LAN echo가 필요하고, 그 주소가 없는 머신에서는 skip한다(CI에서는 실패로 바뀐다, `net_probe`). `QSH_ACCEPTANCE_SLOW`가 없으면 skip 줄을 찍고 끝나며 `ci.yml` acceptance job이 `QSH_ACCEPTANCE_SLOW: 1`로 켠다. `FAST_CAP`과 `REDIAL_DEADLINE`은 crate 내부 상수라 테스트가 같은 값을 다시 적는다.

**30분 회차.** `docs/PRD.md` §13 "30분 단절 후에도 TTL 내 세션 복구" 행의 판정 근거는 같은 파일의 세 번째 테스트 `a_real_30_minute_blackout_is_resumed_within_the_ttl`이다. `QSH_ACCEPTANCE_SLOW`가 아니라 새 게이트 `QSH_ACCEPTANCE_LONG` 뒤에 있고, 이 게이트를 켜는 것은 `.github/workflows/long.yml`의 `workflow_dispatch` 전용 job뿐이다 — PR 게이트가 아니다. 출고 기본값(`attempts: 3`, `registration_wait: LOCAL_WAIT_MAX`)으로는 붙어 있던 attach 자체가 1800초를 버티지 못하므로, 이 회차가 재는 것은 그 attach의 생존이 아니라 차단이 걷힌 뒤 같은 `session_ref`로 다시 붙어 보존된 ring을 받는지다. 길이는 `QSH_BLACKOUT_SECS`가 정하며(미설정 1800초), `.config/nextest.toml`의 `[profile.long]`이 그만큼 실행되도록 deadlock 가드를 늦춰 둔다.

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
- **`acl check` fixture + 거부 문면 상수-문서 일치 게이트:** `acl.check.allow.json`·`acl.check.deny.json`이 `acl check`가 실제 enforcement와 같은 코드 경로임을 값으로 보여준다. 거부 문면(균일 상수)이 `README.md`/`docs/CLI.md`에 축자 인용되는지는 `tunnel_docs.rs`/`doctor_docs.rs` 선례와 동형인 anti-drift 테스트가 고정한다 — `crates/qsh-core/tests/acl_docs.rs`는 같은 원리로 `Action::ALL` ↔ PRD §9 action 목록의 드리프트를 잡는다.
- **값-보유(value-bearing) golden fixture는 append-only의 예외, diff 리뷰가 필수다:** `capabilities.json`(scope-creep tripwire)은 파일의 존재가 아니라 안에 든 값 자체가 계약 단언이므로, 보통의 append-only 규율을 따르지 않는다 — `wire::LOCAL_CAPABILITIES`가 바뀌면 `QSH_UPDATE_FIXTURES=1`로 재생성하고 그 diff를 계약 변경과 같은 무게로 리뷰해야 한다(`fixtures.rs`의 `golden_local_fixtures` 자체 문서). 이전에는 옛 L7의 `tools_list.json`도 같은 예외에 속했다 — 그 fixture는 `crates/qsh-cli/tests/fixtures/mcp/`에 append-only로 남아 있지만(같은 디렉터리의 `README.md` 참고), 이를 검증하던 conformance 하네스 자체가 철회됐다(ADR-0011). 반대로 `schema.get`은 golden fixture를 두지 않는다: payload가 스텝마다 command 하나씩 자라는 전체 registry dump라 append-only와 정면충돌하기 때문이며, 대신 `every_fixture_payload_validates_against_its_command_schema`의 스키마 검증과 `qsh-cli/tests/fixtures.rs`의 `schema_command_output_matches_the_single_source_generator`(구조 동등성)가 생성기 정확성을 지킨다는 채택 기록이다.

**release 프로파일 기능 스모크.** `crates/qsh-cli/tests/release_smoke.rs`가 네 축(init → trust → `exec --json` 왕복 → PTY 셸 + `~d` detach → `qsh attach` 재부착)을 한 시나리오로 잇는다. 이 스위트는 `QSH_SMOKE_BIN`으로 **임의의 `qsh` 바이너리**를 구동할 수 있고, 그것이 존재 이유다. 출고되는 것은 release 빌드인데 CI의 기능 테스트는 전부 dev 프로파일이다. 하네스를 release로 컴파일한다는 뜻이 아니라 출고되는 release 바이너리를 dev 하네스로 구동한다는 뜻이며, `adversarial_load`·`soak`이 `QSH_LOAD_BIN`으로 쓰는 것과 같은 규율이다.

- 변수를 주지 않으면 `CARGO_BIN_EXE_qsh`로 떨어져 PR 게이트에서 debug 축으로 돈다. `QSH_SMOKE_STRICT=1`은 그 fallback을 없애 "출고 바이너리를 인증한다"는 job이 debug를 인증하고 통과하는 길을 막는다.
- 증명하는 것은 그 바이너리로 네 축이 왕복한다는 것뿐이다. 서명·공증·static 링크·설치 경로는 릴리스의 다른 항목이 판정하고, 절대 RSS/fd/echo 수치는 `adversarial_load`·`soak`(L9/L10)의 몫이며, 경로 단절 뒤 resume은 `a_severed_path_is_detected_and_resumed_under_a_live_attach`가 담당한다.
- 기능 테스트는 `release_smoke_covers_init_trust_exec_pty_detach_and_reattach`다. PTY 축은 unix 전용이고 그 밖의 플랫폼에서는 init·trust·exec 셋만 돈다.

**`acl show`와 SSH 키 가져오기.** 등록 완전성 게이트는 op `acl.show`와 `trust.ssh_preview`를 포함한다. 신규 fixture 여덟은 `acl.show.json`, `acl.show.no_policy.json`, `identity.init.imported_ssh_key.json`, `error.UNSUPPORTED.ssh_key_encrypted.json`, `error.UNSUPPORTED.ssh_key_type.json`, `error.INVALID_ARGUMENT.ssh_key_malformed.json`, `error.INVALID_ARGUMENT.ssh_key_identity_exists.json`, `trust.ssh_preview.json`이다. `crates/qsh-cli/tests/fixtures.rs`의 `golden_acl_show_fixtures`, `golden_identity_init_import_ssh_key_fixtures`, `golden_trust_ssh_preview_fixture`가 실제 바이너리로 재현한다.

- `acl show`의 실효 집합과 `acl check` 판정이 표 기반 정책마다 일치함은 `crates/qsh-cli/tests/acl_check_equivalence.rs`의 `acl_show_effective_set_agrees_with_acl_check_for_every_action_in_every_table_row`가 고정한다. 재시작 고지 상수가 human 출력에 바이트 그대로 실림은 `acl_show_human_output_carries_the_acl_restart_notice_byte_for_byte`가 고정한다.
- `Policy::decide`의 비테스트 호출 지점은 셋(`Policy::check`, `Policy::effective_actions`, `Ops::acl_check`)이고 `acl_check_equivalence.rs` 모듈 doc과 `Policy::decide` doc이 같은 grep으로 그 셋을 적는다.
- 가져오기 쪽은 `crates/qsh-cli/tests/init_trust.rs`의 `init_import_ssh_key_*` 테스트(거절이 파일을 남기지 않음, 기존 identity 바이트 보존, `trust.toml`·`acl.toml` 바이트 동일, 입력 바이트 부재)와 `crates/qsh-cli/tests/trust_ssh_preview.rs`가 잡는다. 미리보기가 예측하는 fingerprint와 가져오기가 내는 fingerprint의 일치는 `trust_ssh_preview_predicts_the_fingerprint_import_ssh_key_produces_for_the_same_key`가 같은 키로 두 경로를 대조한다.

**`qsh setup`.** 등록 완전성 게이트는 op `setup.run`을 포함한다. 마커 `SetupRunOp`는 게이트가 `crates/qsh-core/src/ops/`만 훑기 때문에 `ops/setup.rs`에 두고, 판단 로직은 `crates/qsh-core/src/setup/`에 있다. 신규 fixture 넷은 `setup.run.host_pending_acl.json`, `setup.run.client_complete.json`, `setup.run.listener_pending_acl.json`, `error.INVALID_ARGUMENT.setup_missing_input.json`이고 생산 테스트는 `crates/qsh-cli/tests/fixtures.rs`의 `golden_setup_run_fixtures`다. step command와 detail에는 절대 경로를 싣지 않고(acl.toml 경로는 `steps[acl].result[].policy.path`에만 있고 normalize가 가린다), `client_complete`의 doctor 단계는 `overall`까지 가려서 머신 의존 값을 없앤다.

CLI 경계는 `crates/qsh-cli/tests/setup.rs`의 테스트 일곱(`setup_machine_mode_rejects_missing_input_before_any_write`, `setup_machine_mode_never_opens_a_prompt`, `setup_human_mode_without_a_tty_treats_missing_input_as_invalid_argument`, `setup_usage_conflicts_exit_2`, `setup_output_never_carries_key_material`, `setup_step_vocabulary_matches_cli_md`, `setup_run_never_appears_as_a_control_message_wire_variant`)와 `exit_code_matrix.rs`의 두 행이 잡는다. 역할별 판단은 `crates/qsh-core/tests/setup.rs`가 잡는다. 그 fixture가 파일을 쓰기 때문에 `setup/` 디렉터리 금지 토큰을 피해 이 위치에 둔다.

## L7 — MCP conformance (철회, ADR-0011)

내장 `qsh mcp` stdio adapter를 raw JSON-RPC로 구동하던 conformance 하네스(`mcp_conformance.rs`)는 adapter 자체와 함께 철회했다. 그 하네스가 지키던 계약(fixture 고정·stdout 순수성·오류 표면·취소 의미론·터널 truthful-close·fixture 세트 등가성)은 이제 CLI 표면에서 직접 구동한다 — long-poll cursor 정순서와 취소 무결성은 §6.4의 `session read --wait`/`--follow` 경로가, 터널 truthful-close는 §6.9의 `tunnel open`/`tunnel close` 경로가 각각 같은 값을 검증한다. 근거는 ADR-0011.

## L8 — Fuzzing (`cargo-fuzz`)

cargo-fuzz 타깃 **19종**이 `fuzz/fuzz_targets/`에 있다(`fuzz/Cargo.toml`의 `[[bin]]`과 같은 수). 구성은 sans-IO 파서 타깃, stateful 타깃 `broker_ops`, ADR-0019가 더한 `parse_socks5`, ADR-0026이 더한 `parse_openssh_key`다. 아래 표는 `[[bin]]` 이름 그대로이고, 이 절이 처음 계획했던 이름(`frame_decode`/`control_message`/`roundtrip`/`json_envelope`/`broker_ops`)은 착륙 시점에 다시 갈라졌다(`docs/design/protocol.md` §13). 실행법과 `fuzz/`가 워크스페이스 밖에 있는 이유는 `fuzz/README.md`가 적는다.

| 타깃 | 내용 | 비고 |
|---|---|---|
| `frame_decoder` | 길이 프리픽스 framing에 적대적 부분 청크를 흘리고 `push`/`next_frame`/`take_remaining`을 임의 순서로 인터리브 | 구 `frame_decode` |
| `decode_control` | `decode_msg::<ControlMessage>` — 루트 oneof | 구 `control_message` |
| `decode_hello` | `decode_msg::<Hello>` — handshake 최초 파싱 |  |
| `decode_stream_header` | `decode_msg::<StreamHeader>` + `StreamKind::try_from`(unknown i32 포함) |  |
| `decode_session_frame` | `decode_msg::<SessionFrame>` + `validate()` 체인 |  |
| `decode_exec_frame` | `decode_msg::<ExecFrame>` — EXEC_DATA 경로 |  |
| `decode_connect_result` | `decode_msg::<ConnectResult>` — ticket/ACL 게이트가 없는 유일한 decode 경로 |  |
| `decode_local_hello` | `decode_local::<LocalHello>` — localctl 첫 메시지 (`qsh.local.v1`) |  |
| `decode_local_admin_request` | `decode_local::<LocalAdminRequest>` — localctl 두 번째 프레임 |  |
| `valid_host_name` | `Hello.reverse.offered_name` 모양 검사 |  |
| `valid_forward_id` | `forward_id`/`ticket` 모양 검사 |  |
| `parse_invite_code` | Crockford Base32 invite code 디코드 |  |
| `parse_forward_spec` | `-L`/`-R` grammar (`[bind:]listen_port:host:host_port`) | 구 "문자열 파서류" |
| `sanitize_peer_text` | 화면에 뿌릴 peer 문자열의 제어문자 제거 |  |
| `fingerprint_principal` | `Fingerprint`/`Principal`의 `from_str` |  |
| `json_request_types` | `serde_json::from_slice` → `qsh_proto::types::*Req` | 구 `json_envelope` |
| `parse_socks5` | `crates/qsh-proto/src/socks5.rs`의 `parse_greeting`/`parse_request` — `-D`가 로컬 loopback listener에서 받는 SOCKS5 codec (ADR-0019) | `docs/design/protocol.md` §13-7) |
| `parse_openssh_key` | `crates/qsh-proto/src/openssh/`의 OpenSSH 개인키 봉투·이진 본문과 `authorized_keys` 줄 분류 — 첫 바이트가 층을 고른다 (ADR-0026) | `docs/design/protocol.md` §13-8) |
| `broker_ops` | **stateful**: byte열 → 19종 op 어휘(NewSession/Append/AppendControl/ReadAt/ReadBeyond/ReadFollow/TakeLease/DropConnection/Attach/Detach/SetExited/SetClosing/IssueResume/VerifyResume/RotateResume/ForgetResume/TickSmall/TickLarge/Reap) 시퀀스를 `ModelSession` oracle(naive Vec + 독립 재구현한 `predict_reap_reason`/`predict_verify`)과 대조 — sequence·control id·gap·byte-identity·메모리 예산·writer lease·resume 토큰·TTL/reap 전부. default deny 축은 `acl/policy.rs`의 proptest(§13-5)가 담당하고, `broker_ops`는 그 대신 상태 부재·불일치 → `Err(ResumeDenied)`·`Conflict`·`CursorBeyondEnd`의 fail-closed 성질을 잰다. 하네스는 `crates/qsh-core/tests/support/broker_ops_harness.rs`, fuzz 타깃은 `fuzz/fuzz_targets/broker_ops.rs`(같은 파일을 `#[path]`로 include), 회귀 재생은 `crates/qsh-core/tests/broker_ops_corpus.rs`(`fuzz/corpus/broker_ops/` seed를 일반 nextest로 상시 재생, seed가 0개면 FAIL) |

구 `roundtrip` 행(structure-aware `Arbitrary` → encode → decode → eq)은 별도 타깃으로 두지 않았고, 그 자리는 proptest 다섯 종이 맡는다(§L2 및 `protocol.md` §13-5). 둘은 등가가 아니다. 위 표의 decode 타깃은 임의 바이트를, proptest는 타입 수준 모델을 흔든다.

캠페인 기록(배치별 run-id, 누적 fuzz-hours, DoD 1 판정)은 [`docs/campaigns/m8-fuzz.md`](../campaigns/m8-fuzz.md)가 canonical이다.

ACL glob 평가기는 fuzz보다 property test가 적합하다(위 L2 "정책 평가기 property" 행이 그 자리다). action 어휘가 PRD §9의 닫힌 11종(`Action::ALL`)이고 wildcard가 trailing `.*`만 허용되도록 정해져 있으므로(`docs/design/architecture.md` §6), `session.control.escalate` 같은 가상의 깊은 이름 문제는 애초에 발생하지 않는다 — 로더가 `Action::ALL`의 어느 것에도 매칭되지 않는 패턴을 로드 시점 `CONFIG_ERROR`로 거부한다. property로 직접 표현할 질문은: `session.*`가 `session.control`에 매칭되는가? `forward.*`를 가진 정책에서도 `forward.socks`는 여전히 deny인가(항상-deny 게이트가 wildcard 매칭보다 먼저 적용)? `user:dave`가 `user:dave2`에 매칭되지 않는가?

Corpus는 checked-in하고, 그중 `broker_ops`는 일반 유닛 테스트로 전 플랫폼에서 상시 replay된다(`crates/qsh-core/tests/broker_ops_corpus.rs`). 나머지 파서 18종의 상시 replay는 선언일 뿐이고 현재는 `fuzz-smoke.yml`의 짧은 결정적 스모크가 그 자리를 맡는다. fuzzing이 돌지 않는 동안에도 발견된 crash는 seed로 고정된다. 공개 beta 전 목표는 타깃당 누적 72시간과 OSS-Fuzz 제출이다(`fuzz/oss-fuzz/README.md`).

## L9/L10 — Soak·Perf

### Soak

목표는 24h 수다스러운 세션(메모리 유계), 100 동시 세션(listener RSS ≤ 30MB idle), 10k connect/disconnect 사이클(fd·세션 누수 0), Linux ASAN/LSAN 통합 스위트 1회다. 하나의 시나리오 `crates/qsh-cli/tests/soak.rs`가 두 속도로 돈다.

- 짧은 모드(기본 120s/8세션, `QSH_SOAK_*` env로 조절)는 `[profile.load]`로 `load.yml`이 push(main)마다 도는 회귀 감시자다.
- 24h/100세션 모드는 `[profile.soak]`(`.config/nextest.toml`: `test-threads=1`, `slow-timeout={period="3600s"}`, `terminate-after` 없음. kill하지 않고 SLOW 경고만 반복한다)로 GHA 6h 상한 밖에서 `scripts/soak/run.sh`가 기동한다. 사람이 `docs/campaigns/m8-soak.md`에 기록하며 M2 mobility·adversarial-load 캠페인과 같은 지위로, PR을 막지 않는다.

판정식은 idle RSS ≤ 30MiB, 세션당 buffer ≤ 8MiB, RSS 추세 < 1MiB/h, listener/self fd 성장 ≤ +2, echo p95 spike 비율 ≤ 10%(`ECHO_SPIKE_FRACTION_MAX`, steady 창 중 bound `max(3 × ramp 직후 baseline p95, 50ms)`를 넘는 창의 비율), TTL reap이다.

- 짧은 모드에서 판단 가능한 축은 테스트가 직접 assert한다. 표본이 많이 필요한 두 축(세션당 buffer의 24h 형태, RSS 추세 회귀선)은 `scripts/soak/summarize.py`(stdlib만, CSV를 읽어 위반 시 exit 1)가 24h CSV로 판단한다. 두 판정이 같은 임계를 쓰는 것은 CSV 헤더 상수 `SOAK_CSV_HEADER`가 양쪽에 핀으로 박혀 있어서다.
- fd 두 축(listener, self)은 steady 구간의 fd 표본을 4등분해 마지막 1/4의 최댓값이 첫 1/4의 최댓값 + 2를 넘는지로 판단한다. 사이클링 도중의 증가를 재는 것이다.
- boot baseline과 drain idle_end는 직접 비교하지 않는다. 그 전체 생애주기 비교에는 첫 세션 open이 lazy하게 올리는 일회성 fd 세트(감사 로그 fd, DNS resolver 소켓, keystore fd, tokio io-driver eventfd/epoll: cold-boot 11 → warm-idle ~21)와 ramp의 일회성 비용이 같이 잡혀 per-cycle 누수와 대상이 다르기 때문이다. boot→idle_end 델타는 soak.rs와 summarize.py에 정보성 줄로만 남고 위반으로 세지 않는다. soak.rs는 listener 쪽 정보성 줄에 idle_end 시점의 fd 인벤토리(`open_fd_targets`, `/proc/<pid>/fd` readlink)를 같이 찍어 델타가 lazy 세트임을 `load.yml` 로그에서 바로 확인하게 한다. summarize.py가 읽는 CSV는 fd 개수만 싣는다.
- client 쪽 fd 위반은 `FD_GROWTH_CLIENT`로 태그한다. pull마다 새 UDS conduit을 여는 `Ops::connect_target` 경로의 누수가 실측으로 재현됐다는 뜻이고, 이 축만 strict 실패로 다룬다.
- ramp의 세션 open과 사이클 교체 open은 재시도 가능한(`retryable: true`) `ConnectionFailed`/`Timeout` `OpError`를 1초 간격으로 최대 3회 재시도한다. fuzz로 포화된 호스트가 qsh-core의 10초 dial 타임아웃을 이따금 못 맞추는 것을 흡수하기 위해서이고 그 타임아웃 자체는 건드리지 않는다. 재시도 횟수는 verdict에 정보성으로만 찍히고, 3회를 모두 쓰고서야 실패로 집계된다.
- 10k connect/disconnect 사이클은 24h 런의 부수 결과로 기록만 한다(24h × 10세션/60s ≈ 14,400회로 자연히 넘는다). Linux ASAN/LSAN 통합 스위트 1회는 soak 시나리오 밖의 별도 1회 항목이다.

### Perf

- **Perf는 절대값이 아니라 비율로 게이트한다.** raw-quinn 기준 throughput을 같은 프로세스, 같은 실행에서 측정한 뒤 터널 ≥ 80%를 단언한다. runner와 무관하므로 CI에서 돌릴 수 있다. PTY p95 산식은 (client 수신 시각 − pty write 시각 − 측정된 loopback RTT) < 10ms다. 비율 throughput과 echo-under-load p95는 acceptance job에서 상시 게이트이고, 절대 throughput 추세는 `perf.yml`의 `perf` job이 쌓는다(공유 runner의 flake가 무시 습관을 만든다. 저장소와 임계는 CI 규율 절).
- **PR 게이트 금지 원칙과의 조정.** 일반 원칙은 perf를 PR 단위 테스트 스위트에 넣지 않는 것이다. 그런데 `docs/design/protocol.md` §12는 "포화 터널 + PTY echo p95 < 10ms"를 수용 기준으로 요구한다. 두 지표를 분리해 푼다. 비율 throughput(raw-quinn 대비 터널 ≥ 80%)은 같은 실행의 결정적 측정이라 runner flake에 노출되지 않으므로 acceptance job(`crates/qsh-testkit/tests/tunnel_throughput.rs`, `ci-ok`가 `needs`로 요구하는 job)에서 strict 게이트로 돈다. echo-under-load p95(`crates/qsh-testkit/tests/tunnel_echo_under_load.rs`)는 wall-clock 변동에 노출되므로 추세 기록에도 남기되 acceptance job에도 게이트 하나를 둔다. 둘 다 일반 `cargo nextest run` 스위트에는 넣지 않는다. L4의 "60초 DoD 이중 게이트"(`reverse_blackout.rs`, `QSH_ACCEPTANCE_SLOW` 하 acceptance job)와 같은 패턴이다.
- **PRD §13 "느린 파일·터널 stream이 PTY stream을 block하지 않아야 함"의 판정 근거.** v1에는 파일 전송 표면이 없어 대역 스트림 대체 하네스가 필요했는데, 새 하네스를 만들지 않고 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`(`crates/qsh-testkit/tests/tunnel_echo_under_load.rs`)를 근거로 삼는다. `-L` 터널은 PTY와 같은 연결에 지속적인 벌크를 얹을 수 있는 v1의 유일한 표면이고, `FloodServer`가 그 포워드를 host→client 방향으로 포화시키면 호스트의 송신 스케줄러가 `PRIORITY_TUNNEL`과 `PRIORITY_SESSION_DATA`를 중재하게 되므로 대체 하네스가 물을 것을 이미 묻는다. 이 테스트는 `ci.yml`의 `acceptance` job에서 `QSH_ACCEPTANCE_STRICT`로 상시 돈다. 테스트 모듈 doc이 같은 귀속을 적는다.
- **덮는 축은 포화(고속)와 기아(저속·역압) 둘이다.** 위 테스트는 포화 축을 잰다. 터널 피어가 읽지 않아 바이트를 flow control에 세워 두는 기아 축은 `crates/qsh-testkit/tests/tunnel_stalled_streams.rs`가 잰다. 한 연결 위에 PTY 세션과 읽지 않는 `-L` 소비자 N개를 올리고, client가 host의 `DATA_BLOCKED`나 스트림마다의 `STREAM_DATA_BLOCKED`를 관측한 뒤에만 측정을 시작한다. 단언은 넷이다.
  - N=4·8에서 PTY 출력이 10초 안에 200줄 더 진행한다(`pty_output_keeps_progressing_while_four_unread_tunnel_streams_stall`).
  - N=4에서 echo p95가 측정 RTT + 10ms 아래다(`pty_echo_p95_stays_within_measured_rtt_plus_10ms_while_four_unread_tunnel_streams_stall`).
  - 경계 N=3이 진행한다(`pty_output_keeps_progressing_with_three_unread_tunnel_streams`).
  - 하네스가 정체를 실제로 만들었다(`stalled_stream_harness_observes_data_blocked_before_measuring`, strict와 무관하게 단언).

  두 창 상수(2 MiB와 8 MiB)만으로는 이 축을 막지 못했다. 커밋 `209e764`가 N=4를 붉게 쟀고, 막는 것은 ADR-0037의 연결 단위 정체 장부다(`docs/design/protocol.md` §12). 장부의 단위 테스트는 `crates/qsh-core/src/tunnel/stall/tests.rs`와 `crates/qsh-core/src/tunnel/splice/tests.rs`의 `stalled` 모듈에 있다. 이 파일도 `acceptance` job에서 `QSH_ACCEPTANCE_STRICT`로 상시 돈다.
- **T2 적대적 부하(`crates/qsh-cli/tests/adversarial_load.rs`, ROADMAP M8 DoD 5).** acceptance job이 아니라 별도 워크플로 `.github/workflows/load.yml`을 쓴다. DoD 5가 재는 RSS(MB)·fd 개수·echo p95(ms)는 비율이 아닌 절대 수치이고, acceptance job은 `ci-ok`의 `needs`에 있어 PR 필수 경로이기 때문이다. `load.yml`은 push(main)·`workflow_dispatch`뿐인 회귀 감시자다.
  - idle listener RSS 30 MB는 `docs/PRD.md` §13의 "목표" 수치를 그대로 쓴 것이고, 재는 대상은 **release 빌드**의 `qsh serve`다. debug 바이너리는 이 수치가 겨냥한 대상이 아니라서 `load_bin()`은 `QSH_LOAD_BIN` 미설정을 조용히 넘기지 않고 패닉한다. 이 수치는 T2 이전에 실측된 적이 없으므로 실패 시 코드가 아니라 임계를 의심할 여지가 있고, 진단은 baseline·peak·idle 세 값을 항상 함께 남긴다.
  - 부하 중 상한(`30 MB + 8 MB × 살아 있는 세션 수`)의 8 MB는 `docs/PRD.md` §13의 세션당 기본 replay buffer 설정값에서 빌린 것이지 실측된 RSS 증분이 아니다.
  - echo 임계는 M4와 다르다. M4는 절대 10ms 고정이고 T2는 같은 실행 baseline p95의 3배 또는 50ms 중 큰 값이다. 부하가 협조적 포화 터널이 아니라 적대적 flood라 baseline 자체가 실행마다 달라질 수 있기 때문이다.
  - T1(`crates/qsh-testkit/tests/quota.rs`의 flood-survival 테스트)의 echo는 `PipeFactory` 기반 pipe echo이고, T2가 서브프로세스 `qsh serve`의 실제 PTY를 재는 PTY echo다.
  - RSS/fd 측정은 `/proc` 기반이라 Linux 전용이다. `/proc`이 없는 플랫폼(macOS)에서는 `QSH_LOAD_STRICT`가 아닌 한 그 시나리오가 skip이다.
- **musl 바이너리의 RSS 주장 범위.** `docs/PRD.md` §13의 idle 30 MB는 gnu 바이너리에만 주장한다. `x86_64-unknown-linux-musl` 빌드는 `tikv-jemallocator` 의존이 `target_env = "gnu"`로 좁혀져 시스템(musl) 할당자를 쓰고, 그 의존이 겨냥한 retention 자체가 glibc arena high-water라서 대상이 아니다. soak·적대적 부하 회차는 gnu 바이너리로만 돌고, musl 자산이 릴리스 전에 통과하는 것은 `release_smoke_covers_init_trust_exec_pty_detach_and_reattach`의 기능 네 축과 정적 링크 증거뿐이다. musl 바이너리의 idle RSS 수치가 필요해지면 별도 회차를 연다.

## CI 규율

- **환경 문제는 빠르고 분명하게 실패한다(재시도로 가리지 않는다):** 호스트 nftables 잔재(`udp dport 60000-61000 drop`, loopback 예외 없음)가 loopback UDP를 막아 `bind(0)` QUIC endpoint의 약 4.3%가 도달 불능이 되었고, 그 테스트들이 10초 타임아웃으로 죽으며 제품 flake처럼 보였다. 원인 규칙은 dave-environment c6c5359c가 제거했다. nextest `--retries`로 이런 실패를 덮지 않는다. 재시도는 원인 진단을 늦추고 환경 결함을 통과로 바꿔 버린다. 대신 `qsh-testkit`의 `env_check::ensure_loopback_udp`(프로세스당 한 번, 50ms 미만)가 하네스 생성자(`Listener::bind` 앞, `ServeGuard` spawn, raw endpoint)에서 ephemeral 범위와 60000-61000의 UDP 왕복을 확인하고, 막혔으면 막힌 포트와 예상 원인, 우회책을 담은 메시지로 즉시 panic한다. `qsh-core` 단위 테스트는 `qsh-testkit`에 의존할 수 없어(아키텍처 §1) 이 점검 밖이다. 우회책은 `scripts/test/nextest-ns.sh`로, `unshare -Urn`과 `lo` 기동, 안쪽 `unshare -U --map-user/--map-group`으로 전용 netns에서 비루트로 스위트를 돌린다(nft 테이블은 netns마다 별개). 같은 계열로 긴 `$TMPDIR`(약 100자 이상)는 unix socket 경로를 `sun_path` 108바이트 밖으로 밀어 약 120개 테스트를 `path must be shorter than SUN_LEN`으로 죽였다. `.config/nextest.toml`의 setup script `scripts/test/short-tmpdir.sh`가 `$TMPDIR`가 48바이트를 넘으면 `/tmp/qsh-t-<uid>`로 바꿔 준다.
- 모든 테스트는 port 0 바인딩, 테스트별 고유 tempdir.
- `sleep()` 금지 — `tokio::time::pause()` 또는 이벤트 통지 + `timeout`. T2의 RSS/fd 안정화(`crates/qsh-cli/tests/common/mod.rs`)는 폴링을 `tokio::time::sleep`으로 한다 — 고정 대기가 아니라 200ms 간격 *조건* 폴링(연속 3회 상대 변동 1% 미만을 안정으로 본다)이라는 점에서 이 규율이 금지하는 고정 대기와는 다르지만, 벽시계를 쓴다는 사실 자체는 남는다(4c 적대 검토 A13).
- Chaos는 seeded, 실패 시 seed를 단언 메시지에 출력.
- 타이밍 민감 테스트는 착지 전에 `scripts/stress/run.sh`로 CPU 부하 아래 50회 연속 초록이어야 한다. 근거는 `8fd4602`다. 유휴 머신에서는 초록이던 역방향 reset 관찰 경합이 부하 아래에서 80회 중 16회 실패했다. 이 반복은 공유 runner에서 재현성이 낮고 수십 분이 걸려 PR 게이트에는 넣지 않는다.
- `Swatinem/rust-cache`, concurrency group으로 구식 run 취소.
- 절대 throughput 추세는 `.github/workflows/perf.yml`의 `perf` job이 쌓는다. 저장소는 같은 저장소의 orphan 브랜치 `perf-data`이고 파일은 `perf.jsonl`이다. 회차마다 JSON 한 줄을 덧붙인다. 점 하나는 `at`, `sha`, `runner`, `throughput_mbps`, `raw_quinn_mbps`, `echo_p95_ms`, `rtt_ms`, `injected`를 싣는다. 보존은 최근 365점이다. 판정은 직전 7점의 중앙값과 견준다. throughput이 20% 이상 떨어지거나 echo p95가 50% 이상 오르면 job이 붉다. 인위적 지연을 주입한 회차(`injected: true`)의 점은 기록하되 중앙값 계산에서 뺀다. 주입이 아닌 점이 7개 미만이면 판정 없이 기록만 한다. 이 job은 PR 게이트가 아니고 `ci-ok`의 `needs`에도 없다. 판정기는 `cargo xtask perf-judge`(`xtask/src/perf.rs`)다. 공유 runner의 편차로 붉음이 잦으면 임계를 올리고 그 결정을 여기에 기록한다. 브랜치 보호 규칙이 `perf-data` push를 막으면 Actions artifact로 물러나고 그 사실도 여기에 적는다.
- GHA macOS runner는 UDP 소켓 버퍼 기본값이 작다 — `SO_RCVBUF`를 명시 설정하거나 throughput 수치 저하를 예상할 것.
- clippy는 **모든 타깃에서** 실행 — Linux 전용 clippy는 `cfg(target_os = "macos")` 블록 전체를 놓친다. 이 프로젝트처럼 플랫폼 분기가 많으면 실질적 구멍이다. Windows도 포함: 지원 플랫폼은 아니지만 `cfg(unix)`/`cfg(not(unix))` 분기가 계속 컴파일되는지는 CI만이 보증한다.
- 어느 테스트가 어느 위협을 갚고 있는지의 인덱스는 [threat-model.md](threat-model.md) §4가 canonical이다. 이 문서는 계층별로 무엇을 갚아야 하는지를 적고, 그쪽은 위협별로 무엇이 그것을 갚고 있는지를 적는다. 통제를 지키는 테스트의 이름이 바뀌면 그 표도 같은 커밋에서 바뀐다.
- `cargo-nextest` **필수**, `cargo test`는 게이트가 아니다: 테스트별 프로세스 격리(전역 상태를 바꾸는 PTY/termios 테스트에 필수), 실 timeout, flake 재시도, JUnit 출력이 이유의 절반이고, 나머지 절반은 이 repo의 실측이다 — `cargo test`는 전역 상태를 공유하는 동일 바이너리 실행 때문에 baseline부터 빨간불(`acl::load`·`localctl::daemon` 계열이 프로세스 안에서 서로 간섭)이고, CI(`.github/workflows/ci.yml`)도 nextest만 돈다. 커밋 전 게이트는 `TMPDIR=<격리 디렉터리> cargo nextest run --workspace`이며, `cargo test`로 빨간불이 뜨는 것은 회귀 신호가 아니다 — nextest로 같은 스위트를 돌려 실제로 깨졌는지 확인한다.
- macOS 서명·공증 축은 PR 게이트가 아니다. `release.yml`의 darwin 두 leg은 Apple 시크릿 여섯이 전부 설정됐을 때만 서명·공증 스텝을 돌리고(`steps.apple.outputs.has-apple`), 없으면 leg은 green인 채 서명 없이 지나간다 — `release.yml`에 `pull_request` 트리거가 없어 PR은 이 경로에 닿지도 않는다. 판정은 태그·dispatch run 로그로만 하고 문자열 셋이 근거다: `codesign -dv --verbose=4`의 `Authority=Developer ID Application`, 같은 출력의 `flags=…(runtime)`, `notarytool`의 `status=Accepted`. `codesign --verify --strict`만으로는 판정할 수 없다 — 지금 출고되는 ad-hoc linker-signed 바이너리에도 exit 0을 낸다(2026-09-25 실측). Gatekeeper 최종 판정은 `docs/campaigns/m10-clean-vm.md`의 사람 회차 몫이다.

**테스트 게이트 환경변수.**

| 변수 | 켜는 것 | 어디서 |
|---|---|---|
| `QSH_ACCEPTANCE_STRICT` | `tui_expect`의 대화형 셸 5종이 없을 때 skip이 아니라 실패, `tunnel_throughput`·`tunnel_echo_under_load`·`tunnel_stalled_streams`의 게이트 단언, `socks_curl`의 curl 없을 때 skip이 아니라 실패 | `ci.yml`의 `acceptance` job |
| `QSH_ACCEPTANCE_SLOW` | `reverse_blackout`의 실제 60초 차단 회차와, `qsh-core`의 `idle_timeout` 통합 테스트 둘(quinn idle 45초를 실제로 기다린다, L4), `supervised_dynamic_listener_stays_bound_through_a_50_second_blackhole_and_connects_after_it`의 실제 50초 차단 | `ci.yml`의 `acceptance` job |
| `QSH_ACCEPTANCE_LONG`·`QSH_BLACKOUT_SECS` | `reverse_blackout`의 30분 차단 회차와 그 회차의 길이(미설정이면 1800초) | `long.yml`의 dispatch 전용 job |
| `QSH_LOAD_STRICT`·`QSH_LOAD_BIN` | `adversarial_load`·`soak`의 절대 RSS/fd/echo 단언과 측정 대상 release 바이너리 | `load.yml` |
| `QSH_SMOKE_BIN`·`QSH_SMOKE_STRICT` | `release_smoke`가 구동할 `qsh` 바이너리와, 미지정 시 debug fallback 금지 | `release.yml`의 build job·`load.yml`(둘 다 `QSH_SMOKE_STRICT=1`로 설정한다); 미설정이면 PR 게이트가 debug 바이너리로 실행 |
| `QSH_SOAK_*`(`DURATION_SECS`·`SESSIONS`·`SAMPLE_SECS`·`CYCLE_SECS`·`CYCLE_FRACTION`·`ABANDON`·`RESUME_TTL_SECS`·`CSV`) | soak 시나리오의 길이·세션 수·CSV 경로 | `scripts/soak/run.sh` |
| `QSH_PERF_OUT` | `tunnel_throughput`와 `tunnel_echo_under_load`가 측정 뒤 JSON 한 줄(`test`, 지표, `inject_delay_ms`)을 이 경로에 덧붙인다. 미설정이면 아무것도 쓰지 않고 게이트 동작은 그대로다 | `perf.yml`의 `perf` job |
| `QSH_PERF_INJECT_DELAY_MS` | 두 perf 테스트의 loopback 경로에 고정 단방향 지연(ms)을 넣는다. 훅은 `qsh-testkit` 하네스에만 있고 제품 크레이트와 바이너리는 읽지 않는다. 0 이상이면 절대값 게이트 단언은 적용하지 않고 판정기가 추세로 판정한다 | `perf.yml`의 `workflow_dispatch` 입력 `inject_delay_ms` |
| `QSH_UPDATE_FIXTURES` | 값-보유 golden fixture 재생성, L6 | 로컬 |
| `QSH_TEST_PLATFORM_KEYSTORE` | OS 자격 증명 저장소를 실제로 건드리는 `#[ignore]` 테스트 | 로컬 |
| `BROKER_OPS_WRITE_SEEDS` | `broker_ops_corpus.rs`의 seed 재생성 | 로컬 |

**`#[ignore]` 테스트 3건.** 기본 실행에서는 돌지 않고 `--run-ignored`로만 돈다.

- `crates/qsh-core/src/identity/keystore.rs`의 `platform_store_round_trips` — 실 OS 자격 증명 저장소를 건드리기 때문에 opt-in이다.
- `crates/qsh-core/src/doctor/probe.rs`의 `probe_reports_unreachable_when_nothing_listens_on_the_port` — ICMP port-unreachable을 연결된 UDP 소켓에 전달하는 동작이 OS/샌드박스마다 달라서다.
- `crates/qsh-core/tests/broker_ops_corpus.rs`의 `regenerate_seeds` — `fuzz/corpus/broker_ops/*`에 쓰는 동작이라서다.

`docs/man/*.1`은 `xtask/src/man.rs`의 테스트 `checked_in_man_pages_match_the_generator`가 지킨다 — 체크인된 `.1` 집합과 바이트를 현재 clap 트리가 렌더한 결과와 비교한다. `xtask`가 워크스페이스 멤버라 `cargo nextest run --workspace`에 포함되고 별도 CI 단계는 없다. 실패하면 `cargo xtask man`으로 재생성해 같은 커밋에 넣는다.

**crates.io publish gate.** `ci.yml`의 `publish-dry-run` 잡이 `cargo publish --dry-run --workspace`를 한 번 돌려 공개 대상 넷(`qsh-proto`·`qsh-transport`·`qsh-core`·`qsh-cli`)의 tarball을 만들고 각각을 추출본에서 컴파일한다. `qsh-testkit`·`xtask`는 `publish = false`라 cargo가 스스로 건너뛴다. 크레이트별로 네 번 돌리지 않는 이유는 첫 실제 publish 전에는 `qsh-transport` 단독 dry-run이 "no matching package named `qsh-proto` found"로 실패하기 때문이다 — 발행 매니페스트가 path를 떼고 version만 남기므로 레지스트리에 없는 의존은 풀 수 없다. dry-run은 어느 크레이트가 열려 있는지는 고정하지 않으므로(닫혀 있어야 할 크레이트를 열어도 배치에 들어와 통과한다) 같은 잡의 `cargo metadata` 대조 스텝이 그 집합을 고정한다. 이 게이트가 잡지 못하는 것 둘은 `categories` 슬러그의 유효성과 `keywords` 개수 제한이다(둘 다 crates.io가 업로드 때 거부한다). 레지스트리 토큰은 필요 없다.

## CI 구성

`.github/workflows/ci.yml`이 push(main)/PR마다 돌고 단일 required check `ci-ok`로 합쳐진다.

- fmt, arch-lint, cargo-deny, doc-test와 `RUSTDOCFLAGS=-D warnings` doc을 돈다. test(nextest)는 ubuntu-24.04, ubuntu-24.04-arm, macos-14, windows-latest 네 runner에서, clippy는 ubuntu-24.04와 windows-latest에서 돈다. macos-15-intel 레그는 커버리지가 macos-14와 겹쳐 매트릭스에서 뺐다(`ci.yml` 매트릭스 상단 주석).
- Windows에서는 POSIX 시그널·process-group·`$$` 의존 테스트가 `cfg(unix)`로 빠지고, 나머지(`sh -c` 기반 DoD 테스트 포함)는 runner의 Git for Windows `sh`에 의존해 그대로 돈다.
- `acceptance` job이 인수 게이트를 strict로 돈다(아래 환경변수 표). `publish-dry-run` job은 위 publish gate다.
- `fuzz-smoke.yml`은 짧은 결정적 fuzz 스모크를 돌리고, 같은 job에서 `cargo deny --locked --manifest-path fuzz/Cargo.toml check advisories`도 돈다. `fuzz/Cargo.lock`이 워크스페이스 락과 별개라 `ci.yml`의 `deny` job이 보지 못하기 때문이다(licenses·bans는 켜지 않는다).
- `load.yml`은 push(main)와 dispatch에서 T2 적대적 부하(`adversarial_load`)와 짧은 soak(`cargo nextest run --profile load -p qsh-cli --test soak`)을 돌리고, `release_smoke`를 `QSH_SMOKE_STRICT=1`로 돌려 출고 바이너리의 기능 축을 본다.
- `release.yml`의 build job도 `release_smoke`를 strict로 돈다. darwin 두 leg은 Apple 시크릿이 있을 때 Developer ID 서명과 공증을 붙인다(위 CI 규율). release job은 `actions/attest-build-provenance`로 `dist/*` 전 자산(`SHA256SUMS` 포함)의 provenance attestation을 만든다. 태그 ref에서만 도는 릴리스 시점 산출물이고 PR 게이트가 아니며, 판정은 내려받은 자산에 대한 `gh attestation verify`다.
- `long.yml`의 `blackout` job(`workflow_dispatch` 전용)이 `docs/PRD.md` §13 "30분 단절 후에도 TTL 내 세션 복구"를 판정한다(위 L4 30분 회차).
- `perf.yml`의 `perf` job이 절대 throughput 추세를 쌓는다(위 CI 규율). 비율 게이트는 `acceptance` job이 상시 맡는다.
- 24h/100세션 soak은 CI job이 아니라 `docs/campaigns/m8-soak.md`의 사람 캠페인이다. nightly fuzz job은 없다.

## 계층별 보충 게이트

L6 이후 층에서 문서를 상수·생성기·등록부에 고정하는 게이트와 하네스를 모은다.

- **등록 완전성.** `crates/qsh-core/tests/acl_registry.rs`는 `OP_REGISTRY`와 CLI.md §2.5 매핑 표를 양방향으로 대조하고 `Server::dispatch`의 `control_message::Body` variant를 전수 분류하며 registry 항목의 DoD 2 audit 완전성을 구동한다. 항상-deny 3종(`forward.socks`·`file.read`·`file.write`)은 이 열거에서 빠진다. `file.read`/`file.write`는 구동할 wire op이 없고, `forward.socks`는 어떤 op도 구동하지 않는다(`-D`는 항상 `forward.local`로 인가되고 client가 붙이는 표지는 인가를 실을 수 없다, ADR-0019 결정 6). 나머지 인가 seam의 거부 문면 균일성은 `crates/qsh-testkit/tests/acl_uniformity.rs`가, `Server::dispatch`만으로 구동할 수 없는 `forward.local`·`forward.remote`·`host.reverse` 세 seam의 DoD 2는 `crates/qsh-testkit/tests/acl_registry_audit.rs`가 맡는다. `authorize_stream_has_exactly_two_production_call_sites`와 `action_variant_literals_are_pinned_to_the_one_documented_exception`은 소스텍스트 매칭 게이트다. 리팩터가 이런 게이트를 무증상으로 무력화하기 쉬우므로 호출 형태를 바꾸면 검출력이 남았는지 확인한다.
- **`Op` 타입.** `declare_ops!` 매크로 하나가 `Op`·`Op::as_str`·`Op::spec`·`OP_REGISTRY`를 같은 선언에서 뽑는다(`crates/qsh-core/src/acl/registry.rs`). 없는 variant는 이름을 쓰는 순간 컴파일이 안 되고 `Op::spec()`의 match에 wildcard arm이 없어 등록 없는 variant도 컴파일되지 않는다.
- **CLI 등록 두 겹.** `crates/qsh-core/tests/op_registration_completeness.rs`의 `section_2_4_fence_matches_every_implemented_operation_bidirectionally`가 CLI.md §2.4 펜스를 실제 구현된 모든 operation과 양방향으로 대조한다. `layer_2_every_schema_command_has_all_six_faces`는 `CLI_V1_SCHEMA_COMMANDS`의 각 항목이 여섯 얼굴(schemars 타입, `CLI_V1_SCHEMA_COMMANDS` 등록, main.rs dispatch, human 렌더러, CLI.md 행, man 항목)을 모두 갖췄는지 증명한다. JSON 렌더러는 여섯에 들지 않는다. 펜스(37종)와 `CLI_V1_SCHEMA_COMMANDS`(36종)의 차이는 `session.attach` 하나다. stream operation이라 schema 항목이 없다. `CLI_V1_SCHEMA_COMMANDS` 완전성은 `Operation` impl 전수와의 양방향 set-equality로 고정한다.
- **인증 경로.** `crates/qsh-core/tests/cert_e2e.rs`가 `qsh cert init`/`qsh cert issue`(§6.16, `crates/qsh-core/src/ca.rs`)가 만드는 self-signed root + device leaf 승격을 실 handshake로 검증한다. CA-vs-pin `auth_path` 분기는 ACL 판정과 audit 기록(`auth_path:"ca"`) 양쪽에서 load-bearing이며, pin 전용 규칙에 CA principal이 매칭하도록 뒤집으면 실패해야 한다. `trust.invite`/`trust.accept`(ADR-0002)는 channel binding(TLS exporter 변조 시 교환 실패)·상수시간 비교(`ct_eq`)·단일사용·secret 비영속을 mutation으로 검증한다. `hosts.toml`의 주소 우선순위(hosts.toml이 trust.toml을 덮되 신뢰는 trust.toml 단독 판정)는 실 QUIC 연결 테스트가 고정한다.
- **doctor.** `qsh doctor`(§6.17, `ops/doctor.rs` + `doctor/probe.rs`)의 findings 코드는 `EXPECTED_DOCTOR_CODES`(`crates/qsh-core/src/doctor.rs`) 동결 set-equality로 고정하고(현재 24종), CLI.md §6.11·§6.17의 계수 산문은 `cli_md_prose_doctor_code_count_matches_expected_len`이 고정한다. golden fixture는 환경 의존이라 byte-freeze하지 않는다(`schema.get`과 같은 이유). 시각 임계값 세 곳의 경계와 `classify_io_error`의 errno 분류는 유닛 테스트다. CLI.md에 축자 인용된 진단 문면은 `doctor_docs.rs` 계열이 지키고, README는 서사 산문이라 축자 인용 대상에서 뺀다. 이 외에 `-R` accept의 터널 스트림 permit과 `config_unknown_key`가 in-process/서브프로세스 양쪽 강제 테스트를 갖는다.
- **문서-상수 일치.** `crates/qsh-core/tests/acl_docs.rs`는 `Action::ALL`·`PERMISSION_DENIED_MESSAGE`·시작 진단 문면이 PRD·CLI.md·README와 어긋나지 않는지 본다. `crates/qsh-core/tests/quota_docs.rs`는 CLI.md §6.12의 audit 부피 상계 문장(`[audit].max_bytes × (retain + 1)`)을 `AuditConfig::default()`와 대조한다. `crates/qsh-core/tests/service_docs.rs`는 `docs/deploy/service.md`의 여섯 펜스를 생성기 출력과 바이트 단위로 대조한다. 상수가 아니라 생성기가 만든 파일에 맞춰 손으로 쓴 산문을 고정하는 게이트다.
- **문면 규율.** `crates/qsh-core/tests/failure_text_discipline.rs`는 `cli_md_section_6_11_quotes_the_address_port_assumed_notice_verbatim`, `cli_md_section_6_13_quotes_the_bind_unavailable_remedy_verbatim`, `readme_known_limitations_quotes_the_bind_unavailable_remedy_verbatim`, `no_pairing_pin_notice_constant_still_says_asked_for_itself`, `each_failure_wording_has_observation_impact_and_next_command`, `host_not_found_split_has_observation_impact_and_next_command`로 실패 문면이 관찰·영향·다음 명령을 갖추고 문서 인용과 일치함을 고정한다.
- **`-D`(ADR-0019, ADR-0020).** `crates/qsh-cli/tests/dynamic_forward.rs`가 실패 경로(비-loopback bind, 잘못된 handshake)와 역방향 route의 왕복 성공(ADR-0020 결정 1)을 CLI 블랙박스로 고정한다. `crates/qsh-testkit/tests/dynamic_loopback.rs`는 정방향 route에서 실제 비-loopback 목적지로 SOCKS5 CONNECT 왕복을 구동한다. `qsh_testkit::net_probe`가 못 찾는 라우트는 로컬에서는 사유와 함께 skip하지만 CI에서는 실패로 다룬다(`net_probe::Gap`). `crates/qsh-testkit/tests/dynamic_reverse.rs`는 같은 왕복을 역방향 route(`ReverseHarness`)로 반복해 ADR-0020 결정 1(daemon을 거친 `deny_host_local` 통과)과 결정 3(대화형 `-L`의 역방향 왕복)을 고정한다: `dash_d_over_reverse_reaches_a_non_loopback_echo`, `dash_d_over_reverse_filters_loopback_and_the_target_sees_no_accept`, `interactive_dash_l_over_reverse_round_trips_at_the_ops_level`, `discovery_fails_closed_on_a_shared_runtime_dir_but_resolves_cleanly_once_isolated`. capability(`dial-filter.v1`) 부재 거절은 이 코드베이스에 capability를 뺀 실 peer가 없어 블랙박스로 구동할 수 없으므로 `crates/qsh-core/src/ops/tunnel/tests.rs`의 유닛 테스트 둘이 두 route에서 고정한다(ADR-0019 결정 3): `tunnel_dynamic_without_dial_filter_capability_is_unsupported_and_binds_nothing`, `tunnel_dynamic_over_reverse_without_dial_filter_capability_is_unsupported_and_binds_nothing`. `crates/qsh-cli/tests/socks_curl.rs`는 실 `curl`로 acceptance job에서 `-D`를 인수 테스트로 닫는다. L8의 `parse_socks5` 타깃이 sans-IO 파서 짝이다.
- **L6 fixture 마스크.** `crates/qsh-testkit/src/fixtures.rs`의 `normalize`는 `"manager"`(host OS의 서비스 매니저 `launchd`/`systemd`라 플랫폼마다 값이 다르므로 `config_dir`처럼 모양만 고정, `docs/CLI.md` §6.18)와 `"cert_pem"`(leaf PEM이 샌드박스 실행마다 새 키·일련번호로 재생성, ADR-0013)을 가린다. 각각 `normalize_masks_the_manager_field_to_its_shape`와 `normalize_replaces_volatile_fields_only`가 고정한다.
- **`capabilities.json`.** 값-보유 golden이라 `QSH_UPDATE_FIXTURES=1`로만 재생성하고 diff를 계약 변경 무게로 리뷰한다. 그 밖의 기존 fixture는 고치지 않는다. `REQUIRED_FIXTURES`(`crates/qsh-cli/tests/fixtures.rs`)가 필수 목록이다.
- **man 페이지.** 위 `checked_in_man_pages_match_the_generator`가 `docs/man/*.1` 전부(현재 51종)를 지킨다. 새 명령을 더하면 별도 게이트 없이 이 테스트가 재생성을 요구한다.
- **adversarial_load.** T2 시나리오는 `fleet_boot_reports_rss_and_fd_above_the_floor` 등 6개이고 감사 부피 시나리오는 집계·회전·보존으로 나뉜다. 회전 실패 fail-closed 시나리오는 넣지 않았다. `chmod 500`으로 디렉터리 쓰기 권한만 없애는 구성에서는 `audit/writer.rs`의 `rotate()`가 rename 실패를 의도적으로 non-fatal로 다뤄 이미 열린 파일 핸들로 계속 append하므로 degraded 래치에 닿지 않는다. 필수 판정은 in-crate fail-closed 유닛 테스트가 맡는다. 반복 세션 open/attach/close는 `Server::MAX_PENDING_TICKETS_PER_CONN`(32, 감사 상태와 무관한 커넥션당 티켓 상한)에 먼저 걸린다. 큰 N의 수동 실측은 `docs/campaigns/m8-adversarial-load.md`가 담당한다(M2 mobility 캠페인과 같은 지위).
- **testkit 하네스.** `crates/qsh-testkit`에는 chaos proxy(`chaos.rs`, L4), loopback 하네스(`loopback.rs`, L3), 역방향 하네스(`reverse.rs`, `ReverseHarness`)가 있다. 그 위에 attach recovery 스위트(`crates/qsh-cli/tests/attach_recovery.rs`)와 역방향 resume 게이트 둘(`reverse_resume_chaos.rs` PR 상시, `reverse_blackout.rs` 60초 수용, L4)이 선다. L2의 정책 평가기 property test(`crates/qsh-core/src/acl/policy/`)는 default-deny·wildcard·principal 정확 일치를, audit 수명주기 테스트(`crates/qsh-core/src/audit/writer.rs`)는 회전·retention·쓰기 실패 fail-closed를 본다.
- **nextest baseline.** `cargo test`는 전역 상태 간섭으로 baseline부터 빨간불이라 게이트가 아니다(위 CI 규율). 통과 수는 실행 시점마다 달라 이 문서에 고정하지 않는다.
