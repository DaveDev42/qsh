# ADR-0041: 역방향 등록 연결의 PathWatch 감지 예산을 대화형 attach의 2초 상한에서 분리하고 기본 창을 약 5초로 둔다

날짜: 2026-10-05
상태: 승인됨 (2026-10-06 사용자 확정, 이슈 #10·#11)

개정 관계: ADR-0021을 개정한다. 대상은 두 자리다. 하나는 결과 절에서 `[recovery]` 세 값의 범위를 세 회귀 테스트(`attach_recovery.rs`·`reverse_blackout.rs`·`reverse_resume_chaos.rs`)의 `detection_budget` 상한 아래로 잡으라고 한 문장이다. 이 상한은 연결 종류별 둘(attach 2000ms, 역방향 등록 5000ms)이 된다. 다른 하나는 결정 4가 못박은 기본값(250ms·1초·3)과 "설정이 없으면 오늘과 바이트 단위로 같은 동작"이다. 이 두 문장은 대화형 attach와 supervised 터널에는 그대로 서고 역방향 등록 연결에는 서지 않는다. 역방향 등록의 기본 감지가 4.25초로 바뀐다. 결정 4의 나머지(세 값만 연다, 검증은 결정 1과 같은 fail-closed 규율)와 결정 7은 건드리지 않는다. `docs/design/protocol.md` §10의 `[recovery]` 서술과 §11-4 항목 4의 "양쪽 role에서 같은 정책을 재사용한다"가 이 ADR로 바뀌는 자리다. ADR-0023 결정 17(wake 뒤 감지)은 attach 기본값 기준 서술이라 그대로 선다. `docs/ROADMAP.md` M13 범위 (k)의 "설정이 없을 때 동작이 오늘과 같다"는 이제 역방향 등록에는 해당하지 않는다. 그 문구와 `PLAN.md` 배치는 메인 세션이 맞춘다.

## 맥락

GitHub 이슈 #10은 0.4.0을 양 끝에 올린 현장에서 역방향 등록이 중간 길이로 반복해서 끊긴다고 보고했다. 이 ADR의 입력은 그 이슈 본문과 2026-10-04T14:48Z 코멘트, 2026-10-05 코멘트, 그리고 이슈 #11이다. 이슈 #10의 요청은 셋이다. 끊긴 사유를 진단 줄에서 읽게 해 달라는 것(`cause`, 구현됨), 역방향 등록의 감지를 더 느슨하게 해 달라는 것, `lost` 줄에 RTT와 침묵 시간을 싣는 것(구현됨)이다. 이 ADR은 둘째만 다룬다.

첫 번째 관측(이슈 #10 본문과 첫 코멘트)은 이렇다.

- 본문 집계는 `lost` 282건이고 `cause`별로 `path_dead` 223, `peer_closed` 55, `local` 4, `idle_timeout` 0이다. `registered`에서 `lost`까지의 중앙값은 10.2초다.
- 코멘트의 양 끝 합계는 laptop이 `path_dead` 316, `peer_closed` 69, `local` 19, `idle_timeout` 0이고 hub가 `path_dead` 429, `peer_closed` 1, `local` 6, `idle_timeout` 0이다.
- `path_dead` 판정이 내려질 때까지 hub 쪽 패킷이 100~300ms마다 계속 도착했다.

이 원인의 한 갈래는 감시가 control 스트림의 `Pong`만 응답으로 세어서, 순서가 있는 그 스트림이 손실 복구에 묶이면 패킷이 계속 도착해도 3-strike가 약 1초에 쌓이던 것이다. v0.4.1의 커밋 `54ce47d`가 고쳤다. 수신된 UDP datagram도 응답으로 센다(`docs/design/protocol.md` §10). 회귀는 `datagram_liveness_controller_control_stall_is_not_path_dead_but_a_sever_is`와 `crates/qsh-core/src/client/pathwatch/tests.rs`의 `a_moving_datagram_counter_keeps_the_path_alive_without_control_replies`, `a_frozen_datagram_counter_without_replies_is_dead_on_the_existing_schedule`가 지킨다.

남은 갈래는 경로가 실제로 조용한 구간이다. 이것은 오탐이 아니라 설계된 판정이다. 이 ADR의 초안은 여기서 기본값을 그대로 두고 현장 데이터를 기다리기로 했다(옛 결정 1과 5). 그 데이터가 이제 있다.

두 번째 관측(이슈 #10의 2026-10-05 코멘트)은 원인을 laptop의 Wi-Fi 업링크로 좁혔다. 양 끝에서 20분 동안 잡은 캡처에서 laptop에서 hub로 가는 reverse 흐름은 11,492개 중 13.0%를 잃었고 hub에서 laptop으로는 8,253개 중 0.13%를 잃었다. 업링크 손실 구간(burst) 중 가장 긴 것은 3.6초, 2.6초, 2.1초였고 reverse 흐름에서만 약 800개였다. NAT 재바인딩은 없었다. 깨끗한 네트워크로 옮기자 손실이 사라졌고 이후 16시간 동안 역방향 손실은 한 번(망 전환 때)뿐이었다. 보고자의 요청은 이렇다. 2~4초 업링크 정전 동안 hub는 laptop에서 아무것도 못 받고, 1초 `min_dead_after`로는 링크가 1~2초 뒤 돌아와도 등록을 끊는다. 역방향 등록의 기본을 약 5초로 두면 이 캡처의 모든 burst를 견딘다. 진짜 정전의 감지는 몇 초 늦어지고, 등록 위의 터널은 흔한 경우에 산다.

세 번째 관측(이슈 #11)은 네트워크 손실이 없는 경우다. 부하 평균이 50~84인 macOS laptop에서 Wi-Fi와 5G 라우터는 정상이었는데 16시간 유지되던 등록이 hub의 `path_dead` 판정으로 끊겼고, 이어진 등록 셋도 같은 식으로 끊겨 안정될 때까지 약 4.5분이 걸렸다. 같은 호스트에서 `sleep 1`을 다섯 번 도는 쉘 루프가 49~84초를 쟀다. 짧은 프로세스가 스케줄링되는 데 초 단위가 걸렸다는 뜻이다.

2초 상한은 대화형 attach의 사정에서 나왔다. 사용자가 터미널 앞에서 기다리므로 사망 감지 뒤 재dial과 resume이 2초 안에 끝나야 하고(`docs/design/testing.md` L4의 통과 기준), 세 회귀 테스트는 감지 시간도 같은 2초(`REDIAL_DEADLINE_MS`)를 넘지 못하게 묶는다. 역방향 등록은 사정이 다르다.

- 등록 연결이 끊기면 그 위의 역방향 터널이 모두 재생 없이 끝난다. 끊김 한 번의 비용이 attach 재접속 한 번보다 크다.
- 사람이 그 순간 터미널 앞에서 기다리지 않는다. 복구 예산은 감지보다 target의 `backoff_max_ms`(기본 30초)가 지배한다. `reverse_blackout.rs`의 `recovery_budget`은 `BLACKOUT + DIAL_TIMEOUT + detection_budget + backoff_max + REDIAL_DEADLINE + SCHEDULING_SLACK`이고 감지는 그 합의 작은 항이다.
- 같은 등록을 target과 controller 두 쪽이 따로 감시한다(`docs/design/protocol.md` §11-4 항목 4). 한쪽이 느슨해도 상대가 기본값이면 상대가 `CLOSE_CODE_PATH_DEAD`로 연결을 끊는다. 새 기본은 양 끝에 같은 값으로 들어가야 효과가 있다.

## 결정

1. 대화형 attach와 supervised 터널의 기본값은 그대로다. `probe_interval` 250ms, `min_dead_after` 1초, `strikes` 3이고 상한 `RECOVERY_DETECTION_CEILING_MS`는 2000ms다. `[recovery].min_dead_after_ms`와 `[recovery].strikes`는 이 둘에만 적용한다. 설정이 없는 attach는 오늘과 바이트 단위로 같은 동작이다(`PathWatchConfig`의 Debug 출력을 구현 테스트가 고정한다).

2. 역방향 등록 연결의 기본을 `probe_interval` 250ms, `min_dead_after` 4250ms, `strikes` 3으로 한다. 이 연결은 두 곳에서 감시되고 두 곳이 같은 기본을 쓴다. target의 `qsh serve --to`(`qsh reverse`)가 dial한 연결의 watch와 controller의 `qsh listen`이 받은 등록 연결의 watch다. `P×S+D`는 250×3+4250=5000ms로 결정 4의 상한과 같다. 숫자는 이렇게 골랐다.
   - 관측한 최장 burst가 3.6초다. watch는 매 tick(250ms)마다 datagram 수신 카운터를 표본하므로 도착이 tick 경계 직후에 있었다면 침묵을 최대 한 tick 길게 본다(`DeadVerdict::silence` 문서). 3.6초+250ms=3.85초가 판정에 닿지 않아야 하고, 4250ms는 거기에 0.4초의 여유를 둔다.
   - cadence(250ms)와 strike 수(3)는 일반 기본과 같게 두고 `min_dead_after`만 움직여 예산을 상한까지 쓴다. 침묵이 cadence를 넘으면 probe는 tick마다 나가므로 `min_dead_after` 안에 열여섯 번 넘게 나간다. 이 구간에서 판정을 좌우하는 것은 `min_dead_after`이고 `strikes`는 예산 식의 항으로 남는다.
   - 약 5초는 이슈 #10의 요청이다. 그보다 느슨하게 잡으면 죽은 등록이 `stale`로 표시되기까지 늦어지는 비용이 커지고, 요청이 그 위를 요구한 근거도 없다.

3. 역방향 등록 연결 전용 재정의 키 둘을 `[recovery]` 안에 둔다. 이름은 `reverse_min_dead_after_ms`와 `reverse_strikes`다. 각 프로세스가 자기 `config.toml`에서 읽고 자기 쪽 watch에만 적용하므로 target과 controller는 따로 조정된다. `probe_interval_ms`는 재정의하지 않는다. cadence는 두 연결 종류가 같은 키를 공유한다. 일반 `min_dead_after_ms`와 `strikes`는 역방향 등록에 닿지 않는다. 키가 없으면 역방향 등록은 일반 값이 아니라 결정 2의 기본을 쓴다. 이유는 대안 절에 있다.

4. 새 상한 `REVERSE_DETECTION_CEILING_MS`를 5000으로 둔다. 역방향 등록 연결의 `probe_interval × reverse_strikes + reverse_min_dead_after`는 5000ms 이하여야 하고 `reverse_strikes ≥ 2`, `50ms ≤ probe_interval ≤ reverse_min_dead_after`다. 곱과 합은 checked 산술이라 큰 값이 감겨 통과하지 못한다. 범위를 벗어난 값은 clamp하지 않고 소켓을 만들기 전에 `CONFIG_ERROR`(`retryable: false`)로 기동을 거절한다. `ReverseConfig::backoff`와 같은 fail-closed 규율이다. 기본값이 상한에 닿아 있으므로 `reverse_strikes`만 올리거나 `reverse_min_dead_after_ms`만 올리면 상한을 넘어 거절된다. 둘을 함께 맞춰야 한다. 공유 `probe_interval_ms`를 250보다 올려도 같다. 오류 메시지는 어느 키가 상한을 넘겼는지 적는다.

5. `reverse_blackout.rs`와 `reverse_resume_chaos.rs`의 `detection_budget` 상한은 역방향 등록 쪽을 5000ms로 올린다. `attach_recovery.rs`의 2000ms는 그대로다. 두 역방향 테스트는 실제로 쓰이는 역방향 watch 설정에서 예산을 계산하고 복구 예산(`recovery_budget` 등)에 그 값을 넣는다. 상한을 올리는 변경이 테스트 자신을 올려서 통과하는 모양이 되지 않도록, 테스트는 설정 값이나 `REVERSE_DETECTION_CEILING_MS`를 읽지 않고 상수 두 개(2000, 5000)를 각자 리터럴로 본다.

6. 문서와 진단은 구현 커밋과 같은 커밋에서 바꾼다. `docs/design/protocol.md` §10의 `[recovery]` 서술과 §11-4 항목 4, `docs/design/architecture.md` §7의 키 나열, `docs/CLI.md` §6.4·§6.12·§6.13의 키 서술과 상태 헤더를 고친다. `qsh doctor`의 `config_unknown_key`는 `Config`가 직렬화하는 리프 경로에서 known set을 만들므로(`collect_leaf_paths`) 두 키를 `Config`에 더하면 진단 어휘가 따라온다. wire, `.proto`, `qsh.cli/v1`, `ErrorCode`는 바뀌지 않는다.

7. 새 기본이 현장에서 맞는지는 같은 토폴로지의 기록으로 본다. 판단에 쓰는 기록은 사람이 이슈 #10이나 캠페인 문서에 남긴 `lost`/`retry` 줄 분포다. 3.85초를 넘는 정체가 `path_dead`로 계속 나오면 그 호스트는 `reverse_*` 키로 푼다. 5000ms 상한을 넘기는 변경은 새 ADR로 연다.

이 ADR은 이슈 #11의 나머지 요청을 결정하지 않는다. 자기 프로세스의 tick 간격이 벌어졌는지 보고 침묵 계산을 다시 시작하는 안(요청 2), `cause=local`의 문서화(요청 3), 빠른 `path_dead`가 반복될 때 재등록 사이의 backoff(요청 4)는 따로 다룬다.

## 근거

- **현장 데이터가 생겼다.** 옛 초안이 기본값 변경을 미룬 이유는 `54ce47d` 전의 숫자로 기본값을 움직이는 것을 피하려는 것이었다. 이슈 #10의 2026-10-05 코멘트는 `54ce47d`가 겨냥한 오탐과 별개인 실제 2~4초 업링크 정전을 재고, 사용자가 약 5초 기본을 승인했다(2026-10-06).
- **attach의 2초는 attach의 근거다.** 2초 상한은 사용자가 기다리는 재접속에서 나왔고 역방향 등록에는 그 근거가 닿지 않는다. 복구 예산이 backoff에 지배되는 연결에 같은 상한을 거는 것이 이슈 #10의 불만과 맞물린 지점이다.
- **ADR-0021을 최소로 고친다.** 결정 4의 세 값만 연다는 범위와 검증 규율은 그대로고, 역방향 등록의 기본과 상한이 연결 종류별로 갈린다. attach의 기본·상한·설정 없을 때의 바이트 동일성은 그대로다.
- **회귀 테스트의 의미가 남는다.** 세 테스트가 지키는 성질은 "느슨한 설정이 자기 허용치를 스스로 올리지 못한다"이다. 연결 종류마다 상수를 따로 두면(결정 5) 그 성질이 유지된다.

## 대안

- **기본값은 두고 손잡이만 연다(이 ADR의 초안).** 기각한다. 사용자가 역방향 등록의 기본을 약 5초로 승인했고, 기본이 1초면 운영자가 양 끝 모든 호스트에 키를 적어야 일반적인 Wi-Fi 정체를 넘긴다.
- **일반 `min_dead_after_ms`·`strikes`가 `reverse_*` 키가 없을 때 역방향에도 닿게 한다.** 기각한다. attach 감지를 빠르게 조여 둔 운영자가 모르는 사이에 역방향 등록의 기본을 1초 안팎으로 되돌리게 되고, 이슈 #10의 불만이 정확히 그 값이다. 두 연결 종류는 같은 값을 원할 이유가 없으므로 각자의 키로만 움직인다.
- **역방향 전용 cadence 키(`reverse_probe_interval_ms`)를 둔다.** 기각한다. cadence는 감지 판정 시간이 아니라 탐지 해상도이고 두 연결 종류가 같게 둘 이유가 충분하다. 필요가 생기면 additive로 더한다.
- **역할 절(`[reverse]`·`[listen]`)에 감지 키를 둔다.** ADR-0021이 이미 기각했다. 같은 이유로 기각한다. 감지 정책은 watch하는 쪽의 것이고 역할에 묶이지 않는다. 이 ADR의 키는 `[recovery]` 안에 남고 이름 접두만 다르다.
- **상한을 일반 `[recovery]`에서 5초로 통째로 올린다.** 기각한다. 대화형 attach의 2초 약속(`docs/design/testing.md` L4)이 설정 하나로 깨진다. 결정 4가 연결 종류별로 상한을 가르는 이유다.
- **상한을 5초보다 높게 잡는다.** 기각한다. 요청이 그 위를 요구한 근거가 없다. 이슈 #11의 굶주린 호스트는 쉘 루프 측정으로 1초 sleep당 10초 넘게 밀렸으므로 5초를 넘는 값을 설정으로 푸는 쪽이 아니라 정체를 진단하는 쪽(위 요청 2)에서 풀 문제다.
- **감지 대신 keep-alive나 idle timeout을 조정한다.** 기각한다. idle timeout은 ADR-0021 결정 2·3이 고정했고, keep-alive는 송신 cadence라서 감지 판정 시간과 무관하다.

## 결과

- 역방향 등록 연결의 기본 감지가 1초에서 4.25초가 된다. `[recovery]`에 선택 키 둘이 더해진다. 둘 다 optional이다.

  | 키 | 기본 | 범위 | 적용 대상 |
  |---|---|---|---|
  | `[recovery].reverse_min_dead_after_ms` | 4250 | 결정 4 | 역방향 등록 연결의 `PathWatch` 둘(target, controller) |
  | `[recovery].reverse_strikes` | 3 | 결정 4 | 같음 |

  `[recovery].probe_interval_ms`는 attach와 역방향 등록이 공유한다. `min_dead_after_ms`와 `strikes`는 attach와 supervised 터널에만 적용한다.
- 구현은 `PathWatchConfig::reverse_default()`, `RecoverySection::reverse_path_watch()`, `Liveness::reverse_watch`, `REVERSE_DETECTION_CEILING_MS`다. 두 reverse watch(`reverse::target::run_reverse_unix`, `reverse::listen::Listen`)가 그 값을 읽고, 값을 주지 않은 `Listen`(테스트, 임베딩)의 기본도 같은 `reverse_default()`다.
- 새 기본은 양 끝에 같은 빌드가 들어가야 효과가 있다. 상대가 이전 빌드면 상대의 1초 watch가 먼저 연결을 끊는다. 한쪽만 키로 느슨하게 한 배포도 같다. `docs/CLI.md` §6.12·§6.13에 이 문장을 적는다.
- ADR-0021 결과 절의 상한 문장이 "연결 종류별 상한"으로 바뀐다. `crates/qsh-cli/tests/reverse_blackout.rs`와 `crates/qsh-testkit/tests/reverse_resume_chaos.rs`는 역방향 등록의 상한을 5000ms로 보고 실제 역방향 watch 설정에서 감지 예산을 계산한다. `crates/qsh-cli/tests/attach_recovery.rs`는 2000ms로 남는다.
- 진짜로 죽은 등록이 `stale`로 표시되고 target이 재dial하기까지가 약 3.25초 늦어진다(1초에서 4.25초). 역방향 route 위의 attach가 재등록을 기다리기 시작하는 시점도 그만큼 늦다. 재등록 시점부터 resume 완료까지 2초라는 약속은 그대로다.
- 설정이 없을 때의 `PathWatchConfig` Debug 출력은 attach 쪽이 오늘과 같다. 이 불변을 구현 테스트가 byte 단위로 고정한다. 역방향 등록의 기본은 새 값이고 그 값도 테스트가 고정한다.
- `docs/ROADMAP.md`와 `PLAN.md`의 배치는 메인 세션이 정한다.
- 잔여 위험은 셋이다. 느슨한 감지는 진짜로 죽은 등록의 `stale` 표시를 늦춘다. 새 기본은 상한에 닿아 있어서 한 키만 올리면 `CONFIG_ERROR`가 난다. 그리고 호스트 자체가 5초 넘게 멈추는 경우(이슈 #11)는 이 기본으로 풀리지 않는다. 복호화 전에 세는 datagram 카운터가 가짜 datagram으로 감지를 지연시킬 수 있는 위험(`docs/design/threat-model.md` §4 G7)은 창이 길어져도 달라지지 않는다.
