# ADR-0041: 역방향 등록 연결의 PathWatch 감지 예산을 대화형 attach의 2초 상한에서 분리한다

날짜: 2026-10-05
상태: 제안됨

개정 관계: ADR-0021을 개정한다. 대상은 결과 절에서 `[recovery]` 세 값의 범위를 세 회귀 테스트(`attach_recovery.rs`·`reverse_blackout.rs`·`reverse_resume_chaos.rs`)의 `detection_budget` 상한 아래로 잡으라고 한 문장 하나다. 결정 4의 기본값(250ms·1초·3)과 "설정이 없으면 오늘과 바이트 단위로 같은 동작"은 건드리지 않는다. `docs/design/protocol.md` §10과 §11-4 항목 4의 "양쪽 role에서 같은 정책을 재사용한다"가 이 ADR이 승인되면 바뀌는 자리다. ADR-0023 결정 17(wake 뒤 감지)은 기본값 기준 서술이라 그대로 선다. 승인 전에는 아무 코드도 바뀌지 않는다.

## 맥락

GitHub 이슈 #10은 0.4.0을 양 끝에 올린 현장에서 역방향 등록이 중간 길이로 반복해서 끊긴다고 보고했다. 이 ADR의 입력은 이슈 본문과 2026-10-04T14:48Z 코멘트에 적힌 사람의 기록이다. 요청은 셋이다. 첫째는 끊긴 사유를 진단 줄에서 읽게 해 달라는 것, 둘째는 역방향 등록의 감지를 더 느슨하게(3~5초 허용) 해 달라는 것, 셋째는 `lost` 줄에 RTT와 침묵 시간을 싣는 것이다. 이 ADR은 둘째만 다룬다.

관측은 이렇다.

- 본문 집계는 `lost` 282건이고 `cause`별로 `path_dead` 223, `peer_closed` 55, `local` 4, `idle_timeout` 0이다. `registered`에서 `lost`까지의 중앙값은 10.2초다. 이슈 제목의 "~30초"와 다르다.
- 코멘트의 양 끝 합계는 laptop이 `path_dead` 316, `peer_closed` 69, `local` 19, `idle_timeout` 0이고 hub가 `path_dead` 429, `peer_closed` 1, `local` 6, `idle_timeout` 0이다.
- 코멘트는 `path_dead` 판정이 내려질 때까지 hub 쪽 패킷이 100~300ms마다 계속 도착했다고 적는다. 본문 캡처에는 1~2초짜리 무패킷 구간이 몇 개 있다는 말도 있다.
- 모든 손실이 `PathWatch` 판정이고 `idle_timeout`은 0건이다. 그래서 ADR-0021 결정 4가 겨냥한 타이머가 맞다.

코드로 확인한 원인은 둘로 갈린다.

1. 감시가 control 스트림의 `Pong`만 응답으로 세어서, 순서가 있는 그 스트림이 손실 복구에 묶이면 패킷이 계속 도착해도 3-strike가 약 1초에 쌓였다. 이것은 v0.4.1의 커밋 `54ce47d`가 고쳤다. 수신된 UDP datagram도 응답으로 세고(`docs/design/protocol.md` §10), 회귀는 `datagram_liveness_controller_control_stall_is_not_path_dead_but_a_sever_is`와 `crates/qsh-core/src/client/pathwatch/tests.rs`의 `a_moving_datagram_counter_keeps_the_path_alive_without_control_replies`, `a_frozen_datagram_counter_without_replies_is_dead_on_the_existing_schedule`가 지킨다.
2. 경로가 실제로 1초 넘게 조용한 구간은 `54ce47d` 뒤에도 `min_dead_after`(1초) 안에 `Dead`가 난다. 이것은 오탐이 아니라 설계된 판정이다. 1~2초짜리 실제 무패킷 구간을 견디려면 감지 예산을 늘려야 하고, 요청 둘째가 이 부분이다.

예산을 늘리는 길은 오늘 두 겹으로 막혀 있다.

- ADR-0021 결정 4가 기본값을 250ms·1초·3으로 고정하고 ROADMAP M13 범위 (k)가 "설정이 없을 때 동작이 오늘과 같다"를 요구한다. 기본값을 바꾸는 안은 이 두 문장과 충돌한다.
- ADR-0021 결과 절은 `[recovery]` 세 값의 상한을 세 테스트의 감지 상한(`REDIAL_DEADLINE_MS` 2000)에서 역산하라고 한다. `probe_interval × strikes + min_dead_after ≤ 2000ms`에 `strikes ≥ 2`, `probe_interval ≥ 50ms`, `probe_interval ≤ min_dead_after`를 더하면 `min_dead_after_ms`는 최대 1900ms다. 이 한도 안에서는 3~5초 허용을 설정으로도 만들 수 없다.

2초 상한은 대화형 attach의 사정에서 나왔다. 사용자가 터미널 앞에서 기다리므로 사망 감지 뒤 재dial과 resume이 2초 안에 끝나야 하고(`docs/design/testing.md` L4의 통과 기준), 세 회귀 테스트는 감지 시간도 같은 2초(`REDIAL_DEADLINE_MS`)를 넘지 못하게 묶는다. 역방향 등록은 사정이 다르다.

- 등록 연결이 끊기면 그 위의 역방향 터널이 모두 재생 없이 끝난다. 끊김 한 번의 비용이 attach 재접속 한 번보다 크다.
- 사람이 그 순간 터미널 앞에서 기다리지 않는다. 복구 예산은 감지보다 target의 `backoff_max_ms`(기본 30초)가 지배한다. `reverse_blackout.rs`의 `recovery_budget`은 `BLACKOUT + DIAL_TIMEOUT + detection_budget + backoff_max + REDIAL_DEADLINE + SCHEDULING_SLACK`이고 감지는 그 합의 작은 항이다.
- 같은 등록을 target과 controller 두 쪽이 따로 감시한다(`docs/design/protocol.md` §11-4 항목 4). 한쪽이 느슨해도 상대가 기본값이면 상대가 `CLOSE_CODE_PATH_DEAD`로 연결을 끊는다. 느슨한 값은 양 끝에 같이 올려야 효과가 있다.

## 결정

1. 기본값은 바꾸지 않는다. `probe_interval` 250ms, `min_dead_after` 1초, `strikes` 3은 attach와 역방향 등록 양쪽에서 그대로다. 설정이 없으면 오늘과 바이트 단위로 같은 동작이라는 ADR-0021 결정 4와 ROADMAP M13 (k)가 유지된다.

2. 역방향 등록 연결 전용 재정의 키를 `[recovery]` 안에 둔다. 이름은 `reverse_min_dead_after_ms`와 `reverse_strikes`다. 두 키는 target의 `qsh serve --to`와 controller의 `qsh listen`이 각자의 `config.toml`에서 읽고, 등록 연결의 `PathWatch`에만 적용한다. 대화형 attach와 supervised 터널의 `[recovery]` 세 값은 그대로 `[recovery].min_dead_after_ms`와 `[recovery].strikes`를 따른다. 키가 없으면 역방향 등록도 일반 `[recovery]` 값을 쓴다. `probe_interval_ms`는 재정의하지 않는다. cadence는 두 연결 종류가 같다.

3. 새 상한 `REVERSE_DETECTION_CEILING`을 5000ms로 둔다. 역방향 등록 연결의 `probe_interval × reverse_strikes + reverse_min_dead_after`는 5000ms 이하여야 하고 `reverse_strikes ≥ 2`, `probe_interval ≤ reverse_min_dead_after`다. 범위를 벗어난 값은 clamp하지 않고 `CONFIG_ERROR`(`retryable: false`)로 기동을 거절한다. `ReverseConfig::backoff`와 같은 fail-closed 규율이다. 5000ms는 이슈 #10 요청의 상단(3~5초)을 한도 안에 넣는 값이고, 그보다 느슨하게 잡으면 죽은 등록이 `stale`로 표시되기까지 늦어지는 비용이 커지고, 요청이 그 위를 요구한 근거도 없다.

4. `reverse_blackout.rs`와 `reverse_resume_chaos.rs`의 `detection_budget` 상한을 역방향 등록 쪽은 `REVERSE_DETECTION_CEILING`으로 바꾸고, `attach_recovery.rs`의 2000ms 상한은 그대로 둔다. 상한을 올리는 변경이 테스트 자신을 올려서 통과하는 모양이 되지 않도록, 테스트는 설정 값이 아니라 상수 두 개(2000, 5000)를 각자 본다.

5. 기본값을 바꿀지는 `54ce47d`가 들어간 빌드로 같은 토폴로지에서 모은 현장 관측 뒤에만 판단한다. 보고자가 적은 `54ce47d` 이전 기준선은 하루 1~3건의 짧은 `path_dead`다. 그 수준으로 돌아오면 기본값 변경은 기각한다. 판단에 쓰는 기록은 사람이 이슈 #10이나 캠페인 문서에 남긴 `lost`/`retry` 줄 분포다. 이 결정은 구현을 요구하지 않고 기본값 변경의 문턱만 적는다.

6. 문서와 진단은 구현 커밋과 같은 커밋에서 바꾼다. `docs/design/protocol.md` §10의 `[recovery]` 서술과 §11-4 항목 4(양쪽 role이 같은 정책을 쓴다는 문장과 두 키의 존재, 양 끝에 같이 올려야 한다는 문장), `docs/design/architecture.md` §7의 키 나열, `docs/CLI.md` §6.12·§6.13의 키 서술과 상태 헤더를 고친다. `qsh doctor`의 `config_unknown_key`는 `Config`가 직렬화하는 리프 경로에서 known set을 만들므로(`collect_leaf_paths`) 두 키를 `Config`에 더하면 진단 어휘가 따라온다. wire, `.proto`, `qsh.cli/v1`, `ErrorCode`는 바뀌지 않는다.

## 근거

- **원인에 맞는 순서다.** 오탐이던 부분은 `54ce47d`가 이미 없앴다. 남는 문제는 실제 1~2초 정체를 견딜지 여부이고 이것은 정책 선택이다. 선택은 현장 데이터를 보고 하는 편이 낫다. 그래서 기본값은 두고(결정 1) 손잡이만 먼저 열며(결정 2) 기본값 변경은 `54ce47d` 이후 기록에 묶는다(결정 5).
- **attach의 2초는 attach의 근거다.** 2초 상한은 사용자가 기다리는 재접속에서 나왔고 역방향 등록에는 그 근거가 닿지 않는다. 복구 예산이 backoff에 지배되는 연결에 같은 상한을 거는 것이 이슈 #10의 불만과 맞물린 지점이다.
- **ADR-0021을 최소로 고친다.** 결정 4의 기본값과 "세 값만 연다"는 범위, 검증 규율은 그대로고, 상한이 한 숫자(2000)에서 연결 종류별 둘(2000, 5000)이 되는 것만 바뀐다.
- **회귀 테스트의 의미가 남는다.** 세 테스트가 지키는 성질은 "느슨한 설정이 자기 허용치를 스스로 올리지 못한다"이다. 상한을 상수로 두면(결정 4) 그 성질이 유지된다.

## 대안

- **기본값을 지금 올린다.** 기각한다. ADR-0021 결정 4와 ROADMAP M13 (k)에 어긋나고, `54ce47d` 이후 데이터 없이 오탐 제거 전의 숫자로 기본값을 움직이는 것이 된다. 결정 5의 문턱을 넘으면 새 ADR로 다시 연다.
- **역할 절(`[reverse]`·`[listen]`)에 감지 키를 둔다.** ADR-0021이 이미 기각했다. 같은 이유로 기각한다. 감지 정책은 watch하는 쪽의 것이고 역할에 묶이지 않는다. 이 ADR의 키는 `[recovery]` 안에 남고 이름 접두만 다르다.
- **상한을 일반 `[recovery]`에서 5초로 통째로 올린다.** 기각한다. 대화형 attach의 2초 약속(`docs/design/testing.md` L4)이 설정 하나로 깨진다. 결정 3이 연결 종류별로 상한을 가르는 이유다.
- **감지 대신 keep-alive나 idle timeout을 조정한다.** 기각한다. idle timeout은 ADR-0021 결정 2·3이 고정했고, keep-alive는 송신 cadence라서 감지 판정 시간과 무관하다.
- **아무것도 하지 않는다.** `54ce47d`만으로 충분할 수도 있다. 이 ADR은 그 가능성을 결정 5의 문턱으로 열어 두되, 실제 정체가 남을 때 설정으로도 풀 수 없는 상태를 방치하지 않으려고 손잡이는 지금 제안한다.

## 결과

- 승인되면 `[recovery]`에 선택 키 둘이 더해진다. 둘 다 optional이고 없으면 오늘 동작과 같다.

  | 키 | 기본 | 범위 | 적용 대상 |
  |---|---|---|---|
  | `[recovery].reverse_min_dead_after_ms` | 일반 `min_dead_after_ms`를 따른다 | 범위 규칙은 결정 3 | 역방향 등록 연결의 `PathWatch` 둘(target, controller) |
  | `[recovery].reverse_strikes` | 일반 `strikes`를 따른다 | 같음 | 같음 |

- 느슨한 값은 양 끝에 같이 올려야 한다. 한쪽만 올리면 상대의 기본 감시가 먼저 연결을 끊는다. `docs/CLI.md` §6.12·§6.13에 이 문장을 적는다.
- ADR-0021 결과 절의 상한 문장이 "연결 종류별 상한"으로 바뀐다. `crates/qsh-cli/tests/reverse_blackout.rs`와 `crates/qsh-testkit/tests/reverse_resume_chaos.rs`의 `detection_budget` 상한 상수가 5000ms로 오른다. `crates/qsh-cli/tests/attach_recovery.rs`의 상한은 2000ms로 남는다.
- 설정이 없을 때의 `PathWatchConfig` Debug 출력은 오늘과 같다. 이 불변을 구현 테스트가 byte 단위로 고정한다.
- 구현은 이 ADR이 `승인됨`이 된 뒤의 별도 커밋이다. 이 ADR은 구현을 포함하지 않는다. 승인 전까지 이슈 #10의 요청 둘째는 열려 있다.
- `docs/ROADMAP.md`와 `PLAN.md`의 배치는 승인 뒤 메인 세션이 정한다. M13 (k)의 크기와 밖에 있다.
- 잔여 위험은 둘이다. 느슨한 감지는 진짜로 죽은 등록의 `stale` 표시를 늦춘다(최대 5초 더). 그리고 한쪽 설정만 바뀐 비대칭 배포에서는 효과가 없다.
