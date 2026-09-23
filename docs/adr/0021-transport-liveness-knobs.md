# ADR-0021: keep-alive만 `[transport]` 설정으로 열고 idle timeout 45초는 고정 상수로 남긴다. `PathWatchConfig`의 세 값은 `[recovery]`로 내린다

날짜: 2026-09-24
상태: 제안됨

개정 관계: `docs/design/protocol.md` §1 요약표와 §2를 개정한다. §10이 이미 적어 둔 "세 값 모두 상수가 아니라 설정(`RecoveryConfig`)이다"는 개정 대상이 아니라 이행 대상이다. 기존 ADR은 하나도 대체하지 않는다. 두 타이머를 다룬 ADR은 오늘 없다.

## 맥락

이슈 `#4`의 항목 1이 전송 계층의 liveness 타이머를 설정으로 열 수 있느냐고 물었다. 오늘 그 타이머는 둘 다 컴파일 상수다.

`crates/qsh-transport/src/endpoint.rs`의 `transport_config()`가 quinn `TransportConfig`에 `KEEP_ALIVE_INTERVAL`(15초)과 `MAX_IDLE_TIMEOUT`(45초)을 박는다. 둘 다 같은 파일의 `pub const`이고 `config.toml`을 읽는 경로는 없다. `docs/design/protocol.md` §1 요약표의 "keep-alive / idle" 행이 `15s / 45s`를 적고 §2가 그 근거를 적는다. 15초는 흔한 30초 UDP NAT binding timeout보다 짧아야 NAT 뒤 역방향 target의 장수명 연결이 유지되기 때문이고 45초는 절전한 노트북의 연결은 죽이되 세션은 살려 두는 값이다. §2는 같은 자리에서 "idle timeout을 키워 QUIC 레벨에서 절전 생존을 추구하지 않는다"고 닫았다.

두 값의 성격은 같지 않다. keep-alive PING은 송신측이 혼자 정하는 로컬 cadence다. 상대는 그 간격을 광고받지도 않고 알 필요도 없다. 반면 `max_idle_timeout`은 QUIC이 양쪽이 광고한 값의 min으로 실효값을 정한다. 한쪽만 키운 설정은 그 자리에서 무효가 되거나, 운영자가 키운 줄 아는 값과 실제로 도는 값이 어긋나는 비대칭을 만든다.

그리고 45초는 이 제품에서 감지 기전이 아니다. §10 "Path 사망 감지"가 그 전제를 명문화했다. quinn이 죽은 연결을 포기하는 유일한 무조건 신호는 45초 idle timeout인데 "그 값은 위에서 튜닝 대상이 아니라고 못박았다"이므로, 감지는 control 스트림 위의 애플리케이션 `Ping`/`Pong`으로 한다. 같은 전제가 코드에도 적혀 있다. `crates/qsh-core/src/client/pathwatch.rs`의 `impl Default for PathWatchConfig`가 250ms × 3 strike를 고른 이유를 "45초 idle timeout에서 두 자릿수 배 떨어져 있어야 하고 그것이 결코 기전이 되어서는 안 된다"로 적는다. `crates/qsh-core/src/reverse/listen.rs`의 `CLOSE_CODE_PATH_DEAD` doc도 45초를 "unconfigurable"로 부르며 명시적 close가 없으면 그 값에 기대게 된다는 이유로 close를 넣는다.

문서와 코드가 어긋나 있는 자리는 따로 있다. §10은 사망 판정 기준 `max(1s, 관측 RTT × 8)`과 3회 무응답에 대해 "세 값 모두 상수가 아니라 설정(`RecoveryConfig`)이다"라고 적었다. 실제로는 그렇지 않다. `PathWatchConfig`는 `probe_interval`·`idle_probe_interval`·`active_window`·`min_dead_after`·`rtt_multiple`·`strikes` 여섯 필드가 있지만 `config.toml`에서 채워지는 경로가 없고 프로덕션 호출 지점 셋이 전부 `PathWatchConfig::default()`를 박는다.

- `crates/qsh-core/src/reverse/target.rs`의 `run_reverse_unix`. target이 controller와 유지하는 등록 연결의 watch다.
- `crates/qsh-core/src/reverse/listen/registration.rs`의 `drive_registered_session`. 같은 연결을 controller 쪽에서 보는 watch다.
- `crates/qsh-core/src/ops/session.rs`의 `impl Default for RecoveryConfig`. `RecoveryConfig.watch`가 여기서 채워진다.

셋 중 마지막 것만 `crates/qsh-core/src/ops/mod.rs`의 `Ops::with_recovery`로 덮을 수 있고 그 호출자는 테스트뿐이다. 역방향 두 자리는 덮을 방법 자체가 없다.

마지막으로 `Config`(`crates/qsh-core/src/config.rs`)에는 `[serve]`·`[identity]`·`[listen]`·`[reverse]`·`[audit]` 다섯 절만 있다. `[transport]`도 `[recovery]`도 없다. 검증의 모범은 같은 파일의 `ReverseConfig::backoff`다. 기본값 상수 셋과 상한 `MAX_BACKOFF_MS`를 두고 위반마다 `backoff_config_error`로 `ErrorCode::ConfigError` + `retryable(false)`를 돌려주며 조용한 clamp를 하지 않는다.

## 결정

1. `KEEP_ALIVE_INTERVAL`을 `[transport].keep_alive_ms`로 연다. 기본값은 오늘과 같은 15000이고 범위는 `1000..=20000`이다. 검증은 `ReverseConfig::backoff`의 모양을 그대로 따른다. 범위를 벗어난 값은 clamp하지 않고 `CONFIG_ERROR`(`retryable: false`)로 기동을 거절한다. 여는 근거는 값을 고른 이유 자체다. 15초는 NAT binding 수명에서 나온 숫자이고(§2) 그 수명은 망마다 다르다. keep-alive PING은 순수 송신측 로컬 동작이라 이 값을 바꿔도 상대에게는 아무 의미가 없다. 상한 20초는 45초 idle timeout의 절반(22.5초) 아래다. keep-alive가 그 절반을 넘으면 PING 하나를 잃는 것만으로 idle timeout이 먼저 만료되어 keep-alive가 지키려던 연결을 keep-alive 설정이 죽이게 된다. 하한 1초는 무선 라디오를 깨우는 비용의 바닥이다.

2. `MAX_IDLE_TIMEOUT`은 45초 고정 상수로 남긴다. 어떤 config 키로도 열지 않는다. §2의 "idle timeout을 키워 QUIC 레벨에서 절전 생존을 추구하지 않는다"와 §10의 "그 값은 튜닝 대상이 아니다"를 이 ADR이 재확인한다. 이 결정을 뒤집으려면 이 ADR을 개정해야 한다.

3. 뒤집지 않는 이유를 두 문장으로 명문화한다. `max_idle_timeout`의 실효값은 양 peer가 광고한 값의 min이므로, 한쪽만 키운 설정은 상대가 기본값이면 아무 효과가 없고 운영자의 기대를 배신한다. 그리고 45초가 지금 어디에도 쓰이지 않는다는 것이 설계 전제다. `PathWatchConfig`의 기본값 doc과 `CLOSE_CODE_PATH_DEAD`의 doc이 둘 다 "idle timeout은 결코 감지 기전이 아니다"에 기대어 자기 값을 고르고 있으므로, idle timeout을 운영 손잡이로 만드는 순간 그 전제가 설정값에 따라 참이었다 거짓이었다 한다.

4. `PathWatchConfig`의 `probe_interval`·`min_dead_after`·`strikes` 셋을 새 `[recovery]` 절에서 읽는다. 기본값은 250ms·1초·3으로 오늘과 같고 설정이 없으면 오늘과 바이트 단위로 같은 동작이다. 검증은 결정 1과 같은 규율이다. 이 결정은 새 정책을 세우지 않는다. §10이 이미 약속한 것을 코드에 옮기는 일이다. 나머지 세 필드(`idle_probe_interval`·`active_window`·`rtt_multiple`)는 이번에 열지 않는다.

5. 두 타이머 모두 M8 wire freeze 대상이 아님을 기록한다. §16.1의 `.proto` 동결표에도 §16.2의 "`.proto` 밖의 상호운용 계약" 표에도 keep-alive 행과 idle 행이 없다. 이 ADR은 freeze 문면을 건드리지 않고 결정 1의 개방이 §16.5의 금지 사항에 닿지도 않는다.

6. 문서와 진단은 같은 커밋에서 정리한다. `docs/design/protocol.md` §1 요약표의 "keep-alive / idle" 행과 §2 산문이 "15s 기본값, `[transport].keep_alive_ms`로 조정, idle 45s 고정"을 적도록 고친다. §11-4 항목 4의 "연결 유지는 §2의 15s keep-alive이고"도 같은 커밋에서 기본값 서술로 바꾼다. `docs/design/architecture.md` §7의 `config.toml` 절별 키 나열에 두 절을 더하고 `docs/CLI.md`에 같은 키를 적는다. `qsh doctor`의 `config_unknown_key` 진단에는 따로 등록할 목록이 없다. `crates/qsh-core/src/ops/doctor.rs`의 `doctor_config_unknown_key_findings`가 `collect_leaf_paths`로 `Config` 자신의 `Serialize` 출력에서 known set을 만들기 때문에, 두 절을 `Config`의 필드로 더하는 것만으로 진단 어휘가 따라온다. 손으로 맞출 목록이 없다는 것이 그 코드의 설계 의도이고 이 ADR은 거기에 아무것도 더하지 않는다.

7. 구현 스텝은 이슈 `#4` 항목 6의 `cause` 데이터가 먼저 착지한 뒤에만 연다. 지금 우리는 현장에서 연결이 어느 타이머로 죽는지 모른다. `docs/CLI.md` §6.13이 규정하는 `qsh::reverse` tracing target의 한 줄 JSON 진단은 등록 이벤트 어휘(`registered|denied|replaced|lost|expired|retry`)만 싣고 사인을 싣지 않는다. `lost`가 `PathWatch`의 판정인지 quinn의 idle timeout인지 상대의 close인지 구분되지 않는 상태에서 타이머 값을 움직이면 관측 없는 추측이 된다. `cause`가 그 줄에 붙어 실제 사인이 보인 뒤에 이 ADR의 결정 1과 결정 4를 구현한다. `cause`가 idle timeout을 한 번도 가리키지 않으면 결정 1만 구현하고 결정 4는 필요 없다는 결론이 나올 수도 있다.

## 대안

- idle timeout도 함께 연다. 기각한다. 실효값이 min 협상이므로 한쪽만 여는 설정은 효과가 없거나 비대칭이고(결정 3) 그 값을 운영 손잡이로 만들면 `PathWatchConfig`와 `CLOSE_CODE_PATH_DEAD`가 기대고 있는 설계 전제가 설정에 따라 흔들린다. §16 freeze 밖이라는 사실은 "바꿔도 된다"가 아니라 "이 값은 peer 간 계약으로 얼리지 않는다"는 뜻일 뿐이다.
- 둘 다 닫아 둔다. 기각한다. 15초를 고른 이유가 NAT binding 수명이고 그 수명은 망마다 다르다. 짧은 binding을 쓰는 망 뒤의 역방향 target은 15초로도 매 주기 재등록하게 되고 반대로 배터리가 아까운 장치는 15초가 과하다. keep-alive는 상호운용 의미가 없어서 여는 비용이 낮은 쪽에 속한다.
- `PathWatchConfig`의 여섯 필드를 전부 연다. 기각한다. `idle_probe_interval`과 `active_window`는 cadence 전환 정책이라 잘못 맞추면 watchdog이 자기 `Pong`으로 active 창을 갱신하는 문제(그 필드들의 doc이 경고하는 바로 그 문제)에 가까워지고 `rtt_multiple`은 `min_dead_after`와 곱해져 감지 예산에 비선형으로 들어간다. 요구가 확인된 값만 연다.
- `[transport]`·`[recovery]`를 새로 만들지 않고 기존 `[serve]`나 `[reverse]`에 키를 얹는다. 기각한다. keep-alive는 dial하는 쪽과 accept하는 쪽 모든 연결에 붙는 endpoint 수준 값이라 어느 한 역할의 절에 두면 나머지 역할에서 읽히지 않는 것처럼 보인다. `PathWatchConfig`는 반대로 watch하는 쪽만의 정책이고 그 쪽은 `qsh serve`·`qsh listen`·`qsh reverse` 어디든 될 수 있다. 역할 절에 얹으면 `[listen]`이 admission 값을 `[serve]`에서 상속하는 식의 예외 규칙이 하나 더 는다.
- CLI flag로 낸다. 기각한다. 이 값들을 움직일 상황은 상주 데몬이 특정 망 뒤에 있을 때인데, 그 데몬은 `qsh service install`이 쓴 unit이 고정 인자로 띄운다(ROADMAP M9 (g)). 파일에 있어야 재시작을 견딘다.
- `cause` 없이 지금 구현한다. 기각한다. 결정 7의 이유 그대로다. 손잡이를 먼저 만들면 원인을 모르는 채로 값을 돌리는 운영이 시작되고 그 뒤에 들어오는 제보는 어느 타이머 이야기인지 더 구분하기 어려워진다.

## 결과

- `config.toml`에 다음 키가 생긴다. 전부 optional이고 기본값은 오늘 동작과 같다.

  | 키 | 기본 | 범위 | 오늘의 자리 |
  |---|---|---|---|
  | `[transport].keep_alive_ms` | 15000 | `1000..=20000` | `KEEP_ALIVE_INTERVAL` |
  | `[recovery].probe_interval_ms` | 250 | 검증 범위는 구현 시 확정 | `PathWatchConfig::probe_interval` |
  | `[recovery].min_dead_after_ms` | 1000 | 같음 | `PathWatchConfig::min_dead_after` |
  | `[recovery].strikes` | 3 | 같음 | `PathWatchConfig::strikes` |

  `[recovery]` 세 값의 범위는 감지 예산 회귀 테스트가 지키는 상한 아래로 잡는다. `crates/qsh-cli/tests/reverse_blackout.rs`·`crates/qsh-cli/tests/attach_recovery.rs`·`crates/qsh-testkit/tests/reverse_resume_chaos.rs`의 `detection_budget`이 이미 "어떤 `PathWatchConfig`도 스스로 올릴 수 없는 상한"을 고정하고 있으므로, 설정으로 그 상한을 넘길 수 있게 되면 그 테스트들이 지키던 성질이 사라진다. 구체적인 숫자는 구현 시 그 상한에서 역산한다.

- `config.toml`은 기동 시 1회 읽힌다. 두 절도 같다. 값을 바꾸면 그 프로세스를 재시작해야 반영된다.

- `crates/qsh-transport/tests/loopback.rs`의 `keep_alive_and_idle_timeout_are_configured_and_ping_pong_roundtrips`에서 `MAX_IDLE_TIMEOUT == 45초` 단언은 그대로 남고 이 ADR이 그 단언을 우연한 현황에서 계약으로 승격한다. 같은 테스트의 `KEEP_ALIVE_INTERVAL == 15초` 단언은 "설정이 없을 때의 기본값"을 고정하는 단언으로 뜻이 바뀐다. 구현은 범위 밖 값이 `CONFIG_ERROR`로 fail closed되는 테스트를 `ReverseConfig::backoff`의 검증 테스트와 같은 형식으로 더한다.

- `docs/design/testing.md` L4 표의 `blackhole(dur)` 행("PTO/keep-alive 튜닝, idle timeout 동작")은 chaos 하네스가 기본값으로 도는 한 그대로다. 이 ADR은 그 행이 검증하는 대상을 바꾸지 않는다.

- `qsh capabilities`가 내는 협상 결과는 바뀌지 않는다. 두 타이머 어느 쪽도 capability 문자열이 아니고 `Hello`에 실리지 않는다.

- 마일스톤 배치는 M9 밖이다. ROADMAP M9 범위 (a)~(k)에 이 항목이 없다. M10 이후 또는 P1이고 착수 선행 조건은 결정 7의 `cause`다.

- 이 ADR이 승인되면 이슈 `#4`의 항목 1이 닫힌다. 답은 "keep-alive는 연다, idle timeout은 열지 않는다, 실제로 어긋나 있던 것은 `PathWatchConfig` 쪽이었다"다.

- 구현 크기는 0.3~0.4ew로 추정한다. 측정값이 아니다. 내역은 config 타입과 검증 0.15, 호출 지점 넷의 배선 0.1, 테스트 0.1, 문서 네 곳 0.05다. `[recovery]` 배선이 역방향 두 자리까지 닿아야 해서 `[transport]` 쪽보다 넓다.
