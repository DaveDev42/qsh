# ADR-0042: PathWatch는 자기 tick의 지연을 침묵에서 덜어내고, 역방향 target은 빨리 끝나는 등록이 연속되면 재dial을 늦춘다

날짜: 2026-10-06
상태: 승인됨 (2026-10-06 사용자 승인 (이슈 #11 처리 계획))

개정 관계: ADR-0041이 이슈 #11의 나머지 요청으로 남긴 둘(요청 2, 요청 4)을 이 ADR이 결정하고, 요청 3(`cause=local`의 문서화)의 분류 보정을 함께 기록한다. 개정하는 자리는 셋이다. 첫째, ADR-0023 결정 20의 "wake가 target의 backoff를 `backoff_initial_ms`부터 다시 센다"에 빨리 끝난 등록의 연속 횟수도 0으로 돌린다는 문장이 붙는다. 둘째, `docs/CLI.md` §6.13과 ADR-0023의 `cause` 대응 문단이 `local`을 나머지 칸으로 둔 것에서 두 경우가 빠진다. stateless reset은 `peer_closed`로, 등록 중 `Hello` 응답 시간 초과는 `dial_timeout`으로 간다. 어휘는 9값 그대로다. 셋째, ADR-0041 결과 절의 잔여 위험 "호스트 자체가 5초 넘게 멈추는 경우(이슈 #11)는 이 기본으로 풀리지 않는다"를 이 ADR이 부분적으로 받는다. 무엇이 풀리고 무엇이 풀리지 않는지는 결과 절에 적는다. ADR-0023 결정 17(wake 감지)은 건드리지 않고 이 ADR의 결정 1이 짝으로 선다.

## 맥락

GitHub 이슈 #11은 부하 평균 52/84/74인 macOS laptop에서 네트워크 손실 없이 역방향 등록이 끊긴 경우다. 16시간 유지되던 등록이 hub의 `path_dead` 판정으로 끊겼고 뒤따른 등록 셋도 같은 식으로 끊겼으며, 안정될 때까지 약 4.5분이 걸렸다. 같은 호스트에서 `sleep 1`을 다섯 번 도는 쉘 루프가 49~84초를 쟀으므로 프로세스가 스케줄링되는 데 초 단위가 걸렸다. 이슈 #11의 요청은 넷이다. 요청 1(감지 창을 수 초로)은 ADR-0041이 받았다. 이 ADR은 나머지 셋을 다룬다.

- **요청 2.** watch가 발화했을 때 이 프로세스 자신이 늦었는지 보고, 지연이 초 단위면 침묵을 사망으로 읽지 말고 세기를 다시 시작하자는 것이다. 틱 간격을 `lost cause=path_dead` 줄에 싣는 것도 요청이다.
- **요청 3.** `cause=local`이 무엇인지, 부하 아래에서 기대되는 것인지 적어 달라는 것이다.
- **요청 4.** 빨리 끝나는 `path_dead`가 반복되면 같은 정체 속으로 곧바로 재dial하지 말고 늦추자는 것이다. 보고자는 이 요청이 사건에 도움이 됐을지 모른다고 적었다.

코드를 읽고 확인한 사실은 이렇다.

1. watch는 `tokio::time::sleep(cadence)`로 tick을 만들고 매 tick에서 `last_inbound`로부터의 침묵을 잰다(`client/pathwatch.rs`). 프로세스가 굶어 timer가 늦게 발화하면, 그 사이 소켓에 쌓인 응답이 아직 읽히지 않은 채로 침묵 시간만 커 보인다. 그 tick이 곧바로 `strikes`와 `dead_after`를 둘 다 채우면 판정이 선다. 늦은 tick은 이 구조에서 직접 오탐을 만든다.
2. 절전 감지기(`client/wake.rs`, ADR-0023 결정 17)는 wall clock이 단조 시계보다 3초 넘게 앞서 갈 때만 발화한다. 이슈 #11은 `kern.waketime`이 전날을 가리켰으므로 절전이 아니었고 단조 시계는 계속 갔다. 감지기는 이 경우를 보지 못한다.
3. target의 재dial 지연은 등록이 한 번 받아들여지면 `backoff.reset()`으로 초기값(500ms)으로 돌아간다(`reverse/target/mod.rs`). 등록이 수 초 만에 끝나는 일이 반복되어도 지연은 0.5초 안팎에 머문다.
4. `cause=local`의 출처를 코드에서 전부 찾았다(결정 3과 `docs/CLI.md` §6.13). 두 가지가 시간 초과 또는 상대의 행동인데 `local`로 찍히고 있었다. 등록 중 `Hello` 응답 시간 초과(`HelloError::Timeout`)는 `local`로 떨어졌다. 상대가 이미 버린 연결에 대한 stateless reset(`ConnectionError::Reset`)도 `local`이었다. 또 `serve_control`은 연결이 끝나서 `accept_bi`가 실패하면 이유와 무관하게 `Ok(())`로 돌아오는데, target은 그것을 무조건 `peer_closed`로 읽었다. quinn의 idle timeout이 그 경로로 오면 `idle_timeout`이 `peer_closed`로 찍힌다.
5. 이슈의 laptop `local` 둘이 위 둘 중 어느 쪽인지는 로그만으로 확정하지 못한다. hub가 `path_dead`로 연결을 닫은 17초 뒤, 등록이 70초 가까이 산 시점에 laptop이 `local`을 냈다. hub가 닫은 연결에 laptop이 한참 늦게 패킷을 보내 stateless reset을 받은 모양과 맞지만 추정이다.
6. 사건에서 `path_dead`를 내린 쪽은 굶지 않은 hub였다. hub가 laptop에서 응답을 못 받은 것은 laptop이 굶어서 ACK와 `Pong`을 못 보냈기 때문이다. hub는 그것을 알 수 없다. 그러므로 요청 2의 장치는 굶은 쪽이 자기 판정으로 연결을 끊는 것을 막고, 건강한 상대가 내리는 판정은 막지 못한다.

## 결정

1. **watch는 자기 tick의 지연을 침묵에서 덜어내고, 지연된 tick은 사망을 선언하지 못한다.**
   - **측정.** `watch_path_with_wake`는 timer arm이 이긴 라운드에서만 tick 간격을 잰다. `gap`은 그 라운드가 잠들기 시작한 시각부터 발화까지의 실제 경과이고 `late = gap - (잔 beat)`다. 다른 arm(`woken`, wake, closed)은 라운드를 다시 시작하거나 끝내므로 표본이 아니다.
   - **임계.** `late >= probe_interval`이면 자기 지연이다. 기본 250ms이고 `[recovery].probe_interval_ms`를 따른다. 새 설정 키는 없다. 임계는 `PathWatchConfig`에서 파생하는 값이라 구조체와 그 Debug 출력이 바뀌지 않는다(ADR-0041 결과 절이 byte 단위로 고정한 불변). 숫자의 근거는 `probe_interval`이 strike 하나가 세는 단위라는 점이다. 그만큼 늦은 tick은 probe 한 칸과 strike 하나를 이미 잃었으므로 장부가 한 strike만큼 어긋난다. 그보다 작은 지연은 침묵 계산이 원래 가진 한 tick의 해상도 안이라 건드리지 않는다. 이 값은 정상 프로세스의 스케줄링 잡음(수 ms)과 굶은 프로세스의 지연(초 단위) 사이에 넉넉한 틈이 있어, 정확한 값이 중요하지 않다.
   - **조치.** 임계를 넘으면 `last_inbound`를 `late`만큼 앞으로 민다. 현재 시각을 넘지 않게 자른다. 침묵은 "이 프로세스가 깨어서 본 침묵"이 된다. 그 tick은 `silence >= dead_after + late`일 때만 사망을 선언한다. 덜어낸 뒤의 침묵이 이 값에 닿는 일은 사실상 없으므로 그 tick은 선언하지 않는다. probe는 평소처럼 나가고 strike도 평소처럼 센다. 다음 정시 tick은 `late = 0`이라 평소의 규칙으로 판정한다. 그 사이에 쌓여 있던 응답이 읽혔으면 `observe_inbound`가 strike를 지운다. 응답이 정말 없었다면 한 정시 tick(250ms) 뒤에 판정이 선다.
   - **모든 tick이 늦는 경우.** 덜어내기는 용서가 아니다. 매 tick이 300ms씩 늦는 호스트에서 침묵은 tick마다 beat 하나(250ms)씩만 쌓이고, `dead_after + late`에 닿으면 판정이 선다. 테스트(`a_watchdog_that_is_late_on_every_tick_still_reaches_a_verdict`)가 이 수렴을 고정한다. 정상일 때보다 느릴 뿐 영원히 미루지는 않는다. 어떤 경로로든 판정이 서지 못해도 QUIC idle timeout 45초가 마지막 상한이다.
   - **wake 감지기와의 관계.** 감지기를 재사용하지 않고 짝으로 둔다. 감지기는 단조 시계가 멈췄을 때(wall clock이 앞서 갈 때)를 보고 그 조치는 즉시 probe이며 침묵 시계를 건드리지 않는다. 단조 시계가 멈췄으니 침묵도 멈춰 있기 때문이다. 이 장치는 단조 시계는 갔는데 프로세스가 돌지 못한 경우를 보고 침묵 시계를 앞으로 민다. 두 입구는 `PathState`의 서로 다른 메서드(`observe_wake`, `observe_tick`)이고 서로의 상태를 읽지 않는다. 감지기가 놓친 절전이 단조 시계가 계속 가는 플랫폼에서 큰 tick 간격으로 나타나면 이 장치가 같은 방향으로 처리한다.
   - **진단.** `lost cause=path_dead` 줄에 `tick_gap_ms`가 붙는다. 이 프로세스의 감시가 직접 판정했을 때만 싣고(`srtt_ms`·`silence_ms`와 같은 규칙), 그 밖의 줄에는 키가 없다. 값은 마지막 생존 증거 이후 이 감시의 tick이 잔 beat보다 가장 늦게 발화한 양(`간격 - 잔 beat`)이다. 이름은 `tick_gap_ms`지만 간격 자체가 아니라 지연이다. 간격을 그대로 실으면 유휴 cadence(5초 beat)의 정상 감시가 5000 언저리로 찍혀 굶은 프로세스와 구별되지 않기 때문이다. 정상은 cadence와 상관없이 0 언저리이고 몇 초면 프로세스가 굶고 있었다는 뜻이다. 생존 증거가 오면 0으로 돌아가므로 그 판정이 선 침묵 구간을 서술한다.
   - **적용 범위.** attach, supervised 터널, 역방향 등록 target과 controller가 모두 `watch_path`를 지나므로 같이 적용된다. attach에서는 굶은 laptop이 정상 연결을 스스로 끊고 재dial하는 일이 사라진다.

2. **빨리 끝난 등록이 연속되면 target의 재dial 지연을 늘린다.**
   - **빠른 유실.** 받아들여진 등록이 60초(`STABLE_REGISTRATION`)가 못 되어 끝난 것이다. 종료 원인과 무관하다. 사건의 laptop은 hub의 `path_dead`를 `local`이나 `peer_closed`로 봤으므로, 원인 분류에 기대면 같은 현상이 다른 이름으로 빠져나간다. 60초는 등록이 죽은 것으로 보일 수 있는 시간(5초, ADR-0041)의 열 배가 넘으므로, 그보다 오래 산 연결은 문제의 조건에서 실제로 트래픽을 나른 것이다.
   - **규칙.** 연속 빠른 유실 횟수를 `n`이라 하면 `n = 1`의 지연은 평소의 첫 지연(`backoff_initial_ms`, 기본 500ms)이라 동작이 달라지지 않는다. `n >= 2`부터 `backoff_initial_ms × 2^(n-1)`이고 `max(backoff_initial_ms, 8초)`와 `backoff_max_ms` 가운데 작은 값에서 멈춘다. jitter는 평소대로 적용한다. 기본값으로 0.5, 1, 2, 4, 8, 8초가 된다.
   - **리셋.** 60초 이상 산 등록이 끝나면 횟수가 0이 된다. wake도 0으로 돌리고(ADR-0023 결정 20이 backoff를 되돌리는 것과 같은 자리) 이후 60초 창의 상한(2초)이 이 지연에도 걸린다. 받아들여진 등록은 횟수를 지우지 않는다. 그것이 횟수의 목적이다.
   - **dial 실패와의 관계.** 재dial이 실패했을 때의 지수 backoff(`next_delay`)는 그대로이고 이 횟수와 서로 독립이다. 등록이 받아들여지면 그 지수는 처음부터 다시 센다. 그래서 오래 산 등록의 유실 뒤 진짜 정전이 이어지는 경우 지연열은 오늘과 같다(500ms, 1s, 2s, ...). 빠른 유실이 쌓인 뒤의 첫 재dial만 늘어난다.
   - **상한 8초.** 기본 초기값의 네 번째 두 배이고 등록의 감지 창(5초)보다 조금 길다. 정체된 호스트로 초당 네 번 재dial하는 일은 멈추고, 연속 유실 직후의 진짜 정전에서 네트워크가 돌아온 뒤 복구가 늦어지는 양은 8초 이하로 묶인다.
   - **설정 키는 열지 않는다.** 배수와 같은 방침이다. `[reverse]`의 `backoff_*` 세 키가 이미 하한과 상한을 정하고, 8초는 `backoff_max_ms`와 `backoff_initial_ms`로 양쪽에서 조정된다.
   - **controller는 재dial하지 않으므로** 이 결정은 `qsh serve --to`에만 닿는다.

3. **`cause` 분류 보정과 `local`의 문서화.** `cause` 어휘는 9값 그대로다(새 값을 더하면 그 줄을 읽는 스크립트가 깨진다).
   - `ConnectionError::Reset`은 `local`에서 `peer_closed`로 옮긴다. stateless reset은 상대의 endpoint만 보낼 수 있고 상대가 그 연결을 더는 갖고 있지 않다는 뜻이다. 이 쪽에서 난 일이 아니다.
   - `HelloError::Timeout`(등록 중 `Hello` 응답 시간 초과)은 `local`에서 `dial_timeout`으로, `HelloError::ClosedBeforeHello`는 `local`에서 `peer_closed`로 옮긴다.
   - target의 `serve_control`이 `Ok(())`로 돌아오면 연결의 `close_reason()`을 읽어 같은 판정으로 분류한다. 닫히지 않은 연결의 정상 EOF만 `peer_closed`다. idle timeout이 `accept_bi`를 거쳐 와도 `idle_timeout`으로 찍힌다.
   - `docs/CLI.md` §6.13에 `cause=local`의 뜻, 나오는 코드 경로 전체, 시간 초과는 담지 않으며 부하 아래에서 기대되는 값이 아니라는 설명을 적는다.

4. **문서와 진단은 구현 커밋과 같은 커밋에서 바꾼다.** `docs/design/protocol.md` §10과 §11-4, `docs/CLI.md` §6.13과 상태 헤더(v0.24), `docs/design/threat-model.md` G7, `docs/design/testing.md`를 고친다. `tick_gap_ms`는 `qsh.cli/v1`·`qsh.event/v1` 밖의 열린 진단 어휘이고(ADR-0022 결정 5) wire, `.proto`, `ErrorCode`, fixture는 바뀌지 않는다.

## 근거

- **오탐의 원인이 측정되는 자리에 있다.** 굶은 프로세스의 침묵은 경로의 침묵이 아니다. 같은 tick에서 같은 타이머로 둘을 구별하는 것이 가장 싼 장치이고, 새 신호를 wire에 더하지 않는다.
- **덜어내는 쪽을 골랐다.** 침묵을 처음부터 다시 세는 안은 단순하지만 굶은 호스트에서 판정이 영원히 오지 않고, 정지 직전까지 쌓은 증거를 버린다. 지연만큼만 덜어내면 쌓인 침묵은 보존되고 모든 tick이 늦는 호스트에서도 판정이 수렴한다. 지연된 tick에 판정을 막는 것은 그 tick에서 아직 읽히지 않은 응답이 가장 많기 때문이다.
- **임계가 strike 단위인 이유.** 고정 시간(예: 1초)은 `probe_interval_ms`를 올린 설정에서 의미가 어긋나고, `dead_after`의 몇 분의 일은 attach(1초)와 등록(4.25초)에서 서로 다른 임계를 만든다. probe 간격은 두 연결 종류가 공유하는 값이라 같은 논거가 양쪽에 선다.
- **빠른 유실을 수명으로 잡은 이유.** 원인 분류는 사건에서 정확하지 않았고(맥락 5), 수명은 이 프로세스가 직접 아는 값이다.
- **재dial 지연이 이슈 #11을 얼마나 푸는가.** 사건의 등록 수명은 7초에서 70초였다. 이 규칙이면 지연이 0.5, 1, 2초로 늘었을 뿐이라 4.5분의 flap을 이 규칙만으로 끊지 못한다. 이 규칙이 겨냥하는 것은 등록이 수 초 만에 반복해서 죽는 경우다. 그때 굶은 호스트로 초당 몇 번씩 TLS handshake를 거는 일이 사라진다. 사건의 flap을 줄이는 쪽은 결정 1과 ADR-0041이다.

## 대안

- **침묵을 처음부터 다시 센다(요청 2의 문면).** 기각한다. 굶는 호스트에서 판정이 계속 미뤄지고 정지 직전의 증거를 버린다. 덜어내기가 같은 보호를 주면서 수렴한다.
- **지연된 tick 직후 고정 개수의 tick을 면제한다.** 기각한다. 면제 길이를 지연의 크기와 상관없이 정해야 하고, 모든 tick이 늦으면 면제가 영구가 된다. `dead_after + late` 기준은 지연에 비례하고 다음 정시 tick에서 끝난다.
- **임계를 `[recovery]`의 새 키로 연다.** 기각한다. `PathWatchConfig`의 Debug 바이트 동일성이 깨지고 손잡이 하나가 늘어난다. 파생값으로 충분하다.
- **wake 감지기를 확장해 자기 지연도 알리게 한다.** 기각한다. 감지기는 프로세스 전체에서 1초 타이머 하나이고 구독자마다 다른 cadence의 지연을 알 수 없다. 지연은 각 watch의 tick에서 재는 것이 정확하다.
- **빠른 유실을 `cause=path_dead`로 한정한다.** 기각한다. 위 근거의 이유로 원인 분류에 기대면 같은 flap이 `local`이나 `peer_closed`로 빠진다.
- **`backoff_max_ms`(30초)까지 올린다.** 기각한다. 정전 직후 복구가 최대 30초 늦어진다. 8초 상한이 요청이 말한 "bounded"와 "genuine outage를 크게 늦추지 않는다"를 함께 만족한다.
- **빠른 유실 임계나 상한을 설정 키로 연다.** 기각한다. 지금까지 값이 없었고, `backoff_initial_ms`와 `backoff_max_ms`가 이미 양끝을 조정한다. 필요가 생기면 additive로 더한다.
- **`Reset`에 새 `cause` 값(`reset`)을 준다.** 기각한다. 9값 어휘는 고정이고, 이 줄을 읽는 소비자가 새 값을 모른다. 의미상 상대가 연결을 버린 것이므로 `peer_closed` 안에 든다.
- **`Reset`을 그대로 `local`로 두고 문서만 적는다.** 기각한다. `local`을 "이 쪽에서 난 일"로 정의한 문서와 맞지 않는 분류를 문서로 덮는 일이 된다.

## 결과

- 구현은 `PathState::observe_tick`/`max_tick_gap`, `PathWatch`의 내부 tick 입구, `DeadVerdict::tick_gap`(`client/pathwatch.rs`), `watch_path_with_wake`의 tick 간격 측정(진단에는 지연만 싣는다), `Backoff::loss_delay`(`reverse/target/mod.rs`), `classify_connection_error`·`classify_hello_error`·`classify_target_connection_loss`(`reverse/`)다. `RegistrationEvent`와 `ReconnectEvent`가 `tick_gap_ms`를 싣는다.
- 회귀는 `crates/qsh-core/src/client/pathwatch/tests.rs`의 `a_late_tick_discounts_the_delay_and_cannot_rule_the_path_dead_on_itself`, `a_watchdog_that_was_starved_does_not_declare_the_path_dead_when_it_resumes`, `a_path_that_stays_silent_after_a_stall_is_still_declared_dead`, `a_watchdog_that_is_late_on_every_tick_still_reaches_a_verdict`와 임계 경계 테스트 둘, `crates/qsh-core/src/reverse/target/tests.rs`의 빠른 유실 테스트들(`consecutive_quick_losses_double_the_redial_delay_up_to_the_cap`, `a_stable_registration_ends_the_streak`, `a_genuine_outage_after_a_long_registration_is_not_slowed`, `a_wake_ends_the_streak_and_its_window_caps_the_next_losses` 외), 분류 테스트(`classify_hello_error_maps_a_hello_timeout_to_dial_timeout_not_local`, `classify_target_connection_loss_reads_the_close_reason_behind_an_ok_return`, `classify_connection_error_reads_a_stateless_reset_as_the_peer_dropping_the_connection`), 통합 `consecutive_quick_losses_double_the_retry_delay_on_the_real_loop`와 `datagram_liveness_silent_path_lost_line_carries_srtt_ms_and_silence_ms_on_the_side_whose_watchdog_ruled`가 지킨다.
- **풀리는 것.** 굶은 프로세스가 자기 watch의 판정으로 정상 연결을 끊는 일. 사건에서 laptop 자신의 watch가 낸 `path_dead`와 그 직후의 재dial 폭주. 빠르게 끝나는 등록이 정체된 호스트로 연속해서 handshake를 거는 일.
- **풀리지 않는 것.** 굶지 않은 상대가 내리는 판정이다. 사건에서 `path_dead`를 낸 것은 hub였다. 굶은 laptop이 ACK와 `Pong`을 못 보내면 hub의 watch는 정당하게 침묵을 본다. hub는 laptop이 굶었다는 것을 알 방법이 없다. 이 창은 ADR-0041의 4.25초 기본과 `reverse_*` 키(상한 5초)가 정한다. 호스트가 그 이상 멈추면 정상 상대가 끊고, 재등록은 호스트가 풀려야 서서히 안정된다. 이를 풀려면 상대에게 "이쪽이 느리다"를 알리는 wire 신호나 더 긴 상한이 필요하고, 둘 다 이 ADR의 범위 밖이다.
- 잔여 위험은 셋이다. 굶는 호스트에서 정말 죽은 경로의 사망 선언이 지연만큼 늦어진다(최악에도 idle timeout 45초가 상한이며 `docs/design/threat-model.md` G7에 적는다). `probe_interval` 미만의 지연은 보정하지 않는다. 8초 상한은 연속 유실 직후의 정전 복구를 최대 그만큼 늦춘다.
- 이 변경만 있는 쪽도 효과가 있다. 자기 지연 보정은 각 프로세스에서 독립이라 한쪽 빌드만 올려도 그 쪽이 자기 판정으로 끊는 일이 사라진다. 다만 상대가 이전 빌드면 상대의 판정은 위 "풀리지 않는 것"대로 남는다.
- `RELEASE-NOTES.md`, `docs/ROADMAP.md`, `PLAN.md`는 메인 세션이 다룬다.
