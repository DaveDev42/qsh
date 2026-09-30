# ADR-0037: 연결 하나에서 정체한 터널 스트림이 연결 수신 창을 다 쓰기 전에 가장 오래 정체한 스트림부터 끊는다

날짜: 2026-10-01
상태: 제안됨

개정 관계: 새 ADR이다. 다른 ADR을 개정하지 않는다. `CONNECTION_RECEIVE_WINDOW`(8 MiB, M8 DoD 2의 세션당 buffer 상한)와 `TUNNEL_STREAM_RECEIVE_WINDOW`(2 MiB, `docs/design/protocol.md` §12가 측정으로 확정한 값)는 그대로 두고, ADR-0010의 터널 스트림 quota 기본값도 건드리지 않는다. 느린 스트림 역압 하네스(`crates/qsh-testkit/tests/tunnel_stalled_streams.rs`, 커밋 `209e764`)의 strict 결과가 이 ADR의 입력이다.

## 맥락

`docs/PRD.md` §13은 느린 파일·터널 stream이 PTY stream을 막지 않아야 한다고 적는다. 포화(고속) 축은 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`가 닫았다. 소비자가 읽지 않는 저속·역압 축은 `docs/design/testing.md` L9/L10의 "덮는 축은 포화(고속) 하나다" 문단이 잔여 위험으로 남겨 두었고, `docs/ROADMAP.md` M13 범위 (b)가 그것을 재라고 했다.

커밋 `209e764`의 하네스는 한 QUIC 연결 위에 PTY 세션과 `-L` 포워드 N개를 올린다. 호스트 쪽 목적지가 끝없이 쓰고, 클라이언트 쪽 로컬 소비자는 작은 `SO_RCVBUF`로 연결만 열고 한 바이트도 읽지 않는다. `QSH_ACCEPTANCE_STRICT=1`로 로컬에서 돌린 결과는 이렇다.

- `pty_output_keeps_progressing_while_four_unread_tunnel_streams_stall`의 N=4 행은 붉다. 10초 동안 200줄 중 44줄만 왔다. N=8 행도 붉고 16줄이었다.
- `pty_echo_p95_stays_within_measured_rtt_plus_10ms_while_four_unread_tunnel_streams_stall`은 붉다. echo 4라운드 뒤 2초 타임아웃이 났다(그때까지 p95 28.9ms).
- 정체 관찰은 `DATA_BLOCKED`=1, `STREAM_DATA_BLOCKED`=3이었다. 호스트가 연결 수준 credit을 다 썼다고 알린 것이다.
- `pty_output_keeps_progressing_with_three_unread_tunnel_streams`(N=3, `DATA_BLOCKED`=0)와 `stalled_stream_harness_observes_data_blocked_before_measuring`은 초록이고, CPU 부하 아래 50회 연속 초록이었다.

가설 그대로다. 읽히지 않는 스트림 넷이 각자 2 MiB 스트림 창을 채우면 합이 8 MiB 연결 창과 같아지고, 호스트는 같은 연결의 `SESSION_DATA`에 보낼 credit을 잃는다.

판정 전에 splice에 단순 결함이 있는지 먼저 확인했다. `crates/qsh-core/src/tunnel/splice.rs`의 `pump`는 방향마다 64 KiB 버퍼 하나로 read, `write_all`, read를 되풀이한다. 로컬 소켓 쓰기가 막히면 그 방향은 QUIC 수신 스트림을 더 읽지 않는다. 이것은 결함이 아니다. 모듈 doc이 약속한 동작("a slow reader stalls its own direction ... instead of growing memory here")이다. 정체는 다른 스트림이나 PTY 쪽 task로 번지지 않는다. `splice_tcp_quic`은 두 방향을 한 `select!` 루프에서 따로 poll하고, 터널마다 별도 task에서 돈다. `localctl::daemon`의 UDS와 QUIC 중계도 같은 `pump`를 쓴다. PTY를 멈춘 것은 splice의 읽기 중단 조건이 아니라 QUIC 연결 수준 흐름 제어다. 스트림이 읽지 않은 바이트는 그 스트림 창과 함께 연결 창도 붙잡고, credit은 앱이 읽어야 돌아온다. 상수를 고치는 길은 ROADMAP 범위 (b)가 이미 막았다. 연결 창을 키우면 M8 DoD 2 상한을 넘고, 스트림 창을 줄이면 `docs/design/protocol.md` §12가 기각한 128 KiB 사례로 돌아간다. quinn 0.11에는 스트림 종류별 수신 창이 없다는 것도 같은 절이 적었다. 그래서 고치려면 설계를 바꿔야 한다.

설계를 가르는 사실이 둘 더 있다.

- quinn-proto 0.11(잠금 파일 기준 0.11.18)의 `RecvStream::stop`은 그 스트림이 받아 두고 읽지 않은 바이트만큼 연결 수준 credit을 곧바로 돌려준다(`streams/recv.rs`의 `stop`, "Issue flow control credit for unread data"). 정체 스트림 하나를 끊으면 그 스트림이 붙잡던 최대 2 MiB가 바로 풀린다.
- 터널 스트림을 잘린 채 끝낼 때의 규율은 이미 있다. `SpliceGuard`가 QUIC 스트림을 reset·stop하고 로컬 TCP를 `SO_LINGER 0`으로 닫아 로컬 앱에 RST를 보인다(`docs/design/protocol.md` §7의 splice 중단 신호). 잘린 전송이 정상 EOF로 보이는 일은 없다.

## 결정

1. 연결마다 그 연결 위 터널 스트림의 정체 상태를 세는 장부를 `qsh-core`에 둔다. 장부는 스트림마다 수신 방향(QUIC에서 로컬로)의 마지막 진전 시각 하나만 갖는다. `pump`가 로컬 쪽에 바이트를 한 번 쓸 때마다 그 시각을 갱신한다. 장부에는 바이트 내용이 들어갈 자리가 없다.

2. 스트림의 로컬 쓰기가 `STALL_AGE` 넘게 한 바이트도 진전하지 않으면 그 스트림을 정체로 본다. 느리게라도 읽는 소비자는 정체가 아니다. `STALL_AGE`의 초안은 1초이고, 구현이 `tunnel_throughput_meets_raw_quinn_ratio`와 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms` 아래에서 정상 스트림이 정체로 잡히지 않음을 확인한 뒤 확정한다.

3. 한 연결에서 동시에 정체할 수 있는 터널 스트림 수의 상한을 `CONNECTION_RECEIVE_WINDOW / TUNNEL_STREAM_RECEIVE_WINDOW - 1`로 둔다. 오늘 값으로는 3이다. 정체 스트림이 이 수를 넘는 순간 마지막 진전이 가장 오래된 정체 스트림부터 끊어 상한 안으로 되돌린다. 그러면 정체 스트림이 붙잡는 credit의 합은 연결 창에서 스트림 창 하나를 뺀 값(6 MiB)을 넘지 못하고, PTY와 나머지 스트림에 적어도 스트림 창 하나만큼의 credit이 남는다. 상한은 상수 관계식으로 코드에 두어, 두 창 상수 중 하나가 바뀌면 같이 움직이게 한다.

4. 보조 조건을 하나 둔다. 연결의 `Connection::stats()`에서 peer가 보낸 `DATA_BLOCKED` 계수가 늘었고 정체 스트림이 하나 이상 있으면, 정체 스트림 수가 상한 안이어도 가장 오래 정체한 스트림 하나를 끊는다. 결정 3의 수 조건은 정체 스트림 하나가 창을 가득 채웠다고 가정한 상계라서 거의 멈췄지만 가끔 읽는 소비자 여럿이 창을 채우는 경우는 놓칠 수 있다. 이 조건이 그 경우를 받는다. 정체 스트림이 없으면 `DATA_BLOCKED`만으로는 아무것도 끊지 않는다. 그 경우는 포화 상태에서 창이 잠깐 빈 것이고, 앱이 읽는 중이라 곧 credit이 돌아온다.

5. 끊을 대상은 정체한 터널 스트림뿐이다. control, `SESSION_DATA`, `EXEC_DATA` 스트림은 이 장부에 오르지 않고 끊기지도 않는다.

6. 끊는 방법은 기존 `SpliceGuard` teardown과 같다. 수신 쪽은 `stop`, 송신 쪽은 `reset`을 하고 로컬 TCP는 `SO_LINGER 0`으로 닫는다. 로컬 앱은 RST를 보므로 전송이 정상적으로 끝났다고 오인하지 않는다. reset 코드는 새 내부 코드 `0x200E`(`RESET_CODE_TUNNEL_STALLED`)다. 진단과 audit의 상관관계를 잡으려고 `0x2007`과 가른다. 받는 peer는 이 값으로 분기하지 않는다(`docs/design/protocol.md` §16.5).

7. 끊을 때 끊는 쪽이 구조적 진단 한 줄을 낸다. 필드는 터널 식별자(`forward_id`나 `host:port`), 정체 시간, 방향별 바이트 수, 이유(`stalled_limit` 또는 `data_blocked`)다. payload는 싣지 않는다.

8. 이 규칙은 연결의 양 끝에 똑같이 적용된다. `splice_tcp_quic`을 부르는 네 자리(`tunnel/local.rs`, `tunnel/remote.rs` 두 곳, `server/tunnels.rs`)와 `localctl::daemon`의 UDS·QUIC 중계가 모두 같은 장부를 쓴다. 클라이언트 쪽 PTY 출력과 호스트 쪽 PTY 입력이 같은 모양으로 굶을 수 있기 때문이다.

9. 이 동작에는 설정 키를 두지 않는다. 끄는 스위치가 있으면 PRD §13의 약속이 설정에 따라 깨진다.

## 근거

후보 셋을 ROADMAP M13 범위 (b)가 요구한 축으로 비교한다. (가)는 수신 스트림을 앱 쪽 유계 버퍼로 비우고 그 버퍼가 차면 그 스트림만 끊는 안이다. (나)는 이 ADR의 결정이다. (다)는 연결당 동시 터널 스트림 수에 상한을 두어 창 합이 연결 창을 넘지 못하게 하는 안이다.

| 축 | (가) 스트림별 앱 버퍼 | (나) 연결 단위 정체 계수 | (다) 동시 터널 스트림 상한 |
|---|---|---|---|
| 세션당 buffer 8 MB | 새 메모리가 quinn 창 밖에 생긴다. 연결당 합이 스트림 수 × 버퍼 크기라 ADR-0010 기본값(principal당 터널 스트림 256)에서는 8 MB 안에 두려면 버퍼가 32 KiB 아래로 내려가야 하고 그러면 연결 단위 합계를 따로 세야 해서 (나)의 장부가 결국 필요하다 | 새 버퍼가 없다. 붙잡힌 바이트는 여전히 quinn의 8 MiB 연결 창 안이다 | 새 버퍼가 없다 |
| `tunnel_throughput_meets_raw_quinn_ratio`(≥80%) | `pump`가 읽기 task와 쓰기 task로 갈리고 버퍼 복사가 한 번 는다. 비율에 닿을 수 있는 변경이다 | 로컬 쓰기마다 시각 하나를 갱신할 뿐이다. `pump`의 read, `write_all` 구조는 그대로다 | 스트림 하나의 경로는 바뀌지 않는다 |
| 느린 소비자에게 보이는 의미 | 보내는 쪽보다 느린 소비자는 버퍼가 차는 순간 모두 끊긴다. 느린 디스크로 받는 다운로드나 잠시 멈춘 pager처럼 살아 있지만 느린 소비자가 대상이다. 흐름 제어가 사실상 폐기 정책으로 바뀐다. 끊김은 RST로 보인다 | 한 바이트도 진전하지 않는 소비자가 넷 이상 겹칠 때만, 가장 오래 멈춘 것부터 끊긴다. 느리게라도 읽는 소비자는 역압을 그대로 받는다. 끊김은 RST로 보인다 | 넷째 동시 연결부터 연결 자체가 거절된다. SOCKS `-D`로 브라우저를 쓰면 동시 연결 수십 개가 흔한데, 셋이면 정상 사용이 깨진다 |
| `docs/design/protocol.md` §16.2의 새 행 | 없다. reset 코드값은 §16.3이 동결 밖에 둔다 | 없다. 새 내부 코드 `0x200E`는 §7 목록과 §16.3·§16.5의 코드 범위 문구만 바꾼다 | 없다. 기존 `RESOURCE_EXHAUSTED` 거부 경로를 쓴다 |
| `docs/design/threat-model.md` §4 C의 새 행 | 느린 소비자로 PTY를 굶기는 위협과 통제가 오르지만, 버퍼 크기만큼 메모리를 쓰게 하는 새 표면도 같이 적어야 한다 | 느린 소비자로 PTY를 굶기는 위협 한 행이 오른다. 통제는 정체 상한과 `DATA_BLOCKED` 보조 조건, 핀 테스트는 N=4 진행 테스트다 | 새 행 대신 C4(quota) 행의 기본값이 사실상 3으로 바뀐다. ADR-0010의 principal당 256, forward당 64가 뜻을 잃는다 |

(나)가 다섯 축 모두에서 가장 작게 움직인다. 메모리 상한을 새로 증명할 것이 없고, 성능 경로에 새 복사가 없으며, 정상 사용에서 보이는 동작 변화가 "읽지 않는 연결 넷이 한꺼번에 멈춘" 경우로 좁다. 그 경우에 끊지 않으면 같은 연결의 셸이 멈춘다. 한 바이트도 읽지 않는 로컬 소비자를 위해 셸을 멈추는 것보다 그 소비자의 연결을 RST로 끝내는 쪽이 PRD §13의 우선순위와 맞다.

상한을 3으로 두면 하네스의 경계와 맞는다. N=3은 오늘도 초록이고 PTY가 진행한다. 결정 3은 그 상태를 건드리지 않고 넷째부터만 개입한다. 연결 창의 절반(정체 스트림 2개)을 문턱으로 두면 더 일찍 끊지만, 이미 PTY가 진행하는 상태에서 연결을 하나 더 죽이는 셈이라 얻는 것이 없다.

## 대안

- (가) 스트림별 앱 버퍼로 비우고 차면 그 스트림만 끊는다. ROADMAP 범위 (b)가 예로 든 안이다. 기각한다. 근거 표의 첫 열 그대로다. 역압이 사라져 살아 있지만 느린 소비자까지 끊기고, 8 MB 상한을 지키려면 연결 단위 합계를 따로 세야 해서 (나)의 장부를 결국 들인다.
- (다) 연결당 동시 터널 스트림을 3으로 제한한다. 기각한다. SOCKS `-D`와 여러 `-L`을 함께 쓰는 정상 사용이 깨지고, ADR-0010이 정한 quota 기본값을 사실상 덮는다.
- 연결 창을 키우거나 스트림 창을 줄인다. 기각한다. ROADMAP 범위 (b)와 `docs/design/protocol.md` §12가 이미 막았다. 앞은 M8 DoD 2의 8 MB 상한을 넘고, 뒤는 128 KiB 사례의 처리량 붕괴로 돌아간다.
- PTY를 별도 QUIC 연결에 싣거나 스트림 종류별 수신 창을 둔다. 비교 대상에서 뺐다. 앞은 연결 하나에 세션과 터널을 싣는 설계와 wire를 바꾸고(`docs/design/protocol.md` §16), 뒤는 quinn 0.11에 API가 없다(같은 문서 §12).
- 끊지 않고 진단만 낸다. 기각한다. PTY가 멈춘 사실을 알려도 셸은 여전히 멈춰 있다. ROADMAP DoD (b)는 진행과 echo p95를 단언한다.
- 정체 스트림의 reset 코드로 `0x2007`을 재사용한다. 채택하지 않는다. peer 동작은 같지만, 진단과 audit에서 "splice가 오류로 끊겼다"와 "정체 상한으로 끊었다"를 가를 수 없게 된다. 사용자가 코드 범위 문구를 건드리지 않는 쪽을 더 무겁게 보면 이 안으로 바꿀 수 있고, 결정 6의 한 문장만 바뀐다.

## 결과

- `crates/qsh-core/src/tunnel/splice.rs`의 `pump`와 `splice_tcp_quic`, `localctl::daemon`의 중계가 연결 단위 장부에 진전 시각을 기록하고, 장부가 결정 3·4의 조건으로 대상 스트림의 guard를 발동시킨다. `CONNECTION_RECEIVE_WINDOW`와 `TUNNEL_STREAM_RECEIVE_WINDOW`의 값은 바뀌지 않는다. 두 상수의 doc에는 창 관계가 더는 PTY 기아를 막는 유일한 방어가 아니라는 문장을 더한다.
- `crates/qsh-testkit/tests/tunnel_stalled_streams.rs`의 네 테스트가 strict에서 초록이 되어야 하고, 그 테스트를 `ci.yml` acceptance job에 `QSH_ACCEPTANCE_STRICT`로 넣는다. `CLAUDE.md` Commands 절의 acceptance 목록과 `docs/design/testing.md`의 게이트 환경변수 표, L9/L10의 "덮는 축은 포화(고속) 하나다" 문단을 같이 고친다.
- 고치지 않은 기준으로 `tunnel_throughput_meets_raw_quinn_ratio`, `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`, `transport_config_sets_connection_receive_window`, `tunnel_stream_receive_window_never_regresses_below_quinns_own_default`, `socks_curl`이 초록이어야 한다. 정체 판정을 끄는 mutation 하나가 N=4 진행 테스트를 붉혀야 한다.
- 새 단위 테스트는 적어도 넷을 고정한다. 상한을 넘은 정체 스트림만 끊긴다. 끊긴 스트림 말고 다른 터널 스트림과 PTY는 영향을 받지 않는다. 끊긴 스트림은 로컬 앱에 정상 종료가 아니라 RST로 보인다. 느리게라도 읽는 스트림은 정체로 잡히지 않는다.
- `docs/design/protocol.md` §7의 내부 reset 코드 목록에 `0x200E`를 더하고, §16.3·§16.5의 코드 범위 문구를 `0x200E`까지로 고친다. §16.2 상호운용 계약 표에는 행이 늘지 않는다. §12의 backpressure 서술에 이 정체 상한을 더한다.
- `docs/design/threat-model.md` §4 C에 "읽지 않는 로컬 소비자가 터널 스트림 창으로 연결 창을 채워 PTY를 굶긴다" 행이 오른다. 통제는 결정 3·4이고 핀 테스트는 N=4 진행 테스트와 위 단위 테스트다. 잔여 위험으로 `EXEC_DATA` 스트림의 정체는 이 장부 밖이라는 사실을 적는다.
- wire, `.proto`, `qsh.cli/v1`, `ErrorCode`는 바뀌지 않는다.
- 이 ADR이 승인되면 `docs/ROADMAP.md` M13 DoD (b)의 "수정이 설계 선택이면 ADR이 먼저 선다"가 채워지고 splice 수정이 열린다.
