# ADR-0052: M22의 범위. 대화형 세션은 host가 터미널 상태를 들고 client에 최신 화면과의 차이만 보내며, 화면 갱신은 QUIC DATAGRAM에 싣고 스트림으로 되돌아갈 수 있다. 전송 손잡이는 관측한 연결 통계의 순수 함수인 적응 정책이 정한다

날짜: 2026-11-06
상태: 승인됨

개정 관계: ADR-0050 결정 5의 M22를 구체화한다. 다음을 개정한다.
- ADR-0043 결정 4와 `docs/design/protocol.md` §14의 "wire가 datagram에 기대지 않는다"(결정 7). datagram은 선택 운반체가 되고, 모든 datagram 메시지는 스트림에 같은 뜻의 짝이 있다. 스트림만으로 프로토콜이 완결된다는 성질은 그대로다.
- ADR-0021 결정 1의 `[transport].keep_alive_ms`. 키를 적으면 오늘처럼 고정값이고, 키가 없을 때만 적응 정책이 15초 아래로 줄일 수 있다(결정 13).
- `docs/design/protocol.md` §4(capability 둘), §12(bulk 양보), 새 §18(화면 동기화).

개정하지 않는 것: 0-RTT 전면 금지(`docs/design/protocol.md` §2, §16.2, threat model A9·g5), BBR(§1), MTU 기본값, `TUNNEL_STREAM_RECEIVE_WINDOW` 2 MiB와 `CONNECTION_RECEIVE_WINDOW` 8 MiB(§12), keep-alive 범위 `1000..=20000`ms와 idle 45초 고정(ADR-0021 결정 2), replay ring과 그 바이트 계약(ADR-0004, `docs/design/protocol.md` §8), ADR-0048의 재생분 질의 제거(바이트 경로에 그대로 남는다).

## 맥락

ADR-0050은 M22를 "대화형 form에서 host가 터미널 상태를 들고 client에는 현재 화면과의 차이만 보낸다"로 정했다. 오늘 대화형 attach는 PTY가 낸 바이트를 하나도 빼지 않고 순서대로 나른다(`SessionFrame.Output`, `docs/design/protocol.md` §7·§8). 이 방식에서 생기는 문제는 셋이다.

1. 출력이 몰리면(`yes`, 큰 `cat`, 빌드 로그) 화면에 닿을 때쯤에는 이미 지나간 바이트를 끝까지 그린다. Ctrl-C는 바로 닿아도 그 결과가 보이려면 쌓인 바이트가 다 흘러가야 한다.
2. 손실이 있는 경로에서는 스트림의 순서 보장 때문에 한 패킷이 빠지면 뒤의 모든 화면 갱신이 재전송을 기다린다(head-of-line blocking).
3. 재부착은 ring에 남은 바이트를 다시 흘린다. ADR-0048이 막은 재생분 터미널 질의 누출과 폭이 다른 터미널의 재그리기 찌꺼기(`docs/campaigns/p1-windows.md` §7 W1)가 여기서 나온다.

사용자는 같은 자리에서 워크로드, proxy 사용, 네트워크 상태에 따라 전송이 스스로 맞춰지기를 요청했다.

### 측정 (2026-11-05~06, 에이전트)

Linux user network namespace 안의 veth 한 쌍에 netem을 걸고 20 Mbit 링크로 쟀다. 하네스는 일회용 프로그램이었고 지금은 남아 있지 않다. 그래서 아래 수치는 방향을 정하는 근거로만 쓰고, M22는 같은 측정을 다시 돌릴 수 있는 벤치를 `scripts/` 아래에 남기는 것을 수용 기준으로 진다(결정 18의 8). staleness의 정확한 정의도 하네스와 함께 사라졌다. 수치로 보아 "host에서 상태가 생긴 시각부터 client가 그 상태 이상을 적용한 시각까지에서 기저 단방향 지연을 뺀 값"으로 읽고, 새 벤치가 이 정의를 고정한다.

| 질문 | 관측 | 이 ADR에서 쓰는 곳 |
|---|---|---|
| 화면 갱신을 DATAGRAM과 스트림 중 어디에 싣나 | RTT 150 ms, 손실 3~5%에서 staleness p95가 DATAGRAM 17~19 ms, 스트림 162~176 ms. datagram 프레임 유실률은 손실률과 같았다 | 결정 6, 결정 12 (c) |
| 혼잡 제어 | BBR은 문제없었다. Cubic은 손실 아래 화면 갱신이 무너졌다 | BBR 유지 |
| MTU | 기본값으로 충분했다. 최대 datagram 크기는 1500 링크에서 1452, 1280 링크에서 1230바이트 | MTU 기본값 유지, 결정 6의 조각 크기 |
| 키 입력 에코의 꼬리 지연 | 손실 아래 RTO를 따라간다. 상태 재동기화나 예측만 이것을 없앤다 | 결정 8, 결정 12 (d) |
| 공유 병목에서 bulk와 대화형 | 깊은 netem 큐의 bufferbloat가 지배했다. QUIC 스트림 우선순위도, 연결을 따로 여는 것도 도움이 되지 않았다 | 결정 12 (a), 얕은 큐로 다시 잼(결정 18의 6) |
| qsh 안의 qsh(중첩 전송) | 바깥을 DATAGRAM으로 나를 때가 스트림보다 낫다. 안쪽 p99 913 ms 대 1880 ms, 처리량 2.10 대 1.64 MB/s | 결정 12 (f) |

### 오늘의 전송 설정 (`crates/qsh-transport/src/endpoint.rs`의 `transport_config`)

BBR(`BbrConfig::default()`), `send_fairness(true)`, 스트림 수신 창 2 MiB, 연결 수신 창 8 MiB, keep-alive 15초(`[transport].keep_alive_ms`), idle 45초 고정, bidi 스트림 1024개. 우선순위 band는 control 200, session 100, exec 50, tunnel/file 0이다(§12). QUIC DATAGRAM은 응용이 쓰지 않는다. datagram 관련 transport parameter와 버퍼는 따로 설정하지 않아 quinn 기본값에 맡겨져 있다. 연결 통계는 `ConnStats`(`rtt`, `rx_frames`, `peer_blocked_events`, `peer_stream_blocked_events`, `rx_raw_datagrams`, `lost_packets`)로 나온다.

## 결정

### 범위

1. **화면 동기화는 대화형 PTY attach에만 쓴다.** 로컬 stdout이 TTY이고 사람 모드(`--json`/`--jsonl`이 아님)인 `qsh host`, `qsh session attach`, `qsh host -t cmd`가 대상이다. 다음은 지금 그대로 바이트 경로다.
   - `--json`/`--jsonl`의 `session.output`, `session read`(`--wait`, `--follow`), `qsh.event/v1`. 바이트 계약(`docs/CLI.md` §2.3·§6.4)은 바뀌지 않는다.
   - `exec`(PTY 없는 실행)와 `-T`. stdout·stderr는 바이트 그대로의 스트림이다.
   - 로컬 stdout이 TTY가 아닌 attach(`qsh host | tee log`).
   - 터널(`-L`/`-R`/`-D`)과 `qsh cp`. 스트림과 raw bytes 그대로이고 DATAGRAM에 싣지 않는다.

2. **host의 터미널 상태.** host는 세션마다 터미널 에뮬레이터 하나를 둔다(`crates/qsh-core/src/screen/`). 에뮬레이터는 I/O가 없는 상태 기계이고, pty_reader가 ring에 쓴 바이트를 같은 task 안에서 차례로 먹인다. ring은 그대로 남아 바이트 경로와 재생분을 계속 맡는다. 에뮬레이터는 네트워크도 소비자도 기다리지 않으므로 "pty_reader는 절대 블록되지 않는다"(`docs/design/architecture.md` §3)는 유지된다. 에뮬레이터 crate는 첫 스텝에서 고르고, 기준은 순수 Rust, I/O 없음, fuzz 가능, `cargo deny` 통과, 세 OS 동작이다. Windows ConPTY 출력도 같은 에뮬레이터가 먹는다.
   - 에뮬레이터는 화면 동기화 capability(결정 9)를 광고하는 host의 모든 PTY 세션에서 돈다. 떼어 둔 세션도 재부착 때 현재 화면 한 장을 바로 보내야 하기 때문이다.
   - 메모리는 세션당 화면 하나(셀 수 × 셀 크기)와 결정 10의 history 상한, attach당 기준 상태 하나로 묶인다. 상한은 `docs/ROADMAP.md` M8 DoD 2의 세션당 8 MB 예산과 별도 항목으로 threat model에 적는다.

3. **터미널 질의에는 host 에뮬레이터가 답한다.** 화면 동기화 경로에서는 로컬 터미널이 PTY의 바이트를 보지 못하므로, 앱이 보낸 DA1/DA2, DSR/CPR, 에뮬레이터가 구현한 모드의 DECRQM에는 host 에뮬레이터가 자기 상태로 답하고 그 답을 PTY 입력에 쓴다(mosh와 같다). OSC 10/11 색 질의는 client가 attach 때 알린 전경·배경색(결정 9의 선택 필드)으로 답하고, 알리지 않았으면 답하지 않는다. 그 밖의 질의(XTVERSION, 그래픽 프로토콜 질의 등)에는 답하지 않는다. 바이트 경로의 질의 처리(ADR-0048)는 바뀌지 않는다.

4. **화면 밖의 효과.** 창 제목(OSC 0/2), 종(BEL), 클립보드 쓰기(OSC 52), 하이퍼링크(OSC 8)는 화면 차이에 딸린 효과 목록으로 실어 client가 로컬 터미널에 다시 낸다. sixel·kitty 그래픽 같은 이미지 프로토콜은 화면 동기화에서 그리지 않는다. 필요한 사용자는 결정 15의 `--screen-sync=off`로 바이트 경로를 쓴다.

### 동기화 프로토콜

5. **상태 번호와 차이.** host 에뮬레이터의 상태에는 세션 수명 동안 단조 증가하는 `state_num`이 붙는다. 상태에는 그 상태가 반영한 누적 출력 offset(`output_seq`, §8)이 함께 기록된다. 갱신 메시지 `ScreenUpdate`는 `{base_num, new_num, output_seq, diff, effects, state_hash}`다.
   - `diff`는 VT 바이트열이 아니라 구조화된 셀 차이다. 크기, 커서, 모드 비트, 바뀐 행마다 (열 위치, 글자, 속성) run의 목록이다. 양쪽 에뮬레이터 버전이 달라도 같은 결과를 내고, decode가 fuzz 표면이 된다.
   - `state_hash`는 새 상태를 정규화한 바이트의 BLAKE3 앞 8바이트다. client는 적용 뒤 같은 값을 계산해 대조하고, 다르면 base 0(전체 화면)을 요청한다.
   - client는 적용한 최신 `state_num`을 `ScreenAck{state_num}`로 알린다. 최근 적용한 상태를 8개까지 보관한다.

6. **운반체 둘.** 같은 메시지를 두 가지로 나른다.
   - **DATAGRAM.** host는 client가 마지막으로 ack한 상태를 base로 최신 상태까지의 차이를 보낸다. 각 갱신은 base만 있으면 독립으로 적용되므로 잃어도 다음 갱신이 대신한다. 오래된 화면은 다시 보내지 않고 건너뛴다. 한 갱신이 `max_datagram_size`(연결마다 quinn이 알려 주는 값, PMTU를 따라 바뀐다)를 넘으면 조각(`part`, `parts`)으로 나누고, client는 한 상태의 조각이 모두 와야 적용한다. 조립 중인 상태는 channel당 하나, 버퍼는 1 MiB 상한이고, 더 새 상태의 조각이 오면 버린다. client가 가진 base가 아닌 갱신은 버리고 ack를 다시 보낸다.
   - **스트림.** 세션 data 스트림(`SESSION_DATA`)에 `SessionFrame`의 새 항목으로 싣는다. 순서와 도달이 보장되므로 base는 마지막으로 **보낸** 상태다. host는 그 스트림의 송신 깊이가 `SEND_DEPTH_CAP_BYTES`(128 KiB)를 넘는 동안 새 갱신을 쓰지 않고, 깊이가 줄면 그때의 최신 상태까지 한 번에 보낸다. 스트림에서도 중간 화면은 건너뛰고, 재전송 대기만 남는다. 한 갱신이 `DATA_FRAME_MAX`(64 KiB)를 넘으면 같은 `part`/`parts` 규칙으로 나눈다.

7. **datagram과 transport 중립.** ADR-0043 결정 4와 `docs/design/protocol.md` §14의 "wire가 datagram에 기대지 않는다"를 이렇게 바꾼다. "datagram은 선택 운반체다. datagram으로 나르는 모든 메시지는 스트림에 같은 뜻의 짝이 있고, 스트림만으로 프로토콜이 완결된다. datagram 안의 메시지는 QUIC stream ID나 transport parameter가 아니라 자기 머리의 channel id로 식별한다."
   - `qsh-transport`의 중립 파사드에 `Connection::max_datagram_size() -> Option<usize>`, `send_datagram`, `read_datagram`을 더한다. datagram 층이 없는 백엔드는 `None`을 돌려주고 호출자는 스트림을 쓴다. `crates/qsh-transport/tests/it/conformance.rs`가 이 행동을 고정한다. `qsh-core`·`qsh-cli`는 여전히 quinn 이름을 쓰지 않는다.
   - datagram 수신 버퍼와 송신 버퍼는 quinn 기본값에 맡기지 않고 명시 상수로 정한다(`DATAGRAM_RECEIVE_BUFFER` 256 KiB, `DATAGRAM_SEND_BUFFER` 256 KiB가 시작값이고 벤치로 확정한다). 0-RTT 다섯 상수처럼 실제 `TransportConfig`를 읽는 유닛 테스트가 값과 BBR 선택을 함께 고정한다. 0-RTT가 꺼져 있으므로 datagram은 1-RTT 키로만 나간다.
   - datagram 머리의 channel id는 attach가 ACL을 통과한 뒤 host가 발급하는 128비트 난수이고, 그 연결에서만 유효하다. 모르는 channel id의 datagram은 버리고 세기만 한다. datagram으로는 어떤 리소스도 생기지 않는다.

8. **입력의 datagram 사본.** 키 입력은 지금처럼 세션 data 스트림의 `Input{input_seq, data}`로 보내고 이것이 정본이다. datagram 운반체가 살아 있으면 같은 `Input`을 datagram으로도 한 번 보낸다. host는 사본의 시작 offset이 그 attach 축의 적용 offset과 정확히 같을 때만 적용하고(`docs/design/protocol.md` §10-5의 축), 아니면 버린다. 스트림으로 늦게 온 같은 바이트는 기존 중복 제거가 버린다. 그래서 무손실·무중복(PRD §8)은 스트림이 지키고, 손실 아래의 입력 지연은 사본이 줄인다. QUIC 패킷 번호 보호가 datagram 재전송 공격을 막고, 막지 못하더라도 offset 규칙이 같은 바이트를 두 번 적용하지 않는다.

9. **capability와 wire 추가.** 모두 additive이고 capability로 막는다(`docs/design/protocol.md` §16.4, ADR-0019 결정 4의 규칙).
   - capability `screen.v1`: host가 에뮬레이터를 돌리고 `ScreenUpdate`/`ScreenAck`를 처리한다. `datagram.v1`: 이 peer가 결정 6·8의 datagram 메시지를 처리한다. 둘 다 모든 빌드가 광고한다.
   - `SessionOpen`과 `SessionAttach`에 선택 필드 `screen`(`ScreenRequest{cols, rows, fg, bg}`)을 더한다. 보내는 쪽은 협상된 교집합에 `screen.v1`이 있을 때만 세팅한다.
   - `SessionOpened`와 `SessionAttached`에 선택 필드 `screen_channel`(bytes)을 더한다. 비어 있으면 host가 화면 동기화를 받지 않은 것이고 client는 바이트 경로로 간다.
   - `SessionFrame` oneof에 `ScreenUpdate screen_update = 7`, `ScreenAck screen_ack = 8`을 더한다.
   - 새 message `DatagramFrame{bytes channel = 1; oneof body { ScreenUpdate screen_update = 10; ScreenAck screen_ack = 11; Input input = 12; }}`. datagram 하나에 하나이고 길이 머리가 없다(datagram 자체가 경계다). `datagram.v1`이 교집합에 있고 `max_datagram_size()`가 `Some`일 때만 보낸다.
   - 화면 동기화 attach에서 host는 `Output`을 보내지 않는다. `Exit`, `Resize`, `Input`, `InputAck`는 그대로 쓰고, `Gap`은 생기지 않는다(재생분이 없다).

10. **history(스크롤백).** 기본 화면(대체 화면이 아닌)의 맨 위에서 밀려난 행은 host 에뮬레이터가 세션당 history에 모으고(기본 5000행, 바이트 상한 함께), 연결이 한가할 때 세션 data 스트림으로 순서대로 보내 로컬 터미널의 스크롤백에 남게 한다. 갱신이 밀리면 history 전송을 줄이고, 건너뛴 행 수는 `--- N lines skipped ---` 한 줄로 알린다. 조용히 건너뛰지 않는다는 PRD §8의 규칙을 화면 경로에도 적용한 것이다. 재부착은 현재 화면 한 장만 보낸다. 지나간 출력 전체는 바이트 그대로 `qsh session read`가 준다.

11. **재부착, 떼어 두기, resume.** 재부착과 resume은 지금 절차(`docs/design/protocol.md` §10)를 그대로 지난다. 다른 점은 data 스트림이 열린 뒤 ring 재생 대신 base 0의 `ScreenUpdate` 한 장(현재 화면)이 첫 갱신이라는 것뿐이다. `last_output_seq`는 화면 경로에서 쓰이지 않고, 같은 세션에 바이트 경로로 다시 붙으면 지금처럼 그 offset부터 재생한다. writer lease, read-only 강등, 입력 축 규칙은 바뀌지 않는다. 여러 attach가 있으면 attach마다 자기 ack 상태를 갖는다. 화면 크기는 PTY 크기 하나이고(지금과 같다), 로컬 터미널이 더 작거나 크면 client가 자르거나 채운다.

### 적응 정책

12. **정책은 순수 함수다.** `qsh_core::adapt::decide(observed, previous) -> Knobs`가 연결마다 1초에 한 번, 그리고 관측값이 문턱을 넘을 때 돈다. I/O도 시계도 읽지 않으므로 표 하나로 시험한다. `previous`는 직전 `Knobs`이고 문턱의 hysteresis에만 쓴다.

    입력 `Observed`는 다음이다.
    - `srtt`, `rtt_var`, `min_rtt`. quinn이 주는 `rtt`를 1초마다 표본으로 받아 qsh-core가 EWMA 분산과 10초 창 최소값을 센다.
    - `loss`. 최근 5초의 `lost_packets` 증가분을 `sent_packets` 증가분으로 나눈 값. `ConnStats`에 `sent_packets`, `cwnd`, `current_mtu`를 더한다(공개 통계에 있는 값만. bytes in flight는 quinn 0.11 공개 통계에 없으면 선택 입력으로 두고 비운다).
    - `queue_delay = srtt - min_rtt`.
    - `interactive`. 최근 2초 안에 키 입력이나 화면 갱신이 있었는가.
    - `bulk`. 최근 1초 안에 터널이나 파일 스트림의 바이트가 움직였는가.
    - `datagram`. `max_datagram_size()`와 capability 교집합, 그리고 결정 12 (c)의 응답 없음 판정.
    - `nested`. 이 연결이 jump나 proxy 안에 실려 있는가. M26이 세우는 값이고 M22에서는 늘 거짓이다.
    - `user`. 사용자가 고정한 값(결정 15).

    출력 `Knobs`와 규칙은 다음이다. 숫자는 시작값이고 벤치로 확정한 값은 이 ADR 개정 이력과 정책 표 테스트에 함께 적는다.

    | 손잡이 | 규칙 | 근거 |
    |---|---|---|
    | (a) bulk 양보 | `interactive`이고 `bulk`이면 `Yield{target: 25 ms}`, 아니면 `Off`. `Yield`에서는 터널·파일 송신(splice와 `FILE_DATA` 펌프)이 LEDBAT 식 송신 예산을 따른다. `queue_delay`가 target을 넘으면 예산을 절반으로, 아래면 RTT마다 조금씩 늘린다. 하한은 `max(64 KiB/s, 추정 대역의 5%)`라 bulk가 굶지 않는다. `interactive`가 꺼지면 2초 뒤 `Off`로 돌아가 오늘의 처리량을 낸다 | 깊은 큐에서는 우선순위도 별도 연결도 효과가 없었다. 병목 큐를 비우는 것은 보내는 양을 줄이는 쪽뿐이다. BBR은 연결 단위라 스트림마다 혼잡 제어를 둘 수 없으므로 응용 층 예산으로 한다 |
    | (b) 화면 주기 | 갱신 간격 `clamp(srtt / 2, 20 ms, 250 ms)`. 첫 변화 뒤 모으는 시간 `clamp(srtt / 8, 1 ms, 8 ms)` | mosh의 간격 규칙. 모으는 시간을 RTT에 비례시켜 loopback·LAN의 에코 게이트(p95 < 10 ms)를 지킨다 |
    | (c) 운반체 | `datagram`이 없으면 `Stream(datagram_unavailable)`. datagram 갱신이 4×srtt 넘게 연속으로 ack되지 않는데 스트림 ack는 오면 `Stream(datagram_unacked)`로 바꾸고 30초마다 datagram을 다시 시험한다. 그 밖에는 갱신마다 조각 수 k로 `(1 - loss)^k < 0.5`이면 그 갱신만 `Stream(fragments_lossy)`, 아니면 `Datagram` | 손실 아래 datagram이 스트림보다 staleness가 열 배 낮았다. 조각이 많은 큰 갱신은 모두 도착할 확률이 낮아 스트림이 낫다. datagram을 버리는 중간 장비는 응답 없음으로 알아챈다 |
    | (d) 예측 | `srtt > 30 ms`면 `Display`, `< 20 ms`면 `Off`. `srtt > 80 ms`면 `Underline`, `< 50 ms`면 `Display`로 내린다. 사이 구간은 `previous`를 유지한다. M22는 값을 계산해 내놓기만 하고, 예측 자체와 echo-off·전체 화면 앱·연속 오예측의 차단은 M23이 한다 | mosh의 문턱과 hysteresis |
    | (e) keep-alive | `[transport].keep_alive_ms`가 있으면 그 값(`user_override`). 없으면 15초에서 시작하고, 한가한 g초 뒤 peer 주소가 바뀐 것(NAT 재바인딩)을 보면 `clamp(g / 2, 1 s, 15 s)`로 줄인다. 늘리지는 않는다. 줄인 값은 그 프로세스가 그 host에 대해 기억한다 | NAT 수명은 망마다 다르다. 손으로 정하지 않아도 끊김을 한 번 본 뒤에는 맞춘다. 배터리를 위해 기본은 지금보다 짧아지지 않는다 |
    | (f) 바깥 운반체 | `nested`이고 바깥 연결에 `datagram`이 있으면 `Datagram`, 아니면 `Stream`. M26의 jump가 이 값을 읽는다 | 중첩 측정에서 바깥 datagram이 안쪽 p99를 절반으로 줄였다. 바깥 스트림은 안쪽 QUIC 재전송 위에 또 재전송을 얹는다 |

    MTU는 quinn 기본값(PLPMTUD 포함)을 그대로 쓰고, 정책은 `max_datagram_size()`를 읽기만 한다. 혼잡 제어는 BBR로 고정하고 정책 손잡이로 두지 않는다.

13. **keep-alive의 적용 수단.** quinn이 연결 도중 keep-alive 간격을 바꾸는 API를 내놓으면 그것을 쓰고, 없으면 control 스트림의 `Ping`(이미 있는 frame)을 정책 간격으로 보낸다. 어느 쪽이든 wire는 바뀌지 않고, ADR-0021의 범위 `1000..=20000`ms와 idle 45초 고정은 그대로다. 수단은 첫 스텝에서 quinn 0.11 API를 확인해 정한다.

14. **보이는 곳.**
    - `qsh doctor <host>`가 pin된 host에 3초짜리 측정 연결을 맺고, `DoctorData`에 선택 필드 `transport`를 싣는다. 필드는 `rtt_ms`, `rtt_var_ms`, `min_rtt_ms`, `loss_pct`, `max_datagram_bytes`(없으면 `null`), `screen_sync`(`"datagram"`/`"stream"`/`"off"`), `frame_interval_ms`, `bulk_yield`(`"off"`/`"yield"`), `prediction`(`"off"`/`"display"`/`"underline"`), `keep_alive_ms`, `nested`, `reasons`(문자열 배열)다. 연결하지 못했으면 필드가 없다. 측정 연결은 대화형 트래픽이 없으므로 (a)는 늘 `off`로 나오고, 이 사실을 human 렌더가 한 줄로 적는다.
    - 새 doctor 코드는 둘이다. `screen_sync_unsupported`(info, peer가 `screen.v1`을 광고하지 않음)와 `datagram_unavailable`(info, `datagram.v1`이 없거나 경로가 DATAGRAM을 나르지 않음). `EXPECTED_DOCTOR_CODES`에 더한다.
    - 대화형 client는 정책 출력이 바뀔 때마다 stderr에 tracing target `qsh::adapt`의 한 줄 JSON을 남긴다(`qsh::recovery`와 같은 규율, 통계와 손잡이 값만, PTY 내용 없음). M23의 상태 줄은 같은 값을 `qsh-core`의 `Ops`에서 읽어 짧게 그린다.
    - `reasons`의 어휘는 열린 문자열이다. 시작 집합은 `rtt_high`, `rtt_low`, `loss_high`, `queue_delay_high`, `interactive`, `bulk`, `datagram_unavailable`, `datagram_unacked`, `fragments_lossy`, `nat_rebind`, `nested`, `user_override`이다.

15. **사용자 손잡이.** ADR-0050 결정 2대로 플래그와 `qsh config` 키를 함께 둔다.
    - `--screen-sync=auto|on|off`, 키 `[interactive].screen_sync`(기본 `auto`). `auto`는 peer가 `screen.v1`을 광고하면 쓰고 아니면 바이트 경로로 조용히 간다. `on`은 peer가 광고하지 않으면 `UNSUPPORTED`(`details.reason: "screen_sync_unsupported"`)로 끝난다. `off`는 오늘의 바이트 경로다.
    - 키 `[transport].adaptive = "on"|"off"`(기본 `on`). `off`면 (a) `Off`, (b) mosh 기본값 고정, (c) datagram이 있으면 `Datagram`, (d) `Off`, (e) 오늘의 15초 고정이다.
    - 새 오류 코드는 없다. 새 `details.reason`은 `screen_sync_unsupported` 하나다.

### 계약과 경계

16. **JSON 추가는 모두 additive다.** `DoctorData.transport`, doctor 코드 둘, `capabilities` 결과의 새 문자열 둘(`capabilities.json` golden은 `QSH_UPDATE_FIXTURES=1`로 다시 만들고 계약 변경과 같은 무게로 본다), `config.list`의 새 키 둘. 기존 fixture는 고치지 않고 새 fixture(`doctor_transport.json`)를 더해 `REQUIRED_FIXTURES`에 올린다. `--json`/`--jsonl`의 stdout은 지금처럼 JSON뿐이다.

17. **층 배치.**
    - `qsh-proto`: 새 message와 diff codec(sans-IO, fuzz 표면).
    - `qsh-transport`: datagram 파사드와 상수, `ConnStats` 추가 필드.
    - `qsh-core`: host 에뮬레이터, 상태 번호와 차이 계산, client 쪽 화면 모델(M23 예측이 그 위에 선다), 적응 정책과 bulk 송신 예산, `Ops`로 내놓는 정책 상태.
    - `qsh-cli`: client 화면 모델의 그리기 연산을 로컬 터미널의 escape 바이트로 바꾸는 렌더러뿐이다. 정책 판단은 하지 않는다.
    - 새 디렉터리 `crates/qsh-core/src/screen/`와 `crates/qsh-core/src/adapt/`는 `crates/qsh-core/src/`의 `quinn::` 금지를 그대로 받는다. `xtask arch`에 새 경로 금지는 더하지 않는다.

### 수용 기준(M22 DoD)

18. 1. **손실 아래 staleness.** testkit chaos proxy(L4)에 단방향 75 ms 지연과 5% `drop`을 걸고 `QSH_ACCEPTANCE_SLOW`에서 도는 `screen_sync_staleness_under_loss`가 datagram 운반체의 staleness p95 ≤ 50 ms를 확인한다. 같은 조건의 스트림 운반체는 중간 상태를 건너뛰고(적용한 상태 수 < 만든 상태 수) 마지막 상태가 정지 후 2×RTO 안에 맞는 것을 확인한다. netem 벤치(8번)에서는 datagram p95 ≤ 25 ms를 기록한다.
    2. **출력 홍수 아래 Ctrl-C.** RTT 150 ms·손실 3%에서 `yes`를 돌리는 세션에 Ctrl-C를 보내고 프롬프트가 client 화면에 보이기까지 ≤ 1 s(`ctrl_c_reaches_a_flooding_session_within_budget`). 바이트 경로에서 같은 시나리오의 값을 함께 기록한다.
    3. **재부착은 화면 한 장.** 떼어 둔 세션이 10 MB를 낸 뒤 재부착하면 첫 갱신까지 나르는 바이트가 화면 한 장의 상한 안이고, client 화면이 host 상태의 `state_hash`와 맞는다(`reattach_sends_one_screen_not_the_backlog`). 재생분 질의 누출 시험(ADR-0048)은 화면 경로에서 질의가 로컬 터미널에 닿지 않음을 함께 단언한다.
    4. **옛 peer와 운반체 fallback.** testkit의 capability를 가린 peer로 세 조합을 돈다. 새 client와 옛 host는 바이트 경로이고 `Output` 바이트가 오늘과 같다. 옛 client와 새 host에서 host는 `ScreenUpdate`를 보내지 않는다. `screen.v1`은 있고 datagram이 없는 연결은 스트림 운반체로 화면 동기화를 한다. 경로가 datagram만 버리는 chaos 정책에서는 `datagram_unacked`로 스트림으로 바뀐다.
    5. **정책 표 테스트.** `adapt::decide`의 표가 결정 12의 손잡이마다 문턱 양쪽, hysteresis 사이 구간, `user`와 `[transport].adaptive = "off"`의 덮어쓰기를 한 행씩 고정한다. bulk 송신 예산 상태 기계도 주입된 시계 위에서 같은 방식으로 시험한다. `docs/design/testing.md` L2에 올린다.
    6. **bulk 양보.** chaos proxy에 대역과 큐 깊이를 거는 `rate(bps, queue)` fault를 더하고, 20 Mbit·RTT 50 ms에서 깊은 큐(≥ 500 ms 분량)와 얕은 큐(≤ 25 ms 분량) 두 프로필로 포화 터널과 키 에코를 함께 돌린다. 양보가 켜졌을 때 에코 p95 ≤ min_rtt + 50 ms, 대화형이 없을 때 터널 처리량 ≥ 링크의 80%. 기존 loopback 게이트(포화 터널 + 에코 p95 < 10 ms, `tunnel_echo_under_load`)와 `tunnel_throughput`도 그대로 통과한다. 얕은 큐 재측정 결과는 개정 이력에 적는다.
    7. **doctor fixture.** `doctor_transport.json` fixture와 `EXPECTED_DOCTOR_CODES`의 두 코드, `DoctorData.transport`가 연결 실패 때 빠지는 경우를 시험한다.
    8. **재현 가능한 벤치.** `scripts/netbench/`가 root 없이(`unshare -rn`의 user netns, veth, netem) 맥락 절의 여섯 질문을 다시 잰다. 프로필(RTT, 손실, 대역, 큐 깊이)은 파일로 고정하고, 결과는 한 줄 JSON이며, staleness의 정의를 README에 적는다. UDP 4433은 쓰지 않고 임시 포트만 쓴다. `scripts/README.md`에 올리고, 첫 결과를 이 ADR 개정 이력에 남긴다. 사람 회차가 아니라 에이전트가 돌리는 도구이고, user netns를 막은 CI 러너에서는 돌리지 않는다.
    9. **바이트 계약 불변.** `session.output`·`session read`·exec·터널·`qsh cp`의 기존 테스트와 fixture가 diff 없이 통과한다. 0-RTT 유닛(`tls_configs_disable_0_rtt_and_session_resumption`)이 그대로이고, BBR과 datagram 버퍼 상수를 읽는 새 유닛이 더해진다.
    10. **fuzz.** `fuzz/`에 diff decode, `DatagramFrame` decode, host 에뮬레이터 입력의 세 타깃을 더하고 `fuzz/README.md`의 목록을 고친다.
    11. **성능.** 세션 안에서 100 MB를 `cat`할 때 host의 처리량이 에뮬레이터를 끈 빌드의 0.5배 이상이다(nightly perf judge에 항목을 더한다). 처음 값 0.8배는 2026-11-06 Dave가 고쳤다(개정 이력).
    12. **세 OS.** 1~4와 7은 Linux·macOS·Windows CI에서 돈다. Windows host는 ConPTY 출력으로 같은 시험을 통과한다.
    13. threat model에 결과 절의 행이 고정 테스트와 함께 들어간다.

## 근거

- **화면 동기화가 세 문제를 구조로 없앤다.** 지나간 바이트를 그리지 않으므로 출력 홍수 뒤의 지연이 없고, 갱신마다 독립이므로 손실이 뒤 갱신을 붙잡지 않으며, 재부착이 재생이 아니므로 재생분 질의와 재그리기 찌꺼기가 생길 자리가 없다. mosh가 같은 방식으로 이 문제들을 풀었다.
- **바이트 경로를 남기는 이유.** 에이전트와 스크립트는 바이트를 정확히 받아야 하고(`qsh.cli/v1`), 화면 모델은 그 정확성을 보장하지 않는다. 그래서 화면 동기화는 사람이 보는 TTY에만 쓰고, ring과 바이트 계약은 손대지 않는다.
- **구조화된 셀 차이를 고른 이유.** mosh처럼 VT 바이트로 차이를 보내면 양쪽 에뮬레이터가 같은 버전이어야 결과가 같다. qsh는 버전이 다른 peer끼리도 붙으므로, 해석이 필요 없는 셀 차이와 상태 해시로 어긋남을 알아채고 전체 화면으로 다시 맞춘다.
- **datagram을 선택 운반체로 두는 이유.** 측정에서 손실 아래 staleness가 열 배 차이 났다. 그래도 datagram을 버리는 중간 장비와 옛 peer가 있으므로 스트림 운반체가 늘 있어야 하고, 그러면 §14의 원래 목적(wire가 한 전송 기능에 묶이지 않음)도 지켜진다.
- **입력은 스트림이 정본인 이유.** PRD §8의 입력 무손실·무중복은 이미 offset 축으로 증명돼 있다. 사본은 그 규칙 안에서만 적용되므로 새 증명이 필요 없다.
- **정책을 순수 함수로 두는 이유.** 네트워크 적응은 재현하기 어려운 버그를 낳는다. 입력과 출력을 값으로 고정하면 표 테스트와 doctor 출력이 같은 함수를 보고, 사용자가 보는 모드와 실제 동작이 어긋나지 않는다.
- **bulk 양보를 응용 층에 두는 이유.** 측정에서 bufferbloat 아래 우선순위와 별도 연결이 모두 실패했다. 큐 지연을 신호로 bulk를 줄이는 LEDBAT 방식은 병목이 어디든 통하고, BBR을 바꾸지 않는다.
- **BBR·MTU·0-RTT를 두는 이유.** BBR은 측정에서 문제가 없었고 Cubic은 나빴다. MTU 기본값은 1500·1280 링크에서 맞는 datagram 크기를 냈다. 0-RTT는 이 마일스톤과 상관없이 replay 위험 때문에 꺼져 있고 datagram도 그 규칙 안에 있다.

## 대안과 기각 사유

- **모든 attach를 화면 동기화로 바꾼다.** `session.output`의 바이트 계약을 깨고 `/v2`가 필요하다. 기각.
- **차이를 VT 바이트열로 보낸다(mosh 방식).** 에뮬레이터 버전이 다른 peer 사이에서 화면이 조용히 어긋난다. 기각.
- **화면 갱신을 스트림에만 싣는다.** 운반체가 하나라 단순하지만 손실 아래 staleness가 162~176 ms로 측정됐다. 스트림 운반체는 fallback으로 남긴다. 기각.
- **큰 갱신은 조각내지 않고 늘 스트림으로 보낸다.** 큰 터미널의 `ls` 한 번이 손실 아래 스트림 지연을 그대로 받는다. 조각 수와 손실률로 고르는 (c)가 두 경우를 다 다룬다. 기각.
- **입력도 datagram만으로 보낸다.** 입력 무손실을 다시 증명해야 하고 datagram을 버리는 경로에서 입력이 사라진다. 기각.
- **스트림 종류마다 다른 혼잡 제어나 별도 연결로 bulk를 떼어 낸다.** 측정에서 깊은 큐 아래 효과가 없었고, 별도 연결은 인증·resume·감사 단위를 둘로 나눈다. 기각.
- **혼잡 제어를 정책 손잡이로 둔다(손실 많으면 Cubic 등).** Cubic이 손실 아래 화면 갱신을 무너뜨렸다. 기각.
- **스크롤백 없이 mosh처럼 화면만 보낸다.** mosh 사용자의 가장 흔한 불만이 스크롤백이다. 결정 10이 비용을 bulk 이하로 묶고 넣는다. Dave가 2026-11-06에 넣는 쪽을 골랐다.
- **터미널 질의를 client 터미널로 넘겨 답을 받아 온다.** 질의마다 RTT가 붙고, 재부착이나 떼어 둔 동안의 질의에는 답할 터미널이 없다. 기각.

## 결과

- 개정할 문서: `docs/design/protocol.md` §1(datagram 줄), §4(capability 둘), §9(새 필드와 message), §12(bulk 양보), §14(결정 7의 문장), 새 §18(화면 동기화 상태 기계, 조각, channel id), §16.2의 표에 datagram 버퍼 상수 행. `docs/design/architecture.md` §3·§4(에뮬레이터 위치, 메모리 상한). `docs/design/testing.md` L2·L4·L9/L10. `docs/CLI.md` §6.17(doctor), §6.23(새 키), §7(`--screen-sync`). ADR-0043 결정 4와 ADR-0021 결정 1에는 이 ADR을 가리키는 개정 이력 줄을 더한다.
- 새 threat model 행:
  - datagram channel 위조: channel id는 ACL 통과 뒤 발급된 128비트 난수이고 그 연결의 1-RTT 키로만 닿는다. 모르는 id는 버리고 센다. datagram은 리소스를 만들지 않는다.
  - 입력 사본 재전송: QUIC 패킷 번호 보호와 입력 축 offset 규칙이 이중 적용을 막는다.
  - 자원: 조립 버퍼 channel당 1 MiB와 상태 하나, attach당 기준 상태 하나, history 행·바이트 상한, datagram 송수신 버퍼 상수. 모두 상한 시험을 둔다.
  - 정보노출: 화면 차이와 history는 PTY 내용이다. `qsh::adapt` 로그와 doctor는 통계와 손잡이 값만 담고, 감사 기록에는 새 필드가 없다.
  - 파서 표면: host 에뮬레이터는 자기 세션의 출력을, client는 peer가 보낸 diff를 해석한다. 둘 다 fuzz 타깃이 있다.
  - host가 대신 답하는 질의: 답은 host 에뮬레이터 자기 상태에서만 나오고 client 정보는 attach 때 알린 두 색뿐이다.
- 남는 위험: 넓은 문자 폭이나 자형 결합을 host 에뮬레이터와 로컬 터미널이 다르게 세면 행 안에서 커서가 어긋난다. client는 행마다 절대 위치로 그려 피해를 그 행에 가둔다. 이미지 프로토콜은 화면 경로에서 보이지 않는다(`--screen-sync=off`).
- 크기: ADR-0050의 4ew에 적응 정책, bulk 양보, 벤치가 더해져 추정 6ew로 고친다. 스텝 순서는 벤치(`scripts/netbench/`) → datagram 파사드와 상수, `ConnStats` 추가 → 적응 정책과 표 테스트 → 에뮬레이터 선택과 host 상태, diff codec, fuzz → capability와 스트림 운반체 → datagram 운반체와 입력 사본 → client 화면 모델과 렌더러, 재부착 → history → bulk 양보와 `rate` fault → keep-alive → doctor·`qsh::adapt`·설정 키 → 문서·man·threat model 순이다. 계약·wire를 건드리는 스텝은 이 ADR이 승인되기 전에 열지 않는다(ADR-0050 결정 7).

### Dave가 정한 것(2026-11-06)

1. **스크롤백.** 밀려난 행을 로컬 스크롤백으로 보낸다(결정 10). 한가할 때 스트림으로 순서대로 보내고, 밀리면 건너뛴 행 수를 한 줄로 알리며, 재부착은 화면 한 장만 보낸다. 지나간 출력 전체는 `qsh session read`로 남는다. 다른 답은 mosh처럼 화면만 보내는 것(단순하지만 스크롤백이 비어 있다)이다.
2. **기본값.** `[interactive].screen_sync`의 기본은 `auto`(peer가 지원하면 켬)다. 이미지 프로토콜이나 에뮬레이터 차이를 겪는 사용자는 `--screen-sync=off` 한 번으로 오늘 동작을 얻고, 바이트 경로는 계속 시험된다.
3. **터미널 질의.** 화면 경로에서 DA·CPR·DECRQM에는 host 에뮬레이터가 답하고(mosh 방식), OSC 10/11 색 질의에는 client가 attach 때 알린 색으로 답한다(결정 3). 질의를 client 터미널로 넘기는 방식은 RTT가 붙고, 떼어 둔 동안에는 답할 곳이 없다.

## 개정 이력

- 2026-11-06 초안(에이전트). 측정 수치는 맥락 절에 있고 하네스는 남아 있지 않다. 결정 18의 8이 벤치를 다시 세운다.
- 2026-11-06 승인(Dave). 결과 절의 세 질문은 모두 추천대로 정했다: 스크롤백을 보낸다, 기본값 `auto`, 터미널 질의는 host가 답한다.
- 2026-11-06 datagram 파사드 스텝의 확인(quinn 0.11.12, quinn-proto 0.11.18). 결정 13의 수단은 control `Ping`이다: quinn은 `keep_alive_interval`을 연결 생성 때의 `TransportConfig`에서만 받고 연결 도중 바꾸는 API가 없다. 결정 12의 입력 가운데 rttvar는 quinn이 공개하지 않아 qsh-core가 1초 `rtt` 표본으로 계산하고, bytes in flight와 버퍼 초과로 버린 datagram 수는 공개되지 않아 비워 둔다. datagram은 quinn 기본으로 이미 켜져 있었고, 수신·송신 버퍼를 각 64 KiB 상수로 고정했다(수신 값이 광고하는 `max_datagram_frame_size`다).
- 2026-11-06 `scripts/netbench/` 첫 결과(`53bc540`, Dave-Windows-WSL, quinn 위 합성 트래픽, staleness는 기저 단방향 지연을 뺀 값). q1: RTT 150 ms·손실 3~5%에서 datagram staleness p95 3.6~4.4 ms, 스트림 151.9~171.9 ms로 방향이 같다(이전 수치와의 차이는 정의 차이로 본다). q2: Cubic은 스트림 p95 480 ms·datagram p95 43 ms로 무너져 BBR 유지를 지지한다. q3: `max_datagram_size()` 1414·1192에 프레임 오버헤드 38바이트를 더하면 이전의 1452·1230이다. 결정 6의 조각 크기는 `max_datagram_size()`를 쓴다. q4: 에코 p50은 RTT에 머물고 꼬리만 손실을 따라 p99 157·502·654 ms로 는다. q5: 깊은 큐에서는 우선순위·별도 연결 모두 돕지 않았다. 얕은 큐(20 ms)에서는 별도 연결만 에코를 p95 78 ms(에코 단독 54 ms)로 지켰고, 같은 연결과 스트림 우선순위는 p95 334~447 ms였다. 같은 연결의 에코가 큐 지연보다 훨씬 긴 원인은 규명하지 못했다. 이 결과는 결정 12 (a)의 같은-연결 양보가 얕은 큐에서 충분한지를 bulk 양보 스텝에서 확인해야 한다는 뜻이다. q6: 바깥 DATAGRAM이 낫다는 이전 결과는 재현되지 않았다. 바깥 DATAGRAM은 run마다 안쪽 에코 미반환 185~266개, bulk 0.77~1.13 MB/s였고 바깥 스트림은 p99 1393~1657 ms·1.66~1.72 MB/s, 송신 버퍼를 64 KiB로 줄인 바깥 DATAGRAM은 한 번은 0.36 MB/s, 한 번은 2.17 MB/s·p99 748 ms·미반환 0이었다. 편차가 커서 결정 12 (f)의 기본(중첩이면 바깥 datagram)은 M26 전에 반복 측정으로 다시 확인한다. 결정 자체는 이 결과만으로 바꾸지 않는다.
- 2026-11-06 결정 18의 11을 0.8배에서 0.5배로 고쳤다(Dave 결정). 실제 PTY의 101 MiB `cat`이 에뮬레이터 끔 85 MiB/s, 켬 48~57 MiB/s(0.56~0.67배, `bb7743e`)다. PTY 읽기(약 11.7 ns/B)와 `vt100` 해석(약 13~14 ns/B)이 결정 2대로 같은 task에서 직렬이라 약 0.7배가 한계다. 별도 task 에뮬레이터는 밀렸을 때의 동기 상실 상태가 새로 필요해 택하지 않았다. 50 MiB/s는 20 Mbit 링크의 약 20배라 원격 사용에서는 네트워크가 먼저 막히고, exec·`-T`·`--json`은 바이트 경로라 영향이 없다.
- 2026-11-07 bulk 양보 스텝의 확인과 측정(Dave-Windows-WSL). 같은 연결의 양보는 얕은 큐에서도 에코를 지킨다. netbench q5(`scripts/netbench/`, 20 Mbit·RTT 50 ms, 에코 p95): 얕은 큐(20 ms) 같은 연결 380 ms, 우선순위 328 ms, 별도 연결 75.4 ms, 같은 연결에서 bulk가 양보(`q5-shallow-yield`, qsh 규칙의 포트) 71.5 ms, 에코 단독 51.6 ms다. 깊은 큐(600 ms)는 같은 연결 579 ms, 우선순위 299 ms, 별도 연결 641 ms, 양보 83.0 ms다. 양보 쪽 bulk는 1.65 MB/s(링크의 66%)로 양보 없는 2.3 MB/s보다 낮다. 실제 코드는 testkit chaos proxy의 `rate`로 같은 링크를 만들어 잰다(`bulk_yield`, 3회 반복): 깊은 큐 에코 p95 80~87 ms(`min_rtt` 51 ms, 양보 전 423 ms), 얕은 큐 69~71 ms(양보 전 144 ms), 입력이 없을 때 터널 처리량은 링크의 97~98%, 타이핑 중에는 69~72%다. 얕은 큐에서 에코가 큐 지연(20 ms)보다 훨씬 길었던 원인은 이번에도 직접 규명하지 못했다. 관찰한 것: 양보 없이 포화시키면 proxy가 30초에 66,000개를 버렸고, 예산만 걸고 쓰기를 64 KiB 덩어리로 두면 타이핑 중 에코 p95가 90~97 ms였으며, 쓰기를 16 KiB 알갱이로 나누고 토큰 burst를 10 ms로 줄이자 67~71 ms로 내려갔다. quinn이 받은 덩어리를 한 번에 내보내므로 20 ms 큐(20 Mbit/s에서 50 KB)보다 긴 burst의 꼬리 손실이 원인 후보다. 25 ms 목표만으로는 얕은 큐에서 한 번도 문턱을 넘지 못해(큐가 그보다 얕다) 양보가 작동하지 않았다. ADR이 정하지 않아 이 스텝이 고른 것: (1) 손실도 혼잡 신호로 세되, 큐가 목표의 절반(12.5 ms) 이상 서 있을 때만 센다(큐가 빈 경로의 무작위 손실에 bulk가 굶지 않게). (2) 제한 중 송신 알갱이 16 KiB, 토큰 burst 10 ms(최소 16 KiB). (3) 추정 대역은 `cwnd / srtt`가 아니라 지난 60초 최고 전달률의 125%다. 응용이 막힌 BBR의 `cwnd / srtt`는 링크의 10배 넘게 나오고(창 4 MB), 손실 복구 중에는 몇 패킷으로 줄어 예산을 하한으로 끌어내렸다. (4) 예산 규칙이 쓰는 `interactive`는 키 입력(host는 입력 pump, client는 `send_input`)만 세고 화면 갱신은 세지 않는다. (5) 연결 단위 governor는 `stable_id`로 묶은 레지스트리의 `Arc`이고 터널 스트림의 `StallWatch`가 쥔다. 열린 한계: `FILE_DATA`는 프레임 단위(청크 상한)라 값은 치르지만 16 KiB 알갱이로 나누지 않는다. reverse 경로(client에 QUIC 연결이 없음)의 입력은 governor에 닿지 않는다. `[transport].adaptive`는 아직 설정 키가 아니라 `adapt::set_process_adaptive`가 그 자리다(설정 키 스텝이 부른다).
- 2026-11-07 결정 9에 history 운반 모양을 더했다(Dave 결정). 결정 10은 밀려난 행을 세션 data 스트림으로 보낸다고만 했고 결정 9는 `ScreenUpdate`·`ScreenAck`만 정해 history를 실을 message가 없었다(화면 동기화 attach는 `Output`을 보내지 않는다). `SessionFrame` oneof에 `ScreenHistory screen_history = 9`(`repeated bytes lines`, `uint64 skipped`)를 더한다. frame 하나는 16 KiB 이하, 스트림으로만 가고 datagram으로는 보내지 않으며, `screen.v1`이 덮는다. 한 frame 안에서 `lines`가 먼저이고 `skipped`가 뒤다. host는 `ScreenUpdate` 송신이 비었을 때만 보내고, 밀리면 건너뛴 수를 `skipped`로 알린다. 재부착은 history를 재생하지 않는다. 대안이던 `ScreenUpdate`의 필드(상태 번호·조각·datagram 운반체에 묶임)와 history 철회는 택하지 않았다.
