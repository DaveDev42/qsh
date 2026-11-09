# ADR-0058: jump 채널의 침묵 전환 시한을 고친다. client 쪽은 끝에서 끝 왕복(안쪽 연결의 srtt)으로, 중간 peer 쪽은 바깥 연결의 srtt로 재고, 두 쪽 모두 RTT 하한 50 ms와 ack 지연 25 ms를 더한다

날짜: 2026-11-10
상태: 승인됨

개정 관계: ADR-0056 결정 4 넷째 항목의 "datagram으로 보낸 지 4×srtt(바깥 연결)가 넘도록 그 채널로 datagram이 한 번도 돌아오지 않는데 스트림과 바깥 ack는 살아 있으면 스트림으로 바꾸고"에서 시한만 바꾼다. 30초 재시험, 운반체의 정적 규칙(1217), 자리 초과 패킷 버림은 그대로다.

## 맥락

M26 수용 시험(2026-11-10)에서 건강한 datagram 채널이 스트림으로 떨어졌다.
- loopback에서 바깥 srtt는 0.1 ms 안팎이라 4×srtt가 1 ms도 안 된다. CPU 부하 아래 healthy한 hop 하나 채널이 전환했고, bulk `-L` 업로드 5초 동안 전환이 464번, 침묵 전환이 232번 일어나 스트림 큐에서 7874 패킷이 버려졌다. 터널 처리량 비율이 0.37~0.56으로 흔들려 DoD 25.13의 0.5를 세 번에 한 번 못 넘었다. 시한을 크게 두면 전환이 0번이고 비율이 0.58~0.59로 안정됐다.
- 규칙의 원형인 ADR-0052 결정 12 (c)의 구현(`crates/qsh-core/src/adapt/runner.rs`)은 `RTT_FLOOR` 50 ms를 둔다. jump 쪽 구현은 이 하한을 옮기지 않았다. 하한은 원형 규칙의 일부이므로 이 ADR 없이도 구현에 넣을 수 있다.
- 하한만으로는 남는 문제가 둘이다. 첫째, client가 보낸 datagram에 대한 "돌아오는 datagram"은 체인 끝 T가 안쪽 QUIC로 답한 것이라 끝에서 끝 왕복이 걸린다. C–J 10 ms, J–T 200 ms면 4×max(10, 50) = 200 ms 안에 답이 오지 않아 건강한 경로가 전환한다. 둘째, 안쪽 QUIC 수신자는 ack를 최대 `max_ack_delay`(25 ms)까지 미룬다. ADR-0052의 원형은 바깥 QUIC가 datagram을 ack했는지를 봐서 이 두 문제가 없었다. jump는 채널로 돌아오는 datagram을 보므로 시한의 기준이 달라야 한다.

## 결정

1. 침묵 시한 `silence = 4 × max(rtt, RTT_FLOOR) + ACK_DELAY_ALLOWANCE`. `RTT_FLOOR`은 ADR-0052 구현과 같은 50 ms, `ACK_DELAY_ALLOWANCE`는 QUIC 기본 `max_ack_delay`와 같은 25 ms다.
2. `rtt`는 쪽마다 다르다.
   - client(C → 다음 hop 방향): 그 채널 위에서 맺은 안쪽 연결의 srtt. 끝에서 끝 왕복이다. 안쪽 연결의 handshake가 끝나기 전에는 바깥 srtt를 쓴다.
   - 중간 peer(T → C 방향)와 역방향 데몬: 바깥 연결의 srtt. 이쪽에서 보낸 datagram에 C의 안쪽 endpoint가 바로 ack를 돌려보내므로 바깥 왕복과 ack 지연이면 된다.
3. 나머지 조건(스트림과 바깥 ack가 살아 있을 때만 전환, 30초 뒤 재시험)은 ADR-0056 결정 4 그대로다.
4. 시험: 단위 시험이 두 쪽의 시한 계산을 표로 고정한다(`jump_silence_window_table`). 수용 시험 `jump_tunnel_throughput`과 `jump_carrier_switches_to_datagram_after_pmtud`가 CPU 부하 아래에서 전환 0번을 확인하고, `jump_silence_on_the_datagram_path_falls_back_to_the_stream`이 진짜 침묵에서는 여전히 전환함을 확인한다.

## 근거

- 원형 규칙의 하한을 그대로 쓰면 두 규칙이 같은 장면에서 같게 움직인다.
- 끝에서 끝 왕복을 client 쪽에만 쓰는 것은 그쪽 답만 체인 전체를 거치기 때문이다. 중간 peer에도 끝에서 끝을 쓰면 J는 그 값을 모르고, 바깥 왕복으로 충분하다.
- 시한이 길어지면 datagram을 버리는 중간 장비를 늦게 알아챈다. 대륙 간 끝에서 끝 300 ms 체인이면 약 1.2초다. 그동안 안쪽 QUIC는 손실을 보고 재전송을 시작하므로 연결은 끊기지 않는다.

## 대안

- 하한 50 ms만 넣는다(이 ADR 없이 가능). loopback과 근거리 hop의 흔들림은 없어지지만 J–T가 먼 체인의 client 쪽에서 건강한 경로가 전환한다. 기각.
- 시한을 고정값(예: 1초)으로 둔다. 근거리 체인에서 datagram을 버리는 장비를 필요 이상 늦게 알아챈다. 기각.
- 바깥 QUIC의 datagram ack를 직접 본다(ADR-0052 원형과 같은 기준). quinn이 datagram별 ack를 알려 주지 않고, 원형도 직접 보지 않고 바깥 패킷 ack 진행으로 어림한다. jump 채널 단위로는 그 어림이 채널마다 갈리지 않는다. 기각.

## 개정 이력

- 2026-11-10 초안(main 세션, M26 수용 시험의 측정에서).
- 2026-11-10 Dave가 승인했다.
