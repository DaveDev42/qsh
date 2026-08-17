# ADR-0005: TCP/TLS fallback은 P1 유지, transport 추상화는 P0 산출물

날짜: 2026-08-17
상태: 승인됨

## 맥락

일부 기업/네트워크 환경은 UDP를 차단하므로 QUIC(UDP 기반) 연결이 불가능할 수 있다(PRD §16 주요 위험). TCP/TLS를 대체 transport로 제공하는 fallback을 P0에 앞당길지, P1로 유지할지가 §18 남은 결정 항목이었다.

## 결정

TCP fallback 구현 자체는 **P1으로 유지**한다. 단, **transport 추상화는 P0 산출물**로 지금 만든다:

- 모든 프로토콜 코드를 `Transport`/`StreamMux` trait 위에 작성하고, QUIC 고유 기능(stream ID, unreliable datagram 등)에 wire 구조가 의존하지 않게 한다. 스트림 정체성은 in-band `StreamHeader`(ADR-0001)로 표현하므로 QUIC stream ID와 TCP mux 어느 쪽에서도 동일하게 동작한다.
- `qsh doctor`에 **UDP reachability probe를 P0로** 포함시켜, 차단 환경을 사용자가 지금 바로 진단할 수 있게 한다(fallback 구현 여부와 무관하게 진단은 가치가 있다).

## 근거

- M0~M2 로드맵(`docs/ROADMAP.md` 참고)은 이미 identity/mTLS/QUIC/framing/dispatch/ACL/JSON envelope라는 리스크 척추를 관통하는 것으로 꽉 차 있다 — TCP fallback을 지금 추가하면 두 번째 transport 구현+테스트 매트릭스가 필요해 일정이 크게 늘어난다.
- ADR-0001의 custom QUIC protocol 결정 덕분에, TCP fallback은 나중에 붙여도 **wire 프로토콜 변경이 필요 없다** — "TLS over TCP + 소형 mux"만 추가하면 끝난다. 즉 지금 미루는 비용이 낮다(나중에 재설계가 필요 없음).
- 반대로 `Transport` trait 없이 QUIC 전용으로 P0를 구현하면, P1에서 TCP를 붙일 때 dispatch/broker/ACL 코드 전반에 QUIC 전제(stream ID 등)가 스며들어 있어 대규모 재작업이 필요해진다 — 이 비용은 지금 trait 하나로 막을 수 있다.
- UDP 차단은 실사용에서 바로 부딪힐 수 있는 문제이므로, fallback을 구현하지 않더라도 최소한 "왜 안 되는지 진단"은 P0에 있어야 사용자가 좌절하지 않는다. `qsh doctor`의 UDP probe는 구현 비용이 낮고 즉시 가치를 준다.

## 대안과 기각 사유

- **TCP fallback을 P0로 앞당김**: 기각. 일정 비용이 크고, direct QUIC 경로의 품질(mobility, migration, resume)을 먼저 검증하는 것이 우선순위가 높다. PRD 성공 기준(SC1~SC5)은 모두 QUIC 경로 기준이다.
- **Transport 추상화 없이 QUIC hardcode 후 나중에 리팩터링**: 기각. "나중에 리팩터링"이 광범위한 코드(broker, dispatch, ACL choke point 전체)에 걸쳐 있어 재통합 리스크가 크다 — CLI.md §11이 "typed op layer를 나중에 붙이면 오류 체계가 이중화된다"고 경고하는 것과 같은 패턴의 함정이다.
- **UDP probe도 P1로 미룸**: 기각. Probe는 구현 비용이 매우 낮고(단순 UDP echo 시도) `qsh doctor`가 이미 P0 기능이므로, fallback 없이도 사용자에게 "당신 네트워크가 문제"라는 신호를 주는 데 비용 대비 가치가 크다.

## 결과

- `qsh-transport`는 P0부터 `Transport`/`StreamMux` trait을 정의하고, quinn 구현체 하나만 제공한다(TCP 구현체는 P1).
- `qsh-proto`의 `StreamHeader`는 스트림 정체성을 in-band로 표현해야 하며, QUIC stream ID에 의존하는 로직을 `qsh-core`/`qsh-proto`에 두지 않는다.
- `qsh doctor`는 P0에서 UDP reachability probe를 포함해야 하며, 결과를 human/JSON 양 출력 모드에서 보고해야 한다(CLI.md §11 준수).
- PRD §16 위험 표의 "기업망의 UDP 차단" 대응란은 "P1 TCP/TLS fallback과 `qsh doctor`"로 이미 반영되어 있다 — 이 ADR은 그 실행 순서(추상화 P0, 구현 P1)를 명문화한다.
