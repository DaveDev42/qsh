# ADR-0001: Custom QUIC application protocol 채택

날짜: 2026-08-17
상태: 승인됨

## 맥락

QSH는 QUIC transport 위에서 동작하는 원격 셸 프로토콜을 정의해야 한다. 후보는 두 가지였다: (1) HTTP/3(및 필요 시 WebTransport)를 core semantics로 채택, (2) custom application protocol을 정의하고 QUIC 위에 직접 얹는 것.

QSH의 실제 통신 패턴은 request/resource 모델이 아니다. connection당 role-symmetric control stream 1개 + attach/exec/tunnel마다 별도 bidi stream을 열고, PTY output/input은 저지연 byte stream으로, control message는 typed RPC로 주고받는다. 캐싱, 중개자(intermediary), 리소스 URI 같은 HTTP semantics를 활용할 지점이 없다.

## 결정

Custom QUIC application protocol을 core로 채택한다. ALPN은 `qsh/1`. HTTP/3, QPACK, WebTransport는 사용하지 않는다.

프로토콜은 "ordered reliable byte stream + typed header" 만을 QUIC/TCP 양쪽에 가정하는 얇은 frame layer(`qsh-proto`)로 정의한다: `StreamHeader` + 단회용 ticket으로 스트림을 자기 식별하고, control message는 protobuf(prost)로 직렬화한다.

## 근거

- QSH에는 request/resource 시맨틱, HTTP 캐싱, 프록시/중개자가 없다 — HTTP/3이 주는 이점이 사실상 없다.
- HTTP/3 core를 채택하면 QPACK 등 불필요한 fuzz surface가 커진다. QSH는 신뢰 불가 입력을 다루는 보안 민감 제품이라 attack surface를 최소화해야 한다.
- 결정적 이유: P1의 TCP/TLS fallback(ADR-0005) 시, HTTP/3을 core로 삼으면 QUIC 전용 layer이므로 TCP fallback에 **완전히 다른 제2의 프로토콜**이 필요해진다. Custom frame layer는 "ordered reliable stream" 가정만으로 QUIC stream과 TCP mux 위에서 동일하게 동작하므로 wire 변경 없이 fallback을 추가할 수 있다.
- Control stream 1개 + per-attach/exec/tunnel bidi stream이라는 QSH의 스트림 배치는 HTTP/3의 stream-per-request 모델과 근본적으로 다르다.

## 대안과 기각 사유

- **HTTP/3 core**: 기각. 위 근거대로 이점 없이 surface만 증가하고, TCP fallback 시 이중 프로토콜 문제가 생긴다.
- **WebTransport 위에 구현**: 기각. WebTransport도 결국 HTTP/3 session 위의 계층이라 동일한 문제를 상속한다. 브라우저 상호운용성은 QSH의 목표가 아니다.
- **gRPC-style(HTTP/2 기반)**: 기각. QUIC 고유의 stream 우선순위·fair queuing·독립적 loss recovery를 그대로 활용하지 못하고, PTY 저지연 요구(p95 <10ms)에 불리하다.

## 결과

- `qsh-proto` crate는 sans-IO로 frame codec, `StreamHeader`, control message(prost) 정의를 소유하며 QUIC/TCP 어느 쪽에도 의존하지 않는다.
- `qsh-transport`는 quinn 위에 ALPN `qsh/1`만 얹고, 프로토콜 semantics를 모른다.
- P0에서 모든 프로토콜 코드를 `Transport`/`StreamMux` trait 위에 작성해야 한다(ADR-0005와 직결) — QUIC 고유 기능(stream ID 등)에 wire 구조가 의존하지 않도록 스트림 정체성은 in-band `StreamHeader`로 표현한다.
- 신뢰 불가 입력을 다루는 파싱 코드는 `qsh-proto`에 격리되어 cargo-fuzz 타깃으로 커버 가능해야 한다.
