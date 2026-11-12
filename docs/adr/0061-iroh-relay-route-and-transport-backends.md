# ADR-0061: 직결 route 옆에 iroh relay route를 선택 사항으로 더하고, transport를 backend 경계로 정리한다

날짜: 2026-11-13
상태: 승인됨 (2026-11-13 Dave 결정. 방향과 결정 10~14는 같은 날 터미널 문답으로 골랐다)

개정 관계(승인되면): 다음을 고친다.
- `docs/PRD.md` §3 목표 8("relay 없이 완전히 동작한다")과 §14("Relay는 QSH 코어와 분리된 선택 제품"). 직결은 여전히 기본이고 relay 없이 완전히 동작한다는 약속은 남지만, 사용자가 켜는 relay route 하나가 코어에 들어온다.
- ADR-0043 결정 1("TCP/TLS fallback을 만들지 않는다"). iroh relay 구간은 TLS/TCP 위 WebSocket이다. 이 ADR은 qsh가 자체 TCP transport를 만드는 것이 아니라, 외부 라이브러리의 relay 경로를 선택 route로 받는 것으로 범위를 좁혀 개정한다.
- ADR-0050 결정 3("relay, TURN, 공용 STUN 서버, 중앙 서비스는 들이지 않는다")과 ADR-0054의 "relay·TURN·STUN 없음". 홀펀칭 설계 자체는 바꾸지 않는다.
- ADR-0043 결정 3이 남긴 transport 중립 facade(M14 (a))를 이 ADR의 결정 5~8이 넓힌다.

## 맥락

2026-11-13에 기업 VPN(TITAN) 아래의 Mac에서 집 qsh로 가는 경로를 실측했다.
- 집 공인 IP로 가는 UDP는 4433과 41641만 통과했다(80, 443, 3478, 8443, 고포트 각 20회 중 0회 도착). 집 IP를 바꿔도 같았다. 분류된 목적지(google.com, cloudflare.com 등)로는 UDP 443이 통과했다.
- TCP 443은 TLS가 가로채졌다(TITAN Root CA로 재서명). 집 IP로 가는 SYN은 공유기에 닿지 않았다.
- iroh 공용 relay(`aps1-1.relay.n0.iroh.link` 등)도 TLS가 가로채졌지만 `/ping` 200, WebSocket 업그레이드 101로 통과했다. pkarr 조회와 iroh의 주소 탐지 UDP 7842도 닿았다.

결론: 이런 망에서 qsh 직결은 관리자가 열어 둔 포트에 기대야 하고, 그 포트도 정책 변경 한 번에 사라진다. 사용자가 상시 허브를 따로 운영하지 않고도 닿는 길은 TLS를 통과하는 relay뿐이다.

iroh 1.x(n0, MIT/Apache-2.0, 1.0 2026-06-15, 조사 시점 1.4.1)는 Ed25519 raw public key로 dial하고, 직결·홀펀칭·relay 경로를 한 연결 안에서 다중 경로로 다룬다. qsh 신원도 Ed25519라 같은 키를 쓸 수 있다.

qsh 쪽 결합 지점(2026-11-13 조사):
- `qsh-core`는 quinn을 이름으로 쓰지 않는다(M14 (a), `xtask arch`). 공개 표면에 남은 quinn 흔적은 `Connection::quinn()` 탈출구 하나이고 crate 밖 호출자는 없다.
- 소켓 주소에 기대는 곳은 넷이다: admission(Retry·증폭 방어, `Incoming` 제어), 감사와 ACL의 `peer_addr: SocketAddr`, 펀칭과 route, serve의 bind.
- 오류 매핑은 quinn/rustls 오류에서 `ErrorCode`로 간다(`crates/qsh-transport/src/error.rs`).

## 결정

### A. iroh relay route

1. **route 하나를 더한다.** 호스트의 route 목록에 `iroh` 종류가 생긴다. 직결(주소, DNS 이름)과 펀칭은 그대로 먼저 시도되고, 사용자가 `iroh`를 목록에 넣었을 때만 마지막에 시도된다. 기본 route 목록은 바뀌지 않는다. 기존 설정과 동작은 그대로다.
2. **서버 쪽은 선택이다.** `serve`와 `listen`은 설정으로 iroh endpoint를 하나 더 띄운다. 기존 UDP 소켓과 별개다. 기본값은 끈다.
3. **신원은 pin 그대로다.** iroh EndpointId는 qsh 신원 키의 Ed25519 공개키다. qsh fingerprint(SPKI SHA-256)는 같은 키에서 계산되므로 `trust.toml`의 pin, 역할, ACL 판정, 페어링(TLS exporter 채널 바인딩)이 그대로 동작한다. ADR-0060의 이름 결속은 iroh route에서 "dial한 EndpointId = 그 이름의 pin 키"로 구조적으로 성립한다.
4. **지원하지 않는 것은 명시적으로 거부한다.** 사설 CA 모드(인증서 체인, SAN principal)는 iroh route에서 `UNSUPPORTED`다. admission은 handshake 뒤 키 기준으로 판정한다(iroh가 handshake 전 `Incoming` 제어를 열지 않는다). jump 체인의 바깥 hop을 iroh로 여는 것은 별도 확인 뒤 정한다(미결 4).

### B. transport backend 경계 (ut 전환 대비)

5. **backend trait.** `qsh-transport`의 연결 표면(연결, 양방향/단방향 스트림, datagram, TLS exporter, 상대 신원, 경로 정보, close)을 trait 하나로 정의하고 quinn과 iroh를 각각 그 구현으로 둔다. 나중의 ut는 세 번째 구현으로 들어온다. `Connection::quinn()` 탈출구는 없앤다.
6. **`PeerAddr`.** 소켓 주소 대신 "소켓 주소 | 키+경로(직결/relay URL)"를 표현하는 타입을 둔다. 감사, ACL, admission이 이 타입을 쓴다. JSON 계약(`qsh.cli/v1`, 감사 레코드)은 additive로만 바꾼다. 기존 `peer_addr` 문자열 필드는 그대로 두고 relay 경로를 나타내는 선택 필드를 더한다.
7. **오류 매핑은 backend마다 한 곳.** backend별 오류는 각 backend 모듈 안에서 중립 오류로 바뀌고, `ErrorCode`와 doctor 코드는 중립 오류만 본다.
8. **arch 규칙을 넓힌다.** `qsh-core`와 `qsh-cli`는 `iroh`, `noq`도 이름으로 쓰지 않는다. `xtask arch`가 manifest와 토큰 둘 다 막는다.

### C. 순서

9. **정리가 먼저다.** 결정 5~8은 동작 변화 없는 리팩터로 먼저 착지하고, 기존 시험과 `crates/qsh-transport/tests/it/conformance.rs`가 초록이어야 한다. iroh route(결정 1~4)는 그 경계 위에 붙인다.

### D. 2026-11-13 Dave 결정

10. **기본 relay는 n0 공용 relay다.** 설정 없이 n0 공용 relay로 동작하고, 사용자가 relay URL을 주면 그것(자가 운영 `iroh-relay` 등)을 쓴다. 공용 relay는 rate limit이 있고 조건이 바뀔 수 있다는 점을 `docs/CLI.md`와 README에 적는다.
11. **발견을 게시하지 않는다.** pkarr·DNS 게시와 조회는 끈다. 상대의 relay URL은 그 pin(`trust.toml`)에 적고, 없으면 기본 relay를 쓴다. 제3자에게는 아무것도 게시하지 않는다. 발견이 없으므로 endpoint는 지연으로 home relay를 고르지 않고, 설정된 relay URL 하나에 고정으로 붙는다. 기본값은 n0 공용 relay 가운데 한 URL이고, 양 끝이 같은 기본값을 쓰면 pin에 relay URL을 적지 않아도 닿는다.
12. **relay TLS는 OS 인증서 저장소로 검증한다**(`platform-verifier`). 기업망이 TLS를 가로채도 relay 연결이 선다. 그 구간은 그 망이 들여다볼 수 있지만, 안쪽 QUIC은 pin으로 인증한 종단 암호화라 내용과 신원은 보호된다. threat model에 이 차이를 적는다.
13. **iroh는 기본 빌드에 들어간다.** 릴리스 바이너리 하나로 설정만 바꿔 쓴다.
14. **`-J`와 iroh route.** 첫 구현에서 jump 체인의 어느 hop도 iroh route로 열지 않는다(`UNSUPPORTED`). 바깥 hop을 iroh로 여는 것은 pipe 위 QUIC-in-QUIC이 iroh 연결 위에서 도는지 시험으로 확인한 뒤 이 ADR의 개정 이력으로 연다.

## 결과

- 직결만 쓰는 사용자에게는 바뀌는 것이 없다.
- UDP가 막힌 망의 사용자는 상시 허브를 운영하지 않고 relay route로 닿는다. 세션 resume은 qsh 계층이라 그대로 동작한다.
- 바이너리 크기와 의존(noq, iroh, iroh-relay, reqwest/hyper)이 는다. `cargo deny`에 `webpki-roots`(CDLA-Permissive-2.0) 허용이 필요할 수 있다.
- relay 운영자는 암호문, 양 끝의 EndpointId, 접속 시각과 양을 본다. threat model에 새 항목이 필요하다.
- iroh 의존은 단일 회사가 주도하는 1.x다. backend 경계 덕분에 이후 ut나 다른 구현으로 갈아 끼울 수 있다.

## 기각한 대안

- **qsh 자체 TCP/TLS transport.** ADR-0043이 따진 비용 그대로이고, TLS를 가로채는 망에서는 pin 인증이 실패한다.
- **표준 TURN 클라이언트.** UDP 3478이 열린 망에서만 통하고, 실측한 망에서 UDP 443 TURN은 막혔다. 만남의 광장 문제도 따로 풀어야 한다.
- **transport 전체를 iroh로 교체.** jump 체인(사용자 정의 소켓 위 QUIC-in-QUIC), 사설 CA 모드, 주소 기반 admission을 잃는다. 선택 route로 두면 그것들을 지킨다.

## 개정 이력

- 2026-11-13 Toss(TITAN) 실측. 단독 probe(iroh 1.4.1, relay TLS는 OS 인증서 저장소, n0 `aps1-1` relay 고정, 발견 끔)로 Toss에서 MacMini(집 LAN, 임의 포트 bind)에 연결했다. relay 경유 541 ms에 연결되고(첫 RTT 214 ms) 0.2 s에 직결로 승격했다(집 공인 IP의 NAT 매핑 포트 `52705`, RTT 15~19 ms). 10회 반복에서 10/10 직결 승격, 연결 501~513 ms. 일방적으로 보낸 UDP는 집 IP의 같은 종류 포트에서 막혔으므로(맥락 절), TITAN은 상대도 보내 오는 흐름을 통과시키는 것으로 보인다. 같은 조건에서 기성 `dumbpipe` 0.40.1(webpki 루트만 신뢰)은 relay TLS가 `UnknownIssuer`로 거부돼 연결하지 못했다. 결정 12가 이 망에서 필수임을 확인했다. relay 주소 탐지 UDP 7842도 통과했다. 결정 본문은 고치지 않았다.

