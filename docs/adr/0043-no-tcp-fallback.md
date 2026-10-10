# ADR-0043: TCP/TLS fallback을 만들지 않는다. QSH는 QUIC 전용이고 UDP가 막힌 망은 범위 밖이다

날짜: 2026-10-11
상태: 승인됨 (2026-10-11 사용자 결정)

개정 관계: ADR-0005의 "TCP fallback은 P1에 한다"를 철회한다. ADR-0005의 다른 결정(transport 추상, wire 구조가 QUIC 고유 개념에 기대지 않음, doctor의 UDP probe)은 그대로 둔다. 제안 상태였던 ADR-0028은 기각한다. 단 ADR-0028 결정 0(공개 enum facade와 비공개 계약 trait)은 M14 (a)로 이미 착지했고 이 ADR이 그 모양을 그대로 승인한다. PRD §7 P1 목록, §16 위험 표, §17 확정된 결정 중 TCP fallback 문장을 이 ADR에 맞춰 고친다.

## 맥락

ADR-0005는 UDP를 막는 망(기업·학교 방화벽, 일부 호텔·카페 Wi-Fi와 captive portal, TCP 전용 VPN)을 이유로 TCP/TLS fallback을 P1에 두었다. ADR-0028은 그 설계를 `[transport].mode = quic | tcp | auto`, 자체 sans-IO mux, 항상 resume 복구로 구체화했고 `docs/ROADMAP.md` M14는 4.3~6.9ew로 P1에서 가장 큰 마일스톤 가운데 하나였다.

ADR-0028을 쓰면서 드러난 비용은 이렇다.

- TCP 경로에는 connection migration이 없다. IP가 바뀌면 연결이 끊기고 resume으로만 돌아오며, 연결에 묶인 터널(ADR-0018)은 매번 끊긴다. QSH가 내세우는 "망이 바뀌어도 같은 셸"이 이 경로에서는 약해진다.
- 선두 차단(head-of-line blocking) 아래에서는 PTY 우선순위(`tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`가 지키는 M4 예산)를 약속할 수 없다. ADR-0028은 "손실 아래 예산 없음"을 고지하는 쪽을 골랐다.
- 두 번째 transport는 테스트 매트릭스를 두 배로 늘리고, 새 TCP listener와 mux 파서라는 공격면, 강제 downgrade 처분, fuzz 타깃, threat model 행을 더한다. SC7 독립 보안 리뷰의 범위도 넓어진다.

반면 UDP가 막힌 망에서 원격 셸이 필요한 사용자에게는 이미 SSH가 있다. mosh도 같은 경계를 두고 TCP fallback 없이 쓰인다. WireGuard나 Tailscale 같은 overlay는 UDP를 쓰지만 DERP 같은 TCP relay로 넘어가는 경로가 있어 그 위에서는 QSH가 동작한다(doctor `udp_egress_blocked`의 remedy가 이미 이 우회를 안내한다).

## 결정

1. QSH는 TCP/TLS fallback을 만들지 않는다. transport는 QUIC 하나다. P1에서 빼고, P2 후보로도 두지 않는다. 다시 열려면 새 ADR이 이 결정을 개정해야 하고, 그 ADR은 이 ADR의 근거 절이 적은 비용을 다시 따진다.
2. `docs/ROADMAP.md` M14는 철회로 닫는다. 마일스톤 번호 M15~M19는 다시 매기지 않는다(코드와 문서가 번호로 인용한다). M14 (a)의 착지 기록은 남긴다.
3. M14 (a)로 착지한 transport 중립 facade(`Connection`·`SendStream`·`RecvStream`·`Endpoint`와 중립 오류 타입, `crates/qsh-transport/tests/conformance.rs`)는 유지한다. `qsh-core`·`qsh-cli`가 QUIC 스택 이름을 쓰지 않는다는 `cargo xtask arch` 규칙도 유지한다. 이 경계는 fallback이 없어도 quinn 버전 갱신과 오류 분류를 한 crate에 가둔다. ADR-0028 결과 절이 적은 테스트 접근자 교체 편집은 이 ADR로 받아들인다.
4. `docs/design/protocol.md` §14의 제약(wire가 stream ID·datagram·transport parameter에 기대지 않음, 스트림 정체성은 in-band `StreamHeader`)은 계속 지킨다. 근거를 "TCP fallback 준비"에서 "transport 중립 wire"로 바꾼다.
5. doctor `udp_egress_blocked`의 message는 "(P1, ADR-0005)" 대신 이 ADR을 가리킨다. 진단 코드, 등급, remedy는 바꾸지 않는다.
6. README Known limitations는 "TCP fallback 없음"을 계획 중인 기능이 아니라 범위 결정으로 적고, UDP가 막힌 망에서는 SSH나 overlay를 쓰라고 안내한다.

## 근거

- 제품의 핵심 약속(IP 변경·절전·망 전환을 견디는 세션)은 QUIC migration과 resume에서 나온다. TCP 경로는 그 약속의 약한 판이고, 그 판을 위해 P1 예산의 15~20%와 보안 리뷰 범위를 쓰는 것은 수지가 맞지 않는다.
- UDP 차단 망은 실재하지만 그 망의 사용자에게는 SSH라는 성숙한 대안이 있다. QSH가 같은 망에서 SSH보다 나은 경험을 줄 수 없다면 두 번째 transport의 값은 "연결은 된다"뿐이다.
- 결정을 "P1 유보"가 아니라 "만들지 않음"으로 두면 doctor 문면, README, ROADMAP 가드레일이 "언젠가 된다"는 기대를 만들지 않는다.

## 대안과 기각 사유

- **ADR-0028을 승인하고 M14 (c)를 구현:** 기각. 근거 절의 비용.
- **P2로 미룸:** 기각. P2 목록에 두면 가드레일과 고지가 계속 "예정"을 말하고, 다시 열 조건이 없다. 필요해지면 새 ADR로 여는 편이 정직하다.
- **M14 (a) facade를 되돌림:** 기각. 동작 변경 없는 경계이고 성능 회귀가 없었다(처리량 비율과 포화 터널 echo p95가 기준선 안). 되돌리면 quinn이 다시 `qsh-core` 전역으로 퍼진다.
- **WebSocket·HTTP/2 터널 같은 다른 우회 transport:** 기각. TCP fallback과 같은 비용(migration 없음, 선두 차단, 새 파서)에 HTTP 의미까지 더한다(ADR-0001이 HTTP/3를 기각한 이유와 같다).

## 결과

- `docs/ROADMAP.md`: M14를 철회로 닫고, §3 가드레일 표의 TCP 행, §5.1 원칙 3·4, M15 DoD의 "두 transport", §5.2 크기 표, §5.3 밖으로 보낸 항목, §5.4 위험 3, §5.5 mux fuzz 타깃을 고친다.
- `docs/PRD.md` §7 P1 목록, §16 위험 표, §17 확정된 결정, `docs/adr/README.md`(0005 개정 표시, 0028 기각, 0043 추가), `docs/design/protocol.md` §14, README.
- 코드: `crates/qsh-core/src/doctor.rs`의 `UDP_EGRESS_BLOCKED` message와 그 문면을 옮겨 적은 `docs/CLI.md` §6.17, transport facade의 모듈 주석. wire·fixture·capability·`qsh.cli/v1` 변경 없음.
- 인용된 ADR-0028 결정 0은 기각된 ADR 안에 있지만 이 ADR 결정 3이 그 모양을 승인하므로, 코드 주석의 `docs/adr/0028-tcp-tls-fallback.md` decision 0 인용은 이 ADR 결정 3으로 바꾼다.
