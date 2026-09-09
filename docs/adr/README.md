# Architecture Decision Records

QSH의 아키텍처/설계 결정을 기록한다. 각 ADR은 맥락, 결정, 근거, 대안과 기각 사유, 결과를 담는다. 상태 값은 `승인됨`(확정), `제안됨`(결정 절은 다 냈으나 사용자 확정 전 초안), `예약됨`(결정 절이 미정인 자리표시자) 셋이다.

| 번호 | 제목 | 상태 |
|---|---|---|
| [0001](0001-custom-quic-protocol.md) | Custom QUIC application protocol 채택 | 승인됨 |
| [0002](0002-pairing-invite-code.md) | 기본 pairing UX로 일회용 invite code 채택 | 승인됨 |
| [0003](0003-sessions-in-listener.md) | PTY 세션을 MVP에서 `qsh serve` 프로세스 내부에 둔다 | 승인됨 |
| [0004](0004-replay-buffer-memory-only.md) | Replay buffer는 memory-only ring으로 시작한다 | 승인됨 |
| [0005](0005-tcp-fallback-p1.md) | TCP/TLS fallback은 P1 유지, transport 추상화는 P0 산출물 | 승인됨 |
| [0006](0006-product-name-and-crate-name.md) | 제품명은 `qsh` 유지, crates.io 패키지명만 `qsh-cli`로 분리 | 승인됨 |
| [0007](0007-session-ref-and-resume-token-custody.md) | `session_ref`는 클라이언트 `Ops`가 조립하고 resume token은 클라이언트 상태 파일에만 둔다 | 승인됨 |
| [0008](0008-private-ca-cert-issuance.md) | private CA는 단일 self-signed root로 device cert를 발급한다 | 승인됨 |
| [0009](0009-admission-defenses.md) | 미검증 Initial은 항상 Retry로 되돌리고, admission은 handshake 상한과 source별 rate limit으로 자원 생성 전에 결정한다 | 승인됨 |
| [0010](0010-resource-quotas.md) | 세션·exec·터널·연결 quota는 인가 이후·자원 생성 이전에 결정하고, 살아 있는 자원 자체를 계수한다 | 승인됨 |
| [0011](0011-remove-mcp-adapter.md) | 내장 MCP 어댑터(`qsh mcp`)를 제거하고 에이전트 연동은 JSON CLI와 exec stdio로 한다 | 승인됨 |
| [0012](0012-human-surface-naming.md) | 사람용 표면의 이름 규약을 역할 어휘·`serve --to`·`pair --as`로 재정렬한다 | 승인됨 |
| [0013](0013-cert-file-exchange.md) | 인증서 파일 교환을 프로비저닝 1급 경로로 승격한다(ADR-0002 개정) | 승인됨 |
| [0014](0014-address-default-port.md) | peer 주소는 포트 생략 시 4433을 채우고 읽기·쓰기 양쪽에서 정규화하되 파일은 쓰지 않는다 | 제안됨 |
| [0015](0015-listener-pairing.md) | listener 를 상대로 한 초대 코드 pairing | 예약됨 |
| [0016](0016-csr-issuance.md) | CA 서명 요청(CSR) 흐름 | 예약됨 |
| [0017](0017-acl-toml-not-written.md) | `acl.toml`은 어떤 명령도 쓰지 않고 부담은 doctor 진단과 페어링 직후 고지로 옮긴다 | 승인됨 |
| [0018](0018-tunnel-lifetime-bound-to-connection.md) | 터널 수명은 v1 내내 QUIC connection에 결합하고, forward-route live carrier와 `-R` 자동 재발행은 P1로 둔다 | 승인됨 |
