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
| [0014](0014-address-default-port.md) | peer 주소는 포트 생략 시 4433을 채우고 읽기·쓰기 양쪽에서 정규화하되 파일은 쓰지 않는다 | 승인됨 |
| [0015](0015-listener-pairing.md) | listener를 상대로 한 초대 코드 pairing | 예약됨 |
| [0016](0016-csr-issuance.md) | CA 서명 요청(CSR) 흐름 | 예약됨 |
| [0017](0017-acl-toml-not-written.md) | `acl.toml`은 어떤 명령도 쓰지 않고 부담은 doctor 진단과 페어링 직후 고지로 옮긴다 | 승인됨 |
| [0018](0018-tunnel-lifetime-bound-to-connection.md) | 터널 수명은 v1 내내 QUIC connection에 결합하고, forward-route live carrier와 `-R` 자동 재발행은 P1로 둔다 | 승인됨 |
| [0019](0019-socks-dynamic-forward.md) | SOCKS `-D`를 구현한다. client가 SOCKS5를 번역해 CONNECT마다 기존 `TCP_CONNECT`로 싣고 host는 그 dial에서 host-local 주소를 거른다 | 승인됨 |
| [0020](0020-socks-reverse-route.md) | 역방향 route에서도 `-D`를 켠다(ADR-0019 결정 10 개정) | 승인됨 |
| [0021](0021-transport-liveness-knobs.md) | keep-alive만 `[transport]` 설정으로 열고 idle timeout 45초는 고정 상수로 남긴다. `PathWatchConfig`의 세 값은 `[recovery]`로 내린다 | 승인됨 |
| [0022](0022-reverse-health-surface.md) | 역방향 등록 health는 `Host.lost_at`과 `qsh::reverse` 진단 줄까지로 두고, push 계약 표면은 필요가 관측된 뒤에 `qsh.event/v1`에 additive로 연다 | 승인됨 |
| [0025](0025-acl-show-read-only.md) | writer 없이 ACL 가시성만 올린다. 읽기 전용 `qsh acl show`를 신설하고 `acl grant`/`acl revoke`는 기각한다 | 승인됨 |
| [0026](0026-ssh-key-import-scope.md) | SSH 키 가져오기(`--import-ssh-key`)는 v1에 넣지 않는다. P1으로 미루고 착수할 때의 모양만 지금 고정한다 | 승인됨 |

0023(ADR-0018 결정 2·3을 개정하는 supervised tunnel mode)과 0024(`qsh setup`)는 번호만 예약돼 있고 파일은 아직 없다. P1 계획(`docs/ROADMAP.md` §5)이 0027~0035를 예약했으므로 예약 밖의 다음 새 번호는 0036이다. 조건부로 서는 ADR은 설 때 그 번호부터 쓴다.

- 0027 `doctor --fail-on`의 exit 규칙(M13)
- 0028 TCP/TLS fallback(M14)
- 0029 파일 복사(M15)
- 0030 pin 방향(M16)
- 0031 cert rotation·revocation(M16)
- 0032 서비스 매니저 실호출(M17)
- 0033 세션·audit 관리 범위(M17)
- 0034 세션 거처(M18)
- 0035 Windows client(M19)
