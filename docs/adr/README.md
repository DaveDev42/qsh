# Architecture Decision Records

QSH의 아키텍처/설계 결정을 기록한다. 각 ADR은 맥락, 결정, 근거, 대안과 기각 사유, 결과를 담는다. 상태 값은 `승인됨`(확정), `제안됨`(결정 절은 다 냈으나 사용자 확정 전 초안), `예약됨`(결정 절이 미정인 자리표시자), `기각됨`(사용자가 받지 않은 제안) 넷이다.

| 번호 | 제목 | 상태 |
|---|---|---|
| [0001](0001-custom-quic-protocol.md) | Custom QUIC application protocol 채택 | 승인됨 |
| [0002](0002-pairing-invite-code.md) | 기본 pairing UX로 일회용 invite code 채택 | 승인됨 |
| [0003](0003-sessions-in-listener.md) | PTY 세션을 MVP에서 `qsh serve` 프로세스 내부에 둔다 | 승인됨 |
| [0004](0004-replay-buffer-memory-only.md) | Replay buffer는 memory-only ring으로 시작한다 | 승인됨 |
| [0005](0005-tcp-fallback-p1.md) | TCP/TLS fallback은 P1 유지, transport 추상화는 P0 산출물 | 승인됨 (fallback 부분은 0043이 철회) |
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
| [0016](0016-csr-issuance.md) | CSR 흐름을 파일 교환으로만 연다. `qsh identity request`·`qsh cert sign`·`qsh identity install`을 신설하고, 서명 장비는 CSR에서 공개키와 `device_id`만 꺼내 leaf를 새로 만든다. user cert 발급은 별도 ADR로 남긴다 | 제안됨 |
| [0017](0017-acl-toml-not-written.md) | `acl.toml`은 어떤 명령도 쓰지 않고 부담은 doctor 진단과 페어링 직후 고지로 옮긴다 | 승인됨 |
| [0018](0018-tunnel-lifetime-bound-to-connection.md) | 터널 수명은 v1 내내 QUIC connection에 결합하고, forward-route live carrier와 `-R` 자동 재발행은 P1로 둔다 | 승인됨 |
| [0019](0019-socks-dynamic-forward.md) | SOCKS `-D`를 구현한다. client가 SOCKS5를 번역해 CONNECT마다 기존 `TCP_CONNECT`로 싣고 host는 그 dial에서 host-local 주소를 거른다 | 승인됨 |
| [0020](0020-socks-reverse-route.md) | 역방향 route에서도 `-D`를 켠다(ADR-0019 결정 10 개정) | 승인됨 |
| [0021](0021-transport-liveness-knobs.md) | keep-alive만 `[transport]` 설정으로 열고 idle timeout 45초는 고정 상수로 남긴다. `PathWatchConfig`의 세 값은 `[recovery]`로 내린다 | 승인됨 |
| [0022](0022-reverse-health-surface.md) | 역방향 등록 health는 `Host.lost_at`과 `qsh::reverse` 진단 줄까지로 두고, push 계약 표면은 필요가 관측된 뒤에 `qsh.event/v1`에 additive로 연다 | 승인됨 |
| [0023](0023-tunnel-supervise.md) | `qsh tunnel open --supervise`로 연결 유실 뒤 터널을 스스로 재수립한다(ADR-0018 결정 2·3 개정, 결정 1 유지) | 승인됨 |
| [0024](0024-setup-orchestrator.md) | `qsh setup`은 기존 op을 정해진 순서로 부르는 오케스트레이터다. `acl.toml`은 쓰지 않고 자동 신뢰는 없다 | 승인됨 |
| [0025](0025-acl-show-read-only.md) | writer 없이 ACL 가시성만 올린다. 읽기 전용 `qsh acl show`를 신설하고 `acl grant`/`acl revoke`는 기각한다 | 승인됨 |
| [0026](0026-ssh-key-import-scope.md) | SSH 키 가져오기(`--import-ssh-key`)는 v1에 넣지 않는다. P1으로 미루고 착수할 때의 모양만 지금 고정한다 | 승인됨 |
| [0027](0027-doctor-fail-on-exit.md) | `qsh doctor --fail-on <warn\|error>`는 임계 이상 finding이 있으면 envelope을 그대로 둔 채 exit만 `1`로 바꾼다 | 승인됨 |
| [0028](0028-tcp-tls-fallback.md) | TCP/TLS fallback은 `[transport].mode` = `quic`(기본) \| `tcp` \| `auto`로 고르고, TCP listener는 `tcp_bind`가 있을 때만 bind한다. mux는 `qsh-proto`의 자체 sans-IO codec이고 `docs/design/protocol.md` §16.2의 새 행이다. TCP 연결은 항상 resume으로 복구한다. M14 (a)의 추상은 공개 enum facade와 비공개 계약 trait이다 | 기각됨 (0043) |
| [0029](0029-file-copy.md) | `qsh file get`/`qsh file put`(op `file.read`/`file.write`)로 파일 하나를 QUIC 위에서 원자적으로 옮긴다. 원격 경로는 그 action을 준 `[[acl]]` 행의 `paths`(정규 경로 기준 성분 단위 prefix, 없으면 파일 권한 없음) 아래로만 허용하고, qsh 자신의 config·state·runtime 경로는 `paths`와 무관하게 항상 거부한다. 재개 없음, BLAKE3 검증, 역방향 route 지원 | 제안됨 |
| [0030](0030-pin-direction.md) | pin에 방향 축(`direction = "both" \| "outbound" \| "inbound"`)을 더하고 handshake 역할로 pin 조회를 거른다. 필드가 없는 pin은 오늘처럼 양방향이고, §16.2 검증 경로의 의미 변경이 아니라 로컬 trust 입력의 변경이다. TOFU는 열지 않는다 | 제안됨 |
| [0031](0031-cert-rotation-revocation.md) | revocation은 이 장비의 `trust.toml` `[[revoked]]` 목록으로만 강제하고 전파하지 않는다. trust 변경 뒤 장기 실행 프로세스는 2초 안에 기존 연결을 재검증해 닫는다. 키 rotation은 옛 키가 서명한 rotation 문서를 파일로 건네고 `trust rotate`로 pin 교체와 옛 키 revoke를 한 번에 한다 | 제안됨 |
| [0032](0032-service-manager-activation.md) | `qsh service`는 명시적 플래그가 있을 때만 서비스 매니저를 부르고, 이미 떠 있는 유닛은 재시작하지 않는다 | 제안됨 |
| [0033](0033-session-audit-management.md) | 세션 및 audit 관리 개선은 세션 목록 필터와 읽기 전용 로컬 `qsh audit`까지로 하고, audit 삭제 경로와 텔레메트리 계약 승격은 만들지 않는다 | 제안됨 |
| [0035](0035-windows-client.md) | Windows client는 직접 연결 client 명령과 콘솔 raw 모드 대화형 attach까지 연다. host 역할과 localctl 대체는 열지 않는다 | 제안됨 |
| [0036](0036-stateless-reset-key.md) | stateless reset key는 config 디렉터리의 0600 파일 `stateless_reset.key`에 두고, 읽을 수 없거나 형식이 틀리면 파일을 건드리지 않은 채 이번 기동만 임시 키로 뜬다 | 승인됨 |
| [0037](0037-stalled-tunnel-stream-eviction.md) | 연결 하나에서 정체한 터널 스트림이 연결 수신 창을 다 쓰기 전에 가장 오래 정체한 스트림부터 끊는다 | 승인됨 |
| [0038](0038-setup-client-complete-without-acl.md) | `qsh setup client`의 `complete`는 doctor의 `acl_policy_missing` 하나를 세지 않는다(ADR-0024 결정 9 개정). doctor의 진단 등급과 host 쪽 역할의 판정은 그대로 둔다 | 승인됨 |
| [0039](0039-forced-doh-resolver.md) | DNS-over-HTTPS 강제 모드는 P1에 넣지 않는다. P2 후보로 두고 착수할 때의 모양(해석 seam 하나, IP 리터럴 bootstrap, fail closed `doh-only`)만 지금 고정한다 | 승인됨 |
| [0040](0040-ech-policy.md) | ECH는 기본으로 켜지 않는다. rustls에 서버 쪽 ECH가 생길 때까지 구현을 보류하고 `off`/`prefer`/`require` 정책의 모양만 고정한다. hostname SNI는 ECH와 별개로 보내지 않는 쪽을 권한다 | 승인됨 |
| [0041](0041-reverse-registration-detection-budget.md) | 역방향 등록 연결의 PathWatch 감지 예산을 대화형 attach의 2초 상한에서 분리하고 기본 창을 약 5초로 둔다. attach 기본값은 그대로이고 역방향 등록은 `min_dead_after` 4250ms·`strikes` 3, 재정의 키 `reverse_min_dead_after_ms`·`reverse_strikes`, 상한 5초다(ADR-0021 결정 4의 기본값과 결과 절 상한을 역방향에 한해 개정) | 승인됨 |
| [0042](0042-watch-self-delay-and-quick-loss-backoff.md) | PathWatch는 자기 tick의 지연을 침묵에서 덜어내고(`late >= probe_interval`이면 `last_inbound`를 앞으로 밀고 그 tick은 사망을 선언하지 못한다) 판정 줄에 `tick_gap_ms`를 싣는다. 역방향 target은 60초 안에 끝난 등록이 연속되면 재dial 지연을 두 번째부터 2배씩 8초까지 늘린다. `cause` 분류를 보정한다(`Reset`은 `peer_closed`, `Hello` 시간 초과는 `dial_timeout`). 설정 키·wire 변경 없음 | 승인됨 |
| [0043](0043-no-tcp-fallback.md) | TCP/TLS fallback을 만들지 않는다. QSH는 QUIC 전용이고 UDP가 막힌 망은 범위 밖이다. M14를 철회로 닫고 (a)의 transport facade는 유지한다 | 승인됨 |

P1 계획(`docs/ROADMAP.md` §5)이 0029~0035를 예약했다. 예약 밖의 번호는 0036(stateless reset key), 0037(정체 터널 스트림), 0038(`setup client`의 `complete`), 0039(DoH 강제 모드), 0040(ECH 정책), 0041(역방향 등록 감지 예산), 0042(감시 자기 지연과 빠른 유실 backoff), 0043(TCP fallback 철회)이 받았으므로 다음 새 번호는 0044이다. 조건부로 서는 ADR은 설 때 그 번호부터 쓴다.

- 0034 세션 거처(M18). 착수 조건(M8 DoD 3 기록)이 닫히면 쓴다

0029~0033과 0035는 2026-10-11 초안이 올라 위 표에 있다.
