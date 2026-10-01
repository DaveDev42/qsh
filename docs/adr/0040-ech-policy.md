# ADR-0040: ECH는 기본으로 켜지 않는다. rustls에 서버 쪽 ECH가 생길 때까지 구현을 보류하고 `off`/`prefer`/`require` 정책의 모양만 고정한다. hostname SNI는 ECH와 별개로 보내지 않는 쪽을 권한다

날짜: 2026-10-01
상태: 승인됨 (2026-10-01 사용자 확정, 결정 2를 M13에서 구현)

개정 관계: 새 ADR이다. 다른 ADR을 개정하지 않는다. `docs/design/protocol.md` §3(SNI는 검증에 쓰지 않는다)과 §4(ALPN `qsh/1`), ADR-0014(기본 포트 4433), ADR-0036(비밀 파일을 config 디렉터리의 0600 파일로 두는 모양)을 전제로 삼는다. ECHConfig를 DNS로 받는 경로는 ADR-0039(DoH, 제안됨)와 같은 PRD 경계 문제를 공유한다. 예약 번호(0027~0035) 밖의 새 번호다.

## 맥락

GitHub 이슈 #9는 qsh의 QUIC 핸드셰이크에 Encrypted ClientHello(ECH)를 기본으로 켜 달라고 요청한다. 요구 사항은 의존 TLS 스택의 현행 ECH 사용(ESNI 초안 제외), ECHConfig의 발견과 갱신(HTTPS/SVCB 레코드나 명시적 프로비저닝), private CA·pin·device 신원 검사 유지, outer(cover) 이름 규정, `require`/`prefer`/`disable` 호환 정책, ECH 불가·ECH 거부·일반 TLS/인증 실패를 구별하는 진단, 역방향 등록·직접 dial·터널 재접속의 정책 일치다. ESNI는 이 ADR의 범위 밖이다.

오늘 qsh 클라이언트가 보내는 ClientHello를 코드에서 확인했다.

- 모든 qsh 다이얼은 `qsh_transport::Dialer::dial_inner`(`crates/qsh-transport/src/endpoint.rs`)를 지나고, 그 안의 `client_tls_config` 하나가 rustls `ClientConfig`를 만든다. 테스트 하네스(`crates/qsh-testkit/src/raw_quic.rs`)를 빼면 다른 빌더는 없다. TLS 1.3 전용이고 ALPN은 `qsh/1`(`crates/qsh-proto/src/wire.rs`의 `ALPN`)이다. 세션 재개와 0-RTT는 꺼져 있다.
- SNI 값은 `server_name_for`(`crates/qsh-core/src/ops/mod.rs`)가 정한다. 주소의 host 부분을 그대로 쓰고, 그 함수의 doc comment는 "the host part of the address is the most useful one for packet captures"라고 이유를 적는다.
- rustls 0.23.45(`Cargo.lock`)는 `ServerName::DnsName`일 때만 SNI 확장을 싣는다(`src/client/hs.rs`의 `exts.server_name` 분기). 주소가 IP 리터럴이면 quinn이 `ServerName::IpAddress`로 넘기므로 SNI가 아예 없다. `qsh pair invite`가 안내하는 후보 주소는 커널이 고른 소스 IP다(`docs/CLI.md` §6.11). 그래서 흔한 배치는 이미 SNI 없이 돈다. hostname으로 pin한 peer에서만 그 이름이 평문으로 나간다.
- 서버는 SNI를 쓰지 않는다. `server_tls_config`은 `with_single_cert`로 인증서 하나만 내고, `QshPeerVerifier`는 `_server_name`을 무시한다(`crates/qsh-transport/src/tls.rs`, `docs/design/protocol.md` §3).

QUIC Initial 패킷의 보호 키는 클라이언트가 고른 Destination Connection ID에서 유도되므로(RFC 9001 §5.2) on-path 관찰자는 누구나 ClientHello를 읽는다. 오늘 수동 관찰자가 qsh 연결에서 얻는 것은 다음과 같다.

| 관찰 대상 | 오늘 | ECH가 켜지면 |
|---|---|---|
| 목적지 IP와 UDP 포트(기본 4433, ADR-0014) | 보인다 | 그대로 보인다 |
| QUIC 버전, 패킷 크기와 타이밍 | 보인다 | 그대로 보인다 |
| ALPN `qsh/1` | 평문이라 qsh 연결임을 그대로 드러낸다 | inner ClientHello로 들어간다. outer에 무엇이 남는지는 rustls 구현을 따르므로 구현 때 패킷으로 확인해야 한다 |
| SNI | IP로 dial하면 없다. hostname으로 dial하면 그 이름이 보인다 | outer에는 ECHConfig의 `public_name`, inner에 실제 이름 |
| 그 이름에 대한 DNS 질의 | 클라이언트의 평문 DNS로 보인다 | 바뀌지 않는다(ADR-0039의 범위) |
| 양쪽 인증서와 device principal | TLS 1.3 Handshake 패킷 안이라 수동 관찰자에게는 안 보인다 | 바뀌지 않는다 |

능동 관찰자는 사정이 다르다. TLS 1.3에서 서버는 클라이언트 인증서를 받기 전에 자기 Certificate를 보낸다. Retry 왕복(ADR-0009)을 마친 아무 프로버나 서버 leaf를 받아 갈 수 있다. ECH는 ClientHello만 다루므로 이것도 바꾸지 않는다.

ECH의 프라이버시는 같은 IP 뒤에 여러 서비스가 숨는 데서 나온다. CDN 같은 client-facing 서버가 그 익명 집합을 만든다. qsh는 직접 연결 도구라서(PRD §4 "Direct first") 목적지 IP가 곧 그 host다. 익명 집합의 크기는 1이다. qsh 연결에서 ECH가 실제로 감추는 것은 hostname SNI와 ALPN 두 가지다.

`docs/design/threat-model.md`에는 메타데이터 프라이버시가 자산으로 올라 있지 않다. §1 자산 표에 없고, §2의 "네트워크 관찰자·능동 공격자" 행은 그들이 가진 권한이 없다는 것만 적는다. hostname과 프로토콜 식별은 오늘 위협 표의 어느 행에도 걸리지 않는다.

rustls의 ECH 지원을 소스에서 확인했다(`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rustls-0.23.45`).

- 클라이언트 쪽은 있다. `client::{EchConfig, EchGreaseConfig, EchMode, EchStatus}`, `ConfigBuilder::with_ech`(TLS 1.3 고정), `ClientConnection::ech_status()`가 있고, `EchStatus`는 `NotOffered`/`Grease`/`Offered`/`Accepted`/`Rejected`를 구별한다. 거부는 `PeerIncompatible::ServerRejectedEncryptedClientHello(retry configs)`, 설정 오류는 `Error::InvalidEncryptedClientHello(EncryptedClientHelloError::{InvalidConfigList, NoCompatibleConfig, SniRequired})`로 나온다. HPKE suite는 `crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES`에 있어 이 저장소의 aws-lc-rs provider와 맞는다. outer 이름은 `EchState::outer_name: DnsName`이고 주석이 "It can only be a DnsName, not an IP address"라고 적는다.
- 서버 쪽은 없다. `src/manual/features.rs`의 기능 목록은 "Client-side Encrypted client hello (ECH)"만 적고 `src/server/` 아래에 ECH 처리 코드가 없다. crates.io에 올라온 최신 pre-release인 0.24.0-dev.1도 같다(같은 기능 목록 문장, `src/server/config.rs`에는 클라이언트용 필드 초기화 한 줄뿐이다).

`qsh serve`와 `qsh listen`은 rustls 서버다. 양쪽이 모두 qsh인 연결에서 ECH는 오늘 성립할 수 없다. 이슈의 "peer가 지원하면 기본으로 켠다"는 조건은 현재 의존성으로는 한 번도 참이 되지 않는다.

ECHConfig를 어디서 받느냐도 열려 있다. HTTPS/SVCB 레코드는 DNS 통합이라 PRD §12("DNS와 service discovery"는 QSH 밖)와 부딪히고(ADR-0039 맥락), IP로 pin한 peer에는 레코드를 걸 이름 자체가 없다. 남는 길은 명시적 프로비저닝인데, `trust.toml`이나 pairing 교환에 새 필드를 들이는 일이다.

## 결정

1. ECH는 기본으로 켜지 않는다. 이슈 #9의 "기본으로 켠다"는 지금 받지 않는다. 서버 쪽 ECH가 rustls에 없어서 기본 `prefer`는 아무것도 협상하지 못하고, 할 수 있는 일은 GREASE뿐이다. GREASE는 미래 ECH 트래픽과 섞일 익명 집합이 있을 때 의미가 있는데 qsh 연결에는 그런 집합이 없다.

2. hostname SNI는 ECH와 별개로 보내지 않는 쪽을 권한다. `client_tls_config`에서 `enable_sni = false`로 두면 hostname으로 dial해도 ClientHello에 이름이 실리지 않는다. 검증도 서버도 SNI를 쓰지 않고, IP로 dial하는 흔한 배치가 이미 SNI 없이 돌고 있다. 이 변경으로 잃는 것은 패킷 캡처에서 보이던 이름(`server_name_for`의 doc comment가 적은 디버깅 편의)뿐이다. wire freeze 계약에도 SNI 행이 없다(`docs/design/protocol.md` §16.1·§16.2의 동결 표는 ALPN과 검증 코어는 고정하지만 SNI는 적지 않는다). ECH가 이 ADR로 막아 주려던 hostname 노출의 대부분을 비용 없이 없앤다. 넣을지와 어느 마일스톤에 넣을지는 사용자가 정한다. 넣는다면 작은 단독 커밋이다.

3. ECH 구현은 착수 조건이 설 때까지 보류한다. 조건은 둘이다. (a) qsh가 쓰는 rustls 줄(지금은 0.23)의 정식 릴리스에 서버 쪽 ECH가 들어온다. (b) quinn 0.11의 `QuicClientConfig`/`QuicServerConfig`가 그 설정을 막지 않음을 테스트로 확인한다. 둘이 서면 이 ADR에 추기를 달고 그때 열린 마일스톤에 넣는다. 지금 ROADMAP §5의 P1 마일스톤 어디에도 넣지 않는다. 그 전까지 플래그와 config 키를 예약하지 않는다.

4. 정책의 모양은 지금 고정한다. `config.toml`의 `[transport].ech`(ADR-0021이 연 `[transport]` 표) 값 셋이다.

   | 값 | 거동 |
   |---|---|
   | `off` (착지 시 기본) | ECH 확장을 싣지 않는다. GREASE도 싣지 않는다 |
   | `prefer` | 그 peer의 ECHConfig가 있으면 ECH를 제시한다. 없으면 일반 핸드셰이크다. 서버가 거부하면 그 시도는 실패로 끝내고, 같은 dial 안에서 ECH 없이 한 번 다시 시도한다. 그 강등은 진단 줄에 `rejected`로 남는다. 서버가 보낸 retry config는 자동으로 저장하지 않는다 |
   | `require` | ECHConfig가 없거나, 형식이 틀리거나, 서버가 거부하면 dial을 실패로 끝낸다. 강등하지 않는다 |

   기본값을 `off`에서 `prefer`로 옮기는 일은 단계적 배포를 전제로 한 별도 결정이다. 옛 qsh peer와 섞인 상태에서 `prefer`가 연결을 깨지 않음을 상호운용 테스트로 보인 뒤에 한다.

5. 정책은 클라이언트 쪽 한 지점에서 걸린다. 모든 다이얼이 `Dialer::dial_inner`의 `client_tls_config`를 지나므로 역방향 등록(`reverse/target`), 직접 dial(attach, exec), supervise 재수립, probe, `pair accept`가 자동으로 같은 정책을 따른다. 경로별 예외는 두지 않는다. 단 pairing dial(`AcceptAnyForPairing`)은 아직 상대의 ECHConfig를 알 수 없으므로 `require`에서도 ECH 없이 간다. 이 예외는 문서에 적는다.

6. ECHConfig는 명시적 프로비저닝으로만 받는다. 서버는 config 디렉터리에 HPKE 키 쌍을 0600 파일로 두고(ADR-0036의 보관 규율), `qsh identity export`처럼 공개 ECHConfigList를 내보내는 명령을 둔다. 클라이언트는 그것을 `trust.toml`의 peer 항목 필드(base64 ECHConfigList)로 갖는다. DNS HTTPS/SVCB 레코드에서 읽는 경로는 ADR-0039가 PRD 경계를 고친 뒤에만 연다. 키 회전 때 서버는 이전 키를 정해진 기간 동안 함께 받는다. 개인키는 로그, audit, 진단, JSON 어디에도 싣지 않는다.

7. outer 이름은 운영자가 정한다. rustls가 `public_name`에 DNS 이름만 받으므로 IP로 pin한 peer에도 이름이 하나 있어야 한다. qsh가 고정 기본값(예: `qsh.invalid`)을 두면 그 값 자체가 ALPN처럼 qsh를 드러내므로 기본값을 두지 않는다. `prefer`나 `require`를 켠 서버에 `public_name`이 없으면 `CONFIG_ERROR`로 기동을 거절한다. 문서는 outer 이름이 평문으로 보인다는 사실을 적는다.

8. 신원 규칙은 바뀌지 않는다. pin, private CA 체인, leaf 유효기간 검사, principal 도출은 ECH 상태와 무관하다. ECH 상태는 principal이나 ACL 판정의 입력이 되지 않는다. ECH가 거부되어 outer 핸드셰이크로 끝나는 경우에도 `QshPeerVerifier`는 같은 규칙으로 검증한다.

9. 진단은 실패 종류를 가른다. 다이얼 결과에 ECH 상태(`not_offered`/`accepted`/`rejected`/`unavailable`/`invalid_config`)를 붙인다. `unavailable`은 `require`인데 ECHConfig가 없는 경우, `invalid_config`는 `EncryptedClientHelloError`인 경우다. 이 값은 `qsh::reverse`와 supervise의 stderr 진단 줄에 additive 필드로 들어가고 TLS·인증 실패의 기존 분류(`tls_rejected` 등)와 겹치지 않는다. `ErrorCode`는 늘리지 않는다. `require` 실패는 `CONNECTION_FAILED`이고 `retryable: false`다. 같은 설정으로 다시 시도해도 결과가 같기 때문이다.

10. 문서는 ECH가 감추지 않는 것을 적는다. 목적지 IP와 포트, 패킷 타이밍과 크기, outer 이름, 클라이언트의 DNS 질의, 능동 프로버가 받아 가는 서버 인증서다.

## 근거

이 결정의 축은 두 사실이다. 서버 쪽 ECH가 의존성에 없으니 지금 할 수 있는 구현이 없다. 그리고 qsh 연결에서 ECH가 감추는 것 중 가장 민감한 hostname은 ECH 없이도 SNI를 끄면 사라진다. 그러면 남는 이득은 ALPN `qsh/1`을 감추는 것인데, 포트 4433, 직접 연결이라 크기 1인 익명 집합, QUIC 패킷 모양이 그대로 보이는 상황에서 ALPN 하나를 감춘 효과는 작다. 위협 모델에 메타데이터 프라이버시 자산이 없다는 점도 같은 방향이다. 자산을 새로 두는 것부터가 사용자 결정이다.

정책 모양을 지금 고정하는 것은 이슈가 요구한 세 값의 의미를 rustls의 실제 API(`EchMode`, `EchStatus`, 거부 오류의 retry config)에 맞춰 두려는 것이다. 특히 `prefer`가 거부를 만나 강등하는 규칙과 retry config를 저장하지 않는 규칙은 다운그레이드 공격의 표면을 정한다. 구현 직전에 급히 정할 일이 아니다.

## 대안

- 이슈대로 기본 `prefer`로 지금 구현한다. 기각한다. 서버가 ECH를 받지 못하므로 협상이 한 번도 성립하지 않는다. 클라이언트 코드와 테스트만 늘고 효과는 0이다.
- 서버 쪽 ECH를 qsh가 직접 구현하거나 rustls를 fork한다. 기각한다. TLS 핸드셰이크 상태 기계를 qsh가 소유하게 되고, `deny.toml`의 `unknown-git = "deny"` 규율과 공급망 단순성을 버린다. 독립 보안 리뷰(SC7)의 범위도 그만큼 커진다.
- ECH를 GREASE 모드로만 켠다. 기각한다. 결정 1의 이유대로 qsh 연결에는 섞일 익명 집합이 없고, 이미 ALPN과 포트로 식별되는 트래픽에 GREASE를 얹어도 숨는 것이 없다.
- ECHConfig를 DNS HTTPS/SVCB 레코드로 받는다. 지금은 기각한다. PRD §12와 부딪히고, IP로 pin한 peer에는 레코드를 걸 이름이 없다. ADR-0039가 PRD 경계를 바꾸면 결정 6의 프로비저닝 경로에 더하는 additive 확장으로 다시 연다.
- `prefer`에서 서버가 보낸 retry config를 자동으로 받아 들인다. 기각한다. 거부 응답의 retry config는 그 연결의 outer 핸드셰이크가 검증된 뒤에야 믿을 수 있고, 자동 저장은 `trust.toml`을 사람이 모르게 바꾸는 쓰기가 된다. qsh는 trust 파일을 명시적 명령으로만 바꾼다.
- 결정 2(SNI 끄기)도 하지 않고 그대로 둔다. 가능한 선택이고 사용자 결정으로 남긴다. hostname으로 pin하는 사용자가 적다면 이득이 작다. 다만 비용도 패킷 캡처의 편의 하나뿐이라 권장은 끄는 쪽이다.

## 결과

- 이 ADR이 승인되어도 P1 마일스톤 범위는 바뀌지 않는다. 결정 2를 받기로 하면 그것만 작은 단독 변경으로 열린 마일스톤에 넣는다. 그 변경이 갚을 것은 이렇다. `client_tls_config`의 `enable_sni = false`, `server_name_for` doc comment 수정, 테스트 `client_hello_carries_no_sni_for_a_hostname_address`(testkit에서 hostname 주소로 dial한 ClientHello를 서버 쪽 rustls `ClientHello::server_name()`으로 관찰해 `None`임을 단언), `docs/design/protocol.md` §3의 SNI 문장 보강. `qsh.cli/v1`, wire, fixture는 바뀌지 않는다.
- `docs/ROADMAP.md` §5.3("P1 밖으로 보낸다")에 ECH 행을 이 ADR 인용과 착수 조건(결정 3)으로 더하는 것은 메인 세션이 한다.
- 결정 3의 조건이 서서 구현할 때 갚아야 할 계약 변경이다. 모두 additive다. `[transport].ech`와 서버의 `public_name`·HPKE 키 파일, `trust.toml` peer 항목의 ECHConfigList 필드, ECHConfig 내보내기 명령(새 op이므로 `docs/CLI.md`와 capability fixture에 함께 오른다), stderr 진단 줄의 ECH 상태 필드, 키 파일 권한에 관한 doctor 진단이 필요하면 `EXPECTED_DOCTOR_CODES`에 하나. `docs/design/threat-model.md` §1에 HPKE 개인키 자산 행, §4에 다운그레이드(거부 유도로 `prefer`를 평문 강등) 행을 더한다.
- 그때 갚아야 할 테스트다. 이름은 구현 시 확정한다.
  - `ech_off_is_byte_identical_to_today`: `off`에서 ClientHello에 ECH 확장이 없다.
  - `ech_prefer_negotiates_with_a_capable_server`: 두 qsh 사이에서 `EchStatus::Accepted`이고 outer SNI가 `public_name`이다.
  - `ech_prefer_against_an_old_peer_connects_without_ech`: ECH를 모르는 qsh 서버와도 연결된다(단계적 배포의 근거).
  - `ech_prefer_downgrade_is_reported_as_rejected`, `ech_require_refuses_when_unavailable`, `ech_require_refuses_when_rejected`.
  - `ech_malformed_config_is_invalid_config_not_tls_rejected`: 진단 분류가 일반 TLS 실패와 섞이지 않는다.
  - `ech_key_rotation_accepts_the_previous_key_within_the_window`.
  - `ech_never_changes_the_principal`: 같은 peer의 principal과 ACL 판정이 ECH 상태와 무관하다.
  - `ech_private_key_never_appears_in_logs_audit_or_diagnostics`(ADR-0036의 핀 테스트와 같은 모양).
  - 기업 TLS 가로채기(ECH를 벗기고 재암호화하는 middlebox)는 qsh의 pin 검증이 이미 실패시키므로 새 통제가 아니라 기존 A행의 사례로 문서에 적고, `require`에서 그 실패가 `tls_rejected`로 분류됨을 테스트한다.
- 크기는 조건이 선 뒤 1.5~3ew로 추정한다. 측정값이 아니다. 프로비저닝 표면(키 파일, 내보내기 명령, `trust.toml` 필드)이 대부분이고 rustls 연결 자체는 작다.
