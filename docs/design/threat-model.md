# QSH 위협 모델

관련 문서: [PRD](../PRD.md) · [CLI 계약](../CLI.md) · [wire protocol](protocol.md) · [아키텍처](architecture.md) · [테스트 전략](testing.md) · [ADR](../adr/) · [fuzz 캠페인](../campaigns/m8-fuzz.md)

## 0. 지위와 범위

이 문서는 M8 Step 7이 wire freeze 문면([protocol.md](protocol.md) §16)과 함께 내는 산출물이고, `docs/PRD.md` §15가 요구하는 "공개 beta 전 protocol과 key lifecycle의 독립 보안 review"(SC7)에 넘길 리뷰어 입력이다. 기준 트리는 M8 Step 7 시점이며, 인용한 `파일:줄`은 그 트리에서 확인한 값이다.

**이 문서가 canonical인 것은 §4의 위협 → 통제 → 근거 → 핀 테스트 대응표 하나다.** 통제 자체의 설계 근거는 여전히 ADR과 protocol.md·architecture.md에 있고, 어느 테스트가 어느 계층을 갚는지는 testing.md에 있다. 그 셋을 가로질러 "이 위협을 무엇이 막고, 그것이 깨지면 무슨 테스트가 빨개지는가"를 한 곳에 모은 표가 여기 말고는 없다.

범위:

- `qsh.wire.v1` 프로토콜 표면 전체 — 프레이밍, control message, 스트림 배치, resume, 역방향 등록, 터널.
- TLS 신뢰 수립(pin·private CA·pairing 세 경로)과 principal 도출.
- ACL 판정과 audit 기록.
- admission·quota 자원 상한.
- 로컬 상태 파일(identity, trust, invites, resume, audit)과 그 권한.
- localctl UDS(`qsh.local.v1`) — freeze 대상은 아니지만(protocol.md §16.3) 진입점으로는 이 문서 안에 있다.
- M9가 신설한 사람용 표면 명령 여섯 — `pair invite|accept --as`, `identity export`, `trust add --cert-file`, `trust add-ca`, `trust rename`, `service install|uninstall|status`. 구현은 `db122f5`·`699af37`·`93e8b76`·`bd34c92`로 착지했고, 진입점은 §3, 위협은 §4, 핀이 없는 것은 §5와 §7에 있다. §5 g4는 닫혔다.

비범위:

- OS 커널·하이퍼바이저·컨테이너 격리, 물리 접근, 콜드부트류 메모리 추출.
- 사용자가 세션 안에서 실행하는 프로그램. qsh는 셸을 내주는 도구이고, 인가된 peer가 그 셸로 무엇을 하는지는 ACL의 관심사가 아니다(PRD §9의 action 어휘가 정하는 것은 "어떤 종류의 요청을 받는가"까지다).
- 공급망(의존성 취약점·yanked crate)은 `cargo deny check`가 별도 게이트로 본다 — 이 문서는 그 게이트의 존재만 기록하고 위협 표에 행을 두지 않는다.
- 릴리스 아티팩트 서명·notarization은 M10 소관이다(`docs/ROADMAP.md` M10 수용 기준).

## 1. 자산

| 자산 | 위치 | 근거 |
|---|---|---|
| device 개인키 | `identity/device.key`(0600, PKCS#8 PEM) 또는 OS keyring | `architecture.md:75-76`; `crates/qsh-core/src/identity/mod.rs:8-9` |
| CA 루트 개인키 | `config_dir/ca/ca.key`(0600, 파일 전용) | `docs/adr/0008-private-ca-cert-issuance.md`(ADR-0008 결정 4) |
| `trust.toml` | pinned peer(이름+fingerprint)와 private CA 목록 | `architecture.md:77,102` |
| `invites.toml` | 0600. `mac_key`(invite secret의 BLAKE3)와 생성 시각 | `protocol.md` §15.7 |
| `acl.toml` | 정책. qsh는 이 파일을 절대 쓰지 않는다 | `architecture.md:103`; `docs/adr/0017-acl-toml-not-written.md`(ADR-0017 결정 1) |
| resume token | `resume.json`(0600, flock + tmp·rename 원자 교체), 메모리에서는 `Zeroizing<[u8;32]>` | `architecture.md:105`; `docs/adr/0007-session-ref-and-resume-token-custody.md`(ADR-0007 결정 2) |
| 세션 PTY와 child 프로세스 | broker `SessionActor`가 소유. child는 항상 `qsh serve`를 실행한 OS 계정 | `architecture.md:46,69` |
| audit 로그 | `$XDG_STATE_HOME/qsh/audit.log`, JSONL, fail-closed | `architecture.md:90,105` |
| localctl UDS | `$XDG_RUNTIME_DIR/qsh/<pid>.sock`, 디렉터리 0700, 소켓 파일 0600 | `architecture.md:106`; `crates/qsh-core/src/localctl/daemon.rs:144` |
| ReplayRing(세션 output 이력) | 세션당 기본 8 MiB byte 예산의 메모리 chunk ring, `ReplayStore` trait 뒤 | `docs/adr/0004-replay-buffer-memory-only.md`(ADR-0004 결정); `crates/qsh-core/src/broker/ring.rs:13-15`; 기본값 `crates/qsh-core/src/config.rs:539` |

ReplayRing은 자산이면서 그 자체가 통제다. PTY 평문 output이 프로세스 메모리에만 남고 디스크에는 어떤 경로로도 남지 않는다는 것이 ADR-0004의 보안적 요점이고(`:19` "PTY 내용이 디스크에 남는 것 자체가 새로운 공격 표면", `:26` 평문 disk spool은 "논의 대상조차 아니다"), 그 대가가 §7 h15의 8 MiB 상한이다.

## 2. 주체와 신뢰 경계

| 주체 | 권한 | 경계를 세우는 것 |
|---|---|---|
| pin된 원격 peer(`AuthPath::Pin`) | 자기 principal에 걸린 `acl.toml` 행이 허용하는 action | SPKI SHA-256 pin 일치(`protocol.md` §3) |
| CA 발급 peer(`AuthPath::Ca`) | 같음. principal은 leaf의 SAN URI에서만 온다 | private CA 체인 검증(`protocol.md` §3), `auth_path` 키로 정책 행 분리(`architecture.md:84`) |
| 페어링 중인 미지 peer(`Principal::Pairing`) | 없음 — `Hello`에도 dispatch에도 ACL에도 닿지 못한다 | `pairing_open()`이 참인 창(살아 있는 invite ≤ 20분) 안에서만 TLS를 통과하고(`protocol.md` §15.1), 그 뒤로는 §15.2의 우회 경로만 탄다(`protocol.md` §15.2) |
| 그 외 미지 peer | 없음 | 검증 코어의 3번 경로: 무조건 거부(`protocol.md` §3) |
| 같은 uid의 로컬 호출자(localctl) | 데몬이 들고 있는 것을 조회·조작 | same-uid peer credential. **인가 계층이 아니다** — 그 프로세스는 이미 device 개인키를 읽을 수 있는 uid다 |
| 같은 호스트의 다른 사용자 | localctl UDS와 로컬 상태 파일에는 없음. `-L`/`-D`가 여는 loopback TCP listener에는 있다 — 그 principal의 `forward.local` 권한 전체(`-D`는 host가 닿는 모든 목적지) | localctl UDS·상태 파일: 파일 권한(0600/0700) + accept 시 euid 검사. loopback TCP listener: 없음 — TCP 포트는 파일 권한도 euid 검사도 거치지 않고 같은 머신의 어떤 uid에서도 그냥 connect된다(ADR-0019 결정, §7 h16) |
| 네트워크 관찰자·능동 공격자 | 없음 | QUIC/TLS 1.3 양방향 인증(`protocol.md` §3), 0-RTT 전면 금지(`protocol.md` §2) |
| 에이전트(`--json` 호출자) | 그 CLI를 실행한 사용자와 같다 | 별도 경계가 아니다 — `Ops` 파사드를 통과할 뿐이고, JSON 모드는 권한이 아니라 출력 형식이다 |

경계는 셋이다. (1) 네트워크 ↔ `qsh serve` 프로세스: TLS 검증 코어가 유일한 통과점이고, 검증된 principal 없이는 어떤 스트림도 application 계층에 닿지 않는다. (2) principal ↔ 리소스: `Server::dispatch`(`crates/qsh-core/src/server/mod.rs:782`)가 단일 choke point이고 네 인가 지점이 그 아래에 있다(`server/mod.rs:906,931,1018`, `crates/qsh-core/src/reverse/admit.rs:78`). (3) 로컬 파일 시스템 ↔ 프로세스: 권한 비트 하나가 전부다.

## 3. 진입점

| 진입점 | 신뢰 수준 | 비고 |
|---|---|---|
| `qsh serve` accept loop | 미인증 UDP | 노출 포트는 하나뿐이다 — 기본 `[::]:4433`(`crates/qsh-core/src/serve.rs`의 `DEFAULT_BIND`, `docs/adr/0014-address-default-port.md`(ADR-0014 맥락)). ADR-0014는 `상태: 승인됨`(`:4`)이고, peer 주소의 포트 생략은 파서·조회 양쪽에서 4433으로 채운다 — 파일은 쓰지 않는다(`docs/CLI.md` §6.11) |
| `qsh listen` / `qsh serve --to`(구 표기 `qsh reverse`) accept | 미인증 UDP | **pairing evaluator를 attach하지 않는다** — 역방향 conduit은 사전 pin/CA로만 신뢰를 세운다(`protocol.md` §15.8) |
| localctl UDS | same-uid 로컬 | `<pid>.sock`, 디렉터리 0700, 소켓 파일 0600(`crates/qsh-core/src/localctl/daemon.rs:144`) |
| CLI 전체 | 로컬 사용자 | 모든 명령이 `Ops`를 통과한다 |
| `qsh pair invite`(구 표기 `qsh trust invite`)의 경로 질의 | 로컬 커널 (나가는 바이트 0) | 소스 주소를 묻기 위해 문서용 예약 주소(RFC 5737 `192.0.2.1`, RFC 3849 `2001:db8::1`)로 UDP `connect`만 하고 전송은 하지 않는다 — 와이어에 패킷이 없으므로 원격 관찰자에게는 표면이 아니고, 대기가 없으므로 대화형 명령을 막지도 않는다. 결과는 human stdout 전용이고 machine mode는 질의 자체를 하지 않는다. `xtask arch`의 디렉터리 스코프 금지(`crates/qsh-core/src/trust/invite_address/`)가 이 전제를 기계로 강제하고, machine mode 불변식은 별도로 `route::observation_count`(관측 카운터)가 `qsh-cli`의 실제 dispatch arm 테스트로 고정한다 |
| `config.toml` / `trust.toml` / `acl.toml` / `hosts.toml` | 로컬 파일 | 파싱 실패는 fail-closed(`architecture.md:87`) |
| invite code 입력 | 사람이 옮긴 문자열 | 20바이트 CSPRNG → Crockford Base32, `crates/qsh-proto/src/pairing.rs` |
| cert 파일 교환 | 로컬 파일 | ADR-0013 |
| `qsh pair invite [--as N]` / `qsh pair accept <address> <code> [--as N]` | 로컬 사용자(이름 결정) + 원격 미지 peer(교환 자체) | 이름 결정권은 pin하는 쪽에만 있다(ADR-0012 결정 6). `--as`는 로컬 요청 타입 `TrustInviteReq.as_name`/`TrustAcceptReq.as_name`에만 실리고 wire의 자칭 값(`PairingProof.device_name`/`PairingAccepted.device_name`)은 `device_id` 그대로라, 상대가 보낸 문자열이 내 `trust.toml` 이름이 되는 경로가 없다. invite 쪽 `--as`는 발급 시점에 `invites.toml` 레코드로 들어가 redeem 때 자칭 이름을 밀어내고, accept 쪽 `--as`는 이쪽 store에만 적용되며 둘은 서로에게 관여하지 않는다. 경로 질의 축은 위 `qsh pair invite`의 경로 질의 행, invite code의 형식·입력 경로는 위 invite code 입력 행과 같다. 자산: `invites.toml`(0600), `trust.toml`(0600), 둘 다 0700 config dir 안. 인가: 로컬 op이라 ACL 밖이고, 교환 자체의 관문은 invite 비밀 소지 증명(TLS exporter 결합) 하나다 — 교환 중 peer는 `Principal::Pairing`이라 §2 그대로 ACL에 닿지 않는다 |
| `qsh identity export [--out <path>]` | 로컬 사용자 → 파일시스템/stdout | 키스토어에서 나가는 것은 `identity/device.pem`의 텍스트뿐이다 — `Ops::identity_export`(`crates/qsh-core/src/ops/identity.rs:50`)가 `read_identity` 뒤 `device.pem`을 직접 다시 읽어 그 바이트를 그대로 돌려주고, `identity::load`·`KeyStore`·`KEY_FILE`·`open_store` 어느 것도 본문에 없다(ADR-0013 결정 3). `--out`은 `create_new(true)`라 기존 파일을 덮지 않고(`identity.rs:100-104`) 마지막 경로 요소가 심링크여도 `EEXIST`다. 산출물 모드는 0600을 강제하지 않는다 — 공개값이라는 것이 ADR-0013 결정 3의 명시적 판단이다. 자산: `identity/device.key`와 OS keyring은 이 경로가 열지 않는다. 인가: 로컬 op |
| `qsh trust add <name> --cert-file <pem|->` | 로컬 파일 또는 stdin | 전달 채널의 인증은 qsh 밖에 있다 — 이 경로가 요구하는 유일한 것이 그것이고, `--trust-on-first-use` 부류 플래그는 명시적 비목표다(ADR-0013 결정 6). 읽은 PEM은 `CERTIFICATE` 블록 정확히 하나여야 하고 다른 라벨 블록이 하나라도 섞이면 거부한다(ADR-0013 결정 4). 구조 검증만 한다 — 유효기간도, EKU/basicConstraints도 보지 않는다(`docs/CLI.md` §6.11). 파일·stdin 읽기는 `CERT_PEM_MAX`(64 KiB, `crates/qsh-core/src/ops/mod.rs:292`) 상한보다 1바이트만 더 `take`해 초과를 탐지할 수 있게 하고, 상한을 넘는 입력은 파싱 전에 `INVALID_ARGUMENT`로 거부된다(`check_cert_pem_size`, `crates/qsh-core/src/ops/trust.rs:60,528`; `docs/CLI.md` §6.11) — M10이 코드로 닫았다(심링크는 D9가 흡수해 무해하다). 경로 교환 자체는 위 cert 파일 교환 행과 같다. 자산: `trust.toml`. 인가: 로컬 op |
| `qsh trust add-ca <name> --cert-file <pem|->` | 로컬 파일 또는 stdin | 등재된 루트는 **이름 결정권 그 자체**를 준다 — CA 경로의 principal은 leaf의 SAN URI에서만 오고(§2) `[[ca]]` 라벨은 principal이 아니므로, 그 CA가 서명한 leaf는 자기 SAN이 자칭하는 어떤 principal로든 인증된다. 등재는 append-only다: 같은 이름에 다른 PEM이면 `INVALID_ARGUMENT`이고 교체는 `trust remove`를 거쳐야 한다(ADR-0013 결정 5). `<name>`은 앞뒤 공백을 제거한 뒤 `trust rename`의 `new`와 같은 공유 검증기를 거친다(`validate_peer_label_arg`, ADR-0012 결정 6, `crates/qsh-core/src/ops/trust.rs:155`) — M10이 코드로 닫았다. 트리밍이 검증에 앞서는 이유는 공유 검증기 혼자서는 순수 공백(U+0020)을 통과시키기 때문이다: `validate_device_name`이 거부하는 네 부류(길이·제어문자·bidi·zero-width) 어디에도 공백은 들지 않으므로, 트리밍 없이 이 검증기만 얹으면 `trust add-ca "   "`가 조용히 성공해 옛 trim+빈 문자열 검사보다 오히려 느슨해진다. cert PEM 크기 상한은 위 `trust add --cert-file` 행과 같다. 자산: `trust.toml`의 `[[ca]]`. 인가: 로컬 op이고, 이 등재가 `acl.toml`을 쓰지는 않는다(ADR-0017 결정 1) |
| `qsh trust rename <old> <new>` | 로컬 사용자 → `trust.toml` | 이 명령은 principal 문자열을 바꾼다 — `trust.toml`의 이름이 그대로 `Principal::Device(<name>)`가 되고 store는 매 handshake마다 내용 diff로 다시 읽히므로, 재시작 없이 다음 handshake부터 새 principal이다. `acl.toml`은 기동 시 1회만 읽으므로 새 이름을 겨눈 행은 재시작 전까지 없고 그 사이는 default-deny다(ADR-0012 결정 7). 로컬 trust 조작 중 유일하게 audit을 남기며, 순서가 잠금 → load → rename → audit → save라 기록 없이 이름만 바뀌는 조합이 없다. 자산: `trust.toml`(tmp+rename 원자 교체, 0600), `audit.log`. 인가: 로컬 op |
| `qsh service install|uninstall|status` | 로컬 사용자 → 서비스 매니저 유닛 디렉터리 | 쓰는 것은 사용자 유닛 하나와, launchd에서는 그 유닛이 로그를 보낼 `~/Library/Logs/qsh` 디렉터리뿐이다 — macOS `~/Library/LaunchAgents/io.qsh.<mode>.plist`, Linux `~/.config/systemd/user/qsh-<mode>.service`. 시스템 스코프(root LaunchDaemon, `/etc/systemd/system`) 경로는 코드에 없다. `<mode>`는 `doctor.run`의 `service_not_registered`와 같은 추론 규칙으로 정하고, `[serve].to`와 구 `[reverse].controller`가 어긋나면 세 op 모두 `CONFIG_ERROR`로 fail closed하며 아무것도 쓰지 않는다. macOS/Linux가 아니면 무엇을 읽거나 쓰기 전에 `UNSUPPORTED`가 먼저 난다. 유닛 파일은 항상 0600, 부모 디렉터리는 없을 때만 만들고 기존 모드는 건드리지 않는다. `status`는 `path.exists()`만 본다 — `launchctl`/`systemctl`을 호출하지 않으므로 파싱할 외부 출력 자체가 없다. 자산: 유닛 파일, `audit.log`. 인가: 로컬 op이고 `acl.toml`은 쓰지 않는다(ADR-0017 결정 1) |
| `Server::dispatch` | 인증된 peer | `server/mod.rs:782` — 디코딩된 모든 요청의 단일 통과점 |

`.proto` 디코더와 로컬 입력 파서가 이 진입점들의 첫 코드다. 그 표면 전체가 freeze 대상이자 fuzz 대상이며(`protocol.md` §16.9, ADR-0001 결과 4번째 불릿), 파서 타깃 16개와 stateful 타깃 `broker_ops`의 상태는 [m8-fuzz.md](../campaigns/m8-fuzz.md)가 기록한다.

## 4. 위협 표

STRIDE를 이 저장소의 증거 구조에 맞춰 일곱 범주로 쓴다: A 스푸핑 / B 무단접근 / C 자원고갈 / D 정보노출 / E 무결성 / F 부인방지 / G 가용성. "핀 테스트" 열은 그 통제가 깨지면 빨개지는 테스트다.

### A — 스푸핑·신원

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| A1 | 피어 신원 위장(pin 경로) | SPKI SHA-256 pin 양방향 검증 | `protocol.md` §3 | `crates/qsh-transport/tests/handshake_matrix.rs:309` case02, `:341` case03. 양성 기준선은 `:273` `case01_pin_pin_both_valid_ok` | — |
| A2 | 피어 신원 위장(CA 경로) | private CA 체인 검증, SAN URI 없는 leaf는 거부 | ADR-0008 | `handshake_matrix.rs:519` case10, `:543` case11, `:628` case14. 양성 대조군 `:483` `case09_ca_mode_both_ways_ok` | CA revocation 메커니즘 자체가 없다 → §7 h4 |
| A3 | pin/CA 모드 혼동 | 신뢰 저장소 종류별로 검증 경로 분리 | ADR-0008 결정 6 | `handshake_matrix.rs:573` case12, `:605` case13. 혼합 구성이 정상 동작함을 고정하는 양성 대조군 `:653` `case15_mixed_pin_client_ca_server_ok` | — |
| A4 | 인증서 미제시 | 상호 인증 필수(`client_auth_mandatory`) | `protocol.md` §3 | `handshake_matrix.rs:733` case16 | — |
| A5 | 만료·미도래 인증서 | leaf `not_before`/`not_after`를 두 경로 모두에서 검사 | `protocol.md` §3 | `handshake_matrix.rs:363` case04, `:390` case05, `:411` case06 | 로컬 시계에 의존한다 → §8. 장기 device cert에서 유효기간은 유일한 revocation 레버다 |
| A6 | ALPN 위장으로 application 상태에 진입 | `no_application_protocol` alert로 principal 생성 전에 종료 | `protocol.md` §4 | `handshake_matrix.rs:938` case18, `:1015` 대조군 | 서버측 거울 케이스는 의도적으로 쓰지 않았다 |
| A7 | pairing이 pin/CA를 다운그레이드 | pairing 경로는 pin·CA가 **둘 다** 실패한 뒤에만 평가된다 | `protocol.md` §15.1 | `handshake_matrix.rs:803` case17, `:840` case17b | 이미 pin된 상대의 재페어링은 아예 불가 → §7 h7 |
| A8 | resume token 탈취 후 다른 장비에서 attach | 토큰이 opener peer의 SPKI에 결합된다 | ADR-0007 결정 2 | `crates/qsh-testkit/tests/resume_loopback.rs:500` `a_stolen_credential_is_useless_to_a_different_peer`, `:561` | — |
| A9 | 0-RTT early data replay로 부수효과 있는 control message 재전송 | 0-RTT 전면 금지 + 세션 티켓 미발급. client `enable_early_data = false` / `Resumption::disabled()`, server `max_early_data_size = 0` / `send_tls13_tickets = 0` / `NoServerSessionStorage` — 모든 연결이 full mutual auth를 다시 돈다 | `protocol.md` §1, §2; `crates/qsh-transport/src/endpoint.rs:511-512`(client), `:527-529`(server) | `endpoint.rs:1242` `tls_configs_disable_0_rtt_and_session_resumption` — 실제 `ClientConfig`/`ServerConfig`에서 세 필드를 직접 읽고 resumption·session storage는 `Debug` 문자열로 단언한다. 간접 증거는 `crates/qsh-transport/tests/loopback.rs:391` | — (M8 Step 7 이전에는 다섯 상수 중 하나를 되돌려도 깨지는 테스트가 없었다 → §5 g5) |
| A10 | 발급된 invite의 `assigned_name`을 손으로 고쳐 redeem 시 엉뚱한 이름으로 pin하게 만든다 | mint 시점과 redeem 시점 양쪽에서 같은 `validate_peer_label`을 다시 통과해야 한다. redeem에서 실패하면 자칭 이름으로 조용히 되돌아가지 않고 거부하며 invite는 소비되지 않는다 | ADR-0012 결정 6; `docs/CLI.md` §6.11 | `crates/qsh-core/src/trust/pairing.rs:605-609`의 재검증; `crates/qsh-core/src/pairing/tests.rs:133` `invalid_assigned_name_and_pin_collision_produce_the_same_wire_error`(두 거부가 구별 불가능한 같은 wire 오류임을 고정) | — |
| A11 | 상대가 자칭한 이름이 내 `trust.toml` 별칭이 되어 ACL 문자열을 상대가 고른다 | 이름 결정권은 pin하는 쪽에만 있다. `--as`는 로컬 요청 타입에만 실리고 wire의 자칭 값은 `device_id` 그대로다 | ADR-0012 결정 6 | `crates/qsh-testkit/tests/pairing_loopback.rs:320` `invite_assigned_name_never_reaches_the_wire_proof`; `crates/qsh-cli/tests/trust_pairing_live.rs:759` `pairing_frames_still_carry_the_device_id_not_the_assigned_name`, `:689` `invite_side_and_accept_side_as_names_are_independent` | `--as`를 생략하면 자칭 이름이 그대로 pin된다 — 그 경우의 방어선은 `PAIRING_PINNED_SELF_ASSERTED` 고지 하나다 |
| A12 | `trust add --cert-file`로 이미 pin된 이름을 다른 fingerprint에 재결합한다 | `TrustStore::add_peer`가 fingerprint 불일치를 조용한 no-op으로 두고 기존 항목을 한 바이트도 건드리지 않는다(`crates/qsh-core/src/trust/mod.rs:472-475`). 재결합 경로는 `trust remove` 뒤 `trust add` 하나뿐이다 | `docs/CLI.md` §6.11 | `crates/qsh-core/src/ops/tests.rs:2062` `trust_add_cert_file_is_a_silent_no_op_when_the_name_holds_a_different_fingerprint`; CLI 축은 `crates/qsh-cli/tests/init_trust.rs:708`(같은 이름) | 거부가 조용해서 운영자는 성공으로 읽는다 → §7 h23 |
| A13 | `trust add-ca`에 CA가 아닌 leaf를 등재해 그 leaf 키 보유자에게 이름 결정권을 넘긴다 | 없다 — 구조만 검증하고 `basicConstraints`의 CA 여부도 자기서명 여부도 보지 않는다. 계약이 그 사실과 운영자 확인 의무를 명시한다 | ADR-0013 결정 5; `docs/CLI.md` §6.11 | 핀 없음(§7 h24). 인접 통제인 이름 충돌 거부는 `crates/qsh-core/src/ops/tests.rs:2113` `trust_add_ca_rejects_a_second_pem_under_an_existing_name` | 루트성 미검증 자체가 잔여 → §7 h24. h3(CA 키 복제)·h4(revocation 부재)와 같은 뿌리다 |

`exec`, `session.write`, tunnel open은 전부 부수효과가 있다. A9가 다른 행과 성격이 다른 이유가 그것이다 — 재전송이 곧 재실행이므로, replay 가능성을 남기는 대신 성능을 포기했다.

A11이 A7과 짝이다. A7은 pairing이 pin/CA를 다운그레이드하지 못하게 막고, A11은 pairing이 성공한 뒤에도 상대가 내 정책 문자열을 고르지 못하게 막는다. 전자는 TLS 검증 코어가, 후자는 요청 타입의 모양이 지킨다 — 후자 쪽이 더 강하다. 와이어에 그 값을 실을 자리가 아예 없기 때문이다.

### B — 무단접근·인가

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| B1 | 호출자별 판정이 갈려 ACL이 우회됨 | 판정 함수 하나(`Authorizer::check`)를 모든 지점이 공유 | `architecture.md:88` | `crates/qsh-cli/tests/acl_check_equivalence.rs:116,177,220,273,314,434,502,547,596` 아홉 행 | — |
| B2 | 새 wire op이 ACL 커버리지 밖으로 샘 | `control_message::Body` variant 전수 대조 | — | `acl_check_equivalence.rs:692` `acl_check_never_appears_as_a_control_message_wire_variant` | freeze 이후 additive로 새 op이 붙어도 이 트랩이 계속 작동해야 한다 → §10 |
| B3 | 거부 형태의 차이로 리소스 존재를 유추 | 단일 `PERMISSION_DENIED_MESSAGE` | `architecture.md:89` | `crates/qsh-testkit/tests/acl_uniformity.rs:344` `every_deny_seam_in_the_registry_denies_with_the_uniform_message` | — |
| B4 | 정책 파일이 없거나 파손됐을 때 fail-open | default-deny. 로드 실패는 전면 거부이고 `CONFIG_ERROR`는 운영자에게만 | PRD §9; `architecture.md:87` | `crates/qsh-cli/tests/acl_enforcement.rs:50,125,207` | hot reload가 없어 편집 반영이 재시작까지 지연된다 → §7 h10 |
| B5 | wildcard(`forward.*`)로 `forward.socks`까지 부여됐다고 착각 | 항상-deny action 게이트가 wildcard 매칭보다 먼저 — `forward.*`가 `forward.socks`에도 매칭되지만 그 action은 설계상 항상 deny라 추가로 여는 것이 없다(ADR-0019 결정 6). 실제로 `forward.*`가 여는 것은 `forward.local`(host가 닿는 모든 목적지로의 egress, `-D` egress 포함, ADR-0019 결과 "`forward.local` 부여는 egress 부여")과 `forward.remote`(host 쪽 listener 등록) 둘이다 — `forward.socks`만 게이트에 걸려 아무것도 더하지 않는다 | `architecture.md:85`; ADR-0019 결정 6 | `acl_check_equivalence.rs:273` `row_always_denied_action_overrides_an_explicit_allow_rule` | — |
| B6 | quota 포화를 인가 우회 신호로 이용 | ACL 판정이 quota 예약보다 항상 먼저 | — | `crates/qsh-testkit/tests/quota.rs:457` `saturated_quota_still_answers_permission_denied_to_an_unauthorized_principal_end_to_end` | — |
| B7 | 정책 엔진 자체의 커버리지 구멍 | 무작위 정책×요청을 naive oracle과 대조 | testing.md L2 | `crates/qsh-core/src/acl/policy.rs:765` `decide_agrees_with_naive_coverage_oracle`(proptest) | — |
| B8 | trust store가 비어 있는 상태에서 우발적 허용 | 빈 trust store는 전면 거부. 검증 코어의 1·2번 경로가 모두 실패하면 3번(거부)이라 별도 분기가 필요 없는 구조다 | `protocol.md` §3 | `handshake_matrix.rs:438` `case07_client_trust_store_empty_local_rejected`, `:463` `case08_server_trust_store_empty_remote_rejected` | — |
| B9 | 같은 호스트의 다른 로컬 사용자가 localctl UDS로 데몬의 세션·터널을 조작 | accept 직후 euid 일치 검사(`SO_PEERCRED`/`getpeereid`), 프레임을 하나도 읽기 전 | `crates/qsh-core/src/localctl/daemon.rs:1460,1805`; `crates/qsh-core/src/localctl/mod.rs:13-17` | `daemon.rs:1935` `peer_is_authorized_only_when_the_uid_matches`, `:1950` `same_euid_peer_is_authorized_via_the_real_peer_cred_syscall`, `:2255` `an_unauthorized_peer_is_closed_before_any_frame_is_read_or_answered`(셋 중 판정 자체를 고정하는 것은 `:1935`뿐이다 — `:2255`는 거부 판정을 `Ok(false)`로 주입해 그 뒤의 "프레임을 읽지 않고 닫는다"만 고정한다) | 같은 uid의 프로세스는 이미 device 개인키를 읽을 수 있어 이 게이트가 지키는 것은 uid 경계뿐(§2) |
| B10 | `trust rename`이 ACL 매칭 대상을 조용히 바꿔 인가 결과가 달라진다 | 바꾸는 것이 설계다 — 이름이 곧 principal이고, 그래서 rename이 로컬 trust 조작 중 유일하게 audit을 남긴다. `acl.toml`은 hot reload가 없으므로 새 이름을 겨눈 행은 재시작 전까지 없고 그 창은 default-deny다(fail closed) | ADR-0012 결정 7; `docs/CLI.md` §6.11 | `crates/qsh-cli/tests/trust_lifecycle_live.rs:354` `trust_rename_takes_effect_on_the_next_handshake_without_a_restart`, `:406` `renamed_principal_has_no_acl_row_until_restart`, `:445` `an_established_connection_keeps_its_authority_across_a_rename` | 옛 이름을 부르는 `[[acl]]` 행은 아무 pin도 가리키지 않는 죽은 행으로 남는다 → h10과 같은 뿌리 |
| B11 | `trust add-ca`가 `auth_path`를 옵트인하지 않은 기존 `[[acl]]` 행까지 CA 인증 peer에게 열어 준다 | 행이 `auth_path`를 생략하면 기본값이 `AuthPath::Pin`이고 매칭은 정확 일치라(`crates/qsh-core/src/acl/policy.rs:223`의 `rule.auth_path != auth_path`) CA 인증 요청에는 절대 매칭되지 않는다. 운영자 축은 doctor `acl_ca_auth_path_missing` warn이 받는다 | `crates/qsh-core/src/acl/policy.rs:18-20` 모듈 doc; ADR-0017 결정 2 | `crates/qsh-cli/tests/acl_check_equivalence.rs:318` `row_auth_path_mismatch`(ca 행이 pin 요청에 매칭되지 않음); 운영자 축은 `crates/qsh-core/src/ops/doctor/tests.rs:2013` `doctor_acl_findings_reports_acl_ca_auth_path_missing_when_no_row_sets_ca` | 반대 방향(pin 기본값 행이 CA 요청에 매칭되지 않음)은 같은 한 줄의 대칭이지만 전용 테스트가 없다 → §5 g6 |
| B12 | pairing으로 붙은 새 peer가 우연히 같은 이름을 쓰던 기존 `[[acl]]` 행의 권한을 통째로 물려받는다 | 충돌 판정은 자칭 이름이 아니라 실제로 pin되는 이름 기준이고, 행이 이미 있으면 `qsh serve`가 stderr 고지로 그 사실과 "including any you did not mean for this device"를 함께 알린다(`PAIRING_ACL_ROW_PRESENT`) | ADR-0017 결정 3; `docs/CLI.md` §6.11 | `crates/qsh-cli/tests/trust_pairing_live.rs:214` `pairing_with_an_existing_acl_row_notes_the_row_present_on_the_host`, `:795` `pair_accept_as_collides_on_the_chosen_name_not_the_self_asserted_one`, `:161` `pairing_with_no_acl_toml_notes_the_row_absent_on_the_host` | 고지는 host stderr 전용이라 서비스 유닛으로 띄운 `qsh serve`에서는 아무도 보지 않는 로그 파일로 간다 → §7 h25 |
| B13 | 여섯 명령 중 하나가 원격 peer의 요청 표면으로 샌다 | 여섯 전부 local operation이고 `OP_REGISTRY`에 행이 없어 `Server::dispatch`가 닿는 op 집합 밖이다. `service.*`는 `DENY_SEAMS` 표에도 없다 | `docs/CLI.md` §2.5 | `crates/qsh-core/tests/acl_registry.rs`의 §2.5 "인가 불요" 행 대조(그 목록에 `trust.*`·`identity.export`·`service.install|uninstall|status`가 전부 열거되고, 어느 것도 `OP_REGISTRY` 행을 갖지 않음을 단언); 등록 양방향 대조는 `crates/qsh-core/tests/op_registration_completeness.rs:148` `section_2_4_fence_matches_every_implemented_operation_bidirectionally` | "인가 불요"는 원격 ACL 평가 대상이 아니라는 뜻이지 부작용이 없다는 뜻이 아니다 — B10·D10이 그 예다 |

B8은 B4의 TLS 계층 평행 위협이다. 설치 직후·설정 소실·잘못된 config 경로로 pin도 CA도 없이 뜬 노드가 아무나 받아들이면, ACL이 아무리 옳아도 그 앞에서 이미 졌다. B9는 원격 peer가 아니라 같은 머신의 다른 사용자를 상대로 같은 모양의 게이트를 세운다.

B13이 B2의 로컬판이다. B2는 새 wire op이 ACL 커버리지 밖으로 새는 것을 variant 전수 대조로 막고, B13은 로컬 op이 원격 표면으로 흘러드는 것을 등록 완전성 테스트로 막는다. 두 트랩 사이에 op 하나가 끼는 경로는 없다.

### C — 자원고갈

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| C1 | 스푸핑된 Initial로 서버 상태를 만들게 함 | 주소 미검증 `Incoming`은 부하와 무관하게 무조건 Retry | ADR-0009 결정 1 | `crates/qsh-transport/src/endpoint.rs:1339` `fresh_incoming_is_unvalidated`, `:1372` `retry_forces_a_validated_second_incoming`, `:1412` `retry_on_validated_incoming_errs` | — |
| C2 | handshake 동시성 고갈 | `Semaphore`로 handshake 중 연결 수 상한(기본 64) | ADR-0009 결정 2 | `crates/qsh-testkit/tests/admission.rs:106,194,297,374,493,533,602,681,740` | — |
| C3 | source별 handshake flood | count-min sketch rate limit 2단(미검증·검증) | ADR-0009 결정 3; ADR-0010 결정 2 | `crates/qsh-cli/tests/adversarial_load.rs:1086` `spoofed_initial_flood_leaves_the_listener_rss_and_fd_bounded` — `rate_limited`·`validated_rate_limited` audit 행 수를 각각 단언한다 | — |
| C4 | 단일 principal이 자원을 독점 | 세션·exec·터널·연결·pairing에 걸친 quota 키 | ADR-0010 | `quota.rs` 전반(`:94,137,513,692,876,1027,1152,1192`); pairing 축은 `crates/qsh-testkit/tests/pairing_quota.rs:67,91` | M8 이전에는 이 축이 무상한이었다 — 그 이전 시점을 서술한 문서를 읽을 때 주의 |
| C5 | quota 방어가 정상 트래픽을 죽임 | 기존 세션의 생존을 보장 | — | `quota.rs:170,1243,1350,1547` | — |
| C6 | 자원 반납 누수 | splice 종료·자식 종료 시 permit 반납 | — | `quota.rs:544,584,820` | — |
| C7 | localctl hub 자원 고갈 | `MAX_INFLIGHT_LONG_POLL_PER_HUB`(16) < `MAX_INFLIGHT_PER_CONDUIT`(64) | `crates/qsh-core/src/reverse/listen.rs:605`; `crates/qsh-core/src/localctl/mux.rs:94` | hub-wide 캡은 `listen.rs:2730` `long_poll_cap_is_hub_wide_not_per_conduit`, per-conduit 캡 초과 거부는 `mux.rs:433` `cap_exhausted_on_one_conduit_does_not_affect_another` | — |
| C8 | audit 큐 포화·디스크 만실이 인가로 번짐 | 큐가 포화하면 `record()`가 즉시 에러를 돌려주고, 그 에러가 앞단 인가 결정을 fail-closed로 만든다 | `architecture.md:90` | `crates/qsh-core/src/audit/writer.rs:816,834`; `crates/qsh-core/src/server/mod.rs:6071,6149,6249`; `crates/qsh-core/src/reverse/admit.rs:474` | — |
| C9 | audit 자체가 디스크를 채움 | 회전 + retention 상한 | ADR-0010 | `audit/writer.rs:740,774`; `adversarial_load.rs:1674` | — |
| C10 | 세션 output이 리스너 메모리를 무한 점유 | 세션당 byte 예산 8 MiB + whole-chunk oldest-first eviction. 작은 push는 tail chunk에 coalesce돼 per-entry 오버헤드가 `budget / chunk_max`로 유계다 | ADR-0004 결정·대안 3번째 불릿; `crates/qsh-core/src/broker/ring.rs:13-15` | `ring.rs:639` `overflow_evicts_whole_chunks_and_reports_exact_available_from`, `:669` `large_pushes_are_split_so_eviction_stays_granular`, `:783` `small_pushes_coalesce_so_entry_count_is_bounded` | 8 MiB를 넘긴 output은 gap으로 손실된다 → §7 h15 |
| C11 | `trust add --cert-file`/`trust add-ca --cert-file`가 무제한 크기의 PEM을 받아들여 호출자 자신의 프로세스를 굶긴다 | 네 진입점 모두 `CERT_PEM_MAX`(64 KiB, `crates/qsh-core/src/ops/mod.rs:292`) 상한을 받는다: `trust_add`(`crates/qsh-core/src/ops/trust.rs:60`)와 `trust_add_ca`(`:156`)는 받은 `cert_pem` 문자열 길이를 `check_cert_pem_size`(`:528`)로 거부하고, 파일 경로는 `read_cert_file_arg`(`:585`)가 상한보다 1바이트만 더 `take`해 읽은 뒤 같은 함수로 거부하며, CLI의 stdin(`-`) 경로는 `read_cert_arg`(`crates/qsh-cli/src/main.rs`)가 같은 상한으로 `take`한다 — invite code stdin 경로(`INVITE_CODE_STDIN_MAX`)와 같은 규율이다. 핵심은 크기 검사가 아니라 읽기 자체가 유계라는 것이다: `take`가 없으면 EOF를 보내지 않는 입력(파이프)에서 무기한 대기한다 | `docs/CLI.md` §6.11 | `crates/qsh-core/src/ops/tests.rs:2189` `trust_add_ca_rejects_an_oversized_cert_pem`, `:2212` `read_cert_file_arg_rejects_an_oversized_file`, `:2233` `trust_add_rejects_an_oversized_cert_pem`(`trust_add` 자신의 검사), `:2270` `read_cert_file_arg_never_waits_past_the_cap_for_eof`(FIFO로 EOF 없는 입력을 흘려 `take` 자체가 읽기를 끊는지 고정 — 위 세 테스트는 평범한 파일이라 `take`를 지워도 통과한다); CLI stdin 축은 `crates/qsh-cli/tests/init_trust.rs:687` `trust_add_cert_file_stdin_is_bounded_by_cert_pem_max` | 같은 uid의 로컬 호출자가 자기 프로세스를 굶기는 것이라 경계를 넘지 않는다(§2 "같은 uid의 로컬 호출자" 행) — M10이 코드로 닫았다 |

C10의 coalescing이 없으면 1바이트씩 echo하는 PTY가 entry 하나당 오버헤드를 곱해 예산 밖으로 나간다. 예산은 byte를 세지 entry를 세지 않기 때문이다.

### D — 정보노출

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| D1 | resume token이 로그나 JSON으로 샘 | 토큰은 클라이언트 로컬 custody. wire·JSON 어디에도 노출하지 않는다 | ADR-0007 결정 2 | `crates/qsh-testkit/tests/resume_secrecy.rs:69` `a_resume_credential_never_reaches_a_log_line_or_the_json_contract`, `:211`; `crates/qsh-cli/tests/fixtures.rs:977` `no_fixture_carries_a_resume_token` | — |
| D2 | 시크릿이 `{:?}`로 새어 나감 | `Zeroizing` + 수동 `Debug` 구현 | `architecture.md:76` | `crates/qsh-core/src/resume.rs:709` `secrets_redact_themselves`; `crates/qsh-core/src/broker/resume.rs:481` `the_secret_types_redact_themselves` | rustls로 넘어간 키 사본은 이 규율 밖이다 → §7 h13 |
| D3 | invite raw secret이 디스크에 잔존 | `mac_key`만 저장하고 raw secret은 쓰지 않는다 | `protocol.md` §15.7 | `crates/qsh-core/src/trust/pairing.rs:975` `on_disk_record_never_contains_the_raw_secret` | `mac_key`는 이 invite에 대해 raw secret과 **동등한 verifier**다(`protocol.md` §15.7) — 실제 방어선은 해시가 아니라 0600 하나 |
| D4 | 파일 권한이 넓어짐 | 생성 시점에 0600/0700 강제 | `architecture.md:104-106` | `trust/pairing.rs:838` `saved_store_is_private`(`mode & 0o777 == 0o600` 직접 단언); `crates/qsh-cli/tests/localctl_perms.rs:162` | 생성 이후 다른 프로세스·백업·sync가 넓히는 것은 막지 못한다 → §8 |
| D5 | machine-mode stdout 오염 | 진단·로그·진행 표시는 stderr만 | CLAUDE.md 계약 안정성 규칙; `docs/CLI.md` §6.12 | `crates/qsh-cli/tests/jsonl_purity.rs:54,131,205,298,324,358` | — |
| D6 | 페어링 확인 줄의 시각적 위장 | `validate_device_name`이 제어문자·bidi override/isolate·zero-width를 거부 | `protocol.md` §15.5; `crates/qsh-proto/src/wire.rs:393` | `wire.rs:1875` `validate_device_name_boundary_table`; `crates/qsh-core/src/pairing.rs:479,519` | homoglyph는 의도적 미검사 → §7 h9 |
| D7 | PTY 평문 output이 디스크에 잔존 | replay는 memory-only. disk spool 경로 자체가 없다 | ADR-0004 결정·근거 2번째 불릿·대안 2번째 불릿 | 구조적 부재가 증거다 — `ReplayStore` 구현체가 `ring.rs` 하나뿐이고, 파일을 여는 코드가 그 아래에 없다 | P1에서 ephemeral-key encrypted disk spool을 재검토하면 이 성질이 opt-in으로 뒤집히고 key 관리 표면이 새로 생긴다(ADR-0004 결과 4번째 불릿) |
| D8 | `identity export`가 개인키를 내보낸다 | 구조적으로 불가능하다 — `Ops::identity_export` 본문이 `device.pem`만 읽고 `identity::load(`·`KeyStore`·`KEY_FILE`·`open_store` 어느 것도 참조하지 않는다. 그 부재 자체를 소스 스캔 테스트가 고정한다 | ADR-0013 결정 3 | `crates/qsh-core/src/ops/tests.rs:2416` `identity_export_never_opens_the_key_store`(함수 본문을 중괄호 균형으로 잘라 금지 토큰 넷의 부재를 단언); stdout 축은 `crates/qsh-cli/tests/jsonl_purity.rs:726` `identity_export_json_and_jsonl_confine_the_pem_to_one_field_on_one_line`, `:761` `identity_export_with_out_never_puts_pem_text_on_stdout_in_either_mode`, `:797` `identity_export_human_mode_without_out_prints_exactly_one_certificate_block` | — |
| D9 | `--cert-file`에 개인키를 흘려 넣어 오류 문면이나 감사 기록으로 되비추게 한다 | `CERTIFICATE` 외 라벨 블록은 블록 수 판정보다 먼저 `ForeignBlock`으로 거부되고, 문면은 고정 문자열 넷 중 하나라 입력 바이트가 들어갈 자리가 없다(`details`는 항상 `null`) | ADR-0013 결정 4; `docs/CLI.md` §6.11 | `crates/qsh-cli/tests/init_trust.rs:647` `trust_add_cert_file_rejects_a_bundle_carrying_a_private_key_and_echoes_no_input`(문면에 `BEGIN`·`PRIVATE KEY`가 없음을 단언), `:617` `trust_add_cert_file_rejects_a_chain_of_two_certificates`; core 축은 `crates/qsh-core/src/ops/tests.rs:2033`·`:2013` | 심링크로 `device.key`를 가리켜도 같은 거부에 걸린다 — 읽기 자체는 막지 않지만 바이트가 밖으로 나가는 경로가 없다 |
| D10 | `service install`이 쓴 유닛 파일로 비밀이나 환경이 샌다 | systemd 유닛 템플릿에는 `Environment=` 줄이 아예 없고, launchd plist의 `EnvironmentVariables`는 `HOME`과 하드코딩 `PATH` 둘뿐이라 호출 프로세스의 환경을 상속하지 않는다. 유닛 파일은 manager와 무관하게 항상 0600으로 원자 교체된다 | `docs/CLI.md` §6.18; `docs/deploy/service.md` | `crates/qsh-core/src/ops/service/tests.rs:49` `plist_environment_variables_carry_no_xdg_keys`; 모드 축은 `:277` `install_leaves_an_existing_unit_directory_mode_alone`(유닛 0600과 기존 부모 디렉터리 0755 유지를 같은 테스트가 대조) | 부모 디렉터리가 이미 넓으면 넓은 채로 둔다 — qsh 소유가 아닌 공용 디렉터리라는 것이 그 이유이고 의도된 동작이다 |
| D11 | `identity export --out`이 낸 파일이 world-readable이라 다른 로컬 사용자가 읽는다 | 0600을 강제하지 않는 것이 결정이다 — 산출물이 공개값(leaf 인증서)이라 강제할 필요가 없다 | ADR-0013 결정 3 | 핀 없음(§5 g7) — `identity_export_refuses_to_clobber_an_existing_out_file`(`crates/qsh-core/src/ops/tests.rs:2387`)이 덮어쓰기 거부만 고정하고 모드는 아무도 보지 않는다 | 이 파일만 §1 자산 표의 0600/0700 규율 밖이다. 그 예외가 의도라는 것을 아는 유일한 자리가 ADR-0013 결정 3 문장 하나다 → §5 g7 |
| D12 | `trust add-ca`의 CA 라벨(`<name>`)이 bidi override나 zero-width 문자로 시각적으로 위장된다 | `<name>`은 여전히 먼저 `trim()`되고(공백만으로 이뤄진 이름은 트리밍 뒤 빈 문자열로 걸린다), 그다음 `trust rename`의 `new`와 같은 공유 검증기를 거친다 — 이전에는 `trim()` 후 빈 문자열만 보던 검사가, 이제는 D6과 같은 `qsh_proto::wire::validate_device_name`까지 도는 `validate_peer_label_arg`를 호출한다(`crates/qsh-core/src/ops/trust.rs:155`). 트리밍을 남긴 이유는 공유 검증기 혼자로는 순수 공백을 걸러내지 못하기 때문이다(C11 통제 열과 같은 근거) | ADR-0012 결정 6; `crates/qsh-proto/src/wire.rs:368-369` | `crates/qsh-core/src/ops/tests.rs:2147` `trust_add_ca_rejects_a_bad_name`(공백 전용 `"   "` 행 포함), `:2172` `trust_add_ca_trims_surrounding_whitespace_from_the_name` | homoglyph는 D6과 같은 이유로 의도적 미검사 → §7 h9 |

D7은 테스트로 지킬 수 있는 성질이 아니라 코드가 없어서 성립하는 성질이다. 그러므로 이 행을 깨는 방법은 회귀가 아니라 새 기능이고, 그 시점의 방어선은 ADR 하나다.

D8은 D7과 같은 종류의 행이다. 둘 다 "코드가 없어서 성립하는 성질"이고, 차이는 D7이 그 부재를 단언할 테스트조차 없는 반면 D8은 소스 스캔이라는 값싼 수단으로 그 부재를 실제로 고정했다는 점이다. 새 기능이 이 성질을 뒤집으려 하면 D8은 빨개지고 D7은 조용하다.

### E — 무결성

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| E1 | resume 오프셋 어긋남·입력 중복 적용 | 정확 오프셋 stitch + 입력 exactly-once | `protocol.md` §10 | `resume_loopback.rs:171,282,290,301,384,392,404,478,484` | — |
| E2 | writer lease 탈취 | `session.write`는 `no_steal: true` 고정 | `architecture.md:56` | `resume_loopback.rs:637` `no_steal_conflicts_with_a_foreign_lease_and_spends_no_credential` | 세션 open 직후 lease 공백 창이 있다 — 다른 principal이 먼저 write하면 lease를 가져가고 opener가 `SESSION_CONFLICT`를 맞는, 문서화된 트레이드오프 |
| E3 | ring 오프셋 산술 오류 | gap 정확 보고 | testing.md L2 | `ring.rs:977` `read_matches_naive_vec_oracle`(proptest) | — |
| E4 | reverse 등록 generation 재사용 | 롤백된 generation의 재발행 금지 | — | `crates/qsh-core/src/reverse/registry.rs:1102` `generation_is_never_repeated_across_any_replace_stale_remove_sequence`(proptest) | — |
| E5 | localctl request-id 교차 응답 | mux 오라클 대조 | — | `crates/qsh-core/src/localctl/mux.rs:575` `interleaved_reused_peer_ids_never_cross`(proptest) | — |
| E6 | 재접속 backoff 폭주 | 단조 증가 + cap | — | `crates/qsh-core/src/reverse/target/tests.rs:193` `backoff_sequence_is_monotone_nondecreasing_until_the_cap`(proptest) | — |
| E7 | 터널 재경로 중 바이트 손실 | QUIC path migration을 투명하게 통과 | ADR-0018 결정 1 | `crates/qsh-testkit/tests/tunnel_chaos.rs:149,299,781` | connection 자체가 끊기면 터널은 재생되지 않는다 — v1의 명시적 비대칭 → §7 h11 |
| E8 | overflow로 인한 output 손실을 조용히 숨김 | overflow는 절대 숨기지 않는다. `available_from` 이전을 가리키는 커서는 먼저 `Gap`을 받고 그다음 데이터를 받는다 | ADR-0004 맥락 2번째 문단·근거 1번째 불릿·결과 3번째 불릿 — "`session.gap` event가 buffer overflow의 유일하고 명시적인 신호여야 하며, 이를 숨기는 어떤 fallback도 있어서는 안 된다"; `protocol.md` §10 | `ring.rs:877` `forced_control_loss_is_signalled_by_a_gap_never_hidden`, `:639` | 손실 자체는 §7 h15. 이 행이 지키는 것은 "숨기지 않는다"는 성질이다 |
| E9 | `trust rename`이 쓰다 말아 `trust.toml`이 깨지거나, 감사 기록 없이 이름만 바뀐다 | store 잠금 아래 load → rename → audit → save 순서가 고정이다. audit이 실패하면 `INTERNAL`이고 `trust.toml`은 손대지 않는다 — 기록 없으면 rename도 없다. save는 tmp+`sync_all`+rename 원자 교체이고 임시 파일도 0600이다 | ADR-0012 결정 7 | `crates/qsh-core/src/ops/tests.rs:937` `trust_rename_writes_exactly_one_audit_record`, `:965` `trust_rename_is_refused_when_the_audit_sink_fails`, `:1032` `trust_rename_goes_through_trust_store_lock`, `:786` `trust_rename_preserves_added_at_and_fingerprint`, `:1004` `trust_rename_appends_to_the_default_audit_log_path_when_no_sink_is_injected` | — |
| E10 | `[serve].to`/`[reverse].controller` 값이 유닛 파일 문법을 깨고 argv를 하나 더 만든다 | launchd는 `xml_escape`가, systemd는 `systemd_quote`가 그 한 문자열을 감싼다. 유닛의 argv는 mode마다 고정이라 `--bind`·`--name`·config·verbosity 플래그가 끼어들 자리가 없다 | `docs/CLI.md` §6.18 | `crates/qsh-core/src/ops/service/tests.rs:70` `plist_escapes_xml_significant_characters_in_the_controller`, `:86` `systemd_unit_quotes_a_controller_with_whitespace`, `:112` `unit_arguments_are_fixed` | 바이너리 경로는 `current_exe()`에서 오고 절대 경로면 `canonicalize`하지 않는다 — `brew upgrade`가 Cellar 경로를 갈아치울 때 심링크를 살려 두기 위한 의도된 선택이다 |
| E11 | 설치되는 유닛이 배포 문서의 예시와 어긋난 채 표류한다 | `docs/deploy/service.md`의 유닛 fence 여섯을 렌더러 출력과 바이트 단위로 대조한다 | — | `crates/qsh-core/tests/service_docs.rs:85` `service_md_declares_exactly_six_unit_fences`, `:100` `service_md_launchd_fences_match_the_generated_plists`, `:122` `service_md_systemd_fences_match_the_generated_units`; `UNSUPPORTED` 문면 축은 `:148` `cli_md_quotes_the_service_unsupported_message_verbatim` | — |

E8이 무결성 범주에 있는 이유: 응용이 "끊긴 출력"과 "완전한 출력"을 구별하지 못하는 것이 실질적 무결성 침해이기 때문이다. 손실을 없애는 것보다 손실을 정직하게 알리는 것이 이 프로토콜의 계약이다.

### F — 부인방지·감사

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| F1 | 무단 인가가 흔적을 남기지 않음 | audit 기록 없이는 allow 자체가 성립하지 않는다 | `architecture.md:90` | `server/mod.rs:6071,6149,6249`(session.open/attach/write); `reverse/admit.rs:474` `allowed_registration_fails_closed_when_the_audit_sink_cannot_record_it` | — |
| F2 | 감사 레코드에 payload가 섞임 | 구조적 필드만 — 타입에 payload를 실을 자리가 없다 | `crates/qsh-core/src/audit.rs:100` "Fields are exactly those listed in architecture.md §6" | `audit.rs:102-143` `AuditRecord` 필드 전수: `ts`·`request_id`·`principal`·`action`·`resource`·`decision`·`rule`·`auth_path`·`peer_addr`·`count`. PTY·명령·환경변수를 담을 필드가 존재하지 않는다 | `resource`(`audit.rs:113`)는 사용자 지정 식별자를 담는다(`session_id`, `host:port`). 정확한 서술은 "payload 0"이 아니라 "모양 검사를 통과한 구조적 식별자만"이고, 이는 설계된 동작이다 |
| F3 | 거부 상관관계를 추적할 수 없음 | 개별 거부는 실제 peer_addr를 남기고 `"-"`는 집계 요약에만 쓴다 | — | `quota.rs:334` `quota_rejection_audit_line_carries_the_real_client_peer_addr` | — |
| F4 | 크래시로 audit 라인이 파손됨 | torn-write 절단 복구 + 파일 락 | 구현 주석 — 설계 문서 서술은 §6 r1·r2가 흡수한다 | `audit/writer.rs:925` `repair_partial_write_truncates_a_torn_fragment_back_to_the_last_known_good_offset`, `:1173` `two_sinks_on_one_path_interleave_without_losing_or_corrupting_lines`, `:892`, `:1023` | — |
| F5 | 로컬 신뢰·서비스 조작이 아무 흔적도 남기지 않는다 | `trust rename`과 `service install`/`uninstall`은 기록 없이 성립하지 않는다 — 둘 다 파일을 바꾸기 전에 audit을 쓰고, 기록이 실패하면 변경을 포기한다. `trust.rename` 레코드는 `auth_path: "local"`, `principal`이 옛 이름, `resource`가 새 이름이다 | ADR-0012 결정 7; `docs/CLI.md` §6.11 | `crates/qsh-core/src/ops/tests.rs:965` `trust_rename_is_refused_when_the_audit_sink_fails`, `:937` `trust_rename_writes_exactly_one_audit_record`; service 축은 `crates/qsh-core/src/ops/service/tests.rs:410` `install_is_refused_when_the_audit_sink_fails` | `trust add`·`trust add-ca`·`trust remove`·`pair invite`·`pair accept` 다섯은 audit 대상이 아니다 — pin을 만들거나 지우는 조작이 rename과 달리 기록을 남기지 않는다 → §7 h26 |

F2의 정확도가 이 범주에서 가장 중요하다. "audit에 payload를 남기지 않는다"를 런타임 규율로 지키는 시스템은 언젠가 실수하지만, 담을 필드가 없는 타입은 실수할 자리가 없다.

F5가 F1의 로컬판이면서 비대칭이다. F1은 원격 인가 전부가 기록 없이 성립하지 않게 만들지만, 로컬 쪽에서 그 규율을 받는 것은 rename과 service 둘뿐이다. 그 경계선이 어디인지를 정한 것은 ADR-0012 결정 7이고, 사유는 "이름이 principal이라 rename이 실제로 인가 결과를 바꾸기 때문"이다 — `trust add`는 새 이름을 만들 뿐 기존 행의 매칭 대상을 옮기지 않는다는 판단이 그 아래에 있다.

### G — 가용성

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| G1 | garbage flood로 데몬 사망 | admission 게이트 | ADR-0009 | `admission.rs:374` `host_survives_garbage_initial_flood`, `:194` | — |
| G2 | 종료 시 좀비·고아 프로세스 | SIGTERM drain | ADR-0003; `README.md` "Known limitations" | `crates/qsh-cli/tests/serve_sigterm_drain.rs:157` `sigterm_drains_the_session_and_leaves_no_orphan` | best-effort다. 재시작은 그 프로세스의 모든 detached 세션의 끝 → §7 h12 |
| G3 | 나쁜 UDS 피어 하나가 데몬을 죽임 | bounded close | 구현 — 설계 문서 서술은 §6 r3이 흡수한다 | `localctl_perms.rs:194` `a_garbage_peer_is_refused_with_a_bounded_close_and_the_daemon_keeps_serving` | — |
| G4 | stale socket 때문에 데몬 발견 실패 | 거부되는 소켓은 unlink하고 다음으로 | `architecture.md:109` | `localctl_perms.rs:247` `discovery_unlinks_a_stale_socket_ahead_of_the_real_daemon_and_still_finds_it` | — |
| G5 | `service uninstall`이 qsh가 쓰지 않은 유닛까지 지운다 | 없다 — 계약이 경로이지 출처가 아니다. 파일 안에 마커도 헤더도 없고 `remove_file`은 그 경로에 있는 것을 그대로 지운다. 유닛이 이미 없으면 오류가 아니라 `removed: false`로 성공한다 | `docs/CLI.md` §6.18 | `crates/qsh-core/src/ops/service/tests.rs:341` `uninstall_on_an_absent_unit_is_ok_and_reports_removed_false`(손으로 쓴 파일을 먼저 놓고도 지워짐을 함께 고정) | 같은 경로에 손으로 쓴 유닛이 있으면 install은 덮고 uninstall은 지운다. 손으로 고친 유닛의 복구 경로라는 것이 install 쪽 설계 근거다 → §7 h27 |

## 5. 갭 — 통제는 있고 핀 테스트가 없거나 불확실한 것

M8 Step 7 착수 시점에 다섯 개를 열어 두고 조사했다. 넷은 그때 닫혔고, 남은 g4는 M9 구현(`963809e`)으로 닫혔다 — 다섯 모두 닫힘이었다. M10이 M9 사람용 표면을 훑으면서 둘을 더 열었다.

| # | 통제 | 판정 | 근거 |
|---|---|---|---|
| g1 | `MAX_INFLIGHT_PER_CONDUIT`(64) 초과 시 거부 | **닫힘 — 기존 테스트가 이미 정확히 이 시나리오를 친다.** 새 테스트는 만들지 않았다 | `crates/qsh-core/src/localctl/mux.rs:433` `cap_exhausted_on_one_conduit_does_not_affect_another`가 한 conduit의 in-flight를 `MAX_INFLIGHT_PER_CONDUIT`까지 채운 뒤 `map_outbound`가 `Err(Exhausted)`를 반환함을 확인한다. hub-wide 캡(`listen.rs:2730`)과는 다른 축이다 |
| g2 | `trust remove` 후 기존 연결의 동작(`README.md` "Known limitations") | **닫힘 — 기존 테스트 있음** | `crates/qsh-cli/tests/trust_lifecycle_live.rs:118` `an_established_connection_survives_the_hosts_trust_remove`가 실제 QUIC 연결로 `trust remove` 뒤에도 같은 PTY 세션의 write/read가 계속됨을 확인한다. 이 테스트가 고정하는 것은 통제가 아니라 §7 h5의 한계 자체다 |
| g3 | `session.control`의 `close`가 scope 예외라는 것(`architecture.md:86`) | **닫힘 — 기존 테스트가 양성 방향으로 고정한다** | `crates/qsh-testkit/tests/session_loopback.rs:891` `session_close_is_exempt_from_scope_owned_while_write_and_resize_are_not`가 `scope = "owned"` 규칙 아래에서 `close`는 비-owner에게 허용되고 `write`/`resize`는 거부됨을 같은 테스트에서 대조한다 |
| g4 | doctor `acl_principal_unmatched` / `acl_ca_auth_path_missing` | **닫힘 — M9가 두 code를 구현·테스트·문서화했다** | 두 code 모두 `963809e`에서 착지했다. `acl_principal_unmatched`는 error, `acl_ca_auth_path_missing`은 warn이다(ADR-0017 결정 2). `crates/qsh-core/src/ops/doctor/tests.rs`의 `doctor_acl_findings_reports_acl_principal_unmatched_for_an_unmatched_pin`과 `doctor_acl_findings_reports_acl_ca_auth_path_missing_when_no_row_sets_ca`가 각각 판정을 고정한다. `docs/CLI.md` §6.17 표에 두 code 모두 등재돼 있다 |
| g5 | 0-RTT 금지 다섯 상수의 회귀 탐지 | **닫힘 — M8 Step 7이 유닛을 추가했다** | `crates/qsh-transport/src/endpoint.rs:1242` `tls_configs_disable_0_rtt_and_session_resumption`. 이전에는 `loopback.rs:395-403`이 "0-RTT를 구조적으로 도달 불가하게 만들어 단언할 API 표면이 남지 않았다"고 기록한 상태였고, 다섯 상수 중 하나를 되돌려도 깨지는 테스트가 없었다. 새 유닛은 config 객체를 직접 읽어 그 상태를 끝낸다 |
| g6 | `auth_path`를 생략한 `[[acl]]` 행이 CA 인증 peer에 매칭되지 않는다 | **열림 — 반대 방향만 테스트가 있다.** `crates/qsh-cli/tests/acl_check_equivalence.rs:318` `row_auth_path_mismatch`는 `auth_path = "ca"` 행이 pin 인증 요청에 매칭되지 않음을 real handshake로 고정하지만, 그 거울(생략=Pin 기본값 행이 CA 인증 요청에 매칭되지 않음)은 CA 발급 하네스가 필요해 없다. 근거는 `crates/qsh-core/src/acl/policy.rs:223`의 `rule.auth_path != auth_path` 한 줄의 대칭성뿐이다 | 같은 한 줄이 두 방향을 다 결정하므로 회귀가 한쪽만 깨질 수는 없다는 것이 이 갭을 P1로 두는 근거다. 값싸게 닫으려면 `handshake_matrix.rs`의 CA 케이스(case09~case15)가 이미 만드는 CA 발급 장치를 빌려 ACL 층에 한 케이스를 더하면 된다 |
| g7 | `identity export --out`이 낸 파일의 모드 | **열림 — 아무도 보지 않는다.** `crates/qsh-core/src/ops/tests.rs:2387` `identity_export_refuses_to_clobber_an_existing_out_file`가 덮어쓰기 거부만 고정하고, 모드를 단언하는 테스트는 없다. 0600으로 좁혀도, `create_new`를 `create(true)`로 바꿔 심링크 뒤를 덮게 해도 빨개지는 것이 없다 | 0600 미강제가 ADR-0013 결정 3의 결정("산출물은 공개값(leaf 인증서)이라 파일 권한을 0600으로 강제할 필요는 없다")이라 이 갭이 막는 것은 모드 자체가 아니라 그 결정의 무언 변경이다. 닫는 비용은 낮다 — 같은 테스트에 `create_new` 거동을 심링크로 한 번 더 치는 줄 하나 |

## 6. 문서가 서술하지 않던 통제

테스트가 강제하고 있으나 설계 문서 어디에도 서술이 없던 성질 다섯 개다. §4의 해당 행이 그 서술을 겸하지만, 왜 그런 통제가 있는지는 여기 적는다.

**r1 — audit의 torn-write 복구.** 프로세스가 write 도중에 죽으면 마지막 줄이 잘린 채 남는다. `RotatingAuditSink`는 다음 열기에서 마지막으로 알려진 온전한 offset까지 파일을 잘라내고 거기서부터 이어 쓴다(`audit/writer.rs:593` `repair_partial_write`, 테스트 `:925`). 이것이 없으면 파손 줄 하나가 그 뒤의 모든 audit 파싱을 오염시키고, JSONL을 읽는 도구는 그 지점에서 멈춘다 — 부인방지 자산이 크래시 한 번에 통째로 무효가 되는 셈이다.

**r2 — 하나의 경로에 두 sink가 붙는 것을 전제한다.** `qsh serve`와 `qsh listen`이 같은 계정에서 동시에 뜨면 audit 경로가 겹친다. writer는 append를 파일 락 아래에서 수행하므로(`writer.rs:518,548`) 두 sink가 줄을 섞지도 잃지도 않는다(`:1173`). 설계 문서는 audit sink를 단수로만 서술해 왔고, 그래서 이 전제가 어디에도 적혀 있지 않았다.

**r3 — localctl 데몬은 쓰레기 피어 하나로 죽지 않는다.** UDS accept 뒤 프로토콜을 지키지 않는 피어는 유계 시간 안에 닫히고 데몬은 계속 서빙한다(`localctl_perms.rs:194`). same-uid 경계 안이라 인가 위협은 아니지만 가용성 불변식이고, 명문화된 문장이 없었다.

**r4 — localctl 프로토콜에는 resume token을 담을 필드가 아예 없다.** `resume_secrecy.rs:211` `no_localctl_message_type_or_source_file_ever_names_a_resume_token`이 메시지 타입과 소스 파일 양쪽에서 이를 확인한다. ADR 형태의 근거는 없고 테스트가 설계를 강제하는 형태다 — 토큰 custody를 클라이언트에 두기로 한 ADR-0007 결정 2의 자연스러운 귀결이지만, 그 ADR은 localctl을 언급하지 않는다.

**r5 — 작은 push의 tail-chunk coalescing.** ADR-0004는 byte 예산만 결정했고 `architecture.md:54`도 크기만 적는다. 실제 구현은 작은 push를 tail chunk에 합쳐 per-entry 오버헤드를 `budget / chunk_max`로 묶는다(`ring.rs:13-15`, 테스트 `:783`). 이것이 없으면 1바이트씩 echo하는 PTY 하나가 예산 안에서도 entry 수를 폭발시킨다 — 8 MiB라는 숫자가 실제로 메모리 상한이 되게 만드는 것이 이 방어다.

## 7. 잔여 위험

통제가 없거나 의도적으로 두지 않은 것들이다. 리뷰어가 먼저 볼 목록이 이것이다.

| # | 한계 | 근거 |
|---|---|---|
| h1 | TOFU 미지원. `trust.toml`이 pin의 방향을 구분하지 않아, client 쪽 자동 pin이 같은 상대의 inbound 인증까지 통과시킨다 | ADR-0017 결정 5(방향 축 `direction = "outbound"`는 별도 ADR로 미뤘고 번호도 아직 없다); `ROADMAP.md:119`가 M9 명시적 out으로 적는다 |
| h2 | listener를 상대로 한 pairing이 미정 | ADR-0015 결정 "미정" |
| h3 | CSR 기반 발급이 없어, 여러 장비를 한 CA로 서명하려면 CA 개인키를 그 장비 모두에 복제해야 한다 | ADR-0016 맥락 2번째 문단·결정; ADR-0013 결정 8 뒤 단락 |
| h4 | CA rotation·revocation 설계가 없다. 단일 root, intermediate 없음 | ADR-0008 근거 1번째 불릿·대안 1번째 불릿 |
| h5 | `qsh trust remove`가 기존 연결에 소급되지 않는다. 제거된 peer는 그 연결이 끊길 때까지 협상된 권한 전체를 유지한다 | README "Known limitations". 강제 종료는 P1 |
| h6 | `qsh pair accept`(구 표기 `qsh trust accept`)의 양쪽 pin이 원자적이지 않다. 호스트 쪽 pin과 invite 소비가 먼저 일어나고 클라이언트 로컬 pin이 나중이라, 그 사이 로컬 이름 충돌이 나면 invite는 이미 소비된 채 남는다 | README "Known limitations"; `protocol.md` §15.6 |
| h7 | 이미 pin된 상대의 재페어링이 불가능하다. 새 invite로도 풀리지 않고 복구 경로는 호스트의 `trust remove` 뿐이다 | README "Known limitations"; `protocol.md` §15.6 |
| h8 | 역방향 conduit에 pairing evaluator가 붙어 있지 않다. 사전 pin/CA로만 신뢰를 세우고, 그것이 손상됐을 때의 복구 절차 문서가 없다 | `protocol.md` §15.8; ADR-0015 미정 |
| h9 | homoglyph 미탐지. 서로 다른 코드 포인트가 같은 글리프로 렌더되는 이름을 `validate_device_name`이 잡지 않는다 | `protocol.md` §15.5; `crates/qsh-proto/src/wire.rs:385-392`. 실제 방어선은 fingerprint 병기 대조 |
| h10 | `acl.toml` hot reload 없음. 편집은 다음 `serve`/`listen`/`reverse` 시작부터 적용된다 | `README.md` "Known limitations"; ADR-0017 |
| h11 | 터널에는 replay ring이 없다. connection 손실 시 in-flight TCP 연결은 재생되지 않고 깨끗이 끊긴다 | ADR-0018 결정 1; `README.md` "Known limitations" |
| h12 | 세션이 리스너 프로세스 수명에 결합된다. 재시작은 그 위 모든 detached 세션의 끝이다 | ADR-0003; `README.md` "Known limitations" |
| h13 | rustls 내부로 넘어간 키 사본이 `Zeroizing` 밖에 있다. `LocalIdentity.key_pkcs8_der`까지가 규율의 경계이고, rustls-pki-types 1.15.1에 `impl Drop`이 없다 | M8 Step 6이 명시적으로 수용한 잔여(코드 주석에 기록, 업스트림 이슈는 열지 않았다) |
| h14 | 이미 redeem된 invite도 20분 retention 창 안에서는 TLS 게이트가 계속 열려 있다. 실제 거부는 그다음 단인 redeem 판정에서 난다 | `protocol.md` §15.7. 이 관찰이 뚫는 것은 없다 — redeem 판정 자체가 매번 지켜진다 |
| h15 | 세션 replay는 기본 8 MiB까지다. 그보다 오래 끊겼다가 돌아오면 그 구간은 gap event로 통보될 뿐 복구 수단이 없다. disk spool이 없으므로 늘리는 유일한 방법은 `[serve].replay_bytes`이고, 그건 리스너 메모리를 직접 늘린다 | ADR-0004 결정·근거 1번째 불릿·근거 3번째 불릿·대안 3번째 불릿·결과 4번째 불릿; 기본값 `crates/qsh-core/src/config.rs:539`. h11과는 다른 항목이다 — 이쪽은 세션 output 이력의 **크기 상한** 문제다 |
| h16 | `-D`가 인가하는 것은 `forward.local` 하나뿐이고, 이미 그 principal이 갖고 있던 grant다. `-D`는 그 egress를 SOCKS 클라이언트가 쓰기 쉬운 형태로 옮길 뿐, 새 권한을 만들지 않는다 — 다만 host가 닿는 모든 목적지로 무제한 egress라는 위험 자체는 `-D` 이전부터 있었다 | ADR-0019 결과 R1; Q1 목적지 ACL 문법이 나오면 완화 후보 |
| h17 | `-L`/`-D`가 여는 loopback TCP listener는 같은 머신의 다른 uid도 그냥 connect할 수 있다 — localctl UDS와 달리 파일 권한도 accept 시 euid 검사도 거치지 않는다. `-D`는 목적지가 고정되지 않아 피해 범위가 `-L`보다 넓다(그 principal이 닿는 모든 곳). 정방향·역방향 두 route 모두 같다 — 역방향은 daemon을 거쳐 relay될 뿐 이 listener 자체의 신뢰 경계를 바꾸지 않는다. 처방은 다중 사용자 머신에서 `-D`를 쓰지 않는 것 | ADR-0019 결과 R2; ADR-0020 결과 3번째 불릿("새 신뢰 경계는 없다"); listener별 자격증명(RFC 1929)은 P2 후보. §2의 "같은 호스트의 다른 사용자" 행이 이 예외를 반영한다 |
| h18 | 응용이 `socks5h://`가 아니라 `socks5://`를 쓰면 이름 해석이 client 쪽 로컬 DNS로 새어 나간다 | ADR-0019 결과 R3. client 설정 문제이므로 통제가 아니라 문서 안내(README, `docs/CLI.md` §6.9)로 대응한다 |
| h19 | SOCKS5 REP 분류가 거칠다 — `0x03`/`0x06`은 나오지 않고, `0x04`(`HOST_NOT_FOUND`)와 `0x05`(`CONNECTION_FAILED`)의 구분이 원격 포트 스캔의 단서가 된다 | ADR-0019 결과 R4. `-L`의 `ConnectResult`와 같은 수준의 잔여 위험이다 |
| h20 | `dial-filter.v1`의 host-local 필터는 loopback/link-local/메타데이터 주소만 거른다 — host 자신의 비-loopback 인터페이스 주소와 RFC 1918 사설망 대역, IPv6 metadata 주소(예: `fd00:ec2::254`)는 거르지 않는다. 사내망 접근이 실제 용례이기 때문이다 | ADR-0019 결과 R5 |
| h21 | `acl.toml`의 `allow = ["forward.socks"]`는 `-D`에 아무 효과가 없다 — `-D`는 항상 `forward.local`로만 판정된다(`DYNAMIC_FORWARD_ACL_NOTE`). 운영자가 이 행으로 `-D`를 허용했다고 착각할 수 있다 | ADR-0019 결과 R6. `qsh doctor` 진단은 후속 후보 |
| h22 | `-D`가 splice하는 연결에는 idle timeout이 없다 — 클라이언트도 목적지도 조용한 연결이 끊기지 않고 자원을 계속 쥔다 | ADR-0019 결과 R7. `-L`과 같은 수준의 잔여 위험이다 |
| h23 | `trust add`가 이미 있는 이름을 다른 fingerprint로 부르면 조용한 no-op이다 — 거부도 경고도 없고 JSON은 `created: false, updated: false`로만 다르다. `--cert-file` 경로도 같은 규칙을 그대로 받는다(A12) | 재결합을 막는다는 점에서 통제이지만 그 사실이 호출자에게 전달되지 않는다. `pair accept` 쪽은 같은 상황을 `SESSION_CONFLICT`로 시끄럽게 실패시키므로(ADR-0012 결정 6; `docs/CLI.md` §6.11), 두 경로가 같은 상황에 다르게 답한다. doctor 진단이나 human 한 줄 고지가 후속 후보다 |
| h24 | `trust add-ca`가 등재 대상이 실제 CA 루트인지 검증하지 않는다 — `basicConstraints`의 CA 여부도 자기서명 여부도 보지 않고 구조만 본다. leaf를 잘못 등재하면 그 leaf 키 보유자가 SAN으로 아무 principal이나 자칭할 수 있다 | `docs/CLI.md` §6.11이 그 사실과 "등록하려는 파일이 실제 CA 루트인지는 운영자가 직접 확인해야 한다"를 명시한다(ADR-0013 결정 5). h3(CA 키 복제)·h4(revocation 부재)와 한 묶음으로 읽어야 한다 — 셋 다 "CA를 등재하는 순간 그 키가 곧 발급 권한"이라는 같은 사실의 다른 얼굴이다 |
| h25 | 페어링 직후 고지(`PAIRING_ACL_ROW_PRESENT`/`PAIRING_ACL_ROW_ABSENT`)가 host의 stderr 전용이다 — envelope에도 JSON 어느 줄에도 들어가지 않는다(ADR-0017 결정 3) | `qsh service install`이 만드는 유닛으로 `qsh serve`를 띄우면 그 stderr는 launchd의 `~/Library/Logs/qsh/<mode>.err.log`나 systemd journal로 가고 아무도 그 순간에 읽지 않는다. 사람용 표면이 열린 M9 이후 이 고지가 실제로 사람 눈에 닿는 경우가 foreground 실행뿐이라는 점이 M10에서 새로 두드러진다. 처방 후보는 `qsh doctor`가 같은 판정을 재발행하는 것 |
| h26 | 로컬 신뢰 조작 중 audit을 남기는 것은 `trust rename` 하나뿐이다. `trust add`·`trust add-ca`·`trust remove`·`pair invite`·`pair accept`는 pin을 만들거나 지우면서도 `audit.log`에 아무것도 쓰지 않는다 | ADR-0012 결정 7이 rename을 "그 첫 사례"로 만들면서 나머지를 그대로 둔 결과다. 그 ADR의 판단은 "이름이 principal이라 rename이 실제로 인가 결과를 바꾼다"였는데, `trust add`도 새 principal을 만들고 `trust remove`도 있던 것을 없앤다. 소급 확장은 P1 후보이고, 확장하면 F5 행의 잔여 위험 열이 비워진다 |
| h27 | `service uninstall`이 출처를 보지 않는다 — 추론한 경로에 있는 파일을 누가 썼든 지운다. `install`도 같은 경로를 무조건 덮어쓴다 | 손으로 고친 유닛을 복구하는 경로라는 것이 `install` 쪽 설계 근거이고(`docs/CLI.md` §6.18의 `created: false` 서술), `uninstall`은 "계약이 경로이지 출처가 아니다"를 코드 주석이 명시한다. 같은 라벨의 유닛을 손으로 관리하던 기존 배포(`docs/deploy/service.md`의 `io.qsh.reverse` 선례)가 그대로 사정권에 든다 |

h4와 h5는 함께 읽어야 한다. revocation 메커니즘이 없고 `trust remove`도 소급되지 않으므로, 손상된 peer를 즉시 끊는 수단이 v1에는 없다. 실무적 대응은 그 연결이 끊길 때까지 기다리거나 `qsh serve`를 재시작하는 것이고, 후자는 h12에 따라 모든 세션을 끝낸다.

h16–h22는 ADR-0019의 R1–R7이다(그 ADR 자신이 "잔여 위험은 §7에 행으로 올린다"고 요구한다). h17만 ADR-0020으로 개정됐다 — 역방향 route에도 같은 loopback listener 노출이 적용되지만, ADR-0020 자신이 "새 신뢰 경계는 없다"고 명시하므로 위험의 성격은 그대로다.

h23~h27은 M10이 M9 사람용 표면을 훑으면서 처음 적은 것이다. 원래 후보 일곱 중 cert PEM 크기 상한과 `trust add-ca` 이름 미검증 둘은 잔여로 남기지 않고 이 브랜치의 별도 코드 변경으로 닫아 §4 C11·D12 행으로 올렸다(`trust_add_ca_rejects_an_oversized_cert_pem`, `read_cert_file_arg_rejects_an_oversized_file`, `trust_add_ca_rejects_a_bad_name`) — 남은 다섯이 h23부터 다시 번호를 받았다. h24·h25·h26은 ADR-0013 결정 5·ADR-0017 결정 3·ADR-0012 결정 7이 각각 이미 수용한 잔여이고, h23과 h27이 이 표에 처음 오른다.

## 8. 운영 가정

qsh가 지키지 않고 운영자에게 맡긴 것들이다.

- **시계 동기.** cert 유효기간(`protocol.md` §3), invite TTL 10분과 retention 20분(`protocol.md` §15.5), resume TTL이 전부 로컬 시계에 의존한다. NTP를 요구하는 명시적 문장은 어느 문서에도 없다. A5가 지적하듯 장기 device cert에서 유효기간은 유일한 revocation 레버이므로, 시계가 크게 어긋난 호스트는 만료된 cert를 받아들일 수 있다.
- **파일 권한 유지.** 생성 시점의 0600/0700은 qsh가 강제하지만(D4), 그 이후 다른 프로세스·백업·잘못 설정된 sync가 넓히는 것은 막지 못한다. `invites.toml`이 특히 민감하다 — `mac_key`가 raw secret과 동등한 verifier라서(D3), 이 파일이 새면 TTL이 남은 invite는 그것만으로 완결된다(`protocol.md` §15.7).
- **네트워크 도달성.** 역방향 모드는 target에서 controller로 가는 직접 UDP 경로를 요구한다. relay·NAT traversal·discovery를 qsh는 제공하지 않는다(`README.md` "Known limitations"; PRD §12).
- **CA 키 복제 관행.** h3이 닫힐 때까지 여러 장비 서명은 `ca.key` 복제로만 가능하다. 그 사본 하나하나가 발급 권한 그 자체다(ADR-0016 맥락 2번째 문단).
- **`acl.toml` 재시작 규율.** h10에 따라 정책 편집은 재시작해야 반영된다. 편집했는데 반영이 안 된 상태를 "정책이 느슨한 채로 돌고 있는 창"으로 인식해야 한다.
- **replay 여유 조정.** `[serve].replay_bytes` 기본 8 MiB가 자기 워크로드에 충분한지는 운영자가 판단한다. ADR-0004 근거 3번째 불릿이 "전형적 텍스트 터미널 output 기준 수십 초~수 분 분량"이라고 추정한 값이다.

## 9. 명시적 비목표

- **relay·NAT traversal.** 제품 경계 밖이다(`README.md` "Known limitations"; PRD §14).
- **user switching.** child는 항상 `qsh serve`를 실행한 OS 계정으로 spawn하고, `SessionOpen`의 `user` hint가 다르면 spawn 없이 `UNSUPPORTED`다(`architecture.md:69`). qsh는 OS 사용자 경계를 대신하지 않는다.
- **세션 안 활동의 통제.** ACL은 요청 종류를 판정하고, 그 뒤 셸에서 벌어지는 일은 OS의 소관이다.
- **PTY 내용의 감사.** F2가 구조적으로 보장하는 비목표다 — 감사 레코드에 payload를 담을 필드가 없다.
- **homoglyph 판정.** 표 기반 confusable 검사를 커스텀 crate 없이 정확히 구현하기 어렵고, 이 자리에서 실제 방어선 노릇을 하는 것은 fingerprint 병기다(`protocol.md` §15.5).
- **TOFU.** h1의 방향 축이 먼저 정리되기 전에는 채택하지 않는다(ADR-0017 대안 절의 TOFU 항목).
- **web PKI.** root를 어떤 경로로도 로드하지 않는다(`protocol.md` §3).

## 10. 유지 규율

- **새 wire op이 들어오면 §4에 행이 하나 는다.** freeze 이후에도 additive 변경으로 새 message·새 capability가 붙을 수 있고(`protocol.md` §16.4), 그때 ACL 커버리지를 지키는 것은 B2의 variant 전수 대조다. 그 트랩이 빨개지면 여기 표에도 행이 빠져 있다는 뜻이다.
- **새 통제가 들어오면 근거와 핀 테스트를 같은 커밋에서 채운다.** 근거 열이 빈 행은 리뷰어에게 "왜 이걸 믿어야 하는가"를 답하지 못한다.
- **핀 테스트 인덱스는 이 문서가 canonical이다.** testing.md는 계층별로 무엇을 갚아야 하는지를, 이 문서는 위협별로 무엇이 그것을 갚고 있는지를 적는다. 테스트 이름이 바뀌면 여기도 바뀐다.
- **갭이 닫히면 §5의 행을 지우지 말고 판정을 적는다.** 어느 시점에 무엇으로 닫혔는지가 다음 리뷰의 입력이다.
- **`파일:줄` 인용은 리팩터에 밀린다.** 절 이름·테스트 이름을 함께 적어 두는 것이 그 대비이고, 줄만 적힌 인용은 다음 라운드에서 재확인 대상이다.
- 같은 커밋에서 편집한 파일을 인용할 때는 편집 후 트리에서 다시 grep한다 — 인용은 편집 전 줄 번호를 기억하지 않는다.
