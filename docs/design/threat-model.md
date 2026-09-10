# QSH 위협 모델

관련 문서: [PRD](../PRD.md) · [CLI 계약](../CLI.md) · [wire protocol](protocol.md) · [아키텍처](architecture.md) · [테스트 전략](testing.md) · [ADR](../adr/) · [fuzz 캠페인](../campaigns/m8-fuzz.md)

## 0. 지위와 범위

이 문서는 M8 Step 7이 wire freeze 문면([protocol.md](protocol.md) §16)과 함께 내는 산출물이고, `docs/PRD.md:311`이 요구하는 "공개 beta 전 protocol과 key lifecycle의 독립 보안 review"(SC7)에 넘길 리뷰어 입력이다. 기준 트리는 M8 Step 7 시점이며, 인용한 `파일:줄`은 그 트리에서 확인한 값이다.

**이 문서가 canonical인 것은 §4의 위협 → 통제 → 근거 → 핀 테스트 대응표 하나다.** 통제 자체의 설계 근거는 여전히 ADR과 protocol.md·architecture.md에 있고, 어느 테스트가 어느 계층을 갚는지는 testing.md에 있다. 그 셋을 가로질러 "이 위협을 무엇이 막고, 그것이 깨지면 무슨 테스트가 빨개지는가"를 한 곳에 모은 표가 여기 말고는 없다.

범위:

- `qsh.wire.v1` 프로토콜 표면 전체 — 프레이밍, control message, 스트림 배치, resume, 역방향 등록, 터널.
- TLS 신뢰 수립(pin·private CA·pairing 세 경로)과 principal 도출.
- ACL 판정과 audit 기록.
- admission·quota 자원 상한.
- 로컬 상태 파일(identity, trust, invites, resume, audit)과 그 권한.
- localctl UDS(`qsh.local.v1`) — freeze 대상은 아니지만(protocol.md §16.3) 진입점으로는 이 문서 안에 있다.

비범위:

- OS 커널·하이퍼바이저·컨테이너 격리, 물리 접근, 콜드부트류 메모리 추출.
- 사용자가 세션 안에서 실행하는 프로그램. qsh는 셸을 내주는 도구이고, 인가된 peer가 그 셸로 무엇을 하는지는 ACL의 관심사가 아니다(PRD §9의 action 어휘가 정하는 것은 "어떤 종류의 요청을 받는가"까지다).
- 공급망(의존성 취약점·yanked crate)은 `cargo deny check`가 별도 게이트로 본다 — 이 문서는 그 게이트의 존재만 기록하고 위협 표에 행을 두지 않는다.
- 릴리스 아티팩트 서명·notarization은 M10 소관이다(`docs/ROADMAP.md:135`).
- M9가 신설할 사람용 표면 명령(`pair`, `service`, `trust rename` 등, `ROADMAP.md:118`)은 아직 코드가 없으므로 위협 표의 대상이 아니다. 그중 이 문서가 지금 인지해야 하는 것은 §5 g4 하나다.

## 1. 자산

| 자산 | 위치 | 근거 |
|---|---|---|
| device 개인키 | `identity/device.key`(0600, PKCS#8 PEM) 또는 OS keyring | `architecture.md:75-76`; `crates/qsh-core/src/identity/mod.rs:8-9` |
| CA 루트 개인키 | `config_dir/ca/ca.key`(0600, 파일 전용) | `docs/adr/0008-private-ca-cert-issuance.md:24` |
| `trust.toml` | pinned peer(이름+fingerprint)와 private CA 목록 | `architecture.md:77,102` |
| `invites.toml` | 0600. `mac_key`(invite secret의 BLAKE3)와 생성 시각 | `protocol.md:425` |
| `acl.toml` | 정책. qsh는 이 파일을 절대 쓰지 않는다 | `architecture.md:103`; `docs/adr/0017-acl-toml-not-written.md:18` |
| resume token | `resume.json`(0600, flock + tmp·rename 원자 교체), 메모리에서는 `Zeroizing<[u8;32]>` | `architecture.md:105`; `docs/adr/0007-session-ref-and-resume-token-custody.md:16` |
| 세션 PTY와 child 프로세스 | broker `SessionActor`가 소유. child는 항상 `qsh serve`를 실행한 OS 계정 | `architecture.md:46,69` |
| audit 로그 | `$XDG_STATE_HOME/qsh/audit.log`, JSONL, fail-closed | `architecture.md:90,105` |
| localctl UDS | `$XDG_RUNTIME_DIR/qsh/<pid>.sock`, 디렉터리 0700, 소켓 파일 0600 | `architecture.md:106`; `crates/qsh-core/src/localctl/daemon.rs:144` |
| ReplayRing(세션 output 이력) | 세션당 기본 8 MiB byte 예산의 메모리 chunk ring, `ReplayStore` trait 뒤 | `docs/adr/0004-replay-buffer-memory-only.md:14`; `crates/qsh-core/src/broker/ring.rs:13-15`; 기본값 `crates/qsh-core/src/config.rs:539` |

ReplayRing은 자산이면서 그 자체가 통제다. PTY 평문 output이 프로세스 메모리에만 남고 디스크에는 어떤 경로로도 남지 않는다는 것이 ADR-0004의 보안적 요점이고(`:19` "PTY 내용이 디스크에 남는 것 자체가 새로운 공격 표면", `:26` 평문 disk spool은 "논의 대상조차 아니다"), 그 대가가 §7 h15의 8 MiB 상한이다.

## 2. 주체와 신뢰 경계

| 주체 | 권한 | 경계를 세우는 것 |
|---|---|---|
| pin된 원격 peer(`AuthPath::Pin`) | 자기 principal에 걸린 `acl.toml` 행이 허용하는 action | SPKI SHA-256 pin 일치(`protocol.md:33`) |
| CA 발급 peer(`AuthPath::Ca`) | 같음. principal은 leaf의 SAN URI에서만 온다 | private CA 체인 검증(`protocol.md:34`), `auth_path` 키로 정책 행 분리(`architecture.md:84`) |
| 페어링 중인 미지 peer(`Principal::Pairing`) | 없음 — `Hello`에도 dispatch에도 ACL에도 닿지 못한다 | `pairing_open()`이 참인 창(살아 있는 invite ≤ 20분) 안에서만 TLS를 통과하고(`protocol.md:360`), 그 뒤로는 §15.2의 우회 경로만 탄다(`protocol.md:364`) |
| 그 외 미지 peer | 없음 | 검증 코어의 3번 경로: 무조건 거부(`protocol.md:35`) |
| 같은 uid의 로컬 호출자(localctl) | 데몬이 들고 있는 것을 조회·조작 | same-uid peer credential. **인가 계층이 아니다** — 그 프로세스는 이미 device 개인키를 읽을 수 있는 uid다 |
| 같은 호스트의 다른 사용자 | 없음 | 파일 권한(0600/0700) + accept 시 euid 검사 |
| 네트워크 관찰자·능동 공격자 | 없음 | QUIC/TLS 1.3 양방향 인증(`protocol.md:39`), 0-RTT 전면 금지(`protocol.md:26`) |
| 에이전트(`--json` 호출자) | 그 CLI를 실행한 사용자와 같다 | 별도 경계가 아니다 — `Ops` 파사드를 통과할 뿐이고, JSON 모드는 권한이 아니라 출력 형식이다 |

경계는 셋이다. (1) 네트워크 ↔ `qsh serve` 프로세스: TLS 검증 코어가 유일한 통과점이고, 검증된 principal 없이는 어떤 스트림도 application 계층에 닿지 않는다. (2) principal ↔ 리소스: `Server::dispatch`(`crates/qsh-core/src/server/mod.rs:782`)가 단일 choke point이고 네 인가 지점이 그 아래에 있다(`server/mod.rs:906,931,1018`, `crates/qsh-core/src/reverse/admit.rs:78`). (3) 로컬 파일 시스템 ↔ 프로세스: 권한 비트 하나가 전부다.

## 3. 진입점

| 진입점 | 신뢰 수준 | 비고 |
|---|---|---|
| `qsh serve` accept loop | 미인증 UDP | 노출 포트는 하나뿐이다 — 기본 `[::]:4433`(`crates/qsh-core/src/serve.rs:21`, `docs/adr/0014-address-default-port.md:8`). ADR-0014는 아직 `상태: 제안됨`(`:4`)이고 peer 주소 쪽 정규화는 M9 소관이라, 여기 적는 사실은 "포트 하나, 기본 4433"까지다 |
| `qsh listen` / `qsh reverse` accept | 미인증 UDP | **pairing evaluator를 attach하지 않는다** — 역방향 conduit은 사전 pin/CA로만 신뢰를 세운다(`protocol.md:433`) |
| localctl UDS | same-uid 로컬 | `<pid>.sock`, 디렉터리 0700, 소켓 파일 0600(`crates/qsh-core/src/localctl/daemon.rs:144`) |
| CLI 전체 | 로컬 사용자 | 모든 명령이 `Ops`를 통과한다 |
| `config.toml` / `trust.toml` / `acl.toml` / `hosts.toml` | 로컬 파일 | 파싱 실패는 fail-closed(`architecture.md:87`) |
| invite code 입력 | 사람이 옮긴 문자열 | 20바이트 CSPRNG → Crockford Base32, `crates/qsh-proto/src/pairing.rs` |
| cert 파일 교환 | 로컬 파일 | ADR-0013 |
| `Server::dispatch` | 인증된 peer | `server/mod.rs:782` — 디코딩된 모든 요청의 단일 통과점 |

`.proto` 디코더와 로컬 입력 파서가 이 진입점들의 첫 코드다. 그 표면 전체가 freeze 대상이자 fuzz 대상이며(`protocol.md` §16.9, ADR-0001:36), 파서 타깃 16개와 stateful 타깃 `broker_ops`의 상태는 [m8-fuzz.md](../campaigns/m8-fuzz.md)가 기록한다.

## 4. 위협 표

STRIDE를 이 저장소의 증거 구조에 맞춰 일곱 범주로 쓴다: A 스푸핑 / B 무단접근 / C 자원고갈 / D 정보노출 / E 무결성 / F 부인방지 / G 가용성. "핀 테스트" 열은 그 통제가 깨지면 빨개지는 테스트다.

### A — 스푸핑·신원

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| A1 | 피어 신원 위장(pin 경로) | SPKI SHA-256 pin 양방향 검증 | `protocol.md:31-35` | `crates/qsh-transport/tests/handshake_matrix.rs:309` case02, `:341` case03. 양성 기준선은 `:273` `case01_pin_pin_both_valid_ok` | — |
| A2 | 피어 신원 위장(CA 경로) | private CA 체인 검증, SAN URI 없는 leaf는 거부 | ADR-0008 | `handshake_matrix.rs:519` case10, `:543` case11, `:628` case14. 양성 대조군 `:483` `case09_ca_mode_both_ways_ok` | CA revocation 메커니즘 자체가 없다 → §7 h4 |
| A3 | pin/CA 모드 혼동 | 신뢰 저장소 종류별로 검증 경로 분리 | ADR-0008 결정 6 | `handshake_matrix.rs:573` case12, `:605` case13. 혼합 구성이 정상 동작함을 고정하는 양성 대조군 `:653` `case15_mixed_pin_client_ca_server_ok` | — |
| A4 | 인증서 미제시 | 상호 인증 필수(`client_auth_mandatory`) | `protocol.md:39` | `handshake_matrix.rs:733` case16 | — |
| A5 | 만료·미도래 인증서 | leaf `not_before`/`not_after`를 두 경로 모두에서 검사 | `protocol.md:37` | `handshake_matrix.rs:363` case04, `:390` case05, `:411` case06 | 로컬 시계에 의존한다 → §8. 장기 device cert에서 유효기간은 유일한 revocation 레버다 |
| A6 | ALPN 위장으로 application 상태에 진입 | `no_application_protocol` alert로 principal 생성 전에 종료 | `protocol.md` §4 | `handshake_matrix.rs:938` case18, `:1015` 대조군 | 서버측 거울 케이스는 의도적으로 쓰지 않았다 |
| A7 | pairing이 pin/CA를 다운그레이드 | pairing 경로는 pin·CA가 **둘 다** 실패한 뒤에만 평가된다 | `protocol.md:360` | `handshake_matrix.rs:803` case17, `:840` case17b | 이미 pin된 상대의 재페어링은 아예 불가 → §7 h7 |
| A8 | resume token 탈취 후 다른 장비에서 attach | 토큰이 opener peer의 SPKI에 결합된다 | ADR-0007:16 | `crates/qsh-testkit/tests/resume_loopback.rs:500` `a_stolen_credential_is_useless_to_a_different_peer`, `:561` | — |
| A9 | 0-RTT early data replay로 부수효과 있는 control message 재전송 | 0-RTT 전면 금지 + 세션 티켓 미발급. client `enable_early_data = false` / `Resumption::disabled()`, server `max_early_data_size = 0` / `send_tls13_tickets = 0` / `NoServerSessionStorage` — 모든 연결이 full mutual auth를 다시 돈다 | `protocol.md:16,26`; `crates/qsh-transport/src/endpoint.rs:511-512`(client), `:527-529`(server) | `endpoint.rs:1242` `tls_configs_disable_0_rtt_and_session_resumption` — 실제 `ClientConfig`/`ServerConfig`에서 세 필드를 직접 읽고 resumption·session storage는 `Debug` 문자열로 단언한다. 간접 증거는 `crates/qsh-transport/tests/loopback.rs:391` | — (M8 Step 7 이전에는 다섯 상수 중 하나를 되돌려도 깨지는 테스트가 없었다 → §5 g5) |

`exec`, `session.write`, tunnel open은 전부 부수효과가 있다. A9가 다른 행과 성격이 다른 이유가 그것이다 — 재전송이 곧 재실행이므로, replay 가능성을 남기는 대신 성능을 포기했다.

### B — 무단접근·인가

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| B1 | 호출자별 판정이 갈려 ACL이 우회됨 | 판정 함수 하나(`Authorizer::check`)를 모든 지점이 공유 | `architecture.md:88` | `crates/qsh-cli/tests/acl_check_equivalence.rs:116,177,220,273,314,434,502,547,596` 아홉 행 | — |
| B2 | 새 wire op이 ACL 커버리지 밖으로 샘 | `control_message::Body` variant 전수 대조 | — | `acl_check_equivalence.rs:692` `acl_check_never_appears_as_a_control_message_wire_variant` | freeze 이후 additive로 새 op이 붙어도 이 트랩이 계속 작동해야 한다 → §10 |
| B3 | 거부 형태의 차이로 리소스 존재를 유추 | 단일 `PERMISSION_DENIED_MESSAGE` | `architecture.md:89` | `crates/qsh-testkit/tests/acl_uniformity.rs:344` `every_deny_seam_in_the_registry_denies_with_the_uniform_message` | — |
| B4 | 정책 파일이 없거나 파손됐을 때 fail-open | default-deny. 로드 실패는 전면 거부이고 `CONFIG_ERROR`는 운영자에게만 | PRD §9; `architecture.md:87` | `crates/qsh-cli/tests/acl_enforcement.rs:50,125,207` | hot reload가 없어 편집 반영이 재시작까지 지연된다 → §7 h10 |
| B5 | wildcard(`forward.*`)로 미구현 기능까지 삼킴 | 항상-deny action 게이트가 wildcard 매칭보다 먼저 | `architecture.md:83` | `acl_check_equivalence.rs:273` `row_always_denied_action_overrides_an_explicit_allow_rule` | — |
| B6 | quota 포화를 인가 우회 신호로 이용 | ACL 판정이 quota 예약보다 항상 먼저 | — | `crates/qsh-testkit/tests/quota.rs:457` `saturated_quota_still_answers_permission_denied_to_an_unauthorized_principal_end_to_end` | — |
| B7 | 정책 엔진 자체의 커버리지 구멍 | 무작위 정책×요청을 naive oracle과 대조 | testing.md L2 | `crates/qsh-core/src/acl/policy.rs:765` `decide_agrees_with_naive_coverage_oracle`(proptest) | — |
| B8 | trust store가 비어 있는 상태에서 우발적 허용 | 빈 trust store는 전면 거부. 검증 코어의 1·2번 경로가 모두 실패하면 3번(거부)이라 별도 분기가 필요 없는 구조다 | `protocol.md:31-35` | `handshake_matrix.rs:438` `case07_client_trust_store_empty_local_rejected`, `:463` `case08_server_trust_store_empty_remote_rejected` | — |
| B9 | 같은 호스트의 다른 로컬 사용자가 localctl UDS로 데몬의 세션·터널을 조작 | accept 직후 euid 일치 검사(`SO_PEERCRED`/`getpeereid`), 프레임을 하나도 읽기 전 | `crates/qsh-core/src/localctl/daemon.rs:1460,1805`; `crates/qsh-core/src/localctl/mod.rs:13-17` | `daemon.rs:1935` `peer_is_authorized_only_when_the_uid_matches`, `:1950` `same_euid_peer_is_authorized_via_the_real_peer_cred_syscall`, `:2255` `an_unauthorized_peer_is_closed_before_any_frame_is_read_or_answered`(셋 중 판정 자체를 고정하는 것은 `:1935`뿐이다 — `:2255`는 거부 판정을 `Ok(false)`로 주입해 그 뒤의 "프레임을 읽지 않고 닫는다"만 고정한다) | 같은 uid의 프로세스는 이미 device 개인키를 읽을 수 있어 이 게이트가 지키는 것은 uid 경계뿐(§2) |

B8은 B4의 TLS 계층 평행 위협이다. 설치 직후·설정 소실·잘못된 config 경로로 pin도 CA도 없이 뜬 노드가 아무나 받아들이면, ACL이 아무리 옳아도 그 앞에서 이미 졌다. B9는 원격 peer가 아니라 같은 머신의 다른 사용자를 상대로 같은 모양의 게이트를 세운다.

### C — 자원고갈

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| C1 | 스푸핑된 Initial로 서버 상태를 만들게 함 | 주소 미검증 `Incoming`은 부하와 무관하게 무조건 Retry | ADR-0009:16-18 | `crates/qsh-transport/src/endpoint.rs:1339` `fresh_incoming_is_unvalidated`, `:1372` `retry_forces_a_validated_second_incoming`, `:1412` `retry_on_validated_incoming_errs` | — |
| C2 | handshake 동시성 고갈 | `Semaphore`로 handshake 중 연결 수 상한(기본 64) | ADR-0009:20-22 | `crates/qsh-testkit/tests/admission.rs:106,194,297,374,493,533,602,681,740` | — |
| C3 | source별 handshake flood | count-min sketch rate limit 2단(미검증·검증) | ADR-0009:24; ADR-0010:69 | `crates/qsh-cli/tests/adversarial_load.rs:1086` `spoofed_initial_flood_leaves_the_listener_rss_and_fd_bounded` — `rate_limited`·`validated_rate_limited` audit 행 수를 각각 단언한다 | — |
| C4 | 단일 principal이 자원을 독점 | 세션·exec·터널·연결·pairing에 걸친 quota 키 | ADR-0010 | `quota.rs` 전반(`:94,137,513,692,876,1027,1152,1192`); pairing 축은 `crates/qsh-testkit/tests/pairing_quota.rs:67,91` | M8 이전에는 이 축이 무상한이었다 — 그 이전 시점을 서술한 문서를 읽을 때 주의 |
| C5 | quota 방어가 정상 트래픽을 죽임 | 기존 세션의 생존을 보장 | — | `quota.rs:170,1243,1350,1547` | — |
| C6 | 자원 반납 누수 | splice 종료·자식 종료 시 permit 반납 | — | `quota.rs:544,584,820` | — |
| C7 | localctl hub 자원 고갈 | `MAX_INFLIGHT_LONG_POLL_PER_HUB`(16) < `MAX_INFLIGHT_PER_CONDUIT`(64) | `crates/qsh-core/src/reverse/listen.rs:605`; `crates/qsh-core/src/localctl/mux.rs:94` | hub-wide 캡은 `listen.rs:2730` `long_poll_cap_is_hub_wide_not_per_conduit`, per-conduit 캡 초과 거부는 `mux.rs:433` `cap_exhausted_on_one_conduit_does_not_affect_another` | — |
| C8 | audit 큐 포화·디스크 만실이 인가로 번짐 | 큐가 포화하면 `record()`가 즉시 에러를 돌려주고, 그 에러가 앞단 인가 결정을 fail-closed로 만든다 | `architecture.md:90` | `crates/qsh-core/src/audit/writer.rs:816,834`; `crates/qsh-core/src/server/mod.rs:6071,6149,6249`; `crates/qsh-core/src/reverse/admit.rs:474` | — |
| C9 | audit 자체가 디스크를 채움 | 회전 + retention 상한 | ADR-0010 | `audit/writer.rs:740,774`; `adversarial_load.rs:1674` | — |
| C10 | 세션 output이 리스너 메모리를 무한 점유 | 세션당 byte 예산 8 MiB + whole-chunk oldest-first eviction. 작은 push는 tail chunk에 coalesce돼 per-entry 오버헤드가 `budget / chunk_max`로 유계다 | ADR-0004:14,27; `crates/qsh-core/src/broker/ring.rs:13-15` | `ring.rs:639` `overflow_evicts_whole_chunks_and_reports_exact_available_from`, `:669` `large_pushes_are_split_so_eviction_stays_granular`, `:783` `small_pushes_coalesce_so_entry_count_is_bounded` | 8 MiB를 넘긴 output은 gap으로 손실된다 → §7 h15 |

C10의 coalescing이 없으면 1바이트씩 echo하는 PTY가 entry 하나당 오버헤드를 곱해 예산 밖으로 나간다. 예산은 byte를 세지 entry를 세지 않기 때문이다.

### D — 정보노출

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| D1 | resume token이 로그나 JSON으로 샘 | 토큰은 클라이언트 로컬 custody. wire·JSON 어디에도 노출하지 않는다 | ADR-0007:16 | `crates/qsh-testkit/tests/resume_secrecy.rs:69` `a_resume_credential_never_reaches_a_log_line_or_the_json_contract`, `:211`; `crates/qsh-cli/tests/fixtures.rs:977` `no_fixture_carries_a_resume_token` | — |
| D2 | 시크릿이 `{:?}`로 새어 나감 | `Zeroizing` + 수동 `Debug` 구현 | `architecture.md:76` | `crates/qsh-core/src/resume.rs:709` `secrets_redact_themselves`; `crates/qsh-core/src/broker/resume.rs:481` `the_secret_types_redact_themselves` | rustls로 넘어간 키 사본은 이 규율 밖이다 → §7 h13 |
| D3 | invite raw secret이 디스크에 잔존 | `mac_key`만 저장하고 raw secret은 쓰지 않는다 | `protocol.md:425` | `crates/qsh-core/src/trust/pairing.rs:975` `on_disk_record_never_contains_the_raw_secret` | `mac_key`는 이 invite에 대해 raw secret과 **동등한 verifier**다(`protocol.md:427`) — 실제 방어선은 해시가 아니라 0600 하나 |
| D4 | 파일 권한이 넓어짐 | 생성 시점에 0600/0700 강제 | `architecture.md:104-106` | `trust/pairing.rs:838` `saved_store_is_private`(`mode & 0o777 == 0o600` 직접 단언); `crates/qsh-cli/tests/localctl_perms.rs:162` | 생성 이후 다른 프로세스·백업·sync가 넓히는 것은 막지 못한다 → §8 |
| D5 | machine-mode stdout 오염 | 진단·로그·진행 표시는 stderr만 | CLAUDE.md 계약 안정성 규칙; `docs/CLI.md` §6.12 | `crates/qsh-cli/tests/jsonl_purity.rs:54,131,205,298,324,358` | — |
| D6 | 페어링 확인 줄의 시각적 위장 | `validate_device_name`이 제어문자·bidi override/isolate·zero-width를 거부 | `protocol.md` §15.5; `crates/qsh-proto/src/wire.rs:393` | `wire.rs:1875` `validate_device_name_boundary_table`; `crates/qsh-core/src/pairing.rs:479,519` | homoglyph는 의도적 미검사 → §7 h9 |
| D7 | PTY 평문 output이 디스크에 잔존 | replay는 memory-only. disk spool 경로 자체가 없다 | ADR-0004:14,19,26 | 구조적 부재가 증거다 — `ReplayStore` 구현체가 `ring.rs` 하나뿐이고, 파일을 여는 코드가 그 아래에 없다 | P1에서 ephemeral-key encrypted disk spool을 재검토하면 이 성질이 opt-in으로 뒤집히고 key 관리 표면이 새로 생긴다(ADR-0004:34) |

D7은 테스트로 지킬 수 있는 성질이 아니라 코드가 없어서 성립하는 성질이다. 그러므로 이 행을 깨는 방법은 회귀가 아니라 새 기능이고, 그 시점의 방어선은 ADR 하나다.

### E — 무결성

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| E1 | resume 오프셋 어긋남·입력 중복 적용 | 정확 오프셋 stitch + 입력 exactly-once | `protocol.md:286-290` | `resume_loopback.rs:171,282,290,301,384,392,404,478,484` | — |
| E2 | writer lease 탈취 | `session.write`는 `no_steal: true` 고정 | `architecture.md:56` | `resume_loopback.rs:637` `no_steal_conflicts_with_a_foreign_lease_and_spends_no_credential` | 세션 open 직후 lease 공백 창이 있다 — 다른 principal이 먼저 write하면 lease를 가져가고 opener가 `SESSION_CONFLICT`를 맞는, 문서화된 트레이드오프 |
| E3 | ring 오프셋 산술 오류 | gap 정확 보고 | testing.md L2 | `ring.rs:977` `read_matches_naive_vec_oracle`(proptest) | — |
| E4 | reverse 등록 generation 재사용 | 롤백된 generation의 재발행 금지 | — | `crates/qsh-core/src/reverse/registry.rs:1102` `generation_is_never_repeated_across_any_replace_stale_remove_sequence`(proptest) | — |
| E5 | localctl request-id 교차 응답 | mux 오라클 대조 | — | `crates/qsh-core/src/localctl/mux.rs:575` `interleaved_reused_peer_ids_never_cross`(proptest) | — |
| E6 | 재접속 backoff 폭주 | 단조 증가 + cap | — | `crates/qsh-core/src/reverse/target.rs:823` `backoff_sequence_is_monotone_nondecreasing_until_the_cap`(proptest) | — |
| E7 | 터널 재경로 중 바이트 손실 | QUIC path migration을 투명하게 통과 | ADR-0018:14 | `crates/qsh-testkit/tests/tunnel_chaos.rs:149,299,781` | connection 자체가 끊기면 터널은 재생되지 않는다 — v1의 명시적 비대칭 → §7 h11 |
| E8 | overflow로 인한 output 손실을 조용히 숨김 | overflow는 절대 숨기지 않는다. `available_from` 이전을 가리키는 커서는 먼저 `Gap`을 받고 그다음 데이터를 받는다 | ADR-0004:10,18,33 — "`session.gap` event가 buffer overflow의 유일하고 명시적인 신호여야 하며, 이를 숨기는 어떤 fallback도 있어서는 안 된다"; `protocol.md:289` | `ring.rs:877` `forced_control_loss_is_signalled_by_a_gap_never_hidden`, `:639` | 손실 자체는 §7 h15. 이 행이 지키는 것은 "숨기지 않는다"는 성질이다 |

E8이 무결성 범주에 있는 이유: 응용이 "끊긴 출력"과 "완전한 출력"을 구별하지 못하는 것이 실질적 무결성 침해이기 때문이다. 손실을 없애는 것보다 손실을 정직하게 알리는 것이 이 프로토콜의 계약이다.

### F — 부인방지·감사

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| F1 | 무단 인가가 흔적을 남기지 않음 | audit 기록 없이는 allow 자체가 성립하지 않는다 | `architecture.md:90` | `server/mod.rs:6071,6149,6249`(session.open/attach/write); `reverse/admit.rs:474` `allowed_registration_fails_closed_when_the_audit_sink_cannot_record_it` | — |
| F2 | 감사 레코드에 payload가 섞임 | 구조적 필드만 — 타입에 payload를 실을 자리가 없다 | `crates/qsh-core/src/audit.rs:100` "Fields are exactly those listed in architecture.md §6" | `audit.rs:102-143` `AuditRecord` 필드 전수: `ts`·`request_id`·`principal`·`action`·`resource`·`decision`·`rule`·`auth_path`·`peer_addr`·`count`. PTY·명령·환경변수를 담을 필드가 존재하지 않는다 | `resource`(`audit.rs:113`)는 사용자 지정 식별자를 담는다(`session_id`, `host:port`). 정확한 서술은 "payload 0"이 아니라 "모양 검사를 통과한 구조적 식별자만"이고, 이는 설계된 동작이다 |
| F3 | 거부 상관관계를 추적할 수 없음 | 개별 거부는 실제 peer_addr를 남기고 `"-"`는 집계 요약에만 쓴다 | — | `quota.rs:334` `quota_rejection_audit_line_carries_the_real_client_peer_addr` | — |
| F4 | 크래시로 audit 라인이 파손됨 | torn-write 절단 복구 + 파일 락 | 구현 주석 — 설계 문서 서술은 §6 r1·r2가 흡수한다 | `audit/writer.rs:925` `repair_partial_write_truncates_a_torn_fragment_back_to_the_last_known_good_offset`, `:1173` `two_sinks_on_one_path_interleave_without_losing_or_corrupting_lines`, `:892`, `:1023` | — |

F2의 정확도가 이 범주에서 가장 중요하다. "audit에 payload를 남기지 않는다"를 런타임 규율로 지키는 시스템은 언젠가 실수하지만, 담을 필드가 없는 타입은 실수할 자리가 없다.

### G — 가용성

| # | 위협 | 통제 | 근거 | 핀 테스트 | 잔여 위험 |
|---|---|---|---|---|---|
| G1 | garbage flood로 데몬 사망 | admission 게이트 | ADR-0009 | `admission.rs:374` `host_survives_garbage_initial_flood`, `:194` | — |
| G2 | 종료 시 좀비·고아 프로세스 | SIGTERM drain | ADR-0003; `README.md:510-522` | `crates/qsh-cli/tests/serve_sigterm_drain.rs:157` `sigterm_drains_the_session_and_leaves_no_orphan` | best-effort다. 재시작은 그 프로세스의 모든 detached 세션의 끝 → §7 h12 |
| G3 | 나쁜 UDS 피어 하나가 데몬을 죽임 | bounded close | 구현 — 설계 문서 서술은 §6 r3이 흡수한다 | `localctl_perms.rs:194` `a_garbage_peer_is_refused_with_a_bounded_close_and_the_daemon_keeps_serving` | — |
| G4 | stale socket 때문에 데몬 발견 실패 | 거부되는 소켓은 unlink하고 다음으로 | `architecture.md:109` | `localctl_perms.rs:247` `discovery_unlinks_a_stale_socket_ahead_of_the_real_daemon_and_still_finds_it` | — |

## 5. 갭 — 통제는 있고 핀 테스트가 없거나 불확실했던 것

M8 Step 7 착수 시점에 다섯 개를 열어 두고 조사했다. 넷은 닫혔고 하나는 M9 소유로 남는다.

| # | 통제 | 판정 | 근거 |
|---|---|---|---|
| g1 | `MAX_INFLIGHT_PER_CONDUIT`(64) 초과 시 거부 | **닫힘 — 기존 테스트가 이미 정확히 이 시나리오를 친다.** 새 테스트는 만들지 않았다 | `crates/qsh-core/src/localctl/mux.rs:433` `cap_exhausted_on_one_conduit_does_not_affect_another`가 한 conduit의 in-flight를 `MAX_INFLIGHT_PER_CONDUIT`까지 채운 뒤 `map_outbound`가 `Err(Exhausted)`를 반환함을 확인한다. hub-wide 캡(`listen.rs:2730`)과는 다른 축이다 |
| g2 | `trust remove` 후 기존 연결의 동작(`README.md:563-572`) | **닫힘 — 기존 테스트 있음** | `crates/qsh-cli/tests/trust_lifecycle_live.rs:118` `an_established_connection_survives_the_hosts_trust_remove`가 실제 QUIC 연결로 `trust remove` 뒤에도 같은 PTY 세션의 write/read가 계속됨을 확인한다. 이 테스트가 고정하는 것은 통제가 아니라 §7 h5의 한계 자체다 |
| g3 | `session.control`의 `close`가 scope 예외라는 것(`architecture.md:86`) | **닫힘 — 기존 테스트가 양성 방향으로 고정한다** | `crates/qsh-testkit/tests/session_loopback.rs:891` `session_close_is_exempt_from_scope_owned_while_write_and_resize_are_not`가 `scope = "owned"` 규칙 아래에서 `close`는 비-owner에게 허용되고 `write`/`resize`는 거부됨을 같은 테스트에서 대조한다 |
| g4 | doctor `acl_principal_unmatched` / `acl_ca_auth_path_missing` | **열림 — M9 소유.** M8 시점의 잔여 위험으로 남긴다 | ADR-0017 결정 2(`:21-22`)가 이 둘을 요구하고, `docs/ROADMAP.md:118` M9 범위 (h) "doctor 진단 7종 추가"가 소유한다. 저장소에 아직 구현이 없다. 실무적 영향: `trust.toml`에 pin은 됐지만 `acl.toml`에 대응 행이 없는 peer가 조용히 전면 거부 상태로 남고, 운영자는 `serve` 시작 시 stderr 고지에만 의존한다(ADR-0017:36이 이 채널이 상시 데몬에서는 보이지 않는다고 적는다) |
| g5 | 0-RTT 금지 다섯 상수의 회귀 탐지 | **닫힘 — M8 Step 7이 유닛을 추가했다** | `crates/qsh-transport/src/endpoint.rs:1242` `tls_configs_disable_0_rtt_and_session_resumption`. 이전에는 `loopback.rs:395-403`이 "0-RTT를 구조적으로 도달 불가하게 만들어 단언할 API 표면이 남지 않았다"고 기록한 상태였고, 다섯 상수 중 하나를 되돌려도 깨지는 테스트가 없었다. 새 유닛은 config 객체를 직접 읽어 그 상태를 끝낸다 |

## 6. 문서가 서술하지 않던 통제

테스트가 강제하고 있으나 설계 문서 어디에도 서술이 없던 성질 다섯 개다. §4의 해당 행이 그 서술을 겸하지만, 왜 그런 통제가 있는지는 여기 적는다.

**r1 — audit의 torn-write 복구.** 프로세스가 write 도중에 죽으면 마지막 줄이 잘린 채 남는다. `RotatingAuditSink`는 다음 열기에서 마지막으로 알려진 온전한 offset까지 파일을 잘라내고 거기서부터 이어 쓴다(`audit/writer.rs:593` `repair_partial_write`, 테스트 `:925`). 이것이 없으면 파손 줄 하나가 그 뒤의 모든 audit 파싱을 오염시키고, JSONL을 읽는 도구는 그 지점에서 멈춘다 — 부인방지 자산이 크래시 한 번에 통째로 무효가 되는 셈이다.

**r2 — 하나의 경로에 두 sink가 붙는 것을 전제한다.** `qsh serve`와 `qsh listen`이 같은 계정에서 동시에 뜨면 audit 경로가 겹친다. writer는 append를 파일 락 아래에서 수행하므로(`writer.rs:518,548`) 두 sink가 줄을 섞지도 잃지도 않는다(`:1173`). 설계 문서는 audit sink를 단수로만 서술해 왔고, 그래서 이 전제가 어디에도 적혀 있지 않았다.

**r3 — localctl 데몬은 쓰레기 피어 하나로 죽지 않는다.** UDS accept 뒤 프로토콜을 지키지 않는 피어는 유계 시간 안에 닫히고 데몬은 계속 서빙한다(`localctl_perms.rs:194`). same-uid 경계 안이라 인가 위협은 아니지만 가용성 불변식이고, 명문화된 문장이 없었다.

**r4 — localctl 프로토콜에는 resume token을 담을 필드가 아예 없다.** `resume_secrecy.rs:211` `no_localctl_message_type_or_source_file_ever_names_a_resume_token`이 메시지 타입과 소스 파일 양쪽에서 이를 확인한다. ADR 형태의 근거는 없고 테스트가 설계를 강제하는 형태다 — 토큰 custody를 클라이언트에 두기로 한 ADR-0007:16의 자연스러운 귀결이지만, 그 ADR은 localctl을 언급하지 않는다.

**r5 — 작은 push의 tail-chunk coalescing.** ADR-0004는 byte 예산만 결정했고 `architecture.md:54`도 크기만 적는다. 실제 구현은 작은 push를 tail chunk에 합쳐 per-entry 오버헤드를 `budget / chunk_max`로 묶는다(`ring.rs:13-15`, 테스트 `:783`). 이것이 없으면 1바이트씩 echo하는 PTY 하나가 예산 안에서도 entry 수를 폭발시킨다 — 8 MiB라는 숫자가 실제로 메모리 상한이 되게 만드는 것이 이 방어다.

## 7. 잔여 위험

통제가 없거나 의도적으로 두지 않은 것들이다. 리뷰어가 먼저 볼 목록이 이것이다.

| # | 한계 | 근거 |
|---|---|---|
| h1 | TOFU 미지원. `trust.toml`이 pin의 방향을 구분하지 않아, client 쪽 자동 pin이 같은 상대의 inbound 인증까지 통과시킨다 | ADR-0017:40,42(방향 축 `direction = "outbound"`는 별도 ADR로 미뤘고 번호도 아직 없다); `ROADMAP.md:119`가 M9 명시적 out으로 적는다 |
| h2 | listener를 상대로 한 pairing이 미정 | ADR-0015:16 "미정" |
| h3 | CSR 기반 발급이 없어, 여러 장비를 한 CA로 서명하려면 CA 개인키를 그 장비 모두에 복제해야 한다 | ADR-0016:10,16; ADR-0013:31 |
| h4 | CA rotation·revocation 설계가 없다. 단일 root, intermediate 없음 | ADR-0008:34,41 |
| h5 | `qsh trust remove`가 기존 연결에 소급되지 않는다. 제거된 peer는 그 연결이 끊길 때까지 협상된 권한 전체를 유지한다 | `README.md:563-572`. 강제 종료는 P1 |
| h6 | `qsh trust accept`의 양쪽 pin이 원자적이지 않다. 호스트 쪽 pin과 invite 소비가 먼저 일어나고 클라이언트 로컬 pin이 나중이라, 그 사이 로컬 이름 충돌이 나면 invite는 이미 소비된 채 남는다 | `README.md:573-581`; `protocol.md` §15.6 |
| h7 | 이미 pin된 상대의 재페어링이 불가능하다. 새 invite로도 풀리지 않고 복구 경로는 호스트의 `trust remove` 뿐이다 | `README.md:582-588`; `protocol.md:417` |
| h8 | 역방향 conduit에 pairing evaluator가 붙어 있지 않다. 사전 pin/CA로만 신뢰를 세우고, 그것이 손상됐을 때의 복구 절차 문서가 없다 | `protocol.md:433`; ADR-0015 미정 |
| h9 | homoglyph 미탐지. 서로 다른 코드 포인트가 같은 글리프로 렌더되는 이름을 `validate_device_name`이 잡지 않는다 | `protocol.md:409`; `crates/qsh-proto/src/wire.rs:385-392`. 실제 방어선은 fingerprint 병기 대조 |
| h10 | `acl.toml` hot reload 없음. 편집은 다음 `serve`/`listen`/`reverse` 시작부터 적용된다 | `README.md:539-541`; ADR-0017 |
| h11 | 터널에는 replay ring이 없다. connection 손실 시 in-flight TCP 연결은 재생되지 않고 깨끗이 끊긴다 | ADR-0018:14; `README.md:523-538` |
| h12 | 세션이 리스너 프로세스 수명에 결합된다. 재시작은 그 위 모든 detached 세션의 끝이다 | ADR-0003; `README.md:510-522` |
| h13 | rustls 내부로 넘어간 키 사본이 `Zeroizing` 밖에 있다. `LocalIdentity.key_pkcs8_der`까지가 규율의 경계이고, rustls-pki-types 1.15.1에 `impl Drop`이 없다 | M8 Step 6이 명시적으로 수용한 잔여(코드 주석에 기록, 업스트림 이슈는 열지 않았다) |
| h14 | 이미 redeem된 invite도 20분 retention 창 안에서는 TLS 게이트가 계속 열려 있다. 실제 거부는 그다음 단인 redeem 판정에서 난다 | `protocol.md:429`. 이 관찰이 뚫는 것은 없다 — redeem 판정 자체가 매번 지켜진다 |
| h15 | 세션 replay는 기본 8 MiB까지다. 그보다 오래 끊겼다가 돌아오면 그 구간은 gap event로 통보될 뿐 복구 수단이 없다. disk spool이 없으므로 늘리는 유일한 방법은 `[serve].replay_bytes`이고, 그건 리스너 메모리를 직접 늘린다 | ADR-0004:14,18,20,27,34; 기본값 `crates/qsh-core/src/config.rs:539`. h11과는 다른 항목이다 — 이쪽은 세션 output 이력의 **크기 상한** 문제다 |

h4와 h5는 함께 읽어야 한다. revocation 메커니즘이 없고 `trust remove`도 소급되지 않으므로, 손상된 peer를 즉시 끊는 수단이 v1에는 없다. 실무적 대응은 그 연결이 끊길 때까지 기다리거나 `qsh serve`를 재시작하는 것이고, 후자는 h12에 따라 모든 세션을 끝낸다.

## 8. 운영 가정

qsh가 지키지 않고 운영자에게 맡긴 것들이다.

- **시계 동기.** cert 유효기간(`protocol.md:37`), invite TTL 10분과 retention 20분(`protocol.md:405`), resume TTL이 전부 로컬 시계에 의존한다. NTP를 요구하는 명시적 문장은 어느 문서에도 없다. A5가 지적하듯 장기 device cert에서 유효기간은 유일한 revocation 레버이므로, 시계가 크게 어긋난 호스트는 만료된 cert를 받아들일 수 있다.
- **파일 권한 유지.** 생성 시점의 0600/0700은 qsh가 강제하지만(D4), 그 이후 다른 프로세스·백업·잘못 설정된 sync가 넓히는 것은 막지 못한다. `invites.toml`이 특히 민감하다 — `mac_key`가 raw secret과 동등한 verifier라서(D3), 이 파일이 새면 TTL이 남은 invite는 그것만으로 완결된다(`protocol.md:427`).
- **네트워크 도달성.** 역방향 모드는 target에서 controller로 가는 직접 UDP 경로를 요구한다. relay·NAT traversal·discovery를 qsh는 제공하지 않는다(`README.md:608-613`; PRD §12).
- **CA 키 복제 관행.** h3이 닫힐 때까지 여러 장비 서명은 `ca.key` 복제로만 가능하다. 그 사본 하나하나가 발급 권한 그 자체다(ADR-0016:10).
- **`acl.toml` 재시작 규율.** h10에 따라 정책 편집은 재시작해야 반영된다. 편집했는데 반영이 안 된 상태를 "정책이 느슨한 채로 돌고 있는 창"으로 인식해야 한다.
- **replay 여유 조정.** `[serve].replay_bytes` 기본 8 MiB가 자기 워크로드에 충분한지는 운영자가 판단한다. ADR-0004:20이 "전형적 텍스트 터미널 output 기준 수십 초~수 분 분량"이라고 추정한 값이다.

## 9. 명시적 비목표

- **relay·NAT traversal.** 제품 경계 밖이다(`README.md:615-620`; PRD §14).
- **user switching.** child는 항상 `qsh serve`를 실행한 OS 계정으로 spawn하고, `SessionOpen`의 `user` hint가 다르면 spawn 없이 `UNSUPPORTED`다(`architecture.md:69`). qsh는 OS 사용자 경계를 대신하지 않는다.
- **세션 안 활동의 통제.** ACL은 요청 종류를 판정하고, 그 뒤 셸에서 벌어지는 일은 OS의 소관이다.
- **PTY 내용의 감사.** F2가 구조적으로 보장하는 비목표다 — 감사 레코드에 payload를 담을 필드가 없다.
- **homoglyph 판정.** 표 기반 confusable 검사를 커스텀 crate 없이 정확히 구현하기 어렵고, 이 자리에서 실제 방어선 노릇을 하는 것은 fingerprint 병기다(`protocol.md:409`).
- **TOFU.** h1의 방향 축이 먼저 정리되기 전에는 채택하지 않는다(ADR-0017:60).
- **web PKI.** root를 어떤 경로로도 로드하지 않는다(`protocol.md:35`).

## 10. 유지 규율

- **새 wire op이 들어오면 §4에 행이 하나 는다.** freeze 이후에도 additive 변경으로 새 message·새 capability가 붙을 수 있고(`protocol.md` §16.4), 그때 ACL 커버리지를 지키는 것은 B2의 variant 전수 대조다. 그 트랩이 빨개지면 여기 표에도 행이 빠져 있다는 뜻이다.
- **새 통제가 들어오면 근거와 핀 테스트를 같은 커밋에서 채운다.** 근거 열이 빈 행은 리뷰어에게 "왜 이걸 믿어야 하는가"를 답하지 못한다.
- **핀 테스트 인덱스는 이 문서가 canonical이다.** testing.md는 계층별로 무엇을 갚아야 하는지를, 이 문서는 위협별로 무엇이 그것을 갚고 있는지를 적는다. 테스트 이름이 바뀌면 여기도 바뀐다.
- **갭이 닫히면 §5의 행을 지우지 말고 판정을 적는다.** 어느 시점에 무엇으로 닫혔는지가 다음 리뷰의 입력이다.
- **`파일:줄` 인용은 리팩터에 밀린다.** 절 이름·테스트 이름을 함께 적어 두는 것이 그 대비이고, 줄만 적힌 인용은 다음 라운드에서 재확인 대상이다.
- 같은 커밋에서 편집한 파일을 인용할 때는 편집 후 트리에서 다시 grep한다 — 인용은 편집 전 줄 번호를 기억하지 않는다.
