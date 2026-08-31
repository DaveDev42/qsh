# ADR-0008: private CA는 단일 self-signed root로 device cert를 발급한다

날짜: 2026-08-31
상태: 승인됨

## 맥락

QSH는 password 인증을 지원하지 않고 상호 TLS로만 인증한다(PRD §9). peer 신뢰 근원은 세 가지다 — pinned fingerprint(M1), 일회용 invite code pairing(M7 Step 4, ADR-0002), 그리고 private CA. 앞의 둘은 구현됐고, private CA는 M7 Step 5의 대상이다.

검증 층은 이미 완성돼 있다. `QshPeerVerifier::verify_core`(`crates/qsh-transport/src/tls.rs`)는 pin → CA-chain → pairing 순으로 신뢰를 판정하며, CA-chain 경로는 `TrustEvaluator::ca_roots()`가 돌려준 루트로 webpki 체인 검증을 실제로 수행하고 leaf의 SAN에서 principal을 유도한다. `trust.toml`은 `[[ca]]`(name·cert_pem) 슬롯을 이미 가지며 `SharedTrustStore::ca_roots()`가 이를 DER로 파싱해 verifier에 먹인다. `principal_from_san`은 `qsh://device/<seg>` → `Principal::Device`, `qsh://user/<seg>` → `Principal::User`를 파싱한다. 실 QUIC 핸드셰이크 테스트(handshake_matrix case09/case15)가 pin 없는 CA-chain 경로·principal·`AuthPath::Ca`를 이미 단언한다.

비어 있는 것은 발급/등재 프런트엔드다. CA 키를 만들고, CA-서명 device cert를 발급하고, CA 루트를 `trust.toml`에 등재하는 명령이 없어 프로덕션 경로에서 `ca_roots()`가 늘 빈다. Step 5는 새 검증 로직이 아니라 이미 배선된 소켓에 발급 플러그를 꽂는 일이며, 아래 결정은 그 플러그의 모양을 고정한다.

## 결정

**단일 self-signed root CA가 device cert를 직접 서명한다. `qsh cert`가 CA를 생성하고, 로컬 device identity를 CA-서명 cert로 발급하고, CA 루트를 `trust.toml [[ca]]`에 등재한다.**

1. **CA 계층 — 단일 루트, intermediate 없음.** self-signed root 1개(`is_ca` basic constraint)가 device leaf를 1-hop으로 서명한다. 루트 cert(PEM)는 `trust.toml [[ca]]`에 공개로 등재하고, 루트 개인키는 별도 보관한다(아래 4). CA 자체는 principal을 갖지 않는다 — principal은 발급된 leaf의 SAN에서만 나온다.

2. **서명 대상 = device cert, SAN 확정분 재사용.** `qsh cert issue`는 로컬 device identity의 기존 `device_id`를 `qsh://device/<device_id>` SAN에 담아 CA-서명한다. self-signed identity와 SAN 본문은 동일하고 서명자만 CA로 바뀐다. CA-chain이 성립하면 verifier는 이 SAN에서 `Principal::Device(<device_id>)` + `AuthPath::Ca`를 낸다. SAN 스킴·파서는 신설하지 않는다.

3. **user cert 발급은 범위 밖(P1).** `qsh://user/<name>` → `Principal::User` 검증 경로는 이미 존재하며 유지한다. 그러나 `qsh cert`는 M7에서 user leaf를 발급하지 않는다 — user identity는 "누가 이 이름인가"라는 정책 결정을 수반해 device보다 무거운 발급 UX가 필요하고, 이는 M7 예산 밖이다. device cert 발급만 구현한다.

4. **파일 배치 — `config_dir/ca/`.** `config_dir/ca/`(0700) 아래에 `ca.pem`(루트 cert)과 `ca.key`(PKCS#8 PEM 개인키)를 두며 둘 다 0600, PEM이다. 공개 루트는 `trust.toml [[ca]].cert_pem`에 등재한다. `identity/` 디렉터리 선례(0700 디렉터리 + 0600 PEM 파일)와 대칭이되, 발급 권한(CA 키)을 device 신원과 다른 디렉터리로 분리해 "device 신원 ≠ 발급 권한"이 파일 트리에 드러나게 한다. CA 키는 M7에서 file(0600) 저장만 지원한다(platform keystore는 P1).

5. **발급 대상은 로컬 device identity로 한정.** `qsh cert issue`는 이 장비의 self-signed identity를 CA-서명본으로 "승격"한다. 임의 device_id를 인자로 받는 원격 발급(headless provisioning)은 P1로 미룬다.

6. **세 신뢰 경로 우선순위 — pin > CA > pairing 유지.** 동일 leaf가 pin과 CA 양쪽에 해당하면 pin이 이기고 `AuthPath::Pin`이 된다(더 강한 명시적 pin 우선). pairing은 pin·CA가 모두 실패한 뒤에만 열리므로 CA 등재가 pairing 창구를 가리는 일은 없다 — CA로 신뢰되는 peer는 애초에 pairing 경로를 타지 않는다.

**principal 검증의 load-bearing 축은 principal 모양이 아니라 `AuthPath`다.** pin device와 CA device는 둘 다 `device:` principal일 수 있고(architecture.md §6/§7 불변식), 이 둘을 가르는 것은 `AuthPath`(Pin vs Ca)다. Step 5의 완료 판정 "`fp:`/`device:` principal 매핑"은 이 축으로 읽어야 한다 — pin 경로 → `AuthPath::Pin`, CA 경로 → `AuthPath::Ca`를 실 핸드셰이크로 단언하는 것이 검증 대상이며, 현행 코드가 아무도 생산하지 않는 `Principal::Fingerprint`(`fp:`)를 새로 만들어 내는 것은 이 ADR의 결정이 아니다.

## 근거

- rotation/revocation이 명시적으로 범위 밖(아래 결과)이므로 intermediate의 유일한 실익(루트 오프라인화·중간 교체)이 지금은 무의미하다. 단일 루트가 표면·테스트를 최소화하며, verifier는 이미 intermediates를 받으나 발급기가 체인을 만들 이유가 없다.
- SAN 스킴·파서·device cert의 SAN 삽입·`trust.toml [[ca]]` 슬롯·CA-chain 검증이 전부 이미 존재하고 테스트로 고정돼 있다. 발급 명령이 이 확정분을 그대로 재사용하면 신규 검증 코드가 0이 되어, 새로 도입되는 신뢰 표면이 "발급된 leaf가 기존 검증 경로에 올바로 들어가는가"로 한정된다.
- CA 키를 `identity/`와 섞지 않고 `ca/`로 분리하면, 이 장비가 발급 권한을 갖는지가 파일 트리에서 즉시 드러나고 감사·백업 정책을 device 신원과 독립적으로 세울 수 있다.
- user cert 검증은 공짜지만 발급 UX는 정책 결정을 수반한다. device 발급만으로 (d) 완료 판정(CA 발급 cert로 실 handshake + device principal 매핑)을 전부 충족하므로, user 발급을 P1로 미루는 것이 범위를 정확히 지킨다.

## 대안과 기각 사유

- **2계층 CA(root + intermediate)**: 기각. rotation이 범위 밖인데 계층만 늘어 발급기·테스트 표면이 커진다. 미래에 rotation을 도입할 때 별도 ADR로 계층을 추가하는 편이 낫다.
- **발급 시 사람이 지정하는 별칭을 SAN에 사용**(`qsh://device/<사람-이름>`): 기각. device_id ULID와 이원화되어 감사·매핑이 혼선된다. 사람 친화적 이름은 trust 별칭과 `hosts.toml`이 담당하며, cert의 SAN은 안정적 device_id를 담는다.
- **user cert 발급을 M7에 포함**: 기각. 검증은 이미 지원되나 발급 UX(사용자명 근거·다중 device 매핑)가 M7 예산 밖이고 ROADMAP의 out 항목에 인접한다.
- **CA 키를 `identity/`에 병치**: 기각. 경로 하나를 아끼는 대신 발급 권한과 device 신원이 한 디렉터리에 섞여, "이 키를 읽으면 임의 device를 발급할 수 있다"는 위협이 device 키와 구분되지 않는다.
- **`Principal::Fingerprint`(`fp:`)를 CA 경로 또는 이름 없는 pin에서 새로 생산**: 기각. 현행 코드에서 `fp:`는 미생산 예약 variant이고, pin/CA 구분은 이미 `AuthPath`가 담당한다. `fp:` 생산을 도입하면 `parsed_pins`/`principal_from_san` 변경과 fixture 개정이 따라와 Step 5 범위를 넘는다.

## 결과

- 발급/서명 로직은 `qsh-core`(신규 `ca` 모듈 또는 `identity/` 확장)에 두고, `qsh-cli`는 clap + 렌더러만 담당한다. rcgen은 `qsh-core`가 이미 의존한다. `qsh cert`가 value op을 내면 `CLI_V1_SCHEMA_COMMANDS` 등록과 fixture 추가가 완전성 게이트(`schema_commands_registry`) 때문에 필수다.
- `qsh cert`를 MCP tool로 노출할지는 별도 결정이다 — trust/identity 관리는 현재 MCP 표면이 0이므로(CLI.md §8.4 "MCP를 통해 interactive trust prompt를 열지 않는다"), Step 5는 신규 MCP tool을 추가하지 않는다. 노출이 필요하면 §8.2 표를 갱신하는 별도 결정으로 다룬다.
- `trust.toml [[ca]]` 등재는 additive·append-only이며 중복 방지·갱신 semantics는 trust add(Step 2) 선례를 따른다. CA 관련 값-보유 golden fixture는 diff 리뷰 규율(testing.md) 대상이다.
- **CA rotation·CRL/OCSP·revocation 전파는 이 ADR의 범위 밖(P1)이다.** cert 무효화의 유일한 레버는 validity window 만료이며(verifier가 이미 fail-closed로 강제), 신규 CA·leaf도 이 동작을 그대로 상속한다. rotation UX는 미래 ADR로 다룬다.
- CA 발급은 신뢰 근원을 넓히는 표면이므로 PRD의 SC7 외부 보안 리뷰 대상에 포함한다.
- `CaEntry` doc의 낡은 주석("private CA는 M6 scope, M1엔 CLI 없음")은 Step 5 구현에서 실상(M7 Step 5, CLI 신설)에 맞게 갱신한다.
- `qsh cert` CLI 계약은 CLI.md 신설 절에 문서화하고 이 ADR을 링크한다.
