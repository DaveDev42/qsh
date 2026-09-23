# ADR-0026: SSH 키 가져오기(`--import-ssh-key`)는 v1에 넣지 않는다. P1으로 미루고 착수할 때의 모양만 지금 고정한다

날짜: 2026-09-24
상태: 제안됨

개정 관계: ADR-0008을 확장한다(결정 5는 유지). ADR-0017의 결정 1과 결정 5가 세운 제약은 개정하지 않고 인수한다.

## 맥락

이슈 #3 항목 e가 묻는 것은 하나다. 운영자가 이미 쥐고 있는 OpenSSH 키를 qsh device identity로 들여오는 `--import-ssh-key` 같은 입구를 둘 것인가.

저장소에는 그 입구의 흔적이 없다. `--import-ssh-key`, `import_ssh_key`, `authorized_keys`, `ssh-agent`를 `.rs`·`.md`·`.toml` 전체에서 찾으면 한 건도 걸리지 않는다. 구현도, 설계 문서의 한 절도, 자리를 잡아 둔 예약 ADR도 없다. `docs/ROADMAP.md` §3의 유예 가드레일 표에도 행이 없다. 그 표의 작동 원리는 "ACL action과 오류 경로만 정의하고 구현하지 않는다"인데, SSH 키 가져오기는 이름조차 붙지 않은 순수한 부재 상태다. 유예된 기능이 아니라 논의된 적 없는 기능이다.

오늘의 identity 경로는 단일하다. `crates/qsh-core/src/identity/mod.rs`의 `init`이 `device_<ULID>`를 만들고 같은 파일의 `generate`를 부른다. `generate`는 `rcgen::PKCS_ED25519`로 keypair를 뽑고 `CN=<device_id>`와 SAN `qsh://device/<device_id>`를 담은 10년짜리 self-signed 인증서를 서명한다. 프로덕션에서 키를 만드는 코드는 이 함수 하나뿐이고 그 결과를 `LoadedIdentity`가 identity와 개인키로 묶어 transport에 넘긴다.

fingerprint는 키가 아니라 인증서에서 나온다. `generate`는 `Fingerprint::of_cert_der(cert.der())`로 값을 얻고 그 함수는 leaf의 `subject_pki.raw`, 곧 SPKI DER에 SHA-256을 건다(`crates/qsh-transport/src/identity.rs`의 `Fingerprint::of_cert_der`와 `Fingerprint::of_spki_der`). `identity.toml`, `IdentityInitData.fingerprint`, `trust.toml`의 pin, `acl.toml`의 `fp:sha256:<base64>` principal이 전부 이 한 값을 쓴다.

keystore는 import 경로가 아니다. `crates/qsh-core/src/identity/keystore.rs`의 `KeyStore::store`는 PKCS#8 DER를 받는 sink이고 프로덕션에서 이 trait을 부르는 자리는 같은 crate의 `store_key` 하나이며 그 인자는 방금 `generate`가 만든 `key_pkcs8_der`다. `FileKeyStore`·`PlatformKeyStore`·`MemoryKeyStore` 어디에도 바깥에서 온 키 파일을 읽어 들이는 입구가 없다.

의존도 없다. `Cargo.lock`에 OpenSSH 키 포맷을 읽을 수 있는 crate가 한 줄도 없다. 가져오기를 구현하려면 새 의존이 먼저 필요하고 그 의존은 `deny.toml`의 `[advisories]`·`[licenses]`·`[bans]`·`[sources]` 네 절을 모두 통과해야 한다.

`init`은 멱등이다. 이미 identity가 있으면 `created: false`로 기존 값을 돌려준다(`docs/CLI.md` §6.11). 가져오기는 이 멱등성과 정면으로 만난다. 이미 identity를 만든 장비에서 키를 갈아 끼우는 일은 가져오기가 아니라 rotation이다. rotation은 ADR-0008의 결과 절이 P1로 밀어 둔 자리다.

## 결정

1. `--import-ssh-key`는 v1에 넣지 않는다. P1 백로그 항목으로 둔다. 이 결정이 이 ADR의 본문이고 아래 2번부터 8번까지는 P1에서 착수할 때 이미 정해져 있는 모양을 미리 적어 두는 것이다. 지금 구현되는 것은 없고 flag도 ACL action도 오류 경로도 신설하지 않는다.

2. 착수한다면 기본값은 qsh 자체 생성 키다. `--import-ssh-key`는 명시적 opt-in이고 1차 범위는 평문 Ed25519 파일 하나로 한정한다. RSA와 ECDSA는 받지 않는다. 오늘의 identity가 `rcgen::PKCS_ED25519` 단일 경로여서 다른 알고리즘을 받는 순간 인증서 생성 경로와 그 아래 서명 알고리즘 축이 하나 더 생긴다. 그 비용은 가져오기 자체와 분리해서 따로 정한다.

3. 가져온 키의 qsh fingerprint는 self-signed leaf의 SPKI SHA-256이지 그 SSH 키 자신의 fingerprint가 아니다. 같은 키를 두고도 두 값이 다르다. qsh 쪽은 X.509 SPKI DER를 해시하고 OpenSSH 쪽은 자기 wire 형식 공개키 blob을 해시하기 때문이다. 그러므로 가져오기 출력은 두 값을 이름표와 함께 나란히 낸다. 그러지 않으면 운영자가 `ssh-keygen`이 보여 준 값을 `trust.toml`이나 `acl.toml`에 적고 아무 행도 매칭되지 않는 default-deny 상태를 원인 없이 마주한다.

4. `authorized_keys`에서 trust와 ACL로 넘어가는 이행은 preview만 낸다. 읽어서 "이 키들에 대해 어떤 pin과 어떤 `[[acl]]` 행이 필요한지"를 출력할 뿐 `acl.toml`을 쓰지 않고(ADR-0017 결정 1) 자동으로 pin하지도 않는다(ADR-0017 결정 5, TOFU는 닫혀 있다). `authorized_keys`에는 principal 이름이 없고 `acl.toml` 한 행은 렌더된 principal 문자열과 정확히 일치해야 하므로, 이름은 사람이 고르는 것 말고 다른 출처가 없다.

5. raw SSH 공개키 모양의 새 principal 축은 만들지 않는다. `Principal`의 렌더 형식은 `device:<name>`·`user:<name>`·`fp:sha256:<base64>` 셋이다(`crates/qsh-transport/src/identity.rs`). ADR-0008의 대안 절은 CA 경로나 이름 없는 pin에서 `Principal::Fingerprint`를 새로 생산하는 안을 이미 기각했다. 이행은 이름 있는 pin으로만 간다. 이 기각을 뒤집으려면 이 ADR이 아니라 ADR-0008을 개정하는 ADR이 필요하다.

6. CA 발급은 ADR-0008 결정 5를 넘지 않는다. `crates/qsh-core/src/ops/cert.rs`의 `Ops::cert_issue`는 이 장비 자신의 identity를 CA-서명본으로 승격하는 일만 하고 바깥에서 받은 키에 leaf를 발급하는 것은 ADR-0008이 P1로 미뤄 둔 원격 프로비저닝이다. 가져오기가 그 선을 넘는 지점은 없다.

7. 암호화된 키, `ssh-agent`, OS keychain 연동은 별도 결정으로 분리한다. 1차 범위에는 평문 파일만 둔다. 암호가 걸린 키는 passphrase 프롬프트를 요구하는데 `--json`·`--jsonl` 모드는 프롬프트를 열 수 없다(`docs/CLI.md` §2.1). `ssh-agent`는 애초에 개인키를 내주지 않으므로 그쪽 연동은 가져오기가 아니라 서명 위임 설계다. 오늘의 `LoadedIdentity`에는 그런 seam이 없다.

8. 새 의존은 `cargo deny check`를 통과해야 한다. OpenSSH 키 파서는 신뢰할 수 없는 입력을 읽는 파서이므로 ADR-0001 결과 절의 규율("신뢰 불가 입력을 다루는 파싱 코드는 `qsh-proto`에 격리되어 cargo-fuzz 타깃으로 커버 가능해야 한다")이 그대로 걸린다. 착수하면 fuzz 타깃이 하나 늘고 `fuzz/README.md`의 개수 서술도 같이 움직인다.

## 근거

P1으로 미루는 이유는 비용과 이득의 비례가 맞지 않아서다. 이득은 최초 설정에서 `qsh init` 한 번을 아끼는 것뿐이다. 비용은 새 파서 의존 하나, 오늘 정확히 한 갈래뿐인 키 경로의 두 번째 갈래, 그리고 서로 다른 두 fingerprint 어휘가 한 화면에 동시에 나오는 상태다. 압력원도 없다. 유예 가드레일 표의 다른 행들은 전부 "스펙 예시에 있다", "외부 기여 PR이 온다", "doctor가 보고하는 순간" 같은 구체적인 압력을 적어 두었는데 이 항목에는 이슈 #3의 질문 한 줄 말고 아무것도 없다.

키 재사용 자체도 이득만 있는 것이 아니다. 같은 키를 SSH와 qsh가 나눠 쓰면 두 시스템의 키 수명이 묶인다. 한쪽에서 키를 폐기하면 다른 쪽도 같이 폐기해야 하는데, ADR-0008이 적었듯 qsh에는 아직 revocation 전파가 없고 무효화 레버는 validity window 만료 하나뿐이다.

그런데도 지금 모양을 적어 두는 것은 다른 결정들이 그 모양을 이미 거의 다 정해 놓았기 때문이다. ADR-0008 결정 5가 발급 대상을 로컬 device identity로 묶었고, 같은 ADR의 대안 절이 `fp:` principal 생산을 막았고, ADR-0017 결정 1이 `acl.toml` writer를 막았고, 결정 5가 자동 pin을 막았다. 남는 자유도는 알고리즘 집합과 출력 문면 정도다. 이 제약을 문서로 고정해 두지 않으면 다음 라운드가 "가져오기 하는 김에 `acl.toml` 행도 써 주자"거나 "SSH 공개키를 그대로 principal로 쓰자"는 제안을 원점에서 다시 꺼낸다.

fingerprint 두 값을 나란히 내라는 것은 문서 취향이 아니라 실패 모드에 대한 처방이다. 이 저장소에서 principal 불일치는 침묵한다. 파일이 틀린 것도 파싱이 실패하는 것도 아니라서 `acl_policy_invalid`가 잡지 못하고 원격 peer에게는 `PERMISSION_DENIED`로만 보인다(ADR-0017 맥락). 가져오기는 바로 그 침묵하는 실패로 가는 지름길을 하나 더 내는 명령이므로, 값을 잘못 베낄 여지를 출력 단계에서 없애야 한다.

## 대안

- v1에 넣는다. 기각한다. 위 근거의 비용 구조 그대로다. 덧붙여, 신뢰할 수 없는 키 파일을 읽는 파서를 들이면 ADR-0001이 `qsh-proto`로 격리하기로 한 fuzz 표면이 넓어지는데, 그 crate는 지금 wire와 CLI 인접 문자열만 다룬다. v1 마감을 앞두고 늘릴 표면이 아니다.
- 번호만 잡아 두고 결정 절은 비운 예약 ADR로 둔다(ADR-0015·ADR-0016의 `예약됨` 선례). 기각한다. 그 둘은 결정해야 할 축이 실제로 열려 있는 항목이다. 이 항목은 반대다. 축은 다른 ADR들이 이미 닫아 두어서 지금 적는 비용이 거의 없다.
- 가져오기가 성공하면 `acl.toml`에 대응하는 `[[acl]]` 행까지 써 준다. 기각한다. ADR-0017 결정 1이 닫은 자리다. `acl.toml`에는 `trust.toml`·`invites.toml`이 쓰는 `FileLock` 규율이 없고 잠금을 새로 세우더라도 프로세스 시작 시 1회만 읽히므로 조용한 쓰기가 다음 재시작 전까지 반영되지 않는다.
- `authorized_keys`를 읽어 해당 키들을 자동으로 pin한다. 기각한다. ADR-0017 결정 5가 적은 대로 `trust.toml`의 pin에는 방향 축이 없어서 들어오는 쪽을 염두에 두고 만든 pin이 나가는 dial의 인증까지 그대로 통과시킨다.
- SSH 공개키 문자열을 그대로 principal 어휘에 더한다. 기각한다. ADR-0008 대안 절의 `fp:` 기각과 같은 이유이고 `parsed_pins`와 `principal_from_san` 양쪽을 건드리면서 fixture 개정까지 끌고 온다.
- 가져오기 대신 `ssh-agent`에 서명을 위임한다. 1차 범위에서는 기각하고 결정 7로 분리한다. 개인키가 프로세스 안으로 들어오지 않는다는 점은 더 낫지만 그것은 가져오기 명령이 아니라 `LoadedIdentity`와 transport 사이에 서명 seam을 새로 내는 설계다. 같은 작업으로 묶을 수 없다.
- 1차부터 RSA와 ECDSA도 받는다. 기각한다. 오늘 인증서 생성이 `rcgen::PKCS_ED25519` 한 갈래라 알고리즘을 늘리면 그 축의 테스트가 곱해진다. 실사용 요구가 확인되면 별도 결정으로 다시 본다.

## 결과

- v1 표면은 한 바이트도 바뀌지 않는다. `qsh init`의 flag 집합, `IdentityInitReq`, `IdentityInitData`, wire 형식, `docs/CLI.md` §6.11 모두 그대로다. 이 ADR은 문서만 더한다.
- `docs/ROADMAP.md` §3 유예 가드레일 표에 행이 하나 늘어야 한다. 가드레일 문면은 "구현 0줄, 명령·flag·ACL action 신설 없음, P1 착수 시의 모양은 이 ADR이 이미 고정"이다. 그 편집은 메인 세션 소관이다.
- P1에서 착수하면 새 의존과 `cargo deny check`, 새 flag에 따른 man 재생성(`checked_in_man_pages_match_the_generator`), 새 fuzz 타깃과 `fuzz/README.md`의 개수 서술을 등록 항목으로 갚아야 한다. value op을 하나 신설한다면 `CLI_V1_SCHEMA_COMMANDS` 등록과 `cli_v1_data_schema` 대응 arm(`crates/qsh-core/tests/schema_commands_registry.rs`), fixture 추가와 `REQUIRED_FIXTURES` 등재, human과 JSON 렌더러 두 벌, `docs/CLI.md` §6.11 갱신까지 함께 간다.
- 이 ADR은 ADR-0008과 ADR-0017을 개정하지 않는다. ADR-0008 결정 5와 그 대안 절의 `fp:` 기각, ADR-0017 결정 1과 결정 5를 명시적으로 재확인한다.
- 이슈 #3 항목 e는 이 ADR이 승인되는 시점에 닫힌다. 답은 "v1에는 없다"다. 없다는 사실이 이제 이름과 근거를 갖는다.
- 이 ADR을 다시 여는 조건은 둘 중 하나다. P1 착수, 또는 rotation ADR이 먼저 서서 두 번째 키 경로가 어차피 필요해지는 경우다. 후자라면 가져오기는 그 경로에 얹히는 입력 하나가 되므로 비용 구조가 달라진다.
