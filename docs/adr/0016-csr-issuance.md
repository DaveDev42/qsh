# ADR-0016: CA 서명 요청(CSR) 흐름

날짜: 2026-09-09
상태: 제안됨
초안: 2026-10-11 결정 절 작성(ROADMAP M16 (c)). 사용자 확정 전이다.

## 맥락

ADR-0008이 정한 `qsh cert issue`는 "발급 대상은 로컬 device identity로 한정"(ADR-0008 결정 5)한다. 이 명령은 실행되는 바로 그 장비의 self-signed identity를 CA-서명본으로 승격할 뿐이고, 임의 device_id를 인자로 받는 원격 발급은 ADR-0008이 이미 P1로 미뤄 뒀다.

이 한계의 실무적 결과는 CA 개인키(`config_dir/ca/ca.key`, ADR-0008 결정 4)를 서명이 필요한 장비마다 두어야 한다는 것이다. 열 대를 한 CA로 서명하려면 `ca.key`가 열 대 모두에 있어야 한다. CA 키는 발급 권한 그 자체이므로 이는 "발급 권한을 가진 루트가 하나"라는 ADR-0008의 전제(단일 self-signed root)와 실제로는 반대 방향으로, 발급 권한을 여러 장비에 복제하는 결과를 낳는다. `docs/design/threat-model.md` §7 h3와 §8 "CA 키 복제 관행"이 이 상태를 잔여 위험으로 적어 두었다.

CSR(Certificate Signing Request) 흐름은 이 문제의 통상적 해법이다. 서명 대상 장비는 자기 개인키를 밖으로 내보내지 않고 공개키와 SAN만 담은 요청을 만들어 CA 보유 장비에 전달하고, CA 보유 장비만 `ca.key`를 쥔 채 서명해 돌려준다. 이 ADR은 그 흐름을 qsh에 들일지, 들인다면 어떤 모양일지를 정한다.

결정에 앞서 확인한 현재 트리의 사실은 다음과 같다.

- 검증 쪽은 손댈 것이 없다. `QshPeerVerifier::verify_core`(`crates/qsh-transport/src/tls.rs`)는 `TrustEvaluator::ca_roots()`가 돌려준 모든 루트로 webpki 체인 검증을 하고, `principal_from_san`이 leaf의 `qsh://device/<seg>`에서 principal을 낸다. `docs/design/protocol.md` §16.2가 동결한 검증 코어(pin → CA → 거부)는 "누가 서명했는가"를 묻지 않으므로, 다른 장비의 CA가 서명한 leaf도 로컬 `cert issue`가 만든 leaf와 같은 경로를 탄다.
- 발급 쪽 부품도 대부분 있다. `ca::issue_device_leaf`는 주어진 공개키 대신 장비 자신의 PKCS#8 키를 받지만 실제로 쓰는 것은 그 공개키와 `device_id`뿐이다. `identity::promote_to_ca_issued`는 `device.pem`과 `identity.toml`의 `issued_by_ca`를 교체하는 함수이고 키를 건드리지 않는다.
- 모든 qsh CA 루트는 같은 subject DN(`CN=qsh private CA`, `ca::ca_issuer_params`)을 쓴다. 장비마다 `cert init`을 하면 subject가 같은 루트가 여럿 생긴다. 한 장비가 그런 루트 둘 이상을 `[[ca]]`에 등재했을 때의 체인 검증은 지금 어떤 테스트도 고정하지 않는다.
- qsh가 만드는 device 키는 Ed25519 하나다(`qsh init`의 생성 경로, ADR-0026 결정 8의 가져오기 경로 모두).
- 파일 교환 관례는 ADR-0013이 고정했다. 입력은 `--cert-file <pem|->`(`-`는 표준입력), 출력은 `--out <path>`가 없으면 표준출력, `--json`/`--jsonl`에서는 PEM을 envelope 필드로 나르고 `--out`이면 경로만 남긴다. 이 경로의 신뢰 근거는 qsh가 아니라 전달 채널의 인증이다(ADR-0013 결정 6).

## 결정

**CSR 흐름을 들인다. 파일 교환만 쓰고 네트워크 경로는 열지 않는다. 요청 생성과 서명본 설치는 `qsh identity`에, 서명은 `qsh cert`에 둔다. 서명 장비는 CSR에서 공개키와 `device_id` 둘만 꺼내 leaf를 처음부터 다시 만든다. user cert 발급은 이 ADR에서 다루지 않는다.**

1. **명령 배치.** 세 op을 신설한다. 요청은 신원의 일이고 서명은 CA의 일이라는 구분을 그룹 이름으로 드러낸다.
   - `qsh identity request [--out <path>]` (op `identity.request`). 이 장비의 기존 키로 서명한 PKCS#10 CSR PEM(`CERTIFICATE REQUEST` 블록 하나)을 낸다. CSR에는 `qsh://device/<device_id>` URI SAN 하나만 담는다. 키 서명이 필요하므로 `identity export`와 달리 `KeyStore`를 연다. 개인키는 인자로도 출력으로도 나가지 않는다(ADR-0013 결과 절의 계약). identity가 없으면 `CONFIG_ERROR`("no local identity; run `qsh init` first")다.
   - `qsh cert sign --csr-file <pem|-> [--out <path>]` (op `cert.sign`). 이 장비의 로컬 CA(`config_dir/ca/`)로 CSR을 검증하고 서명해 device leaf PEM 하나를 낸다. CA가 없으면 `cert issue`와 같은 `CONFIG_ERROR`("no local CA; run `qsh cert init` first")다.
   - `qsh identity install --cert-file <pem|->` (op `identity.install`). 다른 장비가 서명한 leaf를 이 장비의 `identity/device.pem`으로 설치한다. 검증 규칙은 결정 7이 정한다.

   `qsh cert issue`는 그대로 둔다. 같은 장비 안에서 request → sign → install을 한 번에 하는 지름길이라는 뜻이 명확해질 뿐 동작은 바뀌지 않는다.

2. **파일 교환으로 한정한다.** 세 op 모두 로컬 op이고 wire 메시지·capability·ACL action을 새로 만들지 않는다. 입출력은 ADR-0013 관례를 그대로 물려받는다. `-`는 표준입력이고, `--out`이 없으면 표준출력이며, `--out`이 기존 파일과 겹치면 덮지 않고 거부한다. `--json`/`--jsonl`에서는 PEM을 stdout 원문으로 내지 않고 `data`의 필드(`csr_pem`/`cert_pem`)로 싣는다. `--out`이면 두 모드 모두 경로만 남는다. 입력 크기 상한은 `trust add --cert-file`의 `CERT_PEM_MAX`를 같이 쓴다. 문서에 싣는 기본 관용구는 human 모드 한 줄이다.

   ```bash
   qsh identity request | ssh ca-box 'qsh cert sign --csr-file -' | qsh identity install --cert-file -
   ```

   이 파이프의 신뢰 근거는 ADR-0013 결정 6과 같이 ssh 쪽(known_hosts)에서 온다. ADR-0008 결정 5가 P1로 남긴 원격 프로비저닝(headless provisioning)은 이 결정으로 닫는다. 프로비저닝 스크립트는 대상 장비에서 `qsh init`과 `qsh identity request`를 돌리고, 인증된 채널로 CSR을 CA 장비에 옮겨 서명받아 돌려준다. CA 장비가 남의 키를 만들어 주는 경로와 `--device-id` 같은 임의 id 인자는 만들지 않는다(대안 절).

3. **`device_id`는 CSR이 자칭하고 서명 장비는 모양과 충돌만 검사한다.** ADR-0008 결정 2의 선례대로 SAN 본문은 요청 장비 자신의 `device_id`다. 서명 장비는 다음을 전부 통과한 CSR만 서명하고, 하나라도 어긋나면 `INVALID_ARGUMENT`로 거부한다. 거부 사유는 `details.reason`에 싣고 오류 문면과 audit 어디에도 입력 바이트를 되비추지 않는다.
   - (a) PEM 블록이 `CERTIFICATE REQUEST` 정확히 하나다. 다른 라벨 블록, 특히 `PRIVATE KEY`가 섞이면 거부한다(ADR-0013 결정 4와 같은 규율).
   - (b) CSR 자기서명이 검증된다(키 보유 증명).
   - (c) 공개키가 Ed25519다. 그 밖의 알고리즘은 `UNSUPPORTED`다. qsh가 만드는 키가 Ed25519뿐이라 받는 모양을 좁혀도 잃는 것이 없다.
   - (d) SAN이 URI 하나이고 그 값이 `qsh://device/<device_id>`이며 `<device_id>`가 qsh가 만드는 `device_<ULID>` 모양이다. `qsh://user/…`와 그 밖의 SAN은 거부한다(결정 4).
   - (e) `<device_id>`가 서명 장비 자신의 `device_id`와 같지 않다. 자기 자신은 `cert issue`로 발급한다.
   - (f) 발급 장부(아래)에 같은 `device_id`가 다른 SPKI fingerprint로 이미 있지 않다. 같은 `device_id`와 같은 SPKI면 재서명(갱신)이고 허용한다.

   서명 장비는 CSR의 subject DN, 요청 확장(basicConstraints, keyUsage, EKU 등), 속성을 하나도 복사하지 않는다. leaf는 공개키와 `device_id` 두 값만으로 `issue_device_leaf`와 같은 빌더에서 새로 만든다. subject `CN=<device_id>`, `IsCa::NoCa`, 유효기간 `LEAF_VALIDITY_DAYS`, 백데이트 `BACKDATE_MINUTES`가 로컬 발급과 같다. `issue_device_leaf`는 키 대신 공개키를 받는 내부 함수로 쪼개 두 경로가 그것을 공유한다.

   발급 장부는 `config_dir/ca/issued.toml`(0600)이다. 행마다 `device_id`, `fingerprint`(SPKI), `issued_at`, `not_after`를 담고, `cert sign`과 `cert issue`가 모두 `ca/.lock` 안에서 쓴다. 장부는 (f)의 충돌 검사와 운영자 열람용이다. revocation 목록이 아니고 handshake는 이 파일을 읽지 않는다. 이 ADR은 장부 행을 지우거나 고치는 명령을 만들지 않는다. 같은 `device_id`의 키 교체는 오늘 qsh에 경로가 없고(`device_id`는 `qsh init`이 키와 함께 만든다) 생기면 ADR-0031의 소관이다.

   `device_id` 위조, 곧 요청 장비가 남의 `device_id`를 자칭하는 것을 막는 근거는 셋이다. (e)·(f)가 서명 장비가 이미 아는 id를 가로채지 못하게 하고, 서명 장비는 결과에 `device_id`와 SPKI fingerprint를 내서 운영자가 요청 장비의 `qsh init`/`identity export` 출력과 대조할 수 있게 하며, 나머지는 전달 채널의 인증에 맡긴다(결정 2). 서명 장비가 처음 보는 id를 자칭하는 요청을 "진짜인가"로 판정할 근거는 qsh 안에 없고, 이 사실을 `docs/CLI.md`와 threat-model에 운영자 확인 의무로 적는다(결과 절).

4. **user cert 발급은 이 ADR에서 다루지 않고 별도 ADR로 남긴다.** M16 범위에도 넣지 않는다. 이유는 둘이다. ADR-0008 결정 3이 미룬 사유("누가 이 이름인가"라는 정책 결정과 다중 device 매핑)는 CSR이 생겨도 그대로다. 그리고 user leaf는 같은 장비가 device leaf와 함께 두 번째 leaf를 갖고 handshake마다 어느 쪽을 낼지 고르는 문제를 만든다. 이는 `identity/device.pem` 단일 leaf 불변식과 TLS 클라이언트 인증서 선택을 바꾸는 일이라 이 ADR의 파일 교환 범위를 넘는다. 결정 3 (d)가 `qsh://user/` SAN을 명시적으로 거부하므로, 나중에 user 발급 ADR이 서면 `cert sign`에 additive 플래그나 새 op을 얹는 방식이 된다. 그 ADR의 번호는 지금 배정하지 않는다. `qsh://user/<name>` → `Principal::User` 검증 경로는 지금처럼 유지한다.

5. **CA 키 복제는 채택과 동시에 비권장으로 문서화한다.** 기술적으로 막지는 않는다. 파일 복사는 qsh가 관측할 수 없고 막을 자리도 없다. `docs/CLI.md` §6.16과 README는 "`ca.key`는 한 장비에만 두고 다른 장비는 `identity request` → `cert sign` → `identity install`로 발급받는다"를 권장 경로로 적는다. threat-model §7 h3는 "CSR 경로가 있고 복제는 비권장 운영 관행"으로 바꾸고 §8의 "CA 키 복제 관행" 문단도 그에 맞게 고친다. 이미 복제해 둔 배치를 위한 이행 명령은 만들지 않는다. 복제본 `ca/` 디렉터리를 지우면 그 장비는 CA 보유 장비가 아니게 되고, 이미 발급된 leaf는 루트가 같으므로 계속 유효하다.

6. **기존 계약은 그대로이고 신규 op 셋이 additive하게 얹힌다.** `cert.init`·`cert.issue`·`identity.export`·`trust.add_ca`의 플래그, `data` 모양, 실패 모드는 바뀌지 않는다. `cert.issue`가 결정 3의 장부에 행을 쓰는 것은 로컬 파일 부작용이고 envelope은 같다. 세 op의 `data`는 다음 필드를 갖는다.
   - `identity.request`: `device_id`, `fingerprint`(SPKI), 그리고 `csr_pem`(stdout일 때) 또는 `path`(`--out`일 때).
   - `cert.sign`: `device_id`, `principal`(`device:<device_id>`), `fingerprint`(서명한 leaf의 SPKI), `not_after`, `renewed`(장부에 같은 id·같은 SPKI가 이미 있었으면 `true`), `ca`(`{ "fingerprint" }`. 루트 PEM은 싣지 않는다, 결정 7), 그리고 `cert_pem` 또는 `path`.
   - `identity.install`: `device_id`, `fingerprint`, `issued_by_ca`(체인이 닿은 `[[ca]]` 루트의 SPKI fingerprint), `ca_name`(그 루트의 `[[ca]]` 라벨), `installed`(설치된 `device.pem`과 바이트가 같으면 `false`인 멱등 축).

   세 op은 `docs/CLI.md` §2.5의 "인가 불요" 행에 들어간다. 원격 peer가 요청할 수 없고 wire 메시지가 없다.

7. **CA 루트는 계속 `trust add-ca`로 따로 등재하고, 설치는 등재된 루트로 검증한다.** `cert sign`은 leaf 하나만 낸다. 루트를 서명본에 붙여 보내지 않는다. ADR-0013 대안 절이 leaf와 루트를 한 출력에 섞는 안을 이미 기각했고, 루트 등재는 장비당 CA당 한 번인 반면 leaf는 갱신마다 오가므로 둘의 수명이 다르다. `cert.sign`의 `data.ca.fingerprint`는 요청 장비 운영자가 자기 `[[ca]]`와 대조하는 용도다.

   `identity install`은 다음을 전부 통과한 leaf만 설치하고, 어긋나면 `INVALID_ARGUMENT`(`details.reason` 포함)로 거부하며 아무것도 쓰지 않는다.
   - (a) PEM 블록이 `CERTIFICATE` 정확히 하나이고 다른 라벨 블록이 없다(ADR-0013 결정 4).
   - (b) leaf의 SPKI가 이 장비 identity의 SPKI와 같다. 남의 leaf나 다른 키로 만든 leaf는 설치되지 않는다.
   - (c) SAN이 `qsh://device/<이 장비의 device_id>` 하나다.
   - (d) CA 인증서가 아니다(`basicConstraints` CA가 아님).
   - (e) 지금 유효하다. `trust add --cert-file`은 유효기간을 보지 않지만(ADR-0013 결정 4) 설치는 다르다. 만료된 leaf를 설치하면 이 장비의 모든 handshake가 죽는다.
   - (f) 이 장비 `trust.toml`의 `[[ca]]` 루트 중 하나로 webpki 체인 검증이 server·client 두 용도 모두 성공한다. 성공한 루트의 fingerprint가 `issued_by_ca`가 된다. 맞는 루트가 없으면 거부하고 remedy는 "`qsh trust add-ca <name> --cert-file <root.pem>`를 먼저"다.

   (f) 때문에 설치 순서는 `trust add-ca` → `identity install`로 고정된다. 이 순서는 설치하는 장비가 같은 CA가 발급한 다른 peer도 transport 수준에서 신뢰하게 만들지만, 그 peer가 실제로 얻는 것은 `acl.toml`의 `auth_path = "ca"` 행뿐이다(default-deny). 루트 교체는 ADR-0013 결정 5의 거부 규칙을 그대로 따른다. 같은 라벨에 다른 PEM은 `INVALID_ARGUMENT`이고, 교체하려면 `trust remove` 뒤 `trust add-ca`다. CSR 흐름에는 그 규칙을 우회하는 경로가 없다.

   설치는 `identity::promote_to_ca_issued`를 재사용해 `device.pem`과 `identity.toml`을 교체한다. 키와 `device_id`는 그대로이므로 이 장비를 SPKI로 pin한 peer의 pin은 깨지지 않는다(`docs/CLI.md` §6.16의 `cert issue` 문단과 같은 근거). 이미 떠 있는 `serve`/`listen`/`serve --to`가 새 leaf를 내는 시점은 `cert issue`와 같다. human 출력은 그 사실을 한 줄로 알린다.

8. **doctor 코드는 늘리지 않고, principal 고지는 `cert sign`의 출력에 싣는다.** `acl_ca_auth_path_missing`(ADR-0017 결정 2)의 파일 전체 수준 검사는 그대로 둔다. leaf 단위 진단은 만들지 않는다. host는 어떤 leaf가 발급됐는지 알 길이 없고(장부는 CA 장비에만 있다), CA 경로 principal은 handshake 전에는 열거할 수 없다는 ADR-0017 결정 2의 이유가 여기에도 적용된다. 발급된 leaf의 만료는 그 leaf를 쓰는 장비에서 기존 `cert_expired`/`cert_expiring_soon`이 이미 본다. 두 진단은 `device.pem`을 읽을 뿐 발급자를 가리지 않는다. `EXPECTED_DOCTOR_CODES`는 24종 그대로다.

   ROADMAP M16 DoD의 "페어링 직후 pin 이름·매칭 규칙 고지"(ADR-0017 결정 3의 문구 규율)는 이 경로에서 `cert sign`이 맡는다. human 모드는 stderr에 "이 leaf는 `device:<device_id>`로 인증되고, 이를 허용하는 `[[acl]]` 행은 `auth_path = \"ca\"`를 적어야 한다"를 한 줄로 낸다. `--json`/`--jsonl`에서는 같은 정보가 `data.principal`로 간다. `identity install`의 human 출력도 같은 principal 문자열을 적는다. 예시 행은 `acl/load.rs`의 `minimal_policy_example`을 재사용한다.

## 근거

- **파일 교환이 필요를 충족하고 네트워크 경로는 그 위에 얹을 것이 없다.** 문제는 "`ca.key`를 여러 장비에 두지 않고 여러 장비를 서명한다"이고, 이는 CSR과 leaf가 한 번씩 오가면 풀린다. 네트워크 경로를 열면 세 가지가 새로 생긴다. 서명 op을 원격에서 받는 wire 메시지와 그 ACL action, 그 op을 받기 위해 `ca.key`를 메모리에 쥔 상시 프로세스(온라인 CA), 그리고 첫 신뢰가 없는 장비가 서명을 받으려면 먼저 연결을 인증해야 하는 닭과 달걀 문제다. 마지막 것은 결국 pin이나 pairing을 먼저 하라는 뜻이고, 그러면 이미 파일 하나를 옮길 수 있는 채널이 있다. 온라인 CA는 CA 키의 노출을 지금(명령 실행 순간에만 디스크에서 읽힘)보다 넓힌다.
- **ADR-0013 관례를 그대로 쓰면 새 계약 규칙이 0개다.** `--cert-file`/`--out`/`-`/envelope 필드/덮어쓰기 거부/PEM 블록 규율이 이미 테스트로 고정돼 있어 세 op은 그 틀을 채우는 일이 된다.
- **leaf를 처음부터 다시 만드는 것이 CSR 서명의 고전적 함정을 닫는다.** CSR이 요청한 확장을 복사하면 `basicConstraints CA=true`를 요청한 장비가 하위 CA가 된다. 단일 루트 1-hop 구조(ADR-0008 결정 1)에서 이는 곧 무제한 발급 권한이다. 서명 장비가 공개키와 `device_id`만 쓰면 이 부류 전체가 구조적으로 사라지고, 산출 leaf가 로컬 `cert issue` 결과와 같은 모양이라 검증 코어도 §16.2도 움직이지 않는다.
- **PKCS#10을 쓰는 이유.** self-signed device leaf(`identity export` 출력)를 요청으로 쓰면 신규 형식이 없어 보이지만, CA 서명본으로 승격된 뒤에는 그 leaf의 서명이 CA의 것이라 키 보유 증명이 안 된다. 갱신이나 다른 CA로의 재발급이 불가능해진다. PKCS#10은 매번 장비 키로 서명되고 `openssl req -text`로 사람이 들여다볼 수 있으며, rcgen이 생성(`serialize_request`)과 파싱을 이미 제공한다.
- **설치 시 `[[ca]]`로 검증하는 이유.** 등재되지 않은 루트로 설치를 허용하면 `issued_by_ca`에 적을 값이 없고, 만료·키 불일치·엉뚱한 SAN을 handshake 실패가 나서야 알게 된다. 검증을 설치 시점으로 당기면 실패가 명령의 `INVALID_ARGUMENT`로 드러난다. 같은 이유로 ADR-0013 결정 5가 `trust add-ca`의 구조 검증을 등재 시점으로 당겼다.
- **장부를 두는 이유.** 결정 3 (f)가 없으면 처음 서명한 장비의 `device_id`를 나중 요청이 다른 키로 가로챌 수 있고, 그 id를 겨눈 `[[acl]]` 행(`auth_path = "ca"`)이 그대로 새 키에 열린다. 장부는 이 한 부류를 운영자 주의 없이 막는 가장 작은 상태다. revocation 의미를 붙이지 않은 것은 ADR-0031이 아직 서지 않았기 때문이다.
- **user cert를 미루는 이유.** 결정 4의 두 이유는 CSR 흐름과 독립이다. CSR이 해결하는 것은 발급 권한의 분산이지 "어느 이름이 누구인가"나 "한 장비가 leaf를 몇 개 갖는가"가 아니다.

## 대안과 기각 사유

- **현행 유지**(로컬 발급만, CA 키 복제로 다중 장비 서명). 기각. h3가 그대로 남고, threat-model §7 h3·h24와 §8이 같은 뿌리로 묶은 "CA를 등재하는 순간 그 키가 곧 발급 권한"이라는 위험이 장비 수만큼 늘어난다. 구현 비용(결과 절, 1.3~1.7ew)이 작아 남겨 둘 이유가 약하다.
- **네트워크 서명 op**(`cert.sign`을 wire에 올려 CA 장비의 `serve`가 받는다). 기각. 근거 절 첫 항목의 세 가지가 새로 생기고, 그 대가로 얻는 것은 파일 한 번 옮기는 수고뿐이다. 필요가 관측되면 이 ADR의 `cert.sign` 검증 함수를 그대로 쓰는 새 ADR로 연다.
- **CA 장비가 대상 장비의 키까지 만들어 주는 원격 발급**(`qsh cert issue --device-id <id>`가 키와 leaf를 함께 낸다). 기각. 개인키가 장비 밖에서 만들어져 전달 채널을 건넌다. "개인키는 어느 명령의 인자로도 출력으로도 나가지 않는다"(ADR-0013 결과 절)를 깨는 유일한 명령이 된다.
- **CA 위임 키**(임시 하위 CA나 위임 키를 배포). 기각. 원래 예약본이 적은 대로 위임 키의 수명과 철회를 새로 설계해야 하고, intermediate는 ADR-0008 대안 절이 rotation과 함께 묶어 미뤘다.
- **`cert issue`에 CSR 출력·입력 모드를 더하는 안**(`cert issue --csr-out`, `cert issue --csr-file`). 기각. `cert issue`는 "이 장비를 이 장비의 CA로"라는 한 문장 명령이다. 요청 장비에는 CA가 없는데 `qsh cert` 아래 명령을 부르게 되면 "이 장비가 서명할 수 있는가"와 "이 장비가 누구인가"를 갈라 둔 ADR-0008 결정 4의 디렉터리 분리가 표면에서 흐려진다.
- **`cert sign`이 루트를 함께 내고 `identity install`이 그 루트를 자동 등재.** 기각. 결정 7의 수명 차이에 더해, 설치가 루트를 자동 등재하면 `trust add-ca`의 운영자 확인 지점(threat-model A13, h24)이 우회된다.
- **서명 시 `--expect-fingerprint <fp>`로 요청 SPKI를 대조.** 지금은 넣지 않는다. 전달 채널이 인증돼 있으면 중복이고, 인증되지 않은 채널을 이 플래그로 보완하라는 신호가 될 수 있다. 결과 `data.fingerprint`로 사후 대조가 이미 가능하다. 필요해지면 additive 플래그로 붙인다.
- **CSR 파서를 별도 fuzz 타깃으로 세우는 안.** 지금은 넣지 않는다. 입력은 인증된 채널로 운영자가 옮긴 로컬 파일이고, 파서 본체(x509-parser)는 이미 원격 peer의 인증서라는 더 적대적인 입력을 매 handshake마다 받는다. 결정 3의 검증 함수는 단위 테스트의 거부 행렬로 고정한다.

## 결과

**구현 범위.**

- `qsh-core`의 `ca` 모듈: `issue_device_leaf`를 공개키 입력 빌더로 쪼갠다. `validate_csr`(결정 3 (a)~(e))와 장부 읽기·쓰기(`ca/issued.toml`, `ca/.lock`)를 더한다. `cert issue`도 장부에 쓴다.
- `qsh-core`의 `identity` 모듈: CSR 생성(`KeyStore`로 서명), 설치 검증(결정 7 (a)~(f))과 `promote_to_ca_issued` 재사용.
- `qsh-core`의 `ops`: `identity.request`·`cert.sign`·`identity.install` 세 `Operation`. `qsh-cli`는 clap과 렌더러만 맡는다.
- 의존성: CSR 파싱에 rcgen의 `x509-parser` feature를 켠다. 워크스페이스의 `x509-parser`(0.18, `qsh-transport`가 이미 씀)와 버전이 맞는지 `cargo deny check`로 확인하고, 맞지 않으면 `qsh-core`가 `x509-parser`를 직접 써서 파싱·서명 검증을 한다. `xtask arch` 규칙에는 걸리지 않는다.

**고정할 테스트.**

- 왕복: 장비 B `identity request` → 장비 A `cert sign` → B `trust add-ca` + `identity install` → 루트를 등재한 제3 장비 C와의 실 QUIC handshake에서 B가 server·client 어느 쪽이어도 `Principal::Device(<B의 device_id>)` + `AuthPath::Ca`. B를 SPKI로 pin해 둔 peer는 설치 뒤에도 `AuthPath::Pin`(ADR-0008 결정 6). `crates/qsh-cli/tests/cert_e2e.rs`의 선례를 잇는다.
- `crates/qsh-transport/tests/handshake_matrix.rs` 새 행 둘: subject DN이 같은 두 루트를 함께 등재했을 때 둘째 루트가 서명한 leaf가 통과한다. 등재되지 않은 루트가 서명한 leaf는 거부된다(ROADMAP M16 DoD의 handshake matrix 행).
- `cert sign` 거부 행렬: 위조 서명, Ed25519가 아닌 키(`UNSUPPORTED`), SAN 없음·둘·`qsh://user/`·qsh 밖 URI, `device_<ULID>` 모양 위반, 서명 장비 자신의 `device_id`, 장부 충돌(같은 id·다른 SPKI), `PRIVATE KEY` 블록 혼입과 다중 블록. 거부 문면에 입력 바이트가 없음을 단언한다.
- `cert sign`은 CSR이 `basicConstraints CA=true`, keyUsage `keyCertSign`, 임의 subject를 요청해도 결과 leaf가 `IsCa::NoCa`이고 subject가 `CN=<device_id>`다(threat-model 새 A 행의 핀).
- 장부: 같은 id·같은 SPKI의 재서명은 `renewed: true`. 동시 `cert sign` 두 개가 장부를 잃지 않는다(`ca/.lock`).
- `identity install` 거부 행렬: 다른 SPKI, 다른 `device_id`, CA 인증서, 만료·미래 `not_before`, `[[ca]]`에 없는 발급자. 거부 시 `device.pem`·`identity.toml`의 바이트가 그대로다. 같은 leaf 재설치는 `installed: false`.
- `identity request`: 출력에 `PRIVATE KEY`가 없다. `--json`에서 stdout이 순수 JSON 한 줄이고 CSR은 `data.csr_pem`에만 있다. `--out`이 기존 파일을 덮지 않는다. `ca/`가 없는 장비에서 동작한다.
- `cert sign` human 모드의 principal·`auth_path = "ca"` 고지 문면 축자 테스트(결정 8).

**threat-model 반영.**

- §3 진입점에 세 행: `qsh identity request`(로컬 사용자 → stdout/파일, `KeyStore`를 열지만 키는 나가지 않음), `qsh cert sign --csr-file <pem|->`(로컬 파일 또는 stdin, 서명 장비의 `ca.key`를 읽는 두 번째 명령), `qsh identity install --cert-file <pem|->`(로컬 파일 또는 stdin, 이 장비가 내는 leaf를 교체).
- §4 A 표에 두 행. 하나는 "CSR이 남의 `device_id`를 자칭"으로, 통제는 결정 3 (e)·(f)와 결과 `device_id`·fingerprint 출력, 잔여는 처음 보는 id에 대한 운영자 확인 의무다. 다른 하나는 "CSR이 CA 권한이나 임의 확장을 요청"으로, 통제는 leaf 재구성(결정 3)이고 핀은 위 `IsCa::NoCa` 테스트다.
- §7 h3를 결정 5대로 고치고, h24 문면의 "h3(CA 키 복제)"를 갱신한다. §8 "CA 키 복제 관행" 문단을 비권장 관행으로 고친다. 처음 보는 `device_id`의 진위를 qsh가 판정하지 못한다는 잔여를 새 h 행으로 더한다.

**계약 영향.**

- `qsh.cli/v1`는 additive만 일어난다. 신규 op 셋, 각각 `qsh-proto::types`의 schemars 타입, `cli_v1_data_schema` arm, `CLI_V1_SCHEMA_COMMANDS` 등재, 렌더러 두 벌, `crates/qsh-cli/tests/fixtures/cli-v1/`의 새 fixture(`identity.request.json`, `cert.sign.json`, `identity.install.json`)와 `REQUIRED_FIXTURES` 등재가 필요하다. 거부 사유는 기존 `INVALID_ARGUMENT`·`UNSUPPORTED`·`CONFIG_ERROR`에 `details.reason`을 더할 뿐이고 새 `ErrorCode`는 없다. 기존 fixture는 건드리지 않는다.
- wire(`qsh.wire.v1`), capability 집합(`capabilities.json` golden), `docs/design/protocol.md` §16.2 검증 코어, `acl.toml` 어휘, doctor 코드 집합은 바뀌지 않는다.
- 문서: `docs/CLI.md` §6.16에 세 명령과 권장 경로를 싣는다. 같은 절의 "partner의 CA root를 신뢰하려면" 문단은 `trust add-ca`(ADR-0013 결정 5)가 생기기 전 서술이라 이번에 함께 고친다. §6.11에 `identity request`·`identity install`, §2.5 "인가 불요" 행에 세 op을 더한다. `docs/PRD.md` §11 명령 표, README의 CA 관련 서술, `docs/man/`(`qsh-identity-request.1`, `qsh-identity-install.1`, `qsh-cert-sign.1`, `cargo xtask man`으로 재생성)이 따라 움직인다. ADR-0008 결정 5와 결정 3의 "P1" 문구는 각각 이 ADR 결정 2와 결정 4를 가리키도록 포인터를 단다.

**크기 추정.** 약 1.3~1.7ew(1인 기준). `ca` 빌더 분리·CSR 검증·장부 0.5~0.6, `identity request`·`install` 0.3~0.4, op·schema·렌더러·fixture·man 0.2~0.3, handshake matrix 두 행과 e2e 왕복 0.2, `docs/CLI.md`·threat-model·README 0.1~0.2. ROADMAP M16의 (c) 결정 절 작성 0.3은 이 초안으로 소진된다.
