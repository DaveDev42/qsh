# ADR-0017: `acl.toml`은 어떤 명령도 쓰지 않고 부담은 doctor 진단과 페어링 직후 고지로 옮긴다

날짜: 2026-09-09
상태: 승인됨

## 맥락

`acl.toml`은 `crates/qsh-core/src/acl/load.rs`의 `PolicySource::load`가 `<config_dir>/acl.toml`에서 읽는 사람 손으로 쓰는 파일이고, 프로세스 시작 시 1회만 로드된다("process-start-once by design", `acl/load.rs`). 이 파일을 만드는 프로덕션 코드 경로는 없다. `acl_file()`에 쓰는 지점은 테스트뿐이고, `ACL_STARTUP_NO_AUTOGEN` 상수 자체가 "acl.toml is never auto-generated — create it by hand"라고 못박는다. 파일이 없으면 `PolicyLoad::Missing`이 되고, 이 상태를 파일로 영구화하지 않는다는 것은 `docs/design/architecture.md` §6("acl.toml이 없거나 파싱 불가 → 전부 deny")과 `acl/load.rs` 모듈 문서("absent `acl.toml` … means nobody has been granted anything yet")가 이미 정한 바다.

규칙 한 행(`[[acl]]`)은 `Rule::principal`을 `Principal`의 렌더 문자열과 정확히 매치한다. 모양은 `device:<name>` | `user:<name>` | `fp:sha256:<base64>` 셋이고, `Principal::Pairing`은 애초에 ACL 평가에 닿지 않는다(`crates/qsh-transport/src/identity.rs`). `auth_path`를 생략하면 `AuthPath::Pin` 기본값이 매겨져 CA로만 인증한 peer는 조용히 매칭에서 빠진다(`crates/qsh-core/src/acl/policy.rs`, `docs/CLI.md` §6.16). 사람 표면 설계가 새로 들이는 명령들, `identity export`, `trust add --cert-file`, `trust add-ca`, `pair invite|accept --as`, `trust rename`, `service install`은 모두 이 파일의 바깥에 있다. 지금 조사 범위에서 이 파일에 쓰기를 시도하는 명령은 하나도 없다.

이 설계가 새로 만드는 마찰은 두 갈래다. 하나는, 페어링이 상대를 pin해도 `acl.toml`에는 그 이름을 언급하는 행이 아직 없어서 페어링 성공 순간에도 그 상대가 아무 action도 얻지 못하고 조용히 default-deny에 머무는 문제다. 다른 하나는 `[[ca]]`를 등록해 두고도 해당 principal 행에 `auth_path = "ca"`를 명시하지 않아 CA 인증 경로 전체가 조용히 막히는 실수다. 두 경우 모두 파일이 틀린 것도 파싱이 실패하는 것도 아니라서 `acl_policy_invalid`가 잡지 못하고, 원격 peer에게는 그저 `PERMISSION_DENIED`로만 보인다.

pin 경로에는 방향 입력이 없다. `crates/qsh-transport/src/tls.rs`의 `QshPeerVerifier`는 `ServerCertVerifier`와 `ClientCertVerifier`를 둘 다 구현하면서 같은 `TrustEvaluator::lookup_pin`을 호출한다. `verify_core`가 받는 `PeerRole`(`Server`/`Client`)은 CA 경로의 `KeyUsage` 선택에만 쓰이고 `lookup_pin`에는 넘어가지 않는다. 즉 `trust.toml`에 등록된 pin 하나는 이 장비가 그 상대에게 나갈 때(outbound dial)와 그 상대가 이 장비로 들어올 때(inbound accept) 양쪽에 동일하게 적용된다. 이 사실이 TOFU를 지금 들이지 못하는 이유다.

## 결정

1. 이번 사람용 표면에서 신설하는 어떤 명령도 `acl.toml`을 쓰지 않는다. `identity export`, `trust add --cert-file`, `trust add-ca`, `pair invite|accept --as`, `trust rename`, `service install` 전부 해당한다. `PolicySource::load`의 process-start-once 동작과 자동 생성 금지는 그대로 유지하고 이 ADR로 재확인만 한다. 다시 열자는 제안이 아니다.

2. doctor 진단 두 종을 신설한다.
   - `acl_principal_unmatched`: 이 장비에 `acl.toml`이 있을 때(`docs/design/architecture.md` §7의 "acl.toml # serve/listen 역할만 읽음"), `trust.toml`에 pin된 peer마다 `device:<name>` 형식의 principal 문자열과 그 peer의 fingerprint에 해당하는 `fp:sha256:<base64>` 형식을 둘 다 후보로 삼고, `auth_path`가 `"pin"`인(생략 시 기본값도 포함) `acl.toml` 행에 한해 매칭으로 센다. 어느 후보도 그런 행을 찾지 못한 peer만 finding이 된다. 파일이 없거나 파싱에 실패한 경우(`acl_policy_missing`/`acl_policy_invalid`)와는 다른 원인이므로 별개 code로 둔다.
   - `acl_ca_auth_path_missing`: `trust.toml`에 `[[ca]]` 항목이 하나 이상 있는데 `acl.toml`의 어느 행에도 `auth_path = "ca"`가 없는 경우. CA로 인증한 principal도 `device:<id>` 모양이라 발급 가능한 이름을 미리 열거할 수 없으므로(`docs/CLI.md` §6.16 끝 문단, 구별 근거는 audit의 `auth_path`뿐), 이 code는 peer 단위가 아니라 파일 전체 수준의 거친 검사로 둔다.

   두 code 모두 예시 행은 `acl/load.rs`의 `minimal_policy_example`을 재사용한다. 다만 그 함수의 `EXAMPLE_ALLOW` 상수는 `exec.run`/`session.open`/`session.list`/`session.attach`/`session.control` 다섯뿐이고 `host.reverse`가 없어서, 결정 3이 요구하는 `listen` 역할 예시를 만들려면 역할별 allow 목록을 받도록 그 함수를 넓히는 작업이 구현 스텝에 들어간다. 새 표면이 같은 TOML을 다시 타이핑하면 저장소의 anti-drift 규율을 깬다.

   두 code 모두 `crates/qsh-core/src/doctor.rs`의 닫힌 `EXPECTED_DOCTOR_CODES`와 `docs/CLI.md` §6.17 표에 동시에 추가해야 잠금 어휘 규율(`crates/qsh-core/tests/doctor_docs.rs`)을 지킨다. 각 code의 `status`(warn/error/info)는 이 ADR이 정하지 않는다. 구현 스텝에서 정한다. 이 잠금 목록 갱신 자체는 구현 스텝의 일이고 이 ADR은 그 신설 대상 두 개만 정한다.

   운영자가 이 finding을 보고 `acl.toml`에 행을 추가해도, `qsh serve`/`qsh listen`은 프로세스 시작 시 1회만 정책을 읽으므로 재시작 전까지 그 행은 반영되지 않는다. 반면 `qsh acl check`는 호출마다 파일을 다시 읽으므로(`crates/qsh-core/src/ops/acl.rs`) 재시작하지 않은 상태에서도 allow로 보일 수 있다. 두 진단의 remedy 문면에는 "행을 추가한 뒤 `serve`/`listen`을 재시작해야 반영된다"를 반드시 넣는다.

3. 고지를 내는 것은 `qsh serve`(responder)다. `crates/qsh-core/src/server/mod.rs`의 `Server::serve_pairing_connection`이 `crate::pairing::respond`를 부르면서 넘기는 pin 콜백에서 `TrustStore::add_peer`로 상대를 pin하는데, 그 순간 같은 프로세스가 자기 stderr에 방금 pin한 이름과 그 이름을 언급하는 `[[acl]]` 행이 지금 있는지 여부를 적는다. `trust.accept`(향후 `pair accept`, ADR-0012 소관)는 가입하는 쪽(initiator)의 프로세스이고, 이 시나리오에서 host가 아니므로 고지 대상이 아니다.

   이 고지가 "그 이름이 곧 principal"이라고 말할 수 있으려면 pin 쪽이 이름을 정한다는 전제가 필요하다. DECISIONS Q3가 확정한 `pair invite|accept --as`(ADR-0012 소관)가 그 전제를 만드는 선행 조건이다. 그 선행 조건은 같은 마일스톤의 `--as` 스텝(설계 §7 S7)이 착지할 때 갖춰진다. 그 전 스텝 사이에는 responder가 상대의 자칭 `device_name`으로 그대로 pin하므로, 고지 문면도 그 사이에는 "이 이름은 상대가 자칭한 값이다"를 함께 적는다. `PairingError::PinCollision`(`crates/qsh-core/src/pairing.rs`)은 같은 이름이 이미 다른 fingerprint로 pin돼 있는 경우만 막으므로, 아직 아무도 pin하지 않았지만 `acl.toml`에는 이미 행이 있는 이름을 자칭한 peer는 이 가드에 걸리지 않고 그 행의 grant를 그대로 얻는다. 이 한계는 대안이나 결과 절이 아니라 이 결정 자체가 안고 가는 조건이다.

   매칭 규칙 부재는 예시 행으로 보여준다. 이 장비가 `qsh serve`로 쓰인다면 `session.open`/`exec.run` 계열이고, `qsh listen`으로 쓰인다면 `host.reverse`다(§2.5). 이 예시는 앞으로 이 장비가 어떤 역할을 맡을지 감지해서 고르는 것이 아니라 문면이 들 수 있는 두 대표 사례를 보여주는 것뿐이다. 이 고지는 로컬 콘솔 문자열이고 페어링의 JSON envelope(`trust.accept`/`pair.accept`의 `data`)에는 필드를 더하지 않는다.

   이 stderr 고지는 사람이 `serve`를 앞에서 띄웠을 때만 보이는 best-effort 채널이다. DECISIONS Q5가 확정한 `qsh service install` 경로로 상시 데몬으로 등록된 `serve`에서는 이 stderr가 launchd/systemd 로그로 가고 페어링을 실행한 사람의 터미널에는 뜨지 않는다. 그 형태에서는 결정 2의 `acl_principal_unmatched`가 유일한 내구 채널이다. 두 표면을 둘 다 두는 이유가 이것이다.

4. 원격 오류와 콘솔 진단을 분리한다. 실패 문면이 관측·영향·다음 명령을 갖는다는 일반 규칙에서 이 두 축은 예외로 남긴다. 원격으로 나가는 페어링 실패 문면(`PairingError::as_wire_error`가 `NoMatch → AUTH_FAILED`, `Expired → TRUST_REQUIRED`, `AlreadyConsumed`와 `PinCollision` 둘 다 `SESSION_CONFLICT`로 매핑하는 것 포함)과 `PERMISSION_DENIED`의 균일 문면(`crates/qsh-core/src/acl/mod.rs`의 `PERMISSION_DENIED_MESSAGE`, 어느 인가 지점에서 왔든 같은 문장)에는 원인을 앞세우는 처방을 얹지 않고 현행 그대로 둔다. 위 2, 3항이 신설하는 doctor 진단과 페어링 고지는 둘 다 로컬에서만 보이고 원격 wire 문면을 바꾸지 않는다. `doctor.run`은 애초에 `docs/CLI.md` §2.5·§6.17이 "로컬 operation, 원격 peer가 요청할 수 없다"고 계약으로 못박은 op이므로, 이 분리는 서술이 아니라 계약이다. 이 두 축(principal 매칭 여부, ACL 판정 자체)을 원격 응답에서 합치거나 구분해 노출하는 안, 그리고 이 두 축의 code 자체를 나누거나 합치는 안은 이 ADR의 범위 밖으로 명시해 둔다. 다음 라운드가 "원격 오류에 principal 불일치 사실을 얹어 진단을 돕자"거나 "구별 안 되는 code들을 정리하자"는 제안을 다시 꺼내지 못하게 하기 위해서다.

5. TOFU는 이번 표면에 넣지 않는다. `trust.toml`이 방향을 구분하지 않으므로, client 쪽에서 미지 peer를 자동 pin하면 그 pin은 같은 상대가 이 장비로 들어올 때의 inbound 인증도 그대로 통과시킨다. 이 인증 통과가 실제로 여는 것은 두 갈래다. 하나는 3항의 권한 상속과 같은 모양이다. TOFU가 정한 이름이 `acl.toml`에 이미 행을 가진 이름과 겹치면 그 행을 그대로 얻는다. 다른 하나는 인가 판정 이전에 성립하는 자원과 창이다. handshake, admission, quota 예약, 페어링 창 자체가 인증 통과만으로 열린다. 즉 default-deny는 폭발 반경을 줄이지만 없애지 않는다.

   이걸 막으려면 pin에 방향 축(`direction = "outbound"`, additive)이 먼저 있어야 하는데, 이 축을 넣을지와 그 위에서 TOFU를 다시 검토할지는 별도 ADR로 미룬다. 번호는 아직 배정하지 않는다. 같은 설계 배치가 listener 상대 페어링을 ADR-0015로, CSR 흐름을 ADR-0016으로 배정하므로 이 논의는 그 둘과 다른 자리다. 미지 peer를 dial했을 때 이 장비가 로컬에서 내는 현행 결과, `TRUST_REQUIRED` + `details.observed_fingerprint`(`crates/qsh-core/src/ops/mod.rs`)는 그대로 둔다.

## 결과

- doctor 진단 코드는 `acl_principal_unmatched`와 `acl_ca_auth_path_missing` 두 개가 늘어난다. 같은 설계 문서(§5)가 함께 나열한 나머지 넷, 서비스 미등록(info), systemd linger 미설정(warn), macOS LaunchAgent가 로그인 세션 안에서만 산다는 한계(warn), `bindv6only`는 `acl.toml`과 무관하고 이 ADR이 정하지 않는다. 같은 설계의 doctor 스텝과 `qsh service` 스텝 소관이다. 최종 code 총수는 그 넷이 같은 구현 스텝에 들어가는지에 달렸다.
- 새 code마다 다음이 같은 커밋에서 함께 움직여야 한다(`crates/qsh-core/tests/doctor_docs.rs`).
  - `crates/qsh-core/src/doctor.rs`의 `DiagnosticId` variant 2개, 대응하는 `Diagnostic` 상수(`code`/`message`/`remedy`), 모듈 문서의 "N variants, one per `docs/CLI.md` §6.17 finding code" 산문.
  - `crates/qsh-core/src/ops/doctor.rs`의 검출기. 결정 2가 정의한 매칭 로직을 실제로 도는 자리다.
  - `docs/CLI.md` §6.17 표에 새 code를 이름으로 추가(`cli_md_names_every_frozen_doctor_code`가 표가 모든 동결 code를 담는지 강제한다).
  - `docs/CLI.md` §6.11(현재 L752 "진단 코드 14종")과 §6.17(현재 L1038 "14종 진단 코드") 두 곳의 산문 숫자를 `EXPECTED_DOCTOR_CODES.len()`과 같게 갱신(`doctor_code_counts_named_in_prose`/`cli_md_prose_doctor_code_count_matches_expected_len`). 표만 고치면 이 테스트가 붉어진다.
- 바뀌지 않는 것: `qsh-cli`의 `render::human::print_doctor`는 순수 렌더러라 변경이 없다. `crates/qsh-cli/tests/fixtures/cli-v1/`에는 `doctor.run` 픽스처가 없어 append-only 규칙에 걸리는 항목이 없다. `docs/PRD.md`와 `README.md`가 축자 인용하는 것은 `CONTROLLER_UNREACHABLE`뿐이라 이 두 code와 무관하다.
- 페어링 고지 문면은 `docs/CLI.md` §6.11과 §6.13(역할별 예시 행)에 반영이 필요하다.
- `docs/adr/README.md`의 색인 표에 0017 행을 추가한다.
- `qsh.cli/v1` envelope과 wire 프로토콜에는 아무 변화가 없다. 새 doctor code는 기존 finding 모델에 추가되는 것뿐이고(additive), 페어링 고지는 stderr 텍스트다.

## 대안

- `pair accept --allow <action>...`가 성공 시 `acl.toml`에 행을 직접 추가하는 안. 기각한다. `acl.toml`은 사람이 손으로 편집하는 파일이고 지금까지 어떤 명령도 여기에 쓰지 않는다는 성질 위에 `PolicyLoad`/`StartupDiagnostic` 문면과 `ACL_STARTUP_NO_AUTOGEN`의 자동 생성 금지가 서 있다. `trust.toml`과 `invites.toml`은 `crates/qsh-core/src/config.rs`의 `FileLock`으로 read-modify-write 전체를 직렬화하지만(`Ops::trust_add`, `Ops::trust_invite` 등이 load→mutate→save를 그 lock 안에서 한다), `acl.toml`에는 그런 규율이 없다. 여기에 writer를 만들면 잠금 기전을 새로 세우거나, 사람이 편집기로 열어 둔 파일을 잠금 없이 덮어쓰는 두 선택지밖에 없다. 게다가 `acl.toml`은 그 둘과 달리 매 handshake가 아니라 프로세스 시작 시 1회만 읽으므로, 잠금을 갖추더라도 조용한 쓰기가 다음 재시작 전까지 반영되지 않는다는 오해가 그대로 남는다.
- TOFU를 지금 채택한다. 기각한다. 맥락에 적은 대로 `trust.toml`의 방향 무관 구조상 client 쪽 TOFU pin이 inbound 인증까지 열어 준다.
- `acl.toml`에 핫 리로드를 넣는다. 기각한다. `PolicySource::load`가 process-start-once인 것은 이미 내려진 결정이고(`acl/load.rs`의 "process-start-once by design") 이 ADR이 다시 여는 대상이 아니다. 재론하려면 그 결정 자체를 개정하는 새 ADR이 필요하다.
