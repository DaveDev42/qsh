# ADR-0038: `qsh setup client`의 `complete`는 doctor의 `acl_policy_missing` 하나를 세지 않는다(ADR-0024 결정 9 개정). doctor의 진단 등급과 host 쪽 역할의 판정은 그대로 둔다

날짜: 2026-10-01
상태: 승인됨 (2026-10-01 사용자 확정)

개정 관계: [ADR-0024](0024-setup-orchestrator.md) 결정 9의 마지막 조건("`complete`는 `pending`·`blocked` 단계가 없고 doctor의 `overall`이 `"error"`가 아닐 때만 `true`다")을 `client` 역할에 한해 개정한다. 결정 9의 나머지(`SetupRunData`의 필드, `steps[].result`가 op의 `data`를 그대로 담는 규율, `complete`가 첫 셸의 성공을 뜻하지 않는다는 문장)와 ADR-0024의 다른 결정은 바뀌지 않는다. ADR-0017 결정 1·5, ADR-0024 결정 3·4·6, `docs/CLI.md` §6.17의 진단 코드 표를 전제로 삼는다. 제안 상태인 ADR-0027(`doctor --fail-on`)과는 서로 닿지 않는다.

## 맥락

GitHub 이슈 #3의 흐름으로 들어온 `qsh setup`(ADR-0024)은 마지막 단계에서 `doctor.run`을 부르고, 결정 9는 doctor `overall`이 `"error"`이면 `complete`를 `false`로 둔다. 구현은 `crates/qsh-core/src/setup/run.rs`의 `assemble`이 doctor 단계 `result`의 `overall` 문자열만 보고 판정한다.

client 전용 장비에는 보통 `acl.toml`이 없다. 그 장비는 다이얼만 하고 인바운드 요청을 받지 않으므로 정책 파일이 할 일이 없다. 그런데 doctor는 그 장비에서도 `acl_policy_missing`을 `error`로 낸다(`docs/CLI.md` §6.17 표). doctor는 장비의 역할을 모른다. `doctor_acl_findings`(`crates/qsh-core/src/ops/doctor.rs`)는 `infer_run_mode`로 역할을 고르고, 그 함수는 `[listen]`도 outbound 대상도 없는 `config.toml`을 `serve`로 추론한다. client 전용 장비와 `acl.toml`을 빠뜨린 host는 doctor가 보는 입력으로는 구별되지 않는다.

그 결과 `qsh setup client`는 모든 단계가 `done`이나 `already`여도 `complete: false`를 낸다. README "Known limitations"가 이 한계를 적고 `acl.toml`을 client에 두거나 doctor 단계의 그 finding을 무시하라고 안내한다. `golden_setup_run_fixtures`(`crates/qsh-cli/tests/fixtures.rs`)도 `setup.run.client_complete.json`을 만들려고 client 샌드박스에 쓸모없는 `acl.toml`을 써 넣는다. 시험이 사용자에게 권하지 않는 우회를 스스로 쓰고 있는 셈이다.

`complete`가 틀리게 `false`면 두 가지가 무너진다. 에이전트나 프로비저닝 스크립트가 `complete`로 분기하지 못하고 findings를 직접 걸러야 한다. 그리고 `next`가 비어 있다. `assemble`은 `complete`일 때만 역할별 다음 명령(`client`는 `qsh <name>`)을 넣기 때문이다. 이슈 #3의 "안내 명령만 따라 첫 셸까지"라는 기준에서 client 쪽 마지막 안내가 사라진다.

지켜야 할 것도 분명하다. host 쪽 세 역할(`host`, `host --to`, `listener`)에서 `acl.toml`이 없으면 그 장비는 모든 요청을 거부하므로 `complete`가 `true`여서는 안 된다. 그 역할들은 결정 4의 `acl` 단계가 `policy.loaded: false`일 때 이미 `pending`이지만, doctor 조건도 같은 사실을 한 번 더 막고 있다. 이 이중 잠금은 줄이지 않는다.

## 결정

1. `complete`의 doctor 조건을 "doctor `overall`이 `"error"`가 아니다"에서 "doctor의 `findings`에 `status: "error"`인 원소가 없다. 단, 그 역할의 면제 목록에 든 `code`는 세지 않는다"로 바꾼다. 면제 목록이 비어 있으면 이 조건은 오늘의 `overall` 조건과 같은 값을 낸다(`overall`은 가장 심각한 `status`를 반영하므로).

2. 면제 목록은 역할마다 고정한다.

   | 역할 | 면제되는 doctor `code` |
   |---|---|
   | `client` | `acl_policy_missing` |
   | `host` | 없음 |
   | `host_to` | 없음 |
   | `listener` | 없음 |

   목록은 `crates/qsh-core/src/setup/`에 닫힌 상수로 두고, 코드 문자열은 `DiagnosticId::AclPolicyMissing.code()`를 참조한다. 다시 타이핑한 사본을 두지 않는다. 목록을 늘리려면 새 ADR이 필요하다.

3. `acl_policy_invalid`는 면제하지 않는다. 파일이 있는데 파싱되지 않는다면 누군가 그 장비에 정책을 두려 했다는 뜻이고 client 겸 host로 쓰는 장비라면 실제로 모든 인바운드가 거부되는 상태다. `acl_principal_unmatched` 등 정책이 로드된 뒤에만 나오는 다른 `acl_*` 진단도 면제하지 않는다. 면제는 "정책 파일이 아예 없다"는 사실 하나에 한정한다.

4. doctor는 바꾸지 않는다. `acl_policy_missing`의 `status`는 모든 장비에서 `error`로 남고, `overall`, `findings`, exit code, `qsh serve`/`qsh listen`의 시작 진단도 그대로다. `qsh setup client`의 doctor 단계 `result`도 오늘처럼 `doctor.run`의 `data` 그대로라서 `overall: "error"`와 `acl_policy_missing` finding을 담은 채 나간다. 같은 값의 진실 소스를 둘로 만들지 않는다는 결정 9의 규율을 지킨다. 면제가 일어난 실행에서는 doctor 단계 `detail`에 그 사실을 한 문장으로 덧붙인다(예: `overall: error (acl_policy_missing is not counted toward complete for the client role)`). `detail`은 오늘도 자유 문자열이다.

5. 면제는 판정만 바꾸고 정책은 바꾸지 않는다. ACL은 default-deny 그대로다. `qsh setup`은 여전히 `acl.toml`을 쓰지 않고(ADR-0024 결정 3), 이 결정으로 새 신뢰 경로가 생기지 않으며(결정 6), 인가기(`Authorizer`)와 `acl_check`의 결과도 달라지지 않는다. `acl.toml`이 없는 client 장비는 인바운드 요청을 전부 거부하는 상태로 남는다. `client`의 `complete: true`는 "이 장비가 `<name>`으로 다이얼할 준비를 마쳤다"를 말하고 인바운드를 받을 준비는 말하지 않는다. 그 장비에서 나중에 `qsh serve`를 띄우면 시작 진단과 `qsh doctor`가 지금처럼 `acl_policy_missing`을 알린다.

6. 보안 자세를 명시한다. `host`, `host_to`, `listener`는 면제 목록이 비어 있으므로 `acl.toml`이 없으면 doctor 조건만으로도 `complete: false`다. 결정 4의 `acl` 단계 `pending`과 함께 두 겹으로 막히는 오늘의 상태가 그대로 유지된다.

7. 계약 표면은 늘지 않는다. `SetupRunData`에 필드를 더하거나 빼지 않고, `complete`의 타입도 그대로다. 바뀌는 것은 `docs/CLI.md` §6.20이 적은 `complete` 판정 문장 하나이고, 그 효과는 `client` 역할에서 `acl.toml`만 없는 실행의 `complete`가 `false`에서 `true`로 바뀌는 경우 하나다. 기존 fixture는 건드리지 않고 새 fixture를 append한다.

## 근거

`complete`의 뜻은 결정 9가 "이 장비에서 `qsh setup`이 할 일이 없다"로 정했다. `client` 역할에서 `acl.toml`을 쓰는 일은 `qsh setup`의 할 일도, 사람의 할 일도 아니다. 결정 2의 표가 `client`의 `acl.toml` 행 allow를 "없음"으로 적고 단계 순서에 `acl`이 없는 것도 그래서다. 그런데 doctor 조건이 그 장비에 없는 할 일을 요구하고 있으니, 판정이 결정 9 스스로의 정의와 어긋난다. 이 ADR은 그 어긋남만 고친다.

고칠 자리를 doctor가 아닌 setup에 두는 이유는 역할을 아는 쪽이 setup뿐이어서다. setup은 사용자가 고른 역할을 인자로 받는다. doctor는 `config.toml`로 역할을 추론하고, client 전용 장비와 정책을 빠뜨린 host를 같은 `serve`로 본다. doctor에서 등급을 낮추면 뒤쪽 경우까지 함께 낮아진다.

client 장비에서도 doctor의 다른 error(`cert_expired`, `clock_skew`, `peer_untrusted`, `audit_path_unwritable` 등)는 여전히 첫 셸을 막거나 실제 결함을 뜻하므로 면제를 `code` 단위 목록으로 좁혔다. doctor 단계를 통째로 빼거나 `overall`을 무시하면 그런 신호까지 사라진다.

## 대안

- doctor가 `acl_policy_missing`의 `status`를 역할에 따라 달리 낸다(client로 보이는 장비에서는 `warn`이나 `info`). 기각한다. doctor는 역할을 모르고 `infer_run_mode`가 설정 없는 장비를 `serve`로 본다. client를 구별하려면 `config.toml`에 새 역할 표지를 들이거나 `trust.toml`·`hosts.toml` 모양으로 추측해야 하는데, 추측이 틀리면 `acl.toml`을 빠뜨린 host의 유일한 경보가 `error`에서 내려간다. fail closed 원칙과 반대 방향의 오판이다. 계약도 걸린다. `docs/CLI.md` §6.17 표는 `acl_policy_missing`의 등급을 `error`로 적고 있고, `overall`로 게이트를 거는 스크립트와 제안 중인 ADR-0027의 `--fail-on error`가 그 값에 기댄다. 같은 입력에 대한 등급 변경은 additive로 볼 수 없는 의미 변경이다. 시작 진단(`ACL_POLICY_MISSING_CODE`)과 doctor가 같은 code를 같은 무게로 공유한다는 §6.17의 드리프트 방지 규율도 깨진다.
- `qsh doctor`에 `--role <role>` 플래그를 더하고 setup이 그 플래그를 넘긴다. 기각한다. 새 플래그와 역할별 등급 표가 doctor 계약에 새로 붙는데, 그 표를 쓰는 곳은 setup 하나다. setup 안의 면제 목록 하나로 같은 결과를 내므로 표면을 늘릴 이유가 없다.
- `client` 역할에서 doctor 단계를 뺀다. 기각한다. 인증서 만료, 시계 어긋남, pin 없는 이름 같은 진짜 결함을 `complete`가 놓치게 된다.
- `client` 역할의 `complete`에서 doctor 조건을 통째로 뺀다. 같은 이유로 기각한다.
- `acl_*` 진단 전체를 client에서 면제한다. 기각한다. 결정 3대로 `acl_policy_invalid`와 정책 로드 뒤의 진단은 누군가 정책을 두려 했다는 증거이고, client 겸 host 장비에서는 실제 거부로 이어진다.
- `qsh setup client`가 빈 `acl.toml`이나 거부 전용 `acl.toml`을 만든다. 기각한다. ADR-0024 결정 3과 ADR-0017 결정 1이 막는 쓰기다. 빈 정책이라도 사람이 모르는 사이 생긴 파일은 나중에 그 장비를 host로 쓸 때 "정책이 있다"는 착시를 준다.
- README의 우회 안내(client에도 `acl.toml`을 둔다)를 정식 경로로 남긴다. 기각한다. 인바운드를 받지 않는 장비에 정책 파일 작성을 요구하는 것은 이슈 #3이 줄이려는 사람 구간을 도로 늘린다.

## 결과

- 이 결정을 고정할 테스트다. 이름은 구현 시 확정한다.
  - `setup_client_completes_without_acl_toml` (`crates/qsh-core/tests/setup.rs`): `acl.toml` 없는 client 샌드박스에서 `--peer-cert`로 `pin_cert`까지 마친 실행이 `complete: true`이고 `next`에 `qsh <name>`이 있다. 실행 뒤에도 `acl.toml`은 존재하지 않고, doctor 단계 `result.overall`은 `"error"`이며 `acl_policy_missing` finding을 담는다.
  - `setup_client_incomplete_on_invalid_acl_toml`: 파싱되지 않는 `acl.toml`이 있으면 client도 `complete: false`다(결정 3).
  - `setup_client_incomplete_on_other_doctor_error`: `acl_policy_missing` 외의 error finding(예: 만료된 device leaf)이 있으면 `complete: false`다.
  - `setup_complete_exemption_applies_to_client_only` (`crates/qsh-core/src/setup/tests.rs`): `assemble`에 `acl_policy_missing` 하나만 error인 doctor `result`를 넣었을 때 `client`만 `complete: true`이고 `host`, `host_to`, `listener`는 `false`다. 다른 단계는 모두 `done`으로 두어 doctor 조건만 격리한다.
  - `setup_host_roles_incomplete_without_acl_toml`: 세 host 쪽 역할의 실제 실행에서 `acl.toml`이 없으면 `complete: false`다(결정 6의 보안 자세).
  - `setup_complete_exemptions_reference_doctor_codes`: 면제 목록의 문자열이 `DiagnosticId::code()` 값과 같고 `EXPECTED_DOCTOR_CODES`에 들어 있다.
  - 기존 `setup_never_writes_acl_toml_in_any_role`, `acl_diagnostic_codes_are_the_acl_module_constants_verbatim`, doctor fixture 테스트는 바뀌지 않고 초록이어야 한다. doctor 출력이 그대로라는 증거다.
- fixture는 append만 한다. `setup.run.client_complete_without_acl.json`을 더하고 `REQUIRED_FIXTURES`에 등록한다. `golden_setup_run_fixtures`가 `acl.toml` 없는 client 샌드박스로 그 fixture를 만든다. 기존 `setup.run.client_complete.json`과 그것을 만드는 샌드박스의 `acl.toml`은 그대로 둔다. 그 fixture는 정책이 있는 client의 모양을 계속 고정한다.
- 승인되면 바뀌는 문서다.
  - `docs/CLI.md` §6.20: `complete` 판정 문장("`complete`는 `pending`·`blocked`가 없고 doctor의 `overall`이 `"error"`가 아닐 때만 `true`다")을 결정 1·2로 바꾸고, 면제 목록 표와 "`client`의 `complete`는 인바운드 준비를 뜻하지 않는다"는 문장을 더한다.
  - `docs/CLI.md` §6.17: `acl_policy_missing` 행의 등급은 그대로 두고, `qsh setup client`의 `complete` 판정만 이 code를 세지 않는다는 참조 한 줄을 더한다.
  - `README.md` "Known limitations"의 첫 항목(`qsh setup client` reports `complete: false` on a machine that has no `acl.toml` …)을 지운다.
  - `docs/adr/0024-setup-orchestrator.md`의 개정 관계 또는 개정 이력에 결정 9가 이 ADR로 개정됐다는 줄을 더한다.
  - `docs/adr/README.md` 색인에서 이 행의 상태를 `승인됨`으로 바꾼다.
- `docs/design/threat-model.md`에 닿는 변경은 없다. 새 진입점이 없고, 인가 경로와 정책 로드는 바뀌지 않는다.
- `qsh.cli/v1`에 필드가 늘거나 줄지 않는다. `capabilities.json`, wire 메시지, `ErrorCode`, doctor 진단 어휘도 그대로다.
- 구현 크기는 0.2~0.3ew로 추정한다. 측정값이 아니다. `assemble`의 판정 변경과 면제 상수, doctor 단계 `detail` 문구, 위 테스트와 fixture 하나, 문서 세 곳이다.
