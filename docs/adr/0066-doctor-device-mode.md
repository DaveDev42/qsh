# ADR-0066: `qsh doctor`는 장비를 client와 server 중 하나로 판정하고, client로 본 장비에서는 인바운드에만 뜻이 있는 점검을 하지 않는다. 판정은 장비의 상태에서 추론하고 `--mode`와 `[doctor].mode`로 정할 수 있다

날짜: 2026-11-14
상태: 승인됨 (2026-11-14 Dave 결정. "client 전용 장비가 doctor에서 ok로 나오게 풀어라")

개정 관계: [ADR-0038](0038-setup-client-complete-without-acl.md) 결정 4와 대안 1이 doctor를 고치지 않기로 한 이유("doctor는 역할을 모른다")를 이 ADR이 푼다. doctor가 장비 종류를 판정하는 입력을 정하고, 그 판정이 틀렸을 때 안전한 쪽으로 틀리게 하고, 사람이 판정을 고정하는 길을 둔다. ADR-0038의 면제 목록과 `complete` 판정 규칙은 그대로 두고, 면제가 쓰이는 범위만 좁아진다(결정 6). [ADR-0045](0045-trust-roles.md) 결정 12의 "client pin의 기본 role은 `none`"을 판정의 입력으로 쓰고, 그 결정이 정한 doctor 문안과 조건은 server로 판정된 장비에서 그대로다. [ADR-0065](0065-server-client-concept-model.md) 결정 1의 server·client 개념을 doctor의 보고에 연결한다. ADR-0065 결정 5가 막은 "doctor 문안 변경"은 문서 단계에 한정된 말이고 이 ADR은 문안을 바꾸지 않는다. `qsh.cli/v1`은 additive다(결정 5).

## 맥락

`qsh doctor`는 모든 장비를 server로 가정한다. `doctor_acl_findings`는 `infer_run_mode`로 `serve`·`listen`·`reverse` 중 하나를 고르고, 그 함수는 설정이 비어 있으면 `serve`를 낸다. 그래서 `qsh serve`도 `qsh listen`도 돌리지 않고 밖으로 dial만 하는 장비가 이런 결과를 받는다.

- `acl.toml`이 없으면 `acl_policy_missing`(error). ADR-0038은 `qsh setup client`의 `complete`만 이 코드를 세지 않게 했을 뿐 doctor의 보고는 그대로 뒀다.
- 배포가 모든 장비에 같은 `acl.toml`을 렌더하면 그 장비의 pin마다 `acl_principal_unmatched`(error) 하나씩. client 장비의 pin은 `role none`이라 행이 없는데, 그 행은 인바운드를 인가하는 것이어서 client에는 쓸 곳이 없다.
- 서비스 유닛이 없으면 `service_not_registered`, 기본 bind가 IPv6 wildcard이면 `bindv6only_blocks_ipv4`. 둘 다 listener를 띄울 장비의 점검이다.

Dave-MBP16이 그런 장비다(`qsh serve`·`qsh listen` 서비스가 없고 pin은 `role none`이며 `acl.toml`은 배포가 렌더한다). 이 장비의 `qsh doctor`는 error를 내므로 `--fail-on error` 게이트도, 사람이 보는 `overall`도 쓸 수 없다. ADR-0065가 server·client를 개념 모델로 올린 뒤라서 "client 전용 장비는 건강하다"가 doctor 수준에서도 말이 되어야 한다.

ADR-0038이 doctor를 고치지 않은 이유는 두 가지였다. client 장비와 `acl.toml`을 빠뜨린 server는 doctor가 보는 입력으로 구별되지 않는다는 점, 그리고 구별을 추측으로 하면 그 server의 유일한 경보가 사라진다는 점이다. 둘째는 지금도 맞다. 이 ADR은 추측을 한쪽으로만 기울여서 이 문제를 푼다. server의 징후가 하나라도 있으면 server로 보고, 징후가 전혀 없을 때만 client로 본다. 징후는 "인바운드를 받는 장비라면 거의 반드시 남기는 흔적"으로 고른다.

## 결정

1. **장비 종류는 둘이다.** `server`는 인바운드 연결을 받는(또는 곧 받게 될) 장비이고 `client`는 그 밖의 장비다. 이름은 ADR-0065의 개념과 같다. `qsh listen`·`qsh serve --to`를 돌리는 장비는 연결을 받거나 등록을 받는 쪽이라 `server`다.

2. **판정은 위에서부터 먼저 맞는 것이 정한다.**
   1. 요청의 `mode`. `qsh doctor --mode <auto|client|server>`가 `DoctorReq.mode`로 들어온다. `auto`나 없음은 다음으로 넘어간다. 그 밖의 값은 `INVALID_ARGUMENT`다.
   2. `config.toml`의 `[doctor].mode`(`auto`·`client`·`server`, 없으면 `auto`). 그 밖의 값은 설정을 읽을 때 `CONFIG_ERROR`다. `qsh config set doctor.mode`로 쓴다.
   3. 장비의 상태에서 추론한다(결정 3).

3. **추론은 server의 징후를 이 순서로 찾고, 하나라도 있으면 `server`, 없으면 `client`다.** 판정에 쓴 징후는 결과의 `mode_basis`에 닫힌 낱말 하나로 남는다.

   | 순서 | `mode_basis` | 징후 |
   |---|---|---|
   | 1 | `config_section` | `config.toml`의 `[serve]`·`[listen]`·`[reverse]` 표 가운데 하나라도 값을 하나 이상 가진다 |
   | 2 | `service_unit` | `serve`·`listen`·`reverse` 어느 mode든 그 서비스 유닛이 등록돼 있다(`service_not_registered`가 쓰는 같은 검출. Windows는 작업 정의 파일) |
   | 3 | `daemon` | `serve.json`이 있거나(가리키는 프로세스가 죽었어도, 비정상 종료한 serve의 흔적이다), 런타임 디렉터리에 살아 있는 프로세스의 localctl endpoint가 있다 |
   | 4 | `role_pin` | `trust.toml`에 role이 `none`이 아닌 pin이 있다. 인바운드를 role로 인가한다는 뜻이다 |
   | 5 | `role_invite` | role이 `none`이 아닌 role을 실은 살아 있는 초대(`invites.toml`)가 있다 |
   | 없음 | `no_server_signal` | 위 어느 것도 없다. `client`다 |

   징후가 아닌 것도 못 박는다. `acl.toml`의 유무와 내용은 징후가 아니다(배포가 client에도 렌더한다). `role none`이거나 role 키가 없는 pin, `[iroh]`·`[interactive]`·`[agent]`·`[punch]`·`[transport]` 같은 client 설정, 열려 있는 `hosts.toml`도 아니다. 추론은 파일과 프로세스 목록만 읽고 어떤 네트워크 호출도 하지 않는다.

4. **`client`로 판정한 장비의 보고.** 인바운드에만 뜻이 있는 점검을 하지 않는다. 다음 진단 코드는 나오지 않는다.
   - ACL: `acl_policy_missing`, `acl_principal_unmatched`, `acl_ca_auth_path_missing`, `acl_forward_socks_ineffective`, `acl_file_paths_missing`.
   - 서비스: `service_not_registered`, `service_restart_drops_sessions`, `systemd_linger_disabled`, `launchagent_session_scoped`, `logon_task_session_scoped`, `keystore_session_bound`.
   - listener: `bindv6only_blocks_ipv4`, `listen_serve_ignores_serve_bind`, `serve_unit_beside_listen_serve`, `agent_dir_unusable`(agent 디렉터리는 전달을 받는 host가 쓴다).

   하나만 예외다. `acl_policy_invalid`는 `client`에서도 나오되 `status`가 `warn`이다. 파싱되지 않는 파일은 그 장비가 나중에 server가 되는 날 모든 요청과 role 인가를 거부하므로(ADR-0038 결정 3과 같은 이유) 알려야 하고, 지금은 아무것도 거부하지 않으므로 error는 아니다. `detail`에 그렇게 적는다.

   그 밖의 모든 점검(`audit_path_unwritable`, `cert_expired`, `cert_expiring_soon`, `clock_skew`, `keystore_unavailable`, `qsh_path_shadowed`, `config_unknown_key`, `config_serve_to_conflict`, trust 관련 `peer_untrusted`·`trust_pin_role_unset`·`trust_remove_scope`·`jump_hop_missing`, `host_pinned_without_address`, 연결성·전송·펀칭·jump 진단, `agent_unreachable`)은 `server`일 때와 똑같이 돈다. 나오지 않는 점검을 `info` finding으로 대신 알리지 않는다. 진단 코드 어휘가 고정이고(`EXPECTED_DOCTOR_CODES`는 그대로다), 점검이 빠졌다는 사실은 `mode`가 이미 말하기 때문이다. `overall`, `--fail-on`, exit code의 규칙은 그대로다.

5. **계약.** `qsh.cli/v1`은 additive다.
   - `DoctorReq`에 선택 필드 `mode`(`"auto"` | `"client"` | `"server"`, 열린 문자열).
   - `DoctorData`에 선택 필드 `mode`(`"client"` | `"server"`)와 `mode_basis`(결정 2·3의 낱말: `request`, `config`, 또는 결정 3 표의 값). `doctor.run`은 항상 둘을 채운다. 없는 쪽은 이 필드가 생기기 전의 보고다.
   - 기존 필드의 타입과 뜻, `ErrorCode`, finding의 `code`·`status`·`detail`·`remedy`, 문안 상수는 바뀌지 않는다. 바뀌는 것은 어떤 장비에서 어떤 점검이 도느냐뿐이다. 이 점이 "같은 입력에 같은 등급"이라는 ADR-0038 대안 1의 반대 근거와 닿는다. 같은 입력(징후 없는 장비, `acl.toml` 없음)의 결과가 error에서 ok로 바뀌므로 이것은 의도한 동작 변경이고, Dave 결정이다. `--fail-on error`로 client 장비를 게이트하던 스크립트는 이제 통과한다.
   - human 출력은 `overall` 다음 줄에 `mode: client (no_server_signal)`을 낸다.
   - 새 `ErrorCode`와 새 finding code는 없다. 새 설정 키 `doctor.mode`가 `config.get`·`config.list`에 나온다(`applies_from` 없음, 명령마다 읽는다).

6. **`qsh setup`.** host 쪽 세 역할(`host`, `host --to`, `listener`)의 doctor 단계는 `mode: "server"`를 요청한다. 사용자가 server로 만들겠다고 고른 장비이므로 아직 서비스도 pin도 없는 setup 도중에도 `acl_policy_missing`이 나와야 ADR-0038 결정 6의 이중 잠금이 유지된다. `client` 역할은 `auto`로 둔다. 그 결과 징후 없는 client 장비의 `setup client`는 doctor 단계에서 `acl_policy_missing` 자체가 나오지 않아 `complete: true`가 면제 없이 선다. ADR-0038의 면제(`client` 역할의 `acl_policy_missing`)는 그대로 남고, client 역할 장비가 server로 판정되는 경우(예: client 겸 server)에만 쓰인다.

7. **틀릴 수 있는 방향과 그 비용.** 아직 한 번도 띄운 적 없고 서비스·`serve.json`·role pin·role 초대·`[serve]` 표가 하나도 없는 server 후보는 `client`로 판정된다. 이때 `acl.toml`을 빠뜨려도 `qsh doctor`는 `acl_policy_missing`을 내지 않는다. 이 틈을 다음이 메운다.
   - `qsh serve`·`qsh listen`의 시작 진단은 이 ADR과 무관하게 그대로 `acl_policy_missing`·`acl_policy_invalid`를 낸다. 인가기는 role도 `acl.toml` 행도 허용하지 않으면 요청을 거부한다(default-deny). doctor의 판정은 인가에 관여하지 않는다.
   - 결정 3의 징후 가운데 role pin·role 초대는 `qsh trust add --role`, `qsh pair invite`, `qsh setup host`가 server를 세우는 첫 단계에서 이미 남긴다.
   - `qsh setup host`(결정 6), `qsh doctor --mode server`, `[doctor].mode = "server"`는 판정을 고정한다. 배포가 server 장비에 `[doctor].mode = "server"`를 렌더하면 징후와 무관하게 점검이 돈다.
   - 보고가 `mode: client (no_server_signal)`을 첫머리에 말한다. 사람은 이 장비가 server여야 하는지를 거기서 본다.

## 근거

client 전용 장비를 ok로 만드는 길은 doctor가 그 장비가 client임을 아는 것뿐이다. `acl.toml`의 유무는 신호가 못 된다. 배포가 모든 장비에 같은 파일을 렌더하기 때문이다. 그래서 장비가 server로서 한 일(서비스 등록, 데몬 기록, 설정 표, role로 인가한 pin)을 신호로 삼았다. 이 신호들은 "인바운드를 받는다"와 인과로 이어져 있다. 서비스를 등록한 장비는 listener를 띄우려는 장비이고, `role`이 있는 pin은 그 peer에게 인바운드 권한을 준 장비다. client 장비의 pin은 ADR-0045 결정 12가 기본으로 `none`으로 쓴다.

판정의 오류를 비대칭으로 설계했다. client를 server로 오판하면 이전과 같은 보고가 나온다(군더더기 error). server를 client로 오판하면 경보 하나가 빠진다. 앞의 비용이 훨씬 작으므로 징후 하나면 server다. 징후가 없다는 사실로 client라고 단정하는 것은 틀릴 수 있어서 그 방향의 안전장치를 결정 7에 따로 적었다.

새 진단 코드로 "client라서 건너뜀"을 알리는 대신 `mode`를 둔 것은 어휘를 늘리지 않으면서 사람과 스크립트가 판정을 읽게 하려는 것이다. 한 점검이 빠졌다는 사실을 finding으로 쓰면 client 장비의 보고마다 열다섯 개의 info가 나온다.

`acl_policy_invalid`를 남긴 것은 ADR-0038 결정 3과 같은 판단이다. 누군가 그 장비에 정책을 두려 한 증거이고, 깨진 채로 server가 되면 전부 거부한다. 등급만 내렸다.

`setup`이 host 역할에 server를 요청하는 것은 ADR-0038 결정 6이 말한 이중 잠금을 지키려는 것이다. 이 요청이 없으면 서비스를 아직 안 쓴 host 후보가 `setup host` 도중 client로 판정되어 doctor 쪽 잠금이 풀린다. `acl` 단계의 `pending`이 남아 있어 `complete`는 여전히 `false`지만, 두 겹이던 것이 한 겹이 된다.

## 대안

- **(a) 명시 설정만 둔다(`[doctor].role = "client"`).** 기각한다. 제일 단순하지만 지금 있는 client 장비마다 사람이 설정을 써야 하고, ADR-0063이 낮춘 "설정 없이 쓴다"는 방향과 어긋난다. 설정이 없는 장비는 계속 error이므로 Dave-MBP16 문제가 설정을 쓰기 전까지 남는다. 명시 설정은 override로 남겼다.
- **(b) 추론만 둔다.** 기각한다. 징후가 없는 server 후보(결정 7)와 서비스가 남아 있는 client를 사람이 바로잡을 길이 없다.
- **(c) `qsh doctor --client` 플래그만 둔다.** 기각한다. 호출마다 붙여야 하므로 `--fail-on error` 게이트와 배포 점검이 장비마다 다른 명령줄을 가져야 한다. 값이 셋(`auto`·`client`·`server`)이어야 하는 것도 setup이 server를 요청하려면 필요하다. 그래서 플래그는 `--mode <값>` 하나다.
- **`acl.toml`이 없거나 행이 없으면 client로 본다.** 기각한다. 배포가 client에도 `acl.toml`을 렌더하는 것이 이 ADR의 출발이고, 반대로 `acl.toml`을 빠뜨린 server는 가장 경보가 필요한 경우다.
- **client에서 `acl_*`를 `info`나 `warn`으로 내린다.** 기각한다. 판정이 틀렸을 때 server의 error가 내려가는 것은 같고, client 장비의 보고에 쓸모없는 줄이 남는다.
- **나오지 않는 점검마다 `info` finding(`skipped_for_client`)을 낸다.** 기각한다. 위 근거와 같다.
- **`qsh setup client`가 `[doctor].mode = "client"`를 써 넣는다.** 기각한다. 판정은 장비의 상태에서 나오는 것이 기본이다. setup이 쓴 키는 그 장비가 나중에 server가 되어도 남아 server의 경보를 조용히 끈다.

## 결과

- 이 결정을 고정할 테스트다. 이름은 구현에서 확정했다.
  - `crates/qsh-core/src/ops/doctor/tests/mode.rs`: `a_client_only_device_without_acl_toml_is_ok`, `a_client_only_device_with_an_acl_toml_that_names_none_of_its_pins_is_ok`, `a_client_judgment_leaves_out_every_server_only_check`(client에서 빠지는 코드와 같은 장비가 `--mode server`에서 내는 코드), `a_client_with_an_unparseable_acl_toml_is_told_so_as_a_warning`, `a_client_still_gets_the_checks_that_do_not_depend_on_inbound`, 징후 하나마다 한 시험(`a_config_section_for_serving_makes_the_device_a_server`, `a_registered_service_unit_of_any_run_mode_makes_the_device_a_server`, `a_serve_record_live_or_left_by_a_crash_makes_the_device_a_server`, `a_live_localctl_endpoint_makes_the_device_a_server`, `a_pin_with_a_role_or_a_live_role_invite_makes_the_device_a_server`), `a_server_device_reports_what_it_always_did`, `the_request_overrides_the_config_and_the_config_overrides_the_inference`, `server_in_the_config_makes_a_bare_device_report_the_missing_policy`, `an_unknown_request_mode_is_invalid_argument`, `the_config_key_takes_only_the_three_words`.
  - `crates/qsh-cli/tests/it/doctor_mode.rs`: 같은 계약을 실제 바이너리로. client가 `acl.toml` 없이도, 배포가 렌더한 `acl.toml`로도 error 없이 끝나고 `--fail-on error`가 exit 0이고, `--mode server`·`[doctor].mode`·플래그가 설정을 이기는 것, human 출력의 `mode:` 줄, 알 수 없는 `--mode` 값의 exit 2.
  - `crates/qsh-core/tests/it/setup.rs`: `setup_client_judged_client_completes_without_acl_toml`, `setup_client_judged_client_completes_on_invalid_acl_toml`. 기존 `setup_client_completes_without_acl_toml`와 `setup_client_incomplete_on_invalid_acl_toml`은 장비가 server로 판정되는 경우를 다루므로 `[doctor].mode = "server"`를 써서 그 판정을 고정한다(이전에는 이 시험을 도는 장비의 `$HOME`에 서비스 유닛이 있는지에 따라 결과가 달랐다).
  - `crates/qsh-proto/src/types/tests.rs`의 `doctor_data_mode_is_additive`, `crates/qsh-cli/src/render/human/tests.rs`의 `render_doctor_lines_names_the_judged_mode_and_its_basis`.
- fixture는 append만 한다. `doctor.run.client_mode.json`, `doctor.run.server_mode.json`, `setup.run.client_complete_judged_client.json`을 더하고 `REQUIRED_FIXTURES`에 등록한다. 기존 fixture는 건드리지 않는다. 기존 fixture 가운데 `doctor.run` 결과를 담은 것은 `mode`·`mode_basis`가 없는 모양을 계속 고정하므로(`strip_doctor_mode`로 양쪽에서 두 키를 뺀다) 비교 방식만 `check_without_doctor_mode`·`check_without_roles`로 넓혔다. `setup.run.client_complete_without_acl.json`은 `[doctor].mode = "server"`인 client 샌드박스로 계속 만든다.
- 기존 시험 가운데 "초기화만 한 장비는 server다"를 전제로 한 것은 그 장비에 판정을 고정했다. 시험 하나가 server 징후를 보이지 않는 장비에서 `acl_policy_missing`을 기대했다면 그 전제가 옛 가정이다. 바뀐 시험: `doctor_fail_on.rs`의 `error_box`와 `doctor_on_an_initialized_client_reports_the_same_findings_on_every_platform`, `trust_ssh_preview.rs`의 `trust_ssh_preview_placeholder_row_pasted_unedited_matches_no_pinned_principal`, `doctor/tests.rs`의 `doctor_wires_the_service_not_registered_finding_into_the_full_report_deterministically`·`doctor_wires_the_bindv6only_finding_into_the_full_report_deterministically`·`doctor_wires_the_acl_principal_and_ca_findings_into_the_full_report`·`doctor_reports_acl_policy_missing_when_acl_toml_is_absent`·`doctor_reports_acl_policy_invalid_for_malformed_acl_toml`, `fixtures.rs`의 `golden_doctor_keystore_session_bound_fixture`·`golden_setup_run_fixtures`.
- 바뀌는 문서: `docs/CLI.md` §6.17(장비 종류 판정 문단, `mode`·`mode_basis`, 코드 표의 server 전용 표시, `--mode`), §6.20(`complete` 판정과 doctor 단계의 요청), §6.23(`doctor.mode` 키), `docs/design/testing.md` L6, `README.md`(doctor 설명), `docs/adr/README.md`, `RELEASE-NOTES.md`의 v0.8.1. `docs/man/qsh-doctor.1`은 `cargo xtask man`으로 다시 만든다.
