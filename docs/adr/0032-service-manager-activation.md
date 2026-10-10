# ADR-0032: `qsh service`는 명시적 플래그가 있을 때만 서비스 매니저를 부르고, 이미 떠 있는 유닛은 재시작하지 않는다

날짜: 2026-10-11
상태: 제안됨

개정 관계: 새 ADR이다. ADR-0024 결정 11이 "활성화까지 맡기려면 §6.18을 개정하는 별도 결정이 필요하다"고 남겨 둔 자리를 채운다. `docs/CLI.md` §6.18의 "`status`는 존재 여부만 본다" 문단과 "유닛 파일만 쓴다"는 계약을 플래그가 있을 때에 한해 개정하고, `docs/design/threat-model.md` §3의 `qsh service` 행(`launchctl`/`systemctl`을 호출하지 않는다는 서술)을 같은 범위로 고친다. `docs/ROADMAP.md` M17 (a)가 이 ADR을 요구한다. ADR-0017 결정 1(`acl.toml`을 쓰지 않는다)과 ADR-0024 결정 11의 나머지(`qsh setup`은 유닛을 활성화하지 않는다)는 그대로다.

## 맥락

`qsh service install`은 유닛 파일을 쓰기만 한다(`docs/CLI.md` §6.18). 유닛이 실제로 도는 것은 사람이 `docs/deploy/service.md`의 레시피(`launchctl bootstrap gui/$UID …`, `systemctl --user enable --now …`)를 손으로 칠 때다. `qsh doctor`의 `service_not_registered`가 "`qsh service install`로 유닛을 생성하고 등록하라"고 안내하는데, 등록이 실제로는 두 단계라서 안내와 동작 사이에 한 칸이 비어 있다.

설계를 가르는 사실은 이렇다.

- 현행 계약은 매니저를 부르지 않는 것에서 이득을 얻고 있다. `status`는 `path.exists()`만 보므로 파싱할 외부 출력이 없고, 세 op은 `cfg!(target_os)`만으로 매니저를 정하며 `launchctl`/`systemctl`을 탐색조차 하지 않는다(`crates/qsh-core/src/ops/service/mod.rs` 모듈 doc). 이 성질은 테스트가 실제 매니저 없이 전부 돈다는 뜻이기도 하다.
- 매니저 호출은 되돌리기 어려운 부작용이 있다. 서비스 매니저의 재시작은 프로세스와 함께 detach된 세션을 전부 지운다(ADR-0003, `docs/deploy/service.md` Notes for both). 그래서 `install`을 다시 쳤다는 이유로 이미 떠 있는 유닛을 재시작하면 안 된다. `install`은 바이너리 경로를 갱신하려고 반복해서 치는 명령이다(§6.18 "바이너리 경로를 다시 잡는다").
- 두 매니저의 "이미 적재됨" 처리가 다르다. `launchctl bootstrap`은 이미 적재된 label에 오류로 답하고, `systemctl --user enable --now`는 이미 떠 있는 유닛을 건드리지 않고 성공한다.
- macOS의 `gui/<uid>` 도메인은 로그인한 GUI 세션이 있어야 존재한다. SSH로만 들어간 Mac에서는 `bootstrap`이 실패한다. WSL은 systemd가 PID 1이 아니면 `systemctl --user`가 소켓 오류로 실패한다(`docs/deploy/service.md` WSL 절).
- `docs/ROADMAP.md` M17의 명시적 out이 범위를 닫는다. `acl.toml`을 쓰는 동작, 로그인 세션 밖 상시 기동(systemd linger 자동 설정, macOS LaunchDaemon), qsh 자체 데몬화는 이 ADR에 없다.

## 결정

1. 매니저 호출은 명시적 플래그가 있을 때만 일어난다. `qsh service install --activate`, `qsh service uninstall --deactivate`, `qsh service status --live` 셋이고 플래그를 주지 않으면 세 op의 동작과 출력은 오늘과 바이트 단위로 같다. 이 플래그들은 `[service]` 같은 config 키나 환경 변수로 기본값을 바꿀 수 없다. `qsh setup`(ADR-0024)과 `doctor`는 이 플래그를 넘기지 않으며, `setup`의 `next`와 `service_not_registered`의 remedy가 `qsh service install --activate`를 안내할 수는 있다.

2. 활성화는 `install` 전체 성공 뒤의 마지막 단계다. 순서는 오늘의 prefix(매니저 판정, `Config::load`, 충돌 판정, run mode, `HOME`, 유닛 경로, 바이너리 해석·렌더, audit 한 건, 파일 쓰기)에 매니저 호출 한 단계를 더한 것이다. 유닛 파일 쓰기가 실패하면 매니저를 부르지 않는다. 매니저 호출이 실패하면 쓴 유닛 파일은 그대로 두고(`install`은 멱등이라 다시 치면 이어진다) 오류로 끝낸다.

3. 부르는 명령은 아래 표의 argv 그대로다. 셸을 거치지 않고 `Command`에 인자 배열로 넘긴다. 인자에 들어가는 값은 euid, 유닛 경로, 닫힌 집합인 `<mode>`(`serve`/`listen`/`reverse`)뿐이라 사용자 입력이 인자가 되는 경로가 없다. `<uid>`는 프로세스 euid이고 `docs/deploy/service.md`의 `$UID` 레시피와 같은 값이다.

   | 동작 | launchd (macOS) | systemd (Linux user unit) |
   |---|---|---|
   | 이미 떠 있는지 | `launchctl print gui/<uid>/io.qsh.<mode>` (exit 0이면 적재됨) | `systemctl --user is-active qsh-<mode>.service` (exit 0이면 active) |
   | 활성화 | `launchctl bootstrap gui/<uid> <unit path>` | `systemctl --user daemon-reload`, `systemctl --user enable --now qsh-<mode>.service` |
   | 비활성화 | `launchctl bootout gui/<uid>/io.qsh.<mode>` | `systemctl --user disable --now qsh-<mode>.service` |

4. 이미 떠 있는 유닛은 재시작하지 않는다. macOS는 "이미 떠 있는지" 질의가 적재됨이면 `bootstrap`을 부르지 않는다. Linux는 active여도 `enable`은 보장하되(`--now`는 active 유닛을 재시작하지 않는다) `restart`는 어떤 경우에도 부르지 않는다. 이때 새 바이너리 경로는 다음 재시작에야 반영된다. 결과의 `activation`이 `"already_active"`로 이를 알리고 human 렌더는 "다음 재시작에 반영된다"는 한 줄과 detach된 세션이 재시작에 지워진다는 `docs/deploy/service.md` 고지를 가리킨다. 강제 재시작 플래그는 만들지 않는다.

5. 비활성화는 활성 해제가 먼저이고 파일 삭제가 나중이다. `uninstall --deactivate`는 `bootout`/`disable --now`를 부른 뒤 유닛 파일을 지운다. 유닛이 적재돼 있지 않거나 active가 아니면 비활성화 단계는 건너뛰고 `deactivation: "not_active"`로 성공한다. 비활성화가 실패하면 파일은 지우지 않는다. `--deactivate` 없이 `uninstall`하면 오늘처럼 파일만 지우고, 떠 있는 유닛은 그대로 남는다는 사실을 §6.18이 명시한다.

6. `status --live`는 외부 출력을 파싱하지 않고 결정 3의 "이미 떠 있는지" 질의의 exit code 하나만 읽는다. 결과의 `active`는 `true`/`false`다. 유닛 파일이 없으면 매니저를 부르지 않고 `active: false`다. `--live`가 없으면 `active` 필드를 싣지 않는다.

7. 모양은 additive다. `ServiceInstallData`에 `activation`(선택, `"started"` | `"already_active"`), `ServiceUninstallData`에 `deactivation`(선택, `"stopped"` | `"not_active"`), `ServiceStatusData`에 `active`(선택, bool)를 더한다. 플래그를 주지 않은 호출은 필드를 싣지 않으므로(`skip_serializing_if`) 기존 fixture와 바이트가 같다. 새 `ErrorCode`도 새 dotted op도 만들지 않는다(`docs/CLI.md` §2.4).

8. 오류 매핑은 기존 어휘만 쓴다. 매니저 실행 파일을 찾지 못하면(spawn의 `NotFound`) `UNSUPPORTED`이고, 메시지는 WSL이면 `/etc/wsl.conf`의 `systemd=true`를, 그 밖에는 `docs/deploy/service.md`를 가리킨다. 매니저가 0이 아닌 exit로 끝나면 `INTERNAL`이고 `details`에 `step`(`"activate"`/`"deactivate"`/`"live"`)과 `exit_code`를, 메시지에 매니저의 stderr 첫 줄을 512바이트로 잘라 싣는다. 호출 하나의 제한 시간은 30초이며 넘으면 `TIMEOUT`이다. macOS에서 `gui/<uid>` 도메인이 없어 실패하는 경우(SSH만 접속한 Mac)는 `user/<uid>` 도메인으로 우회하지 않고 같은 `INTERNAL`로 끝낸다. 메시지가 `docs/deploy/service.md`를 가리킨다.

9. audit과 fail-closed는 오늘 그대로다. `install`/`uninstall`의 audit 한 건은 첫 변경 전에 쓰고, 실패하면 파일도 매니저도 건드리지 않는다. 활성화는 같은 op의 일부이므로 레코드를 더 만들지 않는다. `AuditRecord`에 "활성화했다"를 담을 필드는 없고 만들지 않는다(`docs/design/threat-model.md` F2). `status --live`는 읽기라 audit을 쓰지 않는다.

10. 매니저 호출은 `qsh-core`의 `ops/service/` 안에서 `ManagerRunner` seam(argv와 제한 시간을 받아 exit 상태와 stderr 첫 줄을 돌려주는 trait 하나) 뒤에 둔다. `qsh-cli`는 clap 플래그와 결과 렌더만 갖는다(`docs/design/architecture.md` §1). 테스트는 기록용 가짜 runner를 주입하며 실제 `launchctl`/`systemctl`을 부르는 테스트는 만들지 않는다. 기본 runner는 공개 `Ops::service_*` 메서드만 만든다. `*_with_home` 쌍둥이는 runner를 인자로 받는다.

11. 문서와 코드의 대조를 테스트가 고정한다. `crates/qsh-core/tests/service_docs.rs`가 이미 `docs/deploy/service.md`의 `xml`/`ini` 펜스를 렌더러 출력과 대조하는 틀이므로, 같은 파일에 `service.md`의 활성화 레시피(`launchctl bootstrap …`, `systemctl --user daemon-reload`, `enable --now …`, 비활성화 레시피)를 읽어 결정 3 표의 argv 빌더 출력과 같은지 확인하는 테스트를 더한다. `service.md`는 같은 커밋에서 비활성화 레시피와 `--activate` 안내를 얻는다.

12. `launchctl`의 label과 `systemctl`의 유닛 이름은 오늘의 `io.qsh.<mode>`, `qsh-<mode>.service` 그대로다. `reverse` 유닛은 파일 이름과 label만 `reverse`라는 §6.18 규칙도 그대로다. linger, LaunchDaemon, 시스템 스코프 유닛은 이 ADR이 다루지 않는다(M17 명시적 out).

## 근거

`install`이 활성화까지 기본으로 하지 않는 이유는 재시작이 세션을 지우기 때문이다. 바이너리를 옮긴 뒤 `qsh service install`을 다시 치는 것이 §6.18이 문서화한 갱신 경로인데, 그 명령이 기본으로 매니저를 건드리면 갱신 한 번이 세션 전부를 지울 수 있다. 플래그를 켜는 것도 "이미 떠 있으면 건드리지 않는다"는 결정 4가 없으면 같은 위험이 있어서, 재시작을 결과 값으로만 알리고 실행하지는 않는다.

플래그를 config 기본값으로 올리지 않는 것은 ROADMAP의 요구("명시적 플래그로만")를 문자 그대로 지키기 위해서다. 호출 줄에 `--activate`가 적혀 있어야 사람이 "이 명령이 매니저를 부른다"는 것을 호출 지점에서 읽는다.

`status --live`가 exit code 하나만 읽는 것은 현행 `status`의 장점(파싱할 외부 출력이 없다)을 최대한 보존하기 위해서다. `launchctl print`와 `systemctl status`의 본문은 OS 버전마다 달라서 계약으로 삼을 수 없다.

argv를 문서와 대조하는 테스트는 이미 있는 장치(`service_docs.rs`)를 넓히는 것이라 비용이 작다. "`service.md`의 레시피가 코드가 실제로 치는 명령과 같다"는 성질은 지금도 유닛 텍스트에 대해 성립하며, 활성화 줄이 그 바깥에 있으면 두 곳이 조용히 어긋난다.

## 대안과 기각 사유

- `install`이 기본으로 활성화한다. 기각한다. 위 근거의 세션 손실 때문이다. `--no-activate`로 끄는 모양도 같은 이유로 기각한다. 기본이 위험한 쪽이면 플래그를 빠뜨린 사람이 피해를 본다.
- 별도 subcommand(`qsh service start`/`stop`)로 연다. 이번에는 채택하지 않는다. 의미는 같지만 세 op이 한 쌍(파일과 활성화)을 한 호출에서 같은 audit 한 건으로 다루는 편이 부분 성공 상태(파일은 있고 활성화는 안 됨)를 한 곳에서 처리한다. 실사용에서 파일 없이 start/stop만 필요하다는 요구가 관측되면 그때 additive로 연다.
- 이미 떠 있는 유닛을 `--activate`에서 재시작한다(`bootout`+`bootstrap`, `restart`). 기각한다. 결정 4의 이유다. 재시작이 필요하면 사람이 `docs/deploy/service.md` 절차로 세션 손실을 감수하고 한다.
- `launchctl bootstrap` 실패 시 `user/<uid>` 도메인으로 대체한다. 기각한다. 도메인이 다르면 LaunchAgent의 수명 모델(로그인 세션 종속)이 달라지고, 그 선택은 로그인 세션 밖 상시 기동으로 이어져 M17 명시적 out과 겹친다.
- 매니저 호출 전에 `launchctl`/`systemctl` 존재를 `PATH`에서 탐색한다. 기각한다. 현행 코드가 의도적으로 탐색하지 않는 성질("probing for `systemctl`/`launchctl`, ever")을 깨고, 탐색과 호출 사이의 어긋남이 생긴다. spawn의 `NotFound`가 같은 정보를 준다.
- `systemctl --user enable`만 하고 `--now`는 빼서 재부팅 때 뜨게 한다. 기각한다. `service.md`의 레시피가 `enable --now`이고 `doctor`의 `service_not_registered` 안내가 "등록하라"에서 끝나므로, 사람이 기대하는 상태는 "지금 떠 있다"이다. 둘을 어긋나게 두면 문서-코드 대조 테스트(결정 11)의 기준도 흐려진다.
- 활성화 전용 audit 레코드를 더한다. 기각한다. 결정 9대로 필드가 없고, audit의 action 문자열은 op의 `COMMAND`(`ServiceInstallOp::COMMAND`)라서 새 action은 새 dotted op를 뜻하고, `docs/CLI.md` §2.4 목록과 `op_registration_completeness.rs`의 분류를 건드린다. 활성화 사실이 audit에 남아야 한다는 요구가 생기면 `AuditRecord`의 확장을 별도 ADR로 연다.

## 결과

- `docs/CLI.md` §6.18의 세 시그니처에 플래그가 들어가고, "`status`는 존재 여부만 본다"와 "유닛 파일만 쓴다" 문장에 플래그 예외가 붙으며, `data` 필드 설명에 `activation`/`deactivation`/`active`가 더해진다. 버전 헤더에 이 변경이 오른다. 같은 커밋에서 `docs/man/qsh-service-install.1`, `qsh-service-uninstall.1`, `qsh-service-status.1`을 `cargo xtask man`으로 다시 만들고 `checked_in_man_pages_match_the_generator`가 확인한다.
- `docs/design/threat-model.md` §3의 `qsh service` 행에서 "`launchctl`/`systemctl`을 호출하지 않으므로 파싱할 외부 출력 자체가 없다"를 플래그가 있을 때의 호출과 exit code만 읽는다는 서술로 고친다. 새 위협 행으로, 매니저 호출의 인자 주입 불가(결정 3)와 재시작 부재(결정 4)를 오른다. 핀 테스트는 아래와 같다.
- 고정할 테스트(`crates/qsh-core/src/ops/service/tests.rs`, 이름은 구현 때 확정):
  - `install_without_activate_never_invokes_the_manager`, `uninstall_without_deactivate_never_invokes_the_manager`, `status_without_live_never_invokes_the_manager`: 가짜 runner의 호출 기록이 비어 있다.
  - `install_activate_runs_the_documented_argv_on_launchd`와 `…_on_systemd`: 호출 기록이 결정 3 표와 같다.
  - `activate_is_skipped_when_the_unit_write_fails`, `activate_is_skipped_when_the_audit_sink_fails`: 기존 `install_is_refused_when_the_audit_sink_fails`와 짝이다.
  - `activate_does_not_restart_an_already_active_unit`: active 응답에서 `bootstrap`/`restart`가 호출되지 않고 `activation`이 `already_active`다.
  - `deactivate_runs_before_the_unit_file_is_removed`, `a_failed_deactivate_keeps_the_unit_file`.
  - `a_missing_manager_binary_is_unsupported_and_a_nonzero_exit_is_internal_with_exit_code`, `a_manager_call_past_the_deadline_is_timeout`.
  - `service_md_activation_recipes_match_the_argv_builders`(`crates/qsh-core/tests/service_docs.rs`).
- fixture: `crates/qsh-cli/tests/fixtures/cli-v1/`에 플래그를 준 호출의 성공 envelope 세 개(`activation`, `deactivation`, `active`)를 append하고 `REQUIRED_FIXTURES`에 등록한다. 기존 service fixture는 바뀌지 않는다. `qsh.cli/v1`은 additive만 쓰고, wire 프로토콜과 `ErrorCode`는 변하지 않는다.
- `docs/deploy/service.md`가 비활성화 레시피와 `--activate` 안내를 얻는다. `docs/adr/README.md` 목록의 이 ADR 상태 열을 `승인됨`으로 고치고 ADR-0024 결정 11의 "별도 결정" 문장이 이 ADR을 가리키게 하는 것은 승인 뒤 같은 커밋에서 한다.
- 크기는 ADR 0.2ew에 구현 0.3~0.5ew다(`docs/ROADMAP.md` M17 (a)). `ManagerRunner` seam과 플래그 세 개, 필드 세 개, 테스트와 문서 동기화로 구성된다.
- 이 ADR이 `승인됨`이 되면 M17 (a)의 착수 조건이 풀린다.
