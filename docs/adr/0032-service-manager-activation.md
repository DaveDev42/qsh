# ADR-0032: `qsh service`는 명시적 플래그가 있을 때만 서비스 매니저를 부르고, 이미 떠 있는 유닛은 재시작하지 않는다

날짜: 2026-10-11 (개정 2026-10-13)
상태: 승인됨

개정 관계: 새 ADR이다. ADR-0024 결정 11이 "활성화까지 맡기려면 §6.18을 개정하는 별도 결정이 필요하다"고 남겨 둔 자리를 채운다. `docs/CLI.md` §6.18의 "`status`는 존재 여부만 본다" 문단과 "유닛 파일만 쓴다"는 계약을 플래그가 있을 때에 한해 개정하고, `docs/design/threat-model.md` §3의 `qsh service` 행(`launchctl`/`systemctl`을 호출하지 않는다는 서술)을 같은 범위로 고친다. `docs/ROADMAP.md` M17 (a)가 이 ADR을 요구한다. ADR-0017 결정 1(`acl.toml`을 쓰지 않는다)과 ADR-0024 결정 11의 나머지(`qsh setup`은 유닛을 활성화하지 않는다)는 그대로다.

2026-10-13 개정: 사용자 결정("원칙에 예외는 없어", "전부 다 알아서 진행해")에 따라 플랫폼 간 동등(PRD §4, `docs/ROADMAP.md` §5.1 원칙 7)을 상시 기동에도 적용한다. 처음 판은 macOS LaunchDaemon을 M17의 명시적 out으로 남겨, Linux(사람이 `loginctl enable-linger`를 치는 레시피와 `systemd_linger_disabled`)와 Windows(ADR-0035 결정 27의 상시 기동 작업 레시피와 `logon_task_session_scoped`)가 가진 수준을 macOS만 갖지 못했다. 이 개정은 결정 12를 고치고 결정 13~17을 더한다. 어느 플랫폼에서도 qsh는 로그인 세션 밖 상시 기동을 스스로 설정하지 않는다는 선은 그대로이고, macOS도 사람이 한 번 치는 문서화된 레시피와 그것을 알리는 doctor finding을 얻는다. 같은 점검에서 드러난 keystore 문제(로그인 세션 밖 프로세스가 `platform` 개인키를 읽지 못한다, 결정 15)는 macOS와 Linux 모두에 해당해 함께 닫는다. ADR-0035 결정 27의 "macOS LaunchDaemon은 이 ADR의 범위가 아니다" 문장은 이 ADR을 가리키게 고쳤다(결과 절).

승인 2026-10-14: 사용자 위임 결정("전부 다 알아서 진행해")으로 승인했다. 결정 3의 매니저 호출 표가 Windows 열을 갖지 않아 "원칙에 예외 없음"과 어긋나던 점을 Windows 열 추가(결정 3·4·5·6·8·10)로 닫았고, 비활성화가 실행 여부만 보고 등록은 보지 않아 멈춘 채 등록된 유닛이 파일 삭제 뒤 고아로 남던 틈을 닫았으며(결정 5), Windows 상시 기동 작업이 Credential Manager를 읽는다는 가정에 실측 뒤 대체 경로를 정했다(결정 15) 사람이 설치한 상시 기동 형태(macOS LaunchDaemon, Windows `Password` 주체 작업)를 `--activate`의 재등록이 덮거나 `--deactivate`가 해제하던 틈은 결정 18로 닫았다.

## 맥락

`qsh service install`은 유닛 파일을 쓰기만 한다(`docs/CLI.md` §6.18). 유닛이 실제로 도는 것은 사람이 `docs/deploy/service.md`의 레시피(`launchctl bootstrap gui/$UID …`, `systemctl --user enable --now …`)를 손으로 칠 때다. `qsh doctor`의 `service_not_registered`가 "`qsh service install`로 유닛을 생성하고 등록하라"고 안내하는데, 등록이 실제로는 두 단계라서 안내와 동작 사이에 한 칸이 비어 있다.

설계를 가르는 사실은 이렇다.

- 현행 계약은 매니저를 부르지 않는 것에서 이득을 얻고 있다. `status`는 `path.exists()`만 보므로 파싱할 외부 출력이 없고, 세 op은 `cfg!(target_os)`만으로 매니저를 정하며 `launchctl`/`systemctl`을 탐색조차 하지 않는다(`crates/qsh-core/src/ops/service/mod.rs` 모듈 doc). 이 성질은 테스트가 실제 매니저 없이 전부 돈다는 뜻이기도 하다.
- 매니저 호출은 되돌리기 어려운 부작용이 있다. 서비스 매니저의 재시작은 프로세스와 함께 detach된 세션을 전부 지운다(ADR-0003, `docs/deploy/service.md` Notes for both). 그래서 `install`을 다시 쳤다는 이유로 이미 떠 있는 유닛을 재시작하면 안 된다. `install`은 바이너리 경로를 갱신하려고 반복해서 치는 명령이다(§6.18 "바이너리 경로를 다시 잡는다").
- 두 매니저의 "이미 적재됨" 처리가 다르다. `launchctl bootstrap`은 이미 적재된 label에 오류로 답하고, `systemctl --user enable --now`는 이미 떠 있는 유닛을 건드리지 않고 성공한다.
- macOS의 `gui/<uid>` 도메인은 로그인한 GUI 세션이 있어야 존재한다. SSH로만 들어간 Mac에서는 `bootstrap`이 실패한다. WSL은 systemd가 PID 1이 아니면 `systemctl --user`가 소켓 오류로 실패한다(`docs/deploy/service.md` WSL 절).
- `docs/ROADMAP.md` M17의 명시적 out이 범위를 닫는다. `acl.toml`을 쓰는 동작과 qsh 자체 데몬화는 이 ADR에 없다. 로그인 세션 밖 상시 기동은 어느 플랫폼에서도 qsh가 자동으로 설정하지 않는다(linger 자동 설정, LaunchDaemon 설치, Windows 상시 기동 작업 등록 모두). 대신 플랫폼마다 사람이 root 또는 관리자 권한으로 한 번 치는 문서화된 레시피와, 상시 기동이 아닌 상태를 알리는 doctor finding이 있다(결정 12~14).
- 개인키가 OS credential store에 있으면(`identity.key_store = "platform"`) 로그인 세션 밖에서 읽히지 않는다. macOS `platform`은 사용자의 login Keychain(`apple-native-keyring-store`)이고, login Keychain은 로그인 전과 로그아웃 뒤에 잠겨 있다. Linux `platform`은 Secret Service이며 linger로 뜬 유닛에는 D-Bus 세션도 잠금 해제된 collection도 없다. 적재 경로는 `identity.toml`에 기록된 store만 열고 대체 경로가 없으므로(`crates/qsh-core/src/identity/mod.rs`의 `open_store`), 이 조합의 `qsh serve`는 기동 시 개인키를 읽지 못하고 끝난다. `auto`의 파일 대체는 `qsh init` 때 한 번만 판정되므로, 데스크톱에서 init한 장비는 대개 `platform`이다. Windows는 상시 기동 작업이 `LogonType=Password`로 사용자 프로필과 DPAPI 키를 적재하므로 Credential Manager 항목을 그대로 읽는다(ADR-0035 결정 12·27).

## 결정

1. 매니저 호출은 명시적 플래그가 있을 때만 일어난다. `qsh service install --activate`, `qsh service uninstall --deactivate`, `qsh service status --live` 셋이고 플래그를 주지 않으면 세 op의 동작과 출력은 오늘과 바이트 단위로 같다. 이 플래그들은 `[service]` 같은 config 키나 환경 변수로 기본값을 바꿀 수 없다. `qsh setup`(ADR-0024)과 `doctor`는 이 플래그를 넘기지 않으며, `setup`의 `next`와 `service_not_registered`의 remedy가 `qsh service install --activate`를 안내할 수는 있다.

2. 활성화는 `install` 전체 성공 뒤의 마지막 단계다. 순서는 오늘의 prefix(매니저 판정, `Config::load`, 충돌 판정, run mode, `HOME`, 유닛 경로, 바이너리 해석·렌더, audit 한 건, 파일 쓰기)에 매니저 호출 한 단계를 더한 것이다. 유닛 파일 쓰기가 실패하면 매니저를 부르지 않는다. 매니저 호출이 실패하면 쓴 유닛 파일은 그대로 두고(`install`은 멱등이라 다시 치면 이어진다) 오류로 끝낸다.

3. 부르는 명령은 아래 표의 argv 그대로다. 셸을 거치지 않고 `Command`에 인자 배열로 넘긴다. 인자에 들어가는 값은 euid, 유닛 경로, 닫힌 집합인 `<mode>`(`serve`/`listen`/`reverse`)뿐이라 사용자 입력이 인자가 되는 경로가 없다. `<uid>`는 프로세스 euid이고 `docs/deploy/service.md`의 `$UID` 레시피와 같은 값이다. Windows 인자에는 사용자 입력도 uid도 들어가지 않는다(닫힌 집합인 `<mode>`와 qsh가 정한 경로뿐).

   | 동작 | launchd (macOS) | systemd (Linux user unit) | 작업 스케줄러 (Windows) |
   |---|---|---|---|
   | 이미 떠 있는지 | `launchctl print gui/<uid>/io.qsh.<mode>` (exit 0이면 적재됨) | `systemctl --user is-active qsh-<mode>.service` (exit 0이면 active) | 작업 스케줄러 COM `IRegisteredTask::get_State`가 `TASK_STATE_RUNNING`인지 (subprocess 없음) |
   | 등록돼 있는지 | 위와 같다(적재됨이면 등록) | 질의 없음. 유닛 파일이 있으면 등록으로 본다 | `schtasks /Query /TN \qsh\qsh-<mode>` (exit 0이면 등록됨) |
   | 활성화 | `launchctl bootstrap gui/<uid> <unit path>` | `systemctl --user daemon-reload`, `systemctl --user enable --now qsh-<mode>.service` | `schtasks /Create /F /TN \qsh\qsh-<mode> /XML <task path>`, 실행 중이 아니면 `schtasks /Run /TN \qsh\qsh-<mode>` |
   | 비활성화 | `launchctl bootout gui/<uid>/io.qsh.<mode>` | `systemctl --user disable --now qsh-<mode>.service` | `schtasks /End /TN \qsh\qsh-<mode>`, `schtasks /Delete /F /TN \qsh\qsh-<mode>` |

   Windows 열은 ADR-0035 결정 27·28의 백엔드를 이 표에 옮긴 것이다. `<uid>`는 Windows에 없고, 작업 이름은 `\qsh\qsh-<mode>`, `<task path>`는 `<config_dir>\service\qsh-<mode>.task.xml`이다. 실행 상태를 COM으로 읽는 이유는 `schtasks /Query`의 exit code가 등록 여부만 알려 주고 실행 상태는 지역화된 본문에만 있어서, 결정 6의 "외부 출력을 파싱하지 않는다"를 지키는 길이 이것뿐이기 때문이다. COM이 돌려주는 것은 열거형 상태값 하나다.

4. 이미 떠 있는 유닛은 재시작하지 않는다. macOS는 "이미 떠 있는지" 질의가 적재됨이면 `bootstrap`을 부르지 않는다. Linux는 active여도 `enable`은 보장하되(`--now`는 active 유닛을 재시작하지 않는다) `restart`는 어떤 경우에도 부르지 않는다. 이때 새 바이너리 경로는 다음 재시작에야 반영된다. 결과의 `activation`이 `"already_active"`로 이를 알리고 human 렌더는 "다음 재시작에 반영된다"는 한 줄과 detach된 세션이 재시작에 지워진다는 `docs/deploy/service.md` 고지를 가리킨다. 강제 재시작 플래그는 만들지 않는다. Windows는 작업 정의가 매니저 안에 저장되고 파일은 입력일 뿐이라, 바이너리 경로 갱신이 반영되려면 `/Create /F`가 항상 돌아야 한다. 그래서 실행 중이어도 `/Create /F`는 부르고 `/Run`만 부르지 않는다(상시 기동 형태가 등록돼 있으면 `/Create`도 부르지 않는다, 결정 18). `/Create /F`가 실행 중인 인스턴스를 멈추는지는 Windows 백엔드의 첫 서비스 스텝에서 실측한다. 멈춘다면 실행 중일 때 `/Create`도 부르지 않고 `already_active`로 끝내며, human 렌더가 "저장된 작업 정의는 다음 `uninstall --deactivate` 뒤 `install --activate`에 갱신된다"고 알린다. 어느 쪽이든 인스턴스를 멈추거나 재시작하는 호출은 없다.

5. 비활성화는 활성 해제가 먼저이고 파일 삭제가 나중이다. `uninstall --deactivate`는 `bootout`/`disable --now`/`/End`와 `/Delete`를 부른 뒤 유닛 파일을 지운다. 판정 기준은 실행 여부가 아니라 등록 여부다(결정 3 표의 "등록돼 있는지"). 멈춘 채 등록만 남은 유닛(systemd의 enabled이지만 inactive, Windows의 등록됐지만 실행 중이 아닌 작업)을 두고 파일만 지우면 매니저에 고아 등록이 남아 다음 로그인에 옛 경로로 다시 뜨기 때문이다. 등록돼 있지 않으면(launchd는 적재되지 않음, Windows는 `/Query`가 0이 아님) 비활성화 단계는 건너뛰고 `deactivation: "not_active"`로 성공한다. 해제 호출을 하나라도 했으면 `"stopped"`다. systemd는 유닛 파일이 있으면 `disable --now`를 부른다(active가 아니어도 멱등이다). Windows는 실행 중이 아니면 `/End`를 건너뛰고 `/Delete /F`만 부른다. 비활성화가 실패하면 파일은 지우지 않는다. `--deactivate` 없이 `uninstall`하면 오늘처럼 파일만 지우고, 떠 있는 유닛은 그대로 남는다는 사실을 §6.18이 명시한다.

6. `status --live`는 외부 출력을 파싱하지 않고 결정 3의 "이미 떠 있는지" 질의의 exit code 하나(Windows는 COM이 돌려주는 상태값 하나)만 읽는다. 결과의 `active`는 `true`/`false`다. 유닛 파일이 없으면 매니저를 부르지 않고 `active: false`다. `--live`가 없으면 `active` 필드를 싣지 않는다.

7. 모양은 additive다. `ServiceInstallData`에 `activation`(선택, `"started"` | `"already_active"` | `"always_on_present"`), `ServiceUninstallData`에 `deactivation`(선택, `"stopped"` | `"not_active"` | `"always_on_present"`), `ServiceStatusData`에 `active`(선택, bool)를 더한다. 플래그를 주지 않은 호출은 필드를 싣지 않으므로(`skip_serializing_if`) 기존 fixture와 바이트가 같다. 새 `ErrorCode`도 새 dotted op도 만들지 않는다(`docs/CLI.md` §2.4).

8. 오류 매핑은 기존 어휘만 쓴다. 매니저 실행 파일을 찾지 못하면(spawn의 `NotFound`) `UNSUPPORTED`이고, 메시지는 WSL이면 `/etc/wsl.conf`의 `systemd=true`를, 그 밖에는 `docs/deploy/service.md`를 가리킨다. 매니저가 0이 아닌 exit로 끝나면 `INTERNAL`이고 `details`에 `step`(`"activate"`/`"deactivate"`/`"live"`)과 `exit_code`를, 메시지에 매니저의 stderr 첫 줄을 512바이트로 잘라 싣는다. 호출 하나의 제한 시간은 30초이며 넘으면 `TIMEOUT`이다. macOS에서 `gui/<uid>` 도메인이 없어 실패하는 경우(SSH만 접속한 Mac)는 `user/<uid>` 도메인으로 우회하지 않고 같은 `INTERNAL`로 끝낸다. 메시지가 `docs/deploy/service.md`를 가리킨다. Windows는 `schtasks.exe`가 `System32`에 있어 `NotFound`가 사실상 없고, 있다면 같은 `UNSUPPORTED`다. 로그온한 대화형 세션이 없어 `InteractiveToken` 작업이 시작되지 못하는 경우(SSH로만 들어간 Windows)도 `schtasks /Run`이 0이 아닌 exit로 끝나면 같은 `INTERNAL`이고, 다른 주체나 로그온 유형으로 우회하지 않는다(macOS의 `user/<uid>` 우회 금지와 같은 이유). COM 질의 실패는 `step: "live"`의 `INTERNAL`이다.

9. audit과 fail-closed는 오늘 그대로다. `install`/`uninstall`의 audit 한 건은 첫 변경 전에 쓰고, 실패하면 파일도 매니저도 건드리지 않는다. 활성화는 같은 op의 일부이므로 레코드를 더 만들지 않는다. `AuditRecord`에 "활성화했다"를 담을 필드는 없고 만들지 않는다(`docs/design/threat-model.md` F2). `status --live`는 읽기라 audit을 쓰지 않는다.

10. 매니저 호출은 `qsh-core`의 `ops/service/` 안에서 `ManagerRunner` seam(argv와 제한 시간을 받아 exit 상태와 stderr 첫 줄을 돌려주는 trait 하나) 뒤에 두고, Windows의 실행 상태 질의는 그 옆의 작은 trait 하나(작업 이름을 받아 실행 중 여부를 돌려준다, ADR-0035 결정 28)로 둔다. Windows 분기의 구현은 백엔드가 서는 M19가 하고 seam은 M17 (a)가 그 모양으로 세운다. `qsh-cli`는 clap 플래그와 결과 렌더만 갖는다(`docs/design/architecture.md` §1). 테스트는 기록용 가짜 runner를 주입하며 실제 `launchctl`/`systemctl`을 부르는 테스트는 만들지 않는다. 기본 runner는 공개 `Ops::service_*` 메서드만 만든다. `*_with_home` 쌍둥이는 runner를 인자로 받는다.

11. 문서와 코드의 대조를 테스트가 고정한다. `crates/qsh-core/tests/it/service_docs.rs`가 이미 `docs/deploy/service.md`의 `xml`/`ini` 펜스를 렌더러 출력과 대조하는 틀이므로, 같은 파일에 `service.md`의 활성화 레시피(`launchctl bootstrap …`, `systemctl --user daemon-reload`, `enable --now …`, 비활성화 레시피, Windows는 `schtasks` 레시피)를 읽어 결정 3 표의 argv 빌더 출력과 같은지 확인하는 테스트를 더한다. Windows 레시피는 ADR-0035 백엔드와 함께 들어온다. `service.md`는 같은 커밋에서 비활성화 레시피와 `--activate` 안내를 얻는다.

12. `launchctl`의 label과 `systemctl`의 유닛 이름은 오늘의 `io.qsh.<mode>`, `qsh-<mode>.service` 그대로다. `reverse` 유닛은 파일 이름과 label만 `reverse`라는 §6.18 규칙도 그대로다. 로그인 세션 밖 상시 기동은 qsh가 어느 플랫폼에서도 자동으로 설정하지 않는다. `--activate`는 linger를 켜지 않고, LaunchDaemon을 설치하지 않으며, Windows에서 상시 기동 작업을 등록하지 않는다. 플랫폼마다 사람이 치는 레시피가 `docs/deploy/service.md`에 있다. Linux는 `loginctl enable-linger $USER`(오늘 있다), macOS는 결정 13의 LaunchDaemon, Windows는 ADR-0035 결정 27의 상시 기동 작업이다. 시스템 스코프 systemd 유닛(`/etc/systemd/system`)은 linger가 같은 효과를 내므로 레시피를 따로 두지 않는다.

13. macOS 상시 기동 레시피는 `UserName`을 지정한 LaunchDaemon이다. 사람이 root로 설치하고 qsh는 그 파일을 쓰지도 `launchctl`에 넘기지도 않는다. `docs/deploy/service.md` launchd 절이 다음을 갖는다.
    - 파일은 `/Library/LaunchDaemons/io.qsh.<mode>.plist`이고 label은 LaunchAgent와 같은 `io.qsh.<mode>`다. 둘을 동시에 적재하지 않으므로 label이 겹쳐도 혼동이 없고, doctor와 `status`가 같은 이름으로 찾는다.
    - plist 본문은 LaunchAgent 렌더러가 내는 것과 같은 `ProgramArguments`·`KeepAlive`·`RunAtLoad`·로그 경로(`~/Library/Logs/qsh/`를 절대 경로로 펼친 것)에 `UserName`(그 사용자), `GroupName`(`staff`), `EnvironmentVariables`의 `HOME`을 더한 것이다. LaunchDaemon은 `HOME`을 채워 주지 않으므로 이 값이 있어야 `~/.config/qsh`를 찾는다.
    - 설치는 `qsh service uninstall --deactivate`로 LaunchAgent를 먼저 내린 뒤, `sudo cp`로 파일을 놓고 `sudo chown root:wheel`, `sudo chmod 644`, `sudo launchctl bootstrap system /Library/LaunchDaemons/io.qsh.<mode>.plist` 순서다. 해제는 `sudo launchctl bootout system/io.qsh.<mode>`와 파일 삭제다. 바이너리를 옮기면 사람이 plist의 경로를 고쳐 다시 `bootout`/`bootstrap`하고, 이때 detach된 세션이 지워진다는 고지를 그대로 단다.
    - 이 펜스는 렌더러가 만들지 않으므로 `service_docs.rs`의 대조는 바이트 일치가 아니다. 펜스의 `ProgramArguments`와 `KeepAlive`·`RunAtLoad`가 LaunchAgent 렌더러 출력과 같고 `UserName`·`HOME`이 있다는 것만 확인한다(결과 절의 `service_md_launchdaemon_recipe_matches_the_agent_program_arguments`).

14. doctor는 macOS 상시 기동을 Linux linger와 같은 수준으로 본다.
    - `service_not_registered`는 macOS에서 LaunchAgent(`~/Library/LaunchAgents/io.qsh.<mode>.plist`)나 LaunchDaemon(`/Library/LaunchDaemons/io.qsh.<mode>.plist`) 중 하나가 있으면 등록된 것으로 본다. 두 경로 모두 파일 존재만 보고 `launchctl`을 부르지 않는다(`probe_systemd_linger`가 linger 파일만 보는 것과 같은 모양).
    - `launchagent_session_scoped`는 LaunchAgent가 있고 같은 mode의 LaunchDaemon 파일이 없을 때만 낸다. 문구는 "일반 사용자 계정에는 헤드리스 대응물이 없다"에서 "로그인 세션 밖에서 돌리려면 `docs/deploy/service.md`의 LaunchDaemon 레시피를 root로 한 번 실행하라"로 바뀐다. code와 수준은 그대로라 기존 소비자에게 additive다.
    - `qsh service status`의 `exists`는 오늘처럼 LaunchAgent 경로만 본다. LaunchDaemon은 사람이 설치한 파일이고 §6.18의 `service.*` op이 관리하는 대상이 아니다. `status --live`는 LaunchDaemon 파일이 없으면 `gui/<uid>` 도메인만 묻고, 있으면 결정 18대로 `system` 도메인을 묻는다. `--activate`와 `--deactivate`가 LaunchDaemon을 건드리지 않는 것도 결정 18이다.

15. 상시 기동과 OS credential store가 겹치면 doctor가 알리고, 사람이 개인키를 파일 store로 옮기는 op을 둔다.
    - 새 doctor finding `keystore_session_bound`(warn)는 `identity.key_store`가 `platform`이고 상시 기동 형태가 있을 때 낸다. 상시 기동 형태는 macOS에서 LaunchDaemon 파일, Linux에서 linger 파일과 등록된 user unit의 조합이다. Windows에서는 내지 않는다(맥락 절, 상시 기동 작업이 DPAPI를 적재한다). 이 가정은 ADR-0035 첫 서비스 스텝에서 `LogonType=Password` 작업이 Credential Manager 항목을 실제로 읽는지로 실측한다. 읽지 못하면 이 finding을 Windows의 상시 기동 작업(`BootTrigger`와 `Password` 주체로 등록된 것, ADR-0035 결정 27의 COM 읽기로 판정)에도 같은 remedy로 낸다. 원칙에 예외를 두지 않으므로 어느 쪽이든 Windows에서 상시 기동과 `platform` 개인키의 충돌은 알려진다. remedy는 `qsh identity move-key --to file`이다. 진단 코드 목록에 하나를 더하는 additive 변경이다.
    - 새 op `identity.move_key`(`qsh identity move-key --to <file|platform>`)는 개인키를 store 사이에서 옮긴다. device_id, 인증서, fingerprint는 바뀌지 않으므로 상대 장비의 pin과 ACL 행은 그대로 유효하다. 순서는 원래 store에서 읽기, 새 store에 쓰기(파일이면 0600, Windows는 ADR-0035 결정 9의 DACL), 새 store에서 다시 읽어 공개키 대조, `identity.toml`의 `key_store` 갱신, 원래 store의 항목 삭제다. 어느 단계든 실패하면 그 앞까지 만든 것을 지우고 원래 상태로 끝나며, 마지막 삭제만 실패하면 성공으로 끝내되 결과에 `stale_entry_left: true`를 싣고 human 렌더가 남은 항목을 알린다. 이미 그 store면 아무것도 하지 않고 `moved: false`로 성공한다.
    - 계약은 additive다. 결과 `data`는 `{ "from", "to", "moved", "stale_entry_left" }`이고 `from`/`to`는 기존 `key_store` 값 어휘(`platform`/`file`)를 쓴다. 오류는 기존 `ErrorCode`만 쓴다. 초기화 전이면 `identity.export`와 같은 `CONFIG_ERROR`, `--to platform`인데 store가 없으면 `identity.init --key-store platform`과 같은 `INTERNAL`이다. Windows의 `platform`은 Credential Manager(ADR-0035 결정 12)이고 `move-key`는 세 플랫폼에서 같은 순서와 같은 결과를 낸다. ADR-0013대로 개인키는 인자로도 결과로도 나가지 않는다.
    - audit은 `trust.*`처럼 첫 변경 전에 한 건 쓰고(action `identity.move_key`, 구조 필드만), 실패하면 아무것도 옮기지 않는다. 원격에서 부를 수 없는 로컬 op이라 ACL 대상이 아니다.
    - `qsh init`의 `auto`가 판정하는 규칙(platform 우선)은 바꾸지 않는다. 상시 기동을 쓰는지는 init 시점에 알 수 없고, 데스크톱에서는 OS store가 더 나은 기본값이다.

16. 레시피를 자동화하지 않는다는 선은 세 플랫폼에 같다. qsh가 root나 관리자 권한을 요구하거나 `sudo`를 부르는 경로는 없다. `doctor`와 `setup`의 `next`는 레시피를 가리킬 수는 있어도 실행하지 않는다.

17. 이 개정은 wire 프로토콜을 바꾸지 않는다. `qsh.cli/v1`에는 새 op 하나(`identity.move_key`)와 새 진단 코드 하나(`keystore_session_bound`)가 더해지고, 둘 다 additive다. 새 `ErrorCode`는 없다.

18. 사람이 설치한 상시 기동 형태는 `--activate`와 `--deactivate`도 건드리지 않는다. 세 플랫폼에 같은 규칙이고, 결정 12·16의 "qsh는 상시 기동을 설정하지 않는다"를 해제와 재설치까지 넓힌 것이다(2026-10-14 승인 때 정했다). 상시 기동 형태는 macOS에서 같은 mode의 LaunchDaemon 파일(결정 13), Windows에서 `\qsh\qsh-<mode>` 작업이 `Password` 주체로 등록된 상태(ADR-0035 결정 27의 상시 기동 변형, 주체는 같은 결정의 COM 읽기로 판정)다. Linux의 linger는 사용자 속성이고 그 아래 도는 유닛은 qsh가 쓴 바로 그 유닛이라, 따로 판정할 형태가 없고 결정 3 표 그대로다.
    - `install --activate`는 상시 기동 형태가 있으면 유닛 파일만 쓰고 매니저를 부르지 않으며 `activation: "always_on_present"`로 성공한다. macOS에서 `bootstrap`을 부르면 같은 label이 `gui`와 `system` 두 도메인에 적재되어 같은 포트를 다투고, Windows에서 `/Create /F`를 부르면 사람이 등록한 `BootTrigger`·`Password` 정의가 기본 정의로 조용히 덮여 로그온 범위로 돌아가기 때문이다. human 렌더는 바이너리 경로를 바꿨다면 `docs/deploy/service.md`의 상시 기동 레시피를 다시 치라고 알린다.
    - `uninstall --deactivate`는 상시 기동 형태에 해제 호출을 하지 않는다. macOS는 LaunchAgent의 `gui` 도메인 해제만 결정 5대로 하고, Windows는 그 작업이 곧 상시 기동 형태이므로 `/End`·`/Delete`를 부르지 않는다. 두 플랫폼 모두 유닛 파일은 지우고 `deactivation: "always_on_present"`로 성공한다. 상시 기동 형태의 해제는 레시피의 해제 명령을 사람이 친다.
    - `status --live`의 `active`는 상시 기동 형태가 있으면 그 형태의 실행 여부다. Windows는 같은 작업 이름이라 결정 3의 COM 질의 그대로이고, macOS는 `launchctl print system/io.qsh.<mode>`의 exit code다. 이 질의가 root 없이 되는지는 구현 첫 스텝에서 확인한다. 되지 않으면 LaunchDaemon 파일이 있을 때의 `--live`는 결정 8의 `INTERNAL`(`step: "live"`)로 끝나고 message가 `sudo launchctl print system/io.qsh.<mode>`를 안내한다. 이 대체는 이미 정한 것이고 ADR 개정이 필요 없다.

## 근거

`install`이 활성화까지 기본으로 하지 않는 이유는 재시작이 세션을 지우기 때문이다. 바이너리를 옮긴 뒤 `qsh service install`을 다시 치는 것이 §6.18이 문서화한 갱신 경로인데, 그 명령이 기본으로 매니저를 건드리면 갱신 한 번이 세션 전부를 지울 수 있다. 플래그를 켜는 것도 "이미 떠 있으면 건드리지 않는다"는 결정 4가 없으면 같은 위험이 있어서, 재시작을 결과 값으로만 알리고 실행하지는 않는다.

플래그를 config 기본값으로 올리지 않는 것은 ROADMAP의 요구("명시적 플래그로만")를 문자 그대로 지키기 위해서다. 호출 줄에 `--activate`가 적혀 있어야 사람이 "이 명령이 매니저를 부른다"는 것을 호출 지점에서 읽는다.

`status --live`가 exit code 하나만 읽는 것은 현행 `status`의 장점(파싱할 외부 출력이 없다)을 최대한 보존하기 위해서다. `launchctl print`와 `systemctl status`의 본문은 OS 버전마다 달라서 계약으로 삼을 수 없다.

argv를 문서와 대조하는 테스트는 이미 있는 장치(`service_docs.rs`)를 넓히는 것이라 비용이 작다. "`service.md`의 레시피가 코드가 실제로 치는 명령과 같다"는 성질은 지금도 유닛 텍스트에 대해 성립하며, 활성화 줄이 그 바깥에 있으면 두 곳이 조용히 어긋난다.

## 대안과 기각 사유

- `install`이 기본으로 활성화한다. 기각한다. 위 근거의 세션 손실 때문이다. `--no-activate`로 끄는 모양도 같은 이유로 기각한다. 기본이 위험한 쪽이면 플래그를 빠뜨린 사람이 피해를 본다.
- 별도 subcommand(`qsh service start`/`stop`)로 연다. 이번에는 채택하지 않는다. 의미는 같지만 세 op이 한 쌍(파일과 활성화)을 한 호출에서 같은 audit 한 건으로 다루는 편이 부분 성공 상태(파일은 있고 활성화는 안 됨)를 한 곳에서 처리한다. 실사용에서 파일 없이 start/stop만 필요하다는 요구가 관측되면 그때 additive로 연다.
- 이미 떠 있는 유닛을 `--activate`에서 재시작한다(`bootout`+`bootstrap`, `restart`). 기각한다. 결정 4의 이유다. 재시작이 필요하면 사람이 `docs/deploy/service.md` 절차로 세션 손실을 감수하고 한다.
- `launchctl bootstrap` 실패 시 `user/<uid>` 도메인으로 대체한다. 기각한다. 도메인이 다르면 LaunchAgent의 수명 모델(로그인 세션 종속)이 조용히 달라진다. 로그인 세션 밖 상시 기동은 사람이 의도해서 치는 결정 13의 레시피 하나로만 들어간다.
- qsh가 LaunchDaemon을 직접 설치한다(`--system` 같은 플래그로 `/Library/LaunchDaemons`에 쓰고 `launchctl bootstrap system`). 기각한다. root가 필요하고, Linux의 linger와 Windows의 상시 기동 작업도 qsh가 대신 설정하지 않으므로 macOS만 자동화하면 그 자체로 플랫폼 간 차이가 생긴다(결정 16). 세 플랫폼을 함께 자동화하는 요구가 관측되면 별도 ADR로 연다.
- LaunchDaemon이 System Keychain이나 별도 keychain 파일에서 개인키를 읽게 한다. 기각한다. System Keychain은 root 소유라 `UserName`으로 내려간 프로세스가 읽지 못하고, 별도 keychain은 잠금 해제 비밀번호를 어딘가에 저장해야 해서 0600 파일 store보다 나은 점이 없다. Linux Secret Service에도 같은 구조의 답이 없다.
- 적재 시 `platform`이 Unavailable이면 파일 store로 대체한다. 기각한다. 파일 store에는 키가 없으므로 대체할 대상이 없고, 대체가 성공하는 경우가 있다면 두 store에 키가 따로 있다는 뜻이라 fail-closed 원칙에 어긋난다.
- 사람이 `qsh init --key-store file`로 새 identity를 만든다. 기각한다. fingerprint가 바뀌어 상대 장비의 pin과 ACL 행을 전부 다시 만들어야 한다. `identity.move_key`는 fingerprint를 유지한다.
- 매니저 호출 전에 `launchctl`/`systemctl` 존재를 `PATH`에서 탐색한다. 기각한다. 현행 코드가 의도적으로 탐색하지 않는 성질("probing for `systemctl`/`launchctl`, ever")을 깨고, 탐색과 호출 사이의 어긋남이 생긴다. spawn의 `NotFound`가 같은 정보를 준다.
- `systemctl --user enable`만 하고 `--now`는 빼서 재부팅 때 뜨게 한다. 기각한다. `service.md`의 레시피가 `enable --now`이고 `doctor`의 `service_not_registered` 안내가 "등록하라"에서 끝나므로, 사람이 기대하는 상태는 "지금 떠 있다"이다. 둘을 어긋나게 두면 문서-코드 대조 테스트(결정 11)의 기준도 흐려진다.
- 활성화 전용 audit 레코드를 더한다. 기각한다. 결정 9대로 필드가 없고, audit의 action 문자열은 op의 `COMMAND`(`ServiceInstallOp::COMMAND`)라서 새 action은 새 dotted op를 뜻하고, `docs/CLI.md` §2.4 목록과 `op_registration_completeness.rs`의 분류를 건드린다. 활성화 사실이 audit에 남아야 한다는 요구가 생기면 `AuditRecord`의 확장을 별도 ADR로 연다.

## 결과

- `docs/CLI.md` §6.18의 세 시그니처에 플래그가 들어가고, "`status`는 존재 여부만 본다"와 "유닛 파일만 쓴다" 문장에 플래그 예외가 붙으며, `data` 필드 설명에 `activation`/`deactivation`/`active`가 더해진다. 버전 헤더에 이 변경이 오른다. 같은 커밋에서 `docs/man/qsh-service-install.1`, `qsh-service-uninstall.1`, `qsh-service-status.1`을 `cargo xtask man`으로 다시 만들고 `checked_in_man_pages_match_the_generator`가 확인한다.
- `docs/design/threat-model.md` §3의 `qsh service` 행에서 "`launchctl`/`systemctl`을 호출하지 않으므로 파싱할 외부 출력 자체가 없다"를 플래그가 있을 때의 호출과 exit code만 읽는다는 서술로 고친다. 새 위협 행으로, 매니저 호출의 인자 주입 불가(결정 3)와 재시작 부재(결정 4)를 오른다. 핀 테스트는 아래와 같다.
- 고정할 테스트(`crates/qsh-core/src/ops/service/tests.rs`, 이름은 구현 때 확정):
  - `install_without_activate_never_invokes_the_manager`, `uninstall_without_deactivate_never_invokes_the_manager`, `status_without_live_never_invokes_the_manager`: 가짜 runner의 호출 기록이 비어 있다.
  - `install_activate_runs_the_documented_argv_on_launchd`, `…_on_systemd`, `…_on_task_scheduler`: 호출 기록이 결정 3 표와 같다(Windows는 가짜 상태 질의 주입).
  - `deactivate_calls_disable_for_a_registered_but_inactive_unit`, `deactivate_skips_when_the_unit_is_not_registered`, `windows_activate_updates_the_stored_task_without_running_it_when_already_running`.
  - `activate_and_deactivate_leave_a_human_installed_always_on_form_untouched`(launchd는 LaunchDaemon 파일, 작업 스케줄러는 가짜 COM의 `Password` 주체): 매니저 호출 기록에 `bootstrap`·`/Create`·`/Run`·`/End`·`/Delete`가 없고 `activation`·`deactivation`이 `always_on_present`다. `status_live_reports_the_always_on_form_when_present`.
  - `activate_is_skipped_when_the_unit_write_fails`, `activate_is_skipped_when_the_audit_sink_fails`: 기존 `install_is_refused_when_the_audit_sink_fails`와 짝이다.
  - `activate_does_not_restart_an_already_active_unit`: active 응답에서 `bootstrap`/`restart`가 호출되지 않고 `activation`이 `already_active`다.
  - `deactivate_runs_before_the_unit_file_is_removed`, `a_failed_deactivate_keeps_the_unit_file`.
  - `a_missing_manager_binary_is_unsupported_and_a_nonzero_exit_is_internal_with_exit_code`, `a_manager_call_past_the_deadline_is_timeout`.
  - `service_md_activation_recipes_match_the_argv_builders`(`crates/qsh-core/tests/it/service_docs.rs`).
- fixture: `crates/qsh-cli/tests/fixtures/cli-v1/`에 플래그를 준 호출의 성공 envelope 세 개(`activation`, `deactivation`, `active`)를 append하고 `REQUIRED_FIXTURES`에 등록한다. 기존 service fixture는 바뀌지 않는다. `qsh.cli/v1`은 additive만 쓰고, wire 프로토콜과 `ErrorCode`는 변하지 않는다.
- `docs/deploy/service.md`가 비활성화 레시피와 `--activate` 안내를 얻는다. launchd 절의 "LaunchDaemon은 이 문서의 범위가 아니다" 문단은 결정 13의 LaunchDaemon 펜스, 설치·해제 레시피, 바이너리 이동 시 절차로 바뀐다. 상시 기동 레시피 가운데 linger와 LaunchDaemon에는 "`platform` keystore면 먼저 `qsh identity move-key --to file`"이라는 한 줄이 붙는다. Windows 상시 기동 작업 레시피에는 그 줄 대신, `Password` 주체 작업이 프로필과 DPAPI를 적재하므로 Credential Manager 키를 그대로 읽는다는 한 줄이 붙는다(결정 15의 실측 결과가 반대면 다른 두 레시피와 같은 줄이 붙는다). 같은 파일이 Windows 절의 `--activate` 안내와 비활성화 레시피(`/End`, `/Delete /F`)를 얻는다. `docs/adr/README.md` 목록의 이 ADR 상태 열을 `승인됨`으로 고치고 ADR-0024 결정 11의 "별도 결정" 문장이 이 ADR을 가리키게 하는 것은 승인 뒤 같은 커밋에서 한다.
- 2026-10-13 개정분의 착지 항목은 아래와 같다.
  - `docs/CLI.md`: §2.4 op 목록에 `identity.move_key`, `identity.*` 절에 `qsh identity move-key` 시그니처와 결과·오류, §6.17 표에 `keystore_session_bound` 행과 `launchagent_session_scoped`·`service_not_registered`의 macOS 문구 갱신, 진단 코드 개수 문장, 버전 헤더의 additive 기록.
  - `crates/qsh-core/src/doctor.rs`: `LAUNCHAGENT_SESSION_SCOPED` 문구, 새 `KEYSTORE_SESSION_BOUND`, 진단 코드 목록. `doctor/probe.rs`: LaunchDaemon 경로 존재 확인과 `service_unit_registered`의 macOS 분기.
  - `docs/man/qsh-identity-move-key.1`(`cargo xtask man`), fixture `crates/qsh-cli/tests/fixtures/cli-v1/`에 `identity.move_key` 성공 envelope 둘(`moved: true`, `moved: false`)과 `keystore_session_bound`를 담은 doctor envelope 하나를 append하고 `REQUIRED_FIXTURES`에 등록, `op_registration_completeness.rs` 분류.
  - `docs/design/threat-model.md` §3: `qsh service` 행에 "상시 기동은 사람이 설치한 파일이고 qsh는 읽기만 한다"를, 새 행 "`identity move-key`"(로컬 사용자, 개인키가 store 사이를 옮겨 가는 동안의 상태)를 더한다. §4 D(정보노출)에 파일 store로 옮긴 개인키의 0600·DACL 통제와 아래 핀 테스트를 적는다.
  - `docs/design/testing.md` L1 「플랫폼 키스토어 릴리스 전 수동 단계」에 `move-key` 왕복(platform에서 file로, 다시 platform으로)을 세 OS에 더한다.
  - ADR-0035 결정 27의 수명 항목은 "macOS 상시 기동 레시피는 ADR-0032 결정 13이다"로 고쳐 두었다(2026-10-13). 결정 28은 이 ADR의 Windows 열을 가리키도록 2026-10-14에 맞췄다. README Known limitations의 LaunchAgent 문장도 레시피를 가리키게 한다.
  - 고정할 테스트: `service_not_registered_accepts_a_launchdaemon_plist`, `launchagent_session_scoped_is_silent_when_a_launchdaemon_plist_exists`, `keystore_session_bound_fires_for_platform_store_under_launchdaemon`, `…_under_linger_with_a_registered_unit`, `keystore_session_bound_is_silent_for_file_store`, `move_key_keeps_the_fingerprint_and_device_id`, `move_key_to_the_current_store_is_a_no_op`, `a_failed_move_key_write_leaves_the_original_store_untouched`, `move_key_file_store_is_mode_0600`, `move_key_is_refused_when_the_audit_sink_fails`, `service_md_launchdaemon_recipe_matches_the_agent_program_arguments`. 실제 Keychain과 Secret Service를 쓰는 왕복은 위 수동 단계가 맡는다.
- 크기는 ADR 0.3ew(처음 판 0.2, 2026-10-13 개정 0.1)에 구현 1.0~1.5ew다(`docs/ROADMAP.md` M17 (a)). 2026-10-14에 더한 Windows 열의 구현(COM 상태 질의, `schtasks` argv, 문서 대조)은 ADR-0035 M19 크기의 `--live` COM 질의 0.1~0.2와 서비스 백엔드 0.6~1.0에 이미 들어 있어 여기에 더하지 않는다. 처음 판 0.3~0.5는 `ManagerRunner` seam과 플래그 세 개, 필드 세 개, 테스트와 문서 동기화다. 개정분 0.7~1.0은 LaunchDaemon 레시피와 문서 대조 테스트 0.1~0.2, doctor의 LaunchDaemon 인식과 `keystore_session_bound` 0.2~0.3, `identity.move_key` op(세 플랫폼 store, 원자적 순서, audit, CLI·man·fixture) 0.4~0.5다.
- 이 ADR이 `승인됨`이 되어 M17 (a)의 착수 조건이 풀렸다.
