# PLAN.md — M19: Windows client

P1 M19의 실행 계획이다. M17이 닫혀 이 문서가 M17 계획(마지막 커밋 `047db25`)을 전면 교체했다. 다음 마일스톤 순서상 M18(세션 거처)이 먼저지만 착수 조건인 M8 DoD 3(실기기 mobility 60회)이 아직 기록되지 않아 `docs/ROADMAP.md` §5.1 원칙 6대로 M18을 건너 M19를 먼저 연다. 건너뛴 사실과 날짜는 Step 1이 §5.1에 적는다. 착수 ADR인 ADR-0035(Windows client·host)는 2026-10-14 사용자 위임 결정("전부 다 알아서 진행해")으로 `승인됨`이다. 기능 의존인 ADR-0029(`qsh cp`, M15)와 ADR-0044(SSH 부트스트랩, M16)는 이미 착지했고, ADR-0032의 `ManagerRunner`·`TaskStateQuery` seam은 M17이 세웠다(`1790cad`). 그래서 M19의 착수 조건은 모두 충족됐고 새 ADR은 필요 없다(Step 1 (a) 4). 구속 근거는 다음과 같다.

- `docs/ROADMAP.md` §5의 M19 절(범위, 착수 조건, 명시적 out, 수용 기준, 크기), §5.1 시퀀싱 원칙(특히 원칙 6·7), §5.4 리스크 5(Windows 산정 신뢰도), §5.5 P1 사람 몫, 마일스톤 마감 공통 절차(같은 문서 §2), §3 유예 가드레일의 Windows 행
- ADR-0035 결정 1~28과 결과 절(특히 "마일스톤 배치"와 "크기"의 M19 항목)
- ADR-0035가 Windows 쪽 착지를 M19로 넘긴 다른 ADR의 문장: ADR-0032 결정 3·4·5·6·8·10·11·15·18(작업 스케줄러 열, `keystore_session_bound`의 Windows 실측, 상시 기동 형태 보존의 Windows 갈래), ADR-0033 결정 6·13(Windows share mode, named pipe 비노출, reverse fan-out 필터 동등), ADR-0031 결정 3과 개정 이력(재검증 감시의 Windows 쌍둥이), ADR-0029 결정 2·23(드라이브 문자 operand, client 로컬 쓰기), ADR-0044 결정 1·5·22·25(Windows client의 자동 발동과 `--reverse`), ADR-0023 결정의 절전 감지 전제(Windows 확인)
- 참조 ADR: ADR-0013(개인키는 인자·결과로 나가지 않음), ADR-0007(resume token custody), ADR-0010(audit 회전·retention), ADR-0017 결정 1(`acl.toml`을 쓰지 않음), ADR-0036(stateless reset key)
- `docs/CLI.md` §6.7·§6.9·§6.11·§6.12·§6.13·§6.14·§6.17·§6.18·§6.20·§6.21·§7
- `docs/deploy/service.md`, `docs/deploy/release-secrets.md`, `docs/design/architecture.md` §1·§4·§7·§8, `docs/design/testing.md` L1·L5와 Windows leg 문단, `docs/design/threat-model.md` §3·§4 A·B·D·E·§7
- `CLAUDE.md` "Security defaults"와 "Hard architecture rules"

이 계획과 `docs/ROADMAP.md`의 편집은 main 세션만 한다.

인용 규율은 M17판과 같다. 문서는 절 이름, ADR 번호와 결정 번호, 테스트 이름, 커밋 해시로 가리킨다. 코드 위치는 파일 경로와 심볼 이름으로 가리키고, 줄 수나 개수를 적을 때는 origin `e47ffd9` 트리에서 잰 값임을 밝힌다(Step 1이 이 기준을 유지하기로 했다). 옛 계획의 스텝은 "M17 plan Step N (`047db25`)" 꼴로만 인용한다. 코드 주석과 문서에는 이 계획의 스텝 번호를 쓰지 않는다.

**M19가 하지 않는 것(M20의 일).** Windows host 역할 전부는 M20이다. ConPTY 백엔드와 PTY 세션(ADR-0035 결정 20·21), 세션 신호 일곱의 Windows 사상과 `qsh internal console-ctrl`(결정 22), host 쪽 `exec`의 Job Object와 환경 고정(결정 23), host audit writer의 `LockFileEx` 잠금·재검증과 `acl.toml` DACL 경고(결정 24), `setup host`·`pair invite`·`pair ssh-respond`(결정 25의 나머지), host 쪽 `qsh cp`와 `paths` 드라이브 표기(결정 26, ADR-0029 결정 23), `release_smoke`의 PTY 축, `exit_code_matrix.rs`의 `session close --signal` Windows 행, PTY를 포함한 정방향·역방향 종단, 캠페인 host 회차다. M19가 걷는 Windows host 쪽 게이트는 `qsh serve --to`의 게이트 하나이고, 그 목적은 역방향 CI다(ADR-0035 결과 절 "마일스톤 배치"). M19 동안 Windows host(인바운드 `qsh serve`와 `serve --to`)는 PTY 세션과 파일 op에 `UNSUPPORTED`로 답하고 `exec`와 터널만 낸다. 이 중간 상태는 지원 약속이 아니다.

## 0. 열린 사람 몫

여기 적힌 항목은 이 파일이 다음 계획으로 바뀔 때 그대로 승계한다. M17 계획 §0의 상태를 M17 마감 시점 그대로 옮겼다(main 세션이 Step 1에서 M17 마감 노트와 대조한다).

### 0.1 P0에서 열린 일곱

- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** 기준은 `docs/campaigns/m10-clean-vm.md`. Linux 회차는 PASS(v0.3.0 세 회차 `69a6414`, v0.4.3 Ubuntu 24.04 x86_64 회차 4, 2026-10-09). macOS arm64·x86_64 두 회차가 남았고 둘 다 클린 macOS VM과 Gatekeeper 판정이 필요하다. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 서명·공증 태그는 `v0.4.0`부터 있다. 회차는 `docs/campaigns/m10-clean-vm.md`. 소유: 사람.
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** `x86_64-unknown-linux-musl` 한정. Debian 10(glibc 2.28) 회차 2(v0.3.0)와 회차 5(v0.4.3, 2026-10-09)가 `DoD 3 = PASS`다. 캠페인 §9 판정과 함께 닫히므로 macOS 두 회차를 기다린다. 두 회차 모두 에이전트가 컨테이너에서 돌렸으니, 캠페인을 닫을 때 사람이 이것을 회차로 셀지 다시 본다. 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** 기준은 `docs/campaigns/m7-stopwatch.md`(예행 1회만 끝남). 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** 기준은 `docs/campaigns/m2-mobility.md`. M18의 착수 조건이고, 이것이 닫히지 않아 M19를 먼저 열었다. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** 저장소 밖 조직 액션. 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** 기준은 `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 소유: 사람.

### 0.2 P1 마일스톤이 만든 사람 몫 (`docs/ROADMAP.md` §5.5)

- [ ] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 기록 자리는 `docs/campaigns/m8-fuzz.md`. 출처 M11. 소유: 사람.
- [ ] **`p1-supervise-wake` 회차 넷.** 기준은 `docs/campaigns/p1-supervise-wake.md`. 출처 M12. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 기준은 `docs/campaigns/p1-setup-stopwatch.md`(ADR-0024 결정 12). 출처 M12. PASS가 기록되기 전에는 이슈 #3 완료 기준 첫 줄이 충족됐다고 적지 않는다. 소유: 사람.
- [ ] **`decode_file_frame` fuzz 타깃의 누적 72 fuzz-hours.** M15 (b)가 타깃을 더했다(`a86123d`). 기록 자리는 `docs/campaigns/m8-fuzz.md` 형식이고 §5.5 표의 "새 파서 fuzz 타깃" 행에 상태를 적는다. 공개 beta 전(`docs/design/protocol.md` §13). 소유: 사람.

### 0.3 M16이 만든 사람 몫 (`docs/ROADMAP.md` §5.5)

- [ ] **`parse_ssh_bootstrap_line` fuzz 타깃의 누적 72 fuzz-hours.** 타깃은 `aba7bd6`이 더했다(smoke 20,000 runs만). 기록 자리는 `docs/campaigns/m8-fuzz.md` 형식이고 §5.5 표의 "새 파서 fuzz 타깃" 행에 상태를 적는다. 공개 beta 전(`docs/design/protocol.md` §13). 소유: 사람.
- [ ] **실제 OpenSSH 위의 SSH 부트스트랩 회차.** 기준은 `docs/campaigns/p1-ssh-bootstrap.md`(사전 고정 `e8cd7a3`). ProxyJump, ssh-agent, 암호 걸린 키, `--reverse` 한 회. 그 문서의 R5(Windows client 명시 `qsh pair ssh`)는 요건 4·6(`qsh box`의 대화형 attach와 `qsh cp`)을 M19로 미뤘고, 그 몫은 이 계획 Step 14가 `docs/campaigns/p1-windows.md`에 회차로 받는다(§9 #10). 소유: 사람.

### 0.4 M17이 만든 사람 몫

M17은 새 캠페인 문서를 만들지 않았다(M17 plan §0.4 (`047db25`)). 실제 Keychain·Secret Service 위의 `move-key` 왕복은 `docs/design/testing.md` L1의 릴리스 전 수동 단계이고 §1이 추적한다.

### 0.5 M19가 새로 만드는 사람 몫

- [ ] **Windows client 확인 회차.** 문서 `docs/campaigns/p1-windows.md`는 Step 14가 구현 마지막 스텝(Step 15) 전에 사전 고정한다(ADR-0035 결정 18). M19 몫은 client·서비스·서명·패키지 회차((1), (3)의 Windows `qsh listen` 쪽, (4), (5), (6), (8), (9), (10), (11))이고, host 회차((2), (3)의 Windows target 쪽, (7))는 M20이 더해 다시 고정한다. 회차는 Windows 자산이 붙은 태그에서 돈다. 소유: 사람.
- [ ] **Windows 서명·배포 준비(ADR-0035 결정 16, 결과 절 "사람이 할 일").** SSL.com 개인 신원 검증 코드 서명 인증서 구매와 신원 확인, eSigner 등록과 TOTP 발급, 저장소 시크릿 넷 `WINDOWS_SIGN_ESIGNER_USERNAME`·`WINDOWS_SIGN_ESIGNER_PASSWORD`·`WINDOWS_SIGN_ESIGNER_CREDENTIAL_ID`·`WINDOWS_SIGN_ESIGNER_TOTP_SECRET`과 저장소 변수 `WINDOWS_SIGN_EXPECTED_SUBJECT`, `DaveDev42/scoop-bucket` 저장소와 배포 키 `SCOOP_BUCKET_DEPLOY_KEY`, `WINGET_PAT`과 `DaveDev42.qsh` 첫 매니페스트의 수동 제출. M19를 막지 않는다. 시크릿이 없는 동안 서명·검증 스텝은 경고와 함께 건너뛰고 scoop·winget job은 green인 채 건너뛴다. 소유: 사람.

에이전트는 `gh secret set`, `gh variable set`, `gh workflow run`, 태그 push, 저장소 설정 변경, 외부 저장소(`scoop-bucket`, `winget-pkgs`) 쓰기를 어느 스텝에서도 하지 않는다. 시크릿은 이름만 문서에 적고 값은 어디에도 적지 않는다(`docs/deploy/release-secrets.md`).

## 1. 유지보수에서 남은 확인

M17 계획 §1의 네 항목을 M17 마감 시점 상태로 승계한다(main 세션이 Step 1에서 채운다).

- [ ] macOS Keychain 왕복(`08a6173` 이후 keyring-core 1). `docs/design/testing.md` L1 수동 단계.
- [ ] 다음 태그 run에서 `release.yml` 액션 갱신(`1557f50`) 뒤의 서명·공증·provenance 확인.
- [ ] `qsh identity move-key` 왕복을 macOS Keychain·Linux Secret Service에서. Windows Credential Manager 왕복은 Step 5가 L1에 줄을 더하고 같은 회차에 묶는다(ADR-0035 결정 12).
- [ ] `launchctl print system/io.qsh.<mode>`의 root 요구 확인(ADR-0032 결정 18 셋째 항목, M17 plan §9 #5 (`047db25`)).

M19가 더하는 확인은 다음과 같다.

- [ ] Windows Credential Manager 위의 `qsh init --key-store platform` → `move-key --to file` → `move-key --to platform` 왕복. Step 5가 `docs/design/testing.md` L1에 Windows 줄로 더하고, Dave-Windows(`ssh dave-windows.tail91e9e.ts.net`)에서 에이전트가 태그 전에 돌려 결과를 커밋 본문에 적는다. CI 러너가 실제 Credential Manager 쓰기를 허용하면 Step 5의 자동 테스트가 이를 대신 고정한다(§7.1 #6).
- [ ] 첫 서비스 스텝(Step 10)이 실측하는 셋. (i) `RestartOnFailure`가 실행 중 동작의 비정상 종료에도 다시 띄우는지(ADR-0035 결정 27 재시작 항목), (ii) 일반 사용자가 `BootTrigger`·`LogonType=Password` 작업을 관리자 없이 등록할 수 있는지(결정 27 수명 항목), (iii) `LogonType=Password` 작업이 Credential Manager 항목을 읽는지(ADR-0032 결정 15 첫 항목, ADR-0035 결정 12). (iii)은 Step 11이 `keystore_session_bound`의 Windows 판정에 쓴다. 셋 모두 Dave-Windows에서 에이전트가 사람 승인 아래 돌리고 결과를 커밋 본문과 `docs/deploy/service.md`에 적는다. 실제 작업 등록은 Dave-Windows의 테스트 계정 작업 이름(`\qsh-test\…`)으로만 하고 끝나면 지운다.
- [ ] `schtasks /Create /F`가 실행 중 인스턴스를 멈추는지(ADR-0032 결정 4). Step 11이 같은 머신에서 실측한다.

## 2. 테스트 환경

M17과 같고, Windows가 주 무대가 된다.

- CI는 `ci.yml`의 `windows-latest` leg(clippy, `cargo nextest run --workspace`, `cargo doc -D warnings`)이 착지 판정이다. M19는 이 leg에서 `cfg(unix)`로 빠져 있던 client·reverse 테스트를 `cfg(windows)` 쌍둥이로 연다. ConPTY probe는 `qsh-testkit`의 작은 실행 파일과 `portable-pty`(Windows dev 의존)로 러너 위에서 돈다(ADR-0035 결정 17, 결과 절 "의존 추가").
- 로컬 Windows 검사는 Dave-Windows(16c/64GB, `ssh dave-windows.tail91e9e.ts.net`, pwsh)에서 네이티브로 `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace`, `cargo doc`을 돌린다. M17까지 쓰던 `cargo xwin clippy`는 Linux에서의 빠른 컴파일 확인으로만 남는다. 로컬 검사로 CI를 대신하지 않는다.
- 실제 외부 상태를 건드리지 않는 주입점은 M17의 셋(가짜 `ManagerRunner`, `KeyStore` 주입, doctor probe의 `system_root`)에 넷을 더한다.
  - 가짜 `TaskStateQuery`와 가짜 작업 정의 읽기(주체 `InteractiveToken`/`Password`/읽기 실패). 실제 COM을 부르는 테스트는 `status --live`의 Windows 실경로 하나만 둔다(§7.1 #9).
  - "프로세스 ID → 사용자 SID" 함수 주입(ADR-0035 결정 17 (3)). 진짜 둘째 계정은 캠페인 (5)다.
  - DACL 적용 실패 주입(결정 17 첫 항목).
  - Credential Manager 백엔드 주입(`MemoryKeyStore` 자리, Step 5).
- 부하 반복은 두 곳에서 돈다. Linux·공통 테스트는 지금처럼 Dave-Windows-WSL(8 vCPU)의 `scripts/stress/run.sh`, Windows 전용 타이밍 민감 테스트는 Dave-Windows에서 Git for Windows bash로 같은 스크립트를 돌린다(§7.1 #12). 두 결과를 마감 노트에 따로 적는다.

## 3. DoD 체크리스트 (ROADMAP M19)

체크박스는 근거가 되는 테스트와 CI run이 초록일 때만 채운다.

- [x] **착수 — ADR-0035가 `승인됨`이다.** 근거: `09266dc`(2026-10-14). 소유: 에이전트(main 세션 확인).
- [ ] **DoD 1 — Windows leg의 역방향 종단과 콘솔 계층.** 실제 CLI로 Windows `qsh listen` ← Windows `qsh serve --to`의 `exec`, 터널 echo, `qsh hosts`의 reverse 항목, 데몬 재시작 뒤 재등록(`windows_reverse_e2e::`), 같은 케이스 목록의 정방향 쌍둥이(`windows_forward_e2e::`), ConPTY probe로 raw 입력·resize 폴링·모드 복원·초대 코드 에코 부재(`console_probe::`). ROADMAP 문장의 "ADR-0029 착지 뒤 `qsh cp`"는 Windows host 파일 op가 M20이라 이 leg에서 돌 수 없다. client 쪽 `cp`는 Step 9의 단위·통합 테스트가 고정하고 종단은 M20 DoD로 옮긴다(§9 #1). 근거: Step 3·7·9.
- [ ] **DoD 2 — 소유자 전용 DACL과 fail closed.** identity 키, `resume.json`, `trust.toml`, audit 로그, `stateless_reset.key`(그리고 ADR-0035 결정 9 목록 전부)가 보호된 단일 ACE DACL로 만들어지고, 적용할 수 없으면 파일을 만들지 않는다. `windows_private_files_have_an_owner_only_protected_dacl`, `a_dacl_failure_creates_no_file`. 근거: Step 4.
- [ ] **DoD 3 — named pipe localctl.** 이름 선점 시 기동 실패, 보호 DACL, 주입한 SID 불일치 거부(서버·클라이언트). `listen_fails_before_the_quic_listener_when_the_pipe_name_is_taken`, `pipe_instance_dacl_is_protected_and_owner_only`, `pipe_server_drops_a_client_with_another_sid_before_reading_a_frame`, `pipe_client_writes_nothing_to_a_server_with_another_sid`. 근거: Step 6·7.
- [ ] **DoD 4 — 작업 정의 펜스와 `logon_task_session_scoped`.** `service_md_windows_task_fence_matches_the_renderer`(바이트 단위), `logon_task_session_scoped_fires_for_an_interactive_token_task`, `logon_task_session_scoped_is_silent_for_a_password_task`, `logon_task_session_scoped_is_silent_when_the_task_cannot_be_read`. 근거: Step 10.
- [ ] **DoD 5 — `exit_code_matrix.rs`에 client 쪽과 서비스 명령의 Windows 전용 `UNSUPPORTED` 행이 없다.** 남는 Windows 행은 host 쪽 `session open`(PTY, M20) 하나다. 근거: Step 9·11, 확인 Step 16.
- [ ] **DoD 6 — 출고.** `release.yml` Windows leg이 Authenticode 서명 뒤 `signtool verify /pa /v`와 `Get-AuthenticodeSignature`로 상태·주체·타임스탬프를 검증하고, zip의 `man/`이 `docs/man/`과 같음을 대조하며, scoop·winget job이 `homebrew-tap`과 같은 게이트로 돈다. 근거: Step 12·13·15.
- [ ] **DoD 7 — 위협 모델.** §3에 Windows 콘솔 입력·localctl named pipe·Windows 작업 스케줄러 작업 정의 진입점이, §4에 pipe 선점·가짜 데몬(A)·다른 사용자 접속(B)·DACL(D)이, §7에 PID 재사용 틈이 오른다. 각 행은 그 통제를 구현한 스텝에서 오른다. 근거: Step 3·4·6·10.
- [ ] **DoD 8 — 캠페인 문서 `docs/campaigns/p1-windows.md` 사전 고정.** 구현 마지막 스텝(Step 15) 전 커밋. 근거: Step 14.
- [ ] **DoD 9 — README Known limitations·설치 절과 ROADMAP §3 Windows 행.** README는 Step 16, §3 행은 main 세션이 마감 노트와 함께.
- [ ] **DoD 10 — ADR-0032 Windows 열과 `move-key` 왕복.** `install_activate_runs_the_documented_argv_on_task_scheduler`, `windows_activate_updates_the_stored_task_without_running_it_when_already_running`, `activate_and_deactivate_leave_a_human_installed_always_on_form_untouched`(작업 스케줄러 행), `status_live_reports_the_always_on_form_when_present`(작업 스케줄러 행), `service_md_activation_recipes_match_the_argv_builders`(Windows 행)가 Windows leg에서 초록이고, `move_key_round_trips_between_credential_manager_and_file_with_the_same_fingerprint`가 Windows leg에서 초록이다. 근거: Step 5·11.
- [ ] **계획 규율 — route 동등(§5.1 원칙 7).** Windows client에서 여는 기능마다 forward와 reverse route의 같은 테스트가 Windows leg에서 초록이다(§4 규율 "route 동등" 표). 근거: Step 7~9.
- [ ] **계획 규율 — M19 유예 전수 귀속.** `rg -n "M19"`의 모든 hit가 §5.7의 표에서 스텝이나 M20·범위 밖 사유에 귀속돼 있고, 착지 뒤에는 그 문장이 착지 상태로 고쳐졌다. 근거: Step 16.
- [ ] **안정성 — 새 타이밍 민감 테스트의 부하 반복.** M19가 더한 타이밍 민감 테스트 전부가 `scripts/stress/m19.filter`로 묶여 Linux(Dave-Windows-WSL)와 Windows(Dave-Windows) 각각에서 CPU 부하 아래 50회 연속 초록이다. M19에는 지연 예산 단언이 없으므로 `-j 1` 대체 필터를 두지 않는다. ROADMAP M19 DoD에는 아직 이 줄이 없고 Step 1이 더한다(§9 #2). 근거: Step 3·6·7·8·9·10·16.
- [ ] **DoD 마감 — 마감 공통 절차(§2) 1·2.** 근거: Step 16.

## 4. 실행 단계 (PR 단위)

스텝 번호는 이 문서 안에서만 쓰는 참조다. 크기는 ADR-0035 결과 절 "크기"의 M19 내역을 그대로 나눈 것이다.

| ADR-0035 산정 항목 | 크기(ew) | 스텝 |
|---|---|---|
| 첫 개정 client 범위(test-only 하니스 제외) | 5.6~9.3 | Step 2(0.5~1.0), 3 중 0.8~1.3, 4(0.7~1.1), 5(0.4~0.7), 6(1.1~1.8), 7 중 0.7~1.2, 8 중 0.2~0.3, 9(0.8~1.3), 14(0.3~0.4), 16(0.1~0.2) |
| 초대 코드 에코 억제와 ConPTY 단언 | 0.1~0.2 | Step 3 |
| `serve --to` 게이트 제거와 PTY 없는 역방향 CLI 종단 | 0.1 | Step 7 |
| 절전 감지 표본 함수 | 0.1~0.2 | Step 8 |
| 서비스 백엔드 | 0.6~1.0 | Step 10(0.5~0.8), Step 11(0.1~0.2) |
| 상시 기동 레시피와 `logon_task_session_scoped` COM 읽기 | 0.2~0.4 | Step 10 |
| `--live` COM 질의 | 0.1~0.2 | Step 11 |
| aarch64 자산과 `install.ps1`, zip의 man 페이지와 목록 대조 | 0.3~0.5 | Step 12 |
| Authenticode 서명·검증, 시크릿 게이트, `release-secrets.md` | 0.3~0.5 | Step 13 |
| scoop·winget job과 매니페스트 | 0.3~0.5 | Step 15 |
| 합 | 7.7~12.9 | ROADMAP M19 크기와 같다 |

스텝별 크기는 다음과 같다. Step 1은 크기 내역 밖이다.

| 스텝 | 내용 | 크기(ew) |
|---|---|---|
| 2 | 터미널 trait 추출, ConPTY probe 하니스, 모드 계산 순수 함수, keystore 경로 판정, 재산정 | 0.5~1.0 |
| 3 | Windows 콘솔 계층(raw·VT·복원·resize 폴링·하한)과 초대 코드 프롬프트 | 0.9~1.5 |
| 4 | 소유자 전용 DACL 모듈과 적용처 전부 | 0.7~1.1 |
| 5 | Credential Manager `platform` store와 Windows `move-key` 왕복 | 0.4~0.7 |
| 6 | named pipe localctl transport | 1.1~1.8 |
| 7 | Windows reverse 역할: `qsh listen`·`setup listener`·`serve --to` 게이트, reverse dial, `hosts`·`tunnels` 데몬 항목, 정방향·역방향 CLI 종단 | 0.8~1.3 |
| 8 | supervise와 절전 감지, reverse 쌍둥이(신뢰 철회 `listen`, 세션 필터 fan-out) | 0.3~0.5 |
| 9 | client 기능 동등: 대화형 attach, `-L`/`-R`/`-D`, `qsh cp` client, 자동 부트스트랩, `pair ssh --reverse`의 이 장비 쪽, doctor, `release_smoke` | 0.8~1.3 |
| 10 | 작업 스케줄러 서비스 백엔드, `qsh service run`, 상시 기동 레시피, `logon_task_session_scoped` | 0.7~1.2 |
| 11 | ADR-0032 Windows 열: `schtasks` argv, COM `TaskStateQuery`, `--live`, 상시 기동 형태 보존, `keystore_session_bound` Windows 판정 | 0.2~0.4 |
| 12 | aarch64 자산, `install.ps1`, zip의 man 페이지와 목록 대조 | 0.3~0.5 |
| 13 | Authenticode 서명·검증과 시크릿 게이트 | 0.3~0.5 |
| 14 | 캠페인 문서 `p1-windows.md` 사전 고정 | 0.3~0.4 |
| 15 | scoop·winget job | 0.3~0.5 |
| 16 | 마감 | 0.1~0.2 |
| 합 | | 7.7~12.9 |

Step 2 뒤 main 세션이 이 표와 ROADMAP §5.2·§5.4 리스크 5를 다시 매긴다(ROADMAP M19 크기 줄, ADR-0035 결과 절 마지막 항목).

**순서의 근거.**

- 콘솔(Step 2·3)을 맨 앞에 둔다. ADR-0035 결과 절과 ROADMAP §5.4 리스크 5가 첫 스텝을 "콘솔 probe·터미널 trait 추출과 `cfg(unix)` 게이트 제거"로 정했고, 재산정의 근거가 여기서 나온다. trait 추출은 unix 동작을 바꾸지 않는 리팩터라 Windows 구현(Step 3)과 나눠 unix 회귀(`tui_expect::`)를 먼저 확인한다.
- DACL 모듈(Step 4)은 Credential Manager의 `auto` 대체(Step 5), named pipe 인스턴스(Step 6), 작업 정의 파일과 서비스 로그(Step 10)가 모두 부르므로 그 셋보다 앞이다. 콘솔 사슬과는 코드가 겹치지 않아 병렬이다.
- named pipe(Step 6)는 `qsh listen`(Step 7)의 전제다. pipe transport와 데몬 기동을 한 PR에 넣으면 1.9~3.1ew가 되므로 transport·자격 확인·이름 규칙(Step 6)과 run mode 개방·종단(Step 7)으로 나눈다. 이름 선점 시 "QUIC listener를 열기 전에 실패"는 기동 경로의 성질이라 Step 7이 단언한다.
- 대화형 attach의 Windows 개방(`tui::run`의 비unix 분기 제거)은 Step 3이 아니라 Step 9에 둔다. reverse route의 attach는 localctl 위 reverse dial(Step 7)이 있어야 하고, 한쪽 route만 여는 PR은 착지하지 않기 때문이다(§4 규율 "route 동등"). Step 3은 route와 무관한 콘솔 계층만 연다.
- 서비스(Step 10·11)는 DACL 뒤면 언제든 열 수 있어 콘솔·pipe 사슬과 병렬이다. Step 11은 Step 10의 작업 정의 경로와 COM 읽기를 쓴다. `setup listener --service`는 Step 7의 `setup listener`와 Step 10의 백엔드가 모두 있어야 하므로 Step 10이 Step 7 뒤면 Step 10이, 앞이면 Step 7이 그 테스트를 착지시킨다.
- 출고(Step 12·13·15)는 `release.yml`만 만지므로 Step 1 직후부터 병렬이다. 캠페인 문서(Step 14)는 ADR-0035 결정 18이 "구현 마지막 스텝 전"을 요구하므로 마지막 구현 스텝(Step 15) 앞에 둔다. 회차 (11)이 세 설치 경로를 보므로 `install.ps1`(Step 12)과 서명(Step 13)의 이름이 굳은 뒤에 쓴다.

**의존과 병렬.**

| 스텝 | 선행 | 다른 에이전트와 병렬 가능 여부 |
|---|---|---|
| Step 2 | Step 1 | Step 4·12와 병렬 |
| Step 3 | Step 2 | Step 4·5·6·10·12·13과 병렬 |
| Step 4 | Step 1 | Step 2·3·12와 병렬 |
| Step 5 | Step 4 | Step 3·6·10·12·13과 병렬 |
| Step 6 | Step 4 | Step 3·5·10·12·13과 병렬. `xtask/src/arch.rs`를 만지는 유일한 스텝 |
| Step 7 | Step 6 | Step 10·12·13과 병렬 |
| Step 8 | Step 7 | Step 9·10·11과 병렬 |
| Step 9 | Step 3, Step 7(reverse attach·`-R`), Step 5(`init`의 `auto`) | Step 8·10·11과 병렬. `exit_code_matrix.rs`·`release_smoke.rs`는 Step 11과 같은 줄 근처라 rebase |
| Step 10 | Step 4 | Step 3·5·6·7·8·9와 병렬. `docs/CLI.md` §6.17·§6.18은 Step 11과 겹침 |
| Step 11 | Step 10 | Step 8·9와 병렬 |
| Step 12 | Step 1 | 전부와 병렬(`release.yml`, `scripts/`) |
| Step 13 | Step 12 | 전부와 병렬 |
| Step 14 | Step 3·5·7·9·10·12·13(회차가 가리키는 명령과 자산 이름) | Step 15 앞 |
| Step 15 | Step 12, Step 14 | — |
| Step 16 | 전부 | — |

**규율.** 앞 마일스톤 그대로이고 M19에서 몇 가지를 덧붙인다.

- 각 스텝은 일곱 게이트(`cargo fmt --all --check`, clippy `-D warnings`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`, `cargo xtask arch`, `cargo deny check`)가 초록인 채로 착지한다. clippy·test·doc은 `ci.yml`의 네 test 다리(`ubuntu-24.04`, `ubuntu-24.04-arm`, `macos-14`, `windows-latest`)에서 돈다. `cfg(windows)` 코드를 더하는 스텝(Step 2~11)은 push 전에 Dave-Windows에서 네이티브 clippy·nextest·doc을 돌리고, unix 쪽을 리팩터하는 스텝(Step 2·6·7)은 Linux와 macOS 다리를 같은 무게로 본다. 착지 판정은 CI 초록이다.
- **unix 회귀 0.** 터미널 trait 추출(Step 2)과 localctl transport 분리(Step 6), reverse 쌍둥이 제거(Step 7)는 unix 동작을 바꾸지 않는다. `tui_expect::`, `attach_ops::`, `attach_recovery::`, `localctl_perms::`, `reverse_e2e::`, `hosts_reverse::`, `reverse_blackout::`, `tunnel_supervise::`, `trust_withdrawal::` 기존 테스트가 고치지 않은 채 초록이어야 한다. acceptance job(`tui_expect`, `reverse_blackout`, `quinn_idle_timeout_as_idle_timeout`, 터널·파일 echo 예산, `socks_curl`, supervised 50초 blackhole)도 같다.
- **Windows 의존.** `windows-sys`는 `qsh-core`·`qsh-cli`의 `[target.'cfg(windows)'.dependencies]`로만 들어오고 feature는 스텝마다 필요한 것만 더한다(콘솔 Step 3, 보안·파일 Step 4, 자격 증명 Step 5, pipe·프로세스 Step 6, 전원·시간 Step 8). 작업 스케줄러 COM은 `windows` crate의 해당 feature만 `qsh-core`의 `cfg(windows)`로(Step 10). `portable-pty`는 `qsh-testkit`의 Windows dev 의존(Step 2). 새 의존마다 같은 커밋에서 `cargo deny check`가 초록이어야 한다. 의존 방향 행렬은 바뀌지 않는다.
- 계약 문서 델타는 그 표면을 바꾼 스텝의 같은 커밋에 싣는다.
  - `docs/CLI.md` 상태 헤더는 M17 마감 뒤의 다음 판(가칭 v0.N)을 CLI.md를 처음 고치는 스텝이 열고, 뒤 스텝은 덧붙이거나 다음 판을 연다(`crates/qsh-core/tests/it/cli_md_header.rs` 핀).
  - additive 계약은 ADR-0035 결과 절의 셋이 전부다. M19 몫은 `manager` 값 `"task_scheduler"`(§6.18, Step 10)와 doctor finding `logon_task_session_scoped`(§6.17, `EXPECTED_DOCTOR_CODES`, 진단 개수 27 → 28, Step 10)다. 세션 환경변수 `QSH_SIGNAL_EVENT_USR1`·`USR2`는 M20이다.
  - 숨김 subcommand `qsh service run <mode>`(Step 10)는 `hide = true`이고 `docs/man/`은 바뀌지 않는다. `checked_in_man_pages_match_the_generator`가 숨김 항목을 렌더하지 않음을 Step 10이 확인한다(ADR-0035 결과 절 "계약").
  - clap 트리가 바뀌는 스텝이 있으면 같은 커밋에서 `cargo xtask man`을 돌린다. M19의 공개 플래그 변화는 예상되지 않는다.
- 판정 로직은 `qsh-core`에 둔다. DACL(`fsutil` 하위 새 모듈), Credential Manager store(`identity/keystore.rs` 옆), named pipe transport(`localctl/transport/windows.rs`), 절전 표본(`client/wake.rs`), 작업 정의 렌더러·COM 읽기(`ops/service/`)는 `qsh-core`다. `qsh-cli`에는 Win32 콘솔 계층(`tui/windows.rs`, ADR-0035 결정 4)과 렌더러만 둔다. 콘솔 모드 비트 계산 같은 순수 함수는 `cfg` 없이 두어 네 다리 모두에서 테스트가 돈다(M17 plan §7.1 #1 (`047db25`)과 같은 규율).
- **wire 소유.** M19의 어느 스텝도 `.proto`를 바꾸지 않는다(ADR-0035 결과 절 "계약", 결정 14의 `qsh.local.v1` 불변). 완료 판정마다 다음을 확인한다.
  - `git diff --stat -- crates/qsh-proto/proto crates/qsh-proto/src/wire.rs crates/qsh-proto/src/local.rs crates/qsh-cli/tests/fixtures/cli-v1/capabilities.json`이 비어 있다.
  - `ErrorCode`는 바뀌지 않는다. 새 실패는 기존 코드(`UNSUPPORTED`는 Windows 10 1809 미만 VT 하한 하나, `CONFIG_ERROR`, `INTERNAL`, `TIMEOUT`, `INVALID_ARGUMENT`)에 붙는다.
  - capability 문자열은 바뀌지 않는다. Windows host는 M19 동안 `file.v1`을 광고하지 않는다(ADR-0029 결정 23).
- fixture는 추가만 한다. ADR-0035 결과 절은 새 fixture가 없다고 적는다. 그대로 따르되, `logon_task_session_scoped`의 doctor fixture를 둘지는 M17의 `doctor.run.keystore_session_bound.json` 선례와 함께 Step 10이 정한다(§7.1 #10). 기존 fixture는 고치지 않은 채 초록이다.
- **테스트 배치.** 통합 테스트는 `crates/<crate>/tests/it/<name>.rs` 모듈로 두고 같은 커밋에서 `tests/it/main.rs`에 `mod <name>;`을 등재한다. Windows 전용 모듈(예: `console_probe`, `windows_reverse_e2e`)도 같은 규칙이고, 모듈 안에서 `#![cfg(windows)]`로 가른다. `cfg(unix)` 테스트의 `cfg(windows)` 쌍둥이는 가능하면 같은 함수 본문을 두 cfg에서 부르는 꼴로 둔다(`cp_e2e.rs`의 `round_trip` 공유 선례). 쌍둥이를 가질 수 없는 테스트는 빠진 이유를 주석으로 남긴다(ADR-0035 결정 3).
- **route 동등(§5.1 원칙 7, PRD §4, 예외 없음).** Windows client에서 여는 기능마다 forward route(Windows `qsh` → Windows 인바운드 `qsh serve`)와 reverse route(Windows `qsh` → Windows `qsh listen` 데몬 → Windows `qsh serve --to`)를 같은 케이스 목록으로 Windows leg에서 돈다. 같은 러너의 loopback이다(ADR-0035 결정 17). PTY 세션이 필요한 케이스는 Windows host PTY가 M20이라 이 계획에서는 qsh-testkit의 `EchoPipeFactory` host로 대신하고(§7.1 #4), 실제 PTY 쌍둥이는 M20이 같은 목록에 더한다. 한쪽 route만 덮는 PR은 착지하지 않는다. 기능별 배치는 다음과 같다.

  | 기능 | forward 테스트 | reverse 테스트 | 스텝 |
  |---|---|---|---|
  | `exec` | `windows_forward_e2e::exec_round_trip` | `windows_reverse_e2e::exec_round_trip` | 7 |
  | `-L` 터널 echo | `windows_forward_e2e::local_tunnel_echo` | `windows_reverse_e2e::local_tunnel_echo` | 7 |
  | `-R` 터널 echo | `windows_forward_e2e::remote_tunnel_echo` | `windows_reverse_e2e::remote_tunnel_echo` | 7 |
  | `qsh hosts`·`tunnels`·`tunnel close` | forward 항목만(데몬 없음은 오류 아님) | 데몬의 reverse 항목, 데몬 재시작 뒤 재등록 | 7 |
  | supervise·절전 감지 | `-L`/`-D --supervise` | `-R --supervise`(데몬 carrier) | 8 |
  | 신뢰 철회 | inbound `serve`(M16에서 이미 Windows) | `listen` 등록 연결(이 계획), `serve --to` 연결(§9 #3) | 8 |
  | `qsh sessions` 필터 | forward host | `qsh listen` 데몬 fan-out의 reverse 항목 | 8 |
  | 대화형 attach·detach·resume | echo host forward | echo target reverse | 9 |
  | `-D` SOCKS | `windows_forward_e2e::dynamic_forward_connect` | `windows_reverse_e2e::dynamic_forward_connect` | 9 |
  | `qsh cp` client | 단위·통합(드라이브 문자, 로컬 쓰기). 종단은 M20 | 같음. 종단은 M20 | 9 |
  | 자동 부트스트랩 | 가짜 ssh로 `qsh box` 대화형 form | 가짜 ssh로 `--reverse` 뒤 `qsh listen` 쪽 | 9 |
  | `qsh service`·`--service` | `serve` mode 유닛 | `listen`·`reverse` mode 유닛 | 10·11 |
  | `move-key` | 이동 뒤 inbound `serve` handshake | 이동 뒤 `listen`·`serve --to` handshake | 5 |
  | `qsh audit` | `serve`가 쓴 레코드 | `listen`·`serve --to`가 쓴 레코드 | 7 |

- **플랫폼 동등.** 결정의 동작은 세 OS에서 같다. unix에 없는 Windows 고유 통제(DACL, pipe SID 대조)는 unix 대응물(0600/0700, `peer_cred`)과 같은 성질을 같은 이름 꼴의 테스트로 단언한다. Windows host 쪽 차이는 M20으로 미루고, 스텝마다 그 스텝의 "M20" 항목에 무엇을 미루는지 적는다.
- 손대는 소스 파일이 800줄을 넘으면 인라인 테스트를 같은 커밋에서 형제 `tests.rs`로 옮긴다. origin `e47ffd9` 기준 `crates/qsh-core/src/reverse/listen.rs`(1197줄), `localctl/client.rs`(1480줄), `localctl/daemon.rs`(2139줄), `tunnel/remote.rs`(1489줄), `ops/service/mod.rs`(871줄), `crates/qsh-cli/src/main.rs`(2595줄)가 이미 넘었으므로 인라인 테스트가 남아 있는지 먼저 확인한다. `tui/unix.rs`(768줄)는 Step 2의 추출로 줄어들 것이고, 새 `tui/windows.rs`와 `localctl/transport/windows.rs`는 처음부터 `tests.rs`를 둔다.
- 안정성 규율은 M17과 같다. 시계를 주입하고(resize 폴링 200 ms, 절전 표본, 매니저 호출 30초 기한), 관찰 가능한 상태를 넉넉한 `timeout`으로 기다리며, 고정 `sleep()`은 쓰지 않는다. resize 폴링 테스트는 "폴링이 한 번만 콜백을 부른다"를 ConPTY 크기 변경 뒤 콜백 기록으로 기다려 단언하고 간격 자체를 재지 않는다. 타이밍 민감 테스트(ConPTY probe, 실제 QUIC loopback, 실제 프로세스 기동, pipe accept 경합, 데몬 재시작 재등록)는 그 스텝의 완료 판정에서 부하 아래 50회 연속 초록이어야 착지한다. `scripts/stress/m19.filter`의 초안은 타이밍 민감 테스트를 처음 더하는 스텝이 만들고 Step 16이 완성한다. 흔들리는 테스트는 대기 조건을 고친다. 필터에서 빼거나 `-j 1`로 옮기지 않는다.

### Step 1 — M19 계획 교체와 ROADMAP 갱신 (main 세션, 크기 내역 밖) ✅ 2026-10-16

근거: `docs/ROADMAP.md` 현재 위치, §5.1 원칙 6, M19 절, ADR-0035 결과 절. 선행: M17 마감(M17 plan Step 8 (`047db25`))과 그 마감 노트.

**(a) 범위:**

1. `PLAN.md`를 이 문서로 바꾼다. ROADMAP M17 마감 노트에 M17 계획의 마지막 커밋 해시가 적혀 있는지 확인하고 이 문서의 `047db25` 자리 전부를 그 해시로 바꾼다. 줄 수·개수의 기준 `e47ffd9`는 그대로 둔다. 그 뒤 M17 커밋은 `qsh audit` 표면과 문서만 더했고 측정 대상의 기준을 고정 해시로 두는 편이 재현 가능하다. §0·§1의 승계 상태를 M17 마감 노트와 대조한다.
2. `docs/ROADMAP.md`를 고친다.
   - 현재 위치를 "현재 마일스톤은 M19"로 바꾸고 M17 닫힘을 적는다.
   - §5.1 원칙 6 아래에 "M18의 착수 조건(M8 DoD 3)이 닫히지 않아 M18을 건너 M19를 먼저 열었다(날짜)"를 적는다.
   - M19 DoD에 안정성 줄을 더한다(§9 #2).
   - M19 DoD 첫 줄의 "ADR-0029 착지 뒤 `qsh cp`"를 M20 DoD로 옮기고 M19 쪽은 client 쪽 단위·통합 테스트로 바꾼다(§9 #1).
   - M19 범위 문장에 ADR-0035 결정 1 목록 중 빠진 `qsh identity move-key`와 `qsh audit`을 더하고, M16·M17이 M19로 넘긴 쌍둥이(신뢰 철회 `listen`, 세션 필터 fan-out, `audit.query` pipe 비노출, 자동 부트스트랩의 Windows 분기)를 한 줄로 적는다(§9 #4).
3. README Roadmap 표의 M17 행을 "Done"으로, M19 행을 "In progress"로 고치고 M18 행에 "waiting on M8 DoD 3"을 적는다.
4. ADR 준비 점검. ADR-0035는 승인됐고 M19에 새 ADR은 필요 없다. 다음의 실제 상태를 확인해 이 계획 §9에 적는다(ADR 본문은 고치지 않는다).
   - ADR-0035 결정 12의 keystore 구현 판정(crate냐 `CredReadW` 직접이냐)은 "구현 선택이라 ADR을 개정하지 않는다"고 적혀 있다. Step 2가 판정한다(§7.1 #5).
   - ADR-0035 결정 20의 "ConPTY 배치가 서지 않으면 ADR 개정"은 M20의 일이다.
   - ADR-0031 결정 3의 `serve --to` 쌍둥이 귀속(M20)과 이 계획의 당겨 오기(§9 #3).
   - ADR-0023의 "Windows에서 `Instant` 전제가 맞는지는 M19가 확인한다"는 ADR-0035 결정 15(`QueryUnbiasedInterruptTime`)가 대체했다. 개정 없이 Step 8이 결정 15를 인용한다(§9 #11).
5. `CLAUDE.md` Document map의 "M11–M19 (P1)"를 "M11–M20"으로, campaigns 목록의 중복 `p1-ssh-bootstrap`을 지우고 Step 14 착지 뒤 `p1-windows`를 더한다(§9 #7). 이 편집은 사용자 지시 범위(main 세션)다.

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록.

**(c) 완료 판정:** `PLAN.md` 첫 줄이 이 문서의 제목이다. ROADMAP 현재 위치가 M19를 가리키고 §5.1에 M18 건너뜀이 날짜와 함께 있으며, M19 DoD에 안정성 줄이 있고 `cp` 종단이 M20 DoD에 있다.

### Step 2 — 터미널 trait 추출, ConPTY probe 하니스, 모드 계산 순수 함수, keystore 경로 판정 (0.5~1.0ew) ✅ 2026-10-16

근거: ADR-0035 결정 4·5·11의 모드 계산, 결정 12의 "첫 스텝 판정", 결정 17 콘솔 계층 항목, 결과 절 "크기" 마지막 항목(첫 스텝 뒤 재산정). 선행: Step 1.

**(a) 범위:**

- `crates/qsh-cli/src/tui/`: `tui/unix.rs`에서 플랫폼 중립 부분(행 시작 escape 처리, 이벤트 루프, 입출력 스레드 구성, 종료 코드 매핑)을 꺼내 새 `tui/session_loop.rs`(가칭)에 두고, 작은 터미널 trait(raw 모드 guard, 창 크기 조회, stdin 읽기, 끊김 신호)에 올린다(결정 4). unix 구현은 `tui/unix.rs`에 남고 동작은 바뀌지 않는다. trait의 가짜 구현을 테스트에 둔다.
- 콘솔 모드 계산 순수 함수(`cfg` 없음, `tui/console_mode.rs` 가칭): 원래 입력·출력 모드에서 raw 모드(`ENABLE_LINE_INPUT`·`ENABLE_ECHO_INPUT`·`ENABLE_PROCESSED_INPUT` 끔, `ENABLE_VIRTUAL_TERMINAL_INPUT` 켬)와 출력 모드(`ENABLE_VIRTUAL_TERMINAL_PROCESSING`·`DISABLE_NEWLINE_AUTO_RETURN` 켬), 에코 억제 모드(`ENABLE_ECHO_INPUT`만 끔)를 만든다(결정 5·11). 비트 상수는 Win32 값을 이 파일에 직접 둔다(`windows-sys` 없이 네 다리에서 컴파일).
- `qsh-testkit`: ConPTY 하니스(`portable-pty` Windows dev 의존)와 콘솔 probe 바이너리 `qsh-console-probe`(`src/bin/`, 표준 라이브러리와 `windows-sys`만). probe는 raw 모드 진입 뒤 읽은 바이트, resize 콜백 횟수, 종료 전후 콘솔 모드를 stdout 한 줄씩으로 보고한다(결정 17). 바이너리 위치 탐색은 `qsh-fake-ssh`와 같은 순서(`QSH_CONSOLE_PROBE_BIN`, 테스트 실행 파일 옆, `cargo build -p qsh-testkit --bin`)를 쓴다(`docs/design/testing.md`의 가짜 ssh 하네스 문단).
- keystore 경로 판정(결정 12): keyring-core 계열 Windows store crate가 있는지, `cargo deny check`(license·advisory)를 넘는지 확인한다. 못 넘으면 `CredReadW`·`CredWriteW`·`CredDeleteW` 직접 구현으로 정한다. 결과를 §7.1 #5와 커밋 본문에 적는다. 구현은 Step 5다.
- 재산정: Step 3~11의 크기를 이 스텝에서 본 trait 경계와 probe 비용으로 다시 매겨 커밋 본문에 적는다. main 세션이 §4 표, ROADMAP M19 크기 줄·§5.2·§5.4 리스크 5를 갱신한다.
- M20: 없음(host 쪽을 만지지 않는다).

**(b) 테스트·게이트:**

- unix 회귀: `tui_expect::` 전부, `attach_ops::`, `attach_recovery::`, `crates/qsh-cli/src/tui/` 기존 단위 테스트가 무변경 초록. acceptance job 초록.
- 중립 루프(가짜 터미널, 네 다리): `session_loop_forwards_stdin_bytes_verbatim`, `session_loop_tilde_dot_at_line_start_detaches`, `session_loop_tilde_inside_a_line_is_plain_input`, `session_loop_size_change_sends_one_resize`, `session_loop_hangup_signal_detaches_and_keeps_the_session`
- 모드 계산(네 다리): `raw_input_mode_clears_line_echo_processed_and_sets_vt_input`, `raw_output_mode_sets_vt_processing_and_disables_newline_auto_return`, `echo_suppressed_mode_clears_only_echo_input`, `mode_computation_preserves_unrelated_bits`
- 하니스(Windows 다리): `console_probe::probe_reports_its_initial_size_under_conpty`

**(c) 완료 판정:** unix attach 경로의 동작 diff가 0이다(위 회귀 초록). ConPTY 하니스가 Windows 다리에서 probe를 띄운다. keystore 판정과 재산정이 커밋 본문에 있다. wire diff 0.

**(d) 결과 (2026-10-16):** 터미널 경계는 `Terminal` trait 메서드 다섯(`window_size`, `enter_raw`, `read_stdin`, `open_events`, `leave_on_hangup`)과 보조 trait `RawGuard`·`EventSource`로 섰고, `tui/unix.rs`는 768줄에서 154줄로 줄었다. ConPTY 하니스와 probe는 `portable-pty`·`windows-sys`만으로 섰다. keystore 판정은 §7.1 #5. 재산정: Step 3~11의 크기 범위는 그대로 둔다. trait 경계가 예상보다 작아 Step 3은 아래쪽(0.9) 근처로 보고, crate 판정으로 Step 5도 아래쪽(0.4)으로 보지만, named pipe(Step 6)와 작업 스케줄러 COM(Step 10·11)의 불확실성이 그대로라 합계 7.7~12.9ew는 바꾸지 않는다. `session_loop.rs`의 `signal_number`는 비 unix에서 `None`을 돌려주는 위임이고 Windows에서는 Step 9의 대화형 attach가 쓰기 전까지 쓰이지 않는다.

### Step 3 — Windows 콘솔 계층과 초대 코드 프롬프트 (0.9~1.5ew) ✅ 2026-10-16

근거: ADR-0035 결정 4~8·11, 결정 17 콘솔 계층 항목, 결정 19의 threat-model §3 "Windows 콘솔 입력" 행과 `docs/CLI.md` §6.11·§7. 선행: Step 2.

**(a) 범위:**

- `crates/qsh-cli/src/tui/windows.rs`: Step 2 trait의 Windows 구현.
  - raw 모드: 입출력 핸들의 원래 모드와 코드 페이지를 저장하고 결정 5의 모드와 UTF-8(65001)로 바꾼다. 키는 파싱하지 않는다.
  - 복원(결정 6): guard의 `Drop`, 전역 slot을 쓰는 panic hook, `SetConsoleCtrlHandler`(`CTRL_CLOSE_EVENT`·`CTRL_BREAK_EVENT`·`CTRL_LOGOFF_EVENT`·`CTRL_SHUTDOWN_EVENT`)를 detach로 처리. 복원 함수는 멱등.
  - 하한(결정 7): 출력 핸들에 VT 처리를 켤 수 없으면 `session.open` 전에 `UNSUPPORTED`이고 message가 Windows 10 1809를 적는다. stdin이 콘솔이 아니면(파이프, 리디렉션, mintty) unix 비 tty 경로와 같이 raw·escape 없이 흘린다.
  - resize(결정 8): 전용 스레드가 200 ms마다 `srWindow` 크기를 읽어 바뀔 때만 콜백. 간격은 상수이고 시계는 주입한다. `SessionOpen.term`은 `TERM`이 있으면 그 값, 없으면 VT가 켜졌을 때 `xterm-256color`.
- 초대 코드 프롬프트(결정 11): `crates/qsh-cli/src/main.rs`의 `read_invite_code_from_terminal`·`read_invite_code_from_stdin` 비unix 분기를 에코 억제 경로로 바꾼다. `qsh-core`의 `NO_TERMINAL_ECHO_SUPPRESSION`과 `resolve_invite_code_source`의 `echo_can_be_suppressed` 플랫폼 게이트를 지운다(ADR-0035 결정 2·11). machine mode와 비 콘솔 stdin의 `INVALID_ARGUMENT` 규칙은 그대로.
- 이 스텝은 `tui::run`의 비unix 분기를 아직 지우지 않는다(대화형 attach 개방은 Step 9, §4 "순서의 근거").
- 문서: `docs/CLI.md` §6.11 콘솔 프롬프트 개방 문장, §7 Windows 지원 범위(VT 하한, mintty 안내, `TERM` 기본값). `docs/design/threat-model.md` §3 "Windows 콘솔 입력" 행(로컬 사용자, VT 입력 바이트는 키 해석 없이 원격으로, 해석은 원격 PTY). README에 mintty 계열은 Windows Terminal이나 `winpty`를 쓰라는 한 줄.
- M20: 없음.

**(b) 테스트·게이트:**

ConPTY probe 테스트는 새 통합 모듈 `crates/qsh-cli/tests/it/console_probe.rs`(`#![cfg(windows)]`, `tests/it/main.rs` 등재).

- 콘솔 계층: `conpty_raw_mode_reads_input_bytes_unprocessed`(`Ctrl-C`가 `0x03`으로 읽힘 포함), `conpty_resize_poll_fires_once_per_size_change`, `conpty_console_modes_are_restored_after_normal_exit`, `conpty_console_modes_are_restored_after_panic`, `conpty_console_modes_are_restored_after_a_close_event`, `conpty_code_page_is_restored_on_exit`
- 하한과 비 콘솔: `vt_unavailable_is_unsupported_before_session_open`(VT 켜기 실패 주입, 가짜 host에 `session.open` 0건), `non_console_stdin_passes_bytes_verbatim_on_windows`, `session_open_term_defaults_to_xterm_256color_when_term_is_unset`
- 초대 코드: `invite_code_prompt_never_echoes_under_conpty`(ConPTY 출력 스트림에 코드 문자 없음), `invite_code_prompt_restores_the_console_mode`, `code_stdin_from_a_console_suppresses_echo`, 기존 `ops::tests::resolve_invite_code_source_decision_table`을 새 표로 갱신(Windows 행이 `UNSUPPORTED`가 아님)
- `failure_text_discipline.rs`가 VT 하한 message를 덮음
- 부하 필터 초안 `scripts/stress/m19.filter`에 `console_probe::`를 넣는다.

**(c) 완료 판정:** `NO_TERMINAL_ECHO_SUPPRESSION`이 소스에 없다. ConPTY 테스트가 Windows 다리에서 초록이고 Dave-Windows 부하 아래 50회 연속 초록이다. unix 회귀 0. wire diff 0.

**(d) 결과 (2026-10-16):** Linux 부하 아래 `m19.filter`(19개) 50/50. Windows 부하 반복은 Dave-Windows 박스에서 WSL interop으로 Windows 테스트 실행 파일을 직접 돌리고 Windows 쪽에 PowerShell busy loop 8개를 띄운 채 `console_probe::`(12개) 50/50이었다. Git for Windows bash의 `scripts/stress/run.sh` 대신 이 방식을 썼고 대상 OS·장비는 같다(§7.1 #12). 남은 약점: `session_open_term_defaults_to_xterm_256color_when_term_is_unset`은 `session_term` 순수 함수만 보고 `session_loop::run`이 `fallback_term()`을 `session.open`에 싣는 배선은 Step 9의 Windows attach 종단이 덮는다. close 이벤트 ConPTY 테스트는 ConPTY가 실제 `CTRL_CLOSE_EVENT`를 전달하지 못해 핸들러 본문을 직접 부르고, 실제 `SetConsoleCtrlHandler` 등록은 `CTRL_BREAK` 테스트가 본다. `preflight`는 출력뿐 아니라 입력의 `ENABLE_VIRTUAL_TERMINAL_INPUT` 거부도 `UNSUPPORTED`로 본다(1809 하한과 같은 판정).

### Step 4 — 소유자 전용 DACL 모듈과 적용처 전부 (0.7~1.1ew) ✅ 2026-10-16

근거: ADR-0035 결정 9·10, 결정 17 첫 항목, 결정 19의 threat-model §4 D와 README Known limitations, `resume.rs` 모듈 doc. ADR-0033 결정 6의 Windows 읽기 불가 행(`crates/qsh-core/src/audit/reader/tests.rs` 주석, `docs/design/architecture.md` §6 audit 조회 문단). 선행: Step 1.

**(a) 범위:**

- `qsh-core`의 `fsutil` 하위 새 모듈(가칭 `fsutil/dacl.rs`, `fsutil.rs`를 디렉터리로 바꾸는지는 §7.1 #2): 프로세스 토큰 사용자 SID로 보호된 DACL 하나를 만든다. 파일은 그 SID에 `FILE_ALL_ACCESS` ACE 하나, 디렉터리는 `OBJECT_INHERIT | CONTAINER_INHERIT` ACE 하나. `CreateFileW`의 `SECURITY_ATTRIBUTES`로 만드는 순간부터 적용하고 `icacls`를 부르지 않는다.
- 적용처(`cfg(windows)` 분기): `ensure_private_dir_io`, `write_private_file_io`, resume 저장소의 임시 파일·`.lock`, audit 로그·회전 파일·잠금 파일과 디렉터리(`audit.rs`, `audit/writer.rs`), `identity/device.pem`·`device.key`(`move-key --to file` 포함), private CA 산출물(`ca.rs`), `trust.toml`, `config.toml`(쓰는 경우), `stateless_reset.key`(ADR-0036), config·state·audit 디렉터리. 서비스 작업 정의 파일과 서비스 로그는 Step 10이 같은 모듈을 부른다.
- fail closed(결정 10): SID 조회 실패, ACL 미지원 파일시스템이면 파일을 만들지 않고 기존 `config_io_error`의 `CONFIG_ERROR`(경로와 원인). audit 경로는 writer의 fail closed 규칙 그대로. 옛 상속 ACL 파일은 다음 쓰기(임시 파일 + rename)가 바꿔 놓는다. 읽기 경로는 ACL을 검사하지 않는다.
- audit 읽기 코어의 Windows 읽기 불가 행: 읽기를 거부하는 DACL을 건 로그에 대해 `audit.query`가 경로와 오류 종류만 담은 `INTERNAL`인지(ADR-0033 결정 6).
- 문서: `docs/design/threat-model.md` §4 D에 "Windows에서 키·상태·audit 파일이 상속 ACL로 다른 사용자에게 읽힌다" 행(통제 결정 9·10, 핀은 아래). README Known limitations의 "Windows ACL checking is out of scope" 삭제. `crates/qsh-core/src/resume.rs` 모듈 doc의 "inherited directory ACL" 문단, `docs/design/architecture.md` §7 Windows 경로 줄, `docs/CLI.md` §6.11의 `move-key` Windows 문단 중 DACL 부분(나머지는 Step 5).
- M20: host audit writer의 `LockFileEx` 잠금·(볼륨 일련번호, 파일 인덱스) 재검증과 `acl.toml` DACL 경고(결정 24)는 M20이다. 이 스텝은 writer가 만드는 파일의 DACL만 한다.

**(b) 테스트·게이트:**

`crates/qsh-core/src/fsutil/` 단위 테스트(`cfg(windows)`)와 각 소유 모듈의 Windows 쌍둥이.

- 핀: `windows_private_files_have_an_owner_only_protected_dacl`(대상 파일 전부를 표로 돌며 `GetNamedSecurityInfoW`로 SE_DACL_PROTECTED, ACE 하나, 그 SID가 토큰 사용자, 마스크 `FILE_ALL_ACCESS`), `windows_private_dirs_have_an_inheriting_owner_only_dacl`, `a_dacl_failure_creates_no_file`(주입), `a_legacy_inherited_acl_file_is_replaced_on_the_next_write`, `a_sid_lookup_failure_is_config_error_with_the_path`
- 소유 모듈 쌍둥이: `move_key_file_store_has_an_owner_only_dacl`(`move_key_file_store_is_mode_0600`의 Windows 쌍둥이), `audit_sink_fails_closed_when_the_dacl_cannot_be_applied`, `stateless_reset_key_has_an_owner_only_dacl`, `resume_tmp_and_lock_have_an_owner_only_dacl`
- audit 조회: `audit_query_unreadable_log_is_internal_with_path_and_kind_only`의 Windows 행(읽기 거부 DACL)
- 기존 unix 0600/0700 테스트 무변경 초록

**(c) 완료 판정:** 결정 9 목록의 모든 생성 경로가 같은 모듈을 부르고(`rg`로 `cfg(windows)` 생성 분기 전수 확인), DACL 실패 주입에서 파일이 없다. README 문장이 지워졌다. wire diff 0.

**(d) 결과 (2026-10-16):** §7.1 #2는 `fsutil.rs`를 파일로 두고 하위 모듈 `fsutil/dacl.rs`(테스트는 `fsutil/dacl/tests.rs`)를 더하는 쪽으로 정했다. 경로 단위 금지에 걸리는 이동이 없어 `xtask/src/arch.rs`는 그대로다. "옛 상속 ACL 파일은 다음 쓰기가 바꿔 놓는다"는 임시 파일 + rename으로 쓰는 파일(키, `trust.toml`, `resume.json`)에만 성립한다. append로 여는 audit 로그는 회전이 새 파일을 만들 때, lock 모드로 여는 resume `.lock`은 지워졌다 다시 만들어질 때 바뀐다. 이 잔여는 threat-model D18과 architecture.md에 적었다. audit writer의 Windows 사이드카 잠금 파일은 `LockFileEx`와 함께 M20이다(ADR-0035 결정 24). Windows 다리: `wintest.sh -p qsh-core` 단위 1422개·통합 124개 초록.

### Step 5 — Credential Manager `platform` store와 Windows `move-key` 왕복 (0.4~0.7ew) ✅ 2026-10-16

근거: ADR-0035 결정 12, ADR-0032 결정 15 둘째~넷째 항목·17, ROADMAP M19 DoD의 `move-key` 왕복 줄. `docs/CLI.md` §6.11 `move-key` Windows 문단, threat-model §3 `identity move-key` 행, `docs/design/testing.md` L1. 선행: Step 4(파일 대체가 DACL을 씀), Step 2의 keystore 판정.

**(a) 범위:**

- `qsh-core` `identity/keystore.rs` 옆: Step 2가 정한 경로(store crate 또는 `CredReadW`·`CredWriteW`·`CredDeleteW`)로 Windows `platform` store를 붙인다. 항목은 target `qsh`·사용자 이름 `device_id`·`CRED_TYPE_GENERIC`·`CRED_PERSIST_LOCAL_MACHINE`, blob은 다른 플랫폼과 같은 base64 PKCS#8 DER. store는 연산마다 열고 전역 기본 store를 등록하지 않는다. 읽기 버퍼는 `Zeroizing`.
- `auto`(결정 12): platform을 먼저 시도하고 `Unavailable`이면 파일 모드(Step 4 DACL)로 떨어진다.
- `move-key`: M17 Windows 빌드의 처분(`--to platform`은 `INTERNAL`, `--to file`은 `moved: false`, M17 plan §9 #10 (`047db25`))을 걷고 다른 OS와 같은 순서·결과로 동작한다. op·순서·audit·잠금 코드는 M17(`5100fdc`) 그대로이고 store만 붙는다.
- 문서: `docs/CLI.md` §6.11의 `move-key` Windows 문단을 착지 상태로("Windows `platform`은 Credential Manager"), 상태 헤더 v0.37 서술은 고치지 않고 새 판에 적는다. threat-model §3 `identity move-key` 행의 "Windows 빌드에서는 … 구현은 M19" 문장 갱신. `docs/design/testing.md` L1 「플랫폼 키스토어 릴리스 전 수동 단계」에 Windows 줄과 `move-key` 왕복(ADR-0035 결정 12). `docs/design/architecture.md` §8 keystore 행의 Windows 항목.
- route 동등: 이동 뒤 이 장비가 forward host, reverse listener, reverse target일 때 상대 pin을 고치지 않은 채 handshake한다. M17의 `move_key_then_serve_listen_and_serve_to_handshake_with_unchanged_pins`는 `cfg(unix)`이고 Windows `listen`·`serve --to`는 Step 7이 연다. 그래서 이 스텝은 inbound `serve` 행만 Windows에서 열고, `listen`·`serve --to` 행은 Step 7이 같은 테스트의 `cfg(unix)`를 걷어 연다(§5.6에 귀속).
- M20: 없음.

**(b) 테스트·게이트:**

- 핀(ROADMAP DoD): `move_key_round_trips_between_credential_manager_and_file_with_the_same_fingerprint`(Windows 다리, 주입 백엔드로 platform → file → platform, fingerprint·device_id 불변, file 뒤 DACL, platform 뒤 파일 부재)
- 실제 Credential Manager(§7.1 #6): `credential_manager_round_trip_on_the_runner`(`cfg(windows)`, 테스트마다 고유 target 이름, 끝나면 삭제). 러너가 허용하지 않으면 이 테스트는 두지 않고 §1의 수동 단계만 남긴다.
- 계획 추가: `credential_entry_attributes_are_generic_local_machine_under_target_qsh`(순수 함수), `auto_falls_back_to_the_file_store_when_credential_manager_is_unavailable`, `credential_manager_blob_is_the_same_pkcs8_base64_as_other_platforms`, `move_key_never_emits_key_bytes`의 Windows 행
- 기존 `identity_move_key::` Windows 처분 테스트(`--to platform`이 `INTERNAL`인 행, `crates/qsh-cli/tests/it/identity_move_key.rs`의 M19 주석)를 성공 행으로 바꾸는 것은 fixture 편집이 아니라 테스트 기대 변경이다. 기존 `identity.move_key.*` fixture는 무변경.
- route 동등(부분): `move_key_then_serve_listen_and_serve_to_handshake_with_unchanged_pins`의 inbound `serve` 행이 Windows에서 초록

**(c) 완료 판정:** Windows에서 `qsh init --key-store platform`이 `INTERNAL`이 아니다. 왕복 핀이 Windows 다리에서 초록이다. `cargo deny check` 초록. L1에 Windows 줄이 있다. wire diff 0.

**(d) 결과 (2026-10-16):** 항목 target은 (a)의 `qsh`가 아니라 store crate 기본 방식의 `<device_id>.qsh`다(ADR-0035 개정 이력 2026-10-16). 실제 Credential Manager 테스트 `credential_manager_round_trip_on_the_runner`와 `credential_manager_blob_is_the_same_pkcs8_base64_as_other_platforms`는 Dave-Windows에서 초록이었고 실행 뒤 `cmdkey /list`에 남은 항목이 없었다. windows-latest 러너가 `CredWriteW`를 거부하면 §7.1 #6대로 두 테스트를 빼고 L1 수동 단계만 둔다. 바이너리 수준의 Windows `qsh init --key-store platform` 테스트는 OS 자격 증명 저장소를 건드리므로 두지 않았고, (c)의 "INTERNAL이 아니다"는 주입 store 왕복과 실제 `PlatformKeyStore` 왕복이 덮는다. M17의 Windows 처분 테스트 `move_key_to_platform_is_internal_on_windows_before_m19`는 지웠다. 이 스텝과 Step 4가 `qsh-core` 의존을 늘려 `fuzz/Cargo.lock`을 같은 커밋에서 갱신했다(fuzz-smoke의 `--locked` 실패, run 38817991446).

### Step 6 — named pipe localctl transport (1.1~1.8ew) ✅ 2026-10-16

근거: ADR-0035 결정 14(이름·생성·접근 통제·자격 확인·공통 부분·모듈 구조), 결정 17 named pipe 항목 (2)~(6), 결정 19의 threat-model §3·§4 A·B·§7과 `xtask/src/arch.rs`, `docs/design/architecture.md` §1·§7, `localctl/mod.rs` 모듈 doc. ADR-0033 결정 4·13의 named pipe 비노출. 선행: Step 4.

**(a) 범위:**

- 모듈 구조: `localctl/frame.rs`·`client.rs`를 `AsyncRead + AsyncWrite` 스트림에 대해 일반화하고, 연결·인스턴스 생성·자격 확인을 `localctl/transport/unix.rs`(지금의 UDS 코드)와 `localctl/transport/windows.rs`로 옮긴다. `frame.rs`·`client.rs`는 파일로 남는다. `localctl/mod.rs`의 `#[cfg(unix)]` 게이트와 `lib.rs`의 모듈 선언 주석을 걷는다.
- Windows transport:
  - 이름 `\\.\pipe\qsh-<scope>-<pid>`, `<scope>`는 사용자 SID 문자열과 `Paths::runtime_dir()` 정규 경로(소문자)를 NUL로 이은 SHA-256 앞 16 hex(순수 함수).
  - 첫 인스턴스는 `FILE_FLAG_FIRST_PIPE_INSTANCE`, 항상 `PIPE_REJECT_REMOTE_CLIENTS`, `PIPE_TYPE_BYTE`·`PIPE_READMODE_BYTE`. 이름이 있으면 bind가 실패한다.
  - 모든 인스턴스는 Step 4 모듈의 보호된 소유자 전용 DACL(소유자 SID에 읽기·쓰기·`FILE_CREATE_PIPE_INSTANCE`). 다음 인스턴스는 현재 연결을 넘기기 전에 만든다.
  - 서버는 accept마다 프레임을 읽기 전에 `GetNamedPipeClientProcessId` → `PROCESS_QUERY_LIMITED_INFORMATION` → 토큰 사용자 SID를 대조하고 다르거나 실패하면 말 없이 끊는다. 클라이언트는 `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`으로 열고 첫 프레임 전에 `GetNamedPipeServerProcessId`로 서버 SID를 대조해 다르면 그 후보를 건너뛴다. "pid → SID" 함수는 주입 가능하게 쪼갠다.
  - 발견: `\\.\pipe\` 열거에서 `qsh-<scope>-*` 접두만 후보(unix `candidate_sockets` 대응). stale 정리 경로는 없다.
- 공통: `qsh.local.v1` 프레이밍과 `LOCAL_ADMIN`·`LOCAL_CONTROL`·`LOCAL_STREAM`은 그대로. 데몬은 `Authorizer::check`를 conduit에 부르지 않고 클라이언트가 보낸 principal을 믿지 않으며 resume token은 어떤 프레임에도 실리지 않는다. `audit.query`는 어떤 localctl 요청으로도 노출되지 않는다(ADR-0033 결정 4·13).
- `xtask/src/arch.rs`: 새 `localctl/transport/{unix,windows}.rs`를 `frame.rs`·`client.rs`와 같은 파일 단위 금지(`qsh_transport`·`quinn`·`rustls`)에 올리고, `qsh-cli/src` 금지 토큰에 `named_pipe`와 `\\.\pipe`를 더한다. `daemon.rs` 면제는 그대로. 같은 커밋(`CLAUDE.md` path-scoped 금지 규칙).
- 문서: threat-model §3 "localctl named pipe" 행(기존 "localctl UDS" 옆), §4 A(pipe 이름 선점, 가짜 데몬과 클라이언트 토큰 가장), §4 B(다른 로컬 사용자의 pipe 접속), §7 잔여 위험(PID 재사용 틈 하나, same-SID 모델은 unix와 같음). `docs/design/architecture.md` §1 localctl 줄(pure UDS → pure 로컬 스트림), §7 runtime dir·pipe 이름 줄. `localctl/mod.rs` 모듈 doc의 trust model 문단에 Windows 대응을 더한다.
- 이 스텝은 `qsh listen`을 Windows에서 아직 열지 않는다(Step 7). 데몬 쪽 transport는 테스트에서 in-process로 띄운다.
- M20: 없음(host 쪽 overlapped pipe는 ConPTY 배치로 M20, 결정 20).

**(b) 테스트·게이트:**

`localctl/transport/windows/tests.rs`(가칭)와 기존 `localctl/frame.rs`·`client.rs` 테스트.

- DoD 핀: `pipe_instance_dacl_is_protected_and_owner_only`(SE_DACL_PROTECTED, 소유자 ACE 하나, Everyone·익명 ACE 없음), `pipe_server_drops_a_client_with_another_sid_before_reading_a_frame`(주입), `pipe_client_writes_nothing_to_a_server_with_another_sid`(주입)
- 결정 17 (2)~(6): `pipe_create_options_reject_remote_clients_and_claim_the_first_instance`(순수 함수), `pipe_bind_fails_when_the_name_already_exists`, `pipe_client_opens_with_sqos_identification`(순수 함수), `pipe_name_differs_by_sid_or_state_dir_and_matches_otherwise`, `pipe_enumeration_picks_only_scope_prefixed_names`, `the_next_pipe_instance_exists_before_the_current_connection_is_handed_off`
- 공통 케이스: `localctl::frame::tests`와 `localctl::client::tests`가 `cfg(unix)` 없이 두 OS에서 같은 케이스로 돈다(결정 17 (6))
- ADR-0033: `audit_query_has_no_wire_message_and_no_localctl_request`가 Windows 다리에서도 돈다(지금 cfg가 있으면 걷는다), 계획 추가 `localctl_request_enum_has_no_audit_variant_on_any_platform`
- arch: `cargo xtask arch` 초록, `xtask` 단위 테스트에 새 금지 행(`localctl_transport_files_are_banned_from_naming_quic`, `cli_src_bans_named_pipe_tokens`)
- unix 회귀: `localctl_perms::`, `localctl::daemon` 테스트, `hosts_reverse::` 무변경 초록
- pipe accept 경합 테스트를 `m19.filter`에 넣는다.

**(c) 완료 판정:** `localctl` 모듈이 Windows에서 컴파일되고 `cfg(unix)` 게이트가 없다. DoD 3의 핀 셋 중 두 개(DACL, SID 불일치)가 Windows 다리에서 초록이다(선점 기동 실패는 Step 7). xtask 금지 목록이 같은 커밋이다. wire diff 0, `local.rs` diff 0.

**(d) 결과 (2026-10-16):** Windows 다리 `wintest.sh -p qsh-core` lib 1487·it 125 초록, pipe accept 경합 `pipe_accept_serves_concurrent_clients_without_a_name_gap` Windows 부하 아래 50/50. Step 7이 이어받을 것: `daemon`이 아직 `cfg(unix)`라 `transport/windows.rs`의 `cfg_attr(not(test), allow(dead_code))`와 `client.rs`의 `cfg_attr(windows, allow(dead_code))`는 임시이고 Step 7이 지운다. byte 모드 pipe에는 half-close가 없어 Windows `shutdown_write`는 no-op이고, `DataSendHalf::finish` 뒤의 EOF는 stream drop 때 보인다. Step 7은 데몬 relay가 finish 뒤 EOF에 기대는 곳을 Windows에서 확인한다. socket 파일 전용 client 케이스 다섯과 `discover_moves_past_a_silent_daemon_instead_of_hanging_on_it_forever`는 `cfg(unix)`이고, Windows 쌍둥이 `discover_moves_past_a_candidate_that_never_answers_instead_of_hanging_on_it`가 같은 발견 기한 계약을 본다.

### Step 7 — Windows reverse 역할과 정방향·역방향 CLI 종단 (0.8~1.3ew) ✅ 2026-10-16

근거: ADR-0035 결정 1·2(client 쪽), 14의 "`qsh listen`의 나머지"·"동작 요약", 17의 정방향·역방향 종단 항목(PTY 없는 부분), 25 가운데 `serve --to` 게이트 제거, 결과 절 "마일스톤 배치"의 M19 역방향 CI. `docs/CLI.md` §6.9·§6.13·§6.14. 선행: Step 6.

**(a) 범위:**

- 게이트 제거: `reverse/listen.rs`의 `windows_unsupported()`와 부르는 곳, `run_listen`의 `cfg` 분기, `reverse/listen/hub.rs`·`registration.rs`·`reverse/target`(`run_reverse_unix`를 이식 가능한 `run_reverse`로)·`client/link.rs`·`ops/exec.rs`의 reverse 분기·`ops/session.rs`의 `dial_reverse`·`ops/mod.rs`의 관련 `cfg(unix)`. `windows_unsupported()`를 지운다.
- `qsh listen`(Windows): 종료는 `tokio::signal::ctrl_c`와 콘솔 닫힘 이벤트(Step 3의 핸들러 계열). config·정책 진단·감사·ACL 규율은 unix와 같고 감사 로그·reset key는 Step 4 모듈로 만든다. 이름 선점이면 QUIC listener를 열기 전에 기동이 실패한다. `qsh setup listener`(`--service` 없이)도 연다.
- `qsh serve --to`(Windows): 게이트만 걷는다. PTY 세션 요청과 파일 op는 M20까지 `UNSUPPORTED`이고 `exec`와 터널을 낸다. Windows Defender 방화벽 첫 허용 프롬프트 안내는 README.
- `qsh hosts`는 forward와 데몬의 reverse 항목(데몬 없음은 오류 아님), `qsh tunnels`는 데몬 항목 포함, `qsh tunnel close <id>`는 데몬들에 묻는다.
- `qsh audit`의 route 동등: 같은 장비가 Windows `serve`·`listen`·`serve --to`로 남긴 레코드를 같은 `AuditRecordView` 모양으로 돌려준다(ADR-0033 결정 13).
- 문서: `docs/CLI.md` §6.13("Windows에서는 `qsh listen`/`qsh serve --to` 둘 다 `UNSUPPORTED`" 문단 삭제, 방화벽 안내), §6.9·§6.14의 Windows 문장(데몬 항목, supervise 판별은 Step 8), §6.12는 M20이 고친다(Windows `serve`의 PTY). `crates/qsh-core/src/localctl/mod.rs`·`reverse/listen.rs` 모듈 doc의 Windows 문장.
- M20: `serve --to`의 PTY 세션과 host 쪽 `cp`, `setup host`(`--to` 형태 포함), `pair invite`, `pair ssh-respond`. 이 스텝은 그 게이트를 걷지 않는다.

**(b) 테스트·게이트:**

새 통합 모듈 `crates/qsh-cli/tests/it/windows_forward_e2e.rs`와 `windows_reverse_e2e.rs`(`#![cfg(windows)]`, 같은 케이스 함수를 공유하고 route만 바꾼다).

- 정방향(Windows `qsh` → Windows 인바운드 `qsh serve`): `exec_round_trip`, `local_tunnel_echo`, `remote_tunnel_echo`, `hosts_lists_the_forward_host_without_a_daemon`
- 역방향(Windows `qsh listen` ← Windows `qsh serve --to`, 실제 CLI 양쪽, test-only 하니스 없음): `exec_round_trip`, `local_tunnel_echo`, `remote_tunnel_echo`, `hosts_lists_the_reverse_entry`, `hosts_drops_the_reverse_entry_after_the_daemon_dies`, `target_re_registers_with_a_new_daemon`, `tunnels_and_tunnel_close_reach_the_daemon`
- DoD 3 마지막 핀: `listen_fails_before_the_quic_listener_when_the_pipe_name_is_taken`
- route 동등 잔여: `move_key_then_serve_listen_and_serve_to_handshake_with_unchanged_pins`의 `listen`·`serve --to` 행이 Windows에서 초록(Step 5에서 넘어옴), `audit_query_reads_records_written_by_serve_listen_and_serve_to`가 Windows에서 초록
- 기존 `reverse_e2e::`, `hosts_reverse::`, `reverse_unreachable_diagnostic::`의 `cfg(unix)` 중 PTY와 무관한 케이스를 Windows에서 연다. PTY가 필요한 케이스는 주석으로 M20을 적는다(ADR-0035 결정 3).
- `exit_code_matrix.rs`: `listen`·`serve --to`·`setup listener`의 Windows 행이 성공 또는 기능 오류(Windows 전용 `UNSUPPORTED` 아님)
- 종단 모듈 둘을 `m19.filter`에 넣는다.

**(c) 완료 판정:** `windows_unsupported`와 `run_reverse_unix`가 소스에 없다. 정방향·역방향 종단이 Windows 다리와 Dave-Windows 부하 아래 50회 연속 초록이다. unix 회귀 0. wire diff 0.

**(d) 결과 (2026-10-16):** `run_reverse_unix`는 플랫폼 공통 `run_reverse_observed`가 됐고 옛 이름을 부르던 ADR-0021·0031·0041에는 날짜 줄을 더했다. byte 모드 pipe에 half-close가 없는 문제는 한계로 두지 않고 Windows conduit의 raw byte 구간을 chunk(4바이트 big-endian 길이, 길이 0이 end chunk, 상한 65536)로 실어 풀었다(`localctl/chunked.rs`, ADR-0035 개정 이력 2026-10-16, `docs/design/protocol.md` localctl 절). unix는 바이트 그대로이고 `qsh.local.v1` proto·`qsh-proto`·fixture·ErrorCode diff는 0이다. Windows 종단은 unix와 같은 단언(쓰기를 닫고 응답을 EOF까지 읽기)을 쓴다. 부하 반복 중 역방향 `local_tunnel_echo`가 100회에 1~4회 잘린 원인은 framing이 아니라 테스트 echo 서버가 copy 뒤 소켓을 그냥 놓아 Windows에서 RST로 끊긴 것이었고, echo 서버가 먼저 `shutdown(Write)`를 보내게 고쳤다. 데몬은 Windows에서 터널 양방향이 깨끗하게 끝난 뒤 상대가 conduit을 닫을 때까지 최대 10초 기다린다. Dave-Windows 부하 아래 `windows_reverse_e2e::` 100/100, `windows_forward_e2e::` 50/50, Linux 부하 아래 바뀐 Linux 타이밍 테스트(`hosts_reverse::`·`identity_move_key::`·`audit_query_reads*`·`exit_code_matrix::qsh_(listen|serve_to|reverse)*`) 50/50. `listen_fails_before_the_quic_listener_when_the_pipe_name_is_taken`은 `reverse/listen/tests.rs`의 cfg(windows) 단위 테스트다. `wintest.sh`로 qsh-core lib을 한 프로세스에서 직렬로 돌리면 이번에 Windows에서 처음 열린 `reverse::` 테스트 넷(`datagram_liveness_controller_control_stall_is_not_path_dead_but_a_sever_is` 등)이 `wait_for_line` 기한을 넘긴다. 단독과 `reverse::` 묶음(157개)에서는 초록이고 nextest는 테스트마다 프로세스를 나누므로 CI에는 해당하지 않는다. supervise의 reverse route `cfg` 제거는 컴파일이 요구해 이 스텝에 들어왔고 supervise 테스트와 §6.14의 supervise 판별 문구는 Step 8이 맡는다.

### Step 8 — supervise와 절전 감지, reverse 쌍둥이 (0.3~0.5ew) ✅ 2026-10-16

근거: ADR-0035 결정 15, ADR-0023의 절전 감지 전제(Windows 확인을 결정 15가 대체), ADR-0031 결정 3과 개정 이력(`listen` 쌍둥이 M19), ADR-0033 결정 13(세션 필터의 reverse fan-out), `docs/CLI.md` §6.2 route 문단·§6.14 절전 감지 문장, `crates/qsh-core/src/client/wake.rs` 모듈 doc, `crates/qsh-cli/tests/it/sessions_filter.rs` 모듈 doc. 선행: Step 7.

**(a) 범위:**

- 절전 감지: `client/wake.rs`의 단조 시계 표본 함수 하나만 `cfg`로 갈라 Windows에서 `QueryUnbiasedInterruptTime`을 읽는다. 감지 알고리즘(`WAKE_TICK`, `WAKE_SKEW`, 앞으로 뛴 차이만 셈)과 tokio 타이머는 그대로. `qsh.event/v1`의 `wake`와 supervise·target backoff의 즉시 재시도가 Windows에서도 나온다.
- `qsh tunnel open --supervise`: forward route(`-L`/`-D`)는 이미 이식 가능하고, reverse route `-R`은 데몬 reverse connection이 carrier이며 운영자 닫기를 `LocalHostList`·`LocalTunnelList`로 판별한다. named pipe 위에서 같은 값을 돌려주므로 규칙은 그대로다.
- 신뢰 철회: `crates/qsh-testkit/tests/it/trust_withdrawal.rs`의 `listen` 모듈 `cfg(unix)`를 걷는다(ADR-0031 결정 3). `serve_to` 모듈의 `cfg(unix)`도 같이 걷는다(§9 #3 확정, ADR-0031 2026-10-16 개정 이력).
- 세션 필터: `sessions_filter_applies_identically_to_forward_and_reverse_hosts`를 Windows에서 연다. Windows host는 PTY 세션이 없으므로 세션 0개 위에서 필터와 `data.unreachable` 유지, fan-out의 reverse 항목을 본다(`sessions_filter.rs` 모듈 doc의 M19 문장 갱신).
- 문서: `docs/CLI.md` §6.14의 "절전 감지 Windows 미확인" 문장 삭제, §6.2 route 문단의 "M19가 연다" 갱신, `client/wake.rs` 모듈 doc, `docs/design/testing.md`의 신뢰 철회 문단 플랫폼 줄.
- M20: PTY 세션이 있는 필터 e2e.

**(b) 테스트·게이트:**

- 절전: `windows_wake_sample_is_monotonic`(Windows), `wake_sample_excludes_suspended_time_by_contract`(표본 함수의 출처 상수 확인. 실제 절전은 캠페인 (4)), 기존 `client::wake` 감지 테스트(주입 표본)가 네 다리에서 초록
- supervise: `tunnel_supervise::`·`tunnel_supervise_cli::`의 reverse `-R` 케이스 중 PTY와 무관한 것을 Windows에서 연다. 계획 추가 `windows_supervised_remote_tunnel_survives_a_target_reconnect`
- 신뢰 철회: `trust_withdrawal::listen::`와 `trust_withdrawal::serve_to::` 전부가 Windows 다리에서 초록
- 세션 필터: `sessions_filter_applies_identically_to_forward_and_reverse_hosts`, `sessions_filter_keeps_unreachable_in_fan_out`가 Windows 다리에서 초록
- 위 셋을 `m19.filter`에 넣는다.

**(c) 완료 판정:** `client/wake.rs`의 Windows 분기가 표본 함수 하나다. 신뢰 철회 `listen` 쌍둥이와 세션 필터 reverse 쌍둥이가 Windows 부하 아래 50회 연속 초록이다. wire diff 0.

**(d) 결과 (2026-10-16):** 플랫폼별로 갈라지는 지점은 `mono_sample` 하나이고, Windows 쪽에 `windows_sample` 모듈(`unbiased`·`anchor`·`now`, 카운터를 못 읽으면 `Instant::now`로 폴백)과 출처 상수 `MONO_SAMPLE_SOURCE`, `unbiased_ticks_to_duration`이 딸린다. 감지 알고리즘과 상수는 그대로다. `with_mono_source`는 `cfg(test)`이고 `subscribe()`에 표본 출처를 남기는 debug 로그가 하나 늘었다. `wake_sample_excludes_suspended_time_by_contract`는 출처 상수 확인이고 실제 절전 복귀는 캠페인 (4)다. SIGTERM으로 멈추던 supervise 테스트 셋(`*_without_forward_*_ends_permission_denied_with_one_audit_deny` 둘, `supervised_sigterm_during_an_outage_releases_the_listener_and_exits_zero`)도 Windows에서 열었다. Windows `qsh tunnel open --supervise`는 Ctrl-C만 받고 있어 `CTRL_BREAK`와 콘솔 닫힘을 `qsh serve`·`qsh listen`과 같은 정지 경로에 붙였고(`docs/CLI.md` §6.14), 테스트는 새 process group의 자식에 `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT)`를 보낸다. 세션 필터 Windows 쌍둥이는 세션 0개 위에서 돌고 세션이 있는 판은 M20이다. ADR-0023에 2026-10-16 개정 이력 줄을 더했다(결정 17의 Windows 문장과 알려진 한계의 Windows 미확인 항목을 이 줄이 대체). `windows-sys` feature가 늘었지만 `fuzz/Cargo.lock`은 바뀌지 않았다. Dave-Windows 부하 아래 `trust_withdrawal::` 50/50(1200회), `sessions_filter::` 50/50(200회), `tunnel_supervise(_cli)::` 50/50(750회), 정지 테스트 셋 50/50(150회).

### Step 9 — client 기능 동등: 대화형 attach, `-D`, `qsh cp` client, 자동 부트스트랩, `pair ssh --reverse`, doctor, `release_smoke` (0.8~1.3ew)

근거: ADR-0035 결정 1·2·3(client 쪽), 5~8의 attach, 17의 `release_smoke` 항목(PTY 축 제외), ADR-0029 결정 2·23(드라이브 문자 operand, client 로컬 쓰기)과 ADR-0035 결정 26 마지막 항목(client get의 로컬 쓰기), ADR-0044 결정 1·5·22·25(Windows client 자동 발동과 `--reverse`의 이 장비 쪽). `docs/CLI.md` §6.21 Windows 문장, ADR-0044 터미널 순서 문단(§6.11 근처의 "Unix 빌드에만 있다"), README Known limitations의 부트스트랩 문단. 선행: Step 3, Step 5, Step 7.

**(a) 범위:**

- 대화형 attach: `tui::run`의 비unix 분기를 지우고 Step 3의 Windows 터미널로 `qsh [user@]host`와 `qsh attach <session-ref>`를 연다. 콘솔 이벤트는 detach, 세션은 남는다. route와 무관하게 같은 루프다.
- `-L`/`-R`/`-D` 대화형 플래그와 `qsh tunnel open --dynamic`: `crates/qsh-cli/src/main.rs`의 `TunnelShutdown` 등 비unix 분기를 Windows 의미(`ctrl_c`와 콘솔 닫힘)로 정리하고, `dynamic_forward.rs`의 `cfg(unix)` 중 이식 가능한 것을 연다.
- `qsh cp` client: `crates/qsh-core/src/file/operand.rs`에 드라이브 문자 규칙(한 글자 뒤 `:`는 로컬, ADR-0029 결정 2)을 Windows 빌드에서 켠다. get의 로컬 쓰기는 결정 26 규칙(mode 합성, 소유자 쓰기 비트가 꺼졌을 때만 읽기 전용 특성, 임시 파일은 Step 4 DACL로 만들고 rename 직전 보호를 풀어 상속 ACL을 받음, `-p`는 `SetFileTime`). Windows host는 M20까지 파일 op에 `UNSUPPORTED`이므로 이 스텝의 종단은 Windows client → Windows host의 `UNSUPPORTED` 경로와 client 쪽 단위·통합 테스트다(§9 #1).
- 자동 부트스트랩: `crates/qsh-cli/src/auto_bootstrap.rs`의 unix 한정을 걷어 Windows의 대화형 attach와 `qsh cp`에서 같은 분기를 켠다(ADR-0044 결정 25). 터미널 순서(ssh 동안 cooked, 끝난 뒤 raw)를 Windows 콘솔에서도 지킨다.
- `qsh pair ssh --reverse`: 이 장비 쪽(`qsh listen`이 서는 쪽, ADR-0044 결정 22)을 Windows에서 연다. 원격 쪽 응답자(`pair ssh-respond`)는 M20이라 응답자 모드 가짜 ssh 종단은 Windows 원격으로는 돌 수 없다. 이 장비 쪽만으로 끝나는 부분은 `pair_client` 모듈이 이미 Windows 다리에서 돈다(`docs/design/testing.md` 가짜 ssh 문단).
- `qsh doctor`: Windows에서 client 쪽 finding이 다른 OS와 같은 집합으로 돈다. `controller_unreachable` 문안 그대로, 방화벽 안내는 README.
- `release_smoke`의 `#[cfg(not(unix))]` 쌍둥이를 넓힌다: 기존 `init` → `trust` → `exec --json`에 `doctor --json`, `tunnel open --local`의 TCP echo 왕복, 만든 파일의 DACL 단언(Step 4)을 더한다. PTY session open·write·read·close 축은 M20.
- `exit_code_matrix.rs`: client 쪽 Windows 전용 `UNSUPPORTED` 행을 지운다(대화형 형태, `cp`의 client 쪽, `pair accept` 프롬프트). 남는 Windows 행은 `session open`(host PTY, M20)과 Step 11이 지울 `service install --activate` 행이다. `session open` 행의 주석 "Windows host is P2"를 "Windows host PTY is M20 (ADR-0035)"로 고친다.
- 문서: `docs/CLI.md` §6.21의 "Windows client의 `qsh cp`는 M19" 문단을 착지 상태로, ADR-0044 터미널 순서 문단의 "Unix 빌드에만" 문장 갱신, §7 Windows 범위. README Known limitations의 부트스트랩 문단(Windows client 자동 발동은 착지, 응답자는 M20).
- M20: Windows host 쪽 파일 op와 `cp` 종단, `pair ssh-respond`, PTY 축.

**(b) 테스트·게이트:**

- attach(§7.1 #4의 echo host, Windows 다리, ConPTY 안의 실제 `qsh` 바이너리): `windows_attach::echo_round_trip_forward`, `windows_attach::echo_round_trip_reverse`, `windows_attach::detach_then_attach_resumes_forward`, `windows_attach::detach_then_attach_resumes_reverse`, `windows_attach::console_close_detaches_and_keeps_the_session`
- `-D`: `windows_forward_e2e::dynamic_forward_connect`, `windows_reverse_e2e::dynamic_forward_connect`(curl 없이 SOCKS5 CONNECT를 테스트 코드가 직접 보냄)
- `cp` client: `drive_letter_operand_is_local_on_windows`, `drive_letter_operand_with_a_user_host_prefix_is_remote`, `a_one_letter_host_needs_brackets_or_user_on_windows`(계획 추가, 규칙 경계는 §7.1 #7), `windows_get_writes_a_read_only_attribute_only_when_owner_write_is_clear`, `windows_get_temp_file_is_owner_only_until_rename`, `windows_get_preserves_mtime_with_p`, `cp_to_a_windows_host_is_unsupported_before_m20`(forward와 reverse 두 route, file.v1 미광고)
- 자동 부트스트랩: `auto_bootstrap::` 중 대화형 form 케이스를 Windows에서 연다(가짜 ssh, `ssh.exe`). 계획 추가 `auto_bootstrap_keeps_the_console_cooked_until_ssh_exits_on_windows`
- `pair ssh --reverse`: `ssh_bootstrap::pair_client` 기존 행 초록, 계획 추가 `pair_ssh_reverse_local_side_runs_on_windows_and_names_serve_to_as_the_next_command`
- `release_smoke` 확장 쌍둥이, `exit_code_matrix.rs`의 Windows 전용 `UNSUPPORTED`가 `session open` 하나와 `service install --activate`(Step 11 몫)뿐
- `windows_attach::`를 `m19.filter`에 넣는다.

**(c) 완료 판정:** `tui::run`에 비unix 분기가 없다. 표의 client 기능마다 두 route 테스트가 Windows 다리에서 초록이다. `auto_bootstrap.rs` 모듈 doc에 unix 한정이 없다. wire diff 0, `capabilities.json` diff 0.

### Step 10 — 작업 스케줄러 서비스 백엔드, `qsh service run`, 상시 기동 레시피, `logon_task_session_scoped` (0.7~1.2ew)

근거: ADR-0035 결정 27(작업 정의, 콘솔과 로그, 재시작, 수명, 등록, doctor, `manager` 값), 결정 9(작업 정의 파일 DACL), 결정 17의 `service_docs.rs` 확장과 `ops/service/tests.rs` 항목, 결정 19의 threat-model §3 작업 정의 행과 `docs/CLI.md` §6.17·§6.18·§6.20, `docs/deploy/service.md` Windows 절. ADR-0032 결정 12(상시 기동 자동 설정 없음)·16. 선행: Step 4. `setup listener --service`는 Step 7.

**(a) 범위:**

- `ops/service/`: `SERVICE_UNSUPPORTED_PLATFORM`의 Windows 분기를 걷고 작업 스케줄러 백엔드를 연다.
  - `install`은 `<config_dir>\service\qsh-<mode>.task.xml`을 Step 4 DACL로 쓴다. 내용은 고정: `LogonTrigger` 하나, 현재 사용자 `InteractiveToken`·`LeastPrivilege`, `MultipleInstancesPolicy=IgnoreNew`, `ExecutionTimeLimit=PT0S`, 배터리 조건 끔, `RestartOnFailure`(1분). 동작은 `current_exe()` 절대 경로와 `service run <mode>`. 작업 이름 `\qsh\qsh-<mode>`.
  - `status`는 파일 존재만, `uninstall`은 파일 삭제만(플래그 없는 동작, M9 계약 그대로). audit 한 건 뒤 쓰기.
  - `manager` 값 `"task_scheduler"`(additive).
- 숨김 subcommand `qsh service run <mode>`(clap `hide = true`, 모든 플랫폼에서 파싱): `FreeConsole` 뒤 stdout·stderr를 `<state_dir>\log\<mode>.out.log`·`<mode>.err.log`(Step 4 DACL, 덧붙이기)로 돌리고 같은 run mode 진입 함수를 부른다. unix에서 직접 치면 같은 리디렉션 뒤 같은 진입 함수.
- 재시작 실측(§1 (i)): `RestartOnFailure`가 실행 중 비정상 종료에 다시 띄우지 않으면 로그온 트리거에 1분 간격 무기한 `Repetition`을 더한다(`IgnoreNew`가 중복을 막음). 결과를 커밋 본문과 렌더러에 반영.
- 상시 기동 레시피: `docs/deploy/service.md` Windows 절에 기본 작업 정의 펜스, 등록·해제 레시피(`schtasks /Create /F /TN \qsh\qsh-<mode> /XML <file>`, `/End`, `/Delete /F`), 상시 기동 변형 펜스(`BootTrigger` 추가, `LogonType=Password`)와 `/RU <DOMAIN\user> /RP` 등록, 암호 변경 시 재등록 고지, 관리자 프롬프트 필요 여부(§1 (ii) 실측), supervised tunnel 작업 예시. `Password` 주체의 Credential Manager 한 줄은 Step 11의 실측(§1 (iii)) 결과로 채운다. qsh는 상시 기동 작업을 대신 등록하지 않는다(ADR-0032 결정 12).
- doctor: `service_not_registered`·`service_restart_drops_sessions`를 작업 정의 파일 경로로 Windows에서 낸다. 새 warn `logon_task_session_scoped`(Windows에서만, 해당 mode의 작업이 등록돼 있고 주체가 `InteractiveToken`이면). 등록 상태와 주체는 COM(`ITaskService` → `IRegisteredTask`의 정의 주체)으로 읽고 subprocess는 띄우지 않는다. 못 읽으면 내지 않는다. remedy는 상시 기동 레시피. `EXPECTED_DOCTOR_CODES` 27 → 28, `docs/CLI.md` §6.11 끝 문장과 §6.17 머리 문장의 개수.
- `qsh setup listener --service`(Step 7 뒤)와 `setup` 단계가 이 백엔드를 부른다. `setup host --service`는 M20.
- 문서: `docs/CLI.md` §6.18(`manager` 값 목록, 버전 헤더, `SERVICE_UNSUPPORTED_PLATFORM` 인용문 갱신과 `service_docs.rs`의 인용 단언 갱신), §6.17 행, §6.20 `--service`. threat-model §3 "Windows 작업 스케줄러 작업 정의" 행(기존 `qsh service` 행의 Windows 변형). `ops/service/mod.rs` 모듈 doc의 Windows 문장.
- M20: `setup host --service`의 Windows host 경로.

**(b) 테스트·게이트:**

`crates/qsh-core/src/ops/service/tests.rs`와 `crates/qsh-core/tests/it/service_docs.rs`.

- DoD 4 핀: `service_md_windows_task_fence_matches_the_renderer`(바이트 단위, 세 mode), `logon_task_session_scoped_fires_for_an_interactive_token_task`, `logon_task_session_scoped_is_silent_for_a_password_task`, `logon_task_session_scoped_is_silent_when_the_task_cannot_be_read`(가짜 COM 읽기)
- 렌더·경로·존재(ADR-0035 결과 절): `windows_task_definition_renders_the_fixed_settings`, `windows_task_path_is_under_config_dir_service`, `windows_task_definition_file_has_an_owner_only_dacl`, `windows_status_reports_existence_from_the_task_file_only`, `windows_install_writes_one_audit_record_before_the_file`
- `qsh service run`: `service_run_redirects_stdout_and_stderr_to_the_mode_logs`, `service_run_log_files_have_an_owner_only_dacl`, `service_run_is_hidden_from_help_and_man`(`checked_in_man_pages_match_the_generator` 무변경 초록 포함)
- route 동등: `windows_task_definition_covers_serve_listen_and_reverse_modes`(세 mode 인자가 launchd·systemd 렌더러와 같은 규칙)
- doctor: `service_not_registered_reads_the_windows_task_file`, `logon_task_session_scoped_covers_serve_listen_and_reverse_tasks`, `doctor_probe_never_spawns_schtasks`, `EXPECTED_DOCTOR_CODES` 대조와 `doctor_docs.rs`
- 플래그 없는 호출은 매니저를 부르지 않음: `install_without_activate_never_invokes_the_manager` 등 M17 셋이 Windows 다리에서 초록(`ManagerRunner` 호출 0회)
- `setup::`의 `--service` 행이 Windows에서 성공(Step 7 뒤)
- `qsh service run` 리디렉션 테스트(실제 프로세스)를 `m19.filter`에 넣는다.

**(c) 완료 판정:** Windows `qsh service install|uninstall|status`가 `UNSUPPORTED`가 아니고 매니저를 부르지 않는다. 펜스 대조가 바이트 단위로 초록이다. §1 (i)(ii)의 실측 결과가 커밋 본문과 `service.md`에 있다. `docs/man/` diff 0. wire diff 0.

### Step 11 — ADR-0032 Windows 열: `schtasks` argv, COM `TaskStateQuery`, `--live`, 상시 기동 형태 보존, `keystore_session_bound` Windows 판정 (0.2~0.4ew)

근거: ADR-0032 결정 3 표의 작업 스케줄러 열, 4(실행 중 재등록), 5(등록 여부 기준 비활성화, `/Query`), 6(COM 상태값 하나), 8(`schtasks` 오류, `InteractiveToken` 시작 실패의 `INTERNAL`), 10(Windows 분기 구현), 11(Windows 레시피 대조), 15 첫 항목(Windows 실측), 18(Windows `Password` 주체 갈래). ADR-0035 결정 12 마지막 문장, 27·28. M17 plan §5.1·§5.2의 "M19 밖" 행 전부 (`047db25`). 코드 쪽 M19 주석(`doctor.rs`의 `KEYSTORE_SESSION_BOUND` 문단, `doctor/probe.rs`, `doctor/tests.rs`, `doctor/probe/tests.rs`, `crates/qsh-cli/tests/it/fixtures.rs`). 선행: Step 10.

**(a) 범위:**

- argv 빌더(`cfg` 없는 순수 함수): 활성화 `schtasks /Create /F /TN \qsh\qsh-<mode> /XML <task path>`, 실행 중이 아니면 `schtasks /Run /TN …`. 비활성화는 `/Query` exit 0(등록)이면 실행 중일 때만 `/End`, 그다음 `/Delete /F`. 인자는 닫힌 집합 `<mode>`와 qsh가 정한 경로뿐.
- `TaskStateQuery`의 COM 구현(`IRegisteredTask::get_State`가 `TASK_STATE_RUNNING`인지, M17 seam `1790cad`). 외부 출력을 파싱하지 않는다.
- 결정 4 실측(§1 마지막 항목): `/Create /F`가 실행 중 인스턴스를 멈추면 실행 중일 때 `/Create`도 부르지 않고 `already_active`로 끝나도록 ADR-0032 결정 4가 정한 처분을 따른다. 결과를 커밋 본문에.
- 결정 18 Windows 갈래: `\qsh\qsh-<mode>` 작업이 `Password` 주체로 등록돼 있으면(Step 10의 COM 읽기) `--activate`는 파일만 쓰고 `/Create`·`/Run`을 부르지 않으며 `always_on_present`, `--deactivate`는 `/End`·`/Delete`를 부르지 않고 파일을 지운 뒤 `always_on_present`. `--live`는 그 작업의 실행 여부.
- 오류(결정 8): `schtasks.exe` `NotFound`는 `UNSUPPORTED`, 0이 아닌 exit는 `INTERNAL`(`step`, `exit_code`, stderr 첫 줄 512바이트), 30초 초과 `TIMEOUT`. `InteractiveToken` 작업이 대화형 세션 없이 시작 못 하면 같은 `INTERNAL`이고 다른 주체로 우회하지 않는다.
- `keystore_session_bound`의 Windows 판정(§1 (iii)): `Password` 주체 작업이 Credential Manager를 읽으면 Windows에서 내지 않는 지금 동작을 유지하고 코드 주석의 "M19 전에는 내지 않음"을 실측 결과로 바꾼다. 못 읽으면 `BootTrigger`·`Password` 주체로 등록된 작업(Step 10 COM 읽기)에 같은 remedy(`qsh identity move-key --to file`)로 낸다. 어느 쪽이든 `docs/deploy/service.md` Windows 상시 기동 레시피의 한 줄을 결과에 맞추고(ADR-0032 결과 절), `docs/CLI.md` §6.17 `keystore_session_bound` 행의 Windows 문장을 고친다.
- `service_activation_flags_are_unsupported_on_windows_before_m19`(M17 계획 추가 테스트)를 지우고, `exit_code_matrix.rs`의 `service install --activate` Windows `UNSUPPORTED` 행을 성공 행으로 바꾼다.
- 문서: `docs/deploy/service.md` Windows 절의 `--activate` 안내와 비활성화 레시피(ADR-0032 결정 11), `docs/CLI.md` §6.18 플래그 문단의 Windows 서술. threat-model §4 E "매니저 호출 인자 주입" 행에 Windows 열(인자에 사용자 입력·uid 없음), §4 G "재시작 부재" 행에 Windows 처분.
- M20: 없음.

**(b) 테스트·게이트:**

- DoD 10 핀(Windows 다리, 가짜 runner와 가짜 `TaskStateQuery`): `install_activate_runs_the_documented_argv_on_task_scheduler`, `windows_activate_updates_the_stored_task_without_running_it_when_already_running`, `activate_and_deactivate_leave_a_human_installed_always_on_form_untouched`의 작업 스케줄러 행, `status_live_reports_the_always_on_form_when_present`의 작업 스케줄러 행
- 비활성화: `deactivate_calls_disable_for_a_registered_but_inactive_unit`의 Windows 행(`/End` 없이 `/Delete /F`), `deactivate_skips_when_the_unit_is_not_registered`의 Windows 행(`/Query` 0 아님)
- argv·오류: `install_activate_argv_covers_serve_listen_and_reverse_modes`의 Windows 행, `manager_argv_never_contains_user_input`의 Windows 행, `a_missing_manager_binary_is_unsupported_and_a_nonzero_exit_is_internal_with_exit_code`의 Windows 행, 계획 추가 `interactive_token_start_failure_is_internal_without_a_fallback_principal`
- 문서 대조: `service_md_activation_recipes_match_the_argv_builders`의 Windows 행
- 실경로(Windows 다리, 1건): `status_live_queries_the_real_task_scheduler_for_an_unregistered_task`(등록되지 않은 이름에 대해 `active: false`, 작업을 만들지 않음, §7.1 #9)
- `keystore_session_bound`: 실측이 "읽음"이면 `keystore_session_bound_is_silent_for_a_password_task_that_reads_credential_manager`, "못 읽음"이면 `keystore_session_bound_fires_for_platform_store_under_a_password_boot_task`. M17의 `keystore_session_bound_is_silent_on_windows_before_m19`는 그 결과 테스트로 바꾼다.

**(c) 완료 판정:** M17 plan §5.1·§5.2의 "M19 밖" 행이 모두 이 스텝의 테스트로 덮였다. `Command::new("schtasks")`가 기본 runner 한 곳에만 있다. `exit_code_matrix.rs`의 Windows 전용 `UNSUPPORTED`가 `session open` 하나다. wire diff 0.

### Step 12 — aarch64 자산, `install.ps1`, zip의 man 페이지와 목록 대조 (0.3~0.5ew)

근거: ADR-0035 결정 16 자산·man 페이지·설치 스크립트 항목, `docs/design/architecture.md` §8의 `windows-sys` 행. 선행: Step 1.

**(a) 범위:**

- `release.yml`: `aarch64-pc-windows-msvc`를 x86_64 러너에서 교차 빌드하는 matrix 행을 더한다. `Check every target is published`와 `verify-publish-path`의 목록, `SHA256SUMS`, attestation 대상에 같은 규칙으로 넣는다. aarch64 기능 확인은 캠페인 (9)다.
- Windows 패키징: zip에 `qsh.exe`와 `man/*.1`(`docs/man/`과 같은 바이트)을 담고, 패키징 스텝에 zip 안 `man/` 목록이 `docs/man/`과 같은지 대조하는 검사를 둔다.
- `scripts/install.ps1`: 아키텍처를 골라 zip을 받고 `SHA256SUMS`로 대조, `%USERPROFILE%\.local\bin`에 `qsh.exe`, `%USERPROFILE%\.local\share\man\man1`에 페이지, 사용자 `PATH`에 bin이 없으면 더한다. 관리자 권한 없음. release 자산으로도 올린다(서명은 Step 13).
- 문서: README 설치 절의 Windows 한 줄(`irm <URL> | iex`), `scripts/README.md`의 `install.ps1` 절, `RELEASE-NOTES.md`는 Windows 자산이 처음 서명된 태그 절에서(Step 13).
- M20: 없음.

**(b) 테스트·게이트:**

- `xtask/tests/install_script.rs`와 같은 무게의 `install.ps1` 검사: 계획 추가 `install_ps1_verifies_the_checksum_before_extracting`, `install_ps1_refuses_an_unknown_architecture`, `install_ps1_does_not_require_elevation`. 실행 위치는 §7.1 #11(Windows 다리의 pwsh로 로컬 가짜 release 디렉터리를 대상으로).
- `release.yml`은 브랜치 `workflow_dispatch` dry-run 경로(`verify-publish-path`)가 초록. 에이전트는 workflow를 실행하지 않는다. 실행은 사람이 하거나 PR의 CI가 하는 경로만 쓴다.
- `checked_in_man_pages_match_the_generator` 무변경 초록

**(c) 완료 판정:** 두 Windows 자산이 목록 검사에 있고 man 대조 스텝이 있다. `install.ps1`이 체크섬 대조를 건너뛰는 경로가 없다.

### Step 13 — Authenticode 서명·검증과 시크릿 게이트 (0.3~0.5ew)

근거: ADR-0035 결정 16 코드 서명·서명 검증·시크릿 게이트 항목, 결과 절의 시크릿 게이트 세 경우, 결정 19의 `docs/deploy/release-secrets.md`와 `RELEASE-NOTES.md`. 선행: Step 12.

**(a) 범위:**

- `release.yml` Windows leg: `Check for Windows signing secrets` 스텝(macOS `Check for Apple signing secrets`와 같은 셸 로직, 전부-또는-전무). 시크릿 넷이 모두 있으면 `Sign the binary`가 `sslcom/esigner-codesign`로 `qsh.exe`(두 아키텍처)와 `install.ps1`에 SHA-256 다이제스트와 RFC 3161 타임스탬프(`http://ts.ssl.com`)를 붙이고, `Verify the signature`가 `signtool verify /pa /v`와 `Get-AuthenticodeSignature`로 상태 `Valid`, 주체가 `WINDOWS_SIGN_EXPECTED_SUBJECT`, 타임스탬프 서명 존재를 확인한다. 하나도 없으면 건너뛰고 태그 push에서 `Unsigned release` 경고, 일부만 있으면 태그 push는 오류, 브랜치 `workflow_dispatch`는 경고 뒤 건너뜀.
- 순서: 빌드, 서명, 서명 검증, `release_smoke`, 패키징(서명된 바이트). `release_smoke`의 Windows 쌍둥이는 서명된 바이너리로 돈다.
- macOS와 공유하는 게이트 셸 로직을 한 스크립트(가칭 `scripts/release/secret-gate.sh`)로 빼서 세 경우를 한 번에 고정한다(ADR-0035 결과 절).
- 문서: `docs/deploy/release-secrets.md`에 Windows 서명 시크릿 넷과 변수 하나의 절(이름, 발급처 SSL.com eSigner, 회전 절차, 값은 적지 않음). `RELEASE-NOTES.md`는 Windows 자산이 처음 서명되는 태그 절에 적는다(그 태그는 사람 몫 시크릿 뒤).
- 사람 몫: 인증서와 시크릿(§0.5). 에이전트는 시크릿을 설정하지 않는다.
- M20: 없음.

**(b) 테스트·게이트:**

- `secret_gate_signs_when_all_secrets_are_present`, `secret_gate_skips_with_a_warning_when_none_are_present`, `secret_gate_fails_a_tag_push_when_some_are_present`(게이트 스크립트를 가짜 환경 변수로 돌리는 셸 테스트, 위치는 §7.1 #11)
- 서명 검증 스텝의 판정 함수(주체·상태·타임스탬프)를 pwsh 스크립트로 두고 서명되지 않은 바이너리에서 `NotSigned`로 실패함을 Windows 다리 테스트로 고정한다: 계획 추가 `windows_signature_check_fails_on_an_unsigned_binary`
- 실서명은 시크릿이 준비된 태그 run에서만 돈다. 그 전까지 DoD 6의 "검증한다"는 스텝 존재와 위 판정 테스트로 본다(§9 #8).

**(c) 완료 판정:** 시크릿 없는 PR CI와 브랜치 dry-run이 초록이고 경고를 낸다. `release-secrets.md`에 이름만 있다. 에이전트가 시크릿 관련 `gh` 명령을 부른 흔적이 없다.

### Step 14 — 캠페인 문서 `docs/campaigns/p1-windows.md` 사전 고정 (0.3~0.4ew)

근거: ADR-0035 결정 18, ROADMAP M19 DoD 캠페인 줄과 §5.5, `docs/campaigns/p1-ssh-bootstrap.md` R5(요건 4·6의 M19 이월). 선행: Step 3·5·7·9·10·12·13(회차가 가리키는 명령·자산 이름). Step 15(구현 마지막 스텝) 앞.

**(a) 범위:**

- 회차와 합격 기준. M19 몫은 (1) Windows Terminal과 conhost 각각에서 Linux·macOS host로 attach(bash/zsh 입력, 한글·이모지, vim 전체 화면과 복원, 콘솔 창 닫기 뒤 세션 생존과 모드 복원), (3)의 Windows `qsh listen` ← Linux/macOS `qsh serve --to`(attach·`cp`·터널), (4) 절전 복귀, (5) 둘째 Windows 계정의 pipe 접속 거부와 이름 선점 기동 실패, (6) 로그온 작업의 로그온 기동·강제 종료 뒤 재기동·로그오프 정지, (8) Credential Manager 왕복, (9) Windows on ARM에서 (1) 축약, (10) 상시 기동 변형의 로그오프·재부팅 생존과 `logon_task_session_scoped` 소멸, (11) 서명 주체 표시·SmartScreen·`install.ps1`·`scoop install`·`winget install`. 그리고 `p1-ssh-bootstrap` R5가 넘긴 Windows client 자동 부트스트랩(`qsh box`가 `ssh.exe`로 pin을 세우고 attach, `qsh cp` 한 번).
- host 회차 (2), (3)의 Windows target 쪽, (7)은 자리만 두고 "M20이 더해 다시 고정"이라고 적는다.
- 대상 트리 SHA 고정 칸, 회차 표, 판정 규칙. 형식은 `p1-ssh-bootstrap.md`를 따른다.
- `docs/ROADMAP.md` §5.5 행의 사전 고정 해시는 main 세션이 채운다. `CLAUDE.md` campaigns 목록에 `p1-windows`(main 세션, §9 #7).

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록. 회차가 가리키는 명령 이름이 착지한 clap 트리와 같은지 손으로 대조한다.

**(c) 완료 판정:** 문서가 Step 15 착지 전에 main에 있다. M19 회차와 M20 자리가 구분돼 있다.

### Step 15 — scoop·winget job (0.3~0.5ew)

근거: ADR-0035 결정 16 패키지 관리자 항목. 선행: Step 12, Step 14.

**(a) 범위:**

- `release.yml`에 `scoop-bucket` job: `DaveDev42/scoop-bucket`의 `bucket/qsh.json`을 새 버전·URL·해시로 bump한다(두 아키텍처, `checkver`·`autoupdate`). 쓰기는 `SCOOP_BUCKET_DEPLOY_KEY` 하나로 범위를 좁힌다.
- `winget` job: `wingetcreate update --submit`으로 `microsoft/winget-pkgs`에 `DaveDev42.qsh` 갱신 PR(설치 형식 zip 안 portable). `WINGET_PAT`.
- 두 job은 `homebrew-tap`과 같이 시크릿이 없으면 green인 채 건너뛰고 `continue-on-error`로 release를 붉히지 않는다. 매니페스트는 `man/*.1`을 설치하지 않는다(같은 내용은 `qsh help`).
- 매니페스트 템플릿을 저장소에 두고(가칭 `packaging/scoop/qsh.json.in`, `packaging/winget/`) job이 값을 채운다.
- 문서: `docs/deploy/release-secrets.md`에 `SCOOP_BUCKET_DEPLOY_KEY`·`WINGET_PAT` 절, README 설치 절의 `scoop install`·`winget install` 줄(첫 매니페스트 제출 전에는 "after the first manifest is accepted" 단서).
- 사람 몫: 저장소 생성, 배포 키, PAT, 첫 winget 매니페스트 제출(§0.5).
- M20: 없음.

**(b) 테스트·게이트:**

- 매니페스트 렌더 테스트: 계획 추가 `scoop_manifest_renders_both_architectures_with_hashes_from_sha256sums`, `winget_manifest_renders_a_portable_zip_installer`(xtask 또는 셸 테스트, §7.1 #11)
- 게이트: `package_jobs_skip_green_without_secrets`(시크릿 없는 dry-run에서 두 job이 건너뜀)

**(c) 완료 판정:** 시크릿 없는 run에서 두 job이 green으로 건너뛴다. 에이전트가 외부 저장소에 쓰지 않았다.

### Step 16 — 마감 (0.1~0.2ew)

근거: 마일스톤 마감 공통 절차(`docs/ROADMAP.md` §2) 1·2, 이 문서 §4의 안정성 규율과 §5.7 유예 대응표. 선행: Step 2~15.

**(a) 범위:**

- **부하 반복.** M19 타이밍 민감 테스트 전부를 `scripts/stress/m19.filter`로 묶는다(§7.1 #12). Linux·공통은 Dave-Windows-WSL에서, Windows 전용은 Dave-Windows에서 `QSH_ACCEPTANCE_SLOW=1 scripts/stress/run.sh`로 50회 돌리고 각각의 "50/50 passed under load" 줄, 테스트 개수, 호스트 사양을 마감 노트에 적는다. `m19-latency.filter`는 두지 않는다.
- **절차 1. 구속 문서 태그 대조.** 대상은 다음과 같다.
  - `docs/CLI.md` M19 판 이후 항목: §6.2·§6.9·§6.11·§6.13·§6.14·§6.17·§6.18·§6.20·§6.21·§7
  - `docs/deploy/service.md` Windows 절, `docs/deploy/release-secrets.md` Windows 절
  - `docs/design/architecture.md` §1·§6·§7·§8, `docs/design/testing.md` L1·L5·Windows leg 문단·신뢰 철회 문단·가짜 ssh 문단
  - `docs/design/threat-model.md` §3·§4 A·B·D·E·G·§7
  - ADR-0035 결과 절 "마일스톤 배치"의 M19 항목 전수와 결정 19의 client 쪽 문서 목록, ADR-0032 결정 3·4·10·11·15·18의 Windows 문장, ADR-0033 결정 6·13, ADR-0031 결정 3, ADR-0029 결정 2·23, ADR-0044 결정 25, ADR-0023의 절전 전제
  - 코드 모듈 doc: `localctl/mod.rs`, `resume.rs`, `client/wake.rs`, `ops/service/mod.rs`, `file/operand.rs`, `auto_bootstrap.rs`, `doctor.rs`·`doctor/probe.rs`
  - §5.7 유예 대응표의 모든 행이 착지했거나 M20·범위 밖으로 남았다. `rg -n "M19"`를 다시 돌려 남은 hit가 기록(ADR 개정 이력, ROADMAP 마감 노트, 캠페인 문서)뿐임을 확인한다.
  - M20 귀속 기록: ConPTY·PTY 세션·신호·host `exec`·host audit 잠금과 `acl.toml` 경고·`setup host`·`pair invite`·`pair ssh-respond`·host `cp`·`release_smoke` PTY 축·`session close --signal` 행·PTY를 포함한 종단과 `cp` 종단·캠페인 host 회차(ADR-0035 결정 20~26, 결과 절)
- **절차 2. README 동기화.** 기능 목록(Windows client), 설치 절(`install.ps1`, scoop, winget, 서명), Known limitations(Windows host는 M20, mintty, VT 하한 1809, 방화벽 프롬프트, Windows ACL 문장 삭제 확인, 부트스트랩 응답자는 M20), 보안 절(named pipe 신뢰 모델). README Roadmap 표의 M19 행을 "Done"으로.
- §3 유예 가드레일 Windows 행을 "client는 M19 착지, host는 M20"으로 고치는 일은 main 세션이 마감 노트와 함께 한다.
- ROADMAP M19 마감 노트(main 세션). 이 `PLAN.md`의 마지막 커밋 해시를 적고 다음 계획으로 교체한다. §5.5에 M19가 만든 사람 몫(캠페인, 서명·배포 준비)을 적는다.

**(b) 테스트·게이트:** 일곱 게이트, CI(acceptance 포함) 초록, 부하 반복 50/50 두 호스트.

**(c) 완료 판정:** §3의 DoD가 근거 커밋, run id와 함께 `[x]`다. `git diff --stat <Step 2 부모>..<마지막 구현 스텝 머지> -- crates/qsh-proto/proto crates/qsh-proto/src/wire.rs crates/qsh-proto/src/local.rs crates/qsh-cli/tests/fixtures/cli-v1/capabilities.json`이 비어 있다. M19에는 wire 변경을 소유한 스텝이 없다.

## 5. 결정·핀 테스트 대응표

각 결정과 핀 테스트의 주인은 스텝 하나다. 한 결정이 여러 스텝에 걸치면 하위 항목으로 나눠 각각 주인 하나를 적는다. "M20 밖"은 이 계획이 하지 않고 M20이 하는 것이다.

### 5.1 ADR-0035 결정

| 결정 | 스텝 |
|---|---|
| 1 client 쪽 명령 집합(`init`~`schema`), `move-key`·`audit` 포함 | 3·5·7·8·9(명령별) |
| 1 host 쪽 명령 집합 | M20 밖 |
| 1 서비스 명령과 `setup listener --service` | 10 |
| 1 `setup host --service` | M20 밖 |
| 1 `qsh cp` 드라이브 문자 operand | 9 |
| 2 UNSUPPORTED 경로 제거: `NO_TERMINAL_ECHO_SUPPRESSION` | 3 |
| 2 같은 항목: `windows_unsupported()`, `ops/exec.rs` reverse 분기 | 7 |
| 2 같은 항목: `tui::run` 비unix 분기 | 9 |
| 2 같은 항목: `SERVICE_UNSUPPORTED_PLATFORM` Windows 분기 | 10 |
| 2 같은 항목: `UnsupportedFactory` | M20 밖 |
| 3 client·서비스 행의 매트릭스 조건 | 9(client), 11(서비스), 16(확인) |
| 3 `session close --signal` Windows 행 | M20 밖 |
| 4 터미널 trait 추출 | 2 |
| 4 Windows 구현 | 3 |
| 5 raw 모드 비트(순수 함수) | 2 |
| 5 raw 모드 적용과 UTF-8 코드 페이지 | 3 |
| 6 복원 경로 | 3 |
| 7 VT 하한과 비 콘솔 경로 | 3 |
| 8 resize 폴링, `term` 기본값 | 3 |
| 9 DACL 모듈과 적용처(작업 정의 파일 제외) | 4 |
| 9 작업 정의 파일·서비스 로그 | 10 |
| 10 fail closed, 옛 ACL 교체, README 문장 삭제 | 4 |
| 11 에코 억제 모드 비트 | 2 |
| 11 콘솔 프롬프트 개방과 ConPTY 단언 | 3 |
| 12 store 경로 판정 | 2 |
| 12 Credential Manager store, `auto`, `move-key` 왕복 | 5 |
| 12 `Password` 작업의 Credential Manager 실측 | 11 |
| 13 Windows 경로(`%USERPROFILE%\.config\qsh` 등) | 4(DACL 대상 확인과 architecture §7) |
| 14 transport·이름·DACL·SID 대조·xtask | 6 |
| 14 `qsh listen`의 나머지, 동작 요약 | 7 |
| 15 supervise와 절전 표본 | 8 |
| 16 aarch64 자산, man, `install.ps1` | 12 |
| 16 Authenticode 서명·검증·시크릿 게이트 | 13 |
| 16 scoop·winget | 15 |
| 17 DACL 테스트 | 4 |
| 17 named pipe 테스트 (2)~(6) | 6 |
| 17 named pipe 테스트 (1) 기동 실패 | 7 |
| 17 콘솔 계층 테스트 | 2(하니스), 3(단언) |
| 17 host 테스트 | M20 밖 |
| 17 정방향·역방향 종단(PTY 없음) | 7 |
| 17 같은 종단의 attach 케이스(echo host) | 9 |
| 17 같은 종단의 PTY·`cp` 케이스 | M20 밖 |
| 17 절전 표본 단위 테스트 | 8 |
| 17 `service_docs.rs` Windows 펜스 | 10 |
| 17 `release_smoke` 쌍둥이(PTY 축 제외) | 9 |
| 17 `release_smoke` PTY 축 | M20 밖 |
| 18 캠페인 사전 고정(client·서비스·서명·패키지 회차) | 14 |
| 18 host 회차 추가와 재고정 | M20 밖 |
| 19 threat-model §3 콘솔 입력 | 3 |
| 19 threat-model §4 D | 4 |
| 19 threat-model §3 pipe, §4 A·B, §7 | 6 |
| 19 threat-model §3 작업 정의 | 10 |
| 19 threat-model PTY 행, §4 E `acl.toml` | M20 밖 |
| 19 architecture §1·§7 localctl | 6 |
| 19 architecture §8 keystore 행 | 5 |
| 19 architecture §8 `windows-sys` 행 | 3(첫 의존 착지) |
| 19 architecture §4 PTY 절 | M20 밖 |
| 19 testing.md L5·Windows leg 문단 | 16(client 쪽 대조), M20(host) |
| 19 CLI.md §6.9·§6.13·§6.14 | 7·8 |
| 19 CLI.md §6.11 | 3·5 |
| 19 CLI.md §6.17·§6.18·§6.20 | 10·11 |
| 19 CLI.md §6.7·§6.12, §7의 host 환경변수 | M20 밖 |
| 19 CLI.md §7 client 범위 | 3·9 |
| 19 release-secrets.md, RELEASE-NOTES.md | 13·15 |
| 19 service.md Windows 절 | 10·11 |
| 19 xtask/arch.rs | 6 |
| 19 README Known limitations·설치 절 | 4·12·16 |
| 19 ROADMAP §3 Windows 행 | 16(main 세션) |
| 19 모듈 doc(`resume.rs`, `localctl/mod.rs`, `client/wake.rs`, `ops/service/mod.rs`) | 4·6·8·10 |
| 19 모듈 doc(`pty/mod.rs`) | M20 밖 |
| 20~24, 26 | M20 밖 |
| 25 `serve --to` 게이트 제거 | 7 |
| 25 나머지 | M20 밖 |
| 27 작업 정의·`service run`·재시작·수명·등록·doctor·`manager` 값 | 10 |
| 28 Windows 열 활성화·비활성화·COM 상태·상시 기동 형태 보존 | 11 |

### 5.2 ADR-0035 결과 절의 고정 테스트

| 항목 | 스텝 |
|---|---|
| `exit_code_matrix.rs` client·서비스 Windows `UNSUPPORTED` 행 없음 | 9·11 |
| 같은 파일의 `session close --signal` 일곱 값 행 | M20 밖 |
| Windows DACL 테스트(보호·단일 ACE·SID·마스크, 실패 주입, 옛 ACL 교체, audit·reset key) | 4 |
| 콘솔 모드 계산 단위 테스트 | 2 |
| ConPTY probe 테스트(raw, resize 한 번, 복원, 비 콘솔, VT 하한, 초대 코드) | 3 |
| named pipe 테스트(선점 기동 실패) | 7 |
| named pipe 테스트(DACL, SID 불일치, 이름·열거, 공통 케이스) | 6 |
| `pty/tests.rs` Windows 쌍둥이, `exec` 트리 종료, audit 잠금, `acl.toml` 경고 | M20 밖 |
| 정방향·역방향 종단(`exec`, 터널, `hosts`, 재등록) | 7 |
| 같은 종단의 attach(echo host) | 9 |
| 같은 종단의 PTY attach와 `cp` | M20 밖 |
| 절전 표본 단위 테스트 | 8 |
| `service_docs.rs` Windows 펜스, 작업 정의 렌더·경로·존재, `service run` 리디렉션, `logon_task_session_scoped` 세 경우 | 10 |
| `--live` 판정(가짜 COM) | 11 |
| `release.yml` 서명 검증 스텝, zip `man/` 대조 | 12·13 |
| 시크릿 게이트 세 경우 | 13 |
| `release_smoke` 쌍둥이 확장(PTY 제외) | 9 |
| unix 회귀(`tui_expect`, attach·localctl 테스트) | 2·6·7 |

### 5.3 ADR-0032 Windows 갈래 (M17 plan §5.1·§5.2 (`047db25`)의 "M19 밖" 행)

| 항목 | 스텝 |
|---|---|
| 결정 3 작업 스케줄러 열과 COM 질의 | 11 |
| 결정 4 Windows `/Create /F` 실측과 처분 | 11 |
| 결정 5 Windows 등록 기준(`/Query`) 비활성화 | 11 |
| 결정 6 COM 상태값 하나 | 11 |
| 결정 8 Windows 오류 사상 | 11 |
| 결정 10 Windows 분기 구현 | 11 |
| 결정 11 Windows 레시피 문서 대조 | 10(작업 정의 펜스), 11(`schtasks` 레시피) |
| 결정 12 상시 기동 자동 설정 없음(Windows) | 10 |
| 결정 15 `keystore_session_bound` Windows 실측과 판정 | 11 |
| 결정 15 `move-key` Credential Manager와 DACL | 5(store), 4(DACL) |
| 결정 18 상시 기동 형태 보존(Windows `Password` 주체) | 11 |
| `install_activate_runs_the_documented_argv_on_task_scheduler` | 11 |
| `windows_activate_updates_the_stored_task_without_running_it_when_already_running` | 11 |
| `activate_and_deactivate_leave_a_human_installed_always_on_form_untouched` 작업 스케줄러 행 | 11 |
| `status_live_reports_the_always_on_form_when_present` 작업 스케줄러 행 | 11 |
| `service_activation_flags_are_unsupported_on_windows_before_m19` 제거 | 11 |
| `keystore_session_bound_is_silent_on_windows_before_m19` 교체 | 11 |
| `move_key_file_store_is_mode_0600`의 Windows 쌍둥이 | 4 |
| `docs/design/testing.md` L1 Windows `move-key` 왕복 | 5 |

### 5.4 ADR-0033 Windows 항목

| 항목 | 스텝 |
|---|---|
| 결정 4·13 named pipe localctl 비노출 | 6 |
| 결정 6 읽기 불가 로그의 Windows ACL 행 | 4 |
| 결정 13 `qsh audit`의 세 역할 동등(Windows) | 7 |
| 결정 13 세션 필터 reverse fan-out(Windows `qsh listen`) | 8 |

### 5.5 다른 ADR이 M19로 넘긴 항목

| 항목 | 스텝 |
|---|---|
| ADR-0031 결정 3 `trust_withdrawal.rs` `listen` 쌍둥이 | 8 |
| ADR-0031 결정 3 `serve_to` 쌍둥이 | 8(§9 #3) |
| ADR-0029 결정 2 드라이브 문자 operand | 9 |
| ADR-0029 결정 23 Windows client 로컬 쓰기 | 9 |
| ADR-0029 결정 23 Windows host 파일 op | M20 밖 |
| ADR-0044 결정 1·5·25 Windows client 자동 발동 | 9 |
| ADR-0044 결정 22 `--reverse`의 이 장비 쪽 | 9 |
| ADR-0044 결정 10·14·25 응답자 | M20 밖 |
| ADR-0023 절전 감지의 Windows 전제(ADR-0035 결정 15가 대체) | 8 |

### 5.6 route 동등 핀의 귀속

§4 규율 "route 동등" 표가 정본이다. 한 테스트가 두 스텝에 걸치는 것은 `move_key_then_serve_listen_and_serve_to_handshake_with_unchanged_pins`(inbound `serve` 행 Step 5, `listen`·`serve --to` 행 Step 7) 하나다.

### 5.7 M19 유예 hit 대응표 (`rg -n "M19"`, origin `e47ffd9`)

`PLAN.md`(M17 계획)와 `docs/ROADMAP.md`, ADR-0035의 hit는 위 §5.1~§5.5가 덮는다. 나머지는 다음과 같다.

| 위치 | 내용 | 귀속 |
|---|---|---|
| `README.md` Known limitations(Windows 계획 문단) | client M19·host M20, 자동 부트스트랩은 M19 | 9(부트스트랩 문장), 16(문단 갱신) |
| `CLAUDE.md` Document map | "M11–M19 (P1)" | Step 1 (main 세션, §9 #7). 유예가 아니라 낡은 범위 |
| `docs/adr/README.md` ADR-0035 행 | 제목의 "M19 client" | 귀속 불요(ADR 제목) |
| `docs/adr/0043-no-tcp-fallback.md` 결정 2 | 번호 M15~M19 유지 | 귀속 불요(번호 기록) |
| `docs/adr/0039-forced-doh-resolver.md` 맥락 | M11~M19에 resolver 없음 | 귀속 불요(사실 기록) |
| `docs/adr/0023-tunnel-supervise.md` 절전 전제 | Windows 확인은 M19 | 8 |
| `docs/adr/0031-cert-rotation-revocation.md` 개정 이력·결정 3 | `listen` 쌍둥이 M19 | 8 |
| `docs/adr/0029-file-copy.md` 결정 2·23 | Windows client operand·로컬 쓰기 | 9 |
| `docs/adr/0044-ssh-bootstrap.md` ADR-0035 문단 | Windows client 자동 발동 | 9 |
| `docs/adr/0032-service-manager-activation.md` 결정 10·결과 절 크기 | Windows 분기 구현 | 11(크기 문장은 귀속 불요) |
| `docs/PRD.md` P1 목록 | Windows client M19 | 16(대조) |
| `docs/CLI.md` 상태 헤더 v0.37·v0.38 | `move-key`·`keystore_session_bound` Windows | 5·11(새 판에 적고 옛 판 문면은 두지 않고 고치지도 않음) |
| `docs/CLI.md` §6.2 route 문단 | Windows `qsh listen` fan-out | 8 |
| `docs/CLI.md` §6.11 `move-key` Windows 문단 | Credential Manager·DACL | 4·5 |
| `docs/CLI.md` §6.17 진단 머리 문장·`keystore_session_bound` 행 | Windows는 M19 전 미발화 | 11 |
| `docs/CLI.md` §6.21 Windows 문단 | Windows client `cp` | 9 |
| `docs/CLI.md` 부트스트랩 터미널 순서 문단 | Windows 분기 | 9 |
| `docs/design/architecture.md` §6 audit 조회 문단 | 읽기 불가 Windows ACL 행 | 4 |
| `docs/design/threat-model.md` §3 `identity move-key` 행 | Windows 구현 M19 | 5 |
| `docs/design/testing.md` L1 `move-key` 왕복 | Windows 줄 | 5 |
| `docs/design/testing.md` 가짜 ssh 문단 | 역방향의 이 장비 쪽 `qsh listen` Windows M19 | 9 |
| `docs/design/testing.md` 신뢰 철회 문단 | `listen` 쌍둥이 M19 | 8 |
| `docs/campaigns/p1-ssh-bootstrap.md` R5 | 요건 4·6 이월 | 14(p1-windows 회차로 받음, 사전 고정된 R5 문면은 고치지 않음) |
| `crates/qsh-core/src/doctor.rs`(`KEYSTORE_SESSION_BOUND` 문단 둘) | Windows 미발화 | 11 |
| `crates/qsh-core/src/doctor/probe.rs`(두 곳) | Windows 미발화 | 11 |
| `crates/qsh-core/src/doctor/tests.rs`, `doctor/probe/tests.rs` | 같음 | 11 |
| `crates/qsh-cli/tests/it/fixtures.rs` doctor fixture Windows 건너뜀 | 같음 | 11 |
| `crates/qsh-cli/src/auto_bootstrap.rs` 모듈 doc | Windows 자동 발동 | 9 |
| `crates/qsh-core/src/audit/reader/tests.rs` 주석 | Windows 읽기 불가 행 | 4 |
| `crates/qsh-cli/tests/it/identity_move_key.rs` 주석 | Windows `--to platform` | 5 |
| `crates/qsh-core/src/file/operand.rs` 모듈 doc | 드라이브 문자 규칙 | 9 |
| `crates/qsh-cli/tests/it/sessions_filter.rs` 모듈 doc | Windows fan-out 쌍둥이 | 8 |
| `crates/qsh-core/src/client/wake.rs` 모듈 doc | Windows 절전 전제 | 8 |

## 6. 명시적 non-goals

- Windows host 역할 전부(M20). ConPTY 백엔드와 PTY 세션, 세션 신호 일곱과 `qsh internal console-ctrl`, host `exec`의 Job Object·환경 고정, host audit writer 잠금·재검증, `acl.toml` DACL 경고, `setup host`, `pair invite`, `pair ssh-respond`, host 쪽 `qsh cp`와 `paths` 드라이브 표기, `release_smoke` PTY 축, `session close --signal` 매트릭스 행, PTY와 `cp`를 포함한 종단, 캠페인 host 회차(ADR-0035 결정 20~26, ROADMAP M20).
- MSI 설치 관리자(ROADMAP M19 명시적 out). 내장 roff 렌더러(결정 16).
- crossterm 채택, 키 파싱, `ReadConsoleInput` 이벤트 기반 resize, resize 간격 설정 키(결정 4·5·8).
- `%APPDATA%`·`%LOCALAPPDATA%` 경로, runtime dir 생성(결정 13).
- `icacls` 호출, 읽을 때의 ACL 검사(결정 9·10).
- 로그인 세션 밖 상시 기동의 자동 설정. qsh는 Windows 상시 기동 작업을 대신 등록하지 않는다(ADR-0032 결정 12·16, ADR-0035 결정 27). S4U 주체(결정 27).
- `schtasks /Query` 본문 파싱(ADR-0032 결정 6).
- test-only 역방향 하니스(ADR-0035 결정 17). §7.1 #4의 echo host는 PTY attach를 대신하는 테스트 host이고 역방향 CI 종단은 실제 CLI 양쪽이다.
- 새 `ErrorCode`, 새 wire 메시지, `.proto`·`local.rs` 변경, `capabilities.json` 변경.
- 에이전트가 하는 `gh secret set`, `gh variable set`, `gh workflow run`, 태그 push, 저장소 설정 변경, 외부 저장소 쓰기.
- P2 전부.

## 7. 리스크와 감시 항목

- **산정 신뢰도(ROADMAP §5.4 리스크 5).** 비교 표본이 없다. Step 2 뒤 재산정하고, 그 뒤에도 Step 6(pipe)과 Step 3(콘솔)이 예상 상한을 넘으면 main 세션이 범위 순서를 다시 정한다. 출고 사슬(Step 12·13·15)은 독립이라 일정 압박의 완충으로 쓴다.
- **unix 회귀.** trait 추출과 localctl 분리는 unix의 가장 민감한 경로(attach echo 예산, localctl 권한)를 만진다. acceptance job과 `localctl_perms::`를 각 PR의 필수 확인으로 둔다. echo 예산 단언(`tunnel_echo_under_load` 등)이 흔들리면 그 PR은 착지하지 않는다.
- **Windows 러너의 ConPTY 안정성.** `windows-latest`의 ConPTY는 conhost 버전에 따라 출력 순서·초기 크기 보고가 다를 수 있다. probe는 바이트 흐름이 아니라 probe가 보고한 줄로 단언하고, 대기는 관찰 가능한 줄로 한다.
- **pipe accept 경합.** "다음 인스턴스를 넘기기 전에 만든다"를 어기면 이름이 비는 틈이 생기고 테스트가 간헐로 실패한다. 경합 테스트를 Windows 부하 반복에 넣는다.
- **CI 러너에서의 Credential Manager·COM.** 러너가 서비스 계정으로 돌아 Credential Manager 쓰기나 작업 스케줄러 COM 연결이 다르게 동작할 수 있다. 실경로 테스트는 각각 하나로 줄이고(§7.1 #6·#9), 안 되면 주입 테스트와 §1의 Dave-Windows 수동 단계로 덮는다.
- **서명 시크릿의 공백.** 사람 몫이 늦으면 서명된 Windows 태그가 M19 마감 뒤로 밀린다. DoD 6은 스텝 존재와 판정 테스트로 닫고, 실서명 태그는 캠페인 (11)의 선행 조건으로 §5.5에 둔다(§9 #8).
- **방화벽 프롬프트.** Windows 러너의 loopback UDP는 방화벽 프롬프트 없이 열리지만 실제 장비에서는 첫 실행에 프롬프트가 뜬다. README와 캠페인 (3)이 본다.
- **Windows 다리의 시간.** Windows 종단과 ConPTY 테스트가 test leg 시간을 늘린다. nextest 병렬도와 필터를 바꾸지 않고, 길어지면 main 세션이 Windows 종단을 별도 job으로 뗄지 정한다(§9 #9).

### 7.1 구현 중 확정할 값 (해당 step (a)에 근거와 함께 추기)

| # | 질문 | 초안 | 확정 시점 |
|---|---|---|---|
| 1 | 터미널 trait의 경계 | raw guard·크기 조회·stdin 읽기·끊김 신호 넷. stdout 쓰기는 trait 밖(양쪽 모두 `std::io::Stdout`) | Step 2 |
| 2 | DACL 모듈의 자리 | `fsutil.rs`를 디렉터리로 바꾸지 않고 형제 `fsutil_dacl.rs`(가칭)를 둔다. `fsutil`은 `xtask arch`의 path-scoped 금지 대상이 아님을 확인하고, 바꾼다면 같은 커밋에서 `arch.rs`를 본다 | Step 4 |
| 3 | DACL 실패 주입 seam | 생성 함수가 `&dyn SecurityDescriptorSource`(가칭)를 받는 `*_with` 쌍둥이를 두고 공개 함수만 기본 구현을 만든다(`ManagerRunner`와 같은 모양) | Step 4 |
| 4 | Windows client attach의 종단 host | Windows host PTY가 M20이므로 qsh-testkit의 `EchoPipeFactory`를 쓰는 in-process host(forward: `loopback`, reverse: testkit target이 실제 Windows `qsh listen`에 등록)를 실제 UDP loopback에 띄우고, ConPTY 안의 실제 `qsh` 바이너리가 붙는다. 역방향 CI 종단(Step 7)은 실제 CLI 양쪽이라 ADR-0035 결정 17의 "test-only 하니스 없음"과 겹치지 않는다. M20이 같은 케이스를 실제 `qsh serve`로 바꾼다(§9 #4) | Step 9 |
| 5 | Credential Manager 구현 경로 | keyring-core 계열 Windows store crate가 `cargo deny`를 넘으면 그것, 아니면 `windows-sys` `Win32_Security_Credentials` 직접 구현. **판정(2026-10-16):** `windows-native-keyring-store` 1.1.0(MIT OR Apache-2.0, keyring-core 1, 의존은 `windows-sys` 0.61·`zeroize`·`byteorder`, `default-features = false`로 `regex` 제외)을 `qsh-core`의 `cfg(windows)` 의존으로 시험 추가했을 때 `cargo deny check`의 advisories·bans·licenses·sources가 모두 ok였다. 그래서 crate를 쓴다. macOS·Linux와 같은 keyring-core 1 계열이라 `identity/keystore.rs`의 store 생성 분기 하나만 늘어난다 | Step 2(판정), Step 5 |
| 6 | 러너 위 실제 Credential Manager | `CredWriteW`가 러너 계정에서 되면 고유 target 이름으로 왕복 테스트 하나를 둔다. 안 되면 두지 않고 L1 수동 단계만 | Step 5 |
| 7 | 한 글자 host와 드라이브 문자의 경계 | Windows 빌드에서 `C:path`는 로컬. 한 글자 host는 `user@c:path`나 `[c]:path`로만 원격(ADR-0029 결정 2의 대괄호 규칙). unix 빌드는 지금 그대로. CLI.md §6.21에 한 문장 | Step 9 |
| 8 | Windows 콘솔 닫힘과 `qsh listen` 종료 | `SetConsoleCtrlHandler`를 `qsh listen`과 대화형 client가 공유하는 `qsh-cli` 헬퍼 하나로 두고, `qsh-core`는 종료 future만 받는다 | Step 7 |
| 9 | COM 실경로 테스트 | 등록되지 않은 작업 이름(`\qsh-test\absent-<난수>`)에 대한 `TaskStateQuery`가 "실행 중 아님"이고 아무것도 만들지 않음 하나만. 실제 등록을 만드는 테스트는 두지 않는다 | Step 11 |
| 10 | `logon_task_session_scoped` fixture | ADR-0035 결과 절대로 새 fixture를 두지 않는다. M17의 `doctor.run.keystore_session_bound.json`은 Linux에서 재현 가능했지만 이 finding은 Windows에서만 나므로 golden 생산 테스트가 Windows 다리 전용이 된다. `EXPECTED_DOCTOR_CODES`·§6.17 대조와 단위 테스트로 충분하다고 본다. main 세션이 다르게 정하면 Windows 전용 golden 하나를 더한다 | Step 10 |
| 11 | 릴리스 스크립트 테스트의 자리 | `install.ps1`·게이트 스크립트·매니페스트 렌더는 `xtask/tests/` 아래 새 파일이 아니라 기존 `xtask/tests/install_script.rs`에 모듈을 더하는 쪽(통합 파일 하나 규칙 유지). pwsh가 필요한 케이스는 `cfg(windows)` | Step 12 |
| 12 | M19 부하 filterset과 Windows 실행 | 모듈 접두 `console_probe::`, `windows_forward_e2e::`, `windows_reverse_e2e::`, `windows_attach::`, `trust_withdrawal::listen::`, `sessions_filter::`와 pipe 경합·`service run` 리디렉션 테스트 이름. `m17.filter`와 같은 `(?:\w+::)?` 꼴. Windows는 Dave-Windows의 Git for Windows bash로 `scripts/stress/run.sh`를 돌리고, 부하 생성기가 POSIX 전용이면 같은 커밋에서 Windows 분기를 더한다 | Step 3·16 |
| 13 | `qsh service run`의 숨김 확인 | `checked_in_man_pages_match_the_generator`가 `hide = true` 항목을 렌더하지 않으면 그대로, 렌더하면 생성기에서 거른다(ADR-0035 결과 절) | Step 10 |
| 14 | 데몬 재시작 재등록 테스트의 대기 | target의 재등록 backoff를 config로 줄이고(기존 키가 있으면 그것), `qsh hosts --json`의 reverse 항목 출현을 넉넉한 timeout으로 기다린다 | Step 7 |

## 8. 완료 절차

1. §3 DoD 전건을 실제 테스트와 CI run으로 확인한다. 체크박스는 근거가 초록일 때만 채운다.
2. 부하 반복 50/50을 두 호스트에서 기록한다(Step 3·6·7·8·9·10·16).
3. 구속 문서 태그를 대조하고 §5.7 표의 모든 행을 확인한다(Step 16 (a)).
4. README를 동기화한다.
5. `docs/ROADMAP.md` "현재 위치"와 M19 절을 갱신하고 마감 노트를 적는다(main 세션). §3 Windows 행과 §5.5 사람 몫 행을 고친다.
6. §0.1~§0.5의 상태를 승계한다.
7. 이 `PLAN.md`를 다음 계획으로 교체하고, 마감 노트에 이 계획의 마지막 커밋 해시를 적는다. 다음 마일스톤은 M18 착수 조건(M8 DoD 3)이 그때 닫혀 있으면 M18, 아니면 M20이다(M20의 착수 조건은 M19 닫힘). M18을 다시 건너면 그 사실을 §5.1에 날짜와 함께 적는다.

## 9. 열린 질문

각 항목의 권고는 main 세션이 Step 1 커밋에서 결정으로 확정했다(2026-10-16, 1~12 모두 권고대로). 2026-10-14 사용자 위임 결정("전부 다 알아서 진행해")의 범위다. #3은 ADR-0031 개정 이력에 2026-10-16 줄로, #1·#2·#4는 ROADMAP M19·M20 절에, #7의 앞 두 항목은 M17 마감 절차 커밋 `f87692e`에 반영됐다.

1. **ROADMAP M19 DoD 첫 줄의 `qsh cp`.** "Windows `qsh listen` ← Windows `qsh serve --to`의 실제 CLI로 역방향 종단(… ADR-0029 착지 뒤 `qsh cp`)"은 M19에서 돌 수 없다. Windows host의 파일 op는 M20이고(ADR-0029 결정 23, ADR-0035 결정 26), 그 전까지 Windows host는 `file.v1`을 광고하지 않는다. ADR-0029는 이미 M15에 착지했으니 "착지 뒤"라는 조건이 이미 참이 되어 DoD가 불가능한 항목을 요구하게 된다. **권고:** M19 DoD에서 `cp` 종단을 빼고 "Windows client의 `qsh cp`는 드라이브 문자 operand와 로컬 쓰기 규칙을 단위·통합 테스트가 고정한다"로 바꾼다. 종단은 M20 DoD의 기존 `qsh cp` 줄이 두 route로 맡는다. 실제 Linux·macOS host 상대 Windows client `cp`는 캠페인 (3)이 본다.
2. **ROADMAP M19 DoD에 안정성 줄.** M12·M15·M16·M17에는 있고 M19에는 없다. **권고:** "M19가 더한 타이밍 민감 테스트는 Linux와 Windows 각각에서 부하 아래 50회 연속 초록(`scripts/stress/run.sh`, `scripts/stress/m19.filter`)"을 더한다. 지연 예산 단언이 없으므로 `-j 1` 대체 문장은 넣지 않는다.
3. **`trust_withdrawal.rs`의 `serve_to` 쌍둥이.** ADR-0031 결정 3과 개정 이력, `docs/design/testing.md`, ROADMAP M16 마감 노트는 이것을 M20(Windows host)으로 적었다. 그러나 M19가 `qsh serve --to`의 Windows 게이트를 걷고(ADR-0035 결정 25 일부) 역방향 CI가 실제 Windows `serve --to`를 돌린다. 재검증 감시는 PTY와 무관해서 M19에서 돌 수 있다. **권고:** Step 8에서 `serve_to` 모듈의 `cfg(unix)`도 걷고, ADR-0031 개정 이력에 "M19가 `serve --to` 게이트를 걷으면서 쌍둥이도 당겼다"는 한 줄을 main 세션이 더한다(결정 내용은 바뀌지 않음). 당기지 않는다면 Step 8 범위에서 빼고 §5.5 행을 M20으로 둔다.
4. **ROADMAP M19 범위 문장의 누락.** ADR-0035 결정 1 목록의 `qsh identity move-key`·`qsh audit`, 그리고 M16·M17이 M19로 넘긴 쌍둥이(신뢰 철회 `listen`, 세션 필터 fan-out, `audit.query` pipe 비노출, Windows client 자동 부트스트랩)가 M19 범위·DoD 문장에 이름으로 없다. 마감 공통 절차 1의 "후속 마일스톤에 명시 귀속"을 M16·M17 쪽에서 증명하려면 M19 쪽에 이름이 있어야 한다. 함께, Windows client의 대화형 attach 종단은 Windows host PTY가 없어 테스트 host(§7.1 #4)로 돈다는 사실도 적는다. **권고:** Step 1이 M19 범위에 한 문장, DoD에 "M16·M17이 넘긴 Windows 쌍둥이(…)가 Windows leg에서 초록" 한 줄을 더한다.
5. **CLI.md 상태 헤더의 옛 판 서술.** v0.37·v0.38 항목이 "Windows는 M19 전에는 …"이라고 적는다. 헤더는 판별 기록이라 옛 판 문면을 고치지 않는 것이 지금까지의 관행이다. **권고:** 옛 판은 그대로 두고 M19 판 항목이 "v0.37·v0.38의 Windows 단서를 걷는다"로 적는다. §5.7 표의 해당 행은 이것으로 닫는다.
6. **ROADMAP M19 DoD의 DACL 대상.** DoD는 identity 키, `resume.json`, `trust.toml`, audit 로그, `stateless_reset.key` 다섯만 적고 ADR-0035 결정 9는 CA 산출물, `config.toml`, 잠금·임시 파일, 디렉터리, 작업 정의 파일까지 적는다. **권고:** DoD 문장은 그대로 두고 이 계획의 테스트가 결정 9 목록 전부를 덮는다(Step 4·10). ROADMAP 수정은 필요 없다.
7. **`CLAUDE.md`의 낡은 문장.** Document map이 ROADMAP을 "M11–M19 (P1)"로 적지만 P1은 M11~M20이다. campaigns 목록에 `p1-ssh-bootstrap`이 두 번 있다. **권고:** Step 1에서 main 세션이 고치고, `p1-windows`는 Step 14 착지 뒤 더한다.
8. **DoD 6의 "서명 검증"과 사람 몫 시크릿.** 시크릿이 없으면 서명·검증 스텝은 건너뛴다. DoD가 실서명 run을 요구하면 M19가 사람 몫에 막힌다(§5.1 원칙 6은 사람 회차를 DoD에 넣지 않는다). **권고:** DoD 6은 스텝 존재, 게이트 세 경우의 테스트, 서명되지 않은 바이너리에서 판정 스크립트가 실패하는 테스트로 닫는다. 첫 실서명 태그는 §5.5 "Windows 서명·배포 준비" 행의 결과로 기록한다. ROADMAP M19 착수 조건 문장("그 전까지는 게이트가 경고와 함께 건너뛴다")과 맞는다.
9. **Windows 종단을 별도 job으로.** 종단과 ConPTY 테스트는 지금의 `test (windows-latest)` 안에서 돈다. CI 시간이 크게 늘면 acceptance처럼 별도 job으로 뗄 수 있다. **권고:** 일단 같은 leg에 두고, Step 7 뒤 Windows leg 시간이 Linux leg의 두 배를 넘으면 main 세션이 job 분리를 정한다. 분리하면 그 job도 merge 필수로 둔다.
10. **`p1-ssh-bootstrap` R5의 이월.** 사전 고정된 R5는 Windows의 대화형 attach와 `qsh cp`를 M19로 미뤄 요건 4·6을 보지 않는다. **권고:** R5 문면은 고치지 않고 `p1-windows.md`에 "Windows client 자동 부트스트랩" 회차를 두어 요건 4·6을 Windows에서 본다(Step 14). M16 계획 §0.3이 이미 그렇게 적었다.
11. **ADR-0023의 "M19가 확인한다".** ADR-0023은 Windows `Instant`가 절전 중 멈추는지를 M19가 확인한다고 적었고, ADR-0035 결정 15는 확인 대신 `QueryUnbiasedInterruptTime`을 표본으로 쓰기로 정했다. **권고:** ADR-0023은 고치지 않는다. Step 8이 결정 15를 인용하고 `client/wake.rs` 모듈 doc을 고치며, 실제 절전 복귀는 캠페인 (4)가 본다.
12. **태그.** M19 DoD에는 태그가 필요 없다. 캠페인 회차 전부가 Windows 자산이 붙은 태그를 요구한다. **권고:** 사람 몫 서명 시크릿이 준비된 뒤 Step 15 직후 태그 하나를 권한다. 시크릿 전이라면 서명 없는 태그(`Unsigned release` 경고)를 찍을지는 유지보수자가 정한다. 그 태그로는 캠페인 (11)을 돌릴 수 없다.
