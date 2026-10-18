# PLAN.md — M20: Windows host

P1 M20의 실행 계획이다. M19가 닫혀 이 문서가 M19 계획(마지막 커밋 `d853388`)을 전면 교체했다. M20은 P1 순서상 마지막 마일스톤이다. M18(세션 거처)은 착수 조건인 M8 DoD 3(실기기 mobility 60회)이 기록되지 않아 2026-10-16 건넜고(`docs/ROADMAP.md` §5.1 원칙 6), 그 회차가 기록되면 M20과 무관하게 따로 연다. 착수 ADR인 ADR-0035(Windows client·host)는 2026-10-14 사용자 위임 결정("전부 다 알아서 진행해")으로 `승인됨`이다. 기능 의존인 ADR-0029(`qsh cp`, M15)와 ADR-0044(SSH 부트스트랩, M16)는 착지했고, M19가 Windows 공통 기반(소유자 전용 DACL 모듈, named pipe localctl, 콘솔 계층, Credential Manager, 작업 스케줄러 백엔드)과 `qsh serve --to`의 Windows 게이트 제거를 착지시켰다. 그래서 M20의 착수 조건(ROADMAP M20 "M19 닫힘", `qsh cp`와 `pair ssh-respond`의 ADR 착지)은 모두 충족되고 새 ADR은 필요 없다(Step 1 (a) 4). 구속 근거는 다음과 같다.

- `docs/ROADMAP.md` §5의 M20 절(범위, 착수 조건, 명시적 out, 수용 기준, 크기), §5.1 시퀀싱 원칙(특히 원칙 6·7), §5.4 리스크 5(Windows 산정 신뢰도), §5.5 P1 사람 몫, 마일스톤 마감 공통 절차(같은 문서 §2), §3 유예 가드레일의 Windows 행
- ADR-0035 결정 1·2·3의 host 쪽, 17의 host 테스트와 PTY를 포함한 종단·`release_smoke` PTY 축, 18의 host 회차, 19의 host 쪽 문서, 20~26, 결과 절(특히 "고정할 테스트", "계약", "마일스톤 배치"와 "크기"의 M20 항목)
- ADR-0035가 Windows host 쪽 착지를 M20으로 넘긴 다른 ADR의 문장: ADR-0029 결정 6·7·8·13·23(Windows host의 파일 op, 경로 판정, `FILE_DATA` host 처리, `file.v1` 광고), ADR-0044 결정 10·14·25(Windows 응답자, `cmd.exe` 9009 사상)
- 참조 ADR: ADR-0003(SIGTERM drain), ADR-0004(replay는 메모리에만), ADR-0010(audit 회전·retention), ADR-0017 결정 1(`acl.toml`을 쓰지 않음), ADR-0045(role), ADR-0024 결정 2·8·10(`setup` 역할 표와 `service` 단계)
- `docs/CLI.md` §2.4·§6.4·§6.7·§6.11·§6.12·§6.17·§6.20·§6.21·§7
- `docs/design/protocol.md` capability 절(`file.v1`)과 §17(SSH 부트스트랩 응답자), `docs/design/architecture.md` §4·§6·§7·§8, `docs/design/testing.md` L5·L6와 Windows leg 문단, `docs/design/threat-model.md` §1·§3·§4 B·D·E·§7
- `CLAUDE.md` "Security defaults"와 "Hard architecture rules"

이 계획과 `docs/ROADMAP.md`의 편집은 main 세션만 한다.

인용 규율은 M19판과 같다. 문서는 절 이름, ADR 번호와 결정 번호, 테스트 이름, 커밋 해시로 가리킨다. 코드 위치는 파일 경로와 심볼 이름으로 가리키고, 줄 수나 개수를 적을 때는 origin `357fd58` 트리에서 잰 값임을 밝힌다. 옛 계획의 스텝은 "M19 plan Step N (`d853388`)" 꼴로만 인용한다. 코드 주석과 문서에는 이 계획의 스텝 번호를 쓰지 않는다.

**M20이 닫는 것.** M19 동안 Windows host(인바운드 `qsh serve`와 `serve --to`)는 PTY 세션과 파일 op에 `UNSUPPORTED`로 답하고 `exec`와 터널만 냈다. 이 중간 상태는 지원 약속이 아니었고(ADR-0035 결과 절 "마일스톤 배치") M20이 끝낸다. M20이 닫히면 `exit_code_matrix.rs`에 Windows 전용 `UNSUPPORTED` 행이 하나도 없고(ADR-0035 결정 3, ROADMAP M20 DoD), Windows 빌드의 `LOCAL_CAPABILITIES`가 unix 빌드와 같아진다(ADR-0029 결정 23). 남는 플랫폼 차이는 없다(ADR-0035 결과 절 "남는 플랫폼 차이는 없다").

## 0. 열린 사람 몫

여기 적힌 항목은 이 파일이 다음 계획으로 바뀔 때 그대로 승계한다. M19 계획 §0의 상태를 M19 마감 시점 그대로 옮긴다(main 세션이 Step 1에서 M19 마감 노트와 대조한다).

### 0.1 P0에서 열린 일곱

M19 계획 §0.1의 일곱 항목(M10 DoD 1·2·3, M7 DoD 1, M8 DoD 3, M8 DoD 4, M9 DoD 1)을 문면 그대로 승계한다. M8 DoD 3은 M18의 착수 조건이고, 이것이 닫히면 M20 진행과 무관하게 M18을 연다.

- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** `docs/campaigns/m10-clean-vm.md`. macOS 두 회차가 남았다. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 같은 문서. 소유: 사람.
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** 캠페인 §9 판정과 함께 닫힌다. 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** `docs/campaigns/m7-stopwatch.md`. 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** `docs/campaigns/m2-mobility.md`. M18의 착수 조건. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** 저장소 밖 조직 액션. 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 소유: 사람.

### 0.2 P1 마일스톤이 만든 사람 몫 (`docs/ROADMAP.md` §5.5)

M19 계획 §0.2·§0.3의 다섯 항목을 승계한다.

- [ ] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 출처 M11. 소유: 사람.
- [ ] **`p1-supervise-wake` 회차 넷.** 출처 M12. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 출처 M12(ADR-0024 결정 12). 소유: 사람.
- [ ] **`decode_file_frame`·`parse_ssh_bootstrap_line` fuzz 타깃의 누적 72 fuzz-hours.** 출처 M15·M16. 공개 beta 전(`docs/design/protocol.md` §13). 소유: 사람.
- [ ] **실제 OpenSSH 위의 SSH 부트스트랩 회차.** `docs/campaigns/p1-ssh-bootstrap.md`(사전 고정 `e8cd7a3`). Windows 원격이 응답자가 되는 회차는 이 문서가 아니라 `p1-windows.md` W7이 맡는다(Step 10). 소유: 사람.

### 0.3 M19가 만든 사람 몫

- [ ] **Windows client 확인 회차.** `docs/campaigns/p1-windows.md`(M19 사전 고정 `ad409e0`)의 W1, W3a, W4, W5, W6, W8, W9, W10, W11, W12. Windows 자산이 붙은 태그에서 돈다. 소유: 사람.
- [ ] **Windows 서명·배포 준비(ADR-0035 결정 16, 결과 절 "사람이 할 일").** SSL.com 인증서와 eSigner TOTP, 시크릿 `WINDOWS_SIGN_ESIGNER_*` 넷과 변수 `WINDOWS_SIGN_EXPECTED_SUBJECT`, `DaveDev42/scoop-bucket`과 `SCOOP_BUCKET_DEPLOY_KEY`, `WINGET_PAT`과 첫 winget 매니페스트 수동 제출. 소유: 사람.

### 0.4 M20이 새로 만드는 사람 몫

- [ ] **Windows host 확인 회차.** Step 10이 `docs/campaigns/p1-windows.md`의 M20 자리(W2, W3b, W7)를 회차 절로 채워 구현 마지막 스텝(Step 11) 전에 다시 고정한다(ADR-0035 결정 18). W2는 Linux·macOS client가 Windows host(`qsh serve`)에 붙어 `cmd.exe`·PowerShell·Windows 빌드 `vim` 전체 화면, 한글 입출력, resize, `Ctrl-C`를 본다. W3b는 Linux·macOS `qsh listen` ← Windows `qsh serve --to`의 attach·`cp`·터널이다. W7은 `qsh pair ssh`와 `--reverse`가 Windows OpenSSH Server를 상대로 pin을 세우는 것이다. 회차는 M20 착지가 담긴 Windows 자산 태그에서 돈다. 이 회차는 마일스톤을 막지 않고 P1 완료 선언을 막는다(ROADMAP §5.1 원칙 6, §5.5). 소유: 사람.

에이전트는 `gh secret set`, `gh variable set`, `gh workflow run`, 태그 push, 저장소 설정 변경, 외부 저장소 쓰기를 어느 스텝에서도 하지 않는다. Dave-Windows에서 OpenSSH Server 선택적 기능을 켜거나 방화벽 규칙을 더하는 일도 사람 몫이다(§1).

## 1. 유지보수에서 남은 확인

M19 계획 §1의 항목을 M19 마감 시점 상태로 승계한다(main 세션이 Step 1에서 채운다). 열린 채로 넘어올 것으로 보이는 것은 macOS Keychain 왕복, 다음 태그 run의 서명·공증·provenance 확인, `launchctl print system/io.qsh.<mode>`의 root 요구, Windows `Password` 주체 작업의 Credential Manager 읽기(ADR-0032 결정 15 첫 항목, M19가 보수 판정으로 닫고 열린 항목으로 남김)다.

M20이 더하는 확인은 다음과 같다.

- [ ] ConPTY 배치의 실측 셋(ADR-0035 결정 20). (i) ConPTY 쪽 입출력 핸들을 동기 pipe로, host 쪽 끝을 overlapped named pipe로 만들어 tokio에서 읽고 쓰는 배치가 `windows-latest`(Server 2022)와 Dave-Windows(Windows 11 26100)에서 같은 출력 순서로 서는지, (ii) `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`과 `PROC_THREAD_ATTRIBUTE_JOB_LIST`를 한 `STARTUPINFOEX`에 실은 `CreateProcessW`가 두 OS에서 자식을 처음부터 Job Object 안에 두는지, (iii) 자식 종료 뒤 출력을 다 읽기 전에 `ClosePseudoConsole`을 부르면 막히는지. 셋 모두 Step 2가 에이전트로 돌리고 결과를 커밋 본문에 적는다. (i)이 서지 않으면 결정 20이 미리 적은 대체(세션마다 읽기 스레드)로 접고 main 세션이 ADR-0035 개정 이력 줄을 더한다.
- [ ] 신호 사건의 실측 둘(ADR-0035 결정 22). (i) `DETACHED_PROCESS`로 띄운 보조 프로세스가 `AttachConsole(<세션 루트 pid>)` 뒤 `GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)`로 세션 콘솔의 모든 프로세스에 닿는지(세션 루트를 `CREATE_NEW_PROCESS_GROUP` 없이 만든 경우), (ii) `ClosePseudoConsole`이 붙은 프로세스에 `CTRL_CLOSE_EVENT`를 보내는지와 그 뒤 처리기가 받는 시간. Step 4가 Dave-Windows와 CI 러너에서 본다.
- [ ] Windows OpenSSH Server 위의 `qsh pair ssh-respond`. Dave-Windows에 OpenSSH Server를 켜는 것은 사람이 하고(관리자 권한), 켜져 있으면 Step 9가 같은 머신의 loopback ssh로 응답자 한 회를 에이전트가 돌려 커밋 본문에 적는다. 실제 두 장비 회차는 캠페인 W7이다.
- [ ] Windows 방화벽 첫 허용 프롬프트(ADR-0035 결정 25). CI 러너의 loopback UDP는 프롬프트 없이 열린다. 실제 장비의 프롬프트 문안과 README·doctor 안내의 대응은 캠페인 W2가 본다.

## 2. 테스트 환경

M19와 같다.

- CI는 `ci.yml`의 `windows-latest` leg(clippy, `cargo nextest run --workspace`, `cargo doc -D warnings`)이 착지 판정이다. M20은 이 leg에서 PTY와 파일 host 때문에 `cfg(unix)`로 빠져 있던 테스트를 `cfg(windows)` 쌍둥이로 연다. Windows host 쪽 PTY 테스트의 셸은 `cmd.exe`이고 기대값은 Windows 명령으로 바꾼다(ADR-0035 결정 17 host 테스트 항목).
- 로컬 Windows 검사는 Dave-Windows(16c/64GB, `ssh dave-windows.tail91e9e.ts.net`, pwsh)에서 네이티브 clippy·nextest·doc. 로컬 검사로 CI를 대신하지 않는다.
- 실제 외부 상태를 건드리지 않는 주입점은 M19의 것(가짜 `ManagerRunner`·`TaskStateQuery`·`TaskDefinitionReader`, "pid → SID" 함수, `DaclSource` 실패 주입, Credential Manager 주입)에 셋을 더한다.
  - 신호 보조 프로세스 경로 주입. 단위 테스트의 `current_exe()`는 qsh가 아니므로 `qsh internal console-ctrl`의 실행 파일 위치를 seam으로 둔다(§7.1 #5).
  - 세션 신호 수신 probe. `qsh-testkit`의 작은 실행 파일(가칭 `qsh-signal-probe`)이 `CTRL_C_EVENT`·`CTRL_BREAK_EVENT`·`CTRL_CLOSE_EVENT` 처리기와 `QSH_SIGNAL_EVENT_USR1`·`USR2` 이벤트 대기로 받은 것을 정해진 종료 코드로 보고한다(ADR-0035 결정 17 host 테스트 항목). 위치 탐색은 `qsh-console-probe`와 같은 순서다.
  - Windows 파일 guard의 정규화기 주입. `file::guard`의 `Normalizer` seam(M15)을 그대로 쓰고, `GetFinalPathNameByHandleW` 결과를 흉내 내는 가짜로 대소문자·`\\?\` 접두·재분석 지점 경우를 네 다리에서 돈다.
- 부하 반복은 M19와 같이 두 곳에서 돈다. Linux·공통 테스트는 Dave-Windows-WSL(8 vCPU), Windows 전용 타이밍 민감 테스트는 Dave-Windows의 Git for Windows bash로 `scripts/stress/run.sh`를 돌린다. 두 결과를 마감 노트에 따로 적는다.

## 3. DoD 체크리스트 (ROADMAP M20)

체크박스는 근거가 되는 테스트와 CI run이 초록일 때만 채운다.

- [x] **착수 — ADR-0035가 `승인됨`이고 M19가 닫혔다.** 근거: `09266dc`(2026-10-14), M19 마감 노트. 소유: main 세션 확인.
- [ ] **DoD 1 — `pty/tests.rs`의 Windows 쌍둥이.** spawn·입출력·resize·종료 코드·Job Object 트리 종료·신호 일곱의 사상과 escalation·환경 고정을 단언한다. `conpty_last_byte_arrives_before_the_exit_event`, `conpty_close_terminates_the_whole_job_including_grandchildren`, `conpty_resize_is_applied_to_the_pseudo_console`, `conpty_child_environment_is_the_user_block_not_ours`, `conpty_pinned_keys_cannot_be_overridden_case_insensitively`, `each_signal_raises_its_windows_event_then_escalates_to_an_ended_session`(계획 추가 이름). 근거: Step 2·3·4.
- [ ] **DoD 2 — Windows leg의 정방향·역방향 같은 케이스 목록.** 같은 러너에서 정방향(`qsh serve` ← `qsh`)과 역방향(`qsh listen` ← `qsh serve --to`)을 `route_cases.rs`의 같은 케이스로 돈다: `exec`, 터널 echo, ConPTY 안의 대화형 attach와 detach 뒤 resume(실제 PTY host), Windows host 상대 `qsh cp`(M19 DoD에서 옮겨 옴). `windows_forward_e2e::`, `windows_reverse_e2e::`, `windows_attach::`의 PTY 케이스. 근거: Step 7·11.
- [ ] **DoD 3 — `release_smoke`의 `#[cfg(not(unix))]` 쌍둥이가 PTY 축을 포함해 unix 쪽과 같은 축으로 넓어진다.** PTY session open·write·read·close, 만든 파일의 DACL 단언 유지. 근거: Step 11.
- [ ] **DoD 4 — `exit_code_matrix.rs`에 Windows 전용 `UNSUPPORTED` 행이 하나도 없다.** origin `357fd58`에 남은 host 쪽 행 셋(`session open`, `cp: put of a local file that does not exist`, `cp: get from a host that grants this client no file access`)의 `#[cfg(not(unix))]` 갈래가 사라지고, `cfg(windows)` 행 하나가 `qsh session close --signal <SIG>`의 허용 값 일곱이 Windows host에서 모두 exit `0`임을 단언한다(ADR-0035 결정 3). 근거: Step 3(`session open`), Step 4(`--signal` 행), Step 7(`cp` 두 행), 확인 Step 12.
- [ ] **DoD 5 — 위협 모델.** threat-model의 PTY 행(§1 자산 "세션 PTY와 child 프로세스", architecture §4 인용)에 ConPTY와 Job Object가, §4 E에 `acl.toml` DACL 경고가 오른다. 더해 계획 규율로 §3 진입점에 세션 신호 이벤트(이름 있는 이벤트 둘)와 `qsh internal console-ctrl` 보조 프로세스, §4 B·D에 Windows host 파일 op의 상태 경로·재분석 지점·UNC 거부가 오른다(ADR-0035 결정 19). 각 행은 그 통제를 구현한 스텝에서 오른다. 근거: Step 3·4·6·7.
- [ ] **DoD 6 — 캠페인 문서에 host 회차가 더해져 다시 고정된다.** W2, W3b, W7(Linux·macOS client → Windows host, Windows target의 역방향, Windows OpenSSH Server 상대 `pair ssh`). 구현 마지막 스텝(Step 11) 전 커밋. 근거: Step 10.
- [ ] **계획 규율 — 안정성.** M20이 더한 타이밍 민감 테스트 전부가 `scripts/stress/m20.filter`로 묶여 Linux(Dave-Windows-WSL)와 Windows(Dave-Windows) 각각에서 CPU 부하 아래 50회 연속 초록이다. ROADMAP M20 DoD에는 아직 이 줄이 없고 Step 1이 더한다(§9 #1). 근거: Step 2~11, 12.
- [ ] **계획 규율 — route 동등(§5.1 원칙 7).** Windows host에서 여는 기능마다 forward와 reverse route의 같은 테스트가 Windows leg에서 초록이다(§4 규율 "route 동등" 표). 근거: Step 3·4·5·7·8·9·11.
- [ ] **계획 규율 — `cfg(unix)` 쌍둥이 전수.** origin `357fd58`에서 `#![cfg(unix)]`인 테스트 모듈과 파일 안의 `#[cfg(unix)]` 테스트 각각이 `cfg(windows)` 쌍둥이를 갖거나, 개념이 unix인 이유(POSIX 신호 번호, `$$`, `setsid`, `expectrl`, UDS)를 주석으로 남기고 같은 성질을 Windows 수단으로 보는 테스트를 따로 둔다(ADR-0035 결정 3). §5.6 표가 정본이다. 근거: Step 3·7·11.
- [ ] **계획 규율 — M20 유예 전수 귀속.** `rg -n "M20"`의 모든 hit가 §5.7의 표에서 스텝이나 기록(ADR 개정 이력, ROADMAP 마감 노트, 캠페인 문서)으로 귀속돼 있고, 착지 뒤에는 그 문장이 착지 상태로 고쳐졌다. 근거: Step 12.
- [ ] **DoD 마감 — 마감 공통 절차(§2) 1·2.** 근거: Step 12.

## 4. 실행 단계 (PR 단위)

스텝 번호는 이 문서 안에서만 쓰는 참조다. 크기는 ADR-0035 결과 절 "크기"의 M20 내역을 그대로 나눈 것이다.

| ADR-0035 산정 항목 | 크기(ew) | 스텝 |
|---|---|---|
| ConPTY 백엔드(의사 콘솔과 Job Object, pipe 배치, resize, 종료와 배수, 환경 블록과 고정 키, 기본 셸, `user@`, `pty/tests.rs` 쌍둥이) | 1.2~2.0 | Step 2(0.5~0.8), Step 3 중 0.7~1.2 |
| 신호 일곱(`qsh internal console-ctrl`, 세션 이벤트와 환경변수, escalation, 테스트) | 0.3~0.5 | Step 4 |
| host 쪽 나머지(`exec`의 Job Object와 환경, `setup host`·`pair invite` 게이트 제거, 방화벽 안내) | 0.3~0.6 | Step 5(0.2~0.3), Step 8(0.1~0.3) |
| host 쪽 상태(audit writer 잠금·재검증, `acl.toml` DACL 경고) | 0.4~0.7 | Step 6 |
| host 쪽 `qsh cp` | 0.5~0.9 | Step 7 |
| `pair ssh-respond` | 0.2~0.4 | Step 9 |
| PTY를 포함한 CI 종단과 `release_smoke` PTY 축 | 0.4~0.7 | Step 11 |
| 문서·threat model·캠페인 확장 | 0.2~0.4 | Step 10(0.1~0.2), Step 12(0.1~0.2) |
| ADR 개정 | 0.1 | Step 3 |
| 합 | 3.6~6.3 | ROADMAP M20 크기와 같다 |

스텝별 크기는 다음과 같다. Step 1은 크기 내역 밖이다.

| 스텝 | 내용 | 크기(ew) |
|---|---|---|
| 2 | ConPTY 시제품: 의사 콘솔·Job Object 생성, pipe 배치 판정, 출력 배수, 재산정 | 0.5~0.8 |
| 3 | ConPTY 백엔드 완성: 환경·셸·`user@`, `UnsupportedFactory` 제거, `pty/tests.rs` 쌍둥이, PTY 세션의 두 route | 0.8~1.3 |
| 4 | 세션 신호 일곱의 Windows 사상, `qsh internal console-ctrl`, 세션 이벤트, `--signal` 매트릭스 행 | 0.3~0.5 |
| 5 | host 쪽 `exec`의 Job Object와 환경 고정 | 0.2~0.3 |
| 6 | host 쪽 상태: audit writer `LockFileEx` 잠금·재검증, `acl.toml` DACL 경고 | 0.4~0.7 |
| 7 | host 쪽 `qsh cp`: 경로 판정, 파일 host, `FILE_DATA`, `file.v1` 광고, `cp` 종단 | 0.5~0.9 |
| 8 | `setup host`(`--to`, `--service` 포함), `pair invite`, 방화벽 안내 | 0.1~0.3 |
| 9 | Windows `qsh pair ssh-respond` | 0.2~0.4 |
| 10 | 캠페인 `p1-windows.md` host 회차 추가와 재고정 | 0.1~0.2 |
| 11 | PTY를 포함한 정방향·역방향 종단, 실제 PTY attach, `release_smoke` PTY 축, `cfg(unix)` 쌍둥이 전수 | 0.4~0.7 |
| 12 | 마감 | 0.1~0.2 |
| 합 | | 3.6~6.3 |

Step 2 뒤 main 세션이 이 표와 ROADMAP M20 크기 줄·§5.2·§5.4 리스크 5를 다시 매긴다(ROADMAP M20 크기 줄, ADR-0035 결과 절 "크기" M20 항목 끝 문장).

**순서의 근거.**

- ConPTY 시제품(Step 2)을 맨 앞에 둔다. ADR-0035 결과 절과 ROADMAP M20 크기 줄이 "첫 스텝은 ConPTY 시제품이고, 그 뒤 다시 매긴다"로 정했고, 결정 20의 pipe 배치가 서는지가 Step 3·4의 모양을 정한다. 시제품은 `UnsupportedFactory`를 아직 지우지 않는다. 지우면 그 순간 Windows host가 PTY 세션을 광고된 대로 열어야 하고 그것은 두 route 테스트가 함께 서야 착지할 수 있다(§4 규율 "route 동등").
- 신호(Step 4)는 Step 3의 Job Object와 의사 콘솔 핸들을 쓴다. 신호 없는 `session close`의 첫 단계(`Hup` = `ClosePseudoConsole`)와 escalation의 `Kill`(`TerminateJobObject`)은 세션 정리의 기본 경로라서 Step 3이 먼저 세우고, Step 4는 나머지 다섯 신호와 이벤트·보조 프로세스를 더한다.
- host `exec`(Step 5)는 Step 2의 Job Object 생성 함수와 Step 3의 환경 블록 함수를 쓴다. 그래서 Step 3 뒤다. 범위가 작아 Step 4와 병렬이다.
- host 쪽 상태(Step 6)와 host 쪽 `qsh cp`(Step 7)는 PTY와 코드가 겹치지 않아 Step 1 직후부터 병렬이다. Step 7의 하드 링크 우회 방지는 Step 6과 같은 (볼륨 일련번호, 파일 인덱스) 식별 함수를 쓰므로, 그 함수를 `fsutil` 하위에 먼저 세우는 쪽이 다른 쪽에 rebase한다(§7.1 #9).
- `setup host`·`pair invite`(Step 8)와 응답자(Step 9)는 PTY와 무관하다. 그러나 `setup host`의 완료 단계 안내와 응답자의 "다음 명령"은 사람이 바로 attach하는 흐름이라, 문서 문장이 PTY 세션 착지(Step 3) 뒤의 상태를 적도록 Step 3 뒤에 착지시킨다. 코드는 Step 1 직후부터 병렬로 써도 된다.
- 캠페인(Step 10)은 ADR-0035 결정 18이 "M20 마지막 스텝 전에 다시 고정"을 요구하므로 구현 마지막 스텝(Step 11) 앞이다. W2·W3b·W7이 가리키는 명령(`qsh serve`의 PTY, `serve --to`의 `cp`, 응답자)이 굳은 뒤에 쓴다.
- 종단·`release_smoke`·쌍둥이 전수(Step 11)는 Step 3·4·7·9가 연 표면 전부를 같은 케이스 목록으로 묶는 스텝이라 마지막 구현 스텝이다. 각 기능 스텝은 자기 route 동등 핀을 착지시키고, Step 11은 그 위에 대화형 attach의 실제 PTY 케이스, `release_smoke` PTY 축, 남은 `cfg(unix)` 쌍둥이를 더한다.

**의존과 병렬.**

| 스텝 | 선행 | 다른 에이전트와 병렬 가능 여부 |
|---|---|---|
| Step 2 | Step 1 | Step 6·7·8·9와 병렬 |
| Step 3 | Step 2 | Step 6·7·8·9와 병렬. `exit_code_matrix.rs`는 Step 4·7과 같은 파일이라 rebase |
| Step 4 | Step 3 | Step 5·6·7·8·9와 병렬. clap 트리(`qsh internal`)를 만지는 유일한 스텝 |
| Step 5 | Step 3 | Step 4·6·7·8·9와 병렬 |
| Step 6 | Step 1 | 전부와 병렬. `fsutil` 식별 함수는 Step 7과 조율(§7.1 #9) |
| Step 7 | Step 1 | Step 2~6·8·9와 병렬. `crates/qsh-proto/src/wire.rs`를 만지는 유일한 스텝. `file/guard.rs`의 `xtask arch` 금지(§7.1 #8) |
| Step 8 | Step 1(코드), Step 3(문서 착지) | 전부와 병렬 |
| Step 9 | Step 1(코드), Step 3(문서 착지) | 전부와 병렬. `crates/qsh-cli/src/cli.rs`의 `#[cfg(unix)] SshRespond`는 Step 4의 clap 변경과 같은 파일 |
| Step 10 | Step 3·4·7·8·9(회차가 가리키는 명령) | Step 11 앞 |
| Step 11 | Step 3·4·5·7·9, Step 10 | — |
| Step 12 | 전부 | — |

**규율.** M19 그대로이고 M20에서 몇 가지를 덧붙인다.

- 각 스텝은 일곱 게이트(`cargo fmt --all --check`, clippy `-D warnings`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`, `cargo xtask arch`, `cargo deny check`)가 초록인 채로 착지한다. clippy·test·doc은 `ci.yml`의 네 test 다리(`ubuntu-24.04`, `ubuntu-24.04-arm`, `macos-14`, `windows-latest`)에서 돈다. `cfg(windows)` 코드를 더하는 스텝(Step 2~9, 11)은 push 전에 Dave-Windows에서 네이티브 clippy·nextest·doc을 돌린다. 착지 판정은 CI 초록이다.
- **unix 회귀 0.** M20은 unix의 PTY 백엔드(`pty/posix.rs`), 신호 경로, audit writer, 파일 host를 Windows 갈래와 나누며 만진다. `pty::tests`의 unix 케이스, `tui_expect::`, `attach_ops::`, `attach_recovery::`, `session_kill9::`, `serve_sigterm_drain::`, `cp_e2e::`, `cp_recursive::`, `cp_cancel::`, `ssh_bootstrap::`, `audit_query::`, `acl::load`의 기존 테스트가 고치지 않은 채 초록이어야 한다. acceptance job(`tui_expect`, `reverse_blackout`, `quinn_idle_timeout_as_idle_timeout`, 터널·파일 echo 예산, `cp_many_small_files_stays_within_the_echo_budget`, `socks_curl`, supervised 50초 blackhole)도 같다. 플랫폼 중립 부분을 꺼낼 때는 unix 쪽 동작 diff가 0이어야 한다.
- **Windows 의존.** `windows-sys`의 feature를 스텝마다 필요한 것만 더한다(ConPTY·Job Object·프로세스·스레드 속성 Step 2, 환경 블록·토큰 Step 3, 콘솔 사건·동기화 객체 Step 4, 파일 잠금·파일 정보 Step 6, 경로·재분석 지점·디스크 공간·파일 시간 Step 7). 새 crate는 두지 않는다. ADR-0035 결과 절 "의존 추가"가 M20에 새 crate를 적지 않았고, `portable-pty`는 `qsh-testkit`의 Windows dev 의존으로 이미 있다(M19). 새 feature마다 같은 커밋에서 `cargo deny check`가 초록이어야 한다. 의존 방향 행렬은 바뀌지 않는다.
- 계약 문서 델타는 그 표면을 바꾼 스텝의 같은 커밋에 싣는다.
  - `docs/CLI.md` 상태 헤더는 M19 마감 뒤의 다음 판(가칭 v0.N)을 CLI.md를 처음 고치는 스텝이 열고, 뒤 스텝은 덧붙이거나 다음 판을 연다(`crates/qsh-core/tests/it/cli_md_header.rs` 핀).
  - additive 계약은 ADR-0035 결과 절의 셋 가운데 M20 몫 하나다. 세션 환경변수 `QSH_SIGNAL_EVENT_USR1`·`QSH_SIGNAL_EVENT_USR2`(§7의 host가 넣는 환경변수 목록, Step 4). 결정 22의 종료 상태는 wire `Exit`의 기존 필드(`exit_code`, `signal`)에 싣는다.
  - 숨김 subcommand `qsh internal console-ctrl <pid> <c|break>`(Step 4)는 `hide = true`이고 `docs/man/`은 바뀌지 않는다. `checked_in_man_pages_match_the_generator`가 숨김 항목을 렌더하지 않음은 M19(`qsh service run`)가 확인했고 Step 4가 같은 테스트로 다시 본다.
  - 숨김 `qsh pair ssh-respond`의 `#[cfg(unix)]`를 걷는 것(Step 9)도 man 페이지와 `--help`를 바꾸지 않는다(ADR-0044 결정 9의 숨김).
- 판정 로직은 `qsh-core`에 둔다. ConPTY 백엔드(`pty/conpty.rs`), 신호 사상과 보조 프로세스 본문(`pty/` 하위), 환경 블록, host `exec`, audit 잠금(`audit/writer.rs`), `acl.toml` DACL 경고(`acl/load.rs`), Windows 경로 판정(`file/guard.rs`)과 파일 host(`file/host.rs`), 응답자(`ssh_bootstrap/respond.rs`)는 `qsh-core`다. `qsh-cli`에는 clap 정의와 숨김 진입점의 얇은 배선만 둔다. 신호 사상 표, 고정 키 대조, 원격 경로 문자열 분류, mode 합성처럼 OS 호출이 없는 순수 함수는 `cfg` 없이 두어 네 다리 모두에서 테스트가 돈다.
- **wire 소유.** M20의 어느 스텝도 `.proto`와 `crates/qsh-proto/src/local.rs`를 바꾸지 않는다(ADR-0035 결과 절 "계약"). 완료 판정마다 다음을 확인한다.
  - `git diff --stat -- crates/qsh-proto/proto crates/qsh-proto/src/local.rs crates/qsh-cli/tests/fixtures/cli-v1/capabilities.json`이 비어 있다.
  - `crates/qsh-proto/src/wire.rs`의 diff는 Step 7 하나에만 있고, 그 내용은 `LOCAL_CAPABILITIES`의 `#[cfg(unix)]`/`#[cfg(not(unix))]` 두 정의를 하나로 합쳐 Windows 빌드도 `CAP_FILE_V1`을 광고하는 것과 그 doc 주석뿐이다. capability 문자열 자체와 협상 규칙은 바뀌지 않는다. 이것은 ADR-0029 결정 23("그 전까지 Windows 빌드는 `file.v1`을 광고하지 않고")이 이미 정한 착지이고, `capabilities.json` golden은 unix 빌드의 집합을 기록하므로 바뀌지 않는다(§9 #2).
  - `ErrorCode`는 바뀌지 않는다. 새 실패는 기존 코드(`INVALID_ARGUMENT`는 UNC·장치 이름 공간 경로, `PERMISSION_DENIED`는 상태 경로·재분석 지점, `UNSUPPORTED`는 `user@` 불일치, `INTERNAL`은 ConPTY·Job Object 생성 실패)에 붙는다.
- fixture는 추가만 한다. ADR-0035 결과 절은 새 fixture가 없다고 적는다. 기존 fixture 가운데 Windows에서 건너뛰던 생산 테스트(`crates/qsh-cli/tests/it/fixtures.rs`의 파일 host 관련 `cfg(unix)` 갈래)는 Windows에서도 같은 golden을 내야 하고, 다르면 그것이 결함이다(§7.1 #13).
- **테스트 배치.** 통합 테스트는 `crates/<crate>/tests/it/<name>.rs` 모듈로 두고 같은 커밋에서 `tests/it/main.rs`에 `mod <name>;`을 등재한다. `cfg(unix)` 테스트의 `cfg(windows)` 쌍둥이는 같은 함수 본문을 두 cfg에서 부르는 꼴을 먼저 고른다(`route_cases.rs`와 `cp_e2e.rs`의 `round_trip` 공유 선례). 쌍둥이를 가질 수 없는 테스트는 빠진 이유를 주석으로 남긴다(ADR-0035 결정 3).
- **route 동등(§5.1 원칙 7, PRD §4, 예외 없음).** Windows host에서 여는 기능마다 forward route(Windows `qsh` → Windows 인바운드 `qsh serve`)와 reverse route(Windows `qsh` → Windows `qsh listen` 데몬 → Windows `qsh serve --to`)를 같은 케이스 목록으로 Windows leg에서 돈다. 같은 러너의 loopback이고 test-only 하니스는 없다(ADR-0035 결정 17). 한쪽 route만 덮는 PR은 착지하지 않는다. 기능별 배치는 다음과 같다.

  | 기능 | forward 테스트 | reverse 테스트 | 스텝 |
  |---|---|---|---|
  | PTY 세션 open·write·read·resize·close(headless) | `windows_forward_e2e::pty_session_{runs_a_command,default_shell_takes_input,resize_is_applied,close_ends_a_running_session}` | `windows_reverse_e2e::` 같은 넷 | 3 |
  | `user@` 힌트 비교 | `windows_attach::a_foreign_user_hint_is_refused_without_creating_a_session`(interactive 형태) | 해당 없음: reverse route에는 `user@`를 싣는 CLI 표면이 없다(unix도 같다). 서버 경로 `open_with_a_foreign_user_hint_is_unsupported_after_acl_and_creates_nothing`가 지킨다 | 3 |
  | `session close --signal` 일곱 | `windows_forward_e2e::session_close_with_each_signal_ends_the_session` | `windows_reverse_e2e::session_close_with_each_signal_ends_the_session` | 4 |
  | `exec` 타임아웃의 트리 종료 | `windows_forward_e2e::exec_timeout_kills_the_whole_tree` | `windows_reverse_e2e::exec_timeout_kills_the_whole_tree` | 5 |
  | audit 회전 잠금 | `serve`가 쓴 레코드 | `serve --to`가 쓴 레코드(같은 `<state>/audit.log`) | 6 |
  | `acl.toml` DACL 경고 | `serve` 기동 | `serve --to` 기동 | 6 |
  | `qsh cp` put·get·`-r`·`-p` | `windows_forward_e2e::cp_round_trip` | `windows_reverse_e2e::cp_round_trip` | 7 |
  | `qsh cp` 상태 경로·재분석 지점 거부 | `windows_forward_e2e::cp_refuses_state_paths_and_reparse_points` | `windows_reverse_e2e::cp_refuses_state_paths_and_reparse_points` | 7 |
  | `setup host`와 `setup host --to`, `--service` | `setup::` host 행(Windows) | `setup::` host_to 행(Windows) | 8 |
  | `pair invite` → `pair accept` | `trust_pairing_live::` Windows 쌍둥이 | 해당 없음. reverse의 신뢰 수립은 `pair ssh --reverse`(아래 행) | 8 |
  | `pair ssh` 응답자 | `ssh_bootstrap::` 응답자 행(Windows 응답자) | `ssh_bootstrap::` `--reverse` 응답자 행(Windows 응답자) | 9 |
  | 대화형 attach·detach·resume(실제 PTY) | `windows_attach::pty_attach_round_trip_forward`, `pty_detach_then_attach_resumes_forward` | `windows_attach::pty_attach_round_trip_reverse`, `pty_detach_then_attach_resumes_reverse` | 11 |
  | client crash 뒤 세션 생존(SC5) | `windows_attach::killed_client_leaves_the_session_running_forward` | `..._reverse` | 11 |
  | `qsh sessions` 필터(live 세션) | `sessions_filter::` forward Windows 쌍둥이 | `sessions_filter::` 데몬 fan-out Windows 쌍둥이 | 11 |
  | host 정지 drain(SIGTERM drain의 Windows 대응) | `serve` 정지 | `serve --to` 정지 | 11 |

  `pair invite`의 reverse 칸이 "해당 없음"인 이유: `pair invite`/`accept`는 route가 정해지기 전의 신뢰 수립이고 reverse route의 같은 일은 `pair ssh --reverse`가 한다(ADR-0044 결정 22). unix에서도 같은 배치다.

- **플랫폼 동등.** 결정의 동작은 세 OS에서 같다. unix에 없는 Windows 고유 통제(Job Object, 세션 이벤트 DACL, 재분석 지점 거부, 파일 DACL 경고)는 unix 대응물(`setsid`+`killpg`, 신호 처리기, `O_NOFOLLOW`, group/world-writable 경고)과 같은 성질을 같은 이름 꼴의 테스트로 단언한다.
- 손대는 소스 파일이 800줄을 넘으면 인라인 테스트를 같은 커밋에서 형제 `tests.rs`로 옮긴다. origin `357fd58` 기준 `crates/qsh-core/src/server/mod.rs`(2680줄), `acl/load.rs`(1042줄), `file/guard.rs`(1099줄)가 이미 넘었으므로 인라인 테스트가 남아 있는지 먼저 확인한다. `pty/posix.rs`(761줄), `pty/tests.rs`(781줄), `audit/writer.rs`(700줄), `exec/mod.rs`(635줄)는 M20 편집으로 넘을 수 있다. 새 `pty/conpty.rs`는 처음부터 형제 `pty/conpty/tests.rs`를 두고, `pty/tests.rs`가 넘으면 `pty/tests/{posix,conpty}.rs`로 나눈다.
- 안정성 규율은 M19와 같다. 시계를 주입하고(`[serve].close_grace_ms`를 테스트 config로 줄임, 매니저 호출 기한), 관찰 가능한 상태를 넉넉한 `timeout`으로 기다리며, 고정 `sleep()`은 쓰지 않는다. 타이밍 민감 테스트(ConPTY 출력 배수, 신호 사건 수신, escalation, Job Object 종료, 실제 QUIC loopback, 실제 프로세스 기동, audit 잠금 경합)는 그 스텝의 완료 판정에서 부하 아래 50회 연속 초록이어야 착지한다. `scripts/stress/m20.filter`의 초안은 타이밍 민감 테스트를 처음 더하는 스텝(Step 2)이 만들고 Step 12가 완성한다. 흔들리는 테스트는 대기 조건을 고친다. 필터에서 빼거나 `-j 1`로 옮기지 않는다.

### Step 1 — M20 계획 교체와 ROADMAP 갱신 (main 세션, 크기 내역 밖) ✅ 2026-10-18

근거: `docs/ROADMAP.md` 현재 위치, M20 절, §5.2, ADR-0035 결과 절. 선행: M19 마감(M19 plan Step 16 (`d853388`))과 그 마감 노트.

**(a) 범위:**

1. `PLAN.md`를 이 문서로 바꾼다. ROADMAP M19 마감 노트에 M19 계획의 마지막 커밋 해시가 적혀 있는지 확인하고 이 문서의 `d853388` 자리 전부를 그 해시로 바꾼다. 줄 수·개수의 기준 `357fd58`은 M19 마감 커밋으로 옮길지 정한다. M19 마감 뒤 `#![cfg(unix)]` 모듈 목록(§5.6)과 `rg -n "M20"` 목록(§5.7)이 바뀌었으면 그 커밋에서 다시 센다. §0·§1의 승계 상태를 M19 마감 노트와 대조한다.
2. `docs/ROADMAP.md`를 고친다.
   - 현재 위치를 "현재 마일스톤은 M20"으로 바꾸고 M19 닫힘을 적는다. M18은 여전히 건너뛴 상태임을 한 문장으로 남긴다.
   - M20 DoD에 안정성 줄을 더한다(§9 #1).
   - M20 DoD의 `exit_code_matrix.rs` 줄 옆에 `session close --signal` 일곱 값 행을 이름으로 적을지 정한다(§9 #3).
   - §5.2 M20 행의 상태를 "진행 중(날짜)"으로.
3. README Roadmap 표의 M19 행을 "Done"으로, M20 행을 "In progress"로 고친다.
4. ADR 준비 점검. ADR-0035는 승인됐고 M20에 새 ADR은 필요 없다. 다음 실제 상태를 확인해 이 계획 §9에 적는다(ADR 본문은 고치지 않는다).
   - ADR-0035 결정 20의 "pipe 배치가 첫 host 스텝에서 서지 않으면 읽기 스레드로 접고 개정"은 Step 2가 판정하고, 개정이 필요하면 main 세션이 개정 이력 줄로 더한다.
   - ADR-0029 결정 6 5번(inode 대조)의 Windows 수단은 ADR-0035 결정 26에 이름이 없다. 결정 24가 audit 재검증에 쓰는 (볼륨 일련번호, 파일 인덱스)를 같은 성질로 쓰는 것이 ADR-0029 결정 23("갈리는 것은 시스템 호출과 경로 표기뿐")의 범위인지 확인한다(§9 #4).
   - ADR-0044 결정 10의 Windows 응답자와 결정 14의 9009 사상은 2026-10-14 개정에 이미 들어 있다. 클라이언트 쪽 9009 사상은 M16에 착지했고 M20은 응답자 등록만 연다.
5. `CLAUDE.md`는 바꿀 것이 없다. Document map은 이미 "M11–M20"이다. M20이 끝나 열린 마일스톤이 없어지는 문장은 Step 12 뒤 main 세션의 마감 커밋이 다룬다(§8).

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록.

**(c) 완료 판정:** `PLAN.md` 첫 줄이 이 문서의 제목이다. ROADMAP 현재 위치가 M20을 가리키고, M20 DoD에 안정성 줄이 있다.

**(d) 결과 (2026-10-18):** M19 계획의 마지막 커밋 `d853388`. 줄 수·개수의 기준은 `357fd58`에 그대로 둔다. 그 뒤 M19 커밋 `04abb92`·`d1ff674`는 코드 주석·문서·`deny.toml`만 바꿨다. 그래서 §5.6 목록은 같고, §5.7에는 `04abb92`가 "Windows host is P2" 주석을 M20으로 고치며 생긴 hit 일곱(코드 여섯 파일)을 행 넷으로 더했다. ROADMAP 현재 위치·M19 마감 노트·M20 DoD 안정성 줄과 `--signal` 행·§3 Windows 행·§5.2 상태, README Roadmap 표를 고쳤다. §0·§1의 승계 상태는 M19 마감 노트와 같다. §9 결정은 위 §9 머리말.

### Step 2 — ConPTY 시제품: 의사 콘솔·Job Object 생성, pipe 배치 판정, 출력 배수, 재산정 (0.5~0.8ew) ✅ 2026-10-18

근거: ADR-0035 결정 20(ConPTY 구현, `CreateProcessW` 한 번, Job Object `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, overlapped named pipe 또는 읽기 스레드, `ResizePseudoConsole`, 출력을 다 읽은 뒤 blocking task에서 `ClosePseudoConsole`), 결과 절 "크기" M20 항목 끝 문장(첫 스텝은 ConPTY 시제품, 그 뒤 재산정), ROADMAP §5.4 리스크 5. 선행: Step 1.

**(a) 범위:**

- `crates/qsh-core/src/pty/conpty.rs`(`cfg(windows)`)와 형제 `pty/conpty/tests.rs`. `CreatePseudoConsole`, `STARTUPINFOEXW`에 `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`과 `PROC_THREAD_ATTRIBUTE_JOB_LIST`를 실어 `CreateProcessW` 한 번으로 자식을 만든다. Job Object는 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Job Object 생성 함수는 Step 5의 `exec`가 다시 쓰도록 `pty/` 밖에서도 부를 수 있는 꼴로 둔다(가칭 `crate::winproc::JobObject`, §7.1 #1).
- pipe 배치 판정(§1 첫 항목 (i)). ConPTY 쪽은 동기 anonymous pipe 또는 동기 named pipe, host 쪽 끝은 overlapped named pipe(이름은 128비트 난수, M19의 DACL 모듈 `fsutil/dacl`로 만든 소유자 전용)를 tokio `NamedPipeClient`/`NamedPipeServer`로 감싼다. 이 배치가 두 OS에서 출력 순서와 EOF를 지키지 못하면 세션마다 읽기 스레드 하나(`spawn_blocking` 루프, 기존 quota가 세션 수를 묶음)로 접고 그 결과를 커밋 본문에 적는다. main 세션이 ADR-0035 개정 이력 줄을 더한다.
- 출력 배수와 종료 순서. 자식 종료는 프로세스 핸들 대기로 받고, 출력 pipe를 EOF까지 읽은 뒤 blocking task에서 `ClosePseudoConsole`을 부른다(§1 첫 항목 (iii)). broker의 `SessionSource` 계약("모든 출력이 replay buffer에 들어간 뒤에야 `session.exit`", `docs/design/testing.md` L5 순서 불변식)을 그대로 지킨다.
- resize는 `ResizePseudoConsole`.
- 이 스텝은 `pty::factory()`를 바꾸지 않는다. `UnsupportedFactory`는 Step 3이 지운다. 시제품은 `ConPtySource::spawn`(가칭)을 단위·통합 테스트에서 직접 부른다.
- 재산정: Step 3~11의 크기를 이 스텝에서 본 pipe 배치와 배수 비용으로 다시 매겨 커밋 본문에 적는다. main 세션이 §4 표, ROADMAP M20 크기 줄·§5.2·§5.4 리스크 5를 갱신한다.

**(b) 테스트·게이트:** (Windows 다리, `cmd.exe`)

- 순서 불변식 쌍둥이: `conpty_last_byte_arrives_before_the_exit_event`(`cmd /c "echo x"`의 `x`가 exit 이벤트 전), `conpty_one_mib_of_output_precedes_exit_completely`, `conpty_reader_is_never_blocked_by_a_slow_consumer`(unix `pty::tests`의 같은 이름 케이스 쌍둥이)
- Job Object: `conpty_child_is_in_the_session_job_from_creation`(unix `child_is_a_session_leader_with_the_pty_as_controlling_tty`의 Windows 대응, `IsProcessInJob`), `conpty_job_close_ends_the_whole_tree`(손자 프로세스까지)
- resize: `conpty_resize_is_applied_to_the_pseudo_console`(자식이 `mode con` 또는 probe로 보고한 크기)
- 배치 판정 결과를 가르는 계획 추가 `conpty_host_pipe_is_owner_only`(overlapped 배치를 채택한 경우, `fsutil/dacl/testing.rs`의 판독기)
- `m20.filter` 초안에 `conpty_` 접두 테스트를 넣는다.

**(c) 완료 판정:** pipe 배치 판정과 재산정이 커밋 본문에 있다. Windows 다리에서 순서 불변식 쌍둥이 셋이 부하 아래 50/50이다. unix `pty::tests` 무변경 초록. wire diff 0.

**(d) 결과 (2026-10-18):** `d538468`. overlapped named pipe 배치가 섰고(Windows 11 26100) 읽기 스레드 대체는 쓰지 않는다. JOB_LIST는 Windows 11에서 자식을 job 안에 만든다. Server 2022 러너는 첫 CI run이 판정하고, 거부되면 `CREATE_SUSPENDED` 대체로 바꾼다(§7.1 #1). `ClosePseudoConsole`은 닫아야 EOF가 오므로 자식 종료 시점에 blocking task에서 부르고 pump는 계속 읽는다. ADR-0035 개정 이력 2026-10-18 줄이 이것과 `STARTF_USESTDHANDLES`, 콘솔 닫힘에 따른 손자 종료를 적는다. 계획 이름과 다른 점: Job Object 생성은 `crate::winproc`(`JobObject`, `spawn_in_job`, `ExitWatch`)에 있고, `conpty_kill_signal_terminates_the_job`은 계획에 없던 smoke 테스트다(종료 status·signal 단언은 Step 4). 쓰이지 않던 `cwd`·환경 블록 경로는 Step 3이 테스트와 함께 들인다. 재산정: Step 2는 크기 안이고 Step 3~11과 M20 3.6~6.3ew는 그대로 둔다. Step 3에는 기본 셸을 `COMSPEC` 전체 경로로 풀어 argv[0]이 host cwd에서 탐색되지 않게 하는 일과 종료 코드 u32→i32 표기(§7.1 #4)가 더해진다. 부하: m20.filter 9개 50/50(Dave-Windows). nextest 3245/3245.

### Step 3 — ConPTY 백엔드 완성: 환경·셸·`user@`, `UnsupportedFactory` 제거, `pty/tests.rs` 쌍둥이, PTY 세션의 두 route (0.8~1.3ew) ✅ 2026-10-18

근거: ADR-0035 결정 2(`UnsupportedFactory` 제거), 3(`session open` 매트릭스 행, `cfg(unix)` 쌍둥이), 20, 21(환경 블록·고정 키·대소문자 무시·`COMSPEC` 기본 셸·`USERPROFILE` cwd·`user@` 비교·utmp 없음), 22의 `Hup`·`Term`(`ClosePseudoConsole`)과 `Kill`(`TerminateJobObject`), 17 host 테스트 항목, 19의 architecture §4 PTY 절·threat-model PTY 행·`pty/mod.rs` 모듈 doc. ROADMAP M20 범위 첫 문장. 선행: Step 2.

**(a) 범위:**

- `pty::factory()`가 Windows에서 ConPTY 팩토리를 돌려준다. `UnsupportedFactory`와 그 `#[cfg(not(unix))]` 갈래(`pty/mod.rs`)를 지운다. broker의 `SessionSource`/`SourceFactory` trait은 바뀌지 않는다.
- 환경(결정 21). `CreateEnvironmentBlock`으로 프로세스 토큰 사용자의 기본 환경을 받고, 그 위에 `TERM`(client 힌트, 기본 `xterm-256color`), locale·시간대(`LANG`, `LANGUAGE`, `LC_*`, `TZ`, 있을 때만), client `env` overlay를 얹은 뒤 고정 키를 다시 적용한다. 고정 키는 unix의 `HOME`/`USER`/`LOGNAME`/`SHELL`/`PATH`에 `USERPROFILE`/`USERNAME`/`USERDOMAIN`/`HOMEDRIVE`/`HOMEPATH`/`COMSPEC`/`SystemRoot`를 더한 집합이고, 대조는 대소문자 무시다. 고정 키 대조와 overlay 합성은 `cfg` 없는 순수 함수로 둔다(§7.1 #2). Step 4가 이 집합에 `QSH_SIGNAL_EVENT_USR1`·`USR2`를 더한다.
- 셸과 cwd. `argv`가 비면 그 환경의 `COMSPEC`(없으면 `%SystemRoot%\System32\cmd.exe`), cwd는 `USERPROFILE`. 비지 않은 `argv`는 Rust std의 Windows 명령줄 인용 규칙으로 넘긴다(결정 23과 같은 규칙).
- `user@` 비교. `crates/qsh-core/src/server/mod.rs`의 `lookup_login_name` Windows 구현이 프로세스 토큰의 계정 이름(`USERNAME`, `DOMAIN\USERNAME`이면 둘 다)을 돌려주고 비교는 대소문자 무시다. 불일치는 unix와 같은 `UNSUPPORTED`(`user switching is not supported`), 검사 순서는 `Authorizer::check(session.open)` → `user` 힌트 → spawn(architecture §4). 지금의 주석 "until a Windows host lands (P2)"는 낡았으므로 지운다.
- 세션 정리의 기본 경로(결정 22 중 이 스텝 몫). 신호 없는 `session close`의 첫 단계 `Hup`은 `ClosePseudoConsole`(`CTRL_CLOSE_EVENT`), escalation의 `Term`은 같은 사건이라 다시 보내지 않고 유예만 지나며, `Kill`은 `TerminateJobObject`다. `[serve].close_grace_ms`와 escalation 순서는 unix 코드와 같은 broker 경로를 탄다.
- `exit_code_matrix.rs`의 `session open` 행에서 `#[cfg(not(unix))]` 갈래를 지운다(모든 OS에서 `Succeeds(0)`).
- PTY 세션의 두 route(§4 규율 표 첫 두 행). `route_cases.rs`에 PTY 세션 케이스를 더하고 `windows_forward_e2e`·`windows_reverse_e2e`가 그것을 건다.
- `crates/qsh-cli/tests/it/acl_check_equivalence.rs`의 "A Windows host has no PTY sessions yet (M20)" 갈래와 `crates/qsh-cli/tests/it/sessions_filter.rs`·`exit_code_matrix.rs`의 PTY 의존 `cfg(not(unix))` 단언 가운데 이 스텝이 연 표면에 닿는 것을 정리한다(나머지는 Step 11, §5.6).
- 문서: architecture §4 PTY 절에 Windows 백엔드 문단(ConPTY, Job Object, 환경 블록, `COMSPEC`, `user@` 비교), threat-model §1 "세션 PTY와 child 프로세스" 행과 그 PTY 관련 §4 행에 ConPTY와 Job Object(DoD 5 첫 부분), `docs/CLI.md` §7의 host 쪽 Windows 범위 문장과 §6.7의 Windows 사건 사상(`Hup`·`Term`·`Kill`), `pty/mod.rs` 모듈 doc. `docs/design/testing.md` L5에 Windows quirk(ConPTY 출력 배수 순서, `ClosePseudoConsole` 시점) 항목.
- ADR 개정 보고(크기 내역의 "ADR 개정 0.1"): Step 2의 배치 판정과 이 스텝의 착지 형태(Job Object 함수의 자리, 환경 합성 순서) 가운데 결정 20·21 본문과 다른 것을 ADR-0035 개정 이력 줄 초안으로 커밋 본문에 적는다. main 세션이 더한다.

**(b) 테스트·게이트:** `crates/qsh-core/src/pty/` 쌍둥이(Windows 다리, `cmd.exe`)와 순수 함수(네 다리).

- DoD 1 핀: `conpty_close_terminates_the_whole_job_including_grandchildren`(unix `close_terminates_the_whole_process_group_including_grandchildren` 쌍둥이), `conpty_child_environment_is_the_user_block_not_ours`(serve 프로세스에 심은 변수가 자식에 없음, `USERPROFILE`·`USERNAME` 존재), `conpty_pinned_keys_cannot_be_overridden_case_insensitively`(client `env`의 `path`, `UserProfile`, `comspec`가 무시됨)
- unix 쌍둥이: `conpty_foreign_user_hint_is_unsupported_and_spawns_nothing`, `conpty_spawn_failure_leaves_no_process_in_the_job`(unix `post_fork_spawn_failure_kills_and_reaps_the_child`의 대응), `hundred_sequential_conpty_sessions_leave_no_processes_and_no_handle_growth`(`GetProcessHandleCount`, unix 좀비·fd 케이스 대응), `conpty_empty_argv_runs_comspec_in_userprofile`
- 순수 함수(네 다리): `windows_pinned_keys_match_case_insensitively`, `windows_env_overlay_reapplies_pinned_keys_last`, `login_name_comparison_accepts_user_and_domain_user_case_insensitively`
- 기본 정리 경로: `conpty_close_without_a_signal_starts_with_close_pseudo_console_and_escalates_to_terminate_job`
- route 동등: `windows_forward_e2e::pty_session_round_trip`·`windows_reverse_e2e::pty_session_round_trip`, `..._session_with_a_foreign_user_hint_is_unsupported` 두 route
- `exit_code_matrix.rs`의 `session open` 행이 Windows에서 `Succeeds(0)`
- 새 타이밍 민감 테스트를 `m20.filter`에 넣는다.

**(c) 완료 판정:** `pty/mod.rs`에 `UnsupportedFactory`가 없다. Windows host의 `session open`이 두 route에서 성공한다. unix `pty::tests`와 `tui_expect::` 무변경 초록. wire diff 0, `capabilities.json` diff 0(`session`은 이미 광고 중이다).

**(d) 결과 (2026-10-18):** `bd4b272`. `ConPtyFactory`가 `UnsupportedFactory`를 대체했고 환경 합성·고정 키·exit code는 `crates/qsh-core/src/pty/env_policy.rs`의 cfg 없는 순수 함수다. JOB_LIST는 첫 CI run(39060317009, Server 2022)에서 통과해 `CREATE_SUSPENDED` 대체는 쓰지 않는다. ADR-0035 개정 이력 2026-10-18 둘째 줄이 착지 형태(JOB_LIST 판정, application 이름은 자식 `PATH`와 시스템 디렉터리에서만 해석, 사용자 블록에 없는 고정 키는 자식에도 없음, 합성 순서, exit code 부호)를 적는다. 계획 이름과 다른 점: route 케이스 `pty_session_round_trip` 하나 대신 run·input·resize·close 넷이고(§4 표 고침), 외부 `user@` 힌트는 forward interactive 형태의 `windows_attach::a_foreign_user_hint_is_refused_without_creating_a_session`이 맡는다. reverse route에는 힌트를 싣는 CLI 표면이 없다. 부하에서 닫기 테스트 둘이 8회에 한 번꼴로 멈췄다. 원인은 Toolhelp 목록에 보인 손자가 아직 콘솔에 붙지 않아 `ClosePseudoConsole`의 사건을 놓친 것이고, 테스트가 손자가 직접 찍은 출력을 본 뒤 닫도록 고쳤다(제품은 escalation의 `Kill`이 같은 경우를 끝낸다). 부하: qsh-core conpty 17개 50/50, qsh-cli `pty_session_` 8개와 외부 힌트 1개 50/50(Dave-Windows). CI run 39071261522 초록.

### Step 4 — 세션 신호 일곱의 Windows 사상, `qsh internal console-ctrl`, 세션 이벤트, `--signal` 매트릭스 행 (0.3~0.5ew) ✅ 2026-10-18

근거: ADR-0035 결정 3(`cfg(windows)` 매트릭스 행), 22 전체(`Int` `CTRL_C_EVENT`, `Quit` `CTRL_BREAK_EVENT`, 숨김 보조 프로세스 `qsh internal console-ctrl <pid> <c|break>`를 `DETACHED_PROCESS`로, `Hup`·`Term` `ClosePseudoConsole`, `Usr1`·`Usr2` 이름 있는 자동 리셋 이벤트와 환경변수, `Kill` `TerminateJobObject`, 종료 상태의 `exit_code`·`signal`), 17 host 테스트 항목(신호 일곱과 escalation), 결과 절 "계약"(세션 환경변수 additive, 숨김 subcommand). `docs/CLI.md` §6.7·§7. 선행: Step 3.

**(a) 범위:**

- 신호 사상 표를 `cfg` 없는 순수 함수로 둔다(신호 이름 → Windows 첫 단계 동작, 그리고 `Hup` 다음 `Term` 단계 생략 규칙). 사상 자체는 결정 22 그대로다.
- `Int`·`Quit`: 같은 바이너리의 숨김 진입점 `qsh internal console-ctrl <pid> <c|break>`(clap `hide = true`, man 페이지와 `--help` 목록에서 제외)를 `DETACHED_PROCESS`로 띄운다. 본문(`AttachConsole(pid)`, 자기 처리기 끔, `GenerateConsoleCtrlEvent(_, 0)`, 끝)은 `qsh-core`에 두고 `qsh-cli`는 배선만 한다. 세션 루트는 `CREATE_NEW_PROCESS_GROUP` 없이 만든다(Step 2 생성 플래그 확인). 보조 프로세스 실행 파일 위치는 seam으로 둔다(§7.1 #5). ConPTY 입력에 `0x03`을 쓰는 방법은 쓰지 않는다.
- `Usr1`·`Usr2`: 세션을 만들 때 `Local\qsh-sig-<128비트 난수 hex>-usr1`·`-usr2`를 결정 9의 소유자 전용 DACL로 만든 자동 리셋 이벤트로 두고, 그 이름을 세션 환경의 `QSH_SIGNAL_EVENT_USR1`·`QSH_SIGNAL_EVENT_USR2`에 넣는다. 두 키는 Step 3의 고정 키 집합에 더해져 client가 덮어쓸 수 없다. 신호는 `SetEvent`다. 기다리는 프로그램이 없으면 세션은 유예 뒤 escalation으로 끝난다.
- 종료 상태: `exit_code`는 Windows 종료 코드 u32를 같은 비트의 i32로(std `ExitStatus::code()`와 같다), qsh가 보낸 사건 뒤에 세션이 끝났으면 `signal`에 그 단계의 신호 이름. 판정 규칙(어느 단계 뒤의 종료를 그 단계의 신호로 보는가)은 §7.1 #4.
- `exit_code_matrix.rs`에 `cfg(windows)` 행 하나: 일곱 값(`HUP`, `INT`, `QUIT`, `TERM`, `KILL`, `USR1`, `USR2`, `docs/CLI.md` §6.7의 허용 목록 표기를 따름) 각각으로 새 세션을 열고 `session close --signal`이 exit `0`.
- 문서: `docs/CLI.md` §6.7(Windows 사상 문단, 어느 신호든 세션은 결국 끝난다는 문장), §7의 host가 넣는 환경변수 목록에 `QSH_SIGNAL_EVENT_USR1`·`USR2`(additive), 상태 헤더 판. threat-model §3에 "세션 신호 이벤트(`Local\qsh-sig-…`)"와 "`qsh internal console-ctrl` 보조 프로세스" 진입점 행(같은 사용자 로컬, 난수 이름과 소유자 전용 DACL, 인자는 pid와 닫힌 두 값). architecture §4 신호 문단.

**(b) 테스트·게이트:**

- DoD 1 핀(Windows 다리, testkit `qsh-signal-probe`가 받은 사건을 종료 코드로 보고): `each_signal_raises_its_windows_event_then_escalates_to_an_ended_session`(일곱 신호 각각의 첫 사건, 그 뒤 유예·escalation으로 세션 종료), `int_reaches_every_process_on_the_session_console`, `quit_is_ctrl_break_not_ctrl_c`, `hup_then_term_does_not_send_ctrl_close_twice`
- 이벤트: `usr_signal_events_are_owner_only_and_named_in_the_session_environment`, `usr_signal_event_variables_cannot_be_overridden_by_the_client`, `an_unwaited_usr_signal_ends_the_session_by_escalation`
- 종료 상태: `exit_after_a_qsh_sent_event_reports_the_stage_signal`, `windows_exit_code_is_the_u32_bit_pattern_as_i32`(순수, 네 다리)
- 보조 프로세스: `console_ctrl_is_hidden_from_help_and_man`(`checked_in_man_pages_match_the_generator` 무변경 초록 포함), `console_ctrl_rejects_anything_but_a_pid_and_c_or_break`
- 순수 사상 표(네 다리): `signal_map_matches_adr_0035_decision_22`
- 매트릭스: `exit_code_matrix`의 `cfg(windows)` `session close --signal` 일곱 값 행
- route 동등: `windows_forward_e2e::session_close_with_each_signal_ends_the_session`·`windows_reverse_e2e::` 같은 이름
- 신호 수신·escalation 테스트를 `m20.filter`에 넣는다.

**(c) 완료 판정:** 일곱 신호가 Windows에서 모두 성공으로 답하고 세션이 끝난다. 새 계약은 환경변수 둘뿐이고 CLI.md §7에 있다. `docs/man/` diff 0. wire diff 0.

**(d) 결과 (2026-10-18):** `a475f08`. 신호 이름→첫 단계 사상과 `Hup`·`Term`이 콘솔 닫기 한 번을 나눠 쓰는 규칙은 `pty/signal_map.rs`의 cfg 없는 순수 함수(`first_step`, `next_step`)이고 `hup_and_term_share_one_console_close_step`이 네 다리에서 돈다. testkit `qsh-signal-probe`가 받은 사건을 종료 코드로 알리고, `each_signal_raises_its_windows_event_then_escalates_to_an_ended_session`은 신호마다 곧 끝나는 프로그램(첫 사건 실측)과 살아남는 프로그램(유예·`Term`·`Kill` 뒤 종료) 두 번을 돈다. `console-ctrl`의 전달 판정은 종료 상태가 아니라 성공 직후 표준 출력에 쓰는 한 바이트다(사건을 받은 콘솔이 사라지면 보조 프로세스도 비정상 종료 상태를 받는다). 바이트가 없으면 신호 기록을 지운다(`a_failed_console_ctrl_delivery_leaves_no_signal_note`). ADR-0035 개정 이력 2026-10-18 셋째 줄. 계획 문구와 다른 점: `exit_code_matrix`의 `cfg(windows)` `--signal` 커버리지는 `Case` 행 하나가 아니라 `Case` 루프 뒤의 블록이고, 일곱 값 모두 exit `0`을 단언한다(DoD 4와 Step 12 확인은 이 블록을 본다). 부하: qsh-core conpty·signals 27개 50/50, qsh-cli `pty_session_`·`session_close_with_each_signal_` 10개 50/50(Dave-Windows). 첫 부하 시도는 부하 스크립트가 `qsh-signal-probe.exe`를 복사하지 않아 무효였다. CI a475f08 초록.

### Step 5 — host 쪽 `exec`의 Job Object와 환경 고정 (0.2~0.3ew) ✅ 2026-10-18

근거: ADR-0035 결정 23(Job Object 안의 자식, 타임아웃 kill의 트리 도달, 결정 21 환경 규칙, `exec/mod.rs`의 `#[cfg(not(unix))]` 분기 제거, std 인용 규칙, `cmd /c`), 17 host 테스트 항목(`exec` 타임아웃 트리 종료), 결과 절 "고정할 테스트"의 `exec` 줄. 선행: Step 3.

**(a) 범위:**

- `crates/qsh-core/src/exec/mod.rs`: Windows에서 자식을 Step 2의 Job Object 안에서 만든다(생성 시점부터, `PROC_THREAD_ATTRIBUTE_JOB_LIST` 또는 `CREATE_SUSPENDED` 뒤 할당 후 재개 중 Step 2가 고른 쪽, §7.1 #1). 타임아웃 kill은 `TerminateJobObject`로 트리 전체에 닿는다(unix `process_group(0)` + `kill_group`의 대응).
- 환경은 Step 3의 순수 함수(사용자 환경 블록, locale·시간대 pass-through, client `env`, 고정 키 재적용)를 그대로 쓴다. 서버 환경을 거르지 않고 넘기던 `#[cfg(not(unix))]` 분기와 모듈 doc의 그 문장(origin `357fd58`의 `exec/mod.rs` 모듈 doc 첫 문단)을 지운다.
- argv는 셸을 거치지 않는다. `docs/CLI.md` `exec` 절에 `cmd.exe` 내장 명령은 `cmd /c`를 argv에 적어야 한다는 한 문장(unix의 셸 내장 명령과 같은 처지).

**(b) 테스트·게이트:**

- `exec_timeout_kills_the_whole_tree_on_windows`(손자 프로세스까지 사라짐, unix 쌍둥이와 같은 본문), `exec_child_environment_is_the_user_block_not_ours_on_windows`, `exec_pinned_keys_cannot_be_overridden_on_windows`
- route 동등: `windows_forward_e2e::exec_timeout_kills_the_whole_tree`·`windows_reverse_e2e::` 같은 이름
- 기존 `windows_*_e2e::exec_round_trip`(`cmd /c`, 종료 코드 7) 무변경 초록

**(c) 완료 판정:** `exec/mod.rs`에 `#[cfg(not(unix))]` 환경 분기가 없다. wire diff 0.

**(d) 결과 (2026-10-18):** `038f74e`. `exec/{posix,windows}.rs`로 갈랐고 Windows 자식은 생성 순간부터 `KILL_ON_JOB_CLOSE` Job Object 안이다. 계획 문구와 다른 점: 환경에 locale·시간대 전달을 넣지 않는다. unix `exec.run`이 결정적인 환경을 위해 일부러 넣지 않으므로 두 OS를 맞췄다(`exec_locale_and_time_zone_do_not_pass_through_from_the_serve_process`). PTY 세션은 그대로 전달한다. 상속 가능 pipe 끝은 `winproc::spawn_guard()` 잠금 안에서만 열리고, console-ctrl·ssh·서비스 관리자의 `std::process` spawn도 같은 잠금을 잡는다(`the_pipe_ends_are_inheritable_only_inside_spawn_in_job`). ADR-0035 개정 이력 2026-10-18 넷째 줄. `run_exec` 수준의 timeout 트리 테스트는 QUIC stream이 필요해 testkit `exec_loopback::exec_run_timeout_kills_the_whole_tree_on_windows`에 있다. 부하: qsh-core `exec::windows`·winproc 19개, qsh-cli `exec_` 4개, testkit 1개 모두 50/50(Dave-Windows). CI 038f74e 초록.

### Step 6 — host 쪽 상태: audit writer `LockFileEx` 잠금·재검증, `acl.toml` DACL 경고 (0.4~0.7ew)

근거: ADR-0035 결정 24(결정 9 모듈이 audit 로그·회전 파일·잠금 파일과 디렉터리·`stateless_reset.key`를 만듦, `LockFileEx`, `GetFileInformationByHandle`의 (볼륨 일련번호, 파일 인덱스)로 재검증, `acl.toml` DACL 경고 조건과 구조적 필드, 거부로 바꾸지 않음), 19의 threat-model §4 E 행, 결과 절 "고정할 테스트"의 audit·`acl.toml` 줄. ADR-0010(회전), ADR-0017 결정 1. ROADMAP M20 DoD threat model 줄. 선행: Step 1.

**(a) 범위:**

- `crates/qsh-core/src/audit/writer.rs`의 `#[cfg(not(unix))]` `with_lock`·`revalidate` no-op 둘을 Windows 구현으로 바꾼다. 잠금은 `<active>.lock` 파일(결정 9 DACL)에 `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK)`, 재검증은 열린 핸들과 경로의 (볼륨 일련번호, 파일 인덱스)를 비교해 다르면 다시 연다. 식별 함수는 `fsutil` 하위에 두어 Step 7이 다시 쓴다(§7.1 #9). 바이트 append는 unix와 같이 잠금 밖이다(`FILE_APPEND_DATA`로 연 핸들).
- `crates/qsh-core/src/acl/load.rs`: unix `warn_if_group_or_world_writable`의 Windows 쌍둥이. 파일 DACL을 읽어 소유자·`SYSTEM`·`Administrators` 밖의 SID에 쓰기 계열 권한(`FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_WRITE`, `GENERIC_ALL`)을 주는 허용 ACE가 있거나 DACL이 null이면 경고한다. 경고 레코드는 unix와 같은 구조적 필드만 싣고 `mode` 대신 문제의 SID 문자열을 싣는다(필드 이름은 §7.1 #10). 거부로 바꾸지 않는다. qsh는 `acl.toml`을 쓰지 않는다(ADR-0017).
- DACL 판정(ACE 목록 → 경고 여부, 문제 SID)은 ACE를 값으로 받는 `cfg` 없는 순수 함수로 두고, OS에서 ACE를 읽는 부분만 `cfg(windows)`다.
- 문서: threat-model §4 E에 `acl.toml` DACL 경고 행(DoD 5 둘째 부분, unix 쪽 행이 있으면 그 행의 Windows 변형으로), architecture §6 audit 잠금 문단의 Windows 문장, `audit/writer.rs`·`acl/load.rs`의 주석에 있는 "A no-op on non-unix" 류 문장.

**(b) 테스트·게이트:**

- audit(Windows 다리): `rotating_audit_sinks_on_one_path_never_race_a_rename_on_windows`(두 `RotatingAuditSink`가 같은 경로에 번갈아 쓰며 회전, 레코드 유실·중복 0, unix 쌍둥이와 같은 본문), `audit_writer_reopens_after_the_active_file_is_replaced_on_windows`(재검증), `audit_lock_file_has_an_owner_only_dacl`
- 식별 함수: `file_identity_is_volume_serial_and_file_index`(같은 파일 두 핸들은 같고, rename 뒤 새 파일은 다름)
- `acl.toml` 경고: 순수 함수(네 다리) `acl_dacl_warns_for_a_write_ace_to_another_sid`, `acl_dacl_is_silent_for_owner_system_and_administrators`, `acl_dacl_warns_for_a_null_dacl`, `acl_dacl_ignores_read_only_aces`. Windows 다리 `acl_toml_with_an_everyone_write_ace_warns_with_structural_fields_only`(경고 레코드에 SID만, 파일 내용 없음, 로드는 성공)
- route 동등: `serve`와 `serve --to`가 같은 `<state>/audit.log`를 쓰는 경우의 잠금(`audit_rotation_lock_holds_between_serve_and_serve_to_on_windows`), 두 run mode 기동에서 경고가 같은 필드로 나옴
- 잠금 경합 테스트를 `m20.filter`에 넣는다.

**(c) 완료 판정:** `audit/writer.rs`에 `#[cfg(not(unix))]` no-op이 없다. `acl.toml` 경고가 Windows에서 구조적 필드만으로 나온다. wire diff 0.

### Step 7 — host 쪽 `qsh cp`: 경로 판정, 파일 host, `FILE_DATA`, `file.v1` 광고, `cp` 종단 (0.5~0.9ew)

근거: ADR-0035 결정 26 전체(경로: `/`와 `\` 동일시, 드라이브 절대 경로와 `USERPROFILE` 기준 상대 경로, `host:`는 `USERPROFILE`, UNC·장치 이름 공간은 ACL 판정 전 `INVALID_ARGUMENT` / 정규화: `GetFinalPathNameByHandleW`에서 `\\?\` 접두를 뗀 것, 성분 단위 대소문자 무시 비교, `FILE_FLAG_OPEN_REPARSE_POINT`로 열어 재분석 지점 거부, 열린 핸들의 최종 경로 재검증 / mode 합성, 읽기 전용 특성, 임시 파일 소유자 전용 DACL과 rename 직전 보호 해제, `SetFileTime`), ADR-0029 결정 5·6·7·8·13·23(판정 순서, 상태 경로 항상 거부, inode 대조, 원자 교체, 여유 공간, Windows host의 착지와 `file.v1` 광고), ADR-0035 결정 2·3(매트릭스의 `cp` 두 행), 17(`cp` 종단), ROADMAP M20 DoD 둘째 줄의 "Windows host 상대 `qsh cp`(M19 DoD에서 옮겨 옴)". 선행: Step 1(코드), `fsutil` 식별 함수는 Step 6과 조율.

**(a) 범위:**

- `crates/qsh-core/src/file/guard.rs`의 `#[cfg(not(unix))]` stub(경로 판정 없음, 정규화 없음, inode 식별 없음)을 Windows 구현으로 바꾼다.
  - 원격 경로 문자열 분류(순수, 네 다리): `/`·`\` 동일시, 드라이브 절대(`C:\…`, `C:/…`), `USERPROFILE` 기준 상대, 빈 경로와 `host:`는 `USERPROFILE`, UNC(`\\server\share`)와 장치 이름 공간(`\\?\`, `\\.\`)은 기존 `INVALID_ARGUMENT`로 ACL 판정 전에 거부.
  - 정규화: 존재하는 가장 긴 조상을 `FILE_FLAG_BACKUP_SEMANTICS`로 열어 `GetFinalPathNameByHandleW`로 풀고 `\\?\` 접두를 뗀 뒤 나머지를 어휘적으로 접는다(unix `realpath` 절차의 대응, architecture §6의 정규 경로 문장). 비교(`[[acl]] paths` prefix, 보호 집합)는 성분 단위 대소문자 무시다. `paths` 항목 문법(`C:/…`, `\`·드라이브 없는 항목·`"/"`는 `CONFIG_ERROR`)은 M15에 이미 착지했다(`acl/paths.rs`의 `PathStyle::Windows`).
  - 열기와 재검증: 마지막 구성 요소는 `FILE_FLAG_OPEN_REPARSE_POINT`로 열어 재분석 지점(symlink, junction)이면 거부하고(unix `O_NOFOLLOW`의 대응), 열린 핸들의 최종 경로가 판정한 정규 경로와 같은지 다시 본다.
  - inode 대조(ADR-0029 결정 6 5번): 연 파일의 (볼륨 일련번호, 파일 인덱스)가 보호 파일의 것과 같으면 거부한다. 식별 함수는 Step 6과 같다(§9 #4).
- `crates/qsh-core/src/file/host.rs`와 `server/file.rs`·`server/tunnels.rs`의 `#[cfg(not(unix))]` 갈래(파일 host 미설정, `FILE_DATA` 티켓 reset)를 걷는다.
  - 쓰기: 대상 디렉터리 핸들 아래 임시 파일을 결정 9의 소유자 전용 DACL로 만들고(`CREATE_NEW`), 해시 확인 뒤 rename 직전에 보호를 풀어 대상 디렉터리의 상속 ACL을 받게 하고 `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` 또는 `SetFileInformationByHandle`의 rename으로 교체한다(§7.1 #11). umask 읽기(`init_umask`)는 Windows에서 하지 않는다. 상속 ACL이 그 자리다.
  - mode: 읽을 때 합성(파일은 읽기 전용 특성이면 `0o444`, 아니면 `0o644`, 디렉터리 `0o755`), 쓸 때는 받은 mode의 소유자 쓰기 비트가 꺼져 있을 때만 읽기 전용 특성을 켠다. `-p`의 수정 시각은 `SetFileTime`. 이 규칙은 M19가 client 로컬 쓰기에 이미 착지시킨 `file/local`·`file/stat`과 같은 함수를 쓴다.
  - 여유 공간 probe(ADR-0029 결정 13): `GetDiskFreeSpaceExW`. 기존 주입 seam(`set_free_space_probe`)은 그대로.
- `file.v1` 광고: `crates/qsh-proto/src/wire.rs`의 `LOCAL_CAPABILITIES` 두 정의를 하나로 합쳐 Windows 빌드도 `CAP_FILE_V1`을 광고한다. `CAP_FILE_V1`·`LOCAL_CAPABILITIES`의 doc 주석에서 "unix only" 문장을 지운다. 광고와 data plane은 같은 커밋에 착지한다(ADR-0029 결정 1·9와 같은 규율). `capabilities.json` golden은 바뀌지 않는다. Windows 빌드의 대조 테스트가 "이 항목 하나를 더해 비교"하던 보정은 지운다(`docs/design/protocol.md` capability 절 문장).
- `exit_code_matrix.rs`의 `cp: put of a local file that does not exist`(Windows `INVALID_ARGUMENT`로 합류)와 `cp: get from a host that grants this client no file access`(Windows `PERMISSION_DENIED`로 합류) 두 행에서 `#[cfg(not(unix))]` 갈래와 그 앞 주석(“a Windows host does not advertise `file.v1` until its file operations land”)을 지운다.
- `cp` 종단: `windows_forward_e2e::cp_to_a_windows_host_is_unsupported_before_m20`과 역방향 같은 이름을 지우고 `route_cases.rs`의 `cp` 케이스로 바꾼다.
- 문서: `docs/CLI.md` §6.21의 "Windows host의 파일 op는 M20이 한다" 문단을 착지 상태로(Windows host의 경로 표기, `host:`=`USERPROFILE`, UNC 거부, mode 합성, 재분석 지점 거부), §6 capability 절의 `file.v1` 문장(“unix 빌드만 광고”), `docs/design/protocol.md` capability 절, architecture §6의 "이 모듈은 `cfg(not(unix))`에서 모든 경로를 거부하는 stub" 문장, threat-model §4 B22·B24의 Windows 수단(재분석 지점, (볼륨 일련번호, 파일 인덱스), 대소문자 무시)과 UNC 거부 행(DoD 5 계획 규율 부분), `file/guard.rs`·`file/host.rs` 모듈 doc의 "Windows is M20".

**(b) 테스트·게이트:**

- 경로 분류(순수, 네 다리): `windows_remote_path_treats_slash_and_backslash_alike`, `windows_remote_path_resolves_relative_and_empty_to_userprofile`, `windows_remote_path_refuses_unc_and_device_namespaces_before_acl`
- 정규화·재검증(Windows 다리): `windows_canonical_path_strips_the_verbatim_prefix`, `windows_paths_prefix_match_folds_case_by_component`, `windows_open_refuses_a_symlink_and_a_junction`, `windows_open_handle_revalidation_catches_a_swapped_component`
- 상태 경로(ADR-0029 결정 5·6의 기존 핀 Windows 쌍둥이): `file_write_to_state_paths_is_denied_even_with_root_paths`·`file_read_of_state_paths_is_denied_even_with_root_paths`의 Windows 판(hard link 우회 포함, `CreateHardLinkW`), `state_path_guard_` 접두 기존 케이스의 Windows 행
- 쓰기·mode: `windows_put_temp_file_is_owner_only_until_rename_then_inherits`, `windows_put_sets_read_only_only_when_owner_write_is_clear`, `windows_get_synthesizes_mode_bits`, `windows_put_preserves_mtime_with_p`, `windows_put_refuses_when_free_space_is_short`(주입 probe)
- 광고: `windows_build_advertises_file_v1`(`LOCAL_CAPABILITIES`가 모든 빌드에서 같음), `capabilities.json` 무변경 초록, `crates/qsh-proto/src/wire/tests.rs`의 unix 한정 단언 정리
- 매트릭스: `exit_code_matrix`의 두 `cp` 행이 Windows에서 unix와 같은 결과
- route 동등: `windows_forward_e2e::cp_round_trip`·`windows_reverse_e2e::cp_round_trip`(put·get·`-r`·`-p`), `..._cp_refuses_state_paths_and_reparse_points` 두 route
- 기존 unix `cp_e2e::`·`cp_recursive::`·`cp_cancel::`·`file_host::` 무변경 초록. 이 모듈들의 Windows 쌍둥이 범위는 §5.6과 Step 11.
- 실제 QUIC loopback `cp` 종단을 `m20.filter`에 넣는다.

**(c) 완료 판정:** `file/guard.rs`·`file/host.rs`·`server/file.rs`·`server/tunnels.rs`에 파일 op를 거부하는 `#[cfg(not(unix))]` 갈래가 없다. Windows host가 `file.v1`을 광고하고 두 route에서 `cp`가 왕복한다. `exit_code_matrix.rs`의 `cp` 두 행에 `#[cfg(not(unix))]`가 없다. `git diff -- crates/qsh-proto/src/wire.rs`가 `LOCAL_CAPABILITIES` 통합과 doc 주석뿐이고 `capabilities.json` diff 0, `.proto`·`local.rs` diff 0.

### Step 8 — `setup host`(`--to`, `--service` 포함), `pair invite`, 방화벽 안내 (0.1~0.3ew)

근거: ADR-0035 결정 1 host 쪽(`qsh setup host`(`--to` 형태 포함), `qsh pair invite`), 1 서비스(`qsh setup host --service`), 2(남은 게이트 제거), 25(`setup host`·`pair invite`를 연다, 방화벽 첫 허용 프롬프트를 README와 `qsh doctor`의 기존 finding 문안이 안내), 27 끝 문장(`setup host --service`가 작업 스케줄러 백엔드를 부름). ADR-0024 결정 2·8·10. 선행: Step 1(코드), Step 3(문서 착지).

**(a) 범위:**

- `qsh setup host`와 `qsh setup host --to <controller>`가 Windows에서 다른 OS와 같은 단계(identity, pin, `peer_role`, serve 설정, `service`)를 돈다. origin `357fd58`에서 이 경로에 남은 Windows 전용 거부나 건너뜀이 있는지 먼저 찾는다(`crates/qsh-core/src/setup/`, `crates/qsh-cli/src/main.rs`의 `Setup` 배선). 없으면 이 스텝의 코드는 테스트와 안내 문장뿐이다.
- `--service`: `setup` 단계가 M19의 작업 스케줄러 백엔드를 부른다(`serve`·`reverse` mode 작업 정의 파일). `UNSUPPORTED`를 건너뜀으로 보던 `setup/run.rs`의 분기는 다른 OS에도 쓰이므로 남기되, Windows에서 그 분기를 타지 않음을 테스트가 본다.
- `qsh pair invite`: Windows host에서 초대 코드 발급과 경로 질의(threat-model §3 `pair invite` 경로 질의 행)가 같은 동작을 한다.
- 방화벽 안내: `qsh serve`·`serve --to`가 UDP 포트를 열 때 Windows Defender 방화벽의 첫 허용 프롬프트가 뜰 수 있음을 README와 기존 doctor finding 문안에 적는다. 어느 finding의 문안인지는 이 스텝이 정한다(§7.1 #12). 새 finding code는 두지 않는다.
- 문서: `docs/CLI.md` §6.20(`setup host`의 Windows 문장), §6.11 근처의 `pair invite` Windows 문장, README Known limitations의 방화벽 문장.

**(b) 테스트·게이트:**

- `setup::`의 host·host_to 행이 Windows에서 성공(`--service` 포함, 가짜 매니저 없이 파일만 씀, M9 계약). 계획 추가 `setup_host_service_writes_the_task_definition_on_windows`
- `trust_pairing_live::`의 `pair invite` → `pair accept` 케이스가 Windows host에서 성공(쌍둥이 또는 `#[cfg(unix)]` 제거, §5.6)
- route 동등: §4 규율 표의 `setup`·`pair invite` 행

**(c) 완료 판정:** Windows host 쪽 `setup host`·`setup host --to`·`--service`·`pair invite`에 Windows 전용 거부가 없다. wire diff 0.

### Step 9 — Windows `qsh pair ssh-respond` (0.2~0.4ew)

근거: ADR-0035 결정 1 host 쪽(`qsh pair ssh-respond`), 25(Windows에서 `unsupported_platform`을 내지 않고 다른 OS와 같은 순서, OpenSSH Server 필요, 원격 기본 셸 `cmd.exe`의 9009와 PowerShell의 1), ADR-0044 결정 9·10·12·14·25, `docs/design/protocol.md` §17 응답자 문단. 선행: Step 1(코드), Step 3(문서 착지).

**(a) 범위:**

- `crates/qsh-cli/src/cli.rs`의 `#[cfg(unix)] SshRespond`와 `crates/qsh-cli/src/main.rs`의 `SSH_RESPOND_MODE`·`run_ssh_respond`·명령 이름 표의 `#[cfg(unix)]`를 걷는다. 숨김(`hide = true`)은 그대로다.
- `crates/qsh-core/src/ssh_bootstrap/respond.rs`와 `ssh_bootstrap/mod.rs`의 "Unix only until M20"을 걷는다. 응답자 순서(identity 읽기, `serve` 주소 UDP bind 시험, hello, 30초 commit 대기, 잠금 안에서 `trust.toml` 판정, audit `pair.ssh_respond` 뒤 저장)는 OS와 무관하다. Windows에서 갈리는 것(잠금은 M19의 `FileLock`, 새 `trust.toml`은 결정 9 DACL, stdin·stdout은 ssh가 준 pipe, 줄 끝 `\r\n` 수용)만 확인하고 고친다.
- 클라이언트 쪽 종료 코드 사상(127과 `cmd.exe` 9009는 `remote_qsh_missing`, PowerShell 1은 `remote_command_failed`와 `qsh.exe` `PATH`·`--remote-qsh` 안내)은 M16에 착지했으므로 바꾸지 않는다.
- 테스트의 Windows 응답자는 가짜 ssh(`qsh-fake-ssh`)가 실제 Windows `qsh pair ssh-respond`를 자식으로 띄우는 꼴이다(`docs/design/testing.md` 가짜 ssh 문단). 실제 OpenSSH Server 회차는 §1과 캠페인 W7.
- 문서: `docs/design/protocol.md` §17 응답자 문단의 "Unix 빌드에만 등록돼 있고 Windows 빌드의 응답자는 M20" 문장, `docs/CLI.md` §2.4·부트스트랩 절의 같은 문장, README Known limitations의 "The remote responder ... arrives with the Windows host in M20" 문장, `docs/design/testing.md` 가짜 ssh 문단.

**(b) 테스트·게이트:**

- `ssh_bootstrap::`의 응답자 행이 Windows 응답자로 성공(`pinned`, `exists`, `conflict`, `not_initialized`, commit 없이 끝남). origin `357fd58`의 `crates/qsh-cli/tests/it/ssh_bootstrap.rs`에 있는 "A Windows build has no `qsh pair ssh-respond` before M20" 테스트(`remote_qsh_too_old`를 단언하는 것)는 Windows 응답자가 생겼으므로 지우고, 같은 자리에 계획 추가 `windows_responder_pins_and_reports_serve_listening`
- `responder_trust_toml_has_an_owner_only_dacl_on_windows`, `responder_accepts_crlf_commit_lines`(이미 있으면 Windows 다리에서 초록)
- 자동 부트스트랩: `crates/qsh-cli/tests/it/auto_bootstrap.rs`의 "host does not run until M20, so these cases end at the bootstrap" 케이스가 Windows 응답자 뒤 원래 명령(attach, `cp`)까지 끝남
- route 동등: `pair ssh`와 `pair ssh --reverse` 두 응답자 행

**(c) 완료 판정:** Windows 빌드가 `qsh pair ssh-respond`를 안다. `ssh_bootstrap`의 Windows 응답자 행과 `--reverse` 행이 Windows 다리에서 초록이다. `docs/man/` diff 0. wire diff 0.

### Step 10 — 캠페인 `p1-windows.md` host 회차 추가와 재고정 (0.1~0.2ew)

근거: ADR-0035 결정 18(M20이 host 회차 (2), (3)의 Windows target 쪽, (7)을 더해 M20 마지막 스텝 전에 다시 고정), ROADMAP M20 DoD 캠페인 줄과 §5.5, `docs/campaigns/p1-windows.md` §4.12와 §5. 선행: Step 3·4·7·8·9. Step 11(구현 마지막 스텝) 앞.

**(a) 범위:**

- §4.12 "M20 자리"를 회차 절 셋으로 바꾼다. 문서 스스로 정한 규칙(§4.12 첫 문단)대로 §1~§4.11의 문면과 §5의 규칙은 바꾸지 않고, 바뀌는 것은 §1 표의 "M20 자리"가 "M20"으로 바뀌는 것, 새 회차 절, §5 판정 문장의 회차 목록 한 줄, §5의 "W2, W3b, W7은 M20이 더하기 전에는 판정에 들지 않는다" 줄의 삭제다.
  - W2. Linux·macOS client → Windows host(`qsh serve`). `cmd.exe`·PowerShell(`qsh host -- pwsh`)·Windows 빌드 `vim` 전체 화면과 종료 뒤 복원, 한글 입출력, resize, `Ctrl-C`, `~d` 뒤 `qsh attach` resume, `qsh session close --signal INT`·`USR1` 한 번씩, 방화벽 첫 허용 프롬프트와 README·doctor 안내 대조.
  - W3b. Linux·macOS `qsh listen` ← Windows `qsh serve --to`. attach, `qsh cp` put·get(드라이브 경로, 읽기 전용 특성), `-L`·`-R` 터널. 두 장비 사이 실제 UDP 경로.
  - W7. `qsh pair ssh`와 `--reverse`가 Windows OpenSSH Server를 상대로 pin을 세움. 원격 기본 셸 `cmd.exe`와 PowerShell 두 변형(PowerShell 변형은 `qsh.exe`가 `PATH`에 없을 때 `remote_command_failed`와 안내 문구를 확인).
- 각 회차의 선행 조건(Windows 방화벽 허용 규칙, OpenSSH Server 선택적 기능, 둘째 장비), 확인 문자, 기록 열. 형식은 문서의 기존 회차 절을 따른다.
- `docs/ROADMAP.md` §5.5 Windows 행의 재고정 해시는 main 세션이 채운다.

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록. 회차가 가리키는 명령 이름과 환경변수 이름이 착지한 clap 트리·`docs/CLI.md`와 같은지 손으로 대조한다.

**(c) 완료 판정:** 문서가 Step 11 착지 전에 main에 있다. §1~§4.11의 문면이 바뀌지 않았다(`git diff`로 확인).

### Step 11 — PTY를 포함한 정방향·역방향 종단, 실제 PTY attach, `release_smoke` PTY 축, `cfg(unix)` 쌍둥이 전수 (0.4~0.7ew)

근거: ADR-0035 결정 3(`cfg(unix)` 테스트의 `cfg(windows)` 쌍둥이 또는 이유 주석과 Windows 수단 테스트), 17(정방향 종단의 ConPTY 안 대화형 `qsh <name>`, 입력 echo, resize 전파, `~d` 뒤 `qsh attach` resume; 역방향 종단의 같은 목록; `release_smoke`의 PTY session open·write·read·close와 DACL 단언), 결과 절 "고정할 테스트"의 종단·`release_smoke` 줄, ROADMAP M20 DoD 둘째·셋째 줄, §5.1 원칙 7. 선행: Step 3·4·5·7·9, Step 10.

**(a) 범위:**

- 대화형 attach의 실제 PTY 케이스. M19의 `windows_attach.rs`는 testkit `echo_host`를 상대로 돈다. 같은 모듈에 실제 Windows `qsh serve`(정방향)와 실제 `qsh serve --to`(역방향)의 PTY host를 상대로 ConPTY 안의 실제 `qsh`가 붙는 케이스를 더한다. 입력 echo(`cmd.exe`의 `echo`), resize 전파(`mode con` 보고), `~d` 뒤 `qsh attach` resume, 콘솔 닫힘 detach. `echo_host` 케이스는 남긴다(§9 #5).
- client crash 생존(SC5)의 Windows 쌍둥이. unix `session_kill9`의 Windows 대응으로 ConPTY 안 `qsh`를 `TerminateProcess`로 죽인 뒤 세션이 host에 남고 다른 콘솔에서 `qsh attach`로 이어 붙는다.
- host 정지 drain. unix `serve_sigterm_drain`의 Windows 대응으로 `qsh serve`·`serve --to`가 정상 정지 신호(M19의 콘솔 닫힘·`CTRL_BREAK` 경로)를 받으면 신규 open을 거부하고 모든 세션에 close 절차(Step 3·4의 Windows 사건)를 적용한 뒤 끝나며 Job Object가 고아 프로세스를 남기지 않는다(`docs/CLI.md` SIGTERM drain 문단, ADR-0003).
- `release_smoke`의 `#[cfg(not(unix))]` 쌍둥이를 넓힌다. 이름 `release_smoke_covers_init_trust_exec_doctor_and_a_tunnel_on_a_platform_without_a_pty_host`는 뜻이 틀려지므로 PTY 축을 더한 새 이름으로 바꾼다(가칭 `release_smoke_covers_init_trust_exec_doctor_tunnel_and_a_pty_session_on_windows`). 기존 축(`init` → `trust` → `exec --json` → `doctor --json` → `tunnel open --local` echo)에 PTY session open·write·read·close를 더하고, 만든 파일의 DACL 단언(`assert_account_only`)은 유지한다. 대화형 detach·reattach 축은 unix `expectrl` 축의 Windows 대응을 ConPTY 하니스로 둘지 §7.1 #6이 정한다.
- `cfg(unix)` 쌍둥이 전수. §5.6 표의 각 모듈과 테스트를 처분대로 연다. PTY·파일 host가 없어서 빠졌던 것은 `#![cfg(unix)]`를 걷거나 `route_cases.rs` 꼴의 공유 본문으로 Windows 쌍둥이를 둔다. 개념이 unix인 것은 이유 주석과 Windows 수단 테스트의 이름을 남긴다. M19 뒤에도 "localctl (UDS) ... compiles out on Windows"를 이유로 남은 testkit 모듈의 낡은 주석은 M19가 연 named pipe localctl로 열거나 다른 실제 이유로 고친다.
- `sessions_filter.rs`의 live 세션 케이스 Windows 쌍둥이(모듈 doc의 "The same cases over live sessions are M20's").
- 문서: `docs/design/testing.md` Windows leg 문단들(정방향·역방향 종단, client 기능 동등의 "Windows host에는 PTY 세션이 없으므로(M20)" 문장, L5에 Windows PTY 종단 항목, `release_smoke` 문장), ROADMAP M10 결정 기록 Q1의 Windows leg 축은 main 세션이 마감 노트에서 대조한다.

**(b) 테스트·게이트:**

- DoD 2 핀: `windows_attach::pty_attach_round_trip_forward`·`_reverse`, `windows_attach::pty_detach_then_attach_resumes_forward`·`_reverse`, `windows_attach::pty_resize_propagates_forward`·`_reverse`, 그리고 Step 3·5·7의 `windows_*_e2e::` PTY·`exec`·`cp` 케이스가 같은 run에서 초록
- SC5: `windows_attach::killed_client_leaves_the_session_running_forward`·`_reverse`
- drain: `serve_stop_drains_sessions_and_leaves_no_orphan_on_windows`, `serve_to_stop_drains_sessions_and_leaves_no_orphan_on_windows`
- DoD 3 핀: 이름을 바꾼 `release_smoke`의 Windows 쌍둥이(PTY 축 포함)
- `sessions_filter::`의 Windows live 세션 쌍둥이(forward, 데몬 fan-out reverse)
- §5.6 표의 각 처분이 Windows 다리에서 초록이거나 이유 주석과 대응 테스트 이름이 있음
- 새 종단 테스트를 `m20.filter`에 넣는다.

**(c) 완료 판정:** Windows leg이 정방향과 역방향을 같은 케이스 목록(`exec`, 터널 echo, PTY attach와 resume, `cp`)으로 돈다. `release_smoke` Windows 쌍둥이에 PTY 축이 있다. §5.6 표에 처분 없는 행이 없다. wire diff는 Step 7의 `LOCAL_CAPABILITIES` 통합뿐이다.

### Step 12 — 마감 (0.1~0.2ew)

근거: 마일스톤 마감 공통 절차(`docs/ROADMAP.md` §2) 1·2, 이 문서 §4의 안정성 규율과 §5.7 유예 대응표. 선행: Step 2~11.

**(a) 범위:**

- **부하 반복.** M20 타이밍 민감 테스트 전부를 `scripts/stress/m20.filter`로 묶는다(§7.1 #14). Linux·공통은 Dave-Windows-WSL에서, Windows 전용은 Dave-Windows에서 `QSH_ACCEPTANCE_SLOW=1 scripts/stress/run.sh`로 50회 돌리고 각각의 "50/50 passed under load" 줄, 테스트 개수, 호스트 사양을 마감 노트에 적는다. `m20-latency.filter`는 두지 않는다(M20에 새 지연 예산 단언이 없다. 기존 echo 예산은 acceptance job이 본다).
- **절차 1. 구속 문서 태그 대조.** 대상은 다음과 같다.
  - `docs/CLI.md` M20 판 이후 항목: §2.4·§6 capability 절·§6.7·§6.11·§6.20·§6.21·부트스트랩 절·§7, 그리고 `exec` 절의 `cmd /c` 문장
  - `docs/design/protocol.md` capability 절과 §17 응답자 문단
  - `docs/design/architecture.md` §4·§6·§7·§8, `docs/design/testing.md` L5·Windows leg 문단·가짜 ssh 문단·신뢰 철회 문단
  - `docs/design/threat-model.md` §1·§3·§4 B·D·E·§7
  - ADR-0035 결과 절 "마일스톤 배치"의 M20 항목 전수(결정 1·2·3의 host 쪽, 20~24, 25의 나머지, 26, 17의 host 테스트·PTY 종단·`release_smoke` PTY 축, 18의 host 회차, 19의 host 쪽 문서), ADR-0029 결정 23의 Windows host 문장, ADR-0044 결정 10·25의 Windows 응답자 문장, ADR-0031 결정 3의 플랫폼 문장(“`serve --to`가 M20에서 열린다”는 M19가 당겨 착지했으므로 개정 이력 줄로 이미 기록됐는지 확인)
  - 코드 모듈 doc: `pty/mod.rs`, `pty/conpty.rs`, `exec/mod.rs`, `audit/writer.rs`, `acl/load.rs`, `file/guard.rs`, `file/host.rs`, `ssh_bootstrap/mod.rs`·`respond.rs`, `crates/qsh-proto/src/wire.rs`의 `CAP_FILE_V1`
  - §5.7 유예 대응표의 모든 행이 착지했다. `rg -n "M20"`을 다시 돌려 남은 hit가 기록(ADR 개정 이력, ROADMAP 마감 노트, 캠페인 문서의 M20 회차 표기, `docs/PRD.md` P1 목록)뿐임을 확인한다. `rg -n "Windows host" -g '*.rs'`로 "until/before M20"류 문장이 남지 않았는지도 본다.
  - `exit_code_matrix.rs`에 `#[cfg(not(unix))]`·`#[cfg(windows)]` 갈래로 Windows만 다른 `UNSUPPORTED`를 내는 행이 없음을 `rg -n 'cfg\(not\(unix\)\)|cfg\(windows\)' crates/qsh-cli/tests/it/exit_code_matrix.rs`로 확인하고, 남은 갈래가 있으면 그 이유(예: `cfg(windows)` 신호 행 자체)를 마감 노트에 적는다(DoD 4).
- **절차 2. README 동기화.** 기능 목록(Windows host), Known limitations의 Windows 문단 재작성("Windows support is planned for P1: the client in M19 and the host in M20" 이하를 착지 상태로: 같은 기능, ConPTY의 Windows 10 1809 하한, 방화벽 프롬프트, `cmd.exe` 기본 셸과 `qsh host -- pwsh`, 신호 사상과 `QSH_SIGNAL_EVENT_USR1`·`USR2`, 원격 경로 표기와 UNC 거부, OpenSSH Server가 있어야 응답자가 됨), 보안 절(Job Object, 세션 이벤트 DACL). README Roadmap 표의 M20 행을 "Done"으로.
- §3 유예 가드레일 Windows 행을 "client M19·host M20 착지, 플랫폼 차이 없음"으로 고치는 일과 ROADMAP M10 결정 기록 Q1의 Windows leg 축 문장 대조는 main 세션이 마감 노트와 함께 한다.
- ROADMAP M20 마감 노트(main 세션). 이 `PLAN.md`의 마지막 커밋 해시를 적고 다음 계획 또는 placeholder로 교체한다(§8). §5.5 Windows 행에 재고정 해시와 M20이 만든 사람 몫(W2·W3b·W7)을 적는다.

**(b) 테스트·게이트:** 일곱 게이트, CI(acceptance 포함) 초록, 부하 반복 50/50 두 호스트.

**(c) 완료 판정:** §3의 DoD가 근거 커밋, run id와 함께 `[x]`다. `git diff --stat <Step 2 부모>..<마지막 구현 스텝 머지> -- crates/qsh-proto/proto crates/qsh-proto/src/local.rs crates/qsh-cli/tests/fixtures/cli-v1/capabilities.json`이 비어 있고, 같은 범위의 `crates/qsh-proto/src/wire.rs` diff가 Step 7의 `LOCAL_CAPABILITIES` 통합뿐이다.

## 5. 결정·핀 테스트 대응표

각 결정과 핀 테스트의 주인은 스텝 하나다. 한 결정이 여러 스텝에 걸치면 하위 항목으로 나눠 각각 주인 하나를 적는다. "M19 착지"는 M19가 이미 한 것이고 M20이 다시 하지 않는다.

### 5.1 ADR-0035 결정

| 결정 | 스텝 |
|---|---|
| 1 client 쪽 명령 집합, 서비스 명령, `setup listener --service` | M19 착지 |
| 1 host 쪽: `qsh serve`의 PTY 세션 | 3 |
| 1 host 쪽: `qsh serve --to`와 숨김 alias `qsh reverse`의 PTY 세션 | 3(게이트 제거는 M19 착지) |
| 1 host 쪽: `qsh setup host`(`--to` 포함), `qsh pair invite` | 8 |
| 1 host 쪽: `qsh pair ssh-respond` | 9 |
| 1 `qsh setup host --service` | 8 |
| 1 `qsh cp`의 host 쪽 | 7 |
| 2 UNSUPPORTED 경로 제거: `UnsupportedFactory` | 3 |
| 2 같은 항목: `ops/exec.rs` reverse 분기, `windows_unsupported()`, `SERVICE_UNSUPPORTED_PLATFORM`, `tui::run`, `NO_TERMINAL_ECHO_SUPPRESSION` | M19 착지 |
| 2 같은 항목: 파일 op의 `#[cfg(not(unix))]` 거부 | 7 |
| 2 같은 항목: `exec/mod.rs`의 비unix 환경 분기 | 5 |
| 3 매트릭스: `session open` Windows 행 제거 | 3 |
| 3 매트릭스: `session close --signal` 일곱 값 `cfg(windows)` 행 | 4 |
| 3 매트릭스: `cp` 두 행의 Windows 갈래 제거 | 7 |
| 3 매트릭스 확인 | 12 |
| 3 `cfg(unix)` 쌍둥이 전수 | 3·7(그 스텝 표면), 11(나머지) |
| 4~16 | M19 착지 |
| 17 host 테스트: PTY 종단 쌍둥이 | 2(순서·Job Object·resize), 3(나머지) |
| 17 host 테스트: 신호 일곱과 escalation | 4 |
| 17 host 테스트: `exec` 타임아웃 트리 종료 | 5 |
| 17 host 테스트: `acl.toml` DACL 경고의 구조적 필드 | 6 |
| 17 정방향·역방향 종단의 PTY 세션 케이스 | 3 |
| 17 같은 종단의 `cp` 케이스 | 7 |
| 17 같은 종단의 ConPTY 안 대화형 attach와 resume(실제 PTY host) | 11 |
| 17 `release_smoke` PTY 축 | 11 |
| 18 host 회차 추가와 재고정 | 10 |
| 19 threat-model PTY 행(ConPTY, Job Object) | 3 |
| 19 threat-model §3 세션 이벤트·보조 프로세스 | 4 |
| 19 threat-model §4 E `acl.toml` DACL 경고 | 6 |
| 19 threat-model §4 B·D Windows host 파일 op | 7 |
| 19 architecture §4 PTY 절 | 3(백엔드), 4(신호) |
| 19 architecture §6 audit 잠금·파일 guard 문장 | 6·7 |
| 19 CLI.md §6.7 | 3(`Hup`·`Term`·`Kill`), 4(나머지) |
| 19 CLI.md §7 host 범위·환경변수 | 3·4 |
| 19 CLI.md §6.21, capability 절 | 7 |
| 19 CLI.md §6.20, `pair invite` 문장 | 8 |
| 19 CLI.md §2.4·부트스트랩 절, protocol.md §17 | 9 |
| 19 testing.md L5·Windows leg 문단 | 3(L5), 11(종단), 12(대조) |
| 19 README Known limitations·Roadmap 표 | 8(방화벽), 9(응답자), 12(문단 재작성) |
| 19 모듈 doc(`pty/mod.rs`) | 3 |
| 20 ConPTY 생성·Job Object·pipe 배치·배수·resize | 2 |
| 20 `pty::factory()` 교체와 `UnsupportedFactory` 삭제 | 3 |
| 20 배치가 서지 않을 때의 ADR 개정 | 2(판정), main 세션(개정 이력 줄) |
| 21 환경·고정 키·셸·cwd·`user@` | 3 |
| 22 `Hup`·`Term`·`Kill` | 3 |
| 22 `Int`·`Quit`·`Usr1`·`Usr2`·종료 상태·환경변수 | 4 |
| 23 | 5 |
| 24 audit 잠금·재검증 | 6 |
| 24 `acl.toml` DACL 경고 | 6 |
| 24 결정 9 모듈이 만드는 host 상태 파일(audit, 회전, 잠금, reset key) | M19 착지(DACL), 6(잠금 파일 단언) |
| 25 `serve --to` 게이트 제거 | M19 착지 |
| 25 `serve --to`의 PTY | 3 |
| 25 `setup host`·`pair invite`·방화벽 안내 | 8 |
| 25 `pair ssh-respond` | 9 |
| 26 경로·정규화·재검증·mode·임시 파일·`SetFileTime` | 7 |
| 26 마지막 항목(client get의 로컬 쓰기) | M19 착지 |
| 27·28 | M19 착지(`setup host --service`의 호출은 8) |

### 5.2 ADR-0035 결과 절의 고정 테스트

| 항목 | 스텝 |
|---|---|
| `exit_code_matrix.rs`의 `session close --signal` 일곱 값 행 | 4 |
| 같은 파일에 Windows 전용 `UNSUPPORTED` 행 없음 | 3·7, 확인 12 |
| `pty/tests.rs` Windows 쌍둥이: spawn·입출력·resize·종료 코드·close | 2·3 |
| 같은 항목: Job Object가 손자까지 끝냄 | 2(Job 닫힘), 3(세션 close) |
| 같은 항목: 신호 일곱의 Windows 사건과 escalation, `Usr1`·`Usr2` 이벤트 DACL과 환경변수 고정 | 4 |
| 같은 항목: 고정 환경변수(대소문자 무시) 덮어쓰기 거부, `user@` 힌트 비교 | 3 |
| `exec` 타임아웃의 트리 종료와 환경 고정 | 5 |
| audit 회전 잠금·재검증과 `acl.toml` DACL 경고 | 6 |
| 정방향·역방향 종단의 `cp` | 7 |
| 같은 종단의 ConPTY 안 대화형 attach와 detach 뒤 resume | 11 |
| `release_smoke`의 `cfg(not(unix))` 쌍둥이 확장(PTY 축) | 11 |
| 계약: 새 세션 환경변수 둘(§7) | 4 |
| 계약: 숨김 `qsh internal console-ctrl`과 man 페이지 무변경 | 4 |

### 5.3 ADR-0029 Windows host 항목

| 항목 | 스텝 |
|---|---|
| 결정 5 상태 경로 항상 거부(Windows 경로 표기와 대소문자) | 7 |
| 결정 6 판정 절차, 5번 inode 대조의 Windows 수단 | 7(식별 함수는 6과 공유) |
| 결정 7 원자 교체, mode, umask의 Windows 대응 | 7 |
| 결정 8 host 처리 순서 | 7 |
| 결정 13 여유 공간 probe | 7 |
| 결정 23 Windows host 착지, `paths` 드라이브 표기 | 7(표기 문법은 M15 착지) |
| 결정 23 `file.v1` 광고 | 7 |
| `file_write_to_state_paths_is_denied_even_with_root_paths`·`file_read_of_state_paths_is_denied_even_with_root_paths`의 Windows 판 | 7 |

### 5.4 ADR-0044 Windows 응답자

| 항목 | 스텝 |
|---|---|
| 결정 10 Windows 응답자 등록과 순서 | 9 |
| 결정 14 `cmd.exe` 9009·PowerShell 1 사상 | M16 착지(client 쪽), 9(응답자 쪽 종단 확인) |
| 결정 25 Windows 원격(OpenSSH Server) | 9(가짜 ssh), 캠페인 W7(실제) |
| 자동 부트스트랩의 Windows 원격 뒤 원래 명령 | 9 |

### 5.5 다른 ADR이 M20으로 넘긴 항목

| 항목 | 스텝 |
|---|---|
| ADR-0031 결정 3 `trust_withdrawal.rs`의 `serve_to` Windows 쌍둥이 | M19 착지(당겨 옴, M19 plan §9 #3 (`d853388`)) |
| ADR-0003 SIGTERM drain의 Windows 대응 | 11 |
| ADR-0024 결정 2 `setup host` 역할 행의 Windows | 8 |

### 5.6 `cfg(unix)` 테스트 모듈 처분표 (origin `357fd58`)

모듈 전체가 `#![cfg(unix)]`인 테스트 파일이다. 파일 안의 개별 `#[cfg(unix)]` 테스트(같은 기준으로 `dynamic_forward.rs` 17, `fixtures.rs` 16, `jsonl_purity.rs` 15, `quota.rs` 12, `sessions_filter.rs` 9, `acl_check_path.rs` 8, `acl_check_equivalence.rs` 8, `exec_loopback.rs` 7, `ssh_bootstrap.rs` 6 등)는 Step 11이 같은 기준으로 하나씩 처분하고 결과를 커밋 본문에 표로 남긴다. "열기"는 `#![cfg(unix)]`를 걷거나 공유 본문으로 `cfg(windows)` 쌍둥이를 두는 것이고, "unix 고유"는 이유 주석과 Windows 수단 테스트 이름을 남기는 것이다. 처분은 초안이고 그 스텝이 확정한다.

| 모듈 | 빠진 이유(모듈 doc 기준) | 처분 | 스텝 |
|---|---|---|---|
| `qsh-cli` `attach_ops` | PTY host | 열기(Windows host PTY) | 11 |
| `qsh-cli` `attach_recovery` | PTY host, 경로 감시 | 열기 | 11 |
| `qsh-cli` `cp_e2e`, `cp_recursive`, `cp_cancel` | 파일 host, unix 권한 비트 | 열기(mode 단언은 합성 규칙으로 바꿈) | 7(왕복), 11(나머지) |
| `qsh-cli` `lifecycle_lines` | 정지 신호 | 열기 또는 unix 고유(정지 신호가 콘솔 사건이라 콘솔 없는 test 프로세스가 보낼 수 없으면 M19 `tunnel_supervise` 선례대로) | 11 |
| `qsh-cli` `localctl_perms` | UDS 권한 | unix 고유. Windows 수단은 M19의 `localctl::transport::windows` pipe DACL·SID 테스트 | 11(주석) |
| `qsh-cli` `reverse_blackout` | UDS, PTY | 열기(acceptance job은 Linux에 남고 Windows는 nextest 다리) | 11 |
| `qsh-cli` `reverse_e2e` | 양쪽 PTY | 열기. PTY 없는 케이스는 M19가 `windows_reverse_e2e`로 옮김 | 11 |
| `qsh-cli` `serve_sigterm_drain` | SIGTERM | unix 고유(POSIX 신호). Windows 수단은 Step 11의 drain 쌍둥이 | 11 |
| `qsh-cli` `session_follow` | PTY host, `sh` 스크립트 | 열기(`cmd.exe` 스크립트) | 11 |
| `qsh-cli` `session_kill9` | `expectrl`, SIGKILL | unix 고유. Windows 수단은 `windows_attach::killed_client_leaves_the_session_running_*` | 11 |
| `qsh-cli` `socks_curl` | 프로세스 정지, unix 권한 | 연다(§9 #7 결정): `curl.exe`(Windows 10 1803+ 기본 탑재), 스레드 정지, DACL 단언 | 11 |
| `qsh-cli` `trust_lifecycle_live` | 실제 `qsh serve` 정지 | 열기 | 11 |
| `qsh-cli` `tui_expect` | `expectrl` | unix 고유. Windows 수단은 `windows_attach::` | 11(주석) |
| `qsh-cli` `tunnel_e2e` | 대화형 form | 열기(ConPTY 하니스) 또는 `windows_*_e2e`로 덮였음을 주석으로 | 11 |
| `qsh-testkit` `cp_many_small_files`, `cp_scripted_host`, `file_copy_echo_under_load`, `file_host` | 파일 host | 열기(acceptance 예산 단언은 Linux job 유지) | 7(`file_host`), 11(나머지) |
| `qsh-testkit` `dynamic_reverse`, `host_list_reverse`, `local_control_reverse`, `local_stream_reverse`, `reverse_exec`, `reverse_tunnel` | "localctl (UDS) compiles out on Windows"(M19 뒤 낡은 이유) | 열기(named pipe localctl) | 11 |
| `qsh-testkit` `reverse_attach`, `reverse_session_ops`, `reverse_resume_chaos`, `reverse_chaos` | UDS, PTY | 열기 | 11 |
| `qsh-testkit` `reverse_lost_cause_and_since_registered_ms`, `reverse_unreachable_hook`, `liveness_config` | unix 재연결 루프 | 이유 재확인 뒤 열기 | 11 |
| `qsh-testkit` `supervised_dynamic_blackhole` | acceptance(50초) | 이유 재확인. acceptance job은 Linux | 11 |

M19 마감이 이 표의 일부를 이미 처분했으면 Step 1이 그 행을 지운다.

### 5.7 M20 유예 hit 대응표 (`rg -n "M20"`, origin `357fd58`, `04abb92`가 더한 hit 포함)

`PLAN.md`(M19 계획), `docs/ROADMAP.md`, ADR-0035의 hit는 위 §5.1~§5.5가 덮는다. 나머지는 다음과 같다.

| 위치 | 내용 | 귀속 |
|---|---|---|
| `README.md` Known limitations(Windows 문단) | host M20, 응답자 M20, `file.v1` 미광고, PTY `UNSUPPORTED` | 8·9(해당 문장), 12(문단 재작성) |
| `README.md` Roadmap 표 M20 행 | "Design record approved" | 1("In progress"), 12("Done") |
| `CLAUDE.md` Document map | "M11–M20 (P1)" | 귀속 불요(범위 기록) |
| `docs/PRD.md` P1 목록 | Windows host (M20) | 12(대조, 귀속 불요) |
| `docs/adr/README.md` ADR-0035 행 | 제목 | 귀속 불요 |
| `docs/adr/0029-file-copy.md` 결정 23 | Windows host 착지 배치 | 7 |
| `docs/adr/0031-cert-rotation-revocation.md` 결정 3 | `serve --to` 쌍둥이 M20 | M19 착지(개정 이력 줄 확인 12) |
| `docs/adr/0044-ssh-bootstrap.md` 결정 10·14·25와 ADR-0035 문단 | Windows 응답자 | 9 |
| `docs/CLI.md` 상태 헤더 v0.49 | Windows 서비스 착지 서술 | 귀속 불요(판별 기록) |
| `docs/CLI.md` §2.4 `pair ssh-respond` | Unix 빌드만 | 9 |
| `docs/CLI.md` §6.2 route 문단 | live 세션 필터 | 11 |
| `docs/CLI.md` §6 capability 절 `file.v1` | unix만 광고 | 7 |
| `docs/CLI.md` 부트스트랩 절(원격이 응답하지 못하는 경우) | Windows 원격 | 9 |
| `docs/CLI.md` reverse 절 Windows 문단 | Windows `serve --to`의 PTY·파일 | 3·7 |
| `docs/CLI.md` §6.21 Windows host 문단 | 파일 op M20 | 7 |
| `docs/CLI.md` 부트스트랩 터미널 순서 문단 | Windows 원격 | 9 |
| `docs/design/protocol.md` capability 절 | `file.v1` unix만 | 7 |
| `docs/design/protocol.md` §17 응답자 문단 | Unix 빌드만 | 9 |
| `docs/design/architecture.md` §4 `portable-pty` 문장 | Windows host(M20)로의 문 | 3 |
| `docs/design/architecture.md` 부트스트랩 문단 | Windows 응답자 | 9 |
| `docs/design/architecture.md` §6 파일 guard stub 문장 | `cfg(not(unix))` stub | 7 |
| `docs/design/testing.md` 가짜 ssh 문단 | Windows 응답자 | 9 |
| `docs/design/testing.md` Windows 정방향·역방향 종단 문단, client 기능 동등 문단 | PTY 없음(M20) | 11 |
| `docs/design/testing.md` 신뢰 철회 문단 | 플랫폼 문장 | 12(대조) |
| `docs/design/threat-model.md` §3 `pair ssh-respond` stdin 행 | Windows 응답자 | 9 |
| `docs/design/threat-model.md` D18 | Windows 파일 DACL | 12(대조, M19 착지) |
| `docs/campaigns/p1-windows.md` 상태 줄, §1 표, §4.12, §5 | M20 자리 | 10 |
| `crates/qsh-core/src/file/host.rs`, `file/guard.rs`(여섯 곳) | Windows is M20 | 7 |
| `crates/qsh-core/src/ssh_bootstrap/mod.rs`, `respond.rs` | Unix only until M20 | 9 |
| `crates/qsh-core/src/server/tests.rs` 파일 op `UNSUPPORTED` 테스트 | Windows 파일 op 거부 | 7(테스트를 Windows 성공 경로로 바꿈) |
| `crates/qsh-core/src/server/mod.rs` `lookup_login_name` 주석 | "(P2)" | 3 |
| `crates/qsh-proto/src/wire.rs`, `wire/tests.rs` | `file.v1` unix만 | 7 |
| `crates/qsh-cli/src/cli.rs` `SshRespond` doc | Unix builds only until M20 | 9 |
| `crates/qsh-cli/tests/it/acl_check_equivalence.rs` | PTY 없음 | 3 |
| `crates/qsh-cli/tests/it/reverse_e2e.rs` 모듈 doc | PTY 양쪽 | 11 |
| `crates/qsh-cli/tests/it/sessions_filter.rs` 모듈 doc·주석 | live 세션 M20 | 11 |
| `crates/qsh-cli/tests/it/auto_bootstrap.rs` | host M20 | 9 |
| `crates/qsh-cli/tests/it/fixtures.rs`(세 곳) | 파일 host unix만 | 7 |
| `crates/qsh-cli/tests/it/exit_code_matrix.rs` `session open` 주석 | Windows host PTY M20 | 3 |
| `crates/qsh-cli/tests/it/ssh_bootstrap.rs`(네 곳) | 응답자 M20 | 9 |
| `crates/qsh-cli/tests/it/windows_forward_e2e.rs`, `windows_reverse_e2e.rs` `cp_to_a_windows_host_is_unsupported_before_m20` | 미광고 단언 | 7 |
| `crates/qsh-core/src/acl/load.rs` `warn_if_group_or_world_writable` 주석(`04abb92`) | Windows DACL 경고 M20 | 6 |
| `crates/qsh-core/src/exec/mod.rs` 모듈 doc(`04abb92`) | host 환경 고정 없음 | 5 |
| `crates/qsh-core/src/serve.rs` `HostRuntime` doc(`04abb92`) | factory `UNSUPPORTED` | 3 |
| `crates/qsh-cli/tests/it/fixtures.rs` session 골든 경로(`04abb92`, 넷째 곳), `jsonl_purity.rs` session 출력 테스트, `session_follow.rs` 모듈(`04abb92`) | PTY 경로 unix만 | 11(§5.6 쌍둥이와 함께) |

## 6. 명시적 non-goals

- 사용자 전환과 utmp/wtmp 기록. unix에도 없으므로 같은 선이다(ROADMAP M20 명시적 out, ADR-0035 결정 21).
- `portable-pty`의 Windows 구현으로 ConPTY 백엔드를 만드는 것(결정 20 대안 기각). OpenSSH의 `DefaultShell` 레지스트리 값 읽기(기각). 신호 셋 전체를 `TerminateJobObject` 하나로 사상, `Int`를 ConPTY 입력 `0x03`으로, `Usr1`·`Usr2`를 콘솔 사건이나 입력 바이트로 사상(모두 기각).
- `session.signal` operation과 wire 번호 25 `SessionSignal`(ROADMAP §5.3). 신호는 `session close --signal`로만 간다.
- 세션 수명 거처 변경(M18, ADR-0034). M20의 Job Object `KILL_ON_JOB_CLOSE`는 host 프로세스가 죽으면 세션 트리도 끝나는 unix와 같은 수명이다.
- 새 `ErrorCode`, 새 wire 메시지, `.proto`·`local.rs` 변경, `capabilities.json` 변경, 새 fixture.
- 새 doctor finding code. 방화벽 안내는 기존 finding 문안이다(결정 25).
- `-L`의 non-loopback bind, UDP forwarding, relay, P2 전부(local echo prediction, read-only multi-attach, jump chaining, agent forwarding).
- reserved P2 플래그는 그대로 파싱되고 `UNSUPPORTED`를 낸다. M20은 그 경로를 건드리지 않는다(`CLAUDE.md` Session onboarding 4).
- 에이전트가 하는 `gh secret set`, `gh variable set`, `gh workflow run`, 태그 push, 저장소 설정 변경, 외부 저장소 쓰기, Dave-Windows의 관리자 권한 설정 변경.

## 7. 리스크와 감시 항목

- **ConPTY 산정 신뢰도(ROADMAP §5.4 리스크 5).** 결정 20의 pipe 배치가 가장 불확실하다. Step 2가 판정과 재산정을 하고, 읽기 스레드로 접으면 Step 3의 크기를 위쪽으로 다시 매긴다. host 쪽 상태(Step 6)와 `cp`(Step 7)는 PTY와 독립이라 일정 압박의 완충으로 쓴다.
- **ConPTY 출력 순서와 러너 차이.** `windows-latest`(Server 2022)와 Windows 11의 conhost가 초기 화면 재그리기(`\x1b[?25l` 등 VT 머리)를 다르게 낼 수 있다. 테스트는 바이트 흐름 전체가 아니라 표지 문자열의 도착과 exit 이벤트 순서로 단언한다.
- **`GenerateConsoleCtrlEvent`의 전역 상태.** 콘솔 붙이기가 프로세스 전역이라 보조 프로세스로 뺐다(결정 22). host 프로세스가 직접 `AttachConsole`을 부르는 코드가 생기면 다른 세션과 host 자신의 콘솔 처리기를 흔든다. `console_ctrl_is_the_only_attach_console_caller`(계획 추가, `qsh-core`·`qsh-cli` 소스에서 `AttachConsole` 호출이 보조 진입점 한 곳뿐) 같은 구조 테스트로 막는다(M19 `schtasks_is_spawned_only_by_the_default_runner` 선례).
- **unix 회귀.** 신호 경로, audit writer, 파일 guard를 플랫폼별로 나누며 unix 쪽을 만진다. acceptance job과 `pty::tests`, `cp_e2e::`, `audit_query::`를 각 PR의 필수 확인으로 둔다. echo 예산 단언이 흔들리면 그 PR은 착지하지 않는다.
- **`file.v1` 광고의 버전 차이.** Windows host가 `file.v1`을 광고하기 시작하면 M19 이전 client가 Windows host에 파일 op를 보낼 수 있다. 협상은 교집합이고 client는 이미 `file.v1`을 아는 버전만 파일 op를 보내므로 새 위험은 아니다. Windows 빌드는 M19 전에 host로 배포된 적이 없다는 점(ADR-0035 개정 이력 2026-10-16의 localctl 문장과 같은 논리)을 커밋 본문에 적는다.
- **파일 host의 Windows 의미 차이.** 대소문자 무시 파일시스템, 8.3 짧은 이름(`PROGRA~1`), 대체 데이터 스트림(`file.txt:stream`), 예약 장치 이름(`CON`, `NUL`)은 상태 경로 판정을 우회하는 통로가 될 수 있다. `GetFinalPathNameByHandleW`가 긴 이름으로 풀어 주는 것과, 경로 분류가 `:`를 드라이브 문자 자리 밖에서 거부하는지를 Step 7이 테스트로 고정한다(§7.1 #7). 남는 것은 threat-model §7 잔여 위험에 적는다.
- **Windows 다리의 시간.** PTY 종단과 쌍둥이 전수가 Windows test leg 시간을 늘린다. M19 plan §9 #9 (`d853388`)의 기준(Linux leg의 두 배)을 넘으면 main 세션이 Windows 종단을 별도 job으로 뗄지 정하고, 떼면 그 job도 merge 필수로 둔다.
- **OpenSSH Server가 없는 CI.** 러너에서 실제 Windows sshd를 상대하는 응답자 테스트는 두지 않는다. 가짜 ssh와 실제 응답자 바이너리로 덮고, 실제 sshd는 §1과 캠페인 W7이다.

### 7.1 구현 중 확정할 값 (해당 step (a)에 근거와 함께 추기)

| # | 질문 | 초안 | 확정 시점 |
|---|---|---|---|
| 1 | Job Object 생성 함수의 자리와 할당 방식 | `qsh-core`의 `cfg(windows)` 모듈 하나(가칭 `winproc.rs`)에 `JobObject::new_kill_on_close()`와 "Job 안에서 만든 자식" 생성 도우미. ConPTY와 `exec` 모두 `PROC_THREAD_ATTRIBUTE_JOB_LIST`. 러너에서 그 속성이 안 되면 `CREATE_SUSPENDED` → `AssignProcessToJobObject` → `ResumeThread`로 접고 그 사실을 ADR 개정 이력 초안에 적는다. `xtask arch`의 path-scoped 금지 대상이 아닌지 확인 | Step 2 |
| 2 | 고정 키 대조와 환경 합성의 순수 함수 | `env_policy`(가칭)에 플랫폼 표(`PINNED_POSIX`, `PINNED_WINDOWS`)와 대조 함수(Windows 표는 ASCII 대소문자 무시). unix 쪽은 기존 상수를 옮기기만 한다(동작 diff 0) | Step 3 |
| 3 | `user@` 힌트의 계정 이름 출처 | `GetUserNameExW(NameSamCompatible)`로 `DOMAIN\user`를, `GetUserNameW`로 `user`를 얻어 프로세스 수명 동안 캐시(unix `getpwuid_r` 캐시와 같음). 환경변수 `USERNAME`은 쓰지 않는다(architecture §4의 "`$USER`를 쓰지 않는다"와 같은 이유) | Step 3 |
| 4 | 종료 상태의 `signal` 귀속 규칙 | 세션마다 "qsh가 마지막으로 보낸 단계"를 기록하고, 자식 종료가 그 단계 이후에 관찰되면 그 단계의 신호 이름을 싣는다. 단계를 보내지 않은 자연 종료는 `signal` 없음. `Kill`은 항상 `KILL`. `CTRL_C` 뒤 `STATUS_CONTROL_C_EXIT`(0xC000013A)는 `exit_code`에 같은 비트로 남는다 | Step 4 |
| 5 | `qsh internal console-ctrl`의 실행 파일 위치 seam | 기본은 `current_exe()`. 테스트는 `QSH_CONSOLE_CTRL_BIN`(가칭, `qsh-console-probe`의 `QSH_CONSOLE_PROBE_BIN`과 같은 규칙)으로 빌드된 `qsh`를 가리킨다. 환경변수 seam이 운영 경로에서 쓰일 수 없게 테스트 빌드에서만 읽을지(`cfg(test)`가 통합 테스트에 닿지 않는 문제)는 `ManagerRunner`처럼 `Ops` 생성 시 주입하는 쪽을 먼저 본다 | Step 4 |
| 6 | `release_smoke` Windows의 대화형 detach·reattach 축 | unix 축은 `expectrl`이다. Windows는 `qsh-testkit` ConPTY 하니스로 같은 축을 둘 수 있으면 둔다. 릴리스 바이너리 스모크가 testkit 의존을 끌어오는 비용이 크면 headless PTY 축(open·write·read·close)에서 멈추고 대화형 축은 `windows_attach::`가 맡는다고 주석으로 적는다(ADR-0035 결정 17은 headless 축만 명시) | Step 11 |
| 7 | 원격 경로의 `:`와 예약 이름 | 드라이브 문자 자리(두 번째 문자) 밖의 `:`는 대체 데이터 스트림이므로 `INVALID_ARGUMENT`. 예약 장치 이름(`CON`, `PRN`, `AUX`, `NUL`, `COM1`~`9`, `LPT1`~`9`, 확장자 포함)은 `GetFinalPathNameByHandleW`가 실패하거나 장치로 열리므로 열기 단계에서 `INVALID_ARGUMENT`. 이 둘은 ADR-0035 결정 26 "경로" 항목의 UNC·장치 이름 공간 거부와 같은 이유(host가 장치에 대신 접근)라 같은 결정의 적용으로 보고, main 세션이 개정 이력 줄로 남길지 정한다 | Step 7 |
| 8 | `file/guard.rs`의 `xtask arch` 파일 단위 금지 | Windows 구현을 `file/guard.rs` 안의 `cfg(windows)` 블록으로 두면 금지가 그대로 덮는다. 형제 파일(`file/guard/windows.rs`)로 빼면 `xtask/src/arch.rs`의 `FILE_GUARD_FILE` 규칙을 같은 커밋에서 넓힌다(`CLAUDE.md` path-scoped 규칙). 1099줄이라 인라인 테스트는 이미 `guard/tests.rs`에 있다 | Step 7 |
| 9 | (볼륨 일련번호, 파일 인덱스) 식별 함수 | `fsutil` 하위 `file_identity`(가칭)에 `GetFileInformationByHandle`. ReFS의 128비트 파일 ID는 `GetFileInformationByHandleEx(FileIdInfo)`를 먼저 쓰고 실패하면 64비트로 내려간다. Step 6과 7 중 먼저 착지하는 쪽이 세운다 | Step 6·7 |
| 10 | `acl.toml` DACL 경고 레코드의 필드 | unix 경고의 구조적 필드(대상 `qsh::acl`, 경로 종류, 이유 코드)에 `sid`(문제 SID 문자열, 여럿이면 첫 번째와 개수). `mode`는 싣지 않는다. 계정 이름으로 풀지 않는다(SID 조회가 실패할 수 있고 경고는 fail-open 진단이다) | Step 6 |
| 11 | Windows 원자 교체 호출 | `SetFileInformationByHandle(FileRenameInfoEx, FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS)`를 먼저, 실패하면 `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`. 디렉터리 `fsync`의 대응은 없으므로 파일 `FlushFileBuffers` 뒤 `WRITE_THROUGH`로 대신하고, 이 차이를 architecture §6에 한 문장 적는다 | Step 7 |
| 12 | 방화벽 안내를 싣는 doctor finding | `qsh serve`·`listen`·`serve --to` 쪽 도달성 finding 가운데 기존 code(예: `controller_unreachable`이나 serve 바인드 관련 code)의 Windows 문안에 한 문장. 어느 code인지는 `EXPECTED_DOCTOR_CODES`와 §6.17 표에서 Step 8이 고른다. code 집합은 바뀌지 않는다 | Step 8 |
| 13 | Windows에서 건너뛰던 fixture 생산 테스트 | `fixtures.rs`의 파일 host 갈래가 Windows에서 같은 golden을 내는지 본다. 경로 문자열이 든 golden(예: `paths` 표기)이 OS마다 다르면 그 golden은 unix 생산으로 두고 Windows는 구조만 대조한다(M19 `capabilities.json` 처리와 같은 꼴). fixture는 고치지 않는다 | Step 7 |
| 14 | M20 부하 filterset | 모듈 접두 `conpty_`·`pty::`의 Windows 쌍둥이, `windows_forward_e2e::`, `windows_reverse_e2e::`, `windows_attach::pty_`, 신호 수신·escalation, audit 잠금 경합, `cp_round_trip`, drain. `m19.filter`와 같은 `(?:\w+::)?` 꼴 | Step 2·12 |

## 8. 완료 절차

1. §3 DoD 전건을 실제 테스트와 CI run으로 확인한다. 체크박스는 근거가 초록일 때만 채운다.
2. 부하 반복 50/50을 두 호스트에서 기록한다(Step 2~11, 12).
3. 구속 문서 태그를 대조하고 §5.6·§5.7 표의 모든 행을 확인한다(Step 12 (a)).
4. README를 동기화한다.
5. `docs/ROADMAP.md` "현재 위치"와 M20 절을 갱신하고 마감 노트를 적는다(main 세션). §3 Windows 행과 §5.5 Windows 행을 고친다. ADR-0035 결과 절 "남는 플랫폼 차이는 없다"가 실제로 성립함을 마감 노트에 한 줄로 적는다.
6. §0.1~§0.4의 상태를 승계한다.
7. 이 `PLAN.md`를 교체하고, 마감 노트에 이 계획의 마지막 커밋 해시를 적는다. M20은 P1 순서상 마지막 마일스톤이다. 그때 M18의 착수 조건(M8 DoD 3)이 닫혀 있으면 M18 계획으로, 아니면 "열린 마일스톤 없음" placeholder로 바꾼다. placeholder의 §0이 P0 사람 회차 일곱과 §5.5의 P1 사람 몫을 승계하고, ROADMAP 현재 위치는 "P1의 에이전트 몫은 M18을 빼고 착지했다. M18은 M8 DoD 3이 기록되면 연다. P1 완료 선언은 §5.5가 닫힐 때"를 적는다. `CLAUDE.md` Session onboarding 1·2의 placeholder 문장이 이 상태를 이미 덮는지 main 세션이 확인한다.

## 9. 열린 질문

각 항목의 권고는 main 세션이 Step 1 커밋에서 결정으로 확정했다(2026-10-18). 1~6·8·9는 권고대로, 7은 권고를 바꿔 쌍둥이를 필수로 두었다(아래 #7 결정). 2026-10-14 사용자 위임 결정("전부 다 알아서 진행해")의 범위다. #1과 #3은 Step 1 커밋이 ROADMAP M20 DoD에 반영했다(#3은 `session close --signal` 일곱 값 행을 괄호 아닌 문장으로 더함).

1. **ROADMAP M20 DoD에 안정성 줄.** M12·M15·M16·M17·M19에는 있고 M20에는 없다. **권고:** "M20이 더한 타이밍 민감 테스트는 Linux와 Windows 각각에서 부하 아래 50회 연속 초록(`scripts/stress/run.sh`, `scripts/stress/m20.filter`)"을 더한다. 새 지연 예산 단언이 없으므로 `-j 1` 대체 문장은 넣지 않는다.
2. **`file.v1` 광고와 wire 소유 규율.** M19까지의 완료 판정은 `crates/qsh-proto/src/wire.rs` diff 0을 요구했다. Windows host가 `file.v1`을 광고하려면 `LOCAL_CAPABILITIES`의 cfg 갈래를 합쳐야 하고 그것이 `wire.rs`에 있다. capability 문자열·협상 규칙·`.proto`는 바뀌지 않고, ADR-0029 결정 23이 이 착지를 이미 정했으며, `capabilities.json` golden은 unix 빌드의 집합이라 그대로다. **권고:** 새 ADR 없이 Step 7이 이 diff 하나를 소유하고, 완료 판정의 wire 확인을 "`.proto`·`local.rs`·`capabilities.json` diff 0, `wire.rs`는 `LOCAL_CAPABILITIES` 통합뿐"으로 바꾼다(§4 규율 "wire 소유"). `docs/design/protocol.md` §16.1 목록이 capability 광고 집합의 변경을 따로 적고 있으면 같은 커밋에서 그 목록도 고친다.
3. **ROADMAP M20 DoD의 매트릭스 문장.** DoD는 "Windows 전용 `UNSUPPORTED` 행이 하나도 없다"만 적고, ADR-0035 결정 3이 요구하는 `cfg(windows)` `session close --signal` 일곱 값 행은 DoD 첫 줄의 "신호 일곱의 사상"에 묻혀 있다. **권고:** ROADMAP는 고치지 않고 이 계획의 DoD 4가 두 조건(Windows 전용 `UNSUPPORTED` 0, `--signal` 일곱 값 행)을 함께 체크한다. ROADMAP 문장에 "`session close --signal` 일곱 값 행"을 괄호로 더하는 것은 main 세션 재량이다.
4. **inode 대조의 Windows 수단과 ADR-0035 결정 26.** ADR-0029 결정 6 5번(연 파일의 `(dev, ino)`가 보호 파일과 같으면 거부, hard link 우회 차단)은 결정 23이 "같은 성질을 낸다"고 묶었지만 ADR-0035 결정 26의 Windows 수단 목록에 이름이 없다. 결정 24가 audit 재검증에 쓰는 (볼륨 일련번호, 파일 인덱스)가 같은 성질을 낸다. **권고:** 결정을 바꾸는 것이 아니라 결정 23·26의 적용이므로 새 ADR 없이 Step 7이 그 식별 쌍을 쓰고, main 세션이 ADR-0035 개정 이력에 "결정 26의 재검증에 ADR-0029 결정 6 5번의 inode 대조가 결정 24의 (볼륨 일련번호, 파일 인덱스)로 들어간다"는 한 줄을 더한다. §7.1 #7의 대체 데이터 스트림·예약 이름 거부도 같은 줄에 묶을 수 있다.
5. **M19의 `echo_host` attach 케이스.** M19의 `windows_attach::`는 Windows host PTY가 없어 testkit `echo_host`를 상대로 돌았다(M19 plan §7.1 #4 (`d853388`)). 이제 실제 PTY host가 있다. **권고:** `echo_host` 케이스는 남긴다. 그것은 host 쪽 셸과 무관하게 client·콘솔·wire·데몬·broker의 detach와 resume을 고정하고, `crates/qsh-cli/tests/it/echo_host.rs`가 같은 하니스를 unix에서도 건다. Step 11은 실제 PTY host 케이스를 같은 모듈에 더하고 `pty_` 접두로 구분한다. ADR-0035 결정 17의 "test-only 하니스 없음"은 역방향 CI 종단의 양쪽이 실제 CLI라는 뜻이고 실제 PTY 케이스가 그것을 지킨다.
6. **`cfg(unix)` 쌍둥이 전수의 범위.** §5.6 표의 testkit 모듈 상당수는 PTY가 아니라 "localctl (UDS)"를 이유로 빠져 있고, 그 이유는 M19가 named pipe localctl을 착지시키며 사라졌다. 이것은 M19 몫이 남은 것인지 M20 몫인지 경계가 흐리다. **권고:** M19 마감에서 처분되지 않은 것은 M20 Step 11이 받는다. ADR-0035 결정 3은 마일스톤을 가르지 않고 "이 마일스톤(ADR-0035의 두 마일스톤)에서 쌍둥이를 갖는다"고 적었고, M20이 마지막이므로 여기서 닫지 않으면 귀속처가 없다. 크기는 Step 11의 상한 쪽으로 본다.
7. **`socks_curl`의 Windows 쌍둥이.** acceptance job의 `socks_curl`은 실제 `curl`을 쓴다. Windows 10 1803부터 `curl.exe`가 기본 탑재되지만 테스트가 기대는 프로세스 정지와 unix 권한 단언이 있다. **권고:** acceptance job은 Linux에 그대로 두고, Windows nextest 다리에서 `curl.exe`로 같은 SOCKS 왕복을 보는 쌍둥이를 둘 수 있으면 둔다. 프로세스 정지가 콘솔 사건이라 콘솔 없는 test 프로세스가 보낼 수 없으면 M19 `tunnel_supervise`의 처분(unix 고유, 이유 주석)을 따른다. 어느 쪽이든 M19의 `dynamic_forward_connect` 두 route가 SOCKS 기능 동등을 이미 고정한다. **결정 (2026-10-18):** 권고를 바꿔 쌍둥이를 필수로 둔다(2026-10-13 사용자 결정 "모든 플랫폼에서 평등한 기능", "원칙에 예외는 없다"). Windows nextest 다리에서 `curl.exe --socks5-hostname`으로 같은 왕복과 거부(host-local 필터, ACL) 케이스를 돈다. 프로세스 정지는 콘솔 사건이 아니라 스레드 정지(대상 프로세스 스레드 전부의 `SuspendThread`/`ResumeThread`)로 내고, unix 권한 단언은 소유자 전용 DACL 단언으로 바꾼다. 같은 성질을 Windows 수단으로 낼 수 없는 단언이 남으면 그 단언만 이유 주석과 함께 unix 고유로 두고 Step 11 (d)에 적는다.
8. **M20 뒤의 `PLAN.md`.** M20이 P1 순서상 마지막이고 M18은 사람 회차를 기다린다. **권고:** §8 7대로 placeholder로 바꾼다. placeholder의 제목은 "PLAN.md — 열린 마일스톤 없음"이고 §0에 P0 일곱, §5.5 P1 사람 몫, M18 착수 조건을 적는다. M8 DoD 3이 그 전에 기록되면 M20 마감 직후 M18 계획으로 바꾼다.
9. **태그.** M20 DoD에는 태그가 필요 없다. 캠페인 W2·W3b·W7은 M20 착지가 담긴 Windows 자산 태그를 요구한다. **권고:** Step 11 직후 태그 하나를 권한다. 서명 시크릿(§0.3)이 없으면 서명 없는 태그를 찍을지는 유지보수자가 정한다. W2·W3b·W7은 서명과 무관하므로 서명 없는 태그로도 돌 수 있고, W11만 서명된 태그를 요구한다.
