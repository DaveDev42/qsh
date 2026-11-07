# PLAN.md — M23: 로컬 에코 예측과 연결 상태 줄

M22(화면 상태 동기화와 적응 전송)는 2026-11-07 닫혔다. 직전 M22 계획의 마지막 커밋은 `1a07d99`다. M23의 범위는 ADR-0050의 M23 행(M22 화면 모델 위의 mosh식 예측, 확인 전 글자 밑줄, echo-off·전체 화면 앱·연속 오예측에서 끔, 응답이 끊기면 "마지막 응답 N초 전" 줄)이고, 첫 스텝인 범위 ADR이 승인되기 전에는 계약·wire 스텝을 열지 않는다(ROADMAP §6.1 원칙 2·4).

이 파일과 `docs/ROADMAP.md`의 편집은 main 세션만 한다.

## 0. 열린 사람 몫

여기 적힌 항목은 이 파일이 다음 계획으로 바뀔 때 그대로 승계한다.

회차의 대상 태그는 `v0.5.0`이다(2026-10-20, 태그 커밋 `1c653e0`, release run 39354944687 초록, 자산 9개와 `SHA256SUMS`). M15~M20 착지와 Windows 자산이 모두 담겨 있어 `p1-windows`·`p1-ssh-bootstrap`·`p1-setup-stopwatch`·`p1-supervise-wake`와 P0 회차가 이 태그에서 돈다. 첫 태그 push(`02d4c32`)는 musl 빌드가 `libc::time_t` deprecation 경고로 실패해 아무것도 게시되지 않았고, `1c653e0`이 고친 뒤 같은 이름으로 다시 찍었다. 패치 태그 `v0.5.1`(2026-10-22, 태그 커밋 `b4639a8`, release run 39723802624 초록)이 ADR-0046 `79e6d6f`, admission `14d802b`, `cargo install --git` 커밋 `314bbbd`, webpki `698b4bc`를 더했다. Windows host 회차(W2·W3b·W7)와 Windows `qsh listen` 회차(W3a)는 이 태그에서 돈다. 다른 회차는 `v0.5.0`에서 돌아도 된다. 패치 태그 `v0.5.2`(2026-10-24, 태그 커밋 `4240767`, release run 40103741549 초록)는 ctutils `6c7d986`, tokio `2bb68d0`, macOS `status --live` `6f565b6`을 더했다. 바뀐 경로가 Windows에 닿지 않아(tokio 변경은 unix의 `AsyncFd` 두 곳) 회차 대상 태그는 그대로다. 세 태그의 wire와 계약은 같다.

### 0.1 P0에서 열린 일곱

M20 계획 §0.1의 일곱 항목을 문면 그대로 승계한다. M8 DoD 3은 M18의 착수 조건이고, 이것이 닫히면 M18을 연다.

- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** `docs/campaigns/m10-clean-vm.md`. macOS arm64는 2026-11-05 `v0.5.8`에서 회차 6(수동 다운로드)·7(brew) 모두 PASS다(tart VM, Dave-MBP16). macOS x86_64 회차가 남았고 실제 Intel Mac이 필요하다(§2.2). 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 같은 문서. arm64는 회차 6에서 PASS다. `spctl -t execute`의 "does not seem to be an app" 거부는 §4.2대로 그 회차에서 판정 방식을 정했다. x86_64 회차(Intel Mac)가 남았다. 소유: 사람.
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** 캠페인 §9 판정과 함께 닫힌다. 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** `docs/campaigns/m7-stopwatch.md`. 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** `docs/campaigns/m2-mobility.md`. M18의 착수 조건. 소유: 사람.
- [x] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** 2026-11-05 ADR-0049(사용자 결정)로 리뷰는 하지 않기로 하고 마감 조건에서 뺐다. wire freeze(`docs/design/protocol.md` §16)는 같은 커밋에서 발효했다.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 소유: 사람.

### 0.2 P1 마일스톤이 만든 사람 몫 (`docs/ROADMAP.md` §5.5)

M20 계획 §0.2의 다섯 항목을 승계한다.

- [x] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 출처 M11. 2026-10-23 배치 3에서 72h, crash 0(`docs/campaigns/m8-fuzz.md` §5 배치 3).
- [ ] **`p1-supervise-wake` 회차 넷.** 출처 M12. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 출처 M12(ADR-0024 결정 12). 소유: 사람.
- [x] **`decode_file_frame`·`parse_ssh_bootstrap_line` fuzz 타깃의 누적 72 fuzz-hours.** 출처 M15·M16. 공개 beta 전(`docs/design/protocol.md` §13). 에이전트가 Dave-Windows-WSL에서 `parse_openssh_key`와 함께 돌렸다(run-id `m8-fuzz-20261020-0931`, 커밋 `60e54fa`). 2026-10-23 09:35+09:00 세 타깃 모두 259201초, `exit=0`, crash·artifact 0이다(`docs/campaigns/m8-fuzz.md` §5 배치 3).
- [x] **실제 OpenSSH 위의 SSH 부트스트랩 회차.** `docs/campaigns/p1-ssh-bootstrap.md`(사전 고정 `e8cd7a3`). Windows 원격이 응답자가 되는 회차는 이 문서가 아니라 `p1-windows.md` W7이 맡는다. 2026-10-30 에이전트가 `v0.5.6`에서 R1~R5를 돌려 모두 PASS이고 캠페인이 PASS다(캠페인 §7). R1~R4는 Dave-Windows-WSL 위 docker 컨테이너 셋(§2.2가 허용하는 별도 netns와 `sshd`), R5는 Dave-Windows client와 WSL 위 컨테이너다. 처음 돈 R1·R4는 하네스가 B의 host key를 미리 넣지 않아 클린을 깨서 무효로 적었고 같은 날 다시 돌았다. passphrase와 host key 응답은 에이전트가 expect로 입력했고, 두 물리 장비 사이의 네트워크는 이 회차들이 보지 않았다. 컨테이너를 장비로 센 것, expect 입력, R5·W12의 원격 serve UDP 4436은 2026-11-01 Dave가 받아들였다.

### 0.3 M19가 만든 사람 몫

- [ ] **Windows client 확인 회차.** `docs/campaigns/p1-windows.md`(M19 사전 고정 `ad409e0`)의 W1, W3a, W4, W5, W6, W8, W9, W10, W11, W12. Windows 자산이 붙은 태그에서 돈다. 2026-10-21 에이전트가 `v0.5.0`에서 단일 장비 회차를 돌렸다(캠페인 §7, `87e3c1d`). `v0.5.0`의 W8은 a~c PASS, d 미실행으로 보류였다. W11b는 PASS다. W11c는 `cargo install --git` 빌드가 커밋을 내지 않아 c1 FAIL이었고 `314bbbd`가 고쳤다. 2026-10-22 `v0.5.1`에서 다시 돌려 PASS다(캠페인 §7 셋째 W11c 행). W11a(Edge 다운로드와 SmartScreen 창)는 사람이 한다. W8은 2026-10-23 `v0.5.1`에서 a~d 모두 PASS다(캠페인 §7 셋째 W8 행). 재부팅 뒤 Credential Manager 항목이 남아 `key_store`가 `platform`이고 fingerprint가 같았다. c 뒤 doctor에 `bindv6only_blocks_ipv4`가 없어 ADR-0046을 실제 Windows에서 확인했다. 2026-10-26 `v0.5.5`에서 W3a를 L(WSL2)·M(Dave-MacMini) 동시로 돌렸다. a·c·d·e는 둘 다 PASS이고 b가 둘 다 FAIL이다. raw 모드 입력이 코드 페이지 65001의 `ReadFile`이라 이모지(서로게이트 쌍)가 U+FFFD로 바뀌었다(캠페인 §7 W3a v0.5.5 행). 같은 날 `v0.5.6`(`184fce2`, 이모지 입력과 pty 없는 Windows ssh 세션의 `pair ssh` 정지를 고침)에서 b를 다시 돌려 L·M 모두 PASS다. 이로써 W3a는 PASS다(캠페인 §7 W3a v0.5.6 행). W5는 `v0.5.5`에서 임시 표준 계정으로 a~e 모두 PASS다(캠페인 §7 W5 행). 회차가 끝나고 W·L·M의 회차 구성은 모두 지웠다. hive가 로드된 채 남았던 Dave-Windows의 고아 프로필 `C:\Users\qshtest2`·`C:\Users\qshtest5`는 2026-10-29 09:00 재부팅 뒤 지웠다(캠페인 §7 W3a v0.5.6 기록). W12는 2026-10-30 `v0.5.6`에서 a~f 모두 PASS다(캠페인 §7 W12 행, 원격은 WSL 위 컨테이너, serve는 UDP 4436). 2026-11-02 W6이 `v0.5.7`에서 PASS다(client는 MacMini, 로그온은 자동 로그온, 캠페인 §7). 2026-11-02 W10 변형 A(`--key-store file`)가 `v0.5.7`에서 PASS다(캠페인 §7). 변형 B(`platform`)는 2026-11-03 Dave가 암호를 입력해 `v0.5.7`에서 a~d 모두 PASS다(캠페인 §7). `Password` 주체 작업이 Credential Manager의 개인키를 읽어 ADR-0035 결정 12의 가정이 실측으로 성립했고, W10은 두 변형 모두 PASS다. 2026-11-03 W1 네 변형과 W11a가 `v0.5.7`에서 PASS다(에이전트가 Dave의 데스크톱에서 키 입력과 화면 캡처로 돌림, 캠페인 §7). W1에서 재부착 때 터미널 질의 응답이 원격 입력으로 새는 결함을 관측했다(판정 밖, 캠페인 §7 W1 관측). 이 결함은 ADR-0048(승인됨, `369ab4e`)로 고쳐 `v0.5.8`(Release run 41584853176 초록, 자산 9개와 SHA256SUMS, 첫 macos-15 `aarch64-apple-darwin` 빌드, homebrew-tap 초록)에 실었고, 같은 날 `v0.5.8`에서 conhost와 Windows Terminal 재부착이 깨끗함을 확인했다(캠페인 §7 W1 관측 재확인). 남은 Windows client 회차는 W4(Windows 노트북 필요)와 W9(Windows on ARM 필요, Dave가 포기)다. 소유: 사람.
- [x] **Windows 배포 준비.** 2026-10-19 사용자 결정으로 Authenticode 서명과 scoop·winget을 모두 철회해 사람이 준비할 것이 없다(ADR-0035 개정 이력 2026-10-19 두 줄). Windows 설치 경로는 release zip, `install.ps1`, `cargo install --locked --git https://github.com/DaveDev42/qsh qsh-cli`다.

### 0.4 M20이 만든 사람 몫

- [x] **Windows host 확인 회차.** `docs/campaigns/p1-windows.md`의 W2, W3b, W7(M20 재고정 `048df57`, ADR-0035 결정 18). W2는 Linux·macOS client가 Windows host(`qsh serve`)에 붙어 `cmd.exe`·PowerShell·Windows 빌드 `vim` 전체 화면, 한글 입출력, resize, `Ctrl-C`, 방화벽 첫 허용 프롬프트를 본다. W3b는 Linux·macOS `qsh listen` ← Windows `qsh serve --to`의 attach·`cp`·터널이다. W7은 `qsh pair ssh`와 `--reverse`가 Windows OpenSSH Server를 상대로 pin을 세우는 것이다. M20 착지가 담긴 Windows 자산 태그에서 돈다. 2026-10-24 `v0.5.2` 에이전트 회차(Dave-Windows ↔ Dave-MacMini, 사용자가 MacMini controller를 허용): W3b M은 PASS다. W3b L은 이 집의 Linux가 Windows와 같은 박스의 WSL뿐이라 §2.2의 다른 장비 조건을 채우지 못했는데, 2026-10-26 사용자 승인으로 §2.2에 WSL2 예외(배포판 자신의 주소로 dial, 물리 경로는 M 변형 몫)를 더하고 `v0.5.3`에서 Dave-Windows-WSL을 controller로 돌려 a~e 모두 PASS다(W3b 끝, 캠페인 §7 W3b L 행). 그 회차 d의 `tunnel close` 뒤 `--supervise` 없는 holder가 끝나면서 tokio `JoinHandle polled after completion` panic을 stderr에 냈다(판정 밖, 프로세스는 끝남). `c8b04ea`가 고쳤고 다음 태그에 담긴다. W7 A는 d가 FAIL이다. 실제 `cmd.exe`에서 없는 명령의 종료 코드가 9009가 아니라 1이었고 `b525e2c`가 고쳤고, 2026-10-25 `v0.5.3` 재회차에서 d가 `remote_qsh_missing`(`remote_exit` 1)으로 PASS, b·c도 PASS다. 같은 날 사용자가 WR의 방화벽 허용 프롬프트를 눌러 A·B를 a~f 모두 다시 돌렸고 둘 다 PASS다(W7 끝, 캠페인 §7 W7 A 셋째 행·W7 B 둘째 행). W2는 2026-10-26 `v0.5.4` L 회차가 a(doctor remedy 문안)와 f(USR1 종료 상태)에서 FAIL이었고, `32f5b69`·`b61ac8c`(ADR-0047)를 담은 `v0.5.5`에서 WH를 §2.3 클린으로 되돌려 처음부터 다시 돌아 L·M 모두 a~f PASS다(캠페인 §7 W2 L·M `v0.5.5` 행). Windows Server 참고 행은 장비가 없어 비워 둔다. W7 B는 b·c·d가 PASS이고 a·e·f는 WR의 `qsh serve`로 들어오는 UDP 4433에 방화벽 허용이 필요해 보류다. W3b d에서 본 reverse `-R` holder의 무한 재시도도 `b525e2c`가 고쳤다. 기록은 `docs/campaigns/p1-windows.md` §7(`085e07e`). 기본 `[::]:4433` bind의 Windows host와 Windows `qsh listen`이 IPv4 peer를 받지 못하던 결함을 `79e6d6f`(ADR-0046)가 고쳤다. 그래서 W2·W3a·W3b·W7은 이 커밋이 담긴 `v0.5.1`에서 돈다. `v0.5.0`에서 IPv4 경로로 돌면 실패할 수 있다. P1 완료 선언을 막는다(ROADMAP §5.1 원칙 6, §5.5). 소유: 사람.

에이전트는 `gh secret set`, `gh variable set`, `gh workflow run`, 태그 push, 저장소 설정 변경, 외부 저장소 쓰기를 하지 않는다. Dave-Windows에서 방화벽 규칙을 더하는 일도 사람 몫이다. Dave-Windows의 OpenSSH Server는 2026-10-21 이미 켜져 돌고 있다(`sshd` Running, Automatic).

### 0.5 M21이 만든 사람 몫

- [ ] **`--always-on` 레시피 실행 회차.** ADR-0051 결정 15의 4. 테스트는 세 OS에서 `service install --always-on`이 `docs/deploy/service.md` 레시피와 같은 바이트를 내는 것까지만 고정한다. linger·LaunchDaemon·Windows `Password` 작업을 실제로 켜고 로그아웃 뒤 serve가 남는지를 사람이 한 번 기록한다. 소유: 사람.
- [ ] **Windows 원격 설치 대본 실장비 실행.** ADR-0051 결정 3. Windows 원격용 PowerShell 설치·스트림 대본은 문자열 테스트로만 고정돼 있다. qsh가 없는 Windows host(OpenSSH Server)에 `qsh --install-remote <host>`를 한 번 돌려 (가)·(나) 경로를 기록한다. 소유: 사람.

## 1. 유지보수에서 남은 확인

자리표시자 계획 §1에서 열린 채로 넘어온 항목이다.

- [ ] 공유 runner 위 `adversarial_load` 시나리오 2 RSS의 경계 근접. `6d4fa37`의 load run 39569439731에서 `connection_flood_past_the_cap_leaves_the_listener_rss_and_fd_bounded`가 peak 30972 KiB로 30720 KiB 상한(`docs/campaigns/m8-adversarial-load.md` §3, PRD §13 idle 30MB)을 넘었고, 재실행은 peak 28704 KiB로 초록이었다. 최근 열두 run의 peak는 22.9~29.8 MiB이고, baseline이 18 MiB대와 24 MiB대 두 무리로 갈린다. 이 run의 변경(dual-stack bind, admission 키 정규화, `build.rs`)은 메모리 경로에 닿지 않는다. 상한은 PRD 수치라 낮추거나 늘리지 않는다. 붉음이 잦아지면 baseline이 갈리는 원인(runner 종류, allocator arena)부터 가른다. 같은 날 야간 perf(run 39571078325)의 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`도 p95 10.525ms로 붉었다. perf-judge 추세 판정은 GREEN(median 대비 109.2%)이었다. 아래 항목의 관찰에 더한다. 2026-10-23 load run 50회를 다시 보면 붉음은 1회다. baseline은 runner 이미지와 맞물린다(20261018 이미지 약 18 MiB, 20261012 이미지 약 24 MiB). peak와 baseline의 차는 3~7 MiB로 일정해, 늘어나는 것은 출발점이지 flood가 더하는 양이 아니다. 시나리오 1의 idle-after도 28.3~29.5 MiB로 상한 가까이 있다. 2026-10-25 `061bec3`(버전만 올린 커밋)의 load run 40169900486 첫 시도에서 같은 시나리오가 baseline 26196 KiB, peak 32312 KiB로 다시 붉었고(차 6.1 MiB, idle-after 28896 KiB, fd는 13 그대로), 같은 20261012 runner 이미지에서 돈 실패 job 재실행은 초록이었다. 같은 커밋의 release 빌드를 WSL에서 8회 돌리면 baseline 18.1~18.6 MiB, peak 23.3~24.1 MiB다. 50여 회 중 붉음 2회이고 둘 다 24 MiB대 무리다. 2026-10-26에는 메모리 경로에 닿지 않는 두 커밋에서 연달아 붉었다. `32f5b69`(doctor 문안, load run 40287496702)가 peak 30772 KiB, `ce30697`(문서만, load run 40289657907)이 peak 33972 KiB였고, 뒤의 것은 실패 job 재실행이 초록이었다. 다음 커밋 `2973986`의 load run도 초록이었다. `0381cbb`(문서만)의 load run 40321653844에서는 시나리오 1(`spoofed_initial_flood_leaves_the_listener_rss_and_fd_bounded`)이 baseline 28744 KiB, idle-after 32612 KiB로 30720 KiB를 넘었고 실패 job 재실행은 초록이었다. 시나리오 1의 붉음은 처음이다. 열어 둔다.
- [ ] 공유 runner 위 PTY echo p95 게이트의 경계 근접. 10-18 야간 perf의 `tunnel_echo_under_load`가 p95 10.959ms, 같은 날 acceptance의 `file_copy_echo_under_load`가 10.176ms로 10ms를 넘었고, 최근 야간 값이 9.6ms대에 자주 머문다. 기준은 `docs/design/protocol.md` §12의 수용 기준이라 낮추지 않는다. 붉음이 잦아지면 원인(runner 편차인지 회귀인지)을 perf 추세로 가르고, 재시도나 측정 방식 변경은 `docs/design/testing.md` CI 규율에 결정을 적은 뒤에 한다. 2026-10-23 야간 20회 중 붉음은 2회(10-18 10.96ms, 10-21 10.53ms)이고 CI acceptance에서 1회(10-18 10.176ms)다. runner가 측정 RTT로 두 무리로 갈리며, 느린 무리(RTT 0.31~0.50ms)의 p95가 7.2~11ms다. perf-judge는 median 대비 150%에서만 붉어서 게이트 경계의 넘침을 잡지 못한다. 붉음이 5회 중 1회 꼴에 이르면 testing.md에 결정을 적는다. 10-26 야간 perf(`2973986`, run 40296752973)도 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`가 p95 10.114ms로 붉었다(max 32.756ms, rounds 3260). 10-21 뒤 처음이다.

M22가 남긴 후속이다(ADR-0052 개정 이력, M22 계획 `1a07d99`).

- [ ] `FILE_DATA`는 bulk 예산을 내지만 16 KiB 알갱이로 쪼개지 않는다. 얕은 큐에서 `qsh cp`가 터널만큼 에코를 지키는지 `bulk_yield`에 cp 시나리오를 더해 확인한다.
- [ ] 결정 12 (e)의 줄인 keep-alive 간격을 host별로 기억하지 않는다. 지금은 attach 단위다.
- [ ] client가 로컬 fg/bg 색을 알리지 않아 host 에뮬레이터가 OSC 10/11에 답하지 않는다.
- [ ] 결정 18의 11 처리량 비율이 로컬 0.61~0.64배로 하한 0.5배에 가깝다. 야간 perf의 `screen_cat_ratio`가 붉어지면 같은 task 직렬 경로(ADR-0052 개정 이력)부터 본다.
- [ ] 중첩 바깥 운반체(결정 12 (f))의 netbench q6은 run 편차가 커서 M26 전에 반복 측정한다.
- [ ] 흔들리는 테스트. 2026-11-07 셋을 고쳤다: `the_send_depth_gate_defers_updates_while_the_client_does_not_read`(개수 단언 제거, `2e8cc42`), `quit_is_ctrl_break_not_ctrl_c`(probe의 파일·콘솔 쓰기 순서, `bdf2300`), `concurrent_saves_to_the_same_path_never_corrupt_the_file`(Windows rename 재시도, `e1f3d0d`, 원인 미재현). 여러 에이전트가 Dave-Windows를 함께 쓰는 부하에서 전체 run이 다른 시간 의존 시험으로 흔들린다: `attach_recovery::a_repath_is_survived_by_the_live_attach`, `sessions_filter::sessions_filter_does_not_change_the_wire_request`, `ssh_revival::a_changed_port_updates_the_pin`, `ssh_revival::a_command_revives_the_serve_after_it_idled_out`, `supervised_reverse::supervised_with_wait_still_caps_the_initial_wait_to_stale_retention`, `reverse_resume_chaos::a_severed_reverse_path_resumes_the_same_session_under_a_live_cli_attach`, `chaos_relay::reorder_lets_the_successor_arrive_first`. CI에서 붉어지면 하나씩 가른다.

M20이 더했던 ConPTY 배치 실측 셋(ADR-0035 결정 20)은 `d538468`·`bd4b272`, 신호 사건 실측 둘(결정 22)은 `a475f08`이 닫았다.

## 2. 테스트 환경

- CI의 `windows-latest` leg은 clippy, `cargo nextest run --workspace`, `cargo doc -D warnings`를 돌고, Windows host의 PTY·`exec`·파일 op·응답자를 정방향과 역방향으로 덮는다. 로컬 Windows 검사는 Dave-Windows(`ssh dave-windows.tail91e9e.ts.net`)에서 하고 CI를 대신하지 않는다.
- 부하 반복은 Linux·공통 테스트를 Dave-Windows-WSL(8 vCPU)에서, Windows 전용 타이밍 민감 테스트를 Dave-Windows에서 `scripts/stress/run.sh`로 돈다. 마일스톤별 필터는 `scripts/stress/m<N>.filter`다.

## 3. M23 스텝

- [x] **범위 ADR(ADR-0053).** 2026-11-07 승인(Dave 결정, 네 항목 모두 추천대로: `predict` 기본 `auto`, 상태 줄 맨 윗줄, 한글 예측, 옛 host는 예측 끔). 수용 기준은 ADR-0053의 마지막 결정(DoD 열세 항목)이다.
- [x] **`Predictor`와 표 테스트, proptest.** 2026-11-07 착지(`015d8e4`, 표 테스트 26개와 proptest 512 case). 256 상한은 동시에 판정을 기다리는 예측 수로 읽었다. 커서 위치를 모르는 동안(Enter·제어 키·오예측 뒤, 그 offset을 덮는 리포트가 올 때까지)은 새 예측을 만들지 않는다. 빈 셀과 공백을 같은 글자로 보되 공백·Backspace·좌우 같은 약한 증거는 epoch 확정에 넣지 않아 암호 입력에서 가짜 확인이 생기지 않는다. `qsh-core/src/client/predict.rs`, 시계 없는 상태 기계, epoch 규칙, 예측 대상·끄는 조건, 연속 오예측 3회 정지·확인 4회 재개, 상한 256. wire 없이 가짜 `ScreenEcho`로 "모든 예측이 정리되면 로컬 화면 = host 화면" proptest.
- [ ] **렌더러 합성과 로컬 터미널 모델 시험.** `ScreenRenderer`가 host 화면 위에 예측 겹을 그리고, 철회는 바뀐 셀만 다시 그린다(화면 지우기 없음). 밑줄 규칙(ADR-0052 결정 12 손잡이, 250 ms 늦은 확인).
- [ ] **`screen-echo.v1`과 `ScreenEcho`, host 입력 시각 표, tty 판정, fuzz.** `SessionFrame` 10, `DatagramFrame` 13, `ECHO_GRACE` 50 ms, Unix `tcgetattr`(KERNEL/APP/SECRET), Windows `UNKNOWN`, `capabilities.json` 재생성, protocol §18, fuzz 타깃.
- [ ] **attach driver 연결과 정책 값, 늦은 확인.** 입력 송신 지점에서 예측, `ScreenEcho`로 확인·철회, 역방향 route의 RTT 표본(`InputAck` 간격).
- [ ] **`LinkStatus`와 상태 줄, 역방향.** `PathWatch`+복구 루프, `max(2 s, 4×srtt)`, 맨 윗줄 반전, 1초 갱신, 첫 인증 응답에서 지움.
- [ ] **플래그·설정 키·doctor·`qsh::predict`.** `--predict=auto|always|never`, `[interactive].predict`, `--status-line=on|off`, `[interactive].status_line`, info 코드 `screen_echo_unsupported`, man.
- [ ] **수용 시험.** chaos(RTT 300 ms 예측 표시 p95 ≤ 20 ms 등), 암호 입력 비표시, 세 OS, Windows host(cmd.exe/pwsh).
- [ ] **문서와 마감.** `docs/CLI.md`·man·README, threat model 행과 고정 테스트, ROADMAP M23 마감 노트.
