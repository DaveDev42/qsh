# PLAN.md — M25: agent forwarding

M24(홀펀칭)는 2026-11-09 닫혔다. 직전 M24 계획의 마지막 커밋은 `569e859`다. M25의 범위와 수용 기준은 ADR-0055(2026-11-09 승인, 크기 2.5ew)다. 수용 기준은 결정 23의 열네 항목이고, 그보다 더 만들지 않는다.

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

### 0.6 M23이 만든 사람 몫

- [x] **ADR-0053 결정 7의 커서 숨김 차단을 좁힌 것의 확인.** 2026-11-07 Dave가 받아들였다(ADR-0053 개정 이력). 수용 시험에서 Windows pwsh(PSReadLine)가 키마다 커서를 숨겼다 보여 예측이 꺼졌다. 코드는 적용된 상태 둘이 연달아 커서를 숨길 때만 차단한다(`HIDDEN_CURSOR_STATES = 2`, `3da871a`). 결정 본문은 고치지 않고 ADR-0053 개정 이력에만 적었다. Dave가 받아들이면 개정 이력에 승인을 적고, 받아들이지 않으면 pwsh에서 예측이 꺼지는 것을 감수하고 되돌린다. 소유: Dave.
- [ ] **vt100 upstream 보고.** `vt100` 0.18.1의 `Screen::text_cleanup`이 U+FE0F가 앞 셀을 넓힐 때 `unwrap()`에서 panic한다(재현: `Parser::new(2, 1, 0).process("0\u{fe0f}".as_bytes())`). qsh는 host 입구에서 막았다(`d548c10`). 외부 저장소 쓰기라 사람 몫이다. 소유: Dave.

### 0.7 M24가 만든 사람 몫

- [ ] **실제 망 펀칭 회차.** `docs/campaigns/m24-punch.md`. 휴대폰 테더링의 CGNAT, 집 공유기, 회사 망, IPv6 전용 망에서 A–B 쌍을 기록한다. DoD 밖이다.
- [ ] **`punch-netns`를 필수 검사로 올릴지.** 저장소 설정이라 사람 몫이다. 지금은 `ci-ok`의 `needs`에 없다.

### 0.8 M25가 만든 사람 몫

- [ ] **ADR-0055 DoD 23.5의 첫 연결 시간 확인.** 경로가 끊긴 뒤 첫 로컬 agent 연결은 probe 대기(`clamp(4×RTT, 300 ms, 2 s)`) 안에 닫히고 100 ms 기준은 둘째 연결부터 맞는다(ADR-0055 개정 이력). 받아들일지 Dave가 정한다.

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

M23이 남긴 후속이다(ADR-0053 개정 이력, M23 계획 `d50f003`).

- [ ] host 출력 pump가 에뮬레이터 panic으로 죽으면 그 세션의 출력이 알림 없이 멎는다(client는 오류를 받지 않는다). 알려진 trigger는 `d548c10`이 막았고, `catch_unwind`로 에뮬레이터를 다시 세우는 backstop은 두지 않았다.
- [ ] `Vs16Filter` 탓에 U+FE0F가 필요한 이모지(하트·키캡)가 host 화면 모델에서 한 칸을 차지한다.
- [ ] 서로 다른 task(입력 pump, reader, recovery ticker)의 화면 바이트를 직렬화하지 않는다. 수용 시험에서는 어긋나지 않았다.
- [ ] 역방향 attach는 watchdog이 없어 입력이 있어야 상태 줄 시계가 돈다. 완전히 쉬는 역방향 attach는 conduit이 끊길 때까지 줄을 띄우지 않는다.
- [ ] client가 자기 principal을 몰라 첫 `writer_changed`로 배운다. 같은 principal의 둘째 attach와 첫 알림으로 온 steal을 구분하지 못한다(효과는 철회되는 예측 하나 또는 보류된 예측).
- [ ] 느린 예측 수용 셋(`predict_accept::`)은 ubuntu acceptance job에서만 돈다. macOS는 test job의 unix 셋만 돈다.
- [ ] Windows pwsh에서 키 서른 개 중 하나가 105~142 ms를 쓸 때가 있다(p95는 2.0 ms).

M24가 남긴 후속이다(ADR-0054 개정 이력, M24 계획 `569e859`).

- [ ] 펀칭한 `exec`는 채택된 연결의 closing drain도 200 ms에서 끊는다. 마지막 CONNECTION_CLOSE가 잃히면 host는 idle timeout에서야 끝을 안다. 진 후보만 따로 닫는 방법(다른 endpoint 또는 quinn의 연결별 drain 상태)은 transport 재설계가 필요해 미뤘다.
- [ ] derived 후보(결정 23 (d))는 IPv4만 만든다. IPv6에서 중개자가 B와 같은 방화벽 뒤인 장면은 시험이 없다.
- [ ] 커널 대조는 masquerade(port-restricted)와 fully-random(symmetric)만 덮는다. full cone·restricted는 conntrack에 그대로 대응하는 것이 없어 netsim에서만 본다.
- [ ] 역방향 등록 자체의 펀칭과 일반 `qsh serve`·on-demand serve의 펀칭은 ADR-0054에서 미뤘다.
- [ ] 흔들림: `trust_withdrawal::listen::listen_closes_a_withdrawn_peer_that_stopped_reading_the_control_stream`이 전체 실행 한 번과 CI run 42573815011에서 8초 안에 닫힘을 보지 못했다. `1acd3d6`이 고정 2.5초 sleep 대신 host가 막혔다는 보고(`peer_stream_blocked_events`)를 기다리고 flood를 60000건으로 줄여 양보하게 했다(제품 코드는 응답 스트림을 기다리지 않는다). 원래 실패는 로컬에서 재현되지 않아 원인은 가설이다. 부하 아래 30/30. 짝인 `serve_closes_a_withdrawn_peer…`는 아직 고정 1.5초 sleep이다. 같은 부하에서 `chaos_relay::reorder_lets_the_successor_arrive_first`가 전체 여섯 번 중 두 번 실패했다.

M20이 더했던 ConPTY 배치 실측 셋(ADR-0035 결정 20)은 `d538468`·`bd4b272`, 신호 사건 실측 둘(결정 22)은 `a475f08`이 닫았다.

## 2. 테스트 환경

- CI의 `windows-latest` leg은 clippy, `cargo nextest run --workspace`, `cargo doc -D warnings`를 돌고, Windows host의 PTY·`exec`·파일 op·응답자를 정방향과 역방향으로 덮는다. 로컬 Windows 검사는 Dave-Windows(`ssh dave-windows.tail91e9e.ts.net`)에서 하고 CI를 대신하지 않는다.
- Dave-Windows에 SSH로 들어가 돌리는 전체 실행에서는 일곱 시험이 늘 실패한다: `cp_cancel::` 넷과 `auto_bootstrap::console::ctrl_c_during_the_bootstrap_ends_canceled_on_windows`(비대화 세션에 콘솔 Ctrl-C가 없다), `identity::keystore::tests::credential_manager_` 둘(SSH 로그온에는 Credential Manager가 없다). CI `windows-latest`에서는 통과한다. 로컬 Windows 판정은 이 일곱을 빼고 한다.
- 부하 반복은 Linux·공통 테스트를 Dave-Windows-WSL(8 vCPU)에서, Windows 전용 타이밍 민감 테스트를 Dave-Windows에서 `scripts/stress/run.sh`로 돈다. 마일스톤별 필터는 `scripts/stress/m<N>.filter`다.

## 3. M25 스텝

각 스텝은 PR 하나 크기다. 스텝마다 그 스텝의 시험과 일곱 게이트가 초록이어야 닫힌다. 순서는 위에서 아래다.

- [x] **범위 ADR(ADR-0055).** 2026-11-09 승인(Dave 결정, 다섯 항목 모두 추천 (가)).
- [x] **전제 확인 둘.** 2026-11-09 둘 다 성립(ADR-0055 개정 이력). Win32-OpenSSH 9.5p2의 `ssh-add`·`ssh`·`ssh-keygen -Y sign`이 사용자 지정 named pipe(소유자 전용 DACL, `PIPE_REJECT_REMOTE_CLIENTS`, `FIRST_PIPE_INSTANCE`)를 쓴다. `ssh-agent.exe`는 `-a`를 무시하고 서비스가 꺼져 있으면 기본 pipe가 없다. OpenSSH 9.6p1 `ssh-agent`는 `session-bind` 없는 연결에서 목적지 제한 키의 서명을 `FAILURE`로 거부하고 목록에는 보인다. Windows CI 시험의 가짜 agent는 P/Invoke `CreateNamedPipeW` 서버로 대신할 수 있다.
- [x] **가짜 agent와 `qsh_proto::agent`.** 2026-11-09 착지(`4e1e488`, protocol §20, fuzz 타깃 `agent_frames`(27종), WSL 전체 4087개, Dave-Windows agent 시험 18개). `AgentDecoder`는 길이와 종류만 읽고 길이 0과 256 KiB 초과를 오류로 굳힌다. `ALLOWED_REQUESTS = [11, 13]`, `FAILURE_REPLY`. `qsh_testkit::FakeAgent`는 unix 소켓과 Windows named pipe로 듣고 받은 종류를 모두 기록한다. Windows client는 다음 pipe instance가 서기 전의 `ERROR_PIPE_BUSY`(231)를 짧게 재시도한다. 이 재시도는 client 스텝의 진짜 로컬 agent 연결에도 필요하다. 시험 `agent_filter_table`, decoder 수준의 `an_oversized_agent_frame_resets_the_stream`.
- [x] **`agent.v1` wire.** 2026-11-09 착지(`b509380`, `docs/CLI.md` v0.90, protocol §4·§7·§9·§16·§20.0, WSL 전체 4107개, Dave-Windows 전체 4111/4118). `CAP_AGENT_V1`, `StreamKind::AGENT = 6`, `agent_channel`(SessionOpen 9·SessionAttach 7·ExecStart 6), `AgentGrant`(SessionOpened 7·SessionAttached 9·ExecStarted 3; UNSPECIFIED·FORWARDED·DENIED·UNAVAILABLE·NO_SOCKET). 광고하지 않은 peer 앞에서 client는 필드를 비우고, host는 길이 검사 뒤 아직 `UNAVAILABLE`로 답하며 세션과 exec는 그대로 연다. `capabilities.json`에 `agent.v1` 하나가 더해졌다. 시험 `no_agent_field_without_dash_a`(골든 바이트)와 `agent_wire` 넷. Dave-Windows의 일곱 실패(`cp_cancel` 넷, `credential_manager_` 둘, `ctrl_c_during_the_bootstrap_ends_canceled_on_windows`)는 손대지 않은 main에서도 SSH 세션이라 같게 실패한다(콘솔 Ctrl-C와 Credential Manager가 비대화 세션에 없다). recovery의 재attach는 아직 `agent_channel`을 싣지 않는다.
- [x] **`forward.agent`와 감사.** 2026-11-09 착지(`a13b68d`, `docs/CLI.md` v0.91, PRD §9 어휘 13종, ADR-0045 개정 이력, threat model B46·D24·E25·G12). `check_agent`가 소켓 생성 전에 choke point와 감사를 거친다. 거부는 `DENIED`, 감사 실패는 `UNAVAILABLE`이고 둘 다 소켓 없이 세션과 exec는 연다. role 없는 pin과 `tunnel`·`read-only`·`reverse`·`none`이 각각 시험된다. fixture `acl.show.forward_agent.json`·`acl.show.with_role_agent.json`·`setup.run.host_complete_with_role_agent.json`.
- [x] **host 쪽(unix).** runtime `agent/`(0700)의 0600 소켓, peer uid 검사, 긴 경로의 `mkdtemp` 대체, `SSH_AUTH_SOCK` 고정 키, 세션·exec 끝의 정리와 시작 때 죽은 소켓 쓸기(결정 6·8). 시험: `agent_socket_is_removed_when_the_session_ends`, `stale_agent_sockets_are_swept_at_start`. 1차 2026-11-09(`18b255f`): 독립 모듈 `qsh_core::agent`의 `AgentListener`(unix 0700 `agent/`의 0600 소켓, 긴 경로의 `/tmp` mkdtemp 대체, localctl의 peer uid 검사, 소켓당 16 상한과 `StreamBudget`, drop 때 제거, 5초보다 오래된 죽은 소켓만 지우는 `sweep_stale`)와 Windows의 localctl `PipeListener` 재사용(소유자 전용 DACL, `FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`). WSL 전체 4099개, Dave-Windows agent·localctl 99개. 배선 `a13b68d`: 세션·exec마다 소켓과 `AGENT` 스트림 브리지(연결당 64), `SSH_AUTH_SOCK`을 `PINNED_POSIX`·`PINNED_WINDOWS`에 넣고 agent가 없으면 client 값도 지운다, 종료·close·TTL·exec 끝의 제거와 serve 시작의 sweep. 시험 `agent_host`(python3로 `$SSH_AUTH_SOCK`에 목록 조회).
- [x] **client 쪽과 플래그.** 2026-11-09 착지(`d47599c`, `docs/CLI.md` v0.92, man 넷 재생성). 로컬 agent 탐색(unix `SSH_AUTH_SOCK`, Windows는 그 pipe 또는 `\\.\pipe\openssh-ssh-agent`, `ERROR_PIPE_BUSY` 재시도), 연결당 dispatcher(등록 안 된 channel reset, 11·13만 로컬 agent로, 나머지는 client가 `FAILURE`, 길이 0·상한 초과 reset, 연결당 64), `-A`·`-a`·`-o ForwardAgent`·`agent.forward`의 우선순위(`forward_agent_precedence_table`), doctor `agent_unreachable`·`agent_dir_unusable`, fixture `doctor_agent_unreachable.json`·`session.open.agent.json`·`exec.run.agent_denied.json`. `qsh cp -A`는 다른 scp 플래그처럼 종료 2다(ADR-0055 개정 이력). 진짜 host와 잇는 `agent_forward_loopback_lists_and_signs`는 아직 없다. WSL 전체 4148개, Dave-Windows 4133개(SSH 세션 일곱 제외).
- [x] **받치는 연결과 `attach -A`.** 2026-11-09 착지(`40d7968`, WSL 전체 4164개, Dave-Windows 4142개). 진짜 `Ops`와 host를 잇는 `agent_forward` 다섯: `agent_forward_loopback_lists_and_signs`(받은 종류가 정확히 11·13, remove-all은 client가 막음), `agent_forward_over_a_punched_connection`, `agent_backing_follows_the_writer_attach`, 절단 뒤 resume, `a_healthy_path_adds_no_round_trip_to_an_agent_request`. 조용히 죽은 경로의 backing 연결에 로컬 연결이 매달리던 결함을 실제 스트림과 동시에 도는 probe로 고쳤다(ADR-0055 개정 이력). 끊긴 뒤 첫 로컬 연결은 `probe_wait`(loopback 300 ms) 안에, 둘째부터 100 ms 안에 닫힌다. 이 차이는 §0.8의 Dave 확인 항목이다.
- [x] **역방향 route.** 2026-11-09 착지(`bd7fb6e`, protocol §20.2.1, threat model B47, Dave-Windows 4142개). `ControlHub`가 요청이 나가는 순간 `agent_channel`을 그 conduit에 묶고, 등록된 16바이트 channel의 `AGENT` 스트림만 hub당 32 상한 안에서 큐에 넣는다. CLI는 `LOCAL_STREAM`으로 channel과 claim token을 내밀고 처음 claim한 토큰이 seat에 앉는다. 데몬은 바이트만 옮긴다. 역방향 attach·exec·재attach가 같은 channel을 싣는다. hub당 등록 channel 256 상한을 더했다(ADR에 없는 방어 상한). 남은 위험: 같은 uid 프로세스가 주인보다 먼저 channel 값을 알아 claim하면 seat을 차지할 수 있다(B47 잔여 위험).
- [x] **Windows host와 client.** 2026-11-09 착지(`a6f99b9`, Dave-Windows 전체 4148개). `windows_client_reaches_an_agent_on_a_named_pipe`, `windows_agent_pipe_is_owner_only_and_rejects_remote_clients`(DACL은 `GetSecurityInfo`로 읽고 원격 거부는 생성 파라미터로 고정), `windows_host_pipe_serves_win32_openssh_ssh_add`(Windows CI 러너에서 ssh-agent 서비스를 켜고 Win32-OpenSSH `ssh-add -l`이 host pipe를 읽는다).
- [ ] **수용 시험.** 1차 `a6f99b9`: 진짜 agent 시험 `ssh_add_and_ssh_keygen_sign_through_a_forwarded_real_agent`(목록·서명 통과, `-D`·키 추가·`-d` 거부, 로컬 키 목록 불변; test 잡 네 레그에 `QSH_REQUIRE_SSH_AGENT=1`), `a_host_without_agent_v1_gets_no_agent_field`, `n_with_a_forwards_no_agent_and_says_so`. 남은 것: DoD 10의 세 OS(`agent_forward`·`agent_host`·`agent_reverse`의 안쪽이 `cfg(unix)`라 Windows에서 돌지 않는다), 결정 22가 이름 댄 시험 중 없는 셋(`agent_socket_is_owner_only`, `session_bind_is_refused_so_constrained_keys_stay_unbound`, `agent_audit_and_logs_carry_no_payload`), CI 확인.
- [ ] **문서와 마감.** man, README, `docs/CLI.md` §7.2의 `ssh-add -c` 권고, threat model 결정 22의 행, ROADMAP M25 마감 노트.
