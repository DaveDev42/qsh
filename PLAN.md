# PLAN.md — 자리표시자: 열린 마일스톤 없음

M26(jump chaining)이 2026-11-11 닫혀 P2(ADR-0050)의 마일스톤 여섯이 모두 끝났다. 직전 M26 계획의 마지막 커밋은 `4f60cf7`다. 다음 마일스톤은 아직 없고, 여는 것은 사용자 결정이다. 그때까지 이 파일의 live state는 §0의 사람 몫과 §1의 유지보수 확인이다.

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

- [x] **ADR-0055 DoD 23.5의 첫 연결 시간 확인.** 2026-11-09 Dave가 받아들였다(ADR-0055 개정 이력). 경로가 끊긴 뒤 첫 로컬 agent 연결은 probe 대기 안에 닫히고 100 ms 기준은 둘째 연결부터 맞는다.

## 1. 유지보수에서 남은 확인

자리표시자 계획 §1에서 열린 채로 넘어온 항목이다.

- [ ] 공유 runner 위 `adversarial_load` 시나리오 2 RSS의 경계 근접. `6d4fa37`의 load run 39569439731에서 `connection_flood_past_the_cap_leaves_the_listener_rss_and_fd_bounded`가 peak 30972 KiB로 30720 KiB 상한(`docs/campaigns/m8-adversarial-load.md` §3, PRD §13 idle 30MB)을 넘었고, 재실행은 peak 28704 KiB로 초록이었다. 최근 열두 run의 peak는 22.9~29.8 MiB이고, baseline이 18 MiB대와 24 MiB대 두 무리로 갈린다. 이 run의 변경(dual-stack bind, admission 키 정규화, `build.rs`)은 메모리 경로에 닿지 않는다. 상한은 PRD 수치라 낮추거나 늘리지 않는다. 붉음이 잦아지면 baseline이 갈리는 원인(runner 종류, allocator arena)부터 가른다. 같은 날 야간 perf(run 39571078325)의 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`도 p95 10.525ms로 붉었다. perf-judge 추세 판정은 GREEN(median 대비 109.2%)이었다. 아래 항목의 관찰에 더한다. 2026-10-23 load run 50회를 다시 보면 붉음은 1회다. baseline은 runner 이미지와 맞물린다(20261018 이미지 약 18 MiB, 20261012 이미지 약 24 MiB). peak와 baseline의 차는 3~7 MiB로 일정해, 늘어나는 것은 출발점이지 flood가 더하는 양이 아니다. 시나리오 1의 idle-after도 28.3~29.5 MiB로 상한 가까이 있다. 2026-10-25 `061bec3`(버전만 올린 커밋)의 load run 40169900486 첫 시도에서 같은 시나리오가 baseline 26196 KiB, peak 32312 KiB로 다시 붉었고(차 6.1 MiB, idle-after 28896 KiB, fd는 13 그대로), 같은 20261012 runner 이미지에서 돈 실패 job 재실행은 초록이었다. 같은 커밋의 release 빌드를 WSL에서 8회 돌리면 baseline 18.1~18.6 MiB, peak 23.3~24.1 MiB다. 50여 회 중 붉음 2회이고 둘 다 24 MiB대 무리다. 2026-10-26에는 메모리 경로에 닿지 않는 두 커밋에서 연달아 붉었다. `32f5b69`(doctor 문안, load run 40287496702)가 peak 30772 KiB, `ce30697`(문서만, load run 40289657907)이 peak 33972 KiB였고, 뒤의 것은 실패 job 재실행이 초록이었다. 다음 커밋 `2973986`의 load run도 초록이었다. `0381cbb`(문서만)의 load run 40321653844에서는 시나리오 1(`spoofed_initial_flood_leaves_the_listener_rss_and_fd_bounded`)이 baseline 28744 KiB, idle-after 32612 KiB로 30720 KiB를 넘었고 실패 job 재실행은 초록이었다. 시나리오 1의 붉음은 처음이다. 열어 둔다.
- [ ] 공유 runner 위 PTY echo p95 게이트의 경계 근접. 10-18 야간 perf의 `tunnel_echo_under_load`가 p95 10.959ms, 같은 날 acceptance의 `file_copy_echo_under_load`가 10.176ms로 10ms를 넘었고, 최근 야간 값이 9.6ms대에 자주 머문다. 기준은 `docs/design/protocol.md` §12의 수용 기준이라 낮추지 않는다. 붉음이 잦아지면 원인(runner 편차인지 회귀인지)을 perf 추세로 가르고, 재시도나 측정 방식 변경은 `docs/design/testing.md` CI 규율에 결정을 적은 뒤에 한다. 2026-10-23 야간 20회 중 붉음은 2회(10-18 10.96ms, 10-21 10.53ms)이고 CI acceptance에서 1회(10-18 10.176ms)다. runner가 측정 RTT로 두 무리로 갈리며, 느린 무리(RTT 0.31~0.50ms)의 p95가 7.2~11ms다. perf-judge는 median 대비 150%에서만 붉어서 게이트 경계의 넘침을 잡지 못한다. 붉음이 5회 중 1회 꼴에 이르면 testing.md에 결정을 적는다. 10-26 야간 perf(`2973986`, run 40296752973)도 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`가 p95 10.114ms로 붉었다(max 32.756ms, rounds 3260). 10-21 뒤 처음이다.

M22가 남긴 후속이다(ADR-0052 개정 이력, M22 계획 `1a07d99`).

- [x] `FILE_DATA`는 bulk 예산을 내지만 16 KiB 알갱이로 쪼개지 않는다. 얕은 큐에서 `qsh cp`가 터널만큼 에코를 지키는지 `bulk_yield`에 cp 시나리오를 더해 확인한다. 2026-11-11 `bulk_yield::bulk_yields_to_echo_on_a_shallow_queue_under_file_copy`로 확인했다. 얕은 큐에서 cp 부하의 echo p95는 68~72 ms(기준 min_rtt+50 ≈ 101 ms)로 터널(70 ms)과 같아 알갱이 변경은 필요 없다.
- [x] 결정 12 (e)의 줄인 keep-alive 간격을 host별로 기억하지 않는다. 지금은 attach 단위다. 2026-11-11 결정 본문의 "프로세스가 host별로 기억한다"대로 `adapt::KeepAliveMemory`(프로세스 안, peer별, 최대 256, 줄이기만 하고 사용자 고정값 제외)가 다음 attach를 그 값으로 시작한다(`keep_alive_policy::a_shortened_interval_is_remembered_for_the_next_attach_of_the_same_peer`). host가 다시 뜨면 잊는다.
- [ ] client가 로컬 fg/bg 색을 알리지 않아 host 에뮬레이터가 OSC 10/11에 답하지 않는다.
- [ ] 결정 18의 11 처리량 비율이 로컬 0.61~0.64배로 하한 0.5배에 가깝다. 야간 perf의 `screen_cat_ratio`가 붉어지면 같은 task 직렬 경로(ADR-0052 개정 이력)부터 본다. 2026-11-11 프로파일을 시도했으나 load average 100 넘는 부하에서 한 번(끔 24 MiB/s, 켬 12, 0.497)만 재서 쓸 수 없었다. 조용한 host에서 PTY 시험과 in-process `screen_throughput`을 다섯 번씩 돌린 뒤 `perf record`로 parse 경로를 본다.
- [ ] 중첩 바깥 운반체(결정 12 (f))의 netbench q6. 2026-11-11 네 변형을 열 번씩 돌렸다(Dave-Windows-WSL, 부하가 커서 절댓값은 거칠다). 직접 bulk 2.25 MB/s·echo p99 782 ms, 바깥 스트림 1.77 MB/s·p99 1563 ms(echo 유실 0, 편차 가장 작음), 바깥 datagram 0.36 MB/s(0.03~1.19)이고 열 번 모두 echo 360개 중 146~360개가 돌아오지 않았다(64 KiB 버퍼도 같음). netbench는 결정 12 (f)의 "바깥 datagram이 안쪽 p99를 반으로 줄인다"를 뒷받침하지 않는다. 다만 이 하네스의 중첩 datagram은 qsh jump 코드가 없는 합성 운반체이고, 실제 jump 채널(ADR-0056)은 `jump_perf`·`jump_loss`가 초록이다. (f)를 Datagram으로 둘지 Stream으로 바꿀지는 Dave 결정이다(ADR 개정). 원자료는 남기지 않았고 `scripts/netbench/run.sh`로 다시 만든다. 소유: Dave.
- [ ] 흔들리는 테스트. 2026-11-07 셋을 고쳤다: `the_send_depth_gate_defers_updates_while_the_client_does_not_read`(개수 단언 제거, `2e8cc42`), `quit_is_ctrl_break_not_ctrl_c`(probe의 파일·콘솔 쓰기 순서, `bdf2300`), `concurrent_saves_to_the_same_path_never_corrupt_the_file`(Windows rename 재시도, `e1f3d0d`, 원인 미재현). 여러 에이전트가 Dave-Windows를 함께 쓰는 부하에서 전체 run이 다른 시간 의존 시험으로 흔들린다: `attach_recovery::a_repath_is_survived_by_the_live_attach`, `sessions_filter::sessions_filter_does_not_change_the_wire_request`, `ssh_revival::a_changed_port_updates_the_pin`, `ssh_revival::a_command_revives_the_serve_after_it_idled_out`, `supervised_reverse::supervised_with_wait_still_caps_the_initial_wait_to_stale_retention`, `reverse_resume_chaos::a_severed_reverse_path_resumes_the_same_session_under_a_live_cli_attach`, `chaos_relay::reorder_lets_the_successor_arrive_first`. CI에서 붉어지면 하나씩 가른다.

M23이 남긴 후속이다(ADR-0053 개정 이력, M23 계획 `d50f003`).

- [x] host 출력 pump가 에뮬레이터 panic으로 죽으면 그 세션의 출력이 알림 없이 멎는다(client는 오류를 받지 않는다). 알려진 trigger는 `d548c10`이 막았고, `catch_unwind`로 에뮬레이터를 다시 세우는 backstop은 두지 않았다. 2026-11-11 `HostScreen::feed`가 슬라이스마다 `catch_unwind`로 감싸 panic하면 그 슬라이스를 버리고 빈 에뮬레이터로 다시 세워 모든 client에 전체 화면을 보낸다(`an_emulator_panic_rebuilds_the_screen_and_the_session_keeps_going`, `an_emulator_panic_does_not_stop_the_output_pump`, threat model C23). 다시 세운 화면은 프로그램이 다시 그릴 때까지 비어 있고, fuzz 타깃 둘은 `emulator_resets() == 0`을 단언해 삼킨 panic도 crash로 센다.
- [ ] `Vs16Filter` 탓에 U+FE0F가 필요한 이모지(하트·키캡)가 host 화면 모델에서 한 칸을 차지한다.
- [x] 서로 다른 task(입력 pump, reader, recovery ticker)의 화면 바이트를 직렬화하지 않는다. 수용 시험에서는 어긋나지 않았다. 2026-11-11 `ScreenSink::emit`이 프레임 계산과 frontend 큐 삽입을 한 잠금 안에 묶는다(`frames_from_different_tasks_reach_the_frontend_in_the_order_they_were_made`, 잠금을 빼면 실패 확인).
- [x] 역방향 attach는 watchdog이 없어 입력이 있어야 상태 줄 시계가 돈다. 2026-11-11 증상만 닫았다. 역방향 route의 Ping은 로컬 데몬에서 끝나므로(protocol §11) 상태 줄을 그리는 역방향 attach는 쉰 지 idle probe 간격(5초)이 지나면 바이트 없는 `Input`(이미 유효한 frame, wire 변경 없음)을 보내고 host는 반복 입력으로 읽어 `InputAck`로 답한다. host는 빈 `Input`을 bulk 양보의 대화형 입력으로 세지 않는다(protocol §18.10, `reverse_idle_attach_keeps_asking_the_host`, `reverse_idle_status_line_appears_during_a_blackhole`, `heartbeat::a_heartbeat_is_answered_with_the_applied_offset_and_runs_no_input`).
- [ ] 역방향 route에는 경로가 죽었다는 PathWatch 판정이 없다(데몬의 등록 watchdog과 `LocalReconnect`가 맡는다). ADR-0053 본문은 역방향에도 watchdog이 있다고 적었는데 코드와 다르다. 빈 `Input` heartbeat를 받아들일지, 진짜 판정을 둘지(ADR 필요)는 Dave 결정이다. 소유: Dave.
- [ ] client가 자기 principal을 몰라 첫 `writer_changed`로 배운다. 같은 principal의 둘째 attach와 첫 알림으로 온 steal을 구분하지 못한다(효과는 철회되는 예측 하나 또는 보류된 예측).
- [x] 느린 예측 수용 셋(`predict_accept::`)은 ubuntu acceptance job에서만 돈다. macOS는 test job의 unix 셋만 돈다. 2026-11-11 ci.yml에 macOS job `acceptance-macos`가 `QSH_ACCEPTANCE_SLOW=1`로 `predict_accept::`를 돈다. 20 ms p95가 공유 runner의 시간 단언이라 `ci-ok`의 `needs`에는 넣지 않았고, 몇 번 초록을 본 뒤 필수 검사로 올릴지는 저장소 설정이라 사람 몫이다.
- [ ] Windows pwsh에서 키 서른 개 중 하나가 105~142 ms를 쓸 때가 있다(p95는 2.0 ms).

M24가 남긴 후속이다(ADR-0054 개정 이력, M24 계획 `569e859`).

- [x] `jump_chain::jump_mtu_budget_on_a_four_hop_chain`이 CPU 버너 16개의 극단 부하에서 한 번, 한 층이 4×srtt 침묵 규칙으로 스트림으로 바뀌어 실패했다. 침묵 시한에 RTT 하한을 둔 ADR-0058 뒤 약 29 버너 부하에서 20/20이다(`b6109b4`).
- [ ] 펀칭한 `exec`는 채택된 연결의 closing drain도 200 ms에서 끊는다. 마지막 CONNECTION_CLOSE가 잃히면 host는 idle timeout에서야 끝을 안다. 진 후보만 따로 닫는 방법(다른 endpoint 또는 quinn의 연결별 drain 상태)은 transport 재설계가 필요해 미뤘다.
- [ ] derived 후보(결정 23 (d))는 IPv4만 만든다. IPv6에서 중개자가 B와 같은 방화벽 뒤인 장면은 시험이 없다.
- [ ] 커널 대조는 masquerade(port-restricted)와 fully-random(symmetric)만 덮는다. full cone·restricted는 conntrack에 그대로 대응하는 것이 없어 netsim에서만 본다.
- [ ] 역방향 등록 자체의 펀칭과 일반 `qsh serve`·on-demand serve의 펀칭은 ADR-0054에서 미뤘다.
- [ ] 흔들림: `trust_withdrawal::listen::listen_closes_a_withdrawn_peer_that_stopped_reading_the_control_stream`이 전체 실행 한 번과 CI run 42573815011에서 8초 안에 닫힘을 보지 못했다. `1acd3d6`이 고정 2.5초 sleep 대신 host가 막혔다는 보고(`peer_stream_blocked_events`)를 기다리고 flood를 60000건으로 줄여 양보하게 했다(제품 코드는 응답 스트림을 기다리지 않는다). 원래 실패는 로컬에서 재현되지 않아 원인은 가설이다. 부하 아래 30/30. 짝인 `serve_closes_a_withdrawn_peer…`도 2026-11-11 같은 방식으로 고쳤다. `chaos_relay::reorder_lets_the_successor_arrive_first`는 10 ms 보류가 부하에서 만료되던 시험 결함이었다(64 busy loop 18/60 실패). `ChaosPolicy::reorder_hold`로 이 시험만 4초로 넓혀 0/60이다.

M25가 남긴 후속이다(ADR-0055 개정 이력, M25 계획 `3604a16`).

- [x] Windows에서 exec 소켓 제거를 기다리는 단언은 세션 소켓만 보아 거의 공으로 통과한다. exec pipe의 수명을 직접 보는 시험이 없다. 2026-11-11 `agent_host::an_exec_agent_endpoint_is_gone_after_the_exec`가 exec가 받은 `SSH_AUTH_SOCK` 자체에 붙어 보아 끝난 뒤 `NotFound`를 단언한다(Linux, Dave-Windows).
- [ ] Windows CI 러너의 `ssh-agent` 서비스는 기계 하나에 하나라서 그 서비스를 쓰는 시험은 시험 그룹 `shared-ssh-agent`로 한 번에 하나씩 돈다(`38d30ec`). 그 서비스를 쓰는 시험을 더하면 같은 그룹에 넣는다.
- [x] `punch_features::a_local_forward_carries_bytes_over_a_punched_connection`의 Windows 10060(CI run 42594749119, 42612491760)은 시험 결함이었다. 부하 아래 `try_clone`(WSADuplicateSocket) 복제본이 미연결로 돌아와 `shutdown(Write)`가 WSAENOTCONN으로 실패해 half-close가 나가지 않았다(Dave-Windows 부하 아래 63/64 재현). 한 소켓으로 쓰고 읽게 고쳤다. 도우미는 `qsh_testkit::tunnel::echo_round_trip`으로 모았고 `jump_chain`·`jump_reverse`도 쓴다(`2f68b24`). 2026-11-11 `qsh-cli`의 `tunnel_e2e.rs`·`route_cases.rs` 도우미도 `echo_round_trip`·`echo_exchange`로 바꿨다.
- [x] `agent_reverse::end_to_end::a_reverse_reattach_registers_its_channel_again`의 간헐 실패는 제품 결함이었다. localctl 소켓 bind가 프로세스 전역 umask를 0o177로 좁히는 동안 다른 스레드가 만든 0700 디렉터리가 0600이 되어 audit 쓰기가 EACCES로 실패하고 허용이 fail-closed로 거부가 됐다. 0o077로 고치고 회귀 시험을 더했다.

M26이 남긴 후속이다(ADR-0056·ADR-0058 개정 이력).

- [x] 종류 14 datagram만 골라 버리는 시험 훅이 없다. datagram 경로의 침묵은 chaos proxy로 링크 전체를 막거나 `set_max_packet`으로 줄여서만 만든다. 2026-11-11 `Server::blackhole_jump_datagrams`(화면용 `blackhole_datagrams`와 같은 모양)와 `jump_chain::jump_silence_when_only_kind_14_datagrams_vanish_falls_back_to_the_stream`이 닫았다.
- [ ] 연결 수명 중간에 PLPMTUD가 자리를 올려 운반체가 바뀌는 장면은 시험으로 몰 수 없다. 시작 직후 상승(`jump_carrier_switches_to_datagram_after_pmtud`)만 고정돼 있다.
- [x] 같은 포트로 다시 뜬 중간 peer를 체인이 다시 찾는 시험이 없다. 2026-11-11 `jump_recovery::a_chain_finds_a_middle_peer_that_restarted_on_the_same_port`(감독 `-L`, 같은 포트·신원으로 재기동, 왕복이 약 0.26초에 복구). graceful stop이라 stateless reset이 아니라 중간 peer의 CONNECTION_CLOSE 경로를 덮는다. 런타임을 drop하는 crash 모양은 `datagram.rs`의 프로세스 전역 허브 표가 listener 소켓을 붙들어 시험에 쓸 수 없다(제품 영향 없음).
- [x] 주소 없이 펀칭으로만 닿는 첫 hop은 `jump_plan`의 주소 검사에 막힌다. 펀칭 첫 hop 시험은 주소가 있는 pin으로 돈다. 2026-11-11 ADR-0056 결정 13(첫 hop은 평소 route)대로 `jump_plan`이 랑데부가 있으면 빈 주소를 통과시키고, redial 예산과 doctor의 첫 hop probe도 주소 없는 pin을 따른다(`jump_punch::jump_first_hop_with_no_address_is_reached_by_punching_alone`, 수정을 끄면 실패 확인).
- [ ] 건강한 경로에서 침묵 fallback이 난다. 2026-11-11 가설을 확인했다. 직전 교환 끝에 받은 쪽이 보낸 ack-only datagram 하나가 답을 받지 못해 침묵 시계를 켜고, 시한보다 긴 틈(300 ms 이상) 뒤 다음 송신이 그것을 침묵으로 센다(임시 계측에서 틈 100 ms 0/6, 300·600·1000 ms 6/6, 손실 0). 반대편 datagram이 오면 풀려 운반체가 오간다. 개정안(ADR-0058 결정 1, Dave 승인 필요): 받은 datagram 뒤 첫 송신은 침묵 시계를 시작하지 않는다. 임시로 넣으면 같은 실험이 0/4이고 침묵 시험 둘도 통과했다. "시한보다 긴 틈 뒤 시계 되돌리기"는 srtt가 큰 경로에서 진짜 blackhole의 PTO 간격이 시한을 넘어 탐지를 막을 수 있어 권하지 않는다. 재현 시험 `jump_chain::jump_silence_ignores_an_unanswered_ack_across_an_idle_gap`(`#[ignore]`, 개정 전까지 실패). 소유: Dave.
- [ ] 명령마다 체인 전체를 다시 다이얼한다. 링크마다 3% 손실인 세 hop에서는 안쪽 handshake가 잃은 비행을 거듭하면 PTO가 두 배씩 늘어 10초 체인 시한을 다 쓸 수 있다(CI run 42852092810, 로컬 12/12 통과). `jump_loss`만 dial 시한을 30초로 넓혔다. 손실이 큰 다단 체인에서 사용자가 `TIMEOUT`(stage `handshake`)을 볼 수 있다는 뜻이고, 체인 연결 재사용이나 hop 수에 비례한 시한은 ADR이 필요하다.
- [ ] 결정 25.3의 datagram·스트림 p95 비교는 출력만 하고 단언하지 않는다. C–J–T에서 차가 약 5%로 얇다.
- [ ] 한 hop 처리량 비율은 조용한 WSL에서 0.68~0.73이고 CI acceptance(debug 빌드)에서는 runner 부하에 따라 하한 0.5에 가까울 수 있다. 붉어지면 재전송 비율(`jump_perf` 출력)부터 본다.

M20이 더했던 ConPTY 배치 실측 셋(ADR-0035 결정 20)은 `d538468`·`bd4b272`, 신호 사건 실측 둘(결정 22)은 `a475f08`이 닫았다.

## 2. 테스트 환경

- CI의 `windows-latest` leg은 clippy, `cargo nextest run --workspace`, `cargo doc -D warnings`를 돌고, Windows host의 PTY·`exec`·파일 op·응답자를 정방향과 역방향으로 덮는다. 로컬 Windows 검사는 Dave-Windows(`ssh dave-windows.tail91e9e.ts.net`)에서 하고 CI를 대신하지 않는다.
- Dave-Windows에 SSH로 들어가 돌리는 전체 실행에서는 일곱 시험이 늘 실패한다: `cp_cancel::` 넷과 `auto_bootstrap::console::ctrl_c_during_the_bootstrap_ends_canceled_on_windows`(비대화 세션에 콘솔 Ctrl-C가 없다), `identity::keystore::tests::credential_manager_` 둘(SSH 로그온에는 Credential Manager가 없다). CI `windows-latest`에서는 통과한다. 로컬 Windows 판정은 이 일곱을 빼고 한다.
- 부하 반복은 Linux·공통 테스트를 Dave-Windows-WSL(8 vCPU)에서, Windows 전용 타이밍 민감 테스트를 Dave-Windows에서 `scripts/stress/run.sh`로 돈다. 마일스톤별 필터는 `scripts/stress/m<N>.filter`다.
