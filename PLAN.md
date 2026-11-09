# PLAN.md — M24: 홀펀칭

M23(로컬 에코 예측과 연결 상태 줄)은 2026-11-07 닫혔다. 직전 M23 계획의 마지막 커밋은 `d50f003`이다. M24의 범위는 ROADMAP §6 M24 행(둘 다 닿는 사용자의 qsh peer를 중개자로 쓴 후보 교환, 동시 송신, 첫 handshake 채택, 실패 시 포기, relay·TURN·공용 STUN 없음)이고, 첫 스텝인 범위 ADR이 승인되기 전에는 계약·wire 스텝을 열지 않는다(ROADMAP §6.1 원칙 2·4).

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

M24가 남긴 후속이다(ADR-0054 개정 이력, M24 계획은 ROADMAP 마감 노트의 커밋).

- [ ] 펀칭한 `exec`는 채택된 연결의 closing drain도 200 ms에서 끊는다. 마지막 CONNECTION_CLOSE가 잃히면 host는 idle timeout에서야 끝을 안다. 진 후보만 따로 닫는 방법(다른 endpoint 또는 quinn의 연결별 drain 상태)은 transport 재설계가 필요해 미뤘다.
- [ ] derived 후보(결정 23 (d))는 IPv4만 만든다. IPv6에서 중개자가 B와 같은 방화벽 뒤인 장면은 시험이 없다.
- [ ] 커널 대조는 masquerade(port-restricted)와 fully-random(symmetric)만 덮는다. full cone·restricted는 conntrack에 그대로 대응하는 것이 없어 netsim에서만 본다.
- [ ] 역방향 등록 자체의 펀칭과 일반 `qsh serve`·on-demand serve의 펀칭은 ADR-0054에서 미뤘다.
- [ ] 흔들림 후보: `trust_withdrawal::listen::listen_closes_a_withdrawn_peer_that_stopped_reading_the_control_stream`이 전체 실행에서 한 번 실패하고 단독 다섯 번과 재실행에서 통과했다.

M20이 더했던 ConPTY 배치 실측 셋(ADR-0035 결정 20)은 `d538468`·`bd4b272`, 신호 사건 실측 둘(결정 22)은 `a475f08`이 닫았다.

## 2. 테스트 환경

- CI의 `windows-latest` leg은 clippy, `cargo nextest run --workspace`, `cargo doc -D warnings`를 돌고, Windows host의 PTY·`exec`·파일 op·응답자를 정방향과 역방향으로 덮는다. 로컬 Windows 검사는 Dave-Windows(`ssh dave-windows.tail91e9e.ts.net`)에서 하고 CI를 대신하지 않는다.
- 부하 반복은 Linux·공통 테스트를 Dave-Windows-WSL(8 vCPU)에서, Windows 전용 타이밍 민감 테스트를 Dave-Windows에서 `scripts/stress/run.sh`로 돈다. 마일스톤별 필터는 `scripts/stress/m<N>.filter`다.

## 3. M24 스텝

- [x] **범위 ADR(ADR-0054).** 2026-11-07 승인(Dave 결정, 다섯 항목 모두 추천 (가), 펀칭 대상은 `serve --to` host로 한정). 수용 기준은 ADR-0054의 마지막 결정(DoD 열여섯 항목)이다.
- [x] **netsim과 NAT 상자 표 테스트.** 2026-11-07 착지(`112f442`, netsim 시험 20개, WSL 전체 통과, Dave-Windows 20/20). `qsh_testkit::netsim`의 `Net`·`Realm`·`Site`·`NatHandle`·`NetSocket`(quinn `AsyncUdpSocket`), tokio 일시정지 시계와 seed 하나. 프리셋은 hairpin 꺼짐, 포트 보존 상자는 같은 소켓의 매핑마다 안쪽 포트를 다시 쓴다. wildcard·dual-stack bind는 아직 없어 `PunchEndpoint` 스텝이 더한다. `qsh-testkit`의 가상 UDP 위 실제 quinn, RFC 4787 NAT 상자(full-cone·restricted·port-restricted·symmetric 등), 세 OS. wire 없음.
- [x] **`PunchEndpoint`와 손으로 넣은 후보의 NAT 쌍 측정.** 2026-11-07 착지(`a4634ff`, WSL 전체 3958개, Dave-Windows punch·netsim 25/25와 단위 24/24). 펀치 datagram·tag는 qsh-proto(`punch.rs`, tag key는 `blake3::derive_key("qsh punch attempt key v1", attempt_id)`), 감싼 소켓과 서버 창은 qsh-transport(`PunchEndpoint`), 일정·채택은 qsh-core(`punch/`). 25쌍 중 22쌍 채택 p95 125 ms(신호 구간 제외), 세 쌍 5000 ms 포기, 손실 5%에서 최대 1449 ms. peer-reflexive 후보는 dial만 해 한 끝의 펀치가 64개를 넘지 않는다. 0x1006은 아직 transport 내부 상수이고 protocol.md §16.3 기재는 `punch.v1` 스텝 몫이다. 창이 닫힌 endpoint가 모르는 Initial에 stateless reset 하나를 돌려주는 것(Initial보다 작음)을 거를지 `punch.v1` 스텝이 정한다. 감싼 소켓, 펀치 datagram 송수신, 서버 창, dual-stack. 수치는 ADR 개정 이력에. wire 없음.
- [x] **`punch.v1`, message, 후보 검사, tag, fuzz.** 2026-11-07 착지(`155b60c`, `docs/CLI.md` v0.83, protocol §19, threat model 아홉 행, fuzz 타깃 `punch_candidates`(26종), WSL 전체 3967개). ControlMessage 90~92·Response 16~18, `valid_punch_candidate`는 사설·CGNAT 주소를 받는다. `Server::dispatch`는 아직 `UNSUPPORTED`. 창이 닫힌 endpoint의 stateless reset은 거르지 않는다(부른 datagram보다 작고 속도 제한, ADR-0054 개정 이력).
- [x] **`host.punch`와 role 표, 감사.** 2026-11-07 착지(`0865392`, `docs/CLI.md` v0.84, threat model B45·C25, WSL 전체 3983개). `none`을 뺀 다섯 role이 준다. `check_punch(PunchOp::Request|Offer|Rendezvous)`가 R·B의 자원 생성 전 판정과 감사(resource에 op 이름, 주소 필드 없음)를 맡는다. 기존 fixture 둘은 그대로 두고 `strip_host_punch`로 비교하며 새 fixture 셋을 더했다. `Op`·`OP_REGISTRY`·`DENY_SEAMS` 행은 R·B 서비스 스텝 몫이다.
- [x] **R의 중개 서비스와 B의 offer 처리.** 2026-11-09 착지(`4e6c91b`, protocol §19.9, WSL 전체 3998개, Dave-Windows punch·rendezvous 70개, load 11개, 역방향 느린 수용 셋 통과). `qsh listen`은 `Hello.reverse` 없이 `punch.v1`을 광고한 peer를 펀칭 연결(동시 16, idle 3초)로 받는다. 거부된 시도는 속도 표에 세지 않는다. B에 pin이 없는 initiator는 평가기가 허용해도 거부한다. R 자신의 거부는 wire `Error`로, B에서 난 일은 `PunchReply.refusal`로 알린다. 등록이 끊기면 OS 소켓의 endpoint와 `PunchTarget`을 새로 만든다(같은 소켓 재dial이 chaos sever 시험에 걸렸다). 남은 "예정" 핀 테스트: C24의 64개 상한 끝단 시험, D23의 로그 캡처. 전체 run에서 한 번 `trust_withdrawal::listen::listen_closes_a_withdrawn_peer_that_stopped_reading_the_control_stream`이 10.6 s로 실패했고 단독 5회·전체 재실행은 통과했다(흔들리는 목록 후보).
- [x] **client route, 경주, 채택, 포기 사유.** 2026-11-09 착지(`c0d3381`, `docs/CLI.md` v0.85, fixture `error.CONNECTION_FAILED.punch.json`, WSL 전체 4010개, Dave-Windows punch·route 126개). `ops/route.rs`의 `dial_routed`가 직접 dial·펀칭·1초 타이머·전체 시한을 함께 기다리고, `punch/client.rs`의 `attempt`가 신호 3초와 창 5초를 쓰며 중개자를 둘까지 시도한다(R 앞이나 R에서 실패한 넷만 다음 중개자로). `details.punch`는 `CONNECTION_FAILED`·`TIMEOUT`에만 붙는다. 직접 dial이 어떤 이유로든 먼저 실패하면 1초를 기다리지 않는다. 중개자 출처는 아직 주입값(`ClientPunch.rendezvous`)이고 pin의 `rendezvous` 필드는 힌트 스텝 몫, recovery는 `REDIAL_DEADLINE`을 그대로 쓴다(recovery 스텝 몫). `-4`/`-6` 경로는 시험이 없다.
- [x] **recovery의 route 재해석과 `--supervise`.** 2026-11-09 착지(`7e99880`, `docs/CLI.md` v0.86, protocol §19.10, WSL 전체 4015개, 느린 수용 셋 9개, Dave-Windows punch·recover·supervise 175개). 재dial이 시도마다 route를 다시 돈다. 펀칭할 수 있는 host의 시도 시한은 head start 1초를 더한 9초(주소 없는 pin은 8초)이고, 펀칭이 먼저 실패하면 직접 dial에 시작부터 2초까지만 더 준다(ADR이 열어 둔 것, 기존 backoff를 늦추지 않으려고). recovery 시한은 기존처럼 `-o ConnectTimeout`을 따르지 않는다. netsim 시험은 중개자·target이 std 시간을 써서 실제 시계로 돈다.
- [x] **힌트 배우기, `trust rendezvous`, 플래그와 키.** 2026-11-09 착지(`b00a424`, doctor 연결 `86c7fc0`, `docs/CLI.md` v0.88, fixture `trust.set_rendezvous`·`trust.list.rendezvous`, WSL 전체 4048개, Dave-Windows punch·rendezvous·doctor 328개). 정방향 route의 중개자 후보는 `--rendezvous`(주면 이것만), 그다음 pin의 `rendezvous` 목록(fingerprint 최대 넷, 주소 있는 pin만, 쓰는 것은 둘)에서 온다. 연결이 선 뒤 `punch.v1`이 협상됐으면 host마다 `RendezvousQuery`를 한 번 쓰고 답을 기다리지 않으며, 이미 주소와 함께 pin한 fingerprint만 `trust.toml.lock` 아래에서 합친다. `qsh trust rendezvous <name> <peer>...|--clear`(op `trust.set_rendezvous`)가 목록을 직접 정한다. `--no-punch`와 `[punch].mode = "off"`는 요청·학습을 끄고, `qsh listen`·`qsh serve --to`는 중개와 offer를 `UNSUPPORTED`로 거절한다. doctor는 `Ops::punch_mode()`와 route의 `punch_plan`을 읽는다. netsim 시험 `punch_hints` 다섯.
- [x] **doctor, `qsh::punch`, JSON과 fixture.** 2026-11-09 착지(`7f04d1f`, `docs/CLI.md` v0.87, doctor 코드 34종, fixture `doctor_punch.json`·`doctor_punch_failed.json`, 위협 모델 D23 핀 테스트, WSL 전체 4026개). doctor는 직접 경로가 없을 때만 펀칭을 한 번 돌리고 선 연결은 곧바로 닫는다. 주소 없는 pin에서 doctor가 `HOST_NOT_FOUND`로 멈추던 것이 펀칭 시도로 바뀌었다. 중개자 후보와 mode는 아직 주입값이고 힌트 스텝이 잇는다. 직접 경로가 있는 host에서 `data.punch`가 없음은 실제 네트워크 probe라 시험하지 않았다.
- [x] **수용 시험.** 2026-11-09 착지. 1차 `ff928f9`: `punch_accept::punch_route_nat_matrix`(진짜 route, 25쌍, seed 다섯, 채택 p95 약 400 ms)와 `scripts/netns/punch.sh`·ci.yml `punch-netns`(CI run 42559582248에서 아홉 쌍 모두 기대대로, 채택 최대 438 ms). 보강 `bcace4c`: 장면 넷(`punch_scenes`), A–B 손실 5% route 표(채택 p95 397 ms), `punch_bounds` 아홉 행, `a_host_without_rendezvous_dials_exactly_as_before`. 이동·기능 `912bf6b`: 주소가 바뀐 뒤 resume 10회 모두 2 s 안, B 재등록 뒤 resume, 펀칭 연결 위의 화면 동기화+예측·`exec`·`-L`·`cp`, R·B 감사 실패 때 offer 없음, 실패한 펀칭 뒤 ssh 되살리기. 채택 뒤 `exec` 끝까지 0.9 s 걸리던 것은 경주에서 진 후보의 closing 기간을 기다린 탓이라 펀칭한 `exec`만 drain 대기를 200 ms로 끊었다(0.36 s). Windows client의 `b:` 드라이브 해석에 걸린 cp 시험 수정 `ed95325`. WSL 전체 4069개, Dave-Windows punch 138개.
- [x] **문서와 마감.** 2026-11-09 착지(`14c7c9d`, `docs/CLI.md` v0.89). architecture §1·§7, `CONTROLLER_UNREACHABLE` 문안(relay 없음, controller가 중개자), README의 NAT 한계, `docs/campaigns/m24-punch.md`, threat model A21·E23의 고정 테스트 이름. man은 생성기와 diff 0이다. ADR-0054 결정 26의 테스트 이름 넷은 개정 이력에서 구현 이름에 이었다. DoD 열여섯 항목의 대응은 아래와 같다: 1 `punch_accept`, 2 `punch_scenes`, 3 `punch_route`·`punch_hints`, 4 `punch_give_up_reasons`·`punch_doctor`·`punch_revival`, 5 `punch_signal`(감사 실패 둘 포함), 6 `punch_bounds`, 7 채택·창 시험, 8 `punch_recovery`, 9 `punch_features`, 10 `punch_hints`, 11 fixture·man·role 표, 12 fuzz 26종, 13 `punch-netns`, 14 세 OS CI, 15 `a_host_without_rendezvous_dials_exactly_as_before`, 16 threat model 행.
