# PLAN.md — 자리표시자: P1 마일스톤 전부 닫힘, 사람 몫 대기

M20(Windows host)이 2026-10-18 닫혔다(`docs/ROADMAP.md` M20 마감 노트). M20 계획의 마지막 커밋은 `addffb5`이다. M20은 P1 순서상 마지막 마일스톤이다. M14는 철회됐고(ADR-0043), M18(세션 거처)은 착수 조건인 M8 DoD 3(실기기 mobility 60회)이 기록되지 않아 건넌 상태다(`docs/ROADMAP.md` §5.1 원칙 6). 그래서 지금 열린 에이전트 마일스톤은 없다. M8 DoD 3이 기록되면 M18 계획이 이 파일을 대체한다. 그 전까지 남은 일은 아래 사람 몫과 유지보수 확인이다.

이 파일과 `docs/ROADMAP.md`의 편집은 main 세션만 한다.

## 0. 열린 사람 몫

여기 적힌 항목은 이 파일이 다음 계획으로 바뀔 때 그대로 승계한다.

회차의 대상 태그는 `v0.5.0`이다(2026-10-20, 태그 커밋 `1c653e0`, release run 39354944687 초록, 자산 9개와 `SHA256SUMS`). M15~M20 착지와 Windows 자산이 모두 담겨 있어 `p1-windows`·`p1-ssh-bootstrap`·`p1-setup-stopwatch`·`p1-supervise-wake`와 P0 회차가 이 태그에서 돈다. 첫 태그 push(`02d4c32`)는 musl 빌드가 `libc::time_t` deprecation 경고로 실패해 아무것도 게시되지 않았고, `1c653e0`이 고친 뒤 같은 이름으로 다시 찍었다. 패치 태그 `v0.5.1`(2026-10-22, 태그 커밋 `b4639a8`, release run 39723802624 초록)이 ADR-0046 `79e6d6f`, admission `14d802b`, `cargo install --git` 커밋 `314bbbd`, webpki `698b4bc`를 더했다. Windows host 회차(W2·W3b·W7)와 Windows `qsh listen` 회차(W3a)는 이 태그에서 돈다. 다른 회차는 `v0.5.0`에서 돌아도 된다. 두 태그의 wire와 계약은 같다.

### 0.1 P0에서 열린 일곱

M20 계획 §0.1의 일곱 항목을 문면 그대로 승계한다. M8 DoD 3은 M18의 착수 조건이고, 이것이 닫히면 M18을 연다.

- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** `docs/campaigns/m10-clean-vm.md`. macOS 두 회차가 남았다. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 같은 문서. 소유: 사람.
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** 캠페인 §9 판정과 함께 닫힌다. 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** `docs/campaigns/m7-stopwatch.md`. 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** `docs/campaigns/m2-mobility.md`. M18의 착수 조건. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** 저장소 밖 조직 액션. 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 소유: 사람.

### 0.2 P1 마일스톤이 만든 사람 몫 (`docs/ROADMAP.md` §5.5)

M20 계획 §0.2의 다섯 항목을 승계한다.

- [x] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 출처 M11. 2026-10-23 배치 3에서 72h, crash 0(`docs/campaigns/m8-fuzz.md` §5 배치 3).
- [ ] **`p1-supervise-wake` 회차 넷.** 출처 M12. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 출처 M12(ADR-0024 결정 12). 소유: 사람.
- [x] **`decode_file_frame`·`parse_ssh_bootstrap_line` fuzz 타깃의 누적 72 fuzz-hours.** 출처 M15·M16. 공개 beta 전(`docs/design/protocol.md` §13). 에이전트가 Dave-Windows-WSL에서 `parse_openssh_key`와 함께 돌렸다(run-id `m8-fuzz-20261020-0931`, 커밋 `60e54fa`). 2026-10-23 09:35+09:00 세 타깃 모두 259201초, `exit=0`, crash·artifact 0이다(`docs/campaigns/m8-fuzz.md` §5 배치 3).
- [ ] **실제 OpenSSH 위의 SSH 부트스트랩 회차.** `docs/campaigns/p1-ssh-bootstrap.md`(사전 고정 `e8cd7a3`). Windows 원격이 응답자가 되는 회차는 이 문서가 아니라 `p1-windows.md` W7이 맡는다(Step 10). 소유: 사람.

### 0.3 M19가 만든 사람 몫

- [ ] **Windows client 확인 회차.** `docs/campaigns/p1-windows.md`(M19 사전 고정 `ad409e0`)의 W1, W3a, W4, W5, W6, W8, W9, W10, W11, W12. Windows 자산이 붙은 태그에서 돈다. 2026-10-21 에이전트가 `v0.5.0`에서 단일 장비 회차를 돌렸다(캠페인 §7, `87e3c1d`). `v0.5.0`의 W8은 a~c PASS, d 미실행으로 보류였다. W11b는 PASS다. W11c는 `cargo install --git` 빌드가 커밋을 내지 않아 c1 FAIL이었고 `314bbbd`가 고쳤다. 2026-10-22 `v0.5.1`에서 다시 돌려 PASS다(캠페인 §7 셋째 W11c 행). W11a(Edge 다운로드와 SmartScreen 창)는 사람이 한다. W8은 2026-10-23 `v0.5.1`에서 a~d 모두 PASS다(캠페인 §7 셋째 W8 행). 재부팅 뒤 Credential Manager 항목이 남아 `key_store`가 `platform`이고 fingerprint가 같았다. c 뒤 doctor에 `bindv6only_blocks_ipv4`가 없어 ADR-0046을 실제 Windows에서 확인했다. 소유: 사람.
- [x] **Windows 배포 준비.** 2026-10-19 사용자 결정으로 Authenticode 서명과 scoop·winget을 모두 철회해 사람이 준비할 것이 없다(ADR-0035 개정 이력 2026-10-19 두 줄). Windows 설치 경로는 release zip, `install.ps1`, `cargo install --locked --git https://github.com/DaveDev42/qsh qsh-cli`다.

### 0.4 M20이 만든 사람 몫

- [ ] **Windows host 확인 회차.** `docs/campaigns/p1-windows.md`의 W2, W3b, W7(M20 재고정 `048df57`, ADR-0035 결정 18). W2는 Linux·macOS client가 Windows host(`qsh serve`)에 붙어 `cmd.exe`·PowerShell·Windows 빌드 `vim` 전체 화면, 한글 입출력, resize, `Ctrl-C`, 방화벽 첫 허용 프롬프트를 본다. W3b는 Linux·macOS `qsh listen` ← Windows `qsh serve --to`의 attach·`cp`·터널이다. W7은 `qsh pair ssh`와 `--reverse`가 Windows OpenSSH Server를 상대로 pin을 세우는 것이다. M20 착지가 담긴 Windows 자산 태그에서 돈다. 기본 `[::]:4433` bind의 Windows host와 Windows `qsh listen`이 IPv4 peer를 받지 못하던 결함을 `79e6d6f`(ADR-0046)가 고쳤다. 그래서 W2·W3a·W3b·W7은 이 커밋이 담긴 `v0.5.1`에서 돈다. `v0.5.0`에서 IPv4 경로로 돌면 실패할 수 있다. P1 완료 선언을 막는다(ROADMAP §5.1 원칙 6, §5.5). 소유: 사람.

에이전트는 `gh secret set`, `gh variable set`, `gh workflow run`, 태그 push, 저장소 설정 변경, 외부 저장소 쓰기를 하지 않는다. Dave-Windows에서 방화벽 규칙을 더하는 일도 사람 몫이다. Dave-Windows의 OpenSSH Server는 2026-10-21 이미 켜져 돌고 있다(`sshd` Running, Automatic).

## 1. 유지보수에서 남은 확인

M20 계획 §1에서 열린 채로 넘어온 항목이다.

- [ ] macOS Keychain 왕복(`08a6173` 이후 keyring-core 1). `docs/design/testing.md` L1 수동 단계.
- [x] 다음 태그 run에서 `release.yml`의 Apple 서명·공증과 provenance 확인(Windows 자산은 미서명, ADR-0035 개정 이력 2026-10-19). `v0.5.0`(run 39354944687)에서 macOS 두 job의 `codesign` Authority가 Developer ID Application이고 notarytool이 둘 다 `Accepted`다. 받은 자산 다섯과 `SHA256SUMS`가 `sha256sum -c`를 통과하고, 각 digest에 `refs/tags/v0.5.0`·`1c653e0`을 가리키는 provenance attestation이 하나씩 있다(attestations API로 확인, 이 머신의 gh 2.45에는 `gh attestation verify`가 없어 서명 검증 자체는 하지 않았다). x86_64 musl 바이너리는 static-pie이고 `qsh 0.5.0`을 낸다. `v0.5.1`(run 39723802624)도 같다. macOS 두 job이 Developer ID Application과 notarytool `Accepted`이고, 자산 아홉과 `install.ps1`이 `sha256sum -c`를 통과하며 각 digest에 attestation이 있다. musl 두 바이너리는 static이고 x86_64 쪽 `qsh version --json`의 `build.commit`이 `b4639a896a6e4728d3e8787c522cab3ae4466a74`다.
- [ ] `qsh identity move-key` 왕복을 macOS Keychain·Linux Secret Service에서. Linux 쪽은 2026-10-21 `v0.5.0` gnu 자산(sha256 `9bb38ba4…`)으로 `ubuntu:24.04` 컨테이너의 gnome-keyring 세션에서 돌려 `docs/design/testing.md`의 기준을 모두 충족했다. `--to file` 뒤 `device.key` 0600과 Secret Service 항목 0개, `--to platform` 뒤 파일 없음과 항목 1개, fingerprint·`device_id` 불변이다. Secret Service가 없는 세션에서 `auto`는 파일로 내려가고 `platform` 명시는 `INTERNAL`("platform key store unavailable …")로 실패한다. Windows 줄은 캠페인 W8(`v0.5.1`, a~d PASS)이 봤다. macOS 쪽이 남았다.
- [x] `launchctl print system/io.qsh.<mode>`의 root 요구 확인(ADR-0032 결정 18 셋째 항목). 2026-10-23 Dave-MacMini(macOS 27.0.1, 빌드 26A434)에서 root 없이(uid 501, ssh) 쟀다. 적재된 system 서비스는 실행 중이든 아니든 종료 코드 0, 적재되지 않은 label은 113(`Could not find service`)이다. `6f565b6`이 `status --live`가 이 질의를 직접 부르게 했다. 0은 `active: true`, 113은 `false`, 그 밖은 `INTERNAL`(`step: "live"`)이고, 적재됐으나 멈춘 서비스도 `true`로 읽히는 점은 threat-model h45에 적었다.
- [ ] Windows `Password` 주체 작업의 Credential Manager 읽기(ADR-0032 결정 15 첫 항목). M19가 `keystore_session_bound`를 보수적으로 내는 것으로 닫았고, 실측은 열려 있다.
- [ ] Windows OpenSSH Server 위의 `qsh pair ssh-respond`. Dave-Windows에 OpenSSH Server를 켜는 것은 사람이 한다. 두 장비 회차는 캠페인 W7이다. 2026-10-23 에이전트 점검(캠페인 행 아님): Dave-Windows OpenSSH의 `cmd` 기본 셸 위에서 `qsh pair ssh`가 exit 0, 원격 serve가 없어 `verified: false`와 `CONNECTION_FAILED`(`remote_serve_not_listening`)로 설계대로 끝났고, `--reverse`도 exit 0에 `next_command` `qsh serve --to Dave-Windows-WSL`을 냈다. ssh 토큰에는 Credential Manager가 없어 원격 key store가 파일로 내려간 것도 설계대로다. 결함은 없었고 정리했다. 원격 serve·방화벽 규칙이 필요한 W7 a와 exec는 사람 몫이다.
- [ ] Windows 방화벽 첫 허용 프롬프트의 실제 문안과 README·doctor `udp_egress_blocked` 안내의 대응(ADR-0035 결정 25 개정 이력 2026-10-18). Windows Server에서의 같은 판정을 포함해 캠페인 W2가 본다.

- [x] `trust_withdrawal::listen::listen_closes_a_withdrawn_peer_that_stopped_reading_the_control_stream`의 CI 흔들림(run 39135082029). 원인은 테스트 쪽이다. 흐름에 막힌 peer는 보내는 것이 없어서 host의 CONNECTION_CLOSE 한 장을 놓치면 다음 keep-alive(15초)까지 모르고, 대기 한도는 8초다. `448d69a`가 닫힘 대기 중 probe를 보내게 고쳤고, 같은 커밋이 Windows 부하에서 나온 `unreadable_trust_toml_defers_the_comparison_until_it_can_be_read`의 공유 위반(32) 흔들림과 ConPTY `conpty_last_byte_arrives_before_the_exit_event`의 escape 순서 의존도 고쳤다. 부하 Linux 50/50, Windows 50/50. `session_follow`의 두 세션 바이트 비교는 `e7997f4`가 한 세션 ring 두 번 읽기로 바꿨다.

- [x] `tunnel_supervise::supervised_forward_initial_open_failure_is_not_retried`의 windows-latest 흔들림(job 117519179651, `AUTH_FAILED`). `kill_serve` 뒤 빈 UDP 포트를 병렬 테스트의 host가 다시 잡아 dial이 모르는 peer에 닿은 것으로 보고, `c9e5367`이 응답 없는 소켓으로 포트를 붙잡는다. 부하 Linux 50/50, Windows 50/50.
- [x] `identity::keystore::tests::credential_manager_round_trip_on_the_runner`의 windows-latest 흔들림(run 39352939458, 삭제한 항목이 다시 읽힘). 실제 Credential Manager를 쓰는 테스트 둘이 nextest의 병렬 프로세스로 같은 사용자 vault에 동시에 쓰다 갱신을 잃는다. 대상 이름은 ULID라 겹치지 않고 store crate에 캐시는 없다. Dave-Windows에서 동시 실행 300회 중 4회 재현했다. `b7ed672`가 nextest test group으로 직렬화했다. 서로 다른 대상 이름의 동시 쓰기가 갱신을 잃는 OS 동작이라 제품 경로에서도 qsh와 다른 프로그램이 같은 순간 vault에 쓰면 같은 일이 날 수 있다. qsh는 키를 init·move-key 때만 쓰고 쓴 직후 다시 읽어 확인하지 않으므로, 회차 W8(Credential Manager 왕복)에서 이 가능성을 함께 본다.
- [x] musl release 빌드의 deprecation 경고(`v0.5.0` 첫 push, run 39351214931). PR 게이트에 musl 타깃이 없어 놓쳤다. `1c653e0`이 고치고 `ci.yml`에 `clippy-musl` 잡을 더해 `ci-ok`가 요구한다.
- [x] Windows 기본 bind의 IPv4 peer 거부(2026-10-21 Dave-Windows `v0.5.0` doctor의 `bindv6only_blocks_ipv4`). Windows는 새 IPv6 소켓을 `IPV6_V6ONLY`로 열어 기본 `[::]:4433` `qsh serve`·`qsh listen`이 IPv4 peer를 조용히 거부했다. `79e6d6f`(ADR-0046)가 listener도 client처럼 그 옵션을 best-effort로 끄게 했다. doctor 진단은 OS가 끄기를 거부할 때만 나온다. 같은 작업에서 dual-stack listener의 IPv4-mapped peer가 모두 `::/64` admission 버킷 하나에 몰리는 결함(Linux 기본값에서 이미)을 찾았고 `14d802b`가 IPv4로 정규화했다(ADR-0009 개정 이력).
- [x] `cargo deny`의 RUSTSEC-2026-0382(rustls-webpki 0.103.15). `698b4bc`가 0.103.16으로 올렸다.
- [x] `cargo deny`의 RUSTSEC-2026-0385(ctutils 0.4.3, 2026-10-23 공개, `b8ada0d`의 deny·fuzz-smoke 실패). `6c7d986`이 두 lockfile을 0.4.4로 올렸다. digest·sha2와 Secret Service의 hmac·hkdf 경로로 들어온다. `v0.5.1` 자산은 0.4.3으로 빌드됐고, 다음 태그에서 바뀐다.
- [x] `cargo install --git` 빌드의 `qsh version`에 커밋이 없음(캠페인 W11c c1 FAIL). `314bbbd`가 `qsh-core` `build.rs`로 cargo git checkout에서만 `HEAD`를 박는다.
- [x] 다음 태그. `79e6d6f`·`14d802b`·`314bbbd`가 담긴 패치 태그 `v0.5.1`을 2026-10-22 사용자 승인 뒤 push했다(`b4639a8`, release run 39723802624 초록). W11c는 그 태그에서 PASS다. W2·W3a·W3b·W7은 사람 몫으로 남는다.
- [ ] 공유 runner 위 `adversarial_load` 시나리오 2 RSS의 경계 근접. `6d4fa37`의 load run 39569439731에서 `connection_flood_past_the_cap_leaves_the_listener_rss_and_fd_bounded`가 peak 30972 KiB로 30720 KiB 상한(`docs/campaigns/m8-adversarial-load.md` §3, PRD §13 idle 30MB)을 넘었고, 재실행은 peak 28704 KiB로 초록이었다. 최근 열두 run의 peak는 22.9~29.8 MiB이고, baseline이 18 MiB대와 24 MiB대 두 무리로 갈린다. 이 run의 변경(dual-stack bind, admission 키 정규화, `build.rs`)은 메모리 경로에 닿지 않는다. 상한은 PRD 수치라 낮추거나 늘리지 않는다. 붉음이 잦아지면 baseline이 갈리는 원인(runner 종류, allocator arena)부터 가른다. 같은 날 야간 perf(run 39571078325)의 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`도 p95 10.525ms로 붉었다. perf-judge 추세 판정은 GREEN(median 대비 109.2%)이었다. 아래 항목의 관찰에 더한다. 2026-10-23 load run 50회를 다시 보면 붉음은 1회다. baseline은 runner 이미지와 맞물린다(20261018 이미지 약 18 MiB, 20261012 이미지 약 24 MiB). peak와 baseline의 차는 3~7 MiB로 일정해, 늘어나는 것은 출발점이지 flood가 더하는 양이 아니다. 시나리오 1의 idle-after도 28.3~29.5 MiB로 상한 가까이 있다. 열어 둔다.
- [ ] 공유 runner 위 PTY echo p95 게이트의 경계 근접. 10-18 야간 perf의 `tunnel_echo_under_load`가 p95 10.959ms, 같은 날 acceptance의 `file_copy_echo_under_load`가 10.176ms로 10ms를 넘었고, 최근 야간 값이 9.6ms대에 자주 머문다. 기준은 `docs/design/protocol.md` §12의 수용 기준이라 낮추지 않는다. 붉음이 잦아지면 원인(runner 편차인지 회귀인지)을 perf 추세로 가르고, 재시도나 측정 방식 변경은 `docs/design/testing.md` CI 규율에 결정을 적은 뒤에 한다. 2026-10-23 야간 20회 중 붉음은 2회(10-18 10.96ms, 10-21 10.53ms)이고 CI acceptance에서 1회(10-18 10.176ms)다. runner가 측정 RTT로 두 무리로 갈리며, 느린 무리(RTT 0.31~0.50ms)의 p95가 7.2~11ms다. perf-judge는 median 대비 150%에서만 붉어서 게이트 경계의 넘침을 잡지 못한다. 붉음이 5회 중 1회 꼴에 이르면 testing.md에 결정을 적는다.

M20이 더했던 ConPTY 배치 실측 셋(ADR-0035 결정 20)은 `d538468`·`bd4b272`, 신호 사건 실측 둘(결정 22)은 `a475f08`이 닫았다.

## 2. 테스트 환경

- CI의 `windows-latest` leg은 clippy, `cargo nextest run --workspace`, `cargo doc -D warnings`를 돌고, Windows host의 PTY·`exec`·파일 op·응답자를 정방향과 역방향으로 덮는다. 로컬 Windows 검사는 Dave-Windows(`ssh dave-windows.tail91e9e.ts.net`)에서 하고 CI를 대신하지 않는다.
- 부하 반복은 Linux·공통 테스트를 Dave-Windows-WSL(8 vCPU)에서, Windows 전용 타이밍 민감 테스트를 Dave-Windows에서 `scripts/stress/run.sh`로 돈다. 마일스톤별 필터는 `scripts/stress/m<N>.filter`다.
