# PLAN.md — 자리표시자: P1 마일스톤 전부 닫힘, 사람 몫 대기

M20(Windows host)이 2026-10-18 닫혔다(`docs/ROADMAP.md` M20 마감 노트). M20 계획의 마지막 커밋은 `addffb5`이다. M20은 P1 순서상 마지막 마일스톤이다. M14는 철회됐고(ADR-0043), M18(세션 거처)은 착수 조건인 M8 DoD 3(실기기 mobility 60회)이 기록되지 않아 건넌 상태다(`docs/ROADMAP.md` §5.1 원칙 6). 그래서 지금 열린 에이전트 마일스톤은 없다. M8 DoD 3이 기록되면 M18 계획이 이 파일을 대체한다. 그 전까지 남은 일은 아래 사람 몫과 유지보수 확인이다.

이 파일과 `docs/ROADMAP.md`의 편집은 main 세션만 한다.

## 0. 열린 사람 몫

여기 적힌 항목은 이 파일이 다음 계획으로 바뀔 때 그대로 승계한다.

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

- [ ] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 출처 M11. 소유: 사람.
- [ ] **`p1-supervise-wake` 회차 넷.** 출처 M12. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 출처 M12(ADR-0024 결정 12). 소유: 사람.
- [ ] **`decode_file_frame`·`parse_ssh_bootstrap_line` fuzz 타깃의 누적 72 fuzz-hours.** 출처 M15·M16. 공개 beta 전(`docs/design/protocol.md` §13). 소유: 사람.
- [ ] **실제 OpenSSH 위의 SSH 부트스트랩 회차.** `docs/campaigns/p1-ssh-bootstrap.md`(사전 고정 `e8cd7a3`). Windows 원격이 응답자가 되는 회차는 이 문서가 아니라 `p1-windows.md` W7이 맡는다(Step 10). 소유: 사람.

### 0.3 M19가 만든 사람 몫

- [ ] **Windows client 확인 회차.** `docs/campaigns/p1-windows.md`(M19 사전 고정 `ad409e0`)의 W1, W3a, W4, W5, W6, W8, W9, W10, W11, W12. Windows 자산이 붙은 태그에서 돈다. 소유: 사람.
- [ ] **Windows 배포 준비(ADR-0035 결정 16, 서명은 2026-10-19 개정 이력으로 철회).** `DaveDev42/scoop-bucket` 저장소(README를 넣어 `main`을 만들어 둔다)와 쓰기 배포 키, 시크릿 `SCOOP_BUCKET_DEPLOY_KEY`, `WINGET_PAT`과 첫 winget 매니페스트 수동 제출. 비용이 드는 항목은 없다. 소유: 사람.

### 0.4 M20이 만든 사람 몫

- [ ] **Windows host 확인 회차.** `docs/campaigns/p1-windows.md`의 W2, W3b, W7(M20 재고정 `048df57`, ADR-0035 결정 18). W2는 Linux·macOS client가 Windows host(`qsh serve`)에 붙어 `cmd.exe`·PowerShell·Windows 빌드 `vim` 전체 화면, 한글 입출력, resize, `Ctrl-C`, 방화벽 첫 허용 프롬프트를 본다. W3b는 Linux·macOS `qsh listen` ← Windows `qsh serve --to`의 attach·`cp`·터널이다. W7은 `qsh pair ssh`와 `--reverse`가 Windows OpenSSH Server를 상대로 pin을 세우는 것이다. M20 착지가 담긴 Windows 자산 태그에서 돈다. P1 완료 선언을 막는다(ROADMAP §5.1 원칙 6, §5.5). 소유: 사람.

에이전트는 `gh secret set`, `gh variable set`, `gh workflow run`, 태그 push, 저장소 설정 변경, 외부 저장소 쓰기를 하지 않는다. Dave-Windows에서 OpenSSH Server 선택적 기능을 켜거나 방화벽 규칙을 더하는 일도 사람 몫이다.

## 1. 유지보수에서 남은 확인

M20 계획 §1에서 열린 채로 넘어온 항목이다.

- [ ] macOS Keychain 왕복(`08a6173` 이후 keyring-core 1). `docs/design/testing.md` L1 수동 단계.
- [ ] 다음 태그 run에서 `release.yml`의 Apple 서명·공증과 provenance 확인(Windows 자산은 미서명, ADR-0035 개정 이력 2026-10-19).
- [ ] `qsh identity move-key` 왕복을 macOS Keychain·Linux Secret Service에서.
- [ ] `launchctl print system/io.qsh.<mode>`의 root 요구 확인(ADR-0032 결정 18 셋째 항목).
- [ ] Windows `Password` 주체 작업의 Credential Manager 읽기(ADR-0032 결정 15 첫 항목). M19가 `keystore_session_bound`를 보수적으로 내는 것으로 닫았고, 실측은 열려 있다.
- [ ] Windows OpenSSH Server 위의 `qsh pair ssh-respond`. Dave-Windows에 OpenSSH Server를 켜는 것은 사람이 한다. 두 장비 회차는 캠페인 W7이다.
- [ ] Windows 방화벽 첫 허용 프롬프트의 실제 문안과 README·doctor `udp_egress_blocked` 안내의 대응(ADR-0035 결정 25 개정 이력 2026-10-18). Windows Server에서의 같은 판정을 포함해 캠페인 W2가 본다.

- [x] `trust_withdrawal::listen::listen_closes_a_withdrawn_peer_that_stopped_reading_the_control_stream`의 CI 흔들림(run 39135082029). 원인은 테스트 쪽이다. 흐름에 막힌 peer는 보내는 것이 없어서 host의 CONNECTION_CLOSE 한 장을 놓치면 다음 keep-alive(15초)까지 모르고, 대기 한도는 8초다. `448d69a`가 닫힘 대기 중 probe를 보내게 고쳤고, 같은 커밋이 Windows 부하에서 나온 `unreadable_trust_toml_defers_the_comparison_until_it_can_be_read`의 공유 위반(32) 흔들림과 ConPTY `conpty_last_byte_arrives_before_the_exit_event`의 escape 순서 의존도 고쳤다. 부하 Linux 50/50, Windows 50/50. `session_follow`의 두 세션 바이트 비교는 `e7997f4`가 한 세션 ring 두 번 읽기로 바꿨다.

M20이 더했던 ConPTY 배치 실측 셋(ADR-0035 결정 20)은 `d538468`·`bd4b272`, 신호 사건 실측 둘(결정 22)은 `a475f08`이 닫았다.

## 2. 테스트 환경

- CI의 `windows-latest` leg은 clippy, `cargo nextest run --workspace`, `cargo doc -D warnings`를 돌고, Windows host의 PTY·`exec`·파일 op·응답자를 정방향과 역방향으로 덮는다. 로컬 Windows 검사는 Dave-Windows(`ssh dave-windows.tail91e9e.ts.net`)에서 하고 CI를 대신하지 않는다.
- 부하 반복은 Linux·공통 테스트를 Dave-Windows-WSL(8 vCPU)에서, Windows 전용 타이밍 민감 테스트를 Dave-Windows에서 `scripts/stress/run.sh`로 돈다. 마일스톤별 필터는 `scripts/stress/m<N>.filter`다.
