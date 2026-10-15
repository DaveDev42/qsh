# PLAN.md — M17: 운영 표면

P1 M17의 실행 계획이다. M16이 닫혀 이 문서가 M16 계획(마지막 커밋 `66b6f4d`)을 전면 교체했다. 착수 ADR 둘(ADR-0032 서비스 매니저 실호출, ADR-0033 세션 및 audit 관리 개선)은 2026-10-14 사용자 위임 결정("전부 다 알아서 진행해")으로 `승인됨`이 되었다(`09266dc`). (b) README 재작성은 `2fc879b`로 착지했고 (c) QR pairing은 2026-10-12에 폐기했다. 남은 범위는 (a)와 (d)이고 착수 조건은 모두 충족됐다. M17에 새 ADR은 필요 없다(Step 1 (a) 4). 구속 근거는 다음과 같다.

- `docs/ROADMAP.md` §5의 M17 절(범위 (a)~(d), 착수 조건, 명시적 out, 수용 기준, 크기), §5.1 시퀀싱 원칙(특히 원칙 6·7), §5.5 P1 사람 몫, 마일스톤 마감 공통 절차(같은 문서 §2), §3 유예 가드레일의 "Service 설치" 행
- ADR-0032 결정 1~18과 결과 절, ADR-0033 결정 1~13과 결과 절
- 두 ADR이 기대는 결정: ADR-0024 결정 11(활성화는 별도 결정), ADR-0017 결정 1(`acl.toml`을 쓰지 않음), ADR-0007(resume token custody), ADR-0010(audit 회전·retention의 유계), ADR-0013(개인키는 인자·결과로 나가지 않음), ADR-0022 결정 3·4, ADR-0025 결정 4(열거 oracle), ADR-0045 결정 16(audit `role` 키)
- 참조 ADR: ADR-0035 결정 9·12·13·14·24·25·27·28(Windows DACL, Credential Manager, Windows 경로, named pipe localctl, host audit 잠금, Windows host, 작업 스케줄러 백엔드와 상시 기동 작업, COM 상태 질의. Windows client는 M19, Windows host는 M20)
- `docs/CLI.md` §2.4·§2.5·§6.2·§6.11·§6.17·§6.18과 새 `qsh audit` 절
- `docs/deploy/service.md`, `docs/design/architecture.md` §2·§6·§7, `docs/design/testing.md` L1, `docs/design/threat-model.md` §3·§4 D·E·F·G·§7
- `CLAUDE.md` "Security defaults"

이 계획과 `docs/ROADMAP.md`의 편집은 main 세션만 한다.

인용 규율은 M16판과 같다. 문서는 절 이름, ADR 번호와 결정 번호, 테스트 이름, 커밋 해시로 가리킨다. 코드 위치는 파일 경로와 심볼 이름으로 가리키고, 줄 수나 개수를 적을 때는 origin `7c43332` 트리에서 잰 값임을 밝힌다. 옛 계획의 스텝은 "M16 plan Step N (`66b6f4d`)" 꼴로만 인용한다. 코드 주석과 문서에는 이 계획의 스텝 번호를 쓰지 않는다.

## 0. 열린 사람 몫

여기 적힌 항목은 이 파일이 다음 계획으로 바뀔 때 그대로 승계한다. M16 계획 §0의 상태를 M16 마감 시점 그대로 옮겼다.

### 0.1 P0에서 열린 일곱


- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** 기준은 `docs/campaigns/m10-clean-vm.md`. Linux 회차는 PASS(v0.3.0 세 회차 `69a6414`, v0.4.3 Ubuntu 24.04 x86_64 회차 4, 2026-10-09). macOS arm64·x86_64 두 회차가 남았고 둘 다 클린 macOS VM과 Gatekeeper 판정이 필요하다. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 서명·공증 태그는 `v0.4.0`부터 있다. 회차는 `docs/campaigns/m10-clean-vm.md`. 소유: 사람.
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** `x86_64-unknown-linux-musl` 한정. Debian 10(glibc 2.28) 회차 2(v0.3.0)와 회차 5(v0.4.3, 2026-10-09)가 `DoD 3 = PASS`다. 캠페인 §9 판정과 함께 닫히므로 macOS 두 회차를 기다린다. 두 회차 모두 에이전트가 컨테이너에서 돌렸으니, 캠페인을 닫을 때 사람이 이것을 회차로 셀지 다시 본다. 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** 기준은 `docs/campaigns/m7-stopwatch.md`(예행 1회만 끝남). 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** 기준은 `docs/campaigns/m2-mobility.md`. M18의 착수 조건. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** 저장소 밖 조직 액션. 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** 기준은 `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 소유: 사람.

마지막 줄(M9 DoD 1)은 M16 계획 §0.1에서 빠져 있었다. 제목은 "일곱"인데 여섯 줄만 있었다. M15 계획(`7cbeced`)의 같은 줄을 문면 그대로 되살렸고, `docs/ROADMAP.md` "P0 MVP 완료 선언의 조건" 표의 일곱과 맞는다(§9 #7).

### 0.2 P1 마일스톤이 만든 사람 몫 (`docs/ROADMAP.md` §5.5)


- [ ] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 기록 자리는 `docs/campaigns/m8-fuzz.md`. 출처 M11. 소유: 사람.
- [ ] **`p1-supervise-wake` 회차 넷.** 기준은 `docs/campaigns/p1-supervise-wake.md`. 출처 M12. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 기준은 `docs/campaigns/p1-setup-stopwatch.md`(ADR-0024 결정 12). 출처 M12. PASS가 기록되기 전에는 이슈 #3 완료 기준 첫 줄이 충족됐다고 적지 않는다. 소유: 사람.
- [ ] **`decode_file_frame` fuzz 타깃의 누적 72 fuzz-hours.** M15 (b)가 타깃을 더했다(`a86123d`). 기록 자리는 `docs/campaigns/m8-fuzz.md` 형식이고, §5.5 표의 "새 파서 fuzz 타깃" 행("M15의 새 decode 타깃")에 상태를 적는다. 공개 beta 전에 끝나야 한다(`docs/design/protocol.md` §13). 소유: 사람.

### 0.3 M16이 만든 사람 몫 (`docs/ROADMAP.md` §5.5)

아래 두 줄은 M16 계획 §0.3을 문면 그대로 옮긴 것이다. 줄 안의 "Step 4", "Step 8", "Step 1", "§9 #3"은 M16 계획(`66b6f4d`)의 번호이고 이 문서의 스텝이 아니다.

- [ ] **`parse_ssh_bootstrap_line` fuzz 타깃의 누적 72 fuzz-hours.** Step 4가 타깃을 더한다. 기록 자리는 `docs/campaigns/m8-fuzz.md` 형식이고 §5.5 표의 "새 파서 fuzz 타깃" 행(이미 "M16 (a) `parse_ssh_bootstrap_line`"을 적어 둠)에 상태를 적는다. 공개 beta 전에 끝나야 한다(`docs/design/protocol.md` §13). 소유: 사람.
- [ ] **실제 OpenSSH 위의 SSH 부트스트랩 회차.** ADR-0044 결과 절의 사람 캠페인이다. ProxyJump, ssh-agent, 암호 걸린 키 위에서 처음 `qsh box`부터 셸 프롬프트까지, 그리고 `--reverse` 구도 한 회. 문서 `docs/campaigns/p1-ssh-bootstrap.md`는 Step 8이 사전 고정한다(구현 마지막 스텝 전). Windows `ssh.exe` client 회차는 Windows 대화형 client가 서는 M19의 `docs/campaigns/p1-windows.md`가 이어받는다(§9 #3). §5.5 표에 행을 더하는 일은 main 세션이 Step 1에서 한다. 소유: 사람.

### 0.4 M17이 새로 만드는 사람 몫

M17은 새 캠페인 문서를 만들지 않는다. ADR-0032·0033 결과 절 어디에도 사람 회차가 없다. 실제 Keychain·Secret Service 위의 `move-key` 왕복은 캠페인이 아니라 `docs/design/testing.md` L1의 릴리스 전 수동 단계이고(ADR-0032 결과 절), §1이 추적한다. 에이전트는 `gh secret set`, `gh workflow run`, 태그 push, 저장소 설정 변경을 어느 스텝에서도 하지 않는다.

## 1. 유지보수에서 남은 확인

- [ ] macOS Keychain 왕복. `keyring-core` 1과 플랫폼 store crate로 옮긴 변경(`08a6173`)의 Linux Secret Service 왕복은 확인했지만, macOS 쪽은 Dave-MBP16이 오프라인이라 못 했다. 다음 태그 전에 `docs/design/testing.md` L1의 수동 단계로 돌린다.
- [ ] 다음 태그 run에서 `release.yml` 액션 갱신(`1557f50`) 뒤의 서명·공증·provenance를 확인한다.
- [ ] `qsh identity move-key` 왕복(platform → file → platform)을 macOS Keychain과 Linux Secret Service에서 돌린다. Step 3이 `docs/design/testing.md` L1에 더하는 수동 단계다. Windows Credential Manager 왕복은 Windows `platform` store가 서는 M19(ADR-0035 결정 12)의 몫이다. 위 첫 항목과 같은 회차에 묶을 수 있다.
- [ ] `launchctl print system/io.qsh.<mode>`가 root 없이 exit code로 실행 여부를 돌려주는지 실제 Mac에서 확인한다(ADR-0032 결정 18 셋째 항목). 확인 전에는 Step 2가 ADR이 미리 정한 대체(`INTERNAL`, `step: "live"`, `sudo` 안내)로 착지한다(§9 #5). Dave-MBP16이 돌아오면 에이전트가 확인하고 결과를 커밋 본문에 적는다.

## 2. 테스트 환경

M16과 같다. 호스트 nftables의 `inet dave_mosh` 표 문제는 dave-environment `c6c5359c`와 저장소 `414f1fd`가 막는다(loopback UDP 자가 점검, `scripts/test/nextest-ns.sh`, 긴 TMPDIR에서의 unix 소켓 경로 단축). M16의 가짜 `ssh` 하네스(`crates/qsh-testkit/src/bin/qsh-fake-ssh.rs`)는 그대로 남는다.

M17이 더하는 것은 실제 외부 상태를 건드리지 않는 주입점 셋이다.

- 기록용 가짜 `ManagerRunner`(ADR-0032 결정 10). 실제 `launchctl`/`systemctl`/`schtasks`를 부르는 테스트는 만들지 않는다.
- `move-key`의 store 주입. 기존 `KeyStore` trait과 `MemoryKeyStore`(`crates/qsh-core/src/identity/keystore.rs`)를 `platform` 자리에 꽂는다. 실제 OS store 왕복은 §1의 수동 단계다.
- doctor probe의 시스템 경로 뿌리. `/Library/LaunchDaemons`와 linger 디렉터리를 tempdir 아래로 돌려 읽는다(§7.1 #3).

부하 반복은 Dave-Windows-WSL(8 vCPU)에서 돈다. M15·M16 기록과 같은 호스트다.

## 3. DoD 체크리스트 (ROADMAP M17)

체크박스는 근거가 되는 테스트와 CI run이 초록일 때만 채운다.

- [x] **DoD (a) — ADR-0032가 `승인됨`이다.** 근거: `09266dc`(2026-10-14). 소유: 에이전트(main 세션 확인).
- [ ] **DoD (a) — 플래그 없이는 매니저를 부르지 않는다.** `install_without_activate_never_invokes_the_manager`, `uninstall_without_deactivate_never_invokes_the_manager`, `status_without_live_never_invokes_the_manager`. 플래그 없는 호출의 출력은 기존 fixture와 바이트가 같다. 근거: Step 2.
- [ ] **DoD (a) — 부르는 argv가 `docs/deploy/service.md`의 안내와 같다.** 문서-코드 대조 `service_md_activation_recipes_match_the_argv_builders`. 테스트는 실제 매니저를 부르지 않는다. 근거: Step 2.
- [ ] **DoD (a) — `docs/CLI.md` §6.18과 man이 같은 커밋에서 바뀐다.** `qsh-service-install.1`·`qsh-service-uninstall.1`·`qsh-service-status.1`, `checked_in_man_pages_match_the_generator`. 근거: Step 2.
- [ ] **DoD (a) — LaunchDaemon 펜스가 LaunchAgent 렌더러와 같은 인자를 쓴다.** `service_md_launchdaemon_recipe_matches_the_agent_program_arguments`. 근거: Step 4.
- [ ] **DoD (a) — `keystore_session_bound`와 `identity.move_key`의 테스트와 fixture 등록 완전성, `move-key`가 fingerprint를 바꾸지 않음.** 다음을 갖춘다. 근거: Step 3·4.
  - `move_key_keeps_the_fingerprint_and_device_id`
  - `identity.move_key` fixture 둘과 doctor fixture 하나의 `REQUIRED_FIXTURES` 등재, `layer_2_every_schema_command_has_all_six_faces`, `op_registration_completeness.rs`의 `OP_FACES` 행
  - man `qsh-identity-move-key.1`
- [x] **DoD (b) — README 재작성판, 두 SHA 고정 커밋 뒤.** 재작성 `2fc879b`(2026-10-11)는 m9 대상 트리 고정 `1a7798d`와 `p1-setup-stopwatch` 고정 `43da2fb`의 자손이다(`git merge-base --is-ancestor`로 확인). 마감 공통 절차 2를 재작성판에 대해 수행하는 일은 아래 마감 줄이 맡는다.
- [x] **DoD (c) — PRD §17 개정 결정이 기록된다.** 2026-10-12 폐기로 충족.
- [ ] **DoD (d) — ADR-0033이 `승인됨`이다.** 근거: `09266dc`(2026-10-14). 소유: 에이전트(main 세션 확인). 이 줄은 Step 1이 확인하고 채운다.
- [ ] **DoD (d) — 범위 ADR이 정한 항목마다 테스트와 fixture 등록 완전성.** 세션 필터(결정 1~3), `audit.query`(결정 4~9), retention 가시성(결정 10·11), 텔레메트리 처분(결정 12), 동등(결정 13). 근거: Step 5·6·7.
- [ ] **DoD (d) — `audit.query`에 대응하는 wire 메시지가 없음을 op registry 분류 테스트가 확인한다.** `op_registration_completeness.rs`·`acl_registry.rs`의 local-only 분류와 `audit_query_has_no_wire_message_and_no_localctl_request`. 근거: Step 7.
- [ ] **계획 규율 — route·플랫폼 동등.** 각 스텝의 동등 테스트가 초록이고, M19·M20으로 미룬 Windows 항목이 §6과 각 스텝 "Windows" 줄에 ADR 결정과 함께 귀속돼 있다(§5.1 원칙 7). 근거: Step 2~7.
- [ ] **계획 규율 — 위협 모델.** `docs/design/threat-model.md` §3의 `qsh service` 행 개정과 새 진입점 둘(`identity move-key`, `qsh audit`), §4의 매니저 인자 주입(E)·재시작 부재(G)·이동 중 개인키 노출(D)·audit 열람 oracle과 삭제 경로 부재(F)가 핀 테스트와 함께 오른다. 각 행은 그 통제를 구현한 스텝에서 오른다. 근거: Step 2·3·4·7.
- [ ] **DoD 마감 — 마감 공통 절차(§2) 1·2.** 근거: Step 8.
- [ ] **안정성 — 새 타이밍 민감 테스트의 부하 반복.** M17이 더한 타이밍 민감 테스트 전부가 `scripts/stress/m17.filter`로 묶여 `scripts/stress/run.sh`로 CPU 부하 아래 50회 연속 초록이다. M17에는 지연 예산 단언이 없으므로 `-j 1` 대체 필터를 두지 않는다. ROADMAP M17 DoD에는 아직 이 줄이 없고 Step 1이 더한다(§9 #1). 근거: Step 3·5·6·7·8.

## 4. 실행 단계 (PR 단위)

스텝 번호는 이 문서 안에서만 쓰는 참조다. 크기는 다음과 같다.

| 묶음 | 스텝 | 합(ew) | ADR·ROADMAP 산정 | 비고 |
|---|---|---|---|---|
| (a) ADR-0032 | Step 2~4 | 1.0~1.5 | 구현 1.0~1.5(ADR-0032 결과 절) | ADR 작성분 0.3은 이미 소진 |
| (d) ADR-0033 | Step 5~7 | 1.2~1.8 | 구현 1.2~1.8(ADR-0033 결과 절) | ROADMAP은 "구현 미산정"으로 남아 있다(§9 #2). 범위 ADR 0.2~0.3은 이미 소진 |
| 마감 | Step 8 | 0.1~0.2 | 0.1~0.2 | |
| 합 | | 2.3~3.5 | ROADMAP 2.1~3.1 + 미산정 | ROADMAP 2.1~3.1에서 소진분((a) ADR 0.3, (b) 0.5~0.8, (d) ADR 0.2~0.3)을 빼면 1.1~1.7이고, 여기에 (d) 구현 1.2~1.8을 더하면 2.3~3.5로 이 표와 같다 |

Step 1은 크기 내역 밖이다.

**순서의 근거.**

- (a)와 (d)는 코드가 겹치지 않는다. (a)는 `crates/qsh-core/src/ops/service/`, `ops/identity.rs`, `identity/`, `doctor.rs`·`doctor/probe.rs`, `docs/deploy/service.md`를 만지고, (d)는 `ops/session.rs`, `audit.rs`·`audit/`, 새 `ops/audit.rs`, `qsh-proto`의 새 타입을 만진다. 그래서 두 사슬을 병렬로 연다. 겹치는 곳은 `docs/CLI.md` 상태 헤더와 §2.4·§2.5, `REQUIRED_FIXTURES`, `OP_FACES`, `CLI_V1_SCHEMA_COMMANDS`, threat-model §3이고 늦게 착지하는 쪽이 rebase로 푼다.
- (a) 안에서는 활성화(Step 2)를 먼저 둔다. ADR-0032 처음 판의 핵심이고 §6.18 계약 개정이 여기 있다. 사람이 설치한 상시 기동 형태를 건드리지 않는 규칙(결정 18)은 `--activate`·`--deactivate`의 분기라서 활성화와 같은 스텝에 싣는다. 나중 스텝으로 미루면 그 사이 macOS에서 `--activate`가 LaunchDaemon과 같은 label을 `gui` 도메인에 적재하는 창이 생긴다.
- `move-key`(Step 3)를 doctor(Step 4)보다 먼저 둔다. `keystore_session_bound`의 remedy와 `service.md` 상시 기동 레시피의 한 줄이 `qsh identity move-key --to file`을 가리키므로, 그 명령이 먼저 있어야 안내가 실제 명령을 가리킨다.
- (d) 안에서는 세션 필터(Step 5)가 가장 작고 독립적이라 먼저 둔다. audit 조회는 읽기 코어(Step 6, 사용자 표면 없음)를 먼저 세우고 op·CLI·계약 문서(Step 7)를 나중에 얹는다. M16의 줄 파서 → op 순서와 같은 모양이다.

**의존과 병렬.**

| 스텝 | 선행 | 다른 에이전트와 병렬 가능 여부 |
|---|---|---|
| Step 2 | Step 1 | Step 5·6과 병렬 가능 |
| Step 3 | Step 2(`docs/CLI.md` 헤더 순서, `ops/` 등록 표) | Step 5·6·7과 병렬 가능. Step 3은 `identity/`와 `ops/identity.rs`를 만진다 |
| Step 4 | Step 2(결정 18의 LaunchDaemon 경로 상수), Step 3(remedy가 가리킬 명령) | Step 6·7과 병렬 가능. 겹치는 곳은 `docs/CLI.md` §6.17 진단 개수 문장 하나뿐이다(Step 7은 진단을 더하지 않는다) |
| Step 5 | Step 1 | Step 2·3·4와 병렬 가능 |
| Step 6 | Step 1 | Step 2·3·4·5와 병렬 가능. 사용자 표면이 없어 계약 문서를 만지지 않는다 |
| Step 7 | Step 6 | Step 3·4와 병렬 가능하지만 `REQUIRED_FIXTURES`·`OP_FACES`·§2.4·§2.5가 같은 줄 근처라 rebase가 필요하다 |
| Step 8 | 전부 | — |

**규율.** 앞 마일스톤 그대로이고 M17에서 몇 가지를 덧붙인다.

- 각 스텝은 일곱 게이트(`cargo fmt --all --check`, clippy `-D warnings`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`, `cargo xtask arch`, `cargo deny check`)가 초록인 채로 착지한다. clippy와 test는 `ci.yml`의 `windows-latest`·`macos-14` 다리에서도 돈다. M16 규율대로 `cfg(unix)`/`cfg(windows)` 분기, 경로 표기, 자식 프로세스, 파일 열기 모드를 건드리는 스텝(Step 2·3·4·6)은 push 전에 로컬에서 Windows 타깃 검사(`cargo xwin clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings`와 같은 타깃의 `cargo xwin doc`)를 돌린다. xwin이 없는 머신에서는 Dave-Windows(`ssh dave-windows.tail91e9e.ts.net`)에서 같은 두 명령을 돌린다. 이 검사로 CI의 Windows 다리를 대신하지 않는다. 착지 판정은 CI 초록이다. 특히 Step 2·4의 launchd 분기는 macOS 다리에서만 컴파일되는 코드가 생기지 않게, 판정·argv 빌더를 `cfg` 없는 순수 함수로 두고 `cfg`는 `resolve_manager` 한 곳에만 남긴다(§7.1 #1).
- 계약 문서 델타는 그 표면을 바꾼 스텝의 같은 커밋에 싣는다.
  - `docs/CLI.md` 상태 헤더의 v0.35 항목은 CLI.md를 처음 고치는 스텝(Step 2 또는 Step 5 중 먼저 착지하는 쪽)이 열고, 뒤 스텝은 "같은 v0.35에"로 덧붙이거나 다음 판을 연다(`crates/qsh-core/tests/it/cli_md_header.rs` 핀, 새 판이 옛 판 뒤에 오지 않음).
  - clap 트리가 바뀌는 스텝(Step 2·3·5·7)은 같은 커밋에서 `cargo xtask man`을 돌린다.
  - doctor code는 Step 4가 하나(`keystore_session_bound`)만 더한다. 진단 개수 문장 26 → 27은 `docs/CLI.md` §6.11 끝 문장과 §6.17 머리 문장 두 곳이고 `EXPECTED_DOCTOR_CODES`(`crates/qsh-core/src/doctor.rs`)와 같은 커밋에서 바뀐다.
- 판정 로직은 `qsh-core`에 둔다. 매니저 호출과 상시 기동 판정은 `ops/service/`, 키 이동은 `ops/identity.rs`와 `identity/`, 세션 필터는 클라이언트 `Ops`(`ops/session.rs`), audit 읽기와 필터는 `qsh-core`의 새 모듈(가칭 `audit/reader.rs`)과 `ops/audit.rs`다. `qsh-proto`에는 계약 타입(`ServiceInstallData` 등의 additive 필드, `IdentityMoveKeyReq`·`IdentityMoveKeyData`, `AuditQueryReq`·`AuditQueryData`·`AuditRecordView`)만 들어간다. `qsh-cli`에는 clap 플래그, 렌더러, 필터 인자 전달만 둔다(ADR-0032 결정 10, ADR-0033 결과 절 "아키텍처 규칙").
- **wire 소유.** M17의 어느 스텝도 `.proto`를 바꾸지 않는다. ADR-0032 결정 17과 ADR-0033 결정 2·4가 근거다. 완료 판정마다 다음을 확인한다.
  - `git diff --stat -- crates/qsh-proto/proto crates/qsh-proto/src/wire.rs crates/qsh-proto/src/local.rs crates/qsh-cli/tests/fixtures/cli-v1/capabilities.json`이 비어 있다.
  - `ErrorCode`는 어느 스텝에서도 바뀌지 않는다. 새 실패는 기존 코드(`UNSUPPORTED`, `INTERNAL`, `TIMEOUT`, `CONFIG_ERROR`, `INVALID_ARGUMENT`)에 붙는다.
  - `SessionListReq`는 바뀌지 않는다(ADR-0033 결정 2). 필터는 그 밖의 인자로 `Ops`에 들어간다(§7.1 #6).
  - 구현 중 wire 변경이 필요해 보이면 그 스텝은 착지하지 않고, main 세션이 새 ADR 필요 여부를 정한다(`CLAUDE.md` 머리말).
- fixture는 추가만 한다. 새 fixture마다 실제 바이너리로 재현하는 `golden_*` 생산 테스트를 같은 커밋에 둔다. 기존 `service.*`·`identity.*`·`session.list`·`doctor.*` fixture는 고치지 않은 채 초록이어야 한다. `capabilities.json`은 바뀌지 않는다(새 peer capability 없음). 바뀌면 그 스텝이 잘못된 것이다.
- **테스트 배치.** 통합 테스트는 `crates/<crate>/tests/it/<name>.rs` 모듈로 두고 같은 커밋에서 `crates/<crate>/tests/it/main.rs`에 `mod <name>;`을 등재한다. 새 `tests/*.rs` 파일을 crate 최상위에 두지 않는다. nextest 이름은 `<name>::<test>`이고 한 모듈만 돌릴 때는 `--test it -E 'test(/^<name>::/)'`이다. 단위 테스트는 소스 옆 `tests.rs`에 둔다.
- **route 동등(§5.1 원칙 7, PRD §4).** M17의 표면은 원격 op을 더하지 않지만, 운영 표면은 세 역할(forward host `qsh serve`, reverse listener `qsh listen`, reverse target `qsh serve --to`) 모두에 같아야 한다. 스텝마다 다음을 같은 스텝의 테스트로 단언한다.
  - (a) 활성화·비활성화·`--live`는 세 mode(`serve`, `listen`, `reverse`)의 유닛 이름과 label에서 같은 argv 모양이다(Step 2). `keystore_session_bound`는 세 mode 유닛 어느 것이 상시 기동이어도 낸다(Step 4). `move-key` 뒤 세 프로세스가 상대 장비의 pin을 고치지 않은 채 다시 handshake한다(Step 3).
  - (d) 세션 필터는 forward host와 reverse host(`qsh sessions <reverse host>`, 데몬의 reverse 항목 fan-out)에서 같은 결과다(Step 5). `qsh audit`은 세 프로세스가 쓴 레코드를 같은 모양으로 돌려준다(Step 7).
  - 한쪽 route만 덮는 PR은 착지하지 않는다.
- **플랫폼 동등(PRD §4, 예외 없음).** 결정의 동작은 세 OS에서 같다. 플랫폼 차이는 ADR이 이미 M19·M20에 귀속시킨 것만 미루고, 스텝마다 무엇을 미루는지를 그 스텝의 "Windows" 항목에 적는다. 요약은 다음과 같다.
  - (a) 활성화. Linux(systemd)와 macOS(launchd)는 M17이다. 작업 스케줄러 분기(`schtasks` argv, COM 실행 상태 질의, Windows 레시피와 그 문서 대조, `/Create /F`의 실행 중 인스턴스 실측)는 M19다(ADR-0032 결정 4·10·11, ADR-0035 결정 27·28). M17은 `ManagerRunner`와 실행 상태 질의 trait을 그 모양으로 세우고 Windows 빌드에서도 컴파일한다. M17 Windows 빌드의 `qsh service`는 플래그가 있어도 지금처럼 `SERVICE_UNSUPPORTED_PLATFORM`으로 먼저 끝난다.
  - (a) 상시 기동 레시피. Linux linger는 이미 있고 macOS LaunchDaemon은 M17이다. Windows 상시 기동 작업 레시피와 `Password` 주체 판정(결정 18의 Windows 갈래)은 M19다(ADR-0035 결정 27).
  - (a) `keystore_session_bound`. macOS·Linux는 M17이다. Windows는 `LogonType=Password` 작업이 Credential Manager를 읽는지 실측한 뒤 M19가 정한다(ADR-0032 결정 15 첫 항목).
  - (a) `move-key`. op과 순서·결과는 세 OS에 M17에서 연다. Windows `platform` store(Credential Manager)는 M19(ADR-0035 결정 12)라서 M17 Windows 빌드의 `--to platform`은 `identity.init --key-store platform`과 같은 `INTERNAL`이고, Windows의 파일 store 소유자 전용 DACL은 M19(ADR-0035 결정 9)다. M17 Windows 빌드에는 옮길 `platform` 키가 존재할 수 없으므로 실제로 일어나는 것은 `moved: false`뿐이다.
  - (d) `qsh audit`. 세 OS 모두 M17이다(ADR-0033 결정 13). Windows는 `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`로 연다(결정 6). host audit writer의 `LockFileEx` 잠금은 M20(ADR-0035 결정 24)이고 조회와 겹치지 않는다.
  - (d) 세션 필터. 필터 함수와 forward route는 세 OS 모두 M17이다. 실제 PTY 세션이 필요한 e2e는 Windows host PTY가 M20(ADR-0035 결정 25)이라 `cfg(unix)`이고, Windows `qsh listen` 데몬 fan-out의 reverse 쌍둥이는 M19(ADR-0035 결정 14)다.
- 손대는 소스 파일이 800줄을 넘으면 인라인 테스트를 같은 커밋에서 형제 `tests.rs`로 옮긴다. origin `7c43332` 기준 `crates/qsh-core/src/ops/session.rs`(1327줄)가 이미 넘었으므로 인라인 테스트가 남아 있는지 먼저 확인한다. `ops/service/mod.rs`(491줄)와 `doctor.rs`(690줄), `audit.rs`(745줄)는 M17 변경으로 800줄을 넘길 수 있고, 넘기는 커밋이 옮긴다.
- 안정성 규율은 M16과 같다. 시계를 주입하고(매니저 호출 30초 기한, `--since`의 상대 시각), 관찰 가능한 상태를 넉넉한 `timeout`으로 기다리며, 고정 `sleep()`은 쓰지 않는다. 타이밍 민감 테스트(실제 QUIC loopback, 실제 프로세스 기동, writer 회전과 겹치는 읽기)는 그 스텝의 완료 판정에서 부하 아래 50회 연속 초록이어야 착지한다. 필터 `scripts/stress/m17.filter`의 초안은 타이밍 민감 테스트를 처음 더하는 스텝(Step 3 또는 Step 5, 먼저 착지하는 쪽)이 만들고 Step 8이 완성한다. 부하 아래에서 흔들리는 테스트는 대기 조건을 고친다. 필터에서 빼거나 `-j 1`로 옮기지 않는다(M17에는 지연 예산 단언이 없다).

### Step 1 — M17 계획 교체와 ROADMAP 갱신 (main 세션, 크기 내역 밖)

근거: `docs/ROADMAP.md` 현재 위치와 M17 절, ADR-0032·0033 결과 절의 문서 목록. 선행: M16 마감(M16 plan Step 10 (`66b6f4d`))과 그 마감 노트. 두 ADR 승인(`09266dc`).

**(a) 범위:**

1. `PLAN.md`를 이 문서로 바꾼다. ROADMAP M16 마감 노트에 M16 계획의 마지막 커밋 해시가 적혀 있는지 확인하고, 이 문서의 `66b6f4d` 자리 전부를 그 해시로 바꾼다.
2. `docs/ROADMAP.md`를 고친다.
   - 현재 위치를 "현재 마일스톤은 M17"로 바꾼다.
   - M17 DoD에 안정성 줄을 더한다(§9 #1).
   - M17 크기 줄, §5.2 표의 M17 행, 머리말 "총 크기" 문장의 "미산정 둘"을 ADR-0033 결과 절의 (d) 구현 1.2~1.8ew로 갱신한다(§9 #2).
   - §5.4 리스크 1의 "제안 ADR 여섯" 문장을 2026-10-14 승인 뒤의 상태로 고친다(§9 #3).
   - M19 수용 기준에 ADR-0032 Windows 열의 귀속 한 줄을 더한다(§9 #4).
3. README Roadmap 표의 M16 행을 "Done"으로, M17 행을 "In progress"로 고친다(현재 `M17–M20` 한 행이므로 M17을 따로 뗀다).
4. ADR 준비 점검. 두 ADR은 승인됐고 M17에 새 ADR은 필요 없다. 다음 셋의 실제 상태를 확인해 이 계획 §9에 적는다(ADR 본문은 고치지 않는다).
   - ADR-0032 결정 18 셋째 항목의 `launchctl print system/…` root 여부는 ADR이 대체를 미리 정했으므로 개정 없이 구현 중 정한다(§9 #5).
   - ADR-0033 결정 13의 "CLI 새 절 번호는 그때 가장 큰 `§6.N` 다음"은 origin `7c43332` 기준 §6.21(`qsh cp`) 다음인 §6.22다(§9 #9).
   - ADR-0033 맥락 절의 "로컬 op 중 audit을 남기는 것은 `trust.rename`과 `service.*`뿐(F5)"은 ADR-0045·0044 착지로 낡았다. 결정에는 영향이 없고, threat-model F5·h26 문면만 Step 7이 대조한다.
5. 이 문서 §3의 "DoD (d) — ADR-0033이 `승인됨`" 줄을 채운다.

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록.

**(c) 완료 판정:** `PLAN.md` 첫 줄이 이 문서의 제목이다. ROADMAP 현재 위치가 M17을 가리키고 M17 DoD에 안정성 줄이 있으며, M17 크기에 "미산정"이 남아 있지 않다.

### Step 2 — (a) 서비스 매니저 실호출: `ManagerRunner`, `--activate`·`--deactivate`·`--live`, 상시 기동 형태 보존, §6.18·man·fixture (0.35~0.55ew)

근거: ADR-0032 결정 1~11, 18과 결과 절의 첫 세 항목. 선행: Step 1.

**(a) 범위:**

- `crates/qsh-core/src/ops/service/`:
  - `ManagerRunner` trait(argv와 제한 시간을 받아 exit 상태와 stderr 첫 줄을 돌려줌)과 Windows 실행 상태 질의 trait(작업 이름 → 실행 중 여부)을 둔다(결정 10). 기본 runner는 `std::process::Command`에 인자 배열로 넘기고 셸을 거치지 않는다. 공개 `Ops::service_*`만 기본 runner를 만들고 `*_with_home` 쌍둥이는 runner를 인자로 받는다.
  - 결정 3 표의 argv 빌더(launchd, systemd)를 `cfg` 없는 순수 함수로 둔다. 인자는 euid, 유닛 경로, 닫힌 집합 `<mode>`뿐이다. Windows 열의 빌더는 M19다.
  - `install --activate`: 오늘의 prefix 전체 성공 뒤 마지막 단계(결정 2). launchd는 `launchctl print gui/<uid>/io.qsh.<mode>`가 0이면 `bootstrap`을 부르지 않고 `already_active`, systemd는 `daemon-reload`와 `enable --now`를 부르고 `restart`는 어떤 경우에도 부르지 않는다(결정 4). 유닛 파일 쓰기 실패와 audit 실패면 매니저를 부르지 않는다.
  - `uninstall --deactivate`: 등록 여부로 판정하고 해제가 먼저, 파일 삭제가 나중이다(결정 5). 해제가 실패하면 파일을 지우지 않는다. `stopped`/`not_active`.
  - `status --live`: 결정 3 "이미 떠 있는지" 질의의 exit code 하나만 읽는다. 유닛 파일이 없으면 매니저를 부르지 않고 `active: false`(결정 6).
  - 상시 기동 형태 보존(결정 18의 macOS 갈래). 같은 mode의 `/Library/LaunchDaemons/io.qsh.<mode>.plist`가 있으면 `--activate`는 파일만 쓰고 `always_on_present`, `--deactivate`는 `gui` 도메인 해제만 결정 5대로 하고 파일을 지운 뒤 `always_on_present`. `--live`는 그 형태의 실행 여부다. `launchctl print system/…`가 root 없이 되는지 확인되기 전에는 ADR이 정한 대체(`INTERNAL`, `step: "live"`, message가 `sudo launchctl print system/io.qsh.<mode>` 안내)로 착지한다(§9 #5). LaunchDaemon 경로 상수는 Step 4의 doctor probe와 공유한다.
  - 오류(결정 8): spawn `NotFound`는 `UNSUPPORTED`(WSL이면 `/etc/wsl.conf`의 `systemd=true`, 그 밖에는 `docs/deploy/service.md` 안내), 0이 아닌 exit는 `INTERNAL`(`details.step`, `details.exit_code`, stderr 첫 줄 512바이트), 30초 초과는 `TIMEOUT`. macOS `gui/<uid>` 도메인 부재는 `user/<uid>`로 우회하지 않는다.
  - audit은 오늘 그대로 한 건이고 활성화 레코드를 더하지 않는다(결정 9). `status --live`는 audit을 쓰지 않는다.
  - 플래그는 config 키나 환경 변수로 기본값을 바꿀 수 없다(결정 1). `qsh setup`과 doctor는 이 플래그를 넘기지 않는다. `service_not_registered` remedy와 `setup`의 `next`가 `qsh service install --activate`를 안내하는 문면 변경은 이 스텝에서 한다.
- `qsh-proto`: `ServiceInstallData.activation`, `ServiceUninstallData.deactivation`, `ServiceStatusData.active`를 선택 필드로 더한다(`skip_serializing_if`, 결정 7).
- `qsh-cli`: clap 플래그 셋, human 렌더(`already_active`의 "다음 재시작에 반영" 한 줄과 `docs/deploy/service.md` 세션 손실 고지 안내, `always_on_present`의 레시피 재실행 안내).
- 문서(모두 이 커밋):
  - `docs/CLI.md` 상태 헤더 v0.35(또는 Step 5가 먼저 열었으면 덧붙임), §6.18 세 시그니처, "`status`는 존재 여부만 본다"와 "유닛 파일만 쓴다"의 플래그 예외, `data` 필드 설명, `--deactivate` 없는 `uninstall`은 떠 있는 유닛을 남긴다는 문장.
  - man 셋 재생성(`cargo xtask man`).
  - `docs/deploy/service.md`: launchd·systemd 절의 `--activate` 안내와 비활성화 레시피(결정 11). LaunchDaemon 레시피는 Step 4.
  - `docs/design/threat-model.md` §3 `qsh service` 행: "호출하지 않는다"를 "플래그가 있을 때만 결정 3 argv를 부르고 exit code만 읽는다"로. §4 E에 "매니저 호출 인자에 사용자 입력이 들어가 옵션·명령을 주입한다" 행(결정 3, 핀 `manager_argv_never_contains_user_input`), §4 G에 "`install` 재실행이 떠 있는 유닛을 재시작해 detach된 세션을 지운다" 행(결정 4, 핀 `activate_does_not_restart_an_already_active_unit`).
- fixture(추가만, `REQUIRED_FIXTURES`, `golden_*`): 플래그를 준 성공 envelope 셋(이름은 §7.1 #4). 기존 `service.install.json`·`service.uninstall.json`·`service.status.json`은 무변경 초록.
- Windows: trait 둘과 플래그는 Windows 빌드에도 들어간다. Windows `qsh service`는 플래그가 있어도 `SERVICE_UNSUPPORTED_PLATFORM`으로 먼저 끝나고 아무것도 부르지 않는다. 작업 스케줄러 argv 빌더, COM 질의 구현, `install_activate_runs_the_documented_argv_on_task_scheduler`, `windows_activate_updates_the_stored_task_without_running_it_when_already_running`, 결정 18의 Windows 갈래는 M19다(ADR-0032 결정 10, ADR-0035 결정 27·28).

**(b) 테스트·게이트:**

`crates/qsh-core/src/ops/service/tests.rs`(가짜 runner 주입)와 `crates/qsh-core/tests/it/service_docs.rs`.

- 부르지 않음: `install_without_activate_never_invokes_the_manager`, `uninstall_without_deactivate_never_invokes_the_manager`, `status_without_live_never_invokes_the_manager`
- argv: `install_activate_runs_the_documented_argv_on_launchd`, `install_activate_runs_the_documented_argv_on_systemd`, `install_activate_argv_covers_serve_listen_and_reverse_modes`(계획 추가, route 동등), `manager_argv_never_contains_user_input`(계획 추가, 컨트롤러 이름에 공백·따옴표·`--`를 넣은 config)
- 재시작 부재: `activate_does_not_restart_an_already_active_unit`
- 비활성화: `deactivate_calls_disable_for_a_registered_but_inactive_unit`, `deactivate_skips_when_the_unit_is_not_registered`, `deactivate_runs_before_the_unit_file_is_removed`, `a_failed_deactivate_keeps_the_unit_file`
- 상시 기동 보존: `activate_and_deactivate_leave_a_human_installed_always_on_form_untouched`(launchd 행. 작업 스케줄러 행은 M19), `status_live_reports_the_always_on_form_when_present`(launchd 행, §9 #5의 대체가 착지했으면 그 `INTERNAL`을 단언)
- 실패 순서: `activate_is_skipped_when_the_unit_write_fails`, `activate_is_skipped_when_the_audit_sink_fails`(기존 `install_is_refused_when_the_audit_sink_fails` 무변경 초록)
- 오류: `a_missing_manager_binary_is_unsupported_and_a_nonzero_exit_is_internal_with_exit_code`, `a_manager_call_past_the_deadline_is_timeout`(시계 주입), `manager_stderr_first_line_is_capped_at_512_bytes`(계획 추가), `wsl_without_systemd_unsupported_message_names_wsl_conf`(계획 추가)
- 플래그 기본값 불가: `activation_flags_cannot_be_defaulted_by_config_or_env`(계획 추가, 결정 1)
- 문서 대조: `service_md_activation_recipes_match_the_argv_builders`
- `crates/qsh-cli/tests/it/exit_code_matrix.rs`·`jsonl_purity.rs`에 플래그 행, `checked_in_man_pages_match_the_generator`, `golden_*` 셋
- Windows 다리: `service_activation_flags_are_unsupported_on_windows_before_m19`(계획 추가, `cfg(windows)`, 가짜 runner 호출 0회)

**(c) 완료 판정:** 플래그 없는 세 op의 출력이 기존 fixture와 바이트가 같다. §6.18·man·`service.md`가 같은 커밋이다. 실제 매니저를 부르는 테스트가 없다(`Command::new("launchctl"|"systemctl")`이 기본 runner 한 곳에만 있음). wire diff 0, `ErrorCode` diff 0. Windows 타깃 로컬 검사와 CI 세 다리 초록.

### Step 3 — (a) `qsh identity move-key` (`identity.move_key`) (0.4~0.5ew)

근거: ADR-0032 결정 15 둘째~넷째 항목, 17과 결과 절의 개정분 착지 항목(CLI.md §2.4·identity 절, man, fixture, threat-model §3·§4 D, testing.md L1). 선행: Step 2.

**(a) 범위:**

- `qsh-core`(`ops/identity.rs`, `identity/`): `Ops::identity_move_key(to)`. 인가 불요 local op이고 원격에서 부를 수 없다.
  - 순서: audit 한 건(action `identity.move_key`, 구조 필드만) → 원래 store에서 읽기 → 새 store에 쓰기(파일이면 0600) → 새 store에서 다시 읽어 공개키 대조 → `identity.toml`의 `key_store` 갱신 → 원래 store 항목 삭제.
  - 실패 처분: audit 실패면 아무것도 옮기지 않는다. 쓰기·대조·`identity.toml` 갱신 중 어느 단계든 실패하면 그 앞까지 만든 것을 지우고 원래 상태로 끝난다. 마지막 삭제만 실패하면 성공에 `stale_entry_left: true`.
  - 이미 그 store면 아무것도 하지 않고 `moved: false`(audit도 쓰지 않는지는 §7.1 #5).
  - 오류: 초기화 전이면 `identity.export`와 같은 `CONFIG_ERROR`, `--to platform`인데 store가 없으면 `identity.init --key-store platform`과 같은 `INTERNAL`. 새 `ErrorCode` 없음.
  - 개인키는 인자·결과·오류 message·`details`·로그 어디에도 나가지 않는다(ADR-0013). 읽기 버퍼는 `Zeroizing`이다.
  - device_id, 인증서, fingerprint는 바뀌지 않는다. `qsh init`의 `auto` 규칙은 바꾸지 않는다.
  - 동시성: 같은 config 디렉터리에서 다른 `move-key`나 `init`이 겹치지 않게 잠근다(§7.1 #5).
- `qsh-proto`: `IdentityMoveKeyReq { to }`, `IdentityMoveKeyData { from, to, moved, stale_entry_left }`. `from`/`to`는 기존 `key_store` 어휘(`platform`/`file`).
- `qsh-cli`: clap `qsh identity move-key --to <file|platform>`, human 렌더(`stale_entry_left`일 때 남은 항목 안내), JSON 렌더.
- 등록 완전성: schemars, `cli_v1_data_schema` arm, `CLI_V1_SCHEMA_COMMANDS`, `OP_FACES` 행, man `qsh-identity-move-key.1`, `docs/CLI.md` §2.4(`identity.move_key`)·§2.5 "인가 불요" 행·§6.11 identity 절의 시그니처·결과·오류.
- fixture(추가만): `identity.move_key.moved.json`, `identity.move_key.noop.json`(이름은 §7.1 #4).
- 문서: `docs/design/threat-model.md` §3 새 행 "`qsh identity move-key`"(로컬 사용자, 옮기는 동안의 상태), §4 D에 "store 사이를 옮기는 개인키가 권한이 넓은 파일·로그·출력으로 샌다" 행(0600, 비노출, 핀은 아래). `docs/design/testing.md` L1 「플랫폼 키스토어 릴리스 전 수동 단계」에 `move-key` 왕복(platform → file → platform)을 macOS·Linux에 더하고 Windows는 M19라고 적는다. `docs/design/architecture.md` §5에 이동 순서 한 문단.
- Windows: op은 Windows 빌드에도 열린다. Windows `platform` store(Credential Manager)는 M19(ADR-0035 결정 12)라서 M17 Windows 빌드에서 `--to platform`은 `INTERNAL`이고 `--to file`은 `moved: false`다. 파일 store의 소유자 전용 DACL과 그 테스트 쌍둥이는 M19(ADR-0035 결정 9)다.

**(b) 테스트·게이트:**

`crates/qsh-core/src/identity/tests.rs`·`ops/tests.rs`(store 주입)와 새 통합 모듈 `crates/qsh-cli/tests/it/identity_move_key.rs`(`tests/it/main.rs` 등재).

- 핀: `move_key_keeps_the_fingerprint_and_device_id`, `move_key_to_the_current_store_is_a_no_op`, `a_failed_move_key_write_leaves_the_original_store_untouched`, `move_key_file_store_is_mode_0600`(`cfg(unix)`), `move_key_is_refused_when_the_audit_sink_fails`
- 계획 추가: `move_key_readback_mismatch_rolls_back`, `move_key_reports_stale_entry_left_when_only_the_final_delete_fails`, `move_key_before_init_is_config_error`, `move_key_to_platform_without_a_store_is_internal`, `move_key_never_emits_key_bytes`(stdout·stderr·tracing 캡처·audit 레코드에 키 바이트 없음)
- route 동등(계획 추가, 실제 QUIC loopback): `move_key_then_serve_listen_and_serve_to_handshake_with_unchanged_pins`(이 장비가 forward host, reverse listener, reverse target일 때 각각 상대 장비의 `trust.toml`을 고치지 않은 채 handshake 성공, `cfg(unix)`)
- 등록: `layer_2_every_schema_command_has_all_six_faces`, `checked_in_man_pages_match_the_generator`, `golden_*` 둘, `jsonl_purity.rs`·`exit_code_matrix.rs` 행, `record_has_only_structural_fields`가 `identity.move_key` 레코드를 포함해 키 집합 그대로
- 부하 필터 초안 `scripts/stress/m17.filter`에 route 동등 테스트를 넣는다(Step 5가 먼저 만들었으면 덧붙인다).

**(c) 완료 판정:** fingerprint·device_id 불변이 테스트로 고정됐다. 실패 경로마다 원래 store와 `identity.toml`이 바이트 단위로 같다. route 동등 테스트가 부하 아래 50회 연속 초록이다. wire diff 0.

### Step 4 — (a) LaunchDaemon 레시피, doctor의 상시 기동 인식, `keystore_session_bound` (0.25~0.45ew)

근거: ADR-0032 결정 12, 13, 14, 15 첫 항목, 16과 결과 절의 개정분(`service.md` launchd 절, doctor 문구, 진단 목록, fixture, threat-model §3 문장, README Known limitations). 선행: Step 2, Step 3.

**(a) 범위:**

- `docs/deploy/service.md` launchd 절: "LaunchDaemon은 이 문서의 범위가 아니다" 문단을 결정 13의 LaunchDaemon 펜스(LaunchAgent 렌더러와 같은 `ProgramArguments`·`KeepAlive`·`RunAtLoad`·로그 경로에 `UserName`, `GroupName` `staff`, `EnvironmentVariables`의 `HOME`), 설치(`qsh service uninstall --deactivate` 먼저, `sudo cp`, `chown root:wheel`, `chmod 644`, `sudo launchctl bootstrap system …`)·해제·바이너리 이동 절차와 세션 손실 고지로 바꾼다. linger와 LaunchDaemon 레시피에 "`platform` keystore면 먼저 `qsh identity move-key --to file`" 한 줄. qsh는 이 파일을 쓰지도 `launchctl`에 넘기지도 않는다(결정 12·16).
- doctor(`crates/qsh-core/src/doctor.rs`, `doctor/probe.rs`):
  - `service_not_registered`는 macOS에서 LaunchAgent나 LaunchDaemon 파일 중 하나가 있으면 등록으로 본다. 파일 존재만 보고 `launchctl`을 부르지 않는다(결정 14).
  - `LAUNCHAGENT_SESSION_SCOPED`는 같은 mode의 LaunchDaemon 파일이 없을 때만 내고 문구가 LaunchDaemon 레시피를 가리킨다. code와 수준은 그대로다.
  - 새 `KEYSTORE_SESSION_BOUND`(warn): `identity.key_store = "platform"`이고 상시 기동 형태(macOS LaunchDaemon 파일, Linux linger 파일과 등록된 user unit)가 있을 때. remedy는 `qsh identity move-key --to file`. `EXPECTED_DOCTOR_CODES`에 하나를 더한다(26 → 27).
  - probe가 시스템 경로를 읽는 자리는 주입 가능한 뿌리를 받는다(§7.1 #3).
- `qsh service status`의 `exists`는 오늘처럼 LaunchAgent 경로만 본다(결정 14 셋째 항목).
- 문서: `docs/CLI.md` §6.17 표에 `keystore_session_bound` 행, `launchagent_session_scoped`·`service_not_registered`의 macOS 문구, 개수 문장 두 곳(§6.11 끝, §6.17 머리). `docs/design/threat-model.md` §3 `qsh service` 행에 "상시 기동은 사람이 설치한 파일이고 qsh는 읽기만 한다". README Known limitations의 LaunchAgent 문장이 레시피를 가리키게 한다.
- fixture(추가만): `keystore_session_bound`를 담은 doctor envelope 하나(이름은 §7.1 #4).
- Windows: `keystore_session_bound`는 Windows에서 내지 않는다. Windows 상시 기동 작업이 Credential Manager를 읽는지의 실측과 그 결과에 따른 Windows 판정은 M19다(ADR-0032 결정 15 첫 항목, ADR-0035 결정 27). Windows 상시 기동 작업 레시피와 그 문서 대조도 M19다. 진단 코드 집합 자체는 세 OS에서 같다(Windows 빌드도 27종을 안다).

**(b) 테스트·게이트:**

`crates/qsh-core/src/doctor/tests.rs`, `crates/qsh-core/tests/it/service_docs.rs`, `crates/qsh-core/tests/it/doctor_docs.rs`.

- 핀: `service_not_registered_accepts_a_launchdaemon_plist`, `launchagent_session_scoped_is_silent_when_a_launchdaemon_plist_exists`, `keystore_session_bound_fires_for_platform_store_under_launchdaemon`, `keystore_session_bound_fires_for_platform_store_under_linger_with_a_registered_unit`, `keystore_session_bound_is_silent_for_file_store`, `service_md_launchdaemon_recipe_matches_the_agent_program_arguments`
- 계획 추가: `keystore_session_bound_covers_serve_listen_and_reverse_units`(route 동등), `keystore_session_bound_is_silent_on_windows_before_m19`(`cfg(windows)`), `doctor_probe_never_invokes_launchctl`(probe 경로에 `Command`가 없음)
- 기존 `doctor_docs.rs`의 코드 전수 대조와 `cli_md`가 문면을 그대로 인용하는 테스트가 27종으로 초록
- `golden_*` 하나, `checked_in_man_pages_match_the_generator`(clap 변화 없음 확인)

**(c) 완료 판정:** 진단 개수 27이 코드·CLI.md 두 곳에서 같다. LaunchDaemon 펜스 대조가 초록이다. qsh가 `/Library/LaunchDaemons`에 쓰는 경로가 없다. wire diff 0.

### Step 5 — (d) `qsh sessions`의 `--state`·`--writer`·`--attachable` (0.3~0.5ew)

근거: ADR-0033 결정 1, 2, 3, 13의 세션 문장과 결과 절의 세션 테스트·fixture·man 항목. 선행: Step 1.

**(a) 범위:**

- `qsh-core`(`ops/session.rs`): 호스트 응답을 받은 뒤 클라이언트 `Ops`가 필터를 적용한다. `--state`는 `state` 문자열 정확 일치(모르는 값은 빈 결과), `--writer <principal|none>`(`none`은 `writer: null`), `--attachable`은 이 장비 resume 상태 파일에 그 `session_ref`의 credential이 있는 세션만. 여러 개는 AND다. host 없는 fan-out의 `data.unreachable`은 필터와 무관하게 그대로 남는다.
- `SessionListReq`와 wire 메시지는 바뀌지 않는다. 필터 인자의 자리는 §7.1 #6.
- JSON 모양은 `{"sessions": […]}` 그대로이고 새 필드가 없다. human 렌더는 필터가 걸렸을 때 stderr에 "N개 중 M개 표시" 한 줄. `--attachable` 판정은 `session_ref`당 상태 파일을 한 번 읽고 token 값은 어디에도 싣지 않는다(ADR-0007).
- `qsh-cli`: clap 플래그 셋.
- 문서: `docs/CLI.md` 상태 헤더(v0.35를 열거나 덧붙임), §6.2 필터 서술. man `qsh-sessions.1` 재생성.
- fixture(추가만): 필터를 건 `session.list` 하나(이름은 §7.1 #4). 기존 `session.list.json` 무변경 초록.
- Windows: 필터 함수와 forward route 위의 필터는 Windows client에서 같은 커밋에 연다. 실제 PTY 세션을 여는 e2e는 Windows host PTY가 M20(ADR-0035 결정 25)이라 `cfg(unix)`이고, Windows `qsh listen` 데몬 fan-out의 reverse 쌍둥이는 M19(ADR-0035 결정 14)가 연다.

**(b) 테스트·게이트:**

필터 단위(`ops/session` 옆 tests, 세 다리)와 새 통합 모듈 `crates/qsh-cli/tests/it/sessions_filter.rs`(실제 바이너리, `tests/it/main.rs` 등재).

- 핀: `sessions_filter_state_writer_attachable_and_combined`, `sessions_filter_does_not_change_the_wire_request`, `sessions_filter_keeps_unreachable_in_fan_out`, `sessions_attachable_never_prints_the_resume_token`
- 계획 추가: `sessions_filter_unknown_state_is_empty_not_an_error`, `sessions_filter_human_count_line_goes_to_stderr_only`
- route 동등(계획 추가, 실제 QUIC loopback, `cfg(unix)`): `sessions_filter_applies_identically_to_forward_and_reverse_hosts`(`qsh sessions <forward host>`, `qsh sessions <reverse host>`, host 없는 fan-out 셋이 같은 세션 집합에 같은 결과)
- `checked_in_man_pages_match_the_generator`, `golden_*` 하나, `jsonl_purity.rs` 행
- 부하 필터 초안 `scripts/stress/m17.filter`에 통합 모듈을 넣는다(Step 3이 먼저 만들었으면 덧붙인다).

**(c) 완료 판정:** `SessionListReq`와 wire diff 0. 기존 `session.list.json` 무변경. route 동등 테스트가 부하 아래 50회 연속 초록이다.

### Step 6 — (d) audit 읽기 코어: `AuditRecordView`, 활성·회전 파일 읽기, 필터, `oldest_ts`·`truncated` (0.5~0.75ew)

근거: ADR-0033 결정 5, 6, 7(읽기 쪽), 8, 9, 10, 11, 13의 플랫폼 문장. 선행: Step 1. 사용자 표면(op·CLI)은 Step 7이다.

**(a) 범위:**

- `qsh-proto`: `AuditRecordView`(`ts`, `request_id`, `principal`, `action`, `resource`, `decision`, `rule`, `auth_path`, `peer_addr`, `count`, 선택 `role`)와 `AuditQueryReq`(`since`, `until`, `principal`, `action`, `resource`, `decision`, `limit`), `AuditQueryData`(`records`, `skipped_lines`, `oldest_ts`, `truncated`). 자리는 §7.1 #7.
- `qsh-core` 새 모듈(가칭 `crates/qsh-core/src/audit/reader.rs`):
  - `[audit].path`(또는 `Paths::audit_log()`)의 활성 로그와 `<path>.1` … `<path>.<retain>` 회전분을 읽는다. 회전 파일 이름 규칙은 `audit/writer.rs`의 `rotated_path` 하나를 공유하고 다시 만들지 않는다.
  - 읽기만 한다. writer의 파일 락을 잡지 않고, torn write 복구를 흉내 내지 않고, 어떤 파일도 쓰기 모드로 열지 않는다. Unix는 읽기 전용 open, Windows는 `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`를 명시한다(`std::os::windows::fs::OpenOptionsExt::share_mode`).
  - 파싱되지 않는 줄과 상한을 넘는 줄은 건너뛰고 개수만 센다(§7.1 #8). 줄 내용은 오류에도 출력에도 싣지 않는다.
  - 파일이 없으면 빈 결과. 읽을 수 없으면 `INTERNAL`, message에 경로와 오류 종류만.
  - 필터는 정확 일치 AND, `--since <RFC3339|N[smhd]>`(상대 시각은 주입 시계 기준), `--until <RFC3339>`, `--decision <allow|deny>`, `--limit` 기본 100·최대 1000(넘으면 `INVALID_ARGUMENT`). 결과는 최신이 먼저다. `truncated`는 `--limit` 때문에 잘렸을 때 `true`, `oldest_ts`는 읽은 파일 전체에서 가장 오래된 레코드의 `ts`(필터와 무관).
  - `AuditRecord` → `AuditRecordView`는 필드 단위로 옮기고 가공·보강(역조회, 별칭 해석)이 없다. `role`은 레코드에 키가 있을 때만.
  - 읽기는 audit 레코드를 남기지 않는다. writer가 degraded로 latch돼 있어도 읽는다(결정 7). 이 성질의 op 수준 핀은 Step 7이다.
- 삭제 경로 없음(결정 10). reader 모듈에 삭제·절단·쓰기 API가 없다. `[audit].max_bytes`·`retain`의 의미와 기본값은 바뀌지 않는다. 새 doctor finding은 없다(결정 11).
- 문서: `docs/design/architecture.md` §6에 "조회는 읽기 전용, 락 없음, 복구 없음" 한 문단. 사용자 계약 문서는 Step 7.
- Windows: reader와 그 테스트 전부가 Windows 다리에서 돈다. `audit_query_reads_while_the_writer_rotates`의 Windows 행은 share mode로 연 핸들이 writer의 회전 rename을 막지 않음까지 본다. host 쪽 writer의 `LockFileEx` 잠금은 M20(ADR-0035 결정 24)이고 잠금 파일에 걸리므로 이 reader와 겹치지 않는다.

**(b) 테스트·게이트:**

`crates/qsh-core/src/audit/` 옆 tests(세 다리).

- 핀: `audit_record_view_fields_equal_audit_record_fields`, `audit_query_reads_active_and_rotated_files_newest_first`, `audit_query_filters_are_and_combined`, `audit_query_limit_above_the_cap_is_invalid_argument`, `audit_query_skips_a_torn_line_and_counts_it_without_echoing_it`, `audit_query_does_not_modify_the_log`(활성·회전 파일 바이트 불변), `audit_query_works_while_the_audit_sink_is_degraded`, `audit_query_on_a_missing_log_is_empty_not_an_error`, `audit_query_oldest_ts_matches_the_oldest_retained_record`, `audit_query_reads_while_the_writer_rotates`
- 계획 추가: `audit_query_since_accepts_rfc3339_and_relative_units`(시계 주입), `audit_query_role_key_is_present_only_when_recorded`, `audit_query_unreadable_log_is_internal_with_path_and_kind_only`(`cfg(unix)` 권한 행, Windows는 ACL 행을 M19 DACL 모듈과 함께), `audit_query_skips_overlong_lines_and_counts_them`, `audit_query_truncated_is_set_only_when_the_limit_cut_records`
- `audit_query_reads_while_the_writer_rotates`를 `scripts/stress/m17.filter`에 넣는다.

**(c) 완료 판정:** reader가 쓰기 모드로 여는 경로가 없다(`OpenOptions`의 write·append·truncate가 reader 모듈에 없음). 세 다리 초록, 회전 겹침 테스트가 부하 아래 50회 연속 초록이다. 사용자 표면 변화 0(clap·man·fixture diff 0). wire diff 0.

### Step 7 — (d) `qsh audit` 표면: op `audit.query`, CLI, 렌더러, 계약 문서, 분류 테스트, 텔레메트리 처분 (0.4~0.55ew)

근거: ADR-0033 결정 4, 7(op 수준), 9의 출력 모드, 10의 문서 문장, 12, 13과 결과 절의 계약 문서·분류·fixture·threat-model 항목. 선행: Step 6.

**(a) 범위:**

- `qsh-core` 새 `ops/audit.rs`: `Ops::audit_query`, 인가 불요 local op `audit.query`. 원격 peer가 요청할 수 없고, `qsh-proto` 프레임 enum에 variant가 없으며, localctl 데몬의 요청(UDS, Windows named pipe)으로도 노출하지 않는다. ACL action을 새로 요구하지 않는다. `Config::load`가 실패하면 기존 `CONFIG_ERROR`(§7.1 #9).
- `qsh-cli`: clap `qsh audit`과 결정 5의 인자, human 렌더(표 하나와 `skipped_lines`·`oldest_ts`·`truncated` 요약), JSON 렌더. 지원 모드는 human과 `--json`이고 `--jsonl`은 기존 value op 관례대로 처리한다(§7.1 #10). `--follow`는 두지 않는다.
- 등록 완전성: schemars, `cli_v1_data_schema` arm, `CLI_V1_SCHEMA_COMMANDS`, `OP_FACES` 행, man `qsh-audit.1`, `op_registration_completeness.rs`·`acl_registry.rs`의 local-only 분류.
- 문서:
  - `docs/CLI.md` 상태 헤더, §2.4 목록에 `audit.query`(`acl.show` 옆), §2.5 "인가 불요" 행과 "원격에서 부를 수 있으면 열거 oracle" 문장(ADR-0022 결정 4·ADR-0025 결정 4와 같은 문장), 새 §6.22 `qsh audit`(인자, `data`, 읽기 전용, 조회가 audit을 남기지 않음, 삭제·축약 명령이 없고 개수 기반 회전이 유일한 삭제이며 더 긴 보존은 qsh 밖 복사라는 문장, `oldest_ts`).
  - `docs/design/threat-model.md` §3 새 행 "`qsh audit`"(로컬 사용자, 로컬 읽기, 열거 oracle 방지), §4 F2에 `AuditRecordView` 필드 전수 테스트 확장, §4 F에 "audit을 지우거나 줄이는 경로가 원격 또는 로컬 op으로 생긴다" 행(결정 10, 핀은 아래 삭제 부재 테스트), §4 D 또는 B에 "원격 peer가 audit 열람으로 principal과 거부 이력을 열거한다" 행(결정 4, 핀 `audit_query_has_no_wire_message_and_no_localctl_request`). F5·h26 문면이 ADR-0045·0044 착지 뒤 상태와 맞는지 대조한다(Step 1 (a) 4).
  - `docs/design/architecture.md` §2 local op 목록.
- 텔레메트리(결정 12): `crates/qsh-core/src/telemetry.rs` 모듈 doc의 "That promotion is a P1 decision"을 ADR-0033 결정 12 인용으로 바꾼다. 코드 변화 없음. 다른 stderr 진단 줄은 건드리지 않는다.
- fixture(추가만): `audit.query` 성공 envelope 둘(비어 있지 않은 것, `truncated: true`인 것. 이름은 §7.1 #4).
- Windows: op·CLI·렌더러·분류 테스트가 세 다리에서 같은 이름으로 돈다(결정 13). 로그 경로는 ADR-0035 결정 13의 Windows state dir이다. Windows named pipe localctl 자체는 M19(ADR-0035 결정 14)이고, 그때 이 op이 pipe 요청에도 없다는 단언이 같은 테스트에 한 행으로 붙는다.

**(b) 테스트·게이트:**

새 통합 모듈 `crates/qsh-cli/tests/it/audit_query.rs`(실제 바이너리, `tests/it/main.rs` 등재)와 `crates/qsh-core/tests/it/`의 분류 테스트.

- 분류: `op_registration_completeness.rs`·`acl_registry.rs`의 `audit.query` local-only 행, `audit_query_has_no_wire_message_and_no_localctl_request`, `audit_query_never_appears_as_a_control_message_wire_variant`(`pair_ssh_never_appears_as_a_control_message_wire_variant` 형식)
- 삭제 부재: `no_op_other_than_audit_query_reads_the_audit_log_and_none_writes_it`(가칭, `ops/` 아래에서 audit 경로를 여는 op이 `audit.query` 하나이고 그것도 읽기만, SC6)
- op 수준: `audit_query_writes_no_audit_record`, `audit_query_envelope_is_the_only_stdout_line`(`--json`), `audit_query_human_mode_never_prints_skipped_line_contents`
- route 동등(계획 추가, 실제 QUIC loopback, `cfg(unix)`): `audit_query_reads_records_written_by_serve_listen_and_serve_to`(같은 장비가 forward host, reverse listener, reverse target으로 남긴 레코드가 같은 `AuditRecordView` 모양으로 나옴)
- 등록: `layer_2_every_schema_command_has_all_six_faces`, `checked_in_man_pages_match_the_generator`, `golden_*` 둘, `jsonl_purity.rs`·`exit_code_matrix.rs` 행, `failure_text_discipline.rs`가 새 message를 덮음
- route 동등 테스트와 실제 바이너리 테스트를 `scripts/stress/m17.filter`에 넣는다.

**(c) 완료 판정:** `audit.query`가 local-only로 분류되고 wire·localctl variant가 없음을 테스트가 고정한다. 새 fixture 둘과 man 페이지가 같은 커밋에 있다. `capabilities.json` diff 0, wire diff 0. route 동등 테스트가 부하 아래 50회 연속 초록이다.

### Step 8 — 마감 (0.1~0.2ew)

근거: 마일스톤 마감 공통 절차(`docs/ROADMAP.md` §2) 1·2, 이 문서 §4의 안정성 규율. 선행: Step 2~7.

**(a) 범위:**

- **부하 반복.** M17 타이밍 민감 테스트 전부를 `scripts/stress/m17.filter`로 묶는다(§7.1 #11). `QSH_ACCEPTANCE_SLOW=1 scripts/stress/run.sh`로 50회 돌리고 "50/50 passed under load" 줄, 테스트 개수, 호스트 사양을 마감 노트에 적는다. `m17-latency.filter`는 두지 않는다.
- **절차 1. 구속 문서 태그 대조.** 대상은 다음과 같다.
  - `docs/CLI.md` v0.35 이후 항목: §2.4·§2.5·§6.2·§6.11·§6.17·§6.18·§6.22
  - `docs/deploy/service.md` launchd·systemd 절과 WSL 절
  - `docs/design/architecture.md` §2·§5·§6
  - `docs/design/testing.md` L1
  - `docs/design/threat-model.md` §3·§4 D·E·F·G·§7
  - ADR-0032·0033 결과 절 문서 목록 전수, ADR-0024 결정 11의 "별도 결정" 문장이 ADR-0032를 가리킴, ADR-0035 결정 27·28이 ADR-0032를 가리킴
  - `crates/qsh-core/src/telemetry.rs` 모듈 doc
  - Windows 귀속 기록: 작업 스케줄러 분기와 Windows 레시피·`keystore_session_bound` 실측·`move-key`의 Credential Manager와 DACL은 M19, Windows host audit 잠금과 PTY 세션 e2e는 M20(ADR-0032 결정 10·15, ADR-0035 결정 9·12·14·24·25·27·28)
- **절차 2. README 동기화.** 재작성판(`2fc879b`) 위에서 한다(DoD (b)). 기능 목록(`qsh service install --activate`, `qsh identity move-key`, `qsh sessions` 필터, `qsh audit`), Known limitations(qsh는 linger·LaunchDaemon·Windows 상시 기동 작업을 대신 설정하지 않음, `--activate`는 떠 있는 유닛을 재시작하지 않음, audit 조회는 로컬 전용이고 삭제 명령이 없음, Windows 서비스 백엔드는 M19), 보안 절. M16 마감 뒤 README Roadmap 표의 M17 행을 "Done"으로.
- §3 유예 가드레일 "Service 설치" 행의 "서비스 매니저 실호출은 M17 (a)"를 착지 상태로 고치는 일은 main 세션이 마감 노트와 함께 한다.
- ROADMAP M17 마감 노트(main 세션). 이 `PLAN.md`의 마지막 커밋 해시를 적고 다음 계획으로 교체한다. 계획 원문은 커밋 해시로 인용한다(ROADMAP 머리말 규칙). §5.5에는 M17이 만든 사람 몫이 없다고 적는다.

**(b) 테스트·게이트:** 일곱 게이트, CI(acceptance 포함) 초록, 부하 반복 50/50.

**(c) 완료 판정:** §3의 DoD가 근거 커밋, run id와 함께 `[x]`다. `git diff --stat <Step 2 부모>..<마지막 구현 스텝 머지> -- crates/qsh-proto/proto crates/qsh-proto/src/wire.rs crates/qsh-proto/src/local.rs crates/qsh-cli/tests/fixtures/cli-v1/capabilities.json`이 비어 있다. M17에는 wire 변경을 소유한 스텝이 없다.

## 5. 결정·핀 테스트 대응표

각 결정과 핀 테스트의 주인은 스텝 하나다. 한 결정이 여러 스텝에 걸치면 하위 항목으로 나눠 각각 주인 하나를 적는다.

### 5.1 ADR-0032 결정

| 결정 | 스텝 |
|---|---|
| 1 명시적 플래그 셋, config·환경 변수 기본값 불가, setup·doctor는 넘기지 않음 | 2 |
| 2 활성화는 `install` 마지막 단계 | 2 |
| 3 argv 표의 launchd·systemd 열 | 2 |
| 3 argv 표의 작업 스케줄러 열과 COM 질의 | M19 밖(ADR-0035 결정 27·28) |
| 4 재시작 부재(launchd·systemd) | 2 |
| 4 Windows `/Create /F` 실측과 처분 | M19 밖(ADR-0035 결정 27) |
| 5 등록 여부 기준 비활성화, 해제가 먼저 | 2 |
| 6 `status --live`는 exit code 하나 | 2 |
| 7 `activation`·`deactivation`·`active` 필드 | 2 |
| 8 오류 사상(`UNSUPPORTED`·`INTERNAL`·`TIMEOUT`, `user/<uid>` 우회 금지) | 2 |
| 9 audit 한 건, 활성화 레코드 없음 | 2 |
| 10 `ManagerRunner`와 상태 질의 trait의 모양 | 2 |
| 10 Windows 분기 구현 | M19 밖(ADR-0032 결정 10) |
| 11 launchd·systemd 레시피 문서 대조 | 2 |
| 11 Windows 레시피 문서 대조 | M19 밖(ADR-0035 백엔드) |
| 12 label·유닛 이름 유지, 상시 기동 자동 설정 없음 | 4 |
| 13 macOS LaunchDaemon 레시피와 펜스 대조 | 4 |
| 14 doctor의 LaunchDaemon 인식, `status`의 `exists` 범위 | 4 |
| 15 `keystore_session_bound`(macOS·Linux) | 4 |
| 15 `keystore_session_bound`의 Windows 실측과 판정 | M19 밖(ADR-0032 결정 15) |
| 15 `identity.move_key` op, 순서, 결과, audit | 3 |
| 15 `move-key`의 Windows Credential Manager와 DACL | M19 밖(ADR-0035 결정 9·12) |
| 16 레시피 비자동화, root·`sudo` 경로 없음 | 4 |
| 17 wire 불변, additive 계약 | 2(검증), 3·4(각 additive 항목) |
| 18 상시 기동 형태 보존(macOS) | 2 |
| 18 상시 기동 형태 보존(Windows `Password` 주체) | M19 밖(ADR-0035 결정 27) |

### 5.2 ADR-0032 핀 테스트와 결과 절 항목

| 항목 | 스텝 |
|---|---|
| `install_without_activate_never_invokes_the_manager` | 2 |
| `uninstall_without_deactivate_never_invokes_the_manager` | 2 |
| `status_without_live_never_invokes_the_manager` | 2 |
| `install_activate_runs_the_documented_argv_on_launchd` | 2 |
| `install_activate_runs_the_documented_argv_on_systemd` | 2 |
| `install_activate_runs_the_documented_argv_on_task_scheduler` | M19 밖 |
| `deactivate_calls_disable_for_a_registered_but_inactive_unit` | 2 |
| `deactivate_skips_when_the_unit_is_not_registered` | 2 |
| `windows_activate_updates_the_stored_task_without_running_it_when_already_running` | M19 밖 |
| `activate_and_deactivate_leave_a_human_installed_always_on_form_untouched`(launchd 행) | 2 |
| 같은 테스트의 작업 스케줄러 행 | M19 밖 |
| `status_live_reports_the_always_on_form_when_present`(launchd 행) | 2 |
| `activate_is_skipped_when_the_unit_write_fails` | 2 |
| `activate_is_skipped_when_the_audit_sink_fails` | 2 |
| `activate_does_not_restart_an_already_active_unit` | 2 |
| `deactivate_runs_before_the_unit_file_is_removed` | 2 |
| `a_failed_deactivate_keeps_the_unit_file` | 2 |
| `a_missing_manager_binary_is_unsupported_and_a_nonzero_exit_is_internal_with_exit_code` | 2 |
| `a_manager_call_past_the_deadline_is_timeout` | 2 |
| `service_md_activation_recipes_match_the_argv_builders` | 2 |
| `service_not_registered_accepts_a_launchdaemon_plist` | 4 |
| `launchagent_session_scoped_is_silent_when_a_launchdaemon_plist_exists` | 4 |
| `keystore_session_bound_fires_for_platform_store_under_launchdaemon` | 4 |
| `keystore_session_bound_fires_for_platform_store_under_linger_with_a_registered_unit` | 4 |
| `keystore_session_bound_is_silent_for_file_store` | 4 |
| `move_key_keeps_the_fingerprint_and_device_id` | 3 |
| `move_key_to_the_current_store_is_a_no_op` | 3 |
| `a_failed_move_key_write_leaves_the_original_store_untouched` | 3 |
| `move_key_file_store_is_mode_0600` | 3 |
| `move_key_is_refused_when_the_audit_sink_fails` | 3 |
| `service_md_launchdaemon_recipe_matches_the_agent_program_arguments` | 4 |
| 계획 추가: `install_activate_argv_covers_serve_listen_and_reverse_modes`, `manager_argv_never_contains_user_input`, `manager_stderr_first_line_is_capped_at_512_bytes`, `wsl_without_systemd_unsupported_message_names_wsl_conf`, `activation_flags_cannot_be_defaulted_by_config_or_env`, `service_activation_flags_are_unsupported_on_windows_before_m19` | 2 |
| 계획 추가: `move_key_readback_mismatch_rolls_back`, `move_key_reports_stale_entry_left_when_only_the_final_delete_fails`, `move_key_before_init_is_config_error`, `move_key_to_platform_without_a_store_is_internal`, `move_key_never_emits_key_bytes`, `move_key_then_serve_listen_and_serve_to_handshake_with_unchanged_pins` | 3 |
| 계획 추가: `keystore_session_bound_covers_serve_listen_and_reverse_units`, `keystore_session_bound_is_silent_on_windows_before_m19`, `doctor_probe_never_invokes_launchctl` | 4 |
| `docs/CLI.md` §6.18, man 셋, fixture 셋 | 2 |
| `docs/deploy/service.md` `--activate` 안내와 비활성화 레시피 | 2 |
| `docs/deploy/service.md` LaunchDaemon 펜스·설치·해제, `move-key` 한 줄 | 4 |
| `docs/CLI.md` §2.4·§2.5·§6.11 `identity.move_key`, man `qsh-identity-move-key.1`, fixture 둘, `OP_FACES` | 3 |
| `docs/CLI.md` §6.17 `keystore_session_bound` 행·문구·개수, doctor fixture 하나 | 4 |
| `service_not_registered` remedy의 `--activate` 안내 | 2 |
| threat-model §3 `qsh service` 행(호출 서술) | 2 |
| threat-model §3 `qsh service` 행(상시 기동은 읽기만) | 4 |
| threat-model §3 `identity move-key` 행, §4 D 개인키 이동 | 3 |
| threat-model §4 E 매니저 인자 주입, §4 G 재시작 부재 | 2 |
| `docs/design/testing.md` L1 `move-key` 왕복 | 3 |
| README Known limitations LaunchAgent 문장 | 4 |
| ADR-0024 결정 11·ADR-0035 결정 27·28 상호 인용 대조 | 8 |

### 5.3 ADR-0033 결정

| 결정 | 스텝 |
|---|---|
| 1 세션 필터 셋과 AND | 5 |
| 2 클라이언트 적용, `SessionListReq`·wire 불변, `unreachable` 유지 | 5 |
| 3 JSON 모양 불변, stderr 한 줄, token 비노출 | 5 |
| 4 `audit.query` local op, wire·localctl 비노출, §2.4·§2.5 | 7 |
| 5 인자, 정확 일치 AND, `--limit` 상한, 최신 먼저 | 6 |
| 6 읽기 전용, 락·복구 없음, torn line 계수, 없음은 빈 결과, Windows share mode | 6 |
| 7 조회는 audit을 남기지 않음(읽기 코어) | 6 |
| 7 같은 성질의 op 수준 핀 | 7 |
| 8 `AuditRecordView`와 필드 전수 | 6 |
| 9 `data` 모양 | 6 |
| 9 출력 모드(human·`--json`) | 7 |
| 10 삭제·축약 op 없음, 회전 의미 불변(코드) | 6 |
| 10 삭제 부재 분류 테스트와 CLI.md 문장 | 7 |
| 11 새 doctor finding 없음 | 6 |
| 12 텔레메트리 비승격과 모듈 doc 인용 | 7 |
| 13 세션 필터의 route 동등 | 5 |
| 13 audit 조회의 플랫폼·역할 동등 | 6(reader), 7(op) |
| 13 CLI 새 절 번호(§6.22) | 7 |
| 13 Windows named pipe localctl 비노출 행 | M19 밖(ADR-0035 결정 14) |

### 5.4 ADR-0033 핀 테스트와 결과 절 항목

| 항목 | 스텝 |
|---|---|
| `op_registration_completeness.rs`·`acl_registry.rs`의 `audit.query` local-only 분류 | 7 |
| `audit_query_has_no_wire_message_and_no_localctl_request` | 7 |
| `audit_record_view_fields_equal_audit_record_fields` | 6 |
| `audit_query_reads_active_and_rotated_files_newest_first` | 6 |
| `audit_query_filters_are_and_combined` | 6 |
| `audit_query_limit_above_the_cap_is_invalid_argument` | 6 |
| `audit_query_skips_a_torn_line_and_counts_it_without_echoing_it` | 6 |
| `audit_query_does_not_modify_the_log` | 6 |
| `audit_query_works_while_the_audit_sink_is_degraded` | 6 |
| `audit_query_writes_no_audit_record` | 7 |
| `audit_query_on_a_missing_log_is_empty_not_an_error` | 6 |
| `audit_query_oldest_ts_matches_the_oldest_retained_record` | 6 |
| 삭제 부재 분류 테스트(가칭 `no_op_other_than_audit_query_reads_the_audit_log_and_none_writes_it`) | 7 |
| `audit_query_reads_while_the_writer_rotates`(세 다리) | 6 |
| `sessions_filter_state_writer_attachable_and_combined` | 5 |
| `sessions_filter_does_not_change_the_wire_request` | 5 |
| `sessions_filter_keeps_unreachable_in_fan_out` | 5 |
| `sessions_attachable_never_prints_the_resume_token` | 5 |
| 계획 추가: `sessions_filter_unknown_state_is_empty_not_an_error`, `sessions_filter_human_count_line_goes_to_stderr_only`, `sessions_filter_applies_identically_to_forward_and_reverse_hosts` | 5 |
| 계획 추가: `audit_query_since_accepts_rfc3339_and_relative_units`, `audit_query_role_key_is_present_only_when_recorded`, `audit_query_unreadable_log_is_internal_with_path_and_kind_only`, `audit_query_skips_overlong_lines_and_counts_them`, `audit_query_truncated_is_set_only_when_the_limit_cut_records` | 6 |
| 계획 추가: `audit_query_never_appears_as_a_control_message_wire_variant`, `audit_query_envelope_is_the_only_stdout_line`, `audit_query_human_mode_never_prints_skipped_line_contents`, `audit_query_reads_records_written_by_serve_listen_and_serve_to` | 7 |
| `docs/CLI.md` §6.2 필터, man `qsh-sessions.1`, 필터 건 `session.list` fixture | 5 |
| `docs/CLI.md` §2.4·§2.5·§6.22, man `qsh-audit.1`, `audit.query` fixture 둘 | 7 |
| threat-model §3 `qsh audit` 행, F2 확장, F 삭제 경로 행, 열거 oracle 행 | 7 |
| `docs/design/architecture.md` §6 조회 문단 | 6 |
| `telemetry.rs` 모듈 doc 인용 | 7 |

## 6. 명시적 non-goals

- `acl.toml`을 쓰는 어떤 동작(ADR-0017 결정 1, ADR-0025 결정 1), 핫 리로드, qsh 자체 데몬화(§5.3). ROADMAP M17 명시적 out.
- 로그인 세션 밖 상시 기동의 자동 설정. 어느 플랫폼에서도 qsh가 linger·LaunchDaemon·Windows 상시 기동 작업을 대신 설정하지 않고 `sudo`를 부르지 않는다(ADR-0032 결정 12·16). LaunchDaemon을 직접 설치하는 `--system` 류 플래그(ADR-0032 대안 절).
- 강제 재시작 플래그, `qsh service start`/`stop`, `launchctl bootstrap` 실패 시 `user/<uid>` 우회, 매니저 존재의 `PATH` 탐색, 활성화 전용 audit 레코드(ADR-0032 결정 4·8·9와 대안 절).
- 적재 시 `platform`이 없을 때의 파일 store 자동 대체, System Keychain·별도 keychain(ADR-0032 대안 절). `qsh init`의 `auto` 규칙 변경(결정 15 넷째 항목).
- 원격 `qsh audit <host>`, 새 ACL action, `qsh audit prune`·`export --delete`, 시간 기반 retention(`retain_days`), 새 doctor finding(`audit_retention_short` 등), `--follow`, 조회 출력의 역조회·별칭 보강, 조회 자신의 audit 기록(ADR-0033 대안 절).
- 호스트 쪽 세션 필터(`SessionListReq` 필드), 텔레메트리 `qsh.event/v1` 승격(ADR-0033 결정 2·12).
- h26(trust 조작 audit의 소급 확장)과 세션 상태 영속화(M18). ADR-0033 결과 절 마지막 문장.
- 새 `ErrorCode`, 새 wire 메시지, `.proto` 변경, `capabilities.json` 변경.
- Windows: 작업 스케줄러 분기·Windows 상시 기동 레시피·`keystore_session_bound` 실측·`move-key`의 Credential Manager와 DACL·named pipe 비노출 행은 M19, host audit writer 잠금과 PTY 세션 e2e는 M20(ADR-0032 결정 10·15, ADR-0035 결정 9·12·14·24·25·27·28).
- 에이전트가 하는 `gh secret set`, `gh workflow run`, 태그 push, 저장소 설정 변경.
- P2 전부.

## 7. 리스크와 감시 항목

- **launchd 분기가 macOS 다리에서만 컴파일되는 문제.** 오늘 `resolve_manager`가 `cfg!(target_os)`로 매니저를 정하므로 launchd 경로의 테스트는 macOS 다리에서만 돈다. M15는 macOS 다리에서만 깨지는 실패를 착지 뒤 보정했다(`1d02860`). 판정·argv 빌더를 `cfg` 없는 순수 함수로 두고, 테스트가 매니저를 인자로 주입해 Linux에서도 launchd 행을 돌게 한다(§7.1 #1).
- **`launchctl print system/…`의 root 요구.** Dave-MBP16이 오프라인이라 확인이 늦을 수 있다. ADR이 대체를 정해 두었으므로 막히지 않는다. 대체로 착지하면 `--live`가 LaunchDaemon이 있는 Mac에서 `INTERNAL`이고, 확인 뒤 질의로 바꾸는 작은 커밋이 따른다(§9 #5).
- **`move-key`의 중간 상태.** 원래 store 삭제와 `identity.toml` 갱신 사이에 다른 qsh 프로세스(`qsh serve` 재시작 등)가 키를 적재할 수 있다. 결정 15의 순서(갱신 뒤 삭제)라면 어느 순간에도 `identity.toml`이 가리키는 store에 키가 있다. 같은 디렉터리의 `move-key`·`init` 동시 실행은 잠금으로 막는다(§7.1 #5). 이미 떠 있는 `qsh serve`는 메모리의 키를 계속 쓰므로 재시작이 필요 없다는 사실을 human 렌더가 알린다.
- **실제 OS store 왕복의 공백.** CI는 `MemoryKeyStore`로만 돈다. Keychain·Secret Service의 실제 쓰기·읽기·삭제는 §1 수동 단계 몫이고, 태그 전에 돌지 않으면 README Known limitations에 "수동 확인 전"을 적을지 마감 때 정한다.
- **audit reader와 writer 회전의 경합.** Unix에서는 rename 중 열린 핸들이 옛 파일을 계속 읽어 같은 레코드가 두 번 보이거나 한 줄이 잘려 보일 수 있다. 잘린 줄은 `skipped_lines`로 세고, 중복은 파일을 회전분 번호 역순으로 한 번씩만 여는 순서로 줄인다. 결정 6이 정확성보다 "막지 않음"을 우선했으므로, 회전 겹침 테스트는 "오류 없이 끝나고 writer가 막히지 않음"을 단언하고 레코드 수의 정확성은 단언하지 않는다.
- **`docs/CLI.md` 상태 헤더와 `REQUIRED_FIXTURES`·`OP_FACES` 충돌.** 두 사슬이 병렬이라 같은 줄을 만진다. 늦게 착지하는 쪽이 rebase하고, 헤더 판 번호가 역순이 되지 않게 `cli_md_header.rs`로 확인한다.
- **Windows 다리의 늦은 실패.** Step 6의 share mode와 Step 3의 Windows `--to platform` 처분은 Windows에서만 갈리는 경로다. §4 규율의 로컬 Windows 타깃 검사로 줄이고, 그래도 깨지면 보정 커밋을 같은 스텝 이름으로 단다.
- **부하 반복의 비용.** M17의 타이밍 민감 테스트는 M16보다 적다(실제 QUIC loopback 넷과 회전 겹침 하나 남짓). 50회 반복은 한 번에 끝낼 수 있지만 stress run이 머신을 쓰는 동안 다른 cargo 작업을 겹치지 않는다.

### 7.1 구현 중 확정할 값 (해당 step (a)에 근거와 함께 추기)

| # | 질문 | 초안 | 확정 시점 |
|---|---|---|---|
| 1 | 매니저 판정과 테스트 주입 | `resolve_manager`만 `cfg`를 갖고, `*_with_home` 쌍둥이가 `manager: Manager`와 `runner: &dyn ManagerRunner`를 함께 받아 세 다리 모두에서 launchd·systemd 행을 돈다. 실제 플랫폼 경로의 테스트는 다리별로 하나씩만 둔다 | Step 2 |
| 2 | `ManagerRunner`의 시계 | 30초 기한을 runner 밖의 주입 시계로 재고 가짜 runner가 "끝나지 않음"을 흉내 내 `TIMEOUT`을 시간 정지 테스트로 고정한다 | Step 2 |
| 3 | doctor probe의 시스템 경로 뿌리 | probe 함수가 `system_root: &Path`(기본 `/`)를 받아 `/Library/LaunchDaemons`와 `/var/lib/systemd/linger`를 그 아래에서 찾는다. 기존 `probe_systemd_linger`의 주입 방식을 먼저 확인하고 같은 모양으로 맞춘다 | Step 4 |
| 4 | 새 fixture 이름 | `service.install.activated.json`, `service.uninstall.deactivated.json`, `service.status.live.json`, `identity.move_key.moved.json`, `identity.move_key.noop.json`, `doctor.run.keystore_session_bound.json`(doctor의 command가 `doctor.run`이라 기존 `doctor.run.*` 규칙을 따름), `session.list.filtered.json`, `audit.query.json`, `audit.query.truncated.json`. 기존 이름 규칙(`<op>.<variant>.json`)과 대조해 맞춘다 | 각 스텝 |
| 5 | `move-key`의 잠금과 no-op audit | identity 디렉터리에 `init`이 쓰는 잠금이 있으면 그것을 쓰고 없으면 `TrustStore::lock`과 같은 모양의 파일 잠금을 identity 쪽에 둔다. 결정 15 셋째 항목은 "첫 변경 전에 한 건"이라 적으므로, 이미 그 store인 no-op은 변경이 없어 audit을 쓰지 않는 쪽이 초안이다. ADR 문면과 어긋나면 main 세션이 정한다 | Step 3 |
| 6 | 세션 필터 인자의 자리 | `SessionListReq`는 그대로 두고 `qsh-core`의 새 구조체(가칭 `SessionFilter { state, writer, attachable }`)를 `Ops::session_list`의 둘째 인자로 받는다. `qsh-proto`에는 넣지 않는다(계약 타입이 아니라 클라이언트 쪽 인자). `SessionListReq`가 localctl(`local.rs`)에도 쓰이는지 확인하고, 쓰인다면 데몬 fan-out 경로가 응답을 받은 뒤 같은 필터를 적용한다 | Step 5 |
| 7 | `AuditRecordView`·`AuditQuery*`의 자리 | `crates/qsh-proto/src/types/` 아래 새 `audit.rs`. 기존 `acl.show` 타입의 자리와 같은 규칙 | Step 6 |
| 8 | audit 줄 상한 | writer가 쓰는 레코드의 최대 길이보다 넉넉한 64 KiB. 넘는 줄은 읽어 버리지 않고 건너뛰며 `skipped_lines`에 센다(결정 6의 "파싱되지 않는 줄"로 본다). fuzz 타깃은 더하지 않는다. 입력이 같은 uid의 qsh가 쓴 로컬 파일이고 파서가 `serde_json`이기 때문이다 | Step 6 |
| 9 | config를 읽을 수 없을 때의 `qsh audit` | `Config::load` 실패는 기존 `CONFIG_ERROR`. 운영자가 config를 고치는 동안에도 읽고 싶다면 기본 경로를 읽는 대체를 둘 수 있으나, `[audit].path`가 바뀐 장비에서 엉뚱한 파일을 읽게 되므로 대체하지 않는 쪽이 초안 | Step 7 |
| 10 | `qsh audit --jsonl` | `acl.show` 등 value op이 `--jsonl`에 하는 처분을 그대로 따른다(`jsonl_purity.rs`의 기존 행 확인) | Step 7 |
| 11 | M17 부하 filterset | 모듈 접두 `identity_move_key::`, `sessions_filter::`, `audit_query::`와 이름 `audit_query_reads_while_the_writer_rotates`, `move_key_then_serve_listen_and_serve_to_`. `m16.filter`와 같은 `(?:\w+::)?` 접두 허용 꼴 | Step 3·5·8 |
| 12 | `--live`의 Windows 상태 질의 trait 이름과 반환형 | `TaskStateQuery::is_running(name) -> Result<bool, OpError>`. M19가 COM으로 구현한다. M17에서는 가짜 구현만 있고 Windows 빌드에서 호출 경로가 없다 | Step 2 |

## 8. 완료 절차

1. §3 DoD 전건을 실제 테스트와 CI run으로 확인한다. 체크박스는 근거가 초록일 때만 채운다.
2. 부하 반복 50/50을 기록한다(Step 3·5·6·7·8).
3. 구속 문서 태그를 대조한다(Step 8 (a)의 목록 전수).
4. README를 동기화한다(재작성판 위에서).
5. `docs/ROADMAP.md` "현재 위치"와 M17 절을 갱신하고 마감 노트를 적는다(main 세션).
6. §0.1, §0.2, §0.3, §0.4의 상태를 승계한다.
7. 이 `PLAN.md`를 다음 계획으로 교체하고, 마감 노트에 이 계획의 마지막 커밋 해시를 적는다. 다음 마일스톤은 M18 착수 조건(M8 DoD 3)이 닫혀 있으면 M18, 아니면 M19다(§5.1 원칙 6). M19를 먼저 열면 건너뛴 사실을 §5.1에 날짜와 함께 적는다.

## 9. 열린 질문

각 항목의 권고는 main 세션이 Step 1 커밋에서 결정으로 확정한다. 2026-10-14 사용자 위임 결정("전부 다 알아서 진행해")의 범위다.

1. **ROADMAP M17 DoD에 안정성 줄을 더할 것인가.** M12·M15·M16에는 있고 M17에는 없다. **권고:** 더한다. 문면은 "M17이 더한 타이밍 민감 테스트는 부하 아래 50회 연속 초록(`scripts/stress/run.sh`)"이다. M17에는 지연 예산 단언이 없으므로 M15·M16의 `-j 1` 대체 문장은 넣지 않는다.
2. **M17 크기의 "(d) 구현 미산정".** ADR-0033 결과 절이 1.2~1.8ew로 매겼는데 ROADMAP M17 크기 줄, §5.2 표("2.1~3.1 + 미산정 하나"), 머리말 "총 크기"("미산정 둘(M17 (d)의 구현, M18의 보안 가산분)")가 그대로다. **권고:** M17 크기를 "3.3~4.9ew. (a) ADR 0.3 + 구현 1.0~1.5 / (b) 0.5~0.8 / (c) 0 / (d) ADR 0.2~0.3 + 구현 1.2~1.8 / 마감 0.1~0.2"로, §5.2 행과 P1 합을 그에 맞추고, 머리말의 미산정을 M18 하나로 줄인다. 남은 작업은 이 계획 §4의 2.3~3.5ew다.
3. **§5.4 리스크 1의 낡은 문장.** "제안 ADR 여섯(0029, 0031~0033, 0035, 0044, 0045)"은 2026-10-14 승인 뒤 사실이 아니다. **권고:** "착수 ADR은 모두 승인됐고(2026-10-14) 남은 것은 조건부 0034(M18)다"로 고친다.
4. **ADR-0032 Windows 열의 M19 귀속이 ROADMAP M19 DoD에 이름으로 없다.** M17 (a) 범위 문장은 "Windows 분기의 구현은 M19"라고 적지만, M19 수용 기준은 작업 정의 펜스와 `logon_task_session_scoped`만 적고 `--activate`의 `schtasks` argv·문서 대조, 결정 18의 Windows 갈래, `keystore_session_bound`의 Windows 실측, `move-key`의 Credential Manager·DACL을 적지 않는다. 마감 공통 절차 1의 "후속 마일스톤에 명시 귀속"을 M17 마감에서 증명하려면 M19 쪽에 이름이 있어야 한다. **권고:** Step 1이 M19 수용 기준에 "ADR-0032 Windows 열(결정 3·4·5·6·11·15·18의 Windows 갈래)의 핀 테스트 `install_activate_runs_the_documented_argv_on_task_scheduler`, `windows_activate_updates_the_stored_task_without_running_it_when_already_running`과 `move-key`의 Credential Manager 왕복" 한 줄을 더한다.
5. **`launchctl print system/…`가 root 없이 되는지 모를 때.** ADR-0032 결정 18 셋째 항목이 대체를 이미 정했다. 확인 없이 질의 경로로 착지하면, root가 필요한 경우 권한 실패의 0이 아닌 exit가 `active: false`로 잘못 읽힌다. **권고:** Step 2는 대체(`INTERNAL`, `step: "live"`, `sudo` 안내)로 착지한다. 실제 Mac에서 root 없이 실행 여부가 exit code로 갈림을 확인하면 질의 경로로 바꾸는 작은 커밋을 단다(§1 넷째 항목). ADR 개정은 필요 없다.
6. **(a)와 (d)의 순서.** ROADMAP은 순서를 정하지 않는다. **권고:** §4 "순서의 근거"대로 두 사슬(Step 2→3→4, Step 5→6→7)을 병렬로 연다. 한 에이전트만 쓴다면 Step 2, 5, 3, 6, 4, 7 순으로 번갈아 계약 문서 충돌을 작게 나눈다.
7. **M16 계획 §0.1에서 빠진 M9 DoD 1.** "일곱" 제목 아래 여섯 줄만 있었다. **권고:** 이 문서 §0.1처럼 M15 계획의 줄을 되살린다. ROADMAP의 P0 표에는 이미 있으므로 ROADMAP 수정은 없다.
8. **태그.** M17 DoD에는 태그가 필요 없다. **권고:** 찍을지는 유지보수자가 정한다. §1의 Keychain·Secret Service `move-key` 왕복과 macOS `launchctl` 확인이 그 바이너리로 돌 수 있으므로 Step 4 뒤 태그 하나를 권한다.
9. **`qsh audit` 절 번호.** ADR-0033 결과 절은 "§6.20 뒤"라고 적었지만 그 자리를 ADR-0029의 `qsh cp`(§6.21)가 먼저 차지했다. 결정 13의 규칙("그때 가장 큰 `§6.N` 다음 빈 번호")대로 §6.22다. **권고:** §6.22로 하고 ADR 본문은 고치지 않는다. `identity move-key`는 새 절을 만들지 않고 §6.11 identity 절에 넣는다(ADR-0032 결과 절 "`identity.*` 절").
10. **Windows `move-key`의 M17 처분.** M17 Windows 빌드에는 `platform` store가 없어 옮길 키가 존재할 수 없다. **권고:** 표면 동등을 위해 op을 Windows에도 M17에서 열고, `--to platform`은 `identity.init --key-store platform`과 같은 `INTERNAL`, `--to file`은 `moved: false`로 둔다. Windows의 실제 이동(Credential Manager, DACL)은 M19가 같은 op 위에 얹는다. ADR 개정은 필요 없다.
