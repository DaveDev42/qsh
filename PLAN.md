# PLAN.md — M16: SSH 부트스트랩과 신뢰 철회

P1 M16의 실행 계획이다. M15가 닫혀(2026-10-15) 이 문서가 M15 계획(마지막 커밋 `7cbeced`)을 전면 교체했다. 착수 ADR 둘(ADR-0044 SSH 부트스트랩, ADR-0031 축소판 trust 철회 시 연결 닫기)은 2026-10-14 사용자 위임 결정("전부 다 알아서 진행해")으로 `승인됨`이 되었고(`09266dc`), M15 (a)(ADR-0045 role)는 `85ea34f`로 착지했으므로 착수 조건은 모두 충족됐다. 구속 근거는 다음과 같다.

- `docs/ROADMAP.md` §5의 M16 절(범위 (a)(b), 착수 조건, 명시적 out, 수용 기준, 크기), §5.1 시퀀싱 원칙(특히 원칙 5·6·7), §5.5 P1 사람 몫, 마일스톤 마감 공통 절차(같은 문서 §2)
- ADR-0044 결정 1~26과 결과 절, ADR-0031 결정 1~10과 결과 절
- 두 ADR이 기대는 결정: ADR-0045 결정 4(ⓡ 단계와 role 조회 함수)·8(기본 role, local op audit)·12(`trust_remove_scope` 문면)·13(페어링 직후 고지), ADR-0012 결정 3·4·6·7, ADR-0013 결정 6, ADR-0014 결정 1·2·6, ADR-0017 결정 1·5, ADR-0026 결정 7
- 참조 ADR: ADR-0010(연결 수 상한), ADR-0043(QUIC 하나, transport 중립 타입), ADR-0035 결정 1·5·14·25(Windows client M19, Windows host M20)
- `docs/CLI.md` §2.4·§2.5·§6.1·§6.9·§6.11·§6.12·§6.13·§6.14·§6.17·§6.21·§7
- `docs/design/protocol.md` §3·§7·§13·§16.2·§16.3·§16.5와 새 부트스트랩 스트림 절, `docs/design/architecture.md` §6·§7, `docs/design/threat-model.md` §3·§4 A·B·D·E·§5 g2·§7(h4·h5·h35)
- `CLAUDE.md` "Security defaults"

이 계획과 `docs/ROADMAP.md`의 편집은 main 세션만 한다.

인용 규율은 M15판과 같다. 문서는 절 이름, ADR 번호와 결정 번호, 테스트 이름, 커밋 해시로 가리킨다. 코드 위치는 파일 경로와 심볼 이름으로 가리키고, 줄 수나 개수를 적을 때는 origin `1a4af3b` 트리에서 잰 값임을 밝힌다. 옛 계획의 스텝은 "M15 plan Step N (<해시>)" 꼴로만 인용한다.

## 0. 열린 사람 몫

여기 적힌 항목은 이 파일이 다음 계획으로 바뀔 때 그대로 승계한다. M15 계획 §0의 상태를 M15 마감 시점 그대로 옮겼다.

### 0.1 P0에서 열린 일곱


- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** 기준은 `docs/campaigns/m10-clean-vm.md`. Linux 회차는 PASS(v0.3.0 세 회차 `69a6414`, v0.4.3 Ubuntu 24.04 x86_64 회차 4, 2026-10-09). macOS arm64·x86_64 두 회차가 남았고 둘 다 클린 macOS VM과 Gatekeeper 판정이 필요하다. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 서명·공증 태그는 `v0.4.0`부터 있다. 회차는 `docs/campaigns/m10-clean-vm.md`. 소유: 사람.
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** `x86_64-unknown-linux-musl` 한정. Debian 10(glibc 2.28) 회차 2(v0.3.0)와 회차 5(v0.4.3, 2026-10-09)가 `DoD 3 = PASS`다. 캠페인 §9 판정과 함께 닫히므로 macOS 두 회차를 기다린다. 두 회차 모두 에이전트가 컨테이너에서 돌렸으니, 캠페인을 닫을 때 사람이 이것을 회차로 셀지 다시 본다. 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** 기준은 `docs/campaigns/m7-stopwatch.md`(예행 1회만 끝남). 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** 기준은 `docs/campaigns/m2-mobility.md`. M18의 착수 조건. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** 저장소 밖 조직 액션. 소유: 운영자.

### 0.2 P1 마일스톤이 만든 사람 몫 (`docs/ROADMAP.md` §5.5)


- [ ] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 기록 자리는 `docs/campaigns/m8-fuzz.md`. 출처 M11. 소유: 사람.
- [ ] **`p1-supervise-wake` 회차 넷.** 기준은 `docs/campaigns/p1-supervise-wake.md`. 출처 M12. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 기준은 `docs/campaigns/p1-setup-stopwatch.md`(ADR-0024 결정 12). 출처 M12. PASS가 기록되기 전에는 이슈 #3 완료 기준 첫 줄이 충족됐다고 적지 않는다. 소유: 사람.
- [ ] **`decode_file_frame` fuzz 타깃의 누적 72 fuzz-hours.** M15 (b)가 타깃을 더했다(`a86123d`). 기록 자리는 `docs/campaigns/m8-fuzz.md` 형식이고, §5.5 표의 "새 파서 fuzz 타깃" 행("M15의 새 decode 타깃")에 상태를 적는다. 공개 beta 전에 끝나야 한다(`docs/design/protocol.md` §13). 소유: 사람.

### 0.3 M16이 새로 만드는 사람 몫 (`docs/ROADMAP.md` §5.5)

M16 DoD에는 들지 않는다(§5.1 원칙 6). 에이전트는 `gh secret set`, `gh workflow run`, 태그 push, 저장소 설정 변경을 어느 스텝에서도 하지 않는다.

- [ ] **`parse_ssh_bootstrap_line` fuzz 타깃의 누적 72 fuzz-hours.** Step 4가 타깃을 더한다. 기록 자리는 `docs/campaigns/m8-fuzz.md` 형식이고 §5.5 표의 "새 파서 fuzz 타깃" 행(이미 "M16 (a) `parse_ssh_bootstrap_line`"을 적어 둠)에 상태를 적는다. 공개 beta 전에 끝나야 한다(`docs/design/protocol.md` §13). 소유: 사람.
- [ ] **실제 OpenSSH 위의 SSH 부트스트랩 회차.** ADR-0044 결과 절의 사람 캠페인이다. ProxyJump, ssh-agent, 암호 걸린 키 위에서 처음 `qsh box`부터 셸 프롬프트까지, 그리고 `--reverse` 구도 한 회. 문서 `docs/campaigns/p1-ssh-bootstrap.md`는 Step 8이 사전 고정한다(구현 마지막 스텝 전). Windows `ssh.exe` client 회차는 Windows 대화형 client가 서는 M19의 `docs/campaigns/p1-windows.md`가 이어받는다(§9 #3). §5.5 표에 행을 더하는 일은 main 세션이 Step 1에서 한다. 소유: 사람.

## 1. 유지보수에서 남은 확인

- [ ] macOS Keychain 왕복. `keyring-core` 1과 플랫폼 store crate로 옮긴 변경(`08a6173`)의 Linux Secret Service 왕복은 확인했지만, macOS 쪽은 Dave-MBP16이 오프라인이라 못 했다. 다음 태그 전에 `docs/design/testing.md` L1의 수동 단계로 돌린다.
- [ ] 다음 태그 run에서 `release.yml` 액션 갱신(`1557f50`) 뒤의 서명·공증·provenance를 확인한다.

## 2. 테스트 환경

M15와 같다. 호스트 nftables의 `inet dave_mosh` 표 문제는 dave-environment `c6c5359c`와 저장소 `414f1fd`가 막는다(loopback UDP 자가 점검, `scripts/test/nextest-ns.sh`, 긴 TMPDIR에서의 unix 소켓 경로 단축).

M16이 더하는 것은 가짜 `ssh` 하네스 하나다(Step 5). 실제 sshd와 OpenSSH 설정 없이 돈다. 하네스는 셸 스크립트가 아니라 testkit이 빌드하는 Rust 실행 파일이라 Windows 다리에서도 같은 바이너리가 돈다. 실제 OpenSSH 동작(ProxyJump, agent, 암호 키, host key 프롬프트)은 §0.3의 사람 캠페인 몫이다.

## 3. DoD 체크리스트 (ROADMAP M16)

체크박스는 근거가 되는 테스트와 CI run이 초록일 때만 채운다.

- [x] **DoD — ADR-0044·0031이 `승인됨`이다.** 근거: `09266dc`(2026-10-14). 소유: 에이전트(main 세션 확인).
- [x] **DoD (a) — 가짜 `ssh`로 끝까지 도는 부트스트랩.** 다음을 테스트가 고정한다. 결과: 근거: `6db09a3`·`ddb39fb`·`6445922`·`7c43332`.
  - 양쪽 pin(이름, 주소, role)과 이어진 handshake: `ssh_bootstrap_pins_both_sides_and_connects`.
  - pin 충돌은 아무것도 쓰지 않고 끝난다: `ssh_bootstrap_never_overwrites_a_pin_with_a_different_fingerprint`.
  - role 없는 기존 원격 pin을 `full`로 넓히지 않는다: `ssh_bootstrap_does_not_widen_an_existing_roleless_pin`.
  - 원격 audit를 쓸 수 없으면 pin도 쓰지 않는다: `ssh_respond_refuses_to_pin_when_audit_is_unwritable`.
  - `--json`/`--jsonl`에서는 자동 발동하지 않고 ssh 자식이 BatchMode로 뜬다: `ssh_bootstrap_is_never_implicit_in_machine_mode`, `ssh_bootstrap_ssh_argv_is_fixed`.

  근거: Step 5·6·7·9.
- [x] **DoD (a) — 역방향 동등.** `--reverse` 부트스트랩 뒤 원격이 `serve --to`로 등록하면 reverse route 위의 attach·exec·`qsh cp`가 정방향과 같은 테스트를 통과한다(§5.1 원칙 7). 근거: Step 8(`ssh_bootstrap_reverse_*`, `bootstrapped_reverse_route_passes_the_forward_attach_exec_cp_suite`). 결과: 근거: `e8cd7a3`.
- [x] **DoD (a) — 줄 파서와 fuzz.** stdio 줄 파서는 `qsh-proto`에 있고 fuzz 타깃 `parse_ssh_bootstrap_line`이 걸린다. 근거: Step 4. 결과: 근거: `aba7bd6`(fuzz smoke 20,000 runs clean, 누적 72 fuzz-hours는 §0.3 사람 몫).
- [x] **DoD (a) — 키 재료와 rc 출력이 로그에 남지 않는다.** 근거: Step 5(로그 규율), Step 7(`ssh_bootstrap_skips_untagged_stdout_and_never_logs_it`, `ssh_respond_audit_record_has_only_structural_fields`). 결과: 근거: `6db09a3`·`6445922`.
- [x] **DoD (b) — `trust remove` 뒤 2초 안에 CLOSE와 audit 한 줄.** `an_established_connection_survives_the_hosts_trust_remove`가 반대 단언 `an_established_connection_is_closed_within_two_seconds_of_trust_remove`로 바뀐다. 세 프로세스(`qsh serve`, `qsh serve --to`, `qsh listen`) 모두에서 같다. 근거: Step 3. 결과: 근거: `029c83b`(연결 512개가 한 번의 변경에 240ms 안에 닫힘).
- [x] **DoD (b) — role 축소와 파싱 실패 처분이 ADR대로다.** role 축소(`full`→`exec`, `full`→`tunnel`의 `any`→`owned` 포함)는 `grants_reduced`로 닫히고, 넓히면 닫히지 않으며, `trust.toml` 파싱 실패 중에는 닫지 않고 role 요청만 멈춘다(ADR-0031 결정 5·6). 근거: Step 3. 결과: 근거: `fd92130`·`029c83b`.
- [x] **DoD (b) — 문면.** `TrustRemoveScope`(`crates/qsh-core/src/doctor.rs`의 `TRUST_REMOVE_SCOPE`) message·remedy와 `docs/CLI.md` §6.11·§6.17 문면이 같은 커밋에서 바뀐다. 만료 30일 전 doctor 경고(P0)는 유지된다(`doctor_reports_cert_expiring_soon_within_the_30_day_window` 무변경 초록). 근거: Step 3. 결과: 근거: `029c83b`.
- [x] **DoD — 등록 완전성.** 새 명령·필드마다 다음을 갖춘다. 근거: Step 5·6·7·8·9. 결과: 근거: `6445922`·`e8cd7a3`(fixture 다섯, `qsh-pair-ssh.1`, `capabilities.json` diff 0).
  - fixture 등재(`REQUIRED_FIXTURES`)와 `layer_2_every_schema_command_has_all_six_faces`
  - man 재생성(`qsh-pair-ssh.1`, `checked_in_man_pages_match_the_generator`)
  - `capabilities.json` golden은 바뀌지 않는다(두 ADR 모두 peer capability를 더하지 않음). 바뀌면 그 스텝이 잘못된 것이다.
  - 부트스트랩 직후 pin 이름·role 고지(Step 7)
- [x] **DoD — 위협 모델.** `docs/design/threat-model.md` §3에 진입점 두 행(ssh 자식과 부트스트랩 스트림, `pair ssh-respond`의 stdin)이, §4에 ssh 신뢰 승계(A), `full` pin 생성·방향 없는 pin·role 확대(B), 로그 유출(D), 응답자 출력 조작·옵션 주입(E), 연결 재검증(B)이 핀 테스트와 함께 오른다. 각 행은 그 통제를 구현한 스텝에서 오른다. 근거: Step 3·4·5·6·7·8. §7 잔여 위험은 Step 3(h4·h5·h35 개정)과 Step 10(ADR-0044 잔여 둘). 결과: 근거: `029c83b`·`aba7bd6`·`6db09a3`·`ddb39fb`·`6445922`·`e8cd7a3`·`b880aab`(§7 h42·h43·h44).
- [x] **DoD 마감 — 마감 공통 절차(§2) 1·2.** 근거: Step 10. 결과: 근거: `b880aab`, CI run `38704818413`(acceptance 포함) 초록.
- [x] **계획 규율 — 새 타이밍 민감 테스트의 부하 반복.** ROADMAP M16 DoD에는 없는 줄이다(§9 #1). M12·M13·M15 규율대로 M16이 더한 타이밍 민감 테스트 전부가 `scripts/stress/run.sh`로 CPU 부하 아래 50회 연속 초록이어야 한다. 근거: Step 3·10. 결과: 근거: `b880aab`, 부하 아래 `scripts/stress/m16.filter` 50/50 passed under load(195개, Dave-Windows-WSL 8 vCPU·31 GB).

## 4. 실행 단계 (PR 단위)

스텝 번호는 이 문서 안에서만 쓰는 참조다. 크기는 다음과 같다.

| 묶음 | 스텝 | 합(ew) | ADR 산정 | 비고 |
|---|---|---|---|---|
| (b) ADR-0031 축소판 | Step 2~3 | 0.8~1.25 | 0.9~1.35 | 차이 0.1은 이미 끝난 ADR 작성분이다 |
| (a) ADR-0044 | Step 4~9 | 2.4~3.8 | 2.6~4.0 | 차이 0.2는 이미 끝난 ADR 작성분이다. 계약 문서 델타는 각 스텝에 나눠 실었다 |
| 마감 | Step 10 | 0.1~0.2 | 0.1~0.2 | |
| 합 | | 3.3~5.25 | ROADMAP 3.6~5.6 | 끝난 ADR 작성분 0.3을 더하면 3.6~5.55로 범위 안이다 |

Step 1은 크기 내역 밖이다.

**순서의 근거.**

- (b)를 (a)보다 먼저 둔다. ADR-0044 결과 절의 잔여 위험("ssh 접근을 거둬도 이미 선 qsh pin은 남는다")의 처방이 "원격에서 `qsh trust remove`, ADR-0031이 그 순간 열린 연결까지 끊는다"이다. 부트스트랩이 `full` pin을 명령 한 번으로 심게 되기 전에, 그 pin을 거두는 수단이 열린 연결까지 닿아야 한다. (b)는 작고(1ew 남짓) `trust/mod.rs`의 `SharedTrustStore`를 바꾸는데, (a)의 응답자·client 쓰기(Step 6·7)가 같은 파일의 `TrustStore::lock`·`save`를 쓰므로 (b)를 먼저 착지시키면 충돌 면적이 준다.
- (b) 안에서는 판정 입력을 먼저 세우고(Step 2, 동작 변화 없음) 닫기를 나중에 켠다(Step 3). 닫기를 켜는 커밋이 테스트 교체와 문면 변경을 같이 싣는다(ROADMAP M16 DoD (b)의 "같은 커밋" 요구).
- (a) 안에서는 신뢰할 수 없는 입력의 파서(Step 4)를 먼저 세운다. 그다음 ssh 쪽 기계 장치(Step 5), 원격 응답자(Step 6), 이 장비 쪽 op(Step 7), 역방향(Step 8), 자동 발동(Step 9) 순이다. 자동 발동은 명시 명령이 완전히 선 뒤에 켜서, 사람이 모르게 ssh가 불리는 경로가 미완성 op을 부르는 창을 두지 않는다.

**의존과 병렬.**

| 스텝 | 선행 | 다른 에이전트와 병렬 가능 여부 |
|---|---|---|
| Step 2 | Step 1 | Step 4와 병렬 가능. Step 2는 `qsh-transport`의 `endpoint.rs`·`tls.rs`와 `qsh-core/src/trust/`를 만지고, Step 4는 `qsh-proto`의 새 모듈과 `fuzz/`, `docs/design/protocol.md` 새 절을 만진다 |
| Step 3 | Step 2 | Step 4·5와 병렬 가능. Step 3은 `server/`, `reverse/`, `audit.rs`, `doctor.rs`, `docs/CLI.md` §6.9·§6.11·§6.14·§6.17을 만진다. 겹치는 곳은 `docs/CLI.md` 상태 헤더 한 줄과 threat-model §4이고 rebase로 푼다 |
| Step 4 | Step 1 | Step 2·3과 병렬 가능(위와 같음) |
| Step 5 | Step 4 | Step 3과 병렬 가능. Step 5는 새 모듈 `crates/qsh-core/src/ssh_bootstrap/`, `config.rs`의 `[ssh]` 절, testkit의 가짜 `ssh`를 만진다 |
| Step 6 | Step 3(`trust/mod.rs` 충돌 회피), Step 5 | — |
| Step 7 | Step 6 | — |
| Step 8 | Step 7 | — |
| Step 9 | Step 7 | Step 8과 병렬 가능하지만 권하지 않는다. 둘 다 `crates/qsh-cli/src/cli.rs`와 `docs/CLI.md` §6.11을 만진다 |
| Step 10 | 전부 | — |

**규율.** 앞 마일스톤 그대로이고 M16에서 몇 가지를 덧붙인다.

- 각 스텝은 일곱 게이트(`cargo fmt --all --check`, clippy `-D warnings`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`, `cargo xtask arch`, `cargo deny check`)가 초록인 채로 착지한다. clippy와 test는 `ci.yml`의 `windows-latest`·`macos-14` 다리에서도 돈다. M15는 Windows·macOS 다리에서만 깨지는 실패를 착지 뒤 보정 커밋으로 넷이나 고쳤다(`eb4216e`, `668214b`, `1d02860`, `a9748a4`). 그래서 M16은 `cfg(unix)`/`cfg(windows)` 분기나 경로 표기, 자식 프로세스, 소켓 옵션을 건드리는 스텝마다 push 전에 로컬에서 Windows 타깃 검사(`cargo xwin clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings`와 같은 타깃의 `cargo xwin doc`)를 돌린다. xwin이 없는 머신에서는 Dave-Windows(`ssh dave-windows.tail91e9e.ts.net`)에서 같은 두 명령을 돌린다. 이 검사로 CI의 Windows 다리를 대신하지 않는다. 착지 판정은 CI 초록이다.
- 계약 문서 델타는 그 표면을 바꾼 스텝의 같은 커밋에 싣는다.
  - `docs/CLI.md` 상태 헤더의 v0.32 항목은 CLI.md를 처음 고치는 Step 3이 열고 뒤 스텝이 덧붙인다(`crates/qsh-core/tests/it/cli_md_header.rs` 핀).
  - clap 트리가 바뀌는 스텝(Step 6·7·8)은 같은 커밋에서 `cargo xtask man`을 돌린다.
  - doctor code는 더하지 않는다. `trust_remove_scope`는 code·status·노출 조건이 그대로이고 문면만 바뀐다(ADR-0031 결정 9). `config_unknown_key`의 알려진 키 목록에 `[ssh]` 세 키가 오르는 것은 code 추가가 아니다(Step 5).
- 판정 로직, 재검증, 부트스트랩 절차, ssh 자식 관리, 응답자, UDP bind 확인은 `qsh-core`에 둔다. `qsh-proto`에는 부트스트랩 메시지 타입과 줄 파서(sans-IO), `PairSshReq`·`PairSshData` 계약 타입만 들어간다. `qsh-transport`에는 chain 보관, `Connection::reverify`, `CLOSE_CODE_TRUST_WITHDRAWN`만 들어가고 QUIC 스택을 이름 짓지 않는 중립 타입을 쓴다(ADR-0043 결정 3). `qsh-cli`에는 clap 정의(`pair ssh`, 숨김 `pair ssh-respond`), 자동 발동 분기, 렌더러 둘만 둔다. 새 모듈이 `xtask arch`의 경로 범위 금지 목록에 들어가는지는 그 모듈을 만드는 스텝이 판단하고, 들어가면 `xtask/src/arch.rs`를 같은 커밋에서 고친다(`CLAUDE.md`의 경로 범위 규칙, §7.1 #1).
- **wire 소유.** M16의 어느 스텝도 `.proto`를 바꾸지 않는다. ADR-0044 결과 절("wire(`.proto`)와 `capabilities.json`은 바뀌지 않는다")과 ADR-0031 결정 1·10("새 wire 메시지 없음")이 근거다. 새 CLOSE 코드 `0x1005`는 `docs/design/protocol.md` §16.3이 동결 밖에 둔 대역이고(Step 2), 부트스트랩 스트림은 QUIC wire가 아닌 상호운용 계약이다(Step 4). 완료 판정마다 다음을 확인한다.
  - `git diff --stat -- crates/qsh-proto/proto crates/qsh-proto/src/wire.rs crates/qsh-proto/src/local.rs crates/qsh-cli/tests/fixtures/cli-v1/capabilities.json`이 비어 있다.
  - `ErrorCode`는 어느 스텝에서도 바뀌지 않는다. 새 실패는 모두 기존 코드에 붙는 additive `details.reason`이다(ADR-0044 결정 14, ADR-0031 결정 1).
  - 구현 중 wire 변경이 필요해 보이면 그 스텝은 착지하지 않고, main 세션이 새 ADR 필요 여부를 정한다(`CLAUDE.md` 머리말).
- fixture는 추가만 한다. 새 fixture마다 실제 바이너리로 재현하는 `golden_*` 생산 테스트를 같은 커밋에 둔다. 기존 `trust.*`·`pair`·`error.*` fixture는 고치지 않은 채 초록이어야 한다.
- **테스트 배치.** 통합 테스트는 `crates/<crate>/tests/it/<name>.rs` 모듈로 두고 같은 커밋에서 `crates/<crate>/tests/it/main.rs`에 `mod <name>;`을 등재한다(`0e1215e`가 crate마다 통합 테스트 바이너리를 하나로 합쳤다). 새 `tests/*.rs` 파일을 crate 최상위에 두지 않는다. nextest 이름은 `<name>::<test>`이고 한 모듈만 돌릴 때는 `--test it -E 'test(/^<name>::/)'`이다. 단위 테스트는 소스 옆 `tests.rs`에 둔다.
- **route 동등(§5.1 원칙 7, PRD §4).** 인가·신뢰 동작을 바꾸는 스텝은 forward route(`qsh serve` ← client)와 reverse route(`qsh listen` ← `qsh serve --to`)의 같은 성질을 같은 스텝의 테스트로 단언한다. 한쪽만 덮는 PR은 착지하지 않는다. (b)는 Step 3 하나가 세 프로세스를 모두 덮고, (a)는 정방향 부트스트랩(Step 7)과 역방향 부트스트랩(Step 8)이 각자의 route로 이어지는 같은 attach·exec·`qsh cp` 묶음을 통과해야 마일스톤이 닫힌다.
- **플랫폼 동등(PRD §4, 예외 없음).** 결정의 동작은 세 OS에서 같다. 플랫폼 차이는 ADR이 이미 M19·M20에 귀속시킨 것만 미루고, 스텝마다 무엇을 미루는지를 그 스텝의 "Windows" 항목에 적는다. 요약은 다음과 같다.
  - (b) 재검증은 이식 가능한 코드다(ADR-0031 결정 3의 플랫폼 문단). Windows 빌드의 `qsh serve`(오늘도 exec·터널을 냄)는 M16에서 감시 작업을 갖고 Windows 다리에서 그 테스트가 돈다. `qsh serve --to`와 `qsh listen`은 오늘 unix 전용(`run_reverse_unix`, localctl)이라 그 Windows 쌍둥이의 테스트는 각각 M20(ADR-0035 결정 25)과 M19(ADR-0035 결정 14)가 연다. 코드는 M16에서 플랫폼 분기 없이 쓴다.
  - (a) client 쪽 `qsh pair ssh`(명시 명령)는 Windows client에서도 M16에 연다(ADR-0044 결정 25, ADR-0035 결정 1의 "착지와 함께 열린다"). `ssh.exe` 탐색과 `ssh_not_found` 문면은 Step 5다. 대화형 형태와 `qsh cp`의 자동 발동은 Windows의 대화형 attach와 `qsh cp` 자체가 M19(ADR-0035 결정 1·5)라 M19가 그 분기를 켠다. 응답자 `qsh pair ssh-respond`의 Windows 판(`SO_EXCLUSIVEADDRUSE` probe, cmd.exe·PowerShell 사상의 응답자 쪽)은 M20(ADR-0044 결정 10, ADR-0035 결정 25)이다. 그 전의 Windows 빌드는 이 하위 명령을 몰라 client가 `remote_qsh_too_old`로 받는다(§9 #2). 원격 기본 셸이 `cmd.exe`·PowerShell일 때의 종료 코드 사상(9009, 1)은 client 쪽 코드라 M16 Step 5에서 연다.
  - macOS는 M16 범위다. `ssh -G` 출력과 BSD `ssh`의 종료 코드는 Linux와 같은 OpenSSH이고, macOS 다리에서 가짜 `ssh` 하네스 전체가 돈다.
- 손대는 소스 파일이 800줄을 넘으면 인라인 테스트를 같은 커밋에서 형제 `tests.rs`로 옮긴다. origin `1a4af3b` 기준 `crates/qsh-core/src/server/mod.rs`(2639줄), `reverse/target/mod.rs`(1242줄), `trust/mod.rs`(1172줄), `config.rs`(1383줄), `ops/trust.rs`(846줄), `qsh-transport/src/endpoint.rs`(1378줄), `qsh-cli/src/cli.rs`(1310줄)가 이미 넘었으므로 인라인 테스트가 남아 있는지 먼저 확인한다.
- 안정성 규율은 M13·M15와 같다. 시계를 주입하고, 관찰 가능한 상태를 넉넉한 `timeout`으로 기다리며, 고정 `sleep()`은 쓰지 않는다. 타이밍 민감 테스트는 그 스텝의 완료 판정에서 부하 아래 50회 연속 초록이어야 착지한다(`scripts/stress/run.sh`, 필터는 Step 10이 묶는 `scripts/stress/m16.filter`의 초안을 Step 3이 먼저 만든다). 2초 보장의 계약 핀은 tokio 시간을 멈춘 테스트가 맡는다(ADR-0031 결과 절). 실제 시계로 2초를 재는 테스트가 부하 아래에서 흔들리면 §9 #4의 절차를 따른다.

### Step 1 — M16 계획 교체와 ROADMAP 갱신 (main 세션, 크기 내역 밖)

근거: `docs/ROADMAP.md` 현재 위치와 M16 절, ADR-0044·0031 결과 절의 문서 목록. 선행: M15 마감(M15 plan Step 16)과 그 마감 노트. 두 ADR 승인(`09266dc`).

**(a) 범위:**

1. `PLAN.md`를 이 문서로 바꾼다. ROADMAP M15 마감 노트에 M15 계획의 마지막 커밋 해시가 적혀 있는지 확인한다.
2. `docs/ROADMAP.md`를 고친다.
   - 현재 위치를 "현재 마일스톤은 M16"으로 바꾼다.
   - M16 DoD에 안정성 줄을 더한다(§9 #1). 문면은 M15의 안정성 줄을 따른다.
   - §5.5 표에 "SSH 부트스트랩 실제 OpenSSH 회차" 행을 더한다. 사전 고정 문서 `docs/campaigns/p1-ssh-bootstrap.md`(Step 8), 만드는 마일스톤 M16 (a), 선행은 M16 (a)가 담긴 태그.
3. README Roadmap 표의 P1 행을 "M16 진행 중"으로 고친다.
4. ADR 준비 점검. 두 ADR은 승인됐고 M16에 새 ADR은 필요 없다. 다만 다음 두 문장의 실제 상태를 확인해 이 계획 §9에 적는다(ADR 본문은 고치지 않는다).
   - ADR-0044 결정 10의 "그 전의 Windows 빌드는 이 하위 명령을 몰라"가 M16 Windows 빌드의 `pair ssh-respond` 처분을 정한다(§9 #2).
   - ADR-0044 결정 11의 "§16의 freeze 규칙 중 additive-only를 같은 방식으로 따른다"를 `docs/design/protocol.md` §16.2 목록 등재로 읽는다(§9 #5).

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록.

**(c) 완료 판정:** `PLAN.md` 첫 줄이 이 문서의 제목이다. ROADMAP 현재 위치가 M16을 가리키고 M16 DoD에 안정성 줄이 있다.

### Step 2 — (b) 재검증의 입력: chain 보관, `Connection::reverify`, CLOSE 상수, trust store 세대 번호와 poll (0.3~0.5ew)

근거: ADR-0031 결정 3(세대 번호·`watch`·poll), 4(재검증 입력), 7의 상수 정의. 선행: Step 1. 이 스텝은 연결을 닫지 않는다. 판정 입력과 알림 통로만 세운다.

**(a) 범위:**

- `qsh-transport`(`crates/qsh-transport/src/endpoint.rs`의 `Connection`):
  - handshake 때 `peer_chain`으로 얻은 peer chain(DER)과 TLS 역할(`PeerRole::Server`/`Client`)을 보관한다. 지금은 `peer_fingerprint`만 남기고 chain은 버린다.
  - `Connection::reverify(&self, evaluator: &dyn TrustEvaluator) -> Result<VerifiedPeer, RejectReason>`를 더한다. 보관한 chain과 역할로 `crates/qsh-transport/src/tls.rs`의 `verify_peer` 코어를 다시 부른다. 새 검증 경로를 만들지 않는다. chain이 비었거나 leaf를 파싱할 수 없으면 거부를 돌려준다(결정 5의 판정 불능 = 거부).
  - `CLOSE_CODE_TRUST_WITHDRAWN: u32 = 0x1005`를 `CLOSE_CODE_UNVERIFIED_PEER`·`CLOSE_CODE_PROTOCOL` 옆에 두고, `Connection::close`가 이 코드와 고정 reason `b"trust withdrawn"`로 닫는 경로를 연다. peer가 이 코드로 닫았는지 읽는 중립 접근자(가칭 `Connection::closed_by_trust_withdrawal`)를 둔다. Step 3의 `serve --to` 재dial 분류가 쓴다.
- `qsh-core`(`crates/qsh-core/src/trust/mod.rs`):
  - `SharedTrustStore`에 단조 증가 세대 번호와 `tokio::sync::watch` 송신단을 둔다. `refresh`가 snapshot을 실제로 바꿀 때(새 내용 파싱, 파일 소실로 빈 store)만 세대를 올린다. 읽기·파싱 실패로 마지막 정상 snapshot을 유지하면 올리지 않는다.
  - `SharedTrustStore::subscribe()`와 1초 간격 poll 작업 하나(`refresh`만 부름)를 둔다. poll 간격은 상수(가칭 `TRUST_POLL_INTERVAL`)이고 테스트가 시계를 멈춰 쓴다.
  - ADR-0045 ⓡ 단계가 쓰는 role 조회(`role_of_pin`, `TrustStore::query_role`)를 "연결의 기록된 principal과 fingerprint → (action, 소유 축) 집합" 함수(가칭 `role_grants_for`)로 노출하고, 인가 판정과 재검증이 같은 함수를 부르게 한다. 덮음 관계(`any`가 `owned`를 덮음)를 계산하는 순수 함수(가칭 `RoleGrants::covers`)를 같이 둔다.
- 문서: `docs/design/protocol.md` §16.3의 CLOSE 코드 목록과 §7·§16.5의 값 범위 서술에 `0x1005`를 반영한다(ADR-0031 결정 10). §3 한 문장은 동작이 켜지는 Step 3이 싣는다.
- Windows: 전부 이식 가능한 코드다. Windows 다리에서 단위 테스트가 그대로 돈다.

**(b) 테스트·게이트:**

- `qsh-transport` 단위(`endpoint` 옆 tests): `reverify_agrees_with_the_handshake_verdict_for_pin_ca_and_pairing`, `reverify_rejects_a_connection_with_an_empty_chain`
- `crates/qsh-transport/tests/it/handshake_matrix.rs`에 실제 handshake 뒤 `reverify`가 같은 principal·`auth_path`를 돌려주는 행
- `trust/tests.rs`: `trust_store_generation_bumps_only_when_the_snapshot_changes`(같은 바이트 재기록은 올리지 않음, 파싱 실패는 올리지 않음, 파일 삭제는 올림), `trust_store_poll_notifies_subscribers_within_one_tick`(tokio 시간 정지)
- `role_grants_cover_relation_treats_any_as_covering_owned`, `authorizer_and_reverify_share_one_role_grant_function`(같은 입력에 같은 집합)
- 기존 `crates/qsh-cli/tests/it/trust_lifecycle_live.rs`의 `an_established_connection_survives_the_hosts_trust_remove`는 이 스텝에서 그대로 초록이다(아직 닫지 않으므로).

**(c) 완료 판정:** 동작 변화 0(기존 trust·acl 테스트 무변경 초록). wire diff 0. Windows 타깃 로컬 검사와 CI Windows 다리 초록.

### Step 3 — (b) 세 프로세스의 연결별 감시와 닫기, audit, 재dial 분류, 문면 (0.5~0.75ew)

근거: ADR-0031 결정 1, 2, 3(연결별 감시와 수명 묶음, 플랫폼 문단), 5, 6, 7(닫는 동작, `serve --to`·`listen` 처분), 8, 9, 10과 결과 절. 선행: Step 2.

**(a) 범위:**

- 기록값. `ConnCtx`(`crates/qsh-core/src/server/mod.rs`)에 수립 시점 `Established { principal, auth_path, role_grants }`를 둔다. `Principal::Pairing` 연결은 기록하지 않는다(결정 2).
- 감시 작업. 연결마다 `SharedTrustStore::subscribe()`를 기다리는 작업을 그 연결을 서빙하는 작업과 같은 `select!`에 묶는다. 붙이는 곳은 셋이다.
  - `qsh serve` inbound: `Server::serve_connection`(→ `serve_connection_inner`)
  - `qsh serve --to` outbound: `crates/qsh-core/src/reverse/target/mod.rs`의 연결 수명 안(`Server::serve_control`을 도는 자리)
  - `qsh listen` inbound 등록: `crates/qsh-core/src/reverse/listen/registration.rs`와 등록표(`reverse/registry.rs`). 등록 연결의 role grant는 `reverse`가 주는 `host.reverse` 하나다.
- 닫는 조건은 결정 5의 다섯 항목 순서 그대로다(`reverify` 거부, `auth_path` 변화, `Pairing`, 판정 불능, role grant 축소). 넓어지면 닫지 않고 기록값을 갈아 끼운다. role 없는 pin의 rename, `acl.toml` 행 grant, 무관한 항목 변경은 닫지 않는다. 판정은 매번 돌고 관련 항목을 미리 가리는 최적화는 하지 않는다.
- fail closed(결정 6). 빈 store는 전부 닫는다. 파싱 실패 중에는 세대가 오르지 않아 감시가 돌지 않고, role 요청은 ADR-0045 결정 4대로 멈춘다. 닫기는 audit보다 먼저 하고, audit 실패는 로그 줄로만 남는다.
- 닫기(결정 7). `Connection::close(CLOSE_CODE_TRUST_WITHDRAWN, b"trust withdrawn")`. 그 위 세션은 오늘의 연결 유실과 같은 규칙으로 detach된다.
  - `serve --to` 재dial 루프(`classify_target_connection_loss`)는 로컬이 닫았든 상대가 닫았든 `0x1005`를 신뢰 철회로 분류하고, 로그 한 줄만 남기며, 빠른 재dial 경로(`loss_delay`)가 아니라 handshake 거부와 같은 일반 backoff를 탄다.
  - `listen`은 닫힌 등록의 relay를 끝내고, 등록은 연결 유실과 같은 정리 경로로 `[listen].stale_retention` 동안 Stale로 남는다(ADR-0031 결정 7 개정 이력).
- audit(결정 8). `AuditRecord::connection_withdrawn(principal, auth_path, peer_addr, reason)`를 `crates/qsh-core/src/audit.rs`의 `handshake_rejected` 옆에 둔다. `resource`는 `trust_withdrawn` 또는 `grants_reduced`, `action` `connect`, `decision` `deny`, `rule` `null`, `request_id` `"-"`, `role` 키 없음.
- 문면(결정 9). 좁히는 명령(`trust remove`, role을 낮추는 `trust set-role`, role이 있는 pin의 `trust rename`)의 사람용 출력이 "언제·어디에·무엇을 하지 않는가" 세 문장을 `qsh-core` 상수 한 벌(가칭 `TRUST_NARROWING_SCOPE`)로 말한다. `qsh-cli`는 받은 것을 쓰기만 한다. JSON 필드는 바뀌지 않는다.
  - `crates/qsh-core/src/doctor.rs`의 `TRUST_REMOVE_SCOPE` message·remedy를 같은 규율로 바꾼다. code·status(`info`)·노출 조건은 그대로다. remedy에서 "(P1)"과 재시작 권고가 빠지고, 다른 장비에서도 같은 명령을 실행하라는 안내가 들어간다.
- 문서(모두 이 커밋):
  - `docs/CLI.md` 상태 헤더 v0.32를 연다. §6.11의 "`trust.remove`의 유효 범위" 문단, `trust rename` 문단의 "이미 확립된 연결" 문장(role이 있는 pin은 닫힘), `trust set-role` 절의 세 문장, 파싱 실패 중 미반영 창. §6.9·§6.14의 `--supervise` 설명. §6.17 `trust_remove_scope` 인용과 표 설명. audit `resource` 범주에 두 값.
  - `docs/design/architecture.md` §6 audit `resource` 범주.
  - `docs/design/protocol.md` §3에 "확립된 연결은 trust 변경 뒤 재검증된다" 한 문장.
  - README "Known limitations"의 `trust remove` 줄과 M15가 남긴 "role을 줄여도 열린 연결은 M16까지 유지" 줄.
  - `docs/design/threat-model.md`: §5 g2 설명 교체, §4 B에 "신뢰를 거둔 peer가 기존 연결로 권한을 유지한다" 행(통제 결정 3·5, 핀은 아래 연결 닫힘 테스트, 잔여 h5), §7 h4·h5·h35 개정과 "h4·h5를 함께 읽으라" 문단의 "2초 안에 끊는다", 새 잔여 한 줄("닫는 것은 연결이지 세션이 아니다").
- Windows: `qsh serve` 감시는 Windows 빌드에도 붙고 아래 serve inbound 테스트 중 PTY가 필요 없는 것(exec·터널 위의 연결)이 Windows 다리에서 돈다. `serve --to`·`listen` 테스트는 기존 reverse 테스트처럼 `cfg(unix)`이고 Windows 쌍둥이는 M19(listen)·M20(serve --to)이 연다.
- 부하 필터 초안 `scripts/stress/m16.filter`를 만든다(Step 10이 완성).

**(b) 테스트·게이트:**

새 통합 모듈 `crates/qsh-testkit/tests/it/trust_withdrawal.rs`(실제 QUIC loopback, `tests/it/main.rs` 등재)와 기존 파일의 교체·추가다.

- 교체: `crates/qsh-cli/tests/it/trust_lifecycle_live.rs`의 `an_established_connection_survives_the_hosts_trust_remove` → `an_established_connection_is_closed_within_two_seconds_of_trust_remove`(실제 바이너리, `0x1005`, audit 한 줄 `trust_withdrawn`)
- 세 프로세스: `serve_inbound_connection_closes_on_trust_remove`, `serve_to_outbound_connection_closes_on_trust_remove`, `listen_registration_closes_on_trust_remove`
- 시계: `trust_withdrawal_closes_within_one_poll_tick_under_paused_time`(2초 보장의 계약 핀)
- 경로: `pin_and_ca_path_connections_each_close_on_trust_remove`, `removing_a_ca_closes_ca_path_connections_and_spares_pin_path_ones`, `pin_removed_but_ca_still_accepts_closes_on_auth_path_change`, `deleting_trust_toml_closes_every_connection`
- listen role: `listen_registration_closes_with_grants_reduced_when_target_role_drops_to_none`, `listen_registration_survives_a_same_or_wider_target_role`
- role: `set_role_narrowing_closes_with_grants_reduced`(`full`→`exec`, `full`→`tunnel`의 `any`→`owned` 행 포함), `set_role_widening_does_not_close`, `widen_then_narrow_closes_against_the_widened_record`, `rename_of_a_role_pin_closes_and_rename_of_a_roleless_pin_does_not`, `alias_reorder_does_not_close`
- 다른 항목: `unrelated_trust_changes_do_not_close_a_connection`, `acl_row_only_connection_survives_while_its_pin_remains`
- fail closed: `unparseable_trust_toml_keeps_connections_but_suspends_role_requests`, `an_unverifiable_connection_is_closed`(chain을 비운 합성 연결), `audit_failure_does_not_keep_a_withdrawn_connection_open`
- 닫힘 뒤: `closed_connection_sessions_detach_and_a_still_trusted_peer_resumes_with_reduced_grants`, `a_withdrawn_peer_cannot_handshake_again`, `supervised_tunnel_gives_up_after_trust_withdrawal`
- 재dial: `reverse/target/tests.rs`의 `trust_withdrawn_close_is_not_a_transient_loss`(로컬·상대 양쪽, 일반 backoff)
- audit: `record_has_only_structural_fields`(`crates/qsh-core/src/audit/tests.rs`)가 `connection_withdrawn`을 포함해 키 집합 그대로임을 계속 단언
- 문면: `cli_md_quotes_the_trust_narrowing_scope_verbatim`(새, `crates/qsh-core/tests/it/doctor_docs.rs` 옆 형식), 기존 `cli_md_quotes_the_trust_remove_scope_diagnostic_verbatim` 새 문면으로 초록, `doctor_reports_trust_remove_scope_only_once_a_peer_is_pinned` 초록
- P0 유지: `doctor_reports_cert_expiring_soon_within_the_30_day_window`와 `doctor_reports_cert_expiring_soon_at_exactly_the_30_day_window` 무변경 초록
- 새 fixture 없음(ADR-0031 결과 절). 기존 `trust.remove.json`·`trust.set_role.json`·`trust.rename.json` 무변경 초록

**(c) 완료 판정:**
- 세 프로세스가 같은 커밋에서 닫히고, 테스트 교체와 `TRUST_REMOVE_SCOPE`·CLI.md §6.11·§6.17 문면 변경이 같은 커밋에 있다.
- 위 테스트 중 시간 민감한 것(실제 시계 2초 단언, 세 프로세스, 닫힘 뒤)이 부하 아래 50회 연속 초록이다.
- `git diff`에 새 `ErrorCode`, 새 op, 새 fixture, 새 CLI 필드가 없다(ADR-0031 결정 1). wire diff 0.

### Step 4 — (a) 부트스트랩 스트림: 메시지 타입, 줄 파서, 버전 협상, fuzz 타깃, protocol.md 절 (0.3~0.4ew)

근거: ADR-0044 결정 11과 결과 절의 fuzz·계약 문서 항목. 선행: Step 1.

**(a) 범위:**

- 새 모듈 `crates/qsh-proto/src/ssh_bootstrap.rs`(sans-IO, async 없음):
  - 메시지 셋: `Hello { versions, qsh_version, status, fingerprint?, serve_bind?, serve_listening? }`, `Commit { version, fingerprint, name, role, address? }`, `BootstrapResult { status, name, role?, created, code?, message? }`. `status`는 열린 문자열을 닫힌 enum으로 읽되 모르는 값은 별도 변종으로 보존한다(결정 11 "알 수 없는 `status` 값은 `REMOTE_ERROR`(`bootstrap_protocol`)"). 모르는 필드는 무시한다.
  - 상수: 접두 `qsh-bootstrap `(`BOOTSTRAP_LINE_PREFIX`), 한 줄 상한 8 KiB(`BOOTSTRAP_LINE_MAX`), hello 앞 접두 없는 줄 합계 상한 64 KiB(`BOOTSTRAP_PREAMBLE_MAX`), 이 ADR의 버전 목록 `[1]`.
  - `parse_ssh_bootstrap_line(&[u8]) -> Result<BootstrapLine, BootstrapLineError>`와, hello 앞 접두 없는 줄을 개수만 세고 내용은 버리는 수신 상태 기계(가칭 `BootstrapReader`). hello 뒤의 접두 없는 줄, 상한 초과, 순서 위반은 프로토콜 오류다.
  - `negotiate_version(ours, theirs) -> Option<u32>`(교집합의 최댓값, 비면 `None` → client가 `UNSUPPORTED`).
  - 직렬화는 `serde_json`이고 한 줄에 개행이 들어가지 않음을 보장한다.
- fuzz: `fuzz/fuzz_targets/parse_ssh_bootstrap_line.rs`(줄 파서와 `BootstrapReader`에 임의 바이트를 넣음), `fuzz/Cargo.toml` 등록, 씨앗 corpus `fuzz/corpus/parse_ssh_bootstrap_line/`(정상 hello·commit·result 각 하나, rc 출력 섞인 입력).
- 문서:
  - `docs/design/protocol.md`에 새 절 "SSH 부트스트랩 스트림 (ADR-0044)"(접두, 상한, 메시지 셋, 버전 규칙, additive-only). §13 fuzz 표에 행. §16.2 목록에 상호운용 계약 한 행(§9 #5).
  - fuzz 개수 문장 20 → 21: `fuzz/README.md`, `docs/design/protocol.md` §13, `docs/design/threat-model.md` §3 끝 문장. 개수는 착지 시점의 실제 `fuzz/fuzz_targets` 수로 맞춘다.
  - `docs/design/threat-model.md` §4 E에 "조작된 응답자 출력이 client 파서를 깨거나 다른 이름·fingerprint를 심는다" 행의 파서 쪽 통제(상한, fuzz). 덮어쓰기 없음 쪽 핀은 Step 7이 같은 행에 덧붙인다.
- Windows: sans-IO라 플랫폼 차이 없음.

**(b) 테스트·게이트:**

- `crates/qsh-proto/src/ssh_bootstrap` 옆 tests: `bootstrap_line_round_trips_every_message`, `bootstrap_line_rejects_lines_over_8_kib`, `bootstrap_reader_skips_untagged_preamble_up_to_64_kib_and_keeps_only_a_count`, `bootstrap_reader_rejects_untagged_lines_after_hello`, `bootstrap_unknown_fields_are_ignored`, `bootstrap_unknown_status_is_preserved_as_unknown`, `negotiate_version_picks_the_largest_common_and_none_when_disjoint`
- fuzz 타깃 빌드 확인(`cargo +nightly fuzz build parse_ssh_bootstrap_line`이 도는 환경에서, 아니면 `fuzz/README.md`의 기존 절차)과 corpus 재생 단계(기존 타깃과 같은 방식)
- `crates/qsh-core/tests/it/op_registration_completeness.rs`·`failure_text_discipline.rs`는 이 스텝에서 영향 없음(op이 아직 없음)

**(c) 완료 판정:** fuzz 타깃 수가 문서 세 곳에서 실제 수와 같다. wire diff 0(이 스트림은 `.proto` 밖이다).

### Step 5 — (a) ssh 쪽 기계 장치: `[ssh]` 설정, `ssh -G`, 인자와 인용, ssh 자식, 종료 코드 사상, 가짜 `ssh` 하네스 (0.45~0.7ew)

근거: ADR-0044 결정 4, 6(키 읽기), 7, 9(로컬 ssh 자식 인자와 `<remote_qsh>` 인용), 14(ssh 종료 코드와 원격 셸별 사상), 16(터미널·BatchMode·타임아웃·Ctrl-C), 19(로그 규율), 20(`StrictHostKeyChecking` 비덮어쓰기), 25(`ssh.exe`), 결과 절의 하네스 문단. 선행: Step 4.

**(a) 범위:**

- 새 모듈 `crates/qsh-core/src/ssh_bootstrap/`(가칭 `mod.rs`, `ssh.rs`, `dest.rs`). 이 스텝은 원격과 말하지 않는 부분만 세운다.
- `[ssh]` 설정(`crates/qsh-core/src/config.rs`): `bootstrap`(`"auto"` 기본 | `"off"`, 그 밖은 `CONFIG_ERROR`), `program`(없으면 `PATH`의 `ssh`, Windows는 `ssh.exe`), `remote_qsh`(없으면 `qsh`). doctor `config_unknown_key`의 알려진 키 목록에 세 키. `docs/CLI.md` §6.12의 `config.toml` 키 목록과 §7의 `[ssh]` 문단.
- `<dest>` 검증(결정 7): `-`로 시작하면 ssh를 부르기 전에 `INVALID_ARGUMENT`, `ssh://` 꼴 거부, 이 장비가 쓸 pin 이름 기본값 = host 부분(마지막 `@`에서 자름, `crates/qsh-cli/src/cli.rs`의 `parse_target`과 같은 규칙을 `qsh-core`에 둔다), `validate_peer_label`과 `/` 금지.
- `ssh -G -- <dest>` 읽기(결정 4): 출력 64 KiB·줄 길이 상한, `hostname`·`user`·`proxyjump`·`proxycommand` 네 키만 꺼낸다(`user`는 저장하지 않는다, 결정 26). `proxyjump`/`proxycommand`가 `none`이 아니면 `ssh_proxied`(결정 6, 고지와 `data` 필드는 Step 7).
- 응답자 호출 인자(결정 9): `ssh -T -a -x -o ClearAllForwardings=yes -o RemoteCommand=none -o RequestTTY=no -o PermitLocalCommand=no [-o BatchMode=yes] -- <dest> <remote_qsh> pair ssh-respond`. `StrictHostKeyChecking`·`UserKnownHostsFile` 등 그 밖의 설정은 건드리지 않는다(결정 20). `<remote_qsh>`는 `[A-Za-z0-9_./~+:\\-]`만이면 그대로, 아니면 POSIX 작은따옴표 인용. `--remote-as`·`--role` 같은 사용자 문자열은 명령줄에 싣지 않는다.
- ssh 자식(결정 16): stdin·stdout 파이프, stderr와 제어 터미널은 물려받음. `BatchMode=yes`는 machine mode이거나 stdin이 터미널이 아닐 때만. hello까지 대기는 사람 모드 무제한·BatchMode 60초, hello 뒤 메시지마다 30초. SIGINT(Windows는 콘솔 Ctrl-C)에서 ssh가 끝나면 `CANCELED`로 끝나고 아무것도 쓰지 않는다. 자식이 끝날 때까지 기다려 좀비를 남기지 않는다.
- 종료 코드 사상(결정 14): 127과 9009 → `REMOTE_ERROR`(`remote_qsh_missing`, message에 `--remote-qsh`와 `[ssh].remote_qsh`), hello 없이 2 → `UNSUPPORTED`(`remote_qsh_too_old`), hello 없이 1 → `REMOTE_ERROR`(`remote_command_failed`, `details.remote_exit`, PowerShell 안내), 255 → `CONNECTION_FAILED`(`ssh_failed`, `details.ssh_exit`), ssh 실행 파일 없음 → `CONFIG_ERROR`(`ssh_not_found`, Windows는 선택적 기능 "OpenSSH Client"를 적음). ssh stderr는 다시 해석하지 않는다. 모든 `details.reason`은 additive다.
- 로그 규율(결정 19): tracing에는 단계와 결과 코드만. 접두 없는 줄은 개수만, ssh stderr는 로그로 복사하지 않는다. 키 재료를 읽는 코드 경로가 없다.
- 가짜 `ssh` 하네스(`crates/qsh-testkit`): testkit이 빌드하는 작은 Rust 실행 파일(가칭 `qsh-fake-ssh`, §7.1 #2). 받은 argv를 파일에 기록하고, 환경변수로 고른 모드에 따라 (1) `-G`에 미리 정한 출력을 내거나, (2) 다른 `QSH_CONFIG_DIR`로 로컬 `qsh pair ssh-respond`를 실행해 stdin·stdout을 이어 주거나(Step 6부터), (3) 정해진 종료 코드(127, 9009, 2, 1, 255)나 rc 출력·조작된 줄을 낸다. 하네스 헬퍼는 그 실행 파일을 `PATH` 앞에 두거나 `[ssh].program`으로 가리킨다.
- `docs/design/threat-model.md` §3에 진입점 행 "`qsh pair ssh`의 ssh 자식과 부트스트랩 스트림"(로컬 사용자 + ssh로 인증된 원격 계정의 출력, 신뢰할 수 없는 입력으로 파싱). §4 E에 "`<dest>`나 `--remote-qsh`로 ssh 옵션이나 원격 셸 명령을 주입한다" 행(결정 7·9). §4 A에 "처음 보는 host key를 받아들인 ssh 접속 위의 중간자" 행(결정 20, 잔여 위험은 Step 10이 §7에).
- 새 모듈의 arch 금지 편입 여부를 판단한다(§7.1 #1).
- Windows: 이 스텝의 코드는 전부 Windows 빌드에 들어간다(`ssh.exe` 탐색, 콘솔 Ctrl-C, 9009·1 사상). 가짜 `ssh` 하네스도 Windows에서 빌드된다. 응답자를 부르는 (2) 모드 테스트는 Windows 응답자가 M20이라 `cfg(unix)`이다.

**(b) 테스트·게이트:**

새 통합 모듈 `crates/qsh-cli/tests/it/ssh_bootstrap.rs`(`tests/it/main.rs` 등재)와 `ssh_bootstrap/` 옆 단위 tests.

- `ssh_bootstrap_ssh_argv_is_fixed`: 결정 9의 인자 집합, `--` 위치, `BatchMode`가 machine mode와 비터미널 stdin에서만 붙음, `StrictHostKeyChecking`이 argv에 없음
- `ssh_bootstrap_rejects_a_dest_that_looks_like_an_option`: ssh를 한 번도 부르지 않음(하네스 기록 0줄)
- `ssh_bootstrap_remote_qsh_quoting_is_bare_for_safe_chars_and_single_quoted_otherwise`(`C:/Program Files/qsh/qsh.exe` 같은 Windows 경로 행 포함)
- `ssh_g_output_is_capped_and_only_four_keys_are_read`, `ssh_g_proxyjump_marks_the_bootstrap_as_proxied`
- `ssh_exit_codes_map_to_the_adr_reasons`(127, 9009, 2, 1, 255 각각과 `ssh_not_found`)
- `ssh_config_bootstrap_value_outside_auto_off_is_a_config_error`, `config_unknown_key_knows_the_three_ssh_keys`
- `ssh_bootstrap_rc_output_is_counted_not_logged`(단위: tracing 캡처에 rc 줄 바이트가 없음)
- `ssh_child_is_reaped_on_cancel`(Unix SIGINT, Windows는 해당 쌍둥이를 `cfg(windows)`로)

**(c) 완료 판정:** Windows·macOS 다리에서 응답자 없는 테스트가 모두 돈다. 응답자를 부르는 경로가 아직 없으므로 사용자에게 보이는 명령은 없다(clap 변경 없음, man diff 0). wire diff 0.

### Step 6 — (a) 원격 응답자 `qsh pair ssh-respond` (0.3~0.5ew)

근거: ADR-0044 결정 9(숨김 하위 명령, envelope 없음, "operation 아님"), 10, 12의 응답자 쪽(잠금 아래 검사·쓰기, `exists`·`conflict`, role 불변, audit 순서), 결과 절의 응답자 핀. 선행: Step 3, Step 5.

**(a) 범위:**

- `qsh-cli`: 숨김 하위 명령 `pair ssh-respond`(`--help`에 나오지 않음, ADR-0012 결정 4의 숨김 방식). `qsh.cli/v1` envelope을 내지 않고 stdout은 부트스트랩 스트림, stdin은 commit이다. Unix 빌드에만 등록한다(§9 #2).
- `qsh-core` `ssh_bootstrap::respond`:
  - identity(`identity/device.pem`)를 읽고, 없으면 쓰기 없이 `status: not_initialized` hello. 원격 identity를 만들지 않는다.
  - serve 포트를 `[serve].bind`(없으면 `[::]:4433`)에서 정하고 그 주소로 UDP bind를 한 번 시도해 곧바로 닫는다. `EADDRINUSE` → `serve_listening: true`, 성공 → `false`, 그 밖 → `null`.
  - hello를 보내고 commit을 30초 기다린다. 오지 않으면 쓰지 않고 끝난다. 버전이 hello의 목록 밖이면 쓰지 않고 `error`.
  - commit을 받으면 `TrustStore::lock` 아래에서 load → 검사 → mutate → audit → save. 이 장비의 fingerprint가 이미 어떤 이름으로든 pin돼 있으면 `exists`(기존 이름과 role, role은 바꾸지 않음). 같은 이름이 다른 fingerprint로 있으면 `conflict`. 새로 쓸 때는 commit의 `address` 유무로 inbound 전용 pin 또는 주소 담은 pin(역방향 주소 갱신 규칙은 Step 8), role은 commit에 실린 값을 그대로 쓴다(기본값 `full`은 client가 정해 commit에 싣는다, Step 7. 응답자는 기본값을 따로 두지 않는다). `AuditRecord::local_op("pair.ssh_respond", <pin 이름>, <role>)`. audit를 쓸 수 없으면 pin도 쓰지 않고 `error`.
- 문서: `docs/CLI.md` §2.4에 "`qsh pair ssh-respond`는 operation이 아니다" 문장(`qsh serve` 문장과 같은 꼴)과 audit `action` 문자열 `pair.ssh_respond`. `docs/design/threat-model.md` §3 진입점 행 "`qsh pair ssh-respond`의 stdin"(ssh로 그 계정에 인증된 주체), §4 B "ssh로 그 계정에 로그인할 수 있는 누구나 `full` pin을 만든다" 행(결정 8, 근거 셋째 항목, audit 기록). man: 숨김 하위 명령의 페이지 처분을 확인한다(§7.1 #3).
- Windows: 응답자는 M20(ADR-0044 결정 10, ADR-0035 결정 25). M16 Windows 빌드는 이 하위 명령을 등록하지 않아 clap이 exit 2로 끝나고, client 쪽 사상(Step 5)이 `remote_qsh_too_old`로 읽는다. `SO_EXCLUSIVEADDRUSE` probe는 M20이 더한다.

**(b) 테스트·게이트:**

`crates/qsh-cli/tests/it/ssh_bootstrap.rs`와 `ssh_bootstrap/respond` 옆 단위 tests. 응답자를 직접 띄우고 stdin에 commit을 써 넣는 방식이다.

- `ssh_respond_reports_not_initialized_without_writing`
- `ssh_respond_serve_listening_reflects_a_bound_udp_port`(실제 `qsh serve` 하나를 띄운 행과 띄우지 않은 행)
- `ssh_respond_writes_an_inbound_only_pin_with_the_committed_role`
- `ssh_respond_returns_exists_and_keeps_the_role_for_a_known_fingerprint`
- `ssh_respond_returns_conflict_for_the_same_name_with_another_fingerprint`(`trust.toml` 바이트 불변)
- `ssh_respond_writes_nothing_when_commit_times_out`(시계 주입)
- `ssh_respond_refuses_to_pin_when_audit_is_unwritable`
- `ssh_respond_audit_record_has_only_structural_fields`(`record_has_only_structural_fields`와 같은 형식)
- `ssh_respond_is_hidden_from_help`
- `pair_ssh_respond_is_unknown_on_windows_before_m20`(`cfg(windows)`, exit 2)

**(c) 완료 판정:** 응답자 쓰기가 lock → load → mutate → audit → save 순서임을 테스트가 고정한다. wire diff 0. Windows 다리에서 `cfg(windows)` 테스트 초록.

### Step 7 — (a) `pair.ssh` op(정방향): 두 단계 쓰기, 확인 dial, 오류 사상, `PairSshData`, 렌더러, fixture, man (0.65~0.95ew)

근거: ADR-0044 결정 1(정방향 플래그 `--as`·`--remote-as`·`--role`·`--address`·`--remote-qsh`, local op), 5, 6(고지와 `data.ssh_proxied`), 8, 12의 client 쪽, 13(정방향 처분), 14의 hello 기반 사상, 15, 17, 18, 21, 26, 결과 절의 계약 문서·코드·핀 항목. 선행: Step 6.

**(a) 범위:**

- `qsh-proto`: `PairSshReq`·`PairSshData`(`direction`, `peer`(통일 pin 객체 `TrustPeer`), `created`, `remote { name, role, created }`, `next_command?`, `identity_created`, `ssh_proxied`, `verified`, `verify_error?`). 자리는 `crates/qsh-proto/src/types/trust.rs` 또는 새 `types/pair.rs`(§7.1 #4).
- `qsh-core` `Ops::pair_ssh`(새 파일 `crates/qsh-core/src/ops/pair_ssh.rs`, 인가 불요 local op `pair.ssh`):
  1. 이 장비 identity가 없으면 `Ops::identity_init`(멱등)을 먼저 부르고 `identity_created`(결정 18).
  2. `<dest>` 검증과 `ssh -G`(Step 5).
  3. ssh 자식으로 응답자를 띄우고 hello를 받는다. `not_initialized` → `REMOTE_ERROR`(`remote_not_initialized`, 원격에서 `qsh setup host` 안내). 버전 교집합 없음 → commit 없이 `UNSUPPORTED`.
  4. 쓰기 전 로컬 검사: 같은 이름이 다른 fingerprint로 있거나 원격 fingerprint가 다른 이름으로 pin돼 있으면 commit 없이 `SESSION_CONFLICT`(`pin_conflict`, `side: local`, `name`, `pinned_fingerprint`, `observed_fingerprint`).
  5. commit(`name` = 결정 8의 기본값 또는 `--remote-as`, `role` = `--role` 또는 `full`). 결과 `conflict` → `SESSION_CONFLICT`(`side: remote`), `error` → 응답자 `code`, `pinned`/`exists` → 계속. 결과 role이 요청과 다르면 사람 모드 stderr 한 줄과 `data.remote.role`에 실제 값(결정 12).
  6. 이 장비 pin을 쓴다. 주소는 `<ssh -G hostname>:<hello.serve_bind의 포트>`를 `normalize_peer_address`로(`--address`가 덮음), `role = "none"` 명시. `none`이라 audit 레코드는 없다(ADR-0045 결정 8, ADR-0044 결정 12). 디스크 오류로 실패하면 원격 pin만 남고 재실행이 수렴한다.
  7. 확인(결정 13). `serve_listening: false`면 dial하지 않고 `verified: false`, `verify_error`(`CONNECTION_FAILED`, `remote_serve_not_listening`). 그 밖에는 handshake와 mTLS 양방향 pin 검증까지만 하고 세션을 열지 않는다. 다른 인증서면 `AUTH_FAILED`(`remote_serve_identity_mismatch`), pin은 고치지 않는다. dial 실패는 기존 `CONNECTION_FAILED`에 `ssh_proxied` 사실을 덧붙인다. 확인이 실패해도 pin이 섰으면 exit 0.
  - `hosts.toml`, `config.toml`, `acl.toml`을 어느 쪽에서도 쓰지 않고 ssh `User`를 저장하지 않는다(결정 26).
- `qsh-cli`: clap `pair ssh <[user@]host>`와 정방향 플래그(`--reverse`/`--to`는 Step 8), human 렌더러(부트스트랩 직후 두 pin의 이름·role 고지, ADR-0045 결정 13의 페어링 고지와 같은 꼴, `ssh_proxied` 한 줄, role 불일치 한 줄, 충돌 시 재부트스트랩 두 줄과 `--remote-as` 안내), JSON 렌더러(envelope 하나만 stdout).
- 등록 완전성: schemars, `cli_v1_data_schema` arm, `CLI_V1_SCHEMA_COMMANDS`(`crates/qsh-core/tests/it/schema_commands_registry.rs`), 렌더러 둘, man `qsh-pair-ssh.1`(`cargo xtask man`), `docs/CLI.md` §2.4(`pair.ssh`), §2.5 "인가 불요" 행, §6.11 pairing 절의 `qsh pair ssh`(결정 1·7·8·12~18)와 `PairSshData`와 오류 표(결정 14·15).
- fixture(추가만, `REQUIRED_FIXTURES` 등재, `golden_*` 생산 테스트): `pair.ssh.json`(정방향 성공·`verified: true`), `pair.ssh.unverified.json`(`remote_serve_not_listening`), `error.SESSION_CONFLICT.pin_conflict.json`, `error.REMOTE_ERROR.remote_qsh_missing.json`.
- threat-model §4 B "이 장비 쪽 pin이 방향 없이 원격의 inbound 인증까지 통과시킨다"(결정 21), "기존 role 없는 pin을 부트스트랩이 `full`로 넓힌다"(결정 12), §4 D "rc 출력이나 ssh stderr에 섞인 비밀이 qsh 로그에 남는다"(결정 11·19), §4 E 응답자 출력 조작 행에 덮어쓰기 없음 핀 덧붙임.
- Windows: `qsh pair ssh`는 Windows client에서 연다(ADR-0044 결정 25). 원격 응답자가 필요한 테스트는 `cfg(unix)`이고, Windows 다리는 `remote_qsh_too_old`·`ssh_not_found`·`INVALID_ARGUMENT` 경로와 렌더러 테스트를 돈다.

- Step 5 리뷰에서 넘어온 것(`crates/qsh-core/src/ssh_bootstrap/`):
  - `Dest::parse`는 host 절반에 `validate_peer_label`을 늘 건다. 결정 7의 `--as`가 기본 pin 이름을 대신하므로, label 규칙에 맞지 않는 Host alias도 `--as`와 함께면 쓸 수 있어야 한다. ssh 피연산자 검증과 pin 이름 검증을 나눈다.
  - 실제 OpenSSH는 연결 뒤 SIGINT에 signal로 죽지 않고 255(`Killed by signal 2`)로 끝날 수 있다. 취소 토큰이 늦게 서면 `map_ssh_exit`가 `CONNECTION_FAILED`를 낸다. 호출자를 배선할 때 `reap_after_close`가 `cancel.is_canceled()`를 먼저 보고 `CANCELED`를 고른다. 테스트로 고정한다.
  - 옵션처럼 보이는 dest 거부를 pair 수준에서 단언한다(가짜 `ssh` 호출 0회). Step 5의 `ssh_bootstrap_rejects_a_dest_that_looks_like_an_option`은 `Dest::parse`만 부르므로 이 단언을 대신하지 못한다. 실제 호출자의 BatchMode 배선도 같이 고정한다.
  - `resolve`의 취소 경로(취소 시 `ssh -G` 자식 종료)와 Windows에서 실제 자식이 회수되는지를 테스트로 덮는다.

**(b) 테스트·게이트:**

`crates/qsh-cli/tests/it/ssh_bootstrap.rs`(가짜 `ssh` 하네스가 다른 `QSH_CONFIG_DIR`의 응답자를 부름).

- `ssh_bootstrap_pins_both_sides_and_connects`: 이 장비 pin은 ssh 별칭 이름과 `hostname:4433`, role `none`. 원격 pin은 address 빈 값, role `full`. 이어진 handshake 성공
- `ssh_bootstrap_role_flag_sets_the_remote_role`, `ssh_bootstrap_local_pin_has_explicit_role_none`
- `ssh_bootstrap_does_not_widen_an_existing_roleless_pin`
- `ssh_bootstrap_never_overwrites_a_pin_with_a_different_fingerprint`(로컬·원격 각각, 양쪽 `trust.toml` 바이트 불변)
- `ssh_bootstrap_writes_nothing_when_the_remote_cannot_respond`(127, 종료 코드 2, `not_initialized`, 9009, 버전 교집합 없음, commit 타임아웃 각각 양쪽 무변경)
- `ssh_bootstrap_reports_the_actual_remote_role_when_an_existing_pin_differs`
- `ssh_bootstrap_skips_untagged_stdout_and_never_logs_it`(rc 줄이 있어도 성공, 그 바이트가 stdout·stderr·로그 어디에도 없음, 64 KiB 초과면 `bootstrap_protocol`)
- `ssh_bootstrap_reports_identity_mismatch_when_serve_runs_another_identity`
- `ssh_bootstrap_unverified_when_remote_serve_is_not_listening`
- `ssh_bootstrap_initializes_a_missing_local_identity_once`
- `ssh_bootstrap_never_writes_hosts_config_or_acl_files`(결정 26, 양쪽 파일 집합 불변)
- `ssh_bootstrap_envelope_is_the_only_stdout_line`(`--json`)
- `pair_ssh_never_appears_as_a_control_message_wire_variant`(`setup_run_never_appears_as_a_control_message_wire_variant` 형식)
- `jsonl_purity.rs`·`exit_code_matrix.rs`에 `pair ssh` 행, `layer_2_every_schema_command_has_all_six_faces`, `checked_in_man_pages_match_the_generator`
- `failure_text_discipline.rs`가 새 `details.reason` 문면을 덮는다

**(c) 완료 판정:** 정방향 부트스트랩 뒤 기존 forward e2e 묶음(attach, exec, `qsh cp`)이 부트스트랩이 만든 pin만으로 초록이다(`bootstrapped_forward_route_passes_the_attach_exec_cp_suite`). 새 fixture 넷과 man 페이지가 같은 커밋에 있다. `capabilities.json` diff 0, wire diff 0.

### Step 8 — (a) 역방향 부트스트랩 `--reverse --to`, reverse route 동등, 캠페인 사전 고정 (0.4~0.7ew)

근거: ADR-0044 결정 1(`--reverse`·`--to` 조합 규칙), 12의 역방향 갈래(commit `address`, 주소 갱신, 이 장비 pin `reverse`와 그 audit), 13의 역방향 처분, 17의 `next_command`, 22, 결과 절의 역방향 핀과 사람 캠페인. 선행: Step 7.

**(a) 범위:**

- 플래그 검증: `--reverse`만, `--to`만, `--reverse`와 `--address` 조합은 ssh를 부르기 전에 `INVALID_ARGUMENT`. `--to`는 `trust add --address`와 같은 정규화.
- commit에 `address`(= 정규화한 `--to`)를 싣고 원격 pin role 기본값 `full`(ADR-0045 결정 8의 `host --to` listener pin 예외). 응답자는 기존 pin의 주소가 다르면 `trust add` 규칙으로 주소만 갱신한다(Step 6 응답자 코드에 갈래 추가).
- 이 장비 pin은 주소 없이 `role = "reverse"`. `AuditRecord::local_op("pair.ssh", <pin 이름>, "reverse")`를 lock → load → mutate → audit → save 순서로 남기고, audit를 쓸 수 없으면 이 장비 pin을 쓰지 않는다.
- 확인 dial을 하지 않고 `verified: false`, `verify_error` 없음. `data.next_command`와 사람 모드 stderr 한 줄이 원격에서 실행할 `qsh serve --to <이 장비를 pin한 이름>`(또는 `qsh service install`)을 안내한다. 원격에서 아무것도 띄우지 않고 `[serve].to`를 쓰지 않는다.
- clap `--reverse`·`--to`, man 재생성, `docs/CLI.md` §6.11 역방향 문단, fixture `pair.ssh.reverse.json`(+ `golden_*`).
- reverse route 동등: 역방향 부트스트랩이 만든 pin 둘만으로 원격 config가 `qsh serve --to`로 이 장비의 `qsh listen`에 등록하고, 기존 reverse e2e 묶음(`crates/qsh-cli/tests/it/reverse_e2e.rs`의 attach·exec, `cp_e2e.rs`의 reverse 왕복)과 같은 단언을 통과한다.
- 사람 캠페인 `docs/campaigns/p1-ssh-bootstrap.md`를 사전 고정해 커밋한다(구현 마지막 스텝인 Step 9 전, ADR-0044 결과 절). 정방향 ProxyJump·ssh-agent·암호 걸린 키 회차, 역방향 회차, 기록 표, PASS 판정. `CLAUDE.md` 문서 지도의 `docs/campaigns/` 목록에 `p1-ssh-bootstrap`을 더한다.
- threat-model: §4 B 결정 21 행에 역방향 `reverse` role 문장을 덧붙인다.
- Windows: 역방향의 이 장비 쪽(`qsh listen`)이 Windows에서 M19(ADR-0035 결정 14)라 Windows 다리는 플래그 검증 테스트만 돈다. 원격(target) 쪽 Windows는 M20.

**(b) 테스트·게이트:**

- `ssh_bootstrap_reverse_pins_listener_full_with_address_and_target_reverse_without`(원격 pin 주소와 `full`, 이 장비 pin 주소 없이 `reverse`, 확인 dial 없음, `verified: false`, `data.next_command`, 한쪽 플래그만·`--address` 조합은 ssh 호출 0회로 `INVALID_ARGUMENT`)
- `ssh_bootstrap_reverse_local_reverse_role_leaves_an_audit_record_and_needs_it`
- `ssh_bootstrap_reverse_updates_only_the_address_of_an_existing_remote_pin`
- `bootstrapped_reverse_route_passes_the_forward_attach_exec_cp_suite`
- `golden_pair_ssh_reverse`(fixture 생산)
- 타이밍 민감한 reverse 등록 테스트는 부하 아래 50회

**(c) 완료 판정:** 정방향(Step 7)과 역방향이 같은 attach·exec·`qsh cp` 단언을 통과한다. 캠페인 문서가 Step 9 착지 전에 커밋돼 있다. wire diff 0.

### Step 9 — (a) 자동 발동: `qsh [user@]host`와 `qsh cp`의 미등록 이름, `[ssh].bootstrap`, 사전 고지, README First run (0.3~0.55ew)

근거: ADR-0044 결정 2, 3, 16의 "대화형 형태는 ssh 자식이 끝난 뒤에야 raw 모드", ADR-0029 결정 2 마지막 항목(`qsh cp`의 발동), 결과 절의 §6.1·§7·`qsh cp` 절·README 항목. 선행: Step 7.

**(a) 범위:**

- 발동 조건은 `HOST_NOT_FOUND`의 첫 갈래("이름이 아예 미등록", `docs/CLI.md` §6.1)뿐이다. 다음이면 발동하지 않는다: `--json`/`--jsonl`, `hosts.toml`에 이름이 있음, reverse 등록이 stale로라도 있음, `trust.toml`에 그 이름의 pin이 있음, `[ssh].bootstrap = "off"`, `qsh exec`·`qsh session open`·`qsh tunnel open`·`qsh sessions`.
- 발동 전 stderr 한 줄 `qsh_core::ssh_bootstrap::AUTO_BOOTSTRAP_NOTICE`. 성공하면 원래 명령을 그대로 이어 간다. 대화형 형태는 ssh 자식이 끝난 뒤 raw 모드에 들어간다(TUI 진입점 `crates/qsh-cli/src/tui/`). 자동 경로의 확인은 원래 명령의 연결 자체이고, `serve_listening: false`면 `CONNECTION_FAILED`(`remote_serve_not_listening`)로 끝나며 pin은 남는다.
- 자동 발동은 역방향을 고르지 않는다(결정 22 마지막 항목).
- 발동 판정은 `qsh-core`(가칭 `Ops::should_auto_bootstrap`)에 둔다. `qsh-cli`는 분기만 한다.
- 사람 모드 `HOST_NOT_FOUND` message에 다음 명령 `qsh pair ssh <host>`를 적는다. `details`는 바꾸지 않는다(기존 `error.HOST_NOT_FOUND*` fixture 무변경 초록).
- 문서: `docs/CLI.md` §6.1 `HOST_NOT_FOUND` 문단, §7 자동 발동(결정 2·16), §6.21 `qsh cp` 절의 발동 문장. README First run에 `qsh box` 한 줄로 시작하는 경로를 기존 경로 앞에 둔다(§7의 README·스톱워치 항목).
- Windows: 대화형 attach와 `qsh cp`가 Windows에서 M19라 이 분기는 Windows에서 M19가 켠다(ADR-0035 결정 1·5, ADR-0044 결정 25). M16 Windows 빌드에서 그 두 표면은 지금처럼 `UNSUPPORTED`이고 발동 판정 함수의 단위 테스트는 Windows 다리에서도 돈다.

**(b) 테스트·게이트:**

- `ssh_bootstrap_is_never_implicit_in_machine_mode`(`qsh cp --json`이 가짜 ssh를 부르지 않음, 기록 0줄)
- `ssh_bootstrap_is_not_triggered_for_hosts_toml_or_reverse_names`, `ssh_bootstrap_off_in_config_is_respected`
- `ssh_bootstrap_is_not_triggered_for_exec_session_tunnel_or_sessions`
- `auto_bootstrap_prints_the_notice_before_ssh_runs`(stderr 순서: 고지 줄이 하네스의 첫 기록보다 먼저)
- `auto_bootstrap_then_cp_completes_the_original_command`(미등록 이름으로 `qsh cp` put 하나가 부트스트랩 뒤 그대로 끝남)
- `auto_bootstrap_then_interactive_attach_enters_raw_mode_only_after_ssh_exits`(`tui_expect.rs` 형식, `cfg(unix)`)
- `host_not_found_human_message_names_qsh_pair_ssh`
- `golden_*` 기존 `error.HOST_NOT_FOUND*` 무변경 초록

**(c) 완료 판정:** 발동 경계 여섯이 테스트로 고정됐다. machine mode에서 ssh 호출이 한 번도 없다. wire diff 0.

### Step 10 — 마감 (0.1~0.2ew)

근거: 마일스톤 마감 공통 절차(`docs/ROADMAP.md` §2) 1·2, §4 안정성 규율. 선행: Step 2~9.

**(a) 범위:**

- **부하 반복.** M16 타이밍 민감 테스트 전부를 `scripts/stress/m16.filter`로 묶는다(§7.1 #5). `QSH_ACCEPTANCE_SLOW=1 scripts/stress/run.sh`로 50회 돌리고 "50/50 passed under load" 줄과 호스트 사양을 마감 노트에 적는다. M16에는 새 지연 단언(p95 예산)이 없으므로 `m16-latency.filter`는 두지 않는다. §9 #4로 실제 시계 2초 단언을 옮겼다면 `scripts/stress/m16-latency.filter`를 두고 부하 없이 `-j 1`로 50회 돌린다.
- **절차 1. 구속 문서 태그 대조.** 대상은 다음과 같다.
  - `docs/CLI.md` v0.32 항목: §2.4·§2.5·§6.1·§6.9·§6.11·§6.12·§6.14·§6.17·§6.21·§7
  - `docs/design/protocol.md` §3·§7·§13·§16.2·§16.3·§16.5와 부트스트랩 스트림 절
  - `docs/design/architecture.md` §6(audit `resource` 두 값)과 `ssh_bootstrap` 모듈 서술
  - `docs/design/threat-model.md` §3·§4 A·B·D·E·§5 g2·§7
  - `fuzz/README.md`(21종)
  - ADR-0044·0031 결과 절 문서 목록 전수, ADR-0045 결정 4·12 문장이 ADR-0031 착지로 대체됐다는 기록
  - ADR-0044 결정 23·24(ADR-0026 결정 7의 별도 결정을 열지 않음, ADR-0015·0016 기각 사유의 대체 경로)가 문서에서 어긋나지 않음
  - Windows 귀속 기록: 자동 발동 Windows 분기 M19, 응답자 M20, `serve --to`·`listen` 재검증 테스트 쌍둥이 M19·M20(ADR-0035 결정 1·14·25)
- **절차 2. README 동기화.** 기능 목록(`qsh pair ssh`, 첫 `qsh box`의 자동 부트스트랩, trust 철회 시 2초 안 연결 닫기), Known limitations(ssh host 인증 강도 승계, ssh 접근을 거둬도 qsh pin은 남음, Windows 응답자는 M20, 거둔 신뢰는 그 장비에서만), 보안 절.
- threat-model §7 잔여 위험에 ADR-0044 결과 절의 둘을 적는다(qsh 신뢰는 그 ssh 접속의 host 인증 강도를 넘지 않음, ssh 접근 철회가 qsh pin에 전파되지 않음. 처방은 원격 `qsh trust remove`이고 Step 3이 그 순간 열린 연결까지 닫음).
- ROADMAP M16 마감 노트(main 세션). 이 `PLAN.md`의 마지막 커밋 해시를 적고 다음 계획으로 교체한다. 계획 원문은 커밋 해시로 인용한다(ROADMAP 머리말 규칙). §5.5에 M16이 만든 사람 몫 둘(§0.3)의 상태를 적는다.

**(b) 테스트·게이트:** 일곱 게이트, CI(acceptance 포함) 초록, 부하 반복 50/50.

**(c) 완료 판정:** §3의 DoD가 근거 커밋, run id와 함께 `[x]`다. `git diff --stat <Step 2 부모>..<Step 9 머지> -- crates/qsh-proto/proto crates/qsh-proto/src/wire.rs crates/qsh-proto/src/local.rs crates/qsh-cli/tests/fixtures/cli-v1/capabilities.json`이 비어 있다. M16에는 wire 변경을 소유한 스텝이 없다.

## 5. 결정·핀 테스트 대응표

각 결정과 핀 테스트의 주인은 스텝 하나다. 한 결정이 여러 스텝에 걸치면 하위 항목으로 나눠 각각 주인 하나를 적는다.

### 5.1 ADR-0031 결정

| 결정 | 스텝 |
|---|---|
| 1 범위와 불변식, 새 표면 없음 | 3 |
| 2 재검증하는 연결 셋, 방향 간 동등 | 3 |
| 3 세대 번호, `watch`, 1초 poll | 2 |
| 3 연결별 감시와 수명 묶음, 플랫폼 문단 | 3 |
| 4 chain·역할 보관, `Connection::reverify`, 기록값 모양, role grant 함수 공유 | 2 |
| 5 닫는 조건과 닫지 않는 경우 | 3 |
| 6 fail closed | 3 |
| 7 `CLOSE_CODE_TRUST_WITHDRAWN` 정의 | 2 |
| 7 닫는 동작, `serve --to` 재dial 분류, `listen` 등록표 | 3 |
| 8 audit `connection_withdrawn`, `resource` 두 값 | 3 |
| 9 문면 상수, doctor `TRUST_REMOVE_SCOPE`, CLI.md·README 문장 | 3 |
| 10 protocol.md §3 문장 | 3 |
| 10 protocol.md §16.3·§7·§16.5 `0x1005` | 2 |

### 5.2 ADR-0031 핀 테스트와 결과 절 항목

| 항목 | 스텝 |
|---|---|
| `an_established_connection_is_closed_within_two_seconds_of_trust_remove`(교체) | 3 |
| `serve_inbound_connection_closes_on_trust_remove` | 3 |
| `serve_to_outbound_connection_closes_on_trust_remove` | 3 |
| `listen_registration_closes_on_trust_remove` | 3 |
| `trust_withdrawal_closes_within_one_poll_tick_under_paused_time` | 3 |
| `pin_and_ca_path_connections_each_close_on_trust_remove` | 3 |
| `removing_a_ca_closes_ca_path_connections_and_spares_pin_path_ones` | 3 |
| `pin_removed_but_ca_still_accepts_closes_on_auth_path_change` | 3 |
| `deleting_trust_toml_closes_every_connection` | 3 |
| `listen_registration_closes_with_grants_reduced_when_target_role_drops_to_none` | 3 |
| `listen_registration_survives_a_same_or_wider_target_role` | 3 |
| `set_role_narrowing_closes_with_grants_reduced` | 3 |
| `set_role_widening_does_not_close` | 3 |
| `widen_then_narrow_closes_against_the_widened_record` | 3 |
| `rename_of_a_role_pin_closes_and_rename_of_a_roleless_pin_does_not` | 3 |
| `alias_reorder_does_not_close` | 3 |
| `unrelated_trust_changes_do_not_close_a_connection` | 3 |
| `acl_row_only_connection_survives_while_its_pin_remains` | 3 |
| `unparseable_trust_toml_keeps_connections_but_suspends_role_requests` | 3 |
| `an_unverifiable_connection_is_closed` | 3 |
| `audit_failure_does_not_keep_a_withdrawn_connection_open` | 3 |
| `closed_connection_sessions_detach_and_a_still_trusted_peer_resumes_with_reduced_grants` | 3 |
| `a_withdrawn_peer_cannot_handshake_again` | 3 |
| `supervised_tunnel_gives_up_after_trust_withdrawal` | 3 |
| `trust_withdrawn_close_is_not_a_transient_loss` | 3 |
| `cli_md_quotes_the_trust_narrowing_scope_verbatim` | 3 |
| `record_has_only_structural_fields` 키 집합 불변 | 3 |
| `reverify_agrees_with_the_handshake_verdict_for_pin_ca_and_pairing` | 2 |
| `reverify_rejects_a_connection_with_an_empty_chain` | 2 |
| `trust_store_generation_bumps_only_when_the_snapshot_changes` | 2 |
| `trust_store_poll_notifies_subscribers_within_one_tick` | 2 |
| `role_grants_cover_relation_treats_any_as_covering_owned` | 2 |
| `authorizer_and_reverify_share_one_role_grant_function` | 2 |
| threat-model §5 g2, §4 B 행, §7 h4·h5·h35 | 3 |
| 새 fixture 없음, 새 `ErrorCode` 없음(검증) | 3 |

### 5.3 ADR-0044 결정

| 결정 | 스텝 |
|---|---|
| 1 `qsh pair ssh`, `pair.ssh` 이름, local op, 정방향 플래그 | 7 |
| 1 `--reverse`·`--to` 조합 규칙 | 8 |
| 2 자동 발동과 경계, `AUTO_BOOTSTRAP_NOTICE`, `[ssh].bootstrap` 판정 | 9 |
| 2 `[ssh].bootstrap` 설정 키와 `CONFIG_ERROR` | 5 |
| 3 pin 뒤 ssh 미호출 | 9 |
| 4 `ssh -G`, `[ssh].program`, 최소 버전, 64 KiB 상한 | 5 |
| 5 dial 주소 | 7 |
| 6 proxy 키 읽기 | 5 |
| 6 proxy 고지와 `data.ssh_proxied` | 7 |
| 7 이름 기본값과 `<dest>` 검증 | 5 |
| 8 원격이 쓰는 이름 기본값과 role `full` | 7 |
| 9 ssh 인자와 `<remote_qsh>` 인용 | 5 |
| 9 숨김 `pair ssh-respond`, "operation 아님", audit `action` | 6 |
| 10 응답자 순서와 UDP bind 확인(Unix·macOS) | 6 |
| 10 Windows 응답자와 `SO_EXCLUSIVEADDRUSE` | M20 밖(ADR-0035 결정 25) |
| 11 스트림 형식, 상한, 메시지, 버전, 파서, fuzz | 4 |
| 12 응답자 쪽 검사·쓰기·audit | 6 |
| 12 client 쪽 검사·쓰기, role 불일치 안내 | 7 |
| 12 역방향 주소 갱신과 이 장비 `reverse` pin audit | 8 |
| 13 정방향 확인 dial 처분 | 7 |
| 13 역방향 무확인 | 8 |
| 13 자동 경로의 확인 = 원래 연결 | 9 |
| 14 ssh 종료 코드·원격 셸별 사상, `ssh_not_found` | 5 |
| 14 hello 기반 사상(`remote_not_initialized`) | 7 |
| 15 pin 불일치 fail closed와 문면 | 7 |
| 16 터미널, BatchMode, 타임아웃, Ctrl-C | 5 |
| 16 raw 모드는 ssh 뒤 | 9 |
| 17 `PairSshData`와 machine mode | 7 |
| 17 `next_command` | 8 |
| 18 로컬 identity 자동 생성 | 7 |
| 19 키 재료·rc 출력·ssh stderr 로그 규율 | 5 |
| 20 `StrictHostKeyChecking` 비덮어쓰기 | 5 |
| 20 잔여 위험 문장 | 10 |
| 21 pin 방향과 role `none` | 7 |
| 22 역방향 route | 8 |
| 23 ADR-0026과의 관계(문서 대조) | 10 |
| 24 ADR-0015·0016 기각과의 관계(문서 대조) | 10 |
| 25 Windows client `ssh.exe`와 사상 | 5 |
| 25 Windows client 자동 발동 | M19 밖(ADR-0035 결정 1·5) |
| 25 Windows 응답자 | M20 밖(ADR-0035 결정 25) |
| 26 하지 않는 일 | 7 |

### 5.4 ADR-0044 핀 테스트와 결과 절 항목

| 항목 | 스텝 |
|---|---|
| `ssh_bootstrap_pins_both_sides_and_connects` | 7 |
| `ssh_bootstrap_role_flag_sets_the_remote_role` | 7 |
| `ssh_bootstrap_local_pin_has_explicit_role_none` | 7 |
| `ssh_bootstrap_does_not_widen_an_existing_roleless_pin` | 7 |
| `ssh_bootstrap_never_overwrites_a_pin_with_a_different_fingerprint` | 7 |
| `ssh_bootstrap_writes_nothing_when_the_remote_cannot_respond` | 7 |
| `ssh_bootstrap_reverse_pins_listener_full_with_address_and_target_reverse_without` | 8 |
| `ssh_bootstrap_reverse_local_reverse_role_leaves_an_audit_record_and_needs_it` | 8 |
| `ssh_bootstrap_reports_the_actual_remote_role_when_an_existing_pin_differs` | 7 |
| `ssh_bootstrap_remote_qsh_quoting_is_bare_for_safe_chars_and_single_quoted_otherwise` | 5 |
| `ssh_bootstrap_ssh_argv_is_fixed` | 5 |
| `ssh_bootstrap_rejects_a_dest_that_looks_like_an_option` | 5 |
| `ssh_bootstrap_skips_untagged_stdout_and_never_logs_it` | 7 |
| `ssh_bootstrap_is_never_implicit_in_machine_mode` | 9 |
| `ssh_bootstrap_is_not_triggered_for_hosts_toml_or_reverse_names` | 9 |
| `ssh_bootstrap_off_in_config_is_respected` | 9 |
| `ssh_bootstrap_reports_identity_mismatch_when_serve_runs_another_identity` | 7 |
| `ssh_respond_refuses_to_pin_when_audit_is_unwritable` | 6 |
| `ssh_respond_audit_record_has_only_structural_fields` | 6 |
| `ssh_bootstrap_envelope_is_the_only_stdout_line` | 7 |
| 계획 추가: `ssh_exit_codes_map_to_the_adr_reasons`, `ssh_g_output_is_capped_and_only_four_keys_are_read`, `ssh_g_proxyjump_marks_the_bootstrap_as_proxied`, `ssh_config_bootstrap_value_outside_auto_off_is_a_config_error`, `config_unknown_key_knows_the_three_ssh_keys`, `ssh_bootstrap_rc_output_is_counted_not_logged`, `ssh_child_is_reaped_on_cancel` | 5 |
| 계획 추가: `ssh_respond_reports_not_initialized_without_writing`, `ssh_respond_serve_listening_reflects_a_bound_udp_port`, `ssh_respond_writes_an_inbound_only_pin_with_the_committed_role`, `ssh_respond_returns_exists_and_keeps_the_role_for_a_known_fingerprint`, `ssh_respond_returns_conflict_for_the_same_name_with_another_fingerprint`, `ssh_respond_writes_nothing_when_commit_times_out`, `ssh_respond_is_hidden_from_help`, `pair_ssh_respond_is_unknown_on_windows_before_m20` | 6 |
| 계획 추가: `ssh_bootstrap_unverified_when_remote_serve_is_not_listening`, `ssh_bootstrap_initializes_a_missing_local_identity_once`, `ssh_bootstrap_never_writes_hosts_config_or_acl_files`, `pair_ssh_never_appears_as_a_control_message_wire_variant`, `bootstrapped_forward_route_passes_the_attach_exec_cp_suite` | 7 |
| 계획 추가: `ssh_bootstrap_reverse_updates_only_the_address_of_an_existing_remote_pin`, `bootstrapped_reverse_route_passes_the_forward_attach_exec_cp_suite` | 8 |
| 계획 추가: `ssh_bootstrap_is_not_triggered_for_exec_session_tunnel_or_sessions`, `auto_bootstrap_prints_the_notice_before_ssh_runs`, `auto_bootstrap_then_cp_completes_the_original_command`, `auto_bootstrap_then_interactive_attach_enters_raw_mode_only_after_ssh_exits`, `host_not_found_human_message_names_qsh_pair_ssh` | 9 |
| 줄 파서 단위 일곱(`bootstrap_line_*`, `bootstrap_reader_*`, `bootstrap_unknown_*`, `negotiate_version_*`) | 4 |
| fuzz `parse_ssh_bootstrap_line`, corpus, 개수 문장 20 → 21 | 4 |
| `docs/design/protocol.md` 부트스트랩 스트림 절, §13, §16.2 행 | 4 |
| `PairSshData`의 `CLI_V1_SCHEMA_COMMANDS`·`cli_v1_data_schema` 등록 | 7 |
| fixture `pair.ssh`·`pair.ssh.unverified`·`error.SESSION_CONFLICT.pin_conflict`·`error.REMOTE_ERROR.remote_qsh_missing` | 7 |
| fixture `pair.ssh.reverse` | 8 |
| man `qsh-pair-ssh.1` 신설 | 7 |
| man `qsh-pair-ssh.1` `--reverse`·`--to` 갱신 | 8 |
| `docs/CLI.md` §2.4 "operation 아님" 문장 | 6 |
| `docs/CLI.md` §2.4 `pair.ssh`, §2.5, §6.11 | 7 |
| `docs/CLI.md` §6.12 `[ssh]` 키 | 5 |
| `docs/CLI.md` §6.1, §7, §6.21 | 9 |
| threat-model §3 진입점 "ssh 자식과 부트스트랩 스트림" | 5 |
| threat-model §3 진입점 "`pair ssh-respond`의 stdin" | 6 |
| threat-model §4 A ssh host 인증 승계 | 5 |
| threat-model §4 B `full` pin 생성 | 6 |
| threat-model §4 B 방향 없는 pin, role 확대 | 7 |
| threat-model §4 D 로그 유출 | 7 |
| threat-model §4 E 응답자 출력 조작(파서 쪽) | 4 |
| threat-model §4 E 옵션·셸 주입 | 5 |
| threat-model §7 잔여 둘 | 10 |
| 사람 캠페인 `docs/campaigns/p1-ssh-bootstrap.md` 사전 고정 | 8 |
| README First run | 9 |
| README 기능 목록·Known limitations·보안 절 | 10 |

## 6. 명시적 non-goals

- 조직 계정·중앙 관리(PRD §12 경계 밖), SSH 공개키를 principal로 쓰는 것(ADR-0026이 거부), 원격 qsh 설치·serve 기동·서비스 유닛 등록(ADR-0044 결정 26). ROADMAP M16 명시적 out.
- `StrictHostKeyChecking` 덮어쓰기(ADR-0044 결정 20), `~/.ssh/config` 직접 파싱, ssh를 세션 transport로 계속 쓰는 폴백(ADR-0043), `--replace` 덮어쓰기 플래그(ADR-0044 대안 절).
- revocation 목록·`qsh trust revoke`, rotation 문서·`qsh identity rotate`·`qsh trust rotate`, CA 발급 인증서 개별 revoke와 CRL·OCSP, leaf 유효기간 기한 연결 만료(ADR-0031 대안 절, 2026-10-12 폐기).
- 신뢰를 거둔 principal의 세션 즉시 종료(ADR-0031 결정 7, ADR-0033 몫), 다른 장비로의 철회 전파, 파일 감시·프로세스 간 신호(ADR-0031 대안 절).
- 새 `ErrorCode`, 새 wire 메시지, `.proto` 변경, `capabilities.json` 변경, 새 doctor code.
- Windows: 대화형·`qsh cp` 자동 발동은 M19, 응답자 `pair ssh-respond`는 M20, `serve --to`·`listen` 재검증의 Windows 테스트 쌍둥이는 M20·M19(ADR-0035 결정 1·5·14·25).
- 에이전트가 하는 `gh secret set`, `gh workflow run`, 태그 push, 저장소 설정 변경.
- P2 전부(jump chaining 포함).

## 7. 리스크와 감시 항목

- **2초 보장과 부하.** poll 1초에 연결당 판정 여유 1초다. CPU 부하 아래에서 tokio 타이머와 감시 작업 스케줄이 밀리면 실제 시계 단언이 흔들릴 수 있다. 계약 핀은 시간 정지 테스트가 맡고, 실제 시계 테스트는 부하 아래 50회로 확인한다. 흔들리면 §9 #4.
- **CA 경로 재검증 비용.** 연결마다 chain 검증을 다시 한다. 연결 수는 ADR-0010 상한이 묶지만 `trust.toml`이 바뀔 때마다 모든 연결이 동시에 깬다. Step 3이 연결 수 상한 근처(기본 상한 연결 수)에서 한 번의 변경이 끝나는 시간을 재고 커밋 본문에 적는다. 2초를 넘으면 착지하지 않고 main 세션이 정한다.
- **chain 보관의 메모리.** 연결당 수 KB(ADR-0031 맥락). 상한 연결 수에서 MB 단위라 문제로 보지 않지만 Step 2 커밋 본문에 상한 기준 추정치를 적는다.
- **`trust/mod.rs`와 `server/mod.rs`의 충돌.** (b)와 (a)가 같은 파일을 만진다. 순서(§4)와 병렬 표가 줄이고, Step 6은 Step 3 뒤로 묶었다.
- **가짜 `ssh`와 실제 OpenSSH의 차이.** 하네스는 argv와 stdio만 흉내 낸다. ProxyJump·ControlMaster·host key 프롬프트·`RemoteCommand` 충돌 같은 실제 동작은 사람 캠페인 몫이다. 특히 결정 9의 `-o RemoteCommand=none`이 설정 파일의 `RemoteCommand`와 충돌하지 않는지는 OpenSSH 7.6 이상의 실제 ssh로만 확인된다. 에이전트는 Step 5에서 머신에 있는 실제 `ssh -G`(네트워크 없음)로 인자 수용 여부를 한 번 확인하고 버전을 커밋 본문에 적는다.
- **원격 셸 종료 코드의 모호성.** PowerShell의 1은 다른 실패와 구별되지 않는다(ADR-0044 결정 14). `remote_command_failed`의 message가 안내를 대신한다. 사람 캠페인이 Windows 원격 회차를 갖는 것은 M20 이후다.
- **README First run과 스톱워치.** First run은 m7·m9 스톱워치가 재는 "literal script"다. m9 대상 트리는 `docs/campaigns/m9-stopwatch.md` §8에 SHA로 고정돼 있어 Step 9의 First run 변경이 측정을 흔들지 않는다. `p1-setup-stopwatch`는 실행 전에 SHA를 채우므로 문서를 고치지 않는다.
- **CLI.md 상태 헤더와 `REQUIRED_FIXTURES` 충돌.** 병렬 스텝(2∥4, 3∥4·5)이 같은 한 줄, 같은 배열, threat-model §3 개수 문장을 만진다. 늦게 착지하는 쪽이 rebase하고 개수 문장(fuzz 20 → 21)을 착지 시점 값으로 맞춘다.
- **Windows 다리의 늦은 실패.** M15의 보정 커밋 넷이 보여 준 패턴이다. §4 규율의 로컬 Windows 타깃 검사로 줄이고, 그래도 CI Windows 다리에서 깨지면 보정 커밋을 같은 스텝 이름으로 단다.

### 7.1 구현 중 확정할 값 (해당 step (a)에 근거와 함께 추기)

| # | 질문 | 초안 | 확정 시점 |
|---|---|---|---|
| 1 | `ssh_bootstrap` 모듈의 arch 금지 편입 | `crates/qsh-core/src/ssh_bootstrap/`은 자식 프로세스와 UDP probe만 쓰고 QUIC를 이름 짓지 않으므로 `crates/qsh-core/src/`의 `quinn::` 금지로 충분하다. 확인 dial은 `qsh_transport`의 중립 타입으로 한다. 디렉터리 범위 금지를 새로 더하지 않는 쪽이 초안 | Step 5 |
| 2 | 가짜 `ssh` 실행 파일의 자리 (확정: `crates/qsh-testkit/src/bin/qsh-fake-ssh.rs`, `FakeSsh::locate_bin`이 nextest 빌드 산출물을 찾고 없으면 `cargo build` 한 번, mode는 환경 변수가 아니라 복사한 바이너리 옆 `fake-ssh.cfg`로 고른다(`set_var` 경합 회피, testing.md)) | `crates/qsh-testkit`에 `[[bin]] qsh-fake-ssh`를 두고 하네스 헬퍼가 `env!("CARGO_BIN_EXE_qsh-fake-ssh")`로 찾는다. testkit bin이 cargo-deny나 release 묶음에 들어가지 않는지 확인 | Step 5 |
| 3 | 숨김 `pair ssh-respond`의 man 페이지 (확정: 생성기가 숨김 하위 명령을 건너뛰어 페이지 없음, `qsh reverse`·`qsh trust invite`와 같다. Windows 빌드는 하위 명령을 등록하지 않고 Windows 응답자는 M20(ADR-0044 결정 10)) | 생성기가 숨김 하위 명령을 건너뛰면 페이지 없음. 건너뛰지 않으면 생성기에서 숨김을 걸러 내는 쪽(사용자 표면이 아니므로) | Step 6 |
| 4 | `PairSshReq`·`PairSshData`의 자리 | `crates/qsh-proto/src/types/trust.rs`(origin `1a4af3b` 기준 360줄)에 더한다. 800줄을 넘기게 되면 새 `types/pair.rs` | Step 7 |
| 5 | M16 부하 filterset | 테스트 이름 접두 `trust_withdrawal::`, `an_established_connection_is_closed`, `ssh_bootstrap`, `ssh_respond`, `auto_bootstrap`, `bootstrapped_`, `trust_store_poll_` | Step 3·10 |
| 6 | `TRUST_NARROWING_SCOPE` 상수의 모양 | 세 문장(언제·어디에·무엇을 하지 않는가)을 한 `&'static str`로. `trust remove`·`set-role`·`rename` 렌더러와 doctor message가 같은 상수를 인용 | Step 3 |
| 7 | 감시 작업이 쓰는 trust store 핸들 | 세 프로세스가 이미 각자 여는 `SharedTrustStore` 하나에 poll 작업 하나(ADR-0031 결정 3). `qsh listen`의 handshake verifier와 감시가 같은 핸들을 공유하는지 Step 3이 확인 | Step 3 |
| 8 | 응답자 commit 대기 시계 | `ssh_bootstrap::respond`에 시계를 주입해 30초 타임아웃을 시간 정지 테스트로 고정 | Step 6 |
| 9 | 역방향 원격 pin 주소 갱신의 audit | ADR-0044 결정 12는 새 pin 쓰기의 audit만 적는다. 주소만 갱신하는 `exists` 갈래는 `trust add`의 주소 갱신과 같은 처분을 따른다(현재 `trust add`가 그 경우 audit를 남기는지 Step 8이 확인하고 같게 맞춘다) | Step 8 |

## 8. 완료 절차

1. §3 DoD 전건을 실제 테스트와 CI run으로 확인한다. 체크박스는 근거가 초록일 때만 채운다.
2. 부하 반복 50/50을 기록한다(Step 3·10).
3. 구속 문서 태그를 대조한다(Step 10 (a)의 목록 전수).
4. README를 동기화한다.
5. `docs/ROADMAP.md` "현재 위치"와 M16 절을 갱신하고 마감 노트를 적는다(main 세션).
6. §0.1, §0.2, §0.3의 상태를 승계한다.
7. 이 `PLAN.md`를 다음 계획으로 교체하고, 마감 노트에 이 계획의 마지막 커밋 해시를 적는다.

## 9. 열린 질문

각 항목의 권고는 main 세션이 Step 1 커밋(2026-10-15)에서 그대로 결정으로 확정했다. 2026-10-14 사용자 위임 결정("전부 다 알아서 진행해")의 범위다.

1. **ROADMAP M16 DoD에 안정성 줄을 더할 것인가.** M12·M15에는 있다. **권고:** 더한다. Step 1이 M15 문면을 옮긴다.
2. **M16 Windows 빌드의 `pair ssh-respond`.** ADR-0044 결정 10은 "M20 전의 Windows 빌드는 이 하위 명령을 몰라 `remote_qsh_too_old`"라고 적고, ADR-0035 결정 1의 "착지와 함께 열린다"는 client 쪽 `pair ssh`와 응답자를 한 문장에 묶는다. 두 문장은 ADR-0035 결과 절의 M20 목록(`pair ssh-respond`)과 결정 25로 맞춰진다. **권고:** client `qsh pair ssh`는 M16에서 Windows에도 열고, 응답자는 Unix 빌드에만 등록한다. Windows는 clap이 exit 2로 끝나 client가 `remote_qsh_too_old`로 읽는다(`pair_ssh_respond_is_unknown_on_windows_before_m20`). ADR 개정은 필요 없다.
3. **Windows `ssh.exe` 사람 회차.** ADR-0044 결과 절의 캠페인은 Windows `ssh.exe`를 포함한다. 그러나 Windows의 대화형 `qsh box`(자동 발동의 대표 경로)는 M19다. **권고:** `p1-ssh-bootstrap.md`는 Linux·macOS client 회차와 Windows client의 명시 `qsh pair ssh` 회차를 갖고, Windows 대화형 회차는 M19의 `p1-windows.md`가 이어받는다고 문서에 적는다.
4. **실제 시계 2초 단언이 부하 아래에서 흔들릴 때.** **권고:** 실제 시계 테스트의 단언은 "trust.toml 쓰기 시각부터 2초"로 두고 부하 아래 50회를 먼저 시도한다. 50/50이 안 되면 그 테스트들만 `scripts/stress/m16-latency.filter`로 옮겨 부하 없이 `-j 1`로 50회를 요구하고, 계약 핀은 `trust_withdrawal_closes_within_one_poll_tick_under_paused_time`이 맡는다. 단언을 2초보다 느슨하게 바꾸지는 않는다.
5. **부트스트랩 스트림의 freeze 지위.** ADR-0044 결정 11은 "§16의 freeze 규칙 중 additive-only를 같은 방식으로 따른다"고만 적는다. **권고:** `docs/design/protocol.md` §16.2(`.proto` 밖의 상호운용 계약)에 한 행으로 올린다. freeze 발효(M8 DoD 4) 뒤에도 같은 규칙이 적용된다는 뜻이고, 결정 11의 문장과 어긋나지 않는다.
6. **(b)와 (a)의 순서.** ROADMAP M16 범위는 (a)를 먼저 적지만 순서를 정하지 않는다. **권고:** §4 "순서의 근거"대로 (b)를 먼저 둔다. (a)의 첫 스텝(Step 4)은 Step 2·3과 병렬로 열 수 있어 일정상 손실이 없다.
7. **태그.** M16 DoD에는 태그가 필요 없다. **권고:** 찍을지는 유지보수자가 정한다. §0.3의 사람 캠페인과 `parse_ssh_bootstrap_line` fuzz-hours가 그 바이너리로 돌 수 있으므로 Step 9 뒤 태그 하나를 권한다.
