# PLAN.md — M15: 역할 기반 권한과 scp 호환 파일 복사

P1 M15의 실행 계획이다. 직전 내용은 승인 대기용 자리표시자였고, 이 문서가 그 자리를 전면 교체한다. 2026-10-14 사용자 위임 결정("전부 다 알아서 진행해")으로 착수 ADR 둘(ADR-0045 역할 기반 권한, ADR-0029 `qsh cp`)이 `승인됨`이 되어 착수 조건이 모두 충족됐다. 구속 근거는 다음과 같다.

- `docs/ROADMAP.md` §5의 M15 절(범위 (a)(b), 착수 조건, 명시적 out, 수용 기준, 크기), §5.1 시퀀싱 원칙(특히 원칙 3·5·6·7), §5.4 일정 리스크 2, §5.5 P1 사람 몫, 마일스톤 마감 공통 절차(같은 문서 §2)
- ADR-0045 결정 1~20과 결과 절, ADR-0029 결정 1~23과 결과 절
- 두 ADR이 개정하는 ADR-0017 결정 2·3, ADR-0024 결정 4·9, ADR-0025 결정 2·3·6, ADR-0038
- 참조 ADR: ADR-0010(quota 모양), ADR-0037(정체 장부), ADR-0043(QUIC 하나), ADR-0035 결정 1·24·26(Windows 대응, M19·M20)
- `docs/CLI.md` §2.4·§2.5·§4·§6.11·§6.12·§6.13·§6.15·§6.17·§6.19·§6.20과 새 `qsh cp` 절
- `docs/design/protocol.md` §4·§7·§9·§12·§13·§16.1, `docs/design/architecture.md` §6·§7, `docs/design/threat-model.md` §2·§3·§4 B·§7, `docs/PRD.md` §9
- `CLAUDE.md` "Security defaults"

이 계획과 `docs/ROADMAP.md`의 편집은 main 세션만 한다.

인용 규율은 M13판과 같다. 문서는 절 이름, ADR 번호와 결정 번호, 테스트 이름, 커밋 해시로 가리킨다. 코드 위치는 파일 경로와 심볼 이름으로 가리키고, 줄 수나 개수를 적을 때는 origin `09266dc` 트리에서 잰 값임을 밝힌다. 옛 계획의 스텝 번호는 새로 인용하지 않는다.

## 0. 열린 사람 몫

여기 적힌 항목은 이 파일이 다음 계획으로 바뀔 때 그대로 승계한다.

### 0.1 P0에서 열린 일곱

- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** 기준은 `docs/campaigns/m10-clean-vm.md`. Linux 회차는 PASS(v0.3.0 세 회차 `69a6414`, v0.4.3 Ubuntu 24.04 x86_64 회차 4, 2026-10-09). macOS arm64·x86_64 두 회차가 남았고 둘 다 클린 macOS VM과 Gatekeeper 판정이 필요하다. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 서명·공증 태그는 `v0.4.0`부터 있다. 회차는 `docs/campaigns/m10-clean-vm.md`. 소유: 사람.
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** `x86_64-unknown-linux-musl` 한정. Debian 10(glibc 2.28) 회차 2(v0.3.0)와 회차 5(v0.4.3, 2026-10-09)가 `DoD 3 = PASS`다. 캠페인 §9 판정과 함께 닫히므로 macOS 두 회차를 기다린다. 두 회차 모두 에이전트가 컨테이너에서 돌렸으니, 캠페인을 닫을 때 사람이 이것을 회차로 셀지 다시 본다. 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** 기준은 `docs/campaigns/m7-stopwatch.md`(예행 1회만 끝남). 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** 기준은 `docs/campaigns/m2-mobility.md`. M18의 착수 조건. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** 저장소 밖 조직 액션. 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** 기준은 `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 소유: 사람.

### 0.2 P1 마일스톤이 만든 사람 몫 (`docs/ROADMAP.md` §5.5)

- [ ] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 기록 자리는 `docs/campaigns/m8-fuzz.md`. 출처 M11. 소유: 사람.
- [ ] **`p1-supervise-wake` 회차 넷.** 기준은 `docs/campaigns/p1-supervise-wake.md`. 출처 M12. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 기준은 `docs/campaigns/p1-setup-stopwatch.md`(ADR-0024 결정 12). 출처 M12. PASS가 기록되기 전에는 이슈 #3 완료 기준 첫 줄이 충족됐다고 적지 않는다. 소유: 사람.
- [x] **`aarch64-unknown-linux-musl` 구형 glibc 판정.** 2026-10-09 회차 1 PASS(`docs/campaigns/p1-aarch64-musl.md`). 컨테이너를 회차로 센 판단은 m10-clean-vm과 같고 사람이 다시 볼 항목이다.

### 0.3 M15가 새로 만드는 사람 몫 (`docs/ROADMAP.md` §5.5)

M15 DoD에는 들지 않는다(§5.1 원칙 6). 에이전트는 `gh secret set`, `gh workflow run`, 태그 push, 저장소 설정 변경을 어느 스텝에서도 하지 않는다.

- [ ] **`decode_file_frame` fuzz 타깃의 누적 72 fuzz-hours.** Step 11이 타깃을 더한다. 기록 자리는 `docs/campaigns/m8-fuzz.md` 형식이고, §5.5 표의 "새 파서 fuzz 타깃" 행("M15의 새 decode 타깃")에 상태를 적는다. 공개 beta 전에 끝나야 한다(`docs/design/protocol.md` §13). 소유: 사람.

## 1. 유지보수에서 남은 확인

- [ ] macOS Keychain 왕복. `keyring-core` 1과 플랫폼 store crate로 옮긴 변경(`08a6173`)의 Linux Secret Service 왕복은 확인했지만, macOS 쪽은 Dave-MBP16이 오프라인이라 못 했다. 다음 태그 전에 `docs/design/testing.md` L1의 수동 단계로 돌린다.
- [ ] 다음 태그 run에서 `release.yml` 액션 갱신(`1557f50`) 뒤의 서명·공증·provenance를 확인한다.

## 2. 테스트 환경

nextest의 간헐 실패 원인은 호스트 nftables에 남은 `inet dave_mosh` 표였다. 이 표가 loopback UDP 60000~61000을 버려서 ephemeral 범위(32768~60999)와 겹쳤고 bind(0) QUIC endpoint의 약 4%가 닿지 않았다. 호스트는 dave-environment `c6c5359c`가 고쳤다. 저장소 쪽은 `414f1fd`가 막는다. loopback UDP 자가 점검이 같은 상황을 즉시 원인과 함께 실패시키고, `scripts/test/nextest-ns.sh`가 격리 네트워크 namespace에서 스위트를 돌리며, 긴 TMPDIR에서는 nextest setup script가 unix 소켓 경로를 줄인다(`docs/design/testing.md` CI 규율).

## 3. DoD 체크리스트 (ROADMAP M15)

체크박스는 근거가 되는 테스트와 CI run이 초록일 때만 채운다.

- [x] **DoD (a) — 역할 기반 권한(ADR-0045).** 테스트가 다음을 고정한다.
  - role 키가 없는 기존 `trust.toml`은 오늘과 같은 판정을 낸다.
  - 새 pin은 role 키를 명시한다.
  - 모르는 role 값은 `CONFIG_ERROR`로 fail closed한다.
  - `acl.toml` 세 상태(있음·없음·파싱 불가)마다 role grant의 동작이 ADR대로임을 oracle 테스트가 고정한다.
  - `acl_check_equivalence.rs`와 `acl_uniformity.rs`가 role 경로를 포함한다.
  - role로 allow된 요청의 audit 레코드가 근거(`role`, `rule = null`)를 싣는다.

  근거: Step 2~8(`2d52a0f`·`b08b813`·`d659dbb`·`a7d94dd`·`9d99e36`·`64facab`·`85ea34f`, Windows 보정 `eb4216e`). CI run `38471301026`(eb4216e) 초록. 부하 반복 `scripts/stress/m15.filter` 50/50. wire diff 0. 소유: 에이전트.
- [ ] **DoD (b) — 왕복과 트리.** 큰 파일과 디렉터리 트리 왕복이 해시 기준으로 byte-identical이다. forward route와 reverse route 모두 같은 스텝에서 확인한다(QUIC 하나, ADR-0043). 트리 안 symlink와 특수 파일 처리, 부분 실패의 exit code와 JSON 레코드가 ADR대로다. 지원하지 않는 scp 플래그는 exit 2다. 근거: Step 14·15.
- [ ] **DoD — 권한 없음은 deny.** 새 seam 넷이 `DENY_SEAMS`에 행으로 오른다(14 → 18). `acl_uniformity.rs`가 문면 균일성을 단언한다. 항상-deny 예외 목록(`ALWAYS_DENIED_NO_OP`, `crates/qsh-core/tests/acl_registry.rs`)에는 `forward.socks`만 남는다. 근거: Step 11·12.
- [ ] **DoD — 상태 경로 핀.** 다음을 핀 테스트가 단언한다.
  - `full` role과 `allow = ["file.*"]` 행 어느 쪽으로도 상태 경로에 대한 `file.*`는 `PERMISSION_DENIED`이고 파일 바이트는 그대로다.
  - 대상은 `acl.toml`, `trust.toml`, `invites.toml`, identity 파일, audit 로그다.
  - 그 경로를 가리키는 symlink와 `..` 이탈 두 우회도 결과가 같다.

  근거: Step 9·12.
- [ ] **DoD — 인가 전 자원 생성 없음.** deny된 `file.write`·`file.mkdir` 뒤 목적지에 새 파일, 임시 파일, 디렉터리가 없고 기존 파일은 바이트 단위로 같다. 근거: Step 12.
- [ ] **DoD — 동시 전송 quota.** ADR-0010 모양으로 인가 뒤·열기 전에 판정한다. `quota_registry.rs`에 두 행이 오르고, `quota_docs.rs`가 문서의 거부 범주와 기본값을 대조한다. 근거: Step 12.
- [ ] **DoD — audit 필드 집합.** 키는 아홉에 optional `role`을 더한 것이다. 파일 내용 바이트가 어떤 필드에도 들어갈 수 없음을 `record_has_only_structural_fields` 형식의 테스트가 고정한다. 근거: Step 2(키), Step 4(role 판정 레코드), Step 12(`file_audit_record_carries_path_but_no_payload`).
- [ ] **DoD — 복사 중 PTY echo.** 파일 복사와 PTY echo를 동시에 돌린 상태에서 M13 (b) 하네스가 같은 예산으로 초록이다. 근거: Step 14(`file_copy_echo_under_load`), Step 15(`cp_many_small_files_stays_within_the_echo_budget`).
- [ ] **DoD — 등록 완전성.** 신규 op·명령마다 다음을 갖춘다. 근거: Step 5·6·7·10·11·13·14·15.
  - fixture 등재와 `layer_2_every_schema_command_has_all_six_faces`
  - `capabilities.json` golden 재생성(`file.v1`)
  - man 재생성
  - 새 wire op의 decode 경로가 fuzz 타깃에 걸림(`decode_file_frame` 신설)
  - freeze 발효 전이므로 `docs/design/protocol.md` §16.1 목록 동시 갱신
- [ ] **DoD — 위협 모델.** `docs/design/threat-model.md` §3에 파일 op 진입점과 role 경로가 오른다. §4 B에 상태 경로 쓰기, 경로 이탈, 덮어쓰기, 신뢰 등록이 곧 권한 부여가 되는 위협 행이 핀 테스트와 함께 오른다. 각 행은 그 통제를 구현한 스텝에서 오른다. 근거: Step 4·5·9·11·12·13·15. §7 잔여 위험은 Step 8·16.
- [ ] **DoD 마감 — 마감 공통 절차(§2) 1·2.** 근거: Step 16.
- [ ] **계획 규율 — 새 타이밍 민감 테스트의 부하 반복.** ROADMAP M15 DoD에는 없는 줄이다(§9 #2). M12·M13의 규율대로 M15가 더한 타이밍 민감 테스트 전부가 `scripts/stress/run.sh`로 CPU 부하 아래 50회 연속 초록이어야 한다. 지연 단언(`file_copy_echo_under_load`, `cp_many_small_files_stays_within_the_echo_budget`의 p95 단언)은 부하 없이 `-j 1`로 50회 연속 초록이어야 한다. 근거: Step 8·16.

## 4. 실행 단계 (PR 단위)

스텝 번호는 이 문서 안에서만 쓰는 참조다. 크기는 다음과 같다.

| 묶음 | 스텝 | 합(ew) | ADR 산정 | 비고 |
|---|---|---|---|---|
| (a) ADR-0045 | Step 2~8 | 2.6~4.0 | 2.7~4.2 | 차이는 이미 끝난 ADR 작성분이다 |
| (b) ADR-0029 | Step 9~16 | 4.6~6.0 | 4.3~6.3 | ADR 0.3을 빼면 4.0~6.0. 경로 판정과 wire를 스텝으로 쪼개면서 하한이 0.6 올랐다 |
| 합 | | 7.2~10.0 | ROADMAP 7.0~10.5 | 범위 안이다 |

Step 1은 크기 내역 밖이다.

**순서의 근거.**

- (a)가 (b)보다 먼저다. ADR-0045 결정 2 각주와 결정 19, ADR-0029 머리말이 정한 순서다. `full` role의 `file.*`는 ADR-0029가 항상-deny를 걷을 때 비로소 효과가 난다.
- (a) 안에서는 측정을 먼저 한다(§5.1 원칙 3). Step 3은 판정마다 `trust.toml`을 읽는 비용을 판정 의미를 바꾸지 않은 채 먼저 잰다. 예산을 넘으면 ADR-0045 근거 절이 정해 둔 대체 경로를 그 스텝 안에서 고른다. 그 위에 Step 4가 판정 의미를 바꾼다.
- 권한을 쓰는 명령(Step 5)은 판정기(Step 4) 뒤에 둔다. 그 사이에 생기는 pin은 role 키가 없어 `none`으로 판정되므로 권한이 넓어지는 창이 없다.
- (b) 안에서는 보안 층을 먼저 세운다. 경로 판정 모듈(Step 9), 행 `paths`(Step 10), wire와 deny 전용 seam(Step 11)이 먼저 오고, 항상-deny를 걷는 일(Step 12)은 상태 경로·재검증·자원 생성 전 인가 테스트를 모두 같은 커밋에 싣는다.
- 데이터 평면(Step 13)은 그 뒤에 온다. `file.v1` capability는 데이터 평면이 끝나는 Step 13에서야 광고한다. client(Step 14·15)는 마지막이다.

**의존과 병렬.**

| 스텝 | 선행 | 다른 에이전트와 병렬 가능 여부 |
|---|---|---|
| Step 2 | Step 1 | — |
| Step 3 | Step 2 | — |
| Step 4 | Step 3 | — |
| Step 5 | Step 4 | Step 6과 병렬 가능. Step 5는 `ops/trust.rs`, `trust/pairing.rs`, `qsh-proto/src/types/trust.rs`, CLI trust·pair 명령을 만지고, Step 6은 `ops/acl.rs`, `qsh-proto/src/types/acl.rs`, CLI acl 명령을 만진다. 겹치는 곳은 `docs/CLI.md` 상태 헤더 한 줄, `crates/qsh-cli/tests/fixtures.rs`의 `REQUIRED_FIXTURES`, `docs/man/`이고 rebase로 푼다 |
| Step 6 | Step 4 | Step 5와 병렬 가능(위와 같음) |
| Step 7 | Step 5(`--peer-role`이 초대 레코드의 role 저장을 쓴다), Step 6 | — |
| Step 8 | Step 2~7 | — |
| Step 9 | Step 1만 | Step 5~7과 병렬 가능. 새 모듈 `crates/qsh-core/src/file/`과 `lib.rs` 한 줄만 만진다. 인가에 닿지 않으므로 "ADR-0045 먼저" 순서를 어기지 않는다 |
| Step 10 | Step 7(doctor 개수 24 → 25 → 26 순서), Step 9 | Step 11과 병렬 가능. Step 10은 `acl/load*`, `acl/policy*`, `ops/acl.rs`, `ops/doctor*`, `doctor.rs`를 만지고 Step 11은 `.proto`, `wire.rs`, `server/dispatch.rs`, `acl/registry.rs`, `fuzz/`를 만진다 |
| Step 11 | Step 4(`Authorizer::check` 입력이 바뀐 뒤) | Step 10과 병렬 가능(위와 같음) |
| Step 12 | Step 9·10·11 | — |
| Step 13 | Step 12 | — |
| Step 14 | Step 13 | — |
| Step 15 | Step 14 | — |
| Step 16 | 전부 | — |

**규율.** 앞 마일스톤 그대로이고 M15에서 몇 가지를 덧붙인다.

- 각 스텝은 일곱 게이트(`cargo fmt --all --check`, clippy `-D warnings`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `RUSTDOCFLAGS=-D warnings cargo doc`, `cargo xtask arch`, `cargo deny check`)가 초록인 채로 착지한다. clippy와 test는 `ci.yml`의 `windows-latest`·`macos-14` 다리에서도 돈다.
- 계약 문서 델타는 그 표면을 바꾼 스텝의 같은 커밋에 싣는다.
  - `docs/CLI.md` 상태 헤더의 v0.26 항목은 CLI.md를 처음 고치는 Step 2가 열고 뒤 스텝이 덧붙인다(`crates/qsh-core/tests/cli_md_header.rs` 핀).
  - clap 트리가 바뀌는 스텝은 같은 커밋에서 `cargo xtask man`을 돌린다.
  - doctor code를 더하는 스텝은 `EXPECTED_DOCTOR_CODES`, §6.17 표, §6.11·§6.17의 개수 문장을 같은 커밋에서 바꾼다(origin `09266dc` 기준 24 → Step 7에서 25 → Step 10에서 26).
- 판정 로직, role 표, 경로 판정, 전송 상태 기계, 트리 순회는 `qsh-core`에 둔다. `qsh-proto`에는 열린 문자열 필드, 새 op·wire 타입, 상수만 들어간다. `qsh-cli`에는 clap 정의, 렌더러 둘, 진행 표시, exit 매핑만 둔다. 새 모듈이 `xtask arch`의 경로 범위 금지 목록에 들어가는지는 그 모듈을 만드는 스텝이 판단하고, 들어가면 `xtask/src/arch.rs`를 같은 커밋에서 고친다(`CLAUDE.md`의 경로 범위 규칙).
- (a) 스텝(2~8)은 wire를 바꾸지 않는다(ADR-0045 결정 17). 완료 판정마다 다음을 확인한다.
  - `git diff --stat -- crates/qsh-proto/proto crates/qsh-proto/src/wire.rs crates/qsh-proto/src/local.rs crates/qsh-cli/tests/fixtures/cli-v1/capabilities.json`이 비어 있다.
  - `ErrorCode`는 어느 스텝에서도 바뀌지 않는다(ADR-0029 결정 17).
- fixture는 추가만 한다. 새 fixture마다 실제 바이너리로 재현하는 `golden_*` 생산 테스트를 같은 커밋에 둔다. 기존 `trust.*`·`acl.*`·`setup.run.*` fixture는 role 키 없는 샌드박스에서 만들었으므로 고치지 않은 채 초록이어야 한다(ADR-0045 결정 15).
- route 동등(§5.1 원칙 7). 인가나 파일 동작을 바꾸는 스텝은 forward route(`qsh serve` ← client)와 reverse route(`qsh listen` ← `qsh serve --to`)의 같은 성질을 같은 스텝의 테스트로 단언한다. 한쪽만 덮는 PR은 착지하지 않는다.
- 플랫폼 동등. role(ADR-0045 결정 20)은 플랫폼 중립 코드라 M15에서 세 OS 모두 같다. 파일 op의 Windows 대응은 범위 밖이다. Windows host 경로 판정, `paths`의 드라이브 표기, `FILE_DATA` host 처리는 M20(ADR-0029 결정 23, ADR-0035 결정 26)이 하고, Windows client의 `qsh cp`와 드라이브 문자 operand 해석은 M19(ADR-0035 결정 1)가 한다. M15에서 Windows 빌드의 `qsh serve`는 `file.v1`을 광고하지 않고 네 op에 `UNSUPPORTED`로 답한다(§6). macOS는 M15 범위다(`F_GETPATH`, 대소문자 무시 보호 집합).
- 손대는 소스 파일이 800줄을 넘으면 인라인 테스트를 같은 커밋에서 형제 `tests.rs`로 옮긴다. origin `09266dc` 기준 `crates/qsh-core/src/acl/load.rs`(881줄), `trust/mod.rs`(869줄), `server/mod.rs`(2492줄), `ops/doctor.rs`(1144줄), `qsh-proto/src/wire.rs`(918줄)가 이미 넘었으므로 인라인 테스트가 남아 있는지 먼저 확인한다.
- 안정성 규율은 M13과 같다. 시계를 주입하고, 관찰 가능한 상태를 넉넉한 `timeout`으로 기다리며, 고정 `sleep()`은 쓰지 않는다. 타이밍 민감 테스트는 그 스텝의 완료 판정에서 부하 아래 50회 연속 초록이어야 착지한다. 지연 단언은 부하 없이 50회다.

### Step 1 — M15 계획 교체와 ROADMAP 갱신 (main 세션, 크기 내역 밖)

근거: `docs/ROADMAP.md` 현재 위치와 M15 절, ADR-0045 결정 19, ADR-0029 결과 절의 "메인 세션이 고친다" 문장들. 선행: 두 ADR 승인(2026-10-14, `09266dc`).

**(a) 범위:**

1. `PLAN.md`를 이 문서로 바꾼다.
2. `docs/ROADMAP.md`를 고친다.
   - M15 DoD에 안정성 줄을 더한다(§9 #2). 문면은 M12의 안정성 줄을 따르고 지연 단언 예외를 한 구절로 붙인다.
   - ADR-0029 결과 절이 메인 세션 몫으로 남긴 두 편집(DoD transport 문구, 명시적 out의 재귀 복사)이 이미 반영됐는지 확인하고, 빠졌으면 고친다.
   - §5.5 표 "새 파서 fuzz 타깃" 행의 "M15의 새 decode 타깃"에 `decode_file_frame`을 적는다.
3. README Roadmap 표의 P1 행을 "M15 진행 중"으로 고친다.

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록.

**(c) 완료 판정:** `PLAN.md` 첫 줄이 이 문서의 제목이다. ROADMAP M15 DoD에 안정성 줄이 있다.

### Step 2 — (a) `TrustRole`, `trust.toml`의 `role` 키, role 표 상수, audit optional 키 (0.3~0.5ew)

근거: ADR-0045 결정 2·3·9·16, 결정 15의 `TrustPeer.role`. 선행: Step 1. 이 스텝은 판정을 바꾸지 않는다. role을 저장하고 보여 주기만 하고, 평가기는 아직 읽지 않는다.

**(a) 범위:**

- `crate::trust::TrustRole`(`full`·`exec`·`tunnel`·`read-only`·`reverse`·`none`)을 둔다. 이름이 겹치지 않도록 `crate::acl::load::Role`(Serve/Listen)과 분리한다.
- `trust.toml`의 `[[peer]]` optional 키 `role`을 다룬다.
  - 읽기: 여섯 값 밖이면 파일 전체가 `CONFIG_ERROR`다.
  - 쓰기: 키가 없던 pin은 키 없이 다시 쓴다.
  - `trust rename`은 role을 옮기고 `trust remove`는 지운다.
- 결정 2의 표를 `crate::acl` 안의 닫힌 상수 하나(가칭 `ROLE_GRANTS`)로 둔다. 각 행은 action 배열과 소유 축이다. 평가기, `acl show`, doctor, 렌더러가 뒤 스텝에서 모두 이 상수를 읽는다.
- `qsh-proto`의 `TrustPeer`에 optional `role`(열린 문자열)을 더한다. 키가 없으면 필드를 생략한다.
- `trust list` human 출력에 role 열을 더한다. 키 없는 pin은 `(none, legacy)`로 적는다.
- `AuditRecord`에 optional 키 `role`을 더하고 직렬화에서 `None`이면 생략한다. 아직 아무 레코드도 채우지 않는다. `record_has_only_structural_fields`는 아홉 키에 optional `role`을 허용하도록 넓힌다.
- 문서:
  - `docs/CLI.md` §6.11에 role 표, 기본값 표 자리, `trust list`의 role 열을 적는다. 기본값과 `trust set-role` 문단은 Step 5가 채운다.
  - `docs/PRD.md` §9에 role 표와 `full` 예시를 더한다. 인가 서술 문장은 Step 4에서 바뀐다.
  - `docs/design/architecture.md` §7에 `trust.toml`의 `role` 키를 적는다.
  - `docs/CLI.md` 상태 헤더 v0.26을 연다.

**(b) 테스트:**

- `unknown_role_string_makes_trust_toml_a_config_error`
- `role_action_table_matches_docs`: 상수가 CLI.md §6.11의 role 표와 PRD §9와 일치한다. `acl_docs.rs`와 같은 형식이고 자리는 `crates/qsh-core/tests/acl_docs.rs`다.
- `trust/tests.rs`에 rename이 role을 옮기고, remove가 지우고, 키 없는 pin을 다시 써도 키가 생기지 않는 행을 더한다.
- `record_has_only_structural_fields` 갱신.
- 새 fixture `trust.list.with_role.json`과 `golden_*` 생산 테스트를 `REQUIRED_FIXTURES`에 등재한다.

**(c) 완료 판정:** 기존 trust fixture가 고치지 않은 채 초록이다. 판정 결과가 바뀐 테스트가 0개다(`acl_check_equivalence.rs`, `acl_enforcement.rs` 무변경 초록). wire diff 0.

### Step 3 — (a) `Authorizer` 입력에 연결 fingerprint, 판정마다 role 해석의 배선과 비용 측정 (0.3~0.4ew)

근거: ADR-0045 결정 6 둘째 문단(Authorizer 입력과 구성), 근거 절의 "판정마다 읽는 비용… 구현 커밋이 그 테스트로 확인한다"와 대체 경로. 선행: Step 2. 판정 의미는 바꾸지 않는다. ⓡ 자리는 있지만 role 표 적용은 Step 4에서 켠다.

**(a) 범위:**

- `Authorizer::check` 입력에 연결의 검증된 fingerprint(`ConnCtx::peer_fingerprint`)를 더한다. 이것은 `qsh-core` 내부 trait 변경이다. 요청자 묶음 구조체로 할지 인자로 할지는 이 스텝이 정한다(§7.1 #1).
- 호출 지점(`Server::authorize`, `authorize_stream`, `authorize_session_control`, `authorize_owned`, `forward.local` 인라인 게이트 `authorize_and_dial_tunnel`, `authorize_and_bind_remote_forward`, `reverse::admit`)이 모두 값을 넘긴다.
- 테스트 대역(`AllowAllPinned`, `DenyAll`, testkit의 대역들)을 기계적으로 고친다.
- production `Authorizer`는 `load_or_deny`가 `SharedTrustStore` 핸들을 함께 쥐도록 구성한다. `qsh serve`, `qsh listen`, `qsh serve --to` 세 구성이 같다.
- 판정마다 `SharedTrustStore`를 refresh하고 pin을 찾는 경로를 켜되, 결과는 아직 판정에 쓰지 않는다. 이렇게 해야 비용을 의미 변경과 분리해서 잴 수 있다.
- **측정.** `QSH_ACCEPTANCE_STRICT=1`로 다음을 이 스텝 전과 후에 돌려 값을 커밋 본문에 적는다.
  - `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`(`crates/qsh-testkit/tests/tunnel_echo_under_load.rs`. ADR이 `tunnel_echo_under_load`라 부른 것)
  - `tunnel_throughput_meets_raw_quinn_ratio`
  - 새 측정 행 하나. 짧은 `-L` 연결을 연속으로 여는 경우다. 판정이 `TCP_CONNECT`마다 일어나는 경로이며, `trust.toml`에 pin 100개를 둔다(§7.1 #2).
- **미리 정한 대체 경로.** 예산을 넘으면 `SharedTrustStore::refresh`가 파일 내용을 읽기 전에 (크기, 수정 시각 나노초, dev·inode)를 먼저 보고, 달라졌을 때만 다시 읽게 이 스텝 안에서 바꾼다. "role 변경은 다음 요청부터 보인다"는 의미는 그대로다. 지금 refresh 문서가 내용 전체를 비교하는 이유로 적은 것(M7의 mtime 해상도 우려)과 부딪히므로, 그 문서를 같은 커밋에서 고치고 §7 리스크의 조건을 확인한다.

**(b) 테스트:**

- 전 스위트가 판정 변화 0으로 초록이다.
- 새 단위 테스트 `authorizer_receives_the_connection_fingerprint_at_every_call_site`. seam 표(`DENY_SEAMS`)를 돌며 대역 authorizer가 받은 fingerprint가 연결의 값과 같음을 본다. 이름은 이 계획이 정했다.

**(c) 완료 판정:** 측정값 셋과, 대체 경로를 썼는지가 커밋 본문에 있다. 지연 단언 둘은 부하 없이 50회 초록이다.

### Step 4 — (a) 평가 단계 ⓡ, `acl.toml` 세 상태, reload 실패 시 role 정지, role audit, 시작 진단 (0.6~0.9ew)

근거: ADR-0045 결정 1·4·6(세 상태)·7·13(시작 진단)·16(판정 레코드)·20. 선행: Step 3. 인가 의미를 바꾸는 스텝이므로 fail-closed 테스트와 `CLAUDE.md` 문장을 같은 커밋에 싣는다.

**(a) 범위:**

- `Policy::decide`(`pub(crate)` 유지)에 role 입력을 더하고 ①과 ② 사이에 ⓡ을 넣는다. ⓡ은 다음이 모두 참일 때만 본다.
  - `auth_path = Pin`이다.
  - principal이 `device:<name>`이다.
  - 그 이름의 pin이 있고, pin의 fingerprint가 연결의 fingerprint와 같다. `None`이면 role이 없다.
- 결정 2 표의 소유 축은 `tunnel`만 owned로 적용한다.
- `Verdict`에 판정 근거가 role임을 싣는 필드를 더한다(rule = `None`).
- 판정 함수 호출 지점은 셋 그대로다(결정 7. `grep` 기계 점검 문장 유지).
- `acl.toml` 세 상태를 바꾼다.
  - `Missing`은 행 없는 `Policy` + role이다. 지금은 `DenyAll`이다.
  - `Invalid`는 `DenyAll` 그대로이고 role까지 거부한다.
- `SharedTrustStore`가 마지막 reload의 실패 여부를 가진다. 실패 중이면 pin 인증은 마지막 정상 snapshot으로 하되 role은 전부 `none`으로 친다. 기존 reload 실패 경고 줄에 "role grant를 멈춘다" 구절을 더한다.
- role 근거 allow의 audit 레코드에 `role`을 싣는다.
- `StartupDiagnostic`: `Missing`이면 블록 대신 "acl.toml이 없다. 요청은 trust role로만 인가된다(`qsh trust list`)" 뜻의 한 줄을 낸다. `Invalid`는 지금 블록 그대로다.
- 문서:
  - `CLAUDE.md` "Security defaults" 첫 항목을 고친다(ADR-0045 결과 절 "문서 밖"). 새 문장의 요지는 다음과 같다. 요청은 pin role이나 `[[acl]]` 행이 줄 때만 허용된다. 없는 `acl.toml`은 행 없음이고 role은 동작한다. 파싱할 수 없는 `acl.toml`은 role을 포함해 모든 요청을 거부한다. `trust.toml` reload가 파싱에 실패하면 role grant를 멈춘다. `acl.toml`은 시작 때 한 번 읽고 role은 판정마다 읽는다. 단일 choke point, 자원 생성 전 인가, fail-closed audit 문장은 그대로다.
  - `docs/PRD.md` §9의 인가 서술
  - `docs/design/architecture.md` §6의 평가 순서(ⓡ, 세 상태)
  - `docs/CLI.md` §6.12·§6.13의 시작 진단 문단
  - `docs/design/threat-model.md`: §2 "pin된 원격 peer" 행을 합집합으로 고친다. B4 통제 문장을 "없는 `acl.toml`은 행 없음이고 role만 동작한다. 파손은 role까지 전면 거부"로 고친다. §4 B 새 행 셋(CA leaf가 pin된 이름을 실음, 이름 재등록 뒤 옛 연결, 깨진 `trust.toml`이 옛 role을 살림)을 더한다.

**(b) 테스트 (route 동등: 각 행을 `qsh serve`·`qsh serve --to`에서, `host.reverse` 행은 `qsh listen`에서):**

- `legacy_pin_without_role_is_authorized_by_acl_rows_only`
- `role_full_without_acl_toml_allows_every_action_but_forward_socks`. 여섯 role 전부를 같은 표에 둔다. `full`의 `file.*`는 이 시점에 ①이 막으므로 deny로 기대하고, Step 12가 그 행을 allow로 뒤집는다.
- `invalid_acl_toml_denies_role_grants_too`
- `role_grant_does_not_reach_a_ca_leaf_naming_a_pinned_device`(`cert_e2e.rs`의 CA leaf 도구 재사용)
- `role_requires_the_connection_fingerprint_to_match_the_current_pin`
- `trust_remove_ends_role_grants_on_the_next_request`
- `trust_store_reload_failure_suspends_role_grants`
- `role_grant_audit_record_names_the_role_and_no_rule`
- `role_tunnel_cannot_close_another_principals_remote_forward`, `role_read_only_can_attach_but_not_write`
- `decide_agrees_with_naive_coverage_oracle`(`crates/qsh-core/src/acl/policy/tests.rs`)에 role 차원을 더한다. 여섯 값과 "role 없음", fingerprint 일치 여부, `auth_path`, reload 실패 플래그다.
- `crates/qsh-testkit/tests/acl_uniformity.rs`: role 없음 거부, role 범위 밖 거부, reload 실패 중 거부가 같은 `PERMISSION_DENIED_MESSAGE`를 낸다.
- 시작 진단 테스트: `Missing` 한 줄 문면, `Invalid` 블록 불변.
- 이 스텝의 테스트는 role 키를 손으로 쓴 `trust.toml`로 샌드박스를 만든다. 명령은 Step 5에서 생긴다.

**(c) 완료 판정:** 위 테스트가 초록이고 부하 아래 50회 초록이다. `acl.toml`이 있는 기존 판정 테스트(`acl_enforcement.rs`, `acl_check_equivalence.rs` 기존 행)가 고치지 않은 채 초록이다. `CLAUDE.md` diff가 이 커밋에 있다.

### Step 5 — (a) 권한을 쓰는 명령: `--role`, 초대 레코드의 role, `trust set-role`, 페어링 고지 (0.6~0.9ew)

근거: ADR-0045 결정 8(`setup` 줄 제외), 결정 13(페어링 고지), 결정 15의 `TrustAddReq.role`·`TrustInviteReq.role`·`TrustInviteData.assigned_role`·`TrustAcceptReq.role`·`TrustSetRoleReq`·`TrustSetRoleData`, 결정 18. 선행: Step 4. Step 6과 병렬 가능.

**(a) 범위:**

- 기본값(주소 유무 규칙)과 `--role` 플래그:

  | 명령 | 기본 role |
  |---|---|
  | `trust add`, `--address` 없음 | `full` |
  | `trust add`, `--address` 있음 | `none` |
  | `pair invite` | `full` |
  | `pair accept` | `none` |

  이 뒤로 pin을 만드는 모든 경로는 `role` 키를 명시한다(`none` 포함).
- `invites.toml` 초대 레코드에 role을 저장한다. 상환 때 `qsh serve`는 레코드의 role로 pin한다. 상환하는 쪽은 role을 고를 수 없다.
- 이미 있는 이름과 같은 fingerprint로 `trust add`를 다시 부르면 role을 바꾸지 않는다. `created: false`, `updated: false`이고 human 출력이 "role is unchanged; use `qsh trust set-role`" 줄을 낸다.
- 새 local op `trust.set_role`과 `qsh trust set-role <name> <role>`:
  - 순서는 `trust.toml.lock` → load → 변경 → `AuditRecord::local_op` → save다. audit 실패면 `INTERNAL`(`retryable: true`)이고 파일은 그대로다.
  - 이름이 없거나 CA 이름이면 `HOST_NOT_FOUND`다. role 문자열이 틀리면 `INVALID_ARGUMENT`다.
  - 같은 값이면 `changed: false`이고 audit도 쓰지 않는다.
- role을 `none`이 아닌 값으로 쓰는 모든 경로(add, 상환, set-role)가 `local_op` 레코드 하나를 남긴다(`action` = op 이름, `resource` = pin 이름, `role` = 새 role). 기록이 없으면 쓰기도 없다.
- 등록 완전성: schemars 타입, `cli_v1_data_schema` arm, `CLI_V1_SCHEMA_COMMANDS`, 렌더러 둘, CLI.md 새 문단, man `qsh-trust-set-role`. `crates/qsh-core/tests/acl_registry.rs`의 §2.5 "인가 불요" 대조에 `trust.set_role`이 오르고 `OP_REGISTRY` 행은 없다.
- 페어링 직후 고지를 바꾼다(ADR-0017 결정 3 문면 개정). pin 이름, role, role이 주는 action을 적고, 같은 이름의 행이 있으면 "그 행의 grant도 더해진다"를 덧붙인다. 자칭 이름 경고와 stderr 전용은 그대로다.
- ADR-0026 `trust ssh-preview`가 내는 ACL 초안을 `--role`을 단 pin 명령으로 바꾼다.
- 문서:
  - `docs/CLI.md` §2.4·§2.5(`trust.set_role`), §6.11(기본값 표, `trust set-role`, `--role`, 결정 18의 "`exec`는 `full`에 대한 보안 경계가 아니다" 문장)
  - man `qsh-trust-add`, `qsh-pair-invite`, `qsh-pair-accept`
  - threat-model §3 진입점(`trust set-role`, 세 `--role`)
  - §4 B 새 행 셋(상환 쪽이 role을 고름, 업그레이드나 `trust add` 재실행이 넓힘, 권한 변경이 audit에 없음)

**(b) 테스트 (route 동등: `set_role` 반영을 forward와 `serve --to` 두 route에서):**

- `set_role_takes_effect_on_the_next_request_without_restart`
- `trust_add_never_changes_an_existing_pin_role`
- `invite_role_is_fixed_by_the_issuer`
- `pair_accept_and_trust_add_default_to_role_none`(`trust add`는 `--address`를 준 경우), `pair_invite_defaults_to_role_full`. 주소 없는 `trust add`가 `full`인 행도 같은 표에 둔다.
- `set_role_without_a_durable_audit_record_leaves_trust_toml_untouched`, `role_writes_leave_a_local_op_audit_record_with_the_role`
- 페어링 고지 문면 테스트(`trust_pairing_live.rs`의 기존 셋을 새 문면으로 고치고 role 행을 더한다)
- 새 fixture `trust.set_role.json`, `trust.set_role.unchanged.json`, `trust.add.with_role.json`, `trust.invite.with_role.json`과 각 `golden_*`

**(c) 완료 판정:** `layer_2_every_schema_command_has_all_six_faces`, `section_2_4_fence_matches_every_implemented_operation_bidirectionally`가 초록이다. man diff가 커밋에 있다. 기존 trust fixture가 무변경 초록이다.

### Step 6 — (a) `acl check`·`acl show`의 role 필드와 3-way 대조 (0.3~0.5ew)

근거: ADR-0045 결정 10·11, 결정 15의 `AclCheckData.role`·`granted_by`·`AclPolicyRef.state`·`AclShowData.role`·`role_actions`. 선행: Step 4. Step 5와 병렬 가능.

**(a) 범위:**

- `Ops::acl_check`가 principal이 `device:<name>`이고 `--auth-path pin`이면 pin 자신의 fingerprint로 ⓡ을 돈다.
- `acl check` `data`에 optional 필드를 더한다. `role`(그 이름의 pin이 없거나 `ca`면 생략), `granted_by`(`"role"`|`"acl"`, allow일 때만), `policy.state`(`"loaded"`|`"missing"`|`"invalid"`). `AclPolicyRef.loaded` field doc의 "deny" 문장을 `state = invalid`로 고친다.
- `acl show`:
  - `role`, `role_actions`(표 순서)를 더한다.
  - `effective_actions`를 role ∪ 행으로 넓힌다.
  - human 출력은 role 줄을 먼저 내고, role은 즉시 반영되며 행은 재시작해야 반영된다는 두 줄을 낸다. 행 줄은 `ACL_RESTART_NOTICE`를 축자로 쓴다.
- 문서: `docs/CLI.md` §6.15·§6.19.

**(b) 테스트:**

- `crates/qsh-cli/tests/acl_check_equivalence.rs`에 role pin 샌드박스 행들을 더한다. `acl check`, `acl show`, 실제 op, audit 넷이 일치하는지 보고, `full`·`exec`·`tunnel`·`read-only`·`none`·legacy를 덮는다. ADR-0025 결정 3의 3-way를 role 차원으로 넓힌 것이다.
- `missing` 정책 상태에서 role allow 행을 둔다.
- 새 fixture `acl.check.allow_by_role.json`, `acl.check.missing_policy_role.json`, `acl.show.with_role.json`

**(c) 완료 판정:** 기존 `acl.check.*`·`acl.show.*` fixture가 무변경 초록이다. `grep` 기계 점검으로 `decide` 호출 지점이 셋이다.

### Step 7 — (a) doctor와 `qsh setup` (0.4~0.6ew)

근거: ADR-0045 결정 8의 `setup` 줄(`--peer-role`), 결정 12, 결정 14, 결정 15의 `SetupRunReq.peer_role`. 선행: Step 5·6.

**(a) 범위:**

- doctor 조건과 문면을 바꾼다.

  | code | 바뀌는 것 |
  |---|---|
  | `acl_policy_missing` | role이 `none`이 아닌 pin도, 그런 초대도 없을 때만 낸다. remedy에 `trust set-role`을 더한다 |
  | `acl_policy_invalid` | 문면에 "role grant도 거부"를 더한다 |
  | `acl_principal_unmatched` | role이 `none`이 아닌 pin은 세지 않는다 |
  | `acl_ca_auth_path_missing` | `acl.toml`이 없어도 낸다 |
  | `trust_remove_scope` | message를 고친다 |
  | `trust.toml` 파싱 실패의 `CONFIG_ERROR` | 문면에 "실행 중인 serve/listen은 role grant를 거부한다"를 더한다 |

- 신설 `trust_pin_role_unset`(info). role 키 없는 pin마다 하나를 내고 `detail`은 pin 이름만 싣는다. doctor code는 24 → 25이다.
- `qsh setup --peer-role`의 역할별 기본값: `host` → 초대에 `full`, `host --to` → listener pin에 `full`, `listener` → target pin에 `reverse`, `client` → server pin에 `none`.
  - ACL 단계는 `none`이 아니면 `done`이고 `detail`에 pin·초대와 role을 적으며 `acl_rows`를 내지 않는다.
  - `none`이면 지금처럼 동작한다.
  - `complete` 판정 문장은 그대로다.
- 문서: `docs/CLI.md` §6.17(표, 개수 문장 25), §6.11 개수 문장, §6.20(`--peer-role`), man `qsh-setup`

**(b) 테스트:**

- `crates/qsh-core/src/ops/doctor/tests.rs`에 이 계획이 이름을 정한 테스트를 둔다(ADR은 이름을 정하지 않았다).
  - `doctor_trust_pin_role_unset_reports_each_legacy_pin_by_name_only`
  - `doctor_acl_policy_missing_is_silent_when_a_role_pin_exists`
  - `doctor_acl_principal_unmatched_skips_role_pins`
  - `doctor_acl_ca_auth_path_missing_fires_without_acl_toml`
- `doctor_docs.rs` 잠금 어휘 대조
- `setup_never_writes_acl_toml_in_any_role` 무변경 초록
- `setup_host_roles_incomplete_without_acl_toml`는 `--peer-role none` 조건으로 좁힌다.
- 새 `setup_host_roles_complete_with_a_role_and_no_acl_toml`과 fixture `setup.run.host_complete_with_role.json`

**(c) 완료 판정:** `EXPECTED_DOCTOR_CODES`가 25이고 CLI.md 개수 문장이 같다. ADR-0038 client 면제 테스트가 무변경 초록이다.

### Step 8 — (a) 정리: 잔여 위험, README, 부하 반복 (0.1~0.2ew)

근거: ADR-0045 결정 17·18과 결과 절의 위협 모델·"문서 밖" 문단, ROADMAP M15 크기 줄의 "(a)와 (b)를 순서대로 따로 닫아도 된다". 선행: Step 2~7.

**(a) 범위:**

- `docs/design/threat-model.md` §7 잔여 위험 다섯을 적는다.
  1. `exec`·`full`은 serve uid와 같은 힘이다.
  2. `tunnel`의 `forward.local` egress는 host가 닿는 모든 TCP 목적지에 닿는다.
  3. `read-only`는 다른 장비 세션의 화면 출력을 본다.
  4. role을 줄여도 이미 만든 자원은 M16 ADR-0031 전까지 끝까지 간다.
  5. 이 ADR 이전 바이너리가 `trust.toml`을 다시 쓰면 `role` 키가 사라져 그 pin이 `none`이 된다.
- README First run과 보안 절을 role 기준으로 고친다(§9 #3). README 축자 게이트가 걸린 문장을 먼저 확인한다.
- (a) 타이밍 민감 테스트를 `scripts/stress/m15.filter`에 묶어 50회 돌린다.
- (a) wire diff 0을 기록한다(결정 17).
- ROADMAP M15 절에 (a) 착지 노트를 적는다(main 세션).

**(b) 테스트·게이트:** 일곱 게이트, CI 초록, 부하 반복 50/50.

**(c) 완료 판정:** §3 DoD (a)가 근거 커밋, run id와 함께 `[x]`다. `git diff --stat <Step 2 부모>..HEAD -- crates/qsh-proto/proto crates/qsh-cli/tests/fixtures/cli-v1/capabilities.json`이 비어 있다.

### Step 9 — (b) 경로 판정 모듈 `file::guard` (0.5~0.7ew)

근거: ADR-0029 결정 5·6, 결정 23의 macOS 항목. 선행: Step 1. Step 5~7과 병렬 가능하다. 인가 경로에 아직 연결하지 않는 순수 모듈이다.

**(a) 범위:** `crates/qsh-core/src/file/guard.rs`(새 모듈)에 다음을 둔다.

1. **모양 검사와 home 해석(6-1).** home은 serve 계정의 passwd 항목에서 구하고 `HOME`은 쓰지 않는다. `~name`, NUL, 4096바이트 초과, 비UTF-8을 거부한다. 쓰기 계열은 마지막 성분이 `.`·`..`이면 거부하고, `name_if_dir`는 단일 성분이어야 한다.
2. **정규화(6-2).** 존재하는 가장 긴 조상을 `realpath`로 풀고, 나머지 성분을 어휘적으로 접는다. 존재하는 symlink는 끝까지 따른다. 정규화 함수는 주입 가능하게 두어 호출 수를 셀 수 있게 한다. Step 12의 `file_request_without_a_file_grant_touches_no_filesystem`이 쓴다.
3. **보호 집합(5).**
   - 보호 디렉터리: config, state, runtime(localctl 소켓 디렉터리 포함)
   - 보호 파일: `[audit].path`가 디렉터리 밖이면 그 파일·회전 파일·회전 임시 이름. file-mode keystore 경로
   - 실제 경로(`$QSH_CONFIG_DIR`·`$XDG_*` 반영)와 `$HOME` 기본값 경로의 합집합이다.
   - 요청마다 새로 해석한다.
4. **보호 대조(6-3).** 존재하지 않는 경로도 보호 디렉터리 아래면 거부한다. macOS(와 Windows, 그 구현은 M20)에서는 성분 단위 대소문자를 무시하고 비교한다.
5. **열린 핸들 재검증 기본 요소(6-4).** Linux는 `/proc/self/fd/<n>` readlink, macOS는 `fcntl(F_GETPATH)`이다. 평가기 재호출은 Step 12가 연결한다.
6. **보호 파일 `(dev, ino)` 집합(6-5)과 파일 종류 판정(6-6).**

추가로:
- `docs/design/architecture.md` §7에 "이 트리는 원격 파일 op에서 항상 거부된다" 한 문장과 집합을 적는다.
- `xtask arch` 금지 목록 편입 여부를 이 스텝이 판단한다.
- `cfg(not(unix))`에서는 모듈이 모든 경로를 거부하는 stub이다. Windows 구현은 M20, ADR-0029 결정 23·ADR-0035 결정 26.

**(b) 테스트:**

- `state_path_guard_denies_nonexistent_paths_under_state_dirs`
- `state_path_guard_covers_env_overridden_and_default_dirs`
- `state_path_guard_rechecks_the_opened_handle`. 판정과 열기 사이에 디렉터리 성분을 symlink로 바꾸는 경쟁을 재현한다.
- macOS 전용 행: 대소문자만 다른 표기로 상태 경로를 우회하는 시도를 거부한다(`cfg(target_os = "macos")`, `macos-14` 다리).
- 모양 검사·home 해석 단위 행

**(c) 완료 판정:** 모듈이 인가 경로 어디에서도 호출되지 않는다(`grep`). Linux·macOS 다리가 초록이다. Windows 다리에서 stub이 컴파일된다.

### Step 10 — (b) `acl.toml` 행의 `paths`: 로더, 평가 ③-1, `acl check --path`, `acl show`, doctor (0.5~0.7ew)

근거: ADR-0029 결정 4(4-1~4-8), 결정 19, ADR-0045 결정 5. 선행: Step 7(doctor 개수 순서), Step 9. Step 11과 병렬 가능. 이 시점에는 ①이 아직 `file.*`를 막으므로 enforcement 결과는 바뀌지 않는다.

**(a) 범위:**

- 로더:
  - optional `paths`를 읽는다. 다음은 모두 파일 전체의 `CONFIG_ERROR`이고 문면에는 행·항목 index만 싣는다.
    - 절대 경로가 아닌 항목
    - `.`·`..`·빈 성분, 끝 `/`(`"/"` 예외)
    - NUL, 4096바이트 초과
    - 빈 배열, `MAX_PATHS_PER_RULE` 64개 초과
    - 파일 action이 아닌 행이나 섞인 행의 `paths`
  - 파일 패턴이 있는데 `paths`가 없는 행은 로드에 성공한다. `tracing::warn!` 한 줄을 내고 파일 권한은 주지 않는다.
- 평가: ③-1 성분 단위 포함 판정을 둔다. 항목도 요청마다 같은 정규화 함수로 정규화하고, 실패한 항목은 아무것도 덮지 않는다. `ResourceRef`에 optional 정규 경로 필드를 더한다. role grant에는 `paths`를 적용하지 않는다(ADR-0045 결정 5).
- 결정 4-6 (a)의 순수 판정 helper를 둔다. "이 principal·`auth_path`가 파일 action을 받을 근거가 있는가"를 보며, `acl show`의 `matching_rules`와 같은 helper다.
- `acl check --path <abs-path>`: 파일 action인데 `--path`가 없거나, 비파일 action인데 있으면 `INVALID_ARGUMENT`다. `data.path`와 `data.canonical_path`를 더한다. 상태 경로 판정은 돌리지 않는다는 §6.15 문단을 고친다.
- `acl show`: `matching_rules[].paths`를 더한다. 파일 action의 `effective_actions` 정의를 바꾸고, `paths` 없는 파일 행에는 human 줄을 더한다.
- doctor `acl_file_paths_missing`(warn): 같은 이름 pin이 role `full`이면 침묵하고, 정책이 없거나 파싱 실패면 침묵한다. `detail`은 index와 `auth_path`만 싣는다. remedy 꼬리는 `ACL_RESTART_NOTICE`다. doctor code는 25 → 26이다.
- 문서: `docs/PRD.md` §9(문법과 예시, action 모양 inline code를 새로 쓰지 않음), `docs/design/architecture.md` §6(문법 줄 `paths?`, ③-1), `docs/CLI.md` §6.15·§6.17·§6.19, man `qsh-acl-check`

**(b) 테스트:**

- `crates/qsh-core/src/acl/load/tests.rs`: 모양 위반 전 행, 비파일·섞인 행, 문면에 경로 문자열이 없음, `paths` 없는 파일 행의 로드와 경고
- `crates/qsh-core/src/acl/policy/tests.rs`: `file_paths_match_component_wise`(`/srv/share` 대 `/srv/shared`), 같음 매칭, `"/"` 항목, first-match가 불일치 행을 건너뜀, 경로 없는 파일 요청의 행 deny. ①을 우회하는 helper 단위로 둔다.
- doctor: `doctor_acl_findings_reports_acl_file_paths_missing_for_a_file_row_without_paths`, `acl_file_paths_missing_is_silent_for_a_role_full_pin`, 정책 없음 침묵, `detail`에 principal 문자열이 없음. `doctor_docs.rs`
- 새 fixture 이름은 이 계획의 초안이다(§7.1 #4): `acl.check.path.json`, `acl.show.with_paths.json`

**(c) 완료 판정:** `EXPECTED_DOCTOR_CODES`가 26이다. 기존 ACL fixture가 무변경 초록이다. enforcement 결과 diff 0(①이 여전히 `file.*`를 막음).

### Step 11 — (b) wire와 fuzz, 네 op의 dispatch와 deny seam (0.4~0.5ew)

근거: ADR-0029 결정 3·9, 결과 절의 fuzz·ACL 테스트 갱신 문단. 선행: Step 4. Step 10과 병렬 가능. 이 스텝 뒤에도 네 op은 ①로 모두 거부된다. 자원도 파일시스템 접근도 없다.

**(a) 범위:**

- `.proto`(`crates/qsh-proto/proto/qsh/wire/v1.proto`)에 다음을 더한다. 번호는 origin `09266dc`에서 비어 있음을 확인했다.
  - `ControlMessage` 80~83(`FileReadOpen`·`FileWriteOpen`·`FileListOpen`·`FileMkdirOpen`)
  - `Response` 11~14
  - `StreamKind FILE_DATA = 5`
  - message 12종과 `FileKind`
- `crates/qsh-proto/src/wire.rs`에 상수 `FILE_CHUNK_MAX`(32 KiB), `FILE_LIST_PAGE_MAX`(512), `FILE_LIST_DIR_MAX`(65536)를 둔다. capability 상수 `file.v1`도 정의하지만 `LOCAL_CAPABILITIES`에는 넣지 않는다(Step 13).
- `Server::dispatch`가 네 op을 받아 결정 8의 1단계(모양 검사)와 2단계(ACL) 앞부분까지 돈다. ①이 `file.*`를 막으므로 `PERMISSION_DENIED`와 audit 한 줄로 끝난다.
- `qsh listen` controller는 네 op에 `UNSUPPORTED`로 답한다(결정 16).
- `DENY_SEAMS`에 `SeamKind::ControlStreamOp` 네 행을 더한다(14 → 18). `ALWAYS_DENIED_NO_OP`에서 `file.read`/`file.write`를 빼서 `forward.socks`만 남긴다. op이 생겼기 때문이다.
- `docs/CLI.md` §2.4에 wire op 넷, §2.5에 매핑 넷을 더한다.
- fuzz:
  - 새 타깃 `decode_file_frame`(`FileFrame`)을 둔다.
  - 새 `Response` message 넷이 `decode_control` 경로에 걸리는지 확인하고, 걸리지 않으면 타깃에 더한다.
  - `fuzz/README.md`와 `docs/design/protocol.md` §13의 타깃 수를 19에서 20으로 고친다.
- `docs/design/protocol.md` §7(`FILE_DATA`와 ticket 규칙), §9(`.proto` 발췌), §16.1(freeze 발효 전 목록)
- threat-model §3 진입점 "`Server::dispatch`의 파일 op 넷과 `FILE_DATA` 스트림"

**(b) 테스트:**

- `deny_seams_row_names_and_count_are_pinned`(18), `deny_seams_cover_every_action_except_the_always_denied_trio`(갱신), `crates/qsh-core/tests/acl_registry.rs`
- `acl_uniformity.rs`: `every_deny_seam_in_the_registry_denies_with_the_uniform_message`가 네 seam을 덮는다.
- `acl_check_never_appears_as_a_control_message_wire_variant`(B2 트랩)의 variant 전수 대조 갱신
- wire round-trip 단위 테스트, 새 fuzz 타깃 smoke

**(c) 완료 판정:** `is_always_denied`가 아직 셋을 막는다. 네 op의 응답이 전부 `PERMISSION_DENIED`이고, 정규화 함수 호출이 0회다(주입 계수). `capabilities.json` diff 0.

### Step 12 — (b) host 제어 평면: 항상-deny 해제, 상태 경로, 재검증, quota, `file.list`·`file.mkdir` 완결, ticket (0.8~1.0ew)

근거: ADR-0029 결정 3(항상-deny 해제), 4-6, 5, 6-4~6-6의 연결, 8, 12(host quota), 14, 16(host 쪽), 20의 host 디렉터리 해석(`name_if_dir`/`into_dir`), ADR-0045 결정 18의 상태 경로 행. 선행: Step 9·10·11. 이 스텝이 `file.*`를 처음 연다. 거부 층과 그 테스트가 모두 같은 커밋이다.

**(a) 범위:**

- `Action::is_always_denied`에는 `forward.socks`만 남긴다.
- 결정 8 순서를 그대로 구현한다. 앞 단계가 실패하면 뒤 단계는 돌지 않는다.
  1. 모양 검사와 home 해석
  2. ACL: (a) 근거 판정 → (b) 근거가 있을 때만 정규화 → (c) `Authorizer::check` + audit
  3. user hint 대조(`UNSUPPORTED`)
  4. 상태 경로(role만으로 allow됐으면 여기서 처음 정규화한다. deny면 audit 한 줄 더)
  5. `file.read`/`file.write`의 quota 예약
  6. 열기와 재검증(보호 집합 + 평가기 재호출, deny면 audit 한 줄 더). `file.read`의 inode 대조와 종류 판정, `file.write`의 대상 존재·`overwrite`·디렉터리 해석
  7. 응답
- `file.read`/`file.write`는 연 fd를 ticket에 묶는다(30초, 단회). 만료되면 fd를 닫고 quota를 돌려준다. temp는 아직 만들지 않는다.
- `file.mkdir`은 3~5단계를 통과한 뒤에만 `mkdirat`을 부른다.
- `file.list`는 이름 바이트 순서, `after` 커서, `FILE_LIST_PAGE_MAX`, `unlistable` 계수, `FILE_LIST_DIR_MAX` 초과 시 `RESOURCE_EXHAUSTED`다.
- quota:
  - `[serve].max_file_transfers_per_principal`(기본 4)와 `[serve].max_file_transfers`(기본 64)를 둔다.
  - `QuotaKind` 두 값을 더하고 audit `resource`는 `quota_files_principal`, `quota_files_host`다.
  - `docs/CLI.md` §6.12 quota 문단에 적는다. `serve --to`도 같은 `[serve]` 키를 쓴다(§7.1 #5).
- 쓰기 여유 공간 확인(결정 13)은 Step 13의 데이터 평면과 함께 둔다. 6단계의 `statvfs` 자리만 이 스텝에서 연다.
- 문서:
  - threat-model §4 B 새 행: 상태 파일 쓰기로 role·인가를 올림, symlink·`..`·경쟁·hard link 우회, `paths` 밖 도달, 정규화 시간 차로 구조를 더듬음, `file.read`로 키·token 읽기, qsh 밖 비밀, `file.list` 반복 CPU
  - `CLAUDE.md` "Security defaults"에 "원격 파일 op은 role이나 행과 무관하게 qsh 자신의 config·state·runtime 경로에 닿지 못한다" 한 항목을 더한다(§9 #6).

**(b) 테스트 (route 동등: 각 행을 `qsh serve`와 `qsh serve --to` 두 harness에서. 이 스텝에는 client가 없으므로 testkit의 raw wire 요청자로 돈다):**

- `file_ops_are_denied_without_a_matching_rule_or_role`
- `role_full_file_ops_allow_any_path_but_still_deny_state_paths`(ADR-0029). 대상은 `acl.toml`, `trust.toml`, `invites.toml`, `identity/device.key`, `audit.log` 다섯과 symlink, `..` 이탈이고 네 op이다. 바이트 불변을 단언한다.
- `role_full_file_ops_still_deny_state_paths`(ADR-0045)는 같은 테스트 파일 안의 별도 함수다. `full`로 `trust.toml`, `invites.toml`, `acl.toml`, identity 키를 읽거나 쓰지 못한다.
- `file_write_to_state_paths_is_denied_even_with_root_paths`, `file_read_of_state_paths_is_denied_even_with_root_paths`(hard link 우회 포함)
- `file_list_and_mkdir_in_state_dirs_are_denied`
- `file_rule_without_paths_grants_no_file_access`
- `file_read_through_a_symlink_out_of_paths_is_denied`, `file_dotdot_escape_out_of_paths_is_denied`, `file_paths_recheck_the_opened_handle`
- `file_request_without_a_file_grant_touches_no_filesystem`(정규화 함수 주입 계수 0)
- `denied_file_write_leaves_no_file_or_temp_behind`, `unredeemed_file_write_ticket_leaves_nothing_behind`
- `file_list_pages_are_sorted_and_resumable_by_cursor`, `file_list_rejects_directories_over_the_entry_cap`
- `file_audit_record_carries_path_but_no_payload`
- `crates/qsh-core/tests/quota_registry.rs` 두 행, `quota_docs.rs`의 키·기본값 대조, `saturated_quota_still_answers_permission_denied_to_an_unauthorized_principal_end_to_end`의 파일 행
- `is_always_denied_is_exactly_the_undrivable_trio`를 `forward.socks` 하나로 고치고 이름도 바꾼다.
- `acl_check_equivalence.rs`: `file.read`·`file.write` 두 action 행, `paths` 안·형제 밖·symlink 밖·`..` 이탈·`--path` 누락·비파일 `--path` 행, role `full`이 경로와 무관하게 allow인 행. 각 행에서 `acl check --path`, enforcement, `acl show`가 일치해야 한다.
- `acl_uniformity.rs`: `paths` 밖, `paths` 없음, 정규화 실패, 상태 경로, 재검증 불일치가 같은 `PERMISSION_DENIED_MESSAGE`를 낸다(네 seam).
- Step 4의 `role_full_without_acl_toml_allows_every_action_but_forward_socks`에서 `file.*` 행을 allow로 뒤집는다.

**(c) 완료 판정:** 위 테스트가 초록이고 부하 아래 50회 초록이다. 상태 경로 핀의 바이트 대조가 sha256으로 커밋 본문 재현 절차와 일치한다. 이 시점에 `file.v1`은 광고되지 않으므로 정상 client는 요청을 보내지 않는다.

### Step 13 — (b) host 데이터 평면: `FILE_DATA`, 원자적 교체, 무결성, 여유 공간, 정체 장부, `file.v1` 광고 (0.7~0.9ew)

근거: ADR-0029 결정 1의 capability, 7(host 쪽), 10, 11(host 쪽), 13, 15, 16의 데몬 중계 정체 장부. 선행: Step 12.

**(a) 범위:**

- `FILE_DATA` 스트림(`StreamHeader{FILE_DATA, ticket}`)을 다룬다.
  - read: host가 `data`를 보내고 마지막에 `FileEnd`(size, BLAKE3-256)를 보낸다.
  - write: host가 `data`와 `FileEnd`를 받는다. `size` 초과는 즉시 끊는다.
  - 상한을 넘는 `data`, `end` 뒤의 frame, 요청자의 `result`는 `BAD_HEADER`(0x2001) reset이다.
- write 흐름:
  1. 디렉터리 fd에서 temp `.<name>.qsh-<16 hex>.part`(`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600)를 만든다.
  2. 검증, `fsync`, `fchmod`(mode/umask/`preserve`와 `futimens`)를 한다.
  3. `overwrite`면 `renameat`, 아니면 `linkat` + `unlinkat`이다. `EEXIST`면 `FileWriteResult{ok=false, INVALID_ARGUMENT}`다.
  4. 디렉터리 `fsync`를 하고 `FileWriteResult`를 보낸 뒤 `finish()`한다.
  - 실패, 취소, 연결 유실, 정체 끊음이면 temp를 `unlinkat`한다.
- `FILE_WRITE_FREE_RESERVE`(256 MiB)를 `statvfs`로 확인한다. `ENOSPC`는 `RESOURCE_EXHAUSTED`다.
- `file.mkdir` mode 규칙 `((mode & ~umask) | 0o700)`
- band 0과 `SEND_DEPTH_CAP_BYTES`를 적용한다. 받는 쪽 디스크 쓰기를 ADR-0037 장부(`crates/qsh-core/src/tunnel/stall.rs`, `STALL_AGE`, `0x200E`)에 올린다. 연결 양 끝과 localctl 데몬 중계 모두다.
- `LOCAL_CAPABILITIES`에 `file.v1`을 더한다(`cfg(unix)` 빌드만, §4 규율). `QSH_UPDATE_FIXTURES=1`로 `capabilities.json` golden을 다시 만든다.
- 문서: `docs/design/protocol.md` §4(`file.v1`), §12(정체 장부 범위), §16.1. threat-model §4 새 행: 덮어쓰기가 반쯤 쓴 파일이나 temp를 남김, 디스크를 채워 audit fail-closed가 host를 멈춤, 정체한 `FILE_DATA`가 수신 창을 묶음.

**(b) 테스트 (route 동등: forward와 `serve --to` 두 harness):**

- `file_write_overwrites_atomically_by_default`, `file_write_no_clobber_never_replaces_an_existing_file`(확인과 교체 사이 경쟁 포함)
- `interrupted_file_write_removes_its_temp_file`(연결 유실, 취소, 정체 장부 끊음 세 경우)
- `file_write_size_or_hash_mismatch_renames_nothing`
- 여유 공간 거부 행(주입한 `statvfs`)
- `capabilities.json` golden 대조 테스트

**(c) 완료 판정:** M13 (b)의 `tunnel_stalled_streams` 네 테스트와 `tunnel_throughput_meets_raw_quinn_ratio`가 고치지 않은 기준으로 초록이다. 부하 반복 50/50이다.

### Step 14 — (b) client `qsh cp`: 단일 파일, operand 문법, JSON, forward·reverse 왕복, 복사 중 PTY echo 측정 (0.8~1.0ew)

근거: ADR-0029 결정 1(client 쪽 거부와 capability 확인), 2, 7(client 로컬 쓰기), 11(client 정리, Ctrl-C), 16(client·데몬 conduit), 17, 18, 21. 선행: Step 13.

**(a) 범위:**

- `Ops::file_copy`(합성 local op `file.copy`, `qsh-core`)를 둔다.
- operand 판별은 scp 규칙이다. 첫 `/` 앞의 `:`가 원격 표지이고, IPv6는 대괄호로 싸며, `host:`는 `~`이다. 거부와 exit는 다음과 같다.

  | 상황 | 결과 |
  |---|---|
  | put/get 구성이 아님(원격↔원격, 섞인 operand, host가 둘 이상) | `INVALID_ARGUMENT` exit 2 |
  | `-` operand | `INVALID_ARGUMENT` |
  | 지원하지 않는 scp 플래그 | exit 2 + stderr 한 줄 |

- 플래그는 `-r`(Step 15), `-p`, `-q`, `--no-clobber`, `--json`/`--jsonl`이다.
- host 해석은 `qsh exec`과 같다(§6.1, live reverse 우선). `user@`는 user hint다.
- peer capability에 `file.v1`이 없으면 보내기 전에 `UNSUPPORTED`다. 역방향이면 `LocalHelloAck.capabilities`로 확인하고, 원인 둘을 짚는 문면을 낸다.
- get의 로컬 쓰기는 temp + link/rename + fsync이고 DST 디렉터리 fd 기준 `*at`으로 한다. DST 아래 기존 symlink는 `INVALID_ARGUMENT`다.
- `FILE_COPY_PARALLEL = 2`
- Ctrl-C는 `CANCELED` exit 255다.
- JSON: 결정 18 모양(`direction`, `entries`, `COPY_JSON_ENTRIES_MAX` 1000). `--jsonl`은 `qsh.event/v1` `file.entry` 줄 + 마지막 envelope이다.
- 부분 실패는 결정 21 모양이다(`error.details`의 다섯 수와 `failures`, `COPY_JSON_FAILURES_MAX` 64). 여러 SRC를 주면 `-r` 없이도 부분 실패가 생긴다.
- human 진행 표시는 stderr TTY일 때만 그리고 요약은 stdout 한 줄이다.
- `qsh-cli`에는 clap, 렌더러 둘, 진행 표시만 둔다.
- 등록 완전성: schemars, `cli_v1_data_schema`, `CLI_V1_SCHEMA_COMMANDS`, 렌더러 둘, man `qsh-cp`, CLI.md §2.4(`file.copy`)·§2.5("인가 불요" 행), 새 `qsh cp` 절(결정 2·3·4-8 범위 문장·17·18·21·22). §2.5 끝의 "향후 예약: streaming file copy" 문장을 지운다.
- `docs/CLI.md` §10에 `file.entry` event type을 더한다.
- `file_copy_echo_under_load`(새 testkit 파일. M13 (b) 하네스 모양)를 `ci.yml` acceptance job에 strict로 넣고, `CLAUDE.md` Commands 절의 acceptance 목록과 `docs/design/testing.md` 게이트 환경변수 표에 이름을 더한다.

**(b) 테스트:**

- `file_round_trip_is_byte_identical_forward`, `file_round_trip_is_byte_identical_reverse`(64 MiB 이상 무작위 파일, BLAKE3와 sha256 대조)
- `cp_operand_grammar_separates_remote_from_local`(`./a:b`, `[::1]:p`, `host:`, `host:dir/x`)
- `cp_rejects_unsupported_scp_flags_with_exit_2`, `cp_remote_to_remote_is_invalid_argument`, `cp_mixed_operands_are_invalid_argument`
- `cp_into_existing_directory_uses_the_source_name_get_and_put`, `cp_multiple_sources_require_an_existing_directory`
- `cp_home_relative_paths_expand_against_the_serve_account`, `cp_tilde_user_is_invalid_argument`, `cp_user_hint_mismatch_is_unsupported_after_acl`
- `cp_preserve_sets_mode_and_mtime`, `cp_without_preserve_applies_the_umask`
- `cp_partial_failure_exits_255_and_reports_failures`
- `cp_json_and_jsonl_report_every_entry`
- `file_copy_never_appears_as_a_control_message_wire_variant`(`setup_run_never_appears_as_a_control_message_wire_variant` 형식)
- `file_copy_echo_under_load`(acceptance strict, 예산은 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`와 같은 측정 RTT + 10ms)
- `jsonl_purity.rs`·`exit_code_matrix.rs`에 `cp` 행을 더한다.
- 새 fixture `file.copy.get.json`, `file.copy.put.json`, `error.file.copy.partial.json`, `file.entry` event 예시(이름 §7.1 #4)

**(c) 완료 판정:**
- 두 route 왕복이 같은 커밋에서 초록이다.
- `file_copy_echo_under_load`가 부하 없이 50회 초록이다.
- 붉으면 수정은 band·송신 깊이·정체 장부 쪽에서 한다. ADR이 이 축의 대체 경로를 미리 정하지 않았으므로, 상수 조정을 넘는 변경이면 착지하지 않고 판정을 기록한 뒤 main 세션이 ADR 필요 여부를 정한다(§7).

### Step 15 — (b) 재귀 복사 `-r`: 트리 순회, 이름 검증, 병렬과 quota 재시도, 트리 측정과 audit 처리량 (0.8~1.0ew)

근거: ADR-0029 결정 12(client 병렬·재시도), 20, 22, 결정 14와 근거 절의 처리량·성능 대체 경로. 선행: Step 14.

**(a) 범위:**

- get `-r`: `file.list` 페이지를 이름 바이트 순서로 받고, 로컬 mkdir(0o700 보장) 뒤 재귀한다.
- put `-r`: 로컬 트리를 이름 바이트 순서로 걷고, 부모를 먼저 `file.mkdir`한 뒤 파일을 `file.write`한다. 최상위는 `name_if_dir`이고 `into_dir`로 기준 경로를 정한다.
- 트리 안 symlink는 `skipped`(reason `symlink`)다. 최상위 operand symlink는 따른다. 특수 파일은 그 항목이 `INVALID_ARGUMENT`다.
- `unlistable`은 실패 항목 하나다. 4096바이트를 넘는 경로는 실패다.
- `.` 같은 이름 없는 SRC는 내용 복사다.
- 원격 항목 이름 검증(결정 22): 빈 이름, 255바이트 초과, `/`·NUL, `.`·`..`는 그 항목 실패이고 로컬에는 아무것도 만들지 않는다. 디렉터리 하나에서 `FILE_LIST_DIR_MAX`를 넘으면 그 디렉터리를 `RESOURCE_EXHAUSTED`로 실패시킨다.
- 연결 수준 실패는 순회를 멈추고 `not_attempted`를 센다.
- quota 초과면 자기 전송 하나가 끝나기를 기다렸다 재시도한다. 자기 전송이 없는데도 거부되면 실패다.
- **측정.** `cp_many_small_files_stays_within_the_echo_budget`가 파일 수천 개 트리를 옮기는 동안 PTY echo p95와 audit writer 처리량을 같이 잰다. 처리량은 writer의 bounded queue가 차서 fail-closed 거부가 난 횟수와 초당 레코드 수다. 값은 커밋 본문에 적는다.
- **미리 정한 대체 경로**(ADR-0029 결정 14, 근거 절):
  1. audit 처리량이 모자라면 writer 안에서 같은 내구성 계약을 지키는 group commit을 한다(`crates/qsh-core/src/audit/writer.rs`). 줄을 합치거나 솎지 않는다.
  2. 그래도 모자라면 `FILE_COPY_PARALLEL`을 낮춘다.
  3. 트리 처리 시간이 모자라면 `FILE_COPY_PARALLEL`을 per-principal quota(기본 4) 안에서 올린다.
  4. 이 셋을 넘는 변경은 새 ADR이다.
- 문서: threat-model §4 새 행 "악의적인 host가 `..`나 `/`가 든 이름으로 client 로컬 경로를 벗어난다"와 "트리 일부 실패가 성공으로 보인다". `docs/CLI.md` `qsh cp` 절의 재귀 문단.

**(b) 테스트:**

- `cp_recursive_round_trip_tree_is_identical_forward`, `cp_recursive_round_trip_tree_is_identical_reverse`
- `cp_recursive_skips_symlinks_inside_trees_and_follows_an_operand_symlink`
- `cp_special_files_fail_their_entry_and_the_walk_continues`
- `cp_connection_loss_stops_the_walk_and_reports_not_attempted`
- `cp_rejects_hostile_entry_names`(`..`, `a/b`, 빈 이름, NUL을 돌려주는 가짜 host)
- `cp_dot_source_copies_contents`, `cp_directories_are_owner_writable_while_filling`
- `cp_json_truncates_entries_but_not_totals`
- `cp_many_small_files_stays_within_the_echo_budget`
- 새 fixture `file.copy.tree.json`

**(c) 완료 판정:** 두 route 트리 왕복이 같은 커밋에서 초록이다. 측정값, 그리고 대체 경로를 썼는지와 어느 것인지가 커밋 본문에 있다. 지연 단언은 부하 없이 50회, 나머지는 부하 아래 50회 초록이다.

### Step 16 — 마감 (0.1~0.2ew)

근거: 마일스톤 마감 공통 절차(`docs/ROADMAP.md` §2) 1·2, §4 안정성 규율. 선행: Step 2~15.

**(a) 범위:**

- **부하 반복.** M15 타이밍 민감 테스트 전부를 `scripts/stress/m15.filter`로, 지연 단언을 `scripts/stress/m15-latency.filter`로 묶는다. 앞의 것은 `QSH_ACCEPTANCE_SLOW=1 scripts/stress/run.sh`로 50회, 뒤의 것은 부하 없이 `-j 1`로 50회 돌린다. "50/50 passed under load" 줄과 호스트 사양을 마감 노트에 적는다.
- **절차 1. 구속 문서 태그 대조.** 대상은 다음과 같다.
  - `docs/CLI.md` v0.26 항목: §2.4·§2.5·§6.11·§6.12·§6.13·§6.15·§6.17·§6.19·§6.20·§10·`qsh cp` 절
  - `docs/PRD.md` §9
  - `docs/design/architecture.md` §6·§7
  - `docs/design/protocol.md` §4·§7·§9·§12·§13·§16.1
  - `docs/design/threat-model.md` §2·§3·§4 B·§7
  - `docs/design/testing.md` 게이트 표
  - `fuzz/README.md`
  - ADR-0045·0029 결과 절 문서 목록 전수, ADR-0017·0024·0025·0038의 개정 대상 결정 문장
  - ADR-0029 결정 23의 Windows 문장이 M19·M20에 귀속됐다는 기록
- **절차 2. README 동기화.** 기능 목록(`qsh cp`, role), Known limitations("role을 줄여도 열린 연결은 M16까지 유지", Windows `qsh cp`는 M19·M20, 재개 없음, 트리 원자성 없음, 교체로 소유자·xattr가 바뀜), 보안 절.
- threat-model §7 잔여 위험(ADR-0029 결과 절의 다섯 + 교체 의미)
- ROADMAP M15 마감 노트(main 세션). 이 `PLAN.md`의 마지막 커밋 해시를 적고 다음 계획(M16)으로 교체한다. 계획 원문은 커밋 해시로 인용한다(ROADMAP 머리말 규칙).

**(b) 테스트·게이트:** 일곱 게이트, CI(acceptance 포함) 초록, 부하 반복 두 세트 50/50.

**(c) 완료 판정:** §3의 DoD가 근거 커밋, run id와 함께 `[x]`다. `git diff --stat <Step 2 부모>..<Step 10 머지> -- crates/qsh-proto/proto`가 비어 있다. wire 변경은 Step 11과 Step 13에만 있다.

## 5. 결정·핀 테스트 대응표

각 결정과 핀 테스트의 주인은 스텝 하나다. 한 결정이 여러 스텝에 걸치면 하위 항목으로 나눠 각각 주인 하나를 적는다.

### 5.1 ADR-0045 결정

| 결정 | 스텝 |
|---|---|
| 1 신뢰 등록이 곧 권한 부여, 불변식 유지 | 4 |
| 2 role 여섯과 표, 소유 축 | 2 |
| 3 `trust.toml` `role` 키, 키 없음 = `none`, `TrustRole` | 2 |
| 4 평가 ⓡ, 합집합, fingerprint 대조, CA 제외, 판정마다 읽기, reload 정지 | 4 |
| 5 role grant에는 `paths`를 적용하지 않음 | 10 |
| 6 Authorizer 입력과 구성(둘째 문단) | 3 |
| 6 `acl.toml` 세 상태 | 4 |
| 7 판정 함수 하나 | 4 |
| 8 `--role`, 기본값, 초대 role, `trust add` 불변, `trust set-role`, local_op audit | 5 |
| 8 `qsh setup --peer-role` | 7 |
| 9 `TrustPeer.role`, `trust list` role 열 | 2 |
| 10 `acl check` | 6 |
| 11 `acl show` | 6 |
| 12 doctor | 7 |
| 13 시작 진단 | 4 |
| 13 페어링 직후 고지 | 5 |
| 14 `qsh setup` ACL 단계 | 7 |
| 15 필드: `TrustPeer.role` | 2 |
| 15 필드: `TrustAddReq`·`TrustInviteReq`·`TrustInviteData.assigned_role`·`TrustAcceptReq`·`TrustSetRole*` | 5 |
| 15 필드: `AclCheckData`·`AclPolicyRef.state`·`AclShowData` | 6 |
| 15 필드: `SetupRunReq.peer_role` | 7 |
| 16 audit optional `role` 키 | 2 |
| 17 wire 불변(검증) | 8 |
| 18 권한 확대 경로 목록, `exec`는 경계가 아님 문장 | 5 |
| 19 마일스톤 배치·순서 | 1 |
| 20 플랫폼·route 동등 | 4 |

### 5.2 ADR-0045 핀 테스트

| 테스트 | 스텝 |
|---|---|
| `legacy_pin_without_role_is_authorized_by_acl_rows_only` | 4 |
| `role_full_without_acl_toml_allows_every_action_but_forward_socks` | 4 |
| `invalid_acl_toml_denies_role_grants_too` | 4 |
| `role_grant_does_not_reach_a_ca_leaf_naming_a_pinned_device` | 4 |
| `role_requires_the_connection_fingerprint_to_match_the_current_pin` | 4 |
| `set_role_takes_effect_on_the_next_request_without_restart` | 5 |
| `trust_remove_ends_role_grants_on_the_next_request` | 4 |
| `trust_store_reload_failure_suspends_role_grants` | 4 |
| `trust_add_never_changes_an_existing_pin_role` | 5 |
| `invite_role_is_fixed_by_the_issuer` | 5 |
| `pair_accept_and_trust_add_default_to_role_none` | 5 |
| `pair_invite_defaults_to_role_full` | 5 |
| `set_role_without_a_durable_audit_record_leaves_trust_toml_untouched` | 5 |
| `role_writes_leave_a_local_op_audit_record_with_the_role` | 5 |
| `role_grant_audit_record_names_the_role_and_no_rule` | 4 |
| `role_tunnel_cannot_close_another_principals_remote_forward` | 4 |
| `role_read_only_can_attach_but_not_write` | 4 |
| `role_full_file_ops_still_deny_state_paths` | 12 |
| `unknown_role_string_makes_trust_toml_a_config_error` | 2 |
| `role_action_table_matches_docs` | 2 |
| `decide_agrees_with_naive_coverage_oracle`의 role 차원 | 4 |
| `acl_check_equivalence.rs` role 행 | 6 |
| `acl_uniformity.rs` role 거부 셋 | 4 |
| `setup_never_writes_acl_toml_in_any_role` 무변경 초록 | 7 |
| `setup_host_roles_incomplete_without_acl_toml` 축소 + role 기본값 `complete` 새 테스트 | 7 |
| fixture 아홉: `trust.list.with_role` | 2 |
| fixture 아홉: `trust.set_role`, `trust.set_role.unchanged`, `trust.add.with_role`, `trust.invite.with_role` | 5 |
| fixture 아홉: `acl.check.allow_by_role`, `acl.check.missing_policy_role`, `acl.show.with_role` | 6 |
| fixture 아홉: `setup.run.host_complete_with_role` | 7 |
| doctor code `trust_pin_role_unset`과 조건이 바뀐 넷 | 7 |
| 측정: 판정마다 `trust.toml` 읽기 비용 | 3 |

### 5.3 ADR-0029 결정

| 결정 | 스텝 |
|---|---|
| 1 범위, 원격↔원격 거부, client capability 확인 | 14 |
| 1 capability `file.v1` 정의 | 11 |
| 1 capability `file.v1` 광고 | 13 |
| 2 CLI 모양과 operand 문법 | 14 |
| 3 op↔action 매핑, seam | 11 |
| 3 항상-deny 해제 | 12 |
| 4 role과 행 두 길, `paths` 문법·매칭·정규화 시점·resource, 4-6 helper | 10 |
| 4-6 ACL 단계의 host 연결 | 12 |
| 5 상태 경로 집합 | 9 |
| 6 경로 판정 절차(모듈) | 9 |
| 6-4~6-6 host 연결 | 12 |
| 7 host 원자적 교체·mode | 13 |
| 7 client 로컬 쓰기 | 14 |
| 8 host 처리 순서 | 12 |
| 9 wire | 11 |
| 10 무결성 | 13 |
| 11 재개 없음, host 정리 | 13 |
| 11 client 정리, Ctrl-C | 14 |
| 12 host quota | 12 |
| 12 client 병렬·재시도 | 15 |
| 13 여유 공간 | 13 |
| 14 audit 필드 | 12 |
| 14 처리량 대체 경로 | 15 |
| 15 band, 송신 깊이, 정체 장부 | 13 |
| 15 PTY echo 측정 | 14 |
| 16 host 쪽(serve --to 판정, listen `UNSUPPORTED`) | 11 |
| 16 데몬 중계 정체 장부 | 13 |
| 16 client conduit와 capability relay | 14 |
| 17 오류 코드 | 14 |
| 18 JSON | 14 |
| 19 `acl check --path`, `acl show` `paths`, `acl_file_paths_missing` | 10 |
| 20 재귀 의미 | 15 |
| 20 host `name_if_dir`·`into_dir` | 12 |
| 21 부분 실패와 exit | 14 |
| 22 원격 이름·크기 불신 | 15 |
| 23 macOS 행 | 9 |
| 23 Windows host | M20 밖(ADR-0035 결정 26) |
| 23 Windows client | M19 밖(ADR-0035 결정 1) |

### 5.4 ADR-0029 핀 테스트와 결과 절 항목

| 항목 | 스텝 |
|---|---|
| `file_ops_are_denied_without_a_matching_rule_or_role` | 12 |
| `role_full_file_ops_allow_any_path_but_still_deny_state_paths` | 12 |
| `file_write_to_state_paths_is_denied_even_with_root_paths` | 12 |
| `file_read_of_state_paths_is_denied_even_with_root_paths` | 12 |
| `file_list_and_mkdir_in_state_dirs_are_denied` | 12 |
| `state_path_guard_denies_nonexistent_paths_under_state_dirs` | 9 |
| `state_path_guard_covers_env_overridden_and_default_dirs` | 9 |
| `state_path_guard_rechecks_the_opened_handle` | 9 |
| `file_rule_without_paths_grants_no_file_access` | 12 |
| `file_paths_match_component_wise` | 10 |
| `file_read_through_a_symlink_out_of_paths_is_denied` | 12 |
| `file_dotdot_escape_out_of_paths_is_denied` | 12 |
| `file_paths_recheck_the_opened_handle` | 12 |
| `file_request_without_a_file_grant_touches_no_filesystem` | 12 |
| `denied_file_write_leaves_no_file_or_temp_behind` | 12 |
| `unredeemed_file_write_ticket_leaves_nothing_behind` | 12 |
| `file_write_overwrites_atomically_by_default` | 13 |
| `file_write_no_clobber_never_replaces_an_existing_file` | 13 |
| `interrupted_file_write_removes_its_temp_file` | 13 |
| `file_write_size_or_hash_mismatch_renames_nothing` | 13 |
| `file_round_trip_is_byte_identical_forward` / `_reverse` | 14 |
| `file_audit_record_carries_path_but_no_payload` | 12 |
| `quota_registry.rs` 두 행, `quota_docs.rs` | 12 |
| `file_copy_echo_under_load` | 14 |
| `cp_operand_grammar_separates_remote_from_local` | 14 |
| `cp_rejects_unsupported_scp_flags_with_exit_2` | 14 |
| `cp_remote_to_remote_is_invalid_argument` | 14 |
| `cp_mixed_operands_are_invalid_argument` | 14 |
| `cp_into_existing_directory_uses_the_source_name_get_and_put` | 14 |
| `cp_multiple_sources_require_an_existing_directory` | 14 |
| `cp_dot_source_copies_contents` | 15 |
| `cp_home_relative_paths_expand_against_the_serve_account` | 14 |
| `cp_tilde_user_is_invalid_argument` | 14 |
| `cp_user_hint_mismatch_is_unsupported_after_acl` | 14 |
| `cp_recursive_round_trip_tree_is_identical_forward` / `_reverse` | 15 |
| `cp_recursive_skips_symlinks_inside_trees_and_follows_an_operand_symlink` | 15 |
| `cp_special_files_fail_their_entry_and_the_walk_continues` | 15 |
| `cp_partial_failure_exits_255_and_reports_failures` | 14 |
| `cp_connection_loss_stops_the_walk_and_reports_not_attempted` | 15 |
| `cp_rejects_hostile_entry_names` | 15 |
| `cp_preserve_sets_mode_and_mtime` | 14 |
| `cp_without_preserve_applies_the_umask` | 14 |
| `cp_directories_are_owner_writable_while_filling` | 15 |
| `file_list_pages_are_sorted_and_resumable_by_cursor` | 12 |
| `file_list_rejects_directories_over_the_entry_cap` | 12 |
| `cp_json_and_jsonl_report_every_entry` | 14 |
| `cp_json_truncates_entries_but_not_totals` | 15 |
| `cp_many_small_files_stays_within_the_echo_budget` | 15 |
| `acl_check_equivalence.rs` paths 행과 두 action 행 | 12 |
| `acl_uniformity.rs` 네 seam 문면 | 11 |
| `acl_uniformity.rs` paths·상태 경로·재검증 거부 문면 | 12 |
| `acl/load/tests.rs` paths 행 | 10 |
| `acl/policy/tests.rs` paths 행 | 10 |
| doctor `acl_file_paths_missing` 테스트, `acl_file_paths_missing_is_silent_for_a_role_full_pin` | 10 |
| `is_always_denied_is_exactly_the_undrivable_trio` 갱신 | 12 |
| `deny_seams_row_names_and_count_are_pinned`(14 → 18), `ALWAYS_DENIED_NO_OP` | 11 |
| `file_copy_never_appears_as_a_control_message_wire_variant` | 14 |
| fixture `acl.show`(paths)·`acl.check`(--path) | 10 |
| fixture `capabilities.json` | 13 |
| fixture `file.copy.get`·`file.copy.put`·`error.file.copy.partial`·`file.entry` 예시 | 14 |
| fixture `file.copy.tree` | 15 |
| fuzz `decode_file_frame`, Response 넷 decode 확인 | 11 |
| man `qsh-acl-check` | 10 |
| man `qsh-cp` | 14 |
| macOS 대소문자 우회 행 | 9 |
| Windows 행(대소문자 무시, `\`/`/`, UNC, junction, 드라이브 `paths`) | M20 밖 |

## 6. 명시적 non-goals

- 디렉터리 동기화(rsync류), 원격↔원격 복사(`-3`), 재개, `qsh ls`·원격 파일 브라우징, UDP forwarding. ROADMAP M15 명시적 out, ADR-0029 결정 1·11.
- symlink 만들기, 소유자·xattr·ACL·hard link 옮기기, stdin/stdout `-`, scp/sftp 프로토콜 호환, `file.stat` op, `paths` glob, `deny_paths`. ADR-0029 결정 1·2·20과 대안 절.
- role 추가·매핑 변경, 사용자 정의 role, `acl.toml` deny 행, `acl check --role`, `acl grant`/`revoke`. ADR-0045 결정 2·4·10과 대안 절, ADR-0025.
- `trust remove`·role 축소·rename 뒤 열린 연결 닫기. M16 (b) ADR-0031. M15 동안은 알려진 잔여 위험이고 `an_established_connection_survives_the_hosts_trust_remove`는 그대로다.
- SSH 부트스트랩과 `qsh cp`의 미등록 host 자동 부트스트랩. M16 (a) ADR-0044. ADR-0029 결정 2 마지막 항목은 M16이 착지할 때 효력이 생긴다.
- Windows. client `qsh cp`와 드라이브 문자 operand는 M19, host 파일 op·경로 판정·`paths` 드라이브 표기·`FILE_DATA` host 처리는 M20(ADR-0035 결정 1·26, ADR-0029 결정 23). M15의 Windows 빌드 `qsh serve`는 `file.v1`을 광고하지 않는다.
- 새 `ErrorCode`, `qsh.local.v1` 변경, 새 `LocalStreamKind`. ADR-0029 결정 16·17.
- (a) 범위의 wire·capability 변경. ADR-0045 결정 17.
- 에이전트가 하는 `gh secret set`, `gh workflow run`, 태그 push, 저장소 설정 변경.
- P2 전부.

## 7. 리스크와 감시 항목

- **판정마다 `trust.toml` 읽기 비용.** 지금 `SharedTrustStore::refresh`는 호출마다 파일 내용 전체를 읽어 비교한다(M7에서 mtime 해상도 때문에 고른 방식). `forward.local` 인라인 게이트처럼 잦은 지점에서는 연결마다 파일 읽기가 하나 는다. Step 3이 의미를 바꾸지 않은 채 먼저 잰다. 넘치면 (크기, 수정 시각 ns, dev·inode) 선확인으로 바꾼다. 거친 mtime 해상도의 파일시스템에서 같은 크기·같은 시각의 편집을 놓치면 role 축소가 늦게 보이는 쪽(fail-open 방향)이 된다. 대체 경로를 쓰게 되면 Step 3이 이 조건을 테스트로 고정하거나 커밋 본문에 잔여로 적는다(§10 영문 노트 #2).
- **`Authorizer::check` 시그니처 변경의 파급.** testkit 대역, `qsh-core` 내부 테스트, `reverse::admit` 경로가 함께 바뀐다. Step 3을 기계적 변경과 측정만으로 좁혀 리뷰 면적을 줄인다.
- **(a) Step 4와 5 사이의 간극.** 판정기는 role을 읽지만 명령은 아직 role을 쓰지 않는다. 이 사이에 생기는 pin은 키 없음 = `none`이라 좁아지는 방향이다. Step 5의 "새 pin은 role 키를 명시" 테스트가 간극을 닫는다.
- **audit writer 처리량.** writer는 bounded queue + fail-closed다. 작은 파일 수천 개 트리에서 queue가 차면 op이 거부되고 복사가 `failed` 항목으로 끝난다. Step 15가 재고, 대체 경로는 group commit → `FILE_COPY_PARALLEL` 낮춤 순이다. 그 너머는 새 ADR이다.
- **복사 중 PTY echo.** `file_copy_echo_under_load`가 붉으면 ADR에 미리 정한 대체 경로가 없다. 수정이 band·송신 깊이·정체 장부 상수 조정을 넘으면 (b)를 닫지 못하고 ADR이 필요하다. Step 14 (c)에 판정 절차를 적었다.
- **열린 핸들 재검증의 플랫폼 차이.** Linux `/proc` 미마운트 환경(일부 컨테이너)에서는 readlink가 실패한다. 실패는 거부로 접는다(fail closed). 그 경우 모든 파일 op이 거부되므로 Step 9가 진단 문면과 테스트 skip 조건을 정한다.
- **macOS runner의 대소문자.** `macos-14` runner 볼륨은 대소문자를 구분하지 않는다. 보호 대조는 대소문자 무시이고 `paths` 매칭은 디스크 표기로 한다. 두 비교가 다른 결과를 내는 경계 행을 Step 9·10이 각각 둔다.
- **CLI.md 상태 헤더와 `REQUIRED_FIXTURES` 충돌.** 병렬 스텝(5∥6, 10∥11)은 같은 한 줄과 같은 배열을 만진다. 늦게 착지하는 쪽이 rebase하고 개수 문장(doctor 24 → 25 → 26, seam 14 → 18, fuzz 19 → 20)을 착지 시점 값으로 맞춘다.
- **README First run과 캠페인.** README First run은 m7·m9 스톱워치가 재는 "literal script"다. m9 대상 트리는 `docs/campaigns/m9-stopwatch.md` §8에 SHA로 고정됐고 m7은 pre-M9 커밋이라 문면을 바꿔도 측정이 흔들리지 않는다. `p1-setup-stopwatch`는 "실행 전에 채우는" 트리이므로 Step 7 이후 트리로 돌리면 ACL 단계가 사라져 다른 절차를 재게 된다(§9 #3).
- **M16 착수 압력.** M16의 착수 조건은 "M15 (a) 착지"라 Step 8 뒤에 열 수 있다. 두 마일스톤을 동시에 열면 `trust/`·`ops/trust.rs`(M16 (a))와 `server/`(M15 (b)·M16 (b))가 겹친다(§9 #1).

### 7.1 구현 중 확정할 값 (해당 step (a)에 근거와 함께 추기)

| # | 질문 | 초안 | 확정 시점 |
|---|---|---|---|
| 1 | `Authorizer::check`의 fingerprint 전달 모양 | `(principal, auth_path, fingerprint)`를 묶은 요청자 구조체 하나. 인자 넷을 늘리지 않는다 | Step 3 |
| 2 | 짧은 연결 측정 행의 모양 | `-L`로 1000회 연속 연결·닫기, `trust.toml`에 pin 100개, 연결당 시간 중앙값·p95를 Step 3 전후로 비교. 차이 10% 이내면 대체 경로를 쓰지 않는다 | Step 3 |
| 3 | role 근거를 싣는 `Verdict` 필드 | `granted_by: GrantBasis { Rule(u32), Role(TrustRole) }`로 두고 `rule`은 파생값. 이름과 모양은 Step 4가 정한다 | Step 4 |
| 4 | ADR이 이름을 정하지 않은 fixture | `acl.check.path.json`, `acl.show.with_paths.json`, `file.entry` event는 `event.file.entry.json`(cli-v1에 event fixture 선례가 없어 Step 14가 자리를 정한다). `error.file.copy.partial.json`은 `error.<CODE>.<variant>` 관례와 다르지만 ADR 이름대로 둔다 | Step 10·14 |
| 5 | `serve --to` target의 파일 quota 키 | `[serve]` 두 키를 그대로 쓴다(`serve --to`가 `[serve]` 절을 읽는 지금 규칙) | Step 12 |
| 6 | 파일 op 모듈 자리와 arch 금지 | `crates/qsh-core/src/file/`(guard·host·copy). `qsh_transport`·`quinn` 금지 목록 편입 여부는 Step 9가 판단 | Step 9 |
| 7 | identity 파일 핀 대상 | `identity/device.key`(file keystore)와 `identity/device.pem` 둘 다 행으로 둔다 | Step 12 |
| 9 | 판정마다 읽기의 대체 경로가 fail-open이 되는 경계(ADR-0045 근거 절의 stat 선검사) | 확정: stat 선검사를 쓰게 되면 git의 racy-clean 규칙을 함께 둔다. 마지막으로 읽은 시각과 파일 mtime의 차가 2초 안이면 크기·시각·inode가 같아도 내용을 다시 읽는다. 거친 mtime 해상도에서도 같은 크기의 role 축소를 놓치지 않는다. 테스트 `trust_store_refresh_rereads_a_racily_clean_file`를 Step 3에 둔다 | Step 3 |
| 10 | 모르는 role 값: 시작과 reload | 확정: 시작 때는 `CONFIG_ERROR`로 기동 실패, 실행 중 reload에서는 마지막 정상 pin을 유지하고 role을 전부 멈춘다(ADR-0045 결정 4의 reload 실패와 같은 경로) | Step 2·4 |
| 11 | M15 동안 Windows `qsh serve`의 파일 op | 확정: `file.v1`을 광고하지 않고 네 op에 `UNSUPPORTED`로 답한다. M20이 연다 | Step 11 |
| 12 | `file_copy_echo_under_load`가 붉을 때 | 확정: `FILE_DATA`를 band 0보다 낮은 송신 우선순위로 두고 송신 깊이 상한을 줄이는 조정까지 허용한다. 그 너머는 ADR-0029 개정이다 | Step 14 |
| 8 | M15 부하 filterset | 테스트 이름 접두 `role_`, `trust_store_reload_`, `set_role_`, `file_`, `state_path_guard_`, `cp_`, `denied_file_`, `unredeemed_file_`, `interrupted_file_`. 지연 단언은 별도 식 | Step 8·16 |

## 8. 완료 절차

1. §3 DoD 전건을 실제 테스트와 CI run으로 확인한다. 체크박스는 근거가 초록일 때만 채운다.
2. 부하 반복 50/50과 지연 단언의 부하 없는 50/50을 기록한다(Step 8·16).
3. 구속 문서 태그를 대조한다(Step 16 (a)의 목록 전수).
4. README를 동기화한다.
5. `docs/design/testing.md`의 M15 반영(게이트 환경변수 표의 새 acceptance 행)을 확인한다.
6. `docs/ROADMAP.md` "현재 위치"와 M15 절을 갱신하고 마감 노트를 적는다.
7. §0.1 일곱, §0.2, §0.3의 상태를 승계한다.
8. 이 `PLAN.md`를 다음 계획(M16)으로 교체하고, 마감 노트에 이 계획의 마지막 커밋 해시를 적는다.

## 9. 열린 질문

각 항목 끝의 **결정** 문장은 main 세션이 Step 1 커밋(2026-10-14)에서 확정했다.

1. **(a)를 따로 닫고 M16을 먼저 열 것인가.** ROADMAP M15 크기 줄은 (a)와 (b)를 따로 닫아도 된다고 하고, M16 착수 조건은 "M15 (a) 착지"다. **결정:** Step 8이 ROADMAP M15 절에 (a) 착지 노트를 적는다. M16은 M15가 닫힌 뒤 연다. 다만 (b)가 Step 14의 PTY echo 판정처럼 ADR 대기로 멈추면, 그날 main 세션이 M16 (a)를 여는 것을 허용한다.
2. **ROADMAP M15 DoD에 안정성 줄을 더할 것인가.** M12에는 있었고 M13은 계획 규율로 넣었다. **결정:** 더한다. Step 1이 M12 문면에 지연 단언 예외 구절을 붙여 넣는다.
3. **README First run과 `p1-setup-stopwatch`.** ADR-0045 결과 절은 README First run을 고치라고 한다. **결정:** First run은 Step 8에서 role 기준(주소 없는 `trust add`·`pair invite`가 `full`이라 손으로 쓰는 `acl.toml` 행이 필요 없음)으로 고친다. m7·m9 대상은 SHA로 고정돼 있어 측정이 흔들리지 않는다. `p1-setup-stopwatch`는 그 문서의 "qsh 커밋 SHA" 칸이 실행 전에 채워지므로 문서를 고치지 않는다. 대신 §5.5 그 행에 "M15 Step 7 이후 트리는 ACL 단계가 `done`으로 끝나는 절차를 잰다"를 적는다(main 세션).
4. **`full` role 해제 직후 `role_full_without_acl_toml_…`의 `file.*` 행.** Step 4 시점에는 ①이 막고 Step 12에서 뒤집힌다. **결정:** 같은 테스트 표의 기대값을 Step 12가 고친다. 테스트 이름과 주인(Step 4)은 그대로다.
5. **`acl_check_equivalence.rs`의 `paths` 행 시점.** ADR은 enforcement(`Server::dispatch`)와의 대조를 요구하므로 op이 열리는 Step 12에 둔다. Step 10은 `acl check`·`acl show` 쪽 단위 대조만 둔다. **결정:** 그대로 한다.
6. **`CLAUDE.md`에 상태 경로 규칙을 더할 것인가.** ADR-0029는 `CLAUDE.md`를 문서 목록에 적지 않았지만, 이 성질은 "role이나 행으로 열 수 없다"는 보안 기본값이다. **결정:** Step 12가 "Security defaults"에 한 항목을 더한다. Step 4의 role 문장 개정(ADR-0045 결과 절)과는 별개 편집이다.
7. **태그.** M15 DoD에는 태그가 필요 없다. **결정:** 찍을지는 유지보수자가 정한다. 권고는 Step 15 뒤 태그 하나다. §1의 두 확인(macOS Keychain, `release.yml` provenance)과 `decode_file_frame` 사람 몫이 그 바이너리로 돌 수 있다.
