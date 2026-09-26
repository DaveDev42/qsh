# PLAN.md — M11: 이슈 후속과 ACL 가시성

P1의 첫 마일스톤인 M11의 실행 계획이다. 2026-09-26 사용자 지시("모두 승인. 전부 다 진행해.")로 P1이 열렸고, 이 문서가 자리표시자 `PLAN.md`(제목 "P1 계획 미정 (사용자 결정 대기)")를 전면 교체한다. 구속 근거는 다음과 같다. `docs/ROADMAP.md` §5의 M11 절(범위 (a)~(e), 명시적 out, 수용 기준, 크기, 결정 기록 Q1~Q5), 같은 문서 §5.1 시퀀싱 원칙과 §5.5 P1 사람 몫, 마일스톤 마감 공통 절차(같은 문서 §2), ADR-0012 결정 3, ADR-0017 결정 1·2·5, ADR-0019 결정 6·14와 결과 절 R6, ADR-0021 결정 2·4·7, ADR-0022 결정 5·6, ADR-0025 결정 1~6과 결과 절, ADR-0026 결정 1~8과 결과 절, ADR-0001 결과 절의 파서 격리 규율, `docs/CLI.md` §2.4·§2.5·§3.2·§6.11·§6.13·§6.15·§6.17, `docs/design/testing.md` L0·L2·L4·L6·L8, `docs/design/threat-model.md` §3·§4·§7·§10. 이 계획과 `docs/ROADMAP.md`의 편집은 main 세션 전용이다.

M11에는 사용자 승인을 기다리는 항목이 없다. 다섯 범위 모두 승인 ADR로 모양이 정해졌거나 새 결정 없이 끝낼 수 있는 것만 담았다. 제안 상태의 ADR-0023(supervised tunnel)과 ADR-0024(`qsh setup`)는 M12 몫이고 이 계획은 그 둘을 구현하지 않는다. 다만 M11이 만드는 것 가운데 둘을 M12가 가져다 쓴다. 재시작 고지 상수(Step 2)는 ADR-0024 결정 4가, `cause` 어휘(Step 5a)는 ADR-0023 결정 12가 인용한다. 두 초안은 이미 M11과 부딪히지 않게 적혀 있다. ADR-0023 결정 12는 값 개수 없이 "§6.13의 고정 어휘"를 인용하고, ADR-0024 결과 절은 `docs/CLI.md`의 `qsh setup` 절 번호를 `acl show` 절과의 착지 순서로 정한다고 적는다. 그래도 두 스텝은 M11 안에서 이름과 문면을 고정하고 뒤에 바꾸지 않는다.

인용 규율은 M10판과 같다. `docs/` 아래 문서는 줄 번호로 가리키지 않는다. 절 이름, DoD 문장, ADR 번호와 결정·결과 라벨, 테스트 이름, 커밋 해시, 이슈 번호가 앵커다. 코드 위치만 `path:line`을 쓰고 그때는 어느 트리에서 잰 값인지를 같은 문장에 적는다. 이 문서의 `path:line`은 모두 HEAD `21ab11d` 실측이다. 옛 계획의 스텝 번호는 새로 인용하지 않는다.

## 0. 착수 조건

### 0.1 P0에서 열린 채 넘어온 사람 몫 일곱

일곱 중 어느 것도 M11의 코드 스텝을 막지 않는다. 다만 일곱이 다 닫히기 전에는 P0 MVP 완료를 선언할 수 없다. 자리표시자 `PLAN.md` §0이 들고 있던 목록을 내용 그대로 옮긴다.

- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** 기준은 `docs/campaigns/m10-clean-vm.md`에 사전 고정. v0.3.0 Linux 세 회차가 PASS로 기록됐고(`69a6414`) macOS 둘이 남았다. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 선행: Apple 시크릿 여섯 등록과 서명·공증이 붙은 첫 태그. 판정은 같은 캠페인 §4.2. v0.3.0은 미서명 태그라 이 DoD를 판정하지 않는다(`21ab11d`). 소유: 사람(등록·회차).
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** 판정은 같은 캠페인 §5. 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** 기준은 `docs/campaigns/m7-stopwatch.md`. 예행 1회만 끝났다. M9 DoD 1의 비교 대상이라 그보다 먼저 온다. 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** 기준은 `docs/campaigns/m2-mobility.md`. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** `docs/design/protocol.md` §16의 상태가 아직 "초안 — 발효 전"이다. 발효 소커밋에 딸린 잔여 셋(CLOSE `0x1003` 이중 이름 처분, README Security posture 한 줄, DoD 4 문구)도 같이 온다. 저장소 밖 조직 액션이다. 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** 기준은 `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 소유: 사람.

M7 DoD 1과 M9 DoD 1은 README "First run" 절과 호스트 쪽 `qsh init --json`부터의 흐름을 잰다(`docs/campaigns/m7-stopwatch.md`의 측정 범위와 타이머 시작 행). 그래서 M11은 그 절의 문면과 플래그 없는 `qsh init`의 human·JSON 출력을 바꾸지 않는다(§2 규율).

### 0.2 M11이 새로 만드는 사람 몫 둘 (`docs/ROADMAP.md` §5.5)

둘 다 M11 DoD가 아니다. M11은 이 둘 없이 닫힌다. 두 항목은 Step 1이 붙이는 §5.5 표에 이미 행이 있고, 기록 자리도 그 표가 정한다.

- [ ] **`cause` 분포 관측 기록.** Step 5a가 착지한 바이너리를 현장에서 돌려 `qsh::reverse` `lost` 줄의 `cause` 값 분포(`idle_timeout` 대 `path_dead` 대 `peer_closed`)를 모은다. ADR-0021 결정 7이 구현 스텝의 선행 조건으로 적은 "현장에서 연결이 어느 타이머로 죽는지"에 대한 답이고, `docs/ROADMAP.md` M13 (k)의 착수 조건이다. 기록 자리는 §5.5 표의 "이슈 #4 코멘트 또는 캠페인 문서"다. 소유: 사람.
- [ ] **새 파서 fuzz 타깃의 누적 72 fuzz-hours.** Step 7이 더하는 `parse_openssh_key` 타깃에 M8 DoD 1과 같은 기준을 건다. 기록 자리는 `docs/campaigns/m8-fuzz.md`의 회차 표다. 소유: 사람.

### 0.3 착수 조건

없다. M11은 저장소 밖 자격에 묶이지 않는다. Step 1이 이 계획을 저장소에 들인 뒤 Step 2~9를 연다.

## 1. DoD 체크리스트 (ROADMAP M11)

- [ ] **DoD (a) — `cause` 어휘 분리.** 단위 테스트가 `classify_connection_error`의 세 갈래를 고정한다. `TimedOut`은 `idle_timeout`, `CLOSE_CODE_PATH_DEAD`를 실은 `ApplicationClosed`는 `path_dead`, 그 밖의 `ApplicationClosed`는 `peer_closed`다. 통합 테스트에서 target의 `lost`·`retry` 줄과 controller의 `lost` 줄이 `cause: "idle_timeout"`을 낸다(controller는 `retry` 줄을 내지 않는다. `ReconnectCause` 타입 doc). `run_target_lost_and_retry_lines_report_a_silent_path_as_path_dead`는 고치지 않고 초록이다. fixture·wire·`qsh.cli/v1` diff 0. 근거: Step 5a + Step 5b. 소유: 에이전트.
- [ ] **DoD (b) — `qsh acl show`와 재시작 고지 상수.** `acl.show`가 등록 완전성을 갖추고(`layer_2_every_schema_command_has_all_six_faces`, `every_implemented_operation_has_a_schema_or_a_documented_exclusion`), `acl show`의 실효 집합과 `acl check` 판정이 표 기반 정책마다 일치하며, 실효 집합이 독립 모델과도 일치하고, 정책 부재·파싱 실패와 항상-deny 성질이 따로 고정되고, 원격 wire 경로가 없다. 재시작 문구 상수를 두 doctor 진단과 `acl show`가 함께 쓰고, `acl show`의 human 출력과 두 doctor remedy가 그 상수를 바이트 단위로 담는다. `Policy::decide`의 비테스트 호출 지점이 셋이고 두 doc 산문이 셋을 적는다. 근거: Step 2 + Step 6. 소유: 에이전트.
- [ ] **DoD (c) — `qsh init --import-ssh-key`와 `authorized_keys` 미리보기.** 평문 Ed25519 OpenSSH 개인키 하나로 identity가 만들어지고 qsh fingerprint와 SSH fingerprint가 나란히 나온다. 거절 코드(`UNSUPPORTED`·`INVALID_ARGUMENT`)가 fixture로 고정되고, 거절은 identity 파일을 남기지 않으며, 기존 identity와 keystore는 바이트 동일이다. identity가 이미 있을 때의 message는 오늘 실행할 수 있는 복구 경로를 적는다. 가져오기와 미리보기 전후로 `trust.toml`·`acl.toml`이 바이트 동일이다. 미리보기의 자리표시자 행을 고치지 않고 붙여도 pin된 principal에 매칭되지 않는다. 입력 바이트는 message·`details`·로그 어디에도 실리지 않고 개인키 버퍼는 `Zeroizing`에 있다. 기존 `identity.init` fixture는 무변경이다. 새 fuzz 타깃이 fuzz-smoke에서 돌고 `cargo fuzz list`가 19개를 내며 개수 문장이 같은 커밋에서 바뀐다. README Known limitations에 공유 키 잔여 위험이 있다. `cargo deny check`와 `checked_in_man_pages_match_the_generator`가 초록이다. 근거: Step 7 + Step 8 + Step 9. 소유: 에이전트.
- [ ] **DoD (d) — doctor 진단 1종(ADR-0019 결과 절 R6).** 새 진단이 안정된 code와 실행 가능한 remedy로 테스트에 고정되고 `EXPECTED_DOCTOR_CODES`가 22종에서 23종이 된다. `docs/CLI.md` §6.11·§6.17의 계수와 `crates/qsh-core/src/doctor.rs` 모듈 doc·테스트 배열이 같은 커밋에서 바뀐다. 근거: Step 3. 소유: 에이전트.
- [ ] **DoD (e) — 두 별칭 절과 `stale_retention` 안내.** 두 별칭 절이 적는 동작을 먼저 테스트로 확인하고, 테스트 이름을 README 절 근처 주석과 커밋 본문에 남긴다. 근거: Step 4. 소유: 에이전트.
- [ ] **DoD 마감 — 마감 공통 절차 1·2.** 구속 문서 태그 대조와 README 동기화. 근거: Step 10. 소유: 에이전트.

## 2. 실행 단계 (PR 단위)

스텝 번호는 이 문서 안에서만 쓰는 참조다. 크기 내역은 각 스텝 옆에 적는다. Step 2~10의 합은 2.8~4.1ew이고, Step 1이 `docs/ROADMAP.md` M11 크기 줄을 같은 값으로 붙인다(내역: (a) 0.6~0.9, (b) 0.55~0.8, (c) 1.2~1.8, (d) 0.15~0.25, (e) 0.1~0.15, 마감 0.2). Step 1은 크기 내역 밖이다. 순서는 작고 서로 독립인 스텝을 앞에 둔다. Step 2·3·4·5a는 서로를 막지 않으며 Step 3만 Step 2의 상수를 쓴다. Step 5b는 5a에, Step 6은 Step 2에, Step 8은 Step 7에, Step 9는 Step 7·8에 기댄다.

규율은 앞 마일스톤 그대로이고 M11에서 몇 가지를 더한다.

- 각 스텝은 일곱 게이트(`cargo fmt --all --check`, clippy `-D warnings`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `RUSTDOCFLAGS=-D warnings cargo doc`, `cargo xtask arch`, `cargo deny check`)가 초록인 채로 착지한다. clippy와 test는 `ci.yml`에서 Windows 다리도 돈다. unix 전용 경로에만 쓰이는 새 항목은 기존 `#[cfg_attr(not(any(unix, test)), allow(dead_code))]` 선례를 따르고, 테스트만 쓰는 항목은 `#[cfg(test)]`에 둔다.
- 계약 문서 델타는 그 표면을 바꾼 스텝의 같은 커밋에 싣는다. `docs/CLI.md` 상태 헤더의 v0.14 항목은 CLI.md를 처음 고치는 스텝이 열고 뒤 스텝이 항목을 덧붙인다. clap 트리가 바뀌는 스텝은 같은 커밋에서 `cargo xtask man`을 돌려 `docs/man/` diff를 싣는다.
- fixture는 추가만 하고 기존 파일은 한 바이트도 고치지 않는다. 새 fixture마다 `crates/qsh-cli/tests/fixtures.rs`에 실제 바이너리로 그 결과를 재현하는 `golden_*` 생산 테스트를 같은 커밋에 둔다. 손으로 쓴 fixture 파일은 들이지 않는다.
- 새 오류는 `ErrorCode`의 기존 변형만 쓴다. `acl.toml`을 쓰는 코드 경로는 어느 스텝에도 생기지 않는다(ADR-0017 결정 1). 판정 로직은 `qsh-core`의 `Ops`에 두고 `qsh-cli`에는 clap 정의와 렌더러만 더한다. 새 op마다 `qsh-core`에 `impl Operation` marker를 두고 `main.rs` 디스패치가 `<Marker>::COMMAND`를 쓴다.
- 손대는 소스 파일이 800줄을 넘으면 인라인 테스트를 같은 커밋에서 형제 `tests.rs`로 옮긴다. 새 모듈이 처음부터 800줄을 넘을 것이 분명하면 처음부터 디렉터리 모듈과 `tests.rs`로 만든다.
- M11은 README "First run" 절과 플래그 없는 `qsh init`의 human·JSON 출력을 바꾸지 않는다(§0.1). 기존 `identity.init.created.json`·`identity.init.existing.json` golden이 초록인 것이 그 증거다.
- 테스트 스위트는 `sleep()`을 쓰지 않는다(`docs/design/testing.md` L2). 벽시계를 실제로 기다리는 테스트는 이벤트 대기와 `timeout`으로 쓰고 `QSH_ACCEPTANCE_SLOW`로 가른다.

### Step 1 — M11 계획 교체와 ROADMAP §5 부착 (main 세션, 크기 내역 밖)

근거 ADR: ADR-0026 결과 절(다시 여는 조건 "P1 착수"). 선행: 없음. M11의 첫 커밋이다. ⑧만 별도 커밋이다.

**(a) 범위:**

① `PLAN.md`를 이 문서로 전면 교체한다. 자리표시자는 `docs/history/`로 옮기지 않는다. 자리표시자는 마일스톤 계획이 아니었고, 그 본문(§0 일곱과 §1 P1 귀속 목록)은 이 문서 §0.1과 `docs/ROADMAP.md` §5가 전부 흡수하며, 원문은 `21ab11d`의 `PLAN.md`로 언제든 꺼낼 수 있다. 이 사유를 커밋 본문에 한 문장으로 적는다.

② `docs/ROADMAP.md`의 머리와 기존 절을 고친다. §5 "P1 마일스톤"(§5.1~§5.5, M11~M19)을 §4 뒤에 붙인다. 문서 머리의 "현재 위치" 줄을 M11로 바꾸고, 머리말 첫 문장을 P0(M0~M10)과 P1(M11~M19) 두 단계의 기록이라는 뜻으로 바꾼다. 머리의 총 크기 줄 뒤에 P1 총 크기 한 문장(내역은 §5.2)을 더한다. P0 완료 선언 문단의 마지막 문장 "다음은 P1이고 그 계획은 사용자가 연다"를 "P1은 2026-09-26 사용자 결정으로 열었고 P0 완료 선언과 독립적으로 진행한다(§5)"로 바꾼다. §3 유예 가드레일 표의 P1 행 가드레일 칸 끝에 귀속 표기를 붙인다(TCP/TLS fallback → M14, File copy → M15, Windows → P1 client M19 / P2 host, Forward-route live carrier와 `-R` 자동 재발행 → M12, Cert rotation UX → M16). ADR-0026 결과 절이 요구한 SSH 키 가져오기 가드레일 행은 P1 착수로 범위 항목이 되므로 행 대신 "SSH 키 가져오기 → M11 (c)" 한 줄을 붙인다. §4 리스크 4의 마지막 문장을 "H1·H1b는 M13, H2·H4·H5와 세션 거처 결정은 M18이 가진다(§5)"로 바꾼다. 자리표시자 §1의 "`ControlLink`/`DataLink` enum → trait 전환" 문구는 ADR-0005의 실제 부채 서술과 맞지 않으므로 §5에 옮겨 적지 않는다.

③ 붙이는 M11 절을 이 계획에 맞춘다. 결정 기록의 표기는 "2026-09-27, main 세션이 사용자 전면 자율 지시에 따라 정함"이다(§8 #4). 범위 (a)의 통합 테스트 문장은 이 계획의 방식으로 바꾼다. `#[cfg(test)]` 주입으로 `PathWatchConfig`의 `min_dead_after`를 idle 45초보다 크게 두고, 약 50초짜리 crate 내부 테스트를 `QSH_ACCEPTANCE_SLOW` 아래 `ci.yml` acceptance job에서 돌리며, 대안은 `load.yml`이다(§8 #6). 수용 기준 (a)의 "target과 controller 양쪽의 `lost`·`retry` 줄"을 "target의 `lost`·`retry` 줄과 controller의 `lost` 줄"로 고친다. 수용 기준 (b)의 "세 출력이 그 상수와 바이트 단위로 같다"를 "`acl show`의 human 출력과 두 doctor remedy가 그 상수를 바이트 단위로 담는다"로 고친다(§8 #8). 수용 기준 (c)와 Q5의 "remedy가 rotation을 가리킨다"를 "message가 오늘 되는 복구 경로(`identity/`를 치우고 다시 가져온 뒤 peer가 다시 pin)를 적고, 제자리 교체는 M16 (d)의 rotation으로 남는다"로 고친다. 오류 envelope에는 remedy 필드가 없다(`docs/CLI.md` §3.2). 수용 기준 (c)의 fuzz 개수 문장은 §8 #5대로 고친다. 크기 줄을 2.7~3.9ew에서 2.8~4.1ew로, 내역 (a)를 0.6~0.9로, (b)를 0.55~0.8로 고치고 §5.2 표의 M11 행도 같은 값으로 고친다. P1 합의 "약 29~48"은 반올림 안이라 그대로 둔다.

④ `CLAUDE.md` 문서 지도의 `docs/ROADMAP.md` 줄 "milestones M0–M10 with scope and acceptance criteria"를 "milestones M0–M10 (P0) and M11–M19 (P1) with scope and acceptance criteria"로 바꾼다. `PLAN.md` 줄은 이미 "current milestone, or a placeholder"라 그대로다.

⑤ `docs/adr/README.md` 색인의 "다음 새 번호는 0027이다." 뒤에 "P1 계획(`docs/ROADMAP.md` §5)이 0027~0035를 예약했다." 한 문장과 번호·제목 목록을 더한다.

⑥ `docs/adr/0026-ssh-key-import-scope.md` 결과 절 끝에 날짜가 붙은 추기 한 문단을 더한다. 내용은 "2026-09-26 P1 착수로 이 ADR의 다시 여는 조건이 충족됐다. 결정 2~8을 `docs/ROADMAP.md` M11 (c)에서 구현한다. 구현은 `qsh.cli/v1`에 optional 필드만 더하는 additive 변경이다. 결정 1이 막은 것은 P0 출고 범위였다."이다. 결정 본문과 결과 절의 기존 문장은 고치지 않는다(ADR-0011 결과 절 2026-09-25 추기가 선례다).

⑦ README Roadmap 표에 P1 행 하나(M11 진행 중)를 더한다.

⑧ 선택: ADR-0023·0024 초안을 `docs/adr/`에 제안 상태로 들이는 별도 `docs(adr)` 커밋. 두 초안의 M11 교차 참조는 이미 맞다(머리말 둘째 문단). 들이면 ⑤의 "번호만 예약돼 있고 파일은 아직 없다" 문장을 그 커밋이 고친다.

`docs/ROADMAP.md` 초안 §C의 선택 항목(`crates/qsh-proto/proto/qsh/wire/v1.proto`의 `SessionSignal` 주석과 `crates/qsh-core/src/tunnel/local.rs` 모듈 doc의 "P1" 주석 교체)은 M11에서 하지 않는다(§3).

**(b) 테스트·게이트:** 문서 변경이라 새 게이트가 없다. README 축자 게이트(`readme_quotes_the_controller_unreachable_diagnostic_verbatim`, `readme_quotes_the_acl_startup_diagnostic_wording_verbatim`, `readme_quotes_the_dynamic_forward_acl_note_verbatim`)가 걸린 자리는 건드리지 않는다. 일곱 게이트 초록.

**(c) 완료 판정:** `PLAN.md` 첫 줄이 이 문서의 제목이다. `docs/ROADMAP.md`에 §5와 M11 절이 있고 "현재 위치"가 M11을 가리킨다. 다음 grep이 기대대로 나온다. `grep -n 'enum → trait' docs/ROADMAP.md` 0건(`PLAN.md`에서는 ②의 설명과 이 판정문 두 곳에만 나온다), `grep -n '그 계획은 사용자가 연다' docs/ROADMAP.md` 0건, `grep -n '사용자 확정 대상' docs/ROADMAP.md` 0건(M12 결정 기록은 "초안, M12를 열 때 확정"), `grep -c 'M11–M19' CLAUDE.md` 1, `grep -n 'SSH 키 가져오기 → M11' docs/ROADMAP.md` 1건. `docs/adr/README.md`에 0027~0035 예약 문단이, ADR-0026 결과 절에 2026-09-26 추기가 있다.

### Step 2 — 재시작 고지 상수 추출 (0.05ew)

근거 ADR: ADR-0017 결정 2, ADR-0025 결정 6. 선행: 없음.

**(a) 범위:** `crates/qsh-core/src/doctor.rs`의 `ACL_PRINCIPAL_UNMATCHED.remedy`(`:446`)와 `ACL_CA_AUTH_PATH_MISSING.remedy`(`:464`)가 각자 품은 꼬리를 공개 상수 하나로 뽑는다. 상수 문면은 "then " 없이 "restart serve/listen — acl.toml is only read once at process start."다. `acl show`와 M12의 `qsh setup`(ADR-0024 결정 4)이 이 문장을 단독 줄로 인용하기 때문이다. `remedy` 필드가 `&'static str`이므로 문자열 리터럴을 내는 crate 내부 매크로 `acl_restart_notice!()`를 두고, 상수 `ACL_RESTART_NOTICE: &str = acl_restart_notice!()`와 두 remedy `concat!("Add a matching [[acl]] row (ADR-0017), then ", acl_restart_notice!())` 꼴을 같은 매크로로 조립한다. 두 remedy는 오늘과 바이트 단위로 같다. 상수 자리는 `crate::acl`이다(§4.1 #1). 매크로는 `#[macro_export]` 없이 crate 안에서만 쓴다. `docs/CLI.md` §6.17이 `acl_ca_auth_path_missing`의 remedy를 축자 인용하는데 바이트가 같으니 그 인용도 그대로다. 손대는 doc comment 안의 ADR-0017 줄 번호 인용(`결정 2 (:20-26)` 꼴)은 결정 번호 앵커로 바꾼다.

**(b) 테스트·게이트:** 신규 `acl_restart_notice_is_the_verbatim_tail_of_both_acl_diagnostic_remedies`(`crates/qsh-core/src/doctor.rs` 테스트 모듈, L6 성격의 문면 고정). 두 remedy 문자열이 `"… then "`과 상수의 이어붙임과 같고, 상수 앞의 머리말이 오늘 문면과 같음을 단언한다. `cli_md_names_every_frozen_doctor_code`와 `cli_md_prose_doctor_code_count_matches_expected_len`은 무변경으로 초록.

**(c) 완료 판정:** `git diff`가 두 remedy의 조립 방식만 바꾸고 `docs/`는 무변경이다. `grep -rn 'only read once at process start' crates/`의 리터럴 등장이 매크로 정의 한 곳뿐이다.

### Step 3 — doctor 진단 `acl_forward_socks_ineffective` (0.15~0.25ew)

근거 ADR: ADR-0019 결정 6·14와 결과 절 R6, ADR-0017 결정 2(재시작 고지). 선행: Step 2.

**(a) 범위:** `forward.socks`는 어떤 op도 인가하지 않는다(ADR-0019 결정 6). 그래서 `allow`에 `forward.socks`를 적어 `-D`를 허락하려던 `[[acl]]` 행은 아무 효과가 없다(결과 절 R6). 이 행을 짚는 진단 하나를 더한다. 코드 초안은 `acl_forward_socks_ineffective`, 등급 초안은 `warn`이다(§4.1 #2).

탐지 자리는 doctor 쪽이 아니라 인덱스 쪽이다. `Ops::doctor_acl_findings`(`crates/qsh-core/src/ops/doctor.rs:291`)는 `load_or_deny_with_index`에서 `Arc<dyn Authorizer>`와 `PinnedPrincipalIndex`만 받고 `Policy.rules`는 볼 수 없다. 그 함수의 doc은 네 code를 한 번의 `acl.toml` 읽기로 낸다고 약속한다. 그래서 `crates/qsh-core/src/acl/load.rs`의 `PinnedPrincipalIndex::from_policy`(`:398`)가 `Policy`가 지워지기 전에 이 판정도 함께 뽑게 한다. 새 필드는 짚을 행의 (배열 index, `auth_path`) 목록이다. 판정 단위는 (principal 문자열, `auth_path`) 쌍이다. 어떤 행의 `allow`가 `forward.socks`를 exact로 적었고, 같은 principal 문자열과 같은 `auth_path`(생략이면 `pin`)를 가진 행 어디에도 `ActionPattern::matches(Action::ForwardLocal)`이 참인 패턴이 없으면 그 행을 짚는다. `forward.*`만 적은 행은 이미 `forward.local`을 덮으므로 짚지 않는다. 판정 단위가 문자열 일치라서 같은 peer를 `device:<name>` 행과 `fp:sha256:…` 행으로 나눠 적은 정책은 짚힌다. 이 한계를 finding의 `message`와 `docs/CLI.md` §6.17 표 행에 적는다. 정책이 없거나 파싱에 실패하면 인덱스가 비므로 이 진단은 침묵한다(그 상태는 기존 진단이 알린다). `load.rs`는 802줄이지만 테스트가 이미 `acl/load/tests.rs`에 있으므로 800줄 규칙에 새로 걸리지 않는다.

`detail`은 행의 배열 index와 `auth_path`만 싣고 principal 문자열은 싣지 않는다. `acl.toml`에서 읽은 principal 값을 되풀이하지 않는 `acl/load.rs`의 F1 규율을 따른다. `remedy`는 "`forward.local`을 더하라"는 머리말 뒤에 Step 2의 매크로로 끝난다(§4.1 #2 문면). `-D`가 CONNECT마다 `forward.local`로 인가된다는 사실은 ADR-0019 결정 14의 `DYNAMIC_FORWARD_ACL_NOTE`와 모순되지 않게 적는다. `DiagnosticId` 변형 하나와 `EXPECTED_DOCTOR_CODES` 항목 하나가 는다.

같은 커밋에서 계수 문장을 모두 고친다. `docs/CLI.md` §6.11의 "진단 코드 22종", §6.17의 "22종 진단 코드 (재사용 5종·신설 17종 …)"와 표, `crates/qsh-core/src/doctor.rs` 모듈 doc의 "22 variants", 같은 파일 테스트의 `const ALL: [DiagnosticId; 22]`와 "exactly those 22 codes" doc을 23과 신설 18종으로 고친다. `docs/CLI.md` 상태 헤더 v0.11 항목의 "doctor 22종"은 그 시점의 기록이라 두고, v0.14 항목에 23종을 적는다.

**(b) 테스트·게이트:** 인덱스 단위 테스트(`crates/qsh-core/src/acl/load/tests.rs`) 하나. `pinned_principal_index_lists_forward_socks_rows_not_covered_by_forward_local_for_the_same_principal_and_auth_path`. 표에 다음 경우를 넣는다. 같은 행의 `forward.local`, 같은 행의 `forward.*`, 같은 (principal, `auth_path`)의 다른 행이 주는 `forward.local`, `pin` 행의 `forward.socks`와 `ca` 행의 `forward.local`(서로 덮지 않음), `device:<name>` 행의 `forward.socks`와 같은 peer의 `fp:sha256:` 행의 `forward.local`(문자열 단위라 짚힘).

doctor 테스트(`crates/qsh-core/src/ops/doctor/tests.rs`) 넷. `acl_forward_socks_ineffective_flags_a_row_whose_allow_names_forward_socks_without_forward_local`, `acl_forward_socks_ineffective_is_silent_when_the_same_row_also_covers_forward_local`, `acl_forward_socks_ineffective_is_silent_when_another_row_for_the_same_principal_grants_forward_local`, `acl_forward_socks_ineffective_remedy_ends_with_the_acl_restart_notice`. 첫 테스트는 `detail`에 principal 문자열이 없음도 단언한다. 기존 계수 게이트 `expected_doctor_codes_matches_every_diagnostic_id_variant_exactly`, `cli_md_prose_doctor_code_count_matches_expected_len`, `cli_md_names_every_frozen_doctor_code`가 23으로 초록.

**(c) 완료 판정:** 위 테스트 초록. `grep -n '22종' docs/CLI.md`의 결과가 상태 헤더 v0.11 항목 한 줄뿐이다. `qsh doctor --json`이 `allow = ["forward.socks"]`만 가진 행에 대해 새 code를 한 번 낸다.

### Step 4 — 두 별칭 동작의 테스트와 README 절, `stale_retention` 안내 (0.1~0.15ew)

근거 ADR: ADR-0017 결정 3·5(pin 이름이 inbound principal이 되는 맥락). 정식 해법은 `docs/ROADMAP.md` M16 (a)이고 이 스텝은 현재 동작을 문서로 드러내기만 한다. 선행: 없음.

**(a) 범위:** README 절을 쓰기 전에 그 절이 적을 성질을 테스트로 먼저 고정한다. `SharedTrustStore::lookup_pin`(`crates/qsh-core/src/trust/mod.rs:841`)은 handshake마다 `refresh()`로 파일을 다시 읽고 fingerprint가 같은 첫 항목을 돌려준다. 그 결과 셋이 따라 나온다. inbound principal은 `trust.toml`에서 먼저 나오는 이름이다. 두 번째 이름으로 쓴 `[[acl]]` 행은 inbound에서 매칭되지 않는다. 파일 순서를 바꾸면 재시작 없이 principal이 바뀐다. doctor `acl_principal_unmatched`의 계수 동작도 확인한다. 두 이름이 한 fingerprint를 공유하고 두 번째 이름에만 행이 있으면, 탐지기는 이름마다 따로 보고 fingerprint 행도 확인하므로 첫 이름을 짚고 두 번째 이름은 침묵한다. README "Reverse connections" 절 근처에 "One machine, two aliases" 소절을 더한다. inbound `qsh serve` 주소 별칭과 `qsh serve --to`로 등록되는 이름의 배치를 설명하고 "ACL 행은 먼저 나오는 이름으로 쓰고 두 번째 이름은 outbound dial 별칭으로만 쓴다"를 안내하며 이 배치를 정식으로 푸는 자리가 M16 (a)라고 적는다. 같은 커밋에서 더 긴 정전을 `[listen].stale_retention`으로 덮는 운영 안내를 더한다. `ListenConfig::stale_retention`(`crates/qsh-core/src/config.rs`)의 기본값 120초와 `backoff_max_ms × 3`보다 커야 하는 하한(`docs/design/protocol.md` §11-4)을 함께 적는다. 주소 상한 문장은 `docs/CLI.md` §6.13에 이미 있으므로 README는 그 절을 가리키기만 한다. "First run" 절은 건드리지 않는다.

**(b) 테스트·게이트:** 단위(L1) 둘. `lookup_pin_returns_the_first_name_pinned_for_a_shared_fingerprint`, `lookup_pin_follows_a_reordered_trust_toml_without_a_restart`(`crates/qsh-core/src/trust/tests.rs`). e2e(L6) 하나. 신규 `crates/qsh-cli/tests/trust_alias_order.rs`가 실제 `qsh serve` 하나를 띄워 두 번째 별칭에만 행이 있을 때 inbound 요청이 `PERMISSION_DENIED`이고 audit principal이 첫 이름이며, `trust.toml` 순서를 바꾸면 재시작 없이 같은 요청이 허용됨을 단언한다. 순서 변경 뒤의 대기는 이벤트 대기와 `timeout`으로 쓴다. doctor 테스트 하나. `acl_principal_unmatched_flags_the_first_alias_when_only_the_second_has_a_row`(`crates/qsh-core/src/ops/doctor/tests.rs`). 네 테스트 이름을 README 절 옆 HTML 주석과 커밋 본문에 적는다.

**(c) 완료 판정:** 네 테스트 초록. README에 두 소절이 있고 그 문면이 테스트가 고정한 성질과 어긋나지 않는다. 테스트가 README 문안과 다른 동작을 보이면 README 문안을 고치고, 동작 자체는 이 스텝에서 바꾸지 않는다.

### Step 5a — `cause` 어휘 분리: 값·분류·문서 (0.2~0.3ew)

근거 ADR: ADR-0021 결정 7(이 스텝이 그 선행 조건이다), ADR-0022 결정 5·6. 선행: 없음. 혼자 초록으로 착지하고 DoD (a)의 단위 절반을 닫는다.

**(a) 범위:** `ReconnectCause`(`crates/qsh-core/src/reverse/mod.rs`)에 변형 `IdleTimeout`을 더하고 `as_str`는 `"idle_timeout"`을 낸다. `classify_connection_error`에서 quinn `ConnectionError::TimedOut`만 `IdleTimeout`으로 옮긴다. `CLOSE_CODE_PATH_DEAD`(`0x1004`)를 실은 `ApplicationClosed`와 자기 쪽 `PathWatch` 판정은 `path_dead`에 남는다. 그 밖의 `ApplicationClosed`는 `peer_closed`, 나머지는 `local` 그대로다. `classify_connection_error`는 unix 전용이 아닌 경로(`reverse/listen/registration.rs`)에서도 불리므로 새 변형에 `cfg_attr` 가드가 필요 없다. 변형 전체를 담는 `ReconnectCause::ALL`은 문서 대조 테스트만 쓰므로 `#[cfg(test)]`로 둔다. 비테스트 코드로 두면 Windows lib 빌드의 dead_code 경고로 clippy가 붉다.

doc을 같은 커밋에서 고친다. 타입 doc의 "Exactly these eight"를 아홉으로, "`docs/CLI.md` §6.13 bullet at :952" 줄 번호 인용을 절 앵커로 바꾼다. `PathDead` 변형 doc의 "or the QUIC idle timeout fired"를 지운다. 함수 doc의 "fixed eight-value vocabulary"와 `TimedOut`을 `path_dead`로 보내는 근거 문장을 새 분류로 고친다. `as_str` doc의 "emitted on the wire"는 실제로는 stderr 진단 줄이므로 그렇게 고친다. `docs/CLI.md` §6.13의 "고정 8값 — `resolve`/…/`local`" 괄호를 "고정 9값"으로 바꾸고 `idle_timeout`과 그 정의 한 구절("QUIC idle timeout 만료. 상대가 보낸 path-dead close나 자기 쪽 경로 감시 판정과 구별된다")을 붙인다. `qsh::reverse` 줄은 계약이 아니므로(ADR-0022 결정 5) `qsh.cli/v1`·fixture·wire는 바뀌지 않는다. 값은 static string이라 ADR-0022 결정 6의 구조 전용 규율도 그대로다.

기존 두 단위 테스트를 고친다. `classify_target_connection_loss_maps_a_connection_error_via_the_shared_judgment`(`crates/qsh-core/src/reverse/target/tests.rs:727`)와 `classify_client_error_maps_the_documented_vocabulary`(`crates/qsh-core/src/reverse/listen/registration.rs:921`)는 `TimedOut → path_dead`를 단언한다. 정의가 바뀐 곳이라 같은 커밋에서 `idle_timeout`으로 고치고 이름은 그대로 둔다. `registration.rs`는 957줄이고 인라인 `mod tests`(`:914`)가 있으므로 같은 커밋에서 그 테스트 모듈을 `crates/qsh-core/src/reverse/listen/registration/tests.rs`로 옮긴다. `xtask/src/arch.rs`의 경로 금지 목록에 이 경로는 없다.

**(b) 테스트·게이트:** 단위(L2 성격) 둘. `reverse/mod.rs`에 새 테스트 모듈을 두고 `classify_connection_error_separates_idle_timeout_from_path_dead_and_peer_closed`와 `reconnect_cause_vocabulary_matches_cli_md_section_6_13`(`ReconnectCause::ALL`의 문자열 집합과 §6.13 괄호의 값 목록이 양방향으로 같음)을 더한다. 위의 고친 두 테스트 초록. `run_target_lost_and_retry_lines_report_a_silent_path_as_path_dead`(`crates/qsh-testkit/tests/reverse_lost_cause_and_since_registered_ms.rs`)는 손대지 않고 초록이다. 이 테스트는 PathWatch가 켜진 실제 경로에서는 여전히 `path_dead`가 먼저 난다는 증거다. Windows clippy·test 다리 초록.

**(c) 완료 판정:** 위 테스트 전부 초록. `git diff --stat -- crates/qsh-cli/tests/fixtures crates/qsh-proto/proto`가 비어 있다. mutation 하나(`TimedOut`을 다시 `PathDead`로 돌림)가 새 단위 테스트와 고친 두 테스트를 붉힌다. `grep -n '고정 8값' docs/CLI.md`가 0건이다.

### Step 5b — `idle_timeout` 통합 테스트와 CI 배선 (0.4~0.6ew)

근거 ADR: ADR-0021 결정 2(idle 45초 고정)·결정 4(`[recovery]` 미개방), ADR-0022 결정 5. 선행: Step 5a.

**(a) 범위:** 통합 테스트에는 제약이 셋 있다. 역방향 두 자리(`crates/qsh-core/src/reverse/target/mod.rs:423`, `crates/qsh-core/src/reverse/listen/registration.rs:400`)가 `PathWatchConfig::default()`를 박고 있어 경로가 조용해지면 약 1초 안에 `path_dead`로 판정한다. idle timeout은 45초 고정이고(ADR-0021 결정 2) `qsh-transport`의 `transport_config()`(`crates/qsh-transport/src/endpoint.rs:244`)는 private이라 짧은 idle을 주입할 seam이 없다. target과 controller를 한 프로세스에서 끝까지 돌리는 하네스는 `qsh-testkit::reverse::ReverseHarness`뿐이고 `qsh-core` 안에는 없다. `qsh-testkit`은 `qsh-core`에 의존하므로 dev 의존으로 끌어오면 `qsh-core`가 두 벌 링크되어 crate 내부 타입과 `cfg(test)` 주입이 그쪽에 닿지 않는다.

그래서 이렇게 한다. 두 자리에 `#[cfg(test)]` 전용 주입을 더해 `PathWatchConfig`를 바꿔 넣는다. 주입값은 watch를 끄는 것이 아니라 `min_dead_after`를 60초 이상으로 올린 설정이다. 두 자리의 `watch.dead()`는 연결이 어떤 이유로든 닫히면 깨어나고, 그 arm이 `close_reason()`을 먼저 읽어 `classify_connection_error`로 분류한다(`target/mod.rs`의 `pre_close_reason`, `registration.rs`의 같은 arm). watch를 제거하면 이 경로가 사라지므로 판정 하한만 idle 45초 뒤로 밀어 quinn의 `TimedOut`이 실제 방출 경로를 타게 한다. `cfg(test)` 코드는 바이너리에 들어가지 않으므로 ADR-0021 결정 4의 `[recovery]` config 개방이 아니다. 주입 지점의 doc에 그렇게 적는다. cargo feature로 여는 방식은 쓰지 않는다. 워크스페이스 빌드의 feature 통합으로 바이너리에 들어갈 수 있기 때문이다.

crate 내부 하네스를 새로 짓는다. 자리는 `#[cfg(all(test, unix))]`로 가린 `crates/qsh-core/src/reverse/test_harness.rs`다. 신원 둘, trust evaluator, `reverse::target::run_reverse_observed`(`target/mod.rs:161`), `reverse::listen`의 `run`(`listen.rs:843`), 끊기 스위치 하나를 가진 작은 UDP 중계를 묶는다. 줄 관찰은 `run_reverse_observed`의 관찰 경로와 tracing 캡처를 쓴다. 두 통합 테스트는 `#[cfg(unix)]`로 두고(dial 경로가 unix 전용이다. `run_reverse_is_unsupported_on_non_unix`) `QSH_ACCEPTANCE_SLOW`가 없으면 skip 줄을 찍고 끝난다. 45초 대기는 `sleep()` 없이 이벤트 대기와 `timeout`으로 쓴다.

CI와 문서를 같은 커밋에서 고친다. `.github/workflows/ci.yml` acceptance job에 `reverse_blackout` 스텝과 같은 모양으로 `cargo nextest run -p qsh-core --lib -E 'test(/quinn_idle_timeout_as_idle_timeout/)'`를 `QSH_ACCEPTANCE_SLOW: 1` 아래 한 스텝으로 더한다(§4.1 #3). `CLAUDE.md` Commands 절의 acceptance job 테스트 목록 문장에 이 둘을 더한다. `docs/design/testing.md`의 `sleep()` 금지 문단이 `reverse_blackout`을 유일한 의도적 벽시계 예외로 적고 있으므로 이 둘을 같은 예외로 더하고, L4에 두 테스트와 그 게이트를 적는다. 어느 방식을 골랐는지는 커밋 본문에 남긴다(`docs/ROADMAP.md` M11 범위 (a)의 요구).

**(b) 테스트·게이트:** 통합(L4) 둘. `run_target_lost_and_retry_lines_report_a_quinn_idle_timeout_as_idle_timeout`(`crates/qsh-core/src/reverse/target/tests.rs`, target의 `lost`·`retry`)과 `controller_lost_line_reports_a_quinn_idle_timeout_as_idle_timeout`(`crates/qsh-core/src/reverse/listen/tests.rs`, controller의 `lost`). 둘 다 중계를 끊은 뒤 약 45초 안에 `path_dead` 줄이 나지 않았음도 단언한다. Step 5a의 테스트와 `run_target_lost_and_retry_lines_report_a_silent_path_as_path_dead` 초록. Windows clippy·test 다리 초록.

**(c) 완료 판정:** 두 통합 테스트가 `QSH_ACCEPTANCE_SLOW=1` 아래 CI acceptance job에서 한 번 이상 초록이다. mutation 하나(`TimedOut`을 다시 `PathDead`로 돌림)가 두 통합 테스트를 붉힌다. `git diff --stat -- crates/qsh-cli/tests/fixtures crates/qsh-proto/proto`가 비어 있다. `grep -n 'quinn_idle_timeout' CLAUDE.md .github/workflows/ci.yml`이 각 1건 이상이다.

### Step 6 — `qsh acl show` (0.5~0.75ew)

근거 ADR: ADR-0025 결정 1~6과 결과 절, ADR-0017 결정 1·2. 선행: Step 2.

**(a) 범위:** 인가 불요 local op `acl.show`를 신설한다(ADR-0025 결정 4).

계약 타입은 `crates/qsh-proto/src/types/acl.rs`의 `AclCheckReq`·`AclCheckData` 옆에 둔다. 요청 `AclShowReq { principal: String, auth_path: Option<String> }`의 `auth_path`는 `AclCheckReq.auth_path`(`crates/qsh-proto/src/types/acl.rs:16`)처럼 열린 문자열이다. 데이터 `AclShowData`는 구조 필드만 싣는다. 요청한 `principal`, 평가에 쓴 `auth_path`, 기본값으로 채웠는지를 뜻하는 `auth_path_defaulted: bool`(ADR-0025 결정 5), 정책 상태 `policy`(`AclPolicyRef` 재사용, `loaded`·`path`·`rules`), 매칭 행 목록 `matching_rules`(행마다 `index`, 적힌 그대로의 `allow` 패턴, 행의 `auth_path`, 행의 `scope`), 실효 action 집합 `effective_actions`다. 소유된 리소스에서는 이 집합이 상한이라는 고지(결정 2)와 재시작 고지(결정 6)는 산문이라 JSON에 싣지 않는다. 산문을 JSON에 실으면 append-only fixture가 그 문면을 `qsh.cli/v1`로 얼리고, `ACL_RESTART_NOTICE`는 doctor remedy 둘과 M12의 `qsh setup`이 공유하므로 영향이 네 표면으로 번진다. ADR-0025 결정 2가 `--json`에 요구한 것은 매칭 행과 실효 집합 둘이다. 두 고지는 human 렌더러가 상수에서 찍고, 기계 소비자를 위해서는 `docs/CLI.md` §6.19가 같은 사실을 계약 문장으로 적는다(§4.1 #9, §8 #8).

판정은 `crates/qsh-core/src/acl/policy.rs`에 둔다. `Policy::effective_actions(principal, auth_path)`가 `Action::ALL` 11종마다 `self.decide`를 소유자 없는 리소스로 불러 allow만 모은다(결정 3). 이것이 `Policy::decide`의 세 번째 호출 지점이다. `Policy::matching_rules(principal, auth_path)`는 평가 순서 ②(principal 정확 일치와 `auth_path` 일치)와 ③(action 패턴 일치)을 통과하는 행을 뽑는다. ②·③은 `decide` 본문에서 private helper로 빼내 `decide`와 `matching_rules`가 같은 helper를 부르게 하고, 두 번째 구현을 쓰지 않는다. `decide`의 동작은 바뀌지 않으며 기존 `acl/policy/tests.rs`와 `acl_check_equivalence.rs`가 그것을 지킨다. 두 새 메서드와 `decide`는 모두 `pub(crate)`다. `crates/qsh-core/src/ops/acl.rs`에 `AclShowOp`(`impl Operation`, `COMMAND = "acl.show"`)과 `Ops::acl_show`를 두고, `ops/mod.rs`와 `lib.rs`가 재수출하며, `crates/qsh-cli/src/main.rs` 디스패치가 `AclShowOp::COMMAND`를 쓴다. principal 모양이 틀리거나 `--auth-path`가 `pin`·`ca`가 아니면 `acl.check`와 같이 `INVALID_ARGUMENT`다. 정책이 없거나 파싱에 실패하면 실효 집합은 공집합이고 `policy.loaded`가 `false`다(ADR-0025 결과 절). `acl.toml`을 권한 때문에 읽지 못하면 `PolicySource::load_path`(`crates/qsh-core/src/acl/load.rs:115`)가 읽기 오류를 `PolicyLoad::Invalid`로 돌려주므로 같은 "정책 없음"이 된다. 이때 규칙 내용은 한 줄도 나오지 않으므로 ADR-0025 결과 절이 말한 경계는 유지된다. 이 동작을 테스트로 고정하고 §6.19에 적는다. CLI는 `AclCmd`(`crates/qsh-cli/src/cli.rs:765`)에 `Show(AclShowArgs)` 하나, 렌더러 `print_acl_show`를 `print_acl_check` 옆에 둔다. `--resource`와 `--owner` 축은 두지 않는다(결정 2).

계약 델타는 같은 커밋에 싣는다. `docs/CLI.md` §2.4 op 목록에 `acl.show`, §2.5 마지막 행에 `acl.check` 옆으로 `acl.show`, 새 절 §6.19 "`qsh acl show`"를 더한다. 상태 헤더 v0.14 항목은 규율대로 열거나 덧붙인다. fixture `cli-v1/acl.show.json`과 `cli-v1/acl.show.no_policy.json`을 추가하고 `REQUIRED_FIXTURES`에 등재하며, 생산 테스트 `golden_acl_show_fixtures`(자기 샌드박스)를 `crates/qsh-cli/tests/fixtures.rs`에 둔다. `policy.path`는 기존 `normalize`의 `"path"` arm이 가린다. 새 데이터 타입에는 `path`·`name`·`fingerprint`라는 키를 더 두지 않아 기존 arm과 부딪히지 않게 한다. `CLI_V1_SCHEMA_COMMANDS`, `cli_v1_data_schema` arm, `crates/qsh-core/tests/op_registration_completeness.rs`의 `OP_FACES` 행(`op: "acl.show"`, `marker: "AclShowOp"`, `renderer: "print_acl_show"`, `cli_spelling: "qsh acl show"`, `man_file: "qsh-acl-show.1"`), `cargo xtask man`으로 `docs/man/qsh-acl-show.1`과 `qsh-acl.1`의 diff를 싣는다.

호출 지점 산문을 고친다. `Policy::decide`의 doc(`crates/qsh-core/src/acl/policy.rs:194` 부근)과 `crates/qsh-cli/tests/acl_check_equivalence.rs` 모듈 doc의 "정확히 두 호출 지점" 산문을 셋(`Authorizer for Policy`의 `check`, `Ops::acl_check`, `Policy::effective_actions`)으로 고친다. 그 doc 속 기계 확인 문장 "workspace-wide `grep -rn '\.decide(\|Policy::decide'`"는 `Admission::decide` 호출 둘(`crates/qsh-core/src/server/mod.rs:1132`, `crates/qsh-core/src/reverse/listen.rs:894`)과 doc 언급까지 세므로, `grep -rn 'policy\.decide(\|self\.decide(' crates/qsh-core/src/acl crates/qsh-core/src/ops --exclude=tests.rs`로 좁힌다(ADR-0025 결과 절).

`acl_check_equivalence.rs`의 `row_*` 테스트는 각자 정책을 만들어 따로 떨어져 있어 "표의 행마다"를 돌릴 공유 표가 없다. 그래서 이 스텝이 정책 표를 한 상수로 뽑는 리팩터를 함께 한다. 기존 `row_*` 테스트는 이름과 단언을 그대로 두고 표에서 정책을 읽는다. `docs/design/threat-model.md` §3 진입점 표에 `acl show` 행, §7에 ADR-0025 결과 절의 잔여 위험(한 호출로 정책 전모를 요약) 한 항목을 더한다.

**(b) 테스트·게이트:** `crates/qsh-cli/tests/acl_check_equivalence.rs`(L6)에 다음을 더한다. `acl_show_effective_set_agrees_with_acl_check_for_every_action_in_every_table_row`(공유 표의 행마다, `Action::ALL` 각각에 대해 `acl check` 판정과 실효 집합 소속이 같음), `acl_show_reports_an_empty_set_and_no_policy_for_a_missing_or_invalid_acl_toml`, `acl_show_on_an_unreadable_acl_toml_reports_no_policy_and_no_rule_content`(`#[cfg(unix)]`, euid 0이면 skip), `acl_show_distinguishes_a_loaded_policy_with_no_matching_row_from_no_policy`, `acl_show_never_lists_always_denied_actions_even_under_family_patterns`(`forward.*`·`file.*` 행에서 `forward.socks`·`file.read`·`file.write` 부재), `acl_show_evaluates_the_ca_auth_path_when_asked`, `acl_show_rejects_a_malformed_principal_or_auth_path_as_invalid_argument`, `acl_show_does_not_modify_acl_toml`, `acl_show_never_appears_as_a_control_message_wire_variant`(기존 `acl_check_never_appears_as_a_control_message_wire_variant`의 쌍둥이). L6 문면 둘. `acl_show_notes_the_pin_default_when_auth_path_is_omitted`(human 고지 줄과 JSON `auth_path_defaulted: true`), `acl_show_human_output_carries_the_acl_restart_notice_byte_for_byte`.

L2 둘을 `crates/qsh-core/src/acl/policy/tests.rs`에 둔다. proptest `effective_actions_equals_an_independent_model_over_arbitrary_policies`의 oracle은 `decide`를 부르지 않는 독립 모델이다. principal과 `auth_path`가 일치하는 행들의 `allow` 패턴 합집합을 `Action::ALL` 위로 펼치고, `is_always_denied` 셋을 뺀다. 소유자 없는 리소스라 `scope`는 무시한다. 표 기반 테스트 `effective_actions_every_allowed_action_names_a_rule_index_in_matching_rules`는 allow가 난 action마다 `Verdict.rule`의 index가 `matching_rules`에 있음을 단언한다. 동치 테스트만으로는 둘이 같이 틀려도 초록이므로 독립 모델과 성질 테스트가 따로 고정한다.

fixture 생산 테스트 `golden_acl_show_fixtures`. 기존 등록 게이트 `layer_2_every_schema_command_has_all_six_faces`, `section_2_4_fence_matches_every_implemented_operation_bidirectionally`, `every_implemented_operation_has_a_schema_or_a_documented_exclusion`(`crates/qsh-core/tests/schema_commands_registry.rs`), `every_registered_command_has_a_schema`, `registry_matches_cli_md_section_2_5_bidirectionally`, `checked_in_man_pages_match_the_generator`, `every_error_code_is_covered_by_a_fixture_or_explicitly_deferred`가 초록.

**(c) 완료 판정:** 위 테스트 초록. 기존 fixture 무변경(`git diff --stat -- crates/qsh-cli/tests/fixtures`가 새 파일 둘만 보인다). `grep -rn 'policy\.decide(\|self\.decide(' crates/qsh-core/src/acl crates/qsh-core/src/ops --exclude=tests.rs`가 정확히 세 줄(`acl/policy.rs`의 `check`와 `effective_actions`, `ops/acl.rs`의 `acl_check`)이고 두 doc 산문이 셋과 이 grep을 적는다.

### Step 7 — OpenSSH 키 파서(`qsh-proto`)와 fuzz 타깃 (0.4~0.6ew)

근거 ADR: ADR-0026 결정 2·7·8, ADR-0001 결과 절(신뢰 불가 입력 파서의 `qsh-proto` 격리와 fuzz 커버). 선행: 없음. Step 8·9가 이 파서를 쓴다.

**(a) 범위:** `qsh-proto`에 sans-IO OpenSSH 파서 모듈을 더한다(모듈 이름 초안 `openssh`, §4.1 #4). 골든·절단·표 테스트로 800줄을 넘길 것이 분명하므로 처음부터 `crates/qsh-proto/src/openssh/mod.rs`와 `openssh/tests.rs`로 만든다. 새 크레이트를 들이지 않고 손으로 쓴다. `qsh-proto`는 워크스페이스에 이미 있는 `base64`와 `zeroize`를 의존에 더한다.

함수는 둘이다. `parse_openssh_private_key`는 `-----BEGIN OPENSSH PRIVATE KEY-----` 봉투를 벗긴 뒤 `openssh-key-v1` 형식에서 평문 Ed25519 키 하나만 받는다. 봉투 해제와 이진 형식 해석은 따로 부를 수 있는 두 층으로 둔다. cipher `none`·kdf `none`·키 개수 1이 아니면 거절하고, 두 check-int가 다르면 거절하며, 개인 섹션의 공개키가 공개 섹션과 다르면 거절한다. 오류 열거형은 `Encrypted`, `UnsupportedKeyType`, `Malformed`, `CheckIntMismatch`, `PublicKeyMismatch`, `TooLarge`를 구별한다. 길이 접두는 남은 입력보다 크면 할당 전에 거절한다. seed는 `Zeroizing`에 담고 `Debug`는 값을 가린다. `parse_authorized_keys`는 줄 단위로 읽어 줄마다 결과를 낸다(`ssh-ed25519` 공개키, 다른 키 타입, options 접두가 붙은 줄, 손상). CRLF, `#` 주석 줄, 빈 줄을 받아들인다. options가 있는 줄은 restricted로 표시만 하고 options 본문은 해석하지 않는다. 따옴표 안의 공백은 options 경계로 보지 않는다. comment는 호출자가 `sanitize_peer_text`(`crates/qsh-proto/src/wire.rs:344`)로 거를 수 있게 원문 슬라이스로만 돌려준다. SSH fingerprint 계산(SHA-256)은 해시 의존을 `qsh-proto`에 들이지 않으려고 이 모듈에 두지 않는다(Step 8).

golden 입력은 `ssh-keygen -t ed25519 -N ''`로 한 번 만든 테스트 전용 키다. 저장소에는 PEM 머리줄이 있는 파일을 두지 않는다. 키 파일 바이트를 hex 텍스트로 `crates/qsh-proto/testdata/openssh/ed25519_golden.hex`에 두고, 테스트가 `include_str!`로 읽어 복원한다(§4.1 #11). secret scanning과 push protection에 걸리지 않게 하려는 조치다. 같은 파일을 Step 8·9의 테스트도 읽는다. `ssh-keygen -lf`가 보여 준 SSH fingerprint와 공개키 줄은 테스트 상수로 고정한다. 파일 머리에 테스트 전용 키라는 주석을 둔다.

fuzz 타깃 `parse_openssh_key`를 더하고 등록 면을 모두 같은 커밋에서 고친다. `fuzz/fuzz_targets/parse_openssh_key.rs`는 첫 바이트로 봉투 층, 이진 층, `parse_authorized_keys`를 고른다. `fuzz/Cargo.toml`에 `[[bin]] parse_openssh_key`를 더하고(`cargo fuzz list`는 이 목록을 읽는다), `fuzz/corpus/parse_openssh_key/`에 golden에서 파생한 시드를 체크인한다. 개인키 시드는 PEM 머리줄 없는 이진 본문으로 둔다. `fuzz/Cargo.lock`을 갱신한다. `fuzz/oss-fuzz/build.sh`는 타깃 이름을 박지 않는다(그 파일의 주석이 이유를 적는다). `fuzz-smoke.yml`은 `cargo fuzz list`를 도는 루프라 수정이 필요 없다.

개수 문장도 같은 커밋에서 고친다. `fuzz/README.md` 머리의 "seventeen `cargo-fuzz` parser harnesses"와 "An eighteenth"(각각 하나씩 올라가고 타깃 목록에 행이 는다)와 `broker_ops` 절의 "Unlike the seventeen parser targets"(`fuzz/README.md:277`). `CLAUDE.md` 문서 지도의 "the eighteen cargo-fuzz targets". `docs/design/protocol.md` §13의 "18종 중"과 "나머지 파서 타깃 17종", 그리고 §13에 새 항목 8(`parse_openssh_key`, ADR-0026)을 `parse_socks5` 항목 7과 같은 모양으로 더한다. `docs/design/testing.md` L8의 개수 문장("…ADR-0019가 `parse_socks5`를 더해 18종이 됐다" 뒤에 ADR-0026과 19종), `[[bin]]` 이름 표의 새 행, "파서 17종의 상시 replay"를 18종으로 고친다. §13의 "파서 16종"은 M8 DoD 1의 분모이고 `parse_socks5`도 그 분모에 들지 않은 이후 추가였으므로 바꾸지 않는다(§8 #5). 새 타깃의 72 fuzz-hours는 §0.2의 별도 사람 몫이다.

**(b) 테스트·게이트:** L0 단위(`openssh/tests.rs`). `parse_openssh_private_key_reads_an_unencrypted_ed25519_golden_vector`(seed·공개키 대조), `parse_openssh_private_key_rejects_an_encrypted_key_as_encrypted`, `..._rejects_rsa_and_ecdsa_as_unsupported_key_type`, `..._rejects_every_truncation_of_the_golden_vector`, `..._rejects_a_length_prefix_larger_than_the_input_before_allocating`(4 GiB 접두), `..._rejects_mismatched_check_ints`, `..._rejection_table`(키 개수가 1이 아님, cipher `none`에 kdf만 `bcrypt`, `sk-ssh-ed25519@openssh.com`, `ssh-ed25519-cert-v01@openssh.com`), `openssh_seed_debug_output_never_contains_key_bytes`, `parse_authorized_keys_classifies_each_line_independently`(따옴표 안 공백이 있는 options, CRLF, `#` 주석, 빈 줄 포함). proptest 하나 `parse_openssh_private_key_never_panics_on_a_bitflipped_golden_vector`. fuzz-smoke run 한 번이 새 타깃을 포함해 초록. `cargo deny check`(워크스페이스)와 fuzz-smoke의 `cargo deny --locked` advisories가 초록.

**(c) 완료 판정:** 위 테스트 초록. `cargo fuzz list`가 19개를 낸다. `grep -n '18종 중\|파서 타깃 17종\|파서 17종' docs/design/protocol.md docs/design/testing.md`가 0건이고 protocol.md의 "파서 16종"은 그대로 남아 있다. `grep -n 'nineteen' CLAUDE.md`가 1건이다. `cargo tree -p qsh-proto -e normal --depth 1`의 직접 의존이 serde·serde_json·thiserror·prost·schemars·base64·zeroize뿐이다. `cargo xtask arch`는 워크스페이스 크레이트 사이의 방향만 보므로 이 판정을 대신하지 못한다. `git grep -n 'BEGIN OPENSSH PRIVATE KEY'`가 파서 소스의 상수 정의 말고는 0건이다.

### Step 8 — `qsh init --import-ssh-key <path>` (0.5~0.7ew)

근거 ADR: ADR-0026 결정 2·3·5·6·7, ADR-0008 결정 5, ADR-0017 결정 1·5, `docs/ROADMAP.md` M11 결정 기록 Q5. 선행: Step 7.

**(a) 범위:** `IdentityInitReq`에 `import_ssh_key: Option<String>`(경로), `IdentityInitData`에 `ssh_fingerprint: Option<String>`을 더한다. 둘 다 `#[serde(default, skip_serializing_if = "Option::is_none")]`를 단다. 그래야 플래그 없는 `init`이 새 키를 내지 않고 기존 `identity.init.created.json`·`identity.init.existing.json` golden이 한 바이트도 바뀌지 않는다. `qsh.cli/v1`에 additive다.

처리 순서를 고정한다. 먼저 identity 존재를 검사하고, 있으면 키 파일을 열지 않고 거절한다. 거절 경로에서 개인키 바이트를 아예 읽지 않기 위해서다. 없으면 `qsh-core`가 상한 `SSH_KEY_FILE_MAX`까지 경계 읽기로 파일을 `Zeroizing` 버퍼에 읽는다(§4.1 #5). 개인키 바이트가 계약 타입이나 CLI 쪽 버퍼를 거치지 않게 하려고 이렇게 나눈다. `crate::identity::init`에 분기를 하나 둔다. 파서가 돌려준 seed로 공개키를 포함한 PKCS#8 v2 DER을 `Zeroizing` 안에서 조립해 rcgen 키 쌍을 만든다. rcgen의 aws-lc-rs 경로가 v1 Ed25519 PKCS#8을 받는지는 확인하지 않았으므로 v2로 조립하고, golden 벡터 테스트가 그 조립을 직접 덮는다. 그 뒤는 오늘의 `generate` 경로와 같은 self-signed leaf(CN/SAN `qsh://device/<id>`)와 keystore 저장을 탄다. qsh fingerprint는 오늘과 같이 leaf의 SPKI SHA-256이다(ADR-0026 결정 3). SSH fingerprint는 OpenSSH wire 공개키 blob의 SHA-256을 `SHA256:` 접두와 패딩 없는 base64로 적는다(§4.1 #7). 그래서 `qsh-core`가 워크스페이스의 `sha2`를 의존에 더한다. 출력은 human과 JSON 모두 두 값을 이름표와 함께 나란히 낸다. 자동 pin과 `acl.toml` 쓰기는 없다(ADR-0017 결정 1·5). 새 principal 축도 만들지 않는다(ADR-0026 결정 5).

거절은 다음으로 고정한다. identity가 이미 있는 장비는 `created: false` 멱등 경로를 타지 않고 `INVALID_ARGUMENT`로 끝난다(Q5). 오류 envelope에는 remedy 필드가 없으므로(`docs/CLI.md` §3.2) 다음 행동은 `message`에 들어간다. 그 문장은 오늘 실행할 수 있는 경로를 적는다. config 디렉터리의 `identity/`를 치우고 `qsh init --import-ssh-key <path>`를 다시 돌리면 되고, 그 뒤 peer들이 다시 pin해야 한다. `CERT_EXPIRED` remedy와 같은 서술이다. 제자리 교체가 아직 없다는 사실은 한 구절로만 붙인다. 이 문면을 `pub const IMPORT_SSH_KEY_IDENTITY_EXISTS`(`crate::identity`)로 두고 관찰·영향·다음 명령 순서를 따른다(§4.1 #10). 이때 기존 identity 파일과 keystore는 바이트 동일이다. 암호화된 키, RSA, ECDSA는 `UNSUPPORTED`(ADR-0026 결정 2·7). 손상된 입력과 상한 초과는 `INVALID_ARGUMENT`. 모든 거절은 파일을 하나도 남기지 않는다. 오류 message에는 사용자가 넘긴 경로 문자열과 거절 사유만 싣고, `details`에는 거절 사유 종류만 싣는다. 입력 바이트는 어디에도 싣지 않는다.

계약 델타. fixture 다섯을 추가하고 `REQUIRED_FIXTURES`에 등재한다. `identity.init.imported_ssh_key.json`, `error.UNSUPPORTED.ssh_key_encrypted.json`, `error.UNSUPPORTED.ssh_key_type.json`, `error.INVALID_ARGUMENT.ssh_key_malformed.json`, `error.INVALID_ARGUMENT.ssh_key_identity_exists.json`. 생산 테스트는 `golden_identity_init_import_ssh_key_fixtures`(fixture마다 자기 샌드박스)다. 샌드박스를 cwd로 두고 키 파일을 상대 경로로 넘겨 message 속 경로를 결정적으로 만든다. 공용 실행 헬퍼에 cwd 인자가 없으면 이 스텝이 더한다. `normalize`에 새 arm은 필요 없다(§4.1 #8). 기존 `identity.init.created.json`·`identity.init.existing.json`은 무변경이다.

`crates/qsh-cli/tests/fixtures.rs`의 `DEFERRED`에서 `UNSUPPORTED` 행을 지운다. 그 행의 사유는 "같은 빌드의 결정적 생산자가 없다"였고, 이제 `qsh init --import-ssh-key`가 암호화된 키와 RSA 입력으로 결정적으로 `UNSUPPORTED`를 낸다. 지우지 않으면 `every_error_code_is_covered_by_a_fixture_or_explicitly_deferred`가 "must be removed from DEFERRED"로 붉다. `RETIRED_PRODUCERS`의 `error.UNSUPPORTED.json` 행은 그대로 둔다. `docs/design/testing.md` L6의 DEFERRED 서술은 `RESUME_GAP`만 들고 있어 바꿀 것이 없다.

`docs/CLI.md` §6.11의 `init` 항목에 플래그와 두 fingerprint, 거절 표를 더하고 상태 헤더 v0.14 항목에 덧붙인다. `cargo xtask man`으로 `qsh-init.1` diff. README Known limitations에 공유 키의 잔여 위험을 적는다. `docs/ROADMAP.md` M16 (d)의 rotation이 착지하기 전까지 SSH 키가 새면 복구 수단은 재 init과 재 pairing뿐이다. `docs/design/threat-model.md`에는 §3 진입점 표에 키 파일 입력 행, §4 A(스푸핑·신원)에 공유 키 위협 행(SSH와 qsh가 한 키를 쓰면 한쪽 노출이 양쪽 노출이다), §4 D(정보노출)에 개인키 바이트 유출 경로 행(오류 문면, `details`, tracing, `Debug`, 임시 버퍼), §7에 잔여 위험 한 항목을 더한다. 새 행마다 핀 테스트 이름을 적는다(threat-model §10). `docs/design/architecture.md` identity 절에 두 번째 키 생성 경로를 한 문단 적는다.

**(b) 테스트·게이트:** `crates/qsh-cli/tests/init_trust.rs`(L6)에 `init_import_ssh_key_fingerprint_is_the_spki_sha256_of_the_issued_leaf`, `init_import_ssh_key_prints_qsh_and_ssh_fingerprints_side_by_side`, `init_import_ssh_key_on_an_existing_identity_is_invalid_argument_and_preserves_every_byte`, `init_import_ssh_key_checks_for_an_existing_identity_before_opening_the_key_file`(identity가 있을 때 존재하지 않는 경로를 넘겨도 identity 존재 오류가 난다), `init_import_ssh_key_rejections_leave_no_identity_files`, `init_import_ssh_key_leaves_trust_toml_and_acl_toml_byte_identical`, `init_import_ssh_key_malformed_input_bytes_appear_in_neither_message_details_nor_logs`(손상 입력에 표식 바이트를 심고 stdout·stderr·envelope 전체에서 부재를 단언). `crates/qsh-cli/tests/exit_code_matrix.rs`에 새 거절 행. L1 단위로 `ssh_fingerprint_matches_ssh_keygen_output_for_the_golden_vector`(Step 7의 상수와 대조)와 `pkcs8_v2_assembled_from_the_golden_seed_is_accepted_by_rcgen`. fixture 생산 테스트 `golden_identity_init_import_ssh_key_fixtures`가 identity-exists fixture의 message를 `IMPORT_SSH_KEY_IDENTITY_EXISTS`와 대조한다. 기존 게이트 `every_error_code_is_covered_by_a_fixture_or_explicitly_deferred`, `checked_in_man_pages_match_the_generator`, fixture 등재 게이트 초록. 기존 `identity.init.*` golden 초록(§0.1의 측정 대상 무변경 증거).

**(c) 완료 판정:** 위 테스트 초록. golden 키로 만든 identity의 qsh fingerprint를 `qsh identity export` 결과와 대조해 같다. `git diff --stat -- crates/qsh-cli/tests/fixtures`가 새 파일 다섯만 보인다. `DEFERRED`에 `UNSUPPORTED` 행이 없다. `cargo deny check` 초록.

### Step 9 — `authorized_keys` 미리보기 (0.3~0.5ew)

근거 ADR: ADR-0026 결정 4·5, ADR-0017 결정 1·5, ADR-0012 결정 3(명령 자리). 선행: Step 7, Step 8(예측값 일치 테스트가 가져오기 경로를 쓴다).

**(a) 범위:** 인가 불요 local op 하나를 더한다. op 이름 초안은 `trust.ssh_preview`, CLI는 `qsh trust ssh-preview <path>`다(§4.1 #6). `crates/qsh-core/src/ops/trust.rs`에 `TrustSshPreviewOp`(`impl Operation`)과 `Ops::trust_ssh_preview`를 두고, `ops/mod.rs`·`lib.rs` 재수출과 `main.rs` 디스패치를 더한다. `qsh-core`가 상한 `AUTHORIZED_KEYS_MAX`로 파일을 읽고 Step 7의 `parse_authorized_keys`로 줄마다 항목을 낸다. 항목은 줄 번호, 상태(`ok`·`unsupported_key_type`·`restricted_options`·`malformed`), SSH fingerprint, 예측 qsh fingerprint, `already_pinned_as`(같은 fingerprint가 이미 `trust.toml`에 있으면 그 이름), `sanitize_peer_text`를 거친 comment다. `malformed` 줄은 줄 번호와 상태만 싣고 그 줄의 바이트는 싣지 않는다. 예측 qsh fingerprint는 공개키만으로 정해진다. Ed25519 SPKI DER은 고정 접두와 32바이트 공개키이므로 `qsh_transport`의 `Fingerprint::of_spki_der`로 계산하고, Step 8이 같은 키로 만드는 identity의 fingerprint와 같아야 한다. 데이터에는 파일 경로를 싣지 않는다.

출력은 `ok` 항목마다 붙여 넣을 `qsh trust add <name> --fingerprint …` 명령과 `[[acl]]` 행 초안을 싣는다. 행 초안은 새 생성기를 만들지 않고 `crate::acl::policy_example_rows(&[], Role::Serve)`(`crates/qsh-core/src/acl/load.rs:518`)를 그대로 쓴다. doctor와 ADR-0024 결정 4가 같은 함수를 쓰므로 `allow` 목록과 자리표시자 `device:<name>`이 세 표면에서 같다. `authorized_keys`에는 principal 이름이 없으므로 이름 자리는 자리표시자다(ADR-0026 결정 4). `restricted_options` 줄에는 ACL 행 초안을 내지 않는다. options가 거는 제한을 qsh ACL로 옮길 수 없으니 넓게 여는 쪽으로 틀리지 않도록 행을 비운다. human 출력은 두 가지를 적는다. 두 줄의 `<name>`을 같은 이름으로 바꿔야 한다는 것, 그리고 예측 fingerprint는 상대가 같은 키를 `qsh init --import-ssh-key`로 들였을 때만 맞는다는 것. 파일은 어떤 것도 쓰지 않는다.

자리표시자의 실제 성질은 이렇다. `acl.toml` 로더는 principal의 접두와 비지 않은 나머지만 보므로(`has_valid_principal_shape`, `crates/qsh-core/src/acl/load.rs:792`) `device:<name>` 행은 로드된다. 거절되지 않는다. fail closed는 매칭 단계에서 온다. 운영자가 pin은 실제 이름으로 하고 행은 고치지 않고 붙이면, 그 행은 어떤 pin 이름과도 매칭되지 않아 요청이 default-deny로 거부되고, doctor가 그 pin에 `acl_principal_unmatched`를 낸다. trust 이름 문법(`validate_peer_label`, `crates/qsh-core/src/trust/mod.rs:222`)은 `<`·`>`를 막지 않으므로 두 줄을 모두 고치지 않고 붙이면 그 키가 문자 그대로 `<name>`이라는 이름으로 pin되고 예시 목록을 받는다. 이 결과는 운영자가 이름을 골랐을 때보다 넓지 않다. 여러 `ok` 줄을 고치지 않고 붙이면 두 번째부터의 `trust add`는 이름이 같고 fingerprint가 달라 no-op이다(`TrustStore::add_peer`, `crates/qsh-core/src/trust/mod.rs:463`). 이 스텝은 trust 이름 문법을 바꾸지 않는다.

계약 델타. `docs/CLI.md` §2.4 op 목록과 §6.11에 항목을 더하고 상태 헤더 v0.14에 덧붙인다. §2.5 마지막 행은 `trust.*`로 이미 덮이므로 문면이 바뀌지 않는다. 대신 `crates/qsh-core/tests/acl_registry.rs`의 `trust.*` 전개 목록에 `trust.ssh_preview`를 더한다(그 테스트가 `CLI_V1_SCHEMA_COMMANDS`의 `trust.` op과 양방향으로 대조한다). fixture `cli-v1/trust.ssh_preview.json` 추가와 등재, 생산 테스트 `golden_trust_ssh_preview_fixture`, `CLI_V1_SCHEMA_COMMANDS`, `cli_v1_data_schema` arm, `OP_FACES` 행(`op: "trust.ssh_preview"`, `marker: "TrustSshPreviewOp"`, 렌더러 이름, `cli_spelling: "qsh trust ssh-preview"`, `man_file: "qsh-trust-ssh-preview.1"`), 렌더러, `cargo xtask man`으로 `qsh-trust-ssh-preview.1`과 `qsh-trust.1`의 diff. `docs/design/threat-model.md` §3에 입력 행 하나.

**(b) 테스트·게이트:** 파일은 신규 `crates/qsh-cli/tests/trust_ssh_preview.rs`(L6). `trust_ssh_preview_predicts_the_fingerprint_import_ssh_key_produces_for_the_same_key`(golden 키로 Step 8 경로와 대조), `trust_ssh_preview_leaves_trust_toml_and_acl_toml_byte_identical`, `trust_ssh_preview_emits_no_acl_row_for_a_line_with_options`, `trust_ssh_preview_placeholder_row_pasted_unedited_matches_no_pinned_principal`(키를 실제 이름으로 pin하고 초안 행을 고치지 않고 붙인 뒤, `acl.toml`이 로드되고 그 이름의 요청이 `acl check`에서 deny이며 `qsh doctor --json`이 그 pin에 `acl_principal_unmatched`를 냄을 단언), `trust_ssh_preview_acl_row_is_the_policy_example_row`(`policy_example_rows(&[], Role::Serve)`와 바이트 동일), `trust_ssh_preview_reports_already_pinned_as_for_a_known_fingerprint`, `trust_ssh_preview_sanitizes_control_characters_in_comments`, `trust_ssh_preview_never_echoes_bytes_of_a_malformed_line`(표식 바이트 부재). fixture 생산 테스트 `golden_trust_ssh_preview_fixture`. 등록 게이트 `layer_2_every_schema_command_has_all_six_faces`, `section_2_4_fence_matches_every_implemented_operation_bidirectionally`, `every_implemented_operation_has_a_schema_or_a_documented_exclusion`, `registry_matches_cli_md_section_2_5_bidirectionally`, `checked_in_man_pages_match_the_generator` 초록.

**(c) 완료 판정:** 위 테스트 초록. 미리보기 전후 `trust.toml`·`acl.toml`의 sha256이 같다. 고치지 않은 자리표시자 행은 로드되지만 실제 이름으로 pin된 principal과 매칭되지 않고, doctor가 그 pin을 짚는다.

### Step 10 — 마감 (0.2ew)

근거: 마일스톤 마감 공통 절차(`docs/ROADMAP.md` §2) 1·2. 선행: Step 2~9.

**(a) 범위:** 절차 1. 구속 문서 태그 대조. `docs/CLI.md`는 상태 헤더 v0.14 항목이 M11의 계약 델타(§2.4 op 둘, §6.11 `init` 플래그와 미리보기, §6.13 `cause` 9값, §6.17 23종, 새 §6.19)를 빠짐없이 적는지 본다. `docs/design/protocol.md` §13, `docs/design/threat-model.md` §3·§4·§7, `docs/design/testing.md`(L0 새 파서, L2 독립 모델 proptest, L4 idle timeout 테스트와 게이트, L6 새 fixture, L8 19종)도 대조한다. 절차 2. README 동기화. Status, Roadmap 표의 M11 행, Known limitations의 공유 키 문단, 두 별칭 절, `stale_retention` 안내. "First run" 절은 무변경임을 확인한다. `docs/ROADMAP.md` M11 절에 마감 노트를 적는다. "현재 위치"는 ADR-0023·0024가 승인됐으면 M12로, 아니면 M13으로 옮긴다(§5.1 원칙 2). §0.2 둘은 §5.5 표에 이미 행이 있으므로 새 행을 더하지 않고 상태만 갱신한다. 이 `PLAN.md`는 `docs/history/m11-plan.md`로 옮기고 다음 마일스톤 계획으로 교체한다.

**(b) 테스트·게이트:** 새 게이트 없음. 일곱 게이트와 CI acceptance job 초록.

**(c) 완료 판정:** §1의 DoD (a)~(e)가 근거 커밋과 함께 `[x]`다. `docs/history/m11-plan.md`가 있다.

## 3. 명시적 non-goals

- `qsh acl grant`/`revoke`. ADR-0025가 기각했고 ADR-0017 결정 1이 막는다.
- 원격 ACL 미리보기와 원격 `acl.show`. ADR-0025 결정 4.
- 암호화된 SSH 키, `ssh-agent`, OS keychain 연동, RSA·ECDSA 가져오기. ADR-0026 결정 2·7이 별도 결정으로 분리했다.
- 가져온 키에 CA leaf 발급. ADR-0026 결정 6과 ADR-0008 결정 5.
- supervised tunnel(ADR-0023)과 `qsh setup`(ADR-0024). `docs/ROADMAP.md` M12.
- push health 표면(`qsh.event/v1`의 `reverse.*`). ADR-0022 결정 3의 관측 트리거 전이다.
- `HOST_NOT_FOUND` 구제 문면 교체. `docs/ROADMAP.md` §5.3.
- ADR-0021 결정 1(`[transport].keep_alive_ms`)과 결정 4(`[recovery]`)의 구현, 그리고 `PathWatchConfig`의 비테스트 개방. `docs/ROADMAP.md` M13 (k)이고 §0.2의 관측 기록이 선행이다.
- 두 별칭 배치의 정식 해법(방향별 pin, 이름 결합). `docs/ROADMAP.md` M16 (a).
- identity rotation. `docs/ROADMAP.md` M16 (d). Step 8은 기존 identity를 갈아 끼우지 않고 거절한다.
- trust 이름 문법 변경. 미리보기 자리표시자 때문에 `validate_peer_label`을 좁히지 않는다.
- `.proto` 파일의 주석 정리와 `crates/qsh-core/src/tunnel/local.rs` 모듈 doc의 "P1" 주석 교체. wire 무변경을 지키려고, 그리고 손대지 않는 파일의 주석만 고치는 커밋을 만들지 않으려고 이번에는 하지 않는다.
- P2 항목 전부.

## 4. 리스크와 감시 항목

- **약 50초 통합 테스트의 벽시계.** Step 5b의 두 통합 테스트는 idle 45초를 실제로 기다린다. PR 필수 경로에 넣으면 acceptance job이 그만큼 길어진다. 두 테스트는 nextest가 병렬로 돌려 한 몫만 늘고, 기본 프로파일의 slow 판정(60초)과 종료(180초) 안에 있다. job 시간이 문제가 되면 `load.yml`이나 `long.yml` dispatch로 옮기고 그 사실을 커밋 본문과 `docs/design/testing.md`에 적는다.
- **crate 내부 하네스의 비용.** `qsh-testkit`의 `ReverseHarness`를 쓸 수 없어 Step 5b가 `qsh-core` 안에 target·controller·UDP 중계를 새로 묶는다. 크기가 5b의 상단을 넘으면 controller 쪽 테스트를 뒤로 미루지 않고 크기 줄을 다시 매긴다. DoD (a)가 두 쪽을 모두 요구한다.
- **`cause` 어휘를 M12가 인용한다.** ADR-0023 결정 12 초안은 값 개수 없이 §6.13의 고정 어휘를 인용하므로 9값이 되어도 문면이 틀리지 않는다. 그 초안의 대응 목록에 QUIC idle 만료가 없으므로, supervise 쪽에서 `idle_timeout`을 어떻게 쓸지는 M12가 정한다.
- **`docs/CLI.md` §6.19 번호.** ADR-0024 초안은 `qsh setup` 절 번호를 `acl show` 절과의 착지 순서로 정한다고 적는다. M11이 먼저 착지하므로 §6.19는 `acl show`가 갖는다.
- **손으로 쓴 파서.** 새 크레이트를 들이지 않는 대신 파서 결함은 우리 몫이다. 대응은 golden vector, 절단 전수, 길이 접두 상한, 거절 표, bitflip proptest, fuzz 타깃과 §0.2의 72 fuzz-hours다. 파서가 받는 입력 형식을 평문 Ed25519 하나로 좁혀 표면을 줄인다.
- **개인키 바이트의 유출 경로.** 오류 문면, `details`, tracing, `Debug`, 임시 버퍼, 체크인된 테스트 키가 후보다. 대응은 Step 7의 가리는 `Debug`와 `Zeroizing`과 hex 보관, Step 8의 identity 우선 검사와 입력 바이트 부재 테스트, 경로만 계약 타입에 싣는 설계다.
- **예측 fingerprint와 실제 fingerprint의 어긋남.** 미리보기가 틀린 fingerprint를 권하면 운영자는 pin을 걸어도 매칭되지 않는 default-deny를 겪는다. Step 9의 일치 테스트가 두 경로를 같은 키로 대조한다.
- **자리표시자를 그대로 붙이는 경우.** 로더는 `device:<name>` 행을 받는다. 행만 고치지 않으면 매칭이 없어 거부되고 doctor가 짚는다. 두 줄을 다 고치지 않으면 키가 `<name>`이라는 이름을 갖는다. 어느 쪽도 운영자가 고른 것보다 넓게 열지 않는다. Step 9 (a)가 근거를 적는다.
- **doctor 새 진단의 오탐.** `forward.socks`만 적은 행이 다른 행으로 `forward.local`을 받는 배치를 짚으면 잡음이다. Step 3은 같은 (principal, auth_path)의 다른 행을 보고 침묵한다. 같은 peer를 `device:`와 `fp:` 두 문자열로 나눠 쓴 배치는 짚힌다. 이 한계는 finding 문면과 §6.17 표에 적는다.
- **Windows 다리.** unix 전용 dial 경로에 붙는 새 코드와 테스트는 cfg 가드 없이는 Windows clippy·test에서 붉다. §2 규율과 Step 5a·5b (a)가 가드를 정한다.

### 4.1 구현 중 확정할 값 (해당 step (a)에 근거와 함께 추기)

| # | 질문 | 초안 | 확정 시점 |
|---|---|---|---|
| 1 | 재시작 고지 상수의 이름·자리·문면 | `crate::acl::ACL_RESTART_NOTICE`와 crate 내부 매크로 `acl_restart_notice!()`. 문면은 "restart serve/listen — acl.toml is only read once at process start."이고 두 remedy는 `concat!("… (ADR-0017), then ", acl_restart_notice!())`로 오늘과 바이트 동일 | Step 2 |
| 2 | doctor 새 진단의 code·등급·문면 | `acl_forward_socks_ineffective`, `warn`. 행의 다른 action은 여전히 동작하고 깨지는 것은 운영자의 `-D` 의도 하나라서 `acl_principal_unmatched`의 `error`(확실히 전부 거부)보다 한 단계 낮다. remedy 초안은 "Add \"forward.local\" to that row's allow; -D is authorized per CONNECT as forward.local and forward.socks alone grants nothing (ADR-0019), then " + `acl_restart_notice!()`. `detail`은 행 index와 `auth_path`만 | Step 3 |
| 3 | idle timeout 통합 테스트의 주입·게이트·자리 | `#[cfg(test)]` 주입으로 `PathWatchConfig.min_dead_after`를 60초 이상. `QSH_ACCEPTANCE_SLOW`로 가르고 `ci.yml` acceptance job에 `cargo nextest run -p qsh-core --lib -E 'test(/quinn_idle_timeout_as_idle_timeout/)'` 스텝 하나. 대안은 `load.yml`의 `--profile load` 또는 `long.yml` dispatch | Step 5b |
| 4 | 파서 모듈 이름과 손 구현 여부 | `qsh_proto::openssh`(디렉터리 모듈, `tests.rs` 분리), 손 구현. 외부 크레이트(`ssh-key` 계열)는 암호 백엔드를 끌고 와 `cargo deny`와 의존 심사 비용이 커서 배제 | Step 7 |
| 5 | 입력 파일 상한 | `SSH_KEY_FILE_MAX` 16 KiB, `AUTHORIZED_KEYS_MAX` 1 MiB. 읽기는 `CERT_PEM_MAX + 1` 경계 읽기(`crates/qsh-cli/src/main.rs:1378`)와 같은 모양을 `qsh-core`로 옮긴 것 | Step 8·9 |
| 6 | 미리보기의 op 이름, CLI 철자, 자리표시자 | `trust.ssh_preview`, `qsh trust ssh-preview <path>`, 자리표시자는 `policy_example_rows`의 `<name>`. ADR-0012 결정 3은 `trust`를 저장소 조작, `pair`를 새 신뢰 항목을 만드는 교환에 둔다. 미리보기는 교환을 하지 않고 `trust.toml`을 읽어 `trust add` 명령을 내므로 `trust` 아래가 맞다. 표준입력(`-`)은 받지 않는다. 받으면 `qsh-core`가 stdin을 읽거나 CLI가 공개키 바이트를 계약 타입에 실어야 한다. `<name>`을 고치지 않은 명령을 셸에 붙이면 `<`·`>`가 리다이렉션으로 해석돼 qsh에 닿지 않을 수 있다. 문면은 doctor `host_pinned_without_address` remedy의 `<host:port>` 선례를 따른다 | Step 9 |
| 7 | SSH fingerprint 표기 | `SHA256:` + 패딩 없는 base64. `ssh-keygen -lf`와 같은 문자열 | Step 8 |
| 8 | 새 fixture의 비결정 값 | 기존 `normalize` arm(`fingerprint`·`device_id`·`config_dir`·`path`)으로 충분하다. 오류 message의 경로는 샌드박스를 cwd로 두고 상대 경로를 넘겨 결정적으로 만든다. `ssh_fingerprint`와 예측 fingerprint는 golden 키에서 결정적이라 가리지 않는다. 새 데이터 타입은 `path`·`name`·`fingerprint` 키를 새로 쓰지 않는다 | Step 6·8·9 |
| 9 | `acl show`의 JSON과 human 모양 | JSON은 `principal`, `auth_path`, `auth_path_defaulted`, `policy`, `matching_rules`, `effective_actions`. 산문 고지는 싣지 않는다. human은 행 목록 뒤에 실효 집합 한 줄, 고지 셋(기본 auth_path, 소유 리소스 상한, 재시작 상수)을 각 한 줄 | Step 6 |
| 10 | identity가 있을 때의 message | `crate::identity::IMPORT_SSH_KEY_IDENTITY_EXISTS`. 초안 "An identity already exists in this config directory; --import-ssh-key only creates a new one. To use the SSH key instead, remove identity/ from the config directory and re-run `qsh init --import-ssh-key <path>` — peers must then re-pin. In-place key rotation does not exist yet." | Step 8 |
| 11 | golden 키 보관 | `ssh-keygen -t ed25519 -N ''`로 한 번 만든 테스트 전용 키의 파일 바이트를 hex 텍스트로 `crates/qsh-proto/testdata/openssh/ed25519_golden.hex`에 둔다. 세 크레이트의 테스트가 `include_str!`로 읽는다. 기대 fingerprint는 테스트 상수. 스캐너가 hex도 잡으면 예외 설정을 같은 커밋에 넣는다 | Step 7 |

## 5. 완료 절차

1. §1 DoD (a)~(e) 전건을 실제 테스트와 CI run으로 확인한다. 체크박스는 근거가 초록일 때만 채운다.
2. 구속 문서 태그 대조. Step 10 (a)가 열거한 자리 전수.
3. README 동기화. Status, Roadmap 표, Known limitations, 두 별칭 절, `stale_retention` 안내. "First run" 절 무변경 확인.
4. `docs/design/testing.md`의 M11 반영을 확인한다. L0 OpenSSH 파서, L2 독립 모델 proptest, L4 idle timeout 통합 테스트와 게이트(Step 5b), L8 타깃 19종(Step 7).
5. `docs/ROADMAP.md` "현재 위치"와 M11 절 갱신, 마감 노트.
6. §0.1 일곱의 상태를 승계한다. 닫힌 것은 근거와 함께 종결로, 열린 것은 소유자와 함께 이월로 적는다.
7. §0.2 둘의 상태를 `docs/ROADMAP.md` §5.5 표의 기존 행에 갱신한다.
8. 이 `PLAN.md`를 `docs/history/m11-plan.md`로 옮기고 ADR-0023·0024가 승인됐으면 M12 계획으로, 아니면 M13 계획으로 교체한다.

## 6. 이월 항목

자리표시자 `PLAN.md` §1의 P1 귀속 목록은 `docs/ROADMAP.md` §5의 M12~M19와 §5.3이 전부 흡수했다. M11이 직접 넘겨받은 것은 아래뿐이다.

| # | 항목 | M11 처분 |
|---|---|---|
| i | 이슈 #4 항목 6이 남긴 `cause` 어휘의 합침(`TimedOut`과 path-dead close가 같은 `path_dead`) | Step 5a + Step 5b |
| ii | ADR-0025 `acl show`와 ADR-0017 결정 2 remedy의 상수화 | Step 2 + Step 6 |
| iii | ADR-0026 SSH 키 가져오기(P1 백로그 항목) | Step 1(ADR 추기) + Step 7 + Step 8 + Step 9 |
| iv | ADR-0019 결과 절 R6(`forward.socks` 무효 행)의 doctor 후속 후보 | Step 3 |
| v | 이슈 #3이 드러낸 두 별칭 배치와 긴 정전 운영 안내 | Step 4. 정식 해법은 M16 (a) |
| vi | 옛 계획·ADR 줄 번호 인용 부채 | M11은 새 인용을 만들지 않고, 손대는 파일의 인용만 앵커로 바꾼다(Step 2의 `doctor.rs`, Step 5a의 `ReconnectCause` doc이 그 예). 일괄 정리는 `docs/ROADMAP.md` §5.3이 P1 밖으로 보냈다 |

## 7. 태그 정책

- M11 마감에 태그는 필요 없다. DoD 어디에도 태그가 걸리지 않는다.
- 권고 하나. Step 5a가 착지한 뒤 태그를 하나 찍으면 §0.2의 `cause` 분포 관측을 배포 바이너리로 시작할 수 있다. 찍을지는 유지보수자 결정이다.
- 찍는다면 M10판 정책을 그대로 따른다. 찍은 태그는 옮기지 않고, 태그 push가 `release.yml`을 구동하며, 서명·공증이 없는 태그로는 M10 DoD 2를 판정하지 않는다.

## 8. 열린 질문

2026-09-26 사용자 지시("모두 승인. 전부 다 진행해.")에 따라 아래를 main 세션이 결정한다. 각 항목 끝의 **결정** 문장은 초안이고 Step 1 커밋에서 확정한다.

1. **ADR-0023 결정 12의 어휘 인용.** Step 5a 뒤 §6.13은 9값이다. **결정:** 초안이 이미 값 개수 없이 "§6.13의 고정 어휘"를 인용하므로 고칠 것이 없다. 초안이 저장소에 들어간 뒤 누가 개수를 적으면 그 커밋이 고친다.
2. **`docs/CLI.md` §6.19 번호.** **결정:** Step 6의 `acl show`가 §6.19를 갖는다. ADR-0024 초안은 번호를 착지 순서로 정한다고 적으므로 초안 문면은 그대로이고, M12의 `qsh setup` 절이 다음 번호를 쓴다.
3. **M11이 ADR-0023·0024를 흡수할 것인가.** **결정:** 흡수하지 않는다. 둘은 M12 범위이고 M12는 두 ADR 승인 뒤에 연다(`docs/ROADMAP.md` M11 결정 기록 Q1, §5.1 원칙 2). M11은 두 ADR이 인용할 상수와 어휘만 고정한다.
4. **`docs/ROADMAP.md` M11 결정 기록 Q1~Q5의 확정.** 초안은 사용자 확정 대상으로 적혀 있다. **결정:** 사용자는 P1을 여는 것을 승인했지만 다섯 문장 자체를 본 적은 없다. 그래서 M10 결정 기록의 선례대로 main 세션이 사용자 전면 자율 지시에 따라 정한 것으로 적는다. Step 1이 ROADMAP 문면의 표기를 그렇게 바꾸고, Q5의 remedy 구절은 Step 1 ③대로 고친다.
5. **`docs/ROADMAP.md` M11 수용 기준 (c)의 fuzz 개수 문장.** 그 문장은 `docs/design/protocol.md` §13의 "18종, 파서 16종"이 함께 바뀐다고 적는데, "파서 16종"은 M8 DoD 1의 고정 분모라 새 타깃으로 움직이지 않는다(`parse_socks5` 선례). **결정:** Step 1이 ROADMAP 문장을 "`fuzz/README.md`·`docs/design/testing.md` L8의 타깃 개수와 `docs/design/protocol.md` §13의 타깃 개수(18종)·나머지 파서 타깃 수가 바뀌고 M8 DoD 1 분모(파서 16종)는 그대로"로 고친다. Step 7 (a)가 그 문면을 따른다.
6. **idle timeout 통합 테스트를 PR 필수 경로에 둘 것인가.** **결정:** 둔다(§4.1 #3). 어휘를 가르는 증거가 merge 뒤에만 돌면 회귀가 한 번은 main에 들어간다. `docs/ROADMAP.md` 범위 (a)의 "`--profile load` 50초 테스트" 문장은 Step 1 ③이 이 결정으로 고쳐 두 문서가 같은 말을 하게 한다. job 시간이 문제가 되면 §4의 대응으로 옮긴다.
7. **ADR-0026 결정 1과 M11 (c)의 관계.** 결정 1은 "v1에 넣지 않는다", 결과 절은 v1 표면이 그대로라고 적고, 다시 여는 조건으로 P1 착수를 든다. **결정:** 결정 본문은 고치지 않고 Step 1 ⑥의 날짜 붙은 추기로 조건 충족과 구현 범위를 기록한다. 결정을 바꾸지 않으므로 새 ADR은 필요 없다.
8. **`acl show` JSON에 고지 산문을 실을 것인가.** **결정:** 싣지 않는다. 구조 필드만 싣고 산문은 human 렌더러와 §6.19 계약 문장이 맡는다(Step 6 (a)). 실으면 append-only fixture가 `ACL_RESTART_NOTICE` 문면을 `qsh.cli/v1`로 얼리고 그 상수를 쓰는 네 표면이 함께 묶인다.
