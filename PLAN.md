# PLAN.md — M12: supervised tunnel과 `qsh setup`

P1의 둘째 마일스톤인 M12의 실행 계획이다. M11 마감 커밋이 M11 계획을 `docs/history/m11-plan.md`로 옮겼고, 이 문서가 그 자리를 전면 교체한다. 구속 근거는 다음과 같다. `docs/ROADMAP.md` §5의 M12 절(범위 (a)·(b), 착수 조건, 명시적 out, 수용 기준, 크기, 결정 기록 Q1~Q4), 같은 문서 §5.1 시퀀싱 원칙과 §5.5 P1 사람 몫, 마일스톤 마감 공통 절차(같은 문서 §2), ADR-0023 결정 1~25와 이슈 요청 대응 절과 결과 절, ADR-0024 결정 1~12와 결과 절, ADR-0018 결정 1~4, ADR-0019 결정 3·6·11, ADR-0021 결정 2·4·7, ADR-0022 결정 3·5·7, ADR-0017 결정 1·3·5, ADR-0012 결정 1·6·8, ADR-0013 결정 4·8, ADR-0015(예약), ADR-0025 결정 6, `docs/CLI.md` §2.2·§2.4·§2.5·§4·§6.1·§6.9·§6.11~§6.14·§6.18·§6.19, `docs/design/protocol.md` §2·§10·§11-3·§11-4·§16.4, `docs/design/architecture.md` §2, `docs/design/testing.md` L2·L4·L6과 CI 규율, `docs/design/threat-model.md` §3·§4 A·B·C·§7·§10, `docs/campaigns/m9-stopwatch.md` §8. 이 계획과 `docs/ROADMAP.md`의 편집은 main 세션 전용이다.

M12에는 사용자 승인을 기다리는 항목이 없다. ADR-0023과 ADR-0024는 2026-09-30 사용자 지시("github issue들도 확인해서 이것들의 반영도 모두 진행해줘")로 함께 승인됐다(`6e6ee7f`). ADR-0023은 같은 날 이슈 #6과 이슈 #4의 2026-09-30 코멘트를 반영해 결정 17~25를 더했고, 결정 24가 M12 (a)를 두 단위로 나눈다. 첫 단위는 forward route의 `--local`과 `--dynamic`이고 둘째 단위는 reverse route 전부와 `--remote`다. 이 계획은 그 순서를 그대로 따르고, 두 단위 뒤에 ADR-0024의 `qsh setup`을 둔다. M11이 만든 것 가운데 셋을 M12가 가져다 쓴다. `ACL_RESTART_NOTICE`(M11 Step 2, `d0df06c`)는 ADR-0024 결정 4가, `cause` 어휘의 `idle_timeout`(M11 Step 5a)은 ADR-0023 결정 12가, crate 내부 역방향 하네스 `crates/qsh-core/src/reverse/test_harness.rs`(M11 Step 5b)는 이 계획의 target wake 테스트가 쓴다.

인용 규율은 M11판과 같다. `docs/` 아래 문서는 줄 번호로 가리키지 않는다. 절 이름, DoD 문장, ADR 번호와 결정·결과 라벨, 테스트 이름, 커밋 해시, 이슈 번호가 앵커다. 코드 위치는 파일 경로와 심볼 이름으로 가리키고, `path:line`을 쓸 때는 그 값이 origin `8fd4602` 트리 실측임을 같은 문장에 적는다. 옛 계획의 스텝 번호는 새로 인용하지 않는다.

## 0. 착수 조건

### 0.1 P0에서 열린 채 넘어온 사람 몫 일곱

일곱 중 어느 것도 M12의 코드 스텝을 막지 않는다. M11 계획 §0.1의 목록을 M11 마감 시점 상태 그대로 옮긴다. 마감 커밋이 그 사이 닫힌 항목을 표시했으면 그 표시를 따른다.

- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** 기준은 `docs/campaigns/m10-clean-vm.md`. v0.3.0 Linux 세 회차 PASS(`69a6414`), macOS 둘이 남았다. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 선행: Apple 시크릿 여섯 등록과 서명·공증이 붙은 첫 태그. 소유: 사람(등록·회차).
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** 기준은 `docs/campaigns/m7-stopwatch.md`. 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** 기준은 `docs/campaigns/m2-mobility.md`. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** 기준은 `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 측정 대상 트리는 Step 16이 SHA로 고정한다(ADR-0024 결정 12). 소유: 사람.

M7 DoD 1과 M9 DoD 1은 README "First run" 절과 플래그 없는 `qsh init`의 흐름을 잰다. 그래서 M12는 README "First run" 절을 Step 16의 SHA 고정 전에도 뒤에도 고치지 않는다. 고정 뒤에는 새 `qsh setup` 절을 따로 더한다(ADR-0024 결과 절).

### 0.2 M11에서 넘어온 사람 몫 둘 (`docs/ROADMAP.md` §5.5)

M12 DoD가 아니다. 상태는 §5.5 표의 기존 행에 적혀 있다.

- [ ] **`cause` 분포 관측 기록.** M13 (k)의 착수 조건이다. ADR-0023 결정 25가 적듯 이슈 #6의 holder 오류 계수와 0.3.0 hub의 `cause=path_dead` 58건은 이 기록을 대신하지 못한다. 소유: 사람.
- [ ] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 기록 자리는 `docs/campaigns/m8-fuzz.md`. 소유: 사람.

### 0.3 M12가 새로 만드는 사람 몫 둘 (`docs/ROADMAP.md` §5.5)

둘 다 M12 DoD가 아니다. DoD는 캠페인 문서가 사전 고정돼 커밋되는 데까지다(§5.1 원칙 6). 회차를 돌리는 것은 사람 몫이다.

- [ ] **`p1-supervise-wake` 회차 넷.** 기준은 Step 12가 사전 고정하는 `docs/campaigns/p1-supervise-wake.md`(ADR-0023 결과 절의 캠페인 항목). 이슈 #6 토폴로지(macOS 노트북, 전체 터널 VPN, hub `qsh serve`·`qsh listen`)에서 뚜껑 10분 닫기, 뚜껑 20초 닫기, 깨어 있는 동안 VPN underlay 전환, 노트북 `qsh serve --to`의 깨어남 뒤 재등록과 hub 쪽 supervised reverse route `--local`을 잰다. 넷째 회차는 둘째 단위(Step 14) 착지 뒤에만 돌 수 있다. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 기준은 Step 20이 사전 고정하는 `docs/campaigns/p1-setup-stopwatch.md`(ADR-0024 결정 12). 비교 세트는 같은 날 같은 진행자의 m9 3회이고, M9 DoD 1 공식 회차가 그날이면 재사용한다. PASS가 기록되기 전에는 이슈 #3 완료 기준 첫 줄이 충족됐다고 적지 않는다. 소유: 사람.

### 0.4 착수 조건

충족됐다. ADR-0023과 ADR-0024가 2026-09-30 `승인됨`이고(`6e6ee7f`) M11이 닫혔다(`docs/ROADMAP.md` M11 마감 노트). Step 1이 이 계획을 저장소에 들인 뒤 Step 2~21을 연다. (b)의 첫 코드 커밋(Step 17)은 Step 16의 SHA 고정 뒤에만 온다.

## 1. DoD 체크리스트 (ROADMAP M12)

- [ ] **DoD (a1) — supervised tunnel 첫 단위: forward route `-L`/`-D`.** `--supervise`와 `--accept-hold`가 forward route의 `--local`/`--dynamic`에서 ADR-0023 결정 1~6, 7-1~7-3, 8~13, 17~21대로 동작한다. 켜지 않은 호출은 stdout·JSON·동작이 바이트 단위로 같고 stderr에 `qsh::lifecycle` 줄만 더해진다. `a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes`와 `jsonl_purity.rs`의 기존 테스트가 고치지 않고 초록이다. 켠 `-D`는 50초 blackhole 동안 listener가 bind된 채 connection refused를 한 번도 내지 않고, 걷힌 뒤 새 CONNECT가 빠른 창 안에서 성공한다. 주입한 wake 뒤 유실 선언과 target 재dial이 곧바로 일어난다. 이 단위만 착지한 트리에서 reverse route나 `--remote`의 `--supervise`는 연결 전에 `UNSUPPORTED`다. 근거: Step 3~12. 소유: 에이전트.
- [ ] **DoD (a2) — supervised tunnel 둘째 단위: reverse route와 `-R`.** 결정 7-4, 7-5, 14, 16, 22가 착지하고 결정 24의 `UNSUPPORTED` 분기와 그 테스트가 지워진다. reverse route로 연 supervised 터널은 forward pin을 한 번도 dial하지 않는다. 다른 fingerprint로 재등록한 장비로 한 바이트도 relay되지 않는다. `-R`은 close-then-open으로 같은 포트를 다시 얻고, `Scope::Owned` 아래 다른 principal의 close는 `PERMISSION_DENIED`로 남는다. `tunnel_open_local_over_reverse_ends_when_the_registration_drops`, `local_forward_primitive_over_reverse_survives_a_registration_drop_and_self_heals_per_connection`, `tunnel_open_wait_returns_the_same_stale_error_once_the_budget_expires`가 고치지 않고 초록이다. 근거: Step 13~15. 소유: 에이전트.
- [ ] **DoD (a) 공통 — 문서와 wire.** `docs/CLI.md` §6.9·§6.12·§6.13·§6.14, `docs/design/protocol.md` §2·§10·§11-4·§16.4, `docs/design/testing.md` L4, `docs/design/architecture.md` §2, `docs/design/threat-model.md` §4 A·B·C, README Known limitations, `docs/deploy/service.md`가 ADR-0023 결과 절대로 바뀐다. `git diff` 기준 `crates/qsh-proto/proto/`와 `crates/qsh-cli/tests/fixtures/`의 변경이 0이다. `p1-supervise-wake.md`가 사전 고정돼 커밋된다. 근거: 각 스텝 (a)의 문서 목록, Step 12. 소유: 에이전트.
- [ ] **DoD (b) — `qsh setup`.** 네 역할의 모든 분기 테스트 뒤 `acl.toml`이 없거나 실행 전과 바이트 단위로 같다. `setup.run`이 원격 op을 만들지 않는다. 인쇄된 행을 그대로 넣으면 `qsh acl check`가 의도한 action을 allow로 판정한다. machine mode stdout은 envelope 한 줄이고 프롬프트가 없으며 빠진 입력은 파일이 생기기 전에 `INVALID_ARGUMENT`다. 재시작 고지는 `ACL_RESTART_NOTICE`와 바이트 단위로 같다. `crates/qsh-core/src/setup/`이 `cargo xtask arch`의 디렉터리 범위 금지 대상이고 자기 테스트가 있다. 등록 완전성, fixture 등재, `docs/CLI.md` §2.4·§2.5·§6.20, `docs/PRD.md` §11, man 재생성을 갖춘다. 근거: Step 17~20. 소유: 에이전트.
- [ ] **DoD (b) 순서 — m9 재측정 SHA 고정.** Step 17의 부모 커밋이 Step 16이고, Step 16이 `docs/campaigns/m9-stopwatch.md` §8에 적은 SHA와 Step 17의 부모 사이 차이가 그 캠페인 파일 하나뿐이다(§8 #1). README `qsh setup` 절은 그 뒤에 붙는다. `p1-setup-stopwatch.md`가 사전 고정돼 커밋된다. 근거: Step 16, Step 20. 소유: 에이전트.
- [ ] **DoD 안정성 — 새 타이밍 민감 테스트의 부하 반복.** 이 마일스톤이 더한 타이밍 민감 테스트 전부가 Step 2의 하네스로 CPU 부하 아래 50회 연속 초록이다. 근거: Step 2, Step 21. 소유: 에이전트.
- [ ] **DoD 마감 — 마감 공통 절차 1·2.** 구속 문서 태그를 대조하고 README를 동기화한다. 근거: Step 21. 소유: 에이전트.

## 2. 실행 단계 (PR 단위)

스텝 번호는 이 문서 안에서만 쓰는 참조다. 크기 내역은 각 스텝 옆에 적는다. Step 2~21의 합은 5.1~6.1ew이고 Step 1이 `docs/ROADMAP.md` M12 크기 줄을 같은 값으로 고친다. 내역은 안정성 하네스 0.05~0.1, (a) 3.3~3.8(첫 단위 2.45~2.85, 둘째 단위 0.85~0.95), (b) 1.55~1.95, 마감 0.2다. (a)는 ADR-0023 결과 절의 3.3~3.8ew를 그대로 나눈 값이다. (b)는 ADR-0024 결과 절의 1.6~2.0ew에서 M11 Step 2가 이미 끝낸 재시작 상수 추출 몫 0.05를 뺀 값이다. Step 1은 크기 내역 밖이다.

순서는 과제가 정한 대로다. 첫 단위는 wake 감지기(Step 3), 빠른 창과 예산(Step 4), 요청 필드(Step 5), forward `-L`/`-D`의 supervise(Step 6~8), accept 유지(Step 9), `qsh::lifecycle`(Step 10), `serve --to` wake reset(Step 11), 첫 단위 운영 문서와 캠페인(Step 12)이다. 둘째 단위는 peer close 응답 시점 수정(Step 13), reverse route `-L`/`-D`(Step 14), `-R` 재발행(Step 15)이다. 그 뒤 ADR-0024의 SHA 고정(Step 16), `qsh setup` 세 스텝(Step 17~19), README와 캠페인(Step 20), 마감(Step 21)이다. 의존은 이렇다. Step 4·6은 Step 3에, Step 7은 Step 4·5·6에, Step 8·9는 Step 7에, Step 10은 없음(Step 7 뒤에 두는 것은 `tunnel_*` 줄의 `supervise` 필드를 한 번에 채우기 위해서다), Step 11은 Step 3에, Step 14는 Step 7·13에, Step 15는 Step 13·14에, Step 17은 Step 16에, Step 18은 Step 17에, Step 19는 Step 18에, Step 20은 Step 16·19에 기댄다. Step 13은 첫 단위와 독립이라 먼저 착지해도 된다.

규율은 앞 마일스톤 그대로이고 M12에서 몇 가지를 덧붙인다.

- 각 스텝은 일곱 게이트(`cargo fmt --all --check`, clippy `-D warnings`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `RUSTDOCFLAGS=-D warnings cargo doc`, `cargo xtask arch`, `cargo deny check`)가 초록인 채로 착지한다. clippy와 test는 `ci.yml`에서 Windows 다리도 돈다. unix 전용 경로에만 쓰이는 새 항목은 `#[cfg_attr(not(any(unix, test)), allow(dead_code))]` 선례를, 테스트만 쓰는 항목은 `#[cfg(test)]`를 따른다. reverse route 경로는 unix 전용이다.
- 계약 문서 델타는 그 표면을 바꾼 스텝의 같은 커밋에 싣는다(ADR-0023 결과 절 "문서는 같은 커밋에서 고친다"). `docs/CLI.md` 상태 헤더의 v0.15 항목은 CLI.md를 처음 고치는 스텝(Step 5)이 열고 뒤 스텝이 덧붙인다. clap 트리가 바뀌는 스텝은 같은 커밋에서 `cargo xtask man`을 돌려 `docs/man/` diff를 싣는다.
- ADR-0023 쪽 스텝은 fixture, `.proto`(`qsh.local.v1` 포함), capability 문자열, `ErrorCode`를 바꾸지 않는다. 스텝마다 `git diff --stat -- crates/qsh-cli/tests/fixtures crates/qsh-proto/proto`가 비어 있음을 완료 판정에 둔다. ADR-0024 쪽 fixture는 추가만 하고, 새 fixture마다 실제 바이너리로 그 결과를 재현하는 `golden_*` 생산 테스트를 같은 커밋에 둔다.
- 판정 로직은 `qsh-core`의 `Ops`와 그 아래 모듈에 두고 `qsh-cli`에는 clap 정의, 렌더러, 신호 handler 배선만 더한다. `acl.toml`을 쓰는 코드 경로는 어느 스텝에도 생기지 않는다(ADR-0017 결정 1).
- 손대는 소스 파일이 800줄을 넘으면 인라인 테스트를 같은 커밋에서 형제 `tests.rs`로 옮긴다. `crates/qsh-core/src/client/pathwatch.rs`는 origin `8fd4602`에서 797줄이고 인라인 테스트가 들어 있어 Step 3이 옮긴다. 새 모듈이 800줄을 넘을 것이 분명하면 처음부터 디렉터리 모듈과 `tests.rs`로 만든다.
- 테스트 스위트는 고정 대기 `sleep()`을 쓰지 않는다(`docs/design/testing.md` L2, CI 규율). M12는 여기에 안정성 규율을 더하는데, 새 타이밍 민감 테스트는 다음 셋을 모두 지킨다.
  - 시계는 주입한다. 순수 로직(wake 감지기, backoff, 예산, `PathState`)은 `tokio::time::pause()`와 주입한 벽시계·RNG로 돌리고 벽시계를 실제로 기다리지 않는다.
  - 기다림은 관찰 가능한 상태로 한다. 통합 테스트는 carrier 상태의 `watch` 채널, 테스트 관찰자 채널, 캡처한 진단 줄을 기다리고 넉넉한 `timeout`으로 묶는다. "N초 뒤에는 이렇게 됐을 것이다"를 고정 대기로 쓰지 않는다.
  - 벽시계 상한은 결정 경로를 가르는 데만 쓴다. 상한을 문자 그대로 단언해야 하는 값(ADR-0023 결정 17의 `WAKE_TICK + dead_after(rtt)`, 결정 10의 `FAST_CAP`)은 주입 시계 층에서 정확히 단언하고, 실제 소켓을 쓰는 통합 층은 "다른 경로였다면 걸렸을 시간보다 훨씬 짧다"와 순서를 단언한다(§4.1 #9).
- 새 타이밍 민감 테스트는 그 스텝의 완료 판정에서 Step 2 하네스로 CPU 부하 아래 50회 연속 초록이어야 착지한다. Step 21이 마일스톤 전체 목록으로 다시 돌린다.
- 벽시계를 실제로 기다리는 테스트는 `QSH_ACCEPTANCE_SLOW`로 가르고 `docs/design/testing.md`의 벽시계 예외 목록에 이름을 올린다.

### Step 1 — M12 계획 교체와 ROADMAP 갱신 (main 세션, 크기 내역 밖)

근거: `docs/ROADMAP.md` M11 마감 노트, ADR-0023 결과 절의 ROADMAP 항목, ADR-0024 결과 절. 선행: M11 마감. M12의 첫 커밋이다.

**(a) 범위:** ① `PLAN.md`가 이 문서다(M11 마감 커밋이 옮기지 않았으면 이 커밋이 M11 계획을 `docs/history/m11-plan.md`로 옮긴다). ② `docs/ROADMAP.md`를 고친다. "현재 위치" 줄을 M12로, M12 절의 범위 (a)·착수 조건·명시적 out·수용 기준·크기·결정 기록을 두 ADR의 승인 문면과 ADR-0023 결정 17~24에 맞춘다. §3 가드레일 표의 "Forward-route live carrier·`-R` 자동 재발행" 행 끝 문장을 두 단위 순서로 고친다. §5.2 표의 M12 행과 머리의 P1 총 크기 줄을 새 크기로 고친다. §5.5 표에 `p1-supervise-wake` 행을 더한다. 문안은 main 세션이 가진 편집안 그대로다. ③ README Roadmap 표의 P1 행을 "M12 진행 중"으로 고친다.

**(b) 테스트·게이트:** 문서 변경이라 새 게이트가 없다. README 축자 게이트가 걸린 자리는 건드리지 않는다. 일곱 게이트 초록.

**(c) 완료 판정:** `PLAN.md` 첫 줄이 이 문서의 제목이다. "현재 위치"가 M12를 가리킨다. `grep -n '초안, M12를 열 때 확정' docs/ROADMAP.md` 0건, `grep -n 'p1-supervise-wake' docs/ROADMAP.md` 1건 이상, `grep -n '3.8~5.3' docs/ROADMAP.md` 0건.

### Step 2 — 부하 반복 하네스 (0.05~0.1ew)

근거: §2의 안정성 규율, `docs/design/testing.md` CI 규율. 선행: 없음. 첫 단위의 모든 스텝이 이 하네스로 완료를 판정한다.

**(a) 범위:** `scripts/stress/run.sh`를 더한다. 인자는 nextest filterset 하나와 반복 수(기본 50)다. 스크립트는 논리 CPU 수만큼 바쁜 루프 프로세스를 띄워 CPU를 포화시키고(§4.1 #8), `cargo nextest run --workspace --no-fail-fast -E '<filterset>'`을 반복 수만큼 돌린다. nextest가 반복 실행 옵션을 제공하면 그것을 쓰고, 없으면 셸 반복으로 대신한다. 한 번이라도 붉으면 그 회차 번호와 실패 테스트 이름을 찍고 exit `1`이다. 끝에는 "N/N passed under load"를 한 줄 찍는다. 부하 프로세스는 `trap`으로 반드시 거둔다. `QSH_ACCEPTANCE_SLOW=1`을 넘기면 벽시계 테스트도 돈다. macOS와 Linux에서 돈다.

`scripts/README.md`에 절 하나를 더하고, `docs/design/testing.md` CI 규율에 "타이밍 민감 테스트는 착지 전에 `scripts/stress/run.sh`로 CPU 부하 아래 50회 연속 초록이어야 한다" 한 항목을 넣는다. 근거로 `8fd4602`(부하 아래 16/80 실패하던 역방향 reset 관찰 경합)를 적는다. PR 게이트에는 넣지 않는다. 부하 반복은 공유 runner에서 재현성이 낮고 수십 분이 걸리기 때문이다.

**(b) 테스트·게이트:** 스크립트 자체의 게이트는 없다. 착지 커밋 본문에 기존 테스트 하나(`run_target_lost_and_retry_lines_report_a_silent_path_as_path_dead`)를 이 하네스로 50회 돌린 결과 줄을 적어 동작을 보인다.

**(c) 완료 판정:** `scripts/stress/run.sh 'test(/no_such_test/)' 1`이 "0 tests" 경고와 함께 exit `0`, 일부러 실패하는 filterset이면 exit `1`이고 부하 프로세스가 남지 않는다(`pgrep` 0건). 일곱 게이트 초록.

---

첫 단위(ADR-0023 결정 24): forward route의 `--local`과 `--dynamic`. 결정 1~6, 7-1~7-3, 8~13, 17~21.

### Step 3 — wake 감지기와 `PathWatch` 배선 (0.25~0.3ew)

근거 ADR: ADR-0023 결정 17, 결정 4(wake는 활동이고 즉시 probe), 결정 21과 무관. 선행: 없음.

**(a) 범위:** `qsh-core`에 프로세스마다 하나인 wake 감지기를 둔다(모듈 자리 §4.1 #1). `WAKE_TICK` 1초마다 벽시계(`SystemTime`)와 단조 시계(`Instant`)를 함께 읽고, 직전 tick 이후 벽시계 증가량에서 단조 증가량을 뺀 값이 `WAKE_SKEW` 3초 이상이면 wake로 판정하고 그 차를 `slept_ms`로 알린다. 벽시계가 뒤로 가면 wake가 아니다. 두 상수는 설정으로 열지 않는다(ADR-0021 결정 4의 규율, ADR-0023 개정 관계 절). 알림은 구독자마다 놓치지 않는 `tokio::sync::watch`(값은 wake 순번과 `slept_ms`)로 낸다. 벽시계 원천은 트레이트로 주입하고 제품 코드는 `SystemTime::now`를, 테스트는 손으로 움직이는 가짜 시계를 쓴다. tick 타이머는 tokio 시계라 `tokio::time::pause()` 아래에서 결정적이다. 감지기는 처음 구독될 때 한 번 뜨고 패킷을 보내지 않는다.

`PathWatch`(`crates/qsh-core/src/client/pathwatch.rs`)가 wake 구독을 받는다. wake가 오면 `PathState::observe_activity`로 활동을 기록하고 잠든 watchdog을 기존 `wake` Notify로 깨워 곧바로 판정한다. 침묵은 잠들기 전 마지막 수신부터 단조 시계로 재므로, 깨어난 뒤 빠른 cadence probe 3번과 `dead_after(rtt)` 가운데 긴 쪽이 지나면 사망이 선언된다. 소비자는 대화형 attach의 recovery, `qsh serve --to` target의 `PathWatch`(`crates/qsh-core/src/reverse/target/mod.rs`), `qsh listen` 등록의 `PathWatch`(`crates/qsh-core/src/reverse/listen/registration.rs`)다. supervised forward 터널과 두 backoff는 뒤 스텝이 붙인다. recovery의 분류와 결과 어휘는 바뀌지 않는다. `PathWatch::new`의 시그니처를 바꾸면 호출 지점 셋을 같은 커밋에서 고치고, 두 역방향 자리의 `#[cfg(test)]` `PathWatchConfig` 주입(M11 Step 5b)은 그대로 둔다.

`pathwatch.rs`는 797줄이라 이 스텝에서 800줄을 넘기므로 같은 커밋에서 인라인 테스트를 `crates/qsh-core/src/client/pathwatch/tests.rs`로 옮긴다. `xtask/src/arch.rs`의 경로 금지 목록에 이 경로는 없다.

문서를 같은 커밋에서 고친다. `docs/design/protocol.md` §2의 "절전 복귀 시 클라이언트는 monotonic clock 점프/PTO 실패로 죽은 연결을 즉시 버리고" 문장을 결정 17의 기전(벽시계와 단조 시계의 차이, 1초 tick, 3초 문턱, 깨어난 뒤 약 2초 안의 유실 선언)으로 고친다. §10 "Path 사망 감지" 목록에 wake 항목 하나를 넣는다. 둘 다 wire 밖의 서술이다. `docs/design/architecture.md` §2나 §3의 `PathWatch` 서술이 있으면 한 구절을 더한다.

**(b) 테스트·게이트:** 단위(결정 17, 시계 주입). `wake_detector_reports_a_wall_clock_jump_the_monotonic_clock_did_not_see`(벽시계 60초, 단조 0초 → `slept_ms` 60000), `wake_detector_ignores_divergence_below_three_seconds`, `wake_detector_ignores_a_backward_wall_clock_step`, `wake_detector_delivers_every_wake_to_a_subscriber_that_was_busy`(`watch` 순번이 건너뛰지 않음). 단위(결정 4·17, `pathwatch/tests.rs`). `path_state_probes_at_once_and_uses_the_fast_cadence_after_a_wake`(idle cadence에서 wake 뒤 첫 판정이 `Probe`이고 3 strike 뒤 `Dead`까지 250ms cadence), `path_state_treats_a_local_accept_as_activity`, `path_watch_declares_dead_within_wake_tick_plus_dead_after_of_a_wake`(paused 시계에서 주입한 wake부터 `dead()`가 풀리기까지 `WAKE_TICK + dead_after(rtt)` 이하, §4.1 #9). 기존 `pathwatch` 테스트와 `detection_budget`을 쓰는 recovery 테스트가 고치지 않고 초록.

**(c) 완료 판정:** 위 테스트 초록. 새 테스트 전부가 `scripts/stress/run.sh`로 50회 연속 초록. `grep -n 'monotonic clock 점프' docs/design/protocol.md` 0건. `git diff --stat -- crates/qsh-cli/tests/fixtures crates/qsh-proto/proto`가 비어 있다.

### Step 4 — supervise 빠른 창, 예산, 오류 분류 (0.4~0.45ew)

근거 ADR: ADR-0023 결정 9, 10, 18, 결정 17(wake 소비). 선행: Step 3.

**(a) 범위:** supervisor가 쓸 순수 로직 셋을 네트워크 없이 만든다. 자리는 supervisor 모듈(§4.1 #2)이다.

- backoff. 첫 시도는 유실 감지 즉시, 그 뒤 500ms에서 2배씩 늘리고 full jitter를 준다. 유실 감지와 wake마다 `FAST_WINDOW` 60초 창을 새로 열고, 창 안에서는 간격이 `FAST_CAP` 2000ms를 넘지 않는다. 창이 끝나면 그 자리에서 2배씩 이어 늘려 30000ms에서 멈춘다. wake는 위치를 처음으로 되돌리고 진행 중인 대기를 끊어 즉시 한 번 시도하게 하고 창을 새로 연다. 다만 진행 중인 시도는 끊지 않는다. `refused`로 끝난 시도는 그 자리에서 창을 닫는다. 네 상수는 `[reverse]`를 읽지 않는 고정 상수다. RNG는 주입한다(target `Backoff`의 선례).
- 예산. "끊김" 시간의 합을 단조 시계로 재고 살아 있던 시간은 더하지 않는다. 재수립된 터널이 30초 이상 살아야 그 유실이 끝난 것으로 치고, 그 전에 다시 죽으면 누적 예산과 창 밖 backoff 위치를 이어 쓴다. 절전 시간은 예산을 쓰지 않고, 절전이 예산보다 길어도 깨어난 뒤 한 번은 시도한다. 예산이 떨어지면 마지막 시도의 오류로 끝낸다.
- 오류 분류. 결정 9의 표 하나를 `(출처, ErrorCode, retryable) → {Retry, Stop}` 함수로 옮긴다. 표에 없는 조합과 `Unknown(_)`은 `Stop`이다. 예외 둘(7-4의 close 직후 bind 경합 재시도, "no such forward_id"를 성공으로 읽기)은 둘째 단위가 쓰지만 분류 함수의 입력 모양은 이 스텝에서 정한다.

이 셋은 `pub(crate)`이고 아직 호출자가 없으므로 Windows lib 빌드의 dead_code를 피하도록 cfg 가드를 단다.

**(b) 테스트·게이트:** 단위(결정 10·18, paused 시계, 고정 seed). `supervise_backoff_caps_at_two_seconds_inside_the_fast_window_then_doubles_to_thirty`, `supervise_backoff_restarts_and_reopens_the_fast_window_on_wake`, `supervise_backoff_closes_the_fast_window_on_refused`, `supervise_backoff_wake_cuts_a_pending_wait_but_not_an_attempt_in_flight`. 단위(결정 10 예산). `supervise_budget_counts_only_disconnected_time_and_carries_over_inside_the_thirty_second_stability_window`(`--supervise 5000`, 3초 끊김, 재수립, 20초 뒤 재유실이면 남은 예산 2초), `supervise_budget_refills_after_thirty_seconds_alive`, `supervise_budget_excludes_slept_time_and_still_attempts_once_after_a_wake_longer_than_the_budget`. 단위(결정 9). `supervise_error_classification_covers_every_source_and_error_code`(출처마다 `ErrorCode`의 모든 변형과 `Unknown(_)`을 돌려 표와 대조). proptest `supervise_backoff_never_exceeds_thirty_seconds_and_never_exceeds_two_inside_a_window`.

**(c) 완료 판정:** 위 테스트 초록. 새 테스트 전부가 부하 아래 50회 연속 초록. mutation 하나(`FAST_CAP` 적용을 빼기)가 첫 테스트와 proptest를 붉힌다.

### Step 5 — 요청 필드, CLI 플래그, 검증 (0.15ew)

근거 ADR: ADR-0023 결정 1, 2, 13, 19의 검증 문장, 24. 선행: 없음(Step 7이 이 스텝의 `UNSUPPORTED`를 좁힌다).

**(a) 범위:** `TunnelOpenReq`와 `TunnelDynamicReq`(`crates/qsh-proto`)에 `supervise_ms`와 `accept_hold_ms`(둘 다 optional u32, `#[serde(default, skip_serializing_if = "Option::is_none")]`)를 더한다. `wait_ms`(`c9113cc`)와 같은 모양이다. standalone `qsh tunnel open`의 clap 정의에 `--supervise <ms>`와 `--accept-hold <ms>`를 넣는다. 대화형 form에는 두지 않는다.

검증은 `Ops`가 연결이나 bind 전에 한다. `supervise_ms`가 `0..=86400000` 밖이면 `INVALID_ARGUMENT`다. `accept_hold_ms`가 `0..=2000` 밖이거나, `supervise_ms`가 0인데 0이 아니거나, `--remote`에 주면 `INVALID_ARGUMENT`다. `Ops::tunnel_open_and_hold`와 `Ops::tunnel_dynamic_and_hold`는 `supervise_ms`가 0이 아니면 `INVALID_ARGUMENT`다. 이 검증을 통과한 0이 아닌 `supervise_ms`와 `accept_hold_ms`는 이 스텝에서 모두 연결 전에 `UNSUPPORTED`다. 예약된 옵션이 `UNSUPPORTED`를 돌려준다는 기존 규율을 따른 것이고 결정 24가 같은 규율을 적는다. 생략하거나 0이면 요청·응답·동작이 바이트 단위로 같다.

`docs/CLI.md` §6.9에 두 옵션 문단을 넣고(값 범위, 기본값, 검증 순서, 현재 `UNSUPPORTED` 범위), 상태 헤더에 v0.15 항목을 연다. `cargo xtask man`으로 `qsh-tunnel-open.1`의 diff를 낸다.

**(b) 테스트·게이트:** 단위(`crates/qsh-core/src/ops/tunnel/tests.rs`). `supervise_out_of_range_is_invalid_argument_before_any_listener_exists`, `tunnel_open_and_hold_with_supervise_is_invalid_argument_before_connecting`, `accept_hold_without_supervise_or_above_two_thousand_or_on_remote_is_invalid_argument_before_bind`, `supervise_on_an_unsupported_route_or_mode_is_unsupported_before_connecting`(결정 24. 표 기반이고 이 스텝에서는 모든 route·mode 행이 `UNSUPPORTED`, Step 7·9·14·15가 행을 줄이고 Step 15가 지운다), `supervise_zero_and_absent_serialize_byte_identically`. 기존 `wait_ms` 테스트와 `checked_in_man_pages_match_the_generator` 초록.

**(c) 완료 판정:** 위 테스트 초록. `git diff --stat -- crates/qsh-cli/tests/fixtures crates/qsh-proto/proto`가 비어 있다(`TunnelOpenReq`는 `crates/qsh-proto/src/types`에 있고 `.proto`가 아니며 schema·fixture에 나타나지 않는다, 결정 13).

### Step 6 — carrier `watch` 교체와 "끊김" 거절 (0.25~0.3ew)

근거 ADR: ADR-0023 결정 3, 5, 6. 선행: 없음(Step 7이 이 구조 위에 감독을 얹는다).

**(a) 범위:** `-L`의 accept 루프(`crates/qsh-core/src/tunnel/local.rs`)와 `-D`의 accept 루프(`crates/qsh-core/src/tunnel/dynamic.rs`)가 시작 시 한 번 받던 `ForwardCarrier` 스냅숏 대신 accept마다 `watch` 채널에서 현재 carrier를 읽게 바꾼다. 채널 값은 "살아 있음(carrier, 확인된 peer fingerprint)"과 "끊김" 둘이다. 기본 모드는 값이 "살아 있음" 하나로 끝까지 가므로 동작이 같다. "끊김"일 때 들어온 연결은 대기열에 넣지 않고 즉시 거절한다. `-L`은 accept 뒤 `abort_local`(`SO_LINGER 0`, RST), `-D`는 SOCKS CONNECT에 REP `0x01`을 보내고 `shutdown(Write)` 뒤 닫는다(`docs/CLI.md` §6.9 REP 표의 "로컬: 스트림 열기 실패" 행). 옛 carrier 위에서 `ConnectResult`를 기다리던 handshake는 그 자리에서 같은 방식으로 거절하고, `ConnectResult{ok:true}`를 지나 splice 중이던 연결은 건드리지 않는다. accept마다 활동을 알리는 훅(결정 4의 `observe_activity`)을 이 자리에 두고 Step 7이 연결한다. `local.rs`는 이미 `local/tests.rs`를 쓰므로 800줄 규칙에 새로 걸리지 않는다.

**(b) 테스트·게이트:** 단위(`tunnel/local/tests.rs`, `tunnel/dynamic/tests.rs`). `local_forward_rejects_with_rst_while_the_carrier_is_disconnected`, `dynamic_forward_replies_rep_01_while_the_carrier_is_disconnected`, `a_splice_in_progress_survives_a_carrier_switch_to_disconnected`, `a_handshake_awaiting_connect_result_on_the_old_carrier_is_rejected_on_disconnect`, `accept_reads_the_carrier_current_at_accept_time`. 기다림은 carrier `watch` 값과 accept 이벤트로 한다. 기존 `tunnel_chaos.rs`의 `a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes`, `dynamic_forward.rs`, `socks_curl`, `tunnel_throughput`, `tunnel_echo_under_load` 초록.

**(c) 완료 판정:** 위 테스트 초록과 부하 아래 50회 연속 초록. 기본 모드 테스트 diff 0. `grep -n 'a forward has to be restarted across a recovery' crates/qsh-core/src/tunnel/local.rs`가 0건이고 그 doc이 `watch` carrier를 설명한다.

### Step 7 — forward route supervisor (0.6~0.7ew)

근거 ADR: ADR-0023 결정 2, 3, 4(forward), 5, 7-1~7-3, 8, 9, 10, 11, 12, 15, 24. 선행: Step 3·4·5·6.

**(a) 범위:** `TunnelHold::hold`(`crates/qsh-core/src/ops/tunnel.rs`) 경로에 supervisor를 붙인다. 새 daemon은 없다. forward route의 `--local`과 `--dynamic`에서 `supervise_ms`가 0이 아니면 최초 open이 성공한 뒤 감독을 시작한다. 최초 open 실패는 지금 봉투로 끝나고 재시도하지 않는다(결정 2).

감지. supervised 터널의 control 스트림에 `PathWatch`를 붙인다. 설정은 `RecoveryConfig.watch`이고(`crates/qsh-core/src/ops/session.rs`), Step 3의 wake 구독과 Step 6의 accept 활동 훅을 연결한다. 사망 판정 뒤 `RecoveryConfig.migration`이 켜져 있으면 `Endpoint::rebind()` migration을 먼저 시도하고 connection이 살아나면 아무것도 하지 않는다. 기본 모드에는 `PathWatch`도 wake 구독도 붙이지 않는다. 유실은 현재 carrier의 죽음뿐이고 남겨 둔 옛 connection이 나중에 닫히는 것은 유실이 아니다.

재수립. 사망 판정 즉시 carrier를 "끊김"으로 바꾼다. 시도마다 최초 open에서 해석한 주소로 다시 dial하고 `REDIAL_DEADLINE`(2초)으로 묶으며 `hosts.toml`은 다시 읽지 않는다. 새 carrier의 TLS peer fingerprint가 최초 값과 다르면 요청 없이 `AUTH_FAILED`로 끝낸다(7-2). 최초 open이 확인한 capability(`-D`는 `dial-filter.v1`)가 없으면 `UNSUPPORTED`로 끝낸다(7-3). 통과하면 carrier를 확인된 신원과 함께 "살아 있음"으로 바꾼다. `-L`/`-D`는 control 메시지를 보내지 않는다. 새 dial은 admission과 mTLS를 다시 거치고 `TCP_CONNECT`는 스트림마다 `forward.local`로 판정된다(결정 8). 옛 connection은 마지막 splice가 끝날 때 close code `0`으로 닫는다. 재dial 경로는 세션의 `DialReconnect`와 dial 절차만 공유하고 `recover_attach`는 쓰지 않는다(결정 3). 분류·간격·예산은 Step 4를 그대로 쓴다.

끝. 예산이 떨어지거나 `Stop`이면 stderr에 `gave_up` 줄을 쓰고 이어 `human::print_error`로 오류를 낸 뒤 listener를 놓고 exit `255`로 끝난다. stdout에는 최초 봉투 뒤로 한 바이트도 더하지 않는다. supervised 모드에서만 `qsh serve`/`qsh listen`의 `shutdown_signal()`과 같은 SIGINT·SIGTERM handler를 두고, 받으면 감독을 멈추고 listener를 놓고 exit `0`으로 끝난다. 신호 handler 배선만 `crates/qsh-cli/src/main.rs`의 `run_tunnel_open`·`run_tunnel_open_dynamic`에 두고 판단은 `qsh-core`에 둔다. 기본 모드의 신호 동작은 바꾸지 않는다.

진단. tracing target `qsh::tunnel::supervise`의 한 줄 JSON을 낸다. 첫 키 `supervise`, 값 `lost`·`retry`·`reestablished`·`gave_up`·`wake`(이 스텝), `closed`(Step 15). 모든 줄에 `at`, `tunnel_id`, `mode`, `route`(이 스텝은 `forward`)가 붙는다. `lost`·`retry`에 `cause`(결정 12의 대응. connection 종료는 `classify_connection_error`를 그대로 부르고, quinn idle timeout은 M11 (a) 뒤라 `idle_timeout`, 원인을 모르면 키 생략), `retry`에 `attempt`·`code`·`outage_ms`, `reestablished`와 `gave_up`에 `outage_ms`, `wake`에 `slept_ms`를 싣는다. 주소, 토큰, payload, peer 오류 본문은 싣지 않는다. `init_tracing`(`crates/qsh-cli/src/main.rs`)에 `qsh::reverse`와 같은 전용 layer와 `{default},qsh::tunnel::supervise=info` 필터를 더하고, human layer의 제외 목록에 이 target을 넣는다. `--quiet`에서만 꺼지며 명시한 `QSH_LOG`/`RUST_LOG`가 있으면 그 값을 따른다. target 상수는 `qsh-core`에 공개 상수로 둔다.

`supervise_on_an_unsupported_route_or_mode_is_unsupported_before_connecting`의 표에서 forward `-L`/`-D` 행을 뺀다(accept 유지 0이 아닌 값은 Step 9까지 `UNSUPPORTED`로 남는다).

문서를 같은 커밋에서 고친다. `docs/CLI.md` §6.14 첫 문단 끝에 "`--supervise` 예외는 아래 문단" 한 구절, 그 아래 "supervised 예외" 문단(결정 5, 6, 11과 forward route 한정 문장)을 더하고 §6.9 옵션 문단의 `UNSUPPORTED` 범위를 좁힌다. §6.14와 §6.9에 `trust remove` 뒤에도 살아 있는 연결 위의 켠 터널이 계속 돈다는 사실(`TrustRemoveScope` remedy의 현행 범위)을 적는다. `docs/design/architecture.md` §2에 "supervisor는 `Ops` 안, 터널을 연 프로세스에 있다" 한 줄을 넣는다. `docs/design/threat-model.md` §4 A에 재연결 시 peer 치환(통제 결정 6·7-2, 핀 테스트 이름), §4 B에 재발행의 인가 재사용(통제 결정 8), §4 C에 재시도 소음·옛 connection 누적·빠른 창의 재dial 빈도(통제 결정 9·10의 `refused` 창 닫기, peer의 연결 quota) 행을 더한다. README Known limitations에는 forward 몫 셋(진행 중인 TCP 연결은 옛 connection이 살아날 때만 산다, 최초 open 실패는 감독하지 않는다, wake 감지는 Windows에서 확인되지 않았다)을 적는다.

**(b) 테스트·게이트:** crate 내부 통합(`crates/qsh-core/src/ops/tunnel/tests.rs` 또는 supervisor 모듈 `tests.rs`, loopback 서버, 수 초). `supervised_local_keeps_its_port_and_tunnel_id_across_two_reestablishments`(결정 3·5), `supervised_local_splice_survives_a_short_blackhole_and_new_accepts_ride_the_new_connection`(결정 4·5. 같은 조건의 기본 모드 터널과 진행 중 연결의 생존이 같음을 함께 단언), `supervised_local_accept_during_disconnect_gets_rst_once_the_carrier_is_disconnected`와 `supervised_dynamic_connect_during_disconnect_gets_rep_01`(결정 5·6. 관찰 채널로 "끊김"을 기다린 뒤 accept하고 즉시 거절을 단언. 기본 `PathWatchConfig`로 "끊김"까지 걸린 시간은 10초 상한으로만 단언하고 기록한다, §4.1 #9), `supervised_forward_redial_to_a_different_fingerprint_ends_with_auth_failed_and_sends_no_request`(7-2), `supervised_dynamic_redial_to_a_peer_without_dial_filter_ends_unsupported`(7-3), `supervised_forward_peer_restarted_without_forward_local_ends_permission_denied_with_one_audit_deny`(결정 8·9. peer audit에 거부 줄 하나, listener 해제), `supervised_forward_initial_open_failure_is_not_retried`(결정 2), `supervised_budget_exhaustion_emits_gave_up_then_the_error_then_exit_255`(결정 11), `supervised_sigterm_during_an_outage_releases_the_listener_and_exits_zero`(결정 11, `crates/qsh-cli/tests/`의 서브프로세스). L6(`crates/qsh-cli/tests/`). `supervised_stdout_stays_one_envelope_across_two_reestablishments`(`jsonl_purity.rs`의 `a_tunnel_in_progress_keeps_stdout_pure_json_while_qsh_tunnel_diagnostics_land_on_stderr`와 같은 모양), `supervise_lost_and_gave_up_lines_are_visible_at_default_verbosity_and_silent_under_quiet`, `supervise_lines_never_carry_an_address_or_token_field`. 기존 트랩 `a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes`와 `jsonl_purity.rs` 초록.

**(c) 완료 판정:** 위 테스트 초록과 부하 아래 50회 연속 초록. mutation 둘(7-2 fingerprint 대조 제거, 끊김 동안의 즉시 거절 제거)이 각각 대응 테스트를 붉힌다. fixture·`.proto` diff 0. `grep -n 'qsh::tunnel::supervise' docs/CLI.md crates/qsh-cli/src/main.rs`가 각 1건 이상.

### Step 8 — supervise 수용 테스트와 CI 배선 (0.2~0.25ew)

근거 ADR: ADR-0023 결정 4, 5, 10, 17과 결과 절의 2026-09-30 테스트 목록, 이슈 요청 대응 #6-2. 선행: Step 7.

**(a) 범위:** 결과 절이 이름 붙인 두 테스트를 세운다. 하나는 crate 내부 통합 `supervised_forward_carrier_is_declared_lost_within_two_seconds_of_an_injected_wake`다. idle cadence에 들어간 supervised `-D`의 서버를 CONNECTION_CLOSE 없이 사라지게 하고(quinn idle 타이머는 45초가 남음), 주입한 wake 뒤 `lost`(`cause: path_dead`)가 나오는지 본다. 주입은 Step 3의 가짜 벽시계를 `#[cfg(test)]`로 프로세스 감지기에 꽂는 방식이며 바이너리에 들어가지 않는다(M11 (a)와 같은 규율). 벽시계 상한 단언은 §4.1 #9의 층 나눔을 따른다. 정확한 상한 `WAKE_TICK + min_dead_after + 500ms`는 Step 3의 `path_watch_declares_dead_within_wake_tick_plus_dead_after_of_a_wake`가 주입 시계로 고정하고, 이 통합 테스트는 `lost`가 quinn idle(45초)보다 훨씬 이른 10초 안에 `path_dead`로 나오며 wake 이전에는 나오지 않았음을 단언하고 실측 지연을 기록한다.

다른 하나는 testkit 수용 테스트 `supervised_dynamic_listener_stays_bound_through_a_50_second_blackhole_and_connects_after_it`(`crates/qsh-testkit/tests/`, chaos proxy)다. 45초를 넘는 blackhole이라 peer는 idle timeout으로 connection을 걷는다. blackhole 동안 1초 간격 탐침이 로컬 포트에 붙어 한 번도 connection refused가 아님(REP `0x01`이나 RST)을 단언한다. 탐침 간격은 고정 대기가 아니라 조건 탐침이다. blackhole을 걷은 뒤에는 다음 시도의 예정 간격을 supervisor 관찰 채널로 보고 그 값이 `FAST_CAP` 이하임을 단언하고, SOCKS CONNECT 성공은 `FAST_CAP + REDIAL_DEADLINE`에 여유를 더한 `timeout` 안으로 단언한다(§4.1 #9). SIGSTOP이나 blackhole은 단조 시계를 멈추지 않으므로 이 테스트는 wake 경로를 부르지 않는다. `QSH_ACCEPTANCE_SLOW`가 없으면 skip 줄을 찍고 끝난다.

CI와 문서를 같은 커밋에서 고친다. `.github/workflows/ci.yml` acceptance job에 `reverse_blackout` 스텝과 같은 모양으로 이 testkit 테스트를 `QSH_ACCEPTANCE_SLOW: 1` 아래 한 스텝으로 더하고 strict로 둔다. `CLAUDE.md` Commands 절의 acceptance job 테스트 목록에 이 이름을 적는다. `docs/design/testing.md` L4 표에 "주입한 wake" 행과 "45초를 넘는 blackhole 뒤 supervised listener" 행을 더하고, `sleep()` 금지 문단의 의도적 벽시계 예외 목록과 `QSH_ACCEPTANCE_SLOW` 표 행에 이 테스트를 넣는다.

**(b) 테스트·게이트:** 위 두 테스트. Step 7의 테스트와 `reverse_blackout` 초록.

**(c) 완료 판정:** testkit 테스트가 `QSH_ACCEPTANCE_SLOW=1` 아래 CI acceptance job에서 한 번 이상 초록. 두 테스트가 부하 아래 50회 연속 초록(느린 테스트는 약 50분이 든다). mutation 하나(결정 5의 listener 유지를 빼고 유실 때 listener를 놓기)가 testkit 테스트를 붉힌다. `grep -n 'supervised_dynamic_listener_stays_bound' CLAUDE.md .github/workflows/ci.yml docs/design/testing.md`가 각 1건 이상.

### Step 9 — accept 유지 `--accept-hold` (0.2ew)

근거 ADR: ADR-0023 결정 6(예외), 19. 선행: Step 7.

**(a) 범위:** 켠 터널은 "끊김" 동안 accept한 연결을 곧바로 거절하지 않고 최대 `accept_hold_ms` 동안 쥔다. 조건은 재수립 시도가 진행 중이거나 다음 시도가 그 기한 안에 시작되는 경우다. 창 밖의 긴 backoff 대기 중에 들어온 연결은 쥐지 않고 결정 6대로 즉시 거절한다. 쥐는 동안 바이트를 어느 carrier로도 보내지 않는다. `-L`은 소켓을 읽지 않고 두고, `-D`는 SOCKS 인사와 CONNECT 요청을 로컬에서 읽은 뒤 `TCP_CONNECT`를 보내기 전에 멈춘다. carrier가 7-2·7-3을 통과해 "살아 있음"이 되면 accept 순서대로 새 carrier에 싣고, 기한이 먼저 오면 결정 6 방식으로 거절한다. 동시에 쥐는 연결은 터널당 64개까지이고 넘치면 즉시 거절한다. 기한 타이머는 tokio 시계다.

`supervise_on_an_unsupported_route_or_mode_is_unsupported_before_connecting` 표에서 forward `accept_hold_ms` 행을 뺀다. `docs/CLI.md` §6.9 옵션 문단과 §6.14 supervised 예외 문단에 결정 19를 적는다. `docs/design/threat-model.md` §4 C에 쥔 accept의 파일 기술자 행(통제 2초·64개 상한)을 더한다.

**(b) 테스트·게이트:** 단위와 crate 내부 통합(paused 시계 가능한 것은 paused로). `accept_hold_zero_keeps_the_immediate_rejection_of_decision_6`, `accept_hold_dispatches_a_held_connect_once_the_carrier_is_confirmed`, `accept_hold_rejects_at_the_deadline_without_sending_a_byte_to_any_carrier`, `accept_hold_rejects_past_sixty_four_held_connections`, `accept_hold_is_not_used_during_a_backoff_wait_longer_than_the_hold`, `accept_hold_preserves_accept_order_on_dispatch`. Step 5의 `accept_hold_without_supervise_or_above_two_thousand_or_on_remote_is_invalid_argument_before_bind` 초록.

**(c) 완료 판정:** 위 테스트 초록과 부하 아래 50회 연속 초록. "쥔 동안 carrier로 가는 바이트 0"을 carrier 쪽 카운터로 단언한다.

### Step 10 — `qsh::lifecycle` 수명 줄 (0.15~0.2ew)

근거 ADR: ADR-0023 결정 21, 결정 1의 유일한 예외. 선행: Step 7(`supervise` 필드의 값이 참이 되는 자리).

**(a) 범위:** tracing target `qsh::lifecycle`의 한 줄 JSON을 더한다. 첫 키 `lifecycle`, 값 `listening`·`shutting_down`·`tunnel_opened`·`tunnel_ended`. 모든 줄에 `at`(RFC3339 초 단위, `crate::config::now_rfc3339`)과 `process`(`serve`·`listen`·`serve_to`·`tunnel`)가 붙는다. `tunnel_*`은 `tunnel_id`·`mode`·`supervise`(bool), `tunnel_ended`는 `code`와 알 수 있으면 `cause`를 싣는다. 주소, bind 주소, 토큰, 오류 본문은 싣지 않는다. 사람용 줄 `qsh serve: listening on {addr}`, `qsh listen: listening on {addr}`, `… shutting down`, `the connection carrying this tunnel closed: …`의 바이트는 그대로다. `--supervise`와 무관하게 모든 holder와 두 데몬, `serve --to`에 붙는다. 이벤트를 내는 판단은 `qsh-core`에 두고, `main.rs`는 이미 사람용 줄을 쓰는 자리에서 `qsh-core`가 준 함수를 부르기만 한다. `init_tracing`에 전용 layer와 `{default},qsh::lifecycle=info` 필터, human layer 제외를 더한다.

`docs/CLI.md` §6.12와 §6.13에 `qsh::lifecycle` 문단을 더한다(열린 어휘, stdout에 쓰지 않음, §2.2).

**(b) 테스트·게이트:** L6(`crates/qsh-cli/tests/`). `serve_and_listen_listening_lines_are_byte_identical_and_a_lifecycle_line_carries_at`, `a_default_mode_tunnel_end_emits_a_lifecycle_line_with_code_and_no_address`, `quiet_suppresses_lifecycle_lines`, `serve_to_emits_listening_and_shutting_down_lifecycle_lines`. `LISTENING_PREFIX`·`LISTEN_LISTENING_PREFIX`를 쓰는 기존 하네스와 `jsonl_purity.rs` 초록.

**(c) 완료 판정:** 위 테스트 초록과 부하 아래 50회 연속 초록. `crates/qsh-cli/tests/common/mod.rs`의 두 접두 상수 diff 0.

### Step 11 — `qsh serve --to` wake reset과 `qsh::reverse` `wake` 줄 (0.15~0.2ew)

근거 ADR: ADR-0023 결정 17, 20, ADR-0022 결정 5. 선행: Step 3.

**(a) 범위:** target의 `Backoff`(`crates/qsh-core/src/reverse/target/mod.rs`)에 wake라는 두 번째 reset 지점을 더한다. wake가 오면 `reset()`해 `backoff_initial_ms`부터 다시 세고, 진행 중인 `wait_backoff` 대기를 끊어 즉시 재dial한다. `wait_backoff`의 `select!`에는 wake 구독 arm을 넣는다. wake 뒤 60초 동안 지연은 `max(backoff_initial_ms, 2000)`을 넘지 않고, 설정한 `backoff_max_ms`가 그보다 작으면 그 값이 이긴다. 60초는 단조 시계로 잰다. 창은 wake에만 열고 유실마다 열지 않는다. `[reverse]` 키와 기본값은 그대로이고 옵션도 없다. `qsh::reverse` 줄에 `event=wake`(`slept_ms`, `at`)를 더한다. target의 `PathWatch`는 Step 3으로 이미 wake 뒤 곧바로 판정한다. `target/mod.rs`는 이미 `target/tests.rs`를 쓴다.

`docs/CLI.md` §6.13의 이벤트 목록(`registered|denied|replaced|lost|expired|retry`)에 `wake`를, target의 wake 뒤 backoff 규칙을 더한다. `docs/design/protocol.md` §11-4의 backoff 문장에 "wake 뒤 초기값으로 되돌리고 60초 동안 2초 상한"을 더한다.

**(b) 테스트·게이트:** 단위(paused 시계, 고정 seed, `target/tests.rs`). `target_backoff_restarts_from_backoff_initial_on_wake_and_cuts_the_pending_delay`, `target_fast_window_never_exceeds_a_configured_backoff_max_below_two_seconds`, `target_fast_window_opens_on_wake_only_not_on_loss`. crate 내부 통합(M11의 `reverse/test_harness.rs`, 주입 wake). `serve_to_target_probes_and_redials_at_once_after_an_injected_wake`. 기존 proptest `backoff_sequence_is_monotone_nondecreasing_until_the_cap`과 `reset_returns_the_sequence_to_initial`, M11의 `quinn_idle_timeout_as_idle_timeout` 두 테스트 초록.

**(c) 완료 판정:** 위 테스트 초록과 부하 아래 50회 연속 초록. `docs/CLI.md` §6.13 이벤트 목록에 `wake`가 있다. `[reverse]` 설정 키 diff 0.

### Step 12 — 첫 단위 운영 문서와 `p1-supervise-wake` 캠페인 사전 고정 (0.1ew)

근거 ADR: ADR-0023 결과 절(캠페인 항목, `docs/deploy/service.md`), §5.1 원칙 6. 선행: Step 7~11.

**(a) 범위:** `docs/campaigns/p1-supervise-wake.md`를 사전 고정해 커밋한다. 결과 절의 회차 넷, 재현 절차(`pmset relative wake <s>` 뒤 `pmset sleepnow`, Linux는 `rtcwake -m mem -s <s>`), 망 복귀 시각(VPN 너머 hub로 200ms마다 보내는 ping의 첫 응답), 판정 셋(1초 주기 탐침의 connection refused 0회, 망 복귀 뒤 새 SOCKS CONNECT 성공 시각의 회차 안 중앙값 2초 이하·최댓값 4초 이하, 끊김 시간이 `lost`·`wake`·`reestablished` 줄만으로 계산됨), 기록 표를 적는다. 넷째 회차는 둘째 단위(Step 14) 착지 뒤 트리에서만 돈다고 적는다. 형식은 `docs/campaigns/m9-stopwatch.md`를 따른다. `docs/deploy/service.md`에 launchd·systemd 배치 예시(`--supervise`와 service manager 재시작을 함께 쓰는 모양)를 더한다. `CLAUDE.md` 문서 지도의 `docs/campaigns/` 목록에는 `p1-supervise-wake`를 넣는다. main 세션은 이 착지 뒤 이슈 #6에 결정 24의 순서와 대응표로 답한다(DoD 밖).

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록.

**(c) 완료 판정:** 캠페인 파일이 있고 판정 기준이 ADR-0023 결과 절의 숫자와 같다. `grep -c 'p1-supervise-wake' CLAUDE.md` 1.

---

둘째 단위(ADR-0023 결정 24): reverse route(`--local`, `--dynamic`, `--remote`)와 forward route `--remote`. 결정 7-4, 7-5, 14, 16, 22.

### Step 13 — peer `RemoteForwardClose` 응답 시점 수정 (0.1ew)

근거 ADR: ADR-0023 결정 16. 선행: 없음.

**(a) 범위:** `Server::handle_rfwd_close`(`crates/qsh-core/src/server/reverse.rs`)가 abort한 forward task가 실제로 끝나 listener가 drop된 뒤에 성공 응답을 보내게 고친다. `entry.task.abort()` 뒤 그 `JoinHandle`을 기다린다(cancel 결과는 무시). wire와 응답 모양은 바뀌지 않는다. 기다림에는 상한을 두고(§4.1 #6), 상한을 넘으면 지금처럼 응답한다. `Server::purge_connection` 경로는 건드리지 않는다.

**(b) 테스트·게이트:** crate 내부(`crates/qsh-core/src/server/tests.rs`). `rfwd_close_success_means_the_port_can_be_bound_immediately`(close 응답 직후 같은 포트 bind 성공을 반복 100회 단언), `rfwd_close_by_another_principal_under_owned_scope_is_permission_denied_and_the_listener_stays`(ROADMAP M12 DoD (a)의 `authorize_owned` 문장), `rfwd_close_of_a_purged_forward_id_is_no_such_forward_id`. 기존 `purge_connection_removes_and_aborts_this_connections_remote_forwards` 초록.

**(c) 완료 판정:** 위 테스트 초록과 부하 아래 50회 연속 초록. `.proto` diff 0.

### Step 14 — reverse route supervisor: `-L`과 `-D` (0.35~0.4ew)

근거 ADR: ADR-0023 결정 2, 4(reverse), 6, 7-1, 7-2, 7-5, 9, 12, 22. 선행: Step 7, Step 13.

**(a) 범위:** reverse route로 연 supervised `-L`/`-D`를 켠다. 유실 신호는 `LOCAL_CONTROL` conduit 종료, 7-5의 accept별 신원 불일치, 데몬 socket 연결 실패다. migration은 없다. 재수립은 시도마다 이 머신의 `qsh listen` 데몬 socket만 다시 찾는다. §6.1 우선순위 전체를 다시 타지 않으므로 같은 이름의 forward pin을 한 번도 dial하지 않는다(결정 4 셋째 항목, 22). 탐색 함수는 `resolve_route`의 reverse 쪽 절반을 떼어 쓰고 forward 분기를 호출하지 않는다. socket이 직전과 같으면 `LocalHello.known_generation`에 마지막 확인 generation을 싣고, 바뀌었으면(데몬 재시작) 싣지 않고 7-2에 기댄다. `LocalHello.wait_ms`는 남은 예산과 `LOCAL_WAIT_MAX`(60초) 중 작은 값이다. `LocalHelloAck.peer_fingerprint`가 최초 값과 다르면 `AUTH_FAILED`로 끝낸다. `HOST_NOT_FOUND`는 stale·미설정 둘 다 재시도하고 `TIMEOUT`·`CONNECTION_FAILED`도 재시도한다(결정 9 표). 예산은 `stale_retention`으로 깎지 않는다.

accept마다 여는 `LOCAL_STREAM` conduit의 `LocalHelloAck`(`peer_fingerprint`, `generation`)를 carrier의 확인된 신원과 대조한 뒤에만 `StreamHeader`를 보낸다. 다르면 그 accept를 결정 6대로 거절하고 carrier를 "끊김"으로 바꾼 뒤 1단계부터 다시 한다. 이를 위해 `localctl::client`의 `DataHandshake`를 ack 확인과 header 전송 사이에서 나눈다. `crates/qsh-core/src/localctl/client.rs`는 `xtask arch`의 정확한 파일 금지 대상이므로 파일을 디렉터리로 바꾸지 않고 안에서만 고친다. `qsh.local.v1`은 바뀌지 않는다. 진단 줄은 `route: "reverse"`와 `host`(별칭 이름), `reestablished`의 `generation`을 싣는다.

`supervise_on_an_unsupported_route_or_mode_is_unsupported_before_connecting` 표에서 reverse `-L`/`-D` 행을 뺀다. `docs/CLI.md` §6.14 supervised 예외 문단에 reverse route 문장(forward pin을 보지 않음, accept별 대조)을, README Known limitations에 "최초 open의 route는 §6.1을 따르므로 reverse 전용 host는 pin에 주소를 두지 않아야 reverse route로 열린다(결정 22)"를 더한다. `docs/design/threat-model.md` §4 A의 peer 치환 행에는 reverse 통제(결정 7-5)와 핀 테스트 이름을 적는다. §6.1은 고치지 않는다.

**(b) 테스트·게이트:** testkit(`ReverseHarness`, `crates/qsh-testkit/tests/`). `supervised_reverse_local_reestablishes_after_the_target_reregisters`, `supervised_reverse_local_reestablishes_after_a_listen_daemon_restart`, `supervised_reverse_local_reestablishes_after_a_gap_longer_than_stale_retention`(7-1. `stale_retention`을 테스트 설정으로 짧게 둔다), `supervised_reverse_local_sends_no_byte_to_a_device_that_reregistered_under_the_same_name_with_another_fingerprint`(결정 6·7-2·7-5. 그 장비 쪽 accept 카운터 0과 supervisor 종료), `supervised_reverse_route_local_never_dials_a_forward_pin_while_the_registration_is_stale_or_swept`(결정 22. blackhole 주소의 forward pin을 두고 pin 주소로 가는 dial 0회와 `reestablished`), `supervised_reverse_dynamic_reestablishes_and_keeps_the_host_local_filter`, `supervised_with_wait_still_caps_the_initial_wait_to_stale_retention`(결정 2), `supervise_lines_on_reverse_route_carry_host_and_a_generation_that_matches_the_registered_line`(결정 12·23), `supervise_wake_line_reports_slept_ms_and_outage_ms_excludes_it`. 기다림은 `qsh::reverse`·`qsh::tunnel::supervise` 줄과 하네스 이벤트로 한다. 기존 `tunnel_open_local_over_reverse_ends_when_the_registration_drops`, `local_forward_primitive_over_reverse_survives_a_registration_drop_and_self_heals_per_connection`, `tunnel_open_wait_returns_the_same_stale_error_once_the_budget_expires`, `resolve_route_reverse_prefers_the_live_daemon_over_a_forward_pin`, `dash_d_over_reverse_filters_loopback_and_the_target_sees_no_accept` 초록.

**(c) 완료 판정:** 위 테스트 초록과 부하 아래 50회 연속 초록. mutation 하나(7-5의 ack 대조 제거)가 fingerprint 치환 테스트를 붉힌다. `git diff --stat -- crates/qsh-proto/proto`가 비어 있다.

### Step 15 — `-R` close-then-open과 운영자 닫기 (0.4~0.45ew)

근거 ADR: ADR-0023 결정 7-4, 9(예외 둘), 11(`-R` 종료), 13, 14, 15, 24. 선행: Step 13, Step 14.

**(a) 범위:** forward route와 reverse route의 supervised `--remote`를 켠다. 새 carrier 위에서 먼저 `RemoteForwardClose{직전 forward_id}`를 보내고, 성공과 "no such forward_id"(`INVALID_ARGUMENT`)를 둘 다 옛 forward가 없어졌다는 뜻으로 읽는다. 이어 `RemoteForwardOpen`을 `bind_host`·`forward_host`·`forward_port`는 최초 요청 그대로, `bind_port`는 최초 `actual_port`로 보낸다. `claim_token`은 새로 만든다. 같은 시도 안에서 close가 성공했거나 "no such"였는데 open이 bind 실패 `CONNECTION_FAILED`를 받으면 200ms 간격으로 3번까지 open만 다시 보내고, 그래도 실패하면 끝낸다(구버전 peer 대응). 그 간격 타이머는 tokio 시계다. 재발행은 peer choke point에서 `forward.remote` 판정, loopback 강제, quota 예약을 지금처럼 밟는다. `reestablished` 줄에는 `previous_tunnel_id`를 싣되 봉투의 `tunnel_id`는 최초 값 그대로다.

운영자 닫기(결정 14). reverse route의 `-R`에서 claim 시도가 대기 없이 곧바로 돌아왔는데 `LOCAL_CONTROL`이 살아 있으면 `LOCAL_ADMIN`의 `LocalHostList`와 `LocalTunnelList`를 한 번씩 조회한다. host가 확인된 generation 그대로 `reachable`이고 현재 `forward_id`만 없으면 운영자 닫기로 보고 `closed` 줄을 낸 뒤 listener 없이 exit `0`으로 끝난다. 등록이 바뀌었거나 사라졌으면 유실로 본다. SIGTERM 때 살아 있는 carrier가 있으면 best-effort `RemoteForwardClose`를 보내되 1초를 넘겨 기다리지 않는다.

`supervise_on_an_unsupported_route_or_mode_is_unsupported_before_connecting`을 지운다(결정 24, 결과 절 "둘째 단위가 이 테스트를 지운다"). `docs/CLI.md` §6.9와 §6.14에 `-R` 문장(재발행마다 `tunnel_id`가 바뀜, 현재 값은 `reestablished` 줄과 reverse route의 `qsh tunnels`, 결정 14의 닫기 규칙, 최초 `tunnel_id`로 닫으면 `closed: false`), README Known limitations에 `-R` 몫 둘(포트를 지킬 수 없으면 끝남, 재발행마다 `tunnel_id`가 바뀜)을 더한다. `docs/design/protocol.md` §16.4의 ADR-0018 결정 3 항목에 "ADR-0023은 이 길을 쓰지 않았다" 한 줄을 적는다. `docs/design/threat-model.md` §4 B에 재발행 소유 행(통제 `authorize_owned`, 결정 8, 핀 테스트 이름, `scope = "any"` 행을 가진 principal은 오늘도 남의 forward를 닫을 수 있으므로 켠 터널이 새 권한을 만들지 않는다는 문장)을 넣는다.

**(b) 테스트·게이트:** testkit과 crate 내부 통합. `supervised_forward_remote_reissues_before_the_peer_idle_timeout_and_regains_the_same_port`(7-4), `supervised_remote_reissue_survives_a_delayed_listener_drop_via_bounded_open_retries`(test binder로 listener drop을 늦춰 경합을 만든다), `supervised_ephemeral_remote_reissue_is_permission_denied_when_the_policy_allows_only_port_zero`, `supervised_remote_ends_when_another_principal_took_the_port_during_the_outage`(ROADMAP DoD 문장), `supervised_remote_reestablished_line_carries_a_new_tunnel_id_and_previous_tunnel_id_and_qsh_tunnels_shows_the_new_one`(결정 13), `supervised_reverse_remote_closed_by_qsh_tunnel_close_emits_closed_and_exits_zero_without_reopening`(결정 14), `supervised_reverse_remote_registration_loss_is_not_read_as_an_operator_close`, `supervised_remote_sigterm_sends_a_best_effort_close_the_peer_receives`(결정 11), `supervised_reverse_remote_reissues_after_the_target_reregisters`(7-1). 기존 `tunnel_open_local_over_reverse_ends_when_the_registration_drops`, `admin_close_forward_removes_the_registration_and_notifies_the_target_exactly_once` 초록.

**(c) 완료 판정:** 위 테스트 초록과 부하 아래 50회 연속 초록. `grep -rn 'supervise_on_an_unsupported_route_or_mode' crates/` 0건. `git diff --stat -- crates/qsh-cli/tests/fixtures crates/qsh-proto/proto`가 첫 단위 시작부터 누적으로 비어 있다. main 세션은 이 착지 뒤 이슈 #4 코멘트 질문 1·2·3에 supervised 몫과 결정 22가 넘기는 몫, 주소 없는 pin 우회로를 나눠 답한다(DoD 밖).

---

ADR-0024 `qsh setup`.

### Step 16 — m9 재측정 대상 트리 SHA 고정 (0.05ew)

근거 ADR: ADR-0024 결정 12, 결과 절(README는 SHA 고정 뒤), `docs/ROADMAP.md` M12 수용 기준 (b) 둘째 항목. 선행: Step 15(또는 (a)가 끝나지 않았어도 (b)를 먼저 시작할 때는 그 시점 main). 이 스텝 다음 커밋이 Step 17이어야 한다.

**(a) 범위:** `docs/campaigns/m9-stopwatch.md` §8 표의 m9 재측정 열 제목 "현재 바이너리"를 "고정 트리"로 바꾸고 "qsh 커밋 SHA" 칸에 이 커밋의 부모 SHA(착지 직전 origin main의 HEAD, 아래 B)를 적는다. 같은 절에 한 문단을 더한다. 측정 대상은 B 트리의 바이너리와 README "First run" 절이다. B와 이 커밋(P)의 차이는 이 캠페인 파일 하나뿐이므로 두 트리의 바이너리와 README는 같다. `qsh setup`의 첫 코드 커밋은 P의 직계 자식이다. §7이 README나 제품 수정을 요구하면 B에 그 수정만 얹은 트리를 새 대상으로 삼고 그 SHA를 §8에 적는다(ADR-0024 결정 12). M7·M9 캠페인의 §5 기준은 그대로다.

B와 P 사이를 한 커밋으로 두는 이유는 ADR 문면 "첫 코드 커밋의 부모"를 문자 그대로 한 커밋 안에 적을 수 없기 때문이다. P는 자기 SHA를 담을 수 없다. 그래서 "B를 적고, P는 B에 캠페인 파일만 더한 커밋이고, Step 17의 부모는 P다"라는 세 사실로 같은 보장을 만든다(§8 #1). main 세션은 P와 Step 17 사이에 다른 커밋이 끼지 않도록 두 커밋을 연달아 착지시킨다. 다른 에이전트의 커밋이 끼면 Step 17을 P 위에 다시 올리지 않고, 끼어든 커밋이 `crates/`, `README.md`, `docs/CLI.md`를 건드리지 않았음을 Step 17 커밋 본문에 `git diff --stat P <Step 17 부모>`로 입증한다.

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록.

**(c) 완료 판정:** `git diff --name-only B P`가 `docs/campaigns/m9-stopwatch.md` 한 줄. §8의 SHA 칸이 B다. `grep -n '현재 바이너리' docs/campaigns/m9-stopwatch.md`의 §8 표 머리 0건.

### Step 17 — `setup.run` 계약 타입, 초대 읽기 도우미, arch 금지 (0.3~0.35ew)

근거 ADR: ADR-0024 결정 1, 3, 5, 8, 9. 선행: Step 16. `qsh setup`의 첫 코드 커밋이다.

**(a) 범위:** `crates/qsh-proto`에 `SetupRunReq`, `SetupRunData`(`role`, `complete`, `steps`, `acl_rows` 선택, `next`), `SetupStep`(`id`, `status`, `command`, `detail` 선택, `result` 선택)을 더한다. 단계 id(`identity`·`mode_config`·`acl`·`pin_cert`·`pair`·`invite`·`service`·`doctor`)와 상태(`done`·`already`·`pending`·`blocked`·`skipped`)는 닫힌 목록이고 추가만 허용한다. `result`는 부른 op의 `data`를 그대로 담는 열린 JSON이다.

`qsh-core`에 초대 읽기 도우미를 신설한다. 만료되지 않은 미상환 초대 수를 `assigned_name`별로만 돌려주고 `mac_key`는 노출하지 않는다(결정 5). 자리는 invite store 옆이다.

`crates/qsh-core/src/setup/` 디렉터리 모듈의 뼈대(`mod.rs`, `tests.rs`)를 만들고 `xtask/src/arch.rs`에 디렉터리 범위 금지를 더한다. 금지 토큰은 `acl_file`, `fs::write`, `File::create`, `OpenOptions`, `write_private_file`, `write_atomically`, `.save(`, `probe_fingerprint` 여덟이다. 자기 테스트는 `broker/` 중첩 디렉터리 자기 테스트의 형식을 따라 더하고, 그 파일이 경고한 `//` 주석 제거 방식을 새 범위에서 다시 확인한다. `CLAUDE.md`의 "`xtask arch`'s module bans are path-scoped" 문장에 `crates/qsh-core/src/setup/`을 넣는다.

**(b) 테스트·게이트:** xtask 자기 테스트 `module_ban_flags_every_forbidden_token_under_setup_including_nested_directories`와 `module_ban_ignores_forbidden_tokens_in_setup_comments`. 단위 `live_unassigned_invite_count_never_exposes_mac_key`, `live_invite_count_excludes_expired_and_redeemed_invites`. `cargo xtask arch` 초록.

**(c) 완료 판정:** 위 테스트 초록. 이 커밋의 부모가 Step 16(P)이거나 §16 (a)의 예외 증거가 커밋 본문에 있다. `grep -n 'setup/' xtask/src/arch.rs` 1건 이상.

### Step 18 — `Ops::setup_plan`과 `Ops::setup_step`: 네 역할 (0.6~0.7ew)

근거 ADR: ADR-0024 결정 1~10, ADR-0017 결정 1·3·5, ADR-0012 결정 1·6, ADR-0013 결정 4, ADR-0014 결정 7, ADR-0019 결정 6, ADR-0025 결정 6. 선행: Step 17.

**(a) 범위:** `crates/qsh-core/src/setup/`에 판단 로직 전부를 둔다. 읽기 전용 `Ops::setup_plan`이 현재 상태에서 단계 목록과 상태를 계산하고, `Ops::setup_step`이 단계 하나를 기존 `Ops` 메서드(`identity_init`, `trust_invite`, `trust_accept`, `trust_add`, `service_install`, `doctor`)로 실행한다. 읽기는 `trust_list`, `acl_check`, `service_status`, `Ops::config()`, Step 17의 초대 도우미뿐이다.

역할 표(결정 2)와 단계 순서(결정 8)를 그대로 옮긴다. `host`는 `identity → mode_config → acl → service → invite(또는 pin_cert) → doctor`, `host --to`는 `identity → pin_cert → mode_config → acl → service → doctor`, `client`는 `identity → pair(또는 pin_cert) → doctor`, `listener`는 `identity → pin_cert → mode_config → acl → service → doctor`. `mode_config`와 `acl`은 읽기만 하므로 앞 단계가 `pending`이어도 평가한다.

ACL 단계(결정 4·5). 행은 `policy_example_rows`로 만들고 principal은 `device:<name>`이다. host 두 역할의 `--forward`는 allow 목록에 `forward.local` 하나를 더하고 `Role`에 variant를 더하지 않는다. 검증은 action마다 `acl_check`(`--auth-path pin`)이고 전부 allow면 충족이다. `policy.loaded: false`나 deny가 하나라도 있으면 `pending`이고 `detail`에 거부 action을 적는다. 충족일 때마다 `ACL_RESTART_NOTICE`를 붙인다. `host`에서는 만료되지 않고 `assigned_name`이 없는 미상환 초대가 하나라도 있으면 충족이 아니고 `detail`에 TTL(10분)을 적는다. `qsh setup`이 발급하는 초대는 항상 `--as <name>`을 단다.

신뢰(결정 3·6). `TrustAddReq`는 항상 `cert_pem`을 채운다. `--peer-cert`는 쓰기 전에 fingerprint를 계산해, 같은 이름이 다른 fingerprint로 있거나 같은 fingerprint가 다른 이름으로 있으면 `trust_add`를 부르지 않고 `pending`이다. `pair`는 이름이 이미 있으면 다이얼하지 않고 `already`, `trust_accept` 뒤 같은 fingerprint가 다른 이름에도 있으면 `pending`이다.

재실행(결정 8). 쓰는 단계가 모두 `already`나 `skipped`면 config 디렉터리와 유닛 경로의 어떤 파일도 바꾸지 않는다. 상환 전 `host` 재실행만 새 코드를 발급하고 `detail`에 살아 있는 같은 이름 코드 수를 적는다. exit·오류 규칙(결정 10). op 실패는 그 op의 `code`·`retryable` 그대로이고 `details.step`, `details.steps`(id와 상태만, `result` 없음)를 additive로 더한다. service op의 `UNSUPPORTED`는 `skipped`다. `SetupRunOp`(`impl Operation`, `COMMAND = "setup.run"`)을 두고 `ops/mod.rs`·`lib.rs`가 재수출한다.

**(b) 테스트·게이트:** `crates/qsh-core/src/setup/tests.rs`와 `crates/qsh-core/tests/`. ADR-0024 결과 절의 이름을 그대로 쓴다. `setup_never_writes_acl_toml_in_any_role`(네 역할, `acl.toml` 있음·없음, 존재와 바이트 동일), `setup_rerun_after_completion_changes_no_file`, `setup_invite_always_carries_assigned_name`, `setup_acl_step_pending_while_unassigned_invite_is_live`, `setup_refuses_second_name_for_pinned_fingerprint`, `setup_pin_cert_pending_on_fingerprint_mismatch`, `setup_pair_pending_on_duplicate_fingerprint`, `setup_trust_add_always_carries_cert_pem`, `setup_mode_config_pending_on_wrong_run_mode`(`[serve].to`가 `--to`와 다른 경우 포함). 더하는 것. `setup_printed_rows_pasted_verbatim_make_acl_check_allow_every_intended_action`(네 역할과 `--forward`), `setup_acl_step_appends_the_acl_restart_notice_byte_for_byte`, `setup_op_failure_keeps_code_and_retryable_and_adds_step_ids_without_results`, `setup_service_unsupported_is_skipped`. 기존 `minimal_policy_example_fills_in_actual_pinned_peer_names`와 doctor 두 remedy 테스트(`acl_restart_notice_is_the_verbatim_tail_of_both_acl_diagnostic_remedies`) 초록. 파일 시스템 샌드박스는 테스트마다 따로 두고 시간 의존 경로(초대 만료)는 주입 시계로 돈다.

**(c) 완료 판정:** 위 테스트 초록과 초대 만료 테스트의 부하 아래 50회 연속 초록. `cargo xtask arch` 초록(금지 토큰 0). `git grep -n 'probe_fingerprint' crates/qsh-core/src/setup` 0건.

### Step 19 — `qsh setup` CLI, fixture, 계약 문서 (0.5~0.6ew)

근거 ADR: ADR-0024 결정 2, 7, 9, 10, 11과 결과 절. 선행: Step 18.

**(a) 범위:** clap에 `qsh setup <role>`과 역할별 인자(`--peer`, `--peer-cert <path|->`, `--to`, `--address`, 위치 인자 `<code>`, `--code-stdin`, `--forward`, `--service`)를 더한다. 코드와 `--peer-cert`를 함께 주거나, `--forward`·`--service`를 해당하지 않는 역할에 주거나, 위치 코드와 `--code-stdin`을 함께 주면 exit `2`다. 렌더러 `print_setup_run`은 단계 표, 인쇄할 `acl_rows`, `next`를 찍는다. human mode 프롬프트는 다섯(역할, pin 이름, 에코 없는 초대 코드, `acl.toml` 저장 확인, 서비스 설치 여부 기본 아니오)뿐이고 stderr로 묻는다. 표준입력이 터미널이 아니거나 `--peer-cert -`면 프롬프트를 열지 않고 빠진 입력은 `INVALID_ARGUMENT`다. machine mode는 envelope 하나를 내고 프롬프트가 없다. 첫 단계 전에 입력 전부를 검증하고 틀리면 아무것도 쓰지 않는다. `qsh serve`·`qsh listen`·대화형 세션을 띄우지 않는다. 판단은 모두 Step 18의 `Ops`가 하고 CLI는 계획이 요구한 입력만 받아 다음 단계를 부른다.

계약 델타를 같은 커밋에 싣는다. `docs/CLI.md` §2.4 목록, §2.5 "인가 불요" 행에 `setup.run`, 새 §6.20 "`qsh setup`"(역할 표, 단계 id·상태 어휘 표, exit 규칙, `setup`이라는 host 별칭이 이 서브커맨드에 가려진다는 사실). 번호는 M11의 §6.19 `acl show` 다음이다(ADR-0024 결과 절). 상태 헤더 v0.15 항목에 덧붙인다. `docs/PRD.md` §11 명령 체계 표에 `qsh setup` 행을 넣는다. fixture `setup.run.host_pending_acl.json`, `setup.run.client_complete.json`, `setup.run.listener_pending_acl.json`, `error.INVALID_ARGUMENT.setup_missing_input.json`을 더하고 `REQUIRED_FIXTURES`에 등재하고 생산 테스트 `golden_setup_run_fixtures`를 둔다(비결정 값은 §4.1 #7). `CLI_V1_SCHEMA_COMMANDS`, `cli_v1_data_schema` arm, `crates/qsh-core/tests/op_registration_completeness.rs`의 `OP_FACES` 행(`op: "setup.run"`, `marker: "SetupRunOp"`, `renderer: "print_setup_run"`, `cli_spelling: "qsh setup"`, `man_file: "qsh-setup.1"`), `crates/qsh-core/tests/acl_registry.rs`의 인가 불요 목록. `cargo xtask man`으로 `docs/man/qsh-setup.1`을 만든다. `docs/design/threat-model.md` §3 진입점 표에 local-only 행, §7에 잔여 위험 둘(사람이 `qsh setup` 밖에서 `--as` 없는 초대를 TTL 안에 발급하는 경우, `host` 역할 상환 뒤 생긴 fingerprint 중복은 responder 고지로만 드러남)과 핀 테스트 이름.

**(b) 테스트·게이트:** L6(`crates/qsh-cli/tests/setup.rs` 신설). `setup_machine_mode_rejects_missing_input_before_any_write`(stdout envelope 한 줄, 파일 0개), `setup_machine_mode_never_opens_a_prompt`(stdin을 닫은 채 `--json`), `setup_output_never_carries_key_material`(네 역할의 stdout·stderr·오류 envelope. 초대 코드는 `host`의 `invite` 단계 `result`에만), `setup_usage_conflicts_exit_2`, `setup_human_mode_without_a_tty_treats_missing_input_as_invalid_argument`, `setup_step_vocabulary_matches_cli_md`(`crates/qsh-core/tests/doctor_docs.rs`의 잠금 어휘 규율), `setup_run_never_appears_as_a_control_message_wire_variant`. `crates/qsh-cli/tests/exit_code_matrix.rs`에 새 행. fixture 생산 `golden_setup_run_fixtures`. 등록 게이트 `layer_2_every_schema_command_has_all_six_faces`, `section_2_4_fence_matches_every_implemented_operation_bidirectionally`, `every_implemented_operation_has_a_schema_or_a_documented_exclusion`, `registry_matches_cli_md_section_2_5_bidirectionally`, `checked_in_man_pages_match_the_generator`, `every_error_code_is_covered_by_a_fixture_or_explicitly_deferred` 초록.

**(c) 완료 판정:** 위 테스트 초록. `git diff --stat -- crates/qsh-cli/tests/fixtures`가 새 파일 넷만 보인다. `capabilities.json` diff 0. `grep -n '6.20' docs/CLI.md` 1건 이상.

### Step 20 — README `qsh setup` 절과 `p1-setup-stopwatch` 캠페인 사전 고정 (0.1~0.25ew)

근거 ADR: ADR-0024 결정 12와 결과 절. 선행: Step 16(SHA 고정), Step 19.

**(a) 범위:** README에 `qsh setup` 절을 새로 더한다. "First run" 절은 한 바이트도 고치지 않는다. m9 측정 대상은 Step 16의 고정 트리이고 그 절은 여전히 수동 경로의 정본이다. 새 절은 네 역할의 한 줄 예시, `acl.toml`은 쓰지 않고 행을 인쇄한다는 것, 자동 신뢰가 없다는 것, 재시작 고지를 적는다. `docs/campaigns/p1-setup-stopwatch.md`를 사전 고정해 커밋한다. 형식은 `m9-stopwatch.md` §3~§8을 계승하고 자동 신뢰 배제(§7)를 포함한다. 피실험자 지시 한 줄, 대상 문서 없음, 타이머 종료는 첫 원격 프롬프트, 합격은 3회 전부 300초 이내이고 중앙값이 같은 날 같은 진행자의 m9 3회 중앙값보다 짧을 것, 단계 기록표의 사람 구간과 기계 구간 분리. `CLAUDE.md` 문서 지도의 캠페인 목록에 `p1-setup-stopwatch`를 더한다.

**(b) 테스트·게이트:** README 축자 게이트(`readme_quotes_the_controller_unreachable_diagnostic_verbatim`, `readme_quotes_the_acl_startup_diagnostic_wording_verbatim`, `readme_quotes_the_dynamic_forward_acl_note_verbatim`) 초록. 기존 `identity.init.created.json`·`identity.init.existing.json` golden 초록.

**(c) 완료 판정:** `git diff <Step 16의 B> -- README.md`에서 "First run" 절 안의 변경이 0줄이다. 캠페인 파일의 합격 기준이 ADR-0024 결정 12와 같다. `grep -c 'p1-setup-stopwatch' CLAUDE.md` 1.

### Step 21 — 마감 (0.2ew)

근거: 마일스톤 마감 공통 절차(`docs/ROADMAP.md` §2) 1·2, §2의 안정성 규율. 선행: Step 2~20.

**(a) 범위:** 부하 반복. 이 마일스톤이 더한 타이밍 민감 테스트 전부(§4.1 #8의 filterset으로, Step 3·4·6·7·8·9·10·11·13·14·15·18의 테스트 이름을 한 filterset으로 묶은 것)를 `scripts/stress/run.sh`로 `QSH_ACCEPTANCE_SLOW=1`과 함께 50회 돌리고 "50/50 passed under load" 줄과 호스트 사양(OS, 논리 CPU 수)을 마감 노트에 적는다. 한 번이라도 붉으면 그 테스트를 고치고 50회를 처음부터 다시 돈다.

절차 1. 구속 문서 태그를 대조한다. `docs/CLI.md` v0.15 항목이 M12 델타(§6.9 두 옵션, §6.12·§6.13 `qsh::lifecycle`, §6.13 `wake` 이벤트와 target backoff 규칙, §6.14 supervised 예외, §2.4·§2.5·§6.20 `setup.run`)를 빠짐없이 적는지 본다. `docs/design/protocol.md` §2·§10·§11-4·§16.4, `docs/design/testing.md`(L4 두 행, 벽시계 예외, CI 규율의 부하 반복 항목), `docs/design/architecture.md` §2, `docs/design/threat-model.md` §3·§4 A·B·C·§7, `docs/PRD.md` §11, ADR-0023·0024의 결과 절 문서 목록 전수를 대조한다. §6.1이 무변경임을 확인한다. 절차 2. README를 동기화한다. 대상은 Status, Roadmap 표의 M12 행, Known limitations의 ADR-0023 여섯 한계, `qsh setup` 절이고 "First run" 절은 무변경이다. `docs/ROADMAP.md` M12 절에 마감 노트를 적고, §5.5 표 두 행의 상태를 갱신한다. 이 `PLAN.md`를 `docs/history/m12-plan.md`로 옮기고 다음 마일스톤 계획(M13)으로 교체한다.

**(b) 테스트·게이트:** 일곱 게이트와 CI acceptance job 초록. 부하 반복 50/50.

**(c) 완료 판정:** §1의 DoD가 근거 커밋과 함께 `[x]`다. `docs/history/m12-plan.md`가 있다. `git diff --stat <M12 Step 1>..HEAD -- crates/qsh-proto/proto`가 비어 있다.

## 3. 명시적 non-goals

- supervision을 기본값으로 켜는 것, 기본 모드 터널의 wake 감지와 `PathWatch`. ADR-0023 결정 1, 17, 대안 절.
- 대화형 form(`qsh [user@]host -L/-R/-D`)의 `--supervise`. ADR-0023 대안 절.
- `forward_id` 재claim(`reclaim`) wire 필드, `LocalHello`의 새 필드, 데몬의 자발적 `RemoteForwardOpen`. ADR-0023 결정 7-5, 15, 대안 절.
- 진행 중 TCP 연결의 생존(옛 connection이 살아나는 경우 밖), 최초 open 실패의 감독. ADR-0023 결정 2, 5.
- 플랫폼 절전 통지(IOKit, logind)와 interface·route 변화 관측. ADR-0023 결정 17, 18.
- §6.1 route 우선순위 변경과 pin의 "reverse 전용" 표시. ADR-0023 결정 22가 ADR-0030(M16 (a)) 또는 새 ADR로 넘겼다.
- 호스트를 넘는 복구 타임라인, `qsh.event/v1`의 supervise·lifecycle event. ADR-0023 결정 12, 23, ADR-0022 결정 3의 트리거 전.
- ADR-0021 결정 1·4의 구현과 `[recovery]` 개방. M13 (k)이고 §0.2의 관측 기록이 선행이다(ADR-0023 결정 25).
- `qsh setup`이 `acl.toml`·`config.toml`·`hosts.toml`을 쓰는 것, 관측 fingerprint의 y/n pin, `serve`·`listen`을 띄우는 것, 서비스 유닛 활성화, `acl show` 의존, SSH 키 가져오기. ADR-0024 결정 3, 6, 11.
- `qsh listen`의 초대 상환 창구. ADR-0015(예약).
- README "First run" 절의 개편. M7·M9 캠페인의 측정 대상이다(ADR-0024 결정 12).
- P2 항목 전부.

## 4. 리스크와 감시 항목

- **타이밍 테스트의 부하 민감성.** supervisor 통합 테스트는 실제 QUIC와 소켓을 쓴다. `8fd4602`가 드러낸 것처럼 부하 아래에서 RST와 connect 완료의 순서가 바뀌는 식의 경합이 새 테스트에도 생길 수 있다. 대응은 §2의 세 규율(시계 주입, 관찰 가능한 상태 대기, 벽시계 상한의 층 나눔)과 스텝마다의 50회 부하 반복이다. 부하 반복이 스텝 크기에 0.02~0.05ew씩 얹힌다.
- **ADR 테스트 문면과 층 나눔의 차이.** ADR-0023 결과 절은 `supervised_forward_carrier_is_declared_lost_within_two_seconds_of_an_injected_wake`가 `WAKE_TICK + min_dead_after + 500ms`를, 50초 blackhole 테스트가 "`FAST_CAP` 2초와 handshake 1회 안에 성공"을 단언한다고 적는다. 이 계획은 정확한 상한을 주입 시계 층에서 고정하고 통합 층은 경로 구별과 넉넉한 상한을 단언한다(§4.1 #9). 결과 절이 "이름은 제안이고 대응 결정은 doc에 적는다"고 하므로 결정 문면은 지켜지지만, 통합 층의 숫자가 느슨해지는 것은 ADR 결과 절의 문장과 다르다. 다르게 할 경우 Step 8 커밋 본문과 테스트 doc에 근거를 적는다(§8 #2).
- **50초 blackhole 테스트의 CI 시간.** acceptance job에 한 몫이 는다. nextest가 병렬로 돌리므로 `reverse_blackout`과 M11의 idle timeout 테스트와 겹쳐 늘어나는 것은 가장 긴 하나만큼이다. 문제가 되면 `load.yml`로 옮기고 `docs/design/testing.md`에 적는다.
- **`TunnelHold`와 supervisor의 drop 순서.** `TunnelHold`는 필드 선언 순서가 runtime drop 순서를 정한다(`forward`가 `conn`보다 먼저). carrier 교체로 connection이 여럿이 되면 옛 connection을 쥐는 자리와 drop 순서를 다시 적어야 한다. Step 7 (a)의 doc과 `supervised_local_splice_survives_a_short_blackhole_and_new_accepts_ride_the_new_connection`이 감시한다.
- **`localctl/client.rs`의 handshake 분리.** arch의 정확한 파일 금지 대상이라 파일을 옮기면 `cargo xtask arch`가 붉다. Step 14는 파일 안에서만 나눈다.
- **SHA 고정과 동시 커밋.** 다른 에이전트가 main에 커밋하는 동안 Step 16과 Step 17 사이에 커밋이 끼면 "부모"의 문자 그대로의 뜻이 깨진다. 대응은 Step 16 (a)의 연달아 착지와 예외 증거다.
- **`qsh setup` 테스트의 플랫폼 차이.** `service` 단계는 macOS LaunchAgent, Linux systemd user unit, 그 밖은 `skipped`다. CI에서 실제 서비스 매니저를 부르지 않도록 기존 `service` 테스트의 유닛 경로 주입 선례를 따른다.
- **Windows 다리.** reverse route와 wake 감지기의 Windows 전제(ADR-0023 결정 17)가 확인되지 않았다. 감지기는 Windows에서도 빌드되고 발화하지 않을 수 있다. 새 unix 전용 코드와 테스트는 cfg 가드 없이는 Windows clippy·test에서 붉다.

### 4.1 구현 중 확정할 값 (해당 step (a)에 근거와 함께 추기)

| # | 질문 | 초안 | 확정 시점 |
|---|---|---|---|
| 1 | wake 감지기의 자리와 공유 방식 | `crate::client::wake`(`WakeDetector`, `WAKE_TICK`, `WAKE_SKEW`, 벽시계 트레이트). 프로세스 하나에 하나를 `OnceLock`으로 두고 첫 구독 때 뜬다. 테스트는 `#[cfg(test)]` 설치 함수로 가짜 벽시계를 꽂는다 | Step 3 |
| 2 | supervisor 모듈 자리 | `crates/qsh-core/src/tunnel/supervise/`(디렉터리 모듈, `tests.rs`). `TunnelHold`가 부른다. target 상수 `qsh_core::tunnel::supervise::TARGET = "qsh::tunnel::supervise"` | Step 4 |
| 3 | supervise 관찰 채널 | carrier `watch`와 별개로 `#[cfg(test)]` 관찰자에 `SuperviseEvent`(lost, retry{attempt, planned_delay}, reestablished, gave_up)를 보낸다. `run_reverse_observed`의 선례. 통합 테스트는 이것과 캡처한 진단 줄을 기다린다 | Step 7 |
| 4 | `qsh::lifecycle` 상수와 자리 | `qsh_core::lifecycle`(`TARGET = "qsh::lifecycle"`, 이벤트 함수 넷). `main.rs`는 사람용 줄 옆에서 부르기만 한다 | Step 10 |
| 5 | `supervise` 신호 handler | `shutdown_signal()`을 `qsh-cli`에서 재사용하고 결과를 `qsh-core`의 취소 토큰으로 넘긴다. 기본 모드에는 달지 않는다 | Step 7 |
| 6 | `handle_rfwd_close`의 대기 상한 | task join 대기 1초. 넘으면 지금처럼 응답하고 `warn` 한 줄. 7-4의 client 쪽 재시도가 나머지를 덮는다 | Step 13 |
| 7 | `setup.run` fixture의 비결정 값 | 기존 `normalize` arm(`fingerprint`·`device_id`·`config_dir`·`path`)에 초대 코드를 가리는 arm 하나(`code`)가 필요한지 Step 19에서 확인한다. 필요하면 `invite` 단계 `result` 안의 `code`만 가린다. 단계의 `command` 문자열은 샌드박스 상대 경로로 결정적으로 만든다 | Step 19 |
| 8 | 부하 도구와 filterset | 부하는 논리 CPU 수만큼의 `yes > /dev/null` 프로세스(외부 의존 없음, macOS·Linux 공통). `stress-ng`가 있으면 `--cpu 0`을 쓴다. 반복은 nextest의 반복 실행 옵션이 있으면 그것, 없으면 셸 반복. filterset은 M12 테스트 이름 접두(`wake_detector_`, `path_state_`, `path_watch_`, `supervise`, `supervised_`, `accept_hold_`, `target_backoff_`, `target_fast_window_`, `serve_to_target_`, `rfwd_close_`, `lifecycle`, `setup_` 중 시간 의존 테스트)를 묶은 한 식으로 `scripts/stress/m12.filter`에 둔다. 50회는 로컬 개발 머신에서 돈다 | Step 2, Step 21 |
| 9 | 벽시계 상한의 층 나눔 | 정확한 상한(`WAKE_TICK + dead_after(rtt)`, `FAST_CAP`, accept 유지 기한, 64개)은 paused tokio 시계와 주입 벽시계로 단언한다. 실제 소켓 통합 테스트는 (i) 경로 구별(예: wake 경로의 `lost`가 45초 idle보다 훨씬 이른 10초 안에 `path_dead`로 남), (ii) 관찰 채널의 예정 간격(`planned_delay ≤ FAST_CAP`), (iii) 넉넉한 `timeout`(단언 대상 값의 5배 이상)으로 쓰고 실측값을 테스트 출력에 남긴다 | Step 3, 7, 8 |
| 10 | 첫 단위 동안의 `UNSUPPORTED` 문면 | 기존 예약 옵션의 `UNSUPPORTED` 문면 선례를 따르고 "`--supervise` is not yet supported on the reverse route or with --remote" 꼴. 문면은 fixture로 얼리지 않는다(Step 15가 지운다) | Step 5 |
| 11 | `setup` host 별칭 가림의 안내 | `docs/CLI.md` §6.20에 한 문장, `qsh setup --help` 머리 한 줄. 새 doctor 진단은 만들지 않는다(ADR-0024 결정 1) | Step 19 |

## 5. 완료 절차

1. §1 DoD 전건을 실제 테스트와 CI run으로 확인한다. 체크박스는 근거가 초록일 때만 채운다.
2. 부하 반복 50/50을 기록한다(Step 21).
3. 구속 문서 태그를 대조한다. 대상은 Step 21 (a)가 열거한 자리 전수다.
4. README를 동기화한다. Status, Roadmap 표, Known limitations 여섯, `qsh setup` 절, "First run" 절 무변경.
5. `docs/design/testing.md`의 M12 반영을 확인한다. L4 두 행, 벽시계 예외 목록, CI 규율의 부하 반복 항목.
6. `docs/ROADMAP.md` "현재 위치"와 M12 절을 갱신하고 마감 노트를 적는다.
7. §0.1 일곱과 §0.2 둘의 상태를 승계한다.
8. §0.3 둘은 §5.5 표의 행에 상태만 갱신한다.
9. 이 `PLAN.md`를 `docs/history/m12-plan.md`로 옮기고 M13 계획으로 교체한다.

## 6. 이월 항목

| # | 항목 | M12 처분 |
|---|---|---|
| i | 이슈 #4 항목 5b(supervised tunnel) | Step 3~15 |
| ii | 이슈 #6 요청 1~6 | Step 3~12(대응표는 ADR-0023 이슈 요청 대응 절) |
| iii | 이슈 #4 2026-09-30 코멘트 질문 1~3 | Step 14·15와 Step 7·10의 진단. §6.1과 pin 표시는 ADR-0030 또는 새 ADR |
| iv | 이슈 #3 `qsh setup` | Step 16~20. 5분 기준은 §0.3의 캠페인 PASS로만 닫힌다 |
| v | `docs/design/protocol.md` §2의 "monotonic clock 점프" 문장이 약속한, 코드에 없던 감지 | Step 3 |
| vi | 옛 계획·ADR 줄 번호 인용 부채 | 새 인용을 만들지 않고 손대는 파일의 인용만 앵커로 바꾼다 |

## 7. 태그 정책

- M12 마감에 태그는 필요 없다. DoD 어디에도 태그가 걸리지 않는다.
- 권고 하나. Step 12가 착지한 뒤 태그를 하나 찍으면 `p1-supervise-wake` 셋째 회차까지를 배포 바이너리로 돌릴 수 있고, Step 15 뒤 태그로 넷째 회차를 돈다. `p1-setup-stopwatch`는 Step 20 뒤 태그가 필요하다. 찍을지는 유지보수자 결정이다.
- 찍는다면 M10판 정책을 그대로 따른다. 찍은 태그는 옮기지 않고, 태그 push가 `release.yml`을 구동하며, 서명·공증이 없는 태그로는 M10 DoD 2를 판정하지 않는다.

## 8. 열린 질문

2026-09-30 사용자 지시에 따라 아래를 main 세션이 결정한다. 각 항목 끝의 **결정** 문장은 초안이고 Step 1 커밋에서 확정한다.

1. **ADR-0024 결정 12의 "첫 코드 커밋의 부모".** 한 커밋은 자기 SHA를 담을 수 없으므로, SHA를 적는 커밋(P)이 그 SHA의 트리 자체가 될 수는 없다. **결정:** P의 부모 B를 적고, P는 B에 캠페인 파일 하나만 더한 커밋이며, Step 17의 부모는 P다. B와 Step 17의 부모는 바이너리와 README가 같으므로 결정 12의 보장이 성립한다. ROADMAP M12 수용 기준 (b)의 문장을 이 해석으로 고친다. ADR 문면은 바꾸지 않는다.
2. **ADR-0023 결과 절의 벽시계 상한을 통합 층에서 느슨하게 단언하는 것.** 안정성 규율(부하 아래 50회)과 결과 절의 숫자가 부딪힌다. **결정:** 결과 절이 테스트 이름과 모양을 "제안"으로 두었으므로 정확한 상한은 주입 시계 층에서 고정하고 통합 층은 경로 구별로 단언한다(§4.1 #9). 결정 문면(17의 상한, 10의 `FAST_CAP`)은 그대로 지켜진다. ADR 추기는 하지 않고 Step 8 커밋 본문과 `docs/design/testing.md` L4 행에 근거를 적는다.
3. **M12 크기의 변경.** ROADMAP의 3.8~5.3ew는 개정 전 초안 기준이다. **결정:** 5.1~6.1ew로 고친다. 내역은 ADR-0023 결과 절의 (a) 3.3~3.8, ADR-0024 결과 절에서 재시작 상수 몫 0.05를 뺀 (b) 1.55~1.95, 안정성 하네스 0.05~0.1, 마감 0.2다. P1 합은 약 31~49가 된다.
4. **첫 단위만으로 (a)를 부분 마감할 것인가.** **결정:** 하지 않는다. ADR-0023 결정 24가 "두 단위가 모두 착지해야 닫힌다"고 적는다. 대신 §1의 DoD를 (a1)·(a2)로 나눠 진행을 보인다.
5. **(b)를 (a) 둘째 단위보다 먼저 시작할 것인가.** 두 흐름은 코드가 겹치지 않는다. **결정:** 순서는 과제대로 (a) 뒤에 둔다. 다만 (a) 둘째 단위가 막히면 Step 16부터 먼저 열 수 있고, 그때 Step 16의 B는 그 시점 main이다.
6. **`p1-supervise-wake`를 §5.5에 더하는 시점.** **결정:** Step 1이 행을 더한다(ADR-0023 결과 절의 ROADMAP 항목). 캠페인 파일은 Step 12에서 생긴다.
