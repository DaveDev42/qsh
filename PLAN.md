# PLAN.md — M13: 측정·배포 기반

P1의 셋째 마일스톤인 M13의 실행 계획이다. M12 마감 커밋이 M12 계획을 `docs/history/m12-plan.md`로 옮겼고, 이 문서가 그 자리를 전면 교체한다. 구속 근거는 `docs/ROADMAP.md` §5의 M13 절(범위 (a)~(k), 착수 조건, 명시적 out, 수용 기준, 크기), 같은 문서 §5.1 시퀀싱 원칙(특히 원칙 2·3·6), §5.4 일정 리스크 1·3, §5.5 P1 사람 몫, 마일스톤 마감 공통 절차(같은 문서 §2), ADR-0021 결정 1~7과 결과 절, ADR-0023 결정 12·17·25, ADR-0003, ADR-0004, ADR-0007, ADR-0018 결정 1, `docs/design/reexec-estimate.md` §3의 H1·H1b 행과 §4·§5, `docs/CLI.md` §2.2·§4·§6.3·§6.4·§6.11·§6.12·§6.13·§6.17, `docs/design/protocol.md` §1·§2·§10·§11-4·§12·§16.2·§16.4, `docs/design/architecture.md` §7, `docs/design/testing.md` L4·L6·L9/L10과 CI 규율, `docs/design/threat-model.md` §4 C·D·G·§7, `docs/campaigns/m10-clean-vm.md`(수정 금지 대상으로만)이다. 이 계획과 `docs/ROADMAP.md`의 편집은 main 세션 전용이다.

M13은 마일스톤 자체의 착수 조건이 없다(ROADMAP M13 착수 조건). 다만 항목 셋이 사용자 승인을 기다린다. (d)는 ADR-0027, (f)는 이 계획이 새로 세우는 ADR-0036(stateless reset key의 보관과 읽기 실패 동작), (b)는 하네스가 붉게 나오고 고칠 길이 설계 변경일 때 서는 splice ADR(번호는 §0.5)이다. 세 ADR은 모두 `제안됨`으로 올리고 승인은 사용자가 정한다. 이 계획은 어느 승인도 가정하지 않으므로 승인을 기다리는 동안 승인이 필요 없는 스텝을 먼저 연다. (k)는 사람이 남기는 `cause` 관측 기록이 착수 조건이고, 기록이 없으면 M13을 막지 않는다(§0.6).

인용 규율은 M12판과 같다. `docs/` 아래 문서는 줄 번호가 아니라 절 이름, DoD 문장, ADR 번호와 결정·결과 라벨, 테스트 이름, 커밋 해시, 이슈 번호를 앵커로 가리킨다. 코드 위치는 파일 경로와 심볼 이름으로 가리키고, `path:line`을 쓸 때는 그 값이 origin `ed905e8` 트리 실측임을 같은 문장에 적는다. 옛 계획의 스텝 번호는 새로 인용하지 않는다.

## 0. 착수 조건

### 0.1 P0에서 열린 채 넘어온 사람 몫 일곱

일곱 중 어느 것도 M13의 코드 스텝을 막지 않는다. M12 계획 §0.1의 목록을 M12 마감 시점 상태 그대로 옮기되, 마감 커밋이 그 사이 닫힌 항목을 표시했으면 그 표시를 따른다.

- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** 기준은 `docs/campaigns/m10-clean-vm.md`. v0.3.0 Linux 세 회차 PASS(`69a6414`), macOS 둘이 남았다. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 선행: Apple 시크릿 여섯 등록과 서명·공증이 붙은 첫 태그. 등록(`gh secret set`)과 태그는 사람이 한다. 소유: 사람.
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** `x86_64-unknown-linux-musl` 한정이다. M13 (c)의 aarch64 자산은 이 항목의 분모를 바꾸지 않는다. 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** 기준은 `docs/campaigns/m7-stopwatch.md`. 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** 기준은 `docs/campaigns/m2-mobility.md`. M18의 착수 조건이다. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** 기준은 `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 측정 대상 트리는 M12가 `docs/campaigns/m9-stopwatch.md` §8에 SHA로 고정했다(ADR-0024 결정 12). 소유: 사람.

README "First run" 절은 M7·M9 캠페인의 측정 대상이라 M13이 고치지 않는다. (h)·(i)가 설치 경로 문면을 바꾸므로 README의 설치 절은 고치지만 "First run" 절 안의 변경은 0줄이어야 한다(§4 리스크 "README 설치 절과 캠페인 대상").

### 0.2 M11에서 넘어온 사람 몫 둘 (`docs/ROADMAP.md` §5.5)

- [ ] **`cause` 분포 관측 기록.** M13 (k)의 착수 조건이다. M11 (a)가 담긴 빌드로 현장에서 `lost`/`retry` 줄을 모아, 그 `cause` 분포를 사람이 이슈 #4 코멘트나 캠페인 문서에 적어야 한다. ADR-0023 결정 25가 적듯 이슈 #6의 holder 오류 계수와 0.3.0 hub의 `cause=path_dead` 58건은 이 기록을 대신하지 못한다. 소유: 사람.
- [ ] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 기록 자리는 `docs/campaigns/m8-fuzz.md`. 소유: 사람.

### 0.3 M12에서 넘어온 사람 몫 둘 (`docs/ROADMAP.md` §5.5)

M12는 이 계획 시점에 닫혔다(`docs/ROADMAP.md` M12 마감 노트). 에이전트 몫은 전부 착지했고, 아래 두 캠페인의 회차는 사람 몫으로 남는다. 둘 다 M13 DoD가 아니다.

- [ ] **`p1-supervise-wake` 회차 넷.** 기준은 `docs/campaigns/p1-supervise-wake.md`. 넷째 회차(`serve --to` 재등록과 hub의 supervised reverse route)는 ADR-0023 둘째 단위가 담긴 태그에서만 돈다. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 기준은 `docs/campaigns/p1-setup-stopwatch.md`(ADR-0024 결정 12). 비교 세트는 같은 날 같은 진행자의 m9 3회다. PASS가 기록되기 전에는 이슈 #3 완료 기준 첫 줄이 충족됐다고 적지 않는다. 소유: 사람.

### 0.4 M13이 새로 만드는 사람 몫 (`docs/ROADMAP.md` §5.5)

DoD는 캠페인 문서가 사전 고정돼 커밋되는 데까지다(§5.1 원칙 6). 아래 회차와 GitHub 조작은 사람이 한다. 에이전트는 `gh secret set`, `gh workflow run`, 태그 push, 저장소 설정 변경을 어떤 스텝에서도 하지 않는다. 에이전트는 사람이 돌린 run의 로그를 읽어(`gh run view`) run id와 판정을 기록한다.

- [ ] **`aarch64-unknown-linux-musl` 구형 glibc 판정.** 기준은 Step 8이 사전 고정하는 `docs/campaigns/p1-aarch64-musl.md`. 선행은 aarch64 musl 자산이 붙은 태그다. 소유: 사람.
- [ ] **(c) 새 leg의 첫 release run.** 유지보수자가 `release.yml`을 `workflow_dispatch`로 한 번 돌려 새 leg의 빌드와 `release_smoke_covers_init_trust_exec_pty_detach_and_reattach`(`QSH_SMOKE_STRICT=1`)를 초록으로 보인다. `SHA256SUMS`와 provenance attestation은 태그 push에서만 만들어지므로(`release.yml`의 release job은 태그 ref 한정) 그 판정은 첫 태그 run이 근거다(§7, §8 #4). 소유: 사람(실행), 에이전트(기록).
- [ ] **(a) 인위적 지연 회차.** 유지보수자가 Step 7의 `perf.yml`을 `workflow_dispatch`로 `inject_delay_ms`를 주어 한 번 돌리고, 그 run이 임계로 붉어지는지 본다. 소유: 사람(실행), 에이전트(run id 기록).

### 0.5 승인 게이트

아래 스텝은 해당 ADR이 `승인됨`이 된 뒤에만 연다. 승인 전에는 초안 스텝(Step 3·4·5)까지만 착지한다. 승인이 늦으면 M13은 그 항목만 열어 둔 채 기다리고, main 세션은 §5.1 원칙 2대로 순서상 다음 마일스톤의 ADR 없는 스텝을 연다.

| 항목 | ADR | 초안 스텝 | 막히는 스텝 | 근거 |
|---|---|---|---|---|
| (d) `qsh doctor --fail-on` | ADR-0027(ROADMAP이 예약) | Step 4 | Step 15 | ROADMAP M13 착수 조건, DoD (d) |
| (f) stateless reset key | ADR-0036(새 번호) | Step 5 | Step 16 | ROADMAP DoD (f)의 "읽기 실패 시 동작을 골라 커밋에 적는다", §8 #2 |
| (b) splice 설계 변경 | ADR-0037(조건부, 새 번호) | Step 3 | Step 14 | ROADMAP M13 착수 조건, DoD (b) 끝 문장, §5.4 리스크 3 |

ADR 번호는 `docs/adr/README.md`의 예약 규칙을 따른다. 0027~0035는 P1 계획이 예약했고 0027이 (d)의 자리임을 README의 예약 목록이 적는다. 예약 밖의 다음 새 번호는 0036이다. 조건부 ADR은 "설 때 그 번호부터 쓴다"는 규칙대로 초안을 올리는 순서로 번호를 받는다. 이 계획은 Step 5의 (f) ADR이 Step 3의 판정보다 먼저 서거나 같은 날 서도록 두므로 (f)가 0036, (b)의 splice ADR이 서면 0037을 받을 것으로 적는다. 순서가 뒤집히면 먼저 올리는 쪽이 0036이고, 그 커밋이 이 표와 README의 "다음 새 번호" 문장을 같이 고친다.

### 0.6 (k)의 관측 게이트

(k)는 §0.2의 관측 기록이 있어야 연다. 기록이 오면 Step 17을 ADR-0021 결정 7의 분기대로 여는데 `idle_timeout`이 관측되면 결정 1과 결정 4를, 기록이 있는데 `idle_timeout`이 한 번도 없으면 결정 1만 구현한다. M13 마감까지 기록이 없으면 (k)는 M13을 막지 않는다. 그때 Step 18이 `docs/ROADMAP.md` M13 절에 "관측 기록 없음"과 이월 대상 마일스톤을 적는다(ROADMAP M13 착수 조건, §8 #6).

### 0.7 착수 조건

M12가 닫혔고 M13 자체에는 선행 조건이 없으므로 충족됐다. Step 1이 이 계획을 저장소에 들인 뒤 Step 2~13을 연다. Step 14·15·16은 §0.5의 승인, Step 17은 §0.6의 기록을 기다린다.

## 1. DoD 체크리스트 (ROADMAP M13)

- [ ] **DoD (a) — 야간 성능 추세.** 저장소, 보존 기간, 회귀 판정 임계(직전 N회 중앙값 대비 변화율)가 `docs/design/testing.md` CI 규율 절에 적힌다. 예약 실행이 회차마다 데이터 점을 하나씩 더한다(연속 두 회차의 점을 저장소에서 확인). 인위적 지연을 주입한 회차 하나가 그 임계로 job을 붉게 만든 것을 run id로 기록한다(실행은 §0.4의 사람 몫). 이 job은 PR 게이트가 아니고 `ci-ok`의 `needs`에 없다. 근거: Step 6·7. 소유: 에이전트(기록), 사람(지연 회차 실행).
- [ ] **DoD (b) — 느린 스트림의 저속·역압 축.** 소비자가 읽지 않는 터널 스트림 넷 이상이 동시에 정체한 상태에서 PTY echo p95가 M4 예산(측정 RTT + 10ms) 안에 있고 PTY 출력이 계속 진행함을 새 testkit 테스트가 단언하고, 이 테스트가 `ci.yml` acceptance job에서 strict로 돈다. 수정 뒤에도 M8 DoD 2의 세션당 buffer 상한(8 MB)과 `tunnel_throughput_meets_raw_quinn_ratio`의 비율(≥80%)이 고치지 않은 기준으로 초록이다. 수정이 설계 선택이면 그 ADR이 `승인됨`이다. 근거: Step 2·3·14. 소유: 에이전트(구현), 사용자(ADR 승인).
- [ ] **DoD (c) — `aarch64-unknown-linux-musl` 자산.** `release.yml`이 네이티브 arm 러너에서 이 자산을 만들고 그 leg에서 `release_smoke_covers_init_trust_exec_pty_detach_and_reattach`가 `QSH_SMOKE_STRICT=1`로 초록이다. 자산이 `SHA256SUMS`와 provenance attestation에 들어간다. 설치 스크립트는 aarch64에서 `QSH_LIBC=musl`일 때 대상 태그의 `SHA256SUMS`에 그 자산이 있으면 고르고 없으면 지금처럼 끝나며, 기본값(`gnu`)의 선택이 바뀌지 않음을 설치 스크립트 테스트가 고정한다. 구형 glibc 판정은 새 캠페인 문서에 사전 고정되고 `docs/campaigns/m10-clean-vm.md`는 diff 0이다. 근거: Step 8, §0.4의 release run 기록. 소유: 에이전트, 사람(release run·태그).
- [ ] **DoD (d) — `qsh doctor --fail-on`.** ADR-0027이 `승인됨`이다. `--fail-on`을 주지 않으면 exit code와 stdout이 오늘과 바이트 단위로 같다. 주면 임계 이상 finding이 있을 때 ADR-0027이 정한 값으로 끝나고, envelope의 `ok` 값과 exit의 관계가 `docs/CLI.md` §4·§6.17에 적힌다. §6.17의 "`--fail-on` 플래그는 아직 없다" 문단이 교체되고 man 페이지가 재생성된다. JSON 모양이 바뀌면 새 fixture를 등재하고 기존 fixture는 그대로다. 근거: Step 4·15. 소유: 에이전트, 사용자(ADR 승인).
- [x] **DoD (e) — graceful re-exec H1.** SIGTERM drain이 닫은 세션 수를 payload 없는 구조적 로그 한 줄로 남긴다. 새 doctor 진단이 `EXPECTED_DOCTOR_CODES`에 24번째로 오르고, `docs/CLI.md` §6.11·§6.17과 `crates/qsh-core/src/doctor.rs` 모듈 doc의 개수 산문이 같은 커밋에서 바뀐다. 근거: Step 13. 소유: 에이전트. 완료: `9442364`. drain·배너 테스트 넷은 부하 아래 50/50이고, CI 36781422270이 초록이다.
- [ ] **DoD (f) — H1b stateless reset key 고정.** testkit에서 `qsh serve`를 재시작하면 attach 중이던 클라이언트가 재시작 뒤 첫 패킷에 stateless reset을 받아 `REDIAL_DEADLINE`(2초) 안에 단절을 확정하고, 45초 idle timeout을 기다리지 않은 채 세션 소실을 `docs/design/protocol.md` §10-2의 비구별성 규칙과 `docs/CLI.md` §6.3·§6.4의 현행 attach 실패 코드로 보고한다. reset key 파일은 0600이다. 읽을 수 없거나 형식이 틀린 파일을 만나면 조용히 새 키를 만들지 않고 ADR-0036이 정한 동작을 한다. reset key는 로그와 audit 어디에도 나오지 않는다. `docs/design/threat-model.md` §4 D·G에 키 유출 행이 오른다. wire diff 0. 근거: Step 5·16. 소유: 에이전트, 사용자(ADR 승인).
- [x] **DoD (g)~(j) — 배포 결정 넷.** 각 결정이 커밋에 남는다. (g)는 `publish-dry-run`, (h)·(i)는 설치 스크립트 테스트와 `scripts/README.md`·README 문면, (j)는 핀 테스트 또는 기각 기록이 근거다. 근거: Step 9·10·11·12. 소유: 에이전트. 완료: (g) `fe01fc2`, (h) `b73ea88`, (i) `233ada0`, (j) `21844ca`는 기각하지 않고 핀으로 고정했다. (h)·(i)의 macOS 하네스 수정은 `f993d84`이고 CI 36781422270이 초록이다.
- [ ] **DoD (k) — ADR-0021 결정 1·4(관측 게이트).** 구현했다면 새 설정 값의 검증이 `ReverseConfig::backoff`와 같은 fail-closed `CONFIG_ERROR` 패턴이고 설정이 없을 때 동작이 오늘과 같다. ADR-0021 결정 6의 문서 자리가 같은 커밋에서 바뀐다. `[recovery]` 상한은 세 `detection_budget`에서 역산하고, 세 테스트와 `a_real_60_second_blackout_survives_and_resumes_the_same_session`이 고치지 않은 예산으로 초록이다. 구현하지 않았다면 관측 기록 부재와 이월 대상이 ROADMAP M13 절에 적힌다. 근거: Step 17 또는 Step 18. 소유: 에이전트, 사람(관측 기록).
- [ ] **DoD 마감 — 마감 공통 절차 1·2.** 구속 문서 태그를 대조하고 README를 동기화한다. 근거: Step 18. 소유: 에이전트.
- [ ] **계획 규율 — 새 타이밍 민감 테스트의 부하 반복.** ROADMAP M13 DoD에는 없는 줄이다. M12가 세운 규율(`docs/design/testing.md` CI 규율)을 따라 M13이 더한 타이밍 민감 테스트 전부가 `scripts/stress/run.sh`로 CPU 부하 아래 50회 연속 초록이다. Step 1이 ROADMAP M13 DoD에 이 줄을 더할지는 §8 #7이 정한다. 근거: 각 스텝 (c), Step 18. 소유: 에이전트.

## 2. 실행 단계 (PR 단위)

스텝 번호는 이 문서 안에서만 쓰는 참조다. Step 2~18의 합은 3.05~6.05ew이고 ROADMAP M13 크기 줄(3.1~6.1ew, 0.1 단위 반올림)과 같다. 항목별 내역은 ROADMAP 크기 줄을 그대로 나눴다. (a) 0.5~0.8(저장소 0.2, job과 임계 0.3~0.6), (b) 0.5~2.0(하네스 0.5, 판정과 ADR 0~0.2, 수정 0~1.3), (c) 0.2~0.3, (d) 0.35~0.55(ADR 0.1, 구현 0.25~0.45), (e) 0.25, (f) 0.3~0.45(ADR 0.05~0.1, 구현 0.25~0.35), (g) 0.1~0.2, (h) 0.2~0.3, (i) 0.1~0.2, (j) 0.1~0.3, (k) 0.35~0.5, 마감 0.1~0.2. (k)를 이월하면 하한은 2.7ew로 내려간다. (f)의 ADR 몫은 ROADMAP의 (f) 크기 안에서 떼었다. Step 1은 크기 내역 밖이다.

순서는 위험을 먼저 드러내도록 짰으므로 첫 코드 스텝이 (b) 하네스(Step 2)다. 하네스는 붉을 가능성이 크고 붉으면 splice 설계 변경과 ADR 승인이 M15 착수를 민다(§5.4 리스크 3). 그래서 하네스 판정(Step 3)과 두 ADR 초안(Step 4·5)을 맨 앞에 두어 승인 대기 시간을 나머지 스텝 뒤에 숨긴다. 그다음은 승인이 필요 없는 스텝으로, 측정 도구인 (a)(Step 6·7)를 기능성 배포 항목보다 먼저 두고(§5.1 원칙 3), 설치 경로 셋((c) Step 8, (h) Step 9, (i) Step 10)은 Step 8이 세우는 설치 스크립트 테스트 하네스를 함께 쓰므로 연달아 둔다. (g)·(j)·(e)가 뒤를 잇는다. 승인이 필요한 구현 셋(Step 14·15·16)과 관측 게이트 (k)(Step 17)는 뒤에 두되, 승인이 나는 날 바로 열 수 있다. Step 18이 마감이다.

Step 3은 Step 2에, Step 7은 Step 6에, Step 9·10은 Step 8의 하네스에, Step 14는 Step 3의 ADR 승인에, Step 15는 Step 4의 승인에, Step 16은 Step 5의 승인에, Step 17은 §0.6의 기록에 기댄다. Step 11·12·13은 독립이다. Step 16과 Step 17은 같은 설정 로더(`crates/qsh-core/src/config.rs`)를 만질 수 있으므로 둘이 겹치면 Step 17을 먼저 착지한다(§4.1 #12).

규율은 앞 마일스톤 그대로이고 M13에서 몇 가지를 덧붙인다.

- 각 스텝은 일곱 게이트(`cargo fmt --all --check`, clippy `-D warnings`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `RUSTDOCFLAGS=-D warnings cargo doc`, `cargo xtask arch`, `cargo deny check`)가 초록인 채로 착지한다. clippy와 test는 `ci.yml`에서 Windows 다리도 돈다. 설치 스크립트 테스트처럼 POSIX 셸이 필요한 테스트는 `#[cfg(unix)]`로 가른다.
- 계약 문서 델타는 그 표면을 바꾼 스텝의 같은 커밋에 싣는다. `docs/CLI.md` 상태 헤더의 v0.19 항목은 CLI.md를 처음 고치는 스텝이 열고 뒤 스텝이 덧붙인다. clap 트리가 바뀌는 스텝은 같은 커밋에서 `cargo xtask man`을 돌려 `docs/man/` diff를 싣는다.
- 판정 로직은 `qsh-core`에 두고 `qsh-cli`에는 clap 정의, 렌더러, exit 매핑만 둔다. `qsh-transport`는 설정 파일과 키 파일 경로를 모른다. keep-alive 값과 reset key 바이트는 `qsh-core`가 읽어 인자로 넘긴다(아키텍처 규칙, `docs/design/architecture.md` §1).
- `.proto`, capability 문자열, `ErrorCode`는 바꾸지 않는다. 스텝마다 `git diff --stat -- crates/qsh-proto/proto`가 비어 있음을 완료 판정에 둔다. fixture는 추가만 하고, 새 fixture마다 실제 바이너리로 재현하는 `golden_*` 생산 테스트를 같은 커밋에 둔다. (b)의 수정이 새 스트림 reset 코드를 부르면 그 판단은 ADR-0037이 `docs/design/protocol.md` §16.2·§16.4에 비추어 내린다.
- 손대는 소스 파일이 800줄을 넘으면 인라인 테스트를 같은 커밋에서 형제 `tests.rs`로 옮긴다. `crates/qsh-core/src/tunnel/splice.rs`와 `crates/qsh-transport/src/endpoint.rs`는 origin `ed905e8`에서 각각 인라인 테스트를 가진 큰 파일이므로 Step 14·16이 손댈 때 줄 수를 먼저 확인한다.
- 안정성 규율은 M12와 같다. 새 타이밍 민감 테스트는 시계를 주입하고, 관찰 가능한 상태(`watch` 채널, 캡처한 진단 줄, quinn `Connection::stats()`의 프레임 계수)를 넉넉한 `timeout`으로 기다리며, 고정 대기 `sleep()`을 쓰지 않는다. 정확한 상한은 주입 시계 층에서 단언하고 실제 소켓 층은 경로 구별과 넉넉한 상한을 단언한다. 그 스텝의 완료 판정에서 `scripts/stress/run.sh`로 CPU 부하 아래 50회 연속 초록이어야 착지한다. 예외는 지연 자체를 재는 perf 게이트 단언(echo p95, throughput 비율) 하나다. 이 단언은 CPU 포화가 측정 대상을 바꾸므로 부하 반복 대상이 아니고 대신 부하 없이 50회 연속 초록을 기록한다(§8 #5). 같은 테스트 파일 안에서도 진행 여부 단언과 지연 단언은 다른 테스트 함수로 나눠 앞의 것은 부하 반복에 넣는다.
- 벽시계를 실제로 기다리는 테스트는 `QSH_ACCEPTANCE_SLOW`로 가르고 `docs/design/testing.md`의 벽시계 예외 목록에 이름을 올린다.

### Step 1 — M13 계획 교체와 ROADMAP 갱신 (main 세션, 크기 내역 밖)

근거: `docs/ROADMAP.md` M12 마감 노트, ROADMAP M13 절. 선행: M12 마감. M13의 첫 커밋이다.

**(a) 범위:** ① `PLAN.md`가 이 문서다(M12 마감 커밋이 옮기지 않았으면 이 커밋이 M12 계획을 `docs/history/m12-plan.md`로 옮긴다). ② `docs/ROADMAP.md`를 고친다. "현재 위치" 줄을 M13으로 옮긴다. §5.1 원칙 2의 "M13 (b)는 …, M13 (d)는 ADR-0027을 기다린다" 문장과 M13 착수 조건, §5.2 표 M13 행의 착수 조건 칸에 (f)의 ADR-0036을 더한다(§8 #2). §5.4 리스크 1의 ADR 개수에 ADR-0036을 더한다. §8 #7이 정하면 M13 DoD에 안정성 줄을 더한다. §5.5 표의 `aarch64-unknown-linux-musl` 행 "사전 고정 문서" 칸에 `docs/campaigns/p1-aarch64-musl.md`를 적는다. ③ README Roadmap 표의 P1 행을 "M13 진행 중"으로 고친다.

**(b) 테스트·게이트:** 문서 변경이라 새 게이트가 없다. README 축자 게이트가 걸린 자리는 건드리지 않는다. 일곱 게이트 초록.

**(c) 완료 판정:** `PLAN.md` 첫 줄이 이 문서의 제목이다. "현재 위치"가 M13을 가리킨다. `grep -n 'ADR-0036' docs/ROADMAP.md`가 M13 착수 조건과 §5.2 표에서 각 1건 이상이다.

### Step 2 — (b) 느린 스트림 역압 하네스 (0.5ew)

근거: ROADMAP M13 범위 (b)와 DoD (b), `docs/design/testing.md` L9/L10의 "덮는 축은 포화(고속) 하나다" 문단, `docs/design/protocol.md` §12, PRD §13의 "느린 파일·터널 stream이 PTY stream을 block하지 않아야 함". 선행: 없음. M13의 첫 코드 스텝이다.

**(a) 범위:** 새 testkit 테스트 파일 `crates/qsh-testkit/tests/tunnel_stalled_streams.rs`를 만든다. `tunnel_echo_under_load.rs`의 하네스 모양(같은 연결 위의 PTY 세션과 `-L` 포워드, 측정 RTT, `percentile`)을 따르되 흐름 방향과 소비자가 다르다. 호스트 쪽 목적지 서버 N개가 연결마다 끝없이 쓰고, 클라이언트 쪽 로컬 소비자는 TCP 연결을 연 뒤 한 바이트도 읽지 않는다. 로컬 소켓의 `SO_RCVBUF`는 작게 잡아 커널 버퍼가 곧 차게 한다. 그러면 클라이언트 splice가 QUIC 수신 스트림을 더 읽지 못하고, 스트림마다 `TUNNEL_STREAM_RECEIVE_WINDOW`(2 MiB)가 차며, N이 넷이면 `CONNECTION_RECEIVE_WINDOW`(8 MiB)가 소진된다(ROADMAP M13 범위 (b)의 가설).

정체 성립은 시간이 아니라 관찰 가능한 상태로 기다린다. 클라이언트 쪽 `Connection::stats()`에서 호스트가 보낸 `DATA_BLOCKED` 프레임 수(연결 수준)가 0보다 커지거나, 스트림 N개 모두에서 `STREAM_DATA_BLOCKED`가 관찰될 때를 정체로 본다(§4.1 #1). 그 뒤 PTY 쪽을 재는데 진행 단언은 PTY에 한 줄씩 순번을 찍는 프로세스를 돌리고 정체 이후 순번이 계속 늘어나는지를 넉넉한 `timeout` 안에서 본다. 지연 단언은 정체 상태에서 echo 표본을 모아 p95를 `측정 RTT + 10ms`와 비교한다.

게이트는 기존 perf 테스트와 같은 규칙이다. `QSH_ACCEPTANCE_STRICT`가 없으면 측정값과 정체 관찰을 출력만 하고 초록으로 끝나고 있으면 단언한다. 예상 결과가 붉음이라 필수 경로를 붉게 만들 수 없으므로 이 스텝은 `ci.yml` acceptance job에 테스트를 넣지 않는다. 배선은 수정이 착지하는 Step 14(또는 하네스가 초록이면 Step 3)가 한다. 모듈 doc에 가설, 정체 관찰 기준, 넷이라는 수의 근거(8 MiB ÷ 2 MiB), 셋일 때는 막히지 않아야 한다는 경계 조건을 적는다.

**(b) 테스트·게이트:** testkit(strict 게이트, 수 초). `pty_output_keeps_progressing_while_four_unread_tunnel_streams_stall`(진행 단언, 표 기반으로 N=4와 N=8 두 행), `pty_echo_p95_stays_within_measured_rtt_plus_10ms_while_four_unread_tunnel_streams_stall`(지연 단언), `pty_output_keeps_progressing_with_three_unread_tunnel_streams`(경계 조건. 창 합이 6 MiB라 연결 창이 남으므로 지금도 초록이어야 한다), `stalled_stream_harness_observes_data_blocked_before_measuring`(정체 관찰이 실제로 일어났음을 단언해, 정체가 안 생겨서 초록인 경우를 막는다). 기존 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`와 `tunnel_throughput_meets_raw_quinn_ratio` 초록.

**(c) 완료 판정:** 네 테스트가 기본 실행(strict 없음)에서 초록이다. 로컬에서 `QSH_ACCEPTANCE_STRICT=1`로 돌린 결과(어느 테스트가 붉고 어떤 값이 나왔는지, `DATA_BLOCKED` 계수)를 커밋 본문에 적는다. 경계 조건 테스트와 정체 관찰 테스트가 strict에서 초록이고 부하 아래 50회 연속 초록이다. 지연 단언은 §2 규율의 예외다. `git diff --stat -- crates/qsh-proto/proto crates/qsh-core/src crates/qsh-transport/src`가 비어 있다(하네스는 제품 코드를 건드리지 않는다).

### Step 3 — (b) 판정 기록과 splice ADR 초안 (0~0.2ew, 조건부)

근거: ROADMAP M13 착수 조건과 DoD (b) 끝 문장, §5.4 리스크 3의 "설계 변경이 필요하다고 판정되면 그날 ADR 초안을 올린다". 선행: Step 2.

**(a) 범위:** Step 2의 strict 결과로 세 갈래 중 하나를 고른다.

- 초록(가설이 틀림). 연결 창이 소진되지 않거나 소진돼도 PTY가 진행한다. 그 이유(quinn의 credit 반환 시점 등)를 `docs/design/testing.md` L9/L10의 "덮는 축은 포화(고속) 하나다" 문단에 실측으로 적고, 잔여 위험 문장을 "측정됨"으로 바꾼다. Step 2의 테스트를 `ci.yml` acceptance job에 strict로 넣고 `CLAUDE.md` Commands 절의 acceptance 목록과 `docs/design/testing.md` 게이트 환경변수 표에 이름을 더한다. (b)는 이 스텝으로 닫히고 Step 14는 0ew다.
- 붉음, 설계 변경 불필요. 상수 조정은 ROADMAP 범위 (b)가 이미 기각했으므로(8 MiB는 M8 DoD 2 상한, 스트림 창 축소는 `docs/design/protocol.md` §12가 기각한 128 KiB 사례) 이 갈래는 splice 안의 결함(예: 읽기 중단 조건의 버그)일 때만 성립한다. 그 판단 근거를 커밋 본문에 적고 Step 14를 ADR 없이 연다.
- 붉음, 설계 변경 필요. 예상 갈래다. `docs/adr/0037-*.md`(번호는 §0.5)를 `제안됨`으로 올린다. 초안은 적어도 다음 후보를 한 표로 비교한다. (가) 수신 스트림을 앱 쪽 유계 버퍼로 비우고 그 버퍼가 차면 그 스트림만 `STOP_SENDING`/reset한다(ROADMAP 범위 (b)가 예로 든 안). (나) 연결 단위로 정체 바이트 합을 세어 문턱(예: 연결 창의 절반)을 넘으면 가장 오래 정체한 터널 스트림부터 끊는다. (다) 동시 터널 스트림 수에 상한을 두어 창 합이 연결 창을 넘지 못하게 한다. 비교 축은 세션당 buffer 8 MB 상한 준수, `tunnel_throughput_meets_raw_quinn_ratio` 비율, 느린 소비자에게 보이는 의미(끊김이 RST로 보이는지), 새 reset 코드가 `docs/design/protocol.md` §16.2의 상호운용 계약 표에 새 행이 되는지, `docs/design/threat-model.md` §4 C의 새 행이다. `docs/adr/README.md` 표에 행을 더하고 "다음 새 번호" 문장을 고친다.

**(b) 테스트·게이트:** 문서 변경(초록 갈래는 CI 배선 포함). 일곱 게이트 초록. 초록 갈래는 acceptance job이 한 번 이상 초록.

**(c) 완료 판정:** 고른 갈래와 근거가 커밋 본문에 있다. 셋째 갈래면 ADR 파일이 `상태: 제안됨`이고 README 표에 같은 상태로 있다. ADR이 `승인됨`으로 바뀌는 것은 사용자 결정이고 이 스텝의 완료 조건이 아니다.

### Step 4 — ADR-0027 초안: `doctor --fail-on`의 exit 규칙 (0.1ew)

근거: ROADMAP M13 범위 (d), `docs/CLI.md` §4·§6.17, `docs/adr/README.md` 예약 목록. 선행: 없음.

**(a) 범위:** `docs/adr/0027-doctor-fail-on-exit.md`를 `제안됨`으로 올린다. 결정 절 초안에서 `--fail-on <warn|error>`는 additive 플래그다. 임계 이상의 `status`를 가진 finding이 하나라도 있으면 envelope은 `ok: true`와 findings를 오늘 그대로 내고 exit만 새 값 `1`로 바꾼다. `1`은 §4 일반 명령 표에 비어 있는 값이고, `255`("연결, 인증, 정책 등 QSH runtime 실패")와 섞이지 않으며, 검사 도구가 "문제를 찾았다"를 알리는 관례 값이다. `info`는 임계로 받지 않는다(구조적 고지라 CI 게이트로 쓰면 늘 붉다). doctor 자신이 조회를 시작하지 못하는 경우(`Err`, exit `255`)는 `--fail-on`과 무관하게 지금과 같다. 출력 모드에 따라 exit 의미가 달라지지 않는다(§4 마지막 문단). JSON 모양은 바꾸지 않는 것이 초안이고, 대안 절에 `data.fail_on` echo 필드를 두는 안과 exit `255`를 쓰는 안(ROADMAP 범위 (d)가 짚은 신호 불일치로 기각)을 적는다. 결과 절에는 `docs/CLI.md` §4 표의 새 행, §6.17 문단 교체, `exit_code_matrix.rs` 행, man 재생성을 적는다. `docs/adr/README.md` 표에 행을 더한다.

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록.

**(c) 완료 판정:** ADR 파일이 `상태: 제안됨`이고 README 표에 같은 상태로 있다. 결정 절이 exit 값 하나, 임계 어휘, `ok`와 exit의 관계를 각각 한 문장으로 적는다.

### Step 5 — ADR-0036 초안: stateless reset key의 보관과 읽기 실패 동작 (0.05~0.1ew)

근거: ROADMAP M13 범위 (f)와 DoD (f), `docs/design/reexec-estimate.md` §3 H1b 행("키 보관 위치 결정 1건")·§5, ADR-0007(비밀 custody 규율). 선행: 없음.

**(a) 범위:** `docs/adr/0036-stateless-reset-key.md`를 `제안됨`으로 올리고 결정 절에 아래 초안을 적는다.

- 쓰는 프로세스는 서버 endpoint를 여는 `qsh serve`와 `qsh listen`이다. `qsh serve --to` target과 클라이언트는 쓰지 않는다(재시작한 쪽이 서버일 때만 옛 연결의 패킷을 받는다).
- 키는 32바이트 OS 난수이고 config 디렉터리의 `stateless_reset.key`에 둔다(§4.1 #8). `identity/` 아래에 두지 않는 이유는 `identity/`를 치우는 복구 경로(ADR-0026 거절 문면)가 이 키까지 지울 까닭이 없기 때문이다. 재시작 때마다 blocking 로드가 늘고(`docs/design/reexec-estimate.md` §1) 이 키의 가치가 device 키보다 낮으므로 플랫폼 키스토어는 쓰지 않는다.
- 없으면 처음 기동 때 `O_CREAT|O_EXCL`, 모드 0600으로 만든다. 권한이 0600보다 넓으면 기동 진단을 낸다.
- 읽을 수 없거나 형식이 틀린 파일을 만나면 조용히 새 키를 만들거나 덮어쓰지 않는다. 초안은 이번 기동에만 쓰는 임시 키로 뜨고 stderr 기동 진단 한 줄(경로와 오류 종류만, 키 바이트 없음)을 내는 쪽이다. 근거는 `acl.toml`이 없어도 프로세스가 뜨고 답한다는 규칙(`docs/CLI.md` §6.12)과 같은 결이다. 이 키는 감지 지연을 줄이는 최적화라서, 읽기 실패로 기동을 거절하면 `Restart=always` 유닛이 재시작 루프에 빠진다. 기동 거절(`CONFIG_ERROR`)은 대안 절에 적고 기각 사유를 붙인다.
- reset key는 로그, audit, 진단 `detail`, JSON 어디에도 나오지 않는다. 회전 명령은 두지 않는다. 파일을 지우면 다음 기동이 새 키를 만든다.
- 결과 절. `qsh-transport`의 `EndpointConfig`가 `default()` 대신 주입된 키로 만들어진다. wire 변경 0, RFC 9000 §10.3 준수. `docs/CLI.md` §6.12·§6.13의 기동 진단 문단, `docs/design/threat-model.md` §4 D(키 유출로 off-path 연결 절단)와 §4 G(재시작 뒤 감지 지연 개선) 행, `docs/deploy/service.md`의 재시작 고지 문단.

이 ADR이 서면 그것으로 ROADMAP DoD (f)의 "골라 커밋에 적는다"가 채워진다. ROADMAP은 이 결정을 ADR 없이 커밋 기록으로 둘 수 있게 적었지만, 이 계획은 결정이 기동 계약(`docs/CLI.md` §6.12)과 비밀 보관 규율에 닿으므로 ADR로 올린다(§8 #2).

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록.

**(c) 완료 판정:** ADR 파일이 `상태: 제안됨`이고 README 표에 같은 상태로 있으며 "다음 새 번호" 문장이 갱신됐다. 결정 절이 파일 위치, 권한, 읽기 실패 동작, 로그 금지를 각각 한 문장으로 적는다.

### Step 6 — (a) 성능 추세 저장소와 판정 임계 (0.2ew)

근거: ROADMAP M13 범위 (a)의 "쌓을 저장소를 먼저 정한다", `docs/design/testing.md` L9/L10의 "절대 throughput 추세는 여전히 nightly". 선행: 없음.

**(a) 범위:** 후보를 비교하고 하나를 고른다. (1) 같은 저장소의 orphan 브랜치 `perf-data`에 회차마다 JSON 한 줄을 덧붙이는 안. (2) Actions artifact. 보존 상한(최대 90일)이 있고 회차 사이를 잇는 조회가 API 호출이다. (3) gh-pages와 외부 벤치마크 action. 새 서드파티 action이 브랜치에 쓰는 권한을 갖는다. (4) 외부 저장소. 새 시크릿이 필요해 사람 몫이 늘어난다. 초안은 (1)이다(§4.1 #3). 보존은 최근 365점, 판정은 직전 7점 중앙값 대비 throughput 20% 이상 하락 또는 echo p95 50% 이상 상승이면 붉음, 점이 7개 미만이면 판정 없이 기록만 한다(§4.1 #4). `docs/design/testing.md` CI 규율 절에 저장소, 보존, 임계, "PR 게이트가 아니다", 판정기 위치를 한 항목으로 적는다. 같은 절의 "절대 throughput 추세는 여전히 nightly" 문장이 가리킬 job 이름을 적는다.

**(b) 테스트·게이트:** 문서 변경. 일곱 게이트 초록.

**(c) 완료 판정:** `docs/design/testing.md` CI 규율 절에 저장소·보존·임계가 숫자로 있다. 고르지 않은 후보와 사유가 커밋 본문에 있다.

### Step 7 — (a) 야간 perf job과 판정기 (0.3~0.6ew)

근거: ROADMAP M13 DoD (a). 선행: Step 6.

**(a) 범위:** 판정기를 `xtask`에 둔다(`cargo xtask perf-judge`, 모듈 `xtask/src/perf.rs`). 입력은 기록 파일과 이번 회차의 점 하나이고, 출력은 판정 한 줄과 exit(`0` 초록, `1` 붉음)이다. 기록 자르기(보존 365점)도 여기서 한다. `xtask`는 게시되지 않는 워크스페이스 멤버라 판정 로직의 단위 테스트가 `cargo nextest run --workspace`에 들어간다.

측정은 기존 두 테스트를 재사용한다. `tunnel_throughput_meets_raw_quinn_ratio`와 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`가 `QSH_PERF_OUT=<path>`를 받으면 절대 throughput(MB/s), raw-quinn 기준값, echo p95(ms), 측정 RTT를 JSON 한 줄로 그 파일에 덧붙인다. 설정되지 않으면 동작이 지금과 같다. 인위적 지연은 `QSH_PERF_INJECT_DELAY_MS`로 testkit 하네스의 루프백 경로에만 넣는다. 제품 바이너리에는 이 훅이 없다(§4.1 #5).

`.github/workflows/perf.yml`을 새로 만든다. 트리거는 `schedule`(매일 한 번)과 `workflow_dispatch`(입력 `inject_delay_ms`, 기본 0)뿐이고 `pull_request`와 `push`는 없다. job은 `perf-data` 브랜치를 가져오고(없으면 orphan으로 만든다), 두 테스트를 `QSH_PERF_OUT`과 함께 돌리고, `cargo xtask perf-judge`로 판정한 뒤 점을 덧붙여 push한다. 판정이 붉어도 점은 기록한다. 권한은 그 job에만 `contents: write`를 주고 워크플로 기본은 `contents: read`다. 점에는 커밋 SHA, runner 이름, 주입 지연 값을 싣고 주입 회차의 점은 `injected: true`로 표시해 다음 회차의 중앙값 계산에서 뺀다. `ci.yml`의 `ci-ok`는 이 워크플로를 모른다. `docs/design/testing.md` 게이트 환경변수 표에 `QSH_PERF_OUT`과 `QSH_PERF_INJECT_DELAY_MS` 행을 더한다.

**(b) 테스트·게이트:** 단위(`xtask/src/perf.rs` 또는 `xtask/src/perf/tests.rs`). `perf_judge_is_green_within_the_threshold_of_the_last_seven_median`, `perf_judge_is_red_when_throughput_drops_past_twenty_percent`, `perf_judge_is_red_when_echo_p95_rises_past_fifty_percent`, `perf_judge_records_without_judging_until_seven_points_exist`, `perf_judge_excludes_injected_points_from_the_median`, `perf_history_trims_to_the_retention_bound`. testkit. `perf_out_appends_one_json_line_per_run_and_changes_nothing_when_unset`. 기존 `tunnel_throughput_meets_raw_quinn_ratio`와 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`가 `QSH_PERF_OUT` 없이 바이트 단위로 같은 게이트를 유지한다. `actionlint`가 도는 자리가 있으면 새 워크플로도 통과한다.

**(c) 완료 판정:** 위 테스트 초록. 판정기 테스트는 시간 의존이 없어 부하 반복 대상이 아니다. 머지 뒤 예약 실행 두 회차가 `perf-data`에 점을 하나씩 더했음을 에이전트가 브랜치를 읽어 확인하고 run id 둘을 ROADMAP M13 마감 노트 초안에 적는다. §0.4의 지연 회차는 유지보수자가 돌리고, 에이전트가 그 run id와 붉은 판정 줄을 기록한다. `git diff --stat -- .github/workflows/ci.yml`이 비어 있다.

### Step 8 — (c) `aarch64-unknown-linux-musl` leg, 설치 스크립트 분기, 설치 스크립트 테스트 하네스, 캠페인 사전 고정 (0.2~0.3ew)

근거: ROADMAP M13 범위 (c)와 DoD (c), M10 결정 기록 Q3, `docs/design/testing.md` L9/L10의 "M10 — musl 바이너리의 RSS 주장 범위" 문단. 선행: 없음.

**(a) 범위:** `release.yml` build 매트릭스에 `os: ubuntu-24.04-arm`, `target: aarch64-unknown-linux-musl`, `musl: true` 행을 더한다. x86_64 musl 레시피(`musl-tools` 설치, 정적 링크 증거 스텝, `release_smoke`)가 `matrix.musl` 조건으로 이미 붙어 있으므로 새 스텝은 없다. 행 주석에 "네이티브 arm 러너, cross 빌드 아님"과 aws-lc-sys의 aarch64 musl 경로 확인 결과를 적는다(§4 리스크). `SHA256SUMS`와 attestation은 release job의 `dist/*` glob이 이미 모든 자산을 덮으므로 바꾸지 않는다. 대신 release job에 매트릭스 target마다 자산이 `dist/`에 있고 `SHA256SUMS`에 한 줄씩 있는지 확인하는 스텝 하나를 더해, 새 leg가 조용히 빠지는 경우를 붉게 만든다.

`scripts/install.sh`는 aarch64에서 `QSH_LIBC=musl`일 때만 바뀐다. 지금은 target 판정 단계에서 "no aarch64 musl asset is published"로 끝난다. 바뀐 뒤에는 target을 `aarch64-unknown-linux-musl`로 정하고, 대상 태그의 `SHA256SUMS`를 먼저 받아 그 자산 줄이 있으면 설치를 이어가고, 없으면 지금과 같은 뜻의 메시지("no aarch64 musl asset is published for <tag>; unset QSH_LIBC to install the glibc build")로 끝난다. 기본값 `gnu`와 x86_64 경로의 다운로드 순서는 바꾸지 않는다(§4.1 #6). 머리 주석의 "x86_64 only" 문장을 고친다.

설치 스크립트 테스트 하네스를 세운다. 자리는 게시되지 않는 `xtask`다(§4.1 #7). 테스트는 임시 디렉터리에 가짜 릴리스(작은 셸 스크립트를 `qsh`로 담은 tar.gz, `man/*.1`, `SHA256SUMS`)를 만들고, PATH 앞에 `curl`·`uname`·`gh` 대역 셸 스크립트를 둔 채 `sh scripts/install.sh`를 돌린다. `curl` 대역은 URL을 가짜 릴리스 파일로 대응시키고, 요청 URL을 로그 파일에 남겨 테스트가 어느 자산을 골랐는지 단언한다. 네트워크에 닿지 않는다. `#[cfg(unix)]`다.

`docs/campaigns/p1-aarch64-musl.md`를 사전 고정해 커밋한다. 형식은 `docs/campaigns/m10-clean-vm.md` §5("DoD 3의 조작적 정의: musl static")와 §8~§11을 계승한다. 대상 배포판(자산의 요구 glibc보다 오래된 aarch64 배포판 하나 이상), 설치 경로(`QSH_LIBC=musl`로 설치 스크립트 실행), 기능 스모크 네 축, 판정 규칙, 기록 표를 적는다. `docs/campaigns/m10-clean-vm.md`는 한 바이트도 고치지 않는다. `CLAUDE.md` 문서 지도의 캠페인 목록과 `scripts/README.md`의 설치 스크립트 절(`QSH_LIBC` 설명)을 고친다.

**(b) 테스트·게이트:** 설치 스크립트 테스트(`xtask/tests/install_script.rs`). `install_defaults_to_gnu_on_x86_64_and_aarch64_linux`, `install_picks_x86_64_musl_when_qsh_libc_is_musl`, `install_picks_aarch64_musl_when_the_tag_publishes_it`, `install_aarch64_musl_ends_as_today_when_the_tag_lacks_the_asset`, `install_rejects_an_unknown_qsh_libc`, `install_refuses_a_checksum_mismatch`. 기존 `release_smoke_covers_init_trust_exec_pty_detach_and_reattach` 초록.

**(c) 완료 판정:** 위 테스트 초록. `git diff --stat -- docs/campaigns/m10-clean-vm.md`가 비어 있다. 머지 뒤 §0.4의 dispatch run에서 새 leg의 빌드, 정적 링크 증거, `release_smoke`(`QSH_SMOKE_STRICT=1`)가 초록이고 에이전트가 run id를 기록한다. `SHA256SUMS`와 attestation 포함은 첫 태그 run에서 확인한다(§8 #4).

### Step 9 — (h) 설치 스크립트의 provenance 검증 (0.2~0.3ew)

근거: ROADMAP M13 범위 (h)와 DoD (g)~(j), `release.yml`의 "Attest build provenance" 스텝 주석(`gh attestation verify <asset> --repo`). 선행: Step 8의 하네스.

**(a) 범위:** `scripts/install.sh`가 체크섬 검증 뒤 provenance를 검증한다. 동작은 fail closed 쪽이다.

- `gh`가 있고 인증된 상태면 `gh attestation verify <asset> --repo "$QSH_REPO"`를 부르고, 실패하면 설치하지 않고 끝난다.
- 검증 도구가 없거나 쓸 수 없으면(`gh` 없음, 미인증) `SHA256SUMS` 검증까지 하고 "provenance not verified" 경고를 stderr에 낸 뒤 설치한다(§4.1 #9가 미인증을 "도구 없음"으로 볼지 정한다).
- 둘 다 건너뛰는 것은 명시 플래그 `QSH_INSECURE_SKIP_VERIFY=1`로만 한다. 이 플래그는 경고를 내고, 체크섬도 건너뛴다는 사실을 문면에 적는다.

머리 주석의 "What the checksum does and does not prove" 문단을 provenance가 증명하는 것(자산이 이 저장소의 `release.yml` run에서 만들어졌다)과 증명하지 않는 것으로 고친다. `scripts/README.md`와 README 설치 절에 세 경로를 적는다. README "First run" 절은 건드리지 않는다.

**(b) 테스트·게이트:** 설치 스크립트 테스트. `install_verifies_provenance_with_gh_when_available`(`gh` 대역이 받은 인자를 단언), `install_refuses_when_provenance_verification_fails`, `install_warns_and_continues_with_checksum_only_when_gh_is_absent`, `install_skip_verify_flag_skips_both_and_warns`, `install_never_skips_the_checksum_without_the_explicit_flag`. Step 8의 테스트 초록.

**(c) 완료 판정:** 위 테스트 초록. 결정(fail closed의 범위와 플래그 이름)이 커밋 본문에 있다. `git diff <Step 8 머지 커밋> -- README.md`에서 "First run" 절 안의 변경이 0줄이다.

### Step 10 — (i) curl 설치 경로의 man 페이지 설치 (0.1~0.2ew)

근거: ROADMAP M13 범위 (i), `release.yml`의 아카이브 구성 스텝(unix 아카이브가 `man/*.1`을 담는다), `scripts/install.sh`의 "which this installer does not install" 주석. 선행: Step 8의 하네스.

**(a) 범위:** 설치 스크립트가 아카이브의 `man/*.1`을 `QSH_MAN_DIR`(기본 `$HOME/.local/share/man/man1`, §4.1 #10)에 설치한다. 추출은 지금처럼 이름으로 하고, 이름이 `man/<name>.1` 꼴이 아니거나 심볼릭 링크인 항목은 거절한다. 바이너리처럼 임시 이름으로 복사한 뒤 rename한다. man 설치 실패는 바이너리 설치를 되돌리지 않고 경고로 끝낸다. `QSH_NO_MAN=1`이면 건너뛴다. 설치 뒤 `MANPATH`에 그 디렉터리가 잡히지 않는 플랫폼이면 안내 한 줄을 낸다. 아카이브에 man 페이지가 없으면(옛 태그) 조용히 건너뛴다. `release.yml`의 아카이브 스텝 주석("install.sh extracts only the binary")을 같은 커밋에서 고치고 `scripts/README.md`와 README 설치 절도 고친다.

**(b) 테스트·게이트:** 설치 스크립트 테스트. `install_places_every_man_page_under_qsh_man_dir`, `install_skips_man_pages_with_qsh_no_man`, `install_rejects_a_man_member_outside_man_or_a_symlink`, `install_keeps_the_binary_when_man_installation_fails`, `install_tolerates_an_archive_without_man_pages`. Step 8·9의 테스트 초록.

**(c) 완료 판정:** 위 테스트 초록. 결정(기본 디렉터리, 끄는 플래그, 실패 처리)이 커밋 본문에 있다. README "First run" 절 diff 0.

### Step 11 — (g) 공개 크레이트 tarball의 test 타깃 `exclude` 정책 (0.1~0.2ew)

근거: ROADMAP M13 범위 (g), `docs/design/testing.md` "M10 — crates.io publish gate" 문단. 선행: 없음.

**(a) 범위:** 공개 넷(`qsh-proto`, `qsh-transport`, `qsh-core`, `qsh-cli`)의 tarball에 `tests/`를 넣을지 정한다. 초안은 넣지 않는 쪽이다. 공개 매니페스트는 버전 없는 path dev-dependency(`qsh-testkit`)를 떨어뜨리므로(루트 `Cargo.toml` 주석의 실측) 통합 테스트 대부분이 tarball에서 컴파일되지 않고, `qsh-cli`의 fixture와 `ssh_golden`은 tarball 크기만 늘린다. 네 `Cargo.toml`에 `exclude = ["tests/"]`를 더하고, 루트 `Cargo.toml`의 게시 정책 주석에 이유를 적는다. `ci.yml`의 `publish-dry-run` job에 크레이트마다 `cargo package --list`의 결과에 `tests/`가 없음을 확인하는 스텝을 더한다. 인라인 `#[cfg(test)]`와 `tests.rs` 형제 모듈은 `src/` 아래라 영향이 없다는 점을 주석에 적는다.

**(b) 테스트·게이트:** `publish-dry-run` job 초록(새 스텝 포함). 일곱 게이트 초록.

**(c) 완료 판정:** `publish-dry-run`이 PR에서 초록이고 새 스텝이 `tests/` 부재를 단언한다. 결정과 기각한 대안(tarball에 두고 `cargo test`가 깨지는 것을 받아들이기)이 커밋 본문에 있다.

### Step 12 — (j) `docs/CLI.md` 상태 헤더의 기계 핀 또는 기각 (0.1~0.3ew)

근거: ROADMAP M13 범위 (j)의 "무엇을 고정할지부터 정하고, 0.3ew 안에 정하지 못하면 기각으로 기록한다". 선행: 없음.

**(a) 범위:** 상태 헤더는 한 줄짜리 변경 기록이라 사람이 손으로 맞춘다. 고정할 수 있는 불변식 후보를 먼저 적고 하나를 고른다. 초안은 "헤더가 인용하는 `§N`과 `§N.M`이 모두 이 문서의 실제 절 제목으로 있다"와 "헤더 첫 버전 표기(`Draft v0.N`)가 헤더 안의 가장 큰 버전 번호다" 둘이다. 둘 다 코드 없이 문서만 읽는 테스트라 `crates/qsh-core/tests/doctor_docs.rs`의 문서 대조 테스트 옆에 둔다(§4.1 #11). 0.3ew 안에 쓸모 있는 불변식을 고르지 못하면 기각하고, 기각 사유를 `docs/CLI.md` 상태 헤더가 아니라 이 스텝의 커밋 본문과 ROADMAP M13 마감 노트에 적는다.

**(b) 테스트·게이트:** 핀을 고르면 `cli_md_status_header_cites_only_sections_that_exist`, `cli_md_status_header_leads_with_its_newest_version`. mutation 하나(헤더에 없는 절 번호 하나를 넣기)가 첫 테스트를 붉힌다. 기각이면 테스트 없음.

**(c) 완료 판정:** 핀 테스트 초록 또는 기각 기록. 스텝에 쓴 시간이 0.3ew를 넘지 않았다.

### Step 13 — (e) graceful re-exec H1: drain 요약, doctor 진단 1종, 배너 (0.25ew)

근거: ROADMAP M13 범위 (e)와 DoD (e), `docs/design/reexec-estimate.md` §3 H1 행과 §7 H1 행, `docs/deploy/service.md`의 재시작 고지(H0). 선행: 없음.

**(a) 범위:** drain 요약, doctor 진단, 배너를 더한다.

- drain 요약. `Server::drain`(`crates/qsh-core/src/server/mod.rs`)이 끝날 때 `qsh::lifecycle` target에 한 줄을 낸다. 값은 `drained`이고, 닫은 세션 수 `sessions_closed`, 그중 detach 상태였던 수 `detached_closed`, `DRAIN_TIMEOUT`에 걸렸는지 `timed_out`을 싣는다. 세션 id, 명령, PTY 내용, 주소는 싣지 않는다(§4.1 #13). `docs/CLI.md` §6.12의 `qsh::lifecycle` 문단에 값을 더한다(열린 어휘).
- doctor 진단. 이 머신에 해당 run mode의 서비스 유닛이 등록돼 있으면 "서비스 매니저의 재시작은 detach된 세션을 전부 지운다"를 알리는 info 진단을 낸다. 유닛 검출은 `service_not_registered`가 쓰는 두 갈래(LaunchAgent, systemd user unit)를 재사용한다. code 초안은 `service_restart_drops_sessions`, remedy는 `docs/deploy/service.md`의 해당 절과 README Known limitations를 가리킨다. `EXPECTED_DOCTOR_CODES`가 23종에서 24종이 되고 같은 커밋에서 `docs/CLI.md` §6.11의 "진단 코드 N종", §6.17의 "N종 진단 코드"와 표, `crates/qsh-core/src/doctor.rs` 모듈 doc의 "23 variants"가 바뀐다.
- 배너. `qsh serve`와 `qsh listen`의 기동 stderr에 "세션은 이 프로세스 안에 산다. 재시작하면 detach된 세션이 사라진다"는 한 줄을 사람용 줄로 낸다. `qsh serve: listening on {addr}` 줄의 바이트와 `LISTENING_PREFIX`·`LISTEN_LISTENING_PREFIX`를 쓰는 하네스는 바뀌지 않도록 그 줄 뒤에 둔다. `--quiet`이면 내지 않는다. 문면 상수는 `qsh-core`에 둔다.

**(b) 테스트·게이트:** L6(`crates/qsh-cli/tests/serve_sigterm_drain.rs`, `lifecycle_lines.rs`). `sigterm_drain_emits_one_drained_lifecycle_line_with_the_closed_session_count`, `drained_line_carries_no_session_id_address_or_payload`, `serve_startup_banner_states_that_a_restart_drops_detached_sessions`, `quiet_suppresses_the_restart_banner`. 단위(`crates/qsh-core/src/ops/doctor/tests.rs`). `service_restart_drops_sessions_appears_only_when_a_unit_is_registered`, `service_restart_drops_sessions_is_info_and_carries_a_remedy`. 개수 게이트 `expected_doctor_codes_matches_every_diagnostic_id_variant_exactly`, `cli_md_prose_doctor_code_count_matches_expected_len`. 기존 `serve_and_listen_listening_lines_are_byte_identical_and_a_lifecycle_line_carries_at`, `jsonl_purity.rs` 초록.

**(c) 완료 판정:** 위 테스트 초록. drain 줄 테스트는 SIGTERM 뒤 캡처한 stderr 줄을 기다리므로 부하 아래 50회 연속 초록. `grep -n '24' docs/CLI.md`로 §6.11·§6.17의 개수 산문이 바뀐 것을 확인한다. fixture diff 0.

### Step 14 — (b) splice 수정 (0~1.3ew, ADR-0037 승인 뒤. Step 3의 둘째 갈래면 ADR 없이)

근거: ROADMAP M13 DoD (b), 승인된 ADR-0037의 결정 절. 선행: Step 2, Step 3, ADR 승인.

**(a) 범위:** 승인된 설계를 `crates/qsh-core/src/tunnel/splice.rs`(필요하면 `tunnel/local.rs`, `tunnel/dynamic.rs`, `tunnel/remote.rs`)에 구현한다. 계획 시점의 제약은 셋이다. `CONNECTION_RECEIVE_WINDOW`(8 MiB)와 `TUNNEL_STREAM_RECEIVE_WINDOW`(2 MiB)의 값은 바꾸지 않는다. 앱 쪽 버퍼를 새로 두면 그 합이 세션당 buffer 상한(M8 DoD 2) 안에 있다는 것을 상수 관계와 테스트로 보인다. 느린 소비자의 연결을 끊는 설계라면 그 끊김이 로컬 앱에 RST로 보여 "스트림이 정상 종료됐다"로 오인되지 않게 한다(`SpliceGuard`의 기존 규율).

Step 2의 테스트를 `ci.yml` acceptance job에 `QSH_ACCEPTANCE_STRICT` 아래 한 스텝으로 넣는다. `CLAUDE.md` Commands 절의 acceptance 목록, `docs/design/testing.md` 게이트 환경변수 표와 L9/L10의 "덮는 축은 포화(고속) 하나다" 문단(이제 두 축을 덮는다), `docs/design/protocol.md` §12의 backpressure 서술, `crates/qsh-transport/src/endpoint.rs`의 두 창 상수 doc(창 관계가 더는 PTY 기아의 유일한 방어가 아님), `docs/design/threat-model.md` §4 C(느린 소비자로 PTY를 굶기는 위협과 통제, 핀 테스트 이름)를 같은 커밋에서 고친다. ADR이 새 reset 코드를 정했으면 `docs/design/protocol.md` §16.2 표에 행을 더한다.

**(b) 테스트·게이트:** Step 2의 네 테스트가 strict에서 초록. 단위(`crates/qsh-core/src/tunnel/splice/tests.rs` 또는 기존 테스트 모듈, ADR이 고른 설계에 맞춰 이름 확정). 초안은 `splice_stops_only_the_stalled_stream_when_its_app_buffer_fills`, `a_stalled_stream_stop_leaves_other_tunnel_streams_and_the_pty_untouched`, `a_stopped_stalled_stream_reaches_the_local_app_as_a_reset_not_a_clean_end`, `tunnel_app_buffers_per_connection_stay_within_the_session_buffer_ceiling`. 고치지 않은 기준으로 `tunnel_throughput_meets_raw_quinn_ratio`, `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`, `transport_config_sets_connection_receive_window`, `tunnel_stream_receive_window_never_regresses_below_quinns_own_default`, `socks_curl`, `a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes`, `load.yml`의 soak·adversarial load 초록.

**(c) 완료 판정:** 위 테스트 초록. 진행 단언과 단위 테스트는 부하 아래 50회 연속 초록, 지연 단언은 부하 없이 50회 연속 초록(§8 #5). acceptance job이 새 스텝을 포함해 한 번 이상 초록. mutation 하나(새 방어를 끄기)가 `pty_output_keeps_progressing_while_four_unread_tunnel_streams_stall`을 붉힌다. `git diff --stat -- crates/qsh-proto/proto`가 비어 있다.

### Step 15 — (d) `qsh doctor --fail-on` 구현 (0.25~0.45ew, ADR-0027 승인 뒤)

근거: ROADMAP M13 DoD (d), 승인된 ADR-0027. 선행: Step 4와 승인.

**(a) 범위:** 임계 비교는 `qsh-core`에 둔다(`DoctorData`의 finding 중 임계 이상 `status`가 있는지 답하는 함수 하나). `qsh-cli`는 clap에 `--fail-on <warn|error>`를 더하고, 그 함수의 답에 따라 ADR-0027이 정한 exit 값으로 끝나며, 렌더러 출력은 바꾸지 않는다. 임계 어휘 밖의 값은 clap이 exit `2`로 거절한다. `docs/CLI.md` §4 표에 ADR-0027의 행을 더하고, §6.17의 "exit code는 항상 `0`이다" 문단에 `--fail-on` 예외를, "`--fail-on` 플래그는 아직 없다" 문단을 새 동작 설명으로 교체한다. 상태 헤더 v0.19 항목에 덧붙인다. `cargo xtask man`으로 `qsh-doctor.1`을 다시 만든다. JSON 모양은 ADR이 바꾸지 않으면 fixture를 더하지 않는다.

**(b) 테스트·게이트:** L6(`crates/qsh-cli/tests/`). `doctor_without_fail_on_keeps_exit_zero_and_byte_identical_stdout`, `doctor_fail_on_warn_exits_one_when_a_warn_or_error_finding_exists`, `doctor_fail_on_error_ignores_warn_findings`, `doctor_fail_on_keeps_the_envelope_ok_true_and_every_finding`, `doctor_fail_on_rejects_info_and_unknown_severities_with_exit_2`, `doctor_fail_on_does_not_change_the_255_of_a_doctor_that_cannot_start`. `crates/qsh-cli/tests/exit_code_matrix.rs`에 새 행. 단위(`qsh-core`). `doctor_threshold_matches_the_overall_severity_order`. 기존 doctor fixture, `checked_in_man_pages_match_the_generator`, `layer_2_every_schema_command_has_all_six_faces` 초록.

**(c) 완료 판정:** 위 테스트 초록. `git diff --stat -- crates/qsh-cli/tests/fixtures`가 비어 있다(ADR이 JSON을 바꾸면 새 파일만). `grep -n 'fail-on' docs/CLI.md`가 §4와 §6.17에서 각 1건 이상이고 "아직 없다" 문장은 0건.

### Step 16 — (f) H1b stateless reset key 구현 (0.25~0.35ew, ADR-0036 승인 뒤)

근거: ROADMAP M13 DoD (f), 승인된 ADR-0036, `docs/design/reexec-estimate.md` §3 H1b 행. 선행: Step 5와 승인.

**(a) 범위:** `qsh-core`가 ADR-0036이 정한 자리에서 키를 읽거나 만들고, 읽기 실패는 ADR이 정한 동작을 따른다. `qsh-transport`의 서버 endpoint 생성 함수가 키 바이트를 인자로 받아 `quinn::EndpointConfig::new`에 HMAC 키로 넘긴다. 클라이언트 endpoint와 테스트용 raw quinn 경로(`crates/qsh-testkit/src/raw_quic.rs`)는 `default()`를 유지한다. 키 버퍼는 `Zeroizing`에 둔다(`crates/qsh-core/src/resume.rs`의 토큰 위생과 같은 규율). 기동 진단의 문면 상수는 `qsh-core`에 둔다.

클라이언트가 reset을 받으면 quinn이 `ConnectionError::Reset`으로 연결을 닫는다. recovery는 그 뒤 재dial하고, 새 서버에 세션이 없으므로 현행 attach 실패 코드로 끝난다. recovery의 분류 어휘는 바꾸지 않는다(ROADMAP 범위 (f)의 "감지 지연이지 recovery 분류가 아니다"). `classify_connection_error`(`crates/qsh-core/src/reverse/mod.rs`)가 `Reset`을 지금처럼 `local`로 적을지는 §8 #3이 정한다.

문서를 같은 커밋에서 고친다. `docs/CLI.md` §6.12·§6.13(키 파일과 기동 진단), `docs/design/threat-model.md` §4 D·G, `docs/deploy/service.md`의 재시작 고지(재시작 뒤 클라이언트가 곧바로 단절을 안다), `docs/design/protocol.md` §10의 재시작 감지 서술, README Known limitations의 해당 문장, `docs/design/reexec-estimate.md` 추기 한 줄(H1b 착지 커밋). 상태 헤더 v0.19 항목에 덧붙인다.

**(b) 테스트·게이트:** testkit(`crates/qsh-testkit/tests/serve_restart_reset.rs`). `restarted_serve_resets_an_attached_client_within_the_redial_deadline_and_reports_the_session_lost`(재시작 뒤 첫 패킷부터 단절 확정까지를 관찰 채널로 재고, 45초 idle보다 훨씬 이른 `REDIAL_DEADLINE` 안임을 단언. 오류 코드는 §6.3·§6.4의 현행 attach 실패 코드), `a_serve_restarted_with_a_new_key_leaves_detection_to_path_watch`(대조군. 키 파일을 지우고 재시작하면 reset이 오지 않는다). 단위(`qsh-core`). `reset_key_file_is_created_once_with_mode_0600_and_reused_across_restarts`, `reset_key_file_with_wider_permissions_emits_a_startup_diagnostic`, `unreadable_or_malformed_reset_key_is_never_silently_replaced`(파일 바이트가 전후 같음, ADR이 정한 경로의 동작), `reset_key_never_appears_in_logs_audit_or_diagnostics`. 단위(`qsh-transport`). `server_endpoint_uses_the_injected_reset_key`. 기존 `keep_alive_and_idle_timeout_are_configured_and_ping_pong_roundtrips`, `resume_secrecy.rs`, `serve_sigterm_drain.rs` 초록.

**(c) 완료 판정:** 위 테스트 초록. testkit 테스트는 부하 아래 50회 연속 초록(재시작한 서버가 같은 UDP 포트를 다시 잡는 경합이 여기서 드러난다, §4). mutation 하나(`EndpointConfig::default()`로 되돌리기)가 첫 testkit 테스트를 붉힌다. `git diff --stat -- crates/qsh-proto/proto crates/qsh-cli/tests/fixtures`가 비어 있다.

### Step 17 — (k) ADR-0021 결정 1(과 4) 구현 (0.35~0.5ew, 관측 기록 뒤. 기록이 없으면 0ew)

근거: ADR-0021 결정 1·4·6·7과 결과 절, ROADMAP M13 범위 (k)와 DoD (k), ADR-0023 결정 25. 선행: §0.2의 관측 기록.

**(a) 범위:** 관측 기록을 먼저 읽고 결정 7의 분기를 커밋 본문에 적는다(기록의 위치와 `cause` 값별 계수). 결정 1은 `[transport].keep_alive_ms`(기본 15000, `1000..=20000`)를 연다. `qsh-core`의 `Config`가 읽고 검증하며 범위 밖이면 clamp하지 않고 `CONFIG_ERROR`(`retryable: false`)로 기동을 거절한다(`ReverseConfig::backoff` 선례). 값은 `qsh-transport`의 transport config 생성 함수에 인자로 넘어가고 `KEEP_ALIVE_INTERVAL`은 기본값 상수로 남는다. `MAX_IDLE_TIMEOUT`은 건드리지 않는다(결정 2). 결정 4까지 가는 분기면 `[recovery].probe_interval_ms`, `min_dead_after_ms`, `strikes`를 열고, 범위 상한은 `crates/qsh-cli/tests/reverse_blackout.rs`, `crates/qsh-cli/tests/attach_recovery.rs`, `crates/qsh-testkit/tests/reverse_resume_chaos.rs`의 `detection_budget`에서 역산한다. 세 값은 대화형 recovery, 두 역방향 자리, supervised 터널의 `PathWatch`에 모두 들어간다. M11 (a)가 두 역방향 자리에 둔 `#[cfg(test)]` `PathWatchConfig` 주입은 그대로 둔다. 나머지 세 필드는 열지 않는다.

결정 6의 문서 자리를 같은 커밋에서 고친다. `docs/design/protocol.md` §1 요약표의 keep-alive/idle 행, §2 산문, §11-4 항목 4, `docs/design/architecture.md` §7의 `config.toml` 키 나열, `docs/CLI.md`의 설정 키 서술(상태 헤더 v0.19에 덧붙임). `config_unknown_key`는 `Config`의 필드로 따라오므로 손댈 목록이 없다(결정 6).

**(b) 테스트·게이트:** 단위(`crates/qsh-core/src/config.rs`의 테스트 모듈). `transport_keep_alive_ms_outside_1000_to_20000_is_config_error_without_clamping`, `absent_transport_section_keeps_the_fifteen_second_keep_alive`, `keep_alive_ms_reaches_the_quinn_transport_config`. 결정 4 분기면 `recovery_values_beyond_the_detection_budget_bound_are_config_error`, `absent_recovery_section_keeps_todays_path_watch_config_byte_identically`, `recovery_section_reaches_attach_reverse_and_supervised_path_watch`. 고치지 않은 예산으로 세 `detection_budget` 테스트, `a_real_60_second_blackout_survives_and_resumes_the_same_session`(`QSH_ACCEPTANCE_SLOW`), `keep_alive_and_idle_timeout_are_configured_and_ping_pong_roundtrips`, `doctor_config_unknown_key_findings` 계열 초록.

**(c) 완료 판정:** 위 테스트 초록. 설정 검증 테스트는 시간 의존이 없다. 설정이 없을 때 `PathWatchConfig`와 transport config의 `Debug` 출력이 오늘과 같다. `git diff --stat -- crates/qsh-proto/proto`가 비어 있다. 기록이 없어 이 스텝을 열지 않으면 Step 18이 이월을 적는다.

### Step 18 — 마감 (0.1~0.2ew)

근거: 마일스톤 마감 공통 절차(`docs/ROADMAP.md` §2) 1·2, §2의 안정성 규율. 선행: Step 2~17(열지 않은 조건부 스텝은 그 사실의 기록).

**(a) 범위:** 부하 반복. M13이 더한 타이밍 민감 테스트 전부(Step 2의 진행·경계·정체 관찰 테스트, Step 13의 drain 줄 테스트, Step 14의 진행 단언과 splice 단위, Step 16의 testkit 테스트)를 한 filterset(`scripts/stress/m13.filter`, §4.1 #2)으로 묶어 `scripts/stress/run.sh`로 `QSH_ACCEPTANCE_SLOW=1`과 함께 50회 돌리고, "50/50 passed under load" 줄과 호스트 사양(OS, 논리 CPU 수)을 마감 노트에 적는다. 지연 단언 테스트(Step 2·14)는 부하 없이 50회 돌린 결과를 따로 적는다. 한 번이라도 붉으면 그 테스트를 고치고 50회를 처음부터 다시 돈다.

절차 1. 구속 문서 태그를 대조한다. `docs/CLI.md` v0.19 항목이 M13 델타(§4 새 exit 행, §6.11·§6.17의 진단 개수와 `--fail-on`, §6.12의 `drained`·배너·reset key, §6.13, 설정 키)를 빠짐없이 적는지 본다. `docs/design/protocol.md` §1·§2·§10·§11-4·§12(·§16.2), `docs/design/testing.md`(CI 규율의 perf 항목, 게이트 환경변수 표, L9/L10), `docs/design/architecture.md` §7, `docs/design/threat-model.md` §4 C·D·G, `docs/deploy/service.md`, `docs/design/reexec-estimate.md` 추기, ADR-0021·0027·0036·(0037)의 결과 절 문서 목록 전수를 대조한다. `docs/campaigns/m10-clean-vm.md` diff 0을 확인한다. 절차 2. README를 동기화한다. 대상은 Status, Roadmap 표의 M13 행, 설치 절(provenance, man, aarch64 musl), Known limitations(재시작 고지, reset key), "First run" 절 무변경이다.

`docs/ROADMAP.md` M13 절에 마감 노트를 적는다. (k)를 열지 않았으면 "관측 기록 없음"과 이월 대상 마일스톤을 적는다(§8 #6). (j)를 기각했으면 그 기록을 적는다. §5.5 표의 aarch64 musl 행 상태를 갱신한다. 이 `PLAN.md`를 `docs/history/m13-plan.md`로 옮기고 다음 계획으로 교체한다. M14의 ADR-0028이 승인되지 않았으면 다음 계획은 사람 몫만 추적하는 자리표시자다(`CLAUDE.md` Session onboarding 2).

**(b) 테스트·게이트:** 일곱 게이트와 CI acceptance job 초록. 부하 반복 50/50.

**(c) 완료 판정:** §1의 DoD가 근거 커밋과 run id와 함께 `[x]`다. `docs/history/m13-plan.md`가 있다. `git diff --stat <M13 Step 1>..HEAD -- crates/qsh-proto/proto docs/campaigns/m10-clean-vm.md`가 비어 있다.

## 3. 명시적 non-goals

- H2(인스턴스 식별값), H4(execve 제자리 handoff), H5(supervisor 분리). M18이다. H3(소켓만 넘기는 handoff)은 `docs/design/reexec-estimate.md` §4가 기각했다.
- 재시작 뒤 세션을 살리는 것. H1b는 감지 지연만 줄이고 세션은 여전히 죽는다(`docs/design/reexec-estimate.md` §3 H1b 행 "잃는 것" 칸).
- 흐름 제어 상수(`TUNNEL_STREAM_RECEIVE_WINDOW`, `CONNECTION_RECEIVE_WINDOW`)의 값 조정으로 (b)를 푸는 것. ROADMAP M13 범위 (b)가 기각했다.
- idle timeout 45초의 개방, `PathWatchConfig`의 나머지 세 필드 개방. ADR-0021 결정 2·4.
- 야간 perf job을 PR 게이트나 `ci-ok`의 `needs`에 넣는 것. 새 시크릿이 필요한 외부 저장소.
- `QSH_LIBC` 기본값 변경과 musl 자동 감지. `scripts/install.sh` 머리 주석과 ROADMAP M13 범위 (c).
- `docs/campaigns/m10-clean-vm.md`의 수정, `.pkg` 배포 형식. ROADMAP M13 명시적 out.
- `doctor --fail-on`이 finding 출력을 거르는 것. 임계는 exit만 바꾼다(ADR-0027 초안).
- reset key 회전 명령과 키스토어 보관. ADR-0036 초안.
- Windows 설치 스크립트, Windows 서버의 reset key 권한 모델. Windows host는 P2다.
- 에이전트가 하는 `gh secret set`, `gh workflow run`, 태그 push, 저장소 설정 변경. 전부 사람 몫이다(§0.4).
- `qsh.event/v1`의 새 type. ADR-0022 결정 3의 관측 트리거 전이다.
- P2 항목 전부.

## 4. 리스크와 감시 항목

- **(b)가 붉고 ADR 승인이 늦는 경우.** 예상 갈래다. M15의 착수 조건이 M13 (b)이므로 승인 지연이 M15를 그만큼 민다(§5.4 리스크 3). 대응은 하네스와 ADR 초안을 맨 앞(Step 2·3)에 두고, 승인을 기다리는 동안 M13의 나머지와 M14의 ADR 없는 스텝을 여는 것이다. 수정 크기의 상단 1.3ew는 ADR이 (나)안처럼 연결 단위 계수를 고르면 넘을 수 있다. 그때는 Step 14 착수 전에 다시 매겨 이 절에 적는다.
- **(b) 하네스가 정체를 못 만드는 경우.** 로컬 소켓 버퍼가 커서 splice가 계속 읽거나, quinn이 credit을 예상과 다른 시점에 돌려주면 "정체가 안 생겨서 초록"이 된다. `stalled_stream_harness_observes_data_blocked_before_measuring`이 이 경우를 붉게 만든다. 플랫폼마다 `SO_RCVBUF` 하한이 달라 macOS runner에서 정체까지 걸리는 시간이 길어질 수 있다.
- **perf 게이트와 부하 반복의 충돌.** CPU 포화 아래에서 echo p95가 10ms를 넘는 것은 측정 대상의 변화이지 경합이 아니다. §2 규율이 지연 단언을 부하 반복에서 빼고 부하 없는 50회로 대신한다(§8 #5).
- **야간 perf의 잡음.** 공유 runner의 편차가 20%·50% 임계를 넘으면 거짓 붉음이 습관이 된다(`docs/design/testing.md`의 "공유 runner의 flake가 무시 습관을 만든다"). 대응은 중앙값 기준, 7점 미만 무판정, 주입 회차 제외다. 붉음이 잦으면 임계를 올리는 결정을 testing.md에 기록한다.
- **`perf-data` 브랜치 쓰기.** 워크플로가 브랜치에 push하려면 그 job에 `contents: write`가 필요하고, 브랜치 보호 규칙이 모든 브랜치에 걸려 있으면 push가 막힌다. 보호 규칙 확인과 변경은 사람 몫이다. 막히면 Step 6의 후보 (2)로 물러나고 그 사실을 testing.md에 적는다.
- **aws-lc-sys의 aarch64 musl 빌드.** `release.yml` 주석은 x86_64 musl에 미리 생성된 바인딩이 있다고만 적는다. aarch64 musl에서 cmake·bindgen 경로를 타면 leg이 붉다. M10 결정 기록 Q3의 대응(ADR 선행)을 따른다. 이 판정은 사람이 돌리는 dispatch run에서만 나오므로 Step 8 머지와 판정 사이에 시차가 있다.
- **설치 스크립트 대역의 충실도.** `curl`·`gh` 대역은 실제 도구의 오류 문면과 exit 값을 흉내 낼 뿐이다. `gh attestation verify`의 실제 출력과 인증 요구는 첫 태그 뒤 사람이 한 번 확인한다(§8 #4의 태그 권고와 같은 때).
- **README 설치 절과 캠페인 대상.** (h)·(i)는 README 설치 절을 고친다. M7·M9 캠페인이 재는 "First run" 절과 설치 절의 경계가 흐리면 측정 대상이 바뀐다. Step 9·10의 완료 판정이 "First run" 절 diff 0을 확인한다.
- **stateless reset 테스트의 포트 재사용.** 재시작한 `qsh serve`가 같은 UDP 포트를 다시 잡아야 reset이 성립한다. `SO_REUSEADDR`를 쓰지 않으므로 닫힌 직후 다른 테스트가 그 포트를 잡을 수 있다. 부하 반복에서 드러나면 재시작을 같은 소켓 주소로 재시도하는 테스트 도우미를 두고, 재시도 횟수를 테스트 출력에 남긴다.
- **(k)의 `[recovery]`와 supervised 터널.** `PathWatchConfig`가 ADR-0023의 supervisor와 wake 감지 상한(`WAKE_TICK + dead_after(rtt)`)에도 들어가므로, 값을 넓히면 M12 테스트의 주입 시계 상한이 설정에 따라 달라진다. 범위 상한을 `detection_budget`에서 역산하면 M12의 상한 단언도 그 안에 들어가는지 Step 17이 확인한다.
- **(k)가 끝내 열리지 않는 경우.** 관측 기록은 사람 몫이라 M13 안에 오지 않을 수 있다. §0.6과 §8 #6대로 이월한다.
- **`exclude = ["tests/"]`와 cargo 경고.** 테스트 타깃이 tarball에 없으면 cargo가 게시 매니페스트에서 그 타깃을 빼며 경고를 낸다. `publish-dry-run`이 경고를 오류로 다루지 않는지 Step 11에서 확인한다.
- **Windows 다리.** 설치 스크립트 테스트와 reset key 권한 테스트는 unix 전용이라 cfg 가드 없이는 Windows clippy·test에서 붉다.

### 4.1 구현 중 확정할 값 (해당 step (a)에 근거와 함께 추기)

| # | 질문 | 초안 | 확정 시점 |
|---|---|---|---|
| 1 | (b) 정체의 관찰 기준 | 클라이언트 쪽 `Connection::stats()`의 수신 `DATA_BLOCKED` 계수가 0보다 크거나 N개 스트림 전부에서 `STREAM_DATA_BLOCKED` 관찰. quinn 0.11 stats가 이 계수를 주지 않으면 호스트 쪽 목적지 서버의 누적 쓰기 바이트가 N × 2 MiB에 닿는 것을 대신 쓴다 | Step 2 |
| 2 | M13 부하 filterset | 테스트 이름 접두(`pty_output_keeps_progressing_`, `stalled_stream_harness_`, `sigterm_drain_emits_`, `drained_line_`, `splice_stops_`, `a_stalled_stream_`, `restarted_serve_resets_`, `a_serve_restarted_`)를 묶은 한 식을 `scripts/stress/m13.filter`에 둔다. 지연 단언은 별도 식 | Step 2, Step 18 |
| 3 | perf 저장소 | orphan 브랜치 `perf-data`의 `perf.jsonl`. 점 하나에 `at`, `sha`, `runner`, `throughput_mbps`, `raw_quinn_mbps`, `echo_p95_ms`, `rtt_ms`, `injected` | Step 6 |
| 4 | perf 임계와 보존 | 직전 7점(주입 제외) 중앙값 대비 throughput −20% 이하 또는 echo p95 +50% 이상이면 붉음. 7점 미만 무판정. 보존 365점 | Step 6 |
| 5 | 인위적 지연의 자리 | `QSH_PERF_INJECT_DELAY_MS`를 testkit 하네스가 읽어 루프백 relay에 고정 지연을 넣는다. `qsh-core`와 바이너리에는 훅이 없다 | Step 7 |
| 6 | aarch64 musl 분기의 다운로드 순서 | 이 분기만 `SHA256SUMS`를 먼저 받아 자산 줄을 확인한다. 나머지 경로의 순서와 문면은 그대로 | Step 8 |
| 7 | 설치 스크립트 테스트의 자리 | `xtask/tests/install_script.rs`. 게시되지 않는 크레이트라 (g)의 tarball 정책과 얽히지 않는다. 가짜 릴리스와 PATH 대역은 테스트마다 고유 tempdir | Step 8 |
| 8 | reset key 파일 자리 | config 디렉터리 바로 아래 `stateless_reset.key`(32바이트 원시값). ADR-0036이 확정한다 | Step 5, Step 16 |
| 9 | 미인증 `gh`의 취급 | `gh auth status`가 실패하면 "도구 없음"과 같게 보고 경고 뒤 체크섬만으로 설치. `gh attestation verify`가 인증 없이 도는 것이 확인되면 이 분기를 없앤다 | Step 9 |
| 10 | man 설치 기본 디렉터리 | `${XDG_DATA_HOME:-$HOME/.local/share}/man/man1`, 끄는 플래그 `QSH_NO_MAN=1`, 덮는 변수 `QSH_MAN_DIR` | Step 10 |
| 11 | (j) 핀 테스트의 자리 | `crates/qsh-core/tests/doctor_docs.rs` 옆의 새 파일 `crates/qsh-core/tests/cli_md_header.rs`. 문서만 읽는다 | Step 12 |
| 12 | Step 16·17의 설정 로더 충돌 | 둘 다 `crates/qsh-core/src/config.rs`를 만질 수 있다. 겹치면 Step 17을 먼저 착지하고 Step 16이 그 위에 얹는다 | Step 16·17 |
| 13 | drain 요약 줄의 필드 | `qsh::lifecycle`의 `drained`, 필드 `at`, `process`, `sessions_closed`, `detached_closed`, `timed_out`. 세션 id는 싣지 않는다 | Step 13 |
| 14 | H1 doctor code 이름 | `service_restart_drops_sessions`(info). 잠금 어휘라 착지 뒤에는 바꿀 수 없다 | Step 13 |

## 5. 완료 절차

1. §1 DoD 전건을 실제 테스트와 CI run으로 확인한다. 체크박스는 근거가 초록일 때만 채운다. 사람이 돌린 run은 run id로 근거를 삼는다.
2. 부하 반복 50/50과 지연 단언의 부하 없는 50/50을 기록한다(Step 18).
3. 구속 문서 태그를 대조한다. 대상은 Step 18 (a)가 열거한 자리 전수다.
4. README를 동기화한다. Status, Roadmap 표, 설치 절, Known limitations, "First run" 절 무변경.
5. `docs/design/testing.md`의 M13 반영을 확인한다. CI 규율의 perf 항목, 게이트 환경변수 표의 새 행, L9/L10의 역압 축 문단.
6. `docs/ROADMAP.md` "현재 위치"와 M13 절을 갱신하고 마감 노트를 적는다. (k) 이월과 (j) 기각 여부를 포함한다.
7. §0.1 일곱, §0.2 둘, §0.3 둘의 상태를 승계한다.
8. §0.4의 aarch64 musl 캠페인은 §5.5 표의 행에 상태만 갱신한다.
9. 이 `PLAN.md`를 `docs/history/m13-plan.md`로 옮기고 다음 계획으로 교체한다.

## 6. 이월 항목

| # | 항목 | M13 처분 |
|---|---|---|
| i | `docs/design/testing.md` L9/L10의 "넷이 동시에 멈추면 … 실측된 적이 없다" 잔여 위험 | Step 2·3·14 |
| ii | `docs/design/testing.md`의 "절대 throughput 추세는 여전히 nightly"가 가리키던, 실제로는 없던 nightly job | Step 6·7 |
| iii | M10 결정 기록 Q3의 aarch64 musl | Step 8. 구형 glibc 판정은 §5.5 사람 몫 |
| iv | `docs/CLI.md` §6.17의 "`--fail-on` 플래그는 아직 없다" | Step 4·15 |
| v | `docs/design/reexec-estimate.md` 추기(2026-09-24)가 P1로 재기록한 H1·H1b | Step 13·16. H2는 M18 |
| vi | `scripts/install.sh`의 "this installer does not check" provenance 문장과 "does not install" man 문장 | Step 9·10 |
| vii | ADR-0021 결정 1·4 | Step 17. 관측 기록이 없으면 §8 #6의 이월 |
| viii | 옛 계획·ADR 줄 번호 인용 부채 | 새 인용을 만들지 않고 손대는 파일의 인용만 앵커로 바꾼다. `docs/design/reexec-estimate.md`의 줄 번호 인용은 Step 16의 추기 한 줄 외에는 건드리지 않는다 |

## 7. 태그 정책

- M13 마감에 태그가 하나 필요하다. DoD (c)의 "자산이 `SHA256SUMS`와 provenance attestation에 들어간다"는 태그 push에서만 도는 release job이 근거이기 때문이다. 태그를 찍을지와 언제 찍을지는 유지보수자 결정이다(§8 #4).
- 권고. Step 8·9·10이 모두 착지한 뒤 태그 하나를 찍으면 aarch64 musl 자산, provenance 검증, man 설치를 한 번에 실제 릴리스로 확인할 수 있고, `p1-aarch64-musl` 회차와 `p1-supervise-wake`·`p1-setup-stopwatch` 회차도 그 바이너리로 돌 수 있다.
- 찍는다면 M10판 정책을 그대로 따른다. 찍은 태그는 옮기지 않고, 태그 push가 `release.yml`을 구동하며, 서명·공증이 없는 태그로는 M10 DoD 2를 판정하지 않는다. `RELEASE-NOTES.md`에 새 절을 더한다.

## 8. 열린 질문

각 항목 끝의 **결정** 문장은 초안이다. main 세션이 Step 1 커밋에서 확정하되, ADR 승인에 걸린 항목은 사용자가 정한다.

1. **(b)의 splice ADR을 언제 올리는가.** §5.4 리스크 3은 "설계 변경이 필요하다고 판정되면 그날" 올리라고 한다. **결정:** Step 2 착지 당일 strict 결과로 Step 3의 갈래를 고르고, 셋째 갈래면 같은 날 ADR-0037을 `제안됨`으로 올린다. 승인은 사용자가 정하며 Step 14는 승인 전에 열지 않는다.
2. **(f)의 읽기 실패 동작을 ADR로 올릴 것인가.** ROADMAP DoD (f)는 "골라 커밋에 적는다"고만 적어 ADR 없이도 닫을 수 있다. 그러나 선택지 하나(기동 거절)는 `docs/CLI.md` §6.12의 기동 계약을 바꾸고, 다른 하나(임시 키)는 비밀을 디스크에 두는 규율을 정한다. **결정:** ADR-0036으로 올리고 Step 16을 그 승인에 건다. Step 1이 ROADMAP §5.1 원칙 2, M13 착수 조건, §5.2 표에 이 게이트를 더한다. 사용자가 ADR 없이 커밋 기록으로 충분하다고 정하면 ADR-0036은 기각으로 닫고, Step 16은 초안의 임시 키 동작으로 연다.
3. **stateless reset으로 닫힌 연결의 `cause`.** `classify_connection_error`는 `ConnectionError::Reset`을 지금 `local`로 적는다. H1b 뒤에는 `qsh serve` 재시작이 현장 로그에 `local`로 보여 (k)가 읽는 분포를 흐린다. **결정:** Step 16에서 `stateless_reset` 값 하나를 더하고 `docs/CLI.md` §6.13의 고정 값 개수 문장과 함수 doc을 같은 커밋에서 고친다. `qsh::reverse` 줄은 계약이 아니므로(ADR-0022 결정 5) fixture와 `qsh.cli/v1`은 바뀌지 않는다. 사용자가 범위 밖으로 보면 README Known limitations에 한 줄로 적고 넘긴다.
4. **(c)의 `SHA256SUMS`·attestation 판정과 태그.** release job은 태그 ref에서만 돈다. **결정:** leg 빌드와 스모크는 유지보수자의 dispatch run으로 판정하고, `SHA256SUMS`와 attestation 포함은 M13 마감 전 첫 태그 run으로 판정한다. 마감 시점에 태그가 없으면 DoD (c)의 그 문장만 "태그 대기"로 남기고 main 세션이 M13을 닫을지 정한다. 에이전트는 태그를 찍지 않는다.
5. **지연 단언의 부하 반복 면제.** CPU 포화는 echo p95를 바꾼다. **결정:** 지연 단언(echo p95, throughput 비율)은 부하 없이 50회 연속 초록을 기록하고, 같은 하네스의 진행·정체 관찰 단언은 부하 아래 50회를 지킨다. `docs/design/testing.md` CI 규율의 부하 반복 항목에 이 예외를 한 문장으로 더한다(Step 2 커밋).
6. **(k) 이월 대상.** 관측 기록 없이 M13이 닫히면 (k)를 어디로 보내는가. **결정:** M17(운영 표면)로 보낸다. 설정 키와 운영 진단을 다루는 마일스톤이고 착수 조건에 사람 기록을 더해도 다른 항목이 막히지 않는다. 그보다 먼저 기록이 오면 그때 열린 마일스톤에 ROADMAP 개정으로 넣는다.
7. **ROADMAP M13 DoD에 안정성 줄을 더할 것인가.** M12 DoD에는 있었고 M13 DoD에는 없다. **결정:** 더한다. 문면은 M12의 안정성 줄을 따르고 §8 #5의 예외를 한 구절로 붙인다. Step 1이 넣는다.
8. **`doctor --fail-on`의 exit 값.** ADR-0027 초안은 `1`이다. **결정:** 사용자 승인 사항이라 이 계획은 정하지 않는다. Step 15의 테스트 이름에 들어간 `exits_one`은 승인된 값에 맞춰 바꾼다.
