# PLAN.md — M10: 릴리스

M9가 코드 스텝과 계약 문서를 마치고 사람 몫 DoD 하나를 남긴 채, 이 문서는 M10 실행 계획으로 전면 교체됐다. 구속 근거: `docs/ROADMAP.md` M10 절(범위, 스켈레톤 조기 반영, 수용 기준, 감사 개정, M8 이관, M9 이관, 크기, 검토 항목), 마일스톤 마감 공통 절차(같은 문서 §2), `docs/PRD.md` §13·§15·§16, `docs/CLI.md` §2.4·§2.5, `docs/design/threat-model.md` §0·§3·§4·§5, `docs/design/testing.md` L9/L10과 CI 규율, ADR-0006, ADR-0011 결정 5. 이 계획과 `docs/ROADMAP.md`의 편집은 main 세션 전용이다.

M10은 저장소 밖 자격에 묶인 첫 마일스톤이다. Apple 계정과 인증서, 서명·공증 시크릿, crates.io 토큰, 클린 VM — 네 묶음이 §0.1에 있고, 그것이 늦으면 Step 5·10·11만 밀리고 나머지 스텝은 그대로 진행된다. 인용 규율 하나를 앞세운다. 이 문서는 `docs/` 아래 문서를 줄 번호로 가리키지 않는다 — 절 이름, DoD 문장, ADR 번호와 결정·결과 라벨, 테스트 이름, 커밋 해시가 앵커다. 코드 위치만 `path:line`을 쓰고 그때는 어느 트리에서 잰 값인지를 같은 문장에 적는다. 옛 마일스톤 계획의 스텝 번호도 새로 인용하지 않는다(§6).

## 0. 착수 조건

### 0.1 Step 5·10·11 이전에 사람이 확보해야 하는 자격 넷

- [ ] **Apple Developer Program 계정과 Developer ID Application 인증서.** `docs/ROADMAP.md` §4 리스크 5가 "notarization은 M10이 아니라 M8 중 시작"을 대응으로 적었는데 두 마일스톤이 지나는 동안 시작 기록이 없다. 막는 것: Step 5 전부, Step 10의 DoD 2 축. 소유: 사람.
- [ ] **notarization·서명 시크릿 여섯.** App Store Connect API key 방식(`notarytool --key`)을 권고한다 — `APPLE_API_KEY_ID`, `APPLE_API_ISSUER_ID`, `APPLE_API_PRIVATE_KEY`(p8 본문), 서명용 `APPLE_CERT_P12`(base64), `APPLE_CERT_PASSWORD`, `APPLE_TEAM_ID`. Apple ID + app-specific password 방식은 2FA 정책에 얽혀 회전이 번거롭다. 막는 것: Step 5. 소유: 사람.
- [ ] **crates.io 토큰 `CARGO_REGISTRY_TOKEN`.** dry-run은 토큰 없이 돌지만 실제 publish는 토큰과 사람 손이 필요하다(§8 #8). 막는 것: Step 11의 publish 실행분. 소유: 사람.
- [ ] **클린 VM 다섯.** macOS arm64, macOS x86_64, Linux arm64, Linux x86_64, 그리고 DoD 3을 위한 구형 glibc 이미지 하나. macOS x86_64는 실제 Intel 호스트가 필요하다 — Apple silicon의 Rosetta로 잰 것은 Gatekeeper 판정이 달라 회차로 세지 않는다. 막는 것: Step 10. 소유: 사람.

### 0.2 M7·M8·M9에서 열린 채 넘어온 DoD 넷

넷 중 어느 것도 M10의 코드 스텝을 막지 않는다. 다만 넷이 다 닫히기 전에는 P0 MVP 완료를 선언할 수 없다. M8 DoD 1(파서 타깃당 누적 72 fuzz-hours), DoD 2(24h/100-session soak run #6 PASS), DoD 5(적대적 부하 하네스)는 각각 `docs/campaigns/m8-fuzz.md`·`m8-soak.md`·`m8-adversarial-load.md`의 회차 기록으로 닫혀 있어 이 목록에 없다.

- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** 기준은 `docs/campaigns/m7-stopwatch.md`에 사전 고정돼 있고 회차 환경은 `scripts/stopwatch/round.sh`가 준비하지만 재는 대상이 사람 시간이다. 예행 1회만 끝났다. M9 DoD 1의 비교 대상이라 그보다 먼저 와야 한다. 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** Wi-Fi와 테더링 사이 자동 유지·resume 95% 이상, migrated/resumed 분해 보고. 통과 기준은 `docs/campaigns/m2-mobility.md`에 사전 정의. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 리뷰 계약(SC7).** `docs/design/protocol.md` §16의 상태가 아직 "초안 — 발효 전"이다. 선택지는 지금 리뷰를 예약하고 freeze를 예약일 6주 전으로 앞당기거나, 예약 없이 freeze만 진행하고 PRD를 개정하는 둘이다. 저장소 밖 조직 액션이라 에이전트가 대신할 수 없다. 발효 소커밋에 딸린 잔여 셋(CLOSE `0x1003` 이중 이름 처분, README Security posture 한 줄, DoD 4 문구)도 같이 온다. 다섯 마일스톤 연속 이월이고 리드타임은 이미 만료됐다. 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** 새 표면으로 독립 3회, 5분 이내, baseline 대비 단축 기록. 기준은 `docs/campaigns/m9-stopwatch.md`에 사전 고정됐고 에이전트 몫은 끝났다. M7 DoD 1에 종속이라 같은 진행자가 하루 안에 이어서 잰다. 소유: 사람.

## 1. DoD 체크리스트 (ROADMAP M10)

- [ ] **DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** macOS arm64/x86_64, Linux arm64/x86_64에서 brew 또는 curl 설치 후 `docs/ROADMAP.md` M10 수용 기준의 2026-08-21 감사 개정 항목이 정의한 기능 스모크 네 축이 통과. 근거: Step 10 회차. 소유: 사람(문서 사전 정의는 에이전트).
- [ ] **DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 조작적 정의는 Step 10 캠페인 문서가 고정한다. 근거: Step 5 + Step 10 회차. 소유: 에이전트(CI) + 사람(회차).
- [ ] **DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** 근거: Step 4 + Step 10의 구형 glibc 회차. 소유: 에이전트 + 사람.
- [ ] **DoD 4 — release 프로파일 기능 스모크가 태그 전 CI에서 최소 1회.** 감사 개정이 `version --json`을 명시적으로 배제했다. 근거: Step 2(하네스) + Step 3(배선). 소유: 에이전트.
- [ ] **DoD 5 — PRD §13 두 항목의 직접 증거.** "30분 단절 후에도 TTL 내 세션 복구"와 "느린 파일·터널 stream이 PTY stream을 block하지 않아야 함"이 각각 테스트 이름이나 회차 기록으로 인용 가능. 근거: Step 9. 소유: 에이전트(dispatch 1회 포함).
- [ ] **DoD 6 — threat-model이 M9 사람용 표면을 다룸.** §3 진입점과 §4 위협 표에 여섯 명령이 서고 §0의 유예 문장이 걷힌다. 근거: Step 8. 소유: 에이전트.
- [ ] **DoD 7 — 마감 공통 절차 1·2.** 구속 문서 태그 대조와 README 동기화. 근거: Step 13. 소유: 에이전트.

## 2. 실행 단계 (PR 단위)

스텝 번호는 이 문서 안에서만 쓰는 참조다. 크기 내역은 각 스텝 옆에 적고, `docs/ROADMAP.md` M10 크기 줄은 그 합계 2.6ew만 적는다. Step 0(자격 확보)과 Step 13(마감)은 크기 내역 밖이다. 규율은 앞 마일스톤 그대로다 — 문서·CI 변경은 코드 커밋과 분리하고, 계약 문서 델타는 그 표면을 바꾼 스텝의 같은 커밋에 싣는다. M10은 새 op을 만들지 않으므로 등록 완전성·fixture 축은 잠잠하고, 대신 CI 워크플로가 주된 변경면이다.

### Step 0 — 자격 확보 (사람, 크기 내역 밖)

§0.1의 넷을 실제로 받는 자리다. 넷이 다 늦어도 Step 1·2·3·4·8·9·12는 진행한다. Apple 자격만 받으면 Step 5가 열리고, 클린 VM이 오면 Step 10 회차가 열린다.

### Step 1 — M10 계획 교체와 옛 계획 복원 (0.25ew)

선행: 없음. M10의 첫 커밋이다.

**(a) 범위:** ① `PLAN.md`를 이 문서로 전면 교체하고 M9판을 `docs/history/m9-plan.md`로 옮긴다. 서두에는 `docs/history/m8-plan.md` 첫 문단과 같은 형식의 이관 문단을 붙인다 — 어느 날 무엇으로 교체됐는지, 어느 커밋에서 꺼낸 원문인지, 새 판정을 여기에 덧붙이지 않는다는 문장. M9 §1 체크박스는 DoD 1만 열린 상태 그대로 옮긴다. ② `docs/ROADMAP.md` — "현재 위치"를 M10으로, M9 헤더를 `🔄 기능 완료 (2026-09-24) · DoD 1 잔여`로(M7 선례와 같은 어휘, ✅는 붙이지 않는다), M9 절에 마감 노트 불릿 하나, M10 크기를 2.6ew로 갱신하고 그 사유를 한 줄, M10 결정 기록(§8 #1~#8), §7 태그 정책 한 줄 이관, M8 이관 항목의 PRD 줄 번호 인용을 §13 항목 문장 앵커로 전환. ③ `README.md` Status 산문과 Roadmap 표의 M9·M10 행. ④ 별도 커밋으로 M2~M6 계획 다섯을 `docs/history/m{2,3,4,5,6}-plan.md`로 복원한다 — 각각 교체 직전 커밋의 `PLAN.md`를 `git show`로 꺼내고 ①과 같은 형식의 서두를 붙인다. 이 복원이 `crates/` 아래 754건 인용의 대상 문서를 저장소 안에 되돌려 놓는다(§6).

**(b) 테스트·게이트:** 문서 변경이라 새 게이트가 없다. README 축자 게이트 `readme_quotes_the_controller_unreachable_diagnostic_verbatim`(`crates/qsh-core/tests/doctor_docs.rs`)이 걸린 자리는 건드리지 않는다. 기존 일곱 게이트 green.

**(c) 완료 판정:** `grep -nE 'docs/PRD\.md:[0-9]' docs/ROADMAP.md PLAN.md`가 0건. `ls docs/history/`가 m2부터 m9까지 여덟 파일. `docs/ROADMAP.md`에 태그 정책 문장 한 줄이 존재하고 M10 크기 줄이 2.6ew.

**(a)-추기 — Step 1 착지 (2026-09-24, main 세션).** 커밋 셋이다. `b9a621b`가 ①②③을 담고, `2473c88`이 ④를, `6efaf05`가 §6 viii의 reexec 추기를 담는다. ① `docs/history/m9-plan.md`는 서두 한 문단 뒤에 M9판 원문을 그대로 두었고 §1 체크박스는 DoD 2~7이 `[x]`, DoD 1만 `[ ]`다. ② `docs/ROADMAP.md`의 현재 위치는 M10, M9 헤더는 `🔄 기능 완료 (2026-09-24) · DoD 1 잔여`이고 마감 노트 불릿 하나가 DoD 2~7의 근거와 마감 절차 두 번의 수치, CI run 둘을 든다. M10 절에는 크기 2.6ew와 그 사유 한 줄, 결정 기록 Q1~Q8, 태그 정책 한 줄, M8 이관 항목의 §13 문장 앵커가 들어갔다. 계획에 없던 편집이 하나 있다. 문서 머리의 총 크기 줄이 M9의 SOCKS 추가분과 M10 갱신분을 더하지 않은 채 28~29ew로 남아 있어 31.5~32ew로 다시 적었다. ③ `README.md`는 Status 산문, Roadmap 표의 M9·M10 행, tap 문단의 시제를 고쳤다. ④ M2~M6 다섯은 각각 교체 커밋의 부모 `f5cd30a`·`e823ba1`·`4994e42`·`9d61b13`·`2f5d21a`에서 `git show`로 꺼냈고 서두는 m7·m8과 같은 H1 `# M<N> 계획 — <제목> (감사 기록)`과 이관 문단 하나다. (c)의 판정 셋은 모두 선다. `docs/PRD.md:<줄>` 꼴 인용은 ROADMAP과 PLAN에 0건, `docs/history/`는 m2부터 m9까지 여덟 파일, 태그 정책 문장과 2.6ew 크기 줄이 ROADMAP에 있다. 이 계획 본문은 humanize light 경로로 문장 셋만 손봤고 헤딩·표·식별자·수치는 바이트 동일하다. 검증: 문서만 바뀐 트리에서 nextest `1983 passed / 4 skipped`. CI run 36010207826(CI)·36010207979(fuzz-smoke)·36010208029(load) 전부 초록.

### Step 2 — release 프로파일 기능 스모크 하네스 (0.25ew)

선행: 없음. Step 1과 병렬로 열 수 있다.

**(a) 범위:** 바이너리 축은 절반이 이미 뚫려 있다 — HEAD 21d3507 실측으로 `Sandbox::command_with_bin`(`crates/qsh-cli/tests/common/mod.rs:128`)·`ServeGuard::start_with_bin`(`:444`)·`start_with_bin_logging`(`:464`)이 `pub`이고 적대적 부하 하네스가 release 서버를 재는 데 쓴다. 클라이언트 쪽이 빠져 있다. 같은 파일에서 `Sandbox::command`(`:119`)가 `CARGO_BIN_EXE_qsh`를 하드와이어하고 `Fleet::start_with`(`:695`)가 `ServeGuard::start_with`(`:427`)를 부른다. `Sandbox`가 바이너리 경로를 들게 하고 `Fleet::start_with_bin`을 더해 양쪽을 같은 경로로 모은다. 신규 `crates/qsh-cli/tests/release_smoke.rs`가 네 축을 한 시나리오로 잇는다 — `init --json` → 양방향 pin(`identity export` + `trust add --cert-file` 또는 `trust add --fingerprint`) → `exec --json` 왕복(remote exit code와 두 스트림 확인) → PTY 셸 획득 후 `~d` detach → `attach`로 같은 세션 재부착 → 정상 종료. 환경 변수는 둘이다. `QSH_SMOKE_BIN`이 측정 대상 바이너리를 가리키고, 없으면 `CARGO_BIN_EXE_qsh`로 떨어져 PR에서도 debug로 돈다. `QSH_SMOKE_STRICT=1`이면 `QSH_SMOKE_BIN` 부재를 패닉으로 만든다. 조용한 debug fallback이 이 스텝의 유일한 실패 모드이므로, `crates/qsh-cli/tests/adversarial_load.rs` 모듈 doc이 `load_bin()` 부재를 패닉으로 다루는 사유를 그대로 옮겨 적는다. PTY·detach 축은 `#[cfg(unix)]`로 가른다 — HEAD 21d3507 실측으로 `tui_expect.rs`는 파일 머리에 `#![cfg(unix)]`가 있고 `exec_e2e.rs`에는 없어서 exec 왕복은 Windows에서도 선다.

**(b) 테스트·게이트:** 새 테스트 자신이 게이트다. 기존 일곱 게이트 green. `tui_expect.rs`·`exec_e2e.rs`·`init_trust.rs`는 손대지 않는다 — 중복 커버리지를 만들지 말고 새 파일이 얇게 잇는다. Windows leg은 `cargo check --target x86_64-pc-windows-gnu`로 미리 본다.

**(c) 완료 판정:** `cargo build --release -p qsh-cli` 뒤 `QSH_SMOKE_STRICT=1 QSH_SMOKE_BIN=$(pwd)/target/release/qsh cargo nextest run -p qsh-cli --test release_smoke`가 green이고, `QSH_SMOKE_BIN` 없이 같은 명령이 패닉 문구를 내며 실패한다. 네 축이 로그에 순서대로 찍힌다.

**(a)-추기 — Step 2 착지 (2026-09-24, main 세션).** 커밋 `152dd78`. seam은 `Sandbox`가 `bin: PathBuf`를 들고 `Sandbox::with_bin`·`Fleet::start_with_bin`이 그 경로로 host와 client 둘을 세우는 모양이다. `Sandbox::command`·`ServeGuard::spawn`·`Fleet::start_with`·`Fleet::rogue`가 하드와이어 대신 그 필드를 읽고 기존 시그니처는 하나도 바뀌지 않았다. 양방향 pin은 `Fleet`이 이미 쓰던 `trust add --fingerprint` 경로를 그대로 탄다. (a)가 열어 둔 `identity export` + `--cert-file` 선택지는 `init_trust.rs`가 따로 덮고 있어 여기서 다시 잇지 않았다. 새 파일 `crates/qsh-cli/tests/release_smoke.rs`의 unix 테스트 `release_smoke_covers_init_trust_exec_pty_detach_and_reattach`가 네 축을 잇고 `#[cfg(not(unix))]` 쌍둥이 `release_smoke_covers_init_trust_and_exec_on_a_platform_without_a_pty_client`는 exec까지만 돈다. PTY 클라이언트는 `tui_expect.rs`의 `Client`를 잘라 복사했다. `expectrl`을 `tests/common`으로 끌어올리면 `mod common;`을 선언한 모든 테스트 바이너리가 그 의존을 떠안기 때문이다. 재부착 뒤 마커는 detach 전 것과 다른 값으로 왕복시켜 replay만으로 통과하는 길을 막았고 replay 자체는 단언하지 않는다(브리프 질문 2의 결정). `smoke_bin()`은 어느 바이너리를 구동했는지 stderr에 한 줄 남긴다. 리뷰 두 렌즈의 소견 가운데 `docs/design/testing.md`의 조작적 정의 문장 누락, 표 행의 계획 스텝 번호 인용, `with_bin` doc의 틀린 앵커, 모듈 doc의 과장("every test binary"), 테스트 이름의 `resume` 오용은 고쳤다. `initialized_with_bin`의 미사용은 doc 한 줄로 밝힌 채 남겼다. 검증: 게이트 8종 초록, nextest `1983 passed / 4 skipped`(baseline 1982에 새 테스트 1), release 바이너리 STRICT 실행 초록, mutation 3건 전건 CAUGHT(STRICT에 BIN 부재 → 변수명을 지목하는 패닉, `main.rs`의 exec exit code를 0으로 고정 → `7` 단언 실패, `tui/unix.rs`의 재부착 `session_ref` 훼손 → 재부착 마커 EOF). `docs/design/testing.md`는 L6 끝 문단 하나와 환경변수 표 행 하나를 얻었다. Linux 검증(WSL 박스, 같은 커밋): rustdoc·clippy 초록, `-p qsh-cli` nextest 285 passed(loopback 10초 타임아웃 flaky 10건은 재시도 통과), release 빌드 뒤 STRICT 스모크 PASS. CI run 36008333318(CI)·36008333337(fuzz-smoke)·36008333321(load) 전부 초록.

### Step 3 — CI에 release 스모크 배선 (0.20ew)

선행: Step 2(하네스가 있어야 배선할 것이 생긴다).

**(a) 범위:** ① `.github/workflows/release.yml`의 `build` job에서 `Smoke test` 스텝을 승격한다. 오늘 그 스텝은 `qsh version --json` 한 줄이고 감사 개정이 "아니다"라고 지목한 바로 그 형태다. unix 네 leg(darwin 둘, linux-gnu 둘, 전부 네이티브 러너)은 `QSH_SMOKE_BIN`을 방금 빌드한 타깃 바이너리로 가리켜 `QSH_SMOKE_STRICT=1`로 `release_smoke`를 돌린다. Windows leg은 init → trust → `exec --json` 왕복까지만 돈다 — PTY·detach 축은 `cfg(unix)`로 빠지고 Windows host 자체는 P2 그대로다. Step 4가 musl leg을 더하면 그 leg도 같은 스텝을 받는다. ② `.github/workflows/load.yml`에 같은 스텝 한 줄. 이 워크플로는 이미 `cargo build --release -p qsh-cli`를 갖고 있어 빌드 비용이 0이고, main push마다 도는 회귀 감시자가 된다. ③ `.github/workflows/fuzz-smoke.yml`에 `cargo deny --manifest-path fuzz/Cargo.toml check advisories` 한 스텝. licenses와 bans는 켜지 않는다(§6 iv).

**(b) 테스트·게이트:** `workflow_dispatch`로 release.yml을 브랜치에서 한 번 돌려 `build` job만 확인한다 — `release` job은 태그 ref 조건이라 돌지 않는다. fuzz-smoke.yml은 push로 확인한다. 두 워크플로 모두 `ci-ok`의 `needs` 밖이라 PR 게이트를 늘리지 않는다.

**(c) 완료 판정:** dispatch run의 build leg 전부 green이고 각 unix leg 로그에 스모크 네 축이, Windows leg 로그에 exec 축이 찍힌다. fuzz-smoke run에 deny advisories 스텝이 green으로 뜬다.

**(a)-추기 — Step 3 착지 (2026-09-25, main 세션).** 커밋 둘이다. `0350438`이 release.yml의 build job과 load.yml에 `release_smoke`를 배선했고 `159e1fa`가 fuzz-smoke.yml에 `cargo deny --locked --manifest-path fuzz/Cargo.toml check advisories` 스텝을 켜면서 fuzz 락의 rustls를 0.23.45로 올렸다. 켜자마자 RUSTSEC-2026-0285(rustls 0.23.43)에 걸려 첫날부터 붉었을 스텝이라 같은 커밋에서 락을 갱신했고 그 재해석이 path 의존 세 줄과 tempfile의 getrandom 엣지 하나를 함께 바꿨다. 판정은 dispatch run 36014862118(브랜치 `m10-step3`, 커밋 `159e1fa`)로 했다. build 다섯 leg 전부 초록이고 unix 네 leg 로그에 `release_smoke: driving …/target/<triple>/release/qsh`와 `release_smoke_covers_init_trust_exec_pty_detach_and_reattach ... ok`가, Windows leg 로그에 `…/qsh.exe`와 `release_smoke_covers_init_trust_and_exec_on_a_platform_without_a_pty_client ... ok`가 찍혔다. `release`·`homebrew-tap` job은 태그 조건이라 skipped다. leg 벽시계는 v0.2.0 태그 run 35579517383 대비 x86_64 linux 3:54→4:44, aarch64 linux 2:57→4:30, aarch64 darwin 3:49→5:13, windows 5:49→8:22, x86_64 darwin 10:02→14:57이다. 늘어난 몫은 스모크 자체(1초 안팎)가 아니라 nextest 설치와 dev 프로파일 테스트 트리의 첫 컴파일이다. 리뷰가 고친 것은 셋이다. fuzz/README.md의 "on every push"를 실제 트리거(main push와 PR)로 바로잡았고 load.yml의 "빌드 비용 0" 주석을 테스트 트리 컴파일이 더해진다는 사실로 고쳤으며 deny 스텝에 `--locked`를 붙여 커밋된 락 자체를 검사하게 했다. release.yml의 dispatch 주석에는 브랜치 이름에 `/`가 있으면 `upload-artifact`가 artifact 이름을 거부한다는 제약을 적었다. 그래서 이 스텝부터 브랜치 이름에서 슬래시를 뺀다. (c)의 남은 둘, fuzz-smoke run의 deny 스텝과 load.yml의 스모크 스텝은 main push의 run 36016814396와 run 36016814282에서 초록으로 확인했다. `crates/qsh-cli/tests/release_smoke.rs` 모듈 doc의 "release.yml's smoke step" 문구는 스텝 이름이 둘로 갈린 뒤 낡았지만 이 스텝에서 그 파일을 열지 않기로 해 그대로 두었다. Step 7이 설치 문면을 손볼 때 같이 고친다.

### Step 4 — musl static 타깃 (0.25ew)

선행: Step 3(같은 스텝이 musl leg에도 스모크를 붙인다). §8 #3.

**(a) 범위:** `release.yml` 매트릭스에 `x86_64-unknown-linux-musl` 한 leg을 더한다(ubuntu-24.04 네이티브, 교차 컴파일 없음). musl 툴체인(`musl-tools` 또는 `cargo-zigbuild`), aws-lc-rs가 요구하는 cmake와 clang, `RUSTFLAGS=-C target-feature=+crt-static`이 필요하다. jemalloc 처분이 이 스텝의 판단 지점이다 — HEAD 21d3507 실측으로 `crates/qsh-cli/Cargo.toml`의 `[target.'cfg(target_os = "linux")'.dependencies]`가 `tikv-jemallocator`를 걸고 있어 musl에도 붙는다. 빌드가 서면 그대로 두고, 안 서면 `cfg(all(target_os = "linux", target_env = "gnu"))`로 좁힌다. 좁히면 musl 바이너리의 idle RSS 특성이 gnu와 달라지므로 musl 바이너리에는 PRD §13의 idle 30MB 항목을 주장하지 않는다는 문장을 `docs/design/testing.md` L9에 남긴다(그 의존이 붙은 사유가 glibc arena high-water다). `scripts/install.sh`의 `detect_target`에는 `QSH_LIBC=musl` 옵트인 분기를 넣는다 — 자동 판별은 gnu가 있는 시스템을 잘못 잡을 수 있어 하지 않는다. `README.md` 수동 다운로드 자산 표에 한 행. aarch64 musl은 §3 non-goal이다.

**(b) 테스트·게이트:** Step 2의 스모크가 musl leg에서 네이티브로 돈다. `ldd target/x86_64-unknown-linux-musl/release/qsh`가 "not a dynamic executable". jemalloc cfg를 좁혔다면 gnu 빌드의 의존 그래프가 그대로임을 `cargo tree -p qsh-cli --target x86_64-unknown-linux-gnu`로 확인한다. 기존 일곱 게이트 green.

**(c) 완료 판정:** dispatch run에서 musl leg green, musl 자산 하나가 아티팩트로 올라오고 스모크 통과, `ldd` 출력이 run 로그에 남는다. aws-lc-rs가 musl에서 막히면 이 스텝을 닫지 않고 §8 #3으로 올린다 — `ring` backend 전환은 wire와 무관한 빌드 변경이지만 M8이 얼린 것을 되짚는 인상이 있어 ADR을 먼저 쓴다.

### Step 5 — macOS codesign + notarization (0.40ew)

선행: Step 0의 Apple 자격 둘. §8 #2.

**(a) 범위:** `release.yml`의 darwin 두 leg에 서명과 공증을 붙인다. 순서는 임시 키체인 생성, `APPLE_CERT_P12` import, `codesign --force --options runtime --timestamp --sign "Developer ID Application: <team>"`, zip으로 감싸 `xcrun notarytool submit --wait --key`(App Store Connect API key 방식), tar.gz 재패키징이다. `stapler`는 걸지 않는다 — 티켓은 `.app`/`.dmg`/`.pkg`에만 붙고 단일 실행 파일은 대상이 아니다. 그 사실과 오프라인 판정이 미보장이라는 점을 Step 10 캠페인 문서와 README에 적는다(§8 #2). 시크릿이 없으면 job이 붉지 않고 서명 없이 지나가게 한다 — `release.yml`의 `homebrew-tap` job이 배포 키 유무를 `steps.check.outputs.has-key`로 보고 건너뛰는 패턴을 그대로 복제한다. `release.yml`은 `pull_request`에서 돌지 않으므로 fork PR은 이 분기와 무관하다 — Step 0의 Apple 자격이 오기 전에도 브랜치 `workflow_dispatch` 실행이 붉지 않아야 하므로 이 분기가 실동작 경로다.

**(b) 테스트·게이트:** dispatch run 로그에 `notarytool` status `Accepted`. 내려받은 자산에 `codesign -dv --verbose=4`가 Developer ID를 보고한다. 시크릿 없는 브랜치에서 같은 job이 green.

**(c) 완료 판정:** 위 둘에 더해, 클린 macOS 회차에서 `spctl -a -vvv -t execute`가 `accepted source=Notarized Developer ID`를 낸다(Step 10에서 판정). Apple 자격이 늦으면 이 스텝만 대기하고 나머지는 진행한다.

### Step 6 — SLSA provenance (0.10ew)

선행: 없음. 판정만 첫 M10 태그를 기다린다.

**(a) 범위:** `release` job에 `actions/attest-build-provenance`를 붙이고 `permissions`에 `id-token: write`와 `attestations: write`를 더한다. 오늘 그 job의 권한은 `contents: write` 하나뿐이다. 대상은 `dist/*` 전 자산. 검증 명령 `gh attestation verify <asset> --repo DaveDev42/qsh` 한 문단을 `README.md` Install 절과 `scripts/README.md`에 넣는다. `scripts/install.sh`는 손대지 않는다 — `gh` CLI를 필수 의존으로 만들면 그 스크립트가 머리에 적은 "No Rust toolchain required"와 같은 등급의 약속이 깨지고 실패 모드가 하나 는다.

**(b) 테스트·게이트:** attestation은 태그 job에 붙으므로 태그 전에는 검증할 수 없다. 이 스텝의 판정만 첫 M10 태그로 미뤄진다.

**(c) 완료 판정:** 첫 M10 태그의 자산 전부에 대해 `gh attestation verify`가 통과하고 두 문서에 검증 절이 있다.

### Step 7 — 설치 문면 동기화와 man 패키징 (0.15ew)

선행: Step 4(musl 자산 행), Step 5(서명 사실), Step 6(검증 절). §8 #4.

**(a) 범위:** man page는 Homebrew만 설치한다(§8 #4). 두 조각이다. ① `release.yml`의 `Package archive (unix)` 스텝이 오늘 `tar czf "$asset" -C target/<t>/release qsh`로 바이너리 하나만 넣는다(HEAD 21d3507 실측) — `docs/man/`의 45면을 아카이브 안 `man/` 아래로 더한다. `scripts/install.sh`는 `tar xzf … qsh`로 멤버를 이름으로 하나만 꺼내므로 손대지 않되, 멤버가 늘어도 그 추출과 심링크 거부가 그대로 통과함을 구현자가 실측한다. ② tap `Formula/qsh.rb`에 `man1.install Dir["man/*.1"]` 한 줄. bump job은 version·url·sha256 세 줄만 다시 쓰므로 이 줄은 살아남는다. tap 저장소 커밋은 이 저장소 게이트 밖이다. `README.md`의 man 문단은 "Homebrew installs them; the curl installer does not"로 정확히 고친다. 같은 커밋에 Step 4의 musl 자산 행, Step 5가 붙인 서명 사실, Step 6의 provenance 검증 절을 싣는다.

**(b) 테스트·게이트:** 새 게이트 없음. README는 축자 게이트 대상이라 `readme_quotes_the_controller_unreachable_diagnostic_verbatim`이 보는 자리를 건드리지 않는다. man 생성기 게이트 `checked_in_man_pages_match_the_generator`(`xtask/src/man.rs`)는 `docs/man/`을 그대로 쓰므로 영향이 없다 — 아카이브에 복사만 한다.

**(c) 완료 판정:** dispatch run 아티팩트의 `tar tzf`에 `qsh`와 `man/qsh.1`이 함께 있고, 같은 아카이브로 `scripts/install.sh`가 여전히 성공한다. brew로 설치한 회차에서 `man qsh`가 뜬다(Step 10). `grep -rn 'M9' scripts/`가 0건으로 유지된다.

### Step 8 — threat-model의 M9 사람용 표면 커버리지 (0.30ew)

선행: 없음. 다른 스텝과 독립이다.

**(a) 범위:** `docs/design/threat-model.md` §3 진입점 표에 여섯 명령의 행을 세운다 — `pair invite|accept --as`, `identity export`, `trust add --cert-file`, `trust add-ca`, `trust rename`, `service install|uninstall|status`. §4 위협 표는 각 명령에 대해 위협 → 통제 → 핀 테스트 삼단을 채운다. 통제 쪽 핀은 대부분 이미 있다: `crates/qsh-core/tests/service_docs.rs`, `crates/qsh-cli/tests/cert_file_exchange.rs`, `crates/qsh-cli/tests/trust_pairing_live.rs`, `crates/qsh-cli/tests/trust_lifecycle_live.rs`, `crates/qsh-core/tests/op_registration_completeness.rs`. 핀이 없는 위협은 잔여 위험으로 §5에 적고 근거를 남긴다. §0 비범위의 유예 문장("이 표는 아직 그 표면을 다루지 않으며 그 커버리지는 M10으로 미룬다")을 걷는다. `-D`는 잔여 위험 h16~h22로 이미 완비라 대상이 아니다.

**(b) 테스트·게이트:** 문서 변경이라 새 게이트가 없다. ADR을 줄 번호로 인용하지 않는다 — 커밋 `0c5e43c`가 이 문서의 32건을 절·라벨 앵커로 바꾼 정책을 그대로 잇는다.

**(c) 완료 판정:** `grep -nE '[A-Za-z0-9_/.-]+\.md:[0-9]+' docs/design/threat-model.md`의 건수가 이 스텝 전(HEAD 21d3507 실측 24건)보다 늘지 않고, 여섯 명령 이름이 §3과 §4 양쪽에서 잡히며, §0에 M10 유예 문장이 0건이다. 기존 24건까지 이 스텝에서 손볼지는 (a)에서 정한다.

### Step 9 — PRD §13 두 항목의 릴리스 게이트 판정 (0.15ew)

선행: 없음. dispatch 1회의 벽시계 30분만 확보하면 된다.

**(a) 범위:** ① "30분 단절 후에도 TTL 내 세션 복구" — `a_real_60_second_blackout_survives_and_resumes_the_same_session`(`crates/qsh-cli/tests/reverse_blackout.rs`)의 형태를 30분으로 늘린 회차를 `workflow_dispatch` 전용 job으로 둔다. `load.yml`에 job을 더할지 `long.yml`을 새로 만들지는 구현자가 고르고 §4.1에 기록한다. PR 게이트가 아니다. 기본 resume TTL이 24시간이라 30분은 TTL의 2%이고 재개 여부만 보면 된다. dispatch 1회의 run id를 `docs/ROADMAP.md` M10 절의 M8 이관 항목에 인용하면 이 축이 닫힌다. ② "느린 파일·터널 stream이 PTY stream을 block하지 않아야 함" — 새 하네스를 만들지 않고 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`(`crates/qsh-testkit/tests/tunnel_echo_under_load.rs`)를 이 항목의 판정 근거로 명시 귀속한다. 그 테스트는 `ci.yml`의 acceptance job이 `QSH_ACCEPTANCE_STRICT=1`로 상시 돌리지만 지금까지 M4 DoD의 계약으로만 인용됐다. 귀속은 테스트 모듈 doc 한 문단과 `docs/design/testing.md` L9/L10 한 문단으로 한다. 오늘 덮는 축은 포화(고속)이고 저속·역압 축은 없다 — 하네스가 값싸게 받으면 그 축을 더하고, 아니면 잔여로 §4에 적는다.

**(b) 테스트·게이트:** ①은 PR 게이트가 아니다. `docs/design/testing.md` L9/L10의 "절대 수치와 긴 벽시계는 비차단 job" 규율 그대로다. ②는 기존 acceptance job 안이고 새 게이트를 만들지 않는다.

**(c) 완료 판정:** PRD §13 두 항목이 각각 테스트 이름 또는 dispatch run id로 인용 가능하고, `docs/ROADMAP.md` M10 수용 기준의 M8 이관 행이 그 인용을 담는다.

### Step 10 — 클린 VM 스모크 캠페인 (문서 0.15ew + 사람 회차)

선행: 문서 사전 정의는 Step 5의 판정 정의에 맞춰 쓰므로 Step 5와 같이 움직이고, 회차는 Step 4·5·7이 다 얹힌 태그를 기다린다. Step 0의 클린 VM 다섯.

**(a) 범위:** `docs/campaigns/m10-clean-vm.md`를 신설한다. 형식은 `m7-stopwatch.md`·`m8-soak.md` 선례 그대로 — 기준을 먼저 커밋하고 회차 표는 나중에 채운다. 회차 요건 여섯: 바이너리 sha256(같은 회차 안에서 같은 sha256을 쓴다는 soak 캠페인의 규율을 승계), 설치 경로(brew / curl 스크립트 / 수동 다운로드), DoD 2 판정, DoD 3 판정, 기능 스모크 네 축의 수동 재현, brew 회차에서 설치된 버전이 태그와 같은지 확인. DoD 2의 조작적 정의를 이 문서가 고정한다 — quarantine 속성이 살아 있는 수동 다운로드 경로에서 `spctl -a -vvv -t execute`가 `accepted source=Notarized Developer ID`를 내고, `codesign -dv --verbose=4`가 Developer ID를 보고하며, release run 로그의 `notarytool` status가 `Accepted`다. curl과 brew 경로는 판정 경로가 아니다 — HEAD 21d3507 실측으로 `scripts/install.sh:217-219`가 `xattr -d com.apple.quarantine`를 best-effort로 걸어 속성을 떼기 때문이다. DoD 3은 구형 glibc 이미지에서 `ldd`가 "not a dynamic executable"을 내고 스모크 네 축이 통과하는 것으로 잰다. brew 확인을 요건에 넣는 이유는 tap bump 스텝이 `continue-on-error`라 tap이 조용히 낡을 수 있어서다.

**(b) 테스트·게이트:** 캠페인 자체가 DoD 1·2·3의 판정이다. 사후에 기준을 늘리거나 실패한 회차를 빼지 않는다.

**(c) 완료 판정:** 네 플랫폼 전부 PASS와 구형 glibc musl 회차 1건 PASS가 회차 표에 기록되고, 각 행에 바이너리 sha256과 설치 경로가 있다.

### Step 11 — crates.io publish gate 해제 (0.20ew)

선행: dry-run은 없음, publish 실행은 Step 10 PASS와 Step 0의 토큰. §8 #8.

**(a) 범위:** HEAD 21d3507 실측으로 `Cargo.toml`의 `[workspace.package]`가 `publish = false`이고 크레이트 여섯이 전부 `publish.workspace = true`로 상속한다. `qsh-proto`·`qsh-transport`·`qsh-core`·`qsh-cli`는 publish로 열고 `qsh-testkit`·`xtask`는 `publish = false`를 유지한다 — 테스트 하네스와 빌드 도구는 공개 의미가 없고 testkit은 워크스페이스 내부 경로 의존이 많다. publish 대상 넷에 `description`·`repository`·`readme`·`keywords`·`categories`를 더한다(오늘 0건이고 crates.io는 `description`과 `license`를 필수로 본다). path 의존에는 `version` 필드를 붙여야 publish가 통과하므로, `deny.toml`의 `allow-wildcard-paths = true` 주석이 사유로 적은 "private, unpublished workspace"도 같이 갱신한다. CI에 `cargo publish --dry-run -p <crate>`를 의존 순서(proto → transport → core → cli)로 스텝화한다. 이름은 착수 시점에 다시 확인한다 — 2026-09-24 실측으로 `qsh-cli`는 미점유이고, `qsh`는 PRD §16이 적은 대로 타인이 점유 중이다(그 성격은 착수 시점에 다시 확인한다). 이름 분리는 ADR-0006이 이미 정했으므로 재론하지 않는다. 실제 `cargo publish`는 에이전트가 실행하지 않는다 — 되돌릴 수 없고(yank만 가능) DoD 어디에도 없다. Step 10 PASS 뒤에 사람이 실행한다(§8 #8). `README.md`의 "crates.io에서 아직 설치할 수 없다"는 문단은 실제 publish가 일어난 뒤에만 고친다.

**(b) 테스트·게이트:** `cargo publish --dry-run` 네 건 green, `cargo deny check` green, 기존 일곱 게이트 green.

**(c) 완료 판정:** dry-run 네 건이 CI에서 green이고 `deny.toml` 주석이 갱신돼 있으며 CI에 그 스텝이 있다. publish 실행 여부는 DoD가 아니므로 미실행이면 마감 노트에 미실행으로 적는다.

### Step 12 — 릴리스 문서 (0.20ew)

선행: Step 5·6·7(문면이 가리킬 사실이 먼저 서야 한다). §8 #5.

**(a) 범위:** "beta"를 선언하지 않는다(§8 #5). `docs/ROADMAP.md` M10 범위의 "beta 문서"는 산출물 이름으로 읽고 릴리스 문서로 만든다. `README.md` Status의 "Not for production use"는 유지하되, M10 게이트가 닫힌 뒤 그 사유를 SC7(독립 보안 리뷰 — PRD §15 마지막 항목이자 M8 DoD 4)과 열린 사람 캠페인 둘로 좁힌다. Roadmap 표의 M10 행을 갱신하고, Known limitations의 Gatekeeper 문단(오늘 "a release build is only ad-hoc linker-signed"라고 자인한다)을 Step 5 착지 후의 사실로 갈아탄다. PRD §15는 개정하지 않는다 — SC7이 열린 채 beta를 선언하면 그 자체가 PRD 위반이고, 선언하지 않으면 개정할 이유가 없다. 릴리스 노트 초안도 여기서 낸다: 설치 경로 셋, provenance 검증 절차, musl 바이너리의 RSS 주의, 서명이 붙지 않는 경로가 남는지 여부.

**(b) 테스트·게이트:** README 축자 게이트 두 테스트 green.

**(c) 완료 판정:** 마감 공통 절차 2의 README 동기화 불일치 0이고, README에 "beta" 선언 문장이 0건이며, Status의 유보 사유가 SC7과 사람 캠페인만 남는다.

### Step 13 — 마감 (마감 공통 절차, 크기 내역 밖)

선행: Step 1~12 전부와 §1 DoD 판정.

**(a) 선행 감사:** 인벤토리 → 대조 → 반박 검증 → fixer. 대조 대상은 M10 태그가 박힌 자리들이다 — `docs/design/threat-model.md` §0의 서명·notarization 귀속과 M9 표면 유예, `docs/design/testing.md`의 nightly perf job 유예, `README.md` 여덟 자리, `scripts/install.sh`와 `scripts/README.md`의 서명 문면, ADR-0011 결정 5의 `-W` 검토, `docs/design/reexec-estimate.md`의 H4/H5 배치 줄, `fuzz/README.md`의 deny 범위 문단. `docs/CLI.md`에는 M10 태그가 0건이라 계약 문서 대조 부담이 앞 마일스톤보다 가볍다. 절차 1 수치 형식은 앞 마감과 같다: 대조 문장 N건 — 검증 M, 후속 마일스톤 명시 유예 P, 열린 DoD 종속 Q, 대조 대상 아님 R, 충돌 S. 절차 2는 "대조 항목 N개 중 불일치 M".

**(b) 마감 커밋에 남길 것:** §1 DoD 체크박스, `docs/ROADMAP.md` M10 절 갱신과 마감 노트, README 동기화, `-W` 검토 결론, crates.io publish 실행 여부, `docs/CLI.md` 상태 헤더의 M10 반영, P0 MVP 완료 선언과 그 다음(P1)의 귀속처. `-W`는 기각이 기본값이다 — ADR-0011 결정 5가 "`qsh exec`와 `-L`로 부족한 사용례가 나올 때"를 조건으로 걸었고 `-D`가 M9에서 착지해 SOCKS 경유 사용례가 열리면서 압력원이 오히려 줄었다. 기각이면 ADR-0011 결과 절에 제자리 추기하고, 관측된 사용례가 있으면 신규 ADR을 쓴다.

**(c) 완료 판정:** §1 전건 판정 완료(사람 몫이 남으면 그 사실을 노트에 적는다), 절차 1 충돌 0, 절차 2 불일치 0, 마감 커밋 CI green.

## 3. 명시적 non-goals (P1 유예 / 타 마일스톤)

- `-W`(ProxyCommand형 stdio와 원격 TCP의 브리지) — ADR-0011 결정 5의 검토 의무일 뿐 DoD가 아니다. 기각이 기본값이고 판정은 Step 13.
- `aarch64-unknown-linux-musl` — x86_64 하나로 시작한다. 네이티브 arm 러너가 매트릭스에 이미 있어 같은 레시피로 값싸게 더할 수 있다는 점만 적어 둔다.
- `.pkg` 배포 형식 — 단일 실행 파일은 stapler 대상이 아니라는 구조적 사실 때문에 `.pkg`가 매력적으로 보이지만 만들지 않는다. 오프라인 판정 미보장은 캠페인 문서에 적는 쪽으로 처리한다.
- `scripts/install.sh`의 provenance 자동 검증 — `gh` CLI 의존이 "no Rust toolchain required"와 같은 등급의 약속을 깬다. 검증은 문서의 선택 경로로 둔다.
- curl 설치 경로의 man page 설치 — Homebrew만 설치한다.
- README의 서사·구조 전면 재작성 — ROADMAP M9 명시적 out이 SC1 재측정 뒤로 미뤘고 그 재측정(§0.2 M9 DoD 1)이 아직 열려 있다. Step 7·12가 손대는 것은 사실 동기화이지 재작성이 아니다.
- graceful re-exec H1·H1b·H2 — `docs/design/reexec-estimate.md` §4가 셋을 M9에 배치했으나 M9 계획의 어느 스텝에도 들어가지 않았고 H0(재시작이 detached 세션을 지운다는 고지, `docs/deploy/service.md`)만 착지했다. M10은 릴리스 게이트에 묶여 있어 셋 다 P1로 재기록한다. 같은 문서 §4에 날짜 있는 추기 한 문단을 별도 `docs(design)` 커밋으로 남긴다.
- `ControlLink`/`DataLink` enum → trait 전환 — ADR-0005의 P0 부채. M3부터 연쇄 이월이고 M10도 트리거하지 않는다. P1 재기록.
- TOFU와 pin 방향 축 — `trust.toml`이 양방향 구조라 outbound pin이 상대의 inbound 인증까지 통과시키는 문제가 있다. 번호 미배정 ADR로 예약(ADR-0017 결정 5).
- listener 대상 초대 상환 — ADR-0015 예약됨. CSR 기반 다대 CA 서명 — ADR-0016 예약됨.
- cert rotation/revocation UX — P1. doctor 만료 경고만 유지.
- doctor `--fail-on` — `docs/CLI.md`가 향후 additive 후보로 남긴 플래그. M10 미구현.
- file copy, Windows host, TCP/TLS fallback, relay, multi-attach observer, local echo prediction — `docs/ROADMAP.md` §3 가드레일 표 그대로.
- 서비스 매니저 실호출(`launchctl bootstrap`, `systemctl --user enable`) — M9가 대행하지 않기로 했고 M10도 하지 않는다. unit 파일 생성·삭제까지가 범위다.
- qsh 자체 데몬화 — foreground 전용 불변.
- wire 변경 — M8 freeze 이후 축이 그대로다. M10은 빌드·패키징·문서 축만 건드린다.
- 옛 계획 인용의 일괄 정리 — §6과 §8 #6.

## 4. 리스크와 감시 항목

- **notarization 리드타임이 가장 큰 단일 일정 리스크다.** `docs/ROADMAP.md` §4 리스크 5가 "M8 중 시작"을 대응으로 적었는데 두 마일스톤이 지나도록 시작 기록이 없다. Apple Developer Program 승인 자체가 수일에서 수주다. Step 0이 늦으면 Step 5와 Step 10의 DoD 2 축이 통째로 밀리고 그것만으로 M10이 닫히지 않는다.
- **Gatekeeper와 단일 바이너리의 구조적 불일치.** `stapler`는 `.app`/`.dmg`/`.pkg`에만 티켓을 붙인다. tar.gz 안의 맨 실행 파일은 공증은 되지만 스테이플이 안 되므로 오프라인 머신의 `spctl` 판정이 미검증이다. curl 경로는 quarantine 속성을 떼므로 무증상일 가능성이 높지만, DoD 2 문면이 "차단하지 않음"이라 판정 방법 자체를 Step 10 캠페인 문서가 먼저 정의해야 한다.
- **musl과 aws-lc-rs.** 워크스페이스는 rustls·quinn·rcgen 셋 모두 aws-lc-rs backend로 고정돼 있다. C/asm 빌드라 musl 타깃에서 cmake·clang·musl 헤더가 필요하고 `-C target-feature=+crt-static`와의 조합이 가장 깨지기 쉽다. 선행 신호가 하나 있다 — `ci.yml`의 주석이 cargo-deny-action 도커 이미지가 musl 툴체인을 못 찾아 깨졌던 이력을 적는다.
- **musl과 jemalloc의 RSS 특성.** 빌드가 서더라도 그 의존이 붙은 사유(glibc arena high-water)가 musl에는 해당하지 않아 idle RSS 모양이 gnu와 달라진다. soak과 적대적 부하 판정은 gnu 바이너리 기준이고, musl 바이너리에 30MB bound를 그대로 주장하면 안 된다.
- **release 프로파일 테스트가 태그 벽시계를 늘린다.** `cargo build --release` 뒤 테스트 크레이트를 다시 컴파일하므로 leg당 수 분이 붙는다. 매트릭스 leg은 병렬이라 증가분은 leg 합이 아니라 가장 느린 leg 하나 몫이지만, 첫 dispatch run에서 실제 증가를 재서 §4.1에 적는다.
- **provenance 검증의 실효성.** Sigstore 공개 로그에 기록은 남지만 검증에 `gh` 또는 `cosign`이 필요하다. 검증을 선택 경로로 두는 대가로 "대부분의 사용자는 검증하지 않는다"가 남는다.
- **tap bump의 `continue-on-error`.** bump 스텝이 실패해도 릴리스가 붉지 않아 tap이 조용히 낡을 수 있다. M10에서 brew 경로가 DoD 1의 절반이므로 Step 10 회차가 버전 일치를 확인한다.
- **crates.io publish의 불가역성.** yank는 되지만 삭제는 안 되고 이름은 영구 점유된다. Step 11의 dry-run과 publish 실행 사이에 Step 10 PASS를 끼운다.
- **SC7이 열린 채로는 beta를 선언할 수 없다.** PRD §15가 "공개 beta 전에 protocol과 key lifecycle의 독립 보안 review를 완료한다"고 적고 M8 DoD 4가 다섯 마일스톤 연속 이월이다. Step 12는 그래서 릴리스 문서만 만든다.
- **줄 번호 인용 오차가 또 있을 수 있다.** M8 이관 항목의 PRD 인용이 처음부터 세 행 어긋나 있던 것이 발견돼 커밋 `5daee3d`가 고쳤다. 같은 부류를 Step 13의 선행 감사가 전수로 본다.
- **느린 스트림 축의 미커버 부분.** Step 9 ②가 귀속시키는 테스트는 포화(고속) 축만 덮는다. 저속·역압 축이 남으면 잔여 위험으로 적고 P1로 넘긴다.

### 4.1 구현 중 확정할 값 (해당 step (a)에 근거와 함께 추기)

| # | 질문 | 초안 | 확정 시점 |
|---|---|---|---|
| 1 | 스모크 env 변수 이름 | `QSH_SMOKE_BIN`·`QSH_SMOKE_STRICT`. 적대적 부하 하네스의 `QSH_LOAD_BIN`·`QSH_LOAD_STRICT` 관례를 그대로 따른다. **확정(2026-09-24):** 초안대로(`152dd78`). `docs/design/testing.md`의 환경변수 표에 행이 올랐다 | Step 2 |
| 2 | musl에서 jemalloc의 처분 | 먼저 그대로 빌드해 보고, 안 서면 `target_env = "gnu"`로 좁히고 testing.md L9에 30MB 미주장 문장 | Step 4 |
| 3 | musl 툴체인 경로 | `musl-tools` 네이티브가 1순위, `cargo-zigbuild`는 차선. 교차 컴파일은 aws-lc-rs를 다시 어렵게 만든다 | Step 4 |
| 4 | 서명 identity 문자열의 출처 | `APPLE_TEAM_ID` 시크릿으로 조립할지 identity 전체를 시크릿에 둘지 | Step 5 |
| 5 | notarytool 자격 방식 | App Store Connect API key(`--key`). Apple ID + app-specific password는 회전 비용 때문에 배제 | Step 0·5 |
| 6 | attestation 대상 범위 | `dist/*` 전 자산. `SHA256SUMS` 자체를 포함할지 | Step 6 |
| 7 | man 아카이브 안의 경로 접두 | `man/*.1`. formula의 `man1.install Dir["man/*.1"]`와 같은 문자열 | Step 7 |
| 8 | 30분 회차의 자리 | `load.yml`에 `workflow_dispatch` 전용 job 추가 또는 `long.yml` 신설 | Step 9 |
| 9 | 저속·역압 축의 보강 여부 | 기존 하네스가 값싸게 받으면 더하고, 아니면 잔여 위험으로 적는다 | Step 9 |
| 10 | 캠페인 회차 수와 구형 glibc 이미지 | 네 플랫폼 각 1회 + musl 1회가 하한. 이미지 후보는 CentOS 7 또는 Debian 10 계열 | Step 10 |
| 11 | publish 대상 크레이트 집합 | proto·transport·core·cli 넷. testkit·xtask는 `publish = false` 유지 | Step 11 |
| 12 | 릴리스 노트의 자리 | GitHub Release 본문인지 `docs/` 아래 파일인지 | Step 12 |
| 13 | 스모크의 양방향 pin 경로 | `identity export` + `trust add --cert-file`이 1순위(릴리스 바이너리 하나로 파일만 주고받으면 된다), `trust add --fingerprint`는 fingerprint를 어디서 관측할지가 한 단계 더 붙어 차선. **확정(2026-09-24):** `trust add --fingerprint`다. `Fleet::start_with_bin`이 기존 `Fleet::start_with`의 pin 순서를 그대로 물려받아 fingerprint는 `init --json` 출력에서 이미 손에 있고, `identity export` + `--cert-file` 경로는 `init_trust.rs`가 따로 덮는다(`152dd78`) | Step 2 |

## 5. 완료 절차

1. §1 DoD 1~7 전건을 실제 테스트·회차 기록으로 확인한다. 체크박스는 근거가 green일 때만 채운다.
2. 구속 문서 태그 대조 — Step 13 (a)가 열거한 자리 전수. `docs/CLI.md`는 M10 태그가 0건이라 상태 헤더만 본다.
3. README 동기화 — Status, Install 절(musl·man·provenance), Known limitations의 Gatekeeper 문단, Roadmap 표.
4. `docs/design/testing.md`에 M10 테스트 층 반영 — release 프로파일 스모크의 자리, musl 바이너리의 RSS 주장 범위, PRD §13 두 항목의 귀속.
5. `docs/ROADMAP.md` "현재 위치"와 M10 절 갱신 + 마감 노트.
6. §7 태그 정책의 M10판 한 줄이 `docs/ROADMAP.md`에 실제로 들어갔는지 확인한다(Step 1이 옮긴다 — PLAN.md가 교체돼도 정책이 남도록).
7. §0.2 잔여 넷의 상태를 승계한다. 닫힌 것은 근거와 함께 종결로, 열린 것은 소유자와 함께 이월로 적는다. 이 넷이 P0 MVP 완료 선언의 전제다.
8. 이 PLAN.md의 처분. M10이 P0의 마지막 마일스톤이므로 `docs/history/m10-plan.md`로 옮기고, P1 계획을 새로 열지 PLAN.md를 비워 둘지는 사용자 결정이다(§8이 적은 아홉 건과 같은 성질의 열린 항목이다).

## 6. M9에서 이월된 항목

M9 §6의 i(`hint_alias` 조회 키 trim)·ii(doctor `acl_principal_unmatched`·`acl_ca_auth_path_missing`)·iii(`purge_expired` doc)는 M9 안에서 닫혔다(각각 `d5eef05`·`963809e`와 `e6c81c5`·`36146d5`). 아래는 닫히지 않은 채 넘어온 것들이다.

| # | 항목 | M10 처분 |
|---|---|---|
| iv | `fuzz/Cargo.lock`은 워크스페이스 락과 별개라 `cargo deny check` 범위 밖이다(`fuzz/README.md` "Cargo.lock scope" 절) | Step 3이 `fuzz-smoke.yml`에 advisories 한 스텝을 켠다. licenses·bans는 켜지 않는다 |
| v | fuzz 크레이트는 `36b594d`로 edition 2024가 됐다 — M9 표의 이 행은 이미 해소됐고 M10으로 넘기지 않는다 | 해소됨. 참고용으로만 남긴다 |
| vi | CLOSE `0x1003`의 이중 이름(`RESOURCE_EXHAUSTED`/`REPLACED`) 처분 | M8 DoD 4의 §16 발효 소커밋 몫. M8 소관 유지(§0.2) |
| vii | `ControlLink`/`DataLink` enum → trait 전환 | P1 재기록(§3). M10도 트리거하지 않는다 |
| viii | M9 §3의 P1 재기록 항목 전건 — TOFU·pin 방향, listener pairing, CSR, cert rotation/revocation UX, doctor `--fail-on`, file copy, Windows host, 서비스 매니저 실호출, 자체 데몬화, wire 변경, README 서사·구조 전면 재작성(SC1 재측정 대기) | §3에 전건 승계. 새로 추가된 것은 graceful re-exec H1·H1b·H2 하나다 |
| ix | 옛 계획 인용 부채 — 2026-09-24 실측 엄격 793건, bare `Step N` 포함 878건. 내역은 `crates/` 754, `docs/` 33, `xtask/` 6, README·fuzz·scripts 0 | 기존 문면은 부채로 두고 새 인용은 만들지 않는다. 기계 치환이 안 되는 코드 주석이 대부분이라 일괄 정리는 M10 예산과 맞먹는다. 귀속처는 P1 정리 라운드. Step 1이 M2~M6 계획을 `docs/history/`로 복원해 앵커가 가리킬 문서만 저장소 안에 되돌린다 |
| x | `crates/` 아래 코드 주석의 ADR 줄 번호 인용 5건(`ops/mod.rs`, `ops/tests.rs`, `failure_text_discipline.rs`, `exit_code_matrix.rs`, `tui_expect.rs`) | ix와 같은 부채. 구속 문서 쪽은 `0c5e43c`·`edcb754`·`d82f7a6`가 이미 걷었다. P1 정리 라운드 |
| xi | `docs/design/threat-model.md`가 M9 사람용 표면을 아직 다루지 않는다 | Step 8. DoD 6 |
| xii | `docs/CLI.md` 상태 헤더에 기계 핀이 없다 | 이 헤더는 다섯 마일스톤 동안 갱신되지 않은 전례가 있다. Step 13이 M10 사실로 갱신하고, 헤더를 `EXPECTED_DOCTOR_CODES` 계수처럼 테스트로 고정할지는 후보로만 적어 둔다 — 자유 서술이라 무엇을 고정할지가 먼저 정해져야 한다 |

## 7. 태그 정책

- M10 태그는 마일스톤 마감 트리가 아니라 판정 근거가 실제로 돈 트리를 가리킨다. M10에서 그 근거는 클린 VM 캠페인이므로, 회차가 PASS한 트리에 찍는다.
- 서명과 공증이 붙은 첫 태그가 곧 DoD 2의 판정 대상이다. Step 5가 닫히기 전에 찍은 태그로는 DoD 2를 판정하지 않는다.
- 찍은 태그는 옮기지 않는다. 대상 트리가 틀렸으면 새 태그를 찍고 그 사유를 캠페인 회차 표에서 인용한다.
- 태그 push가 `release.yml`을 구동한다 — 빌드 매트릭스, GitHub Release 생성, tap formula bump. 재실행은 `--clobber`로 자산을 덮는다.
- 착지 기록(2026-09-21): `v0.2.0`을 `2907488`에 찍었고 release run 35579517383의 잡 일곱이 전부 성공해 자산 5개와 `SHA256SUMS`가 붙었으며 tap `Formula/qsh.rb`를 job이 0.2.0으로 다시 썼다(tap 커밋 397b2a3). M10 DoD 다섯은 그 태그로 닫히지 않는다.
- 후속 하나가 게이트 밖에 남아 있다. `-D`를 담은 트리의 24h soak run #7이 아직 없다 — 돌면 `docs/campaigns/m8-soak.md` 회차 표에 남기고, 게이트는 아니다.
- 이 절의 요지 한 줄은 Step 1이 `docs/ROADMAP.md`로 옮긴다. PLAN.md가 다시 교체돼도 정책이 남도록 하기 위해서다.

## 8. 열린 질문 (사용자 결정 필요)

2026-09-24: 사용자의 전면 자율 진행 지시에 따라 아래 아홉 건을 main 세션이 결정했다. 각 항목 끝의 **결정** 문장이 그것이다.

1. **release 스모크를 어느 leg에서 돌릴 것인가.** 전 leg는 태그 벽시계를 늘리고, 일부 leg만 돌리면 감사 개정 문면("CI에서 최소 1회")은 만족해도 출고되는 바이너리 중 일부가 미검증으로 남는다. **결정(2026-09-24, main 세션 — 사용자 전면 자율 지시):** 네이티브 unix leg 전부(darwin 둘, linux-gnu 둘, Step 4 뒤 musl 하나)에서 `QSH_SMOKE_STRICT=1`로 돌리고, Windows leg은 exec 축까지만 돌린다. 매트릭스 leg이 병렬이라 벽시계 증가는 leg 합이 아니라 가장 느린 leg 하나 몫이고, DoD 1이 Linux arm64를 이름으로 적으므로 그 바이너리가 스모크 대상이어야 한다. 사용자가 뒤집으면 leg 집합만 줄이고 하네스는 그대로 둔다.
2. **macOS 배포 형식.** 맨 바이너리 tar.gz를 유지할지 `.pkg`로 감쌀지. **결정(2026-09-24, main 세션 — 사용자 전면 자율 지시):** tar.gz를 유지하고 공증만 붙인다. `.pkg`는 만들지 않는다. 단일 실행 파일이 stapler 대상이 아니라 오프라인 판정이 미보장이라는 사실은 Step 10 캠페인 문서에 적는다. 사용자가 뒤집으면 Step 5에 `.pkg` 빌드와 stapler 단계를 더하고 install.sh의 설치 경로를 하나 늘린다.
3. **musl을 두 아키텍처 다 할 것인가.** **결정(2026-09-24, main 세션 — 사용자 전면 자율 지시):** `x86_64-unknown-linux-musl` 하나. aarch64 musl은 §3 non-goal로 적되 네이티브 arm 러너가 있어 같은 레시피로 값싸게 더할 수 있다는 한 줄을 남긴다. aws-lc-rs가 막히면 Step 4를 닫지 않고 여기로 다시 올린다. 사용자가 뒤집으면 leg 하나를 더한다.
4. **man page를 packaging이 설치하는가.** **결정(2026-09-24, main 세션 — 사용자 전면 자율 지시):** Homebrew만 설치한다. unix 아카이브에 `man/*.1`을 더하고 formula에 `man1.install` 한 줄을 둔다. curl 설치 경로는 man을 설치하지 않고 README가 그 비대칭을 명시한다. 사용자가 뒤집으면 install.sh에 `MANPATH` 후보 탐색과 설치·제거 경로가 붙는다.
5. **"beta"를 선언할 것인가.** SC7이 공개 beta 전 독립 보안 리뷰를 요구하고 M8 DoD 4가 열려 있다. **결정(2026-09-24, main 세션 — 사용자 전면 자율 지시):** 선언하지 않는다. ROADMAP의 "beta 문서"는 릴리스 문서로 만들고 README Status의 유보는 유지하되 사유를 SC7과 열린 사람 캠페인으로 좁힌다. PRD §15는 개정하지 않는다. 사용자가 뒤집으면 SC7 문장의 개정 ADR이 먼저 필요하다.
6. **옛 계획 인용의 처분.** `docs/history/` 절 앵커로 바꾸는 일괄 정리를 M10에 넣을지, 기존 문면을 예외로 두고 신규 인용만 금할지. **결정(2026-09-24, main 세션 — 사용자 전면 자율 지시):** 후자다. 기존 793건은 부채로 두고 새 인용은 만들지 않으며 귀속처는 P1 정리 라운드다. 다만 M2~M6 계획을 `docs/history/`로 복원하는 것만은 따로 싸므로 Step 1에서 한다. 사용자가 뒤집으면 1.0~1.5ew 규모의 정리 스텝이 하나 들어온다.
7. **`fuzz/Cargo.lock`의 `cargo deny` 범위.** **결정(2026-09-24, main 세션 — 사용자 전면 자율 지시):** advisories만 켠다. licenses와 bans는 켜지 않는다 — fuzz 크레이트는 배포물이 아니고 워크스페이스 밖이라 라이선스·금지 목록 규율을 따로 유지할 이유가 약하다. 사용자가 뒤집으면 `fuzz/deny.toml`을 따로 두고 세 축을 다 켠다.
8. **crates.io publish를 M10 안에서 실행할 것인가.** ROADMAP M10 범위가 publish gate 해제를 이름으로 적지만 DoD 셋 어디에도 publish가 없다. **결정(2026-09-24, main 세션 — 사용자 전면 자율 지시):** 준비는 M10 안에서 에이전트가 하고(메타데이터, 크레이트별 `publish` 값, path 의존 `version`, `deny.toml` 주석, dry-run 네 건) 실제 `cargo publish`는 Step 10 PASS 뒤에 사람이 실행한다. 되돌릴 수 없어서다. 사람이 실행하지 않아도 M10은 닫히고 그 경우 마감 노트에 미실행으로 적는다. 사용자가 뒤집으면 CI에 publish 스텝을 배선한다.
9. **M9를 어떻게 닫을 것인가.** M9 DoD 1은 사람 몫이고 M7 DoD 1에 종속이며 둘 다 미실행이다. **결정(2026-09-24, main 세션 — 사용자 전면 자율 지시):** "기능 완료 · DoD 1 잔여"로 닫고 M10을 연다. M7이 같은 형식으로 닫힌 선례가 있고, 현재 마일스톤이 사람 캠페인을 기다리는 앞 마일스톤보다 앞설 수 있다는 규율도 이미 적혀 있다. ✅는 붙이지 않고 "현재 위치"만 M10으로 옮기며 M9 DoD 1은 §0.2로 이월한다. 사용자가 뒤집으면 M9를 열어 둔 채 M10 스텝만 진행하고 ROADMAP 헤더를 되돌린다.

## 9. 리뷰 반영 기록

(리뷰 라운드가 열리면 앞 마일스톤 계획과 같은 형식으로 채운다.)
