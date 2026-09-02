# PLAN.md — M7: Trust UX·profiles·doctor

M6 마감(2026-08-31, ROADMAP M6 마감 노트)과 함께 이 문서는 M7 실행 계획으로 전면 교체됐다. 구속 근거: `docs/ROADMAP.md` M7 절(범위·감사 개정 ①②③·DoD), `docs/PRD.md` §6·§11·§15(SC1/SC2), `docs/adr/0002-pairing-invite-code.md`, `docs/design/architecture.md` §2(trust 이중 모드)·§7(`hosts.toml`). 이 계획과 ROADMAP.md의 편집은 main 세션 전용이다.

> **2026-09-02 — M8 선행 착수 (문서 순서 예외).** §5.7은 M7 마감 시점에 이 파일을 M8 계획으로 전면 교체하라고 정한다. 그런데 M7의 잔여는 코드가 아니라 사람이 실행해야 하는 두 항목(DoD 1 스톱워치 3회, SC7 예약)뿐이고, M8의 fuzz DoD는 "parser 타깃당 누적 ≥72 fuzz-hours"라 벽시계 시간이 걸린다. 그 시계를 M7 마감까지 세워두면 리드타임을 두 번 잃는다. 그래서 M7 본문(§1–§5)은 감사 기록으로 그대로 두고 M8 계획을 §6으로 병기한다. 전면 교체는 M7 마감 커밋에서 §1–§5를 삭제하고 §6을 승격하는 것으로 수행한다.

## 1. DoD 체크리스트 (ROADMAP M7)

- [ ] **DoD 1 — 스톱워치 테스트**: 한 번도 설정한 적 없는 두 장비가 README만 보고 `qsh user@host`까지 5분 이내, 독립 3회 측정·기록 (SC1/SC2, 캠페인 문서 사전 정의). **미실행 — 사람이 해야 한다.** 기준은 `docs/campaigns/m7-stopwatch.md`에 사전 고정됐고 예행 1회를 마쳤으며 회차 환경은 `scripts/stopwatch/round.sh`가 준비하지만, 재는 대상이 사람 시간이라(같은 문서 §9) 에이전트가 대신 수행하면 그 문서가 이미 기각한 과소측정을 재생산할 뿐이다.
- [x] **DoD 2 — doctor 진단 6종**: UDP 차단/경로 없음/비신뢰 peer/만료 cert/keystore 부재(headless)/clock skew 각각 실행 가능한 메시지 + 안정된 JSON code. 근거: Step 6 — `EXPECTED_DOCTOR_CODES` 13종 동결 set-equality, 시각 임계값 경계 테스트, `classify_io_error` errno 분류, CLI.md 축자 문면을 지키는 `doctor_docs.rs`.
- [x] **DoD 3 — `qsh capabilities --json` == checked-in fixture** (scope-creep tripwire). 근거: Step 1 — fixture 등록 + `CLI_V1_SCHEMA_COMMANDS` 양방향 set-equality(단방향 const→arm 대조로는 등록 누락을 못 잡는다는 것을 mutation으로 확인한 뒤 재작성).
- [x] **DoD 4 (감사 ①) — `trust remove` 유효 범위**: 기존 연결·신규 handshake 각각의 동작이 테스트로 고정되고 문서·doctor 고지와 일치. 근거: Step 2 — 현행 의미론(다음 handshake부터) 확정 + 3문서·doctor 고지 + 내용 기반 재로드.

## 2. 실행 단계 (PR 단위)

### Step 1 — 저위험 노출 3종: version 식별자 + `qsh schema --json` + `qsh capabilities`

**(a) 범위:** ① `VersionData`에 빌드/커밋 식별자 additive 추가(감사 ③ — 필드명은 4.1 #1에서 확정). ② `qsh schema --json`: `fixtures.rs`가 이미 schemars로 생성해 검증에만 쓰는 스키마를 CLI 표면으로 서빙(한 소스 원칙, testing.md L82 문면). ③ `qsh capabilities` CLI 계약 확정(§6.10은 현재 예시 한 줄뿐) — peer와 negotiation된 `Hello.capabilities`를 반환하는 op 신설 + fixture 등재(DoD 3). CLI.md 해당 절 신설은 additive.

**(d) 완료 판정:** schema 출력 == fixtures.rs 생성물(동일 소스 구조 증명), capabilities fixture 대조 green, version 필드 additive 검사(기존 fixture 무변경).

**(a)-추기 — Step 1 확정 + 검증 라운드 판정 (2026-08-31, main 세션).** 검증자 발견 P1 0·P2 3·P3 6 판정:
① **4.1 #1·#2 확정** — version 식별자는 `VersionData.build: Option<BuildInfo{commit}>`(`option_env!("QSH_BUILD_COMMIT")`, 부재 = 키 생략), capabilities fixture는 no-host form(`wire::LOCAL_CAPABILITIES` 축자)만 golden. host form은 기존 `Ops::call`의 handshake 결과 판독 — 신규 wire op 0(§2.5 "인가 불요" 행이 M5 이전부터 예고했음을 git log -L로 확인). 인가 전 리소스 생성 0·audit 흔적 0 실측.
② **P2-1 수정 지시** — CLI.md §6.10 신설 문면이 "CI는 commit sha를 주입"을 현재형 단언하나 배선 0건, 게다가 주입 시 `version.json` golden이 깨짐(normalize가 build 키 무마스킹, 실증). 수정: (i) normalize()가 `build` 키를 마스킹/제거, (ii) ci.yml에 `QSH_BUILD_COMMIT: ${{ github.sha }}` 실배선 — 문면을 사실로 만든다.
③ **P2-2 수정 지시** — `CLI_V1_SCHEMA_COMMANDS`는 const→arm 단방향 게이트뿐이라 command 누락이 무증상(mutation 2종 실증 — Step 6의 `doctor.run` 등록 누락을 아무것도 못 잡음). M5 `OP_REGISTRY`↔`DENY_SEAMS` set-equality 선례대로 `Operation` impl 전수와 양방향 대조 + 의도적 제외(`session.attach` — stream op, data envelope 없음)는 사유 명시 목록으로.
④ **P2-3 수정 지시** — 값-보유 golden fixture(`capabilities.json`, L7 `tools_list.json` 동형)의 "diff 리뷰 필수, append-only 예외" 규율을 testing.md에 additive 명문화. `schema.get` golden 미보유(구조 동등성 테스트로 대체)도 같은 자리에서 채택 기록 — payload가 스텝마다 자라 append-only와 정면충돌, 생성기 정확성은 fixture payload 검증 20/21이 방어.
⑤ **P3 수정 2건** — §6.10 host form 문면의 reverse route 부정확("실제로 dial" → 직접 연결/reverse 등록 시점 합의 구분 1줄), "20 commands" 오계수 잔존물 정정(실제 21).
⑥ **P3 기록(무수정)** — §10의 schema deprecation 조회 약속은 대상 0건이라 미이행 무해(첫 deprecation 도입 시 additive 필드로 이행, §5.2 대조 항목); PRD §11의 schema/capability 병합 서술은 CLI.md §6.10이 더 구체적 구속이라 분리 설계 유지; 성공 dial의 host측 audit 무흔적 vs 거부 dial 기록의 비대칭은 M5 기존 설계 — Step 6(doctor) 입력으로 귀속; 서빙 스키마가 omitted-not-null을 인코딩하지 않음(schemars 기본)은 무해한 문서-스키마 간극.
⑦ **부재 증명 채택** — envelope 무변경·additive 검증(required 미포함, 기존 fixture 무변경), 단일 소스의 실제 방어선 규명(live-comparison은 CLI↔generator만; generator↔reality는 fixture payload 검증이 잡음 — wrong-type mutation 실증), no-host form identity 불요·부작용 0, §3.2 오류 표면 문자 단위 보존, stdout 순수성(32KB 1줄), 게이트 독립 재실행 동수치(1168/1 skipped), 트리 byte-identical 복원.
⑧ **수정 라운드 마감** — fixer가 ②③④⑤ 전건 반영(완전성 게이트는 4방향: 누락·중첩·유령 등록·유령 제외 + 스캔 붕괴 하한 ≥20; 우주는 M5 acl_registry 소스 스캔 선례 — OP_REGISTRY는 인가 필요 13종만 담아 부적합), mutation 3종(등록 제거 FAIL·EXCLUDED 중첩 FAIL·주입/비주입 왕복 956/1 동일) 전건 기대대로. main 세션 독립 spot-check: normalize의 build 제거 1줄 mutation → `normalize_drops_the_build_key` FAIL(EXIT=100) → byte-identical 원복. ②의 배선은 ci.yml(워크플로 전역 env)에 더해 release.yml에도 main 세션이 추가 — 배포 바이너리가 이 필드의 존재 이유다. 게이트 5종 전건 green(nextest 1172 passed/1 skipped, +4 = 신규 테스트 정확 일치). 잔여: release.yml 실릴리스 검증은 M9 태그 시점에 자연 수행.

### Step 2 — `trust remove` 의미론 확정 (감사 ①, 유예 불가) + `trust add` address 갱신 경로

**(a) 범위:** ① 현행 semantics(다음 handshake부터 적용, README Known limitations L417-419 문면 == `ops/mod.rs::trust_remove` 실코드)를 유지할지 즉시 종료로 바꿀지 **결정하고 근거를 이 절에 추기**. 어느 쪽이든: 기존 연결 생존/종료 + 신규 handshake 거부 두 동작을 실 QUIC 테스트로 고정, README·CLI.md·doctor 고지(Step 5와 연동) 문면 일치. ② M6 캠페인 백로그: `trust add`가 기존 peer의 address를 갱신하지 못하는 문제(`created:false` 시 무변경) — 갱신 경로를 결정(덮어쓰기 vs 별도 서브커맨드)하고 구현. 멱등성 계약(§6.11) 훼손 없이.

**(d) 완료 판정:** 두 동작 고정 테스트 green, 세 문서 문면 대조 일치, address 갱신 실측(M6 캠페인 재현 시나리오).

**(a)-추기 — Step 2 확정 + 검증 라운드 판정 (2026-08-31, main 세션).** 구현 결과 결정 A는 무신규로직으로 성립 — `SharedTrustStore`가 M1부터 handshake마다 mtime 확인·변경 시 재로드했고(M6 캠페인의 "시작 시 1회"는 ACL 얘기), 실 QUIC 테스트(trust_lifecycle_live.rs)로 러닝 데몬의 신규 handshake 거부 + 기존 연결 생존을 고정. 결정 B는 `trust add` 덮어쓰기(같은 fp+새 addr → addr만 갱신, `updated` additive 필드; fp 상이 → no-op 유지)로 구현, init_trust.rs 수정은 은폐 아닌 정당한 진화로 판정(단언 완화 0, 시나리오 보존, 계약 문면 동시 문서화). opus 검증 P1 0·P2 2·P3 4:
① **P2-1 수정 지시** — "기존 연결 생존"이 실노출을 과소 기술: 제거된 peer가 살아남은 연결로 **새** 터널/스트림을 무기한 열 수 있음이 실증됨(authorizer는 시작 시 ACL 1회 로드, trust 재평가는 handshake뿐, 연결 수명 상한 없음). README·CLI.md에 "이미 보유"가 아니라 "협상된 권한 전체(새 스트림·터널 개설 포함)를 연결 종료까지 보유, 강제 종료는 P1" 취지의 정직한 한 문장씩 추가. doctor 고지 문면에도 반영하도록 Step 6 입력으로 귀속.
② **P2-2 수정 지시** — mtime 전용 무효화는 같은 mtime 창에서 fail-open(실증; APFS 실측 200회 충돌 0건이라 주 플랫폼 미실현, 1–2s 해상도 FS 한정 노출). 판정: 문서를 약화하지 않고 **코드를 강화** — 매 handshake 파일 내용 해시 비교(trust.toml은 소형, TLS handshake 대비 비용 무시 가능)로 무효화를 내용 기반으로 바꿔 README의 "re-reads on every handshake"를 문자 그대로 사실로 만든다. 같은 mtime 내용 변경 반영 회귀 테스트(FileTimes로 mtime 고정) 필수.
③ **P3 기록(무수정)** — fp 충돌 no-op이 JSON·human 모두 무음(순수 no-op과 구분 불가): 보안 신호 관점 개선 여지가 있으나 §6.11이 방금 명문화한 무변경 계약이라 Step 2에서 확장하지 않고 **Step 4(invite pairing) 입력**으로 귀속; 신규 fixture가 normalize 탓에 주소 변경 값을 못 고정(실 QUIC 테스트가 고정하므로 무해); 스키마 `["boolean","null"]`은 schemars 기본으로 무해; trust store read-modify-write 무잠금(동시 CLI lost update)은 **Step 7 이월 부채 목록에 추가**.
④ **부재 증명 채택** — TLS 세션 재개/0-RTT 명시 비활성(재개 우회 구멍 없음), resume 주소 무캐시·reverse는 dial 시점 snapshot 해석이라 갱신 영향 없음, mutation 2종(갱신 라인 무력화 → 4레이어 5건 동사, 재로드 무력화 → 실 QUIC 거부 테스트 FAIL — tautology 아님), 독립 재실행 1180/1 일치, 트리 byte-identical 복원.

### Step 3 — `hosts.toml` host profile + 첫 실행 경험

**(a) 범위:** architecture.md §7 문면대로 `hosts.toml`(`[[host]] name·address·user`) 도입 — trust.toml(신뢰)과 분리된 주소 directory. `host.list`/host 해석이 trust.toml 단일 출처에서 hosts.toml 우선으로 확장(우선순위 규칙은 4.1 #4). `user`는 M7에서도 assertion hint일 뿐(불일치 시 `UNSUPPORTED`, PRD §6 user switching 없음 유지). README 첫 실행 절 초안(Step 8 스톱워치의 대본이 된다).

**(d) 완료 판정:** hosts.toml 유무·병합 각 조합의 host 해석 테스트, `qsh hosts`/`qsh host` 출력 계약 additive 검사.

**(a)-추기 — Step 3 확정 + 검증 라운드 판정 (2026-08-31, main 세션).** §4.1 #4 확정: hosts.toml 주소 우선, trust pinned fallback, 신뢰(fingerprint)는 trust.toml 단독 판정 — 실 QUIC 우선순위 테스트로 고정. 구현 증분 14+4 파일, 신규 테스트 25건(1182→1207), 게이트 5종 green(구현자 watchdog 종료로 §G 미기입 — main 세션이 로그 5건으로 직접 확인). tools_list.json 재생성은 값-보유 golden 규율(testing.md L6)대로 main 세션 diff 리뷰 통과(required 무변경, 신규 2필드 ["string","null"]). opus 검증 라운드는 사용자 중단으로 §C 이후 미완 — §A 주장 5건 판정(4 성립, #5 "성립하나 불충분")과 P1 1·P2 3·P3 5는 확보, mutation 실증·게이트 재실행은 fixer 라운드에 승계. 중단 잔재(mutation ① 미원복 1줄)는 main 세션이 원복하고 byte-identical 재확인. 판정:
① **P1-1 수정 지시** — README "First run"이 acl.toml 단계 누락 + serve 선기동 순서로 M6 캠페인이 기록한 실패 모드(PERMISSION_DENIED)를 재발시킴(실측 재현). acl.toml 작성이 serve 시작 **전**에 오도록 절 재구성(trust add는 Step 2의 내용 기반 재로드 덕에 serve 후라도 무방 — 검증자 실측), "Five commands" 계수 정정. 이 절이 Step 8 스톱워치의 대본이므로 문면 그대로 따라 성공해야 한다.
② **P2-0+P2-1 수정 지시(한 몸)** — pin 조회가 fingerprint 기준 전역이라 hosts.toml 한 줄로 이름을 기핀 타 peer로 무성 재지향 가능(0700 동일 디렉터리라 신규 권한 계층은 아님 — P1 격하 타당). 잔여 문제는 탐지 창구의 거짓말: 충돌 시 `host get`이 실재하지 않는 (주소, device_id) 조합을 단언하고 `source:"both"`가 충돌을 가림. 수정: **`source` 의미를 주소 승자 기준으로 재정의**(미커밋 필드라 자유) — "hosts"(hosts.toml 주소 채택: trust와 다르거나 trust 무주소), "trust"(trust 주소 채택), "both"(**양쪽이 같은 주소로 일치할 때만**). 이러면 재지향이 `source:"hosts"`로 즉시 드러나고 "both"는 일치의 증언이 된다. device_id 문서에 "이름에 핀된 신원이지 주소 현점유자의 관측이 아니다" 명시, CLI.md §6.1+README에 threat 한 문장(hosts.toml 쓰기 = 기핀 peer로의 이름 재지향 권한; mTLS는 여전히 임의 주소를 막는다), 충돌 시나리오 고정 테스트 + 값-보유 golden 재생성(diff 리뷰).
③ **P2-2 수정 지시** — exec.rs map_dial_error 직전 주석("주소가 있다 = trust store에 있다")이 Step 3으로 무효 — hosts.toml-only 이름의 LocalRejected는 missing pin인데도 mismatch로 설명. 주석만 실동작 서술로 갱신(계약은 §6.11이 이미 일관 — 검증자 실측).
④ **P3 수정 2건** — P3-1: CLI.md §6.1에 hosts.toml 신선도 의미론 1-2문장(op 시작 시 해석; attach 재접속은 attach 시점 해석 유지 — trust 내용 기반 재로드와 명시 대비). P3-5: reverse 라우팅에서 hosts.toml user hint가 적용은 되는데 표시는 None인 불일치 — reverse Host emit에도 user를 채워 표시-적용 일치(additive, source는 주소 개념이라 reverse에서 계속 생략), 테스트 1건.
⑤ **P3 기록(무수정)** — P3-2 human 표에 SOURCE/USER 열 상시 추가는 human 비계약이라 무해; P3-3 serve 측 hosts.toml 비독자는 의도 부합(architecture.md §7에 1줄 명시는 fixer 재량); P3-4 PLAN 오참조는 아래에서 main 세션이 정정.
⑥ **검증 승계** — 중단으로 미완된 mutation 2종(우선순위 반전 → 우선순위+실연결 테스트 FAIL, user 불일치 우회 → UNSUPPORTED 테스트 FAIL)은 fixer가 표적 cargo test로 실증하고, 수정 후 전체 게이트 5종 재실행. 환경: main 세션이 cargo clean 단행(deps 173GB → 디스크 99% 해소, syspolicyd 부하 근원 제거) — 이번 게이트는 풀 리빌드 1회 비용.
⑦ **CI-red 후속(e93368c → Windows red, main 세션 직접 수정)** — user-hint 불일치 테스트가 대화형 attach(`qsh box`) 경유였는데 Windows는 그보다 앞선 POSIX 터미널 게이트가 다른 UNSUPPORTED로 먼저 거부(로그 실측). `session open --json` 경유로 재작성 — `resolve_user_hint`는 3 frontend 공유 단일 choke point(문서화된 사실)라 의도 동일, envelope의 UNSUPPORTED + user-gate 메시지("user switching is not supported")를 단언해 Windows에서도 PTY-unsupported 경로와 구분되는 비공허 검증(서버 user 게이트가 세션 자원 생성보다 선행 — server/mod.rs 실측). 게이트 5종 재green.

### Step 4 — invite pairing (ADR-0002 구현)

**(a) 범위:** `qsh trust invite`/`qsh trust accept <code>` — 고엔트로피 일회용 invite code(10분 TTL), TLS exporter 기반 HMAC proof 교환으로 양방향 pin 동시 설정. CLI 계약(플래그·JSON envelope) 확정 + CLI.md §6.11 확장(additive, L604의 "M7에서 확정" 이행). `--json` 경로는 prompt 금지 — `TRUST_REQUIRED` + `details.fingerprint`(ADR-0002 문면). pairing 안내 문구에 대역 외 fingerprint 대조 경로 포함(감사 ②). wire 추가분은 `docs/design/protocol.md`에 반영 — **M8 wire freeze 전 마지막 프로토콜 확장이므로 스키마를 보수적으로**.

**(d) 완료 판정:** 실 QUIC 왕복 pairing E2E(성공/TTL 만료/재사용 거부/HMAC 불일치 4상한), `--json` 비대화형 검사, fingerprint fallback(§6.11 기존 경로) 회귀 무손상.

**(a)-추기 — Step 4 검증 라운드 판정 (2026-08-31, main 세션).** 구현 28+7 파일, 신규 테스트 대량(1209→1243), 게이트 5종 green. opus 적대적 검증(mutation 8건 주입·전건 원복, tree baseline `549544…` byte-identical 확인)에서 **P1 0건 실증**: 자원 선행 생성 금지가 라우팅+ACL loader의 이중 방어(`auth_path="pairing"`을 파서가 아예 못 받음)로 성립, rogue-responder 방어·도메인 분리(0x01/0x02가 실제 해시 입력)·channel binding(exporter 1비트 변조 시 교환 실패)·constant-time(비교 2곳 전부 `ct_eq`, `==` 0건)·단일사용/no-burn·collision loud-fail·secret 비영속(0600+mac_key만) 전부 mutation으로 검출 확인. 구현자 §B13(rogue responder)·§B14(pin-before-consume ordering) 자체수정 실버그 재현 확인 — 과장 아님. 계약 규율(fixture append-only, `CLI_V1_SCHEMA_COMMANDS` 등록 완전성 게이트 mutation 실효 확인, tools_list 무변경)·arch 경계 PASS. P2 3건·P3 다수 처분:
① **F-2 수정 지시 (P2, DoD 게이트)** — 이미 상호 pin된 peer의 `trust accept`가 `verify_core`의 pin-우선 순서로 `Principal::Pairing`을 못 얻고 `handshake::respond`의 `ExpectedHello`에서 error frame 없이 죽어 `CONNECTION_FAILED`+`retryable:true`를 반환(실증). (d) 완료판정의 "재사용 거부→`SESSION_CONFLICT`" 상한이 **가장 흔한 same-client 재시도에서 미충족**이고, README "Known limitations"+§F의 복구 안내("fresh invite 받으라")가 실제 무효(host `trust remove`만이 유일 해법). 수정: (a) handshake 경계에서 이미 인증된 연결의 첫 프레임이 `PairingProof`면 침묵 drop 대신 명시 Error frame(`SESSION_CONFLICT` 계열, **`retryable:false`**)을 `accept()`가 surface하도록 — 프레임 정합 확인 필수; (b) CLI.md §6.11의 무조건 `SESSION_CONFLICT` 약속을 실제 동작(다른 peer 재사용=`SESSION_CONFLICT` / 이미 paired peer 재-pair=연결 수준 거부, 이유=verify_core pin 우선)에 맞게 정정; (c) README+protocol.md §15.6 복구 안내를 "fresh invite로 불가, host `trust remove` 선행"+이유로 정정. mechanism/ErrorCode는 rebuttal 가능하나 `retryable:true` 무한루프 제거와 복구 안내 정정은 필수. 회귀: same-client 소진 code 재사용→non-retryable 명시 오류 테스트.
② **F-3 수정 지시 (P2)** — PLAN Step 4 (a) 명시 항목 "pairing 안내에 대역 외 fingerprint 대조 경로 포함(감사 ②)" 미이행+미공개(README는 오히려 "neither side needs the other's fingerprint" 서술). 수정: pairing 안내(CLI.md §6.11 + protocol.md §15 + human/README 중 최소 1)에 **사후** out-of-band fingerprint 대조를 defense-in-depth로 안내(`print_trust_accept`가 이미 pin된 fingerprint 출력 — 대조 재료 존재), "ahead of time 불요"와 "사후 대조는 선택 가능"을 양립하게 문면 조정. **F-4 병합**(P3): 저장된 `mac_key`가 verifier-equivalent(파일 읽으면 초대 소비 가능)임을 문서 1줄로 밝히고 "0600이 실질 방어" 명시.
③ **F-9 처분 (P2 → 일부 수정 + Step 7 승계)** — `invites.toml`이 두 프로세스(trust invite/serve) 간 락 없는 read-modify-write라 lost update 시 `consumed_at` 유실로 "정확히 1회" 붕괴(경합 창 미트리거, 귀결은 결정적 재현). **완전한 락킹은 Step 7 이월부채의 "trust store no-locking"을 `invites.toml`까지 확장해 승계.** M7-now: (a) 소진 단조성 — 쓰기 직전 재읽기 후 `consumed_at`을 절대 되돌리지 않는 단조 병합으로 창을 좁히거나, `std::fs::File::lock`/기존 workspace dep으로 값싼 advisory lock이 가능하면 적용(신규 의존/플랫폼 분기 필요 시 병합으로 대체, rebuttal 가능); (b) "정확히 1회"를 무조건 단언하는 문면이 있으면 프로세스 간 경합 잔여 창을 정직히 부기.
④ **F-1 수정 지시 (P3, 최우선 test gap)** — ADR-0002 유일 anti-MITM 근거 channel binding에 회귀 0건(exporter를 `[0u8;32]`로 치환해도 전 테스트 녹색). 수정: responder ekm 1비트 변조 시 성공 quadrant 실패(실험 3a 회귀 고정) 또는 두 별개 연결 exporter 값 상이 단언 중 최소 1건 추가.
⑤ **F-6 수정 지시 (P3, SC1 UX)** — `trust accept`가 방금 dial 성공한 주소를 버려(`add_peer`에 `None`) 페어링 직후 `qsh exec <peer>`가 `HOST_NOT_FOUND`. 수정: dial한 주소를 `Some`로 pin(`trust add --address`와 동일 의미). address는 fixture 정규화가 무조건 마스킹하므로 golden 무변경 예상(fixer 확인).
⑥ **F-5/F-7/F-8 처분** — F-5(소비 후 20분 retention 내내 TLS 게이트 열림): 설계 의도이나 "소비 후에도 열림" 문서 미명시 → protocol.md §15.7에 1줄 부기(소비 후 짧은 grace 동작 변경은 M8 refinement 이월). F-7(Crockford 조기 길이 컷오프 부재): 실 위험 0(argv 상한), >32 심볼 즉시 bail이 trivial하면 적용, 아니면 생략. F-8(`redeem`이 lock 내 블로킹 I/O): Step 7 런타임/no-locking 부채로 승계.
⑦ **검증 방법 승계** — 수정 후 표적 회귀(F-1 채널바인딩, F-2 same-client 재사용, F-9 병합/락, F-6 주소 pin) + 게이트 5종 재실행. fixer는 각 수정을 mutation으로 self-verify(수정한 속성을 깨보고 새 테스트가 FAIL하는지). tree는 baseline(`549544…`) 위 증분만.

### Step 5 — private CA `qsh cert` (ADR 선행)

**(a) 범위:** ① **ADR 신설이 선행** — CA 계층(단일 CA), 서명 대상(device cert, `qsh://device/…` SAN → `device:` principal), user cert 취급, 파일 위치·포맷. 현재는 architecture.md의 부분 결정(pin-or-CA verifier·rcgen)만 있는 백지 표면이다. ② ADR 승인 후 `qsh cert` 최소 표면 구현: CA 생성, device cert 발급, trust store CA 등재. rotation/revocation UX는 명시 out(§3).

**(d) 완료 판정:** CA 발급 cert로 실 handshake 성공 + pin 없는 CA-chain 경로 검증 테스트, `fp:`/`device:` principal 매핑 검사, ADR 링크가 CLI.md 신설 절에 명시.

**(a)-추기 — Step 5 ADR 선행 게이트 확정 (2026-08-31, main 세션).** opus 설계 조사(브리프 `$SP/m7s5-adr-brief.md`, file:line 실측)로 핵심 사실 확정: **CA-chain 검증 경로는 껍데기가 아니라 완전 실동작**(verify_core가 `ca_roots()`→webpki 체인 검증→SAN principal 유도, handshake_matrix case09/15가 pin 없는 CA 경로를 실 QUIC로 이미 통과). SAN 파서(`principal_from_san`)·device cert SAN 삽입·`trust.toml [[ca]]` 슬롯·`ca_roots()` 배선·testkit CA 발급기까지 전부 존재 — **비어 있는 건 발급/등재 프런트엔드(`qsh cert`)뿐.** 이에 근거해 **ADR-0008 신설·승인**(docs/adr/0008): ① 단일 self-signed root 직접 서명(intermediate 없음, rotation out이라 실익 0), ② `qsh cert issue`가 로컬 device_id를 `qsh://device/<device_id>` SAN에 담아 CA-서명 → `device:<device_id>`+`AuthPath::Ca`(SAN·파서 재사용, 신설 0), ③ user cert 발급은 P1(검증 경로는 유지, 발급 UX만 out), ④ `config_dir/ca/`(0700)에 `ca.pem`·`ca.key`(PKCS#8 PEM, 0600), 공개 루트는 `[[ca]]` 등재, ⑤ 발급 대상=로컬 device 승격만(원격 발급 P1), ⑥ pin>CA>pairing 유지+"pin·CA 동시 시 pin 우선(auth_path=Pin)". **(d) 문구 재해석(D-1, ADR §결정에 명문화)**: pin/CA의 load-bearing 구분은 principal 모양이 아니라 `AuthPath`(Pin vs Ca)다 — pin device와 CA device는 둘 다 `device:`일 수 있고 auth_path가 가른다(architecture.md §6/§7 불변식). "`fp:`/`device:` principal 매핑 검사"는 "pin→`AuthPath::Pin`, CA→`AuthPath::Ca`를 실 핸드셰이크로 단언"으로 이행하며, 미생산 예약 variant인 `Principal::Fingerprint`(`fp:`)를 새로 생산하는 것은 **scope-creep이라 하지 않는다.** 구현 체크리스트 승계: D-2(CaEntry 낡은 주석 갱신), D-3(CA 키 file 0600, platform P1), D-5([[ca]] 등재 멱등성=trust add 선례), D-6(신규 MCP tool 미노출 — §8.4 일관), D-7(CA 발급 표면 SC7 대상).

**(a)-추기 — Step 5 검증 라운드 판정 (2026-08-31, main 세션).** 구현 증분 16 M + 6 신규 파일(신규 `ca.rs`/`ops/cert.rs`/`cert_e2e.rs` + golden 2, `qsh cert init`/`issue` 2 서브커맨드), 게이트 5종 green(nextest 1264 passed/1 skipped, +21). 두 축 멱등성: leaf 재서명은 `identity.toml`의 신규 `issued_by_ca`(CA root fp)로, `[[ca]]` 등재는 `TrustStore::add_ca`(name-dedup, created/updated tri-state). 발급 대상은 로컬 device 승격(같은 key 재사용 → 기존 pin 불변), CA 저장은 `config_dir/ca/`(0700)+`ca.pem`/`ca.key`(0600). opus 적대적 검증(mutation 10건 주입·전건 exact-inverse 원복, baseline `1c16153c…` byte-identical 재확인 — transport diff 0건, 16 M + 6 ?? 일치)에서 **P1 0·P2 0 실증**: 파일 권한(dir 0700→0755 / file 0600→0644 느슨화 시 `ca::init_writes_private_files` FAIL — write_private_file은 temp를 처음부터 0600 생성 후 rename, umask 무의존·노출창 0), `add_ca` 멱등(dedup `==`→`!=`·name-dedup 제거 시 tri-state 단언 FAIL), `issued_by_ca` 재서명 멱등(`==`→`!=` 시 E2E first issued=false FAIL), **`ca_issuer_params()` 결정론성**(CN에 pid 부착 시 CA handshake E2E가 AUTH_FAILED — §B "매 프로세스 DN 재구성" 우회가 실 handshake로 결정론적임 증명), **auth_path ca-vs-pin load-bearing 축**(ACL 규칙 ca→pin 시 CA principal이 PERMISSION_DENIED로 거부, 단언 ca→pin 시 실 audit `auth_path:"ca"`+`principal:"device:<id>"`(fp: 아님) 확인 — D-1 재해석 실증), fail-closed(no-CA 에러 retryable flip 시 FAIL) 전부 mutation 검출. 정적: verify_core/principal_from_san/parsed_pins/우선순위 무변경(transport diff 0), 신규 `fp:` producer 0, 신규 MCP tool 0(tools_list.json 미변경), CA·leaf 개인키 로그/에러/렌더 유출 0, 계약 additive·fixture append-only·순수 JSON·신규 에러코드 0. P3 4건 처분:
① **P3-1 수정 지시 (진짜 gap, 방어-전용)** — `ca::init`의 key-first/cert-last crash-safety 쓰기 순서를 뒤집어도 7개 ca 테스트 전부 PASS(성공 경로엔 두 파일 다 존재해 순서 미강제). 코드는 올바르나 회귀 방어 부재. 동일 무테스트 패턴이 신규 코드 `promote_to_ca_issued`(device.pem→identity.toml)에도 존재. 수정: 신규 코드 두 경로(`ca::init`, `promote_to_ca_issued`)에 "선행 파일만 쓰고 중단된 상태"를 시뮬레이션해 `read_root`/재-issue가 깨끗이 재생성함을 단언하는 회귀 테스트 추가 — 테스트 전용, 다른 게이트 무영향. `identity::init`의 동일 패턴은 **기존 코드**라 Step 5 범위 밖(회귀 하네스는 미래 하드닝으로 이월). fixer는 추가 테스트를 mutation으로 self-verify(순서 뒤집어 FAIL 확인).
② **P3-2 유지(수정 안 함)** — leaf 멱등이 on-disk cert 실 issuer를 재검증 않고 `issued_by_ca` 문자열만 비교(손상된 device.pem 재-issue 미복구). §B 명시 의도적 트레이드오프, 반환 fp는 실 on-disk cert 기반이라 거짓 보고 아님(handshake 실패로 운영자 감지), CLI.md §6.16에 문서화됨. 판정: 낮음, 현행 유지.
③ **P3-3 Step 7 이월** — `cert_issue`의 trust.toml RMW 무잠금(last-writer-wins). `trust add`(Step 2)와 **동일 posture, 신규 리스크 아님.** Step 7 이월 부채의 "trust store no-locking"에 이미 포함 — 그 자리에서 invites.toml full locking과 함께 처리.
④ **P3-4 Step 7 이월(관찰)** — 동시 `cert init` temp 파일 인터리브(ca.key/ca.pem 불일치 가능). `identity::init`과 동일 posture, ADR §5 단일-로컬-device 스코프상 비현실적. Step 7 no-locking 부채에 병기.
⑤ **M9 부재-gap 판정** — `issued_by_ca`의 `#[serde(default)]` 제거해도 green이나, serde가 `Option` 누락을 intrinsic하게 `None` 처리하므로 잉여 속성일 뿐(gap 아님). 하위호환은 `init` 왕복 테스트가 `skip_serializing_if` 생략 toml 로드 경로를 실제로 지나 방어 — 수정 불요. belt-and-suspenders로 `serde(default)`는 유지.
⑥ **검증 방법 승계** — fixer는 P3-1 회귀 테스트 추가 후 mutation self-verify(쓰기 순서 뒤집어 새 테스트 FAIL 확인) + 게이트 5종 재실행. tree는 baseline(`1c16153c…`) 위 증분(테스트 추가)만.
⑦ **CI-red 후속(6a83abd → Windows red, main 세션 직접 수정)** — 신규 `Identity.issued_by_ca` 필드가 `reverse/listen.rs`·`reverse/target.rs`의 `#[cfg(not(unix))]` Windows-leg 테스트(Step 3이 심은 positive assertion) 두 `Identity{}` 리터럴에서 누락돼 Windows clippy·nextest가 E0063으로 컴파일 실패(로컬 unix 게이트는 이 cfg 블록을 컴파일하지 않아 놓침 — Step 3 ⑦과 동형 갭). 워크스페이스 전체 `Identity` 리터럴 전수 조사로 정확히 이 2건만 누락 확인(프로덕션 `identity/mod.rs`·testkit는 커버됨), 각 리터럴에 `issued_by_ca: None` 추가. 재발 방지로 `cargo check --target x86_64-pc-windows-gnu -p qsh-core --lib --tests` 크로스 컴파일 실증(EXIT=0, cfg(not(unix)) 모듈까지 E0063 없이 통과) — CI가 컴파일할 대상을 로컬에서 확인. fmt/clippy(unix) 재green.

### Step 6 — `qsh doctor`

**(a) 범위:** `doctor.run` op + `qsh doctor` CLI(§6.11 L604 예약 이행). 진단 항목: DoD 2의 6종 + 기존 core 상수 2종(`controller_unreachable`·`audit_path_unwritable` 소비) + PATH 상 타 qsh 경고 + acl 시작 진단 코드(`acl_policy_missing`/`acl_policy_invalid`) 노출 + Step 2의 trust remove 고지. code 어휘는 4.1 #5에서 사전 고정(안정성 계약).

**(d) 완료 판정:** 진단 각각을 실제로 유발하는 테스트(UDP 차단은 협조적 mock, clock skew는 주입) + code 안정성 fixture, 사람 문면에 실행 가능한 다음 행동 포함.

**(a)-추기 — Step 6 설계 게이트 확정: 4.1 #5 code 어휘 잠금 (2026-09-01, main 세션).** opus 설계 조사(브리프 `$SP/m7s6-doctor-brief.md`, file:line 실측)로 표면 대부분이 이미 존재함을 확정: `doctor.run`은 CLI.md §2.4/§2.5에 **로컬 value-op·ACL 불요**로 예약됨(`acl.check` 동급), `crates/qsh-core/src/doctor.rs`가 이미 상수 2종·`probe_audit_path_writable`·`DiagnosticId` enum + **`#[cfg(unix)]` 금지 규율**(L13-15, text-not-behavior)을 담음, cert 판독기 `qsh_transport::identity::validity_unix`(transport/identity.rs:234)·ACL code 2종(acl/load.rs:239/243)·keystore 도달성(`PlatformKeyStore::load`의 `Err(Unavailable)`, 비변경 read)이 전부 재사용 가능.
**진단 code 어휘 13종 잠금(snake_case, shipped 후 additive-only 안정성 계약 — §4.1 #5 확정).** 재사용 5(문자열 verbatim): `controller_unreachable`·`audit_path_unwritable`(doctor.rs:52/65)·`acl_policy_missing`·`acl_policy_invalid`(acl/load.rs) + cert 판독기. 신설 8: `udp_egress_blocked`(error — 문면에 "TCP fallback P1 예정·ADR-0005" 필수), `no_route`(error), `peer_untrusted`(error — hosts.toml이 이름을 알지만 trust.toml에 pin 없음=TRUST_REQUIRED 운명의 정적 교차대조 + target 지정 시 동적 dial), `cert_expired`(error — device leaf `identity/device.pem` **와** CA root `ca/ca.pem` 양쪽, detail로 어느 cert인지 구분), `cert_expiring_soon`(warn — 30일 이내, `cert_expired`와 상호배타), `keystore_unavailable`(warn — headless file fallback 보고, load probe만), `clock_skew`(warn 경미/error 핸드셰이크 파탄 — 5분 backdate 창 초과), `qsh_path_shadowed`(warn — `$PATH`에 `current_exe`보다 앞선 다른 qsh), `trust_remove_scope`(info — Step 2 확정 semantics 고지, pin ≥1이면 상시). **status 어휘 4값 잠금**: `ok`·`warn`·`error`·`info`(§10 열린 문자열 규율, `ok`는 개별 finding엔 미출현·`overall`에만). 완전성: M7 기능축(identity/CA/trust/ACL/audit/연결성/환경) 소진 논증으로 닫힌 집합 — 유예 기능(TCP fallback 등)·전제조건 실패(identity 부재)·로더가 이미 CONFIG_ERROR로 잡는 파싱오류는 진단 대상 아님.
**envelope/op**: `DoctorData{ overall:String, findings:Vec<DoctorFinding{code,status,detail,remedy:Option<String>}> }` + `DoctorReq{host:Option<String>}`(= `qsh capabilities [host]` 동형). **findings 모델**(ok 항목 미포함 — 재사용 상수가 실패-명명이라 이중 어휘 방지, 통과 가시성은 `overall:"ok"`+human "N checks passed"). `Ops::doctor(req, now: SystemTime)` — **now 주입 필수**(cert 3종+clock 유발; 아키텍처 변경 아님, 선례 pairing.rs:305/config.rs:346). 연결성 분류는 `classify_connectivity(Result)->finding` **순수함수**(errno/DialError 주입 → 실소켓 flaky 배제). 플랫폼 probe(UDP·PATH)는 신규 `doctor/probe.rs`로 격리(doctor.rs no-cfg 규율 보존, 양 플랫폼 컴파일), probe 진단은 `tracing`(stderr)만·`println!` 금지(jsonl_purity). **exit 항상 0**(finding은 data, `overall`이 건강도 — `acl.check` L845 선례; doctor **자체** 미가동만 OpError→255). `--fail-on`(CI 게이트 nonzero)은 미래 additive, **지금 미구현.**
**완전성 게이트**: `CLI_V1_SCHEMA_COMMANDS`에 `"doctor.run"` 등재 필수(양방향 set-equality 게이트 — Step 1 ③이 심음, data-envelope라 EXCLUDED 아님) + `cli_v1_data_schema` arm. golden fixture는 **byte-freeze 안 함**(환경 의존, schema.get 선례) — 대신 "code 안정성 fixture" = `DiagnosticId` 13종 ↔ `EXPECTED_DOCTOR_CODES` 동결집합 set-equality 테스트 + 재사용 상수 문자열 고정(doctor.rs:106 선례). 신규 정적 문면(#13 등)은 `doctor_docs.rs`형 README·CLI.md 대조. **precedence 명문화**: 한 연결 실패에 code 하나만 — controller target이면 `controller_unreachable`, 일반 egress면 errno로 `udp_egress_blocked`(침묵드롭) 또는 `no_route` 중 하나(중복 발화 금지, 테스트로 단언). arch: 감지·분류·문면 전부 qsh-core, CLI는 `print_doctor` 순수 렌더, **신규 MCP tool 0**(tools_list.json 미변경).

**(a)-추기 — Step 6 검증 라운드 판정 (2026-09-01, main 세션).** 구현 증분 11 M + 2 신규(`doctor/probe.rs` 458줄·`ops/doctor.rs` 899줄), 신규 테스트 41건, 게이트 5종 green(**nextest 1305 passed / 2 skipped**, main 세션 독립 재실행 동수치). 검증은 Workflow로 오케스트레이션(6차원 병렬 정적 분석 → 제안 변이 직렬 실증 → opus 종합 판정, 8 에이전트, 변이 36건 제안·주요 9건 전체 스위트 재현). tree baseline `0282927c…` byte-identical 복원 확인(HEAD 무변경, 12 M + 2 ??).
**P1 = 0 실증**: exit-0 계약(변이 4건 전건 CAUGHT), 시크릿 비노출(`keystore_finding`이 `Ok(Some(key_bytes))`를 `_` arm으로 버려 키 바이트가 finding에 들어갈 경로가 **타입 수준에서** 없음), stdout 순수성(`println!`/`print!` 0건), arch 경계(`print_doctor` 로직 0줄), ACL 무변경(`Authorizer` 즉시 폐기), 신규 ErrorCode 0. 잠긴 계약 중 code 13종 set-equality·envelope additivity·`CLI_V1_SCHEMA_COMMANDS` 양방향 게이트·precedence 순수함수·`now` 주입·MCP tool 0은 전부 변이로 방어 확인(24/33 CAUGHT).
**그러나 DoD (d) ①은 미충족(9/13)** — 결함이 프로덕션 로직이 아니라 **테스트 방어선**에 있다. 판정자가 **배선 지점**을 겨냥해 심은 변이 9건이 전체 스위트(704 tests)에서 **전부 GREEN**: 진단이 아예 사라져도 아무 테스트도 실패하지 않는다. (앞 라운드 GREEN 3건이 `ops::doctor::` 스코프 한정 인공물이었음을 판정자가 스스로 간파하고 전체 스위트로 재현 — 결론 강화.) P2 5건·P3 8건 전건 수용, 처분:
① **P2-1 수정 지시** — `no_route`의 `Ops::doctor` 레벨 유발 테스트 부재. **브리프 §C/§E-2의 "실소켓 no_route는 OS 의존이라 불가"는 실증으로 기각됨**: 포트 없는 주소(`203.0.113.9`)를 pin하면 `resolve_probe_socket_addr` 파싱 실패 → `Unreachable` → `no_route`가 소켓·DNS·OS 의존 없이 결정론적으로 뜬다(판정자 실행 `NOROUTE codes=[…,"no_route"]`). 변이 MC(`Err(_)=>Unreachable`→`TimedOut`) GREEN. 수정: 그 시나리오 E2E 테스트 추가(테스트 전용).
② **P2-2 수정 지시** — `keystore_unavailable`의 유일한 E2E가 `if let Some(finding) = …` 조건부 단언이라 **발화 0회여도 통과**. 변이 MA(배선 라인 삭제) GREEN. DoD (d)가 이름을 건 6종 중 하나. 수정: `keystore_finding_of(store: &impl KeyStore)` 자유함수로 시임 한 겹 분리(`KeyStore`는 이미 doctor가 import 중인 공개 트레잇) + `Err(Unavailable)` 스텁으로 결정론 단위테스트. qsh-core 내부라 arch/proto/fixture 무영향.
③ **P2-3 수정 지시 (잠긴 계약 위반)** — `cert_expired`/`cert_expiring_soon`의 **CA root 절반이 전혀 실행되지 않음**. 잠긴 계약은 "device leaf **와** CA root 양쪽, detail로 구분"인데 `ops/doctor.rs` 테스트 모듈 전체에서 `crate::ca::init` 호출 0건(전부 CA 미초기화 `healthy_ops()`). 변이 MD(`&ca.cert_der`→`&identity.cert_der`) GREEN — CA 분기를 통째로 지워도 통과. 수정: `cert_init` 후 CA `not_after` 이후 시각을 `now`로 주입해 `cert_expired`가 **2건**(detail에 leaf/CA root 각각) 나옴을 단언.
④ **P2-4 수정 지시** — `qsh_path_shadowed`도 조건부 단언(변이 MB 배선 삭제 GREEN). 이 머신엔 PATH에 실제 qsh가 있어 **발화하는데도** 통과했고(앞 라운드가 잡힌 건 머신 운), qsh 미설치 CI에선 완전 공허 — 환경 의존 테스트. 수정: `path_shadow_finding(current_exe, dirs)` 순수함수 분리(`std::env` 읽기는 호출부 잔류) + 임시 PATH 주입 결정론 테스트(probe.rs:393-431에 이미 있는 패턴).
⑤ **P2-5 수정 지시 + README 판단** — PLAN L98이 잠근 완전성 게이트("신규 정적 문면은 `doctor_docs.rs`형 문서 대조")가 미이행(여전히 `CONTROLLER_UNREACHABLE` 하나만 대조). CLI.md §6.17은 이미 `TRUST_REMOVE_SCOPE`의 message/remedy를 verbatim 인용하므로 대조 테스트를 추가하면 그대로 통과. **README는 verbatim을 강제하지 않는다(main 세션 결정)** — README는 첫 실행 서사용 산문이고 진단 문자열을 그대로 박으면 가독성이 상한다. 대조는 **CLI.md 한정**.
⑥ **P3-1 수정 지시 (유일한 프로덕션 로직 버그)** — `clock_skew_finding`이 `(not_before-now)/60`으로 **초를 분으로 절삭**한 뒤 `> CERT_BACKDATE_MINUTES`를 비교해, 301초(=300초 마진 초과) skew를 error가 아닌 **warn**으로 보고(판정자 실측 `SKEW301 status=warn`; main 세션도 ops/doctor.rs:362 직접 확인). doctor.rs 문면·CLI.md §6.17("마진을 넘으면 error")과 어긋난다. 수정: **비교를 초 단위로**(`not_before - now > CERT_BACKDATE_MINUTES * 60`), 분은 detail 문면용으로만 유지 + 301초 경계 테스트. 기존 두 테스트(600s→error, 180s→warn)는 수정 후에도 통과.
⑦ **P3-2/3-3 수정 지시** — 세 시간 임계값(now==not_after, 정확히 30일, 정확히 5분) **경계 테스트 전무**(변이 MF/MG/MI 전건 GREEN, 기존 테스트가 여유 오프셋만 씀) → 각 임계값에 정확 경계 1건씩. `classify_io_error` 구동 테스트 0건(변이 MH GREEN) → 능동 거부 포트가 `no_route`가 아니라 `udp_egress_blocked`("방화벽이 UDP를 막음")로 보고돼 **운영자에게 틀린 remedy**가 나가므로 `io::Error::from(ErrorKind)`로 단위테스트.
⑧ **P3-4/3-5/3-6/3-7/3-8 수정 지시(전건 저비용)** — (3-4) controller alias와 positional host가 같은 대상이면 한 실패에 code 2개(실측 `DUPCODES`) → `extra_host`가 controller와 같게 해석되면 두 번째 probe 생략(문자 그대로의 계약 위반은 아니나 운영자에겐 모순). (3-5) `audit_path_unwritable` 유발 테스트가 `#[cfg(unix)]` 단독 → doctor.rs 모듈 doc이 선언한 "Windows leg 포함 build+run" 규율에 맞게 존재하지 않는 경로 등으로 Windows leg 커버(플레이키하면 주석으로 강등). (3-6) human 렌더의 `sanitize()`가 ACL 진단의 멀티라인 배너를 U+FFFD로 뭉갬 → `print_doctor`에서 detail을 **줄 단위로 쪼갠 뒤 각 줄을 sanitize**해 들여쓰기 출력(escape-injection 방어 유지 필수, `--json` 무영향). (3-7) `status` 4값 전수 단언 테스트 1건(타입은 §10 열린 문자열 계약이라 `String` 유지). (3-8) `exit_code_matrix.rs`에 doctor `Succeeds(0)` row 1줄.
⑨ **기각 승인** — "ACL code 재타이핑 미강제"는 기각 타당(그 변이는 값 무변경 no-op이고 `acl_diagnostic_codes_are_…_verbatim`이 실제 drift는 잡는다). "controller/extra-host 중복이 precedence 계약 위반"의 P2→P3 강등도 타당(CLI.md 문면이 "한 probe"로 한정).
⑩ **검증 방법 승계** — fixer는 각 수정을 **mutation으로 self-verify**(해당 속성을 깨보고 새 테스트가 FAIL하는지 — 특히 MA/MB/MC/MD 4건은 수정 후 CAUGHT로 바뀌어야 한다) + 게이트 5종 재실행 + windows-gnu 크로스 체크. tree는 baseline(`0282927c…`) 위 증분만.

**(a)-추기 — Step 6 수정 라운드 마감 (2026-09-01, main 세션).** 지시 13건 전건 이행, 신규 테스트 20건. 게이트 5종 green(**nextest 1325 passed / 2 skipped**, main 세션 직접 실행) + windows-gnu 크로스 체크 2종 무경고. 프로덕션 로직 변경은 3곳뿐: `clock_skew_finding` 초 단위 비교(P3-1), `doctor_connectivity_findings`의 controller 중복 probe 생략(P3-4), `print_doctor`의 줄 단위 sanitize(P3-6). 공개 시그니처·wire 타입·fixture는 무변경(fixture는 HEAD와 byte-identical 확인, MCP tool 0).
**fixer rebuttal 2건 수용.** (1) **P2-2/P2-4의 "자유함수 분리" 지시는 불충분했다** — 자유함수도 그 단위테스트도 `Ops::doctor`를 부르지 않아 **배선 라인 삭제(MA/MB)를 볼 수 없고**, 실기계의 keystore·`$PATH`는 실패 상태로 강제할 수 없다. fixer가 대신 `DoctorEnvironment{keystore, current_exe, path_dirs}` + private `Ops::doctor_assemble(...)` DI 시임을 넣어 스텁이 **실제 조립 경로**를 타게 했다 — `Ops::doctor(req, now)` 공개 시그니처는 그대로. 이 판단이 지시보다 옳다. (2) **P2-3의 첫 테스트도 불충분했다** — leaf·CA가 **둘 다** 만료된 시각을 주면 MD(CA 분기가 몰래 leaf 바이트를 재검사)가 여전히 통과한다. fixer가 self-verify로 스스로 잡아 "leaf만 만료, CA는 유효" 시각의 좁은 테스트를 추가했고 그것이 MD를 잡는다.
**P2-5 처분 확정.** 나머지 7종은 CLI.md가 표에서 **패러프레이즈만** 하므로 verbatim 단언은 드리프트가 아니라 정확한 산문을 깨뜨린다 — fixer의 판단을 수용하고 문면 verbatim은 2종(`TRUST_REMOVE_SCOPE`·`CERT_EXPIRING_SOON`)에 한정. 대신 **main 세션이 개인 리뷰에서 code 어휘 게이트를 보강**: `cli_md_names_every_frozen_doctor_code`(`EXPECTED_DOCTOR_CODES` 13종이 전부 CLI.md에 이름으로 등장) — 잠긴 §4.1 #5 계약의 본체는 산문이 아니라 **code**이므로 14번째 code를 문서화 없이 추가하거나 개명하면 여기서 깨진다.
**main 세션 독립 변이 점검 3건 전건 CAUGHT**(fixer 보고를 그대로 믿지 않고 직접 재현): ① `EXPECTED_DOCTOR_CODES`의 `clock_skew`→`clock_skew_detected` → 새 문서 게이트 EXIT=101(`missing: ["clock_skew_detected"]`). ② P3-1 수정 원복(`skew_minutes > CERT_BACKDATE_MINUTES`) → 301초 테스트 EXIT=101, 실제로 `status:"warn"` 재현(나머지 경계 3건은 그대로 통과 — 그 테스트만이 속성을 진다). ③ MA(keystore 배선 `findings.extend`→`let _ =`) → EXIT=101. 3건 모두 exact-inverse 원복 후 재확인.
**개인 리뷰(프로덕션 3곳 정독)**: DI 시임은 실환경을 **가장자리에서 한 번 읽어 데이터로 내려주는** 형태라 `now` 주입 선례와 동형이고 `DoctorEnvironment`/`doctor_assemble` 둘 다 private; dedup은 `resolve_peer_address`를 **먼저** 부르므로 오타의 loud-fail(HOST_NOT_FOUND)을 보존한 채 이름·해석주소 이중 매칭으로만 생략하고, 남는 code가 더 구체적인 `controller_unreachable`이라 잠긴 precedence와 일치; 렌더는 줄을 나눈 뒤 **각 줄에** `sanitize`를 적용해 escape-injection 방어가 유지된다(remedy는 전 항목 단일 줄임을 확인). Step 6 종료.

### Step 7 — M6 이월 부채 정리 4건 (7-1 잠금 / 7-2 런타임·enum·tool 결정)

**(a) 범위:** ① **`Ops::session_read` per-call 런타임+QUIC 구조 결정** — M6 판정 ⑤(방치 pull당 ~11 threads·5 fd·0.86MB ≤60s, 400건 → 4,412 threads/372MB)의 원인. 공유 런타임 vs bounded pull executor 중 구조를 결정하고(4.1 #6) 동일 측정으로 전후 비교. ② `action_of` op 키 enum화(M5 P2-3 이월). ③ `acl_check`의 13번째 MCP tool 노출 **결정**(§8.2 표 additive 개정 선행 — 채택이든 명시 기각이든 이 절에 추기; 조용히 추가하지 않는다).

**(d) 완료 판정:** ①은 측정 전후표 + 기존 conformance 전건 green(계약 무변경), ②는 컴파일 타임 전수성(match) 확보, ③은 결정 기록 + (채택 시) fixture 개정 diff 리뷰.

**(a)-추기 — Step 7 설계 게이트 확정 + 범위 3건→4건 확장 (2026-09-01, main 세션).** opus 설계 조사(브리프 `$SP/m7s7-brief.md`)가 M6 수치를 자체 하네스로 재현하고 A/B를 실측했다. **Step 7을 두 커밋으로 쪼갠다**: **7-1 동시성/잠금 부채**(아래 ④ — 가장 위험하고 가장 싸다), **7-2 런타임 구조 + enum + tool 결정**(①②③).

**④ 범위 편입 확정 — 이월 잠금 부채 4건은 Step 7의 정식 범위다.** 지금까지 L39·L66·L69·L83·L84에 기록만 되고 (a) 범위 L122에는 들어가 있지 않아 서로를 참조하지 않는 상태였다. 조사가 위험도를 두 단계 올렸다.
**S3/S4 (파일 파손) — main 세션이 직접 재확인했다.** `write_private_file_io`의 temp가 `.tmp{pid}`라 **writer 스코프가 아니다**(config.rs:288-290). `serve`는 연결마다 `tokio::spawn`하고(server/mod.rs:1866) pairing 응답자가 그 안에서 trust.toml을 load→mutate→save 한다(server/mod.rs:2067). 한 프로세스 안의 동시 pairing 2건이 **같은 temp 경로**를 truncate/write하므로 결과는 lost update가 아니라 **깨진 TOML = trust store 전체 벽돌**. 결정적 근거: **리포가 이 함정을 이미 알고 한 번 고쳤다** — `resume.rs:464-472`가 `AtomicU64` ticket을 붙이며 *"a temp name two of them could share would be the one way this corrupts a file rather than losing an update, and that is a much worse failure"*라고 적어뒀는데 **그 수정이 `write_private_file_io`에는 오지 않았다**. 같은 코드베이스가 같은 실패를 두 번 만난 것이고, 두 번째는 신뢰 저장소다.
**S1 (조용한 핀 부활) — 프레임 정정 수용.** 기존 기록은 전부 "동시 CLI 두 개"였는데 실제 상시 writer는 **상주 `qsh serve`**다. pairing 진행 중 `qsh trust remove`를 하면 철회한 핀이 되살아나고, 운영자는 `removed:true`를 봤고 파일은 멀쩡한 TOML이며 진단이 0건이다 — **fail-closed 원칙에 정면으로 어긋나는 조용한 권한 복구**라 P2가 아니라 P1급으로 취급한다.
**처분(순서 고정).** (1) `write_private_file_io`의 temp에 writer 스코프 ticket 부착 — **한 줄로 파손이 사라진다. 나머지를 다 미뤄도 이것만은 반드시.** (2) `FileLock`(resume.rs:508-548, `std::fs::File::lock` = flock/LockFileEx, **신규 의존 0·플랫폼 분기 0**)을 `crate::config`로 승격하고 trust.toml RMW 5개 사이트(ops/mod.rs:436,461,575 · cert.rs:105 · server/mod.rs:2067)와 `InviteStore::save`가 **load→mutate→save 전체**를 임계구역으로 감싸게(save만 감싸면 lost update가 남는다). `ca::init`의 key+cert 두 쓰기도 한 임계구역으로 묶어 Step 5 P3-4를 함께 닫는다. **잠금 순서를 문서화할 것: 항상 RwLock→FileLock** — `redeem`이 이미 `cache.write()` 안에서 블로킹 I/O를 한다(pairing.rs:521-547). (3) 회귀 2건은 선례 `resume.rs:766`(`concurrent_writers_do_not_lose_each_others_entries`)의 형태를 그대로 쓴다. `identity::init`의 동일 패턴은 Step 5 판정대로 범위 밖으로 두되 (1)이 `write_private_file_io` 자체를 고치므로 **단일 파일의 바이트 파손에 한해** 부수적으로 안전해진다 — `device.pem`↔`identity.toml` cross-file 불일치는 그대로 남는다(검증 라운드 A3 정정).

**① 4.1 #6 확정 — (A) Ops 공유 런타임 채택.** 원인은 pull 1건당 런타임 2개(ops/host.rs:550 current_thread + ops/session.rs:1058 multi_thread) + 전용 quinn Endpoint + UDP 소켓, `worker_threads` 미지정이라 `num_cpus`+blocking 1 = 11 스레드. 60s는 QUIC idle timeout이 아니라 **호스트측 long-poll clamp** `SESSION_READ_MAX_WAIT`(server/mod.rs:149)다. 취소가 회수 못 하는 건 MCP가 동기 `Ops`를 `spawn_blocking`으로 감싸는데(mcp/mod.rs:316-321) abort 불가이고 `Connected::run`의 `block_on`(session.rs:3544)에 인터럽트 훅이 없어서다. 조사가 40건 in-flight로 재현: per-pull 11.05 threads/5.00 fds/~1.16MB(M6 기록과 일치), 취소 3초 뒤 **1바이트도 회수 안 됨**, 65초 뒤 완전 회수. **A/B 실측: 공유 런타임 61 threads(per-pull 1.00) vs 현행 461(per-pull 11.00) = 11× 감소**, 32개 `spawn_blocking`이 하나의 `Arc<Runtime>`에 동시 `block_on`(내부에서 다시 `spawn_blocking`)해도 정상 — **재진입 위험 배제 확인**. 계약·arch·동기 시그니처 영향 0(바뀌는 건 `Connected`의 private 필드 타입뿐). 런타임 종료의 강제 abort에 기대는 코드가 0건임을 전수 확인(attach는 `stop` drop, 터널은 local.rs:482/remote.rs:731의 `impl Drop`). **소유는 `Ops`의 `Arc<OnceLock<Runtime>>`, lazy 필수**(안 그러면 `qsh version`도 10 스레드를 문다). **전역 `static` 기각**(테스트 격리 파괴), **MCP 서버 런타임 재사용 기각**(blocking pool 공유 시 ~256건 데드락).
**(B) bounded executor는 지금 하지 않는다.** 원인이 "건수 무제한"이 아니라 "단가 11배"다. `RESOURCE_EXHAUSTED`는 이미 정의된 코드지만(error.rs:65, CLI.md:180) §6.4 문서 개정이 선행돼야 하고 상한 숫자의 자연스러운 자리는 M8 적대적 부하 하네스(ROADMAP.md:112)다. **단 새 관찰 1건을 M8 입력으로 명시 이관: fd가 pull당 선형 증가해 400건이면 2,000 fd로 기본 `ulimit -n`(256)을 스레드보다 먼저 터뜨린다** — M6 기록에 fd 총량이 없었다. 연결 재사용(옵션 C)은 P1 재기록.
**측정**: 리포에 하네스가 없다(`docs/campaigns/`는 m2/m6, `scripts/`는 mobility뿐). 조사가 만든 `$SP/lab/mcp_load.py`를 전후 비교의 동일 측정으로 쓴다. 스레드 수는 코어수 의존이라 CI 게이트로 부적합 — 기계 게이트를 심으면 fd 기준으로, `reverse_e2e.rs:171-215`의 `lsof`//proc 이중 경로를 재사용.


**② `action_of` enum화 채택, 범위 엄격 한정.** 조사의 정정을 수용한다: **op 키 문자열과 `Action` 문자열은 다른 축이다.** `acl.toml`의 `allow` 어휘는 `Action::as_str()` 11종뿐이고(acl/load.rs:594-614) `session.write`/`resize`/`close`/`get`/`read`/`forward.remote.close`는 정책 파일 문법에 아예 없다(더 거친 Action으로 접힘). 정책 파일 쪽 enum화는 M5에 끝나 있고 **남는 문자열은 `action_of`의 내부 조회 키뿐 → wire/JSON/정책파일 계약 영향 0.** fail-closed도 사정권 밖이다 — 알 수 없는 action은 `parse_rule`이 파일 전체를 `Invalid`로 만들고(load.rs:546, 부분 로드 없음) `load_or_deny`가 `DenyAll`로 접는다(load.rs:343-365). 프로덕션 호출부는 server/mod.rs 13곳 + reverse/admit.rs 3곳뿐이고 **전부 `'static` 리터럴**(동적으로 보이던 server/mod.rs:4397/4425-4436은 둘 다 `#[cfg(test)]`) → **`FromStr` 불필요**, `as_str()`은 문서 대조·audit 렌더링 경계에만. **진짜 작업량은 게이트 재작성**이다: `tests/acl_registry.rs`의 source_scan 2건이 `action_of("...")` **소스 텍스트를 문자열 매칭**하므로(:1169, :1193-1213) 둘 다 깨진다 — 소스 스캔을 `Op::spec()` match 전수성으로 **대체**하고, `#[should_panic]` `action_of_panics_on_an_unregistered_name`은 그 자리를 match가 대신하므로 삭제한다. `DENY_SEAMS` 14행 vs `OP_REGISTRY` 13행(내부 전용 `session.attach@data-stream`)의 개수 차는 설계에 명시적으로 반영.

**③ `acl_check` 13번째 MCP tool — 명시 기각(조용한 미추가가 아니라 기록된 결정).** 기각의 본체는 정보 노출이 아니라 **정확성**이다: `acl.check`는 **호출자 로컬**의 `acl.toml`을 본다(ops/acl.rs:89). 에이전트가 알고 싶은 건 "저 host가 나를 허용하나"인데 클라이언트에 `acl.toml`이 없는 정상 배치에서 답은 `policy.loaded:false` + 무조건 `"deny"`(CLI.md:843)다 — **에이전트가 이걸 "못 한다"로 오독한다.** 게다가 에이전트는 자기 principal을 알 방법이 tool 표면에 없다(`get_host`의 `device_id`는 *peer* 신원이다). 틀린 답을 주는 tool은 열거 오라클 논쟁 이전에 탈락이다. 보조 근거로 `principal`이 자유 문자열이라 임의 principal 조회 오라클이 되고(types.rs:877) `AclPolicyRef`가 acl.toml 절대경로와 행 개수를 노출한다 — M5가 원격 노출을 금지한 이유와 같은 방향(acl.rs:1-6).
**함께 확정: §8.4에 tool 포함 기준을 additive로 신설한다.** §8 어디에도 포함/제외 기준이 없어서 §2.5의 "인가 불요" 행에 `host.list`/`host.get`과 `acl.check`가 나란한데 앞의 둘만 tool인 상태가 설명되지 않는다. 문면: **"원격 host에 대해 do/observe 하는 op만 tool로 낸다. 로컬 config를 읽거나 쓰는 op(`identity.init`·`trust.*`·`cert.*`·`schema.get`·`capabilities.get`·`version.get`·`doctor.run`·`acl.check`)은 tool이 아니다."** 이 한 줄이 Step 5의 D-6, Step 6의 "신규 tool 0", 이번 기각을 **하나의 규칙**으로 설명한다 — tool 개수는 12로 유지(`tools_list.json` 무변경).

**(a)-추기 — Step 7-1 검증 라운드 판정 (2026-09-01, main 세션).** 구현 증분 9파일 +450/-78(전부 qsh-core), 신규 회귀 4건, 게이트 5종 green(**nextest 1329 passed / 2 skipped**) + windows-gnu 2종. 검증은 Workflow 8 에이전트(6차원 병렬 분석 → 직렬 변이 실증 → opus 판정), 발견 19건. **P1 0 / P2 2 / P3 5 — 커밋 가능.**
**원래 목적 달성 여부.** **S3 파손 차단은 판정자가 리포 밖 standalone 대조로 실증했다**: 24 writer × 40 라운드에서 ticket 없으면 8/40 라운드가 최종 파일이 **어느 writer와도 불일치**(바이트 인터리브), ticket 있으면 **0/40**. S1/S2(lost update·핀 부활)는 **메커니즘은 달성**(잠금 8곳 전부 `load` 이전 획득 → `save` 이후 유지, 코드 판독 확인) **방어선은 미달**(아래 A2).
**판정자가 자기 분석 단계를 기각한 것을 승인한다.** 3개 차원이 "이 diff가 `cargo test`를 red로 만든다"며 P1을 주장했는데, 판정자가 `git stash`로 베이스라인을 재서 **diff 이전에 이미 2~3건 실패**(acl::load, localctl::daemon)임을 반증했다. `ci.yml:92-93`은 *"nextest: one process per test — required for the PTY/process tests"* 주석과 함께 nextest 전용이다. 데드락 가설도 전부 기각 — `FileLock`과 중첩되는 in-process 락은 `SharedInviteStore.cache` 하나뿐이고 두 지점 모두 RwLock을 선취하므로 순환 구성이 불가능하다. `lock_path_for` 중복(audit/writer.rs)도 다른 디렉터리·다른 베이스명이라 충돌 불가로 기각.
① **A1 (P2) 수용 — 거짓 주석 정정.** `config.rs`의 전역 `WRITE_TICKET` 자체는 문제가 아니지만 `ca.rs:429-430`과 `identity/mod.rs:623`이 *"nothing else in this test touches that counter first … not raced against it"*라고 **단언**하는데 스레드 병렬에서 거짓이다(판정자가 `cargo test`로 `ca.rs:447` 3/3 FAIL 직접 재현). 거짓 주석은 다음 사람을 함정에 빠뜨린다. 수정: 두 주석 + `config.rs:290-296`에 "프로세스 격리(nextest) 하에서만 유효" caveat.
② **A2 (P2) 수용 — 잠금 배선 8곳 전건 미검증.** 변이 6/6 GREEN(724/724 통과): **어느 잠금 라인을 지워도 스위트가 통과한다.** 신규 테스트 4건은 `TrustStore::lock`/`InviteStore::lock`을 테스트 스레드에서 **직접** 부를 뿐(trust/mod.rs:951,1003,1013 · pairing.rs:984) `Ops`·server·`ca::init`를 거치지 않는다. 정상 참작: trust/mod.rs:978-981이 한계를 스스로 적어뒀다 — 숨겨진 공백이 아니라 공개된 공백이다. 수정: `ops/mod.rs`에 8스레드 `Ops::trust_add` 동시성 테스트 1건(M1/M2 변이가 CAUGHT로 뒤집혀야 한다).
③ **A5 (P3, 판정자 신규 발견) 수용 — 가장 중요한 테스트의 검출력이 0.2다.** 파손 회귀(`trust/mod.rs:1051`)는 파손 발생률이 8/40이라 **ticket을 되돌려도 5회 중 4회 GREEN**이다. 커밋 근거가 이 테스트에 걸려 있으므로 그대로 둘 수 없다. 수정: `for _round in 0..16` 루프로 감싸 검출력 ≈97%.
④ **A3 (P3) 수용 — 문구만.** PLAN L131의 "부수적으로 안전해진다"는 과장이다. ticket은 **단일 파일의 바이트 파손**만 막고 `device.pem`↔`identity.toml` cross-file 불일치는 못 막는다. **코드 수정은 기각**(L81·L84가 명시 이월, acceptance criteria 초과) — 문구를 "단일 파일 파손에 한해"로 정정한다.
⑤ **A4 (P3) 수용 — 문구만.** `pairing.rs:542,548`의 accept/consume 판정과 pinning 부작용이 `:560`의 FileLock **이전**에 실행되므로 cross-process 이중 redeem 창이 남는다. diff 이전엔 잠금이 아예 없었으니 회귀는 아니다. `pairing.rs:197-198`의 *"closing F-9's residual window rather than only narrowing it"*는 거짓이므로 "좁힌다"로 정정.
⑥ **A6 (P3) 인지만.** rename 전 실패 시 `.tmp{pid}-{N}` orphan이 누적되고 스윕이 없다. 오작동은 없다(설정 로더·doctor·trust list 모두 영향 없음 확인). M8 입력으로 기록.
⑦ **판정자 부수 발견 — `cargo test`가 baseline부터 red다**(acl::load, localctl::daemon). CI는 nextest 전용이라 CI 영향은 없지만 **`CLAUDE.md`가 `cargo test`를 첫 번째 명령으로 적어둔다** — 그대로 따르는 사람은 트리가 깨진 줄 안다. 이 라운드 범위 밖이므로 **Step 8(문서 마감)의 항목으로 등재**: nextest를 preferred가 아니라 **required**로 문면 정정 + `docs/design/testing.md` 반영.
⑧ **검증 방법 승계.** fixer는 수정 후 **M1/M2(ops/mod.rs:441,468 잠금 삭제)가 GREEN→CAUGHT**로, **M3(config.rs:309의 `-{ticket}` 제거)이 5/5 FAIL**로 뒤집히는 것을 변이로 실증할 것. 게이트 기준선은 `cargo nextest run --workspace` = 1329 passed/2 skipped + clippy/fmt/arch clean이며 **`cargo test`는 baseline부터 red이므로 게이트로 쓰지 않는다**. tree는 baseline(`98d0584a…`) 위 증분만.

**(a)-추기 — Step 7-1 수정 라운드 마감 (2026-09-01, main 세션).** 4건 전건 이행, **프로덕션 로직 변경 0건**(전부 테스트·주석). 게이트 5종 green(**nextest 1331 passed / 2 skipped** — 기준선 1329 + 신규 2건 정확히 일치, main 세션 직접 실행) + windows-gnu 2종 무경고. fixture·`Cargo.toml`·proto·cli 전부 HEAD와 무변경(직접 확인).
A2는 `Ops::trust_add`/`trust_remove`를 8스레드로 동시 구동하는 테스트 2건으로 닫았다 — 잠금 프리미티브가 아니라 **실제 호출부**를 지난다. A5는 파손 회귀를 16라운드로 감쌌고 writer 24를 유지해도 10/10이 1.6~2.0초에 통과해 트레이드오프가 필요 없었다.
**main 세션 독립 변이 2건 전건 CAUGHT**(fixer 보고를 그대로 믿지 않고 재현): M1(`ops/mod.rs:441` 잠금 삭제) → EXIT=101 `a concurrent Ops::trust_add lost a peer`; M3(`config.rs`의 `-{ticket}` 제거) → **3/3 EXIT=101**, 전부 round 0에서 즉시 실패(rename ENOENT 경쟁). 검출력 0.2가 사실상 결정론으로 바뀐 것을 실측으로 확인했다. 둘 다 exact-inverse 원복 후 재확인.
**개인 리뷰**: 정정된 주석 2곳이 정직하다 — `config.rs`는 ticket 예측이 "프로세스 격리 러너 하에서만 성립"함을 CI 파일까지 인용해 적고, `pairing.rs`는 남는 창이 무엇인지(accept/consume 판정과 pinning 부작용이 잠금 **이전**) 명시하면서 **한 프로세스 안에서는 cache RwLock이 그 판정을 완전 직렬화한다**는 실제 배치의 사실도 함께 적는다 — 과소·과대 주장 어느 쪽도 아니다. 영어 주석 안의 한국어 PLAN 절 인용은 M6 선례가 이미 다수라 리포 관행과 일관. **Step 7-1 종료.**

**(a)-추기 — Step 7-2 ③ 착지: 위치를 §8.4 아닌 §8.2로 정정 (2026-09-01, main 세션).** 설계 게이트(위 ③·L141)는 tool 포함 기준을 §8.4(보안)에 신설한다고 했으나 **§8.2(Tool mapping)에 넣었다.** §8.4는 MCP 표면이 무엇을 노출해도 되는지를 다루는 절이고, "어떤 op이 tool이 되는가"는 tool 목록 표 바로 아래에 있어야 다음 사람이 표를 고치려 할 때 읽는다. 기각 근거 문단도 같은 자리에 붙였다.

기준 문면을 게이트 초안보다 **좁혔다**: 초안은 "로컬 config를 읽거나 쓰는 op은 tool이 아니다"로 8개를 한 부류로 묶었는데, `capabilities.get`은 host 인자를 주면 실제로 그 peer와 negotiation한 결과를 답한다(§6.10) — 초안 기준의 **반례**다. 그래서 제외를 두 부류로 갈랐다: ① 로컬 상태 op(`identity.init`·`trust.*`·`cert.*`·`doctor.run`·`acl.check`), ② wire contract introspection(`schema.get`·`capabilities.get`·`version.get`) — 후자가 답하는 것은 host의 상태가 아니라 두 build 사이의 protocol 합의이고, 에이전트는 그 합의를 이미 tool schema로 받아 들고 있다. 규칙에 설명되지 않는 예외를 남기지 않기 위한 정정이며, 결론(tool 12개 유지, `tools_list.json` 무변경)은 게이트와 동일하다.

**(a)-추기 — Step 7-2 ② 설계 게이트: `Op` enum을 유일 표로, `OP_REGISTRY`는 그 투영 (2026-09-01, main 세션).** ②의 결함은 `acl::action_of(op: &str)`(registry.rs:389)가 문자열 선형 탐색 + 런타임 panic이라 **`action_of("sesion.open")` 오타가 컴파일된다**는 것이다 — 그것도 인가 choke point 위에서. 지금 이를 막는 것은 컴파일러가 아니라 `tests/acl_registry.rs`의 **소스 텍스트 매칭 게이트 2건**(`server/mod.rs`를 문자열로 읽어 `Action::` 리터럴을 세고 `action_of("forward.local")` 문자열의 존재를 본다)이다. grep하는 테스트는 리팩터가 줄을 옮기면 무증상으로 무력해지므로 대용품이지 검사가 아니다.

**설계 제약은 "표 두 벌 금지"**(`OpSpec` 자체 doc, M5 Step 8)다 — enum과 `OP_REGISTRY`가 같은 (op, action, resource_kind, owned) 사실을 두 번 적으면 그 규율 위반이고, 순진한 enum화는 정확히 그 함정에 빠진다. 그래서 **match를 유일한 표로 삼는다**: `Op::spec(self) -> OpSpec`을 `const fn` + 전수 `match`로 쓰고, `OP_REGISTRY`는 `&[Op::SessionOpen.spec(), …]` 즉 **그 match의 투영**으로 만든다. variant 추가 시 컴파일 에러가 나는 지점이 표 그 자체가 된다. 이 형태(`const fn`·`match`·const 컨텍스트 호출 `const A: Action = Op::SessionOpen.action();`)는 main 세션이 standalone `rustc`로 직접 컴파일해 stable Rust에서 성립함을 확인했다 — 구현자에게 미검증 설계를 넘기지 않는다.

**소스 텍스트 게이트 2건은 유지**하고 새 문법에 맞게 갱신만 한다. enum화해도 핸들러가 `Action::SessionControl`을 직접 박는 실수는 여전히 가능하므로 `action_variant_literals_are_pinned_to_the_one_documented_exception`은 죽지 않았다 — 컴파일러가 덮는 범위(오타·미등록 이름)와 이 게이트가 덮는 범위(등록표 우회)가 다르다. 반대로 `action_of_panics_on_an_unregistered_name`은 **삭제**한다: "등록되지 않은 이름"이라는 상태가 타입에서 사라지는 것이 이 작업의 목적이므로 그 테스트는 표현 불가능해진다. nextest 수가 그 1건만큼 줄어드는 것이 정상 — 그 외 증감은 원인 보고 대상이다.

**(a)-추기 — Step 7-2 ① 구현 착지 + 측정 전후표 (2026-09-01, main 세션).** 공유 런타임 구현 완료(`ops/mod.rs` +194, `ops/session.rs` +85/-47, 둘 다 qsh-core 내부). 게이트 5종 green(**nextest 1334 passed / 2 skipped** = 기준선 1331 + 신규 3건 정확 일치) + windows-gnu 2종.

**측정(N=40 in-flight `read_session`, 동일 하네스 `$SP/lab/mcp_load.py`, before는 `eb784cc` 격리 worktree 별도 빌드):**

| 지표 | 전 | 후 |
|---|---:|---:|
| pull당 threads | 11.03 | **1.00**(순증분) / 1.25(naive) |
| pull당 fds | 5.00 | 1.10 |
| pull당 RSS | 1,074 KB | 638 KB |
| 3초 후 취소 회수 | 없음 | 없음(전후 동일 — 이 축은 이번 스텝 범위 밖) |
| 65초 clamp 후 | 완전 회수 12/9 | **부분 22/13** |

naive 1.25가 예측 1.00보다 큰 것은 baseline 12스레드가 **공유 런타임 생성 이전** 값이라 델타 50에 1회성 부트스트랩(≈10)이 섞였기 때문 — `(50−10)/40 = 1.00`으로 rtprobe A/B 예측과 정확히 일치하고 N이 클수록 0으로 수렴한다(400건이면 0.975). 구현자가 이 분해를 스스로 적어 naive 수치를 성과로 포장하지 않은 것을 승인한다.

**부수 비용을 정직하게 기록한다**: 65초 clamp 후 완전 회수가 사라졌다(22/13, baseline 12/9 대비 +10/+4). 공유 런타임은 `Ops`가 사는 한 프로세스 수명 내내 산다 — 상시 상주 10워커를 지불하고 pull당 11배 곱셈을 없앤 것이며, 설계 게이트가 이미 인지한 대칭 트레이드오프다. **fd는 여전히 pull당 선형(1.10)** — 공유 런타임은 스레드만 줄이고 QUIC Endpoint/UDP 소켓은 pull마다 새로 연다. M8 이월(L134) 그대로이고 표에 숨기지 않았다.

**구현자가 브리프 밖 실버그를 하나 잡았다 — 승인.** 첫 구현(`Arc<Runtime>` 직접)은 `qsh-testkit::reverse_attach detaching_leaves_the_session_running_…`을 *"Cannot drop a runtime in a context where blocking is not allowed"*로 깼다. 원인: 공유·참조계수 런타임의 **마지막 `Arc`가 어디서 drop될지 통제 불가**인데 `qsh-testkit` fixture는 `#[tokio::test]` 안에서 `Ops`를 만들고 그 async 함수 안에서 drop한다. 기존 불변식("`connect_target`은 sync, 러닝 런타임 안에서 호출되지 않는다")은 **build+block_on에 대한 보장이지 drop에 대한 보장이 아니었다** — 공유화가 이 구분을 처음으로 load-bearing하게 만들었다. 수정은 `SharedRuntime` 래퍼로 `Drop`을 `shutdown_background()`(tokio가 "다른 런타임 안에서 drop"의 공식 해법으로 문서화)에 라우팅. 한 호출부 특례가 아니라 타입 차원 해결이라 옳다.

**main 세션 개인 리뷰 2건.** ① `shutdown_timeout(CLOSE_DRAIN)` 4곳 제거가 QUIC close 드레인을 없앤 것 아닌지 직접 확인 — 아니다. 드레인은 `close()`의 `endpoint.wait_idle().await`가 지고 그건 무변경이며, `shutdown_timeout`은 런타임 잔여 태스크용이었다. 다만 `Drop for Connected`(panic/early-return 경로)는 이제 close 프레임 플러시를 전혀 기다리지 않으므로 **검증 라운드 질문으로 승계**. ② double-checked init에서 경쟁에 진 스레드의 런타임이 bare `Runtime`으로 drop되면 §2 버그가 그대로 재현되는데, 구현은 `set()` **이전에** `SharedRuntime`으로 감싸므로 패자의 drop도 `shutdown_background()`를 탄다 — 코드 판독 확인. 이 순서가 뒤집히면 무증상 회귀이므로 검증 라운드 변이 후보로 넘긴다.

**(a)-추기 — Step 7-2 검증 라운드 판정 (2026-09-01, main 세션).** Workflow 11 에이전트(6차원 병렬 분석 → 직렬 변이 실증 4건 → opus 판정). 게이트 5종 green(nextest 1333 passed / 2 skipped, main 세션 직접 실행)이지만 **P1 1건 — 커밋 불가.** P2 2 / P3 7.

**판정자가 자기 앞 단계 4개 에이전트의 실험 설계를 기각한 것을 승인한다.** A3-5·A6-F1·E1·E3이 모두 `Op::Probe`를 **아무 데도 쓰지 않고** 추가해 "1333 green"을 얻었는데, 그것은 "죽은 코드는 테스트를 안 깬다"는 약한 명제만 증명한다. 판정자는 그 variant를 `handle_session_list`(server/mod.rs:1181-1188)의 **인가 인자로 실제 배선**한 뒤(반환 `Action` 동일 → 런타임 동작 바이트 무변경) 게이트를 돌렸고 fmt·clippy clean에 **1333 passed 전건 green**을 얻었다. 결정적인 것은 **대조군**이다: 같은 변이의 diff 이전 등가물(격리 worktree, HEAD `eb784cc`, `action_of("session.list")`→`action_of("probe")`)에서 `server::tests` **3건이 `registry.rs:393` panic으로 FAIL**한다. 회귀임이 before/after로 증명됐다. E1이 "M5부터 있던 기존 한계"라며 P2로 매긴 것은 **대조군을 안 재서** 나온 판단이므로 기각한다.

**① P1-1 수용 — 조용한 구멍 금지 규율 위반. A안(매크로 파생)으로 닫는다.** 구 `action_of`는 호출마다 `OP_REGISTRY.iter().find(...)`를 지나 **등재가 곧 동작 조건**이었는데, `Op::action()`은 `self.spec().action`만 본다. 기존 감사가 전부 자기 목록(`Op::ALL`·`OP_REGISTRY`)을 순회 시작점으로 삼아 그 목록에 없는 variant는 원천적으로 시야 밖이다. 판정자가 제시한 두 안 중 **A안(`macro_rules! declare_ops` 1회 invocation에서 enum 선언·`ALL`·`as_str`·`spec`·`OP_REGISTRY`를 전부 파생)** 을 택한다 — B안(전수 `match` witness 테스트)은 신규 variant가 테스트 컴파일을 깨서 작성자가 **알아채게** 할 뿐 `Op::ALL`에 넣도록 강제하지 못하는 과속방지턱이고, 안정 Rust에서 variant를 열거하는 유일한 by-construction 수단이 매크로다. 설계 게이트가 건 제약("match를 유일한 표로, 표 두 벌 금지")도 A안에서만 실제로 충족된다. `session.close`의 `owned: false` 예외 주석과 per-variant doc은 `#[$m:meta]`로 보존한다.

**범위 판단**: 이것은 acceptance criteria 초과가 아니다. (d)②가 요구하는 "컴파일 타임 전수성"이 미달인 상태이고, ACL choke point에서 **시끄러운 실패를 무증상으로 바꾼 회귀**는 CLAUDE.md의 "Fail closed on any ambiguous auth/ACL state"와 이 리포가 M5부터 지킨 "제외는 기록될 때만 정당하다"에 정면으로 걸린다.

**② P2-1 수용 — 거짓 주석 2곳.** `registry.rs:225-229`가 "never a second hand-maintained list … by construction"이라, `:295-302`가 "'registered nowhere' stopped being a state this type can hold"라 단언하는데 둘 다 거짓이었다(P1-1 실측이 바로 그 상태를 만들어 인가까지 시켰다). Step 7-1 A1과 같은 계열이며 대상이 ACL 표라는 점만 다르다. A안으로 고치면 두 문장은 **사실이 되므로 그대로 두고**, `Op::ALL` doc의 "establishes" 문장만 정정한다.

**③ P2-2 수용 — `Drop for Connected`의 Arc 조기 drop.** `if self.runtime.take().is_some() { … }`는 `if let`이 아니라 `if EXPR.method()`라 조건식 임시값이 **body 진입 전에** drop된다 — 이 `Connected`의 Arc가 마지막이면 `shutdown_background()`가 quinn endpoint driver를 먼저 내린 뒤에야 `connection.close()`가 호출된다. 판정자가 rustc 1.97.1 edition 2021·2024 양쪽에서 직접 재현했다. 수정은 이름 바인딩으로 drop을 `close()` 뒤로 미루고(6줄), 같은 hunk의 "never shuts the runtime itself down" **절대 표현**을 이 `Connected`의 핸들 하나만 놓는다는 사실 서술로 좁힌다.

**④ P3-2·P3-4 수용(판정자는 수정 불요라 했으나 main 세션이 채택).** 둘 다 **이 diff가 새로 도입한 doc 주장**을 뒷받침하는 3줄짜리 테스트 확장이고, P2-1이 바로 "doc가 단언하는 것을 코드가 안 지킨다"는 결함이라 같은 잣대를 적용한다: `connect_runtime_is_lazy_until_first_connect_call`에 `trust_list`·schema 계열을 추가(필드 doc가 `qsh trust list`를 이름으로 지목한다), `..._same_instance_across_calls_and_clones`에 독립된 두 번째 `Ops::new(other_paths)`로 `Arc::ptr_eq == false`를 추가(필드 doc가 `static OnceLock`을 명시 기각한 근거를 양방향으로 고정).

**⑤ P3-6 수용 — main 세션이 직접 수정한다.** 내가 쓴 §8.2 "두 부류"가 tool 아닌 op 전부를 설명하지 못한다: `tunnel.list`는 tool이 아닌데 같은 §2.5 행의 `tunnel.close`(=`close_tunnel`)는 tool이고, `session.attach`는 어느 부류에도 안 들어간다. 규칙에 설명되지 않는 예외를 남기지 않겠다며 쓴 문단이 정확히 그 결함을 갖고 있었다. 한 줄 추가로 닫는다(결론 불변, fixture 무영향).

**⑥ P3-1 — Q1 미측정으로 명시.** 코드로 확정된 것: MCP 서버 런타임(`qsh-cli/src/main.rs:1073`)과 공유 dial 런타임(`ops/mod.rs:357`)은 별개 인스턴스라 필드 doc가 경고한 "같은 pool을 두 번 요구" 조건이 성립하지 않고, 워크스페이스에 `max_blocking_threads` 오버라이드 0건이며, 60초 long-poll을 무는 것은 MCP pool 스레드이고 공유 pool에서 잡는 건 ms 단위 `lookup_host`다. 하드 데드락 가능성은 구조적으로 낮아 커밋을 막지 않는다. **다만 추론이므로 main 세션이 수정 라운드 후 커밋 전에 N=256·512를 직접 실측한다** — ①의 존재 이유가 부하 특성이므로 부하 질문 하나를 미측정으로 남기고 닫지 않는다.

**⑦ P3-7 Step 8 이월** — `docs/CLI.md` §2.4 operation 목록에 `cert.init`/`cert.issue`가 없다(§6.16은 정식 dotted op으로 문서화). 이 diff 이전부터의 gap이라 여기서 고치지 않고 Step 8(문서 마감) 항목으로 등재한다.

**⑧ 기각 승인 (R-1) — 그리고 그것은 내 절차 결함이다.** A3-6·A5-1이 "워킹 트리 오염"을 P1으로 올렸으나 diff 결함이 아니라 **검증 프로세스 결함**이므로 기각한다. 원인은 내가 A4(완전성 **분석**) 프롬프트에 "실행하지 마라"라고 적으면서 결정적 실험 절차를 함께 넣어둔 것이고, A4가 그대로 실행해 A3·A5·A6이 같은 트리를 읽는 동안 변이가 살아 있었다. 결과는 전부 원복돼 무해했고 최종 sha는 baseline과 일치(총 4회 확인)하지만, 규율을 깬 것은 orchestrator다. 이후 라운드는 변이 차원을 직렬화하거나 차원별 worktree로 격리한다.

**⑨ 검증 방법 승계.** fixer는 P1-1 수정 후 **판정자의 변이를 그대로 재적용**해 A안이면 "표현 불가"(컴파일 에러)임을 실증할 것: `Op::Probe` variant + `spec`/`as_str` arm 추가 + `handle_session_list`의 인가 인자를 `Op::Probe.action()`으로 치환. 게이트 기준선은 nextest **1333 passed / 2 skipped**이며 `cargo test`는 baseline부터 red이므로 게이트로 쓰지 않는다. tree는 baseline(`427a1248…`) 위 증분만.

**(a)-추기 — Step 7-2 수정 라운드 마감 (2026-09-01, main 세션).** 판정 ①~④를 fixer가 이행했고, 그 뒤 fixer가 변이 3(V3) 실행 중 멈춰 **main 세션이 인계받아 마무리**했다. 게이트 6종 green, 트리 sha `03a2f3e3…`.

**P1-1은 두 방향 모두에서 닫혔다.** fixer가 판정자의 변이를 재적용해 실증한 것: (a) `Op::Probe`를 `declare_ops!` invocation 밖에서 참조하면 `error[E0599] no variant … named 'Probe'`로 **컴파일 자체가 안 된다** — variant가 태어나는 곳이 invocation 한 군데뿐이라 "등재 없이 존재"가 표현 불가능한 상태가 됐다. (b) invocation 안에 합법적으로 넣으면 컴파일은 되지만 `op_registry_matches_deny_seams_by_name_and_action`이 즉시 FAIL한다 — `DENY_SEAMS`에 짝이 없기 때문. 이 (b)는 브리프가 요구하지 않은 보충 실험인데, "A안이 새 우회로를 열지 않는다"를 확인해 준다는 점에서 (a)보다 값이 크다.

**main 세션 독립 검증 3건 — fixer 보고를 액면가로 받지 않았다.**

① **호출부 재작성이 충실한가**(기계 대조). HEAD의 `action_of("x")` 20곳과 현재 `Op::X.action()` 20곳이 **같은 줄 번호·같은 순서·같은 op 이름**임을 registry의 variant→dotted name 사상으로 대조해 확인했다. `git grep`이 22건을 세는 것은 `:693` doc과 `:3022` 주석이 예시로 그 형태를 적기 때문이고, 실제 호출부는 20곳이다. `:3029`의 리터럴 `Action::SessionAttach`(문서화된 유일 예외)는 diff에 없다 — 보존됐다.

② **`OpSpec::op`의 `&'static str` → `Op` 타입 변경이 계약 표면에 닿는가.** 닿지 않는다. `registry.rs` 어디에도 serde derive가 없고, `qsh-cli`는 `OP_REGISTRY`를 doc 주석으로만 언급하며(`mcp/mod.rs:35`), 모든 소비처가 `spec.op.as_str()`로 문자열을 되찾는다. `qsh.cli/v1`·fixture 무영향.

③ **독립 변이 2건**(fixer·판정자가 건드리지 않은 축). **변이 A** — `SharedRuntime::drop`을 `shutdown_background()` 대신 평범한 blocking drop으로: `qsh-core`·`qsh-testkit` 두 크레이트 **11건 FAIL**, 전부 *"Cannot drop a runtime in a context where blocking is not allowed"*. 구현자가 새로 쓴 `dropping_ops_with_a_live_shared_runtime_from_inside_another_runtime_does_not_panic`이 정확히 그 패닉을 잡는다 — 새 타입이 테스트로 뒷받침된다. **변이 B** — `Drop for Connected`를 P2-2 수정 이전의 `if EXPR.take().is_some()` 형태로 되돌림: **935 passed, 검출 0건.**

**변이 B의 0건은 결함이 아니라 기록해야 할 제외다.** 그 경로가 밟히려면 `Connected`가 자기를 만든 `Ops`보다 오래 살아 마지막 `Arc`를 쥐어야 하는데, `connect_runtime`의 `OnceLock`이 `Ops` 수명 동안 `Arc` 하나를 영구 보유하므로 현재 어떤 호출자도 그 상태를 만들지 않는다. 관측 가능한 차이도 panic 경로에서 CONNECTION_CLOSE 한 프레임이 덜 나가는 것뿐이고, peer는 idle timeout으로 수렴한다. P2-2 수정은 6줄이고 옳으며 유지하되, **테스트가 아니라 추론이 근거**라는 사실을 여기 남긴다. 억지 테스트를 만들지 않는 쪽을 택한 이유는 재현에 실제 QUIC peer와 crate 내부 타입 접근이 동시에 필요해서, 얻는 것에 비해 대가가 크기 때문이다.

**⑥ Q1 실측 완료 — 커밋 전 약속 이행.** release 빌드로 `qsh mcp` 한 프로세스에 동시 `read_session` long-poll을 N=256·512·700 던지고 스레드/fd/RSS를 표본.

| N | in-flight threads | fds | threads/pull | 65초 후 회수 |
|---|---|---|---|---|
| 40 (기존) | 62 | 53 | 1.25 | 22 / 13 |
| 256 | 278 | 269 | 1.04 | 22 / 13 |
| 512 | 533 | 524 | 1.02 | 23 / 13 |
| 700 | **533** | **525** | 0.74 | 210 / 13 |

**데드락도 starvation도 없다.** 필드 doc가 경고한 조건은 성립하지 않는다 — `spawn_blocking`은 MCP 서버 런타임(`main.rs:1073`)이, `lookup_host`는 공유 dial 런타임(`ops/mod.rs:358`)이 각각 자기 pool에서 처리한다.

**대신 천장의 실제 위치가 측정됐다: 512.** N=700에서 스레드가 512와 **똑같은 533에 정체**한다 — 513번째 이후 pull은 시작조차 못 하고 tokio 기본 `max_blocking_threads = 512`가 포화된 MCP pool 뒤에 큐잉된다. 65초 회수가 22가 아닌 210인 것이 그 증거다(늦게 슬롯을 받은 188건이 그때서야 자기 wait를 돌고 있다). 클라이언트에겐 `RESOURCE_EXHAUSTED`가 아니라 **최대 한 wait 주기만큼의 조용한 지연**으로 보인다. 이 숫자는 doc의 추론을 그대로 확인해 준다 — pool을 공유하면 pull당 두 개를 요구하니 ~256, 분리하면 하나씩이라 512. 그리고 이 천장은 **이 diff가 만든 것이 아니다**: 그 `spawn_blocking`은 `qsh-cli/src/mcp/mod.rs:420`에 있고 이번 diff는 `qsh-cli`를 한 줄도 건드리지 않았다.

**M8 이월 2건 추가.** (i) 위 512 천장을 근거 숫자로 삼아 bounded pull executor + `RESOURCE_EXHAUSTED`를 설계한다(기존 이월 항목이 이제 실측 근거를 갖는다). (ii) `Ops::exec`(`ops/exec.rs:81`)는 여전히 호출마다 `new_multi_thread()`를 세운다. ①이 고친 것은 pull 경로(`connect_target`/`connect_reverse`)뿐이고 `exec`는 MCP tool 표면에 있으므로, 동시 `exec` 호출은 아직 호출당 ~11 스레드를 문다. exec는 long-poll이 아니라 노출이 훨씬 작지만 남은 사실이다. (`ops/mod.rs:654`의 pairing 런타임은 일회성 대화형이라 대상 아님.)

**게이트 6종 (main 세션 직접 실행, 전건 rc=0).** fmt / clippy `-D warnings` / **nextest 1333 passed, 2 skipped** / xtask arch / cargo deny / windows-gnu cross-check(qsh-core, qsh-cli). 변이 A·B는 exact-inverse 원복 후 sha `03a2f3e3…` 재확인으로 원복을 증명했고 트리에 마커 0건이다.

### Step 8 — man page·설치 문서 + 스톱워치 캠페인 (DoD 1) + 마감

**(a) 범위:** man page·설치 문서, README 최종 동기화. `docs/campaigns/m7-stopwatch.md` 사전 정의(M6 캠페인 선례: 기준 먼저 커밋) — 한 번도 설정한 적 없는 두 장비(신선한 sandbox 프로필 2식 또는 실장비 2대), README만 보고 `qsh user@host`까지, 독립 3회, 5분 기준. ROADMAP §4 리스크 3의 "조기·반복" — Step 4(pairing) 착륙 직후 1회 예행 측정을 먼저 수행해 병목을 마감 전에 노출한다. 이후 §5 마감 절차.

**(a)-추기 — Step 8 착지 (2026-09-01, main 세션).** 문서 5건은 sonnet 에이전트가, DoD 1 캠페인 하네스는 main 세션이 직접 만들었다. 게이트 6종 green, nextest **1334 passed / 2 skipped**(기준선 1333 + man page 대조 1건).

**man page는 생성물로 착지했다.** 손으로 쓰면 `docs/CLI.md` 명령 표의 두 번째 사본이 되므로 `clap_mangen`으로 `qsh-cli`의 실제 `clap::Command` 트리에서 뽑는다(`cargo xtask man` → `docs/man/*.1` 38장, 노드당 1장 — cargo·git이 같은 이유로 쓰는 모양). 이를 위해 `qsh-cli`에 `src/lib.rs`(`pub mod cli;`)를 신설했다. 재생성 대조 테스트(`xtask::man::tests::checked_in_man_pages_match_the_generator`)가 파일 집합과 바이트 내용 양쪽을 본다.

**lib 타깃이 아키텍처를 넓히는가 — 직접 변이로 확인했다.** 전에는 `qsh-cli`에 lib 타깃이 없어 아무도 의존할 수 **없었는데** 이제 표현 가능한 간선이 됐다. `qsh-core`에 `qsh-cli` 의존을 넣어 보니 **cargo가 순환 패키지 의존으로 거부**한다 — arch-lint가 돌기도 전에. `qsh-proto`·`qsh-transport`·`qsh-core`는 전부 `qsh-cli` 아래에 있어 되돌아오는 간선이 곧 순환이고, 순환이 아닌 경로는 매트릭스가 이미 면제하는 `qsh-testkit`과 매트릭스 밖의 `xtask` 둘뿐이다. 실효 아키텍처는 그대로다. 다만 에이전트가 그 보장을 arch-lint에 귀속시켜 놨길래, 실제로 막는 것은 cargo라는 사실로 `lib.rs`의 doc을 정정했다 — 기계가 무엇을 강제하는지 틀리게 적는 것은 이 리포가 Step 7-2에서 P2-1로 다뤘던 결함과 같은 계열이다.

**main 세션이 잡은 에이전트 산출물의 결함 3건.**

① **README의 사실 오류.** "crates.io 패키지 이름이 이미 남에게 선점됐다"고 적었는데 확인해 보니 `qsh-cli`는 **비어 있다**. 선점된 것은 바이너리와 같은 짧은 이름 `qsh`(무관한 `haukened/quicshell` v0.0.2)다. crates.io 설치가 안 되는 진짜 이유는 선점이 아니라 M9까지 `publish = false`인 것이므로 그렇게 고쳤다. 검증 가능한 사실을 검증 없이 README에 적은 사례.

② **`docs/design/testing.md` M7 문단의 사실 오류.** "Step 7-2가 소스텍스트 매칭 게이트 두 벌을 `Op::spec()` exhaustive match로 **대체**했다"고 적었으나 대체하지 않았다 — `authorize_stream_has_exactly_two_production_call_sites`와 `action_variant_literals_are_pinned_to_the_one_documented_exception`은 `tests/acl_registry.rs`에 그대로 살아 있고(:1160, :1202) 새 호출 형태에 맞춰 갱신됐을 뿐이며, 검증 라운드 E5가 검출력 보존을 실증했다. 오타 구멍을 닫는 것은 `Op` 타입 자체다. 문면을 사실대로 고쳤다.

③ 같은 문단에 U+200B 제로폭 공백 1개, 그리고 낡은 baseline 숫자(1333 → 1334). 둘 다 정정.

**man page 대조 게이트 검출력 — main 세션 독립 변이 2건.** 내용 드리프트(clap doc 주석 한 줄 수정) → `docs/man/qsh.1 is stale` FAIL. 파일 집합 드리프트(체크인된 페이지 1장 삭제) → `does not have the same *.1 file set` FAIL. 두 축 모두 잡힌다. 첫 시도는 정규식이 `about = "…"` 형태를 찾다가 매치에 실패해 **변이가 적용되지 않은 채 13 passed**를 봤다 — clap이 doc 주석에서 help를 가져오는 구조라서다. 무변이 green을 검출 실패로 오독하지 않고 다시 돌렸다.

**DoD 1 하네스 — `scripts/stopwatch/`(main 세션).** 캠페인 §3이 "loopback으로 대신하면 두 장비라는 전제가 무너진다"고 못박으므로 컨테이너 두 개를 bridge 네트워크에 띄운다. `round.sh N` 하나가 작업 트리를 빌드하고 회차마다 홈을 비우고 §3의 여섯 조건을 검사한다 — 검사에 qsh 명령을 쓰지 않아 "미리 실행하면 그게 연습"이라는 §3 항목 2의 제약을 지킨다. compose는 안 쓴다(별도 플러그인이라 daemon마다 있으리라는 보장이 없다). 하네스 자체를 한 번 검증했다: 전제 조건 전건 통과 + README "First run" 문면 그대로 실행해 클라이언트가 `dave@box:~$` 원격 프롬프트를 받는 것까지 확인. 컨테이너에는 Secret Service가 없어 keystore 파일 fallback으로 내려가므로 **컨테이너 회차는 실장비 회차보다 관대하다** — 이 비대칭을 `scripts/stopwatch/README.md`와 캠페인 §3에 적어 뒀고, 감추고 유리한 조건만 쓰지 않는다.

**부수 발견 1건(범위 밖, 기록만).** `qsh session open dave@box`는 `user@` 문법을 받지 않아 `HOST_NOT_FOUND`인데(대화형 `qsh dave@box`와 문법이 다르다 — §7), 그 에러 메시지가 `qsh trust add dave@box --address …`를 제안한다. 문자 그대로 "dave@box"라는 이름의 host를 핀하라는 뜻이 되어 오해를 부른다. 대화형 형태에서 유추해 치기 쉬운 실수라 UX 결함이고, 이번 diff가 만든 것이 아니므로 M8 백로그로 넘긴다.

**Step 7 이월 문서 항목 2건**(여기서 처리): (i) P3-7 — `docs/CLI.md` §2.4 operation 목록에 `cert.init`/`cert.issue` 등재(§6.16이 이미 정식 dotted op으로 문서화하는데 목록에만 빠져 있다). (ii) `cargo test`는 baseline부터 red이고 CI(`ci.yml:92-93`)도 nextest만 돌리는데 `CLAUDE.md`와 `docs/design/testing.md`는 아직 nextest를 "preferred"로 적는다 — **required**로 문면을 맞춘다. Step 7-1·7-2 두 라운드 모두 에이전트가 `cargo test`를 게이트로 오인할 뻔한 지점이라 문서 결함으로 취급한다.

**Step 8 후속 — Windows CI 복구(`11c51ae`).** Step 8(`959b4a2`)의 CI가 `test (windows-latest)` 한 레그에서만 깨졌다(run 33473165611, 1067 passed / 1 failed). 로컬 게이트 6종이 green이었으니 플랫폼 특이 문제라는 것까지는 맞았고, 실제 원인은 man page **내용**이 아니라 **체크아웃**이었다. GitHub Windows 러너는 `core.autocrlf=true`라 체크인된 `docs/man/*.1`이 CRLF로 풀리는데 `clap_mangen`은 LF로 쓴다. CI 로그의 assert 바이트 덤프가 그대로 증거다 — left(체크인)에 `13, 10`인 자리가 right(방금 생성)에는 `10`이다. 38장 전부 해당이고 정렬 첫 장 `qsh-acl-check.1`에서 터졌을 뿐이다.

**추정으로 고치지 않고 양쪽 팔을 실측했다.** 대조군 `git clone -c core.autocrlf=true` → 38/38 CRLF(CI 실패 로컬 재현). 처치군 `.gitattributes`(`* text=auto eol=lf`) 추가 후 같은 clone → 0/38, 소스 트리와 바이트 동일. 비교 쪽을 CRLF 관대하게 푸는 선택지도 있었지만 바이트 대조 게이트의 엄밀함을 깎는 대가가 있고, 무엇보다 Windows 개발자가 `cargo xtask man`을 돌리면 38장이 통째로 modified로 뜨는 진짜 문제가 남는다 — 체크아웃 쪽을 고치는 것이 원인 위치다. 추적 파일 중 CRLF가 필요한 것은 없고(`.bat`/`.cmd`/`.ps1` 부재) 전부 이미 인덱스·작업 트리 모두 LF라 재정규화 패스도 필요 없다. CI run 33474230870에서 12개 job 전건 success, Windows 레그가 **1068/1068**로 man page 대조 테스트까지 PASS — 로컬 실험이 예측한 대로다.

**(a)-추기 — M7 교차 스텝 스윕 판정 (2026-09-01, main 세션).** 여덟 스텝이 각자 자기 diff에 대해서만 적대적 검증을 받았으므로, **두 스텝이 맞물릴 때만 드러나는 결함**은 구조적으로 아무도 보지 못했다. 126파일·14.4k 삽입이면 그 이음매가 좁지 않다. 5개 렌즈(trust·hosts·ACL 상호작용 / 런타임 수명 / 계약 표면 합집합 / 문서 대 실동작 드리프트 / FS·동시성)로 훑고 각 결과를 적대적으로 반박시켰다. 원 발견 다수 중 3건 생존, main 세션이 전건 코드로 재확인했다. 런타임 수명 렌즈는 무소득 — Step 7-1·7-2가 이미 mutation으로 다진 자리라 예상된 결과다.

**P2 — pairing이 만든 첫 원격 제어 문자열이 터미널에 그대로 나간다.** `PairingProof.device_name`/`PairingAccepted.device_name`은 프로토콜 주석이 "never an authentication input"이라 못박은 자기신고 값인데, `TrustStore::add_peer`에 검증 0으로 들어가(trust/mod.rs:207-242) 양방향 모두 verbatim으로 핀된다(초대자 ops/mod.rs:706, 응답자 server/mod.rs:2092). 그리고 human 렌더러가 그대로 찍는다 — 같은 diff가 추가한 형제 함수 `print_hosts`/`print_host`는 전 필드를 `sanitize()`하는데(human.rs:302-365), trust 쪽 4함수는 빠졌다. `sanitize()`의 doc이 바로 이 위협을 명시하는데도 그렇다.

문제의 무게는 `print_trust_accept`가 `{name} ({fingerprint})`를 **한 줄에** 찍는다는 데 있다(human.rs:281). 이름에 `\x1b[K`나 CR을 넣으면 뒤따르는 fingerprint를 덮거나 감출 수 있고, 그 fingerprint가 바로 ROADMAP 감사 ②가 요구하는 **대역 외 대조 대상**이다. pairing 의식의 보안이 얹혀 있는 그 한 값을 원격이 가릴 수 있다는 뜻이고, 이후 `trust list`마다 재현된다. Step 4 이전에는 `TrustPeer.name`이 항상 운영자 타이핑이라 잠재였다 — Step 4가 처음으로 원격 제어를 준 것이 교차 결함인 이유다.

**감사 추적은 무사하다**(main 세션 확인, 검증자 미추적): `FileAuditSink::record`가 `serde_json::to_string`으로 직렬화하므로(audit.rs:307) 제어문자가 이스케이프되어 감사 줄 위조는 성립하지 않는다. 더 무거운 쪽이 배제됐으므로 등급은 터미널 이스케이프 수준에 머문다.

**수정은 두 층 — 렌더러만으로는 부족하다.** ① 렌더러: trust 4함수에 `sanitize()`(형제 함수와 같은 규율). 이미 핀돼 있는 이름도 덮는다. 폭 계산은 손대지 않는다 — `sanitize`가 제어문자를 U+FFFD로 1:1 치환이라 `chars().count()`가 보존되기 때문인데, 이 불변식을 **단언이 아니라 테스트로** 박게 했다(검증자 제안은 폭 계산도 고치라는 것이었으나 1:1이라 불필요 — 근거 없이 따르지 않는다). ② 유입 choke point: `qsh serve`의 tracing 방출(server/mod.rs:2100, :2117)은 렌더러 밖이고, trust.toml에 독을 남기면 다른 모든 소비자가 노출된다. `pairing.rs`에서 양방향 모두 핀·영속·로그 **이전에** 제어문자 이름을 `INVALID_ARGUMENT`로 거부한다(기존 enum, ad hoc 코드 신설 아님). 거부 로그에 값 자체를 되울리지 않는다.

**범위 밖으로 명시 기록(구현 안 함, M8).** 이름 길이 상한 — 오늘은 `CONTROL_FRAME_MAX` 256 KiB로만 묶여 있다. 그리고 Unicode bidi override/homoglyph 스푸핑 — U+202E류는 `is_control()`이 아니라 이번 가드도 `sanitize()`도 건드리지 않는다. 실증된 벡터는 제어문자이므로 거기까지만 고치고, 남는 구멍을 조용히 덮지 않고 적어 둔다.

**P3 — doctor 처방 2건이 진단한 바로 그 조건에 무효인 명령을 시킨다.** `ca::init`은 루트 파일이 있기만 하면 `not_after`를 보지 않고 `created:false`로 돌아오고(ca.rs:97-102), `cert_issue`의 `already_issued`는 "누가 서명했나"만 볼 뿐 유효한가를 보지 않는다(ops/cert.rs:83-86). 즉 CA 루트 만료와 이미 승격된 leaf 만료 — 이 진단이 실제로 뜨는 두 상태 — 에서 처방 명령이 순수 no-op이다. 스윕은 `CERT_EXPIRED`만 잡았으나 main 세션이 코드를 읽다 **`CERT_EXPIRING_SOON`도 동일 결함**임을 찾았다(doctor.rs:201-206, 승격된 leaf에 대해 똑같이 no-op). 둘 다 고친다. **`--force` 플래그는 만들지 않는다** — cert rotation UX는 ROADMAP이 M7 명시 out으로 잡은 항목이라 그쪽으로 가면 인수 기준을 넘는다. 문면만 실제 복구 절차로 바꾸고 §6.17을 같이 맞춘다(`doctor_docs.rs`가 축자 대조로 강제).

**README 자기모순 1건.** Step 8이 상단 Status를 "M7 has landed the features below"로 고쳐 놓고 같은 파일 Roadmap 표의 M7 행은 `Planned`로 남겼다(README.md:20 vs :523). 검증자는 "마감 커밋이 Done으로 뒤집으니 별건으로 열지 말라"고 판정했고 논리는 맞지만, M7 마감이 사람 대기로 묶여 있어 그동안 사용자 대면 문서가 자기모순으로 남는다. `In progress`로 한 칸만 고친다 — Step 8의 범위가 "README 최종 동기화"였으므로 새 일이 아니라 Step 8 미완의 마무리다.

**수정 라운드 마감 + main 세션 독립 검증.** fixer가 A·B·C 전건 반영. main 세션이 diff 전건을 직접 읽고 **형태 2건을 고쳤다**: 새 doctor 처방 문면이 430·476자로 같은 파일 나머지 진단의 최댓값(228자)의 2배였다 — `qsh doctor` 한 줄로 나가는 문자열로는 벽이라, 근거는 이미 충실한 doc 주석에 두고 운영자 문면은 실행 가능한 핵심만 ~265자로 줄였다(§6.17 예제 동기화).

**처방의 사실성을 코드로 확인했다.** 처방이 "`ca/`를 지우고 `qsh cert init` 재실행"을 시키는데, `add_ca`는 이름 충돌 시 `add_peer`와 **달리 덮어쓴다**(trust/mod.rs:267) — no-op이었다면 처방이 운영자를 더 나쁜 자리로 몰았을 것이다. leaf 경로도 `identity::init`이 부재 시 재생성함을 확인. ADR-0008이 rotation을 P1 범위 밖으로 못박은 것도 대조했다(L52).

**독립 mutation 2종 — 전건 검출.** ① 유입 가드 무력화 → 비자명 검출 2건(실 QUIC loopback의 responder 측 거부 + `Ops::trust_accept`의 initiator 측 거부, 후자는 **검증되는 proof를 가진 rogue responder**가 나쁜 이름을 보내도 `trust.toml`이 생성조차 되지 않음을 단언한다). 가드 함수를 직접 부르는 단위 테스트 1건은 자명 검출로 분리 계상. ② 렌더러 `sanitize` 제거 → 해당 테스트 FAIL. 양쪽 byte-identical 원복. 게이트 6종 green, nextest **1342 passed / 2 skipped**(1334 + 신규 8 = 정확 일치). CI run 33479926317 12개 job 전건 success(`37e1867`).

**과정 사고 1건(기록).** mutation 원복에 `git checkout <file>`을 썼는데 fixer 변경이 미스테이지 상태라 `pairing.rs`의 Fix A2가 통째로 소실됐다. 같은 세션에 캡처해 둔 diff로 재구성했고, `cargo fmt`가 아무것도 바꾸지 않은 점(포맷 일치)·관련 27건 통과·최종 테스트 수 정확 일치(+8)로 복원이 원본과 동등함을 확인했다. 이후 mutation은 파일 복사본으로 원복했다. 감사하는 사람이 "착지한 코드가 검토된 코드와 같은가"를 물을 수 있으므로 남긴다.

**스윕 2라운드 — 무소득(기록할 가치가 있는 음성 결과).** 1라운드가 다루지 않은 세 면을 마저 훑었다: ① **MCP 어댑터 × M7의 Ops 변경** — M6가 닫힌 뒤 그 아래 facade가 hosts.toml 해석·trust 의미론·pairing·capabilities·cert·doctor로 바뀌었는데 어댑터를 그에 대조한 사람이 없었다. ② **M7 신규 에러 경로의 panic·자원 정리** — 원격/디스크 입력이 닿는 unwrap·조기 반환 시 미해제 자원. ③ **reverse/tunnel × trust·hosts 변경** — M3·M4가 hosts.toml과 내용 기반 재로드 이전에 지어진 코드다. 세 렌즈 모두 빈 배열을 반환했고, 에이전트별 도구 호출 44·67·44건으로 실제 조사를 거친 결과임을 journal로 확인했다(빈 결과를 조사 실패와 구분).

여기서 스윕을 끝낸다. 1라운드가 3건 중 1건을 마감 전 수정 대상으로 건졌고 2라운드가 0건이면 이 표면에서의 수확 체감이 분명하다. 더 돌리는 것은 인수 기준을 넘어가는 일이다.

**(d) 완료 판정:** 캠페인 3회 기록 완료(전건 5분 이내), §5 전 항목 완료.

## 3. 명시적 non-goals (P1 유예 / 타 마일스톤)

- **cert rotation/revocation UX, background service 설치, QR** — ROADMAP M7 명시 out.
- **`ControlLink`/`DataLink` enum → trait 전환(ADR-0005 P0 부채)** — M3→M6 연쇄 이월. M7도 트리거하지 않는다(trust/doctor는 transport 추상에 접촉하지 않는다). P1 입력으로 재기록.
- **HTTP/SSE transport, streaming MCP** — M6판 그대로 P1.
- **revocation의 실시간 전파**(trust remove 즉시 종료를 Step 2가 기각할 경우) — 결정 결과에 따라 P1 재기록.
- **rmcp minor 업그레이드** — 착수하지 않음. 단 업그레이드가 필요해지는 순간 `local_ct_pool` 취소 구조 재검증이 선행 조건(M6 판정 ① 감시 항목 승계).

## 4. 리스크와 감시 항목

- **cert/CA는 진짜 백지** — ADR 없이 구현 착수 금지(Step 5 ①이 게이트). CLI 절도 PRD 한 줄뿐이라 표면 설계 자체가 리스크.
- **pairing wire 확장은 M8 freeze 직전** — protocol.md 반영 누락이 곧 freeze 결함. 감시: Step 4 (d)에 protocol.md diff 포함.
- **SC1 스톱워치는 간판 숫자** — 한 번에 몰지 말 것(ROADMAP §4 리스크 3). 감시: Step 4 직후 예행 1회.
- **capabilities는 scope-creep tripwire** — fixture diff로만 표면이 바뀔 수 있다(M6 tool fixture와 같은 규율).
- **SC7 외부 보안 리뷰 예약** — 운영자 액션 미완 재이월 중(M5→M6→M7). M8 wire freeze 리드타임 소진 중.

### 4.1 구현 중 확정할 값 (해당 step (a)에 근거와 함께 추기)

| # | 질문 | 초안 | 확정 시점 |
|---|---|---|---|
| 1 | version 식별자 필드명·소스 | `build.commit`(vergen류 없이 `option_env!` 주입) | Step 1 |
| 2 | capabilities fixture 범위 | negotiated 리스트 그대로(가공 없음) | Step 1 |
| 3 | trust remove 의미론 | 현행 유지(다음 handshake부터) + 3문서·doctor 고지 | Step 2 |
| 4 | hosts.toml vs trust.toml 해석 우선순위 | hosts.toml 우선, 없으면 pinned peer fallback | Step 3 |
| 5 | doctor JSON code 어휘 | snake_case, 기존 `controller_unreachable` 선례 준용, 전 목록 사전 고정 | Step 6 |
| 6 | session_read 구조 | Ops 공유 런타임(측정으로 결정) | Step 7 |
| 7 | invite code 인코딩·엔트로피 | ≥128bit, 사람 전달 가능한 그룹 구분 인코딩 | Step 4 |

## 5. 완료 절차

1. §1 DoD 4항목 전건을 실제 테스트/캠페인 기록으로 확인(체크박스는 근거 green일 때만).
2. 구속 문서 태그 대조: CLI.md §6.10·§6.11·§8(13번째 tool 결정 반영 시)·PRD §15의 M7 관련 전 문장 전수 대조.
3. README 갱신: 첫 실행·pairing·doctor 절 최종화, Roadmap 표 M7 → Done.
4. `docs/design/testing.md`에 M7 테스트 층 반영(§6 조사 결과 M7 절은 현재 빈칸).
5. `docs/ROADMAP.md` "현재 위치"·M7 절 갱신 + 마감 노트.
6. **SC7 외부 보안 리뷰 예약 재확인** — 계속 미완이면 M8 착수 전 운영자 에스컬레이션 필수(리드타임 조건이 이번 마일스톤으로 사실상 만료).
7. 이 PLAN.md를 M8 계획으로 전면 교체(§3의 P1 재기록 항목 이관 포함).

---

## 6. M8 — Hardening (선행 착수분)

구속 근거: `docs/ROADMAP.md` M8 절(범위·감사 개정 ①②③④·DoD·적대적 부하 하네스), §3 유예 가드레일 표의 M8 소유 행, §4 리스크 1·4·5, `docs/design/protocol.md` §7(터널 무상한 갭)·§15, `docs/PRD.md` SC3/SC7. M7과 마찬가지로 이 절의 편집은 main 세션 전용이다.

### 6.0 착수 전 에스컬레이션 — SC7 (§5.6이 요구한 액션)

§5.6은 "SC7이 계속 미완이면 M8 착수 전 운영자 에스컬레이션 필수"라고 정했고, M8을 여는 지금이 그 시점이다. 상태를 있는 그대로 적는다.

- **외부 보안 리뷰 예약은 M5→M6→M7 3연속 미완**이다. 저장소 안에서 완결할 수 없는 조직 액션이라 에이전트가 대신할 수 없다.
- 조건은 ROADMAP §4 리스크 5: 리뷰 시작 ~6주 전에 wire format을 freeze한다. **지금 예약해도 freeze는 이미 리뷰 일정을 밀어내는 쪽**이다 — 리드타임이 남아 있지 않다.
- 결과적으로 남는 선택지는 둘뿐이다. (가) 지금 예약하고 wire freeze(6.7)를 예약일 기준 6주 전으로 앞당긴다. (나) 예약 없이 freeze만 진행하고 리뷰를 M9로 미룬다 — 이 경우 SC7은 릴리스 게이트에서 빠지므로 PRD 개정이 따라야 한다.
- **판단은 운영자 몫**이고 코드 작업으로 대체되지 않는다. 이 항목이 미해결인 채로 6.7(wire freeze)을 넘기지 않는다.

### 6.1 DoD 체크리스트 (ROADMAP M8)

- [ ] **DoD 1 — fuzz**: parser 타깃당 누적 ≥72 fuzz-hours 무crash.
- [ ] **DoD 2 — soak**: 24h/100-session에서 idle listener ≤30MB, 세션당 buffer ≤8MB, fd 무증가.
- [ ] **DoD 3 — 실기기 mobility**: Wi-Fi↔테더링 ≥60회(macOS+Linux) 자동 유지+resume ≥95%, migrated/resumed 분해 보고. 통과 기준은 사전 정의(idle timeout에 기대지 않는 2초 내 재dial). **사람이 실행한다.**
- [ ] **DoD 4 — wire freeze 후 독립 리뷰 계약** (SC7 — 6.0 참조).
- [ ] **DoD 5 (감사 개정) — 적대적 부하 하네스**: 스푸핑 Initial flood·대량 연결·principal당 세션 폭주 각각에서 선언된 상한이 실제로 강제되고, 부하 중·후 idle listener RSS/fd가 soak과 같은 bound를 지키며, 기존 세션의 PTY echo가 살아 있음.

### 6.2 실행 단계 (PR 단위)

#### Step 1 — fuzz 인프라: 타깃 + corpus + CI smoke

`crates/qsh-proto`가 CLAUDE.md가 지목한 fuzz 표면이다. DoD 1이 벽시계 시간을 요구하므로 M8에서 가장 먼저 세운다.

- 제약: `rust-toolchain.toml`이 stable 1.97.1로 고정돼 있고 cargo-fuzz는 nightly가 필요하다. `fuzz/`를 워크스페이스 **밖**(자체 빈 `[workspace]` 테이블)에 두어 기존 게이트 6종을 건드리지 않는다. `xtask arch`는 워크스페이스 멤버만 순회하므로 영향이 없다 — 추론이 아니라 실행으로 확인한다.
- 타깃 단위는 **파서 표면 단위**다. DoD가 "타깃당" 시간을 세므로 타깃 집합 자체가 계약이다.
- corpus seed는 기존 테스트·fixture의 실제 값에서 뽑는다.
- CI는 결정적인 `-runs=` 고정 횟수 smoke만 돌린다. 72시간 누적은 CI가 아니라 6.3의 별도 실행이다.
- 완료 기준: 전 타깃 build+run, libFuzzer 커버리지 카운터가 seed 이상으로 움직임, 게이트 6종 불변.

**(a)-추기 — Step 1 착륙 판정 (2026-09-02).**

착륙물: `fuzz/`(워크스페이스 밖, 자체 빈 `[workspace]`) 타깃 16종 + curated seed 110 파일 + `.github/workflows/fuzz-smoke.yml` + `fuzz/README.md`. 타깃 구성 — 바이트 디코더 8(`frame_decoder` 상태 기계, `decode_control`·`hello`·`exec_frame`·`session_frame`·`stream_header`·`connect_result`, `decode_local_hello`·`local_admin_request`), 문자열 파서 5(`parse_invite_code`·`parse_forward_spec`·`fingerprint_principal`·`valid_host_name`·`valid_forward_id`), 술어 1(`sanitize_peer_text`), JSON 1(`json_request_types` — MCP `arguments`→`types::*Req` 12종, selector byte). `cargo metadata`로 워크스페이스 비멤버 확인, `xtask arch` OK — 추론이 아니라 실행 결과다.

1라운드 조사(3분할, 후보 26개) → 구축(14 타깃) → 검증 2건 병렬. 실행 검증은 14 타깃 전부를 빈 corpus에서 50k runs 돌려 cov 0→N(최소 38, 최대 902)을 확인했고 dud 0. 적대적 리뷰 6항목 중 채택 4: ① `ConnectResult` 디코더 누락(`tunnel/local.rs:518`, `-L` dial 응답을 티켓 없이 wire에서 바로 읽는 유일한 스트림) → 타깃 추가. ② MCP 인자 JSON 역직렬화 미커버(`mcp/mod.rs:411`) — 구축 에이전트가 "JSON은 in-repo 파스 지점 없음"이라 제외했는데 그 근거가 이 경로엔 안 맞았다 → 타깃 추가, `SessionAttachReq`는 MCP 라우팅이 없어 제외(grep으로 확인). ③ corpus 정책 — 측정 실행이 체크인 디렉터리에 2,498개 SHA1-이름 파일을 써넣어 8.3 MB로 불었고 README는 "grown corpus를 유지하라"는 반대 정책을 적고 있었다. 판정: **체크인은 curated seed만, 장기 실행은 쓰기용 grown dir을 첫 인자로**(libFuzzer는 첫 corpus dir에 쓴다) → 2,498개 삭제, README 정책 재작성, 72h 레시피의 하드코딩 14-이름 루프를 `$(cargo fuzz list)`로. ④ CI matrix 14-leg가 같은 크레이트를 14번 sanitizer 빌드하고 타깃 추가 시 조용히 누락 → 단일 job + `cargo fuzz list` 루프 + 실패 수집 후 non-zero exit. 리뷰의 "구축 보고가 corpus 리셋을 거짓 주장" 지적은 병렬 검증의 경쟁 산물(실행 검증 에이전트가 자기 run으로 다시 불렸다고 스스로 보고)이라 사실 판정은 기각, 정책 결정은 그대로 채택. false target·input mapping 지적 0건.

2라운드 검증: 신규 2 타깃 빈 corpus 50k runs cov 0→269 / 0→826, selector 12종을 `mcp/mod.rs` `tool::<…Req>()` 등록과 교차 대조해 일치, `actionlint` 통과, corpus 110 파일·40-hex 이름 0개, 게이트 6종 green(nextest 1342 불변).

main 세션 독립 검증: `frame_decoder`(바이트 보존 단언이 `HEADER_LEN`=4와 일치, `Err` 후 조기 반환은 "oversize 헤더 이후 복구 불가" 계약과 정합, payload 선할당은 명시 단언 대신 rss 상한이 담당)·`fingerprint_principal`·신규 2건을 직접 읽음. 변이 검사 2건 — **MUT-F1** `next_frame`에 `len == 0x1337` panic 주입 → `frame_decoder`가 120 s 캡 안에 검출, 아티팩트 오프셋 6에 `00 00 13 37`(seed에 없는 값을 변이로 합성 — 타깃이 파서에 닿는다는 실증). **MUT-F2** `sanitize_peer_text`에 `ESC [` panic 주입 → `decode_connect_result`가 즉시 검출, 단 아티팩트가 ANSI seed 그 자체라 seed-hit(crash 표면화 경로의 증명이지 탐색력의 증명은 아님). 두 파일 모두 cp 백업과 바이트 동일 복원, `crates/` diff 0줄.

의도적 미커버(기록): `SessionEvent`·`ErrorCode`의 JSON `Deserialize` — 워크스페이스 안에 비테스트 파스 지점이 없다(직접 grep 확인). `resume.rs:375-408`의 salvage JSON 파서 — 로컬 파일이고 qsh-proto 밖이라 이번 타깃 집합 밖, 단 fuzz가 결함을 잘 찾는 모양의 코드라 Step 5(soak)에서 재검토.

CI 마감(`d87e76b`): CI run 33601462030 11 job 전부 success(`test (windows-latest)` 포함 — 로컬에서 미검증으로 남긴 G6를 CI가 확인), fuzz-smoke run 33601462001 success, step 로그에서 16 타깃 전부 `Done 4096 runs`, crash/`SUMMARY:` 0건. **Step 1 마감.**

다음: 이 커밋을 push한 뒤 fuzz 호스트(Dave-Windows-WSL, 8 vCPU / 31 GB, cargo-fuzz 0.13.2 설치 완료)에 clone하고 72 h 시계를 돌린다. 16 타깃 × 72 h를 8 코어로 돌리면 2 배치 = 최소 144 h 벽시계.

**72 h 시계 시작 기록.** 커밋 `d87e76b`, 호스트 Dave-Windows-WSL, run-id `m8-fuzz-20260902-1600`, 시작 2026-09-02T16:01:37+09:00, 16 타깃을 8 워커로 2 배치(`-max_total_time=259200 -rss_limit_mb=1536`, grown corpus는 `~/fuzz/grown/<t>`를 첫 인자로 두어 체크인 seed는 읽기 전용). 1차 배치 종료 예정 09-05 16:01, 2차 배치 종료 예정 09-08 16:01 이후. 기동 직후 실측: `decode_control` 7.1M execs / 170k exec/s / cov 1873 / RSS 541 MB, load 6.2, 가용 메모리 16 GB. 로그·exit 코드는 호스트 `~/fuzz/logs/m8-fuzz-20260902-1600/`. DoD 1 판정은 `exits.txt`의 16행 전부 `exit=0`이고 어떤 로그에도 `SUMMARY:`/`deadly signal`/`Test unit written`이 없을 때.

#### Step 2 — 적대적 부하 방어선 ①②: 주소 검증 + accept 상한

감사 개정 ①②. 인터넷에 직접 노출되는 데몬에 현재 방어선이 없다.

- `Incoming::retry()` 주소 검증 — 스푸핑 Initial 1패킷당 상태 생성 차단.
- accept 동시성 상한 + source rate limit.
- 초과는 거부이며 **자원 생성 전에** 결정한다(CLAUDE.md: 인가 성공 전 자원 생성 금지와 같은 규율).

#### Step 3 — 적대적 부하 방어선 ③: 세션·터널 쿼터

- `[serve].max_sessions`, principal별 세션 쿼터.
- **터널 전용 할당량** — principal별·forward별 동시 `TCP_CONNECT` 스트림 수, remote-forward listener 개수 상한. `docs/design/protocol.md` §7이 명시하고 M4·M5 어느 쪽도 만들지 않은 무상한 갭을 여기서 인수한다.
- 초과는 `RESOURCE_EXHAUSTED`(CLI.md §3.3 기정의 어휘 — 새 코드를 만들지 않는다).

#### Step 4 — 적대적 부하 하네스 (DoD 5) + audit 수명주기 부하 검증

협조적 soak과 **별도 게이트**다. 감사 개정 ④의 연쇄(스푸핑 flood → 세션 없는 audit 쓰기 → 디스크 만실 → resume 실패)가 차단되는지를 본다. Step 2·3이 선언한 상한이 실제로 강제되는지를 이 하네스가 판정한다.

#### Step 5 — 24h/100-session soak + fd/메모리 게이트 (DoD 2)

M7 이월 부채가 여기서 만난다: bounded pull executor 부재(측정된 512 천장), pull당 fd 선형 증가, 고아 `.tmp{pid}-{N}` 미청소. soak이 이것들을 드러내는 자리다.

#### Step 6 — wire freeze 선행 정리

freeze 이후에는 고칠 수 없는 것들을 먼저 처리한다.

- handshake matrix에 **ALPN 불일치** 케이스 추가 — "application 상태 생성 전 실패" 불변식을 의존성 상속이 아니라 테스트로 고정한다.
- device 개인키 프로세스 상주 사본에 `Zeroizing`.
- TUI 펌프 스레드 spawn 실패 panic 제거.
- pairing device_name 길이 상한(현재 `CONTROL_FRAME_MAX` 256 KiB로만 묶임)과 Unicode bidi-override·homoglyph 스푸핑 — `docs/design/protocol.md` §15.5가 M8 백로그로 기록한 2건.

#### Step 7 — wire format freeze + threat model + OSS-Fuzz 제출

6.0의 SC7 판단이 선행 조건이다. freeze 문면은 `docs/design/protocol.md`에 박고, threat model은 새 문서로 낸다.

#### Step 8 — perf 게이트

#### Step 9 — 실기기 mobility 캠페인 ≥60회 (DoD 3, 사람 몫)

M2가 20회를 조기 측정해 SC4/SC5를 실기기로 확인했고 SC3 판정을 N≥60으로 미뤄뒀다. M2 기록의 이월 1건 — 예산 내 복구 1/10의 지배 요인이 Tailscale underlay 재경로(~4–5 s)였고 qsh 자체 resume은 233–1076 ms — 를 이 캠페인이 분해 보고로 갈라야 한다.

#### Step 10 — 마감

### 6.3 실행 환경

72시간 fuzz 누적과 24h soak은 heavy compute다. 로컬 개발 머신이 아니라 전용 호스트에서 돌린다(전역 지침의 머신 라우팅). 캠페인 기록은 M2·M6·M7 선례대로 `docs/campaigns/`에 사전 정의 후 실행한다.

### 6.4 M7에서 이월된 항목

| # | 항목 | 소유 step |
|---|---|---|
| i | bounded pull executor + `RESOURCE_EXHAUSTED` (측정된 512 천장) | Step 3·5 |
| ii | `Ops::exec`(`ops/exec.rs:81`) 호출당 `new_multi_thread()` 런타임 | Step 5 |
| iii | pull당 fd 선형 증가 | Step 5 |
| iv | 고아 `.tmp{pid}-{N}` 청소 부재 | Step 5 |
| v | `qsh trust add dave@box --address …` 오도 제안 | Step 6 |
| vi | trust store read-modify-write 잠금 부재 | Step 6 |
| vii | invites.toml CLI/데몬 lock-free 창 | Step 6 |
| viii | device_name 길이 상한 + Unicode bidi/homoglyph 스푸핑 | Step 6 |
| ix | forward-route live carrier·`-R` 자동 재발행 (ROADMAP §3 표가 M8 소유로 등재) | Step 3 |
| x | `ControlLink`/`DataLink` enum → trait 전환 (ADR-0005 P0 부채, M3→M7 연쇄 이월) | P1 재기록 — M8도 트리거하지 않음 |

### 6.5 리스크

- **SC7 리드타임은 이미 만료**다(6.0). wire freeze 일정이 조직 액션에 묶여 있다.
- **DoD 1·2·3은 전부 벽시계**다. 압축되지 않으므로 순서가 곧 일정이다 — Step 1을 가장 먼저 세운 이유.
- **graceful re-exec(fd 보존 handoff)** 는 ROADMAP §4 리스크 4가 M8 stretch로 비용 산정만 요구한다. 구현은 범위 밖.
- **notarization은 M9가 아니라 M8 중 시작**(ROADMAP M9 크기 주석). 리드타임 항목이라 6.0과 같은 성질이다.
