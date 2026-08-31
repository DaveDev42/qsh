# PLAN.md — M7: Trust UX·profiles·doctor

M6 마감(2026-08-31, ROADMAP M6 마감 노트)과 함께 이 문서는 M7 실행 계획으로 전면 교체됐다. 구속 근거: `docs/ROADMAP.md` M7 절(범위·감사 개정 ①②③·DoD), `docs/PRD.md` §6·§11·§15(SC1/SC2), `docs/adr/0002-pairing-invite-code.md`, `docs/design/architecture.md` §2(trust 이중 모드)·§7(`hosts.toml`). 이 계획과 ROADMAP.md의 편집은 main 세션 전용이다.

## 1. DoD 체크리스트 (ROADMAP M7)

- [ ] **DoD 1 — 스톱워치 테스트**: 한 번도 설정한 적 없는 두 장비가 README만 보고 `qsh user@host`까지 5분 이내, 독립 3회 측정·기록 (SC1/SC2, 캠페인 문서 사전 정의).
- [ ] **DoD 2 — doctor 진단 6종**: UDP 차단/경로 없음/비신뢰 peer/만료 cert/keystore 부재(headless)/clock skew 각각 실행 가능한 메시지 + 안정된 JSON code.
- [ ] **DoD 3 — `qsh capabilities --json` == checked-in fixture** (scope-creep tripwire).
- [ ] **DoD 4 (감사 ①) — `trust remove` 유효 범위**: 기존 연결·신규 handshake 각각의 동작이 테스트로 고정되고 문서·doctor 고지와 일치.

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

### Step 7 — M6 이월 부채 정리 3건

**(a) 범위:** ① **`Ops::session_read` per-call 런타임+QUIC 구조 결정** — M6 판정 ⑤(방치 pull당 ~11 threads·5 fd·0.86MB ≤60s, 400건 → 4,412 threads/372MB)의 원인. 공유 런타임 vs bounded pull executor 중 구조를 결정하고(4.1 #6) 동일 측정으로 전후 비교. ② `action_of` op 키 enum화(M5 P2-3 이월). ③ `acl_check`의 13번째 MCP tool 노출 **결정**(§8.2 표 additive 개정 선행 — 채택이든 명시 기각이든 이 절에 추기; 조용히 추가하지 않는다).

**(d) 완료 판정:** ①은 측정 전후표 + 기존 conformance 전건 green(계약 무변경), ②는 컴파일 타임 전수성(match) 확보, ③은 결정 기록 + (채택 시) fixture 개정 diff 리뷰.

### Step 8 — man page·설치 문서 + 스톱워치 캠페인 (DoD 1) + 마감

**(a) 범위:** man page·설치 문서, README 최종 동기화. `docs/campaigns/m7-stopwatch.md` 사전 정의(M6 캠페인 선례: 기준 먼저 커밋) — 한 번도 설정한 적 없는 두 장비(신선한 sandbox 프로필 2식 또는 실장비 2대), README만 보고 `qsh user@host`까지, 독립 3회, 5분 기준. ROADMAP §4 리스크 3의 "조기·반복" — Step 4(pairing) 착륙 직후 1회 예행 측정을 먼저 수행해 병목을 마감 전에 노출한다. 이후 §5 마감 절차.

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
