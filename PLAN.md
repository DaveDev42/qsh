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

### Step 3 — `hosts.toml` host profile + 첫 실행 경험

**(a) 범위:** architecture.md §7 문면대로 `hosts.toml`(`[[host]] name·address·user`) 도입 — trust.toml(신뢰)과 분리된 주소 directory. `host.list`/host 해석이 trust.toml 단일 출처에서 hosts.toml 우선으로 확장(우선순위 규칙은 4.1 #4). `user`는 M7에서도 assertion hint일 뿐(불일치 시 `UNSUPPORTED`, PRD §6 user switching 없음 유지). README 첫 실행 절 초안(Step 7 스톱워치의 대본이 된다).

**(d) 완료 판정:** hosts.toml 유무·병합 각 조합의 host 해석 테스트, `qsh hosts`/`qsh host` 출력 계약 additive 검사.

### Step 4 — invite pairing (ADR-0002 구현)

**(a) 범위:** `qsh trust invite`/`qsh trust accept <code>` — 고엔트로피 일회용 invite code(10분 TTL), TLS exporter 기반 HMAC proof 교환으로 양방향 pin 동시 설정. CLI 계약(플래그·JSON envelope) 확정 + CLI.md §6.11 확장(additive, L604의 "M7에서 확정" 이행). `--json` 경로는 prompt 금지 — `TRUST_REQUIRED` + `details.fingerprint`(ADR-0002 문면). pairing 안내 문구에 대역 외 fingerprint 대조 경로 포함(감사 ②). wire 추가분은 `docs/design/protocol.md`에 반영 — **M8 wire freeze 전 마지막 프로토콜 확장이므로 스키마를 보수적으로**.

**(d) 완료 판정:** 실 QUIC 왕복 pairing E2E(성공/TTL 만료/재사용 거부/HMAC 불일치 4상한), `--json` 비대화형 검사, fingerprint fallback(§6.11 기존 경로) 회귀 무손상.

### Step 5 — private CA `qsh cert` (ADR 선행)

**(a) 범위:** ① **ADR 신설이 선행** — CA 계층(단일 CA), 서명 대상(device cert, `qsh://device/…` SAN → `device:` principal), user cert 취급, 파일 위치·포맷. 현재는 architecture.md의 부분 결정(pin-or-CA verifier·rcgen)만 있는 백지 표면이다. ② ADR 승인 후 `qsh cert` 최소 표면 구현: CA 생성, device cert 발급, trust store CA 등재. rotation/revocation UX는 명시 out(§3).

**(d) 완료 판정:** CA 발급 cert로 실 handshake 성공 + pin 없는 CA-chain 경로 검증 테스트, `fp:`/`device:` principal 매핑 검사, ADR 링크가 CLI.md 신설 절에 명시.

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
