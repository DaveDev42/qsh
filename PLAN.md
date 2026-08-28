# PLAN — M6: MCP adapter

**전제:** M5 완료(2026-08-28, `docs/ROADMAP.md` 마감 노트). 이 문서는 M6의 실행 계획이며 마일스톤이 닫히면 M7 계획으로 전면 교체된다. 정본 우선순위는 언제나 `docs/CLI.md` §8·§9·§10·§11(계약) > `docs/ROADMAP.md` M6 절(수용 기준) > 이 문서다.

**한 줄 요약:** `qsh mcp`(stdio 전용)가 CLI.md §8.2의 tool 12종을 노출한다. tool schema는 CLI와 **같은 Rust 타입**(`qsh-proto`의 `*Req`/`*Data`, schemars)에서 생성하고, adapter는 `Ops`를 직접 호출하는 얇은 층(~300줄, architecture.md §8·§9)이다 — command string 조립도, CLI output 재파싱도, 인증·ACL·세션 로직도 0줄.

## 1. DoD 체크리스트 (`docs/ROADMAP.md` M6 수용 기준 문면 그대로)

- [ ] **DoD 1 — stdio conformance 하네스**: initialize → `tools/list` == checked-in fixture → open/write/read/close 시나리오가 실 바이너리 `qsh mcp`에 대해 통과.
- [ ] **DoD 2 — Claude Code 실접속으로 원격 명령 실행**: 실제 MCP client 접속 기록(수동 캠페인, 절차·판정 기준 사전 정의).
- [ ] **DoD 3 — `read_session` 취소 후 세션 상태 `running` 유지** (CLI.md §8.4·§9의 cancellation 의미론).
- [ ] **DoD 4 — adapter 의존성 ban(arch-lint)**: subprocess 실행·CLI 재파싱을 원천 봉쇄하는 기계 게이트.
- [ ] **DoD 5 — `-vv`에도 MCP stdout에 JSON-RPC 외 바이트 0** (§8.1: 진단은 전부 stderr).

## 2. 실행 순서 (PR 단위)

### Step 1 — 계약·의존성 확정: rmcp pin + DTO 감사 + 결정 기록

**(a) 범위:** 코드보다 결정이 먼저다. ① rmcp 3.x 정확 pin + schemars 버전 정합(architecture.md §8 표) — `cargo deny` green 확인. ② tool 12종 ↔ `Ops` 메서드 ↔ `*Req`/`*Data` 타입 전수 감사: 12종 각각에 대응 타입이 `qsh-proto`에 있고 `JsonSchema` derive가 있는지, 없으면 additive로 추가(§10: 기존 field 재해석 금지). ③ §4.1 결정 표의 미확정 항목을 확정해 이 문서에 추기. ④ `tools/list` fixture의 파일 위치·정규화 규칙 확정(`qsh capabilities` fixture 선례).

**(b) crate/파일:** `crates/qsh-cli/Cargo.toml`(rmcp 도입 — **adapter는 qsh-cli 소속**, arch 매트릭스 무변경), `crates/qsh-proto/src/types.rs`(JsonSchema 파생 보강, additive만).

**(c) 빚지는 테스트:** 12종 매핑의 문서 대조 게이트(§8.2 표 ↔ 코드 상수, `acl_docs.rs`/`acl_registry.rs` L6 선례 — MCP tool 이름·op 이름 쌍을 양방향 대조).

**(d) 완료 판정:** cargo deny green, 12종 매핑 표가 코드 상수로 실재, §4.1 전 항목 확정 기록.

**(a)-추기 — Step 1 완료 확정 (2026-08-29, main 세션).** ① rmcp `=3.1.4` 정확 pin, `default-features = false`, features `["server", "transport-io"]`만 — client/auth/HTTP 제외. 워크스페이스 schemars 1.x(lock 1.2.2)가 rmcp 요구(`schemars = "1.0"`)를 그대로 만족, 상향 불요. cargo deny: rmcp 유발 신규 중복 경고 0건. ② DTO 감사 결과 12종 전부 기존 `*Req`/`*Data`에 `JsonSchema` 파생이 이미 있어 qsh-proto 수정 0줄 — `SessionReadReq`가 §8.3 예시와 필드명까지 일치(설계 시점에 이미 MCP를 겨냥). ③ 매핑 상수 `TOOL_MAP`은 `crates/qsh-cli/src/mcp/mod.rs` 소속(소비자 단독 축 — `OP_REGISTRY`와 다른 축이라 qsh-core에 두지 않는다). **qsh-cli는 lib 타깃 없는 bin-only crate라 MCP 문서 대조·conformance 계열 중 내부 심볼이 필요한 테스트는 `tests/*.rs`가 아니라 어댑터 모듈 내 `#[cfg(test)]`에 둔다** — Step 2의 실바이너리 conformance 하네스(`tests/mcp_conformance.rs`)는 내부 심볼이 불필요하므로 원계획대로 외부 테스트 파일. ④ §4.1 확정: #1 `=3.1.4`; #2 초안 유지(스키마 결정성은 rmcp `Tool::with_input_schema` 경로 3회 반복 바이트 동일로 실증 — 사전순 정렬 여부는 Step 2에서 fixture 형태로 확정); #3 초안 그대로(`CallToolResult::structured_error` = isError:true + structuredContent, 프로토콜 오류 불개입 — 컴파일 실증); #4 **문면 정정** — "MCP 전용 timeout 인자를 새로 추가하지 않는다"로 좁힌다: `ExecRunReq.timeout_ms`는 §6.8 기존 계약의 상속이지 신규가 아니다; #5 초안 그대로(rmcp stdio는 newline-delimited JSON-RPC — raw `std::process::Command` 하네스 실현 가능, 소스 확인). ⑤ 부수: `chacha20 0.10.1`이 crates.io에서 실제 yank됨(레지스트리 플레이크 아님 — 0.10.2 정상 존재)을 확인하고 `cargo update -p chacha20`으로 0.10.2 이동, deny advisories green 복원 — deny.toml 예외를 파지 않았다(arrayref와 달리 진짜 yank이므로 업데이트가 옳다).

### Step 2 — `qsh mcp` 골격: stdio 서버 + initialize + tools/list == fixture (DoD 1 전반부, DoD 5)

**(a) 범위:** `qsh mcp` subcommand가 rmcp stdio 서버를 띄운다. tool schema는 schemars가 `*Req`에서 생성. **stdout 순수성이 이 step의 본체다**: 로깅·진단·panic 출력까지 전부 stderr(§8.1), `-vv` 포함. MCP 서버 시작 시 M5 시작 진단(`StartupDiagnostic`)도 stderr로만.

**(b) crate/파일:** `crates/qsh-cli/src/mcp/mod.rs`(신규, ≤300줄 목표), `crates/qsh-cli/src/cli.rs`·`main.rs`(subcommand 배선).

**(c) 빚지는 테스트:** conformance 하네스 1절 — 실 바이너리 spawn → initialize 왕복 → `tools/list` 응답 == checked-in fixture(`crates/qsh-cli/tests/mcp_conformance.rs` + `tests/fixtures/mcp/tools_list.json`). `-vv` 플래그로 같은 하네스를 돌려 stdout에서 JSON-RPC frame 외 바이트 0 단언(DoD 5).

**(d) 완료 판정:** fixture 대조 green. schema에 `*Req` 타입 변경이 그대로 반영됨(fixture diff로만 tool 표면이 바뀔 수 있음 — scope-creep tripwire, ROADMAP §3 메타 가드레일과 같은 원리).

**(a)-추기 — Step 2 완료 확정 (2026-08-29, main 세션).** ① `tools/list` fixture는 **정규화 0**의 원시 JSON-RPC 응답 전체다 — 하네스가 request id를 스스로 pin하고 protocol version도 `"2025-11-25"`로 pin(SEP-2322 `resultType` 문턱 `2026-07-28` 미만이라 rmcp 기본값 변동에도 fixture 형태 불변). §4.1 #2의 "request_id류 마스킹" 예상은 불필요로 판명 — 정렬은 tool 이름 사전순 확정. ② 미배선 `call_tool`은 stub이 아니라 **rmcp 기본 `-32601 Method not found`**(프로토콜 오류)로 둔다 — 임시 stub은 ErrorCode 뒷받침 없는 임의 계약 형태를 발명하는 것이라 단일 ErrorCode 규율 위반이고, 실바이너리 테스트가 이 동작을 고정한다(Step 3가 배선하면서 이 테스트를 성공 경로 테스트로 대체). ③ stdout 순수성은 기존 tracing 구조가 이미 stderr-only라 신규 코드 0 — `-vv` 실바이너리 단언으로 고정. `qsh mcp`는 host runtime이 아니라 `StartupDiagnostic`을 내지 않는다(명시 문서화). ④ **Step 3 범위 추가**: `tool_schemas()`가 `output_schema`를 채우지 않는 갭 발견 — Step 3가 `*Data` 배선과 함께 `Tool::with_output_schema::<Data>()`를 12종에 채우고 conformance가 `schema_for!(Data)`와 묶는다(testing.md L7 문면 대응; fixture는 이때 형태가 바뀌므로 **신규 fixture 추가가 아니라 Step 2 fixture의 의도된 확장**임을 커밋에 명시 — MCP fixture는 qsh.cli/v1 계약 fixture가 아니라 tool 표면 tripwire라 append-only 규율의 적용 방식이 다르다: diff 리뷰 필수). ⑤ 검증 라운드 배치: M6는 step이 M5보다 작아 **Step 2+3 통합 adversarial 1회**를 Step 3 완료 뒤에 돌린다 — call_tool 라우터가 실질 공격면이고 Step 2는 골격이라 결합 검증이 효율·커버리지 모두 낫다(main 세션 결정).

### Step 3 — 값 반환 tool 11종: 역직렬화 → `Ops` → 직렬화

**(a) 범위:** `read_session`을 제외한 11종(`list_hosts`/`get_host`/`list_sessions`/`get_session`/`open_session`/`write_session`/`resize_session`/`close_session`/`exec`/`open_tunnel`/`close_tunnel`)을 얇게 배선한다. tool input → `*Req` 역직렬화, `Ops` 호출, `*Data` → tool output. 오류는 `OpError`의 `ErrorCode`·message·retryable을 MCP tool 오류 표면에 보존(§4.1 #3). ACL은 host 쪽 dispatch가 이미 강제한다(architecture.md §6 — adapter에 검사 로직 0줄, §8.4의 "각 tool call에 동일 ACL"은 이 상속을 말한다).

**(b) crate/파일:** `crates/qsh-cli/src/mcp/mod.rs` 확장.

**(c) 빚지는 테스트:** conformance 하네스 2절 — open_session → write_session → close_session 실 시나리오(testkit ServeGuard 위, M5가 심는 정책 하네스 그대로). 오류 경로 1종(deny 정책 하에서 open_session → `PERMISSION_DENIED` 보존) — M5의 균일 문면이 MCP 표면에서도 그대로임을 단언.

**(d) 완료 판정:** 11종 전부 하네스에서 1회 이상 실구동. adapter 파일에 `std::process`·CLI 문자열 조립 0건(Step 5의 기계 게이트 전까지는 리뷰로).

### Step 4 — `read_session` long-poll + 취소 의미론 (DoD 3)

**(a) 범위:** `read_session`은 cursor-pull primitive의 1회 pull과 1:1이다(architecture.md §3 — 새 스트리밍 경로를 만들지 않는다). `after_sequence`/`ctl_after` 되먹임, `wait_ms` long-poll, `limit_bytes`. 취소(MCP cancellation·client 연결 종료)는 대기 중인 pull만 끊고 세션·PTY는 건드리지 않는다(§8.4·§9).

**(c) 빚지는 테스트:** conformance 하네스 3절 — read long-poll 중 취소 → `get_session`으로 `running` 확인(DoD 3). `next_after` 되먹임 루프로 출력 전순서 보존 1회.

**(d) 완료 판정:** DoD 3 green. long-poll이 `session read --wait`와 같은 pull 소스를 쓰는 것이 코드 구조로 확인됨.

### Step 5 — 기계 게이트: arch-lint ban (DoD 4) + conformance 총합 (DoD 1 마감)

**(a) 범위:** ① `xtask arch`에 MCP adapter 규칙 추가: `crates/qsh-cli/src/mcp/` 안에서 `std::process`(subprocess)·`Command::new`·CLI output 재파싱 패턴을 금지하는 소스 게이트(M5 Step 8의 `source_scan` 선례 — CRLF 정규화 포함). ② conformance 하네스에 남은 시나리오 결합, fixture 등록(`REQUIRED_FIXTURES` 규율 준용). ③ `docs/CLI.md` §8 문면과 구현의 최종 대조.

**(d) 완료 판정:** DoD 1·4·5 전건 green. Windows leg 포함(— MCP는 stdio뿐이라 플랫폼 분기가 없어야 정상이고, 있으면 그것이 버그).

### Step 6 — DoD 2 실접속 캠페인 + 마감

**(a) 범위:** Claude Code를 실제 MCP client로 `qsh mcp`에 붙여 원격 명령 실행을 기록한다(수동 1회, 절차·pass 기준을 `docs/campaigns/m6-mcp.md`에 사전 정의 — M2 mobility 캠페인 선례). 이후 §5 마감 절차.

**(d) 완료 판정:** 캠페인 기록 완료, §5 전 항목 완료.

## 3. 명시적 non-goals (M7+ / P1 유예)

- **`acl_check`의 MCP tool 노출** — ROADMAP M6 범위는 "§8.2의 tool 12종" 문면이고 §8.2 표에 acl 계열이 없다. M5가 만든 `AclCheckReq`/`AclCheckData`는 노출 준비가 돼 있으나(schemars 파생), 13번째 tool 추가는 §8.2 표 개정(additive)이 선행돼야 하는 **별도 결정**이다 — M7(doctor·capabilities 정비)로 이월. 조용히 추가하지 않는다.
- **HTTP/SSE transport** — §8.1이 stdio만 명시. P1.
- **streaming MCP extension** — §8.3이 명시적으로 배제(long-poll 모델).
- **MCP 쪽 trust prompt·pairing** — §8.4 금지 문면 그대로. pairing UX는 M7.
- **`ControlLink`/`DataLink` enum → trait 전환(ADR-0005 P0 부채)** — M3→M4→M5가 연쇄 이월한 부채. M6도 트리거하지 않는다(MCP는 transport에 접촉하지 않는다). P1 입력으로 재기록.
- **`action_of` op 키의 enum 타입화** — M5 Step 8 검증 라운드 P2-3 이월분. MCP tool 이름 상수와 함께 다루면 자연스러우나 M6 DoD와 무관 — 착수는 M6 중 여유가 있을 때만, 없으면 M7.

## 4. 리스크와 감시 항목

- **rmcp 3.x API 변동**(architecture.md §9 리스크 4) — 정확 pin + adapter ≤300줄 격리. 감시: adapter 밖으로 rmcp 타입이 새어 나가지 않는가(`Ops` 시그니처에 rmcp 타입 0).
- **stdout 오염** — 가장 깨지기 쉬운 불변식. tracing 기본 출력·panic hook·M5 시작 진단·`stderr_note!` 계열이 전부 stderr로 가는지. 감시: DoD 5 테스트가 `-vv`로 돈다.
- **tool schema drift** — schemars 생성 schema는 `*Req` 변경에 자동 추종하므로, 의도치 않은 계약 변경이 fixture diff로만 보인다. 감시: fixture는 append-only 규율이 아니라 **diff 리뷰 필수** 규율(스키마 자체가 바뀌는 것이므로) — 단 기존 field 삭제·재해석이 diff에 보이면 그것은 §10 위반이다.
- **cancellation 의미론의 회귀** — long-poll 취소가 pull loop 밖 자원(세션·writer lease)을 건드리면 DoD 3이 잡아야 한다. 감시: 취소 후 `running` 단언이 lease 상태까지 보는가.

### 4.1 구현 중 확정할 값 (해당 step (a)에 근거와 함께 추기)

| # | 질문 | 초안 | 확정 시점 |
|---|---|---|---|
| 1 | rmcp 정확 버전 | 3.x 최신 안정, minor까지 pin | Step 1 |
| 2 | `tools/list` fixture 정규화(순서·기본값 직렬화) | tool 이름 사전순 정렬 후 pretty JSON | Step 1 |
| 3 | `OpError` → MCP 오류 표면 매핑 | tool 실행 오류(`isError: true`) + content에 §3.2 error object 그대로(JSON) — MCP protocol 오류로 승격하지 않음 | Step 1 |
| 4 | `--timeout` 상당의 tool 인자 | 두지 않음 — `wait_ms`(read_session)만; 나머지는 client cancellation에 맡김(§9) | Step 1 |
| 5 | conformance 하네스의 client 구현 | rmcp client가 아니라 raw JSON-RPC(stdin/stdout 직접) — 서버가 SDK 아닌 계약을 지키는지 보는 것이므로 | Step 2 |

## 5. 완료 절차

1. §1 DoD 5항목 전건을 실제 테스트/캠페인 기록으로 확인(체크박스는 근거 green일 때만).
2. 구속 문서 태그 대조: CLI.md §8·§9·§10·§11의 M6 관련 전 문장이 검증됐거나 후속 귀속됐는지 전수 대조.
3. README 갱신: MCP 사용법 절 추가(client 설정 예시 포함), Roadmap 표 M6 → Done.
4. `docs/design/testing.md` 현재 상태 문단에 M6 테스트 층(conformance 하네스) 반영.
5. `docs/ROADMAP.md` "현재 위치"·M6 절 갱신 + 마감 노트(로드맵 소유자 몫).
6. **SC7 외부 보안 리뷰 예약 재확인** — M5 마감 노트가 미완으로 이월한 항목. M8 wire freeze까지의 리드타임이 이번 마일스톤 중에도 소진되고 있다 — 운영자 액션 필요.
7. 이 PLAN.md를 M7 계획으로 전면 교체(§3의 M7 입력 — acl_check tool 노출 결정, action_of enum화 — 을 그 계획으로 이관).
