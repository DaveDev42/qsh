# PLAN.md — M5 실행 계획

> **M5 플래닝 에이전트의 초안이다(2026-08-27). main 세션의 검토·확정 전에는 실행 지시가 아니다.** ROADMAP M5 범위·감사 개정·수용 기준을 실행 순서로 분해했고, 확정되면 이 문서가 완료된 M4용 계획을 전면 교체한다. §4.1의 열린 결정은 전부 **보수적(현행 권한 경계를 넓히지 않는) 기본값**으로 채택해 두었다 — **#1(acl.toml 부재 시 거동):** 전량 deny + 시작 시 운영자 진단, 자동 생성 없음. **#2(정책 행의 auth_path):** 선택 키, 생략 시 `pin` — M1–M4가 실제로 허용하던 경계를 그대로 보존하고 CA 경로 확대는 명시 opt-in. **#3(소유권 기본값):** 소유자 있는 리소스의 action은 `scope = "owned"`가 기본이고 `"any"`가 명시 확대. 세 결정 모두 "정책 엔진이 켜지는 순간 권한이 조용히 넓어지지 않는다"는 한 원칙의 세 얼굴이며, 어느 하나라도 반대로 뒤집으면 그것은 별도 범위 승격이다.

이 문서는 **현재 마일스톤(M5 — ACL 정책 + audit)의 실행 계획**이다. 마일스톤 정의(범위·수용 기준·크기)의 정본은 항상 [`docs/ROADMAP.md`](docs/ROADMAP.md)이며, 이 문서는 그 정의를 바꾸지 않고 실행 순서로 분해한다. **M5가 Done 처리되면 이 문서는 다음 마일스톤(M6 — MCP adapter)의 계획으로 전면 교체된다** — living doc이며 과거 마일스톤의 실행 기록으로 남기지 않는다.

## 1. M5 목표 요약

`docs/ROADMAP.md` "M5 — ACL 정책 + audit" 절 인용:

> - **범위:** TOML 정책 로더, principal 매칭(fingerprint·CA 발급 user/device), action wildcard(`session.*` 형태, 후행 `.*`만), default-deny, PRD §9 action 전체(미구현 기능의 `forward.socks`/`file.*`는 정의하되 항상 deny), `qsh acl check`, 전 privileged op의 구조화 audit.
> - **감사 개정 (2026-08-21) 추가 범위:** ① **audit 수명주기** — "audit 완전성"에서 한 걸음 더: `[audit]` config(회전·크기 상한·retention), 런타임 스레드 밖 비동기 쓰기(현재 동기 blocking I/O), 디스크 만실 시 fail-closed 정책(현재 ENOSPC fail-open). ② **resource-ownership 축** — M3가 넣은 opener-principal P0 결합을 정책 어휘로 승격(리소스에 소유자 개념, 정책이 owner 기준으로 매칭 가능). ③ **거부 메시지 균일성** — deny 응답이 거부된 action/capability를 노출하지 않게 통일. 선례는 `reverse/admit.rs`의 단일 문면 테스트이고, 현재 forward 경로(`server/mod.rs`)의 deny 메시지는 action 이름을 노출한다 — interim allow-all에서는 정보량 0이지만 M5 정책이 켜지는 순간 capability 열거 oracle이 된다.
> - **수용 기준 (DoD):** `qsh acl check` 결과 == 실제 enforcement 결과 (같은 코드 경로임을 표 기반 테스트로 증명). **op registry를 열거해 audit 레코드 없는 op가 있으면 실패하는 테스트** (SC6). Property test: 임의 정책에서 어떤 rule도 커버하지 않는 action은 반드시 Deny.
>   - **(감사 개정)** 모든 `PERMISSION_DENIED` 응답 문면이 동일함을 op 전수로 단언하는 테스트. audit 수명주기 동작 테스트(회전 트리거·상한 준수·디스크 만실 fail-closed).
> - **크기:** 2ew

### DoD 체크리스트 (`docs/ROADMAP.md` M5 "수용 기준" 인용)

- [ ] **DoD 1** — `qsh acl check` 결과 == 실제 enforcement 결과, **같은 코드 경로임을 표 기반 테스트로 증명**. Step 7이 마감한다 — `Ops::acl_check`가 enforcement가 쓰는 바로 그 `Policy::decide`를 호출하고(두 번째 평가기 금지), 표 기반 테스트가 (정책 × principal × auth_path × action × resource) 행마다 CLI envelope의 `decision`과 loopback 하네스의 실제 거동(허용/거부)이 일치함을 단언.
- [ ] **DoD 2** — **op registry를 열거해 audit 레코드 없는 op가 있으면 실패하는 테스트**(SC6). Step 8이 마감한다 — 프로덕션 코드에 사는 op registry(현재는 테스트 안에만 있는 손-작성 표뿐)를 만들고, 각 항목을 실제로 구동해 audit 레코드 유무·action 일치를 단언. `handle_rfwd_close`(현재 무인가·무audit)가 이 테스트가 잡아야 할 실제 갭이다.
- [ ] **DoD 3** — Property test: **임의 정책에서 어떤 rule도 커버하지 않는 action은 반드시 Deny**. Step 2가 마감한다(엔진이 배선되기 전, 순수 평가기 단계에서).
- [ ] **DoD 4 (감사 개정)** — 모든 `PERMISSION_DENIED` 응답 **문면이 동일**함을 **op 전수**로 단언하는 테스트. Step 4가 마감한다.
- [ ] **DoD 5 (감사 개정)** — **audit 수명주기 동작 테스트**(회전 트리거·상한 준수·디스크 만실 fail-closed). Step 3이 마감한다.

M5 크기: 2ew (`docs/ROADMAP.md` M5 "크기"). 이 크기에 대한 정직한 평가는 §4.3에 있다 — 감사 개정 3축과 M4 이관 5건을 더하면 2ew를 넘으며, 무엇을 먼저 세우고 무엇을 명시 이관하는지를 그 절이 제안한다.

### 이 마일스톤이 새로 만드는 것 / 이미 있는 것

**M5가 새로 만드는 것은 "정책"이라는 데이터와 그것을 읽는 평가기, 그리고 audit이 실제로 신뢰할 수 있는 기록이 되게 하는 수명주기뿐이다.** 아래는 이미 있어 M5가 **발명하지 않는다**:

- **인가 지점 전부.** `Authorizer::check(principal, auth_path, action, resource)`는 M1부터 있고(`crates/qsh-core/src/acl/mod.rs`), 호출 지점은 네 곳(`server/mod.rs`의 `authorize`·`authorize_stream`·`authorize_session_control`, `reverse/admit.rs`의 `admit`)이며 전부 **리소스 생성 이전**이다. M5는 이 지점을 옮기지 않는다 — `check`가 돌려주는 값이 `AllowAllPinned`의 상수 판정에서 정책 판정으로 바뀔 뿐이다(`docs/ROADMAP.md` §1 원칙 5: "지점은 M1부터, 엔진은 M5").
- **action 어휘 8종과 `Action::ALL`.** `exec.run`·`session.open`·`session.list`·`session.attach`·`session.control`·`host.reverse`·`forward.local`·`forward.remote`가 이미 `as_str()` 문자열까지 `docs/CLI.md` §2.5 표와 일치한다. M5는 여기에 PRD §9의 나머지 3종(`forward.socks`·`file.read`·`file.write`)을 **정의하되 항상 deny**로 더할 뿐이다.
- **audit 레코드 타입과 그 "payload 무기록" 속성.** `AuditRecord{ts, request_id, principal, action, resource, decision, rule, peer_addr}`가 이미 있고, argv·PTY·키를 담을 **필드 자체가 없다**(`crates/qsh-core/src/audit.rs` 머리말 — 규율이 아니라 타입 수준 속성). `rule: Option<u32>`은 이미 "M5+"로 예약된 채 항상 `null`이다 — M5는 이 필드를 **채운다**.
- **소유권 결합의 원형.** `opener_key(principal, auth_path) = "{auth_path:?}:{principal}"`(`server/mod.rs:2746`)과 `require_opener`(`:648`)가 M3에서 `session.control`에 이미 붙었다. M5는 이것을 발명하지 않고 **정책 어휘로 승격**한다(감사 개정 ②).
- **단일 문면 deny의 선례.** `reverse::registry::host_reverse_denied()`(`registry.rs:511`)와 그것을 세 실패 경로에 대해 단언하는 `every_permission_denied_refusal_carries_the_identical_message()`(`reverse/admit.rs:319`)가 이미 있다. M5는 이 패턴을 **전 op로 일반화**한다(감사 개정 ③).
- **config·trust 파일의 로딩 관용구.** `Config::load`(`config.rs:635`)와 `TrustStore::load`(`trust/mod.rs:70`)가 "부재 → default, 파손 → `CONFIG_ERROR`"를 이미 확립했다. M5는 이 관용구를 **그대로 베끼지 않는다** — acl.toml의 "부재"는 default가 아니라 전량 deny다(§4.1 #1).
- **ErrorCode 전 어휘.** `PERMISSION_DENIED`·`CONFIG_ERROR`·`INVALID_ARGUMENT`가 전부 `docs/CLI.md` §3.3에 있다. **M5는 새 `ErrorCode`를 만들지 않는다**(`CLAUDE.md` "never invent an ad hoc error string").

M5가 실제로 지는 것은 (i) `acl.toml`이라는 새 신뢰 입력 표면과 그 평가기, (ii) enforcement가 상수 판정에서 정책 판정으로 **뒤집히는 단 한 번의 전환**과 그 마이그레이션 이야기, (iii) audit이 "쓰였다고 믿는 기록"에서 "쓰이지 않으면 서비스가 거부되는 기록"으로 바뀌는 수명주기, (iv) 정책이 켜지는 순간 정보 oracle이 되는 두 표면(거부 문면·소유권 판정)의 봉인 — 넷이다.

## 2. 작업 분해 (Step 1..8)

원칙: **모든 step은 완료 시점에 `cargo fmt --all` / `cargo clippy --workspace --all-targets -- -D warnings` / `cargo test`(또는 `cargo nextest run`) / `cargo run -p xtask -- arch` / `cargo deny check` 전부 green을 유지해야 한다.** 이 게이트를 통과하지 못한 상태로 다음 step으로 넘어가지 않는다(`CLAUDE.md` "Before committing"). clippy는 CI 5개 runner의 모든 타깃에서 green이어야 하고, **Windows leg는 clippy뿐 아니라 전체 `cargo nextest run --workspace` + doc-test가 돈다**(`docs/design/testing.md` "현재 상태"). M5가 만지는 코드 대부분(정책 평가기·audit 수명주기·`acl check`)은 플랫폼 무관이라 M4보다 Windows 노출은 작지만, audit 파일 회전의 `0o600`/`0o700` 검사와 rename 의미론은 `cfg(unix)` 분기를 가진다 — 각 step의 완료 판정은 Windows leg의 nextest green을 포함한다.

각 step은 독립적으로 리뷰 가능한 PR 하나 크기다(예외는 Step 6 — 전환 step이라 두 PR로 나누는 경계를 명시한다). 순서는 **계약·어휘 → 순수 평가기 → audit 수명주기 → 거부 문면 봉인 → 소유권 축 → enforcement 전환 → `acl check` → SC6 registry·마감**이며, 그 안에서 다음 네 가지가 순서를 지배한다:

1. **어휘와 문법이 종이로 먼저 확정된다(Step 1).** M5의 진짜 미지수 — (a) `acl.toml`의 정확한 문법과 principal 문자열이 `auth_path`와 어떻게 갈리는가, (b) `forward.socks`/`file.*`의 "항상 deny"가 **어느 층**에서 강제되는가(wildcard `forward.*`가 socks를 삼키지 못하게 하려면 rule 매칭 **이전**이어야 한다), (c) `acl.check`가 operation 목록(`docs/CLI.md` §2.4)에 없다, (d) `[audit]` 섹션이 `architecture.md` §7 레이아웃에는 있으나 `Config` 구조체에는 없다 — 를 `.toml` 문법·JSON DTO·정본 문서에 못박아 구현이 계약을 발명하지 못하게 한다.
2. **엔진은 배선 전에 완성된다(Step 2).** DoD 3의 property test는 정책 엔진이 순수 평가기인 동안에만 값싸게 쓸 수 있다. `AllowAllPinned`가 여전히 프로덕션 정책인 상태로 평가기를 완성하면, Step 6의 전환은 "어느 생성자를 바꾸는가" 하나만 남은 리뷰 가능한 커밋이 된다.
3. **enforcement 전환은 정확히 한 step이고, 그 앞에 감사 개정 3축이 전부 서 있다(Step 3·4·5 → 6).** 정책이 켜지기 **전에** audit이 신뢰 가능해야(①) 전환 이후의 거부가 조사 가능하고, 거부 문면이 균일해야(③) 정책이 capability 열거 oracle이 되지 않으며, 소유권이 정책 어휘가 되어야(②) 전환이 M3의 P0 결합을 우회하지 않는다. 세 축을 전환 뒤로 미루면 그 사이 창(window) 동안 정확히 ROADMAP이 경고한 결함이 실재하게 된다.
4. **`acl check`는 엔진 뒤에 온다(Step 7).** DoD 1은 "같은 코드 경로"를 요구하므로, 평가기가 하나로 존재한 뒤에 그 위에 얇은 조회 op을 얹는 것만이 이 DoD를 구조로 만족시킨다 — 순서를 뒤집으면 설명용 평가기와 강제용 평가기가 갈라진다.

`docs/ROADMAP.md` §1 원칙 5번("인가 **지점**은 M1부터, 정책 **엔진**은 M5")이 이 마일스톤의 존재 이유이고, 같은 문서 §1 원칙 7번 (b)("모든 op 앞에 `Authorizer::check` + audit 기록")가 DoD 2(SC6 registry)가 **지금** 기계화되어야 하는 이유다 — M1부터 지켰다고 믿어 온 불변식을 처음으로 열거해 증명하는 것이 이 마일스톤이다.

### 전 step 공통 계약 규율

- `qsh.cli/v1`·`qsh.event/v1`은 **additive-only**(optional 필드·새 event type·열린 문자열의 새 값만; 삭제·type 변경·의미 변경은 `/v2`), `crates/qsh-cli/tests/fixtures/cli-v1/`의 fixture는 **append-only**(기존 파일 편집·삭제 금지) — `docs/CLI.md` §10, `docs/design/testing.md` L6, `CLAUDE.md` "Contract stability rules". M5의 신규 fixture는 `acl.check.allow.json`·`acl.check.deny.json`(신규)과 **`error.PERMISSION_DENIED.json`**(신규 — Step 6이 `DEFERRED`에서 제거하고 `REQUIRED_FIXTURES`에 등록)이다. `acl.check`라는 **새 operation 이름을 §2.4 목록에 더하는 것은 additive**다(열린 목록에 값 추가 — `docs/CLI.md` §10과 M3의 `connection_mode` 선례).
- **거부 문면(`error.message`)은 계약이 아니다.** `docs/CLI.md` §3.2가 "`message`는 사람을 위한 설명이다. 자동화는 `code`와 구조화된 `details`만 사용해야 한다"고 못박았으므로, Step 4의 문면 통일은 `qsh.cli/v1` 호환성 사건이 아니다. 다만 §3.2의 **예시 문안**(`"peer is not allowed to attach to this session"`)은 새 상수와 어긋나게 되므로 Step 1이 정본 문서에서 먼저 갱신한다(각 문서 머리말의 "구현이 어긋나면 문서를 먼저 갱신").
- **M5는 새 `ErrorCode`를 만들지 않는다.** 정책 거부 = `PERMISSION_DENIED`(항상 동일 문면), acl.toml 부재·파손 = 운영자에게 `CONFIG_ERROR`(원격 peer에게는 절대 노출되지 않는다 — §4.1 #4), `acl check`의 잘못된 인자 = `INVALID_ARGUMENT`, `forward.socks`/`file.*` = `PERMISSION_DENIED`(기능 미구현이 아니라 **정책상 항상 거부**이므로 `UNSUPPORTED`가 아니다 — `-D` 플래그 자체의 `UNSUPPORTED`와는 층이 다르다, §4.1 #5).
- 기계 모드 stdout은 순수 JSON만(`docs/CLI.md` §2.2). M5가 새로 만드는 운영자 진단 중 audit degraded·파일 모드 경고는 **stderr 한 줄 JSON**(tracing target `qsh::acl`·`qsh::audit`)이고, 정책 로드 실패의 시작 진단은 **stderr 평문 블록**(`StartupDiagnostic::render` — 6a 확정: doctor.rs 선례처럼 문안 정본은 core에 두고 CLI는 출력만 한다)이다. 어느 쪽도 acl.toml 원본 소스 라인을 덤프하지 않는다 — 단 Step 2가 의도적으로 유지한 문법 토큰 echo 3종(unknown action/auth_path/scope, ≤128B·한 줄 이스케이프)은 예외로 남고(6a 검증 라운드 확정 ①), 최소 정책 예시가 trust store의 pinned peer 이름을 채우는 것은 마이그레이션 이야기 1의 의도된 동작이다(acl.toml이 아니라 trust.toml에서 온다).
- **audit 레코드는 구조적이다.** `op`·`principal`·`resource`·`decision`·`rule`만 남기고 payload·argv·키·정책 파일 원문은 어느 필드로도 남기지 않는다(`crates/qsh-core/src/audit.rs` 머리말, `CLAUDE.md` "audit records are structural"). M5가 필드를 하나라도 더하면(`auth_path`) `record_has_only_structural_fields` 테스트의 key 열거를 함께 갱신해 그 속성이 계속 기계 검사되게 한다.
- **리소스는 인가 후에만 생성한다** — M5는 이 순서를 새로 만들지 않지만 **깨뜨릴 수 있다**: 정책 로딩이 첫 요청 시점의 lazy load가 되면 "로드 중 판정 불가" 창이 생기고, 그 창에서 fail-open하면 M1부터의 불변식이 무너진다. 정책은 **프로세스 시작 시 1회** 로드하고, 로드 실패는 그 자체로 전량 deny다(§4.1 #1·#6).
- 테스트는 `sleep()` 금지, chaos는 seeded, 포트는 0 바인딩(`docs/design/testing.md` CI 규율). Step 3의 회전·ENOSPC 테스트는 실디스크를 채우지 않고 **주입형 sink**(쓰기 실패를 반환하는 테스트 double)와 tempdir로 결정적으로 돌린다.

---

### Step 1 — 계약 확정: action 어휘 완성(PRD §9 전체) + `acl.toml` 문법 + `acl.check` operation·JSON DTO + `[audit]` config 계약 + 정본 문서 갱신

**(a) 범위:** M5가 구현 중에 발명하면 안 되는 것을 전부 이 step에서 계약으로 고정한다. 코드는 `qsh-proto`(계약 타입)와 `qsh-core`의 어휘(`acl::Action`)·config 구조체, 그리고 문서만 건드린다. **평가기도, 로더도, 배선도 이 step에는 없다.**

*action 어휘 완성 (`crates/qsh-core/src/acl/mod.rs`)*: `Action`에 `ForwardSocks`(`"forward.socks"`)·`FileRead`(`"file.read"`)·`FileWrite`(`"file.write"`)를 더해 PRD §9의 11종을 전부 채우고 `ALL`을 `[Action; 11]`로 늘린다. 이 셋은 **항상 deny**이므로 그 성질을 타입에 박는다 — `Action::is_always_denied()`(또는 `Action::implemented()`의 역) 하나를 두고, 평가기가 **rule 매칭 이전에** 이 술어로 먼저 거부하도록 Step 2가 구현한다. 어휘만으로는 부족하다는 것이 이 설계의 핵심이다: `allow = ["forward.*"]`라고 쓴 정책은 wildcard 매칭만으로는 `forward.socks`를 삼키므로, "정의하되 항상 deny"(`docs/ROADMAP.md` §3 유예 가드레일 표)는 **매칭 층이 아니라 그 앞의 게이트**여야 성립한다.

*`acl.toml` 문법 확정 (문서 + 파서 계약)*: PRD §9의 예시를 실제 문법으로 승격한다.

```toml
[[acl]]
principal = "user:dave"        # "device:<name>" | "user:<name>" | "fp:<sha256-hex>"
auth_path = "pin"              # optional — "pin" | "ca". 생략 시 "pin" (§4.1 #2)
allow     = ["session.*", "exec.run", "forward.local"]
scope     = "owned"            # optional — "owned" | "any". 생략 시 "owned" (§4.1 #3)
```

- **principal 매칭은 정확 일치**다(`docs/design/architecture.md` §6). `Principal`의 `Display`(`device:<name>`/`user:<name>`/`fp:<...>`, `crates/qsh-transport/src/identity.rs`)와 문자열 비교이며, `user:dave`는 `user:dave2`에 매칭되지 않는다(`docs/design/testing.md` L8 마지막 문단이 지목한 그 property).
- **action wildcard는 후행 `.*`만**이다(같은 §6 — 중간 glob 금지, `qsh acl check`의 설명 가능성 유지). `session.*`는 `session.`으로 시작하는 action에 매칭된다. 어휘가 닫힌 집합(`Action::ALL`)이므로 `session.control.escalate` 같은 가상의 깊은 이름 문제는 **애초에 발생하지 않는다** — 그 대신 로더가 `Action::ALL`의 어느 것에도 매칭되지 않는 패턴을 **로드 시점 `CONFIG_ERROR`**로 거부한다(오타가 조용히 무권한 rule이 되지 않게).
- **`auth_path`**: 정책 행이 pin 경로로 인증된 peer에만 적용되는지 CA 경로도 포함하는지. 생략 시 `"pin"`(§4.1 #2). 이 키가 필요한 이유는 `Principal` 하나로는 pin과 CA를 구별할 수 없기 때문이며(`qsh-transport::tls::AuthPath` 문서, `server::opener_key`가 이미 같은 이유로 `auth_path`를 소유권 키에 접어 넣는다), 구별하지 않으면 CA가 발급한 `qsh://device/hermes` leaf가 pinned `device:hermes`의 권한을 그대로 상속한다.
- **`scope`**: 소유자 개념이 있는 리소스(세션·remote forward)에 대한 action을 소유자에게만 허용할지(`"owned"`, 기본) 임의 소유자에게 허용할지(`"any"`). 소유자 개념이 없는 action(`exec.run`·`host.reverse`·`forward.local`)에는 무의미하며 무시된다(문서에 명시). Step 5가 구현한다.
- **평가 순서**(정본으로 못박는다): ① 항상-deny action 게이트 → ② principal 정확 일치 + `auth_path` 일치 → ③ action 패턴 매칭 → ④ `scope` 판정 → 매칭 rule 없으면 **Deny**. 매칭된 rule의 배열 index가 `AuditRecord.rule`이 되고 `acl check`의 `rule`이 된다. rule은 **첫 매칭이 이긴다**(deny rule은 없다 — allow-only 문법이므로 순서 의존 정책 충돌이 존재하지 않는다).

*JSON 계약 (`crates/qsh-proto/src/types.rs`)*: `AclCheckReq { principal: String, action: String, resource: Option<String>, auth_path: Option<String> }`, `AclCheckData { principal, action, resource, auth_path, decision: "allow"|"deny", rule: Option<u32>, policy: AclPolicyRef }`, `AclPolicyRef { path: String, rules: u32, loaded: bool }`. `decision`·`auth_path`는 `connection_mode`와 동형의 **열린 문자열**이다. `policy.loaded=false`는 acl.toml이 없거나 파손된 상태를 운영자에게 그대로 보여 준다(그때 `decision`은 항상 `"deny"`).

*Operation 이름 (`docs/CLI.md` §2.4·§2.5)*: `acl.check`를 operation 목록에 추가하고, §2.5 매핑 표의 마지막 행("인가 불요 — local operation")에 `acl.check`를 넣는다 — 이 op은 **이 머신의 정책 파일을 이 머신에서 조회**하는 것이지 원격 peer가 요청하는 operation이 아니다. `qsh serve`가 원격으로 노출하는 표면이 아님을 §2.5와 §6에 명시한다(원격 peer에게 정책 조회를 허용하면 그 자체가 capability 열거 oracle이다).

*`[audit]` config 계약 (`crates/qsh-core/src/config.rs` + `docs/design/architecture.md` §7)*: `architecture.md` §7의 레이아웃 줄에 이미 `[audit]`이 적혀 있으나 `Config` 구조체에는 없다. 이 step이 `AuditConfig`를 정의한다 — `path`(기본 `Paths::audit_log()`), `max_bytes`(회전 트리거, 기본 제안 64 MiB), `retain`(회전본 보관 개수, 기본 제안 5), `queue_depth`(비동기 writer의 유계 큐, 기본 제안 1024). **`fail_closed` 노브는 두지 않는다** — ROADMAP은 이것을 옵션이 아니라 정책 변경("디스크 만실 시 fail-closed 정책")으로 쓴다. 값의 최종 확정은 §4.2.
  `architecture.md` §6이 언급하는 opt-in `audit.log_argv`는 **M5에서 구현하지 않는다**(§3) — argv를 audit에 넣는 것은 "payload 무기록"의 타입 수준 속성을 깨는 변경이라 별도 결정이 필요하다.

*정본 문서 갱신(구현 전에)*:
- `docs/CLI.md` — §2.4에 `acl.check` 추가, §2.5 "인가 불요" 행에 `acl.check` 추가, §3.2 예시 error `message`를 Step 4의 균일 문면으로 교체, **신규 §6.15 `qsh acl check`** 계약(인자·`data` 형태·human 출력·exit code), §6.12/§6.13에 "정책 파일이 없거나 파손이면 시작 시 운영자 진단 + 전량 deny" 문단 추가.
- `docs/design/architecture.md` — §6을 실현으로 갱신: acl.toml 평가 순서(위 5단계), `auth_path`·`scope` 키의 존재와 기본값, audit 레코드 필드 목록에 `auth_path` 추가, audit이 **fail-closed**임을 명문화(현재 §6은 "결정당 한 줄"만 말하고 실패 시 거동을 말하지 않는다). §7의 `[audit]` 줄을 실제 키 목록으로 확장.
- `docs/design/protocol.md` — §7의 두 문장("이보다 좁은 터널 전용 할당량(principal별·forward별)은 **M5 정책 엔진 범위**", "이 갭을 좁히는 터널 전용 할당량은 … M5 정책 엔진 범위")을 **M8 적대적 부하 게이트 귀속으로 정정**한다(§4.1 #7 — ROADMAP M5 DoD에 할당량 기준이 없고 M8 감사 개정 ③이 `[serve].max_sessions`·principal별 쿼터를 소유한다). 문서를 먼저 고치고 구현은 만들지 않는다.
- `docs/design/testing.md` — L2에 "정책 평가기 property(default-deny·wildcard·principal 정확 일치)" 행, L6에 "`acl check` fixture + 거부 문면 상수-문서 일치 게이트(`tunnel_docs.rs`/`doctor_docs.rs` 선례)" 행, L8의 마지막 문단("ACL glob 평가기는 fuzz보다 property test가 적합")을 M5 실현으로 갱신, 신규 "audit 수명주기(회전·retention·쓰기 실패 fail-closed)" 행.
- `docs/PRD.md` — §9는 **바꾸지 않는다**(구속 문서, M5는 이행할 뿐). 다만 §9의 TOML 예시와 Step 1이 확정한 문법이 어긋나면 그때는 PRD가 정본이므로 문법을 PRD에 맞춘다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/acl/mod.rs` (확장 — `Action` 3종 추가, `ALL: [Action; 11]`, `is_always_denied()`)
- `crates/qsh-proto/src/types.rs` (확장 — `AclCheckReq`/`AclCheckData`/`AclPolicyRef`)
- `crates/qsh-core/src/config.rs` (확장 — `AuditConfig`, `Config`에 `audit` 필드; `[acl]` 섹션은 두지 않는다 — 정책은 `config.toml`이 아니라 `acl.toml`이라는 별도 파일이다(`architecture.md` §7))
- `docs/CLI.md`, `docs/design/architecture.md`, `docs/design/protocol.md`, `docs/design/testing.md` (갱신)
- **(파급 주의):** `Action::ALL`의 크기가 8→11이 되면 `Action::ALL`을 배열 길이로 쓰는 코드·테스트가 함께 갱신된다(`acl/mod.rs`의 `action_and_decision_strings`가 이미 "count에 기대지 말고 이름을 명시하라"고 써 두었으므로 그 규율대로 새 3종을 이름으로 단언한다). 새 variant는 아직 어느 호출 지점도 갖지 않으므로 dispatch에는 파급이 없다.

**(c) 빚지는 테스트 (`docs/design/testing.md` L0·L2·L6):** 새 3종의 `as_str()` 문자열이 PRD §9 목록과 일치(하드코딩 0), `Action::ALL`이 11종 전부를 포함하고 문자열이 중복되지 않음, `is_always_denied()`가 정확히 그 3종에 참, `AclCheckReq`/`AclCheckData`의 serde roundtrip + schemars 스키마 생성, `AuditConfig`의 TOML 파싱(부재 시 기본값·미지 키 무시 — `docs/CLI.md` §2.3), `[audit]` 기본값이 문서 값과 일치하는 단언. **문서 일치 게이트**: PRD §9의 action 11종 목록과 `Action::ALL`이 어긋나면 실패하는 L6 테스트(`crates/qsh-core/tests/acl_docs.rs` 신규 — `tunnel_docs.rs`/`doctor_docs.rs`와 동형).

**(d) 완료 판정:** L0/L2/L6 green. **관찰 가능한 동작 변화 0** — `AllowAllPinned`가 여전히 프로덕션 정책이므로 기존 테스트가 하나도 수정되지 않고 green, 기존 fixture 바이트 단위 불변. `xtask arch` green(`qsh-proto`는 여전히 무의존, 새 DTO는 계약 타입뿐). Windows leg nextest green. 위 문서 갱신이 같은 PR에 포함. **DEFERRED 판정:** 이 step은 어떤 `ErrorCode`도 새 CLI envelope 경로를 얻지 않으므로 `crates/qsh-cli/tests/fixtures.rs`의 `DEFERRED`는 무변경.

**(e) 인용:** `docs/PRD.md` §9(action 11종·principal 정의·TOML 예시·인증 전 리소스 금지), `docs/CLI.md` §2.3·§2.4·§2.5·§3.2·§3.3·§10, `docs/design/architecture.md` §6(정확 일치·후행 `.*`·default deny·fail closed·audit 필드)·§7(config·state 경로), `docs/design/testing.md` L2·L6·L8, `docs/ROADMAP.md` M5 범위·§1 원칙 5·§3 유예 가드레일 표(`forward.socks`·`file.*` "정의·항상 deny").

---

### Step 2 — 정책 엔진: `acl.toml` 로더 + 순수 평가기 + **default-deny property test** — **DoD 3**

**(a) 범위:** Step 1이 종이로 확정한 문법을 `qsh-core` 안의 **순수 평가기**로 실물화한다. 이 step은 **아무것도 배선하지 않는다** — 프로덕션은 여전히 `AllowAllPinned`다. 그래서 이 step의 완료 판정에 "기존 테스트 무수정 green"이 들어간다.

**로더(`crates/qsh-core/src/acl/load.rs` 신규).** `PolicySource::load(paths) -> PolicyLoad`. 세 상태를 **명시적으로** 구별한다: `Loaded(Policy)` / `Missing` / `Invalid(OpError{CONFIG_ERROR})`. `Config::load`(`config.rs:635`)의 "부재 → default" 관용구를 **의도적으로 따르지 않는다** — 정책 파일의 부재는 "기본 설정"이 아니라 "아직 아무에게도 권한을 주지 않았다"이며, `architecture.md` §6이 "acl.toml이 없거나 파싱 불가 → 전부 deny + 운영자에게 `CONFIG_ERROR` 노출"이라고 이미 못박았다. 세 상태 모두 유효 정책은 각각 `Policy` / `DenyAll` / `DenyAll`이고, **부분 로드는 없다**(rule 하나가 파손이면 파일 전체가 `Invalid` — 반쯤 적용된 정책은 운영자가 읽은 파일과 다른 것을 강제한다).

**평가기(`crates/qsh-core/src/acl/policy.rs` 신규).** `Policy { rules: Vec<Rule> }`, `Rule { principal: String, auth_path: AuthPath, allow: Vec<ActionPattern>, scope: Scope }`, `ActionPattern::{Exact(Action), Prefix(&'static str)}`. 핵심 진입점은 하나다:

```
Policy::decide(&self, principal: &Principal, auth_path: AuthPath, action: Action, resource: ResourceRef<'_>) -> Verdict
Verdict { decision: Decision, rule: Option<u32> }
```

`Authorizer` trait이 `Decision`만 돌려주므로(`acl/mod.rs:123`) **trait 시그니처를 `Verdict` 반환으로 바꾼다** — `AuditRecord.rule`을 채우려면 판정과 함께 매칭 rule index가 나와야 하고, 이것은 Rust 내부 API이지 계약이 아니다(§4.1 #8). `AllowAllPinned`·`DenyAll`은 `rule: None`을 돌려주도록 기계적으로 갱신한다. `ResourceRef`는 이 step에서는 `{ id: &str }`뿐이고 `owner` 필드는 Step 5가 더한다(그때 `scope`도 살아난다) — 지금은 `scope`를 파싱·보존만 하고 판정에 쓰지 않으며, 그 사실을 코드 주석과 테스트로 못박는다.

**항상-deny 게이트.** `action.is_always_denied()`가 참이면 rule을 **한 줄도 보기 전에** `Verdict{Deny, rule: None}`이다. `allow = ["forward.*"]`도, `allow = ["forward.socks"]`를 직접 쓴 정책도 통과하지 못한다. 후자의 경우 로더가 로드 시점에 운영자 경고를 stderr에 한 줄 남긴다(정책 파일이 주지 못할 권한을 주려 하고 있다는 사실은 조용히 넘어갈 일이 아니다) — 그러나 `CONFIG_ERROR`로 시작을 막지는 않는다(존재하는 action 이름이므로 문법 오류가 아니다).

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/acl/load.rs` (신규 — `PolicySource`, `PolicyLoad`, TOML 파싱, 패턴 검증)
- `crates/qsh-core/src/acl/policy.rs` (신규 — `Policy`/`Rule`/`ActionPattern`/`Scope`/`Verdict`, `Policy::decide`, `impl Authorizer for Policy`)
- `crates/qsh-core/src/acl/mod.rs` (확장 — `Authorizer::check` → `Verdict` 반환, `ResourceRef` 도입, 재수출)
- `crates/qsh-core/src/server/mod.rs`·`reverse/admit.rs` (기계적 갱신 — 네 호출 지점이 `Verdict`를 받아 `decision`을 쓰고 `rule`을 `AuditRecord`에 전달; 동작 변화 없음)
- `crates/qsh-core/src/audit.rs` (확장 — `AuditRecord::now`/`connection_level`가 `rule: Option<u32>`을 인자로 받는다; `auth_path` 필드 추가는 Step 3과 함께)

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L8):**
- **DoD 3 — default-deny property**: `proptest`로 임의의 `Policy`(임의 principal 문자열·임의 패턴 집합·임의 `auth_path`)와 임의의 `(principal, auth_path, action)`을 생성해, **어떤 rule도 그 action을 커버하지 않으면 반드시 `Deny`**임을 단언. 커버 판정은 평가기와 독립한 naive oracle(패턴을 문자열로 전개해 `Action::ALL`과 대조)로 계산해 평가기와 대조한다.
- wildcard property: `session.*`는 `session.open`/`list`/`attach`/`control`에 매칭하고 `exec.run`·`host.reverse`에는 매칭하지 않는다. 접두가 `.`에서 끊기지 않는 매칭(예: `session*`)은 문법상 존재하지 않는다(로더가 거부).
- principal property: `user:dave`가 `user:dave2`·`user:dav`·`device:dave`에 매칭되지 않는다(정확 일치).
- `auth_path` property: `auth_path` 생략 rule은 `AuthPath::Ca` 요청을 절대 허용하지 않는다.
- 항상-deny: `forward.socks`·`file.read`·`file.write`는 `allow = ["forward.*", "file.*", "session.*", "exec.run"]`처럼 최대한 관대한 정책 아래서도 `Deny`이고 `rule: None`이다.
- 로더: 부재 → `Missing`(유효 정책 `DenyAll`), 파손 TOML → `Invalid(CONFIG_ERROR)`, 미지 action 패턴 → `Invalid`, 미지 키는 무시(`docs/CLI.md` §2.3), 빈 `[[acl]]` 배열 → `Loaded`이되 모든 판정이 `Deny`.
- rule index: 여러 rule이 매칭 가능할 때 **첫 매칭의 index**가 나온다.

**(d) 완료 판정:** **DoD 3 green.** **관찰 가능한 동작 변화 0** — 기존 테스트가 하나도 수정되지 않고 green(단, `Authorizer::check` 시그니처 변경에 따른 **기계적** 갱신은 허용하고 그 diff가 순수 기계적임을 리뷰에서 확인), fixture 바이트 단위 불변. `Policy`가 프로덕션의 어느 생성자에도 아직 나타나지 않음을 grep으로 확인(전환은 Step 6). `xtask arch` green. Windows leg nextest green. **DEFERRED 판정:** 무변경.

**(e) 인용:** `docs/design/architecture.md` §6(정확 일치·후행 `.*` only·default deny·fail closed·acl.toml 부재 시 전량 deny), `docs/PRD.md` §9(TOML 형태·principal 정의), `docs/CLI.md` §2.3(미지 키 무시)·§2.5, `docs/design/testing.md` L2·L8("ACL glob 평가기는 fuzz보다 property test가 적합"), `docs/ROADMAP.md` M5 범위·DoD 3.

---

### Step 3 — audit 수명주기(감사 개정 ①): 비동기 writer + 회전·크기 상한·retention + **쓰기 실패 fail-closed** — **DoD 5**

**(a) 범위:** ROADMAP 감사 개정 ①을 전부 이 step이 진다. 정책 전환(Step 6)보다 **먼저** 오는 이유는 하나다 — 정책이 켜진 뒤의 거부는 조사 가능해야 하고, 지금의 audit은 조사 가능하지 않다: 디스크가 차면 `tracing::error!` 한 줄 남기고 **레코드를 조용히 버린다**(`crates/qsh-core/src/audit.rs`의 `FileAuditSink::record` — `AuditSink::record`가 `()`를 반환하므로 호출자가 실패를 **구조적으로 관측할 수 없다**).

**비동기 쓰기.** 현재 `FileAuditSink::append`는 레코드마다 `OpenOptions::open` + `write_all` 두 번을 **동기 blocking I/O**로 수행하고, 이 호출은 `Server::authorize`류가 `async fn` 핸들러 안에서 부르므로 그대로 tokio worker 스레드를 막는다. 이 step은 `record()`를 **유계 채널로의 enqueue**로 바꾸고 전용 writer task(또는 `spawn_blocking` 전용 스레드) 하나가 파일 핸들을 **열어 둔 채** 순차 append한다. 파일 핸들을 유지하는 것이 회전 회계(누적 바이트)의 전제이기도 하다.

**회전·상한·retention.** writer가 누적 바이트를 세다가 `[audit].max_bytes`를 넘으면 `audit.log` → `audit.log.1`로 rename하고 새 파일을 `0o600`으로 연다; `audit.log.N`은 `retain` 개를 넘으면 가장 오래된 것부터 unlink한다. rename 기반이므로 열린 핸들이 있는 독자가 있어도 안전하고, 부분 줄이 남지 않는다(항상 줄 경계에서 회전).

**fail-closed(ROADMAP ①의 핵심).** `AuditSink::record`가 `Result<(), AuditError>`를 반환하도록 trait을 바꾸고, 네 인가 지점이 **판정 결과와 무관하게** 기록 실패를 **거부**로 처리한다. 실패의 정의는 둘이다: (i) 유계 큐가 가득 참(backpressure), (ii) writer가 치명적 I/O 오류(ENOSPC·EROFS 등)를 만나 **degraded 래치**가 걸림 — 래치는 이후 성공적 쓰기가 일어나야 풀린다. 두 경우 모두 peer에게는 Step 4의 **균일 `PERMISSION_DENIED`**가 나가고(감사 불가 상태를 peer가 구별할 수 있으면 그 자체가 신호다), 운영자에게는 stderr 진단(`qsh::audit`, degraded 진입·해제 각 1회)이 나간다. 순서는 **판정 → 기록 시도 → (기록 성공 시에만) 리소스 생성**이며, `authorize_session_control`이 이미 확립한 "단일 terminal 레코드" 규율을 그대로 유지한다.
  fail-closed의 경계: **handshake 거부 레코드**(`AuditRecord::handshake_rejected`)는 이미 연결을 거부하는 경로라 fail-closed가 자명하고, 기록 실패가 거부를 뒤집을 여지가 없다 — 이 경로는 enqueue 실패를 진단만 남기고 거부를 유지한다(더 안전한 쪽으로만 실패한다).

**`auth_path` 필드 추가.** 레코드에 `auth_path`(`"pin"`/`"ca"`)를 더한다 — 구조적 필드이고 payload가 아니며, pin/CA가 같은 principal 문자열을 낼 수 있는 이상(§4.1 #2) 이것 없이는 사고 조사에서 "누가"를 복원할 수 없다. `record_has_only_structural_fields`의 key 열거와 `architecture.md` §6 필드 목록을 함께 갱신한다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/audit.rs` (대폭 확장 — `AuditSink::record -> Result`, `AuditError`, `AuditRecord.auth_path`, `AuditRecord::now`/`connection_level`/`handshake_rejected` 시그니처)
- `crates/qsh-core/src/audit/writer.rs` (신규 — 유계 큐 + writer task + 회전/retention + degraded 래치)
- `crates/qsh-core/src/config.rs` (확장 — Step 1의 `AuditConfig` 값이 실제로 소비되는 지점)
- `crates/qsh-core/src/serve.rs` (확장 — `host_runtime`이 `FileAuditSink::new(path)` 대신 config 기반 회전 sink를 만들고 writer task를 띄운다; `HostRuntime.audit`의 타입 갱신)
- `crates/qsh-core/src/server/mod.rs`·`reverse/admit.rs` (확장 — `record()` 실패를 deny로 처리, 네 지점 전부)
- `crates/qsh-core/src/audit.rs`의 `MemoryAuditSink`·`NullAuditSink` (갱신 — `Result` 반환; 신규 `FailingAuditSink`(테스트 double)로 ENOSPC를 결정적으로 주입)
- **(부수 정리, 이 step에 귀속):** `Server::authorize_stream`이 연결 수준 결정에 `request_id: 0`을 하드코딩하는 알려진 불일치(`audit.rs:73-76`의 "next behavior-change window" 주석)를 `AuditRecord::connection_level`(`request_id: "-"`)로 마이그레이션한다 — 이 step이 바로 그 behavior-change window이고, SC6 registry(Step 8)가 레코드를 열거하기 전에 표기가 통일돼 있어야 한다.

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L6 + 신규 audit 행):**
- **DoD 5 — 회전 트리거**: `max_bytes`를 작게 준 tempdir sink에 레코드를 밀어 넣어 `audit.log.1`이 생기고 `audit.log`가 새로 시작됨, 모든 줄이 유효 JSON이며 **줄이 잘리지 않음**, 회전 경계에서 레코드 유실 0(총 레코드 수 == 모든 파일의 줄 합).
- **DoD 5 — 상한 준수**: `retain = 2`에서 회전 3회 후 파일이 `audit.log`+`audit.log.1`+`audit.log.2`뿐이고 그 이상은 unlink됨. 디렉터리 총 바이트가 `max_bytes * (retain + 1)`의 유계 안.
- **DoD 5 — 디스크 만실 fail-closed**: `FailingAuditSink`(ENOSPC 반환)를 물린 `Server`에서 **정상적으로 허용되어야 할** op(예: `AllowAllPinned` 아래 pinned peer의 `session.open`)가 `PERMISSION_DENIED`로 거부되고 **세션이 하나도 생기지 않음**을 단언. degraded 해제 후 같은 op이 성공함도 단언(래치가 영구가 아님).
- 큐 포화: `queue_depth`를 1로 두고 writer를 정지시킨 상태에서 두 번째 결정이 거부됨(backpressure = fail-closed).
- 비동기성: 인가 경로에서 파일 I/O가 호출 스레드를 막지 않음 — writer를 막아 둔 상태에서도 `record()`가 즉시 반환(큐 여유가 있는 동안)함을 단언. `sleep()` 없이 채널 신호로.
- 권한: 회전으로 새로 생긴 파일도 `0o600`, 디렉터리 `0o700`(`cfg(unix)`).
- `auth_path` 필드가 레코드에 실리고 key 열거 테스트가 갱신됨.

**(d) 완료 판정:** **DoD 5 green.** 정책은 여전히 `AllowAllPinned`(전환은 Step 6) — 그러나 **동작 변화가 하나 있다**: audit을 쓸 수 없으면 이제 거부한다. 이는 ROADMAP ①이 명시적으로 요구한 변화이므로 조용한 회귀가 아니며, README "Known limitations"에 해당 문장을 이 step에서 추가한다. 기존 테스트 중 audit 실패를 무시하던 것이 있으면 갱신하고 그 목록을 PR 본문에 남긴다. Windows leg nextest green(rename·unlink 의미론의 `cfg` 분기 확인). **DEFERRED 판정:** `PERMISSION_DENIED`는 여전히 CLI 바이너리 envelope 경로를 얻지 못한다(이 경로는 `qsh serve` 내부 상태를 CLI에서 강제할 수단이 없다) — `DEFERRED` 무변경, 사유 문자열에 "audit degraded도 producer지만 CLI에서 결정적으로 유발 불가"를 추기.

**(e) 인용:** `docs/ROADMAP.md` M5 감사 개정 ①·DoD(감사 개정 2번째 문장), `docs/design/architecture.md` §6(결정당 한 줄 JSONL·필드 목록·"오류 시 개방은 존재하지 않는다")·§7(state 경로), `docs/PRD.md` §9(로그에 key·PTY·command 내용 무기록)·§15 SC6, `docs/CLI.md` §2.2(stdout 순수성)·§3.3, `docs/design/testing.md` CI 규율(sleep 금지·tempdir), `CLAUDE.md` "Fail closed on any ambiguous auth/ACL state".

---

### Step 4 — 거부 문면 균일성(감사 개정 ③): 단일 상수 + **op 전수 단언** — **DoD 4**

**(a) 범위:** ROADMAP 감사 개정 ③. 오늘 프로덕션에는 **서로 다른 세 가지 거부 문면**이 있다:
1. `Server::permission_denied`(`server/mod.rs:609`)의 `format!("peer is not allowed to {action} on this host")` — **action 이름이 그대로 박힌다**. `forward.local`의 inline 거부(`:2130`)가 같은 문안을 복제한다. `crates/qsh-testkit/tests/session_loopback.rs:566`이 이 문자열을 바이트 단위로 핀하고 있다.
2. `reverse::registry::host_reverse_denied()`(`registry.rs:511`)의 고정 문자열 — 한 seam 안에서는 균일하지만 문자열 안에 `host.reverse`가 들어 있다.
3. `localctl` 데몬의 `HubSendError::NotOwner` → `"this forward is owned by another client on this host"`(`localctl/daemon.rs:848`).

**(Step 3 이월, 2026-08-27)** Step 3의 fail-closed로 **audit-degraded 상태가 문면 1의 새 producer가 됐다** — allow 판정이어도 기록 실패면 `"peer is not allowed to {action} on this host"`가 나간다(검증 라운드 실측). 이 step의 단일 상수 전환은 이 seam(4개 인가 지점의 기록-실패 분기)도 반드시 포함해야 한다.

interim allow-all에서는 정보량이 0이지만, 정책이 켜지는 순간 1과 2는 **capability 열거 oracle**이 된다: 거부된 요청마다 "너에게 없는 권한의 이름"을 알려 주는 것이기 때문이다.

**해결.** `qsh-core`에 단일 상수를 둔다 — `qsh_core::acl::PERMISSION_DENIED_MESSAGE`, 제안 문안 **`"peer is not allowed to perform this operation on this host"`**(action·capability·리소스·principal 어느 것도 담지 않는다; 최종 문안은 §4.2). 1과 2의 모든 생성 지점이 이 상수 하나를 쓰고, `Server::permission_denied(request_id, action)`은 `action`을 **audit 기록용으로만** 받고 문면에는 쓰지 않는다(시그니처는 유지 — audit 레코드의 action은 여전히 정확해야 한다).

**(a)-추기 — 구현 확정 (2026-08-27).** ① DoD 4의 seam 표는 `qsh_core::acl::DENY_SEAMS`(acl/registry.rs)로 실재화 — Step 8 SC6이 같은 표를 소비한다. ② **항상-deny 3종은 registry에 행이 없다**: 오늘 프로덕션 코드에 그 `Action`을 생성하는 wire op이 없어 구동 가능한 seam 자체가 부재하다(Step 2 라운드 grep 실증). 이 제외는 registry의 앵커 테스트(DENY_SEAMS 커버 action == `Action::ALL` − 3종)가 명문으로 고정하며, wire op이 생기는 순간 그 테스트가 실패해 행 추가를 강제한다. Step 6이 wire 경로 3종 거부를 재확인한다(검증 라운드 이월 노트). ③ SessionData 재접속 게이트(stream-reset seam, RESET_CODE_FORBIDDEN)는 문면 없는 wire 형상이라 균일성 의무가 "reset code + audit deny 레코드"로 정의된다 — registry에 StreamReset kind로 등재.

**균일성의 경계(중요).** 3(localctl `NotOwner`)은 **통일 대상이 아니다.** 그 거부는 원격 peer가 아니라 **같은 uid의 로컬 프로세스**에게 가고, localctl은 인가 계층이 아니라 로컬 머신 신뢰 경계이며(`docs/design/protocol.md` §11-3 "localctl은 인가 계층이 아니다", same-uid `SO_PEERCRED` 검사), 그 수신자에게 유용한 정보를 감추는 것은 보안 이득 없이 UX만 해친다. 이 경계를 코드 주석과 `architecture.md` §6에 명문화하고, DoD 4의 전수 테스트는 **원격 peer에게 나가는 거부**만을 대상으로 정의한다 — 그렇지 않으면 테스트가 로컬 진단을 지워 버린다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/acl/mod.rs` (확장 — `PERMISSION_DENIED_MESSAGE` 상수 + 그 근거 문서)
- `crates/qsh-core/src/server/mod.rs` (수정 — `permission_denied`, `authorize_and_dial_tunnel`의 복제 문안, `require_opener` 경유 거부)
- `crates/qsh-core/src/reverse/registry.rs`·`reverse/admit.rs` (수정 — `host_reverse_denied()`가 상수를 쓴다)
- `crates/qsh-core/src/tunnel/local.rs` (확인 — `ConnectResult{code:"PERMISSION_DENIED"}`의 `message` 경로도 상수를 쓴다)
- `crates/qsh-testkit/tests/session_loopback.rs` (갱신 — 바이트 단위 핀을 새 상수 참조로; 테스트는 fixture가 아니므로 편집 가능)
- `crates/qsh-core/tests/acl_docs.rs` (확장 — 상수 == `docs/CLI.md` §3.2 예시 문안 일치 게이트, `tunnel_docs.rs` 선례)
- `docs/CLI.md` §3.2 (예시 갱신 — Step 1이 이미 반영)

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L6):**
- **DoD 4 — op 전수 단언**: `Action::ALL`(항상-deny 3종 포함)과 **원격 peer 대면 거부를 낼 수 있는 모든 seam**(control-stream op 전부 + `TCP_CONNECT` inline + `host.reverse` 등록)을 표로 열거해, `DenyAll` 정책 아래 각 항목을 구동하고 **`error.code == PERMISSION_DENIED` && `error.message == PERMISSION_DENIED_MESSAGE`**를 바이트 단위로 단언. 표에 빠진 seam이 생기지 않도록, 이 표는 Step 8의 op registry와 **같은 registry를 소비**한다(두 벌의 표를 만들지 않는다 — 그것이 M4가 지적한 "손-작성 표가 테스트 안에만 산다" 문제의 재발이다).
- 소유권 거부와 정책 거부가 구별 불가: 같은 세션에 대해 (i) 정책이 `session.control`을 안 준 principal과 (ii) 정책은 줬지만 opener가 아닌 principal의 거부가 **바이트 단위로 동일**(M3가 이미 확립한 성질의 M5판 재확인, `server/mod.rs:604`의 주석 그대로).
- 존재 oracle 부재 재확인: 없는 session_id와 남의 session_id가 같은 응답(기존 `denied_session_ops_create_nothing_and_do_not_disclose_existence` 유지).
- localctl `NotOwner` 문면은 **바뀌지 않았음**을 단언(경계가 의도적임을 테스트로 고정).

**(d) 완료 판정:** **DoD 4 green.** 정책은 여전히 `AllowAllPinned`. `PERMISSION_DENIED_MESSAGE` 외의 원격 대면 deny 문안이 트리에 남아 있지 않음을 (c)의 전수 테스트가 보장. `xtask arch` green. Windows leg nextest green. **DEFERRED 판정:** 무변경(여전히 CLI envelope producer 없음).

**(e) 인용:** `docs/ROADMAP.md` M5 감사 개정 ③·DoD(감사 개정 1번째 문장), `docs/CLI.md` §3.2(`message`는 사람용, 자동화는 `code`/`details`만)·§3.3, `docs/design/protocol.md` §10-2(non-distinguishing 오류 정책)·§11-3(localctl은 인가 계층이 아니다), `docs/design/architecture.md` §6, `crates/qsh-core/src/reverse/registry.rs:497-510`(단일 문면 선례의 근거 문서), `docs/design/testing.md` L6.

---

### Step 5 — resource-ownership 축(감사 개정 ②): 소유자 개념의 정책 어휘 승격 + `forward_id` 소유(M4 이관 (iv))

**(a) 범위:** ROADMAP 감사 개정 ②. M3가 넣은 opener-principal 결합은 지금 **정책 밖의 하드코딩된 두 번째 게이트**다(`require_opener`, `server/mod.rs:648`) — 정책이 그것을 표현할 수 없고, 운영자가 끄거나 넓힐 수도 없으며, `qsh acl check`가 설명할 수도 없다. M5는 이것을 정책 어휘로 승격한다.

**소유자 있는 리소스의 정의(정본으로 못박는다).** 두 종류뿐이다.
- **세션** — 소유자는 `opener_key(principal, auth_path)`(이미 `SessionInfo.opener`에 저장, `broker/session.rs:159`).
- **remote forward(`-R`)** — 소유자는 `RemoteForwardOpen`을 보낸 연결의 principal. 오늘은 소유권이 **principal이 아니라 `ConnCtx::conn_id`로만** 표현되고(`Server::remote_forwards`, `handle_rfwd_close` `server/mod.rs:2377`), `RemoteForwardClose`는 **인가도 audit도 거치지 않는다**. 이 step이 그 갭을 닫는다: 등록 시 principal을 함께 기록하고, `RemoteForwardClose`를 `Action::ForwardRemote` + 소유권 판정의 choke point로 만들며, allow/deny 양쪽에 audit 레코드를 남긴다. 이것이 M4 §3 이관 (iv)의 **host 쪽** 답이다.

**정책 어휘.** Step 1이 확정한 rule 키 `scope ∈ {"owned"(기본), "any"}`가 살아난다. `ResourceRef`에 `owner: Option<&str>`을 더하고, 평가기는 매칭된 rule의 `scope`가 `"owned"`이면 `owner == Some(현재 요청자의 opener_key)`일 때만 `Allow`한다. `owner: None`(소유자 개념이 없는 리소스)에는 `scope`가 적용되지 않는다. **기본이 `"owned"`인 이유**: M3의 P0 결합을 그대로 보존하고, 정책이 켜지는 순간 "남의 세션에 쓸 수 있게" 조용히 넓어지지 않게 하기 위함이다(§4.1 #3). `"any"`는 명시적 opt-in이며 그 자체로 감사 대상이다.

**`require_opener`의 운명.** 삭제하지 않는다 — **평가기 안으로 옮긴다.** `authorize_session_control`이 하던 "ACL → 소유권 → 단일 terminal 레코드"는 이제 `Policy::decide` 한 번으로 끝나고(rule index와 함께), `require_opener`는 broker에서 owner를 조회해 `ResourceRef`를 채우는 얇은 조회 함수로 축소된다. 조회가 애매하면(broker `NotFound` 이외의 오류) 지금처럼 **deny**다(`CLAUDE.md` fail-closed). `NotFound`는 지금처럼 존재 oracle을 만들지 않기 위해 통과시키고 후속 broker 호출이 `SESSION_NOT_FOUND`를 낸다 — 이 미묘한 규율은 `server/mod.rs:648`의 기존 주석이 정본이며 그대로 보존한다.

**적용 범위의 경계.** PRD §6은 조회·읽기·종료를 교차 기기 ACL 범위로 **명시 허용**한다 — 따라서 `session.get`/`read`/`list`/`open`/`attach`는 `scope`의 대상이 아니고(그 결정은 M3가 이미 내렸다), `session.control`(write/resize/close)과 `forward.remote`(close)만 소유권을 본다.
  **(a)-추기 — 검증 라운드 P0 arbitration (2026-08-27).** 위 문장의 "(write/resize/close)"는 이 문단 첫 문장이 스스로 인용한 PRD §6의 "**종료** 교차 기기 허용"과 모순되는 내부 오류다. 확정: **`session.close`는 `Action::SessionControl`을 공유하되 `scope` 판정에서 면제된다** — PRD §6이 binding이고(CLAUDE.md), M3가 이미 그렇게 구현해 기존 테스트가 핀하고 있으며(close 비결합), 이 step의 (d) 불변식("M3 거동 불변")과도 그쪽만 정합이다. 죽은 기기의 세션을 다른 기기에서 정리하는 것이 PRD가 보호하는 핵심 시나리오다. 따라서 (c) 첫 항목의 `close`도 "거부"가 아니라 "허용(면제 핀)"으로 읽는다. 정책 어휘로 cross-close를 막을 수 없다는 사실은 운영자 대면 문서(§6 계열)에 명시하고, 필요해지면 새 ADR로 어휘를 추가한다. `tunnel.close`/`tunnel.list`의 "소유 peer이면 허용"(`docs/CLI.md` §2.5)이 드디어 host 쪽에서 강제되는 지점이 이 step이다.
  **데몬 쪽 `forward_id` 소유(conduit 축)는 건드리지 않는다.** `reverse::listen::ControlHub`의 `owner: ConduitId` 판정은 "target이 구별하지 못하는 두 로컬 CLI 중 누가 진짜 소유자인가"를 정하는 **로컬 머신 축**이고, ACL principal 축과 직교한다(`docs/design/protocol.md` §11-3의 `admin_close_forward` 문단이 이 직교성을 이미 명문화했다). 두 축을 합치려는 시도는 이 step의 비목표이며 §3에 재기록한다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/acl/policy.rs` (확장 — `Scope` 판정, `ResourceRef.owner`)
- `crates/qsh-core/src/acl/mod.rs` (확장 — `ResourceRef`)
- `crates/qsh-core/src/server/mod.rs` (수정 — `authorize_session_control` 단순화, `require_opener` 축소, `handle_rfwd_close`에 choke point + audit 신설, `remote_forwards`에 owner principal 기록)
- `crates/qsh-core/src/broker/session.rs`·`broker/mod.rs` (확인 — `SessionInfo.opener` 조회 경로)
- `docs/design/architecture.md` §6, `docs/CLI.md` §2.5(`tunnel.close` 행에 host 쪽 강제 지점 명시), `docs/design/protocol.md` §7(`RemoteForwardClose`의 인가 순서 신설 — 지금은 §7이 `RemoteForwardOpen`의 순서만 적고 close는 적지 않는다)

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L3):**
- `scope = "owned"`(기본) 아래: opener가 아닌 principal의 `session.write`/`resize`/`close`가 거부되고 audit에 `session.control` deny가 남음(M3 DoD의 M5판 재확인, 이제 정책 경로로).
- `scope = "any"` 아래: 같은 요청이 허용되고 audit에 `rule` index가 남음 — 그리고 이 확대가 **명시적으로 쓰인 정책에서만** 일어남을 단언.
- `RemoteForwardClose`: 다른 principal(다른 연결)이 남의 `forward_id`를 닫으려 하면 거부 + audit deny + **등록이 그대로 살아 있음**. 소유자의 close는 허용 + audit allow. 미지 `forward_id`는 지금처럼 `INVALID_ARGUMENT`(존재 oracle 금지).
- `forward_id` 소유가 conn_id가 아니라 principal 기준임: 같은 principal의 **다른 연결**이 close할 수 있는지 여부를 표로 고정한다(초안: 허용 — principal이 소유자이지 연결이 소유자가 아니다; `docs/CLI.md` §2.5 "소유 **peer**"의 문자 그대로. §4.2에서 확정).
- `owner: None` 리소스(`exec.run`·`host.reverse`·`forward.local`)에서 `scope`가 판정을 바꾸지 않음.

**(d) 완료 판정:** 위 테스트 green. `RemoteForwardClose`가 더 이상 무인가·무audit이 아님(Step 8의 SC6 registry가 이 갭을 잡을 준비가 됨). M3의 소유권 P0 거동이 **바뀌지 않았음**(기본값 `"owned"`가 그것을 재현). `xtask arch` green. Windows leg nextest green. **DEFERRED 판정:** 무변경.

**(e) 인용:** `docs/ROADMAP.md` M5 감사 개정 ②·M3 감사 개정 ②(소유권 P0가 "M5 정책 어휘의 선행 결정"이라고 이미 선언), `docs/PRD.md` §6(조회·읽기·종료는 교차 기기 허용)·§9, `docs/CLI.md` §2.5(`tunnel.close`/`tunnel.list` 행)·§6.3(opener 결합 문단), `docs/design/protocol.md` §7·§11-3(conduit 축과 principal 축의 직교성), `docs/design/architecture.md` §6, `crates/qsh-core/src/server/mod.rs:2734-2748`(`opener_key`의 근거 문서).

---

### Step 6 — **enforcement 전환**: `AllowAllPinned` → 정책 엔진 (2개 생성 지점) + 마이그레이션 이야기 + `error.PERMISSION_DENIED.json`

> **이 step은 두 PR로 올린다.** (i) **PR 6a — 전환 자체**: `serve::host_runtime`(`serve.rs:128`)과 `reverse::listen`(`listen.rs:251`)의 `Arc::new(AllowAllPinned)`를 정책 로딩으로 교체, 시작 시 운영자 진단, README·문서 동기화. 완료 판정 = 아래 (d)의 앞 네 항목. (ii) **PR 6b — 계약 표면 마감**: `error.PERMISSION_DENIED.json` fixture 추가 + `DEFERRED` 항목 제거 + exit-code matrix 행 추가. 완료 판정 = (d)의 나머지. 두 PR 모두 §2 공통 게이트를 각각 통과.

**(a) 범위:** M5에서 유일하게 **관찰 가능한 권한 경계가 바뀌는** step이다. 그래서 앞의 다섯 step이 전부 "동작 변화 0"으로 설계됐고, 이 step의 diff는 리뷰어가 "무엇이 언제부터 거부되기 시작하는가"만 보면 되도록 좁다.

**전환 지점은 정확히 둘이다.** `AllowAllPinned`가 프로덕션에 나타나는 곳은 `crates/qsh-core/src/serve.rs:128`(`host_runtime` — `qsh serve`와 `qsh reverse` 둘 다 이 팩토리를 쓴다, `reverse/target.rs:241`)과 `crates/qsh-core/src/reverse/listen.rs:251`(controller의 `host.reverse` 판정)뿐이다. 둘 다 `PolicySource::load(paths)`의 결과를 `Arc<dyn Authorizer>`로 세운다.

**검증 라운드 이월 노트 (Step 2 adversarial, 2026-08-27).** 두 가지를 이 step에서 재확인한다:
1. **항상-deny 게이트는 `Policy::decide` 안에만 있다.** interim `AllowAllPinned`는 3종(`forward.socks`/`file.read`/`file.write`)을 Pin peer에 허용하는 형태지만, 오늘 프로덕션 코드에는 그 `Action`을 생성하는 op이 없어 도달 불가함을 grep으로 확인했다. 전환으로 `Policy`가 유일 정책이 되는 순간 게이트가 유일 방어가 된다 — 6a에서 wire 경로 기준 3종 거부를 테스트로 1건 이상 확인한다.
2. **acl.toml 파일 모드는 읽기 시 검증하지 않는다**(쓰기 시에만 검사하는 기존 posture, `config.rs`). world-writable acl.toml이 그대로 수용된다 — 6a의 시작 진단에 모드 경고를 넣을지 결정하고, 넣지 않으면 non-goal로 명시 기록한다. **확정 — main 세션 (2026-08-27): 넣는다 — unix 한정, 로드 시 group/world-writable이면 stderr 경고 1회(비치명, 거부 아님).** 다른 로컬 uid가 acl.toml을 고쳐 원격 권한을 self-grant하는 경로라 침묵은 안 되고, deny로 격상하면 권한 사고 복구 자체를 막아 경고가 맞는 수위다. Windows ACL 검사는 non-goal로 명시(플랫폼 의미론이 달라 별도 설계 없이는 무의미).

**검증 라운드 확정 — PR 6a adversarial (2026-08-27, main 세션 arbitration).** opus 검증 라운드가 FIX-THEN-SHIP으로 판정한 5건의 처분:
① **진단 detail의 내용-무유출 보장 문안 정정.** "정책 파일 내용을 절대 덤프하지 않는다"는 6a가 새로 쓴 보장이 4개 Invalid 형상에서 거짓으로 실증됐다(문법 토큰 echo). Step 2의 의도적 carve-out(unknown action/auth_path/scope 3종, ≤128B·한 줄 이스케이프 — `load.rs` F1 주석이 명문)을 6a가 침묵으로 뒤집지 않는다 — 보장 문안을 "원본 소스 라인 무덤프 + 문법 토큰 3종 echo 허용"으로 정정한다(README·CLI.md·load.rs doc 3곳). 단 **초과 길이 pattern echo는 상한이 없어(≤1MiB 파일 전체까지) 내용을 버리고 바이트 길이·rule index만 보고하도록 고친다** — 이것은 Step 2 carve-out 밖의 무상한 echo라 코드 수정이 맞다. content-free 테스트는 TOML 문법 오류 1형상만 커버하던 것을 전 형상으로 확장한다.
② **PLAN이 빚진 L6 doc-consistency 게이트 추가.** 마이그레이션 이야기 1이 명시한 "README·문서와의 일치를 L6 게이트로 고정(doctor.rs 선례)"이 미작성으로 적발 — `doctor_docs.rs` 선례대로 `render()`의 고정 문면 상수를 README·`docs/CLI.md`와 대조하는 테스트를 6a에 추가한다(①의 문안 정정과 같은 pass에서, 게이트가 정정 전 문안에서 실패하는 것이 정상).
③ **`docs/CLI.md` §6.12 "원격 peer 대면으로는 시작하지 않는다" 정정.** 정본(architecture.md §6 "전부 deny")과 구현(리스너는 뜨고 응답하되 인가 전량 deny, 리소스 생성 0 — 실측 136회 등록 시도 전량 거부) 모두에 어긋나는 문장이라 바인딩 문서를 사실로 고친다. doctor.rs 선례 인용도 사실 범위로 좁힌다(doctor는 `render()` 없는 message/remedy 2필드 — 공통점은 "문안 정본 core + CLI는 인가 로직 0줄로 출력만").
④ **커버리지 3건 동승.** listen(controller) 측 시작 진단은 기능을 삭제해도 전 테스트 green임이 mutation으로 실증 — `ListenGuard` stderr 보존 + 진단 1회 assertion을 추가한다. 파일 모드 경고는 group-writable 단독(0o660) 케이스가 무검증 — 모드 표 구동으로 확장한다. 하네스가 심는 acl.toml은 umask 상속이라 0o600 고정으로 바꾼다(umask 002 러너에서 경고 오발 방지).
⑤ **수용 2건.** 다중 행 진단 블록의 명령 접두사가 첫 행에만 붙는 것은 의도된 cosmetic으로 수용(변경 없음). 빚진 테스트의 두 편차 — CA 왕복을 unit 레벨에서(`load_or_deny` 프로덕션 진입점 경유; CLI CA 발급 하네스는 M6), "자식 프로세스 0"을 인가-선행-순서+구조적 증거로 대리 — 둘 다 수용하되, 테스트 주석의 `server/mod.rs:812` 행 번호 인용은 함수명 인용으로 바꾼다. 항상-deny 3종의 wire 경로 재확인(이월 노트 1)은 registry 앵커 테스트("wire op이 3종 Action을 생성할 수 없음"을 컴파일 타임에 고정)로 이행 완료로 판정 — 신규 테스트가 아니라 커밋 본문 문장으로 남긴다.

**마이그레이션 이야기(acl.toml 없이 업그레이드하는 사용자에게 무슨 일이 일어나는가).** 정본이 이미 답을 정해 두었다 — `docs/design/architecture.md` §6: "acl.toml이 없거나 파싱 불가 → **전부 deny** + 운영자에게 `CONFIG_ERROR` 노출. '오류 시 개방'은 존재하지 않는다." 따라서 M4까지의 사용자가 acl.toml 없이 M5 바이너리를 띄우면 **모든 원격 op이 거부된다**. 이것은 결함이 아니라 default-deny의 정의이고(`docs/PRD.md` §9), 그 대신 M5는 그 전환이 **조용하지 않도록** 세 가지를 진다:
1. **시작 시 진단.** `qsh serve`/`qsh listen`/`qsh reverse`가 정책 없음/파손을 stderr에 **한 번** 구조화 진단으로 낸다 — 정확한 파일 경로, `CONFIG_ERROR` 코드, 그리고 **복사해 붙일 수 있는 최소 정책 예시**(그 머신의 pinned peer 이름을 실제로 채워서). 상수는 `qsh-core`에 두고 README·문서와의 일치를 L6 게이트로 고정한다(`doctor.rs`의 `CONTROLLER_UNREACHABLE` 선례 그대로).
2. **자동 생성 금지.** acl.toml을 자동으로 만들어 주지 않는다. allow-all-pinned를 파일로 자동 기록하는 것은 interim 임시 조치를 **영구 부여 권한으로 승격**하는 일이고, 운영자의 결정 없이 권한이 생기는 것은 M4가 금지한 "silent addition"과 같은 범주다.
3. **사전 검증 경로.** `qsh acl check`(Step 7)로 재시작 **전에** 정책을 확인할 수 있다. 순서상 Step 7이 뒤에 오므로, 6a의 진단 문안은 "`qsh acl check`로 확인하라"를 Step 7 완료 시점에 추가한다(6a에서는 파일 경로와 예시까지).

**CA 경로 peer의 지위 변화.** 오늘 README는 "CA로 인증한 peer는 handshake는 통과하되 모든 op에서 `PERMISSION_DENIED`"라고 고지한다(`AllowAllPinned`가 `AuthPath::Ca`를 거부하므로). M5 이후 CA peer는 **정책이 명시적으로 `auth_path = "ca"` rule을 쓴 경우에만** 권한을 얻는다(§4.1 #2의 기본값이 `"pin"`이므로 기본으로는 여전히 전량 거부). README의 그 문단을 이 step이 갱신한다.

**정책은 시작 시 1회 로드하고 hot reload는 없다.** 실행 중 acl.toml을 고쳐도 다음 재시작까지 적용되지 않으며, 이 사실을 `docs/CLI.md` §6.12/§6.13과 README에 **명시 고지**한다 — M7 감사 개정 ①이 `trust remove`에 대해 요구한 것과 같은 규율("유예 기간의 실제 동작을 문서화하는 것은 유예할 수 없다"). hot reload 자체는 §3의 비목표다.

**`error.PERMISSION_DENIED.json`(PR 6b).** `crates/qsh-cli/tests/fixtures.rs`의 `DEFERRED` 첫 항목이 스스로 조건을 적어 두었다: "Discharge this one the moment `Fleet`/an equivalent gains a way to run the real binary under a denying policy — it needs a fixture then, not a place on this list." 정책 파일 + `$QSH_CONFIG_DIR`만으로 실바이너리를 거부 정책 아래 띄울 수 있게 되므로(새 CLI 노브 불요) 이 조건이 충족된다. `qsh tunnel open --remote --json`을 거부 정책 아래 실행해 나오는 최상위 error envelope를 fixture로 뜨고, `DEFERRED`에서 제거해 `REQUIRED_FIXTURES`에 등록하며, exit-code matrix(`crates/qsh-cli/tests/exit_code_matrix.rs`)에 human/JSON 양 모드 행을 더한다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/serve.rs` (수정 — `host_runtime`이 정책을 로드; 로드 실패 시 진단 + `DenyAll`)
- `crates/qsh-core/src/reverse/listen.rs` (수정 — 같은 로딩)
- `crates/qsh-core/src/acl/load.rs` (확장 — 운영자 진단 상수 `ACL_POLICY_MISSING`/`ACL_POLICY_INVALID`)
- `crates/qsh-cli/src/main.rs` (확장 — 시작 배너에 진단 렌더; **인가 로직 0줄**, 상수 출력만)
- `crates/qsh-cli/tests/fixtures.rs`·`fixtures/cli-v1/error.PERMISSION_DENIED.json`(신규)·`exit_code_matrix.rs` (PR 6b)
- `crates/qsh-testkit/src/*` (확장 — 하네스가 acl.toml을 심을 수 있게; 기존 tempdir config 경로 재사용)
- `README.md`(Security posture 전면 갱신, Known limitations의 "No policy engine before M5" 제거·hot reload 부재 추가), `docs/CLI.md` §6.12·§6.13
- **(파급 주의):** 기존 통합 테스트 다수가 "pinned peer면 다 된다"를 암묵 전제로 한다. 이 step은 하네스에 **명시적 허용 정책을 심는** 것으로 그 전제를 되살린다(테스트마다 개별 수정이 아니라 하네스 한 곳). 어느 테스트가 정책을 심어야 하는지는 이 step의 PR 본문에 목록으로 남긴다 — 조용히 통과시키는 편법(예: 테스트 전용 allow-all 기본값)은 금지다.

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L3·L5·L6):**
- acl.toml 부재로 시작한 host에 pinned peer가 `exec.run`을 시도 → `PERMISSION_DENIED`(균일 문면) + **자식 프로세스 0** + audit deny 1줄. 시작 진단이 stderr에 정확히 한 번.
- 파손 acl.toml → 같은 결과이되 진단 코드가 `CONFIG_ERROR`이고 **stdout은 한 바이트도 오염되지 않음**(`docs/CLI.md` §2.2).
- 최소 허용 정책(`principal = "device:<peer>"`, `allow = ["exec.run"]`) → `exec.run`만 통과하고 `session.open`은 거부, audit에 각각 allow/deny와 `rule: 0`.
- CA 경로: `auth_path` 생략 rule 아래 CA 인증 peer는 전량 거부; `auth_path = "ca"` rule을 명시하면 통과.
- controller 쪽: acl.toml 없는 `qsh listen`에 `qsh reverse`가 등록 시도 → `host.reverse` deny + 등록 0(`reverse/admit.rs`의 기존 불변식이 정책 경로에서도 성립).
- **PR 6b**: `error.PERMISSION_DENIED.json` fixture가 스키마 검증 통과, `ErrorCode` 전수 도달성 테스트에서 `DEFERRED` 밖으로 이동, exit-code matrix가 human/JSON 양 모드에서 동일 exit code.

**(d) 완료 판정:** 정책 엔진이 프로덕션 정책이다(`AllowAllPinned`가 프로덕션 생성자에서 사라졌음을 grep으로 확인 — 테스트 double로는 남는다). 마이그레이션 3종(진단·자동생성 금지·사전 검증 안내)이 코드와 문서에 실재. README가 실제 권한과 일치(마감 절차 2의 선행). hot reload 부재가 명시 고지됨. `error.PERMISSION_DENIED.json` 등록 + `DEFERRED`에서 제거. Windows leg nextest green. **DEFERRED 판정:** `PERMISSION_DENIED` **제거**(producer 확보) — 이것이 M5가 `DEFERRED` 목록을 실제로 줄이는 유일한 항목이다.

**(e) 인용:** `docs/design/architecture.md` §6("acl.toml이 없거나 파싱 불가 → 전부 deny + `CONFIG_ERROR`"), `docs/PRD.md` §9(default-deny·인증 전 리소스 금지), `docs/CLI.md` §2.2·§3.3·§6.12·§6.13·§10, `docs/ROADMAP.md` M5 범위·§2 마감 공통 절차 2(README 동기화)·M7 감사 개정 ①(유예 기간의 실제 동작을 문서화하는 것은 유예할 수 없다), `crates/qsh-cli/tests/fixtures.rs`의 `DEFERRED` PERMISSION_DENIED 항목(자기 해제 조건), `CLAUDE.md` "ACL is default-deny".

---

### Step 7 — `qsh acl check`: **enforcement와 같은 코드 경로** + 표 기반 동치 증명 — **DoD 1**

**(a) 범위:** DoD 1을 마감한다. 핵심은 기능이 아니라 **구조**다: 설명용 평가기를 따로 만드는 순간 DoD 1은 영원히 "지금은 같다"라는 주장이 되고, 두 경로는 반드시 갈라진다.

**Ops.** `Ops::acl_check(AclCheckReq) -> Result<AclCheckData, OpError>`(`crates/qsh-core/src/ops/acl.rs` 신규). 이 op은 **로컬**이다 — 이 머신의 `acl.toml`을 Step 2의 `PolicySource::load`로 읽어 Step 2의 `Policy::decide`를 **그대로** 호출한다. 원격 왕복도, 두 번째 평가기도 없다. 입력 `principal`/`action`/`auth_path` 문자열은 파싱해 `Principal`/`Action`/`AuthPath`로 바꾸고, 어휘에 없는 값은 `INVALID_ARGUMENT`(어떤 action이 존재하는지는 `--help`와 `qsh schema`가 알려 주므로 이 거부는 oracle이 아니다). `resource` 생략 시 소유자 없는 리소스로 평가하고, `--owner`를 주면 `scope` 판정까지 설명한다(§4.2 — `--owner` 표면을 M5에 넣을지).

**CLI.** `qsh acl check --principal device:hermes --action session.open [--resource <id>] [--auth-path pin|ca] [--json]`. human 렌더는 한 줄(`allow (rule 0)` / `deny`)에 정책 파일 경로를 stderr 힌트로, `--json`은 `AclCheckData` envelope. 렌더러에는 **인가 로직 0줄**(`CLAUDE.md` arch rules) — `Ops`가 판정하고 렌더러는 문자열만 만든다.

**DoD 1의 증명 방식.** 두 겹으로 한다.
- **구조적**: `Ops::acl_check`가 호출하는 함수와 `Server::authorize`가 호출하는 함수가 **동일 심볼**임을 타입으로 강제한다 — `Policy::decide` 하나만 `pub(crate)`로 존재하고 `Authorizer for Policy`도 그것을 부른다. 두 번째 진입점이 생기면 컴파일 단계에서 눈에 띄도록 모듈 경계를 좁힌다.
- **표 기반(ROADMAP 문구 그대로)**: (정책 파일 × principal × auth_path × action × resource/owner)의 행렬을 표로 두고, 각 행에 대해 (i) `qsh acl check --json`의 `decision`/`rule`과 (ii) 같은 정책으로 띄운 loopback 하네스에서 **실제 op을 실행한 결과**(성공 / `PERMISSION_DENIED`)와 (iii) 그 op이 남긴 audit 레코드의 `decision`/`rule`이 **셋 다 일치**함을 단언. 세 번째가 중요하다 — `acl check`와 enforcement가 같아도 audit이 다른 것을 기록하면 SC6가 거짓이 된다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/ops/acl.rs` (신규 — `Ops::acl_check`, `COMMAND = "acl.check"`)
- `crates/qsh-core/src/ops/mod.rs` (확장 — 모듈 등록)
- `crates/qsh-cli/src/cli.rs`·`src/main.rs`·`src/render/` (확장 — `Command::Acl(AclCmd::Check)`, human/JSON 렌더)
- `crates/qsh-cli/tests/fixtures/cli-v1/acl.check.allow.json`·`acl.check.deny.json` (신규, append-only)
- `crates/qsh-cli/tests/fixtures.rs` (확장 — `REQUIRED_FIXTURES`에 두 파일 추가)
- `docs/CLI.md` §6.15 (Step 1이 이미 계약을 적었고 이 step이 구현을 맞춘다)

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L5·L6):**
- **DoD 1 — 표 기반 동치**: 위 (a)의 3-way 일치 표. 행에는 최소한 (허용/거부/wildcard 매칭/항상-deny action/`auth_path` 불일치/`scope=owned`의 소유자·비소유자/정책 파일 부재) 7종을 포함.
- `acl check`가 **정책을 변경하지 않음**(읽기 전용) — 실행 전후 acl.toml mtime·내용 불변.
- 원격 노출 없음: `acl.check`가 wire `ControlMessage`의 어느 variant로도 나가지 않음(원격 peer가 정책을 조회할 수 없다).
- fixture 2종이 스키마 검증 통과, `qsh schema --json`이 새 타입을 서빙(M7 구현 대상이므로 스키마 생성만 확인).
- 잘못된 action 이름 → `INVALID_ARGUMENT` + exit `2`(§4 exit code 계약). **확정 — main 세션 (2026-08-28): exit `255`로 정정.** §4의 `2`는 clap 층의 syntax 거부이고, 어휘 밖 값은 `Ops`가 거부하는 `OpError`라 runtime 실패 `255`다 — 기존 exit-code matrix의 모든 `INVALID_ARGUMENT` 행이 이미 이 해석으로 핀돼 있고(`-L`/`-R` 선례 포함), 이 명령 하나만 `2`로 하면 code↔exit 대응이 명령마다 갈라진다. 이 줄의 "exit 2"는 PLAN이 §4를 잘못 옮긴 것이다. 같은 확정: 항상-deny 행의 실구동 leg는 wire producer가 없어(P1) `PolicySource::load`+`Authorizer::check` 교차로 대체 — Step 4 registry 앵커가 도달 불가를 컴파일 타임에 고정하고 있으므로 3-way의 셋째 leg(audit)는 그 행에서 성립 불가가 아니라 무대상이다.

**검증 라운드 확정 — Step 7 adversarial (2026-08-28, main 세션 arbitration).** FIX-THEN-SHIP(P0 0·P1 2·P2 8) 처분: ① 문서화된 기본값 2종(`--owner-auth-path`=pin, `--auth-path`=pin)이 mutation에 무저항으로 실증돼 명시값과의 동치 단언으로 핀한다. ② §6.15의 "`rule`은 null" 문장은 wire가 key 자체를 생략하는 실제와 어긋나 생략으로 정정(owner 문장과 통일). ③ 표에 Invalid(파손 acl.toml) 행을 추가해 3-way를 9행으로 — Missing만 있던 로더 축을 닫는다. ④ `--owner-auth-path`는 clap `requires`로 `--owner` 없이 오면 usage 거부. ⑤ acl check가 Missing/Invalid를 구별하지 못하는 것은 §6.15가 이미 정직하게 문서화한 한계로 수용하되, 파스 상세의 정본이 시작 진단(§6.12/§6.13)임을 §6.15에 한 문장으로 명시(op 자체에 상세 표면 추가는 하지 않는다 — 계약 성장 없이 M7 doctor 통합에서 재평가). ⑥ enforcement 전용 fail-closed 층(audit 기록 실패 시 allow→deny 반전, owner 조회 실패 deny)으로 acl check의 allow 예측만 뒤집힐 수 있음을 §6.15에 명시 — deny 예측은 항상 신뢰 가능. ⑦ 표 행의 acl.toml 심기도 0o600 고정(umask 002 러너의 경고 오발 방지, 6a F8과 동일).

**(d) 완료 판정:** **DoD 1 green.** `acl check`의 판정 경로가 enforcement와 같은 함수임이 구조로 강제됨. 렌더러/CLI에 인가 로직 0줄(`xtask arch` green). fixture 2종 등록. Windows leg nextest green(이 op은 플랫폼 무관 — Windows에서도 `acl check`가 동작해야 한다: 정책 파일 읽기와 순수 평가뿐이므로 `cfg(unix)` 분기가 없어야 한다).

**(e) 인용:** `docs/ROADMAP.md` M5 범위(`qsh acl check`)·DoD 1, `docs/CLI.md` §2.1·§2.4·§2.5·§4(exit code)·§6.15·§11(세 frontend가 같은 typed operation), `docs/design/architecture.md` §1(렌더러에 ACL 로직 0)·§2(typed op layer)·§6("평가와 `qsh acl check` 설명 가능성 유지"가 후행 `.*`만 허용하는 이유), `CLAUDE.md` "Renderers and the MCP adapter contain zero auth/ACL/session logic".

---

### Step 8 — **op registry 열거 + audit 완전성**(SC6) + 문서·README 최종 동기화 + M5 마감 — **DoD 2**

**(a) 범위:** DoD 2를 마감하고 마일스톤을 닫는다. 오늘 "모든 privileged op에 audit 레코드가 있다"는 **믿음**이다 — 열거하는 것이 아무것도 없고, 유일하게 비슷한 것은 `server/mod.rs:3818`의 세션 op만 다루는 손-작성 `match`이며 그것은 `#[cfg(test)]` 안에만 산다. 실제로 `handle_rfwd_close`는 M4 내내 인가도 audit도 없었다(Step 5가 닫는다).

**op registry(프로덕션 코드).** `crates/qsh-core/src/acl/registry.rs` 신규 — 모든 privileged op을 **하나의 표**로 선언한다: `OpSpec { op: &'static str, action: Action, resource_kind: ResourceKind, owned: bool }`. `op`은 `docs/CLI.md` §2.4의 dotted 이름(또는 operation이 아닌 seam은 `host.reverse`·`forward.local`처럼 §2.5가 쓰는 이름)이고, `action`은 §2.5 매핑 표의 오른쪽 열이다. dispatch가 이 표를 **소비**하게 만들어 표와 코드가 갈라지지 않게 한다(최소한 각 핸들러가 `OpSpec`을 참조해 action을 얻도록).

**세 층의 열거 테스트.**
1. **계약 대조(L6)**: registry의 (op → action) 쌍이 `docs/CLI.md` §2.5 매핑 표와 정확히 일치. 문서에 있는 행이 registry에 없거나 그 반대면 실패(`tunnel_docs.rs`/`doctor_docs.rs` 선례).
2. **인가 대조**: `Server::dispatch`의 `control_message::Body` variant 전수와 registry를 대조해, **인가가 필요 없는 variant는 명시 목록**(`Ping`·`Hello`·`SessionEvent`)에만 있고 나머지는 전부 registry에 있음을 단언. 새 wire variant가 생기면 이 테스트가 즉시 실패한다 — 그것이 M1 원칙 7(b)를 기계화하는 방법이다.
3. **DoD 2 — audit 완전성**: registry의 각 항목을 **실제로 구동**해(허용 정책 1회 + 거부 정책 1회) `MemoryAuditSink`에 정확히 그 `action`의 레코드가 남았고 `decision`이 기대와 일치함을 단언. 레코드가 0건인 항목이 하나라도 있으면 실패. `Action::ALL` 중 항상-deny 3종은 아직 op이 없으므로 registry에 op 항목이 없고, 그 사실을 **명시 예외 목록**으로 선언한다(사유 문자열 포함 — `DEFERRED` 규율과 같은 형태로, 조용한 구멍이 되지 않게).

**최종 동기화.**
- `README.md`: "Security posture" 절이 정책 엔진을 전제로 다시 쓰인다(무엇이 기본으로 거부되는가, acl.toml을 어디에 두는가, CA peer의 지위, hot reload 부재, audit 회전·fail-closed의 운영 함의). "Known limitations"에서 "No policy engine before M5"를 제거하고 새 한계(정책 hot reload 없음, principal별 쿼터 없음 — M8, `audit.log_argv` 미구현)를 추가.
- `docs/design/testing.md`: M5가 실제로 심은 테스트 층(정책 property·audit 수명주기·문면 전수·op registry)을 "현재 상태" 문단에 반영.
- `docs/ROADMAP.md`: "현재 위치"와 M5 절 상태 표기 갱신은 **로드맵 문서 소유자의 몫**이다 — 이 계획은 지시만 하고 대신 수정하지 않는다.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/acl/registry.rs` (신규 — `OpSpec`, `OP_REGISTRY`, 예외 목록)
- `crates/qsh-core/src/server/mod.rs`·`reverse/admit.rs`·`tunnel/*` (수정 — 핸들러가 registry에서 action을 얻는다; 문자열·enum 하드코딩 제거)
- `crates/qsh-core/tests/acl_registry.rs` (신규 — 위 3층 테스트)
- `crates/qsh-core/tests/acl_docs.rs` (확장 — §2.5 표 대조)
- `README.md`, `docs/design/testing.md`

**(c) 빚지는 테스트 (`docs/design/testing.md` L2·L6):** 위 3층. 더해서 Step 4의 전수 문면 테스트가 **같은 registry를 소비**하도록 리팩터(표 두 벌 금지). 그리고 registry가 비어 있거나 예외 목록이 registry를 통째로 삼키는 퇴화 상태를 실패로 처리하는 sanity 단언(예외 목록 크기 < registry 크기).

**(d) 완료 판정:** **DoD 2 green.** §1의 DoD 5항목 전건 통과가 실제 테스트 실행 로그로 확인됨. README·testing.md가 실태와 일치. `xtask arch` green. Windows leg nextest green. **DEFERRED 판정:** 무변경(Step 6이 이미 `PERMISSION_DENIED`를 뺐다).

**(e) 인용:** `docs/ROADMAP.md` M5 DoD 2(SC6)·§1 원칙 7(b)·§2 마감 공통 절차 1·2, `docs/PRD.md` §15 SC6("모든 privileged op의 ACL 추적성"), `docs/CLI.md` §2.4·§2.5(정본 매핑 표), `docs/design/architecture.md` §6(단일 choke point), `docs/design/testing.md` L6.

## 3. 명시적 non-goals (M6+ / P1 유예)

`docs/ROADMAP.md` M5 절에는 "명시적 out" 항목이 없다 — 아래는 M5 범위·DoD 문면과 다른 조항에서 파생한 경계다. **경계를 적어 두지 않으면 정책 엔진은 무한히 자란다.**

- **정책 hot reload / `SIGHUP` 재로드** — 정책은 프로세스 시작 시 1회 로드. 실행 중 파일 변경은 재시작까지 무효이며 이 사실을 명시 고지한다(Step 6). 재로드는 살아 있는 연결의 권한을 중간에 바꾸는 문제(=`trust remove`가 M7 감사 개정 ①에서 다루는 것과 같은 종류)를 열므로 그 결정과 함께 다뤄야 한다.
- **principal별·forward별 할당량(쿼터)** — `RESOURCE_EXHAUSTED`로 강제되는 상한은 **M8 적대적 부하 게이트**의 것이다(`docs/ROADMAP.md` M8 감사 개정 ③: `[serve].max_sessions`·principal별 세션 쿼터). `docs/design/protocol.md` §7의 두 문장이 이것을 "M5 정책 엔진 범위"라고 적고 있으나 ROADMAP M5 DoD에는 대응 기준이 없다 — Step 1이 그 문장을 M8 귀속으로 **정정**한다(§4.1 #7). M5는 쿼터를 만들지 않는다.
- **resource 패턴 매칭** — PRD §9의 정책 문법에는 principal과 action만 있다. "이 세션 id에만", "이 포트 범위에만" 같은 resource 조건은 M5에 없다. `resource`는 audit 기록과 `scope` 소유권 판정에만 쓰인다.
- **deny rule / 순서 의존 정책** — 문법은 allow-only다. deny rule을 넣는 순간 순서 의미론과 "왜 거부됐는가"의 설명이 폭발하고, `qsh acl check`의 설명 가능성(architecture.md §6이 후행 `.*`만 허용하는 바로 그 이유)이 무너진다.
- **principal 그룹·역할·상속** — `[[acl]]` 행은 principal 하나에 대응한다. 그룹은 P1 이상.
- **`audit.log_argv` opt-in** — `architecture.md` §6이 유일한 예외로 이름 지어 두었으나 M5는 구현하지 않는다. argv를 레코드에 넣는 것은 "payload 무기록"의 타입 수준 속성을 깨는 변경이라 별도 결정(ADR 후보)이 필요하다.
- **audit 원격 전송·syslog·구조화 sink 플러그인** — 파일 JSONL 하나뿐(`architecture.md` §6).
- **`qsh doctor`의 ACL/audit 진단 항목** — doctor는 M7이다(`docs/ROADMAP.md` M7 범위). M5는 시작 시 진단만 내고, 그 상수를 M7 doctor가 소비할 수 있게 `qsh-core`에 둔다(`doctor::CONTROLLER_UNREACHABLE` 선례).
- **MCP tool로서의 `acl.check` 노출** — MCP adapter는 M6다. Step 1이 정한 DTO가 M6에서 그대로 tool schema가 된다.
- **`ControlLink`/`DataLink` enum → `Transport`/`StreamMux` trait 전환(ADR-0005 P0 부채)** — M3가 남기고 M4가 다시 넘긴 미이행 부채. M5도 트리거하지 않는다. 이 부채의 존재를 여기 재기록해 P1의 입력으로 넘긴다.
- **SOCKS(`-D`)·file copy·UDP forwarding의 구현** — 그대로 P1/P2. M5가 하는 것은 `forward.socks`·`file.read`·`file.write` **어휘를 정의하고 항상 deny로 강제**하는 것까지다(`docs/ROADMAP.md` §3 유예 가드레일 표의 문자 그대로).

### M4가 넘긴 다섯 항목의 처리 (M4 PLAN §3 "M5에 넘기는 것")

| M4 이관 항목 | M5에서의 처리 |
|---|---|
| (i) `forward.socks`·`file.*` 어휘의 "정의하되 항상 deny" 승격 | **Step 1이 어휘를, Step 2가 강제를 진다.** 어휘만으로는 부족하다는 발견(wildcard `forward.*`가 socks를 삼킨다)이 Step 2의 "rule 매칭 이전 게이트" 설계의 근거다. |
| (ii) `forward.local`/`forward.remote`의 TOML 정책 매칭 | **Step 2(평가기) + Step 6(전환)이 진다.** 두 action은 이미 `Action::ALL`에 있으므로 새 어휘가 아니라 정책이 그것을 매칭하게 되는 문제다. |
| (iii) 터널 관련 op 전수의 audit 완전성(SC6)이 op-registry 열거 테스트에 포함되는가 | **Step 8이 진다 — 그리고 답은 "포함돼야 하며, 지금은 구멍이 있다"다.** `handle_rfwd_close`(`server/mod.rs:2377`)는 인가도 audit도 없다. Step 5가 그 갭을 닫고 Step 8의 registry가 재발을 막는다. |
| (iv) reverse 경로 터널의 소유권 축(`forward_id` 소유로 확장할지) | **Step 5가 진다, 축을 나눠서.** host 쪽 `forward_id` 소유는 principal 축으로 승격하고 정책이 본다. 데몬 쪽 conduit 소유(`ControlHub`의 `owner: ConduitId`)는 **로컬 머신 축**이라 그대로 둔다 — 두 축의 직교성은 `docs/design/protocol.md` §11-3이 이미 명문화했고, 합치려는 시도는 비목표다. |
| (v) forward-route live carrier(`ForwardCarrier::Quic`의 스냅샷 → live 뷰) | **M5 범위 밖 — 재유예한다.** ROADMAP M5의 범위·DoD 어디에도 터널 carrier 항목이 없고, 이것은 ACL/audit이 아니라 터널 recovery 의미론의 설계 변경이다(`ops/session.rs` `Link`·`tunnel/local.rs` `ForwardCarrier`·`ops/tunnel.rs`·reverse acceptor를 관통). M4가 이 거동을 이미 테스트로 고정했고(`tunnel_chaos.rs`의 개정 강제 트랩) README가 사용자에게 고지하고 있으므로 **조용히 사라지지는 않는다.** §5 마감 절차가 이 항목을 `docs/ROADMAP.md` §3 유예 가드레일 표(또는 M8 백로그)에 **소유자를 지정해 등재**할 것을 요구한다 — PLAN.md에서 PLAN.md로만 전달되면 언젠가 증발한다. `-R`의 자동 재발행 없음도 같은 항목의 일부로 함께 등재한다. |

## 4. 리스크와 감시 항목

`docs/ROADMAP.md` §4 "일정 리스크" 및 architecture.md §9 중 M5 직결 항목 + M5 고유 감시:

- **정책이 켜지는 순간 무언가가 조용히 넓어진다(가장 값비싼 오류).** M5의 위험 방향은 M4와 반대다 — M4는 "인가 전에 리소스를 만들까"였고 M5는 "정책이 의도보다 많이 허용할까"다. 감시: (a) `auth_path` 기본값이 `pin`이라 CA peer가 자동으로 권한을 얻지 않는가(§4.1 #2), (b) `scope` 기본값이 `owned`라 M3의 소유권 P0가 보존되는가(§4.1 #3), (c) 항상-deny 3종이 **어떤 wildcard로도** 통과하지 못하는가, (d) 테스트 하네스가 편의를 위해 allow-all 기본값을 심어 (a)–(c)를 무력화하지 않는가 — Step 6의 하네스 변경은 **명시 정책 심기**여야 하고 테스트 전용 우회 기본값이어서는 안 된다.
- **acl.toml이 새로운 신뢰 입력 표면이다.** 지금까지 host가 파싱하는 신뢰 불가 입력은 wire뿐이었고 그것은 sans-IO `qsh-proto`에 격리돼 fuzz된다. acl.toml은 **운영자가 쓰는** 파일이라 적대적 입력은 아니지만, 파싱 실패의 처리(부분 로드 금지·fail closed)와 자원 소비(거대한 rule 배열)는 여전히 문제다. 감시: 부분 로드 경로가 존재하지 않는가, rule 수·패턴 길이에 상한이 있는가, 평가가 rule 수에 선형이고 요청당 파일 I/O가 0인가(시작 시 1회 로드).
- **audit fail-closed가 서비스 거부 벡터가 된다.** 디스크를 채울 수 있는 상대(또는 그저 가득 찬 디스크)가 host 전체를 거부 상태로 만든다. 이것은 ROADMAP이 의도한 트레이드오프이지만(감사 없는 서비스보다 서비스 없는 감사가 낫다) 그 대가는 **문서화돼야** 한다. 감시: README·`architecture.md` §6에 이 트레이드오프가 명시됐는가, degraded 진입이 운영자에게 즉시 보이는가(stderr 1회 + M7 doctor 후보), 회전·retention이 디스크를 유계로 만들어 자기 유발 DoS를 줄이는가, M8 적대적 부하 게이트 ④("M5가 구현한 audit 수명주기의 부하 하 검증")가 이 항목을 입력으로 받는가.
- **`acl check`와 enforcement의 분기(DoD 1의 핵심 위험).** "지금은 같다"는 코드 리뷰의 주장이지 불변식이 아니다. 감시: 평가 진입점이 프로덕션에 정확히 하나인가(grep으로 확인 가능한 형태로 유지), Step 7의 3-way 표(check · 실제 거동 · audit 레코드)가 살아 있는가, 새 op을 추가할 때 표에 행이 강제로 늘어나는 구조인가.
- **op registry가 문서와 갈라진다.** registry는 CLI.md §2.5 매핑 표의 코드 복제본이고, 복제본은 갈라진다. 감시: L6 문서 대조 테스트가 양방향(문서→코드, 코드→문서)인가, 새 wire variant가 registry 없이 dispatch에 추가될 수 있는가(불가능해야 한다).
- **거부 문면 통일이 로컬 진단까지 지운다.** ③의 과잉 적용 위험. 감시: 전수 테스트의 대상이 "원격 peer 대면 거부"로 정의됐는가, localctl `NotOwner` 문면이 의도적으로 남았음을 테스트가 고정하는가.
- **`Authorizer::check` 시그니처 변경의 파급(Step 2).** trait 반환 타입이 바뀌면 네 호출 지점과 모든 테스트 double이 함께 움직인다. 감시: Step 2의 diff가 **순수 기계적**인가(판정 로직이 그 커밋에서 바뀌면 리뷰가 불가능해진다), `AllowAllPinned`가 여전히 정확히 같은 판정을 내는가.
- **기존 통합 스위트의 암묵 전제(Step 6).** "pinned면 다 된다"를 전제한 테스트가 다수다. 감시: 어느 테스트가 정책을 심게 됐는지 PR 본문에 목록이 있는가, 그 목록이 "정책을 심어야 할 곳"과 "정책 없이도 통과해야 할 곳(=거부를 단언하는 테스트)"을 구별하는가.
- **SC7 외부 보안 리뷰 예약(`docs/ROADMAP.md` §4 리스크 5).** "리뷰는 M5 시점에 예약하고 wire format을 리뷰 ~6주 전에 freeze"가 명시돼 있다. 코드 작업이 아니라 **일정 작업**이며 M5 안에서 잊히기 쉽다. §5 마감 절차에 항목으로 넣었다.
- **Windows leg.** M5 코드 대부분이 플랫폼 무관이라는 것이 오히려 함정이다 — audit 회전의 rename/unlink와 파일 모드는 `cfg(unix)` 분기를 갖고, `acl check`는 **Windows에서도 동작해야 한다**(정책 파일 읽기와 순수 평가뿐이므로 unix 분기가 있으면 그것이 버그다). 감시: 매 step 완료 조건에 Windows nextest green이 있는가.

### 4.1 이 계획이 확정한 결정 (Step 1이 정본 문서에 기록한다)

| # | 질문 | 초안 결정 | 정본 | 확정도 |
|---|---|---|---|---|
| 1 | acl.toml이 없는 채로 업그레이드한 사용자에게 무슨 일이 일어나는가 | **전량 deny.** `architecture.md` §6이 이미 "없거나 파싱 불가 → 전부 deny + 운영자에게 `CONFIG_ERROR`"로 정해 두었다. 대신 (a) 시작 시 파일 경로·복사 가능한 최소 정책을 포함한 진단 1회, (b) **자동 생성 금지**(allow-all-pinned를 파일로 굳히는 것은 interim을 영구 권한으로 승격하는 silent addition), (c) `qsh acl check`로 재시작 전 검증 | architecture.md §6, PRD §9, CLI.md §6.12·§6.13, README | **확정 — main 세션 승인 (2026-08-27).** 정본이 이미 pin한 결정의 이행이며, 사용자 대면 파괴성은 Step 6의 마이그레이션 3종(진단·자동생성 금지·사전 검증)이 짊어진다 |
| 2 | 정책 행이 pin/CA 경로를 구별하는가 | 구별한다. `[[acl]]`에 optional `auth_path = "pin"\|"ca"`, **생략 시 `"pin"`**. 근거: `Principal` 하나로는 pin과 CA를 구별할 수 없고(`AuthPath` 문서), `opener_key`가 이미 같은 이유로 auth_path를 소유권 키에 접어 넣었으며, 기본을 `"pin"`으로 두면 M1–M4가 실제로 허용하던 경계가 그대로 보존된다 | PRD §9, architecture.md §6, protocol.md §3, `acl/mod.rs` 머리말 | **확정 — main 세션 승인 (2026-08-27).** acl.toml 자체가 M5 신설 표면이라 additive 문제가 없고, 기본 `"pin"`이 기존 실효 경계를 보존한다. Step 1이 PRD §9 예시를 이 키까지 포함해 갱신한다 |
| 3 | 소유권을 정책이 어떻게 표현하는가 | rule 키 `scope = "owned"(기본) \| "any"`. 소유자 있는 리소스(세션·remote forward)에만 적용. 기본 `"owned"`가 M3의 P0 결합을 그대로 재현하고 `"any"`는 명시 확대 | ROADMAP M5 감사 개정 ②, M3 감사 개정 ②, PRD §6 | 초안 확정 |
| 4 | acl.toml 부재/파손을 **원격 peer**가 알 수 있는가 | 없다. peer에게는 언제나 균일 `PERMISSION_DENIED`가 나가고 `CONFIG_ERROR`는 **운영자 대면**(stderr 진단·`qsh acl check`)에만 나타난다. architecture.md §6의 "운영자에게 `CONFIG_ERROR` 노출"을 이 뜻으로 읽는다 — peer에게 노출하면 그것이 곧 host 설정 상태 oracle이다 | architecture.md §6, ROADMAP M5 감사 개정 ③ | 확정 |
| 5 | `forward.socks`/`file.*` 거부의 오류 코드 | `PERMISSION_DENIED`(정책상 항상 거부). `-D` **플래그** 자체가 내는 `UNSUPPORTED`(M4 Step 6, 기능 미구현)와는 층이 다르며 둘 다 유지된다 — CLI는 플래그 단계에서 `UNSUPPORTED`로 끝나므로 action은 실무상 도달하지 않지만, wire로 직접 말하는 peer에게는 action 게이트가 답한다 | CLI.md §3.3·§6.9, ROADMAP §3 유예 가드레일 | 확정 |
| 6 | 정책 로딩 시점 | 프로세스 시작 시 1회. lazy load 금지(첫 요청 시 로드하면 "판정 불가" 창이 생기고 그 창의 fail-open이 M1부터의 불변식을 깬다). hot reload는 §3 비목표 | architecture.md §6, CLAUDE.md fail-closed | 확정 |
| 7 | 터널 할당량(principal별·forward별)은 M5인가 M8인가 | **M8.** ROADMAP M5 DoD에 쿼터 기준이 없고 M8 감사 개정 ③이 `[serve].max_sessions`·principal별 쿼터를 소유한다. `protocol.md` §7의 "M5 정책 엔진 범위" 두 문장을 Step 1이 M8 귀속으로 정정한다(문서를 먼저 고친다). **정정은 삭제가 아니라 이관이다** — 같은 커밋에서 `docs/ROADMAP.md` M8 감사 개정 ③의 범위 문장에 터널 전용 할당량(principal별·forward별 + remote-forward listener 개수 상한, protocol.md §7의 무상한 갭)을 명시 추가해 소유자를 함께 옮긴다. 무소유 갭 금지 | ROADMAP M5 DoD·M8 감사 개정 ③, protocol.md §7 | **확정 — main 세션 승인 (2026-08-27),** 좌측의 이관 조건부 |
| 8 | `Authorizer::check`가 rule index를 돌려주도록 시그니처를 바꾸는가 | 바꾼다(`Decision` → `Verdict{decision, rule}`). `AuditRecord.rule`이 M5+로 예약된 채 비어 있고 `acl check`가 같은 값을 보여야 하므로 판정과 rule은 한 번에 나와야 한다. Rust 내부 API이지 계약이 아니다 | audit.rs `rule` 필드 문서, architecture.md §6 | 확정 |
| 9 | `acl.check`를 원격 peer가 호출할 수 있는가 | 없다. 로컬 operation이며 §2.5의 "인가 불요" 행에 들어간다. 원격 정책 조회는 그 자체가 capability 열거 oracle | CLI.md §2.5, ROADMAP M5 감사 개정 ③ | 확정 |
| 10 | 거부 문면 통일의 대상 범위 | **원격 peer 대면 거부만.** localctl(same-uid 로컬 프로세스) 거부는 인가 계층이 아니라 로컬 머신 신뢰 경계라 통일 대상이 아니며, 그 경계를 테스트로 고정한다 | protocol.md §11-3, architecture.md §6 | 확정 |

### 4.2 구현 중 확정할 값 (측정·검토 후 상수화)

문서가 값을 정하지 않았고 계약도 아닌 것들. 구현 시 정하고 **해당 step의 (a)에 근거와 함께 추기**한다:

- **균일 거부 문면의 최종 문안** (초안 `"peer is not allowed to perform this operation on this host"`) — Step 4. action·리소스·principal 어느 것도 담지 않는다는 성질만 불변이다. **확정 — main 세션 (2026-08-27): 초안 그대로.** 불변 성질을 충족하고, 짧으며, 기존 문면들과 어휘 연속성이 있다.
- **`[audit].max_bytes` / `retain` / `queue_depth` 기본값** (초안 64 MiB / 5 / 1024) — Step 3. `max_bytes * (retain+1)`이 상시 디스크 예산이므로 두 값은 같이 정한다.
- **정책 파일 상한** (rule 수·행당 패턴 수·문자열 길이) — Step 2. 운영자 파일이라 적대적이지는 않지만 상한 없는 파싱은 두지 않는다.
- **`forward_id` 소유가 principal 기준인가 connection 기준인가** (초안: principal — `docs/CLI.md` §2.5의 "소유 **peer**"의 문자 그대로, 같은 principal의 다른 연결도 close 가능) — Step 5. 이 선택은 사용자 가시적이므로 §6.9/§6.14 문안 갱신을 동반한다. **확정 — main 세션 (2026-08-27): 초안 그대로(principal 기준).** §2.5 "소유 peer"의 문자적 의미와 일치하고, 이 제품의 전제 자체가 연결 수명과 리소스 수명의 분리(resume, §10)라 conn_id는 소유 축으로 부적합하다. 다만 오늘의 remote forward는 소유 연결이 죽으면 `purge_connection`이 함께 철거하므로, principal 축의 실효 이익은 "재접속 후 close"가 아니라 **같은 principal의 동시 두 번째 연결**과 세션 소유권 어휘와의 통일성이다(검증 라운드 P2 지적 반영 — 코드 주석도 이 실효 이익으로 정정).
- **`qsh acl check`의 `--owner` 표면을 M5에 넣는가** (초안: 넣는다 — `scope` 판정을 설명할 수 없으면 DoD 1의 "표 기반 증명"이 소유권 행을 커버하지 못한다) — Step 7. **확정 — main 세션 (2026-08-27): 초안 그대로 넣는다.** Step 5가 scope 판정을 이미 가동했으므로(owned 기본), `--owner` 없는 `acl check`는 소유권 행에서 enforcement와 다른 답을 낼 수 없고 그것은 DoD 1의 반례다. 표면은 `--owner <principal>` + `--owner-auth-path <pin|ca>`(생략 시 `pin` — rule 기본값과 같은 이유)이고, 접힘은 Ops가 프로덕션 `acl::opener_key`를 **그대로** 호출해 만든다 — opener_key의 내부 인코딩(`{auth_path:?}` Debug 포맷)은 CLI 표면·계약에 절대 노출하지 않고, 접힘 구현이 두 벌 생기지도 않는다. §6.15에는 `--owner`가 아직 없으므로 Step 7이 **문서 먼저**(추가는 additive) 갱신한 뒤 구현을 맞춘다.
- **시작 진단이 최소 정책 예시에 실제 peer 이름을 채우는가** (초안: 채운다 — trust store의 pinned peer가 이미 로컬 정보이고, 붙여넣기 가능한 예시가 마이그레이션 마찰을 실제로 줄인다) — Step 6. 다만 진단은 stderr이고 stdout 순수성을 해치지 않는다. **확정 — Step 6a 구현 완료 (2026-08-27): 초안 그대로.** trust.toml 부재·파손 시에는 generic placeholder로 우아하게 강등(검증 라운드 실증).
- **audit degraded 래치의 해제 조건** (초안: 다음 성공적 쓰기 — 주기적 재시도 없이 다음 결정 시도에서 자연히 재시도된다) — Step 3.

### 4.3 크기 정직성 — 2ew에 들어가는가

ROADMAP M5 크기는 **2ew**다. 이 계획이 세는 작업은 (i) 본 범위 4덩이(로더·평가기·`acl check`·구조화 audit), (ii) 감사 개정 3축(수명주기·소유권·문면), (iii) M4 이관 4건(다섯 번째는 §3이 재유예), (iv) 전환의 하네스 파급이다. **정직한 평가: 감사 개정 ①(audit 수명주기)과 ②(소유권 축)를 각각 온전한 step으로 세우면 2ew를 넘는다.** M3가 감사 개정분에 +0.5ew를 별도 계상한 선례가 있다(`docs/ROADMAP.md` M3 "크기: 2ew + 0.5ew(감사 개정분)").

범위를 **줄이자는 제안이 아니다** — ROADMAP 수용 기준은 정의상 DoD이고 감사 개정분은 그 안에 들어 있다. 제안은 두 가지다.
1. **크기 표기를 실태에 맞춘다.** `docs/ROADMAP.md` M5의 "크기: 2ew"를 M3와 같은 형식(`2ew + Xew(감사 개정분)`)으로 갱신할 것을 로드맵 소유자에게 제안한다. 이 계획은 로드맵을 대신 수정하지 않는다.
2. **압박이 오면 잘라낼 곳은 정해져 있다.** 우선순위는 **Step 1·2·3·4·6·8 > Step 5 > Step 7의 부가 표면**이다. 근거: DoD 5항목 중 Step 5(소유권 축)만이 DoD 문면에 직접 대응하는 항목이 없고(감사 개정 ② 자체는 범위 문장이지 수용 기준 문장이 아니다), 나머지는 전부 DoD 하나씩을 마감한다. 다만 Step 5를 미루면 `handle_rfwd_close`의 무인가·무audit 갭이 남고 그것은 **DoD 2(SC6 registry)가 실패로 잡는다** — 즉 Step 5를 잘라내는 선택은 DoD 2를 통과시키기 위해 registry에 예외를 파는 것을 뜻하며, 그것은 조용한 축소다. **따라서 Step 5는 잘라낼 수 있는 것이 아니라 "미루면 DoD 2가 막는" 항목으로 취급한다.** 실제로 잘라낼 여지는 Step 7의 `--owner` 표면과 Step 3의 `queue_depth` 튜닝 정도뿐이며, 그 이상은 마일스톤 재정의다.

## 5. 완료 절차

1. §1의 DoD 체크리스트 5항목 전건 통과를 **실제 테스트 실행 로그**로 확인한다(체크박스는 근거가 green일 때만; 각 항목에 "어느 Step이 심고 어느 테스트가 무엇을 단언하는지"를 M4본과 같은 상세도로 적는다).
2. **구속 문서 태그 대조**(ROADMAP §2 절차 1): `docs/CLI.md`·`docs/PRD.md`·`docs/adr/`에서 M5로 태그됐거나 M5가 계약으로 확정한 문장이 전부 DoD로 검증됐거나 후속(M6/M7/M8/P1) 유예로 명시 귀속됐는지 전수 대조. 특히 PRD §9의 action 11종·TOML 예시·default-deny 문장, CLI.md §2.5 매핑 표 전 행, architecture.md §6 전 문장이 대상이다. 어느 쪽도 아닌 문장이 하나라도 있으면 M5를 닫지 않는다.
3. **README 동기화**(ROADMAP §2 절차 2): "Security posture"가 정책 엔진 실태와 일치하고, Known limitations가 새 한계(hot reload 없음·쿼터 없음·`audit.log_argv` 미구현·audit fail-closed의 운영 함의)를 담는다. **인터임 고지가 실제 권한보다 좁으면 그 자체가 결함**이라는 규칙은 이번에는 반대 방향으로도 적용된다 — "allow-all among pinned peers"가 남아 있으면 실제보다 **넓은** 고지가 된다.
4. **M4 이관 (v)의 등재 확인**: forward-route live carrier와 `-R` 자동 재발행 부재가 `docs/ROADMAP.md` §3 유예 가드레일 표 또는 M8 백로그에 **소유자와 함께** 등재됐는지 확인한다(§3 표). PLAN.md에서 PLAN.md로만 넘기지 않는다.
5. **SC7 외부 보안 리뷰 예약**(`docs/ROADMAP.md` §4 리스크 5: "리뷰는 M5 시점에 예약"): 리뷰 계약·일정을 잡고 wire freeze(M8) 시점과의 6주 리드타임을 확인한다. 코드가 아니라 일정 산출물이며, M5 마감 체크리스트에 남긴다.
6. `docs/ROADMAP.md`의 "현재 위치" 줄과 M5 절 상태 표기를 "M5 완료"로 갱신하고, §4.3의 크기 표기 제안을 함께 판단한다(로드맵 문서 소유자의 몫 — PLAN.md는 지시만 하고 대신 수정하지 않는다).
7. Step 1·6·8이 갱신한 정본 문서와 최종 구현 사이 어긋남 최종 대조 — 어긋나면 **문서를 먼저 고치고** 코드를 맞춘다(각 문서 머리말 규칙).
8. 이 PLAN.md를 M6("MCP adapter") 실행 계획으로 전면 교체 — 과거 M5 계획은 git 이력에만. §3의 비목표 중 M6 입력(`acl.check`의 MCP tool 노출, `Ops` 타입에서 생성되는 tool schema)을 그 계획의 입력으로 옮긴다.
