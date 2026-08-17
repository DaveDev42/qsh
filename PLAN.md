# PLAN.md — M1 실행 계획

이 문서는 **현재 마일스톤(M1 — Walking skeleton)의 실행 계획**이다. 마일스톤 정의(범위·수용 기준·크기)의 정본은 항상 [`docs/ROADMAP.md`](docs/ROADMAP.md)이며, 이 문서는 그 정의를 바꾸지 않고 실행 순서로 분해한다. **M1이 Done 처리되면 이 문서는 다음 마일스톤(M2)의 계획으로 전면 교체된다** — living doc이며 과거 마일스톤의 실행 기록으로 남기지 않는다.

## 1. M1 목표 요약

`docs/ROADMAP.md` "M1 — Walking skeleton" 절 인용:

> `qsh init`(device identity 생성, keystore auto/platform/file + headless fallback), `qsh serve`(QUIC listener), `qsh trust add --fingerprint`, `qsh exec host --json -- cmd`. QUIC + TLS 1.3 상호 인증(pinned cert), frame codec 실사용, typed op layer(`version.get`/`exec.run`/`identity.init`/`trust.*`; schema.get 계약은 CLI.md에 존재하나 구현은 M7), JSON envelope·exit code 계약(§4), `Authorizer::check()` chokepoint(임시 allow-all-pinned) + op별 audit line, localhost 통합 하네스. hosts.toml 기반 host directory(M7)가 도입되기 전까지 `qsh exec <host>`의 host→주소 해석은 trust store(trust.toml)의 pinned peer(name→address)가 단일 출처다.

### DoD 체크리스트 (`docs/ROADMAP.md` M1 "수용 기준" 인용)

- [ ] `qsh exec host --json -- sh -c 'echo out; echo err >&2; exit 7'` → 프로세스 exit 7, `ok:true`, 올바른 `stdout_b64`/`stderr_b64`/`remote_exit_code:7`.
- [ ] 비신뢰 peer로 같은 명령 → exit 255 + `AUTH_FAILED`.
- [ ] Handshake matrix 16종(client/server cert × trust store 조합: pin 일치/불일치/만료/cert 없음/CA 모드 혼동) 전부 기대 결과.
- [ ] `-v` 진단은 stderr에만, stdout은 파싱 가능한 JSON 하나.

M1 크기: 3ew (`docs/ROADMAP.md` M1 "크기").

## 2. 작업 분해 (Step 1..7)

원칙: **모든 step은 완료 시점에 `cargo fmt --all` / `cargo clippy --workspace --all-targets -- -D warnings` / `cargo test`(또는 `cargo nextest run`) / `cargo run -p xtask -- arch` 전부 green을 유지해야 한다.** 이 게이트를 통과하지 못한 상태로 다음 step으로 넘어가지 않는다 (`CLAUDE.md` "Before committing").

각 step은 독립적으로 리뷰 가능한 PR 하나 크기로 잡는다. 순서는 의존 순 — wire 계약 → identity/keystore → trust store → transport(quinn/verifier) → serve dispatch + ACL chokepoint → exec end-to-end → handshake matrix/fixture 마감.

---

### Step 1 — Wire 계약: `.proto` v1 스케치 구체화 + JSON contract 타입 확장

**(a) 범위:** M1이 실제로 쓰는 control message 부분집합(`Hello`, `ControlMessage`/`Response`/`Error`, `ExecStart`/`ExecStarted`, `ExecFrame`(Stdin/StdinEof/Stdout/Stderr/ExecExit), `StreamHeader`, `Ping`/`Pong`)을 prost로 구체화한다. `SessionOpen`/`SessionAttach` 등 M2 이후 variant는 oneof에 아직 추가하지 않는다(M1 out-of-scope). `qsh-proto::types`에 `ExecRunReq`/`ExecRunData`, `IdentityInitData`, `TrustPeer`/`TrustAddReq`/`TrustAddData`/`TrustListData`/`TrustRemoveData` JSON contract 타입을 CLI.md §5/§6.8/§6.11 field-for-field로 추가한다.

**(b) crate/모듈/파일:**
- `crates/qsh-proto/proto/qsh/wire/v1.proto` (신규)
- `crates/qsh-proto/build.rs` (신규, prost-build)
- `crates/qsh-proto/src/wire.rs` 또는 `wire/mod.rs` (신규, generated code 포함 모듈)
- `crates/qsh-proto/src/types.rs` (확장 — 기존 `VersionData`/`Host`/`Session` placeholder 옆에 추가)
- `crates/qsh-proto/Cargo.toml` (prost/prost-build 의존성 추가)

**(c) 빚지는 테스트 (`docs/design/testing.md` L0):** 모든 신규 메시지의 `decode(encode(m)) == m` roundtrip (proptest+`arbitrary`), truncation(유효 인코딩의 모든 prefix가 `Err(Incomplete)`), allocation-bound(4GiB 주장 length prefix가 할당 전 거부 — 기존 `crates/qsh-proto/src/frame.rs`의 `CONTROL_FRAME_MAX`/`Oversize` 재사용), golden vector 1개 이상 체크인.

**(d) 완료 판정:** 신규 메시지 전부 L0 테스트 green. `ErrorCode`(`crates/qsh-proto/src/error.rs`)와 `Response.Error.code`가 동일 문자열 어휘를 쓰는지 단언하는 테스트 1개. arch-lint green(`qsh-proto`는 여전히 아무 workspace crate에도 의존하지 않음).

**(e) 인용:** `docs/design/protocol.md` §5(frame layer), §6(직렬화 근거), §7(스트림 배치), §9(.proto 스케치), `docs/CLI.md` §3.3(오류 코드 어휘), §5(Host/Session), §6.8/§6.11(exec/init/trust data shape), ADR-0001(custom QUIC 프로토콜 채택 근거).

---

### Step 2 — Identity: keypair, self-signed cert, 3-mode keystore, `identity.init`

**(a) 범위:** `qsh init` — Ed25519 키쌍 생성, `rcgen` 장기(10y) self-signed X.509 device cert 발급, `auto`/`platform`/`file` 3-mode keystore(headless fallback 포함), `identity.init` typed op(멱등 — 기존 identity면 `created:false`).

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/identity/mod.rs` (신규 — keypair/cert 생성, `KeyStore` trait + `platform`/`file` 구현)
- `crates/qsh-core/src/ops/mod.rs` (확장 — `IdentityInitOp`, `Ops::identity_init()`)
- `crates/qsh-core/src/config.rs` (신규 — `~/.config/qsh/` 경로 해석, `$QSH_CONFIG_DIR` override)
- `crates/qsh-cli/src/cli.rs` (확장 — `Command::Init`)
- `crates/qsh-cli/src/render/{human,json}.rs` (확장 — `identity.init` 렌더)
- `crates/qsh-core/Cargo.toml` (rcgen, keyring, zeroize 의존성 추가)

**(c) 빚지는 테스트 (`docs/design/testing.md` L1 keystore 절):** in-memory `KeyStore` 유닛 테스트, 플랫폼별 게이트 통합 테스트 각 1개(macOS Keychain / Linux Secret Service / **headless Linux file fallback** — "실전에서 가장 중요한 경로"). 키 바이트가 로그에 노출되지 않음을 단언(zeroize 사용 확인은 코드 리뷰 항목).

**(d) 완료 판정:** `qsh init --json`이 CLI.md §6.11 스키마와 일치하는 envelope 산출. 재실행 시 `created:false` 멱등 확인. `key_store` 필드가 실제 사용된 저장소를 정확히 보고(headless Linux에서 `file` 보고 필수).

**(e) 인용:** `docs/design/architecture.md` §5(Identity와 trust 문단 1~2), §7(config/state 경로), §8(rcgen/keyring 버전), `docs/CLI.md` §6.11(identity.init 계약, 실패 경로는 일반 `ErrorCode` 사용), `docs/ROADMAP.md` §4 일정 리스크 3번("Identity·keystore·pairing이 SC1의 critical path").

---

### Step 3 — Trust store: `trust.toml`, `TrustEvaluator` 골격, `trust.add/list/remove`

**(a) 범위:** pinned peer(이름+fingerprint+address) 저장/조회, `trust.add`(fingerprint 지정 시 연결 없이 pin, 멱등)/`trust.list`/`trust.remove`(멱등) typed op 3개 + CLI 서브커맨드. `qsh exec <host>`의 host→주소 해석이 trust store를 단일 출처로 쓰도록 조회 헬퍼도 함께 만든다(M7 이전 hosts.toml 부재 기간의 임시 계약).

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/trust/mod.rs` (신규 — `trust.toml` 로드/저장, `TrustStore`, pinned peer CRUD)
- `crates/qsh-core/src/ops/mod.rs` (확장 — `TrustAddOp`/`TrustListOp`/`TrustRemoveOp`)
- `crates/qsh-cli/src/cli.rs` (확장 — `Command::Trust { Add, List, Remove }`)
- `crates/qsh-cli/src/render/{human,json}.rs` (확장)

**(c) 빚지는 테스트:** `qsh-core` 유닛 테스트 — 신규 pin/멱등 재-add/remove 멱등/미존재 이름 조회. `docs/design/testing.md`가 명시하는 계층은 아니지만 L6 fixture(Step 7)로 최종 검증됨을 여기서 명시.

**(d) 완료 판정:** `trust add`/`list`/`remove` 각각 CLI.md §6.11 예시 envelope와 필드 일치(`peer`/`created`, `peers`, `name`/`removed`). fingerprint 지정 시 연결 없이 pin하는 경로만 Step 3의 완료 판정에 포함한다. fingerprint 없는 `trust add`가 `--json` 모드에서 대화형 prompt 대신 `TRUST_REQUIRED`(`details.observed_fingerprint`/`details.address`)를 반환하려면 실제 연결로 fingerprint를 관찰할 transport가 필요한데, Step 3 시점에는 transport(Step 4)가 아직 없어 이 경로를 테스트할 수 없다 — 따라서 이 경로는 Step 3의 완료 판정에서 전부 제외하고, 관련 코드에는 "transport 미배선" TODO 주석만 남긴 채 Step 6(exec.run end-to-end, transport와 ACL이 모두 갖춰진 시점)에서 실 handshake 관찰 기반으로 처음 구현·테스트한다(설계 문서의 새 결정이 아니라 구현 순서상 임시 상태이므로 §"미해결 질문"에는 기록하지 않는다).

**(e) 인용:** `docs/design/architecture.md` §5(Trust store 문단), §7(config 경로의 `trust.toml`), `docs/CLI.md` §2.5(`trust.*`는 local operation으로 원격 peer의 ACL 평가 대상이 아님), §6.11(trust.add/list/remove 계약), §6.8("hosts.toml 기반 host directory가 도입되는 M7 전까지는 trust.toml의 pinned peer가 host→주소 해석의 단일 출처"), ADR-0002(pairing UX — fingerprint 수동 확인은 1급 fallback).

---

### Step 4 — Transport: quinn endpoint, `QshPeerVerifier`(pin+CA), ALPN, frame codec 배선

**(a) 범위:** `qsh-transport`에 quinn client/server endpoint 구성(ALPN `qsh/1`, keep-alive 15s/idle 45s, 0-RTT 비활성), `QshPeerVerifier`(rustls `danger` verifier — pin 일치 → 허용, 아니면 private CA 체인 검증 → 허용, 그 외 거부, web PKI 미적재) + `TrustEvaluator` trait(구현은 `qsh-core::trust`가 주입). control 스트림 위에 Step 1의 frame codec(`qsh-proto::frame`)을 실제로 얹어 `ControlMessage` 송수신 루프를 만든다.

**(b) crate/모듈/파일:**
- `crates/qsh-transport/src/tls.rs` (신규 — `QshPeerVerifier`, `TrustEvaluator` trait)
- `crates/qsh-transport/src/endpoint.rs` (신규 — client/server `Endpoint` 구성)
- `crates/qsh-transport/src/control.rs` (신규 — control 스트림 위 framed `ControlMessage` 송수신)
- `crates/qsh-transport/src/lib.rs` (확장 — 위 모듈 재노출)
- `crates/qsh-transport/Cargo.toml` (quinn ≥0.11.14, rustls 0.23 aws-lc-rs, prost 의존성 추가)
- `crates/qsh-core/src/trust/mod.rs` (확장 — `TrustEvaluator` 구현)

**(c) 빚지는 테스트 (`docs/design/testing.md` L3):** in-process loopback QUIC(`127.0.0.1:0`, quinn endpoint 2개, subprocess 없음) — verifier pin 성공/실패, CA 성공/실패, keep-alive 동작, control 스트림 프레임 송수신 roundtrip. `cargo test`에서 항상 실행.

**(d) 완료 판정:** 두 로컬 endpoint가 pinned cert로 상호 TLS handshake 성공, `Hello` 교환 성공. 비신뢰 cert는 handshake 단계에서 거부(어떤 스트림도 application 계층에 도달하지 않음). 0-RTT 미사용 확인(`into_0rtt()` 미호출, 서버 early data 비활성).

**(e) 인용:** `docs/design/protocol.md` §2(QUIC 스택/전송 설정 — quinn ≥0.11.14, keep-alive/idle, 0-RTT 금지 근거), §3(`QshPeerVerifier` 검증 순서), §4(ALPN/버전/capability), §5(frame layer 재사용 — 이미 `qsh-proto/src/frame.rs`에 구현됨), `docs/design/architecture.md` §1(crate 의존 매트릭스 — `qsh-transport` → `qsh-proto`만), §5(Trust store 문단 — "검증 로직은 qsh-transport에 살되 신뢰 평가는 qsh-core::trust가 TrustEvaluator trait로 주입"), §8(quinn/rustls 버전 근거), `xtask/src/arch.rs`(강제되는 의존 매트릭스 — 이 step에서 `qsh-transport`가 `qsh-proto` 이외 workspace crate에 의존하지 않아야 함).

---

### Step 5 — `qsh serve` + dispatch 골격 + `Authorizer::check()` chokepoint(allow-all-pinned)

**(a) 범위:** `qsh serve --bind`(foreground 전용, `--bind` 우선순위: flag > config.toml > `[::]:4433` 기본값) — accept 루프, 연결마다 `Hello` 교환 후 control 메시지 dispatch. **모든 op 앞에서** `Authorizer::check(principal, action, resource)` 호출(M1 정책: pinned peer 전부 허용, 진짜 정책 엔진은 M5) + op별 구조화 audit 1줄(JSONL, `$XDG_STATE_HOME/qsh/audit.log`).

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/acl/mod.rs` (신규 — `Authorizer` trait, `AllowAllPinned` 구현, `Action` 타입)
- `crates/qsh-core/src/audit.rs` (신규 — 구조화 audit record: ts/request_id/principal/action/resource/decision — payload 필드 없음)
- `crates/qsh-core/src/server/mod.rs` (신규 — `dispatch(ControlMessage) -> Response`, ACL choke point 호출 지점)
- `crates/qsh-cli/src/cli.rs` (확장 — `Command::Serve { bind: Option<String> }`)
- `crates/qsh-cli/src/main.rs` (확장 — serve 모드는 envelope를 stdout에 내지 않고 bind 주소를 stderr에 출력)

**(c) 빚지는 테스트:** `qsh-core` 유닛 — `AllowAllPinned`가 pinned peer는 허용·비pinned는 거부, 모든 op 호출 경로가 chokepoint를 통과함을 mock dispatch로 단언(리소스 생성 이전에 ACL 통과를 요구하는 구조 자체를 테스트 — `docs/design/protocol.md` §7의 "ACL 통과 후에만 ticket 발급" 규칙의 M1 축소판). `docs/design/testing.md` L3(loopback QUIC 위에서 accept→dispatch 통합).

**(d) 완료 판정:** `qsh serve` 시작 시 실제 bind 주소가 stderr에 출력되고 stdout은 비어 있음. 비신뢰 peer의 연결 시도가 handshake 단계 또는 ACL 단계에서 거부되고 audit에 deny로 기록됨. audit record에 argv/PTY/key 내용이 담길 필드 자체가 없음(타입 검사로 확인).

**(e) 인용:** `docs/CLI.md` §6.12(serve 계약 — foreground 전용, `--bind` 우선순위, stdout/stderr 규칙), `docs/design/architecture.md` §6(ACL 엔진과 audit — "호스트 측 `server::dispatch`가 리소스 생성 이전에 `Authorizer::check` 호출", "audit 레코드 타입에 payload 필드가 없음"), `docs/ROADMAP.md` 시퀀싱 원칙 5번("ACL은 두 단계로 분리 — 인가 지점은 M1부터, 정책 엔진은 M5"), 7번(c)("connection 방향과 세션 역할을 독립 축으로 유지" — M1은 축 도입만, 실제 역방향은 M3), `crates/qsh-core/src/ops/mod.rs`(기존 `Operation`/`OpError` 패턴 재사용).

---

### Step 6 — `exec.run` end-to-end

**(a) 범위:** `qsh exec host --json -- cmd` 전체 척추 — `ExecStart` control 요청(argv/env/timeout) → ACL `exec.run` 검사 → `ExecStarted{exec_id, ticket}` → `EXEC_DATA` 스트림에 `StreamHeader{EXEC_DATA, ticket}` → 자식 프로세스 spawn(비-PTY, stdin/stdout/stderr pipe) → `ExecFrame::{Stdout,Stderr}` 프레이밍 → 종료 시 `ExecExit{exit_code, signal}` → 클라이언트가 `stdout_b64`/`stderr_b64`/`remote_exit_code`로 조립. exit code clamp(remote 255 → process exit 254, JSON `remote_exit_code`는 실값 유지) 로직은 `qsh-cli`에만 존재.

**(b) crate/모듈/파일:**
- `crates/qsh-core/src/exec/mod.rs` (신규 — 서버측 spawn, `EXEC_DATA` 스트림 프레이밍)
- `crates/qsh-core/src/ops/mod.rs` (확장 — `ExecRunOp`, `Ops::exec_run()` — 클라이언트측: dial→Hello→ExecStart→data stream 소비)
- `crates/qsh-cli/src/cli.rs` (확장 — `Command::Exec { host, args }`, `--` 뒤 argv는 shell 재해석 없음)
- `crates/qsh-cli/src/main.rs` (확장 — exit code clamp, 254 규칙)
- `crates/qsh-cli/src/render/json.rs` (확장 — `exec.run` envelope)

**(c) 빚지는 테스트:** L3 loopback 통합 — in-process QUIC endpoint 2개(qsh 바이너리 subprocess 없음) 위에서 서버측이 실제 `sh -c` 자식 프로세스를 spawn하는 데까지 포함한 localhost 통합 하네스(`crates/qsh-testkit`, ROADMAP M1 "localhost 통합 하네스" 항목). ticket이 ACL 통과 전에 발급되지 않음을 단언(`docs/design/protocol.md` §7 ticket 규칙).

**(d) 완료 판정:** DoD 1번째 항목(`echo out; echo err >&2; exit 7` → exit 7, `ok:true`, 올바른 `stdout_b64`/`stderr_b64`/`remote_exit_code:7`)이 실제로 통과. DoD 2번째 항목(비신뢰 peer → exit 255 + `AUTH_FAILED`)도 이 step에서 처음 end-to-end로 통과 가능해짐(Step 3의 TODO가 여기서 해소됨).

**(e) 인용:** `docs/CLI.md` §4(exit code 규칙 — 254 clamp, source of truth는 JSON), §6.8(exec 계약, 결과 envelope 예시), `docs/design/protocol.md` §7(스트림 배치 표의 "Exec data" 행, ticket 발급 규칙), §9(`.proto` 스케치의 `ExecStart`/`ExecFrame`), `docs/design/architecture.md` §2(typed operation layer 확장 패턴), `docs/ROADMAP.md` 시퀀싱 원칙 2번("Walking skeleton은 PTY가 아니라 exec — expect 하네스 없이 CI에서 완전 자동화").

---

### Step 7 — Handshake matrix(16종) + L6 fixture/exit-code/JSONL 순수성 마감

**(a) 범위:** M1 DoD의 나머지 두 항목을 직접 겨냥한 마감 step. (i) 표 기반 handshake matrix: (client cert, server cert, client trust store, server trust store, 모드[pin/CA]) 조합 16종 — fingerprint 불일치, 만료 cert, 다른 CA 서명, pin-only 모드에 CA 서명 cert, CA 모드에 self-signed, client cert 부재, 정상 pin, 정상 CA 등. (ii) `crates/qsh-cli/tests/fixtures/cli-v1/`에 `identity.init`/`trust.add`/`trust.list`/`trust.remove`/`exec.run` golden fixture 추가(append-only, 기존 `version.json`은 그대로 유지). (iii) exit-code matrix(시나리오→exit code/`ok`/`error.code`)를 human/JSON 양 모드에서. (iv) `-vv --jsonl`로 시끄러운 exec 실행 후 stdout 전 줄이 완전한 JSON object임을 단언.

**(b) crate/모듈/파일:**
- `crates/qsh-transport/tests/handshake_matrix.rs` (신규)
- `crates/qsh-cli/tests/fixtures/cli-v1/{identity.init,trust.add,trust.list,trust.remove,exec.run}.json` (신규, append-only)
- `crates/qsh-cli/tests/exit_code_matrix.rs` (신규)
- `crates/qsh-cli/tests/jsonl_purity.rs` (신규)
- `crates/qsh-testkit/src/lib.rs` (확장 — fixture loader, 필요 시 loopback endpoint 헬퍼)

**(c) 빚지는 테스트:** `docs/design/testing.md` L1(handshake matrix 16종 — 이 step의 핵심 산출물), L6(golden fixture append-only, `ErrorCode` 전수 도달성 — 이 step에서 M1이 실제로 생성 가능한 코드(`AUTH_FAILED`/`TRUST_REQUIRED`/`INVALID_ARGUMENT`/`INTERNAL` 등)만큼 fixture 커버리지 확보, exit-code matrix, JSONL 순수성).

**(d) 완료 판정:** DoD 3번째 항목(handshake matrix 16종 전부 기대 결과), 4번째 항목(`-v` 진단 stderr 전용, stdout은 단일 JSON) 통과. `qsh schema --json`으로 검증하려던 스키마 서빙은 M7 구현이므로(§1 인용 "schema.get 계약은 CLI.md에 존재하나 구현은 M7") 이 step에서는 schemars로 생성한 JSON Schema를 **테스트 내부에서만** fixture 검증에 쓰고 `qsh schema` 커맨드 자체는 만들지 않는다.

**(e) 인용:** `docs/design/testing.md` L1("M1의 수용 기준인 16종 조합이 여기서 나온다"), L6(golden fixture/ErrorCode 전수 도달성/exit-code matrix/JSONL 순수성 4항목 전부), `docs/ROADMAP.md` M1 DoD 3·4번째 항목, `docs/CLI.md` §2.2(stdout/stderr 분리 규칙), §10(compatibility policy — fixture append-only가 이 정책의 기계적 강제).

---

## 3. 명시적 non-goals (M2+ 유예)

`docs/ROADMAP.md` M1 절 "명시적 out" 인용: **PTY, 세션, resume, private CA, invite code pairing, 터널, reverse, 정책 파일.**

추가로 M1 범위에 넣지 않는 항목(같은 문서의 다른 조항에서 파생):

- **`schema.get` 구현** — CLI.md §6.10에 계약은 존재하나 ROADMAP M1 절이 명시적으로 "구현은 M7"이라 못박음. Step 7에서 schemars 스키마는 fixture 검증용 내부 도구로만 쓰고 `qsh schema` 커맨드는 만들지 않는다.
- **`doctor.run`** — CLI.md §6.11: "`doctor.run`은 operation 이름만 예약되어 있으며 계약은 M7에서 확정한다."
- **ACL 정책 엔진(TOML 기반 principal/wildcard 매칭)** — `docs/ROADMAP.md` 시퀀싱 원칙 5번, M5 범위. M1의 `Authorizer::check()`는 allow-all-pinned 고정 정책만 구현한다.
- **hosts.toml 기반 host directory** — M7 범위(`docs/CLI.md` §6.8, `docs/design/architecture.md` §7 config 경로 표 주석). M1의 host→주소 해석은 trust.toml 단일 출처(Step 3).
- **P1/P2 유예 기능** 전반(`docs/ROADMAP.md` §3 유예 가드레일 표) — TCP/TLS fallback, SOCKS `-D`, file copy, Windows, multi-attach, local echo prediction, relay, cert rotation UX, service 설치. M1은 이 중 어떤 CLI flag도 새로 노출하지 않으므로(`-L`/`-R`/`-D`는 M4 범위) "flag는 파싱하되 UNSUPPORTED 반환" 가드레일이 실제로 발동하는 표면이 없다 — M4 이후 해당 flag가 도입될 때 지켜야 할 규율로만 여기 기록해 둔다.

## 4. 리스크와 감시 항목

`docs/ROADMAP.md` §4 "일정 리스크 5건" 중 M1과 직결되는 항목 인용:

> 3. **Identity·keystore·pairing이 SC1(간판 숫자)의 critical path.** headless Linux에 Secret Service 부재 → file fallback + doctor 보고 필수, macOS 미서명 바이너리의 Keychain 재프롬프트가 dev loop을 괴롭힘. 대응: keystore fallback을 M1의 명명된 task로, 스톱워치 테스트를 M7 한 번이 아니라 조기·반복 실행.

→ **Step 2**에 직접 매핑. `key_store` 필드가 headless 환경에서 정확히 `file`을 보고하는지가 이 리스크의 M1 관측 지점이다.

`docs/design/architecture.md` §9 "아키텍처 리스크 5건" 중 M1이 지금 지켜야 할 구조적 항목:

> 2. **In-listener 세션 vs listener 재시작** — seam(`SessionBackend`+UDS)이 오염되면 supervisor 전환이 재작성이 된다. 대응: broker의 transport 타입 import 금지를 유지(arch-lint 확장 후보)...

→ M1에는 broker가 아직 없지만(**Step 5**), `qsh-core::server::dispatch`가 `qsh-transport`의 구체 타입을 그대로 노출하지 않고 trait/추상 타입 경계를 지키도록 지금부터 설계한다 — M2에서 broker가 이 경계 위에 얹힐 때 재작업을 피하기 위함. `docs/ROADMAP.md` 시퀀싱 원칙 7(a)(b)(c)의 "M1부터 지켜야 할 선행 불변식"(output byte sequence 태깅, `Authorizer::check`+audit, 연결 방향/세션 역할 축 분리)도 같은 이유로 M1 코드에 구조적으로 반영한다 — 기능은 나중이어도 구조는 지금.

> 3. **Headless Linux 키 저장** — platform store 부재 시 file fallback이 조용히 일어나면 보안 태세 공백. 대응: init/doctor의 명시 보고를 계약으로 유지.

→ 위 ROADMAP 리스크 3번과 동일 지점, **Step 2**.

## 5. 완료 절차

1. §1의 DoD 체크리스트 4항목 전건 통과를 실제 테스트 실행 로그로 확인한다(체크박스는 근거 테스트가 green일 때만 표시).
2. `docs/ROADMAP.md`의 "현재 위치" 줄과 M1 절 상태 표기를 "M1 완료"로 갱신한다(로드맵 자체는 이 계획 문서가 아니라 로드맵 문서 소유자가 갱신 — PLAN.md는 이 절차를 지시만 하고 ROADMAP.md를 대신 수정하지 않는다).
3. 이 PLAN.md를 M2("세션 broker + PTY + resume") 실행 계획으로 전면 교체한다 — 과거 M1 계획은 git 이력에만 남긴다.
