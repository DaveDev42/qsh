# ADR-0007: `session_ref`는 클라이언트 `Ops`가 조립하고 resume token은 클라이언트 상태 파일에만 둔다

날짜: 2026-08-18
상태: 승인됨

## 맥락

M2(세션 broker + resume) 계획 중 두 가지 정의 공백이 드러났다(PLAN.md §4.1 질문 3·4).

1. `session_ref`의 조립 주체. architecture.md §2는 "서버 발급 opaque 값", CLI.md §5는 "CLI가 반환하는 opaque value"였고 예시는 `personal-mac/01K0SESSION`처럼 `<host-alias>/<session_id>` 형태다. 그런데 원격 호스트는 클라이언트가 자신을 어떤 alias(trust store/hosts.toml의 이름)로 부르는지 알 수 없으므로 서버가 이 값을 만들 수 없다.
2. wire `SessionOpened`/`SessionAttached`는 `resume_token`(protocol.md §10, 32-byte CSPRNG, 매 attach마다 rotation)을 반환하지만 CLI.md §6.3의 `session.open` data는 `session_ref`/`initial_sequence`뿐이다. 기계 사용자(`--json`, MCP)가 재attach하려면 토큰을 JSON에 additive 필드로 노출해야 하는지, 아니면 클라이언트 상태에만 남기는지 정해야 했다.

## 결정

1. **`session_ref`는 클라이언트의 `Ops` 계층(qsh-core)이 조립한다.** 서버는 opaque·URL-safe한 `session_id`만 발급·해석하고 wire(`SessionOpened`, `SessionList` 결과)에는 `session_ref`가 없다. `Ops`는 `<host-alias>/<session_id>` 형태로 조립해 반환하고, 입력으로 받은 `session_ref`를 (host alias → connection, session_id)로 해석한다. 조립 형식은 구현 세부이며 사용자·frontend·MCP 호출자에게는 계속 opaque다 — 파싱하지 않고 받은 그대로 되돌려 준다. **파싱 규칙(호출자 입력은 신뢰하지 않는다 — testing.md L8 fuzz 대상):** `session_ref = host-alias "/" session_id`, 분해는 **마지막 `/`** 기준(`session_id`는 `/`를 포함하지 않는 26자 Crockford base32 ULID이므로 alias에 `/`가 있어도 안전), alias 부분은 비어 있을 수 없다. 문법 위반은 원격 요청 없이 `INVALID_ARGUMENT`, 미등록 alias는 `HOST_NOT_FOUND`로 로컬에서 거부한다 — fail closed.
2. **`resume_token`은 어떤 출력 모드·어떤 `*Data`에도 노출하지 않는다.** 토큰은 클라이언트 상태 파일 `$XDG_STATE_HOME/qsh/resume.json`(0600)에 `session_ref`를 key로 저장·rotation되고, 기계 사용자는 `session_ref`만으로 재attach한다(`qsh attach <session-ref>`, `session read --follow`). 토큰 조회·제시는 `Ops`의 내부 동작이다. **토큰이 필요한 것은 wire `SessionAttach`(= `session.attach`와 대화형 attach)뿐이다** — `session.get/read(--wait·--follow)/write/resize/close`는 control 스트림 value op이며 ACL만으로 동작한다(CLI.md §6.3). 해당 `session_ref`의 토큰이 없으면 attach는 원격 요청 없이 로컬에서 `SESSION_NOT_FOUND`(`details.reason: "no_resume_token"`)로 실패한다 — fail closed. 따라서 attach는 세션을 연 장비에서만 가능하다(peer SPKI 결합과 일치, protocol.md §10); 다른 장비는 `session.list`에 보이는 세션을 읽거나 닫을 수는 있어도 attach할 수 없다 — MVP의 알려진 제한이며 세션 이관은 P1이다(아래 대안 절).

## 근거

- alias는 클라이언트 로컬 지식이다(같은 호스트를 두 클라이언트가 다른 이름으로 pin할 수 있다). 조립 지점은 그 지식이 있는 곳, 즉 클라이언트 `Ops`여야 하며, `Ops`는 세 frontend가 공유하는 유일한 계층이므로(architecture.md §2) 조립 로직이 렌더러/adapter로 새지 않는다.
- 토큰을 JSON에 실으면 (a) `--json` 출력이 스크립트 로그·CI 아티팩트·MCP 대화 기록에 그대로 남아 credential 유출 표면이 생기고, (b) 계약이 additive-only이므로 한 번 실으면 되돌릴 수 없으며, (c) 호출자가 토큰을 다시 넣어 줘야 하는 API가 되어 MCP long-poll 모델(CLI.md §8.3 — `session_ref` + cursor만)과 어긋난다. `session_ref`만으로 충분한 API가 더 작고 안전하다.
- 토큰 단독으로는 무용하고(peer SPKI 결합, protocol.md §10) 상태 파일은 이미 protocol.md §10이 정한 보관처다 — 이 ADR은 "거기에만" 둔다는 점을 계약으로 못 박을 뿐이다.
- 토큰이 없을 때 원격에 빈 attach를 보내지 않는 것은 non-distinguishing 오류 정책(protocol.md §10)과 무관하게 로컬에서 판정 가능하며, 불필요한 실패 요청·audit 잡음을 만들지 않는다.

## 대안과 기각 사유

- **서버가 `session_ref`를 발급**: 기각. 서버는 클라이언트 alias를 모른다. `Hello`에 alias를 실어 보내는 방식은 identity 유사 정보를 wire에서 취하는 모양이 되어(protocol.md §3 "wire 데이터에서 identity를 취하지 않는다") 혼동을 부르고, 이득이 없다.
- **`session_ref` = `session_id`(host 없이)**: 기각. `qsh attach <session-ref>`가 어느 host로 dial할지 알 수 없어 호출자가 host를 따로 들고 다녀야 하며, 이는 CLI.md §5 "호출자가 조합하지 않는다"의 정신과 어긋난다.
- **`resume_token`을 `session.open` data의 optional 필드로 노출**: 기각(위 근거). 필요해지면(예: 다른 장비로 세션 이관 — 현재는 peer SPKI 결합 때문에 어차피 불가) 별도 명시적 op로 P1 이후 검토한다.
- **토큰을 OS keychain에 저장**: 기각(protocol.md §10에서 이미 기각 — 재접속마다 인증 프롬프트).

## 결과

- CLI.md §5·§6.3, architecture.md §2·§7, protocol.md §9·§10을 이 결정에 맞게 갱신했다.
- `qsh-core` `Ops`: `session.open`/`session.list`/`session.get` 결과에서 `session_ref` 조립, 모든 session op 입력에서 `session_ref` 해석, `resume.json` 읽기/쓰기/rotation을 담당한다. `qsh-proto`의 `*Data` 타입에는 `resume_token` 필드가 존재하지 않는다(testing.md L6 "노출 금지 field" 부정 테스트 — 생성 스키마·fixture·JSONL event 어디에도 `resume_token`이 등장하지 않음을 단언).
- wire `Session` 메시지에는 `session_ref`가 없다; `session_id`는 opaque·URL-safe(ULID)로 발급한다.
- wire `SessionInfo`에는 `session_ref`도 `host`도 없다(둘 다 클라이언트 alias 지식). JSON `types::Session`은 `Ops`가 두 field를 채워 만든다.
- 상태 파일 `resume.json`: 0600, key = `session_ref`, value = {token, host_alias, session_id, **peer_spki_sha256**, **expires_at**(wire `SessionOpened`/`SessionAttached`의 `expires_at`), updated_at}.
  - **제시 조건:** `Ops`는 연결된 peer의 SPKI fingerprint가 항목의 `peer_spki_sha256`과 일치할 때만 토큰을 보낸다. 불일치(alias가 다른 장비로 re-pin된 경우 등)는 토큰을 보내지 않고 로컬 `SESSION_NOT_FOUND`(`details.reason: "peer_mismatch"`)로 fail closed하고 항목을 폐기한다.
  - **원자성·durability·동시성:** 쓰기는 같은 디렉터리에 `resume.json.tmp`를 0600으로 **생성한 뒤** 기록·fsync·`rename(2)`하는 원자적 교체이고, 프로세스 간(CLI + `qsh mcp` + `--follow` 등 동시 실행) read-modify-write는 파일 락(`flock`)으로 직렬화한다. rotation은 `SessionAttached`의 `new_resume_token`을 **durable하게 기록한 뒤에야** data 스트림을 진행한다 — 기록 실패는 attach 실패로 처리한다(단일 세대 토큰이므로 유실은 곧 영구 orphan, fail closed).
  - **정리:** 항목은 (i) `session.closed` 수신, (ii) attach가 `AUTH_FAILED`/`SESSION_NOT_FOUND`로 실패, (iii) `expires_at` 경과 중 하나면 즉시 삭제하고, 로드 시 만료 항목을 먼저 정리한다(호스트는 stale 토큰에 non-distinguishing `AUTH_FAILED`로 답하므로 (ii)·(iii)이 지배적 경로다).
  - **위생:** 토큰은 `Zeroizing<[u8; 32]>`, 토큰을 담는 타입은 `Debug`에서 `<redacted>`(architecture.md §5).
