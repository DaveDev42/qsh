# QSH CLI, JSON and MCP Contract

**상태:** Draft v0.10 (M3 Step 8 — 역방향 위 resume: §6.4 recovery 진단의 `registration_wait_ms`가 실제로 채워짐(정방향 `0`, 역방향은 재등록 대기 시간) — `recovery` 값 집합은 무변경, 필드는 M2 세 필드 뒤에 additive로 붙는다; v0.9 = M3 Step 7 — 대화형 attach(`qsh [user@]host`/`qsh attach`)가 역방향 등록 host를 향해서도 §6.13의 `LOCAL_CONTROL`/`LOCAL_STREAM` 경로를 타도록 landing — §6.13 갱신(더 이상 forward 전용이 아님, 그리고 역방향 leg에는 reconnect/recovery가 없다는 점 명시); v0.8 = M3 Step 1 — `Host`의 `state`/`device_id` 값 어휘 확정과 역방향 등록 ACL 매핑(§2.5·§5)·`host.list`/`host.get` 데이터 소스(§6.1)·recovery 진단의 `registration_wait_ms`(§6.4)·신규 §6.13 `qsh listen`/`qsh reverse` 계약 추가; v0.7 = M2 Step 7 — `session.attach`는 resume credential을 **반드시** 요구하며 그 실패는 항상 non-distinguishing `AUTH_FAILED`임을 §6.3·§6.4에 명문화; v0.6 = `session read --follow` 출력 형태와 `--wait` 하한 명문화, v0.5 = M2 계약 확정, v0.4 = M1 구현과 동기화)  
**대상:** QSH MVP  
**Canonical interface:** `qsh` CLI

## 1. 목적

QSH는 하나의 명령 체계를 사람, shell script와 MCP client가 함께 사용하도록 설계한다.

- 기본 출력은 사람이 읽기 쉽다.
- `--json`과 `--jsonl`은 안정된 machine-readable contract다.
- `qsh mcp`는 동일한 내부 operation을 MCP tool로 노출한다.
- CLI와 MCP 사이에 별도 business logic이나 권한 모델을 만들지 않는다.

```text
Typed QSH operations
├── Human renderer
├── JSON / JSONL renderer
└── MCP stdio adapter
```

## 2. 공통 규칙

### 2.1 출력 모드

| 옵션 | 용도 |
|---|---|
| 기본값 | 사람이 읽는 text/TUI 출력 |
| `--json` | 명령 하나의 최종 결과 |
| `--jsonl` | 장시간 실행되거나 streaming되는 event |

Global output flag는 subcommand 앞뒤에서 동일하게 동작한다.

```bash
qsh --json hosts
qsh hosts --json
```

`--json`과 `--jsonl`은 동시에 사용할 수 없다. Machine-readable mode에서는 색상, spinner, progress bar와 interactive prompt를 출력하지 않는다.

추가 입력이 필요한 경우 prompt 대신 `TRUST_REQUIRED` 또는 `INVALID_ARGUMENT` 오류를 반환한다.

### 2.2 stdout과 stderr

- stdout: 요청한 결과 또는 JSONL event만 출력
- stderr: 진단 로그와 verbose trace
- PTY 및 remote command stderr: QSH 진단 stderr와 섞지 않고 protocol data로 전달
- `--quiet`: 성공 시 진단 출력 억제
- `-v`, `-vv`: stderr 진단 수준 증가

### 2.3 안정성

- 모든 JSON object는 `schema`를 포함한다.
- 식별자는 숫자로 변환하지 않는 opaque string이다.
- 시간은 UTC RFC 3339, 기간은 integer milliseconds다.
- Byte sequence는 JSON에서 standard Base64로 표현한다.
- 알 수 없는 field는 무시할 수 있어야 한다.
- 기존 field의 의미 변경과 삭제는 새 major schema가 필요하다.
- `sequence`는 chunk index가 아니라 세션 수명(session lifetime) 동안 누적된 output byte 수(u64)다. 각 `session.output` event의 `sequence`는 해당 chunk까지 포함한 누적 byte offset, 즉 그 chunk의 마지막 byte offset + 1이다. 상세 계약은 §6.4를 참고한다.

### 2.4 Operation 이름

CLI의 `command`, JSON envelope, audit record와 MCP tool mapping은 하나의 dotted operation 이름을 공유한다. 각 operation이 요구하는 ACL action은 §2.5의 매핑 표에서 정의한다.

```text
host.list
host.get
session.list
session.get
session.open
session.read
session.write
session.resize
session.close
session.attach
exec.run
tunnel.open
tunnel.close
tunnel.list
identity.init
trust.add
trust.list
trust.remove
doctor.run
schema.get
capabilities.get
version.get
```

`session.attach`는 value operation이 아니라 stream operation이다 (§7.1 참고). CLI subcommand 표기(`qsh hosts`, `qsh session open` 등)와 이 dotted 이름은 서로 다른 계층이며, envelope의 `command` field·audit record·MCP mapping은 항상 이 dotted 이름을 사용한다.

`qsh serve`, `qsh listen`, `qsh reverse`는 operation이 아니라 장기 실행 모드(long-running mode)다. 단일 요청/응답 계약이 없으며 이 목록에 포함되지 않는다.

실행 중인 세션에 **신호만** 보내는 별도 operation(`session.signal`)은 M2 범위가 아니다(P1 후보 — 이 목록에 없다). M2에서 신호를 보내는 유일한 CLI 표면은 `qsh session close --signal <SIG>`(§6.7)이며, 신호는 wire `SessionClose`의 optional `signal` field로 전달된다(ACL은 §2.5의 `session.close` 행 그대로 `session.control`). wire 번호 25(`SessionSignal`)는 **예약만** 하고 M2에서는 메시지를 정의·전송하지 않는다 — 호스트가 25번을 수신하면 리소스 생성 없이 `UNSUPPORTED`로 답한다(protocol.md §9).

### 2.5 Operation과 ACL action 매핑

ACL action은 인가(authorization) 어휘로, operation 이름과는 별개 차원이다. 하나의 action이 여러 operation을 커버할 수 있다. 전체 action 목록은 PRD §9에서 정의하며, 원격 peer가 요청한 operation은 아래 매핑에 따라 인가된다.

| Operation | 필요 ACL action |
|---|---|
| `session.open` | `session.open` |
| `session.list`, `session.get` | `session.list` |
| `session.read`, `session.attach` | `session.attach` |
| `session.write`, `session.resize`, `session.close` | `session.control` |
| `exec.run` | `exec.run` |
| `tunnel.open` (local forward) | `forward.local` |
| `tunnel.open` (remote forward) | `forward.remote` |
| `tunnel.close`, `tunnel.list` | 해당 tunnel의 소유 peer이면 허용 (`forward.*` 부여로 충분) |
| `host.list`, `host.get`, `identity.init`, `trust.*`, `doctor.run`, `schema.get`, `capabilities.get`, `version.get` | 인가 불요 — local operation으로 원격 peer의 ACL 평가 대상이 아님 |

향후 예약: streaming file copy → `file.read`/`file.write`, SOCKS(`-D`) → `forward.socks`.

역방향 host 등록은 operation이 아니라 **연결 수립 시점의 검사**다 — 위 표는 operation→ACL action 매핑이고 `qsh listen`/`qsh reverse`는 §2.4가 명시하듯 operation이 아닌 장기 실행 모드이므로 표에 행을 만들지 않는다. `qsh reverse`(target)가 `qsh listen`(controller)에 dial해 보내는 `Hello.reverse`(protocol.md §9·§11)를 controller가 인증서로 인증한 뒤, 그 principal에 ACL action `host.reverse`를 검사한다 — 통과해야만 registry에 등록된다(default deny, PRD §9).

## 3. JSON envelope

### 3.1 성공

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "host.list",
  "ok": true,
  "data": {
    "hosts": []
  }
}
```

### 3.2 실패

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "session.attach",
  "ok": false,
  "error": {
    "code": "PERMISSION_DENIED",
    "message": "peer is not allowed to attach to this session",
    "retryable": false,
    "details": {}
  }
}
```

`message`는 사람을 위한 설명이다. 자동화는 `code`와 구조화된 `details`만 사용해야 한다.

### 3.3 기본 오류 코드

```text
INVALID_ARGUMENT
CONFIG_ERROR
HOST_NOT_FOUND
CONNECTION_FAILED
AUTH_FAILED
TRUST_REQUIRED
PERMISSION_DENIED
SESSION_NOT_FOUND
SESSION_CONFLICT
RESUME_GAP
TIMEOUT
CANCELED
REMOTE_ERROR
UNSUPPORTED
RESOURCE_EXHAUSTED
INTERNAL
```

오류 코드는 추가될 수 있다. 알 수 없는 code는 일반 QSH 오류로 처리한다. `RESUME_GAP`은 M2에서 **event 전용 상황**이다 — replay 범위 이탈은 항상 `session.gap` event(§6.4)로 전달되며 오류 envelope로는 반환되지 않는다(도달성 테스트에서는 이 사유로 DEFERRED 유지; 오류로 반환하는 strict read 옵션은 P1에서 검토). `UNSUPPORTED`는 요청한 기능이 아직 구현되지 않았거나 peer와 협상되지 않은 경우(예: P1 기능인 `-D`/SOCKS)에 사용한다. `RESOURCE_EXHAUSTED`는 backpressure나 서버측 한도 초과를 나타낸다.

## 4. Process exit code

일반 명령:

| Code | 의미 |
|---|---|
| `0` | QSH operation 성공 |
| `2` | CLI syntax 또는 argument 오류 |
| `255` | 연결, 인증, 정책 등 QSH runtime 실패 |

`qsh exec`는 OpenSSH와 마찬가지로 remote process의 exit code `0..254`를 그대로 반환한다. QSH 자체의 실패는 `255`다. JSON 결과에는 `remote_exit_code`와 QSH 오류가 구분되어 있으므로 자동화는 stdout JSON도 함께 확인한다.

Remote process가 정확히 `255`로 종료한 경우, QSH 자체 실패(`255`)와 구분할 수 없게 되는 것을 막기 위해 qsh exec의 프로세스 exit code는 `254`로 clamp된다. 이때도 JSON 결과의 `remote_exit_code`는 실제 값(`255`)을 그대로 담으며, exit code의 source of truth는 항상 JSON이다.

대화형 세션(`qsh [user@]host`, `qsh attach <session-ref>`, §7)은 원격 셸이 종료되면 그 exit code를 `qsh exec`와 같은 규칙(`0..=254`, `255`는 `254`로 clamp)으로 반환하고, escape 시퀀스 detach(§7)는 세션을 살려 둔 채 `0`으로 종료한다. 신호로 죽은 셸도 `qsh exec`와 같은 값이다: `session.exit`의 `signal`(§6.4)을 `128 + signo`로 되돌려 clamp 규칙에 태운다(예: `SIGHUP` → `129`, `SIGKILL` → `137`). `254`는 remote `255`의 clamp 결과이거나 **호스트가 종료 상태를 알려 주지 못한 경우**(`exit_code`와 `signal`이 모두 null, §6.4)를 뜻하며, 연결이 끊겨 종료 상태를 아예 받지 못한 경우는 QSH 자체 실패라 `255`다.

Output mode에 따라 exit code 의미가 달라져서는 안 된다. 대화형 form(§7)은 machine output mode 자체가 없으므로 이 규칙의 대상이 아니다 — `--json`/`--jsonl`을 붙이면 세션을 만들지 않고 `INVALID_ARGUMENT`로 거부한다(§7).

## 5. 핵심 data type

### Host

```json
{
  "name": "personal-mac",
  "address": "personal-mac.example.com:4433",
  "connection_mode": "forward",
  "state": "unknown",
  "device_id": "sha256:BASE64FINGERPRINT"
}
```

`connection_mode ∈ {"forward", "reverse"}`. `state`는 열린 문자열(§10)이며 `∈ {"reachable", "stale", "unknown"}`: forward host는 도달성을 probe하지 않으므로 항상 `"unknown"`이다 — 확인하지 않은 것을 `"reachable"`로 보고하지 않는다. live 역방향 등록은 `"reachable"`(인증된 연결을 실제로 쥐고 있다), 죽은 등록은 보존 창 동안 `"stale"`이다(§6.13).

`device_id`는 **peer의 SPKI SHA-256 fingerprint 문자열**(`sha256:BASE64`, architecture.md §5의 표기)이다 — forward host는 trust store에 **핀된** fingerprint, reverse host는 상주 데몬이 **TLS로 검증한** peer fingerprint다. `Hello.device_name` 같은 wire 표시 이름은 어떤 경우에도 identity로 쓰지 않는다(protocol.md §3). `Host`는 이전까지 어떤 op도 emit한 적 없는 placeholder였고 fixture도 없었으므로, 위 값 어휘는 field의 **정의**이지 §10이 금지하는 기존 의미의 변경이 아니다.

### Session

```json
{
  "session_ref": "personal-mac/01K0SESSION",
  "host": "personal-mac",
  "session_id": "01K0SESSION",
  "state": "running",
  "writer": "device:hermes",
  "created_at": "2026-08-17T00:00:00Z",
  "last_sequence": 42
}
```

`session_ref`는 CLI가 반환하는 opaque value다. 호출자가 host와 session ID를 조합해 생성하지 않는다. 내부적으로는 **클라이언트의 `Ops` 계층**(qsh-core)이 `<host-alias>/<session_id>` 형태로 조립한다 — 서버는 opaque·URL-safe한 `session_id`만 발급하며 클라이언트의 로컬 host alias(trust store/hosts.toml의 이름)를 알지 못하기 때문이다. 조립 형식은 구현 세부이지 계약이 아니다: 호출자는 `session_ref`를 파싱하지 않고 받은 그대로 되돌려 주며, `Ops`가 이를 (host, session_id)로 해석한다([ADR-0007](adr/0007-session-ref-and-resume-token-custody.md)).

`writer`는 현재 writer lease 보유자의 principal 문자열 표기(architecture.md §5 — `fp:…`/`user:…`/`device:…`)이며, lease 보유자가 없으면(소유 connection이 죽어 lease가 자동 해제된 뒤, architecture.md §3) **`null`**이다. `writer`는 처음부터 nullable로 정의한다 — 나중에 nullable로 바꾸면 type 변경(§10, `/v2`)이 되기 때문이다. `host`와 `session_ref`는 클라이언트 `Ops`가 로컬 alias로 채우는 field이며 wire에는 존재하지 않는다(ADR-0007).

`last_sequence`는 chunk 개수가 아니라 이 세션에서 지금까지 누적된 output byte 수(offset)다. `session read --after`에 그대로 전달할 수 있다.

## 6. 명령 계약

### 6.1 Host 조회

```bash
qsh hosts --json
qsh host get personal-mac --json
```

`host.list`의 `data`는 `{"hosts": [Host, …]}`(§5 Host 배열)이고 `host.get`의 `data`는 Host 객체 하나다.

`hosts`는 두 데이터 소스를 합쳐 반환한다: 로컬 trust store(`trust.toml`)에 pin된 forward host 전부와, 상주 `qsh listen` 데몬이 현재 쥐고 있는 live 역방향 등록(§6.13). **`host.list`는 dial하지 않는다** — forward host의 도달성은 확인하지 않으므로(§5, `state`는 항상 `"unknown"`) 이 목록은 순수 로컬 조회다. 같은 이름이 forward pin과 reverse 등록 양쪽에 존재하면 `hosts` 배열에 `connection_mode`로 구분되는 **두 항목**으로 나타난다 — 목록에서는 병합하지 않는다. 다만 그 이름으로 실제 연결을 맺을 때(attach, `qsh <name>`)의 **라우팅 우선순위는 live reverse 등록이 우선**이다 — 증명된 도달 가능 경로를 trust store의 추정 주소보다 앞세운다.

### 6.2 Session 조회

```bash
qsh sessions [host] --json
qsh session get <session-ref> --json
```

`session.list`의 `data`는 `{"sessions": [Session, …]}`(§5 Session 배열)이고 `session.get`의 `data`는 Session 객체 하나다.

**`qsh sessions`를 host 없이 부르면** 주소가 있는 pinned host 전부에 fan-out한다. 이때는 **best-effort**다: 도달하지 못한 host는 결과를 감추지 않고 `data.unreachable`에 모아 보고하고(`[{"host": …, "code": "CONNECTION_FAILED", "message": …}, …]`, additive field이므로 비어 있으면 아예 생략된다) 나머지 host의 세션은 그대로 돌려준다. 잠든 노트북 한 대가 다른 host의 목록을 통째로 숨겨서는 안 되기 때문이다. **모든** host가 실패하면 그것은 부분 응답이 아니라 호출 실패이며, 마지막 오류의 `code`로 실패하고 `error.details.unreachable`에 같은 배열이 실린다. host를 명시한 단일 호출(`qsh sessions <host>`)은 fan-out이 아니므로 그 host의 실패가 곧 호출의 실패이고 `unreachable`은 항상 비어 있다. human 모드에서는 도달 실패가 stdout 표가 아니라 stderr 경고 줄로 나간다(§2.2). `session.list`는 그 host의 세션을 (ACL `session.list` 범위에서) 장비와 무관하게 반환한다. 다만 **`session.attach`(및 `qsh attach`)는 세션을 연 장비에서만 가능하다** — resume credential이 세션에 결합된 peer identity에 묶여 있고(protocol.md §10, PRD §9) 토큰은 그 장비의 상태 파일에만 있기 때문이다(§6.3, ADR-0007). 다른 장비에서는 목록에 `running`으로 보이더라도 attach는 로컬 `SESSION_NOT_FOUND`(`details.reason: "no_resume_token"`)로 실패한다 — 그리고 이 제한은 클라이언트의 편의가 아니라 **호스트가 강제한다**: credential 없이 보낸 `SessionAttach`는 non-distinguishing `AUTH_FAILED`로 거부되므로, 직접 wire를 말하는 peer도 우회할 수 없다. `session.get`/`read`/`write`/`resize`/`close`는 토큰이 아니라 ACL만으로 동작하므로 다른 장비에서도 가능하다 — 다만 `write`/`resize`는 ACL을 통과한 뒤 추가로 opener 결합을 거친다(§6.3).

### 6.3 Session 생성

```bash
qsh session open personal-mac --json
qsh session open personal-mac --json -- claude
```

명령이 없으면 login shell PTY를 생성한다. `--` 뒤의 argv는 shell string으로 재해석하지 않는다.

결과:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "session.open",
  "ok": true,
  "data": {
    "session_ref": "personal-mac/01K0SESSION",
    "initial_sequence": 0
  }
}
```

wire `SessionOpened`가 반환하는 `resume_token`(protocol.md §10)은 **어떤 출력 모드에서도 JSON에 노출되지 않는다.** 토큰은 클라이언트 상태 파일 `$XDG_STATE_HOME/qsh/resume.json`(0600)에 `session_ref`를 key로 저장되고 rotation도 거기서 갱신된다. 기계 사용자는 `session_ref`만으로 재attach(`qsh attach <session-ref>`, §7.1)하며, 토큰 조회·제시는 `Ops` 계층이 내부에서 처리한다([ADR-0007](adr/0007-session-ref-and-resume-token-custody.md)). **토큰이 필요한 경로는 wire `SessionAttach`(= `session.attach`와 그 위의 대화형 attach)뿐이다.** `session.get`/`read`(`--wait`·`--follow` 모두)/`write`/`resize`/`close`는 control 스트림 value op(protocol.md §9 `SessionRead`/`SessionWrite` 등)이며 토큰 없이 ACL(§2.5)만으로 동작한다 — `--follow`는 `session.read`의 pull 루프이지 attach가 아니다. 상태 파일에 해당 `session_ref`의 토큰이 없으면(다른 장비, 상태 파일 삭제) attach는 원격 요청 없이 로컬에서 `SESSION_NOT_FOUND`(`details.reason: "no_resume_token"`, human `message`는 세션이 아직 살아 있어 `session read`/`close`는 가능함을 안내)로 실패한다 — fail closed. 상태 파일 항목에 기록된 peer fingerprint가 현재 연결의 peer와 다르면 토큰을 보내지 않고 같은 코드(`details.reason: "peer_mismatch"`)로 실패한다.

**`session.write`/`session.resize`는 ACL 통과 후 이 세션을 연 principal(opener)에도 결합된다** — §2.5의 ACL principal과 같은 축이며(§6.2의 attach가 쓰는, peer fingerprint에 결합된 resume credential과는 다른 축이다), M1–M4의 고정 장비 전용 posture에서는 principal이 장비 하나에 1:1로 대응하므로 사실상 장비 결합과 같다. principal이 다른 요청은 ACL을 통과하더라도 정책 거부와 문면이 동일한 `PERMISSION_DENIED`로 거부되고(어떤 세션이 누구 소유인지는 노출하지 않는다) `session.control` deny로 감사 기록에 남는다(PRD §6). `session.get`/`read`/`close`는 이 결합의 영향을 받지 않고 §6.2의 ACL 범위를 그대로 따른다.

### 6.4 Session 읽기

```bash
qsh session read <session-ref> --after 42 --wait 30000 --json
qsh session read <session-ref> --after 42 --follow --jsonl
```

- `--after`: 마지막으로 수신한 누적 output byte offset (sequence)
- `--ctl-after`: 마지막으로 수신한 **control entry id** — 직전 응답의 `next_ctl_after`를 그대로 되돌려준다. 생략하면 `0`(처음부터).
- `--wait`: 새 output을 기다릴 최대 milliseconds. 호스트는 이 값도 상한(현재 60 s, `SESSION_READ_MAX_WAIT`)으로 clamp한다 — `--limit-bytes`와 같은 취급으로, 더 큰 값은 오류가 아니라 상한이다. 더 오래 기다리려면 같은 cursor로 다시 부른다. `--follow`와 함께 쓰면 이 값은 **하한 30 s 아래로 내려가지 않는다** — follower는 parking 하는 것이지 spin 하는 것이 아니므로, 단발 pull용으로 준 작은 `--wait`이 follow loop을 tight round-trip loop으로 만들지 않는다.
- `--follow`: 종료나 취소까지 event를 계속 출력
- `--limit-bytes`: 한 응답의 최대 payload. 호스트는 이 값을 상한(현재 192 KiB, `SESSION_READ_MAX_BYTES`)으로 clamp한다 — 더 큰 값은 오류가 아니라 상한으로 취급된다.

단일 JSON 응답은 event 배열을 반환한다: `data`는 `{"session_ref": "...", "events": [Event, …], "next_after": <sequence>, "next_ctl_after": <id>}`이며 각 원소는 아래 event 객체 그대로다. `--follow --jsonl`은 event 하나당 한 줄을 출력한다. `--follow`는 값 하나가 아니라 stream이므로 `--json`과 함께 써도 같은 streaming 형태(event 하나당 한 줄, envelope 없음)를 출력한다 — envelope는 단발 value operation의 형태이고 follower에는 적용되지 않는다. 실패 보고는 영향받지 않는다: `--follow`의 실패는 두 모드 모두 §4의 동일한 error envelope와 동일한 exit code다.

**Cursor는 두 값이다.** `session.exit`/`session.writer_changed`/`session.closed`는 zero-length control entry라서 자신이 append된 시점의 offset을 달고 나오지만 offset을 **증가시키지 않는다**(아래 "전달 경로와 순서"). 따라서 `--after` 하나로는 "offset N에 있는 control event는 이미 받았다"를 표현할 수 없다. `next_after`/`next_ctl_after`를 그대로 `--after`/`--ctl-after`로 되먹이는 소비자는 모든 event를 **정확히 한 번** 받는다. 되먹이지 않는 소비자(`--ctl-after` 생략)는 offset이 정확히 `--after`인 control event를 **매번 다시** 받으며(at-least-once), `--wait` 폴링 루프는 그 event 때문에 즉시 반환되어 대기하지 않는다 — 폴링 루프는 반드시 두 값을 함께 되먹여야 한다.

소비자 규칙의 정확한 범위: "알 수 없는 event `type`은 무시"는 **`type` 문자열이 미지인 경우**에만 적용된다. 알려진 `type`(`session.output` 등)인데 필수 필드가 없거나 타입이 틀린 event는 잘못된 입력이며, 소비자는 이를 건너뛰지 말고 오류로 처리해야 한다(조용한 output 손실 금지, PRD §8).

**Sequence 시맨틱**: `sequence`는 세션 시작(0)부터 누적된 output byte 수이며 chunk index가 아니다. 각 `session.output` event의 `sequence`는 그 chunk까지 포함한 누적 byte offset, 즉 chunk의 마지막 byte offset + 1이다. `--after N`은 누적 offset `N` 이후의 byte를 요청한다. 서버는 chunk를 자유롭게 분할·병합할 수 있으므로 클라이언트가 매번 같은 크기로 chunk를 받는다고 가정해서는 안 되지만, replay는 항상 정확히 `N`에서 끊어 재개할 수 있다. 아래 예시는 `--after 42`로 요청한 뒤 7 byte(`Hello\r\n`) chunk 하나를 받아 누적 offset이 `49`가 된 상황이다.

Output event:

```json
{
  "schema": "qsh.event/v1",
  "type": "session.output",
  "session_ref": "personal-mac/01K0SESSION",
  "sequence": 49,
  "data_b64": "SGVsbG8NCg=="
}
```

Gap event:

```json
{
  "schema": "qsh.event/v1",
  "type": "session.gap",
  "session_ref": "personal-mac/01K0SESSION",
  "requested_after": 42,
  "available_from": 120
}
```

`available_from`은 replay buffer가 보존하고 있는 가장 오래된 byte offset이다. `requested_after`가 `available_from`보다 작으면 그 사이 byte는 영구히 유실된 것이며, QSH는 이를 숨기지 않고 gap event로 명시한다.

Input(`session write`) 방향에도 동일한 누적 byte offset 모델이 적용된다. 다만 input side의 재전송/중복 제거(`input_seq`+ack)는 내부 프로토콜 동작이며, 이 문서가 정의하는 CLI 계약에는 별도 field가 없다.

Exit event:

```json
{
  "schema": "qsh.event/v1",
  "type": "session.exit",
  "session_ref": "personal-mac/01K0SESSION",
  "sequence": 180,
  "exit_code": 0,
  "signal": null
}
```

`exit_code`와 `signal`은 둘 중 하나만 채워진다(정상 종료 → `exit_code`, 신호 종료 → `signal`, `SIGTERM` 정규형). **둘 다 `null`이면 호스트가 child의 종료 상태를 알 수 없었다는 뜻이다**(reap 실패 등 예외 경로) — 소비자는 "종료했으나 상태 미상"으로 처리한다.

Writer changed event (wire `SessionEvent::WriterChanged`, protocol.md §10 writer lease). writer lease 보유자가 바뀔 때마다 — steal로 다른 attach가 가져갔을 때, 또는 소유 connection이 죽어 lease가 자동 해제됐을 때(그때 `writer: null`) — 발생한다. **세션의 모든 read 소비자에게 broadcast**되는 세션 상태 변화 event다(lease를 뺏긴 기존 보유자에게는 read-only 강등 통지를 겸한다; `writer` principal은 이미 `session.list`의 `Session.writer`로 같은 ACL 범위에 노출되는 값이므로 새 정보 누설은 없다). `writer`는 §5 Session의 `writer`와 같은 형식(새 보유자의 principal 문자열, 없으면 `null`)이고 `sequence`는 event 시점의 누적 output byte offset이다.

```json
{
  "schema": "qsh.event/v1",
  "type": "session.writer_changed",
  "session_ref": "personal-mac/01K0SESSION",
  "sequence": 180,
  "writer": "device:hermes"
}
```

Closed event (wire `SessionEvent::Closed`). 세션이 broker에서 제거되어 더 이상 read/attach할 수 없을 때 stream의 **마지막 event**로 전달된다. `reason`은 **누가 세션을 제거했는가**로 정해지며 세션의 이전 상태와 무관하다: `"closed"` = 명시적 `session.close`(세션이 `running`이든 이미 `exited`든) 또는 `qsh serve`의 SIGTERM drain(§6.12); `"exit"` = child가 스스로 종료해 `exited`가 된 세션을 **호출자 없이** TTL reaper가 정리(앞서 `session.exit`가 먼저 온다; `exited` 세션도 같은 `[serve].resume_ttl`을 exit 시점부터 적용해 정리한다); `"ttl_expired"` = **실행 중이던** 세션이 attach 없이 resume TTL을 넘겨 reaper가 process group을 종료. 알 수 없는 `reason` 값은 "세션이 끝났다"로만 해석한다(값 추가는 additive, §10). 이후 같은 `session_ref`에 대한 `session.get`/`read`/`write`/`resize`/`close`는 `SESSION_NOT_FOUND`다; `session.attach`는 protocol.md §10의 non-distinguishing 규칙에 따라 호스트가 `AUTH_FAILED`로 답하며(세션 존재 여부 비노출), 클라이언트는 이 event를 받으면 `resume.json` 항목을 지우므로 실제로는 로컬 `SESSION_NOT_FOUND`(`no_resume_token`)로 먼저 실패한다. 이 `AUTH_FAILED`는 credential 제시 여부와 무관하다 — 세션이 제거되면 그 resume credential도 함께 폐기되고, credential을 **제시하지 않은** `SessionAttach`는 호스트가 같은 `AUTH_FAILED`로 거부하기 때문이다(§6.3: attach는 항상 credential을 요구한다).

```json
{
  "schema": "qsh.event/v1",
  "type": "session.closed",
  "session_ref": "personal-mac/01K0SESSION",
  "sequence": 180,
  "reason": "closed"
}
```

두 event는 `qsh.event/v1`에 additive로 추가된 타입이다(§10). **소비자는 알 수 없는 event `type`을 오류 없이 무시(skip)해야 한다** — 알 수 없는 field를 무시하는 §2.3 규칙의 event 수준 대응이며, 새 event 타입은 major bump 없이 추가될 수 있다. `qsh.event/v1`은 아직 출시된 producer가 없으므로 이 규칙은 v1 최초 구현부터 적용된다(`qsh-proto`의 event 타입은 unknown-type fallback을 가져야 한다, architecture.md §2).

**전달 경로와 순서.** `session.exit`/`session.writer_changed`/`session.closed`는 broker가 ReplayRing에 **zero-length 제어 엔트리**로 append하며, `pull()`(architecture.md §3)의 반환 event 열에서 `session.output`과 **전순서(total order)** 로 섞여 나온다 — 단발 `session read --wait`/MCP `read_session` 결과 배열에도 그대로 포함될 수 있다. 이 event들의 `sequence`는 append 시점의 누적 output offset이며 offset을 증가시키지 않는다. attach 중인 connection은 같은 event를 control 스트림의 wire `SessionEvent`로도 받는다.

**`--follow`의 종료.** `--follow`는 `session.exit`를 수신하면 즉시 정상 종료한다(exit `0`) — TTL 정리(`session.closed{reason:"exit"}`)를 기다리지 않는다. 실행 중이던 세션이 `session.close`/reaper로 제거되면 `session.closed`가 마지막 event이고 그 직후 종료한다.

Recovery 텔레메트리(`recovery ∈ {migrated, resumed, failed}`, `time_to_recovery_ms`, `session_ref`; testing.md L4)는 M2에서 `qsh.event/v1` event가 **아니라** stderr 구조화 진단(tracing target `qsh::recovery`, level `INFO`, **한 줄 JSON** 렌더링 — 기본 verbosity에서 방출되고 §2.2의 `--quiet`/`-v` 규칙을 그대로 따른다; PTY 내용·토큰 field는 존재하지 않는다)으로만 나가며 stdout에는 절대 나타나지 않는다(§2.2). event로의 승격은 P1에서 결정한다.

M3 Step 8이 이 진단에 additive field `registration_wait_ms`(밀리초, `u64`)를 더했다 — 정방향(`DialReconnect`)은 항상 `0`(재등록을 기다릴 대상이 없다), 역방향(`LocalReconnect`)은 controller의 attach driver가 target의 새 `generation` 등록을 기다린 시간이다. 라인의 키 순서는 M2가 낸 세 field 뒤에 이 field가 오는 것으로 고정된다(`{"recovery":…,"time_to_recovery_ms":…,"session_ref":…,"registration_wait_ms":…}`) — 접두사만 읽는 기존 소비자는 영향받지 않는다. **`recovery` 값 집합 자체는 바뀌지 않는다**(`migrated`가 역방향에서 나오는 일은 없다 — 이 leg에 migration/rebind이 없다는 것이 Step 8의 설계 그 자체다, protocol.md §11-4). 이 field는 `time_to_recovery_ms`를 **분해**하는 값이지 별도 시계가 아니다: `time_to_recovery_ms - registration_wait_ms`가 재등록 이후 resume 자체가 쓴 시간이고, 그 값이 정방향과 동일한 2초 예산에 묶인다(testing.md L4) — target의 재dial backoff까지 qsh의 예산으로 세지 않기 위함이다.

### 6.5 Session 쓰기

```bash
printf 'continue\n' | qsh session write <session-ref> --stdin --json
qsh session write <session-ref> --data-b64 Yw== --json
```

`--stdin`과 `--data-b64`는 상호 배타적이다. 전자는 raw stdin bytes, 후자는 명시적인 Base64 bytes를 전송한다. 한 번의 `session.write`가 받는 입력은 **16 MiB**로 제한된다(`SESSION_WRITE_MAX`) — 단일 value op의 envelope은 유계여야 하므로, 초과분은 `INVALID_ARGUMENT`이고 `--stdin`은 상한을 넘겨 버퍼링하지 않는다. 더 큰 입력은 반복 write나 attach로 흘려보낸다. (호스트는 이 입력을 16 KiB wire chunk로 나눠 같은 connection에서 순서대로 보낸다.)

결과 `data`는 `{"session_ref": "...", "bytes_written": <accepted byte count>}`다. ACL을 통과해도 이 세션을 연 principal이 아니면 `PERMISSION_DENIED`다(§6.3).

### 6.6 Terminal resize

```bash
qsh session resize <session-ref> --cols 120 --rows 40 --json
```

결과 `data`는 적용된 크기를 되돌려 준다: `{"session_ref": "...", "cols": 120, "rows": 40}`. ACL을 통과해도 이 세션을 연 principal이 아니면 `PERMISSION_DENIED`다(§6.3).

### 6.7 Session 종료

```bash
qsh session close <session-ref> --json
qsh session close <session-ref> --signal TERM --json
```

`session.close`는 세션의 **process group 전체**(architecture.md §4)를 종료하고 세션을 broker에서 제거한다. 기본 절차는 SIGHUP → 유예 후 SIGTERM → 유예 후 SIGKILL escalation이며, 단계별 유예는 `[serve].close_grace_ms`(기본 5000)다. `--signal <SIG>`는 이 절차의 **첫 신호를 지정한 신호로 바꾼다** — 신호를 process group에 보낸 뒤 동일한 유예·escalation과 세션 정리가 이어진다. `--signal`은 wire `SessionClose`의 optional `signal` field로 전달되며(§2.4), 허용 값은 `HUP|INT|QUIT|TERM|USR1|USR2|KILL`(대소문자 무시, `SIG` 접두 유무 무관)뿐이다. 그 외(숫자, stop 계열 `STOP`/`TSTP`, 미지의 이름)는 `INVALID_ARGUMENT`(exit `2`)다. 이름은 내부적으로 `SIGTERM` 형태의 정규형으로 정규화되며 `session.exit`의 `signal` field도 같은 정규형을 쓴다. `--signal KILL`은 escalation 없이 즉시 `killpg(SIGKILL)` 후 정리다. 세션을 종료하지 않고 신호만 보내는 operation은 M2에 없다(§2.4, P1). 종료가 완료되면 `--follow` 소비자는 `session.closed{reason: "closed"}` event(§6.4)를 받는다. 이미 종료된(`exited`) 세션의 close는 **어떤 신호도 보내지 않고**(재사용된 pgid로 무관한 프로세스에 신호가 갈 수 있다) 정리만 수행하며 오류가 아니다 — 이때도 `reason`은 `"closed"`다.

결과 `data`는 `{"session_ref": "...", "final_sequence": <제거 시점의 누적 output byte offset>}`다.

### 6.8 비대화형 실행

```bash
qsh exec personal-mac --json -- uname -a
qsh exec personal-mac --json --timeout 5000 --env FOO=bar -- sh -c 'echo "$FOO"'
```

`host` 인자는 host 이름이다. hosts.toml 기반 host directory가 도입되는 M7 전까지는 trust store(trust.toml)의 pinned peer(name→address)가 host→주소 해석의 단일 출처다.

- 실행할 명령은 항상 `--` 뒤에 온다(`--` 이후는 qsh가 해석하지 않는다). `--` 뒤에 명령이 없으면 usage 오류(exit `2`)다.
- `--timeout <milliseconds>`(§9): 기한 내 종료하지 않으면 remote 프로세스(process group)를 kill하고 `TIMEOUT`(`retryable: true`, `details.timeout_ms`)을 반환한다. 기한은 해석·연결·협상·실행 전체에 하나의 예산으로 적용되고, 종료 후 연결 정리 시간은 포함하지 않는다(제때 끝난 명령이 정리가 느리다고 `TIMEOUT`이 되지 않는다). 호스트도 같은 기한을 스스로 강제하며(`ExecExit.timed_out`), 어느 쪽이 먼저 걸리든 결과는 `TIMEOUT`이다.
- `exec.run`은 출력 전체를 한 envelope에 담으므로 stdout+stderr 합계에 상한(64 MiB)이 있다. 초과하면 remote 명령을 중단하고 `RESOURCE_EXHAUSTED`(`details.limit_bytes`)를 반환한다 — 대용량·스트리밍 출력은 session(§6.4, M2)의 몫이다.
- `--env NAME=VALUE`(반복 가능): remote 명령의 환경 변수를 추가한다.
- local stdin이 terminal이 아니면(pipe/file) EOF까지 remote 명령의 stdin으로 전달하고, terminal이면 remote stdin을 즉시 닫는다.
- human mode에서는 remote stdout/stderr 바이트를 각각 local stdout/stderr에 그대로 통과시키고, exit code는 §4 규칙을 따른다.

결과는 stdout과 stderr를 별도 Base64 field로 반환한다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "exec.run",
  "ok": true,
  "data": {
    "stdout_b64": "RGFyd2luCg==",
    "stderr_b64": "",
    "remote_exit_code": 0,
    "signal": null,
    "duration_ms": 18
  }
}
```

### 6.9 Tunnel

```bash
qsh tunnel open personal-mac --local 8080:localhost:3000 --json
qsh tunnel open server --remote 9000:localhost:9000 --json
qsh tunnels --json
qsh tunnel close <tunnel-id> --json
```

`-D`(SOCKS5 dynamic forwarding, `forward.socks`)는 CLI 인자로 parsing되지만 P0에서는 항상 `UNSUPPORTED` 오류를 반환한다. 구현은 P1이다.

### 6.10 Schema와 capability

```bash
qsh schema --json
qsh capabilities personal-mac --json
qsh version --json
```

`schema`는 CLI가 지원하는 schema version을, `capabilities`는 peer와 negotiation된 기능을 반환한다.

### 6.11 Identity와 trust

```bash
qsh init --json
qsh init --key-store file --json
```

`identity.init`은 device identity(keypair와 self-signed certificate)를 생성한다. 이미 초기화된 경우 오류가 아니라 기존 identity 정보를 `created: false`와 함께 반환한다(멱등). `--key-store <auto|platform|file>`는 private key 저장소를 고른다 — `auto`(기본, platform 우선·부재 시 file fallback), `platform`(OS credential store 강제, 부재 시 `INTERNAL` 실패), `file`(0600 파일). 기본값은 `config.toml`의 `[identity].key_store`, 그 다음 `auto`다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "identity.init",
  "ok": true,
  "data": {
    "device_id": "device_01K0EXAMPLE",
    "fingerprint": "sha256:BASE64FINGERPRINT",
    "key_store": "platform",
    "config_dir": "/Users/dave/.config/qsh",
    "created": true
  }
}
```

`key_store`는 `platform`(OS credential store) 또는 `file`(0600 permission fallback)이다. 어느 쪽이 사용됐는지는 항상 결과에 명시한다.

`identity.init`의 실패 경로는 전용 오류 코드를 두지 않고 일반 `ErrorCode` 어휘(§3.3)를 따른다 — 예: keystore 쓰기 실패는 `INTERNAL`(`retryable: false`)로 보고한다.

```bash
qsh trust add <name> --address <host:port> --fingerprint sha256:... --json
qsh trust list --json
qsh trust remove <name> --json
```

`trust.add`는 fingerprint를 명시하면 연결 없이 peer를 pin한다(provisioning 친화). 이때 `--address`는 선택이며 생략하면 `address`는 빈 문자열로 기록된다 — 단, `qsh exec <name>`의 host→주소 해석(§6.8)은 address가 있는 pin만 대상으로 하므로, 명령을 보낼 host는 address와 함께 pin한다(inbound 전용 peer, 즉 "이 장비에 접속해 올 client"는 fingerprint만으로 충분하다). fingerprint 없이 연결해서 확인하는 방식은 human mode에서만 prompt를 열며, `--json` mode에서는 §2.1 규칙에 따라 prompt 대신 `TRUST_REQUIRED` 오류에 `details.observed_fingerprint`와 `details.address`를 담아 반환한다 — 호출자는 그 값을 검증한 뒤 `--fingerprint`로 재호출한다.

세 명령 모두 통일된 pinned peer 객체를 사용한다:

```json
{
  "name": "personal-mac",
  "fingerprint": "sha256:BASE64FINGERPRINT",
  "address": "personal-mac.example.com:4433",
  "added_at": "2026-08-17T00:00:00Z"
}
```

`trust.add` 결과 (신규 pin):

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.add",
  "ok": true,
  "data": {
    "peer": {
      "name": "personal-mac",
      "fingerprint": "sha256:BASE64FINGERPRINT",
      "address": "personal-mac.example.com:4433",
      "added_at": "2026-08-17T00:00:00Z"
    },
    "created": true
  }
}
```

이미 같은 이름으로 pin된 경우도 오류가 아니라 멱등이다 — 기존 항목은 그대로 유지되고 `data.created`가 `false`로 돌아온다.

`trust.list` 결과:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.list",
  "ok": true,
  "data": {
    "peers": [
      {
        "name": "personal-mac",
        "fingerprint": "sha256:BASE64FINGERPRINT",
        "address": "personal-mac.example.com:4433",
        "added_at": "2026-08-17T00:00:00Z"
      }
    ]
  }
}
```

`trust.remove` 결과:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.remove",
  "ok": true,
  "data": {
    "name": "personal-mac",
    "removed": true
  }
}
```

존재하지 않는 이름을 제거하는 것도 오류가 아니라 멱등이다 — `ok: true`에 `data.removed: false`를 반환한다.

일회용 invite code pairing(`qsh trust invite` 계열, ADR-0002)의 CLI 계약은 M7에서 확정한다. `doctor.run`은 operation 이름만 예약되어 있으며 계약은 M7에서 확정한다. M3가 만드는 진단 항목 상수(`qsh::reverse`의 `event` 값 어휘, `registration_wait_ms` 등)는 M7의 `doctor.run`이 그대로 소비한다 — 계약 확정을 앞당기지 않는다.

원격 operation(`exec.run`, `session.*`, `tunnel.*`)의 mTLS 실패 오류 경로는 다음과 같다.

- `TRUST_REQUIRED`: peer가 trust store에 없음. `details`: `observed_fingerprint`, `address`. `retryable: false`. (M7의 host directory 이전에는 `qsh exec <host>`의 host 자체가 trust store에서 해석되므로 원격 op가 이 코드를 낼 수 없다 — 미등록 host는 `HOST_NOT_FOUND`, pin 불일치는 `AUTH_FAILED`다. M1에서 이 코드의 유일한 생산자는 fingerprint 없는 `trust add`다.)
- `AUTH_FAILED`: certificate 검증 실패(만료, CA 불일치, client certificate 미제시 등). `retryable: false`. 보안상 `details`에는 실패 category만 담고 상세 사유를 노출하지 않는다.

### 6.12 장기 실행 모드: `qsh serve`

`qsh serve`는 §2.4가 명시하듯 operation이 아니라 장기 실행 모드(long-running mode)이며 단일 요청/응답 JSON 계약이 없다.

```bash
qsh serve --bind <ip:port>
```

- **Foreground 전용(M1).** 데몬화는 QSH 자체가 하지 않고 OS 서비스 매니저(systemd/launchd)에 위임한다.
- `--bind`의 우선순위: CLI flag > `config.toml`의 `[serve].bind` > 기본값 `[::]:4433`.
- 시작 시 실제로 bind된 주소를 stderr에 출력한다 — stdout은 §2.2 규칙에 따라 JSON 계약 전용이므로 여기서는 쓰지 않는다.
- listener 재시작 시 세션 소실에 대해서는 README의 [Known limitations](../README.md#known-limitations-mvp-by-design)를 참고한다.
- **SIGTERM drain(M2, ADR-0003):** 신규 attach·open을 거부한 뒤 모든 세션에 §6.7의 close 절차(SIGHUP→TERM→KILL, `close_grace_ms`)를 적용하고, 붙어 있는 소비자에게 `session.closed{reason: "closed"}`(§6.4)를 보낸 다음 종료한다 — 세션은 프로세스와 함께 끝나며 고아 셸을 남기지 않는다.

### 6.13 장기 실행 모드: `qsh listen` / `qsh reverse`

`qsh listen`(controller)과 `qsh reverse <controller>`(target)는 §2.4가 명시하는 장기 실행 모드다 — 단일 요청/응답 JSON 계약이 없고 operation 목록(§2.4)에 포함되지 않는다.

```bash
qsh listen [--bind <ip:port>]
qsh reverse <controller> [--offered-name <name>]
```

- **Controller reachability 요구.** `qsh listen`은 target이 dial할 수 있는 주소에서 실행돼야 한다 — 역방향은 NAT 뒤 target을 도달 가능하게 만들 뿐, controller 자신은 여전히 direct-reachable해야 한다(relay·NAT traversal은 M3의 명시적 out-of-scope, ROADMAP.md M3). 이 요구의 정본 문안은 `qsh-core::doctor::CONTROLLER_UNREACHABLE`(`crates/qsh-core/src/doctor.rs`, `PLAN.md` M3 Step 9)이며, `qsh reverse`의 연결 실패 경로가 그 invocation 생애주기 동안 stderr에 **정확히 한 번**(백오프 재시도마다 반복하지 않는다) 렌더한다:

  > Reverse attach needs a directly reachable UDP path from the target to the controller. QSH provides no relay, NAT traversal, or discovery — that is out of scope for P0.
  >
  > Put the controller on a publicly routable address, a forwarded port, or an existing overlay such as WireGuard or Tailscale. If the controller itself is behind NAT, M3 has no answer for that.

  같은 상수를 `qsh listen` 시작 배너, `README.md`의 "Known limitations", 그리고 이 절이 함께 소비한다 — 문안 정본이 여러 벌 생기지 않는다. M7의 `doctor.run`(§6.11)도 `code: "controller_unreachable"`을 그대로 소비할 예정이다.
- `--bind`의 우선순위: CLI flag > `[listen].bind` > 기본값 `[::]:4433` — `qsh serve`(§6.12)와 **기본값이 같다**. 한 머신에서 두 역할을 겸하려면 명시적 `--bind`가 필요하고, 충돌은 조용한 오작동이 아니라 즉시·명시적 실패(stderr 진단 + exit `255`)다.
- 시작 시 실제로 bind된 주소와 등록 이벤트(`registered|denied|replaced|lost|expired|retry`)를 stderr에 구조화 진단(tracing target `qsh::reverse`, 한 줄 JSON, payload·토큰 field 없음)으로 출력한다 — stdout에는 §2.2 규칙에 따라 한 바이트도 쓰지 않는다.
- `qsh reverse <controller>`의 `<controller>`는 trust store alias다(§6.8의 host→주소 해석과 동일 — M7 이전에는 trust.toml pinned peer가 단일 출처). 등록에 성공하면 그 연결 위에서 host 역할로 동작하며, 서비스하는 세션은 `qsh serve`와 같은 broker·writer lease 규율을 그대로 따른다. **관찰 가능한 차이는 writer lease를 쥐는 connection이 상주 `qsh listen` 데몬이 유지하는 역방향 connection에 결합된다는 점이다** — 그 connection이 죽으면(재접속 루프가 새 connection을 세우기 전) lease는 forward 세션과 동일하게 자동 해제된다(architecture.md §3).
- `qsh listen`/`qsh reverse` 둘 다 Windows에서는 리소스를 생성하지 않고 `UNSUPPORTED` + exit `255`다 — localctl(UDS)과 host 역할(PTY)이 `cfg(unix)`이기 때문이다. Windows의 `qsh hosts`는 forward host만 반환하며(데몬 개념 없음) 오류가 아니다.
- 연결이 죽은 등록은 `state:"stale"`로 표시됐다가 `[listen].stale_retention`(기본 120s, `docs/design/protocol.md` §11-4)이 지나면 목록에서 제거된다.
- **Controller 측 writer lease 결합 (M3 Step 6).** live 역방향 등록으로 뜨는 host를 향한 controller 쪽의 `qsh session ...`(value op 6종: open/get/list/read/write/resize/close)는 그 명령을 실행한 CLI 프로세스 자신의 QUIC connection이 아니라, 상주 `qsh listen` 데몬이 target과 유지하는 그 **하나의** reverse connection을 `LOCAL_CONTROL` conduit(`docs/design/protocol.md` §11-3)으로 relay해서 나간다. **대화형 attach(`qsh <name>`/`qsh attach <name>/<id>`)도 M3 Step 7부터 이 경로를 탄다.** `Ops::session_attach`는 route-aware해졌다(`Ops::connect`로 host route를 먼저 resolve하고, 그 결과가 live 역방향 등록이면 forward의 `connect_target`이 아니라 이 §의 `LOCAL_CONTROL` conduit으로 향한다); ticket을 실제로 redeem하는 data 스트림도 이제 `LOCAL_STREAM` conduit(위 conduit 모델 문단, `docs/design/protocol.md` §11-3)로 역방향에서 열린다 — 데몬은 그 conduit 위에서 `LocalHello`/`LocalHelloAck` 교환 뒤 wire `StreamHeader{SESSION_DATA, ticket}`를 받아 host의 QUIC connection 위에 새 bidi stream을 열고 그 뒤로는 순수 byte splice로만 동작한다(SessionFrame을 파싱하지도, payload를 로그하지도 않는다). 아래 lease 결합 규칙은 지금 이 value op·stream op 양쪽 모두에 참이다: 위 항목의 "writer lease를 쥐는 connection이 데몬의 reverse connection에 결합된다"는 target 쪽 서술의 controller 쪽 대응이다 — target이 실제로 보는 유일한 connection은 데몬의 것이므로, **writer lease는 데몬의 connection에 묶이지, lease를 요청한 CLI 프로세스 자체에는 묶이지 않는다.** 그 CLI 프로세스가 죽어도(터미널 종료, `Ctrl-C`, 비정상 종료) 데몬의 reverse connection이 살아 있는 한 lease는 자동 해제되지 않는다 — forward 세션(§5, architecture.md §3)의 "소유 connection이 죽으면 lease가 자동 해제"라는 기대가 reverse 경로에서는 CLI 프로세스 단위가 아니라 데몬 connection 단위로 적용된다는 뜻이다. **동시 attach 격리.** 이 lease를 실제로 쥐는지 판정하는 identity는 물리 connection(`ctx.connection_id()`)이 아니라 그 attach가 redeem한 단발성 ticket에서 유도된다(`WriterLease::take_owned`) — 그렇지 않으면 한 데몬을 거치는 모든 local CLI가 같은 물리 connection을 공유하는 탓에 서로 다른 두 attach가 같은 identity로 오인되어 조용히 lease를 공동 소유하고 (`no_steal`이 걸려 있어도) 서로의 keystroke를 같은 PTY에 섞어 넣는다. 반면 `no_steal`이 충돌 여부를 판단하는 기준은 여전히 **principal뿐**이다(architecture.md §3(b)). reverse 경로에서 한 데몬을 relay로 쓰는 모든 local CLI 프로세스는 — 어느 프로세스가 열었든 — 항상 그 데몬의 reverse connection과 같은 controller principal로 인증되므로, "타 principal이 lease를 쥐고 있다"는 `no_steal` 충돌의 전제 자체가 reverse 경로 안에서는 성립하지 않는다(`session.write`가 opener 결합 때문에 이미 이 규칙을 재현할 수 없는 것과 같은 이유, 바로 위 architecture.md §3(b) 인용). 즉 죽은 CLI가 남긴 lease는 자동 해제되지 않지만, 다음 attach는 대화형이든 `no_steal`을 쓰는 자동화든 관계없이 항상 그 lease를 이어받는다 — `SESSION_CONFLICT`는 이 reverse 시나리오에서는 발생하지 않는다.
- **역방향 attach에는 아직 recovery/reconnect가 없다 (M3 Step 7).** Forward 경로의 attach는 connection이 끊겨도 (`docs/CLI.md` 이 절 밖의) 자동 재접속·resume 시도를 갖지만, `LOCAL_STREAM`/`LOCAL_CONTROL` conduit 위의 역방향 attach는 그 driver가 아직 없다 — 데몬의 reverse connection이나 conduit 자체가 죽으면 attach는 그 즉시 명확한 typed error로 끝난다(panic도, 무한 대기도 아니다). 세션 자체는 forward와 동일하게 살아남는다(broker가 쥐고 있고, connection 수명과 분리돼 있다 — architecture.md §3); 사용자가 다시 `qsh attach <name>/<id>`를 실행하면 데몬의 reverse connection이 살아 있는 한 정상적으로 재attach된다. 이 driver는 M3 Step 8에서 forward와 같은 `Reconnect` 추상 위에 통합될 예정이다.

## 7. Human interactive mode

다음 명령은 위의 session operation을 조합한 편의 인터페이스다.

```bash
qsh dave@personal-mac
qsh attach <session-ref>
```

Interactive mode는 terminal raw mode, window resize와 signal forwarding을 처리한다. 세션 생성·읽기·쓰기의 권한과 동작은 machine-readable command와 동일하다.

**Machine output mode가 없다.** 이 두 form의 stdout은 원격 터미널의 byte 그 자체이므로(§2.2) envelope가 들어갈 자리가 없다 — `qsh serve`(§6.12)와 같은 이유로 예외다. `--json`/`--jsonl`을 붙이면 **세션을 만들기 전에** `INVALID_ARGUMENT` error envelope 한 줄과 exit `255`(§4)로 거부한다. 기계 소비자는 같은 일을 `qsh session open --json` + `qsh session read --follow --jsonl` + `qsh session write`로 조합한다(§7.1).

**전달되는 환경변수.** 대화형 form은 로컬 터미널을 재현하는 데 필요한 것만 보낸다: `TERM`은 `SessionOpen.term`으로, locale(`LANG`, `LANGUAGE`, `LC_ALL`, `LC_CTYPE`, `LC_COLLATE`) 중 클라이언트 프로세스에 설정된 것은 `SessionOpen.env` overlay로 전달한다(architecture.md §4). 이는 **대화형 form 한정** 동작이다 — `qsh session open`·`qsh exec`·MCP는 호출자가 명시한 `--env`만 보내며, 클라이언트 프로세스의 환경을 암묵적으로 상속시키지 않는다. `HOME`/`USER`/`LOGNAME`/`SHELL`/`PATH`는 어느 경로에서도 호스트가 고정한다.

**`user@`의 의미.** 원격 셸은 항상 **`qsh serve`를 실행한 OS 계정**으로 실행된다 — MVP에는 user switching이 없고, ACL principal은 항상 인증서에서 나온다(§2.5, protocol.md §3). `user@`는 SSH 근육 기억을 위해 받아들이며 생략해도 된다(`qsh personal-mac`). 지정하면 `SessionOpen`에 선택 hint로 전달되고, 호스트는 그 값이 serve 계정의 login name과 다르면 세션을 만들지 않고 `UNSUPPORTED`(message: user switching is not supported)로 거부한다 — fail closed. 즉 `user@`는 "이 계정이어야 한다"는 단언이지 계정 선택이 아니다(PRD §6). 검사 순서는 **ACL `session.open` → `user` hint → spawn**이다: 인가되지 않은 peer는 hint 값과 무관하게 항상 `PERMISSION_DENIED`를 받고(계정명 비노출, audit는 ACL 판정만 기록), `UNSUPPORTED`는 인가된 peer에게만 반환된다. 비교는 serve 계정의 login name과 정확 일치(case-sensitive)다. `user@`는 `qsh [user@]host` 형태(`-L`/`-R` 플래그를 동반한 경우 포함 — 모두 `SessionOpen`을 보낸다)에서만 받으며, `qsh exec`/`qsh session open`/`qsh tunnel open`은 bare host만 받는다.

**Detach와 escape 시퀀스.** SSH와 같은 방식의 tilde escape를 쓴다. escape 문자는 **행의 시작에서만** 인식되며, 그 외 위치의 `~`는 그대로 원격 PTY로 전달된다. raw mode에는 line discipline이 없으므로 "행의 시작"은 *세션 시작 직후이거나, 클라이언트가 마지막으로 원격에 전달한 byte가 CR(`\r`, 0x0D) 또는 LF(`\n`, 0x0A)인 상태*로 정의한다.

| 입력 | 동작 |
|---|---|
| `~d` | detach — local client만 종료하고 세션은 계속 실행된다 |
| `~.` | detach와 동일 — **세션을 죽이지 않는다.** 세션은 설계상 client보다 오래 산다(PRD §8); 종료는 `qsh session close <session-ref>`(§6.7)로 한다 |
| `~~` | 리터럴 `~` 하나를 전송 |
| `~?` | escape 도움말을 **stderr**에 출력 |

이 표가 전부이며 다른 시퀀스(`~^Z`, `~#`, `~&` 등)는 없다. 행 시작의 escape 문자 1 byte는 다음 byte가 올 때까지 로컬에 보류되고 전달되지 않는다; 표에 없는 두 번째 byte가 오면 escape 문자와 그 byte를 **둘 다 그대로** 원격에 전달하고 상태를 초기화한다(ssh와 동일 — 입력이 조용히 사라지지 않는다). escape 처리는 **local stdin이 TTY일 때만** 활성이다 — pipe/file stdin에서는 `--escape-char`와 무관하게 꺼지고 모든 byte가 그대로 전달된다(`qsh session write`·MCP 경로에는 애초에 escape 처리가 없다).

escape 문자는 `--escape-char <c>`로 바꿀 수 있고 `--escape-char none`은 escape 처리를 끈다(그때 detach 수단은 client 프로세스 종료뿐이며 세션은 여전히 유지된다). 기본값은 `~`. `--escape-char`는 `qsh [user@]host`와 `qsh attach`에만 붙는 flag이며 값은 **단일 출력 가능한(printable, 공백·제어문자 제외) ASCII 문자** 또는 `none`이다(그 외는 `INVALID_ARGUMENT`, exit `2`) — 행 시작에서 눈에 보이지 않는 byte가 입력을 삼키는 일이 없도록 하는 제한이다; 설정 파일 기본값은 M2에 없다. escape 시퀀스는 client 로컬에서 소비되고 원격으로 전달되지 않는다.

### 7.1 Value operation과 stream operation

QSH operation은 두 종류로 나뉜다.

- **Value operation**: 단일 요청에 단일 응답을 반환하는 일반 RPC. `session.read`, `session.write`를 비롯해 이 문서 대부분의 command가 여기 속한다.
- **Stream operation**: 하나의 duplex byte channel을 열고 유지하는 operation. `session.attach`가 유일한 stream op이며, resume(`last_sequence` 기반) semantics를 갖는 duplex channel을 반환한다.

`qsh dave@personal-mac`와 `qsh attach <session-ref>` 같은 interactive attach는 내부적으로 이 `session.attach` 하나의 streaming operation 위에 구현된다. `session.read`/`session.write`는 machine-facing value operation으로 별도 존재하며, `--follow --jsonl`(§6.4)도 같은 streaming source에서 값을 공급받는다. attach와 read/write 사이에 별도 business logic은 없다.

## 8. MCP server

### 8.1 실행

```bash
qsh mcp
```

MVP에서는 stdio transport만 지원한다. MCP stdout에는 protocol frame만 출력하고 모든 진단 로그는 stderr로 보낸다.

### 8.2 Tool mapping

| MCP tool | Typed operation |
|---|---|
| `list_hosts` | `host.list` |
| `get_host` | `host.get` |
| `list_sessions` | `session.list` |
| `get_session` | `session.get` |
| `open_session` | `session.open` |
| `read_session` | `session.read` |
| `write_session` | `session.write` |
| `resize_session` | `session.resize` |
| `close_session` | `session.close` |
| `exec` | `exec.run` |
| `open_tunnel` | `tunnel.open` |
| `close_tunnel` | `tunnel.close` |

Tool input과 output field는 JSON CLI의 data type과 동일하다. MCP adapter가 command string을 만들거나 CLI output을 다시 parse해서는 안 된다. 두 adapter 모두 같은 Rust operation layer를 직접 호출한다.

### 8.3 지속 출력

MVP의 `read_session`은 streaming MCP extension에 의존하지 않는다.

```json
{
  "session_ref": "personal-mac/01K0SESSION",
  "after_sequence": 42,
  "wait_ms": 30000,
  "limit_bytes": 65536
}
```

Agent는 응답의 `next_after`/`next_ctl_after`를 다음 호출의 `after_sequence`/`ctl_after`로 그대로 되먹인다(§6.4의 두-값 cursor; `ctl_after`는 additive optional field라 처음 호출에서는 생략한다). 이 long-poll model은 다양한 MCP client에서 동일하게 동작한다.

### 8.4 보안

- MCP server는 실행한 local user의 QSH identity와 config를 사용한다.
- 각 tool call에 일반 CLI와 동일한 ACL을 적용한다.
- MCP를 통해 interactive trust prompt를 열지 않는다.
- `write_session`, `exec`, `open_tunnel`은 read operation과 별도 권한으로 검사한다.
- Tool cancellation은 해당 operation을 취소하지만 remote PTY를 자동 종료하지 않는다.

## 9. Timeout과 cancellation

- 모든 blocking machine operation은 `--timeout <milliseconds>`를 지원한다.
- `session read --wait`은 long-poll 대기 시간이며 전체 command timeout과 구분한다.
- SIGINT는 현재 local operation을 취소한다.
- Interactive attach의 SIGINT는 기본적으로 remote PTY로 전달하며, detach는 행 시작의 `~d`(또는 `~.`) escape 시퀀스로 한다(§7, `--escape-char`로 변경·비활성화). detach는 세션을 종료하지 않는다.
- MCP cancellation은 local wait 또는 request를 취소하고 session lifecycle을 변경하지 않는다.

## 10. Compatibility policy

- `qsh.cli/v1`과 `qsh.event/v1`에는 optional field를 추가할 수 있다. `qsh.event/v1`에는 새 event `type`도 추가할 수 있으며, 소비자는 알 수 없는 `type`을 무시해야 한다(§6.4).
- `reason`·`state`·`error.code`처럼 값 집합이 열린 문자열 field에는 새 값을 추가할 수 있다. 소비자는 알 수 없는 값을 오류 없이 처리해야 한다(`ErrorCode` 미지 코드 pass-through와 같은 원칙, §3.3).
- Field 삭제, type 변경과 의미 변경은 `/v2`가 필요하다.
- MCP tool에는 optional argument를 추가할 수 있지만 기존 argument를 재해석하지 않는다.
- Deprecated field와 tool은 최소 두 minor release 동안 유지한다.
- `qsh schema --json`으로 지원 version과 deprecation을 조회할 수 있어야 한다.

## 11. 구현 제약

- Human, JSON과 MCP adapter는 같은 Rust typed operation을 호출한다.
- Renderer 또는 adapter 내부에 인증·ACL·session logic을 구현하지 않는다.
- JSON mode를 test fixture로 사용해 schema compatibility를 검증한다.
- JSONL event는 한 줄에 하나의 완전한 JSON object이며 중간에 plain text를 삽입하지 않는다.
- Streaming backpressure가 remote PTY를 무제한으로 memory에 적재하게 해서는 안 된다.

