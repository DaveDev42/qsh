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
trust.invite
trust.accept
cert.init
cert.issue
doctor.run
acl.check
schema.get
capabilities.get
version.get
```

`session.attach`는 value operation이 아니라 stream operation이다 (§7.1 참고). CLI subcommand 표기(`qsh hosts`, `qsh session open` 등)와 이 dotted 이름은 서로 다른 계층이며, envelope의 `command` field·audit record·MCP mapping은 항상 이 dotted 이름을 사용한다.

`acl.check`(§6.15, M5)는 원격 peer가 요청하는 operation이 아니라 **이 머신 자신의** `acl.toml`을 로컬에서 조회하는 op이다 — §2.5의 "인가 불요" 행이 다른 local-only operation들과 함께 명시한다.

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
| `tunnel.close`, `tunnel.list` | 해당 tunnel의 소유 peer이면 허용 (`forward.*` 부여로 충분) — remote forward(`-R`)의 `tunnel.close`는 이 로컬-머신 축(§6.13·§6.14, `docs/design/protocol.md` §11-3)과 별개로, host 쪽 `forward.remote` principal 소유권 검사를 하나 더 거친다(M5 Step 5, §6.9 아래 문단). `-L`의 `tunnel.close`에는 이 host 쪽 검사가 없다 — 로컬 listener를 닫는 것뿐인 순수 local operation이다 |
| `host.list`, `host.get`, `identity.init`, `trust.*`, `cert.init`, `cert.issue`, `doctor.run`, `acl.check`, `schema.get`, `capabilities.get`, `version.get` | 인가 불요 — local operation으로 원격 peer의 ACL 평가 대상이 아님 |

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
    "message": "peer is not allowed to perform this operation on this host",
    "retryable": false,
    "details": {}
  }
}
```

`message`는 사람을 위한 설명이다. 자동화는 `code`와 구조화된 `details`만 사용해야 한다.

> 위 예시의 `message` 문안은 M5 Step 4가 확정한 균일 거부 문면이다(`crates/qsh-core/src/acl/mod.rs`의 `PERMISSION_DENIED_MESSAGE`) — 원격 peer 대면 `PERMISSION_DENIED`는 어느 인가 지점(정책 거부, 소유권 거부, 감사 기록 실패에 의한 fail-closed 거부)에서 왔든 거부된 action/capability/resource/principal을 노출하지 않고 이 문장 그대로 나간다(`docs/ROADMAP.md` M5 감사 개정 ③, `PLAN.md` M5 Step 4 §4.2). `message`는 계약이 아니므로(위 문단) 이 문안 자체는 `qsh.cli/v1` 호환성 대상이 아니지만, 상수와의 일치는 CI가 지킨다(`crates/qsh-core/tests/acl_docs.rs`).

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
  "device_id": "sha256:BASE64FINGERPRINT",
  "source": "both",
  "user": "dave"
}
```

`connection_mode ∈ {"forward", "reverse"}`. `state`는 열린 문자열(§10)이며 `∈ {"reachable", "stale", "unknown"}`: forward host는 도달성을 probe하지 않으므로 항상 `"unknown"`이다 — 확인하지 않은 것을 `"reachable"`로 보고하지 않는다. live 역방향 등록은 `"reachable"`(인증된 연결을 실제로 쥐고 있다), 죽은 등록은 보존 창 동안 `"stale"`이다(§6.13).

`device_id`는 **peer의 SPKI SHA-256 fingerprint 문자열**(`sha256:BASE64`, architecture.md §5의 표기)이다 — forward host는 trust store에 **핀된** fingerprint, reverse host는 상주 데몬이 **TLS로 검증한** peer fingerprint다. `Hello.device_name` 같은 wire 표시 이름은 어떤 경우에도 identity로 쓰지 않는다(protocol.md §3). `Host`는 이전까지 어떤 op도 emit한 적 없는 placeholder였고 fixture도 없었으므로, 위 값 어휘는 field의 **정의**이지 §10이 금지하는 기존 의미의 변경이 아니다. `device_id`는 **이 이름에 핀된 신원**이지 — `address`에 지금 실제로 누가 응답하고 있는지에 대한 관측이 아니다: forward host의 `address`는 `hosts.toml`에서 올 수 있지만 `hosts.toml`은 신원을 전혀 공급하지 않으므로, `address`가 어느 디렉터리에서 왔든 `device_id`는 항상 trust.toml이 그 이름에 핀한 peer를 가리킨다(아래 `source` 문단).

`source`/`user`는 M7 Step 3에서 추가된 **additive-optional** field다(§10) — `hosts.toml` 디렉터리가 전혀 없거나 항목이 하나도 없으면 두 field 모두 생략된다(키 자체가 나타나지 않는다, `null`이 아니라). `hosts.toml`에 항목이 하나라도 있으면 forward host마다 `source ∈ {"hosts", "trust", "both"}`를 보고한다 — 다만 이는 어느 디렉터리가 이 이름을 *아는지*가 아니라 **어느 디렉터리의 `address`가 실제로 이겼는지**를 가리킨다(§6.1 우선순위 참고): `hosts.toml`이 이 이름에 비어 있지 않은 주소를 설정했고 그 값이 `trust.toml`의 pin과 다르거나 `trust.toml`에 아예 pin이 없으면 `"hosts"`, `hosts.toml`에 항목이 없거나 그 주소가 빈 문자열이라 `trust.toml`의 pin된 주소가 그대로 쓰이면 `"trust"`, 양쪽 주소가 **일치할 때만** `"both"`다. reverse host는 항상 `source`가 생략된다 — 역방향 등록은 `hosts.toml`에서 오지 않는다. `user`는 `hosts.toml`이 그 이름에 설정한 hint가 있을 때만 나타나며 §7의 assertion hint와 동일한 의미다(계정 선택이 아니다).

**threat 참고.** `hosts.toml`에 쓰기 권한이 있다는 것은 어떤 이름을 이미 핀된 다른 peer로 돌릴 수 있는 권한이다(mTLS는 여전히 핀되지 않은 주소를 막는다) — 이런 redirect는 `source: "hosts"`로 드러난다(주소가 trust.toml의 pin과 다르거나, trust.toml에 pin이 아예 없는 경우).

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

`hosts`는 두 데이터 소스를 합쳐 반환한다: forward host(`hosts.toml`과 `trust.toml`을 아래 우선순위로 합친 결과)와, 상주 `qsh listen` 데몬이 현재 쥐고 있는 live 역방향 등록(§6.13). **`host.list`는 dial하지 않는다** — forward host의 도달성은 확인하지 않으므로(§5, `state`는 항상 `"unknown"`) 이 목록은 순수 로컬 조회다. 같은 이름이 forward host와 reverse 등록 양쪽에 존재하면 `hosts` 배열에 `connection_mode`로 구분되는 **두 항목**으로 나타난다 — 목록에서는 병합하지 않는다. 다만 그 이름으로 실제 연결을 맺을 때(attach, `qsh <name>`)의 **라우팅 우선순위는 live reverse 등록이 우선**이다 — 증명된 도달 가능 경로를 forward host의 추정 주소보다 앞세운다.

**forward host 해석 우선순위 (`hosts.toml` vs `trust.toml`, M7 Step 3):** 같은 이름이 `hosts.toml`과 `trust.toml` 양쪽에 있으면 **`hosts.toml`의 `address`가 이긴다**. `trust.toml`에만 있으면 그 주소를, `hosts.toml`에만 있으면 그 주소를 쓴다. **fingerprint(신원)는 항상 `trust.toml`에서만 온다** — `hosts.toml`은 이름과 주소, `user` hint만 담는 순수 주소록이며 신원 판단에 절대 관여하지 않는다: `hosts.toml`이 어떤 이름에 주소를 대더라도 실제 dial 시 TLS 계층에서 그 주소가 제시한 fingerprint가 trust store 어딘가에 핀되어 있지 않으면 인증은 그대로 실패한다(pin 조회는 이름이 아니라 fingerprint 기준이다). `hosts.toml` 파일이 없거나 비어 있으면 이 절차는 M7 이전과 동일하게 `trust.toml`의 pin이 유일한 출처다. `hosts.toml`은 **read-only 디렉터리**다 — 이를 쓰는 CLI 명령은 없으며 수동으로 직접 편집한다. `hosts.toml`에 쓰기 권한이 있다는 것은 곧 어떤 이름을 이미 핀된 다른 peer로 돌릴 수 있는 권한이다(mTLS는 여전히 핀되지 않은 주소를 막는다) — 그런 redirect는 `host.list`/`host.get`의 `source: "hosts"`로 드러난다(§5).

`hosts.toml`의 주소는 op 시작 시점에 한 번 resolve된다 — session이 열려 있는 동안 파일을 고쳐도 그 session에는 반영되지 않는다. `attach`가 끊긴 연결을 자동으로 재접속할 때도 최초 attach 시점에 resolve된 주소를 계속 쓴다(재resolve 없음). 이는 매 handshake마다 내용을 다시 읽는 `trust.toml`과 대비된다(§6.11 `trust remove` 문단).

**`hosts.toml` 파일 계약.** `<config_dir>/hosts.toml`(`trust.toml`과 같은 디렉터리, architecture.md §7)에 다음 형식으로 둔다.

```toml
[[host]]
name = "personal-mac"
address = "personal-mac.example.com:4433"
user = "dave"
```

`name`·`address`는 필수, `user`는 선택이다. 파일이 없으면 빈 디렉터리로 취급한다(오류 아님) — M7 Step 3 도입 이전과 동일하게 `trust.toml`의 pin만으로 동작한다. 파싱 실패(TOML 문법 오류, 필수 필드 누락)는 `CONFIG_ERROR`(`retryable: false`)로, `trust.toml`이 손상됐을 때와 동일한 실패 형태다. 같은 `name`이 여러 번 나오면 첫 항목이 이긴다(`trust.toml`과 같은 규칙). `address`를 빈 문자열로 명시하면 파싱은 되지만 그 이름에 대해 `hosts.toml`은 "주소 없음"으로 취급되어 `trust.toml`의 주소로 폴백한다(`trust.toml`의 client-only pin과 동일한 관례).

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

**`session.write`/`session.resize`는 ACL 통과 후 이 세션을 연 principal(opener)에도 결합된다** — §2.5의 ACL principal과 같은 축이며(§6.2의 attach가 쓰는, peer fingerprint에 결합된 resume credential과는 다른 축이다), M1–M4의 고정 장비 전용 posture에서는 principal이 장비 하나에 1:1로 대응하므로 사실상 장비 결합과 같다. `acl.toml`의 `scope` 키(§2.5, 기본값 `"owned"`)가 M5부터 이 결합을 실제로 판정한다 — 방금 설명한 opener 결합이 `scope = "owned"`(기본값)이고, rule에 명시적으로 `scope = "any"`를 준 경우만 이 결합을 벗어난다. principal이 다른 요청은 ACL을 통과하더라도 정책 거부와 문면이 동일한 `PERMISSION_DENIED`로 거부되고(어떤 세션이 누구 소유인지는 노출하지 않는다) `session.control` deny로 감사 기록에 남는다(PRD §6). **`session.get`/`read`/`close`는 이 결합의 영향을 받지 않고 §6.2의 ACL 범위를 그대로 따른다 — `scope = "owned"`가 걸린 rule 아래에서도 마찬가지다.** `close`가 `write`/`resize`와 같은 `session.control` action을 쓰면서도 이 결합에서 빠진 것은 우연이 아니라, PRD §6이 요구하는 교차 기기 종료(꺼진 장비가 남긴 세션을 다른 장비에서 정리하는 시나리오)를 위한 의도적인 예외다(`docs/design/architecture.md` §6).

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

`host` 인자는 host 이름이다. host→주소 해석은 §6.1의 우선순위(`hosts.toml` 우선, 없으면 `trust.toml`의 pinned peer로 폴백)를 따른다 — `exec`뿐 아니라 attach·`session open`·`qsh reverse <controller>`의 controller dial까지 모두 이 동일한 해석을 공유한다.

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

**Spec grammar.** `--local`(`-L`)과 `--remote`(`-R`)는 같은 grammar를 공유한다: `[bind:]listen_port:host:host_port`(예: `8080:localhost:3000`, IPv6 bind는 `[::1]:8080:localhost:3000`처럼 대괄호로 감싼다). `listen_port`/`host_port`는 `1..=65535`만 유효하며 `0`과 `65536`은 파싱 단계에서 `INVALID_ARGUMENT`다. 이 grammar를 파싱하는 `qsh-proto::wire::parse_forward_spec`은 sans-IO 순수 함수이고 **모양만** 검사한다 — non-loopback `bind`도 grammar상으로는 유효하게 파싱된다. `-L`은 로컬 머신에서 `listen_port`를 열고 들어오는 각 TCP 연결마다 host에 `host:host_port`로 dial을 요청하며, `bind`를 생략하면 loopback에 bind한다. `-R`은 반대 방향이다: host가 자신의 `listen_port`를 열고 들어오는 각 연결을 로컬 머신의 `host:host_port`로 되돌려 보낸다 — **non-loopback `-R` bind는 host 쪽에서 `INVALID_ARGUMENT`로 거부된다**(parser는 모양만 검사하고, loopback-only는 파서가 아니라 host가 강제하는 policy다). 그 거부의 `message`는 정확히 "remote forward binds loopback only"다(`qsh_core::tunnel::REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE`, `docs/design/testing.md` L6 — README와 이 문구가 그 상수와 어긋나면 CI가 실패한다).

`-R`은 리스너를 bind하기 전에 두 층을 순서대로 통과해야 한다: 먼저 host가 `forward.remote`(§2.5)로 principal을 ACL 평가하고, 거부면 `PERMISSION_DENIED`이며 아무것도 뜨지 않는다. 통과한 뒤에야 위 loopback 강제가 적용되고, 위반이면 `INVALID_ARGUMENT`다(마찬가지로 아무것도 뜨지 않는다). 두 거부는 층이 다르다는 점이 핵심이다 — 하나는 그 principal이 `forward.remote`를 가졌는지 판정하는 ACL이고, 다른 하나는 `forward.remote`를 **가진** principal에게도 예외 없이 적용되는 host 쪽 요청 제약이다(`docs/PRD.md` §9).

**`-R`을 닫는 쪽(`tunnel.close`)도 host 쪽 ACL choke point다(M5 Step 5).** `RemoteForwardOpen`을 보낸 principal만 그 `forward_id`를 닫을 수 있다 — 다른 principal이 시도하면 host는 그 forward를 건드리지 않고 `PERMISSION_DENIED`로 거부한다(§3.2와 byte-for-byte 동일한 문면). 이 거부가 "존재하지 않는 forward_id"와 "남의 forward_id"를 구별 불가능하게 만드는 것은 그 principal이 **`forward.remote` 권한 자체를 갖지 못한 경우뿐**이다(F2, M5 Step 5 adversarial review) — 그때는 ACL 게이트가 principal 일치 단계에서 이미 걸려 두 경우 모두 같은 `PERMISSION_DENIED`다. `forward.remote`는 가졌지만 이 forward의 소유자가 아닌 principal에게는 두 경우가 갈린다: 남의 실재하는 forward_id는 `scope = "owned"`가 걸러 `PERMISSION_DENIED`, 존재하지 않는 forward_id는 owner가 없어 scope에 걸러지지 않고 ACL 게이트를 통과한 뒤에야 등록표에 없어서 `INVALID_ARGUMENT`("no such forward_id")다 — `session.write`/`resize`가 남의 세션과 존재하지 않는 세션에 각각 `PERMISSION_DENIED`/`SESSION_NOT_FOUND`를 주는 것과 M3이 이미 받아들인 것과 같은 트레이드오프다. 소유 축은 `RemoteForwardOpen`을 실어 나른 QUIC connection이 아니라 그것을 **보낸 principal**이다 — `acl.toml`의 `scope`(§2.5, 기본값 `"owned"`)가 세션의 `session.control`과 같은 어휘로 이 축을 판정하며, 같은 principal이 다른 connection으로 재접속해도 자신이 연 forward는 여전히 닫을 수 있다(`docs/design/protocol.md` §7). 이 검사는 §6.13·§6.14가 다루는 **로컬 머신** 축(localctl의 `NotOwner`, same-uid 두 CLI 프로세스 사이의 conduit 소유권)과는 완전히 다른 층이다 — 그쪽은 원격 peer 인가가 아니어서 `PERMISSION_DENIED_MESSAGE`를 쓰지 않는다(`docs/design/architecture.md` §6).

**JSON envelope.** `tunnel.open`의 `data`는 아래 `Tunnel` 하나다:

```json
{
  "tunnel_id": "01K0TUNNEL",
  "mode": "local",
  "bind": "127.0.0.1:8080",
  "forward_to": "localhost:3000",
  "actual_port": 8080,
  "host": "personal-mac"
}
```

`mode`는 §10과 같은 열린 문자열(open string)이며 `∈ {"local", "remote"}`(`connection_mode`와 같은 패턴 — 값 집합이 늘어나도 type 변경이 아니다). `actual_port`는 optional이다 — bind 시점에 실제로 배정된 port를 돌려주는 field로, ephemeral(`0`) 요청이거나 요청 port를 그대로 못 받았을 때 요청값과 달라진다. optional인 이유는 아직 bind되지 않은 tunnel에는 보고할 port가 없기 때문이고, **bind된 port를 아는 producer는 요청 port가 그대로 배정된 fixed-port forward에서도 항상 이 field를 채운다**(위 예시가 그렇다) — reader가 field 부재를 만나 `bind`를 되쪼개는 일이 없게 하기 위함이다. `host`는 클라이언트 `Ops`가 채우는 alias field이며 wire에는 없다 — `Session.host`/`session_ref`와 같은 패턴이다(§5, [ADR-0007](adr/0007-session-ref-and-resume-token-custody.md)). `bind`의 모양은 요청과 결과에서 다르다 — `tunnel.open` 요청(`TunnelOpenReq.bind`)에서는 `[bind:]` prefix만 담아 host-only(예: `"127.0.0.1"`, 생략 시 `None` = 호출자 쪽 default)이지만, 위 `Tunnel.bind`처럼 결과에서는 `listen_port`를 합친 host:port 전체(예: `"127.0.0.1:8080"`)다 — `Tunnel`에는 별도 `listen_port` field가 없으므로 실제로 bind된 address와 port가 `bind` 하나에 온전히 남아있게 하기 위함이다.

`tunnels`(`tunnel.list`)의 `data`는 `{"tunnels": [Tunnel, …]}`이고, `tunnel.close`의 `data`는 `{"tunnel_id": "...", "closed": true}`다. 존재하지 않는 `tunnel_id`를 닫는 것도 오류가 아니라 멱등이다 — `ok: true`에 `data.closed: false`를 반환한다(§6.11 `trust.remove`와 같은 패턴). **`tunnels`는 상주 `qsh listen` 데몬이 실제로 쥐고 있는 터널만 보고한다** — 즉 reverse route 위에서 daemon-held로 등록된 `-R`(`mode: "remote"`)뿐이다. forward route에서 standalone `qsh tunnel open`이 연 터널은 그것을 연 CLI 프로세스가 유일한 홀더이고 (§6.14) 그 프로세스의 메모리를 조회할 IPC 경로가 없으므로, 다른 프로세스의 `qsh tunnels`에는 절대 나타나지 않는다 — 마찬가지로 reverse route 위의 `-L`도 로컬 listener는 그것을 연 CLI 자신의 소켓이라 데몬이 쥔 것이 아니므로 나타나지 않는다. 이는 스펙 결함이 아니라 §6.14가 이미 확정한 holder 모델의 직접적 귀결이다: `tunnels`는 daemon-held 터널을 조회하는 것이지 이 머신의 모든 터널을 조회하는 것이 아니다.

**Holder 수명은 route에 따라 갈린다.** forward route에서는 tunnel(`-L`/`-R` 모두)이 그것을 연 CLI 프로세스에 수명이 결합된다(§6.14). **reverse route의 `-R`만은 다르다** — target의 listener는 그 CLI가 아니라 상주 `qsh listen` 데몬이 쥔 reverse connection에 결합돼, CLI가 죽어도 살아남고 reverse connection이 죽어야 함께 죽는다(§6.13·§6.14 예외 문단, `docs/design/protocol.md` §11-3).

`-D`(SOCKS5 dynamic forwarding, `forward.socks`)는 CLI 인자로 parsing되지만 P0에서는 항상 `UNSUPPORTED`(`message`는 정확히 "SOCKS dynamic forwarding (-D) is a P1 feature" — `qsh_core::ops::tunnel::DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE`, `docs/design/testing.md` L6 게이트 대상)로 거부된다 — envelope data에는 절대 도달하지 않는다. 구현은 P1이다. 스펠링은 두 곳에 있고 둘 다 반복 가능하다 — 대화형 form의 `-D <[bind:]port>`와 `tunnel open`의 `-D`/`--dynamic <[bind:]port>`. 값은 P0에서 전혀 parsing되지 않는다 — 어떤 값을 주든 동일한 `UNSUPPORTED` 거부 한 건으로 수렴한다. 대화형 form에는 우선순위가 하나 더 얹힌다: `--json`/`--jsonl`이 함께 오면 `-D`와 무관하게 §7의 `INVALID_ARGUMENT`가 우선한다 — 대화형 form에는 애초에 machine mode가 없기 때문이다.

### 6.10 Schema와 capability

```bash
qsh schema --json
qsh capabilities --json
qsh capabilities personal-mac --json
qsh version --json
```

`schema`는 `qsh.cli/v1` envelope과 각 command의 `data` payload에 대한 JSON Schema(schemars, draft 2020-12 dialect)를 그대로 서빙한다 — golden fixture를 검증하는 것과 **동일한 스키마**다(한 소스, `docs/design/testing.md` L6). `data.schemas`는 이 build가 이해하는 wire/CLI schema 식별자 목록(`version.get`과 동일), `data.envelope`는 envelope 자체의 schema, `data.commands`는 dotted operation 이름(§2.4)을 key로 하는 schema map이다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "schema.get",
  "ok": true,
  "data": {
    "schemas": ["qsh.cli/v1", "qsh.event/v1"],
    "envelope": { "...": "CliEnvelope의 JSON Schema" },
    "commands": {
      "version.get": { "...": "VersionData의 JSON Schema" }
    }
  }
}
```

`capabilities`를 host 없이 호출하면 이 build가 `Hello`에 advertise하는 로컬 capability 집합을 가공 없이 그대로 반환한다 — 이 형태만 checked-in fixture로 고정되어 값이 바뀌면 fixture diff로 드러난다(scope-creep tripwire, `docs/ROADMAP.md` M7 DoD 3). host를 주면 그 host와 negotiation된 `Hello`의 교집합을 반환한다 — forward(pinned) host는 그 주소로 직접 dial해 호출마다 새로 negotiation하고, reverse 등록 host는 이 머신의 `qsh listen`/`qsh reverse` daemon이 이미 들고 있는 연결(등록 시점에 그 daemon과 합의된 capability 집합)을 relay로 읽어 보고할 뿐 이 프로세스가 peer를 직접 dial하지 않는다(`docs/design/architecture.md` §2). 이를 위한 별도 wire request는 없다: 어떤 value operation이든 연결을 여는 순간 이미 수행하는 handshake의 결과를 읽어 보고할 뿐이며, 그래서 `capabilities.get`은 §2.5의 "인가 불요" 행에 다른 local operation들과 함께 있다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "capabilities.get",
  "ok": true,
  "data": {
    "capabilities": ["exec", "session", "resume.v1"],
    "host": "personal-mac"
  }
}
```

host 없이 호출한 결과에는 `host` field가 없다 — omitted, `null`이 아니다.

`version`의 `data.build.commit`은 이 binary가 컴파일될 때 `QSH_BUILD_COMMIT` 환경변수가 있었을 때만 채워지는 additive optional field다(`docs/ROADMAP.md` M7 감사 개정 ③): CI는 commit sha를 주입하고, 그런 변수 없이 만든 local build는 `build` field 자체가 통째로 생략된다 — 조작된 값이나 빈 문자열이 아니라 부재다.

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

`trust.add`는 fingerprint를 명시하면 연결 없이 peer를 pin한다(provisioning 친화). 이때 `--address`는 선택이며 생략하면 `address`는 빈 문자열로 기록된다 — 단, `qsh exec <name>`의 host→주소 해석(§6.1, §6.8)은 address가 있는 pin만 이 store 쪽 후보로 삼으므로 명령을 보낼 host는 address와 함께 pin하거나 `hosts.toml`에 주소를 적어 둔다(inbound 전용 peer, 즉 "이 장비에 접속해 올 client"는 fingerprint만으로 충분하다). fingerprint 없이 연결해서 확인하는 방식은 human mode에서만 prompt를 열며 `--json` mode에서는 §2.1 규칙에 따라 prompt 대신 `TRUST_REQUIRED` 오류에 `details.observed_fingerprint`와 `details.address`를 담아 반환한다 — 호출자는 그 값을 검증한 뒤 `--fingerprint`로 재호출한다.

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

이미 같은 이름으로 pin된 경우도 오류가 아니라 멱등이다 — `data.created`가 `false`로 돌아온다. 이때 갈리는 경우가 둘 있다(M7 Step 2 결정 B):

- **같은 fingerprint, 다른 `--address`:** 저장된 address를 그 자리에서 갱신한다 — host의 실제 주소가 바뀌었을 때(예: 재기동으로 바인딩 포트가 달라짐, 모바일 캠페인처럼 IP 자체가 바뀜) `trust remove` 없이 같은 identity로 `trust add`를 다시 실행하면 pin이 새 주소를 따라간다. 결과는 `data.updated: true`이고 `data.peer.address`가 새 값이다. `added_at`은 identity가 처음 pin된 시각을 그대로 유지한다(주소가 바뀐 시각이 아니다). `--address`를 아예 생략하면(기존 값을 건드릴 뜻이 없다는 뜻이므로) 아무것도 바뀌지 않는다.
- **다른 fingerprint:** identity 자체를 바꿔치기하는 것이므로 아무것도 바뀌지 않는다 — address도, fingerprint도 기존 값 그대로다. identity를 다시 묶으려면 `trust remove` 후 `trust add`를 명시적으로 실행해야 한다(반복 호출의 부작용으로는 일어나지 않는다).

두 경우 모두, 그리고 완전한 no-op(같은 fingerprint·같은 address) 재호출도 `data.updated`가 나온다 — 값은 실제로 address가 바뀌었을 때만 `true`, 그 외에는 `false`다. 새 pin(`data.created: true`)에는 `updated` 자체가 없다(적용 대상이 없으므로 키가 생략된다 — additive: M7 Step 2 이전 envelope에는 없던 필드다).

`trust.add` 결과 (같은 identity, 주소만 갱신):

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
      "address": "personal-mac.example.com:5555",
      "added_at": "2026-08-17T00:00:00Z"
    },
    "created": false,
    "updated": true
  }
}
```

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

**`trust.remove`의 유효 범위(M7 Step 2, 감사 ①, DoD 4):** 제거는 즉시 적용되지만, 무엇에 즉시 적용되는지가 핵심이다. 러닝 중인 `qsh serve`를 **재시작할 필요 없이** 그 다음 handshake부터 거부가 적용된다 — host는 `trust.toml`을 매 handshake마다 다시 읽어 내용을 대조하므로(파일 바이트 비교가 유일한 판정자다 — `mtime`은 판정에 쓰이지 않고 진단 기록으로만 남으므로, 1–2초 해상도의 파일시스템이라도 내용이 다르면 재로드가 일어난다; 프로세스 시작 시 1회만 읽는 `acl.toml`과는 다르다) `trust remove` 직후의 새 연결 시도는 즉시 `AUTH_FAILED`로 거부된다. 반대로 **이미 확립된 연결**은 이 제거의 영향을 받지 않는다 — 그 peer는 연결의 협상된 권한 전체를 유지한다: 이미 열어 둔 세션뿐 아니라, `qsh serve` 시작 시 로드된 ACL 허용 범위 안에서 새 세션·터널·forward를 여는 능력까지, 연결이 끊기고 다시 handshake해야 하는 시점까지 그대로 유지된다(README "Known limitations" 동일 문면). 살아 있는 연결의 즉시 강제 종료는 P1이다(`docs/ROADMAP.md` §3).

```bash
qsh trust invite --json
qsh trust accept <address> <code> --json
```

`trust.invite`는 이 장치에서 10분 TTL짜리 1회용 invite code를 발급한다(ADR-0002, M7 Step 4). 160-bit CSPRNG secret을 Crockford Base32로 인코딩해 `xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx` 형태(소문자, 4자씩 8그룹)로 보여준다. code 자체에는 주소가 들어 있지 않다 — 이 장치에 닿을 `host:port`는 별도로, out-of-band 경로로 전달해야 한다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.invite",
  "ok": true,
  "data": {
    "code": "abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab",
    "expires_at": "2026-08-31T00:10:00Z",
    "accept_command": "qsh trust accept <address> abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab"
  }
}
```

human mode는 `accept_command`를 화면에 그대로 찍는다. operator는 `<address>` 자리만 실제 주소로 바꿔 상대에게 전달하면 된다 — 그게 이 필드의 유일한 용도다.

`trust.accept <address> <code>`는 `address`로 dial해 `code`가 가리키는 invite를 redeem한다. 인증의 근거는 TLS identity가 아니라 secret 소유 증명이다: 양쪽은 TLS exporter(RFC 5705 `export_keying_material`)로 채널에 묶인 값을 뽑고, 그 위에 도메인을 분리한 두 개의 BLAKE3 keyed-hash 증명(initiator→responder, responder→initiator)을 constant-time으로 주고받는다. 상대 쪽 증명이 검증되기 전에는 어느 쪽도 pin하지 않는다 — 메시지가 도착했다는 사실만으로 pin하는 경로는 없다.

이 증명이 보장하는 것은 "상대가 invite secret을 안다"까지다 — 그 이상의 신원 주장은 아니다. secret은 전화나 채팅처럼 사람이 개입하는 경로로 전달되는 경우가 많으므로, 더 높은 확신이 필요하면 pairing이 끝난 뒤 `trust list`가 보여주는 fingerprint를 out-of-band로 상대와 사후 대조하는 것도 방법이다 — pairing 자체가 요구하는 단계는 아니고, 원하는 operator가 추가로 얹는 defense-in-depth다(`docs/design/protocol.md` §15.4).

성공하면 두 장치가 같은 교환 안에서 서로를 pin한다. pin은 `trust.add`와 같은 경로(`TrustStore::add_peer`)를 타므로 `trust.accept`의 결과 모양도 `trust.add`와 같다 — 다만 `address`는 `trust.add`의 기본값(생략 시 빈 문자열)과 달리 방금 dial에 성공한 그 주소가 그대로 채워진다: pairing은 항상 실제 연결을 전제하므로 채울 주소가 없는 경우가 없고, 이걸 비워 두면 `qsh exec <name>`(§6.1, §6.8)이 곧바로 `HOST_NOT_FOUND`가 되어 ADR-0002가 노리는 "페어링 후 바로 접속" 경험이 깨진다:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.accept",
  "ok": true,
  "data": {
    "peer": {
      "name": "personal-mac",
      "fingerprint": "sha256:BASE64FINGERPRINT",
      "address": "192.0.2.10:4433",
      "added_at": "2026-08-31T00:05:00Z"
    },
    "created": true
  }
}
```

invite는 한 번만 redeem된다 — 성공하는 순간 소비되고, **다른** 상대가 같은 code를 다시 쓰면 `SESSION_CONFLICT`다. TTL이 지난 code는 `TRUST_REQUIRED`, secret이 맞지 않는 code(오타, 아직 발급되지 않은 code 등 — 이미 소비된 code와는 다른 오류다)는 `AUTH_FAILED`로 거부한다.

**이미 pin된 상대가 재시도하는 경우는 이 "다시 쓰면 `SESSION_CONFLICT`"와 겉모습은 같지만 원인이 다르다.** 페어링에 성공한 바로 그 상대가 (예: accept 명령을 실수로 두 번 실행해서) 같은 code로 다시 접속을 시도하면, host는 이미 그 신원을 pin해 뒀으므로 TLS 단에서 pin 경로가 먼저 잡혀 이 연결은 애초에 invite/pairing 판정 자체에 닿지 못한다 — 대신 일반 handshake 경로가 이를 자리를 벗어난 메시지로 보고 `SESSION_CONFLICT`(`retryable: false`)로 명시적으로 거부한다. **이때는 새 invite를 발급받아도 소용없다** — code나 invite의 상태가 문제가 아니라 이 신원이 host에 이미 pin되어 있다는 사실 자체가 원인이므로, 복구하려면 host가 `trust remove`로 기존 pin을 먼저 지워야 한다(`docs/design/protocol.md` §15.6, README Known limitations).

pin 시점에 이름 충돌이 생기면 — 상대가 자칭하는 이름이 이미 다른 fingerprint로 pin되어 있으면 — `trust.add`가 같은 상황에서 취하는 조용한 no-op과 달리 pairing은 `SESSION_CONFLICT`로 크게 실패한다. 이 실패는 invite를 소비하지 않는다: 충돌은 pin을 시도한 쪽의 로컬 상태 문제일 뿐이므로, 같은 code를 다른 상대가 곧바로 다시 시도할 수 있다.

상대가 자칭하는 `device_name`(양쪽 다 — initiator의 `PairingProof.device_name`, responder의 `PairingAccepted.device_name`)에 제어 문자(tab 포함, `char::is_control()`)가 하나라도 있으면 그 자리에서 `INVALID_ARGUMENT`로 거부한다 — 어느 쪽도 pin되지 않고, 거부된 값 자체는 로그에 남기지 않는다. `device_name`은 인증 입력이 아닌 자칭 label일 뿐이지만, human 렌더러가 `{name} ({fingerprint})`를 한 줄에 찍으므로 이스케이프 시퀀스가 그 fingerprint(바로 위 문단이 사후 대조를 권하는 값)를 가리거나 지울 수 있다는 것이 이 거부의 이유다(`docs/design/protocol.md` §15.5).

`qsh serve`로 이미 떠 있는 데몬은 재시작 없이 새로 발급된 invite를 인식한다 — `trust.remove`(바로 위 문단)가 따르는 것과 같은 content-based reload 원칙이 invite store에도 그대로 적용된다. 이 재로드는 `qsh trust invite`(CLI 프로세스)와 `qsh serve`(daemon)가 같은 `invites.toml`을 서로 다른 프로세스에서 잠금 없이 읽고 쓰는 형태라, 두 프로세스의 쓰기가 정확히 겹치는 좁은 창에서는 한쪽의 갱신이 다른 쪽에 곧바로 반영되지 않을 수 있다(예: 거의 동시에 발급된 두 invite 중 하나가 다음 redeem 조회에서 아직 보이지 않는 경우) — 이후 재시도나 다음 저장 시점에는 다시 수렴하므로 invite가 영구히 사라지지는 않지만, 완전한 파일 잠금은 아직 없다(Step 7 debt로 이월).

`--json` mode에서는 pairing도 interactive prompt를 열지 않는다(§2.1) — 잘못된 code나 인자 오류는 곧바로 오류 envelope로 반환된다.

`doctor.run`의 전체 계약(§6.17, M7 Step 6)은 진단 코드 13종·envelope 모양·exit code 규칙을 담는다 — 이 절 밖에서는 더 설명하지 않는다.

원격 operation(`exec.run`, `session.*`, `tunnel.*`)의 mTLS 실패 오류 경로는 다음과 같다.

- `TRUST_REQUIRED`: peer가 trust store에 없음. `details`: `observed_fingerprint`, `address`. `retryable: false`. (`qsh exec <host>`의 host 이름 자체는 §6.1의 우선순위로 `hosts.toml`/`trust.toml`에서 해석되므로 원격 op가 이 코드를 낼 수 없다 — 미등록 host(양쪽 모두 이 이름의 주소가 없음)는 `HOST_NOT_FOUND`, 주소는 해석됐지만 그 fingerprint가 trust store에 핀되어 있지 않거나 실제 응답이 핀과 다른 경우는 `AUTH_FAILED`다 — `hosts.toml`이 주소를 대더라도 신원 판단은 여전히 trust store 단독이다(§6.1). M1에서 이 코드의 유일한 생산자는 fingerprint 없는 `trust add`다.)
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
- **정책 파일 진단(M5).** 시작 시 `acl.toml`을 1회 읽는다(hot reload 없음). 파일이 없거나 파싱에 실패해도 프로세스는 뜨고 bind하지만, 그 상태에서 도달하는 모든 인가 판정은 항상 `deny`이고 어떤 리소스(세션·터널·등록)도 생성되지 않는다(`docs/design/architecture.md` §6, `PLAN.md` M5 §4.1 #1). 운영자에게는 stderr에 `no usable acl.toml policy`, `every request is denied until this is fixed`, 파일 경로, `CONFIG_ERROR` 코드, 복사해 붙일 수 있는 최소 정책 예시(이 머신에 실제로 pin된 peer 이름을 채운), `acl.toml is never auto-generated — create it by hand`, `verify a fix before restarting: qsh acl check`를 담은 진단을 한 번 출력한다 — 진단의 `code` 필드는 `acl_policy_missing`(파일 부재)과 `acl_policy_invalid`(파싱·검증 실패) 두 code word로 두 원인을 구분한다 — core(`crates/qsh-core/src/acl/load.rs`의 `StartupDiagnostic::render`)가 조립한 완성 문자열을 CLI가 그대로 stderr에 쓰는 평문 블록이다(tracing JSON 라인이 아니다). §6.13이 인용하는 `qsh-core::doctor::CONTROLLER_UNREACHABLE`과 공통점은 딱 하나다 — 문안 정본은 core에 있고 CLI는 인가 로직 0줄로 출력만 한다는 것. `doctor::Diagnostic`에는 `render()`가 없어 CLI가 `message`/`remedy` 두 필드를 직접 조립해 쓴다는 점에서 조립 방식 자체는 다르다. 정책 파일의 원본 소스 라인은 절대 덤프하지 않는다 — 유일한 echo는 문제 rule의 문법 토큰(≤128바이트, 한 줄 이스케이프) 3종(unknown action/auth_path/scope)뿐이다. `acl.toml`을 자동으로 만들지는 않는다(§4.1 #1 (b): interim allow-all-pinned 경계를 파일로 영구화하는 것은 의도치 않은 권한 확대다). 재시작 전 정책을 검증하려면 §6.15의 `qsh acl check`를 쓴다.
- **Admission 상한(M8).** 주소 검증되지 않은 Initial은 항상 `Retry`로 되돌려 보낸다(스푸핑 1패킷당
  상태 생성 차단) — 정상 클라이언트는 새 연결마다 왕복 1회를 더 지불하며, migration은 영향이 없다.
  `[serve].max_concurrent_handshakes`(기본 64)는 동시에 진행 중인 handshake 수의 상한이다.
  `[serve].handshake_rate_per_source`(기본 10/초)는 **주소 미검증 Initial에만** 적용되는 source당
  속도 상한이고, `[serve].validated_rate_per_source`(기본 10/초, M8 Step 3)는 **검증된**(Retry
  토큰 왕복을 마친) Initial에 적용되는 별개의 source당 속도 상한이다 — 검증을 통과해도 시도 속도
  자체는 통과 전과 같은 자릿수로 계속 제한된다(`docs/adr/0009-admission-defenses.md`의 한계
  절이 Step 3에 넘긴 항목). 두 속도 상한 모두 키는 동일하다(IPv4 /32, IPv6 /64) — 2초 window에서
  지속 10/초까지는 항상 통과하고, window 하나 안에 몰린 순간 burst는 최대 20건까지 받아준 뒤 그
  이상을 거부한다. 세 값 모두 `0`은 "무제한"이 아니라 "기본값"이며, 방어선을 끄는 설정은 없다.
  상한 초과는 자원 생성 전 거부이고, 클라이언트에게는 `CONNECTION_FAILED`(retryable)로 보인다 —
  handshake도, 세션도, task도 만들어지지 않는다. `retry_token_lifetime`(quinn 기본 15초)은 이
  방어선의 대상이 아니다 — 시도 *속도*를 제한하는 것은 이 rate limiter이지 토큰 수명이 아니다.
- 거부는 audit에 구조적으로만 남는다: `action="connect"`, `resource`는 `"rate_limited"`(주소
  미검증)·`"at_capacity"`(handshake 동시성 상한)·`"validated_rate_limited"`(검증된 Initial,
  source당) 중 하나, `principal`/`auth_path`는 `"-"`. 각 category 첫 행에 실리는 `peer_addr`는
  `rate_limited`의 경우 주소 검증 이전에 관측된 값이라 스푸핑 가능하다 — 상관관계 확인용일 뿐
  발신자 증명은 아니다(`validated_rate_limited`/`at_capacity`는 검증된 주소이므로 이 제약이 없다).
  `Retry` 발급 자체는 audit하지 않으며, 창(10초)당 category별 1행 + 요약 1행으로 집계된다 — flood가
  audit flood가 되지 않는다.
- **세션·exec quota(M8 Step 3, `docs/adr/0010-resource-quotas.md`).** `[serve].max_sessions`(기본
  256)는 전체 principal을 합친 live 세션 수의 전역 상한이고, `[serve].max_sessions_per_principal`(기본
  32)는 opener별 상한이며, `[serve].max_exec_per_principal`(기본 32)는 principal별로 동시에
  진행 중인(ticket 발급 시점부터 완료까지, redeem 여부와 무관) `exec.run` 상한이다. exec 쿼터는
  미상환 exec 티켓도 센다(티켓 TTL로 유계). 세 값 모두 `0`은
  "무제한"이 아니라 "기본값"이며 방어선을 끄는 설정은 없다. **ACL 판정이 quota보다 먼저다** — 인가되지
  않은 principal은 quota가 이미 포화돼 있어도 여전히 `PERMISSION_DENIED`를 보며, 그 응답만으로는 quota
  상태를 유추할 수 없다. 상한 초과는 자원(세션·child process) 생성 전 거부이고 클라이언트에게는
  `RESOURCE_EXHAUSTED`(`retryable: true`)로 보인다. 세션 quota는 살아 있는 세션 자체를 센다 — 세션이
  `session.close`나 attach 없는 TTL 만료로 broker registry에서 제거될 때까지 slot을 점유하며,
  attach 중이든 detach된 상태로 백그라운드에서 계속 실행 중이든 점유량은 같다(detach는 quota를
  풀어주지 않는다). 거부는 audit에 구조적으로만 남는다: `action`은
  `"session.open"`(세션 quota) 또는 `"exec.run"`(exec quota)이고, `resource`는
  `"quota_sessions_host"`(전역 세션)·`"quota_sessions_principal"`(principal별 세션)·
  `"quota_exec_principal"`(principal별 exec) 중 하나이며, admission과 동일하게 창(10초)당
  category별 1행 + 요약 1행으로 집계된다. 터널 스트림·remote forward listener·연결 자체의 상한은
  이 Step의 범위 밖이며 M8 Step 3b가 추가한다.

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

  같은 상수를 `qsh listen` 시작 배너, `README.md`의 "Known limitations", 그리고 이 절이 함께 소비한다 — 문안 정본이 여러 벌 생기지 않는다. `qsh doctor`(§6.17)도 `code: "controller_unreachable"`을 그대로 소비한다.
- `--bind`의 우선순위: CLI flag > `[listen].bind` > 기본값 `[::]:4433` — `qsh serve`(§6.12)와 **기본값이 같다**. 한 머신에서 두 역할을 겸하려면 명시적 `--bind`가 필요하고, 충돌은 조용한 오작동이 아니라 즉시·명시적 실패(stderr 진단 + exit `255`)다.
- **정책 파일 진단(M5).** `qsh serve`(§6.12)와 동일한 규율이다 — `qsh listen`/`qsh reverse` 둘 다 시작 시 `acl.toml`을 1회 읽고, 없거나 파싱 불가면 리소스를 생성하지 않으며 그 상태에서 도달하는 모든 인가 판정은 항상 `deny`다(`docs/design/architecture.md` §6, `PLAN.md` M5 §4.1 #1). 운영자에게는 stderr에 파일 경로, `CONFIG_ERROR` 코드, 최소 정책 예시를 담은 진단을 한 번 출력하고(§6.12와 같은 평문 블록 — `StartupDiagnostic::render`, tracing JSON 라인이 아니다), 자동 생성은 하지 않는다. `qsh listen`은 controller로서 `host.reverse` 등록 요청을, `qsh reverse`는 target으로서 그 연결 위에서 relay되는 세션 op을 각각 자기 자신의 `acl.toml`로 평가한다.
- 시작 시 실제로 bind된 주소와 등록 이벤트(`registered|denied|replaced|lost|expired|retry`)를 stderr에 구조화 진단(tracing target `qsh::reverse`, 한 줄 JSON, payload·토큰 field 없음)으로 출력한다 — stdout에는 §2.2 규칙에 따라 한 바이트도 쓰지 않는다.
- `qsh reverse <controller>`의 `<controller>`는 trust store alias다(§6.8의 host→주소 해석과 동일 — M7 이전에는 trust.toml pinned peer가 단일 출처). 등록에 성공하면 그 연결 위에서 host 역할로 동작하며, 서비스하는 세션은 `qsh serve`와 같은 broker·writer lease 규율을 그대로 따른다. **관찰 가능한 차이는 writer lease를 쥐는 connection이 상주 `qsh listen` 데몬이 유지하는 역방향 connection에 결합된다는 점이다** — 그 connection이 죽으면(재접속 루프가 새 connection을 세우기 전) lease는 forward 세션과 동일하게 자동 해제된다(architecture.md §3).
- `qsh listen`/`qsh reverse` 둘 다 Windows에서는 리소스를 생성하지 않고 `UNSUPPORTED` + exit `255`다 — localctl(UDS)과 host 역할(PTY)이 `cfg(unix)`이기 때문이다. Windows의 `qsh hosts`는 forward host만 반환하며(데몬 개념 없음) 오류가 아니다.
- 연결이 죽은 등록은 `state:"stale"`로 표시됐다가 `[listen].stale_retention`(기본 120s, `docs/design/protocol.md` §11-4)이 지나면 목록에서 제거된다.
- **Controller 측 writer lease 결합 (M3 Step 6).** live 역방향 등록으로 뜨는 host를 향한 controller 쪽의 `qsh session ...`(value op 6종: open/get/list/read/write/resize/close)는 그 명령을 실행한 CLI 프로세스 자신의 QUIC connection이 아니라, 상주 `qsh listen` 데몬이 target과 유지하는 그 **하나의** reverse connection을 `LOCAL_CONTROL` conduit(`docs/design/protocol.md` §11-3)으로 relay해서 나간다. **대화형 attach(`qsh <name>`/`qsh attach <name>/<id>`)도 M3 Step 7부터 이 경로를 탄다.** `Ops::session_attach`는 route-aware해졌다(`Ops::connect`로 host route를 먼저 resolve하고, 그 결과가 live 역방향 등록이면 forward의 `connect_target`이 아니라 이 §의 `LOCAL_CONTROL` conduit으로 향한다); ticket을 실제로 redeem하는 data 스트림도 이제 `LOCAL_STREAM` conduit(위 conduit 모델 문단, `docs/design/protocol.md` §11-3)로 역방향에서 열린다 — 데몬은 그 conduit 위에서 `LocalHello`/`LocalHelloAck` 교환 뒤 wire `StreamHeader{SESSION_DATA, ticket}`를 받아 host의 QUIC connection 위에 새 bidi stream을 열고 그 뒤로는 순수 byte splice로만 동작한다(SessionFrame을 파싱하지도, payload를 로그하지도 않는다). 아래 lease 결합 규칙은 지금 이 value op·stream op 양쪽 모두에 참이다: 위 항목의 "writer lease를 쥐는 connection이 데몬의 reverse connection에 결합된다"는 target 쪽 서술의 controller 쪽 대응이다 — target이 실제로 보는 유일한 connection은 데몬의 것이므로, **writer lease는 데몬의 connection에 묶이지, lease를 요청한 CLI 프로세스 자체에는 묶이지 않는다.** 그 CLI 프로세스가 죽어도(터미널 종료, `Ctrl-C`, 비정상 종료) 데몬의 reverse connection이 살아 있는 한 lease는 자동 해제되지 않는다 — forward 세션(§5, architecture.md §3)의 "소유 connection이 죽으면 lease가 자동 해제"라는 기대가 reverse 경로에서는 CLI 프로세스 단위가 아니라 데몬 connection 단위로 적용된다는 뜻이다. **동시 attach 격리.** 이 lease를 실제로 쥐는지 판정하는 identity는 물리 connection(`ctx.connection_id()`)이 아니라 그 attach가 redeem한 단발성 ticket에서 유도된다(`WriterLease::take_owned`) — 그렇지 않으면 한 데몬을 거치는 모든 local CLI가 같은 물리 connection을 공유하는 탓에 서로 다른 두 attach가 같은 identity로 오인되어 조용히 lease를 공동 소유하고 (`no_steal`이 걸려 있어도) 서로의 keystroke를 같은 PTY에 섞어 넣는다. 반면 `no_steal`이 충돌 여부를 판단하는 기준은 여전히 **principal뿐**이다(architecture.md §3(b)). reverse 경로에서 한 데몬을 relay로 쓰는 모든 local CLI 프로세스는 — 어느 프로세스가 열었든 — 항상 그 데몬의 reverse connection과 같은 controller principal로 인증되므로, "타 principal이 lease를 쥐고 있다"는 `no_steal` 충돌의 전제 자체가 reverse 경로 안에서는 성립하지 않는다(`session.write`가 opener 결합 때문에 이미 이 규칙을 재현할 수 없는 것과 같은 이유, 바로 위 architecture.md §3(b) 인용). 즉 죽은 CLI가 남긴 lease는 자동 해제되지 않지만, 다음 attach는 대화형이든 `no_steal`을 쓰는 자동화든 관계없이 항상 그 lease를 이어받는다 — `SESSION_CONFLICT`는 이 reverse 시나리오에서는 발생하지 않는다.
- **역방향 attach에는 아직 recovery/reconnect가 없다 (M3 Step 7).** Forward 경로의 attach는 connection이 끊겨도 (`docs/CLI.md` 이 절 밖의) 자동 재접속·resume 시도를 갖지만, `LOCAL_STREAM`/`LOCAL_CONTROL` conduit 위의 역방향 attach는 그 driver가 아직 없다 — 데몬의 reverse connection이나 conduit 자체가 죽으면 attach는 그 즉시 명확한 typed error로 끝난다(panic도, 무한 대기도 아니다). 세션 자체는 forward와 동일하게 살아남는다(broker가 쥐고 있고, connection 수명과 분리돼 있다 — architecture.md §3); 사용자가 다시 `qsh attach <name>/<id>`를 실행하면 데몬의 reverse connection이 살아 있는 한 정상적으로 재attach된다. 이 driver는 M3 Step 8에서 forward와 같은 `Reconnect` 추상 위에 통합될 예정이다.
- **Tunnel(`-R`)도 같은 결합을 따른다 (M4 Step 5 PR 5a).** 위 두 항목이 세션의 writer lease/attach에 대해 말하는 "데몬의 reverse connection에 결합된다"는 성질은 `-R`이 연 target 쪽 listener에도 그대로 적용된다 — §6.9·§6.14의 예외 문단이 다룬다.

### 6.14 Holder lifetime

터널의 local listener(`-L`) 또는 remote 등록(`-R`, host가 bind)은 그것을 연 CLI 프로세스가 살아 있는 동안만 존재한다 — 터널 전용의 별도 client daemon은 두지 않는다(M4 Step 1 결정): `qsh serve`/`qsh listen`(§6.12·§6.13)과 달리 터널은 그 자체로 장기 실행 모드가 아니라, 터널을 연 **interactive foreground 프로세스**(대화형 `qsh [user@]host -L …/-R …` 또는 foreground로 유지되는 `qsh tunnel open --json`)에 수명이 결합된다. (아래 reverse route `-R` 예외는 이 규칙을 어기지 않는다 — 새 daemon을 두는 것이 아니라, session op이 이미 §6.13에서 쓰는 **기존** `qsh listen` 데몬의 reverse connection을 carrier로 재사용할 뿐이다.) 그 프로세스가 끝나거나(Ctrl-C, 터미널 종료) 밑에 깔린 QUIC connection이 죽으면, 그 프로세스가 쥔 모든 터널이 함께 끝난다 — 진행 중이던 개별 TCP 연결은 끊기고, local listener/remote 등록 자체가 재수립 없이 사라진다(§7 대화형 attach의 세션과 달리, 터널 listener/등록은 connection 수명과 분리되지 않는다 — splice된 개별 TCP 연결의 생존 여부는 M4 이후 splice 구현 단계의 몫이다). 다시 쓰려면 새 `tunnel.open`이 필요하다.

**예외 — reverse route 위의 `-R`(M4 Step 5 PR 5a).** 위 규칙은 그 tunnel의 control 요청(`RemoteForwardOpen`)을 **어느 QUIC connection이 실어 날랐는가**를 홀더로 삼는다는 관찰로 다시 읽을 수 있다 — forward route에서는 CLI 프로세스가 직접 dial한 connection이 그것이므로 둘의 수명이 그냥 같다. reverse route에서는 다르다: CLI 프로세스는 QUIC connection을 전혀 쥐지 않고 상주 `qsh listen` 데몬의 `LOCAL_CONTROL` conduit(§6.13)으로 `RemoteForwardOpen`을 relay할 뿐이며, 실제로 그 요청을 나르는 것은 그 CLI가 아니라 **데몬이 유지하는 하나의 reverse connection**이다. target 쪽에서 그 listener를 실제로 등록해 두는 표는 `Server::remote_forwards`다(`crates/qsh-core/src/server/mod.rs`) — `forward_id`를 key로 하는 flat map이고, 각 항목은 그것을 연 **principal**(`RemoteForwardEntry::owner`)과 그것을 실어 나른 connection의 `conn_id`를 함께 기록한다(M5 Step 5, F5 adversarial review). 이 둘은 서로 다른 축이다: `tunnel.close`(`RemoteForwardClose`, 위 §6.9)로 **명시적으로 닫을 권한**은 owner principal 축이라 그 principal의 **어느 live connection**에서 요청해도 자신이 연 forward를 닫을 수 있다. 반면 connection이 **죽어서** 정리되는 경로는 지금도 `conn_id` 축이다 — `Server::purge_connection`이 그 connection이 연 forward를 통째로 걷어간다(purge). 그래서 아래에서 말하는 "이 connection이 살아 있는 동안"이라는 listener 수명 자체는 지금도 맞다(그 connection이 죽으면 listener도 함께 죽는다) — M5 Step 5가 더한 것은 "**다른** connection에서 닫을 권한이 있는가"가 connection이 아니라 principal로 판정된다는 축 하나뿐이다. 그래서 reverse route 위의 `-R`은 그것을 연 CLI 프로세스가 죽어도(Ctrl-C, 터미널 종료) target의 listener는 살아남는다 — 죽는 것은 reverse connection 자체가 끊어질 때뿐이다(`docs/design/protocol.md` §11-3의 `forward_id`→conduit 등록표 문단). 다만 그 CLI가 지녔던 `LOCAL_STREAM` claim conduit도 함께 죽으므로, target이 그 뒤 여는 `TCP_ACCEPTED`는 데몬에서 받을 conduit이 없어 즉시 reset된다 — listener는 살아 있지만 그 accept를 로컬 목적지로 이어줄 소비자가 없는 상태이며, 이 상태를 해소하려면(=다시 claim하려면) 새 `tunnel.open`으로 같은 `forward_id`를 재등록하는 op이 필요하다 — 그런 op은 아직 없다(M4 Step 5 PR 5b가 실제로 구현한 것은 이것이 아니다: `PLAN.md`의 PR 5b 범위 목록은 이 재등록 op을 포함하지 않았고, 구현하려면 `RemoteForwardOpen`이 기존 `forward_id`를 받아들이는 새 wire 의미가 필요해 범위 밖이었다 — P1 백로그). PR 5b가 실제로 제공하는 유일한 회복 경로는 `qsh tunnel close <id>`(§6.9)로 등록 자체를 닫아 target의 listener까지 해제하고, 새 `forward_id`로 처음부터 `-R`을 다시 여는 것뿐이다 — 같은 포트를 재사용하려는 claim conduit 재수립은 아니다. `-L`은 이 예외에 해당하지 않는다 — reverse route에서도 local listener(bind)는 여전히 그것을 연 CLI 프로세스 자신의 소켓이고, 데몬은 그 위를 오가는 개별 `TCP_CONNECT` 스트림의 carrier일 뿐 listener의 홀더가 아니다.

### 6.15 `qsh acl check` (M5)

```bash
qsh acl check --principal <principal> --action <action> [--resource <resource>] [--auth-path pin|ca] [--owner <principal>] [--owner-auth-path pin|ca] --json
```

`acl.check`는 §2.4·§2.5가 명시하듯 **로컬 operation**이다 — 원격 peer가 요청할 수 없고, 이 머신 자신의 `acl.toml`을 이 머신에서 조회한다. 원격으로 정책 조회를 허용하면 그 자체가 capability 열거 oracle이 되기 때문이다(`docs/ROADMAP.md` M5 감사 개정 ③). `qsh serve`/`qsh listen`/`qsh reverse`가 실제로 강제하는 것과 **같은 평가기**를 호출하므로(`PLAN.md` M5 DoD 1), 이 명령의 결과는 실제 enforcement 결과의 신뢰할 수 있는 예측이다 — 재시작 전 정책을 검증하는 용도(§6.12·§6.13의 정책 파일 진단 문단)로 쓴다. 이 예측에는 한계가 둘 있다. `policy.loaded: false`는 파일이 아예 없는 경우와 파싱에 실패한 경우를 구별하지 않으며, 파싱 실패의 상세(어떤 rule의 어떤 토큰이 문제였는지)는 `acl check`가 아니라 §6.12·§6.13의 시작 진단이 정본이다 — `acl check` 자신은 그 상세를 출력하지 않는다. 그리고 enforcement에는 이 평가기 위에 fail-closed 층이 하나 더 있어서, audit 기록 자체가 실패하면 `allow` 판정이 `deny`로 뒤집히고 세션 소유자 조회가 실패해도 `deny`로 처리된다(`crates/qsh-core/src/server/mod.rs`) — 그래서 `acl check`의 `allow` 예측은 실제 운영 상태에 따라 `deny`로 뒤집힐 수 있지만, `deny` 예측이 `allow`로 뒤집히는 일은 없다.

인자:

- `--principal <principal>` (필수): 평가할 principal 문자열(`device:<name>` | `user:<name>` | `fp:sha256:<base64>`, `docs/PRD.md` §9). 모양이 셋 중 어느 것과도 맞지 않으면 `INVALID_ARGUMENT`.
- `--action <action>` (필수): PRD §9의 11종 action 중 하나(닷 표기, 예 `session.open`). 어휘에 없는 값은 `INVALID_ARGUMENT`(정책 로더가 잘못된 wildcard 패턴을 거부하는 것과 같은 층 — 오타가 조용히 통과하지 않는다).
- `--resource <resource>` (선택): action이 겨냥하는 리소스 식별자. 생략하면 리소스 개념이 없는 action으로 평가한다.
- `--auth-path <pin|ca>` (선택): 생략 시 `acl.toml` 자체의 기본값(`"pin"`, `PLAN.md` M5 §4.1 #2)을 적용한 것과 동일하게 평가한다.
- `--owner <principal>` (선택, M5 Step 7 — additive): `--resource`의 소유자 principal. `scope = "owned"`(rule의 기본값) 행이 실제로 적용되려면 소유자가 있어야 하므로, `--owner` 없이는 그런 행이 항상 "소유자 없는 리소스"로 평가되어 무조건 통과한다 — enforcement가 소유자를 아는 상황(예: 이미 열린 세션에 대한 `session.control`)을 재현하려면 필요하다. 생략하면 이전과 동일하게 `--resource`를 소유자 없는 리소스로 평가한다.
- `--owner-auth-path <pin|ca>` (선택, `--owner`와 함께일 때만 의미 있음): `--owner`가 인증했다고 가정할 auth path. 생략 시 `"pin"`. 접힘은 enforcement가 실제로 쓰는 프로덕션 `opener_key`(`crates/qsh-core/src/acl/mod.rs`)를 그대로 호출해 만들며, 그 내부 인코딩은 CLI 표면이나 계약에 절대 노출되지 않는다 — `--owner`/`--owner-auth-path`는 그 인코딩 이전의 평문 principal/auth-path 문자열이다. `--owner` 없이 `--owner-auth-path`만 단독으로 주는 것은 clap이 usage 오류로 거부한다(exit `2`) — `--escape-char`/`-L`이 `target` 없이는 거부되는 것(§7)과 같은 `requires` 관계다.

`data`는 `AclCheckData`(`crates/qsh-proto/src/types.rs`)다:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "acl.check",
  "ok": true,
  "data": {
    "principal": "user:dave",
    "action": "exec.run",
    "resource": "exec",
    "auth_path": "pin",
    "decision": "allow",
    "rule": 0,
    "policy": {
      "path": "/Users/dave/.config/qsh/acl.toml",
      "rules": 2,
      "loaded": true
    }
  }
}
```

`decision`은 `Host.connection_mode`와 같은 열린 문자열 규율(§10)로 `"allow"`/`"deny"`다. `rule`은 매칭된 정책 행의 배열 index이며, 아무 행도 매칭하지 않았거나(항상 `"deny"`를 동반) 정책이 로드되지 않은 경우 `null`이 아니라 필드 자체가 나타나지 않는다(`owner`/`owner_auth_path` 생략과 같은 규율 — `qsh.cli/v1`은 additive-only, `CLAUDE.md`). `policy.loaded: false`는 `acl.toml`이 없거나 파싱에 실패한 상태를 그대로 보여준다 — 그 상태에서는 `decision`이 항상 `"deny"`다(§6.12·§6.13의 정책 파일 진단, `PLAN.md` M5 §4.1 #1). `qsh acl check`는 이 상태를 오류로 만들지 않는다 — 조회는 성공했고(`ok: true`), 다만 조회된 사실이 "정책 없음"일 뿐이다. `owner`/`owner_auth_path`(M5 Step 7 — additive)는 `--owner`/`--owner-auth-path`를 그대로 echo하며, 둘 다 생략됐을 때는 필드 자체가 나타나지 않는다(`qsh.cli/v1`은 additive-only, `CLAUDE.md`).

`--principal`/`--action`이 잘못된 모양이 아닌 한 `acl.check` 자체는 실패하지 않는다(exit `0`, §4). human mode 출력은 한 줄 요약(`allow`/`deny` + 근거 rule index 또는 "no policy loaded")이다.

### 6.16 `qsh cert` — private CA (M7 Step 5)

```bash
qsh cert init --json
qsh cert issue --json
```

이 device를 자기 자신의 private CA로 만드는 두 명령이다([ADR-0008](adr/0008-private-ca-cert-issuance.md)). intermediate 없이 self-signed root 하나가 device leaf를 직접 서명하는 구조이며, `qsh trust add`/`trust accept`(§6.11)가 다루는 "각 device를 개별로 pin"하는 모델과는 별도의, 병행 가능한 신뢰 축이다 — 한 device가 어느 CA의 root를 신뢰하면 그 CA가 서명한 모든 device를 개별 pin 없이 신뢰한다.

`cert.init`은 `<config_dir>/ca/`(0700)에 `ca.pem`(root 인증서)과 `ca.key`(PKCS#8 PEM private key, 0600)를 생성한다. `identity/`(§6.11의 device identity)와 의도적으로 분리된 디렉터리다 — 이 device가 *서명할 수 있는지*는 이 device *자신이 누구인지*와 다른 threat이기 때문이다. 이미 root가 있으면 새로 만들지 않고 기존 root를 `created: false`로 반환한다(멱등).

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "cert.init",
  "ok": true,
  "data": {
    "fingerprint": "sha256:BASE64FINGERPRINT",
    "config_dir": "/Users/dave/.config/qsh",
    "created": true
  }
}
```

`cert.issue`는 이 device의 **로컬 identity만**을 발급 대상으로 한다(ADR §5 — 다른 device나 user cert 발급은 범위 밖, P1) — 이미 있는 device identity(`qsh init`으로 만든 keypair·`device_id`)를 CA로 "승격"한다: 같은 keypair, 같은 `qsh://device/<device_id>` SAN을 CA 서명으로 다시 감싸 `identity/device.pem`을 그 자리에서 교체한다. keypair가 그대로이므로 이 device를 이미 fingerprint로 pin해 둔 다른 peer가 있어도 그 pin은 깨지지 않는다 — fingerprint는 인증서 전체가 아니라 SPKI(공개키)에서만 계산되기 때문이다(architecture.md §5). CA root는 `trust.toml [[ca]]`에 이름 `"local"`로 등록된다(`qsh trust add`와 같은 append-only·dedup 선례 — Step 2).

`qsh init`(§6.11)을 먼저 실행하지 않았거나 `qsh cert init`을 먼저 실행하지 않았으면, 어느 쪽도 조용히 만들어 주지 않고 `CONFIG_ERROR`로 실패한다 — 어느 리소스도 그 전제조건이 충족되기 전에 만들어지지 않는다(§11의 원칙).

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "cert.issue",
  "ok": true,
  "data": {
    "device_id": "device_01K0EXAMPLE",
    "fingerprint": "sha256:BASE64FINGERPRINT",
    "issued": true,
    "ca": {
      "name": "local",
      "fingerprint": "sha256:BASE64FINGERPRINT",
      "created": true
    }
  }
}
```

`cert.issue`는 두 축이 각각 독립적으로 멱등이다. leaf 재발급 축은 `issued`로 나타난다 — 이미 이 CA가 발급한 leaf라면 다시 서명하지 않고 `issued: false`를 반환한다(`fingerprint`는 이전 호출과 동일). `trust.toml [[ca]]` 등록 축은 `ca.created`/`ca.updated`로 나타나며, `trust.add`(§6.11)와 정확히 같은 모양이다 — 새 이름이면 `created: true`(이때 `updated`는 필드 자체가 생략된다), 이미 등록된 이름에 같은 root PEM이면 순수 no-op(`created: false, updated: false`), 같은 이름에 root가 달라졌으면(로컬 CA를 지우고 다시 `cert init`한 경우뿐이다) `updated: true`로 그 자리에서 덮어쓴다.

**partner의 CA root를 신뢰하려면.** `qsh cert`는 이 device 자신의 CA만 다룬다 — 상대 device가 발급한 CA root를 이 device의 `trust.toml`에 등록하는 op은 아직 없다(ADR §5, out-of-band로 상대의 `ca.pem`을 전달받아 `trust.toml`의 `[[ca]]` 표에 직접 적어 넣는 것이 M7 시점의 유일한 경로다). `trust.toml` 자체는 `qsh cert`가 만들었든 operator가 손으로 적었든 구분 없이 평가한다(trust/mod.rs).

**`acl.toml` 작성 시 주의.** CA로 인증한 principal을 허용하려는 `[[acl]]` 행은 `auth_path = "ca"`를 **명시**해야 한다 — 이 field를 생략하면 `"pin"`으로 기본값이 매겨져(§6.15의 `--auth-path` 문단과 같은 기본값, `PLAN.md` M5 §4.1 #2) CA로만 인증한 peer는 그 행에 조용히 매칭되지 않는다(default-deny이므로 결과는 `PERMISSION_DENIED`).

pin(`AuthPath::Pin`)과 CA(`AuthPath::Ca`) 양쪽 모두 principal은 똑같이 `device:<id>` 모양이다 — 구별의 근거는 principal이 아니라 audit 기록의 `auth_path`뿐이다(ADR §6).

### 6.17 `qsh doctor` — 배포 진단 (M7 Step 6)

```bash
qsh doctor [host] --json
```

`doctor.run`은 §2.4·§2.5가 이미 예약해 둔 대로 **로컬 operation**이다 — 원격 peer가 요청할 수 없고, 이 머신 자신의 identity·ACL 정책·audit 로그·trust store·시계·(best-effort) 네트워크 도달성을 조회해 하나의 report로 묶는다. 인자 없는 `qsh doctor`는 `[reverse].controller`가 설정돼 있으면 그 연결성만 점검하고, `qsh doctor <host>`는 그 pinned host를 추가로 점검한다 — `qsh capabilities [host]`(§6.10)와 같은 UX 형태다.

**exit code는 항상 `0`이다 — finding은 data이지 실패가 아니다.** `qsh acl check`(§6.15, L845)의 선례를 그대로 확장한다: `deny`나 "정책 없음"조차 `acl check` 자체를 실패로 만들지 않듯, `doctor.run`도 아무리 심각한 finding이 나와도 조회 자체는 성공이다(`ok: true`). 건강도는 `data.overall`이 담는다. `doctor.run`이 `Err`(exit `255`)로 실패하는 경우는 doctor 자신이 조회를 시작할 조건조차 없을 때뿐이다 — 대표적으로 `qsh init`을 아직 실행하지 않아 device identity가 없는 경우, 또는 `config.toml`/`hosts.toml`/`trust.toml`이 파싱조차 되지 않는 경우(각 로더가 이미 `CONFIG_ERROR`로 잡는다 — doctor가 별도 code로 다시 잡지 않는다). output mode에 따라 이 규칙이 달라지지 않는다(§4).

`data`는 `DoctorData`(`crates/qsh-proto/src/types.rs`)다:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "doctor.run",
  "ok": true,
  "data": {
    "overall": "warn",
    "findings": [
      {
        "code": "cert_expiring_soon",
        "status": "warn",
        "detail": "A certificate this device relies on expires within 30 days. (this device's own leaf certificate, not_after unix: 1780000000)",
        "remedy": "`qsh cert issue` only re-issues a leaf this CA has not signed yet; on one it already signed, or on the CA root, it and `qsh cert init` are no-ops. Renew ahead of the deadline by removing `identity/` or `ca/` from the config directory and re-running `qsh init`/`qsh cert init` — peers must then re-pin."
      },
      {
        "code": "trust_remove_scope",
        "status": "info",
        "detail": "trust.toml has at least one pinned peer. `qsh trust remove` only takes effect starting with that peer's next handshake — an already-established connection keeps its entire negotiated authority (including opening brand-new sessions, tunnels and forwards) until that connection drops and has to handshake again.",
        "remedy": "Force-closing an already-established connection on removal is not implemented (P1). If that matters right now, restart the process holding the connection."
      }
    ]
  }
}
```

`overall`은 `Host.connection_mode`와 같은 열린 문자열 규율(§10)로 `"ok"`/`"warn"`/`"error"`다 — `findings` 중 가장 심각한 `status`를 반영한다(`"error"` > `"warn"` > 그 외 `"ok"`). `"info"`만 있거나 `findings`가 비어 있으면 `"ok"`다. `overall`은 개별 finding에는 원칙적으로 나타나지 않는다 — 통과한 점검은 finding 자체를 만들지 않으므로("findings 모델": 재사용 상수 3종이 전부 실패-명명 문자열이라, 통과까지 담으려면 별도 subject-code 어휘가 이중으로 필요해진다), 통과 가시성은 `overall`과 human 렌더의 요약 줄로 얻는다.

`findings`의 각 원소(`DoctorFinding`)는 다음 field를 갖는다:

- `code`: 아래 표의 잠금 어휘(snake_case) 중 하나. shipped 후 **추가만** 가능하다 — 삭제·의미 변경은 `qsh.cli/v1` 위반이라 `/v2`가 필요하다(§10 additive-only 규율).
- `status`: `"warn"`/`"error"`/`"info"` 중 하나 — `"ok"`는 여기 나타나지 않는다.
- `detail`: 무엇이 관측됐는지에 대한 사람이 읽을 수 있는 설명(해석된 경로, 관측된 만료 시각 등). 시크릿·PTY/명령 payload는 절대 담지 않는다(`CLAUDE.md`의 보안 기본값).
- `remedy`: 실행 가능한 다음 행동 한 줄. 없으면 필드 자체가 생략된다(additive-optional, `CapabilitiesData.host`와 같은 규율).

**13종 진단 코드** (재사용 5종·신설 8종 — `PLAN.md` M7 §4.1 #5가 확정한 잠금 어휘):

| `code` | `status` | 무엇을 점검하는가 |
|---|---|---|
| `controller_unreachable` | error | `[reverse].controller`가 설정돼 있으면 그 dial이 실패 — reverse는 relay·NAT traversal이 없다(M3 out-of-scope, §6.13). 문면은 `qsh_core::doctor::CONTROLLER_UNREACHABLE`을 그대로 재사용한다(§6.13과 동일 정본) |
| `udp_egress_blocked` | error | `host` 인자로 준 일반 대상으로의 raw UDP probe가 응답 없이 침묵 타임아웃 — 방화벽이 UDP를 막고 있을 가능성. QSH는 TCP fallback이 없다(P1, ADR-0005) |
| `no_route` | error | 일반 대상으로의 probe가 OS 레벨에서 즉시 거부됨(경로 자체가 없음) — 침묵 타임아웃(`udp_egress_blocked`)과 구분된다 |
| `peer_untrusted` | error | `hosts.toml`이 이름을 알지만 `trust.toml`에 그 이름의 pin이 없음 — 그 이름으로 연결하면 `TRUST_REQUIRED`로 실패할 운명이다(정적 교차대조, 위양성 없음) |
| `cert_expired` | error | device leaf(`identity/device.pem`) 또는 CA root(`ca/ca.pem`)의 `not_after`가 이미 지났음 — `detail`이 어느 쪽인지 밝힌다 |
| `cert_expiring_soon` | warn | 같은 인증서의 `not_after`가 30일 이내(만료 전)임 — `cert_expired`와 같은 인증서에 대해 상호배타 |
| `keystore_unavailable` | warn | 플랫폼 키스토어(macOS Keychain / Linux Secret Service)에 도달 불가 — 이미 file store(0600)로 정상 동작 중이므로 기능에는 지장 없음(read-only probe, 실제 키 저장소를 바꾸지 않는다) |
| `clock_skew` | warn 또는 error | 로컬 시계가 device cert의 backdated `not_before`보다 과거 — `qsh init` 시 준 5분 backdate 여유(`CERT_BACKDATE_MINUTES`)를 넘으면 error, 그 안이면 warn |
| `audit_path_unwritable` | error | 설정된 `[audit].path`를 append로 열 수 없음 — fail-closed로 privileged operation(`session.open`/`exec.run`/`host.reverse`)이 전부 거부되는 상태. 문면은 `qsh_core::doctor::AUDIT_PATH_UNWRITABLE`을 재사용한다 |
| `acl_policy_missing` | error | `acl.toml`이 없음 — `qsh serve`/`qsh listen`(§6.12·§6.13)의 시작 진단과 같은 검사·같은 code(`ACL_POLICY_MISSING_CODE`)를 재사용한다. default-deny로 모든 요청이 거부되는 상태 |
| `acl_policy_invalid` | error | `acl.toml`이 있지만 파싱/검증에 실패함 — 같은 시작 진단(`ACL_POLICY_INVALID_CODE`)을 재사용한다. `detail`이 시작 진단과 같은 banner(경로·오류 코드·오류 상세·예시)를 담는다 |
| `qsh_path_shadowed` | warn | `$PATH`에서 지금 실행 중인 바이너리(`current_exe`)보다 앞서는 다른 `qsh` 실행파일이 있음 — 맨몸 `qsh`를 실행하면 그 다른 바이너리가 대신 뜬다 |
| `trust_remove_scope` | info | `trust.toml`에 pin이 하나라도 있으면 상시 노출되는 고지 — `trust remove`의 유효 범위(§6.11)를 다시 알려준다: 제거는 다음 handshake부터만 적용되고, 이미 확립된 연결은 협상된 권한 전체를 연결이 끊길 때까지 유지한다 |

**연결성 진단의 우선순위 규칙.** 한 probe 실패는 항상 code 하나만 낸다: probe 대상이 `[reverse].controller`면 결과와 무관하게 `controller_unreachable`이고, `host` 인자로 준 일반 대상이면 침묵 타임아웃은 `udp_egress_blocked`, OS의 즉시 거부(경로 없음)는 `no_route`다 — 세 code가 한 실패에 동시에 나오는 일은 없다.

**`--fail-on` 플래그는 아직 없다.** severity 임계값 이상일 때 CI 게이트용 nonzero exit을 내는 옵션은 향후 additive 확장 후보이며, 지금은 구현하지 않는다 — 위 exit code 문단대로 지금은 findings의 존재와 무관하게 항상 `0`이다.

## 7. Human interactive mode

다음 명령은 위의 session operation을 조합한 편의 인터페이스다.

```bash
qsh dave@personal-mac
qsh attach <session-ref>
qsh personal-mac -L 8080:localhost:3000
qsh personal-mac -R 9000:localhost:9000
```

Interactive mode는 terminal raw mode, window resize와 signal forwarding을 처리한다. 세션 생성·읽기·쓰기의 권한과 동작은 machine-readable command와 동일하다.

**Machine output mode가 없다.** 이 두 form의 stdout은 원격 터미널의 byte 그 자체이므로(§2.2) envelope가 들어갈 자리가 없다 — `qsh serve`(§6.12)와 같은 이유로 예외다. `--json`/`--jsonl`을 붙이면 **세션을 만들기 전에** `INVALID_ARGUMENT` error envelope 한 줄과 exit `255`(§4)로 거부한다. 기계 소비자는 같은 일을 `qsh session open --json` + `qsh session read --follow --jsonl` + `qsh session write`로 조합한다(§7.1).

**전달되는 환경변수.** 대화형 form은 로컬 터미널을 재현하는 데 필요한 것만 보낸다: `TERM`은 `SessionOpen.term`으로, locale(`LANG`, `LANGUAGE`, `LC_ALL`, `LC_CTYPE`, `LC_COLLATE`) 중 클라이언트 프로세스에 설정된 것은 `SessionOpen.env` overlay로 전달한다(architecture.md §4). 이는 **대화형 form 한정** 동작이다 — `qsh session open`·`qsh exec`·MCP는 호출자가 명시한 `--env`만 보내며, 클라이언트 프로세스의 환경을 암묵적으로 상속시키지 않는다. `HOME`/`USER`/`LOGNAME`/`SHELL`/`PATH`는 어느 경로에서도 호스트가 고정한다.

**`user@`의 의미.** 원격 셸은 항상 **`qsh serve`를 실행한 OS 계정**으로 실행된다 — MVP에는 user switching이 없고, ACL principal은 항상 인증서에서 나온다(§2.5, protocol.md §3). `user@`는 SSH 근육 기억을 위해 받아들이며 생략해도 된다(`qsh personal-mac`). 지정하면 `SessionOpen`에 선택 hint로 전달되고, 호스트는 그 값이 serve 계정의 login name과 다르면 세션을 만들지 않고 `UNSUPPORTED`(message: user switching is not supported)로 거부한다 — fail closed. 즉 `user@`는 "이 계정이어야 한다"는 단언이지 계정 선택이 아니다(PRD §6). 검사 순서는 **ACL `session.open` → `user` hint → spawn**이다: 인가되지 않은 peer는 hint 값과 무관하게 항상 `PERMISSION_DENIED`를 받고(계정명 비노출, audit는 ACL 판정만 기록), `UNSUPPORTED`는 인가된 peer에게만 반환된다. 비교는 serve 계정의 login name과 정확 일치(case-sensitive)다. `user@`는 `qsh [user@]host` 형태(`-L`/`-R` 플래그를 동반한 경우 포함 — 모두 `SessionOpen`을 보낸다)에서만 받으며, `qsh exec`/`qsh session open`/`qsh tunnel open`은 bare host만 받는다.

**`hosts.toml`의 `user` 기본값 (M7 Step 3).** `user@`를 명시하지 않았고 그 host 이름에 `hosts.toml`이 `user`를 설정해 뒀다면 그 값이 hint로 채워진다 — ssh_config의 `User` directive와 같은 위치의 편의 기능이다. 명시적으로 준 `user@`가 있으면 그것이 항상 이긴다(`hosts.toml`의 값은 덮어쓰지 않는다). 이 기본값 채움은 `qsh [user@]host`뿐 아니라 `qsh session open`·MCP를 포함해 `SessionOpen`을 보내는 모든 경로에 동일하게 적용된다 — 위 문단의 검사(ACL → user hint → spawn, 불일치 시 `UNSUPPORTED`)는 hint의 출처가 명시값이든 `hosts.toml` 기본값이든 완전히 동일하게 작동한다.

**`-L`/`-R`은 이 대화형 form의 companion flag이지 별도 명령이 아니다.** `qsh [user@]host -L …`/`-R …`는 여전히 대화형 셸을 여는 `qsh [user@]host` 그 자체이며 — 위 문단대로 `SessionOpen`을 보내고 §4의 exit code 규칙을 그대로 따르는 실제 interactive 세션이 열린다 — 거기에 하나 이상의 터널(§6.9)이 **곁들여** 열릴 뿐이다. `-L`/`-R`이 세션 없이 터널만 여는 경로는 없다: 터널만 필요하고 셸은 필요 없으면 machine-mode `qsh tunnel open --json`(§6.9)을 쓴다 — 이쪽은 `SessionOpen`을 전혀 보내지 않고 `tunnel.open` 하나만 나간다. 두 경로 모두 홀더는 그 명령을 실행한 foreground CLI 프로세스다(§6.14).

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

`tunnel.open`(§6.9)은 이 분류에서 value operation이다 — envelope은 터널이 열렸다는 사실과 메타데이터(`Tunnel`)만 한 번 반환하고 즉시 끝난다. 터널을 오가는 실제 TCP payload는 JSON envelope 층에 전혀 노출되지 않는 wire-level data 스트림(`TCP_CONNECT`/`TCP_ACCEPTED`, protocol.md §7·§9)이며, `session.attach`와 달리 이 문서의 stream operation 개념에 속하지 않는다 — 이 streaming byte channel은 `qsh-core`가 로컬 TCP 연결과 host 사이에서 직접 splice하고, CLI operation 계층은 그 존재를 모른다.

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

**어떤 op이 tool이 되는가.** 원격 host의 상태를 바꾸거나 조회하는 op만 tool로 낸다. 두 부류가 빠진다.

첫째, 이 기계의 로컬 상태를 읽거나 쓰는 op — `identity.init`, `trust.*`, `cert.*`, `doctor.run`, `acl.check`. `host.list`와 `host.get`이 §2.5에서 `acl.check`와 같은 "인가 불요" 행에 있으면서도 앞의 둘만 tool인 이유가 이것이다: 앞의 둘은 도달 가능한 원격 host를 답하고, 뒤는 이 기계의 파일 내용을 답한다.

이 부류의 경계는 §2.5의 행이 아니라 "답이 어느 기계의 사실인가"다. `tunnel.close`(=`close_tunnel`)와 `tunnel.list`는 §2.5에서 한 행에 있지만 앞의 것만 tool이다 — `tunnel.close`는 host 쪽 소유권 검사를 거쳐 원격의 forward를 닫지만, `tunnel.list`는 이 기계의 상주 `qsh listen` daemon이 쥔 hold를 답한다(§6.9). `session.attach`는 아예 다른 이유로 빠진다: value operation이 아니라 stream operation이라(§7.1) value tool 표면에 애초에 후보가 아니다.

둘째, wire contract 자체를 기술하는 introspection op — `schema.get`, `capabilities.get`, `version.get`. `capabilities.get`은 host를 주면 실제로 그 peer와 negotiation한 결과를 답하므로(§6.10) 첫째 기준으로는 걸러지지 않지만, 그 답은 host의 상태가 아니라 두 build 사이의 protocol 합의다 — 에이전트는 그 합의를 이미 tool schema 형태로 받아 들고 있고, 자기가 부를 수 있는 tool 목록보다 더 많은 것을 negotiation 결과에서 알아낼 수 없다. 이 셋은 사람이 버전 불일치를 진단할 때 쓰는 CLI 표면으로 남는다.

`acl.check`를 tool로 내지 않기로 한 결정(M7)의 근거는 정보 노출이 아니라 **정확성**이다. `acl.check`는 호출자 로컬의 `acl.toml`을 평가한다(§6.15). 에이전트가 알고 싶은 것은 "저 host가 나를 허용하는가"인데, 클라이언트 쪽에 `acl.toml`이 없는 정상 배치에서 이 op의 답은 `policy.loaded: false`와 무조건 `deny`다. 에이전트는 이것을 "그 작업은 불가능하다"로 읽는다. 게다가 tool 표면에는 에이전트가 자기 principal을 알아낼 방법이 없다 — `get_host`의 `device_id`는 상대 peer의 신원이다. 로컬 정책을 확인하려면 사람이 `qsh acl check`를 직접 실행한다.

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
- MCP 취소의 실제 동작은 해당 요청의 응답 전달 중단이다: MCP server는 취소된 요청에 응답을 보내지 않을 뿐, session·PTY·writer lease는 그대로 유지된다. server 내부에 남은 대기는 host의 wait clamp까지 자연 소멸하며, 그 결과는 어느 client에서도 관측되지 않는다.

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

