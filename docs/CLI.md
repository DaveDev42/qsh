# QSH CLI, JSON and MCP Contract

**상태:** Draft v0.4 (M1 구현과 동기화)  
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

향후 예약: streaming file copy → `file.read`/`file.write`, SOCKS(`-D`) → `forward.socks`, 역방향 host 등록 → `host.reverse`.

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

오류 코드는 추가될 수 있다. 알 수 없는 code는 일반 QSH 오류로 처리한다. `UNSUPPORTED`는 요청한 기능이 아직 구현되지 않았거나 peer와 협상되지 않은 경우(예: P1 기능인 `-D`/SOCKS)에 사용한다. `RESOURCE_EXHAUSTED`는 backpressure나 서버측 한도 초과를 나타낸다.

## 4. Process exit code

일반 명령:

| Code | 의미 |
|---|---|
| `0` | QSH operation 성공 |
| `2` | CLI syntax 또는 argument 오류 |
| `255` | 연결, 인증, 정책 등 QSH runtime 실패 |

`qsh exec`는 OpenSSH와 마찬가지로 remote process의 exit code `0..254`를 그대로 반환한다. QSH 자체의 실패는 `255`다. JSON 결과에는 `remote_exit_code`와 QSH 오류가 구분되어 있으므로 자동화는 stdout JSON도 함께 확인한다.

Remote process가 정확히 `255`로 종료한 경우, QSH 자체 실패(`255`)와 구분할 수 없게 되는 것을 막기 위해 qsh exec의 프로세스 exit code는 `254`로 clamp된다. 이때도 JSON 결과의 `remote_exit_code`는 실제 값(`255`)을 그대로 담으며, exit code의 source of truth는 항상 JSON이다.

Output mode에 따라 exit code 의미가 달라져서는 안 된다.

## 5. 핵심 data type

### Host

```json
{
  "name": "personal-mac",
  "address": "personal-mac.example.com:4433",
  "connection_mode": "forward",
  "state": "reachable",
  "device_id": "device_01K0EXAMPLE"
}
```

### Session

```json
{
  "session_ref": "personal-mac/01K0SESSION",
  "host": "personal-mac",
  "session_id": "01K0SESSION",
  "state": "running",
  "writer": "device_01K0EXAMPLE",
  "created_at": "2026-08-17T00:00:00Z",
  "last_sequence": 42
}
```

`session_ref`는 CLI가 반환하는 opaque value다. 호출자가 host와 session ID를 조합해 생성하지 않는다.

`last_sequence`는 chunk 개수가 아니라 이 세션에서 지금까지 누적된 output byte 수(offset)다. `session read --after`에 그대로 전달할 수 있다.

## 6. 명령 계약

### 6.1 Host 조회

```bash
qsh hosts --json
qsh host get personal-mac --json
```

`hosts`는 설정된 forward host와 현재 연결된 reverse host를 함께 반환한다.

### 6.2 Session 조회

```bash
qsh sessions [host] --json
qsh session get <session-ref> --json
```

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

### 6.4 Session 읽기

```bash
qsh session read <session-ref> --after 42 --wait 30000 --json
qsh session read <session-ref> --after 42 --follow --jsonl
```

- `--after`: 마지막으로 수신한 누적 output byte offset (sequence)
- `--wait`: 새 output을 기다릴 최대 milliseconds
- `--follow`: 종료나 취소까지 event를 계속 출력
- `--limit-bytes`: 한 응답의 최대 payload

단일 JSON 응답은 event 배열을 반환한다. `--follow --jsonl`은 event 하나당 한 줄을 출력한다.

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

### 6.5 Session 쓰기

```bash
printf 'continue\n' | qsh session write <session-ref> --stdin --json
qsh session write <session-ref> --data-b64 Yw== --json
```

`--stdin`과 `--data-b64`는 상호 배타적이다. 전자는 raw stdin bytes, 후자는 명시적인 Base64 bytes를 전송한다.

### 6.6 Terminal resize

```bash
qsh session resize <session-ref> --cols 120 --rows 40 --json
```

### 6.7 Session 종료

```bash
qsh session close <session-ref> --json
qsh session close <session-ref> --signal TERM --json
```

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

일회용 invite code pairing(`qsh trust invite` 계열, ADR-0002)의 CLI 계약은 M7에서 확정한다. `doctor.run`은 operation 이름만 예약되어 있으며 계약은 M7에서 확정한다.

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

## 7. Human interactive mode

다음 명령은 위의 session operation을 조합한 편의 인터페이스다.

```bash
qsh dave@personal-mac
qsh attach <session-ref>
```

Interactive mode는 terminal raw mode, window resize와 signal forwarding을 처리한다. 세션 생성·읽기·쓰기의 권한과 동작은 machine-readable command와 동일하다.

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

Agent는 반환된 마지막 sequence를 다음 cursor로 사용한다. 이 long-poll model은 다양한 MCP client에서 동일하게 동작한다.

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
- Interactive attach의 SIGINT는 기본적으로 remote PTY로 전달하며, detach key는 별도로 제공한다.
- MCP cancellation은 local wait 또는 request를 취소하고 session lifecycle을 변경하지 않는다.

## 10. Compatibility policy

- `qsh.cli/v1`과 `qsh.event/v1`에는 optional field를 추가할 수 있다.
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

