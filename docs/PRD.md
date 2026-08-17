# QSH Product Requirements Document

**상태:** Draft v0.2  
**작성일:** 2026-08-17  
**제품명:** QSH (Quick Shell / QUIC Shell)  
**CLI:** `qsh`

## 1. 제품 요약

QSH는 QUIC 기반의 직접 연결형 원격 셸이다. SSH의 핵심 기능을 제공하면서 네트워크 변경과 일시적 단절에도 동일한 PTY 세션을 유지한다.

중앙 서버나 relay 없이 동작하며, 사용자가 제공한 IP 주소나 hostname으로 연결한다. 그 아래의 네트워크 구성에는 관여하지 않는다.

> 한 번의 명령으로 접속하고, 연결이 끊겨도 같은 셸로 돌아온다.

## 2. 해결하려는 문제

- SSH 연결은 IP 변경, 절전, Wi-Fi 전환과 일시적 단절에 취약하다.
- mosh는 대화형 경험은 우수하지만 터널링과 프로그램 제어가 제한적이다.
- tmux는 프로세스를 보존하지만 접속과 인증을 해결하지 않는다.
- 장시간 실행되는 Claude Code 같은 CLI 세션을 사람과 에이전트가 함께 제어하기 어렵다.
- 중앙 relay나 SaaS 계정이 필수인 원격 도구는 설치와 운영이 복잡하다.

QSH는 이를 해결하는 작은 원격 세션 primitive를 제공한다.

## 3. 목표

1. SSH처럼 한 줄로 접속한다.
2. 정방향과 역방향 연결을 동일하게 지원한다.
3. 모든 연결을 상호 인증하고 암호화한다.
4. transport 연결과 무관하게 PTY 세션을 유지한다.
5. 셸, 명령 실행, 포트 포워딩을 제공한다.
6. 사람이 쓰는 CLI와 프로그램이 쓰는 JSON 인터페이스를 하나의 명령 체계로 제공한다.
7. 단일 Rust 바이너리로 배포한다.
8. relay 없이 완전히 동작한다.

## 4. 제품 원칙

### Direct first

두 endpoint 사이에 IP 경로가 있으면 제3자 서비스 없이 작동한다. NAT traversal과 relay는 코어에 포함하지 않는다.

### Provider agnostic

QSH는 routable address만 필요로 한다. 특정 VPN, tunnel, DNS 또는 identity provider와 직접 통합하지 않는다.

### 연결과 세션의 분리

PTY 세션은 QUIC connection보다 오래 살아야 한다. 연결이 교체되면 기존 세션에 다시 attach한다.

### 연결 방향과 역할의 분리

연결을 시작한 endpoint가 반드시 셸을 사용하는 쪽일 필요는 없다. target이 controller로 연결한 뒤 자신의 셸을 제공할 수 있다.

### 명시적 권한

인증에 성공해도 자동으로 셸 권한을 얻지 않는다. 각 기능은 ACL로 별도 허용하며 기본값은 deny다.

### 단일 바이너리

`qsh` 하나가 client, listener, agent, 인증서 관리와 선택적 MCP server 역할을 수행한다.

## 5. 주요 사용자

- 여러 Mac과 Linux 장비를 사용하는 개발자
- Claude Code, Codex 등 장시간 실행되는 CLI 에이전트 운영자
- 원격 서버에 지속적으로 접속하는 인프라 운영자
- MCP를 통해 원격 셸과 명령을 제어하는 orchestrator

## 6. 핵심 사용자 경험

### 초기화와 신뢰 설정

```bash
qsh init
qsh trust add <peer>
qsh serve
```

`qsh init`은 device identity를 생성하고 private key를 OS credential store에 보관한다. Peer 신뢰는 fingerprint 확인, 일회용 pairing code 또는 private CA로 설정한다.

### 정방향 접속

```bash
qsh dave@personal-mac
```

기본 동작은 대화형 PTY를 여는 것이다.

### 역방향 접속

```bash
# Controller
qsh listen

# Target
qsh reverse controller.example.com

# Controller
qsh attach company-mac
```

역방향 접속에도 target에서 controller까지 직접 연결 가능한 경로가 필요하다.

### 세션 복구

```bash
qsh sessions personal-mac
qsh attach personal-mac:<session-id>
```

클라이언트 종료, 절전 또는 네트워크 단절이 remote PTY를 종료해서는 안 된다. 재접속하면 마지막으로 확인한 output부터 복구한다.

### 명령 실행

```bash
qsh exec personal-mac -- uname -a
```

비대화형 실행은 argv, stdout, stderr와 exit status를 구조적으로 전달한다.

### 포트 포워딩

```bash
qsh -L 8080:localhost:3000 dave@personal-mac
qsh -R 9000:localhost:9000 dave@server
qsh -D 1080 dave@server
```

## 7. 기능 요구사항

### P0 — MVP

| 영역 | 요구사항 |
|---|---|
| Transport | QUIC과 TLS 1.3 상호 인증 |
| Connection | 정방향 및 역방향 direct connection |
| Mobility | IP 변경 시 connection migration, 단절 시 session resume |
| PTY | POSIX PTY, resize, signal, attach와 detach |
| Recovery | sequence 기반 output replay와 중복 제거 |
| Exec | argv 기반 비대화형 명령 실행과 exit status |
| Tunnel | local 및 remote TCP forwarding |
| Identity | pinned certificate와 private CA |
| ACL | principal·resource·action 기반 local policy |
| Automation | 안정된 JSON/JSONL CLI와 `qsh mcp` stdio adapter |
| Operations | host profile, local audit, `qsh doctor` |
| Platform | macOS와 Linux, arm64와 x86_64 |

### P1 — 실사용 확장

- UDP가 차단된 환경을 위한 TCP/TLS fallback
- SOCKS5 dynamic forwarding
- streaming file copy
- 인증서 rotation과 revocation UX
- Windows client
- background service 설치와 자동 시작
- 세션 및 audit 관리 개선

### P2 — 선택 기능

- 안전한 local echo prediction
- read-only multi-attach
- jump chaining
- agent forwarding
- Windows host
- mobile client SDK

## 8. 세션 모델

각 PTY 세션은 다음을 가진다.

- 고유 session ID
- 허용된 peer identity
- 하나의 writer lease
- output sequence와 제한된 replay buffer
- command, environment, terminal mode와 생성 시각 metadata
- configurable resume TTL

전송 연결이 끊겨도 세션과 child process는 유지된다. 새 연결은 session ID와 마지막 수신 sequence를 제시해 이어받는다. Buffer 범위를 벗어난 경우 QSH는 누락 구간을 숨기지 않고 명시한다.

## 9. 보안과 ACL

모든 직접 연결은 TLS 1.3으로 암호화하고 양쪽 certificate를 검증한다. 비밀번호 인증은 MVP에서 지원하지 않는다.

ACL principal은 certificate fingerprint 또는 CA가 발급한 user/device identity다. 최소 action은 다음과 같다.

- `session.create`, `session.list`, `session.attach`, `session.control`
- `exec.run`
- `forward.local`, `forward.remote`, `forward.socks`
- `file.read`, `file.write`
- `host.reverse`

```toml
[[acl]]
principal = "user:dave"
allow = ["session.*", "exec.run", "forward.local"]

[[acl]]
principal = "device:hermes"
allow = ["session.list", "session.attach", "exec.run"]
```

대화형 shell 권한은 사실상 임의 명령 실행 권한이다. 제한된 자동화에는 shell 대신 별도의 `exec.run` 정책을 사용한다.

추가 요구사항:

- 인증 전에는 PTY, exec 또는 tunnel resource를 생성하지 않는다.
- Resume credential은 session과 peer identity에 결합한다.
- Remote forwarding은 기본적으로 loopback에만 bind한다.
- 로그에 key, PTY 내용과 command 내용을 기본 저장하지 않는다.
- Protocol parser와 control message를 fuzzing한다.

## 10. 프로그램 인터페이스

CLI가 QSH의 canonical programmatic interface다. 모든 비대화형 명령은 안정된 exit code와 `--json` 출력을 제공하며, streaming output은 JSONL event로 제공한다.

```bash
qsh hosts --json
qsh sessions personal-mac --json
qsh exec personal-mac --json -- uname -a
qsh session read <session-ref> --after 42 --jsonl
```

JSON schema는 version을 포함하고, stdout에는 결과만 출력한다. 진단 로그는 stderr로 분리한다. PTY bytes는 sequence와 함께 lossless encoding으로 전달한다.

MCP가 필요한 환경에서는 같은 바이너리를 stdio server로 실행한다.

```bash
qsh mcp
```

최소 tool set:

- `list_hosts`, `list_sessions`
- `open_session`, `attach_session`, `close_session`
- `read_session`, `write_session`, `resize_session`
- `exec`
- `open_tunnel`, `close_tunnel`

`qsh mcp`는 별도 기능 계층이 아니다. CLI와 같은 typed operation, identity, ACL과 session broker를 MCP tool로 노출하는 얇은 adapter다. 내부에서 `qsh` subprocess를 반복 실행하거나 별도 business logic을 구현하지 않는다.

JSON/JSONL과 MCP의 상세 계약은 `docs/CLI.md`에서 정의한다.

## 11. 명령 체계

```text
qsh [user@]host                 대화형 셸
qsh exec host -- command        비대화형 실행
qsh serve                       target listener
qsh listen                      reverse listener
qsh reverse controller          역방향 연결
qsh hosts                       호스트 조회
qsh sessions [host]             세션 조회
qsh attach host:session         세션 attach
qsh tunnel ...                  터널 관리
qsh trust ...                   신뢰 관리
qsh cert ...                    인증서 관리
qsh acl ...                     ACL 관리와 검사
qsh <command> --json            machine-readable result
qsh mcp                         MCP server
qsh schema --json               지원 schema와 capability 조회
qsh doctor                      연결·인증·정책 진단
```

SSH 사용자에게 익숙한 `-L`, `-R`, `-D`, `-t`, `-T`, `-v`는 의미가 충돌하지 않는 범위에서 유지한다.

## 12. 시스템 경계

QSH가 책임지는 것:

- transport와 상호 인증
- ACL
- PTY 및 session lifecycle
- reconnect와 replay
- exec와 tunnel multiplexing
- Human CLI, JSON/JSONL과 얇은 MCP adapter

QSH 밖에서 해결하는 것:

- hostname과 IP reachability
- VPN과 사설 overlay network
- DNS와 service discovery
- NAT traversal
- 조직 계정과 중앙 관리

QSH는 `qsh user@host`에 주어진 주소로 연결할 뿐이다.

## 13. 비기능 요구사항

- PTY 처리 오버헤드 p95: 네트워크 RTT 외 10ms 미만
- Tunnel throughput: 동일 경로 raw QUIC의 80% 이상
- Idle listener 메모리: 30MB 이하 목표
- 기본 replay buffer: 세션당 8MB, 설정 가능
- 기본 resume TTL: 24시간, 설정 가능
- 30분 단절 후에도 TTL 내 세션 복구
- 느린 파일·터널 stream이 PTY stream을 block하지 않아야 함
- 보안 민감 오류는 fail-closed로 처리

## 14. Relay 확장

Relay는 QSH 코어와 분리된 선택 제품이다. Direct connection이 불가능할 때만 사용하며, CLI의 기본 접속 형태와 endpoint identity를 유지해야 한다.

```bash
qsh personal-mac --relay auto
```

Relay는 payload와 endpoint private key를 볼 수 없어야 한다. 이를 위해 logical session identity를 transport connection과 분리하되, MVP에는 relay 구현이나 negotiation을 포함하지 않는다.

## 15. 성공 기준

- 신규 두 장비의 최초 연결을 5분 이내에 완료한다.
- 등록된 host에는 한 개의 명령으로 접속한다.
- 테스트한 Wi-Fi와 tethering 전환의 95% 이상에서 자동 유지 또는 resume한다.
- Resume 가능한 단절에서 output loss가 없다.
- Client crash가 remote PTY를 종료하지 않는다.
- 모든 privileged operation이 ACL decision으로 추적 가능하다.
- 공개 beta 전에 protocol과 key lifecycle의 독립 보안 review를 완료한다.

## 16. 주요 위험

| 위험 | 대응 |
|---|---|
| 기업망의 UDP 차단 | P1 TCP/TLS fallback과 `qsh doctor` |
| Replay buffer 초과 | 누락 구간 표시, configurable buffer |
| Shell 권한의 과도한 범위 | 제한 자동화는 별도 `exec.run` 사용 |
| 역방향 연결을 relay로 오인 | Controller reachability 요구 명시 |
| Listener 재시작으로 세션 손실 | 초기 제한 명시, 추후 supervisor 검토 |
| `qsh` 기존 명령과 충돌 | 지원 플랫폼의 패키지 충돌 재검증 |

## 17. 확정된 결정

- 제품명과 CLI는 `QSH` / `qsh`다.
- MVP는 relay 없는 direct-only다.
- 정방향과 역방향은 모두 일급 기능이다.
- Rust 단일 바이너리로 시작한다.
- QUIC과 TLS 1.3 상호 인증을 기본으로 한다.
- PTY session lifetime을 transport lifetime과 분리한다.
- JSON CLI를 canonical programmatic interface로 삼는다.
- `qsh mcp`는 동일 operation을 노출하는 얇은 내장 adapter다.
- Relay는 향후 별도 self-hosted/managed 제품으로 개발한다.

## 18. 남은 결정

1. HTTP/3 semantics와 custom QUIC protocol 중 어느 쪽을 core로 둘지
2. Pairing 기본 UX를 fingerprint, 일회용 code, QR 중 무엇으로 할지
3. Detached PTY를 listener 내부에 둘지 별도 supervisor로 분리할지
4. Replay buffer를 memory-only로 둘지 encrypted disk spool을 허용할지
5. TCP fallback을 P0로 앞당길지
