# QSH Wire Protocol 설계

**상태:** 설계 확정 (2026-08-17)
**적용 범위:** P0 전체 (M1 transport/mTLS부터 M8 hardening까지)
**관련 문서:** [ADR-0001 custom QUIC](../adr/0001-custom-quic-protocol.md) · [ADR-0005 TCP fallback P1](../adr/0005-tcp-fallback-p1.md) · [CLI/JSON 계약](../CLI.md) · [아키텍처](architecture.md) · [테스트 전략](testing.md)

> **규칙:** 구현이 이 문서와 어긋나게 되는 경우, 코드를 우회하지 말고 이 문서(필요 시 ADR)를 먼저 갱신한 뒤 구현한다. JSON envelope·오류 코드·sequence의 사용자 노출 계약은 [docs/CLI.md](../CLI.md)가 canonical이며 여기서는 중복 기술하지 않는다.

## 1. 결정 요약

| 항목 | 결정 |
|---|---|
| QUIC 스택 | quinn **≥ 0.11.14** (0.11.14 미만은 원격 DoS 취약점) + rustls 0.23 (aws-lc-rs provider) + tokio |
| ALPN | `qsh/1` — 호환 파괴 시 `qsh/2`, 추가적 확장은 capability로 |
| 직렬화 | control message = protobuf(prost), 터널 payload = raw bytes |
| 0-RTT | 사용 안 함 (replay 위험) |
| keep-alive / idle | 15s / 45s |
| mobility | Tier 1 = connection migration(rebind), Tier 2 = session resume |
| congestion control | BBR (quinn 내장) |

## 2. QUIC 스택과 전송 설정

- **quinn 선정 근거:** 순수 Rust·tokio 네이티브·사실상의 커뮤니티 표준. 결정적으로 per-stream 송신 우선순위(`SendStream::set_priority(i32)`)와 fair queuing(`TransportConfig::send_fairness`)을 제공해 "느린 터널이 PTY를 막지 않는다"(PRD §13)를 스케줄러 레벨에서 구현할 수 있다. s2n-quic은 커스텀 인증서 검증(pin+CA 이중 모드)이 provider 추상화 탓에 번거롭고, quiche는 sans-IO C 스타일이라 이벤트 루프·타이머·소켓을 직접 소유해야 한다. **quinn은 반드시 0.11.14 이상으로 고정한다.**
- **Connection migration:** 서버측 passive migration(NAT rebind 등, path validation 포함)은 quinn이 자동 처리. 클라이언트는 인터페이스 변화 감지 시 `Endpoint::rebind(new_socket)`으로 active migration. migration은 **지연 최적화일 뿐**이며 실패해도 무방하다 — correctness는 resume(§8)이 보장한다. migration 성공에 의존하는 설계를 하지 않는다.
- **keep-alive 15s / max_idle_timeout 45s:** 15s는 일반적인 30s UDP NAT binding timeout보다 짧아 역방향 target의 장수명 연결을 NAT 뒤에서 유지한다. 절전한 노트북은 45s 후 연결이 죽지만 **세션은 유지**된다(그것이 분리 설계의 목적). 절전 복귀 시 클라이언트는 monotonic clock 점프/PTO 실패로 죽은 연결을 즉시 버리고 재다이얼→resume한다. idle timeout을 키워 "QUIC 레벨에서 절전 생존"을 추구하지 않는다(listener 메모리 낭비 + 설계와 충돌).
- **0-RTT 금지:** QSH의 control message는 전부 부수효과가 있다(`exec`, `session.write`, tunnel open). 0-RTT early data는 on-path 공격자가 재전송할 수 있으므로 절대 받지 않는다 — 클라이언트는 `into_0rtt()`를 호출하지 않고 서버는 early data를 활성화하지 않는다. TLS 세션 티켓(1-RTT resumption)은 성능상 켤 수 있으나, **티켓 기반 재개에서도 클라이언트 인증서 재검증이 보장되는지 확인**하고 의심스러우면 `NoServerSessionStorage`로 티켓을 끈다. 연결은 장수명이므로 handshake 지연은 중요하지 않다.

## 3. TLS 상호 인증 — `QshPeerVerifier`

client/server 양쪽 verifier가 **하나의 검증 코어**를 공유한다 (`qsh-transport/src/tls.rs`, rustls `danger` verifier trait 구현):

1. 제시된 leaf 인증서의 **SPKI SHA-256 fingerprint가 로컬 trust store에 pin**되어 있으면 → 허용, principal = 그 pin에 결합된 `device:<name>`/`fp:...`.
2. 아니면 **private CA 체인 검증**(rustls-webpki, 신뢰 root는 trust store의 CA만) 성공 시 → 허용, principal = leaf의 SAN URI(`qsh://user/dave`, `qsh://device/hermes`).
3. 그 외 → 거부. **web PKI root는 어떤 경로로도 로드하지 않는다.**

두 경로 모두에서 leaf 인증서의 **유효기간(not_before/not_after)을 검사**한다 — pin 일치라도 만료·미도래 인증서는 거부한다(M1 명확화: 장기 device cert에서 유효기간은 유일한 revocation 레버이며, 모호하면 fail closed). SNI/hostname은 검증에 쓰지 않는다(identity는 pin 또는 SAN principal이지 DNS 이름이 아니다).

양방향 인증서 필수(`client_auth_mandatory`). 검증된 peer identity 없이는 어떤 스트림도 application 계층에 도달하지 않는다. principal은 연결 수립 시 1회 계산되어 연결에 부착되고, ACL은 이것만 사용한다 — **`Hello`의 `device_name` 등 wire 데이터에서 identity를 취하지 않는다.** TLS 1.3 전용(QUIC이 보장).

## 4. ALPN·버전·capability

- ALPN `qsh/1`. 파괴적 wire 개정만 `qsh/2`. ALPN 불일치는 application 상태가 생기기 전에 handshake에서 실패한다.
- major 내 확장은 `Hello.versions`(minor 교집합) + `Hello.capabilities`(문자열 집합 교집합)로 협상한다. 새 기능 = 새 capability 문자열 + 새 optional message. protobuf라 구 peer는 unknown field를 무시하고, 광고하지 않은 capability의 스트림은 받지 않는다. `qsh capabilities` 명령은 협상된 교집합을 그대로 반환한다(CLI.md §6.10).

## 5. Frame layer

모든 control·data 스트림의 메시지는 `u32` big-endian length prefix + prost 인코딩 body다. **선언된 길이는 버퍼 할당 전에 상한 검사**한다:

| 대상 | 상한 |
|---|---|
| control 스트림 frame | 256 KiB (`CONTROL_FRAME_MAX`) |
| data 스트림 frame | 64 KiB (`DATA_FRAME_MAX`) |
| PTY/exec payload chunk | 16 KiB (frame 내부 data 필드) |

이 frame codec은 **`crates/qsh-proto/src/frame.rs`에 이미 구현·테스트되어 있다** (M0). 상한 초과는 즉시 연결 종료. `Vec::with_capacity(attacker_length)`는 어떤 경로에도 존재해서는 안 된다.

**예외 — 터널 스트림:** 초기 `StreamHeader`/응답 교환 후에는 frame 없이 **raw bytes**를 흘린다(순수 파이프, `copy_bidirectional`). per-chunk 오버헤드 제거가 "raw QUIC 대비 throughput ≥80%"(PRD §13)의 달성 수단이다.

## 6. 직렬화 — protobuf(prost)

근거: (1) CLI.md §2.3의 "unknown field 무시, major 내 additive-only" 규칙이 protobuf tagged field의 네이티브 시맨틱이다(postcard는 위치 인코딩이라 필드 추가가 구 디코더를 깨뜨리고, CBOR은 스키마 산출물이 없다). (2) prost 디코더는 malformed 입력에 panic 없이 실패하며, `.proto` 파일 자체가 보안 리뷰 산출물이자 structure-aware fuzzing 문법이 된다. (3) P2 mobile SDK·별도 relay 제품의 cross-language 표면. `.proto` 소스는 `crates/qsh-proto/proto/qsh/wire/v1.proto`(M1에서 생성)에 둔다.

## 7. 스트림 배치

connection당 **control 스트림 1개** + 리소스별 스트림. 비-control 스트림은 첫 frame의 `StreamHeader`로 자기 식별하며, QUIC stream ID 등 transport 고유 개념에 의존하지 않는다(ADR-0005의 transport 불가지 원칙).

| 스트림 | 여는 쪽 | 유형 | 내용 |
|---|---|---|---|
| Control | dialer가 handshake 후 첫 bidi | bidi, 연결당 1개 | `Hello` 교환 후 양방향 `ControlMessage` RPC(role 대칭), heartbeat, 비동기 event |
| Session data | attach하는 쪽, attach당 1개 | bidi | `StreamHeader{SESSION_DATA, ticket}` 후 framed `Output/Input/InputAck/Gap/Resize/Exit` |
| Exec data | exec 요청자, exec당 1개 | bidi | `StreamHeader{EXEC_DATA, ticket}` 후 framed `Stdin/StdinEof/Stdout/Stderr/ExecExit` |
| Tunnel (local fwd) | local listener 쪽, TCP 연결당 1개 | bidi | `StreamHeader{TCP_CONNECT, host, port}` → `ConnectResult` → raw bytes |
| Tunnel (remote fwd) | remote port를 bind한 쪽, accept당 1개 | bidi | `StreamHeader{TCP_ACCEPTED, forward_id}` → raw bytes |

**Ticket:** `SESSION_DATA`/`EXEC_DATA`용 ticket은 128-bit 난수, **해당 control 요청이 ACL을 통과한 뒤에만 발급**, 단회용, 30s 만료. 스트림이 인가받지 않은 리소스에 붙는 것을 구조적으로 차단한다("인증·인가 전 리소스 생성 금지", PRD §9). 유일한 예외는 `TCP_CONNECT`(local forward) — per-connection RPC 왕복을 피하려 스트림 오픈 시점에 `forward.local` ACL을 inline 검사하고, 거부 시 아무것도 dial하지 않고 스트림을 reset한다.

## 8. Sequence 시맨틱 (wire 관점)

사용자 노출 계약은 [CLI.md §2.3, §6.4] 참조. wire에서도 동일 모델을 쓴다:

- `sequence`는 세션 수명 동안 **누적된 output byte 수(u64)**다. `Output` frame의 `sequence`는 해당 chunk까지 포함한 누적 offset(= chunk 마지막 byte offset + 1).
- replay 요청(`last_output_seq = N`)은 "누적 offset N 이후 byte"를 의미하며, 서버는 chunk를 자유롭게 분할·병합해 **정확히 N에서 끊어** 재전송할 수 있다. UTF-8 경계·`--limit-bytes` 절단 문제가 원천적으로 없다.
- input 방향도 동일한 누적 byte offset(`input_seq`)을 쓴다. input 재전송/중복 제거는 wire 내부 동작이며 CLI 계약에는 노출되지 않는다.

## 9. `.proto` 스케치 (v1)

M1에서 `crates/qsh-proto/proto/qsh/wire/v1.proto`로 구체화한다. `Response.Error.code`는 CLI.md §3.3의 오류 코드 문자열을 **그대로** 사용한다(wire→JSON 번역표 없음, 어휘 단일화).

```protobuf
// Control 스트림 양방향. 요청은 request_id를 갖고 Response가 상관된다.
// 비동기 event는 request_id = 0.
message ControlMessage {
  uint64 request_id = 1;
  oneof body {
    Hello               hello = 10;
    Response            response = 11;      // 성공 payload 또는 Error — 상세는 아래 Response 참고

    SessionOpen         session_open = 20;  // argv, env, term, cols, rows
                                            // -> SessionOpened{session_id, resume_token, ticket, initial_seq}
    SessionAttach       session_attach = 21;// session_id, resume_token, last_output_seq,
                                            //   mode(RW|RO), no_steal
                                            // -> SessionAttached{ticket, new_resume_token,
                                            //      replay_from, writer_lease}
    SessionList         session_list = 22;  // -> Session[] (CLI.md §5와 동일 형태)
    SessionGet          session_get = 23;
    SessionResize       session_resize = 24; // detached resize; ACL session.control
    SessionSignal       session_signal = 25;
    SessionClose        session_close = 26;

    ExecStart           exec_start = 30;    // argv, env, timeout_ms -> ExecStarted{exec_id, ticket}

    RemoteForwardOpen   rfwd_open = 40;     // bind_host(기본 loopback), bind_port
                                            // -> RemoteForwardOpened{forward_id, actual_port}
    RemoteForwardClose  rfwd_close = 41;

    Ping                ping = 50;
    Pong                pong = 51;
    SessionEvent        session_event = 60; // 비동기: Exited{exit_code, signal, final_seq}
                                            //        | WriterChanged{new_writer} | Closed
  }
}

// Response.body의 non-Error variant는 요청과 1:1 대응하는 typed 성공 payload다.
// 새 op 추가 = 이 oneof에 variant 추가(additive) — 기존 필드 번호는 재사용 금지.
message Response {
  oneof body {
    SessionOpened       session_opened = 1;  // session_open 성공
    SessionAttached     session_attached = 2;// session_attach 성공
    ExecStarted         exec_started = 3;    // exec_start 성공
    RemoteForwardOpened rfwd_opened = 4;     // rfwd_open 성공
    Error               error = 15;          // { code, message, retryable } — code는 CLI.md §3.3 어휘
  }
}

message Hello {
  repeated uint32 versions = 1;        // major 내 minor; 교집합 채택
  string device_name = 2;              // 표시용. principal은 항상 TLS cert에서 나온다.
  repeated string capabilities = 3;    // "session","exec","tunnel.local","tunnel.remote","resume.v1",...
  ReverseRegistration reverse = 4;     // 역방향 target이 자신을 host로 제공할 때만 존재
}

// 모든 비-control 스트림의 첫 frame.
message StreamHeader {
  StreamKind kind = 1;                 // SESSION_DATA | EXEC_DATA | TCP_CONNECT | TCP_ACCEPTED
  bytes ticket = 2;                    // SESSION_DATA / EXEC_DATA / TCP_ACCEPTED(forward_id)
  string host = 3; uint32 port = 4;    // TCP_CONNECT 전용
}

// Session data 스트림 frame. sequence/input_seq는 누적 byte offset(§8).
message SessionFrame {
  oneof body {
    Output   output = 1;    // { uint64 sequence; bytes data; }  chunk ≤ 16 KiB
    Input    input = 2;     // { uint64 input_seq; bytes data; }
    InputAck input_ack = 3; // { uint64 acked_input_seq; }  적용 완료된 최고 누적 offset
    Gap      gap = 4;       // { uint64 requested_after; uint64 available_from; }
    Resize   resize = 5;    // { uint32 cols; uint32 rows; }
    Exit     exit = 6;      // { uint64 final_seq; int32 exit_code; optional string signal; }
  }
}

// Exec data 스트림 frame. exec 스트림은 session data 스트림과 달리 resume
// 대상이 아니다 — sequence 필드가 없고 QUIC 스트림 자체의 신뢰·순서 전달에
// 의존한다. ExecExit는 이 스트림의 마지막 frame이며, 이후 서버가 스트림을
// FIN한다.
message ExecFrame {
  oneof body {
    Stdin    stdin = 1;     // { bytes data; }        chunk ≤ 16 KiB
    StdinEof stdin_eof = 2; // {}
    Stdout   stdout = 3;    // { bytes data; }         chunk ≤ 16 KiB
    Stderr   stderr = 4;    // { bytes data; }          chunk ≤ 16 KiB
    ExecExit exec_exit = 5; // { int32 exit_code; optional string signal; bool timed_out; }
  }
}
```

`ExecExit.timed_out`은 호스트가 `ExecStart.timeout_ms` 만료로 프로세스 그룹을 kill했음을 뜻한다(이때 `exit_code`/`signal`은 보통 `137`/`SIGKILL`). 클라이언트는 이를 일반 signal 종료가 아니라 `TIMEOUT`으로 보고한다. 호스트는 한 connection이 미상환 ticket을 과도하게 쌓지 못하도록 per-connection 상한(현재 32)을 두며 초과 시 `ExecStart`에 `RESOURCE_EXHAUSTED`(retryable)로 답한다 — ACL 판정이 아니므로 audit되지 않는다. 자식이 종료된 뒤 peer가 data 스트림을 읽지 않아 flow control에 막히면 호스트는 유예(5s) 후 스트림을 reset(code 1)하고 자식을 reap한다 — 읽지 않는 peer가 호스트 exec를 붙잡아 둘 수 없다.

## 10. Session resume 프로토콜

**토큰.** `SessionOpened`가 32-byte CSPRNG `resume_token`을 반환한다. 호스트는 **`blake3(token)` 해시만** `(session_id, peer_spki_sha256, expires_at)`과 함께 저장한다. 클라이언트는 토큰을 `$XDG_STATE_HOME/qsh/resume.json`(0600)에 보관한다 — OS keychain이 아닌 이유는 재접속마다 인증 프롬프트가 뜨는 UX를 피하기 위해서이고, 토큰 단독으로는 무용하기 때문에 안전하다: 상환에는 기록된 SPKI와 일치하는 클라이언트 인증서로 맺은 상호 인증 TLS 연결이 필요하다(PRD §9 "resume credential은 session과 peer identity에 결합").

**Rotation.** `SessionAttach` 성공 시마다 제시된 토큰은 즉시 무효화되고 replay 시작 전에 `new_resume_token`이 발급된다(단일 세대 유효). 상태 파일과 device key를 함께 탈취해도 정당한 클라이언트와 경쟁해야 하고, 탈취 성공은 피해자 측에서 resume 실패/`SESSION_CONFLICT`로 드러난다. 해시 비교는 `subtle::ConstantTimeEq`.

**Reattach 절차.**
1. 새 QUIC 연결, 상호 TLS, `Hello` 교환.
2. `SessionAttach{session_id, resume_token, last_output_seq = L, mode}` → 호스트는 순서대로 검사: 토큰 해시 일치·미만료 → peer fingerprint가 세션 결합 identity와 일치 → ACL `session.attach`. **전부 통과 후에만** ticket + 새 토큰 발급. 실패는 fail-closed이며, 인가되지 않은 peer에게 세션 존재 여부를 누설하지 않도록 **non-distinguishing 오류**(`AUTH_FAILED`/`PERMISSION_DENIED`)로 답한다 — `SESSION_NOT_FOUND`는 identity 검사를 통과한 뒤에만 쓴다.
3. 클라이언트가 ticket으로 data 스트림을 연다. ring이 `L` 이후를 보존 중이면 정확히 `L`부터 재전송 후 live 전환. 클라이언트는 방어적으로 `sequence ≤ L`인 frame을 버린다.
4. **Gap:** ring의 보존 최소 offset `G > L`이면 첫 frame으로 `Gap{requested_after: L, available_from: G}`를 보낸 뒤 `G`부터 재전송. CLI는 이를 `session.gap` event로 렌더링(대화형은 `--- output lost ---` 마커). 절대 조용히 건너뛰지 않는다(PRD §8).
5. **Input 무손실·무중복:** 클라이언트는 미-ack input을 소량 버퍼(64 KiB 상한, 초과 시 조용히 쌓지 않고 오류)에 보관하고 reattach 후 재전송한다. 호스트는 세션별 최고 적용 `input_seq`를 기록·ack하며(`InputAck`), `input_seq ≤ 적용 완료 offset`인 input을 버린다. 끊김 중 타이핑이 유실도 중복도 되지 않는다.

**Writer lease.** 세션당 writer lease 1개. lease는 소유 연결이 죽으면 자동 해제된다(세션은 유지). `mode=RW` attach는 **기본이 steal**이다 — "절전 후 같은 사람이 재접속"이 지배적 경로이므로 수동 정리를 요구하면 핵심 약속이 깨진다. 기존 보유자가 실제로 살아 있으면 `SessionEvent::WriterChanged`를 받고 read-only로 강등된다. 신중한 자동화를 위해 `no_steal = true`는 steal 대신 `SESSION_CONFLICT`를 반환한다. 모든 handover 판정은 broker 단일 락 안에서 일어난다.

## 11. 역방향 모드

**대칭 원칙:** TLS 역할(누가 dial했나)과 QSH 역할(누가 셸을 제공하나)은 `Hello`에서 분리된다. control 스트림 수립 후 프로토콜은 완전 대칭 — 어느 쪽이든 요청을 보낼 수 있고, **요청 수신자가 자기 ACL을 평가**한다. "client/host"는 연결 단위가 아니라 요청 단위 역할이다.

1. `qsh listen`(controller)이 QUIC listener 실행, `qsh reverse <controller>`(target)가 평범한 상호 TLS로 dial.
2. target의 `Hello.reverse = ReverseRegistration{offered_name, capabilities}`. controller는 target을 **인증서로** 인증(pin 또는 CA — `offered_name`은 절대 인증에 쓰지 않음)한 뒤 그 principal에 ACL action **`host.reverse`**를 검사한다. 기본 deny, 거부 시 연결 종료 + audit. 허용 시 controller는 자기 통제 하의 이름으로 등록한다: 그 fingerprint의 trust-store alias 우선, `offered_name`은 명시적 `allow_advertised_names` 설정 시에만 — 인가된 장비가 `personal-mac` 같은 이름을 사칭(name-squatting)하는 것을 막는다.
3. 이후 controller에서 `qsh attach company-mac` 등: CLI 프로세스는 상주 `qsh listen` 데몬과 **local unix socket IPC**(`$XDG_RUNTIME_DIR/qsh/<pid>.sock`, 0600, §5와 동일한 frame layer — 파서 하나로 통일)로 통신하고, 데몬이 살아 있는 역방향 연결 위로 `SessionOpen`/`SessionAttach`를 보낸다. target은 자기 ACL(`session.open` 등)을 controller principal에 대해 평가한다 — **역방향 등록은 도달성만 부여하고 권한은 부여하지 않는다.**
4. 연결 유지는 15s keep-alive. 연결이 죽으면 host 목록에서 stale 처리되고 target의 `qsh reverse` 재접속 루프(지수 backoff + jitter)가 재등록한다. target의 세션들은 재등록과 무관하게 유지되고 §10으로 resume된다.

## 12. 우선순위와 backpressure

- **우선순위 band (quinn `set_priority`):** control **200** > session data(PTY) **100** > exec **50** > tunnel/file **0** (tunnel 간에는 `send_fairness(true)` round-robin). 로컬 송신 큐에서 포화 터널이 PTY chunk를 지연시키지 못한다.
- **Bufferbloat 방지:** 우선순위는 큐 순서만 고치고 깊이는 못 고친다 — bulk가 congestion window를 채우면 PTY chunk가 in-flight 뒤에서 기다린다. 대응: (a) per-stream receive window 비대칭(터널 ~2–4 MB, PTY ~256 KiB), (b) BBR congestion control, (c) "포화 터널 + PTY echo p95 < 10ms" 통합 벤치마크를 CI에 조기 도입(M4 수용 기준, [testing.md](testing.md)).
- **Replay ring = 만능 decoupler:** PTY reader task는 항상 ring에만 쓰고 네트워크에 블록되지 않는다. 각 attach/read 소비자는 ring 위의 cursor다. 느린 소비자는 cursor가 밀릴 뿐이고, ring 밖으로 밀리면 `Gap`을 받고 전진한다. 세션당 메모리는 ring 8MB + 소비자별 소량으로 유계이며(CLI.md §11 backpressure 규칙), 멈춘 reader가 child process의 stdout을 막을 수 없다.
- `session read --wait`/MCP long-poll/`--follow`는 모두 같은 cursor-pull primitive의 다른 표면이다([architecture.md](architecture.md) 참조).

## 13. Fuzzing·검증 계획

신뢰 불가 입력 표면 전체를 sans-IO `qsh-proto`에 격리한다(순수 `&[u8] → Result<Frame>` + sans-IO 상태 기계). cargo-fuzz(libFuzzer) 타깃:

1. **`fuzz_frame_split`** — frame splitter에 적대적 부분 청크(1-byte 피드, 쪼개진 length prefix, 상한 근접 길이). 불변식: panic 없음, 상한 초과 할당 없음, 청킹 방식과 무관하게 결과 동일.
2. **`fuzz_control_decode`** — raw bytes → `ControlMessage::decode` + `arbitrary` 기반 structure-aware 변형. 불변식: decode는 panic하지 않고, 의미 검증은 결정적.
3. **`fuzz_stream_header`** — 모든 `StreamKind`(unknown 포함)·불량/만료 ticket의 첫 frame 처리. 불변식: `Hello` 완료 전에는 control 외 어떤 것도 존재 불가, ACL 미통과 경로에서 리소스(PTY/exec/socket) 생성 0건(계측 mock broker로 단언).
4. **`fuzz_session_machine`** — `arbitrary` 생성 control message 시퀀스 + 연결 단절 이벤트를 sans-IO broker에 주입. 불변식: default deny 유지, writer lease 단일성, sequence 단조성, gap 범위 정확성, resume token 단회성.
5. **proptest 모델 테스트** — 전 message encode/decode round-trip; ring buffer를 naive Vec 오라클과 대조(임의 append/attach/evict 후 replay·gap 정확성); reconnect 경쟁 하의 input dedup 모델.

corpus는 `fuzz/corpus/`에 체크인하고 **모든 플랫폼에서 유닛 테스트로 상시 재생**한다(발견된 크래시의 회귀 고정). CI에서 PR마다 fuzz 빌드 게이트 + nightly smoke fuzz, 공개 beta 전 타깃당 누적 72시간 + OSS-Fuzz 제출. 상세는 [testing.md](testing.md).

## 14. P1 TCP fallback을 위한 제약 (지금 지켜야 할 것)

ADR-0005에 따라 P0 코드는 다음을 지킨다 — 이를 지키면 fallback은 wire 변경 없이 "TLS over TCP + 소형 스트림 mux" 추가로 끝난다:

- 모든 프로토콜 코드는 `Transport`/`StreamMux` trait(open_bi/accept, ordered reliable bytes, 우선순위 힌트)에 대해 작성한다. quinn이 첫 구현일 뿐이다.
- wire 구조는 QUIC 고유 개념(stream ID, datagram, transport parameter)에 의존하지 않는다. 스트림 정체성은 항상 in-band `StreamHeader`다.
- `qsh doctor`는 P0부터 UDP reachability probe를 갖는다(차단 환경을 "미스터리"가 아닌 진단 가능한 상태로).
