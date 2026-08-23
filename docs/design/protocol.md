# QSH Wire Protocol 설계

**상태:** 설계 확정 (2026-08-17)
**적용 범위:** P0 전체 (M1 transport/mTLS부터 M8 hardening까지)
**관련 문서:** [ADR-0001 custom QUIC](../adr/0001-custom-quic-protocol.md) · [ADR-0005 TCP fallback P1](../adr/0005-tcp-fallback-p1.md) · [CLI/JSON 계약](../CLI.md) · [아키텍처](architecture.md) · [테스트 전략](testing.md)

> **규칙:** 구현이 이 문서와 어긋나게 되는 경우, 코드를 우회하지 말고 이 문서(필요 시 ADR)를 먼저 갱신한 뒤 구현한다. JSON envelope·오류 코드·sequence의 사용자 노출 계약은 [docs/CLI.md](../CLI.md)가 canonical이며 여기서는 중복 기술하지 않는다.

## 1. 결정 요약

| 항목 | 결정 |
|---|---|
| QUIC 스택 | quinn (`quinn-proto` **≥ 0.11.14**; 그 미만은 원격 DoS 취약점) + rustls 0.23 (aws-lc-rs provider) + tokio |
| ALPN | `qsh/1` — 호환 파괴 시 `qsh/2`, 추가적 확장은 capability로 |
| 직렬화 | control message = protobuf(prost), 터널 payload = raw bytes |
| 0-RTT | 사용 안 함 (replay 위험) |
| keep-alive / idle | 15s / 45s |
| mobility | Tier 1 = connection migration(rebind), Tier 2 = session resume |
| congestion control | BBR (quinn 내장) |

## 2. QUIC 스택과 전송 설정

- **quinn 선정 근거:** 순수 Rust·tokio 네이티브·사실상의 커뮤니티 표준. 결정적으로 per-stream 송신 우선순위(`SendStream::set_priority(i32)`)와 fair queuing(`TransportConfig::send_fairness`)을 제공해 "느린 터널이 PTY를 막지 않는다"(PRD §13)를 스케줄러 레벨에서 구현할 수 있다. s2n-quic은 커스텀 인증서 검증(pin+CA 이중 모드)이 provider 추상화 탓에 번거롭고, quiche는 sans-IO C 스타일이라 이벤트 루프·타이머·소켓을 직접 소유해야 한다. **`quinn-proto`는 반드시 0.11.14 이상으로 고정한다**(RUSTSEC-2026-0037의 advisory 대상은 파사드 `quinn`이 아니라 `quinn-proto`다).
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

    SessionOpen         session_open = 20;  // argv, env, term, cols, rows,
                                            //   optional user(hint; `qsh user@host`의 user — 검사 순서는
                                            //   ACL session.open → hint → spawn; serve 계정 login name과
                                            //   다르면 세션 생성 없이 UNSUPPORTED, 미인가 peer는 항상
                                            //   PERMISSION_DENIED, CLI.md §7)
                                            // -> SessionOpened{session_id, resume_token, ticket, initial_seq,
                                            //      expires_at}
                                            //    session_id는 opaque·URL-safe; session_ref는 클라이언트가
                                            //    조립한다(ADR-0007). expires_at = 토큰/세션 TTL 만료 시각
                                            //    (클라이언트 resume.json 정리용)
    SessionAttach       session_attach = 21;// session_id, resume_token, last_output_seq,
                                            //   mode(AttachMode: UNSPECIFIED=0|RW=1|RO=2), no_steal
                                            //   — writer lease는 명시적 RW에만 요청된다. UNSPECIFIED(필드
                                            //   미설정)·미지 값은 INVALID_ARGUMENT, 절대 RW로 취급하지
                                            //   않는다. RO=2는 번호만 확보(M2에 관찰자 모드 없음, ROADMAP
                                            //   §3) — M2 호스트는 INVALID_ARGUMENT로 답한다
                                            // -> SessionAttached{ticket, new_resume_token,
                                            //      replay_from, writer_lease, expires_at}
    SessionList         session_list = 22;  // -> SessionInfo[] — wire SessionInfo는
                                            //    session_id/state/writer(optional)/created_at/last_sequence만
                                            //    담는다. CLI.md §5 Session의 session_ref·host는 클라이언트
                                            //    Ops가 로컬 alias로 채운다(ADR-0007)
    SessionGet          session_get = 23;   // session_id -> SessionInfo
    SessionResize       session_resize = 24; // session_id, cols, rows -> SessionResized{cols, rows}
                                            //   (호스트가 실제 적용한 크기); detached resize; ACL session.control
    reserved 25;                             // (구 SessionSignal) 번호만 예약, P1. M2 호스트는 25번 수신 시
                                            //   리소스 생성 없이 UNSUPPORTED로 답한다(CLI.md §2.4).
                                            //   구현 메모: prost는 unknown field를 버리므로 25/40/41 등
                                            //   예약·미지 번호는 body 없는 ControlMessage로 디코드되고,
                                            //   호스트는 body 없는 메시지를 일괄 UNSUPPORTED로 답한다
    SessionClose        session_close = 26; // session_id, optional signal(HUP|INT|QUIT|TERM|USR1|USR2|KILL —
                                            //   `session close --signal`, CLI.md §6.7) -> SessionClosed{final_seq};
                                            //   ACL session.control
    SessionRead         session_read = 27;  // session_id, after, max_bytes(uint64; 0 = 호스트 기본,
                                            //   SESSION_READ_MAX_BYTES = 192 KiB로 clamp — 응답이 항상
                                            //   control frame 1개(256 KiB)에 들어가도록),
                                            //   wait_ms(SESSION_READ_MAX_WAIT = 60 s로 clamp — 거부가 아니라
                                            //   상한. 한 long-poll이 호스트 슬롯을 무한정 붙잡지 못하게),
                                            //   ctl_after(직전 응답의 next_ctl_after; 0 = 처음부터)
                                            // -> SessionReadResult{events[], next_after, next_ctl_after} —
                                            //   broker pull() 1회; events[]의 원소는
                                            //   SessionReadEvent{Output|Gap|Exit|WriterChanged|Closed}
                                            //   (CLI.md §6.4 `session read --wait`/`--follow` 루프/MCP long-poll);
                                            //   ACL session.attach, resume token 불요(CLI.md §6.3)
    SessionWrite        session_write = 28; // session_id, data(≤ 16 KiB, 초과 시 INVALID_ARGUMENT)
                                            // -> SessionWritten{bytes_written} ; ACL session.control

    ExecStart           exec_start = 30;    // argv, env, timeout_ms -> ExecStarted{exec_id, ticket}

    RemoteForwardOpen   rfwd_open = 40;     // bind_host(기본 loopback), bind_port
                                            // -> RemoteForwardOpened{forward_id, actual_port}
    RemoteForwardClose  rfwd_close = 41;

    Ping                ping = 50;
    Pong                pong = 51;
    SessionEvent        session_event = 60; // 비동기: {session_id, oneof
                                            //          exited(Exit — SessionFrame.Exit와 같은 메시지)
                                            //        | WriterChanged{optional new_writer, seq}
                                            //          (new_writer 없음 = lease 해제, 보유자 없음)
                                            //        | Closed{reason: "closed"|"exit"|"ttl_expired" (open string,
                                            //          CLI.md §6.4·§10), seq}}
                                            // → qsh.event/v1 session.exit / session.writer_changed /
                                            //   session.closed (CLI.md §6.4). attach 중인 connection에만
                                            //   전송; pull 소비자는 같은 event를 ReplayRing의 제어 엔트리로
                                            //   받는다(architecture.md §3)
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
    SessionReadResult   session_read_result = 5; // session_read 성공 (events[], next_after, next_ctl_after)
    SessionListResult   session_list_result = 6; // session_list 성공 (SessionInfo[])
    SessionInfo         session_info = 7;    // session_get 성공
    SessionWritten      session_written = 8; // session_write 성공 {bytes_written — 호스트가 실제 수용한 바이트}
    SessionResized      session_resized = 9; // session_resize 성공 {cols, rows — 실제 적용된 크기}
    SessionClosed       session_closed = 10; // session_close 성공 (final_seq)
    Error               error = 15;          // { code, message, retryable } — code는 CLI.md §3.3 어휘
  }
}

message Hello {
  repeated uint32 versions = 1;        // major 내 minor; 교집합 채택
  string device_name = 2;              // 표시용. principal은 항상 TLS cert에서 나온다.
  repeated string capabilities = 3;    // "session","exec","tunnel.local","tunnel.remote","resume.v1",...
  ReverseRegistration reverse = 4;     // 역방향 target이 자신을 host로 제공할 때만 존재
}

// target이 자신을 host로 제공할 때 Hello.reverse에 담는 값(§11-2).
message ReverseRegistration {
  string offered_name = 1;  // 인증에 절대 쓰이지 않는 자기 신고 값. 검사 규칙은
                             //   `name.is_empty() || wire::valid_host_name(name)` — 빈 문자열은
                             //   검사에서 제외(이름을 controller에 위임한다는 뜻)이고, 비어 있지
                             //   않으면 wire::valid_host_name()(1..=64 bytes, [A-Za-z0-9._-])을
                             //   만족해야 한다. 실제 등록 이름은 controller가 정한다(§11-2 이름
                             //   확정 규칙) — name-squatting 방지.
  repeated string capabilities = 2;  // 이 target이 **이 등록에서 host 역할로 제공할** 기능
                             //   문자열 집합(비어 있으면 Hello.capabilities와 동일). 미지 문자열은
                             //   controller가 무시하며, 인가·identity 입력이 아니다. 신규 문자열을
                             //   만들지 않는다 — 역방향의 신호는 Hello.reverse 필드의 존재 자체다.
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
                            //   SessionEvent.exited / SessionReadEvent.exit도 같은 Exit 메시지를 쓴다
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

**Cursor는 (output offset, control id) 쌍이다.** 제어 엔트리(`Exit`/`WriterChanged`/`Closed`)는 zero-length라서 append 시점의 offset을 달고 나오되 offset을 증가시키지 않는다. 따라서 `after` 하나로는 "offset N에 있는 제어 엔트리는 이미 받았다"를 표현할 수 없고, `ctl_after`(ring이 부여하는 단조 증가 id)가 그 나머지 절반이다. `next_after`/`next_ctl_after`를 되먹이는 소비자는 모든 event를 **정확히 한 번** 받고, 새 event가 없으면 long-poll이 정상적으로 대기한다. `ctl_after`를 되먹이지 않는 stateless 소비자는 offset이 정확히 `after`인 제어 엔트리를 매번 다시 받고(at-least-once) 그 때문에 long-poll이 즉시 반환된다 — 폴링 루프는 두 값을 함께 되먹여야 한다(CLI.md §6.4).

**Control 스트림의 순서 계약.** 호스트는 control 메시지를 **도착 순서대로 인라인 처리**한다 — pipelining하는 클라이언트가 보낸 두 `SessionWrite`는 보낸 순서대로 PTY에 도달한다. 예외는 오래 블록될 수 있는 두 종류(`SessionRead` long-poll, `SessionClose`의 HUP→TERM→KILL escalation)로, 이들만 연결 소유의 task로 떼어내 control 스트림을 막지 않게 한다(둘 다 입력을 재배열하지 않는다: read는 변경이 없고 close는 세션의 마지막 op다). 떼어낸 task는 **연결보다 오래 살지 않는다** — 연결 루프가 반환하면 함께 취소되고, 그 다음에야 `purge_connection`(ticket 폐기 + writer lease 해제)이 돌아 lease가 죽은 연결 이름으로 다시 잡히는 창이 없다. 동시 실행 상한은 연결당 `MAX_INFLIGHT_REQUESTS_PER_CONN`(현재 64)이고 초과분은 dispatch 없이 `RESOURCE_EXHAUSTED`(retryable, ACL 판정이 아니므로 audit 없음)로 답한다.

**세션 id는 모양부터 검사한다.** peer가 보낸 `session_id`는 ACL resource이자 audit field가 되므로, ACL choke point **이전에** `1..=64` 바이트의 URL-safe(`[A-Za-z0-9_-]`) 형태인지 검사하고 아니면 `INVALID_ARGUMENT`로 답한다. 존재 여부와 무관한 검사라 §10-2의 non-distinguishing 성질을 해치지 않으며, pinned peer가 요청마다 256 KiB짜리 id로 audit 로그를 부풀리지 못하게 막는다.

`ExecExit.timed_out`은 호스트가 `ExecStart.timeout_ms` 만료로 프로세스 그룹을 kill했음을 뜻한다(이때 `exit_code`/`signal`은 보통 `137`/`SIGKILL`). 클라이언트는 이를 일반 signal 종료가 아니라 `TIMEOUT`으로 보고한다. 호스트는 한 connection이 미상환 ticket을 과도하게 쌓지 못하도록 per-connection 상한(현재 32)을 두며 초과 시 `ExecStart`에 `RESOURCE_EXHAUSTED`(retryable)로 답한다 — ACL 판정이 아니므로 audit되지 않는다. 자식이 종료된 뒤 peer가 data 스트림을 읽지 않아 flow control에 막히면 호스트는 유예(5s) 후 스트림을 reset(code 1)하고 자식을 reap한다 — 읽지 않는 peer가 호스트 exec를 붙잡아 둘 수 없다.

## 10. Session resume 프로토콜

**토큰.** `SessionOpened`가 32-byte CSPRNG `resume_token`을 반환한다. 호스트는 **`blake3(token)` 해시만** `(session_id, peer_spki_sha256, expires_at, input_stream)`과 함께 저장한다. `expires_at`은 **세션의 수명에 고정된다** — attach 중인 세션은 TTL이 흐르지 않으므로(architecture.md §3) reaper가 매 tick마다 credential의 만료를 세션 자신의 reap deadline으로 다시 맞춘다. 발급 시각 기준으로 두면 하루 넘게 붙잡고 일한 세션이 살아 있는 채로 resume 불가가 되어, 다음 단절에서 영구 orphan이 된다. 클라이언트는 토큰을 `$XDG_STATE_HOME/qsh/resume.json`(0600, `session_ref`를 key로, peer SPKI fingerprint·`expires_at`과 함께; 쓰기·rotation·정리 규율은 ADR-0007)에 보관하며 **JSON 출력에는 절대 노출하지 않는다**(CLI.md §6.3, ADR-0007) — OS keychain이 아닌 이유는 재접속마다 인증 프롬프트가 뜨는 UX를 피하기 위해서이고, 토큰 단독으로는 무용하기 때문에 안전하다: 상환에는 기록된 SPKI와 일치하는 클라이언트 인증서로 맺은 상호 인증 TLS 연결이 필요하다(PRD §9 "resume credential은 session과 peer identity에 결합").

**Rotation.** `SessionAttach` 성공 시마다 제시된 토큰은 즉시 무효화되고 replay 시작 전에 `new_resume_token`이 발급된다(단일 세대 유효). 상태 파일과 device key를 함께 탈취해도 정당한 클라이언트와 경쟁해야 하고, 탈취 성공은 피해자 측에서 resume 실패/`SESSION_CONFLICT`로 드러난다. 해시 비교는 `subtle::ConstantTimeEq`.

**Reattach 절차.**
1. 새 QUIC 연결, 상호 TLS, `Hello` 교환.
2. `SessionAttach{session_id, resume_token, last_output_seq = L, mode}` → 호스트는 순서대로 검사: 토큰 해시 일치·미만료 → peer fingerprint가 세션 결합 identity와 일치 → ACL `session.attach`. **전부 통과 후에만** ticket + 새 토큰 발급. `resume_token`은 **선택 항목이 아니다** — 비어 있는 `SessionAttach`는 아래와 같은 `AUTH_FAILED`로 거부한다(그렇지 않으면 credential의 peer 결합을 필드를 비우는 것만으로 우회할 수 있고, attach가 "세션을 연 장비에서만"이라는 ADR-0007 결정 2가 클라이언트 예의로 전락한다). 세션을 막 연 연결의 첫 스트림은 이 경로가 아니라 `SessionOpened`의 ticket으로 열린다. writer lease는 이 검사들이 결정을 끝낼 때까지 **움직이지 않는다**: `no_steal` 판정은 읽기 전용 probe이고, 실제 take는 data 스트림이 열릴 때 broker 락 안에서 일어난다. 실패는 fail-closed이며, 인가되지 않은 peer에게 세션 존재 여부를 누설하지 않도록 **non-distinguishing 오류**(`AUTH_FAILED`/`PERMISSION_DENIED`)로 답한다 — `SESSION_NOT_FOUND`는 identity 검사를 통과한 뒤에만 쓴다.
3. 클라이언트가 ticket으로 data 스트림을 연다. ring이 `L` 이후를 보존 중이면 정확히 `L`부터 재전송 후 live 전환. 클라이언트는 방어적으로 `sequence ≤ L`인 frame을 버린다.
4. **Gap:** ring의 보존 최소 offset `G > L`이면 첫 frame으로 `Gap{requested_after: L, available_from: G}`를 보낸 뒤 `G`부터 재전송. CLI는 이를 `session.gap` event로 렌더링(대화형은 `--- output lost ---` 마커). 절대 조용히 건너뛰지 않는다(PRD §8).
5. **Input 무손실·무중복:** 클라이언트는 미-ack input을 소량 버퍼(64 KiB 상한, 초과 시 조용히 쌓지 않고 오류)에 보관하고 reattach 후 재전송한다. 호스트는 최고 적용 `input_seq`를 기록·ack하며(`InputAck`), `input_seq ≤ 적용 완료 offset`인 input을 버린다. 끊김 중 타이핑이 유실도 중복도 되지 않는다.

   이 cursor는 **attach 단위 축(axis)** 이다. attach마다 호스트가 새 축을 발급하고, 그 축의 시작 offset은 resume credential이 가리키는 **직전 축의 적용 offset**이다 — 그래서 재전송은 여전히 exactly-once이면서, 아직 죽은 줄 모르고 계속 타이핑하는 **이전 attach**(read-only로 강등된 쪽)가 현재 writer의 cursor를 움직이지 못한다. lease 없는 peer의 write는 거절되고 **자기 축만** 전진시킨다(steal-back 시 거절된 바이트를 다시 보내지 않기 위해). 축이 세션 하나로 공유되면, 강등된 peer가 올린 offset 때문에 현재 writer의 입력이 "재전송"으로 오인돼 조용히 버려지고 ack까지 받는다 — PRD §8이 금지하는 정확히 그 손실이다. 축 개수는 상한이 있고 오래된 것부터 정리된다.

**Path 사망 감지 (클라이언트).** §2의 예산("path 사망 감지 후 2초 내 재dial + resume")을 지키려면 감지가 QUIC 계층에서는 나오지 않는다는 사실을 인정해야 한다: quinn이 죽은 연결을 포기하는 유일한 무조건 신호는 `max_idle_timeout` 45 s이고, 그 값은 위에서 튜닝 대상이 아니라고 못박았다. 그래서 감지는 **제어 스트림 위의 애플리케이션 `Ping`/`Pong`** 으로 한다(§9의 frame은 이미 있고 호스트는 이미 응답한다):

- **두 cadence.** 사용자 활동(입력 또는 **세션 트래픽** — 출력·이벤트)이 최근 15 s 안에 있었으면 250 ms마다, 아니면 5 s마다 probe한다. 하루 종일 idle한 셸이 초당 4번 radio를 깨우지 않게 하기 위해서다. idle 창에서의 감지는 느리지만, 그 창에는 잃을 대화형 상태도 없다. **`Pong`은 활동이 아니다** — probe에 대한 응답을 활동으로 세면 watchdog이 자기 자신에게 답하며 active 창을 영구히 갱신해 idle cadence에 영원히 도달하지 못한다(살아 있는 path에서만 그렇게 되므로 더 나쁘다). `Pong`은 liveness만 갱신하고, watchdog task의 sleep 길이도 현재 cadence를 따른다(activity가 idle→active 전환을 만들면 즉시 깨운다).
- **RTT에 비례하는 deadline.** 사망 판정 기준은 `max(1 s, 관측 RTT × 8)`이며, 연속 3회 무응답을 요구한다. 느린 링크를 죽었다고 오진하지 않기 위한 것이고, 세 값 모두 상수가 아니라 설정(`RecoveryConfig`)이다.
- **소비자 정체는 사망이 아니다.** frontend가 이벤트를 늦게 읽어 pump가 막혀 있는 동안에는 판정을 유예한다. 그렇지 않으면 느린 터미널이 자기 연결을 끊는다.

사망이 선언되면 클라이언트는 (인터페이스가 바뀐 경우) `Endpoint::rebind()`를 먼저 시도하고, 그것이 연결을 살리지 못하면 재dial → 위 4단계 reattach를 수행한다. migration probe의 대기 예산은 상수가 아니라 관측 RTT × 2(100–300 ms clamp)다 — 그 시간은 재dial이 쓸 2초 예산에서 나오고, LAN에서 고정 300 ms는 아무것도 배우지 못한 채 예산의 30%를 태운다.

> **자격증명 임계 구역은 취소 불가다.** 호스트는 successor를 발행하는 순간 제시된 토큰을 죽인다(아래 "Rotation"). 따라서 "요청이 wire에 올라간 시점 ~ successor가 디스크에 안착한 시점" 구간에서 클라이언트를 취소하면 이 기기는 죽은 자격증명만 남고, attach는 기기 바인딩(CLI.md §6.2)이므로 **살아 있는 세션에 아무도 다시 붙을 수 없다.** 그래서 재dial+redemption은 별도 task에서 돌고 2초 deadline은 그 task를 *기다리는 것*만 중단한다 — task 자체는 `store.put`까지 반드시 완주하며, 다음 시도는 새 redemption을 시작하지 않고 그 task를 이어받는다(단회성 토큰을 두 번 제시하는 경주를 만들지 않기 위해). **migration은 지연 최적화일 뿐이며 correctness는 resume이 보장한다.** 전 과정은 frontend에게 보이지 않는다 — 같은 attach 스트림이 계속 살아 있고, 재전송 중복은 `sequence ≤ L` 폐기가, 미-ack input은 위 5번이 처리한다. 결과는 `recovery ∈ {migrated, resumed, failed}` + `time_to_recovery_ms`로 stderr에 기록된다(CLI.md §6.4).

**Writer lease.** 세션당 writer lease 1개. lease는 소유 연결이 죽으면 자동 해제된다(세션은 유지). `mode=RW` attach는 **기본이 steal**이다 — "절전 후 같은 사람이 재접속"이 지배적 경로이므로 수동 정리를 요구하면 핵심 약속이 깨진다. 기존 보유자가 실제로 살아 있으면 `SessionEvent::WriterChanged`를 받고 read-only로 강등된다. 신중한 자동화를 위해 `no_steal = true`는 steal 대신 `SESSION_CONFLICT`를 반환한다. 모든 handover 판정은 broker 단일 락 안에서 일어난다.

## 11. 역방향 모드

**대칭 원칙:** TLS 역할(누가 dial했나)과 QSH 역할(누가 셸을 제공하나)은 `Hello`에서 분리된다. control 스트림 수립 후 프로토콜은 완전 대칭 — 어느 쪽이든 요청을 보낼 수 있고, **요청 수신자가 자기 ACL을 평가**한다. "client/host"는 연결 단위가 아니라 요청 단위 역할이다.

1. `qsh listen`(controller)이 QUIC listener 실행, `qsh reverse <controller>`(target)가 평범한 상호 TLS로 dial.
2. target의 `Hello.reverse = ReverseRegistration{offered_name, capabilities}`. controller는 target을 **인증서로** 인증(pin 또는 CA — `offered_name`은 절대 인증에 쓰지 않음)한다 — mTLS는 QUIC handshake에서 이미 끝나 있으므로 이 인증은 `Hello` 프레임을 읽기 전에 완료돼 있다. 인증된 연결에서 `Hello.reverse`를 받으면 `offered_name`에 모양 검사(`name.is_empty() || valid_host_name(name)` — 빈 문자열은 검사에서 제외되고 실제 이름은 controller가 정한다; 위반은 `INVALID_ARGUMENT` + 연결 종료, choke point 이전이므로 audit 없음)를 적용한 뒤, 그 principal에 ACL action **`host.reverse`**를 검사한다. 기본 deny, 거부 시 연결 종료 + audit(리소스는 하나도 만들지 않는다). 허용 시 controller는 자기 통제 하의 이름으로 등록한다: 그 fingerprint의 trust-store alias 우선, `offered_name`은 명시적 `allow_advertised_names` 설정 시에만(둘 다 없으면 `PERMISSION_DENIED`) — 인가된 장비가 `personal-mac` 같은 이름을 사칭(name-squatting)하는 것을 막는다. **충돌 처리:** 같은 이름의 live 등록이 이미 있고 fingerprint가 **다르면** 신규 등록을 `INVALID_ARGUMENT` + 연결 종료(조용한 덮어쓰기 금지), **같은 fingerprint면** 기존 등록을 대체하고 옛 연결을 닫으며 `generation`을 1 증가시킨다(NAT rebind로 인한 재등록이 정상 경로). **`qsh serve`(정방향 host)가 `Hello.reverse`를 받은 경우**는 이 대칭 원칙 하에서 실제로 발생 가능한 입력이며, 등록하지 않고 `UNSUPPORTED`로 답한다. `Hello.reverse` 없는 peer가 `qsh listen`에 연결한 경우도 `UNSUPPORTED` 후 종료다. (controller가 localctl UDS 연결을 accept할 때 요구하는 peer credential 검사(`SO_PEERCRED`/`getpeereid`)는 이 QUIC 등록 절차와 별개로 §11-3의 conduit 수립 시 수행되며, 구현은 M3 Step 5다.)
3. 이후 controller에서 `qsh <name>`(신규 세션) 또는 `qsh attach <name>/<session_id>`(재attach) 등: CLI 프로세스는 상주 `qsh listen` 데몬과 **local unix socket IPC**(`$XDG_RUNTIME_DIR/qsh/<pid>.sock`, 0600, package `qsh.local.v1` — §5와 동일한 frame codec(`qsh_proto::frame`, u32-BE + prost)을 `tokio::net::UnixStream` 위에서 그대로 재사용하되, wire(`qsh.wire.v1`)와는 별도 `.proto` 파일·별도 package다)로 통신한다. **conduit 모델:** UDS 연결 하나가 논리 스트림(conduit) 하나이고, 첫 frame `LocalHello{version, kind, host, wait_ms}`가 그 정체를 정한다 — `LOCAL_CONTROL`(그 host의 control 세션: 이후 QUIC 위와 **완전히 같은** `ControlMessage`/`Response`가 흐른다), `LOCAL_STREAM`(다음 frame이 wire `StreamHeader{SESSION_DATA, ticket}`인 data 스트림), `LOCAL_ADMIN`(데몬 자신에 대한 조회 — `LocalHostList` 등). **`LOCAL_CONTROL`/`LOCAL_STREAM`에서** 데몬은 `LocalHelloAck{host, peer_fingerprint, generation, capabilities}`로 응답하며, `peer_fingerprint`는 CLI 프로세스가 스스로 알 수 없는(TLS endpoint가 아니므로) peer SPKI fingerprint를 되돌려 줘서 `Ops`가 ADR-0007의 fail-closed peer-mismatch 검사를 역방향에서도 수행할 수 있게 한다 — 두 kind 모두 `LocalHello.host`가 가리키는 구체적 등록 host가 있고, `LocalHelloAck`의 모든 필드가 바로 *그 host*에 관한 값이기 때문이다(Step 6이 구현). **`LOCAL_ADMIN`은 이 ack를 받지 않는다** — `LocalHello.host`는 이 kind에서 애초에 무시되고(그 kind는 "특정 host에 관한 것이 아니다") `LocalHelloAck`의 네 필드(host·peer_fingerprint·generation·capabilities) 전부가 그런 host 하나를 전제하므로 값을 채울 대상이 없다. 대신 `LOCAL_ADMIN` 데몬은 `LocalHello` 바로 뒤에 오는 구체적 요청(`LocalHostList` 등)까지 한 번에 읽고 그 요청 하나에 대한 `LocalResponse` 하나만 돌려준다 — 예: `LocalHello{kind=LOCAL_ADMIN} + LocalHostList{}` → 정확히 하나의 `LocalResponse{host_list_result: LocalHostListResult{...}}`(PR 5a가 구현·검증한 그대로; `crates/qsh-proto/proto/qsh/local/v1.proto`의 머리말도 이 구분을 명시한다). **request_id 재매핑:** `LOCAL_CONTROL` conduit 위의 `ControlMessage.request_id`는 CLI 프로세스가 로컬에서 채번한 것이고, 데몬은 이를 자신이 역방향 QUIC connection 위에서 실제로 보내는 `ControlMessage.request_id`로 재매핑해 상관시킨다(여러 CLI 프로세스가 같은 QUIC connection을 공유하므로 채번 공간이 겹칠 수 있다). **다중화 규칙(M3 Step 6, `crates/qsh-core/src/localctl/mux.rs`가 이 표의 순수 상태 기계를 구현):** 이 재매핑 표는 conduit마다 최대 `MAX_INFLIGHT_PER_CONDUIT`(=64 — `crate::server::MAX_INFLIGHT_REQUESTS_PER_CONN`과 같은 크기이지만 서로 다른 것을 세는 독립된 상수이므로 따로 움직일 수 있다)개의 in-flight 항목만 허용한다 — 초과분은 QUIC 연결에 얹지 않고 데몬이 그 자리에서 `RESOURCE_EXHAUSTED`로 답하며, 다른 conduit의 상한이나 전역 `daemon_request_id` 카운터에는 영향이 없다. `Response`가 도착하면 데몬은 그 `daemon_request_id`로 표를 조회해 그것을 채번했던 바로 그 conduit에게만 `peer_request_id`를 복원해 전달한다 — 다른 conduit은 그 응답을 절대 보지 못하며, 조회와 동시에 항목은 표에서 제거된다(모든 삽입은 정확히 한 번의 제거를 갖는다: 응답 도착 / conduit 사망 / QUIC 연결 사망 세 경로 중 하나로만). **비동기 event 라우팅:** `request_id = 0`인 `SessionEvent`는 그 `session_id`를 구독 중인 conduit들에만 전달된다(구독은 그 conduit이 `session.open`/`session.attach` 응답을 받은 시점에 성립) — 모르는(또는 아무도 구독하지 않은) `session_id`의 event는 어느 conduit에도 가지 않고, 구독자 쪽 클라이언트도 낯선 `session_id`의 event는 방어적으로 무시한다. 유일한 예외는 `session.writer_changed`다: `docs/CLI.md` §6.4의 "모든 read 소비자에게 broadcast" 계약을 conduit 단위에서 만족시키기 위해, 구독 여부와 무관하게 그 host에 등록된 **모든** control conduit에 전달된다. **Ping, conduit 사망, QUIC 사망:** conduit이 보낸 `Ping`은 QUIC 연결에 얹지 않고 데몬이 즉시 로컬 `Pong`으로 답한다(liveness는 연결을 실제로 쥔 데몬의 몫이며 CLI로 새어 나가지 않는다). conduit의 UDS 연결이 죽으면 데몬은 그 conduit이 소유하던 in-flight 항목 전량과 event 구독을 표에서 즉시 제거한다(부분 정리 금지 — 누수 없음). 이 표 정리는 로컬 상태에 한정된다: 여러 conduit이 QUIC control 스트림 하나를 공유하므로, 이미 target에 전달된 개별 요청 하나만 취소하는 wire-level 수단은 현재 프로토콜에 없다 — target이 나중에 그 `daemon_request_id`로 응답을 보내면 표에 항목이 없으므로 데몬은 그 응답을 조용히 버린다. 예외는 없다: session 수명은 connection 수명과 분리되어 있다는 것이 이 프로토콜의 핵심 전제(`docs/PRD.md`)이고, 정방향 경로에서 `session.open` 전송 후 `SessionOpened` 수신 전에 CLI 프로세스가 죽어도 target에는 살아 있는 세션이 남아 `session.list`로 조회되고 `session.close`로 닫을 수 있는 것과 마찬가지로, 역방향 relay도 다르게 동작해서는 안 된다 — conduit이 죽은 뒤 도착한 `SessionOpened`도 그대로 버려지고, target이 이미 만든 세션은 정방향 경로와 동일하게 그대로 살아 있으며 `session.list`로 조회 가능하다. 데몬(relay)은 자기 판단으로 control 요청을 발신하지 않는다 — 여기에 비즈니스 로직을 두지 않는다는 원칙이며, 아무도 요청하지 않은 `session.close`를 controller principal 명의로 보내면 target은 그것을 마치 그 principal이 실제로 요청한 것처럼 감사(audit)하게 되기 때문이다. 이 wire 한계 때문에 `SessionRead`/`SessionClose` long-poll은 죽은 conduit이 쥐고 있던 target-side 허용량이 그 자체의 타임아웃(`crate::server::SESSION_READ_MAX_WAIT`)까지 그대로 점유된 채 남을 수 있다 — 데몬은 이를 개별 conduit 사망 이벤트가 아니라 **사전에** 막는다: 이 hub가 한 번에 QUIC 연결에 얹는 long-poll 총량을(살아 있든 죽었든 모든 conduit 합산으로) target 자신의 연결당 상한보다 훨씬 낮게 고정해, 어떤 conduit 조합도 그 공유 자원을 소진할 수 없게 한다(`crate::reverse::listen::MAX_INFLIGHT_LONG_POLL_PER_HUB`). 역방향 QUIC 연결 자체가 죽으면 그 host의 모든 conduit이 명확한 typed error로 함께 끝난다(host 하나의 전체 conduit 집합을 순회하며 위와 같은 전량 정리를 반복하는 것과 동치). **peer credential 검사:** 데몬은 accept한 UDS 연결의 발신 프로세스가 자신과 같은 로컬 사용자인지 `SO_PEERCRED`(Linux)/`getpeereid`(macOS)로 검사한다. **localctl은 인가 계층이 아니다** — 그것은 이미 target의 ACL 몫이다: 데몬이 살아 있는 역방향 연결 위로 `SessionOpen`/`SessionAttach`를 그대로 전달하면 target이 자기 ACL(`session.open` 등)을 controller principal에 대해 평가한다 — **역방향 등록은 도달성만 부여하고 권한은 부여하지 않는다.** **응답 envelope:** 데몬→클라이언트 방향의 모든 frame은 예외 없이 `LocalResponse{oneof body}` 하나다(`LocalHelloAck`/`LocalError`/`LocalHostListResult`가 필드 shape상 서로 구별 불가능하기 때문에 필요 — wire의 `Response{oneof body}`와 같은 이유). 실패 응답은 `LocalError{code, message}`(`code`는 `docs/CLI.md` §3.3 어휘 그대로), `LocalHostList` 요청의 성공 응답은 `LocalHostListResult{repeated LocalHost hosts}`이며 `LocalHost{name, address, state, fingerprint, capabilities, generation, registered_at}`는 데몬의 admin view다(JSON `Host`와는 별개 타입, `docs/CLI.md` §5).
4. **heartbeat의 정체:** 신규 wire 메시지는 없다. 연결 유지는 §2의 15s keep-alive이고, 사망 **감지**는 §10 "Path 사망 감지"와 같은 control 스트림 `Ping`/`Pong` probe다(두 cadence·RTT 비례 deadline·3-strike 판정 정책을 양쪽 role에서 그대로 재사용한다). 연결이 죽으면 controller는 host 목록에서 `state: "stale"`로 표시했다가 `[listen].stale_retention`(기본 120s — target의 `backoff_max_ms`(기본 30000ms)보다 확실히 크게, `stale_retention > backoff_max_ms × 3`) 후 제거한다. target은 사망 판정 후 지수 backoff + jitter(`backoff_initial_ms` 기본 500 → 배수 2 → `backoff_max_ms` 기본 30000, 등록 성공 시 초기값으로 리셋, 무한 재시도)로 재dial하고 `Hello.reverse`를 재전송해 재등록한다. target의 세션들은 재등록과 무관하게 유지되고 §10으로 resume된다.

   **역방향에서의 §10 Reattach 매핑:** 재dial의 주체는 항상 **target**(host role)이지 controller가 아니다 — controller는 target이 새 연결을 세우기를 기다릴 뿐 자신은 아무것도 dial하지 않는다. controller 측 attach driver(§10의 재dial+redemption task에 대응하는 위치)는 registry에서 그 host의 새 `generation` 등록을 기다렸다가, 등록이 관측되면 §10 절차의 2단계(`SessionAttach{session_id, resume_token, last_output_seq}`)부터 그 새 연결 위에서 수행한다 — §10의 1단계("새 QUIC 연결")는 target이 이미 수행했으므로 controller가 이 leg에서 반복하지 않는다. **migration(`Endpoint::rebind()`)은 이 leg에 존재하지 않는다** — target의 재dial 자체가 유일한 복구 경로다.

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
