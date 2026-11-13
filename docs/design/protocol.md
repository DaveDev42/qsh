# QSH Wire Protocol 설계

**상태:** 설계 확정 (2026-08-17)
**적용 범위:** 현재 구현된 `qsh/1` wire 전체
**관련 문서:** [ADR-0001 custom QUIC](../adr/0001-custom-quic-protocol.md) · [ADR-0043 TCP fallback 없음](../adr/0043-no-tcp-fallback.md) · [ADR-0044 SSH 부트스트랩](../adr/0044-ssh-bootstrap.md) · [CLI/JSON 계약](../CLI.md) · [아키텍처](architecture.md) · [테스트 전략](testing.md)

> **규칙:** 구현이 이 문서와 어긋나게 되는 경우, 코드를 우회하지 말고 이 문서(필요 시 ADR)를 먼저 갱신한 뒤 구현한다. JSON envelope·오류 코드·sequence의 사용자 노출 계약은 [docs/CLI.md](../CLI.md)가 canonical이며 여기서는 중복 기술하지 않는다.

## 1. 결정 요약

| 항목 | 결정 |
|---|---|
| QUIC 스택 | quinn (`quinn-proto` **≥ 0.11.14**; 그 미만은 원격 DoS 취약점) + rustls 0.23 (aws-lc-rs provider) + tokio |
| ALPN | `qsh/1` — 호환 파괴 시 `qsh/2`, 추가적 확장은 capability로 |
| 직렬화 | control message = protobuf(prost), 터널 payload = raw bytes |
| 0-RTT | 사용 안 함 (replay 위험) |
| keep-alive / idle | 15s 기본(`[transport].keep_alive_ms`, 1000..=20000) / 45s 고정 |
| mobility | Tier 1 = connection migration(rebind), Tier 2 = session resume |
| congestion control | BBR (quinn 내장) |

## 2. QUIC 스택과 전송 설정

- **quinn 선정 근거:** 순수 Rust·tokio 네이티브·사실상의 커뮤니티 표준. 결정적으로 per-stream 송신 우선순위(`SendStream::set_priority(i32)`)와 fair queuing(`TransportConfig::send_fairness`)을 제공해 "느린 터널이 PTY를 막지 않는다"(PRD §13)를 스케줄러 레벨에서 구현할 수 있다. s2n-quic은 커스텀 인증서 검증(pin+CA 이중 모드)이 provider 추상화 탓에 번거롭고, quiche는 sans-IO C 스타일이라 이벤트 루프·타이머·소켓을 직접 소유해야 한다. **`quinn-proto`는 반드시 0.11.14 이상으로 고정한다**(RUSTSEC-2026-0037의 advisory 대상은 파사드 `quinn`이 아니라 `quinn-proto`다).
- **Connection migration:** 서버측 passive migration(NAT rebind 등, path validation 포함)은 quinn이 자동 처리. 클라이언트는 인터페이스 변화 감지 시 `Endpoint::rebind(new_socket)`으로 active migration. migration은 **지연 최적화일 뿐**이며 실패해도 무방하다 — correctness는 resume(§8)이 보장한다. migration 성공에 의존하는 설계를 하지 않는다.
- **keep-alive 15s(기본값, `[transport].keep_alive_ms`로 조정) / max_idle_timeout 45s(고정, ADR-0021 결정 2):** 15s는 일반적인 30s UDP NAT binding timeout보다 짧아 역방향 target의 장수명 연결을 NAT 뒤에서 유지한다. NAT binding 수명은 망마다 달라서 keep-alive만 `1000..=20000`ms 안에서 열었고, 범위 밖은 clamp 없이 기동 시 `CONFIG_ERROR`다. keep-alive PING은 송신측 로컬 동작이라 한쪽 값이 상대에게 광고되지 않는다. 화면 동기화 attach에서는 키를 적지 않았을 때만 적응 정책(ADR-0052 결정 12(e)·13)이 NAT 재바인딩을 본 뒤 host가 control 스트림 `Ping`(§9의 기존 frame, `request_id` 0)을 `clamp(g / 2, 1 s, 15 s)` 간격으로 더 보낸다. quinn은 연결 도중 keep-alive를 바꿀 수 없어 quinn의 15s PING은 그대로 돌고, 정책은 그 위에 더하기만 하므로 간격은 줄어들기만 한다. 45s는 양 peer가 광고한 값의 min으로 정해져 한쪽만 바꾸면 효과가 없거나 어긋나므로 어떤 키로도 열지 않는다. 절전한 노트북은 45s 후 연결이 죽지만 **세션은 유지**된다(그것이 분리 설계의 목적). 절전 복귀는 클라이언트가 직접 감지한다. 프로세스마다 1초(`WAKE_TICK`)마다 벽시계와 단조 시계를 함께 읽고, 직전 tick 이후 벽시계 증가량이 단조 시계 증가량보다 3초(`WAKE_SKEW`) 이상 크면 절전에서 깨어난 것으로 본다(절전 중에는 단조 시계만 멈춘다). 벽시계가 뒤로 가는 경우는 깨어남으로 치지 않는다. 깨어나면 곧바로 probe하고, 응답이 없으면 약 2초 안에 죽은 연결을 버리고 재다이얼→resume한다(§10 "Path 사망 감지"). idle timeout을 키워 "QUIC 레벨에서 절전 생존"을 추구하지 않는다(listener 메모리 낭비 + 설계와 충돌).
- **0-RTT 금지:** QSH의 control message는 전부 부수효과가 있다(`exec`, `session.write`, tunnel open). 0-RTT early data는 on-path 공격자가 재전송할 수 있으므로 절대 받지 않는다 — 클라이언트는 `into_0rtt()`를 호출하지 않고 서버는 early data를 활성화하지 않는다. TLS 세션 티켓(1-RTT resumption)은 성능상 켤 수 있으나, **티켓 기반 재개에서도 클라이언트 인증서 재검증이 보장되는지 확인**하고 의심스러우면 `NoServerSessionStorage`로 티켓을 끈다. 연결은 장수명이므로 handshake 지연은 중요하지 않다.
- **Admission — 주소 검증은 항상 Retry (ADR-0009):** 실제 handshake(키 유도·상태 버퍼링)를 시작하기 전에, 주소 검증되지 않은 모든 `Incoming`은 부하와 무관하게 무조건 `Retry`로 되돌린다 — 스푸핑된 출발지는 왕복이 완성되지 않는 한 서버 쪽에 아무 상태도 남기지 못한다. 정상 클라이언트가 새 연결마다 지불하는 비용은 왕복 1회뿐이고, 이미 확립된 연결의 migration(위 항목)은 새 `Incoming`을 만들지 않으므로 전혀 영향받지 않는다. 그 위의 `qsh-core::admission::Gate`(handshake 동시성 상한 + source별 rate limit)는 이 프로토콜 결정과 독립적인 정책층이다.

## 3. TLS 상호 인증 — `QshPeerVerifier`

client/server 양쪽 verifier가 **하나의 검증 코어**를 공유한다 (`qsh-transport/src/tls.rs`, rustls `danger` verifier trait 구현):

1. 제시된 leaf 인증서의 **SPKI SHA-256 fingerprint가 로컬 trust store에 pin**되어 있으면 → 허용, principal = 그 pin에 결합된 `device:<name>`/`fp:...`.
2. 아니면 **private CA 체인 검증**(rustls-webpki, 신뢰 root는 trust store의 CA만) 성공 시 → 허용, principal = leaf의 SAN URI(`qsh://user/dave`, `qsh://device/hermes`).
3. 그 외 → 거부. **web PKI root는 어떤 경로로도 로드하지 않는다.**

**client가 이름으로 dial할 때는 판정 범위가 그 이름으로 좁혀진다**(ADR-0060). verifier는 같고 evaluator만 `BoundTrust`로 좁힌다. 이름에 pin이 있으면 그 pin의 fingerprint와 정확히 같은 leaf만 허용하고(다른 pin, CA 체인, 열린 pairing invite 어느 것도 이 연결을 받지 않는다), pin이 없는 이름(`hosts.toml`에만 있는 이름 등)은 CA 체인이 맞는 leaf만 허용한다. 어긋나면 handshake가 실패하므로 client 인증서도 스트림도 가지 않는다. server가 client를 받는 쪽은 이 규칙을 쓰지 않는다. 위 1~3번 그대로, 어느 pin이든 받는다. jump 체인은 단마다 자기 pin 하나로 좁히고(ADR-0056 결정 10), 펀칭은 기대 fingerprint를 견준다(ADR-0054 결정 12). 이제 직접 dial도 같은 규칙이다.

두 경로 모두에서 leaf 인증서의 **유효기간(not_before/not_after)을 검사**한다 — pin 일치라도 만료·미도래 인증서는 거부한다(장기 device cert에서 유효기간은 유일한 revocation 레버이며, 모호하면 fail closed). SNI/hostname은 검증에 쓰지 않는다(identity는 pin 또는 SAN principal이지 DNS 이름이 아니다). 클라이언트는 SNI를 아예 보내지 않는다(rustls `enable_sni = false`, ADR-0040 결정 2). 접속 대상 hostname이 ClientHello에 실리지 않으며, 서버도 SNI를 읽지 않는다.

확립된 연결은 trust 변경 뒤 같은 검증 코어로 재검증된다(`Connection::reverify`, ADR-0031 결정 10). 거부되거나 신뢰 경로가 바뀐 연결은 `0x1005`로 닫히며, wire에 새 바이트는 없다.

양방향 인증서 필수(`client_auth_mandatory`). 검증된 peer identity 없이는 어떤 스트림도 application 계층에 도달하지 않는다. principal은 연결 수립 시 1회 계산되어 연결에 부착되고, ACL은 이것만 사용한다 — **`Hello`의 `device_name` 등 wire 데이터에서 identity를 취하지 않는다.** TLS 1.3 전용(QUIC이 보장).

## 4. ALPN·버전·capability

- ALPN `qsh/1`. 파괴적 wire 개정만 `qsh/2`. ALPN 불일치는 application 상태가 생기기 전에 handshake에서 실패한다.
- major 내 확장은 `Hello.versions`(minor 교집합) + `Hello.capabilities`(문자열 집합 교집합)로 협상한다. 새 기능 = 새 capability 문자열 + 새 optional message. protobuf라 구 peer는 unknown field를 무시하고, 광고하지 않은 capability의 스트림은 받지 않는다. `qsh capabilities` 명령은 협상된 교집합을 그대로 반환한다(CLI.md §6.10).
- 이 build가 광고하는 capability: `exec`, `session`, `resume.v1`, `dial-filter.v1`(ADR-0019 결정 3 — host dialer가 `StreamHeader.deny_host_local`을 준수한다는 뜻, §7 참조).
- `file.v1`(ADR-0029)은 파일 op와 `FILE_DATA` 데이터 평면을 host가 처리한다는 뜻이고, **모든 빌드가 광고한다**(`LOCAL_CAPABILITIES`의 다섯째 항목, 상수 `CAP_FILE_V1`). Windows host도 네 op와 `FILE_DATA`를 처리하므로(ADR-0029 결정 23, ADR-0035 결정 26) 광고 집합은 빌드마다 갈리지 않는다. client는 협상된 교집합에 `file.v1`이 있을 때만 파일 op를 보낸다. `capabilities.json` golden은 모든 빌드에 같은 값이고, Windows 빌드의 대조 테스트(`windows_build_advertises_file_v1`)는 이 항목이 광고되는지만 확인한다.
- `shell-command.v1`(ADR-0051 결정 6)은 host가 명령 문자열 하나를 계정의 셸에 넘겨 실행한다는 뜻이다. `ExecStart`의 `shell_command`·`login_shell`과 `SessionOpen`의 `shell_command`가 이 capability에 딸린 필드이고, 세부는 §7.1이다. **모든 빌드가 광고한다**(상수 `CAP_SHELL_COMMAND_V1`). 옛 host가 이 필드를 건너뛰는 문제 때문에 sender는 협상된 교집합에 이 문자열이 있을 때만 필드를 세팅한다(§16.4, ADR-0019 결정 4와 같은 규칙).
- `screen.v1`(ADR-0052 결정 9)은 host가 세션마다 터미널 에뮬레이터를 돌리고 `SESSION_DATA` 스트림에 `Output` 대신 `ScreenUpdate`를 싣고 `ScreenAck`를 받는다는 뜻이다. **모든 빌드가 광고한다**(`LOCAL_CAPABILITIES`의 마지막 항목, 상수 `CAP_SCREEN_V1`). `SessionOpen.screen`·`SessionAttach.screen`·`SessionOpened.screen_channel`·`SessionAttached.screen_channel`과 `SessionFrame`의 `screen_update`·`screen_ack`·`screen_history`가 여기 딸린 항목이고 세부는 §18.8과 §18.11이다. sender는 협상된 교집합에 이 문자열이 있을 때만 요청 필드를 세팅하고 `ScreenAck`를 보내며, host는 광고하지 않은 peer에게 `ScreenUpdate`를 보내지 않는다(§16.4). `datagram.v1`(ADR-0052 결정 9, 상수 `CAP_DATAGRAM_V1`, `LOCAL_CAPABILITIES`의 마지막 항목)도 모든 빌드가 광고한다. 이 peer가 화면 동기화 attach의 channel id로 오는 `ScreenUpdate`·`ScreenAck`·`Input` datagram을 처리한다는 뜻이다. 양쪽이 광고하고 transport가 `max_datagram_size()`를 `Some`으로 알려 줄 때만 datagram을 쓰고, 세부는 §18.9다.
- `screen-echo.v1`(ADR-0053 결정 3)은 화면 동기화 attach에서 host가 `ScreenEcho`를 보내고(`SessionFrame` 10, `DatagramFrame` 종류 13) client가 해석한다는 뜻이다. **모든 빌드가 광고한다**(`LOCAL_CAPABILITIES`의 마지막 항목, 상수 `CAP_SCREEN_ECHO_V1`). host는 협상된 교집합에 이 문자열이 있고 화면 동기화 attach일 때만 보내고, 없는 peer는 `SessionFrame` 10도 종류 13도 받지 않는다. client도 협상되지 않았으면 받은 `ScreenEcho`를 버린다. 세부는 §18.12다.
- `punch.v1`(ADR-0054 결정 9)은 이 peer가 홀펀칭 신호 message(`PunchRequest`·`PunchOffer`·`PunchReply`·`PunchAnswer`·`RendezvousQuery`·`RendezvousList`)를 이해하고 자기 역할에서 처리한다는 뜻이다. **모든 빌드가 광고한다**(`LOCAL_CAPABILITIES`의 마지막 항목, 상수 `CAP_PUNCH_V1`). `[punch].mode = "off"`여도 광고하고 요청에는 `UNSUPPORTED`로 답한다. 광고하지 않은 peer에게는 이 message를 보내지 않는다(§16.4). 세부는 §19다.
- `agent.v1`(ADR-0055 결정 3)은 이 peer가 host로서 `SessionOpen`·`SessionAttach`·`ExecStart`의 `agent_channel`을 처리해 `AGENT` 스트림을 열고, client로서 `AGENT` 스트림을 받는다는 뜻이다. **모든 빌드가 광고한다**(`LOCAL_CAPABILITIES`의 마지막 항목, 상수 `CAP_AGENT_V1`). 광고하지 않은 peer에게는 `agent_channel`을 세팅하지 않는다. 옛 host는 모르는 필드를 버리므로 확인 없이 보내면 client가 forwarding이 켜졌다고 착각한다(§16.4, ADR-0019 결정 4와 같은 규칙). 세부는 §20이다.
- `jump.v1`(ADR-0056 결정 3)은 이 peer가 중간 peer로서 `JUMP` 스트림과 종류 14 datagram을 처리한다는 뜻이다. **모든 빌드가 광고한다**(`LOCAL_CAPABILITIES`의 마지막 항목, 상수 `CAP_JUMP_V1`). client는 협상된 교집합에 이 문자열이 있는 hop에만 `JUMP`를 연다. 교집합에 없는 연결의 `JUMP` 스트림은 host가 모르는 종류로 거절한다(`BAD_HEADER` reset, 판정도 소켓도 없다). 세부는 §21이다.

## 5. Frame layer

모든 control·data 스트림의 메시지는 `u32` big-endian length prefix + prost 인코딩 body다. **선언된 길이는 버퍼 할당 전에 상한 검사**한다:

| 대상 | 상한 |
|---|---|
| control 스트림 frame | 256 KiB (`CONTROL_FRAME_MAX`) |
| data 스트림 frame | 64 KiB (`DATA_FRAME_MAX`) |
| PTY/exec payload chunk | 16 KiB (frame 내부 data 필드) |

이 frame codec은 `crates/qsh-proto/src/frame.rs`에 구현돼 있다. 상한 초과는 즉시 연결 종료. `Vec::with_capacity(attacker_length)`는 어떤 경로에도 존재해서는 안 된다.

**예외 — 터널 스트림:** 초기 `StreamHeader`/응답 교환 후에는 frame 없이 **raw bytes**를 흘린다(순수 파이프, `copy_bidirectional`). per-chunk 오버헤드 제거가 "raw QUIC 대비 throughput ≥80%"(PRD §13)의 달성 수단이다.

## 6. 직렬화 — protobuf(prost)

근거: (1) CLI.md §2.3의 "unknown field 무시, major 내 additive-only" 규칙이 protobuf tagged field의 네이티브 시맨틱이다(postcard는 위치 인코딩이라 필드 추가가 구 디코더를 깨뜨리고, CBOR은 스키마 산출물이 없다). (2) prost 디코더는 malformed 입력에 panic 없이 실패하며, `.proto` 파일 자체가 보안 리뷰 산출물이자 structure-aware fuzzing 문법이 된다. (3) P2 mobile SDK·별도 relay 제품의 cross-language 표면. `.proto` 소스는 `crates/qsh-proto/proto/qsh/wire/v1.proto`에 둔다.

## 7. 스트림 배치

connection당 **control 스트림 1개** + 리소스별 스트림. 비-control 스트림은 첫 frame의 `StreamHeader`로 자기 식별하며, QUIC stream ID 등 transport 고유 개념에 의존하지 않는다(ADR-0005의 transport 불가지 원칙).

| 스트림 | 여는 쪽 | 유형 | 내용 |
|---|---|---|---|
| Control | dialer가 handshake 후 첫 bidi | bidi, 연결당 1개 | `Hello` 교환 후 양방향 `ControlMessage` RPC(role 대칭), heartbeat, 비동기 event |
| Session data | attach하는 쪽, attach당 1개 | bidi | `StreamHeader{SESSION_DATA, ticket}` 후 framed `Output/Input/InputAck/Gap/Resize/Exit` |
| Exec data | exec 요청자, exec당 1개 | bidi | `StreamHeader{EXEC_DATA, ticket}` 후 framed `Stdin/StdinEof/Stdout/Stderr/ExecExit` |
| File data | 요청자, `file.read`/`file.write` 전송당 1개 | bidi | `StreamHeader{FILE_DATA, ticket}` 후 framed `FileFrame{data/end/result}`(ADR-0029 결정 9, 아래 문단) |
| Tunnel (local fwd) | local listener 쪽, TCP 연결당 1개 | bidi | `StreamHeader{TCP_CONNECT, host, port}` → `ConnectResult{ok, code, message}` → (ok면) raw bytes |
| Agent | host, agent 소켓에 들어온 로컬 연결당 1개 | bidi, host → client | `StreamHeader{AGENT, ticket = agent_channel}` 후 ssh-agent 프로토콜 바이트 그대로(§20, ADR-0055 결정 4) |
| Jump | client, `-J` hop당 1개 | bidi, client → 중간 peer | `StreamHeader{JUMP, ticket = jump_channel, host, port}` → `ConnectResult{ok, code, message}` → (ok면) `u16` BE 길이 + 패킷 바이트의 반복(§21, ADR-0056 결정 3·4) |
| Tunnel (remote fwd) | remote port를 bind한 쪽, accept당 1개 | bidi | `StreamHeader{TCP_ACCEPTED, forward_id}` → raw bytes |

**Ticket:** `SESSION_DATA`/`EXEC_DATA`용 ticket은 128-bit 난수, **해당 control 요청이 ACL을 통과한 뒤에만 발급**, 단회용, 30s 만료. 스트림이 인가받지 않은 리소스에 붙는 것을 구조적으로 차단한다("인증·인가 전 리소스 생성 금지", PRD §9). 예외는 `TCP_CONNECT`(local forward)와 `JUMP`다 — per-connection RPC 왕복을 피하려 스트림 오픈 시점에 각각 `forward.local`, `forward.jump` ACL을 inline 검사하고, 거부 시 아무것도 dial하지 않는다(`JUMP`는 소켓도 채널도 만들지 않는다, ADR-0056 결정 7, §21.3). 거부 teardown은 아래.

**`FILE_DATA`(ADR-0029 결정 9).** `FileReadOpen`/`FileWriteOpen`이 ACL을 통과한 뒤 발급되는 ticket으로만 열린다. 프레임은 §5 그대로(`u32`-BE length prefix + prost, `DATA_FRAME_MAX` 상한)이고 `data` 청크는 `FILE_CHUNK_MAX`(32 KiB) 이하다. `FileEnd{size, blake3}`가 바이트열을 닫고, `FileWriteResult`는 `file.write` 스트림에서 host가 요청자에게만 보낸다. 청크 상한 초과·`end` 뒤의 frame·요청자가 보낸 `result`·`FileWriteOpen.size`를 넘는 바이트·`end` 없이 끝난 요청자 send half는 `BAD_HEADER`(`0x2001`) reset이다. 알 수 없거나 이미 쓴 ticket도 같은 reset이다. 송신은 band 0이고 `SEND_DEPTH_CAP_BYTES`(128 KiB)마다 양보한다(ADR-0029 결정 15). 아래 두 흐름이 host의 동작이다.

- `file.read`: host가 `data`를 보내고 마지막에 실제로 보낸 바이트의 `FileEnd{size, blake3}`를 보낸 뒤 `finish()`한다. 읽는 도중 실패하면 `end` 없이 reset(`0x2007`)해서 잘린 전송이 정상 끝으로 보이지 않는다. 요청자는 header 뒤에 아무것도 보내지 않는다.
- `file.write`: 요청자가 `data`, `end`를 보내고 send half를 `finish()`한다. host는 대상 디렉터리 fd 안에 임시 파일 `.<name>.qsh-<16 hex>.part`(`O_EXCL|O_NOFOLLOW`, `0600`)를 만들어 받은 바이트를 쓰고 BLAKE3-256을 센다. 받은 총 길이와 해시가 `end`와 `FileWriteOpen.size`에 모두 맞을 때만 `fsync`, `fchmod`(`-p`면 `futimens`)를 하고, `overwrite`면 `renameat`, 아니면 `linkat`과 `unlinkat`으로 제자리에 놓은 뒤 디렉터리를 `fsync`한다. 결과는 `FileWriteResult` 한 frame과 `finish()`다. 불일치와 `--no-clobber`의 `EEXIST`는 `ok=false`, `INVALID_ARGUMENT`이고 `ENOSPC`는 `RESOURCE_EXHAUSTED`다. 실패, 취소, 연결 유실, 정체 장부의 끊음, 프로토콜 위반 어느 경우든 임시 파일은 지워지고 대상은 그대로다. 전송 slot은 결과 frame을 보내기 전에 놓는다.

`FileListOpen`/`FileMkdirOpen`은 control 스트림 안에서만 답하며 `FileListed` 한 페이지는 `FILE_LIST_PAGE_MAX`(512)개 항목으로 `CONTROL_FRAME_MAX` 안에 들어간다(`FILE_LIST_DIR_MAX` 65536은 디렉터리당 상한).

**파일 op의 host 쪽 순서(ADR-0029 결정 8).** 앞 단계가 실패하면 뒤 단계는 돌지 않는다. 1) 경로 모양 검사와 home 해석(`file::guard::shape_path`) — 실패는 `INVALID_ARGUMENT`(비 unix host는 `UNSUPPORTED`), 판정할 것이 없으므로 ACL도 audit도 없다. 2) ACL choke point — 근거 판정(`Authorizer::has_file_grant`)이 참일 때만 정규화하고, 경로 문자열 그대로가 audit `resource`다. 근거가 없는 요청은 정규화기를 부르지 않는다. 3) `user@` 힌트가 serve 계정과 다르면 `UNSUPPORTED`(허용된 뒤에만). 4) 상태 경로 판정 — 보호 집합에 들면 거절하고 audit 한 줄이 더 남는다. 5) `file.read`/`file.write`의 전송 quota. 6) 디렉터리 fd 기준으로 열고 연 핸들의 실제 경로를 보호 집합과 평가기에 다시 대조한다(불일치는 audit 한 줄 추가). `file.read`는 보호 inode와 파일 종류도 본다. 7) 응답: `file.read`/`file.write`는 연 fd를 묶은 ticket(`FileReadOpened`/`FileWriteOpened`)을, `file.list`/`file.mkdir`은 결과를 바로 돌려준다. ticket은 §7의 다른 ticket과 같이 128비트·단회·30초이고 연결당 예산을 공유하며, 소비되지 않고 만료되거나 연결이 끊기면 fd와 quota slot이 풀린다. 정책으로 인한 거절은 모두 같은 `PERMISSION_DENIED`다(행 없음, `paths` 없음·밖, 정규화 실패, 상태 경로, 재검증 불일치, 보호 inode, 보호 inode 스캔 실패, OS `EACCES`). `FILE_DATA` 스트림은 받는 pump가 아직 없어 `BAD_HEADER`로 닫힌다.

**`ConnectResult`(§9의 data-stream message, `qsh.wire.v1`):** `{ bool ok = 1; string code = 2; string message = 3; }`. frame layer는 위와 같은 §5 재사용(`u32`-BE length prefix + prost, `DATA_FRAME_MAX` 상한)이며, `ok = true` 이후로는 frame 없이 raw bytes로 전환된다(§5의 터널 스트림 예외). `ok = false`일 때 `code`는 CLI.md §3.3 어휘에서 온다 — dial 실패는 `CONNECTION_FAILED`, 위 inline ACL 거부는 `PERMISSION_DENIED`.

**`TCP_CONNECT`의 host 모양 검사(ADR-0019 결정 5):** ACL choke point 이전, 길이 검사(255바이트)와 같은 자리에서 `header.host`를 바이트 단위로 본다. ASCII 제어문자, 공백, DEL, 비ASCII 바이트가 하나라도 있으면 `INVALID_ARGUMENT`로 거절한다 — 판정할 것이 없는 요청이므로 ACL도 audit도 dial도 없다. `-L`이 보낸 `TCP_CONNECT`에도 똑같이 적용된다.

**host-local dial 필터(ADR-0019 결정 3):** `StreamHeader.deny_host_local`(§9 필드 5)이 참이면, host dialer는 이름 해석 결과 주소마다 `connect` 직전에 다음 범주를 검사하고 해당하면 연결하지 않는다 — loopback(`127.0.0.0/8`, `::1`), "이 망"(`0.0.0.0/8`; unspecified `0.0.0.0`/`::` 포함), link-local(`169.254.0.0/16`, `fe80::/10`), multicast, IPv4 broadcast(`255.255.255.255`), 그리고 위 주소들의 IPv4-mapped·IPv4-compatible IPv6 표기. 해석은 한 번만 하고 그 결과로만 연결을 시도하므로 검사와 연결 사이에 재해석 경합이 없다. 해석된 주소가 전부 이 범주에 들면 dial을 시도하지 않고 `ConnectResult{ok:false, code:PERMISSION_DENIED}`를 돌려주며, `AuditRecord::connection_level` 모양으로 `action=forward.local, decision=deny, rule=null`인 audit 한 줄을 쓴다(§7 "인가 순서" 위 `forward.local` ACL 판정과는 별개의, 추가되는 한 줄이다 — 이 필터는 ACL 규칙이 아니라 dial 정책이다). 해석된 IP 자체는 audit에도 로그에도 남기지 않는다. 이 필드를 준수하는 것은 `dial-filter.v1` capability(§4)를 광고한 host뿐이다 — 광고하지 않은 구버전 host는 필드를 무시하고 오늘과 같이 무필터로 동작한다.

**거부 teardown(`TCP_CONNECT`):** 거부는 `ConnectResult{ok:false, code}`를 **먼저 쓰고**, 송신 half를 `finish()`로 닫고, 수신 half를 사유에 맞는 코드로 `stop()`한다 — `PERMISSION_DENIED`면 `FORBIDDEN`(0x2003), `INVALID_ARGUMENT`면 `BAD_HEADER`(0x2001), `RESOURCE_EXHAUSTED`면 `RESET_CODE_RESOURCE_EXHAUSTED`(0x200D — principal별·forward별 터널 스트림 quota 초과), 목적지가 그냥 받아주지 않은 경우는 누구의 프로토콜 오류도 아니므로 0이다. **송신 half를 reset하지 않는 것이 요점이다**: QUIC `RESET_STREAM`은 아직 전달되지 않은 스트림 데이터를 버리므로, 방금 쓴 `ConnectResult`를 reset이 그대로 파괴할 수 있다 — 이 절이 요구하는 "요청자가 거부 사유를 `code`로 읽는다"가 전달 경쟁에 걸린다. 그렇다고 거부가 느슨해지지는 않는다. dial은 0건이고, splice는 시작되지 않으며, 수신 half가 stop된 스트림에는 요청자가 더 쓸 수 없다 — 거부는 그대로 종단이다. 구현은 `crates/qsh-core/src/server/tunnels.rs`의 `handle_tcp_connect`.

**splice 중단 신호:** `ok = true` 이후 raw byte 구간이 오류로 끊기면 잘린 전송이 정상 EOF로 보여서는 안 된다 — 응용은 그 차이를 탐지할 수 없고, 그것이 조용한 데이터 손실이다. 그래서 splice는 실패 시 QUIC 스트림을 `RESET_STREAM`/`STOP_SENDING` 코드 `0x2007`로 reset하고 로컬 TCP 소켓은 `SO_LINGER 0`으로 닫아 RST를 보낸다. 양쪽 응용이 관측하는 것은 연결 오류이며, 그것이 사실이다. 정상 종료는 반대로 방향별 half-close다 — 한 방향의 EOF는 그 방향 writer만 닫고(QUIC `finish()` / `shutdown(SHUT_WR)`) 반대 방향은 자기 EOF까지 계속 흐른다(`nc -N`, HTTP request body, tunnel 위의 `git`). `0x2007`은 `RESET_CODE_*`와 같은 내부 코드이지 wire 계약이 아니다 — peer가 알아야 할 것은 "정상 종료가 아니다" 하나이고 그건 reset 자체가 전달한다. 구현은 `crates/qsh-core/src/tunnel/splice.rs`. 연결의 정체 장부(§12, ADR-0037)가 터널 스트림을 끊을 때도 teardown은 같고 코드만 `0x200E`(`RESET_CODE_TUNNEL_STALLED`)다. 진단과 audit에서 "splice가 오류로 끊겼다"와 "정체 상한으로 끊었다"를 가르려는 값이며, 받는 peer는 이 값으로 분기하지 않는다(§16.5).

**동시성 상한:** 한 연결이 동시에 여는 `TCP_CONNECT` 스트림 수는 연결 전체의 bidi 스트림 상한(`MAX_CONCURRENT_BIDI_STREAMS = 1024`, `crates/qsh-transport/src/endpoint.rs`)이 묶는다. 동시 터널 스트림과 그것이 붙잡는 upstream fd는 연결당 1024개로 유계이고, 그 peer는 mTLS로 pin된 상대다.

이보다 좁은 터널 전용 할당량은 별도 상한이다([ADR-0010](../adr/0010-resource-quotas.md)). `[serve].max_tunnel_streams_per_principal`(기본 256)과 `[serve].max_tunnel_streams_per_forward`(기본 64, `(principal, host:port)` 축)를 `authorize_and_dial_tunnel`이 dial하기 전에 검사하고, 초과는 `RESOURCE_EXHAUSTED`로 거부되며 dial은 0건이다. 구현은 `crates/qsh-core/src/quota.rs`의 `Quotas::reserve_tunnel_stream`.

**remote forward 리스너 개수.** 위 1024는 *스트림* 상한이고, `RemoteForwardOpen`이 여는 것은 스트림이 아니라 listener다(host에 TCP listener 하나·fd 하나·`serve_remote_forward` task 하나). `forward.remote`를 가진 principal이 서로 다른 `bind_port`로 요청을 반복하면 매번 새 control 요청-응답이라 스트림 상한이 동시 listener 수를 묶지 못한다. 그래서 `[serve].max_remote_forwards_per_principal`(기본 16, principal별)이 따로 있다([ADR-0010](../adr/0010-resource-quotas.md)). `authorize_and_bind_remote_forward`가 loopback 강제 뒤·`binder.bind` 직전에 검사하고, 초과는 소켓을 하나도 띄우지 않고 `RESOURCE_EXHAUSTED`로 거부된다. 구현은 `crates/qsh-core/src/quota.rs`의 `Quotas::reserve_remote_forward`.

**`forward_id`:** remote forward(`-R`)가 host 쪽에 뜬 listener에 들어온 accept 하나하나를 식별하는, host가 발급하는 opaque URL-safe 문자열이다. peer가 audit field로 쓸 수 있으므로 `session_id`와 같은 규율을 적용한다 — ACL choke point 이전에 모양(`1..=64` 바이트, `[A-Za-z0-9_-]`)을 검사하고 아니면 `INVALID_ARGUMENT`다(§9 "세션 id는 모양부터 검사한다"와 동일 패턴, `qsh-proto::wire`가 검증기를 제공한다). `TCP_ACCEPTED` 스트림은 이 `forward_id`를 `StreamHeader.ticket`에 담아 나른다.

**`RemoteForwardOpen`의 인가 순서:** `TCP_CONNECT`와 달리 `RemoteForwardOpen`은 control 왕복이 있는 요청-응답이므로 인라인 검사로 도망칠 이유가 없다 — 리스너를 bind하기 전에 control 요청 하나로 `Authorizer::check(principal, auth_path, Action::ForwardRemote, "bind_host:bind_port")` + audit을 거치고, 통과한 뒤에도 loopback 강제가 **별도 단계**로 남는다: `bind_host`가 loopback(`127.0.0.0/8`·`::1`, 이름은 해석 후 판정)이 아니면 `INVALID_ARGUMENT`고 소켓은 하나도 뜨지 않는다. 두 단계는 판정 성격이 다르다 — 앞은 principal이 `forward.remote`를 가졌는지(ACL, `PERMISSION_DENIED`), 뒤는 그 principal이 **가졌어도** 통과 못 하는 host 쪽 요청 제약(`INVALID_ARGUMENT`, `docs/PRD.md` §9)이다. 순서는 항상 authorize → loopback 검사 → bind 하나뿐이고, 앞 두 단계 중 하나라도 실패하면 그 뒤 단계는 실행되지 않는다(구현은 `crates/qsh-core/src/server/reverse.rs`의 `authorize_and_bind_remote_forward`). **정방향 연결의 `TCP_ACCEPTED` 방향:** bind한 listener에 들어온 accept마다 host(요청 수신자)가 `StreamHeader{TCP_ACCEPTED, forward_id}`를 host → 요청자 방향으로 연다 — `SESSION_DATA`/`TCP_CONNECT`처럼 요청을 보낸 쪽이 여는 것이 아니라, 리소스(bind한 소켓)를 실제로 쥔 쪽이 여는 것이다. 역방향 연결 위에서 이 방향이 뒤집히지 않고 그대로 유지되는 이유(target이 여전히 여는 쪽)는 §11의 대칭 원칙 문단이 다룬다.

**`RemoteForwardClose`의 인가 순서:** 소유 축은 `RemoteForwardOpen`을 처리한 connection(`conn_id`)이 아니라 그것을 보낸 **principal**이다. 그 principal이 다른 connection으로 재접속해도 자신이 연 forward는 닫을 수 있어야 하고, `conn_id`는 resume마다 죽어 소유 축으로 부적합하기 때문이다(connection이 죽었을 때의 정리는 여전히 `conn_id` 축이다). 순서는 3단계다.

1. 모양 검사: 위 `forward_id` 문단과 같은 `INVALID_ARGUMENT` 규율이며, 아직 어떤 상태도 건드리지 않는다.
2. owner 조회: host의 `forward_id → owner` 등록표를 **읽기만** 한다. 판정은 하지 않는다. `RemoteForwardOpen` 성공 시 등록되는 owner는 요청한 `(principal, auth_path)`다.
3. `Authorizer::check(principal, auth_path, Action::ForwardRemote, resource)` + audit: `session.control`의 ownership 게이트와 같은 헬퍼를 쓴다. 2에서 알려지지 않은 `forward_id`는 owner 없이 3에 들어가고, owner 없는 리소스는 scope 판정에서 걸러지지 않는다([architecture.md](architecture.md) §6).

3을 통과한 뒤에야 listener를 remove+abort한다. 통과했는데 그 시점에 이미 알려지지 않은 id였다면(경쟁으로 이미 닫힌 경우 등) "닫을 것이 없었다"는 성공으로 답하고 아무것도 다시 만들지 않는다.

**존재 오라클.**
- `forward.remote` 권한 자체가 없는 principal은 owner 유무와 무관하게 principal-일치 단계에서 걸리므로, 실재하지 않는 `forward_id`와 실재하되 남의 것인 `forward_id`에 대한 판정이 byte-for-byte 동일하다(`session_loopback.rs`의 `denied_peer_cannot_learn_whether_a_session_exists`와 같은 원칙).
- `forward.remote`를 가진 principal에게는 둘이 갈린다. 남의 owner를 가진 `forward_id`는 `scope = "owned"`가 걸러 3에서 `PERMISSION_DENIED`이고, 알려지지 않은 `forward_id`는 3을 통과해 remove 단계에서 "등록표에 없음"으로 `INVALID_ARGUMENT`("no such forward_id", CLI.md §6.9)를 받는다. `session.write`/`resize`가 남의 세션에는 `PERMISSION_DENIED`, 없는 세션에는 (ACL 통과 뒤 broker 조회에서) `SESSION_NOT_FOUND`를 주는 것과 같은 트레이드오프다.

이 principal 축은 §11-3의 localctl 쪽 conduit 소유권(`ControlHub`의 `owner: ConduitId`, 같은 머신 위 두 CLI 프로세스를 구별하는 문제)과 별개 계층이다. 이쪽은 원격 QUIC peer가 누구인지, 저쪽은 그 peer를 대신해 로컬에서 요청한 프로세스가 어느 것인지를 답한다.

**연결 CLOSE 코드.** 연결 전체를 닫는 `APPLICATION_CLOSE` 코드는 `0x100x` 대역이고 위 RESET 코드(`0x200x`)와 달리 스트림이 아니라 연결에 붙는다. peer는 이 값에 따라 분기하지 않는다(진단·audit 상관관계용이다). 가장 새 값 `0x1005`(`CLOSE_CODE_TRUST_WITHDRAWN`)는 로컬 trust store가 더는 그 연결을 보증하지 않아 닫을 때 쓰고(ADR-0031 결정 7), reason은 주체나 사유를 싣지 않는 고정 문자열 `trust withdrawn`이다. `0x1006`(`CLOSE_CODE_NOT_ADOPTED`)은 펀칭 경주에서 채택되지 않은 연결을 닫을 때 쓰고 reason은 고정 문자열 `not adopted`다(ADR-0054 결정 15, §19.6). 값 목록과 동결 지위는 §16.3·§16.5다.

### 7.1 셸 명령: `shell_command`와 `login_shell` (ADR-0051 결정 6)

`qsh host command...`는 ssh처럼 인자를 공백 하나로 이어 한 문자열로 만들고, 그 문자열을 원격 계정의 셸이 실행하게 한다. argv 의미(`qsh exec host -- argv`, 셸 없음)는 그대로이고, 문자열은 별도 필드로 간다.

| 메시지 | 필드 | 뜻 |
|---|---|---|
| `ExecStart` | `optional string shell_command = 4` | 이 문자열을 host 계정의 셸에 넘긴다. 빈 문자열도 명령이다(`ssh host ''`는 `-c ''`). 그래서 `optional`이다 |
| `ExecStart` | `bool login_shell = 5` | 계정의 로그인 셸 자체를 PTY 없이, `-c` 없이 띄운다(`qsh -T host`). 명령은 stdin에서 읽는다 |
| `SessionOpen` | `optional string shell_command = 7` | `qsh -t host command`. PTY 안에서 같은 셸 규칙으로 실행한다. 로그인 셸은 이미 빈 `argv`다 |

**배타성.** `ExecStart`의 `argv`(비어 있지 않음)·`shell_command`·`login_shell`은 정확히 하나만 올 수 있고, `SessionOpen`은 비어 있지 않은 `argv`와 `shell_command`를 같이 보낼 수 없다. 어긴 요청과 NUL을 품은 문자열은 `INVALID_ARGUMENT`이고, 판정은 `ExecStart::target`·`SessionOpen::shell_command_checked`(`crates/qsh-proto/src/wire.rs`, `decode_control` fuzz 타깃이 연쇄 호출한다)가 한다. 이 검사는 호출자에 의존하지 않으므로 ACL 결정 앞에 있어도 존재 오라클이 되지 않는다. 오류 문면은 명령을 되풀이하지 않는다.

**host의 셸 선택.**
- unix: 계정의 비밀번호 DB 셸에 `-c <문자열>`. 비어 있거나 실행할 수 없으면 `/bin/sh`다(`sshd`와 같은 폴백, `pty::posix`의 `Account::login_shell`). 로그인 셸은 `-c` 없이 그 셸만 띄운다. `exec`의 환경은 기존 규칙(`pinned_identity_env`)을 따르고 PTY 세션의 환경은 기존 세션 규칙을 따른다. PTY 안의 명령은 `sshd`처럼 로그인 셸 접두(`-zsh` 같은 argv[0])를 쓰지 않는다.
- Windows: Win32-OpenSSH 규칙이다. `HKLM\SOFTWARE\OpenSSH\DefaultShell`이 있으면 그 셸에 `DefaultShellCommandOption`(없으면 `/c`)을 붙이고, 없으면 `cmd.exe /c`다(`cmd.exe`는 자식 환경의 `COMSPEC`, 없으면 `<SystemRoot>\System32\cmd.exe`의 전체 경로). 빈 값은 없는 값으로 본다. 문자열은 명령줄 끝에 **그대로** 붙는다. C 런타임식 인용으로 한 인자에 감싸지 않는다(`cmd.exe`는 그 인용을 풀지 않는다). 선택 규칙은 `crates/qsh-core/src/shell.rs`의 순수 함수라 모든 OS에서 단위 테스트된다. 레지스트리를 읽는 곳은 Windows 전용 `winproc::default_shell_config`뿐이다.

**권한과 순서.** 셸 요청도 `exec.run`(PTY는 `session.open`) ACL 한 번을 거치고, 그 앞에서는 아무것도 spawn되지 않으며 ticket도 나가지 않는다. audit 기록은 action·decision·principal 같은 구조 필드뿐이라 문자열을 싣지 않는다. host의 `ExecSpec`·`SessionSpec`에서 문자열은 `Debug`가 길이만 찍는 `ShellRequest`에 담긴다.

**옛 host를 알아보는 방법.** 필드 4·5(`ExecStart`)와 7(`SessionOpen`)을 모르는 host는 건너뛰고 빈 `argv`를 받는다. 조용히 틀린 동작(로그인 셸을 연다)이 되므로 §16.4의 ADR-0019 결정 4 규칙대로 sender가 `Hello`로 협상된 `shell-command.v1`을 확인한 뒤에만 필드를 세팅한다. 없으면 client는 아무것도 보내지 않고 `UNSUPPORTED`로 끝난다(host에 audit도 ticket도 생기지 않는다. 문면은 `crates/qsh-core/src/ops/exec.rs`의 `SHELL_COMMAND_UNSUPPORTED_MESSAGE`이고 `docs/CLI.md` §6.8이 그대로 싣는다). 반대로 이 host는 capability를 협상하지 않은 peer가 필드를 보내면 `UNSUPPORTED`로 답한다. 새 peer가 보낸 요청을 옛 host가 받는 경우는 sender의 확인으로 일어나지 않고, 옛 client가 보낸 요청에는 새 필드가 없어 기본값(`None`/`false`)으로 읽힌다(`an_old_peer_skips_the_shell_fields_and_sees_an_empty_argv`).

## 8. Sequence 시맨틱 (wire 관점)

사용자 노출 계약은 [CLI.md §2.3, §6.4] 참조. wire에서도 동일 모델을 쓴다:

- `sequence`는 세션 수명 동안 **누적된 output byte 수(u64)**다. `Output` frame의 `sequence`는 해당 chunk까지 포함한 누적 offset(= chunk 마지막 byte offset + 1).
- replay 요청(`last_output_seq = N`)은 "누적 offset N 이후 byte"를 의미하며, 서버는 chunk를 자유롭게 분할·병합해 **정확히 N에서 끊어** 재전송할 수 있다. UTF-8 경계·`--limit-bytes` 절단 문제가 원천적으로 없다.
- input 방향도 동일한 누적 byte offset(`input_seq`)을 쓴다. input 재전송/중복 제거는 wire 내부 동작이며 CLI 계약에는 노출되지 않는다.

## 9. `.proto` 계약 (v1)

정본은 `crates/qsh-proto/proto/qsh/wire/v1.proto`다. `Response.Error.code`는 CLI.md §3.3의 오류 코드 문자열을 **그대로** 사용한다(wire→JSON 번역표 없음, 어휘 단일화).

```protobuf
// Control 스트림 양방향. 요청은 request_id를 갖고 Response가 상관된다.
// 비동기 event는 request_id = 0.
message ControlMessage {
  uint64 request_id = 1;
  oneof body {
    Hello               hello = 10;
    Response            response = 11;      // 성공 payload 또는 Error — 상세는 아래 Response 참고

    SessionOpen         session_open = 20;  // argv, env, term, cols, rows, optional shell_command(7, §7.1),
                                            //   agent_channel(9, bytes, agent.v1, §20), optional user(hint; `qsh user@host`의 user — 검사 순서는
                                            //   ACL session.open → hint → spawn; serve 계정 login name과
                                            //   다르면 세션 생성 없이 UNSUPPORTED, 미인가 peer는 항상
                                            //   PERMISSION_DENIED, CLI.md §7)
                                            // -> SessionOpened{session_id, resume_token, ticket, initial_seq,
                                            //      expires_at, screen_channel, agent(7, AgentGrant, §20)}
                                            //    session_id는 opaque·URL-safe; session_ref는 클라이언트가
                                            //    조립한다(ADR-0007). expires_at = 토큰/세션 TTL 만료 시각
                                            //    (클라이언트 resume.json 정리용)
    SessionAttach       session_attach = 21;// session_id, resume_token, last_output_seq,
                                            //   mode(AttachMode: UNSPECIFIED=0|RW=1|RO=2), no_steal,
                                            //   agent_channel(7, bytes, agent.v1, §20)
                                            //   — writer lease는 명시적 RW에만 요청된다. UNSPECIFIED(필드
                                            //   미설정)·미지 값은 INVALID_ARGUMENT, 절대 RW로 취급하지
                                            //   않는다. RO=2는 번호만 확보(관찰자 모드는 없다,
                                            //   ROADMAP §3) — 호스트는 INVALID_ARGUMENT로 답한다
                                            // -> SessionAttached{ticket, new_resume_token,
                                            //      replay_from, writer_lease, expires_at, input_seq, output_end,
                                            //      screen_channel, agent(9, AgentGrant, §20)}
                                            //    (output_end: attach 승인 시점의 출력 끝 offset, additive 필드 7 —
                                            //     [replay_from, output_end)가 재생분이고 TUI 렌더러만 쓴다)
    SessionList         session_list = 22;  // -> SessionInfo[] — wire SessionInfo는
                                            //    session_id/state/writer(optional)/created_at/last_sequence만
                                            //    담는다. CLI.md §5 Session의 session_ref·host는 클라이언트
                                            //    Ops가 로컬 alias로 채운다(ADR-0007)
    SessionGet          session_get = 23;   // session_id -> SessionInfo
    SessionResize       session_resize = 24; // session_id, cols, rows -> SessionResized{cols, rows}
                                            //   (호스트가 실제 적용한 크기); detached resize; ACL session.control
    reserved 25;                             // (구 SessionSignal) 번호만 예약, P1. 호스트는 25번 수신 시
                                            //   리소스 생성 없이 UNSUPPORTED로 답한다(CLI.md §2.4).
                                            //   구현 메모: prost는 unknown field를 버리므로 25 같은 예약·
                                            //   미지 번호는 body 없는 ControlMessage로 디코드되고, 호스트는
                                            //   body 없는 메시지를 일괄 UNSUPPORTED로 답한다
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
                                            //   (CLI.md §6.4 `session read --wait`/`--follow` 루프);
                                            //   ACL session.attach, resume token 불요(CLI.md §6.3)
    SessionWrite        session_write = 28; // session_id, data(≤ 16 KiB, 초과 시 INVALID_ARGUMENT)
                                            // -> SessionWritten{bytes_written} ; ACL session.control

    ExecStart           exec_start = 30;    // argv, env, timeout_ms, optional shell_command(4), login_shell(5) (§7.1),
                                            //   agent_channel(6, bytes, agent.v1, §20)
                                            //   -> ExecStarted{exec_id, ticket, agent(3, AgentGrant, §20)}

    RemoteForwardOpen   rfwd_open = 40;     // bind_host, bind_port, forward_host, forward_port,
                                            //   claim_token(§11-3 forward_id→conduit 등록표 —
                                            //   target은 검사하지 않음, requester-local claim 증명용)
                                            //   (`-R`, CLI.md §6.9 grammar) — non-loopback bind_host는
                                            //   INVALID_ARGUMENT(host-side policy, parser는 모양만 검사,
                                            //   CLI.md §6.9); ACL forward.remote
                                            // -> RemoteForwardOpened{forward_id, actual_port}
    RemoteForwardClose  rfwd_close = 41;    // forward_id; ACL forward.remote — 성공은 bare Response
                                            //   {body: None}(전용 payload 없음 — 아래
                                            //   Response oneof에 rfwd_close 전용 variant는 없다)

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
    PairingProof        pairing_proof = 70; // §15(ADR-0002). Principal::Pairing 연결에서만
                                            //   등장 — 그 연결은 Hello/session/tunnel/exec dispatch에
                                            //   전혀 닿지 않는 전용 responder로만 라우팅된다
    PairingAccepted     pairing_accepted = 71; // §15. 성공 시에만; 실패는 기존 Error frame 재사용

    FileReadOpen        file_read_open = 80;   // ADR-0029. path, user -> FileReadOpened{ticket, size, mode, mtime}
                                               //   ; ACL file.read
    FileWriteOpen       file_write_open = 81;  // path, size, mode, overwrite, name_if_dir, preserve, mtime, user
                                               //   -> FileWriteOpened{ticket, into_dir}; ACL file.write
    FileListOpen        file_list_open = 82;   // path, after, user -> FileListed{kind, size, mode, mtime,
                                               //   entries[](≤ FILE_LIST_PAGE_MAX), more, unlistable}; ACL file.read
    FileMkdirOpen       file_mkdir_open = 83;  // path, mode, name_if_dir, preserve, user
                                               //   -> FileMkdirDone{created, into_dir}; ACL file.write
    PunchRequest        punch_request = 90;    // A -> R, punch.v1, §19: attempt_id, target_fingerprint, candidates
                                               //   -> PunchReply
    PunchOffer          punch_offer = 91;      // R -> B (등록 연결 위), punch.v1: attempt_id, initiator_fingerprint,
                                               //   candidates -> PunchAnswer
    RendezvousQuery     rendezvous_query = 92; // A -> B (어느 연결이든), punch.v1 -> RendezvousList
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
    FileReadOpened      file_read_opened = 11;   // file_read_open 성공
    FileWriteOpened     file_write_opened = 12;  // file_write_open 성공
    FileListed          file_listed = 13;        // file_list_open 성공
    FileMkdirDone       file_mkdir_done = 14;    // file_mkdir_open 성공
    Error               error = 15;          // { code, message, retryable } — code는 CLI.md §3.3 어휘
    PunchReply          punch_reply = 16;    // punch_request 성공 (§19)
    PunchAnswer         punch_answer = 17;   // punch_offer 성공
    RendezvousList      rendezvous_list = 18; // rendezvous_query 성공
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
  StreamKind kind = 1;                 // SESSION_DATA | EXEC_DATA | TCP_CONNECT | TCP_ACCEPTED | FILE_DATA | AGENT(6) | JUMP(7)
  bytes ticket = 2;                    // SESSION_DATA / EXEC_DATA / FILE_DATA / TCP_ACCEPTED(forward_id) / AGENT(agent_channel, 16바이트) / JUMP(jump_channel, 정확히 16바이트)
  string host = 3; uint32 port = 4;    // TCP_CONNECT, JUMP 전용. JUMP도 같은 모양 검사를 받고 port는 1..=65535
  bool deny_host_local = 5;            // TCP_CONNECT 전용(JUMP는 읽지 않는다, host-local 거부가 늘 켜져 있다), dial-filter.v1을 광고하는 peer만 준수
                                        //   (ADR-0019 결정 3). 기본값 false = 오늘 동작(무필터).
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
    ScreenUpdate screen_update = 7; // { uint64 new_num; uint32 part; uint32 parts; bytes data; }  screen.v1, §18.8
    ScreenAck    screen_ack = 8;    // { uint64 state_num; }  0 = 전체 화면 요청, screen.v1, §18.8
    ScreenHistory screen_history = 9; // { repeated bytes lines; uint64 skipped; }  host→client, 스트림 전용, screen.v1, §18.11
    ScreenEcho screen_echo = 10; // { uint64 state_num; uint64 input_seq; TtyEcho tty; }  host→client, screen-echo.v1, §18.12
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

// File data 스트림 frame(ADR-0029 결정 9). data 청크 ≤ FILE_CHUNK_MAX(32 KiB).
// FileWriteResult는 file.write 스트림에서 host -> 요청자 방향으로만 흐른다.
message FileFrame {
  oneof body {
    bytes           data = 1;
    FileEnd         end = 2;     // { uint64 size; bytes blake3; }  blake3는 보낸 모든 바이트의 BLAKE3-256(32바이트)
    FileWriteResult result = 3;  // { bool ok; string code; string message; bool overwritten; }
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

- **두 cadence.** 사용자 활동(입력 또는 **세션 트래픽** — 출력·이벤트)이 최근 15 s 안에 있었으면 250 ms마다, 아니면 5 s마다 probe한다. 하루 종일 idle한 셸이 초당 4번 radio를 깨우지 않게 하기 위해서다. idle 창에서의 감지는 느리지만, 그 창에는 잃을 대화형 상태도 없다. **역방향 등록 연결에서는 양 끝의 터널 splice가 옮기는 바이트도 활동이다**(ADR-0041 결정 8). 터널 데이터는 control 스트림을 지나지 않으므로 이것이 없으면 터널만 바쁜 등록이 15 s 뒤 5 s 간격 probe로 떨어져 사망 판정이 `(S+1)×5 s`, 기본 20 s 안팎까지 늦어진다. **`Pong`은 활동이 아니다** — probe에 대한 응답을 활동으로 세면 watchdog이 자기 자신에게 답하며 active 창을 영구히 갱신해 idle cadence에 영원히 도달하지 못한다(살아 있는 path에서만 그렇게 되므로 더 나쁘다). `Pong`은 liveness만 갱신하고, watchdog task의 sleep 길이도 현재 cadence를 따른다(activity가 idle→active 전환을 만들면 즉시 깨운다).
- **RTT에 비례하는 deadline.** 사망 판정 기준은 `max(1 s, 관측 RTT × 8)`이며, 연속 3회 무응답을 요구한다. 느린 링크를 죽었다고 오진하지 않기 위한 것이다. 프로브 간격·하한·연속 횟수는 `[recovery]`의 `probe_interval_ms`(250)·`min_dead_after_ms`(1000)·`strikes`(3)로 조정한다. `P×S+D ≤ 2000ms`, `S ≥ 2`, `50 ≤ P ≤ D`이고 범위 밖은 clamp 없이 기동 시 `CONFIG_ERROR`다. 배수 8은 고정이다(ADR-0021 결정 4). 이 기본과 2000ms 상한은 사용자가 기다리는 대화형 attach와 supervised 터널의 것이다. 역방향 등록 연결(§11-4)은 따로 `min_dead_after` 4250ms·`strikes` 3을 기본으로 쓰고 `[recovery]`의 `reverse_min_dead_after_ms`·`reverse_strikes`로 조정한다. 상한은 `P×S+D ≤ 5000ms`(`REVERSE_DETECTION_CEILING_MS`)이고 나머지 규칙과 `CONFIG_ERROR` 처리는 같다. `probe_interval_ms`는 두 종류가 공유하고 일반 `min_dead_after_ms`·`strikes`는 등록 연결에 닿지 않는다(ADR-0041). 한쪽 프로세스만 느슨하게 해도 상대가 기본값이면 상대의 watch가 `CLOSE_CODE_PATH_DEAD`로 연결을 끊으므로, 양 끝을 같이 올려야 효과가 있다.
- **인증된 QUIC frame이 응답이고, 수신된 UDP datagram은 힌트다.** `Pong`은 순서가 있는 control 스트림 하나에 실리므로, 그 스트림이 손실 복구에 묶이면(head-of-line blocking) 상대의 패킷이 계속 도착하는 중에도 `Pong`만 늦어진다. 이 경우 3-strike가 약 1 s 만에 쌓여 살아 있는 path를 죽었다고 판정했다(이슈 #10: 터널 데이터를 나르는 역방향 등록이 100–300 ms마다 패킷을 받으면서도 `path_dead`로 끊김). 그래서 watchdog은 매 tick마다 두 카운터를 읽는다.
  - **생존 신호는 인증된 frame뿐이다.** quinn의 수신 frame 카운터(복호화 뒤에 세는 `frame_rx`의 합, `ProbeSource::rx_frames`)가 직전 tick 이후 움직였으면 inbound 트래픽과 같게 취급한다. 침묵 시계가 앞으로 가고 strike가 지워진다. 카운터는 liveness만 갱신하고 활동이 아니다(위 `Pong`과 같은 이유). 시각 도장은 **직전 tick의 표본 시각**이다. 직전 tick 이후 센 frame은 그 시각보다 늦게 도착했으므로 이 값은 도착 시각의 하한이고, 침묵을 실제보다 짧게 보지 않는다. 이 시각은 카운터가 움직였는지와 무관하게 매 tick 갱신한다. 그렇지 않으면 한동안 조용하던 path의 침묵이 부풀려져 `min_dead_after`보다 일찍 사망이 선언될 수 있다.
  - **UDP datagram 수신(`udp_rx.datagrams`, `ProbeSource::rx_datagrams`)은 복호화 전에 세므로 힌트일 뿐 생존이 아니다.** 연결 ID(DCID)를 아는 on-path 공격자가 가짜 datagram을 만들어 죽은 path를 살려 둘 수 있기 때문이다. datagram이 움직여도 침묵 시계와 strike는 건드리지 않는다. 사망 판정이 설 시점(3 strike와 `dead_after` 침묵)에 최근 `datagram_grace` 안에 datagram이 도착했고 인증된 frame은 없었으면, 판정을 **한 번만** 유예한다. `datagram_grace = probe_interval × strikes`(기본 750 ms, 역방향 등록도 같다)이고, 유예가 시작된 뒤 `datagram_grace`가 지나도록 인증된 frame이 오지 않으면 datagram이 얼마나 더 오든 사망으로 판정한다. 유예는 사망 타이머 한 주기에 한 번이고, 인증된 frame(또는 `Pong` 같은 control 트래픽)이 와야 새 주기가 시작된다. 그래서 위조자가 감지를 늦출 수 있는 양은 최대 `datagram_grace` 한 번이다. 감지 시간의 상한은 `P×S+D+datagram_grace`(기본 1750 ms, 역방향 등록 기본 5750 ms)이고, `[recovery]`의 `P×S+D` 상한 검사는 이 유예를 포함하지 않는다. 오래전에 온 datagram(`datagram_grace`보다 오래됨)과 datagram이 전혀 없는 침묵은 유예를 받지 못하고 정상 일정으로 사망 판정된다.
  - 패킷이 실제로 `min_dead_after` 넘게 끊긴 침묵은 여전히 사망으로 판정된다. frame이 끊긴 시점 B부터 선언까지의 상한은 `B + max((strikes+1)·probe_interval, min_dead_after)`이고 datagram 힌트가 있으면 거기에 `datagram_grace`가 한 번 더해진다. wire는 바뀌지 않는다.
- **감시 자신이 늦었으면 그 침묵은 경로의 것이 아니다.** 침묵은 watchdog 자신의 timer로 잰다. 호스트가 CPU에 굶거나(부하 평균 50 이상, 이슈 #11) 프로세스가 멈췄다 풀리면 timer는 한참 뒤에야 발화한다. 그동안 도착한 응답은 소켓에 쌓인 채 아직 읽히지 않았는데, 이것을 침묵으로 읽으면 살아 있는 path를 죽었다고 판정한다. 그래서 watchdog은 매 tick의 실제 간격을 자기가 잔 beat와 비교한다. 늦은 만큼이 `probe_interval`(기본 250ms, strike 하나가 세는 단위) 이상이면 그 지연을 침묵에서 덜어내고(침묵 시계를 지연만큼 앞으로 민다) 그 tick은 `dead_after`에 그 지연을 더한 침묵이 쌓이지 않는 한 사망을 선언하지 못한다. 다음 정시 tick이 평소대로 판정하고, 그 사이에 쌓였던 응답이 읽혔으면 strike는 지워진다. 지연을 용서하는 것이 아니라 덜어내는 것이라서, 모든 tick이 늦는 호스트에서도 관측한 침묵이 쌓이는 만큼 판정은 도달한다. 다만 그만큼 느려진다. `probe_interval` 미만의 지연은 침묵 계산이 원래 가진 한 tick의 해상도 안이라 건드리지 않는다. 이 장치는 절전 감지기(§2)와 짝이다. 감지기는 단조 시계가 멈췄을 때(wall clock이 앞서 갈 때)를, 이 장치는 단조 시계는 갔는데 프로세스가 돌지 못했을 때를 본다. 둘 다 못 본 지연이 남아도 QUIC idle timeout 45초가 상한이다. 굶는 호스트에서 정말 죽은 경로의 판정이 늦어지는 것이 이 장치의 비용이다. 이 장치는 굶은 프로세스가 자기 판정으로 연결을 끊는 것을 막을 뿐이다. 굶은 쪽이 보내지 못한 ACK와 `Pong` 때문에 정상 상대가 내리는 판정은 막지 못한다. 상대는 이쪽이 굶었는지 알 수 없고, 그 창은 위 `reverse_*` 키와 ADR-0041의 기본(4.25초)이 정한다. `lost cause=path_dead` 줄에는 그 판정이 선 침묵 동안 tick이 잔 beat보다 가장 늦게 발화한 양이 `tick_gap_ms`로 실린다(CLI.md §6.13). cadence는 빼므로 활성이든 유휴든 0 언저리면 프로세스는 정상이었고 몇 초면 굶고 있었다. attach, supervised 터널, 역방향 등록의 양 끝이 모두 `watch_path`를 지나므로 같이 적용된다(ADR-0042 결정 1). wire는 바뀌지 않는다.
- **소비자 정체는 사망이 아니다.** frontend가 이벤트를 늦게 읽어 pump가 막혀 있는 동안에는 판정을 유예한다. 그렇지 않으면 느린 터미널이 자기 연결을 끊는다.
- **절전 복귀는 활동이자 즉시 probe다.** wake 감지기(§2)가 깨어남을 알리면 watchdog은 남은 cadence를 기다리지 않고 곧바로 probe하고 fast cadence(250 ms)로 옮긴다. 침묵은 잠들기 전 마지막 수신부터 단조 시계로 재므로, 무응답이면 probe 3번과 사망 deadline 가운데 긴 쪽이 지난 뒤 사망이 선언된다. 기본 설정에서 깨어난 뒤 선언까지의 상한은 감지 tick 1초에 deadline 1초를 더한 약 2초다. 패킷을 보내지 않는 감지라 radio를 깨우지 않는다. wire는 바뀌지 않는다.

**서버 재시작은 이 probe를 기다리지 않는다.** 서버 프로세스가 재시작하면 새 프로세스는 옛 연결을 모른다. 서버 endpoint가 재시작 너머로 유지되는 stateless reset key를 쓰면(ADR-0036, `config_dir/stateless_reset.key`) 새 프로세스가 옛 connection ID로 온 클라이언트의 첫 패킷에 RFC 9000 §10.3의 stateless reset을 돌려주고, 클라이언트의 quinn이 연결을 `ConnectionError::Reset`으로 닫는다. 다음 패킷에 1 RTT면 감지된다. 그 뒤 흐름은 사망 선언 뒤와 같다. 재dial하고 reattach하지만 새 서버에 세션이 없으므로 위 "Reattach 절차"의 non-distinguishing `AUTH_FAILED`로 끝난다. 세션은 살아나지 않고 바뀌는 것은 감지 지연뿐이며 recovery의 분류 어휘도 그대로다. 키 파일이 없거나 쓸 수 없던 기동, 파일을 지우고 한 재시작, 재시작 사이에 다른 프로세스가 같은 UDP 포트를 잡은 경우에는 reset이 오지 않고 감지는 위 probe나 `max_idle_timeout`에 맡겨진다. wire는 바뀌지 않는다.

사망이 선언되면 클라이언트는 (인터페이스가 바뀐 경우) `Endpoint::rebind()`를 먼저 시도하고, 그것이 연결을 살리지 못하면 재dial → 위 4단계 reattach를 수행한다. migration probe의 대기 예산은 상수가 아니라 관측 RTT × 2(100–300 ms clamp)다 — 그 시간은 재dial이 쓸 2초 예산에서 나오고, LAN에서 고정 300 ms는 아무것도 배우지 못한 채 예산의 30%를 태운다. 이 재dial은 route를 다시 돈다. 펀칭한 연결이 죽었으면 새 주소로 다시 펀칭하고, 그 시도의 시한은 2초 대신 펀칭 예산이다(§19.10, ADR-0054 결정 18).

> **자격증명 임계 구역은 취소 불가다.** 호스트는 successor를 발행하는 순간 제시된 토큰을 죽인다(아래 "Rotation"). 따라서 "요청이 wire에 올라간 시점 ~ successor가 디스크에 안착한 시점" 구간에서 클라이언트를 취소하면 이 기기는 죽은 자격증명만 남고, attach는 기기 바인딩(CLI.md §6.2)이므로 **살아 있는 세션에 아무도 다시 붙을 수 없다.** 그래서 재dial+redemption은 별도 task에서 돌고 2초 deadline은 그 task를 *기다리는 것*만 중단한다 — task 자체는 `store.put`까지 반드시 완주하며, 다음 시도는 새 redemption을 시작하지 않고 그 task를 이어받는다(단회성 토큰을 두 번 제시하는 경주를 만들지 않기 위해). **migration은 지연 최적화일 뿐이며 correctness는 resume이 보장한다.** 전 과정은 frontend에게 보이지 않는다 — 같은 attach 스트림이 계속 살아 있고, 재전송 중복은 `sequence ≤ L` 폐기가, 미-ack input은 위 5번이 처리한다. 결과는 `recovery ∈ {migrated, resumed, failed}` + `time_to_recovery_ms`로 stderr에 기록된다(CLI.md §6.4).

**Writer lease.** 세션당 writer lease 1개. lease는 소유 연결이 죽으면 자동 해제된다(세션은 유지). `mode=RW` attach는 **기본이 steal**이다 — "절전 후 같은 사람이 재접속"이 지배적 경로이므로 수동 정리를 요구하면 핵심 약속이 깨진다. 기존 보유자가 실제로 살아 있으면 `SessionEvent::WriterChanged`를 받고 read-only로 강등된다. 신중한 자동화를 위해 `no_steal = true`는 steal 대신 `SESSION_CONFLICT`를 반환한다. 모든 handover 판정은 broker 단일 락 안에서 일어난다.

## 11. 역방향 모드

**대칭 원칙:** TLS 역할(누가 dial했나)과 QSH 역할(누가 셸을 제공하나)은 `Hello`에서 분리된다. control 스트림 수립 후 프로토콜은 완전 대칭 — 어느 쪽이든 요청을 보낼 수 있고, **요청 수신자가 자기 ACL을 평가**한다. "client/host"는 연결 단위가 아니라 요청 단위 역할이다.

1. `qsh listen`(controller)이 QUIC listener 실행, `qsh serve --to <controller>`(구 표기 `qsh reverse`)(target)가 평범한 상호 TLS로 dial.
2. target이 `Hello.reverse = ReverseRegistration{offered_name, capabilities}`를 보낸다.
   - **인증:** controller는 target을 **인증서로** 인증한다(pin 또는 CA, `offered_name`은 인증에 쓰지 않는다). mTLS는 QUIC handshake에서 이미 끝나 있으므로 이 인증은 `Hello` 프레임을 읽기 전에 완료돼 있다.
   - **모양 검사:** `offered_name`에 `name.is_empty() || valid_host_name(name)`을 적용한다. 빈 문자열은 검사에서 제외되고 실제 이름은 controller가 정한다. 위반은 `INVALID_ARGUMENT` + 연결 종료이며 choke point 이전이므로 audit이 없다.
   - **ACL:** 그 principal에 ACL action `host.reverse`를 검사한다. 기본 deny이고, 거부 시 연결 종료 + audit이며 리소스는 하나도 만들지 않는다.
   - **이름 확정:** 허용되면 controller가 자기 통제 하의 이름으로 등록한다. 그 fingerprint의 trust-store alias가 우선이고, `offered_name`은 명시적 `allow_advertised_names` 설정 시에만 쓴다(둘 다 없으면 `PERMISSION_DENIED`). 인가된 장비가 `personal-mac` 같은 이름을 사칭(name-squatting)하는 것을 막기 위해서다.
   - **충돌:** 같은 이름의 live 등록이 이미 있고 fingerprint가 **다르면** 신규 등록을 `INVALID_ARGUMENT` + 연결 종료로 거절한다(조용한 덮어쓰기 금지). **같은 fingerprint면** 기존 등록을 대체하고 옛 연결을 닫으며 `generation`을 1 증가시킨다(NAT rebind로 인한 재등록이 정상 경로).
   - **그 밖의 입력(단독 모드):** 단독 `qsh serve`(정방향 host)가 `Hello.reverse`를 받는 것은 대칭 원칙 아래 실제로 발생 가능한 입력이며, 등록하지 않고 `UNSUPPORTED`로 답한다. `Hello.reverse` 없는 peer가 단독 `qsh listen`에 연결한 경우도 `UNSUPPORTED` 후 종료다. 이 상호 거절은 두 역할이 서로 다른 프로세스일 때의 규칙이다. `[listen].serve = true`인 합친 프로세스는 아래 "합친 모드의 갈림"을 따른다(ADR-0059).
   - controller가 localctl UDS 연결을 accept할 때 하는 peer credential 검사(`SO_PEERCRED`/`getpeereid`)는 이 QUIC 등록 절차와 별개이며 §11-3의 conduit 수립 시 수행된다.
   **합친 모드의 갈림(ADR-0059).** `[listen].serve = true`(또는 `qsh listen --serve`)인 `qsh listen` 프로세스는 같은 UDP 소켓에서 두 역할을 받는다. wire는 바뀌지 않는다(ALPN `qsh/1`, `Hello`, capability, `ErrorCode` 그대로). 갈림은 연결마다 한 번이고 순서는 `Gate` → TLS accept → quota 예약 → `respond` 콜백 → (필요하면) 첫 요청이다. 합친 endpoint가 보내는 `Hello` 응답은 peer의 `Hello`로 정해진다. `Hello.reverse`가 있으면 단독 listen이 보내는 응답을, 없으면 단독 serve가 보내는 응답을 보낸다.

   | peer의 `Hello` | 첫 요청(`Ping` 제외) | 갈래 | 인가 | 이어지는 함수 |
   |---|---|---|---|---|
   | `reverse` 있음 | 해당 없음 | 역방향 등록 | `host.reverse` | `Listen::finish_registration` |
   | `reverse` 없음, `punch.v1` 양쪽, `[punch].mode ≠ off` | `PunchRequest` | 펀칭 연결(§19.9) | `host.punch` | `Listen::relay_punch` |
   | `reverse` 없음 | 그 밖의 control message, 또는 peer가 연 데이터 스트림 | 정방향 host | 요청마다 단독 serve의 판정 | `Server::serve_control` |
   | `Principal::Pairing` | 해당 없음 | pairing(§15.1) | 초대 상환 규칙 | `serve_pairing_connection` |

   등록된 연결은 `Server` dispatch에 닿지 않는다. 그 연결에서 peer가 연 스트림은 단독 listen처럼 `TCP_ACCEPTED`와 `AGENT`만 받고 나머지는 reset한다. 정방향 연결은 단독 serve처럼 Hello 전에 quota를 예약하고 거절을 먼저 알리며(R3), 등록은 ACL을 먼저 보고 quota 거절을 그다음에 알린다(A2/B5). `Gate`, `Quotas`, 감사 sink, `Authorizer`는 프로세스에 하나씩이고 `max_connections`와 principal별 상한은 endpoint 하나의 풀이다. `punch.v1`은 `[punch].mode`와 관계없이 `LOCAL_CAPABILITIES`로 언제나 광고되므로 `Hello` 응답의 capability는 단독 listen·단독 serve와 같다. `[punch].mode = off`는 광고가 아니라 가로채기와 `PunchRequest` 처리를 끈다.

3. 이후 controller에서 `qsh <name>`(신규 세션)이나 `qsh attach <name>/<session_id>`(재attach) 등을 실행하면, CLI 프로세스는 상주 `qsh listen` 데몬과 **local unix socket IPC**(`$XDG_RUNTIME_DIR/qsh/<pid>.sock`, 0600, package `qsh.local.v1`)로 통신한다. §5와 같은 frame codec(`qsh_proto::frame`, u32-BE + prost)을 `tokio::net::UnixStream` 위에서 재사용하되, wire(`qsh.wire.v1`)와는 별도 `.proto` 파일·별도 package다.

   **conduit 모델.** UDS 연결 하나가 논리 스트림(conduit) 하나이고, 첫 frame `LocalHello{version, kind, host, wait_ms}`가 그 정체를 정한다.
   - `LOCAL_CONTROL`: 그 host의 control 세션. 이후 QUIC 위와 **완전히 같은** `ControlMessage`/`Response`가 흐른다.
   - `LOCAL_STREAM`: 다음 frame이 wire `StreamHeader`인 data 스트림.
   - `LOCAL_ADMIN`: 데몬 자신에 대한 조회(`LocalHostList` 등).

   **`LocalHelloAck`.** `LOCAL_CONTROL`/`LOCAL_STREAM`에서 데몬은 `LocalHelloAck{host, peer_fingerprint, generation, capabilities}`로 응답한다. 두 kind 모두 `LocalHello.host`가 가리키는 구체적 등록 host가 있고 ack의 모든 필드가 그 host에 관한 값이기 때문이다. `peer_fingerprint`는 CLI 프로세스가 스스로 알 수 없는 peer SPKI fingerprint(CLI는 TLS endpoint가 아니다)를 돌려줘서, `Ops`가 ADR-0007의 fail-closed peer-mismatch 검사를 역방향에서도 수행하게 한다.

   **`LOCAL_ADMIN`은 이 ack를 받지 않는다.** 이 kind에서 `LocalHello.host`는 무시되고, ack의 네 필드는 모두 특정 host 하나를 전제하므로 채울 대상이 없다. 대신 데몬은 `LocalHello` 바로 뒤에 오는 구체적 요청(`LocalHostList` 등)까지 한 번에 읽고, 그 요청 하나에 `LocalResponse` 하나만 돌려준다. 예: `LocalHello{kind=LOCAL_ADMIN} + LocalHostList{}` → 정확히 하나의 `LocalResponse{host_list_result: LocalHostListResult{...}}`(`crates/qsh-proto/proto/qsh/local/v1.proto` 머리말도 이 구분을 명시한다).

   **request_id 재매핑.** `LOCAL_CONTROL` conduit 위의 `ControlMessage.request_id`는 CLI 프로세스가 로컬에서 채번한 값이다. 여러 CLI 프로세스가 같은 QUIC connection을 공유해 채번 공간이 겹칠 수 있으므로, 데몬은 이를 역방향 QUIC connection 위에서 실제로 보내는 `request_id`(`daemon_request_id`)로 재매핑해 상관시킨다.

   **다중화 규칙**(`crates/qsh-core/src/localctl/mux.rs`가 이 표의 순수 상태 기계를 구현한다).
   - conduit마다 in-flight 항목은 최대 `MAX_INFLIGHT_PER_CONDUIT`(64)개다. `crate::server::MAX_INFLIGHT_REQUESTS_PER_CONN`과 같은 크기이지만 다른 것을 세는 독립 상수다. 초과분은 QUIC 연결에 얹지 않고 데몬이 그 자리에서 `RESOURCE_EXHAUSTED`로 답하며, 다른 conduit의 상한이나 전역 `daemon_request_id` 카운터에는 영향이 없다.
   - `Response`가 도착하면 데몬은 `daemon_request_id`로 표를 조회해, 그것을 채번했던 conduit에게만 `peer_request_id`를 복원해 전달한다. 조회와 동시에 항목은 표에서 제거된다. 모든 삽입은 정확히 한 번 제거된다(응답 도착, conduit 사망, QUIC 연결 사망 중 한 경로로만).
   - **비동기 event 라우팅:** `request_id = 0`인 `SessionEvent`는 그 `session_id`를 구독 중인 conduit에만 전달된다. 구독은 그 conduit이 `session.open`/`session.attach` 응답을 받은 시점에 성립한다. 모르거나 아무도 구독하지 않은 `session_id`의 event는 어느 conduit에도 가지 않고, 클라이언트도 낯선 `session_id`의 event는 방어적으로 무시한다. 유일한 예외는 `session.writer_changed`다. `docs/CLI.md` §6.4의 "모든 read 소비자에게 broadcast" 계약을 conduit 단위에서 만족시키려고, 구독 여부와 무관하게 그 host에 등록된 모든 control conduit에 전달한다.
   - **Ping:** conduit이 보낸 `Ping`은 QUIC 연결에 얹지 않고 데몬이 즉시 로컬 `Pong`으로 답한다. liveness는 연결을 실제로 쥔 데몬의 몫이며 CLI로 새어 나가지 않는다.
   - **conduit 사망:** UDS 연결이 죽으면 데몬은 그 conduit이 소유하던 in-flight 항목 전량과 event 구독을 표에서 즉시 제거한다(부분 정리 없음). 이 정리는 로컬 상태에 한정된다. 여러 conduit이 QUIC control 스트림 하나를 공유하므로, 이미 target에 전달된 요청 하나만 취소하는 wire 수단은 없다. target이 나중에 그 `daemon_request_id`로 응답하면 표에 항목이 없으므로 데몬은 조용히 버린다.
   - **conduit 사망 뒤의 세션:** 세션 수명은 connection 수명과 분리된다(`docs/PRD.md`). 정방향에서 `session.open` 전송 후 `SessionOpened` 수신 전에 CLI가 죽어도 target에 살아 있는 세션이 남아 `session.list`로 조회되고 `session.close`로 닫을 수 있다. 역방향 relay도 같다. conduit이 죽은 뒤 도착한 `SessionOpened`는 버려지고, target이 만든 세션은 그대로 살아 있다. 데몬(relay)은 자기 판단으로 control 요청을 발신하지 않는다. 아무도 요청하지 않은 `session.close`를 controller principal 명의로 보내면 target이 그것을 그 principal의 실제 요청으로 감사하게 되기 때문이다.
   - **long-poll 점유:** 위 wire 한계 때문에 `SessionRead`/`SessionClose` long-poll은, 죽은 conduit이 쥐고 있던 target 쪽 허용량이 자체 타임아웃(`crate::server::SESSION_READ_MAX_WAIT`)까지 점유된 채 남을 수 있다. 데몬은 이를 사후가 아니라 **사전에** 막는다. 이 hub가 한 번에 QUIC 연결에 얹는 long-poll 총량을(살아 있든 죽었든 모든 conduit 합산) target의 연결당 상한보다 훨씬 낮은 `MAX_INFLIGHT_LONG_POLL_PER_HUB`(16, `crates/qsh-core/src/reverse/listen/hub.rs`)로 고정한다.
   - **QUIC 사망:** 역방향 QUIC 연결이 죽으면 그 host의 모든 conduit이 명확한 typed error로 함께 끝난다(host의 전체 conduit 집합에 위 전량 정리를 반복하는 것과 같다).

   **peer credential과 인가.** 데몬은 accept한 UDS 연결의 발신 프로세스가 자신과 같은 로컬 사용자인지 `SO_PEERCRED`(Linux)/`getpeereid`(macOS)로 검사한다. **localctl은 인가 계층이 아니다.** 데몬이 살아 있는 역방향 연결 위로 `SessionOpen`/`SessionAttach`를 그대로 전달하면 target이 자기 ACL(`session.open` 등)을 controller principal에 대해 평가한다. **역방향 등록은 도달성만 부여하고 권한은 부여하지 않는다.**

   **응답 envelope.** 데몬→클라이언트 방향의 모든 frame은 예외 없이 `LocalResponse{oneof body}` 하나다. `LocalHelloAck`/`LocalError`/`LocalHostListResult`가 필드 shape상 서로 구별되지 않아 필요하며, wire의 `Response{oneof body}`와 같은 이유다. 실패 응답은 `LocalError{code, message}`(`code`는 `docs/CLI.md` §3.3 어휘 그대로)다. `LocalHostList`의 성공 응답은 `LocalHostListResult{repeated LocalHost hosts}`이고, `LocalHost{name, address, state, fingerprint, capabilities, generation, registered_at}`는 데몬의 admin view다(JSON `Host`와는 별개 타입, `docs/CLI.md` §5).
**터널 conduit.** 터널 data 스트림은 새 `LocalStreamKind`를 얻지 않는다. `LOCAL_STREAM`이 이미 "다음 frame이 wire `StreamHeader`인 data 스트림"이라는 뜻이므로, `StreamHeader{TCP_CONNECT, host, port}`와 `StreamHeader{TCP_ACCEPTED, forward_id}`는 `StreamHeader{SESSION_DATA, ticket}`과 **같은 `LOCAL_STREAM` conduit**을 탄다(§7의 `StreamKind` 판별로 충분하다).
- **`-R`:** controller(client 역할)가 그 host에 `RemoteForwardOpen`을 보내면, target(host 역할)이 자기 loopback에 `listen_port`를 bind하고 accept마다 `StreamHeader{TCP_ACCEPTED, forward_id}`를 **target → controller** 방향으로 연다. `TCP_ACCEPTED`를 여는 쪽은 언제나 accept를 실제로 받은 쪽이므로(§7의 표, 대칭 원칙: 리소스를 쥔 쪽이 스트림을 연다) 정방향의 "attach하는 쪽이 연다"와 방향이 반대다. 그 스트림은 controller가 상주 `qsh listen` 데몬과 맺은 `LOCAL_STREAM` conduit으로 relay되어, controller의 CLI 프로세스가 쥔 로컬 `host:host_port`로 splice된다.
- **`-L`:** controller가 `TCP_CONNECT` 스트림을 여는 쪽이다(§7의 표대로 "local listener 쪽"). 그 스트림은 controller의 `LOCAL_STREAM` conduit을 거쳐 데몬의 역방향 연결 위로 relay되고, target이 `ConnectResult`로 답한 뒤 raw byte splice가 이어진다. 정방향 `-L`과 같은 흐름에 conduit relay 한 단계가 더해진다.

**`exec` conduit(issue #5).** `StreamHeader{EXEC_DATA, ticket}`도 새 `LocalStreamKind` 없이 같은 `LOCAL_STREAM` conduit을 탄다. `ExecStart`(control, `LOCAL_CONTROL`)가 발급한 ticket을 `LOCAL_STREAM` conduit이 `StreamHeader{EXEC_DATA, ticket}`으로 상환하는 흐름은 `session.open`의 `SESSION_DATA` 상환과 같다.

**`JUMP` conduit (ADR-0056 결정 14).** `StreamHeader{JUMP, channel, host, port}`도 새 `LocalStreamKind` 없이 같은 `LOCAL_STREAM` conduit을 탄다. 데몬은 `ConnectResult` 정확히 하나를 먼저 쓰고(등록한 host의 것이거나 자신의 거절), 이어서 `u16` 길이 frame으로 안쪽 QUIC 패킷을 옮기며 등록 연결 쪽 운반체를 datagram과 스트림 가운데 고른다. 자세한 규칙은 §21.7.

**raw 구간의 chunk framing (Windows).** conduit은 `LocalHello`·`LocalHelloAck`·`StreamHeader`·ack 같은 framed `qsh.local.v1` 메시지를 마친 뒤 raw byte 중계로 바뀐다(`SESSION_DATA`·`TCP_CONNECT`·`TCP_ACCEPTED`·`EXEC_DATA`·`FILE_DATA`). unix 소켓은 이 구간에서 쓰기 방향만 닫을 수 있어 바이트를 그대로 나르지만, Windows byte 모드 named pipe는 그럴 수 없다(ADR-0035 결정 14). 그래서 Windows는 raw 구간의 두 방향을 모두 chunk로 나른다.

```
chunk := length (4바이트, big-endian u32) || length 바이트
```

- 길이 `0`은 end chunk다. 쓰는 쪽이 자기 방향을 끝냈다는 뜻이고(half-close), 읽는 쪽은 end of stream을 보고하며 반대 방향은 계속 흐른다.
- 길이 상한은 65536이다. 그보다 큰 길이는 프로토콜 오류이고 I/O 오류와 같은 abort로 conduit을 끊는다.
- end chunk 뒤에 오는 바이트도 프로토콜 오류다.
- chunk 경계에서 end chunk 없이 스트림이 끝나면 소켓의 drop과 같은 평범한 EOF로 읽는다. chunk 헤더나 본문 중간에서 끝나면 `UnexpectedEof`다.
- framed 구간과 그 마지막 메시지 뒤에 같이 읽혀 들어온 바이트(read-ahead)도 chunk 스트림의 시작이므로 같은 해석기로 푼다.
- 데몬이 QUIC data 스트림을 열지 못했을 때 raw 구간으로 보내는 한 바이트 sentinel(`0x00`)도 chunk 하나로 감싼다. `EXEC_DATA`는 ack 전까지 framed 구간이라 그 시점의 sentinel은 감싸지 않는다.

unix는 raw 구간을 바이트 그대로 나르고 이 절의 어떤 것도 적용하지 않는다. Windows의 localctl은 이 변경 전에 배포된 적이 없어 버전 불일치가 없다. 구현은 `qsh-core`의 `localctl/chunked.rs`이고 두 OS에서 컴파일·시험된다. 접점은 `localctl/transport`의 `raw_reader`·`raw_writer`·`raw_bytes`·`shutdown_write`다.

**UDS EOF는 QUIC stream reset으로 옮겨진다. clean close가 아니다.** `SESSION_DATA`/`TCP_CONNECT`/`TCP_ACCEPTED`는 순수 byte splice라서, 로컬 UDS 쪽이 정상 종료되면 QUIC stream도 정상 종료(FIN)로 닫아도 된다. 그러나 `EXEC_DATA`는 framed 프로토콜(`Stdin`/`StdinEof`/`Stdout`/`Stderr`/`ExecExit`, §7)이고 `StdinEof`가 이미 "이 방향은 끝"을 명시적으로 나른다. 그래서 로컬 UDS 쪽이 (exec 클라이언트 프로세스가 종료·drop·취소되어) EOF로 끝나면 데몬은 이를 clean close가 아니라 QUIC stream reset으로 옮긴다. stdin을 닫는 경우는 해당하지 않는다.

이유는 `run_exec`(`crates/qsh-core/src/exec/mod.rs`)의 stdin 펌프에 있다. 그 루프는 읽기 *오류*만 "peer가 사라졌다" 신호로 보고 자식을 죽이고, 깨끗한 스트림 종료(`Ok(None)`)는 루프를 빠져나가는 무동작이라 아무도 자식을 죽이지 않는다. reset이 없으면 output 없는 명령이 exec 클라이언트가 사라진 뒤에도 host에 고아로 남는다(`local_stream_relay_kind`, `crates/qsh-core/src/localctl/daemon.rs`). 이 규칙은 로컬 UDS→QUIC 방향에만 적용된다. target이 보내는 `Stdout`/`Stderr`/`ExecExit`는 그대로 splice되고, `ExecExit`가 그 exec의 논리적 끝을 명시한다.

**`forward_id` → conduit 등록표.** 위 다중화 규칙은 어느 conduit이 어느 `forward_id`의 `TCP_ACCEPTED`를 받을 자격이 있는지를 정하지 않는다. 그 등록표는 `ControlHub`(`crates/qsh-core/src/reverse/listen/hub.rs`)의 `forwards: HashMap<forward_id, ForwardRegistration>`이고, 소유 conduit(`owner`)과 claim seat(`seat`)을 **한 항목**으로 묶는다. 병행하는 두 map이면 한쪽만 갱신하는 편집이 가능해 실제로 구멍이 됐었다.

*등록.*
- 등록 시점은 그 `forward_id`가 존재하게 되는 순간이다. target의 `RemoteForwardOpened`가 도착해 `daemon_request_id`를 발신 conduit으로 되매핑하는 함수(`ControlHub::deliver_response`) 안에서, 같은 락 아래 등록한다. `forward_id`는 target이 발급하므로 응답 이전에는 존재하지 않아 더 일찍 등록할 방법이 없고, 등록은 되매핑이 방금 증명한 conduit에게만 귀속된다.
- 같은 `forward_id`가 두 번째로 도착하면(target 버그 또는 적대적 target) 등록은 갱신되지 않고 경고 로그만 남긴 채 버려진다. 첫 등록이 최종이며, 소유권이 나중 도착으로 조용히 넘어가는 창을 열지 않는다.
- 되돌아온 `forward_id`가 모양 검사(`qsh_proto::wire::valid_forward_id`)를 통과하지 못하면 등록 자체가 일어나지 않는다.

*claim seat.* 등록(`owner`)은 `TCP_ACCEPTED`를 어느 conduit에 *배달*할지만 정한다. 같은 uid의 다른 conduit이 그 `forward_id`를 안다는 사실만으로 claim할 수 있어서는 안 되므로, 같은 `ForwardRegistration` 안에 `owner`와 별개로 claim seat(`ClaimSeat`)이 있다.
- `token`은 opaque bytes다. 이 hub가 아니라 **요청자**(`crate::tunnel::remote::RemoteForwardAcceptor`)가 인스턴스당 한 번 mint해 `RemoteForwardOpen.claim_token`(§9)에 실어 보내고, target은 이 값을 들여다보거나 비교하지 않는다.
- 요청자 쪽 `ControlHub`가 `send_request` 시점에 `daemon_request_id`로 토큰을 미리 붙잡아 두었다가, `deliver_response`가 `ForwardRegistration`을 등록하는 같은 락 안에서 seat도 앉힌다. `owner`와 seat이 원자적으로 함께 생기므로, 등록 직후 아직 아무도 claim하지 않은 순간에 같은 uid의 다른 conduit이 가로챌 창이 없다.
- **빈 토큰은 영구히 claim 불가능이다.** `claim_token`이 비어 있으면 seat은 `ClaimSeat::seat`에 의해 즉시 "claim 불가능" 상태로 앉고, 이후 어떤 재등록으로도 다시 채워지지 않는다. hub가 토큰을 스스로 mint하지 않는 이유는, 되돌려줄 wire round trip이 없어 hub가 만든 토큰은 정당한 소유자를 잠글 뿐이기 때문이다. 등록(`forward_id`·`owner`)은 유지되어 예약·sweep·소유자의 close 대상이 되지만, 그 `forward_id`로 도착한 `TCP_ACCEPTED`는 큐에 들어가기 전에 거부된다. 부재/빈 capability는 통과가 아니라 거부다.
- 이후 모든 claim 시도(claim이 끝난 뒤 같은 인스턴스의 재시도 포함)는 seat 값과 바이트가 같아야 하고, 다르거나 앉은 토큰이 없거나 비어 있으면 큐 조회 이전에 거부된다.
- **비교는 arrival이 실제로 손을 바꾸는 매 순간 다시 이뤄진다.** claim이 arrival을 기다리며 파킹된 동안에도 그 `forward_id`는 재등록될 수 있다(소유 conduit이 닫고 새 `RemoteForwardOpen`을 여는 경우 등, seat이 다른 토큰으로 갈릴 수 있다). 그래서 데몬은 진입 시점에 한 번만 비교하지 않고, 큐에서 arrival을 꺼내기 직전 잠금을 쥔 채 그 순간의 seat에 대해 다시 비교하여 통과해야만 넘긴다. 진입 시점 검사 하나만으로는 파킹 도중 재등록된 새 소유자의 arrival이 옛 claimant에게 새어 나갈 수 있다(check-then-use).

*소멸.* 데이터-플레인 경로는 둘뿐이다.
- 등록한 conduit이 죽으면(`ControlHub::unregister_conduit`) 그 conduit이 소유한 등록 전량이 즉시 표에서 제거되고, 그 순간 대기 중이던 `TCP_ACCEPTED` 큐(`tunnel_queue`)의 항목 전부가 내부 코드 `0x200A`로 reset된다. peer가 알 필요는 "이 `forward_id`는 더 이상 유효하지 않다" 하나뿐이라 wire 계약이 아니다(§7의 `0x2007`과 같은 성격).
- `RemoteForwardClose`가 성공(빈 `Response`)으로 답하면 같은 함수 안에서 같은 teardown이 일어난다.
- **close도 소유 conduit만 할 수 있다.** outbound(CLI가 보낸 `RfwdClose`)는 그 `forward_id`가 다른 conduit 소유면 target에 아무것도 보내지 않고(`daemon_request_id`를 만들기도 전에 걸러진다) 그 CLI에게만 즉시 `PERMISSION_DENIED`를 돌려준다. inbound(target이 보낸 `RemoteForwardClose`의 성공 `Response`)는 되매핑된 conduit이 `owner`와 다르면 등록도 큐도 그대로 두고 `Response`만 그 conduit에게 평범하게 전달한다(owner의 이후 close나 owner conduit의 사망만이 이 상태를 바꾼다). target이 보는 것은 연결 하나뿐이라 그 위의 두 CLI conduit을 구별할 수 없고, 구별은 데몬만 할 수 있기 때문이다.

*세 번째 경로: `LOCAL_ADMIN` `tunnel.close`.* `qsh tunnel close <id>`를 위해 `ControlHub::admin_close_forward`가 소유 conduit 비교 없이 등록을 지우고 큐를 비운 뒤 target에 `RemoteForwardClose`를 보낸다. 이는 위 owner-conduit 게이트의 우회가 아니라 **다른 축의 인가**다.
- 위 게이트가 지키는 것은 "target이 구별 못 하는 두 conduit 중 누가 진짜 소유자인가"(데이터-플레인, target 신뢰 없음)다.
- `admin_close_forward`가 서는 지점은 그 축과 무관한 **로컬 머신 신뢰 경계**, 즉 UDS accept 시점에 이미 검사한 same-uid peer credential이다(§11-3 앞부분, [architecture.md](architecture.md) §3).
- `docs/CLI.md` §2.5의 `tunnel.close`/`tunnel.list` 행이 "해당 tunnel의 소유 **peer**이면 허용"이라 쓰는 것도 이 축이다. 그 peer를 대신해 요청하는 프로세스가 tunnel을 연 바로 그 프로세스일 필요는 없다. `qsh tunnel close <id>`가 `--host` 없이 새 프로세스로 실행되는 것이 그 증거다(`docs/CLI.md` §6.9 사용 예).
- `forward_id`는 target이 발급하므로 한 hub 안에서만 유일하다. `tunnel.close`가 여러 등록 host의 hub를 동시에 뒤질 때 같은 id가 둘 이상의 hub에서 매치되면 무엇을 닫을지 정할 수 없다. 이때 `tunnel_close_target`(`crates/qsh-core/src/reverse/listen/hub.rs`)은 아무것도 닫지 않고 `closed: false`로 답한다(fail-closed, `CLAUDE.md`의 ambiguous-state 기본값과 같다).

*hub 상한.*
- **터널 스트림 총량:** 한 hub가 동시에 물고 있는 터널 스트림은 `MAX_TUNNEL_STREAMS_PER_HUB`(64, `Semaphore`)로 묶인다. accept된 순간(`TCP_ACCEPTED`) 또는 `open_bi` 직전(`TCP_CONNECT`)부터 splice가 끝날 때까지 보유되므로, 아직 아무도 claim하지 않은 큐잉 backlog도 이 상한을 소비한다. claim을 게을리하는 CLI 하나가 같은 hub의 다른 host/CLI conduit을 굶기지 못한다. 상한 초과로 도착한 `TCP_ACCEPTED`는 큐에 들어가기 전에 내부 코드 `0x200B`로 거부된다(CLI 쪽에서 같은 상한에 걸린 `TCP_CONNECT`는 `RESOURCE_EXHAUSTED`, `docs/CLI.md` §3.3).
- **큐잉된 arrival의 수명:** 큐는 claim 성공·소유 conduit 사망·소유자의 close로만 비워졌으므로, 느리거나 굶주린 claimant의 backlog가 hub permit과 살아 있는 QUIC 스트림을 무한정 붙잡을 수 있었다. 그래서 큐에 들어간 arrival이 `MAX_QUEUED_TUNNEL_ARRIVAL_AGE`(30초)를 넘겨 claim되지 않으면 hub의 주기적 sweep이 내부 코드 `0x200C`로 reset하고 permit을 pool에 돌려준다. 맨 드롭하지 않는 이유는 §7의 splice 규율과 같다. 맨 드롭은 스트림을 정상 종료로 닫아, 아무도 splice하지 않은 연결을 target에게 "정상적으로 끝났다"고 보고한다. 등록 자체는 건드리지 않으므로 backlog가 만료된 `-R`도 여전히 claim 가능한 forward다. 30초는 정상 claimant의 소비 속도보다 몇 자릿수 위다. 등록된 `-R`의 claim loop은 항상 하나를 파킹해 두고 돌아오는 즉시 재무장하므로 보통 1밀리초 안에 claim되고, 모든 claim이 거부돼 200ms 백오프로 재시도되는 최악에도 상한만큼의 backlog가 13초 안에 빠진다.
- **parked-claim 상한:** claim이 arrival을 기다리며 파킹돼 있는 것 자체는 QUIC 자원을 쥐지 않는다. 그러나 그 파킹은 daemon 전역 `MAX_CONCURRENT_LOCAL_STREAM_CONDUITS`(256) permit을 `wait_ms` 예산이 끝날 때까지(최악 `LOCAL_WAIT_MAX` 60초) 붙들고 있어, 한 CLI가 오래 기다리는 claim을 여러 개 열면 daemon 전체 pool을 혼자 소진할 수 있다. 그래서 hub마다 별도 pool(`claim_permits`, `MAX_PARKED_CLAIMS_PER_HUB` = 32)이 있고, 데몬은 `hub.claim_tcp_accepted`를 부르기 **전에** 이 permit을 얻어야 한다. 못 얻으면 파킹이 시작되지 않고 `LocalResponse{error: RESOURCE_EXHAUSTED}`가 즉시 돌아온다(아래 claim leg).
- **parked-claim pool은 conduit별로 나뉜다.** 상한만으로는 공격은 막아도 정상 동작은 못 막는다. 건강한 `-R`의 정상 상태가 permit을 쥔 채 파킹해 있는 것이라, reverse forward를 32개 띄운 CLI 하나가 그 host의 permit 전부를 영구히 쥐고 다른 모든 CLI의 `-R` claim을 막게 된다. 그래서 permit은 그 `forward_id`를 등록한 conduit(=CLI 프로세스)별로 `MAX_PARKED_CLAIMS_PER_CONDUIT`(8, pool의 1/4)까지만 나간다. 이 귀속은 **공정성 회계일 뿐 인가가 아니다.** 누가 arrival을 받을 자격이 있는지는 위 seat 비교 하나뿐이고, 잘못된 토큰을 낸 claim은 await 이전에 거부되어 permit을 즉시 놓으므로 남의 몫을 지속적으로 점유할 수 없다.

데몬은 이 relay 어디에서도 payload를 파싱하거나 로그하지 않는다. 등록표·큐가 들고 있는 것은 `forward_id`·conduit id·스트림 핸들뿐이다.

**`TCP_ACCEPTED` claim leg의 요청/응답.** 위 등록표를 소비하는 쪽, 즉 controller의 CLI 프로세스가 데몬과 주고받는 순서다.

*CLI가 여는 것.* `LOCAL_STREAM` conduit 하나(`LocalHello{version, kind=LOCAL_STREAM, host, wait_ms}`) → `LocalHelloAck` → 다음 frame으로 `StreamHeader{TCP_ACCEPTED, ticket}`.
- `ticket = forward_id ++ 0x00 ++ claim_token`이다. `forward_id`의 문자셋(`[A-Za-z0-9_-]`)에 NUL이 없으므로 첫 NUL로 잘라 무모호하게 분리된다. `crate::tunnel::remote::claim_ticket`이 이 shape를 만드는 유일한 지점이라 양쪽이 어긋날 수 없다.
- 여기까지는 `SESSION_DATA`/`TCP_CONNECT`와 같다. `wait_ms`는 데몬이 그 `forward_id`의 arrival을 기다려 주기를 바라는 예산이며 `clamp_wait`로 `LOCAL_WAIT_MAX`까지 잘린다.

*데몬이 답하는 것.* 이 header에 대해서는 raw byte가 한 바이트라도 흐르기 전에 **반드시 정확히 하나의 `LocalResponse` frame**이 먼저 간다.
- **성공:** `LocalResponse{claim_granted: LocalClaimGranted{}}`이고, 그 frame의 마지막 byte 다음부터가 claim된 `TCP_ACCEPTED` 스트림의 raw payload다. 메시지가 비어 있는 것은 의도다. CLI는 자기가 어느 `forward_id`를 claim했는지 이미 알고, 데몬은 payload에 관해 아무것도 모른다.
- **실패:** 기존 `LocalResponse{error: LocalError{code, message}}` 경로이며 code는 다음과 같이 갈린다.
  - `INVALID_ARGUMENT`: `ticket`에 NUL 구분자가 없거나, 앞부분이 UTF-8이 아니거나, `valid_forward_id` 모양 검사에 걸릴 때. 등록표 조회 이전에 걸러진다. header 자체가 relayable한 네 `StreamKind`(`SESSION_DATA`/`EXEC_DATA`/`TCP_CONNECT`/`TCP_ACCEPTED`) 중 어느 것도 아니거나 data frame 상한을 넘을 때도 같다.
  - `TIMEOUT`: 이 hub가 그 `forward_id`를 등록한 적이 없을 때, 등록은 있으나 제시한 `claim_token`이 seat 값과 다를 때(소유하지 않은 conduit의 claim), `wait_ms`가 끝나도록 arrival이 없을 때. 셋은 구별되지 않는다(CLI가 구별할 수 없어야 하는 이유는 위 등록표 항목).
  - `RESOURCE_EXHAUSTED`: 데몬의 `LOCAL_STREAM` conduit 슬롯이 가득 찬 경우(header를 읽기도 전인 `LocalHello` 단계), 또는 header는 읽었으나 parked-claim permit을 얻지 못한 경우. 후자는 hub의 `MAX_PARKED_CLAIMS_PER_HUB`가 찼든 그 `forward_id`를 등록한 conduit이 자기 몫(`MAX_PARKED_CLAIMS_PER_CONDUIT`)을 다 썼든 파킹을 시작하지 않고 그 자리에서 돌려주며, 두 이유는 CLI에게 같은 code·같은 message로 보인다.
  - `MAX_TUNNEL_STREAMS_PER_HUB` 상한은 이 leg에서 별도 code를 만들지 않는다. 그 permit은 arrival과 함께 이동하고, 상한 초과는 arrival이 큐에 들어가기 전에 `0x200B`로 거부되므로 claim하는 CLI에게는 "아무것도 오지 않았다"와 구별되지 않는 `TIMEOUT`으로 보인다.

*침묵은 응답이 아니다.* 성공도 timeout도 명시적 frame이므로 CLI의 reader는 `StreamHeader`를 보낸 뒤 frame을 정확히 **하나** 읽고, 그 하나로 성공/실패를 판정한 다음 그 자리에서 raw 모드로 전환한다. 그 frame과 같은 `read()`에 실려 온 raw 잔여 byte는 `FrameDecoder::take_remaining`으로 **순서 그대로** 회수되어 splice의 맨 앞에 붙는다. 버려지지도 뒤로 밀리지도 않는다. CLI는 byte 내용으로 "이것이 frame인가 payload인가"를 판정하지 않는다. 어떤 byte 열이든 length prefix로 읽힐 수 있어 그 판정은 원리적으로 결정 불가능하고, 틀리면 살아 있는 연결을 죽이거나 터널 byte를 재배열한다. 마찬가지로 "아무것도 오지 않음"을 성공으로 읽지 않는다. 조용한 성공과 느린 실패는 구별되지 않기 때문이다.

**`EXEC_DATA` ack leg(issue #5).** `TCP_ACCEPTED` claim leg와 나란히 서는 `EXEC_DATA`만의 ack-before-splice 규율이다. `LocalHello{kind=LOCAL_STREAM}` → `LocalHelloAck` → `StreamHeader{EXEC_DATA, ticket}`까지는 같고, 그 뒤가 갈린다.

1. header의 모양이 틀렸거나(위 네 `StreamKind` 중 하나가 아니거나 data frame 상한을 넘음) conduit의 `LOCAL_STREAM` 슬롯이 가득 찬 경우에는 아직 conduit이 framed `qsh.local.v1`를 말하는 중이다. 그래서 `TCP_ACCEPTED`와 마찬가지로 framed `LocalResponse{error: LocalError{code, message}}`(`INVALID_ARGUMENT` 또는 `RESOURCE_EXHAUSTED`)로 답한다. 이 시점까지 QUIC 쪽에는 아무것도 열리지 않았다.
2. header 검증을 통과하면 `LocalConduit::into_raw`가 conduit의 framing 능력을 거둬 가고(이후 이 conduit은 framed 메시지를 말할 수 없다), 그다음에야 `conn.open_bi()`를 시도한다.
3. `open_bi`가 실패하거나 `OPEN_DATA_STREAM_TIMEOUT`(10초) 안에 끝나지 않으면, CLI는 handshake가 성공했다고 믿고 `LocalResponse` frame을 기다리지만 데몬은 더는 그것을 보낼 수 없다. 대신 raw sentinel byte 한 개(`[0]`)를 UDS에 쓰고 스트림을 끝낸다. CLI에서 이 byte는 정상 frame으로 decode되지 않으므로 truncated-frame 오류(`ConnectionFailed`)로 관측되고 `LocalError`로는 도달하지 않는다.
4. `open_bi`가 성공한 뒤에만 데몬은 raw byte splice를 시작하기 직전에 `LocalResponse{claim_granted: LocalClaimGranted{}}` ack을 (여전히 raw로, `encode_local`을 직접 호출해) 쓴다. `TCP_ACCEPTED`의 claim ack과 같은 모양이지만 뜻은 claim 성공이 아니라 "이 exec의 QUIC data stream이 방금 열렸다"이다.

이 순서(ack은 `open_bi` 성공 **후에만**) 덕분에 CLI는 세 결과를 구별한다. framed `LocalError`(header 자체가 거부됨), raw sentinel byte(header는 통과했으나 QUIC stream을 못 엶), `LocalClaimGranted` ack 뒤의 raw splice(정상 진행).

`EXEC_DATA`를 모르는 옛 `qsh listen` 데몬(issue #5 이전)은 이 header를 옛 세 갈래 판정에서 걸러 framed `INVALID_ARGUMENT`로 거부한다. 이 조합은 그 자체로 진단적이라, CLI(`map_local_stream_open_error`, `crate::client`)는 이를 "이 머신의 상주 `qsh listen`이 issue #5 이전 빌드"라는 구체적 메시지로 재작성한다.

4. **heartbeat의 정체:** 신규 wire 메시지는 없다.
   - 연결 유지는 §2의 keep-alive(기본 15s)이고, 사망 **감지**는 §10 "Path 사망 감지"와 같은 control 스트림 `Ping`/`Pong` probe다. 두 cadence·RTT 비례 deadline·strike 판정을 양쪽 role에서 재사용한다. 인증된 QUIC frame의 수신은 `Pong`과 같은 응답으로 세고, 수신된 UDP datagram은 생존이 아니라 한 번의 유예를 받는 힌트다. target과 controller 양쪽의 watch가 같은 `watch_path` 경로를 지나므로 둘 다 적용된다.
   - **등록 연결의 기본값:** attach의 기본(`min_dead_after` 1초, `P×S+D` 1750ms)과 따로 `min_dead_after` 4250ms, `strikes` 3, cadence 250ms를 쓴다(`P×S+D` 5000ms, ADR-0041). 등록이 끊기면 그 위의 역방향 터널이 재생 없이 모두 끝나고 기다리는 사람이 없기 때문이다. 4250ms는 이슈 #10이 잰 최장 업링크 손실 구간 3.6초에 tick 하나와 여유를 더한 값이다.
   - 각 프로세스가 자기 `config.toml`의 `[recovery]`를 읽고(`reverse_min_dead_after_ms`·`reverse_strikes`가 이 연결에만 적용된다) target과 controller는 따로 조정되므로, 양 끝을 같이 올려야 효과가 있다. 진짜로 죽은 등록이 `stale`로 표시되고 target이 재dial하기까지는 attach 기본보다 약 3.25초 늦다.
   - 이 4.25~4.5초는 등록이 쓰이는 구간(control 활동이나 터널 바이트가 15초 안에 있었다)의 값이다. 15초 넘게 아무것도 나르지 않은 등록은 idle beat(5초)로 probe가 나가 `(S+1)×5초`, 기본 20초 안팎에 판정이 선다(ADR-0041 결정 8). control 스트림이 막혀도 터널 스트림 데이터나 ACK가 담긴 인증된 frame이 도착하는 등록은 죽은 것으로 판정되지 않는다.
   - **stale과 재등록:** 연결이 죽으면 controller는 host 목록에서 `state: "stale"`로 표시했다가 `[listen].stale_retention`(기본 120s, `stale_retention > backoff_max_ms × 3`이어야 하며 target의 `backoff_max_ms` 기본 30000ms보다 확실히 크다) 후 제거한다. target은 사망 판정 후 `Hello.reverse`를 재전송해 재등록한다. target의 세션들은 재등록과 무관하게 유지되고 §10으로 resume된다.
   - **target의 재dial backoff:** 지수 backoff + jitter로 무한 재시도한다(`backoff_initial_ms` 기본 500 → 배수 2 → `backoff_max_ms` 기본 30000, 등록 성공 시 초기값으로 리셋).
     - 60초가 못 되어 끝난 등록이 연속되면 두 번째 유실부터 그 뒤 첫 재dial의 지연이 유실마다 두 배가 되어 `max(backoff_initial_ms, 8000)`ms에서 멈춘다(`backoff_max_ms`가 작으면 그 값). 60초 넘게 산 등록이 끝나거나 wake가 오면 연속 횟수는 0으로 돌아가고, dial 실패가 이어질 때의 지수 backoff는 이와 별개다(ADR-0042 결정 2).
     - 절전 복귀(wake, ADR-0023 결정 17)를 감지하면 초기값으로 되돌리고 진행 중인 대기를 끊어 즉시 재dial하며, 이후 60초 동안은 지연에 `max(backoff_initial_ms, 2000)`ms 상한을 둔다. `backoff_max_ms`가 그보다 작으면 그 값이 이긴다.

   **역방향에서의 §10 Reattach 매핑:** 재dial의 주체는 항상 **target**(host role)이지 controller가 아니다 — controller는 target이 새 연결을 세우기를 기다릴 뿐 자신은 아무것도 dial하지 않는다. controller 측 attach driver(§10의 재dial+redemption task에 대응하는 위치)는 registry에서 그 host의 새 `generation` 등록을 기다렸다가, 등록이 관측되면 §10 절차의 2단계(`SessionAttach{session_id, resume_token, last_output_seq}`)부터 그 새 연결 위에서 수행한다 — §10의 1단계("새 QUIC 연결")는 target이 이미 수행했으므로 controller가 이 leg에서 반복하지 않는다. **migration(`Endpoint::rebind()`)은 이 leg에 존재하지 않는다** — target의 재dial 자체가 유일한 복구 경로다.

## 12. 우선순위와 backpressure

- **우선순위 band (quinn `set_priority`):** control **200** > session data(PTY) **100** > exec **50** > tunnel/file **0** (tunnel 간에는 `send_fairness(true)` round-robin). 로컬 송신 큐에서 포화 터널이 PTY chunk를 지연시키지 못한다.
- **Bufferbloat 방지:** 우선순위는 큐 순서만 고치고 깊이는 못 고친다. bulk가 congestion window를 채우면 PTY chunk가 in-flight 뒤에서 기다린다. 대응은 셋이다.
  - (a) 수신 window: quinn 0.11의 `TransportConfig`는 연결 전체에 적용되는 `stream_receive_window` 하나만 노출하고 스트림 *종류*별 window setter가 없다. 그래서 "터널은 크게, PTY는 작게"라는 수신측 비대칭은 구현할 수 없다(quinn의 한계이지 설계 선택이 아니다). 대신 연결 전체에 단일 값을 적용하고(`crates/qsh-transport/src/endpoint.rs`의 `TUNNEL_STREAM_RECEIVE_WINDOW`), 스트림 종류 간 보호는 (c)의 우선순위 band(큐 *순서*)와 송신측 depth cap(큐 *깊이*)의 조합이 맡는다.
  - (b) BBR congestion control.
  - (c) "포화 터널 + PTY echo p95 < 10ms" 통합 벤치마크를 CI에 둔다([testing.md](testing.md)).
  - (d) bulk 양보(ADR-0052 결정 12 (a)). 우선순위와 BBR로도 병목 큐의 깊이는 줄지 않으므로, 대화형 트래픽(최근 2초 안의 키 입력)과 bulk(최근 1초 안에 움직인 터널·`FILE_DATA` 송신)가 한 연결에 함께 있으면 bulk 송신기가 연결마다 하나인 예산(`qsh_core::adapt::BulkGovernor`)에 값을 치르고 쓴다. PTY·세션 스트림은 예산을 묻지 않는다. 터널 splice의 송신 방향(host와 client 양쪽, localctl 데몬의 릴레이 포함)과 `FILE_DATA` 송신(host의 `file.read`, client의 `file.write`)이 대상이고, exec 출력은 세션 data 스트림을 타므로 대상이 아니다. 예산은 `queue_delay = srtt - min_rtt`가 25 ms를 넘으면 srtt마다 한 번 절반으로 줄고(큐가 12.5 ms 이상 서 있는 채로 손실이 늘어도 같다), 아니면 천장의 2%씩 는다. 하한은 `max(64 KiB/s, 천장의 5%)`, 천장은 지난 60초 최고 전달률(1초 평균)의 125%다. 제한 중에는 송신기가 쓰기를 16 KiB 알갱이로 나눠 알갱이마다 값을 치르는데, quinn이 받은 만큼을 한 번에 내보내므로 얕은 큐(20 ms, 20 Mbit/s에서 50 KB)보다 긴 덩어리는 꼬리가 버려지기 때문이다. `[transport].adaptive = "off"`면 예산이 늘 꺼져 있다. 입력이 2초 끊기면 꺼지고 터널은 원래 속도를 낸다.
- **측정으로 확정한 값:**
  - `TUNNEL_STREAM_RECEIVE_WINDOW = 2 MiB`. quinn 기본 STREAM_RWND(약 1.25 MB)보다 크다. 128 KiB는 기각됐다. 128 KiB / 50ms ≈ 2.6 MB/s가 연결 위 *모든* 스트림(PTY/exec/replay 포함)이 공유하는 처리량 상한이 되는데, loopback 기준 처리량 게이트는 raw-quinn 기준선과 tunnel 다리가 같은 연결 전체 window를 공유하므로 이 리그레션을 볼 수 없다. 그래서 이 상수에는 quinn 기본값 1,250,000 이상을 강제하는 floor assertion이 유닛 테스트(`crates/qsh-transport/src/endpoint.rs`)로 따로 있다.
  - `SEND_DEPTH_CAP_BYTES = 128 KiB`(`qsh_core::tunnel::splice`). 우선순위 band만으로는 부족했다. cap 없이 잰 echo p95는 30.579ms(요구 <10ms에 크게 미달)였고, 128 KiB cap에서는 5회 반복 p95 7.1–7.9ms, raw-quinn 대비 처리량 비율 0.899–0.945로 두 게이트(p95 <10ms, 처리량 ≥0.80 floor와 0.85 안정 기준)를 함께 만족했다.
  - UDP 소켓 버퍼(SO_RCVBUF/SO_SNDBUF)는 이 window와 별개다. OS 기본값을 낮추지 않는 하향 ladder(8/4/2/1 MiB)로, OS가 실제로 승인한 값보다 클 때만 적용한다(`bind_tuned_udp_socket`, `crates/qsh-transport/src/endpoint.rs`).
- **정체 터널 스트림 상한(ADR-0037):** 수신 창은 버퍼이기도 하다. 로컬 소비자가 읽지 않는 터널 스트림은 받은 바이트로 자기 스트림 창과 함께 연결 창도 붙잡는다. 그런 스트림 넷이면 `TUNNEL_STREAM_RECEIVE_WINDOW`(2 MiB) × 4가 `CONNECTION_RECEIVE_WINDOW`(8 MiB)를 다 써서 같은 연결의 `SESSION_DATA`가 credit을 잃는다(`crates/qsh-testkit/tests/it/tunnel_stalled_streams.rs`). 두 상수는 그대로 두고 연결마다 정체 장부(`crates/qsh-core/src/tunnel/stall.rs`)를 둔다.
  - **정체의 정의:** 수신 방향(QUIC에서 로컬로)의 로컬 쓰기가 `STALL_AGE`(1초) 넘게 한 바이트도 진전하지 않은 터널 스트림이다.
  - **끊는 규칙:** 정체 스트림이 `CONNECTION_RECEIVE_WINDOW / TUNNEL_STREAM_RECEIVE_WINDOW - 1`(3)을 넘으면 마지막 진전이 가장 오래된 것부터 끊는다. peer의 `DATA_BLOCKED` 계수가 최근 2초 안에 늘었고 정체 스트림이 있으면 가장 오래된 하나를 끊는다.
  - **끊는 방법:** §7의 splice 중단 신호와 같고 코드는 `0x200E`다. quinn은 stop된 스트림의 읽지 않은 바이트만큼 연결 credit을 곧바로 돌려준다.
  - **한계:** 느리게라도 읽는 소비자는 쓰기가 조금씩 진전하므로 정체가 아니고 역압을 그대로 받는다. 다만 진전을 알리는 것은 커널이고 막힌 쓰기는 자동 조정된 송신 버퍼가 절반쯤 비워진 뒤에야 깨어나므로, 그 절반을 `STALL_AGE` 안에 비우지 못할 만큼 느린 소비자는 읽고 있어도 정체로 셀 수 있다(`docs/design/threat-model.md` C14).
  - **범위:** 터널 스트림과 `FILE_DATA` 스트림이 장부에 오른다(ADR-0029 결정 15). `file.write`의 "로컬 쓰기"는 받은 청크를 디스크 writer에 넘기는 일이고, 끊긴 쓰기는 `0x200E`로 reset되며 임시 파일이 지워진다. control·`SESSION_DATA`·`EXEC_DATA` 스트림은 장부에 오르지 않는다. 연결 양 끝과 `localctl` daemon의 UDS·QUIC 중계(`FILE_DATA`는 터널과 같은 half-close 중계 다리를 쓰되 tunnel permit은 받지 않는다)가 같은 규칙을 쓴다. 설정 키는 없다.
- **Replay ring = 만능 decoupler:** PTY reader task는 항상 ring에만 쓰고 네트워크에 블록되지 않는다. 각 attach/read 소비자는 ring 위의 cursor다. 느린 소비자는 cursor가 밀릴 뿐이고, ring 밖으로 밀리면 `Gap`을 받고 전진한다. 세션당 메모리는 ring 8MB + 소비자별 소량으로 유계이며(CLI.md §11 backpressure 규칙), 멈춘 reader가 child process의 stdout을 막을 수 없다.
- `session read --wait`/`--follow`는 같은 cursor-pull primitive의 다른 표면이다([architecture.md](architecture.md) §3).

## 13. Fuzzing·검증 계획

신뢰 불가 입력 표면 전체를 sans-IO `qsh-proto`에 격리한다(순수 `&[u8] → Result<Frame>` + sans-IO 상태 기계). cargo-fuzz(libFuzzer) 타깃은 `fuzz/fuzz_targets/`에 **21종**이다. 처음 착륙한 파서 타깃 16종(커밋 `d87e76b`, 2026-09-02)이 1~4번 항목이고, 이후 `broker_ops`(6), `parse_socks5`(7), `parse_openssh_key`(8), `decode_file_frame`(9), `parse_ssh_bootstrap_line`(10)이 더해졌다. 5번은 fuzz 타깃이 아니라 proptest 모델 테스트다.

1. **frame layer 1종** — `frame_decoder`(구 `fuzz_frame_split`에 대응). `FrameDecoder`에 적대적 부분 청크(1-byte 피드, 쪼개진 length prefix, 상한 근접 길이)를 흘리고 `push`/`next_frame`/`take_remaining`을 임의 순서로 인터리브한다. 불변식: panic 없음, 상한 초과 할당 없음, 청킹 방식과 무관하게 결과 동일.
2. **wire·local 메시지 decode 8종**(구 `fuzz_control_decode`/`fuzz_stream_header`가 갈라진 것) — `decode_control`(`ControlMessage`, 루트 oneof), `decode_hello`(`Hello`), `decode_stream_header`(`StreamHeader`, 모든 `StreamKind` 포함 unknown 값도), `decode_session_frame`(`SessionFrame`, decode 뒤 `validate()`까지 체인), `decode_exec_frame`(`ExecFrame`), `decode_connect_result`(`ConnectResult`, `TCP_CONNECT`에서 유일하게 ticket/ACL 게이트가 없는 decode 경로), `decode_local_hello`/`decode_local_admin_request`(`qsh.local.v1`, localctl UDS 첫 두 메시지). 불변식은 원래 계획과 같다 — decode는 panic하지 않고, `Hello`/ACL 완료 전에는 control 외 어떤 리소스(PTY/exec/socket)도 생성되지 않는다.
3. **로컬 입력 파서·검증기 6종** — `valid_host_name`, `valid_forward_id`, `parse_invite_code`, `parse_forward_spec`, `sanitize_peer_text`, `fingerprint_principal`. 신뢰 불가 peer bytes가 아니라 CLI 인자·trust store·화면 표시 문자열처럼 로컬 기원 입력이지만, `qsh-proto`의 sans-IO 파서 표면에 같이 있어 같은 취급을 받는다(각 타깃 파일 머리 주석에 근거).
4. **JSON 계약 표면 1종** — `json_request_types`. `serde_json::from_slice`로 `qsh_proto::types::*Req`(에이전트가 `--json`으로 주는 요청 타입)를 흔든다.
5. **proptest 모델 테스트** — ACL `decide`를 naive coverage 오라클과 대조(`crates/qsh-core/src/acl/policy.rs`), ring buffer를 naive Vec 오라클과 대조(임의 append/attach/evict 후 replay·gap 정확성, `crates/qsh-core/src/broker/ring.rs`), reverse registry의 `generation` 단조성(`crates/qsh-core/src/reverse/registry.rs`), reverse target의 backoff 단조성(`crates/qsh-core/src/reverse/target.rs`), localctl mux의 request-id 교차 부재(`crates/qsh-core/src/localctl/mux.rs`).

**6. stateful broker fuzzer: `broker_ops`.** `arbitrary`로 생성한 control message *시퀀스*와 연결 단절 이벤트를 sans-IO broker에 주입해 default deny 유지·writer lease 단일성·sequence 단조성·gap 범위 정확성·resume token 단회성을 흔드는 stateful 타깃이다. 위 8종 decode 타깃은 메시지 하나의 decode만 흔들고 시퀀스 상태를 주입하지 않으므로 이 타깃이 따로 필요했다.
- 하네스는 `crates/qsh-core/tests/it/support/broker_ops_harness.rs`(19종 op 어휘: 세션 append/read/control, writer lease, resume issue/verify/rotate, attach/detach, tick, reap)이다. 같은 파일을 fuzz 타깃(`fuzz/fuzz_targets/broker_ops.rs`)과 nextest 회귀 재생(`crates/qsh-core/tests/it/broker_ops_corpus.rs`, `fuzz/corpus/broker_ops/` seed 15개)이 `#[path]`로 나눠 include한다.
- oracle은 naive `ModelSession`(전체 히스토리 `Vec<u8>` + lease/resume/TTL 상태를 독립 재구현) 대조다.
- **default deny 축은 `acl/policy.rs`의 proptest(§13-5)가 담당한다.** `broker_ops`는 그 대신 상태 부재·불일치 → `Err(ResumeDenied)`·`Conflict`·`CursorBeyondEnd`의 fail-closed 성질을 잰다.

**7. `parse_socks5`(ADR-0019).** `crates/qsh-proto/src/socks5.rs`의 sans-IO SOCKS5 codec(greeting·request 파서, method-select·reply 인코더)을 흔든다. 항목 3의 로컬 입력 파서들과 같은 이유(신뢰 불가 **로컬** 입력)로 이 표면에 있고, 처음 착륙한 16종과 DoD 1의 분모(파서 16종, `docs/campaigns/m8-fuzz.md` §2)에는 들지 않는 이후 추가다. 불변식: panic 없음, `consumed <= input.len()`, 유효 메시지의 엄격한 접두는 항상 `Incomplete`다.

**8. `parse_openssh_key`(ADR-0026).** `crates/qsh-proto/src/openssh/`의 손으로 쓴 OpenSSH 키 파서를 흔든다. `qsh init --import-ssh-key`가 읽는 개인키 파일과 `authorized_keys` 미리보기가 읽는 공개키 목록이 대상이다. 항목 7과 같은 이유(신뢰 불가 **로컬** 입력)로 이 표면에 있고, 항목 7과 마찬가지로 DoD 1의 분모(파서 16종)에 들지 않는 이후 추가다. 첫 입력 바이트가 봉투 해제, 이진 `openssh-key-v1` 본문, `authorized_keys` 줄 분류 중 하나를 고른다. 불변식: panic 없음, 받아들인 키의 공개키 wire blob이 온전함, 줄 번호가 입력 줄 수 안에서 단조 증가함. 길이 접두가 남은 입력보다 크면 할당 전에 거절하므로 입력 크기로 할당이 정해진다.

**9. `decode_file_frame`(ADR-0029 결정 9).** `FILE_DATA` 스트림의 프레임(`FileFrame`: `data`/`end`/`result` oneof)을 흔든다. `ExecFrame`·`SessionFrame`과 같은 종류의 신뢰 불가 peer 입력이지만 자기 프레임 상한(`DATA_FRAME_MAX`)과 청크 상한(`FILE_CHUNK_MAX` 32 KiB), 자기 인코더(`encode_file_frame`)를 가지므로 `decode_control`과 별도 타깃이다. `FileReadOpen` 등 control 쪽 새 메시지는 `ControlMessage` 안에 있어 `decode_control`이 이미 덮는다. 항목 7·8과 마찬가지로 DoD 1의 분모(파서 16종)에 들지 않는 이후 추가다. decode 뒤 `validate()`를 체인한다. 불변식: panic 없음, 수신 쪽이 받아들인 프레임은 송신 쪽 청크 상한에 걸리지 않고(전체 프레임 크기 초과만 예외), 거절된 프레임은 `ChunkTooLarge`로 거절된다.

**10. `parse_ssh_bootstrap_line`(ADR-0044 결정 11).** `crates/qsh-proto/src/ssh_bootstrap.rs`의 줄 파서 `parse_ssh_bootstrap_line`과 수신 상태 기계 `BootstrapReader`를 흔다. `qsh pair ssh`가 ssh 자식의 stdout에서 읽는 바이트는 원격 계정이 찍는 출력이라(rc 파일 출력, 그다음 응답자의 메시지) 신뢰할 수 없는 입력이다. QUIC wire는 아니지만 서로 다른 버전의 qsh 둘이 말하는 상호운용 계약이어서(§17) 이 표면에 둔다. 첫 입력 바이트가 나머지를 reader에 몇 바이트씩 나눠 먹일지 고른다(0이면 통째로). 불변식: panic 없음, 받아들인 줄은 다시 인코딩해 파싱해도 같고 한 줄이다, reader의 결과(메시지, 건너뛴 줄·바이트 수, 오류)는 청크 경계와 무관하다, 건너뛴 바이트는 `BOOTSTRAP_PREAMBLE_MAX`를 넘지 않는다. 항목 7~9와 마찬가지로 DoD 1의 분모(파서 16종)에 들지 않는 이후 추가다. 타깃당 누적 72 fuzz-hours는 아직 쌓지 않았다(`docs/campaigns/m8-fuzz.md` 형식으로 사람이 기록한다).

**11. `punch_candidates`(ADR-0054 결정 8·11·13, §19).** 첫 입력 바이트로 후보(`PunchCandidate`, `valid_punch_candidate`), 펀칭 message 다섯의 모양 검사와 `check_candidates`, 16바이트 펀치 datagram과 tag 대조 중 하나를 고른다. 검사가 panic하지 않고, 받아들인 후보 목록이 여덟 이하의 서로 다른 허용 주소이며 `accepted + dropped <= len`이고, 유효한 주소가 같은 ip·port로 다시 부호화되며, tag로 만든 datagram이 제 방향에서만 맞는 것을 단언한다. 새 message는 `decode_control` corpus에도 들어 있다.

**12. `agent_frames`(ADR-0055 결정 4·12, §20).** 첫 입력 바이트가 청크 크기(1~64)를 고르고, 나머지 바이트를 `AgentDecoder`에 그 크기로 나눠 먹인다. 단언: panic 없음, 돌려준 메시지는 길이 접두가 1 이상 `AGENT_MESSAGE_MAX` 이하이고 전체 바이트 수와 맞으며 type 바이트가 `kind`와 같다, 오류(길이 0, 상한 초과)는 그대로 유지되고 버퍼를 비운다, 청크 경계는 메시지와 오류를 바꾸지 않는다, 거르기 표는 11과 13만 넘긴다.

**13. `jump_frames`(ADR-0056 결정 4·8, §21).** 첫 입력 바이트가 청크 크기(1~64)를 고르고, 나머지 바이트를 `JumpStreamDecoder`에 그 크기로 나눠 먹인다. 단언: panic 없음, 돌려준 패킷은 1 이상 `JUMP_PACKET_MAX` 이하이고 다시 부호화하면 소비한 바이트와 같다, 오류(길이 0, 상한 초과)는 유지되고 버퍼를 비운다, 청크 경계는 패킷과 오류를 바꾸지 않는다. 입력 전체와 각 패킷에 대해 short header는 `read_long_header`가 `None`이고, `is_v1_initial_shaped`가 참이면 version 1의 long header이고 길이가 1200~1452이며, `answers_gate`는 DCID가 주어진 SCID와 같을 때만 참이다.

corpus는 `fuzz/corpus/`에 체크인한다. **21종 중 `broker_ops`는 모든 플랫폼에서 유닛 테스트로 상시 재생된다**(위 `broker_ops_corpus.rs`, 발견된 크래시의 회귀 고정). 나머지 파서 타깃 20종의 "유닛 테스트 상시 재생"은 아직 이 문서의 선언일 뿐 별도 회귀 하네스로 구현되지 않았다. 현재는 `fuzz-smoke.yml`의 짧은 결정적 `-runs=<N>` 스모크가 그 자리를 대신한다(`fuzz/README.md` "CI"). CI에서 PR마다 fuzz 빌드 게이트 + nightly smoke fuzz를 돌리고, 공개 beta 전에 타깃당 누적 72시간(파서 16종, DoD 1) + OSS-Fuzz 제출을 한다. 캠페인 기록은 [`docs/campaigns/m8-fuzz.md`](../campaigns/m8-fuzz.md), 상세는 [testing.md](testing.md).

## 14. transport 중립 제약

ADR-0005가 세우고 ADR-0043 결정 4가 TCP fallback 철회 뒤에도 유지한 제약이다. QSH의 transport는 QUIC 하나지만 wire와 프로토콜 코드는 QUIC 고유 개념에 기대지 않는다:

- 모든 프로토콜 코드는 `qsh-transport`의 백엔드 중립 파사드(`Connection`/`SendStream`/`RecvStream`: open_bi/accept, ordered reliable bytes, 우선순위 힌트)에 대해 작성한다. 백엔드가 지켜야 할 행동은 `crates/qsh-transport/tests/it/conformance.rs`가 고정한다. quinn이 첫 백엔드일 뿐이다.
- **datagram은 선택 운반체다**(ADR-0052 결정 7. ADR-0043 결정 4의 "wire가 datagram에 기대지 않는다"를 이렇게 바꾼다). datagram으로 나르는 모든 메시지는 스트림에 같은 뜻의 짝이 있고, 스트림만으로 프로토콜이 완결된다. datagram 안의 메시지는 QUIC stream ID나 transport parameter가 아니라 자기 머리의 channel id로 식별한다. `qsh-transport`는 QUIC DATAGRAM을 켜고 파사드에 `Connection::max_datagram_size() -> Option<usize>`, `send_datagram(Bytes) -> Result<(), DatagramError>`, `read_datagram()`을 둔다. `DatagramError`는 상대 미지원, 로컬 비활성, 너무 큼, 연결 끊김 넷이고 앞의 셋은 호출자가 스트림 짝으로 되돌아가라는 뜻이다. 송신은 기다리지 않고, 송신 버퍼가 차면 가장 오래된 datagram부터 버린다. 버퍼는 `DATAGRAM_RECEIVE_BUFFER_SIZE`·`DATAGRAM_SEND_BUFFER_SIZE`(각 64 KiB)로 고정하고 단위 테스트가 값을 묶는다. 이 상수는 로컬 메모리 한도라 peer가 관측하는 wire 값은 아니지만, 수신 버퍼 크기가 곧 우리가 광고하는 `max_datagram_frame_size`(상대가 보낼 수 있는 datagram의 상한)이다. 화면 갱신·`ScreenAck`·`Input` 사본이 `datagram.v1`로 이것을 쓴다(§18.9). 종류 14 `JumpPacket`(ADR-0056 결정 4)도 datagram으로 나른다. 짝은 같은 패킷을 길이 frame으로 싣는 `JUMP` 스트림이고 channel id는 `jump_channel`이다(§21). 그 밖의 메시지는 datagram을 쓰지 않는다.
- 그 밖의 QUIC 고유 개념(stream ID, transport parameter)에도 wire는 의존하지 않는다. 스트림 정체성은 항상 in-band `StreamHeader`다.
- `qsh doctor`는 P0부터 UDP reachability probe를 갖는다(차단 환경을 "미스터리"가 아닌 진단 가능한 상태로).

## 15. 페어링 프로토콜 — invite code (ADR-0002)

페어링은 스키마를 의도적으로 최소로 유지한다: 새 메시지 둘(`PairingProof`/`PairingAccepted`), 새 `Principal`/`AuthPath` variant 하나(`Pairing`), 그 외에는 기존 frame layer(§5)·직렬화(§6)·`Error`/`ErrorCode` 어휘(CLI.md §3.3)를 그대로 재사용한다. CLI 계약은 CLI.md §6.11.

### 15.1 TLS 게이트 — 세 번째 accept 경로

§3의 `QshPeerVerifier`는 기존 두 경로(pin, private CA 체인) 중 어느 쪽도 통과하지 못한 leaf 인증서를 무조건 거부한다. 페어링은 정의상 서로 한 번도 본 적 없는 상대를 다루므로, 이 거부 앞에 세 번째 경로를 하나 더 둔다: `TrustEvaluator::pairing_open(&self) -> bool`(기본 구현은 `false`)이 `true`를 답하는 동안에만, pin도 CA도 통과하지 못한 leaf가 principal `Pairing`/auth path `Pairing`으로 허용된다. `SharedTrustStore::pairing_open()`은 살아 있는(= `INVITE_RETENTION`, 20분 이내의) invite 레코드가 하나라도 있으면 `true`다 — invite가 하나도 없거나 전부 그 창을 넘기면 즉시 원래의 두-경로 전용 거부로 돌아간다. 단독 `qsh listen`과 `qsh serve --to`(구 표기 `qsh reverse`)는 이 evaluator를 attach하지 않으므로(§15.8) 이 세 번째 경로 자체가 존재하지 않는다. 합친 모드(`[listen].serve`, §11)의 `qsh listen`은 인바운드 `qsh serve`처럼 bind 전에 evaluator를 attach하므로 같은 포트에서 이 경로가 열린다. 창구는 살아 있는 invite가 있을 때만 받고 §15의 통제를 그대로 진다(ADR-0059 결정 16).

이 게이트는 **누가 pin됐는지**는 전혀 묻지 않는다 — "지금 이 host에 살아 있는 invite가 있는가"만 묻는다. 실제 인증(이 연결이 그 invite의 secret을 정말로 아는가)은 TLS 계층이 아니라 §15.3의 control-stream 교환이 담당한다.

### 15.2 dispatch 우회 — `Principal::Pairing`은 `Hello`에 닿지 않는다

`Server::serve_connection_inner`는 `handshake::respond`를 부르기 **전에** `conn.principal()`을 검사한다. principal이 `Pairing`이면 그 연결은 `Hello` 교환, `ConnCtx`, `Server::dispatch`, ACL choke point 중 어느 것에도 도달하지 않고 전용 responder(`serve_pairing_connection`)로 곧장 라우팅된다 — 증명을 검증하고, (성공하면) pin하고, 닫는 것 외에는 아무것도 할 수 없는 경로다. "인증·인가 전 리소스 생성 금지"(PRD §9, CLAUDE.md)를 ACL 규칙이 아니라 **도달 가능한 코드 자체의 모양**으로 보장한다 — 페어링 연결의 도달 가능 경로에는 애초에 세션/터널/exec 핸들러가 없다. 일반 연결에서 `PairingProof`/`PairingAccepted`가 도착하면(경로 오용) 기존의 자리를 벗어난 `Hello`와 같은 취급으로 `INVALID_ARGUMENT`다.

### 15.3 채널 바인딩 — TLS exporter

양방향 증명은 이 연결 자체의 RFC 5705 TLS exporter 값(`quinn::Connection::export_keying_material`, 32바이트)에서 유도한다. 레이블은 `b"qsh pairing v1"`(`EXPORTER_LABEL`), context는 항상 빈 값 — exporter 출력 자체가 이미 TLS session/key-share별로 유일하므로 이것으로 채널 바인딩이 충분하다. 이 바인딩의 안전 속성: 두 개의 별도 TLS 세션을 각각 종단하는 MITM은 서로 다른 exporter 값 두 개를 얻으므로, 한쪽 다리에서 유효한 증명이 다른 쪽 다리에서는 검증되지 않는다 — invite secret이 새어 나가지 않는 한, 증명을 한쪽에서 다른 쪽으로 그대로 옮겨 붙일 수 없다.

### 15.4 증명 — 도메인 분리된 두 개의 BLAKE3 keyed hash

`mac_key = blake3::hash(invite_secret)`. 두 방향의 증명은 exporter 값 뒤에 서로 다른 1바이트를 붙여 도메인을 분리한다:

- initiator → responder(`PairingProof.proof`): `blake3::keyed_hash(mac_key, exporter || 0x01)`
- responder → initiator(`PairingAccepted.proof`): `blake3::keyed_hash(mac_key, exporter || 0x02)`

두 값 다 `mac_key`(즉 invite secret)를 아는 쪽만 만들 수 있고, 어느 한쪽에서 다른 쪽을 유도할 수 없다. 도메인 분리가 필요한 이유는 이렇다. initiator의 dial-time evaluator(`AcceptAnyForPairing`)는 **어떤** 인증서든 받아들인다 — pairing의 진짜 신원 증명은 TLS identity가 아니라 secret 소유이기 때문이다. responder가 initiator의 `proof` 값을 그대로 돌려보내는 것만으로 `PairingAccepted`가 성립한다면, secret을 모르는 임의의 endpoint(잘못 입력한 IP, DNS 스푸핑, 악의적 리스너)도 받은 바이트를 반사하는 것만으로 응답을 위조할 수 있다. 두 방향을 다른 도메인으로 분리하면 반사가 통하지 않는다 — responder는 `0x02` 증명을 **독립적으로** 계산해야만 하고, initiator는 이 값을 constant-time으로(`subtle::ConstantTimeEq`) 검증한 뒤에야 responder를 pin한다. 메시지가 도착했다는 사실만으로 pin하는 코드 경로는 없다.

이 절이 보장하는 것은 정확히 "이 연결 상대는 invite secret을 안다"까지다 — 그 이상의 신원 주장은 하지 않는다. secret은 대개 전화 통화나 채팅처럼 사람이 실수하거나 어깨너머로 새어 나갈 수 있는 경로로 전달되므로, 확신을 더 높이고 싶은 operator는 페어링이 끝난 뒤 `trust list`가 보여주는 fingerprint를 out-of-band로(예: 통화 중에 서로 불러 주기) 사후 대조할 수 있다 — pairing 자체가 요구하지는 않는 defense-in-depth 단계다(CLI.md §6.11도 같은 안내를 담는다).

### 15.5 상태 기계와 오류 매핑

initiator(`qsh pair accept`, 구 `qsh trust accept`)가 control 스트림에 `PairingProof` 하나를 보낸다. responder(`qsh serve`)는 `PairingAccepted`(성공) 또는 기존 `Error` frame(실패) 중 하나만 답하고, 어느 쪽이든 그 직후 연결을 닫는다 — 이 교환은 §9의 일반 `Response` oneof를 타지 않는 pairing 전용의, 의도적으로 더 작은 메시지 모양이다.

| 조건 | 오류 코드(CLI.md §3.3) |
|---|---|
| secret이 어떤 살아 있는 invite와도 안 맞음 | `AUTH_FAILED` |
| 맞는 invite는 있으나 TTL(10분) 초과 | `TRUST_REQUIRED` |
| 맞는 invite가 이미 redeem됨 | `SESSION_CONFLICT` |
| 증명은 맞으나 pin 시점 이름 충돌(§15.7) | `SESSION_CONFLICT` |
| `PairingProof.device_name`(responder 측) 또는 `PairingAccepted.device_name`(initiator 측)이 아래 `validate_device_name` 표를 벗어남 | `INVALID_ARGUMENT` — pin·persist·tracing 어느 것도 그 값을 보기 전에 거부, 값 자체는 로그에 남기지 않는다 |
| responder의 `PairingAccepted.proof`가 검증 실패 | (initiator 로컬 실패 — 어떤 pin도 하지 않고 거부) |

`device_name`이 위 행에서 거부되는 조건은 `qsh-proto`의 `wire::validate_device_name`(`qsh-core`의 `pairing::reject_control_chars`가 양방향에서 호출) 하나의 표로 고정돼 있다:

| 조건 | 비고 |
|---|---|
| 길이가 0바이트, 또는 UTF-8로 64바이트 초과 | 바이트 길이 기준(문자 수 아님) — 멀티바이트 이름은 문자 수가 더 일찍 상한에 닿는다 |
| 제어 문자(`char::is_control()`, tab 포함) | 기존 규칙 |
| bidi override/isolate 제어(U+202A–U+202E, U+2066–U+2069, U+200E–U+200F) | `char::is_control()`이 아니라서 위 행에 안 걸린다 — 이름이 자기 자신이나 옆에 찍힌 fingerprint의 표시 순서를 뒤집을 수 있는 이른바 RLO 위장 |
| zero-width 문자(U+200B–U+200D, U+2060, U+FEFF) | 터미널에 보이지 않으므로 겉보기엔 같은 이름 두 개가 서로 다른 pin으로 갈릴 수 있다 |

invite의 TTL(10분, redeem 가능 창)과 §15.1의 retention(20분, TLS 게이트가 열려 있는 창)은 서로 다른 창이다 — TTL이 지나도 retention 안에서는 `pairing_open()`이 계속 `true`이므로, 뒤늦게 dial한 initiator는 "이 host는 애초에 페어링을 지원하지 않는다"처럼 보이는 TLS 단의 뭉뚱그려진 거부 대신 `TRUST_REQUIRED`라는 명확한 신호를 control 스트림 위에서 받는다.

`device_name`의 표 기반 거부는 인증이 아니라 표시 안전성 문제다 — `device_name`은 애초에 인증 입력이 아니고(§15 서두, v1.proto 주석), 오직 pin의 label로만 쓰인다. 그런데 CLI human 렌더러(`qsh trust add`/`qsh trust list`/`qsh pair accept`)는 `{name} ({fingerprint})`를 한 줄에 찍는다 — 그 fingerprint가 바로 §15.4가 안내하는, operator가 out-of-band로 사후 대조해야 할 값이다. `name`에 터미널 이스케이프 시퀀스나 bare `\r`, 또는 bidi override가 섞이면 같은 줄의 fingerprint를 가리거나 덮어쓰거나 순서를 뒤집어서 그 대조를 무력화할 수 있으므로, `crate::pairing::accept`/`respond` 양쪽 다 이 값을 pin·persist·tracing 어디에도 넘기기 전에 거부한다(`qsh-core/src/pairing.rs`의 `reject_control_chars`, `qsh-proto`의 `wire::validate_device_name`). 길이 상한은 이제 `CONTROL_FRAME_MAX`(256 KiB)가 아니라 위 표의 `1..=64`바이트로 좁혀져 있다.

homoglyph(confusable) 위장 — 서로 다른 코드 포인트가 같은 글리프로 렌더되는 문제 — 는 `validate_device_name`이 탐지하지 않는다. 표 기반 confusable 판정은 커스텀 crate 없이는 정확히 구현하기 어렵고, 이 자리에서 실제로 방어선 노릇을 하는 것은 판정 자체가 아니라 §15.4의 fingerprint 병기다: 이름이 아무리 비슷하게 보여도 pin은 독립적으로 검증된 fingerprint에 걸리므로, homoglyph는 operator의 눈을 헷갈리게 할 수는 있어도 신원 검사 자체를 대신하지 못한다.

### 15.6 동시 양방향 pin과 충돌

성공하면 두 장치가 **같은 교환** 안에서 서로를 pin한다 — 별도의 `trust add` 왕복이 없다. 두 pin 모두 기존 `TrustStore::add_peer` 경로를 그대로 탄다. responder 쪽 pin은 `SharedInviteStore::redeem`의 `on_matched` 훅으로 시점이 고정된다: 증명이 검증된 **직후**, invite가 소비 처리되기 **전에** 호출되어, 그 훅이 `false`(이름 충돌)를 답하면 `redeem` 자체가 `Rejected`를 반환하고 레코드는 바이트 단위로 그대로 남는다 — 충돌 실패가 invite를 태우지 않는다. initiator 쪽 pin은 이 wire 교환이 끝난 **뒤**, 완전히 로컬에서 별도로 실행된다(`Ops::trust_accept`) — 그래서 이 두 pin 사이에는 원자성이 없다: responder 쪽 pin과 invite 소비가 이미 성공한 뒤에 initiator 자신의 로컬 저장소에서 이름 충돌이 나는 경우, invite는 이미 소비된 채로 그 자리에 남고 initiator는 로컬 충돌을 별도로 해결하고 새 invite를 다시 받아야 한다(알려진 제약이다).

pin되는 이름 자체는 이 wire 교환과 별개의 축이다: `PairingProof.device_name`/`PairingAccepted.device_name`은 언제나 각자의 `device_id`를 그대로 실어 나르고, `qsh pair invite --as`/`qsh pair accept --as`가 고르는 이름은 CLI/JSON 축(초대 측은 `invites.toml`의 `assigned_name`, 수락 측은 순전히 로컬 `Ops::trust_accept` 호출)에서만 존재한다 — 어느 쪽 `--as` 값도 이 절의 `PairingProof`/`PairingAccepted` 메시지에 실리지 않는다.

어느 쪽에서 나는 이름 충돌이든, 판정 자체는 항상 크게 실패한다(`SESSION_CONFLICT`) — 상대가 자칭하는 이름이 이미 다른 fingerprint로 로컬에 pin돼 있으면, `trust add`가 같은 상황에서 취하는 조용한 no-op과 달리 페어링은 절대 조용히 넘어가지 않는다(`trust add` 자신의 no-op은 그대로 둔다).

**이미 pin된 상대가 재시도하는 경우는 위 표의 `SESSION_CONFLICT`와 겉모습은 같지만 경로가 다르다.** §15.5의 표는 `serve_pairing_connection`이 실제로 invite store를 조회한 뒤의 판정만 다룬다 — 그런데 initiator가 **이미 이 host에 pin된 신원**으로 재시도하면 그 경로 자체를 타지 않는다: §3의 `verify_core` 우선순위(pin → CA → pairing)가 pin 성공을 먼저 확인하므로, 이 연결은 `Principal::Pairing`이 아니라 보통의 인증된 연결로 분류되고, §15.2가 우회하는 그 일반 `Hello` 교환(`handshake::respond`)으로 들어간다. 거기서 첫 control frame이 여전히 `PairingProof`로 도착하면, `handshake::respond_on`은 이를 `Hello`의 자리를 벗어난 메시지로 취급해 명시적인 `SESSION_CONFLICT`(`retryable: false`) 오류 frame을 쓰고 연결을 닫는다 — invite store는 전혀 건드리지 않는다. 그래서 새 invite를 다시 발급받아도 소용이 없다: 문제는 code나 invite의 상태가 아니라 이 신원이 host에 이미 pin되어 있다는 사실 자체이기 때문이다. 복구하려면 host가 `trust remove`로 기존 pin을 지운 뒤에야 같은 initiator가 새 invite로 다시 페어링할 수 있다(CLI.md §6.11, README Known limitations).

**pairing 연결 자체가 상한을 넘는 경우도 위 재시도 경로와 마찬가지로 §15.5의 표 밖이다.** `Principal::Pairing`으로 분류된 연결이 고정 상한(`MAX_CONCURRENT_PAIRING_CONNECTIONS = 8`)을 넘겨 도착하면, `Server::serve_connection`은 그 표가 다루는 `PairingProof` 판정에 아예 들어가지 않는다 — control 스트림을 받지 않고 proof도 읽지 않은 채, 연결을 `CLOSE_CODE_RESOURCE_EXHAUSTED`(`0x1003`)로 즉시 닫는다. 표의 다른 모든 행과 마찬가지로 이 거부도 non-distinguishing이다: `AUTH_FAILED`(secret 불일치)와 겉모습이 다른 `Error` frame조차 쓰지 않으므로, initiator는 invite가 존재하는지조차 이 거부 하나로는 알 수 없다. 감사에는 `quota_connections_pairing`으로 실체가 남는다(`docs/CLI.md` §6.12).

### 15.7 재시작 없는 invite 인식

`qsh serve`는 시작 시점에 `invites.toml`을 한 번 열어 `SharedInviteStore`를 `SharedTrustStore`에 붙인다(`trust.attach_pairing(...)`, `Listener::bind`보다 먼저 — TLS 검증이 참조하는 evaluator와 동일 인스턴스여야 하므로). 이후의 redeem·`pairing_open()` 조회는 매번 파일을 다시 열어 **내용**을 비교한다 — `trust.toml`의 재로드가 따르는 것과 같은 원칙(CLI.md §6.11 `trust.remove` 문단, mtime이 아니라 바이트 비교가 유일한 판정자)이 invite store에도 그대로 적용된다. 별도 프로세스로 실행된 `qsh pair invite`(구 `qsh trust invite`)가 파일에 새 invite를 쓰면, 이미 떠 있는 `qsh serve`는 재시작·시그널 없이 바로 다음 연결부터 그 invite를 인식한다.

raw secret은 디스크에 절대 남지 않는다 — `invites.toml`에는 `mac_key`(secret의 BLAKE3 해시)와 생성 시각만 기록되고, 파일 자체는 0600이다.

다만 `mac_key`는 통상적 의미의 "안전하게 해시된 비밀"이 아니다. §15.4의 두 증명 모두 raw secret이 아니라 `mac_key` 자체를 keyed-hash의 key로 쓰므로, `invites.toml`을 읽을 수 있는 자는 raw secret 없이 `mac_key`만으로 그 invite의 양방향 증명을 전부 계산할 수 있다 — 즉 `mac_key`는 이 invite에 대해 raw secret과 동등한 verifier다. 이 파일을 실제로 지키는 것은 해시 연산이 아니라 순전히 파일 권한(0600)이다: 같은 계정의 다른 프로세스, 백업, 잘못 설정된 sync 등으로 0600이 뚫리면, 그 invite의 TTL이 남아 있는 동안 누구든 그것만으로 페어링을 완료할 수 있다.

TLS 게이트(`pairing_open()`, §15.1)는 redeem 여부를 보지 않고 오직 `INVITE_RETENTION` 창(20분)만 본다 — 그래서 이미 redeem된 invite라도 그 창이 남아 있는 한 `Principal::Pairing` 경로 자체는 계속 열려 있고, 실제 거부(`SESSION_CONFLICT`, §15.5)는 그 다음 단인 redeem 판정에서만 난다. 이 관찰이 뭔가를 뚫는 것은 아니다 — redeem 판정 자체가 여전히 매번 지켜지므로 이미 소비된 invite로 재인증을 완성할 방법은 없다 — 소비 즉시 TLS 게이트까지 함께 닫는 더 좁은 창은 현재 구현하지 않는다.

### 15.8 범위

이 절은 forward-host 페어링만 다룬다. forward host는 인바운드 `qsh serve`와, `[listen].serve`를 켠 합친 `qsh listen`(ADR-0059 결정 16)이다. 단독 `qsh listen`과 `qsh serve --to`(구 표기 `qsh reverse`)(역방향 conduit)는 이 evaluator를 attach하지 않으므로 페어링 대상이 아니다 — reverse target은 애초에 자신의 accept loop을 돌리지 않고 controller에 dial해 들어가는 쪽이라, 이 절의 TLS 게이트(§15.1)에 도달할 경로 자체가 없다.

### 15.9 Fuzzing

`PairingProof`/`PairingAccepted`는 `ControlMessage.body` oneof의 새 variant일 뿐이므로 §13의 `decode_control` 타깃(`ControlMessage::decode` 전체를 `arbitrary` structure-aware 변형으로 흔드는 타깃)이 이 두 메시지도 그대로 덮는다. 별도 타깃은 필요 없고, 페어링은 §13의 타깃 목록에 새 표면을 추가하지 않는다. §13의 `decode_control` 타깃(`ControlMessage::decode` 전체를 `arbitrary` structure-aware 변형으로 흔드는 타깃)이 이 두 메시지도 그대로 덮는다. 별도 타깃은 필요 없고, 페어링은 §13의 타깃 목록에 새 표면을 추가하지 않는다.

## 16. Wire format freeze (v1)

**상태: 발효.** 발효 조건이던 SC7 운영자 판정은 ADR-0049(2026-11-05, 사용자 결정)로 기록됐다. 판정은 (나), 곧 외부 보안 리뷰를 예약하지 않고 freeze를 진행하는 쪽이고, 리뷰는 뒤에도 하지 않는다. 발효 뒤의 변경 규율은 §16.4·§16.5다.

- 발효 일자: 2026-11-05
- 발효 커밋: ADR-0049를 더한 커밋(`git log --format=%h -1 -- docs/adr/0049-skip-independent-security-review.md`)

### 16.1 동결 대상 — `.proto` 계약 (§9)

§9가 정의하는 `qsh.wire.v1`의 message·field 번호 배정 전체가 얼어붙는다. 정의 위치는 줄 번호가 아니라 심볼로 적는다(줄 번호는 편집마다 어긋난다).

| 항목 | 정의 위치 | 값 |
|---|---|---|
| `ControlMessage` oneof 태그(25 branch) | `crates/qsh-proto/proto/qsh/wire/v1.proto`의 `message ControlMessage` | `hello=10`, `response=11`, `session_open=20`…`session_write=28`(`25`는 결번), `exec_start=30`, `rfwd_open=40`, `rfwd_close=41`, `ping=50`, `pong=51`, `session_event=60`, `pairing_proof=70`, `pairing_accepted=71`, `file_read_open=80`…`file_mkdir_open=83`, `punch_request=90`, `punch_offer=91`, `rendezvous_query=92` |
| `Response` oneof 태그(17 branch + `error`) | 같은 파일의 `message Response` | `session_opened=1`…`session_closed=10`, `file_read_opened=11`…`file_mkdir_done=14`, `error=15`, `punch_reply=16`, `punch_answer=17`, `rendezvous_list=18` |
| top-level `message` 선언 73종의 필드 번호 전체 | 같은 파일 | `grep -c '^message '` = 73 (ADR-0029의 파일 op message 12종, ADR-0054의 펀칭 message 7종 포함) |
| `enum PunchCandidateKind` / `enum PunchRefusal` | 같은 파일 | `UNSPECIFIED=0`/`HOST=1`/`REFLEXIVE=2`; `NONE=0`/`TARGET_NOT_REGISTERED=1`/`TARGET_UNSUPPORTED=2`/`TARGET_DENIED=3`/`TARGET_BUSY=4`/`TARGET_TIMEOUT=5`. 모르는 값은 decode를 실패시키지 않는다 |
| `ATTEMPT_ID_LEN` / `PUNCH_FINGERPRINT_LEN` / `MAX_PUNCH_CANDIDATES` / `MAX_RENDEZVOUS_FINGERPRINTS` / `PUNCH_MESSAGE_MAX` | `crates/qsh-proto/src/punch.rs` | 16 / 32 / 8 / 4 / 1024 바이트(§19.2) |
| `reserved 25` | 같은 파일의 `ControlMessage` 안 | 구 `SessionSignal`, 번호만 예약(P1). prost는 unknown field를 버리므로 25는 body 없는 `ControlMessage`로 디코드되고, 호스트는 `UNSUPPORTED`로 답한다(§9) |
| `AttachMode.ATTACH_MODE_RO = 2` | 같은 파일의 `enum AttachMode` | `UNSPECIFIED=0`/`RW=1`/`RO=2`. 오늘 hosts는 RO 요청에 `INVALID_ARGUMENT`로 답한다 — `reserved 25`와 같은 성격의 예약 번호다 |
| `ErrorCode` 어휘 16종 + `Unknown(raw)` passthrough | `crates/qsh-proto/src/error.rs`의 `ErrorCode::KNOWN`과 모듈 머리의 passthrough 정책 | `InvalidArgument`…`Internal` 16종. 미지 문자열은 `Unknown(raw)`로 무손실 왕복 |
| ALPN | `crates/qsh-proto/src/wire.rs`의 `ALPN`; 1차 결정 `docs/adr/0001-custom-quic-protocol.md` | `qsh/1` |
| Frame 헤더 레이아웃 | `crates/qsh-proto/src/frame.rs` 머리 주석; 1차 결정 `docs/adr/0001-custom-quic-protocol.md` | `u32` BE length prefix + prost body. ADR-0001이 이 모양을 고른 결정적 이유는 P1 TCP fallback(ADR-0005)을 wire 변경 없이 얹기 위해서다 — 이 layer를 얼리는 것은 그 경로도 함께 지키는 일이다 |
| `CONTROL_FRAME_MAX` / `DATA_FRAME_MAX` | `crates/qsh-proto/src/frame.rs` | 256 KiB / 64 KiB |
| `EXEC_CHUNK_MAX` / `SESSION_CHUNK_MAX` / `SESSION_READ_MAX_BYTES` | `crates/qsh-proto/src/wire.rs` | 16 KiB / 16 KiB / 192 KiB |
| `FILE_CHUNK_MAX` / `FILE_LIST_PAGE_MAX` / `FILE_LIST_DIR_MAX` / `FILE_WRITE_FREE_RESERVE` | `crates/qsh-proto/src/wire.rs` | 32 KiB / 512 / 65536 / 256 MiB |
| `enum FileKind` | 같은 파일의 `enum FileKind` | `UNSPECIFIED=0`/`FILE=1`/`DIR=2`/`SYMLINK=3`/`OTHER=4` |
| `StreamKind` enum | `crates/qsh-proto/proto/qsh/wire/v1.proto`의 `enum StreamKind` | `STREAM_KIND_UNSPECIFIED=0`/`SESSION_DATA=1`/`EXEC_DATA=2`/`TCP_CONNECT=3`/`TCP_ACCEPTED=4`/`FILE_DATA=5`/`AGENT=6`/`JUMP=7`. 0값의 취급은 §16.8 |
| sequence 시맨틱 | §8; `crates/qsh-core/src/broker/ring.rs` 머리 주석 | 세션 수명 누적 output byte offset(`u64`). 오프셋 배정은 `ReplayStore::push` 한 곳뿐 |

### 16.2 동결 대상 — `.proto` 밖의 상호운용 계약

`.proto`에 실리지 않지만 peer 간 상호운용을 좌우하는 값들도 함께 얼어붙는다.

| 항목 | 정의 위치 | 값 |
|---|---|---|
| 0-RTT 전면 금지 | §2; `crates/qsh-transport/src/endpoint.rs`의 client/server TLS 구성 | client `enable_early_data = false` + `Resumption::disabled()`; server `max_early_data_size = 0` + `send_tls13_tickets = 0` + `NoServerSessionStorage`. §2가 남긴 조건("의심스러우면 `NoServerSessionStorage`로 끈다")은 코드가 이미 무조건 끄는 쪽으로 해소돼 있다 — 이 freeze가 그 사실을 확정 서술로 올린다 |
| TLS 검증 코어 `QshPeerVerifier` | §3 | pin(SPKI SHA-256) → private CA 체인 → 거부. leaf 유효기간 항상 검사. web PKI root 미적재. TLS 1.3 전용 양방향 |
| pairing exporter label / 도메인 분리 접미사 | §15.3–15.4; `crates/qsh-core/src/pairing.rs`의 `EXPORTER_LABEL` | `b"qsh pairing v1"`, context 빈 값; `exporter‖0x01`(initiator→responder) / `exporter‖0x02`(responder→initiator) |
| `session_id` / `forward_id` 모양 | `session_id`: `crates/qsh-core/src/server/mod.rs`의 `valid_session_id`(상한 `SESSION_ID_MAX_LEN = 64`; §9 "세션 id는 모양부터 검사한다"). `forward_id`: `crates/qsh-proto/src/wire.rs`의 `valid_forward_id`(§7) | 둘 다 `1..=64` bytes `[A-Za-z0-9_-]` |
| `device_name` / `offered_name` 검증 | §15.5; `crates/qsh-proto/src/wire.rs`의 `validate_device_name`·`valid_host_name` | `device_name`은 `1..=64` bytes, 제어문자·bidi override/isolate·zero-width 거부(homoglyph는 의도적 미검사, §15.5). `offered_name`은 빈 문자열이거나 `1..=64` bytes `[A-Za-z0-9._-]`(빈 값은 controller가 이름을 정하는 정상 경로, §9 `ReverseRegistration.offered_name`, 모양 규칙은 §11-2) |
| priority band | §12; `crates/qsh-proto/src/wire.rs`의 `PRIORITY_*` | control=200 / session_data=100 / exec_data=50 / tunnel=0. 송신 큐 힌트라 peer가 관측하는 값은 아니지만 이 문서가 명문화한 값이다 |
| SSH 부트스트랩 스트림 | §17; `crates/qsh-proto/src/ssh_bootstrap.rs` | 줄 접두 `qsh-bootstrap `, 한 줄 8 KiB, hello 앞 접두 없는 줄 합계 64 KiB, 메시지 셋(`hello`·`commit`·`result`)과 `type` 태그, 부트스트랩 버전 `[1]`, `status` 어휘. `.proto`에 실리지 않지만 서로 다른 버전의 qsh 둘이 ssh 파이프 위에서 말하므로 §16.4의 additive-only를 같은 방식으로 따른다 |

### 16.3 동결 밖

아래는 freeze가 명시적으로 선을 그은 것들이다 — wire freeze의 additive-only 규율(§16.4)이 적용되지 않는다.

- **`qsh.local.v1`**(localctl UDS). `crates/qsh-proto/proto/qsh/local/v1.proto` 머리말이 이유를 직접 적고 있다. wire freeze가 얼리는 것은 네트워크를 건너 두 peer 사이를 오가는 원격 계약 `qsh.wire.v1`뿐이고, 이 파일의 메시지는 전부 한 머신 안, same-uid만 열 수 있는 소켓 위에서만 오간다. 별도 버전 축(`LOCAL_HELLO_VERSION = 2`, `crates/qsh-proto/src/local.rs`)을 쓴다.
- **`qsh.event/v1` JSON 봉투**(`crates/qsh-proto/src/event.rs`의 `EVENT_SCHEMA`, `KNOWN_EVENT_TYPES` 5종). wire의 `SessionEvent`(태그 60)와는 다른 표면이고, `docs/CLI.md` §10이 이미 자기 additive-only 규율을 갖는다 — 대조는 §16.6.
- **`ForwardSpec`/`ForwardDirection`**(`crates/qsh-proto/src/wire.rs`의 `ForwardSpec`·`ForwardDirection`). `-L`/`-R` CLI 인자를 로컬에서 파싱한 결과 타입이지 wire에 실리는 값이 아니다 — `.proto` 전체에 이 이름의 message도 field도 없다. `parse_forward_spec`이 §13의 fuzz 타깃인 것은 신뢰 불가 **로컬** 입력 파서이기 때문이지, wire 표면이기 때문이 아니다.
- **QUIC RESET/CLOSE 코드값**(`0x1001`~`0x200E`). CLOSE 대역(`0x100x`)의 정의 위치는 `crates/qsh-transport/src/endpoint.rs`(`CLOSE_CODE_UNVERIFIED_PEER`·`CLOSE_CODE_PROTOCOL`·`CLOSE_CODE_TRUST_WITHDRAWN`·`CLOSE_CODE_NOT_ADOPTED`)·`crates/qsh-core/src/server/mod.rs`(`CLOSE_CODE_RESOURCE_EXHAUSTED`)·`crates/qsh-core/src/reverse/listen.rs`(`CLOSE_CODE_REPLACED`·`CLOSE_CODE_PATH_DEAD`)·`crates/qsh-core/src/reverse/target/mod.rs`이고, RESET 대역(`0x200x`)의 근거는 §7이다. `0x1005`(`CLOSE_CODE_TRUST_WITHDRAWN`)는 로컬 trust store가 더는 연결을 보증하지 않아 닫을 때 쓰는 값이다(ADR-0031 결정 7). `0x1006`(`CLOSE_CODE_NOT_ADOPTED`, `crates/qsh-transport/src/endpoint.rs`)은 펀칭 경주에서 채택되지 않고 이미 선 연결을 닫을 때 쓰는 값이고 reason은 고정 문자열 `not adopted`다(ADR-0054 결정 15, §19.6). 이 값들이 동결 밖인 이유와 그것이 뜻하지 않는 것은 §16.5 끝에서 다룬다.
- **우선순위 band 값**. 로컬 송신 큐 힌트일 뿐 peer가 관측하는 wire 필드가 아니다(값 자체는 §16.2에 명문화돼 있다).
- **SOCKS5 로컬 codec**(`crates/qsh-proto/src/socks5.rs`, ADR-0019). `-D`가 로컬 loopback listener에서 받는 클라이언트 프로토콜이지 두 `qsh` peer 사이의 wire 계약이 아니다 — `.proto`에 이 이름의 message가 없다. `parse_socks5`가 §13의 fuzz 타깃인 것도 `parse_forward_spec`과 같은 이유(신뢰 불가 로컬 입력)이지 wire 표면이기 때문이 아니다.

### 16.4 허용되는 변경 — additive-only

- 새 `message`, 또는 기존 oneof에 새 필드 번호 추가. 기존 번호의 재사용·재번호는 §16.5의 금지 사항이다.
- **예약된 번호를 그 예약 대상으로 채우는 것.** 오늘 예약된 번호는 둘이다 — `reserved 25`(구 SessionSignal, P1)와 `AttachMode.ATTACH_MODE_RO = 2`(오늘은 `INVALID_ARGUMENT`). 둘 다 나란히 적어 둔다 — 나중에 "이 번호는 예약이었나 폐기였나"라는 분기가 생기지 않도록.
- 새 `StreamKind` 값과 새 datagram 종류. `agent.v1`의 `AGENT=6`, `jump.v1`(ADR-0056)의 `JUMP=7`과 종류 14 `JumpPacket`이 그 사례다. 모르는 `StreamKind`는 `stream_kind()`가 `None`을 돌려주고 받는 쪽이 `BAD_HEADER` reset으로 답하며, 모르는 datagram 종류는 버린다. sender는 협상된 교집합에 해당 capability가 있을 때만 연다.
- 새 capability 문자열과 그 capability에 딸린 새 optional message. `punch.v1`(ADR-0054)이 가장 새 사례다: `ControlMessage`의 새 블록 90번대(90~92)와 `Response`의 16~18, 새 message 7종과 enum 2종은 모두 이 규칙으로 들어왔고, sender는 협상된 교집합에 `punch.v1`이 있을 때만 보낸다. 기존 번호는 건드리지 않았다.
- 새 `ErrorCode` 문자열. 구버전 peer는 `Unknown(raw)`로 무손실 왕복한다(`crates/qsh-proto/src/error.rs`; JSON 쪽 대응 규율은 `docs/CLI.md` §10).
- **ADR-0018 결정 3.** `RemoteForwardOpen`의 `forward_id` 재수락(`-R` 자동 재발행)은 v1에 넣지 않는다. 필요해지면 P1 이후 `reclaim: bool` 같은 additive 필드로 넣을 수 있고, 이 freeze는 그 경로를 막지 않는다(`docs/adr/0018-tunnel-lifetime-bound-to-connection.md`). ADR-0023은 이 길을 쓰지 않았다. `-R` 재발행은 새 connection 위에서 옛 `forward_id`를 `RemoteForwardClose`로 닫고 `RemoteForwardOpen`을 다시 보내는 기존 두 op의 조합이다.
- **ADR-0019 결정 4.** 기존 message에 새 필드 번호를 더하는 것 — 단, 기본값의 의미가 오늘 동작과 같고, 송신자가 그 필드를 이해하는 peer임을 capability로 먼저 확인한 경우에 한한다. `StreamHeader.deny_host_local = 5`(§9, `dial-filter.v1` capability로 보호, 기본값 `false` = 무필터)가 이 경로로 들어온 첫 사례다. ADR-0018 결정 3의 `reclaim` 항목과 같은 성격 — 새 번호이지 새 `oneof` branch나 재번호가 아니다.

### 16.5 금지되는 변경 — major bump 사유

- 기존 필드 번호의 재사용·재번호·타입 변경·삭제.
- frame 헤더 레이아웃 변경(§5).
- `CONTROL_FRAME_MAX`/`DATA_FRAME_MAX` 축소.
- TLS 검증 경로(pin → CA → 거부)의 의미 변경, 0-RTT 허용.

이 중 하나라도 필요해지면 ALPN을 `qsh/2`로 올린다 — `qsh/1`은 그대로 두고 새 major로 파괴적 개정을 실어 보낸다(§4).

QUIC RESET/CLOSE 코드값(`0x1001`~`0x200E`, CLOSE 대역 정의 위치는 §16.3, RESET 대역은 §7)은 이 목록에 없다 — 애초에 §16.1/§16.2의 동결 대상이 아니기 때문이다(§16.3). 다만 "동결 밖"이 "아무 때나 바뀐다"는 뜻은 아니다. §7이 말하는 것은 "peer가 이 값에 의존해 분기하면 안 된다"이지 값의 안정성 자체를 포기한다는 뜻이 아니다 — 이 값들은 wire 계약이 아니므로 peer는 값에 의존해서는 안 되지만, 진단·audit 상관관계를 위해 major 버전 안에서는 재배치하지 않는다. `0x1005`(`CLOSE_CODE_TRUST_WITHDRAWN`, reason은 고정 문자열 `trust withdrawn`)는 `0x1001`~`0x1004` 옆에 새로 놓인 값으로, 같은 규율을 받는다. 닫은 쪽이 로컬이든 상대든 `Connection::closed_by_trust_withdrawal`이 이 값을 읽을 수 있지만, 두 peer 사이의 상호운용은 값에 의존하지 않는다. 지금 `0x1003`은 서버 accept 경로의 용량 거부(`crates/qsh-core/src/server/mod.rs`의 `CLOSE_CODE_RESOURCE_EXHAUSTED`)와 reverse 등록 교체(`crates/qsh-core/src/reverse/listen.rs`의 `CLOSE_CODE_REPLACED`)가 각자 정의해 같은 값에 이름이 둘이다. 발신 지점이 다르고 close reason 문자열도 다르므로 지금 부딪히지는 않지만, 값을 갈라 둘지는 §16 발효 판정과 함께 정한다.

### 16.6 wire major와 JSON major는 독립 트랙

wire major(ALPN `qsh/N`)와 JSON major(`qsh.cli/vN`, `qsh.event/vN`)는 서로 다른 표면이다 — 전자는 mTLS로 인증된 두 qsh 인스턴스 사이, 후자는 CLI/에이전트와 로컬 `qsh` 바이너리 사이다. **wire major bump는 `qsh.cli/vN`·`qsh.event/vN`을 자동으로 무효화하지 않는다. 반대도 같다.**

대조할 JSON 쪽 원문은 `docs/CLI.md` §10 "Compatibility policy"다: optional field·새 event `type` 추가는 허용되고, `reason`/`state`/`error.code` 같은 열린 문자열 field에 새 값을 더하는 것도 허용된다. 삭제·type 변경·의미 변경은 `/v2`이고, deprecated field는 최소 두 minor release 유지하며, `qsh schema --json`으로 지원 version·deprecation을 조회한다. CLAUDE.md의 계약 안정성 규칙("`qsh.cli/v1`과 `qsh.event/v1`은 additive-only")이 이 JSON 표면에 적용한 것과, §16.4의 wire additive-only가 이 절에서 적용한 것은 같은 원칙을 서로 다른 표면에 적용한 것뿐이다 — 두 표면은 서로를 강제하지 않는다. `tests/` 밑 JSON 픽스처의 append-only 규칙도 이 wire freeze로 새로 생기는 것이 아니라 원래부터 별도 규율이다.

wire 쪽에는 JSON 쪽의 "두 minor release 유지"와 `qsh schema --json` 조회에 대응하는 메커니즘이 없다 — 이 비대칭을 메우지는 않는다. §16.7이 이유를 적는다.

### 16.7 minor version의 의미

`WIRE_MINOR_VERSIONS`(`crates/qsh-proto/src/wire.rs`)는 v1 내내 `&[0]` 하나만 유지한다. minor 축은 `Hello.versions`의 협상 필드로 예약돼 있을 뿐 지금은 쓰지 않는다 — additive 확장은 이미 capability 문자열(§4)이 맡고 있어서, 지금 minor를 올릴 이유가 없다. 새 minor의 의미를 나중에 정의하는 것 자체는 §16.4의 additive 변경으로 허용된다. 이것은 `docs/CLI.md` §10의 minor(릴리스 축, deprecation 창을 정의하는 축)와는 다른 축이다 — wire minor를 JSON minor와 같은 의미로 맞추는 선택지도 있었지만, wire에는 애초에 CLI의 deprecation 개념(additive-only + `reserved`로 이미 대체돼 있다)이 없어 맞출 이유가 없었다.

### 16.8 `StreamKind`의 0값

`STREAM_KIND_UNSPECIFIED = 0`은 유효한 kind가 아니다. proto3에서는 미설정 필드가 자동으로 0을 갖는데, 이것을 `SESSION_DATA` 등과 같은 취급으로 두면 "kind를 아예 지정하지 않은 스트림"과 "0을 kind로 명시한 스트림"이 구별되지 않는다. `decode_stream_header` 퍼즈 타깃(§13)이 이 값과 그 밖의 unknown 값까지 흔드는 것이 이 규정의 실행 계약이다.

### 16.9 §13과의 교차 참조 — freeze 표면이 곧 fuzz 표면이다

`qsh.wire.v1`이 신뢰 불가 입력 표면 전체라는 것은 이 freeze가 새로 정하는 것이 아니라 ADR-0001의 원래 결정이다(`docs/adr/0001-custom-quic-protocol.md` "신뢰 불가 입력을 다루는 파싱 코드는 `qsh-proto`에 격리되어 cargo-fuzz 타깃으로 커버 가능해야 한다"). 이 절이 얼리는 표면과 §13이 흔드는 표면은 같다 — §16.4에 따라 새 wire op을 additive로 추가할 때마다, 그 op의 decode 경로가 §13의 대응 타깃(대개 `decode_control`)에 이미 걸리는지 확인하는 것이 이 규율을 실제로 지키는 방법이다. 누적 fuzz-hours와 배치 실행 기록은 [`docs/campaigns/m8-fuzz.md`](../campaigns/m8-fuzz.md)가 canonical이다. (이 등식은 §13-1~4의 파서 타깃 16종에 한정된다. §13-6의 `broker_ops`는 반대 방향으로, 동결 대상이 아닌 broker 내부 상태 기계(§16.3)를 흔든다 — freeze 표면을 넓히지 않는다.)

### 16.10 발효 절차

1. SC7 판정((가)/(나), `docs/ROADMAP.md` M8 DoD 4)이 기록된다. 2026-11-05 ADR-0049가 (나)로 기록했고 1~4를 그 커밋에서 마쳤다.
2. 이 절 머리의 상태를 "발효"로 바꾸고 발효 일자·커밋을 채운다.
3. `README.md`의 Known limitations 또는 Security posture 절에 한 줄을 더한다 — wire format `qsh/1`이 그 일자·커밋부터 동결됐다는 것과, 변경 규율이 이 절이라는 것.
4. 판정이 (나)(예약 없이 freeze만 진행)라면 `docs/PRD.md`의 SC7 문장도 함께 개정한다 — 이 개정은 이 절이 아니라 그 판정을 낸 세션의 몫이다.

## 17. SSH 부트스트랩 스트림 (ADR-0044)

`qsh pair ssh <dest>`는 시스템 `ssh`로 원격에서 `qsh pair ssh-respond`를 부르고, 두 프로세스는 그 ssh 자식의 stdin·stdout으로 말한다(ADR-0044 결정 9). 이 스트림은 QUIC wire가 아니다. `.proto`도 없고 `qsh/1` ALPN과도 무관하다. 그래도 서로 다른 버전의 qsh 둘이 말하는 상호운용 계약이라서 여기에 싣고, §16.2 목록에 올려 §16.4의 additive-only 규칙을 같은 방식으로 적용한다(ADR-0044 결정 11, §16 freeze 발효 뒤에도 같다). 구현은 `crates/qsh-proto/src/ssh_bootstrap.rs`(sans-IO)이고 신뢰 불가 입력 파서라서 fuzz 타깃 `parse_ssh_bootstrap_line`이 붙는다(§13-10). ssh를 부르고 pin을 쓰는 절차는 `qsh-core`의 몫이고 이 절은 바이트에 실리는 것만 정한다.

### 17.1 줄 형식과 상한

- 메시지 하나가 한 줄이다. 줄은 `\n`으로 끝나고(`\r\n`도 받는다) 고정 접두 `qsh-bootstrap `(끝의 공백 포함, `BOOTSTRAP_LINE_PREFIX`) 뒤에 JSON 객체 하나가 온다. 직렬화는 개행을 이스케이프하므로 객체 안에 개행 문자가 들어가지 않는다.
- 한 줄은 접두를 포함해 8 KiB(`BOOTSTRAP_LINE_MAX`, 8192바이트)를 넘지 않는다. 수신 쪽은 줄이 끝나기를 기다리지 않고 상한을 넘는 순간 버린다. 송신 쪽 인코더도 상한을 넘는 메시지는 내보내지 않는다.
- 객체의 `type`이 `hello`, `commit`, `result` 중 하나로 메시지를 가른다. ADR-0044 결정 11은 세 메시지의 필드만 적고 구별 방식을 적지 않아서, 필드 구성에 기대지 않는 명시 태그를 이 절이 정한다. 모르는 `type`은 형식 오류다.
- hello 앞에는 원격 셸의 rc 파일이나 배너가 찍은 접두 없는 줄이 올 수 있다. 수신 쪽은 이런 줄을 합계 64 KiB(`BOOTSTRAP_PREAMBLE_MAX`, 개행 포함)까지 건너뛰고 줄 수와 바이트 수만 센다. 내용은 저장하지도 로그나 출력에 내지도 않는다. 줄이 접두로 시작하는지는 첫 14바이트로 정해서, 상한 없이 이어지는 한 줄이 메모리를 쓰지 못한다.
- hello 뒤로는 접두 없는 줄이 하나라도 오면 프로토콜 오류다. result 뒤에 오는 어떤 줄도 오류이므로 client는 result를 받으면 읽기를 멈춘다.

### 17.2 메시지

| 방향 | `type` | 필드 |
|---|---|---|
| 응답자 → client | `hello` | `versions`(지원하는 부트스트랩 버전, 이 절은 `[1]`), `qsh_version`, `status`(`ready`·`not_initialized`), `status`가 `ready`일 때 `fingerprint`(`sha256:BASE64`)·`serve_bind`·`serve_listening`(`true`·`false`, 모르면 `null` 또는 생략), 선택 `on_demand`(`true`면 이 응답자가 `commit.ensure_serve`를 안다, §17.6), 선택 `replace_pin`(`true`면 `commit.replace`를 안다, §17.7) |
| client → 응답자 | `commit` | `version`(고른 버전), `fingerprint`(client의 것), `name`, `role`, 역방향일 때만 `address`, 선택 `ensure_serve`(`true`, §17.6), 선택 `replace`(`true`, §17.7) |
| 응답자 → client | `result` | `status`(`pinned`·`exists`·`conflict`·`error`), `name`, `role`(없으면 `null`), `created`, 실패면 `code`(`ErrorCode` 어휘)와 `message`, `ensure_serve`에 답할 때만 `serve_bind`·`serve_started`·`serve_session_scoped`(§17.6), `replace`에 답할 때만 `replaced_fingerprint`(§17.7) |

순서는 hello, (client가 commit을 보냄), result 하나씩이다. client 쪽 수신 상태 기계는 첫 접두 줄이 hello가 아니거나, hello가 둘이거나, result 앞의 다른 메시지이거나, result 뒤에 줄이 있으면 순서 위반으로 끝낸다.

### 17.3 버전과 호환

- 버전은 정수 목록이다. client가 `hello.versions`와 자기 목록의 교집합에서 가장 큰 값을 `commit.version`으로 고른다(`negotiate_version`). 교집합이 비면 commit을 보내지 않고 `UNSUPPORTED`로 끝난다.
- 알 수 없는 필드는 무시한다. 필수 필드가 없거나 타입이 어긋나면 형식 오류다. 필수 여부는 위 표의 필드 목록이 그대로 기준이고, 선택 필드(`fingerprint`·`serve_bind`·`serve_listening`·`on_demand`·`address`·`ensure_serve`·`code`·`message`·`serve_started`·`serve_session_scoped`, result의 `serve_bind`, `replace_pin`·`replace`·`replaced_fingerprint`)는 없어도 된다. 파서를 느슨하게 푸는 변경은 호환되지만 조이는 변경은 아니므로 필수로 두는 쪽을 보수적으로 골랐다.
- `status`는 열린 문자열이다. 이 빌드가 모르는 값은 별도 변종(`Unknown`)으로 보존해 호출자가 `REMOTE_ERROR`(`details.reason: "bootstrap_protocol"`)로 끝내게 한다. 파서가 추측하지 않는다. 그 문자열은 peer가 쓴 것이므로 화면에 내기 전에 `sanitize_peer_text`를 거친다.
- 허용되는 변경은 §16.4와 같다. 새 선택 필드와 새 `status` 값을 더하는 것은 부트스트랩 버전을 올리지 않는다. 기존 필드의 제거, 의미 변경, 타입 변경, 그리고 새 `type`(모르는 쪽이 형식 오류로 끝낸다)은 새 부트스트랩 버전이 필요하다.

### 17.4 오류와 로그

줄 파서와 수신 상태 기계의 오류(접두 없음, 8 KiB 초과, 형식 오류, 64 KiB 초과, hello 뒤 접두 없는 줄, 순서 위반)는 모두 `REMOTE_ERROR`(`details.reason: "bootstrap_protocol"`)로 사상된다(ADR-0044 결정 14). 오류 값은 입력 바이트를 담지 않는다. rc 출력과 ssh stderr는 로그로 복사하지 않는다(ADR-0044 결정 19). 어떤 fingerprint와 이름을 pin하는지, 충돌을 어떻게 판정하는지는 `qsh-core`가 정하고 이 절의 범위 밖이다.

### 17.5 응답자 쪽 순서

`qsh pair ssh-respond`(ADR-0044 결정 9·10·12)는 이 절의 응답자 쪽이다. Linux·macOS·Windows 빌드 모두에 등록돼 있고 같은 순서로 동작한다(ADR-0044 결정 10, ADR-0035 결정 25. 이 하위 명령을 모르는 옛 qsh는 client가 `remote_qsh_too_old`로 받는다). 신원 파일만 읽어 fingerprint를 얻고(키 저장소는 열지 않는다), 그 `serve` 주소로 UDP bind를 시험해(Windows는 probe 소켓에 `SO_EXCLUSIVEADDRUSE`를 방어용으로 더 건다. ADR-0044 결정 10을 따른 것이고, probe가 `SO_REUSEADDR`를 걸지 않아 이 옵션 없이도 포트를 쥔 소켓과는 bind가 충돌하므로 이 옵션이 결과를 바꾼다고 보인 테스트는 없다) `serve_listening`을 채운 뒤 hello 한 줄을 내보낸다. 이어서 commit을 30초까지 기다린다. 잠금 안에서 `trust.toml`을 읽고 판정하고, audit(`pair.ssh_respond`)을 쓴 다음 저장하는 순서이며 audit이 실패하면 저장하지 않는다. 판정은 `pinned`(새로 씀), `exists`(같은 fingerprint가 이미 어떤 이름으로든 있음. role은 바꾸지 않고, commit에 `address`가 있으면 그 pin의 주소만 `trust add`와 같은 규칙으로 갱신하며 이때 audit은 남기지 않는다), `conflict`(같은 이름에 다른 fingerprint, 메시지에 기존 fingerprint를 싣는다), `error`다. result를 낸 뒤에는 stdin을 더 읽지 않는다. 줄 끝은 `\n`으로 내보내고 commit 줄 끝의 `\r\n`은 받아서 처리한다.

### 17.6 serve 띄우기와 되살리기 (ADR-0051 결정 1·2·4, additive)

부트스트랩 버전은 1 그대로다. 아래는 모두 새 선택 필드라서 §17.3의 규칙대로 모르는 쪽은 무시한다.

| 메시지 | 필드 | 뜻 |
|---|---|---|
| `hello` | `on_demand: true` | 이 응답자는 `commit.ensure_serve`를 이해한다. 모르는 응답자는 이 필드를 보내지 않는다. |
| `commit` | `ensure_serve: true` | 판정이 `pinned`나 `exists`이면 이 계정의 on-demand serve를 찾거나 띄우라는 요청. |
| `result` | `serve_bind` | 응답자가 쓰는 `serve.json`의 실제 바인드 주소(`host:port`). hello의 `serve_bind`(설정값)와 다른 필드이고 hello 쪽 값은 그대로 설정값이다. |
| `result` | `serve_started` | 이번 요청이 serve를 새로 띄웠으면 `true`, 이미 떠 있었으면 `false`. 띄우지 못하면 `false`이고 `message`에 이유를 싣는다. |
| `result` | `serve_session_scoped` | on-demand serve가 이 ssh 세션이 끝날 때 함께 끝날 수 있으면 `true`. Linux는 `loginctl show-user $USER -p KillUserProcesses -p Linger`가 `KillUserProcesses=yes`와 linger 꺼짐을 말할 때(`loginctl`이 없으면 `false`), Windows는 Job Object의 breakaway가 거부됐을 때다. |

호환 규칙: client는 `hello.on_demand == true`인 응답자에게만 `commit.ensure_serve`를 보낸다. 그래서 옛 응답자는 옛 바이트 그대로의 commit을 받고, 옛 client는 이 필드들을 무시한다. `ensure_serve`가 없는 commit에는 응답자가 serve를 건드리지 않으며 result에도 위 세 필드를 싣지 않는다.

client는 pin 주소를 ssh 호스트 이름과 `result.serve_bind`의 포트로 만든다. 바인드 주소가 와일드카드나 loopback이 아닌 특정 IP이면 그 IP가 호스트를 대신한다. `--address`가 있으면 그것이 이긴다. `serve_bind`가 소켓 주소로 읽히지 않으면 hello 기반 주소로 돌아간다.

되살리기(ADR-0051 결정 4)는 같은 대화를 다시 쓴다. pin 대상으로 QUIC 다이얼이 `CONNECTION_FAILED`나 `TIMEOUT`(`udp_egress_blocked` 제외)으로 실패하고 그 pin이 ssh 부트스트랩이 만든 것(`trust.toml`의 `[[peer]]`에 `source = "ssh_bootstrap"`)이면, client가 같은 대상으로 ssh를 다시 열어 `ensure_serve`를 보낸다. 이때 hello의 fingerprint가 pin의 것과 같아야 하고 다르면 `SESSION_CONFLICT`로 멈춘다. 새 pin을 쓰지 않고(verify-only) 주소가 바뀌었으면 그 pin의 주소만 갱신한 뒤 한 번 더 다이얼한다. `hello.on_demand`가 없는 응답자는 `UNSUPPORTED`다.

### 17.7 pin 교체 (ADR-0051 결정 5, additive)

부트스트랩 버전은 1 그대로이고 아래는 모두 새 선택 필드다(§17.3).

| 메시지 | 필드 | 뜻 |
|---|---|---|
| `hello` | `replace_pin: true` | 이 응답자는 `commit.replace`를 이해한다. 모르는 응답자는 보내지 않는다. |
| `commit` | `replace: true` | 사람이 `--replace-pin`이나 TTY 질문으로 "예"라고 했다. 같은 이름의 pin이 다른 fingerprint이면 응답자가 그 pin을 지우고 이 commit의 것을 쓴다. |
| `result` | `replaced_fingerprint` | 지운 pin의 fingerprint. 교체했을 때만 있고 이때 `status`는 `pinned`, `created`는 `true`다. peer가 쓴 값이므로 client는 fingerprint로 파싱될 때만 쓴다. |

호환 규칙: client는 `hello.replace_pin == true`인 응답자에게만 `replace`를 보낸다. 모르는 응답자는 옛 바이트 그대로의 commit을 받고 `conflict`로 답하며, `--replace-pin`을 준 client는 그 `conflict`를 `UNSUPPORTED`로 끝낸다. `replace`가 없는 commit의 이름 충돌은 여전히 `conflict`이고 아무것도 쓰지 않는다. fingerprint가 같은 pin이 다른 이름으로 이미 있으면(`exists`) `replace`는 아무 일도 하지 않는다.

응답자는 새 pin을 처음부터 쓴 것처럼 쓴다. `role`은 commit의 것이고 `grants`·`paths`·`scope`는 없다. audit(`pair.ssh_respond.replace_pin`)을 저장 전에 남기고 실패하면 `trust.toml`은 그대로이며 `error`(`INTERNAL`)로 답한다. 응답자는 `commit`을 한 번 받고 `result`로 끝나므로, client가 `conflict`를 본 뒤 사람에게 묻고 "예"이면 ssh를 새로 열어 같은 fingerprint의 응답자인지 확인한 뒤 `replace: true`인 commit을 보낸다.

## 18. 화면 상태 동기화 (ADR-0052 결정 1~11)

**상태: 스트림 운반체와 datagram 운반체가 협상된다.** capability `screen.v1`(§4)을 광고하고, `SESSION_DATA` 스트림에서 화면 갱신을 나른다(§18.8). `datagram.v1`(§4)을 광고하고, 조건이 맞으면 같은 갱신과 `ScreenAck`를 `DatagramFrame`(§18.6)으로도 나르며 키 입력의 사본을 보낸다(§18.9). 부호화와 검증 규칙은 `crates/qsh-proto/src/screen/`가 코드로 고정하고 fuzz 표면이다(`decode_screen_diff`, `decode_datagram_frame`). `ScreenUpdate`의 정규 바이트열(§18.4)은 protobuf 필드로 풀지 않고 `bytes data`에 조각(`part`/`parts`)으로 싣는다. 그래서 diff·hash 부호화를 바꾸면 `state_hash`처럼 모든 client의 대조가 어긋나므로, 바꾸려면 새 capability가 필요하다.

### 18.1 화면 상태

host 에뮬레이터(`crates/qsh-core/src/screen/`)는 VT 바이트열이 아니라 아래의 정규화된 화면을 낸다. 에뮬레이터 구현이 달라도 같은 화면이면 같은 상태이고, 그래서 qsh 버전이 달라도 hash를 비교할 수 있다.

| 항목 | 뜻 |
|---|---|
| 크기 | 행 수, 열 수. 각각 `1..=2048`, 곱은 `1 048 576` 이하. |
| 커서 | 행, 열(0부터). 화면 안이다. 줄 끝에서 다음 글자를 기다리는 상태는 마지막 열로 정규화한다. |
| 모드 | 비트 다섯(대체 화면, 커서 숨김, 앱 커서 키, 앱 키패드, bracketed paste)과 마우스 모드(0 없음, 1 press, 2 press+release, 3 button motion, 4 any motion), 마우스 인코딩(0 기본, 1 UTF-8, 2 SGR). |
| 행 | 열 수만큼의 셀과 wrap 플래그(다음 행으로 이어짐). |
| 셀 | 글자(비어 있거나 한 글자 또는 결합 문자까지 최대 32바이트, 제어 문자 없음), 전경색, 배경색, 속성 비트. |

색은 기본, 팔레트 번호(0..=255), RGB 중 하나다. 속성 비트는 굵게(1), 흐리게(2), 기울임(4), 밑줄(8), 반전(16), 넓은 글자의 왼쪽 반(32), 넓은 글자의 오른쪽 반(64)이다. 오른쪽 반 셀은 글자가 비어 있고, 32와 64는 함께 서지 않는다.

### 18.2 정규 바이트와 `state_hash`

`state_hash`는 정규 바이트의 BLAKE3 앞 8바이트다. 정규 바이트는 `rows`, `cols`, 커서 행, 커서 열(각 u16 little endian), 모드 세 바이트, 그리고 행마다 wrap 플래그 한 바이트와 `cols`개의 셀(18.3의 셀 부호화)이다. 이 바이트가 바뀌면 모든 client의 대조가 어긋나므로 값을 테스트로 고정한다(`the_state_hash_pins_the_canonical_encoding`). 부호화를 바꾸려면 hash 버전을 새로 두어야 한다.

### 18.3 `ScreenDiff`

정수는 모두 LEB128 varint이고 가장 짧은 형태만 받는다(그래야 부호화가 유일하다). 순서는 다음과 같다.

1. `rows`, `cols`, 커서 행, 커서 열(varint)과 모드 세 바이트.
2. 바뀐 행의 수(varint)와 행마다 `row`(varint, 엄격히 증가), wrap 플래그(0 또는 1), run의 수(varint).
3. run마다 `col`(varint), 셀 수(varint, 1 이상), 그 수만큼의 셀. run은 열 순서이고 겹치지 않으며 행 안에 든다.

셀은 두 바이트 머리로 시작한다. 첫 바이트는 속성 비트(하위 7비트)와 "글자 있음"(상위 비트), 둘째는 전경색 종류(하위 2비트)와 배경색 종류(그 위 2비트)이고 종류는 0 기본, 1 팔레트(뒤따르는 한 바이트), 2 RGB(세 바이트)다. 둘째 바이트의 나머지 비트는 0이다. 색 바이트들이 오고, 글자가 있으면 길이(varint, 1..=32)와 UTF-8 바이트가 온다.

크기, 커서, 모드는 언제나 통째로 보낸다. 새 크기가 base의 크기와 다르면 base를 새 크기의 빈 화면으로 보고 diff를 적용한다. 그래서 크기가 바뀌면 전체를 다시 그리는 비용이 들지만 옛 격자를 새 격자에 대응시킬 필요가 없다. 가까운(4칸 이내) 바뀐 셀은 한 run으로 묶는다.

decode는 임의의 바이트에 대해 전함수다. 모든 개수는 남은 바이트 수로 먼저 검사해서 짧은 입력으로 큰 할당을 일으킬 수 없다. 받아들인 입력은 다시 부호화하면 같은 바이트가 된다.

### 18.4 `ScreenUpdate`와 효과

`ScreenUpdate`는 `base_num`, `new_num`, `output_seq`(각 varint, `new_num > base_num`), `state_hash` 8바이트, 효과의 수(varint, 최대 64)와 효과들, 이어서 diff다. 전체 크기는 1 MiB 이하다.

`base_num == 0`은 빈 화면이고 그 갱신이 전체 화면이다. client는 적용한 결과의 hash를 `state_hash`와 대조하고, 다르면 base 0을 요청한다.

| 효과 | 부호화 | 규칙 |
|---|---|---|
| 창 제목 (OSC 0·2) | 1, 문자열 | 1024바이트 이하, 제어 문자 없음. host가 제어 문자를 지우고 자른다. |
| 종 (BEL) | 2 | 연달은 종은 하나로 합친다. |
| 클립보드 쓰기 (OSC 52) | 3, 선택 문자열, 데이터 문자열 | 선택은 `cpqs01234567` 8자 이하, 데이터는 base64 문자만 64 KiB 이하. 조회(`?`)와 상한을 넘는 쓰기는 전하지 않는다. |
| 하이퍼링크 (OSC 8) | 4, 파라미터 문자열, URI 문자열 | 256바이트·2048바이트 이하, 제어 문자 없음. URI가 비면 링크를 닫는다. |

문자열은 길이(varint)와 UTF-8 바이트다. 효과는 그것이 일어난 상태 번호에 묶이고, 상태 `base_num`에서 `new_num`까지의 갱신은 그 사이의 효과를 순서대로 싣는다. base 0인 갱신은 마지막 창 제목만 싣는다. 놓친 종이나 클립보드 쓰기를 새로 붙는 client에 되풀이하지 않기 위해서다.

### 18.5 상태 번호

host는 화면이나 효과가 바뀔 때만 다음 `state_num`(1부터)을 낸다. 같은 화면이 다시 만들어지면 번호는 그대로이고 `output_seq`만 앞으로 간다. diff의 base로 쓸 수 있는 상태는 최근 8개이고, 그보다 오래된 base를 가진 client에는 base 0의 전체 화면을 보낸다.

### 18.6 `DatagramFrame` 머리

datagram 하나가 한 frame이라서 길이 머리가 없다. 16바이트 channel id, 종류 한 바이트(10 `ScreenUpdate`, 11 `ScreenAck`, 12 `Input`, 13 `ScreenEcho`(ADR-0053 결정 3, §18.12), ADR-0052 결정 9의 필드 번호, 14 `JumpPacket`(ADR-0056 결정 4, §21.0)), 나머지가 payload다. 알 수 없는 종류와 17바이트보다 짧은 입력은 버린다. channel id는 attach가 ACL을 통과한 뒤 host가 발급하는 난수이고, 모르는 channel의 datagram은 버리고 세기만 한다(결정 7). payload는 종류에 따라 §18.8의 protobuf 메시지 하나다(10은 `ScreenUpdate` 조각, 11은 `ScreenAck`, 12는 `Input`, 13은 `ScreenEcho`). 14는 예외로 payload가 protobuf가 아니라 안쪽 QUIC 패킷 바이트 그대로이고, channel은 `JUMP` 스트림의 `jump_channel`이라 jump 채널 표에서만 찾는다. 종류 10~13의 화면 channel과 섞이지 않으며, 14가 화면 channel에 오면 모르는 channel처럼 버린다(§21.0). 조각 나눔(`part`/`parts`)은 `ScreenUpdate` 메시지가 가지고, datagram의 조각 규칙은 §18.9에 있다.

### 18.7 fuzz와 시험

`decode_screen_diff`는 `ScreenDiff`와 `ScreenUpdate`의 decode, 재부호화 동일성, 적용을 본다. `decode_datagram_frame`은 머리 decode와 재부호화 동일성을 본다. `host_emulator_input`은 임의의 PTY 출력을 host 에뮬레이터에 먹이고 가상 client가 갱신을 받아 hash를 대조한다. 같은 속성은 `crates/qsh-proto/src/screen/tests.rs`와 `crates/qsh-core/src/screen/tests.rs`의 proptest가 `cargo nextest`에서 매번 확인한다.

### 18.8 스트림 운반체와 협상 (ADR-0052 결정 1·6·9·11)

**요청과 응답.** client는 협상된 교집합에 `screen.v1`이 있을 때만 `SessionOpen.screen`(`optional ScreenRequest{cols, rows, optional fg, optional bg}`, 색은 0xRRGGBB)이나 `SessionAttach.screen`을 세팅한다. 24비트를 넘는 색은 `INVALID_ARGUMENT`다. host는 `screen.v1`을 협상하지 않은 peer가 보낸 필드를 오류 없이 무시하고(바이트 경로), 협상했고 세션이 에뮬레이터를 돌릴 때(`session.open`이 `screen`과 함께 만든 세션)만 응답의 `screen_channel`에 ACL 통과 뒤 발급한 16바이트 난수를 싣는다. 비어 있으면 바이트 경로다. `session.open` 없이 만들어진 세션에 `screen`을 붙여 attach하면 에뮬레이터가 지나간 출력을 못 봤으므로 `screen_channel`이 비고 바이트 경로로 간다. 경로를 정하는 것은 요청이 아니라 ticket이다. 스트림을 여는 쪽이 운반체를 바꿀 수 없다. channel id는 datagram 운반체가 쓰며 스트림 운반체에서는 "host가 받아들였다"는 표시다.

**프레임.** 화면 동기화 attach에서 host는 `Output`과 `Gap`을 보내지 않는다. `ScreenUpdate{new_num, part, parts, data}`는 §18.4의 `ScreenUpdate` 바이트열 한 개를 `part` 0부터 `parts - 1`까지 순서대로 나눈 조각이다. 조각의 `data`는 16 KiB 이하(`SESSION_CHUNK_MAX`), 한 갱신은 1 MiB 이하(최대 64조각)이고, 한 갱신의 조각은 연달아 온다. 받는 쪽은 `part`가 이어지지 않거나 `parts`가 바뀌거나 상한을 넘으면 프로토콜 위반으로 보고, `part` 0이 오면 만들던 갱신을 버린다. `ScreenAck{state_num}`는 client가 적용한 최신 상태 번호이고 0은 전체 화면(base 0) 요청이다. `Exit`, `Resize`, `Input`, `InputAck`는 그대로 쓴다.

**host의 순서.** attach마다 첫 갱신은 base 0의 현재 화면이다(`SessionAttached.replay_from == output_end`, 재생 없음). 이후 ring이 움직이면 마지막으로 **보낸** 상태를 base로 최신 상태까지의 갱신을 만든다. 스트림이 순서와 도달을 보장하므로 ack를 기다리지 않는다. 쓰이지 않은 화면 조각이 128 KiB(`SEND_DEPTH_CAP_BYTES`)를 넘는 동안은 새 갱신을 만들지 않고, 줄면 그때의 최신 상태까지 한 번에 보내므로 중간 화면은 건너뛴다. `ScreenAck{0}`를 받으면 base를 0으로 되돌려 전체 화면을 보낸다. `Resize`는 출력이 없어도 갱신을 만든다. 세션의 `Exit`·`Closed` 같은 제어 항목은 마지막 갱신을 먼저 내보낸 뒤 바이트 경로와 같은 순서로 나간다. 에뮬레이터는 ring에 쓰기 전에 먹이므로(`pty_reader`), ring이 움직여 깬 쪽은 항상 새 바이트가 반영된 화면을 본다.

**client의 순서.** `qsh_core::client::screen::ClientScreen`이 조각을 모아 갱신을 적용하고 `state_hash`를 대조한다. 대조가 틀렸거나, base가 가진 상태가 아니거나, diff가 적용되지 않으면 가진 화면을 버리고 `ScreenAck{0}`를 보낸다. 전체 화면이 올 때까지 base가 0이 아닌 갱신은 무시한다. 적용에 성공하면 `ScreenAck{new_num}`를 보낸다. client는 최근 적용한 상태 8개(`RETAINED_STATES`)를 가지고 있어서, base가 그중 하나인 갱신은 어느 운반체로 왔든 적용한다. 이미 가진 것보다 새롭지 않은 갱신(다른 운반체의 더 새 갱신과 엇갈렸다)은 버리고 가진 상태 번호를 다시 ack한다. 전체 화면(base 0)은 가진 상태와 같은 번호여도 적용한다. 요청한 쪽이 받아야 하는 것이기 때문이다. 대화형 CLI는 `--screen-sync`(§18.10)로 `screen`을 요청한다.

**재부착.** 재부착과 resume의 절차(§10)는 그대로다. 같은 세션에 바이트 경로로 다시 붙으면 `last_output_seq`부터 재생한다. 화면 경로의 첫 갱신은 한 화면이라서 떼어 둔 동안 10 MB가 쌓였어도 크기가 화면 크기에 비례한다(`reattach_sends_one_screen_not_the_backlog`). 지나간 출력 안의 터미널 질의는 로컬 터미널에 닿지 않고 host 에뮬레이터가 답한다(ADR-0052 결정 3).

### 18.9 datagram 운반체와 입력 사본 (ADR-0052 결정 6·7·8·9·12 (c))

**조건.** 아래가 모두 맞을 때만 쓴다. (1) 협상된 교집합에 `datagram.v1`이 있다. (2) 화면 동기화 attach이고 `screen_channel`이 16바이트다. (3) forward 연결이다. `qsh listen` 데몬을 거치는 reverse 등록은 client가 로컬 conduit 뒤에 있어 datagram을 읽지 못하므로 host가 쓰지 않는다. (4) transport의 `max_datagram_size()`가 `Some`이다. 모든 datagram 메시지는 스트림에 같은 뜻의 짝이 있으므로, 조건이 하나라도 깨지거나 송신이 `UnsupportedByPeer`·`Disabled`·`TooLarge`로 실패하면 그 메시지는 스트림으로 간다.

**channel id.** `screen_channel`이 곧 datagram의 channel id다. ACL을 통과한 attach에만 host가 난수로 발급하고 그 연결에서만 유효하다. 연결마다 datagram reader가 하나(`qsh_core::datagram::DatagramHub`)이고, host는 data 스트림을 시작할 때, client는 스트림을 열 때 자기 attach의 channel을 등록한다. 등록되지 않은 channel의 datagram은 버리고 `unknown_channel`로 센다. 디코드되지 않으면 `malformed`, channel 큐(256개)가 차면 `overflow`로 센다. datagram은 어떤 자원도 만들지 못한다.

**payload와 조각.** `ScreenUpdate` datagram의 payload는 §18.8과 같은 protobuf `ScreenUpdate{new_num, part, parts, data}`다. 조각의 `data` 예산은 `max_datagram_size() - 17(머리) - 24(protobuf 머리 여유)`이다. 다른 곳에서 잰 QUIC 프레임 머리(약 38바이트)는 `max_datagram_size()`가 이미 뺀 값이므로 더 빼지 않는다. 한 갱신은 64조각까지이고(`MAX_DATAGRAM_PARTS`), 그보다 크면 스트림으로 보낸다. 받는 쪽(`DatagramReassembler`)은 조각이 어떤 순서로 와도, 두 번 와도 받고 한 상태의 조각이 모두 모여야 적용한다. 더 새 상태의 조각이 오면 만들던 것을 버리고, 이미 끝낸 것보다 오래된 상태의 조각은 버린다. 버퍼는 1 MiB 이하다. 이 규칙의 오류는 연결을 끊지 않고 센다(`datagram_dropped`).

**host.** attach마다 첫 갱신(전체 화면)은 스트림으로 간다. 그 화면을 적용한 client가 같은 channel로 datagram을 보내면(첫 `ScreenAck`가 그렇다) host는 그 client가 datagram을 읽는다고 보고 운반체를 `adapt`에 맡긴다. 그 전에는 스트림이므로 datagram을 모르는 client도 같은 시험을 통과한다. datagram 갱신의 base는 client가 마지막으로 ack한 상태이고(ack가 없으면 0), 각 갱신은 base만 있으면 독립으로 적용된다. 갱신은 `FIXED_FRAME_INTERVAL`(20 ms)마다 최대 하나이고, ack가 `2 × max(RTT, 50 ms) + 20 ms` 안에 오지 않으면 최신 상태를 다시 보낸다. 잃은 갱신을 다시 보내지는 않지만 출력이 멈춘 뒤에도 client가 따라오게 하기 위해서다. 스트림 갱신의 base는 마지막 ack와 스트림으로 마지막에 보낸 상태 중 큰 쪽이다. `Exit`·`Closed` 앞의 마지막 갱신은 언제나 스트림이다.

**운반체 선택.** `qsh_core::adapt::CarrierRunner`가 연결마다 `ConnStats`를 1초에 한 번(그리고 datagram 가용 여부가 바뀔 때, 미ack 문턱을 넘을 때) `adapt::decide`에 넣는다. 갱신마다 `Knobs::carrier_for_update(parts)`가 고른다. 조각이 k개이고 손실률이 p일 때 `(1 - p)^k < 0.5`이면 그 갱신만 스트림이다. 가장 오래된 미ack datagram 갱신의 나이가 `4 × max(srtt, 50 ms)`를 넘는데 연결이 살아 있으면(인증된 frame이 최근 20초 안에 왔다) `Stream(datagram_unacked)`가 되고, `DATAGRAM_RETEST_PERIOD`(30초)마다 datagram을 다시 시험한다. 50 ms 하한은 loopback의 0.1 ms RTT가 정상 경로를 스트림으로 보내는 것을 막는다. 이 단계의 runner는 attach마다 host 쪽에서 돈다. 손잡이 (c) 밖의 값은 계산만 하고 쓰지 않는다.

**ack.** client는 `ScreenAck`를 두 길로 보낸다. datagram이 가능하면 datagram을 먼저 보내고 스트림에도 보낸다. host는 어느 쪽이든 `fetch_max`로 받고, 0(전체 화면 요청)은 ack 상태를 0으로 되돌린다.

**입력 사본.** 키 입력은 세션 data 스트림의 `Input{input_seq, data}`가 정본이고, datagram 운반체를 쓸 수 있으면 같은 `Input`을 datagram(종류 12)으로 한 번 더 보낸다. 사본은 스트림 프레임보다 먼저 나가며 한 datagram에 들어가는 조각만 보낸다. host는 사본의 시작 offset(`input_seq - len(data)`)이 그 attach 축의 적용 offset과 **정확히 같을 때만** 적용하고 아니면 버린다. 더 앞에서 시작하는 사본은 이미 적용한 바이트의 중복이고, 더 뒤에서 시작하면 스트림 사본이 아직 오지 않은 바이트를 건너뛰게 된다. 스트림 프레임과 사본은 같은 잠금 아래에서 offset을 읽고 쓰므로 섞이지 않고, 늦게 온 스트림 프레임은 기존 중복 제거(§10-5)가 버린다. 그래서 무손실·무중복(PRD §8)은 스트림이 지키고 사본은 손실 아래의 입력 지연만 줄인다. 사본을 적용하면 `InputAck`를 스트림으로 보낸다.

**시험.** `crates/qsh-testkit/tests/it/datagram_carrier.rs`가 고정한다. 손실·순서 뒤바뀜·중복 아래의 입력 무손실·무중복(`input_copies_are_lossless_and_duplicate_free_under_loss_and_reordering`), 틀린 offset의 사본 폐기(`a_datagram_input_copy_at_the_wrong_offset_is_dropped`), 모르는 channel(`a_datagram_for_an_unknown_channel_is_dropped_and_counted`), 경로가 datagram만 버릴 때의 스트림 전환(`a_path_that_eats_datagrams_falls_back_to_the_stream_and_converges`), 옛 peer 조합(`a_peer_without_datagram_v1_gets_the_stream_carrier`, `a_host_without_datagram_v1_gets_the_stream_carrier_from_a_new_client`), 그리고 `QSH_ACCEPTANCE_SLOW`에서 도는 `screen_sync_staleness_under_loss`(단방향 75 ms 지연과 5% 손실에서 datagram의 staleness p95 ≤ 50 ms, 스트림 운반체는 중간 상태를 건너뛰고 출력이 멈춘 뒤 2×RTO 안에 맞는다)다.


### 18.10 client가 화면을 그리는 방법 (ADR-0052 결정 4·11·15)

**누가 그리나.** `qsh_core::client::render::ScreenRenderer`가 상태를 로컬 터미널 바이트로 바꾼다. I/O와 시계가 없고, 호출마다 로컬 창 크기를 받는다. attach driver(`crates/qsh-core/src/ops/session/`)가 한 attach의 `ScreenSink`(렌더러, 로컬 창 크기, 마지막으로 그린 상태)를 쥐고, 연결(leg)마다 `ClientScreen`을 새로 만든다. 적용된 상태는 `qsh.event/v1`의 `Output` 이벤트(`data_b64` = 터미널 바이트)로 frontend에 나가므로 `qsh-cli`는 바이트 경로와 같은 쓰기 경로를 쓴다. 화면 경로의 `Output`은 세션의 출력 스트림이 아니다. `sequence`는 적용한 상태의 `output_seq`다.

**ack.** reader가 `ClientScreen`의 결과(`ScreenOutcome::ack`)를 input pump에 넘기고, pump가 `ScreenAck`를 보낸다(datagram이 되면 양쪽 운반체). 밀린 ack 중 0(전체 화면 요청)은 뒤 번호에 접히지 않는다.

**프레임 맞춤.** 상태를 로컬 창 크기에 맞춘 프레임으로 바꾼 뒤 그린다. 열은 왼쪽부터 자르고 모자라면 빈 셀이다. 행이 많으면 커서 행이 창의 맨 아래가 되게 윗행을 버린다. 자르는 경계에 걸린 이중 폭 문자는 빈칸이다. 보이지 않는 차이(쓴 공백과 지운 셀, 빈 셀의 전경색)는 같은 셀로 본다.

**차이.** 직전에 그린 프레임과 같은 크기이면 행마다 다른 셀 구간을 찾아 6칸 미만의 같은 틈은 이어 쓰고, 구간마다 절대 커서 이동(`CSI r;c H`) 하나와 SGR(항상 `0;`으로 시작하는 절대 형태)을 쓴다. 구간이 행 끝까지 빈 셀이면 4칸 이상은 `CSI K`로 지운다. 이중 폭 문자는 왼쪽 반 셀에서 시작하도록 구간을 넓힌다. 여러 구간이면 그리는 동안 커서를 숨긴다. 크기 변경, 대체 화면 전환, 첫 프레임, `invalidate`(새 연결, 로컬 창 크기 변경)는 모든 셀을 쓴다. 화면을 지우는 `CSI 2J`는 쓰지 않으므로 로컬 스크롤백이 오염되지 않는다.

**모드.** 대체 화면(`?1049`), 커서 숨김(`?25`), 응용 커서 키(`?1`), 응용 키패드(`ESC =`/`ESC >`), 괄호 붙여넣기(`?2004`), 마우스 모드(`?9`·`?1000`·`?1002`·`?1003`)와 인코딩(`?1005`·`?1006`)을 바뀔 때만 쓴다. 렌더러가 한 번이라도 기본이 아닌 모드를 썼으면 `reset`이 기본으로 되돌리는 바이트를 낸다(`SessionAttachStream::screen_reset`). frontend는 세션이 끝나거나 떼어질 때 그 바이트를 터미널에 쓴다.

**효과.** 한 갱신의 효과는 그 갱신을 그린 호출에서 한 번만 나간다(제목은 OSC 2, 종, OSC 52 쓰기, OSC 8). 다시 그리기는 효과를 싣지 않는다. 클립보드 데이터가 `?`이면 쓰지 않는다(읽기 요청). 갱신이 끝날 때 열린 하이퍼링크는 닫는다. 셀에는 링크 속성이 없기 때문이다. datagram 운반체에서 ack가 늦어 client가 이미 적용한 상태 사이의 효과를 다음 갱신이 다시 실을 수 있고, 그때는 같은 효과가 두 번 나갈 수 있다(종과 클립보드 쓰기는 멱등에 가깝다).

**첫 프레임.** 처음 그리기 전에 커서를 맨 아래 행으로 옮기고 창 높이만큼 줄바꿈해 attach 전에 터미널에 있던 출력(client의 안내 등)을 위로 밀어 올린 뒤 그린다. 셀 단위 갱신이 그 출력을 덮어쓰지 않게 하려는 것이다.

**history.** `ScreenRenderer::history`는 밀려난 행을 로컬 스크롤백에 넣는다(§18.11). 행마다 창의 맨 윗행을 지우고 그 위에 쓴 뒤 맨 아랫행에서 줄바꿈해 창을 한 줄 올린다. 그러면 정확히 그 행이 스크롤백으로 들어가고 창의 행은 덮어써질 뿐 밀려 나가지 않으므로 낡은 화면 행이 스크롤백에 섞이지 않는다. 쓰는 동안 자동 줄바꿈(`?7`)과 커서를 끄고, 창보다 넓은 행은 오른쪽을 자른다(화면과 같다). 끝나면 렌더러가 그린 것을 잊고(`invalidate`) driver가 마지막 상태를 다시 그린다. 대체 화면에 있을 때는 `?1049l`로 기본 화면으로 나가 쓰고 `?1049h`로 돌아온다(대체 화면에는 스크롤백이 없다. 기본 화면의 내용은 host가 대체 화면을 떠날 때 전부 다시 그려진다). 첫 프레임 전에는 일반 줄로 출력한다.

**복구.** 연결이 새로 서면(재연결) driver는 같은 `ScreenSink`에 새 `ClientScreen`을 붙이고 `screen`을 다시 요청한다. 첫 갱신은 base 0의 전체 화면이고 렌더러는 모든 셀을 다시 쓴다. 로컬 창 크기가 바뀌면(`AttachCommand::Resize`) 마지막 상태를 새 크기로 다시 그리고 `Resize`를 host에 보낸다.

**시험.** `crates/qsh-core/src/client/render/tests.rs`가 로컬 터미널 모델(두 번째 `HostScreen`)로 고정한다: 첫 프레임, 변화 없음은 0바이트, 한 셀의 변경은 한 셀의 비용(`a_one_cell_change_costs_one_cell`), 바뀐 행만, 빈 꼬리 지우기, 자르기·채우기, 이중 폭·결합 문자, 모드와 reset, 효과 한 번, 클립보드 읽기 거부, 임의의 입력열 뒤에도 로컬 터미널이 host 화면을 따른다(`local_terminal_follows_the_host`). `crates/qsh-cli/tests/it/screen_sync.rs`가 실제 `qsh serve` 위에서 `Ops`로 attach를 건다(`auto_draws_the_remote_screen_on_the_local_terminal`, `off_keeps_the_byte_path`, `a_session_opened_without_screen_sync_attaches_on_the_byte_path_under_auto`).

**연결 상태 줄(ADR-0053 결정 9·10).** 렌더러는 `draw_composed`로 예측 겹침과 상태 줄을 host 상태를 창에 맞춘 뒤에 합성한다. 줄은 창 맨 윗줄(합성된 커서가 맨 윗줄이면 맨 아랫줄)의 셀을 `INVERSE` 속성의 글자와 빈칸으로 폭 전체에 채운다. 20열보다 좁으면 그리지 않는다. 합성이므로 `ClientScreen`의 상태와 `state_hash` 대조는 건드리지 않고, 줄이 빠진 다음 프레임은 그 행의 host 셀이 이전 프레임과 달라서 셀 차이로 되쓰인다(화면 지우기 없음). 대체 화면에서도 합성한다(예측 겹침과 달리 버리지 않는다).

**`LinkStatus`.** attach마다 `qsh_core::client::linkstatus::LinkTracker`가 `LinkStatus{last_reply, waiting_since, recovering}`을 든다. `last_reply`는 `PathWatch`(`PathWatch::linked`)가 본 마지막 인증된 inbound(`Pong`, 세션 트래픽, 전송 계층의 인증된 frame 카운터)의 시각이다. `waiting_since`는 그 뒤 보낸 것(input pump의 `Input`, control pump의 liveness `Ping`) 가운데 답이 없는 가장 오래된 것의 시각이고 인증된 inbound가 오면 비운다. 역방향 route의 attach는 control `Ping`이 로컬 데몬에서 끝나므로(§11-3) 끝까지 가는 질문이 따로 필요하다. 상태 줄을 그리는 역방향 attach의 input pump는 입력도 acknowledgement도 한 idle probe 간격(`PathWatchConfig::idle_probe_interval`, 5초) 동안 없으면 바이트 없는 `Input`(heartbeat, `input_seq`는 host가 이미 ack한 offset 이하)을 보내 `waiting_since`를 세운다. host는 이미 실행한 입력의 재전송으로 읽고 `InputAck`로 다시 답하며(`session_stream`의 입력 루프, 빈 `Input`은 bulk 양보의 "interactive"로 세지 않는다) 그 답이 `last_reply`를 옮기고 대기를 푼다. 죽은 경로 판정과 recovery는 바꾸지 않는다. 데몬 쪽 등록 watchdog과 `LocalReconnect`가 그대로 맡는다. `recovering`은 `recover_attach`가 시도마다 `attempt + 1`로 세우고 recovery가 끝나면 비운다(정방향 `DialReconnect`와 역방향 `LocalReconnect`가 같은 루프를 쓴다). `SessionAttachStream::link_status()`가 스냅샷을 준다. 정방향의 srtt는 `PolicyMonitor`의 표본(`ScreenSink::set_srtt`)이고, 역방향은 `PredictDriver`가 `Input`과 `InputAck` 간격으로 내는 EWMA다. 순수 규칙은 `LinkLine`(시계 없음, `now`를 받는다)이 맡는다: `wants_line = recovering 또는 now - waiting_since >= max(2 s, 4 x srtt)`, 문구, 다음 마감(문턱 교차, 보이는 동안 다음 정수 초).

**attach driver.** `ScreenSink`가 `LinkLine`을 쥐고 칠 때마다(`paint`) 다시 판정한다. 줄이 뜨고 지는 순간 `PredictDriver::on_status_line`에 알려 예측의 밑줄을 맞춘다. `tick_due`는 예측의 250 ms 마감, 줄의 마감, `LinkTracker`의 변화 통지 중 가장 이른 것까지 잔다. leg를 읽는 동안은 `read_leg`의 같은 `tick` 분기가, recovery 동안은 leg를 읽는 태스크가 없으므로 `drive_attach`의 `with_status_ticks`가 recovery 퓨처와 `select!`로 같은 `tick`을 돌려 초와 시도 번호를 갱신한다. 줄 그리기는 `--status-line=off`면 `ScreenSink`가 줄 상태를 만들지 않는 것으로 끝나고 `LinkTracker`와 recovery는 그대로다. control pump는 `writer_changed`를 `ScreenSink::writer_changed`로 넘겨 writer lease를 잃은 attach의 예측을 걷는다(주체 이름은 client가 모르므로 attach 직후의 첫 사건을 자기 이름으로 배운다. 같은 principal의 다른 attach는 구별하지 못한다).

**시험.** `crates/qsh-core/src/client/linkstatus/tests.rs`(문턱, 문구, 마감, 응답에 지움), `crates/qsh-core/src/ops/session/status_tests.rs`(로컬 터미널 모델 위에서 시계를 손으로 가며 나타남·초 갱신·reconnecting·지움과 행 복원·`off`·맨 아랫줄·좁은 창·밑줄·writer 추적), `crates/qsh-core/src/client/render/tests.rs`의 `status` 모듈, `crates/qsh-cli/tests/it/status_line.rs`(chaos blackhole, 정방향과 역방향)가 고정한다.

### 18.11 history: 밀려난 행 (ADR-0052 결정 10)

**프레임.** `SessionFrame.screen_history = 9`, `ScreenHistory{repeated bytes lines = 1; uint64 skipped = 2}`. host에서 client로만 가고 스트림으로만 간다(datagram에 싣지 않는다). 새 capability는 없고 `screen.v1`을 협상한 화면 동기화 attach에서만 보낸다. 부호화된 메시지는 16 KiB(`SESSION_CHUNK_MAX`) 이하이고 받는 쪽이 `SessionFrame::validate`로 검사한다. `lines`는 기본 화면(대체 화면이 아닌)의 맨 위에서 밀려난 행을 오래된 것부터 담은, 개행 없는 SGR 서식 텍스트(UTF-8)다. `skipped`는 `lines` 뒤에 밀려났지만 보관하지 못해 세기만 한 행의 수이고, 한 프레임 안에서 `lines`가 먼저고 `skipped`가 나중이다. 행이 많으면 여러 프레임으로 나누고 `skipped`는 마지막 프레임에 싣는다(`ScreenHistory::batches`). 16 KiB에 한 줄도 못 들어가는 행은 조용히 버리지 않고 `skipped`에 더한다.

**host.** 에뮬레이터의 수집기(`HostScreen::take_history`)가 세션당 5000행·4 MiB까지 모은다. 상한을 넘으면 행은 포맷하지 않고 `skipped`로 센다. 화면 갱신을 막 보냈고(더 보낼 갱신이 없고) 쓰이지 않은 화면 조각이 `SEND_DEPTH_CAP_BYTES` 아래일 때만 수집된 행을 가져가 보낸다. 밀리는 동안에는 가져가지 않으므로 수집기가 상한까지 쌓고 넘치는 만큼을 센다. 그래서 밀린 뒤에 오는 것은 건너뛴 수 한 번이다. `Exit`·`Closed` 앞에서는 마지막 화면 다음에 남은 행을 모두 내보낸다. 같은 행은 한 번만 가져가므로 재전송이 없고, 한 세션에 attach가 둘이면 행은 먼저 가져간 쪽에 간다.

**재부착.** 새 attach(`session.attach`에 `screen`이 있을 때)는 ACL을 통과한 시점에 쌓여 있던 행을 버린다. 재부착은 현재 화면 한 장만 받고 history를 되풀이하지 않는다. 지나간 출력 전체는 `qsh session read`가 바이트로 준다. 옛 peer(`screen.v1` 없음)에는 이 프레임이 가지 않는다.

**client.** 이벤트 `AttachEvent::ScreenHistory`는 화면 경로에서만 오고 attach driver가 `ScreenSink::history`로 넘긴다. 렌더러(`ScreenRenderer::history`, §18.10)가 행을 로컬 터미널의 스크롤백에 넣고 마지막 상태를 다시 그린다. 행은 peer의 입력이므로 SGR(`CSI ... m`)과 글자만 남기고 다른 제어 문자·이스케이프 시퀀스는 버린다. `skipped`가 0이 아니면 `--- N lines skipped ---` 한 줄이 `lines` 뒤에 붙는다.

**로그.** history는 PTY 내용이다. 로그, doctor, 감사 기록에 싣지 않는다. 감사 기록에 새 필드는 없다.

### 18.12 입력 반영 지점: `ScreenEcho` (ADR-0053 결정 3)

**프레임.** `message ScreenEcho { uint64 state_num = 1; uint64 input_seq = 2; TtyEcho tty = 3; }`, `enum TtyEcho { TTY_ECHO_UNKNOWN = 0; TTY_ECHO_KERNEL = 1; TTY_ECHO_APP = 2; TTY_ECHO_SECRET = 3; }`. 늘 스트림(`SessionFrame.screen_echo = 10`)으로 가고, datagram 운반체가 살아 있으면 `DatagramFrame` 종류 13으로도 먼저 한 번 간다. host에서 client로만 가고 capability는 `screen-echo.v1`이다. 모르는 `tty` 값은 `UNKNOWN`으로 읽어 decode를 실패시키지 않는다.

**뜻.** host가 이 frame을 만든 시각 t에 이 attach가 보는 화면은 상태 `state_num`이었고, 이 attach 축의 누적 입력 offset `input_seq`(`Input.input_seq`와 같은 offset, §10-5) 앞의 바이트는 모두 `t - ECHO_GRACE` 전에 PTY에 쓰였다. `tty`는 t에 읽은 PTY의 에코 상태다. `ECHO_GRACE`는 상수이고 50 ms에서 시작한다(세 OS 확정은 ADR-0053 결정 16의 시험).

**입력 시각 표.** host는 attach마다 PTY에 쓴 입력의 (끝 offset, 쓴 시각)을 64개까지 들고(`InputTimes`), 넘치면 가장 오래된 둘을 합친다(시각은 늦은 쪽, 그래서 주장은 늘 보수적이다). `input_seq`는 쓴 시각이 `ECHO_GRACE` 이상 지난 가장 큰 끝 offset이고 뒤로 가지 않는다. 시작값은 attach가 이어받은 입력 offset이다. 표에는 offset과 시각만 있고 바이트는 없다. 스트림 정본과 datagram 사본은 같은 축을 쓰므로 어느 쪽으로 적용됐든 같다.

**보내는 때.** (a) `ScreenUpdate`를 보낼 때마다 같은 운반체로 그 뒤에 하나(그 갱신의 `new_num`), (b) 화면이 바뀌지 않았어도 `input_seq`나 `tty`가 앞으로 가면 하나(입력을 쓴 시각 + `ECHO_GRACE`에 타이머로 깨고 현재 화면 상태 번호를 쓴다). 직전과 같은 값은 보내지 않는다. 최종 화면 뒤 `Exit` 앞에도 (a)가 따른다.

**tty 읽기.** Unix host는 PTY master에서 `tcgetattr`로 `ECHO`와 `ICANON`을 읽는다. `ECHO` 켜짐은 `KERNEL`, `ECHO`와 `ICANON` 꺼짐은 `APP`, `ECHO` 꺼짐과 `ICANON` 켜짐은 `SECRET`이다. Windows host(ConPTY)와 pipe 세션, 읽기 실패는 `UNKNOWN`이다. 플래그만 읽고 PTY 내용은 읽지 않는다.

**client의 검사.** `input_seq`가 client가 보낸 offset보다 크면 거짓 신호로 보고 버리고 센다(`echo_rejected`, `Attached::echo_rejected`). 연결을 끊지 않는다. 두 운반체의 사본은 `(state_num, input_seq)`가 더 앞선 것만 넘기고 같은 점에서는 `tty`가 바뀐 것만 넘긴다. 협상되지 않은 attach에서 온 것은 버린다. 통과한 신호는 `AttachEvent::ScreenEcho`로 나온다.

**시험.** `crates/qsh-testkit/tests/it/screen_echo.rs`(`screen_echo_is_sent_after_input_even_when_the_screen_does_not_change`, `screen_echo_follows_each_screen_update_on_the_same_carrier`, `a_client_without_screen_echo_gets_no_screen_echo_frames`, `a_host_without_screen_echo_gets_no_screen_echo_frames`), `crates/qsh-core/src/client/echo.rs`(`a_screen_echo_beyond_the_sent_input_is_rejected_and_counted`), `crates/qsh-core/src/input_times.rs`(표와 `ECHO_GRACE` 규칙, 주입한 시계), `crates/qsh-core/src/pty/tests.rs`(`tty_echo_reads_echo_and_icanon_from_the_pty`). fuzz는 `decode_session_frame`과 `decode_datagram_frame`이 덮는다.

**client의 사용(attach driver).** `ScreenSink`가 `PredictDriver`(`crates/qsh-core/src/client/predict_drive.rs`)를 쥔다. input pump는 `Input`을 쓰기 직전에 `on_input(bytes, 쓰고 난 뒤의 누적 offset)`을 부르고 곧바로 예측을 겹쳐 다시 그린다. reader는 적용한 상태마다 `on_state`를, 받은 `ScreenEcho`마다 `on_echo`를 부른다. 이름 붙은 상태가 아직 적용되지 않았으면 `Predictor`가 그 리포트를 하나만 들고 있다가(더 새것이 오면 바꾼다. 상한 하나, ADR-0053 결정 3·15) 그 상태를 적용할 때 판정한다. 상태 번호는 attach(leg)마다 1부터라서 새 leg에서는 적용한 상태 번호와 들고 있던 리포트를 버린다. 늦은 확인의 250 ms는 `Predictor::next_deadline`까지 reader가 잠들었다가 `tick`으로 밑줄을 그린다(시간으로 걷어 내지는 않는다). 정책 값은 정방향에서는 `PolicyMonitor`가 1초마다 내는 `prediction`이고, 역방향 route에서는 `Input`을 쓴 시각과 그 offset을 덮는 `InputAck`이 온 시각의 차이를 EWMA(1/8)로 낸 srtt를 `adapt::decide`에 넣어 1초에 한 번 결정한다. 첫 표본 전에는 `Off`다. `--predict=always`는 `adapt::User.prediction`의 `Always` 핀으로 `[transport].adaptive = "off"`보다 이기고 `reasons`에 `user_override`를 남긴다. 양쪽이 `screen-echo.v1`을 광고하지 않으면 예측은 하지 않는다. 상태 변화는 tracing target `qsh::predict`에 한 줄 JSON으로 남는다(개수와 사유만). 시험: `crates/qsh-core/src/client/predict_drive/tests.rs`, `crates/qsh-core/src/ops/session/predict_tests.rs`, `crates/qsh-cli/tests/it/screen_sync.rs`의 `a_predicted_keystroke_is_drawn_before_the_echo_arrives`.

## 19. 홀펀칭 (ADR-0054)

NAT 뒤 장비 B에 밖의 장비 A가 닿도록, 둘 다 닿는 사용자의 `qsh listen` R이 후보 주소를 중개하고 양 끝이 같은 UDP 소켓에서 동시에 보내 구멍을 뚫는다. 이 절은 wire 계약(capability `punch.v1`, message, 상한, 검사, 펀치 datagram, close 코드)만 적는다. 흐름의 역할 분담은 ADR-0054 결정 10이 정본이고, R의 중개 서비스와 B의 offer 처리는 §19.9가 적는다. client 경주는 뒤 스텝이 이 절에 더한다.

### 19.1 message

```proto
message PunchCandidate { bytes ip = 1; uint32 port = 2; PunchCandidateKind kind = 3; }
enum PunchCandidateKind { PUNCH_CANDIDATE_KIND_UNSPECIFIED = 0; ..._HOST = 1; ..._REFLEXIVE = 2; }
message PunchRequest  { bytes attempt_id = 1; bytes target_fingerprint = 2;    repeated PunchCandidate candidates = 3; } // ControlMessage 90, A -> R
message PunchOffer    { bytes attempt_id = 1; bytes initiator_fingerprint = 2; repeated PunchCandidate candidates = 3; } // ControlMessage 91, R -> B
message RendezvousQuery {}                                                                                              // ControlMessage 92, A -> B
message PunchReply    { repeated PunchCandidate candidates = 1; PunchCandidate initiator_reflexive = 2;
                        bool target_reflexive_private = 3; PunchRefusal refusal = 4; }                                  // Response 16, R -> A
message PunchAnswer   { repeated PunchCandidate candidates = 1; }                                                       // Response 17, B -> R
message RendezvousList { repeated bytes fingerprints = 1; }                                                             // Response 18, B -> A
enum PunchRefusal { NONE = 0; TARGET_NOT_REGISTERED = 1; TARGET_UNSUPPORTED = 2; TARGET_DENIED = 3; TARGET_BUSY = 4; TARGET_TIMEOUT = 5; } // PUNCH_REFUSAL_ 접두
```

R 자신의 거부(인가, 속도 상한, 꺼짐, 크기)는 기존 `Error`(`PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`, `UNSUPPORTED`, `INVALID_ARGUMENT`)로 답하고, B 쪽에서 난 일은 `PunchReply.refusal`로 알린다. wire `Error`에는 details가 없어서 A가 "R이 거부"와 "B가 거부"를 가르려면 이 enum이 필요하다. 모르는 `kind`·`refusal` 값은 decode를 실패시키지 않고 각각 `UNSPECIFIED`·`NONE`으로 읽는다. `qsh listen`은 `Hello.reverse` 없이 `punch.v1`을 광고한 peer의 연결을 펀칭 연결로 받는다(ADR-0054 결정 10, §19.9).

### 19.2 상한과 모양 검사

받는 쪽은 인가보다 먼저, 어떤 자원도 만들기 전에 아래를 본다. 어기면 `INVALID_ARGUMENT`이고 R은 그 펀칭 연결을 닫는다. 보내는 쪽 encoder(`encode_control`)도 같은 검사로 거부한다. 기존 `CONTROL_FRAME_MAX`는 그대로 먼저 걸린다.

| 항목 | 값 | 상수(`qsh-proto::punch`) |
|---|---|---|
| `attempt_id` | 정확히 16바이트(A가 CSPRNG로 만든다) | `ATTEMPT_ID_LEN` |
| fingerprint(`target_fingerprint`, `initiator_fingerprint`, `RendezvousList` 항목) | 정확히 32바이트 | `PUNCH_FINGERPRINT_LEN` |
| 한 message의 후보 | 여덟 이하 | `MAX_PUNCH_CANDIDATES` |
| `RendezvousList` | fingerprint 넷 이하. 넘으면 A가 앞의 넷만 쓴다 | `MAX_RENDEZVOUS_FINGERPRINTS` |
| 한 message의 부호화 길이 | 1 KiB 이하 | `PUNCH_MESSAGE_MAX` |
| peer-reflexive(A가 스스로 배우는 후보) | 넷까지 | `MAX_PEER_REFLEXIVE` |
| R의 동시 펀칭 연결 | 16 | `RENDEZVOUS_MAX_CLIENTS` |
| A 하나의 시도 | R: 진행 중 하나, 60초에 여섯 | `PUNCH_RATE`, `PUNCH_RATE_WINDOW_SECS` |

B의 동시 창 넷(`MAX_PUNCH_WINDOWS`)은 `qsh-transport`가 정의한다. 모양 검사는 `PunchRequest::validate`·`PunchOffer::validate`·`PunchAnswer::validate`·`PunchReply::validate`·`RendezvousList::validate`이고 오류는 어긴 규칙의 이름만 담는다(값을 되풀이하지 않는다).

### 19.3 후보 검사

`valid_punch_candidate(ip, port)`는 `ip`가 4바이트나 16바이트(네트워크 순서)이고 `port`가 1..=65535일 때만 주소를 돌려준다. 거부하는 주소: unspecified, loopback, link-local(`169.254.0.0/16`, `fe80::/10`), multicast(`224.0.0.0/4`, `ff00::/8`), `255.255.255.255`, `0.0.0.0/8`, `240.0.0.0/4`, IPv4-mapped IPv6(`::ffff:0:0/96`). 사설(`10/8`, `172.16/12`, `192.168/16`, ULA)과 CGNAT(`100.64.0.0/10`) 주소는 받는다. 같은 LAN과 CGNAT 안쪽 경로가 실제 경로이기 때문이다.

받는 쪽은 `check_candidates`로 같은 검사를 다시 한다. 후보가 여덟을 넘으면 message 오류(`INVALID_ARGUMENT`)이고, 그 안에서 검사에 걸린 후보는 버리고 개수를 센다. 같은 주소는 하나로 합친다. 후보 쌍은 같은 family 안에서만 맺는다(ADR-0054 결정 8).

### 19.4 인증

R은 후보를 중개할 뿐 신원을 보증하지 않는다. A는 펀칭한 연결에서 상대가 내민 fingerprint가 B의 pin과 정확히 같을 때만 받고, B는 창에서 받은 연결의 검증된 fingerprint가 offer의 `initiator_fingerprint`와 같을 때만 serve한다. 다르면 그 연결을 `0x1001`로 닫는다(ADR-0054 결정 12). TLS 검증 경로(§3)는 바뀌지 않는다.

### 19.5 펀치 datagram

16바이트(`PUNCH_DATAGRAM_LEN`)다. 머리 4바이트 `00 71 70 01`(`PUNCH_HEAD`)과 tag 12바이트다. tag는 `attempt_id`에서 `blake3::derive_key("qsh punch attempt key v1", attempt_id)`로 뽑은 key의 BLAKE3 keyed hash를 방향 표지(`"qsh punch a->b"`, `"qsh punch b->a"`)에 적용한 값의 앞 12바이트다. 첫 바이트의 fixed bit가 0이라 QUIC 패킷이 아니고, 길이가 21바이트 이하라서 quinn에 닿아도 답을 부르지 않는다. 이 datagram은 `qsh/1`의 message가 아니라 펀칭 소켓 옆을 오가는 고정 형식이며 `punch.v1`로 협상된 신호의 결과로만 보낸다. 대조는 `verify_punch_datagram`이 모든 바이트를 훑는다.

### 19.6 close 코드 `0x1006`

경주에서 채택되지 않고 이미 선 연결은 `APPLICATION_CLOSE` 코드 `0x1006`(`CLOSE_CODE_NOT_ADOPTED`)과 reason `not adopted`로 닫는다. 진행 중인 handshake는 버리고 quinn이 정리한다. 동결 밖 값이고(§16.3) peer는 이 값에 의존해 분기하지 않는다. `0x1001`은 §19.4의 fingerprint 불일치에 쓴다.

### 19.7 closed-window endpoint의 stateless reset

창이 닫힌 `PunchEndpoint`는 서버 설정이 없어도 quinn의 기본 동작대로 모르는 Initial에 stateless reset 하나로 답한다. 이것은 걸러 내지 않는다. 답은 부른 datagram보다 늘 작고(quinn은 최소 1바이트 작게 맞춘다) `min_reset_interval`로 속도가 제한되어, 제3자에게 향하는 증폭이 없고 ADR-0054 결정 26의 반사 상한(요청 한 번이 낳는 것은 1 KiB 이하)이 입력 크기로 이미 묶인다. 걸러 내면 같은 소켓의 살아 있는 연결이 죽은 상태를 알리는 reset도 함께 잃는다. 근거는 ADR-0054 개정 이력이다.

### 19.8 fuzz와 시험

`decode_control` 타깃이 새 message를 덮고 `validate()`·`check_candidates`를 부른다. 새 타깃 `punch_candidates`가 후보 검사, 모양 검사, 펀치 datagram tag 대조를 먹인다(§13). 신호 경로의 시험은 `crates/qsh-testkit/tests/it/punch_signal.rs`가 가상 NAT 망에서 A·R·B를 모두 띄워 본다(§19.9). 단위 시험: `crates/qsh-proto/src/punch.rs`의 `punch_candidate_validation_table`, `message_shape_rules_are_enforced`, `the_punch_messages_keep_their_pinned_numbers`, `the_encoder_refuses_a_malformed_punch_message`, `the_capability_is_advertised`.

### 19.9 R의 중개와 B의 offer 처리

**펀칭 연결.** 단독 `qsh listen`(R)은 `Hello.reverse` 없이 `punch.v1`을 광고한 peer를 `Hello` 시점에 등록 대신 펀칭 연결로 받는다. 합친 모드(§11, ADR-0059 결정 5)에서는 `punch.v1`이 모든 빌드의 광고라 `Hello`만으로 정방향 client와 펀칭 client를 가를 수 없으므로, `Hello.reverse`가 없는 연결을 정방향으로 시작하고 첫 요청(`Ping` 제외)이 `PunchRequest`일 때 그 연결을 펀칭 연결로 바꾼다. 16개 상한의 permit은 전환 시점에 얻고(모자라면 `RESOURCE_EXHAUSTED`, retryable, 뒤 닫음), 연결 quota는 처음부터 쥔다. `relay_punch`는 최대 1.5초를 기다리므로 control loop를 막지 않는 갈래로 돈다. 다른 요청이나 먼저 연 데이터 스트림은 정방향으로 굳고, 굳은 연결의 `PunchRequest`는 단독 serve처럼 `UNSUPPORTED`다. 아래 3초 규칙과 "그 밖의 message는 `UNSUPPORTED`"는 전환 뒤에 그대로 적용된다. `[punch].mode = "off"`이면 이 분기는 없고 기존 `host.reverse` 누락 거절이 그대로 나간다. 펀칭 연결은 동시에 16개(`RENDEZVOUS_MAX_CLIENTS`)이고 넘으면 `Hello`에 `RESOURCE_EXHAUSTED`로 답한다. 이 연결이 받는 것은 `Ping`(`Pong`으로 답한다)과 `PunchRequest` 한 번이고, 그 밖의 message는 `UNSUPPORTED`다. 요청 없이 3초(`RENDEZVOUS_IDLE`), 답을 보낸 뒤 3초가 지나면 R이 연결을 닫는다. 거부나 오류로 끝난 요청은 오류 frame을 보낸 뒤 바로 닫는다.

**R이 요청을 처리하는 순서.** 인가 전에는 자원을 만들지 않는다.

1. `host.punch`(`punch.request`)를 연결의 principal로 판정하고 감사한다. 거부는 균일한 `PERMISSION_DENIED`이고 어떤 등록이 있는지 알리지 않는다.
2. 모양 검사(§19.2)와 후보 검사(§19.3). 후보가 여덟을 넘거나 모양이 틀리면 `INVALID_ARGUMENT`이고 연결을 닫는다. 검사에 걸린 후보는 버리고 개수만 센다.
3. 속도 표. A 하나(fingerprint)에 진행 중인 시도 하나, 60초에 여섯. 넘으면 `RESOURCE_EXHAUSTED`(재시도 가능)이고 연결은 열려 있다. 거부된 시도는 횟수에 넣지 않는다.
4. `target_fingerprint`의 등록 연결을 찾는다. 없거나 `punch.v1`을 광고하지 않았으면 `PunchReply`의 `refusal`이 `TARGET_NOT_REGISTERED`·`TARGET_UNSUPPORTED`다.
5. A의 후보에 R이 본 A의 주소(이 연결의 원격 주소)를 `REFLEXIVE`로 더해(후보는 여덟 이하로 맞춘다) `PunchOffer`를 B의 등록 연결로 보낸다. 후보 값은 바꾸지 않는다.
6. B의 `PunchAnswer`를 1.5초(`PUNCH_ANSWER_TIMEOUT`) 기다린다. B의 오류는 `UNSUPPORTED`가 `TARGET_UNSUPPORTED`, `RESOURCE_EXHAUSTED`가 `TARGET_BUSY`, 나머지(`PERMISSION_DENIED` 포함)가 `TARGET_DENIED`로 바뀌고, 시간이 지나면 `TARGET_TIMEOUT`이다.
7. `PunchReply`에 B의 후보와 R이 본 B의 주소(등록 연결의 원격 주소, `REFLEXIVE`)를 담고, `initiator_reflexive`에 A의 주소를 담는다. B의 주소가 공인 주소가 아니면(R과 B가 NAT 하나를 나눈다) `target_reflexive_private`가 참이고 A가 후보를 유도한다(ADR-0054 결정 8).

R이 B에게 보내는 `PunchOffer`는 등록 연결의 요청 채널을 쓴다. B가 보기에는 controller가 보낸 요청이고 응답은 같은 `request_id`로 돌아온다.

**B의 처리.** B(`qsh serve --to`)는 등록 연결로 받은 `PunchOffer`만 받는다(그 밖의 연결에서는 `UNSUPPORTED`). 순서는 다음과 같다.

1. 모양 검사. 틀리면 `INVALID_ARGUMENT`.
2. offer의 `initiator_fingerprint`를 B의 `trust.toml` pin으로 찾아 그 principal로 `host.punch`(`punch.offer`)를 판정하고 감사한다. pin이 없으면 감사에 거부를 남기고 균일한 `PERMISSION_DENIED`로 답한다. 권한 평가기가 허용하더라도 pin이 없는 initiator는 받지 않는다.
3. 후보 검사. 쓸 수 있는 후보가 없으면 `INVALID_ARGUMENT`.
4. 속도 표(initiator당 60초에 여섯)와 창 수(동시 `MAX_PUNCH_WINDOWS` = 4). 넘으면 `RESOURCE_EXHAUSTED`이고 창도 소켓 전송도 없다.
5. 서버 창을 6초 연다. 호스트 후보(`invite_address` 경로 조회로 얻은 IPv4 하나, 전역·ULA IPv6 하나)와 이 창의 소켓 포트를 `PunchAnswer`로 답하고, offer의 후보로 펀치 datagram을 보낸다(ADR-0054 결정 14, 일정은 `run_target`).
6. 창이 받은 연결은 검증된 fingerprint가 열려 있는 창의 initiator일 때만 일반 serve 경로로 넘긴다. 여러 창이 동시에 열려 있으면 Initial은 어느 창의 loop에든 닿으므로 "이 창의 initiator"가 아니라 "그 fingerprint의 창이 열려 있다"를 본다. 아니면 `0x1001`로 닫는다.

`RendezvousQuery`는 B에 이미 선 어떤 연결에서든 보낼 수 있다. `host.punch`(`punch.rendezvous`)를 연결의 principal로 판정하고, 통과하면 B가 지금 등록해 있는 controller의 fingerprint(살아 있는 등록이 먼저, 그다음 `[serve].to`의 pin, 중복 없이 넷까지)를 `RendezvousList`로 답한다.

**기록.** `qsh::punch` 로그는 `relayed`(결과 이름과 후보 개수)와 `window_opened`·`window_closed`(개수)만 낸다. 주소, fingerprint, `attempt_id`는 로그에도 감사에도 없다.

### 19.10 recovery와 `--supervise`의 route 재해석 (ADR-0054 결정 18)

§10의 recovery는 연결이 죽으면 재dial하는데, 이 재dial은 처음 해석한 주소를 다시 쓰지 않고 **route를 다시 돈다**. 직접 dial과 펀칭의 경주(결정 16)를 그 순간의 소켓·로컬 후보·중개자로 새로 한다. 그래서 A의 바깥 주소가 바뀌면(NAT 매핑이 사라지거나 다른 망으로 옮기면) 새 주소로 다시 펀칭하고, 직접 길이 돌아와 있으면 직접 dial이 1초 head start 안에 서서 중개자에게 아무것도 보내지 않는다. 이 규칙은 forward 연결의 attach recovery(`recover_attach`의 재dial)와 `--supervise` 터널의 재dial이 같이 쓴다. 역방향 등록 연결의 recovery(§11-4)는 지금 그대로다.

- **시한.** 펀칭할 수 있는 host(중개자 후보가 있고 `[punch].mode`가 `auto`)의 재dial 시도 하나는 `REDIAL_DEADLINE`(2초) 대신 펀칭 예산을 쓴다. 신호 3초와 창 5초를 합한 8초이고(`PUNCH_BUDGET`), 직접 dial이 먼저 도는 host는 그 앞에 head start 1초가 붙어 9초다. 주소가 없는 pin은 곧바로 펀칭하므로 8초다. 명령의 첫 dial 시한(10초)을 넘지 않는다. 펀칭할 수 없는 host는 2초 그대로다. recovery 루프가 시도 하나를 기다리는 시한(`Reconnect::attempt_deadline`)도 같은 값이다. 시한을 넘긴 재dial은 task로 계속 돌고 다음 시도가 이어받으므로(`spawn_reattach`), 시한은 기다림의 한도이지 재dial을 자르는 칼이 아니다.
- **펀칭이 끝난 시도.** 펀칭이 먼저 실패하면(중개자에 닿지 않음, `target_not_registered` 등) 직접 dial은 시도가 시작된 뒤 2초까지만 더 기다린다. 직접 dial만 있던 재dial이 쓰던 시간이다. 이미 2초가 지났으면 곧바로 실패하고, 시도 횟수·backoff(0, 200 ms, 800 ms)·상태 줄의 `reconnecting (attempt k)`는 §10 그대로 다음 시도로 넘어간다. 시도마다 `qsh::recovery` 기록이 남고 모든 시도가 실패하면 attach의 오류는 `CONNECTION_FAILED`다.
- **resume은 그대로다.** 재dial로 선 연결(직접이든 펀칭이든)에서 §10의 reattach 4단계를 그대로 하고, resume token은 route가 아니라 peer 신원에 묶여 있으므로 같은 세션을 이어 붙인다. 입력의 무손실·무중복(§10-5)도 같다. 새 session은 만들어지지 않는다.
- **B의 주소가 바뀌면.** B의 등록 recovery(ADR-0041)가 먼저 R에 다시 등록하고 A의 시도가 그 뒤에 펀칭한다. 등록이 아직 없으면 `target_not_registered`로 그 시도가 실패하고 다음 시도로 넘어간다.
- **`--supervise`.** 터널의 재dial 시도 하나도 같은 시한으로 route를 다시 돌고, 포기하지 않는 동안 listener는 묶여 있다(ADR-0023). `-L`·`-D`·`-R` 어느 쪽이든 carrier를 다시 세우는 길이 같다.

## 20. agent forwarding (ADR-0055)

이 절은 ADR-0055의 wire(capability `agent.v1`, `StreamKind::AGENT`, 요청·응답 필드, `AgentGrant`)와 `qsh_proto::agent`의 메시지 framing·거르기 표를 적는다. host의 소켓, client의 로컬 agent 연결, 인가와 감사는 해당 스텝이 들어올 때 이 절에 더한다.

### 20.0 capability와 필드

```protobuf
enum StreamKind { ...; AGENT = 6; }            // host -> client, StreamHeader.ticket = agent_channel
message SessionOpen     { ...; bytes agent_channel = 9; }
message SessionAttach   { ...; bytes agent_channel = 7; }
message ExecStart       { ...; bytes agent_channel = 6; }
message SessionOpened   { ...; AgentGrant agent = 7; }
message SessionAttached { ...; AgentGrant agent = 9; }
message ExecStarted     { ...; AgentGrant agent = 3; }
enum AgentGrant {
  AGENT_GRANT_UNSPECIFIED = 0;  // 요청하지 않음
  AGENT_GRANT_FORWARDED = 1;
  AGENT_GRANT_DENIED = 2;       // forward.agent 판정이 거부
  AGENT_GRANT_UNAVAILABLE = 3;  // host가 소켓을 만들 수 없음(디렉터리, 경로 길이, 꺼짐, 이 빌드에 agent 지원이 아직 없음)
  AGENT_GRANT_NO_SOCKET = 4;    // attach한 세션이 agent 없이 열렸음
}
```

- `agent_channel`은 client가 CSPRNG로 만든 정확히 16바이트(`AGENT_CHANNEL_LEN`)다. 비어 있으면 요청하지 않은 것이다. 길이가 다르면 host는 ACL 결정 앞에서 `INVALID_ARGUMENT`로 답하고 audit 기록을 쓰지 않는다. `agent.v1`을 협상하지 않은 peer가 보낸 필드는 `screen`과 같이 오류 없이 무시하고 응답의 `agent`는 `UNSPECIFIED`다.
- client는 협상된 교집합에 `agent.v1`이 있을 때만 `agent_channel`을 세팅한다(`Session::session_open`·`attach_request`·`exec_start_with_agent`가 광고하지 않은 peer 앞에서 필드를 비운다). `-A`를 주지 않은 요청은 이 필드가 없으므로 인코딩이 기존과 바이트 단위로 같다(`no_agent_field_without_dash_a`).
- 모르는 `AgentGrant` 값은 `UNSPECIFIED`로 읽는다. 번호는 각 message의 다음 빈 번호이고 기존 번호는 건드리지 않았다. 새 control message는 없다.
- 이 스텝의 host는 소켓을 만들지 못하므로, `agent.v1`을 협상한 peer가 16바이트 `agent_channel`을 보내면 세션이나 exec는 정상으로 열고 응답의 `agent`에 `UNAVAILABLE`을 싣는다. 오류로 끝내지 않는다. 이 답은 host 소켓 스텝이 `FORWARDED`·`DENIED`·`NO_SOCKET` 판정으로 바꾼다.
- `AGENT` 스트림은 host가 연다. header의 `ticket`은 그 `agent_channel`이고 header 뒤의 바이트는 §20.1을 따른다. 받는 쪽의 header 대기는 기존 `HEADER_TIMEOUT`이다. reverse route에서는 `qsh listen` 데몬이 이 스트림을 받아 claim한 CLI에만 건넨다(§20.2.1).

### 20.1 메시지 framing

`AGENT` 스트림은 ssh-agent 프로토콜 바이트를 그대로 싣는다. 메시지는 4바이트 big-endian 길이, 1바이트 type, 내용이고, 길이는 type 바이트와 내용을 센다. `qsh_proto::agent::AgentDecoder`(sans-IO)는 길이와 type 바이트만 읽고 내용은 해석하지 않는다.

- 길이 상한은 `AGENT_MESSAGE_MAX = 262144`(256 KiB, OpenSSH `AGENT_MAX_LEN`과 같다)다. 길이 0(`AgentFrameError::ZeroLength`)과 상한 초과(`AgentFrameError::Oversize`)는 헤더 4바이트만 보고 거절한다. 선언된 길이로 버퍼를 미리 잡지 않고, 실제로 도착한 바이트만 쌓는다.
- 오류가 나면 decoder는 그 상태로 굳고 쌓인 바이트를 버린다. 호출자는 이 오류를 `BAD_HEADER`(`0x2001`) 스트림 reset과 로컬 agent 연결 닫기로 바꾼다(스트림 수준의 시험은 client 스텝에서 더한다).
- `next_message`는 길이 접두를 포함한 메시지 전체를 돌려주므로 로컬 agent에 그대로 쓸 수 있다.

### 20.2 거르기 표

client는 host에서 온 요청의 type을 `ALLOWED_REQUESTS`(`REQUEST_IDENTITIES` 11, `SIGN_REQUEST` 13)에서 찾는다(`request_disposition`). 표에 없는 type은 번호가 SSH1 시절의 것이든 모르는 것이든 로컬 agent에 보내지 않고, client가 `FAILURE_REPLY`(`00 00 00 01 05`)를 스트림에 쓴다. 표를 넓히려면 새 ADR이 필요하다(ADR-0055 결정 12). 응답은 거르지 않고 같은 decoder로 길이만 끊어 상한을 지킨다.

### 20.2.1 역방향 route (ADR-0055 결정 14)

target(`qsh serve --to`)이 host이고 controller 쪽 CLI가 client다. 데몬은 가운데에서 바이트만 옮기고 로컬 agent에 연결하지 않는다.

- 등록. CLI가 `LOCAL_CONTROL` conduit으로 `agent_channel`이 든 `SessionOpen`·`SessionAttach`·`ExecStart`를 보내면, 데몬의 `ControlHub`는 그 요청을 QUIC으로 내보내는 순간 `agent_channel → conduit` 항목을 올린다. 응답을 기다리지 않는다. 길이가 16바이트가 아닌 필드는 올리지 않고, 다른 conduit이 이미 올린 channel은 가져가지 못한다. hub당 channel은 256개까지다. 등록한 conduit이 죽으면 항목이 내려가고 큐에 든 스트림은 reset된다. 재attach(resume)는 새 registration의 hub에 같은 channel을 다시 올린다.
- 도착. target이 등록 연결 위로 `AGENT` 스트림을 열면 데몬은 header를 읽고, `ticket`이 정확히 16바이트이고 등록된 channel이며 hub가 32개(`MAX_AGENT_STREAMS_PER_HUB`)를 넘지 않을 때만 큐에 넣는다. 아니면 `BAD_HEADER`(`0x2001`) 또는 `RESOURCE_EXHAUSTED`(`0x200D`)로 reset한다. 큐에 든 스트림은 `TCP_ACCEPTED`와 같이 30초 안에 claim되지 않으면 `0x200C`로 reset된다. 슬롯은 큐와 splice를 통틀어 센다.
- claim. CLI는 `LOCAL_STREAM` conduit에 `StreamHeader{AGENT, ticket = channel(16바이트) ‖ claim token(1~64바이트)}`를 보낸다. `TCP_ACCEPTED`처럼 데몬은 raw 바이트 전에 `LocalResponse`를 정확히 한 번 보낸다(`ClaimGranted` 또는 `LocalError`). 처음 claim한 토큰이 channel의 seat에 앉고, 이후에는 같은 토큰만 스트림을 가져간다. 다른 토큰, 빈 토큰, 등록 안 된 channel은 모두 같은 `TIMEOUT`을 즉시 받는다. 토큰은 CLI가 프로세스마다 CSPRNG로 만든다.
- 이후 CLI가 로컬 agent에 연결하고 §20.2의 표로 거른다. 길이 오류나 로컬 agent 오류는 conduit을 닫는 것으로 끝나고, 데몬이 QUIC 스트림을 끝낸다(conduit에는 스트림 단위 reset이 없다).

### 20.3 시험

단위 시험은 `crates/qsh-proto/src/agent.rs`의 `agent_filter_table`(type 0~255 전수와 이름 붙은 행), `an_oversized_agent_frame_resets_the_stream`(decoder 수준), 역방향 route의 `agent_hub_tests`(seat·상한·conduit 정리)와 `agent_reverse`(`agent_forward_over_the_reverse_route`, B47의 두 CLI, 33번째 스트림, 재attach), `a_zero_length_message_is_an_error`, `the_cap_itself_is_accepted`, `the_declared_length_is_not_allocated_up_front`, 청크 무관성 proptest다. 가짜 agent(`qsh_testkit::fake_agent::FakeAgent`)는 unix 소켓(Windows는 named pipe)에서 목록 조회와 결정적 서명에 답하고 나머지는 `FAILURE`로 답하며 받은 type을 모두 기록한다. fuzz 타깃은 `agent_frames`(§13-12)다.

## 21. jump chaining (ADR-0056)

이 절은 ADR-0056의 wire 계약(§21.0), `qsh_proto::jump`가 구현한 부분(§21.1, §21.2), 중간 peer의 처리 순서(§21.3)를 적는다. client 체인과 실패 보고, 운반체 적응(§21.5), recovery(§21.6), 역방향 데몬(§21.7), MTU 예산과 침묵 시한(§21.8)을 차례로 적는다. MTU 수치는 ADR-0057이 고친 것을 따른다(한 겹 비용 55바이트).

### 21.0 capability와 wire (ADR-0056 결정 3·4)

```proto
enum StreamKind { ...; JUMP = 7; }   // client -> 중간 peer
// StreamHeader{kind = JUMP, ticket = jump_channel(정확히 16바이트), host, port}
// 응답: ConnectResult{ok, code, message}. ok면 그 뒤로 u16 BE 길이 + 패킷 바이트의 반복
// DatagramFrame 종류 14 JumpPacket: channel = jump_channel, 몸통은 패킷 바이트 그대로
```

- capability 문자열은 `jump.v1`(`CAP_JUMP_V1`)이고 `LOCAL_CAPABILITIES`의 마지막 항목이다(§4). 협상된 교집합에 이 문자열이 없는 연결의 `JUMP` 스트림은 host가 모르는 종류처럼 `BAD_HEADER` reset으로 답한다. 종류 14 datagram은 jump 채널 표에 없는 channel이면 버리고 센다.
- `jump_channel`은 client가 CSPRNG로 만든 정확히 16바이트(`JUMP_CHANNEL_LEN`)다. `StreamHeader::jump`가 header를 만들고 `StreamHeader::jump_channel`이 16바이트가 아닌 ticket과 `JUMP`가 아닌 header에 `None`을 돌려준다. 길이가 다르거나 쓰고 있는 값이면 중간 peer는 ACL 앞에서 `INVALID_ARGUMENT`로 답한다(audit 없음).
- `host`와 `port`는 `TCP_CONNECT`와 같은 필드이고 모양 검사(255바이트, 제어문자 거부, ADR-0019 결정 5)와 `port`의 1..=65535 검사는 `TCP_CONNECT`처럼 받는 쪽(`qsh-core`)이 한다. `deny_host_local`은 읽지 않는다.
- 종류 14 datagram의 몸통은 protobuf로 다시 싸지 않는다. 알 수 없는 channel은 받는 쪽이 버리고 센다.
- 스트림 운반체의 길이 머리 오류(`JumpFrameError`)는 `BAD_HEADER`(`0x2001`) reset이다(§21.1).

### 21.1 스트림 운반체 framing

`JUMP` 스트림은 `ConnectResult{ok}` 뒤로 `u16` big-endian 길이와 그만큼의 안쪽 QUIC 패킷 바이트를 되풀이한다. 몸통은 protobuf로 다시 싸지 않는다. `qsh_proto::jump::JumpStreamDecoder`(sans-IO)는 길이만 읽고 패킷은 해석하지 않는다.

- 상수: `JUMP_PACKET_MIN = 1200`, `JUMP_PACKET_MAX = 1452`, `JUMP_STREAM_QUEUE = 65536`(보내는 쪽이 아직 나가지 않은 바이트의 상한), `JUMP_CHANNEL_LEN = 16`.
- 길이 0(`JumpFrameError::ZeroLength`)과 `JUMP_PACKET_MAX` 초과(`JumpFrameError::Oversize`)는 길이 2바이트만 보고 거절한다. 선언된 길이로 버퍼를 미리 잡지 않고 실제로 도착한 바이트만 쌓는다. 오류가 나면 decoder는 그 상태로 굳고 쌓인 바이트를 버린다. 호출자는 이 오류를 `BAD_HEADER`(`0x2001`) 스트림 reset으로 바꾼다.
- `encode_packet`은 빈 패킷이나 `JUMP_PACKET_MAX`를 넘는 패킷에 `None`을 돌려주고, 보내는 쪽은 그 패킷을 버리고 센다.

### 21.2 QUIC long header 판독과 문의 판정

`read_long_header`는 RFC 8999가 평문으로 고정한 필드만 읽는다: 형식 비트, version, DCID(길이 0~255)와 SCID. 짧거나 잘린 입력과 short header는 `None`이다. 암호문과 version별 필드는 보지 않는다.

- `is_v1_initial_shaped`: long header(첫 바이트 상위 두 비트 `11`), version 1, 패킷 종류 Initial(첫 바이트의 `0x30` 비트가 0), 두 connection ID가 20바이트 이하, datagram 길이가 1200 이상 1452 이하. ADR-0056 결정 8은 종류 비트를 말하지 않고 "long header, version 1, 길이 1200 이상"만 적는다. 이 판정은 거기에 Initial 종류와 상한 1452를 더한 더 좁은 쪽이다. 문이 열리기 전에 client가 보낼 수 있는 것은 Initial뿐이고, 운반체가 1452를 넘는 패킷을 나르지 않기 때문이다.
- `answers_gate(packet, client_scid)`: 대상에서 온 패킷이 long header(종류와 version 무관: Retry, Initial, Version Negotiation)이고 DCID가 client가 문을 통과시킨 패킷의 SCID와 같으면 참이다. short header는 문을 열지 않는다(`is_short_header`로 가려낸다). 문 앞 패킷 수·바이트·10초 시한은 `qsh-core`의 몫이다.

### 21.3 중간 peer의 처리 순서 (ADR-0056 결정 7~9)

구현은 `crates/qsh-core/src/server/jump.rs`(admission)와 `crates/qsh-core/src/jump/middle.rs`(relay)다. `JUMP`는 `TCP_CONNECT`처럼 ticket이 없고 스트림을 여는 그 자리에서 `forward.jump`를 판정한다(§7). 앞 단계가 실패하면 뒤 단계는 돌지 않고, 인가 전에는 소켓도 채널도 없다.

1. 모양 검사. `jump_channel`이 정확히 16바이트이고 이 연결에서 쓰고 있는 값이 아니어야 하고, `host`·`port`는 `TCP_CONNECT`와 같은 검사(255바이트, 제어문자·공백·비ASCII 거부, 포트 1..=65535)를 받는다. 실패는 `INVALID_ARGUMENT`이고 ACL도 감사도 없다. 값의 점유는 인가 전에 잡히고 스트림이 끝나면 풀린다.
2. `forward.jump` 판정과 감사(`acl::check_jump`). resource는 요청한 `host:port` 문자열이다. 거부와 감사 쓰기 실패는 같은 균일한 `PERMISSION_DENIED`다. 스트림은 control 요청이 아니므로 감사의 `request_id`는 `"-"`다.
3. 상한. 연결당 16 채널(`MAX_JUMP_CHANNELS_PER_CONN`)과 터널 스트림 quota(`max_tunnel_streams_per_principal`·`max_tunnel_streams_per_forward`). 초과는 `RESOURCE_EXHAUSTED`다.
4. 해석 한 번, 시한 5초(`JUMP_RESOLVE_TIMEOUT`). 실패는 `CONNECTION_FAILED`다.
5. host-local 거부. 해석된 주소에서 ADR-0019 결정 3의 범주를 거르고 남은 주소가 없으면 `PERMISSION_DENIED`와 감사 한 줄(`rule` 없음)이다. 해석된 IP는 감사·로그·응답에 남지 않는다. 남은 주소의 첫 번째를 쓴다.
6. 그 family의 unspecified 주소, 포트 0에 UDP 소켓을 bind하고 고른 주소에 `connect`한다. `connect`된 소켓이라 그 주소에서 온 datagram만 받는다.
7. `ConnectResult{ok}`를 쓰고 relay를 시작한다. 거부는 `TCP_CONNECT`와 같이 `ConnectResult`, 송신 `finish()`, 수신 `stop()`(사유별 코드)이다. `JUMP` 스트림의 우선순위는 session band(100)다.

relay는 채널마다 한 task다. client에서 온 패킷(스트림 운반체의 `u16` 길이 frame과 종류 14 datagram)은 QUIC 문(§21.2)을 지나 소켓으로 나간다. 문이 닫혀 있는 동안은 Initial 모양만, `JUMP_PREGATE_PACKETS`(8)개·`JUMP_PREGATE_BYTES`(16 KiB)까지 통과하고, 그 SCID를 기억한다. target에서 온 패킷은 long header이고 DCID가 기억한 SCID 가운데 하나일 때 문을 열고(그 패킷도 통과), 그 전의 것은 버리고 센다. 문은 `JUMP_GATE_TIMEOUT`(10초) 안에 열려야 한다.

target에서 client로 가는 운반체는 J가 자기 눈으로 패킷마다 고른다(ADR-0056 결정 4). 양쪽이 `datagram.v1`을 협상했고 바깥 연결의 `max_datagram_size()`가 `JUMP_PACKET_MIN + 17`(1217) 이상이면 종류 14 datagram이고 아니면 `JUMP` 스트림이다. datagram 모드에서 자리를 넘는 패킷은 스트림으로 돌리지 않고 버리고 센다(안쪽 PLPMTUD가 자리를 배운다). 스트림 모드에서는 아직 쓰지 못한 바이트가 `JUMP_STREAM_QUEUE`(64 KiB)를 넘으면 새 패킷을 버리고 센다. datagram이 돌아오지 않을 때 스트림으로 물러서고 30초마다 다시 시험하는 적응은 §21.5와 §21.8이 적는다. J는 같은 규칙을 바깥 연결의 srtt로 돌린다(ADR-0058).

채널은 다음 가운데 하나로 끝나고 소켓과 점유가 함께 풀린다. 끝날 때 스트림을 어떻게 닫는지는 사유가 정한다.

| 사유 | 닫는 방식 |
|---|---|
| `stream_end`(client의 FIN·reset, 스트림 오류) | 송신 `finish()` |
| `connection_closed`(바깥 연결 종료) | 연결과 함께 task가 끝남 |
| `idle`(전달된 패킷이 양방향 모두 60초 동안 없음, `JUMP_IDLE`) | `0x2007`로 reset·stop |
| `gate_timeout`(문이 10초 안에 안 열림) | `0x2007`로 reset·stop |
| `unreachable`(소켓의 거부: Linux `ECONNREFUSED`, Windows `WSAECONNRESET`, 수신과 송신 모두) | `0x2007`로 reset·stop |
| `bad_frame`(길이 0이거나 1452 초과) | `0x2001`(`BAD_HEADER`)로 reset·stop |

`unreachable`은 첫 Initial을 보낸 뒤 ICMP 거부가 오는 즉시(loopback에서 수 ms) 스트림을 reset하므로 client는 handshake 시한을 기다리지 않는다. Windows의 `SIO_UDP_CONNRESET`은 끄지 않는다. client는 reset 값으로 분기하지 않고 "정상 종료가 아니다"만 읽는다(§16.5).

on-demand `qsh serve`의 idle 종료(ADR-0051 결정 2)는 살아 있는 jump 채널도 센다(`HostActivity::jump_channels`). 로그는 target `qsh::jump`(`channel_opened`, `gate_opened`, `channel_closed`)이고 기본에서 꺼져 있다. 해석된 IP, 패킷 내용, connection ID, channel 값은 싣지 않는다.

### 21.4 시험

단위 시험은 `crates/qsh-proto/src/jump.rs`의 `decoder_table`, `a_split_read_gives_the_same_packets`, `many_packets_in_one_chunk`, `the_declared_length_is_not_allocated_up_front`, `an_error_is_sticky_and_leaves_nothing_buffered`, `long_header_reader_table`, `initial_gate_table`, `answer_gate_table`와 proptest(`round_trip_under_any_chunking`, `readers_never_panic`)다. fuzz 타깃은 `jump_frames`(§13-13)다.

중간 peer의 시험은 `crates/qsh-testkit/tests/it/jump_host.rs`(진짜 QUIC 연결 위의 `JUMP` 스트림과 UDP 소켓: `a_real_inner_dial_through_j_reaches_t_over_the_stream_carrier`, `a_real_inner_dial_through_j_reaches_t_over_the_datagram_carrier`, `jump_without_forward_jump_opens_no_socket`, `jump_refuses_host_local_targets`, `a_jump_forwards_only_quic_until_the_target_answers_like_quic`, `the_pregate_caps_hold_on_a_real_channel`, `a_jump_socket_drops_datagrams_from_other_sources`, `a_jump_never_sends_more_than_it_received`, `jump_target_refusal_is_reported_fast`, `jump_bounds`, `jump_idle_closes_the_channel_and_the_socket`, `a_duplicate_jump_channel_is_invalid_argument_without_audit`, `on_demand_serve_stays_up_while_a_jump_channel_lives` 등)과 `crates/qsh-core/src/jump/middle/tests.rs`(문, 운반체 고르기 표, 큐, 점유 표)다.

### 21.5 client 체인 (ADR-0056 결정 4·6·10~13·15·16, ADR-0057)

client 쪽은 `crates/qsh-core/src/jump/{chain,carrier,report}.rs`다. 호출자는 `Ops::with_jump(hops)`로 hop 핀 이름 목록을 주고, 표면(`-J`, 핀 필드, `trust jump`)은 아직 없다.

**검증.** dial 전에 `JumpPlan::new`가 모양을 본다. hop이 4개를 넘거나, 같은 지문이 두 번 나오거나, 끝 target이 hop 목록에 있으면 `INVALID_ARGUMENT`이고 아무것도 dial하지 않는다. hop의 핀이 없거나 주소·지문이 비어 있으면 `HOST_NOT_FOUND`(stage `address`)다. client는 이름을 풀지 않고 핀의 주소를 그대로 다음 hop의 `StreamHeader{host, port}`에 싣는다.

**걷기.** 첫 hop은 보통 경로(펀칭 포함)로 잇고 지문이 핀과 같은지 한 번 더 본다. 다음 단계마다 (1) 앞 연결의 협상 결과에 `jump.v1`이 있는지 보고, (2) CSPRNG 16바이트 channel을 뽑아 `DatagramHub`에 등록한 뒤 `JUMP` 스트림을 열고, (3) `ConnectResult`를 기다리고, (4) `PacketPipe`의 `PipePeer`를 스트림·datagram 운반체에 이어 펌프를 띄우고, (5) `Dialer::with_evaluator`로 그 hop의 정확한 지문만 믿는 평가기를 만들어 `dial_over_pipe`로 안쪽 연결을 맺는다. 마지막 연결이 끝 연결이고 일반 연결처럼 돌려준다(결정 15). 직접 dial과 경주하지 않고 자동 폴백도 없다(결정 13).

**운반체.** client→J 방향은 `choose_carrier`가 정한다. 양쪽이 `datagram.v1`을 광고하고 바깥 연결의 `max_datagram_size()`가 1217 이상이면 datagram, 아니면 스트림이다. 250 ms마다 방을 다시 읽어 바꾼다. 안쪽 packet 상한은 `PipePeer::set_packet_limit`로 (바깥 방 - 17)에 맞춘다(ADR-0057: 한 겹 55바이트). 상한보다 큰 안쪽 packet은 버리고 센다. 침묵 규칙(`SilenceFallback`)은 datagram으로 보낸 뒤 `4 × max(rtt, 50 ms) + 25 ms`(ADR-0058, §21.8) 동안 되돌아오는 datagram이 없으면 스트림으로 내리고(받은 datagram 뒤 첫 송신은 대개 그 datagram에 대한 ack-only 응답이라 되돌아오는 것이 없으므로 시계를 시작하지 않는다. ADR-0058 결정 1 개정, `jump_silence_ignores_an_unanswered_ack_across_an_idle_gap`), 30초마다 datagram을 다시 시도한다. 같은 헬퍼를 중간 peer의 J→client 방향도 쓴다.

**감독.** 층마다 펌프가 하나다. 한 층이 죽으면 끝 연결을 닫고, 끝 연결이 닫히면 안쪽 층부터 정리한다(결정 16). 비정상 종료는 스트림을 `0x2007`로 reset한다. `ChainInfo`가 채널별 계수(보낸·받은 datagram과 스트림 packet 수, 버린 수, 전환 수, 침묵 폴백 수)를 낸다.

**실패 보고.** `JumpFailure{hop, hops, name, stage}`가 `details.jump`와 사람용 접두사 `jump 2/3 (b): `를 만든다. `hop`은 세우던 연결의 1-기준 순번(끝 target은 `hops`)이고 `name`은 그 단계의 핀 이름이다. 그래서 첫 hop이 두 번째 hop을 열어 주지 않으면 hop 2로 보고한다. stage와 코드:

| stage | 코드 |
|---|---|
| `address` | `HOST_NOT_FOUND` |
| `dial` | 보통 경로가 낸 코드 그대로 |
| `unsupported` | `UNSUPPORTED` |
| `denied` | `PERMISSION_DENIED` |
| `resolve` | `CONNECTION_FAILED` |
| `limit` | `RESOURCE_EXHAUSTED` |
| `unreachable` | `CONNECTION_FAILED` |
| `handshake` | `TIMEOUT` |
| `auth` | `AUTH_FAILED` |

안쪽 dial에서 핀 불일치로 거절되면 `auth`다. 시한 초과와 그 밖의 안쪽 dial 실패는 `handshake`로 묶고, 펌프가 먼저 끝났으면 `unreachable`이다. 끝 target이 거부해도 접속 중간에 새 세션이나 exec는 만들어지지 않는다. Ops의 jump는 정방향 route만 쓰고 ssh 되살리기는 끈다.

**시험.** `crates/qsh-testkit/tests/it/jump_chain.rs`: `jump_one_hop_runs_every_feature`, `jump_two_hops_runs_session_exec_and_cp`, `a_malformed_chain_is_invalid_argument_and_dials_nothing`, `a_hop_without_a_pin_or_an_address_is_host_not_found_naming_it`, `jump_pin_mismatch_at_the_first_hop`, `jump_pin_mismatch_at_a_hop_and_at_the_end`, `a_jump_redirect_to_another_pinned_peer_fails_with_auth_failed`, `jump_carrier_selection_table`, `jump_mtu_budget_table`, `the_carrier_follows_the_outer_room_and_datagram_v1`, `jump_mtu_budget_on_a_four_hop_chain`, `jump_failure_stage_table`, `jump_failure_dial_stage_keeps_the_routes_code`, `jump_target_refusal_is_reported_fast`, `a_jump_never_sees_inner_plaintext`, `a_plan_refuses_the_shapes_decision_11_names`. 단위 시험은 `jump/carrier.rs`(침묵 규칙), `jump/report.rs`(stage 표)다. 침묵 폴백의 live 시험(kind 14 blackhole)과 netsim 손실 시험은 수용 시험 스텝이 맡는다.

### 21.6 recovery, migration, `--supervise` (ADR-0056 결정 16)

체인은 하나의 단위다. 끝 연결이 죽는 이유가 어느 층이든 복구는 같은 길이다.

**Tier 1(migration).** `Endpoint::rebinding_via`가 안쪽 연결의 endpoint에 "바깥 endpoint를 옮긴다"를 건다. `dial_chain`이 층마다 아래 층의 endpoint를 거는 터라, 끝 endpoint의 `rebind_ephemeral`은 층을 타고 내려가 첫 hop의 UDP 소켓을 새 포트로 옮긴다. 안쪽 연결과 `JUMP` 채널은 그대로고 J의 소켓도 그대로여서 T는 아무것도 보지 않는다. recovery의 migration 시도와 `--supervise`의 `try_migrate`가 부르는 것이 이 함수다. 파이프 위의 endpoint는 자기 소켓이 없으므로, 바깥을 걸지 않은 파이프 endpoint의 rebind는 `Unsupported`다. 그렇지 않으면 진짜 소켓이 파이프 밑에 깔려 안쪽 연결이 채널에서 떨어진다.

**Tier 2(resume).** 끝 연결의 PathWatch가 사망을 선언하고 migration이 연결을 살리지 못하면, 재dial은 `dial_routed`의 `Dial::Redial`로 체인을 처음부터 다시 세운다. 첫 hop의 route는 펀칭 경주까지 다시 돌고, 재dial 시도 하나의 시한은 첫 hop의 시한에 중간 peer마다 1초를 더한 값이며 명령의 dial 시한을 넘지 않는다(`PeerTarget::redial_deadline`). 새 끝 연결에서 §10의 reattach를 하므로 PTY 입력은 무손실·무중복이다. 대화형 attach의 recovery와 `--supervise` 터널(`-L`·`-R`·`-D`)이 같은 `dial_routed`를 쓴다. 안쪽 연결을 새 바깥 연결 위에 이어 붙이는 일은 하지 않는다.

**옛 체인은 남지 않는다.** `Link::replace`가 옛 끝 연결이 체인 위의 것이면(`Endpoint::is_nested`) 닫는다. 끝 연결이 닫히면 감독 task가 안쪽 층부터 정리하고 J의 채널이 닫힌다. 직접 연결에서 옛 연결을 살려 두는 `--supervise`의 규칙(스플라이스가 끝날 때까지)은 체인에는 적용하지 않는다. 시한이 다 돼 걷는 도중에 버려진 `dial_chain` 호출도 이미 세운 층을 `LayerGuard`가 정리한다.

**닫힘 대기의 상한.** 끝 연결을 닫은 호출자는 `Endpoint::wait_idle`로 닫는 절차(closing period, PTO의 세 배)가 끝나길 기다린다. 파이프 위의 endpoint는 체인이 정리되면 파이프가 닫히고, 그러면 quinn의 endpoint task도 소켓과 함께 끝나서 닫히던 연결이 drained로 보고되는 일이 없다. 경로가 막 끊겼다 살아난 연결은 PTO가 커서 이 경쟁에 질 수 있고, 그때 `--supervise` 터널의 `hold.close()`가 영원히 돌아오지 않았다(부하 아래 15회에 한 번). 그래서 파이프 위의 endpoint는 `NESTED_IDLE_CAP`(3초)까지만 기다리고, 감독 task는 그보다 짧은 `END_DRAIN`(2초) 동안 층을 살려 두어 closing 프레임이 먼저 나가게 한다.

**ssh 되살리기는 jump 대상에 하지 않는다.** `Ops::revive_target`은 `jump`가 있는 대상에 `None`을 낸다. 되살린 serve의 주소는 체인이 쓰던 주소를 바꾸지 못하고, 체인 없는 `PeerTarget`을 내면 jump host가 바깥에서 직접 닿는 길로 새기 때문이다.

**시험.** `crates/qsh-testkit/tests/it/jump_recovery.rs`: `a_session_through_a_jump_resumes_after_the_hop_link_dies`(C-J를 chaos proxy로 5초 끊음), `a_session_through_a_jump_resumes_after_the_target_link_dies`(J-T를 끊음), `outer_migration_is_invisible_to_the_inner_connection`, `a_nested_endpoint_never_binds_a_socket_of_its_own`, `a_supervised_tunnel_through_a_chain_survives_a_cut`, `a_supervised_tunnel_through_a_chain_survives_a_cut_behind_the_hop`, `a_supervised_tunnel_migrates_at_the_first_hop_and_keeps_its_chain`.

### 21.7 역방향 첫 hop: 데몬의 운반체 번역 (ADR-0056 결정 14)

첫 hop이 이 장비의 `qsh listen` 데몬에 live 역방향 등록(`qsh serve --to`)을 들고 있으면 CLI는 그 hop에 QUIC 연결이 없다. 연결은 데몬이 쥐고 있다. 그래서 첫 `JUMP` 채널만 `LOCAL_STREAM` conduit으로 열고, 둘째 hop부터는 §21.5의 걷기가 그대로다. 새 `LocalStreamKind`는 없다(§11-3).

```
CLI ==LOCAL_STREAM (u16 길이 frame)== 데몬 ==등록 연결 (datagram | JUMP 스트림)== 첫 hop(J) --UDP-- 다음 hop
```

**CLI가 하는 일.** `Ops::resolve_route`가 첫 hop의 이름으로 live 역방향 등록을 찾으면(`Ops::reverse_first_hop`, 평소 라우팅과 같은 규칙) 계획의 `first_reverse`에 데몬 소켓과 이름을 적는다. 그 hop의 pin은 주소가 없어도 되고 펀칭 계획은 세우지 않는다. `dial_chain_via_daemon`이 (1) `LocalHello` 뒤의 `LocalHelloAck.peer_fingerprint`가 첫 hop pin의 지문과 같은지 **헤더를 보내기 전에** 본다(`open_stream_expecting`, `generation`은 보지 않는다). 다르면 stage `auth`이고 데몬도 J도 아무것도 열지 않는다. (2) `StreamHeader{JUMP, channel, host, port}`를 보낸다. `host:port`는 둘째 hop(없으면 끝단)의 pin 주소다. (3) 데몬의 `ConnectResult`를 읽고(아래), (4) 이 conduit을 채널의 스트림 운반체로 삼아 §21.5와 같은 펌프를 띄운다. CLI 구간에는 datagram이 없다(`both_datagram = false`). 안쪽 endpoint는 바깥 소켓이 없으므로 첫 hop의 migration(Tier 1)은 해당이 없고 `rebinding_via`를 걸지 않는다. recovery(Tier 2)와 `--supervise`는 같은 `dial_jump`가 데몬 길을 다시 걷는다.

**데몬이 하는 일.** `serve_jump`(`localctl/daemon.rs`)는 raw 단계로 넘어가 `ConnectResult` 정확히 하나를 먼저 쓴다. 순서는 이렇다. 앞 단계가 실패하면 뒤 단계는 돌지 않고, 등록 연결에는 아무것도 열리지 않는다.

1. `jump_channel`이 정확히 16바이트이고 header가 `DATA_FRAME_MAX` 이하인지 본다. 아니면 `INVALID_ARGUMENT`.
2. 등록한 host의 capability에 `jump.v1`이 있는지 본다. 없으면 `UNSUPPORTED`.
3. hub마다 `JumpSlot`을 잡는다(`ControlHub::claim_jump`). 이미 이 hub에 있는 channel 값이면 `INVALID_ARGUMENT`, hub가 `MAX_JUMP_CHANNELS_PER_HUB`(32)개를 쥐고 있으면 `RESOURCE_EXHAUSTED`. 값 점유가 먼저고 상한이 나중이다(J의 모양 검사와 같은 순서). 슬롯은 relay가 끝날 때 풀린다.
4. 등록 연결의 `DatagramHub`에 channel을 등록한 뒤 `open_bi`(`OPEN_DATA_STREAM_TIMEOUT` 10초)로 `JUMP` 스트림을 연다(session band). 열리지 않으면 `CONNECTION_FAILED`.
5. header를 **받은 바이트 그대로** 보내고 J의 `ConnectResult`를 `JUMP_OPEN_TIMEOUT`(12초) 안에 기다린다. 그동안 CLI가 끊으면 스트림을 `0x2007`로 reset하고 끝낸다. 시한이 지나거나 J가 답 없이 닫으면 `CONNECTION_FAILED`.
6. `ConnectResult`를 CLI에 그대로 건넨다. `ok`가 아니면(J의 `PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`, `CONNECTION_FAILED`) 송신을 `finish()`하고 CLI conduit을 닫는다. CLI는 §21.5의 `refusal`로 stage를 정한다. 데몬 자신의 거절도 같은 모양(`ok = false`와 `code`)이라 CLI는 둘을 가르지 않는다.
7. `ok`면 `jump::relay::run`이 패킷을 옮긴다.

**인가는 데몬의 일이 아니다.** `forward.jump`는 등록한 host(J)가 스트림을 받는 자리에서 판정한다(§21.3, 결정 7). 주체는 데몬의 신원(listen 쪽 신원)이다. 데몬은 가시성과 자원만 쥔다: "등록은 도달 가능성을 주지, 권한을 주지 않는다"(§11-3).

**번역.** `run`은 채널마다 한 task다.

- CLI → host: CLI 구간의 `u16` 길이 frame을 `JumpStreamDecoder`로 읽는다. 패킷마다 `choose_carrier(both_datagram, 등록 연결의 max_datagram_size())`와 `SilenceFallback`(데몬 쪽 눈, srtt는 등록 연결의 것)이 고른다. datagram이면 종류 14 frame이고, 자리를 넘으면 스트림으로 돌리지 않고 버리고 센다. 스트림이면 `encode_packet`으로 `JUMP` 스트림의 큐(`JUMP_STREAM_QUEUE` 64 KiB)에 넣고 넘치면 버리고 센다. `both_datagram`은 등록한 host의 capability에 `datagram.v1`이 있는지다(데몬은 늘 광고한다).
- host → CLI: 종류 14 datagram과 `JUMP` 스트림의 frame을 모두 받는다. 둘 다 CLI 구간에 `u16` 길이 frame으로 쓴다. CLI 구간의 쓰기 큐도 64 KiB이고 넘으면 버리고 센다.
- 데몬이 읽는 것은 길이 머리뿐이다. 패킷은 해석하지도 복호화하지도 않는다. 길이 0이나 1452 초과는 어느 쪽에서 오든 `BAD_HEADER`(`0x2001`)다: 등록 연결 쪽 스트림은 그 코드로 reset하고, CLI conduit은 닫는다.

**끝.** CLI conduit이 닫히면(프로세스 종료 포함) 송신을 `finish()`하고 수신을 `stop`한다. J는 스트림 종료로 채널과 소켓을 닫고(`stream_end`) 데몬은 슬롯과 datagram 등록을 푼다. host 쪽 스트림이 끝나거나 reset되면 CLI conduit을 half-close하고 CLI의 펌프는 `StreamEnded`로 끝난다. 등록 연결이 닫히면 같은 길이다. 데몬에는 자기 idle 시한이 없다. 60초 idle은 J가 닫고(`JUMP_IDLE`) 그 reset이 데몬을 끝낸다.

**관측.** `ControlHub::jump_stats()`(`RelayStats`)는 개수만 쥔다: `opened`, `closed`, `to_host_datagrams`, `to_host_stream`, `from_host_datagrams`, `from_host_stream`, `to_cli`, `oversize_dropped`, `queue_dropped`, `datagram_unavailable`, `silence_fallbacks`. `ControlHub::jump_channels_in_use()`는 지금 쥔 슬롯이다. 로그는 target `qsh::jump`의 `channel_opened`·`channel_closed`(`side = "daemon"`, 사유 `cli_gone`·`host_ended`·`connection_closed`·`bad_frame_cli`·`bad_frame_host`)이고 기본에서 꺼져 있다. channel 값과 패킷은 싣지 않는다.

**시험.** `crates/qsh-testkit/tests/it/jump_reverse.rs`: `jump_first_hop_over_the_reverse_route`(진짜 daemon·`serve --to`·loopback T에서 exec, 세션, `-L`이 끝나고 등록 연결 구간이 양방향 datagram 운반체를 쓴 것을 데몬과 J의 카운터로 확인), `a_reverse_first_hop_with_another_fingerprint_opens_nothing`, `the_daemon_claims_a_jump_channel_once_and_refuses_a_malformed_one`, `the_daemon_carries_at_most_32_jump_channels_per_registered_host`, `a_bad_frame_from_the_cli_ends_the_channel_and_frees_its_slot`, `the_daemon_cleans_up_when_the_cli_goes_away`, `a_refusal_of_the_host_reaches_the_cli_verbatim_and_frees_the_slot`, `a_registered_host_without_jump_v1_gets_no_jump_stream`. 펀칭한 첫 hop은 `crates/qsh-testkit/tests/it/jump_punch.rs`의 `jump_first_hop_over_a_punched_connection`(netsim)이다.

### 21.8 MTU 예산과 침묵 시한 (ADR-0057, ADR-0058)

**MTU 예산(ADR-0057).** 바깥 연결의 `max_datagram_size()`는 MTU에서 38바이트를 뺀 값이다(1-RTT 머리 예측 29, DATAGRAM frame 머리 상한 9). 그래서 한 겹 비용은 jump 머리 17에 38을 더한 55바이트다. 구현은 이 값을 굳히지 않고 실행 중 `max_datagram_size()`를 읽으며, 55는 표와 시험의 기대값이다. 링크별 안쪽 패킷 상한은 `jump_mtu_budget_table`이 고정한다.

| 링크 | 바깥 UDP payload | hop 하나 | 둘 | 셋 | 넷 | 운반체 |
|---|---|---|---|---|---|---|
| 1500 (IPv4) | 1472, PLPMTUD 상한 1452 | 1397 | 1342 | 1287 | 1232 | 넷 모두 datagram |
| 1280 (IPv4) | 1252 | 스트림 | 스트림 | 스트림 | 스트림 | 첫 hop부터 스트림(`max_datagram_size()` 1214 < 1217) |
| 1280 (IPv6 최소 MTU) | 1232 | 스트림 | 스트림 | 스트림 | 스트림 | 첫 hop부터 스트림(1194 < 1217) |

둘째 hop부터는 앞 hop의 안쪽 연결이 다음 hop의 바깥 연결이 되므로 hop마다 55씩 준다. 1500 링크의 넷째 hop 상한 1232가 `JUMP_PACKET_MIN`(1200) 위이므로 hop 상한은 넷이다(여유 32바이트). 운반체는 hop마다 그 hop을 나르는 바깥 연결의 `max_datagram_size()`로 고르고, 스트림 운반체는 안쪽 패킷 크기를 줄이지 않으므로 첫 hop이 스트림이어도 둘째 hop부터는 datagram이 될 수 있다. 바깥 PLPMTUD가 자리를 연 뒤에는 스트림에서 datagram으로 바뀐다(`jump_carrier_switches_to_datagram_after_pmtud`).

**침묵 전환 시한(ADR-0058).** datagram으로 보낸 뒤 그 채널로 datagram이 한 번도 돌아오지 않는데 스트림과 바깥 ack는 살아 있으면 스트림으로 바꾼다. 시한은 `silence = 4 × max(rtt, 50 ms) + 25 ms`다(`RTT_FLOOR` 50 ms는 ADR-0052 구현과 같고 25 ms는 QUIC 기본 `max_ack_delay`다). `rtt`는 client(C에서 다음 hop 방향)가 그 채널 위에서 맺은 안쪽 연결의 srtt(끝에서 끝 왕복, handshake 전에는 바깥 srtt)이고, 중간 peer(T에서 C 방향)와 역방향 데몬은 바깥 연결의 srtt다. 30초 뒤 datagram을 다시 시험하는 것과 자리를 넘는 패킷을 버리고 세는 것은 그대로다. 시한 계산은 `jump_silence_window_table`이 고정하고, 건강한 경로에서 전환 0번은 `jump_tunnel_throughput`이, 진짜 침묵에서의 전환은 `jump_silence_on_the_datagram_path_falls_back_to_the_stream`이 본다.

## 22. iroh relay route (ADR-0061, M28)

> 이 절은 M28이 착지한 동작을 적는다. 값은 `[iroh]` 설정(`docs/CLI.md` §6.12, §6.23)이 정한다: 기본 relay URL은 `https://aps1-1.relay.n0.iroh.link`, `head_start_ms`는 1000, 대기 시한은 명령의 dial 시한(10초)이다. 구현이 이 절과 다르면 이 절을 먼저 고친다.

### 22.1 route 순서

pin(`trust.toml`)의 선택 필드 `routes`에 `iroh` 종류가 생긴다(`docs/CLI.md` §6.1, §6.11).

- 기본 route 목록은 바뀌지 않는다. `iroh`가 목록에 없는 설정은 relay에 한 번도 접속하지 않고 iroh endpoint도 만들지 않는다.
- 사용자가 `iroh`를 목록에 넣으면 **직결(주소, DNS 이름)과 펀칭(§19)이 먼저** 출발한다. 직결과 펀칭의 경주(ADR-0054 결정 16)는 그대로이고, 그 경주가 `[iroh].head_start_ms`(기본 1초) 안에 서지 않거나 그 전에 모두 바로 실패하면 iroh 시도를 나란히 시작해 먼저 선 연결을 쓴다. 진 쪽은 닫는다. UDP가 막힌 망에서는 직결이 dial 시한을 다 써야 실패하므로, 경주가 끝나기를 기다리면 iroh에 남는 시간이 없다. 그 안에 직결이나 펀칭이 서면 relay에 아무것도 보내지 않는다.
- **route 기억.** pin마다 마지막으로 이긴 route와 실패한 route를 state의 `route-cache.json`에 둔다. iroh가 이기고 직결·펀칭이 시한까지 못 선 pin은 다음 dial에서 iroh를 곧바로 시작하고 직결·펀칭을 건너뛴다. 건너뛴 route는 10분 뒤(연속 실패마다 두 배, 상한 1시간) iroh와 나란히 한 번 다시 시도한다. 로컬 주소 집합이나 기본 경로가 바뀌면 기억을 버린다. 막힌 망에서 dial과 재dial이 같은 route를 연달아 두드리지 않게 하려는 것이다(`docs/CLI.md` §6.1).
- 새로 도는 route는 §19.10과 같은 규칙으로 **재해석**된다. recovery나 `--supervise`의 재dial은 처음 선 route를 고집하지 않고 route를 다시 돈다. relay로 선 연결도 직결이 돌아와 있으면 다음 재dial에서 직결로 선다.
- 주소도 중개자 후보도 없는 pin에 `routes = ["iroh"]`와 `key`가 있으면 직결·펀칭이 없으므로 head start 없이 곧바로 iroh로 dial한다.
- 이름 없는 대상(주소만 있는 대상)에는 iroh route가 없다. EndpointId를 아는 pin(이름)만 iroh로 dial한다. pin에 `routes = ["iroh"]`가 있어도 `key`가 없으면 iroh는 건너뛴다(`key`는 직결·펀칭·페어링·`trust add --cert-file`·SSH 확인 dial이 채우거나 `qsh trust iroh --key`로 적는다).
- iroh 시도도 명령의 dial 시한(10초)을 늘리지 않는다. 남은 시한으로 잘린다.

### 22.2 relay 경로

- relay 접속은 HTTPS 위 WebSocket(`/relay`)이다. relay URL은 pin(`trust.toml`)의 선택 필드이고, 없으면 설정의 기본 relay URL이다. 양 끝이 같은 기본값을 쓰면 pin에 URL을 적지 않아도 닿는다.
- endpoint는 **설정된 relay URL 하나에 고정**으로 붙는다. 발견(pkarr, n0 DNS)으로 home relay를 고르지 않고 게시도 조회도 하지 않는다. 상대가 다른 relay에 붙어 있으면 pin에 적힌 URL이 그 relay다.
- relay TLS는 OS 인증서 저장소로 검증한다(`platform-verifier`, `CaTlsConfig::system()`). qsh의 다른 곳에서 web PKI를 쓰지 않는다는 규칙(§3)과 충돌하지 않는다: 이 검증은 relay 서버 인증서에만 쓰이고 qsh 신원은 건드리지 않는다.
- relay는 안쪽 QUIC 패킷을 나르는 중계자다. 내용도 신원도 relay가 아니라 **안쪽 QUIC의 pin 인증**이 세운다. relay가 가짜이거나 망이 TLS를 가로채도 pin이 맞는 상대를 만들어 낼 수 없다(threat-model D28·D29).
- HTTP 프록시는 `[iroh].proxy`(기본 `env`, 환경 변수를 따름)로 정한다(`docs/CLI.md` §6.23).

### 22.3 신원과 handshake

- iroh route에서 서버(데몬)의 식별자는 EndpointId, 곧 qsh 신원 키의 Ed25519 공개키다. qsh fingerprint(SPKI SHA-256)는 같은 키에서 계산한다. 클라이언트의 EndpointId는 endpoint마다 새로 뽑는 임의 키이고, 클라이언트의 qsh 신원은 연결 안에서 증명한다(§22.8).
- **검증은 handshake 직후에** 한다. 클라이언트는 서버의 pin 대조와 ADR-0060의 이름 결속(이름으로 dial했다면 그 이름의 pin 키와 같은 EndpointId여야 함)을 거치고, 서버는 §22.8의 증명으로 클라이언트를 판정한다. 서버가 거절하면 클라이언트는 `AUTH_FAILED`(`details.category: "remote_rejected"`)로 끝난다. 이 판정 전에는 `Hello`도, 어떤 스트림도, 세션·터널·listener도 없다.
- 사설 CA 모드(체인, SAN principal)는 iroh route에서 `UNSUPPORTED`다. jump 체인의 어느 hop도 iroh route로 열지 않는다(`UNSUPPORTED`, ADR-0061 결정 14).
- 페어링의 TLS exporter 채널 바인딩(§15.3)은 iroh 연결의 `export_keying_material`로 같은 방식으로 할 수 있다. 다만 클라이언트가 iroh route로 페어링하는 경로는 만들지 않았다(미결 1).

### 22.4 직접 경로로의 승격

iroh는 한 연결 안에서 relay 경로와 직접 경로를 함께 다룬다(multipath). relay로 선 연결은 홀펀칭이 성공하면 **같은 연결 안에서** 직접 경로로 승격되고, 연결이 끊기거나 새로 서지 않는다. 그래서:

- qsh 계층에서는 연결 하나가 그대로다. 세션, 스트림, resume token에 변화가 없다. 경로 변화는 migration과 같은 급의 지연 최적화이고 correctness는 §10의 resume이 지킨다.
- 승격 뒤 pin된 상대는 내 IP를 안다(threat-model D30). 승격 전에는 relay가 본다.
- §19의 qsh 자체 펀칭(`punch.v1`)과 별개다. iroh route 위에서는 `punch.v1`을 쓰지 않는다(경로 승격은 iroh의 몫).
- 경로 정보(어느 경로로 가고 있는가, rtt)는 `PathWatch`와 상태 줄, 감사의 선택 필드로 읽기 전용으로 올라간다. 정책은 정하지 않는다.
- `LinkStatus`와 침묵 판정(§18.12, §21.8)은 경로가 바뀌어도 한 연결의 값으로 계속 돈다. relay 경유로 RTT가 늘어난 연결이 직결 기준 시한에 걸리지 않는지는 구현에서 시험으로 확인한다(미결 2).

### 22.5 wire에서 그대로인 것

- ALPN `qsh/1`, frame layer(§5), `.proto` 계약(§9), 스트림 배치(§7), `Hello`·capability 협상(§4)은 바뀌지 않는다. iroh 연결의 안쪽 QUIC도 같은 ALPN과 같은 메시지를 쓴다. 새 capability는 만들지 않는다(additive 변경 없음).
- **resume은 SPKI + token 기준**이다(§10). 세션은 route가 아니라 peer 신원(SPKI SHA-256)에 묶여 있으므로 직결로 만든 세션을 relay로 이어 붙일 수 있고 그 반대도 된다. reattach 4단계, 입력의 무손실·무중복(§10-5)도 같다.
- 0-RTT 금지(§2)는 iroh 연결에도 같다. 활성화 옵션이 있어도 켜지 않는다.
- datagram(§14)은 iroh backend도 제공한다. 못 쓰면 스트림 짝으로 돌아가는 기존 규칙(`DatagramError`)을 따른다.
- 역방향(§11): `qsh serve --to`의 등록 dial이 iroh route로 컨트롤러에 닿을 수 있고, 컨트롤러(`listen`, 합친 endpoint 포함)가 iroh endpoint로 받는다. 등록 연결의 watchdog과 heartbeat(ADR-0053 개정, ADR-0041)는 그대로다. 역방향 admission은 handshake 뒤 키 기준으로 판정한다.

### 22.6 시험

이름과 계층은 `testing.md`의 「iroh relay route와 backend 경계」 절에 있다. 핀 테스트 인덱스는 `threat-model.md` §4(A27·A28·B54·D28~D31·G15)가 canonical이다.

### 22.7 미결

1. 페어링(§15)을 iroh route 위에서 허용할지. 구현하지 않았다: `pair accept`는 초대에 든 주소로 직결 dial하는 경로만 가진다. 허용하려면 invite에 EndpointId 안내가 필요하다.
2. 실제 망에서 relay 경유 RTT에 `LinkStatus`·침묵 시한의 기본값이 충분한지. 이 항목을 겨냥한 시험은 없고 TITAN 같은 실제 망 측정은 릴리스 전 항목으로 남아 있다.

### 22.8 클라이언트 신원 증명

relay는 EndpointId 하나에 홈 연결 하나만 둔다. 한 기기의 qsh 프로세스가 모두 기기 신원 키로 endpoint를 열면 같은 EndpointId가 겹치고, 나중에 붙은 프로세스가 먼저 붙은 프로세스의 relay 경로를 밀어낸다(relay 로그: "Another endpoint connected with the same endpoint id"). 장기로 도는 `qsh tunnel open`과 대화형 `qsh exec`를 함께 쓰면 앞의 것이 끊긴다. 그래서 endpoint의 두 역할이 키를 달리 쓴다.

- **데몬 endpoint**(`serve`·`listen`이 띄우는 수신 endpoint): 기기 신원 키로 연다. EndpointId가 pin 키이고 상대가 dial하는 값이다. 바뀐 것이 없다.
- **클라이언트 endpoint**(route 층이 명령마다, 재dial마다 만드는 endpoint): endpoint마다 새 임의 iroh 키로 연다. 같은 기기의 클라이언트 프로세스끼리 EndpointId가 겹치지 않는다. qsh 신원은 아래 증명으로 서버에 알린다.

ALPN(`qsh/1`), frame layer, `Hello`·capability 협상은 그대로다(새 capability 없음). QUIC route는 건드리지 않는다. 이 절은 iroh route 안의 연결 직후 한 번만 있는 교환이다.

**교환.** handshake가 끝나고 클라이언트가 서버를 pin으로 확인한 직후, **다른 어떤 스트림보다 먼저** 클라이언트가 단방향 스트림 하나를 열어 증명 프레임을 쓰고 `finish`한다. 클라이언트는 답을 기다리지 않는다(왕복을 더하지 않는다). 서버는 handshake 직후 이 스트림을 받아 읽고, 검증이 끝나기 전에는 어떤 양방향 스트림도 받지 않는다. 거절은 연결 close로 온다.

**프레임.** 97바이트 고정.

| 오프셋 | 길이 | 내용 |
|---|---|---|
| 0 | 1 | 버전, `1` |
| 1 | 32 | 클라이언트의 qsh 신원 Ed25519 공개키 |
| 33 | 64 | Ed25519 서명 |

서명 대상은 다음을 이어 붙인 바이트열이다.

```
"qsh iroh client identity v1"        (도메인 문자열, 27바이트, ASCII)
|| exporter                          (32바이트)
|| server_endpoint_id                (32바이트, 서버 EndpointId)
|| client_endpoint_id                (32바이트, 클라이언트의 임의 EndpointId)
```

`exporter`는 이 iroh 연결의 TLS exporter(RFC 5705)다. 라벨은 `"qsh iroh client identity exporter v1"`, context는 빈 값, 출력은 32바이트. 서명 검증은 엄격 검증(`verify_strict`)이다.

**서버의 검증.** 서버는 자기 EndpointId, 연결의 상대 EndpointId(handshake가 증명한 값), 연결의 exporter로 같은 바이트열을 만들어 프레임의 공개키로 서명을 검증한다. 통과하면 그 공개키가 이 연결의 **상대 신원**이다. fingerprint(SPKI SHA-256)를 이 키에서 계산하고, 이후 pin·role·ACL·감사·admission의 키 기준 버킷·resume 결속(§10)·`Connection::reverify`는 모두 EndpointId가 아니라 이 증명된 키를 쓴다. pin 판정은 §22.3과 같은 함수다(pin이면 `Principal`, 아니면 열린 페어링 창이 있을 때 `Pairing`, 아니면 거절).

**거절.** 다음은 모두 같은 결과다: 연결을 `CLOSE_CODE_UNVERIFIED_PEER`(0x1001)로 닫고, 어떤 `Connection`도 application 계층에 올리지 않는다. 세션·터널·listener 등 자원은 만들어지지 않는다. 서버는 거절 사유를 상대에게 구별해 알리지 않는다(감사 category는 `untrusted`).

- 증명 스트림이 헤더 시한(`server::HEADER_TIMEOUT`, 10초) 안에 오지 않음
- 프레임 길이가 97이 아님(짧거나 97바이트를 넘음), 버전이 `1`이 아님
- 공개키가 올바른 Ed25519 점이 아님, 서명이 맞지 않음
- 서명이 이 연결의 exporter, 서버 EndpointId, 클라이언트 EndpointId 중 하나라도 다른 값에 대한 것임
- 증명된 키가 pin이 아니고 열린 페어링 창도 없음

**한계와 근거.**

- exporter가 서명에 들어 있으므로 다른 연결로 복사한 프레임은 그 연결의 exporter와 맞지 않아 거절된다(재전송 방지). 두 EndpointId가 들어 있어 같은 서버·같은 클라이언트 endpoint가 아닌 쌍에도 쓸 수 없다.
- 읽는 쪽은 최대 97바이트만 잡는다. 프레임이 더 길면 길이 초과로 거절하고 그 이상을 버퍼링하지 않는다.
- 서버는 상대의 EndpointId가 pin인지 따로 보지 않는다. 데몬이 기기 키로 dial하는 연결(`serve --to`의 등록 dial 포함)도 같은 프레임을 보내며, 이때 증명된 키는 EndpointId와 같다. 한 경로로 검증한다.
- 증명 읽기는 handshake permit을 쥔 채 일어나므로 시한까지의 점유는 handshake 동시 상한이 막는다(admission, ADR-0061 결정 4). 키 기준 버킷(`decide_keyed`)은 증명 뒤에 증명된 키로 센다.
- 증명 전에 클라이언트 쪽이 서버 신원을 먼저 확인하므로(dial 전 pin 검사, handshake 직후 재검사) 가짜 서버에 증명이 가지 않는다. 가더라도 증명은 그 연결에 묶여 있어 다른 연결에서는 쓸 수 없다.
- 클라이언트 endpoint는 끝날 때 연결의 close가 상대에게 갔는지만 짧게 기다린다(`wait_idle`·`wait_idle_for`가 상대의 `CONNECTION_CLOSE` 응답을 `IROH_CLOSE_FLUSH_CAP`(150ms)까지 기다린다. 보통 한 왕복). iroh의 `Endpoint::close`는 기다리지 않고 백그라운드로 시작한다. relay와 맺은 주소 발견(QAD) 연결의 close에 relay가 답하지 않아 endpoint가 그 연결의 closing 기간(PTO의 세 배)을 채워야 끝나고, loopback에서도 1초가 걸리기 때문이다(실제 relay에서는 최대 3초). 상대는 연결의 `CONNECTION_CLOSE`로 이미 close를 알았으므로 이 기다림은 명령 종료에 필요하지 않다. 백그라운드 닫기가 끝나기 전에 프로세스가 끝나면 iroh가 "Endpoint dropped without calling `Endpoint::close`" 오류를 로그에 남기므로, 닫는 중인 endpoint의 복제본을 프로세스 전역에 쥐어 두어 프로세스 종료가 endpoint를 drop하지 않게 한다. 마지막 핸들이 닫기 전에 사라지는 경로(오류, 진 route 경주, 취소)도 같은 백그라운드 닫기를 쓴다.

**시험.** `qsh-transport`의 `iroh_identity::` 모듈이 정한다: 같은 신원의 클라이언트 endpoint 둘이 relay에서 모두 살아 있음(`two_client_endpoints_of_one_identity_both_stay_connected`), 손으로 만든 정상 프레임을 받음(`a_hand_made_proof_is_accepted`), 서명 위조(`a_forged_signature_is_refused`), 다른 endpoint 쌍용 증명(`a_proof_made_for_another_endpoint_pair_is_refused`), pin이 아닌 증명 키(`a_proof_for_a_key_the_server_does_not_pin_is_refused`), 증명 없음(`a_missing_proof_times_out`), 길이·버전 오류(`malformed_frames_are_refused`), 다른 연결로 옮긴 증명(`a_proof_replayed_onto_another_connection_is_refused`), 정상 종료 시 오류 로그 없음(`a_short_client_command_ends_without_an_error_log`, `dropping_a_client_endpoint_closes_it_gracefully`), 짧은 명령의 close가 빠르고 서버가 idle timeout이 아니라 close로 연결의 끝을 앎(`a_short_command_over_a_relay_closes_fast_and_the_server_hears_it`, `a_short_command_over_a_direct_path_closes_fast_and_the_server_hears_it`).
