# ADR-0019: SOCKS `-D`를 구현한다. client가 SOCKS5를 번역해 CONNECT마다 기존 `TCP_CONNECT`로 싣고 host는 그 dial에서 host-local 주소를 거른다

날짜: 2026-09-19
상태: 승인됨

## 맥락

2026-09-17 초안은 `-D`를 v1 내내 P1로 두자고 제안했고 구현 결정이 답해야 할 미결 질문 아홉 개를 남겼다. 사용자가 2026-09-19에 구현하기로 결정했다. 이 판은 그 초안을 대체한다. 초안의 사실 목록은 대부분 유효해서 여기에 옮겨 쓰되 인용 위치를 갱신했다. 초안이 `crates/qsh-core/src/server/mod.rs`로 가리키던 `TCP_CONNECT` 인가·dial 경로는 이제 `crates/qsh-core/src/server/tunnels.rs`에 있다.

오늘의 `-D`는 이렇다. 두 spelling(대화형 `qsh host -D spec`, `qsh tunnel open host --dynamic spec`)이 파싱만 되고 `crates/qsh-cli/src/main.rs`의 두 호출 지점이 `Ops` 호출 전에 `dynamic_forward_unsupported()`로 거절한다. 거절 문면은 `crates/qsh-core/src/ops/tunnel.rs`의 `DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE`와 `DYNAMIC_FORWARD_UNSUPPORTED_GUIDANCE` 두 상수다. 앞의 것은 append-only fixture `crates/qsh-cli/tests/fixtures/cli-v1/error.UNSUPPORTED.json`이 봉투째 고정하고 뒤의 것은 `crates/qsh-core/tests/tunnel_docs.rs`가 README와 `docs/CLI.md` §6.9의 축자 인용으로 고정한다.

설계를 가르는 사실은 다음과 같다.

- ACL은 목적지를 보지 않는다. `acl.toml`의 한 행(`Rule`)은 principal·auth_path·allow·scope만 갖고 `Policy::decide`는 자원에서 `owner`만 본다(`crates/qsh-core/src/acl/policy.rs`). `TCP_CONNECT`의 자원 문자열 `host:port`는 audit 필드이자 quota 키일 뿐 판정 기준이 아니다(`crates/qsh-core/src/server/tunnels.rs`의 `authorize_and_dial_tunnel`). 그래서 `forward.local`을 가진 principal은 이미 오늘 host가 닿는 모든 `host:port`로 나갈 수 있다. `-L`을 목적지마다 하나씩 열면 된다.
- host는 `TCP_CONNECT`가 어디서 왔는지 구별하지 못한다. `StreamHeader`는 `kind`·`ticket`·`host`·`port`뿐이고(`crates/qsh-proto/proto/qsh/wire/v1.proto`) `handle_data_stream`의 `TcpConnect` 분기에는 판별자도 역방향 특례도 없다.
- 역방향 target도 같은 `Server::serve_control`을 돌린다(`crates/qsh-core/src/reverse/target.rs`). 역방향 위의 `TCP_CONNECT`도 target 자신의 `acl.toml`에서 `forward.local`로 판정된다.
- 이름 해석은 host 쪽에서 일어난다. `crates/qsh-core/src/tunnel/dial.rs`의 `dial_unbounded`가 `lookup_host` 결과 주소를 차례로 연결한다. SOCKS5의 원격 DNS 의미론이 이미 wire에 있는 셈이고 주소를 거르는 단계는 없다.
- `forward.socks`는 Action 어휘에 있지만 `Action::is_always_denied`가 규칙 평가 전에 막는다(`crates/qsh-core/src/acl/mod.rs`, 평가 순서 1번은 `crates/qsh-core/src/acl/policy.rs` 모듈 doc). 구동하는 wire op은 0건이고 `ALWAYS_DENIED_NO_OP`이 그 사유를 적는다(`crates/qsh-core/src/acl/registry.rs`). `acl.toml` loader는 모르는 action 토큰이 있으면 파일 전체를 `CONFIG_ERROR`로 만든다(`crates/qsh-core/src/acl/load.rs`).
- JSON 계약에서 `Tunnel.forward_to`와 `TunnelOpenReq.forward_host`/`forward_port`는 "dial 대상"을 뜻하는 필수 필드다(`crates/qsh-proto/src/types/tunnel.rs`). `Option`으로 바꾸면 type 변경이고 빈 값을 "SOCKS라 없음"으로 읽게 하면 의미 변경이다. 둘 다 `docs/CLI.md` §10이 `/v2`를 요구한다. 열린 문자열인 `Tunnel.mode`만 새 값을 받을 수 있다.
- wire freeze(`docs/design/protocol.md` §16)는 아직 "초안 — 발효 전"이다. §16.4의 additive 목록에는 동결된 enum에 새 값을 더하는 항목이 없다. 모르는 `StreamKind`는 `stream_kind()`가 `None`을 돌려주고 `RESET_CODE_BAD_HEADER`로 reset된다. 새 capability 문자열은 §16.4가 허용한다.
- client 쪽 `-L`은 loopback에만 bind한다(`crates/qsh-core/src/tunnel/local.rs`의 `loopback_bind_addr`). accept 루프는 상한 없는 `JoinSet`에 연결을 넣는다. `forward_connection(tcp, carrier, host, port)`는 목적지를 매개변수로 받을 뿐이라 목적지가 어디서 왔는지 모르고 `ForwardCarrier`가 정방향(QUIC)과 역방향(daemon의 `LOCAL_STREAM`)을 이미 추상화한다.

SOCKS는 실제로 wire가 아니라 목적지를 고르는 주체를 바꾼다. `-L`은 운영자가 명령줄에 목적지를 하나 적는다. `-D`는 loopback 포트에 붙은 것이 목적지를 고른다. 거기에는 같은 머신의 다른 uid가 있고 무엇보다 프록시를 통해 브라우징하는 웹 페이지가 있다. 원격 DNS와 TTL 0 재바인딩을 쓰면 페이지가 자기 origin을 유지한 채 host의 loopback 서비스나 클라우드 metadata 주소(`169.254.169.254`)를 읽을 수 있다. 브라우저의 사설망 보호는 브라우저가 해석한 주소를 기준으로 하는데, 원격 DNS에서는 브라우저가 주소를 해석하지 않는다. 이 위협은 `-L`에는 없다.

## 결정

1. `-D`를 구현한다. 두 spelling을 모두 연다. 대화형 `qsh [user@]host -D [bind:]port`는 반복 가능하고 `-L`처럼 세션 옆에 listener를 연다. `qsh tunnel open host -D/--dynamic [bind:]port`는 호출 하나에 listener 하나이고 `--local`/`--remote`와 함께 쓸 수 없다. 로드맵상 위치는 현행 마일스톤 M9이며 `docs/ROADMAP.md` 개정은 메인 세션이 한다.

2. wire는 기존 `TCP_CONNECT`를 재사용한다(초안의 선택지 B). client가 SOCKS5 CONNECT 협상을 끝내고 요청된 목적지를 `StreamHeader{TCP_CONNECT, host, port}`에 그대로 싣는다. `StreamKind` 값은 더하지 않는다.

3. host dial에 host-local 주소 필터를 둔다. `StreamHeader`에 새 필드 `bool deny_host_local = 5;`를 더하고 capability 문자열 `dial-filter.v1`을 광고한다. 이 필드가 참이면 host dialer는 `lookup_host`가 돌려준 주소마다 `connect` 직전에 검사하고 다음 범주에 드는 주소는 연결하지 않는다.
   - loopback(`127.0.0.0/8`, `::1`), "이 망"(`0.0.0.0/8`, Linux는 `0.0.0.0`으로 가는 연결을 자기 자신으로 보낸다), unspecified(`::`), link-local(`169.254.0.0/16`, `fe80::/10`), multicast, IPv4 broadcast
   - 위 주소의 IPv4-mapped·IPv4-compatible IPv6 표기

   해석은 한 번만 하고 검사한 주소로만 연결하므로 검사와 연결 사이의 경합이 없다. 해석 결과가 전부 걸러지면 `ConnectResult{ok:false, code: PERMISSION_DENIED}`를 돌려주고 기존 `AuditRecord::connection_level` 모양으로 `action=forward.local`, `resource=host:port`, `decision=deny`, `rule=null`인 audit 한 줄을 fail-closed writer에 쓴다. 해석된 IP는 audit에 싣지 않는다. `AuditRecord`에는 필드를 더하지 않는다. `-D` client는 이 필드를 항상 참으로 보내고 `-L`은 항상 거짓으로 보내 오늘 동작 그대로다. 협상된 capability에 `dial-filter.v1`이 없으면 `-D`는 listener를 bind하기 전에 `UNSUPPORTED`로 거절한다. 조용히 필터 없이 동작하는 fallback은 두지 않는다. 이 필터는 인가 seam이 아니다. 악의적 client는 필드를 빼고 보낼 수 있지만 그런 client는 이미 `forward.local`을 쥐고 있다. 필터가 막는 상대는 정직한 client의 프록시를 빌려 쓰는 웹 콘텐츠다.

4. `docs/design/protocol.md` §16.4 초안에 항목 하나를 더한다. "기존 message에 새 필드 번호를 더하는 것. 단, 기본값의 의미가 오늘 동작과 같고, 송신자가 그 필드를 이해하는 peer임을 capability로 먼저 확인한 경우에 한한다." ADR-0018 결정 3의 `reclaim` 항목과 같은 성격이다. §16이 발효 전이라 지금 고치는 것이 맞고 이 개정은 기능 PR과 분리된 문서 PR로 먼저 낸다. §16.1 동결 표의 `StreamKind` 행은 바뀌지 않는다.

5. host의 `TCP_CONNECT` 모양 검사에 바이트 범주 검사를 더한다. `header.host`에 ASCII 제어문자, 공백, DEL, 비ASCII 바이트가 있으면 ACL 판정 전에 `INVALID_ARGUMENT`로 거절한다. 기존 길이 검사(255바이트) 바로 옆에 두고 `-L`에도 똑같이 적용한다. 악의적 client는 client 쪽 검사를 건너뛰므로 방어선이 host에도 있어야 한다. 이 거절은 audit 줄도 dial도 만들지 않는다.

6. 인가는 CONNECT마다 host에서 `forward.local`로 한다. 자원은 기존과 같은 `format_host_port(host, port)`이고 판정 뒤 quota 예약, 그 뒤 dial 순서도 그대로다. `forward.socks`는 어휘에 남기고 항상-deny 상태도 유지한다. 없애면 그 토큰을 적은 기존 `acl.toml`이 파싱되지 않고 그 host는 전부 거부 상태가 된다. `ALWAYS_DENIED_NO_OP`의 사유 문면만 "아직 wire op이 없다"에서 "`-D`는 설계상 `forward.local`로 인가된다(ADR-0019). client가 붙이는 표지는 인가를 실을 수 없으므로 이 action을 구동할 op을 만들지 않는다"로 바꾼다. `DENY_SEAMS`는 14행 그대로다.

7. SOCKS5 codec은 `crates/qsh-proto/src/socks5.rs`에 sans-IO로 둔다. async도 IO도 없고 `ErrorCode`에만 의존한다. 신뢰할 수 없는 로컬 입력을 읽는 파서이므로 `parse_forward_spec`과 같은 자리에 두고 cargo-fuzz 타깃 `parse_socks5`(열여덟 번째)를 더한다. 이 codec은 두 qsh peer 사이의 계약이 아니므로 `docs/design/protocol.md` §16.3의 "동결 밖" 목록에 올린다. 받는 부분집합은 다음과 같다.
   - 첫 바이트는 반드시 `0x05`다. 다른 값(HTTP의 `G`/`P`, TLS의 `0x16`, SOCKS4의 `0x04` 등)이면 한 바이트도 쓰지 않고 스트림도 열지 않은 채 닫는다.
   - 인증 method는 no-auth(`0x00`) 하나다. 목록에 `0x00`이 없거나 `NMETHODS`가 0이면 `05 FF`를 보내고 닫는다.
   - command는 CONNECT(`0x01`)만 받는다. BIND와 UDP ASSOCIATE, 그 밖의 값에는 REP `0x07`을 보낸다.
   - ATYP는 IPv4(`0x01`), 도메인(`0x03`), IPv6(`0x04`)을 받는다. 그 밖의 값에는 REP `0x08`을 보낸다. IPv6 주소는 괄호 없는 문자열로 넘긴다. `parse_forward_spec`이 넘기는 모양과 같다.
   - `RSV != 0`이나 `DST.PORT = 0`이면 REP `0x01`을 보내고 스트림은 열지 않는다.
   - 도메인은 1~253바이트의 LDH 문자와 `.`, `_`만 받는다. `:`, `[`, `%`, 공백, 제어문자는 받지 않는다. 소문자로 바꾸고 끝의 점 하나를 뗀다. 엄격한 dotted-quad나 IPv6 텍스트라면 해당 주소 리터럴로 정규화한다. 마지막 label이 숫자로만 되어 있거나 `0x`로 시작하는데 엄격한 리터럴이 아니면(`127.1`, `0x7f.1`, `2130706433` 같은 inet_aton 형식) REP `0x08`로 거절한다.
   - codec은 소비한 바이트 수를 돌려준다. IO 드라이버는 고정 헤더를 읽은 뒤 ATYP가 정하는 나머지 길이만큼만 정확히 읽는다. 요청 뒤에 이어 온 바이트는 버리지 않고 splice로 넘어간다. `BufReader`로 감싼 뒤 안쪽 소켓을 splice하는 구현은 금지한다.

8. REP 매핑은 codec 안의 표 하나로 두고 새 `ErrorCode`는 만들지 않는다.

   | 원인 | REP |
   |---|---|
   | `ConnectResult{ok:true}` | `0x00` |
   | `PERMISSION_DENIED` (ACL 거부, 결정 3의 필터 거부) | `0x02` |
   | `HOST_NOT_FOUND` (원격 해석 실패) | `0x04` |
   | `CONNECTION_FAILED` (거절, 모든 주소 실패, 10초 dial 제한 초과) | `0x05` |
   | `RESOURCE_EXHAUSTED`, `INVALID_ARGUMENT`, `Unknown(_)`, 그 밖의 code | `0x01` |
   | 로컬: 스트림 열기 실패, `ConnectResult` 없음, client 쪽 상한 초과 | `0x01` |
   | 로컬: CMD가 CONNECT가 아님 | `0x07` |
   | 로컬: ATYP 미지원, 도메인 모양 위반 | `0x08` |

   REP는 `ConnectResult`를 받은 뒤에만 보낸다. BND 필드는 `ATYP=0x01, 0.0.0.0:0` 고정이다. `ConnectResult`에는 실제 연결 주소를 담는 필드가 없고 추가하지도 않는다. 실패 REP 뒤에는 `shutdown(Write)` 후 보통 close를 한다. `abort_local`의 `SO_LINGER 0`(RST)은 아직 보내지 않은 REP를 없앨 수 있으므로 이 경로에서는 쓰지 않는다. `ConnectResult.message`는 `sanitize_peer_text`를 거쳐 stderr로만 나간다.

9. client 쪽 상한을 listener마다 둔다.
   - bind는 loopback 전용이다. `loopback_bind_addr`를 그대로 재사용하고 비-loopback `bind:`는 연결·listener가 생기기 전에 `INVALID_ARGUMENT`로 거절한다. 오류 문면은 "-L listeners"가 아니라 실제 flag 이름을 댄다.
   - handshake 기한은 greeting과 request를 합쳐 절대 10초다. 읽을 때마다 기한이 늘어나지 않는다.
   - handshake 중인 연결은 64개까지다. 슬롯은 `try_acquire`로 잡고 실패하면 대기열에 넣지 않고 바로 닫는다.
   - 수립된 SOCKS 연결은 128개까지다. host 기본 `max_tunnel_streams_per_principal` 256보다 낮다. 넘으면 스트림을 열지 않고 REP `0x01`을 보낸다.
   - CONNECT 속도는 token bucket으로 초당 50, burst 100이다. 토큰이 없으면 그 연결은 남은 handshake 기한 안에서 토큰을 기다린다. 기한 안에 토큰이 생기지 않을 때만 스트림 없이 REP `0x01`을 받는다. 브라우저는 페이지 하나에 연결 수십 개를 한꺼번에 열기 때문에, 즉시 거절하면 정상 브라우징이 깨진다. host의 fail-closed audit 큐를 한 principal이 채우는 일을 client 쪽에서 먼저 줄이려는 장치다.
   - 기존 `accept_disposition`의 EMFILE 백오프는 그대로 쓴다.

10. 첫 착지에서 `-D`는 정방향 route에서만 켠다. 대상 host가 역방향 route로 해석되면 연결하기 전에 `UNSUPPORTED`로 거절한다. 이것은 범위 결정이지 보안 경계가 아니다. controller는 같은 목적지로 `-L`을 열 수 있다. 역방향을 막는 실제 걸림돌은 capability 확인이다. 역방향 controller는 자기 머신의 `qsh listen` daemon과 UDS로만 말하고 target의 `Hello`는 daemon이 받는다. 그래서 controller가 target의 `dial-filter.v1`을 확인할 길이 아직 없다. 결정 3은 capability를 확인하지 못하면 거절하라고 하므로, daemon이 target의 협상된 capability를 controller에게 알려 주는 경로가 생기면 역방향 `-D`를 같은 작업의 마지막 단계로 켠다. 목적지 ACL 문법(Q1)은 역방향 `-D`의 선행 조건이 아니다. 정방향과 같은 이유로, `forward.local`을 준 target 운영자는 이미 모든 목적지를 허락한 것이다.

11. JSON 계약은 새 op 하나로 더한다.
    - command 문자열은 `tunnel.dynamic`이다. `qsh tunnel open ... --dynamic`의 모든 봉투(성공과 오류)가 이 command를 쓴다. `CLI_V1_SCHEMA_COMMANDS`와 `cli_v1_data_schema`에 등록한다.
    - 요청 타입은 `TunnelDynamicReq { host, bind: Option<String>, listen_port: u32 }`다.
    - 데이터 타입은 `DynamicTunnel { tunnel_id, mode: "dynamic", bind, actual_port, protocol: "socks5", dial_policy: "deny_host_local", host }`다. `actual_port`는 `Tunnel.actual_port`와 타입·의미가 같다. `protocol`과 `dial_policy`는 열린 문자열이다. `forward_to`는 없다.
    - `tunnel.open`, `Tunnel`, `TunnelOpenReq`, `tunnel.list`, `tunnel.close`는 한 바이트도 바뀌지 않는다. `-D` listener는 `-L`처럼 client가 쥐므로 `tunnel.list`에 나타나지 않는다. 같은 프로세스 안의 `tunnel.close`는 기존 hold registry로 닫힌다.
    - machine 모드 stdout에는 봉투 한 줄만 나가고 그 뒤로는 hold한다. 연결별 결과는 stderr로만 나간다.
    - 대화형 form에 `--json`/`--jsonl`이 붙으면 `docs/CLI.md` §7의 `INVALID_ARGUMENT`가 먼저 나오는 우선순위는 그대로다.
    - 처리 순서는 spec 모양과 loopback 검사, route 해석(역방향이면 거절), peer 연결, capability 검사, listener bind다. 모양 검사보다 먼저 생기는 것은 없고 bind보다 먼저 capability가 확인된다. open 시점에 ACL 검사는 없다. `tunnel.dynamic` 성공이 인가를 뜻하지 않고 거부된 principal은 CONNECT마다 REP `0x02`를 받는다. `docs/CLI.md` §6.9에 이 점을 적는다.

12. 로그 규율은 이렇다. host audit은 지금처럼 목적지를 구조적 메타데이터로 남긴다. client는 연결별 목적지를 debug 수준에서만 남긴다. warn 이상에는 개수와 오류 범주만 싣는다. `-L` accept 루프의 `warn!(host, port, …)` 호출을 SOCKS 루프에 옮겨 쓰지 않는다. handshake 이후 바이트는 보지 않는다. SNI나 Host 헤더를 엿보는 일도 하지 않는다.

13. fixture 처리는 이렇다. `error.UNSUPPORTED.json`은 바이트 그대로 둔다. `-D`가 더는 그 봉투를 만들지 않으므로 `crates/qsh-cli/tests/fixtures.rs`에서 생성 코드를 지우고 그 파일 이름을 새 상수 `RETIRED_PRODUCERS`에 사유와 함께 올린다. `ErrorCode` 도달성 테스트는 retired 파일을 커버리지에서 뺀다. 따라서 `UNSUPPORTED`에는 살아 있는 생성자가 새로 있어야 하고 역방향 route `-D` 거절(결정 10)이 새 fixture `error.UNSUPPORTED.dynamic_reverse.json`을 만든다. 새 fixture로 `tunnel.dynamic.json`과 `error.INVALID_ARGUMENT.dynamic_bind.json`도 추가하고 `REQUIRED_FIXTURES`에 등록한다. `capabilities.json`은 `dial-filter.v1` 때문에 `QSH_UPDATE_FIXTURES=1`로 다시 만들고 계약 변경과 같은 무게로 리뷰한다(`docs/design/testing.md` L6).

14. 거절 상수 둘(`DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE`, `DYNAMIC_FORWARD_UNSUPPORTED_GUIDANCE`)과 `dynamic_forward_unsupported()`는 지운다. 대신 상수 `DYNAMIC_FORWARD_ACL_NOTE`를 둔다. 문면은 "`-D` runs SOCKS5 on this machine and authorizes every CONNECT on the peer as `forward.local`; `forward.socks` is never consulted."이다. README와 `docs/CLI.md` §6.9가 이를 축자 인용하고 `crates/qsh-core/tests/tunnel_docs.rs`가 대조한다. 거절 문면에 걸려 있던 문서-상수 대조 장치를 보안상 중요한 이 사실로 옮긴다.

15. 초안의 미결 질문 아홉 개는 이렇게 처분한다. 이유는 근거 절에 있다.
    - Q1 목적지 ACL 문법: 이 ADR의 선행 조건이 아니다. 문법은 `forward.local`을 대상으로 하는 별도 ADR로 만든다. 그 문법은 `allow` 토큰 안에 인코딩해서 구버전 바이너리가 파일을 `CONFIG_ERROR`(전부 거부)로 읽게 한다. 이름 패턴은 요청 문자열에, CIDR은 해석된 주소에 맞춘다. 결정 2 덕분에 그 문법은 `-L`과 `-D`를 함께 덮는다.
    - Q2 역방향 egress: 첫 착지에서는 끄고 daemon이 target capability를 전달하게 되면 켠다(결정 10). target 쪽 "SOCKS 끄기" 스위치는 만들지 않는다. host가 SOCKS와 `-L`을 구별할 수 없으니 그런 스위치는 강제될 수 없다. 강제할 수 있는 통제는 Q1의 문법이다.
    - Q3 stream kind: `TCP_CONNECT`를 재사용한다(결정 2). 필요한 wire 추가는 capability로 보호되는 필드 하나(결정 3)다.
    - Q4 JSON 표현: 새 op `tunnel.dynamic`과 새 타입으로 한다(결정 11). 기존 필드를 `Option`으로 바꾸거나 다르게 해석하게 하지 않는다.
    - Q5 bind와 command 집합: loopback 전용, no-auth, CONNECT만 받는다(결정 7, 9).
    - Q6 REP 매핑: 결정 8의 표로 하고 축자 테스트로 고정한다.
    - Q7 quota: host에 새 축을 두지 않는다. per-principal 축이 먼저 검사되므로 목적지를 흩어도 총량이 묶인다. client 쪽 상한(결정 9)을 새로 둔다.
    - Q8 `-W`와의 선후: 서로 독립이다. `-W`는 M10 검토 항목으로 남고 초안 결정 5(`-D`를 `-W`와 묶어 M10으로)는 철회한다.
    - Q9 크기: 1.6~2.0ew로 추정한다. 측정한 값이 아니다. 내역은 결과 절에 있다.

## 근거

선택지 B가 새 권한을 만들지 않는다는 점이 출발점이다. `forward.local`은 이미 모든 목적지를 허용하고 host는 `TCP_CONNECT`의 출처를 구별하지 못한다. B로 구현한 `-D`가 host에 남기는 흔적은 스크립트가 `-L`을 N개 연 것과 같다. action, 자원 문자열, audit 모양, quota 버킷이 모두 같다. 따로 부여하는 `forward.socks`(선택지 A)는 결과적으로 스스로 SOCKS라고 밝히는 client만 막는다. `forward.socks`는 거부되고 `forward.local`은 허용된 principal도 같은 목적지로 평범한 `TCP_CONNECT`를 보내면 된다. A는 존재하지 않는 경계를 운영자에게 있는 것처럼 보이게 한다.

그런데도 wire에 필드 하나를 더하는 이유는 공격자 모델이 다르기 때문이다. `-D`에서는 qsh 사용자가 아니라 프록시를 쓰는 프로그램, 특히 웹 페이지가 목적지를 고른다. 재바인딩으로 host의 loopback이나 metadata 주소에 닿는 공격은 이름을 해석한 뒤에만 보이므로, 해석하는 쪽인 host가 걸러야 한다. client는 host에게 걸러 달라고 요청할 수 있을 뿐이고 요청을 모르는 구버전 host는 필드를 버린다. 그래서 capability로 먼저 확인하고 없으면 거절한다. fallback을 두면 필터가 있다고 믿는 사용자가 필터 없는 host에 붙게 된다.

필터를 인가 seam이 아니라 dial 정책으로 둔 것은 정직하게 부르기 위해서다. 필드를 뺀 client는 `-L`과 같은 권한으로 돌아갈 뿐이고 그 권한은 이미 `forward.local`로 주어져 있다. audit의 거부 줄은 `rule=null`로 적는다. `AuditRecord::now` doc이 규칙 매칭 밖에서 난 거부를 그렇게 적는다고 정한 대로다.

`forward.socks`를 지우지 않는 이유는 가용성이다. loader는 모르는 토큰이 있으면 파일 전체를 거부하므로, 어휘에서 빼면 그 토큰을 적어 둔 host가 모든 요청을 거부하게 된다. 항상-deny로 두면 기존 파일의 의미가 바뀌지 않고 관련 테스트의 단언도 그대로 남는다. `forward.*` 와일드카드가 새로 SOCKS 권한을 삼키는 문제는 A에서만 생긴다. B에서는 gate 1번이 여전히 `forward.socks`를 막고 `-D`에 필요한 권한은 원래부터 `forward.*`에 들어 있던 `forward.local`이다.

JSON에서는 command마다 data 스키마가 하나라서 새 command를 쓴다. `tunnel.open`의 data는 `Tunnel`이다. 이를 union으로 넓히면 type 변경이고 `forward_to`에 가짜 값을 넣으면 의미 변경이다. 새 command와 새 타입을 더하는 것만 `docs/CLI.md` §10의 additive 규칙 안에 있다.

codec을 `qsh-proto`에 두는 이유는 ADR-0001이 신뢰할 수 없는 입력의 파서를 그 crate에 모으고 fuzz하기로 했기 때문이다. `qsh-proto`는 아무것에도 의존하지 않는다는 규칙도 codec이 `ErrorCode`만 쓰므로 지켜진다. IO 드라이버는 `qsh-core/src/tunnel/`에 두고 `qsh-cli`에는 dispatch와 렌더러만 남는다. `xtask arch`의 모듈 금지 범위(`broker/`, `qsh-cli/src/`)에 걸리는 파일은 없다.

역방향을 첫 착지에서 끄는 것은 보안 경계가 아니라 순서의 문제다. 필터가 있다고 확인하지 못한 채 켜면 결정 3의 "fallback 없음" 원칙이 역방향에서만 깨진다. 확인 경로만 생기면 정방향과 다를 이유가 없다.

받는 부분집합이 작고 이 부분집합을 fuzz 타깃과 축자 테스트로 고정해야 하므로 SOCKS5 crate는 쓰지 않는다. 직접 쓴 codec은 300줄 안팎이고 `deny.toml`과 `Cargo.lock`을 건드리지 않는다.

## 대안

- 선택지 A. 새 `StreamKind`(예: `TCP_CONNECT_DYNAMIC = 5`)와 capability를 두고 `forward.socks`를 항상-deny에서 풀어 새 seam으로 만든다. 기각 사유: 위 근거대로 client가 스스로 붙이는 표지라서 `forward.local` 보유자에게는 경계가 되지 못한다. 대가는 크다. ACL 테스트 12~14개가 빨개지고 `forward.*` 와일드카드가 넓어지는 문제를 막을 "명시 부여 전용" 등급을 새로 만들어야 하며 §16.4를 enum 값 추가까지 넓혀야 한다. 추정 비용은 B보다 0.6~0.9ew 더 든다.
- `StreamHeader`에 SOCKS 표지 필드를 더해 `forward.socks`로 판정한다. 기각 사유: 구버전 host는 필드를 버리고 `forward.local`로 판정하므로 혼합 fleet에서 구분이 조용히 사라진다. 게다가 A와 같은 이유로 경계가 되지 못한다.
- 목적지 ACL 문법을 먼저 만들고 그 뒤에 `-D`를 연다(초안의 입장). 기각 사유: 그 문법이 막는 틈은 M4 이후 `forward.local`에 줄곧 있었고 SOCKS와 무관하다. `-D`를 기다리게 해도 그 틈은 줄지 않는다. 문법은 별도 ADR로 진행하고 결정 2 덕분에 완성되는 즉시 `-D`도 덮는다.
- `tunnel.open`에 `mode:"dynamic"`을 더하고 `forward_to`/`forward_host`/`forward_port`를 `Option`으로 바꾼다. 기각 사유: type 변경이라 `/v2` 사유다(`docs/CLI.md` §10). 빈 값 재해석은 의미 변경이다.
- 필터 없이 OpenSSH `-D`와 같게 낸다. 기각 사유: 브라우저를 프록시에 물리는 것이 SOCKS의 주 용례이고 그 용례에서 재바인딩으로 host loopback과 metadata 자격증명이 노출된다. qsh는 그 주소들을 해석하는 host 쪽에 있으므로 막을 수 있다.
- 필터를 켜되 끄는 flag를 둔다(예: `--dynamic-allow-host-local`). 1단계에서는 기각한다. 켜는 순간 그 listener로 브라우징하는 모든 페이지에 재바인딩 경로가 다시 열린다. host의 loopback 서비스에 닿아야 하면 목적지를 고정하는 `-L`을 쓴다. 실사용 요구가 확인되면 별도 결정으로 다시 본다.
- capability가 없는 host에서는 필터 없이 동작한다. 기각 사유: 사용자는 필터가 있다고 믿는데 실제로는 없는 상태가 된다. 거절하면 원인이 분명하다.
- 역방향 route에서도 `-D`를 첫 착지부터 켠다. 기각한다. target의 `dial-filter.v1`을 확인할 수 없어서다. splice 쪽은 `ForwardCarrier::Local`이 이미 있으므로, daemon이 capability를 전달하게 되면 같은 작업 안에서 켠다.
- SOCKS5 codec을 `qsh-cli`에 둔다. 기각 사유: 신뢰할 수 없는 입력 파서는 `qsh-proto`에서 fuzz한다는 ADR-0001의 규율과 맞지 않는다. 연결 처리 로직이 renderer 계층에 들어가게 된다.
- 외부 SOCKS5 crate를 쓴다. 기각 사유: 받는 부분집합을 좁게 고정하고 fuzz해야 하는데, 넓은 구현을 들여오면 그 경계를 테스트로 다시 좁혀야 한다.
- 초안대로 v1 내내 유예한다. 기각 사유: 사용자가 2026-09-19에 구현을 결정했다. 초안이 유예 근거로 든 Q1·Q2는 위 처분으로 답했다.

## 결과

- 지금까지 `forward.local`을 받은 principal은 추가 설정 없이 `-D`를 쓸 수 있다. 권한이 새로 생긴 것은 아니다. 다만 써먹기가 한 명령으로 쉬워졌으므로 README, `docs/CLI.md` §6.9, `docs/design/threat-model.md`에 "`forward.local` 부여는 그 host가 닿는 모든 목적지로 나가는 egress 부여"라고 분명히 적는다.
- wire 변경은 `StreamHeader.deny_host_local = 5`와 capability `dial-filter.v1` 둘이다. 새 client와 구버전 host 조합에서 `-D`는 `UNSUPPORTED`로 거절되고 `-L`은 영향이 없다. `decode_stream_header` fuzz 타깃이 새 필드를 자동으로 덮는다.
- 빨개지는 기존 테스트와 그 처리는 다음과 같다. 모두 옛 계약(항상 거절)을 고정하던 테스트라 새 계약으로 바꿀 뿐 검사를 느슨하게 하지 않는다.
  - `crates/qsh-cli/tests/dynamic_forward_stub.rs`는 `dynamic_forward.rs`로 대체한다. 무자원 속성은 실패 경로(비-loopback bind, 역방향, capability 부재)의 새 테스트로 옮겨 남긴다.
  - `crates/qsh-core/tests/tunnel_docs.rs`는 `DYNAMIC_FORWARD_ACL_NOTE` 대조로 바꾼다.
  - `crates/qsh-core/tests/failure_text_discipline.rs`의 T6 행과 `CHANNEL_CONSTRAINED` 항목은 역방향·capability 부재 거절 문면으로 바꾼다. 새 문면은 처음부터 관측·영향·다음 명령 세 부분을 envelope `message`에 다 담는다.
  - `crates/qsh-cli/tests/fixtures.rs`의 `-D` 생성 블록은 지운다. 결정 13대로 도달성 검사는 오히려 엄격해진다.
  - `checked_in_man_pages_match_the_generator`는 `cli.rs` doc 주석을 고친 뒤 `cargo xtask man`으로 맞춘다.
  - `capabilities.json` golden은 다시 만들고 리뷰한다.
- ACL 쪽 테스트의 단언은 바뀌지 않는다. `is_always_denied_is_exactly_the_p1_deferred_trio`는 이름만 `is_always_denied_is_exactly_the_undrivable_trio`로 바꾼다.
- `docs/man/qsh.1`의 "or anything else on the command line" 문구는 `--json` 우선순위와 어긋나 있었다. 이번에 doc 주석을 다시 쓰면서 함께 사라진다.
- 잔여 위험은 `docs/design/threat-model.md` §7에 행으로 올린다.
  - R1: `forward.local` 부여가 곧 무제한 egress다. 전부터 있던 위험이고 Q1 문법 ADR이 완화한다.
  - R2: 같은 머신의 다른 uid가 loopback SOCKS 포트를 이 principal로 쓸 수 있다. `-L`도 같지만 `-D`는 모든 목적지가 열려 있어 피해 범위가 넓다. 다중 사용자 머신에서는 `-D`를 쓰지 않는 것이 처방이다. `docs/design/threat-model.md` §2의 "같은 호스트의 다른 사용자: 없음" 행은 loopback TCP listener에는 맞지 않으므로 고친다. RFC 1929 listener별 자격증명은 P2 후보다.
  - R3: 응용이 `socks5h://` 대신 `socks5://`를 쓰면 client 쪽에서 DNS가 샌다. client 설정 문제이므로 문서로 안내한다.
  - R4: REP 분류가 거칠다. `0x03`과 `0x06`은 나오지 않는다. `0x04`와 `0x05`의 구분은 원격 포트 스캔 단서가 되는데, `-L`의 `ConnectResult`와 같은 수준이다.
  - R5: 필터는 host 자신의 비-loopback 인터페이스 주소와 RFC 1918 대역을 거르지 않는다(사내망 접근이 용례다). IPv6 metadata 주소(예: `fd00:ec2::254`)도 걸러지지 않는다.
  - R6: 운영자가 `allow = ["forward.socks"]`로 `-D`를 허락하려 해도 아무 효과가 없다. 문서에 명시하고 `qsh doctor` 진단은 후속 후보로 둔다.
  - R7: splice된 연결에 idle timeout이 없다. `-L`과 같은 잔여 위험이다.
- 크기 추정은 1.6~2.0ew이고 측정값이 아니다. 내역은 codec과 fuzz 0.25, client 드라이버와 상한 0.4, wire 필드·capability·host 필터·resolver seam 0.35, Ops·JSON·CLI 0.25, 테스트와 acceptance 0.3, 문서·man·fixture 정리 0.2다.
- 메인 세션이 고칠 문서가 있다. `docs/ROADMAP.md`에서는 §3 유예 가드레일 표의 "SOCKS `-D` (P1)" 행을 이 ADR 링크로 닫는다. M9 (i) 문구 표본의 "`-D` 현행 유지 문구"는 "`-D` 거절 문구(역방향·capability 부재)"로 바꾼다. M10 `-W` 항목에는 `-D`를 더하지 않는다. M4 DoD 행은 역사 기록으로 두고 이 ADR을 가리키는 한 줄만 붙인다. `docs/PRD.md`의 `-D` P1 서술 네 곳은 사용자의 구현 결정에 따라 같은 작업에서 고친다. CLAUDE.md와 `fuzz/README.md`의 fuzz 타깃 수는 열일곱에서 열여덟이 된다. `docs/adr/README.md` 색인 0019 행은 이 ADR과 같은 커밋에서 제목과 상태를 바꾼다.
