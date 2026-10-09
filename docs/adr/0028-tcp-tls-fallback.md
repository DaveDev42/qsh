# ADR-0028: TCP/TLS fallback은 명시 선택을 기본으로 하고 자체 sans-IO mux 위에서 항상 resume으로 복구한다

날짜: 2026-10-09
상태: 제안됨

개정 관계: ADR-0005를 구체화한다. ADR-0005가 약속한 `Transport`/`StreamMux` trait은 결정 0의 모양(공개 enum facade와 비공개 계약 trait)으로 실현한다. ADR-0021 결정 1(`[transport].keep_alive_ms`)과 결정 2(45초 idle 상수)의 뜻을 TCP 경로로 넓힌다(결정 6). 다른 ADR의 결정은 바꾸지 않는다.

## 맥락

ADR-0005는 TCP fallback을 P1으로 미루면서 두 가지만 정했다. wire 변경 없이 "TLS over TCP + 소형 mux"를 붙인다는 것과, 그 준비로 transport 추상을 P0에 세운다는 것이다. 추상은 세워지지 않았다. `qsh-transport`가 `quinn::{ConnectionError, Endpoint, ReadError, WriteError}`를 그대로 재수출하고, `qsh-core`는 `Cargo.toml`에 quinn을 직접 의존으로 두고 `localctl/daemon.rs`, `tunnel/{splice,stall,local,remote}.rs`, `reverse/{mod,listen}.rs`, `client/pathwatch.rs`, `client/reconnect.rs`에서 quinn 타입과 `Connection::quinn()` 탈출구를 쓴다. 연결 오류 분류(`reverse::classify_connection_error`, `ops/exec.rs`, `pairing.rs`, `handshake.rs`)도 quinn 오류 variant를 직접 매칭한다.

`docs/ROADMAP.md` M14 (b)는 이 ADR이 정할 것을 일곱으로 적었다. transport 선택 정책, TCP listener의 bind와 포트, mux 설계와 `docs/design/protocol.md` §16.2 행 여부, migration 없는 TCP의 복구 경로, 선두 차단(head-of-line blocking) 아래 PTY 우선순위 약속, `keep_alive_ms`의 TCP 의미, 자동 전환을 고를 때의 강제 downgrade 처분이다. 여기에 (a)의 추상 모양(결정 0)과 admission·관측 표면(결정 8)을 더한다.

## 결정

### 결정 0. 추상의 모양: 공개 enum facade, 비공개 계약 trait, 공유 적합성 스위트

`qsh-transport`의 공개 이름(`Connection`, `Endpoint`, `Listener`, `Incoming`, `Dialer`, `FramedSend`/`FramedRecv`)은 그대로 두고, 각 타입을 `Quic`(과 M14 (c)에서 `Tcp`) variant를 가진 enum facade로 만든다. 공개 표면에는 quinn 타입이 나타나지 않는다.

- 스트림: `SendStream`/`RecvStream`을 transport 중립 타입으로 새로 둔다. `write_all`, `finish`(half-close), `reset(u32)`, `stop(u32)`, `set_priority(i32)`, `stopped()`, `read` → `Option<usize>`와 tokio `AsyncRead`/`AsyncWrite`를 갖는다. drop 의미는 quinn을 따른다. `SendStream` drop은 정상 finish이고 `RecvStream` drop은 stop이다. splice guard가 이 의미에 기대므로 계약 테스트로 고정한다.
- 오류: `ConnectionError`, `ReadError`, `WriteError`, `DialError`, `AcceptError`를 qsh 소유 enum으로 둔다. 분류 메서드 `is_crypto_failure()`, `is_idle_timeout()`, `is_reset()`, `application_code() -> Option<u32>`가 기존 매칭을 대신한다. QUIC backend의 `Display` 문자열은 지금의 quinn 문자열과 바이트 단위로 같아야 한다. CLI 메시지(`connection lost: {err}`)에 그대로 흐르기 때문이다.
- 통계: `Connection::stats() -> ConnStats { rtt, rx_frames, peer_blocked_events, rx_raw_datagrams: Option<u64>, lost_packets: Option<u64> }`가 `.quinn().stats()` 호출을 모두 대신한다. `peer_blocked_events`는 QUIC의 `DATA_BLOCKED` 수신 수이고 TCP에서는 mux의 `BLOCKED` 프레임 수다(ADR-0037의 원장 신호).
- 연결 식별자: `Connection::stable_id`(quinn slab id)는 프로세스 전역 단조 증가 `ConnId`로 바꾼다. UDP와 TCP listener가 함께 있을 때도 quota·audit·lease·stall 레지스트리 키가 겹치지 않아야 한다.
- 경로 이동: `Endpoint::rebind_ephemeral() -> io::Result<SocketAddr>`가 `client/reconnect.rs`의 rebind를 대신한다. TCP에서는 `Unsupported`를 돌려주고, `reconnect.rs`는 이미 rebind 실패를 resume으로 넘긴다.
- 계약 trait(`MuxConn`, `SendHalf`, `RecvHalf`)은 `qsh-transport` 안에서 비공개다. 두 backend가 같은 적합성 스위트를 통과하는 것이 계약이다. `docs/design/testing.md` L4가 mock transport를 기각하므로 열린 trait 집합이 줄 이득은 없다.
- `qsh-core`의 `Cargo.toml`에서 quinn 의존을 지우고, `cargo xtask arch`에 `crates/qsh-core/src`와 `crates/qsh-cli/src`의 `quinn` 토큰 금지(디렉터리 범위)를 더한다. 의존 행렬은 `qsh-*` crate만 보므로 이 금지가 따로 필요하다.
- carrier enum의 `Quic` variant 이름(`ControlLink`, `DataLink`, `DataSend`, `DataRecv`, `ForwardCarrier`, `OpenedTunnel`)은 (a)에서 바꾸지 않는다. 테스트가 약 70곳에서 이 이름을 쓰고, 바꿀지는 (c)에서 TCP variant가 생길 때 정한다.

### 결정 1. 선택 정책: `[transport].mode` = `quic`(기본) | `tcp` | `auto`

- 기본은 `quic`이다. 지금 배포의 동작은 바뀌지 않는다.
- `tcp`와 `quic`은 완전히 명시적이다. 설정 파일의 `[transport].mode`, `hosts.toml`의 호스트별 `transport` 키, dial 명령의 `--transport {quic,tcp,auto}`로 고른다. 우선순위는 플래그 > 호스트 행 > `config.toml`이다.
- `auto`는 좁게 정의한다. QUIC을 평소 dial timeout으로 먼저 시도하고, 실패가 네트워크 부류(시간 초과, 망이 거부함)일 때만 TCP를 시도한다. TLS·trust·인증 거부 뒤에는 TCP로 넘어가지 않는다. 두 transport를 병렬로 경주시키지 않는다. 고른 결과를 호출 사이에 캐시하지 않는다.
- resume은 세션이 열린 transport로 먼저 시도하고, 모드가 `auto`일 때만 다른 쪽을 시도한다.
- 무인 기계(`--supervise`, 서비스 unit)는 설정 파일로 `auto`나 `tcp`를 고른다(ADR-0021의 "조정값은 파일에 둔다"와 같은 원칙).

### 결정 2. TCP listener는 기본으로 bind하지 않는다

- `qsh serve`와 `qsh listen`은 `[serve].tcp_bind`(또는 `--tcp-bind <addr>`)가 있을 때만 TCP 소켓을 연다. 값이 없으면 TCP 소켓은 없다.
- 포트 관례는 UDP와 같은 번호(4433/tcp)다. ADR-0014의 "포트가 없으면 4433" 규칙을 그대로 쓴다.
- dial 쪽 주소 문법에 선택적 scheme `tcp://host:port`와 `quic://host:port`를 더한다. scheme이 있으면 결정 1의 정책보다 앞선다. 맨 `host[:port]`는 결정 1의 정책을 따른다. 규칙은 `docs/CLI.md` §6.11의 ADR-0014 규칙 옆에 적는다.
- `docs/design/threat-model.md` §3에 "`qsh serve` TCP listener: 인증 전 TCP, 기본 bind 안 함" 행을, §4 C에 핀 테스트가 붙은 행을 더한다.

### 결정 3. mux는 `qsh-proto`의 자체 sans-IO codec이고 §16.2의 새 행이 된다

- codec은 `qsh-proto`의 새 모듈이다. `FrameDecoder`처럼 증분 디코더이고 할당 전에 길이를 검사한다. 비동기 driver는 `qsh-transport`에 둔다. 새 의존은 `tokio-rustls` 하나다.
- 프레임: `SETTINGS`(mux 버전, 최대 프레임, 초기 window. 첫 프레임이어야 한다), `OPEN`/`DATA`(stream id, flag, payload ≤ 16 KiB. TLS record 하나에 chunk 하나), `FIN`, `RESET(u32)`, `STOP(u32)`, `WINDOW(credit)`, `BLOCKED`(권고, 빈도 제한), `PING`/`PONG`, `CLOSE(code, reason)`.
- stream id는 u32이고 dialer가 홀수, acceptor가 짝수를 쓴다. 고갈되면 `CLOSE`한다.
- 한도는 QUIC 값을 따른다. 동시 bidi 1024, 터널 stream window 2 MiB(`TUNNEL_STREAM_RECEIVE_WINDOW`), 연결 window 8 MiB(`CONNECTION_RECEIVE_WINDOW`). ADR-0010과 ADR-0037의 숫자가 그대로 옮겨 간다.
- writer는 우선순위 대역 200/100/50/0을 지키고 대역 안에서는 round-robin한다.
- application protocol은 ALPN `qsh/1`과 `.proto` v1 그대로다. mux 프레임 형식과 `SETTINGS`는 다른 빌드의 바이너리가 말해야 하는 peer 가시 wire이므로 `docs/design/protocol.md` §16.2에 행("TCP mux 프레임 형식과 SETTINGS")을 더한다. mux 버전은 `SETTINGS`로 협상한다. dialer가 이미 transport를 골랐으므로 capability 문자열은 더하지 않는다.
- fuzz 타깃이 하나 늘고 `fuzz/README.md`와 `docs/design/protocol.md` §13의 개수 문장이 같은 커밋에서 바뀐다. 새 타깃의 누적 72 fuzz-hours는 `docs/ROADMAP.md` §5.5의 사람 몫이다.

### 결정 4. TCP는 항상 resume으로 복구한다

TCP에는 Tier-1(connection migration)이 없다. 감지는 PathWatch(mux 제어 stream의 ping/pong과 `ConnStats.rx_frames`)가 하고 예산은 ADR-0021 결정 4와 같다. 복구는 재dial과 resume token을 쓴 `SessionAttach`다(`docs/design/protocol.md` §10, ADR-0007). 터널은 연결과 함께 죽는다(ADR-0018 결정 1). TCP에서는 IP가 바뀔 때마다 그렇게 되므로 README Known limitations에 적고, ADR-0023의 `--supervise`가 다시 연다. MPTCP와 mux 수준 migration은 목표가 아니다.

### 결정 5. PTY 우선순위 예산은 측정해서 정하고 손실 아래에서는 약속하지 않는다

M13 (b) 하네스에 TCP leg를 먼저 더하고, 결정 3의 chunk 크기와 우선순위 대역, `TCP_NOTSENT_LOWAT`(Linux·macOS), `SEND_DEPTH_CAP_BYTES`(128 KiB) 아래에서 포화 터널 + PTY echo p95를 잰다. 예산은 측정값에 여유를 더해 `RTT + X ms`로 테스트에 고정한다(§12가 7.1~7.9ms를 10ms로 잡은 방식). 약속은 손실 없는 경로에 한한다. TCP segment 하나를 잃으면 재전송까지 그 뒤의 모든 stream이 멈추므로, 손실 아래와 `TCP_NOTSENT_LOWAT`이 없는 플랫폼(Windows)에서는 예산이 없다고 README Known limitations에 적고 그 고지를 테스트로 고정한다. 선두 차단은 받아들인 잔여 위험이다.

### 결정 6. `keep_alive_ms`는 mux `PING` 주기이고 45초 idle은 로컬 타이머다

TCP에서 `keep_alive_ms` 동안 mux 프레임을 보내지 않았으면 `PING`을 보낸다. 그 응답이 `ConnStats.rtt` 표본이다. 수신 쪽은 협상하지 않는 로컬 45초 idle 타이머를 두고, 만료되면 `ConnectionError::TimedOut`으로 닫는다. 그래서 `idle_timeout` 재연결 사유(ADR-0022)가 같은 뜻을 갖는다. 범위 1000..=20000과 위반 시 `CONFIG_ERROR`는 그대로다. `SO_KEEPALIVE`는 켜지 않는다. 두 값 모두 peer 가시 의미가 없으므로(ADR-0021 결정 1) §16.2 행이 필요 없고, (c)가 착지할 때 `docs/design/protocol.md` §2에 두 문장을 적는다.

### 결정 7. `auto`의 downgrade는 시끄럽고 제한된다

- (i) 결정 1의 네트워크 부류 실패 뒤에만 TCP로 넘어간다. TLS·trust 실패 뒤에는 넘어가지 않는다.
- (ii) host audit 레코드와 client stderr 줄이 `transport=tcp`와 사유를 싣는다(결정 8의 additive 필드).
- (iii) 선택을 저장하지 않는다. 새 연결마다 QUIC을 먼저 시도한다.
- (iv) `mode = "quic"`(기본)은 fallback을 금지한다.
- (v) `docs/design/threat-model.md` §7 잔여 위험에 h행을 더한다. "`auto`에서 UDP를 막는 on-path 공격자는 migration 없는 TCP 경로를 강제할 수 있다."

동등성 논거: 인증은 두 transport에서 같다. 같은 `QshPeerVerifier`(pin → CA → 거부), TLS 1.3만, ALPN `qsh/1`, 0-RTT·ticket·resumption 금지, SNI 끔이다. 강제 downgrade가 빼앗는 것은 migration, 손실 아래 PTY 격리, 일부 가용성이고 기밀성과 신원은 아니다. 워크스페이스 rustls가 `tls12` feature를 켜므로 TCP 경로도 `with_protocol_versions(&[TLS13])`를 유지해야 한다. 이 성질은 `crates/qsh-transport/tests/loopback.rs` 형식의 TLS 설정 동등성 단언과 "QUIC 인증 실패는 TCP 시도를 부르지 않는다" 테스트로 고정한다.

### 결정 8. admission과 quota는 같은 표를 쓰고 `transport`를 additive 필드로 드러낸다

- TCP accept arm은 같은 `admission::Gate::decide()`를 부른다(ADR-0009). TCP handshake가 출발지를 이미 검증하므로 Retry는 나오지 않는다. semaphore는 TLS를 시작하기 전에 잡는다. 키는 IPv4 /32, IPv6 /64로 같다. ADR-0010 quota 표도 같다.
- 정체된 TCP peer에는 QUIC idle timeout 같은 받침이 없으므로 TLS handshake에 양쪽 모두 10초(`DEFAULT_DIAL_TIMEOUT`) 마감을 둔다. Hello 전 mux 프레임에도 `CONTROL_FRAME_MAX`/`DATA_FRAME_MAX`를 적용한다.
- audit 연결 레코드와 session·connect JSON에 additive `transport` 필드(`"quic"` | `"tcp"`)를 더한다(`qsh.cli/v1` additive 규칙). `capabilities.json` golden은 `QSH_UPDATE_FIXTURES=1`로 재생성하고 계약 변경과 같은 무게로 검토한다.
- doctor는 `udp_egress_blocked` 옆에 TCP 도달성 검사를 더하고, remedy 문면("QSH has no TCP fallback (P1, ADR-0005)")을 실행 가능한 다음 명령으로 바꿔 축자 테스트로 고정한다.
- `load.yml`의 적대적 부하 시나리오에 TCP handshake flood를 더한다.

## 근거

- 기본을 `quic`으로 두면 지금 배포에 새 소켓도, 성공 경로의 지연도 생기지 않는다. `auto`를 같은 설정의 값으로 두면 무인 기계가 나중에 코드 변경 없이 쓸 수 있다.
- listener를 기본으로 끄면 인증 전 표면은 운영자가 고른 곳에만 생긴다. TLS handshake는 Retry로 걸러지는 QUIC Initial보다 출발지당 비용이 크다. `qsh serve`와 `qsh listen`은 이미 UDP 4433에서 충돌할 수 있는데(`BIND_UNAVAILABLE_REMEDY`), 기본 TCP bind는 그 충돌 부류를 두 배로 만든다.
- 자체 mux만이 지금 코드가 기대는 의미를 모두 준다. 우선순위, u32 application 오류 코드, 별도의 STOP_SENDING, `DATA_BLOCKED`에 해당하는 신호다. splice·stall·deny teardown(`docs/design/protocol.md` §7)이 이 의미에 기댄다. codec이 sans-IO이면 기존 fuzz 표면에 들어간다.
- 항상 resume은 이미 증명된 Tier-2 경로를 바꾸지 않고 쓴다. 정확성은 migration에 기댄 적이 없다(§2: migration은 지연 최적화일 뿐이다). SC4의 TCP 판(`kill -9` 뒤 reattach)도 resume 테스트다.
- enum facade는 `qsh-core`에 제네릭을 퍼뜨리지 않고, 터널 pump의 hot path에 boxing과 vtable을 넣지 않는다. M4 DoD 3의 throughput 관문과 M13 성능 판정을 흔들지 않는다.

## 대안

- 선택 정책: 명시만(자동 없음)은 무인 기계에 길이 없다. 처음부터 자동(Happy Eyeballs식 경주)은 조용한 downgrade, host의 handshake CPU 배증, 테스트의 비결정성을 부른다. 기각.
- listener 기본 bind: 모든 `qsh serve`가 스캐너에 보이는 TLS 서버가 되고 threat model §3의 인증 전 표면 주장이 바뀐다. "loopback이 아니고 ACL 행이 있을 때만"은 암묵적이고 ACL 로드 순서에 기대서 시험하기 어렵다. 기각.
- yamux 0.14: 우선순위, 코드가 있는 RST, 별도 STOP_SENDING, BLOCKED 신호가 없다. futures-io 기반이라 호환 계층이 필요하고 의존 다섯이 늘며, 그 파서가 우리 sans-IO fuzz 표면 밖에 있으면서 freeze에는 참조로 들어온다. 기각.
- HTTP/2(h2): HPACK·SETTINGS 표면이 필요보다 훨씬 넓고 우선순위는 폐기됐으며 rapid-reset 부류의 공격 표면이 있다. 기각.
- `localctl` conduit framing 재사용: UDS 요청/응답 framing이라 흐름 제어가 없다. 기각.
- MPTCP: Windows에 없고 middlebox가 벗기며 GHA macOS에서 시험할 수 없다. mux 수준 migration은 QUIC migration과 미확인 프레임 재전송을 다시 만들고, ADR-0007과 다른 새 재개 자격을 요구한다. 범위 밖이다.
- 제네릭 `Connection<C: MuxConn>`: Server, Ops, Session, Hub, StallLedger를 포함해 25개 넘는 파일로 번지고 테스트가 import 경로 밖까지 바뀌어 DoD (a)를 어긴다. `dyn` 객체: `open_bi`/`accept_bi`/`closed`가 boxed future가 되고 터널 pump의 read·write마다 vtable을 거친다. 둘 다 기각.
- `SO_KEEPALIVE`로 `keep_alive_ms` 구현: RTT 표본이 없고 OS마다 최소 단위가 다르며 `idle_timeout` 개념을 주지 못한다. 기각.
- TCP 전용 admission 키(`[serve].tcp_max_handshakes` 등): ADR-0010의 "표 하나" 규칙에서 갈라진다. 기각.

## 결과

- M14 (a)는 이 ADR의 승인 전에 착지할 수 있다(`docs/ROADMAP.md` M14 착수 조건). 결정 0이 그 모양이다. (c)는 승인 뒤에 연다.
- DoD (a)의 "`qsh-core` 비테스트 코드에 `quinn::` 경로가 남지 않음"은 결정 0의 arch 금지로 강제한다. 남는 자리는 없다.
- wire: application protocol과 `.proto` v1은 바뀌지 않는다. `docs/design/protocol.md` §16.2에 mux 행이 하나 더해진다. freeze 발효 전이므로 §16.1 목록도 같은 커밋에서 갱신한다.
- 계약: `qsh.cli/v1`에 additive `transport` 필드가 생기고 `capabilities.json` golden이 바뀐다. `hosts.toml`의 `transport` 키, `[transport].mode`, `[serve].tcp_bind`, `--transport`, `--tcp-bind`, 주소 scheme이 `docs/CLI.md`에 오른다.
- threat model: §3에 TCP listener와 mux 파서 진입점, §4 C에 행, §7에 `auto` downgrade h행이 핀 테스트와 함께 오른다.
- 사람 몫: mux codec fuzz 타깃의 누적 72 fuzz-hours(`docs/ROADMAP.md` §5.5).
- README Known limitations: TCP에서는 IP가 바뀌면 터널이 끊기고, 손실 아래와 Windows에서는 PTY 우선순위 예산이 없다.
