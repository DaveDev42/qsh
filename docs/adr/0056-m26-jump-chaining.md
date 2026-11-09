# ADR-0056: M26의 범위. `-J a[,b...]`를 주면 client가 첫 hop에 평소처럼 QUIC로 붙고, 그 연결 위의 새 스트림 `JUMP`로 다음 peer의 UDP 주소를 연 뒤 그 위에서 다음 QUIC 연결을 끝에서 끝으로 맺는다. 중간 peer는 안쪽 QUIC의 UDP 패킷을 바깥 연결의 QUIC DATAGRAM(자리가 없으면 같은 스트림)에 실어 나를 뿐 풀지 않는다. 각 hop은 그 hop의 pin으로, 끝단은 끝단 pin으로 확인한다. 중간 peer 쪽 인가는 새 action `forward.jump`다

날짜: 2026-11-09
상태: 승인됨

개정 관계: ADR-0050 결정 5의 M26을 구체화한다. 다음을 개정한다.
- ADR-0045 결정 2의 role 표와 PRD §9의 action 어휘. 새 action `forward.jump`를 더해 `Action::ALL`이 14종이 되고, `full`과 `tunnel`이 이 action을 준다(결정 18, Dave가 정할 것 2).
- ADR-0051 결정 7의 옵션 표에서 `-o ProxyJump`, `-J` 행("QUIC 경로의 점프는 M26 전까지 `UNSUPPORTED`")을 바꾼다(결정 20).
- ADR-0044 결정 6. 부트스트랩의 `ssh -G`가 `proxyjump`을 돌려주면 지금은 QUIC가 `hostname`으로 직접 가고 `ssh_proxied` 경고만 낸다. 이 ADR 뒤로는 그 값이 qsh pin으로 풀리면 pin의 `jump`에 적고 QUIC도 그 jump를 거친다(결정 21, Dave가 정할 것 4).
- ADR-0051 결정 2의 on-demand serve idle 종료 조건. 살아 있는 jump 채널도 센다(결정 9).
- `docs/design/protocol.md` §4(capability 하나), §7(스트림 표 한 행과 인라인 인가 예외 하나), §9(`StreamKind` 값 하나), §14와 §18.6(`DatagramFrame` 종류 하나), §11(역방향 route의 `JUMP`), 새 §21(jump).
- `docs/CLI.md` §2.2(전역 플래그), §2.5(`forward.jump` 행), §3.2(`details.jump`), §6.1(route), §6.8, §6.11(`trust jump`와 pin 필드), §6.17(doctor 코드 둘), §6.21(`qsh cp -J`), §7.2(옵션 표).

개정하지 않는 것: TLS 검증 경로(pin → CA → 거부, `docs/design/protocol.md` §3, §16.5), 0-RTT 금지(§2), 주소 검증되지 않은 Initial은 늘 Retry(ADR-0009), keep-alive 범위와 idle 45초 고정(ADR-0021), session resume 절차(§10), relay를 코어에 넣지 않는다는 것(PRD §14, ADR-0050 결정 3), 펀칭은 시작할 때 한 번이고 실패하면 포기한다는 것(ADR-0054), `-W`의 기각(ADR-0011 결정 5와 그 추기), qsh가 `ssh_config`를 직접 파싱하지 않는다는 것(ADR-0044 결정 4, ADR-0051 결정 8), "datagram은 선택 운반체이고 스트림만으로 완결된다"(ADR-0052 결정 7), 부트스트랩 ssh의 고정 옵션(ADR-0044 결정 9).

## 맥락

ADR-0050 결정 5는 M26을 "`-J`와 `ProxyJump`. 중간 peer가 다음 peer로의 QUIC를 터널로 잇고, 끝단 인증은 끝단 pin으로 한다"로 정했고 크기를 2ew로 잡았다. 결정 2의 SSH 호환 원칙은 흔한 옵션 목록에 `-J`를, `~/.ssh/config` 호환 대상에 `ProxyJump`를 이름으로 넣었다. 흔한 쓰임새는 둘이다. 공인 주소가 있는 bastion 하나를 거쳐 그 뒤 사설망의 장비에 붙는 것, 그리고 회사망처럼 들어가는 문이 하나뿐인 곳에서 그 문을 지나 여러 장비를 오가는 것이다.

### 지금 있는 것

- `-J`는 루트 ssh 형식에서만 파싱된다(`crates/qsh-cli/src/cli.rs`의 `jump`, `requires = "target"`). `crates/qsh-core/src/ssh_bootstrap/options.rs`의 `SshOptions::from_flags`가 `-J`와 `-o ProxyJump`를 부트스트랩 ssh 명령줄로 넘기고, 부트스트랩이 돌지 않는 이름(pin이 있거나 `--no-ssh`)이면 `refuse_quic_jump`가 "a jump on the QUIC path is not supported before M26"으로 `UNSUPPORTED`를 낸다(`crates/qsh-cli/src/main.rs`의 `auto_bootstrap_before_open`). `docs/CLI.md` §7.2의 옵션 표와 ADR-0051 결정 7이 같은 내용을 적는다. `qsh cp`는 scp의 `-J`를 숨김 플래그로 받아 다른 scp 플래그처럼 종료 2로 거부한다(§6.21, `scp_j`).
- 부트스트랩은 `ssh -G`에서 `hostname`·`user`·`proxyjump`·`proxycommand` 네 키를 읽는다(ADR-0044 결정 4, `docs/CLI.md` §7). `proxyjump`이 `none`이 아니면 ssh는 점프를 거쳐 원격에 닿지만 QUIC는 `hostname`으로 직접 가고, 사람 모드는 직접 닿지 않을 수 있다는 줄을, `data`는 `ssh_proxied: true`를 낸다(ADR-0044 결정 6). 되살리기 ssh도 같은 `-J`를 쓴다(ADR-0051 결정 4). pin이 있는 이름에는 ssh를 부르지 않는다(ADR-0051 결정 8).
- `TCP_CONNECT`(`-L`)는 요청자가 스트림을 열고 `StreamHeader{TCP_CONNECT, host, port}`를 보내면 host가 스트림을 여는 그 자리에서 `forward.local`을 판정하고(ticket 규칙의 유일한 예외, `docs/design/protocol.md` §7), 모양 검사(255바이트, 제어문자 거부, ADR-0019 결정 5), 해석 한 번, 선택적 host-local 필터(`deny_host_local`, ADR-0019 결정 3), `ConnectResult{ok, code, message}`, raw byte splice 순서로 간다. 구현은 `crates/qsh-core/src/server/tunnels.rs`의 `handle_tcp_connect`와 `authorize_and_dial_tunnel`이다. 터널 스트림은 `[serve].max_tunnel_streams_per_principal`(256)과 `max_tunnel_streams_per_forward`(64)에 들고(ADR-0010), 정체 장부(ADR-0037)가 본다.
- QUIC DATAGRAM은 `qsh-transport`가 켜 두었고 파사드는 `Connection::max_datagram_size()`, `send_datagram`, `read_datagram`이다. 송수신 버퍼는 각 64 KiB이고 송신 버퍼가 차면 가장 오래된 것부터 버린다(§14). datagram 머리는 16바이트 channel id와 종류 1바이트이고 종류는 10~13을 쓴다(`crates/qsh-proto/src/datagram.rs`, §18.6).
- ADR-0052의 측정(2026-11-05~06)은 qsh 안의 qsh를 이미 재 보았다. 20 Mbit, 손실이 있는 netem 링크에서 바깥을 DATAGRAM으로 나를 때 안쪽 p99가 913 ms, 스트림으로 나를 때 1880 ms였고 처리량은 2.10 대 1.64 MB/s였다. 최대 datagram 크기는 1500 링크에서 1452바이트, 1280 링크에서 1230바이트였다. 결정 12의 정책 입력 `nested`("이 연결이 jump나 proxy 안에 실려 있는가. M26이 세우는 값")와 손잡이 (f) 바깥 운반체("`nested`이고 바깥 연결에 `datagram`이 있으면 `Datagram`, 아니면 `Stream`. M26의 jump가 이 값을 읽는다")가 이 마일스톤을 기다린다.
- quinn을 실제 OS 소켓이 아닌 것 위에서 돌리는 길은 이미 있다. `qsh-transport`의 `PunchEndpoint`는 `Endpoint::new_with_abstract_socket`으로 quinn의 추상 소켓(`AsyncUdpSocket`)을 감싸고, `SocketSource::Virtual`이 testkit의 `netsim` 소켓을 받는다(ADR-0054, `docs/design/architecture.md` §1). `qsh-core`와 `qsh-cli`는 `quinn`을 이름으로 부를 수 없다(`xtask arch`).
- route 순서(`docs/CLI.md` §6.1, ADR-0054 결정 16)는 live 역방향 등록, pin 주소로 직접 dial, 1초 뒤 펀칭 병행, SSH 부트스트랩 pin의 되살리기, 모르는 이름의 자동 부트스트랩이다. recovery와 `--supervise`는 재dial마다 이 순서를 처음부터 돈다(ADR-0054 결정 18, §19.10).
- action 어휘는 13종이다(PRD §9, `qsh_core::acl::Action::ALL`). `acl.toml` 행에는 파일 action의 `paths` 말고는 목적지를 좁히는 키가 없다(PRD §9, `docs/design/architecture.md` §6). `tunnel` role의 `forward.local`은 host가 닿는 모든 TCP 목적지에 닿는다는 것이 ADR-0045의 잔여 위험이다.

### 다른 도구의 jump(개념만)

OpenSSH의 `-J a,b c`는 `a`에 SSH로 붙고, 그 연결의 `direct-tcpip` 채널(`-W`의 정체)로 `b:22`의 TCP를 열어 그 위에 `b`와의 SSH를 맺고, 같은 방법으로 `c`까지 간다. 각 hop은 client가 직접 인증하고 hop의 host key를 known_hosts로 확인한다. 중간 hop은 안쪽 SSH의 암호문만 본다. 안쪽이 TCP라서 바깥 TCP 위에 그대로 얹혀도 재전송이 겹치지 않는다. QUIC는 사정이 다르다. 안쪽 QUIC는 자기 손실 복구와 혼잡 제어를 가진 UDP 프로토콜이고, 이것을 신뢰 스트림 위에 얹으면 바깥의 재전송과 순서 보장이 안쪽의 손실 신호를 감추고 head-of-line 지연을 만든다. MASQUE의 CONNECT-UDP(RFC 9298)는 HTTP/3 위에서 UDP 흐름을 QUIC DATAGRAM(RFC 9221)에 실어 이 문제를 피하고, 안쪽 QUIC가 끝에서 끝으로 남는다. RFC 9221의 DATAGRAM은 바깥의 혼잡 제어를 받지만 재전송되지 않는다.

## Dave가 정할 것

1. jump를 지나는 운반 방식. (가) 중간 peer가 안쪽 QUIC 연결의 UDP 패킷을 바깥 연결의 QUIC DATAGRAM에 하나씩 실어 나르고, datagram에 자리가 없거나(바깥 경로의 MTU가 작음, 상대가 `datagram.v1`을 광고하지 않음) datagram이 사라지는 경로면 같은 채널의 신뢰 스트림에 길이를 붙여 싣는다(결정 4). (나) 안쪽 QUIC를 늘 신뢰 스트림 위에 싣는다(QUIC-over-stream). (다) `-L`처럼 client에 로컬 UDP 포트를 열어 중간 peer를 거쳐 끝단의 UDP 포트로 잇는 일반 UDP 포워딩을 만들고, 안쪽 QUIC는 그 로컬 포트로 dial한다. 추천은 (가). 안쪽 QUIC의 손실 복구, 혼잡 제어, migration이 끝에서 끝으로 남고, ADR-0052 결정 7("스트림만으로 완결된다")과 결정 12 (f)가 이미 이 모양을 정해 두었으며, 측정에서 안쪽 p99가 절반이었다. (나)는 구현이 가장 작지만(추정 -0.3ew) 손실 아래에서 재전송이 두 겹이 되고 안쪽 BBR이 손실을 보지 못한다. (다)는 로컬 포트를 같은 장비의 다른 프로세스도 쓸 수 있게 열고, 범위에 없는 UDP 포워딩 기능 하나를 새로 만들며, 그래도 운반체는 (가)나 (나) 가운데 하나를 골라야 한다.
2. 누가 `forward.jump`를 받나. (가) `full`과 `tunnel`, (나) `full`만, (다) 어느 role도 주지 않고 `qsh trust allow <peer> forward.jump`나 `acl.toml` 행으로만 준다. 추천은 (가). jump가 주는 능력은 "중간 peer의 자리에서 다른 주소의 UDP에 닿는 것"이고, 같은 두 role이 이미 주는 `forward.local`("host가 닿는 모든 TCP 목적지")과 같은 부류다. `tunnel` pin은 셸 없이 bastion 노릇만 하는 장비에 흔히 주는 role이라 여기서 빠지면 jump 전용 장비마다 `trust allow`가 한 번 더 든다. (다)는 "pin 한 번이 곧 권한"인 ADR-0045의 모델을 jump에서만 깨고 ADR-0050 결정 2의 설정 없는 기본과 맞지 않는다.
3. jump가 닿을 수 있는 목적지. (가) 중간 peer가 해석한 주소 가운데 host-local 범주(ADR-0019 결정 3의 loopback, unspecified, link-local, multicast, broadcast와 그 IPv4-mapped 표기)를 늘 빼고 나머지 모든 주소. 다만 목적지가 QUIC 모양으로 답하기 전에는 QUIC v1 long header 패킷만 몇 개 보낸다(결정 8의 "QUIC 문"). (나) 중간 peer가 주소와 함께 pin한 peer의 주소만. (다) (가)에 더해 `acl.toml` 행에 새 키 `targets`를 두어 좁힐 수 있게 한다. 추천은 (가). jump의 흔한 목적지는 bastion 뒤 사설망의 장비이고, (나)는 bastion이 그 장비를 모두 pin해 두어야 해서 bastion에 장비가 늘 때마다 손이 간다. QUIC 문이 있으면 이 권한으로 할 수 있는 일은 "QUIC로 답하는 서비스에 닿기"로 좁아지고, 중간 peer의 loopback 서비스(DNS, memcached 같은 UDP 서비스)에는 닿지 않는다. (다)는 `forward.local`에도 없는 목적지 축을 jump에만 만드는 일이라, 필요해지면 `forward.*` 전체를 덮는 새 ADR로 연다.
4. `~/.ssh/config`의 `ProxyJump`. (가) 부트스트랩이 이미 부르는 `ssh -G`가 돌려준 `proxyjump`을 쓴다. 그 값의 hop마다 qsh pin으로 풀리면(없으면 그 hop부터 부트스트랩한다) 끝단 pin의 `jump`에 적고 QUIC도 그 hop들을 거친다. 그 뒤 접속은 pin의 `jump`를 따르고 ssh를 부르지 않는다. (나) 읽지 않는다. `-J`, `-o ProxyJump`, `--jump`, pin의 `jump`(`qsh trust jump`)만 정한다. (다) 명령마다 `ssh -G <dest>`를 한 번 돌려 `proxyjump`을 읽는다(ADR-0051 결정 8 개정). 추천은 (가). ADR-0055 Dave가 정할 것 5(`ForwardAgent`를 읽지 않음)와 같은 줄에 서는 결정이지만 사정이 다르다. `proxyjump`은 ADR-0044 결정 4가 이미 읽는 네 키 가운데 하나라 새 ssh 호출이 없고, ADR-0050 결정 2는 `ProxyJump`를 `~/.ssh/config` 호환 대상으로 이름까지 적었다. 또 `ProxyJump` 뒤의 장비는 대개 pin 주소로 직접 닿지 않으므로, 기록하지 않으면 부트스트랩이 세운 pin이 다음 접속에서 쓸모없다. (다)는 pin이 있는 모든 접속에 자식 프로세스 하나와 사용자의 `Match exec` 실행을 더한다. 이 ADR 이전에 세운 pin은 기록이 없으므로 `qsh trust jump`로 적는다.
5. 이 장비의 `qsh listen` 데몬을 거쳐서만 닿는 첫 hop(첫 hop이 이 장비에 역방향 등록한 `qsh serve --to`). (가) 데몬이 CLI와의 `LOCAL_STREAM` 구간은 스트림 운반체로, 등록 연결 구간은 datagram 운반체로 바꿔 잇는다(결정 14). (나) `TCP_CONNECT`처럼 데몬이 바이트를 그대로 splice하고 그 경로 전체를 스트림 운반체로 둔다. (다) M26 범위 밖으로 두고 `UNSUPPORTED`. 추천은 (가). ADR-0050 결정 7은 정방향과 역방향이 같은 기능을 갖도록 요구하므로 (다)는 고를 수 없다. 노트북의 `qsh listen`에 집 서버가 등록해 있고 그 서버 뒤 LAN의 NAS로 가는 구성이 흔하다. localctl 구간은 같은 장비 안이라 손실이 없어서 스트림이어도 손해가 없고, 손실은 등록 연결 구간에서만 난다. (나)는 데몬 코드가 거의 없지만(추정 -0.2ew) 손실을 겪는 바로 그 구간에서 측정이 보여 준 손해를 그대로 진다.

## 결정

### 범위

1. 무엇을 하나.
   - `-J a[,b,...]`(또는 같은 뜻의 설정, 결정 20)를 준 명령이 첫 hop `a`에 이 장비의 route(결정 13·14)로 붙고, 그 연결로 다음 hop을, 그 다음 연결로 그다음 hop을 열어 끝단까지 간다. 끝단과의 QUIC 연결은 보통 연결과 같은 것이라 그 위의 모든 기능(셸, `-t` 명령, exec, `-L`·`-R`·`-D`, `qsh cp`, 화면 동기화와 예측, `-A`)이 바뀌지 않고 돈다(결정 15).
   - 대상 명령은 route로 host에 dial하는 모든 client 명령이다. `qsh [user@]host`, `qsh attach`, `qsh exec`, `qsh cp`, `qsh tunnel open`, `qsh session ...`, `qsh doctor <host>`가 `Ops`의 같은 connect 경로를 지나므로 같이 얻는다.
   - 중간 peer가 될 수 있는 것은 `qsh serve`(on-demand serve 포함)와 `qsh serve --to`다. `qsh listen`은 중간 peer가 되지 않는다. 그 프로세스는 등록 연결과 펀칭 연결만 받는다(`docs/CLI.md` §6.13, `docs/design/protocol.md` §19.9).
   - 범위 밖: relay로서의 jump(펀칭이나 직접 dial이 실패했을 때 자동으로 jump로 넘어가는 것. PRD §14와 ADR-0050 결정 3이 막는다), 중간 peer가 다음 hop을 펀칭하는 것, 역방향 등록만 있고 주소가 없는 host를 끝단으로 삼는 것(결정 14), OpenSSH가 qsh host를 jump로 쓰게 하는 `-W`(ADR-0011 결정 5와 그 추기, 결정 20), 바깥 연결이 다시 선 뒤에도 안쪽 연결을 살려 두는 것(결정 16), 여러 hop의 평탄한 relay(대안 절).

2. 층 배치.
   - `qsh-proto`: `StreamKind::JUMP`, `DatagramKind::JumpPacket`, 스트림 운반체의 길이 머리 decoder와 QUIC long header 불변 필드 읽기(`qsh_proto::jump`, sans-IO, 상한 검사). fuzz 표면이다.
   - `qsh-transport`: 패킷 관 `PacketPipe`(양방향 bounded queue, 구체 타입)와 그것을 소켓으로 쓰는 `Dialer::dial_over_pipe`. quinn 추상 소켓의 구현은 `PunchSocket` 옆의 이 한 곳이다. 관이 바깥 연결에서 무엇을 쓰는지는 모른다. 안쪽 endpoint는 client 쪽만 있고 서버 설정이 없다.
   - `qsh-core`: 새 모듈 `crates/qsh-core/src/jump/`. client 쪽(체인 해석, hop마다 `JUMP` 열기, 관과 운반체 잇기, 운반체 고르기, 실패 보고)과 중간 peer 쪽(인라인 인가, 해석, UDP 소켓, QUIC 문, 채널 표, 상한, 정리), 역방향 데몬의 운반체 번역(결정 14). 중간 peer는 안쪽 QUIC를 끝내지 않으므로 `qsh-transport`의 dial이나 TLS를 부르지 않는다.
   - `qsh-cli`: 플래그와 `trust jump`를 `Ops`에 넘기고 안내 줄을 렌더할 뿐이다.
   - `xtask arch`: 새 경로에는 `crates/qsh-core/src/`의 기존 금지(`quinn::`)가 그대로 걸린다. 새 금지 경로는 더하지 않는다.

### wire

3. capability `jump.v1`과 스트림.
   - 모든 빌드가 광고한다(상수 `CAP_JUMP_V1`, `LOCAL_CAPABILITIES`의 마지막 항목). 뜻은 이 peer가 중간 peer로서 `JUMP` 스트림과 종류 14 datagram을 처리한다는 것이다. client는 협상된 교집합에 이 문자열이 있는 hop에만 `JUMP`를 연다. 광고하지 않은 hop이면 아무것도 열지 않고 `UNSUPPORTED`다(결정 12의 stage `unsupported`).
   ```proto
   enum StreamKind { ...; JUMP = 7; }   // client -> 중간 peer
   // StreamHeader{kind = JUMP, ticket = jump_channel(정확히 16바이트), host, port}
   // 응답: ConnectResult{ok, code, message}. ok면 그 뒤로 u16 BE 길이 + 패킷 바이트의 반복
   // DatagramFrame 종류 14 JumpPacket: channel = jump_channel, 몸통은 패킷 바이트 그대로
   ```
   - `jump_channel`은 client가 CSPRNG로 만든다. ADR-0055 결정 3의 `agent_channel`처럼 client가 정하므로 응답보다 datagram이 먼저 오는 경주가 없다. 한 연결 안에서 쓰고 있는 값이거나 길이가 16이 아니면 `INVALID_ARGUMENT`다(ACL 전, audit 없음).
   - `host`와 `port`는 `TCP_CONNECT`와 같은 필드이고 같은 모양 검사(ADR-0019 결정 5)를 받는다. `port`는 1..=65535다. `deny_host_local`은 `JUMP`에서 읽지 않는다. host-local 거부는 늘 켜져 있다(결정 7).
   - 새 control message는 없다. `ConnectResult`는 §7의 것을 그대로 쓴다. 종류 14의 channel은 jump 채널 표에서만 찾고, 종류 10~13의 화면 channel과 섞이지 않는다. 모르는 channel의 datagram은 지금처럼 버리고 센다.
   - 몸통은 protobuf로 다시 싸지 않는다. 안쪽 QUIC 패킷은 이미 자기 경계를 가진 암호문이고, 터널이 raw bytes인 것(§5의 예외)과 같은 이유다.

4. 운반체 둘. Dave가 정할 것 1의 (가)다.
   - datagram 운반체: 패킷 하나가 종류 14 datagram 하나다. 머리는 17바이트(channel 16, 종류 1)다.
   - 스트림 운반체: 같은 `JUMP` 스트림에 `u16` BE 길이와 패킷을 잇는다. 길이 0이나 `JUMP_PACKET_MAX`(1452)를 넘는 길이는 `BAD_HEADER`(`0x2001`) reset이다. decoder는 선언된 길이로 버퍼를 미리 잡지 않는다(§5의 규율). 보내는 쪽은 아직 나가지 않은 바이트가 `JUMP_STREAM_QUEUE`(64 KiB)를 넘으면 새 패킷을 버리고 센다. 쌓아 두면 안쪽 혼잡 제어가 손실 대신 늘어난 지연만 보기 때문이다.
   - 받는 쪽은 언제나 둘 다 받는다. 보내는 쪽은 방향마다 따로 고른다. client는 C → 중간 peer 방향을, 중간 peer는 그 반대 방향을 자기 눈으로 고른다.
   - 고르는 규칙은 ADR-0052 결정 12 (f)와 (c)를 jump 채널에 옮긴 것이다. 양쪽이 `datagram.v1`을 광고했고 바깥 연결의 `max_datagram_size()`가 `JUMP_PACKET_MIN + 17`(1217) 이상이면 datagram, 아니면 스트림이다. datagram으로 보낸 지 4×srtt(바깥 연결)가 넘도록 그 채널로 datagram이 한 번도 돌아오지 않는데 스트림과 바깥 ack는 살아 있으면 스트림으로 바꾸고, 30초마다 datagram을 다시 시험한다. 바깥 자리가 1217 아래로 줄면 스트림으로 바꾼다.
   - datagram 모드에서 자리를 넘는 패킷은 스트림으로 돌리지 않고 버리고 센다. 돌리면 안쪽 PLPMTUD가 큰 패킷이 통한다고 배우고, 그 뒤 거의 모든 패킷이 스트림으로 간다. 버리면 안쪽 PLPMTUD와 black hole 감지가 자리에 맞춘다.
   - 바깥 연결의 `max_datagram_size()`는 바깥 PLPMTUD가 올리기 전에는 1200 아래다. 그래서 채널은 대개 스트림으로 시작해 자리가 생기면 datagram으로 바꾼다. 안쪽 handshake의 첫 패킷 몇 개가 스트림으로 가는 셈이다. 이 전환에 걸리는 시간은 구현 첫 스텝의 probe가 재고 개정 이력에 적는다.

5. MTU와 오버헤드.
   - 안쪽 endpoint는 `initial_mtu`·`min_mtu`를 1200(QUIC의 하한, `JUMP_PACKET_MIN`)으로, PLPMTUD 상한을 `JUMP_PACKET_MAX`로 둔다. 관은 MTU를 알리지 않고, 결정 4의 버림이 PLPMTUD에 자리를 가르친다. GSO는 쓰지 않는다(한 번에 한 패킷).
   - 한 겹마다 드는 비용은 datagram 머리 17바이트와, 그 겹을 나르는 QUIC 연결 자신의 머리·AEAD tag·DATAGRAM frame 머리(ADR-0052 측정에서 UDP payload와 최대 datagram의 차이로 약 20바이트)다. 한 겹에 약 40바이트다.
   - 그래서 1500 링크(최대 datagram 1452)에서는 안쪽 패킷 상한이 hop 하나에 1435, 둘에 약 1395, 셋에 약 1355, 넷에 약 1315로 모두 1200 위라 datagram 운반체로 간다. 1280 링크(1230)에서는 hop 하나(1213)까지 datagram이고 둘째부터 스트림이다. IPv6 최소 MTU 1280 경로는 UDP payload가 1232라 hop 하나부터 스트림이다. 이 계산은 결정 11의 hop 상한 넷의 근거이고, 상수와 표는 `jump_mtu_budget_table`이 고정한다.
   - 처리 비용은 client가 겹마다 한 번 더 암호화하는 것이다. 중간 peer는 바깥 겹만 풀고 안쪽은 풀지 않는다.

6. 흐름(hop 하나, client C, 중간 peer J, 끝단 T).
   - (1) C가 J에 route로 붙는다(결정 13·14). (2) C가 `jump_channel`을 만들고 `StreamHeader{JUMP, channel, host, port}`를 연다. `host:port`는 C의 trust store(또는 `hosts.toml`)에 있는 T의 pin 주소이고, C가 해석하지 않고 문자열 그대로 보낸다. 해석은 J가 한다(T가 J 뒤 사설망의 이름일 수 있어서다). (3) J가 결정 7의 순서로 판정하고 UDP 소켓을 만든 뒤 `ConnectResult{ok}`를 쓴다. (4) C는 `PacketPipe`를 만들어 한쪽 끝을 이 채널의 운반체에 잇고, 다른 쪽 끝으로 `Dialer::dial_over_pipe`를 불러 T와 handshake한다. 안쪽 연결의 검증은 결정 10이다. (5) 안쪽 연결이 서면 그것이 이 명령의 연결이다.
   - hop이 여럿이면 (2)~(5)를 직전 단의 연결 위에서 되풀이한다. 각 단은 같은 모양이다. 관 위의 연결이 다음 관의 바깥 연결이 된다.
   - 전체가 명령의 dial 시한(10초, `-o ConnectTimeout`이 바꾼다) 하나 안에서 끝나야 한다. 단마다 남은 시한을 쓴다.

### 중간 peer

7. 처리 순서. 앞 단계가 실패하면 뒤 단계는 돌지 않는다. 인가 전에는 소켓도 채널도 만들지 않는다.
   - (1) 모양 검사: channel 길이와 중복, `host` 모양, `port`. 실패는 `INVALID_ARGUMENT`이고 ACL도 audit도 없다.
   - (2) `forward.jump` 판정과 감사. `resource`는 요청한 `host:port` 문자열이다(`forward.local`과 같다). 평가 순서(항상-deny 게이트, role, pin grant, `acl.toml` 행)와 파싱할 수 없는 `acl.toml`의 전부 거부는 그대로다. 감사를 쓰지 못하면 거부다.
   - (3) 상한(결정 9). 초과는 `RESOURCE_EXHAUSTED`.
   - (4) 해석 한 번, 시한 5초(`JUMP_RESOLVE_TIMEOUT`). 실패는 `CONNECTION_FAILED`.
   - (5) host-local 거부. 해석된 주소마다 ADR-0019 결정 3의 범주를 보고 걸리는 주소를 뺀다. 남는 주소가 없으면 `PERMISSION_DENIED`이고 dial 필터와 같은 모양의 감사 한 줄(`action=forward.jump, decision=deny, rule=null`)을 더 쓴다. 해석된 IP는 감사에도 로그에도 남기지 않는다. 남은 주소 가운데 해석 순서의 첫 주소를 쓴다(UDP라 하나씩 시도해 볼 수 없다).
   - (6) 그 family의 unspecified 주소, 포트 0에 UDP 소켓을 bind하고 고른 주소로 `connect`한다.
   - (7) `ConnectResult{ok}`를 쓰고 채널을 표에 올린다.
   - 거부의 teardown은 `TCP_CONNECT`와 같다(§7 "거부 teardown"). `ConnectResult`를 먼저 쓰고 송신 half를 `finish()`하고 수신 half를 사유에 맞는 코드로 `stop()`한다. 원격 peer가 받는 `PERMISSION_DENIED`의 문면은 균일 문면이다.
   - 이 인라인 판정은 `TCP_CONNECT`가 쓰는 ticket 규칙의 예외(§7)를 `JUMP`로 넓힌 것이다. 같은 이유(연결마다 RPC 왕복을 피함)이고 같은 규칙(스트림을 여는 그 자리에서 판정, 거부면 아무것도 만들지 않음)이다.

8. UDP 소켓과 QUIC 문.
   - 소켓은 `connect`된 소켓이라 고른 주소 하나에서 온 datagram만 받는다. 다른 출발지가 이 포트로 보낸 것은 커널이 버린다. 그래서 제3자가 채널에 끼어들거나 J를 반사기로 쓸 수 없다.
   - QUIC 문. Dave가 정할 것 3의 (가)다. 채널이 열린 뒤 T가 QUIC 모양으로 답하기 전까지 J는 C에서 온 패킷 가운데 QUIC v1 long header(첫 바이트의 상위 두 비트 `11`, version `0x00000001`)이고 길이가 1200 이상인 것만 T로 보낸다. 그 수는 여덟(`JUMP_PREGATE_PACKETS`), 합은 16 KiB(`JUMP_PREGATE_BYTES`)까지다. T에서 온 첫 패킷이 long header이고(Retry, Initial, Version Negotiation 어느 것이든) 그 DCID가 C가 보낸 패킷 가운데 하나의 SCID와 같으면 문이 열리고, 그 뒤로는 양방향 모든 패킷을 나른다. 문이 열리기 전에 T에서 온 다른 패킷은 버린다. 10초 안에 문이 열리지 않으면 채널을 닫는다.
   - 이 검사는 QUIC가 평문으로 두는 불변 필드(version, connection ID)만 읽는다. 경로 위의 누구나 보는 값이고, 안쪽 암호문은 건드리지 않는다. 판독기는 `qsh_proto::jump::read_long_header`이고 fuzz 표면이다.
   - J가 T로 보내는 바이트는 C에서 받은 바이트를 넘지 않는다. J는 패킷을 만들지 않는다.
   - T의 소켓에서 ICMP 거부(`ECONNREFUSED`, Windows는 `WSAECONNRESET`)를 받으면 J는 스트림을 `0x2007`로 reset하고 채널을 닫는다. C는 그 reset을 보고 handshake 시한을 기다리지 않고 끝낸다(결정 12의 stage `unreachable`). 값으로 분기하지 않고 "정상 종료가 아니다"만 읽는다(§16.5).

9. 상한, 수명, 정리.
   - 한 연결에 동시에 열린 jump 채널은 16개(`MAX_JUMP_CHANNELS_PER_CONN`)다. `JUMP` 스트림은 터널 스트림으로 세어 `max_tunnel_streams_per_principal`(256)과 `max_tunnel_streams_per_forward`(64, `(principal, host:port)` 축)에 든다(ADR-0010). 정체 장부(ADR-0037)도 `JUMP` 스트림을 본다.
   - 채널은 양방향 어느 쪽으로도 60초(`JUMP_IDLE`) 동안 패킷이 없으면 닫는다. 안쪽 idle 45초보다 길어 살아 있는 안쪽 연결을 J가 먼저 끊지 않는다.
   - `JUMP` 스트림이 끝나면(정상 종료, reset, 바깥 연결 종료) 채널과 소켓을 함께 닫는다. 스트림이 채널의 수명이다.
   - on-demand serve의 idle 종료(ADR-0051 결정 2)는 살아 있는 jump 채널도 센다. 채널이 하나라도 있으면 idle이 아니다. 세지 않으면 jump만 하는 연결이 도는 도중에 중간 peer의 serve가 내려간다.
   - 우선순위 band는 `JUMP` 스트림이 session band(100)다. 안쪽 연결이 무엇을 나르는지 J는 모르고, 안쪽의 bulk 양보(ADR-0052 결정 12 (a))가 끝에서 끝으로 돈다.

### 인증

10. 각 단은 그 단의 pin으로 확인한다.
    - 첫 hop은 지금의 TLS 검증(§3)이다. 둘째 hop부터와 끝단은 관 위의 handshake에서 상대가 내민 fingerprint가 C의 trust store에 있는 그 이름의 pin과 정확히 같을 때만 받는다. trust store의 다른 pin이나 CA 경로로 통과하는 인증서는 받지 않는다. 다르면 `0x1001`로 닫고 `AUTH_FAILED`다(ADR-0054 결정 12, §19.4와 같은 규칙). 중간 peer가 목적지를 C가 믿는 다른 장비로 바꿔치기하는 길을 막는다.
    - 그래서 jump로 닿는 단은 모두 C가 fingerprint로 pin한 상대여야 한다. pin이 없으면 결정 21의 부트스트랩이 세우거나 `HOST_NOT_FOUND`다.
    - 반대 방향도 같다. 각 단은 C의 인증서를 자기 trust store로 검증하고, 판정은 그 단이 C에게 준 role과 행으로 한다. T가 보는 principal은 C이지 J가 아니다. T가 보는 peer 주소는 J의 소켓 주소다.
    - resume token은 route가 아니라 peer 신원에 묶여 있으므로(§10) jump로 연 세션을 jump 없이, 또는 다른 jump로 다시 붙일 수 있다.

### 체인

11. hop 해석과 상한.
    - `-J`의 값은 쉼표로 나눈 ssh 목적지 목록이다(`[user@]host[:port]`). qsh 쪽에서 각 항목은 `[user@]host`를 pin 이름으로 찾는다(ADR-0044 결정 7의 이름 규칙). `:port`는 sshd 포트이고 부트스트랩 ssh에만 쓴다(ADR-0051 결정 7의 "ssh 옵션은 ssh 경로를 설명한다").
    - hop의 pin에 `jump`가 있으면 그 hop 앞에 펼친다. 끝단 `c`의 pin이 `jump = ["b"]`이고 `b`의 pin이 `jump = ["a"]`이면 체인은 `a, b, c`다. OpenSSH가 `ProxyJump`를 재귀로 따르는 것과 같다.
    - 펼친 뒤 hop은 넷까지다(`MAX_JUMP_HOPS`, 결정 5의 MTU 계산). 넘거나, 같은 pin이 두 번 나오거나, 끝단이 hop에 들어 있으면 아무것도 dial하기 전에 `INVALID_ARGUMENT`다.
    - 모든 hop과 끝단을 dial 전에 pin으로 푼다. 주소가 없는 pin은 stage `address`의 `HOST_NOT_FOUND`다. 주소는 C가 해석하지 않으므로 C에서 해석되지 않는 이름이어도 된다.

12. 실패 보고.
    - 체인의 어느 단에서 실패했는지를 `error.details`의 `jump`가 알린다. `{"hop": 2, "hops": 3, "name": "b", "stage": "auth"}`의 꼴이다. `hops`는 hop 수에 끝단 하나를 더한 값이고, `hop`은 1부터 센 실패한 단의 자리, `name`은 그 단의 pin 이름이다. 끝단에서 실패하면 `hop`이 `hops`와 같다.
    - `stage`의 어휘는 닫혀 있고 envelope의 `code`가 그에 따른다. `address`(pin이 없거나 주소가 없음, `HOST_NOT_FOUND`), `dial`(첫 hop에 붙지 못함, route가 낸 `CONNECTION_FAILED`·`TIMEOUT` 그대로), `unsupported`(앞 단이 `jump.v1`을 광고하지 않음, `UNSUPPORTED`), `denied`(앞 단이 `forward.jump`나 host-local 거부로 거절, `PERMISSION_DENIED`), `resolve`(앞 단이 이름을 풀지 못함, `CONNECTION_FAILED`), `limit`(앞 단의 상한, `RESOURCE_EXHAUSTED`), `unreachable`(앞 단의 소켓이 ICMP 거부를 받음, `CONNECTION_FAILED`), `handshake`(앞 단을 지나 답이 없음, `TIMEOUT`), `auth`(fingerprint가 pin과 다름, `AUTH_FAILED`).
    - `details.jump`는 client가 쓴다. client는 어느 단에 무엇을 요청했는지 알고, 중간 peer의 거부 문면은 지금처럼 균일하다. 첫 hop의 route에 펀칭이 있었으면 `details.punch`(ADR-0054 결정 17)가 함께 붙는다.
    - 사람 모드는 오류 줄 앞에 `jump 2/3 (b): `를 붙인다. 종료 상태는 qsh 자신의 실패이므로 255다.

### 다른 기능과의 관계

13. 펀칭(ADR-0054).
    - 첫 hop은 이 장비의 평소 route로 닿으므로 직접 dial, 펀칭(결정 16의 경주), SSH 부트스트랩 pin의 되살리기를 모두 쓴다. `--rendezvous`와 `--no-punch`는 첫 hop에 걸린다.
    - 둘째 hop부터와 끝단은 앞 단의 UDP dial로만 닿는다. 중간 peer는 펀칭의 시작하는 쪽(A)이 되지 않는다.
    - jump가 있는 host는 직접 dial이나 펀칭과 경주하지 않는다. `-J`나 pin의 `jump`가 있으면 그 host의 route는 jump 체인 하나다(ssh의 `ProxyJump`와 같은 뜻). 거꾸로 직접 dial이나 펀칭이 실패했다고 jump로 넘어가지도 않는다(결정 1의 범위 밖).

14. 역방향 route. Dave가 정할 것 5의 (가)다.
    - 첫 hop이 이 장비의 `qsh listen` 데몬에 live 역방향 등록을 들고 있으면 route의 (1)대로 데몬을 거친다. CLI는 `LOCAL_STREAM` conduit에 `StreamHeader{JUMP, channel, host, port}`를 보내고, 데몬은 등록 연결 위에 같은 header로 `JUMP`를 연다. 첫 hop(`qsh serve --to`)이 결정 7을 그대로 한다.
    - 데몬은 `ConnectResult`를 그대로 건넨 뒤 운반체를 바꿔 잇는다. CLI 쪽 구간은 스트림 운반체이고(같은 장비 안이라 손실이 없다), 등록 연결 구간은 결정 4의 규칙으로 datagram과 스트림을 고른다. 데몬은 패킷의 길이 머리만 읽고 내용은 보지 않는다. CLI 쪽 구간의 큐 상한은 `JUMP_STREAM_QUEUE`다.
    - 데몬이 한 번에 드는 jump 채널은 hub마다 32개(`MAX_JUMP_CHANNELS_PER_HUB`)다. `qsh.local.v1`은 동결 밖이고(§16.3) 새 `LocalStreamKind`는 만들지 않는다.
    - 역방향 등록만 있고 주소가 없는 host를 끝단으로 삼는 것은 범위 밖이다. 그런 host에 다른 장비에서 닿는 길은 M24의 펀칭이고, 이 장비의 데몬이 등록을 들고 있으면 route의 (1)로 바로 닿는다. pin에 주소가 없으면 stage `address`다.

15. 그 밖의 기능.
    - 끝단 연결 위의 기능은 모두 그대로다. `-L`·`-R`·`-D`, `qsh cp`, 화면 동기화, 예측, 상태 줄이 안쪽 연결에서 돈다. 중간 peer는 그 어느 것의 인가에도 끼지 않는다. 판정은 끝단이 C의 role로 한다.
    - `-A`(ADR-0055)는 끝단에만 간다. agent 소켓은 끝단 host에 생기고 `AGENT` 스트림은 안쪽 연결을 지나므로 중간 peer는 agent 바이트를 암호문으로만 본다. OpenSSH의 `ProxyJump`도 jump host에는 agent를 넘기지 않는다.
    - `-N`, `-f`, `~.`, 종료 상태는 그대로다.

16. recovery, migration, `--supervise`.
    - 체인은 하나의 단위다. 어느 단의 연결이 죽으면 그 위의 관이 닫혀 위의 연결이 모두 죽고, 끝단 연결도 죽는다.
    - Tier 1(migration). C의 주소가 바뀌면 첫 hop과의 연결만 migration을 한다(§2). 그 위의 관과 연결은 바뀌는 것이 없고, J의 UDP 소켓이 그대로라 T도 아무것도 보지 않는다.
    - Tier 2(resume). 끝단 연결의 PathWatch가 경로 사망을 선언하면(§10 "Path 사망 감지") recovery가 체인을 처음부터 다시 세우고(첫 hop의 route는 ADR-0054 결정 18대로 다시 돈다) 새 끝단 연결에서 §10의 reattach를 한다. 재dial 시도 하나의 시한은 첫 hop의 시한(`REDIAL_DEADLINE` 2초, 펀칭할 수 있으면 펀칭 예산)에 hop마다 1초를 더한 값이고 명령의 첫 dial 시한 10초를 넘지 않는다. 살아 있는 앞 단 연결은 다시 써도 된다. 결과는 같다.
    - 바깥 연결이 다시 선 뒤 새 채널로 옛 안쪽 연결을 이어 붙이는 것(T가 보기에 출발지 포트가 바뀌는 안쪽 migration)은 하지 않는다. PathWatch가 이미 사망을 선언한 연결을 되살리는 길이 두 갈래가 되고, resume이 같은 일을 이미 한다.
    - `--supervise` 터널의 재dial도 같은 체인을 다시 세운다(ADR-0023, ADR-0054 결정 18). `-L`·`-D`·`-R` 어느 쪽이든 같다.

17. 적응 정책(ADR-0052 결정 12).
    - 관 위의 연결은 `Observed.nested`가 참이다. `datagram` 입력은 그 연결 자신의 값이고, (f) 바깥 운반체는 결정 4의 규칙이 jump 채널에서 읽는다.
    - `qsh doctor <host>`의 `transport.nested`가 참이 되고, `reasons`에 운반체가 스트림인 이유(`datagram_unavailable`, `datagram_room`, `datagram_unacked`)가 실린다.
    - 그 밖의 손잡이(bulk 양보, 화면 주기, 예측, keep-alive)는 끝단 연결의 관측값으로 그대로 돈다. 측정이 끝에서 끝이므로 hop마다 따로 둘 것이 없다.

### 인가와 감사

18. 새 action `forward.jump`.
    - 판정 자리는 결정 7의 (2)다. role 표는 `full`과 `tunnel`이 준다(Dave가 정할 것 2). `acl.toml` 행과 `qsh trust allow <peer> forward.jump`도 이 이름을 받고, `acl show`의 실효 action과 `acl check`가 따라온다. 항상-deny 게이트에는 넣지 않는다.
    - 이름을 `forward.*` 계열에 두는 이유는 `-L`·`-R`·`-D`·`-A`가 이미 그 계열이고 jump가 그것들처럼 "이 host의 자리에서 다른 곳에 닿는 것"이어서다. `allow = ["forward.*"]` 행은 업그레이드 뒤 이 action도 얻는다. `forward.agent`와 달리 이것은 실제로 넓어지는 권한이다(`forward.local`이 TCP로 닿는 곳에 QUIC로 답하는 UDP 서비스가 더해진다). 이 점을 PRD §9와 `docs/CLI.md` §2.5에 적는다.
    - 목적지 축은 두지 않는다(Dave가 정할 것 3). host-local 거부와 QUIC 문(결정 7·8)이 모든 principal에 같이 걸린다.

19. 감사와 로그.
    - 중간 peer는 `forward.jump` 판정마다 감사 한 줄을 쓴다. `action`은 `forward.jump`, `resource`는 요청한 `host:port`, `peer_addr`는 C의 주소다. 결정 7 (5)의 host-local 거부는 한 줄을 더 쓴다. 채널 하나하나의 패킷이나 종료는 감사하지 않는다(`TCP_CONNECT` 스트림의 splice가 감사되지 않는 것과 같다).
    - 끝단은 지금처럼 C의 principal로 감사하고 `peer_addr`는 J의 주소다. 두 감사를 맞추면 누가 어디를 거쳐 왔는지 나온다.
    - 새 tracing target `qsh::jump`. client는 `chain_up`(hop 수, 단마다 운반체, 걸린 시간), `carrier_changed`(단, 이전과 이후, 사유), `chain_failed`(단, stage)를, 중간 peer는 `channel_opened`, `gate_opened`, `channel_closed`(나른 패킷 수와 바이트, 버린 수, 사유 `idle`·`stream_end`·`unreachable`·`gate_timeout`)를 한 줄 JSON으로 낸다. 해석된 IP, 패킷 내용, connection ID, channel 값은 싣지 않는다. 기본에서 꺼져 있고 `-v`나 `QSH_LOG=qsh::jump=info`가 켠다.

### 사용자 표면

20. 플래그, pin 필드, 우선순위.
    - `-J hops`는 루트 ssh 형식, `qsh cp`(scp의 `-J`), `qsh exec`, `qsh attach`, `qsh tunnel open`, `qsh session open`이 받는다. 모든 하위 명령은 전역 `--jump <hops>`도 받는다(`--rendezvous`와 같은 자리, `docs/CLI.md` §2.2). `-J none`과 `--jump none`은 이번 명령에서 pin의 `jump`를 끄고 평소 route로 간다.
    - `-o ProxyJump=hops|none`. qsh가 읽는 `-o` 키에 더한다(ADR-0051 결정 7의 표). 같은 키를 여러 번 주면 첫 값이 이긴다. 부트스트랩 ssh에는 지금처럼 그대로 간다.
    - pin 필드 `jump`(pin 이름의 배열). `trust.toml`의 `[[peer]]`에 붙는 optional 키이고 비었으면 키가 없다. 새 명령 `qsh trust jump <name> [<hop>...] [--clear]`(op `trust.set_jump`, 인가 불요, ADR-0054의 `trust rendezvous`와 같은 꼴)가 직접 정하고, 결정 21의 부트스트랩이 적는다. 명령줄의 `-J`는 저장하지 않는다.
    - 우선순위: `-J`/`--jump` → `-o ProxyJump` → pin의 `jump` → 평소 route. `config.toml`에는 키를 두지 않는다. jump는 목적지마다 다른 값이고, host마다의 설정은 pin에 둔다는 것이 `rendezvous`의 선례다. `hosts.toml`은 손으로 쓰는 주소록이라(§6.1) 거기 두면 ADR-0050 결정 2의 "설정 파일을 열지 않는다"와 맞지 않는다.
    - 대화형 질문은 두지 않는다. `-J`가 곧 답이다.
    - `-W`는 지금처럼 이름을 대며 거부한다(`UNSUPPORTED`, exit 255). OpenSSH의 `ProxyJump`는 안에서 `-W`를 쓰지만 qsh의 jump는 그것이 필요 없고, ADR-0011의 추기가 닫은 검토를 다시 열 사용례가 이 마일스톤에서 생기지 않았다.
    - `docs/CLI.md` §2.2, §6.8, §6.11, §6.21, §7.2를 고치고 `cargo xtask man`으로 man page를 다시 만든다.

21. 부트스트랩과 `ProxyJump`. Dave가 정할 것 4의 (가)다.
    - pin이 없는 끝단에 `-J`(또는 `ssh -G`의 `proxyjump`)가 걸려 있으면 부트스트랩은 지금처럼 ssh로 점프를 지나 원격에 닿는다(ADR-0044 결정 6). 다른 점은 그 뒤다. `proxyjump`의 hop마다 qsh pin을 찾고, 없는 hop은 앞의 hop들을 ssh `-J`로 주어 차례로 먼저 부트스트랩한다(각 hop의 설치 동의와 질문은 ADR-0051 결정 3 그대로). 모든 hop이 pin으로 풀리면 끝단 pin의 `jump`에 그 이름들을 적고, 확인 dial(ADR-0044 결정 13)과 접속이 jump를 거친다.
    - hop 하나라도 qsh pin을 세우지 못하면(원격이 설치를 거부했거나 `--no-install-remote`) `jump`를 적지 않고 지금 동작(직접 QUIC와 `ssh_proxied` 경고)으로 물러선다. 사람 모드는 어느 hop이 막았는지 한 줄을 더 낸다.
    - `jump`를 적었으면 사람 모드는 stderr에 `qsh: <name> is reached through <hops>; change it with qsh trust jump` 한 줄을 낸다. `data`에는 additive `jump`(배열)가 실린다.
    - 중간 peer 쪽 pin은 부트스트랩의 원격 pin role(`full`, ADR-0044의 `--role`)을 받으므로 `forward.jump`가 따라온다.
    - pin이 있는 이름에는 지금처럼 ssh를 부르지 않는다(ADR-0051 결정 8). 이 ADR 이전에 세운 pin에는 `jump`가 없고, `qsh trust jump`로 적는다.

22. JSON과 doctor. 모두 additive다.
    - `capabilities` 결과의 새 문자열 `jump.v1`(`capabilities.json` golden을 `QSH_UPDATE_FIXTURES=1`로 다시 만들고 계약 변경과 같은 무게로 본다).
    - `error.details.jump`(결정 12). 실패가 jump 체인 안에서 났을 때만 붙어 기존 오류 fixture는 그대로다.
    - `TrustPeer.jump`(`trust.list`, `trust.get`), `trust.set_jump`의 결과, 부트스트랩 결과의 `jump`, action 어휘의 `forward.jump`(`acl.check`·`acl.show`).
    - doctor 코드 둘: `jump_stream_carrier`(info, 이 host로 가는 체인의 어느 단이 스트림 운반체로 돈다. 사유를 함께 싣는다)와 `jump_hop_missing`(warn, pin의 `jump`가 이 trust store에 없는 이름을 가리킨다. remedy는 `qsh trust jump <name> ...`). `EXPECTED_DOCTOR_CODES`에 더한다.
    - 새 fixture: `error.PERMISSION_DENIED.jump_denied.json`, `error.AUTH_FAILED.jump_target_pin.json`, `error.TIMEOUT.jump_handshake.json`, `trust.set_jump.json`, `trust.list.jump.json`, `acl.show.forward_jump.json`, `doctor_jump_stream_carrier.json`. `REQUIRED_FIXTURES`에 올리고 기존 fixture는 고치지 않는다. 기계 모드 stdout은 지금처럼 JSON뿐이고, 결정 12·21의 안내 줄은 사람 모드 stderr에만 나온다.

### 보안

23. 중간 peer가 보는 것과 보지 못하는 것.
    - 보는 것: C의 신원(바깥 연결의 인증서), 요청한 `host:port`와 그것을 해석한 주소, 안쪽 패킷의 크기와 시각, QUIC 불변 필드(version, connection ID), 안쪽 Initial 패킷의 ClientHello와 ServerHello(Initial 보호는 DCID에서 유도되는 공개 키라 누구나 풀 수 있다. qsh는 SNI를 보내지 않으므로 이름은 없고 ALPN `qsh/1`과 키 교환 값이 보인다).
    - 보지 못하는 것: 양쪽 인증서(TLS 1.3이 Handshake 패킷 안에서 암호화한다), 안쪽 control message, PTY 입출력, exec argv와 출력, 터널과 파일 바이트, agent 메시지, resume token. 안쪽 TLS는 C와 T 사이에서 끝나고 J는 그 키를 갖지 않는다.
    - 할 수 있는 것: 패킷을 버리거나 늦추거나 순서를 바꾸는 것(가용성), 시각과 크기로 트래픽을 분석하는 것. 바꾸거나 다시 보낸 패킷은 안쪽 AEAD와 패킷 번호가 버린다. 목적지를 다른 장비로 돌리면 결정 10이 막는다.
    - 그래서 jump는 PRD §14가 relay에 요구한 "payload와 endpoint private key를 볼 수 없어야 한다"를 지킨다. jump가 relay와 다른 점은 사용자가 이름으로 고르고 pin과 `forward.jump`로 허락한 자기 장비라는 것, 그리고 자동으로 끼어들지 않는다는 것이다.

### 위협 모델

24. 새 행과 고정 테스트.
    - A24 스푸핑. 중간 peer가 안쪽 연결을 C가 믿는 다른 장비로 돌린다, 또는 hop 자신이 다른 인증서를 낸다: 단마다 그 이름의 pin과 fingerprint가 정확히 같아야 한다(`a_jump_redirect_to_another_pinned_peer_fails_with_auth_failed`, `jump_pin_mismatch_at_a_hop_and_at_the_end`).
    - B49 무단접근. `forward.jump`가 없는 peer가 중간 peer에서 UDP를 보낸다: 인라인 판정이 소켓보다 먼저이고 감사된다(`jump_without_forward_jump_opens_no_socket`, `role_grants_table`의 `forward.jump` 열).
    - B50 무단접근. jump를 중간 peer의 loopback 서비스나 QUIC가 아닌 UDP 서비스로 쓰는 SSRF: host-local 거부와 QUIC 문(`jump_refuses_host_local_targets`, `a_jump_forwards_only_quic_until_the_target_answers_like_quic`).
    - B51 무단접근. 제3자가 중간 peer의 채널 포트로 datagram을 넣는다: `connect`된 소켓(`a_jump_socket_drops_datagrams_from_other_sources`). 넣더라도 안쪽 AEAD가 버린다.
    - C27 자원고갈. 채널·소켓 홍수, 스트림 운반체의 큐, 문 앞의 패킷: 연결당 16, 터널 quota, hub당 32, 60초 idle, 64 KiB 큐, 문 앞 여덟 패킷·16 KiB·10초(`jump_bounds`).
    - C28 자원고갈. 중간 peer를 증폭기로 쓴다: J가 T로 보내는 바이트는 C에서 받은 바이트를 넘지 않고, 반대 방향은 바깥 혼잡 제어가 묶는다(`a_jump_never_sends_more_than_it_received`).
    - D25 정보노출. 중간 peer가 안쪽 평문을 본다: 안쪽 TLS가 끝에서 끝이다(`a_jump_never_sees_inner_plaintext`가 J를 지나는 모든 바이트를 기록해 PTY 입출력, exec argv, 파일 내용, agent 서명 데이터에 넣은 표지와 두 장비의 인증서 DER이 한 번도 나오지 않음을 본다).
    - D26 정보노출. 감사·로그·JSON에 해석된 IP, 패킷 내용, connection ID가 샌다(`jump_audit_and_logs_carry_no_payload`).
    - E27 무결성. 중간 peer가 안쪽 패킷을 바꾸거나 다시 보낸다: 끝단이 버리고 세션 바이트는 그대로다(`inner_packets_altered_by_a_jump_are_dropped_by_the_end`).
    - E28 파서 표면. 적대적 바이트로 스트림 운반체 decoder나 long header 판독기가 panic하거나 상한을 넘는다: 새 fuzz 타깃 `jump_frames`(분할된 길이 머리, 길이 경계, long header 변형), `decode_stream_header` corpus에 kind 7, `decode_datagram_frame` corpus에 종류 14.
    - F7 부인방지. 누가 어디를 거쳤는지 남지 않는다: 중간 peer와 끝단 양쪽에 C의 principal이 남는다(`jump_audit_names_the_requester_on_both_hops`).
    - G13 가용성. 체인의 한 단이 죽거나 C의 경로가 바뀐다: migration은 첫 단에서 끝나고, 죽으면 체인을 다시 세워 resume한다(`outer_migration_is_invisible_to_the_inner_connection`, `a_session_through_a_jump_resumes_after_the_hop_link_dies`).
    - 잔여 위험 다섯을 §7에 더한다(결과 절).

### 수용 기준(M26 DoD)

25. 1. 한 hop. loopback의 진짜 UDP 위에서 `-J`를 준 PTY 세션, `-t` 명령, exec, `-L`, `-D`, `-R`, `qsh cp`(파일 BLAKE3 일치), `-A`가 끝난다(`jump_one_hop_runs_every_feature`, L3).
    2. 두 hop. `-J a,b`로 같은 시험의 세션·exec·`qsh cp`가 끝나고, pin의 `jump` 펼치기(`c → b → a`)로 같은 체인이 선다(`jump_two_hops_and_recursive_pins`).
    3. 손실 아래 체인. netsim에서 C–J–T와 C–a–b–T의 링크마다 단방향 25 ms 지연과 3% 손실(seed 고정)을 걸고, 세션 입출력이 무손실·무중복이며 `qsh cp`의 해시가 맞고 연결이 끝까지 산다(`jump_chain_under_loss_on_every_link`). 같은 조건에서 datagram 운반체와 스트림 운반체의 안쪽 echo p95를 함께 찍고, datagram 쪽이 작다.
    4. 운반체. 바깥 자리가 1217 이상이면 datagram, `datagram.v1`이 없거나 1280 링크의 둘째 hop이거나 IPv6 최소 MTU 경로면 스트림이고(`jump_carrier_selection_table`, `jump_mtu_budget_table`), 바깥 PLPMTUD가 자리를 연 뒤 스트림에서 datagram으로 바뀌며(`jump_carrier_switches_to_datagram_after_pmtud`), 자리를 넘는 패킷은 버려지고 세어진다. datagram을 버리는 중간 장비(netsim)에서 스트림으로 물러선다.
    5. 평문 없음. `a_jump_never_sees_inner_plaintext`(결정 24 D25).
    6. pin 불일치. 첫 hop의 fingerprint가 pin과 다를 때, 둘째 hop을 중간 peer가 C가 pin한 다른 장비로 돌렸을 때, 끝단이 다를 때 각각 `AUTH_FAILED`이고 `details.jump`가 그 단을 가리키며, 끝단에 세션도 exec도 생기지 않는다(`jump_pin_mismatch_at_a_hop_and_at_the_end`, `a_jump_redirect_to_another_pinned_peer_fails_with_auth_failed`).
    7. 인가와 감사. `forward.jump` 없는 role(`exec`, `read-only`, `reverse`, `none`)과 role 없는 pin은 `PERMISSION_DENIED`, stage `denied`이고 소켓이 없다. 각 판정이 감사 파일에 구조 필드만으로 남고, 감사 쓰기가 실패하면 거부다. host-local 목적지는 role과 무관하게 거부되고 감사 한 줄이 더 남는다. 결정 24의 B50·B51·C28 시험.
    8. 상한과 수명. `jump_bounds`, 60초 idle 뒤 채널과 소켓이 없음, on-demand serve가 jump 채널이 있는 동안 내려가지 않음(`on_demand_serve_stays_up_while_a_jump_channel_lives`).
    9. recovery. chaos proxy로 C–J 링크를 5초 끊은 동안 recovery가 체인을 다시 세우고 같은 세션에 resume하며 입력이 무손실·무중복이다(`a_session_through_a_jump_resumes_after_the_hop_link_dies`, L4). C의 소켓을 rebind해도 안쪽 연결이 끊기지 않는다(`outer_migration_is_invisible_to_the_inner_connection`). `--supervise` 터널이 J의 재시작 뒤 같은 체인으로 다시 선다.
    10. 펀칭과 역방향. 첫 hop이 펀칭으로 선 연결일 때(netsim, `jump_first_hop_over_a_punched_connection`)와 이 장비의 `qsh listen` 데몬을 거칠 때(`jump_first_hop_over_the_reverse_route`, 등록 연결 구간이 datagram 운반체임을 확인) 1번의 세션·exec가 끝난다.
    11. 실패 보고. 결정 12의 stage 아홉이 각각 정해진 `code`와 `details.jump`로 나온다(`jump_failure_stage_table`). `unreachable`은 handshake 시한을 기다리지 않고 1초 안에 나온다(`jump_target_refusal_is_reported_fast`, Windows의 `WSAECONNRESET` 포함).
    12. 표면. `-J`, `--jump`, `-o ProxyJump`, pin의 `jump`, `-J none`의 우선순위가 표 하나로 고정된다(`jump_precedence_table`). hop 다섯, 같은 pin 두 번, 끝단이 hop에 든 체인은 dial 없이 `INVALID_ARGUMENT`다. `qsh cp -J`와 `qsh exec -J`가 돈다. `-W`는 여전히 `UNSUPPORTED`다. `jump.v1`이 없는 hop은 stage `unsupported`이고 `JUMP`를 열지 않는다(`a_hop_without_jump_v1_gets_no_jump_stream`). 가짜 ssh(`qsh-testkit`의 `fake_ssh`)로 `ProxyJump`가 있는 부트스트랩이 hop부터 pin을 세우고 끝단 pin에 `jump`를 적으며, hop이 설치를 거부하면 적지 않고 지금 동작으로 물러선다(`bootstrap_records_proxyjump_as_the_pin_jump`).
    13. 성능. `QSH_ACCEPTANCE_SLOW`에서 loopback의 대화형 echo p95가 직접 연결보다 hop마다 2 ms 넘게 늘지 않는다(`jump_echo_overhead_per_hop`, hop 하나와 둘). 같은 조건에서 hop 하나를 지나는 터널 처리량이 직접 연결의 50% 이상이다(`jump_tunnel_throughput`, 세 장비가 한 CPU를 나누고 client가 두 겹을 암호화하므로 PRD §13의 80%보다 낮게 둔다). 대역이 병목인 경로의 비율은 `scripts/` 아래 벤치가 netem 20 Mbit에서 재 개정 이력에 적고, 목표는 ADR-0052 측정과 같은 80%다. 두 테스트는 `QSH_PERF_OUT`에 JSON 한 줄을 남긴다.
    14. 세 OS. 1~12는 Linux·macOS·Windows CI에서 돈다. netsim 시험은 플랫폼 분기가 없고, loopback 시험은 세 OS의 진짜 UDP 소켓에서 돈다. 중간 peer와 끝단이 Windows인 조합이 1번에 든다.
    15. 계약. `capabilities.json` golden, 결정 22의 새 fixture, `EXPECTED_DOCTOR_CODES`의 둘, `role_grants_table`의 `forward.jump` 열, `acl_docs.rs`의 어휘 14종, man page(`checked_in_man_pages_match_the_generator`)가 초록이다.
    16. fuzz. 새 타깃 `jump_frames`가 더해져 `fuzz/README.md`, `CLAUDE.md`, `docs/design/testing.md` L8의 개수가 28이 되고, `decode_stream_header`·`decode_datagram_frame` corpus에 새 값이 든다.
    17. 회귀 없음. `-J`를 주지 않은 명령의 wire 바이트가 지금과 같고(`no_jump_stream_without_dash_j`), `tunnel_echo_under_load`, `screen_sync_staleness_under_loss`, 펀칭과 agent 수용 시험이 diff 없이 통과한다.
    18. threat model에 결정 24의 행이 고정 테스트와 함께 들어간다.

## 근거

- 안쪽 QUIC를 끝에서 끝으로 두는 이유. 끝단 인증이 끝단 pin으로 되려면 TLS가 C와 T 사이에서 맺어져야 하고(ROADMAP M26의 범위 문장), 그러면 중간 peer가 평문을 볼 길이 구조적으로 없다. 같은 선택이 손실 복구, 혼잡 제어, resume, 화면 동기화와 예측을 바꾸지 않고 그대로 쓰게 한다. 중간 peer가 안쪽 QUIC를 끝내고 다시 여는 설계(대안 절)는 이 셋을 모두 잃는다.
- datagram을 먼저 쓰는 이유. 안쪽 QUIC는 이미 손실을 복구하므로 바깥이 또 복구할 이유가 없다. 바깥 스트림은 안쪽 손실 신호를 지연으로 바꾸고 한 패킷의 손실이 뒤의 모든 패킷을 붙잡는다. ADR-0052의 측정이 안쪽 p99 913 대 1880 ms, 처리량 2.10 대 1.64 MB/s로 이를 보였다. RFC 9221의 DATAGRAM은 바깥 혼잡 제어 아래에 있으므로 바깥 경로를 넘치게 하지 않는다.
- 스트림 짝을 두는 이유. ADR-0052 결정 7이 datagram에 실리는 모든 것에 스트림 짝을 요구한다. 작은 MTU 경로, datagram을 버리는 중간 장비, `datagram.v1`이 없는 peer에서도 jump는 돌아야 한다. 스트림의 큐를 64 KiB로 묶고 넘치면 버리는 것은 바깥 스트림 위에서도 안쪽 혼잡 제어가 손실을 보게 하려는 것이다.
- 겹친 혼잡 제어. 바깥 BBR과 안쪽 BBR이 겹친다. 바깥은 C와 첫 hop 사이 경로의 대역을, 안쪽은 끝에서 끝의 병목을 잰다. datagram 송신 버퍼가 차면 오래된 것부터 버려지므로(§14) 바깥이 막힐 때 안쪽은 지연이 아니라 손실을 보고 물러선다. ADR-0052 측정의 BBR 결과(문제없음)가 이 겹침에서 나온 것이다. 스트림 운반체에서는 위의 64 KiB 버림이 같은 일을 한다.
- client가 다음 hop의 이름을 해석하지 않는 이유. jump 뒤의 장비는 대개 사설망의 이름이나 주소이고, OpenSSH의 `-W host:port`도 jump host가 해석한다. C가 해석하면 C에서 풀리지 않는 이름을 쓸 수 없다.
- 단마다 정확한 pin을 요구하는 이유. `QshPeerVerifier`는 trust store의 어떤 pin이든 받는다. 보통 dial에서는 주소를 C가 정하므로 그것으로 충분하지만, jump에서는 주소를 중간 peer가 해석하고 패킷을 중간 peer가 보낸다. 중간 peer가 목적지를 C가 믿는 다른 장비로 바꾸면 보통 검증은 통과한다. 펀칭의 같은 문제를 ADR-0054 결정 12가 같은 규칙으로 막았다.
- 인라인 판정인 이유. `JUMP`는 `TCP_CONNECT`처럼 스트림 하나가 자원 하나이고, control 왕복을 하나 더 두면 체인의 hop마다 RTT가 늘어난다. 인라인이어도 판정은 자원(소켓) 전이고 choke point(`Authorizer::check`)를 지난다.
- QUIC 문을 두는 이유. `forward.jump`가 "임의의 UDP를 보낼 권리"이면 중간 peer의 loopback DNS, 사설망의 SNMP 같은 곳에 C가 만든 바이트가 간다. 문은 목적지가 QUIC로 답하기 전까지 QUIC Initial 모양의 패킷만 몇 개 보내게 해서, 이 권리를 "QUIC 서비스에 닿기"로 좁힌다. QUIC가 평문으로 두는 필드만 읽으므로 평문을 보지 않는다는 성질은 그대로다.
- hop을 넷으로 묶는 이유. 겹마다 약 40바이트와 암호화 한 번이 더해진다. 1500 링크에서 넷까지는 datagram 운반체에 들어가고, 그 이상은 흔한 쓰임새가 아니다. OpenSSH에 상한이 없는 것과 다르지만, 고리와 무한 펼치기를 막는 상한은 어차피 필요하다.
- relay가 아닌 이유. PRD §14와 ADR-0050 결정 3이 막는 것은 직접 경로가 없을 때 자동으로 끼어드는 제3자 서비스다. jump는 사용자가 이름으로 고른 자기 장비이고, 그 장비가 `forward.jump`로 허락해야 하며, 펀칭이나 직접 dial의 실패 뒤에 자동으로 쓰이지 않는다(결정 13). payload와 key를 보지 못한다는 PRD §14의 요구는 결정 23대로 지킨다.

## 대안과 기각 사유

- 안쪽 QUIC를 늘 스트림 위에 싣는다. Dave가 정할 것 1의 (나).
- 일반 UDP 포워딩(`-L` 꼴의 로컬 UDP 포트). Dave가 정할 것 1의 (다).
- 중간 peer가 안쪽을 끝낸다. J가 C의 QUIC를 받고 T로 새 QUIC를 열어 control message와 스트림을 다시 잇는 방식이다. 끝단 인증이 J의 인증이 되어 ROADMAP의 "끝단 인증은 끝단 pin으로"를 어기고, J가 모든 평문을 보며, resume token과 writer lease가 J에 묶인다. 기각.
- 끝단 TCP 포트로 `TCP_CONNECT`를 연다. qsh는 TCP listener가 없다(ADR-0043). 기각.
- 여러 hop의 평탄한 relay. C가 `a`에게 `b`의 relay 포트로 채널을 열게 하고 `b`에게 T로 채널을 열게 해서, C–T 패킷이 한 겹으로만 싸이고 `a`가 `b`로 날 UDP를 보내게 하는 방식이다. 겹마다 드는 40바이트와 암호화 한 번을 아끼지만, `b`가 relay 포트를 알리는 신호, 받는 주소와 보내는 주소가 다른 소켓, 그 포트에 대한 출발지 검사가 새로 든다. hop 둘 이상은 흔하지 않아 지금은 기각하고, 측정이 필요를 보이면 새 ADR로 연다.
- 바깥 연결이 다시 서면 옛 안쪽 연결을 새 채널에 이어 붙인다. resume보다 빠를 수 있지만, PathWatch가 사망을 선언한 연결을 되살리는 두 번째 길이 생기고 그 시각을 맞추는 상태 기계가 따로 든다. resume이 무손실·무중복을 이미 보장한다(결정 16). 기각.
- 직접 dial이나 펀칭이 실패하면 pin의 `jump`로 넘어간다. 사용자가 모르는 사이 경로가 제3자 장비를 지나게 되어 relay가 된다. 기각.
- jump를 직접 dial과 경주시킨다. ssh의 `ProxyJump`는 늘 jump를 거치고, 경주하면 사설 주소 pin마다 무의미한 직접 dial이 나간다. 직접 가고 싶으면 `-J none`이다. 기각.
- `config.toml`의 전역 키(`[jump].default`)를 둔다. jump는 목적지마다 다르고, 모든 host에 같은 jump를 거는 쓰임새는 드물다. host마다의 값은 pin 필드가 맡는다(결정 20). 기각.
- `-W`를 연다. ADR-0011 결정 5와 그 추기가 닫았고, qsh의 jump는 `-W` 없이 선다. OpenSSH가 qsh host를 jump로 쓰는 사용례는 관측되지 않았다. 기각.
- 중간 peer가 다음 hop을 펀칭한다. 중간 peer가 시작하는 쪽(A)이 되려면 중개자 후보와 펀칭 예산을 중간 peer가 따로 들어야 하고, 그 실패를 C에게 알리는 어휘가 늘어난다. 첫 hop의 펀칭과 jump의 조합으로 대부분의 구성이 덮인다. 기각.
- `forward.local`을 재사용한다. jump는 TCP가 아니라 UDP이고 목적지가 QUIC 서비스로 좁혀져 판정의 뜻이 다르며, 운영자가 `-L`은 주고 jump는 막고 싶을 수 있다. 감사에서도 둘을 가르는 편이 읽기 쉽다. 기각.
- 목적지마다 `acl.toml` 행의 `targets` 키. Dave가 정할 것 3의 (다).

## 결과

- 개정할 문서: `docs/PRD.md` §7 P2 목록의 "jump chaining"에 ADR 번호, §9(action 어휘 14종, `forward.jump` 문단, role 표의 `full`·`tunnel` 행), §14(jump가 relay가 아닌 이유 한 문장). `docs/design/protocol.md` §4(`jump.v1`), §7(스트림 표의 `JUMP` 행, 인라인 인가 예외에 `JUMP`), §9(`StreamKind`), §11(`LOCAL_STREAM`의 `JUMP`와 데몬의 운반체 번역), §14(datagram을 쓰는 메시지에 jump 패킷), §16.1(`StreamKind` 값 목록), §16.4(가장 새 사례 문장), §18.6(종류 14), 새 §21(jump: channel, 두 운반체와 고르기, MTU, 처리 순서, QUIC 문, 상한, 시험). `docs/design/architecture.md` §1(`qsh-core::jump`, `qsh-transport`의 `PacketPipe`), §6(`forward.jump` 인라인 판정과 감사). `docs/design/testing.md` L0·L3·L4·L6·L8·Perf와 CI 구성. `docs/design/threat-model.md` §0(범위), §3(진입점: 중간 peer의 `JUMP` 스트림과 채널 UDP 소켓, client의 관), §4(결정 24의 행), §7(잔여 위험). `docs/CLI.md` §2.2, §2.5, §3.2, §6.1, §6.8, §6.11, §6.17, §6.21, §7.2. ADR-0045 결정 2, ADR-0051 결정 2·7, ADR-0044 결정 6에 이 ADR을 가리키는 개정 이력 줄. `fuzz/README.md`, `CLAUDE.md`(fuzz 개수), `README.md`(`-J` 지원, `ProxyJump`를 부트스트랩 때 한 번 읽는다는 것, jump가 보는 것).
- 새 threat model 행(결정 24): 스푸핑 하나, 무단접근 셋, 자원고갈 둘, 정보노출 둘, 무결성 하나, 파서 표면 하나, 부인방지 하나, 가용성 하나.
- 남는 위험(§7의 새 행):
  - 중간 peer는 C의 신원, 목적지, 안쪽 트래픽의 크기와 시각을 본다. 키 입력의 시각도 여기에 든다.
  - 중간 peer는 체인을 언제든 끊거나 늦출 수 있다. 막을 길은 그 장비를 jump로 고르지 않는 것뿐이다.
  - `forward.jump`는 중간 peer에서 닿는 QUIC 서비스 모두에 닿는 권한이다(qsh 밖의 HTTP/3 서버 포함). 문은 QUIC가 아닌 서비스를 막을 뿐이다.
  - 끝단은 jump로 온 연결의 출발지를 중간 peer의 주소로 본다. 끝단의 source별 rate limit(ADR-0009)은 같은 중간 peer를 지나는 client들을 한 출발지로 센다.
  - 작은 MTU 경로(IPv6 최소 MTU, 1280 링크의 둘째 hop부터)에서는 스트림 운반체로 돌아 손실 아래 지연이 커진다.
- 크기: ADR-0050의 2ew에 스트림 짝과 운반체 고르기, QUIC 문, 역방향 데몬의 운반체 번역, 부트스트랩의 `ProxyJump` 기록과 hop 부트스트랩, 체인 recovery가 더해져 추정 3ew로 고친다. 나눔은 wire·decoder·fuzz 0.3, `PacketPipe`와 `dial_over_pipe` 0.3, 중간 peer(인라인 판정, 해석, 소켓, QUIC 문, 상한, 정리) 0.5, client 체인(해석, 펼치기, 단마다 pin, 실패 보고) 0.4, 운반체 고르기와 MTU, 적응 정책 연결 0.2, 역방향 데몬 0.3, 표면(플래그, pin 필드, `trust jump`, 부트스트랩 기록, `cp -J`, doctor, JSON) 0.4, recovery와 `--supervise` 0.2, 수용 시험·성능·문서 0.4다. Dave가 정할 것 1을 (나)로 정하면 -0.3ew, 5를 (나)로 정하면 -0.2ew, 4를 (나)로 정하면 -0.1ew다.
- 스텝 순서: probe(quinn을 `PacketPipe` 위에서 `initial_mtu`·`min_mtu` 1200으로 돌릴 때의 PLPMTUD와 black hole 감지, 바깥 `max_datagram_size()`가 1217을 넘기까지의 시간, quinn이 datagram과 스트림 frame을 한 패킷에 담는 순서, Windows의 `connect`된 UDP 소켓이 ICMP 거부를 알리는 방식. wire 없음, 결과를 개정 이력에) → `PacketPipe`와 `dial_over_pipe`, netsim 위 한 겹 시험(wire 없음) → `qsh_proto::jump` decoder와 long header 판독기, fuzz(wire 없음) → `jump.v1`, `StreamKind::JUMP`, 종류 14 → `forward.jump`와 role 표, 감사 → 중간 peer(인라인 판정, 소켓, QUIC 문, 상한, on-demand idle) → client 체인과 실패 보고 → 운반체 고르기와 적응 정책 → 역방향 데몬 → recovery와 `--supervise` → 표면(플래그, pin 필드, `trust jump`, 부트스트랩, `cp -J`, doctor, JSON, fixture) → 수용 시험(netsim 체인, 평문 기록, 성능, Windows) → 문서, man, threat model. 계약·wire를 건드리는 스텝은 이 ADR이 승인되기 전에 열지 않는다(ADR-0050 결정 7). 앞의 세 스텝은 wire 없이 열 수 있다.

## 개정 이력

- 2026-11-09 초안(에이전트). Dave가 정할 것 다섯 항목은 추천만 적었다.
- 2026-11-09 Dave가 승인했다. Dave가 정할 것 다섯 항목 모두 (가)를 골랐다(datagram 우선과 스트림 짝, `forward.jump`는 `full`·`tunnel`, host-local을 뺀 목적지와 QUIC 문, 부트스트랩의 `ProxyJump`를 pin의 `jump`에 기록, 역방향 데몬의 운반체 번역). M26 크기는 3ew다.
