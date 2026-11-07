# ADR-0054: M24의 범위. 연결을 시작할 때 세 장비가 서로 pin한 사용자의 상시 `qsh listen`을 중개자로 써서 후보 주소를 바꾸고, 양 끝이 QUIC endpoint와 같은 UDP 소켓에서 동시에 보내 NAT에 구멍을 뚫는다. 끝단 pin으로 확인된 첫 handshake를 쓰고, 정해진 시간 안에 서지 않으면 포기하고 지금의 route 순서로 돌아간다

날짜: 2026-11-07
상태: 제안됨

개정 관계: ADR-0050 결정 3과 결정 5의 M24를 구체화한다. 다음을 개정한다.
- ADR-0045 결정 2의 role 표와 PRD §9의 action 어휘. 새 action `host.punch`를 더해 `Action::ALL`이 12종이 되고, `none`을 뺀 role이 이 action을 준다(결정 6, Dave가 정할 것 2).
- `docs/design/protocol.md` §4(capability 하나), §9(새 message 일곱, enum 둘), §11(`qsh listen`이 등록하지 않는 peer의 연결을 펀칭 요청에 한해 받는다), 새 §19(홀펀칭).
- `docs/CLI.md` §6.1의 route 순서(결정 16), §6.11(`trust rendezvous`와 pin 필드), §6.13(listener가 중개자를 겸한다), §6.17(doctor 코드 셋), §6.23(키 하나), §7(플래그 둘). `qsh_core::doctor::CONTROLLER_UNREACHABLE`의 "QSH provides no relay, NAT traversal, or discovery" 문장을 고친다(결정 20).
- `qsh serve --to`의 등록 연결 소켓. 지금은 controller 주소의 family로 bind하고 서버 설정이 없다(`crates/qsh-transport/src/endpoint.rs`의 `Dialer::dial_inner`). 이 ADR 뒤로는 dual-stack으로 bind하고, 펀칭 창이 열린 동안만 같은 소켓에 서버 설정을 건다(결정 7).
- 펀칭으로 선 연결의 recovery 재dial 시한. 지금의 `REDIAL_DEADLINE`(2초) 대신 펀칭 예산을 쓴다(결정 18).

개정하지 않는 것: TLS 검증 경로(pin → CA → 거부, `docs/design/protocol.md` §3, §16.5), 0-RTT 금지(§2), 주소 검증되지 않은 Initial은 늘 Retry(ADR-0009), keep-alive 범위와 idle 45초 고정(ADR-0021), session resume 절차(§10), 역방향 등록 절차와 live 역방향 우선 규칙(§11-2, `docs/CLI.md` §6.1), SSH 부트스트랩과 되살리기(ADR-0044, ADR-0051 결정 1·4), relay를 코어에 넣지 않는다는 것(PRD §14), listener 초대 코드 pairing의 기각(ADR-0015).

## 맥락

ADR-0050 결정 3은 "NAT traversal 가운데 홀펀칭만 코어에 들어온다. 둘 다 닿는 사용자의 qsh peer 하나를 중개자로 써서 연결을 시작할 때 구멍을 뚫는다. 실패하면 거기서 끝내고 이유를 담은 오류를 낸다. relay, TURN, 공용 STUN 서버, 중앙 서비스는 들이지 않는다"고 정했다. 사용자 문장은 "맨 처음에 펀칭만 하는 것이고, 홀펀칭으로 접근이 안 되면 포기한다"였다. 돈이 드는 것(VPS, 유료 relay)도 쓰지 않는다.

### 지금 있는 것

- **소켓.** `Dialer::dial`은 dial마다 새 quinn endpoint를 만들고, 상대 주소의 family로 `[::]:0`이나 `0.0.0.0:0`에 bind하며 서버 설정이 없다. `Listener`는 `[::]`에 dual-stack으로 bind한다(ADR-0046). `qsh serve --to`는 서버 endpoint가 없고(`docs/CLI.md` §6.13, `--to`와 `--bind`는 함께 줄 수 없다), controller에 dial한 등록 연결 하나를 15초 keep-alive로 붙들어 NAT 매핑을 살려 둔다(ADR-0021).
- **controller가 보는 주소.** `qsh listen`은 등록 연결을 받을 때 `Incoming::remote_address()`로 target의 주소를 안다. Retry를 거친 주소라 위조되지 않았다(ADR-0009). NAT 뒤 target이면 이것이 NAT 바깥의 매핑, 곧 server-reflexive 주소다.
- **quinn 0.11.12에서 확인한 것.**
  - `Endpoint::new_with_abstract_socket`은 `Arc<dyn AsyncUdpSocket>`을 받는다. 그 trait의 `try_send`와 `poll_recv`를 감싸면 quinn이 쓰는 바로 그 소켓에서 우리 datagram을 보내고, 받은 datagram을 quinn보다 먼저 볼 수 있다. 새 dependency는 없다.
  - `Endpoint::set_server_config(Option<ServerConfig>)`로 서버 설정을 켜고 끌 수 있고, 한 endpoint가 바깥으로 dial한 연결과 받아들인 연결을 함께 든다. `connect_with`는 연결마다 `ClientConfig`(따라서 `TransportConfig`의 `initial_rtt`)를 받는다.
  - `quinn-proto`는 모르는 연결로 온 짧은 datagram에 답하지 않는다. long header가 아니면 stateless reset을 고려하는데, datagram이 `RESET_TOKEN_SIZE + 5`(21바이트)보다 크지 않으면 "not larger than minimum stateless reset size"로 버린다(`endpoint.rs`의 `stateless_reset`). 그래서 21바이트 이하의 펀치 datagram은 quinn에 닿더라도 응답을 부르지 않는다.
  - quinn의 수신 루프는 `ConnectionReset`을 무시한다. Windows에서 닫힌 포트로 간 UDP가 돌려받는 ICMP가 `WSAECONNRESET`으로 올라와도 endpoint가 죽지 않는다.
- **route 순서(`docs/CLI.md` §6.1, ADR-0051 결정 1·4).** live 역방향 등록이 있으면 이 장비의 `qsh listen` 데몬을 거친다. 없으면 pin(또는 `hosts.toml`)의 주소로 직접 dial한다(시한 10초 `DEFAULT_DIAL_TIMEOUT`, `-o ConnectTimeout`이 바꾼다). SSH 부트스트랩으로 세운 pin에서 그 dial이 `CONNECTION_FAILED`·`TIMEOUT`이면 ssh로 serve를 되살리고 한 번 더 dial한다. 모르는 이름이면 자동 부트스트랩이다. 주소 없는 pin은 `HOST_NOT_FOUND`(pinned without address)다.
- **주소 관측.** `crates/qsh-core/src/trust/invite_address.rs`가 문서용 주소(`192.0.2.1`, `2001:db8::1`)로 connect한 UDP 소켓의 local addr로 이 장비의 바깥쪽 IPv4·IPv6 주소를 하나씩 얻는다. 패킷은 나가지 않는다.
- **상시 `qsh listen`.** 사용자는 공유기 포트를 열었거나 공인 IPv6를 가진 장비에 `qsh listen`을 상시로 돌리고, NAT 뒤 장비들을 `qsh serve --to`로 거기 등록해 둔다. 그 listener에 앉은 사람은 역방향 route로 target에 닿지만, 밖에 있는 다른 장비(노트북)는 target에 닿을 길이 없다. M24가 메울 곳이 여기다.

### 일반적인 홀펀칭(개념만)

NAT의 동작은 두 축으로 나뉜다(RFC 4787). **매핑**은 안쪽 소켓 하나가 목적지와 관계없이 같은 바깥 포트를 쓰는지(EIM), 목적지마다 바뀌는지(ADM·APDM)다. **필터**는 바깥에서 오는 패킷을 아무 데서나 받는지(EIF), 안에서 보낸 적 있는 주소에서만(ADF), 그 주소와 포트에서만(APDF) 받는지다. 흔한 이름은 full cone(EIM·EIF), restricted cone(EIM·ADF), port-restricted cone(EIM·APDF), symmetric(APDM·APDF)이다. IPv6의 상태 기반 방화벽은 주소 변환이 없는 APDF와 같다.

ICE는 후보(로컬 인터페이스의 host, STUN 서버가 본 server-reflexive, 상대 패킷의 출발지에서 배운 peer-reflexive, TURN relay)를 모아 신호 채널로 바꾸고, 양쪽이 상대 후보로 동시에 보내 서로의 NAT에 매핑과 필터 구멍을 연다. qsh에는 STUN 서버가 없고 relay도 없다. 대신 중개자 자신이 server-reflexive 주소를 본다. 양쪽이 목적지마다 매핑을 바꾸는 NAT의 조합은 포트 예측 없이는 열리지 않고, 이 ADR은 포트 범위를 훑는 예측을 하지 않는다. PRD §12가 그 조합을 qsh 밖의 일로 둔다.

## Dave가 정할 것

1. **중개자를 어떻게 고르나.** (가) 이 장비가 B에 한 번이라도 붙었을 때 B에게 물어 배운 것(B가 등록해 둔 `qsh listen`의 fingerprint 가운데 이 장비가 주소와 함께 pin한 것)과, `qsh trust rendezvous`·`--rendezvous`로 직접 준 것만 쓴다. (나) 직접 준 것만 쓴다. (다) (가)에 더해, 힌트가 없으면 주소가 있는 pin 가운데 셋까지 차례로 "B를 들고 있느냐"고 묻는다. **추천은 (가).** 설정 파일을 열지 않고(ADR-0050 결정 2) 두 번째 접속부터 동작하고, B가 알려 준 값은 이 장비가 이미 pin한 peer로만 걸러져 신뢰를 넓히지 않는다(결정 5). (다)는 첫 접속까지 덮지만 "B에 붙으려 한다"는 사실을 관계없는 peer에게 알리고, 실패할 때 시간을 더 쓴다.
2. **누가 `host.punch`를 받나.** (가) `none`을 뺀 모든 role(`full`, `exec`, `tunnel`, `read-only`, `reverse`), (나) `full`과 `exec`만, (다) 어느 role도 주지 않고 `qsh trust allow <peer> host.punch`로만 준다. **추천은 (가).** 펀칭이 주는 것은 B에 닿는 길뿐이고, B에서 무엇을 할 수 있는지는 B가 자기 role과 행으로 따로 판정한다. 남는 위험은 중개자와 B를 작은 패킷의 반사기로 쓰는 것인데 결정 11·14의 상한이 막는다. (다)는 "pin 한 번이 곧 권한"이라는 ADR-0045의 모델을 펀칭에서만 깨고, 장비마다 손이 한 번 더 간다.
3. **중개자가 B와 같은 NAT 뒤에 있을 때의 추정 후보.** 집 공유기에 포트를 열어 둔 `qsh listen`이 같은 LAN의 B를 중개하면, 중개자가 보는 B의 주소는 사설 주소라 밖에 있는 A에게 쓸모가 없다. (가) A가 중개자에 닿을 때 쓴 공인 IPv4와 B의 포트를 합친 추정 후보 하나를 더한다(포트를 보존하는 NAT에서만 맞는다), (나) 더하지 않는다. **추천은 (가).** 상시 장비를 집에 두는 흔한 구성에서 IPv4로 펀칭이 되는 거의 유일한 길이다. 비용은 후보 하나와, 틀렸을 때 그 주소로 가는 Initial 몇 개와 펀치 datagram 여덟 개다. 포트 범위를 훑는 예측은 어느 쪽이든 하지 않는다(결정 8).
4. **직접 dial과 펀칭의 경주.** pin에 주소가 있는 host에서 (가) 직접 dial을 시작하고 1초 안에 서지 않으면 펀칭을 나란히 시작해 먼저 선 쪽을 쓴다, (나) 직접 dial이 실패한 뒤(최대 10초)에만 펀칭한다, (다) 처음부터 둘을 나란히 시작한다. **추천은 (가).** 직접 경로가 되는 망에서는 중개자에 아무것도 보내지 않고(직접 dial은 대개 1초 안에 선다), 안 되는 망에서도 전체 시간이 지금의 dial 시한 10초를 넘지 않는다(결정 16). (나)는 펀칭이 필요한 망마다 10초를 더 기다리게 하고, (다)는 접속할 때마다 중개자에게 어디로 가는지 알린다.
5. **역방향 등록 자체의 펀칭.** `qsh serve --to L`에서 L(`qsh listen`)이 NAT 뒤라 B가 L에 닿지 못하는 경우를 M24에 넣을지. (가) 미룬다. M24는 B에 정방향으로 닿는 길을 여는 것만 다루고, 그렇게 열린 연결은 정방향 route의 모든 기능(셸, exec, 터널, `qsh cp`, 화면 동기화와 예측)을 나른다. (나) 넣는다. L도 제3의 중개자에 상시 연결을 들어야 해서 등록이 두 겹이 되고, 등록 감시와 재등록 예산(ADR-0041)을 다시 짜야 한다(추정 +1.5ew). **추천은 (가).** 역방향 route는 그 자체가 NAT 뒤 host에 닿는 방법이고, L이 NAT 뒤인 경우는 펀칭으로 B에 직접 붙는 것으로 대신할 수 있다.

## 결정

### 범위

1. **무엇을 펀칭하나.** 세 역할이 있다.
   - **시작하는 쪽(A).** 정방향 route로 dial하는 모든 client 명령이다. `qsh [user@]host`, `qsh attach`, `qsh exec`, `qsh cp`, `qsh tunnel open`, `qsh session ...`, `qsh doctor <host>`가 모두 `Ops`의 같은 connect 경로를 지나므로 같이 얻는다.
   - **닿으려는 쪽(B).** 살아 있는 역방향 등록을 든 `qsh serve --to R` 프로세스다. B는 R에 상시 연결이 있어서 R이 B에게 말을 걸 수 있다.
   - **중개자(R).** 그 등록을 받은 `qsh listen`이다(결정 4).
   - 범위 밖이며 따로 미룬다: 상시 연결이 없는 정방향 전용 `qsh serve`와 on-demand serve를 B로 삼는 것, `qsh serve --to`의 등록 dial 자체의 펀칭(Dave가 정할 것 5), 펀칭 위의 pairing(pin이 없으면 끝단 확인이 없으므로 펀칭은 pin을 전제한다), relay·TURN·공용 STUN, 포트 범위 예측, 공유기에 포트를 여는 UPnP·NAT-PMP·PCP, 여러 중개자를 거치는 경로(M26의 일과 다르다).

2. **전제는 세 장비의 서로 pin과 인가다.** A는 B와 R을, R은 A와 B를, B는 A와 R을 pin한다. 그 위에서 R은 A에게, B는 A에게 `host.punch`를 허락해야 한다(결정 6). pin은 지금의 경로(SSH 부트스트랩, 인증서 파일, pairing code)로 세운다. A와 R, A와 B 사이의 pin은 SSH 부트스트랩이 양쪽에 한 번에 세운다(ADR-0051).

### 층 배치

3. **어디에 무엇을 두나.**
   - `qsh-proto`: 새 message, 후보 검사(`valid_punch_candidate`), 펀치 datagram의 머리와 tag. sans-IO이고 fuzz 표면이다.
   - `qsh-transport`: `PunchEndpoint`(새 모듈 `crates/qsh-transport/src/endpoint/punch.rs`). quinn endpoint 하나와 그 소켓을 감싼 `AsyncUdpSocket`을 쥔다. 하는 일은 같은 endpoint에서 여러 번 dial(`connect_with`, 연결마다 `initial_rtt`), 펀치 datagram 보내기(`send_punch(dest, tag)`, 바이트를 받지 않고 tag만 받는다. `qsh-core`가 임의 UDP를 만들지 못하게 한다), 받은 펀치 datagram을 quinn 앞에서 걸러 `(출발지, tag)`로 알리기, 서버 창 열고 닫기(`open_window` → `set_server_config(Some)`, 창을 놓으면 `None`), dual-stack bind다. 소켓 출처(`SocketSource::Os` 또는 시험용 가상 소켓)를 받아 결정 22의 netsim이 그 아래에 들어간다. `qsh-core`는 quinn 이름을 쓰지 않고 이 타입만 쓴다.
   - `qsh-core`: 새 모듈 `crates/qsh-core/src/punch/`. 후보 모으기, 일정, 시도 상태 기계, 포기 판정은 I/O도 시계도 없는 함수와 상태 기계이고(`now`를 호출자가 넘긴다), 구동부는 셋이다. client route(`Ops`의 connect), R의 중개 서비스(`reverse/listen` 옆), B의 offer 처리(`reverse/target` 옆). 인가는 기존 choke point(`Authorizer::check`)를 지난다. 로컬 주소 관측도 주입한다(netsim에서는 가상 주소가 나와야 한다).
   - `qsh-cli`: 플래그와 `trust rendezvous` 하위 명령을 `Ops`에 넘기고 렌더링만 한다.
   - `xtask arch`: 새 경로에 기존 금지가 그대로 걸린다(`crates/qsh-core/src/`의 `quinn::`). 새 금지 경로는 더하지 않는다.

### 중개자

4. **중개자의 자격과 고르는 순서.** 중개자는 B의 fingerprint를 가진 live 역방향 등록을 든 `qsh listen`이다. A는 B를 이름이 아니라 자기가 pin한 B의 fingerprint로 부르고, R은 그 fingerprint로 검증된 등록을 찾는다. 이름은 장비마다 다르므로 wire에 싣지 않는다.
   - A가 중개자 후보를 고르는 순서: `--rendezvous <peer>`(명령마다, 주면 이것만 쓴다) → B의 pin에 적힌 `rendezvous` 목록(결정 5, 앞에 있을수록 최근에 확인됨). 각 후보는 이 장비의 trust store에 **주소와 함께** pin된 peer여야 하고, 아니면 건너뛴다.
   - 한 번의 시도에서 중개자는 둘까지 차례로 쓴다. 첫째에서 신호가 실패하면(결정 17의 `rendezvous_*`, `target_not_registered`) 남은 신호 예산 안에서 둘째로 간다. 펀칭 창이 연 뒤의 실패(`timeout`)는 다른 중개자로 다시 하지 않는다. 같은 NAT 쌍은 중개자를 바꿔도 같은 결과를 낸다.
   - R에 닿는 길은 R의 pin 주소로 가는 직접 dial뿐이다. R이 역방향 등록이나 펀칭을 거쳐야 닿는 곳이면 중개자가 될 수 없다.

5. **힌트 배우기와 저장.** Dave가 정할 것 1의 (가)다.
   - A가 어느 route로든 B와 연결을 세우고 협상된 교집합에 `punch.v1`이 있으면, 그 프로세스에서 B마다 한 번 `RendezvousQuery`를 보낸다. B는 자기 프로세스가 든 live 등록의 controller fingerprint와, B의 `config.toml`에 `[serve].to`가 있으면 그것을 pin으로 푼 fingerprint를 합쳐 넷까지 돌려준다(on-demand serve도 `[serve].to`는 읽는다).
   - A는 돌아온 fingerprint 가운데 자기 trust store에 주소와 함께 pin된 것만 남겨 B의 `[[peer]]`에 optional 키 `rendezvous = ["sha256:...", ...]`(넷까지, 최근 확인 순)로 쓴다. 값이 바뀔 때만 `trust.toml.lock` 아래에서 쓴다. 감사 기록은 남기지 않는다(신뢰나 권한이 아니라 길 안내다).
   - B가 거짓 목록을 보내도 A가 이미 pin한 peer 밖으로는 넓어지지 않는다. 바꿀 수 있는 것은 A가 어느 pin된 peer에게 먼저 물어볼지뿐이다.
   - `qsh trust rendezvous <name> <peer>...`는 목록을 바꾸고, `--clear`는 비운다. `<peer>`마다 주소 있는 pin이어야 하고 아니면 `HOST_NOT_FOUND`다. `trust rename`은 이 키를 그대로 둔다(fingerprint로 적기 때문이다). 중개자 pin을 지우면 그 fingerprint는 다음 읽기부터 건너뛴다.

6. **인가: 새 action `host.punch`.** 펀칭은 R에 신호 상태를, B에 서버 창과 송신을 만든다. 그래서 둘 다 자원을 만들기 전에 choke point에서 판정한다.
   - R은 `PunchRequest`를 받으면 A에 대해 `host.punch`를 판정한 뒤에야 등록을 찾는다. 거부는 `PERMISSION_DENIED`(균일 문면)이고 등록이 있는지 알리지 않는다.
   - B는 `PunchOffer`를 받으면 offer에 실린 A의 fingerprint로 principal을 만들어(pin 경로, B의 trust store) `host.punch`를 판정한 뒤에야 창을 연다. `RendezvousQuery`도 묻는 연결의 principal에 대해 같은 action으로 판정한다.
   - role 표: `none`을 뺀 모든 role이 `host.punch`를 준다(Dave가 정할 것 2). `acl.toml` 행과 `trust allow`도 이 이름을 받는다. `acl show`의 실효 action과 `acl check`가 따라온다. 항상-deny 게이트에는 넣지 않는다.
   - 감사: R은 `punch.request`, B는 `punch.offer`와 `punch.rendezvous`를 op 이름으로, action `host.punch`로 기록한다. 기존 구조 필드만 쓰고 주소 필드는 없다. 감사 기록을 쓰지 못하면 신호를 보내지 않는다(fail-closed).

### 후보

7. **소켓.** 후보의 포트가 뜻을 가지려면 중개자와 말한 소켓과 펀칭하는 소켓이 같아야 한다.
   - A는 펀칭할 때 `PunchEndpoint`를 `[::]:0` dual-stack으로 하나 만들고(IPv6 소켓을 만들 수 없으면 `0.0.0.0:0`), 그 endpoint에서 R에 dial한 뒤 같은 endpoint에서 B의 후보로 dial한다. 직접 dial은 지금처럼 자기 endpoint를 쓴다.
   - B의 `qsh serve --to` 등록 연결은 이제 `PunchEndpoint`에서 나간다. 같은 dual-stack 규칙으로 bind하고(ADR-0046의 `set_only_v6(false)`), 평소에는 서버 설정이 없다. 펀칭 창이 열린 동안만 B의 identity와 trust 평가기로 만든 서버 설정(ADR-0009의 admission 상한과 Retry 그대로)을 건다. stateless reset key는 지금처럼 이 endpoint에서 읽지 않는다(B가 재시작하면 세션도 끝난다).

8. **후보의 종류와 모으기.**
   - **host.** `invite_address`의 경로 조회로 얻은 IPv4 하나와 IPv6 하나에 펀칭 소켓의 포트를 붙인다. 인터페이스를 모두 훑는 새 dependency는 들이지 않는다. IPv6는 global unicast(`2000::/3`)와 ULA(`fc00::/7`)만 쓴다.
   - **reflexive.** R이 연결에서 본 A와 B의 주소다. R이 덧붙이고, 각 끝은 자기 reflexive를 스스로 보내지 않는다(볼 수 없다). R에 닿은 family 하나에 대해서만 생긴다.
   - **derived(추정).** Dave가 정할 것 3의 (가)다. R이 본 B의 주소가 global이 아니면(사설, CGNAT `100.64.0.0/10`, ULA) R이 그 사실을 알리고, A가 R에 닿을 때 쓴 주소가 공인 IPv4면 A가 그 IPv4와 R이 본 B의 포트로 후보 하나를 만든다. A 쪽에서만 만들고 wire로 보내지 않는다.
   - **peer-reflexive.** A의 `PunchEndpoint`가 이번 시도의 tag를 지닌 펀치 datagram을 후보 목록에 없는 주소에서 받으면 그 출발지를 후보로 더하고 곧바로 dial한다. 넷까지다. B는 dial하지 않으므로 배우지 않는다.
   - 포트 범위를 훑는 예측은 하지 않는다. 공유기에 묻는 프로토콜(UPnP·NAT-PMP·PCP)도 쓰지 않는다.
   - **검사(`valid_punch_candidate`).** 주소는 4바이트나 16바이트, 포트는 1..=65535. 거부: unspecified, loopback, link-local(`169.254.0.0/16`, `fe80::/10`), multicast, `255.255.255.255`, `0.0.0.0/8`, `240.0.0.0/4`, IPv4-mapped IPv6. 사설과 CGNAT 주소는 받는다(같은 LAN과 CGNAT 안쪽 경로가 그것이다). 받는 쪽이 같은 검사를 다시 하고, 걸린 후보는 버리고 센다.
   - **상한.** 한 쪽의 후보는 wire에 여덟까지(`MAX_PUNCH_CANDIDATES = 8`), peer-reflexive 넷까지(`MAX_PEER_REFLEXIVE = 4`).
   - **family.** 후보 쌍은 같은 family 안에서만 맺는다. `-4`/`-6`(ADR-0051 결정 7)은 후보를 그 family로 거르고, 거른 뒤 쌍이 없으면 신호를 보내지 않고 `no_candidate_pair`다.

### 신호 wire

9. **capability `punch.v1`과 message.** 모든 빌드가 광고한다(상수 `CAP_PUNCH_V1`). 뜻은 이 peer가 아래 message를 이해하고, 자기 역할에서 처리한다는 것이다. `[punch].mode = "off"`여도 광고하고 요청에는 `UNSUPPORTED`로 답한다. 광고하지 않은 peer에게는 보내지 않는다(§16.4).
   ```proto
   message PunchCandidate { bytes ip = 1; uint32 port = 2; PunchCandidateKind kind = 3; }
   enum PunchCandidateKind { PUNCH_CANDIDATE_KIND_UNSPECIFIED = 0; PUNCH_CANDIDATE_KIND_HOST = 1; PUNCH_CANDIDATE_KIND_REFLEXIVE = 2; }
   // A → R, ControlMessage 90
   message PunchRequest { bytes attempt_id = 1; bytes target_fingerprint = 2; repeated PunchCandidate candidates = 3; }
   // R → B, ControlMessage 91 (등록 연결 위)
   message PunchOffer { bytes attempt_id = 1; bytes initiator_fingerprint = 2; repeated PunchCandidate candidates = 3; }
   // B → R, Response 17
   message PunchAnswer { repeated PunchCandidate candidates = 1; }
   // R → A, Response 16
   message PunchReply { repeated PunchCandidate candidates = 1; PunchCandidate initiator_reflexive = 2; bool target_reflexive_private = 3; PunchRefusal refusal = 4; }
   enum PunchRefusal { PUNCH_REFUSAL_NONE = 0; PUNCH_REFUSAL_TARGET_NOT_REGISTERED = 1; PUNCH_REFUSAL_TARGET_UNSUPPORTED = 2; PUNCH_REFUSAL_TARGET_DENIED = 3; PUNCH_REFUSAL_TARGET_BUSY = 4; PUNCH_REFUSAL_TARGET_TIMEOUT = 5; }
   // A → B, ControlMessage 92 (어느 연결이든)
   message RendezvousQuery {}
   // B → A, Response 18
   message RendezvousList { repeated bytes fingerprints = 1; }
   ```
   번호는 `ControlMessage`의 새 블록 90번대와 `Response`의 16~18이다. 기존 번호는 건드리지 않는다. R 자신의 거부(인가, 속도 상한, 꺼짐, 크기)는 기존 `Error`(`PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`, `UNSUPPORTED`, `INVALID_ARGUMENT`)로 답하고, B 쪽에서 난 일은 `PunchReply.refusal`로 알린다. wire `Error`에는 details가 없어서, A가 "R이 거부"와 "B가 거부"를 가르려면 이 enum이 필요하다.

10. **흐름.**
    - (1) A가 `PunchEndpoint`에서 R에 dial한다. 보통 Hello에 `reverse` 없이 `punch.v1`을 광고한다. (2) R(`qsh listen`)은 지금 `Hello.reverse` 없는 peer를 `UNSUPPORTED`로 닫는다. 양쪽이 `punch.v1`을 광고했으면 이 연결을 **펀칭 연결**로 두고, `PunchRequest` 하나와 `Ping`만 받는다. 다른 요청은 `UNSUPPORTED`다. 3초 안에 요청이 없거나 답을 보낸 뒤 3초가 지나면 닫는다. 동시에 16개까지 둔다(`RENDEZVOUS_MAX_CLIENTS = 16`), 넘으면 `RESOURCE_EXHAUSTED`로 닫는다. (3) R은 인가(결정 6), 속도 상한(결정 11), fingerprint로 live 등록 찾기, B의 `punch.v1` 확인 순으로 보고, `PunchOffer`(A의 host 후보 + R이 본 A의 reflexive)를 등록 연결로 보낸다. (4) B는 인가하고, 서버 창을 열고, 자기 host 후보를 `PunchAnswer`로 답하고, 곧바로 결정 14의 일정을 시작한다. (5) R은 B의 host 후보에 R이 본 B의 reflexive를 더해 `PunchReply`로 A에 보낸다. (6) A는 답을 받은 때부터 일정을 시작하고, 끝나면 R 연결을 코드 0으로 닫는다.
    - R은 B의 답을 1.5초 기다린다(`PUNCH_ANSWER_TIMEOUT`). 넘으면 `refusal = TARGET_TIMEOUT`이다. B가 늦게 답해도 R은 버리고, B의 창은 결정 14대로 스스로 닫힌다.
    - R은 내용을 고치지 않고 중계하며, 자기가 본 reflexive만 더한다. R이 주는 것은 길이지 신원이 아니다.

11. **상한과 검사.**
    - `attempt_id`는 정확히 16바이트(A가 CSPRNG로 만든다), fingerprint는 정확히 32바이트, 후보는 여덟 이하, 각 message의 부호화 길이는 1 KiB 이하(`PUNCH_MESSAGE_MAX = 1024`)다. 어기면 `INVALID_ARGUMENT`이고 R의 펀칭 연결은 닫는다. 기존 frame 상한(`CONTROL_FRAME_MAX`)은 그대로 먼저 걸린다.
    - **속도 상한.** R: A의 fingerprint마다 진행 중인 시도 하나, 60초에 여섯(`PUNCH_RATE = 6`). B: A의 fingerprint마다 60초에 여섯, 동시에 열린 창 넷(`MAX_PUNCH_WINDOWS = 4`). 넘으면 R은 `RESOURCE_EXHAUSTED`, B는 `refusal = TARGET_BUSY`이고 A에게는 `rate_limited`다.
    - `RendezvousList`는 fingerprint 넷까지, 각 32바이트다. 넘으면 A가 앞의 넷만 쓴다.

12. **인증: 중개자가 할 수 없는 것.** 끝단의 QUIC handshake가 지금처럼 양쪽 pin을 검사하므로 R은 A나 B를 사칭할 수 없다.
    - A는 펀칭으로 dial한 연결에서 상대가 내민 fingerprint가 **B의 pin과 정확히 같을** 때만 받는다. 지금의 직접 dial은 trust store 어딘가에 pin된 상대면 TLS 단계에서 받는다. 펀칭에서는 R이 후보를 고르므로, 그 규칙이면 R이 A를 A가 pin한 다른 peer C로 보낼 수 있다. 다르면 그 연결을 `0x1001`로 닫고 다른 후보를 계속 보며, 모두 그렇게 끝나면 `peer_mismatch`다.
    - B는 창에서 받은 연결의 검증된 fingerprint가 offer의 `initiator_fingerprint`와 같을 때만 serve한다. 아니면 `0x1001`로 닫는다. 그 뒤의 요청은 지금의 `qsh serve` 연결과 같은 인가와 quota를 지난다.
    - R이 할 수 있는 것: 신호를 떨어뜨리거나 늦추기, 틀린 후보 주기(결과는 실패), A가 B에게 언제 붙으려 하는지 알기. 셋 다 남는 위험이다(결과 절).
    - 경로 밖 공격자는 `attempt_id`를 모르므로 tag가 맞는 펀치 datagram을 만들지 못한다. 만들어도 A가 그 주소로 dial한 연결은 B의 pin에 걸린다.

### 동시 송신

13. **펀치 datagram.** 16바이트다(`PUNCH_DATAGRAM_LEN = 16`). 머리 4바이트 `00 71 70 01`과 tag 12바이트이고, tag는 `attempt_id`를 key로 한 BLAKE3 keyed hash에 방향 표지(`"qsh punch a->b"`, `"qsh punch b->a"`)를 넣은 값의 앞 12바이트다. 첫 바이트의 fixed bit가 0이고 길이가 21바이트 이하라서, 감싼 소켓이 놓쳐 quinn에 닿아도 quinn은 답 없이 버린다. 받는 쪽의 감싼 소켓은 GRO로 묶인 버퍼를 segment마다 보고, 머리가 맞는 16바이트 datagram을 quinn에 넘기지 않고 `(출발지, tag)`로 알린다. tag가 이번 시도의 것이 아니면 버리고 센다. 펀치 datagram은 펀칭 소켓에서만 나가고 내용이 고정이라 `qsh-core`가 다른 바이트를 실을 길이 없다.

14. **일정.** 두 끝이 같은 일정을 쓴다.
    - **시작.** B는 `PunchAnswer`를 보낸 때, A는 `PunchReply`를 받은 때가 t=0이다. 그래서 B가 대략 B→R과 R→A의 한쪽 지연만큼 먼저 시작해 자기 NAT를 먼저 연다.
    - **펀치 datagram.** 상대 후보마다 t = 0, 50, 100, 200, 400, 800, 1600, 3200 ms에 하나씩 보낸다(`PUNCH_OFFSETS_MS`, 여덟 개). 한 시도에서 한 끝이 보내는 것은 많아야 후보 여덟 × 여덟 = 64개, 1 KiB다. 연결이 채택되면 남은 것은 보내지 않는다.
    - **handshake.** A만 TLS client다. t=0에 B의 후보마다 `connect_with`로 Initial을 보내고, 이 연결들의 `initial_rtt`는 100 ms(`PUNCH_INITIAL_RTT`)다. 그러면 quinn의 Initial 재전송이 약 0.3, 0.9, 2.1, 4.5초에 온다. peer-reflexive 후보는 배운 즉시 같은 방식으로 dial한다. B는 dial하지 않는다. 역할을 이렇게 둔 이유는 A의 dial 분류와 오류 경로(`classify_dial_failure`, `Dialed::observation`)와 B의 inbound serve 경로를 그대로 쓰기 위해서다. QSH 역할은 Hello가 정하므로(§11의 대칭 원칙) TLS 역할과 무관하다.
    - **창.** B의 서버 창은 t=0부터 6초 열린다(`PUNCH_TARGET_WINDOW = 6000 ms`). 한 offer에서 handshake 넷까지 받고(`MAX_HANDSHAKES_PER_OFFER = 4`), 창이 닫히면 서버 설정을 내린다. 이미 선 연결은 남는다. 동시에 열린 창이 있으면 서버 설정은 마지막 창이 닫힐 때 내린다.

### 채택과 포기

15. **첫 handshake 채택.** A는 TLS handshake가 끝나고 결정 12의 fingerprint 검사를 통과한 첫 연결을 채택하고, 그 연결에서만 Hello를 보낸다. 남은 것은 이렇게 끝낸다. 진행 중인 handshake는 버리고(quinn이 정리한다), 이미 선 다른 연결은 새 close 코드 `0x1006`(`CLOSE_CODE_NOT_ADOPTED`, reason `not adopted`)으로 닫는다. 직접 dial과 경주했으면(결정 16) 진 쪽도 같다. 채택된 연결과 그 endpoint가 지금의 `Dialed`로 돌아가 이후는 보통 정방향 연결과 같다. B는 채택되지 않은 연결이 `0x1006`으로 닫히는 것을 보고 아무것도 남기지 않는다. `0x1006`은 §16.3의 close 코드 규율(동결 밖, major 안에서 재배치하지 않음)을 따른다.

16. **route 순서와 경주.** `docs/CLI.md` §6.1의 순서에 펀칭이 끼는 자리는 이렇다.
    1. live 역방향 등록이 있으면 지금처럼 그것을 쓴다. 펀칭하지 않는다.
    2. pin이나 `hosts.toml`에 주소가 있으면 직접 dial한다. 그 host에 중개자 후보가 있고 `[punch].mode`가 `auto`면, dial을 시작하고 1000 ms(`PUNCH_HEAD_START`) 안에 연결이 서지 않거나 그 전에 dial이 바로 실패하면(no route, 거절) 펀칭을 나란히 시작한다(Dave가 정할 것 4). 먼저 선 쪽을 쓴다.
    3. 주소 없는 pin에 중개자 후보가 있으면 곧바로 펀칭한다. 지금의 "pinned without address" `HOST_NOT_FOUND`는 중개자 후보가 없을 때만 난다.
    4. 그래도 연결이 없으면 지금의 serve 되살리기(SSH 부트스트랩 pin, ADR-0051 결정 4)로 간다. 되살린 on-demand serve는 등록을 들지 않으므로 다시 dial은 직접 dial만이다.
    5. 모르는 이름이면 지금처럼 자동 부트스트랩이다. 펀칭에는 pin이 필요하므로 이 갈래에는 펀칭이 없다.
    - **예산.** 신호(R dial, 요청, 답)는 3000 ms(`PUNCH_SIGNAL_BUDGET`), 답을 받은 뒤 채택까지 5000 ms(`PUNCH_WINDOW`), 합해 8000 ms다. 직접 dial과 경주하면 펀칭은 1초에 시작해 9초에 끝나므로 전체가 지금의 dial 시한 10초를 넘지 않는다. `-o ConnectTimeout`이 시한을 줄이면 펀칭 예산은 남은 시간으로 잘린다. 어느 경우든 펀칭은 명령의 dial 시한을 늘리지 않는다.

17. **포기와 그 뒤.**
    - 포기 사유는 닫힌 어휘다: `no_rendezvous`(후보 없음), `rendezvous_unreachable`(R dial 실패), `rendezvous_unsupported`(`punch.v1` 없음, 꺼짐, 등록을 받지 않는 peer), `rendezvous_denied`, `target_not_registered`, `target_unsupported`, `target_denied`, `rate_limited`, `no_candidate_pair`, `peer_mismatch`, `timeout`.
    - 펀칭이 실패해도 그것만으로는 오류를 내지 않고 다음 route로 간다. 모든 route가 실패하면 명령의 오류는 지금 그 자리에서 나던 오류(직접 dial의 `CONNECTION_FAILED`·`TIMEOUT`, 주소 없는 pin의 `CONNECTION_FAILED`)이고, `details`에 additive `punch: {"rendezvous": "<name>", "reason": "<사유>"}`가 붙는다. 사람 모드의 오류 줄에는 `; hole punching via <name> failed: <사유>`가 덧붙는다. ADR-0050 결정 3의 "이유를 담은 오류"가 이것이다.
    - 펀칭이 성공하면 기본 verbosity에서 아무것도 쓰지 않는다. 결과는 doctor와 `-v`의 `qsh::punch` 줄(결정 20)에서만 보인다.
    - 새 `ErrorCode`는 없다.

### 연결 이동과 resume

18. **펀칭한 경로가 바뀌면.**
    - 채택된 연결은 보통 연결이다. keep-alive 15초가 양쪽 NAT 매핑을 살린다(B의 ACK가 B 쪽 매핑을 갱신한다). connection migration은 지금처럼 시도한다(`docs/design/protocol.md` §2, 최적화일 뿐이다). A의 바깥 주소가 바뀌면 B의 NAT가 EIF가 아닌 한 새 주소의 패킷을 막아 migration은 실패하고, path 사망 감지(약 1초, §10)가 recovery를 연다.
    - recovery의 재dial은 처음 해석한 주소를 다시 쓰는 대신 **route를 다시 돈다**: 직접 dial과 펀칭의 경주(결정 16)를 새 후보로 다시 한다. 그래서 IP가 바뀐 뒤에는 다시 펀칭한다. 펀칭한 route의 시도 하나의 재dial 시한은 `REDIAL_DEADLINE`(2초) 대신 펀칭 예산(8초)이다. 그 뒤 resume은 §10 그대로이고, resume token은 route가 아니라 peer 신원에 묶여 있으므로 직접·펀칭·역방향 어느 route로 세운 연결에서도 같은 세션을 이어 붙인다. 입력의 무손실·무중복(§10-5)도 그대로다.
    - B의 주소가 바뀌면 B의 등록 recovery(ADR-0041)가 먼저 R에 다시 등록하고, A의 recovery 시도가 그 뒤에 펀칭한다. 등록이 아직 없으면 `target_not_registered`로 그 시도가 실패하고 다음 시도로 넘어간다.
    - `--supervise` 터널의 재dial도 같은 route 재해석을 쓴다.

### 사용자 표면

19. **플래그, 키, 명령.** ADR-0050 결정 2대로 플래그와 `qsh config` 키를 함께 둔다.
    - 전역 플래그 `--no-punch`와 키 `[punch].mode = "auto" | "off"`(기본 `auto`). `off`면 이 장비는 펀칭을 시작하지 않고, 중개하지 않고(`PunchRequest`에 `UNSUPPORTED`), offer를 받지 않는다(`refusal = TARGET_UNSUPPORTED`). client 명령은 명령마다 읽고, `qsh listen`과 `qsh serve --to`는 시작할 때 한 번 읽는다(`applies_from`이 그렇게 적힌다). 읽히지 않는 `config.toml`이면 지금의 다른 키와 같은 규칙으로 `CONFIG_ERROR`다.
    - `--rendezvous <peer>`: 정방향 route로 dial하는 명령마다 받는다. 이번 명령에서 중개자 후보를 이것 하나로 바꾼다. 주소 있는 pin이 아니면 `HOST_NOT_FOUND`다. 저장하지 않는다.
    - `qsh trust rendezvous <name> [<peer>...] [--clear]`: 로컬 op `trust.set_rendezvous`(인가 불요, `trust.set_role`과 같은 잠금 규율). `data`는 `{"peer": TrustPeer}`다.
    - `docs/CLI.md` §7, §6.11, §6.23을 고치고 `cargo xtask man`으로 man page를 다시 만든다.

20. **보이는 곳.**
    - **doctor.** `qsh doctor <host>`는 그 host에 직접 경로가 없을 때(직접 probe 실패나 주소 없는 pin) 펀칭을 한 번 해 본다. 새 코드 셋: `punch_succeeded`(info, 채택된 후보의 종류와 family), `punch_failed`(warn, `details.reason`은 결정 17의 어휘), `punch_no_rendezvous`(info, 직접 경로가 없는데 중개자 후보도 없음, remedy는 `qsh trust rendezvous`). `EXPECTED_DOCTOR_CODES`에 더한다. `DoctorData.punch`(optional) = `{rendezvous, outcome, reason, candidate_kind, family, elapsed_ms}`. 주소 없는 pin의 `host_pinned_without_address`는 그 pin에 중개자 후보가 있으면 내지 않는다.
    - **로그.** 새 tracing target `qsh::punch`가 시도마다 `attempt`, `signaled`, `adopted`, `gave_up` 한 줄 JSON을 낸다. 필드는 중개자 이름(이 장비의 pin 이름), 종류·family별 후보 개수, 채택된 후보의 종류와 family, 걸린 시간, 사유, tag가 틀린 datagram과 검사에 걸린 후보의 개수다. **IP와 포트는 어느 verbosity에서도 싣지 않는다.** `qsh::adapt`처럼 기본에서 꺼져 있고 `-v`나 `QSH_LOG=qsh::punch=info`가 켠다. R과 B도 같은 target으로 `relayed`, `window_opened`, `window_closed`를 낸다.
    - **CONTROLLER_UNREACHABLE.** "QSH provides no relay, NAT traversal, or discovery" 문장을 "QSH provides no relay; hole punching needs a rendezvous both ends can reach, and the controller is that rendezvous"의 뜻으로 고친다. 문안 정본은 그 상수 하나이고 `README.md`의 Known limitations도 같이 고친다(ADR-0050 결과 절의 README NAT 문장).

21. **JSON 추가는 모두 additive다.** `capabilities` 결과의 새 문자열 `punch.v1`(`capabilities.json` golden을 `QSH_UPDATE_FIXTURES=1`로 다시 만들고 계약 변경과 같은 무게로 본다), `TrustPeer.rendezvous`(비었으면 키가 없다, 그래서 기존 `trust.*` fixture는 그대로다), `trust.set_rendezvous` op, `CONNECTION_FAILED`·`TIMEOUT`의 `details.punch`, `DoctorData.punch`, doctor 코드 셋, `config.list`의 키 하나, action 어휘의 `host.punch`(`acl.check`·`acl.show` 출력). 새 fixture(`trust_set_rendezvous.json`, `trust_list_rendezvous.json`, `error.CONNECTION_FAILED.punch.json`, `doctor_punch.json`, `acl_show_host_punch.json`)를 `REQUIRED_FIXTURES`에 올리고 기존 fixture는 고치지 않는다. 기계 모드의 stdout은 지금처럼 JSON뿐이다.

### 측정 도구

22. **NAT 시뮬레이터를 기능보다 먼저 세운다(`docs/ROADMAP.md` §6.1 원칙 2).** `qsh-testkit`에 `netsim`을 둔다.
    - 진짜 quinn이 가상 UDP 망 위에서 돈다. `netsim`은 quinn의 `AsyncUdpSocket`을 구현한 가상 소켓을 주고, `PunchEndpoint`와 `Listener`가 `SocketSource`로 그것을 받는다. 망에는 가상 주소(문서용 대역과 사설 대역), 링크별 지연·손실(seed 고정), 그리고 NAT 상자가 있다. path validation, Retry, 재전송은 quinn-proto가 실제로 한다. 시험하는 것이 mock이 아니라 가상 선 위의 실제 QUIC이라는 점이 L4 chaos proxy의 원칙(`docs/design/testing.md` L4 "대안 대비 선택 근거")과 같다. 다만 chaos proxy는 loopback의 진짜 소켓 사이에 서는데, NAT 뒤의 "안쪽"은 loopback에서 만들 수 없어 가상 망이 필요하다.
    - NAT 상자의 축은 RFC 4787 그대로다. 매핑(EIM·ADM·APDM), 필터(EIF·ADF·APDF), 포트 배정(보존·순차·무작위), hairpin 유무, 매핑 수명(기본 30초). 프리셋: `none`, `full_cone`(EIM·EIF·보존), `restricted`(EIM·ADF·보존), `port_restricted`(EIM·APDF·보존), `symmetric`(APDM·APDF·무작위), `firewall_v6`(변환 없음·APDF), `port_restricted_random`(EIM·APDF·무작위). NAT 상자 자체를 RFC 4787 행마다 표 테스트로 고정한다(`nat_box_follows_rfc4787_behaviors`).
    - 로컬 주소 관측과 dial 시한도 주입받아, 시험이 세 OS에서 root 없이 같은 결과를 낸다. 실패 메시지는 seed를 찍는다.
    - 첫 측정은 wire 없이 한다: 두 `PunchEndpoint`에 후보를 손으로 넣고 결정 13·14의 일정만으로 NAT 쌍 표를 돌려 결정 23의 기대를 확인하고, 그 수치(성공 쌍, 채택까지 걸린 시간)를 이 ADR의 개정 이력에 적는다.

23. **기대 표.** A와 B가 각각 다섯 프리셋(`none`, `full_cone`, `restricted`, `port_restricted`, `symmetric`) 뒤에 있고 R은 공인 주소인 25쌍에서 다음이 성립한다.
    - **실패가 기대되는 쌍은 셋**: (symmetric, port_restricted), (port_restricted, symmetric), (symmetric, symmetric). 한쪽은 목적지마다 포트가 바뀌고 다른 쪽은 주소와 포트를 모두 걸러서, 포트를 예측하지 않으면 열리지 않는다. 이 쌍은 `timeout`으로 예산 안에 끝나고 어떤 연결도 남기지 않아야 한다.
    - **나머지 22쌍은 성공한다.** (symmetric, restricted)과 (symmetric, full_cone)은 B가 A의 IP만 거르거나 거르지 않으므로 A의 Initial이 지나간다. (restricted, symmetric)과 (full_cone, symmetric)은 A가 B의 펀치 datagram 출발지를 peer-reflexive로 배워 그 주소로 dial할 때 열린다(결정 8).
    - **장면 넷을 따로 둔다.** (a) A와 B가 같은 NAT 뒤(host 후보가 이긴다), (b) 이중 NAT(EIM 위의 EIM, CGNAT 모양)는 성공, (c) IPv6만 있고 양쪽이 `firewall_v6`이면 성공, (d) R이 B와 같은 `port_restricted` NAT 뒤에 있고 A만 밖에 있으면 derived 후보로 성공하고, 같은 장면에서 B의 NAT가 `port_restricted_random`이면 `timeout`으로 실패한다.

24. **커널 NAT와 대조한다.** Linux에서 network namespace와 nftables로 A·NAT·R·NAT·B를 세우는 하네스(`scripts/netns/punch.sh`, sudo 필요)를 두고, release 빌드의 `qsh` 바이너리로 돈다. `masquerade`(Linux conntrack: EIM, 포트 보존, APDF)와 `masquerade random-fully`(목적지마다 무작위 포트)를 쓴다. masquerade × masquerade는 성공, random-fully × masquerade는 실패, random-fully × NAT 없음은 성공이어야 하고, 이 결과가 netsim의 같은 프리셋과 맞아야 한다. `ci.yml`의 새 job `punch-netns`(ubuntu, `QSH_ACCEPTANCE_NETNS=1`)가 돈다. 이 job을 merge 필수로 만드는 것은 저장소 설정이라 사람 몫이다.

### 플랫폼

25. **세 OS가 같은 기능을 갖는다.** 세 역할(A, R, B)이 모두 Linux·macOS·Windows에서 같은 코드로 돌고, netsim 시험은 세 OS CI에서 돈다.
    - **Linux.** dual-stack은 `IPV6_V6ONLY=0`. 커널 NAT 대조는 결정 24.
    - **macOS.** dual-stack은 같다. 응용 방화벽은 안에서 먼저 보낸 흐름의 답을 막지 않는다고 보고 설계가 그 밖의 허용 규칙에 기대지 않는다. "들어오는 연결 모두 차단"이 켜진 장비에서의 동작은 사람 회차가 기록한다.
    - **Windows.** dual-stack은 ADR-0046의 `set_only_v6(false)`다. 닫힌 포트로 간 펀치 datagram의 ICMP가 `WSAECONNRESET`으로 올라와도 quinn이 무시하고, 감싼 소켓도 그 오류를 그대로 넘긴다(`a_punch_to_a_closed_port_leaves_the_endpoint_alive`, Windows CI). Windows Defender 방화벽의 상태 기반 UDP 필터는 APDF처럼 동작하므로 B가 먼저 보낸 주소의 답은 통과한다. 새 방화벽 규칙이나 관리자 권한은 필요 없다. `qsh serve --to` 등록 소켓이 방화벽 첫 허용 창을 띄우는지는 사람 회차가 기록한다.
    - `-4`/`-6`, `-o ConnectTimeout`은 세 OS에서 같은 뜻이다.

### 위협 모델

26. **새 행과 고정 테스트.**
    - **스푸핑.** (a) R이 A를 A가 pin한 다른 peer로 보낸다: 펀칭한 dial은 B의 pin과 같은 fingerprint만 받는다(`a_punched_dial_rejects_a_different_pinned_peer`). (b) 경로 밖에서 펀치 datagram을 위조해 peer-reflexive 후보를 심는다: tag가 `attempt_id`에 묶이고 peer-reflexive는 넷까지이며, 심겨도 dial이 pin에 걸린다(`a_punch_datagram_with_a_wrong_tag_adds_no_candidate`).
    - **무단접근.** (a) 허락받지 않은 peer가 R을 써서 B에 신호를 보낸다: R과 B가 각자 `host.punch`를 자원 전에 판정하고 감사한다(`a_punch_request_without_host_punch_reaches_no_target`, `a_punch_offer_for_an_unauthorized_initiator_opens_no_window`). (b) B의 창으로 다른 peer가 들어온다: 창은 6초, offer당 handshake 넷, offer의 fingerprint만 serve한다(`a_punch_window_serves_only_the_initiator`, `the_server_config_is_removed_when_the_last_window_closes`).
    - **자원고갈, 반사와 증폭.** 허락받은 A가 R과 B를 시켜 제3자에게 패킷을 쏘게 한다: 후보 검사(결정 8), 시도당 한 끝이 64개·1 KiB, 속도 상한과 동시 상한(결정 11), R의 펀칭 연결 16개와 3초 수명. 요청 한 번(1 KiB 이하)이 제3자에게 낳는 것은 많아야 1 KiB다(`a_punch_attempt_sends_at_most_64_datagrams_per_end`, `rendezvous_rate_limits_an_initiator`, `punch_candidate_validation_table`).
    - **정보노출.** R은 A와 B의 LAN 주소(host 후보)와 "A가 언제 B에 붙으려 하는가"를 새로 안다. A와 B는 서로의 주소를 안다(붙으면 어차피 안다). `RendezvousQuery`는 B의 controller fingerprint를 알린다. 셋 다 허락받은 peer에게만 가고, 로그·감사·JSON에 주소가 없다(`punch_logs_and_audit_carry_no_addresses`가 netsim 주소가 stderr와 감사 파일에 한 번도 나오지 않음을 본다).
    - **무결성.** B가 거짓 `RendezvousList`로 A의 힌트를 바꾼다: A가 주소와 함께 pin한 fingerprint만 남는다(`rendezvous_hints_keep_only_pinned_peers_with_an_address`).
    - **가용성.** 펀칭이 접속을 늦춘다: 직접 경로가 1초 안에 서면 R에 아무것도 보내지 않고, 펀칭은 dial 시한을 늘리지 않는다(`punch_never_extends_the_dial_past_its_timeout`, `a_direct_dial_that_succeeds_sends_nothing_to_the_rendezvous`).
    - **파서 표면.** 새 message는 `decode_control`이 덮도록 corpus를 더하고, 새 fuzz 타깃 `punch_candidates`가 후보 검사, tag 대조, `PunchReply`·`RendezvousList` 처리, 감싼 소켓의 수신 거르기(GRO segment 경계 포함)를 먹인다.

### 수용 기준(M24 DoD)

27. 1. **NAT 표.** `punch_nat_matrix`(netsim, L4)가 결정 23의 25쌍을 seed 다섯으로 돈다. 22쌍은 모든 seed에서 채택된 연결 위에서 `exec` 하나가 끝나고, 세 쌍은 모든 seed에서 `timeout`으로 `PUNCH_SIGNAL_BUDGET + PUNCH_WINDOW` 안에 끝나며 연결이 남지 않는다. 링크마다 한쪽 25 ms(A–R, B–R, A–B), 손실 0에서 성공 쌍의 route 시작부터 채택까지 p95 ≤ 1.0 s이고, 같은 표를 A–B 손실 5%로 돌려 성공 쌍이 모두 예산 안에 선다.
    2. **장면.** 결정 23의 (a)~(d)가 한 시험씩 있다(`punch_same_nat_uses_host_candidates`, `punch_through_double_nat`, `punch_ipv6_firewalls_only`, `derived_candidate_reaches_a_target_behind_the_rendezvous_nat`과 그 무작위 포트 실패 짝).
    3. **경주와 예산.** 직접 경로가 살아 있으면 R의 펀칭 연결이 0개다. 직접 경로를 blackhole하면 펀칭한 연결이 채택되고 전체가 10초 안이다. `-o ConnectTimeout=3`이면 3초 안에 끝난다. 주소 없는 pin은 곧바로 펀칭한다. `--no-punch`와 `[punch].mode = "off"`이면 `PunchRequest`가 나가지 않고 지금과 같은 오류가 난다.
    4. **포기 사유.** 결정 17의 사유마다 한 행(`punch_give_up_reasons`)이 그 상황을 만들고, `details.punch.reason`, doctor의 `punch_failed`, `qsh::punch`의 `gave_up` 줄이 같은 값을 보인다. 펀칭이 실패하면 SSH 부트스트랩 pin의 serve 되살리기가 지금처럼 뒤따른다.
    5. **인증과 인가.** 결정 26의 스푸핑·무단접근 시험이 있고, 각 거부가 R 또는 B의 감사 파일에 구조 필드만으로 남는다. 감사 쓰기가 실패하면 offer가 나가지 않는다.
    6. **상한.** 결정 11·13·14의 상한(후보 여덟, peer-reflexive 넷, 끝마다 datagram 64개, 속도 여섯/60초, 진행 중 하나, 창 넷, offer당 handshake 넷, R의 펀칭 연결 16개, message 1 KiB)이 한 행씩 표로 고정된다(`punch_bounds`).
    7. **채택.** 후보 셋이 모두 통하는 장면에서 정확히 하나가 채택되고, 나머지가 1초 안에 `0x1006`으로 닫히며, B의 서버 설정이 창 시작 뒤 6초 안에 내려간다.
    8. **이동과 resume.** 펀칭한 경로 위의 대화형 attach에서 A의 NAT 바깥 주소를 바꾸면 같은 세션이 4초 안에 resume되고 끊긴 동안의 입력이 한 번만 적용된다(10회 모두). B가 재등록하는 장면(`a_punched_session_resumes_after_the_target_re_registers`)과 `--supervise -L` 터널의 재수립이 각각 한 시험씩 있다.
    9. **기능.** 펀칭한 연결 위에서 화면 동기화 attach(예측 포함), `exec`, `-L` 터널, `qsh cp` 한 파일이 각각 netsim에서 통과한다.
    10. **힌트.** 직접 경로로 한 번 붙은 뒤 B의 pin에 `rendezvous`가 쓰이고, 다음 명령이 직접 경로 없이 그 힌트로 펀칭한다. pin되지 않은 fingerprint는 버려진다. `qsh trust rendezvous`의 설정과 `--clear`, `--rendezvous`의 우선이 시험된다.
    11. **계약.** `capabilities.json` golden, 결정 21의 새 fixture, `EXPECTED_DOCTOR_CODES`의 셋, `every_config_key_is_settable`, role 표(`role_grants_table`의 `host.punch` 열), man page(`checked_in_man_pages_match_the_generator`)가 초록이다.
    12. **fuzz.** `decode_control` corpus에 새 message가 들어가고 새 타깃 `punch_candidates`가 더해져 `fuzz/README.md`, `CLAUDE.md`, `docs/design/testing.md` L8의 개수가 26이 된다.
    13. **커널 대조.** 결정 24의 `punch-netns` job이 기대 셋을 통과한다.
    14. **세 OS.** 1~10은 Linux·macOS·Windows CI에서 돈다. Windows는 `a_punch_to_a_closed_port_leaves_the_endpoint_alive`도 돈다.
    15. **회귀 없음.** 힌트가 없는 host의 직접 dial은 소켓도 바이트도 지금과 같다(`a_host_without_rendezvous_dials_exactly_as_before`). 기존 역방향 시험, `tunnel_echo_under_load`, 등록 감시 시험이 diff 없이 통과한다.
    16. threat model에 결정 26의 행이 고정 테스트와 함께 들어간다.

## 근거

- **중개자를 `qsh listen`으로 두는 이유.** B에게 말을 걸려면 B가 R에 상시 연결을 들고 있어야 한다. 그런 연결은 지금 역방향 등록 하나뿐이고, 그것은 이미 NAT 매핑을 keep-alive로 살리고, R은 Retry로 검증된 B의 바깥 주소를 이미 안다. 새 상시 연결을 만드는 대신 있는 것에 message 둘을 얹는다. 사용자가 상시 장비에 돌리는 것도 이미 `qsh listen`이다.
- **B를 TLS 서버로 두는 이유.** A의 쪽에서는 펀칭한 연결이 보통 정방향 dial과 같아 dial 분류, pin 불일치 처리, `Ops`가 그대로다. B의 쪽에서는 창으로 들어온 연결이 `qsh serve`의 inbound와 같아 admission, Retry, 인가, quota가 그대로다. 반대로 두면 A가 서버 endpoint를 열어야 하고, 사람이 앉은 장비가 임의의 inbound를 받는 시간이 생긴다.
- **같은 소켓을 쓰는 이유.** reflexive 후보는 R과 말한 소켓의 매핑이다. 다른 소켓에서 보내면 EIM NAT에서도 다른 매핑이 생겨 후보가 틀린다. quinn은 감싼 소켓을 받을 수 있어서 소켓을 둘로 나누지 않아도 펀치 datagram을 같은 포트로 보낼 수 있다.
- **펀치 datagram을 따로 두는 이유.** A의 Initial만으로도 A 쪽 NAT는 열리지만 B는 TLS 서버라 dial하지 않으므로 B 쪽 NAT를 여는 것이 없다. 짧은 고정 datagram은 quinn이 답하지 않고 버리는 크기이고, tag를 실으면 A가 B의 진짜 매핑을 peer-reflexive로 배워 symmetric NAT 한쪽의 경우를 넷 더 연다.
- **고정 일정인 이유.** ICE의 후보 쌍 우선순위와 연결성 검사는 relay 후보와 여러 경로를 고를 때 값이 있다. qsh는 relay가 없고 후보가 끝마다 넷 안팎이라, 모두 나란히 보내고 pin으로 확인된 첫 handshake를 쓰는 편이 상태가 적고 시험하기 쉽다. 같은 LAN 후보가 있으면 RTT가 가장 짧아 저절로 이긴다.
- **dial 시한 안에 가두는 이유.** "실패하면 포기"가 사용자에게 뜻하는 것은 기다림에 끝이 있다는 것이다. 펀칭이 없던 때의 최악(10초 dial 시한)보다 길어지지 않게 하면 펀칭이 안 되는 망의 사용자가 손해 보지 않는다.
- **새 action인 이유.** 펀칭은 R과 B에 자원(신호 상태, 서버 창, 송신)을 만든다. 자원 전 단일 choke point(CLAUDE.md 보안 기본값)를 지나려면 판정할 이름이 있어야 하고, 이름이 있어야 감사와 `acl check`가 같은 근거를 말한다.
- **netsim을 먼저 세우는 이유.** 홀펀칭은 실기기로만 재면 NAT 종류를 고를 수 없고 재현되지 않는다. RFC 4787의 축으로 NAT를 만들면 25쌍을 PR마다 세 OS에서 돌릴 수 있다. 모델이 현실과 어긋날 위험은 커널 NAT 대조(결정 24)와 사람 회차가 줄인다.

## 대안과 기각 사유

- **공용 STUN 서버로 reflexive를 얻는다.** ADR-0050이 기각했다. 중개자가 같은 일을 한다.
- **relay로 떨어진다.** ADR-0050과 PRD §14가 기각했다.
- **포트 범위 예측(birthday 방식으로 수백 포트를 연다).** symmetric 쌍 일부를 열지만 송신량이 수백 배가 되어 반사·증폭 상한과 맞지 않고, 공유기의 매핑 표를 채운다. 기각.
- **UPnP·NAT-PMP·PCP로 공유기에 포트를 연다.** 제3자 서비스는 아니지만 공유기 설정을 바꾸는 부수효과가 있고 집 밖 망에서는 대개 없다. M24 밖으로 미룬다.
- **ICE 라이브러리를 들인다.** relay와 후보 우선순위를 포함한 큰 표면이 따라오고, quinn과 소켓을 나눠 쓰는 방식이 맞지 않는다. 기각.
- **양쪽이 모두 TLS client로 서로 dial한다(동시 open).** 연결이 두 개 서서 누가 이겼는지 합의해야 하고, 두 끝 모두 서버 설정을 열어야 한다. 기각.
- **A를 TLS 서버로 둔다.** 결정 14와 근거 절. 사람이 앉은 장비가 inbound를 받는 창이 생기고 A의 dial 경로를 새로 짜야 한다. 기각.
- **이름으로 B를 부른다.** 이름은 장비마다 다르고 R의 이름 확정 규칙(§11-2)과 섞인다. fingerprint가 모두에게 같은 값이다. 기각.
- **힌트를 `hosts.toml`에 쓴다.** `hosts.toml`은 qsh가 쓰지 않는 손편집 주소록이다(`docs/CLI.md` §6.1). 배운 값을 쓸 수 없다. 기각.
- **힌트를 별도 상태 파일에 둔다.** 같은 pin에 대한 정보가 두 파일로 갈리고, pin을 지우거나 바꿀 때 함께 정리해야 한다. pin에 이미 주소가 있듯 중개자도 그 옆에 둔다. 기각.
- **처음부터 직접 dial과 펀칭을 나란히 한다.** 접속마다 중개자에게 목적지를 알린다. Dave가 정할 것 4.
- **펀칭 실패를 바로 오류로 낸다.** 직접 경로가 늦게 서거나 serve 되살리기가 되는 경우를 막는다. 펀칭은 route의 한 칸이고, 모든 칸이 실패했을 때의 오류에 사유를 싣는다. 기각.

## 결과

- 개정할 문서: `docs/PRD.md` §9(action 어휘 12종). `docs/design/protocol.md` §4(`punch.v1`), §9(새 message와 enum), §11(펀칭 연결), 새 §19(홀펀칭: 역할, 후보, 흐름, 상한, 펀치 datagram, 일정, 채택, close 코드 `0x1006`). `docs/design/architecture.md` §1(`PunchEndpoint`, `qsh-core::punch`), §6(`host.punch`), §7(`trust.toml`의 `rendezvous`). `docs/design/testing.md` L4(netsim), L6, L8, CI 구성(`punch-netns`). `docs/CLI.md` §2.4·§2.5(op와 action), §6.1, §6.11, §6.13, §6.17, §6.23, §7. ADR-0045 결정 2에 이 ADR을 가리키는 개정 이력 줄. `fuzz/README.md`, `README.md`의 NAT 문장. 새 사람 회차 문서 `docs/campaigns/m24-punch.md`(실제 망: 휴대폰 테더링의 CGNAT, 집 공유기, 회사 망, IPv6 전용 망에서 A–B 쌍을 기록. DoD에는 넣지 않는다).
- 새 threat model 행(결정 26): 스푸핑 둘, 무단접근 둘, 자원고갈 하나, 정보노출 하나, 무결성 하나, 가용성 하나, 파서 표면.
- 남는 위험:
  - 양쪽이 목적지마다 포트를 바꾸는 NAT 조합과 symmetric × port-restricted는 열리지 않는다. 그런 망에서는 기존 route와 SSH 경로만 남는다(PRD §12).
  - 중개자는 누가 언제 누구에게 붙으려 하는지와 양쪽의 LAN 주소를 안다. 사용자 자신의 장비이고 pin과 role로 허락한 장비라는 것이 통제의 전부다.
  - 중개자가 신호를 떨어뜨리면 펀칭이 안 된다. 다른 route가 있으면 그것으로 간다.
  - 후보는 family 하나씩만 reflexive를 얻는다. A가 R에 IPv6로 닿고 B가 IPv4로 등록했으면 IPv4 쌍은 host 후보에 기대고 대개 실패한다. IPv6 쌍이 남는다.
  - 펀칭한 경로는 A의 주소가 바뀌면 migration이 대개 실패하고 다시 펀칭해야 해서, 직접 경로보다 recovery가 길다(결정 18, 예산 8초).
  - netsim의 NAT 모델과 실제 공유기가 다를 수 있다. 커널 대조와 사람 회차가 줄일 뿐 없애지 못한다.
  - 응용 방화벽(macOS "모두 차단", 회사 정책의 Windows 방화벽)이 안에서 먼저 보낸 흐름의 답까지 막으면 펀칭이 안 된다.
- 크기: ADR-0050의 3ew에 netsim(가상 소켓과 NAT 모델), 새 action과 role 표, 힌트 배우기, recovery의 route 재해석, 커널 대조 job이 더해져 추정 4ew로 고친다. 나눔은 netsim 0.5, `PunchEndpoint` 0.5, wire·검사·fuzz 0.3, 중개와 target 쪽 0.7, client route·경주·recovery 0.7, 힌트·CLI·doctor·로그 0.5, 커널 대조·수용 시험·문서 0.8이다.
- 스텝 순서: netsim과 NAT 상자 표 테스트(wire 없음) → `PunchEndpoint`(감싼 소켓, 펀치 datagram 송수신, 서버 창, dual-stack)와 손으로 넣은 후보로 돌린 NAT 쌍 측정(wire 없음, 수치를 개정 이력에) → `punch.v1`, message, 후보 검사, tag, fuzz → `host.punch`와 role 표, 감사 → R의 중개 서비스와 B의 offer 처리 → client route, 경주, 채택, 포기 사유 → recovery의 route 재해석과 `--supervise` → 힌트 배우기, `trust rendezvous`, 플래그와 키 → doctor, `qsh::punch`, JSON과 fixture → 수용 시험(netsim 세 OS, `punch-netns`) → 문서, man, threat model. 계약·wire를 건드리는 스텝은 이 ADR이 승인되기 전에 열지 않는다(ADR-0050 결정 7). 앞의 두 스텝은 wire 없이 열 수 있다.

## 개정 이력

- 2026-11-07 초안(에이전트). Dave가 정할 것 다섯 항목은 추천만 적었다.
