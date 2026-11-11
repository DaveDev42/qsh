# ADR-0059: 한 `qsh listen` 프로세스가 `[listen].serve = true`(또는 `qsh listen --serve`)일 때 같은 UDP 소켓에서 인바운드 `qsh serve` 노릇도 한다. 연결은 `Hello.reverse`가 있으면 역방향 등록, 없으면 첫 요청이 `PunchRequest`일 때만 펀칭 연결, 그 밖은 정방향 host로 갈린다. wire 변경은 없고, Gate·quota·감사 sink·`Authorizer`는 프로세스에 하나씩이다

날짜: 2026-11-11
상태: 승인됨

개정 관계: 다음을 개정한다.
- ADR-0012 결정 1의 역할 표. 이 표는 `qsh listen`을 "client·인바운드"로만 둔다. `[listen].serve = true`인 `qsh listen`은 "host·인바운드"도 겸한다. "listener는 중계기가 아니라 내가 앉아 있는 client 머신"이라는 서술(`docs/CLI.md` §6.13)도 "listener는 client 머신이고, `serve`를 켜면 host도 된다"로 고친다.
- ADR-0014 결정 9의 포트 충돌 처방. 지금 처방은 "한 장비에서 두 역할을 겸하려면 `--bind`"다. 여기에 "또는 `[listen].serve = true`로 한 프로세스에 합친다"를 더한다. 두 프로세스 구성과 그 문면은 그대로 유효하다.
- ADR-0010과 `docs/design/architecture.md`의 `max_connections` 단위. 지금 단위는 "accept arm마다"다. 합친 endpoint는 arm이 하나라서 정방향 연결과 역방향 등록이 한 풀을 나눈다(결정 9).
- ADR-0054 결정 10 (2). 펀칭 연결을 Hello에서 가른다는 규칙을 고친다. 합친 endpoint에서는 첫 요청에서 가른다(결정 5). `serve`를 켜지 않은 `qsh listen`은 지금 규칙을 그대로 따른다.
- `docs/design/protocol.md` §11의 상호 거절 문장(`qsh serve`는 `Hello.reverse`를 `UNSUPPORTED`로 거절하고, `qsh listen`은 `Hello.reverse` 없는 peer를 `UNSUPPORTED`로 거절한다), §15.1의 pairing 배선 범위(Dave가 정할 것 4), §19의 펀칭 연결 문단.
- `docs/CLI.md` §6.12(재시작 배너, `serve.json`), §6.13(역할 표, `--bind` 기본값 문단, stateless reset key 문단, 새 키와 플래그), §6.17(doctor 코드 둘), §6.18(mode 추론 서술), §6.23(키 하나).

개정하지 않는 것: ALPN `qsh/1`과 `Hello` 형식(`docs/design/protocol.md` §2, §16 wire freeze), capability 집합, `ErrorCode` 집합, 액션 어휘 14종과 role 표(ADR-0045 결정 2, ADR-0056 결정 18), 기본 거부와 단일 choke point, 감사 fail closed, `acl.toml`을 기동 때 한 번만 읽는다는 것(ADR-0045), 역방향 등록 절차(이름 확정, `generation`, 같은 fingerprint 대체, §11-2~4), PathWatch 감지 예산(ADR-0041), keep-alive 범위와 idle 45초 고정(ADR-0021), 연결 하나에 listener 여러 개를 다중화하지 않는다는 지금의 모양, `serve --to`의 동작.

## 맥락

Dave의 요청은 이렇다. Dave-MacMini는 지금 두 데몬을 돌린다. `qsh serve`가 UDP 4433을, `qsh listen`이 UDP 4434를 쓰고, 라우터는 UDP 4433→4433과 443→4434를 둘 다 포워딩한다. Dave는 이것을 4434의 데몬 하나로 줄이고 라우터 포워딩도 443→4434 하나만 남기려 한다. 두 역할은 같은 identity, 같은 mTLS, 같은 ACL을 쓰므로 연결을 첫 요청으로 가를 수 있다는 것이 제안의 근거다.

### 전제 바로잡기: ADR-0003

요청에는 "역방향 registry와 세션 처리가 이미 listen 안에 있다(ADR-0003 sessions-in-listener)"는 전제가 붙어 있었다. 이 전제는 맞지 않는다.
- ADR-0003의 제목은 "PTY 세션을 MVP에서 `qsh serve` 프로세스 내부에 둔다"다. 파일명의 listener는 인바운드를 받는 `qsh serve`를 가리킨다. 이 ADR이 정한 것은 `SessionBackend`와 localctl이라는 seam 둘이다. 어느 명령이 broker를 갖는지는 정하지 않는다.
- `qsh listen`(`crates/qsh-core/src/reverse/listen.rs`의 `Listen`)이 가진 것은 `Registry`, `ConnTable`, `ControlHub`, `Gate`, `Quotas`, `RendezvousState`, localctl 데몬이다. `Broker`, `Server`, `ConnCtx`는 없다. 등록된 연결에서 `Listen`은 protocol client(`client::Session::from_control`)이고, PTY는 target 쪽 `qsh serve --to`의 `host_runtime()`이 호스팅한다.
- `docs/design/architecture.md`도 broker는 "`qsh serve` 프로세스 내부에 산다"고 적고, `docs/CLI.md` §6.13은 `drained` 줄을 "세션을 호스팅하는 `qsh serve --to`만 낸다"고 적는다.

그래서 붙여야 할 것은 정방향 경로 하나가 아니다. listen 프로세스에 들어와야 하는 것은 다음과 같다. broker와 TTL reaper, `Server`의 control dispatch와 데이터 스트림 처리(터널, jump 중간 peer, 파일, agent), 세션 상한과 replay 설정, SIGTERM drain과 재시작 배너, `serve.json`, pairing 창구, 적응 keep-alive. 대신 재사용할 근거가 있다. `qsh serve --to`가 이미 같은 `Server`와 broker를 역방향 연결 위에서 돌린다. 갈림목도 이미 있다. 두 accept 경로는 Gate → TLS accept → quota 예약 → `handshake::respond`까지 같은 순서이고, 그 뒤 이어지는 함수도 이미 따로 있다(`Server::serve_control`, `Listen::finish_registration`).

### 지금 있는 것

- 역할 신호는 `Hello.reverse` 필드의 존재 자체다(`docs/design/protocol.md` §11). `Server`는 `Hello.reverse`를 받으면 자원을 만들지 않고 `UNSUPPORTED`("this host does not accept reverse registrations", `crates/qsh-core/src/server/mod.rs`)로 답한다. `Listen`은 `Hello.reverse`가 없는 peer를 `UNSUPPORTED`("this endpoint only accepts reverse registrations", `reverse/listen/registration.rs`)로 답하고 감사하지 않는다.
- `docs/design/protocol.md` §11은 "client/host는 연결 단위가 아니라 요청 단위 역할"이라고 적는다. 연결 하나가 역할 하나를 갖는다는 wire 규칙은 없다. 이 규칙은 구현에만 있다.
- 펀칭(ADR-0054 결정 10). `qsh listen`은 `Hello.reverse`가 없고 양쪽이 `punch.v1`을 광고한 peer를 Hello 시점에 펀칭 연결로 둔다(`Listen::admit_punch_peer`). 이 연결은 `PunchRequest` 하나와 `Ping`만 받고, 3초(`RENDEZVOUS_IDLE`) 안에 요청이 없거나 답한 뒤 3초가 지나면 닫힌다. 동시에 16개(`RENDEZVOUS_MAX_CLIENTS`)까지 둔다. 그런데 모든 빌드가 `punch.v1`을 광고하므로 정방향 client의 Hello도 이 조건을 채운다. Hello만 보고는 정방향 client와 펀칭 client를 가를 수 없다.
- quota 순서는 경로마다 다르다. 정방향은 Hello 전에 quota를 예약하고 거절을 먼저 알린다(R3). 등록은 ACL을 먼저 보고 quota 거절을 그다음에 알려서, 권한 없는 peer가 포화 여부를 알 수 없게 한다(A2/B5). 등록의 permit은 등록 세션이 끝날 때까지 쥔다(B3).
- `Gate`와 `Quotas`, `RotatingAuditSink`, `acl.toml` 적재는 `Server`와 `Listen`이 저마다 따로 만든다. 감사 파일은 같은 경로를 공유하고 다중 writer 회전 락으로 직렬화된다(`docs/design/architecture.md`). `[listen]`에는 admission 키가 따로 없고 `[serve]`의 값을 이어받는다.
- `Role::{Serve, Listen}`(`acl/load.rs`)은 기동 진단에 보이는 예시 행만 바꾼다. 판정 엔진은 같은 `RoleResolvingAuthorizer`다. role `full`은 `host.reverse`와 정방향 action을 모두 주고, role `reverse`는 `host.reverse`와 `host.punch`만 준다.
- localctl 데몬은 `run_listen`만 띄운다. `LOCAL_ADMIN`·`LOCAL_CONTROL`·`LOCAL_STREAM`으로 역방향 등록 host와 역방향 터널만 보여 주고, 로컬 `Server`나 `Broker`와는 말하지 않는다.
- `serve.json`(ADR-0051 결정 2)은 `run_serve_with`만 쓴다. SSH 부트스트랩의 `live_serve`가 이 파일을 읽어 살아 있는 serve를 찾고, 없으면 `qsh serve --on-demand`를 띄운다.
- 서비스 유닛의 argv는 mode마다 고정이다(`ops/service/mod.rs`, `docs/CLI.md` §6.18, threat model E10). run mode는 `[listen]` 존재 > `[serve].to` > `[reverse].controller` > `serve` 순서로 추론한다. `ListenConfig`에는 `deny_unknown_fields`가 없다.
- jump 중간 peer(`server/jump.rs`)는 `Server`에만 있다. listen 전용 장비는 정방향 client를 거절하므로 hop이 될 수 없다.

## Dave가 정할 것

2026-11-11 Dave가 네 항목 모두 (가)로 정했다.

1. 표면. (가) config 키 `[listen].serve = true`와 플래그 `qsh listen --serve`를 둘 다 둔다. 둘 중 하나라도 켜면 합친 모드다. (나) config 키만 둔다. (다) 반대 방향으로 `qsh serve`에 `[serve].reverse = true`를 둔다. 추천은 (가). 서비스 유닛의 argv는 `listen` 그대로라서 상시 기동은 config 키 하나로 바뀐다. 플래그는 foreground로 시험할 때 쓰고, 플래그를 하나 더하는 비용은 man page 재생성뿐이다. (다)는 Dave의 배포에서 `[listen]` 블록과 controller 이름이 이미 listen 쪽에 있어 옮길 것이 더 많고, run mode 추론 순서(`[listen]` 존재가 먼저)와도 어긋난다.
2. 펀칭과 정방향을 가르는 시점. (가) `Hello.reverse`가 없는 연결은 정방향으로 받는다. 그 연결의 첫 요청(`Ping`은 세지 않는다)이 `PunchRequest`이면 그때 펀칭 연결로 바꾸고 16개 상한과 3초 규칙을 건다. 첫 요청이 다른 control message이거나 peer가 데이터 스트림을 먼저 열면 정방향으로 굳는다(결정 5). (나) 상태를 두지 않는다. 정방향 연결 어디서든 `PunchRequest`를 받고, 16개 상한은 동시에 진행 중인 중계 수에만 건다. (다) client가 Hello에 펀칭 전용 표시를 싣는다. wire 변경이다. 추천은 (가). 지금의 펀칭 연결 규약("요청 하나, 3초")이 갈린 뒤에는 그대로 유지되고, 조용한 정방향 client(요청 없이 `-L`만 쥔 홀더)가 3초 만에 끊기지 않는다. (나)는 "한 연결, 한 역할"이 무너지고 펀칭 감사가 정방향 연결에 섞인다. (다)는 최소 wire 원칙과 §16 freeze에 걸린다.
3. admission 풀. (가) `Gate` 하나와 `Quotas` 하나를 두 역할이 나눈다. 값은 지금처럼 `[serve]`에서 온다. (나) 등록과 정방향에 따로 상한을 둔다(새 키 `[listen].max_registrations` 등). 추천은 (가). principal마다 32개 상한이 한 peer의 홍수를 막고, 등록 수는 registry가 이름마다 하나로 묶는다. 새 키는 쓰임새가 관측되면 additive로 더하면 된다.
4. 코드 pairing. (가) 합친 모드는 인바운드 `qsh serve`처럼 pairing 창구(`attach_pairing`, `SharedInviteStore`, TLS의 세 번째 accept 경로)를 붙인다. (나) 붙이지 않는다. 합친 장비에는 `qsh pair invite`가 듣지 않고, 인증서 파일 교환(ADR-0013)이나 SSH 부트스트랩(ADR-0044)을 쓴다. 추천은 (가). "`serve`를 켜면 그 프로세스는 `qsh serve`가 받는 것을 모두 받는다"는 규칙 하나가 이해하기 쉽다. Dave의 구성에서도 노출이 새로 생기지 않는다. 지금 MacMini의 `qsh serve`가 공용 4433에서 같은 창구를 이미 열고 있기 때문이다. 창구는 살아 있는 초대가 있을 때만 받고 §15의 통제를 그대로 진다.

## 결정

### 범위

1. `[listen].serve = true`(또는 `--serve`)인 `qsh listen` 프로세스는 같은 UDP 소켓, 같은 identity, 같은 trust store와 `Authorizer`로 두 가지를 받는다. 하나는 `qsh listen`이 받는 것(역방향 등록, 펀칭 중개, localctl)이고, 다른 하나는 인바운드 `qsh serve`가 받는 것(세션, exec, 터널, 파일, agent, jump 중간 peer, pairing)이다. 각 기능은 단독 `qsh serve`나 단독 `qsh listen`에서와 같은 뜻으로 동작한다. 범위 밖에 두는 것은 넷이다.
   - 연결 하나에 listener 여러 개를 다중화하는 것. 별도 기능으로 나중에 다룬다.
   - 등록된 연결 위에서 정방향 요청을 받는 것(결정 6).
   - `qsh serve --to`나 `qsh serve --on-demand`와 합치는 것. `--serve`는 `listen`에만 있다.
   - 새 기본 포트. 합친 모드의 bind는 `[listen].bind`, `--bind`, `[::]:4433` 순서로 정해진다. 지금 listen과 같다.
2. 합친 프로세스는 `qsh listen` 위에 `Server`를 얹는 방식이 아니라 `Server`의 accept loop를 앞에 두고 `Listen`을 붙이는 방식으로 조립한다. `Server::run`이 heartbeat, quota 정리, SIGTERM drain을 이미 갖고 있기 때문이다. `Server`는 `Option<Arc<Listen>>`을 갖고, `Listen`의 side task(localctl 데몬, stale sweeper, `set_path_watch`, `set_punch_enabled`)는 `run_listen` 쪽 코드가 그대로 띄운다. `Listen::decide_registration`과 `finish_registration`은 가시성만 넓힌다. 로직은 옮기지 않는다.

### wire

3. wire 변경은 없다. ALPN은 `qsh/1`이고, 새 capability, 새 message, 새 필드, 새 `ErrorCode`는 없다. 합친 endpoint가 보내는 Hello 응답은 peer의 Hello로 정해진다. `Hello.reverse`가 있으면 지금 `Listen`이 보내는 응답을, 없으면 지금 `Server`가 보내는 응답을 보낸다. `[punch].mode`가 `off`가 아니면 후자에 `punch.v1`이 들어 있다. client 쪽 코드는 바뀌지 않는다. 기존 client는 합친 endpoint를 단독 serve나 단독 listen과 구별하지 못하고, 구별할 필요도 없다.

### 연결 가르기

4. 갈림은 연결마다 한 번이다. 순서는 Gate → TLS accept → quota 예약 → `respond` 콜백 → (필요하면) 첫 요청이다.

   | peer의 Hello | 첫 요청(`Ping` 제외) | 갈래 | 인가 | 이어지는 함수 |
   |---|---|---|---|---|
   | `reverse` 있음 | 해당 없음 | 역방향 등록 | `host.reverse`(`reverse::admit::admit`) | `Listen::finish_registration` → `drive_registered_session` |
   | `reverse` 없음, `punch.v1` 양쪽, `[punch].mode ≠ off` | `PunchRequest` | 펀칭 연결 | `host.punch`(`check_punch`) | `Listen::relay_punch`, 그 뒤 펀칭 연결 규약 |
   | `reverse` 없음 | 그 밖의 control message, 또는 peer가 연 데이터 스트림 | 정방향 host | 요청마다 지금 `Server`의 판정 | `Server::serve_control` |
   | `Principal::Pairing` | 해당 없음 | pairing(Dave가 정할 것 4 (가)) | 초대 상환 규칙(§15) | `serve_pairing_connection` |

   `Server`의 `respond` 콜백에 있던 `UNSUPPORTED`("this host does not accept reverse registrations") 자리는 `Listen`이 붙어 있으면 `decide_registration`을 부르는 자리로 바뀐다. 붙어 있지 않으면(단독 `qsh serve`) 지금 그대로다.
5. 펀칭 갈래(Dave가 정할 것 2 (가)). `Hello.reverse`가 없는 연결은 처음부터 정방향 연결로 `serve_control`에 들어간다. 갈림이 정해지기 전에는 `RENDEZVOUS_IDLE` 타이머가 없다. 그 연결의 idle은 단독 `qsh serve`와 같다(transport idle 45초와 keep-alive). `serve_control`에는 `RfwdOpen`·`PunchOffer` 옆에 가로채기 하나가 더 생긴다. 이 연결이 아직 `Ping` 말고 아무 요청도 보내지 않았고 데이터 스트림도 열지 않았으며, 양쪽이 `punch.v1`을 광고했고 `Listen`이 붙어 있으면, 첫 `PunchRequest`는 펀칭 연결로의 전환이다.
   - 전환할 때 `RENDEZVOUS_MAX_CLIENTS` permit을 얻는다. 얻지 못하면 지금처럼 `RESOURCE_EXHAUSTED`(retryable)로 답하고 닫는다.
   - `relay_punch`는 최대 `PUNCH_ANSWER_TIMEOUT`(1.5초)을 기다리므로 control loop를 막지 않도록 `blocking` 갈래로 돈다.
   - 답한 뒤에는 ADR-0054 결정 10 (2)의 규약을 그대로 따른다. `Ping`만 받고, 다른 요청은 `UNSUPPORTED`이며, 3초 뒤 닫는다.
   - 정방향으로 굳은 연결에 나중에 온 `PunchRequest`는 지금 `qsh serve`처럼 `UNSUPPORTED`("hole-punching requests are not served by this peer")다.
   - `[punch].mode = off`이면 가로채기가 없고, `PunchRequest`는 언제나 `UNSUPPORTED`다.
6. 등록된 연결은 `Server`의 dispatch에 닿지 않는다. 지금 listen처럼 그 연결에서 peer가 연 스트림은 `TCP_ACCEPTED`와 `AGENT`만 받고, 나머지는 reset한다. 등록한 target이 합친 장비의 셸도 쓰려면 정방향 연결을 따로 연다. 연결 수는 그만큼 는다.
7. `serve`를 켜지 않은 `qsh listen`과 단독 `qsh serve`의 동작은 바이트 단위로 지금과 같다. 상호 `UNSUPPORTED` 거절, Hello 시점의 펀칭 판정, 감사하지 않는 거절이 그대로 남는다. 그 동작을 고정한 기존 시험(`crates/qsh-core/src/reverse/listen/tests.rs`와 `crates/qsh-core/src/server/tests.rs`의 거절 시험)은 고치지 않고 통과해야 한다.

### 런타임 조립

8. 합친 프로세스에는 다음이 하나씩만 있다. `Gate`, `Quotas`, `RotatingAuditSink`, `Arc<dyn Authorizer>`(`acl.toml` 적재 한 번), trust watch, `stateless_reset.key` 읽기 한 번, QUIC endpoint 하나. `host_runtime`(`crates/qsh-core/src/serve.rs`)은 이 공유 부품을 인자로 받는 부분과 broker·`Server`를 만드는 부분으로 나눈다. `Listen::with_admission_and_quotas`도 같은 부품을 받는다. 정책 스냅샷이 둘이 되는 일은 없다. `acl.toml`을 파싱할 수 없으면 세 갈래(등록, 펀칭, 정방향)가 모두 거부된다. 기동 진단은 `Role::Listen`과 `Role::Serve` 예시 행을 둘 다 보인다.
9. admission(Dave가 정할 것 3 (가)). 동시 handshake 64, 출발지마다 창당 10, 연결 512, principal마다 32라는 값과 키는 지금처럼 `[serve]`에서 온다. 단위는 "endpoint 하나"다. 두 역할이 한 풀을 나눈다. quota 순서는 갈래마다 지금 것을 지킨다.
   - 정방향은 Hello 전에 예약하고 거절을 먼저 알린다(R3).
   - 등록은 `decide_registration`이 ACL을 먼저 보고 quota 거절을 그다음에 알린다(A2/B5). 예약한 permit은 등록 세션이 끝날 때까지 쥔다(B3).
   - 펀칭은 연결 quota를 처음부터 쥐고, 16개 permit은 전환 시점에 더 얻는다(결정 5).
10. 수명과 감시는 연결마다 정해진다. 모든 연결의 transport idle 45초와 `[transport].keep_alive_ms`는 지금처럼 프로세스 상수다. 정방향 연결은 `Server`의 적응 keep-alive(`pin_keep_alive`)를, 등록 연결은 역방향 PathWatch 예산(ADR-0041)을, 펀칭 연결은 전환 뒤 3초 규칙을 따른다. 서로의 정책은 섞이지 않는다.
11. 세션 설정. `[serve]`의 broker·세션 키(`max_sessions`, `replay_bytes`, TTL 등)는 합친 모드의 정방향 세션에 그대로 적용된다. `[serve].bind`는 합친 모드에서 읽지 않는다. bind는 결정 1의 순서로 정해지고, 값이 있으면 doctor가 알린다(결정 22). `[serve].to`는 `qsh serve --to` 프로세스의 키라서 이 모드와 무관하다.

### 인가와 감사

12. 새 action은 없다. 갈래마다 지금 그 갈래를 맡던 쪽의 판정을 그대로 쓴다. 등록은 `host.reverse`, 펀칭은 `host.punch`이고, 정방향은 요청마다 `session.*`·`exec`·`forward.*`(`forward.jump`, `forward.agent` 포함)·`file.*`다. 항상-deny 게이트(`forward.socks`)는 정방향 갈래에서 지금처럼 먼저 검사한다. role로 보면 `full`은 세 갈래를 모두 쓰고, `reverse`는 등록과 펀칭만 쓰며 정방향 요청은 모두 `PERMISSION_DENIED`다. `exec`·`tunnel`·`read-only`는 펀칭과 각자의 정방향 action을 쓰고 등록은 거부된다. 판정은 모두 자원보다 먼저이고 감사되며, 감사 쓰기가 실패하면 거부한다. 한 가지 바뀌는 것이 있다. 지금 단독 listen에 정방향으로 들어온 `reverse` role peer는 감사 없는 `UNSUPPORTED`를 받는다. 합친 모드에서는 요청마다 감사되는 `PERMISSION_DENIED`를 받는다. 감사 레코드에 새 필드는 없다. 갈래는 기존 op 이름으로 구별된다.

### 다른 기능과의 관계

13. 펀칭 중개(ADR-0054). 합친 endpoint는 지금 listen처럼 중개자 R이다. A는 R의 그 하나뿐인 포트로 dial하고, R은 등록된 target T의 `ControlHub`로 `PunchOffer`를 넘긴다. 바뀌는 것은 결정 5의 갈림 시점뿐이다. 합친 endpoint는 펀칭의 target이 되지 않는다. 공인 포트가 있는 host라서 직접 dial로 닿는다.
14. jump(ADR-0056). 합친 endpoint는 정방향 갈래에서 hop이 될 수 있다(`forward.jump`). host-local 거부와 QUIC 문(ADR-0056 결정 8)이 그대로 걸리므로, 자기 자신의 loopback으로 가는 hop은 거부된다. 이 장비의 localctl 데몬이 맡는 역방향 첫 hop 운반체 번역(ADR-0056 결정 14)과 ADR-0058의 침묵 시한은 바뀌지 않는다.
15. agent forwarding(ADR-0055). 정방향 세션은 `Server`의 agent runtime 디렉터리(`<runtime>/agent/`)와 `sweep_stale`을 쓰고, 등록 연결의 `AGENT` 스트림은 `Listen::admit_agent_stream`이 받는다. 경로가 localctl 소켓(`<runtime>/<pid>.sock`)과 겹치지 않는다.
16. pairing(Dave가 정할 것 4 (가)). 합친 모드는 bind 전에 `attach_pairing`을 부르고, `set_pairing`을 `Server`에 건다. 단독 `qsh serve`와 같다. §15의 초대 수명, 상환 속도 상한, 감사가 그대로 걸린다.
17. `serve.json`과 on-demand(ADR-0051 결정 2). 합친 프로세스는 소켓을 쥔 뒤 실제로 bind한 주소로 `serve.json`을 `mode: persistent`로 쓰고, 깨끗이 끝날 때 지운다. 단독 serve와 같은 `RecordGuard`를 쓰므로 마지막에 쓴 쪽이 이기고, 지우는 것은 자기 pid의 레코드뿐이다. 그래서 SSH 부트스트랩의 `live_serve`는 합친 endpoint를 찾고 `qsh serve --on-demand`를 띄우지 않는다. 합친 모드에는 on-demand idle 종료가 없다.
18. localctl 데몬은 지금처럼 QUIC bind 전에 뜨고, 같은 세 conduit만 둔다. 로컬 `Server`의 세션은 localctl로 보이지 않는다. 그 장비의 정방향 세션은 지금 단독 serve 장비에서처럼 QUIC으로 다룬다. Windows에서 named pipe를 UDP보다 먼저 선점하는 규칙(`docs/CLI.md` §6.13)도 그대로다.
19. 종료. SIGTERM을 받으면 다음 순서를 따른다. accept 중단 → 등록 연결과 hub를 지금 listen의 종료 코드로 닫음(target은 backoff 뒤 다시 dial) → `Server::drain()` → endpoint close → localctl 소켓 정리 → `serve.json` 제거. 세션이 이 프로세스 안에 살기 때문에 `docs/CLI.md` §6.12의 재시작 배너("sessions live inside this process")를 합친 모드에서도 낸다.

### 사용자 표면

20. 키 `[listen].serve`(bool, 기본 `false`, `applies_from: next_start`)를 `qsh config` 레지스트리(§6.23)와 doctor `config_unknown_key`의 알려진 키 목록에 등록한다. 플래그 `qsh listen --serve`는 그 키를 이번 기동에서만 켠다. 끄는 플래그는 없다. 합친 모드는 지금 listen의 기동 줄 뒤에 serve의 `listening on` 줄을 같은 stderr에 낸다. 외부 스크립트가 그 줄로 동기화하는 계약(§6.12)을 지키려는 것이다. JSON 출력은 없다. `qsh listen`은 §2.4의 장기 실행 모드다. man page는 `cargo xtask man`으로 다시 만든다.
21. `qsh service install`. run mode 추론과 유닛 argv는 바뀌지 않는다. `[listen]`이 있으면 `listen` 유닛이고, 합친 여부는 config가 정한다. `docs/deploy/service.md`의 fence와 `service_docs.rs` 비교 시험도 그대로다. 설치 안내문에 "이 유닛은 세션도 호스팅한다"는 한 줄을 더한다.
22. `qsh doctor`. `infer_run_mode`는 `listen`을 돌려준다. 다만 `[listen].serve`가 켜져 있으면 serve mode에서만 돌던 검사(세션·pairing 관련 검사)도 돌고, bind 검사(`bindv6only_blocks_ipv4`)는 `[listen].bind`를 본다. 새 코드는 둘이다(additive).
    - `listen_serve_ignores_serve_bind`(info). 합친 모드인데 `[serve].bind`에 값이 있다.
    - `serve_unit_beside_listen_serve`(warn). 합친 모드인데 `serve` 유닛도 등록돼 있거나, 다른 pid의 살아 있는 `serve.json`이 있다.
23. 옛 바이너리. `ListenConfig`에 `deny_unknown_fields`가 없어서 이 ADR 전의 바이너리는 `[listen].serve = true`를 조용히 무시하고 등록 전용으로 뜬다. 이미 나간 바이너리는 고칠 수 없다. 그래서 이전 절차(결정 24)는 바이너리를 먼저 올리게 하고, 결정 20의 serve 기동 줄로 확인하게 한다.

### 이전

24. 두 데몬 구성(`qsh serve`는 4433, `qsh listen`은 `--bind`나 `[listen].bind`로 다른 포트)은 지금처럼 동작하고 권장 구성에서도 빠지지 않는다. 합친 모드로 옮기는 순서는 이렇다. (1) 새 바이너리를 올린다. (2) `[listen].serve = true`를 넣고 listen을 재시작한다. 이 동안 옛 serve가 다른 포트에 그대로 있어도 된다. doctor가 `serve_unit_beside_listen_serve`로 알린다. (3) client의 pin 주소를 합친 포트로 옮긴다. (4) `serve` 유닛을 내리고 `[serve].bind`를 지운다. `[serve]`의 세션 키는 남겨 둔다. 이 모드에서도 적용된다. 되돌리려면 키를 끄고 serve를 다시 올린다. 상태 파일 형식은 바뀌지 않는다.

### 보안

25. 합친 endpoint는 새 신뢰 경계를 만들지 않는다. pin에는 방향이 없고(ADR-0045 결정 4), 같은 pin이 이미 두 프로세스에서 같은 `Authorizer` 규칙으로 판정되고 있었다. 노출 포트는 둘에서 하나로 준다. 바뀌는 것은 세 가지다. 한 프로세스의 실패가 두 역할을 같이 내린다. 등록과 정방향이 같은 상한을 나눈다. 정방향 quota의 거절이 등록 쪽 포화 정보를 함께 드러낸다. 셋 다 결정 26의 행과 남는 위험에 적는다.

### 위협 모델

26. 새 행과 고정 시험. threat model §3 진입점 표의 `qsh serve` accept 행과 `qsh listen` accept 행에 "합친 모드에서는 한 행"이라는 주석을 단다. §6의 r2(두 프로세스가 reset key와 감사 파일을 나눠 씀)에는 한 프로세스 경우를 더한다.
    - A25 스푸핑·역할 혼동. 등록된 target의 연결로 합친 장비의 셸을 연다: 등록 연결은 `Server` dispatch에 닿지 않는다(`a_registered_connection_never_reaches_forward_dispatch`).
    - B52 무단접근. role `reverse` pin(역방향 target)이 같은 포트에서 정방향 셸을 얻는다: 정방향 요청마다 기본 거부이고 감사된다(`combined_role_matrix`의 `reverse` 행).
    - B53 무단접근. 한 갈래의 판정이 다른 갈래에 새거나, 정책 스냅샷이 둘이다: `Authorizer` 하나, 감사 sink 하나(`combined_endpoint_loads_acl_once_and_writes_one_audit_sink`, `combined_unparseable_acl_denies_every_path`, `combined_audit_failure_fails_closed_on_every_path`).
    - C29 자원고갈. 정방향 연결의 홍수가 등록 자리를 막는다: principal마다 32, 출발지마다 Gate 창(`forward_flood_from_one_principal_leaves_room_for_registration`).
    - C30 자원고갈. 결정되지 않은 연결로 펀칭 상한을 피하거나, 펀칭 연결이 정방향 자리를 오래 쥔다: 연결 quota는 처음부터 쥐고, 16개 permit은 전환 때 얻으며, 전환 뒤 3초 규칙이 걸린다(`a_combined_punch_connection_keeps_the_rendezvous_limits`).
    - D27 정보노출. `host.reverse`가 없는 pin된 peer가 정방향 갈래의 quota 거절(R3)로 등록 쪽 포화를 안다: A2/B5를 합친 모드에서 약하게 만든다. 남는 위험으로 둔다. pin된 peer만 콜백에 닿고, 드러나는 것은 "이 endpoint가 연결 상한에 찼다"는 사실 하나다(`combined_forward_reports_quota_before_hello`가 이 동작을 고정한다).
    - G14 가용성. 한 프로세스의 crash나 재시작이 detached 세션과 모든 등록을 함께 끊는다: 재시작 배너, 서비스 재시작, target의 backoff 재등록(`combined_sigterm_drains_sessions_and_closes_registrations`, `combined_endpoint_recovers_both_roles_after_a_blackhole`).
    - Dave가 정할 것 4 (가)이면 pairing 행(§15 계열)의 진입점에 합친 모드를 더한다(`pair_invite_redeems_on_a_combined_endpoint`).

### 수용 기준(DoD)

27. 1. 갈림 표. 결정 4의 표를 행마다 고정한다. Hello(`reverse` 유무, `punch.v1` 유무, `[punch].mode`) × 첫 요청(`Ping` 뒤 `PunchRequest`, `SessionOpen`, `ExecStart`, `RendezvousQuery`, 요청 없이 연 `TCP_CONNECT` 스트림, `JUMP` 스트림)의 조합이 각각 정해진 갈래로 간다(`combined_dispatch_table`, L2).
    2. 조용한 정방향 client. 요청 없이 `-L`만 쥔 연결이 멈춘 시계로 60초를 지나도 닫히지 않는다(`a_quiet_forward_client_on_a_combined_endpoint_is_not_closed_as_punch`). 전환된 펀칭 연결은 16개 상한, 답한 뒤 3초 닫기, 다른 요청의 `UNSUPPORTED`를 지킨다(`a_combined_punch_connection_keeps_the_rendezvous_limits`). 정방향으로 굳은 연결의 `PunchRequest`는 `UNSUPPORTED`다.
    3. 두 역할 동시. loopback의 진짜 UDP 위 `qsh listen --serve` 하나에 target이 등록한 채로, 둘째 장비가 같은 포트로 PTY 세션, `-t` 명령, exec, `-L`, `-D`, `-R`, `qsh cp`(BLAKE3 일치), `-A`, 그리고 합친 장비를 hop으로 둔 `-J`를 끝낸다. 같은 시간에 합친 장비의 localctl을 거친 역방향 route로 target의 세션, exec, `qsh cp`가 끝난다(`combined_endpoint_serves_registration_and_forward_at_once`, L3).
    4. 펀칭. 합친 endpoint를 R로 둔 netsim 펀칭이 서고(`punch_through_a_combined_rendezvous`), `punch_accept::punch_route_nat_matrix`가 R을 합친 endpoint로 바꾼 한 seed에서 통과한다.
    5. 인가와 감사. `full`·`exec`·`tunnel`·`read-only`·`reverse`·`none`·role 없는 pin × 세 갈래의 판정이 결정 12대로 나오고, 거부에는 자원이 없으며 감사 줄이 구조 필드만으로 남는다(`combined_role_matrix`). 결정 26의 A25·B53 시험도 여기에 든다.
    6. quota. `combined_registration_checks_acl_before_quota`, `combined_forward_reports_quota_before_hello`, `combined_endpoint_shares_one_connection_pool`, `forward_flood_from_one_principal_leaves_room_for_registration`.
    7. 회귀 없음. `serve`를 켜지 않은 listen과 단독 serve의 기존 거절 시험이 고치지 않고 통과한다. 두 경우의 Hello 응답 바이트가 지금과 같다(`listen_without_serve_hello_is_unchanged`). `capabilities.json` golden은 doctor 코드나 config 키 목록 때문에 바뀌는 부분 말고는 diff가 없다.
    8. 수명. SIGTERM이 결정 19의 순서로 끝나고 배너가 나온다(`combined_sigterm_drains_sessions_and_closes_registrations`). 합친 endpoint가 `serve.json`을 쓰고, 가짜 ssh(`qsh-testkit`의 `fake_ssh`)로 한 SSH 부트스트랩이 on-demand serve를 띄우지 않고 그 주소로 붙는다(`combined_endpoint_writes_serve_json_and_bootstrap_uses_it`).
    9. recovery. chaos proxy로 5초 blackhole을 건 동안과 그 뒤, 등록은 ADR-0041 예산 안에 다시 서고 정방향 세션은 같은 세션으로 resume하며 입력이 무손실·무중복이다(`combined_endpoint_recovers_both_roles_after_a_blackhole`, L4).
    10. 표면. `--serve`와 `[listen].serve`의 조합 표(`listen_serve_flag_and_config_key`), mode 추론과 유닛 argv가 바뀌지 않음(`service_unit_for_combined_mode_is_the_listen_unit`), `EXPECTED_DOCTOR_CODES`의 새 코드 둘과 그 fixture(append-only), config 레지스트리, man page(`checked_in_man_pages_match_the_generator`).
    11. pairing(Dave가 정할 것 4 (가)일 때). `pair_invite_redeems_on_a_combined_endpoint`. (나)이면 합친 endpoint에 초대 상환 경로가 없음을 시험한다.
    12. 성능. `QSH_ACCEPTANCE_SLOW`에서 합친 endpoint를 상대로 한 `tunnel_echo_under_load` 변형(`combined_tunnel_echo_under_load`)이 단독 serve와 같은 예산 안이다.
    13. 세 OS. 1~11은 Linux·macOS·Windows CI에서 돈다. Windows에서는 named pipe localctl과 ConPTY 세션이 한 프로세스에서 함께 돈다.
    14. fuzz. wire가 바뀌지 않으므로 새 타깃은 없고 개수는 28 그대로다.
    15. 문서와 threat model. 결정 26의 행이 고정 시험과 함께 들어가고, 결과 절의 문서가 개정된다.

## 근거

- 연결 단위로 가르는 이유. control 스트림이 첫 스트림이고 Hello가 거기 실리므로, 갈림에 필요한 정보는 연결의 처음에 다 있다. 두 accept 경로가 콜백 직전까지 같고 이어지는 함수도 따로 있어서, 새 상태 기계 없이 분기 하나로 붙는다. 스트림 단위로 가르면 등록 연결 위에 host 역할이 섞여 결정 6의 경계가 사라진다.
- 펀칭만 첫 요청으로 미루는 이유. `punch.v1`은 모든 빌드가 광고하므로 Hello로는 가를 수 없다. 첫 요청으로 가르되 그 전에는 정방향으로 두면 조용한 홀더가 3초 만에 끊기지 않고, 갈린 뒤의 펀칭 연결은 ADR-0054의 규약을 한 글자도 바꾸지 않는다. 결정되지 않은 연결이 따로 쥐는 자원은 없다. 정방향 연결과 똑같은 quota 아래에 있기 때문이다.
- 부품을 하나씩 두는 이유. `acl.toml`을 두 번 읽으면 두 정책 스냅샷이 생기고, 그 사이에 파일이 바뀌면 같은 pin이 갈래마다 다르게 판정될 수 있다. 감사 sink도 하나라야 fail closed가 갈래마다 같은 뜻이 된다. `Gate`는 `Clone`이 아니어서 하나를 쓰는 것이 자연스럽다.
- `Server`를 앞에 두는 이유. drain, heartbeat, quota 정리가 이미 `Server::run`에 있고, 세션이 있는 프로세스에 필요한 종료 의미(drain과 배너)는 serve 쪽 것이다. `Listen::run`에는 drain이 없다.
- config 키가 기본인 이유. 서비스 유닛 argv는 고정이고 threat model E10이 그것을 묶는다. 키로 켜면 유닛, 문서 fence, 시험이 바뀌지 않는다.
- 연결 수를 그대로 두는 이유. Dave의 구성에서 Toss의 연결은 넷(등록 하나, 정방향 셋)이고, 합쳐도 넷이다. 연결 하나에 여러 listener를 싣는 다중화는 등록 연결 위의 host 역할이라는 다른 문제라서 따로 다룬다.

## 대안과 기각 사유

- 펀칭 상태를 두지 않는다. Dave가 정할 것 2의 (나).
- Hello에 펀칭 전용 표시를 싣는다. Dave가 정할 것 2의 (다).
- 등록과 정방향의 상한을 나눈다. Dave가 정할 것 3의 (나).
- `qsh serve --listen` 또는 `[serve].reverse`. Dave가 정할 것 1의 (다).
- 새 ALPN(`qsh-listen/1` 등)으로 역할을 가른다. ALPN은 `qsh/1` 하나이고 `qsh/2`는 파괴적 개정 전용이다(§16). 갈림 정보는 이미 Hello에 있다. 기각.
- UDP 포트를 공유하는 두 프로세스(SO_REUSEPORT 등). QUIC 연결이 한 프로세스에 고정된다는 보장이 OS마다 다르고, Windows에는 같은 의미의 장치가 없다. 세 OS 동등 원칙에 걸린다. 기각.
- 등록 연결 위에서 정방향 요청도 받는다. 연결 수를 줄이지만, 등록 연결의 감시 정책(ADR-0041)과 정방향의 적응 keep-alive가 한 연결에서 다투고, role `reverse` target이 같은 연결로 host 요청을 보내는 경로가 생긴다. 요청 범위가 아니다(연결 수 4 유지). 기각.
- 합친 모드에서도 pairing을 붙이지 않는다. Dave가 정할 것 4의 (나).
- `serve.json`을 쓰지 않는다. SSH 부트스트랩이 살아 있는 host를 못 찾고 다른 포트에 on-demand serve를 하나 더 띄운다. 기각.

## 결과

- 개정할 문서: `docs/CLI.md` §6.12(재시작 배너와 `serve.json` 문단에 합친 모드), §6.13(역할 표, "listener는 client 머신" 문장, `--bind` 기본값과 "겸하려면 `--bind`" 문단, stateless reset key 문단, `--serve`와 `[listen].serve`, Windows named pipe 열거), §6.17(doctor 코드 둘), §6.18(mode 추론 서술에 "합친 여부는 config"), §6.23(키 하나). `docs/design/protocol.md` §11(상호 거절 문장을 "단독 모드에서"로 좁히고 합친 모드의 갈림 표를 둠), §15.1(pairing 배선), §19(펀칭 연결의 갈림 시점). `docs/design/architecture.md`(broker가 사는 프로세스, `max_connections`의 단위, `host_runtime` 분할). `docs/design/threat-model.md` §3·§4·§6·§7. `docs/PRD.md`의 listener 서술 한 줄. `README.md` Known limitations의 포트 충돌 문단. ADR-0012·0014·0054의 개정 이력에 이 ADR을 적는다.
- 남는 위험(§7의 새 행):
  - 한 프로세스가 두 역할을 맡으므로 crash, OOM, 재시작이 detached 세션과 모든 역방향 등록을 함께 끊는다(G14).
  - pin된 peer는 정방향 quota 거절로 등록 쪽 포화를 알 수 있다(D27).
  - 등록과 정방향이 연결 상한 512를 나눈다. principal마다 상한이 있어도 여러 principal의 동시 홍수는 등록 자리를 줄일 수 있다(C29).
  - 이 ADR 전 바이너리는 `[listen].serve`를 조용히 무시한다(결정 23).
- wire와 `qsh.cli/v1` JSON 계약은 바뀌지 않는다. 추가는 config 키 하나, 플래그 하나, doctor 코드 둘이다.
- 크기: 추정 1.5ew. 나눔은 공유 부품으로 `host_runtime` 나누기와 `Server`에 `Listen` 붙이기 0.35, 갈림 콜백과 펀칭 가로채기 0.2, 수명(drain 순서, localctl, `serve.json`, pairing, 배너) 0.2, 표면(키, 플래그, doctor, service 안내, man) 0.15, 시험(L2·L3·L4, 세 OS) 0.45, 문서와 threat model 0.15다.
- 스텝 순서: `host_runtime` 분할과 공유 부품 주입(동작 변경 없음, 기존 시험 초록) → `Server`의 `Option<Arc<Listen>>`과 등록 갈래(DoD 1의 등록 행, 6) → 펀칭 가로채기(DoD 1, 2, 4) → 수명과 `serve.json`, pairing(DoD 8, 11) → 표면과 doctor(DoD 10) → L3·L4 수용 시험과 세 OS(DoD 3, 5, 9, 12, 13) → 문서와 threat model(DoD 15).

## 개정 이력

- 2026-11-11 초안(에이전트). 요청의 "ADR-0003 sessions-in-listener" 전제를 바로잡았다(맥락 절). Dave가 정할 것 네 항목은 추천만 적었다.
- 2026-11-11 승인(Dave 결정). 정할 것 네 항목 모두 추천 (가): 키와 플래그, 펀칭은 첫 요청으로 가름, admission 풀 하나, pairing 붙임. M27로 연다.
- 2026-11-12 리뷰 반영(결정 본문은 고치지 않았다). 결정 3의 `punch.v1` 광고 조건은 실제와 다르다: 코드는 단독 역할과 같게 `LOCAL_CAPABILITIES`로 `punch.v1`을 늘 광고하고, `[punch].mode = off`는 광고가 아니라 펀칭 가로채기와 `PunchRequest` 처리를 끈다(그 요청은 정방향의 `UNSUPPORTED`). 동작은 `production_runtime_punch_mode_off_turns_the_intercept_off`가 고정한다.
- 2026-11-12 threat model 번호: 이 ADR의 A25(등록된 연결로 정방향 셸을 여는 역할 혼동)는 ADR-0060이 A25를 먼저 써서 A26으로 적었다. B52·B53·C29·C30·D27·G14는 그대로다.
- 2026-11-12 DoD 27.9의 blackhole은 5 s에서 8 s로 늘렸다. 5 s 감지 상한을 넘겨야 재등록(generation 증가)이 결정적으로 일어난다. 재다이얼 `attempts`는 10이다(기본 3이면 `status_line`과 같은 이유로 회복이 늦다).
- 2026-11-12 DoD 27.3의 진짜 바이너리 시험은 `qsh-cli`의 `combined_accept`(unix 전체, Windows는 축소판)다. `-J`는 호스트-로컬 hop 거부에 `set_jump_options` 훅이 필요해 testkit 안에 남는다.
