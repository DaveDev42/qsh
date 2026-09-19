# ADR-0020: 역방향 route에서도 `-D`를 켠다(ADR-0019 결정 10 개정)

날짜: 2026-09-20
상태: 승인됨

## 맥락

ADR-0019 결정 10은 첫 착지에서 `-D`를 정방향 route에서만 켜고 대상이 역방향 route로 해석되면 `UNSUPPORTED`로 거절하기로 했다. 이유는 하나였다. 역방향 controller는 자기 머신의 `qsh listen` daemon과 UDS로만 말하므로 target이 `dial-filter.v1`을 광고했는지 확인할 길이 없다는 것이다. 이 전제는 틀렸다.

- localctl의 `HelloAck`가 이미 target과 협상된 capability 집합을 controller에게 준다(`crates/qsh-core/src/localctl/client.rs`의 `ControlHandshake.capabilities`). 그 집합은 target이 등록할 때 daemon이 자기 `Hello`와 target의 `Hello`를 맞춰 계산해 둔 교집합이다(`crates/qsh-core/src/reverse/listen/registration.rs`의 `negotiated_capabilities`). `capabilities.get <host>`는 역방향 host에 대해 이미 이 값을 보고한다(`docs/CLI.md` §6.10).
- daemon은 `LOCAL_STREAM`으로 받은 `StreamHeader`를 디코드한 구조체에서 다시 인코딩하지 않는다. 받은 바이트를 그대로 QUIC 스트림에 싣는다(`LocalctlDaemon::serve_stream`). controller가 필드 5를 참으로 채우면 그 값은 target까지 바뀌지 않고 간다.

사용자가 2026-09-20에 이 기능의 주 시나리오를 확인했다. A가 `qsh listen`을 돌리고 B가 역방향으로 A에 붙는다. A에서 A의 SOCKS 포트로 붙은 애플리케이션의 트래픽은 모두 B에서 나간다. 이것은 역방향 route 위의 `-D`이고 정방향 전용 `-D`로는 풀 수 없다. B에 인바운드 경로가 없어서 역방향을 쓰는 것이기 때문이다.

대화형 세션의 `-L`도 역방향 route에서는 아직 `UNSUPPORTED`다(`crates/qsh-core/src/ops/session/attach.rs`의 "local forwards over a reverse connection are not implemented yet"). `tunnel open -L`은 역방향에서 `LocalForwardHandle::start_reverse`로 이미 동작한다. 대화형 `-D`를 역방향에서 켜려면 같은 자리를 고쳐야 하므로 `-L`도 함께 다룬다.

## 결정

1. ADR-0019 결정 10을 이렇게 개정한다. "`-D`는 정방향과 역방향 route 모두에서 켠다. 역방향에서는 CONNECT마다 controller가 `deny_host_local`을 참으로 채운 `TCP_CONNECT` 헤더로 `LOCAL_STREAM`을 열고, daemon은 그 헤더를 바이트 그대로 target에 넘긴다. target은 정방향과 똑같이 자기 `acl.toml`에서 `forward.local`로 판정하고 host-local 주소를 거른다." 결정 10의 나머지 문장(범위 결정이지 보안 경계가 아니라는 판단, 목적지 ACL 문법 Q1이 선행 조건이 아니라는 판단)은 그대로다.
2. capability 확인은 ADR-0019 결정 3을 그대로 따른다. 역방향 controller는 `ControlHandshake.capabilities`에 `dial-filter.v1`이 없으면 conduit을 닫고 아무것도 bind하지 않은 채 `UNSUPPORTED`로 거절한다. 교집합은 daemon이 계산하므로 `dial-filter.v1`을 모르는 오래된 daemon이 돌고 있으면 이 값이 빠지고 controller는 거절한다. 거절 문구는 두 원인을 모두 알린다. target의 qsh가 오래됐을 수 있고 이 머신의 `qsh listen`이 업그레이드 전에 뜬 프로세스일 수도 있다.
3. 대화형 세션(`qsh -L … <host>`, `qsh -D … <host>`)도 역방향 route에서는 `tunnel open`과 같은 opener로 forward를 연다. 역방향에서 대화형 `-L`을 막던 `UNSUPPORTED` 경로는 없어진다.
4. ADR-0019 결정 13에서 `error.UNSUPPORTED.dynamic_reverse.json`을 만든다는 부분을 철회한다. 역방향 거절이 없어지므로 그 fixture를 만들 생성자가 없다. `UNSUPPORTED`를 내는 경로는 다른 build의 peer(공통 wire minor가 없거나 `dial-filter.v1`이 없는 경우)와 Windows 전용 경로뿐이다. fixture 하네스는 양 끝을 같은 build로 돌리므로 이 코드를 결정적으로 만들 수 없다. 그래서 `UNSUPPORTED`를 `crates/qsh-cli/tests/fixtures.rs`의 `DEFERRED`에 이 사유와 함께 돌려놓는다. 결정 13의 나머지(`error.UNSUPPORTED.json` 은퇴와 `RETIRED_PRODUCERS`, `tunnel.dynamic.json`, `error.INVALID_ARGUMENT.dynamic_bind.json`, `capabilities.json` 재생성)는 그대로다.
5. ADR-0019의 Q2(역방향 egress)는 켜는 것으로 닫는다. target 쪽 "SOCKS 끄기" 스위치를 만들지 않는다는 판단은 그대로다.
6. 역방향 `-D`의 자원 상한은 정방향과 같은 client 상한(ADR-0019 결정 9)에 daemon의 hub별 터널 스트림 permit(`MAX_TUNNEL_STREAMS_PER_HUB`)이 겹친다. 새 상한은 만들지 않는다.

## 근거

- 주 시나리오가 역방향이다. 정방향 전용으로 남기면 사용자가 원하는 배치에서 `-D`를 쓸 수 없다.
- 새 wire 필드나 localctl 요청이 필요 없다. capability는 이미 `HelloAck`에 있고 필드 5는 이미 daemon을 그대로 통과한다.
- 보안 판단은 정방향과 같다. 필드 5는 권한 경계가 아니라 사고를 막는 장치다(ADR-0019 결정 10). 필드를 빼고 보낼 수 있는 controller는 같은 목적지로 `-L`도 열 수 있고 그 판정은 어느 쪽이든 target의 `acl.toml`이 한다. daemon은 헤더를 해석하거나 고치지 않는다.

## 대안과 기각 사유

- **정방향 전용 유지.** 역방향 사용자에게는 B에서 `qsh serve`를 열고 A가 정방향으로 붙으라고 안내하는 방법이다. B에 인바운드 경로가 없는 배치가 역방향을 쓰는 이유이므로 시나리오를 풀지 못한다.
- **daemon이 필드 5를 채운다.** daemon은 `LOCAL_STREAM` 헤더를 해석하지 않고 넘긴다(`docs/design/protocol.md` §11-3). daemon에는 `-D` 스트림과 `-L` 스트림을 구별할 정보도 없다.
- **capability를 묻는 localctl 요청을 새로 만든다.** 같은 값이 이미 `HelloAck`에 있다.

## 결과

- `docs/CLI.md` §6.9의 역방향 거절 설명은 역방향 동작 설명으로 바뀐다. 대화형 `-L` 역방향 제한도 사라진다.
- 역방향 e2e는 `crates/qsh-testkit`의 `ReverseHarness`로 고정한다. SOCKS CONNECT가 daemon을 거쳐 target에서 나가는 왕복, target의 loopback을 가리키는 이름이 `REP 0x02`로 거절되는 경우(필드 5가 daemon을 통과했다는 증거), capability가 없을 때 아무것도 bind하지 않는 거절, 대화형 `-L`의 역방향 왕복이다.
- `docs/design/threat-model.md`의 `-D` 행에 역방향 경로를 더한다. 새 신뢰 경계는 없다.
