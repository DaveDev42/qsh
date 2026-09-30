# ADR-0023: `qsh tunnel open --supervise`로 연결 유실 뒤 터널을 스스로 재수립한다(ADR-0018 결정 2·3 개정)

날짜: 2026-09-26 (개정 2026-09-30)
상태: 승인됨 (2026-09-30 사용자 지시 "github issue들도 확인해서 이것들의 반영도 모두 진행해줘")

개정 관계:

- [ADR-0018](0018-tunnel-lifetime-bound-to-connection.md)의 결정 2는 `--supervise`를 준 standalone `qsh tunnel open`에 한해 개정한다. 결정 3이 P1 백로그로 둔 `-R` 자동 재발행은 이 ADR의 close-then-open으로 처리한다. ADR-0018 결정 1과 결정 4는 바뀌지 않는다. `--supervise`가 없는 터널과 대화형 form(`qsh [user@]host -L/-R/-D`)에는 결정 2·3도 지금 문면 그대로 적용된다. ADR-0018 제목과 결정 1의 "v1 내내"는 wire 위 터널 객체(`forward_id`, 스트림마다의 splice)의 수명을 가리키는 것으로 읽는다. 켠 터널이 하는 일은 결정 1이 처방한 "새 `tunnel.open`"을 프로세스가 스스로 하는 것이다.
- [ADR-0022](0022-reverse-health-surface.md) 결정 7의 전제("connection이 죽으면 등록도 함께 죽으므로 살아 있지만 아픈 터널이라는 상태가 존재하지 않는다")는 `--supervise` 터널에서는 더는 참이 아니다. listener는 bind돼 있는데 그 뒤의 carrier가 없는 상태가 예산만큼 이어질 수 있다. 이 ADR은 그 상태의 관측 표면을 결정 12의 stderr 진단으로 둔다. 기본 모드 터널에는 결정 7이 그대로 참이다. ADR-0022 결정 5가 `qsh::reverse` 줄의 필드를 진단 어휘로 두었으므로 결정 20이 그 줄에 `wake` 이벤트를 더해도 그 자유 안에 든다. 결정 3의 push 표면 트리거는 건드리지 않는다(결정 23).
- [ADR-0019](0019-socks-dynamic-forward.md) 결정 11은 `TunnelDynamicReq`의 모양을 적어 두었다. 여기에 optional 필드 둘(`supervise_ms`, `accept_hold_ms`)을 더하고 `TunnelOpenReq`에도 같은 둘을 더한다. `qsh.cli/v1` 규칙상 additive이고 `TunnelOpenReq.wait_ms`(commit `c9113cc`)가 같은 방식의 선례다.
- [ADR-0021](0021-transport-liveness-knobs.md)은 개정하지 않는다. 결정 2의 45초 idle timeout과 결정 1의 keep-alive는 손대지 않고, 결정 17의 wake 감지기와 결정 10의 빠른 창은 설정으로 열지 않는 고정 상수다. 결정 4가 `[recovery]`로 여는 세 값과 열지 않은 `idle_probe_interval`도 바뀌지 않는다. 결정 7의 관측 게이트(ROADMAP M13 (k))도 유지한다(결정 25).
- wire(`docs/design/protocol.md` §9, §16)와 `qsh.local.v1`은 바꾸지 않는다. `docs/CLI.md` §6.9와 §6.14에는 문단을 더하고, §6.14 첫 문단 끝에 "`--supervise` 예외는 아래 문단"이라는 참조 한 구절만 넣는다. §6.12와 §6.13에는 결정 20과 21의 진단 문단을 더한다. §6.1의 route 우선순위 문면(결정 22)을 비롯해 그 밖의 기존 문면은 고치지 않는다.

## 맥락

이슈 #4의 항목 5는 "reverse 재등록을 기다렸다가 forwarding listener를 다시 만드는 supervised tunnel mode, 바깥의 exit/relaunch 루프 없이"를 요구한다. 보고된 배치에서는 controller 쪽 launchd가 `qsh tunnel open toss --local 127.0.0.1:6771:localhost:6768 --json`을 쥔다. 연결이 끊기면 그 프로세스가 끝나고 launchd가 30초마다 다시 띄우며, 그 사이 로컬 포트가 사라져 downstream client가 connection refused를 받는다. 한 사례에서는 05:16:46Z에 닫힌 터널이 05:25:58Z에야 다시 열렸다. 같은 이슈의 5a는 commit `c9113cc`의 `--wait`로 처리됐고 5b가 이 ADR의 몫으로 남았다.

오늘의 수명 규칙은 route마다 다르다(`docs/CLI.md` §6.9, §6.14).

- forward route의 `-L`/`-R`/`-D`는 그것을 연 CLI 프로세스가 dial한 QUIC connection에 결합된다. connection이 죽으면 `TunnelHold::hold`(`crates/qsh-core/src/ops/tunnel.rs`)가 `Connected::wait_dead`로 그것을 알고 오류를 돌려주며 프로세스는 exit `255`로 끝난다. path migration은 connection을 살려 보내므로 터널도 산다.
- reverse route의 `-R`만 예외다. target의 listener는 상주 `qsh listen` 데몬의 reverse connection에 결합돼 CLI가 죽어도 남지만, claim conduit이 CLI와 함께 죽으므로 그 뒤의 `TCP_ACCEPTED`는 reset된다.
- reverse route의 `-L`과 `-D`는 예외가 아니다. `TunnelHold::hold`가 `LOCAL_CONTROL` conduit의 종료를 기다리므로 등록이 stale이 되면 프로세스가 끝난다. listener 밑의 `LocalForward`는 등록 drop을 연결 단위로 견딘다. `crates/qsh-testkit/tests/reverse_tunnel.rs`의 `local_forward_primitive_over_reverse_survives_a_registration_drop_and_self_heals_per_connection`이 이 성질을 고정하고, 같은 파일의 `tunnel_open_local_over_reverse_ends_when_the_registration_drops`가 프로세스는 끝난다는 규칙을 고정한다.
- `--wait`는 최초 route 해석이 `reverse_registration_stale`을 만났을 때만 재시도하고 예산은 요청값과 `[listen].stale_retention`(기본 120초) 중 작은 쪽이다(`Ops::cap_wait_budget_to_stale_retention`). 연 뒤의 수명은 바꾸지 않는다. `-D`에는 `--wait`가 없다.

2026-09-30에 현장 자료 두 건이 더 들어왔다.

- 이슈 #6(qsh 0.3.0, 양쪽 macOS). 노트북의 standalone holder(`--dynamic` 하나, `--local` 넷, launchd `KeepAlive=true`, `ThrottleInterval=30`)가 9일 동안 `-D` 기준 56번 닫혔다. 닫힌 사유는 `timed out` 30, `reset by peer` 19, `closed by peer: shutdown` 7(hub 재배포)이다. 앞의 둘은 ±120초 안에 절전·깨어남이 있었던 경우가 19와 14로, 우연 수준(5~7%)보다 훨씬 높다. listener가 사라져 있던 시간은 중앙값 32초이고 1~5분 구간 13건은 VPN이 올라오기 전에 첫 재기동이 실패하고 30초 throttle이 겹친 탓이다. 같은 기간 hub의 `qsh listen`은 노트북 등록에 대해 5일 동안 `lost` 58건(`cause=path_dead`)을 적었다. 이슈는 여섯 가지를 요청한다. forward route의 `-D`/`-L`부터 이 ADR을 구현할 것, 깨어남을 직접 감지해 곧바로 probe할 것, 깨어남과 망 변화 뒤 재dial backoff를 되돌릴 것, 재dial 중 짧은 accept 유지(기본 꺼짐)를 검토할 것, 같은 감지와 backoff 복귀를 `qsh serve --to`에도 적용할 것, 수명 줄에 시각을 붙일 것.
- 이슈 #4의 2026-09-30 코멘트(qsh 0.3.0). 노트북의 reverse client가 07:52:11Z에 `event=lost`, `cause=path_dead`를 적은 뒤 controller DDNS 이름을 해석하지 못해 `CONNECTION_FAILED`를 되풀이했고 재시도 간격은 설정 상한 24.3초까지 늘었다. 등록은 08:01:03Z에 돌아왔다(약 8분 50초). 그동안 hub의 `qsh tunnel open <reverse-host> --local … --wait` holder는 약 30초마다 stale forward pin(예전 NAT 공인 매핑, 임시 포트)을 dial해 매번 10초 무응답으로 끝났다. §6.1의 우선순위상 이름에 forward pin이 있으면 stale 등록 분기보다 pin이 먼저라서 `--wait`가 끼어들 자리가 없었다. 코멘트는 세 가지를 묻는다. reverse 전용 host가 stale forward pin 대신 등록 복귀를 기다릴 수 있는가, supervised 로컬 터널이 재등록 동안 listener를 쥐고 있을 수 있는가, 상관된 복구 타임라인을 진단으로 볼 수 있는가.

이 자료에서 드러난 사실은 다음과 같다.

- `PathWatch`(`crates/qsh-core/src/client/pathwatch.rs`)의 시계는 tokio `Instant`다. macOS와 Linux에서 이 시계는 절전 중에 멈춘다. 깨어난 뒤 watchdog은 잠들기 전에 걸어 둔 sleep의 남은 시간을 마저 잔다. idle cadence(`idle_probe_interval` 5초)에 있던 연결이면 첫 probe까지 최대 5초, 3 strike 판정까지 최대 약 15초가 걸린다. quinn의 idle 타이머도 같은 시계라 45초가 깨어난 뒤부터 다시 흐른다. hub가 그 사이 connection을 걷었으면 노트북의 첫 keep-alive(15초 주기)가 stateless reset을 받고, 망이 아직 없으면 quinn idle timeout으로 끝난다. 이슈 #6의 `reset by peer`와 `timed out`이 깨어난 뒤 2~30초에 몰린 것과 맞는다.
- `docs/design/protocol.md` §2는 "절전 복귀 시 클라이언트는 monotonic clock 점프/PTO 실패로 죽은 연결을 즉시 버리고"라고 적지만 단조 시계는 절전 뒤에 뛰지 않는다. 그 문장이 약속한 감지는 오늘 코드에 없다.
- 이 ADR의 결정 10(초안)은 500ms에서 30초까지 2배씩 늘린다. 깨어난 뒤 망이 2~30초 동안 쓸 수 없는 경우가 흔해서, 망이 돌아온 순간 다음 시도가 8~16초 뒤에 있을 수 있다.
- target의 backoff(`crates/qsh-core/src/reverse/target/mod.rs`의 `Backoff`, `[reverse]` 설정)도 tokio sleep으로 기다리므로 절전 전에 걸린 대기는 깨어난 뒤 남은 만큼 이어진다. 등록 성공에서만 `reset()`한다.
- 사람용 수명 줄은 `stderr_note!`로 바로 쓰인다(`crates/qsh-cli/src/main.rs`의 `qsh serve: listening on {addr}`, `qsh serve: shutting down`, `qsh listen: …`, `crates/qsh-core/src/ops/session/link.rs`의 `the connection carrying this tunnel closed: …`). 시각이 없다. 앞의 둘은 `crates/qsh-cli/tests/common/mod.rs`의 `LISTENING_PREFIX`·`LISTEN_LISTENING_PREFIX`가 접두어를 떼어 주소를 파싱하고 바깥 스크립트도 같은 방식으로 읽을 수 있다. `docs/CLI.md` §2.2는 stderr를 진단 채널로만 규정하므로 이 줄들은 계약이 아니지만, 접두어나 꼬리를 바꾸면 그 파서가 깨진다.
- route 해석(`crates/qsh-core/src/ops/host.rs`의 `resolve_route`)은 live reverse 등록, forward pin, stale 등록, 주소 없는 pin 순으로 본다. 주소 없이 fingerprint만 가진 pin은 forward 분기를 지나쳐 stale 분기에 닿으므로 `--wait`가 동작한다. `qsh doctor`의 `host_pinned_without_address`가 이 배치를 "순정 reverse 대상"으로 정상 취급한다. `trust.accept`는 pairing에 성공한 주소를 pin에 채우므로(`docs/CLI.md` §6.11) pairing으로 만든 pin에는 관측 주소가 남는다.

ADR-0018 결정 2는 "`-L` listener를 쥔 프로세스는 resume 뒤에도 그 listener로 들어오는 새 연결에 reset을 돌려준다"이고, 결정 3은 "`-R` 자동 재발행은 P1 백로그로 옮긴다. 필요해지면 additive 필드(예: `reclaim: bool`)로 넣을 수 있다"이다. 5b는 이 두 결정을 바꾸는 계약 변경이라 결함 수정으로 처리할 수 없다. 그래서 ADR이 먼저다.

설계를 가르는 사실은 다음과 같다.

- 연결이 죽으면 peer 쪽에 되찾을 것이 남지 않는다. peer는 `Server::purge_connection`(`crates/qsh-core/src/server/mod.rs`)으로 그 connection이 연 `-R` forward를 `conn_id` 축에서 걷어간다.
- 닫을 권한은 connection이 아니라 owner principal 축이다(`docs/CLI.md` §6.9). 같은 principal은 새 connection에서 자기가 연 옛 `forward_id`를 `RemoteForwardClose`로 닫을 수 있다.
- `Server::handle_rfwd_close`(`crates/qsh-core/src/server/reverse.rs`)는 등록표에서 항목을 빼고 `entry.task.abort()`를 부른 뒤 바로 성공 응답을 보낸다. listener는 abort된 task의 future 안에 있어서 runtime이 그 취소를 처리할 때 drop된다. 응답과 포트 해제 사이에 순서 보장이 없다. 이어진 `RemoteForwardOpen`이 먼저 bind에 닿으면 `authorize_and_bind_remote_forward`가 `CONNECTION_FAILED`(`retryable: false`)를 돌려준다.
- peer가 client connection의 죽음을 무조건 알게 되는 상한은 45초 idle timeout이다. ADR-0021 결정 2·3은 이 값이 감지 기전이 아니라고 못박았다. forward route의 터널 connection에는 오늘 `PathWatch`가 없다. 대화형 attach에는 `PathWatch` 감지와 `Endpoint::rebind()` migration을 거쳐 재dial하는 recovery가 있다(`crates/qsh-core/src/ops/session/recovery.rs`의 `recover_attach`).
- 그 recovery의 재연결 타입 `DialReconnect`/`LocalReconnect`는 `crates/qsh-core/src/ops/session/reconnect.rs`에 `pub(super)`로 있고, resume token과 `AttachContext`를 쥐고 `(Session, Attached)`를 돌려주는 세션 전용 타입이다. 터널에 그대로 쓸 수 없다.
- `ForwardCarrier`(`crates/qsh-core/src/tunnel/local.rs`)는 시작 시 한 번 받는 스냅숏이다. `Quic` 변형의 doc이 "a forward has to be restarted across a recovery"라고 적는다. `Local { socket, host }` 변형은 accept마다 그 이름으로 새 `LOCAL_STREAM` conduit을 열 뿐 generation이나 fingerprint를 대조하지 않는다. 그 conduit의 `LocalHelloAck`는 `peer_fingerprint`와 `generation`을 싣고(`DataHandshake`, `crates/qsh-core/src/localctl/client.rs`), 데몬은 ack를 보낸 뒤에야 `StreamHeader`를 기다린다. 이슈 #5의 `Session::open_local_data_link`가 바로 이 두 값을 대조해 등록이 바뀐 route를 fail closed로 거른다.
- `LocalHello.known_generation`(`crates/qsh-proto/proto/qsh/local/v1.proto`)은 "이미 죽은 generation보다 새로운 등록"을 기다리는 수단이다. 다만 데몬 socket 경로는 `<runtime_dir>/<pid>.sock`이고 generation 표(`RegistryState::last_generation`, `crates/qsh-core/src/reverse/registry.rs`)는 데몬 메모리에만 있다. 데몬이 재시작하면 socket 경로가 바뀌고 generation은 0부터 다시 센다.
- 데몬은 자기 판단으로 control 요청을 발신하지 않는다(`docs/design/protocol.md` §11-3). 터널 전용 client daemon은 두지 않는다(`docs/CLI.md` §6.14).
- `qsh tunnel close`는 데몬의 `admin_close_forward`(`crates/qsh-core/src/reverse/listen/hub.rs`)로 등록을 지우고 target에 `RemoteForwardClose`를 보낼 뿐, 그 forward를 연 CLI에는 아무것도 알리지 않는다. 그 CLI의 claim 시도는 이후 대기 없이 곧바로 `TIMEOUT`으로 돌아온다(`crates/qsh-core/src/tunnel/remote.rs`의 `FAST_TIMEOUT_THRESHOLD` doc).
- `-D`는 협상된 capability에 `dial-filter.v1`이 없으면 fallback 없이 거절한다(ADR-0019 결정 3).
- `crates/qsh-cli/src/main.rs`의 `init_tracing` 기본 level은 `warn`이다. `qsh::recovery`와 `qsh::reverse`가 기본 verbosity에서 보이는 것은 두 target에 전용 layer와 `{default},<target>=info` 필터를 따로 달았기 때문이다. `run_tunnel_open`은 신호 handler 없이 `hold()`에서 막히고, `qsh serve`/`qsh listen`은 `shutdown_signal()`로 SIGINT·SIGTERM을 받아 exit `0`으로 끝난다.

## 결정

1. standalone `qsh tunnel open`에 `--supervise <ms>`를 더한다. `--local`/`--remote`/`--dynamic` 세 모드 모두에 쓸 수 있다. 값은 연결 유실 한 번에 재수립을 시도할 예산(밀리초)이고 기본값 `0`은 꺼짐이다. 범위는 `0..=86400000`(24시간)이고 그 밖의 값은 연결을 시도하거나 listener를 bind하기 전에 `INVALID_ARGUMENT`다. 검증은 `wait_ms`와 같은 규율로 `qsh-core`의 `Ops`가 한다. JSON 요청에는 `TunnelOpenReq.supervise_ms`와 `TunnelDynamicReq.supervise_ms`(optional u32)로 실린다. 생략하거나 `0`이면 요청·응답·동작 모두 이 옵션이 생기기 전과 바이트 단위로 같다. 예외는 stderr 진단 줄 하나뿐이다. 결정 21이 모든 holder에 더하는 이 줄은 stdout과 JSON 계약에는 닿지 않는다. 대화형 form에는 이 옵션을 두지 않는다. 호출자가 없는 `Ops::tunnel_open_and_hold`와 `Ops::tunnel_dynamic_and_hold`는 `supervise_ms`가 `0`이 아니면 연결 전에 `INVALID_ARGUMENT`로 거절한다.

2. 감독은 최초 open이 성공한 뒤에만 시작한다. 최초 open의 실패는 지금과 같은 오류 봉투로 끝나고 재시도하지 않는다. `--wait`는 지금처럼 최초 open에만 적용되고 `--supervise`와 함께 써도 의미가 바뀌지 않으며, 두 옵션은 서로의 예산을 늘리거나 줄이지 않는다. `-D`에는 `--wait`가 없으므로 이 문장은 `-L`/`-R`에만 해당한다.

3. supervisor는 터널을 연 그 프로세스 안, `qsh-core`의 `Ops`에 있고 `TunnelHold::hold` 경로에서만 돈다. 새 daemon은 두지 않는다. reverse route는 지금처럼 기존 `qsh listen` 데몬을 carrier로만 쓰고 데몬에는 새 상태도 새 요청 발신도 생기지 않는다. `qsh-cli`는 flag를 파싱하고 결과와 진단을 렌더할 뿐이다. `ForwardCarrier`를 스냅숏으로 넘기는 대신 accept 루프가 accept마다 현재 carrier를 `watch` 채널에서 읽는다. 채널 값은 "살아 있음(carrier와 확인된 peer 신원)"과 "끊김" 둘 중 하나다. 재연결 경로는 터널용으로 새로 두고, 세션의 `DialReconnect`/`LocalReconnect`와는 dial 절차와 `LocalHello{known_generation}` 대기 부분만 공유한다. `recover_attach`는 재사용하지 않는다.

4. 감지와 route 고정은 다음과 같다.
   - forward route에서는 supervised 터널의 control 스트림에 대화형 attach와 같은 `PathWatch` probe를 붙인다. 설정은 `RecoveryConfig.watch`이고 ADR-0021 결정 4가 구현되면 `[recovery]`의 값을 따른다. 45초 idle timeout에는 기대지 않는다. 사망 판정 뒤 `RecoveryConfig.migration`이 켜져 있으면 `Endpoint::rebind()` migration을 먼저 시도하고, connection이 살아나면 아무것도 재발행하지 않는다. `--supervise`가 없는 터널에는 `PathWatch`를 붙이지 않는다. 로컬 listener의 accept 하나하나는 `PathWatch`에 활동(`observe_activity`)으로 알린다. 새 연결을 기다리는 사람이 있다는 뜻이라 대화형 attach에서 키 입력이 하는 일과 같고, control 스트림이 조용한 터널도 accept 직후에는 빠른 cadence(250ms)로 판정받는다. 결정 17의 wake 신호도 활동이고 즉시 probe를 부른다.
   - reverse route에서는 `LOCAL_CONTROL` conduit의 종료, 결정 7-5의 accept별 신원 불일치, 데몬 socket 연결 실패가 유실 신호다. migration 단계는 없다.
   - route 종류는 최초 open의 것으로 고정한다. forward route는 최초 open에서 해석한 주소를 계속 쓰고 `hosts.toml`을 다시 읽지 않는다. 대화형 attach의 재접속과 같은 규칙이다(`docs/CLI.md` §6.1). `trust.toml`은 지금처럼 handshake마다 읽힌다. reverse route로 연 터널은 같은 이름에 forward pin이 있어도 reverse 등록만 기다린다. 7-1의 재해석은 이 머신의 `qsh listen` 데몬을 다시 찾는 reverse 쪽 절반만 타고 §6.1 우선순위 전체를 다시 타지 않는다. 그래서 등록이 stale이든 `stale_retention`이 지나 지워졌든 forward pin을 한 번도 dial하지 않는다(이슈 #4 코멘트 질문 1, 결정 22).
   - 유실로 치는 것은 현재 carrier의 죽음뿐이다. 결정 5가 남겨 두는 옛 connection이 나중에 닫히는 것은 유실이 아니다.

5. 사망 판정 즉시 carrier를 "끊김"으로 바꾼다. 그 뒤 client 쪽 자원은 이렇게 된다.
   - `-L`과 `-D`의 로컬 listener는 같은 주소에 bind된 채 남고 `tunnel_id`도 바뀌지 않는다.
   - 옛 carrier 위에서 아직 `ConnectResult`를 기다리던 handshake는 그 자리에서 결정 6의 방식으로 거절한다.
   - forward route의 `-L`/`-D`에서 `ConnectResult{ok:true}`를 지나 splice 중이던 연결은 건드리지 않는다. 옛 connection을 능동적으로 닫지 않으므로, 짧은 끊김 뒤 옛 connection이 살아나면 그 연결도 산다. 옛 connection이 죽으면 기본 모드와 똑같이 reset된다. 옛 connection은 마지막 splice가 끝날 때 close code `0`으로 닫는다. supervised 모드는 진행 중인 TCP 연결에 대해 기본 모드보다 나빠지지 않는다.
   - reverse route의 splice는 데몬의 reverse connection과 함께 끝난다. 오늘과 같다.
   - peer 쪽은 ADR-0018 결정 1대로 connection과 함께 끝난다. `-R`의 진행 중 연결은 결정 7-4가 옛 forward를 닫을 때 peer의 forward task와 함께 끝난다.

6. "끊김" 동안 들어오는 연결은 즉시 거절하고 대기열에 넣지 않는다. 결정 19의 accept 유지를 켠 터널만 예외이고, 그 유지도 기한이 지나면 이 결정의 방식으로 거절한다. `-L`은 accept한 뒤 `abort_local`(`SO_LINGER 0`, RST)로 닫는다. 오늘 등록이 stale인 동안 reverse route의 `LocalForward`가 하는 것과 같다. `-D`는 SOCKS CONNECT에 REP `0x01`(`docs/CLI.md` §6.9 표의 "로컬: 스트림 열기 실패" 행)을 보내고 `shutdown(Write)` 뒤 닫는다. `-R`은 옛 connection이 살아 있으면 peer의 옛 listener가 지금처럼 그 connection으로 잇고, 이미 걷혔으면 원격 client는 peer 커널의 응답(보통 connection refused)을 받는다. carrier는 결정 7-2와 7-3을 통과한 뒤에만 "살아 있음"으로 돌아간다. 확인되지 않은 carrier로 나가는 accept는 없다.

7. 재수립은 시도마다 다음 순서를 따르고 한 단계라도 실패하면 결정 9로 분류한다.
   1. 새 carrier를 세운다. forward route는 고정된 주소로 다시 dial하고 시도마다 `REDIAL_DEADLINE`(2초, `crates/qsh-core/src/client/reconnect.rs`)으로 묶는다. reverse route는 시도마다 현재 데몬 socket을 다시 찾는다. 이 탐색은 결정 4 셋째 항목대로 reverse 쪽만 보고 forward pin으로 넘어가지 않는다. socket이 직전과 같으면 `LocalHello.known_generation`에 마지막으로 확인한 generation을 실어 같은 generation의 죽은 등록이 대기를 만족시키지 못하게 한다. socket이 바뀌었으면(데몬 재시작) `known_generation`을 싣지 않고 7-2의 fingerprint 확인에 기댄다. `LocalHello.wait_ms`는 남은 예산과 `LOCAL_WAIT_MAX`(60초) 중 작은 값이다.
   2. peer를 확인한다. 새 carrier의 peer fingerprint(forward는 TLS, reverse는 `LocalHelloAck.peer_fingerprint`)가 최초 open에서 기록한 값과 같아야 한다. 다르면 요청을 하나도 보내지 않고 `AUTH_FAILED`로 끝낸다. 그 사이 trust store가 바뀌어 다른 peer가 신뢰되더라도 이 supervisor가 이어 붙는 대상은 처음의 peer 하나뿐이다. resume token 제시 조건(ADR-0007 결과 절), `docs/design/protocol.md` §10 Reattach의 peer 신원 검사, `Session::open_local_data_link`(이슈 #5)와 같은 fail-closed 검사다.
   3. capability를 다시 확인한다. 최초 open이 확인한 capability(`-D`는 `dial-filter.v1`)가 새 carrier에도 있어야 한다. 없으면 `UNSUPPORTED`로 끝낸다.
   4. `-R`만, 새 carrier 위에서 먼저 `RemoteForwardClose{직전 forward_id}`를 보낸다. 성공과 `INVALID_ARGUMENT`("no such forward_id")는 둘 다 옛 forward가 없어졌다는 뜻으로 읽는다. 그 다음 `RemoteForwardOpen`을 보낸다. `bind_host`, `forward_host`, `forward_port`는 최초 요청과 같고 `bind_port`는 최초 open의 `actual_port`다. 그래서 `0`(ephemeral)으로 연 `-R`도 재발행 뒤 같은 포트를 요구한다. 이때 peer의 ACL resource는 `bind_host:actual_port`가 되어 최초 판정의 `bind_host:0`과 다르다. 정책이 `:0`만 허락했다면 재발행은 `PERMISSION_DENIED`로 끝난다. `claim_token`은 새로 만들고 새 `forward_id`를 받는다. 같은 시도 안에서 close가 성공했거나 "no such forward_id"였는데 open이 bind 실패 `CONNECTION_FAILED`를 받으면, 옛 listener가 아직 drop되지 않은 경합으로 보고 200ms 간격으로 3번까지 open만 다시 보낸다. 그래도 실패하면 포트를 다른 누군가가 쥔 것으로 보고 끝낸다. 결정 16의 서버 수정이 없는 구버전 peer 때문에 이 재시도가 필요하다.
   5. `-L`과 `-D`는 control 메시지를 보내지 않는다. carrier를 확인된 신원과 함께 "살아 있음"으로 바꾸면 남아 있던 listener의 새 accept가 새 carrier로 나간다. reverse route에서는 accept마다 여는 `LOCAL_STREAM` conduit의 `LocalHelloAck`(`peer_fingerprint`, `generation`)를 carrier의 확인된 신원과 대조한 뒤에만 `StreamHeader`를 보낸다. 다르면 그 accept는 결정 6대로 거절하고, carrier를 "끊김"으로 바꾸고, 1단계부터 다시 한다. 데몬은 ack를 보낸 뒤 header를 받기 전에는 target 쪽에 스트림을 열지 않으므로, 등록이 다른 장비로 바뀐 순간에도 그 장비로 바이트가 가지 않는다. `DataHandshake`가 이미 두 값을 돌려주므로 `qsh.local.v1`은 바뀌지 않고 `localctl::client`의 handshake를 ack 확인과 header 전송 사이에서 나누는 내부 변경만 필요하다.

8. 재발행마다 처음부터 다시 인가한다. 이전 연결에서 넘어오는 인가 상태는 없다.
   - forward route에서는 이 프로세스의 새 dial이 admission(ADR-0009)과 mTLS를 다시 거친다.
   - reverse route에서는 이 프로세스가 connection을 만들지 않는다. target의 재등록이 controller 데몬의 `host.reverse` 등록 판정을 통과한 뒤에만 7-1이 만족된다.
   - `RemoteForwardClose`와 `RemoteForwardOpen`은 peer의 choke point에서 `forward.remote` ACL 판정, loopback 강제, quota 예약(ADR-0010), bind 순서를 지금과 똑같이 밟고 audit도 여느 요청처럼 남긴다. `TCP_CONNECT`는 지금처럼 스트림마다 `forward.local`로 판정된다.
   - supervisor는 peer 쪽 자원을 스스로 만들지 않고 peer는 인가가 끝난 뒤에만 자원을 만든다. 연결을 잃어도 남는 결정 5의 로컬 listener는 이 머신의 소켓이지 peer 자원이 아니다.

9. 오류 분류는 아래 표 하나로 정한다. 표에 없는 출처와 코드의 조합은 재시도하지 않고 끝낸다. `Unknown(_)` 코드도 같다.

   | 출처 | 코드 | 처리 |
   |---|---|---|
   | 로컬 dial(forward) | `CONNECTION_FAILED`: 주소 DNS 해석 실패, 연결 실패, handshake 기한 초과, admission 거절(`DialError::Refused`, ADR-0009) | 재시도 |
   | 로컬 dial(forward) | `AUTH_FAILED`: 우리가 peer 인증서를 거절(`DialError::LocalRejected`, 예: `qsh trust remove` 뒤)하거나 peer가 우리를 거절(`DialError::RemoteRejected`) | 끝냄 |
   | 로컬 dial(forward) | `INTERNAL`(`DialError::Setup`), `CONFIG_ERROR`(`trust.toml` 손상) | 끝냄 |
   | 로컬 데몬(reverse) | `HOST_NOT_FOUND`: `stale_retention` 창 안의 stale 분기(`retryable: true`)와 창이 지나 등록이 지워진 뒤의 미설정 분기(`retryable: false`) 둘 다 | 재시도 |
   | 로컬 데몬(reverse) | `TIMEOUT`(대기 만료), `CONNECTION_FAILED`(데몬 socket 연결 실패, conduit 오류) | 재시도 |
   | supervisor 자체 검사 | 7-2의 fingerprint 불일치(`AUTH_FAILED`), 7-3의 capability 누락(`UNSUPPORTED`) | 끝냄 |
   | peer 응답 | `PERMISSION_DENIED` | 끝냄 |
   | peer 응답 | 그 밖의 코드 | 응답의 `retryable`을 따른다 |
   | 로컬 listener | 치명적 accept 오류 | 끝냄 |

   peer 응답이 `retryable`을 따르는 규칙에는 예외가 둘뿐이다. 7-4의 close 직후 bind 경합은 정해진 횟수만 다시 보내고, `RemoteForwardClose`의 "no such forward_id"는 성공으로 읽는다. 예를 들어 quota의 `RESOURCE_EXHAUSTED`(`retryable: true`)는 재시도하고, bind 실패 `CONNECTION_FAILED`(`retryable: false`)는 경합 재시도가 끝나면 끝낸다. `PERMISSION_DENIED`를 되풀이하지 않는 이유는 peer의 `acl.toml`이 기동 시 1회만 읽혀서 재시작 전에는 결과가 바뀌지 않고 audit에 거부 줄만 쌓이기 때문이다. `AUTH_FAILED`도 되풀이하지 않는다. 운영자가 신뢰를 거둔 뒤에도 다시 붙으려 하면 fail open이 되기 때문이다. reverse route의 미설정 `HOST_NOT_FOUND`는 앞서 존재했던 route를 기다리는 것이고, 돌아오는 peer는 7-2가 확인하며, 예산이 대기를 묶으므로 재시도한다.

10. 예산과 간격은 다음과 같다.
    - 예산은 "끊김" 상태였던 시간의 합으로 잰다. 재수립된 터널이 살아 있던 시간은 더하지 않는다.
    - 시계는 절전 중에 멈추는 단조 시계다. macOS와 Linux에서 Rust `Instant`와 tokio 타이머가 그렇다. 절전한 시간은 예산을 쓰지 않고, 깨어난 뒤 첫 시도는 즉시 한다. 절전이 예산보다 길어도 깨어난 뒤 한 번은 시도한다.
    - 첫 시도는 유실 감지 즉시 한다. 그 뒤 간격은 500ms에서 시작해 2배씩 늘리고 full jitter를 준다. reverse 시도가 데몬에서 기다린 시간도 "끊김" 시간이고, backoff 대기는 실패한 시도가 돌아온 뒤에만 한다.
    - 빠른 창(`FAST_WINDOW` 60초, `FAST_CAP` 2000ms). 유실을 감지한 순간과 결정 17이 wake를 알린 순간마다 60초짜리 빠른 창을 새로 연다. 창 안에서는 간격이 2000ms를 넘지 않는다. 창이 끝나면 그 자리에서 2배씩 이어 늘려 30000ms에서 멈춘다. 창의 60초는 예산과 같은 단조 시계로 잰다.
    - wake를 알리면 backoff 위치를 처음(500ms)으로 되돌리고, 진행 중인 backoff 대기를 끊어 즉시 한 번 시도하고, 빠른 창을 새로 연다. 진행 중인 시도는 끊지 않는다. forward 시도는 `REDIAL_DEADLINE`으로 이미 묶여 있고 reverse 시도는 데몬 대기 중이라 끊어도 얻는 것이 없다.
    - 시도가 `refused`(admission 거절, ADR-0009)로 끝나면 그 자리에서 빠른 창을 닫는다. peer가 부하를 이유로 거절하는데 2초 간격으로 다시 두드리면 거절 이유를 키운다. 창은 다음 wake나 다음 유실 때 다시 열린다.
    - 30000ms와 500ms는 target의 `[reverse]` backoff 기본값과 같지만 `[reverse]`를 읽지 않는 고정 상수다. `[reverse]`는 target 역할의 설정이기 때문이다. `FAST_WINDOW`와 `FAST_CAP`도 설정으로 열지 않는다. ADR-0021 결정 4가 요구가 확인된 값만 여는 규율을 따른다.
    - 재수립된 터널이 30초 이상 살아 있어야 그 유실이 끝난 것으로 친다. 그 전에 다시 죽으면 누적 예산과 창 밖 backoff 위치를 그대로 이어 쓰고, 빠른 창은 새 유실 감지로 다시 연다. 예를 들어 `--supervise 5000`인 터널이 3초 끊겼다가 재수립되고 20초 뒤 다시 죽으면 남은 예산은 2초다.
    - 예산이 다 떨어지면 마지막 시도의 오류로 끝낸다.

11. 포기와 끝내는 오류는 오늘 hold가 끝날 때와 같은 모양으로 끝난다. stderr에 결정 12의 `gave_up` 줄을 쓰고, 이어 지금처럼 오류를 stderr에 렌더하고(`human::print_error`), 로컬 listener를 놓은 뒤 exit `255`로 끝난다. stdout에는 최초 봉투 한 줄 뒤로 한 바이트도 더하지 않는다. supervised 모드에서만 `qsh serve`/`qsh listen`의 `shutdown_signal()`과 같은 SIGINT·SIGTERM handler를 둔다. 신호를 받으면 유실 중이든 아니든 감독을 멈추고 listener를 놓는다. `-R`은 살아 있는 carrier가 있으면 지금의 `TunnelHold::close`처럼 best-effort `RemoteForwardClose`를 보내되 1초를 넘겨 기다리지 않는다. 그 뒤 `qsh serve`/`qsh listen`과 같이 exit `0`으로 끝난다. 기본 모드의 신호 동작은 바꾸지 않는다.

12. supervisor는 stderr에 tracing target `qsh::tunnel::supervise`의 한 줄 JSON 진단을 낸다. `qsh::tunnel`이라는 이름은 사람용 로그 접두어로 이미 쓰이므로 구별되는 target을 쓴다. `init_tracing`에 `qsh::reverse`와 같은 전용 layer와 `{default},qsh::tunnel::supervise=info` 필터를 더해 기본 verbosity에서 보이게 하고, `--quiet`에서만 끈다. 명시한 `QSH_LOG`/`RUST_LOG`는 다른 진단처럼 이 target도 다스린다. 첫 키는 `supervise`이고 값은 `lost`, `retry`, `reestablished`, `gave_up`, `closed`, `wake` 여섯이다. 필드는 다음과 같다.
    - 모든 줄: `at`(RFC3339, 초 단위, `docs/CLI.md` §6.13과 같은 규칙), `tunnel_id`(그 시점의 값), `mode`, `route`(`forward` 또는 `reverse`).
    - reverse route의 모든 줄: `host`(route 해석에 쓴 별칭 이름. 주소가 아니다). 같은 머신의 `qsh::reverse` 등록 줄이 싣는 `host`와 같은 값이라 한 호스트의 stderr만으로 두 줄을 잇는다(결정 23).
    - `lost`와 `retry`: `cause`. 값은 §6.13의 고정 어휘에서만 고르고 이 ADR은 새 값을 더하지 않는다. 대응은 이렇다. `PathWatch` 판정은 `path_dead`, peer의 CONNECTION_CLOSE는 `peer_closed`, quinn idle timeout은 ROADMAP M11 (a)가 착지한 뒤면 `idle_timeout`이고 그 전이면 `path_dead`, 주소 DNS 해석 실패는 `resolve`, dial 기한 초과는 `dial_timeout`, 연결 거절과 admission 거절은 `refused`, TLS 거절은 `tls_rejected`, 로컬 listener 오류는 `local`이다. connection 종료의 분류는 `classify_connection_error`(`crates/qsh-core/src/reverse/mod.rs`)를 그대로 부르고 따로 두지 않는다. 그래서 stateless reset은 오늘 그 함수가 주는 `local`이다. reverse route의 `LOCAL_CONTROL` 종료처럼 원인을 알 수 없으면 `cause` 키를 생략한다. `null`을 쓰지 않는다.
    - `retry`: `attempt`, `code`(`ErrorCode` 문자열), `outage_ms`.
    - `reestablished`: `outage_ms`. `-R`은 `previous_tunnel_id`도 싣는다. reverse route는 확인한 등록의 `generation`도 싣는다. hub의 `qsh::reverse` `registered` 줄이 같은 `generation`을 싣는다.
    - `gave_up`: `code`, `outage_ms`.
    - `closed`: 결정 14의 운영자 닫기로 끝날 때만 낸다.
    - `wake`: `slept_ms`. 결정 17이 wake를 알릴 때마다, 끊김 상태든 아니든 한 줄 낸다.

    `outage_ms`는 결정 10의 예산 시계로 잰 누적 "끊김" 시간이라 절전한 시간을 넣지 않는다. 벽시계로 본 끊김은 `lost`와 `reestablished`의 `at` 차이이고, 그 사이의 `wake` 줄 `slept_ms`가 둘의 차를 설명한다. 이슈 #6의 수용 기준 "stderr 진단만으로 끊김 시간을 계산한다"는 이 세 값으로 채운다. 주소, 토큰, payload, peer가 보낸 오류 본문은 어느 줄에도 싣지 않는다. 이 진단은 `qsh::reverse`와 `qsh::recovery`처럼 `qsh.cli/v1`/`qsh.event/v1` 밖의 열린 어휘다. `qsh.event/v1` event는 지금 열지 않는다. 개정 관계에 적은 ADR-0022 결정 7의 전제 변화 때문에 health 표면이 필요해졌지만, ADR-0022가 역방향 health에 적용한 순서대로 stderr 진단으로 먼저 관측하고 기계가 읽어야 할 필요가 확인되면 additive로 연다.

13. JSON 계약은 요청 필드만 더한다. `TunnelOpenReq`와 `TunnelDynamicReq`에 각각 `supervise_ms`(결정 1)와 `accept_hold_ms`(결정 19)다. `tunnel.open`과 `tunnel.dynamic`의 성공 `data`는 바뀌지 않는다. 봉투의 `tunnel_id`는 최초 open의 값이다. `-L`과 `-D`에서는 그 값이 프로세스가 끝날 때까지 참이다. `-R`의 `tunnel_id`는 peer가 발급한 `forward_id` 그대로라 재발행마다 바뀌고, 뒤의 값은 stderr의 `reestablished` 줄과 reverse route의 `qsh tunnels`에서만 보인다. `TunnelOpenReq`와 `TunnelDynamicReq`는 `qsh schema`(`crates/qsh-proto/src/schema.rs`는 데이터 타입만 등록한다)와 `crates/qsh-cli/tests/fixtures/`에 나타나지 않으므로 fixture 변경은 없고 `capabilities.json`도 그대로다.

14. supervised 터널을 끝내는 수단은 그 프로세스를 끝내는 것이다(결정 11). reverse route의 `-R`에는 수단이 하나 더 있다. `qsh tunnel close <현재 tunnel_id>`로 닫으면 supervisor는 감독을 끝내고 `closed` 줄을 낸 뒤 listener 없이 exit `0`으로 끝난다. 다음 유실 뒤 다시 열지 않는다. 감지는 기존 localctl 메시지만 쓴다. claim 시도가 대기 없이 곧바로 돌아왔는데 `LOCAL_CONTROL` conduit은 살아 있으면, supervisor는 `LOCAL_ADMIN`의 `LocalHostList`와 `LocalTunnelList`를 한 번씩 조회한다. 그 host가 확인된 generation 그대로 `reachable`이고 현재 `forward_id`만 목록에 없으면 운영자 닫기로 본다. 등록이 바뀌었거나 사라졌으면 유실로 보고 결정 7로 간다. 재발행 뒤 봉투의 최초 `tunnel_id`로 닫으면 `closed: false`가 나온다. 현재 값은 `qsh tunnels`나 `reestablished` 줄에서 얻는다. forward route의 터널은 오늘처럼 다른 프로세스가 닫을 수 없다(`docs/CLI.md` §6.9). `docs/CLI.md` §6.14에 이 규칙을 적는다.

15. ADR-0018과의 관계는 다음과 같다.
    - 결정 1은 유지한다. wire 위의 터널 객체(`forward_id`, 스트림마다의 splice)는 여전히 connection 수명에 결합된다. supervised 모드에서는 결정 1이 처방한 "새 `tunnel.open`"을 프로세스가 스스로 하고 로컬 listener를 놓지 않는다는 점만 다르다. `tunnel_chaos.rs`의 `a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes`는 기본 모드를 계속 고정하며 고치지 않는다.
    - 결정 2는 `--supervise`에 한해 개정한다. 이 모드의 프로세스는 재수립 뒤 들어오는 새 연결을 새 carrier로 싣는다. "끊김" 동안의 새 연결은 여전히 거절된다(결정 6). 기본 모드와 대화형 form에는 결정 2가 그대로다.
    - 결정 3의 P1 백로그 항목은 이 ADR의 close-then-open(결정 7-4)으로 처리한다. 재발행은 데몬이 아니라 터널을 연 프로세스가 한다. `reclaim` wire 경로는 쓰지 않고 예약된 채 남는다. `docs/design/protocol.md` §16.4의 ADR-0018 결정 3 항목도 지우지 않는다. ADR-0018 결과 절의 "필요한 것은 wire 필드 하나와 데몬의 재등록 훅 하나다"는 더는 계획이 아니다.
    - 결정 4는 기록 항목이라 그대로다.

16. peer의 `Server::handle_rfwd_close`는 abort한 forward task가 실제로 끝나 listener가 drop된 뒤에 성공 응답을 보내도록 고친다. wire와 응답 모양은 바뀌지 않는다. 이 수정이 들어간 peer에서는 결정 7-4의 bind 경합이 생기지 않는다. 구버전 peer를 위해 7-4의 제한된 재시도는 그대로 둔다.

17. 절전 복귀(wake)를 직접 감지한다(이슈 #6 요청 2).
    - 프로세스마다 wake 감지기 하나를 `qsh-core`에 둔다. 1초(`WAKE_TICK`)마다 `SystemTime`과 `Instant`를 함께 읽고, 직전 tick 이후 벽시계 증가량에서 단조 시계 증가량을 뺀 값이 3초(`WAKE_SKEW`) 이상이면 wake로 판정한다. 그 차를 `slept_ms`로 알린다. 벽시계가 뒤로 간 경우는 wake로 치지 않는다.
    - 비용은 1초 타이머 하나다. 패킷을 보내지 않으므로 `PathWatch`의 두 cadence가 아끼려던 무선 기상은 생기지 않는다. NTP의 3초 이상 앞으로 뛰는 보정은 wake로 오판되고, 그 비용은 probe 몇 번과 backoff 재시작이다. 오판을 막으려고 플랫폼 절전 통지(IOKit, logind)를 붙이지는 않는다.
    - macOS와 Linux에서 `Instant`는 절전 중에 멈춘다(각각 `CLOCK_UPTIME_RAW`, `CLOCK_MONOTONIC`). Windows에서 이 전제가 맞는지는 Windows client(ROADMAP M19)가 확인한다. 맞지 않으면 감지기는 발화하지 않고 동작은 이 결정 전과 같다.
    - 소비자는 모든 `PathWatch`(대화형 attach, `qsh serve --to` target, `qsh listen`의 등록, supervised forward 터널), 결정 10의 supervisor backoff, 결정 20의 target backoff다. `PathWatch`는 wake를 활동으로 기록하고 잠든 watchdog을 깨워 곧바로 판정한다. 침묵은 잠들기 전 마지막 수신부터 단조 시계로 재므로, 깨어난 뒤 빠른 cadence의 probe 3번(약 750ms)과 `dead_after(rtt)`(기본 `min_dead_after` 1초) 가운데 긴 쪽이 지나면 사망이 선언된다. 기본 설정에서 깨어난 뒤 유실 선언까지의 상한은 `WAKE_TICK + dead_after(rtt)`, 약 2초다.
    - 대화형 attach에도 같은 감지가 붙어 깨어난 뒤 resume이 빨라진다. recovery의 분류와 결과 어휘는 바뀌지 않고 `detection_budget`을 쓰는 기존 테스트는 절전을 흉내 내지 않으므로 그대로다. `docs/design/protocol.md` §2의 "monotonic clock 점프" 문장은 이 기전으로 고친다.
    - 기본 모드 터널에는 wake 감지도 `PathWatch`도 붙이지 않는다(결정 4). 기본 모드는 계속 quinn의 keep-alive와 idle timeout으로 유실을 알고, 이슈 #6이 적은 "깨어난 뒤 최대 45초 동안 accept를 받아 버리는" 동작이 남는다. 그 동작을 피하는 방법은 `--supervise`다.

18. 이슈 #6 요청 3(망 복귀 뒤 backoff 되돌리기)은 결정 10의 빠른 창과 wake 되돌리기로 받는다. 제안된 두 방법 가운데 "wake 뒤 60초 동안 2초 상한"은 그대로 택하고, 빠른 창을 wake뿐 아니라 모든 유실 감지에도 연다. 깨어 있는 동안 VPN underlay가 바뀌는 경우(이슈 #6 수용 기준 셋째 줄)는 wake가 없으므로 wake에만 창을 걸면 놓친다. "route나 interface 변화를 관측하면 재시작"은 이번에 택하지 않는다. macOS의 `NWPathMonitor`/SystemConfiguration과 Linux의 netlink는 플랫폼마다 따로 붙여야 하고 새 의존과 권한 표면이 생긴다. 같은 경우는 모든 유실에 여는 빠른 창으로 플랫폼 코드 없이 덮는다. 캠페인(결과 절)에서 창 밖 구간의 공백이 관측되면 별도 ADR로 다룬다.

19. 재dial 중 accept 유지를 opt-in으로 둔다(이슈 #6 요청 4).
    - standalone `qsh tunnel open`의 `--local`과 `--dynamic`에 `--accept-hold <ms>`를 더한다. 범위는 `0..=2000`, 기본값 `0`(꺼짐)이다. JSON 요청의 `accept_hold_ms`(optional u32)로 실린다. `supervise_ms`가 `0`인데 `0`이 아닌 값을 주거나, 범위 밖의 값을 주거나, `--remote`에 주면 연결을 시도하거나 listener를 bind하기 전에 `INVALID_ARGUMENT`다. 검증은 결정 1과 같이 `Ops`가 한다.
    - 켠 터널은 "끊김" 동안 accept한 연결을 곧바로 거절하지 않고 최대 `accept_hold_ms` 동안 쥔다. 조건은 재수립 시도가 진행 중이거나 다음 시도가 그 기한 안에 시작되는 경우다. 창 밖의 긴 backoff 대기 중에 들어온 연결은 쥐지 않고 결정 6대로 곧바로 거절한다.
    - 쥐는 동안 그 연결의 바이트를 어느 carrier로도 보내지 않는다. `-L`은 accept한 소켓을 읽지 않고 둔다. `-D`는 SOCKS 인사와 CONNECT 요청을 로컬에서 읽은 뒤 `TCP_CONNECT`를 보내기 전에 멈춘다. carrier가 결정 7-2·7-3(reverse route는 7-5까지)을 통과해 "살아 있음"으로 돌아오면 accept 순서대로 새 carrier에 싣는다. 기한이 먼저 오면 결정 6의 방식(`-L`은 RST, `-D`는 REP `0x01`)으로 거절한다.
    - 한 터널이 동시에 쥐는 연결은 64개까지다. 넘치면 곧바로 거절한다. 쥔 연결의 파일 기술자는 이 머신의 자원이고 peer 자원이 아니다. peer 쪽 인가(`forward.local`)는 지금처럼 새 carrier 위의 `TCP_CONNECT`마다 판정된다(결정 8).
    - 기본은 꺼 둔다. 유지는 장애를 가리고 자기 failover를 가진 애플리케이션의 실패를 최대 2초 늦춘다. 초안 대안 절이 "유실 중 accept를 대기열에 넣는다"를 기각한 이유(수 시간 예산 동안 소켓을 붙잡는다)는 기한 2초와 개수 상한 64를 두면 사라진다. 그래서 그 기각은 그대로 두고 이 좁은 모양만 연다.

20. `qsh serve --to` target에도 wake 감지와 backoff 되돌리기를 적용한다(이슈 #6 요청 5).
    - target의 `PathWatch`는 결정 17로 깨어난 뒤 곧바로 판정한다.
    - wake를 알리면 target의 `Backoff`를 `reset()`해 `backoff_initial_ms`부터 다시 세고, 진행 중인 `wait_backoff` 대기를 끊어 즉시 재dial한다. wake 뒤 60초 동안 지연은 `max(backoff_initial_ms, 2000)`을 넘지 않는다. 설정한 `backoff_max_ms`가 그보다 작으면 그 값이 이긴다. 60초는 단조 시계로 잰다.
    - target에서는 이 창을 wake에만 연다. 유실마다 열지 않는다. controller가 재시작하면 그 controller에 붙은 target 전부가 같은 순간에 유실을 보므로 유실마다 2초 창을 열면 재등록이 한꺼번에 몰린다. wake는 머신마다 따로 일어나서 그런 상관이 없다.
    - `[reverse]` 설정 키와 기본값은 그대로다. 등록 성공 시 `reset()`하는 오늘 규칙에 wake라는 두 번째 reset 지점이 생길 뿐이다. `crates/qsh-core/src/reverse/target/tests.rs`의 proptest `backoff_sequence_is_monotone_nondecreasing_until_the_cap`은 reset 사이 구간의 성질이라 고치지 않고 초록이어야 한다.
    - `qsh::reverse` 줄에 `event=wake`(`slept_ms`, `at`)를 더한다. ADR-0022 결정 5가 이 줄을 진단 어휘로 두었으므로 additive다. `docs/CLI.md` §6.13의 이벤트 목록과 `docs/design/protocol.md` §11-4의 backoff 문장을 같은 커밋에서 고친다.
    - 이 변경은 target의 기본 동작이다. `--supervise`처럼 따로 켜는 옵션을 두지 않는다. target은 오늘도 무한히 재시도하는 상주 프로세스이고, 바뀌는 것은 재시도 시각뿐이라 계약 표면(`qsh.cli/v1`, wire, 설정 키)에 닿지 않는다.
    - 이슈 #4 코멘트의 8분 50초 공백은 target의 DNS 해석 실패가 대부분이다. 이 결정은 해석이 돌아온 뒤의 backoff 몫(최대 설정 상한 24.3초)만 줄이고, 그것도 그 공백에 절전이 끼어 있었을 때만 해당한다. resolver 장애 자체는 qsh 밖이다.

21. 수명 줄에 시각을 준다(이슈 #6 요청 6). 사람용 줄의 바이트는 바꾸지 않고 옆에 기계용 줄을 더한다.
    - 새 tracing target `qsh::lifecycle`이 한 줄 JSON을 낸다. 첫 키는 `lifecycle`이고 값은 `listening`, `shutting_down`, `tunnel_opened`, `tunnel_ended` 넷이다. 모든 줄에 `at`(RFC3339, 초 단위)과 `process`(`serve`, `listen`, `serve_to`, `tunnel`)가 있다. `tunnel_*` 줄은 `tunnel_id`, `mode`, `supervise`(bool)를 싣고 `tunnel_ended`는 `code`와 알 수 있으면 `cause`(결정 12와 같은 어휘와 대응)를 싣는다. 주소, bind 주소, 토큰, 오류 본문은 싣지 않는다. bind 주소는 사람용 줄에 이미 있다.
    - `qsh serve: listening on {addr}`, `qsh listen: listening on {addr}`, `… shutting down`, `the connection carrying this tunnel closed: …`의 바이트는 그대로다. 접두어 뒤를 주소로 파싱하는 소비자(`crates/qsh-cli/tests/common/mod.rs`의 `LISTENING_PREFIX`, `LISTEN_LISTENING_PREFIX`와 바깥 스크립트)가 있어서 RFC3339 접두어나 꼬리를 붙이면 그 파서가 깨진다. 그래서 이슈가 제시한 두 방법 가운데 "`qsh::reverse`와 같은 한 줄 JSON 진단으로 보낸다"를 택한다.
    - `init_tracing`에 `qsh::reverse`와 같은 전용 layer와 `{default},qsh::lifecycle=info` 필터를 더한다. 기본 verbosity에서 보이고 `--quiet`에서만 꺼진다. `qsh.cli/v1`/`qsh.event/v1` 밖의 열린 어휘이고 stdout에는 쓰지 않는다(§2.2).
    - 이 결정은 `--supervise`와 무관하게 모든 holder와 두 데몬에 붙는다. 결정 1의 "바이트 단위로 같다"에 대한 유일한 예외이고 stderr 진단에만 닿는다.

22. reverse 전용 host의 route 선택(이슈 #4 코멘트 질문 1)은 이 ADR 안에서 supervised 터널에 한해 답하고, 나머지는 별도 ADR로 넘긴다.
    - 이 ADR 안에서 하는 것. reverse route로 연 supervised 터널은 연 뒤에 forward pin을 dial하지 않는다(결정 4, 7-1). 등록이 stale이든 지워졌든 예산 안에서 등록 복귀만 기다리고, 돌아온 등록은 결정 7-2의 fingerprint로 확인한다. 코멘트의 hub holder가 30초마다 stale pin을 dial하던 일은 최초 open이 reverse route였다면 생기지 않는다.
    - 이 ADR이 하지 않는 것. §6.1 우선순위("stale 등록은 forward pin을 앞지르지 않는다")는 고치지 않는다. 최초 open, `exec`, attach, `session open`이 이 우선순위를 공유한다. 그 문장을 바꾸거나 pin에 "동적 주소" 또는 "reverse 전용" 표시를 두는 일은 네 호출자의 route 계약과 `trust.accept`가 관측 주소를 채우는 규칙(§6.11)을 함께 바꾼다. supervised 터널의 수명과는 다른 결정이다.
    - 넘기는 곳. "reverse 전용 host 표시와 route 우선순위"라는 새 결정이 필요하다. reverse 전용 pin은 방향 값의 하나로 볼 수 있으므로 ROADMAP M16 (a)의 pin 방향 ADR(ADR-0030)에 결정 항목으로 넣는 것을 먼저 제안한다. main 세션이 따로 두기로 하면 새 ADR로 연다. 번호는 아직 배정되지 않은 다음 번호(ROADMAP §5가 0027~0035를 이미 배정했으므로 ADR-0036 이후)다.
    - 그 사이의 우회로는 오늘 코드에 있다. reverse 전용 host의 pin에서 주소를 비우면(fingerprint만 가진 pin, `qsh doctor`의 `host_pinned_without_address`가 정상으로 보는 배치) route 해석이 forward 분기를 지나 stale 분기(`reverse_registration_stale`, `retryable: true`)에 닿으므로 최초 open의 `--wait`가 등록 복귀를 기다린다. `stale_retention`이 지나 등록이 지워진 뒤에는 `retryable: false`라 service manager 재시작에 맡긴다.

23. 상관된 복구 타임라인(이슈 #4 코멘트 질문 3)은 호스트 하나 안에서만 낸다.
    - 한 호스트의 stderr에 `qsh::reverse`(등록 `lost`·`expired`·`registered`, target 쪽 `retry`·`wake`), `qsh::tunnel::supervise`(`lost`·`retry`·`reestablished`·`wake`), `qsh::lifecycle`(결정 21)이 모두 `at`을 싣고 나온다. hub에서는 `host`와 `generation`으로 등록 줄과 supervised 터널 줄을 잇는다(결정 12). 로그를 모으는 쪽은 한 파일을 `at`으로 정렬하면 된다.
    - 호스트를 넘는 상관(노트북의 resolver 실패를 hub에서 보는 일)은 하지 않는다. target이 재등록할 때 자기 끊김 이력을 실어 보내려면 `Hello.reverse`에 필드를 더하는 wire 변경이 필요하고, 그 이력은 target 쪽 네트워크 사정을 controller에 드러낸다. push 표면을 여는 조건은 ADR-0022 결정 3의 관측 트리거 그대로이고, 호스트를 넘는 타임라인이 필요하다는 관측이 쌓이면 그 트리거 아래에서 새 ADR로 다룬다.

24. 구현 순서(이슈 #6 요청 1). ROADMAP M12 (a) 안에서 두 단위로 나눠 착지한다.
    - 첫 단위는 forward route의 `--local`과 `--dynamic`이다. 결정 1~6, 7-1~7-3, 8~13, 17~21과 그 테스트를 담는다. 이 단위만 착지한 동안 reverse route나 `--remote`에 `--supervise`를 주면 연결을 시도하기 전에 `UNSUPPORTED`로 끝난다. 예약된 옵션이 `UNSUPPORTED`를 돌려주는 기존 규율과 같다.
    - 둘째 단위는 reverse route(`--local`, `--dynamic`, `--remote`)와 forward route `--remote`다. 결정 7-4, 7-5, 14, 16, 22를 담고 `UNSUPPORTED` 분기를 지운다.
    - M12 (a)의 DoD는 두 단위가 모두 착지해야 닫힌다. 첫 단위만으로 이슈 #6의 노트북 쪽(`-D`와 네 `--local`)이 풀리고 hub 쪽 reverse route holder는 둘째 단위를 기다린다.

25. 관측 게이트와의 관계. ROADMAP M13 (k)(ADR-0021 결정 1·4 구현)의 착수 조건은 바꾸지 않는다. 이슈 #6의 `timed out`/`reset by peer` 계수는 holder 오류 문면이고 M11 (a)의 `idle_timeout` 어휘로 모은 `cause`가 아니며, 절전·VPN 재협상과 겹친다. hub의 `cause=path_dead` 58건은 0.3.0에서 quinn idle timeout도 `path_dead`로 적던 시기의 값이다(ROADMAP M11 (a)). 둘 다 NAT keep-alive 부족의 증거로 읽을 수 없으므로 M13 (k)의 입력으로 쓰지 않는다. 이 ADR의 wake 감지는 keep-alive와 idle timeout을 건드리지 않고 절전이라는 다른 원인을 다룬다.

## 이슈 요청 대응

| 요청 | 처리 | 결정 | 마일스톤 |
|---|---|---|---|
| #6-1 forward route `-D`/`-L`부터 승인·구현 | 택함 | 24 | M12 (a) 첫 단위 |
| #6-2 wake 직접 감지, 즉시 probe, 45초 넘는 정지 테스트 | 택함(상수 `WAKE_TICK` 1초, `WAKE_SKEW` 3초). 테스트는 주입한 wake와 50초 blackhole 둘로 나눈다 | 4, 17 | M12 (a) 첫 단위 |
| #6-3 wake·망 변화 뒤 backoff 되돌리기 | 고쳐서 택함. 60초 동안 2초 상한을 wake와 모든 유실에 연다. interface 변화 관측은 택하지 않음 | 10, 18 | M12 (a) 첫 단위 |
| #6-4 재dial 중 짧은 accept 유지, 기본 꺼짐 | 고쳐서 택함. `--accept-hold` 최대 2000ms, 기본 0, 동시 64개 | 6, 19 | M12 (a) 첫 단위 |
| #6-5 `qsh serve --to`에 같은 감지와 backoff 복귀 | 고쳐서 택함. 창은 wake에만 연다 | 17, 20 | M12 (a) 첫 단위 |
| #6-6 수명 줄 시각 | 고쳐서 택함. 사람용 줄은 그대로 두고 `qsh::lifecycle` JSON 줄을 더한다 | 21 | M12 (a) 첫 단위 |
| #4 코멘트 질문 1 stale forward pin 대신 등록 대기 | supervised 터널은 택함. §6.1 우선순위와 pin 표시는 별도 ADR로 넘김 | 4, 7-1, 22 | M12 (a) 둘째 단위 / ADR-0030 또는 새 ADR |
| #4 코멘트 질문 2 재등록 동안 listener 유지 | 택함(초안 그대로) | 5, 7-1, 9 | M12 (a) 둘째 단위 |
| #4 코멘트 질문 3 상관 타임라인 | 호스트 하나 안에서만 택함. 호스트를 넘는 상관은 미룸 | 12, 21, 23 | M12 (a) / ADR-0022 결정 3 트리거 |

## 근거

supervisor를 터널을 연 프로세스에 두면 새 상태 저장소가 필요 없다. 최초 요청, 최초 peer fingerprint, `actual_port`, 로컬 listener가 이미 그 프로세스 메모리에 있다. 이슈가 원한 것도 그 프로세스가 끝나지 않는 것이다. launchd holder가 30초마다 다시 띄우는 동안 포트가 사라진 것이 관측된 피해였고, 결정 5가 그 포트를 붙잡아 둔다.

wire를 바꾸지 않을 수 있는 이유는 peer가 이미 연결 사망 때 forward를 걷어가고, 닫기 권한이 principal 축에 있기 때문이다. 새 connection에서 옛 `forward_id`를 먼저 닫으면 peer가 옛 connection의 죽음을 아직 모르는 동안에도 같은 포트를 다시 얻을 수 있다. 다만 오늘 peer는 close 응답을 listener 해제보다 먼저 보낼 수 있으므로, 이 순서가 포트를 돌려주는 것은 결정 7-4의 짧은 재시도와 결정 16의 서버 수정이 함께 있을 때다. 그 조건에서 `reclaim` 필드가 줄 이득은 wire 변경 없이 얻는다.

"끊김" 상태를 carrier에 두는 이유는 신원 확인보다 먼저 나가는 accept가 없어야 하기 때문이다. 프로세스가 살아 있는 동안 listener도 살아 있으므로, 확인 전에 accept를 새 경로로 흘리면 결정 7-2의 검사는 이미 바이트가 흐른 뒤에 끝난다. reverse route에서 accept마다 ack를 대조하는 것은 supervisor가 유실을 알기 전에 등록이 바뀌는 경합까지 닫는다.

옛 connection을 감지 즉시 닫지 않는 이유는 `PathWatch`가 1초 안팎에 사망을 판정하기 때문이다. 세션은 replay ring이 있어 일찍 판정해도 잃을 것이 없지만 터널은 진행 중인 TCP를 잃는다. 기본 모드 터널은 quinn이 45초까지 connection을 쥐므로 수 초짜리 Wi-Fi 끊김을 진행 중인 연결과 함께 넘긴다. supervised 모드가 그보다 약해지면 opt-in 사용자가 예상하지 못하는 퇴행이다. 새 accept만 새 carrier로 보내고 옛 splice는 옛 connection의 운명에 맡기면 두 모드 중 나쁜 쪽을 고르지 않아도 된다.

재시도 분류를 가르는 기준은 "기다리면 결과가 바뀔 수 있는가"다. 인가 거부는 peer가 재시작하기 전까지 바뀌지 않으니 되풀이는 audit 소음일 뿐이다. 신뢰 거부를 되풀이하는 것은 운영자의 결정을 거스른다. 반대로 등록이 지워진 뒤의 `HOST_NOT_FOUND`는 target이 돌아오면 바뀐다. 이슈의 9분 공백은 `stale_retention` 120초보다 길었으므로 이 분기를 끝내는 쪽으로 두면 supervised 모드가 바로 그 사례를 놓친다. 대신 돌아온 peer가 처음의 peer인지를 fingerprint로 확인하므로 이름만 같은 다른 장비에 붙을 수 없다. 표에 없는 조합을 끝내는 쪽으로 두는 것은 모호한 인가·신원 상태에서 fail closed한다는 규칙을 따른다.

절전 중에는 프로세스가 아무것도 시도할 수 없으므로 예산은 절전 시간을 빼고 잰다. 벽시계로 재면 예산보다 긴 절전 뒤에는 한 번도 시도하지 않고 포기한다. 이슈 #4의 사례가 바로 절전과 얽힌 공백이다.

그런데 절전을 빼고 재는 시계는 절전을 보지 못한다. 예산 계산에는 그것이 맞지만, 감지와 재시도 시각에는 그 성질이 해가 된다. 깨어난 뒤 watchdog과 backoff는 잠들기 전 계획을 이어서 실행하고, 그 계획은 망이 바뀌었다는 사실을 모른다. 두 시계를 함께 읽으면 그 차이가 곧 절전 길이다. 한 tick에 두 번 읽는 비용으로 플랫폼 통지 없이 wake를 알 수 있어서 결정 17은 이 방법을 택한다. 오판(NTP의 앞으로 뛰는 보정)의 비용이 probe와 backoff 재시작뿐이라 오판을 줄이려고 더 복잡한 장치를 붙일 이유가 없다.

빠른 창은 모든 유실에 연다. qsh가 망 복귀 시각을 모르기 때문이다. 이슈 #6의 수용 기준은 "망이 돌아온 뒤 2초 안"이고, 2배씩 늘리는 backoff는 복귀 순간에 다음 시도를 8~16초 뒤에 둘 수 있다. 창 안에서 시도가 실패하는 동안 드는 비용은 작다. 망이 없으면 forward 시도는 로컬에서 곧바로 실패하거나 `REDIAL_DEADLINE` 2초로 끝나 peer에 닿는 패킷이 없고, 망이 있으면 첫 성공이 창을 끝낸다. peer에 부하를 주는 경우는 peer가 admission으로 거절할 때뿐이라 그 신호(`refused`)가 창을 닫는다. target에서는 한 controller에 붙은 여러 target의 유실이 서로 상관되므로 창을 wake에만 연다. supervised 터널은 한 client 프로세스의 몇 안 되는 터널이다.

accept 유지는 2초로 묶는다. 이슈의 관측은 1~2초짜리 복귀를 가리려는 것이고, 그보다 긴 유지는 애플리케이션의 connect 기한과 겹쳐 장애를 가리는 쪽으로 기운다. 유지 중에도 확인된 carrier로만 바이트가 나가므로 결정 6의 근거("확인되지 않은 carrier로 나가는 accept는 없다")는 그대로다.

수명 줄을 바꾸지 않고 옆에 JSON 줄을 두는 이유는 사람용 줄이 계약이 아니어도 그 줄을 파싱하는 소비자가 이 저장소 안에 있기 때문이다. 기계용 줄을 따로 두면 사람용 문면은 앞으로도 자유롭게 다듬을 수 있다.

## 대안

- 기본값으로 켠다. 기각한다. 연결 유실 때 프로세스가 끝나는 것은 v1 계약이고 바깥 루프가 그 exit에 기대고 있다. `tunnel_chaos.rs`의 트랩과 `docs/CLI.md` §6.14 문면도 기본 동작을 고정한다. 새 동작을 옵션으로만 여는 것이 additive다.
- 터널 전용 client daemon을 둔다. 기각한다. `docs/CLI.md` §6.14가 적어 둔 "터널 전용 client daemon은 두지 않는다"를 다시 여는 일이고 새 IPC, 새 수명 관리, 새 권한 경계가 생긴다. 이 ADR이 필요로 하는 상태는 모두 터널을 연 프로세스에 이미 있다.
- `qsh listen` 데몬이 재등록 직후 `RemoteForwardOpen`을 재발행한다(ADR-0018 결정 3이 그린 모양). 기각한다. 데몬이 자기 판단으로 control 요청을 보내게 되어 `docs/design/protocol.md` §11-3의 relay 규율을 깬다. CLI가 이미 죽었다면 claim 소비자가 없어 재발행한 listener는 accept마다 reset만 돌려준다. ADR-0018 결과 절이 피하려던 "등록돼 있다고 보고되지만 claim conduit이 없는" 상태를 데몬이 스스로 만드는 셈이다.
- `RemoteForwardOpen`에 `reclaim: bool`을 더해 같은 `forward_id`를 다시 붙인다. 기각한다. peer는 연결 사망 때 `conn_id` 축으로 forward를 purge하므로 붙일 대상이 없다. 붙일 대상을 남기려면 purge 축을 principal로 바꾸고 carrier 없이 bind된 소켓을 peer에 남겨야 하는데, 그것은 capability와 threat model 검토가 필요한 wire 변경이다. 얻는 것은 같은 포트의 재사용뿐이고 결정 7-4와 16이 wire 변경 없이 그것을 준다.
- 사망 판정 즉시 옛 connection을 닫는다. 기각한다. 근거 절의 이유로 짧은 끊김에서 기본 모드보다 진행 중인 연결을 더 잃는다.
- `LocalHello`에 기대 generation이나 fingerprint 필드를 더해 데몬이 불일치를 거절하게 한다. 택하지 않는다. `qsh.local.v1`은 freeze 밖(`docs/design/protocol.md` §16.3)이라 가능하지만 `LocalHelloAck`가 이미 두 값을 싣고 데몬이 ack 뒤에야 header를 기다리므로 client가 header 전에 대조하면 같은 보장을 얻는다. 데몬과 client 버전이 어긋나는 경우도 생기지 않는다.
- 데몬의 `admin_close_forward`가 해당 claim conduit에 "closed by admin" `LocalError`를 보낸다. 택하지 않는다. 데몬에 새 동작과 새 오류 구분이 생긴다. 결정 14의 `LOCAL_ADMIN` 조회는 기존 메시지만으로 같은 판단을 한다.
- 터널을 broker 관리 리소스로 올려 진행 중인 TCP까지 resume한다. 기각한다. ADR-0018 대안 절과 같은 이유다. 스트림마다 양쪽 replay buffer가 필요한 재설계이고 터널을 broker 밖에 둔 결정을 뒤집는다.
- 유실 중 accept를 대기열에 넣었다가 재수립 뒤 잇는다. 기각한다. 예산이 수 시간일 수 있는 구간 동안 소켓과 메모리를 붙잡는다. 어차피 애플리케이션의 connect 기한이 먼저 끝나고 대기는 장애를 가린다. 즉시 RST는 오늘 stale 구간의 `LocalForward`와 같은 동작이라 새 규칙이 아니다. 기한 2초와 개수 상한을 둔 좁은 유지만 결정 19가 opt-in으로 연다.
- accept 유지를 기본으로 켠다. 기각한다. 이슈도 기본 꺼짐을 요청했다. 자기 failover를 가진 클라이언트는 즉시 거절을 받아야 다른 경로로 빨리 넘어간다.
- accept 유지 상한을 2초보다 길게 둔다. 기각한다. 근거 절에 적은 대로다. 긴 끊김은 유지 대신 빠른 창과 wake 감지로 덮는다.
- wake를 플랫폼 절전 통지로 감지한다(macOS IOKit `IORegisterForSystemPower`, Linux logind `PrepareForSleep`). 택하지 않는다. 플랫폼마다 코드와 의존이 생기고 Linux에서는 D-Bus 접근이 필요하다. 두 시계의 차이로 같은 사실을 알 수 있고 오판의 비용이 작다.
- wake 감지 tick을 `PathWatch`의 cadence에 싣는다. 택하지 않는다. idle cadence가 5초라 감지가 최대 5초 늦는다. 1초 타이머 하나는 패킷을 만들지 않는다.
- interface나 route 변화를 관측해 backoff를 되돌린다. 이번에는 택하지 않는다(결정 18).
- 빠른 창을 target에도 모든 유실에 연다. 기각한다. controller 재시작처럼 target 여럿이 같이 유실을 보는 경우에 재등록이 몰린다(결정 20).
- 기본 모드 터널에도 wake 감지로 빨리 끝나게 한다. 기각한다. 기본 모드는 바이트 단위로 같아야 하고(결정 1), 빨리 끝나 봐야 service manager의 throttle을 기다린다. 이슈 #6은 listener가 남기를 원했다.
- 수명 줄에 RFC3339 접두어를 붙인다. 기각한다. 접두어 뒤를 파싱하는 소비자가 있다(결정 21).
- stale 등록이 forward pin을 이기도록 §6.1을 이 ADR에서 고친다. 택하지 않는다. `exec`, attach, `session open`까지 함께 바뀌는 route 계약 변경이라 supervised 터널 ADR의 범위가 아니다(결정 22).
- target이 재등록할 때 끊김 이력을 controller에 실어 보내 호스트를 넘는 타임라인을 만든다. 이번에는 택하지 않는다. wire 변경이고 push 표면은 ADR-0022 결정 3의 트리거를 따른다(결정 23).
- `qsh serve --to`처럼 무한히 재시도한다. 기각한다. 포기 신호가 없어지고 테스트로 고정할 끝이 없다. 무한 재시작이 필요하면 service manager가 이미 그것을 준다. target의 무한 재시도는 host 자신의 가용성이라 성격이 다르다.
- `--wait`의 값을 유실마다의 예산으로 재사용한다. 기각한다. `--wait`는 여는 시점에 stale 분기 하나만 재시도하고 `stale_retention`으로 깎이는 옵션이다. 그 의미를 넓히면 기존 옵션의 의미가 바뀐다.
- reverse route의 예산을 `stale_retention`으로 깎는다. 기각한다. `--wait`가 그렇게 하는 이유는 만료 때 "같은 retryable 오류"를 돌려준다는 약속 때문인데, supervisor는 그런 약속을 하지 않는다. 깎으면 120초를 넘는 절전과 이슈의 9분 공백을 놓친다.
- 예산을 벽시계로 잰다. 기각한다. 예산보다 긴 절전 뒤에는 한 번도 시도하지 않고 포기하고, 30초 안정 구간 안에서 짧게 붙었다 끊기면 남은 예산이 살아 있던 시간만큼 줄어 계산을 테스트로 고정하기 어렵다.
- 최초 open 실패도 감독한다. 이번에는 넣지 않는다. listener는 capability 확인 뒤에만 bind하므로(ADR-0019 결정 11의 처리 순서) 최초 open이 성공하기 전에는 붙잡아 둘 포트가 없다. 감독해도 재시도 간격이 service manager보다 짧아질 뿐이다. 최초 open은 `--wait`와 service manager 재시작 몫으로 둔다.
- supervision 상태를 지금 stdout이나 `qsh.event/v1`으로 낸다. 기각한다. ADR-0022와 같은 순서를 따른다. stderr 진단으로 먼저 관측하고 기계가 읽어야 할 필요가 확인되면 additive로 연다.
- 대화형 form에도 같은 모드를 넣는다. 이번에는 넣지 않는다. 대화형 attach는 이미 자기 recovery driver가 있고, 그 driver가 새 connection을 `-L`/`-D` carrier에 넘기는 일은 `SessionAttachStream` 안의 별도 변경이다. 사람이 resume 배너를 보고 있다는 전제도 다르다. 요구가 생기면 새 ADR로 다룬다.

## 결과

- `qsh tunnel open`에 `--supervise <ms>`와 `--accept-hold <ms>`가 생긴다. 이것이 없는 모든 호출은 stdout, JSON, 동작이 오늘과 바이트 단위로 같고 stderr에는 결정 21의 `qsh::lifecycle` 줄만 더해진다. `qsh serve --to`는 wake 뒤 재시도 시각만 바뀐다(결정 20). 문서는 같은 커밋에서 고친다.
  - `docs/CLI.md` §6.9에 두 옵션 문단을 더한다. §6.14에는 첫 문단 끝의 참조 한 구절과 "supervised 예외" 문단(결정 5, 6, 11, 14, 19)을 더한다. §6.12와 §6.13에 `qsh::lifecycle` 문단(결정 21)을 더하고, §6.13의 `qsh::reverse` 이벤트 목록에 `wake`와 target의 wake 뒤 backoff 규칙(결정 20)을 더한다. §6.1은 고치지 않는다.
  - `docs/design/protocol.md` §2의 "monotonic clock 점프/PTO 실패로" 문장을 결정 17의 기전(벽시계와 단조 시계의 차이)으로 고친다. §10 "Path 사망 감지" 목록에 wake 항목 하나를 더한다. §11-4의 target backoff 문장에 "wake 뒤 초기값으로 되돌리고 60초 동안 2초 상한"을 더한다. 모두 wire 밖의 서술이다.
  - `docs/design/testing.md` L4 표에 "주입한 wake" 행과 "45초를 넘는 blackhole 뒤 supervised listener" 행을 더한다.
  - 새 캠페인 문서 `docs/campaigns/p1-supervise-wake.md`를 사전 고정해 커밋한다(아래 캠페인 항목). 회차는 ROADMAP §5.5의 사람 몫이다.
  - README Known limitations에 "진행 중인 TCP 연결은 옛 connection이 살아날 때만 산다, `-R`은 재발행마다 `tunnel_id`가 바뀐다, 최초 open 실패는 감독하지 않는다, 최초 open의 route는 §6.1 우선순위를 따르므로 reverse 전용 host는 pin에 주소를 두지 않아야 reverse route로 열린다(결정 22)"를 적는다. `docs/deploy/service.md`에 launchd·systemd 배치 예시(`--supervise`와 service manager 재시작을 함께 쓰는 모양)를 더한다.
  - `docs/design/architecture.md` §2에 supervisor가 `Ops` 안에 있다는 한 줄을 더한다.
  - `docs/design/threat-model.md`에 위협 셋을 더한다. §4 A(스푸핑)에 재연결 시 peer 치환(통제: 결정 6, 7-2, 7-5, 19), §4 B(인가)에 재발행의 인가 재사용(통제: 결정 8), §4 C(자원고갈)에 재시도 소음, 옛 connection 누적, 빠른 창의 재dial 빈도, 쥔 accept의 파일 기술자(통제: 결정 9, 10의 `refused` 창 닫기, 19의 2초·64개 상한, peer의 연결 quota)다.
  - `docs/design/protocol.md` §16.4의 ADR-0018 결정 3 항목에는 "ADR-0023은 이 길을 쓰지 않았다"는 한 줄만 붙인다.
  - `docs/ROADMAP.md` §3 가드레일 표의 "Forward-route live carrier·`-R` 자동 재발행" 행에 이 ADR을 잇는 갱신이 필요하다. 2026-09-26 P1 착수 때 그 행에 M12 귀속과 이 ADR의 개정 범위를 적었다. §5 M12 (a)의 범위·DoD·크기 줄은 결정 17~24와 아래 크기로 고친다. §5.5에 `p1-supervise-wake` 회차 행을 더한다.
- wire, `.proto`(`qsh.local.v1` 포함), capability 문자열, `ErrorCode`는 바뀌지 않는다. `acl.toml`을 쓰는 명령도 생기지 않는다(ADR-0017 결정 1). 코드에서 바뀌는 peer 동작은 결정 16의 close 응답 시점 하나다.
- 그대로 두는 테스트: `crates/qsh-testkit/tests/tunnel_chaos.rs`의 `a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes`, `crates/qsh-testkit/tests/reverse_tunnel.rs`의 `tunnel_open_local_over_reverse_ends_when_the_registration_drops`, `local_forward_primitive_over_reverse_survives_a_registration_drop_and_self_heals_per_connection`, `tunnel_open_wait_returns_the_same_stale_error_once_the_budget_expires`. 넷 다 기본 모드의 계약이고 이 ADR은 기본 모드를 바꾸지 않는다. `crates/qsh-cli/tests/reverse_blackout.rs`의 테스트도 그대로 둔다.
- 구현이 더할 테스트. 이름은 구현 때 정하되 각 줄이 대응하는 결정을 doc에 적는다.
  - 결정 1: `--supervise` 범위 밖 값은 listener가 생기기 전에 `INVALID_ARGUMENT`다. `tunnel_open_and_hold`에 `supervise_ms`를 주면 연결 전에 `INVALID_ARGUMENT`다.
  - 결정 2: `--supervise`를 줘도 최초 open 실패는 재시도 없이 지금의 봉투와 exit `255`로 끝난다. `--wait`와 함께 줘도 대기 예산은 `stale_retention`으로 깎인다.
  - 결정 3, 5: 재수립을 두 번 거쳐도 `-L`의 로컬 포트와 `tunnel_id`가 같다.
  - 결정 4, 5: forward `-L`에서 2초 blackhole 동안 splice 중이던 연결은 살아남고 재수립 뒤 새 연결은 새 connection으로 나간다. 같은 조건의 기본 모드 터널과 진행 중인 연결의 생존 여부가 같다. 긴 blackhole에서는 유실 전의 연결이 reset된다.
  - 결정 5, 6: blackhole 시작 뒤 accept된 `-L` 연결은 기본 `PathWatchConfig`에서 3초 안에 RST를 받는다. 같은 구간의 `-D` CONNECT는 REP `0x01`을 받는다.
  - 결정 7-1: 유실 중 `qsh listen` 데몬을 재시작해도 예산 안에 재수립된다. reverse route의 `-L`과 `-R`이 target 재등록 뒤 재수립되고, `stale_retention` 창을 넘긴 공백 뒤에도 예산 안이면 재수립된다.
  - 결정 7-2: forward route에서 재dial한 곳의 fingerprint가 다르면 요청 없이 `AUTH_FAILED`로 끝난다.
  - 결정 6, 7-2, 7-5: reverse `-L`에서 다른 fingerprint의 장비가 같은 이름으로 재등록하면 그 사이 accept가 그 장비로 한 바이트도 가지 않고 supervisor가 끝난다.
  - 결정 7-3: `-D`가 재연결 뒤 `dial-filter.v1` 없는 peer를 만나면 `UNSUPPORTED`로 끝난다.
  - 결정 7-4: forward `-R`이 peer의 idle timeout 전에 재발행되고 옛 `forward_id`를 먼저 닫아 같은 포트를 다시 얻는다. listener drop을 늦추는 test binder로 close 직후 bind 경합을 만들어도 재발행이 성공한다. `127.0.0.1:0`만 허락한 정책에서 ephemeral `-R`의 재발행은 `PERMISSION_DENIED`로 끝난다.
  - 결정 8, 9: `forward.remote`가 빠진 `acl.toml`로 재시작한 peer에 대해 supervisor가 `PERMISSION_DENIED`로 끝나고, peer audit에 거부 줄이 하나 남고, 로컬 listener가 놓인다.
  - 결정 9: 출처와 `ErrorCode`의 모든 조합에 대한 분류 단위 테스트. 표에 없는 조합과 `Unknown(_)`은 끝낸다.
  - 결정 10: `--supervise 5000`에서 3초 끊김, 재수립, 20초 뒤 재유실이면 약 2초의 추가 끊김 뒤 `gave_up`이다. 30초를 채운 뒤의 유실은 예산을 새로 채운다.
  - 결정 11: 예산이 끝나면 `gave_up` 줄, 마지막 오류, exit `255`가 순서대로 나온다. 재수립을 두 번 거친 뒤에도 stdout은 봉투 한 줄뿐이다(`crates/qsh-cli/tests/jsonl_purity.rs`의 `a_tunnel_in_progress_keeps_stdout_pure_json_while_qsh_tunnel_diagnostics_land_on_stderr`와 같은 모양). 유실 중 SIGTERM을 받으면 listener를 놓고 exit `0`으로 끝나며 `-R`은 peer에 `RemoteForwardClose`가 닿는다.
  - 결정 12: 기본 verbosity에서 `lost`와 `gave_up` 줄이 stderr에 보이고 `--quiet`에서는 보이지 않는다. 어느 줄에도 주소·토큰 필드가 없다.
  - 결정 13: `-R` 재발행 뒤 `reestablished` 줄의 `tunnel_id`와 `previous_tunnel_id`가 다르고, reverse route의 `qsh tunnels`가 새 값을 보인다.
  - 결정 14: reverse route의 supervised `-R`을 `qsh tunnel close <현재 id>`로 닫으면 `closed` 줄과 exit `0`으로 끝나고 다시 열지 않는다. 등록 유실은 운영자 닫기로 읽히지 않는다.
  - 결정 16: peer가 `RemoteForwardClose`에 성공으로 답한 직후 같은 포트를 bind할 수 있다.
- 2026-09-30 개정이 더하는 테스트. 이름은 제안이고 구현 때 바꿀 수 있지만 대응 결정은 doc에 적는다. 따로 적지 않은 것은 PR 게이트(`cargo nextest run --workspace`)에서 돈다.
  - 결정 17 단위(`qsh-core`, 시계 주입): `wake_detector_reports_a_wall_clock_jump_the_monotonic_clock_did_not_see`(벽시계 60초, 단조 0초 → `slept_ms` 60000), `wake_detector_ignores_divergence_below_three_seconds`, `wake_detector_ignores_a_backward_wall_clock_step`.
  - 결정 4, 17 단위: `path_state_probes_at_once_and_uses_the_fast_cadence_after_a_wake`(idle cadence 상태에서 wake 뒤 첫 판정이 `Probe`이고 3 strike 뒤 `Dead`까지 250ms cadence로 간다), `path_state_treats_a_local_accept_as_activity`.
  - 결정 10, 18 단위: `supervise_backoff_caps_at_two_seconds_inside_the_fast_window_then_doubles_to_thirty`, `supervise_backoff_restarts_and_reopens_the_fast_window_on_wake`, `supervise_backoff_closes_the_fast_window_on_refused`.
  - 결정 20 단위: `target_backoff_restarts_from_backoff_initial_on_wake_and_cuts_the_pending_delay`, `target_fast_window_never_exceeds_a_configured_backoff_max_below_two_seconds`. 기존 proptest `backoff_sequence_is_monotone_nondecreasing_until_the_cap`은 고치지 않고 초록이다.
  - 결정 17 crate 내부 통합(`qsh-core`, loopback 서버, 시계 주입, 수 초): `supervised_forward_carrier_is_declared_lost_within_two_seconds_of_an_injected_wake`. idle cadence에 들어간 supervised `-D`의 서버를 CONNECTION_CLOSE 없이 사라지게 하고(quinn idle 타이머는 45초가 남은 상태), 주입한 wake 뒤 `lost`(`cause: path_dead`)가 `WAKE_TICK + min_dead_after + 500ms` 안에 나옴을 단언한다. 이슈 #6 요청 2의 "깨어난 뒤 `min_dead_after` 안에 유실 선언"은 감지기 tick 1초를 더한 이 상한으로 고정한다. 시계 주입은 `#[cfg(test)]` 전용이다(ROADMAP M11 (a)와 같은 규율). 같은 모양의 `serve_to_target_probes_and_redials_at_once_after_an_injected_wake`가 target 쪽을 고정한다.
  - 결정 5, 10 testkit(`ci.yml` acceptance job, `QSH_ACCEPTANCE_SLOW`, strict): `supervised_dynamic_listener_stays_bound_through_a_50_second_blackhole_and_connects_after_it`. 45초를 넘는 blackhole이라 peer는 idle timeout으로 connection을 걷는다. blackhole 동안 1초마다 로컬 포트에 붙어 보고 한 번도 connection refused가 아님(REP `0x01`이나 RST)을 단언한다. blackhole을 걷은 뒤 SOCKS CONNECT가 `FAST_CAP` 2초와 handshake 1회 안에 성공함을 단언한다. SIGSTOP이나 blackhole로는 단조 시계가 멈추지 않으므로 이 테스트는 wake 감지기를 부르지 않는다. 이 테스트는 "peer가 connection을 걷은 뒤에도 listener가 남고 빨리 돌아온다"를 고정하고 wake 경로는 위의 주입 테스트가 맡는다.
  - 결정 19: `accept_hold_zero_keeps_the_immediate_rejection_of_decision_6`, `accept_hold_dispatches_a_held_connect_once_the_carrier_is_confirmed`, `accept_hold_rejects_at_the_deadline_without_sending_a_byte_to_any_carrier`, `accept_hold_rejects_past_sixty_four_held_connections`, `accept_hold_is_not_used_during_a_backoff_wait_longer_than_the_hold`, `accept_hold_without_supervise_or_above_two_thousand_or_on_remote_is_invalid_argument_before_bind`.
  - 결정 21: `serve_and_listen_listening_lines_are_byte_identical_and_a_lifecycle_line_carries_at`, `a_default_mode_tunnel_end_emits_a_lifecycle_line_with_code_and_no_address`, `quiet_suppresses_lifecycle_lines`. `jsonl_purity.rs`의 기존 테스트가 고치지 않고 초록이다(stdout은 봉투 한 줄).
  - 결정 12, 23: `supervise_lines_on_reverse_route_carry_host_and_a_generation_that_matches_the_registered_line`, `supervise_wake_line_reports_slept_ms_and_outage_ms_excludes_it`.
  - 결정 22: `supervised_reverse_route_local_never_dials_a_forward_pin_while_the_registration_is_stale_or_swept`. 같은 이름에 blackhole 주소의 forward pin을 두고, 등록을 끊고, `stale_retention`을 넘겨 기다린 뒤 재등록한다. pin 주소로 가는 dial이 0번이고 `reestablished`가 나옴을 단언한다. `resolve_route_reverse_prefers_the_live_daemon_over_a_forward_pin`과 §6.1의 stale 분기 테스트는 고치지 않는다.
  - 결정 24: 첫 단위만 착지한 트리에서 reverse route나 `--remote`에 `--supervise`를 주면 연결 전에 `UNSUPPORTED`다. 둘째 단위가 이 테스트를 지운다.
- 캠페인 `docs/campaigns/p1-supervise-wake.md`(사람이 돌린다, CI 아님). 이슈 #6의 토폴로지(macOS 노트북, 전체 터널 VPN, hub `qsh serve`·`qsh listen`)에서 회차 넷을 사전 고정한다. 뚜껑 10분 닫기, 뚜껑 20초 닫기, 깨어 있는 동안 VPN underlay 전환, 노트북 `qsh serve --to`의 깨어남 뒤 재등록과 hub 쪽 supervised reverse route `--local`. 절전은 `pmset relative wake <s>` 뒤 `pmset sleepnow`(Linux는 `rtcwake -m mem -s <s>`)로 재현할 수 있게 적는다. 망 복귀 시각은 VPN 너머 hub로 200ms마다 보내는 ping의 첫 응답으로 정한다. 판정은 이렇다. listener 포트에 붙는 1초 주기 탐침이 한 번도 connection refused를 받지 않는다. 망 복귀 뒤 새 SOCKS CONNECT의 성공 시각이 회차 안 반복의 중앙값 2초 이하, 최댓값 4초 이하다. 4초는 복귀 직전에 시작해 패킷을 잃은 시도가 `REDIAL_DEADLINE` 2초로 끝나고 다음 시도가 `FAST_CAP` 2초 뒤에 오는 최악의 합이다. 끊김 시간이 stderr의 `lost`·`wake`·`reestablished` 줄만으로 계산된다. §5.1 원칙 6에 따라 M12 DoD는 이 문서의 사전 고정 커밋까지이고 회차는 §5.5에 둔다.
- `checked_in_man_pages_match_the_generator`가 새 flag 때문에 빨개지면 `cargo xtask man`으로 맞춘다. fixture 변경은 없다(결정 13).
- 알려진 한계. 진행 중인 TCP 연결은 forward route `-L`/`-D`에서 옛 connection이 살아날 때만 살고 그 밖에는 살지 않는다. `-R`의 포트를 지킬 수 없으면 터널은 이어지지 않고 끝난다. `-R`은 재발행마다 `tunnel_id`가 바뀌어 봉투의 값으로는 닫을 수 없다. 최초 open 실패는 감독하지 않는다. 최초 open의 route는 §6.1을 따르므로 주소가 남은 pin이 있으면 reverse 전용 host도 forward route로 열리려 한다. wake 감지는 Windows에서 확인되지 않았다. 이 여섯은 README와 §6.14에 적는다.
- 마일스톤 배치는 P1이다. 선행 조건은 없다. `[recovery]` 설정(ADR-0021 결정 4)이 먼저 들어오면 결정 4의 `PathWatch`가 그 값을 따르고, 그 전이면 기본값으로 돈다. `docs/ROADMAP.md` §5는 이 ADR을 M12 (a)에 두었고 결정 24가 그 안을 두 단위로 나눈다. 결정 22가 넘기는 route 우선순위 결정은 M12 밖이다(ADR-0030과 M16 (a), 또는 새 ADR).
- 이 ADR이 승인되고 구현되면 이슈 #4 항목 5b 가운데 연 뒤의 유실은 바깥 루프 없이 해소된다. 부팅 직후처럼 최초 open 시점에 target이 없는 경우는 여전히 `--wait`와 service manager 재시작에 맡긴다. 이슈를 닫을지는 이 범위를 보고자에게 적어 확인한 뒤 정한다. 답은 "터널을 연 프로세스가 listener를 쥔 채 스스로 재수립하는 opt-in 모드를 둔다. wire는 바꾸지 않고, 재발행은 매번 처음부터 인가하며, 확인된 peer에만 다시 붙고, 진행 중인 TCP 연결은 옛 connection이 살아날 때만 산다"다.
- 이슈 #6에는 이 ADR이 승인되면 결정 24의 순서와 대응표를 적어 답한다. 이슈 #4 코멘트의 질문 1은 supervised 터널 몫과 결정 22가 넘기는 몫을 나눠 답하고, 그 사이의 우회로(주소 없는 pin)를 함께 적는다.
- 구현 크기는 3.3~3.8ew로 추정한다. 측정값이 아니다. 초안 내역은 supervisor 루프와 오류 분류 0.4, carrier `watch` 교체와 "끊김" 거절 0.3, 터널용 `PathWatch`·migration·재dial 경로 0.3, reverse route 재해석·`known_generation`·accept별 신원 대조 0.25, `-R` close-then-open·경합 재시도·운영자 닫기 감지·결정 16의 서버 수정 0.25, tracing layer와 신호 handler 0.15, 요청 필드와 CLI flag 0.1, 테스트 0.4~0.7, 문서 0.15다. 2026-09-30 개정이 더하는 것은 wake 감지기와 `PathWatch` 배선 0.2, 빠른 창과 target wake reset 0.15, accept 유지 0.2, `qsh::lifecycle` 0.15, 진단 필드 0.05, 테스트 0.2~0.3, 캠페인 문서 0.1이다.

## 개정 이력

- 2026-09-26: 초안(제안됨).
- 2026-09-30: 이슈 #6과 이슈 #4의 2026-09-30 코멘트를 반영했다. 맥락 절에 현장 자료와 그 자료가 드러낸 사실을 더했다. 결정 4(accept를 활동으로, wake), 6(accept 유지 예외), 7-1(reverse 재탐색은 forward pin을 보지 않는다), 10(빠른 창, wake 되돌리기, `refused`가 창을 닫는다), 12(`route`, `host`, `generation`, `wake` 줄, `idle_timeout` 대응), 13(요청 필드 넷)을 고쳤다. 결정 17~25와 이슈 요청 대응 절을 더했다. 결과 절의 문서·테스트·캠페인·크기를 고쳤다. 같은 날 사용자가 이슈 반영을 모두 진행하라고 지시해 승인됨으로 바꿨다.
