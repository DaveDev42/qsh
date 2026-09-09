# ADR-0014: peer 주소는 포트 생략 시 4433을 채우고 읽기·쓰기 양쪽에서 정규화하되 파일은 쓰지 않는다

날짜: 2026-09-09
상태: 제안됨

## 맥락

qsh는 이미 포트 하나만 쓴다. `[::]:4433`이 `qsh serve --bind`/`[serve].bind`의 기본값이고(`crates/qsh-core/src/serve.rs:21`의 `DEFAULT_BIND`), `qsh listen --bind`/`[listen].bind`도 같은 기본값을 공유한다(`docs/CLI.md` §6.13, "`qsh serve`와 기본값이 같다"). 문제는 bind 쪽이 아니라 사람이 손으로 적어 넣는 peer 주소 쪽이다.

형식 자체는 이미 문서와 clap 양쪽에 명시돼 있다. `qsh trust add <name> --address <host:port>`(`docs/CLI.md` §6.11)와 `crates/qsh-cli/src/cli.rs`의 `TrustAddArgs.address`(`value_name = "HOST:PORT"`), `hosts.toml`의 `address = "personal-mac.example.com:4433"` 예시(`docs/CLI.md` §6.1)가 전부 `host:port`를 요구한다. 없는 것은 그 형식을 강제하거나 보정하는 코드다. `Ops::trust_add`(`crates/qsh-core/src/ops/mod.rs:503`)는 fingerprint 파싱만 하고 주소는 손대지 않으며, `TrustStore::add_peer`(`crates/qsh-core/src/trust/mod.rs:224`)도 받은 문자열을 그대로 `TrustPeer.address`에 넣는다. 그 결과 `trust.toml`에 `address = "personal-mac.example.com"`처럼 포트 없이 적으면 어긋난 입력은 저장 시점이 아니라 dial 시점에 조용히 터진다. `dial_peer`(`crates/qsh-core/src/ops/session.rs:1115`)가 `tokio::net::lookup_host(&address)`(같은 파일 1124행)를 그대로 부르는데, `&str`의 `ToSocketAddrs` 구현은 `host:port` 형태를 요구하므로 포트 없는 문자열은 리졸브 자체가 실패한다.

`qsh trust accept <address> <code>`는 사정이 다르다. `Ops::trust_accept`(`crates/qsh-core/src/ops/mod.rs:637`)는 `resolve_one(&dial_address)`로 먼저 dial하고 성공한 뒤에야 `req.address`로 pin하므로("pin with the address this exchange just dialed successfully"), 포트 없는 주소는 dial이 `CONNECTION_FAILED`로 끝나 파일에 남지는 않는다. 쓸모없는 주소가 실제로 저장되는 경로는 `--fingerprint`를 준 `trust add` 하나다. 이때 `Ops::trust_add`의 fingerprint 없는 분기는 `self.probe_fingerprint(address)`를 생짜 리터럴로 불러 `TRUST_REQUIRED`로 조기 반환하므로(`crates/qsh-core/src/ops/mod.rs:517-536`), 포트 없는 주소는 `probe_fingerprint` 내부의 `resolve_one`에서 이미 깨진다. 이 오류의 `details.address`(`docs/CLI.md` §6.11이 계약으로 규정한 field)도 생짜 값을 그대로 돌려주므로, 사용자가 그 값을 복사해 `--fingerprint`로 재호출하는 문서상 절차가 포트 없는 주소를 다시 실어 나른다.

2026-09-08 사람용 CLI 설계(`design.html` §5, `human-surface.md` §5)는 이 구멍을 "포트는 4433 하나다. 파서 한 곳에서 채우고 읽기 시점에도 정규화해, 손으로 쓴 `trust.toml`의 포트 없는 주소도 `trust.list`에서는 `host:port`로 나온다. 파일은 안 건드린다."로 정리했다. 이 항목은 사용자가 2026-09-09 확정한 §8 Q1~Q5 다섯 건 어디에도 걸리지 않아 개별 확정 대상이 아니었다(`DECISIONS.md`). Q1 확정("쪼개서 M9 앞에, M8 Step 6에서 ADR 초안과 역할 표만 먼저 냄")에 따라 이 ADR은 초안으로 낸다. 같은 설계는 `qsh reverse <controller>`를 `qsh serve --to <listener|host:port>`로 개명하기로 했는데(Q2, ADR-0012 소관), 이 새 인자는 지금까지 CLI 어디에도 없던 것을 요구한다. trust 별칭과 생짜 `host:port`를 한 인자로 함께 받아야 한다. 이 ADR은 그 인자의 해석 규칙과, 포트 생략 시 4433을 채우는 정규화 규칙 자체를 결정한다.

## 결정

1. 기본 포트는 4433 하나이고 새로 만들지 않는다. `qsh serve`/`qsh listen`의 bind 기본값(`[::]:4433`)과 이 ADR이 다루는 peer 주소 쪽 기본 포트(4433)는 같은 상수를 가리키는 같은 결정이다. 별도의 "peer 기본 포트"를 신설하지 않는다.

2. 주소 정규화 함수를 신설한다. 입력 문자열이 이미 `host:port` 형태면 그대로, 포트가 없으면 `:4433`을 붙여 반환하는 순수 함수 하나를 `qsh-core`에 둔다. 호출자가 CLI든 core 내부든 이 함수 하나만 거친다("파서 한 곳"). 빈 문자열에는 항등이다. `hosts.toml`/`trust.toml`이 의도적으로 비워 둔 `address`(주소 없는 inbound 전용 pin, §6.1·§6.11이 규정하는 빈 문자열 폴백)에 `:4433`을 붙여 도달 가능해 보이는 dial 후보로 바꾸는 일은 없다.

   포트 유무 판정은 이미 코드에 있는 규칙을 재사용한다. `server_name_for`(`crates/qsh-core/src/ops/mod.rs:919`)가 SNI를 뽑을 때 쓰는 "가장 오른쪽 `:` 뒤가 전부 숫자면 포트가 있는 것"이라는 규칙이다. `qsh-proto`에는 대괄호 IPv6를 이미 정확히 다루는 문법 파서가 둘 있다. `format_host_port`와 `parse_forward_spec`(둘 다 `crates/qsh-proto/src/wire.rs`, `-L`/`-R` 스펙 문법)이다. 새 정규화 함수는 그 표기 규칙과 어긋나지 않게 두고, 배치는 계약층인 `qsh-proto`를 먼저 검토한다(`qsh-cli` → `qsh-proto`는 arch 매트릭스상 허용된다).

   `trust.toml`/`hosts.toml`의 `address`에 대괄호 없는 순수 IPv6 리터럴(`::1` 류)을 쓴 사례는 저장소에 없다(`crates/qsh-core/src/trust/mod.rs`의 테스트 주소, `docs/CLI.md` §6.1·§6.11 예시 전부 도메인 아니면 IPv4). `server_name_for`의 규칙은 그런 리터럴을 오판할 수 있지만, 이 ADR은 그 처리를 결정하지 않고 구현 스텝(S1)의 몫으로 남긴다.

3. 쓰기 시점에 적용한다. 각 op의 진입점에서 사용자가 준 리터럴을 한 번 정규화하고, 그 op 안의 모든 하위 사용처가 그 정규화된 값을 쓴다.
   - `Ops::trust_add`: `req.address`를 정규화한 뒤 `probe_fingerprint`(fingerprint를 관측하는 dial)와 `TrustStore::add_peer`(저장) 양쪽에 그 값을 넘긴다. `TRUST_REQUIRED` 오류의 `details.address`도 정규화된 값을 echo한다. 사용자가 그 값을 그대로 복사해 `--fingerprint`로 재호출해도 포트 없는 주소를 다시 실어 나르지 않는다.
   - `Ops::trust_accept`: `req.address`를 정규화한 뒤 `server_name_for`, `resolve_one`(dial), 오류 메시지, 그리고 `store.add_peer(..., Some(req.address), ...)`(저장되는 pin 주소) 네 자리 모두에 그 값을 쓴다.

   이렇게 새로 쓰이는 `trust.toml` 항목은 처음부터 포트가 박힌 채로 저장되므로 "파일 무변경" 원칙과 충돌하지 않는다. 그 원칙이 지키는 것은 사람이 이미 손으로 써 둔 기존 파일이지, 지금 이 명령이 새로 쓰는 바이트가 아니다.

4. 읽기 시점에도 적용하되 파일은 절대 다시 쓰지 않는다. 사람이 손으로 쓴 `trust.toml`/`hosts.toml`의 포트 없는 주소는 그 값을 소비하는 함수 안에서만 정규화하고 디스크의 바이트는 손대지 않는다. 이 ADR이 지목하는 함수는 `qsh-core`가 이미 host→주소 해석을 몰아 둔 두 곳이다.

   - `host::resolve_forward`(`crates/qsh-core/src/ops/host.rs:231`)가 반환하는 `ForwardEntry.address`. 이 함수는 `Ops::host_list`(내부 `forward_hosts`), `Ops::resolve_host_route`(내부 `resolve_route`의 forward 폴백 분기이고, `Ops::host_get`과 attach 라우팅이 이걸 공유한다), `resolve_peer_address`(`crates/qsh-core/src/ops/mod.rs:889`, `qsh exec`·`reverse::target::dial_and_register`의 controller dial이 이걸 공유한다), `Ops::doctor`(`same_as_controller` 중복 진단이 `resolve_peer_address`의 두 결과를 문자열 동등으로 비교한다)까지 전부가 거치는 단일 지점이다. 여기 한 곳에 정규화를 넣으면 이 소비자 전부가 동시에 고쳐진다. 라이브 역방향 등록으로 뜨는 주소(`resolve_route`의 `HostRoute::Reverse` 분기)는 `resolve_forward`를 거치지 않지만, 그 값은 사람이 손으로 쓴 파일이 아니라 상주 `qsh listen` 데몬이 실제 연결에서 관측해 만든 것이라 정규화 대상이 아니다.
   - `Ops::trust_list`(`crates/qsh-core/src/ops/mod.rs:560`). 이 op은 `resolve_forward`를 거치지 않고 `store.peers().to_vec()`를 그대로 반환하므로 별도 지점이다. 반환하는 `TrustPeer` 벡터의 `address` 필드에 같은 정규화를 적용한 뒤 돌려준다.

   `resolve_forward`는 `source`(§5, "hosts"/"trust"/"both") 판정도 같은 함수 안에서 한다(`host.rs:244-259`, 정규화 전 생짜 문자열 비교). `hosts.toml`이 `mac:4433`, `trust.toml`이 `mac`처럼 표기만 다르고 같은 주소를 가리키는 경우, `source` 비교는 정규화된 값으로 한다. 포트 표기만 다른 같은 주소를 `"hosts"`(불일치)로 보고하면 사용자에게 거짓 신호를 준다. `crates/qsh-cli/tests/hosts_toml.rs`가 이 병합·우선순위 규칙의 기존 소진 테스트이고, 이 상호작용을 여기서 고정한다.

   두 지점 모두 `TrustStore`/`HostsFile`이 메모리에 들고 있는 구조체를 파생시켜 응답을 만드는 자리이지 `TrustStore::save`(파일 직렬화) 경로가 아니다. 정규화된 값이 디스크에 다시 쓰이는 일은 없다.

5. 포트를 채운 경우 사람에게 알린다. 정규화 함수가 실제로 `:4433`을 붙인 경우에만(이미 포트가 있던 입력에는 내지 않는다) `assuming port 4433` 한 줄을 stderr에 낸다. 이 줄을 내는 지점은 결정 3의 쓰기 경로, 즉 `Ops::trust_add`와 `Ops::trust_accept`, 그리고 결정 7의 신설 `serve --to` 인자 해석이다. 읽기 경로(`trust.list`/`host.list`/`host.get`)는 이 줄을 내지 않는다. 목록 op은 여러 항목을 한 번에 돌려주므로 항목마다 줄을 내면 소음이 되고, 사람이 이미 손으로 써 둔 파일의 표기를 op을 부를 때마다 지적하는 것은 결정 4의 "파일은 사람이 관리한다"는 원칙과도 맞지 않는다. stdout에는 쓰지 않는다. `--json`/`--jsonl` 모드에서도 이 줄은 stderr에만 나가고 envelope의 field가 되지 않는다(`docs/CLI.md` §2.2, "stdout: 요청한 결과 또는 JSONL event만 출력").

6. 이 ADR의 어떤 결정도 `config.toml`이나 `hosts.toml`을 생성하거나 기록하지 않는다. `hosts.toml`은 `docs/CLI.md` §6.1이 이미 "read-only 디렉터리"로 규정하고 있고, 이를 쓰는 CLI 명령은 지금도 없다. 위 결정 4가 하는 일은 항상 파생값에만 적용되는 읽기 시점 정규화다.

7. `qsh serve --to <listener|host:port>`(개명 자체는 ADR-0012)의 인자는 다음 순서로 해석한다. 오늘의 `qsh reverse <controller>`는 controller를 `resolve_peer_address`로 해석한다(`reverse::target::dial_and_register`가 직접 부른다). 즉 §6.1의 "`hosts.toml`이 있으면 그 주소가 이기고, 없으면 `trust.toml`의 pin으로 폴백한다"는 host→주소 해석을 그대로 얹은 것이지 trust 별칭 전용이 아니다. 새 인자도 이 해석을 갈라 놓지 않는다.
   - 먼저 그 리터럴을 이름으로 보고 `resolve_peer_address`(`hosts.toml` 우선, 없으면 `trust.toml`의 pin)로 해석을 시도한다. 풀리면 그 결과 주소와, `trust.toml`에 그 이름으로 핀된 fingerprint로 dial한다.
   - 이름으로 풀리지 않으면 리터럴을 이 ADR의 정규화 함수로 `host:port`(포트 생략 시 4433 보정)로 만들고, 그 정규화된 문자열과 정확히 같은 `address`를 가진 pinned peer를 `trust.toml`에서 찾는다. 이름이 아니라 주소로 찾는 이 두 번째 조회는 오늘 코드에는 없는 신설 경로다. `TrustStore`에는 이름 조회 `find`만 있고 주소 조회는 없다. 정규화된 주소가 둘 이상의 pinned peer와 일치하면 상대를 하나로 특정할 수 없으므로 `INVALID_ARGUMENT`로 실패한다("주소가 여러 pin과 일치한다, 별칭으로 지정하라"). 파일 안의 등장 순서로 첫 일치를 고르는 동작은 만들지 않는다.
   - 어느 쪽으로도 pinned peer를 찾지 못하면 실패한다. 이름 리터럴 자체를 새 pin의 근거로 쓰거나 주소만으로 blind dial하는 경로는 만들지 않는다. 이 요구의 근거는 세 가지다. §6.1·§6.8이 이미 세운 이름 해석 규칙을 새 인자가 갈라 놓지 않는 일관성, 네트워크 왕복 전에 실패하는 fail fast, 그리고 새 미핀 dial 표면을 만들지 않는다는 점이다. TOFU를 넣지 않기로 한 결정(설계 §4, ADR-0017이 예약해 둔 축) 자체는 이 ADR이 다시 열지 않는다.

     여기서 실제 인가 경계가 어디인지는 분명히 해 둔다. `TrustEvaluator::lookup_pin`(`crates/qsh-transport/src/tls.rs`, 구현은 `SharedTrustStore`)은 `Fingerprint`를 키로 store 전체를 조회한다. 이름도 주소도 아니라 fingerprint 기준이다(`docs/CLI.md` §6.1, "pin 조회는 이름이 아니라 fingerprint 기준"). 즉 핀되지 않은 상대로의 blind dial은 이 이름/주소 조회가 없어도 TLS 계층에서 이미 fail closed다. 반대로 이름·주소 조회를 통과해도 그 dial이 조회에 쓰인 peer의 fingerprint에 묶이는 것은 아니다. 응답한 상대가 store 어딘가에 핀돼 있기만 하면 TLS는 통과한다. 이름·주소 조회는 편의를 위한 라우팅 결정이지 인가 통제가 아니다. 인가는 언제나 `lookup_pin`의 fingerprint 조회가 한다. alias로 무엇을 선택하든 그 dial이 인증되는 principal은 바뀌지 않는다.
   - 이름 일치가 주소 일치보다 항상 먼저다. 어떤 peer의 이름이 우연히 유효한 `host:port` 꼴(예: peer 이름이 `"192.0.2.10:4433"`)과 같아도 이름 조회가 먼저 걸려 그 peer 자신으로 해석되고, 다른 peer의 주소와 겹치는 경우로는 넘어가지 않는다.

8. bind 기본값은 이 ADR로 바꾸지 않는다. `qsh serve --bind`/`[serve].bind`, `qsh listen --bind`/`[listen].bind`의 기본값(`[::]:4433`)과 우선순위(CLI flag > config > 기본값)는 그대로 둔다. `serve::resolve_bind`와 `reverse::listen::resolve_bind`는 지금도 포트 없는 bind spec을 `InvalidArgument`로 거부하며, 이 비대칭은 의도적이다. bind는 이 장비 자신이 어디서 듣는지를 정하는 값이라 조용한 기본값 보정을 허용하지 않는다. 이 ADR의 정규화 함수를 bind 경로에 꽂지 않는다.

   README·man의 `--bind` 예제를 확인한 결과 `README.md:155,261,361`, 캠페인 문서(`docs/campaigns/m2-mobility.md:29,193`, `docs/campaigns/m7-stopwatch.md:98`) 모두 이미 `qsh serve --bind 0.0.0.0:4433`/`qsh listen --bind 0.0.0.0:4433` 형태이고, man 페이지는 clap 자동 생성이라 사용 예제 자체가 없다. 설계 §5의 "README·man의 예제만 `qsh serve`로 고친다"는 문장은 `qsh reverse --bind` 꼴 예제가 남아 있으리라는 전제에서 쓰였다. 그런 예제는 이 저장소 스냅샷에 없으므로 이 항목은 고칠 대상이 없다.

9. 포트 충돌 문면에 `--bind` 처방을 얹는다. 한 장비에서 인바운드 `qsh serve`와 `qsh listen`을 같이 띄우면 기본 포트 공유로 충돌한다는 사실은(`qsh serve --to`는 bind하지 않아 이 충돌 대상이 아니다. ADR-0012 결정 2) 이미 `docs/CLI.md` §6.13에 "충돌은 조용한 오작동이 아니라 즉시·명시적 실패(stderr 진단 + exit `255`)다"로 적혀 있고, 처방 문면("한 머신에서 두 역할을 겸하려면 명시적 `--bind`가 필요하다") 자체도 §6.13과 `qsh listen --bind`의 clap help에 이미 있다. 이 실패와 그 문면은 기존 결정이고 이 ADR이 바꾸지 않는다. 이 ADR이 요구하는 것은 그 문장을 실제 bind 충돌 시 stderr 출력에도 싣는 것뿐이다. 그 출력은 오늘 두 지점에서 조립된다. `crates/qsh-core/src/serve.rs`의 `run_serve`(`ErrorCode::ConfigError`, `"cannot listen on {bind}: {err}"`)와 `crates/qsh-core/src/reverse/listen.rs`의 별도 bind 경로다. 두 지점 모두 고친다. 한쪽만 고치면 `qsh listen` 쪽 충돌은 처방 없는 옛 문면 그대로 남는다. 운영자 문면의 정본을 core에 두고 CLI는 그대로 출력만 한다는 §6.12·§6.13의 규율을 그대로 따른다. 같은 사실을 README `Known limitations`(`README.md:530`)에도 옮겨 적는다. 오늘 그 절에는 포트 공유 사실이 아직 없다.

10. `trust add`의 이름 필수는 이 ADR이 건드리지 않는다. `TrustAddArgs.name`은 이미 `String`이고(옵션이 아니다, `crates/qsh-cli/src/cli.rs:559`) 생략 자체가 지금도 불가능하다. 이 ADR은 그 상태를 그대로 유지한다는 사실만 기록한다. 설계 §5는 "주소 첫 레이블을 제안 값으로만 쓴다"는 문장을 `trust add` 문장 안에 두었지만, Q3 확정으로 이름 결정권이 pin 쪽(`pair invite|accept --as`)으로 옮겨졌으므로 그 제안값을 어디서 찍을지도 ADR-0012 소관이다. 이 ADR은 그 제안값의 소스가 이 ADR의 정규화 함수를 거친 주소의 첫 레이블이라는 점만 적는다.

## 결과

- 고쳐지는 코드는 `qsh-core`에 신설하는 주소 정규화 함수, `Ops::trust_add`/`Ops::trust_accept`(쓰기 정규화와 `assuming port 4433` stderr 알림), `host::resolve_forward`/`Ops::trust_list`(읽기), 신설 `serve --to`의 이름→주소 이중 조회(ADR-0012의 명령 개명과 함께 구현, 같은 stderr 알림 포함)다.
- `trust.toml`/`hosts.toml` 파일 포맷과 append-only/read-only 성격은 바뀌지 않는다. 정규화는 항상 파생값에만 적용된다.
- 주소를 담는 golden fixture 전부(`crates/qsh-cli/tests/fixtures/cli-v1/`의 `trust.list.json`, `trust.add.json`, `trust.accept.json`, `host.list.json`, `host.get.json`, `host.list.with_hosts_toml.json`, `host.get.with_hosts_toml.json`, `error.TRUST_REQUIRED.json`)는 `address`를 전부 `"<address>"`로 마스킹해 두었으므로, 이 ADR의 정규화는 기존 fixture의 바이트를 하나도 바꾸지 않는다. append-only 규칙과 충돌하지 않으며, 새 동작을 고정하는 사례는 새 fixture로 추가한다. `crates/qsh-cli/tests/hosts_toml.rs`가 `resolve_forward`의 병합·우선순위·`source` 상호작용(위 결정 4의 정규화-후-비교 규칙 포함)을 고정하는 기존 소진 테스트다.
- `TrustPeer`는 `crates/qsh-proto/src/types.rs`의 계약 타입이라 field 값만 바뀌고 shape은 그대로다. `docs/CLI.md` §10의 additive-only 규칙에 걸리지 않는다. wire frame과 op 이름은 불변이다.
- 고쳐지는 문서는 `docs/CLI.md` §6.11(trust add/accept의 주소 처리 서술과 `TRUST_REQUIRED`의 `details.address` echo 규칙), §6.13(포트 공유·`--bind` 처방을 실제 stderr 문면에 반영), README `Known limitations`(포트 공유 문장 추가), 정규화 함수의 위치를 적을 경우의 `docs/design/architecture.md` §2(Typed operation layer) 또는 §5(Identity와 trust)다.
- `EXPECTED_DOCTOR_CODES`(`crates/qsh-core/src/doctor.rs:90`)와 doctor 진단 7종은 이 ADR의 범위가 아니다. `bindv6only`/`acl_principal_unmatched`/`acl_ca_auth_path_missing`은 저장소 어디에도 아직 없는 신설 진단이고, 설계 문서 자체도 이를 별도 스텝(S4)으로 미뤄 뒀다.
- `[serve].to`/`[reverse].controller` 이중 읽기, `qsh serve --to`로의 개명 자체, `pair invite|accept --as`는 ADR-0012 소관이다. 이 ADR은 그 개명이 끝난 뒤의 인자(별칭 또는 `host:port`)를 어떻게 주소로 바꾸는지만 결정한다.
- `identity export`/`trust add --cert-file`(ADR-0013), listener 상대 pairing(ADR-0015), pin 방향 축과 TOFU 예약(ADR-0017)은 이 ADR이 다시 열지 않는다. 결정 7의 blind dial 금지는 그 ADR들이 이미 정한 경계를 따른다.

## 대안

- `qsh listen` 전용 별도 기본 포트를 둔다. 기각한다. `docs/CLI.md` §6.13은 이미 "`qsh serve`와 기본값이 같다"를 의도적 결정으로 명시하고 있고(한 머신에서 두 역할을 겸하려면 명시적 `--bind`가 필요하다는 문장), 별도 기본 포트를 두면 그 문장과 관련 fixture·캠페인 문서를 전부 다시 써야 하는 breaking change다. 설계의 개념 모델도 listener를 중계기가 아니라 공인 도달 가능해야 하는 client 머신으로 규정하고 있어 이 대안과 맞지 않는다. 포트를 분리해도 한 장비에서 둘 다 띄우면 충돌한다는 실질 문제는 그대로 남고 문서만 늘어난다.
- 읽을 때 `trust.toml`/`hosts.toml`을 다시 써서 포트를 박아 넣는다. 기각한다. `hosts.toml`은 `docs/CLI.md` §6.1이 이미 "read-only 디렉터리"로 규정했고 이를 쓰는 CLI 명령은 없다는 것이 계약이다. `trust.toml`은 매 handshake마다 다시 읽는다는 성질(§6.11의 "trust remove"·"trust invite 재로드" 문단)이 있는 파일이라, 읽는 프로세스가 그 파일에 쓰기 경합까지 일으키면 사람이 손으로 관리하는 파일에 프로세스가 예고 없이 개입하는 꼴이 된다. 파생값만 정규화하는 쪽이 "파일은 사람이 관리한다"는 기존 원칙과 부딪히지 않는다.
- `serve --to`가 `host:port` 형태로 보이면 무조건 그 리터럴로 직접 dial하고 trust 조회를 생략한다. 기각한다. 이러면 pinned peer 없이도 임의 주소로 dial을 시도하는 새 미핀 dial 표면이 생겨 §6.1·§6.8이 세운 이름 해석 규칙과 어긋나고, 네트워크 왕복 전에 실패해야 한다는 fail fast 원칙도 잃는다. `serve --to`가 `qsh trust accept`처럼 새 pin을 만드는 명령이 아니라 이미 pin된 상대에게 접속하는 명령이라는 성격과도 어긋난다.
