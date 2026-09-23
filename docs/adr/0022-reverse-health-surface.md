# ADR-0022: 역방향 등록 health는 `Host.lost_at`과 `qsh::reverse` 진단 줄까지로 두고, push 계약 표면은 필요가 관측된 뒤에 `qsh.event/v1`에 additive로 연다

날짜: 2026-09-24
상태: 제안됨

개정 관계: 대체하는 ADR은 없다. `docs/CLI.md` §5의 `Host` 타입과 §6.1을 §10의 additive 규율 안에서 넓히는 것이 전부다. 터널 쪽 판단은 ADR-0018을 재확인한다.

## 맥락

이슈 #4 item 3b가 묻는 것은 하나다. 역방향 등록이 끊겼다는 사실을 기계가 읽을 수 있는 표면으로 내야 하는가.

오늘 그 사실을 아는 곳은 controller의 registry다. `ReverseEntry.stale_since`가 있고(`crates/qsh-core/src/reverse/registry.rs`), `Registry::mark_stale`이 `EntryState::Live`를 `EntryState::Stale`로 옮기면서 그 값을 찍는다. `Registry::sweep_expired`가 `[listen].stale_retention`이 지난 항목만 걷어간다. 그 설정값은 `ListenConfig::stale_retention`(`crates/qsh-core/src/config.rs`)이 검증한다. 기본 120초이고 `[reverse].backoff_max_ms`의 3배를 넘어야 한다는 제약을 진다(`docs/design/protocol.md` §11-4).

그 값이 밖으로 나가는 길이 지금은 없다. `to_local_host`(`crates/qsh-core/src/localctl/daemon.rs`)가 `ReverseEntry`를 `LocalHost`로 옮길 때 `registered_at`만 싣고 잃은 시각은 버린다. `LocalHost`는 `crates/qsh-proto/proto/qsh/local/v1.proto`의 메시지이고 그 축은 `docs/design/protocol.md` §16.3이 wire freeze 밖으로 명시했다(`LOCAL_HELLO_VERSION`, `crates/qsh-proto/src/local.rs`). 필드를 더하는 데는 freeze가 걸리지 않는다.

그래서 기계 소비자가 오늘 볼 수 있는 것은 둘이다.

- 폴링. `qsh hosts --json`(`host.list`, `crates/qsh-core/src/ops/host.rs`의 `HostListOp`)이 `Host.state`를 `"reachable"`/`"stale"`/`"unknown"` 중 하나로 준다(`docs/CLI.md` §5, §6.1). live 역방향 등록은 `"reachable"`, 죽은 등록은 보존 창 동안 `"stale"`이다. 언제 죽었는지는 없다.
- push. controller의 `registered`/`denied`/`replaced`/`lost`/`expired` 줄과 target의 `retry` 줄이 tracing target `qsh::reverse`로 stderr에 한 줄 JSON씩 나간다(`crates/qsh-core/src/reverse/listen.rs`의 `TARGET`과 `RegistrationEvent`, `crates/qsh-core/src/reverse/target.rs`의 `ReconnectEvent`). 이 줄은 계약이 아니라 진단이다(`docs/CLI.md` §6.13).

이 ADR이 baseline으로 깔고 가는 것 둘은 이슈 #4의 다른 항목이 구현한다. `Host`에 additive-optional `lost_at`을 더하는 것이 이슈 #4의 다른 항목의 몫이고(`crates/qsh-proto/src/types.rs`의 `Host`, `source`/`user`와 같은 생략 규율), `qsh::reverse` 줄에 `cause`와 `at`을 더하는 것이 item 6의 몫이다. 둘 다 `docs/CLI.md` §10의 additive 규율 안에 있고 새 `/v2`를 부르지 않는다. 남는 질문은 그 위에 무엇을 더 두느냐다.

판단을 가르는 사실이 하나 더 있다. `qsh.event/v1`의 type은 오늘 정확히 다섯이고 전부 `session.*`이다(`crates/qsh-proto/src/event.rs`의 `KNOWN_EVENT_TYPES`). 다섯 모두 `session_ref`를 필수 필드로 갖고 그 봉투를 실어 나르는 유일한 표면은 `session.read --follow`다(`docs/CLI.md` §6.4). `reverse.*` type은 `session_ref`가 없으므로 붙을 자리가 없다. 내장 MCP 어댑터가 ADR-0011로 사라진 뒤 에이전트가 보는 면은 JSON/JSONL CLI 하나뿐이라, "supervisor가 무엇을 읽는가"는 곧 이 표면을 어떻게 낼 것인가와 같은 질문이 된다.

## 결정

1. 최소 표면을 `Host.lost_at`으로 확정한다. 이 값은 stale 상태인 역방향 host에만 나타나고 그 밖에는 키 자체가 없다(`null`이 아니다). `last_seen_at`은 두지 않는다. live 등록에 대해 그 값은 언제나 "지금"이고 stale 등록에 대해서는 `lost_at`과 같은 시각이라 새로 알려주는 것이 없다. `registered_at`이 이미 RFC 3339 절대 시각이라 같은 축에 맞추려고 절대 시각을 낸다.

2. 그 위에는 지금 아무것도 두지 않는다. 기계 소비자의 경로는 `qsh hosts --json` 폴링과 `qsh::reverse` stderr 줄 둘로 충분하다고 본다. `qsh.event/v1` 확장도 신규 local op도 이번에는 열지 않는다.

3. `qsh.event/v1`에 `reverse.*` type을 더하는 것을 예비 경로로 지정한다. 여는 조건은 관측이다. supervisor가 폴링 주기 안에 놓치는 전이를 실제로 보고하거나 `qsh::reverse` stderr를 읽을 수 없는 배치가 나오면 연다. 열 때 더하는 type은 `reverse.registered`, `reverse.lost`, `reverse.expired` 셋이다. `docs/CLI.md` §10이 새 type 추가를 허용하며 소비자는 미지 type을 무시해야 한다(`SessionEvent::Unknown`이 그 규율의 구현이다). 선행 조건은 carrier다. 그 봉투를 실어 나를 follow 표면을 같이 만들지 않으면 `KNOWN_EVENT_TYPES`에 아무도 발화하지 않는 문자열만 늘어난다.

4. 어떤 표면이 되든 인가 불요 local operation으로 둔다(`docs/CLI.md` §2.5 마지막 행의 부류). 원격 peer가 부를 수 있는 op으로는 만들지 않는다. 원격에서 등록 상태를 조회할 수 있으면 그 응답 자체가 capability 열거 oracle이 된다. `acl.check`를 local-only로 못박은 것과 같은 이유이고(`docs/CLI.md` §6.15, `docs/ROADMAP.md` M5 감사 개정 ③), 등록 목록의 정찰 값은 정책 조회보다 낮지 않다. 이 controller에 어느 이름이 등록돼 있는지와 어느 target이 지금 살아 있는지를 그대로 알려주기 때문이다.

5. `qsh::reverse` 줄이 계약이 아님을 재확인한다(`docs/CLI.md` §6.13). 그 줄의 field set은 진단 어휘이고 자유롭게 늘어난다. 이슈 #4 item 6이 `cause`와 `at`을 더하는 것도 그 자유 안에 있다. 이 ADR은 그 줄을 `qsh.cli/v1`으로 승격하지 않는다. 그 줄의 field 이름에 의존하는 소비자는 계약 소비자가 아니라 진단 소비자다.

6. 어떤 표면도 payload, 토큰, 주소 원문을 싣지 않는다. `lost_at`은 RFC 3339 시각이고 `cause`는 고정 어휘의 static string이다. peer가 보낸 오류 본문이나 해석된 IP는 어디에도 나가지 않는다. `RegistrationEvent`와 `ReconnectEvent`가 오늘 지키는 구조 전용 규율을 그대로 잇고 그 규율의 정본은 audit 레코드 쪽에 있다(`docs/design/architecture.md` §6).

7. 터널 forwarding health는 이 ADR의 범위 밖이다. 이슈 #4 item 3b가 역방향 등록과 터널을 한 문장으로 묶어 물었지만 터널 쪽 답은 ADR-0018이 이미 냈다. 터널 수명은 QUIC connection에 결합하고 connection이 죽으면 등록도 함께 죽으므로, "살아 있지만 아픈 터널"이라는 상태가 존재하지 않는다. 보고할 health가 없다는 뜻이고 `qsh tunnels`가 데몬이 실제로 쥔 터널만 보고한다는 규칙이 그대로 답이다(`docs/CLI.md` §6.9).

8. 마일스톤 배치는 현행 M9 범위 (a)~(k) 밖이다. 결정 3을 실제로 열게 되면 M10 이후나 P1으로 간다. baseline인 `lost_at`만 이슈 #4 작업으로 먼저 착지한다.

9. 이 ADR이 승인되면 이슈 #4 item 3b를 닫는다.

## 근거

이 도메인은 시간 상수가 커서 폴링이 이긴다. stale 표시에서 eviction까지가 기본 120초이고 그 값은 `[reverse].backoff_max_ms`의 3배를 넘어야 한다는 하한을 진다(`docs/design/protocol.md` §11-4). 초 단위로 도는 supervisor라면 어떤 전이도 놓치지 않는다. push가 폴링을 이기는 국면은 전이가 폴링 주기보다 빠를 때인데 여기는 그 국면이 아니다.

push가 아예 없는 것도 아니다. `qsh::reverse` 줄은 한 줄 JSON이고 supervisor는 stderr를 읽는다. 이슈 #4 item 6이 `cause`를 붙이면 그 줄만으로 언제 죽었는지와 왜 죽었는지가 둘 다 나온다. 새 계약 표면을 만들기 전에, 이미 있는 이 줄이 실제로 어디서 부족한지를 먼저 관측하는 편이 값싸다.

`qsh.event/v1`을 지금 넓히지 않는 실질적 이유는 carrier다. 다섯 type이 전부 `session_ref`를 갖고 `session.read --follow`에서만 나온다는 사실은 그 봉투가 세션 단위 스트림 위에 설계됐다는 뜻이다. `reverse.*`를 그 위에 얹을 수 없으므로 follow 표면을 하나 새로 만들어야 하고 그 순간 비용은 신규 local op을 만드는 것과 사실상 같아진다. type만 더하고 carrier를 미루면 어휘에 죽은 문자열이 남는다.

원격 조회는 값이 비대칭이어서 닫아 둔다. 운영자에게 이 값은 자기 머신에서 언제든 읽을 수 있는 로컬 사실이라 local-only로 둬도 잃는 것이 없다. 원격 호출자에게는 같은 값이 이 controller가 쥔 fleet 지도가 된다. 한쪽이 잃는 것 없이 다른 쪽에만 주지 않을 수 있으면 그렇게 한다.

## 대안

- 신규 local op(`qsh status`)을 만들어 등록 health를 전용 표면으로 낸다. 기각한다. 새 op 하나는 `docs/ROADMAP.md` M9 DoD가 요구하는 등록 완전성을 전부 갚아야 한다. 새 fixture와 `REQUIRED_FIXTURES` 등록(`crates/qsh-cli/tests/fixtures.rs`), schemars 타입, `cli_v1_data_schema` arm과 `CLI_V1_SCHEMA_COMMANDS` 등록(`crates/qsh-proto/src/schema.rs`), 렌더러 둘, `docs/CLI.md` 행, man 항목이다. 그렇게 갚고 돌려주는 값은 `host.list`가 이미 주는 값을 다시 배열한 것이다. `host.list`로 안 된다는 관측이 먼저 있어야 이 비용이 정당해진다.
- `Host.state`에 새 값(예: `"reconnecting"`)을 더한다. `state`는 열린 문자열이라 값 추가 자체는 additive지만(`docs/CLI.md` §10) 기각한다. controller는 target이 재시도 중인지 포기했는지 모른다. 재dial의 주체는 언제나 target이고 controller는 새 등록을 기다릴 뿐이다(`docs/design/protocol.md` §11-4). 관측하지 못한 상태를 보고하지 않는다는 규율은 forward host를 `"reachable"`로 적지 않는 §5의 판단과 같다.
- 등록 상태 조회를 원격 op으로 연다. 기각한다. 결정 4의 oracle 논거가 그대로 적용된다. 어느 이름이 지금 살아 있는지는 공격자에게 표적 목록이다.
- `qsh::reverse` 줄을 `qsh.cli/v1` 계약으로 승격한다. 기각한다. 승격하면 진단 field를 하나 더할 때마다 계약 심사가 붙고 이슈 #4 item 6이 정하려는 `cause` 어휘가 관측 경험이 쌓이기 전에 얼어붙는다. 진단은 자유롭게 늘어나는 편이 낫다.
- `Host`에 절대 시각 대신 `lost_ago_ms` 같은 상대값만 낸다. 기각한다. 폴링 소비자가 두 응답을 비교하려면 절대 시각이 있어야 하고 상대값은 그 응답이 만들어진 시각을 따로 알아야 복원된다. `registered_at`과 축을 맞추는 편이 소비자에게 단순하다.
- 터널별 health 표면을 이 작업에 함께 넣는다. 기각한다. ADR-0018이 터널 수명을 connection에 결합해 둔 이상 보고할 중간 상태가 없다.

## 결과

- 이 ADR이 승인돼도 바로 바뀌는 코드는 없다. `lost_at`과 `cause`/`at`은 이슈 #4의 별도 작업이 구현하고 이 ADR은 그 둘을 health 표면의 상한으로 승인한다.
- 문서 변경은 승인 시점에 이슈 #4 작업이 이미 하는 범위와 겹친다. `docs/CLI.md` §5와 §6.1이 `lost_at`을 서술하고 §6.13 bullet이 진단 어휘가 계약이 아님을 한 문장으로 못박는다. §10 자체는 바뀌지 않는다. 이 ADR은 그 규율 안에서 움직인다.
- `qsh.event/v1`은 다섯 type 그대로다. `KNOWN_EVENT_TYPES`와 `EVENT_SCHEMA`가 변하지 않으므로 그 쪽에서 오는 golden 재생성도 없다. `capabilities.json`은 `wire::LOCAL_CAPABILITIES`만 고정하는 fixture라 `Host`에 필드가 붙는 것과 무관하고 재생성되지 않는다. `host.list.json`·`host.get.json`도 새 필드가 `Option::is_none`이면 생략되는 규율 덕에 바이트 그대로다.
- 재검토 트리거를 명시해 둔다. supervisor가 폴링으로 놓친 전이를 보고하거나 `qsh service install`이 만든 unit처럼 stderr를 버리는 구성에서 역방향 health를 봐야 하는 요구가 나오면 결정 3을 연다. 그때는 event type 셋과 carrier 하나가 필요하다. carrier 비용을 세고 나서 신규 local op과 다시 비교한다.
- 잔여 위험은 셋이다.
  - R1. 폴링 주기가 `stale_retention`보다 길면 소비자는 `sweep_expired`가 걷어간 뒤에 보게 되어 그 등록이 있었다는 사실 자체를 놓친다. `qsh::reverse`의 `expired` 줄이 그 창을 메우지만 그 줄은 계약이 아니다.
  - R2. `lost_at`은 controller가 관측한 시각이지 target이 죽은 시각이 아니다. `Ping`/`Pong` 3-strike 판정이 끝난 뒤에 찍히므로 실제 사망보다 늦다(`docs/design/protocol.md` §11-4).
  - R3. 정방향 host의 health는 이 ADR로도 여전히 `"unknown"`이다. `host.list`는 dial하지 않기 때문이다(`docs/CLI.md` §6.1). 정방향 도달성 표면은 이 결정과 별개 문제로 남는다.
- 지금 여는 구현 작업이 없으므로 크기 추정을 두지 않는다. 결정 3을 열 때 event type 셋과 carrier 하나를 그 시점에 센다.
