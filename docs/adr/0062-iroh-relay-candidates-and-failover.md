# ADR-0062: iroh relay는 후보 목록으로 두고, 쓰던 relay가 죽으면 다른 후보로 알아서 옮긴다. 발견은 계속 끈다

날짜: 2026-11-13
상태: 승인됨 (2026-11-13 Dave 결정. "후보 릴레이에 모든 릴레이를 적어두는게 좋겠어. 매번 자동 복구되게.")

개정 관계: ADR-0061 결정 11의 "endpoint는 지연으로 home relay를 고르지 않고, 설정된 relay URL 하나에 고정으로 붙는다. 기본값은 n0 공용 relay 가운데 한 URL"만 고친다. 같은 결정의 나머지(발견 게시·조회 끔, 상대의 relay는 그 pin에 적고 없으면 기본값을 쓴다, 양 끝이 같은 기본값을 쓰면 pin에 relay URL을 적지 않아도 닿는다)와 ADR-0061의 다른 결정은 그대로다. 결정 10(기본 relay는 n0 공용 relay)과 12(relay TLS는 OS 인증서 저장소)도 그대로다.

## 맥락

2026-11-13에 기본 relay `https://aps1-1.relay.n0.iroh.link`가 내려갔다(TCP 연결 거절). qsh는 ADR-0061 결정 11에 따라 relay URL 하나만 쥐고 있어서, 이 장비의 `serve`·`listen`은 home relay를 잃고 클라이언트는 죽은 relay로만 dial했다. iroh relay를 쓰는 qsh 링크가 전부 끊겼다. 같은 시각에 n0의 다른 relay(`usw1-1`, `use1-1`, `euc1-1`)는 멀쩡했다.

iroh 1.4.1은 relay 여럿을 담은 `RelayMap`을 받으면 스스로 home relay를 고르고 옮긴다(발견 없이도 된다).
- net report가 맵에 든 relay를 모두 잰다(QUIC 주소 발견 probe와 HTTPS probe). 응답이 온 relay만 지연표에 오르고, 그중 최근 5분 지연이 가장 낮은 것이 `preferred_relay`다. 옛 home이 아직 답하고 새 후보가 지연의 2/3 이하일 때만 옮기는 hysteresis가 있다(`iroh-1.4.1/src/net_report.rs` `add_report_history_and_set_preferred_relay`, 748~820행).
- report가 새 `preferred_relay`를 내면 relay actor가 home을 바꾼다(`src/socket/transports/relay/actor.rs` `on_network_change`, 1232~1257행). 죽은 relay는 지연표에 없으므로 고를 수 없다.
- report는 20~26초마다 돈다(`src/socket.rs` `new_re_stun_timer`, 2017~2021행). relay 맵이 바뀌면 곧바로 돈다(`handle_relay_map_change`, 1762행).
- 상대에게 dial할 때는 `EndpointAddr`의 모든 relay 주소로 첫 패킷(QUIC Initial)을 동시에 보낸다(`src/socket/remote_map/remote_state.rs` `send_datagram_to_targets`, 1162~1180행. 느린 relay가 다른 대상을 막지 않는 시험이 같은 파일 1575행 이하에 있다). `EndpointAddr`는 relay 주소를 여럿 가질 수 있다(`iroh-base` `EndpointAddr::addrs`는 집합이고 `with_relay_url`이 하나씩 더한다).

## 결정

1. **relay는 후보 목록이다.** endpoint는 설정된 후보 relay URL을 모두 `RelayMap`에 넣고(`RelayMode::Custom`), 맵에는 그 밖의 relay를 넣지 않는다. iroh가 응답한 후보 가운데 지연이 가장 낮은 것을 home으로 고르고, home이 응답하지 않으면 다른 후보로 옮긴다. 발견(pkarr, DNS)은 계속 끈다. 후보는 설정에서만 온다.
2. **설정.** `[iroh].relay_url`은 문자열 하나 또는 문자열 배열을 받는다. 문자열 하나는 지금까지와 같고, 그 relay 하나가 유일한 후보다(실패 시 옮길 곳이 없다). 배열은 후보 목록이다. 비어 있거나, https URL이 아닌 원소가 있거나, 후보가 8개를 넘으면 `CONFIG_ERROR`(`retryable: false`)다. 같은 relay를 두 번 적으면(끝의 `/`나 `.`, 대소문자만 다른 경우 포함) 하나로 본다. `qsh config set iroh.relay_url`은 쉼표나 공백으로 구분한 여러 값을 배열로 쓰고, 값 하나는 문자열로 쓴다. 별도 키(`relay_urls`)는 두지 않는다. 한 키에 두 표기가 겹칠 일이 없어서 "둘 다 설정" 같은 충돌 규칙이 필요 없다.
3. **기본값은 n0 공용 relay 넷이다.** 설정이 없으면 `aps1-1`, `usw1-1`, `use1-1`, `euc1-1`의 `.relay.n0.iroh.link`를 모두 후보로 쓴다. 양 끝이 같은 기본값을 쓰면 pin에 relay를 적지 않아도 어느 relay에서든 만난다. 결정 10의 속도 제한·조건 변경 경고는 그대로 넷 모두에 해당한다.
4. **pin의 `relay`는 그대로 한 URL이다.** `trust iroh --relay <url>`은 그 호스트가 붙어 있는 relay 하나를 이름으로 지정하는 것이라 후보 목록으로 넓히지 않는다. pin에 `relay`가 있으면 그 pin으로 가는 dial은 그 relay 하나만 쓰고 장애 시 옮기지 않는다. 장애 복구가 필요한 pin은 `relay`를 비워 두어 장비의 후보 목록을 쓴다. pin의 `relay`를 목록으로 넓히는 것은 `qsh.cli/v1`의 필드 타입을 바꾸므로 하지 않는다(필요하면 새 선택 필드를 더하는 별도 결정으로 한다).
5. **dial은 후보를 모두 싣는다.** 클라이언트 endpoint는 후보 전체를 자기 `RelayMap`에 넣고, dial 대상의 `EndpointAddr`에도 후보를 모두 넣는다. 첫 패킷이 모든 후보로 동시에 나가므로 상대가 어느 후보에 붙어 있든 handshake가 서고, 죽었거나 대답 없는 후보는 자기 큐만 막을 뿐 dial 시간을 쓰지 않는다. 추가 경주 예산은 없다. 직결·펀칭·iroh를 경주시키는 `ops/route.rs`의 시한 계산도 그대로다.
6. **데몬은 home이 죽으면 바로 재선택을 요청한다.** iroh가 스스로 옮기기를 기다리면 report 주기(20~26초)에 묶이고, 실측에서는 20초 안에 옮기지 못했다. 데몬 endpoint는 `home_relay_status()`를 지켜보다가 연결된 home이 3초 동안 없으면 relay 맵을 다시 넣어 iroh에 전체 net report를 요청하고(맵 변경은 즉시 report를 시작한다), home이 생길 때까지 10초마다 되풀이한다. 요청만 하고 고르는 것은 iroh다. 클라이언트 endpoint는 수명이 짧아 이 감시를 두지 않는다.
7. **`details.iroh.reason`의 `relay_unreachable`은 후보를 하나도 못 쓸 때만이다.** 연결이 서지 못했을 때 후보 relay를 모두 한꺼번에(한 번의 시한 안에) 밖에서 점검한다. 하나라도 통과하면 relay 쪽 실패가 아니므로 `reason`을 싣지 않는다. 모두 실패했는데 접속은 되고 TLS나 WebSocket 단계에서 실패한 후보가 있으면 그 단계의 `reason`(`relay_tls`, `relay_upgrade`)이 우선하고, 어느 후보에도 접속하지 못했을 때만 `relay_unreachable`이다.
8. **`serve.json`.** `iroh` 객체에 선택 필드 `relays`(후보 URL 배열)를 더한다. 기존 `relay`는 기록 시점의 home relay이고, 아직 고르지 않았으면 첫 후보다.

## 결과

- 후보 하나가 내려가도 데몬은 몇 초 안에 다른 후보로 옮기고(시험에서 약 3초), 클라이언트의 새 dial과 복구 재dial이 그 relay로 닿는다. 설정을 바꾸거나 재시작할 필요가 없다.
- 클라이언트 dial은 후보 수만큼 relay에 접속한다(기본 넷). 기업망 로그에 n0 relay 넷이 보인다. relay를 하나로 줄이려면 `[iroh].relay_url`을 문자열 하나로 둔다.
- 자가 운영 relay를 쓰는 사용자는 `relay_url`을 그대로 두면 된다. 자가 운영 relay와 n0 relay를 함께 후보로 두려면 배열로 적는다. 후보 사이에서 home은 지연으로 고르므로 자가 운영 relay를 우선하는 설정은 없다.
- 데몬이 붙은 relay가 죽은 사이에 도착한 첫 패킷은 사라진다. QUIC 재전송이 데몬이 옮긴 뒤 다시 모든 후보로 나가므로 dial은 옮겨 가는 시간만큼 늦게 선다. 이미 선 연결이 relay 경로를 잃은 뒤 어떻게 끝나는지는 iroh의 경로 관리와 qsh의 유휴 시한(45초)·복구 감시를 따르고 이 ADR이 바꾸지 않는다. 연결이 끝나면 복구 재dial이 후보를 모두 실어 새 home으로 닿는다.
- relay 지연 측정과 home 선택은 iroh의 hysteresis를 따른다. 후보 지연이 비슷하면 옮기지 않고, 옮기는 순간에 이어진 연결은 새 home에서 다시 서야 한다.

## 기각한 대안

- **`relay_urls` 별도 키.** `relay_url`과 동시에 설정하면 충돌 규칙이 필요하고, `qsh config`의 키 등록과 "모든 키는 설정 가능" 시험이 두 키의 동시 설정을 가정한다. 한 키가 두 표기를 받는 쪽이 더 작다.
- **pin의 `relay`를 배열로.** `qsh.cli/v1`의 필드 타입 변경이다(결정 4).
- **발견을 켜서 상대의 home relay를 조회.** 결정 11의 "제3자에게 아무것도 게시하지 않는다"를 깬다. 후보를 모두 싣는 dial이면 조회가 필요 없다.
- **클라이언트가 먼저 relay 하나를 골라 dial.** 후보를 순서대로 시도하면 죽은 relay마다 시한이 든다. 모두 싣는 쪽은 추가 시간이 없다.
