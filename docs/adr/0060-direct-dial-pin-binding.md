# ADR-0060: client가 이름으로 dial하는 연결은 그 이름의 pin이 가진 키와 정확히 같은 서버만 받는다. pin이 없는 이름은 CA 경로의 서버만 받고, 다른 이름의 pin으로는 받지 않는다

날짜: 2026-11-11
상태: 승인됨

개정 관계: 다음을 고친다. 모두 "client가 서버를 믿는 기준"이 trust store 전체라는 서술이다.
- `docs/design/protocol.md` §3의 검증 코어 1번 "leaf fingerprint가 로컬 trust store에 pin되어 있으면 허용". 이 규칙은 server가 client를 받을 때(어느 pin이든 받는다)와 client가 이름 없이 확인할 때에 그대로 맞고, client가 **이름을 대고** dial하는 연결에는 이 ADR의 결정 1이 더해진다.
- `docs/design/threat-model.md` A21의 "지금의 직접 dial은 trust store 어딘가에 pin된 상대면 TLS 단계에서 받는다"는 전제.
- `ops/mod.rs`의 `resolve_peer_address` 문서가 말하는 "`hosts.toml`이 주소만 바꾸고 누가 답할 수 있는지는 바꾸지 않는다(fingerprint는 trust 전체에서 찾는다)".

ADR-0056 결정 10(jump의 단마다 그 이름의 pin과 fingerprint가 정확히 같을 때만 선다)은 그대로다. 이 ADR은 직접 경로가 그 결정과 같은 규칙을 따르게 한다.

## 맥락

2026-11-11에 qsh 0.4.3으로 재현했다(에이전트 감사).

- client C가 세 pin을 둔다. `ctl` = A의 키와 A의 주소, `other` = B의 키와 B의 주소, `mm` = **A의 키와 B의 주소**. A와 B는 모두 C를 pin한다.
- `qsh exec mm -- sh -c '…'`가 `ok: true`로 B에서 돌았다. B의 감사에는 `device:c`, `exec.run`, `allow`, `auth_path pin`이 남았다. B의 디렉터리에 표지 파일이 생겼다.
- B의 인증서가 C의 store 어디에도 pin되지 않았을 때는 같은 명령이 `AUTH_FAILED`/`untrusted`로 거절된다. 막히는 이유는 "`mm`의 pin과 다르다"가 아니라 "어디에도 pin되지 않았다"이다.

원인은 한 곳이다. `QshPeerVerifier::verify_core`(`crates/qsh-transport/src/tls.rs`)는 "이 fingerprint가 store에 있는가, 아니면 CA 체인이 맞는가"만 묻는다. client가 어느 이름으로 dial했는지는 verifier에 닿지 않는다. 호출 쪽도 `PeerTarget { trust: Arc<SharedTrustStore> }`(`crates/qsh-core/src/ops/mod.rs`)로 store 전체를 넘기고, `direct_dial`(`ops/route.rs`)과 `ops/exec.rs`의 dialer, 마지막 재검증인 `finish_dial`(`crates/qsh-transport/src/endpoint.rs`)도 모두 같은 store로 판정한다. 이름의 pin과 제시된 fingerprint를 견주는 코드가 직접 dial 경로에 없다.

이름에 결속된 경로는 이미 있다.

- jump 체인: 단마다 `StaticTrust`에 그 단의 pin 하나만 넣어 안쪽 연결을 올린다. 첫 hop은 handshake 뒤에 `plan.step(0).fingerprint`와 견준다(ADR-0056 결정 10, 위협 A24, `a_jump_redirect_to_another_pinned_peer_fails_with_auth_failed`).
- 펀칭: `dial`이 `expected_peer`를 받고 다르면 `CLOSE_CODE_UNVERIFIED_PEER`로 닫는다(ADR-0054 결정 12, 위협 A21).
- 감독 터널의 재dial: `params.fingerprint`와 견준다.
- `qsh pair ssh`의 확인 dial: 기대 fingerprint와 견준다.

직접 dial만 빠져 있다. 이 구멍의 효과는 신원 오인이다. 사용자가 A에서 실행한다고 믿은 명령(비밀을 담은 stdin, `cp`로 보낸 파일, `-L` 터널의 상대)이 C가 pin한 다른 장비에서 실행된다. 이름을 `hosts.toml`의 주소 재정의로 다른 장비에 돌리거나 `trust.toml`의 주소 한 칸을 바꾸는 것으로 일어난다. 인증 자체가 뚫린 것은 아니다(B는 C가 pin한 장비다). 그러나 pin의 의미가 "이 이름은 이 키"인데 지켜지지 않는다.

## 결정

1. **이름을 댄 dial은 그 이름의 pin이 가진 SPKI fingerprint와 정확히 같은 leaf만 받는다.** 판정은 TLS handshake 안의 인증서 검증이다. 다르면 client는 서버 인증서를 받아들이지 않고 alert를 보내므로 client 인증서도 전달되지 않고 스트림은 하나도 생기지 않는다. 이름의 pin이 아닌 다른 pin(store 안 어디에 있든), CA 체인, 열린 pairing invite는 이 연결을 받아 주지 않는다.
2. **적용 범위.** client가 pin의 이름으로 하는 모든 직접 dial이다.
   - `exec`, `session open`, `attach`, `cp`, `capabilities`, `tunnel open`(감독 재dial 포함), 대화형 `qsh [user@]host`의 연결과 세션 복구 재dial.
   - `route`의 직접 dial 경로와 SSH 부트스트랩 부활(`revive_target`)이 만든 대상. 부활은 pin의 fingerprint를 그대로 쓰고 주소만 바꾼다.
   - `qsh serve --to <controller>`의 등록 dial. 컨트롤러의 pin 키만 받는다. 어긋나면 지금처럼 `tls_rejected`다.
   - 시뮬레이션 네트워크의 직접 dial(시험용)은 펀칭이 기대하는 키(`PunchPlan.target`)로 묶는다.
3. **CA 모드.**
   - pin이 있는 이름은 CA와 무관하게 **키로** 묶는다. fingerprint는 SPKI의 SHA-256이라(`Fingerprint::of_cert_der`) 서버가 `qsh cert issue`로 인증서를 CA 서명본으로 바꿔도 키가 같으면 fingerprint도 같다(ADR-0008 결정 6). 그래서 CA 승격은 pin을 깨지 않는다. 서버가 **새 키**를 CA로 서명받아 내놓으면 pin과 다른 키이므로 거절한다. 이는 pin의 정의이고 이름이 가리키는 장비가 바뀐 것이니 `qsh pair ssh --replace-pin` 등 pin을 바꾸는 정해진 길로 갱신한다.
   - pin이 없는 이름(`hosts.toml`에만 있는 이름, `trust add-ca`만 믿는 컨트롤러)은 **CA 체인이 검증되는 leaf만** 받는다. 이 이름에는 묶을 키가 없으므로 신뢰 근거가 CA 하나뿐이다. 다른 이름의 pin이 이 이름을 받아 주지 않는다. 지금까지는 받았다.
   - CA 경로의 leaf SAN(`qsh://device/<id>`)을 로컬 이름과 견주지는 않는다. `hosts.toml`의 이름은 로컬 별칭이고 장비의 `device_id`와 같을 이유가 없어서, 견주면 정상 구성이 깨진다. 이 경로의 신원 근거는 지금처럼 CA다.
   - 이름이 `trust.toml`에 있는데 fingerprint를 읽을 수 없으면 `CONFIG_ERROR`다. pin 없는 이름으로 취급해 받아 주는 범위를 넓히지 않는다.
4. **오류.** 새 `ErrorCode`도, 새 JSON 필드도 없다. 거절은 `AUTH_FAILED`이고 `details.category`는 `untrusted`다. 이미 "서버 인증서가 믿을 수 없다"는 모든 거절이 같은 모양으로 쓴다(`docs/CLI.md` §6.11의 오류 목록, 고정 fixture `error.AUTH_FAILED.json`의 `category` 모양과 같다). jump 체인은 단 번호가 있어서 `details.jump`와 `jump N/M (name):` 메시지를 쓰는데(ADR-0056 결정 12), 직접 dial에는 단이 없으므로 그 필드를 만들지 않는다. 그래서 fixture는 더하지 않는다(append-only 규칙에 걸리는 변경이 없다). 사람용 메시지는 그대로 "peer authentication failed (mutual TLS)"다.
5. **server 쪽 검증은 그대로다.** server는 자기에게 접속하는 client의 키가 store에 있거나 CA에 맞으면 받는다. 어느 이름으로 불렸는지가 server에는 없고, 무엇을 허용하는지는 ACL이 정한다.
6. **jump와 진단 dial은 바꾸지 않는다.** jump 대상(`PeerTarget.binding = None`)은 단마다 자기 pin을 견주므로 두 번 결속하지 않는다. `qsh pair ssh`의 확인 dial은 기존 사후 비교를 유지한다. `ops/probe.rs`(빈 store로 지문만 읽는다)와 pairing redeem의 `AcceptAnyForPairing`은 이름의 pin이 없는 dial이라 대상이 아니다.
7. **구현 위치.**
   - `qsh-transport`: `PeerBinding`(`Pin(Fingerprint)` / `CaOnly`)과, 안쪽 `TrustEvaluator`를 그 결속으로 좁히는 `BoundTrust`. `Dialer::bound_to`, `PunchEndpoint::dial_trusted_bound`. verifier는 바꾸지 않고 evaluator만 좁힌다. 그래서 handshake와 `finish_dial`의 재검증이 같은 규칙을 쓴다.
   - `qsh-core`: `PeerTarget.binding`을 `resolve_peer`, `resolve_exec_route`, `punch_only_target`, 부활 대상이 채우고 `PeerTarget::evaluator()`가 모든 dialer 생성에 쓰인다. 이름 → 결속은 `ops::peer_binding` 한 함수다. `qsh-cli`는 바뀌지 않는다.
8. **한 번 정한 결속.** 결속은 명령이 시작할 때 `trust.toml`에서 정한다. 오래 사는 감독 터널·세션 복구 중에 그 pin이 교체되면 재dial은 옛 키로 묶여 거절되고(fail closed) 명령을 다시 시작해야 새 pin을 쓴다. 감독 터널은 이미 첫 연결의 fingerprint와 견주고 있어서 같은 결과다.

## 대안

- **TLS를 지금대로 두고 handshake 뒤에 `peer_fingerprint()`를 견준다**(펀칭·jump 첫 hop 방식). 기각. 틀린 서버에 client 인증서가 이미 갔고 server 쪽 감사에 `handshake`가 allow로 남을 수 있으며, 호출 위치마다 비교를 빠뜨릴 수 있다(이번 결함이 정확히 그것이다). evaluator를 좁히면 dialer를 만드는 곳이 규칙을 지킨다.
- **verifier에 `server_name`으로 이름을 넘긴다.** 기각. SNI/서버 이름은 검증에 쓰지 않는다는 결정(ADR-0040 결정 2, protocol.md §3)이고, 이름 → pin 해석은 core의 일이라 transport가 trust.toml을 알게 된다.
- **pin 없는 이름을 거부한다**(`HOST_NOT_FOUND`처럼). 기각. CA 모드의 `hosts.toml` 이름이 지금 동작하고, 그 신뢰 근거는 CA다.
- **pin이 있는 이름도 CA 체인을 허용한다**(키가 달라도 CA가 서명했으면 받는다). 기각. 한 CA가 서명한 모든 장비가 서로의 이름을 가장하게 되어 이번 결함과 같은 모양이 CA 안에서 남는다. 키를 갈아 끼우는 정해진 길이 있다.
- **SAN의 device_id를 로컬 별칭과 견준다.** 기각(결정 3).

## 근거

- pin은 "이 이름은 이 키"라는 약속이다. 감사한 결과 약속이 jump·펀칭·감독 터널에는 지켜지고 가장 흔한 경로에서만 안 지켜졌다. 같은 규칙으로 맞춘다.
- evaluator를 좁히는 방식은 호출 위치가 하나(`PeerTarget::evaluator()`)라서 새 명령이 store 전체를 직접 넘기는 일을 구조로 막는다.
- 틀린 장비에 client 인증서를 보내기 전에 끊으므로 그 장비의 감사에 allow가 남지 않는다.
- CA 승격이 키를 바꾸지 않으므로 CA 모드 사용자의 pin이 깨지지 않는다.

## 결과

- 동작이 바뀌는 곳: (a) 이름과 주소가 다른 pin을 가리키던 구성은 `AUTH_FAILED`가 된다. 이 구성이 의도였다면(별칭으로 다른 장비에 붙기) pin을 그 장비의 키로 다시 만든다. (b) pin이 있는 이름의 서버가 키를 바꾸면 CA 서명이든 다른 이름의 pin이든 거절된다. (c) `hosts.toml`에만 있는 이름이 CA가 아닌 pin으로 믿던 서버를 가리키면 거절된다.
- 잔여 위험: CA에 맞는 이름에서는 그 CA가 서명한 어느 장비든 답할 수 있다(CA를 믿는다는 뜻이다. threat-model h3·h24의 CA 위험과 같은 뿌리). 결속은 이름 → 키이며 키 → 사람이 아니다.
- 크기: 0.5ew 안팎(transport 두 메서드, core의 결속 한 필드와 한 함수, 시험).

## DoD

1. `a_name_pinned_to_one_host_never_reaches_another_pinned_host`(`crates/qsh-testkit/tests/it/direct_pin.rs`): 실제 서버 둘, B를 `other`로도 pin하고 `mm` = A의 키 + B의 주소일 때 `exec`, `session open`, `capabilities`, `tunnel open`, `cp`(보내기·받기)가 모두 `AUTH_FAILED`/`untrusted`이고 B와 A의 감사에 allow가 없으며 세션이 없고 파일이 생기지 않는다.
2. `a_correct_pin_still_connects_and_the_refused_host_would_have_served`: 올바른 pin은 그대로 붙고, 같은 B가 자기 이름으로는 서비스한다(거절이 B의 거부가 아니라 pin 때문임).
3. `a_name_without_a_pin_is_reached_through_the_ca_and_not_through_a_pin`: CA 서명 서버가 `hosts.toml`에만 있는 이름으로 붙고, pin된 자체 서명 서버는 pin 없는 이름으로 거절되며, CA leaf를 그 키로 pin한 이름도 붙는다.
4. `a_bound_dial_accepts_only_the_peer_it_names`, `a_dial_bound_to_the_ca_reaches_a_ca_leaf_and_a_pin_does_not_follow_a_new_key`(`crates/qsh-transport/src/endpoint/tests.rs`): `Dialer::bound_to`의 `Pin`/`CaOnly`, 열린 pairing invite가 결속을 풀지 않음, 거절된 키가 `observed`에 실림.
5. `dial_and_register_refuses_a_pinned_stranger_at_the_controllers_address`(`crates/qsh-core/src/reverse/target/tests.rs`): `serve --to`의 등록 dial이 컨트롤러 주소의 다른 pin 서버를 `tls_rejected`로 거절하고, 그 서버를 자기 이름으로 부르면 TLS는 통과한다.
6. 기존 jump 시험(`jump_pin_mismatch_at_the_first_hop`, `a_jump_redirect_to_another_pinned_peer_fails_with_auth_failed`)과 펀칭 시험(`punch_never_adopts_a_trusted_stranger`)이 그대로 초록이다.
7. `docs/design/protocol.md` §3, `docs/design/threat-model.md` A25·A21·h62, `docs/CLI.md` §6.11을 이 ADR에 맞춘다. 워크스페이스 게이트 일곱 가지가 초록이다.

## 개정 이력

- 2026-11-11 Dave가 "ADR + 먼저 고친다"로 정했고 같은 날 승인했다(에이전트가 쓴 초안, 감사 재현은 qsh 0.4.3).
