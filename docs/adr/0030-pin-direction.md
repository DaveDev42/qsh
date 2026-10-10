# ADR-0030: pin에 방향 축(`direction = "both" | "outbound" | "inbound"`)을 더하고 handshake 역할로 pin 조회를 거른다. 필드가 없는 pin은 오늘처럼 양방향이고, 이 변경은 §16.2 검증 경로의 의미 변경이 아니라 로컬 trust 입력의 변경이다. TOFU는 열지 않는다

날짜: 2026-10-11
상태: 제안됨

개정 관계: ADR-0017 결정 5가 번호 없이 미룬 후속 ADR이 이 문서다. 결정 5의 결론(TOFU를 넣지 않는다)은 유지하고, 그 근거 중 "`trust.toml`이 방향을 구분하지 않는다"는 이 ADR 뒤로는 방향 필드가 없는 pin에만 맞는 문장이 된다. TOFU를 계속 닫아 두는 근거는 결정 9가 새로 적는다. ADR-0015 결정 7(listener 상대 pairing과 방향 축의 관계)이 입력으로 쓸 축을 이 ADR이 정한다. `docs/design/protocol.md` §3과 §16.2의 `QshPeerVerifier` 행에 해석 한 줄이 붙고(결정 8), `docs/CLI.md` §6.11·§6.17과 README "One machine, two aliases" 절이 바뀐다. 승인된 다른 ADR의 결정은 개정하지 않는다. ADR-0024 결정의 "같은 fingerprint의 두 번째 이름은 거절한다"(`setup_refuses_second_name_for_pinned_fingerprint`)도 그대로 둔다.

## 맥락

`QshPeerVerifier`(`crates/qsh-transport/src/tls.rs`)는 `ServerCertVerifier`와 `ClientCertVerifier`를 한 코어(`verify_core`)로 구현한다. 코어는 handshake 역할 `PeerRole`(`Server`: 내가 dial한 상대, `Client`: 나에게 dial한 상대)을 받지만 CA 경로의 `KeyUsage` 선택에만 쓰고, pin 조회 `TrustEvaluator::lookup_pin(&Fingerprint)`에는 넘기지 않는다. 그래서 `trust.toml`의 `[[peer]]` 하나는 이 장비가 그 상대에게 나갈 때와 그 상대가 이 장비로 들어올 때 똑같이 적용된다. ADR-0017 결정 5는 바로 이 사실 때문에 TOFU를 닫았다. client 쪽에서 자동으로 만든 pin이 같은 상대의 inbound 인증까지 열어 주기 때문이다.

이 구조가 오늘 만드는 문제는 셋이다.

- **outbound로만 쓸 pin이 inbound를 연다.** `pair accept`나 `trust add --address`로 host를 pin한 laptop이 나중에 `qsh serve`나 `qsh listen`을 띄우면, 그 host는 laptop으로 들어올 때도 같은 pin으로 인증을 통과한다. default-deny ACL이 인가를 막아도 handshake, admission, quota 예약, 페어링 창은 인증 통과만으로 열린다(ADR-0017 결정 5 첫 문단).
- **두 별칭 배치가 파일 순서에 묶인다(M11 (e)).** `SharedTrustStore::lookup_pin`(`crates/qsh-core/src/trust/mod.rs`)은 fingerprint가 같은 첫 항목을 돌려준다. 한 장비를 `workshop-lan`(직접 dial용, 주소 있음)과 `workshop`(역방향 등록용)으로 pin하면 inbound principal은 파일에서 앞선 이름 하나다. 뒤 이름을 겨눈 `[[acl]]` 행은 조용히 매칭되지 않는다. README "One machine, two aliases"는 이것을 "앞 이름에 ACL을 쓰고 뒤 이름은 outbound 별칭으로만 쓰라"는 처방으로 안내하고, `crates/qsh-cli/tests/trust_alias_order.rs`의 `an_acl_row_on_the_second_alias_denies_inbound_until_trust_toml_is_reordered`와 trust 단위 테스트 `lookup_pin_returns_the_first_name_pinned_for_a_shared_fingerprint`, `lookup_pin_follows_a_reordered_trust_toml_without_a_restart`가 그 동작을 고정한다. 같은 절 끝이 "방향으로 별칭을 가르는 일은 M16 계획"이라고 적는다.
- **ADR-0015 결정 7이 답을 기다린다.** listener 상대 pairing은 target이 outbound로만 쓰는 pin을 새로 만드는 경로라서, 방향 축 없이 결론을 내면 그 pin이 listener의 inbound 인증까지 연다.

설계를 가르는 사실은 이렇다.

- **역할은 TLS의 것뿐이다.** verifier가 아는 방향은 "누가 QUIC 연결을 열었는가" 하나다. 요청이 어느 쪽으로 흐르는지는 모른다. 역방향 구도(`docs/CLI.md` §6.13)에서 target(`qsh serve --to`)은 controller(`qsh listen`)에 dial한다. target에게 controller는 `PeerRole::Server`다. 그런데 그 연결 위에서 요청을 보내는 쪽은 controller이고, target의 ACL은 controller의 principal을 판정한다. 따라서 "outbound pin"은 "이 상대는 나에게 아무것도 요청하지 못한다"는 뜻이 될 수 없다. 뜻할 수 있는 것은 "이 상대가 나에게 dial해 오면 이 pin으로는 인증하지 않는다"까지다.
- **pin을 놓친 handshake는 다음 경로로 넘어간다.** pin 조회가 실패하면 코어는 CA 체인을 보고, 그것도 실패하면 `pairing_open()`이 참일 때만 `Principal::Pairing`으로 받는다(ADR-0008 결정 6의 pin > CA > pairing). 방향으로 pin을 놓친 상대도 이 순서를 그대로 탄다.
- **거부 범주는 audit에 남는다.** inbound handshake 거부는 `AuditRecord::handshake_rejected`가 `resource`에 범주를 적는다. 범주는 `RejectReason`의 `Debug` 이름을 소문자로 바꾼 값(`untrusted`, `expired`, `malformed`, `noprincipal`)이다(`crates/qsh-core/src/server/mod.rs`, `reverse/listen/registration.rs`). `RejectReason`은 일부러 거칠다. 원격 peer가 받는 것은 TLS alert뿐이고 trust store 내용을 새는 이유 문자열은 어디에도 실리지 않는다.
- **`trust.toml`은 매 handshake마다 다시 읽힌다.** `SharedTrustStore::refresh`가 파일 바이트를 비교한다. 해석에 실패하면 마지막 정상 스냅숏을 유지한다. 파싱되지 않는 fingerprint를 가진 `[[peer]]` 한 줄은 `parsed_pins`가 WARN과 함께 건너뛰고 나머지는 살린다("a corrupt line must never widen trust, and must not disable the rest of the store").
- **`TrustPeer`는 파일 모양이면서 JSON 계약 타입이다.** `crates/qsh-proto/src/types/trust.rs`의 `TrustPeer`가 `trust.toml`의 `[[peer]]`로도, `trust.add`/`trust.list`/`trust.remove`의 `data`로도 직렬화된다. `deny_unknown_fields`가 없어서 모르는 키는 읽을 때 무시되고 다시 쓸 때 사라진다.
- **§16.5는 "TLS 검증 경로(pin → CA → 거부)의 의미 변경"을 major bump 사유로 둔다.** §16은 아직 발효 전이다(§16.10). §16.5 목록의 다른 항목(필드 번호, frame 헤더, frame 상한, 0-RTT)은 모두 두 peer가 서로 다르게 이해하면 상호운용이 깨지는 것들이다.

## 결정

1. **필드.** `[[peer]]`에 선택 필드 `direction`을 더한다. 값은 `"both"`, `"outbound"`, `"inbound"` 셋이고 이 장비 기준이다.
   - `outbound`: 이 장비가 dial한 연결에서 상대가 제시한 leaf(`PeerRole::Server`)에만 pin으로 쓴다.
   - `inbound`: 상대가 이 장비로 dial한 연결에서 상대가 제시한 leaf(`PeerRole::Client`)에만 pin으로 쓴다.
   - `both` 또는 필드 없음: 두 역할 모두. 오늘의 의미다.

   방향은 QUIC 연결을 누가 열었는지만 말한다. 그 연결 위에서 상대가 무엇을 요청할 수 있는지는 여전히 `acl.toml`이 정한다. `qsh serve --to` target이 controller를 `outbound`로 pin해도 controller는 그 연결 위에서 target의 ACL이 허락하는 요청을 보낼 수 있다. 이 문장은 `docs/CLI.md` §6.11의 `direction` 설명에 그대로 들어간다.

2. **이행.** 필드가 없는 pin은 양방향으로 읽는다. 이 ADR 이전에 쓴 `trust.toml`은 이 ADR 이후에도 모든 handshake에서 오늘과 같은 판정(수용 여부, principal, `auth_path`)을 낸다. 기존 writer(`trust add`, `pair invite`/`pair accept`, `trust rename`, `cert issue`, `qsh setup`)는 `--direction`을 받지 않은 호출에서 필드를 쓰지 않는다. `both`를 명시적으로 받으면 그것도 필드를 지우는 것으로 저장한다. 그래서 방향을 쓰지 않는 사용자의 `trust.toml`은 바이트까지 오늘과 같고, `trust.list` 출력도 같다.

3. **조회.** `TrustEvaluator::lookup_pin`은 `PeerRole`을 받고 세 갈래를 돌려준다. 맞는 방향의 pin(`Match(Principal)`), 그 fingerprint의 pin이 있지만 모두 다른 방향인 경우(`OtherDirection`), pin 없음(`None`)이다. 기본 구현은 두지 않는다. 모든 구현체(`SharedTrustStore`, `StaticTrust`, 테스트·탐침 evaluator)가 같은 커밋에서 역할을 받도록 바뀌고, 방향을 모르는 구현이 조용히 양방향으로 남는 길을 컴파일러가 막는다. 같은 fingerprint가 여러 이름으로 pin돼 있으면 그 역할을 허용하는 항목 중 파일 순서상 첫 항목이 principal이다. 오늘의 첫 항목 규칙을 방향으로 거른 것이다.

4. **pin을 놓친 뒤의 순서.** `OtherDirection`은 pin 경로의 실패로만 다룬다. 코어는 오늘과 똑같이 CA 체인으로, 이어 `pairing_open()`으로 넘어간다. 그래서 `outbound` pin만 있는 상대가 CA가 서명한 leaf로 inbound에 오면 CA 경로로 수용되고(`auth_path` `ca`, principal은 SAN), 초대가 살아 있으면 `Principal::Pairing`으로 받는다. 방향은 pin 경로를 좁힐 뿐 다른 경로를 열거나 닫지 않는다.

5. **거부와 audit.** 모든 경로가 실패했고 pin 조회가 `OtherDirection`이었으면 거부 사유는 새 `RejectReason::WrongDirection`이다. inbound 쪽은 기존 범주 규칙대로 `handshake_rejected`의 `resource`가 `wrongdirection`인 audit 한 줄을 남긴다. 원격 peer에게 보내는 TLS 오류는 그 fingerprint가 아예 pin되지 않았을 때와 같은 값이다. 상대는 alert만 보고 "다른 방향으로 pin돼 있다"는 사실을 알 수 없다. outbound 쪽(이 장비가 dial한 경우)은 로컬 결과이므로 숨길 이유가 없다. 오늘의 미지 peer와 같은 `TRUST_REQUIRED`를 내되 `details`에 `observed_fingerprint`와 함께 additive 필드 `pinned_as`(그 fingerprint를 가진 첫 pin의 이름)와 `pinned_direction`(`"inbound"`)을 싣는다.

6. **모르는 값.** `direction`에 셋 밖의 값이 적힌 pin은 어느 방향으로도 인증하지 않는다. 파싱되지 않는 fingerprint를 가진 pin과 같은 규율이다. 조회 대상에서 빠지고, 파일 내용이 바뀌어 다시 읽을 때마다 WARN을 한 줄 남기며, 나머지 pin은 그대로 산다. 파일 전체를 `CONFIG_ERROR`로 만들지 않는 이유는 `SharedTrustStore::refresh`가 해석 실패 때 마지막 정상 스냅숏을 유지하기 때문이다. 실행 중인 `qsh serve`에서 `"outbound"`를 `"outbund"`로 잘못 고치면 파일 전체 오류는 옛 스냅숏(더 넓을 수 있다)을 붙들고, pin 단위 무시는 그 pin을 즉시 좁힌다. 운영자가 이 상태를 알아차리는 내구 채널은 새 doctor 진단 `trust_pin_direction_invalid`(status `error`)다. `trust.list`는 파일의 값을 그대로 보여 준다. 그래서 `TrustPeer.direction`은 열린 문자열이다(`docs/CLI.md` §10). 요청 쪽에서 셋 밖의 값은 `trust add --direction`이면 clap이 exit `2`로, JSON 요청의 `direction`이면 `INVALID_ARGUMENT`로 거절한다.

7. **writer.**
   - `qsh trust add <name> ... --direction <both|outbound|inbound>`. 주지 않으면 기존 pin의 방향을 건드리지 않고 새 pin은 필드 없이 쓴다. 같은 이름, 같은 fingerprint에 다른 방향을 주면 주소 갱신과 같은 모양으로 그 자리에서 바꾸고 `data.updated: true`를 낸다. 다른 fingerprint는 오늘처럼 조용한 no-op이다(`docs/CLI.md` §6.11).
   - `qsh pair invite --direction`과 `qsh pair accept --direction`. `--as`와 같은 자리에서 같은 방식으로 각자 자기 쪽 pin의 방향을 정한다. invite 쪽 값은 `invites.toml`의 초대 기록에 additive로 남는다. wire에는 실리지 않는다. 상대는 내가 그를 어느 방향으로 pin했는지 알 필요가 없다.
   - pairing responder 규칙 하나. `outbound` 전용 pin만 있는 fingerprint가 inbound pairing으로 들어와(결정 4대로 pairing 경로에 닿는다) 상환에 성공하면, responder는 `--direction`이 없어도 새 pin을 `inbound`로 쓴다. 필드 없이 쓰면 새 pin이 outbound까지 덮어 파일 순서에 따라 기존 pin을 가리기 때문이다. 이 경우는 오늘 불가능하다(같은 fingerprint는 pin 경로가 먼저 잡는다). 이 ADR 뒤에는 그것이 두 별칭 배치를 만드는 정상 경로 하나가 된다.

8. **§16.2와의 관계.** 이 변경은 `docs/design/protocol.md` §16.2가 동결하는 TLS 검증 경로의 의미 변경이 아니라 로컬 trust 입력의 변경이다. 판정 기준을 이렇게 적는다. 아래 넷이 모두 성립하는 변경은 로컬 trust 입력의 변경이고 §16.5의 major bump 사유가 아니다.
   - (가) 경로의 순서(pin → CA → (pairing) → 거부)가 그대로다.
   - (나) 새 입력은 같은 handshake의 수용을 좁히기만 하고 넓히지 않는다.
   - (다) 수용된 경우의 principal 유도 규칙(pin이면 pin 이름, CA면 SAN)이 그대로다.
   - (라) wire에 새 바이트가 없고, 상대 peer가 자기 버전과 무관하게 같은 trust 입력에서 같은 결과를 본다.

   방향 필드는 넷을 다 지킨다. 필드가 없을 때는 판정이 바이트 단위로 같고, 있을 때는 pin 집합을 역할별로 줄일 뿐이다. 구현 커밋은 §16.2 `QshPeerVerifier` 행의 값 칸에 "pin 조회는 handshake 역할로 거른 로컬 입력이다(ADR-0030). 결정 8의 네 조건을 지키는 입력 변경은 경로 의미 변경이 아니다"를 붙이고, `protocol.md` §3 1번 항목에 같은 내용을 한 문장으로 더한다. §16이 그때 아직 발효 전이면 같은 커밋에서, 발효 뒤면 §16.4 규칙 안의 해명으로 붙인다(`docs/ROADMAP.md` M16 DoD). ADR-0031이 같은 기준을 쓴다.

9. **TOFU는 열지 않는다.** ADR-0017 결정 5가 그대로 선다. 방향 축은 그 결정의 첫 근거("client 쪽 TOFU pin이 inbound 인증까지 연다")를 `outbound` TOFU pin에 한해 없애지만, 남는 근거가 둘이다.
   - 역방향 target에서는 `outbound` pin도 권한을 준다(결정 1). `qsh serve --to`가 첫 접속에서 controller를 자동 pin하면, 처음 보는 상대가 이름을 얻고 그 이름이 target의 `acl.toml`에 이미 행을 가지면 셸을 얻는다. ADR-0017 결정 3이 페어링에 대해 적은 이름 겹침 문제와 같은 모양이다.
   - 첫 접속을 가로챈 상대를 pin하는 위험은 방향과 무관하다. pairing(ADR-0002)과 파일 교환(ADR-0013)이 이미 이 장비의 운영자가 상대를 확인하는 경로를 준다.

   TOFU를 다시 검토하는 ADR이 선다면, 그 출발점은 "`outbound` 전용, forward client 명령에서만, `serve --to`에서는 금지"라는 모양일 것이다. 이 문장은 방향을 정하지 않는다. 미지 peer에게 dial했을 때의 결과(`TRUST_REQUIRED` + `details.observed_fingerprint`)는 바뀌지 않는다.

10. **두 별칭 배치의 정식 해법.** 한 장비를 두 이름으로 pin하는 배치는 방향으로 가른다. 예를 들어 controller 쪽이라면 `workshop`은 `direction = "inbound"`(역방향 등록과 `[[acl]]` 행의 principal), `workshop-lan`은 `direction = "outbound"`(직접 dial용, 주소 있음)다. 두 항목의 방향이 겹치지 않으면 파일 순서는 판정에 관여하지 않는다. 방향이 겹치는 두 항목은 오늘의 첫 항목 규칙을 그대로 따른다. 기존 두 별칭 테스트는 고치지 않은 채 초록이어야 한다(결정 2). README "One machine, two aliases"는 이 배치를 처방으로 바꿔 쓰고, 순서 의존 서술은 "방향을 적지 않은 경우"의 설명으로 남긴다.

11. **doctor.**
    - 새 code `trust_pin_direction_invalid`(status `error`)를 더한다. 결정 6의 pin마다 finding 하나이고, 상세에는 pin 이름만 적고 잘못된 값은 적지 않는다.
    - `acl_principal_unmatched`(ADR-0017 결정 2)의 후보 집합을 방향으로 거른다. inbound를 허용하는 pin(필드 없음 포함)은 언제나 후보다. `outbound` 전용 pin은 doctor가 추론한 실행 모드가 역방향 target(`[serve].to` 또는 `[reverse].controller`)일 때만 후보다. 그 모드에서만 outbound 상대가 이 장비에 요청을 보낸다. 방향 필드가 하나도 없는 `trust.toml`에서는 후보 집합이 오늘과 같다.

12. **경계.** 이 ADR은 `acl.toml` 문법을 바꾸지 않는다. ACL 행은 방향을 조건으로 받지 않고 principal은 principal이다. `qsh setup`의 역할 표(ADR-0024 결정 2)도 바꾸지 않는다. 역할별로 방향을 자동으로 채우는 일은 별도 결정이다.

## 근거

방향을 TLS 역할로 정의한 이유는 verifier가 아는 방향이 그것뿐이기 때문이다. "요청을 보내는 쪽"으로 정의하면 판정이 handshake가 아니라 요청 단위로 내려와야 하고, 그것은 ACL이 이미 하는 일이다. 결정 1의 마지막 문단을 계약 문면으로 박아 두는 이유도 여기 있다. `outbound`라는 단어는 "나가기만 한다"로 읽히기 쉽다. 역방향 target에서 그 오해는 controller가 아무것도 못 한다는 착각으로 이어진다.

이행을 "필드 없음 = 양방향"으로 고른 이유는 `docs/ROADMAP.md` M16 (a)가 이미 정한 방향이고, 다른 선택(필드 없음 = outbound)은 오늘 inbound로 들어오는 모든 client를 업그레이드 한 번에 끊기 때문이다. 기존 writer가 기본으로 필드를 쓰지 않게 한 것도 같은 이유다. 방향을 쓰는 순간은 운영자가 고른다.

pin 단위 무시(결정 6)를 파일 전체 오류보다 앞에 둔 근거는 맥락의 `refresh` 동작이다. 파일 전체 오류는 기동 시에는 fail closed지만 실행 중에는 마지막 정상 스냅숏을 붙드는데, 그 스냅숏은 방금 좁히려던 pin을 더 넓은 상태로 들고 있을 수 있다. pin 단위 무시는 두 시점 모두에서 그 pin을 0으로 줄인다. 저장소에 이미 같은 규율(파싱되지 않는 fingerprint)이 있어 새 원칙을 들이는 것도 아니다.

§16.2 판정(결정 8)을 "로컬 입력"으로 내린 근거는 §16.5 목록의 성격이다. 그 목록은 두 peer가 서로 다르게 이해하면 상호운용이 깨지는 것들이다. 방향 필드는 상대 peer가 관측하는 어떤 것도 바꾸지 않는다. 이 장비가 받아 주던 연결 일부를 이 장비의 운영자가 고른 대로 받지 않을 뿐이고, 그것은 오늘 `trust remove`가 하는 일과 같은 종류다. `trust remove`를 major bump 사유로 읽는 사람은 없다. 네 조건을 적어 두는 이유는 다음 변경(ADR-0031의 revocation 목록)이 같은 질문을 다시 받기 때문이다.

TLS 오류를 미지 peer와 같게 둔 것(결정 5)은 원격 오류와 로컬 진단을 분리하는 ADR-0017 결정 4의 규율을 따른 것이다. 다른 alert를 보내면 원격 prober가 "이 fingerprint는 반대 방향으로 pin돼 있다"를 알게 된다.

## 대안과 기각 사유

- **방향별로 다른 표를 쓴다(`[[peer]]`는 양방향, 방향 있는 pin은 `[[peer_outbound]]`/`[[peer_inbound]]`).** 채택하지 않는다. 이 안에는 실제 장점이 하나 있다. 이 ADR 이전 바이너리는 모르는 표를 통째로 무시하므로, 다운그레이드한 바이너리가 방향 있는 pin을 아예 인증하지 않는다(fail closed). 필드 안에서는 옛 바이너리가 `direction`을 무시해 양방향으로 읽고, 옛 writer가 파일을 다시 쓰면 필드가 사라진다(결과 절의 잔여 위험). 그래도 필드를 고른 이유는 셋이다. ROADMAP과 ADR-0017 결정 5가 이미 additive 필드 모양으로 이 축을 예고했다. 이름 공간 하나를 표 셋에 나누면 `remove`·`rename`·충돌 판정(`TrustStore::rename`이 `[[peer]]`와 `[[ca]]`를 한 이름 공간으로 다루는 규칙)을 전부 다시 써야 한다. 다운그레이드는 운영자가 고르는 동작이다. 사용자가 다운그레이드 안전성을 더 무겁게 보면 이 안으로 바꿀 수 있고, 그때 바뀌는 것은 결정 1의 저장 모양과 결정 7의 writer다.
- **필드 없음을 `outbound`로 읽는다.** 기각한다. 업그레이드 한 번이 모든 inbound client를 끊는다. ROADMAP M16 (a)가 이행 정책을 "오늘과 같은 양방향"으로 정했다.
- **방향을 요청 흐름(누가 요청하는가)으로 정의한다.** 기각한다. verifier는 handshake에서 요청 흐름을 모른다. 판정이 ACL 쪽으로 내려가면 `acl.toml` 문법이 바뀌고 ADR-0017 결정 1의 "어떤 명령도 `acl.toml`을 쓰지 않는다"와 엮인다.
- **`OtherDirection`이면 CA·pairing으로 넘어가지 않고 바로 거부한다.** 기각한다. CA로 정당하게 신뢰되는 상대가 다른 방향의 pin을 하나 갖고 있다는 이유로 거부되면, 방향 필드가 좁히는 것을 넘어 CA 경로까지 닫는다. 결정 8 (가)의 순서 보존도 깨진다.
- **모르는 `direction` 값이면 `trust.toml` 전체를 `CONFIG_ERROR`로 만든다.** 기각한다. 근거 절의 이유 그대로다.
- **TOFU를 `outbound` 전용으로 지금 연다.** 기각한다. 결정 9의 두 근거가 남는다. 열자는 압력(사용자 요청, 캠페인 관측)도 지금은 없다.
- **같은 방향이 겹치는 두 별칭을 writer가 거절한다.** 이번 결정에 넣지 않는다. README가 오늘 그 배치를 안내하고 있어 거절은 기존 사용자의 `trust add`를 깨는 동작 변경이다. 겹침을 알리는 doctor 진단은 후속 후보로 둔다.

## 결과

- **코드.** `qsh-transport`에서는 `TrustEvaluator::lookup_pin`의 시그니처(역할 인자, 세 갈래 반환), `RejectReason::WrongDirection`, `verify_core`의 분기가 바뀐다. `qsh-core`에서는 `TrustPeer`의 해석과 `parsed_pins`의 방향 거르기, pairing responder 규칙, doctor 검출기 둘(새 code 하나와 `acl_principal_unmatched` 후보 집합)이 바뀐다. `qsh-proto`에서는 `TrustPeer.direction`, `TrustAddReq.direction`, pairing 요청 두 타입의 `direction`이 optional 문자열로 늘어난다. `qsh-cli`는 clap 플래그와 렌더만 갖는다. `xtask arch`의 금지에 걸리는 이동은 없다.
- **고정할 테스트.**
  - `crates/qsh-transport/tests/handshake_matrix.rs`에 행이 는다.
    - `outbound` pin만 있는 상대의 inbound handshake 거부.
    - `inbound` pin만 있는 상대에게 하는 outbound handshake 거부.
    - `both`와 필드 없음이 두 역할 모두 오늘과 같은 결과.
    - `outbound` pin만 있는 상대가 CA 서명 leaf로 inbound에 오면 `auth_path` `ca`로 수용(양성 대조군).
    - `outbound` pin만 있는 상대가 초대가 열린 동안 inbound에 오면 `Principal::Pairing`.
  - 방향으로 거부할 때 원격이 받는 TLS 오류가 미지 peer의 것과 같다는 단언.
  - inbound 방향 거부가 `handshake_rejected` audit 한 줄(`resource` `wrongdirection`)을 남긴다는 단언(`qsh serve`와 `qsh listen` 등록 경로 둘 다).
  - 방향 필드가 없는 기존 `trust.toml`(이 ADR 이전 writer가 만든 바이트)로 두 역할의 조회 결과가 이 ADR 이전과 같다는 단언. 기존 handshake matrix 전 행과 두 별칭 테스트 셋은 고치지 않은 채 초록이다.
  - 모르는 `direction` 값을 가진 pin이 두 역할 모두에서 인증하지 않고 나머지 pin은 산다는 단언. 실행 중 파일 수정으로도 같다.
  - `trust_pin_direction_invalid`, 방향으로 거른 `acl_principal_unmatched`(역방향 target 모드와 그 밖 모드)의 doctor 단위 테스트.
  - 방향이 갈린 두 별칭이 파일 순서와 무관하게 inbound principal을 `inbound` 쪽 이름으로 내는 CLI 통합 테스트(`trust_alias_order.rs` 옆).
  - outbound 방향 미스가 `TRUST_REQUIRED`와 `details.pinned_as`·`details.pinned_direction`을 내는 테스트.
  - 결정 7의 pairing responder 규칙(기존 `outbound` pin이 있는 fingerprint의 상환은 `inbound` pin을 쓴다) 테스트.
- **`docs/design/threat-model.md`.**
  - §4 A 표에 행 하나를 더한다. 위협은 "outbound로만 쓸 pin이 inbound 인증을 연다", 통제는 결정 1·3, 핀 테스트는 위 handshake matrix 행이다.
  - A1 행의 통제 문면 "SPKI SHA-256 pin 양방향 검증"을 "역할로 거른 pin 검증(필드 없으면 양방향)"으로 고친다.
  - §7에 잔여 위험 한 줄을 더한다. 이 ADR 이전 바이너리는 `direction`을 무시해 방향 있는 pin을 양방향으로 읽고, 그 바이너리가 `trust.toml`을 다시 쓰면 필드가 사라진다. 완화는 릴리스 노트 고지와 기존 `qsh_path_shadowed` 진단(다른 버전의 `qsh`가 PATH에서 앞설 때)이다.
  - §3 진입점은 늘지 않는다. 새 입력은 기존 `trust.toml` 진입점 안의 필드다.
- **계약과 fixture.** `qsh.cli/v1` 변경은 전부 additive다.
  - `TrustPeer.direction`은 optional 열린 문자열이고 파일에 없으면 생략한다.
  - `TrustAddReq.direction`, `pair invite`/`pair accept` 요청의 `direction`.
  - `TRUST_REQUIRED`의 `details.pinned_as`·`details.pinned_direction`.
  - 기존 fixture는 하나도 고치지 않는다. 결정 2 때문에 방향 없는 호출의 출력이 바이트 단위로 같다. 새 fixture는 `trust.add.direction.json`, `trust.list.direction.json`, `error.TRUST_REQUIRED.direction.json`이고 `REQUIRED_FIXTURES`에 등재한다.
  - `ErrorCode`와 wire(`qsh.wire.v1`)는 바뀌지 않는다.
  - `docs/CLI.md` §6.11에 `direction` 설명(결정 1의 마지막 문단 포함)과 세 플래그, §6.17 표에 `trust_pin_direction_invalid`를 더한다. §6.11·§6.17 산문의 doctor code 수는 `EXPECTED_DOCTOR_CODES.len()`과 같게 맞춘다(현재 24종에서 하나 늘지만, 다른 ADR이 doctor code를 더하면 최종 수가 달라지므로 착륙 시점의 실제 값을 쓴다)(`doctor_code_counts_named_in_prose`, `cli_md_prose_doctor_code_count_matches_expected_len`).
  - `cargo xtask man`으로 `qsh-trust-add.1`, `qsh-pair-invite.1`, `qsh-pair-accept.1`을 다시 만든다.
- **문서.** README "One machine, two aliases"(결정 10)와 Known limitations의 다운그레이드 한 줄, `docs/design/protocol.md` §3·§16.2 해석 줄(결정 8), `docs/design/architecture.md`의 trust store 서술(§5·§7)에 `direction` 필드가 더해진다.
- **크기.** ADR 0.2~0.3ew, 구현 0.8~1.2ew. 구현의 내역은 verifier와 evaluator 0.2, 파일·JSON 필드와 writer 세 갈래 0.3, doctor 둘 0.15, pairing 규칙 0.1, 테스트와 문서 0.2~0.45다. `docs/ROADMAP.md` M16 크기 절의 (a) 구현 칸에 이 값을 적는다.
- **후속.** ADR-0015는 결정 7에 이 축을 입력으로 쓴다. listener 상대 pairing이 target에 만드는 pin의 기본 방향을 그 ADR이 정한다. ADR-0031은 결정 3의 역할 인자를 trust 변경 뒤 기존 연결 재검증에 쓴다.
