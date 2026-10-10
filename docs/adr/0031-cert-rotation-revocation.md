# ADR-0031: revocation은 이 장비의 `trust.toml` `[[revoked]]` 목록으로만 강제하고 네트워크로 전파하지 않는다. trust 변경 뒤 장기 실행 프로세스는 2초 안에 기존 연결을 재검증해 지금은 받지 않을 연결을 닫는다. 키 rotation은 옛 키가 서명한 rotation 문서를 파일로 건네고 받는 쪽이 `trust rotate`로 pin 교체와 옛 키 revoke를 한 번에 한다

날짜: 2026-10-11
상태: 제안됨

개정 관계: ADR-0008 결과 절의 "CA rotation·CRL/OCSP·revocation 전파는 이 ADR의 범위 밖(P1)" 중 device leaf의 rotation과 로컬 revocation을 이 ADR이 가져온다. CA root rotation과 CRL/OCSP는 계속 범위 밖이다(결정 11). `docs/CLI.md` §6.11의 "`trust.remove`의 유효 범위" 문단과 §6.17 `trust_remove_scope`의 message·remedy를 결정 6·10대로 바꾼다. 이 문단과 문면은 M7 감사 개정이 고정한 것이고(M7 plan Step 2 (69dd788)), 바뀌는 것은 "이미 확립된 연결은 권한을 유지한다"는 한 문장과 remedy의 "(P1)"이다. ADR-0012 결정 7의 "rename 뒤 이미 붙어 있는 연결은 권한을 유지한다"는 그대로 선다(결정 6의 principal 예외). 이 ADR은 ADR-0030의 방향 필드와 `TrustEvaluator::lookup_pin`의 역할 인자를 입력으로 쓴다(결정 6·9). ADR-0030이 기각되면 그 두 자리만 빠지고 나머지 결정은 그대로 선다. §16.2와의 관계는 ADR-0030 결정 8의 기준을 그대로 쓴다(결정 12).

## 맥락

qsh에서 인증서를 무효로 만드는 수단은 오늘 셋뿐이고, 셋 다 그 장비 혼자의 일이다.

- **`trust remove`.** pin이나 `[[ca]]`를 지운다. 매 handshake마다 `trust.toml`을 다시 읽으므로 다음 handshake부터 거부한다. 이미 확립된 연결은 건드리지 않는다. `docs/CLI.md` §6.11이 이것을 "협상된 권한 전체를 연결이 끊길 때까지 유지한다"로 계약하고, doctor `trust_remove_scope`(info)가 pin이 있는 한 늘 같은 문장을 보여 준다. 그 remedy는 "Force-closing an already-established connection on removal is not implemented (P1)"이다. `docs/design/threat-model.md` §7 h5가 이 사실을 잔여 위험으로 둔다.
- **유효기간.** verifier는 pin 경로와 CA 경로 모두에서 leaf의 `not_before`/`not_after`를 검사한다(`docs/design/protocol.md` §3). 그런데 device leaf의 유효기간은 10년이다(`CERT_VALIDITY_DAYS`, `LEAF_VALIDITY_DAYS`). 그래서 이 레버는 사실상 당길 수 없다.
- **identity 삭제와 재 init.** 새 키를 만들면 모든 peer가 다시 pin해야 한다. doctor `cert_expired`의 remedy가 오늘 안내하는 유일한 복구가 이것이다("peers must then re-pin"). `qsh cert issue`와 `qsh cert init`은 이미 서명한 leaf나 이미 있는 root 앞에서 no-op이고 `--force`가 없다.

여기서 빠진 것이 네 가지다.

- **revocation 전파가 없다.** ADR-0008 결과 절과 ADR-0026 근거 절이 이 사실을 적는다. CA가 서명한 leaf 하나를 무효로 하려면 그 CA를 신뢰하는 모든 장비가 각자 무언가를 해야 하는데, 할 수 있는 것이 그 CA 전체를 지우는 `trust remove`밖에 없다.
- **`trust remove`가 키를 막지 못하는 경우가 있다.** `qsh cert issue`는 같은 키로 CA 서명 leaf를 다시 만든다(`docs/CLI.md` §6.16). 상대를 pin으로도, 그 상대의 CA로도 신뢰하는 장비에서 pin만 지우면 같은 키가 CA 경로로 계속 들어온다.
- **키 rotation 경로가 없다.** 키가 새면 복구는 identity 삭제, 재 init, 모든 peer의 재 pinning뿐이다(threat-model §7 h29, ADR-0026). `qsh init --import-ssh-key`(M11 (c))로 SSH와 키를 나눠 쓰는 identity는 SSH 쪽 키 폐기와 수명이 묶여 있어 이 공백이 더 아프다.
- **이미 열린 연결을 끊을 수 없다.** threat-model §7은 h4(revocation 부재)와 h5(소급 없는 `trust remove`)를 "함께 읽어야 한다"고 적는다. 손상된 peer를 즉시 끊는 수단이 v1에 없다는 뜻이다. 실무 대응은 `qsh serve` 재시작인데, 그러면 모든 세션이 끝난다(h12).

`docs/ROADMAP.md` M16 (d)는 UX만 먼저 내면 "revoke했다"는 출력과 실제 강제가 어긋난다고 경고한다. 이 ADR의 출력 문면은 그 어긋남을 만들지 않는 것이 첫 조건이다.

설계를 가르는 사실은 이렇다.

- `QshPeerVerifier::verify_peer(chain, role)`(`crates/qsh-transport/src/tls.rs`)는 handshake와 같은 코어로 이미 확립된 연결의 peer chain을 다시 판정할 수 있다. 연결에 principal을 붙일 때 이미 이 함수를 쓴다.
- `SharedTrustStore::refresh`는 파일 바이트가 바뀌었을 때만 다시 파싱한다. 파일 하나를 읽고 비교하는 비용은 작다.
- `qsh serve`, `qsh listen`, `qsh serve --to`는 identity를 프로세스 시작 때 한 번 읽는다(`crates/qsh-core/src/serve.rs`의 "`identity` must already be loaded").
- CLOSE 코드는 §16 동결 밖이다(§16.3). 쓰는 값은 `0x1001`~`0x1004`이고, peer는 값에 따라 분기하지 않는다(§7, §16.5 끝).
- audit 기록은 구조 필드만 싣는다(`docs/design/architecture.md` §6). `trust rename`은 잠금 → load → 변경 → audit → save 순서로 움직이고, audit에 실패하면 아무것도 쓰지 않는다(ADR-0012 결정 7).

## 결정

1. **용어.** 이 ADR에서 세 낱말을 이렇게 쓴다. 출력 문면과 `docs/CLI.md`도 같은 뜻으로만 쓴다.
   - 갱신(renewal): 같은 키로 유효기간만 새로 받는다.
   - rotation: 새 키로 바꾸고 옛 키를 revoke한다.
   - revoke: 특정 SPKI fingerprint를 이 장비에서 모든 경로로 거부한다.

2. **revocation 목록.** `trust.toml`에 `[[revoked]]` 표를 더한다. 항목은 `fingerprint`(`sha256:BASE64`, 필수), `revoked_at`(RFC 3339, 필수), `note`(선택, 사람이 읽는 메모)다. verifier 코어는 leaf의 fingerprint를 계산하고 유효기간을 검사한 직후, pin 조회보다 먼저 이 목록을 본다. 목록에 있으면 pin·CA·pairing 어느 경로도 보지 않고 거부한다. 거부 사유는 새 `RejectReason::Revoked`이고, inbound audit의 `resource`는 기존 범주 규칙대로 `revoked`다.
   - 원격 peer에게 보내는 TLS 오류는 미지 peer의 것과 같다(ADR-0030 결정 5와 같은 규율).
   - outbound 쪽 로컬 결과는 `AUTH_FAILED`이고, `details.revoked: true`를 additive로 싣는다.
   - `TrustEvaluator`에 `is_revoked(&Fingerprint) -> bool`을 기본 구현 없이 더한다.
   - 파싱되지 않는 `fingerprint`를 가진 `[[revoked]]` 항목은 무시하지 않는다. 그 파일은 `CONFIG_ERROR`다. pin 항목과 반대인 이유가 있다. pin을 무시하면 trust가 좁아지지만 revocation을 무시하면 넓어진다. 기동 때 `trust.toml`이 이 상태면 프로세스는 fail closed로 뜨지 않는다. 실행 중에 이렇게 바뀌면 `refresh`의 기존 규칙대로 마지막 정상 스냅숏을 유지한다. 그 스냅숏에 목록이 있었다면 거기 있던 revocation은 계속 강제된다. doctor는 이 상태를 기존 `trust.toml` 파싱 실패 경로로 보고한다.

3. **revocation은 전파하지 않는다.** qsh는 CRL, OCSP, gossip, wire 메시지 어느 것으로도 revocation을 다른 장비에 보내지 않는다. revoke는 그 명령을 실행한 장비에서만 강제된다. 다른 장비에 퍼뜨리는 일은 운영자가 한다. fingerprint를 전달해 각 장비에서 `trust revoke`를 실행하거나, rotation 문서(결정 8)를 건네 `trust rotate`를 실행한다. 이 사실은 출력 문면에 빠짐없이 들어간다(결정 10). JSON에는 `data.scope: "local"`로 싣는다. `scope`는 열린 문자열이라 언젠가 전파 경로가 생기면 값을 더할 수 있지만, 이 ADR은 그 값을 정하지 않는다.

4. **`qsh trust revoke`.** `qsh trust revoke --fingerprint <sha256:…> [--note <text>]` 또는 `qsh trust revoke --cert-file <path|->`이다. 둘 중 하나만 받는다. 이미 있는 fingerprint면 조용한 no-op이고 `created: false`다.
   - 같은 fingerprint의 pin이 있어도 pin을 지우지 않는다. pin은 이름과 주소를 들고 있고, revoke가 그것을 같이 지우면 rotation(결정 9)이 쓸 이름이 사라진다. 대신 출력은 그 fingerprint를 쓰는 pin 이름들을 `data.pinned_as`로 보여 준다. revocation이 이기므로 그 pin들은 이제 아무도 인증하지 않는다.
   - 되돌리는 명령은 두지 않는다. `trust.toml`의 해당 `[[revoked]]` 항목을 손으로 지운다. 넓히는 동작에 일부러 마찰을 둔다.
   - op 이름은 `trust.revoke`다. 원격 peer가 요청할 수 없는 로컬 op이고 인가가 필요 없다(`docs/CLI.md` §2.5). wire 메시지도 없다.
   - audit 대상이다. `trust rename`과 같이 잠금 → load → 변경 → audit → save 순서이고, audit에 실패하면 `INTERNAL`로 끝나며 `trust.toml`은 그대로다.
   - `trust.list`는 `data.revoked` 배열을 additive로 싣는다. 목록이 비면 키를 생략한다.

5. **revocation은 방향과 무관하다.** `[[revoked]]`는 두 handshake 역할 모두에 적용된다. ADR-0030의 `direction`이 무엇이든, pin이 있든 없든 같다.

6. **기존 연결 재검증.** 다음 연결을 가진 프로세스는 trust 변경 뒤 그 연결을 다시 판정한다. 상대의 요청을 이 프로세스의 ACL로 인가하는 연결만 해당한다.
   - `qsh serve`가 받은 inbound 연결.
   - `qsh listen`이 받은 inbound 연결(역방향 등록 포함).
   - `qsh serve --to`가 controller로 연 outbound 등록 연결.

   절차는 이렇다.
   - 이 프로세스들은 1초 간격으로 `trust.toml`을 `refresh`한다. 내용이 바뀐 tick에는 살아 있는 연결마다 그 연결을 받았을 때의 peer chain과 역할(ADR-0030 결정 3의 `PeerRole`)로 `verify_peer`를 다시 부른다.
   - 결과가 거부이거나, `auth_path`가 처음과 달라졌거나(pin으로 받았는데 이제 CA로만 받는 경우 포함), `Pairing`이면 그 연결을 새 CLOSE 코드 `0x1005`(`CLOSE_CODE_TRUST_WITHDRAWN`)로 닫는다.
   - principal 문자열만 달라진 경우(`trust rename`, 별칭 순서 변경)는 닫지 않는다. ADR-0012 결정 7의 "rename 뒤 기존 연결은 권한 유지"를 그대로 둔다. rename은 신뢰를 거두는 동작이 아니기 때문이다.
   - 닫을 때 audit에 connection 수준 deny 한 줄을 남긴다. `principal`과 `auth_path`는 처음 값, `action`은 `connect`, `resource`는 `trust_withdrawn`이다. 이 기록의 실패는 닫는 동작을 막지 않는다. 이미 좁히는 쪽이고 `handshake_rejected`와 같은 예외다.
   - 위 ADR-0030 축을 쓰므로, pin을 `both`에서 `outbound`로 좁히면 그 상대의 inbound 연결이 닫힌다.

   보장은 "`trust.toml`의 바이트가 바뀐 시점부터 2초 안에 닫힌다"이다. 1초 tick 하나와 재검증 시간의 여유다. `qsh trust remove`/`revoke`/`rotate` 자신은 어느 프로세스가 무엇을 닫았는지 모른다. 그래서 출력은 "닫았다"가 아니라 "실행 중인 qsh 프로세스가 2초 안에 닫는다"고 말한다(결정 10).

   이 결정은 세션을 끝내지 않는다. 연결이 닫히면 세션은 오늘의 연결 유실과 같은 규칙으로 detach되고, 그 peer는 다시 handshake할 수 없으니 resume으로 돌아오지 못한다. 거둔 principal의 세션을 즉시 종료하는 것은 이 ADR의 결정이 아니다.

   one-shot client 연결(`exec`, 대화형 attach, client 쪽 터널)은 재검증하지 않는다. 그 연결에서 상대는 이 장비에게 요청을 보내 인가받는 쪽이 아니다. `--supervise` 터널은 다음 재수립의 handshake에서 거부되어 오늘처럼 `gave_up`으로 끝난다.

7. **유효기간 만료도 연결을 닫는다.** 결정 6의 프로세스는 각 연결에 그 peer leaf의 `not_after`를 기한으로 건다. 기한이 지나면 같은 CLOSE 코드와 audit 한 줄(`resource` `trust_withdrawn`)로 닫는다. 결정 6의 재검증이 유효기간을 함께 보는 이상, 이 기한이 없으면 만료된 연결의 운명이 "그 사이 `trust.toml`이 바뀌었는가"라는 관계없는 사건에 달린다. 10년짜리 leaf라 평소에는 일어나지 않는다.

8. **rotation과 갱신: `qsh identity rotate`.**
   - **rotation(기본).** 새 키쌍을 만든다. 키 저장소 종류(file 또는 platform)는 지금 identity와 같다. `device_id`와 SAN `qsh://device/<device_id>`는 그대로이고 키만 바뀐다. 지금 leaf가 로컬 CA 서명(`issued_by_ca`)이면 새 leaf도 같은 CA로 서명한다(`qsh cert issue`의 발급 함수 재사용). 아니면 self-signed다.
   - **rotation 문서.** 옛 키로 서명한 rotation 문서를 config 디렉터리 아래 0600 파일로 쓰고 경로를 `data.statement_path`로 돌려준다. 문서는 옛 leaf, 새 leaf, `rotated_at`, 서명으로 이루어진다. 서명은 옛 키로 `b"qsh identity rotation v1" ‖ 0x00 ‖ SHA-256(새 leaf DER) ‖ rotated_at(u64 BE, Unix 초)`에 한다. 개인키는 문서에 들어가지 않는다.
   - **쓰는 순서.** 문서 → 새 identity(원자적 교체) → 옛 개인키 삭제다. 옛 leaf(공개)는 `identity/previous/`에 남긴다. 중간에 실패하면 다시 실행했을 때 그 상태를 보고 이어 가거나 `CONFIG_ERROR`로 멈춘다. 옛 키와 새 키가 둘 다 살아 있는 상태로 성공을 보고하지 않는다.
   - **가져온 키.** `qsh init --import-ssh-key`로 만든 identity도 같은 명령으로 rotation된다. 새 키는 항상 qsh가 새로 만든다. 다른 SSH 키를 다시 가져오는 경로는 이 명령에 없다. 출력의 `ssh_fingerprint`는 사라진다.
   - **갱신.** `--keep-key`를 주면 rotation 대신 같은 키로 유효기간만 새로 받은 leaf를 만든다. CA 서명 여부는 위와 같다. SPKI가 같으니 상대의 pin은 그대로 맞고, rotation 문서도 revoke도 없다. doctor `cert_expiring_soon`/`cert_expired`의 remedy는 이 경로를 가리키도록 바뀐다. 오늘의 "identity를 지우고 peer가 다시 pin하라"는 문면은 사라진다.
   - **재시작.** 두 경우 모두 장기 실행 프로세스는 identity를 기동 때 읽으므로, 재시작해야 새 leaf를 제시한다. 출력이 이것을 말한다.
   - op 이름은 `identity.rotate`다. 로컬 op이고 인가가 필요 없으며 wire 메시지가 없다.

9. **받는 쪽: `qsh trust rotate --statement <path|->`.**
   - **검증.** 문서를 이렇게 검증한다.
     - 옛 leaf와 새 leaf가 모두 파싱된다.
     - 서명이 옛 leaf의 공개키로 검증된다.
     - 두 leaf의 SAN `device_id`가 같다.
     - 새 leaf가 지금 유효기간 안이다.
     - 두 fingerprint가 다르다.

     하나라도 실패하면 `INVALID_ARGUMENT`로 끝나고 아무것도 쓰지 않는다. 오류 문면은 어느 검사가 실패했는지만 말하고 입력 바이트를 되풀이하지 않는다.
   - **적용.** 검증을 통과하면 한 잠금 안에서 둘을 한다.
     - 옛 fingerprint를 가진 모든 pin(두 별칭이면 둘 다)의 fingerprint를 새 값으로 바꾼다. 이름, 주소, `direction`(ADR-0030), `added_at`은 그대로다.
     - 옛 fingerprint를 `[[revoked]]`에 더한다.

     맞는 pin이 하나도 없으면(CA로만 그 상대를 신뢰하는 장비) revoke만 하고 `data.pins_updated: []`를 낸다. 새 leaf는 CA 경로로 이미 받기 때문이다.
   - **권한.** 문서는 새 신뢰를 만들지 않는다. 이미 pin돼 있던 이름만 옮기고, 없던 이름은 만들지 않는다.
   - audit 대상이다. 결정 4와 같은 순서와 실패 규칙을 따른다. 결정 6의 재검증 대상이 되므로, 옛 키로 맺은 기존 연결은 적용 뒤 2초 안에 닫힌다.
   - op 이름은 `trust.rotate`다. 로컬 op이고 인가가 필요 없으며 wire 메시지가 없다.
   - 문서 파서는 신뢰할 수 없는 로컬 입력의 파서다. `qsh-proto`에 sans-IO로 두고 cargo-fuzz 타깃을 하나 더한다(ADR-0026 결정의 SSH 키 파서와 같은 자리).

10. **문면 규율.** trust를 좁히는 명령(`trust remove`, `trust revoke`, `trust rotate`, `trust add --direction`으로 좁히는 경우)의 사람용 출력과 doctor 고지는 세 가지를 빠짐없이 말한다.
    - 언제 적용되는가: 다음 handshake부터, 그리고 실행 중인 `qsh serve`/`qsh listen`/`qsh serve --to`가 기존 연결을 2초 안에 닫는다.
    - 어디에 적용되는가: 이 장비에서만.
    - 무엇을 하지 않는가: 다른 장비에 알리지 않는다. 세션을 끝내지 않는다.

    문장은 `qsh-core`의 상수 한 벌이고 `qsh-cli`는 받은 것을 쓰기만 한다. `docs/CLI.md`가 그 상수를 축자 인용하고 `crates/qsh-core/tests/doctor_docs.rs`와 같은 형식의 테스트가 바이트 일치를 고정한다. `trust_remove_scope`는 code와 status(`info`)를 그대로 두고 message와 remedy만 이 규율로 바꾼다. 노출 조건은 "pin이 하나라도 있으면"에서 "pin, `[[ca]]`, `[[revoked]]` 중 하나라도 있으면"으로 넓힌다. remedy에서 "(P1)"과 재시작 권고가 빠지고, 다른 장비에서도 같은 명령을 실행하라는 안내가 들어간다.

11. **CA root rotation은 이 ADR 밖이다.** 새 root를 이 CA를 신뢰하는 모든 장비에 돌리는 일은 다대 CA 서명(ADR-0016)과 같은 배포 질문이고, 그 ADR이 결정 2(파일 교환인지 네트워크 경로인지)를 정한 뒤에야 모양이 나온다. CA root 유효기간은 20년(`CA_VALIDITY_DAYS`)이다. CA 개인키가 샌 경우의 처방은 오늘과 같이 `trust remove <ca-name>`을 각 장비에서 실행하는 것이고, 결정 6으로 그 CA 경로의 기존 연결도 닫힌다.

12. **§16.2와의 관계.** 이 ADR의 변경은 모두 로컬 trust 입력의 변경이다. ADR-0030 결정 8의 네 조건을 그대로 대 본다.
    - `[[revoked]]` 사전 검사는 수용을 좁히기만 하고, pin → CA → pairing의 상대 순서와 principal 유도 규칙을 바꾸지 않으며, wire에 바이트가 없다.
    - 결정 6·7은 handshake 뒤의 연결 수명 규칙이라 검증 경로가 아니다. 새 CLOSE 코드는 §16.3이 동결 밖에 둔 대역이다.
    - rotation 문서는 파일이고 wire가 아니다.

    구현 커밋은 §16.2 `QshPeerVerifier` 행에 ADR-0030이 붙인 해석 줄을 "revocation 목록 사전 검사(ADR-0031)도 같은 기준의 로컬 입력이다"로 넓히고, `docs/design/protocol.md` §3에 사전 검사 한 문장과 "확립된 연결은 trust 변경 뒤 재검증된다"는 한 문장을 더한다. §16.3의 CLOSE 코드 목록과 §16.5 끝의 값 범위(`0x1001`~`0x200E`)에 `0x1005`가 들어가도록 문장을 고친다.

## 근거

revocation을 로컬 목록으로 두고 전파하지 않는 이유는 qsh에 중앙이 없기 때문이다. PRD §12는 조직 계정과 중앙 관리를 경계 밖에 둔다. CRL과 OCSP는 모든 장비가 닿을 수 있는 배포 지점을 요구하고, 그 지점이 곧 중앙이다. peer끼리 gossip하는 안은 "누구의 revoke를 믿는가"라는 새 신뢰 질문을 만든다. 그 답이 "CA 키 보유자"라면 결국 서명된 CRL이고, 그것을 받을 wire 경로와 배포 주기를 정해야 한다. 그 일은 ADR-0016이 배포 모양을 정한 뒤에야 할 수 있다. 지금 할 수 있고 정직한 것은 각 장비가 자기 거부 목록을 갖고, 출력이 그 범위를 숨기지 않는 것이다. ROADMAP M16 (d)가 경고한 어긋남은 강제가 약해서가 아니라 문면이 강제보다 넓을 때 생긴다. 결정 3과 10이 그 둘의 폭을 맞춘다.

revoke가 pin을 지우지 않게 한 이유는 맥락의 두 번째 공백 때문이다. 지금은 pin을 지워도 같은 키가 CA 경로로 들어올 수 있다. 키를 막는 목록과 이름을 관리하는 pin을 나누면, revoke는 키에 대해 말하고 pin은 이름에 대해 말한다. 그러면 rotation이 이름을 그대로 두고 키만 옮길 수 있다.

기존 연결 재검증을 1초 poll로 고른 이유는 세 장기 실행 프로세스가 공유하는 알림 통로가 없기 때문이다. localctl UDS는 `qsh listen` 데몬의 것이고 `qsh serve`에는 없다. 파일 감시(inotify, FSEvents)는 플랫폼마다 다르고, 원자적 rename으로 쓰는 `trust.toml`을 감시하려면 디렉터리 감시가 필요하다. 이 저장소는 이미 매 handshake마다 파일을 통째로 읽어 비교하고 있어서, 1초 poll은 그 비교를 시계에 한 번 더 거는 것뿐이다. 2초 보장은 `REDIAL_DEADLINE`과 같은 크기라 운영자가 기억할 숫자가 하나다.

principal만 바뀐 연결을 닫지 않는 이유는 rename이 신뢰를 거두는 동작이 아니기 때문이다. rename에 연결을 끊는 효과를 붙이면 ADR-0012 결정 7을 개정해야 하고, 운영자는 이름 정리 한 번에 모든 peer를 끊게 된다. `auth_path` 변화를 닫는 쪽에 둔 것은 그것이 신뢰 근거 자체가 바뀐 경우이기 때문이다. pin을 지웠는데 CA로 남아 있다면, 운영자가 지운 것은 바로 그 pin 근거다.

rotation 문서를 파일로 건네게 한 이유는 ADR-0013이 파일 교환을 프로비저닝의 1급 경로로 올렸기 때문이고, wire로 자동 갱신하면 "자동 신뢰는 없다"(ADR-0024)는 이 저장소의 규율과 부딪히기 때문이다. 문서는 옛 키의 서명으로 연속성을 증명하므로, 받는 운영자는 새 fingerprint를 따로 대조하지 않아도 그것이 같은 장비의 다음 키라는 것을 안다. 이것이 오늘의 "remove 후 add"보다 나은 점이다. 그 사이 pin이 비는 창이 없고, 옛 키가 같은 명령에서 revoke된다.

`--keep-key` 갱신을 같은 명령에 둔 이유는 오늘 `cert_expired`의 remedy가 만료 하나에 모든 peer의 재 pin을 요구하기 때문이다. SPKI가 그대로면 pin도 그대로이므로, 만료는 다른 장비에 아무 일도 시키지 않는 사건이어야 한다.

## 대안과 기각 사유

- **wire로 revocation을 전파한다(연결된 peer에게 revoke 메시지를 보낸다).** 기각한다. 받는 쪽이 누구의 revoke를 믿을지가 새 신뢰 결정이다. 보내는 쪽이 이미 pin한 상대라는 것은 그 상대가 제3자의 키를 무효로 할 권한이 있다는 근거가 되지 않는다. §16.4 안의 additive 변경으로 넣을 수는 있지만, 그 신뢰 모델은 ADR-0016의 배포 결정 위에 서야 한다.
- **CRL 파일을 CA가 서명해 배포한다.** 지금은 채택하지 않는다. 다대 CA(ADR-0016)가 정해지기 전에는 "어느 CA의 CRL인가"가 단일 로컬 CA 하나뿐이다. 그 경우 CRL은 `trust revoke --fingerprint` 목록에 서명을 하나 더 붙인 것과 같다. ADR-0016이 서면 그 위에서 다시 검토한다.
- **revoke가 같은 fingerprint의 pin도 지운다.** 기각한다. 근거 절의 이유 그대로다. rotation이 이름을 잃고, 이름을 잃은 pin을 다시 만들면 `added_at`과 `direction`도 잃는다.
- **trust 변경 때 기존 연결을 닫지 않고 문면만 고친다(현행 유지).** 기각한다. ROADMAP M16 (d)가 이 결정을 요구하고, threat-model §7 h4·h5가 함께 남기는 "손상된 peer를 즉시 끊는 수단이 없다"는 상태가 그대로 남는다.
- **`trust remove`가 실행 중인 프로세스에 직접 신호를 보내 즉시 닫게 한다.** 기각한다. `qsh serve`에는 localctl이 없고, 같은 config 디렉터리를 쓰는 프로세스를 찾는 일 자체가 새 IPC 표면이다(threat-model §3 진입점). poll은 표면을 늘리지 않는다.
- **principal이 바뀐 연결도 닫는다.** 기각한다. ADR-0012 결정 7 개정이 필요하고 rename이 끊김 사건이 된다.
- **rotation 뒤 옛 키를 유예 기간 동안 함께 받아 준다(pin이 두 fingerprint를 갖는다).** 채택하지 않는다. TLS endpoint는 한 번에 leaf 하나만 제시하므로, 유예 기간은 받는 쪽 pin에 두 값을 두는 모양이 된다. 그러면 옛 키가 샌 rotation에서도 유예 기간 동안 옛 키가 계속 들어온다. rotation의 목적과 반대다. 대가로 생기는 짧은 끊김(결과 절)은 문서로 안내한다.
- **rotation 문서 없이 rotation한다(새 키를 만들고 상대는 `trust remove` 후 `trust add --cert-file`).** 채택하지 않지만 크기를 줄이는 대체안으로 남긴다. 문서 파서·fuzz 타깃·`trust rotate`가 빠져 약 0.4~0.5ew가 준다. 대가는 받는 쪽마다 pin이 비는 창, 수동 fingerprint 대조, 따로 해야 하는 revoke다.
- **CA root rotation을 이 ADR에서 같이 한다.** 기각한다. 결정 11의 이유 그대로다.

## 결과

- **계약.** `qsh.cli/v1` 변경은 전부 additive다.
  - 새 op 셋: `identity.rotate`, `trust.revoke`, `trust.rotate`. 모두 로컬 전용이고 인가가 필요 없으며 wire 메시지가 없다. `docs/CLI.md` §2.4 op 목록, §2.5 표, §6.11에 절을 더한다.
  - `trust.list`의 `data.revoked`.
  - `AUTH_FAILED`의 `details.revoked`.
  - 새 `ErrorCode`는 없다.
  - op registry 분류 테스트가 세 op에 대응하는 wire 메시지가 없음을 확인한다(`setup_run_never_appears_as_a_control_message_wire_variant`와 같은 형식).
- **fixture.** 기존 fixture는 고치지 않는다. `trust.list.json`은 `[[revoked]]`가 없으면 바이트가 같다. 새 fixture는 다음 여섯이고 `REQUIRED_FIXTURES`에 등재한다. schemars 타입, 렌더러, `CLI_V1_SCHEMA_COMMANDS` 등록 완전성도 갖춘다.
  - `identity.rotate.json`
  - `identity.rotate.keep_key.json`
  - `trust.revoke.json`
  - `trust.rotate.json`
  - `trust.list.revoked.json`
  - `error.AUTH_FAILED.revoked.json`
- **man.** `cargo xtask man`으로 `qsh-identity-rotate.1`, `qsh-trust-revoke.1`, `qsh-trust-rotate.1`을 더한다. man 페이지는 51종에서 54종이 된다.
- **doctor.** 새 code는 없다. `trust_remove_scope`의 message, remedy, 노출 조건과 `cert_expired`/`cert_expiring_soon`의 remedy가 바뀐다. 셋 다 `docs/CLI.md` §6.17이 축자 인용하므로 같은 커밋에서 바뀌고, `cli_md_quotes_the_trust_remove_scope_diagnostic_verbatim`과 같은 형식의 테스트가 이를 지킨다. 만료 30일 전 경고(`cert_expiring_soon`, P0)의 검출 조건은 그대로다.
- **fuzz.** rotation 문서 파서 타깃이 하나 늘어 19종에서 20종이 된다. `fuzz/README.md`와 `docs/design/protocol.md` §13의 개수 문장이 같은 커밋에서 바뀐다.
- **고정할 테스트.**
  - **rotation.**
    - rotation 뒤 `trust rotate`를 적용한 peer는 옛 leaf의 handshake를 거부(`revoked`)하고 새 leaf를 같은 principal로 수용한다. pin 경로와 CA 경로 각각이다.
    - 적용하지 않은 peer는 새 leaf에 `TRUST_REQUIRED`와 `observed_fingerprint`를 낸다.
    - `--keep-key` 갱신 뒤에는 기존 pin이 고치지 않은 채 새 leaf를 수용한다.
    - `--import-ssh-key`로 만든 identity가 rotation되고 새 키의 fingerprint가 SSH 키의 것과 다르다.
    - 중간 실패를 주입하면 옛 키와 새 키가 둘 다 살아 있는 성공 상태가 남지 않는다.
  - **rotation 문서.** 서명 불일치, `device_id` 불일치, 만료된 새 leaf, 같은 fingerprint를 각각 `INVALID_ARGUMENT`로 거절하고 `trust.toml`이 그대로다. 두 별칭 pin이 함께 옮겨지고 `direction`이 보존된다.
  - **revoke.**
    - revoke한 fingerprint가 pin이 있어도, CA 서명이어도, 초대가 열려 있어도 두 역할 모두에서 거부된다(`handshake_matrix.rs`에 행 추가).
    - 원격 TLS 오류가 미지 peer와 같다.
    - inbound audit `resource`가 `revoked`다.
    - 파싱되지 않는 `[[revoked]]` 항목이 기동 때 `CONFIG_ERROR`다.
  - **기존 연결.**
    - `trust remove`, `trust revoke`, `trust rotate`, pin 방향 축소, `[[ca]]` 제거 각각 뒤 2초 안에 `qsh serve` inbound 연결이 `0x1005`로 닫히고 audit 한 줄이 남는다.
    - `qsh listen` 등록 연결과 `qsh serve --to` 등록 연결도 같다.
    - `trust rename`과 별칭 순서 변경 뒤에는 연결이 살아 있다.
    - leaf `not_after`가 지나면 연결이 닫힌다(시계 주입).
    - `--supervise` 터널은 재수립 거부 뒤 `gave_up`으로 끝난다.
  - **문면.** 결정 10의 상수가 `docs/CLI.md`와 바이트 일치한다.
- **`docs/design/threat-model.md`.**
  - §3: rotation 문서 파일을 신뢰할 수 없는 로컬 입력 진입점으로 더한다.
  - §4 A 표:
    - "CA가 서명한 leaf 하나를 그 CA 전체를 지우지 않고 막을 수 없다" 행. 통제는 결정 2, 핀은 revoke handshake 행이다.
    - "새 rotation 문서로 pin을 공격자 키로 옮긴다" 행. 통제는 결정 9의 다섯 검사와 운영자가 실행하는 명령이라는 점이다. 잔여는 아래 h 행이다.
  - B 표: "제거된 peer가 기존 연결로 권한을 유지한다" 행의 통제를 결정 6으로 채운다.
  - §7:
    - h5를 "trust 변경 뒤 최대 2초의 창"으로 줄인다.
    - h4를 "로컬 revocation은 있고 전파는 없다. CA root rotation은 없다"로 고친다.
    - h29를 rotation 경로가 생긴 것으로 고친다.
    - 새 잔여 위험 두 줄을 더한다. 첫째, 옛 키를 훔친 공격자는 정당한 소유자보다 먼저 rotation 문서를 만들어 건넬 수 있다. 그래서 rotation 문서는 계획된 rotation용이고, 키가 샌 것이 확실하면 처방은 각 장비의 `trust revoke`와 재 pairing이다. 이 구분은 `docs/CLI.md` §6.11에 적는다. 둘째, revoke는 실행한 장비에서만 강제된다.
- **운영 안내.** rotation한 장비가 재시작한 뒤 상대가 `trust rotate`를 적용하기 전까지는 그 상대와의 handshake가 실패한다. 반대 순서(상대가 먼저 적용)면 재시작 전까지 옛 leaf가 거부된다. 권장 순서는 rotate, 재시작, 문서 배포이고 README와 `docs/CLI.md` §6.11에 적는다.
- **ADR-0030 의존.** 결정 6이 연결의 역할을 재검증에 넘기고, 결정 9가 `direction`을 보존한다. ADR-0030이 서지 않으면 재검증은 역할 인자 없이 오늘의 `verify_peer`를 부르고, `trust rotate`는 옮길 `direction`이 없다. 다른 결정은 바뀌지 않는다.
- **크기.** ADR 0.2ew, 구현 2.0~2.6ew. 구현 내역은 다음과 같다.
  - rotation과 갱신: 1.0~1.3. 로컬 CA 발급 함수 재사용 전제, 키 저장소 두 종류와 중간 실패 처리 포함.
  - rotation 문서 파서, fuzz 타깃, `trust rotate`: 0.4~0.5.
  - `[[revoked]]`와 `trust revoke`: 0.2~0.3.
  - 기존 연결 재검증과 만료 기한: 0.3~0.5.
  - 문면 상수와 문서: 0.1.

  `docs/ROADMAP.md` M16 크기 절의 (d) 가정(rotation UX 1.0~1.5, 강제 종료 0.3~0.5)보다 약 0.3~0.6ew 크다. 차이는 rotation 문서와 `[[revoked]]`다. rotation 문서를 빼는 대체안(대안 절)을 고르면 가정 범위 안으로 돌아온다. M16 재산정 합이 4ew를 넘는지는 ADR-0015·0016 결정 뒤 ROADMAP 크기 절이 판정한다.
