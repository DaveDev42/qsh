# ADR-0031: trust에서 peer를 빼거나 role을 줄이면, 장기 실행 프로세스(`qsh serve`, `qsh listen`, `qsh serve --to`)는 2초 안에 살아 있는 연결을 재검증해 더는 신뢰하지 않는 연결과 권한이 줄어든 연결을 닫는다. revocation 목록, rotation 문서, `trust rotate`, CA가 서명한 인증서의 개별 revoke는 두지 않는다

날짜: 2026-10-11 (개정 2026-10-12, 2026-10-13, 2026-10-14, 2026-10-15, 2026-10-16)
상태: 승인됨

개정 이력: 2026-10-15에 결정 7의 `qsh listen` 문장을 착지한 동작에 맞춰 고쳤다. 닫힌 등록은 등록표에서 즉시 빠지지 않고 연결 유실과 같은 정리 경로를 타서 `[listen].stale_retention` 동안 Stale로 남는다. 연결은 그대로 `0x1005`로 닫히고 재등록은 handshake에서 거부되므로 보안 성질은 같다. 같은 날 결정 3의 플랫폼 문단에 테스트 귀속을 더했다. 감시 코드는 플랫폼 분기가 없고, Windows 빌드의 `qsh serve`(inbound)는 M16에서 이 감시를 얻어 이식 가능한 테스트가 Windows 다리에서 돈다. `qsh listen`과 `qsh serve --to`는 오늘 unix 전용(`run_reverse_unix`, localctl)이라 그 재검증 테스트의 Windows 쌍둥이는 `listen`이 M19(ADR-0035 결정 14), `serve --to`가 M20(ADR-0035 결정 25)에서 열린다. 2026-10-16에 `serve --to` 쌍둥이의 귀속을 M19로 당겼다. M19가 Windows `qsh serve --to`의 게이트를 걷고 역방향 CI가 실제 Windows `serve --to`를 돌리며, 재검증 감시는 PTY와 무관하기 때문이다. 결정 내용은 바뀌지 않고, 결정 3의 플랫폼 문단에 적힌 "`serve --to`가 M20"은 이 줄이 이긴다. 2026-10-16에 위 줄의 `run_reverse_unix`와 `qsh listen`·`qsh serve --to`가 오늘 unix 전용이라는 서술을 착지한 상태로 읽는다. M19가 두 명령의 게이트를 걷고 함수를 플랫폼 공통의 `run_reverse_observed`로 바꿨으므로 `listen`·`serve --to` 쌍둥이 테스트는 Windows에서도 도는 대상이다. 결정 내용은 바뀌지 않는다.

개정 관계: 새 ADR이다. `docs/adr/README.md`의 예약 목록이 P1 계획(`docs/ROADMAP.md` §5)에서 이 번호를 인증서 rotation·revocation(M16 (d)) 자리로 잡아 두었고, 이 문서가 그 자리를 채운다. 2026-10-11 초안은 `trust.toml`의 `[[revoked]]` 목록, `qsh trust revoke`, `qsh identity rotate`(rotation 문서와 `--keep-key` 갱신), `qsh trust rotate`, 연결 재검증, 유효기간 기한을 한 묶음으로 제안했다. 2026-10-12 사용자 결정이 P1을 다시 짜면서 앞의 넷을 뺐다. 이 문서는 남은 하나, 곧 "trust를 거두면 이미 열린 연결도 닫는다"만 정한다. 빠진 것은 대안과 기각 사유 절에 사용자 결정으로 옮겼다.

- `docs/CLI.md` §6.11의 "`trust.remove`의 유효 범위" 문단과 §6.17 `trust_remove_scope`의 message·remedy를 결정 9대로 바꾼다. 이 문단과 문면은 M7 감사 개정이 고정한 것이고(M7 plan Step 2 (69dd788)), 바뀌는 것은 "이미 확립된 연결은 권한을 유지한다"는 문장과 remedy의 "(P1)"이다. `trust rename` 문단의 같은 문장도 결정 5대로 좁아진다.
- ADR-0012 결정 7("rename 뒤 이미 붙어 있는 연결은 권한을 유지한다")은 role이 없는 pin에 대해서는 그대로 서고, role이 있는 pin의 rename은 결정 5의 마지막 항목으로 연결을 닫는다. `acl.toml`은 이전처럼 기동 때 한 번만 읽는다.
- ADR-0045 결정 4의 "이미 만들어진 자원은 role이 줄어도 끝까지 간다. 그런 연결을 끊는 일은 ADR-0031(축소판)이 정한다"와 결정 12의 `trust_remove_scope` 문면은 이 ADR이 착지하면 이 ADR의 결정 5·9가 이긴다.
- ADR-0044의 SSH 부트스트랩 잔여 위험 문단이 가리키는 "ADR-0031(축소판)"은 이 문서다. 부트스트랩이 심은 pin도 `trust remove`로 거두면 이 결정이 적용된다.
- ADR-0045의 결정 4와 결과 절 위협 모델 문단은 2026-10-14 승인 때 이 ADR이 `remove`, role 축소, role이 있는 pin의 rename을 모두 다룬다고(결정 1·5) 맞춰 적었다. 두 ADR 사이에 남은 어긋남은 없다.
- ADR-0030(pin 방향)은 기각됐다. 이 ADR은 방향 필드나 `PeerRole` 확장을 입력으로 쓰지 않는다. 쓰는 `PeerRole`은 TLS 역할(상대가 서버인가 클라이언트인가) 둘뿐이고 지금 `QshPeerVerifier::verify_peer`가 이미 받는다.

승인 2026-10-14: 사용자 위임 결정("전부 다 알아서 진행해")으로 승인했다. 결정 2의 `qsh listen`이 role grant 비교를 하는지 열려 있던 문장(listen은 신뢰 자격만 본다고 적었으나 ADR-0045 결정 6에서 listen이 `host.reverse`를 인가하므로 비교 대상이다), 정방향과 역방향 사이의 닫는 범위 동등, Windows host에서의 동작, ADR-0045 의존 분기, `serve --to` 재dial 분류를 닫았다.

## 맥락

오늘 trust를 거두는 수단은 `trust remove` 하나이고, 그 효과는 다음 handshake부터다. `SharedTrustStore`가 handshake마다 `trust.toml`을 다시 읽으므로 새 연결은 거부된다. 이미 확립된 연결은 건드리지 않는다. `docs/CLI.md` §6.11이 이것을 "협상된 권한 전체를 연결이 끊길 때까지 유지한다"로 계약하고, doctor `trust_remove_scope`(info)가 늘 같은 문장을 보여 주며, `docs/design/threat-model.md` §7 h5가 이를 잔여 위험으로, §5의 g2가 테스트 `an_established_connection_survives_the_hosts_trust_remove`로 이 한계를 고정해 둔다. 손상된 peer를 즉시 끊는 수단이 없다는 뜻이다. 실무 대응은 프로세스 재시작인데 그러면 모든 세션이 끝난다(h12).

ADR-0045가 role을 도입하면서 같은 공백이 한 겹 더 생긴다. role은 요청마다 `trust.toml`에서 다시 읽으므로 `trust set-role`로 role을 줄이면 다음 요청부터 새 grant를 받지 못한다. 그러나 이미 열린 세션 attach 스트림, 터널, 진행 중인 전송은 판정 시점에 인가를 받았으므로 끝까지 간다. 그리고 `acl.toml` 행으로 받은 grant는 principal 문자열에 묶여 있고 principal은 연결에 붙은 채 바뀌지 않으므로, pin을 지운 뒤에도 그 연결의 새 요청은 행에 매칭되어 통과한다. 그래서 거둔 신뢰가 "다음 handshake부터"라는 문장과 실제 동작 사이에 구멍이 있다.

사용자가 정한 목표는 이것 하나다. trust를 거두거나 role을 줄이면 장기 실행 프로세스가 2초 안에 재검증해, 더는 신뢰하지 않는 연결과 grant가 줄어든 연결을 닫는다. 키 rotation, revocation 목록, CA가 서명한 인증서의 개별 무효화는 이번 범위가 아니다.

설계를 가르는 사실은 이렇다.

- 인가 결정이 나는 연결을 쥔 프로세스는 셋이다. `qsh serve`는 inbound 연결을 `Server::serve_connection`으로 받는다. `qsh serve --to`(`reverse/target`)는 controller에 outbound로 붙은 연결에서 같은 `Server::serve_control`을 돌린다. `qsh listen`(`reverse/listen`)은 target이 등록하러 붙은 inbound 연결을 쥐고, controller로서 그 위로 요청을 보낸다. listen은 등록 요청의 `host.reverse`를 `Authorizer`로 인가하므로(ADR-0045 결정 6, `reverse::admit`) 이 연결도 role grant를 갖는다. 셋 모두 자기 `SharedTrustStore` 핸들을 따로 연다.
- `qsh listen` 데몬 안의 localctl 브리지(`localctl/daemon.rs`)는 UDS와 peer credential로 신뢰를 정하고 `trust.toml`을 읽지 않는다. 거기서 relay되는 `LOCAL_CONTROL`/`LOCAL_STREAM`은 위 listen의 등록 연결 위에 얹힌다. 그래서 브리지 자체는 이 ADR의 대상이 아니고, 등록 연결이 닫히면 relay도 함께 끝난다.
- one-shot client(`exec`, 대화형 attach, client 쪽 터널)는 상대 host에게 요청을 보낼 뿐 상대의 요청을 인가하지 않는다. 신뢰를 거둔 host를 계속 쓰는 것은 그 client 사용자의 선택이고, `--supervise` 터널은 재수립 handshake에서 거부된다.
- `qsh_transport::Connection`은 principal, `auth_path`, peer fingerprint만 들고 있고 peer 인증서 chain은 handshake 뒤에 버린다. CA 경로의 재검증에는 chain이 필요하다. chain은 수 KB다.
- `SharedTrustStore::refresh`는 파일 바이트가 바뀌었을 때만 다시 파싱하고, 파싱에 실패하면 마지막 정상 snapshot을 쓴다. 파일이 없으면 빈 store로 읽는다(모두 거부). ADR-0045 결정 4는 파싱 실패 동안 role 판정을 전부 멈춘다.
- CLOSE 코드는 동결 밖이다(`docs/design/protocol.md` §16.3). 쓰는 값은 `0x1001`~`0x1004`이고 peer는 값에 따라 분기하지 않는다(§7).
- audit는 구조 필드만 싣고, 연결 수준 deny의 선례가 `handshake_rejected`다(`principal`과 `auth_path`가 `"-"`, `action`이 `connect`, `resource`가 거친 범주).

## 결정

1. 범위. 한 가지 불변식을 세운다. `trust.toml`의 내용이 바뀌면, 그 시점부터 2초 안에, 다음에 해당하는 모든 확립된 연결이 닫힌다. 이 연결이 지금 handshake한다면 거부될 연결, 처음과 다른 근거로만 받아질 연결, 연결이 얻은 role grant가 줄어든 연결이다. 이 ADR은 다음을 하지 않는다. 새 CLI 명령, 새 `qsh.cli/v1` 필드, 새 op, 새 wire 메시지, 새 audit 키, 새 `ErrorCode`를 더하지 않는다. 세션을 끝내지 않고, 다른 장비에 알리지 않으며, `trust.toml`의 모양을 바꾸지 않는다.

2. 재검증하는 연결. 결정 5의 판정을 받는 것은 맥락에 적은 세 가지다.
   - `qsh serve`가 받은 inbound 연결(`Principal::Pairing`으로 분류된 연결은 pairing 처리 중에만 살아 있어 제외한다).
   - `qsh serve --to`가 controller로 연 outbound 연결.
   - `qsh listen`이 받은 inbound 등록 연결.

   one-shot client 연결과 localctl UDS 연결은 재검증하지 않는다(맥락). 세 프로세스 모두 신뢰 자격 재검증(결정 5의 앞 세 항목)과 role grant 비교(마지막 항목)를 받는다. `qsh listen`의 등록 연결이 갖는 role grant는 `reverse` role이 주는 `host.reverse` 하나이고, `trust set-role <target> none`이나 target pin 삭제는 그 grant를 줄이므로 등록이 닫힌다. 이 비교를 빼면 `serve`에서는 role 축소가 연결을 닫는데 `listen`에서는 닫지 않는 방향 간 비대칭이 생긴다.

   정방향과 역방향의 동등은 이렇게 성립한다. 서비스 쪽 장기 프로세스가 쥔 연결은 방향과 상관없이 모두 닫는다. 정방향의 `serve`가 받은 client 연결, 역방향의 `serve --to`가 연 controller 연결, `listen`이 받은 target 등록 연결이 그것이다. 사용자가 터미널에서 직접 띄운 foreground client(`exec`, `attach`, `cp`, `-L`/`-R`/`-D`의 일회성 실행)의 dial 쪽 연결은 두 방향 모두 재검증하지 않는다. 역방향에서 controller 쪽 foreground client는 localctl로 `listen`에 붙으므로 그 연결도 해당하지 않고, 등록 연결이 닫히면 relay가 같이 끝난다. 어느 쪽이든 그 client 사용자가 신뢰를 거둔 상대를 계속 쓰는 것은 본인의 선택이고, `--supervise` 터널은 재수립 handshake에서 거부된다.

3. 변경 감지. 변경 감지는 프로세스 하나가 한 곳에서 한다.
   - `SharedTrustStore`에 단조 증가하는 세대 번호를 더한다. `refresh`가 snapshot을 실제로 바꿀 때마다(새로 파싱한 내용이든, 파일이 없어져 빈 store가 된 경우든) 세대를 올리고 `tokio::sync::watch` 채널로 알린다. 파싱에 실패해 마지막 정상 snapshot을 유지한 경우에는 세대를 올리지 않는다.
   - 프로세스 하나에 1초 간격 poll 작업을 하나 둔다. 이 작업은 `refresh`만 부른다. handshake의 `lookup_pin`이 먼저 `refresh`해 세대를 올릴 수도 있고, 그 경우 같은 알림이 즉시 간다.
   - 연결마다 감시 작업이 채널의 변경을 기다린다. 변경이 오면 결정 4의 판정을 연결마다 한 번 돌린다. 감시 작업은 그 연결을 서빙하는 작업과 같은 수명에 묶는다(`select!`로 같이 끝난다). 감시 작업만 죽고 연결이 남는 상태를 만들지 않는다.
   - 플랫폼 차이는 없다. 테스트의 Windows 쌍둥이는 `listen`이 M19, `serve --to`가 M20에서 열린다(2026-10-15 개정). poll과 `watch` 채널과 `Connection::close`는 모두 이식 가능한 코드이고, Windows host(ADR-0035 M20)의 `serve`·`listen`·`serve --to`도 같은 감시 작업을 쓴다. `trust.toml`을 바꾸는 쓰기가 원자적 rename이든 Windows의 교체 쓰기든 감시는 파일 내용 바이트만 본다.
   - 보장은 "`trust.toml`의 바이트가 바뀐 시점부터 2초 안에 닫힌다"이다. poll 1초와 연결당 판정 시간의 여유다. 파일 감시(inotify, FSEvents)와 프로세스 간 신호는 쓰지 않는다(근거 절).
   - 연결 수는 기존 연결 수 상한(ADR-0010)이 묶는다. 판정은 snapshot만 읽고 I/O가 없다. CA 경로의 chain 검증이 연결당 가장 비싼 일이고, 연결마다 독립 작업이라 한 작업이 모든 연결을 순서대로 돌지 않는다.

4. 재검증의 입력. `qsh-transport`의 `Connection`이 handshake 때 peer chain(DER)과 TLS 역할(`PeerRole`)을 보관하고, 연결이 수립된 뒤의 판정 근거를 다음 값으로 기록한다.
   - 기록값 `Established { principal, auth_path, role_grants }`. `principal`과 `auth_path`는 지금 `ConnCtx`에 있는 값 그대로다. `role_grants`는 수립 시점의 role grant 집합이다(결정 5).
   - `Connection::reverify(&self, evaluator: &dyn TrustEvaluator) -> Result<VerifiedPeer, RejectReason>`를 더한다. 보관한 chain과 역할로 handshake와 같은 `verify_peer` 코어를 다시 부른다. 새 검증 경로를 만들지 않는다. 그래서 유효기간, pin 조회, CA 경로의 chain 검증, pairing 열림 여부가 handshake와 같은 규칙으로 판정된다.
   - role grant를 구하는 함수는 ADR-0045 결정 4의 ⓡ 단계가 쓰는 함수 그대로다(`principal`이 `device:<name>`, `auth_path`가 `Pin`, 지금 `trust.toml`에 그 이름의 pin이 있고 fingerprint가 연결의 것과 같을 때만 그 pin의 role이 주는 action 집합). 두 곳이 같은 함수를 부르므로 인가 판정과 재검증이 서로 다른 답을 낼 수 없다. 이 함수는 연결의 기록된 principal과 fingerprint를 입력으로 받는다. 지금 pin의 이름이 아니다.

5. 닫는 조건. 감시 작업은 변경 알림마다 다음을 순서대로 본다. 하나라도 해당하면 연결을 닫는다.
   - `reverify`가 거부를 돌려준다(pin이 지워졌고 CA로도 받을 수 없음, `[[ca]]`가 지워졌음, `trust.toml`이 없어져 빈 store가 됨, 유효기간이 지남).
   - `reverify`가 돌려준 `auth_path`가 기록값과 다르다(pin으로 받았는데 이제 CA로만 받는 경우 포함). 신뢰 근거 자체가 바뀐 경우이기 때문이다.
   - `reverify`가 `Pairing`을 돌려준다.
   - `reverify` 자체가 판정을 못 한다. 보관한 chain이 비어 있거나 leaf를 다시 파싱할 수 없는 경우다. 판정할 수 없으면 신뢰하지 않는 것으로 친다(fail closed, 결정 6).
   - role grant가 줄었다. 새로 구한 `role_grants`가 기록값을 덮지 못한다. 덮는다는 것은 기록값의 모든 (action, 소유 축) 쌍에 대해 새 집합에 같은 action이 있고, 소유 축이 `any`이던 것이 `owned`로 좁아지지 않았다는 뜻이다(`any`는 `owned`를 덮는다). `trust set-role`이 role을 낮추는 경우, pin이 지워졌다가 role 없이 다시 등록된 경우, 같은 이름이 다른 fingerprint로 바뀐 경우가 모두 여기 든다. `trust rename`으로 role이 있는 pin의 이름이 바뀐 경우도 여기 든다. 연결에 붙은 principal은 옛 이름이라 `device:<옛 이름>`으로 찾는 pin이 없어 role grant가 비기 때문이다.

   닫지 않는 경우도 같이 못 박는다.
   - role grant가 같거나 넓어졌다. 넓어졌으면 닫지 않고 기록값만 새 집합으로 갈아 끼운다(그 뒤 줄어들면 그 시점의 값과 비교한다).
   - principal 문자열만 바뀌었고 기록값의 `role_grants`가 비어 있다(role 없는 pin의 `trust rename`, 별칭 순서 변경). ADR-0012 결정 7의 "rename 뒤 기존 연결은 권한을 유지한다"를 그대로 둔다. rename은 신뢰를 거두는 동작이 아니다. 이때 `acl.toml` 행은 옛 이름으로 계속 매칭되고 새 이름의 행은 재시작해야 반영된다(ADR-0012 결정 7 그대로).
   - `acl.toml` 행이 주는 grant. 행은 기동 때 한 번만 읽히고 바뀌지 않으므로 비교할 변화가 없다. 행으로 받은 권한은 신뢰 자격(pin 또는 CA)이 있는 동안만 쓰이며, 자격이 없어지면 위 조건으로 연결이 닫힌다.
   - `trust.toml`이 바뀌었지만 이 연결과 무관한 항목만 바뀐 경우(다른 pin 추가·삭제, 다른 pin의 role 변경). 판정을 돌려 위 조건에 하나도 걸리지 않으면 아무 일도 없다. 이 판정은 매번 돈다. 어느 항목이 연결과 관련 있는지를 미리 가리는 최적화는 하지 않는다.

6. fail closed 규칙.
   - 판정은 snapshot이 가리키는 지금의 `trust.toml`로 한다. 파일이 없거나 비어 있어 빈 store가 되면 `reverify`가 모든 연결에 거부를 돌려주므로 전부 닫는다. 이것이 handshake가 같은 상태에서 모두 거부하는 것과 같은 방향이다.
   - 파일을 읽지 못하거나(권한 변경 등) 파싱에 실패하면 `refresh`가 마지막 정상 snapshot을 유지하고 세대를 올리지 않는다. 그 동안 감시 작업은 돌지 않는다. 이것은 handshake가 같은 상태에서 마지막 정상 snapshot으로 판정하는 것과 같은 규칙이다. 단 role grant는 ADR-0045 결정 4가 파싱 실패 동안 요청마다 멈춘다. 그래서 그 상태에서 role로만 들어오던 연결은 닫히지 않아도 요청이 모두 거부되고, 행으로 받은 grant와 pin 인증은 마지막 정상 snapshot대로 유지된다. 파일이 다시 파싱되면 세대가 오르고 그때 비교가 돈다. 손으로 고치다 틀린 파일이 연결을 한꺼번에 끊는 일은 없다. 반대로 틀린 파일이 이전의 넓은 role을 살려 두는 일도 요청 단계에서 막혀 있다.
   - 파싱 실패가 길게 이어지는 동안 `trust remove`가 반영되지 않는 창이 생긴다. 이 창은 handshake와 같다(파싱 실패 중에는 마지막 정상 snapshot으로 새 연결도 받는다). 이 사실은 `docs/CLI.md` §6.11에 적고 잔여 위험으로 둔다(결과 절).
   - 닫는 동작은 audit 기록과 무관하게 먼저 한다. 연결 수준 deny는 이미 좁히는 쪽이고 `handshake_rejected`와 같은 예외다. audit 쓰기가 fail-closed로 실패해도 연결은 닫히고, 그 사실은 로그 줄로만 남는다.

7. 닫는 방법. 새 CLOSE 코드 `0x1005`(`CLOSE_CODE_TRUST_WITHDRAWN`)를 `crates/qsh-transport/src/endpoint.rs`의 다른 CLOSE 상수 옆에 정의하고, `Connection::close(0x1005, b"trust withdrawn")`로 닫는다. reason 문자열은 고정이고 어떤 principal이나 사유도 싣지 않는다. peer는 값에 따라 분기하지 않는다(§7). 닫힌 연결 위의 세션은 오늘의 연결 유실과 같은 규칙으로 detach된다. 신뢰를 거둔 peer는 다시 handshake할 수 없어 resume으로 돌아오지 못하고, role만 줄어든 peer는 다시 붙어 줄어든 grant로 resume할 수 있다. 열린 터널, 진행 중인 전송, 열려 있는 스트림은 연결과 함께 끝난다. 거둔 principal의 세션을 즉시 종료하는 것은 이 ADR의 결정이 아니다.
   - `qsh serve --to` 쪽은 연결이 닫히면 지금의 재dial 루프로 돌아간다. 이 루프는 로컬이 `0x1005`로 닫은 경우와 상대가 `0x1005`로 닫은 경우를 모두 일시적 네트워크 유실이 아니라 신뢰 철회로 분류하고, 로그 한 줄만 남기며, 일시 유실용 빠른 재dial 경로를 타지 않고 handshake 거부와 같은 일반 backoff로 간다. 재dial은 handshake에서 거부되거나(신뢰가 거둬진 경우) 줄어든 grant로 받아들여진다(role만 줄어든 경우).
   - `qsh listen` 쪽은 등록 연결이 닫히면 그 위의 relay가 끝나고, 등록은 연결 유실과 같은 정리 경로(`loss_cause = TlsRejected`)를 타서 `[listen].stale_retention`이 지날 때까지 등록표에 Stale로 남은 뒤 sweeper가 거둔다. 등록표에서 즉시 빼지 않는 것은 철회와 일시 유실을 가르는 별도 경로를 만들지 않기 위해서이고, 연결이 닫혔고 target이 다시 handshake할 수 없어 보안상 차이는 없다. target이 다시 등록하려 하면 listen의 verifier가 handshake에서 거부하고 `handshake_rejected`가 남는다.

8. audit. 닫을 때 연결 수준 deny 한 줄을 남긴다. 키 집합은 바뀌지 않는다(아홉 키와 ADR-0045 결정 16의 optional `role`, 여기서는 `role` 키를 싣지 않는다).
   - 새 생성자 `AuditRecord::connection_withdrawn(principal, auth_path, peer_addr, reason)`를 `handshake_rejected` 옆에 둔다. `request_id`는 `"-"`, `action`은 `connect`, `decision`은 `deny`, `rule`은 `null`, `principal`과 `auth_path`는 수립 때의 값, `peer_addr`는 연결의 현재 주소다.
   - `resource`는 닫은 이유의 거친 범주 둘 중 하나다. `trust_withdrawn`은 신뢰 자격을 잃은 경우(`reverify` 거부, `auth_path` 변화, `Pairing`, 판정 불능), `grants_reduced`는 신뢰는 남았고 role grant가 줄어든 경우다. 어느 pin이 어떻게 바뀌었는지는 싣지 않는다. 운영자가 `trust.toml`과 로컬 trust 쓰기 audit 레코드(ADR-0012 결정 7, ADR-0045 결정 8)로 상관 짓는다.
   - 이 두 `resource` 값은 `docs/CLI.md`와 `docs/design/architecture.md` §6의 audit `resource` 범주 목록에 같은 커밋에서 오른다.

9. 문면. trust를 좁히는 명령(`trust remove`, role을 낮추는 `trust set-role`, role이 있는 pin의 `trust rename`)의 사람용 출력과 doctor 고지는 세 가지를 빠짐없이 말한다. 이 규율은 사람용 출력과 문서에만 적용된다. JSON 필드는 바뀌지 않는다.
   - 언제 적용되는가: 새 연결에는 다음 handshake부터, 실행 중인 `qsh serve`/`qsh listen`/`qsh serve --to`가 연 연결에는 2초 안에.
   - 어디에 적용되는가: 이 장비에서만. 다른 장비에 알리지 않는다.
   - 무엇을 하지 않는가: 세션을 끝내지 않는다. 닫힌 연결 위의 세션은 detach되고, 신뢰가 남은 peer는 다시 붙어 이어 갈 수 있다.

   문장은 `qsh-core`의 상수 한 벌이고 `qsh-cli`는 받은 것을 쓰기만 한다. `docs/CLI.md`가 그 상수를 축자 인용하고, `cli_md_quotes_the_trust_remove_scope_diagnostic_verbatim`과 같은 형식의 테스트가 바이트 일치를 고정한다. `trust_remove_scope`는 code와 status(`info`)와 노출 조건("pin이 하나라도 있으면")을 그대로 두고 message와 remedy만 이 규율로 바꾼다. remedy에서 "(P1)"과 재시작 권고가 빠지고, 신뢰는 장비마다 따로 거두므로 다른 장비에서도 같은 명령을 실행하라는 안내가 들어간다. 오늘 `docs/CLI.md` §6.9의 `--supervise` 설명("`trust remove`는 이미 살아 있는 connection 위의 터널을 멈추지 않는다")과 §6.14의 같은 문장, README "Known limitations"의 해당 줄도 같은 커밋에서 새 동작으로 고친다.

10. §16.2와의 관계. 이 ADR은 검증 경로를 바꾸지 않는다. 같은 `verify_peer` 코어를 handshake 뒤에 같은 입력으로 다시 부른다. 수용 결과를 좁히는 것도 넓히는 것도 새 규칙이 아니라 지금 `trust.toml`의 내용을 반영할 뿐이고, pin → CA → pairing의 상대 순서와 principal 유도 규칙은 그대로다. wire에 새 바이트는 없다. 새 CLOSE 코드는 §16.3이 동결 밖에 둔 대역이다. 구현 커밋은 `docs/design/protocol.md` §3에 "확립된 연결은 trust 변경 뒤 재검증된다"는 한 문장을 더하고, §16.3의 CLOSE 코드 목록과 §7·§16.5의 값 범위 서술에 `0x1005`를 반영한다. `0x1003`이 이름 둘로 쓰이는 지금의 서술은 이 ADR이 건드리지 않는다.

## 근거

수단을 연결 재검증 하나로 좁힌 이유는 사용자가 원한 것이 "거둔 신뢰가 곧 효과를 내는 것"이기 때문이다. ADR-0045로 신뢰 등록이 곧 권한 부여가 되었으니, 등록을 지우거나 role을 낮추는 일도 곧 효과가 나야 대칭이 맞는다. 키 rotation이나 revocation 목록은 신뢰를 거두는 새 수단이지만, 지금 있는 수단(`trust remove`, `trust set-role`)이 이미 모든 경로를 거둘 수 있다면 새 수단은 필요 없다. 결정 3·5가 그 수단이 즉시 효과를 내도록 하는 전부다.

판정을 `verify_peer` 재호출로 하는 이유는 handshake와 재검증이 어긋나는 틈을 만들지 않기 위해서다. 새 검사를 따로 쓰면 유효기간, CA chain, pairing 열림 규칙이 두 곳에 있게 되고 한쪽만 고쳐지는 사고가 난다. role grant 비교도 ADR-0045 ⓡ 단계와 같은 함수를 쓰는 이유가 같다.

닫는 조건에 "role grant가 줄었다"를 둔 이유는 ADR-0045의 요청 단위 재읽기만으로는 이미 열린 자원이 남기 때문이다. 요청마다 읽는 쪽은 새 요청을 즉시 막는다. 연결을 닫는 쪽은 이미 열린 터널과 세션 스트림을 끝낸다. 둘이 합쳐야 "role을 낮췄는데 터널은 계속 열려 있다"가 없어진다. 넓어지는 변화에 기록값만 갈아 끼우는 이유는 role을 올렸다 낮추는 운영이 흔하고, 올린 동안 연결이 얻은 자원이 낮춘 뒤에도 남지 않아야 하기 때문이다. 그래서 처음 role로 돌아오는 경우에도 올렸던 동안의 기록값을 기준으로 닫힌다. 재접속 비용이 작아서 이쪽이 안전하다.

rename을 role이 있는 pin에서만 닫는 이유는 두 요구가 부딪히기 때문이다. role이 있는 pin의 rename은 연결의 principal로 찾는 pin이 사라지게 만들어(ADR-0045 결정 4의 이름·fingerprint 대조) role grant가 비게 된다. 이 상태의 연결을 그대로 두면 "role을 거둔 것처럼 보이는데 열린 자원은 살아 있다"가 되고, 그 연결의 새 요청은 role로는 받지 못하고 옛 이름의 `acl.toml` 행으로만 받는다. 이름이 바뀌면서 role이 사라진 연결을 열어 두는 것보다 닫아서 새 이름으로 다시 붙게 하는 쪽이 일관된다. role 없는 pin의 rename은 신뢰를 거두는 일이 아니므로 ADR-0012 결정 7을 개정하지 않는다.

1초 poll을 고른 이유는 세 프로세스가 공유하는 알림 통로가 없기 때문이다. localctl UDS는 `qsh listen` 데몬의 것이고 `qsh serve`에는 없다. 파일 감시는 플랫폼마다 다르고, 원자적 rename으로 쓰는 `trust.toml`을 보려면 디렉터리 감시가 필요하다. 이 저장소는 이미 handshake마다 파일을 통째로 읽어 비교하고 있어서 poll은 그 비교를 시계에 한 번 더 거는 것이다. 세대 번호와 `watch` 채널을 두는 이유는 poll 작업 하나와 연결별 감시가 파싱 결과를 공유해, 연결 수가 많아도 파일을 한 번만 읽고 파싱하기 위해서다. 2초는 `REDIAL_DEADLINE`과 같은 크기라 운영자가 기억할 숫자가 하나다.

파싱 실패 중 연결을 닫지 않는 이유는 손으로 `trust.toml`을 고치다 생긴 일시적 오타가 모든 연결의 단절이 되어서는 안 되기 때문이다. 이 상태에서 위험한 쪽(오타가 넓은 role을 살려 두는 것)은 ADR-0045가 요청 단계에서 이미 막는다. 연결을 닫아도 얻는 안전이 없다.

닫기를 audit보다 먼저 하는 이유는 audit 장애가 신뢰 철회를 막는 모양이 되면 안 되기 때문이다. 좁히는 동작의 실패를 막는 것은 열어 두는 방향으로 실패하는 것이다.

## 대안과 기각 사유

아래 항목 가운데 처음 넷은 2026-10-11 초안이 담았던 것이고, 2026-10-12 사용자 결정으로 이번 범위에서 뺐다. 나머지는 이 결정을 만들며 검토한 대안이다.

- `[[revoked]]` 목록과 `qsh trust revoke`: 사용자 결정으로 뺐다. 초안은 fingerprint를 모든 경로에서 거부하는 `trust.toml` 표를 두고, 같은 fingerprint의 pin이 있어도 pin은 지우지 않는 별도 명령으로 두었다. 뺀 뒤의 영향은 이렇다. 상대를 pin으로도, 그 상대가 속한 CA로도 신뢰하는 장비에서 `trust remove <pin>`만 하면 같은 키가 CA 경로로 계속 들어온다. 그 키를 막으려면 CA 항목까지 지워야 한다(`trust remove`는 같은 이름의 `[[peer]]`와 `[[ca]]`를 둘 다 지운다. 이름이 다르면 각각 지운다). 이 공백은 위협 모델 h4에 남는다.
- 키 rotation 문서, `qsh identity rotate`(`--keep-key` 갱신 포함), `qsh trust rotate`: 사용자 결정으로 뺐다. 초안은 옛 키로 서명한 문서로 pin을 새 키로 옮기고 옛 키를 revoke하는 경로였다. 뺀 뒤의 영향은 이렇다. 키가 새거나 만료가 닥쳤을 때의 복구는 지금과 같이 identity 삭제, 재 init, 모든 peer의 재 pinning이다. 문면이 `cert_expired`/`cert_expiring_soon`의 remedy에 지금 적혀 있는 대로 남는다. 10년 유효기간이라 급하지 않고, `qsh init --import-ssh-key`로 키를 SSH와 나눠 쓰는 identity의 수명 결합(h29)도 그대로 남는다. 새 fuzz 타깃, 새 op, 새 fixture, 새 man 페이지가 없어진다.
- CA가 서명한 인증서의 개별 revoke와 CRL·OCSP·전파: 사용자 결정으로 뺐다. qsh에는 중앙이 없고(PRD §12), CRL은 배포 지점이 곧 중앙이다. CA 개인키가 샌 경우의 처방은 오늘과 같이 그 CA를 신뢰하는 각 장비에서 `trust remove <ca-name>`을 실행하는 것이고, 이 ADR로 그 CA 경로의 기존 연결이 2초 안에 닫힌다.
- leaf 유효기간(`not_after`)을 기한으로 건 연결 만료: 이번 범위에서 뺐다. `reverify`가 유효기간을 보므로 trust 변경 알림이 오면 만료된 연결은 닫힌다. 변경 없이 만료만 닥친 연결을 닫는 기한은 두지 않는다. leaf는 10년이라 평소에 일어나지 않는다. 필요해지면 시계 기한 하나를 결정 3의 감시 작업에 얹으면 된다.
- 알림 전용 신호(`trust remove`가 실행 중인 프로세스에 직접 신호를 보낸다): 기각. `qsh serve`에는 localctl이 없고, 같은 config 디렉터리를 쓰는 프로세스를 찾는 일 자체가 새 IPC 표면이다(threat-model §3 진입점). poll은 표면을 늘리지 않는다.
- 파일 감시(inotify, FSEvents): 기각. 플랫폼마다 다르고 원자적 rename 쓰기에는 디렉터리 감시가 필요하다. 2초 보장에 poll로 충분하다.
- 인가 판정마다 신뢰 자격을 확인한다(choke point 입력 변경): 기각. `Authorizer::check`의 입력을 연결 자격까지 넓히면 평가기의 순수성과 `acl check`의 동등성 계약이 바뀐다. 새 요청이 통과할 수 있는 창은 2초이고, 이미 열린 자원은 어차피 연결을 닫아야 끝난다. 연결을 닫는 쪽이 둘을 한 번에 처리한다.
- principal 문자열만 바뀐 연결도 닫는다: 기각. ADR-0012 결정 7을 개정해야 하고 이름 정리 한 번이 모든 peer의 단절이 된다. role grant가 있는 pin의 rename만 결정 5의 마지막 항목으로 닫는다.
- 신뢰를 거두면 세션도 즉시 종료한다: 기각. 신뢰가 남은 채 role만 줄어든 peer는 다시 붙어 이어 가야 한다. 거둔 principal의 세션 종료는 `qsh session close`와 ADR-0033(세션 관리)의 몫이다.
- 연결마다 따로 poll한다(프로세스 poll 작업과 세대 번호 없이): 기각. 연결 수만큼 파일을 읽고 파싱한다.
- 재검증이 `trust.toml` 파싱 실패 중에도 모든 role 연결을 닫는다: 기각. 결정 6의 이유 그대로다.

## 결과

- 계약. `qsh.cli/v1`과 `qsh.event/v1`은 바뀌지 않는다. 새 op, 새 필드, 새 `ErrorCode`, 새 wire 메시지, 새 audit 키가 없다. 새 fixture도 없다. 바뀌는 것은 문서 문면과 doctor 두 문자열이다.
  - `docs/CLI.md` §6.11의 `trust.remove`의 유효 범위 문단, `trust rename` 문단의 "이미 확립된 연결은 영향받지 않는다" 문장(role이 있는 pin은 닫힌다), `trust set-role` 절(ADR-0045가 더하는 절에 결정 9의 세 문장), §6.9와 §6.14의 `--supervise` 설명, §6.17의 `trust_remove_scope` 인용과 표 설명.
  - README "Known limitations"의 `trust remove` 줄.
  - `docs/design/architecture.md` §6의 audit `resource` 범주에 `trust_withdrawn`, `grants_reduced`.
  - `docs/design/protocol.md` §3 한 문장, §16.3의 CLOSE 코드 목록, §7과 §16.5의 값 범위 문장.
  - `crates/qsh-core/src/doctor.rs`의 `TRUST_REMOVE_SCOPE` message와 remedy.
- 구조. `qsh-transport`가 chain 보관, `Connection::reverify`, `CLOSE_CODE_TRUST_WITHDRAWN`을 갖는다(QUIC 스택을 이름 짓지 않는 중립 타입만 쓴다. ADR-0043 결정 3). 세대 번호, poll 작업, 연결별 감시, role grant 비교는 `qsh-core`가 갖는다. `qsh-cli`는 문면을 쓰기만 한다. `xtask arch`의 방향과 경로 범위 금지는 바뀌지 않는다. 새 모듈이 범위 금지 목록에 들어가야 하는지는 구현 커밋이 판단하고 `xtask/src/arch.rs`를 같은 커밋에서 고친다.
- 고정할 테스트(이름은 구현 때 확정하되 성질은 이대로).
  - 연결 닫힘. 실제 QUIC 연결로, `qsh serve` inbound 연결이 `trust remove` 뒤 2초 안에 `0x1005`로 닫히고 audit 한 줄(`resource` `trust_withdrawn`)이 남는다. `qsh serve --to` outbound 연결과 `qsh listen` 등록 연결도 같다. tokio 시간을 멈춘 상태에서 poll 1초 틱 하나 안에 닫힘을 단언해 2초 보장을 시계로 고정한다.
  - 기존 테스트 교체. `crates/qsh-cli/tests/it/trust_lifecycle_live.rs`의 `an_established_connection_survives_the_hosts_trust_remove`는 g2가 한계 자체를 고정하던 테스트다. 이 ADR이 착지하면 그 단언이 정반대가 되므로 같은 커밋에서 `an_established_connection_is_closed_within_two_seconds_of_trust_remove`로 바꾸고 threat-model g2의 설명도 고친다.
  - 경로별. pin 경로 연결과 CA 경로 연결 각각이 `trust remove`로 닫힌다. `[[ca]]`를 지우면 CA 경로 연결이 닫히고 pin 경로 연결은 살아 있다. pin을 지웠는데 CA로 받을 수 있게 남아 있으면 `auth_path` 변화로 닫힌다. `trust.toml` 삭제는 모든 연결을 닫는다.
  - `qsh listen` 등록 연결의 role. target pin의 role을 `reverse`에서 `none`으로 낮추면 등록 연결이 `grants_reduced`로 닫히고, `reverse`로 올리거나 같은 값이면 닫히지 않는다.
  - role. `trust set-role`이 role을 낮추면(`full`에서 `exec`, `full`에서 `tunnel`로 소유 축이 `any`에서 `owned`로 좁아지는 경우 포함) 연결이 `grants_reduced`로 닫히고, 올리면 닫히지 않는다. 올렸다 낮추면 올린 동안의 기록값 기준으로 닫힌다. role이 있는 pin의 `trust rename`은 닫히고, role이 없는 pin의 `trust rename`과 별칭 순서 변경은 닫히지 않는다.
  - 다른 항목. 이 연결과 무관한 pin의 추가·삭제·role 변경은 연결을 닫지 않는다. `acl.toml` 행으로만 인가되던 연결은 pin이 남아 있는 동안 닫히지 않는다.
  - fail closed. `trust.toml`을 파싱할 수 없는 내용으로 바꾸면 연결은 닫히지 않지만 role 요청은 모두 거부되고(ADR-0045), 다시 고치면 세대가 오르고 비교가 돈다. `reverify`가 판정하지 못하는 연결(chain을 비운 합성 연결)은 닫힌다. audit 쓰기를 실패시켜도 연결은 닫힌다.
  - 닫힘 뒤. 닫힌 연결 위의 세션이 detach되어 있고, 신뢰가 남은 peer는 다시 붙어 resume하고 줄어든 grant를 받는다. 신뢰를 거둔 peer는 handshake가 거부된다. `--supervise` 터널은 재수립 거부 뒤 `gave_up`으로 끝난다.
  - 문면. 결정 9의 상수가 `docs/CLI.md`와 바이트 일치한다. `record_has_only_structural_fields`는 키 집합이 그대로임을 계속 단언한다.
- `docs/design/threat-model.md`.
  - §5 g2: 위 테스트로 설명을 바꾼다.
  - §4 B 표: "신뢰를 거둔 peer가 기존 연결로 권한을 유지한다" 행을 더한다. 통제는 결정 3·5, 핀은 위 연결 닫힘 테스트다. 잔여는 h5다.
  - §7의 h4·h5를 함께 읽으라는 문단("손상된 peer를 즉시 끊는 수단이 v1에는 없다")은 "2초 안에 끊는다"로 고친다.
  - §7 h5: "trust 변경 뒤 최대 2초의 창"으로 줄인다. 이 창은 파싱 실패 중에는 반영되지 않는 handshake와 같은 한계를 함께 적는다. 새 잔여 위험 한 줄은 이것이다. 닫는 것은 연결이지 세션이 아니다. 신뢰가 남은 peer는 다시 붙는다.
  - §7 h4: "CA가 서명한 인증서를 개별로 무효로 하는 수단이 없다. CA 전체를 `trust remove`로 거두는 것이 유일한 처방이고, 기존 연결은 2초 안에 닫힌다"로 고친다.
  - §7 h29: 키 rotation 경로가 없다는 설명은 그대로 둔다.
- 잔여 위험. 변경 알림 뒤 연결이 닫히기까지 최대 2초 동안 그 연결의 요청은 행으로 받은 grant로 통과한다(role grant는 ADR-0045로 요청마다 즉시 멈춘다). 한 장비에서 거둔 신뢰는 그 장비에서만 효과가 난다. `trust.toml`을 읽을 수 없거나 파싱할 수 없는 동안은 거둔 신뢰가 반영되지 않는다.
- ADR 의존. 이 ADR은 ADR-0045의 role 조회 함수를 공유하므로 ADR-0045가 먼저 또는 같이 착지해야 role grant 비교가 의미를 갖는다. ADR-0045도 2026-10-14에 같이 승인됐으므로 role grant 비교(결정 5의 마지막 두 항목)는 이 ADR의 범위에 확정으로 들어 있다. M16 (b)의 착수 조건은 M15 (a)(ADR-0045 role) 착지이고, 그 순서가 지켜지지 않은 채 이 ADR이 먼저 착지하는 일은 없다.
- 크기. 0.9~1.35ew. ADR 0.1, 구현 0.8~1.25. 구현 내역은 다음과 같다.
  - `qsh-transport`의 chain 보관, `reverify`, CLOSE 상수: 0.1~0.15
  - `SharedTrustStore`의 세대 번호, `watch` 채널, poll 작업: 0.1~0.2
  - role grant 비교와 ADR-0045 조회 함수 공유: 0.1~0.15
  - 세 프로세스에 감시 작업을 붙이고 재dial 분류를 고치는 일: 0.2~0.35
  - audit 생성자, 문면 상수, doctor, 문서: 0.1~0.15
  - 테스트(실제 QUIC 연결 셋, 시간 고정, 기존 테스트 교체): 0.2~0.25

  `docs/ROADMAP.md` M16 (b)의 크기와 §5.2 크기 표의 M16 행은 이미 이 값을 쓴다. 2026-10-11 초안의 2.2~2.8ew에서 rotation·revocation 몫 1.3~1.5ew가 빠졌다.
