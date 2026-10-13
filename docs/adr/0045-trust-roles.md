# ADR-0045: trust pin에 role 하나를 두어 신뢰 등록이 곧 권한 부여가 되게 한다. `acl.toml`은 세밀한 제어용 선택 사항으로 남고, role이 없는 기존 pin은 지금처럼 `acl.toml`만 따른다

날짜: 2026-10-12 (개정 2026-10-13)
상태: 승인됨
승인 2026-10-14: 사용자 위임 결정("전부 다 알아서 진행해")으로 승인했다. role을 줄일 때 열린 연결을 닫는 일을 ADR-0031이 맡는다는 점, 역방향 SSH 부트스트랩의 role 예외, 세 OS에서 같은 role 의미, 판정마다 읽는 비용의 대체 경로를 못 박아 남은 미정 항목이 없다.

개정 관계: 새 ADR이다. 2026-10-12 사용자 결정("권한 설정을 보다 간소화… 파일 단위로 복잡하게 관리하는게 귀찮아")을 받아 P1을 다시 짠 결과 M15에 이 ADR과 ADR-0029(개정판, `qsh cp`)가 함께 놓인다. 다음 결정들을 개정한다.

- ADR-0017: 결정 1(어떤 명령도 `acl.toml`을 쓰지 않는다)은 그대로 재확인한다. role은 `trust.toml`에 산다. 맥락 절의 전제 "페어링이 상대를 pin해도 그 상대는 `acl.toml` 행이 생길 때까지 아무 action도 얻지 못한다"는 새 pin에 대해 더는 참이 아니다. 결정 2의 `acl_principal_unmatched`와 `acl_ca_auth_path_missing`은 나오는 조건이 바뀌고(결정 12), 결정 3의 페어링 직후 고지는 문면이 바뀐다(결정 13). 결정 5(TOFU 없음)는 그대로다.
- ADR-0025: 결정 1(writer 없음)은 `acl.toml`에 대해 그대로다. 결정 2의 실효 action 집합은 role이 주는 action과 행이 주는 action의 합집합으로 넓어지고, 출력에 optional 필드가 는다(결정 11). 결정 3의 "규칙을 두 번 구현하지 않는다"는 role 판정에도 그대로 적용된다. 대안 절이 `acl grant`/`acl revoke`를 기각한 두 이유(잠금 규율 없음, 재시작 간극)는 `trust.toml`에는 해당하지 않으므로, 이 ADR은 권한을 바꾸는 명령을 `trust` 쪽에 둔다(근거 절).
- ADR-0024: 결정 4(ACL 단계는 행을 인쇄하고 검증만 한다)와 결정 9의 `complete` 조건이 role로 인가되는 경우를 받아들이도록 바뀐다(결정 14). 결정 3(`acl.toml`을 쓰지 않는다)과 결정 6(자동 신뢰 없음)은 그대로다.
- ADR-0038: 면제 목록과 판정 규칙은 그대로다. 면제 대상인 `acl_policy_missing`이 나오는 조건이 좁아질 뿐이다(결정 12).
- ADR-0029(개정판): `file.read`/`file.write`를 `full` role이 준다. 그 경로 범위와 `[[acl]]` 행 `paths`의 관계는 결정 5가 정하고, 상태 경로 거부(ADR-0029 결정 5)는 role로도 끌 수 없다. ADR-0029 결정 14의 "audit 키 집합은 아홉 그대로"는 이 ADR의 optional 키 하나만큼 바뀐다(결정 16).

계약 문서 가운데 바뀌는 것은 `docs/PRD.md` §9(인가 모델 서술), `docs/CLI.md` §2.4·§2.5·§6.11·§6.12·§6.13·§6.15·§6.17·§6.19·§6.20, `docs/design/architecture.md` §6·§7이다. wire 프로토콜(`docs/design/protocol.md`)은 바뀌지 않는다.

## 맥락

오늘 원격 peer가 무엇을 할 수 있는지는 `acl.toml` 하나가 정한다. pin은 신원만 정하고 권한은 주지 않는다. 그래서 장비 하나를 들이려면 두 번 손이 간다. `qsh pair` 또는 `qsh trust add`로 pin하고, 그 이름을 부르는 `[[acl]]` 행을 손으로 쓰고, `qsh serve`를 재시작한다. ADR-0017은 이 마찰을 doctor 진단과 페어링 직후 고지로 덜어 냈지만 마찰 자체는 그대로 두었다. ADR-0029 초안이 파일 action에 `paths` 범위를 더하면서 손으로 관리할 것은 더 늘었다. 사용자는 이 상태를 받아들이지 않았다. 1인 또는 소수 장비 사용자가 원하는 모델은 SSH의 `authorized_keys`다. 키를 등록하면 그 계정으로 들어온다.

설계를 가르는 사실은 이렇다.

- action 어휘는 `Action::ALL`의 11종이다(`crates/qsh-core/src/acl/mod.rs`). `exec.run`, `session.open`, `session.list`, `session.attach`, `session.control`, `host.reverse`, `forward.local`, `forward.remote`, `forward.socks`, `file.read`, `file.write`. `Action::is_always_denied`는 오늘 `forward.socks`, `file.read`, `file.write`를 어떤 규칙보다 먼저 거부하고, ADR-0029가 착지하면 `forward.socks` 하나만 남는다.
- `acl.toml` 문법은 allow 전용이다. deny 행이 없고 평가는 first-match이며, 평가 순서는 ① 항상-deny 게이트, ② principal 정확 일치와 `auth_path` 일치, ③ action 패턴, ④ `scope`다(`crates/qsh-core/src/acl/policy.rs` 모듈 doc). 아무 행에도 맞지 않으면 deny다. 파일이 없거나(`PolicyLoad::Missing`) 파싱되지 않으면(`PolicyLoad::Invalid`) production `Authorizer`는 `DenyAll`이다. 두 상태는 오늘 같은 결과를 내고 같은 시작 진단을 낸다.
- `acl.toml`은 프로세스 시작 때 한 번 읽히고 쓰는 명령이 없다(ADR-0017 결정 1, ADR-0025 결정 1). `trust.toml`은 반대다. `Ops::trust_add`, `Ops::trust_rename` 같은 경로가 `FileLock` 아래에서 load·mutate·save를 하고, `SharedTrustStore::refresh`가 handshake마다 파일을 다시 읽는다(`crates/qsh-core/src/trust/mod.rs`). 다시 읽다 파싱에 실패하면 마지막 정상 snapshot을 유지한다.
- pin 하나는 `[[peer]]` 항목 하나다. 필드는 `name`, `fingerprint`, `address`, `added_at` 넷이고 타입은 `qsh-proto`의 `TrustPeer`다. 같은 타입이 `trust.list`·`trust.add` 등의 JSON `data`에도 그대로 실린다. serde 속성에 `deny_unknown_fields`가 없어서 모르는 키는 읽을 때 버려진다.
- pin 경로 principal은 `device:<name>`이고 `<name>`은 pin의 이름이다. CA가 발급한 leaf도 SAN으로 같은 모양의 `device:<name>`을 낼 수 있다. 둘을 가르는 것은 `AuthPath`(`Pin`/`Ca`)뿐이다(`crates/qsh-core/src/acl/mod.rs` 모듈 doc). `ConnCtx`는 principal, `auth_path`와 함께 검증된 leaf의 `peer_fingerprint`를 갖지만 지금 이 fingerprint는 ACL 입력이 아니다.
- pin에는 방향이 없다. 같은 pin이 outbound dial 검증과 inbound 인증 양쪽에 쓰인다(ADR-0017 맥락). 방향 축을 더하자던 ADR-0030은 2026-10-12에 폐기됐다.
- 권한이 이미 `acl.toml` 밖에서 넓어지는 경로가 있다. `trust rename`은 principal 문자열을 바꿔 행 매칭을 바꾼다(threat model B10). 페어링한 상대가 기존 행의 이름으로 pin되면 그 행을 물려받는다(B12).
- audit 레코드는 키 아홉 개를 갖는다(`record_has_only_structural_fields`). 원격 판정이 아닌 로컬 trust 조작으로는 `trust rename`만 `AuditRecord::local_op`으로 레코드를 남기고, 그 순서는 lock → load → mutate → audit → save다. audit을 쓰지 못하면 rename도 일어나지 않는다.
- `crates/qsh-core/src/acl/load.rs`에는 이미 `Role`이라는 이름의 enum이 있다. `Serve`/`Listen` 두 값으로 시작 진단의 예시 행을 고르는 데 쓴다. `qsh setup <role>`의 role(ADR-0012 결정 1, ADR-0024 결정 2)도 장비의 역할을 뜻한다. 이 ADR의 role은 둘과 다른 개념이다.

## 결정

1. 신뢰 등록이 곧 권한 부여다. pin 하나에 role 하나를 둔다. 그 pin으로 인증한 peer는 role이 주는 action 집합을 받는다. `acl.toml`은 세밀한 제어가 필요할 때만 쓰는 선택 사항으로 남는다. 단일 choke point(`Authorizer::check`), 자원 생성 전 인가, 균일한 거부 문면(`PERMISSION_DENIED_MESSAGE`), fail-closed audit은 그대로다.

2. role은 고정된 여섯 값이다. 새 값을 더하거나 매핑을 바꾸려면 새 ADR이 필요하다. 사용자 정의 role은 두지 않는다.

   | role | 주는 action | 소유 축 |
   |---|---|---|
   | `full` | `exec.run`, `session.open`, `session.list`, `session.attach`, `session.control`, `forward.local`, `forward.remote`, `file.read`, `file.write`, `host.reverse` | any |
   | `exec` | `exec.run`, `session.open`, `session.list`, `session.attach`, `session.control` | any |
   | `tunnel` | `forward.local`, `forward.remote` | owned |
   | `read-only` | `session.list`, `session.attach` | any |
   | `reverse` | `host.reverse` | 해당 없음 |
   | `none` | 없음 | 해당 없음 |

   - `forward.socks`는 어느 role에도 없다. 항상-deny 게이트(평가 ①)가 role보다 먼저 돌고, `-D`는 지금처럼 `forward.local`로 인가된다(ADR-0019 결정 6).
   - `full`의 `file.read`/`file.write`는 ADR-0029가 항상-deny에서 그 둘을 풀 때 비로소 효과가 난다. 그 전까지는 표에 있어도 ①이 막는다. 같은 M15 안에서 이 ADR이 먼저 착지하고 ADR-0029가 뒤따르는 순서를 전제한다.
   - `exec`는 셸과 비대화형 실행만 주고 터널과 파일은 주지 않는다. 자동화 장비나 셸만 쓰는 장비용이다. `read-only`는 세션 목록과 출력 읽기만 준다(`session.read`, `session.attach`, `session.list`, `session.get`, `docs/CLI.md` §2.5). 입력·크기 조정·종료(`session.control`)와 파일 읽기는 주지 않는다. 파일 읽기를 빼는 이유는 `file.read`가 serve uid의 개인키까지 닿아서 "읽기 전용"이라는 이름이 주는 인상보다 훨씬 강하기 때문이다. 여러 client가 한 세션을 동시에 지켜보는 multi-attach는 P2 L 소관이고 이 role의 전제가 아니다. `reverse`는 `qsh listen` 장비가 target을 pin할 때 쓴다. 등록만 허용하고 listener 장비에서 셸은 주지 않는다. `none`은 신원만 등록하고 권한은 주지 않는다. dial할 상대를 pin할 때 쓴다.
   - 소유 축은 role로 받은 grant가 `scope = "owned"`처럼 걸러지는지를 뜻한다. `full`과 `exec`는 any다. 같은 uid로 명령을 실행할 수 있는 peer에게 세션 소유 필터는 경계가 되지 못하고(`ps`, `/proc`, 터미널 멀티플렉서로 다른 세션에 닿는다), 노트북에서 연 세션에 휴대폰으로 다시 붙는 것이 이 제품의 핵심 사용 장면이다. `read-only`도 any다. 스스로 세션을 열 수 없으니 남이 연 세션을 보는 것이 이 role의 쓸모 전부다. `tunnel`은 owned다. 셸이 없는 장비가 다른 principal의 `-R` listener를 닫을 이유가 없다(`docs/CLI.md` §2.5의 `tunnel.close` 행이 말하는 host 쪽 `forward.remote` 소유권 검사).

3. 저장 위치는 `trust.toml`의 `[[peer]]` 항목에 더하는 optional 키 `role`이다.

   ```toml
   [[peer]]
   name = "phone"
   fingerprint = "sha256:BASE64FINGERPRINT"
   address = ""
   added_at = "2026-10-12T00:00:00Z"
   role = "full"
   ```

   - 값은 결정 2의 여섯 문자열 중 하나다. 다른 값이면 `trust.toml` 전체가 `CONFIG_ERROR`다. 모양이 틀린 다른 필드와 같은 처리다.
   - 키가 없는 항목은 role이 없는 pin이다. 이 ADR 이전에 만든 pin이 모두 여기에 든다. 이 pin은 `none`과 똑같이 판정된다. 업그레이드만으로 권한이 넓어지는 일은 없다. 이 ADR 이후 pin을 만드는 모든 경로는 `role` 키를 명시적으로 쓴다(`none` 포함). 그래서 키가 없다는 것은 곧 "이 ADR 이전의 pin"이고, doctor가 그것을 짚을 수 있다(결정 12).
   - role은 pin(fingerprint)에 묶인다. `trust rename`은 role을 그대로 옮긴다. `trust remove`는 role도 함께 지운다.
   - 코드에서 이 타입의 이름은 `TrustRole`로 하고 `crate::trust`에 둔다. `crate::acl::load::Role`(Serve/Listen)과 이름이 겹치지 않게 하기 위해서다. 결정 2의 표는 `crate::acl` 안의 닫힌 상수 하나로만 존재하고, 평가기·`acl show`·doctor·렌더러가 모두 그 상수를 읽는다.

4. 평가 규칙. 평가 순서에 role 단계 하나를 ①과 ② 사이에 넣는다.

   1. ① 항상-deny 게이트. 그대로다. role도 이 게이트를 넘지 못한다.
   2. ⓡ role 단계. 다음이 모두 참일 때만 role을 본다. `auth_path`가 `Pin`이다. principal이 `device:<name>`이다. 지금 `trust.toml`에 그 이름의 pin이 있고, 그 pin의 fingerprint가 이 연결의 검증된 leaf fingerprint(`ConnCtx::peer_fingerprint`)와 같다. 그러면 그 pin의 role이 이 action을 주는지 결정 2의 표로 보고, 준다면 소유 축 조건(owned면 ④와 같은 규칙)을 거쳐 allow를 낸다. 이때 `Verdict.rule`은 `None`이고, 새 필드가 판정 근거가 role이었음과 그 role 이름을 싣는다.
   3. ②~④ `acl.toml` 행. 그대로다. ⓡ에서 allow가 나지 않았을 때만 돈다.

   - 합성은 합집합이다. role이 주거나 행이 주면 allow다. `acl.toml`에는 deny 행이 없으므로 행이 role을 깎을 방법은 없고, 이 ADR도 deny 행을 들이지 않는다(대안 절). role보다 좁게 주고 싶으면 더 작은 role(`none` 포함)을 고르고 필요한 action을 행으로 더한다. 둘 다 allow를 낼 수 있을 때 판정 근거는 role이다. 순서를 고정해야 audit과 `acl check`가 같은 근거를 말한다.
   - role보다 위에서 거부하는 층은 넷이고 하나도 바뀌지 않는다. ① 항상-deny 게이트, 파싱할 수 없는 `acl.toml`(결정 6), ADR-0029 결정 5의 상태 경로 거부와 열린 핸들 재검증, audit 기록 실패 시 fail-closed다.
   - fingerprint 대조가 맞지 않으면 role은 없는 것으로 친다. pin이 지워졌거나 같은 이름이 다른 fingerprint로 다시 등록된 뒤에도 옛 연결이 새 pin의 role을 얻지 못한다. `peer_fingerprint`가 `None`(leaf가 다시 파싱되지 않음)이면 역시 role이 없다.
   - CA로 인증한 principal(`AuthPath::Ca`)은 ⓡ을 건너뛴다. CA leaf가 pin과 같은 `device:<name>`을 SAN에 실어도 그 pin의 role을 얻지 못한다. CA 경로의 권한은 지금처럼 `auth_path = "ca"` 행만 준다. `user:<name>`과 `fp:sha256:…` principal도 ⓡ에 닿지 않는다. `Principal::Pairing`은 지금처럼 ACL에 닿지 않는다.
   - role은 판정마다 지금의 `trust.toml`에서 읽는다. 연결 수립 때 한 번 얼리지 않는다. 그래서 `trust set-role`과 `trust remove`는 재시작 없이 다음 요청부터 반영된다. `acl.toml` 행이 재시작해야 반영되는 것과 비대칭이고, 이 비대칭은 출력과 문서가 밝힌다(결정 11, 13). 이미 만들어진 자원(열려 있는 세션 attach 스트림, 열린 터널, 진행 중인 전송)은 판정 시점에 인가를 받았으므로 이 ADR만으로는 role이 줄어도 끝까지 간다. 그런 연결을 끊는 일은 ADR-0031(축소판, M16)이 정한다. 그 ADR은 `trust remove`뿐 아니라 `trust set-role`로 role을 줄이는 경우와 role이 있는 pin의 `trust rename`까지 다루고, 줄어든 연결을 2초 안에 닫는다. M15에서 이 ADR만 착지한 동안의 간극은 알려진 잔여 위험이다(결과 절).
   - `trust.toml`을 다시 읽다 파싱에 실패하면 지금은 마지막 정상 snapshot을 쓴다. 이 ADR은 그 동작을 pin 인증에는 그대로 두되, 파일이 다시 파싱될 때까지 role 판정을 전부 멈춘다(모든 pin을 `none`으로 친다). 손으로 고치다 틀린 파일이 이전의 더 넓은 role을 계속 살려 두지 않게 하는 fail closed다. 그 동안 role로만 들어오던 장비는 거부되고, `acl.toml` 행으로 받은 grant는 그대로 동작한다. 멈춘 사실은 지금의 reload 실패 경고 줄에 한 구절을 더해 남기고, `qsh doctor`는 같은 파일에서 `CONFIG_ERROR`로 끝난다(결정 12).

5. 파일 action의 경로 범위. `full`이 주는 `file.read`/`file.write`는 경로 범위가 없다. scp처럼 serve uid가 접근할 수 있는 경로 전부다. `[[acl]]` 행의 `paths` 키(ADR-0029)는 `acl.toml` 행으로 파일 action을 줄 때만 쓰는 선택 제한이 되고, role grant에는 걸리지 않는다. 어느 쪽이든 ADR-0029 결정 5(qsh 자신의 config·state·runtime 경로는 항상 거부)와 열린 핸들 재검증은 그대로 위에 얹힌다. `full`로 `~/.bashrc`나 `~/.ssh/authorized_keys`에 쓸 수 있다는 것은 `full`이 이미 `exec.run`을 준다는 사실에 아무것도 더하지 않는다.

6. `acl.toml`의 세 상태.
   - 로드됨: role과 행의 합집합(결정 4).
   - 없음(`PolicyLoad::Missing`): 행이 하나도 없는 정책으로 친다. role만 동작한다. `acl.toml`이 이제 선택 사항이기 때문이다.
   - 읽을 수 없거나 파싱에 실패함(`PolicyLoad::Invalid`): 지금처럼 `DenyAll`이다. role grant까지 모두 거부한다. 누군가 정책을 두려 했는데 그 정책을 알 수 없는 상태는 모호한 인가 상태이고, 모호하면 닫는다.
   production `Authorizer`는 `SharedTrustStore`를 쥐고 판정마다 role을 해석한다. `qsh serve`, `qsh listen`(controller의 `host.reverse` 판정), `qsh serve --to`(target이 controller의 요청을 받는 판정)가 모두 같은 구성이다. `Authorizer::check`의 입력에 연결의 검증된 fingerprint가 더해진다. `qsh-core` 내부의 trait 변경이고 계약 표면은 아니다. 호출 지점(`Server::authorize`와 그 owner-aware 형제, `forward.local` 인라인 게이트, `reverse::admit`)이 모두 `ConnCtx`에서 그 값을 넘긴다.

7. 판정 함수는 하나다. ⓡ은 `Policy::decide` 안에 들어가고 그 가시성은 `pub(crate)` 그대로다. role 입력 하나가 늘 뿐 호출 지점은 지금의 셋(`impl Authorizer`, `Ops::acl_check`, `Ops::acl_show`)이다. `acl check`와 `acl show`가 enforcement와 다른 role 판정을 할 수 없다.

8. role을 쓰는 명령. 권한을 넓히는 쓰기는 아래 넷과 ADR-0044의 SSH 부트스트랩뿐이고, 모두 이 머신의 로컬 사용자가 실행하는 local operation이다(`docs/CLI.md` §2.5 "인가 불요" 행). 원격 peer는 어느 것도 요청할 수 없다.

   | 명령 | op | 플래그 | 기본값 |
   |---|---|---|---|
   | `qsh trust add <name> … [--role <role>]` | `trust.add` | `--role` | `--address` 없이 등록하면 `full`, `--address`를 주면 `none` |
   | `qsh pair invite [--as <name>] [--role <role>]` | `trust.invite` | `--role` | `full` |
   | `qsh pair accept <address> … [--role <role>]` | `trust.accept` | `--role` | `none` |
   | `qsh trust set-role <name> <role>` | `trust.set_role`(신설) | 위치 인자 | 없음(필수) |

   - 기본값은 `full`이고 좁히고 싶을 때 `--role`로 opt-out한다(2026-10-13 사용자 결정). 예외는 하나, dial할 상대를 pin하는 경우다. pin에는 방향이 없어서(ADR-0030 기각) 여기에 `full`을 얹으면 dial하려고 등록한 상대가 이 장비가 `qsh serve`를 띄울 때 이 장비로 들어올 권한까지 얻는다. 그래서 "들이는 pin"과 "dial 상대 pin"을 주소 유무로 가른다. `pair invite`(초대 코드를 들고 오는 장비를 들인다)와 `--address` 없는 `trust add`(인증서 파일로 client를 들이는 inbound 전용 pin, `docs/CLI.md` §6.11)는 `full`이다. `--address`를 준 `trust add`와 `pair accept`는 dial 상대를 pin하므로 `none`이다. 어느 쪽이든 `--role`이 기본값을 덮는다. ADR-0044의 SSH 부트스트랩은 같은 원칙으로 정방향에서 원격 쪽 pin(주소 없는 inbound pin)에 `full`(`--role`로 지정 가능), 로컬 쪽 pin(dial 상대)에 `none`을 쓴다. 역방향(`pair ssh --reverse`, ADR-0044 결정 22)은 `setup`과 같이 명령이 의도를 알고 role을 명시하는 경우라서 주소 유무 규칙의 예외로 둔다. target 쪽의 listener pin은 주소가 있어도 `full`이고(controller가 중계하는 요청을 target이 그 principal로 인가한다), listener 쪽의 target pin은 주소가 없어도 `reverse`다. `--role`이 덮는 것은 원격(target) 쪽 pin뿐이고, 이 장비 쪽 pin의 role은 플래그 없이 고정이며 바꾸려면 부트스트랩 뒤 `trust set-role`을 쓴다(ADR-0044 결정 1). 예외는 role을 명시하는 이 두 계열(`setup`, 역방향 부트스트랩)뿐이고, 일반 `trust add`·`pair accept`는 주소 유무 규칙을 따른다.
   - `pair invite --role`은 role을 `invites.toml`의 초대 레코드에 저장하고, 상환 때 responder(`qsh serve`)가 그 role로 pin한다. 상환하는 쪽은 role을 고를 수 없다. wire의 페어링 교환에 role 필드는 없고(결정 17), 초대를 만든 사람이 정한 값만 쓰인다. `--as`가 이름 결정권을 pin하는 쪽에 두는 것(ADR-0012 결정 6)과 같은 원칙이다.
   - `trust add`가 이미 있는 이름에 같은 fingerprint로 다시 불리면 role은 바꾸지 않는다. `--role`이 저장된 값과 달라도 `created: false`, `updated: false`이고, human 출력이 "role is unchanged; use `qsh trust set-role`" 뜻의 줄을 하나 낸다. 같은 명령을 자동화가 반복해 부르다 권한을 조용히 바꾸는 경로를 닫기 위해서다. 주소 갱신(`docs/CLI.md` §6.11)은 지금처럼 일어난다.
   - `trust set-role`은 권한을 바꾸는 유일한 명령이다. `trust rename`과 같은 규율로 동작한다. `trust.toml.lock` 아래에서 load → 변경 → audit 기록 → save 순서이고, audit을 쓰지 못하면 `INTERNAL`(`retryable: true`)로 끝나고 파일은 그대로다. 이름이 없으면 `HOST_NOT_FOUND`, role 문자열이 여섯 값 밖이면 `INVALID_ARGUMENT`다. 같은 값으로 다시 부르면 `changed: false`이고 audit도 쓰지 않는다. `[[ca]]` 항목에는 role이 없다. CA 이름을 주면 `HOST_NOT_FOUND`다(`trust rename`이 peer만 다루는 것과 같다).
   - role을 `none`이 아닌 값으로 쓰는 모든 경로(`trust add --role`, 초대 상환으로 생기는 pin, `trust set-role`, ADR-0044의 원격 쪽 등록과 역방향 부트스트랩의 이 장비 쪽 `reverse` pin)는 `AuditRecord::local_op` 레코드 하나를 남긴다. `action`은 그 op 이름, `resource`는 pin 이름, `role`은 새 role이다(결정 16). 기록이 없으면 쓰기도 없다.
   - `qsh setup`(ADR-0024)에서는 위치 인자 `<role>`이 이미 장비의 역할을 뜻하므로 플래그 이름을 `--peer-role`로 한다. 기본값은 setup 역할마다 정한다. `host`는 초대에 `full`, `host --to`는 listener pin에 `full`(controller가 중계하는 요청을 target이 그 principal로 인가한다), `listener`는 target pin에 `reverse`, `client`는 server pin에 `none`이다.

9. `qsh trust list`와 trust 계열 출력. `TrustPeer`에 optional 필드 `role`이 는다. role 키가 없는 pin에서는 필드가 생략된다. 그래서 JSON만으로도 "이 ADR 이전의 pin"과 "명시적 `none`"이 구별된다. human 출력은 role 열을 더하고, 키가 없는 pin에는 `(none, legacy)`처럼 적는다. `trust add`, `trust remove`, `trust rename`, `pair accept`의 `data`가 싣는 `TrustPeer`도 같은 필드를 얻는다.

10. `qsh acl check`(`docs/CLI.md` §6.15). enforcement와 같은 role 해석을 한다. principal이 `device:<name>`이고 `--auth-path`가 `pin`(기본값)이면 이 머신의 `trust.toml`에서 그 이름의 pin을 찾아 그 pin의 role로 ⓡ을 돈다. 로컬 질의라 연결 fingerprint가 없으므로 pin 자신의 fingerprint를 쓴다. `data`에 optional 필드 셋이 는다. `role`(평가에 쓴 role. 그 이름의 pin이 없거나 경로가 `ca`면 생략)과 `granted_by`(allow일 때만, 열린 문자열 `"role"` | `"acl"`), 그리고 `policy`(`AclPolicyRef`)의 optional 필드 `state`(`"loaded"` | `"missing"` | `"invalid"`)다. `state`가 필요한 이유는 결정 6이 `missing`과 `invalid`의 결과를 갈랐기 때문이다. `AclPolicyRef.loaded`의 뜻은 그대로이고, 그 field doc의 "`loaded`가 `false`면 모든 판정이 deny" 문장은 "`state`가 `invalid`면"으로 고친다. "가정한 role로 판정해 보기" 같은 `--role` 플래그는 두지 않는다. 지금의 role은 `trust list`가, role별 action은 결정 2의 표와 `acl show`가 보여 준다.

11. `qsh acl show`(`docs/CLI.md` §6.19). `data`에 optional 필드 `role`(그 principal의 pin role, 결정 10과 같은 해석)과 `role_actions`(그 role이 주는 action 배열, 결정 2의 표 순서)가 는다. `effective_actions`는 role이 주는 action과 매칭 행이 주는 action의 합집합으로 넓힌다. 이 필드의 뜻은 원래 "이 principal이 지금 할 수 있는 것"이었으므로 넓히는 것이 뜻에 맞다. 행 목록 `matching_rules`는 그대로다. human 출력은 role 줄을 먼저 내고, role 변경은 재시작 없이 다음 요청부터 반영되지만 행 변경은 재시작해야 한다는 사실을 두 줄로 나눠 적는다. 행 쪽 줄은 `ACL_RESTART_NOTICE`를 축자로 쓴다(ADR-0025 결정 6). 3-way 대조(ADR-0025 결정 3)는 role 차원으로 넓힌다. `role_actions`와 `effective_actions`가 같은 상태에서 action마다 부른 `acl check`의 판정과 일치하고, 그 판정이 실제 op 결과·audit 기록과 일치해야 한다.

12. doctor(`docs/CLI.md` §6.17). code의 `status`는 하나도 바꾸지 않는다. 바뀌는 것은 나오는 조건과 문면, 그리고 새 code 하나다.
    - `acl_policy_missing`(error, 그대로): `acl.toml`이 없고, role이 `none`이 아닌 pin도, 그런 role을 실은 살아 있는 초대도 없을 때만 낸다. 그 상태는 오늘과 똑같이 "모든 요청이 거부된다"이므로 등급이 맞다. remedy에 "`qsh trust set-role <name> full`로 장비를 들이거나 `acl.toml`을 쓰라"를 더한다. ADR-0038의 client 면제는 그대로 둔다. client 장비의 pin은 기본값이 `none`이라 이 code가 지금처럼 나오기 때문이다.
    - `acl_policy_invalid`(error, 그대로): 조건도 그대로다. 문면에 "role로 받은 권한도 모두 거부된다"를 더한다.
    - `acl_principal_unmatched`(error, 그대로): role이 `none`이 아닌 pin은 세지 않는다. 행이 없어도 role로 무언가를 할 수 있기 때문이다.
    - `acl_ca_auth_path_missing`(warn, 그대로): `[[ca]]`가 있는데 `auth_path = "ca"` 행이 없으면, `acl.toml`이 없는 경우에도 낸다. 지금까지는 그 경우를 `acl_policy_missing`이 덮었지만, role pin이 있어 그 code가 침묵하면 CA 경로가 조용히 막힌 사실을 알릴 곳이 없다. CA 경로에는 role이 없다(결정 4).
    - 신설 `trust_pin_role_unset`(info): `role` 키가 없는 pin마다 finding 하나. 그 pin이 `acl.toml` 행으로만 인가된다는 사실과 `qsh trust set-role <name> <role>`을 알린다. 동작은 바꾸지 않으므로 info다. `detail`은 pin 이름만 싣는다.
    - 결정 4의 role 정지 상태(`trust.toml`이 파싱되지 않음)에는 새 code를 두지 않는다. doctor는 이미 `trust.toml` 파싱에 실패하면 finding을 내지 않고 `CONFIG_ERROR`로 끝난다(`Ops::doctor`의 doc). 그 실패가 운영자에게 가는 신호이고, `qsh serve`/`qsh listen` 쪽에는 결정 4의 경고 줄이 남는다. `CONFIG_ERROR`의 문면에 "실행 중인 serve/listen은 이 파일이 다시 파싱될 때까지 role grant를 거부한다"를 더한다.
    - `trust_remove_scope`(info)의 message는 "role로 받은 권한은 다음 요청부터 사라지고, `acl.toml` 행으로 받은 권한은 연결이 다시 handshake할 때까지 남는다"로 고친다. ADR-0031(축소판)이 착지하면 그 ADR이 다시 고친다.
    - 잠금 어휘 규율대로 새 code는 `EXPECTED_DOCTOR_CODES`와 §6.17 표에 같은 커밋에서 더하고, §6.11·§6.17의 개수 문장은 착지 시점의 실제 개수로 맞춘다. 다른 P1 ADR도 code를 더하므로 순서에 따라 값이 다르다.

13. 시작 진단과 페어링 고지.
    - `qsh serve`/`qsh listen`의 시작 진단(`StartupDiagnostic`)은 `Invalid`에서만 지금의 블록(`ACL_STARTUP_HEADLINE`, `ACL_STARTUP_DENIED_CLAUSE` 등)을 낸다. `Missing`에서는 "acl.toml이 없다. 요청은 trust role로만 인가된다(`qsh trust list`)" 뜻의 한 줄만 낸다. 그 순간 role pin이 하나도 없어도 같은 줄이다. role은 재시작 없이 늘 수 있어서, 시작 시점의 개수를 근거로 "모두 거부"라고 적으면 곧 거짓이 된다. 모두 거부되는 상태를 알리는 일은 doctor의 `acl_policy_missing`이 맡는다.
    - ADR-0017 결정 3의 페어링 직후 고지는 행의 존재 여부 대신 방금 쓴 pin의 이름과 role, 그 role이 주는 action을 적는다. 그 이름을 부르는 `[[acl]]` 행이 이미 있으면 "그 행의 grant도 더해진다"를 덧붙인다. 그 이름을 상대가 자칭한 경우의 경고(ADR-0017 결정 3)는 그대로 둔다. stderr 전용이라는 성질도 그대로다.

14. `qsh setup`(ADR-0024). ACL 단계는 `--peer-role`이 `none`이 아니면 `done`이다. `detail`은 어느 pin 또는 초대가 어느 role을 받는지를 적고, `acl_rows`는 내지 않는다. `none`이면 지금처럼 행을 인쇄하고 `acl.toml`을 검증한다. `complete` 판정(ADR-0024 결정 9, ADR-0038)의 문장은 그대로다. role이 있는 실행에서는 `acl_policy_missing`이 결정 12대로 나오지 않으므로 그 조건을 자연히 통과한다. `qsh setup`은 지금처럼 `acl.toml`을 쓰지 않는다.

15. JSON 계약(`qsh.cli/v1`)은 additive다. 새 optional 필드는 `TrustPeer.role`, `TrustAddReq.role`, `TrustInviteReq.role`, `TrustInviteData.assigned_role`, `TrustAcceptReq.role`, `AclCheckData.role`·`granted_by`, `AclPolicyRef.state`, `AclShowData.role`·`role_actions`, 그리고 `SetupRunReq`의 `peer_role`이다. role 값은 JSON에서 열린 문자열이다(`AclCheckData.decision`과 같은 규율). 새 op `trust.set_role`은 요청 `TrustSetRoleReq { name, role }`과 데이터 `TrustSetRoleData { peer, previous_role?, changed }`를 갖는다. `previous_role`은 이전 pin에 role 키가 없었으면 생략된다. 기존 필드의 타입과 뜻은 바뀌지 않는다. `effective_actions`가 넓어지는 것은 결정 11이 적은 대로 필드의 원래 뜻을 따르는 것이다. fixture는 append만 한다. 기존 `trust.*`·`acl.*`·`setup.run.*` fixture는 role 키가 없는 샌드박스에서 만든 것이라 필드가 생략되는 모양으로 계속 통과한다.

16. audit 레코드. optional 키 `role` 하나를 더한다. 원격 판정 레코드에서는 판정 근거가 role이었을 때만(`decision = "allow"`, `rule = null`) 그 role 이름을 싣는다. 로컬 trust 쓰기 레코드(결정 8)에서는 새 role을 싣는다. 그 밖의 레코드에는 키가 없다. 그래서 오늘 쓰이는 레코드는 한 바이트도 바뀌지 않는다. 값은 결정 2의 고정 어휘라서 구조 필드이고 payload를 실을 수 없다. `record_has_only_structural_fields`는 아홉 키에 optional `role`을 허용하도록 넓힌다. role로 allow된 뒤 ADR-0029의 상태 경로 거부가 붙는 경우의 두 번째 줄은 지금처럼 `rule = null`이고 `role` 키가 없다.

17. wire는 바뀌지 않는다. role은 판정하는 host의 `trust.toml`에만 있고 peer에게 보내지도 받지도 않는다. 페어링 교환(`docs/design/protocol.md` §15), `Hello`, capability 목록, `capabilities.json` golden, `qsh.event/v1`, `qsh.local.v1`, `ErrorCode`가 모두 그대로다. 거부는 지금처럼 `PERMISSION_DENIED_MESSAGE` 한 문장이고, role이 없어서 거부됐는지 행이 없어서 거부됐는지 응답만으로는 가를 수 없다.

18. 권한을 넓히는 경로를 닫아 둔다. 신뢰 등록이 곧 권한 부여가 되었으므로 `trust.toml`과 `invites.toml`에 쓰는 일이 곧 권한을 쓰는 일이다. 열려 있는 길과 닫는 장치를 적는다.
    - 원격 peer가 trust op을 부르는 길: 없다. `trust.*`는 `OP_REGISTRY`에 행이 없는 local operation이다(threat model B13).
    - 원격 peer가 파일 쓰기로 `trust.toml`이나 `invites.toml`을 고치는 길: ADR-0029 결정 5가 config 디렉터리 전체를 role과 행 모두에 대해 항상 거부한다. 이 ADR이 착지한 뒤에는 그 거부가 곧 권한 상승 방지이므로 ADR-0029의 핀 테스트에 `trust.toml`과 `invites.toml`을 반드시 넣는다.
    - 상환하는 상대가 자기 role을 고르는 길: 없다(결정 8).
    - CA 발급 leaf가 pin된 이름을 SAN에 실어 그 pin의 role을 얻는 길: ⓡ이 `auth_path = Pin`과 fingerprint 일치를 함께 요구한다(결정 4).
    - 같은 이름이 다른 fingerprint로 다시 pin된 뒤 옛 연결이 새 role을 얻는 길: 판정마다 fingerprint를 대조한다(결정 4).
    - 업그레이드로 기존 pin이 넓어지는 길: 키 없는 pin은 `none`이다(결정 3).
    - `trust add` 재실행이나 자동화가 role을 바꾸는 길: 기존 pin의 role은 `trust set-role`만 바꾼다(결정 8).
    - 틀리게 고친 `trust.toml`이 옛 role을 살려 두는 길: 파싱될 때까지 role 판정을 멈춘다(결정 4).
    - 관측한 fingerprint를 확인 없이 pin하는 길(TOFU): 여전히 없다(ADR-0017 결정 5, ADR-0024 결정 6). 권한 있는 pin이 생기는 근거는 초대 코드, 인증서 파일과 명시적 `--role`, 사람이 대조한 fingerprint와 명시적 `--role`, SSH 인증(ADR-0044)뿐이다.
    - 이미 `exec.run`이나 세션을 가진 peer가 셸에서 `qsh trust set-role`을 실행해 자기 role을 올리는 길: 막지 않는다. 그 peer는 이미 serve uid로 무엇이든 할 수 있다. 결정 2의 `exec`는 의도를 나타내는 구분이지 `full`에 대한 보안 경계가 아니다. 보안 경계 구실을 하는 role은 명령 실행을 주지 않는 `tunnel`, `read-only`, `reverse`, `none`뿐이다. 이 사실을 `docs/CLI.md` §6.11의 role 표 아래와 threat model 잔여 위험에 적는다.

19. 마일스톤 배치. M15에 ADR-0029(`qsh cp`)와 함께 놓는다. 이 ADR이 먼저 착지한다(결정 2의 `file.*` 각주). ADR-0044의 SSH 부트스트랩(M16)은 이 ADR의 role 기본값과 결정 8의 audit 규율을 그대로 쓴다.

20. 플랫폼과 route 동등(PRD §4). role 표, 평가 순서, 명령, 기본값, 출력, audit 키는 Linux, macOS, Windows와 정방향·역방향에서 모두 같다. 이 ADR의 어느 결정도 OS나 route에 따라 갈리지 않고, 예외를 두지 않는다. `trust.toml`의 `FileLock`·load·mutate·audit·save 순서와 `SharedTrustStore::refresh`는 이미 플랫폼 중립 코드이고, Windows host의 audit 잠금과 재검증은 ADR-0035 결정 24가 같은 의미로 대응한다. 파일 action이 닿는 경로 해석만 OS마다 수단이 다르며, 그 부분은 ADR-0029가 정한다(ADR-0029 결정 23).

## 근거

- 1인·소수 장비 사용에서 "이 장비를 믿는다"와 "이 장비가 내 셸을 쓴다"는 거의 언제나 같은 결정이다. SSH가 `authorized_keys` 한 줄로 두 결정을 함께 내리는 것도 같은 이유다. 지금 qsh는 이 한 결정을 두 파일, 두 명령, 한 번의 재시작으로 쪼개 놓았다. role 하나가 그 거리를 없앤다.
- role을 `acl.toml`이 아니라 `trust.toml`에 두는 이유는 ADR-0017과 ADR-0025가 `acl.toml` writer를 기각한 이유가 `trust.toml`에는 없어서다. `trust.toml`은 이미 `FileLock`으로 read-modify-write를 직렬화하고 handshake마다 다시 읽힌다. 명령이 성공을 보고했는데 재시작 전까지 적용되지 않는 간극(ADR-0025 대안 절)이 생기지 않는다. 그리고 role이 pin에 붙어 있으면 pin을 지우는 순간 권한도 사라진다. 이름 문자열로 두 파일을 잇는 지금의 구조에서는 `trust rename`이나 이름 재사용이 권한을 조용히 옮긴다(B10, B12).
- 기존 pin을 `none`으로 해석하는 것은 손해가 없다. 오늘 그 pin이 받는 권한은 정확히 `acl.toml` 행이 주는 것이고, 업그레이드 뒤에도 그대로다. 반대로 `full`로 해석하면 client로만 쓰려고 pin한 상대가 업그레이드 순간 이 장비의 셸을 얻는다.
- 새 pin의 기본 role을 명령마다 다르게 두는 것은 ADR-0030(pin 방향)을 폐기하면서 남은 문제를 role로 푸는 방법이다. 방향 축 없이도 "dial하려고 등록한 상대"(`--address`를 준 `trust add`, `pair accept`, 로컬 쪽 SSH 부트스트랩)는 권한이 `none`이고 "들이려고 등록한 상대"(`pair invite`, 주소 없는 `trust add`, 원격 쪽 SSH 부트스트랩)는 `full`이다. 기본이 `full`이라 사람이 손댈 일은 좁히는 쪽(opt-out)뿐이다. 사람이 다른 뜻을 가졌으면 플래그 하나로 바꾼다.
- `acl.toml`이 없는 상태를 role만 동작하는 정상 상태로 두되 파싱 실패는 계속 전부 거부하는 것은 CLAUDE.md의 fail closed 원칙을 지키는 가장 좁은 변경이다. 없는 파일은 "아무 행도 쓰지 않았다"는 분명한 상태이고, 깨진 파일은 "무언가 쓰려 했는데 무엇인지 모른다"는 모호한 상태다.
- role을 판정마다 읽는 것은 비용이 거의 없다. `SharedTrustStore::refresh`는 파일 내용이 바뀌지 않았으면 다시 파싱하지 않는다. 판정마다 파일을 한 번 읽는 비용은 `forward.local` 인라인 게이트처럼 잦은 지점에서도 `tunnel_echo_under_load` 예산 안에 든다고 보지만, 측정값은 아니다. 구현 커밋이 그 테스트로 확인한다. 예산을 넘으면 판정마다 파일 내용을 읽는 대신 파일의 크기·수정 시각(나노초)·inode를 먼저 보고, 달라졌을 때만 다시 읽는다. role 변경이 다음 요청부터 보인다는 의미는 그대로다. 이 대체 경로는 이미 정해져 있고 새 ADR이 필요 없다.
- role 집합을 작게 고정하면 매핑이 문서·코드·테스트 한 곳에서 대조된다(`acl_docs.rs`가 PRD §9 action 목록을 대조하는 것과 같은 방식). 사용자 정의 role은 결국 `acl.toml`을 하나 더 만드는 일이다.

## 대안과 기각 사유

- 페어링과 `trust add`가 `acl.toml`에 행을 쓴다: 기각. ADR-0017 대안 절과 ADR-0025 대안 절의 이유 그대로다. 잠금 규율이 없고 재시작 간극이 남는다.
- role을 `acl.toml`에 둔다(`[[role]] principal = "device:phone", role = "full"`): 기각. 권한이 한 파일에 모이는 장점은 있지만 위 기각과 같은 이유로 어떤 명령도 그 파일을 쓸 수 없어서 "등록하면 바로 된다"를 이룰 수 없다.
- CA 발급 인증서 확장에 role을 싣는다: 기각. 발급이 곧 권한 부여가 되고, 발급한 뒤에는 role을 바꾸거나 거둘 방법이 없다(폐기 목록은 ADR-0031 축소로 빠졌다). CA 경로는 지금처럼 `auth_path = "ca"` 행으로만 인가한다.
- role 없는 기존 pin을 `full`로 해석한다: 기각. 근거 절의 조용한 확장이다.
- 모든 `trust add`(주소를 준 dial 상대 pin 포함)의 기본 role을 `full`로 둔다: 기각. pin에 방향이 없어서 dial 상대를 등록하는 흔한 사용이 inbound 권한을 준다(ADR-0017 결정 5가 TOFU를 기각한 것과 같은 모양). 2026-10-12 초안은 반대로 `trust add` 전체를 `none`으로 두었으나, 2026-10-13 사용자 결정("기본을 full로 하고 opt-out")으로 주소 없는 inbound pin은 `full`이 되었다.
- `acl.toml`에 deny 행을 들여 role을 깎는다: 기각. allow 전용 first-match 평가기에 우선순위 규칙이 생기고, `decide_agrees_with_naive_coverage_oracle`의 oracle과 `acl show`의 실효 집합 정의가 함께 복잡해진다. 더 작은 role과 행의 합으로 같은 결과를 낸다.
- role을 연결 수립 때 한 번 정해 연결 내내 쓴다: 기각. `trust set-role`과 `trust remove`가 재연결 전까지 효과가 없어서 `acl.toml`의 재시작 간극을 trust 쪽에 다시 만든다. 이름만으로 판정마다 찾는 안도 기각한다. 같은 이름이 다른 fingerprint로 다시 등록되면 옛 연결이 새 role을 얻는다.
- role 없이 "신뢰하면 전부"라는 불리언 하나: 기각. listener가 target에게 등록만 허용하는 경우(`reverse`)와 dial 상대를 신원만 등록하는 경우(`none`)를 나타낼 수 없다.
- 사용자 정의 role(`[roles.ops] allow = [...]`): 기각. 세밀한 제어는 이미 `acl.toml`이 한다. 같은 일을 두 문법으로 하게 된다.
- 모든 role grant를 `scope = "owned"`로 거른다: 기각. 결정 2의 소유 축 설명대로 `full`/`exec`에서는 경계가 되지 못하고, `read-only`는 쓸모가 없어진다.
- `read-only`에 `file.read`를 넣는다: 기각. 결정 2. serve uid가 읽을 수 있는 개인키와 자격 증명이 모두 열린다.
- role 변경 명령을 두지 않고 remove 후 add로 바꾸게 한다: 기각. 그 사이에 pin이 없는 창이 생기고(`trust rename`을 따로 둔 이유와 같다, `docs/CLI.md` §6.11), 바꾸는 행위가 audit에 한 줄로 남지 않는다.

## 결과

- 핀 테스트. 이름은 구현 때 확정하되 성질은 이대로다.
  - `legacy_pin_without_role_is_authorized_by_acl_rows_only`: role 키가 없는 pin이 행이 주는 action만 받고, 행이 없으면 모두 거부된다.
  - `role_full_without_acl_toml_allows_every_action_but_forward_socks`: `acl.toml`이 없을 때 `full`이 표의 action을 모두 받고 `forward.socks`는 거부된다. `exec`, `tunnel`, `read-only`, `reverse`, `none`도 표대로 판정되는 행을 같은 테스트 표에 둔다.
  - `invalid_acl_toml_denies_role_grants_too`
  - `role_grant_does_not_reach_a_ca_leaf_naming_a_pinned_device`: `device:<name>` SAN을 실은 CA leaf가 같은 이름 pin의 `full`을 얻지 못한다.
  - `role_requires_the_connection_fingerprint_to_match_the_current_pin`: 같은 이름을 다른 fingerprint와 `full`로 다시 pin해도 옛 연결의 다음 요청은 role을 얻지 못한다.
  - `set_role_takes_effect_on_the_next_request_without_restart`, `trust_remove_ends_role_grants_on_the_next_request`
  - `trust_store_reload_failure_suspends_role_grants`: 파싱되지 않는 `trust.toml`로 바꾼 뒤 pin 인증은 되지만 role grant는 거부되고, 행 grant는 동작한다.
  - `trust_add_never_changes_an_existing_pin_role`
  - `invite_role_is_fixed_by_the_issuer`: 상환 쪽이 무엇을 보내도 초대에 저장된 role로 pin된다.
  - `pair_accept_and_trust_add_default_to_role_none`, `pair_invite_defaults_to_role_full`
  - `set_role_without_a_durable_audit_record_leaves_trust_toml_untouched`, `role_writes_leave_a_local_op_audit_record_with_the_role`
  - `role_grant_audit_record_names_the_role_and_no_rule`: 키 집합이 아홉에 `role`만 더한 것이고 `rule`이 `null`이다.
  - `role_tunnel_cannot_close_another_principals_remote_forward`, `role_read_only_can_attach_but_not_write`
  - `role_full_file_ops_still_deny_state_paths`(ADR-0029 착지 뒤): `trust.toml`, `invites.toml`, `acl.toml`, identity 키를 `full`로 읽거나 쓰지 못한다.
  - `unknown_role_string_makes_trust_toml_a_config_error`
  - `role_action_table_matches_docs`: 결정 2의 표가 `docs/CLI.md` §6.11의 role 표, PRD §9와 일치한다(`acl_docs.rs`와 같은 형식).
  - `crates/qsh-core/src/acl/policy/tests.rs`의 `decide_agrees_with_naive_coverage_oracle`에 role 차원(여섯 값과 "role 없음", fingerprint 일치 여부, `auth_path`)을 더한다.
  - `crates/qsh-cli/tests/acl_check_equivalence.rs`: role pin이 있는 샌드박스에서 `acl check`·`acl show`·실제 op·audit 넷이 일치하는 행들. `crates/qsh-testkit/tests/acl_uniformity.rs`: role 없음 거부, role 범위 밖 거부, reload 실패 중 거부가 모두 같은 `PERMISSION_DENIED_MESSAGE`를 낸다.
  - 기존 `setup_never_writes_acl_toml_in_any_role`은 그대로 초록이어야 한다. `setup_host_roles_incomplete_without_acl_toml`(ADR-0038)은 `--peer-role none`에서만 성립하도록 조건을 좁히고, role 기본값의 host 역할에 대해 `complete: true`를 거는 테스트를 새로 둔다.
- 등록 완전성과 fixture. `trust.set_role`은 schemars 타입, `cli_v1_data_schema` arm, `CLI_V1_SCHEMA_COMMANDS` 등록, 렌더러 둘, `docs/CLI.md` 새 문단, man 페이지(`qsh-trust-set-role`)를 갖추고 `crates/qsh-core/tests/schema_commands_registry.rs`가 누락을 잡는다. 새 fixture는 `trust.set_role.json`, `trust.set_role.unchanged.json`, `trust.list.with_role.json`, `trust.add.with_role.json`, `trust.invite.with_role.json`, `acl.check.allow_by_role.json`, `acl.check.missing_policy_role.json`, `acl.show.with_role.json`, `setup.run.host_complete_with_role.json`이고 모두 `REQUIRED_FIXTURES`에 등록한다. 기존 fixture는 건드리지 않는다. `capabilities.json`은 바뀌지 않는다. `cargo xtask man`으로 `qsh-trust-add`, `qsh-pair-invite`, `qsh-pair-accept`, `qsh-setup`이 플래그를 얻는다.
- doctor. 새 code `trust_pin_role_unset`과 조건이 바뀐 넷, message가 바뀐 `trust_remove_scope`가 `crates/qsh-core/src/doctor.rs`, `crates/qsh-core/src/ops/doctor.rs`, `docs/CLI.md` §6.17 표와 개수 문장에서 같은 커밋으로 움직인다(`crates/qsh-core/tests/doctor_docs.rs`).
- 계약 문서. `docs/PRD.md` §9는 "principal은 pin role과 `acl.toml` 행으로 인가된다"로 고치고 role 표와 `full` 예시를 더한다. 기존 `acl.toml` 예시는 세밀한 제어의 예로 남긴다. `docs/CLI.md`는 §2.4에 `trust.set_role`, §2.5 "인가 불요" 행에 같은 op와 role 서술, §6.11에 role 표·기본값·`trust set-role`·`--role` 플래그·`trust list`의 role 열, §6.12·§6.13에 시작 진단 변경, §6.15·§6.19에 결정 10·11의 필드, §6.17에 결정 12, §6.20에 `--peer-role`이 오른다. `docs/design/architecture.md` §6은 평가 순서에 ⓡ과 `acl.toml` 세 상태를, §7은 `trust.toml`의 `role` 키를 적는다.
- 위협 모델(`docs/design/threat-model.md`). §2 주체 표의 "pin된 원격 peer" 행은 "pin의 role이 주는 action과 자기 principal에 걸린 `acl.toml` 행이 주는 action의 합집합"이 된다. §3 진입점에 `qsh trust set-role`과 세 명령의 `--role`을 더한다. §4 B 계열에 다음 위협을 행으로 더한다. 번호는 착지 순서에 따라 정한다.
  - 원격 파일 쓰기로 `trust.toml`/`invites.toml`을 고쳐 role을 올린다 → ADR-0029 결정 5, `role_full_file_ops_still_deny_state_paths`
  - CA leaf가 pin된 이름을 실어 그 role을 얻는다 → 결정 4, `role_grant_does_not_reach_a_ca_leaf_naming_a_pinned_device`
  - 이름 재등록 뒤 옛 연결이 새 role을 얻는다 → 결정 4, `role_requires_the_connection_fingerprint_to_match_the_current_pin`
  - 상환하는 상대가 자기 role을 고른다 → 결정 8, `invite_role_is_fixed_by_the_issuer`
  - 업그레이드나 `trust add` 재실행이 권한을 조용히 넓힌다 → 결정 3·8, `legacy_pin_without_role_is_authorized_by_acl_rows_only`, `trust_add_never_changes_an_existing_pin_role`
  - 깨진 `trust.toml`이 옛 role을 살려 둔다 → 결정 4, `trust_store_reload_failure_suspends_role_grants`
  - 권한 변경이 audit에 남지 않는다 → 결정 8·16, `set_role_without_a_durable_audit_record_leaves_trust_toml_untouched`
  B4 행(정책 파일이 없을 때 fail-open)의 통제 문장은 "없는 `acl.toml`은 행 없음이고 role만 동작한다. 파손은 role까지 전면 거부"로 고친다. §7 잔여 위험에 다섯을 적는다. `exec`와 `full`은 serve uid와 같은 힘이라 `exec`가 스스로 `full`이 될 수 있다(결정 18). `tunnel`의 `forward.local`은 host가 닿는 모든 TCP 목적지에 닿는다(host-local dial 필터가 거르는 것 빼고). `read-only`는 다른 장비가 연 세션의 화면 출력, 그 안에 나온 비밀까지 본다. role을 줄여도 이미 만들어진 자원은 ADR-0031(축소판)이 착지하기 전까지 끝까지 간다(그 ADR은 remove, role 축소, role이 있는 pin의 rename을 모두 다룬다). 이 ADR 이전 버전의 바이너리가 `trust.toml`을 다시 쓰면 `role` 키가 사라져 그 pin이 `none`이 된다(좁아지는 방향이다).
- 문서 밖. `CLAUDE.md` "Security defaults"의 "a request matching no `[[acl]]` row is denied, and a missing or unparseable `acl.toml` denies every request" 문장, README의 First run과 보안 절, ADR-0026의 `trust ssh-preview`가 내는 ACL 초안(`--role`을 단 pin 명령으로 바꾼다)을 고친다. `docs/adr/README.md` 색인과 `docs/ROADMAP.md` M15는 메인 세션이 고친다.
- architecture rule. role 표, role 해석, 평가기 변경, doctor 검출기는 모두 `qsh-core`에 둔다. `qsh-proto`에는 열린 문자열 필드와 새 op 타입만 들어간다. `qsh-cli`는 clap 정의와 렌더러만 바뀐다. 새 모듈이 `xtask arch`의 경로 범위 금지 목록에 들어가야 하는지는 구현 커밋이 판단한다.
- 크기. 2.7~4.2ew로 추정한다. 측정값이 아니다. ADR과 계약 문서 0.3~0.5, `trust.toml`·`invites.toml`의 role 키와 네 명령의 플래그, 새 op `trust.set_role`의 등록 완전성 0.6~0.9, 평가기 ⓡ과 `Authorizer` 입력 변경, 판정마다의 role 해석과 reload 실패 시 정지 0.5~0.8, `acl check`·`acl show` 필드와 3-way 대조 0.3~0.5, doctor·시작 진단·페어링 고지 0.3~0.4, `qsh setup` 연동 0.2~0.3, audit optional 키 0.1~0.2, 위 핀 테스트와 oracle 확장 0.4~0.6이다. ADR-0029의 크기와는 따로 센다.
