# ADR-0025: writer 없이 ACL 가시성만 올린다. 읽기 전용 `qsh acl show`를 신설하고 `acl grant`/`acl revoke`는 기각한다

날짜: 2026-09-24
상태: 제안됨

개정 관계: ADR-0017을 대체하지 않는다. 그 결정 1(어떤 명령도 `acl.toml`을 쓰지 않고 핫 리로드도 두지 않는다)을 명시적으로 재확인하고 읽기 축만 넓힌다. 계약 문서로는 `docs/CLI.md` §6.15와 나란한 절 하나를 신설한다.

## 맥락

이슈 #3 항목 c/c2가 묻는 것을 다룬다. `qsh acl grant/revoke/show` 형태의 최소 CLI를 제안한다. 규칙을 안전하게 편집하고 유효성과 최종 권한을 미리 보여주고 변경 뒤 재시작이 필요한지 표시하거나 안전한 핫 리로드를 설계하자는 것이다. 이 제안은 세 명령을 한 묶음으로 내놓았지만 실제로는 서로 다른 축 둘이 섞여 있다. 쓰기 축은 ADR-0017이 이미 닫았고 읽기 축은 아직 절반만 열려 있다.

오늘의 읽기 표면은 `qsh acl check` 하나다(`docs/CLI.md` §6.15). `Ops::acl_check`(`crates/qsh-core/src/ops/acl.rs`)가 `PolicySource::load`로 이 머신의 `acl.toml`을 읽고 `Policy::decide`(`crates/qsh-core/src/acl/policy.rs`)를 그대로 호출한다. 이 명령이 답하는 질문은 (principal, action, resource) 삼중 하나다. 답하지 못하는 질문은 "이 principal이 지금 무엇을 할 수 있는가"다. 운영자가 그 답을 얻으려면 `Action::ALL`(`crates/qsh-core/src/acl/mod.rs`, 11종)을 손으로 돌며 열한 번 호출하고 결과를 직접 모아야 한다. 어느 `[[acl]]` 행이 그 판정을 냈는지는 `rule` index 하나로만 돌아오므로, 행 자체를 보려면 다시 파일을 열어 index를 세야 한다.

설계를 가르는 사실은 이렇다.

- `acl.toml`은 사람이 손으로 쓰는 파일이고 이 저장소에 그것을 쓰는 프로덕션 경로는 없다. `crates/qsh-core/src/acl/load.rs`의 `ACL_STARTUP_NO_AUTOGEN` 상수가 그 사실을 문자열로 못박고 `PolicySource::load`는 프로세스 시작 시 1회만 돈다. ADR-0017 결정 1이 이 성질을 결정으로 확정했다.
- `trust.toml`과 `invites.toml`은 `crates/qsh-core/src/config.rs`의 `FileLock`이 read-modify-write 전체를 직렬화한다(`Ops::trust_add` 같은 경로가 load에서 save까지를 그 lock 안에서 한다). `acl.toml`에는 그런 규율이 없다.
- `[[acl]]` 한 행(`Rule`)은 `principal`, `auth_path`, `allow`, `scope` 넷을 갖는다. `auth_path`를 적지 않은 행은 `AuthPath::Pin`이 기본값으로 매겨진다. 그래서 CA로만 인증한 peer는 그 행에 영원히 매칭되지 않는다(`crates/qsh-core/src/acl/policy.rs` 모듈 doc의 평가 순서 ②와 `Rule::auth_path`의 field doc). 파일이 틀린 것도 파싱이 실패한 것도 아니라서 이 상태는 조용하다.
- ADR-0017 결정 2가 신설하기로 한 진단 `acl_ca_auth_path_missing`은 파일 전체 수준의 거친 검사가 될 것이다. `[[ca]]`가 있는데 `auth_path = "ca"` 행이 하나도 없으면 finding이 뜬다. 어느 principal이 빠졌는지는 답하지 않고 답할 수도 없다. CA로 인증한 principal도 `device:<id>` 모양이라 발급 가능한 이름을 미리 열거할 수 없기 때문이다.
- `Policy::decide`는 `pub(crate)`다. 그 메서드 자신의 doc이 적었듯 워크스페이스 전체에 호출 지점이 둘뿐이다(`impl Authorizer for Policy`의 `check`와 `Ops::acl_check`). 둘 다 `qsh-core` 안에 있다. 설명 전용 두 번째 평가기가 밖에서 생길 수 없다는 뜻이다. `crates/qsh-cli/tests/acl_check_equivalence.rs`가 그 규율의 표 절반으로, 행마다 `acl check`의 판정과 실제 op의 결과와 그 op이 남긴 audit 기록 셋이 모두 일치함을 건다.
- `acl.check`는 인가 불요 local operation이다(`docs/CLI.md` §2.5 매핑 표의 마지막 행). 원격에서 정책을 조회할 수 있게 하면 그 자체가 capability 열거 oracle이 된다(`docs/CLI.md` §6.15, `docs/ROADMAP.md` M5 감사 개정 ③).

## 결정

1. ADR-0017 결정 1을 재확인한다. 이 ADR이 신설하는 명령은 `acl.toml`을 읽기만 하고 절대 쓰지 않는다. 핫 리로드도 넣지 않는다. `PolicySource::load`의 프로세스 시작 1회 성질과 `ACL_STARTUP_NO_AUTOGEN`이 뜻하는 자동 생성 금지는 그대로다. 이 ADR은 그 결정을 다시 여는 제안이 아니라 그 결정 위에서 읽기 축만 넓히는 제안이다.

2. `qsh acl show --principal <p> [--auth-path pin|ca]`를 신설한다. `--json`에서 내는 것은 둘이다. 하나는 그 principal과 auth path에 매칭되는 `[[acl]]` 행들이다. 행마다 `acl.toml` 안의 배열 index, `allow` 패턴 목록(`ActionPattern`이 적힌 그대로, 즉 `exec.run` 같은 exact와 `forward.*` 같은 family 둘 다), 그 행의 `auth_path`, 그 행의 `scope`를 낸다. 다른 하나는 그 행들에서 나오는 실효 action 집합이다. 이 집합은 소유자 없는 리소스를 가정해 계산한다. `Scope::Owned`(행의 기본값)는 리소스에 소유자가 있을 때만 걸러내므로(`Policy::decide`의 doc), 소유된 리소스에 대해서는 이 집합이 상한이다. 출력은 그 점을 명시한다. `--resource`나 `--owner` 축은 이 명령에 두지 않는다. 그 축이 필요한 질문은 `acl check`가 이미 답한다.

3. 판정은 `Policy`의 기존 matcher를 그대로 재사용한다. 규칙을 두 번 구현하지 않는다. 구현은 `qsh-core` 안에서 `Action::ALL` 11종마다 `Policy::decide`를 부르고 allow가 난 것만 모은다. 매칭 행 목록도 같은 `Policy`의 `rules` 위에서 평가 순서 ②(principal 정확 일치 + `auth_path` 일치)와 ③(action 패턴 일치)을 돌려 뽑는다. `Policy::decide`의 `pub(crate)` 가시성은 그대로 두고 호출 지점만 `qsh-core` 안에서 하나 는다. `crates/qsh-cli/tests/acl_check_equivalence.rs`가 세운 3-way 대조 규율은 이 명령에도 그대로 이어진다. `acl show`가 내는 실효 집합과 같은 정책 아래 `acl check`가 action마다 내는 판정이 어긋나면 테스트가 붉어진다.

4. 인가 불요 local operation이다. `docs/CLI.md` §2.5 매핑 표의 마지막 행에 `acl.show`를 `acl.check` 옆에 더한다. 원격 peer가 이 op을 요청할 수 없고 wire 메시지도 만들지 않는다. 이유는 `acl.check`를 local-only로 못박은 것과 같다. 원격에서 남의 정책을 열람할 수 있으면 그것이 곧 capability 열거 oracle이다. `acl show`는 삼중 하나가 아니라 집합을 통째로 돌려주므로 oracle로서의 효율이 `acl check`보다 높다.

5. `auth_path` 생략 기본값이 만드는 함정을 출력이 명시한다. `--auth-path`를 주지 않으면 `AuthPath::Pin`으로 평가한다는 사실, 그리고 `acl.toml`에서 `auth_path`를 적지 않은 행도 같은 기본값을 받아 CA 인증 peer에게는 매칭되지 않는다는 사실을 둘 다 적는다. 이 고지는 ADR-0017 결정 2의 `acl_ca_auth_path_missing` 진단과 짝이다. 그 진단은 파일 전체에 `auth_path = "ca"` 행이 하나도 없다는 거친 사실을 알리고 이 출력은 지금 묻고 있는 principal 하나에 대해 어느 쪽 축으로 평가했는지를 알린다. 두 표면을 둘 다 두는 이유가 이것이다.

6. 재시작이 필요하다는 고지는 ADR-0017 결정 2가 세운 remedy 문면을 축자 재사용한다. 그 결정은 새 doctor 진단 둘의 remedy에 "행을 추가한 뒤 `serve`/`listen`을 재시작해야 반영된다"를 반드시 넣기로 했다. `acl show`도 같은 비대칭 위에 서 있다. 호출마다 파일을 다시 읽으므로 재시작하지 않은 상태에서도 방금 추가한 행이 보이지만 돌고 있는 `qsh serve`/`qsh listen`은 그 행을 아직 모른다. 그 진단이 착지하면서 만들어질 remedy 상수를 이 명령의 출력이 같은 상수로 인용하고 문면을 다시 타이핑하지 않는다.

7. 마일스톤 배치는 M9 밖이다. `docs/ROADMAP.md` M9 범위 (a)부터 (k)까지에 이 명령이 없고 M9의 남은 항목을 이것 때문에 늘리지 않는다. M10 이후 또는 P1으로 둔다. 이슈 #3의 온보딩 흐름 전체가 그렇듯 이 명령도 SC1 재측정이 어디에서 시간을 쓰는지 보여준 뒤에 우선순위가 정해진다.

## 대안

- `qsh acl grant`/`qsh acl revoke`를 함께 신설한다(#3 제안의 해당 항목). 기각한다. 이유는 ADR-0017이 이미 적은 그대로다. `acl.toml`에는 `trust.toml`/`invites.toml`이 갖는 `FileLock` 규율이 없어서 writer를 만들려면 잠금 기전을 새로 세우거나 사람이 편집기로 열어 둔 파일을 잠금 없이 덮어쓰는 두 선택지밖에 없다. 그리고 `acl.toml`은 그 둘과 달리 매 handshake가 아니라 프로세스 시작 시 1회만 읽히므로, 잠금을 갖추더라도 `grant`가 성공했다는 출력과 실제 강제 사이에 재시작 하나만큼의 간극이 남는다. 그 간극은 writer가 있을 때 더 나쁘다. 손으로 편집한 사람은 자기가 파일을 고쳤다는 것을 알지만 명령이 성공을 보고하면 적용됐다고 읽는다. 읽기 전용 명령에는 이 문제가 없다.
- `acl.toml`에 핫 리로드를 넣어 재시작 간극 자체를 없앤다. 기각한다. ADR-0017 대안 절이 이미 기각했고 그 결정을 다시 열려면 그것을 개정하는 새 ADR이 필요하다. 이 ADR은 그 개정이 아니다.
- 새 명령 대신 `acl check`의 `--action`을 선택 인자로 바꿔 생략하면 어휘 전체를 돌게 한다. 기각한다. `AclCheckData.action`은 필수 필드이고 생략을 표현하려면 타입이 바뀐다. `docs/CLI.md` §10은 그것을 `/v2` 사유로 못박는다. `acl.check.allow.json`/`acl.check.deny.json` 두 fixture가 그 모양을 봉투째 고정하고 있는 것도 같은 이유로 건드릴 수 없다. 새 command와 새 타입을 더하는 것만이 additive 규칙 안에 있다. ADR-0019 결정 11이 `tunnel.dynamic`을 새 command로 낸 것과 같은 판단이다.
- `acl show`를 원격에서도 부를 수 있게 한다. 기각한다. 결정 4의 이유 그대로다. 정책 열람을 원격에 여는 순간 그것이 capability 열거 oracle이 된다(`docs/ROADMAP.md` M5 감사 개정 ③).
- 명령이 `acl.toml` 원문을 그대로 덤프한다. 기각한다. 파일을 그대로 보는 일은 `cat`이 이미 한다. 이 ADR은 덤프가 아니라 판정에서 값을 낸다. 원문만 보여주면 결정 5가 겨냥한 함정, 즉 `auth_path`를 적지 않은 행이 CA 인증 peer에게 매칭되지 않는다는 사실이 눈에 보이지 않는 채로 남는다.
- doctor 진단만으로 충분하다고 보고 새 명령을 두지 않는다. 기각한다. ADR-0017 결정 2가 신설하기로 한 `acl_ca_auth_path_missing`은 파일 전체 수준 검사라 어느 principal이 빠졌는지 답하지 않고 `acl_principal_unmatched`는 pin된 peer 중 어느 행에도 닿지 못한 쪽만 셀 것이다. 둘 다 "행에 닿았다"까지만 말하고 "그래서 무엇을 할 수 있는가"는 말하지 않는다. #3이 요구한 것은 후자다.
- 실효 action 집합에 `forward.socks`/`file.read`/`file.write`를 그 행의 `allow`가 적고 있다는 이유로 포함한다. 기각한다. `Action::is_always_denied`가 규칙 평가보다 먼저 막으므로 이 셋은 어떤 행으로도 부여되지 않는다. 출력이 그것을 allow로 적으면 운영자가 존재하지 않는 권한을 믿게 된다. `allow = ["forward.*"]`가 `forward.socks`를 삼키지 않는다는 사실을 오히려 출력이 밝혀 주는 쪽이 맞다.

## 결과

- 신규 op `acl.show` 하나가 는다. `docs/ROADMAP.md` M9 수용 기준의 등록 완전성 항목이 요구하는 것을 전부 갚는다. 새 fixture 파일과 `REQUIRED_FIXTURES`(`crates/qsh-cli/tests/fixtures.rs`) 등록, schemars 타입, `cli_v1_data_schema` arm, `qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS` 등록, 렌더러 둘(human 쪽은 `crates/qsh-cli/src/render/human.rs`의 `print_acl_check` 옆), `docs/CLI.md` 새 절, man 항목이 모두 있어야 한다. `crates/qsh-core/tests/schema_commands_registry.rs`가 등록 누락을 잡는다.
- 기존 fixture는 한 바이트도 바뀌지 않는다. `acl.check.allow.json`과 `acl.check.deny.json`은 그대로다. `acl.check` 자신의 요청 타입, 데이터 타입, 인자 집합도 변경이 없다.
- `Policy::decide`의 호출 지점이 둘에서 셋이 된다. 셋 다 여전히 `qsh-core` 안이므로 `pub(crate)` 가시성이 지키는 불변식(설명 전용 두 번째 평가기가 crate 밖에 살 수 없다)은 그대로다. 다만 그 메서드의 doc과 `crates/qsh-cli/tests/acl_check_equivalence.rs`의 모듈 doc이 둘 다 "정확히 두 호출 지점"이라고 적고 있으므로, 구현 커밋이 두 산문을 같이 고쳐야 한다. 조용히 세 번째를 더하면 그 문서가 거짓이 된다.
- CLI 쪽은 `crates/qsh-cli/src/cli.rs`의 `AclCmd`에 variant 하나와 args struct 하나가 는다. `qsh-cli`에는 clap 정의와 렌더러만 들어가고 판정은 전부 `Ops`에 남는다. 아키텍처 규칙에 새 예외를 만들지 않는다.
- `acl.toml`을 사람이 손으로 쓴다는 성질은 그대로다. `ACL_STARTUP_NO_AUTOGEN`과 `crates/qsh-core/src/acl/load.rs`의 `minimal_policy_example`은 이 ADR로 바뀌지 않는다.
- wire 프로토콜과 `qsh.event/v1`에는 아무 변화가 없다. 새 op은 local이라 control 메시지를 만들지 않고 `docs/design/protocol.md` §16의 동결 대상에 걸리는 항목도 없다.
- 예측의 한계는 `acl check`와 같고 출력도 같은 말을 한다. `PolicyLoad::Missing`과 `PolicyLoad::Invalid`는 구별 없이 "정책 없음"으로 보이고 그 상태의 실효 집합은 공집합이다. 파싱 실패의 상세는 `docs/CLI.md` §6.12/§6.13의 시작 진단이 정본이다. 그리고 enforcement에는 평가기 위에 fail-closed 층이 하나 더 있어서 `acl show`가 든 action이 운영 상태에 따라 실제로는 거부될 수 있다. 반대 방향, 즉 이 명령이 빼먹은 action이 실제로 허용되는 일은 없다.
- 잔여 위험 하나를 적어 둔다. `acl show`는 로컬 명령이지만 이 머신의 정책 전모를 한 호출로 요약해 준다. 같은 머신에 로그인한 다른 uid에게도 `acl.toml` 자체가 이미 읽히는 상태라면 이 명령이 새로 여는 것은 없다. `acl.toml`의 파일 권한이 그보다 좁게 잠겨 있는 배치에서는 이 명령도 그 파일을 읽지 못하고 실패하므로 경계가 그대로 유지된다.
- 이 ADR이 승인되면 이슈 #3 항목 c/c2(ACL CLI: `acl show` 신설과 `grant`/`revoke` 기각)가 닫힌다. `grant`/`revoke`는 기각으로 닫히고 `show`만 남는다. `docs/adr/README.md` 색인에 0025 행을 더한다. `docs/ROADMAP.md`와 `docs/PRD.md`에 반영할 것이 있으면 메인 세션이 한다.

