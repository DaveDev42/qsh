# ADR-0029: 파일 복사는 scp 인자 문법의 `qsh cp [-r] [-p] [-q] SRC... DST` 하나로 연다. 디렉터리 순회는 client가 하고 wire에는 `file.list`·`file.mkdir` 두 op만 더한다. `full` role은 serve 계정이 닿는 경로 전부를 주되 qsh 자신의 상태 경로는 항상 거부하고, `[[acl]]` 행의 `paths`는 행으로 파일 권한을 줄 때만 쓴다

날짜: 2026-10-11 (개정 2026-10-12, 2026-10-13)
상태: 승인됨
승인 2026-10-14: 사용자 위임 결정("전부 다 알아서 진행해")으로 승인했다. Windows host에서 경로 문법과 판정 수단이 어떻게 대응하는지(결정 23), 트리 전송 성능과 audit 처리량이 모자랄 때의 대체 경로, ADR-0045와의 착지 순서를 정해 남은 미정 항목이 없다.

개정 관계: 새 ADR이다. `docs/adr/README.md`의 예약 목록이 P1 계획(`docs/ROADMAP.md` §5) 시점에 이 번호를 파일 복사(M15) 자리로 잡아 두었고, 이 문서가 그 자리를 채운다. 2026-10-11 초안은 `qsh file get`/`qsh file put`으로 파일 하나씩만 옮기고, 원격 경로는 그 action을 준 `[[acl]]` 행의 `paths` 아래로만 열었다. 2026-10-12 사용자 결정("권한 설정을 보다 간소화… 파일 단위로 복잡하게 관리하는게 귀찮아")이 P1을 다시 짜면서 이 초안을 네 곳에서 개정한다.

- 사람 표면을 scp 호환 `qsh cp`로 바꾼다. `qsh file get`/`put`은 만들지 않는다(출시된 적이 없다). 초안이 범위 밖으로 둔 디렉터리 재귀 복사(`-r`)를 범위에 넣는다. 그에 필요한 wire op은 `file.list`와 `file.mkdir` 둘이고 새 action은 더하지 않는다(결정 1, 2, 3, 20).
- 권한은 ADR-0045의 role로 준다. `full` role은 `file.read`/`file.write`를 경로 제한 없이 주고(ADR-0045 결정 5), qsh 자신의 config·state·runtime 경로 거부(결정 5)는 role로도 끌 수 없다. `[[acl]]` 행의 `paths` 키(결정 4)는 `acl.toml` 행으로 파일 권한을 줄 때만 쓰고 role grant에는 걸리지 않는다. "`paths`가 없는 파일 행은 파일 권한이 없다"와 doctor `acl_file_paths_missing`은 행에 한해 유지한다(결정 4-4, 19).
- 덮어쓰기는 scp처럼 기본 허용이고(원자적 교체), 막으려면 `--no-clobber`를 쓴다(결정 7). 초안의 `--force`는 없다.
- audit 키 집합은 아홉에 ADR-0045 결정 16의 optional 키 `role` 하나를 더한 것이다(결정 14). 크기는 4.3~6.3ew로 다시 센다.

ADR-0045(승인됨)가 먼저 착지해야 `full` role이 파일 action을 준다. 같은 M15 안에서 ADR-0045가 앞서고 이 ADR이 뒤따른다. ADR-0044 결정 2의 자동 SSH 부트스트랩은 사람 모드의 `qsh cp`가 미등록 host 이름에 닿을 때도 발동하고, 이 ADR은 그 발동 지점에 아무것도 더하지 않는다. 승인되면 바뀌는 계약 문서는 셋이다. `docs/PRD.md` §9는 action 목록이 그대로이고 `file.read`/`file.write`가 항상-deny에서 풀리며, `acl.toml` 문법에 optional 키 `paths`가 는다. `docs/CLI.md`는 §2.4에 op 다섯(`file.copy`와 wire op 넷), §2.5에 매핑 넷, §6에 `qsh cp` 절 하나가 늘고, §6.15(`acl check --path`), §6.17(doctor 코드 하나), §6.19(`acl show`의 `paths` 필드)가 바뀐다. `docs/design/protocol.md`는 §4 capability 목록, §7 스트림 표, §9 `.proto`, §12 정체 장부의 범위가 바뀐다. TCP/TLS fallback은 철회됐으므로(ADR-0043) 이 ADR은 QUIC transport 하나만 다룬다.

## 맥락

PRD §7은 streaming file copy를 P1에 두고, PRD §9의 action 어휘는 P0부터 `file.read`/`file.write`를 갖는다. 오늘 두 action은 `Action::is_always_denied`가 어떤 규칙보다 먼저 거부한다. 그것을 부를 wire op이 없으니 `DENY_SEAMS`에도 행이 없다(`crates/qsh-core/src/acl/registry.rs` 모듈 doc). `docs/ROADMAP.md` M15는 op을 등록하고 항상-deny를 걷되, 착수 전에 이 ADR이 다음을 정하라고 적는다. 명령 이름과 모양, 청크·부분 전송·재개 여부, 무결성 확인, ACL resource 모델(경로를 resource로 쓸지와 소유 축), 경로 제약(symlink, 상위 경로 이탈, 덮어쓰기), 동시 전송 quota, audit 레코드의 필드 집합, 역방향 route 지원 여부다.

M15가 반드시 담으라고 한 결정이 하나 더 있다. `file.write`는 `qsh serve`의 uid로 파일을 쓰고, 그 uid는 `acl.toml`, `trust.toml`, `invites.toml`, identity와 keystore, `resume.json`, audit 로그를 모두 쓸 수 있다.

- `acl.toml`에 닿으면 원격 peer가 ACL writer가 된다. ADR-0017 결정 1과 ADR-0025 결정 1이 로컬 명령에서조차 닫아 둔 자리다.
- `trust.toml`은 더 나쁘다. `SharedTrustStore::lookup_pin`이 handshake마다 파일을 다시 읽으므로(`crates/qsh-core/src/trust/mod.rs`) 원격 쓰기 하나로 재시작 없이 새 pin이 심긴다. ADR-0045가 pin에 role을 두면서 `trust.toml`과 `invites.toml`에 쓰는 일은 곧 권한을 쓰는 일이 되었다(ADR-0045 결정 18).
- audit 로그를 덮어쓰면 SC6 추적성이 지워진다.
- `file.read`는 반대 방향으로 같은 자리를 연다. identity 개인키, `resume.json`의 resume token(ADR-0007), `stateless_reset.key`(ADR-0036), `invites.toml`의 invite 상태를 원격으로 읽을 수 있게 된다.

설계를 가르는 사실은 이렇다.

- ACL 규칙(`crates/qsh-core/src/acl/policy.rs`의 `Rule`)은 `principal`, `auth_path`, `allow`, `scope` 넷뿐이다. resource는 `Authorizer::check`가 받는 자유 문자열(`ResourceRef.id`)이고 audit에 실리지만 어떤 규칙도 그것을 매칭하지 않는다. `forward.local`이 목적지를 가리지 않고 `exec.run`이 argv를 가리지 않는 것도 이 때문이다. 소유 축(`scope = "owned"`)은 `ResourceRef.owner`가 있는 자원(세션, `-R` forward)에만 걸린다.
- `acl.toml` 로더(`crates/qsh-core/src/acl/load.rs`)는 모르는 키를 오류 없이 무시한다(`docs/CLI.md` §2.3). 아는 키의 값이 틀리면 파일 전체가 `CONFIG_ERROR`가 되어 모든 요청이 거부된다(부분 적용 없음). action 패턴은 exact와 `<family>.*`뿐이어서 파일 action을 주는 패턴은 `file.read`, `file.write`, `file.*` 셋뿐이다.
- 여러 op이 한 action으로 인가되는 선례가 이미 있다(`docs/CLI.md` §2.5의 `session.read`, `session.get`, `tunnel.close` 등). 그래서 `file.list`와 `file.mkdir`은 새 action 없이 `file.read`/`file.write`로 인가할 수 있다. 새 action을 더하면 PRD §9의 action 어휘(`acl_docs.rs`가 대조한다)와 ADR-0045 결정 2의 role 표가 함께 바뀐다.
- 인가가 필요한 data 스트림의 선례는 `EXEC_DATA`다. control 요청이 ACL을 통과한 뒤에만 ticket(128-bit 난수, 단회, 30초)이 발급되고 data 스트림은 `StreamHeader{EXEC_DATA, ticket}`로 시작한다(`docs/design/protocol.md` §7). 역방향 route에서는 같은 `StreamHeader`가 `LOCAL_STREAM` conduit을 그대로 탄다(§11-3 "터널 conduit").
- 우선순위 band는 이미 "tunnel/file 0"이라고 적어 두었다(§12). 정체 터널 스트림 장부(ADR-0037)는 터널 스트림만 센다. quota는 ADR-0010의 모양을 따른다. 인가 뒤, 자원 생성 전에 판정하고 살아 있는 자원 자체를 센다.
- audit 레코드의 키 집합은 `ts`, `request_id`, `peer_addr`, `principal`, `auth_path`, `action`, `resource`, `decision`, `rule` 아홉이다(`record_has_only_structural_fields`, `crates/qsh-core/src/audit/tests.rs`).
- 원격 host가 돌려주는 디렉터리 항목 이름은 신뢰할 수 없는 입력이다. scp의 알려진 취약점(악의적인 서버가 `..`나 `/`가 든 이름을 보내 client의 로컬 경로를 벗어나게 하는 것)이 정확히 이 자리다. 재귀 복사를 넣으면 qsh client가 같은 자리를 갖게 된다(결정 22).

## 결정

1. 범위. 파일과 디렉터리 트리를 로컬 장비와 원격 qsh host 사이에서 복사한다. 한 번의 호출은 한 방향이다. 로컬에서 원격으로 보내는 쪽을 put, 원격에서 받아 오는 쪽을 get이라 부른다. 하지 않는 일은 다음과 같다.
   - 원격에서 원격으로 복사하지 않는다. 양쪽 operand가 모두 `host:path`이면 `INVALID_ARGUMENT`이고, 로컬을 거쳐 get과 put을 따로 부르라고 안내한다. 로컬에서 로컬로도 복사하지 않는다(`cp`를 쓴다).
   - 동기화(변경분만 보내기, 삭제 전파)와 원격 파일 목록 명령은 만들지 않는다. `file.list`는 복사가 쓰는 op일 뿐이고 `qsh ls`는 없다.
   - symlink와 특수 파일을 만들지 않고, 소유자·xattr·ACL·hard link를 옮기지 않는다(결정 7, 20).
   - transport는 QUIC 하나다(ADR-0043). 새 capability 문자열 `file.v1` 하나가 네 op를 모두 덮는다. client는 peer의 협상된 capability 집합에 `file.v1`이 없으면 요청을 보내기 전에 `UNSUPPORTED`로 끝낸다.
   - scp 프로토콜이나 sftp 서브시스템과는 호환되지 않는다. `qsh cp`는 qsh host와만 말한다. 인자 문법이 같을 뿐이다.

2. CLI 모양과 인자 문법.

   ```bash
   qsh cp [-r] [-p] [-q] [--no-clobber] [--json | --jsonl] SRC... DST
   ```

   - operand가 원격인지는 scp의 규칙으로 가린다. 첫 `/`보다 앞에 `:`가 있고 그 앞의 host 부분이 비어 있지 않으면 `[user@]host:path`다. IPv6는 `[::1]:path`처럼 대괄호로 싼다. `./a:b`는 로컬 파일이다. `host:`는 원격 계정의 home 디렉터리를 뜻한다. Windows client(ADR-0035)에서는 한 글자 뒤의 `:`가 드라이브 문자라서 로컬로 해석한다. 이 문장은 ADR-0035 결정 1(Windows client, M19)과 함께 효력이 생긴다.
   - 한 호출의 operand 구성은 둘 중 하나여야 한다. SRC가 모두 로컬이고 DST가 원격이거나(put), SRC가 모두 같은 host의 원격이고 DST가 로컬이다(get). 그 밖의 구성, 곧 로컬과 원격이 섞인 SRC, host가 둘 이상, 양쪽이 같은 종류인 경우는 복사를 시작하기 전에 `INVALID_ARGUMENT`(exit `2`)다.
   - host 이름 해석은 `qsh exec`와 같다(`docs/CLI.md` §6.1 우선순위, live reverse 등록 우선). `user@`는 `qsh [user@]host`와 같은 뜻의 단언이다(`docs/CLI.md` §7). `FileReadOpen`/`FileWriteOpen`/`FileListOpen`/`FileMkdirOpen`이 optional `user`를 싣고, host는 ACL 판정 뒤에 serve 계정의 login name과 대조해 다르면 `UNSUPPORTED`(user switching is not supported)로 거부한다. `hosts.toml`의 `user` 기본값도 같은 규칙으로 채운다.
   - 원격 경로는 절대 경로, home 기준 상대 경로(`dir/x`), `~`, `~/x`를 받는다. `~name`은 `INVALID_ARGUMENT`다. home은 host가 serve 계정의 passwd 항목에서 구한다. 환경 변수 `HOME`은 쓰지 않는다. 경로 끝의 `/`는 "이것은 디렉터리여야 한다"는 단언이고, 디렉터리가 아니면 `INVALID_ARGUMENT`다.
   - 결과 위치는 scp와 같다. SRC가 둘 이상이면 DST는 이미 있는 디렉터리여야 한다. SRC가 하나이고 DST가 이미 있는 디렉터리면 그 안에 SRC의 마지막 성분 이름으로 놓는다. SRC가 하나이고 DST가 없으면 DST가 새 이름이다. SRC가 디렉터리인데 `-r`이 없으면 그 operand만 실패(`INVALID_ARGUMENT`, "is a directory; use -r")하고 다른 operand는 계속한다. SRC의 마지막 성분이 `.`, `..`, `~`, 빈 문자열, `/`처럼 이름을 만들 수 없으면 디렉터리가 아니라 그 내용을 DST 안에 복사한다(`cp -r src/. dst`와 같다).
   - 플래그는 넷이다. `-r`은 디렉터리를 재귀로 복사한다. `-p`는 파일 mode와 수정 시각을 옮긴다(결정 7). 접근 시각은 옮기지 않는다. `-q`는 진행 표시와 human 요약 줄을 끈다. `-v`는 전역 `-v`와 같다. `--no-clobber`는 이미 있는 대상 파일을 덮지 않고 그 항목을 건너뛴다(결정 7). `--json`/`--jsonl`은 전역 출력 모드다.
   - 그 밖의 scp 플래그(`-P`, `-i`, `-o`, `-F`, `-J`, `-l`, `-c`, `-C`, `-S`, `-B`, `-3`, `-4`, `-6`, `-T`, `-O`, `-s` 등)는 `INVALID_ARGUMENT`(exit `2`)이고, "scp option -P is not supported by qsh cp" 뜻의 한 줄을 stderr에 낸다. 무시하지 않는다. 포트, 키, jump, 대역 제한을 무시하면 사용자가 믿는 것과 실제 동작이 어긋난다. ssh 설정이 필요한 쪽은 ADR-0044의 부트스트랩이 시스템 ssh에 맡긴다.
   - `-`(stdin/stdout)는 받지 않고 `INVALID_ARGUMENT`다. machine 모드의 stdout은 envelope 한 줄만 싣는다(CLAUDE.md 계약 규칙, `docs/CLI.md` §2.2).
   - 출력. human 모드는 stderr가 TTY일 때 파일별 진행 표시를 stderr에 그리고(`-q`로 끈다), 끝나면 stdout에 요약 한 줄(파일 수, 바이트, 시간, 건너뜀과 실패 수)을 낸다. machine 모드는 진행 표시를 내지 않는다(`docs/CLI.md` §2.1). JSON/JSONL 모양은 결정 18이다.
   - ADR-0044 결정 2에 따라 human 모드의 `qsh cp`는 host 이름이 미등록(`HOST_NOT_FOUND`의 첫 갈래)일 때 SSH 부트스트랩을 자동으로 거친 뒤 이어 간다. `--json`/`--jsonl`에서는 발동하지 않는다.

3. op 이름과 ACL 매핑. wire에 오르는 op은 넷이고 action은 둘이다.

   | op | wire 요청 | action | 하는 일 |
   |---|---|---|---|
   | `file.read` | `FileReadOpen` | `file.read` | 정규 파일 하나를 읽어 온다 |
   | `file.write` | `FileWriteOpen` | `file.write` | 파일 하나를 쓴다 |
   | `file.list` | `FileListOpen` | `file.read` | 경로 하나의 메타데이터와, 디렉터리면 그 한 단계 항목을 돌려준다 |
   | `file.mkdir` | `FileMkdirOpen` | `file.write` | 디렉터리 하나를 만든다 |

   - `docs/CLI.md` §2.4에 `file.copy`와 위 넷을 더하고 §2.5에 매핑 넷을 더한다. `qsh cp`의 envelope `command`는 `file.copy`다. 이것은 client가 위 op들을 엮는 합성 operation이고 wire 메시지도 ACL 행도 없다. `setup.run`과 같은 지위의 로컬 operation이라서 §2.5 "인가 불요" 행에 오르고, 원격 peer가 요청할 수 없다. 등록 테스트가 `file.copy`에 대응하는 wire 메시지가 없음을 확인한다(`setup_run_never_appears_as_a_control_message_wire_variant`와 같은 형식).
   - `Action::is_always_denied`는 `forward.socks` 하나만 남긴다. `allow = ["file.*"]`는 두 action을 모두 열되, 행으로 열 때는 그 행의 `paths` 아래에서만이다(결정 4). 거부는 기존 `PERMISSION_DENIED_MESSAGE` 그대로이고, 네 op은 `SeamKind::ControlStreamOp` 행으로 `DENY_SEAMS`에 오른다.
   - `file.list`는 `file.read`로, `file.mkdir`은 `file.write`로 인가한다. 목록을 보는 일은 읽기이고 디렉터리를 만드는 일은 쓰기이기 때문이다. 그래서 파일을 쓰기만 하도록 연 principal은 대상 디렉터리를 `file.list`로 볼 수 없다(결정 20은 그 경우를 위해 쓰기 op이 디렉터리 판별을 host 쪽에서 한다).

4. 권한 모델. 파일 action을 주는 길은 둘이고 합집합이다(ADR-0045 결정 4).
   1. role. `full` role이 `file.read`/`file.write`를 준다(ADR-0045 결정 2). 경로 제한이 없다. serve 계정이 접근할 수 있는 경로 전부이고, scp와 같다. 결정 5의 거부와 열린 핸들 재검증만 위에 얹힌다. `exec` 등 다른 role은 파일 action을 주지 않는다.
   2. `acl.toml` 행. 파일 action을 주는 행은 optional 키 `paths`로 범위를 적고, 이 키는 행에서만 쓴다(role grant에는 걸리지 않는다. ADR-0045 결정 5). 문법과 매칭 규칙은 아래 3~7이다.
   3. 문법. `[[acl]]` 행에 optional 키 `paths`를 둔다. 값은 절대 경로 문자열의 배열이다.

      ```toml
      [[acl]]
      principal = "device:laptop"
      allow = ["file.*"]
      paths = ["/home/dave/share", "/srv/builds"]
      ```

      항목마다 로드 시점에 어휘적 모양만 검사한다. `/`로 시작하고, NUL이 없고, 4096바이트 이하이며, `.`·`..`·빈 성분이 없어야 한다. 끝의 `/`는 `"/"` 자신을 빼면 허용하지 않는다(`acl show`가 돌려주는 문자열이 매칭에 쓰이는 문자열과 같도록 표기를 하나로 고정한다). 빈 배열, 행당 64개(`MAX_PATHS_PER_RULE`) 초과, 위 모양 위반은 모두 파일 전체의 `CONFIG_ERROR`다. 오류 문면은 행 index와 항목 index만 싣고 경로 문자열은 싣지 않는다. glob은 없다(대안 절).
   4. 매칭과 무권한 규칙. 평가 순서 ③(action 패턴)에서 파일 action에 매칭된 행은 ③-1을 하나 더 통과해야 매칭으로 친다. 요청 경로의 정규 경로(결정 6)가 그 행 `paths` 항목 하나의 정규 경로와 같거나 그 아래에 있어야 한다. 비교는 경로 성분 단위다. `/srv/share`는 `/srv/share/a.txt`를 덮지만 `/srv/shared/a.txt`는 덮지 않는다. `"/"`는 상태 경로를 뺀 전 범위를 뜻한다. 항목도 요청마다 결정 6의 함수로 정규화하고, 정규화할 수 없는 항목(존재하지 않음, `EACCES`, 루프)은 아무것도 덮지 않는다. `paths`가 경로를 덮지 않는 행은 매칭되지 않은 행이므로 평가는 다음 행으로 넘어간다. `Verdict.rule`과 audit `rule`은 경로까지 덮은 행의 index다.

      `paths` 없는 파일 행은 파일 권한을 주지 않는다. 파일 action을 주는 패턴이 있고 `paths`가 없는 행은 로드에 성공하지만 ③-1을 언제나 통과하지 못한다. 그 행의 다른 action은 그대로 동작한다. 이 규칙은 role 도입 뒤에도 행에 한해 유지한다. 이유는 근거 절에 있다. 이 상태는 세 곳에서 보인다. 로더가 기동 시 `tracing::warn!` 한 줄을 내고, `qsh acl show`가 그 행의 `paths` 필드를 생략하며 행 몫의 `effective_actions`에서 파일 action을 뺀다. doctor는 `acl_file_paths_missing`으로 알린다(결정 19).
   5. 파일 action이 아닌 행의 `paths`는 `CONFIG_ERROR`다. `paths`가 있는 행의 `allow`는 파일 action 패턴만 담아야 한다. 파일 action이 하나도 없는 행과 섞인 행(`allow = ["file.*", "exec.run"], paths = [...]`) 둘 다 파일 전체의 `CONFIG_ERROR`이고, 문면은 "paths applies only to file actions; put them in a row of their own"의 뜻을 행 index와 함께 싣는다.
   6. 정규화 시점. 경로 매칭에는 정규 경로가 필요하고 정규화는 파일시스템 메타데이터를 읽는다(만들거나 여는 것은 없다). 그래서 ACL 단계를 셋으로 나눈다. (a) 순수 판정으로, 이 principal과 `auth_path`가 이 파일 action을 받을 근거가 있는지만 본다. 근거는 role이 이 action을 주는 것이거나, 이 action을 `paths`와 함께 주는 행이 하나라도 있는 것이다(`acl show`의 `matching_rules`와 같은 helper, ADR-0025 결정 3). 근거가 없으면 정규화하지 않고 (c)로 간다. (b) 근거가 있을 때만 요청 경로를 정규화한다. 정규화가 실패하면(`EACCES`, 루프, 길이 초과) 경로 없이 간다. (c) `Authorizer::check`를 부르고 audit 한 줄을 쓴다. role이 준 grant는 경로를 보지 않고 allow가 나지만, 경로 없는 요청은 행의 ③-1을 통과하지 못해 행으로는 deny다. 그래서 파일 권한이 없는 principal은 host 파일시스템에 조회 한 번 일으키지 못한다.
   7. resource 문자열과 소유 축. `ResourceRef.id`는 요청에 실린 원격 경로 문자열 그대로이고 audit `resource`도 그 값이다(결정 14). 정규 경로는 `ResourceRef`의 새 optional 필드로만 평가기에 건넨다. 파일에는 qsh 소유자 개념이 없으므로 `ResourceRef::unowned`로 넘기고, `scope = "owned"`는 파일 op을 걸러내지 않는다.
   8. 문서에 적을 범위. `docs/CLI.md`의 `qsh cp` 절은 `full` role이 "serve 계정이 접근할 수 있는 경로 전부에서, 결정 5의 상태 경로를 뺀 것"을 준다고 적는다. `~/.bashrc`, `~/.ssh/authorized_keys`, systemd user unit 디렉터리 같은 실행되는 파일에 쓸 수 있으므로 `file.write`가 사실상 `exec.run`과 같은 힘이라는 것도 적는다. `full`은 이미 `exec.run`을 주기 때문에 이 사실은 `full`의 힘에 아무것도 더하지 않는다. 쓰는 범위를 좁히려면 `full`을 쓰지 않고 role `none`에 `paths`가 있는 행을 얹는다. 행 `paths`가 같은 파일을 덮으면 같은 힘이 된다는 점은 같다.

5. 상태 경로는 role과 ACL 행 모두와 무관하게 항상 거부한다. host는 네 op이 결정 6의 정규 경로로 아래 집합에 닿으면 `PERMISSION_DENIED`로 거부한다. 이 판정은 `Authorizer::check`가 allow를 낸 뒤에 돌고, role이나 행이 이 판정을 끌 방법은 없다. `paths = ["/"]`나 config 디렉터리를 직접 적은 항목도, `full` role도 이 집합에 닿지 못한다. 설정 키도 두지 않는다. `file.list`로 보호 디렉터리 안을 나열하는 것과 `file.mkdir`로 그 안에 디렉터리를 만드는 것도 거부 대상이다. 보호 디렉터리의 상위 디렉터리를 나열하면 보호 디렉터리 이름은 항목으로 보이지만, 그 항목 안으로 들어가는 모든 op은 거부된다.
   - 보호 디렉터리(그 아래 전부, 디렉터리 자신 포함): config 디렉터리, state 디렉터리, runtime 디렉터리(`$XDG_RUNTIME_DIR/qsh` 또는 state 아래 `run/`, localctl 소켓 디렉터리). `docs/design/architecture.md` §7의 해석 규칙을 따른다. 그래서 `config.toml`, `acl.toml`, `trust.toml`, `invites.toml`, `hosts.toml`, `identity/`, `stateless_reset.key`(ADR-0036), `resume.json`, 기본 위치의 `audit.log`와 그 회전 파일이 모두 덮인다.
   - 보호 파일: `[audit].path`가 위 디렉터리 밖을 가리키면 그 파일과 회전 파일(`<path>.1`…`<path>.<retain>`), 그리고 그 파일이 있는 디렉터리 안에서 회전이 쓰는 임시 파일 이름. file-mode keystore가 config 밖의 경로를 쓰면 그 경로도 넣는다.
   - 두 해석의 합집합: 위 디렉터리는 이 프로세스가 실제로 쓰는 경로(`$QSH_CONFIG_DIR`, `$XDG_*` 반영)와, 환경 변수 재정의 없이 `$HOME` 기준 기본값으로 해석한 경로를 둘 다 넣는다. 같은 uid의 다른 qsh 인스턴스의 상태도 지키기 위해서다.
   - 집합은 요청마다 새로 해석한다. 기동 시점에 한 번 얼리지 않는다.
   - 이 거부도 `PERMISSION_DENIED_MESSAGE`를 그대로 쓴다. audit에는 ACL allow 줄 뒤에 `decision = "deny"`, `rule = null`인 줄이 하나 더 남는다(role로 allow된 뒤여도 이 두 번째 줄에는 `role` 키가 없다. ADR-0045 결정 16).
   - ADR-0045 결정 18에 따라 이 거부가 곧 권한 상승 방지다. 원격 peer가 `trust.toml`이나 `invites.toml`을 쓰면 자기 role을 올릴 수 있으므로 핀 테스트에 두 파일을 반드시 넣는다(결과 절).

6. 경로 판정 절차. 같은 규칙을 `qsh-core`의 함수 하나(가칭 `file::guard`)에 두고 네 op이 함께 쓴다.
   1. 모양 검사와 home 해석(인가 전). 비어 있지 않음(`host:`의 빈 경로는 client가 `~`로 바꿔 보낸다), UTF-8, NUL 없음, 4096바이트 이하. 형태는 절대, `~`, `~/…`, home 기준 상대 중 하나이고 `~name`은 `INVALID_ARGUMENT`다. 절대가 아니면 passwd 항목의 home을 앞에 붙여 절대 경로로 만든다(어휘적이며 파일시스템 경로를 조회하지 않는다. passwd 항목이 없으면 `INVALID_ARGUMENT`). `file.write`/`file.mkdir`는 마지막 성분이 `.`, `..`이 아니어야 한다. 끝의 `/`는 "디렉터리여야 한다"는 단언으로 따로 기록한다. `name_if_dir`는 단일 성분이어야 한다(비어 있지 않음, `/`와 NUL 없음, `.`·`..` 아님, 255바이트 이하). 위반은 `INVALID_ARGUMENT`이고 ACL 판정도 audit도 파일시스템 접근도 없다. `..` 성분 자체는 모양 위반이 아니다. 이탈 여부는 아래 정규화가 판정한다.
   2. 정규화(ACL 단계 안, 결정 4-6의 (b)). 경로에서 실제로 존재하는 가장 긴 조상을 `realpath`로 해석하고, 남은 성분을 어휘적으로 붙인다(남은 부분의 `..`는 어휘적으로 접는다). 대상이 존재하는 symlink면 끝까지 따라간 경로가 정규 경로다. 그래서 `/tmp/link → ~/.config/qsh/acl.toml`이나 `/home/x/../dave/.config/qsh/trust.toml`은 보호 경로로 판정되고, `paths = ["/srv/share"]` 아래의 `/srv/share/k → ~/.ssh/id_ed25519`나 `/srv/share/../../home/dave/.ssh/id_ed25519`는 `paths` 밖으로 판정된다. 같은 정규 경로를 `paths` 매칭과 보호 집합 대조가 함께 쓴다. role만으로 allow된 요청은 ACL 단계에서 정규화하지 않으므로, 결정 8의 상태 경로 단계가 같은 함수로 정규 경로를 얻는다. 존재하지 않는 경로도 보호 디렉터리 아래면 거부되므로, 상태 디렉터리 안에서 어떤 파일이 있는지를 오류 차이로 알아낼 수 없다.
   3. 보호 집합 대조. 정규 경로가 보호 디렉터리 아래에 있거나 보호 파일과 같으면 거부한다(결정 5).
   4. 열린 핸들 재검증. 판정과 열기 사이에 경로 성분이 바뀌는 경쟁을 막는다. `file.read`는 정규 경로를 `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`로 연다. `file.list`는 정규 경로를 `O_DIRECTORY | O_NOFOLLOW`로 열어(정규 경로가 파일이면 `fstatat`만 한다) 그 fd로 읽는다. `file.write`와 `file.mkdir`은 정규 경로의 부모 디렉터리를 `O_DIRECTORY | O_NOFOLLOW`로 연다. 연 뒤 fd가 가리키는 실제 경로(Linux는 `/proc/self/fd/<n>`의 readlink, macOS는 `fcntl(F_GETPATH)`)로 두 판정을 다시 한다. 하나는 3의 보호 집합 대조이고, 다른 하나는 같은 평가기(`Authorizer::check`)를 이 경로로 다시 불러 allow가 나는지 보는 것이다. 둘 중 하나라도 어긋나면 거부하고 fd를 닫는다. 재평가가 다른 근거로 allow를 내는 것은 허용이다. 이 거부는 audit에 `decision = "deny"`, `rule = null`인 줄 하나를 더 남긴다. 이후의 생성·교체·하위 생성은 모두 이 디렉터리 fd에 대한 `openat`/`mkdirat`/`linkat`/`renameat`/`unlinkat`로만 한다.
   5. inode 대조(`file.read`). 연 파일의 `(dev, ino)`가 보호 파일(결정 5에 열거된 파일, 그 시점에 존재하는 것)의 `(dev, ino)`와 같으면 거부한다. 보호 디렉터리 밖에 만든 hard link로 `acl.toml`이나 `device.key`를 읽는 우회를 막는다. `file.write`는 결정 7대로 디렉터리 항목을 교체할 뿐 기존 inode에 쓰지 않으므로 hard link 우회가 성립하지 않는다.
   6. 파일 종류. `file.read`는 `fstat`이 정규 파일일 때만 진행한다. 디렉터리, FIFO, 소켓, 장치는 `INVALID_ARGUMENT`다. `O_NONBLOCK`으로 열기 때문에 FIFO에서 열기가 멈추지 않는다. `file.write`의 대상이 이미 있고 정규 파일이 아니면 `INVALID_ARGUMENT`다. `file.mkdir`의 경로가 이미 있으면 디렉터리일 때만 성공(`created: false`)이고 아니면 `INVALID_ARGUMENT`다.

7. 덮어쓰기, 원자성, mode.
   - `file.write`는 대상 디렉터리(결정 6-4의 fd) 안에 임시 파일 `.<name>.qsh-<16 hex>.part`를 `O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600`으로 만든다. 받은 바이트를 쓰고, 결정 10의 검증을 통과하면 `fsync`하고 `fchmod`로 최종 mode를 적용한 뒤 교체한다.
   - 기본은 덮어쓴다(scp와 같다). `FileWriteOpen.overwrite`가 `true`이면 `renameat(temp, name)`이다. `--no-clobber`를 주면 client가 `overwrite = false`를 보내고, host는 `linkat(temp, name)`으로 붙인 뒤 temp를 `unlinkat`한다. 대상이 그 사이에 생겼으면 `EEXIST`로 실패하므로 확인과 교체 사이의 경쟁에서도 기존 파일을 덮지 않는다. `overwrite = false`인데 대상이 이미 있으면 host는 열기 단계에서 `INVALID_ARGUMENT`(message `destination exists`)로 답하고 ticket을 발급하지 않는다. client는 이 응답을 실패가 아니라 그 항목의 `skipped`(reason `exists`)로 기록한다. 데이터를 보낸 뒤 `linkat`이 `EEXIST`로 실패하는 경쟁에서는 `FileWriteResult`가 `ok = false`와 `code = "INVALID_ARGUMENT"`를 싣고, client는 같은 `skipped`로 기록한다.
   - 교체 뒤 디렉터리를 `fsync`한다. 교체는 새 inode를 놓는 것이므로 기존 대상 파일의 소유자, hard link, xattr, ACL은 유지되지 않는다. scp가 제자리에서 덮어쓰는 것과 다른 점이고 문서에 적는다.
   - mode. 원본의 권한 비트를 `& 0o777`로 잘라 `FileWriteOpen.mode`에 싣는다. setuid, setgid, sticky는 옮기지 않는다. `-p`가 없으면 최종 mode는 `mode & ~umask`이고 수정 시각은 쓴 시각이다. `-p`가 있으면 client가 `preserve = true`와 원본의 `mtime`을 싣고, 최종 mode는 `mode` 그대로이며 수정 시각은 `futimens`로 temp에 설정한다(접근 시각은 건드리지 않는다). umask는 프로세스 시작 때 한 번 읽어 둔다. 소유자는 serve uid이고 xattr·ACL은 옮기지 않는다.
   - 디렉터리. `file.mkdir`은 `((mode & ~umask) | 0o700)`(`-p`면 `mode | 0o700`)로 만든다. 소유자 rwx를 항상 켜서, 원본이 읽기 전용 디렉터리여도 그 안에 파일을 쓸 수 있게 한다. 그 결과 읽기 전용 디렉터리의 mode는 `-p`로도 옮겨지지 않는다. 디렉터리 수정 시각은 옮기지 않는다(하위 항목을 쓰면 다시 바뀐다). 이미 있는 디렉터리에는 합쳐 넣는다(`created: false`).
   - 실패, 취소, 연결 유실, 검증 실패 중 어느 경우든 temp를 `unlinkat`하고 대상은 건드리지 않는다. 결과적으로 파일 대상은 "옛 내용 그대로" 아니면 "새 내용 전부" 둘 중 하나다. 트리 전체의 원자성은 없다(결정 21).
   - client 쪽 get의 로컬 쓰기도 같은 temp·link/rename·fsync 규칙을 쓴다. 로컬 쪽에는 결정 5의 보호 집합을 적용하지 않는다. 로컬 사용자가 자기 머신에서 직접 고른 경로이고, 원격 peer는 로컬 경로를 정하지 못하기 때문이다. 단 로컬 DST 아래의 쓰기는 DST 디렉터리 fd 기준의 `*at` 호출로 하고 symlink를 따라가지 않는다(DST 자신은 사용자가 준 인자라서 따라간다). DST 아래에 이미 있는 symlink는 그 항목을 `INVALID_ARGUMENT`로 실패시킨다.

8. host 처리 순서. 순서는 고정이고 앞 단계가 실패하면 뒤 단계는 돌지 않는다.
   1. 모양 검사와 home 해석 (6-1). 실패하면 audit도 파일시스템 접근도 없다
   2. ACL (결정 4-6): (a) 이 principal·`auth_path`가 이 파일 action을 받을 근거가 있는지 순수 판정, (b) 있으면 정규화(6-2), (c) `Authorizer::check` + audit 한 줄
   3. user hint 대조 (결정 2). 불일치는 `UNSUPPORTED`
   4. 상태 경로 판정 (6-3. role만으로 allow됐으면 여기서 처음 정규화한다. deny면 audit 한 줄 더)
   5. `file.read`/`file.write`만: quota 예약 (결정 12)
   6. 열기와 재검증 (6-4~6-6). 재검증은 상태 경로와 평가기 재호출을 둘 다 본다. `file.write`는 대상 존재 여부와 `overwrite` 확인, 디렉터리 해석(결정 20), 여유 공간 확인(결정 13)을 여기서 한다
   7. 응답. `file.read`/`file.write`는 ticket 발급과 응답, `file.list`/`file.mkdir`은 결과 응답

   `file.read`는 6에서 연 파일 fd를, `file.write`는 디렉터리 fd를 ticket에 묶어 둔다. 디스크에 보이는 자원(temp 파일)은 data 스트림이 ticket을 상환한 뒤에야 만든다. ticket이 30초 안에 상환되지 않으면 fd를 닫고 quota를 돌려준다. 그래서 deny된 `file.write` 뒤에는 대상 디렉터리에 새 파일도 temp도 없다. `file.mkdir`은 ticket이 없고 3에서 5까지 통과한 뒤에만 `mkdirat`을 부른다. 오류 응답 뒤에 쥔 fd나 quota도 남지 않는다.

9. wire. `docs/design/protocol.md` §16.4의 additive 경로만 쓴다. 기존 번호는 건드리지 않는다.
   - `ControlMessage` oneof에 `FileReadOpen file_read_open = 80`, `FileWriteOpen file_write_open = 81`, `FileListOpen file_list_open = 82`, `FileMkdirOpen file_mkdir_open = 83`을 더한다.
   - `Response` oneof의 빈 번호에 `FileReadOpened file_read_opened = 11`, `FileWriteOpened file_write_opened = 12`, `FileListed file_listed = 13`, `FileMkdirDone file_mkdir_done = 14`를 더한다.
   - `StreamKind`에 `FILE_DATA = 5`를 더한다. `StreamHeader{FILE_DATA, ticket}`로 시작하는 bidi 스트림이고, 요청자가 연다(`EXEC_DATA`와 같다). `file.list`와 `file.mkdir`은 control 요청과 응답으로 끝나서 data 스트림도 ticket도 없다. 디렉터리 순회가 wire에 더하는 것은 이 두 op뿐이고, 새 스트림 종류나 새 frame은 없다.
   - 새 message:

     ```protobuf
     enum FileKind { FILE_KIND_UNSPECIFIED = 0; FILE_KIND_FILE = 1; FILE_KIND_DIR = 2; FILE_KIND_SYMLINK = 3; FILE_KIND_OTHER = 4; }

     message FileReadOpen    { string path = 1; string user = 2; }
     message FileReadOpened  { bytes ticket = 1; uint64 size = 2; uint32 mode = 3; int64 mtime = 4; }
     message FileWriteOpen   {
       string path = 1; uint64 size = 2; uint32 mode = 3; bool overwrite = 4;
       string name_if_dir = 5;  // path가 이미 있는 디렉터리면 그 안에 이 이름으로 쓴다
       bool preserve = 6; int64 mtime = 7; string user = 8;
     }
     message FileWriteOpened { bytes ticket = 1; bool into_dir = 2; }
     message FileListOpen    { string path = 1; string after = 2; string user = 3; }
     message FileEntry       { string name = 1; FileKind kind = 2; uint64 size = 3; uint32 mode = 4; int64 mtime = 5; }
     message FileListed      {
       FileKind kind = 1; uint64 size = 2; uint32 mode = 3; int64 mtime = 4;
       repeated FileEntry entries = 5;  // 이름 바이트 순서, after보다 큰 것만, 최대 FILE_LIST_PAGE_MAX
       bool more = 6; uint32 unlistable = 7;  // UTF-8이 아니라 실을 수 없는 이름의 수
     }
     message FileMkdirOpen   { string path = 1; uint32 mode = 2; string name_if_dir = 3; bool preserve = 4; string user = 5; }
     message FileMkdirDone   { bool created = 1; bool into_dir = 2; }
     message FileFrame {
       oneof body {
         bytes           data   = 1;  // FILE_CHUNK_MAX 이하
         FileEnd         end    = 2;
         FileWriteResult result = 3;  // file.write에서 host → 요청자 방향으로만
       }
     }
     message FileEnd         { uint64 size = 1; bytes blake3 = 2; }   // blake3는 32바이트
     message FileWriteResult { bool ok = 1; string code = 2; string message = 3; bool overwritten = 4; }
     ```

   - `FileListed.kind`는 요청 경로의 종류다(존재하는 symlink는 끝까지 따라간 대상의 종류). `entries[].kind`는 `lstat`의 종류라서 symlink가 `FILE_KIND_SYMLINK`로 보인다. 디렉터리가 아닌 경로의 `entries`는 비어 있다. `FILE_LIST_PAGE_MAX = 512`개를 한 응답의 상한으로 두면 이름 255바이트 기준으로도 `CONTROL_FRAME_MAX`(256 KiB) 안에 든다. 한 디렉터리의 항목이 `FILE_LIST_DIR_MAX = 65536`을 넘으면 `RESOURCE_EXHAUSTED`다. host는 페이지마다 디렉터리를 읽어 정렬하므로(상태를 쥐지 않는다) 상한이 페이지 수와 비용의 곱을 묶는다.
   - `FILE_DATA` 스트림은 §5 frame layer(`u32` BE length + prost, `DATA_FRAME_MAX` 64 KiB)를 그대로 쓰고, `data` 한 조각의 상한은 새 상수 `FILE_CHUNK_MAX = 32 KiB`(`crates/qsh-proto/src/wire.rs`)다. 터널처럼 raw bytes로 바꾸지 않는다. 끝 표지(`FileEnd`)와 쓰기 결과를 스트림 안에서 실어야 하고, 32 KiB당 frame 비용은 수 바이트라 처리량에 의미가 없다. 상한을 넘는 `data`, `end` 뒤의 frame, 요청자가 보낸 `result`는 프로토콜 위반이다. 스트림을 `BAD_HEADER`(0x2001)로 reset하고 결정 7의 정리를 한다.
   - `file.read` 스트림: 요청자가 header를 보내면 host는 EOF까지 `data`를 보낸 뒤 `end`를 보내고 `finish()`한다.
   - `file.write` 스트림: 요청자가 header, `data`들, `end`를 보내고 송신 half를 `finish()`한다. host는 결정 10의 검증과 결정 7의 교체를 끝낸 뒤 `result` 하나를 보내고 `finish()`한다. 거부 teardown은 `TCP_CONNECT`와 같이 결과를 먼저 쓰고 송신 half를 reset하지 않는다(§7).
   - 이 추가로 `.proto`의 top-level `message`가 12개, `ControlMessage` oneof의 branch가 넷, `Response` oneof의 branch가 넷 늘고 enum이 하나 는다. 늘기 전의 총수는 착지 순서에 따라 다르므로 개수 문장은 구현 커밋이 실제 수로 쓴다. §16 발효 전에 착륙하면 같은 커밋에서 §16.1 표의 해당 행을 고친다.

10. 무결성. 보내는 쪽은 보낸 바이트 전체의 BLAKE3-256과 총 길이를 `FileEnd`에 싣는다. 받는 쪽은 받은 바이트로 같은 값을 계산하고, 둘 중 하나라도 다르면 그 파일을 실패로 끝낸다(`file.write`는 host가 교체하지 않고 `INVALID_ARGUMENT`, `file.read`는 client가 교체하지 않고 `REMOTE_ERROR`). 트리 복사에서는 파일마다 따로 검증한다. `file.write`는 `FileWriteOpen.size`와 받은 총 길이도 같아야 하고, `size`를 넘는 바이트가 오면 그 자리에서 끊는다. `FileReadOpened.size`는 열 때의 `fstat` 값으로 안내용이다. 읽는 도중 원본이 바뀌면 `FileEnd`가 실제로 보낸 바이트를 말하고, 그 값이 기준이다. 원본의 일관된 스냅숏은 보장하지 않는다(scp와 같다). TLS가 이미 전송 구간을 인증하므로 이 해시는 구현 결함, 잘린 스트림, 디스크 쓰기 오류를 잡는 끝단 검사다. 성공 envelope의 파일 항목에 hex로 실어 사용자가 원본과 대조할 수 있게 한다. BLAKE3를 고르는 이유는 이미 workspace 의존성이라서다(`Cargo.toml`).

11. 부분 전송과 재개. 재개는 하지 않는다. 전송의 수명은 그것을 실은 QUIC connection에 묶인다(ADR-0018 결정 1과 같은 원칙). connection migration으로 살아남는 경로 변화에서는 전송이 계속되고, connection이 죽으면 진행 중인 파일은 `CONNECTION_FAILED`(`retryable: true`)로 끝나며 양쪽 모두 결정 7대로 temp를 지운다. 같은 명령을 다시 실행하면 모든 파일을 처음부터 다시 보낸다. 덮어쓰기가 기본이라 재실행은 멱등이다(`--no-clobber`로 재실행하면 이미 끝난 파일은 건너뛰고 잘린 파일만 다시 받는 효과가 난다. 잘린 파일은 temp로만 있었으므로 대상 이름에는 없다). 나중에 재개가 필요해지면 `FileWriteOpen`/`FileReadOpen`에 `offset` 같은 필드를 capability 확인 뒤 additive로 더할 수 있다. Ctrl-C(SIGINT)는 진행 중인 스트림을 reset하고 같은 정리를 한 뒤 남은 항목을 시도하지 않고 exit `255`와 `CANCELED`로 끝난다.

12. 동시 전송 quota. ADR-0010의 모양을 따른다. `[serve].max_file_transfers_per_principal`(기본 4)과 `[serve].max_file_transfers`(기본 64, accept arm 단위)를 둔다. 세는 단위는 진행 중인 `file.read`/`file.write` 전송 하나이고, ticket을 발급한 시점부터 스트림이 끝나거나 ticket이 만료될 때까지다. 둘은 같은 계수를 나눠 쓴다. `file.list`와 `file.mkdir`은 자원을 남기지 않는 단발 요청이라 세지 않는다. 판정 자리는 결정 8의 5단계로, ACL과 상태 경로 판정 뒤, 파일을 열기 전이다. 초과는 `RESOURCE_EXHAUSTED`이고 audit `resource`는 `"quota_files_principal"`, `"quota_files_host"`다. `crates/qsh-core/tests/quota_registry.rs`에 두 행을 더하고, `docs/CLI.md` §6.12의 quota 문단에 두 키와 기본값을 적어 `quota_docs.rs`가 대조하게 한다.
    - client는 파일 전송을 동시에 둘까지 돌린다(`FILE_COPY_PARALLEL = 2`, 플래그 없음). 작은 파일이 많은 트리에서 파일마다 드는 control 왕복 하나를 앞 파일의 data 전송과 겹치기 위해서이고, 같은 principal이 `qsh cp`를 둘 동시에 돌려도 기본 quota 4 안에 든다. 디렉터리 생성과 목록 조회는 순서대로 한다.
    - 전송이 quota 초과로 거부되면 client는 자기 전송 하나가 끝나기를 기다렸다 그 항목을 다시 보낸다. 자기 전송이 없는데도 거부되면 그 항목을 `RESOURCE_EXHAUSTED`로 실패시킨다.

13. 쓰기 여유 공간. `file.write`는 결정 8의 6단계에서 대상 파일시스템의 `statvfs` 가용 바이트가 `size + FILE_WRITE_FREE_RESERVE`(256 MiB, 고정 상수) 미만이면 `RESOURCE_EXHAUSTED`로 거부한다. 쓰는 도중 `ENOSPC`도 `RESOURCE_EXHAUSTED`다. audit writer는 기록하지 못하면 모든 op을 거부한다(fail-closed). 그래서 원격 쓰기로 audit 로그가 있는 디스크를 채우면 host 전체가 멈춘다. 이 상수는 그 경로를 막는 최소한의 여유다. 같은 파일시스템을 다른 프로세스가 채우는 경우까지 막지는 않는다(결과 절의 잔여 위험). 트리를 쓰면 파일마다 이 검사를 하므로, 트리 전체가 들어갈지를 미리 계산하지는 않는다.

14. audit 필드 집합. 새 필드를 더하지 않는다. 키 집합은 지금의 아홉에 ADR-0045 결정 16의 optional 키 `role` 하나를 더한 것이다.
    - `action`: `file.read` 또는 `file.write`. `file.list`는 `file.read`로, `file.mkdir`은 `file.write`로 기록되므로 audit 줄만으로는 디렉터리 나열과 파일 읽기를 가를 수 없다. 경로가 디렉터리인지는 `resource`로 짐작할 수밖에 없고, 판정 기록에 필요한 것은 어떤 action으로 어떤 경로에 대한 판정이었는가이다.
    - `resource`: 요청에 실린 원격 경로 문자열(결정 4-7, 정규화·home 해석 전). JSON 직렬화가 제어문자를 이스케이프한다. 정규 경로는 싣지 않는다
    - `rule`: `paths`까지 덮은 행의 index. `paths` 밖이라 deny면 `null`. role로 allow됐으면 `null`
    - `role`: 판정 근거가 role이었을 때만 그 role 이름(ADR-0045 결정 16)
    - 크기, 해시, mode, 파일 내용 바이트는 어디에도 싣지 않는다. audit는 인가 판정의 기록이지 전송 기록이 아니고, 크기와 완료 여부는 판정 시점에 알 수 없다.
    - 한 요청이 남기는 줄: ACL 판정 한 줄(`paths` 밖과 정규화 실패도 여기서 deny). 상태 경로 거부면 deny 한 줄 더. quota 거부면 ADR-0010 모양의 한 줄. 열린 핸들 재검증 거부면 deny 한 줄 더.
    - 트리 복사는 요청마다(목록 페이지, 디렉터리, 파일) 한 줄씩 남는다. 파일 수천 개를 옮기면 줄도 수천 개다. audit writer가 이 양을 감당하는지는 구현 커밋의 측정 테스트가 확인한다(결과 절). 모자라면 고치는 자리는 writer 쪽이다. 줄을 합치거나 솎지 않는다. 요청마다 한 줄이라는 규칙과 fail-closed(기록 없으면 op 없음)는 처리량 때문에 바꾸지 않고, writer 안에서 같은 내구성 계약을 지키는 묶음 기록(group commit)으로 푼다. 그래도 모자라면 `qsh cp`가 파일을 동시에 처리하는 수(`FILE_COPY_PARALLEL`)를 낮추는 것까지가 이 ADR이 허용하는 완화이고, 그보다 나가는 변경은 새 ADR이다.

15. 우선순위와 역압.
    - `FILE_DATA` 송신은 band 0(§12의 tunnel/file)이고, 터널 splice와 같은 송신 깊이 상한 `SEND_DEPTH_CAP_BYTES`(128 KiB)를 적용한다.
    - 받는 쪽의 로컬 쓰기(디스크)는 ADR-0037의 정체 장부에 오른다. 정의(`STALL_AGE` 1초 동안 진전 없음), 끊는 규칙, reset 코드 `0x200E`가 터널 스트림과 같다. 끊긴 전송은 결정 7대로 정리되고 그 항목은 `RESOURCE_EXHAUSTED`로 끝난다. 장부의 범위에 `FILE_DATA`가 들어가는 것은 §12 "범위" 문장의 변경이다. 연결 양 끝과 `localctl` 데몬의 중계에 모두 적용한다.
    - 그래서 같은 연결의 PTY echo 예산은 M13 (b) 하네스가 재는 터널 부하 때와 같은 장치로 지켜진다.

16. 역방향 route를 지원한다. `qsh cp`의 host가 live reverse 등록으로 해석되면 네 op의 control 요청은 `LOCAL_CONTROL` conduit으로, `FILE_DATA` 스트림은 `LOCAL_STREAM` conduit으로 데몬을 거쳐 target에 간다. 새 `LocalStreamKind`는 없다. `LOCAL_STREAM` 다음 frame이 wire `StreamHeader`라는 규칙(§11-3 "터널 conduit")만으로 판별된다. 인가와 상태 경로 판정은 언제나 파일을 쥔 쪽(target의 `qsh serve --to`, forward route의 `qsh serve`)이 한다. `qsh listen` controller는 파일 op 요청을 받으면 지금처럼 `UNSUPPORTED`로 답하고 아무것도 만들지 않는다. capability는 데몬이 `LocalHelloAck.capabilities`로 relay한 target의 집합으로 확인한다. `file.v1`이 없을 때의 메시지는 `-D`의 역방향 거절 문구처럼 원인 둘(target이 오래됨, 로컬 데몬이 업그레이드 전에 뜸)을 함께 짚는다.

17. 오류 코드. 새 `ErrorCode`는 없다.

    | 상황 | code |
    |---|---|
    | 모양 위반, `~name`, `-` 경로, operand 구성 오류, 원격↔원격, 원본 없음, 정규 파일이 아님(`file.read`), 디렉터리에 `-r` 없음, 대상이 디렉터리, 디렉터리를 만들 자리에 파일이 있음, `--no-clobber`로 건너뜀(항목 상태는 `skipped`), 항목 이름 검증 실패(결정 22), 특수 파일, 크기·해시 불일치(`file.write`) | `INVALID_ARGUMENT` |
    | 지원하지 않는 scp 플래그 | `INVALID_ARGUMENT`(exit `2`, 복사 시작 전) |
    | ACL deny(행 없음, role 없음, `paths` 없음, `paths` 밖, 정규화 실패), 상태 경로 판정, 재검증 불일치, inode 일치, OS의 `EACCES`/`EPERM` | `PERMISSION_DENIED`(균일 문면) |
    | quota, 여유 공간, `ENOSPC`, 디렉터리 항목 수 상한, 정체 장부의 끊음 | `RESOURCE_EXHAUSTED` |
    | 크기·해시 불일치(`file.read`, client 판정) | `REMOTE_ERROR` |
    | connection 유실 | `CONNECTION_FAILED`(`retryable: true`) |
    | peer에 `file.v1` 없음, `user@` 불일치 | `UNSUPPORTED` |
    | Ctrl-C | `CANCELED` |

    OS의 `EACCES`를 `PERMISSION_DENIED`로 접는 이유는 상태 경로 판정과 응답이 같아야 하기 때문이다. `ENOENT`(원본 없음의 `INVALID_ARGUMENT`)는 ACL(`paths` 포함)과 상태 경로 판정을 모두 통과한 경로에서만 드러난다. 그래서 파일 존재 여부를 오류 차이로 알아낼 수 있는 범위는 그 principal이 닿는 범위 안으로 한정된다.

18. JSON 계약. `qsh cp --json`은 envelope 하나를 낸다. `command`는 `file.copy`다. 성공 `data`는 다음 모양이다.

    ```json
    {
      "host": "personal-mac",
      "direction": "get",
      "files": 12,
      "directories": 3,
      "bytes": 104857600,
      "skipped": 0,
      "duration_ms": 912,
      "entries": [
        {
          "status": "copied",
          "kind": "file",
          "remote_path": "/home/dave/build/app.tar.zst",
          "local_path": "./out/app.tar.zst",
          "bytes": 104857600,
          "blake3": "5f0c…(64 hex)",
          "mode": 420,
          "overwritten": false
        }
      ],
      "entries_truncated": false
    }
    ```

    - `direction`은 `"get"` 또는 `"put"`이다. `entries`는 항목 하나당 한 원소이고 `status`는 `copied`, `created`(디렉터리), `skipped`(`reason`: `symlink`, `exists`), `failed`(`code`) 중 하나다. 열린 문자열이다. 원소는 처음 `COPY_JSON_ENTRIES_MAX = 1000`개까지만 싣고 넘으면 `entries_truncated: true`다. 모든 항목은 `--jsonl`로 받는다.
    - `remote_path`와 `local_path`는 operand에서 파생한 문자열 그대로다(정규 경로를 돌려주지 않는다). `mode`는 10진 정수다.
    - `--jsonl`은 항목이 끝나는 대로 `qsh.event/v1` event 한 줄을 낸다. `type`은 `file.entry`이고 필드는 위 `entries[]` 원소와 같다. 마지막 줄은 `--json`과 같은 envelope(성공이면 `entries`가 빈 배열)이고 `schema` 필드로 event와 가른다. 새 event `type`은 additive이고 소비자는 모르는 `type`을 무시한다(`docs/CLI.md` §10).
    - 일부 항목이 실패하면 envelope은 `ok: false`이고 `error`에 항목별 결과를 싣는다(결정 21).
    - human 모드는 stdout에 요약 한 줄을 낸다. exit code는 `docs/CLI.md` §4 그대로다(성공 `0`, 인자 오류 `2`, 실패 `255`).

19. ACL 로컬 표면. `paths`가 운영자에게 보이도록 세 로컬 표면을 넓힌다. 모두 `qsh.cli/v1` additive이고 기존 필드의 의미는 바뀌지 않는다. role 쪽 필드(`role`, `granted_by`, `role_actions`)는 ADR-0045 결정 10·11이 정한다.
    - `qsh acl check --path <abs-path>`(`docs/CLI.md` §6.15). 판정할 원격 경로를 받는 optional 플래그다. 모양은 결정 6-1과 같고 위반은 `INVALID_ARGUMENT`다. `acl check`는 enforcement와 같은 정규화 함수(6-2)와 같은 평가기로 판정하므로, 같은 머신에서 돌리면 `paths` 매칭 결과가 enforcement와 같다. `--action`이 파일 action인데 `--path`가 없거나, 파일 action이 아닌데 `--path`가 있으면 `INVALID_ARGUMENT`다. 단 role이 그 action을 주는 principal은 경로와 무관하게 allow이므로, 이때 `--path`는 `paths` 행 판정과 상태 경로 안내에만 쓰인다. `--resource`와 따로 두는 이유는 `--resource`가 정규화 없이 audit `resource`에 실리는 자유 문자열이기 때문이다. `data`에는 optional 필드 `path`(입력 그대로)와 `canonical_path`(정규화에 성공했을 때만)가 는다. `acl check`는 결정 5의 상태 경로 판정을 돌리지 않는다. §6.15의 "enforcement에는 이 평가기 위에 fail-closed 층이 더 있다" 문단에 상태 경로 판정과 열린 핸들 재검증을 더한다. 그래서 `allow` 예측은 `deny`로 뒤집힐 수 있어도 반대로 뒤집히지는 않는다.
    - `qsh acl show`(`docs/CLI.md` §6.19, ADR-0025 결정 2). `matching_rules`의 행마다 optional 필드 `paths`(적힌 그대로의 문자열 배열)를 더한다. 키가 없는 행에서는 필드가 생략된다. `effective_actions`의 파일 action은 role이 주거나, 그 principal에게 그 action을 `paths`와 함께 준 행이 하나라도 있으면 나온다. 이 집합은 파일 action에 대해서도 상한이다. 어느 경로가 열리는지는 `matching_rules[].paths`와 `acl check --path`가 답한다. `paths` 없는 파일 행이 있으면 human 출력이 "grants no file access: the row has no paths" 뜻의 줄을 하나 더 낸다. 3-way 대조(ADR-0025 결정 3)는 "파일 action이 `effective_actions`에 있다 ⇔ role이 주거나 매칭 행의 `paths` 항목 중 하나로 부른 `acl check --path`가 allow"로 넓힌다.
    - doctor `acl_file_paths_missing`(warn, `docs/CLI.md` §6.17). 파일 action 패턴을 가졌는데 `paths`가 없는 행마다 finding 하나를 낸다. 이 code는 `acl.toml` 행에 한해 유지한다. 행은 로드에 성공하고 principal도 매칭되므로 기존 ACL 진단(`acl_principal_unmatched`, `acl_ca_auth_path_missing`, `acl_policy_invalid`)이 덮지 못하는 상태다. 모양과 등급은 `acl_forward_socks_ineffective`를 따른다. 행의 다른 action은 동작하고 깨지는 것은 파일 의도 하나라서 warn이다. 그 행의 principal이 `device:<name>`이고 `auth_path`가 `pin`이며 같은 이름의 pin이 role `full`이면 이 finding을 내지 않는다. 파일 접근이 role로 이미 열려 있어서 깨진 의도가 없기 때문이다. `detail`은 행의 배열 index와 `auth_path`만 싣고 principal 문자열은 싣지 않는다. remedy는 "`paths`를 더하고 serve/listen을 재시작하거나, `qsh trust set-role <name> full`로 role을 주라"이고 꼬리는 `ACL_RESTART_NOTICE`를 축자 재사용한다(ADR-0025 결정 6). 정책이 없거나 파싱에 실패하면 침묵한다. 정규화할 수 없는 `paths` 항목은 이 code로 짚지 않는다. doctor 프로세스와 serve의 파일시스템 시야가 같다는 보장이 없고, 그 항목은 거부 방향으로만 작용한다. 잠금 어휘 규율대로 `EXPECTED_DOCTOR_CODES`와 §6.17 표에 같은 커밋에서 더하고, 개수 문장은 착륙 시점의 실제 개수로 맞춘다.

20. 재귀 복사의 의미. 디렉터리 순회는 항상 원본 쪽 정보를 가진 client가 파일 단위로 한다. host는 트리를 알지 못하고 요청 하나하나를 독립적으로 인가한다.
    - get(`-r`). client가 SRC에 `file.list`를 보내 종류를 안다. 디렉터리면 로컬에 만들고(결정 7) 그 안의 항목을 페이지(`FILE_LIST_PAGE_MAX`)마다 `after` 커서로 이어 받아 이름 바이트 순서로 처리한다. 항목이 파일이면 `file.read`, 디렉터리면 같은 절차를 재귀한다.
    - put(`-r`). client가 로컬 트리를 이름 바이트 순서로 걷는다. 디렉터리는 `file.mkdir`, 파일은 `file.write`로 보낸다. 부모 디렉터리는 항상 자식보다 먼저 만든다.
    - DST가 원격 경로일 때 "이미 있는 디렉터리면 그 안에 놓는다"는 판단은 host가 한다. 쓰기 쪽에 `file.list`를 요구하지 않으려는 것이다(파일 쓰기만 열어 둔 principal이 있다). 최상위 파일은 `FileWriteOpen.name_if_dir`에 SRC 이름을 싣고, 최상위 디렉터리는 `FileMkdirOpen.name_if_dir`를 싣는다. host는 경로가 이미 있는 디렉터리면 `경로/name_if_dir`을 대상으로 삼고(`into_dir = true`), 아니면 경로 자체를 대상으로 삼는다. client는 응답의 `into_dir`로 하위 항목의 기준 경로를 정한다(문자열 이음이고 정규 경로를 받지 않는다). 대상이 경로의 마지막 성분이므로 판정과 쓰기가 같은 디렉터리 fd를 쓴다(6-4). ACL은 요청한 경로에 대해 한 번 판정하며, 그 아래 `name_if_dir`는 이미 허용된 디렉터리의 자식이라 `paths` 안에 머문다.
    - symlink. 명령줄에 준 최상위 operand가 symlink면 끝까지 따라간다(get은 host의 정규화가, put은 로컬 `metadata`가 한다). 트리 안에서 만난 symlink는 따라가지도 복사하지도 않고 `skipped`(reason `symlink`)로 보고한다. 순환과 `paths` 우회를 구조적으로 막고, 만들 수 없는 symlink를 조용히 빠뜨리지도 않기 위해서다.
    - 특수 파일(FIFO, 소켓, 장치)은 트리 안이든 최상위든 그 항목을 `INVALID_ARGUMENT`로 실패시킨다. 거부하는 것이고, 건너뛰는 것이 아니다.
    - hard link는 파일마다 따로 복사하고, 희소 파일은 채워서 보낸다. 소유자·xattr·ACL은 옮기지 않는다.
    - 이름이 UTF-8이 아니라 wire의 `string`에 실을 수 없는 항목은 host가 `FileListed.unlistable`로 개수만 알린다. client는 그 개수를 실패 항목 하나("unrepresentable names")로 보고한다.
    - 경로가 4096바이트를 넘는 항목은 `INVALID_ARGUMENT`로 실패한다. 깊이 상한은 따로 두지 않는다. 경로 길이 상한이 깊이를 묶는다.
    - 트리 순회 중 원본이 바뀌면(파일이 사라지거나 늘어남) 그 항목의 결과는 그 시점의 `file.read`가 말한 대로다. 트리의 일관된 스냅숏은 없다.

21. 부분 실패와 exit code. scp와 같이 한 항목의 실패가 나머지를 멈추지 않는다.
    - 항목의 결과는 `copied`, `created`, `skipped`, `failed` 넷이다. 한 항목이 실패하면 그 항목(디렉터리면 그 아래 전부)만 포기하고 나머지를 계속한다. 연결 수준의 실패(`CONNECTION_FAILED`, `CANCELED`, capability `UNSUPPORTED`, 인증 오류)는 남은 항목을 시도하지 않고 멈춘다. 시도하지 못한 항목 수는 `not_attempted`로 센다.
    - 끝난 항목은 되돌리지 않는다. 만든 디렉터리와 끝낸 파일은 남는다. 실패한 파일은 temp까지 지워서 대상 이름에는 흔적이 없다(결정 7).
    - 모든 항목이 `copied`/`created`/`skipped`이면 exit `0`이다. `skipped`는 정상이며 human 요약 줄과 JSON의 `skipped`, `entries[].reason`으로 드러난다. 하나라도 `failed`이거나 중간에 멈췄으면 exit `255`이고 envelope은 `ok: false`다. 인자 오류는 복사를 시작하기 전에 exit `2`로 끝나고 아무것도 바꾸지 않는다.
    - 실패 envelope의 `error.code`는 첫 `failed` 항목의 code이고(연결 수준 실패로 멈췄으면 그 code), `message`는 "N of M entries failed"의 뜻이다. `error.retryable`은 멈춘 이유가 `CONNECTION_FAILED`일 때만 `true`다. `error.details`는 `copied`, `created`, `skipped`, `failed`, `not_attempted`(정수)와 `failures`(처음 `COPY_JSON_FAILURES_MAX = 64`개의 `{side, path, code}`), `failures_truncated`를 싣는다. 단일 파일 복사의 실패도 같은 모양이다.
    - 읽을 수 없는 하위 항목(상태 경로 거부를 포함한 `PERMISSION_DENIED`)도 같은 규칙이라 `qsh cp -r host:~ .`는 qsh 자신의 상태 디렉터리 때문에 나머지를 다 옮기고도 exit `255`로 끝난다. scp가 읽을 수 없는 항목을 보고하고 계속한 뒤 실패로 끝나는 것과 같다.

22. 원격이 주는 이름과 크기를 믿지 않는다. get에서 client가 받는 `FileEntry.name`은 신뢰할 수 없는 입력이다. client는 로컬 경로를 만들기 전에 이름이 비어 있지 않고, 255바이트 이하이며, `/`와 NUL을 담지 않고, `.`도 `..`도 아닌지 확인한다. 하나라도 어기면 그 항목을 `INVALID_ARGUMENT`로 실패시키고 로컬에는 아무것도 만들지 않는다. 로컬 경로는 항상 DST에서 시작해 검증된 단일 성분 이름을 하나씩 붙여 만들고(결정 7의 `*at` 호출), 성분 안에서 상위로 올라가는 일이 구조적으로 없다. `FileEntry.size`, `mode`, `mtime`과 `FileListed.more`는 안내용이다. 이 값들로 메모리나 디스크를 미리 잡지 않는다(디스크 여유는 로컬에서 쓰는 도중 `ENOSPC`가 판정한다). 호스트가 끝없이 페이지를 이어 주는 경우를 막으려고 client는 한 디렉터리에서 `FILE_LIST_DIR_MAX`를 넘는 항목을 받으면 그 디렉터리를 `RESOURCE_EXHAUSTED`로 실패시킨다.

23. 플랫폼 동등(PRD §4). 위의 결정은 Linux, macOS, Windows host에서 같은 성질을 낸다. 판정 순서(모양 검사, ACL, user hint, 상태 경로, quota, 열기와 재검증), 상태 경로 항상 거부, 임시 파일과 교체, 해시, 오류 코드, audit 키, wire와 JSON은 OS마다 갈리지 않는다. 갈리는 것은 시스템 호출과 경로 표기뿐이고, 대응은 아래와 ADR-0035 결정 26이 정한다.
    - macOS. 결정 6-4의 `fcntl(F_GETPATH)`를 쓴다. 기본 볼륨이 대소문자를 구분하지 않으므로 보호 집합 대조는 macOS와 Windows에서 성분 단위 대소문자 무시로 한다(더 많이 거부하는 방향이다). `paths` 매칭은 두 쪽이 같은 정규화 함수의 결과(디스크에 있는 표기)이므로 같은 비교를 한다. Linux는 대소문자를 구분한다.
    - Windows host. 원격 경로 문자열은 `/`와 `\`를 같게 보고, 드라이브 절대 경로와 프로필 디렉터리(`USERPROFILE`에 해당하는 값. `HOME`을 쓰지 않는 규칙과 같이 환경 변수가 아니라 serve 계정 정보에서 구한다) 기준 상대 경로를 받는다. `~`와 `host:`는 그 프로필 디렉터리다. 드라이브 없이 `/`로 시작하는 경로, UNC, `\\?\`·`\\.\` 이름 공간은 모양 검사에서 `INVALID_ARGUMENT`다. 정규 경로는 `GetFinalPathNameByHandleW`의 결과이고, 열린 핸들 재검증·재분석 지점(symlink, junction) 거부·(볼륨 일련번호, 파일 인덱스) inode 대조·`FlushFileBuffers`·`GetDiskFreeSpaceExW`가 결정 6, 7, 13의 해당 호출에 대응한다. `--no-clobber`의 `linkat`은 덮어쓰기 없는 rename이 대응하고 대상이 이미 있으면 실패하므로 같은 경쟁 보장을 준다. mode의 합성과 수정 시각 설정은 ADR-0035 결정 26을 따른다.
    - Windows host의 `paths`. 항목은 드라이브 절대 경로를 `C:/Users/dave/share`처럼 `/` 구분자만 써서 적는다. 결정 4-3의 어휘 검사는 "`/`로 시작" 대신 "드라이브 문자와 `:/`로 시작"을 요구하고 나머지 규칙(`.`·`..`·빈 성분 없음, NUL 없음, 4096바이트, 끝 `/` 금지, 드라이브 루트 `C:/` 예외)은 같다. `\`가 든 항목, 드라이브 없는 항목, `"/"`는 파일 전체의 `CONFIG_ERROR`다. 적힌 문자열이 곧 매칭에 쓰이는 문자열이라는 성질은 유지된다. 비교는 성분 단위 대소문자 무시다. 모든 드라이브를 덮고 싶으면 드라이브 루트를 각각 적는다. 이것은 표기 차이이고 권한의 모양은 같다. Windows가 아닌 host에서는 드라이브 형식 항목이 `CONFIG_ERROR`다. `acl.toml`은 host마다 따로 있으므로 한 파일이 두 OS를 오가는 일이 없다.
    - 상태 경로 집합(결정 5)은 OS마다 `docs/design/architecture.md` §7의 해석 규칙이 정한 config·state·runtime 디렉터리다. Windows의 localctl은 named pipe(ADR-0035)라서 파일시스템의 runtime 디렉터리가 없을 수 있다. 있으면 같은 규칙으로 덮고, 없으면 그 항목은 비어 있다. 그 밖의 의미는 같다.
    - client 쪽(`qsh cp`)은 세 OS에서 같은 인자 문법과 출력을 낸다. Windows client의 드라이브 문자 operand 해석은 결정 2가 이미 적었다. 로컬 쪽 쓰기는 결정 7의 `*at` 규칙에 대응하는 수단(디렉터리 핸들 기준 상대 열기, 재분석 지점 거부)으로 한다.
    - 핀 테스트는 세 OS 각각에서 결정 5·6·7의 같은 성질 행을 돈다. Windows 전용 행은 대소문자 무시 보호 집합, `\`/`/` 동치, 드라이브 없는 경로와 UNC 거부, junction 우회, `paths`의 드라이브 표기다. macOS 전용 행은 대소문자만 다른 표기의 상태 경로 우회 거부다.

## 근거

scp 인자 문법을 고르는 이유. 사용자가 원한 것은 새 파일 복사 어휘가 아니라 쓰던 `scp`를 그대로 치는 것이다. 2026-10-11 초안은 `host:path` 한 인자에서 얽히는 로컬 콜론, IPv6, 방향 추론을 이유로 scp식 단일 명령을 기각했다. 그 어려움은 scp의 규칙(첫 `/`보다 앞의 `:`가 원격 표지, IPv6는 대괄호)을 그대로 쓰면 풀리고, 방향은 operand 구성에서 정해진다. JSON 계약의 `command`가 방향을 정해야 한다는 걱정은 합성 operation `file.copy`와 `direction` 필드로 풀린다. 그래서 `qsh file get`/`put`은 별칭으로도 남기지 않는다. 출시된 적이 없어서 호환 부담이 없고, 표면이 둘이면 문서와 테스트가 두 배가 된다.

scp 플래그를 무시하지 않고 거부하는 이유. `-P`, `-J`, `-l`, `-i`를 조용히 무시하면 사용자는 포트를 지정했고, jump를 거쳤고, 대역을 제한했다고 믿은 채 다른 동작을 겪는다. 네 가지(`-r`, `-p`, `-q`, `-v`)만 뜻이 같게 받고 나머지는 시작 전에 exit `2`로 끝내는 쪽이 fail closed에 맞다.

디렉터리 순회를 client가 하고 wire에는 두 op만 더하는 이유. 트리를 한 스트림에 싣는 방식(tar류)은 host가 추출기를 갖거나 client가 풀어야 하고, 파일별 원자성(temp와 교체)과 파일별 해시·ACL 판정·audit 줄이 한 덩어리 스트림 안에서 사라지거나 다시 만들어져야 한다. 아카이브 파서는 새 신뢰 불가 입력 표면이기도 하다. 파일 단위 요청 위에 목록과 mkdir만 얹으면 기존 인가 파이프라인(모양 검사, ACL, 상태 경로, 열린 핸들 재검증)을 요청마다 그대로 타고, 부분 실패를 항목 단위로 말할 수 있다. 대가는 작은 파일이 많을 때 파일당 control 왕복이 드는 것이고, 결정 12의 병렬 둘이 그 일부를 가린다. 그 성능은 구현 커밋의 측정 테스트가 확인한다. 모자라면 client 상수 `FILE_COPY_PARALLEL`을 per-principal quota(기본 4) 안에서 올리는 것이 정해진 대체 경로이고 wire나 계약은 바뀌지 않는다. 트리를 한 스트림에 싣는 방식으로 돌아가지 않는다.

새 action 없이 `file.read`/`file.write`로 목록과 mkdir을 인가하는 이유. 목록은 읽기이고 mkdir은 쓰기다. 새 action을 더하면 PRD §9 어휘와 ADR-0045의 role 표가 함께 바뀌고, 이미 `file.*`로 받은 권한이 의미 없이 갈라진다.

쓰기 op이 디렉터리 판별을 host 쪽에서 하는 이유. `scp f host:dir`에서 `dir`이 디렉터리인지 알려면 목록이나 stat이 필요한데, 그것을 `file.list`로 하면 쓰기 전용 principal(드롭 상자 용도로 `file.write`와 `paths`만 가진 행)이 `qsh cp`를 쓸 수 없다. `name_if_dir`는 ACL이 이미 허용한 경로 하나에 대해 host가 판별만 하게 하고, 그 판별은 결정 6-4가 이미 여는 디렉터리 fd를 그대로 쓴다.

덮어쓰기를 기본으로 두는 이유. scp 사용자의 기대이고, 교체가 temp 파일과 `renameat`이라서 실패해도 기존 파일이 그대로 남는다. 초안이 `--force`를 요구한 것은 "실수로 덮는 일"을 막기 위해서였으나, 이제 같은 `qsh cp`를 `full` role이 이미 `exec.run`으로 같은 일을 할 수 있는 장비에 쓴다. 덮는 일에 마찰을 더해도 막을 수 있는 해가 없다. 막고 싶은 사용자에게는 `--no-clobber`가 있다.

트리 안의 symlink를 건너뛰는 이유. 따라가면 순환과 `paths` 밖으로의 우회가 열린다. 복사하려면 symlink를 만드는 wire 의미가 새로 필요하다. 가장 좁은 선택은 만들지도 따르지도 않고 보고하는 것이다. 보고를 exit code에 묶지 않는 것은 정책에 따른 정상 결과이기 때문이다.

`full` role에서 경로 제한을 두지 않는 이유. ADR-0045의 근거 그대로 `full`은 이미 `exec.run`을 주므로 경로 제한은 `exec` 위에서 경계가 되지 못한다. 사용자가 원한 것은 파일 단위로 권한을 관리하지 않는 것이다. 경로를 좁히고 싶으면 role `none`에 `paths`가 있는 행을 얹는다.

`paths` 없는 파일 행을 계속 무권한으로 두는 이유. 이 ADR 전에는 파일 action이 항상 거부됐으므로 `allow = ["session.*", "file.*"]` 같은 행은 오류 없이 로드되는 정상 파일이었다. 이 행을 "paths 없음 = 제한 없음"으로 읽으면 업그레이드가 운영자 모르게 serve 계정의 전 범위 파일 접근을 연다. 이 ADR이 새로 여는 파일 접근은 운영자가 `full`을 명시했거나 `paths`를 적은 경우뿐이어야 "기존 설정은 영향받지 않는다"가 문자 그대로 성립한다. 이 규칙을 `CONFIG_ERROR`로 바꾸면 업그레이드만으로 그 host의 모든 peer, 모든 action이 거부된다. 그래서 로드 성공, 무권한, 경고와 doctor로 드러내는 모양이 가장 좁은 선택이다. 한편 role은 `trust set-role <name> full`이라는 명시적 행위로만 생기므로 같은 우려가 없다.

파일 action이 아닌 행의 `paths`를 오류로 두는 이유. 로더가 모르는 키를 무시하는 것은 버전 사이의 전방 호환을 위해서다(`docs/CLI.md` §2.3). `paths`는 이 버전이 아는 키이고, 아는 키의 잘못된 값은 지금도 파일 전체의 `CONFIG_ERROR`다. `allow = ["exec.run"], paths = ["/srv"]`는 운영자에게 "exec가 `/srv`에 갇혔다"고 믿게 하지만 실제로는 아무 제한이 없다. 제한을 적었는데 제한이 없는 상태는 fail-open이므로 로드를 거부한다. 행을 나누는 비용은 한 줄이다.

상태 경로를 ACL 밖의 고정 규칙으로 두는 이유. 이 성질은 운영자가 실수로라도 열 수 없어야 한다. `full` role이나 `paths = ["/"]`는 흔하게 쓸 설정이고, 그것이 ACL·trust·audit 쓰기 권한으로 번지면 ADR-0017과 ADR-0025가 지킨 "원격 peer는 ACL writer가 아니다"와 ADR-0045의 "role은 `trust set-role`로만 바뀐다"가 무너진다. `forward.socks`를 와일드카드보다 먼저 막는 upfront gate와 같은 이유로, 이 판정도 규칙 매칭 안에 섞지 않고 규칙 판정 뒤의 별도 단계로 둔다.

정규 경로와 열린 핸들 재검증을 함께 쓰는 이유. 문자열 비교만으로는 symlink, `..`, 대소문자 무시 파일시스템, 경로 성분 교체 경쟁을 막지 못한다. `realpath`는 판정 시점의 답만 주므로 열린 fd의 실제 경로로 다시 대조하고, 그 뒤의 모든 조작을 디렉터리 fd 기준(`*at`)으로 해서 판정한 디렉터리와 쓰는 디렉터리를 같게 만든다. hard link는 경로로 구별되지 않으므로 읽기 쪽만 inode로 막는다. 쓰기 쪽은 항목 교체만 하므로 hard link가 무력하다.

존재하지 않는 경로도 거부하는 이유. 상태 디렉터리 아래에서 "없음"과 "거부"가 다르면, 권한 있는 principal이 그 안에 어떤 파일이 있는지 알아낼 수 있다. 보호 디렉터리 아래는 존재 여부와 무관하게 거부로 통일한다.

파일 권한 없는 principal에게 정규화를 돌리지 않는 이유. 정규화는 `lstat`/`realpath`로 host 파일시스템을 조회한다. 응답은 균일해도 조회 시간은 경로의 존재와 깊이에 따라 다르므로, 파일 권한이 없는 principal이 임의 경로를 보내 시간 차로 디렉터리 구조를 더듬을 수 있다. 결정 4-6의 (a)가 순수 판정으로 그 경로를 끊는다. role이 파일 action을 주는 principal은 어차피 그 파일시스템을 읽을 수 있어서 이 우려가 없다.

재개를 넣지 않는 이유. QUIC connection migration이 IP 변경과 짧은 단절을 이미 흡수하고, 재개를 넣으면 host가 connection 수명을 넘어 temp 파일과 상태를 쥐어야 한다. ADR-0018이 터널에서 고른 "connection에 결합" 원칙과 어긋난다. 트리에서는 덮어쓰기가 기본이라 재실행이 멱등이므로 사용자 경험의 손해도 작다.

역방향 route를 넣는 이유. 역방향 모드를 쓰는 사람은 NAT 뒤의 노트북처럼 forward dial이 안 되는 상대를 다루는 사람이고, 파일 복사가 가장 필요한 곳이 거기다. `exec`과 `session`이 이미 같은 conduit으로 역방향에서 돌고 `FILE_DATA`는 새 local 메시지 없이 `LOCAL_STREAM`을 탄다. 추가 비용은 데몬 중계의 정체 장부 범위와 테스트 행 정도다.

audit에 경로를 싣는 이유. `exec.run`이 argv를 싣지 않는 것은 argv가 명령 내용, 곧 payload이기 때문이다. 파일 경로는 `forward.local`의 `host:port`처럼 "무엇에 대한 판정이었나"를 말하는 구조 정보다. 경로가 없으면 "누가 무엇을 썼나"라는 SC6 질문에 답할 수 없다. 크기와 해시는 판정 시점에 없는 값이고, 싣자면 새 필드와 전송 완료 시점의 두 번째 기록이 필요해 audit가 판정 기록에서 전송 기록으로 바뀐다.

## 대안과 기각 사유

- `qsh file get`/`qsh file put`을 유지하거나 `qsh cp`의 별칭으로 둔다: 기각. 출시된 적이 없어 호환 부담이 없고, 표면이 둘이면 문서·man·fixture·테스트가 두 벌이 된다.
- scp/sftp 프로토콜 호환(ssh 서브시스템 또는 `sshd`와 대화): 기각. qsh의 인증·ACL·audit·상태 경로 거부를 모두 우회하는 두 번째 경로가 된다. 인자 문법만 같다.
- 서버가 트리를 아카이브 스트림 하나로 보낸다(tar류): 기각. 근거 절. 파일별 원자성·해시·인가·audit를 잃고 아카이브 파서가 새 공격면이 된다.
- 트리 순회를 host가 하는 op 하나(`file.walk`)로 한다: 기각. host가 걸으면서 인가해야 하므로 요청 하나 안에서 판정이 여러 번 일어나 "요청 하나 = audit 한 줄"이 깨지고, 중간 실패 처분을 응답 하나에 담아야 한다.
- `file.list`/`file.mkdir`에 새 action(`file.list`, `file.mkdir`)을 더한다: 기각. PRD §9 어휘와 ADR-0045 role 표가 함께 바뀌고 `file.*` 의미가 갈라진다.
- 별도 `file.stat` op: 기각. `file.list`가 경로 하나의 메타데이터를 이미 돌려준다. 종류를 알려면 목록과 같은 권한(`file.read`)이 필요하다는 점이 같아서 op을 하나 더 둘 이유가 없다.
- 트리 안의 symlink를 따라가거나 symlink로 복사한다: 기각. 근거 절.
- 원격↔원격 복사를 local relay로 지원한다(`scp -3`): 기각. 두 host의 권한 판정과 데이터 경로를 한 명령이 엮게 되어 실패 처분이 복잡해진다. get 뒤 put으로 같은 일을 할 수 있다.
- 덮어쓰기를 기본 금지로 두고 `--force`를 요구한다(2026-10-11 초안): 기각. 근거 절.
- 알 수 없는 scp 플래그를 무시한다: 기각. 근거 절.
- 무시해도 해가 없는 플래그(`-C`)만 받는다: 채택하지 않는다. 받는 플래그와 거부하는 플래그의 경계를 "뜻이 같은가"로 단순하게 유지한다. QUIC에는 압축 계층이 없으므로 `-C`는 뜻이 같지 않다.
- `paths` 없는 파일 행을 제한 없음으로 해석한다(role `full`과 일관되게): 기각. 근거 절. 업그레이드가 파일 접근을 몰래 연다.
- role `full`에도 `paths`를 건다: 기각. ADR-0045 결정 5. `exec.run`을 가진 role에 경로 경계는 의미가 없다.
- 상태 경로 판정을 문자열 접두 비교로만 한다: 기각. symlink와 `..`, 성분 교체 경쟁, hard link를 모두 놓친다. M15 DoD가 symlink와 `..` 두 우회를 명시한다.
- 상태 경로 목록을 설정으로 늘리거나 줄이게 한다: 기각. 줄이는 쪽은 결정 5의 성질("role과 ACL 행으로 열 수 없다")을 설정으로 여는 셈이다. 늘리는 쪽은 운영자가 `paths`를 좁혀 이미 할 수 있다.
- 파일 경로 제한 없이 행으로 연다(2026-10-11 초안의 첫 결정 4): 기각(2026-10-11 사용자 결정). 행으로 여는 파일 action은 `paths`가 있어야 한다. role `full`이 경로 제한 없이 여는 것은 사용자가 role을 명시했기 때문이다.
- `paths`에 glob(`*`, `**`)을 허용한다: 채택하지 않는다. 성분 단위 접두가 "이 디렉터리 아래"라는 필요를 이미 채운다. glob은 정규 경로에 맞춰야 하는데 `*`가 symlink를 해석한 뒤의 이름에 걸리는지 앞의 이름에 걸리는지가 운영자 직관과 어긋나기 쉽다. action 패턴이 중간 glob을 금지한 것(`docs/design/architecture.md` §6)과 같은 이유다.
- `paths`를 문자열 접두로 비교하거나 로드 시점에 한 번만 정규화한다: 기각. `/srv/share`가 `/srv/shared`를 덮고, 기동 뒤에 바뀐 symlink를 따라가지 못한다.
- `paths` 없는 파일 행을 `CONFIG_ERROR`로 둔다, 파일 action이 아닌 행의 `paths`를 무시하거나 경고만 한다: 기각. 근거 절.
- 거부 목록(`deny_paths`)으로 비밀 경로만 뺀다: 기각. 비밀이 있는 경로를 운영자가 빠짐없이 열거해야 하고, 빠뜨린 경로는 열린다. default-deny인 ACL과 방향이 반대다.
- `acl check`가 `--resource`를 경로로 해석한다: 채택하지 않는다. `--resource`는 정규화 없는 자유 문자열이고 다른 action에서 그 의미로 쓰인다.
- 터널처럼 header 뒤 raw bytes로 흘린다: 기각. 끝 표지와 해시, `file.write`의 결과를 실을 자리가 없다.
- SHA-256으로 해시한다: 채택하지 않는다. BLAKE3는 이미 의존성이고 더 빠르다. 외부 대조가 필요하면 envelope의 BLAKE3를 `b3sum`으로 대조하면 된다.
- 재개 가능한 전송(오프셋 재개, 부분 파일 보존): 기각. 근거 절. additive 경로는 열려 있다.
- 임시 파일 없이 대상에 직접 쓴다: 기각. 실패한 전송이 대상을 반쯤 쓴 채로 남긴다.
- 트리 전체를 원자적으로 교체한다(임시 디렉터리에 받고 한 번에 rename): 기각. 이미 있는 대상 트리에 합쳐 넣는 scp 의미와 맞지 않고, 큰 트리에서 디스크를 두 배로 쓴다.
- 역방향 route는 뒤로 미룬다: 기각. 근거 절. 2026-10-13 사용자 결정이 "qsh는 모든 경우에서 정방향과 역방향에 같은 기능을 준다"를 제품 원칙으로 확인했다(PRD §4). 결정 16은 M15 범위에서 빠질 수 없다.
- 파일 op을 `exec.run`으로 인가한다(`cat`/`tee`와 같은 힘이므로): 기각. PRD §9가 `file.read`/`file.write`를 따로 둔 이유가 exec보다 좁은 권한을 주기 위해서다. 그 좁은 권한을 행으로 줄 수 있어야 한다.

## 결과

- 계약 문서. `docs/CLI.md` §2.4·§2.5에 행이 늘고, §2.5 끝의 "향후 예약: streaming file copy" 문장이 빠지며, 새 절(`qsh cp`)이 결정 2·3·17·18·20·21·22를 담는다. §6.12에 quota 키 둘이 는다. `docs/design/protocol.md`는 §4(`file.v1`), §7(`FILE_DATA` 행과 ticket 규칙), §9(`.proto` 발췌), §12(정체 장부 범위), freeze 발효 전이면 §16.1 표가 같은 커밋에서 바뀐다. `docs/design/architecture.md` §7 아래에 "이 트리는 원격 파일 op에서 항상 거부된다"는 한 문장과 결정 5의 집합이 오른다. `paths` 쪽은 `docs/PRD.md` §9의 `acl.toml` 예시와 문법에 optional 키 `paths`(결정 4-3~4-5)를 더하고, `docs/design/architecture.md` §6의 문법 줄(`[[acl]] principal · auth_path? · allow · scope?`)이 `paths?`를 얻으며 평가 순서에 ③-1과 "파일 action은 항상 deny" 문장의 삭제가 반영된다. `docs/CLI.md` §6.15에 `--path`와 두 optional 필드, §6.17에 `acl_file_paths_missing` 행, §6.19에 `matching_rules[].paths`와 파일 action의 `effective_actions` 정의가 오른다(결정 19). `qsh cp` 절은 결정 4-8의 범위 문장을 담는다.
- ACL 테스트 갱신. `Action::is_always_denied`가 `forward.socks`만 남긴다(`acl/mod.rs`의 `is_always_denied_is_exactly_the_undrivable_trio`가 이 집합을 고정하므로 같이 바꾼다). `DENY_SEAMS`에 `file.read`, `file.write`, `file.list`, `file.mkdir` 네 행이 오르고(`registry.rs`의 `deny_seams_row_names_and_count_are_pinned`가 고정한 행 수 14 → 18), `ALWAYS_DENIED_NO_OP`에서 두 action이 빠져 `forward.socks`만 남으며(`deny_seams_cover_every_action_except_the_always_denied_trio`), `qsh-testkit/tests/acl_uniformity.rs`가 네 seam의 문면 균일성을, `qsh-cli/tests/acl_check_equivalence.rs`가 두 action 행을 단언한다. `acl_docs.rs`의 PRD §9 action 대조는 바뀌지 않는다. PRD §9에 더하는 `paths` 문장과 예시가 action 모양(`word.word`)의 inline code를 새로 담지 않으면 된다.
- `paths` 테스트 갱신.
  - `acl_check_equivalence.rs`: `paths`가 있는 행·없는 행·섞인 정책에서 `acl check --path`와 enforcement(`Server::dispatch`)와 `acl show`의 판정이 같음을 단언하는 행들. `paths` 안, 경계 밖 형제(`/srv/share` 대 `/srv/shared`), `paths` 안 symlink가 밖을 가리키는 경우, `..` 이탈, 파일 action에 `--path`가 없는 `INVALID_ARGUMENT`, 비파일 action에 `--path`가 있는 `INVALID_ARGUMENT`를 덮는다. role `full`인 principal에는 경로와 무관하게 allow인 행을 둔다.
  - `acl_uniformity.rs`: `paths` 밖 거부, `paths` 없는 행의 거부, 정규화 실패 거부가 행 없는 거부와 상태 경로 거부와 같은 `PERMISSION_DENIED_MESSAGE`를 냄을 네 seam 모두에서 단언한다.
  - `acl/load/tests.rs`: `paths` 모양 위반(상대 경로, `.`·`..`·빈 성분, 끝 `/`, 빈 배열, 64개 초과, 4096바이트 초과)과 비파일·섞인 행의 `paths`가 모두 파일 전체의 `CONFIG_ERROR`이고 문면에 경로 문자열이 없음. `paths` 없는 파일 행이 로드되고 경고 한 줄을 냄.
  - `acl/policy/tests.rs`: 성분 단위 매칭, 같음 매칭, `"/"` 항목, first-match가 `paths` 불일치 행을 건너뜀, 경로 없는 파일 요청의 행 deny.
  - doctor: `doctor_acl_findings_reports_acl_file_paths_missing_for_a_file_row_without_paths`, 정책이 없을 때 침묵, `detail`에 principal 문자열이 없음, role `full` pin의 행에서 침묵(`acl_file_paths_missing_is_silent_for_a_role_full_pin`). `doctor_docs.rs`의 잠금 어휘 대조.
- 핀 테스트(이름은 구현 때 확정하되 성질은 이대로).
  - 권한과 상태 경로
    - `file_ops_are_denied_without_a_matching_rule_or_role`
    - `role_full_file_ops_allow_any_path_but_still_deny_state_paths`: ADR-0045의 `role_full_file_ops_still_deny_state_paths`와 같은 사실을 이 ADR 쪽에서 `acl.toml`, `trust.toml`, `invites.toml`, `identity/device.key`(또는 `device.pem`), `audit.log` 다섯과 그 경로를 가리키는 symlink, `..` 이탈 경로에 대해 읽기·쓰기·목록·mkdir 네 op으로 단언한다. `PERMISSION_DENIED`이고 파일 바이트가 그대로다
    - `file_write_to_state_paths_is_denied_even_with_root_paths`(`allow = ["file.*"], paths = ["/"]`), `file_read_of_state_paths_is_denied_even_with_root_paths`(hard link 우회까지)
    - `file_list_and_mkdir_in_state_dirs_are_denied`
    - `state_path_guard_denies_nonexistent_paths_under_state_dirs`, `state_path_guard_covers_env_overridden_and_default_dirs`, `state_path_guard_rechecks_the_opened_handle`: 판정과 열기 사이에 디렉터리 성분을 symlink로 바꾸는 경쟁을 재현한다
    - `file_rule_without_paths_grants_no_file_access`: `allow = ["file.*"]`만 있는 행으로 네 op이 `PERMISSION_DENIED`이고 같은 행의 다른 action은 동작한다
    - `file_paths_match_component_wise`, `file_read_through_a_symlink_out_of_paths_is_denied`, `file_dotdot_escape_out_of_paths_is_denied`, `file_paths_recheck_the_opened_handle`
    - `file_request_without_a_file_grant_touches_no_filesystem`: 파일 grant가 없는 principal의 요청이 정규화 함수를 한 번도 부르지 않는다(정규화 함수 주입으로 센다)
  - 전송과 원자성
    - `denied_file_write_leaves_no_file_or_temp_behind`, `unredeemed_file_write_ticket_leaves_nothing_behind`
    - `file_write_overwrites_atomically_by_default`, `file_write_no_clobber_never_replaces_an_existing_file`
    - `interrupted_file_write_removes_its_temp_file`(connection 유실, 취소, 정체 장부 끊음 세 경우)
    - `file_write_size_or_hash_mismatch_renames_nothing`
    - `file_round_trip_is_byte_identical_forward`, `file_round_trip_is_byte_identical_reverse`: 64 MiB 이상의 무작위 파일
    - `file_audit_record_carries_path_but_no_payload`: `record_has_only_structural_fields`와 같은 형식으로 키 집합이 아홉에 optional `role`뿐이고 `resource`가 요청 경로임을 단언한다
    - `quota_registry.rs`의 두 행, `quota_docs.rs`의 키·기본값 대조
    - `file_copy_echo_under_load`: `tunnel_echo_under_load`와 같은 예산으로 파일 전송 중 PTY echo p95를 잰다(M13 (b) 하네스)
  - `qsh cp`와 트리
    - `cp_operand_grammar_separates_remote_from_local`: `./a:b`, `[::1]:p`, `host:`, `host:dir/x`
    - `cp_rejects_unsupported_scp_flags_with_exit_2`, `cp_remote_to_remote_is_invalid_argument`, `cp_mixed_operands_are_invalid_argument`
    - `cp_into_existing_directory_uses_the_source_name_get_and_put`, `cp_multiple_sources_require_an_existing_directory`, `cp_dot_source_copies_contents`
    - `cp_home_relative_paths_expand_against_the_serve_account`, `cp_tilde_user_is_invalid_argument`, `cp_user_hint_mismatch_is_unsupported_after_acl`
    - `cp_recursive_round_trip_tree_is_identical_forward`, `cp_recursive_round_trip_tree_is_identical_reverse`
    - `cp_recursive_skips_symlinks_inside_trees_and_follows_an_operand_symlink`
    - `cp_special_files_fail_their_entry_and_the_walk_continues`
    - `cp_partial_failure_exits_255_and_reports_failures`, `cp_connection_loss_stops_the_walk_and_reports_not_attempted`
    - `cp_rejects_hostile_entry_names`: `..`, `a/b`, 빈 이름, NUL을 돌려주는 가짜 host에 대해 로컬에 아무것도 만들지 않는다
    - `cp_preserve_sets_mode_and_mtime`, `cp_without_preserve_applies_the_umask`, `cp_directories_are_owner_writable_while_filling`
    - `file_list_pages_are_sorted_and_resumable_by_cursor`, `file_list_rejects_directories_over_the_entry_cap`
    - `cp_json_and_jsonl_report_every_entry`, `cp_json_truncates_entries_but_not_totals`
    - `cp_many_small_files_stays_within_the_echo_budget`: 파일 수천 개 트리 전송 중 PTY echo p95와 audit writer 처리량을 같은 하네스로 잰다
- 등록 완전성과 fixture. `file.copy`는 schemars 타입, `cli_v1_data_schema` arm, `CLI_V1_SCHEMA_COMMANDS` 등록, 렌더러 둘을 갖추고 `layer_2_every_schema_command_has_all_six_faces`가 덮는다. 새 fixture는 `file.copy.get.json`, `file.copy.put.json`, `file.copy.tree.json`, `error.file.copy.partial.json`과 event 줄 `file.entry` 예시이고 모두 `REQUIRED_FIXTURES`에 등재한다(기존 fixture는 건드리지 않는다). `paths`가 보이는 `acl.show` fixture와 `--path`를 준 `acl.check` fixture도 새로 추가한다. `capabilities.json` golden을 `QSH_UPDATE_FIXTURES=1`로 다시 만들어 `file.v1`이 들어간다. `cargo xtask man`으로 `qsh-cp` man 페이지가 늘고 `qsh-acl-check`가 `--path`를 얻는다.
- fuzz. 새 control message 넷은 `decode_control`이, `FILE_DATA`는 `decode_stream_header`가 이미 덮는다. 새 `Response` message 넷(`FileReadOpened`, `FileWriteOpened`, `FileListed`, `FileMkdirDone`)이 기존 타깃의 decode 경로에 걸리는지는 구현 커밋이 확인하고, 걸리지 않으면 타깃에 더한다. data 스트림 message `FileFrame`은 새 타깃 `decode_file_frame`을 받는다(타깃이 하나 늘어난다. 개수 문장은 `fuzz/README.md`와 `docs/design/protocol.md` §13에서 착륙 시점의 실제 타깃 수로 맞춘다. 다른 P1 ADR도 타깃을 더하므로 순서에 따라 값이 다르다).
- 위협 모델. `docs/design/threat-model.md` §3에 진입점 행 "`Server::dispatch`의 파일 op 넷과 `FILE_DATA` 스트림"과 "`qsh cp`가 받는 원격 항목 이름"을 더한다. §4에 다음 행을 더한다. 번호는 착지 순서에 따라 정한다.
  - `file.write`로 qsh 상태 파일(ACL·trust·audit·`invites.toml`)을 고쳐 인가나 role을 올린다 → 결정 5·6, 위 `file_write_to_state_paths_…`·`role_full_file_ops_…` 핀
  - symlink, `..`, 성분 교체 경쟁, hard link로 상태 경로 판정을 우회한다 → 결정 6, `state_path_guard_…` 핀
  - 덮어쓰기가 기존 파일을 반쯤 쓴 채로 두거나, 실패한 쓰기가 temp를 남긴다 → 결정 7, 덮어쓰기·중단 핀
  - symlink, `..`, 성분 교체 경쟁, 성분 문자열 접두로 `paths` 밖에 닿는다 → 결정 4·6, `file_paths_…` 핀
  - 파일 권한 없는 principal이 정규화 조회의 시간 차로 host 디렉터리 구조를 더듬는다 → 결정 4-6 (a), `file_request_without_a_file_grant_touches_no_filesystem`
  - 악의적인 host가 `..`나 `/`가 든 항목 이름으로 client의 로컬 경로를 벗어난다 → 결정 22, `cp_rejects_hostile_entry_names`
  - 원격 쓰기로 디스크를 채워 fail-closed audit가 host 전체를 멈춘다 → 결정 13, 결정 12
  - 정체한 `FILE_DATA`가 연결 수신 창을 묶는다 → 결정 15
  - `file.read`로 identity 키, resume token, reset key를 읽는다 → 결정 5, `file_read_of_state_paths_…` 핀
  - `file.read`로 serve uid의 qsh 밖 비밀(`~/.ssh` 개인키, 클라우드 자격 증명)을 읽는다 → 행으로는 결정 4(`paths` 없는 행은 무권한), role로는 `full`을 명시한 장비에 한정(ADR-0045), `file_rule_without_paths_grants_no_file_access`
  - 잘리거나 손상된 전송이 성공으로 보이고, 트리 일부 실패가 성공으로 보인다 → 결정 10, 결정 21, `cp_partial_failure_exits_255_and_reports_failures`
  - 큰 디렉터리에 대한 `file.list` 반복으로 host가 CPU를 쓴다 → 결정 9의 `FILE_LIST_DIR_MAX`, 단 호출자는 이미 `file.read`를 가진 principal이다
  - §7 잔여 위험에 다섯을 적는다. `full`은 serve 계정의 전 범위이고 `file.write`는 `exec.run`과 같은 힘이다(결정 4-8). 행 `paths`가 실행되는 파일(`~/.bashrc`, `authorized_keys`, 서비스 유닛 디렉터리)을 덮으면 같은 힘이다. `paths` 안에 누군가 밖의 inode로 hard link를 만들어 두면 경로 판정만으로는 그 읽기를 막지 못한다(만들려면 그 디렉터리에 로컬 쓰기 권한이 필요하다). bind mount는 정규 경로가 마운트 지점 쪽으로 해석되므로 `paths` 안에 마운트된 밖의 트리는 `paths` 안으로 보인다. 다른 프로세스와 같은 파일시스템을 쓰면 여유 공간 상수가 audit 디스크를 보장하지 않는다. 보호 디렉터리 안의 열거되지 않은 파일을 밖에서 hard link한 경우의 읽기는 디렉터리 판정만으로 막지 못한다. 교체로 쓰기 때문에 기존 대상 파일의 소유자·hard link·xattr가 바뀐다.
- wire. 추가는 모두 §16.4의 additive 경로다. 새 oneof 번호(`ControlMessage` 80~83, `Response` 11~14), 새 `StreamKind` 값 5, 새 message 12종과 enum 하나, 새 capability `file.v1`, 새 상수 `FILE_CHUNK_MAX`·`FILE_LIST_PAGE_MAX`·`FILE_LIST_DIR_MAX`다. 기존 번호의 재사용이나 의미 변경은 없고 `file.v1`을 광고하지 않는 peer에게는 아무것도 보내지 않는다. `qsh.local.v1`은 바뀌지 않는다. client 쪽 상수 `FILE_COPY_PARALLEL`, `COPY_JSON_ENTRIES_MAX`, `COPY_JSON_FAILURES_MAX`는 wire 계약이 아니다.
- architecture rule. guard, 전송 상태 기계, 트리 순회, quota, 정규화는 모두 `qsh-core`에 둔다(`Ops::file_copy`). `qsh-cli`는 clap 정의와 두 렌더러, 진행 표시만 갖는다. 새 모듈이 `xtask arch`의 경로 범위 금지 목록에 들어가야 하는지는 구현 커밋이 판단하고, 들어가면 `xtask/src/arch.rs`를 같은 커밋에서 고친다.
- 크기. 4.3~6.3ew. ADR 0.3 + op 넷과 wire, 전송 상태 기계, 렌더러와 진행 표시 1.4~2.0 + 경로 판정(home 해석, 정규화, 핸들 재검증, inode, 디렉터리 해석, 두 OS) 0.5~0.7 + 트리 순회 client(양방향 순회, 이름 검증, 병렬 둘, 부분 실패 집계, JSONL) 0.7~1.0 + 역방향 route와 데몬 중계의 정체 장부 0.3~0.5 + ACL·quota·audit 테스트 갱신 0.3~0.5 + fixture·capabilities·man·fuzz 타깃 0.2~0.3 + `paths`(로더 문법과 오류, 평가기 ③-1과 `ResourceRef` 필드, ACL 단계의 후보 판정, 재검증의 재평가, `acl check --path`, `acl show` 필드, doctor code, 위의 `paths` 테스트·fixture, PRD §9·architecture §6·CLI.md 세 절의 문서) 0.5~0.8 + 마감 0.1~0.2. 2026-10-11 초안의 3.3~5.0에서 재귀 복사(op 둘, 트리 순회, 경로 해석, 부분 실패 보고)가 1.0~1.3 늘었다. role 쪽 평가기 변경은 ADR-0045의 크기에 들어 있다. `docs/ROADMAP.md` §5.2 크기 표의 M15 행은 메인 세션이 고친다.
- 이 ADR이 승인되면 `docs/ROADMAP.md` M15의 착수 조건이 풀린다. DoD의 transport 문구와 "명시적 out"의 "디렉터리 동기화(rsync류), UDP forwarding, 원격 파일 브라우징"에서 재귀 복사는 out이 아님을 메인 세션이 고친다.
