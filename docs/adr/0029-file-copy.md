# ADR-0029: 스트리밍 파일 복사는 `qsh file get`/`qsh file put` 두 op으로 열고, qsh 자신의 상태 경로는 ACL 행과 무관하게 정규 경로 기준으로 항상 거부한다

날짜: 2026-10-11
상태: 제안됨

개정 관계: 새 ADR이다. `docs/adr/README.md`의 예약 목록이 P1 계획(`docs/ROADMAP.md` §5) 시점에 이 번호를 파일 복사(M15) 자리로 잡아 두었고, 이 문서가 그 자리를 채운다. 다른 ADR의 결정을 개정하지 않는다. 승인되면 바뀌는 계약 문서는 셋이다. `docs/PRD.md` §9의 action 목록은 그대로이고 `file.read`/`file.write`가 항상-deny에서 풀린다. `docs/CLI.md`는 §2.4에 op 둘, §2.5에 매핑 두 행, §6에 새 절 하나가 는다. `docs/design/protocol.md`는 §4 capability 목록, §7 스트림 표, §9 `.proto`, §12 정체 장부의 범위가 바뀐다. TCP/TLS fallback(M14, ADR-0028)은 오늘(2026-10-11) 사용자 결정으로 철회되어 ADR-0043이 그 결정을 적는다. 그래서 이 ADR은 QUIC transport 하나만 다루고, `docs/ROADMAP.md` M15 DoD의 "QUIC과 TCP 두 transport" 문구는 메인 세션이 고친다.

## 맥락

PRD §7은 streaming file copy를 P1에 두고, PRD §9의 action 어휘는 P0부터 `file.read`/`file.write`를 갖는다. 오늘 두 action은 `Action::is_always_denied`가 어떤 규칙보다 먼저 거부한다. 그것을 부를 wire op이 없으니 `DENY_SEAMS`에도 행이 없다(`crates/qsh-core/src/acl/registry.rs` 모듈 doc). `docs/ROADMAP.md` M15는 op을 등록하고 항상-deny를 걷되, 착수 전에 이 ADR이 다음을 정하라고 적는다. 명령 이름과 모양, 청크·부분 전송·재개 여부, 무결성 확인, ACL resource 모델(경로를 resource로 쓸지와 소유 축), 경로 제약(symlink, 상위 경로 이탈, 덮어쓰기), 동시 전송 quota, audit 레코드의 필드 집합, 역방향 route 지원 여부다.

M15가 반드시 담으라고 한 결정이 하나 더 있다. `file.write`는 `qsh serve`의 uid로 파일을 쓰고, 그 uid는 `acl.toml`, `trust.toml`, `invites.toml`, identity와 keystore, `resume.json`, audit 로그를 모두 쓸 수 있다.

- `acl.toml`에 닿으면 원격 peer가 ACL writer가 된다. ADR-0017 결정 1과 ADR-0025 결정 1이 로컬 명령에서조차 닫아 둔 자리다.
- `trust.toml`은 더 나쁘다. `SharedTrustStore::lookup_pin`이 handshake마다 파일을 다시 읽으므로(`crates/qsh-core/src/trust/mod.rs`) 원격 쓰기 하나로 재시작 없이 새 pin이 심긴다.
- audit 로그를 덮어쓰면 SC6 추적성이 지워진다.
- `file.read`는 반대 방향으로 같은 자리를 연다. identity 개인키, `resume.json`의 resume token(ADR-0007), `stateless_reset.key`(ADR-0036), `invites.toml`의 invite 상태를 원격으로 읽을 수 있게 된다.

설계를 가르는 사실은 이렇다.

- ACL 규칙(`crates/qsh-core/src/acl/policy.rs`의 `Rule`)은 `principal`, `auth_path`, `allow`, `scope` 넷뿐이다. resource는 `Authorizer::check`가 받는 자유 문자열(`ResourceRef.id`)이고 audit에 실리지만 어떤 규칙도 그것을 매칭하지 않는다. `forward.local`이 목적지를 가리지 않고 `exec.run`이 argv를 가리지 않는 것도 이 때문이다. 소유 축(`scope = "owned"`)은 `ResourceRef.owner`가 있는 자원(세션, `-R` forward)에만 걸린다.
- `exec.run`이나 `session.open`을 가진 principal은 이미 serve uid로 아무 파일이나 쓸 수 있다. 그러므로 상태 경로 거부가 지키는 것은 uid의 능력이 아니다. `file.*` 부여가 `exec.run` 부여보다 엄격히 좁다는 성질, 곧 "파일만 옮기라고 준 권한이 ACL·trust·audit를 건드리는 권한으로 번지지 않는다"는 성질을 지킨다.
- 인가가 필요한 data 스트림의 선례는 `EXEC_DATA`다. control 요청이 ACL을 통과한 뒤에만 ticket(128-bit 난수, 단회, 30초)이 발급되고 data 스트림은 `StreamHeader{EXEC_DATA, ticket}`로 시작한다(`docs/design/protocol.md` §7). 역방향 route에서는 같은 `StreamHeader`가 `LOCAL_STREAM` conduit을 그대로 탄다(§11-3 "터널 conduit").
- 우선순위 band는 이미 "tunnel/file **0**"이라고 적어 두었다(§12). 정체 터널 스트림 장부(ADR-0037)는 터널 스트림만 센다.
- quota는 ADR-0010의 모양을 따른다. 인가 뒤, 자원 생성 전에 판정하고, 살아 있는 자원 자체를 센다. 키는 `[serve]` 아래에 있다.
- audit 레코드의 키 집합은 `ts`, `request_id`, `peer_addr`, `principal`, `auth_path`, `action`, `resource`, `decision`, `rule` 아홉이다. `record_has_only_structural_fields`(`crates/qsh-core/src/audit/tests.rs`)가 이 집합을 고정한다.

## 결정

1. **범위.** 파일 하나를 통째로 옮기는 op 둘을 연다. 원격에서 읽어 오는 `file.read`와 원격에 쓰는 `file.write`다. 디렉터리 재귀 복사, 동기화, 원격 파일 목록 조회는 하지 않는다(M15 명시적 out). transport는 QUIC 하나다(ADR-0043). 새 capability 문자열 `file.v1`을 광고하고, client는 peer의 협상된 capability 집합에 `file.v1`이 없으면 요청을 보내기 전에 `UNSUPPORTED`로 끝낸다.

2. **CLI 모양.** 명령은 둘이다.

   ```bash
   qsh file get <host> <remote-path> <local-path> [--force] [--json]
   qsh file put <host> <local-path> <remote-path> [--force] [--json]
   ```

   - `get`의 envelope `command`는 `file.read`, `put`은 `file.write`다. CLI 동사와 op 이름이 다른 것은 `qsh tunnels` → `tunnel.list`와 같은 관례다.
   - `<host>`는 `qsh exec`와 같은 라우팅을 쓴다(`docs/CLI.md` §6.1 우선순위, live reverse 등록 우선).
   - `<remote-path>`는 절대 경로여야 한다(결정 6-1). `~` 확장은 하지 않는다.
   - `-`(stdin/stdout)는 받지 않고 `INVALID_ARGUMENT`다. machine 모드의 stdout은 envelope 한 줄만 싣기 때문이다(CLAUDE.md 계약 규칙, `docs/CLI.md` §2.2).
   - 대상(`get`의 `<local-path>`, `put`의 `<remote-path>`)이 이미 있는 디렉터리면 `INVALID_ARGUMENT`다. 원본 basename을 붙여 주는 scp식 해석은 하지 않는다.
   - 대상 파일이 이미 있으면 `--force` 없이는 `INVALID_ARGUMENT`이고 아무것도 바뀌지 않는다. `--force`면 원자적으로 교체한다(결정 7).
   - 진행 표시는 이 ADR의 범위 밖이다. 나중에 stderr 줄이나 `qsh.event/v1` event로 additive하게 더할 수 있다.

3. **op 이름과 ACL 매핑.** `docs/CLI.md` §2.4에 `file.read`, `file.write`를 더하고 §2.5에 `file.read` → `file.read`, `file.write` → `file.write` 두 행을 더한다. `exec.run` → `exec.run`처럼 op 이름과 action 이름이 같다. `Action::is_always_denied`는 `forward.socks` 하나만 남긴다. `allow = ["file.*"]`는 두 action을 모두 연다. 거부는 기존 `PERMISSION_DENIED_MESSAGE` 그대로이고, 두 op은 `SeamKind::ControlStreamOp` 행으로 `DENY_SEAMS`에 오른다.

4. **ACL resource 모델과 소유 축.**
   - `Authorizer::check`에 넘기는 resource는 요청에 실린 원격 경로 문자열 그대로다(정규화 전). 정규화는 파일시스템을 건드리므로 인가 뒤에만 한다(결정 8).
   - 이 ADR은 `acl.toml` 문법을 바꾸지 않는다. 규칙은 경로를 매칭하지 않으므로 `file.read`는 "serve uid가 읽을 수 있는 정규 파일 중 결정 5의 상태 경로를 뺀 전부"를, `file.write`는 같은 범위의 쓰기를 준다. `forward.local`이 목적지를 가리지 않는 것과 같은 모양이다. `docs/CLI.md`의 새 절은 이 범위를 그대로 적고, `file.write`가 `~/.bashrc` 같은 파일을 통해 사실상 `exec.run`과 같은 힘을 갖는다는 것도 적는다.
   - 경로 범위를 좁히는 규칙 키(예: `[[acl]]`의 `paths`)는 additive로 나중에 더할 수 있다. 그때는 이 ADR을 개정하는 새 ADR이 그 키의 문법과 fail-closed 규칙을 정한다.
   - 파일에는 qsh 소유자 개념이 없다. `ResourceRef::unowned`로 넘기므로 `scope = "owned"`는 파일 op을 걸러내지 않는다. 이 사실도 새 절에 적는다.

5. **상태 경로는 ACL 행과 무관하게 항상 거부한다.** host는 `file.read`/`file.write`가 결정 6의 정규 경로로 아래 집합에 닿으면 `PERMISSION_DENIED`로 거부한다. 이 판정은 `Authorizer::check`가 allow를 낸 뒤에 돌고, ACL 행이 이 판정을 끌 방법은 없다. 설정 키도 두지 않는다.
   - **보호 디렉터리**(그 아래 전부, 디렉터리 자신 포함): config 디렉터리, state 디렉터리, runtime 디렉터리(`$XDG_RUNTIME_DIR/qsh` 또는 state 아래 `run/`, localctl 소켓 디렉터리). `docs/design/architecture.md` §7의 해석 규칙을 따른다. 그래서 `config.toml`, `acl.toml`, `trust.toml`, `invites.toml`, `hosts.toml`, `identity/`, `stateless_reset.key`(ADR-0036, M13 (f)의 reset key 파일), `resume.json`, 기본 위치의 `audit.log`와 그 회전 파일이 모두 덮인다.
   - **보호 파일**: `[audit].path`가 위 디렉터리 밖을 가리키면 그 파일과 회전 파일(`<path>.1`…`<path>.<retain>`), 그리고 그 파일이 있는 디렉터리 안에서 회전이 쓰는 임시 파일 이름. file-mode keystore가 config 밖의 경로를 쓰면 그 경로도 넣는다.
   - **두 해석의 합집합**: 위 디렉터리는 이 `qsh serve` 프로세스가 실제로 쓰는 경로(`$QSH_CONFIG_DIR`, `$XDG_*` 반영)와, 환경 변수 재정의 없이 `$HOME` 기준 기본값으로 해석한 경로를 둘 다 넣는다. 같은 uid의 다른 qsh 인스턴스(예: 다른 환경으로 뜬 `qsh listen` 데몬)의 상태도 지키기 위해서다.
   - 집합은 요청마다 새로 해석한다. 기동 시점에 한 번 얼리지 않으므로, 기동 뒤에 생긴 디렉터리나 회전 파일도 덮인다.
   - 이 거부도 `PERMISSION_DENIED_MESSAGE`를 그대로 쓴다. 그래서 "ACL이 막았다"와 "상태 경로라 막았다"를 응답만으로는 가를 수 없다. audit에는 ACL allow 줄 뒤에 `decision = "deny"`, `rule = null`인 줄이 하나 더 남는다. host-local dial 필터가 `forward.local` 판정 뒤에 한 줄을 더 쓰는 것(`docs/design/protocol.md` §7)과 같은 모양이다.

6. **경로 판정 절차.** host는 다음 순서로 판정한다. 같은 규칙을 `qsh-core`의 함수 하나(가칭 `file::guard`)에 두고 두 op이 함께 쓴다.
   1. **모양 검사**(인가 전): 비어 있지 않음, `/`로 시작함, NUL 없음, UTF-8, 4096바이트 이하. `file.write`는 마지막 성분이 빈 문자열, `.`, `..`가 아니어야 한다. 위반은 `INVALID_ARGUMENT`이고, ACL 판정도 audit도 파일시스템 접근도 없다. `TCP_CONNECT`의 host 모양 검사(ADR-0019 결정 5)와 같은 자리다. `..` 성분 자체는 모양 위반이 아니다. 이탈 여부는 아래 정규화가 판정한다.
   2. **정규화**(인가 뒤): 경로에서 실제로 존재하는 가장 긴 조상을 `realpath`로 해석하고, 남은 성분을 어휘적으로 붙인다(남은 부분의 `..`는 어휘적으로 접는다). 대상이 존재하는 symlink면 끝까지 따라간 경로가 정규 경로다. 그래서 `/tmp/link → ~/.config/qsh/acl.toml`이나 `/home/x/../dave/.config/qsh/trust.toml`은 보호 경로로 판정된다. 존재하지 않는 경로도 보호 디렉터리 아래면 거부되므로, 상태 디렉터리 안에서 어떤 파일이 있는지를 오류 차이로 알아낼 수 없다.
   3. **보호 집합 대조**: 정규 경로가 보호 디렉터리 아래에 있거나 보호 파일과 같으면 거부한다(결정 5).
   4. **열린 핸들 재검증**: 판정과 열기 사이에 경로 성분이 바뀌는 경쟁을 막는다. `file.read`는 정규 경로를 `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`로 연다. `file.write`는 정규 경로의 부모 디렉터리를 `O_DIRECTORY | O_NOFOLLOW`로 연다. 연 뒤 fd가 가리키는 실제 경로(Linux는 `/proc/self/fd/<n>`의 readlink, macOS는 `fcntl(F_GETPATH)`)를 다시 3에 대조한다. 어긋나면 거부하고 fd를 닫는다. 이후의 생성·교체는 모두 이 디렉터리 fd에 대한 `openat`/`linkat`/`renameat`/`unlinkat`로만 한다.
   5. **inode 대조**(`file.read`): 연 파일의 `(dev, ino)`가 보호 파일(결정 5에 열거된 파일, 그 시점에 존재하는 것)의 `(dev, ino)`와 같으면 거부한다. 보호 디렉터리 밖에 만든 hard link로 `acl.toml`이나 `device.key`를 읽는 우회를 막는다. `file.write`는 결정 7대로 디렉터리 항목을 교체할 뿐 기존 inode에 쓰지 않으므로 hard link 우회가 성립하지 않는다.
   6. **파일 종류**: `file.read`는 `fstat`이 정규 파일일 때만 진행한다. 디렉터리, FIFO, 소켓, 장치는 `INVALID_ARGUMENT`다. `O_NONBLOCK`으로 열기 때문에 FIFO에서 열기가 멈추지 않는다. `file.write`의 대상이 이미 있고 정규 파일이 아니면 `INVALID_ARGUMENT`다.

7. **덮어쓰기와 원자성.**
   - `file.write`는 대상 디렉터리(결정 6-4의 fd) 안에 임시 파일 `.<name>.qsh-<16 hex>.part`를 `O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600`으로 만든다. 받은 바이트를 쓰고, 결정 10의 검증을 통과하면 `fsync`하고 `fchmod`로 요청 mode를 적용한 뒤 교체한다.
   - `--force`가 없으면 `linkat(temp, name)`으로 붙인 뒤 temp를 `unlinkat`한다. 대상이 그 사이에 생겼으면 `EEXIST`로 실패하므로 확인과 교체 사이의 경쟁에서도 기존 파일을 덮지 않는다. `--force`면 `renameat(temp, name)`이다. 어느 쪽이든 교체 뒤 디렉터리를 `fsync`한다.
   - mode는 원본의 권한 비트를 `& 0o777`로 잘라 쓴다. setuid, setgid, sticky는 옮기지 않는다. 소유자는 serve uid이고, 소유자·시각·xattr·ACL은 옮기지 않는다.
   - 실패, 취소, 연결 유실, 검증 실패 중 어느 경우든 temp를 `unlinkat`하고 대상은 건드리지 않는다. 결과적으로 대상은 "옛 내용 그대로" 아니면 "새 내용 전부" 둘 중 하나다.
   - client 쪽 `qsh file get`의 로컬 쓰기도 같은 temp·link/rename·fsync 규칙을 쓴다. 로컬 쪽에는 결정 5의 보호 집합을 적용하지 않는다. 로컬 사용자가 자기 머신에서 직접 고른 경로이고, 원격 peer는 로컬 경로를 정하지 못하기 때문이다.

8. **host 처리 순서.** 순서는 고정이고 앞 단계가 실패하면 뒤 단계는 돌지 않는다.
   1. 모양 검사 (6-1)
   2. `Authorizer::check` + audit
   3. 상태 경로 판정 (6-2·6-3, deny면 audit 한 줄 더)
   4. quota 예약 (결정 12)
   5. 열기와 재검증 (6-4~6-6). `file.write`는 대상 존재 여부와 `--force` 확인, 여유 공간 확인(결정 13)을 여기서 한다
   6. ticket 발급과 응답

   `file.read`는 5에서 연 파일 fd를, `file.write`는 디렉터리 fd를 ticket에 묶어 둔다. 디스크에 보이는 자원(temp 파일)은 data 스트림이 ticket을 상환한 뒤에야 만든다. ticket이 30초 안에 상환되지 않으면 fd를 닫고 quota를 돌려준다. 그래서 deny된 `file.write` 뒤에는 대상 디렉터리에 새 파일도 temp도 없고, 상환되지 않은 허용 요청도 아무것도 남기지 않는다. 오류 응답 뒤에 쥔 fd나 quota도 남지 않는다.

9. **wire.** `docs/design/protocol.md` §16.4의 additive 경로만 쓴다. 기존 번호는 건드리지 않는다.
   - `ControlMessage` oneof에 `FileReadOpen file_read_open = 80`, `FileWriteOpen file_write_open = 81`을 더한다.
   - `Response` oneof의 빈 번호에 `FileReadOpened file_read_opened = 11`, `FileWriteOpened file_write_opened = 12`를 더한다.
   - `StreamKind`에 `FILE_DATA = 5`를 더한다. `StreamHeader{FILE_DATA, ticket}`로 시작하는 bidi 스트림이고, 요청자가 연다(`EXEC_DATA`와 같다).
   - 새 message:

     ```protobuf
     message FileReadOpen    { string path = 1; }
     message FileReadOpened  { bytes ticket = 1; uint64 size = 2; uint32 mode = 3; }
     message FileWriteOpen   { string path = 1; uint64 size = 2; uint32 mode = 3; bool overwrite = 4; }
     message FileWriteOpened { bytes ticket = 1; }
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

   - `FILE_DATA` 스트림은 §5 frame layer(`u32` BE length + prost, `DATA_FRAME_MAX` 64 KiB)를 그대로 쓰고, `data` 한 조각의 상한은 새 상수 `FILE_CHUNK_MAX = 32 KiB`(`crates/qsh-proto/src/wire.rs`)다. 터널처럼 raw bytes로 바꾸지 않는다. 끝 표지(`FileEnd`)와 쓰기 결과를 스트림 안에서 실어야 하고, 32 KiB당 frame 비용은 수 바이트라 처리량에 의미가 없다. 상한을 넘는 `data`, `end` 뒤의 frame, 요청자가 보낸 `result`는 프로토콜 위반이다. 스트림을 `BAD_HEADER`(0x2001)로 reset하고 결정 7의 정리를 한다.
   - `file.read` 스트림: 요청자가 header를 보내면 host는 EOF까지 `data`를 보낸 뒤 `end`를 보내고 `finish()`한다.
   - `file.write` 스트림: 요청자가 header, `data`들, `end`를 보내고 송신 half를 `finish()`한다. host는 결정 10의 검증과 결정 7의 교체를 끝낸 뒤 `result` 하나를 보내고 `finish()`한다. 거부 teardown은 `TCP_CONNECT`와 같이 결과를 먼저 쓰고 송신 half를 reset하지 않는다(§7).
   - 이 추가로 `.proto`의 top-level `message`가 49개에서 56개로, `ControlMessage` oneof가 18 branch에서 20 branch로, `Response` oneof가 (`error`를 포함해) 10 branch에서 12 branch로 는다. §16 발효 전에 착륙하면 같은 커밋에서 §16.1 표의 해당 행을 고친다.

10. **무결성.** 보내는 쪽은 보낸 바이트 전체의 BLAKE3-256과 총 길이를 `FileEnd`에 싣는다. 받는 쪽은 받은 바이트로 같은 값을 계산하고, 둘 중 하나라도 다르면 실패로 끝낸다(`file.write`는 host가 교체하지 않고 `INVALID_ARGUMENT`, `file.read`는 client가 교체하지 않고 `REMOTE_ERROR`). `file.write`는 `FileWriteOpen.size`와 받은 총 길이도 같아야 하고, `size`를 넘는 바이트가 오면 그 자리에서 끊는다. `FileReadOpened.size`는 열 때의 `fstat` 값으로 안내용이다. 읽는 도중 원본이 바뀌면 `FileEnd`가 실제로 보낸 바이트를 말하고, 그 값이 기준이다. 원본의 일관된 스냅숏은 보장하지 않는다(scp와 같다). TLS가 이미 전송 구간을 인증하므로 이 해시는 구현 결함, 잘린 스트림, 디스크 쓰기 오류를 잡는 끝단 검사다. 성공 envelope에 hex로 실어 사용자가 원본과 대조할 수 있게 한다. BLAKE3를 고르는 이유는 이미 workspace 의존성이라서다(`Cargo.toml`).

11. **부분 전송과 재개.** 재개는 하지 않는다. 전송의 수명은 그것을 실은 QUIC connection에 묶인다(ADR-0018 결정 1과 같은 원칙). connection migration으로 살아남는 경로 변화에서는 전송이 계속되고, connection이 죽으면 전송은 `CONNECTION_FAILED`(`retryable: true`)로 끝나며 양쪽 모두 결정 7대로 temp를 지운다. 같은 명령을 다시 실행하면 처음부터 다시 보낸다. 나중에 재개가 필요해지면 `FileWriteOpen`/`FileReadOpen`에 `offset` 같은 필드를 capability 확인 뒤 additive로 더할 수 있고, 이 결정은 그 길을 막지 않는다. Ctrl-C(SIGINT)는 스트림을 reset하고 같은 정리를 한 뒤 exit `255`와 `CANCELED`로 끝난다.

12. **동시 전송 quota.** ADR-0010의 모양을 따른다. `[serve].max_file_transfers_per_principal`(기본 4)과 `[serve].max_file_transfers`(기본 64, accept arm 단위)를 둔다. 세는 단위는 진행 중인 전송 하나이고, ticket을 발급한 시점부터 스트림이 끝나거나 ticket이 만료될 때까지다. `file.read`와 `file.write`는 같은 계수를 나눠 쓴다. 판정 자리는 결정 8의 4단계로, ACL과 상태 경로 판정 뒤, 파일을 열기 전이다. 초과는 `RESOURCE_EXHAUSTED`이고 audit `resource`는 `"quota_files_principal"`, `"quota_files_host"`다. `crates/qsh-core/tests/quota_registry.rs`에 두 행을 더하고, `docs/CLI.md` §6.12의 quota 문단에 두 키와 기본값을 적어 `quota_docs.rs`가 대조하게 한다. 범위와 검증 규칙은 기존 quota 키와 같다.

13. **쓰기 여유 공간.** `file.write`는 결정 8의 5단계에서 대상 파일시스템의 `statvfs` 가용 바이트가 `size + FILE_WRITE_FREE_RESERVE`(256 MiB, 고정 상수) 미만이면 `RESOURCE_EXHAUSTED`로 거부한다. 쓰는 도중 `ENOSPC`도 `RESOURCE_EXHAUSTED`다. audit writer는 기록하지 못하면 모든 op을 거부한다(fail-closed). 그래서 원격 쓰기로 audit 로그가 있는 디스크를 채우면 host 전체가 멈춘다. 이 상수는 그 경로를 막는 최소한의 여유다. 같은 파일시스템을 다른 프로세스가 채우는 경우까지 막지는 않는다(결과 절의 잔여 위험).

14. **audit 필드 집합.** 새 필드를 더하지 않는다. 키 집합은 지금의 아홉 그대로다.
    - `action`: `file.read` 또는 `file.write`
    - `resource`: 요청에 실린 원격 경로 문자열(결정 4, 정규화 전). JSON 직렬화가 제어문자를 이스케이프한다
    - 크기, 해시, mode, 파일 내용 바이트는 어디에도 싣지 않는다. audit는 인가 판정의 기록이지 전송 기록이 아니고, 크기와 완료 여부는 판정 시점에 알 수 없다.
    - 한 요청이 남기는 줄: ACL 판정 한 줄. 상태 경로 거부면 deny 한 줄 더. quota 거부면 ADR-0010 모양의 한 줄.

15. **우선순위와 역압.**
    - `FILE_DATA` 송신은 band 0(§12의 tunnel/file)이고, 터널 splice와 같은 송신 깊이 상한 `SEND_DEPTH_CAP_BYTES`(128 KiB)를 적용한다.
    - 받는 쪽의 로컬 쓰기(디스크)는 ADR-0037의 정체 장부에 오른다. 정의(`STALL_AGE` 1초 동안 진전 없음), 끊는 규칙, reset 코드 `0x200E`가 터널 스트림과 같다. 끊긴 전송은 결정 7대로 정리되고 `RESOURCE_EXHAUSTED`로 끝난다. 장부의 범위에 `FILE_DATA`가 들어가는 것은 §12 "범위" 문장의 변경이다. 연결 양 끝과 `localctl` 데몬의 중계에 모두 적용한다.
    - 그래서 같은 연결의 PTY echo 예산은 M13 (b) 하네스가 재는 터널 부하 때와 같은 장치로 지켜진다.

16. **역방향 route를 지원한다.** `qsh file get|put`의 `<host>`가 live reverse 등록으로 해석되면 control 요청은 `LOCAL_CONTROL` conduit으로, `FILE_DATA` 스트림은 `LOCAL_STREAM` conduit으로 데몬을 거쳐 target에 간다. 새 `LocalStreamKind`는 없다. `LOCAL_STREAM` 다음 frame이 wire `StreamHeader`라는 규칙(§11-3 "터널 conduit")만으로 판별된다. 인가와 상태 경로 판정은 언제나 파일을 쥔 쪽(target의 `qsh serve --to`, forward route의 `qsh serve`)이 한다. `qsh listen` controller는 파일 op 요청을 받으면 지금처럼 `UNSUPPORTED`로 답하고 아무것도 만들지 않는다. capability는 데몬이 `LocalHelloAck.capabilities`로 relay한 target의 집합으로 확인한다. `file.v1`이 없을 때의 메시지는 `-D`의 역방향 거절 문구처럼 원인 둘(target이 오래됨, 로컬 데몬이 업그레이드 전에 뜸)을 함께 짚는다.

17. **오류 코드.** 새 `ErrorCode`는 없다.

    | 상황 | code |
    |---|---|
    | 모양 위반, `-` 경로, 원본 없음, 정규 파일 아님, 대상이 디렉터리, `--force` 없이 대상 존재, 크기·해시 불일치(`file.write`) | `INVALID_ARGUMENT` |
    | ACL deny, 상태 경로 판정, 재검증 불일치, inode 일치, OS의 `EACCES`/`EPERM` | `PERMISSION_DENIED`(균일 문면) |
    | quota, 여유 공간, `ENOSPC`, 정체 장부의 끊음 | `RESOURCE_EXHAUSTED` |
    | 크기·해시 불일치(`file.read`, client 판정) | `REMOTE_ERROR` |
    | connection 유실 | `CONNECTION_FAILED`(`retryable: true`) |
    | peer에 `file.v1` 없음 | `UNSUPPORTED` |
    | Ctrl-C | `CANCELED` |

    OS의 `EACCES`를 `PERMISSION_DENIED`로 접는 이유는 상태 경로 판정과 응답이 같아야 하기 때문이다. `ENOENT`는 결정 6-2가 보호 디렉터리 밖에서만 드러나게 한다.

18. **JSON 계약.** 성공 `data`는 두 op 모두 같은 모양이다.

    ```json
    {
      "host": "personal-mac",
      "remote_path": "/home/dave/build/app.tar.zst",
      "local_path": "./app.tar.zst",
      "bytes": 104857600,
      "blake3": "5f0c…(64 hex)",
      "mode": 420,
      "overwritten": false,
      "duration_ms": 912
    }
    ```

    `remote_path`와 `local_path`는 사용자가 준 문자열 그대로다(정규 경로를 돌려주지 않는다). `mode`는 10진 정수다. human 모드는 stdout에 한 줄 요약(바이트 수, 대상, BLAKE3 앞 16자)을 낸다. exit code는 §4 일반 명령 표 그대로다(성공 `0`, 실패 `255`).

## 근거

**상태 경로를 ACL 밖의 고정 규칙으로 두는 이유.** 이 성질은 운영자가 실수로라도 열 수 없어야 한다. `allow = ["file.*"]`는 흔하게 쓸 와일드카드이고, 그 한 줄이 ACL·trust·audit 쓰기 권한으로 번지면 ADR-0017과 ADR-0025가 지킨 "원격 peer는 ACL writer가 아니다"가 무너진다. `forward.socks`를 와일드카드보다 먼저 막는 upfront gate(`Action::is_always_denied`)와 같은 이유로, 이 판정도 규칙 매칭 안에 섞지 않고 규칙 판정 뒤의 별도 단계로 둔다. 설정 키를 두지 않는 것도 같은 이유다.

**정규 경로와 열린 핸들 재검증을 함께 쓰는 이유.** 문자열 비교만으로는 symlink, `..`, 대소문자 무시 파일시스템, 경로 성분 교체 경쟁을 막지 못한다. `realpath`는 판정 시점의 답만 주므로 열린 fd의 실제 경로로 다시 대조하고, 그 뒤의 모든 조작을 디렉터리 fd 기준(`*at`)으로 해서 판정한 디렉터리와 쓰는 디렉터리를 같게 만든다. hard link는 경로로 구별되지 않으므로 읽기 쪽만 inode로 막는다. 쓰기 쪽은 항목 교체만 하므로 hard link가 무력하다.

**존재하지 않는 경로도 거부하는 이유.** 상태 디렉터리 아래에서 "없음"과 "거부"가 다르면, 권한 있는 principal이 그 안에 어떤 파일(예: `device.key`, keystore 모드)이 있는지를 알아낼 수 있다. 보호 디렉터리 아래는 존재 여부와 무관하게 거부로 통일한다.

**경로 범위 규칙을 지금 넣지 않는 이유.** ACL 문법을 바꾸면 policy evaluator, `acl.toml` 로더의 fail-closed 규칙, `qsh acl check`/`acl show` 출력, doctor 진단이 함께 바뀐다. 이는 M15의 크기 밖이고, 오늘의 다른 action(`forward.local`, `exec.run`)도 resource를 매칭하지 않는다. 운영자에게 필요한 것은 "`file.*`를 주면 무엇이 열리는가"를 정확히 아는 것이고, 결정 4가 그 문장을 계약 문서에 적게 한다. 좁히는 문법은 기존 행의 의미를 바꾸지 않고 additive로 더할 수 있다.

**재개를 넣지 않는 이유.** QUIC connection migration이 IP 변경과 짧은 단절을 이미 흡수하고, 재개를 넣으면 host가 connection 수명을 넘어 temp 파일과 상태를 쥐어야 한다. ADR-0018이 터널에서 고른 "connection에 결합" 원칙과 어긋나고, 남는 부분 파일은 원격 peer가 만든 지속 자원이 된다. 실패는 깨끗이 지우고 처음부터 다시 보내는 쪽이 계약이 단순하다.

**역방향 route를 넣는 이유.** 역방향 모드를 쓰는 사람은 NAT 뒤의 노트북처럼 forward dial이 안 되는 상대를 다루는 사람이고, 파일 복사가 가장 필요한 곳이 거기다. `exec`과 `session`이 이미 같은 conduit으로 역방향에서 돌고 `FILE_DATA`는 새 local 메시지 없이 `LOCAL_STREAM`을 탄다. 추가 비용은 데몬 중계의 정체 장부 범위와 테스트 행 정도다.

**audit에 경로를 싣는 이유.** `exec.run`이 argv를 싣지 않는 것은 argv가 명령 내용, 곧 payload이기 때문이다. 파일 경로는 `forward.local`의 `host:port`처럼 "무엇에 대한 판정이었나"를 말하는 구조 정보다. 경로가 없으면 "누가 무엇을 썼나"라는 SC6 질문에 답할 수 없다. 크기와 해시는 판정 시점에 없는 값이고, 싣자면 새 필드와 전송 완료 시점의 두 번째 기록이 필요해 audit가 판정 기록에서 전송 기록으로 바뀐다.

## 대안과 기각 사유

- **`qsh cp host:path ./local` 같은 scp식 단일 명령.** 기각한다. 로컬 경로의 콜론(`./a:b`)과 IPv6 주소, host 이름 해석이 한 인자 안에서 얽힌다. 방향도 인자 순서로 추론해야 해서 JSON 계약의 `command`(`file.read`/`file.write`)를 정하기 어렵다. 나중에 human 별칭으로 더하는 것은 막지 않는다.
- **op 이름을 CLI 동사와 맞춘다(`file.get`/`file.put`).** 채택하지 않는다. action과 op 이름이 같으면 `DENY_SEAMS`, `OP_REGISTRY`, `acl_check_equivalence.rs`의 행이 한 이름으로 정렬되고, PRD §9 어휘와도 그대로 맞는다.
- **상태 경로 판정을 문자열 접두 비교로만 한다.** 기각한다. symlink와 `..`, 성분 교체 경쟁, hard link를 모두 놓친다. M15 DoD가 symlink와 `..` 두 우회를 명시한다.
- **상태 경로 목록을 설정으로 늘리거나 줄이게 한다.** 기각한다. 줄이는 쪽은 결정 5의 성질("ACL 행으로 열 수 없다")을 설정으로 여는 셈이다. 늘리는 쪽은 경로 범위 규칙(결정 4)의 몫이다.
- **`acl.toml`에 `paths` 같은 경로 범위 키를 지금 넣는다.** 이번에는 넣지 않는다. 근거 절 그대로다. 승인 과정에서 사용자가 범위 키 없는 `file.read`를 너무 넓다고 보면, 이 ADR 안에서 "`file.*`를 허용하는 행은 `paths`가 있어야 파일 op에 닿는다"는 결정으로 바꿀 수 있다. 그때 크기는 0.5~0.8ew 늘고 ACL 로더·`acl show`·doctor에 행이 는다.
- **터널처럼 header 뒤 raw bytes로 흘린다.** 기각한다. 끝 표지와 해시, `file.write`의 결과를 실을 자리가 없다. 정상 EOF와 잘린 스트림을 구별하려면 결국 별도 신호가 필요하다.
- **SHA-256으로 해시한다.** 채택하지 않는다. 사용자가 원본을 `sha256sum`으로 대조하기 쉬운 장점은 있지만, BLAKE3는 이미 의존성이고 더 빠르다. 외부 대조가 필요하면 envelope의 BLAKE3를 `b3sum`으로 대조하면 된다.
- **재개 가능한 전송(오프셋 재개, 부분 파일 보존).** 기각한다. 근거 절 그대로다. additive 경로는 열려 있다.
- **임시 파일 없이 대상에 직접 쓴다.** 기각한다. 실패한 전송이 대상을 반쯤 쓴 채로 남기고, `--force` 없는 경우의 "기존 파일을 덮지 않는다"를 경쟁 없이 보장할 수 없다.
- **역방향 route는 뒤로 미룬다.** 채택하지 않는다. 근거 절 그대로다. 사용자가 M15 크기를 줄이길 원하면 결정 16을 "역방향은 `UNSUPPORTED`"로 바꾸고 0.3~0.5ew를 덜 수 있다.
- **파일 op을 `exec.run`으로 인가한다(`cat`/`tee`와 같은 힘이므로).** 기각한다. PRD §9가 `file.read`/`file.write`를 따로 둔 이유가 exec보다 좁은 권한을 주기 위해서다.

## 결과

- **계약 문서.** `docs/CLI.md` §2.4·§2.5에 행이 늘고, §2.5 끝의 "향후 예약: streaming file copy" 문장이 빠지며, 새 절(`qsh file`)이 결정 2·4·5·17·18을 담는다. §6.12에 quota 키 둘이 는다. `docs/design/protocol.md`는 §4(`file.v1`), §7(`FILE_DATA` 행과 ticket 규칙), §9(`.proto` 발췌), §12(정체 장부 범위), freeze 발효 전이면 §16.1 표가 같은 커밋에서 바뀐다. `docs/design/architecture.md` §7 아래에 "이 트리는 원격 파일 op에서 항상 거부된다"는 한 문장과 결정 5의 집합이 오른다.
- **ACL 테스트 갱신.** `Action::is_always_denied`가 `forward.socks`만 남긴다(`acl/mod.rs`의 `is_always_denied_is_exactly_the_undrivable_trio`가 이 집합을 고정하므로 같이 바꾼다). `DENY_SEAMS`에 `file.read`, `file.write` 두 행이 오르고(`registry.rs`의 `deny_seams_row_names_and_count_are_pinned`가 고정한 행 수 14 → 16), `ALWAYS_DENIED_NO_OP`에서 두 action이 빠져 `forward.socks`만 남으며(`deny_seams_cover_every_action_except_the_always_denied_trio`), `qsh-testkit/tests/acl_uniformity.rs`가 두 seam의 문면 균일성을, `qsh-cli/tests/acl_check_equivalence.rs`가 두 action 행을 단언한다. `acl_docs.rs`의 PRD §9 대조는 바뀌지 않는다.
- **핀 테스트(이름은 구현 때 확정하되 성질은 이대로).**
  - `file_ops_are_denied_without_a_matching_rule`
  - `file_write_to_state_paths_is_denied_even_with_file_wildcard`: `acl.toml`, `trust.toml`, `identity/device.key`(또는 `device.pem`), `audit.log` 넷과 그 경로를 가리키는 symlink, `..` 이탈 경로에 대해 `PERMISSION_DENIED`이고 파일 바이트가 그대로임을 단언한다
  - `file_read_of_state_paths_is_denied_even_with_file_wildcard`: 같은 대상과 두 우회, hard link 우회까지
  - `state_path_guard_denies_nonexistent_paths_under_state_dirs`
  - `state_path_guard_covers_env_overridden_and_default_dirs`
  - `state_path_guard_rechecks_the_opened_handle`: 판정과 열기 사이에 디렉터리 성분을 symlink로 바꾸는 경쟁을 재현한다
  - `denied_file_write_leaves_no_file_or_temp_behind`, `unredeemed_file_write_ticket_leaves_nothing_behind`
  - `file_write_without_force_never_replaces_an_existing_file`, `file_write_with_force_replaces_atomically`
  - `interrupted_file_write_removes_its_temp_file`(connection 유실, 취소, 정체 장부 끊음 세 경우)
  - `file_write_size_or_hash_mismatch_renames_nothing`
  - `file_round_trip_is_byte_identical_forward`, `file_round_trip_is_byte_identical_reverse`: 64 MiB 이상의 무작위 파일
  - `file_audit_record_carries_path_but_no_payload`: `record_has_only_structural_fields`와 같은 형식으로 키 집합이 아홉 그대로이고 `resource`가 요청 경로임을 단언한다
  - `quota_registry.rs`의 두 행, `quota_docs.rs`의 키·기본값 대조
  - `file_copy_echo_under_load`: `tunnel_echo_under_load`와 같은 예산으로 파일 전송 중 PTY echo p95를 잰다(M13 (b) 하네스)
- **등록 완전성과 fixture.** 두 op의 성공 fixture와 대표 오류 fixture를 `crates/qsh-cli/tests/fixtures/`에 새로 추가하고 `REQUIRED_FIXTURES`에 등재한다(기존 fixture는 건드리지 않는다). `layer_2_every_schema_command_has_all_six_faces`가 두 op을 덮는다. `capabilities.json` golden을 `QSH_UPDATE_FIXTURES=1`로 다시 만들어 `file.v1`이 들어간다. `cargo xtask man`으로 `qsh-file`, `qsh-file-get`, `qsh-file-put` man 페이지가 는다.
- **fuzz.** 새 control message 둘은 `decode_control`이, `FILE_DATA`는 `decode_stream_header`가 이미 덮는다. data 스트림 message `FileFrame`은 새 타깃 `decode_file_frame`을 받는다(타깃이 하나 늘어난다. 개수 문장은 `fuzz/README.md`와 `docs/design/protocol.md` §13에서 착륙 시점의 실제 타깃 수로 맞춘다. 이 ADR 단독이면 19종 → 20종이지만 ADR-0031도 타깃을 하나 더하므로 순서에 따라 값이 달라진다).
- **위협 모델.** `docs/design/threat-model.md` §3에 진입점 행 "`Server::dispatch`의 `file.read`/`file.write`와 `FILE_DATA` 스트림"을 더한다. §4에 다음 행을 더한다.
  - B16: `file.write`로 qsh 상태 파일(ACL·trust·audit)을 고쳐 인가를 우회한다 → 결정 5·6, 위 `file_write_to_state_paths_…` 핀
  - B17: symlink, `..`, 성분 교체 경쟁, hard link로 상태 경로 판정을 우회한다 → 결정 6, `state_path_guard_…` 핀
  - B18: `--force` 없는 쓰기가 기존 파일을 덮거나, 실패한 쓰기가 반쯤 쓴 파일을 남긴다 → 결정 7, 덮어쓰기·중단 핀
  - C15: 원격 쓰기로 디스크를 채워 fail-closed audit가 host 전체를 멈춘다 → 결정 13, 결정 12
  - C16: 정체한 `FILE_DATA`가 연결 수신 창을 묶는다 → 결정 15
  - D15: `file.read`로 identity 키, resume token, reset key를 읽는다 → 결정 5, `file_read_of_state_paths_…` 핀
  - E12: 잘리거나 손상된 전송이 성공으로 보인다 → 결정 10
  - §7 잔여 위험에 셋을 적는다. `file.*`는 상태 경로 밖에서 serve uid의 전 범위다(결정 4). 다른 프로세스와 같은 파일시스템을 쓰면 여유 공간 상수가 audit 디스크를 보장하지 않는다. 보호 디렉터리 안의 열거되지 않은 파일을 밖에서 hard link한 경우의 읽기는 디렉터리 판정만으로 막지 못한다(만들려면 이미 serve uid의 로컬 쓰기 권한이 필요하다).
- **wire.** 추가는 모두 §16.4의 additive 경로다. 새 oneof 번호(80, 81, Response 11, 12), 새 `StreamKind` 값 5, 새 message 7종, 새 capability `file.v1`, 새 상수 `FILE_CHUNK_MAX`다. 기존 번호의 재사용이나 의미 변경은 없고 `file.v1`을 광고하지 않는 peer에게는 아무것도 보내지 않는다. `qsh.local.v1`은 바뀌지 않는다.
- **architecture rule.** guard, 전송 상태 기계, quota, 정규화는 모두 `qsh-core`에 둔다. `qsh-cli`는 clap 정의와 두 렌더러만 갖는다. 새 모듈이 `xtask arch`의 경로 범위 금지 목록에 들어가야 하는지는 구현 커밋이 판단하고, 들어가면 `xtask/src/arch.rs`를 같은 커밋에서 고친다.
- **크기.** 2.8~4.2ew. ADR 0.3 + op 둘과 wire, 전송 상태 기계, 렌더러 두 벌 1.2~1.8 + 경로 판정(정규화, 핸들 재검증, inode, 두 OS) 0.4~0.6 + 역방향 route와 데몬 중계의 정체 장부 0.3~0.5 + ACL·quota·audit 테스트 갱신 0.3~0.5 + fixture·capabilities·man·fuzz 타깃 0.2~0.3 / 마감 0.1~0.2. ROADMAP의 2.7~4.0과 비교하면 TCP transport 두 벌이 빠진 만큼 줄고, 경로 판정 강화와 역방향이 그만큼 늘었다.
- 이 ADR이 승인되면 `docs/ROADMAP.md` M15의 착수 조건이 풀린다. DoD의 transport 문구는 ADR-0043과 함께 메인 세션이 고친다.
