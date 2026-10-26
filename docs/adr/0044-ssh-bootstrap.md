# ADR-0044: pin이 없는 대상에 `qsh <dest>`를 부르면 시스템 ssh를 한 번 거쳐 양쪽 pin을 등록하고 QUIC로 접속한다. ssh 설정·인증·known_hosts는 ssh가 그대로 처리하고 qsh는 SSH 키를 읽지 않으며, 원격 쪽 pin은 ADR-0045의 role `full`로 쓴다

날짜: 2026-10-12 (개정 2026-10-13, 2026-10-14, 2026-10-15, 2026-10-17, 2026-10-25)
상태: 승인됨

개정 관계: 새 ADR이다. 다른 ADR의 결정을 개정하지 않는다. ADR-0013 결정 6이 이미 통과시킨 파이프(`qsh identity export | ssh box 'qsh trust add laptop --cert-file -'`)를 양방향으로 자동화한 것이고, ADR-0017 결정 1(`acl.toml`을 쓰지 않는다)과 결정 5(TOFU 없음)를 재확인한다. ADR-0026의 `--import-ssh-key`와 `trust ssh-preview`는 그대로 남지만 그 동기(SSH 쪽 자산으로 qsh 신뢰를 빨리 세운다)는 이 ADR이 대신한다(결정 15). ADR-0015와 ADR-0016은 2026-10-12에 기각됐고 그 기각 사유가 이 ADR을 대체 경로로 가리킨다. ADR-0045(역할 기반 권한)의 pin `role`을 쓰므로 ADR-0045가 먼저 또는 같이 승인돼야 하고, 2026-10-14에 같이 승인됐다. 승인되면 바뀌는 계약 문서는 `docs/CLI.md`(§2.4, §2.5, §6.11, §7), `docs/design/protocol.md`(새 절), `docs/design/threat-model.md`(§3, §4, §7)다.

개정 이력: 2026-10-15에 결정 11에 메시지 구별 방식을 더했다. 세 메시지의 필드만 적고 구별 방식을 적지 않아 구현(`crates/qsh-proto/src/ssh_bootstrap.rs`)이 필드 구성에 기대지 않는 명시 태그를 골랐고, 그 선택을 여기 적어 승인된 결정으로 둔다. 다른 결정은 바뀌지 않는다. 2026-10-17에 M19가 결정 25의 Windows client 분기를 착지시켰다. 자동 부트스트랩의 ssh 자식은 콘솔을 물려받고 그동안 입력 모드는 cooked로 남으며 Ctrl-C는 `CANCELED`다(`auto_bootstrap_keeps_the_console_cooked_until_ssh_exits_on_windows`). Windows host 쪽 응답자가 필요한 경로는 M20이다. 결정은 바뀌지 않는다. 2026-10-18에 M20이 결정 10의 Windows 응답자를 착지시켰다. 숨김 `qsh pair ssh-respond`가 Windows 빌드에도 등록되고 순서·판정·audit·종료 코드는 다른 OS와 같다. probe 소켓의 `SO_EXCLUSIVEADDRUSE`는 결정 10을 따른 방어용 설정이다. probe가 `SO_REUSEADDR`를 걸지 않아 이 옵션 없이도 포트를 쥔 소켓과 bind가 충돌하므로, 옵션이 결과를 바꾼다고 보인 테스트는 없다. 결정은 바뀌지 않는다. 2026-10-25에 결정 14와 16을 고쳤다. 캠페인 `docs/campaigns/p1-windows.md` §4.14 W7 변형 A의 실기기 확인에서, 원격 기본 셸 `cmd.exe`에 `qsh`가 없을 때 ssh 종료 코드가 9009가 아니라 1임이 나왔다(Windows 11 25H2 빌드 26200.9711, OpenSSH for Windows 9.5p2, `ssh winbox 'nosuchcmdxyz'`가 1). 그래서 `remote_command_failed`로 떨어지던 것을, ssh의 stderr를 파이프로 받아 바이트 그대로 사용자 stderr로 흘리면서 마지막 4 KiB만 분류용으로 메모리에 두고, 종료 코드 1에 `'<원격 qsh 이름>'`으로 시작하는 줄이 있으면 `remote_qsh_missing`으로 사상한다. 프롬프트는 제어 터미널에서 일어나 stderr 파이프와 무관하다. 꼬리는 로그·envelope·audit에 쓰지 않는다. 새 `ErrorCode`·wire 변화는 없다. 2026-10-26에 Windows OpenSSH Server의 pty 없는 세션에서 `qsh pair ssh`가 `hello` 단계 `bootstrap_timeout`으로 끝나는 결함을 고쳤다. 그 세션의 sshd가 환경에 `<guid>_POSIX_FD_STATE`를 넣고, ssh.exe가 이를 자기 fd 0·1·2의 설명으로 읽는데 qsh가 쥐여 준 익명 파이프와 맞지 않아 종료 단계(`chan_shutdown_write`)에서 멈추기 때문이다. 그래서 Windows에서는 `ssh -G`와 응답자 호출 두 ssh 자식 모두의 환경에서 이름이 `_POSIX_FD_STATE`로 끝나는 변수(대소문자 무시)를 뺀다(캠페인 `docs/campaigns/p1-windows.md` §7 W3a v0.5.5 비고, 테스트 `posix_fd_state_names_picks_only_names_ending_in_the_suffix_ignoring_case`와 Windows 전용 `the_ssh_spawn_path_strips_the_posix_fd_state_variable_on_windows`). 다른 변수는 그대로 물려받고 결정·wire·계약은 바뀌지 않는다.

2026-10-13 사용자 확인: 자동 발동을 기본으로 둔다(결정 2). ssh가 받아들인 host key 신뢰를 그대로 이어받고 `StrictHostKeyChecking`을 덮어쓰지 않는다(결정 20). "qsh는 모든 경우에서 정방향과 역방향에 같은 기능을 준다"(PRD §4)에 따라 역방향 구도의 부트스트랩을 결정 22에 더했다.

승인 2026-10-14: 사용자 위임 결정("전부 다 알아서 진행해")으로 승인했다. 자동 발동의 "권장안" 표현을 확정으로 바꾸고, 역방향 부트스트랩의 플래그·commit 주소 필드·로컬 pin role·audit과 결정 22의 ADR-0045 인용을 정리했으며, Windows 원격 응답자는 ADR-0035 결정 25대로 열고(`unsupported_platform` 삭제, cmd.exe 9009와 PowerShell 종료 코드 사상, 원격 실행 파일 인용 규칙, Windows UDP bind 확인), 기존 pin의 role이 요청과 다를 때의 안내를 정했다.

## 맥락

2026-10-12 사용자 요구 원문은 이렇다. "기존 SSH 키를 import 하는게 아니라, SSH 설정들을 모두 자동으로 가져와서 그대로 하위호환 지원… 기존 SSH의 설정과 키를 활용해서 바로 qsh가 동작할 수 있게."

오늘 두 장비가 처음 서로를 신뢰하는 경로는 셋이다. 초대 코드(ADR-0002, `qsh pair invite`/`qsh pair accept`), fingerprint 수동 pin(`qsh trust add --fingerprint`), 인증서 파일 교환(ADR-0013, `qsh identity export` + `qsh trust add --cert-file`). 셋 모두 양쪽 장비에서 사람이 명령을 한 번씩 쳐야 하고, 원격 장비에 이미 ssh로 들어갈 수 있는 사용자에게는 "ssh로 들어가서 qsh 명령을 치고, 나와서 또 친다"는 왕복이다. ADR-0013 결정 6은 그 왕복을 ssh 파이프 한 줄로 줄일 수 있다고 적었고, 그 파이프의 신뢰 근거가 qsh가 아니라 ssh known_hosts라는 점도 함께 적었다. 이 ADR은 그 파이프를 qsh가 직접 돌리는 모양을 정한다.

ADR-0026은 다른 방향에서 같은 마찰을 다뤘다. 운영자의 OpenSSH 개인키를 qsh identity로 들이는 `qsh init --import-ssh-key`(평문 Ed25519 한정, M11 (c)로 출고)와, `authorized_keys`를 읽어 필요한 pin과 `[[acl]]` 행을 보여 주는 `qsh trust ssh-preview`다. 둘 다 키 재료를 qsh로 옮기는 길이라 암호가 걸린 키, ssh-agent, `~/.ssh/config`의 별칭과 `HostName`·`User`·`ProxyJump`, known_hosts를 하나도 쓰지 못한다(ADR-0026 결정 7이 앞의 둘을 별도 결정으로 미뤘다). 사용자가 원하는 것은 키가 아니라 이미 동작하는 ssh 접속 그 자체를 재사용하는 것이다.

mosh가 같은 문제를 푼 모양이 있다. `mosh host`는 시스템 ssh로 원격에 `mosh-server`를 띄우고, 그 출력 한 줄로 UDP 포트와 세션 키를 받은 뒤 ssh를 닫고 UDP로 옮겨 간다. ssh 설정과 인증은 ssh가 전부 처리하고 mosh는 ssh를 부르기만 한다. qsh는 mosh와 두 가지가 다르다. 세션은 연결마다 새로 뜨는 서버가 아니라 장기 실행 `qsh serve`가 소유하고(ADR-0003), 매 접속마다 새 키를 나눌 필요 없이 한 번 pin하면 그 뒤로는 mTLS가 신원을 증명한다. 그래서 qsh에게 ssh가 필요한 것은 접속마다가 아니라 처음 한 번, pin을 세울 때뿐이다.

관련 사실 몇 가지를 코드에서 확인했다.

- 대상 인자는 `[user@]host`이고 마지막 `@`에서 자른다(`crates/qsh-cli/src/cli.rs`의 `parse_target`). `user@`는 계정 선택이 아니라 단언이다(`docs/CLI.md` §7).
- 이름 해석은 live reverse 등록, `hosts.toml`, `trust.toml` 순이고 어디에도 없으면 `HOST_NOT_FOUND`(`retryable: false`, `details` 비어 있음)다(`docs/CLI.md` §6.1).
- `trust.toml`의 pin은 `name`·`fingerprint`·`address`·`added_at` 넷이고(`qsh_proto::types::trust::TrustPeer`), `TrustStore::add_peer`는 이름을 키로 한다. 같은 이름에 다른 fingerprint가 오면 아무것도 바꾸지 않는다. 장기 실행 프로세스는 `trust.toml`을 매 handshake마다 내용 기준으로 다시 읽는다(`docs/CLI.md` §6.11 `trust remove` 문단).
- 주소에 포트가 없으면 4433을 채운다(ADR-0014 결정 1·2, `qsh_core::trust::normalize_peer_address`).
- `hosts.toml`은 어떤 CLI 명령도 쓰지 않는다(ADR-0014 결정 6, `docs/CLI.md` §6.1).
- `qsh serve`가 떠 있는지 알려 주는 런타임 표지(pid 파일, 소켓)는 없다. localctl 소켓은 `qsh listen`만 연다.
- 로컬 op의 audit 기록은 `AuditRecord::local_op`가 만들고(`trust.rename`이 첫 사용처), pairing으로 생긴 pin은 `AuditRecord::pairing`이 남긴다. audit writer는 fail closed다.

## 결정

### 발동과 명령

1. 명시 명령 `qsh pair ssh <[user@]host>`를 신설한다. 새 신뢰 항목을 만드는 일이므로 ADR-0012 결정 3의 층 분리에 따라 `trust`가 아니라 `pair` 그룹에 둔다. dotted operation 이름은 CLI 토큰을 기계적으로 옮긴 `pair.ssh`다(`docs/CLI.md` §2.4. `pair invite`/`pair accept`가 `trust.invite`/`trust.accept`를 유지한 것은 개명 이전의 이름이어서이고 ADR-0012 결정 9, 새 op에는 해당하지 않는다). 인가 불요 local op이고 원격 peer가 요청할 수 없다(§2.5 "인가 불요" 행에 더한다). 플래그는 다음이 전부다.
   - `--as <name>`: 이 장비가 원격을 pin할 이름. 기본값은 결정 7.
   - `--remote-as <name>`: 원격이 이 장비를 pin할 이름. 기본값은 결정 8.
   - `--role <role>`: 원격 pin의 role. 기본값 `full`(결정 8). 값의 어휘는 ADR-0045가 정한다. 이 장비 쪽 pin의 role은 플래그로 고르지 않는다. 정방향은 `none`, 역방향은 `reverse`로 고정이고(결정 12, 22) 바꾸려면 부트스트랩 뒤에 `qsh trust set-role`을 쓴다. 두 pin의 role을 한 플래그에 섞지 않으려는 것이다.
   - `--reverse`와 `--to <host[:port]>`: 역방향 구도(결정 22). 둘은 함께 쓴다. `--reverse`만 있거나 `--to`만 있으면, 또는 `--reverse`와 `--address`를 함께 주면 ssh를 부르기 전에 `INVALID_ARGUMENT`다. `--to`는 `trust add --address`와 같은 정규화를 거친다.
   - `--address <host[:port]>`: 결정 5가 만드는 dial 주소를 덮어쓴다. `trust add --address`와 같은 정규화를 거친다.
   - `--remote-qsh <path>`: 원격에서 부를 qsh 실행 파일. 기본값은 `config.toml`의 `[ssh].remote_qsh`, 그다음 `qsh`.

2. 사람용 대화형 형태 `qsh [user@]host`(`-L`/`-R`/`-D`를 동반한 경우 포함)와 ADR-0029의 `qsh cp`가 원격 쪽 이름을 해석하다 `HOST_NOT_FOUND`의 첫 갈래, 곧 "이름이 아예 미등록"(`docs/CLI.md` §6.1)에 닿으면 결정 1과 같은 절차를 기본 플래그로 자동 실행하고, 성공하면 원래 명령을 그대로 이어 간다. 2026-10-13 사용자 확인으로 확정된 기본 동작이고 근거는 근거 절 첫 항목이다. 자동 발동의 경계는 다음과 같다.
   - `--json`/`--jsonl`에서는 발동하지 않는다. 대화형 형태는 machine mode를 이미 `INVALID_ARGUMENT`로 거부하고(§7), `qsh cp --json`은 지금처럼 `HOST_NOT_FOUND`를 낸다. 기계 소비자는 `qsh pair ssh --json`을 먼저 부른다. 사람 모드의 `HOST_NOT_FOUND` message에는 `qsh pair ssh <host>`를 다음 명령으로 적는다. `details`는 바꾸지 않는다.
   - `hosts.toml`에 그 이름이 있거나, reverse 등록이 stale로라도 남아 있거나, `trust.toml`에 그 이름의 pin이 있으면 발동하지 않는다. 사용자가 qsh 쪽에 이미 무언가를 적어 둔 이름은 qsh 설정이 이긴다.
   - `qsh exec`, `qsh session open`, `qsh tunnel open`, `qsh sessions`는 발동하지 않는다. 이 명령들은 bare host만 받는 기계 지향 표면이고(§7 `user@` 문단) ssh의 자리를 대신하는 명령이 아니다.
   - `config.toml`의 `[ssh].bootstrap = "off"`이면 발동하지 않는다. 기본값은 `"auto"`이고 허용 값은 둘뿐이다. 다른 값은 `CONFIG_ERROR`다.
   - 발동하기 전에 stderr에 정확히 한 줄을 낸다. "no qsh pin for \"<host>\"; setting one up over ssh (ssh <dest>); set [ssh].bootstrap = \"off\" to disable" 꼴이고 문면은 구현에서 상수(`qsh_core::ssh_bootstrap::AUTO_BOOTSTRAP_NOTICE`)로 고정한다. 사용자가 ssh가 불린다는 사실을 프롬프트보다 먼저 알게 하려는 것이다.

3. 한 번 pin이 서면 그 뒤의 `qsh <host>`는 결정 2의 조건에 닿지 않으므로 ssh를 부르지 않는다. 이후 접속은 QUIC만 쓴다.

### ssh 설정 해석과 qsh 주소

4. 시스템 ssh를 두 번 부른다. 먼저 `ssh -G -- <dest>`로 로컬 설정만 평가해(네트워크 없음) `hostname`, `user`, `proxyjump`, `proxycommand` 네 키를 읽는다. 다음으로 결정 9의 인자로 원격 응답자를 부른다. 두 호출 모두 사용자가 친 `<dest>` 문자열을 그대로 넘겨 `~/.ssh/config`의 `Host`·`Match` 블록, 별칭, `%h` 토큰 확장이 ssh 자신의 규칙대로 적용되게 한다. qsh는 `ssh_config`를 직접 파싱하지 않는다. ssh 실행 파일은 `config.toml`의 `[ssh].program`, 없으면 `PATH`의 `ssh`다. 최소 버전은 OpenSSH 7.6이다(`-G`는 6.8, `RemoteCommand`는 7.6). `ssh -G` 출력은 로컬 프로세스 출력이라 `qsh-core`에서 읽되, 줄 길이와 전체 크기에 상한(64 KiB)을 둔다.

5. qsh dial 주소는 `<ssh -G의 hostname>:<원격이 보고한 serve 포트>`다. ssh의 `Port`는 쓰지 않는다. qsh 포트는 ssh 포트와 무관하고, 원격 응답자가 자기 `[serve].bind`(없으면 기본 `[::]:4433`, ADR-0014 결정 1·8)의 포트를 보고한다(결정 10). bind의 host 부분이 특정 IP여도 dial 주소의 host는 ssh `hostname`을 쓴다. DNS 이름을 pin에 남겨 주소 변경을 따라가게 하려는 것이고, 맞지 않는 배치는 `--address`로 덮는다. 주소는 `normalize_peer_address`를 거쳐 저장한다. `hostname`이 IPv6 리터럴이면 그 규칙대로 대괄호로 감싼 `[addr]:port` 꼴이 된다.

6. `proxyjump`이나 `proxycommand`가 `none`이 아니면 ssh는 중계를 거쳐 닿지만 QUIC는 `hostname`으로 직접 간다. qsh에는 relay도 jump 체인도 없다(jump chaining은 P2). 이 경우 pin 교환은 그대로 진행하고(신뢰는 경로와 무관하다), 사람 모드는 stderr에 직접 닿지 않을 수 있다는 한 줄을, `data`는 `ssh_proxied: true`를 낸다. 결정 13의 확인 dial이 실패하면 그 사유에 이 사실을 덧붙인다.

### 이름

7. 이 장비가 원격을 pin하는 이름은 `<dest>`의 host 부분, 곧 사용자가 친 ssh `Host` 별칭 그대로다(`dave@box`면 `box`). `ssh -G`가 풀어 준 `hostname`이 아니다. 그래야 다음 `qsh box`가 같은 이름으로 pin을 찾는다. 이름은 `validate_peer_label`과 `/` 금지(`docs/CLI.md` §6.11 `--as` 문단과 같은 규칙)를 통과해야 하고, 실패하면 ssh를 부르기 전에 `INVALID_ARGUMENT`다. `--as`가 이 기본값을 대신한다. `<dest>`가 `-`로 시작하면 ssh 옵션으로 읽힐 수 있으므로 같은 자리에서 `INVALID_ARGUMENT`다. `ssh://` URI 꼴은 받지 않는다.

8. 원격이 이 장비를 pin하는 이름은 `--remote-as`, 없으면 이 장비 호스트 이름의 첫 레이블(`validate_peer_label`을 통과할 때), 그것도 아니면 `device_id`다. 이름 결정권은 pin하는 쪽에 있다는 ADR-0012 결정 6과 어긋나지 않는다. 원격 pin을 쓰는 프로세스는 ssh로 그 원격 계정에 인증된 같은 사용자가 띄운 것이고, 그 사용자는 원격에서 `qsh trust add`를 직접 칠 권한을 이미 갖는다. 원격 pin의 `role`은 `--role`, 없으면 `full`이다(ADR-0045). 근거는 근거 절 셋째 항목이다.

### 원격 응답자와 stdio 프로토콜

9. 원격에서는 숨김 하위 명령 `qsh pair ssh-respond`를 부른다(`--help`에 나오지 않는다. ADR-0012 결정 4의 숨김 서브커맨드와 같은 방식). 이 명령은 `qsh.cli/v1` envelope을 내지 않는다. stdout은 결정 11의 부트스트랩 스트림이고 stdin은 그 응답 쪽이다. §2.4에는 `qsh serve`처럼 "operation 아님" 문장으로 적고, audit `action` 문자열로만 `pair.ssh_respond`를 쓴다. 로컬 ssh 자식의 인자는 다음으로 고정한다.

   `ssh -T -a -x -o ClearAllForwardings=yes -o RemoteCommand=none -o RequestTTY=no -o PermitLocalCommand=no [-o BatchMode=yes] -- <dest> <remote_qsh> pair ssh-respond`

   `-T`·`RequestTTY=no`는 원격 PTY를 만들지 않는다. `-a`·`-x`·`ClearAllForwardings`는 설정 파일의 agent·X11·포트 포워딩이 부트스트랩 연결에 붙지 않게 한다(`LocalForward`가 있는 Host에서 포트 충돌로 실패하는 일도 막는다). `RemoteCommand=none`은 설정에 `RemoteCommand`가 있을 때 명령줄 명령과 충돌해 ssh가 거부하는 것을 막는다. 그 밖의 설정(`HostName`, `User`, `IdentityFile`, `IdentitiesOnly`, `ProxyJump`, `ControlMaster`, `StrictHostKeyChecking`, `UserKnownHostsFile` 등)은 건드리지 않는다. `<remote_qsh>`는 원격 셸이 해석한다. 문자가 모두 `[A-Za-z0-9_./~+:\\-]`이면(기본값 `qsh`와 흔한 경로, Windows 드라이브 경로 포함) 인용 없이 그대로 넘긴다. 그래야 POSIX `sh`, `cmd.exe`, PowerShell 어느 기본 셸에서도 같은 토큰이다. 그 밖의 문자(공백 등)가 있으면 POSIX 작은따옴표로 감싸 넘기고, 원격이 Windows이고 기본 셸이 POSIX 인용을 모르면 실패한다. 그 경우 실행 파일 경로를 `PATH`에 두거나 위 문자만 쓰는 경로로 바꾸라고 결정 14의 message가 안내한다. 사용자 문자열(`--remote-as`, `--role`)은 명령줄이 아니라 결정 11의 메시지 안으로 보낸다.

10. 응답자는 이 순서로 동작한다. 자기 identity(`identity/device.pem`)를 읽고, 없으면 쓰기 없이 `not_initialized`를 알린다. 원격 identity를 대신 만들지 않는다. 응답자는 Linux·macOS·Windows에서 같은 순서로 동작한다(Windows host는 ADR-0035 결정 25, 착지는 M20이고 그 전의 Windows 빌드는 이 하위 명령을 몰라 결정 14의 `remote_qsh_too_old`가 된다). serve 포트를 `[serve].bind`에서 정하고, 그 주소로 UDP 소켓 bind를 한 번 시도해 곧바로 닫는다. Windows에서는 이 probe 소켓에 `SO_EXCLUSIVEADDRUSE`를 걸어 다른 소켓이 그 포트를 쥐고 있으면 실패하게 한다(Windows는 기본 옵션만으로는 같은 포트의 중복 bind를 허용하는 경우가 있다). bind가 `EADDRINUSE`(Windows는 `WSAEADDRINUSE`)면 `serve_listening: true`, 성공하면 `false`, 그 밖의 오류는 `null`(모름)이다. 다른 프로그램이 그 포트를 쥐고 있으면 `true`로 잘못 나오지만, 그 경우는 결정 13의 확인 dial이 신원 불일치로 잡는다. 이 정보를 담아 hello를 보내고 commit을 기다린다.

11. 부트스트랩 스트림은 줄 단위다. 각 줄은 고정 접두 `qsh-bootstrap ` 뒤에 JSON 객체 하나이고 한 줄은 8 KiB를 넘지 않는다. 클라이언트는 hello 앞에 오는 접두 없는 줄(원격 셸 rc 파일이 찍는 출력)을 건너뛰되 합계 64 KiB까지만 참고, 그 줄의 내용은 로그에도 출력에도 남기지 않고 개수만 센다. hello 뒤로는 접두 없는 줄이 오면 프로토콜 오류다. 메시지는 셋이다.
   - 응답자 → 클라이언트 `hello`: `versions`(지원하는 부트스트랩 버전 목록, 이 ADR은 `[1]`), `qsh_version`, `status`(`ready`, `not_initialized`), `ready`일 때만 `fingerprint`(`sha256:BASE64`)와 `serve_bind`와 `serve_listening`.
   - 클라이언트 → 응답자 `commit`: `version`(고른 버전), `fingerprint`(이 장비의 것), `name`(결정 8), `role`, 역방향일 때만 `address`(결정 22의 `--to`를 정규화한 값. 없으면 주소 없는 pin).
   - 응답자 → 클라이언트 `result`: `status`(`pinned`, `exists`, `conflict`, `error`), `name`, `role`(없으면 `null`), `created`, 실패면 `code`(`ErrorCode` 어휘)와 `message`.

   모든 메시지 객체는 `type` 필드(`hello`·`commit`·`result`)를 가져 메시지를 가른다. 모르는 `type`은 형식 오류다. 필드 단위의 필수·선택 여부는 `docs/design/protocol.md` §17.2~§17.3이 정하고, 이 태그는 additive-only 규칙에 따라 고정된다(개정 2026-10-15).

   버전은 클라이언트가 `hello.versions`와 자기 목록의 교집합에서 가장 큰 값을 고른다. 교집합이 비면 commit을 보내지 않고 `UNSUPPORTED`로 끝난다. 알 수 없는 필드는 무시한다(additive 확장 여지). 알 수 없는 `status` 값은 `REMOTE_ERROR`(`"bootstrap_protocol"`)다. 메시지 타입과 줄 파서는 신뢰할 수 없는 입력을 읽는 sans-IO 코드이므로 `qsh-proto`에 두고 cargo-fuzz 타깃 `parse_ssh_bootstrap_line`을 붙인다(ADR-0001 결과 절의 규율). 이 스트림은 QUIC wire가 아니지만 서로 다른 버전의 qsh 둘이 말하는 상호운용 계약이므로 `docs/design/protocol.md`에 새 절로 싣고, §16의 freeze 규칙 중 additive-only를 같은 방식으로 따른다.

12. 쓰기는 두 단계로 한다. 클라이언트는 hello를 받은 뒤, 아무것도 쓰기 전에 로컬 상태를 검사한다. 같은 이름의 pin이 다른 fingerprint로 있거나(결정 2의 자동 경로에서는 생기지 않지만 `qsh pair ssh`에서는 생긴다), 원격 fingerprint가 다른 이름으로 이미 pin돼 있으면 commit을 보내지 않고 끝난다. 응답자는 commit을 받으면 `trust.toml`의 `FileLock` 아래에서 검사하고 쓴다. 이 장비의 fingerprint가 이미 어떤 이름으로든 pin돼 있으면 새 pin을 만들지 않고 `exists`로 그 이름과 기존 `role`을 돌려준다. 기존 pin의 role은 바꾸지 않는다. 역방향에서 기존 pin의 주소가 commit의 주소와 다르면 `trust add`와 같은 규칙으로 주소만 갱신한다. 결과의 `role`이 요청한 role과 다르면(기존 pin이 `none`이거나 role이 없는 경우 등) 사람 모드는 stderr에 한 줄, "remote pin <name> keeps role <role>; run `ssh <dest> qsh trust set-role <name> <role>` to change it" 꼴로 알리고, `data.remote.role`이 실제 값을 담는다. role이 없는 기존 pin(ADR-0045가 "acl.toml만"으로 읽는 pin)을 `full`로 올리면 권한이 조용히 넓어지기 때문이다. 같은 이름이 다른 fingerprint로 있으면 `conflict`다. 새로 쓸 때는 commit에 `address`가 없으면 `address`를 비운 inbound 전용 pin(`docs/CLI.md` §6.11)으로, 있으면(역방향) 그 주소를 담은 pin으로 쓰고 `AuditRecord::local_op("pair.ssh_respond", <pin 이름>, <role>)` 꼴의 구조 기록을 남긴다. audit를 쓸 수 없으면 pin도 쓰지 않고 `error`다. 원격이 `pinned`나 `exists`를 돌려준 뒤에 클라이언트가 자기 pin을 쓴다. 클라이언트 쪽 pin은 정방향에서는 결정 5의 주소를 담고 `role = "none"`을, 역방향에서는 주소 없이 `role = "reverse"`를 명시한다(ADR-0045는 새 pin이 role 키를 항상 적게 해 role 없는 legacy pin과 구별한다). 클라이언트 쪽 pin도 role이 `none`이 아니면(역방향) ADR-0045 결정 8에 따라 `AuditRecord::local_op("pair.ssh", <pin 이름>, <role>)` 레코드를 남기고, 순서는 lock → load → mutate → audit → save이며 audit을 쓸 수 없으면 클라이언트 pin을 쓰지 않는다(원격 pin은 이미 섰고 같은 명령의 재실행이 수렴시킨다). 이 순서에서 클라이언트 쓰기가 디스크 오류로 실패하면 원격 pin만 남는데, 같은 명령을 다시 부르면 원격은 `exists`로 멱등하게 지나가므로 따로 되돌리지 않는다.

13. pin이 서면 QUIC handshake로 확인한다. 자동 경로(결정 2)에서는 원래 명령의 연결이 곧 확인이고, `qsh pair ssh`는 handshake와 mTLS 양방향 pin 검증까지만 하고 세션을 열지 않는다. 결과 처분은 다음과 같다.
   - 역방향(결정 22)은 확인 dial을 하지 않는다. 원격이 dial하는 쪽이라 이 장비에서 먼저 닿을 길이 없고, `verified: false`로 성공한다.
   - 정방향에서 hello의 `serve_listening`이 `false`면 dial하지 않는다. `qsh pair ssh`는 `verified: false`와 `verify_error`(`code: CONNECTION_FAILED`, `details.reason: "remote_serve_not_listening"`)로 성공하고, 자동 경로는 `CONNECTION_FAILED`(`details.reason: "remote_serve_not_listening"`)로 끝난다. message는 원격에서 `qsh service install` 또는 `qsh serve`를 띄우라고 적는다. pin은 남는다. 다음 `qsh <host>`는 serve가 뜬 뒤 QUIC로 바로 붙는다.
   - handshake에서 원격이 hello의 fingerprint와 다른 인증서를 내면 `AUTH_FAILED`(`details.reason: "remote_serve_identity_mismatch"`)다. 그 포트의 serve가 ssh 계정과 다른 계정이나 다른 `QSH_CONFIG_DIR`로 떠 있다는 뜻이다. pin을 고치거나 다시 쓰지 않는다.
   - 그 밖의 dial 실패는 기존 `CONNECTION_FAILED` 어휘 그대로이고 결정 6의 중계 사실을 덧붙인다.

### 실패와 불일치

14. 설치나 기동을 대신하지 않는다. 원격에 qsh가 없으면(ssh 원격 명령 종료 코드 127. 원격 기본 셸이 `cmd.exe`이면 ssh의 종료 코드는 1이고 stderr의 어떤 줄이 `'<원격 qsh 이름>'`으로 시작하는 것으로 알아본다. 아래) `REMOTE_ERROR`(`details.reason: "remote_qsh_missing"`), 응답자 명령을 모르는 옛 qsh면(hello 없이 종료 코드 2. M20 전의 Windows 빌드 포함) `UNSUPPORTED`(`"remote_qsh_too_old"`), 원격 identity가 없으면 `REMOTE_ERROR`(`"remote_not_initialized"`, message는 원격에서 `qsh setup host`를 안내)다. 원격 기본 셸이 `cmd.exe`이면 `qsh`가 없을 때 `cmd.exe /c`의 프로세스 종료 코드가 1이다(9009는 배치 안 ERRORLEVEL일 뿐이다. 실측: Windows 11 25H2 빌드 26200.9711, OpenSSH for Windows 9.5p2). 그래서 종료 코드 1이고 ssh가 relay한 stderr 꼬리(마지막 4 KiB, ANSI 이스케이프 제거)의 어떤 줄이 앞 공백을 뺀 뒤 `'<name>'`으로 시작하면(`<name>`은 원격 명령줄에 실린 qsh 프로그램 값이나 그 basename이고, `cmd.exe`의 영어 "'qsh' is not recognized ..."와 한국어 "'qsh'은(는) 내부 또는 외부 명령..."이 모두 걸린다) 127과 같은 `remote_qsh_missing`(`details.remote_exit: 1`)으로 낸다. 127과 9009는 그대로 같은 사상이다. 그 줄이 없는 1, 곧 PowerShell은 `qsh:`로 시작하는 문구를 내고 다른 실패와 구별되지 않으므로 `REMOTE_ERROR`(`"remote_command_failed"`, `details.remote_exit`)로 끝나고 message가 `qsh.exe`를 원격 `PATH`에 등록하거나 `--remote-qsh`에 전체 경로를 주라고 안내한다(ADR-0035 결정 25). 플랫폼 때문에 거부하는 경우는 없다(결정 10). 이 경우들 모두 양쪽에 아무것도 쓰지 않는다. 비대화형 ssh 셸의 `PATH`에 `~/.cargo/bin`이나 `/usr/local/bin`이 없어 127이 나는 흔한 경우를 위해 message는 `--remote-qsh`와 `[ssh].remote_qsh`를 함께 적는다. 이 장비에 ssh가 없으면 `CONFIG_ERROR`(`"ssh_not_found"`), ssh 자체가 실패하면(종료 코드 255: 인증, host key, 네트워크) `CONNECTION_FAILED`(`"ssh_failed"`, `details.ssh_exit`)다. ssh가 stderr에 쓴 원인은 그대로 사용자 stderr로 흘러 이미 보였으므로 qsh가 그 문장을 다시 해석해 알리지 않는다. 위 `cmd.exe` 판정만 예외로, 꼬리를 메모리에서 한 번 훑어 종료 코드 1을 가르는 데만 쓰고 로그·envelope·audit에 싣지 않으며 분류 뒤 버린다. 프로토콜 위반(접두 줄 형식, 상한 초과, 순서 위반)은 `REMOTE_ERROR`(`"bootstrap_protocol"`)다. 모든 `details.reason` 값은 기존 코드에 붙는 additive 필드다.

15. pin 불일치는 fail closed다. 결정 12의 두 충돌(같은 이름 다른 fingerprint, 같은 fingerprint 다른 이름)은 양쪽 모두 `SESSION_CONFLICT`(`details.reason: "pin_conflict"`, `details.side: "local" | "remote"`, `details.name`, 그리고 공개값인 `details.pinned_fingerprint`와 `details.observed_fingerprint`)이고 아무것도 덮어쓰지 않는다. 이미 pin된 `qsh box`가 접속 중 인증서 불일치로 실패하는 경우(원격 identity를 다시 만든 경우 등)는 오늘처럼 handshake의 `AUTH_FAILED`이고 자동 재부트스트랩은 없다. 불일치는 바로 멈춰야 하는 신호이기 때문이다. 사람 모드 message는 명시적 재부트스트랩 두 줄을 적는다. `qsh trust remove box`와 `qsh pair ssh box`다(원격 쪽 이 장비 pin이 충돌이면 `ssh box qsh trust remove <name>`). 원격 쪽 충돌이 이름만 겹친 것이면 `--remote-as <다른 이름>`으로 피할 수 있고 message가 그것도 적는다. `--replace` 같은 덮어쓰기 플래그는 두지 않는다.

### 터미널, machine mode, 로그

16. ssh 자식의 stdin·stdout·stderr는 파이프이고, stderr는 도착하는 대로 한 바이트도 바꾸지 않고 이 프로세스의 stderr로 흘려 사용자가 즉시 본다(분류용으로 마지막 4 KiB만 메모리에 두며 결정 14). 제어 터미널은 그대로 물려준다. 그래서 ssh는 암호, 키 passphrase, keyboard-interactive(2FA), 처음 보는 host key 확인을 `/dev/tty`(Windows는 콘솔)에서 직접 묻고, qsh는 그 입력을 보지도 거치지도 않는다. 대화형 형태는 부트스트랩이 끝나고 ssh 자식이 종료한 뒤에야 raw 모드에 들어간다. `BatchMode=yes`는 machine mode(`--json`/`--jsonl`)이거나 stdin이 터미널이 아닐 때만 붙인다. 사람 모드에서 ssh 프롬프트를 막지 않는 것이 "ssh 설정과 키를 그대로" 쓰는 요구의 핵심이다. 사용자가 ssh 프롬프트에서 Ctrl-C를 누르면 같은 foreground 프로세스 그룹의 ssh가 끝나고 qsh는 `CANCELED`로 끝나며 아무것도 쓰지 않는다. hello까지의 대기는 사람 모드에서 상한이 없고(프롬프트를 사람이 답하는 시간), `BatchMode`에서는 60초다. hello 뒤의 각 메시지는 30초 안에 와야 한다. 응답자도 commit을 30초 기다리고 오지 않으면 쓰지 않고 끝난다.

17. machine mode에서 `qsh pair ssh --json`은 envelope 하나를 낸다. `data`는 `PairSshData`이고 필드는 `direction`(`"forward"` | `"reverse"`), `peer`(이 장비가 쓴 `TrustPeer`, §6.11의 통일 pin 객체), `created`, `remote`(`name`, `role`, `created`), 역방향에서만 `next_command`(결정 22가 안내하는 원격 명령 문자열), `identity_created`(결정 18), `ssh_proxied`, `verified`, 그리고 확인이 실패했거나 건너뛰었을 때만 `verify_error`(`code`, `message`, `details`)다. 확인 dial이 실패해도 pin이 섰으면 exit 0이고 `verified: false`가 그 사실을 담는다(ADR-0024 결정 10이 따른 "남은 일은 데이터" 선례). 오류는 exit 255와 오류 envelope이다. stdout에는 envelope 외에 아무것도 나가지 않는다. ssh의 stderr는 stderr로만 간다.

18. 이 장비에 identity가 없으면 부트스트랩은 플래그 없는 `qsh init`과 같은 `Ops::identity_init`을 먼저 부른다(멱등). 사람 모드는 stderr 한 줄로 알리고 `data.identity_created`가 같은 사실을 담는다. "바로 동작"을 위해서다. 원격 identity는 결정 10대로 만들지 않는다.

19. 키 재료는 어디에도 남기지 않는다. qsh는 SSH 개인키, 암호, agent 소켓을 읽지도 넘기지도 않는다. 인증은 전부 ssh 프로세스 안에서 일어난다. 부트스트랩 스트림에 실리는 것은 공개값인 fingerprint와 이름, role, 포트뿐이고, qsh 개인키(`device.key`나 key store)는 어느 방향으로도 실리지 않는다(ADR-0013 결과 절의 "개인키는 어느 명령에도 인자로 안 오른다"). tracing 로그에는 단계와 결과 코드만 남기고, 원격 rc 출력(결정 11)과 ssh stderr는 로그로 복사하지 않는다. audit 기록은 결정 12의 구조 필드뿐이다.

### 다른 결정과의 관계

20. 신뢰의 성격. 이 경로는 TOFU가 아니다. 원격 fingerprint는 관측해서 믿는 값이 아니라 ssh가 host key로 인증한 채널 위에서 원격 계정 자신이 보고한 값이고, 원격 pin도 ssh 사용자 인증을 통과한 쪽만 쓸 수 있다. ADR-0013 결정 6이 허용한 "인증된 대역 외 채널"이 바로 ssh이고, ADR-0017 결정 5와 ADR-0024 결정 6이 닫은 "관측한 fingerprint를 확인 없이 pin"하는 경로는 여전히 없다. 다만 qsh 신뢰의 강도는 그 ssh 접속의 host 인증 강도와 같다. 사용자의 ssh 설정이 처음 보는 host key를 받아들이면(`StrictHostKeyChecking=accept-new`, 또는 프롬프트에서 `yes`) 그 순간의 TOFU를 qsh가 그대로 물려받는다. qsh는 사용자의 `StrictHostKeyChecking`을 덮어쓰지 않는다. 덮어쓰면 "설정을 그대로" 쓴다는 요구와 어긋나고, 이 위험은 qsh가 새로 만든 것이 아니라 사용자가 ssh에 이미 받아들인 것이다. 이 사실은 threat model 잔여 위험으로 적는다.

21. pin 방향과 role. pin에는 방향 축이 없다(ADR-0017 결정 5, ADR-0030 기각). 그래서 이 장비가 원격을 pin하면 원격이 이 장비로 들어올 때의 인증도 통과한다. 이 장비 쪽 pin을 `role = "none"`으로 쓰는 이유가 이것이다(역방향의 `reverse`도 셸 권한이 없는 role이라 같은 이유로 안전하다). ADR-0045에서 `none` pin은 `acl.toml`만으로 판정하므로, 이 장비가 `qsh serve`를 띄우고 있어도 원격은 `acl.toml` 행 없이 아무것도 할 수 없다(default-deny). 원격 쪽 pin의 `full`은 근거 절 셋째 항목대로 ssh 로그인이 이미 준 권한을 넘지 않는다. 원격이 `acl.toml`을 읽을 수 없으면 role과 무관하게 모든 요청이 거부되는 ADR-0045의 fail closed와, 자원 생성 전 단일 choke point 인가는 그대로다. 새 pin의 role은 재시작 없이 효력을 가진다. ADR-0045 결정이 role을 판정마다 `trust.toml`에서 다시 읽기 때문이다.

22. 역방향 route. 정방향과 역방향은 같은 기능을 갖는다(PRD §4). 부트스트랩도 두 구도를 다 연다.
   - 정방향(기본): 결정 1~21 그대로다. 자동 발동은 reverse 등록이 있는 이름에서 일어나지 않는다(결정 2). 그 이름은 이미 닿는 경로가 있기 때문이다.
   - 역방향: `qsh pair ssh <dest> --reverse --to <이 장비의 주소>`. 원격(target)이 이 장비(listener)로 dial하는 구도다. 원격 쪽 pin은 이 장비를 `--to` 주소와 함께 role `full`로 쓴다(commit의 `address`, 결정 11·12). 주소를 담은 pin이라 ADR-0045 결정 8의 일반 기본값은 `none`이지만, controller가 중계하는 요청을 target이 이 장비의 principal로 인가하므로 `host --to`의 listener pin과 같은 예외로 `full`을 쓴다(ADR-0045 결정 8의 `qsh setup` 기본값 문단). 원격 pin의 role은 `--role`이 덮는다. 이 장비 쪽 pin은 원격을 주소 없이 role `reverse`로 쓴다(ADR-0045 결정 8의 `listener`가 target pin에 쓰는 값과 같다). target이 `host.reverse` 등록만 할 수 있고 이 장비에서 셸은 얻지 못한다. 이 role은 `--role`로 바꾸지 않고(결정 1) 부트스트랩 뒤 `qsh trust set-role`로 바꾼다.
   - 역방향 부트스트랩도 원격에서 아무것도 띄우지 않고 `[serve].to`를 쓰지 않는다. 결과가 `data.next_command`와 사람 모드 stderr 한 줄로 원격에서 실행할 `qsh serve --to <이 장비를 pin한 이름>`(또는 `qsh service install`)을 안내한다. 원격 hello가 `serve_listening: false`를 내는 것이 정상이고 `verified`는 `false`이고 `verify_error`는 싣지 않는다(건너뛴 것이 아니라 이 구도에서 해당이 없다). 원격이 등록하면 `qsh hosts`에 live로 오른다.
   - ssh가 원격에 닿아야 하는 것은 정방향과 같다. NAT 뒤 target이면 ssh의 ProxyJump 같은 경로로 한 번만 닿으면 되고, 그 뒤로는 target이 dial하므로 ssh 경로가 필요 없다. 이 장비가 NAT 뒤라면 `--to`의 주소가 target에서 닿는 주소여야 하고, 맞는지는 이 ADR이 확인하지 않는다(`qsh listen` 쪽 doctor와 `qsh hosts`의 live 등록이 확인 수단이다).
   - 자동 발동은 역방향을 고르지 않는다. 어느 쪽이 dial할지는 이름만으로 알 수 없기 때문이다.

23. ADR-0026과의 관계. `qsh init --import-ssh-key`와 `qsh trust ssh-preview`는 그대로 둔다. 같은 키로 두 시스템을 묶고 싶은 사용자와 `authorized_keys` 이행을 미리 보고 싶은 사용자가 여전히 쓴다. 다만 ADR-0026이 다룬 동기, 곧 ssh 쪽에 이미 있는 것으로 qsh 신뢰를 빨리 세우는 일은 이 ADR이 키 재료를 옮기지 않고 해결한다. ADR-0026 결정 7이 미룬 암호 걸린 키와 ssh-agent는 이 경로에서 ssh가 처리하므로 qsh에 서명 seam을 낼 이유가 사라진다. ADR-0026 결정 7의 별도 결정은 열지 않는다.

24. ADR-0015·ADR-0016 기각과의 관계. 두 ADR의 동기는 장비가 여럿일 때 신뢰를 손으로 맞추는 부담이었다. 이미 ssh로 닿는 장비는 이 ADR로 명령 한 번에 양쪽 pin이 서므로 listener 상환 창구(ADR-0015)도, CA 키를 복제하지 않는 CSR 서명(ADR-0016)도 필요가 작다. 두 ADR의 기각 사유가 이 ADR을 가리킨다. ssh로 닿지 않는 장비는 초대 코드(ADR-0002)와 인증서 파일 교환(ADR-0013)을 그대로 쓴다.

25. Windows client(ADR-0035). Windows 10 1809부터 기본 탑재된 OpenSSH client(`ssh.exe`, 7.7 이상)는 `-G`와 결정 9의 옵션을 모두 받고, OpenSSH Authentication Agent 서비스와 `%USERPROFILE%\.ssh\config`를 쓴다. 1809는 ADR-0035 결정 7이 요구하는 최소 콘솔 버전과 같다. 그래서 `qsh pair ssh`와 결정 2의 자동 발동은 Windows client에서도 연다. ssh 자식이 도는 동안 콘솔은 raw 모드가 아니고(ADR-0035 결정 5의 guard는 부트스트랩 뒤에 만든다), `ssh.exe`는 암호를 콘솔에서 직접 읽는다. `ssh.exe`가 `PATH`에 없으면 결정 14의 `ssh_not_found`이고 message는 Windows 선택적 기능 "OpenSSH Client"를 적는다. 응답자 쪽 Windows는 ADR-0035 결정 25대로 다른 OS와 같이 연다(결정 10, 14. 착지는 M20). ADR-0035 결정 1의 명령 목록은 이미 `qsh pair ssh [--reverse]`와 `qsh pair ssh-respond`를 싣고 있다.

26. 하지 않는 일. 원격에 qsh를 설치하거나 `qsh serve`를 띄우거나 서비스 유닛을 등록하지 않는다. `hosts.toml`, `config.toml`, `acl.toml`을 어느 쪽에서도 쓰지 않는다(ADR-0017 결정 1, ADR-0014 결정 6). ssh `User`를 qsh 어디에도 저장하지 않는다. `user@`는 지금처럼 serve 계정 단언이고(`docs/CLI.md` §7), 원격 pin이 서는 계정과 serve 계정이 다르면 결정 13의 신원 불일치로 드러난다. 부트스트랩 연결로 세션 데이터를 나르지 않는다. ssh 연결은 pin 교환이 끝나면 닫는다.

## 근거

- 자동 발동을 기본으로 두는 이유. 요구는 "바로 qsh가 동작"이고 mosh가 증명한 사용 모양도 `mosh host` 한 줄이다. 명시 명령만 두면 사용자는 `qsh pair ssh box`와 `qsh box`를 외워야 하고, 처음 쓰는 사람은 `HOST_NOT_FOUND`를 먼저 만난다. 자동 발동의 위험은 둘이다. 오타가 ssh 시도로 이어지는 것과, ssh가 불린다는 사실을 모르는 것이다. 앞의 것은 ssh가 실패하고 아무것도 쓰지 않으므로 오타가 `HOST_NOT_FOUND` 대신 ssh 오류로 바뀔 뿐이고, 뒤의 것은 결정 2의 사전 고지 한 줄과 `[ssh].bootstrap = "off"`로 막는다. 기계 표면에서 발동하지 않는 것은 `docs/CLI.md` §2.1의 "machine mode는 프롬프트를 열지 않는다"와, 에이전트가 의도하지 않은 원격 쓰기를 부작용으로 만들지 않게 하려는 것이다.
- ssh를 부르고 설정을 파싱하지 않는 이유. `ssh_config`는 `Match exec`, `Include`, `CanonicalizeHostname`, 토큰 확장, 첫 값 우선 규칙을 갖고, 버전마다 키가 는다. 같은 해석을 qsh가 다시 구현하면 사용자 설정과 어긋나는 순간이 반드시 생긴다. `ssh -G`는 ssh 자신이 평가한 결과를 내므로 "그대로 하위호환"에 가장 가깝다. 인증도 같다. agent, 암호 걸린 키, FIDO 키, 인증서, GSSAPI, 2FA를 qsh가 하나도 몰라도 된다.
- 원격 role을 `full`로 두는 이유. 응답자는 ssh로 그 원격 계정에 로그인한 사용자가 띄운다. 그 사용자는 이미 그 계정으로 셸을 갖고, `trust.toml`과 `acl.toml`을 직접 고칠 수 있다. 이 ADR이 만드는 pin은 그 사용자가 이미 가진 권한을 QUIC 경로로 옮길 뿐 새 권한을 만들지 않는다. 그보다 좁은 기본값은 첫 `qsh box`를 `PERMISSION_DENIED`로 끝나게 해서 "바로 동작"을 깬다. 좁히고 싶은 사람은 `--role`을 준다. 결정 13이 확인하는 신원 일치(serve identity = 응답자 identity)는 그 serve가 같은 config 디렉터리, 사실상 같은 계정이라는 뜻이므로 이 논리가 다른 계정으로 새지 않는다.
- 두 단계 쓰기와 충돌 시 무동작. 두 장비의 파일을 원자적으로 함께 바꿀 방법은 없다. 충돌 검사를 쓰기 전에 끝내고, 원격을 먼저 쓰고, 원격 쓰기를 멱등하게 두면 남는 반쪽 상태는 "원격 pin만 있음" 하나이고 다시 실행하면 수렴한다. 덮어쓰기를 허용하지 않는 것은 `TrustStore::add_peer`가 이미 지키는 규율(재바인딩은 의도된 조작)을 그대로 따른 것이다.
- 설치·기동을 대신하지 않는 이유. mosh는 접속마다 서버를 띄우지만 qsh의 세션은 장기 실행 serve가 소유한다(ADR-0003). ssh 세션 안에서 띄운 serve는 ssh가 닫힐 때 같이 죽거나, 살아남아도 서비스 매니저 밖에서 떠돌아 `qsh service`와 doctor의 진단(`service_not_registered`, `systemd_linger_disabled`)을 우회한다. 원격 설치는 플랫폼·아키텍처 판별과 실행 파일 신뢰를 끌고 온다. 진단 한 줄과 정확한 다음 명령이 이 비용보다 싸다.
- 줄 단위 텍스트 프레이밍. 비대화형 ssh 세션에서도 rc 파일이 stdout에 무언가를 찍는 배치가 흔하다. 바이너리 길이 접두 프레임은 그 한 줄에 깨지고, 접두 태그 줄은 건너뛸 수 있다. mosh의 `MOSH CONNECT` 줄과 같은 해법이다.

## 대안과 기각 사유

- **명시 명령만 둔다(`qsh pair ssh`만, 자동 발동 없음).** 기각. 요구의 "바로 동작"을 채우지 못한다. 대신 명시 명령은 기계 소비자와 `--role`·`--as` 같은 선택이 필요한 사람을 위해 같이 둔다.
- **`qsh trust ssh <dest>`로 이름 짓는다.** 기각. ADR-0012 결정 3이 `trust`를 기존 pin 조작에, `pair`를 새 신뢰 항목 생성에 나눴다. 이 명령은 뒤의 것이다. `trust ssh-preview`는 아무것도 쓰지 않는 미리보기라 `trust`에 남는다.
- **`~/.ssh/config`를 qsh가 직접 파싱한다.** 기각. 근거 절 둘째 항목. 파서가 하나 늘고 fuzz 표면도 는다.
- **ssh를 거치지 않고 SSH 키로 qsh가 직접 인증한다(SSH 공개키를 principal로, 또는 agent 서명 위임).** 기각. ADR-0026 결정 5·7과 그 대안 절이 이미 기각한 두 갈래다. 새 principal 축과 서명 seam을 내야 하고, ssh 설정(ProxyJump, known_hosts)은 여전히 쓰지 못한다.
- **원격에 qsh를 설치하거나 `qsh serve`를 띄운다.** 기각. 근거 절 다섯째 항목. 필요가 확인되면 P2 후보로 새 ADR을 연다.
- **부트스트랩 연결을 세션이나 터널 transport로 계속 쓴다(UDP가 막히면 ssh로 폴백).** 기각. ADR-0043이 TCP 경로를 범위 밖으로 정했다. UDP가 막힌 망에서는 ssh를 직접 쓰면 된다.
- **qsh가 `StrictHostKeyChecking=yes`를 강제한다.** 기각. 결정 20. 사용자 설정을 덮어쓰면 `accept-new`를 쓰는 배치에서 처음 접속이 ssh에서는 되고 qsh 부트스트랩에서만 실패한다. 위험은 잔여 위험으로 적는다.
- **원격 pin role 기본값을 `exec`나 role 없음으로 둔다.** 기각. 근거 절 셋째 항목. ssh 로그인이 이미 준 권한보다 좁은 기본값은 보안을 늘리지 않고 첫 접속만 실패하게 한다.
- **pin 불일치 시 `--replace`로 덮어쓰는 플래그를 둔다.** 기각. `trust remove` 뒤 다시 부르는 두 줄이 같은 일을 하고, 플래그 하나로 재바인딩을 쉽게 만들면 불일치를 확인 없이 넘기는 습관이 생긴다.
- **JSON 대신 `.proto` 프레임을 stdio에 싣는다.** 기각. rc 출력 문제(근거 절 마지막 항목). 메시지 셋에 필드 몇 개라 protobuf의 이점이 작다.

## 결과

- **계약 문서.** `docs/CLI.md` §2.4에 `pair.ssh`를 더하고 `qsh pair ssh-respond`가 operation이 아니라는 문장을 적는다. §2.5 "인가 불요" 행에 `pair.ssh`. §6.11 pairing 절에 `qsh pair ssh`(결정 1, 7, 8, 12~18)와 `PairSshData`, 오류 표(결정 14·15). §6.1의 `HOST_NOT_FOUND` 문단에 사람 모드 message의 다음 명령. §7에 자동 발동(결정 2·16)과 `[ssh]` 설정. §6.12의 `config.toml` 키 목록에 `[ssh].bootstrap`·`[ssh].program`·`[ssh].remote_qsh`(doctor `config_unknown_key`의 알려진 키 목록도 같이). ADR-0029가 개정하는 `qsh cp` 절에 결정 2의 발동. `docs/design/protocol.md`에 부트스트랩 스트림 절(결정 11, 버전 규칙)과 §13 fuzz 표. README First run에 `qsh box` 한 줄로 시작하는 경로를 기존 경로 앞에 둔다.
- **위협 모델.** `docs/design/threat-model.md` §3에 진입점 두 행. "`qsh pair ssh`의 ssh 자식과 부트스트랩 스트림"(로컬 사용자 + ssh로 인증된 원격 계정의 출력, 신뢰할 수 없는 입력으로 파싱), "`qsh pair ssh-respond`의 stdin"(ssh로 그 계정에 인증된 주체). §4에 행을 더한다.
  - A: 처음 보는 host key를 받아들인 ssh 접속 위의 중간자가 자기 fingerprint를 심는다 → 결정 20(ssh host 인증 강도를 승계, qsh 자체 TOFU 없음), 잔여 위험.
  - B: ssh로 그 계정에 로그인할 수 있는 누구나 `full` pin을 만든다 → 결정 8, 근거 셋째 항목(그 주체는 이미 같은 권한을 가진다), `pair.ssh_respond` audit 기록.
  - B: 이 장비 쪽 pin이 방향 없이 원격의 inbound 인증까지 통과시킨다 → 결정 21(이 장비 쪽 pin은 role `none`, 역방향은 `reverse`. 어느 쪽도 셸 권한이 없다).
  - B: 기존 role 없는 pin을 부트스트랩이 `full`로 넓힌다 → 결정 12.
  - D: rc 출력이나 ssh stderr에 섞인 비밀이 qsh 로그에 남는다 → 결정 11·19.
  - E: 조작된 응답자 출력이 클라이언트 파서를 깨거나 다른 이름·fingerprint를 심는다 → 결정 11(상한, fuzz 타깃), 결정 12·15(덮어쓰기 없음).
  - E: `<dest>`나 `--remote-qsh`로 ssh 옵션이나 원격 셸 명령을 주입한다 → 결정 7(`-` 시작 거부, `--` 구분), 결정 9(고정 인자, 작은따옴표, 사용자 문자열은 메시지 안).
  - §7 잔여 위험에 둘을 적는다. qsh 신뢰는 그 ssh 접속의 host 인증 강도를 넘지 않는다(결정 20). ssh 접근을 거둬도(`authorized_keys`에서 키 삭제, 계정 잠금) 이미 선 qsh pin은 남는다. 신뢰 승계는 한 번이고 이후로는 전파되지 않는다. 거두려면 원격에서 `qsh trust remove`를 하고, ADR-0031(축소판)이 그 순간 열린 연결까지 끊는다.
- **코드.** 부트스트랩 절차, `ssh -G` 읽기, ssh 자식 관리, 응답자, UDP bind 확인은 `qsh-core`(새 모듈 `ssh_bootstrap`)에 둔다. 메시지 타입과 줄 파서는 `qsh-proto`. `qsh-cli`는 clap 정의(`pair ssh`, 숨김 `pair ssh-respond`), 자동 발동 분기, 두 렌더러만 갖는다. 새 모듈이 `xtask arch`의 경로 범위 금지에 들어가야 하는지는 구현 커밋이 판단하고, 들어가면 `xtask/src/arch.rs`를 같은 커밋에서 고친다. `PairSshData`는 `CLI_V1_SCHEMA_COMMANDS`와 `cli_v1_data_schema` arm에 등록하고(`crates/qsh-core/tests/it/schema_commands_registry.rs`), 성공 fixture와 대표 오류 fixture(`pin_conflict`, `remote_qsh_missing`)를 새로 추가해 `REQUIRED_FIXTURES`에 등재한다. 기존 fixture는 건드리지 않는다. `qsh-pair-ssh.1`을 `cargo xtask man`으로 만든다(`checked_in_man_pages_match_the_generator`). wire(`.proto`)와 `capabilities.json`은 바뀌지 않는다.
- **fuzz.** 새 타깃 `parse_ssh_bootstrap_line` 하나가 는다. 개수 문장은 `fuzz/README.md`와 `docs/design/protocol.md` §13, threat model §3 끝 문장에서 착륙 시점의 실제 타깃 수로 맞춘다.
- **핀 테스트(이름은 구현 때 확정하되 성질은 이대로).** 실제 sshd 없이 `PATH` 앞에 둔 가짜 `ssh`가 인자를 기록하고 다른 `QSH_CONFIG_DIR`로 로컬 `qsh pair ssh-respond`를 실행하는 testkit 하네스로 돈다.
  - `ssh_bootstrap_pins_both_sides_and_connects`: 이 장비 pin은 ssh 별칭 이름과 `hostname:4433`, role `none`. 원격 pin은 address 빈 값, role `full`. 이어진 handshake 성공.
  - `ssh_bootstrap_role_flag_sets_the_remote_role`, `ssh_bootstrap_local_pin_has_explicit_role_none`
  - `ssh_bootstrap_does_not_widen_an_existing_roleless_pin`: 원격에 role 없는 같은 fingerprint pin이 있으면 `exists`이고 role이 그대로다.
  - `ssh_bootstrap_never_overwrites_a_pin_with_a_different_fingerprint`: 로컬·원격 각각, 양쪽 `trust.toml` 바이트 불변.
  - `ssh_bootstrap_writes_nothing_when_the_remote_cannot_respond`: 127, 종료 코드 2, `not_initialized`, 원격 기본 셸 `cmd.exe`의 종료 코드 9009(가짜 ssh가 9009를 돌려줌, Windows 한정), 버전 교집합 없음, commit 타임아웃 각각에서 양쪽 무변경.
  - `ssh_bootstrap_a_remote_cmd_exe_exit_1_with_its_text_is_a_missing_qsh_and_writes_nothing`: 가짜 ssh가 cmd.exe 문구를 stderr에 쓰고 1로 끝나면 `remote_qsh_missing`, 양쪽 무변경, 그 문구가 qsh의 stderr에 그대로 보이고 envelope에는 없다. `ssh_bootstrap_a_remote_powershell_exit_1_stays_a_failed_command`는 같은 1에 PowerShell 문구면 `remote_command_failed`다. 판정 함수는 `qsh-core`의 `exit_1_with_the_cmd_exe_text_is_a_missing_qsh`·`a_custom_remote_qsh_is_matched_by_its_value_or_basename`·`exit_1_with_powershell_or_unrelated_text_stays_a_failed_command`·`the_cmd_exe_text_changes_only_exit_1_and_only_before_the_hello`가 영어·한국어·ANSI·사용자 지정 경로를 고정한다.
  - `ssh_bootstrap_reverse_pins_listener_full_with_address_and_target_reverse_without`: `--reverse --to`에서 원격 pin은 주소와 `full`, 이 장비 pin은 주소 없이 `reverse`, 확인 dial 없이 `verified: false`, `data.next_command`. `--reverse`와 `--to`의 한쪽만, 또는 `--address`와의 조합은 ssh를 부르기 전에 `INVALID_ARGUMENT`.
  - `ssh_bootstrap_reverse_local_reverse_role_leaves_an_audit_record_and_needs_it`: 이 장비 쪽 `reverse` pin의 audit이 없으면 그 pin도 없다.
  - `ssh_bootstrap_reports_the_actual_remote_role_when_an_existing_pin_differs`: 기존 `none` pin이면 role은 그대로이고 안내 줄과 `data.remote.role`이 실제 값을 말한다.
  - `ssh_bootstrap_remote_qsh_quoting_is_bare_for_safe_chars_and_single_quoted_otherwise`
  - `ssh_bootstrap_ssh_argv_is_fixed`: 결정 9의 인자 집합과 `--` 위치, `BatchMode`가 machine mode와 비터미널 stdin에서만 붙음.
  - `ssh_bootstrap_rejects_a_dest_that_looks_like_an_option`: ssh를 한 번도 부르지 않는다.
  - `ssh_bootstrap_skips_untagged_stdout_and_never_logs_it`: rc 출력 줄이 있어도 성공하고, 그 바이트가 stdout·stderr·로그 어디에도 없다. 64 KiB 초과면 `bootstrap_protocol`.
  - `ssh_bootstrap_is_never_implicit_in_machine_mode`: `qsh cp --json`이 가짜 ssh를 부르지 않는다.
  - `ssh_bootstrap_is_not_triggered_for_hosts_toml_or_reverse_names`, `ssh_bootstrap_off_in_config_is_respected`
  - `ssh_bootstrap_reports_identity_mismatch_when_serve_runs_another_identity`
  - `ssh_respond_refuses_to_pin_when_audit_is_unwritable`, `ssh_respond_audit_record_has_only_structural_fields`(`record_has_only_structural_fields`와 같은 형식)
  - `ssh_bootstrap_envelope_is_the_only_stdout_line`(`--json`)
  - 사람 캠페인 하나: 실제 OpenSSH(ProxyJump, ssh-agent, 암호 걸린 키, Windows `ssh.exe`) 위에서 처음 `qsh box`부터 셸 프롬프트까지. 문서는 `docs/campaigns/`에 구현 마지막 스텝 전에 고정한다.
- **ADR-0035.** 명령 목록과 Windows 응답자 문장(결정 25)은 ADR-0035가 이미 이 ADR에 맞춰 적혀 있다. 대화형 형태의 자동 발동은 Windows client에서도 같이 연다(결정 25). 이 ADR이 M16이고 Windows client가 M19, Windows 응답자가 M20이므로, Windows 쪽 동작은 각 마일스톤의 구현에서 반영한다.
- **크기.** 2.6~4.0ew(2026-10-13 결정 22의 `--reverse` 0.3~0.5 포함). ADR과 계약 문서 0.2 + `ssh -G` 읽기와 ssh 자식 관리(인자, 종료 코드 사상, 타임아웃, Unix와 Windows) 0.3~0.5 + 부트스트랩 스트림 타입·줄 파서·fuzz 타깃·protocol.md 절 0.3~0.4 + 응답자(identity 읽기, UDP bind 확인, 잠금 아래 pin, audit, 원격 셸별 종료 코드 사상) 0.3~0.5 + `pair.ssh` op(두 단계 쓰기, 확인 dial, 오류 사상), 렌더러 두 벌, fixture·schema 등록·man 0.5~0.7 + 자동 발동 분기와 `[ssh]` 설정 0.2~0.4 + 가짜 ssh 하네스와 핀 테스트 0.4~0.6 + 캠페인과 README 0.1~0.2. ADR-0045의 role 필드와 handshake 시점 읽기는 ADR-0045 몫이라 여기 넣지 않았다.
