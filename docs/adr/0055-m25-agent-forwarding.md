# ADR-0055: M25의 범위. `-A`를 주면 host가 세션이나 exec마다 소유자 전용 agent 소켓(Windows는 named pipe)을 만들어 `SSH_AUTH_SOCK`으로 알리고, 그 소켓에 들어온 연결마다 capability `agent.v1`의 새 스트림 `AGENT`를 client 쪽으로 연다. 스트림은 ssh-agent 프로토콜 바이트를 그대로 싣고, client는 목록 조회와 서명만 로컬 agent에 넘긴다. host 쪽 인가는 새 action `forward.agent`다

날짜: 2026-11-09
상태: 승인됨

개정 관계: ADR-0050 결정 5의 M25를 구체화한다. 다음을 개정한다.
- ADR-0045 결정 2의 role 표와 PRD §9의 action 어휘. 새 action `forward.agent`를 더해 `Action::ALL`이 13종이 되고, `full`과 `exec`가 이 action을 준다(결정 16, Dave가 정할 것 2).
- ADR-0051 결정 7의 옵션 표에서 `-A` 행("M25 전까지 `UNSUPPORTED`")을 바꾸고 `-a`와 `-o ForwardAgent`를 더한다(결정 18).
- `docs/design/protocol.md` §4(capability 하나), §7(스트림 표 한 행), §9(`StreamKind` 값 하나, 요청 필드 셋, 응답 필드 셋, enum 하나), 새 §20(agent forwarding).
- `docs/CLI.md` §2.5(`forward.agent` 행), §6.8(`qsh exec -A`), §6.17(doctor 코드 둘), §6.23(키 하나), §7(대화형 form과 `qsh attach`), §7.2(옵션 표).
- host가 고정하는 환경 변수 목록(`crates/qsh-core/src/pty/env_policy.rs`의 `PINNED_POSIX`·`PINNED_WINDOWS`, `docs/CLI.md` §7 "전달되는 환경변수"). `SSH_AUTH_SOCK`이 여기에 든다(결정 6).

개정하지 않는 것: 부트스트랩 ssh의 고정 옵션 `-T -a -x -o ClearAllForwardings=yes`(ADR-0044 결정 9, `crates/qsh-core/src/ssh_bootstrap/ssh.rs`의 `responder_args_with`), qsh가 `ssh_config`를 직접 파싱하지 않고 `ssh -G`는 부트스트랩에서만 부른다는 것(ADR-0051 결정 8, Dave가 정할 것 5), SSH 키나 agent의 키를 qsh identity로 가져오지 않는다는 것(ADR-0026, `docs/ROADMAP.md` §5.3의 "암호화된 SSH 키, ssh-agent" 행), TLS 검증 경로(`docs/design/protocol.md` §3), session resume 절차(§10), writer lease 규칙(§9 `SessionAttach`), 항상-deny 게이트의 범위(`forward.socks` 하나, ADR-0019 결정 6).

## 맥락

ADR-0050 결정 5는 M25를 "`-A`. 원격에서 로컬 ssh-agent(unix socket, Windows named pipe)를 쓰게 하는 스트림. 기본 꺼짐, 역할로 허용"으로 정했고 크기를 2ew로 잡았다. 결정 2는 모든 P2 마일스톤에 세 원칙을 지운다. 설정 파일 없이 동작하고, 대화형 질문과 같은 답의 플래그를 두고, `alias ssh=qsh`의 흔한 쓰임새가 같은 뜻으로 동작한다. 원격 호스트에서 `git push`나 다음 호스트로의 `ssh`를 로컬 키로 하는 것이 그 흔한 쓰임새다.

### 지금 있는 것

- `-A`는 루트 ssh 형식에서 파싱되지만 거부된다. `crates/qsh-cli/src/cli.rs`의 `agent_forwarding` 플래그가 `SshFlags.agent_forwarding`으로 가고, `crates/qsh-core/src/ssh_bootstrap/options.rs`의 `SshOptions::from_flags`가 "ssh option -A (agent forwarding) is not supported before M25"로 `UNSUPPORTED`를 낸다. `docs/CLI.md` §7.2의 옵션 표와 ADR-0051 결정 7이 같은 내용을 적는다. `-a`는 없다.
- 부트스트랩 ssh는 응답자를 부를 때 `-T -a -x -o ClearAllForwardings=yes`를 사용자 옵션보다 앞에 둔다(ADR-0044 결정 9). 그래서 지금 `-o ForwardAgent=yes`를 줘도 부트스트랩 ssh 세션에 agent가 넘어가지 않는다. M25는 이것을 바꾸지 않는다. qsh의 agent forwarding은 QUIC 연결 위에서만 일어난다.
- `~/.ssh/config`는 pin이 없는 이름의 부트스트랩에서 `ssh -G` 한 번에만 쓰인다(ADR-0051 결정 8). pin이 있는 이름에는 ssh를 부르지 않는다.
- host가 먼저 여는 스트림의 선례는 `TCP_ACCEPTED`다(`docs/design/protocol.md` §7). `-R`의 host가 accept마다 `StreamHeader{TCP_ACCEPTED, forward_id}`를 요청자 쪽으로 열고, 요청자는 연결마다 하나인 dispatcher(`crates/qsh-core/src/tunnel/remote.rs`의 `RemoteForwardAcceptor`, `dispatch_remote_forwards`)가 `forward_id`로 표를 찾아 맞을 때만 로컬 목적지에 dial한다. 그 dispatcher는 지금 `TCP_ACCEPTED`가 아닌 스트림을 `BAD_HEADER`로 reset한다. 역방향 route에서는 `qsh listen` 데몬이 그 스트림을 받고, `forward_id → conduit` 등록표와 claim seat(§11-3)이 스트림을 그것을 연 CLI 프로세스에만 건넨다.
- 세션은 연결보다 오래 산다(PRD §4 "연결과 세션의 분리"). 세션을 연 연결이 끊긴 뒤 다른 연결, 다른 장비에서 다시 붙을 수 있고, 쓰기 권한은 writer lease 하나가 정한다(PRD §8). SSH의 agent forwarding은 연결 하나에 묶인 소켓이라 이 모델에 그대로 옮길 수 없다.
- host는 자식 프로세스의 환경을 비우고 다시 짠다(`crates/qsh-core/src/pty/posix.rs`의 `build_env`). serve 프로세스의 환경에서는 `LANG`·`LANGUAGE`·`TZ`·`LC_*`만 넘어가고(`env_policy::PASSTHROUGH`), client가 보낸 `env`는 덮어쓸 수 있으며, `HOME`·`USER`·`LOGNAME`·`SHELL`·`PATH`는 host가 고정한다. `SSH_AUTH_SOCK`은 지금 serve 쪽에서는 넘어가지 않지만 client의 `env`로는 들어올 수 있다.
- runtime 디렉터리(`$XDG_RUNTIME_DIR/qsh`, 없으면 state 아래 `run/`, 0700)는 원격 파일 op가 닿지 못하는 보호 집합에 든다(`docs/design/architecture.md` §7). Windows의 소유자 전용 DACL은 `crates/qsh-core/src/fsutil/dacl.rs` 하나가 만들고, localctl named pipe는 `PIPE_REJECT_REMOTE_CLIENTS`와 보호된 DACL을 쓴다(threat model §3의 localctl named pipe 행).
- action 어휘는 12종이다(PRD §9, `qsh_core::acl::Action::ALL`). `acl.toml` 행은 `session.*`, `forward.*` 같은 trailing `.*` 계열 와일드카드를 받는다(`crates/qsh-core/src/acl/load.rs`).

### ssh-agent 프로토콜(개념만)

요청과 응답은 4바이트 big-endian 길이, 1바이트 종류, 내용으로 된 메시지다. 한 연결 위에서 client가 요청 하나를 보내고 응답 하나를 기다린다. 쓰는 종류는 목록 조회(`REQUEST_IDENTITIES` 11 → `IDENTITIES_ANSWER` 12), 서명(`SIGN_REQUEST` 13 → `SIGN_RESPONSE` 14), 키 추가(17, 25), 삭제(18, 19), 스마트카드(20, 21, 26), 잠금과 풀기(22, 23), 확장(27)이고, 실패는 `FAILURE` 5다. OpenSSH의 `ssh-agent`는 메시지 길이를 256 KiB(`AGENT_MAX_LEN`)로 묶는다. OpenSSH 8.9부터 `ssh`는 agent에 확장 `session-bind@openssh.com`으로 자기가 연 SSH 세션의 host key를 알려 주고, `ssh-add -h`로 목적지를 제한한 키는 그 정보로 어느 hop에서 쓰이는지 판단한다. SSH의 agent forwarding은 remote의 root가 그 소켓으로 로컬 키를 쓸 수 있다는 위험으로 잘 알려져 있고, OpenSSH의 대책은 기본 꺼짐(`ForwardAgent no`), `ssh-add -c`(서명마다 로컬에서 확인), `ssh-add -h`(목적지 제한)다.

## Dave가 정할 것

1. 세션의 agent 수명. 세션은 연결보다 오래 살고 다른 장비에서 다시 붙을 수 있다. (가) 세션마다 소켓 경로 하나를 세션 수명 동안 고정하고, 그 소켓의 뒤는 지금 writer lease를 쥔 attach가 `-A`를 줬을 때 그 attach의 연결이 받친다. 받칠 연결이 없으면 들어온 연결을 바로 닫는다(결정 9). (나) 세션을 연 연결이 살아 있는 동안만 소켓이 있고, resume 뒤에는 쓸 수 없다. (다) attach마다 새 소켓을 만든다. 추천은 (가). 셸의 `SSH_AUTH_SOCK`은 세션을 열 때 한 번 정해져서 경로가 바뀌면 (다)는 셸 안에서 쓸 수 없고, (나)는 qsh의 핵심인 이동과 resume 뒤에 agent가 사라진다. (가)는 tmux 위의 SSH에서 사람들이 손으로 하는 "소켓 경로 고정"을 구조로 준다. 비용은 다른 장비에서 `-A`로 붙으면 그 세션의 프로그램이 그 장비의 agent를 쓰게 된다는 점이고, 그것은 붙은 사람이 `-A`로 고른 일이다.
2. 누가 `forward.agent`를 받나. (가) `full`과 `exec`, (나) `full`만, (다) 어느 role도 주지 않고 `qsh trust allow <peer> forward.agent`로만 준다. 추천은 (가). agent 소켓은 세션이나 exec에 딸려서만 생기므로 셸이나 명령을 열 수 없는 role(`tunnel`, `read-only`, `reverse`, `none`)에는 쓸모가 없다. host가 이 판정으로 지키는 것은 자기 runtime 디렉터리에 소켓 하나를 만드는 일뿐이고, 같은 uid로 명령을 실행할 수 있는 peer에게 그것은 새 능력이 아니다. 위험을 지는 쪽은 agent를 넘기는 client이고, 그 동의는 `-A`다. (다)는 "pin 한 번이 곧 권한"인 ADR-0045의 모델을 깨고 ADR-0050 결정 2의 설정 없는 기본과 맞지 않는다.
3. agent 메시지 거르기. (가) client가 host에서 온 요청을 메시지 단위로 읽어 목록 조회(11)와 서명(13)만 로컬 agent에 넘기고, 나머지(키 추가·삭제, 스마트카드, 잠금·풀기, 확장 전부)는 로컬 agent에 닿지 않게 client가 `FAILURE`로 답한다. (나) OpenSSH처럼 바이트를 거르지 않고 잇는다. (다) (가)를 기본으로 두고 `[agent].filter = "off"`로 끌 수 있게 한다. 추천은 (가). remote의 root가 agent에 키를 심거나 지우거나 잠금 암호를 대입해 보는 길이 닫히고, 원격에서 흔히 하는 일(`ssh`, `git`, `ssh-add -l`, `ssh-keygen -Y sign`)은 11과 13으로 끝난다. 확장을 막으면 `session-bind@openssh.com`도 막혀 목적지 제한 키가 qsh 경로에서 쓰이지 않는데, 이것은 안전한 쪽의 실패다(결정 20). (다)는 설정 키가 하나 늘고 그 키를 켠 상태의 위협을 따로 적어야 한다.
4. 서명 확인. (가) M25에는 qsh 자체의 확인 프롬프트를 넣지 않는다. 확인이 필요한 사용자는 로컬에서 `ssh-add -c`로 키를 넣고, 그 확인은 로컬 agent가 하므로 qsh 경로에서도 그대로 뜬다. (나) client가 서명 요청마다 묻는다. 대화형 attach에서는 M23의 상태 줄 합성 자리에 띄우고 TTY가 아니면 거부한다. 추천은 (가). 확인은 agent가 하는 일이고 OpenSSH의 방식이 이미 qsh 경로를 지나 동작한다. (나)는 화면 동기화 렌더러 위에 입력을 가로채는 새 모드가 필요하고(추정 +0.5ew), 같은 화면 안의 셸이 그 프롬프트를 흉내 낼 수 있어 확인으로서 약하다.
5. `~/.ssh/config`의 `ForwardAgent`. (가) 읽지 않는다. `-A`, `-a`, `-o ForwardAgent`와 qsh 키 `[agent].forward`가 정하고, ssh 설정의 `ForwardAgent`가 qsh 경로에 걸리지 않는다는 것을 `docs/CLI.md` §7.2와 README에 적는다. (나) 명령줄과 키에 값이 없고 시스템 ssh가 있으면 명령마다 `ssh -G <dest>`를 한 번 돌려 `forwardagent`를 읽는다(ADR-0051 결정 8 개정). 추천은 (가). ADR-0051 결정 8은 `ssh -G`를 부트스트랩에서만 부르기로 정했고, (나)는 pin이 있는 모든 접속에 자식 프로세스 하나와 사용자의 `Match exec` 실행을 더한다. (가)가 어긋나는 방향은 "넘기지 않음"이라 안전한 쪽이다. 차이를 메우는 길로 `qsh config set agent.forward yes`가 있다.

## 결정

### 범위

1. 무엇을 하나.
   - `-A`(또는 같은 뜻의 설정)로 연 대화형 세션, `-t`로 연 명령 세션, PTY 없는 명령(`qsh host cmd`, `qsh exec`)의 프로그램이 host에서 `SSH_AUTH_SOCK`으로 이 장비의 ssh-agent를 쓴다. 정방향, 펀칭으로 선 정방향(ADR-0054), 역방향 route 모두에서 같다. host와 client는 Linux, macOS, Windows 어느 조합이든 같은 기능을 갖는다(결정 21).
   - `qsh attach`도 `-A`를 받는다. 그 세션이 소켓을 가지고 있으면 이 attach가 뒤를 받친다(결정 9).
   - 범위 밖: unix socket 일반 포워딩(OpenSSH의 `StreamLocalForward`, `-L /path`), qsh 자체의 서명 확인(Dave가 정할 것 4), agent 키로 qsh 연결을 인증하는 것(ADR-0026), X11 forwarding(ADR-0050 결정 6), `qsh cp`의 `-A`(원격에서 도는 프로그램이 없다. scp의 `-A`처럼 받지 않고 `UNSUPPORTED`로 이름을 대며 거부한다), 부트스트랩 ssh 세션으로 agent를 넘기는 것.

2. 층 배치.
   - `qsh-proto`: `StreamKind::AGENT`, 새 필드와 enum, 그리고 ssh-agent 메시지 머리 decoder `qsh_proto::agent`(길이와 종류만 읽는 sans-IO 상태 기계, 상한 검사, 결정 12의 허용 표). fuzz 표면이다.
   - `qsh-transport`: 바뀌지 않는다. 스트림은 지금의 `Connection::open_bi`·`accept_bi`다.
   - `qsh-core`: 새 모듈 `crates/qsh-core/src/agent/`. host 쪽(소켓·pipe 만들기, accept, 스트림 열기, 정리, 받치는 연결 표), client 쪽(로컬 agent 찾기와 연결, 메시지 거르기, channel 표), 플랫폼 반쪽 `agent/{unix,windows}.rs`. host 쪽 인가는 기존 choke point(`Authorizer::check`)다. client 쪽 dispatcher는 `RemoteForwardAcceptor`의 연결당 하나인 accept 루프를 넓혀 `AGENT` 스트림도 받는다. 같은 연결에 accept 루프를 둘 두면 서로의 스트림을 가로챈다(그 타입의 doc이 적은 이유).
   - `qsh-cli`: 플래그를 `Ops`에 넘기고 경고 줄을 렌더할 뿐이다. 소켓도 pipe도 열지 않는다(`xtask arch`가 이미 `qsh-cli/src`의 UDS·named pipe를 막는다).
   - `xtask arch`: 새 경로에는 `crates/qsh-core/src/`의 기존 금지(`quinn::`)가 그대로 걸린다. 새 금지 경로는 더하지 않는다.

### wire

3. capability `agent.v1`과 필드. 모든 빌드가 광고한다(상수 `CAP_AGENT_V1`, `LOCAL_CAPABILITIES`의 마지막 항목). 뜻은 이 peer가 host로서 아래 요청 필드를 처리해 `AGENT` 스트림을 열고, client로서 `AGENT` 스트림을 받는다는 것이다. 광고하지 않은 peer에게는 요청 필드를 세팅하지 않는다. 옛 host는 모르는 필드를 버리므로 확인 없이 보내면 client가 forwarding이 켜졌다고 착각한다(§16.4, ADR-0019 결정 4와 같은 규칙).
   ```proto
   enum StreamKind { ...; AGENT = 6; }            // host -> client, StreamHeader.ticket = agent_channel
   message SessionOpen     { ...; bytes agent_channel = 9; }
   message SessionAttach   { ...; bytes agent_channel = 7; }
   message ExecStart       { ...; bytes agent_channel = 6; }
   message SessionOpened   { ...; AgentGrant agent = 7; }
   message SessionAttached { ...; AgentGrant agent = 9; }
   message ExecStarted     { ...; AgentGrant agent = 3; }
   enum AgentGrant {
     AGENT_GRANT_UNSPECIFIED = 0;  // 요청하지 않음
     AGENT_GRANT_FORWARDED = 1;
     AGENT_GRANT_DENIED = 2;       // forward.agent 판정이 거부
     AGENT_GRANT_UNAVAILABLE = 3;  // host가 소켓을 만들 수 없음(디렉터리, 경로 길이, 꺼짐)
     AGENT_GRANT_NO_SOCKET = 4;    // attach한 세션이 agent 없이 열렸음
   }
   ```
   - `agent_channel`은 client가 CSPRNG로 만든 정확히 16바이트다. 비어 있으면 요청하지 않은 것이고, 길이가 다르면 `INVALID_ARGUMENT`다(ACL 전, audit 없음). client는 요청을 보내기 전에 그 값을 자기 channel 표에 올린다. `forward_id`처럼 host가 발급하는 값이면 응답보다 스트림이 먼저 오는 경주가 생기는데(`RemoteForwardAcceptor`의 doc), client가 먼저 정하면 그 경주가 없다.
   - 모르는 `AgentGrant` 값은 `UNSPECIFIED`로 읽는다.
   - 번호는 각 message의 다음 빈 번호이고 기존 번호는 건드리지 않는다. 새 control message는 없다.

4. 스트림 위의 바이트. `AGENT` 스트림은 `StreamHeader{AGENT, ticket = agent_channel}` 한 frame 뒤로 ssh-agent 프로토콜 바이트를 그대로 싣는다. qsh의 protobuf로 다시 싸지 않는다. agent 프로토콜이 이미 길이를 달고 오고, 터널 스트림이 raw bytes인 것과 같은 이유(§5의 터널 예외)다.
   - client는 host에서 온 바이트를 `qsh_proto::agent` decoder로 메시지 단위로 읽는다. 길이 0, 길이가 256 KiB(`AGENT_MESSAGE_MAX = 262144`, OpenSSH `AGENT_MAX_LEN`과 같다)를 넘는 것은 `BAD_HEADER`(`0x2001`)로 스트림을 reset하고 로컬 agent 연결을 닫는다. decoder는 선언된 길이로 버퍼를 미리 잡지 않는다(§5의 규율).
   - client는 요청 하나를 넘기고 로컬 agent의 응답 하나를 같은 decoder로 끊어 돌려준 뒤에야 다음 요청을 읽는다. agent 프로토콜이 순차 요청·응답이라 이것으로 충분하고, 한 스트림이 client 메모리에 쌓을 수 있는 것은 메시지 하나다.
   - host는 바이트를 해석하지 않고 로컬 소켓과 스트림을 잇는다. host는 이 데이터의 주인이 아니고, 거르는 일은 agent를 가진 쪽이 해야 의미가 있다(결정 12).
   - 정상 종료는 방향별 half-close이고, 오류는 `0x2007`로 reset한다(§7의 splice 규율 그대로). 송신은 band 0이다.

5. 흐름(정방향).
   - (1) client가 이번 세션·attach·exec의 `agent_channel`을 만들어 channel 표에 올리고 요청에 싣는다. (2) host는 요청 자체의 인가(`session.open`·`session.attach`·`exec.run`)를 먼저 하고, 그다음 `forward.agent`를 판정한다(결정 16). (3) 허락되면 소켓을 만들고 세션이나 exec의 환경에 `SSH_AUTH_SOCK`을 넣은 뒤 자식을 띄운다. 자식을 띄우지 못하면 소켓을 지운다. (4) 응답의 `agent`에 결과를 싣는다. (5) 소켓에 로컬 연결이 들어오면 host는 받치는 연결(결정 9)에 `AGENT` 스트림을 열고 둘을 잇는다. (6) client dispatcher는 header의 `agent_channel`이 자기 표에 있을 때만 로컬 agent에 연결하고 거르기를 시작한다.
   - 받는 쪽 header 대기는 지금의 `HEADER_TIMEOUT`이다.

### 원격 쪽(host)

6. 소켓과 환경(unix).
   - 경로는 runtime 디렉터리 아래 `agent/`(0700) 안의 `<32 hex>.sock`이다. 이름은 128비트 난수이고 세션 id와 무관하다. `agent/`는 원격 파일 op의 보호 집합 안이다(`docs/design/architecture.md` §7).
   - 그 경로가 `sun_path`(macOS 104바이트, Linux 108바이트)에 들어가지 않으면 OpenSSH의 `sshd`처럼 `/tmp` 아래에 `mkdtemp`로 0700 디렉터리(`qsh-agent-XXXXXXXXXX`)를 만들고 그 안에 둔다. 만든 뒤 소유자와 모드를 다시 확인하고 아니면 `UNAVAILABLE`이다.
   - 소켓은 `umask` 077 아래에서 bind하고 0600으로 확인한다. accept한 연결은 `SO_PEERCRED`(Linux)·`getpeereid`(macOS)로 상대 uid가 serve uid와 같은지 보고 아니면 바로 닫는다. root는 이 검사를 넘을 수 있으므로 이것은 권한이 잘못 잡힌 디렉터리에 대한 두 번째 문일 뿐이다(결정 20).
   - `SSH_AUTH_SOCK`은 host가 고정하는 키가 된다(`PINNED_POSIX`·`PINNED_WINDOWS`). agent가 있으면 그 경로이고, 없으면 client의 `env`가 보낸 값까지 지워 환경에 없다. 그래서 peer가 세션의 프로그램을 host의 다른 소켓으로 보내는 길이 없고, `SSH_AUTH_SOCK`의 값이 늘 qsh가 아는 상태와 같다. exec(`crates/qsh-core/src/exec/posix.rs`)도 같은 규칙이다.

7. Windows host.
   - 소켓 대신 named pipe `\\.\pipe\qsh-agent-<32 hex>`를 만든다. 소유자 SID 한 명에게만 접근을 주는 보호된 DACL(`fsutil/dacl.rs`)을 생성 시점에 붙이고, `FILE_FLAG_FIRST_PIPE_INSTANCE`로 같은 이름을 먼저 차지한 pipe가 있으면 실패하게 하며, `PIPE_REJECT_REMOTE_CLIENTS`를 건다. localctl pipe(`localctl/transport/windows.rs`)와 같은 구성이다.
   - `SSH_AUTH_SOCK`에 그 pipe 경로를 넣는다. Win32-OpenSSH의 `ssh`·`ssh-add`·`ssh-keygen`은 `SSH_AUTH_SOCK`이 가리키는 named pipe를 agent로 쓴다. 이 전제는 구현 첫 스텝의 probe가 Windows CI에서 확인하고, 틀리면 이 ADR을 고친다(PRD §4는 한 플랫폼만의 설계에 사용자 승인을 요구한다).
   - 동시 연결을 받기 위해 pipe 인스턴스를 연결마다 하나씩 새로 만든다(인스턴스 수 상한은 결정 10과 같다).

8. 수명과 정리.
   - 세션의 소켓은 세션이 끝날 때(자식 종료, `session close`, resume TTL 만료) 지우고, exec의 소켓은 exec가 끝나거나 그 연결이 닫힐 때 지운다. 지울 때는 accept를 멈추고, 열려 있던 `AGENT` 스트림을 `0x2007`로 reset하고, 소켓 파일과 디렉터리를 지운다.
   - serve 프로세스(`qsh serve`, `qsh serve --to`, on-demand serve)는 시작할 때 `agent/` 안에서 connect가 `ECONNREFUSED`로 끝나는 소켓만 지운다. 살아 있는 다른 serve의 소켓은 connect가 되므로 건드리지 않는다. pid를 이름에 넣지 않으므로 pid 재사용 문제도 없다. `/tmp` 대체 디렉터리는 세션이 끝날 때 지우고, 프로세스가 죽어 남은 것은 OS의 `/tmp` 정리에 맡긴다(OpenSSH와 같다). Windows pipe는 마지막 handle이 닫히면 OS가 지운다.
   - on-demand serve의 idle 종료(ADR-0051 결정 2)는 세션 수만 센다. agent 소켓은 세션에 딸려 있어 따로 세지 않는다.

9. 소켓을 받치는 연결. Dave가 정할 것 1의 (가)다.
   - 세션의 소켓 뒤는 지금 writer lease를 쥔 attach다. 그 attach가 `agent_channel`을 실었으면 그 연결과 channel이, 싣지 않았으면 아무도 받치지 않는다. lease가 다른 attach로 넘어가면 뒤도 함께 넘어간다. 이미 열린 `AGENT` 스트림은 끝까지 가고, 새 로컬 연결부터 새 뒤로 간다.
   - 받칠 연결이 없을 때(lease 보유자가 `-A`를 주지 않음, 연결이 끊겨 recovery 중, 아무도 붙지 않음) 들어온 로컬 연결은 바로 닫는다. 기다리게 두지 않는다. 원격 `ssh`는 agent 실패로 보고 자기 키 파일로 넘어가고, `ssh-add -l`은 "communication with agent failed" 류로 곧바로 끝난다. recovery는 대개 2초 안이고(§10, ADR-0021), 기다리는 쪽은 그만큼 늦게 다시 시도하면 된다.
   - `-A` 없이 연 세션에는 소켓이 없고, 나중에 `-A`로 attach해도 만들지 않는다(셸의 환경은 이미 정해졌다). 응답은 `NO_SOCKET`이고 사람 모드는 stderr에 한 줄을 낸다. 소켓을 미리 두고 싶으면 `qsh session open -A`로 연다(받칠 연결 없이 소켓만 생긴다).
   - resume은 §10 그대로다. client는 recovery의 `SessionAttach`에 같은 `agent_channel`을 다시 싣고 host는 같은 `forward.agent` 판정을 다시 한다. role이 줄었으면 이번 attach에서 `DENIED`이고 소켓은 받칠 연결이 없는 상태로 남는다.
   - exec의 소켓 뒤는 그 exec를 연 연결 하나뿐이다. exec는 resume되지 않는다.

10. 동시 연결과 상한. 한 소켓(세션이나 exec 하나)에 동시에 열린 `AGENT` 스트림은 16개(`MAX_AGENT_STREAMS_PER_SOCKET`)다. 넘는 로컬 연결은 스트림을 열지 않고 바로 닫는다. 한 연결 위의 `AGENT` 스트림 전체는 64개(`MAX_AGENT_STREAMS_PER_CONN`)이고, 그 위로 연결 전체의 bidi 상한 1024(§7)가 있다. 한 host의 동시 agent 소켓은 세션 quota(`max_sessions`, ADR-0010)와 exec quota가 이미 묶는다. 상한에 걸린 로컬 연결은 `qsh::agent` 로그에 개수로만 남는다.

### 로컬 쪽(client)

11. 로컬 agent 찾기.
   - unix: `-o ForwardAgent=<경로>`나 `-o ForwardAgent=$VAR`(OpenSSH 8.2의 꼴)가 있으면 그것, 없으면 client 프로세스의 `SSH_AUTH_SOCK`이다. unix 소켓으로 연결한다.
   - Windows: 같은 순서로 정한 값이 `\\.\pipe\`로 시작하면 그 named pipe, 값이 없으면 Win32-OpenSSH의 기본 `\\.\pipe\openssh-ssh-agent`다. 그 밖의 값(AF_UNIX 경로, Git for Windows의 msys 소켓 파일)은 연결할 수 없다고 보고 아래 "agent가 없을 때"와 같이 다룬다. 1Password와 Pageant(0.75 이상의 pipe)는 이 두 경로로 닿는다. AF_UNIX on Windows는 새 dependency가 필요해 넣지 않는다.
   - 연결은 `AGENT` 스트림 하나마다 로컬 agent 연결 하나다(OpenSSH와 같다).
   - agent가 없을 때. 요청을 보내기 전에 한 번 연결을 시험해 보고, 닿지 않으면 사람 모드에서 stderr에 한 줄(`qsh: -A: no ssh-agent at <SSH_AUTH_SOCK 또는 pipe 이름>; forwarding anyway`)을 낸다. 요청은 그대로 보낸다. 세션 소켓의 경로는 세션 수명 동안 고정이라 나중에 agent가 있는 장비에서 붙을 수 있어서다. 그 뒤 들어온 `AGENT` 스트림은 로컬 연결이 실패하면 FIN으로 닫고, 원격 쪽은 agent 실패를 본다. 기계 모드 stdout에는 아무것도 섞지 않는다.

12. 메시지 거르기. Dave가 정할 것 3의 (가)다.
   - client는 요청마다 종류를 본다. `REQUEST_IDENTITIES`(11)와 `SIGN_REQUEST`(13)만 로컬 agent에 넘긴다. 그 밖의 모든 종류(17~23, 25~27, SSH1 시절의 번호, 모르는 번호)는 로컬 agent에 보내지 않고 client가 `FAILURE`(5) 한 메시지로 답한다. 허용 표는 `qsh_proto::agent::ALLOWED_REQUESTS` 상수 하나가 정본이다.
   - 응답은 거르지 않는다. 로컬 agent는 이 장비의 것이다. 다만 같은 decoder로 길이를 끊어 상한을 지킨다.
   - 거른 횟수와 종류 번호만 `qsh::agent` 로그에 남는다(결정 17).
   - 이 표를 넓히는 것(예: 확장 `query`)은 새 ADR 없이 하지 않는다.

13. 등록하지 않은 channel은 agent에 닿지 않는다. client dispatcher는 `AGENT` header의 `ticket`이 정확히 16바이트이고 지금 channel 표에 있을 때만 로컬 agent에 연결한다. 아니면 `BAD_HEADER`로 reset하고 아무것도 열지 않는다. channel은 그 attach나 exec가 끝나면 표에서 내린다. 그래서 host가 위조하거나 오래된 channel로 스트림을 열어도, client가 `-A`를 주지 않은 연결이면 로컬 agent가 연결 한 번도 받지 않는다. 연결마다 dispatcher가 하나라는 점은 `TCP_ACCEPTED`와 같고, `AGENT`가 아닌 낯선 kind는 지금처럼 reset이다.

### route별

14. 역방향 route. target(`qsh serve --to`)이 host이고 controller 쪽 CLI가 client다.
   - target은 등록 연결 위로 `AGENT` 스트림을 연다. controller의 `qsh listen` 데몬이 그것을 받아, 그 channel을 실은 요청을 보냈던 conduit에만 건넨다.
   - 데몬은 `LOCAL_CONTROL` conduit에서 `agent_channel`이 든 `SessionOpen`·`SessionAttach`·`ExecStart`를 QUIC으로 내보내는 순간 `ControlHub`에 `agent_channel → conduit` 항목을 올린다. 응답을 기다리지 않는다. 셸의 rc 파일이 응답 전에 `ssh-add -l`을 부를 수 있어서다.
   - CLI는 `LOCAL_STREAM` conduit으로 `StreamHeader{AGENT, ticket}`를 내밀어 그 channel의 스트림을 기다린다. `forward_id`의 claim seat(§11-3)과 같은 규칙으로, 처음 claim한 토큰이 seat에 앉고 같은 uid의 다른 conduit은 channel 값을 알아도 가져가지 못한다. 등록한 conduit이 죽으면 항목을 내리고 대기 중인 스트림을 reset한다.
   - 데몬은 로컬 agent에 직접 연결하지 않는다. 데몬의 `SSH_AUTH_SOCK`은 서비스 매니저의 환경이고 사용자가 지금 쓰는 터미널의 agent와 다를 수 있다. agent에 연결하고 거르는 것은 명령을 친 CLI 프로세스다.
   - 데몬이 한 번에 붙잡는 `AGENT` 스트림은 hub의 터널 스트림 총량(`MAX_TUNNEL_STREAMS_PER_HUB`)과 따로 32개(`MAX_AGENT_STREAMS_PER_HUB`)다. 큐에 든 스트림의 수명 상한은 `TCP_ACCEPTED` 큐와 같다.
   - `qsh.local.v1`은 동결 밖이다(§16.3). 새 `LocalStreamKind`는 만들지 않는다. `LOCAL_STREAM`이 이미 "다음 frame이 wire `StreamHeader`인 스트림"이다.

15. 나머지 경로.
   - 펀칭으로 선 연결(ADR-0054 결정 15)은 보통 정방향 연결이라 결정 5 그대로다.
   - `-N`과 `-A`를 함께 주면 세션도 명령도 없어 소켓이 생길 자리가 없다. ssh처럼 받아 두고 아무것도 하지 않으며, 사람 모드에서 `-A has no effect with -N` 한 줄을 낸다.
   - `qsh session open -A`는 소켓만 만들고 받칠 연결이 없다(결정 9). 이 명령은 곧 끝나기 때문이다. 기계 모드에서 세션을 열고 `qsh attach -A`로 붙는 흐름이 이것으로 된다.
   - `--json`/`--jsonl`의 `qsh exec -A`는 그 명령이 도는 동안 agent를 넘긴다. AI 에이전트가 `qsh exec -A host -- git push`를 부르는 경로다.

### 인가와 감사

16. 인가: 새 action `forward.agent`.
   - host는 `agent_channel`이 든 요청에서 요청 자체의 인가를 통과한 뒤, 소켓을 만들기 전에 그 principal에 `forward.agent`를 판정한다. 평가 순서(항상-deny 게이트, role, pin grant, `acl.toml` 행)와 파싱할 수 없는 `acl.toml`의 전부 거부는 그대로다.
   - 거부되면 요청은 agent 없이 진행되고 응답의 `agent`가 `DENIED`다. 세션이나 exec까지 거부하지 않는다. agent는 편의 기능이고, 거부를 이유로 셸을 막으면 같은 role로 지금 되던 일이 `-A` 하나로 실패한다. client는 사람 모드에서 stderr에 `qsh: agent forwarding to <host> was denied` 한 줄을 낸다. 기계 모드는 결정 19의 필드로 알린다.
   - role 표: `full`과 `exec`가 준다(Dave가 정할 것 2). `acl.toml` 행과 `qsh trust allow <peer> forward.agent`도 이 이름을 받고, `acl show`의 실효 action과 `acl check`가 따라온다. 항상-deny 게이트에는 넣지 않는다.
   - 이름을 `forward.*` 계열에 두는 이유는 SSH가 이것을 forwarding이라 부르고 `-L`·`-R`·`-D`가 이미 그 계열이기 때문이다. `allow = ["forward.*"]` 행은 업그레이드 뒤 이 action도 얻는다. 그 principal이 `session.open`이나 `exec.run`을 따로 얻지 않으면 agent 소켓이 생길 자리가 없어 실제로 넓어지는 것은 없다. 이 점을 PRD §9와 `docs/CLI.md` §2.5에 적는다.
   - client 쪽에는 ACL이 없다. 대칭 원칙(§11)대로 요청 수신자가 자기 ACL을 평가하지만, `AGENT` 스트림은 client가 보낸 요청의 결과로만 받고(결정 13) client가 dial 상대에 둔 pin은 대개 role `none`이다(ADR-0045 결정 8). client의 동의는 `-A`다.

17. 감사와 로그.
   - host는 `forward.agent` 판정마다 감사 한 줄을 쓴다. `action`은 `forward.agent`, `resource`는 요청 op 이름(`session.open`, `session.attach`, `exec.run`)이고 기존 구조 필드만 쓴다. 소켓 경로, channel 값, agent 메시지는 어느 필드에도 없다. 감사를 쓰지 못하면 소켓을 만들지 않고 `UNAVAILABLE`로 답한다(fail-closed. 요청 자체는 이미 자기 감사를 통과했다).
   - `AGENT` 스트림 하나하나는 감사하지 않는다. 인가는 channel을 만들 때 끝났다(`TCP_ACCEPTED` 스트림이 감사되지 않는 것과 같다).
   - 새 tracing target `qsh::agent`. client는 `opened`, `refused`(종류 번호), `closed`(요청 수, 거른 수, 걸린 시간)를, host는 `socket_created`, `socket_removed`, `accept_closed`(사유 `no_backing`·`cap`·`peer_uid`)를 한 줄 JSON으로 낸다. 키 이름, fingerprint, 서명할 데이터, 소켓 경로는 싣지 않는다. 값은 개수, 시간, 종류 번호, 닫힌 어휘의 낱말뿐이다. `qsh::punch`처럼 기본에서 꺼져 있고 `-v`나 `QSH_LOG=qsh::agent=info`가 켠다.

### 사용자 표면

18. 플래그, 키, 우선순위.
   - `-A`와 `-a`를 루트 ssh 형식, `qsh attach`, `qsh exec`, `qsh session open`이 받는다. `-a`는 이번 명령에서 끈다. 둘 다 있으면 나중 것이 이긴다(ssh와 같다).
   - `-o ForwardAgent=yes|no|<경로>|$VAR`. qsh가 읽는 `-o` 키에 더한다(ADR-0051 결정 7의 표). 같은 키를 여러 번 주면 첫 값이 이긴다. 부트스트랩 ssh에도 지금처럼 그대로 가지만 고정 `-a`가 앞에 있어 그 세션에는 agent가 넘어가지 않는다.
   - 키 `[agent].forward = "no" | "yes"`(기본 `no`). client 명령마다 읽는다. `qsh config set agent.forward yes`가 같은 값을 준다(ADR-0050 결정 2). 읽히지 않는 `config.toml`은 다른 키와 같이 `CONFIG_ERROR`다.
   - 우선순위: `-A`/`-a` → `-o ForwardAgent` → `[agent].forward` → 꺼짐. `~/.ssh/config`의 `ForwardAgent`는 읽지 않는다(Dave가 정할 것 5).
   - 대화형 질문은 두지 않는다. 묻는 순간 원격 쪽이 이미 기다리고 있고, 기본 꺼짐이 SSH의 기본과 같다.
   - `docs/CLI.md` §6.8, §6.23, §7, §7.2를 고치고 `cargo xtask man`으로 man page를 다시 만든다.

19. JSON과 doctor. 모두 additive다.
   - `capabilities` 결과의 새 문자열 `agent.v1`(`capabilities.json` golden을 `QSH_UPDATE_FIXTURES=1`로 다시 만들고 계약 변경과 같은 무게로 본다).
   - `session.open`과 `exec.run`의 `data`에 optional `agent`(열린 문자열 `"forwarded"`, `"denied"`, `"unavailable"`, `"no_socket"`, `"unsupported"`). `-A`를 주지 않으면 키가 없어서 기존 fixture는 그대로다. `"unsupported"`는 host가 `agent.v1`을 광고하지 않은 경우다.
   - action 어휘의 `forward.agent`(`acl.check`·`acl.show` 출력), `config.list`의 키 하나.
   - doctor 코드 둘: `agent_unreachable`(warn, `[agent].forward = "yes"`인데 로컬 agent에 닿지 않음, remedy는 `ssh-agent`·Windows `ssh-agent` 서비스 시작이나 `SSH_AUTH_SOCK` 확인)와 `agent_dir_unusable`(warn, serve 장비에서 runtime 디렉터리의 `agent/`를 만들거나 확인할 수 없음). `EXPECTED_DOCTOR_CODES`에 더한다.
   - 새 fixture: `session.open.agent.json`, `exec.run.agent_denied.json`, `acl.show.forward_agent.json`, `doctor_agent_unreachable.json`. `REQUIRED_FIXTURES`에 올리고 기존 fixture는 고치지 않는다. 기계 모드 stdout은 지금처럼 JSON뿐이고, 결정 11·15·16의 경고 줄은 사람 모드 stderr에만 나온다.

### 보안

20. remote root의 agent 가로채기와 대책.
   - 남는 위험의 모양은 SSH와 같다. `-A`로 붙어 있는 동안 host의 root(그리고 같은 uid의 다른 프로세스)는 소켓에 연결해 이 장비의 agent로 서명할 수 있다. 키 자체는 넘어가지 않지만 서명은 그 키로 할 수 있는 모든 로그인과 같다.
   - qsh가 좁히는 것: 기본 꺼짐(결정 18), 받치는 연결이 있는 동안만 서명이 된다(결정 9, 끊긴 동안과 `-A` 없이 붙은 동안에는 소켓이 바로 닫힌다), 서명과 목록 조회 밖의 모든 요청은 로컬 agent에 닿지 않는다(결정 12. 키 심기, 지우기, 잠금 암호 대입이 막힌다), 소유자 전용 소켓과 pipe(결정 6·7), host 쪽 `forward.agent` 판정과 감사(결정 16·17).
   - 사용자가 더할 수 있는 것: `ssh-add -c`로 넣은 키는 서명마다 로컬 agent가 확인을 띄우고, 이 확인은 qsh 경로에서도 그대로 동작한다(Dave가 정할 것 4). README와 `docs/CLI.md` §7.2에 권고로 적는다.
   - 목적지 제한 키(`ssh-add -h`). 결정 12가 확장을 막으므로 `session-bind@openssh.com`도 로컬 agent에 닿지 않는다. 그러면 OpenSSH의 `ssh-agent`는 바인드되지 않은 연결에서 목적지 제한 키로 서명하기를 거부한다. qsh의 첫 hop은 SSH가 아니어서 agent가 hop을 셀 수 없는데, 그 상태로 바인드를 통과시키면 원격 hop에서의 사용이 로컬에서의 직접 사용처럼 보인다. 막는 쪽이 안전한 실패다. 이 동작은 구현 첫 스텝에서 OpenSSH 9.x의 `ssh-agent`로 확인하고 결과를 개정 이력에 적는다.
   - 거르기는 client에서 한다. host가 손상된 경우가 막으려는 경우이므로 host 쪽 검사는 대책이 되지 못한다.

21. 세 OS가 같은 기능을 갖는다. host와 client가 Linux·macOS·Windows의 어느 조합이든 같은 코드로 돈다. unix host는 결정 6, Windows host는 결정 7, unix client는 `SSH_AUTH_SOCK`의 unix 소켓, Windows client는 named pipe(결정 11)다. Windows의 전제 둘(Win32-OpenSSH가 `SSH_AUTH_SOCK`의 pipe 경로를 쓴다, `\\.\pipe\openssh-ssh-agent`가 기본 agent다)은 첫 스텝의 probe가 Windows CI에서 확인한다.

### 위협 모델

22. 새 행과 고정 테스트.
   - A23 스푸핑. 원격 hop의 목적지 제한 키 사용이 로컬 직접 사용처럼 보인다: 확장이 로컬 agent에 닿지 않는다(`session_bind_is_refused_so_constrained_keys_stay_unbound`).
   - B46 무단접근. `forward.agent`가 없는 peer가 host에 agent 소켓을 만든다: 판정이 소켓보다 먼저이고 감사된다(`agent_request_without_forward_agent_creates_no_socket`, `role_grants_table`의 `forward.agent` 열).
   - B47 무단접근. 악의적이거나 손상된 host가 client가 열지 않은 channel로 `AGENT` 스트림을 연다: 등록된 channel만 로컬 agent에 닿는다(`an_unregistered_agent_channel_never_reaches_the_local_agent`). 역방향에서 같은 uid의 다른 conduit이 channel을 가로챈다: claim seat(`a_reverse_agent_channel_is_claimed_only_by_its_conduit`).
   - B48 무단접근. host의 다른 사용자가 소켓에 연결한다: 0700 디렉터리, 0600 소켓, peer uid 검사, Windows의 소유자 전용 DACL과 원격 client 거부(`agent_socket_is_owner_only`, `windows_agent_pipe_is_owner_only_and_rejects_remote_clients`).
   - C26 자원고갈. 소켓 연결 홍수나 거대한 메시지: 소켓당 16, 연결당 64, hub당 32, 메시지 256 KiB(`agent_bounds`, `an_oversized_agent_frame_resets_the_stream`).
   - D24 정보노출. 감사·로그·JSON에 agent 메시지, 키 이름, 소켓 경로가 샌다(`agent_audit_and_logs_carry_no_payload`가 가짜 agent의 키 주석과 서명 데이터가 stderr와 감사 파일에 한 번도 나오지 않음을 본다).
   - E25 무결성. host가 로컬 agent의 상태를 바꾼다(키 추가·삭제, 잠금·풀기): 허용 표 밖의 종류는 로컬 agent에 닿지 않는다(`agent_filter_table`이 0~255의 종류마다 통과 여부를 고정한다). peer가 `SSH_AUTH_SOCK`을 다른 소켓으로 돌린다: host가 고정한다(`ssh_auth_sock_is_pinned_by_the_host`).
   - E26 파서 표면. 적대적 바이트로 agent decoder가 panic하거나 상한을 넘는다: 새 fuzz 타깃 `agent_frames`(분할된 입력, 길이 경계, 요청·응답 교대), `decode_stream_header` corpus에 kind 6, `decode_control` corpus에 새 필드.
   - G12 가용성. 죽은 serve가 남긴 소켓이 쌓인다, 끊긴 동안 원격 프로그램이 agent를 기다리며 멈춘다: 시작 때 죽은 소켓 정리(`stale_agent_sockets_are_swept_at_start`), 받칠 연결이 없으면 바로 닫음(`agent_requests_during_a_blackout_fail_fast_and_work_after_resume`).
   - 잔여 위험 넷을 §7에 더한다(결과 절).

### 수용 기준(M25 DoD)

23. 1. 정방향. loopback에서 가짜 agent(`qsh-testkit`)를 둔 client가 `-A` 세션과 `-A` exec 위에서 목록 조회와 서명을 끝낸다(`agent_forward_loopback_lists_and_signs`, L3). 같은 시험이 펀칭으로 선 연결에서 netsim으로 한 번 돈다(`agent_forward_over_a_punched_connection`).
    2. 진짜 agent. 시스템에 `ssh-agent`, `ssh-add`, `ssh-keygen`이 있으면 Ed25519 키를 넣은 진짜 `ssh-agent` 앞에서 원격의 `ssh-add -l`과 `ssh-keygen -Y sign`이 성공하고, `ssh-add -D`와 `ssh-add` 키 추가는 실패하며 로컬 agent의 키 목록이 그대로다(`ssh_add_and_ssh_keygen_sign_through_a_forwarded_real_agent`, L5). 바이너리가 없으면 이유를 찍고 건너뛰고, CI는 `QSH_REQUIRE_SSH_AGENT=1`로 건너뛰기 대신 실패하게 한다.
    3. 역방향. `qsh listen` 데몬을 거친 같은 시험(`agent_forward_over_the_reverse_route`)과 claim seat 시험(결정 22 B47).
    4. 수명. 세션 종료, `session close`, TTL 만료, exec 종료 뒤 소켓과 디렉터리가 없다(`agent_socket_is_removed_when_the_session_ends`). 시작 때 죽은 소켓만 지워진다(`stale_agent_sockets_are_swept_at_start`).
    5. 받치는 연결. writer lease가 `-A`를 준 attach에서 `-A` 없는 attach로, 다시 다른 `-A` attach로 넘어갈 때 서명하는 agent가 그대로 따라간다(`agent_backing_follows_the_writer_attach`). chaos proxy로 경로를 끊은 동안의 로컬 연결은 100 ms 안에 닫히고, resume 뒤 다음 서명이 성공한다(결정 22 G12, L4). `-A` 없이 연 세션에 `-A`로 붙으면 `NO_SOCKET`이다.
    6. 거르기와 상한. `agent_filter_table`, `agent_bounds`, `an_oversized_agent_frame_resets_the_stream`, `an_unregistered_agent_channel_never_reaches_the_local_agent`.
    7. 인가와 감사. `forward.agent` 없는 role(`tunnel`, `read-only`, `reverse`, `none`)과 role 없는 pin은 `DENIED`이고 소켓이 없으며 세션은 열린다. 각 판정이 감사 파일에 구조 필드만으로 남고, 감사 쓰기가 실패하면 소켓이 없고 `UNAVAILABLE`이다. `trust allow <peer> forward.agent`가 `tunnel` pin에 줘도 세션을 열 수 없으면 소켓이 생기지 않는다.
    8. 플래그. `-A`, `-a`, `-o ForwardAgent`, `[agent].forward`의 우선순위가 표 하나로 고정된다(`forward_agent_precedence_table`). `-N -A`는 소켓을 만들지 않는다. `qsh cp -A`는 `UNSUPPORTED`다. 옛 host(`agent.v1` 없음)에는 `agent_channel`이 실리지 않고 결과가 `"unsupported"`다(`a_host_without_agent_v1_gets_no_agent_field`). 부트스트랩 ssh의 인자에는 여전히 고정 `-a`가 사용자 옵션보다 앞에 있다(기존 `responder_args` 시험).
    9. Windows. Windows client가 named pipe의 가짜 agent에 닿는다(`windows_client_reaches_an_agent_on_a_named_pipe`). Windows host의 pipe가 소유자 전용이고 원격 client를 거부한다. Windows CI 러너에서 `ssh-agent` 서비스를 켜고 Win32-OpenSSH의 `ssh-add -l`이 host pipe로 forwarding된 agent를 본다(`windows_host_pipe_serves_win32_openssh_ssh_add`).
    10. 세 OS. 1, 3~8은 Linux·macOS·Windows CI에서 돈다. 2는 세 OS CI에서 `QSH_REQUIRE_SSH_AGENT=1`로 돈다.
    11. 계약. `capabilities.json` golden, 결정 19의 새 fixture, `EXPECTED_DOCTOR_CODES`의 둘, `every_config_key_is_settable`, `role_grants_table`의 `forward.agent` 열, `acl_docs.rs`의 어휘 13종, man page(`checked_in_man_pages_match_the_generator`)가 초록이다.
    12. fuzz. 새 타깃 `agent_frames`가 더해져 `fuzz/README.md`, `CLAUDE.md`, `docs/design/testing.md` L8의 개수가 27이 되고, `decode_stream_header`·`decode_control` corpus에 새 값이 든다.
    13. 회귀 없음. `-A`를 주지 않은 세션·exec의 wire 바이트가 지금과 같고(`no_agent_field_without_dash_a`), `tunnel_echo_under_load`와 `-R`의 `TCP_ACCEPTED` 시험이 diff 없이 통과한다.
    14. threat model에 결정 22의 행이 고정 테스트와 함께 들어간다.

## 근거

- 세션에 소켓을 묶는 이유. qsh의 세션은 연결보다 오래 살고 장비를 옮겨 다닌다. 셸의 환경 변수는 한 번만 정해지므로, 바뀌지 않는 경로 하나와 그 뒤를 바꿔 끼우는 표가 이 모델에서 agent를 쓸 수 있는 유일한 모양이다. 뒤를 writer lease에 묶으면 "지금 키보드를 쥔 사람의 agent"라는 직관과 맞고, 새 상태 축을 만들지 않는다.
- host가 스트림을 여는 이유. 소켓에 연결이 들어오는 곳이 host이고, `-R`의 `TCP_ACCEPTED`가 같은 방향이다. client의 연결당 dispatcher와 역방향의 claim seat을 그대로 쓴다.
- raw 바이트를 싣는 이유. agent 프로토콜은 이미 길이 머리를 가진 순차 요청·응답이다. protobuf로 다시 싸면 decoder가 둘이 되고 얻는 것이 없다. 거르기에 필요한 것은 길이와 종류 한 바이트뿐이고 그것은 sans-IO decoder 하나로 읽는다.
- client에서 거르는 이유. 막으려는 상대가 host의 root다. host 쪽 검사는 그 root가 우회한다. agent를 가진 쪽만이 무엇을 넘길지 정할 수 있다.
- client가 channel을 정하는 이유. host가 id를 발급하면 응답 전에 스트림이 오는 경주가 생기고(`-R`이 실제로 겪는다), 그 사이 들어온 스트림을 버려야 한다. client가 먼저 표에 올리면 경주가 없고, 표에 없는 channel은 곧 "요청하지 않았다"는 뜻이 된다.
- 거부해도 세션을 여는 이유. `forward.agent`는 셸에 붙는 편의이고 셸 권한은 따로 판정됐다. 거부가 셸까지 막으면 `qsh config set agent.forward yes`를 켠 사용자가 role이 낮은 host마다 접속에 실패한다.
- 새 action인 이유. host에 소켓이라는 자원을 만드는 일이고, 자원 전 단일 choke point(CLAUDE.md 보안 기본값)를 지나려면 판정할 이름이 있어야 한다. 이름이 있어야 감사와 `acl check`가 같은 근거를 말하고, 운영자가 sshd의 `AllowAgentForwarding no`처럼 끌 수 있다.

## 대안과 기각 사유

- SSH처럼 연결마다 소켓을 둔다. resume 뒤에 셸의 `SSH_AUTH_SOCK`이 죽은 경로를 가리킨다. Dave가 정할 것 1.
- agent 요청을 control 스트림의 새 message(`AgentRequest`/`AgentResponse`)로 나른다. control 스트림은 연결당 하나이고 순서대로 인라인 처리되므로(§9 "Control 스트림의 순서 계약") 로컬 agent의 확인 대기(`ssh-add -c`)가 같은 연결의 세션 요청을 막는다. 크기 상한도 control frame 256 KiB와 겹친다. 기각.
- host 쪽에서 거른다. 결정 20과 근거 절. 기각.
- 거르지 않는다(OpenSSH와 같다). Dave가 정할 것 3의 (나).
- 소켓 대신 unix socket 일반 포워딩(`-R /remote/path:local/path`)으로 사용자가 직접 잇게 한다. 경로가 세션마다 달라 사용자가 셸에서 `SSH_AUTH_SOCK`을 손으로 맞춰야 하고, `alias ssh=qsh`의 `-A`가 같은 뜻으로 동작하지 않는다. unix socket 포워딩 자체도 M25 범위 밖이다. 기각.
- 역방향에서 controller 데몬이 로컬 agent에 직접 연결한다. 데몬의 환경은 서비스 매니저의 것이라 사용자가 지금 쓰는 agent와 다를 수 있고, 거르기와 경고가 명령을 친 프로세스 밖에서 일어난다. 기각.
- Windows host에서 AF_UNIX 소켓을 쓴다. Windows 10 1803부터 커널은 지원하지만 Win32-OpenSSH 클라이언트가 agent로 쓰는 것은 named pipe이고, Rust 쪽에 새 dependency가 필요하다. 기각.
- `forward.agent` 대신 `session.agent`라는 이름을 쓴다. `session.*` 행이 업그레이드 뒤 이 action을 삼키는 것은 `forward.*`와 같고, agent는 exec에도 붙어 `session` 계열에 들지 않는다. 기각.
- 새 계열 `agent.forward`를 쓴다. 기존 와일드카드가 삼키지 않는 장점이 있지만 결정 16대로 넓어지는 것이 실제로 없고, 한 action만의 계열이 어휘를 늘린다. 기각.
- `-A`를 줬는데 host가 거부하면 명령을 실패시킨다. 근거 절. 기각.
- 받칠 연결이 없는 동안 로컬 연결을 잠시(예: 2초) 붙들고 resume을 기다린다. 대기 중인 연결과 그 상한, 시간 초과 경로가 생기고, 원격 `ssh`는 실패하면 키 파일로 넘어가므로 기다리는 쪽이 늘 낫지도 않다. 기각.

## 결과

- 개정할 문서: `docs/PRD.md` §7 P2 목록의 "agent forwarding"에 ADR 번호, §9(action 어휘 13종, `forward.agent` 문단, role 표의 `full`·`exec` 행). `docs/design/protocol.md` §4(`agent.v1`), §7(스트림 표의 `AGENT` 행, host → client), §9(`StreamKind`, 필드 여섯, `AgentGrant`), §11-3(`agent_channel → conduit` 등록과 claim), §16.4(가장 새 사례 문장), 새 §20(agent forwarding: channel, 스트림 바이트, 상한, 거르기 표, 받치는 연결). `docs/design/architecture.md` §1(`qsh-core::agent`), §6(`forward.agent` 인가 지점과 감사), §7(runtime 디렉터리의 `agent/`와 `/tmp` 대체). `docs/design/testing.md` L3·L4·L5·L6·L8과 CI 구성(`QSH_REQUIRE_SSH_AGENT`, Windows 러너의 `ssh-agent` 서비스). `docs/design/threat-model.md` §3(진입점: host의 agent 소켓·pipe, client의 `AGENT` 스트림), §4(결정 22의 행), §7(잔여 위험). `docs/CLI.md` §2.5, §6.8, §6.17, §6.23, §7, §7.2. ADR-0045 결정 2와 ADR-0051 결정 7에 이 ADR을 가리키는 개정 이력 줄. `fuzz/README.md`, `CLAUDE.md`(fuzz 개수), `README.md`(`-A` 지원과 `ssh-add -c` 권고, `ForwardAgent` 설정을 읽지 않는다는 것).
- 새 threat model 행(결정 22): 스푸핑 하나, 무단접근 셋, 자원고갈 하나, 정보노출 하나, 무결성 하나, 파서 표면 하나, 가용성 하나.
- 남는 위험(§7의 새 행):
  - `-A`로 붙어 있는 동안 host의 root와 같은 uid의 프로세스는 로컬 agent의 모든 키로 서명할 수 있다. 거르기는 서명 자체를 막지 않는다. 대책은 기본 꺼짐과 `ssh-add -c`다.
  - 다른 장비가 `-A`로 붙으면 세션 안에서 이미 돌고 있던 프로그램도 그 장비의 agent를 쓴다(결정 9).
  - 목적지 제한 키(`ssh-add -h`)는 qsh 경로에서 쓰이지 않는다(결정 20). 막힌 쪽의 실패다.
  - Windows client는 named pipe agent만 쓴다. AF_UNIX와 msys 소켓의 agent(Git for Windows의 `ssh-agent`)는 닿지 않는다.
- 크기: ADR-0050의 2ew에 역방향 route의 channel 경로(데몬 등록표와 claim), Windows host pipe와 Win32-OpenSSH 확인, writer lease를 따르는 받치는 연결이 더해져 추정 2.5ew로 고친다. 나눔은 wire·decoder·거르기·fuzz 0.3, host 소켓(unix와 Windows pipe)·환경·수명·정리 0.5, client dispatcher와 로컬 agent 연결(unix, pipe) 0.3, 받치는 연결과 resume·exec 0.3, 역방향 route 0.4, action·role·감사·플래그·키·doctor·JSON 0.3, 진짜 agent 수용 시험·Windows 시험·문서 0.4다. Dave가 정할 것 4를 (나)로 정하면 +0.5ew다.
- 스텝 순서: probe(Win32-OpenSSH의 pipe 경로 `SSH_AUTH_SOCK`, OpenSSH 9.x `ssh-agent`의 바인드되지 않은 연결 동작, wire 없음, 결과를 개정 이력에) → `qsh_proto::agent` decoder·허용 표·fuzz(wire 없음) → host 소켓과 pipe, 정리, 가짜 agent 하네스(wire 없음) → `agent.v1`, `StreamKind::AGENT`, 필드와 `AgentGrant` → `forward.agent`와 role 표, 감사 → 정방향 흐름과 client dispatcher, 로컬 agent 연결 → 받치는 연결과 resume, exec → 역방향 route → 플래그·키·doctor·JSON·fixture → 수용 시험(진짜 agent, Windows, chaos proxy, netsim) → 문서, man, threat model. 계약·wire를 건드리는 스텝은 이 ADR이 승인되기 전에 열지 않는다(ADR-0050 결정 7). 앞의 세 스텝은 wire 없이 열 수 있다.

## 개정 이력

- 2026-11-09 초안(에이전트). Dave가 정할 것 다섯 항목은 추천만 적었다.
- 2026-11-09 승인(Dave 결정). Dave가 정할 것 다섯 항목은 모두 추천 (가)로 정했다: 세션마다 고정 경로이고 writer lease를 쥔 `-A` attach가 받침, `forward.agent`는 `full`·`exec`가 줌, 목록(11)과 서명(13)만 넘기고 나머지는 `FAILURE`, qsh 자체의 서명 확인 없이 `ssh-add -c`에 맡김, `~/.ssh/config`의 `ForwardAgent`는 읽지 않음(ADR-0051 결정 8 유지). 크기는 2.5ew다.
- 2026-11-09 전제 확인 1(결정 7·11·21). Dave-Windows의 Win32-OpenSSH 9.5p2에서 `ssh-add -l`, `ssh`, `ssh-keygen -Y sign`이 `SSH_AUTH_SOCK`에 준 사용자 지정 named pipe를 agent로 썼다. pipe는 소유자 전용 DACL, `PIPE_REJECT_REMOTE_CLIENTS`, `FIRST_PIPE_INSTANCE`로 만들었고, 같은 이름의 둘째 `FIRST_PIPE_INSTANCE` 생성은 접근 거부(5)로 막혔다. `ssh-agent.exe`는 `-a`를 무시하고 기본 pipe `\\.\pipe\openssh-ssh-agent`만 만들며, 서비스가 꺼져 있으면(이 장비의 기본 상태) 기본 pipe 자체가 없다. 그래서 Windows client에서는 결정 11의 "agent가 없을 때" 경로가 흔한 경우다. 원격 client 거부는 이번에 재지 않았고 Windows CI 시험이 맡는다. 결정 본문은 고치지 않았다.
- 2026-11-09 전제 확인 2(결정 20). WSL의 OpenSSH 9.6p1 `ssh-agent`는 `session-bind@openssh.com`을 받지 않은 연결에서 `ssh-add -h`로 넣은 목적지 제한 키의 `SIGN_REQUEST`(13)를 `SSH_AGENT_FAILURE`(5)로 거부했고(`ssh-keygen -Y sign`은 "agent refused operation"), 제한 없는 키는 같은 연결에서 정상 서명했다. 목록 조회(11→12)는 제한 키를 숨기지 않는다. 그래서 qsh 경로에서 제한 키는 목록에 보이지만 서명이 거부된다. 결정 20의 "안전한 쪽의 실패"는 그대로 성립하고, 이 차이는 README와 `docs/CLI.md` §7.2의 안내에 적는다. 결정 본문은 고치지 않았다.
- 2026-11-09 client 쪽 착지. `qsh cp -A`는 다른 받지 않는 scp 플래그(`-P`·`-i`·`-o`·`-J` 등)와 같은 규칙으로 거부한다: 플래그 이름을 댄 안내 한 줄과 종료 상태 2이고 JSON 오류 envelope는 없다(`cp_rejects_unsupported_scp_flags_with_exit_2`). 결정 1의 "이름을 대며 거부"는 이렇게 착지했다. 결정 본문은 고치지 않았다.
- 2026-11-09 받치는 연결 착지(결정 9·13, DoD 23.5). 경로가 조용히 죽으면 host의 QUIC 연결은 idle timeout(45초)까지 살아 보여 로컬 연결이 죽은 연결의 `AGENT` 스트림에 매달렸다. host는 실제 스트림과 동시에 등록되지 않은 channel의 `AGENT` 스트림을 probe로 열고(client는 결정 13대로 곧바로 reset한다), `probe_wait = clamp(4×RTT, 300 ms, 2 s)` 안에 그 reset이나 상대의 인증된 프레임이 오지 않으면 로컬 연결을 닫고 그 연결을 조용하다고 기억한다. 기억된 동안의 로컬 연결은 곧바로 닫는다. 건강한 경로는 왕복이 늘지 않는다(`a_healthy_path_adds_no_round_trip_to_an_agent_request`). 그래서 DoD 23.5의 "끊긴 동안의 로컬 연결은 100 ms 안에 닫힌다"는 끊긴 뒤 둘째 연결부터 성립하고, 첫 연결은 `probe_wait`(loopback 300 ms) 안에 닫힌다. 하한을 100 ms 밑으로 내리면 부하 아래에서 건강한 연결을 잘못 닫을 수 있어 그렇게 두었다. Dave의 확인이 필요하다. 결정 본문은 고치지 않았다.
