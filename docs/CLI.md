# QSH CLI and JSON Contract

**상태:** Draft v0.60 (Windows에서 `keystore_session_bound`를 내지 않는다: 임시 표준 사용자가 대화형 로그온에서 만든 `platform` 신원을 `LogonType=Password` 작업(대화형 세션 없음)이 `qsh serve` 시작 때 같은 fingerprint로 읽었고 `qsh doctor`·`qsh identity export`도 같았으므로, ADR-0032 결정 15가 처음 쓴 대로 Windows의 `Password` 주체 작업에는 이 finding이 없다. M19가 실측 전에 넣은 보수 방출을 철회한다. `logon_task_session_scoped`는 그대로다. 진단 코드 집합(`EXPECTED_DOCTOR_CODES`)은 바뀌지 않고 macOS·Linux는 계속 낸다. 새 `ErrorCode`·wire·fixture·`capabilities.json`·clap 트리 변경 없음, §6.17, ADR-0032 결정 15); v0.59 (원격 기본 셸이 `cmd.exe`이고 `qsh`가 없을 때 `qsh pair ssh`의 사상을 실기기 측정에 맞춘다: 실제 Windows 11 25H2의 OpenSSH for Windows 9.5p2에서 ssh 종료 코드는 9009가 아니라 1이었다(9009는 배치 안 ERRORLEVEL이고 `cmd.exe /c`의 프로세스 종료 코드는 1). ssh의 stderr를 파이프로 받아 한 바이트도 바꾸지 않고 도착하는 대로 qsh의 stderr에 그대로 내보내면서 마지막 4 KiB만 메모리에 두었다가, 종료 코드 1이고 그 꼬리의 어떤 줄이 ANSI 이스케이프와 앞 공백을 걷은 뒤 `'<원격 qsh 이름>'`으로 시작하면(cmd.exe의 영어·한국어 문구 모두) `REMOTE_ERROR`(`remote_qsh_missing`, `details.remote_exit: 1`)로 사상한다. PowerShell의 `qsh: ...`는 그대로 `remote_command_failed`다. 꼬리는 로그·envelope·audit에 쓰지 않고 분류 뒤 버린다. 새 `ErrorCode`·wire·fixture·`capabilities.json`·clap 트리 변경 없음, §6.11, ADR-0044 결정 14·16); v0.58 = (reverse route의 `--supervise` 없는 `qsh tunnel open --remote` holder가 다른 프로세스의 `qsh tunnel close`로 등록이 사라지면 `CONNECTION_FAILED`(exit `255`, `tunnel_ended`)로 끝난다: 이전에는 사라진 `forward_id`의 `TCP_ACCEPTED` claim을 200ms마다 재시도하며 SIGINT까지 남았다. wire·`ErrorCode`·fixture·`capabilities.json`·clap 트리 변경 없음, §6.14, ADR-0023 결정 14); v0.57 = (macOS `status --live`가 사람이 깐 LaunchDaemon 상시 형태의 `launchctl print system/io.qsh.<mode>` 종료 코드를 root 없이 읽는다: 0은 적재됨(`active: true`), 113은 적재 안 됨(`active: false`)이고 그 밖의 종료 코드는 `INTERNAL`(`details.step: "live"`)로 남는다. 새 `ErrorCode`·wire·fixture·`capabilities.json`·clap 트리 변경 없음, §6.18, ADR-0032 결정 18); v0.56 = (§6.2의 route 항목에서 "Windows host는 PTY 세션을 만들 수 없다"는 낡은 문장을 걷어 낸다: Windows host도 ConPTY 세션을 갖고 `--state`·`--writer`·`--attachable`이 그 세션의 같은 필드에 같은 규칙으로 걸리며, 실제 라이브 세션 위에서 `sessions_filter`의 Windows 쌍둥이가 확인한다. 그리고 §7 Windows 콘솔에 클라이언트가 세션 출력의 win32 input mode 요청(`CSI ? 9001 h`/`l`)을 콘솔에 쓰기 전에 지운다는 문장을 더한다: Windows 클라이언트로 Windows host 세션에 붙으면 로컬 콘솔이 키 레코드를 돌려주어 줄 첫머리 `~d` detach가 듣지 않던 결함을 고친다. wire·`ErrorCode`·fixture·`capabilities.json`·clap 트리 변경 없음, §6.2·§7, ADR-0035 결정 5·20·21); v0.55 = (숨김 하위 명령 `qsh pair ssh-respond`가 Windows 빌드에도 등록됨: Windows 장비가 `qsh pair ssh`·`qsh pair ssh --reverse`와 자동 부트스트랩의 원격 쪽이 되며 순서·판정·audit·종료 코드는 Linux·macOS 응답자와 같고, serve 포트 UDP bind 시험의 다른 소켓이 그 포트를 쥐고 있으면 `serve_listening: true`가 되며(probe 소켓의 `SO_EXCLUSIVEADDRUSE`는 ADR-0044 결정 10을 따른 방어용이고 이 결과를 바꾼다고 보인 테스트는 없다), 새 `trust.toml`은 소유자 전용 DACL이며, commit 줄 끝의 `\r\n`을 받고, 원격 기본 셸이 `cmd.exe`이면 `qsh`가 없을 때 9009, PowerShell이면 1인 사상은 M16 그대로이며, 숨김이라 `--help`와 `docs/man/`은 바뀌지 않고 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §2.4·§6.11, ADR-0044 결정 9·10·12·14·25, ADR-0035 결정 25); v0.54 = (Windows host에서 `qsh setup host`·`qsh setup host --to`(`--service` 포함)와 `qsh pair invite`가 다른 OS와 같은 단계·같은 결과로 동작함이 확정됨: Windows 전용 거부나 `skipped`는 없고, `--service`는 `host`에서 `serve`, `host --to`에서 `reverse` mode의 작업 스케줄러 작업 정의 파일을 설정 디렉터리 아래에 쓸 뿐 작업을 등록하지 않으며, 방화벽 첫 허용 프롬프트 문안을 §6.12·§6.13에 하나로 모으고(실행 파일 경로마다 한 번, 고정 UDP 포트를 여는 `qsh serve`·`qsh listen`만이고 `qsh serve --to`와 loopback bind는 묻지 않음) `udp_egress_blocked`의 `remedy`가 상대 Windows host의 방화벽을 한 문장으로 안내함(code 집합 불변), `qsh.cli/v1`의 모양은 바뀌지 않으며 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §6.11·§6.12·§6.13·§6.17·§6.20, ADR-0024 결정 2·8·10, ADR-0035 결정 25·27); v0.53 = (Windows host가 원격 파일 op 넷(`file.read`·`file.list`·`file.write`·`file.mkdir`)과 `FILE_DATA` 스트림을 처리하고 `file.v1`을 광고함: 광고 집합이 빌드마다 갈라지지 않으므로 `capabilities.json` golden은 그대로이고, forward·reverse 어느 route로든 Windows host를 대상으로 하는 `qsh cp`가 `UNSUPPORTED` 대신 unix host와 같은 의미로 동작하며, 원격 경로는 `/`와 `\`를 같은 구분자로 읽는 드라이브 절대 경로(`C:\x`)나 프로필 디렉터리(serve 계정의 `GetUserProfileDirectoryW`, `~`·빈 경로·상대 경로의 기준) 상대 경로이고, UNC(`\\server\share`)와 장치 이름 공간(`\\?\`·`\\.\`), 드라이브 없는 경로(`\x`), 드라이브 상대 경로(`C:x`), 대체 데이터 스트림(`x:s`), Windows가 적힌 대로 저장하지 못하는 구성 요소(`CON`·`NUL.txt`, 끝의 점·공백, 예약 문자)는 ACL 판정보다 앞서 `INVALID_ARGUMENT`이고, 상태 경로 판정은 대소문자를 구성 요소 단위로 무시하며 junction·symlink를 따라간 최종 경로로 하고, `qsh.cli/v1`의 모양은 바뀌지 않으며 새 `ErrorCode`·wire·fixture 변경 없음, §6.21·§7, ADR-0029 결정 5·6·7·8·13·23, ADR-0035 결정 26); v0.52 = (Windows host의 `exec`가 자식을 만들어지는 순간부터 Job Object 안에서 돌림: `--timeout`이나 출력 상한으로 끝낼 때 자식 하나가 아니라 그 트리 전체가 끝나고, 자식 환경은 `qsh serve` 환경이 아니라 계정의 사용자 환경 블록 위에 client `env`를 얹은 뒤 pinned key(세션과 같은 집합)를 다시 적용한 것이고(unix `exec`와 같게 `TERM`도 serve 환경의 locale·시간대도 없다), `argv[0]`은 자식의 `PATH`와 시스템 디렉터리에서만 찾고, 셸을 거치지 않으므로 `dir`·`echo` 같은 `cmd.exe` 내장 명령은 `cmd /c`를 앞에 붙여야 함, `qsh.cli/v1`의 모양은 바뀌지 않으며 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §6.8·§7, ADR-0035 결정 3·20·22); v0.51 = (Windows host의 `session close --signal` 일곱 값이 모두 자기 사건을 가짐: `INT`가 `CTRL_C_EVENT`, `QUIT`가 `CTRL_BREAK_EVENT`(둘 다 숨김 보조 프로세스 `qsh internal console-ctrl <pid> <c|break>`를 `DETACHED_PROCESS`로 띄워 세션 콘솔의 모든 프로세스에 보냄), `HUP`·`TERM`이 의사 콘솔 닫기, `USR1`·`USR2`가 세션의 이름 있는 자동 리셋 이벤트에 `SetEvent`, `KILL`이 Job Object 종료이며 어느 신호로 시작해도 유예와 escalation 뒤 세션이 끝남, 세션 환경에 `QSH_SIGNAL_EVENT_USR1`·`QSH_SIGNAL_EVENT_USR2`가 더해지고(additive) client가 덮어쓸 수 없음, `session.exit`의 `signal`은 qsh가 마지막으로 보낸 단계의 신호 정규형이고 qsh가 보낸 것이 없으면 `null`, `qsh.cli/v1`의 모양은 바뀌지 않으며 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §6.7·§7, ADR-0035 결정 3·22); v0.50 = (Windows host가 PTY 세션을 받음: `qsh serve`와 `qsh serve --to`가 Windows에서 세션마다 ConPTY와 Job Object를 만들어 `session open|read|write|resize|close`와 대화형 form의 상대가 되고, `session open` 행이 `UNSUPPORTED`에서 두 OS 모두 성공으로 바뀜, 자식은 `qsh serve` 환경을 상속하지 않고 계정의 환경 블록 위에 `TERM`·locale·client `env`를 얹은 뒤 pinned key(unix의 다섯에 `USERPROFILE`·`USERNAME`·`USERDOMAIN`·`HOMEDRIVE`·`HOMEPATH`·`COMSPEC`·`SystemRoot`, 대소문자 무시)를 다시 적용함, 빈 `argv`는 `COMSPEC`을 사용자 프로필 디렉터리에서 실행, `user@` hint는 토큰의 계정 이름(`user` 또는 `DOMAIN\user`, 대소문자 무시)과 비교하고 다르면 `UNSUPPORTED`, `session close`의 신호는 Windows host에서 `HUP`·`TERM`이 의사 콘솔 닫기, `KILL`이 Job Object 종료, `qsh.cli/v1`의 모양은 바뀌지 않으며 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §6.7·§7, ADR-0035 결정 2·3·20·21·22); v0.49 = (Windows에서 `qsh service install --activate`·`uninstall --deactivate`·`status --live`가 열려 더는 `UNSUPPORTED`가 아님: 활성화는 `schtasks /Create /F /TN \qsh\qsh-<mode> /XML <작업 정의 파일>`을 부르고 작업이 실행 중이 아닐 때만 `schtasks /Run`을 이어 부름(실측: `/Create /F`는 실행 중인 인스턴스를 멈추지 않아 실행 중이어도 `/Create`는 부르고 `/Run`만 건너뛰며 `already_active`), 해제는 `/Query`가 0(등록)일 때 실행 중이면 `/End`를 부른 뒤 `/Delete /F`이고 등록돼 있지 않으면 `not_active`, 실행 여부는 `schtasks` 출력이 아니라 작업 스케줄러 COM의 상태값 하나로 읽음, `\qsh\qsh-<mode>` 작업이 `Password` 주체로 등록돼 있으면(사람이 깐 상시 기동 형태) `--activate`·`--deactivate`는 파일만 쓰고 지우며 `always_on_present`이고 `--live`는 그 작업의 실행 여부, `schtasks.exe`가 없으면 `UNSUPPORTED`·0이 아닌 종료는 `INTERNAL`(`step`·`exit_code`)·30초 초과는 `TIMEOUT`이며 대화형 세션이 없어 `InteractiveToken` 작업이 시작하지 못해도 같은 `INTERNAL`이고 다른 주체로 우회하지 않음, `keystore_session_bound`가 Windows에서도 나옴(`identity.key_store`가 `platform`이고 COM으로 읽은 같은 mode의 작업이 `Password` 주체일 때, `Password` 작업이 Credential Manager를 읽는지는 암호를 넣지 않고는 실측할 수 없어 보수적으로 냄), `qsh.cli/v1`의 모양은 바뀌지 않으며 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §6.17·§6.18, ADR-0032 결정 3~6·8·10·15·18, ADR-0035 결정 12·27·28); v0.48 = (Windows에서 `qsh service install|uninstall|status`가 열려 작업 스케줄러 작업 정의 파일(`<config_dir>\service\qsh-<mode>.task.xml`, 소유자 전용 DACL, UTF-16)을 쓰고 지우고 존재만 보고하며 `schtasks`나 스케줄러를 부르지 않음(`manager`는 `"task_scheduler"`이고 `--activate`·`--deactivate`·`--live`는 Windows에서 아직 `UNSUPPORTED`), 작업의 동작은 숨김 `qsh service run <mode>`로 콘솔에서 떨어져 stdout·stderr를 `<state_dir>\log\<mode>.out.log`·`.err.log`로 돌린 뒤 `qsh serve`·`qsh listen`·`qsh serve --to`와 같은 진입 함수를 부르고, 작업이 죽으면 로그온 트리거의 1분 `Repetition`이 다시 띄움(`RestartOnFailure`만으로는 다시 뜨지 않음을 실측), 새 warn `logon_task_session_scoped`(Windows에서만, COM으로 읽은 주체가 `InteractiveToken`일 때)로 진단 코드가 27종에서 28종이 되고 `service_not_registered`·`service_restart_drops_sessions`는 Windows에서 작업 정의 파일을 읽음, `qsh setup listener --service`가 Windows에서 이 파일을 씀, `qsh.cli/v1`의 모양은 바뀌지 않으며 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §6.11·§6.17·§6.18·§6.20, ADR-0035 결정 9·17·19·27, ADR-0032 결정 12·16); v0.47 = (Windows client가 unix client와 같은 기능을 갖춤: 대화형 form(`qsh [user@]host`, `qsh attach`)이 Windows 콘솔 계층 위에서 정방향·역방향 route로 붙고 `-L`/`-R`/`-D` companion flag를 unix와 같은 규칙으로 처리하며, 콘솔 창 닫기·로그오프·종료는 클라이언트가 QUIC 연결을 먼저 닫는 detach라 호스트가 세션을 바로 detached로 보고(닫히는 창을 최대 4초 붙잡음) 다른 콘솔에서 곧 이어 붙을 수 있음, `qsh cp`가 Windows client에서 열려 operand 문법에 드라이브 문자 규칙(첫 구분자 앞의 한 글자와 `:`는 로컬 경로이고 `user@`나 대괄호를 붙이면 한 글자 host)이 서고 get의 로컬 쓰기는 소유자 전용 임시 파일을 같은 디렉터리에서 이름 바꿈으로 놓으며 심볼릭 링크와 junction은 거절함, 이름이 어디에도 없을 때의 자동 ssh 부트스트랩이 Windows 대화형 attach와 `qsh cp`에서도 발동하고 ssh가 끝나기 전까지 콘솔은 cooked 상태 그대로이며 첫 Ctrl-C가 ssh를 끝냄, `qsh pair ssh --reverse`의 이 장비 쪽이 Windows에서 돌아 `qsh serve --to <이름>`을 다음 명령으로 안내함, doctor의 클라이언트 진단이 Windows에서도 다른 OS와 같은 조건으로 나옴, Windows host는 여전히 PTY 세션과 파일 op에 `UNSUPPORTED`로 답하고 `file.v1`을 광고하지 않으며 숨김 `qsh pair ssh-respond`도 M20까지 모름, `qsh.cli/v1`의 모양과 동작은 바뀌지 않으며 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §6.11·§6.17·§6.21·§7, ADR-0035 결정 1~3·5~8·17·26, ADR-0029 결정 2·7·22·23, ADR-0044 결정 1·5·22·25); v0.46 = (절전 감지와 `--supervise`의 reverse route 판별, 신뢰 철회, 세션 필터가 Windows에서도 unix와 같은 규칙으로 동작함: 절전 감지의 단조 시계 표본이 macOS·Linux에서는 tokio `Instant`이고 Windows에서는 절전·최대 절전 중 흐른 시간을 빼도록 문서화된 `QueryUnbiasedInterruptTime`이라 세 OS 모두에서 `qsh.event/v1`의 `wake`와 supervise·target backoff의 즉시 재시도가 나오고 감지 알고리즘(1초 틱, 3초 skew, 앞으로 뛴 차이만 셈)은 그대로이며 "Windows에서 단조 시계가 절전 중에 멈추는지는 확인되지 않았다"는 문장이 사라짐, reverse route `-R --supervise`의 운영자 닫기 판별은 `LocalHostList`·`LocalTunnelList`가 named pipe 위에서 같은 값을 돌려주므로 규칙이 그대로이고, `qsh sessions`의 필터가 `qsh listen` 데몬 fan-out의 reverse 항목에서도 Windows client에서 같은 결과를 내며, 신뢰 철회(`qsh listen`의 등록 연결과 `qsh serve --to`의 outbound 연결)가 Windows에서도 2초 안에 닫힘, `--supervise` 터널의 정지 요청(unix의 SIGINT·SIGTERM)이 Windows에서는 Ctrl-C와 콘솔 닫힘(`CTRL_BREAK` 포함)이며 같은 종료 코드 `0`과 같은 최종 출력으로 listener를 놓고 끝남, `qsh.cli/v1`의 모양과 동작은 바뀌지 않으며 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §6.2·§6.14, ADR-0035 결정 15, ADR-0023 결정 17, ADR-0031 결정 3, ADR-0033 결정 13; v0.45 = (`qsh listen`·`qsh serve --to`(숨김 alias `qsh reverse` 포함)가 Windows에서도 열림: `qsh listen`은 v0.44의 named pipe 위에 데몬을 세우고 pipe 이름이 이미 쓰이고 있으면 QUIC listener를 열기 전에 기동이 실패하며, `qsh serve --to`는 게이트만 걷혀 `exec`와 터널을 내고 PTY 세션 요청과 파일 op는 M20까지 `UNSUPPORTED`로 남음, controller 쪽 `qsh exec`·`qsh tunnel open`·`qsh hosts`·`qsh tunnels`·`qsh tunnel close`는 unix와 같은 route 규칙으로 데몬에 닿고 데몬이 없어도 `qsh hosts`는 오류가 아님, 콘솔 닫힘(창 닫기·로그오프·종료·`CTRL_BREAK`)은 두 모드가 등록을 정리하고 끝나는 종료 요청이며 최대 4초를 기다림, named pipe에는 half-close가 없어 데몬과 CLI 사이 conduit이 framed `qsh.local.v1` 메시지를 마치고 raw byte 구간에 들어서면 그 구간을 chunk(4바이트 big-endian 길이와 그 길이만큼의 바이트, 길이 0은 쓰는 쪽이 자기 방향을 끝냈다는 end chunk, 길이 상한 65536)로 나르므로 reverse route의 `-L`에서 로컬 앱의 쓰기 닫기도 목적지에 전해지고 목적지는 그 뒤에도 응답할 수 있음(unix는 chunk 없이 raw byte 그대로), `qsh.cli/v1`의 모양과 동작은 바뀌지 않으며 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §6.9·§6.13·§6.14, ADR-0035 결정 14·17·19); v0.44 = (localctl이 Windows에서도 컴파일되고 named pipe(`\\.\pipe\qsh-<scope>-<pid>`)로 이 장비의 데몬에 닿는 transport가 섬: 이름의 `<scope>`는 사용자 SID와 runtime 디렉터리에서 정해지고, 모든 pipe 인스턴스가 소유자 전용 보호 DACL을 가지며 원격 클라이언트는 거부되고, 서버와 클라이언트가 첫 프레임 전에 상대 프로세스의 사용자 SID를 자기 것과 대조해 다르면 서버는 말 없이 끊고 클라이언트는 그 후보를 건너뜀, `qsh listen`은 Windows에서 아직 열리지 않아 `qsh.cli/v1`의 모양과 동작은 바뀌지 않으며 `audit.query`는 pipe 요청에도 없음(`localctl_request_enum_has_no_audit_variant_on_any_platform`), 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §6.13·§6.22, ADR-0035 결정 14·17, ADR-0033 결정 4·13); v0.43 = (Windows `platform` key store가 Credential Manager로 서서 `qsh init --key-store platform`(`auto`는 platform을 먼저 시도하고 닿을 수 없을 때만 파일로 내려감)과 `qsh identity move-key --to platform|file`이 다른 OS와 같은 순서·결과로 동작함, M19 앞의 Windows 빌드가 `--to platform`을 `INTERNAL`로 두던 처분과 `--to file`의 `moved: false`가 사라짐, 항목은 일반 자격 증명(`CRED_TYPE_GENERIC`)·사용자 이름 `device_id`·대상 이름 `<device_id>.qsh`·`CRED_PERSIST_LOCAL_MACHINE`이고 값은 다른 OS와 같은 base64 PKCS#8 DER, 새 `ErrorCode`·wire·`capabilities.json` 변경 없음, §6.11·§6.17, ADR-0035 결정 12; v0.42 = (Windows에서 키·상태·audit 파일과 그 디렉터리가 만들어지는 순간부터 토큰 사용자 SID 하나만 담은 보호 DACL을 가지고, SID 조회 실패나 ACL 미지원 볼륨이면 파일을 만들지 않고 `CONFIG_ERROR`(경로와 원인)가 됨, 새 `ErrorCode`·wire·`capabilities.json` 변경 없음, §6.11 `move-key`, ADR-0035 결정 9·10; v0.41 = (Windows 콘솔 계층이 서고 초대 코드 프롬프트가 Windows에서 열림: `pair accept`·`trust accept`·`setup`의 프롬프트와 `--code-stdin`이 표준입력이 콘솔일 때 입력 핸들의 `ENABLE_ECHO_INPUT`만 끄고 줄 편집과 시스템 Ctrl-C 처리는 남기며 모든 종료 경로(정상, 오류, panic, 콘솔 닫기·`CTRL_BREAK`·로그오프·종료)에서 원래 모드로 복원함, 플랫폼 때문에 `UNSUPPORTED`가 되던 갈래가 사라지고 machine mode와 비 콘솔 stdin의 `INVALID_ARGUMENT` 규칙은 그대로, §7에 Windows 콘솔 한 문단(대화형 form의 VT 하한 Windows 10 1809 미만은 `session.open` 전에 `UNSUPPORTED`, 비 콘솔 stdin은 raw·escape 없이 바이트 그대로, resize 200 ms 폴링, `TERM` 없으면 `xterm-256color`, mintty 계열 안내), 새 `ErrorCode`·wire·`capabilities.json` 변경 없음, §6.11·§7, ADR-0035 결정 4~8·11·17; v0.40 = (`qsh audit`(`audit.query`)가 열림: 이 장비 자신의 audit 로그(`[audit].path`의 활성 파일과 회전분 `<path>.1`…`<path>.<retain>`)를 읽기 전용으로 조회하는 인가 불요 local op이며, 원격 peer가 요청할 수 없고 wire 메시지·localctl 요청·ACL action이 없음(원격에서 부르면 principal과 거부 이력을 열거하는 oracle이 되므로), 인자는 `--since <RFC3339|N[smhd]>`·`--until`·`--principal`·`--action`·`--resource`·`--decision <allow|deny>`·`--limit`(1~1000, 기본 100, 밖은 `INVALID_ARGUMENT`)이고 문자열 필터는 정확 일치 AND에 결과는 최신이 먼저, `data`는 `{records, skipped_lines, oldest_ts, truncated}`, 로그가 없으면 빈 결과이고 읽을 수 없으면 `INTERNAL`(경로와 오류 종류만)이며 `config.toml`을 읽을 수 없으면 `CONFIG_ERROR`, 조회는 audit 레코드를 남기지 않고 writer가 degraded여도 읽으며 audit을 지우거나 줄이는 명령은 없고 개수 기반 회전이 유일한 삭제, human 모드는 표 하나와 stderr 요약 줄, `--follow`는 없음, 새 `ErrorCode`·wire 메시지·`capabilities.json` 변경 없음, §2.4·§2.5·§6.22, ADR-0033 결정 4·7·9·10·12·13; v0.39 = (`qsh sessions`가 클라이언트 쪽 필터 `--state <값>`·`--writer <principal|none>`·`--attachable`을 받음: 호스트의 응답을 받은 뒤 이 장비의 `Ops`가 거르고 여러 개는 AND, `--state`는 `state` 문자열과 정확 일치이며 모르는 값은 오류가 아니라 빈 결과, `--writer none`은 `writer: null`, `--attachable`은 이 장비의 resume 상태 파일에 그 `session_ref`의 credential이 있는 세션만(token 값은 어디에도 싣지 않음), `SessionListReq`와 wire 메시지는 그대로라 호스트는 필터가 있는 호출과 없는 호출을 구별하지 못하고 호스트가 돌려주는 집합은 ACL `session.list` 범위 그대로, host 없는 fan-out의 `data.unreachable`은 필터와 무관하게 남음, `data`의 JSON 모양은 `{"sessions": […]}` 그대로이고 새 필드·새 `ErrorCode`·`capabilities.json` 변경 없음, human 모드는 필터가 걸렸을 때 stderr에 `qsh: showing M of N sessions` 한 줄을 냄, forward host와 reverse host(`qsh sessions <reverse host>`, 데몬을 거친 reverse 항목)에서 같은 결과, §6.2, ADR-0033 결정 1~3·13; v0.38 = (doctor가 macOS에서 사람이 깐 LaunchDaemon 파일(`/Library/LaunchDaemons/io.qsh.<mode>.plist`)을 등록된 유닛으로 인식함(파일 존재만 보고 `launchctl`을 부르지 않음), `launchagent_session_scoped`는 같은 mode의 LaunchDaemon 파일이 있으면 침묵하고 문구가 `docs/deploy/service.md`의 LaunchDaemon 레시피를 가리킴, 새 진단 코드 `keystore_session_bound`(warn: `identity.key_store = "platform"`이고 상시 기동 형태가 있을 때. macOS는 LaunchDaemon 파일, Linux는 linger 파일과 등록된 user unit. remedy는 `qsh identity move-key --to file`)로 진단 코드가 27종이 됨(Windows 빌드도 같은 27종을 알지만 M19 전에는 이 코드를 내지 않음), `qsh service status`의 `exists`는 그대로 LaunchAgent 경로만 봄, 새 `ErrorCode`·wire·`capabilities.json` 변경 없음, §6.11·§6.17·§6.18, ADR-0032 결정 12~16; v0.37 = (`qsh identity move-key --to <file|platform>`(`identity.move_key`)가 열림: 개인키를 key store 사이에서 옮기되 device_id·인증서·fingerprint는 바꾸지 않아 상대 장비의 pin과 ACL 행이 그대로 유효함, 순서는 audit 한 건 → 원래 store에서 읽기 → 새 store에 쓰기 → 새 store에서 읽어 인증서와 대조 → `identity.toml`의 `key_store` 갱신 → 원래 항목 삭제, 어느 단계든 실패하면 되돌리고 마지막 삭제만 실패하면 성공에 `stale_entry_left: true`, 이미 그 store면 `moved: false`이고 audit도 쓰지 않음, 초기화 전은 `CONFIG_ERROR`, store가 없는 `--to platform`은 `INTERNAL`, Windows 빌드는 `--to platform`이 `INTERNAL`이고 `--to file`이 `moved: false`(Credential Manager는 M19), `data`는 `{from, to, moved, stale_entry_left}`, 새 `ErrorCode`·wire·`capabilities.json` 변경 없음, §2.4·§2.5·§6.11, ADR-0032 결정 15·17; v0.36 = (`qsh service`가 서비스 매니저를 실제로 부른다: `install --activate`가 유닛을 쓴 뒤 등록하고 시작함(이미 떠 있는 유닛은 재시작하지 않음), `uninstall --deactivate`가 유닛 파일을 지우기 전에 매니저에서 내림(등록 여부로 판정), `status --live`가 종료 코드 하나로 실행 상태를 읽음, 플래그가 없으면 매니저를 부르지 않고 `config.toml`·환경 변수로 기본값을 줄 수 없음, `data`에 선택 필드 `activation`·`deactivation`·`active`가 더해지고 새 `ErrorCode`는 없음(매니저 실행 파일 없음은 `UNSUPPORTED`, 30초 초과는 `TIMEOUT`, 그 밖의 실패는 `INTERNAL`이고 `error.details.step`이 단계를 가름), 사람이 깐 macOS LaunchDaemon 상시 형태는 건드리지 않고 `status --live`는 그 형태의 실행 상태를 읽지 않고 `sudo` 힌트를 단 `INTERNAL`로 끝남, Windows는 여전히 `UNSUPPORTED`, wire·`capabilities.json` 변경 없음, §6.17·§6.18, ADR-0032 결정 1~11·18; v0.35 = (이름이 어디에도 없을 때 `qsh [user@]host`(`-L`/`-R`/`-D` 동반 포함)와 `qsh cp`가 `qsh pair ssh`와 같은 ssh 부트스트랩을 먼저 자동으로 돌린 뒤 원래 명령을 잇는다: 사람 모드만이고 `--json`/`--jsonl`·`[ssh].bootstrap = "off"`·`hosts.toml`·pin(주소 유무 불문)·reverse 등록(live와 stale)이 있는 이름·`qsh exec`·`qsh session open`·`qsh tunnel open`·`qsh sessions`에서는 발동하지 않음, ssh를 부르기 전 stderr에 고지 한 줄(`--quiet`로 끄지 않음), 대화형 form은 ssh가 끝난 뒤에 raw 모드에 들어감, 확인 dial 없이 원래 명령의 연결이 확인이라 serve가 없으면 `CONNECTION_FAILED`(`remote_serve_not_listening`)로 끝나고 pin은 남음, 사람 모드 `HOST_NOT_FOUND` 첫 갈래의 오류 줄에 `qsh pair ssh <name>` 힌트가 붙고 envelope의 `message`·`details`는 불변, 새 `ErrorCode`·wire·fixture·`capabilities.json` 변경 없음, §6.1·§6.21·§7, ADR-0044 결정 2·3·13·16·22; v0.34 = (`qsh pair ssh --reverse --to <host[:port]>`가 열림: 원격(target)이 이 장비(listener)로 dial하는 구도의 부트스트랩으로, 원격 pin은 이 장비를 `--to` 주소와 role `full`(`--role`이 덮음)로 쓰고 이 장비 pin은 원격을 주소 없이 role `reverse`로 씀(audit `pair.ssh`를 pin보다 먼저 남기고 쓸 수 없으면 이 장비 pin도 쓰지 않음), 원격의 기존 pin은 주소만 갱신(role 불변), 확인 dial 없음(`verified: false`, `verify_error` 없음), `PairSshData.direction`에 `"reverse"`가 더해지고 `next_command`가 `qsh serve --to <이름>`을 안내함, `--reverse`·`--to` 한쪽만이거나 `--address`와 함께면 ssh를 부르기 전에 `INVALID_ARGUMENT`, 새 `ErrorCode`·wire·`capabilities.json` 변경 없음, §2.5·§6.11, ADR-0044 결정 1·12·13·17·22; v0.33 = (`qsh pair ssh`(`pair.ssh`)가 열림: 정방향, 시스템 ssh를 한 번 거쳐 원격이 이 장비를, 이 장비가 원격을 pin하고 QUIC handshake로 확인함(ADR-0044 결정 1·5~8·12~15·17·18·21·26), 두 단계 쓰기(hello까지는 아무것도 쓰지 않고 commit 뒤에 원격 pin, 이 장비 pin 순서), 이 장비 쪽 pin은 role `none`을 명시, 기존 원격 pin의 role은 넓히지 않고 실제 값을 `data.remote.role`로 보고, 새 `PairSshData`(`direction`·`peer`·`created`·`remote`·`identity_created`·`ssh_proxied`·`verified`·`verify_error`), 새 `details.reason` 값(`pin_conflict`·`remote_not_initialized`·`bootstrap_version`·`remote_responder_error`·`remote_serve_not_listening`·`remote_serve_identity_mismatch`·`remote_serve_rejected_this_device`), `<dest>` 검증이 ssh operand 검증과 pin 이름 검증으로 갈려 `--as`를 주면 pin 이름 규칙에 걸리는 `Host` 별칭도 쓸 수 있음, 새 `ErrorCode`와 wire 변경 없음, §2.4·§2.5·§6.11·§6.21; v0.32 = (신뢰를 거두면 이미 확립된 연결이 닫힘: `qsh serve`·`qsh serve --to`·`qsh listen`이 `trust.toml`의 변경을 받아 자기가 쥔 연결마다 `reverify`와 role grant 비교를 다시 돌리고, 신뢰를 잃은 연결과 role grant가 줄어든 연결을 close 코드 `0x1005`로 2초 안에 닫음, `trust remove`의 유효 범위와 `trust rename`·`trust set-role` 문단과 §6.9·§6.14의 `--supervise` 설명을 새 동작으로 고침, human 출력의 세 문장 문면(`TRUST_NARROWING_SCOPE`), doctor `trust_remove_scope`의 message·remedy, audit `resource` 값 `trust_withdrawn`·`grants_reduced`, 닫힌 연결의 재dial cause는 `tls_rejected`, 선택 필드·JSON 모양·`ErrorCode`는 바뀌지 않음, §6.9·§6.11·§6.12·§6.13·§6.14·§6.17, ADR-0031 결정 3~9; 같은 v0.32에 `config.toml`의 `[ssh]` 세 키(`bootstrap`·`program`·`remote_qsh`)와 시스템 ssh를 부르는 쪽의 규칙(`<dest>` 검증, 고정 인자와 `<remote_qsh>` 인용, `ssh -G` 읽기, 종료 코드 사상, 대기 시간, 로그 규율)이 더해짐, 명령은 아직 열리지 않았고 JSON 모양·`ErrorCode`는 바뀌지 않음, §6.12·§7, ADR-0044 결정 4·7·9·14·16·19·25; 같은 v0.32에 숨김 하위 명령 `qsh pair ssh-respond`가 operation이 아닌 모드로 등록됨(Unix 빌드만이고 Windows 빌드의 응답자는 M20이라 그 전에는 이 하위 명령을 모름, stdout은 부트스트랩 스트림뿐, 새 pin의 audit `action`은 `pair.ssh_respond`, 도움말과 man 페이지에 나오지 않음), `qsh.cli/v1` 모양·`ErrorCode`는 바뀌지 않음, §2.4, ADR-0044 결정 9·10·12 ); v0.31 = (`qsh cp -r`가 열림: 트리 순회(get은 `file.list` 페이지, put은 로컬 트리를 이름 바이트 순서로), 최상위 operand의 `name_if_dir`·`into_dir`와 이름 없는 SRC(`.`)의 내용 복사, 트리 안 symlink는 `skipped`(reason `symlink`)이고 특수 파일은 그 항목의 `INVALID_ARGUMENT`, 원격 항목 이름 검증, 한 디렉터리 항목 수 상한, 파일 전송 둘 병렬과 quota 재시도, 연결 수준 실패의 `not_attempted`, human 모드의 한 줄 요약, dial·handshake 중 취소와 둘째 Ctrl-C의 즉시 종료, §6.21, ADR-0029 결정 12·14·20·21·22; v0.30 = `qsh cp`(`file.copy`)가 생김: 합성 local operation, scp 호환 operand 문법(put과 get, 첫 `/` 앞의 `:`), `-p`·`-q`·`--no-clobber`와 거부하는 scp 플래그(exit 2), forward·역방향 route의 단일 파일 왕복, `--json`의 `FileCopyData`와 `--jsonl`의 `file.entry` event, 부분 실패의 `error.details`, 새 §6.21, §2.4·§2.5·§6.10·§10, ADR-0029 결정 1·2·3·4·7·10·11·15·16·17·18·21·22; v0.29 = `file.v1`을 unix 빌드가 광고함(`LOCAL_CAPABILITIES`의 마지막 항목, `qsh capabilities`와 협상 결과에 나타나고 Windows 빌드는 광고하지 않음), `capabilities.json` golden에 `file.v1`이 더해짐, host의 `FILE_DATA` 데이터 평면(원자적 교체, BLAKE3와 크기 검증, 쓰기 여유 공간 reserve, 정체 장부), 에러 의미는 그대로, ADR-0029 결정 1·7·9·10·11·13·15·16·23, §6.10; v0.28 = 항상-deny 게이트에서 `file.read`·`file.write`가 빠지고 `forward.socks`만 남음, 원격 파일 op의 host 처리(상태 경로 거절, 열린 핸들 재검증, 균일한 `PERMISSION_DENIED`), `[serve].max_file_transfers_per_principal`·`max_file_transfers`와 quota 범주 `quota_files_principal`·`quota_files_host`, `acl check --path`의 `decision`이 `"allow"`가 될 수 있음, ADR-0029 결정 3·5·6·8·12, §2.5·§6.11·§6.12·§6.15·§6.19; v0.27 = `acl.toml` 행의 `paths`(파일 action의 접근 범위)와 `acl check --path`, `AclCheckReq.path`·`AclCheckData.path`·`AclCheckData.canonical_path`, `AclMatchingRule.paths`·`AclMatchingRule.file_paths_missing`, `acl show`의 `paths`와 파일 action의 `effective_actions` 의미, doctor `acl_file_paths_missing`(코드 집합이 26개가 됨), ADR-0029 결정 4·19·23, §6.15·§6.17·§6.19; v0.26 = trust pin의 optional `role` 키와 `TrustPeer.role`, role 표, role을 쓰는 명령(`trust add`·`pair invite`·`pair accept`의 `--role`, `trust set-role`)과 기본값 표, 초대 레코드의 role, 페어링 고지의 role 절, `trust list`의 role 열, audit의 optional `role` 키, `TrustInviteData.assigned_role`, 평가 단계 ⓡ과 `acl.toml` 세 상태, 없는 `acl.toml`의 시작 진단이 한 줄이 됨, `acl check`의 `role`·`granted_by`·`policy.state`와 `acl show`의 `role`·`role_actions`, `effective_actions`가 role ∪ 행이 됨, doctor `trust_pin_role_unset`과 role에 따라 바뀐 `acl_*` 조건, `setup --peer-role`과 role 기본값, ADR-0045, §6.11·§6.12·§6.13·§6.15·§6.17·§6.19·§6.20; v0.25 = 역방향 등록의 경로 감시가 터널 splice 바이트도 생존 신호로 센다, ADR-0041 결정 8, §6.13·§6.12; v0.24 = `qsh::reverse` `lost` 줄에 `tick_gap_ms`, `cause` 분류 보정, 재dial backoff, ADR-0042, §6.13; v0.23 = 역방향 등록의 경로 감시 예산 분리와 `[recovery]`의 `reverse_min_dead_after_ms`·`reverse_strikes`, ADR-0041, §6.12·§6.13; v0.22 = `lost` 줄의 `srtt_ms`·`silence_ms`, `[transport].keep_alive_ms`(ADR-0021 결정 1), `[recovery]` 감시 키(ADR-0021 결정 4), §6.4·§6.9·§6.12·§6.13; v0.21 = doctor의 UDP probe가 QUIC version negotiation 패킷이 됨(§6.17), 주소 해석의 시스템 resolver 한계(§6.1, ADR-0039); v0.20 = `doctor --fail-on`(ADR-0027, §4·§6.17), `stateless_reset.key`(ADR-0036, §6.12·§6.13), `setup client`의 `complete`(ADR-0038, §6.20); v0.19 = doctor `service_restart_drops_sessions`와 `qsh::lifecycle`의 `drained` 값(§6.11·§6.12·§6.13·§6.17); v0.18 = `tunnel open --supervise`·`--accept-hold`(§6.9, §6.14)와 `qsh::lifecycle` 수명 줄; v0.17 = `setup.run`(`qsh setup`, §6.20, ADR-0024); v0.16 = doctor `acl_forward_socks_ineffective`와 `cause`의 `idle_timeout`(§6.13, §6.17); v0.15 = `qsh init --import-ssh-key`와 `trust ssh-preview`(ADR-0026, §6.11); v0.14 = `acl.show`(`qsh acl show`, §6.19, ADR-0025); v0.13 = `qsh exec`가 §6.1 라우팅 우선순위를 공유함(§6.1·§6.8·§6.13); v0.12 = `CERT_PEM_MAX` 상한과 `trust add-ca` 라벨 검증(§6.11); v0.11 = 사람용 표면 재정렬(ADR-0012~0014, ADR-0019/0020): `serve --to`·`pair --as`·`trust add-ca`·`service`(§6.18)·`-D`, §2.4·§2.5·§6.1·§6.9·§6.11·§6.12·§6.13·§6.17·§6.18·§10; v0.10 = 역방향 위 resume의 `registration_wait_ms`(§6.4); v0.9 = 대화형 attach의 역방향 경로(§6.13); v0.8 = `Host`의 `state`/`device_id`와 역방향 등록 ACL 매핑(§2.5·§5), §6.13 신설; v0.7 = `session.attach`의 resume credential 필수(§6.3·§6.4); v0.6 = `session read --follow` 출력 형태; v0.5 = 계약 확정; v0.4 = 구현과 동기화))
**대상:** QSH MVP  
**Canonical interface:** `qsh` CLI

## 1. 목적

QSH는 하나의 명령 체계를 사람과 shell script가 함께 사용하도록 설계한다.

- 기본 출력은 사람이 읽기 쉽다.
- `--json`과 `--jsonl`은 안정된 machine-readable contract다.
- 내장 MCP adapter(`qsh mcp`)는 철회됐다(ADR-0011) — 에이전트 연동 면은 이 `qsh.cli/v1` JSON/JSONL 계약 하나로 통일한다. 원격 stdio MCP 서버를 띄워야 하면 `qsh exec host -- <server>`로 그 프로세스를 실행한다(§8).

```text
Typed QSH operations
├── Human renderer
└── JSON / JSONL renderer
```

## 2. 공통 규칙

### 2.1 출력 모드

| 옵션 | 용도 |
|---|---|
| 기본값 | 사람이 읽는 text/TUI 출력 |
| `--json` | 명령 하나의 최종 결과 |
| `--jsonl` | 장시간 실행되거나 streaming되는 event |

Global output flag는 subcommand 앞뒤에서 동일하게 동작한다.

```bash
qsh --json hosts
qsh hosts --json
```

`--json`과 `--jsonl`은 동시에 사용할 수 없다. Machine-readable mode에서는 색상, spinner, progress bar와 interactive prompt를 출력하지 않는다.

추가 입력이 필요한 경우 prompt 대신 `TRUST_REQUIRED` 또는 `INVALID_ARGUMENT` 오류를 반환한다.

### 2.2 stdout과 stderr

- stdout: 요청한 결과 또는 JSONL event만 출력
- stderr: 진단 로그와 verbose trace
- PTY 및 remote command stderr: QSH 진단 stderr와 섞지 않고 protocol data로 전달
- `--quiet`: 성공 시 진단 출력 억제
- `-v`, `-vv`: stderr 진단 수준 증가

### 2.3 안정성

- 모든 JSON object는 `schema`를 포함한다.
- 식별자는 숫자로 변환하지 않는 opaque string이다.
- 시간은 UTC RFC 3339, 기간은 integer milliseconds다.
- Byte sequence는 JSON에서 standard Base64로 표현한다.
- 알 수 없는 field는 무시할 수 있어야 한다.
- 기존 field의 의미 변경과 삭제는 새 major schema가 필요하다.
- `sequence`는 chunk index가 아니라 세션 수명(session lifetime) 동안 누적된 output byte 수(u64)다. 각 `session.output` event의 `sequence`는 해당 chunk까지 포함한 누적 byte offset, 즉 그 chunk의 마지막 byte offset + 1이다. 상세 계약은 §6.4를 참고한다.

### 2.4 Operation 이름

CLI의 `command`, JSON envelope와 audit record는 하나의 dotted operation 이름을 공유한다. 각 operation이 요구하는 ACL action은 §2.5의 매핑 표에서 정의한다.

```text
host.list
host.get
session.list
session.get
session.open
session.read
session.write
session.resize
session.close
session.attach
exec.run
file.copy
tunnel.open
tunnel.dynamic
tunnel.close
tunnel.list
identity.init
identity.export
identity.move_key
trust.add
trust.add_ca
trust.list
trust.remove
trust.rename
trust.set_role
trust.ssh_preview
trust.invite
trust.accept
pair.ssh
cert.init
cert.issue
doctor.run
service.install
service.uninstall
service.status
setup.run
acl.check
acl.show
audit.query
schema.get
capabilities.get
version.get
```

`session.attach`는 value operation이 아니라 stream operation이다 (§7.1 참고). CLI subcommand 표기(`qsh hosts`, `qsh session open` 등)와 이 dotted 이름은 서로 다른 계층이며, envelope의 `command` field와 audit record는 항상 이 dotted 이름을 사용한다. 이 층 분리의 한 사례로, `qsh trust invite`/`qsh trust accept`가 `qsh pair invite`/`qsh pair accept`로 개명된 뒤에도 dotted 이름 `trust.invite`/`trust.accept`는 그대로다(§6.11, ADR-0012 결정 9).

dotted 이름은 CLI subcommand token을 기계적으로 옮긴 것이다(`cert.init` ↔ `qsh cert init`, `host.get` ↔ `qsh host get`). clap이 렌더링하는 다중 단어 subcommand token은 kebab-case(`add-ca`)이지만, `-`는 모든 `acl.toml` action과 모든 `Op::as_str` 값이 쓰는 `[a-z._]` 어휘 밖이다. 단어 경계를 유지하면서 이 어휘에 들어맞는 유일한 표기는 snake_case이고, 이는 JSON contract가 이미 쓰는 관례(`cert_pem`, `added_at`, `key_store`)와도 같다. `trust.add_ca`(CLI 표기 `qsh trust add-ca`)가 `trust.addca`가 아닌 이유이며, 이후 `trust.rename`·`service.*` 같은 다중 단어 subcommand도 같은 규칙을 따른다.

`file.read`·`file.write`·`file.list`·`file.mkdir`(ADR-0029)는 원격 peer가 요청하는 wire operation이지만 자기 CLI subcommand도 `qsh.cli/v1` envelope도 없다. 그래서 위 코드 펜스(CLI에서 부를 수 있는 operation 목록)에는 넣지 않았고 §2.5 표에서만 ACL action에 묶는다. 이 넷을 엮어 부르는 것이 `file.copy`(`qsh cp`, §6.21)이고, 이쪽은 위 펜스에 있다. 호스트는 모양 검사(`INVALID_ARGUMENT`, 비 unix 호스트는 `UNSUPPORTED`)를 ACL 앞에서 하고, 경로 문자열 그대로를 audit `resource`로 쓴다.

`acl.check`(§6.15, M5)와 `acl.show`(§6.19, M11)는 원격 peer가 요청하는 operation이 아니라 **이 머신 자신의** `acl.toml`을 로컬에서 조회하는 op이다 — §2.5의 "인가 불요" 행이 다른 local-only operation들과 함께 명시한다. `setup.run`(§6.20, M12)도 같은 종류의 로컬 op이다. 기존 op을 순서대로 부르는 오케스트레이터이고 원격 peer가 요청할 수 없으며 wire 메시지도 없다. `file.copy`(§6.21)도 같은 지위다. client가 `file.read`와 `file.write`를 엮는 합성 op이라 wire 메시지도 ACL 행도 없다. `audit.query`(§6.22, M17)도 같은 지위다. 이 머신 자신의 audit 로그를 읽는 로컬 op이고 원격 peer가 요청할 수 없으며, `qsh-proto`의 프레임 enum에도 localctl 요청(Unix 도메인 소켓, Windows named pipe)에도 대응하는 variant가 없고 새 ACL action도 요구하지 않는다(ADR-0033 결정 4).

`qsh serve`, `qsh listen`, `qsh serve --to`(구 표기 `qsh reverse`, §6.13)는 operation이 아니라 장기 실행 모드(long-running mode)다. 단일 요청/응답 계약이 없으며 이 목록에 포함되지 않는다.

`qsh pair ssh-respond`도 operation이 아니다(ADR-0044 결정 9). `qsh pair ssh`가 시스템 ssh로 원격에서 부르는 숨김 하위 명령이고(`--help`와 `qsh pair --help`에 나오지 않으며 man 페이지도 없다), `qsh.cli/v1` envelope을 내지 않는다. stdout은 부트스트랩 스트림(`docs/design/protocol.md` §17)이고 stdin은 client의 `commit`이다. 실패는 stderr에 텍스트로만 나가고 stdout에는 부트스트랩 줄 외에 아무것도 쓰지 않는다. 새 pin을 쓸 때만 audit record 하나를 남기며 그 `action` 문자열이 `pair.ssh_respond`다(`principal`은 `device:<pin 이름>`, `resource`는 pin 이름, `role`은 쓴 role). 이 record를 쓸 수 없으면 pin도 쓰지 않는다. Linux·macOS·Windows 빌드 모두에 등록돼 있고 순서와 판정이 같다(ADR-0044 결정 10, ADR-0035 결정 25). Windows에서도 serve 포트를 다른 소켓이 쥐고 있으면 UDP bind 시험이 `serve_listening: true`로 알린다(probe 소켓의 `SO_EXCLUSIVEADDRUSE`는 ADR-0044 결정 10을 따른 방어용이고, 이 결과를 바꾼다고 보인 테스트는 없다). 새로 쓰는 `trust.toml`은 소유자 전용 DACL이고, stdin·stdout은 ssh가 준 pipe이며, commit 줄 끝의 `\r\n`은 받는다. Windows 장비를 대상으로 할 때 ssh는 OpenSSH Server(선택적 기능)가 있어야 하고, 이 하위 명령을 모르는 옛 qsh는 clap이 exit 2로 끝내 `qsh pair ssh`가 `remote_qsh_too_old`로 읽는다.

실행 중인 세션에 **신호만** 보내는 별도 operation(`session.signal`)은 M2 범위가 아니다(P1 후보 — 이 목록에 없다). M2에서 신호를 보내는 유일한 CLI 표면은 `qsh session close --signal <SIG>`(§6.7)이며, 신호는 wire `SessionClose`의 optional `signal` field로 전달된다(ACL은 §2.5의 `session.close` 행 그대로 `session.control`). wire 번호 25(`SessionSignal`)는 **예약만** 하고 M2에서는 메시지를 정의·전송하지 않는다 — 호스트가 25번을 수신하면 리소스 생성 없이 `UNSUPPORTED`로 답한다(protocol.md §9).

### 2.5 Operation과 ACL action 매핑

ACL action은 인가(authorization) 어휘로, operation 이름과는 별개 차원이다. 하나의 action이 여러 operation을 커버할 수 있다. 전체 action 목록은 PRD §9에서 정의하며, 원격 peer가 요청한 operation은 아래 매핑에 따라 인가된다.

| Operation | 필요 ACL action |
|---|---|
| `session.open` | `session.open` |
| `session.list`, `session.get` | `session.list` |
| `session.read`, `session.attach` | `session.attach` |
| `session.write`, `session.resize`, `session.close` | `session.control` |
| `exec.run` | `exec.run` |
| `tunnel.open` (local forward) | `forward.local` |
| `tunnel.open` (remote forward) | `forward.remote` |
| `tunnel.dynamic` (`-D`, SOCKS5) | `forward.local` — 새 grant가 아니라 `-L`과 같은 action의 재사용이다. `forward.socks`는 이 인가에 관여하지 않는다(ADR-0019 decision 14, §6.9의 `DYNAMIC_FORWARD_ACL_NOTE` 참고) |
| `tunnel.close`, `tunnel.list` | 해당 tunnel의 소유 peer이면 허용 (`forward.*` 부여로 충분) — remote forward(`-R`)의 `tunnel.close`는 이 로컬-머신 축(§6.13·§6.14, `docs/design/protocol.md` §11-3)과 별개로, host 쪽 `forward.remote` principal 소유권 검사를 하나 더 거친다(M5 Step 5, §6.9 아래 문단). `-L`/`-D`의 `tunnel.close`에는 이 host 쪽 검사가 없다 — 로컬 listener를 닫는 것뿐인 순수 local operation이다 |
| `file.read`, `file.list` | `file.read` |
| `file.write`, `file.mkdir` | `file.write` |
| `host.list`, `host.get`, `identity.init`, `identity.export`, `identity.move_key`, `trust.*`, `cert.init`, `cert.issue`, `doctor.run`, `acl.check`, `acl.show`, `audit.query`, `schema.get`, `capabilities.get`, `version.get`, `service.install`, `service.uninstall`, `service.status`, `setup.run`, `pair.ssh`, `file.copy` | 인가 불요 — local operation으로 원격 peer의 ACL 평가 대상이 아님 |

`forward.socks`는 action 어휘에 예약되어 있지만 어떤 operation도 이 action으로 인가하지 않는다 — `-D`가 실제로 구현된 뒤에도 마찬가지다(위 행, ADR-0019 decision 14). 파일 op은 경로마다 판정한다(ADR-0029 결정 8). 원격 파일 op 넷(`file.read`·`file.list` → `file.read`, `file.write`·`file.mkdir` → `file.write`)은 role이 그 action을 주거나 `paths`가 있는 행이 경로를 덮을 때 허용된다. 항상-deny 게이트에는 `forward.socks`만 남았다(ADR-0029 결정 3·8). 허용된 뒤에도 qsh 자신의 config·state·runtime 경로, audit 파일과 그 회전 슬롯, 키 파일에는 role과 행에 무관하게 닿지 못한다(ADR-0029 결정 5, 끄는 설정 키 없음). 이 거절과 `paths` 밖·`paths` 없음·정규화 실패·열린 핸들 재검증 불일치는 모두 같은 `PERMISSION_DENIED`와 같은 문면이다. 이 op들을 보내는 정상 client는 `qsh cp`(§6.21)이고, 협상된 capability 집합에 `file.v1`이 없는 peer에게는 보내지 않는다.

위 표의 "인가 불요"는 원격 peer의 ACL 평가 대상이 아니라는 뜻이지, 이 머신 상태에 부작용이 없다는 뜻이 아니다 — `trust.rename`이 그 예다: 원격 peer를 인가하는 행위가 아니므로 이 표에 없지만, 실행되고 나면 `acl.toml`의 `[[acl]]` 행이 어떤 principal을 매치하는지 자체가 바뀐다(§6.11). `trust.set_role`도 같은 부류다: 원격 peer가 요청할 수 없는 이 머신의 local op이지만 실행되고 나면 그 pin이 받는 action이 바뀐다(§6.11). `service.install`도 마찬가지다: 원격 peer를 인가하지 않지만 실행되면 이 머신의 launchd/systemd 유닛 파일이 쓰이거나 다시 쓰인다(§6.18). `--activate`를 주면 그 유닛이 서비스 매니저에 등록되고 시작되며, `service.uninstall --deactivate`는 반대로 내린다(§6.18).

`audit.query`도 이 행에 있다. 원격에서 남의 audit 로그를 열람할 수 있으면 그것이 곧 principal과 거부 이력에 대한 열거 oracle이 되므로 원격 peer가 요청할 수 없는 local op으로만 둔다(ADR-0022 결정 4·ADR-0025 결정 4와 같은 이유, ADR-0033 결정 4). 로컬 사용자는 같은 계정으로 이미 파일을 읽을 수 있으므로 이 op은 새 능력을 주지 않고 같은 내용을 계약된 모양으로 돌려줄 뿐이다. 읽기만 하고 audit 레코드를 남기지 않으므로 이 머신 상태에 부작용이 없다(§6.22).

역방향 host 등록은 operation이 아니라 **연결 수립 시점의 검사**다 — 위 표는 operation→ACL action 매핑이고 `qsh listen`/`qsh serve --to`(구 표기 `qsh reverse`, §6.13)는 §2.4가 명시하듯 operation이 아닌 장기 실행 모드이므로 표에 행을 만들지 않는다. `qsh serve --to`(target)가 `qsh listen`(controller)에 dial해 보내는 `Hello.reverse`(protocol.md §9·§11)를 controller가 인증서로 인증한 뒤, 그 principal에 ACL action `host.reverse`를 검사한다 — 통과해야만 registry에 등록된다(default deny, PRD §9).

## 3. JSON envelope

### 3.1 성공

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "host.list",
  "ok": true,
  "data": {
    "hosts": []
  }
}
```

### 3.2 실패

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "session.attach",
  "ok": false,
  "error": {
    "code": "PERMISSION_DENIED",
    "message": "peer is not allowed to perform this operation on this host",
    "retryable": false,
    "details": {}
  }
}
```

`message`는 사람을 위한 설명이다. 자동화는 `code`와 구조화된 `details`만 사용해야 한다.
`retryable`은 응답마다 값이 붙는 필드다 — 같은 `code`라도 `ErrorCode::default_retryable()`이
주는 기본값과 다를 수 있으므로(§6.1의 `reverse_registration_stale` 분기가 그 예다), 자동화는
`code`로부터 재시도 가능 여부를 스스로 유추하지 말고 이 필드를 읽어야 한다.

> 위 예시의 `message` 문안은 균일 거부 문면이다(`crates/qsh-core/src/acl/mod.rs`의 `PERMISSION_DENIED_MESSAGE`) — 원격 peer 대면 `PERMISSION_DENIED`는 어느 인가 지점(정책 거부, 소유권 거부, 감사 기록 실패에 의한 fail-closed 거부)에서 왔든 거부된 action/capability/resource/principal을 노출하지 않고 이 문장 그대로 나간다(`docs/ROADMAP.md` M5 감사 개정 ③). `message`는 계약이 아니므로(위 문단) 이 문안 자체는 `qsh.cli/v1` 호환성 대상이 아니지만, 상수와의 일치는 CI가 지킨다(`crates/qsh-core/tests/it/acl_docs.rs`).

### 3.3 기본 오류 코드

```text
INVALID_ARGUMENT
CONFIG_ERROR
HOST_NOT_FOUND
CONNECTION_FAILED
AUTH_FAILED
TRUST_REQUIRED
PERMISSION_DENIED
SESSION_NOT_FOUND
SESSION_CONFLICT
RESUME_GAP
TIMEOUT
CANCELED
REMOTE_ERROR
UNSUPPORTED
RESOURCE_EXHAUSTED
INTERNAL
```

오류 코드는 추가될 수 있다. 알 수 없는 code는 일반 QSH 오류로 처리한다. `RESUME_GAP`은 M2에서 **event 전용 상황**이다 — replay 범위 이탈은 항상 `session.gap` event(§6.4)로 전달되며 오류 envelope로는 반환되지 않는다(도달성 테스트에서는 이 사유로 DEFERRED 유지; 오류로 반환하는 strict read 옵션은 P1에서 검토). `UNSUPPORTED`는 요청한 기능이 아직 구현되지 않았거나 peer와 협상되지 않은 경우(예: `dial-filter.v1`을 advertise하지 않는 route 위의 `-D` — §6.9)에 사용한다. `RESOURCE_EXHAUSTED`는 backpressure나 서버측 한도 초과를 나타낸다.

## 4. Process exit code

일반 명령:

| Code | 의미 |
|---|---|
| `0` | QSH operation 성공 |
| `1` | `qsh doctor --fail-on`의 임계 이상 finding이 있음(operation 자체는 성공, §6.17) |
| `2` | CLI syntax 또는 argument 오류 |
| `255` | 연결, 인증, 정책 등 QSH runtime 실패 |

`qsh exec`는 OpenSSH와 마찬가지로 remote process의 exit code `0..254`를 그대로 반환한다. QSH 자체의 실패는 `255`다. JSON 결과에는 `remote_exit_code`와 QSH 오류가 구분되어 있으므로 자동화는 stdout JSON도 함께 확인한다.

Remote process가 정확히 `255`로 종료한 경우, QSH 자체 실패(`255`)와 구분할 수 없게 되는 것을 막기 위해 qsh exec의 프로세스 exit code는 `254`로 clamp된다. 이때도 JSON 결과의 `remote_exit_code`는 실제 값(`255`)을 그대로 담으며, exit code의 source of truth는 항상 JSON이다.

대화형 세션(`qsh [user@]host`, `qsh attach <session-ref>`, §7)은 원격 셸이 종료되면 그 exit code를 `qsh exec`와 같은 규칙(`0..=254`, `255`는 `254`로 clamp)으로 반환하고, escape 시퀀스 detach(§7)는 세션을 살려 둔 채 `0`으로 종료한다. 신호로 죽은 셸도 `qsh exec`와 같은 값이다: `session.exit`의 `signal`(§6.4)을 `128 + signo`로 되돌려 clamp 규칙에 태운다(예: `SIGHUP` → `129`, `SIGKILL` → `137`). `254`는 remote `255`의 clamp 결과이거나 **호스트가 종료 상태를 알려 주지 못한 경우**(`exit_code`와 `signal`이 모두 null, §6.4)를 뜻하며, 연결이 끊겨 종료 상태를 아예 받지 못한 경우는 QSH 자체 실패라 `255`다.

Output mode에 따라 exit code 의미가 달라져서는 안 된다. 대화형 form(§7)은 machine output mode 자체가 없으므로 이 규칙의 대상이 아니다 — `--json`/`--jsonl`을 붙이면 세션을 만들지 않고 `INVALID_ARGUMENT`로 거부한다(§7).

## 5. 핵심 data type

### Host

```json
{
  "name": "personal-mac",
  "address": "personal-mac.example.com:4433",
  "connection_mode": "forward",
  "state": "unknown",
  "device_id": "sha256:BASE64FINGERPRINT",
  "source": "both",
  "user": "dave"
}
```

`connection_mode ∈ {"forward", "reverse"}`. `state`는 열린 문자열(§10)이며 `∈ {"reachable", "stale", "unknown"}`: forward host는 도달성을 probe하지 않으므로 항상 `"unknown"`이다 — 확인하지 않은 것을 `"reachable"`로 보고하지 않는다. live 역방향 등록은 `"reachable"`(인증된 연결을 실제로 쥐고 있다), 죽은 등록은 보존 창 동안 `"stale"`이다(§6.13).

`device_id`는 **peer의 SPKI SHA-256 fingerprint 문자열**(`sha256:BASE64`, architecture.md §5의 표기)이다 — forward host는 trust store에 **핀된** fingerprint, reverse host는 상주 데몬이 **TLS로 검증한** peer fingerprint다. `Hello.device_name` 같은 wire 표시 이름은 어떤 경우에도 identity로 쓰지 않는다(protocol.md §3). `Host`는 이전까지 어떤 op도 emit한 적 없는 placeholder였고 fixture도 없었으므로, 위 값 어휘는 field의 **정의**이지 §10이 금지하는 기존 의미의 변경이 아니다. `device_id`는 **이 이름에 핀된 신원**이지 — `address`에 지금 실제로 누가 응답하고 있는지에 대한 관측이 아니다: forward host의 `address`는 `hosts.toml`에서 올 수 있지만 `hosts.toml`은 신원을 전혀 공급하지 않으므로, `address`가 어느 디렉터리에서 왔든 `device_id`는 항상 trust.toml이 그 이름에 핀한 peer를 가리킨다(아래 `source` 문단).

`source`/`user`는 **additive-optional** field다(§10) — `hosts.toml` 디렉터리가 전혀 없거나 항목이 하나도 없으면 두 field 모두 생략된다(키 자체가 나타나지 않는다, `null`이 아니라). `hosts.toml`에 항목이 하나라도 있으면 forward host마다 `source ∈ {"hosts", "trust", "both"}`를 보고한다 — 다만 이는 어느 디렉터리가 이 이름을 *아는지*가 아니라 **어느 디렉터리의 `address`가 실제로 이겼는지**를 가리킨다(§6.1 우선순위 참고): `hosts.toml`이 이 이름에 비어 있지 않은 주소를 설정했고 그 값이 `trust.toml`의 pin과 다르거나 `trust.toml`에 아예 pin이 없으면 `"hosts"`, `hosts.toml`에 항목이 없거나 그 주소가 빈 문자열이라 `trust.toml`의 pin된 주소가 그대로 쓰이면 `"trust"`, 양쪽 주소가 **일치할 때만** `"both"`다. reverse host는 항상 `source`가 생략된다 — 역방향 등록은 `hosts.toml`에서 오지 않는다. `user`는 `hosts.toml`이 그 이름에 설정한 hint가 있을 때만 나타나며 §7의 assertion hint와 동일한 의미다(계정 선택이 아니다).

**threat 참고.** `hosts.toml`에 쓰기 권한이 있다는 것은 어떤 이름을 이미 핀된 다른 peer로 돌릴 수 있는 권한이다(mTLS는 여전히 핀되지 않은 주소를 막는다) — 이런 redirect는 `source: "hosts"`로 드러난다(주소가 trust.toml의 pin과 다르거나, trust.toml에 pin이 아예 없는 경우).

`lost_at`은 issue #4가 추가한 **additive-optional** field다(§10) — reverse host가 `state: "stale"`일 때만 나타나며(키 자체가 생략된다, `null`이 아니라), 상주 데몬이 이 등록의 연결이 끊겼다고 관측한 순간을 RFC 3339 UTC로 담는다. `"reachable"` reverse host와 모든 forward host(도달성을 probe하지 않으므로 애초에 끊길 연결이 없다, 위 `state` 문단)는 항상 생략된다. 같은 순간을 `qsh.local.v1`의 `LocalHost.lost_at`이 컨트롤러 프로세스 내부에서 그대로 넘겨준다(`docs/design/protocol.md` §16.3, `crate::reverse::registry::Registry::mark_stale`).

### Session

```json
{
  "session_ref": "personal-mac/01K0SESSION",
  "host": "personal-mac",
  "session_id": "01K0SESSION",
  "state": "running",
  "writer": "device:hermes",
  "created_at": "2026-08-17T00:00:00Z",
  "last_sequence": 42
}
```

`session_ref`는 CLI가 반환하는 opaque value다. 호출자가 host와 session ID를 조합해 생성하지 않는다. 내부적으로는 **클라이언트의 `Ops` 계층**(qsh-core)이 `<host-alias>/<session_id>` 형태로 조립한다 — 서버는 opaque·URL-safe한 `session_id`만 발급하며 클라이언트의 로컬 host alias(trust store/hosts.toml의 이름)를 알지 못하기 때문이다. 조립 형식은 구현 세부이지 계약이 아니다: 호출자는 `session_ref`를 파싱하지 않고 받은 그대로 되돌려 주며, `Ops`가 이를 (host, session_id)로 해석한다([ADR-0007](adr/0007-session-ref-and-resume-token-custody.md)).

`writer`는 현재 writer lease 보유자의 principal 문자열 표기(architecture.md §5 — `fp:…`/`user:…`/`device:…`)이며, lease 보유자가 없으면(소유 connection이 죽어 lease가 자동 해제된 뒤, architecture.md §3) **`null`**이다. `writer`는 처음부터 nullable로 정의한다 — 나중에 nullable로 바꾸면 type 변경(§10, `/v2`)이 되기 때문이다. `host`와 `session_ref`는 클라이언트 `Ops`가 로컬 alias로 채우는 field이며 wire에는 존재하지 않는다(ADR-0007).

`last_sequence`는 chunk 개수가 아니라 이 세션에서 지금까지 누적된 output byte 수(offset)다. `session read --after`에 그대로 전달할 수 있다.

## 6. 명령 계약

### 6.1 Host 조회

```bash
qsh hosts --json
qsh host get personal-mac --json
```

`host.list`의 `data`는 `{"hosts": [Host, …]}`(§5 Host 배열)이고 `host.get`의 `data`는 Host 객체 하나다.

`hosts`는 두 데이터 소스를 합쳐 반환한다: forward host(`hosts.toml`과 `trust.toml`을 아래 우선순위로 합친 결과)와, 상주 `qsh listen` 데몬이 현재 쥐고 있는 live 역방향 등록(§6.13). **`host.list`는 dial하지 않는다** — forward host의 도달성은 확인하지 않으므로(§5, `state`는 항상 `"unknown"`) 이 목록은 순수 로컬 조회다. 같은 이름이 forward host와 reverse 등록 양쪽에 존재하면 `hosts` 배열에 `connection_mode`로 구분되는 **두 항목**으로 나타난다 — 목록에서는 병합하지 않는다. 다만 그 이름으로 실제 연결을 맺을 때(`exec`, attach, `qsh <name>`)의 **라우팅 우선순위는 live reverse 등록이 우선**이다 — 증명된 도달 가능 경로를 forward host의 추정 주소보다 앞세운다. `state: "stale"`인 reverse host는 `lost_at`을 함께 보고한다(§5) — `state`가 그 밖의 값이면 이 field는 생략된다.

라우팅(`host.get`, `exec`, attach)이 이름을 찾지 못하면 `HOST_NOT_FOUND`이지만, 그 원인에 따라 `retryable`이 달라진다(§3.2의 "응답마다 값이 붙는다" 규칙의 실례):

- 이름이 아예 미등록이거나(라이브 reverse 등록도, forward pin도 없음), 등록됐던 이름이 `[listen].stale_retention` 보존 창을 넘겨 이미 sweep된 경우: `retryable: false`. `details`는 비어 있다. 이 첫 갈래가 `qsh [user@]host`와 `qsh cp`의 자동 부트스트랩이 발동하는 조건의 전부다(§7 "이름이 없을 때의 자동 부트스트랩"). `hosts.toml`에 이름이 있거나, `trust.toml`에 pin이 있거나, reverse 등록이 stale로라도 남아 있으면 이 갈래가 아니다. 사람 모드는 이 갈래의 오류 줄 끝에 다음 명령을 덧붙인다: `qsh: <message>; or, if you can ssh to it, set it up with \`qsh pair ssh <name>\` (HOST_NOT_FOUND)`. envelope의 `message`와 `details`는 그대로라서 `--json`/`--jsonl` 출력과 기존 `error.HOST_NOT_FOUND*` fixture는 달라지지 않는다. 힌트는 이 갈래의 두 메시지(`host.get`·attach 쪽과 `qsh exec`의 "not in the trust store")에만 붙고, stale 갈래와 pin은 있으나 주소가 없는 갈래에는 붙지 않는다.
- 이름의 reverse 등록이 살아있지 않지만(연결이 끊겨 `state: "stale"`) 아직 그 daemon의 목록에 남아 있는 경우(`sweep_expired`가 아직 지우지 않았다는 뜻) — target이 재등록할 것으로 예상되는 일시적 상태이므로 `retryable: true`, `details`: `reason: "reverse_registration_stale"`, `lost_ago_ms`(`lost_at` 이후 경과 밀리초 — `lost_at` 자체가 초 단위로 기록되므로 최대 999ms까지 실제보다 크게 보고될 수 있다), `retry_after_ms`(컨트롤러의 `[reverse].backoff_max_ms` 유효값을 재시도 간격 힌트로 내려준 것 — 기본 30000). forward pin이 이 이름에 있으면 이 분기보다 먼저 그 pin으로 라우팅된다 — stale 등록은 live 등록과 마찬가지로 forward pin을 앞지르지 않는다.

**forward host 해석 우선순위 (`hosts.toml` vs `trust.toml`):** 같은 이름이 `hosts.toml`과 `trust.toml` 양쪽에 있으면 **`hosts.toml`의 `address`가 이긴다**. `trust.toml`에만 있으면 그 주소를, `hosts.toml`에만 있으면 그 주소를 쓴다. **fingerprint(신원)는 항상 `trust.toml`에서만 온다** — `hosts.toml`은 이름과 주소, `user` hint만 담는 순수 주소록이며 신원 판단에 절대 관여하지 않는다: `hosts.toml`이 어떤 이름에 주소를 대더라도 실제 dial 시 TLS 계층에서 그 주소가 제시한 fingerprint가 trust store 어딘가에 핀되어 있지 않으면 인증은 그대로 실패한다(pin 조회는 이름이 아니라 fingerprint 기준이다). `hosts.toml` 파일이 없거나 비어 있으면 이 절차에서 `trust.toml`의 pin이 유일한 출처다. `hosts.toml`은 **read-only 디렉터리**다 — 이를 쓰는 CLI 명령은 없으며 수동으로 직접 편집한다. `hosts.toml`에 쓰기 권한이 있다는 것은 곧 어떤 이름을 이미 핀된 다른 peer로 돌릴 수 있는 권한이다(mTLS는 여전히 핀되지 않은 주소를 막는다) — 그런 redirect는 `host.list`/`host.get`의 `source: "hosts"`로 드러난다(§5).

두 파일이 같은 주소를 포트 표기만 다르게 적었으면(`hosts.toml`이 `mac:4433`, `trust.toml`이 `mac`) 비교는 기본 포트를 채운 뒤에 하므로 `source`는 `both`다.

`hosts.toml`의 주소는 op 시작 시점에 한 번 resolve된다 — session이 열려 있는 동안 파일을 고쳐도 그 session에는 반영되지 않는다. `attach`가 끊긴 연결을 자동으로 재접속할 때도 최초 attach 시점에 resolve된 주소를 계속 쓴다(재resolve 없음). 이는 매 handshake마다 내용을 다시 읽는 `trust.toml`과 대비된다(§6.11 `trust remove` 문단). 이름 해석은 시스템 resolver를 쓴다. 한 번의 해석은 10초를 넘기면 `CONNECTION_FAILED`로 끝나며, `qsh serve --to`에서는 `cause`가 `resolve`인 실패 시도 하나가 된다. 기업 VPN처럼 DNS를 가로채는 환경에서 DNS를 피하려면 peer 주소를 IP 리터럴로 pin하거나 OS의 암호화 DNS 설정을 켠다. DoH를 강제하는 내장 resolver는 P2 후보다(ADR-0039 결정 2).

**`hosts.toml` 파일 계약.** `<config_dir>/hosts.toml`(`trust.toml`과 같은 디렉터리, architecture.md §7)에 다음 형식으로 둔다.

```toml
[[host]]
name = "personal-mac"
address = "personal-mac.example.com:4433"
user = "dave"
```

`name`·`address`는 필수, `user`는 선택이다. 파일이 없으면 빈 디렉터리로 취급한다(오류 아님) — `trust.toml`의 pin만으로 동작한다. 파싱 실패(TOML 문법 오류, 필수 필드 누락)는 `CONFIG_ERROR`(`retryable: false`)로, `trust.toml`이 손상됐을 때와 동일한 실패 형태다. 같은 `name`이 여러 번 나오면 첫 항목이 이긴다(`trust.toml`과 같은 규칙). `address`를 빈 문자열로 명시하면 파싱은 되지만 그 이름에 대해 `hosts.toml`은 "주소 없음"으로 취급되어 `trust.toml`의 주소로 폴백한다(`trust.toml`의 client-only pin과 동일한 관례).

`address`에 포트가 없으면 읽는 시점에 4433으로 해석한다. 파일은 다시 쓰지 않으므로 `hosts.toml`의 바이트는 그대로고 `host.list`/`host.get`이 돌려주는 값만 `host:port` 꼴이다. 빈 문자열에는 포트를 채우지 않는다 — 위의 "주소 없음" 관례가 그대로 이긴다.

### 6.2 Session 조회

```bash
qsh sessions [host] [--state <state>] [--writer <principal|none>] [--attachable] --json
qsh session get <session-ref> --json
```

`session.list`의 `data`는 `{"sessions": [Session, …]}`(§5 Session 배열)이고 `session.get`의 `data`는 Session 객체 하나다.

**`qsh sessions`를 host 없이 부르면** 주소가 있는 pinned host 전부에 fan-out한다. 이때는 **best-effort**다: 도달하지 못한 host는 결과를 감추지 않고 `data.unreachable`에 모아 보고하고(`[{"host": …, "code": "CONNECTION_FAILED", "message": …}, …]`, additive field이므로 비어 있으면 아예 생략된다) 나머지 host의 세션은 그대로 돌려준다. 잠든 노트북 한 대가 다른 host의 목록을 통째로 숨겨서는 안 되기 때문이다. **모든** host가 실패하면 그것은 부분 응답이 아니라 호출 실패이며, 마지막 오류의 `code`로 실패하고 `error.details.unreachable`에 같은 배열이 실린다. host를 명시한 단일 호출(`qsh sessions <host>`)은 fan-out이 아니므로 그 host의 실패가 곧 호출의 실패이고 `unreachable`은 항상 비어 있다. human 모드에서는 도달 실패가 stdout 표가 아니라 stderr 경고 줄로 나간다(§2.2). `session.list`는 그 host의 세션을 (ACL `session.list` 범위에서) 장비와 무관하게 반환한다. 다만 **`session.attach`(및 `qsh attach`)는 세션을 연 장비에서만 가능하다** — resume credential이 세션에 결합된 peer identity에 묶여 있고(protocol.md §10, PRD §9) 토큰은 그 장비의 상태 파일에만 있기 때문이다(§6.3, ADR-0007). 다른 장비에서는 목록에 `running`으로 보이더라도 attach는 로컬 `SESSION_NOT_FOUND`(`details.reason: "no_resume_token"`)로 실패한다 — 그리고 이 제한은 클라이언트의 편의가 아니라 **호스트가 강제한다**: credential 없이 보낸 `SessionAttach`는 non-distinguishing `AUTH_FAILED`로 거부되므로, 직접 wire를 말하는 peer도 우회할 수 없다. `session.get`/`read`/`write`/`resize`/`close`는 토큰이 아니라 ACL만으로 동작하므로 다른 장비에서도 가능하다 — 다만 `write`/`resize`는 ACL을 통과한 뒤 추가로 opener 결합을 거친다(§6.3).

**필터** ([ADR-0033](adr/0033-session-audit-management.md) 결정 1~3, 13). 세 플래그는 `qsh sessions`에만 있고 `session get`에는 없다.

| 플래그 | 남기는 세션 |
|---|---|
| `--state <값>` | `state`가 그 문자열과 정확히 같은 세션. §5 Session의 `state`는 열린 문자열 집합이고 대소문자를 구별한다. 모르는 값은 오류가 아니라 빈 결과다 |
| `--writer <principal\|none>` | `writer`가 그 principal 문자열과 같은 세션. 예약 값 `none`은 `writer: null`(아무 연결도 writer lease를 쥐지 않은 세션)을 가리킨다. principal 문자열은 응답한 host가 부르는 표기 그대로라서 host마다 같은 장비가 다른 문자열일 수 있다(forward host는 `device:laptop`, reverse host는 다른 표기). host 없는 fan-out에서 `--writer <principal>`이 여러 route의 세션에 같이 맞으려면 그 문자열이 host들 사이에서 일치해야 한다 |
| `--attachable` | 이 장비의 resume 상태 파일(§6.3)에 그 `session_ref`의 credential이 있고 만료되지 않은 세션. `qsh attach`가 `no_resume_token`으로 실패하지 않을 세션이다. 항목에 기록된 peer fingerprint는 보지 않으므로, 그 이름이 다른 장비로 다시 pin됐다면 attach는 여전히 `peer_mismatch`로 실패할 수 있다 |

여러 플래그를 주면 AND다. 필터는 **클라이언트 쪽**이다. `qsh`가 호스트(들)의 응답을 받은 뒤 이 장비에서 걸러내고, `SessionListReq`와 wire의 `SessionList`는 필터가 없을 때와 바이트 단위로 같다. 그래서 호스트는 필터가 걸린 호출과 아닌 호출을 구별하지 못하고, 돌려주는 집합도 오늘의 ACL `session.list` 범위 그대로다. 필터는 보이는 것을 줄일 뿐 넓히지 않으므로 인가 모델을 건드리지 않는다. `--attachable`은 클라이언트에만 있는 사실(credential 보유)을 쓰므로 서버 필터로는 만들 수 없다. 판정은 호출당 상태 파일을 한 번 읽어 `session_ref` 집합만 꺼내고, token 값은 필터·`data`·로그 어디에도 싣지 않는다([ADR-0007](adr/0007-session-ref-and-resume-token-custody.md)).

- **결과 모양.** `data`는 필터가 없을 때와 같은 `{"sessions": […]}`이고 필터를 되풀이하거나 개수를 알리는 필드는 없다. 남은 세션은 호스트가 준 순서 그대로다.
- **host 없는 fan-out.** `data.unreachable`과 "모든 host가 실패하면 호출 실패"는 필터와 무관하다. 필터가 모든 세션을 걸러내도 도달하지 못한 host는 가려지지 않는다.
- **human 모드.** 필터가 하나라도 걸려 있으면 stderr에 `qsh: showing M of N sessions`(N은 호스트들이 돌려준 수, M은 필터를 통과한 수) 한 줄을 낸다. stdout은 표(또는 `no sessions`)뿐이고(§2.2) `--json`·`--jsonl`에는 이 줄이 없다.
- **route.** 필터는 응답을 받은 뒤에 적용되므로 forward host(`qsh serve`)와 reverse host(`qsh sessions <reverse host>`, 그리고 fan-out에서 `qsh listen` 데몬을 거치는 reverse 항목)에서 같은 세션 집합에 같은 결과를 낸다. 플랫폼별로 다른 필터나 필드는 없다. Windows client에서도 같다. Windows host도 ConPTY 세션을 갖고(ADR-0035 결정 20·21) `--state`·`--writer`·`--attachable`은 그 세션의 같은 필드(`state`, `writer`, `attachable`)에 같은 규칙으로 걸린다. 세션이 하나도 없는 host의 빈 목록 위에서도 필터와 `data.unreachable`, `qsh listen` 데몬 fan-out의 reverse 항목이 같은 규칙으로 동작한다(ADR-0035 결정 14, ADR-0033 결정 13).

### 6.3 Session 생성

```bash
qsh session open personal-mac --json
qsh session open personal-mac --json -- claude
```

명령이 없으면 login shell PTY를 생성한다. `--` 뒤의 argv는 shell string으로 재해석하지 않는다.

결과:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "session.open",
  "ok": true,
  "data": {
    "session_ref": "personal-mac/01K0SESSION",
    "initial_sequence": 0
  }
}
```

wire `SessionOpened`가 반환하는 `resume_token`(protocol.md §10)은 **어떤 출력 모드에서도 JSON에 노출되지 않는다.** 토큰은 클라이언트 상태 파일 `$XDG_STATE_HOME/qsh/resume.json`(0600)에 `session_ref`를 key로 저장되고 rotation도 거기서 갱신된다. 기계 사용자는 `session_ref`만으로 재attach(`qsh attach <session-ref>`, §7.1)하며, 토큰 조회·제시는 `Ops` 계층이 내부에서 처리한다([ADR-0007](adr/0007-session-ref-and-resume-token-custody.md)). **토큰이 필요한 경로는 wire `SessionAttach`(= `session.attach`와 그 위의 대화형 attach)뿐이다.** `session.get`/`read`(`--wait`·`--follow` 모두)/`write`/`resize`/`close`는 control 스트림 value op(protocol.md §9 `SessionRead`/`SessionWrite` 등)이며 토큰 없이 ACL(§2.5)만으로 동작한다 — `--follow`는 `session.read`의 pull 루프이지 attach가 아니다. 상태 파일에 해당 `session_ref`의 토큰이 없으면(다른 장비, 상태 파일 삭제) attach는 원격 요청 없이 로컬에서 `SESSION_NOT_FOUND`(`details.reason: "no_resume_token"`, human `message`는 세션이 아직 살아 있어 `session read`/`close`는 가능함을 안내)로 실패한다 — fail closed. 상태 파일 항목에 기록된 peer fingerprint가 현재 연결의 peer와 다르면 토큰을 보내지 않고 같은 코드(`details.reason: "peer_mismatch"`)로 실패한다.

**`session.write`/`session.resize`는 ACL 통과 후 이 세션을 연 principal(opener)에도 결합된다** — §2.5의 ACL principal과 같은 축이며(§6.2의 attach가 쓰는, peer fingerprint에 결합된 resume credential과는 다른 축이다), M1–M4의 고정 장비 전용 posture에서는 principal이 장비 하나에 1:1로 대응하므로 사실상 장비 결합과 같다. `acl.toml`의 `scope` 키(§2.5, 기본값 `"owned"`)가 M5부터 이 결합을 실제로 판정한다 — 방금 설명한 opener 결합이 `scope = "owned"`(기본값)이고, rule에 명시적으로 `scope = "any"`를 준 경우만 이 결합을 벗어난다. principal이 다른 요청은 ACL을 통과하더라도 정책 거부와 문면이 동일한 `PERMISSION_DENIED`로 거부되고(어떤 세션이 누구 소유인지는 노출하지 않는다) `session.control` deny로 감사 기록에 남는다(PRD §6). **`session.get`/`read`/`close`는 이 결합의 영향을 받지 않고 §6.2의 ACL 범위를 그대로 따른다 — `scope = "owned"`가 걸린 rule 아래에서도 마찬가지다.** `close`가 `write`/`resize`와 같은 `session.control` action을 쓰면서도 이 결합에서 빠진 것은 우연이 아니라, PRD §6이 요구하는 교차 기기 종료(꺼진 장비가 남긴 세션을 다른 장비에서 정리하는 시나리오)를 위한 의도적인 예외다(`docs/design/architecture.md` §6).

### 6.4 Session 읽기

```bash
qsh session read <session-ref> --after 42 --wait 30000 --json
qsh session read <session-ref> --after 42 --follow --jsonl
```

- `--after`: 마지막으로 수신한 누적 output byte offset (sequence)
- `--ctl-after`: 마지막으로 수신한 **control entry id** — 직전 응답의 `next_ctl_after`를 그대로 되돌려준다. 생략하면 `0`(처음부터).
- `--wait`: 새 output을 기다릴 최대 milliseconds. 호스트는 이 값도 상한(현재 60 s, `SESSION_READ_MAX_WAIT`)으로 clamp한다 — `--limit-bytes`와 같은 취급으로, 더 큰 값은 오류가 아니라 상한이다. 더 오래 기다리려면 같은 cursor로 다시 부른다. `--follow`와 함께 쓰면 이 값은 **하한 30 s 아래로 내려가지 않는다** — follower는 parking 하는 것이지 spin 하는 것이 아니므로, 단발 pull용으로 준 작은 `--wait`이 follow loop을 tight round-trip loop으로 만들지 않는다.
- `--follow`: 종료나 취소까지 event를 계속 출력
- `--limit-bytes`: 한 응답의 최대 payload. 호스트는 이 값을 상한(현재 192 KiB, `SESSION_READ_MAX_BYTES`)으로 clamp한다 — 더 큰 값은 오류가 아니라 상한으로 취급된다.

단일 JSON 응답은 event 배열을 반환한다: `data`는 `{"session_ref": "...", "events": [Event, …], "next_after": <sequence>, "next_ctl_after": <id>}`이며 각 원소는 아래 event 객체 그대로다. `--follow --jsonl`은 event 하나당 한 줄을 출력한다. `--follow`는 값 하나가 아니라 stream이므로 `--json`과 함께 써도 같은 streaming 형태(event 하나당 한 줄, envelope 없음)를 출력한다 — envelope는 단발 value operation의 형태이고 follower에는 적용되지 않는다. 실패 보고는 영향받지 않는다: `--follow`의 실패는 두 모드 모두 §4의 동일한 error envelope와 동일한 exit code다.

**Cursor는 두 값이다.** `session.exit`/`session.writer_changed`/`session.closed`는 zero-length control entry라서 자신이 append된 시점의 offset을 달고 나오지만 offset을 **증가시키지 않는다**(아래 "전달 경로와 순서"). 따라서 `--after` 하나로는 "offset N에 있는 control event는 이미 받았다"를 표현할 수 없다. `next_after`/`next_ctl_after`를 그대로 `--after`/`--ctl-after`로 되먹이는 소비자는 모든 event를 **정확히 한 번** 받는다. 되먹이지 않는 소비자(`--ctl-after` 생략)는 offset이 정확히 `--after`인 control event를 **매번 다시** 받으며(at-least-once), `--wait` 폴링 루프는 그 event 때문에 즉시 반환되어 대기하지 않는다 — 폴링 루프는 반드시 두 값을 함께 되먹여야 한다.

소비자 규칙의 정확한 범위: "알 수 없는 event `type`은 무시"는 **`type` 문자열이 미지인 경우**에만 적용된다. 알려진 `type`(`session.output` 등)인데 필수 필드가 없거나 타입이 틀린 event는 잘못된 입력이며, 소비자는 이를 건너뛰지 말고 오류로 처리해야 한다(조용한 output 손실 금지, PRD §8).

**Sequence 시맨틱**: `sequence`는 세션 시작(0)부터 누적된 output byte 수이며 chunk index가 아니다. 각 `session.output` event의 `sequence`는 그 chunk까지 포함한 누적 byte offset, 즉 chunk의 마지막 byte offset + 1이다. `--after N`은 누적 offset `N` 이후의 byte를 요청한다. 서버는 chunk를 자유롭게 분할·병합할 수 있으므로 클라이언트가 매번 같은 크기로 chunk를 받는다고 가정해서는 안 되지만, replay는 항상 정확히 `N`에서 끊어 재개할 수 있다. 아래 예시는 `--after 42`로 요청한 뒤 7 byte(`Hello\r\n`) chunk 하나를 받아 누적 offset이 `49`가 된 상황이다.

Output event:

```json
{
  "schema": "qsh.event/v1",
  "type": "session.output",
  "session_ref": "personal-mac/01K0SESSION",
  "sequence": 49,
  "data_b64": "SGVsbG8NCg=="
}
```

Gap event:

```json
{
  "schema": "qsh.event/v1",
  "type": "session.gap",
  "session_ref": "personal-mac/01K0SESSION",
  "requested_after": 42,
  "available_from": 120
}
```

`available_from`은 replay buffer가 보존하고 있는 가장 오래된 byte offset이다. `requested_after`가 `available_from`보다 작으면 그 사이 byte는 영구히 유실된 것이며, QSH는 이를 숨기지 않고 gap event로 명시한다.

Input(`session write`) 방향에도 동일한 누적 byte offset 모델이 적용된다. 다만 input side의 재전송/중복 제거(`input_seq`+ack)는 내부 프로토콜 동작이며, 이 문서가 정의하는 CLI 계약에는 별도 field가 없다.

Exit event:

```json
{
  "schema": "qsh.event/v1",
  "type": "session.exit",
  "session_ref": "personal-mac/01K0SESSION",
  "sequence": 180,
  "exit_code": 0,
  "signal": null
}
```

`exit_code`와 `signal`은 둘 중 하나만 채워진다(정상 종료 → `exit_code`, 신호 종료 → `signal`, `SIGTERM` 정규형). **둘 다 `null`이면 호스트가 child의 종료 상태를 알 수 없었다는 뜻이다**(reap 실패 등 예외 경로) — 소비자는 "종료했으나 상태 미상"으로 처리한다.

Writer changed event (wire `SessionEvent::WriterChanged`, protocol.md §10 writer lease). writer lease 보유자가 바뀔 때마다 — steal로 다른 attach가 가져갔을 때, 또는 소유 connection이 죽어 lease가 자동 해제됐을 때(그때 `writer: null`) — 발생한다. **세션의 모든 read 소비자에게 broadcast**되는 세션 상태 변화 event다(lease를 뺏긴 기존 보유자에게는 read-only 강등 통지를 겸한다; `writer` principal은 이미 `session.list`의 `Session.writer`로 같은 ACL 범위에 노출되는 값이므로 새 정보 누설은 없다). `writer`는 §5 Session의 `writer`와 같은 형식(새 보유자의 principal 문자열, 없으면 `null`)이고 `sequence`는 event 시점의 누적 output byte offset이다.

```json
{
  "schema": "qsh.event/v1",
  "type": "session.writer_changed",
  "session_ref": "personal-mac/01K0SESSION",
  "sequence": 180,
  "writer": "device:hermes"
}
```

Closed event (wire `SessionEvent::Closed`). 세션이 broker에서 제거되어 더 이상 read/attach할 수 없을 때 stream의 **마지막 event**로 전달된다. `reason`은 **누가 세션을 제거했는가**로 정해지며 세션의 이전 상태와 무관하다: `"closed"` = 명시적 `session.close`(세션이 `running`이든 이미 `exited`든) 또는 `qsh serve`의 SIGTERM drain(§6.12); `"exit"` = child가 스스로 종료해 `exited`가 된 세션을 **호출자 없이** TTL reaper가 정리(앞서 `session.exit`가 먼저 온다; `exited` 세션도 같은 `[serve].resume_ttl`을 exit 시점부터 적용해 정리한다); `"ttl_expired"` = **실행 중이던** 세션이 attach 없이 resume TTL을 넘겨 reaper가 process group을 종료. 알 수 없는 `reason` 값은 "세션이 끝났다"로만 해석한다(값 추가는 additive, §10). 이후 같은 `session_ref`에 대한 `session.get`/`read`/`write`/`resize`/`close`는 `SESSION_NOT_FOUND`다; `session.attach`는 protocol.md §10의 non-distinguishing 규칙에 따라 호스트가 `AUTH_FAILED`로 답하며(세션 존재 여부 비노출), 클라이언트는 이 event를 받으면 `resume.json` 항목을 지우므로 실제로는 로컬 `SESSION_NOT_FOUND`(`no_resume_token`)로 먼저 실패한다. 이 `AUTH_FAILED`는 credential 제시 여부와 무관하다 — 세션이 제거되면 그 resume credential도 함께 폐기되고, credential을 **제시하지 않은** `SessionAttach`는 호스트가 같은 `AUTH_FAILED`로 거부하기 때문이다(§6.3: attach는 항상 credential을 요구한다).

```json
{
  "schema": "qsh.event/v1",
  "type": "session.closed",
  "session_ref": "personal-mac/01K0SESSION",
  "sequence": 180,
  "reason": "closed"
}
```

두 event는 `qsh.event/v1`에 additive로 추가된 타입이다(§10). **소비자는 알 수 없는 event `type`을 오류 없이 무시(skip)해야 한다** — 알 수 없는 field를 무시하는 §2.3 규칙의 event 수준 대응이며, 새 event 타입은 major bump 없이 추가될 수 있다. `qsh.event/v1`은 아직 출시된 producer가 없으므로 이 규칙은 v1 최초 구현부터 적용된다(`qsh-proto`의 event 타입은 unknown-type fallback을 가져야 한다, architecture.md §2).

**전달 경로와 순서.** `session.exit`/`session.writer_changed`/`session.closed`는 broker가 ReplayRing에 **zero-length 제어 엔트리**로 append하며, `pull()`(architecture.md §3)의 반환 event 열에서 `session.output`과 **전순서(total order)** 로 섞여 나온다 — 단발 `session read --wait` 결과 배열에도 그대로 포함될 수 있다. 이 event들의 `sequence`는 append 시점의 누적 output offset이며 offset을 증가시키지 않는다. attach 중인 connection은 같은 event를 control 스트림의 wire `SessionEvent`로도 받는다.

**`--follow`의 종료.** `--follow`는 `session.exit`를 수신하면 즉시 정상 종료한다(exit `0`) — TTL 정리(`session.closed{reason:"exit"}`)를 기다리지 않는다. 실행 중이던 세션이 `session.close`/reaper로 제거되면 `session.closed`가 마지막 event이고 그 직후 종료한다.

Recovery 텔레메트리(`recovery ∈ {migrated, resumed, failed}`, `time_to_recovery_ms`, `session_ref`; testing.md L4)는 M2에서 `qsh.event/v1` event가 **아니라** stderr 구조화 진단(tracing target `qsh::recovery`, level `INFO`, **한 줄 JSON** 렌더링 — 기본 verbosity에서 방출되고 §2.2의 `--quiet`/`-v` 규칙을 그대로 따른다; PTY 내용·토큰 field는 존재하지 않는다)으로만 나가며 stdout에는 절대 나타나지 않는다(§2.2). event로의 승격은 P1에서 결정한다.

이 진단은 additive field `registration_wait_ms`(밀리초, `u64`)를 싣는다 — 정방향(`DialReconnect`)은 항상 `0`(재등록을 기다릴 대상이 없다), 역방향(`LocalReconnect`)은 controller의 attach driver가 target의 새 `generation` 등록을 기다린 시간이다. 라인의 키 순서는 앞의 세 field 뒤에 이 field가 오는 것으로 고정된다(`{"recovery":…,"time_to_recovery_ms":…,"session_ref":…,"registration_wait_ms":…}`) — 접두사만 읽는 기존 소비자는 영향받지 않는다. **`recovery` 값 집합 자체는 바뀌지 않는다**(`migrated`가 역방향에서 나오는 일은 없다 — 이 leg에 migration/rebind이 없다는 것이 설계 그 자체다, protocol.md §11-4). 이 field는 `time_to_recovery_ms`를 **분해**하는 값이지 별도 시계가 아니다: `time_to_recovery_ms - registration_wait_ms`가 재등록 이후 resume 자체가 쓴 시간이고, 그 값이 정방향과 동일한 2초 예산에 묶인다(testing.md L4) — target의 재dial backoff까지 qsh의 예산으로 세지 않기 위함이다.

**keep-alive 설정.** 대화형 attach(`qsh [user@]host`, `qsh attach`)는 route를 해석하거나 dial하기 전에 이 머신의 `config.toml`에서 `[transport].keep_alive_ms`(§6.12, 기본 15000, `1000..=20000`)를 읽어, 최초 dial과 recovery의 재dial에 같은 값을 쓴다. 범위 밖이거나 파일을 파싱할 수 없으면 `CONFIG_ERROR`(`retryable: false`)로 끝난다. 전에는 attach가 `config.toml`을 읽지 않았으므로 이 실패 경로는 새것이다. 키가 없으면 동작은 바이트 단위로 같다. 역방향 route의 attach는 데몬이 쥔 연결을 쓰므로 이 값이 닿지 않는다. 그 밖의 일회성 op(`exec`, `session read/write`, `probe`, trust pairing 등)는 `config.toml`을 읽지 않고 컴파일된 기본값 15초로 dial한다.

**경로 감시 설정.** 같은 시점에 `[recovery]`(§6.12, `probe_interval_ms`·`min_dead_after_ms`·`strikes`)도 읽어 attach의 경로 사망 감지에 쓴다. `reverse_*` 키는 attach에 닿지 않는다. 범위 밖이면 `CONFIG_ERROR`(`retryable: false`)로 끝나고 키가 없으면 동작은 바이트 단위로 같다. attach 연결을 감시하는 쪽은 이 클라이언트뿐이다. 호스트의 `qsh serve`에는 forward 연결을 보는 감시가 없으므로(§6.12) 호스트의 `[recovery]`를 올려도 attach의 사망 판정은 달라지지 않고, 이 머신의 값만 효과가 있다.

### 6.5 Session 쓰기

```bash
printf 'continue\n' | qsh session write <session-ref> --stdin --json
qsh session write <session-ref> --data-b64 Yw== --json
```

`--stdin`과 `--data-b64`는 상호 배타적이다. 전자는 raw stdin bytes, 후자는 명시적인 Base64 bytes를 전송한다. 한 번의 `session.write`가 받는 입력은 **16 MiB**로 제한된다(`SESSION_WRITE_MAX`) — 단일 value op의 envelope은 유계여야 하므로, 초과분은 `INVALID_ARGUMENT`이고 `--stdin`은 상한을 넘겨 버퍼링하지 않는다. 더 큰 입력은 반복 write나 attach로 흘려보낸다. (호스트는 이 입력을 16 KiB wire chunk로 나눠 같은 connection에서 순서대로 보낸다.)

결과 `data`는 `{"session_ref": "...", "bytes_written": <accepted byte count>}`다. ACL을 통과해도 이 세션을 연 principal이 아니면 `PERMISSION_DENIED`다(§6.3).

### 6.6 Terminal resize

```bash
qsh session resize <session-ref> --cols 120 --rows 40 --json
```

결과 `data`는 적용된 크기를 되돌려 준다: `{"session_ref": "...", "cols": 120, "rows": 40}`. ACL을 통과해도 이 세션을 연 principal이 아니면 `PERMISSION_DENIED`다(§6.3).

### 6.7 Session 종료

```bash
qsh session close <session-ref> --json
qsh session close <session-ref> --signal TERM --json
```

`session.close`는 세션의 **process group 전체**(architecture.md §4)를 종료하고 세션을 broker에서 제거한다. 기본 절차는 SIGHUP → 유예 후 SIGTERM → 유예 후 SIGKILL escalation이며, 단계별 유예는 `[serve].close_grace_ms`(기본 5000)다. `--signal <SIG>`는 이 절차의 **첫 신호를 지정한 신호로 바꾼다** — 신호를 process group에 보낸 뒤 동일한 유예·escalation과 세션 정리가 이어진다. `--signal`은 wire `SessionClose`의 optional `signal` field로 전달되며(§2.4), 허용 값은 `HUP|INT|QUIT|TERM|USR1|USR2|KILL`(대소문자 무시, `SIG` 접두 유무 무관)뿐이다. 그 외(숫자, stop 계열 `STOP`/`TSTP`, 미지의 이름)는 `INVALID_ARGUMENT`(exit `2`)다. 이름은 내부적으로 `SIGTERM` 형태의 정규형으로 정규화되며 `session.exit`의 `signal` field도 같은 정규형을 쓴다. `--signal KILL`은 escalation 없이 즉시 `killpg(SIGKILL)` 후 정리다. 세션을 종료하지 않고 신호만 보내는 operation은 M2에 없다(§2.4, P1). 종료가 완료되면 `--follow` 소비자는 `session.closed{reason: "closed"}` event(§6.4)를 받는다. 이미 종료된(`exited`) 세션의 close는 **어떤 신호도 보내지 않고**(재사용된 pgid로 무관한 프로세스에 신호가 갈 수 있다) 정리만 수행하며 오류가 아니다 — 이때도 `reason`은 `"closed"`다. close는 그 세션에 발급된 미상환 데이터 스트림 티켓도 함께 해제한다.

결과 `data`는 `{"session_ref": "...", "final_sequence": <제거 시점의 누적 output byte offset>}`다.

**Windows host(ADR-0035 결정 3·22).** 세션의 "process group"은 세션마다 하나인 Job Object다(`KILL_ON_JOB_CLOSE`, 자식이 만들어지는 순간부터 그 안에 있다). Windows에는 신호가 없어서, 일곱 이름은 각각 그 자리를 맡는 사건으로 사상된다.

| 신호 | Windows host가 하는 일 |
|---|---|
| `INT` | `CTRL_C_EVENT`를 세션 콘솔의 모든 프로세스에 보낸다 |
| `QUIT` | `CTRL_BREAK_EVENT`를 같은 곳에 보낸다 |
| `HUP`, `TERM` | 의사 콘솔을 닫는다(콘솔에 붙은 프로세스에 `CTRL_CLOSE_EVENT`) |
| `USR1`, `USR2` | 세션의 이름 있는 이벤트를 `SetEvent`한다 |
| `KILL` | Job Object를 종료한다(트리 전체가 즉시 끝남) |

`INT`와 `QUIT`는 같은 바이너리의 숨김 진입점 `qsh internal console-ctrl <pid> <c|break>`가 보낸다. host가 이 보조 프로세스를 `DETACHED_PROCESS`로 띄우면 그것이 세션 루트의 콘솔에 붙어 자기 자신은 사건을 무시한 채 콘솔의 모든 프로세스에 사건을 보내고 끝난다. 보조 프로세스는 `GenerateConsoleCtrlEvent`가 0이 아닌 값을 돌려준 바로 뒤에 표준 출력으로 한 바이트(`+`)를 써서 전달을 스스로 알리고(출력이 터미널이면 쓰지 않는다), 실패하면 아무것도 쓰지 않는다. host는 그 바이트를 제한 시간 안에 기다리므로 `INT`·`QUIT` 단계의 성공 여부가 동기로 정해진다. 바이트가 없으면 그 단계는 오류이고 종료 상태에 그 신호가 남지 않는다. 종료 코드로는 실패와 "전달 뒤 콘솔이 닫히며 끝남"을 가를 수 없어서 보고를 보조 프로세스가 맡는다. host 자신은 콘솔에 붙지 않는다. 진입점은 `--help`와 man 페이지에 나오지 않고, 인자는 프로세스 id와 `c` 또는 `break`뿐이다. 입력에 `0x03`을 쓰는 방식은 쓰지 않는다. 터미널 모드를 끈 프로그램은 그 바이트를 문자로 읽는 반면, unix의 `killpg(SIGINT)`는 모드와 무관하게 닿기 때문이다. `HUP`과 `TERM`은 같은 사건이어서 `HUP` 다음의 escalation `TERM` 단계는 아무것도 다시 보내지 않고 유예만 지난다. `USR1`과 `USR2`가 `SetEvent`하는 이벤트의 이름은 세션 환경변수 `QSH_SIGNAL_EVENT_USR1`·`QSH_SIGNAL_EVENT_USR2`에 있다(§7). 그 이벤트를 기다리는 프로그램이 없으면 아무 일도 일어나지 않는다.

기본 절차(`HUP` → `TERM` → `KILL`, `close_grace_ms`)와 `exited` 세션에는 신호를 보내지 않는 규칙은 unix와 같다. `--signal`은 이 절차의 첫 신호만 바꾸므로, 어느 신호로 시작하든 유예 뒤 escalation(의사 콘솔 닫기 → `KILL`)이 이어져 세션은 결국 끝난다. 자식이 아직 콘솔에 붙기 전에 보낸 `HUP`이나 `INT`는 아무에게도 닿지 못하고 `KILL` 단계가 끝낸다. `session.exit`의 `exit_code`는 Windows 종료 코드(u32)를 비트 그대로 `i32`로 옮긴 값이다. `signal`은 qsh가 마지막으로 보낸 단계의 신호 정규형이고(`INT`를 보낸 뒤 프로그램이 끝났으면 `SIGINT`, `KILL`이면 `SIGKILL`), qsh가 아무것도 보내지 않고 세션이 스스로 끝났으면 `null`이다.

### 6.8 비대화형 실행

```bash
qsh exec personal-mac --json -- uname -a
qsh exec personal-mac --json --timeout 5000 --env FOO=bar -- sh -c 'echo "$FOO"'
```

`host` 인자는 host 이름이다. host 라우팅은 §6.1의 우선순위를 그대로 따른다 — 이름에 live reverse 등록이 있으면 forward pin보다 그것이 이기고, 없으면 forward pin(`hosts.toml` 우선, 없으면 `trust.toml`의 pinned peer)으로 폴백한다(issue #5). `exec`는 attach·`session open`과 이 라우팅 전체를 공유하는 세 번째 호출자다 — 이름 조회(=§6.1 우선순위 전체)가 실패하면 그것이 곧 최종 실패이고 다른 폴백은 없다. 이 셋은 `qsh serve --to <listener>`(구 표기 `qsh reverse <controller>`)의 controller dial과는 다르다 — `--to`는 live reverse 등록을 애초에 참조하지 않는 forward-only 조회이고, 그 위에 이름 조회가 실패했을 때 주소로 한 번 더 시도하는 2단계 해석(§6.13, ADR-0014 결정 7)을 추가로 갖는다.

- 실행할 명령은 항상 `--` 뒤에 온다(`--` 이후는 qsh가 해석하지 않는다). `--` 뒤에 명령이 없으면 usage 오류(exit `2`)다.
- `--timeout <milliseconds>`(§9): 기한 내 종료하지 않으면 remote 프로세스(unix는 process group, Windows는 Job Object 전체)를 kill하고 `TIMEOUT`(`retryable: true`, `details.timeout_ms`)을 반환한다. 기한은 해석·연결·협상·실행 전체에 하나의 예산으로 적용되고, 종료 후 연결 정리 시간은 포함하지 않는다(제때 끝난 명령이 정리가 느리다고 `TIMEOUT`이 되지 않는다). 호스트도 같은 기한을 스스로 강제하며(`ExecExit.timed_out`), 어느 쪽이 먼저 걸리든 결과는 `TIMEOUT`이다. 이 예산 **밖에** 있는 비용이 하나 있다 — §6.1 우선순위가 live reverse 등록을 찾으려 이 머신의 상주 `qsh listen` 데몬들(`<pid>.sock`)을 조회하는 단계는 `exec_async`/`exec_async_reverse`가 자신의 기한을 재기 시작하기 전에 끝나며, 각 소켓 조회는 병렬로 최대 1초(`ADMIN_LIST_CANDIDATE_TIMEOUT`)까지 걸릴 수 있다 — 잠긴 로컬 데몬 소켓 하나가 있으면 `--timeout 300`을 준 `qsh exec`도 체감상 약 1.3초까지 걸릴 수 있다는 뜻이다.
- `exec.run`은 출력 전체를 한 envelope에 담으므로 stdout+stderr 합계에 상한(64 MiB)이 있다. 초과하면 remote 명령을 중단하고 `RESOURCE_EXHAUSTED`(`details.limit_bytes`)를 반환한다 — 대용량·스트리밍 출력은 session(§6.4, M2)의 몫이다.
- `--env NAME=VALUE`(반복 가능): remote 명령의 환경 변수를 추가한다.
- Windows host에서는 `exec`도 세션처럼 자식을 만들어지는 순간부터 Job Object 안에 둔다. 그래서 `--timeout`이나 출력 상한으로 명령을 끝내면 자식이 띄운 손자 프로세스까지 함께 끝나고, 타임아웃 kill로 끝난 자식의 종료 코드는 `1`이다. `exec`는 셸을 거치지 않으므로 `argv[0]`은 실행 파일이어야 한다. `dir`·`echo`·`type` 같은 `cmd.exe` 내장 명령이나 `>` 리디렉션·파이프가 필요하면 `qsh exec win-host -- cmd /c "dir C:\\"`처럼 `cmd /c`를 앞에 붙인다. `signal`은 항상 `null`이다. 자식의 환경과 `argv[0]` 탐색 규칙은 §7의 "Windows host의 세션"과 같고(`TERM`만 더해지지 않는다), 작업 디렉터리는 `qsh serve`의 것을 그대로 쓴다.
- local stdin이 terminal이 아니면(pipe/file) EOF까지 remote 명령의 stdin으로 전달하고, terminal이면 remote stdin을 즉시 닫는다.
- human mode에서는 remote stdout/stderr 바이트를 각각 local stdout/stderr에 그대로 통과시키고, exit code는 §4 규칙을 따른다.

결과는 stdout과 stderr를 별도 Base64 field로 반환한다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "exec.run",
  "ok": true,
  "data": {
    "stdout_b64": "RGFyd2luCg==",
    "stderr_b64": "",
    "remote_exit_code": 0,
    "signal": null,
    "duration_ms": 18
  }
}
```

### 6.9 Tunnel

```bash
qsh tunnel open personal-mac --local 8080:localhost:3000 --json
qsh tunnel open server --remote 9000:localhost:9000 --json
qsh tunnels --json
qsh tunnel close <tunnel-id> --json
```

**Spec grammar.** `--local`(`-L`)과 `--remote`(`-R`)는 같은 grammar를 공유한다: `[bind:]listen_port:host:host_port`(예: `8080:localhost:3000`, IPv6 bind는 `[::1]:8080:localhost:3000`처럼 대괄호로 감싼다). `listen_port`/`host_port`는 `1..=65535`만 유효하며 `0`과 `65536`은 파싱 단계에서 `INVALID_ARGUMENT`다. 이 grammar를 파싱하는 `qsh-proto::wire::parse_forward_spec`은 sans-IO 순수 함수이고 **모양만** 검사한다 — non-loopback `bind`도 grammar상으로는 유효하게 파싱된다. `-L`은 로컬 머신에서 `listen_port`를 열고 들어오는 각 TCP 연결마다 host에 `host:host_port`로 dial을 요청하며, `bind`를 생략하면 loopback에 bind한다. `-R`은 반대 방향이다: host가 자신의 `listen_port`를 열고 들어오는 각 연결을 로컬 머신의 `host:host_port`로 되돌려 보낸다 — **non-loopback `-R` bind는 host 쪽에서 `INVALID_ARGUMENT`로 거부된다**(parser는 모양만 검사하고, loopback-only는 파서가 아니라 host가 강제하는 policy다). 그 거부의 `message`는 정확히 "remote forward binds loopback only: this bind could not be confirmed as a loopback address, so nothing was opened on the host. Re-run `-R` with a loopback bind (omit the bind, or use `127.0.0.1` / `[::1]`)."다(`qsh_core::tunnel::REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE`, `docs/design/testing.md` L6 — README와 이 문구가 그 상수와 어긋나면 CI가 실패한다). 관측절 뒤의 문장은 non-loopback IP 리터럴, non-loopback으로 해석된 이름, 빈 응답 집합, resolver 실패, 해석 타임아웃 다섯 경우 전부에 그대로 참이다 — 다섯을 하나로 합치는 것은 실수가 아니라 host의 resolver 거동(이름이 존재하는가, 타임아웃이 걸렸는가)을 이 응답으로 probe하지 못하게 막는 설계다.

`-R`은 리스너를 bind하기 전에 두 층을 순서대로 통과해야 한다: 먼저 host가 `forward.remote`(§2.5)로 principal을 ACL 평가하고, 거부면 `PERMISSION_DENIED`이며 아무것도 뜨지 않는다. 통과한 뒤에야 위 loopback 강제가 적용되고, 위반이면 `INVALID_ARGUMENT`다(마찬가지로 아무것도 뜨지 않는다). 두 거부는 층이 다르다는 점이 핵심이다 — 하나는 그 principal이 `forward.remote`를 가졌는지 판정하는 ACL이고, 다른 하나는 `forward.remote`를 **가진** principal에게도 예외 없이 적용되는 host 쪽 요청 제약이다(`docs/PRD.md` §9).

**`-R`을 닫는 쪽(`tunnel.close`)도 host 쪽 ACL choke point다.** `RemoteForwardOpen`을 보낸 principal만 그 `forward_id`를 닫을 수 있다 — 다른 principal이 시도하면 host는 그 forward를 건드리지 않고 `PERMISSION_DENIED`로 거부한다(§3.2와 byte-for-byte 동일한 문면). 이 거부가 "존재하지 않는 forward_id"와 "남의 forward_id"를 구별 불가능하게 만드는 것은 그 principal이 **`forward.remote` 권한 자체를 갖지 못한 경우뿐**이다— 그때는 ACL 게이트가 principal 일치 단계에서 이미 걸려 두 경우 모두 같은 `PERMISSION_DENIED`다. `forward.remote`는 가졌지만 이 forward의 소유자가 아닌 principal에게는 두 경우가 갈린다: 남의 실재하는 forward_id는 `scope = "owned"`가 걸러 `PERMISSION_DENIED`, 존재하지 않는 forward_id는 owner가 없어 scope에 걸러지지 않고 ACL 게이트를 통과한 뒤에야 등록표에 없어서 `INVALID_ARGUMENT`("no such forward_id")다 — `session.write`/`resize`가 남의 세션과 존재하지 않는 세션에 각각 `PERMISSION_DENIED`/`SESSION_NOT_FOUND`를 주는 것과 M3이 이미 받아들인 것과 같은 트레이드오프다. 소유 축은 `RemoteForwardOpen`을 실어 나른 QUIC connection이 아니라 그것을 **보낸 principal**이다 — `acl.toml`의 `scope`(§2.5, 기본값 `"owned"`)가 세션의 `session.control`과 같은 어휘로 이 축을 판정하며, 같은 principal이 다른 connection으로 재접속해도 자신이 연 forward는 여전히 닫을 수 있다(`docs/design/protocol.md` §7). 이 검사는 §6.13·§6.14가 다루는 **로컬 머신** 축(localctl의 `NotOwner`, same-uid 두 CLI 프로세스 사이의 conduit 소유권)과는 완전히 다른 층이다 — 그쪽은 원격 peer 인가가 아니어서 `PERMISSION_DENIED_MESSAGE`를 쓰지 않는다(`docs/design/architecture.md` §6).

**JSON envelope.** `tunnel.open`의 `data`는 아래 `Tunnel` 하나다:

```json
{
  "tunnel_id": "01K0TUNNEL",
  "mode": "local",
  "bind": "127.0.0.1:8080",
  "forward_to": "localhost:3000",
  "actual_port": 8080,
  "host": "personal-mac"
}
```

`mode`는 §10과 같은 열린 문자열(open string)이며 `∈ {"local", "remote"}`(`connection_mode`와 같은 패턴 — 값 집합이 늘어나도 type 변경이 아니다). `actual_port`는 optional이다 — bind 시점에 실제로 배정된 port를 돌려주는 field로, ephemeral(`0`) 요청이거나 요청 port를 그대로 못 받았을 때 요청값과 달라진다. optional인 이유는 아직 bind되지 않은 tunnel에는 보고할 port가 없기 때문이고, **bind된 port를 아는 producer는 요청 port가 그대로 배정된 fixed-port forward에서도 항상 이 field를 채운다**(위 예시가 그렇다) — reader가 field 부재를 만나 `bind`를 되쪼개는 일이 없게 하기 위함이다. `host`는 클라이언트 `Ops`가 채우는 alias field이며 wire에는 없다 — `Session.host`/`session_ref`와 같은 패턴이다(§5, [ADR-0007](adr/0007-session-ref-and-resume-token-custody.md)). `bind`의 모양은 요청과 결과에서 다르다 — `tunnel.open` 요청(`TunnelOpenReq.bind`)에서는 `[bind:]` prefix만 담아 host-only(예: `"127.0.0.1"`, 생략 시 `None` = 호출자 쪽 default)이지만, 위 `Tunnel.bind`처럼 결과에서는 `listen_port`를 합친 host:port 전체(예: `"127.0.0.1:8080"`)다 — `Tunnel`에는 별도 `listen_port` field가 없으므로 실제로 bind된 address와 port가 `bind` 하나에 온전히 남아있게 하기 위함이다.

`tunnels`(`tunnel.list`)의 `data`는 `{"tunnels": [Tunnel, …]}`이고, `tunnel.close`의 `data`는 `{"tunnel_id": "...", "closed": true}`다. 존재하지 않는 `tunnel_id`를 닫는 것도 오류가 아니라 멱등이다 — `ok: true`에 `data.closed: false`를 반환한다(§6.11 `trust.remove`와 같은 패턴). **`tunnels`는 상주 `qsh listen` 데몬이 실제로 쥐고 있는 터널만 보고한다** — 즉 reverse route 위에서 daemon-held로 등록된 `-R`(`mode: "remote"`)뿐이다. forward route에서 standalone `qsh tunnel open`이 연 터널은 그것을 연 CLI 프로세스가 유일한 홀더이고 (§6.14) 그 프로세스의 메모리를 조회할 IPC 경로가 없으므로, 다른 프로세스의 `qsh tunnels`에는 절대 나타나지 않는다 — 마찬가지로 reverse route 위의 `-L`도 로컬 listener는 그것을 연 CLI 자신의 소켓이라 데몬이 쥔 것이 아니므로 나타나지 않는다. 이는 스펙 결함이 아니라 §6.14가 이미 확정한 holder 모델의 직접적 귀결이다: `tunnels`는 daemon-held 터널을 조회하는 것이지 이 머신의 모든 터널을 조회하는 것이 아니다. Windows의 데몬도 named pipe로 같은 목록을 답하고, `qsh tunnel close <tunnel-id>`는 이 장비의 데몬들에 물어 그 id를 쥔 데몬이 닫는다(§6.13).

**`--wait <ms>`.** `qsh tunnel open`(standalone form)에만 있는 옵션이며 기본값은 `0`이다(대화형 `-L`/`-R`에는 없다). 최초 route 해석이 §6.1의 `reverse_registration_stale` 분기(`HOST_NOT_FOUND`, `retryable: true`)를 만났을 때만 재시도한다 — 그 밖의 모든 오류(등록이 아예 없는 경우 포함)는 지금처럼 즉시 반환된다. 재시도는 등록이 다시 살아나거나 `--wait`로 준 예산이 다 떨어질 때까지 반복되고, 다 떨어지면 마지막 시도가 낸 것과 같은 retryable `HOST_NOT_FOUND`를 그대로 돌려줘 감싼 스크립트가 다시 루프를 돌 수 있다. 범위는 `0..=600000`이고 그 밖의 값은 listener가 뜨기 전에 `INVALID_ARGUMENT`다. 다만 이 상한은 wire/parse 층의 상식적 한도일 뿐, 재시도가 실제로 retryable로 남는 구간을 보장하지는 않는다 — 그 구간은 이 머신 자신의 `[listen].stale_retention`(§6.13, 기본 120초)이 정한다: 그 시간이 지나면 등록 항목 자체가 제거돼 이후 해석은 `retryable: false`인 미설정 `HOST_NOT_FOUND`로 떨어지기 때문에, 실제 대기 예산은 요청값과 `stale_retention` 중 작은 쪽으로 다시 한 번 깎인다(`qsh-core::ops::tunnel::Ops::cap_wait_budget_to_stale_retention`). `TunnelOpenReq.wait_ms`(optional u32, 밀리초)로 실린다 — 생략하거나 `0`이면 요청·응답 모두 이 옵션이 생기기 전과 바이트 단위로 동일하다. `--dynamic`과는 함께 쓸 수 없다 — `-D`는 별도 요청(`TunnelDynamicReq`, 이 field가 없다)을 만들므로 `--wait`와 같이 주면 clap 단계에서 바로 사용법 오류다.

**`--supervise <ms>`와 `--accept-hold <ms>`.** 둘 다 `qsh tunnel open`(standalone form)에만 있고 기본값은 `0`이며 대화형 form에는 없다(ADR-0023 결정 1, 13). `--supervise`는 연결이 끊긴 뒤 터널을 스스로 다시 세우는 모드를 켜고, 값은 끊겨 있던 시간의 총 예산이다. 범위는 `0..=86400000`이고 밖이면 `INVALID_ARGUMENT`다. `--accept-hold`는 끊겨 있는 동안 들어온 로컬 accept를 바로 거절하지 않고 그 시간까지 붙들어 둔다. 붙드는 조건은 재수립 시도가 진행 중이거나 다음 시도가 그 기한 안에 시작되는 경우다. 창 밖의 긴 backoff 대기 중에 들어온 연결은 붙들지 않고 곧바로 거절한다. 붙드는 동안 그 연결의 바이트는 어느 carrier로도 나가지 않는다. `--local`은 accept한 소켓을 읽지 않고 두고, `--dynamic`은 SOCKS 인사와 `CONNECT` 요청을 로컬에서 읽은 뒤 `TCP_CONNECT`를 보내기 전에 멈춘다. carrier가 되돌아오면 붙든 순서대로 새 carrier에 싣고, 기한이 먼저 오면 기본 방식(`--local`은 RST, `--dynamic`은 REP `0x01`)으로 거절한다. 터널 하나가 동시에 붙드는 연결은 64개까지이고 넘치면 곧바로 거절한다. 기한은 tokio 단조 시계로 잰다(ADR-0023 결정 19). 범위는 `0..=2000`이고 밖이거나, `--supervise`가 `0`인데 `0`이 아니거나, `--remote`에 주면 `INVALID_ARGUMENT`다. 검증은 연결이나 bind 전에 `Ops`가 하며 순서는 범위, 조합이다. 같은 프로세스에 터널을 붙들어 두는 `Ops::tunnel_open_and_hold`와 `Ops::tunnel_dynamic_and_hold`는 `supervise_ms`가 `0`이 아니면 `INVALID_ARGUMENT`다. 검증을 통과한 `0`이 아닌 `--supervise`는 `--local`, `--dynamic`, `--remote` 모두에서 forward route와 reverse route 양쪽으로 동작한다(§6.14의 supervised 예외). `--remote`와 `--accept-hold` 조합은 연결 전에 거절한다. supervise하지 않는 터널은 `trust remove`를 받으면 그 connection이 닫히므로(§6.11, ADR-0031) 함께 끝난다. `trust set-role`로 role을 낮춘 경우와 role이 있는 pin의 `trust rename`도 같다. `--supervise` 터널은 닫힌 뒤 다음 재연결의 handshake가 거절되므로 예산 안에서 재시도하다 포기한다(role만 낮아진 peer는 줄어든 grant로 다시 붙는다). 끊김 순간 진행 중이던 TCP 연결은 이 옵션이 살리지 못한다(§6.14). `TunnelOpenReq`와 `TunnelDynamicReq`의 `supervise_ms`·`accept_hold_ms`(optional u32, 밀리초)로 실리고, 생략하거나 `0`이면 요청·응답·동작이 이 옵션이 생기기 전과 바이트 단위로 같다.

**keep-alive 설정.** `qsh tunnel open`은 `--local`, `--remote`, `--dynamic`과 `--supervise` 여부를 가리지 않고 dial하기 전에 이 머신의 `config.toml`에서 `[transport].keep_alive_ms`(§6.12, 기본 15000, `1000..=20000`)를 읽는다. `--supervise`의 재dial도 같은 값을 쓴다. 범위 밖이거나 파일을 파싱할 수 없으면 연결 전에 `CONFIG_ERROR`(`retryable: false`)로 끝나며, 전에는 이 op이 `config.toml`을 읽지 않았으므로 이 실패 경로는 새것이다. 키가 없으면 동작은 바이트 단위로 같다. `--supervise`의 경로 감시는 `[recovery]`(§6.12)를 읽는다. 같은 범위 규칙을 따른다. supervised 터널의 감시도 이 클라이언트 쪽에만 있고 호스트의 `qsh serve`에는 상대 감시가 없으므로, 이 머신의 값만 효과가 있다.

**Holder 수명은 route에 따라 갈린다.** forward route에서는 tunnel(`-L`/`-R` 모두)이 그것을 연 CLI 프로세스에 수명이 결합된다(§6.14). **reverse route의 `-R`만은 다르다** — target의 listener는 그 CLI가 아니라 상주 `qsh listen` 데몬이 쥔 reverse connection에 결합돼, CLI가 죽어도 살아남고 reverse connection이 죽어야 함께 죽는다(§6.13·§6.14 예외 문단, `docs/design/protocol.md` §11-3).

**`-D`(SOCKS5 dynamic forwarding)는 구현되어 있다([ADR-0019](adr/0019-socks-dynamic-forward.md)).** grammar는 `-L`/`-R`과 다르다 — 목적지가 없는 `[bind:]listen_port` 하나뿐이다(목적지는 SOCKS5 CONNECT가 매 연결마다 실어 온다). `bind`를 생략하면 loopback이고, non-loopback `bind`는 listener가 생기기 전에 `INVALID_ARGUMENT`로 거절된다(`-L`의 `loopback_bind_addr`를 그대로 재사용). 두 spelling 모두 존재한다. 대화형 `qsh [user@]host -D [bind:]port`는 `-L`처럼 반복 가능해서 세션 하나에 SOCKS listener를 여러 개 열 수 있다. `qsh tunnel open host -D/--dynamic [bind:]port`는 호출 하나에 listener 하나이고 `--local`/`--remote`와 함께 쓸 수 없다 — 셋 중 하나만 고르는 상호 배타 그룹이다. `--dynamic`을 이 호출 하나에 두 번 이상 주면 peer에 연결하기 전에 `INVALID_ARGUMENT`("one listener per `tunnel open`")로 거절된다. 대화형 form에는 우선순위가 하나 더 얹힌다: `--json`/`--jsonl`이 함께 오면 `-D`의 spec parsing이나 열기보다 §7의 `INVALID_ARGUMENT`가 먼저 나온다 — 대화형 form에는 애초에 machine mode가 없기 때문이다.

**처리 순서**는 spec 모양·loopback 검사 → route 해석(forward/reverse 모두 여기서는 거절하지 않는다) → peer 연결(forward는 QUIC로 직접, reverse는 이 머신의 상주 `qsh listen` 데몬을 경유 — [ADR-0020](adr/0020-socks-reverse-route.md) decisions 1–3) → capability 검사 → listener bind다. `tunnel.dynamic`(standalone form)은 이 순서 그대로다.

대화형 form(`qsh [user@]host -D spec`)은 순서가 다르다: capability 검사가 `session.open`보다 **먼저** 끝난다(ADR-0020 decisions 2–3) — 연결(`Ops::session_open_for_dynamic`) → capability 검사 → 통과해야만 `session.open`을 보낸다. 실패하면 세션은 target 위에 전혀 생기지 않는다. 이는 route를 가리지 않는다: forward든 reverse든 attach가 서기 전에 같은 순서로 거절된다. 통과한 뒤에는 별도의 attach 연결(`session.attach`)이 새로 서고, 그 위에서 여는 `-D` listener도 같은 capability 검사를 한 번 더 거친다(backstop, `SessionAttachStream::open_dynamic_forwards`) — 실제 거절은 항상 attach 이전에 먼저 일어나므로 이 두 번째 검사가 실전에서 거절을 만드는 경우는 없다.

**open 시점에 ACL 검사는 없다** — `tunnel.dynamic`/대화형 `-D`가 성공했다는 것은 SOCKS listener가 떴다는 뜻일 뿐 인가를 뜻하지 않는다. 인가는 SOCKS CONNECT를 받을 때마다 host에서 이루어진다: `-D`는 **새 grant가 아니라 `-L`과 같은 `forward.local`의 재사용**이고, 어휘에 있는 `forward.socks`는 이 인가에 전혀 관여하지 않는다(§2.5).

> `-D` runs SOCKS5 on this machine and authorizes every CONNECT on the peer as `forward.local`; `forward.socks` is never consulted.

(`qsh_core::ops::tunnel::DYNAMIC_FORWARD_ACL_NOTE` — `docs/design/testing.md` L6 게이트 대상. README가 함께 축자 인용한다.) 즉 `forward.local`을 부여받은 principal은 이미 host가 닿는 모든 목적지로 나갈 수 있었고(§2.5 매핑, ADR-0019 근거), `-D`는 그 egress를 브라우저·프록시 클라이언트가 쓰기 쉬운 형태로 옮겼을 뿐이다.

역방향 route로 해석된 host도 이제 지원한다(ADR-0020 decisions 1–3, ADR-0019 decision 10을 대체) — SOCKS listener가 받는 각 CONNECT는 이 머신의 상주 `qsh listen` 데몬을 거쳐 target의 살아있는 역방향 등록으로 `LOCAL_STREAM`을 열어 relay되며, `StreamHeader.deny_host_local = true`는 forward route와 동일하게 매 요청마다 그대로 실려 daemon을 넘어간다 — target 쪽의 host-local 주소 필터는 route와 무관하게 항상 켜져 있다. peer(forward는 그 peer 자신, reverse는 이 머신의 daemon이 target과 협상해 둔 capability 집합)가 capability `dial-filter.v1`을 advertise하지 않으면, listener를 bind하기 전에 `UNSUPPORTED`로 거절한다 — fallback 없음. 역방향 거절의 메시지는 원인을 하나로 특정할 수 없어 둘 다 지목한다: target의 qsh가 `dial-filter.v1`보다 오래됐거나, 이 머신의 `qsh listen` 데몬이 이 머신 자신의 업그레이드보다 먼저 떠서 협상 당시의 예전 capability 집합을 그대로 relay하고 있는 경우다 — 후자라면 `qsh listen`을 재시작하는 것으로 해결된다. 두 route 모두, 거절되면 아무 listener도 뜨지 않은 채 끝난다.

**JSON 계약.** `tunnel.dynamic`은 `tunnel.open`과 별개 op이다(§2.4) — 요청은 `TunnelDynamicReq { host, bind: Option<String>, listen_port: u32 }`, 성공 데이터는 아래 `DynamicTunnel` 하나다:

```json
{
  "tunnel_id": "01K0SOCKS",
  "mode": "dynamic",
  "bind": "127.0.0.1:1080",
  "actual_port": 1080,
  "protocol": "socks5",
  "dial_policy": "deny_host_local",
  "host": "personal-mac"
}
```

`mode`/`protocol`/`dial_policy`는 모두 열린 문자열이다. `forward_to`는 없다 — `Tunnel`과 달리 `DynamicTunnel`은 고정된 목적지를 갖지 않는다. `actual_port`는 `Tunnel.actual_port`와 타입·의미가 같다. machine 모드 stdout에는 이 봉투 한 줄만 나가고 그 뒤로는 hold한다 — 연결별 결과(각 CONNECT의 REP, 거부 사유)는 stderr로만 나간다(`docs/CLI.md` §2.2). `-D` listener는 `-L`처럼 그것을 연 프로세스가 유일한 홀더이므로 `tunnel.list`에 나타나지 않고(§6.14), 닫는 것은 그 프로세스를 끝내는 것뿐이다.

**SOCKS5 CONNECT 처리 결과 → REP 매핑**(codec은 `qsh_proto::socks5`, sans-IO):

| 원인 | REP |
|---|---|
| `ConnectResult{ok:true}` | `0x00` |
| `PERMISSION_DENIED`(host ACL 거부, host-local 주소 필터 거부) | `0x02` |
| `HOST_NOT_FOUND`(원격 이름 해석 실패) | `0x04` |
| `CONNECTION_FAILED`(거절, 모든 주소 실패, dial 타임아웃) | `0x05` |
| `RESOURCE_EXHAUSTED`, `INVALID_ARGUMENT`, 그 밖의 code | `0x01` |
| 로컬: 스트림 열기 실패, client 쪽 상한 초과 | `0x01` |
| 로컬: CMD가 CONNECT가 아님 | `0x07` |
| 로컬: ATYP 미지원, 도메인 모양 위반 | `0x08` |

`BND` 필드는 항상 `ATYP=0x01, 0.0.0.0:0` 고정이다 — `ConnectResult`에는 실제 연결 주소를 담는 필드가 없다. 실패 REP는 `shutdown(Write)` 후 close로 보낸다(RST는 쓰지 않는다 — 아직 보내지 않은 REP가 사라질 수 있어서). SOCKS5가 아닌 첫 바이트(HTTP의 `G`/`P`, TLS의 `0x16` 등)를 받으면 한 바이트도 쓰지 않고 스트림도 열지 않은 채 닫는다.

host는 목적지 이름을 원격으로(자신이) 해석한다 — 즉 SOCKS5의 remote-DNS 의미론이다. 애플리케이션이 `socks5://`(로컬 DNS)를 쓰면 client 쪽에서 이름이 새므로, 이름을 감추려면 `socks5h://`(원격 DNS, 예: `curl --socks5-hostname 127.0.0.1:1080 http://internal-service/`)를 쓴다.

### 6.10 Schema와 capability

```bash
qsh schema --json
qsh capabilities --json
qsh capabilities personal-mac --json
qsh version --json
```

`schema`는 `qsh.cli/v1` envelope과 각 command의 `data` payload에 대한 JSON Schema(schemars, draft 2020-12 dialect)를 그대로 서빙한다 — golden fixture를 검증하는 것과 **동일한 스키마**다(한 소스, `docs/design/testing.md` L6). `data.schemas`는 이 build가 이해하는 wire/CLI schema 식별자 목록(`version.get`과 동일), `data.envelope`는 envelope 자체의 schema, `data.commands`는 dotted operation 이름(§2.4)을 key로 하는 schema map이다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "schema.get",
  "ok": true,
  "data": {
    "schemas": ["qsh.cli/v1", "qsh.event/v1"],
    "envelope": { "...": "CliEnvelope의 JSON Schema" },
    "commands": {
      "version.get": { "...": "VersionData의 JSON Schema" }
    }
  }
}
```

`capabilities`를 host 없이 호출하면 이 build가 `Hello`에 advertise하는 로컬 capability 집합을 가공 없이 그대로 반환한다 — 이 형태만 checked-in fixture로 고정되어 값이 바뀌면 fixture diff로 드러난다(scope-creep tripwire, `docs/ROADMAP.md` M7 DoD 3). host를 주면 그 host와 negotiation된 `Hello`의 교집합을 반환한다 — forward(pinned) host는 그 주소로 직접 dial해 호출마다 새로 negotiation하고, reverse 등록 host는 이 머신의 `qsh listen`/`qsh serve --to`(구 표기 `qsh reverse`) daemon이 이미 들고 있는 연결(등록 시점에 그 daemon과 합의된 capability 집합)을 relay로 읽어 보고할 뿐 이 프로세스가 peer를 직접 dial하지 않는다(`docs/design/architecture.md` §2). 이를 위한 별도 wire request는 없다: 어떤 value operation이든 연결을 여는 순간 이미 수행하는 handshake의 결과를 읽어 보고할 뿐이며, 그래서 `capabilities.get`은 §2.5의 "인가 불요" 행에 다른 local operation들과 함께 있다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "capabilities.get",
  "ok": true,
  "data": {
    "capabilities": ["exec", "session", "resume.v1", "dial-filter.v1", "file.v1"],
    "host": "personal-mac"
  }
}
```

host 없이 호출한 결과에는 `host` field가 없다 — omitted, `null`이 아니다.

`file.v1`(ADR-0029)은 host가 원격 파일 op와 `FILE_DATA` 스트림을 처리한다는 뜻이다. unix host와 Windows host가 모두 광고하므로 광고 집합은 빌드에 따라 갈리지 않고 `capabilities.json` golden이 두 빌드에 같은 값이다. 광고하지 않는 peer에게 `qsh cp`(§6.21)는 요청을 보내기 전에 `UNSUPPORTED`로 끝난다.

`version`의 `data.build.commit`은 이 binary가 컴파일될 때 commit sha를 알 수 있었을 때만 채워지는 additive optional field다(`docs/ROADMAP.md` M7 감사 개정 ③): CI는 `QSH_BUILD_COMMIT`으로 sha를 주입하고, `cargo install --git`이 받은 git checkout에서 만든 build는 `qsh-core`의 `build.rs`가 그 checkout의 `HEAD`에서 sha를 구한다. 둘 다 없는 local build는 `build` field 자체가 통째로 생략된다 — 조작된 값이나 빈 문자열이 아니라 부재다.

### 6.11 Identity와 trust

```bash
qsh init --json
qsh init --key-store file --json
qsh init --import-ssh-key ~/.ssh/id_ed25519 --json
```

`identity.init`은 device identity(keypair와 self-signed certificate)를 생성한다. 이미 초기화된 경우 오류가 아니라 기존 identity 정보를 `created: false`와 함께 반환한다(멱등). `--key-store <auto|platform|file>`는 private key 저장소를 고른다 — `auto`(기본, platform 우선·부재 시 file fallback), `platform`(OS credential store 강제, 부재 시 `INTERNAL` 실패), `file`(0600 파일). 기본값은 `config.toml`의 `[identity].key_store`, 그 다음 `auto`다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "identity.init",
  "ok": true,
  "data": {
    "device_id": "device_01K0EXAMPLE",
    "fingerprint": "sha256:BASE64FINGERPRINT",
    "key_store": "platform",
    "config_dir": "/Users/dave/.config/qsh",
    "created": true
  }
}
```

`key_store`는 `platform`(OS credential store: macOS Keychain, Linux Secret Service, Windows Credential Manager) 또는 `file`(0600 permission fallback, Windows는 소유자 전용 DACL)이다. 어느 쪽이 사용됐는지는 항상 결과에 명시한다.

`identity.init`의 실패 경로는 전용 오류 코드를 두지 않고 일반 `ErrorCode` 어휘(§3.3)를 따른다 — 예: keystore 쓰기 실패는 `INTERNAL`(`retryable: false`)로 보고한다.

`--import-ssh-key <path>`(ADR-0026)는 새 keypair를 만드는 대신 평문 OpenSSH Ed25519 개인키 파일을 이 장치의 키로 쓴다. identity가 아직 없는 config 디렉터리에서만 동작하고, 그 뒤의 인증서 발급(CN/SAN `qsh://device/<device_id>`)과 key store 저장은 플래그 없는 `init`과 같다. 파일은 `qsh-core`가 16 KiB 상한(`SSH_KEY_FILE_MAX`)까지만 읽고, 원본 파일은 바꾸지 않는다. 개인키 바이트는 오류 message, `details`, 로그, JSON 어디에도 실리지 않는다. 자동 pin도 `acl.toml` 쓰기도 없고(ADR-0017), 새 principal 형식도 만들지 않는다(ADR-0026 결정 5).

같은 키라도 fingerprint가 두 가지다. `fingerprint`는 qsh가 쓰는 값으로 leaf 인증서 SPKI의 SHA-256(`sha256:BASE64`)이고, `ssh_fingerprint`는 `ssh-keygen -lf`가 찍는 값으로 OpenSSH 공개키 blob의 SHA-256(`SHA256:` 뒤에 패딩 없는 base64)이다. `trust.toml`과 `acl.toml`에는 앞의 것만 쓴다. `ssh_fingerprint`는 이 플래그로 만든 경우에만 `data`에 들어가는 additive optional 필드이며, 플래그 없는 `init`의 출력은 한 바이트도 바뀌지 않는다. human mode는 두 값을 이름표와 함께 나란히 찍는다(`qsh fingerprint:` 다음 줄이 `ssh fingerprint:`).

| 상황 | code | `details.reason` |
|---|---|---|
| identity가 이미 있음(`created: false` 멱등 경로를 타지 않는다) | `INVALID_ARGUMENT` | `identity_exists` |
| 암호가 걸린 키 | `UNSUPPORTED` | `encrypted` |
| Ed25519가 아닌 키(RSA, ECDSA 등) | `UNSUPPORTED` | `key_type` |
| 형식이 깨졌거나 OpenSSH 키 파일이 아님 | `INVALID_ARGUMENT` | `malformed` |
| 16 KiB 초과 | `INVALID_ARGUMENT` | `too_large` |
| 파일을 열거나 읽을 수 없음 | `INVALID_ARGUMENT` | `unreadable` |

identity 존재 검사는 키 파일을 열기 전에 한다. 그래서 identity가 있는 장비에서는 경로가 틀려도 이 오류가 먼저 나오고, 개인키 바이트는 읽히지도 않는다. 오류 envelope에 remedy 필드가 없으므로(§3.2) 다음 행동은 message에 적는다. config 디렉터리의 `identity/`를 치우고 같은 명령을 다시 돌리면 되며, 그 뒤 peer들은 다시 pin해야 한다. 제자리 교체는 아직 없다. 모든 거절은 파일이나 디렉터리를 하나도 남기지 않는다. message에는 사용자가 넘긴 경로 문자열과 거절 사유만 들어간다.

```bash
qsh identity export --json
qsh identity export --out device.pem --json
```

`identity.export`는 이 장치의 인증서를 PEM으로 반환한다 — 어떤 명령도 개인키를 인자로도 결과로도 다루지 않으며(ADR-0013), 이 명령도 예외가 아니다: `device.pem`(정확히 하나의 `CERTIFICATE` 블록)만 읽고 `device.key`나 key store에는 손대지 않는다. `--out` 없이 부르면 `data.cert_pem`에 그 파일 텍스트가 그대로 담기고, human mode는 그 PEM을 stdout에 그대로 찍는다 — 그 외에는 아무것도 찍지 않으므로 `qsh identity export | ssh box 'qsh trust add laptop --cert-file -'`처럼 파이프할 수 있다. `--out <path>`를 주면 그 경로에 파일로 쓰고 `data.path`에 그 경로가 담기며, human/`--json`/`--jsonl` 어느 모드든 이때는 PEM 자체가 stdout에 나가지 않는다. 이미 있는 경로를 가리키면 덮어쓰지 않고 `INVALID_ARGUMENT`다. `qsh init`을 먼저 하지 않고 부르면 `CONFIG_ERROR`(문면 정확히 "no local identity; run `qsh init` first")다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "identity.export",
  "ok": true,
  "data": {
    "name": "device_01K0EXAMPLE",
    "fingerprint": "sha256:BASE64FINGERPRINT",
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
  }
}
```

```bash
qsh identity move-key --to file --json
qsh identity move-key --to platform --json
```

`identity.move_key`는 이 장치의 개인키를 key store 사이에서 옮긴다(ADR-0032 결정 15). `--to`는 `file`(`identity/device.key`, 0600) 또는 `platform`(OS credential store)이고 `auto`는 받지 않는다. device_id, 인증서, fingerprint는 바뀌지 않으므로 상대 장비의 `trust.toml` pin과 `acl.toml` 행은 그대로 유효하다. `qsh init`의 `auto`가 platform을 먼저 고르는 규칙도 바뀌지 않는다. 주된 쓰임은 로그인 세션 밖에서 도는 상시 기동 유닛(macOS LaunchDaemon, Linux linger)이 OS credential store를 읽지 못할 때 키를 파일 store로 내리는 것이다.

원격에서 부를 수 없는 local operation이고 §2.5의 "인가 불요" 행에 든다. 순서는 다음과 같다.

1. audit 레코드 한 건(action `identity.move_key`, `resource`는 `<from>-><to>`)을 먼저 쓴다. 쓸 수 없으면 아무것도 옮기지 않고 `INTERNAL`이다.
2. 지금 키가 있는 store에서 읽는다.
3. 새 store에 쓴다(파일이면 0600).
4. 새 store에서 다시 읽어 그 키의 공개키가 이 장치 인증서의 것인지 대조한다.
5. `identity.toml`의 `key_store`를 새 store로 고친다.
6. 원래 store의 항목을 지운다.

2~5 어느 단계에서 실패하든 그 앞까지 만든 것을 되돌리고 오류로 끝난다. 원래 store와 `identity.toml`은 바이트 단위로 그대로다. 6단계 삭제만 실패하면 이미 새 store가 쓰이고 있으므로 성공으로 끝내되 `stale_entry_left: true`를 싣고, human mode가 남은 항목의 위치와 손으로 지우라는 안내를 찍는다. 같은 config 디렉터리에서 `init`·`cert issue`·다른 `move-key`가 겹치지 않도록 `identity/identity.toml.lock`을 잡는다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "identity.move_key",
  "ok": true,
  "data": {
    "from": "platform",
    "to": "file",
    "moved": true,
    "stale_entry_left": false
  }
}
```

`from`과 `to`는 `identity.init`의 `key_store`와 같은 어휘(`platform`/`file`)다. 키가 이미 `--to`의 store에 있으면 아무것도 하지 않고 `moved: false`로 성공하며 audit도 쓰지 않는다(바뀐 것이 없다). 개인키는 인자로도 결과로도 message·`details`·로그로도 나가지 않는다(ADR-0013). 오류는 새 `ErrorCode` 없이 기존 어휘를 쓴다.

| 상황 | code |
|---|---|
| `qsh init` 전 | `CONFIG_ERROR`(문면은 `identity.export`와 같은 "no local identity; run `qsh init` first") |
| `--to platform`인데 OS credential store에 닿을 수 없음 | `INTERNAL`(`identity.init --key-store platform`과 같다) |
| 읽기·쓰기·대조·`identity.toml` 갱신 실패, audit 쓰기 실패 | `INTERNAL`(되돌린 뒤) |
| `--to`가 `file`·`platform` 밖 | clap 인자 오류(exit 2) |

Windows 빌드에서 `platform` store는 Credential Manager이고, 왕복 순서와 결과는 다른 OS와 같다(ADR-0035 결정 12). 항목은 일반 자격 증명(`CRED_TYPE_GENERIC`)이고 사용자 이름은 `device_id`, 대상 이름은 `<device_id>.qsh`, 지속성은 `CRED_PERSIST_LOCAL_MACHINE`(재부팅 뒤에도 남고 도메인 프로필로 로밍하지 않는다)이며, 값은 다른 OS와 같은 base64 PKCS#8 DER이다. 대상 이름에 `device_id`가 들어가므로 같은 장비의 다른 설정 디렉터리가 서로의 키를 덮어쓰지 않는다. `--to platform`은 Credential Manager에 쓴 항목을 되읽어 인증서와 대조한 뒤 `identity.toml`을 고치고 `device.key`를 지운다. Credential Manager에 닿을 수 없으면(로그온 세션 없음 등) `INTERNAL`이고 `identity.init`의 `auto`는 파일로 내려간다. 파일 store는 소유자 전용 보호 DACL(`device.key`·`identity.toml`·디렉터리, 프로세스 토큰 사용자 SID의 `FILE_ALL_ACCESS` ACE 하나)로 만들어지고, DACL을 적용할 수 없으면(SID 조회 실패, ACL을 저장하지 않는 볼륨) 파일을 만들지 않고 `CONFIG_ERROR`다(ADR-0035 결정 9·10).

```bash
qsh trust add <name> --address <host[:port]> --fingerprint sha256:... --json
qsh trust list --json
qsh trust remove <name> --json
```

`trust.add`는 fingerprint를 명시하면 연결 없이 peer를 pin한다(provisioning 친화). 이때 `--address`는 선택이며 생략하면 `address`는 빈 문자열로 기록된다 — 단, `qsh exec <name>`의 host→주소 해석(§6.1, §6.8)은 address가 있는 pin만 이 store 쪽 후보로 삼으므로 명령을 보낼 host는 address와 함께 pin하거나 `hosts.toml`에 주소를 적어 둔다(inbound 전용 peer, 즉 "이 장비에 접속해 올 client"는 fingerprint만으로 충분하다). fingerprint 없이 연결해서 확인하는 방식은 human mode에서만 prompt를 열며 `--json` mode에서는 §2.1 규칙에 따라 prompt 대신 `TRUST_REQUIRED` 오류에 `details.observed_fingerprint`와 `details.address`를 담아 반환한다 — 호출자는 그 값을 검증한 뒤 `--fingerprint`로 재호출한다.

`--address`에 포트를 적지 않으면 4433을 채워 저장한다 — `qsh serve`/`qsh listen`의 bind 기본값과 같은 포트 하나다(ADR-0014). 포트를 채운 경우에만 stderr 한 줄이 나가며 envelope에는 이 사실이 들어가지 않는다. 그 문면은 정확히 "assuming port 4433: the peer address names no port, so this command uses port 4433 everywhere that address goes. Re-run with an explicit `host:port` to use a different port."다(`qsh_core::trust::ADDRESS_PORT_ASSUMED_NOTICE`, `trust add`와 `pair accept` 양쪽에서 나온다). `--address`를 아예 생략한 경우는 지금처럼 빈 문자열이고 포트를 채우지 않는다.

세 명령 모두 통일된 pinned peer 객체를 사용한다:

```json
{
  "name": "personal-mac",
  "fingerprint": "sha256:BASE64FINGERPRINT",
  "address": "personal-mac.example.com:4433",
  "added_at": "2026-08-17T00:00:00Z"
}
```

`role`은 ADR-0045가 더한 optional 필드다. `trust.toml`의 해당 `[[peer]]`에 `role` 키가 있을 때만 나오고, 값은 아래 여섯 문자열 중 하나다. 키가 없는 pin(ADR-0045 이전에 만든 pin)에서는 필드가 생략되므로 JSON만으로 "키 없음"과 명시적 `"none"`을 가를 수 있다. 값은 열린 문자열이라 호출자는 모르는 값을 만나도 오류로 취급하지 않는다.

`trust.add` 결과 (신규 pin):

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.add",
  "ok": true,
  "data": {
    "peer": {
      "name": "personal-mac",
      "fingerprint": "sha256:BASE64FINGERPRINT",
      "address": "personal-mac.example.com:4433",
      "added_at": "2026-08-17T00:00:00Z",
      "role": "none"
    },
    "created": true
  }
}
```

이미 같은 이름으로 pin된 경우도 오류가 아니라 멱등이다 — `data.created`가 `false`로 돌아온다. 이때 갈리는 경우가 둘 있다:

- **같은 fingerprint, 다른 `--address`:** 저장된 address를 그 자리에서 갱신한다 — host의 실제 주소가 바뀌었을 때(예: 재기동으로 바인딩 포트가 달라짐, 모바일 캠페인처럼 IP 자체가 바뀜) `trust remove` 없이 같은 identity로 `trust add`를 다시 실행하면 pin이 새 주소를 따라간다. 결과는 `data.updated: true`이고 `data.peer.address`가 새 값이다. `added_at`은 identity가 처음 pin된 시각을 그대로 유지한다(주소가 바뀐 시각이 아니다). `--address`를 아예 생략하면(기존 값을 건드릴 뜻이 없다는 뜻이므로) 아무것도 바뀌지 않는다.
- **다른 fingerprint:** identity 자체를 바꿔치기하는 것이므로 아무것도 바뀌지 않는다 — address도, fingerprint도 기존 값 그대로다. identity를 다시 묶으려면 `trust remove` 후 `trust add`를 명시적으로 실행해야 한다(반복 호출의 부작용으로는 일어나지 않는다).

두 경우 모두, 그리고 완전한 no-op(같은 fingerprint·같은 address) 재호출도 `data.updated`가 나온다 — 값은 실제로 address가 바뀌었을 때만 `true`, 그 외에는 `false`다. 새 pin(`data.created: true`)에는 `updated` 자체가 없다(적용 대상이 없으므로 키가 생략된다 — additive 필드다).

`trust.add` 결과 (같은 identity, 주소만 갱신):

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.add",
  "ok": true,
  "data": {
    "peer": {
      "name": "personal-mac",
      "fingerprint": "sha256:BASE64FINGERPRINT",
      "address": "personal-mac.example.com:5555",
      "added_at": "2026-08-17T00:00:00Z"
    },
    "created": false,
    "updated": true
  }
}
```

`trust.list` 결과:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.list",
  "ok": true,
  "data": {
    "peers": [
      {
        "name": "personal-mac",
        "fingerprint": "sha256:BASE64FINGERPRINT",
        "address": "personal-mac.example.com:4433",
        "added_at": "2026-08-17T00:00:00Z"
      }
    ]
  }
}
```

`trust.list` 결과 (role이 있는 pin과 키가 없는 pin):

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.list",
  "ok": true,
  "data": {
    "peers": [
      {
        "name": "phone",
        "fingerprint": "sha256:BASE64FINGERPRINT",
        "address": "",
        "added_at": "2026-10-12T00:00:00Z",
        "role": "full"
      },
      {
        "name": "personal-mac",
        "fingerprint": "sha256:BASE64FINGERPRINT",
        "address": "personal-mac.example.com:4433",
        "added_at": "2026-08-17T00:00:00Z"
      }
    ]
  }
}
```

human 출력의 `trust list`는 `ROLE` 열을 낸다. `role` 키가 없는 pin은 `(none, legacy)`로 적는다. 판정은 `none`과 같지만 ADR-0045 이전에 만든 pin이라는 사실을 보여 준다.

**Trust role (ADR-0045).** pin 하나에 role 하나를 둔다. role은 고정된 여섯 값이고 사용자 정의 role은 없다. 값을 더하거나 표를 바꾸려면 새 ADR이 필요하다. 코드의 정본은 `qsh_core::acl::ROLE_GRANTS`이고 이 표와 `docs/PRD.md` §9의 표가 그것과 같음을 `role_action_table_matches_docs` 테스트가 고정한다.

| role | 주는 action | 소유 축 |
|---|---|---|
| `full` | `exec.run`, `session.open`, `session.list`, `session.attach`, `session.control`, `forward.local`, `forward.remote`, `file.read`, `file.write`, `host.reverse` | any |
| `exec` | `exec.run`, `session.open`, `session.list`, `session.attach`, `session.control` | any |
| `tunnel` | `forward.local`, `forward.remote` | owned |
| `read-only` | `session.list`, `session.attach` | any |
| `reverse` | `host.reverse` | 해당 없음 |
| `none` | 없음 | 해당 없음 |

- `forward.socks`는 어느 role에도 없다. 항상-deny 게이트가 role보다 먼저 돈다.
- `full`의 `file.read`/`file.write`는 경로와 무관하게 허용된다(ADR-0045 결정 5). 다만 qsh 자신의 config·state·runtime 경로에는 role로도 닿지 못한다(ADR-0029 결정 5, ADR-0045 결정 18).
- 소유 축은 role로 받은 grant가 `scope = "owned"` 행처럼 자기가 만든 자원으로 걸러지는지를 뜻한다.
- `exec`는 의도를 나타내는 구분이지 `full`에 대한 보안 경계가 아니다. 셸이나 `exec.run`을 가진 peer는 serve 계정으로 `qsh trust set-role`을 실행해 자기 role을 올릴 수 있다. 보안 경계 구실을 하는 role은 명령 실행을 주지 않는 `tunnel`, `read-only`, `reverse`, `none`뿐이다.
- 이 표는 role이 무엇을 주는지만 정한다. 판정이 이 표를 읽는 방식(`acl.toml` 행과의 합집합, 없는 `acl.toml`과 파싱 불가의 구분)은 §6.12가 서술한다.

**role을 쓰는 명령(ADR-0045 결정 8).** 권한을 넓히는 쓰기는 아래 넷과 ADR-0044의 SSH 부트스트랩뿐이고, 모두 이 머신의 로컬 사용자가 실행하는 local op이다(§2.5 "인가 불요" 행). 원격 peer는 어느 것도 요청할 수 없다.

| 명령 | op | role 지정 | 기본값 |
|---|---|---|---|
| `qsh trust add <name> … [--role <role>]` | `trust.add` | `--role` | `--address` 없이 등록하면 `full`, `--address`를 주면 `none` |
| `qsh pair invite [--as <name>] [--role <role>]` | `trust.invite` | `--role` | `full` |
| `qsh pair accept <address> … [--role <role>]` | `trust.accept` | `--role` | `none` |
| `qsh pair ssh <dest> … [--role <role>]` | `pair.ssh` | `--role` | 원격 pin은 `full`, 이 장비 쪽 pin은 정방향 `none`, `--reverse --to`에서는 `reverse`(플래그로 고르지 않음) |
| `qsh trust set-role <name> <role>` | `trust.set_role` | 위치 인자 | 없음(필수) |

기본값이 둘로 갈리는 이유는 pin에 방향이 없기 때문이다. 초대 코드를 들고 오는 장비를 들이는 `pair invite`와 인증서 파일로 client를 들이는 주소 없는 `trust add`는 이 장비로 들어올 pin이라 `full`이다. dial할 상대를 등록하는 `--address`를 준 `trust add`와 `pair accept`에 `full`을 얹으면, 이 장비가 `qsh serve`를 띄울 때 그 상대가 들어올 권한까지 얻는다. 그래서 `none`이다. 어느 쪽이든 `--role`이 기본값을 덮는다. `--role`의 값이 여섯 이름 밖이면 `INVALID_ARGUMENT`이고, 연결이나 쓰기 전에 거절한다. `qsh trust invite`와 `qsh trust accept`(숨김 별칭)도 같은 `--role`을 받는다.

- `pair invite --role`은 role을 `invites.toml`의 초대 레코드에 저장하고, 상환 때 responder(`qsh serve`)가 그 role로 pin한다. 상환하는 쪽은 role을 고를 수 없다. wire의 페어링 교환에 role 필드는 없고, 초대를 만든 사람이 정한 값만 쓰인다. `--as`가 이름 결정권을 pin하는 쪽에 두는 것(ADR-0012 결정 6)과 같은 원칙이다. 결과에는 optional `assigned_role`이 실린다. `role` 키가 없는 옛 초대 레코드는 `none`으로 pin하므로 옛 초대가 권한을 넓히지 않는다. `invites.toml`의 `role`이 여섯 값 밖이면 파일 전체가 `CONFIG_ERROR`다.
- `trust add`가 이미 있는 이름에 다시 불려도 role은 바꾸지 않는다. `--role`이 무엇이든 `created: false`이고, human 출력이 "role is unchanged; use `qsh trust set-role <name> <role>`" 뜻의 줄을 하나 낸다. 같은 명령을 자동화가 반복해 부르다 권한을 조용히 바꾸는 경로를 닫기 위해서다. 주소 갱신은 위에서 서술한 대로 일어난다.
- `role`이 `none`이 아닌 값으로 pin을 쓰는 모든 경로(`trust add`, 초대 상환으로 생기는 pin, `trust set-role`)는 audit 레코드 하나를 먼저 남기고 나서 `trust.toml`을 쓴다. `action`은 그 op 이름(`trust.add`, `trust.invite`, `trust.set_role`), `auth_path`는 `"local"`, `principal`은 `device:<pin 이름>`, `resource`는 pin 이름, `role`은 쓴 role이다. 기록하지 못하면 쓰지 않는다. `none`을 쓰는 경로는 아무 action도 주지 않으므로 레코드를 남기지 않는다. 기록 실패의 오류는 `INTERNAL`이고 `retryable: true`다. 다만 `trust.accept`(`qsh pair accept --role`)는 예외다. 이 경로에서는 responder가 일회용 invite를 이미 소비한 뒤에 기록이 실패하므로 같은 code로 다시 실행해도 거부된다. 그래서 `INTERNAL`에 `retryable: false`이고 `details`가 `{"new_invite_required": true}`이며, 메시지가 상대에게 새 invite를 받으라고 안내한다. `trust.toml`은 이때도 바뀌지 않는다.
- `qsh setup`은 이 단계에서 pin마다 `none`을 명시한다. setup 전용 `--peer-role`과 역할별 기본값은 이 절이 아니라 §6.20이 서술한다.

```bash
qsh trust set-role <name> <role> --json
```

`trust.set_role`은 이미 있는 pin의 role을 바꾸는 유일한 명령이다. `trust rename`과 같은 규율로 `trust.toml.lock` 아래에서 읽고, 바꾸고, audit 레코드를 남긴 뒤 저장한다. 이름이 어떤 `[[peer]]`도 가리키지 않으면(`[[ca]]` 이름 포함) `HOST_NOT_FOUND`, role이 여섯 값 밖이면 `INVALID_ARGUMENT`, `trust.toml`을 읽을 수 없으면 `CONFIG_ERROR`다. 이미 그 role이면 `changed: false`이고 파일과 audit 모두 건드리지 않는다. audit을 쓰지 못하면 `INTERNAL`(`retryable: true`)이고 `trust.toml`은 그대로다. 러닝 중인 `qsh serve`·`qsh listen`은 role을 판정마다 읽으므로 재시작 없이 다음 요청부터 새 role이 적용된다. `acl.toml` 행은 그렇지 않다(기동 시 1회). role을 낮추면 실행 중인 `qsh serve`·`qsh listen`·`qsh serve --to`가 그 peer의 이미 확립된 연결을 2초 안에 `0x1005`로 닫는다. 낮춘다는 것은 새 grant 집합이 연결을 수립했을 때의 집합을 덮지 못한다는 뜻이다. 소유 축에서 `any`는 `owned`를 덮으므로 `full`에서 `exec`로, `full`에서 `tunnel`로(`forward.local`의 `any`가 `owned`로 좁아진다) 바꾸는 것은 모두 낮추는 것이고, 올리거나 같은 값으로 쓰는 것은 닫지 않는다. 올린 뒤 낮추면 올린 동안의 기록값이 기준이다. 닫힌 연결 위의 세션은 detach되고 신뢰가 남은 peer는 다시 붙어 줄어든 grant로 이어 갈 수 있다. `qsh listen`의 등록 연결은 `host.reverse`만 본다. `previous_role`은 `role` 키가 없던 pin이면 생략된다. role을 낮춘 경우 사람용 출력은 아래 세 문장을 덧붙인다(JSON은 같다).

> It applies to new connections from the next handshake, and to connections held open by a running `qsh serve`, `qsh listen` or `qsh serve --to` within 2 seconds. It applies on this device only; no other device is told. It does not end sessions: a session on a closed connection is detached, and a peer that is still trusted can reconnect and resume it.

`trust.set_role` 결과:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.set_role",
  "ok": true,
  "data": {
    "peer": {
      "name": "phone",
      "fingerprint": "sha256:BASE64FINGERPRINT",
      "address": "",
      "added_at": "2026-10-12T00:00:00Z",
      "role": "exec"
    },
    "previous_role": "read-only",
    "changed": true
  }
}
```

`trust.toml`의 `role`이 여섯 값 밖이면 파일 전체가 `CONFIG_ERROR`다. `trust rename`은 role을 새 이름으로 옮기고 `trust remove`는 지운다. 키가 없는 pin은 다시 쓸 때도 키가 생기지 않는다.

`trust.remove` 결과:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.remove",
  "ok": true,
  "data": {
    "name": "personal-mac",
    "removed": true
  }
}
```

존재하지 않는 이름을 제거하는 것도 오류가 아니라 멱등이다 — `ok: true`에 `data.removed: false`를 반환한다.

**`trust.remove`의 유효 범위:** `trust remove <name>`은 같은 이름의 `[[peer]]` pin뿐 아니라 `[[ca]]` 루트도 지운다(ADR-0013 결정 5 — `trust add-ca`의 이름 충돌을 푸는 유일한 경로). 둘 다 있으면 둘 다 지운다. 제거는 재시작 없이 적용된다. host는 `trust.toml`을 내용으로 비교해(파일 바이트 비교가 유일한 판정자다 — `mtime`은 판정에 쓰이지 않고 진단 기록으로만 남으므로, 1–2초 해상도의 파일시스템이라도 내용이 다르면 재로드가 일어난다; 프로세스 시작 시 1회만 읽는 `acl.toml`과는 다르다) 새 handshake마다 다시 읽고, 실행 중인 `qsh serve`·`qsh listen`·`qsh serve --to`는 프로세스마다 1초 주기로 같은 파일을 다시 읽는다. 그래서 `trust remove` 직후의 새 연결 시도는 `AUTH_FAILED`로 거부되고, **이미 확립된 연결**은 그 프로세스가 내용 변경을 알아차린 뒤 2초 안에 close 코드 `0x1005`(`CLOSE_CODE_TRUST_WITHDRAWN`, reason `trust withdrawn`)로 닫힌다(ADR-0031 결정 3·5·7). 연결마다 같은 검증 코어(`qsh.wire.v1`의 TLS 검증과 같은 pin → CA 순서)를 지금의 `trust.toml`로 다시 돌려, 거부되거나 `auth_path`가 달라졌거나 pairing 창으로만 받을 수 있게 되었거나 판정할 수 없는 연결(체인이 비었거나 leaf가 해석되지 않는 연결)을 닫는다. pin 하나를 지우면 그 pin으로 들어온 연결이 닫히고, `[[ca]]`를 지우면 그 CA 경로 연결만 닫히며 pin 경로 연결은 남는다. 닫히기까지의 최대 2초 동안 그 연결의 요청은 `acl.toml` 행으로 받은 grant로 통과할 수 있다(role grant는 요청마다 `trust.toml`을 읽으므로 즉시 멈춘다). `trust.toml`이 파싱되지 않는 동안에는 연결을 닫지 않고 role 요청을 모두 거부하며(ADR-0045), 파일이 고쳐지면 그 시점의 내용으로 다시 판정한다. 닫는 쪽은 audit에 연결 수준 deny 한 줄을 남긴다(`action: "connect"`, `resource`는 `trust_withdrawn`, §6.12). 닫는 것은 연결이지 세션이 아니다. 문면은 `trust remove`·role을 낮추는 `trust set-role`·role이 있는 pin의 `trust rename`이 사람용 출력에 같은 세 문장으로 쓴다(JSON은 바뀌지 않는다).

> It applies to new connections from the next handshake, and to connections held open by a running `qsh serve`, `qsh listen` or `qsh serve --to` within 2 seconds. It applies on this device only; no other device is told. It does not end sessions: a session on a closed connection is detached, and a peer that is still trusted can reconnect and resume it.

신뢰는 장비마다 따로 거둔다. 다른 장비의 `trust.toml`은 이 명령이 건드리지 않으므로, 그 peer를 신뢰하는 모든 장비에서 같은 명령을 실행한다. CA 개인키가 샌 경우의 처방도 그 CA를 신뢰하는 각 장비에서 `trust remove <ca-name>`을 실행하는 것이다. peer의 세션까지 끝내려면 `qsh session close`(§6.7)를 따로 쓴다.

```bash
qsh trust add <name> --cert-file <path> --json
qsh identity export | qsh trust add <name> --cert-file - --json
qsh trust add-ca <name> --cert-file <path> --json
```

`trust add --cert-file`은 `--fingerprint`의 대안이다(ADR-0013) — `qsh identity export`가 낸, 정확히 하나의 `CERTIFICATE` 블록을 담은 PEM을 읽어 그 인증서에서 fingerprint를 직접 계산해 pin한다. `--fingerprint`와 함께 주면 `INVALID_ARGUMENT`다. `-`를 주면 표준입력을 읽되, `CERT_PEM_MAX`(64 KiB, `crates/qsh-core/src/ops/mod.rs`) 상한까지만 읽는다 — `--stdin`의 `SESSION_WRITE_MAX`(§6.4)와 같은 취급으로, 이 상한을 넘는 입력은 `INVALID_ARGUMENT`이고 파일 경로·표준입력 어느 쪽으로 주든 상한을 넘겨 버퍼링하지 않는다. 블록이 0개거나 2개 이상(체인·번들)이거나, `CERTIFICATE`가 아닌 블록(개인키 포함)이 하나라도 섞여 있거나, base64가 깨졌거나, X.509로 파싱되지 않거나, 위 크기 상한을 넘으면 모두 `INVALID_ARGUMENT`이고 메시지에는 입력 바이트가 전혀 담기지 않는다(`details`는 항상 `null`). 유효기간은 검사하지 않는다 — 실제 handshake가 만료를 걸러낸다. `--cert-file`이 가리키는 경로가 없거나 읽을 수 없어도 `INVALID_ARGUMENT`다 — 이 장비 자신의 config 문제가 아니라 인자 오류이기 때문이다. 이렇게 pin된 결과의 모양은 `--fingerprint`로 pin했을 때와 완전히 같다(`trust.add`의 결과 자체가 바뀌지 않는다) — 이름 충돌 시의 조용한 no-op을 포함한 §6.11 위 문단의 규칙이 그대로 적용된다.

`trust add-ca <name> --cert-file <path|->`는 외부(다른 장비의) private CA 루트를 등록한다 — `qsh cert issue`가 이 장비 자신의 CA를 재등록할 때 쓰는 갱신-덮어쓰기 경로(§6.16)와 달리 **append-only**다: 같은 이름에 이미 다른 인증서가 등록되어 있으면 `INVALID_ARGUMENT`로 거부하고(먼저 `qsh trust remove <name>`을 하라고 메시지가 안내한다), 같은 인증서면 조용한 no-op(`created: false, updated: false`)이다. PEM 검증 규칙(크기 상한 포함)은 `trust add --cert-file`과 같지만, fingerprint는 구조 검증을 위해서만 계산되고 버려진다 — CA 루트에는 이 장비가 인가할 principal이 없기 때문이다. `trust add-ca`는 구조만 검증한다 — `CERTIFICATE` 블록이 정확히 하나이고 X.509로 파싱되는지만 확인하며, `basicConstraints`의 CA 여부나 자기서명 여부는 검사하지 않는다. 따라서 leaf 인증서를 실수로 등록하면 principal 이름 결정권이 그 leaf의 키 보유자에게 그대로 넘어가므로, 등록하려는 파일이 실제 CA 루트인지는 운영자가 직접 확인해야 한다(ADR-0013 결정 5). `<name>`은 `trust rename`(아래)의 `new`와 같은 라벨 검증을 거친다 — 앞뒤 공백을 제거한 뒤 빈 문자열·제어 문자·bidi·zero-width·`/`를 거부한다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.add_ca",
  "ok": true,
  "data": {
    "name": "partner-ca",
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "created": true,
    "updated": false
  }
}
```

초대 코드의 상환 창구는 인바운드 `qsh serve`의 기동 경로에만 있다(ADR-0013). 그래서 `qsh listen`이나 `qsh serve --to`(§6.13)로 뜬 peer는 `pair invite`/`pair accept`로 pin할 수 없고, 그 peer는 이 인증서 파일 교환으로 pin한다.

```bash
qsh pair invite --json
qsh pair invite --as <name> --json
qsh pair accept <address> <code> --json
qsh pair accept <address> --code-stdin --json
qsh pair accept <address> --as <name>
qsh pair accept <address>
```

**명명 계층(ADR-0012 결정 3/4).** `qsh trust ...`는 이미 store에 있는 pin을 다루는 조작(`add`/`list`/`remove`/`rename`)이고, `qsh pair ...`는 pairing으로 **새** trust 항목을 만드는 조작(`invite`/`accept`)이다 — 이 층 분리 때문에 `trust invite`/`trust accept`는 개명됐다. 구 표기 `qsh trust invite`/`qsh trust accept`는 숨김 서브커맨드로 남아 있으며 경고 없이 v1 내내 그대로 동작한다 — `qsh trust --help`의 `Commands:` 목록에서만 빠질 뿐, `qsh trust invite --help`/`qsh trust accept --help`와 그 실행 자체는 이전과 완전히 동일하게 파싱되고 동작한다(`qsh serve --to`의 숨김 alias `qsh reverse`가 §6.13에서 따르는 것과 같은 패턴). 구 표기가 v1 내내 그대로 파싱되고 동작하는 만큼, 이 문서와 코드 주석 곳곳의 예시가 `qsh trust invite`/`qsh trust accept`와 `qsh pair invite`/`qsh pair accept` 중 어느 쪽을 쓰든 둘 다 유효하다 — 남은 구 표기 예시는 놓친 것이 아니라 의도적으로 방치한 잔여물이다.

`trust.invite`는 이 장치에서 10분 TTL짜리 1회용 invite code를 발급한다(ADR-0002). 160-bit CSPRNG secret을 Crockford Base32로 인코딩해 `xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx` 형태(소문자, 4자씩 8그룹)로 보여준다. code 자체에는 주소가 들어 있지 않다 — 이 장치에 닿을 `host:port`는 여전히 별도로, out-of-band 경로로 전달해야 한다. human mode는 그 자리에 무엇을 넣을지 고르라고 후보 목록을 덧붙이지만(아래), envelope에는 어떤 주소도 싣지 않는다 — `data`는 `code`·`expires_at`·`accept_command`·`assigned_name` 넷이다.

`--as <name>`(`qsh pair invite --as`, ADR-0012 결정 6)은 redeem할 상대의 trust-store 이름을 invite 발급 시점에 미리 정한다 — 이 이름은 이 invite의 `invites.toml` 레코드에 함께 저장되고, redeem 시점에 상대가 자칭하는 이름을 무시하고 이 이름으로 pin된다. `assigned_name`은 `TrustInviteData`의 optional field로, `--as`를 준 경우에만 나타나고(`skip_serializing_if`, additive) 생략 시 자칭 이름이 그대로 pin되는 기존 동작과 같다. 이름은 §6.11 이 문단들이 pin 이름 전반에 적용하는 것과 같은 검증(`docs/design/protocol.md` §15.5의 `validate_device_name` 표에 `/` 금지를 더한 것)을 통과해야 하며, 실패하면 그 자리에서 `INVALID_ARGUMENT`이고 invite 자체가 발급되지 않는다. 저장된 `assigned_name`이 (수동 편집 등으로) 그 검증을 나중에 통과하지 못하게 되면 redeem은 자칭 이름으로 조용히 되돌아가지 않고 `SESSION_CONFLICT`로 거부된다 — invite는 소비되지 않는다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.invite",
  "ok": true,
  "data": {
    "code": "abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab",
    "expires_at": "2026-08-31T00:10:00Z",
    "accept_command": "qsh pair accept <address> abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab",
    "assigned_role": "full"
  }
}
```

human mode는 `accept_command`를 화면에 그대로 찍는다. operator는 `<address>` 자리만 실제 주소로 바꿔 상대에게 전달하면 된다 — 그게 이 필드의 유일한 용도다.

human mode는 `accept_command` 아래에 이 host가 스스로 관측한 후보 주소를 덧붙인다 — `<address>` 자리에 넣을 값을 고르는 재료다. 관측은 커널에 길을 묻는 것 하나뿐이다: 문서용 예약 주소(RFC 5737 `192.0.2.1`, RFC 3849 `2001:db8::1`)를 목적지로 UDP 소켓을 `connect`하고 커널이 고른 소스 주소를 읽는다 — IP 패밀리(v4/v6)당 최대 하나이지, 이 host가 가진 다른 인터페이스 주소(두 번째 NIC, Tailscale/WireGuard 같은 overlay 포함)까지 나열하는 것은 아니다. 전송은 하지 않으므로 와이어로 나가는 바이트는 0이고, 그래서 기다릴 것도 없다. 붙는 포트는 이 host의 `[serve].bind`가 명시한 값이고, 이 명령이 그 값을 읽을 수 없으면(미설정이거나, `config.toml` 읽기·파싱이 실패했거나, bind spec의 포트 부분이 `u16`으로 파싱되지 않는 경우 — 이 세 갈래 모두) 4433이다. `config.toml` 파싱 실패는 이 경로에서 별도 오류나 경고 없이 조용히 4433으로 접힌다. 실행 중인 `qsh serve --bind`가 그 포트를 덮어썼는지, 그리고 `[serve].bind`가 loopback처럼 이 host 자신을 이미 좁혀 놨는지는 이 명령이 알 수 있는 사실이 아니다 — 가령 `[serve].bind`가 `127.0.0.1:4433`이면 여기 찍힐 수 있는 LAN 주소를 실제 서버는 받지 않는다. loopback·unspecified 주소와, zone index 없이는 붙여 넣을 수 없는 IPv6 link-local(`fe80::/10`)은 후보에서 뺀다. 찍히는 IPv6 후보가 이 host가 RFC 8981 privacy extension으로 하루 안팎마다 스스로 회전시키는 임시 주소일 수 있다는 것도 이 관측은 모른다 — `pair accept`는 그 순간 쓰인 주소를 영구적으로 pin하므로, 이 줄을 나중에 복사해 쓰면 이미 낡은 주소일 수 있다. 머리글 문면은 정확히 "Default-route source address per IP family, not every interface -- port is `[serve].bind`'s, or 4433 when it gives none this command can read, never a running `qsh serve --bind`. Not a reachability check: a NAT or firewall can still block any of these for the peer:"다. 커널이 어느 축에서도 소스 주소를 답하지 않거나, 답한 것이 전부 위 규칙에 걸리면 목록 대신 정확히 "No candidate: the kernel named no source address, or only ones this line can't offer (loopback, unspecified, or an unprintable link-local) -- not "this device has no address". Invite still valid; fill `<address>` by hand. Check routing with `ip route`/`route -n`."가 나간다. 인터페이스 열거(`getifaddrs` 계열) 폴백은 없다.

`--json`/`--jsonl`에서는 이 질의를 아예 하지 않는다 — 후보는 human stdout 전용 채널이고, machine mode의 stdout에는 envelope 한 줄 외에 아무것도 나가지 않는다(§2.2). 이 목록은 도달성 주장이 아니다: NAT나 방화벽 뒤에서 상대가 실제로 닿을 수 있는지는 이 host가 볼 수 없는 사실이고, 그래서 머리글이 그것을 명시적으로 부정한다.

`trust.accept <address> <code>`는 `address`로 dial해 `code`가 가리키는 invite를 redeem한다. `address`도 포트를 생략하면 4433으로 읽고, 채운 경우 같은 `assuming port 4433` 한 줄이 stderr로 나간다. pin에 저장되는 주소는 그 정규화된 값, 즉 방금 dial에 성공한 그 문자열이다. 인증의 근거는 TLS identity가 아니라 secret 소유 증명이다: 양쪽은 TLS exporter(RFC 5705 `export_keying_material`)로 채널에 묶인 값을 뽑고, 그 위에 도메인을 분리한 두 개의 BLAKE3 keyed-hash 증명(initiator→responder, responder→initiator)을 constant-time으로 주고받는다. 상대 쪽 증명이 검증되기 전에는 어느 쪽도 pin하지 않는다 — 메시지가 도착했다는 사실만으로 pin하는 경로는 없다.

`code`를 주는 경로는 셋이다. 명령줄 위치 인자, `--code-stdin`(표준입력을 끝까지 읽는다), 그리고 셋 다 없을 때 human mode에서 열리는 프롬프트다. 프롬프트는 표준입력이 터미널일 때만 열리고 에코를 끄며 문면은 stderr로 나간다. Windows에서는 표준입력이 콘솔일 때가 터미널일 때이고, 입력 핸들의 `ENABLE_ECHO_INPUT`만 끈다(`ENABLE_LINE_INPUT`과 `ENABLE_PROCESSED_INPUT`은 켜 둔 채라 틀리게 친 코드를 지우고 Ctrl-C로 멈출 수 있다). 프롬프트가 끝나면 어떤 경로로 끝나도 원래 모드로 돌린다. 표준입력이 콘솔이 아닌 파이프나 파일이면 프롬프트를 열지 않는 규칙이 그대로다. 문면은 stderr로 나간다 — stdout에는 결과 envelope 외에 아무것도 나가지 않는다(§2.2). `--code-stdin`도 표준입력이 터미널이면 같은 방식으로 에코를 끈다 — 프롬프트를 기다리지 않고 바로 타이핑해도 코드가 화면에 남지 않는다. 세 경로 모두 읽은 값은 앞뒤 공백을 제거한 뒤 쓴다 — 위치 인자도 포함이라 `qsh pair accept <address> ' abcd-... '`처럼 앞뒤에 공백이 붙어도 그대로 통한다. code 문법 자체는 Crockford 심볼과 `-`만 허용하므로 `printf '%s\n' "$code" | qsh pair accept <address> --code-stdin`처럼 후행 개행이 붙은 입력은 제거하지 않으면 첫 시도부터 거부된다. 내부 공백은 제거하지 않는다 — 코드 중간의 공백은 여전히 오류다. 위치 인자와 `--code-stdin`을 함께 주는 것은 인자 사용 오류(exit 2, envelope 없음, §4)다. 코드가 셸 히스토리에 남는 것 자체는 재사용 위험이 아니다 — invite는 1회용이고 발급 10분 뒤 상환이 끝난다.

`--as <name>`(`qsh pair accept --as`, ADR-0012 결정 6)은 이 쪽에서 pin할 이름을 상대의 자칭 대신 직접 고른다 — invite 쪽 `--as`(위)와는 독립이다: 두 쪽 다 줄 수도, 한쪽만 줄 수도, 둘 다 생략할 수도 있으며 서로의 값에 관여하지 않는다. `TrustAcceptReq.as_name`으로 실려 가고, `trust.accept`는 `--fingerprint` 없는 `trust.add`와 마찬가지로 이 이름 자체도 `/`를 추가로 금지하는 검증(위 `--as` 문단과 같은 규칙)을 거친다 — 실패하면 dial하기 전에 `INVALID_ARGUMENT`다. 이름 충돌 판정(아래)도 실제로 pin되는 이 이름을 기준으로 한다 — 상대의 자칭 이름이 아니라. **`--as`를 생략한 human mode 호출은 pin 성공 뒤 stderr에 한 줄을 더 낸다**: pin된 자칭 이름과, `address`가 IP 리터럴이 아니라 호스트명을 담고 있으면 거기서 뽑은 제안 라벨(첫 DNS label, `qsh_core::trust::suggested_peer_label`)을 함께 알린다 — 이 관측은 host-local stderr 전용이며 `TrustAcceptData`나 어떤 JSON 줄에도 들어가지 않는다. `qsh pair invite`에는 이런 제안이 없다(주소가 없다).

이 증명이 보장하는 것은 "상대가 invite secret을 안다"까지다 — 그 이상의 신원 주장은 아니다. secret은 전화나 채팅처럼 사람이 개입하는 경로로 전달되는 경우가 많으므로, 더 높은 확신이 필요하면 pairing이 끝난 뒤 `trust list`가 보여주는 fingerprint를 out-of-band로 상대와 사후 대조하는 것도 방법이다 — pairing 자체가 요구하는 단계는 아니고, 원하는 operator가 추가로 얹는 defense-in-depth다(`docs/design/protocol.md` §15.4).

성공하면 두 장치가 같은 교환 안에서 서로를 pin한다. responder(`qsh serve`) 쪽은 그 사실을 자기 stderr에 한 줄 더 낸다 — envelope과는 무관한 host-local 채널이고(ADR-0017 결정 3), 그 자리에서 이 프로세스가 강제 중인 `acl.toml`에 상대 이름을 부르는 `[[acl]]` 행이 있는지까지 함께 알린다. 관측절은 어느 이름이 실제로 pin됐는지에 따라 갈린다: `--as` 없이 상대가 자칭한 이름 그대로 pin됐으면 정확히 "pinned a new peer under the name it sent for itself because the invite carried no --as:"(`PAIRING_PINNED_SELF_ASSERTED`), invite 쪽에서 `qsh pair invite --as`로 미리 지정해 둔 이름이 pin됐으면 "pinned a new peer under the name the invite assigned with --as:"(`PAIRING_PINNED_INVITE_ASSIGNED`)다. 이어지는 " \"<name>\". " 뒤로는 세 절이 차례로 온다. 첫째는 role 절이다: pin이 지금 가진 role(새 pin이면 이 invite가 정한 role, 같은 fingerprint로 이미 pin된 이름이면 그 pin의 기존 role이고 상환은 이를 바꾸지 않는다. `role` 키가 없는 pin은 `none`)이 action을 주면 "Its trust role is"(`PAIRING_ROLE_LEAD`) 뒤에 role 이름을 백틱으로 싸고 ", which grants: "와 §6.11 role 표 순서의 action 목록을 잇고, role이 `none`이면 정확히 "Its trust role is `none`, so the role grants no action."(`PAIRING_ROLE_NONE`)다. 둘째는 행 절이다: 행이 없으면 "No `[[acl]]` row names it, so only the role decides."(`PAIRING_ACL_ROW_ABSENT`), 행이 이미 있으면 "An `[[acl]]` row already names it, so that row's grants are added to the role's, including any you did not mean for this device."(`PAIRING_ACL_ROW_PRESENT`)다. 셋째는 확인 절이고 정확히 "A role change applies from the next request; an acl.toml change needs a restart of this `qsh serve`. Check with:"(`PAIRING_CHECK_LEAD`) 뒤에 "qsh acl check --principal 'device:<name>' --action session.open"이 온다. role은 판정마다 읽히고 `acl.toml`은 기동 시 1회 읽히므로 두 절의 반영 시점이 다르다는 사실을 확인 절이 그대로 말한다. 행 유무는 `qsh serve`가 기동 시 1회 읽은 정책 그대로를 판정 근거로 삼으므로, 기동 이후에 `acl.toml`을 편집했다면 재시작 전까지는 여전히 없는 것으로 보고한다.

pin은 `trust.add`와 같은 경로(`TrustStore::add_peer`)를 타므로 `trust.accept`의 결과 모양도 `trust.add`와 같다 — 다만 `address`는 `trust.add`의 기본값(생략 시 빈 문자열)과 달리 방금 dial에 성공한 그 주소가 그대로 채워진다: pairing은 항상 실제 연결을 전제하므로 채울 주소가 없는 경우가 없고, 이걸 비워 두면 `qsh exec <name>`(§6.1, §6.8)이 곧바로 `HOST_NOT_FOUND`가 되어 ADR-0002가 노리는 "페어링 후 바로 접속" 경험이 깨진다:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.accept",
  "ok": true,
  "data": {
    "peer": {
      "name": "personal-mac",
      "fingerprint": "sha256:BASE64FINGERPRINT",
      "address": "192.0.2.10:4433",
      "added_at": "2026-08-31T00:05:00Z",
      "role": "none"
    },
    "created": true
  }
}
```

invite는 한 번만 redeem된다 — 성공하는 순간 소비되고, **다른** 상대가 같은 code를 다시 쓰면 `SESSION_CONFLICT`다. TTL이 지난 code는 `TRUST_REQUIRED`, secret이 맞지 않는 code(오타, 아직 발급되지 않은 code 등 — 이미 소비된 code와는 다른 오류다)는 `AUTH_FAILED`로 거부한다. 이 재상환 거부의 원격 wire 문면(`SESSION_CONFLICT`)과 콘솔 tracing 로그는 ADR-0017 결정 4가 처방을 얹지 않기로 정한 두 채널이라 손대지 않는다 — 대신 `qsh serve`가 자기 stderr에 세 번째 줄을 더한다: 정확히 "an invite code was presented again after it had already been redeemed. Nothing was pinned and the peer got SESSION_CONFLICT; an invite is single-use by design, so this is not a fault on this host. Mint a fresh one with `qsh pair invite` if that peer still needs to pair."다(`qsh_core::pairing::PAIRING_INVITE_REPLAY_NOTICE`).

**이미 pin된 상대가 재시도하는 경우는 이 "다시 쓰면 `SESSION_CONFLICT`"와 겉모습은 같지만 원인이 다르다.** 페어링에 성공한 바로 그 상대가 (예: accept 명령을 실수로 두 번 실행해서) 같은 code로 다시 접속을 시도하면, host는 이미 그 신원을 pin해 뒀으므로 TLS 단에서 pin 경로가 먼저 잡혀 이 연결은 애초에 invite/pairing 판정 자체에 닿지 못한다 — 대신 일반 handshake 경로가 이를 자리를 벗어난 메시지로 보고 `SESSION_CONFLICT`(`retryable: false`)로 명시적으로 거부한다. **이때는 새 invite를 발급받아도 소용없다** — code나 invite의 상태가 문제가 아니라 이 신원이 host에 이미 pin되어 있다는 사실 자체가 원인이므로, 복구하려면 host가 `trust remove`로 기존 pin을 먼저 지워야 한다(`docs/design/protocol.md` §15.6, README Known limitations).

pin 시점에 이름 충돌이 생기면 — 상대가 자칭하는 이름이 이미 다른 fingerprint로 pin되어 있으면 — `trust.add`가 같은 상황에서 취하는 조용한 no-op과 달리 pairing은 `SESSION_CONFLICT`로 크게 실패한다. 이 실패는 invite를 소비하지 않는다: 충돌은 pin을 시도한 쪽의 로컬 상태 문제일 뿐이므로, 같은 code를 다른 상대가 곧바로 다시 시도할 수 있다.

상대가 자칭하는 `device_name`(양쪽 다 — initiator의 `PairingProof.device_name`, responder의 `PairingAccepted.device_name`)이 `docs/design/protocol.md` §15.5의 `validate_device_name` 표를 벗어나면 — 제어 문자(tab 포함, `char::is_control()`), bidi 제어(U+202A–U+202E, U+2066–U+2069, U+200E–U+200F), zero-width 문자(U+200B–U+200D, U+2060, U+FEFF), 또는 UTF-8 길이가 0바이트이거나 64바이트를 넘음 — 그 자리에서 `INVALID_ARGUMENT`로 거부한다 — 어느 쪽도 pin되지 않고, 거부된 값 자체는 로그에 남기지 않는다. `device_name`은 인증 입력이 아닌 자칭 label일 뿐이지만, human 렌더러가 `{name} ({fingerprint})`를 한 줄에 찍으므로 이스케이프 시퀀스나 bidi override가 그 fingerprint(바로 위 문단이 사후 대조를 권하는 값)를 가리거나 지우거나 표시 순서를 뒤집을 수 있다는 것이 이 거부의 이유다. homoglyph는 탐지하지 않는다 — fingerprint 병기가 방어선이다(`docs/design/protocol.md` §15.5).

`qsh serve`로 이미 떠 있는 데몬은 재시작 없이 새로 발급된 invite를 인식한다 — `trust.remove`(바로 위 문단)가 따르는 것과 같은 content-based reload 원칙이 invite store에도 그대로 적용된다. 이 재로드는 `qsh pair invite`(CLI 프로세스)와 `qsh serve`(daemon)가 같은 `invites.toml`을 서로 다른 프로세스에서 잠금 없이 읽고 쓰는 형태라, 두 프로세스의 쓰기가 정확히 겹치는 좁은 창에서는 한쪽의 갱신이 다른 쪽에 곧바로 반영되지 않을 수 있다(예: 거의 동시에 발급된 두 invite 중 하나가 다음 redeem 조회에서 아직 보이지 않는 경우) — 이후 재시도나 다음 저장 시점에는 다시 수렴하므로 invite가 영구히 사라지지는 않지만, 완전한 파일 잠금은 아직 없다(Step 7 debt로 이월).

**Windows host(ADR-0035 결정 25).** `qsh pair invite`(`--as`, `--role` 포함)는 Windows에서 다른 OS와 같은 동작이다. 초대는 소유자 전용 DACL의 `invites.toml`에 쓰이고 떠 있는 Windows `qsh serve`가 위 규칙대로 재시작 없이 읽으며, 사람용 출력의 후보 주소 질의도 같다. 상환 창구는 인바운드 `qsh serve`에만 있어서 Windows `qsh serve --to`와 `qsh listen`은 열지 않는다(§6.13). 상환하는 쪽이 이 host에 닿으려면 `qsh serve`의 방화벽 허용이 먼저다(§6.13의 "방화벽 첫 허용 프롬프트").

**`qsh pair ssh <[user@]host>`(ADR-0044, `pair.ssh`).** 이미 ssh로 닿는 장비에 시스템 `ssh`를 한 번 거쳐 양쪽 pin을 세운다. 원격이 이 장비의 fingerprint를 pin하고, 이 장비가 원격의 fingerprint를 pin하고, 마지막에 QUIC handshake로 확인한다. 인증은 전부 ssh 프로세스 안에서 일어나므로 암호·passphrase·2FA·host key 확인은 ssh가 직접 묻고 qsh는 SSH 개인키·암호·agent 소켓을 읽지 않는다(ssh 쪽 규칙은 §7 끝의 "시스템 ssh를 부르는 규칙"). 원격에 qsh를 설치하거나 `qsh serve`를 띄우지 않고, `hosts.toml`·`config.toml`·`acl.toml`을 어느 쪽에서도 쓰지 않는다. 인가 불요 local op이고(§2.5) 원격 peer가 요청할 수 없다. 기본은 이 장비가 원격으로 dial하는 정방향이고, `--reverse --to`는 원격이 이 장비로 dial하는 역방향이다(아래 "역방향" 항목).

```bash
qsh pair ssh <[user@]host> --json
qsh pair ssh <[user@]host> --as <name> --remote-as <name> --role <role>
qsh pair ssh <[user@]host> --address <host[:port]> --remote-qsh <path>
qsh pair ssh <[user@]host> --reverse --to <host[:port]> --json
```

- `--as <name>`: 이 장비가 원격을 pin할 이름. 기본값은 `<dest>`의 host 부분이다(결정 7). `--remote-as <name>`: 원격이 이 장비를 pin할 이름. 기본값은 이 장비 호스트 이름의 첫 레이블(pin 이름 규칙을 통과할 때), 그것도 아니면 `device_id`다(결정 8). 두 이름 모두 pin 이름 규칙(`/` 금지 포함)을 따르고 어기면 ssh를 부르기 전에 `INVALID_ARGUMENT`다.
- `--role <role>`: 원격 pin의 role. 기본값은 `full`이다. 이 계정으로 ssh 로그인하는 사람이 어차피 할 수 있는 일을 넘지 않기 때문이다(결정 8). 이 장비 쪽 pin은 정방향에서 항상 `none`을 명시해 쓴다(역방향은 `reverse`, 아래). `none` pin은 `acl.toml` 행 없이는 아무 action도 주지 않으므로, 이 장비가 `qsh serve`를 띄우고 있어도 원격은 그 pin만으로 아무것도 얻지 못한다(결정 21). `none`을 쓰므로 audit 레코드는 남기지 않는다(ADR-0045 결정 8).
- `--address <host[:port]>`: dial 주소를 덮어쓴다(정방향 전용이고 `--reverse`와 함께 줄 수 없다). 기본값은 `ssh -G`가 풀어 준 `hostname`과 원격 응답자가 보고한 serve 포트다(ssh의 `Port`는 쓰지 않는다, 결정 5). `trust add --address`와 같은 정규화를 거친다. `--remote-qsh <path>`: 원격에서 부를 qsh 실행 파일. 기본값은 `[ssh].remote_qsh`, 그다음 `qsh`다.
- **역방향 `--reverse --to <host[:port]>`(결정 1, 22).** 원격(target)이 이 장비(listener, `qsh listen`)로 dial하는 구도다. 정방향과 같은 기능을 갖는다(PRD §4). `--reverse`와 `--to`는 함께 쓴다. 하나만 주거나 `--reverse`에 `--address`를 겹치면 ssh를 부르기 전에, 이 장비 identity를 만들기 전에 `INVALID_ARGUMENT`다. `--to`는 `trust add --address`와 같은 정규화를 거치고 포트를 채우면 같은 stderr 한 줄이 나온다. 쓰는 것은 다음이 전부다.
  - 원격 pin: 이 장비를 `--to` 주소와 함께, role은 `--role` 또는 `full`로 쓴다(commit의 `address`). 주소를 담은 pin이라 ADR-0045 결정 8의 일반 기본값은 `none`이지만, controller가 중계하는 요청을 target이 이 장비의 principal로 인가하므로 `host --to`의 listener pin과 같은 예외로 `full`을 쓴다. 이 장비의 fingerprint가 원격에 어떤 이름으로든 이미 pin돼 있으면 응답자는 `trust add`와 같은 규칙으로 주소만 갱신하고(주소가 같으면 아무것도 쓰지 않는다) role은 바꾸지 않는다. 주소 갱신은 새 pin이 아니므로 audit record를 남기지 않는다.
  - 이 장비 pin: 원격을 주소 없이 role `reverse`로 쓴다. 이 role은 target이 `host.reverse` 등록만 할 수 있고 이 장비에서 셸은 얻지 못하게 한다. `--role`로 고르지 않고 바꾸려면 부트스트랩 뒤 `qsh trust set-role`을 쓴다. role이 `none`이 아니므로 audit record(`action`은 `pair.ssh`, `principal`은 `device:<pin 이름>`, `resource`는 pin 이름, `role`은 `reverse`)를 먼저 남기고 `trust.toml`을 저장한다. 순서는 lock → load → mutate → audit → save이고 audit을 쓸 수 없으면 이 장비 pin을 쓰지 않는다(원격 pin은 이미 섰고 같은 명령의 재실행이 수렴시킨다). 이 장비에 같은 identity의 pin이 이미 있으면 그 pin은 그대로 두고, role이 `reverse`가 아니면 human 모드가 `qsh trust set-role <이름> reverse`를 안내하는 한 줄을 stderr에 낸다.
  - 확인 dial을 하지 않는다(결정 13). 원격은 아직 아무것도 띄우지 않았고 그것이 정상 상태이므로 `data.verified`는 `false`이고 `verify_error`는 싣지 않는다. 건너뛴 것이 아니라 이 구도에 해당이 없다.
  - 결과가 원격에서 실행할 명령을 안내한다. `data.next_command`는 `qsh serve --to <원격이 이 장비를 pin한 이름>`이고 human 모드는 stdout에 `next, on the remote: …` 줄을, stderr에 같은 명령과 `qsh service install`을 한 줄로 알린다. 원격에서 아무것도 띄우지 않고 `[serve].to`도 쓰지 않는다. 원격이 등록하면 `qsh hosts`에 live로 오른다. ssh는 한 번만 원격에 닿으면 되고(ProxyJump도 가능) 그 뒤로는 target이 dial한다. 이 장비가 NAT 뒤라면 `--to`는 target에서 닿는 주소여야 하고, 맞는지는 이 명령이 확인하지 않는다(`qsh listen`의 doctor와 `qsh hosts`의 live 등록이 확인 수단이다). 자동 발동은 역방향을 고르지 않는다.
- **쓰기는 두 단계다(결정 12).** 첫 단계는 인자 검사, 이 장비 identity 확인(없으면 플래그 없는 `qsh init`과 같은 경로로 만들고 `data.identity_created`와 stderr 한 줄이 그 사실을 알린다, 결정 18), `ssh -G`, 응답자의 `hello`, 로컬 충돌 검사까지이며 어느 쪽 `trust.toml`도 쓰지 않는다. 둘째 단계는 `commit`을 보내 원격 pin을 쓰고, 그 결과를 받은 뒤 이 장비 pin을 쓰고, QUIC 확인을 한다. 중간에 실패해도 같은 명령을 다시 부르면 원격은 `exists`로 멱등하게 지나가고 이 장비 pin이 마저 선다.
- **덮어쓰지 않는다(결정 15).** 같은 이름이 다른 fingerprint로 pin돼 있거나(이 장비 쪽, 원격 쪽 모두) 원격의 fingerprint가 이 장비에 다른 이름으로 이미 pin돼 있으면 `SESSION_CONFLICT`(`details.reason: "pin_conflict"`, `details.side: "local" | "remote"`, `details.name`, 공개값인 `details.pinned_fingerprint`·`details.observed_fingerprint`, 다른 이름으로 pin된 경우는 `details.pinned_name`)이고 어느 쪽도 쓰지 않는다. 원격 쪽 `pinned_fingerprint`는 응답자의 message 끝 단어가 fingerprint로 파싱될 때만 싣고 응답자의 다른 말은 message에 옮기지 않는다. message는 `qsh trust remove <name>`과 다시 `qsh pair ssh`, 또는 `--as`·`--remote-as`로 다른 이름을 고르라고 안내한다. `--replace` 같은 플래그는 없다.
- **기존 원격 pin의 role은 바꾸지 않는다(결정 12).** 이 장비의 fingerprint가 원격에 어떤 이름으로든 이미 pin돼 있으면 응답자는 `exists`로 그 이름과 role을 돌려주고 쓰지 않는다. 요청한 role과 다르면 `data.remote.role`이 실제 값을 담고(role 키가 없는 옛 pin은 `role` 필드가 빠진다) human 모드는 stderr에 `ssh <dest> <remote_qsh> trust set-role <name> <role>`로 바꾸라는 한 줄을 낸다. role 없는 pin을 `full`로 올리면 권한이 조용히 넓어지기 때문이다.
- **확인(결정 13, 정방향).** pin이 서면 QUIC handshake와 mTLS 양방향 pin 검증까지만 하고 세션을 열지 않는다. 서버 인증서의 fingerprint가 `hello`가 보고한 값과 다르면 `AUTH_FAILED`(`details.reason: "remote_serve_identity_mismatch"`)다. 서버가 이 장비를 모르면 handshake 직후 연결이 닫히므로 짧게 기다려 `AUTH_FAILED`(`"remote_serve_rejected_this_device"`)로 읽는다. 응답자의 `hello`가 `serve_listening: false`를 알리면 dial하지 않는다. 확인이 실패하거나 건너뛰어도 pin이 섰으면 exit 0이고 `data.verified`가 `false`, `data.verify_error`가 그 사유(`code`·`message`·`details`·`retryable`, 건너뛴 경우 `CONNECTION_FAILED`와 `details.reason: "remote_serve_not_listening"`)다. 그 밖의 dial 실패는 §6.1의 `CONNECTION_FAILED` 어휘 그대로이고, `ssh -G`가 `ProxyJump`·`ProxyCommand`를 보고했다면 `data.ssh_proxied`가 `true`이고 사유에 QUIC는 그 중계를 쓰지 않는다는 말이 붙는다(결정 6). 오류는 exit 255와 오류 envelope이다.
- **원격이 응답하지 못하는 경우(결정 14).** 원격 identity가 없으면 `REMOTE_ERROR`(`"remote_not_initialized"`, 원격 identity는 만들지 않는다)이고, 부트스트랩 버전이 겹치지 않으면 `UNSUPPORTED`(`"bootstrap_version"`)이고, 응답자가 `error`를 보내면 그 `code`와 함께 `"remote_responder_error"`이며 원격이 쓴 문장은 제어 문자를 지우고 200자로 자른 것만 message에 실린다. ssh 종료 코드에서 오는 `remote_qsh_missing`·`remote_qsh_too_old`·`remote_command_failed`·`ssh_failed`·`ssh_not_found`·`bootstrap_protocol`·`bootstrap_timeout`은 §7 끝의 규칙이 정한다. 이 모두는 양쪽에 아무것도 쓰기 전에 끝난다. 모든 `details.reason`은 기존 코드에 붙는 additive 필드이고 새 `ErrorCode`는 없다.
- **출력.** `--json`/`--jsonl`은 envelope 하나만 stdout에 내고(diagnostic은 stderr), human 모드는 stdout에 결과 요약을, stderr에 고지(identity를 만들었다는 줄, 어느 이름으로 pin했고 어느 role인지, 기존 원격 pin의 role이 요청과 다르다는 줄, ProxyJump 경고)를 낸다. 고지의 문면은 `Ops`가 정하고 frontend는 그대로 찍는다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "pair.ssh",
  "ok": true,
  "data": {
    "direction": "forward",
    "peer": {
      "name": "box",
      "fingerprint": "sha256:BASE64FINGERPRINT",
      "address": "192.0.2.10:4433",
      "added_at": "2026-10-15T00:05:00Z",
      "role": "none"
    },
    "created": true,
    "remote": { "name": "laptop", "role": "full", "created": true },
    "identity_created": false,
    "ssh_proxied": false,
    "verified": true
  }
}
```

`PairSshData`의 필드는 `direction`(`"forward"` 또는 `"reverse"`), `peer`(이 장비가 쓴 `TrustPeer`, `trust.accept`의 `peer`와 같은 모양), `created`(이 장비 pin을 새로 썼는지), `remote`(`name`, `role`(없을 수 있음), `created`), `next_command`(역방향에서만 나오고 `qsh serve --to <이름>`), `identity_created`, `ssh_proxied`, `verified`, `verify_error`(확인이 실패했거나 건너뛰었을 때만)다. fixture는 `pair.ssh.json`(확인 성공), `pair.ssh.unverified.json`(원격 serve가 떠 있지 않음), `pair.ssh.reverse.json`(역방향: 이 장비 pin은 `role: "reverse"`이고 `next_command`가 있으며 `verified: false`), `error.SESSION_CONFLICT.pin_conflict.json`, `error.REMOTE_ERROR.remote_qsh_missing.json`이다.

`--json`/`--jsonl` mode에서는 pairing도 interactive prompt를 열지 않는다(§2.1) — 잘못된 code나 인자 오류는 곧바로 오류 envelope로 반환된다. 그래서 machine mode에서 위치 인자도 `--code-stdin`도 없이 부르면 프롬프트 대신 `INVALID_ARGUMENT`다. `--code-stdin`을 줬더라도 표준입력이 터미널이면 machine mode에서는 마찬가지로 `INVALID_ARGUMENT`다 — 터미널 위에서 사람의 입력을 기다리는 것 자체가 §2.1이 금지하는 대기이기 때문이다; 표준입력이 파이프나 파일이면 이 제약과 무관하게 그대로 읽는다. 표준입력이 터미널이 아닌 human mode 호출(스크립트, cron)도 같은 이유로 `INVALID_ARGUMENT`다 — 열 수 있는 프롬프트가 없다. Windows 빌드도 같은 규칙이다. 표준입력이 콘솔이면 프롬프트와 `--code-stdin` 모두 입력 핸들의 에코를 끄고, 콘솔이 아니면 프롬프트를 열지 않는다(위, ADR-0035 결정 4~8).

```bash
qsh trust rename <old> <new> --json
```

`trust.rename`은 pin을 지우지 않고 이름만 바꾼다 — `fingerprint`·`address`·`added_at`은 그대로다. `qsh trust remove <old>` 다음 `qsh trust add <new> ...`로 흉내 내면 그 사이 짧게라도 pin이 아예 없는 창이 생기고 `added_at`도 새로 찍히므로, 이 둘과는 다른 별도 경로다. `new`는 위 `--as` 문단과 같은 라벨 검증(`/` 금지 포함)을 거치고, `old == new`도 `INVALID_ARGUMENT`다. `new`가 이미 다른 `[[peer]]`나 `[[ca]]` 이름과 겹치면 `SESSION_CONFLICT`(`retryable: false`)이고, `old`가 어떤 `[[peer]]`도 가리키지 않으면(`[[ca]]`만 있는 이름 포함) `HOST_NOT_FOUND`다 — `trust.toml` 자체를 읽을 수 없으면 다른 모든 trust 조작과 같은 `CONFIG_ERROR`다. `[[ca]]` 항목은 이 명령이 건드리지 않는다 — CA 라벨은 여전히 별도로 관리되고, `new`가 CA 이름과 겹치는 것은 위처럼 거부 사유가 될 뿐이다.

`trust.remove`(위)와 같은 content-based reload 원칙이 여기도 적용된다 — 러닝 중인 `qsh serve`를 재시작할 필요 없이 다음 handshake부터 새 이름으로 인증된다. **다만 `acl.toml`은 이 재로드 대상이 아니다(`acl.toml`은 기동 시 1회만 읽는다, ADR-0012 결정 7)**: 옛 이름을 부르는 `[[acl]]` 행은 계속 그 이름으로 매치되고(그 이름은 더 이상 아무 pin도 가리키지 않으므로 사실상 죽은 행이 된다), 새 이름을 위한 행은 이 `qsh serve`를 재시작해 정책을 다시 읽어야 비로소 인가에 반영된다 — 재시작 전까지 새 이름의 principal은 인증은 되지만(pin은 이미 바뀌었으므로) 어떤 행도 없어 default-deny로 전부 거부된다. role이 있는 pin을 바꾸면 그 이름으로 들어와 있던 연결은 2초 안에 `0x1005`로 닫힌다. 연결은 수립 때의 principal 이름으로 role을 찾는데, 옛 이름은 더 이상 아무 pin도 가리키지 않아 grant가 사라지기 때문이다(ADR-0031 결정 5). role 키가 없는 pin의 이름 변경과 `[[peer]]` 순서만 바뀌는 별칭 정리는 닫지 않는다. 사람용 출력은 role이 있는 pin의 이름 변경에 `trust.remove`와 같은 세 문장을 덧붙인다. `hosts.toml`에 옛 이름으로 적어 둔 주소 항목은 이 명령이 건드리지 않으므로 그 이름은 여전히 어떤 pin도 없이 주소만 해석된다 — 필요하면 운영자가 `qsh host`(§6.8)로 직접 정리한다. 성공 시 audit record 하나가 남는다 — `action: "trust.rename"`, `auth_path: "local"`(원격 peer 인증 없는 로컬 op이라는 뜻) — 이 field는 이 값 외에도 ACL 경로를 가리키는 `"pin"`/`"ca"`, pairing 레코드의 `"pairing"`, 신원이 아직 확정되지 않은 연결·요약 레코드의 `"-"`을 쓴다, `principal`이 옛 이름, `resource`가 새 이름이다(`docs/design/architecture.md` §6, ADR-0012 결정 7). 기록에 실패하면(예: audit 쓰기 자체가 fail-closed로 거부) 이름은 바뀌지 않는다 — audit이 실패했는데 조용히 이름만 바뀌는 경로는 없다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.rename",
  "ok": true,
  "data": {
    "peer": {
      "name": "personal-mac-2",
      "fingerprint": "sha256:BASE64FINGERPRINT",
      "address": "personal-mac.example.com:4433",
      "added_at": "2026-08-17T00:00:00Z"
    },
    "old_name": "personal-mac"
  }
}
```

```bash
qsh trust ssh-preview ~/.ssh/authorized_keys --json
```

`trust.ssh_preview`(ADR-0026 결정 4)는 OpenSSH `authorized_keys` 파일을 읽어 "이 키들을 qsh에서 쓰려면 어떤 pin과 어떤 `[[acl]]` 행이 필요한가"를 보여 준다. 인가 불요 local op이고 아무것도 쓰지 않는다. 자동으로 pin하지 않고(ADR-0017 결정 5) `acl.toml`도 쓰지 않으며(ADR-0017 결정 1), `authorized_keys`에는 principal 이름이 없으므로 이름은 사람이 고른다. 표준입력(`-`)은 받지 않는다. 파일은 1 MiB(`AUTHORIZED_KEYS_MAX`)까지만 읽고 넘으면 `INVALID_ARGUMENT`(`details.reason`은 `too_large`, 열 수 없으면 `unreadable`)다. `data`에는 파일 경로를 싣지 않는다.

`data.entries`는 빈 줄과 `#` 줄을 뺀 줄마다 하나씩, 파일 순서대로 나온다.

| 필드 | 뜻 |
|---|---|
| `line` | 1부터 세는 줄 번호 |
| `status` | `ok`(옵션 없는 `ssh-ed25519`), `unsupported_key_type`(RSA·ECDSA·보안 키 등 다른 형식), `restricted_options`(`command=`·`from=`·`no-pty` 같은 옵션이 붙은 `ssh-ed25519`), `malformed`(파싱 실패) |
| `ssh_fingerprint` | Ed25519 줄의 `SHA256:…`(`ssh-keygen -lf`와 같은 문자열) |
| `qsh_fingerprint` | 상대가 같은 키를 `qsh init --import-ssh-key`로 들였을 때 갖게 될 `sha256:BASE64`. 공개키만으로 정해지는 예측값이다(Ed25519 SPKI DER은 고정 접두와 32바이트 공개키) |
| `already_pinned_as` | 같은 fingerprint가 이미 `trust.toml`에 있으면 그 이름 |
| `comment` | 줄 끝 comment. 제어 문자는 대체 문자로 바뀐다 |
| `trust_command` | `ok` 줄만. `qsh trust add <name> --fingerprint sha256:…` |
| `acl_row` | `ok` 줄만. `[[acl]]` 행 초안. `doctor`와 같은 생성기라 `allow` 목록과 `device:<name>` 자리표시자가 같다 |

`malformed` 줄은 줄 번호와 상태만 싣고 그 줄의 바이트는 어디에도 싣지 않는다. `unsupported_key_type` 줄도 fingerprint를 싣지 않는다. `restricted_options` 줄은 두 fingerprint까지만 싣고 `trust_command`와 `acl_row`는 내지 않는다. options가 거는 제한을 qsh ACL로 옮길 수 없으니, 그 줄에서 넓게 여는 쪽으로 틀리지 않게 하려는 것이다.

human 출력은 `trust_command`에 `--role full`을 붙여 보여 주고 `acl_row` 블록은 더 내지 않는다. 주소 없는 `trust add`가 이미 `full`이 되는 것을 명시적으로 적을 뿐이다. 좁히려면 `--role`을 바꾼다. JSON의 `trust_command`와 `acl_row`는 바뀌지 않는다(fixture `trust.ssh_preview.json`).

`<name>`은 자리표시자다. JSON에서는 `trust_command`와 `acl_row` 두 곳에서 같은 이름으로 바꿔야 한다. human 출력은 `acl_row`를 내지 않으므로 `trust_command`의 `<name>` 한 곳만 바꾸면 된다. 고치지 않은 `acl_row`를 그대로 붙이면 `acl.toml`은 로드되지만(로더는 principal의 접두와 비지 않은 나머지만 본다) 실제 이름으로 pin한 어떤 principal과도 매치되지 않아 요청은 default-deny로 거부되고, `qsh doctor`가 그 pin에 `acl_principal_unmatched`를 낸다. 고치지 않은 `trust_command`까지 붙이면 그 키는 문자 그대로 `<name>`이라는 이름으로 pin되고 초안 행을 받는다. 결과는 운영자가 이름을 골랐을 때보다 넓지 않다. 여러 `ok` 줄을 고치지 않고 붙이면 두 번째부터의 `trust add`는 이름이 같고 fingerprint가 달라 no-op이다. 셸에 붙일 때 `<`·`>`가 리다이렉션으로 해석될 수 있으니 `<name>`을 먼저 바꿔야 한다. human mode는 이 두 가지, 곧 `<name>`을 pin할 이름으로 바꿔야 한다는 것과 예측 fingerprint는 상대가 같은 키를 `qsh init --import-ssh-key`로 들였을 때만 맞는다는 것을 출력 끝에 적는다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "trust.ssh_preview",
  "ok": true,
  "data": {
    "entries": [
      {
        "line": 1,
        "status": "ok",
        "ssh_fingerprint": "SHA256:XxSbKVKvD1gyArwLk6oM3TZnt9rZogny7tQgxWR2bek",
        "qsh_fingerprint": "sha256:BASE64FINGERPRINT",
        "comment": "laptop",
        "trust_command": "qsh trust add <name> --fingerprint sha256:BASE64FINGERPRINT",
        "acl_row": "[[acl]]\nprincipal = \"device:<name>\"\nallow = [\"exec.run\", \"session.open\", \"session.list\", \"session.attach\", \"session.control\"]\n"
      },
      { "line": 2, "status": "malformed" }
    ]
  }
}
```

`doctor.run`의 전체 계약(§6.17)은 진단 코드 28종·envelope 모양·exit code 규칙을 담는다 — 이 절 밖에서는 더 설명하지 않는다.

원격 operation(`exec.run`, `session.*`, `tunnel.*`)의 mTLS 실패 오류 경로는 다음과 같다.

- `TRUST_REQUIRED`: peer가 trust store에 없음. `details`: `observed_fingerprint`, `address`. `retryable: false`. (`qsh exec <host>`의 host 이름 자체는 §6.1의 우선순위로 `hosts.toml`/`trust.toml`에서 해석되므로 원격 op가 이 코드를 낼 수 없다 — 미등록 host(양쪽 모두 이 이름의 주소가 없음)는 `HOST_NOT_FOUND`, 주소는 해석됐지만 그 fingerprint가 trust store에 핀되어 있지 않거나 실제 응답이 핀과 다른 경우는 `AUTH_FAILED`다 — `hosts.toml`이 주소를 대더라도 신원 판단은 여전히 trust store 단독이다(§6.1). M1에서 이 코드의 유일한 생산자는 fingerprint 없는 `trust add`다.)
- `AUTH_FAILED`: certificate 검증 실패(만료, CA 불일치, client certificate 미제시 등). `retryable: false`. 보안상 `details`에는 실패 category만 담고 상세 사유를 노출하지 않는다.

### 6.12 장기 실행 모드: `qsh serve`

`qsh serve`는 §2.4가 명시하듯 operation이 아니라 장기 실행 모드(long-running mode)이며 단일 요청/응답 JSON 계약이 없다. `qsh serve`는 인바운드일 때 host, `--to`를 주면 target — controller는 listener이자 client 역할을, target은 host 머신 역할을 한다(ADR-0012 결정 1, 역할 표는 §6.13).

```bash
qsh serve --bind <ip:port>
qsh serve --to <listener|host:port> [--name <name>]
```

- **Foreground 전용.** 데몬화는 QSH 자체가 하지 않고 OS 서비스 매니저(systemd/launchd)에 위임한다(§6.18의 `qsh service install`이 그 위임 대상 유닛을 만든다).
- `--bind`의 우선순위: CLI flag > `config.toml`의 `[serve].bind` > 기본값 `[::]:4433`.
- **`--to`(ROADMAP M9 (b), §6.13).** 주면 인바운드 대신 그 controller에 dial해 reverse target으로 등록한다 — `--bind`와 함께 줄 수 없다(`INVALID_ARGUMENT`, exit `255`, clap 사용 오류가 아니다). 우선순위: CLI 플래그(`--to` 또는 `--bind`, 둘 중 하나만 줄 수 있다) 먼저 — 어느 쪽이든 CLI에서 주어지면 그것으로 확정되고 아래 두 config 키는 아예 읽지 않는다. 그다음 `config.toml`의 `[serve].to` > 구 `[reverse].controller`(두 config 키가 다른 값으로 모두 설정되면 `CONFIG_ERROR`로 fail closed, §6.17 `config_serve_to_conflict`) > (아무것도 없으면) 인바운드 기본값 `[::]:4433`. 특히 `--bind`만 주고 `--to`는 생략한 경우도 config의 두 outbound 키를 읽지 않는다 — 오퍼레이터가 인바운드 주소를 직접 타이핑했으므로 `[serve].to`/`[reverse].controller`가 무엇이든 이 실행은 인바운드로 뜨고, 그 경로에서는 `config_serve_to_conflict`로 인한 `CONFIG_ERROR`가 나타날 수 없다. `--to` 리터럴 자체의 대상 해석(`HOST_NOT_FOUND`/`INVALID_ARGUMENT`)이 이보다 먼저 실패할 수도 있다. Windows에서도 같은 경로이고 거부 분기는 없다(§6.13).
- 시작 시 실제로 bind된 주소를 stderr에 출력한다. stdout은 §2.2 규칙에 따라 JSON 계약 전용이므로 여기서는 쓰지 않는다.
- listener 재시작 시 세션 소실에 대해서는 README의 [Known limitations](../README.md#known-limitations)를 참고한다. 서비스 매니저의 `Restart=always`/`KeepAlive` 재시작도 같다(`docs/deploy/service.md`). 세션은 여전히 사라지지만, 붙어 있던 클라이언트는 재시작 뒤 첫 패킷에서 stateless reset을 받아 1 RTT 안에 단절을 안다(아래 "stateless reset key").
- **stateless reset key(ADR-0036).** `qsh serve`(인바운드)와 `qsh listen`(§6.13)은 서버 endpoint의 stateless reset 키를 `config_dir/stateless_reset.key`에서 읽는다. 32바이트 원시 값이고 `identity/` 밖에 있다. 파일이 없으면 첫 기동이 OS 난수로 0600 모드로 만든다(Windows는 소유자 전용 보호 DACL이고, 적용할 수 없으면 파일을 만들지 않으며 이번 기동만 아래 임시 키로 뜬다. ADR-0035 결정 9·10). 같은 디렉터리의 임시 파일에 쓰고 fsync한 뒤 `link(2)`로 올리므로 두 프로세스가 동시에 처음 떠도 한쪽 키로 합쳐지고 반쯤 쓰인 파일을 읽는 쪽은 없다. 클라이언트와 `qsh serve --to`는 이 파일을 읽지 않는다. 키가 같으면 재시작한 서버는 옛 연결의 connection ID에 맞는 reset token을 계산하므로 클라이언트는 `max_idle_timeout`(45초)을 기다리지 않고 1 RTT 안에 연결 종료를 확정한다. 그 뒤 재dial한 attach는 새 서버에 세션이 없어서 §6.3·§6.4의 현행 실패 코드(`AUTH_FAILED`, non-distinguishing)로 끝난다. 새 오류 코드도 recovery 분류 어휘도 없다. 키 파일 문제는 서버를 멈추지 않고 stderr에 평문 한 줄(`qsh serve: ` 접두)로만 알린다. 두 경우다. 모드가 0600보다 넓으면 키를 그대로 쓰고 `stateless reset key file has a mode wider than 0600: <경로> has mode <모드>; the key is used as is; …`를 낸다. 파일을 읽을 수 없거나(권한 거부, I/O 오류) 길이가 32바이트가 아니면 그 파일을 덮어쓰거나 지우거나 새로 만들지 않고, 이번 기동만 메모리의 임시 키로 뜨며 `cannot use the stateless reset key file <경로>: <오류 종류>; running on a temporary in-memory key for this run, …`를 낸다. 이때 재시작 뒤 감지는 오늘처럼 path watch나 idle timeout에 맡겨진다. 파일을 고치거나 지우면 다음 기동이 정상 경로로 돌아온다. 진단에는 경로, 관측한 모드, 오류 종류만 들어가고 키 바이트는 로그, audit, 진단, JSON 어디에도 나오지 않는다. 문면 상수는 `qsh-core`의 `reset_key` 모듈이 갖는다. 회전 명령은 없다. 파일을 지우고 재시작하면 새 키가 만들어지고 그 한 번은 감지가 늦다. 재시작한 서버가 같은 UDP 포트를 다시 잡지 못하면 reset은 오지 않는다. doctor 진단 코드와 JSON 모양은 바뀌지 않는다.
- **keep-alive 간격(ADR-0021 결정 1).** `config.toml`의 `[transport].keep_alive_ms`는 `qsh serve`가 받는 모든 연결이 보내는 keep-alive PING의 간격이다. 기본은 15000이고 범위는 `1000..=20000`이다. 범위 밖이면 clamp하지 않고 소켓을 열기 전에 `CONFIG_ERROR`(`retryable: false`)로 기동을 거절한다. 파일은 기동 때 한 번만 읽으므로 바꾸면 재시작해야 반영된다. 이 값은 송신측이 혼자 정하는 간격이라 상대에게 광고되지 않고 양 끝이 각자 자기 값을 쓴다. 45초 idle timeout은 어떤 키로도 열지 않는다. 키가 없으면 동작은 이 키가 생기기 전과 같다.
- **경로 감시(ADR-0021 결정 4).** `[recovery]`의 `probe_interval_ms`(P, 기본 250)·`min_dead_after_ms`(D, 기본 1000)·`strikes`(S, 기본 3)는 `qsh serve`가 기동 때 검증만 하고 읽는 값이다. `qsh serve`가 받는 연결은 attach와 supervised 터널(forward 연결)인데 호스트에는 그 연결을 감시하는 PathWatch가 없다. 그 연결의 사망은 dial한 클라이언트의 감시(`qsh attach`·`qsh tunnel open --supervise`가 자기 머신의 `[recovery]`로 돌리는 것)가 판정하고, QUIC close나 idle timeout만 호스트 쪽에도 닿는다. 그래서 호스트의 이 키는 forward 연결의 감지를 바꾸지 않고, 같은 `config.toml`을 쓰는 다른 역할(`qsh listen`, `qsh serve --to`, 이 머신에서 도는 attach)을 위한 검증 자리일 뿐이다. 허용 범위는 `P×S+D ≤ 2000`, `S ≥ 2`, `50 ≤ P ≤ D`이고, 범위 밖이면 clamp 없이 소켓을 열기 전에 `CONFIG_ERROR`(`retryable: false`)로 기동을 거절한다. 파일은 기동 때 한 번만 읽는다. 범위는 attach와 supervised 터널 기준이라 그대로다. `rtt_multiple`(8)·idle probe 간격·active window는 닫혀 있어서 `[recovery]`에 적어도 `qsh doctor`가 `config_unknown_key`로 짚고 무시된다. 각 프로세스가 자기 `config.toml`을 읽고, forward 연결은 dial한 클라이언트의 값만 효과가 있다(위). 양 끝을 같이 올려야 하는 것은 역방향 등록 연결뿐이다(§6.13, ADR-0041). 키가 없으면 동작은 이 키가 생기기 전과 같다. 역방향 등록 연결의 감시 키 `reverse_min_dead_after_ms`·`reverse_strikes`는 §6.13에 있다.
- **`[ssh]`(ADR-0044 결정 2·4·9).** `config.toml`의 `[ssh]`는 시스템 ssh를 한 번 거쳐 양쪽 pin을 세우는 경로(§7)가 읽는 세 키다. `qsh serve`는 읽지 않는다. `bootstrap`은 `"auto"`(기본) 또는 `"off"`이고 그 밖의 값은 파일을 읽을 때 `CONFIG_ERROR`(`retryable: false`)다. `program`은 ssh 실행 파일이고 없으면 `PATH`의 `ssh`(Windows는 `ssh.exe`)다. `remote_qsh`는 원격 셸이 실행할 `qsh`이고 없으면 `qsh`다. 공백뿐인 `program`·`remote_qsh`는 쓰는 시점에 `CONFIG_ERROR`다. 세 키 모두 `qsh doctor`의 `config_unknown_key`가 아는 키다.
- **SIGTERM drain(M2, ADR-0003):** 신규 attach·open을 거부한 뒤 모든 세션에 §6.7의 close 절차(SIGHUP→TERM→KILL, `close_grace_ms`)를 적용하고 붙어 있는 소비자에게 `session.closed{reason: "closed"}`(§6.4)를 보낸 다음 종료한다. 세션은 프로세스와 함께 끝나며 고아 셸을 남기지 않는다.
- **Windows 방화벽(ADR-0035 결정 25).** Windows에서 `qsh serve`가 고정 UDP 포트를 처음 열 때 Windows Defender 방화벽의 허용 프롬프트가 뜰 수 있다. 문안은 §6.13의 "방화벽 첫 허용 프롬프트" 항목 하나가 정본이다.
- **정책 파일 진단.** 시작 시 `acl.toml`을 1회 읽는다(hot reload 없음). 상태는 셋이다(ADR-0045 결정 6, `docs/design/architecture.md` §6). 파일이 없으면 행이 없는 정책이고 trust role은 그대로 동작한다. 읽을 수 있으면 행과 role이 함께 동작한다. 파싱에 실패하면 프로세스는 뜨고 bind하지만 role을 포함해 도달하는 모든 인가 판정이 항상 `deny`이고 어떤 리소스(세션·터널·등록)도 생성되지 않는다. 파일이 없을 때 운영자에게는 stderr에 한 줄만 나간다. `no acl.toml (acl_policy_missing): <경로>; requests are authorized by trust roles only (see: qsh trust list)`. 파싱에 실패했을 때는 `no usable acl.toml policy`, `every request is denied until this is fixed`, 파일 경로, `CONFIG_ERROR` 코드, 복사해 붙일 수 있는 최소 정책 예시(이 머신에 실제로 pin된 peer 이름을 채운), `acl.toml is never auto-generated — create it by hand`, `verify a fix before restarting: qsh acl check`를 담은 진단 블록을 한 번 출력한다. 진단의 `code` 필드는 `acl_policy_missing`(파일 부재)과 `acl_policy_invalid`(파싱·검증 실패) 두 code word로 두 원인을 구분하고, doctor의 `acl_policy_missing`·`acl_policy_invalid` finding `detail`은 이전과 같은 블록을 싣는다. `trust.toml` reload가 파싱이나 읽기에 실패하면 마지막 정상 snapshot으로 pin 인증은 계속하지만 role 부여는 다음 reload가 성공할 때까지 멈추고, 기존 reload 실패 경고 줄(tracing)이 그 사실을 함께 적는다. 이 진단은 core(`crates/qsh-core/src/acl/load.rs`의 `StartupDiagnostic::render`)가 조립한 완성 문자열을 CLI가 그대로 stderr에 쓰는 평문 블록이다(tracing JSON 라인이 아니다). §6.13이 인용하는 `qsh-core::doctor::CONTROLLER_UNREACHABLE`과 공통점은 딱 하나다. 문안 정본은 core에 있고 CLI는 인가 로직 0줄로 출력만 한다. `doctor::Diagnostic`에는 `render()`가 없어 CLI가 `message`/`remedy` 두 필드를 직접 조립해 쓴다는 점에서 조립 방식 자체는 다르다. 정책 파일의 원본 소스 라인은 절대 덤프하지 않는다. 유일한 echo는 문제 rule의 문법 토큰(≤128바이트, 한 줄 이스케이프) 3종(unknown action/auth_path/scope)뿐이다. `acl.toml`을 자동으로 만들지는 않는다(§4.1 #1 (b): interim allow-all-pinned 경계를 파일로 영구화하는 것은 의도치 않은 권한 확대다). 재시작 전 정책을 검증하려면 §6.15의 `qsh acl check`를 쓴다.
- **Admission 상한.** 주소 검증되지 않은 Initial은 항상 `Retry`로 되돌려 보낸다(스푸핑 1패킷당
  상태 생성 차단). 정상 클라이언트는 새 연결마다 왕복 1회를 더 지불하며 migration은 영향이 없다.
  `[serve].max_concurrent_handshakes`(기본 64)는 동시에 진행 중인 handshake 수의 상한이다.
  `[serve].handshake_rate_per_source`(기본 10/초)는 **주소 미검증 Initial에만** 적용되는 source당
  속도 상한이고 `[serve].validated_rate_per_source`(기본 10/초)는 **검증된**(Retry
  토큰 왕복을 마친) Initial에 적용되는 별개의 source당 속도 상한이다. 검증을 통과해도 시도 속도
  자체는 통과 전과 같은 자릿수로 계속 제한된다(`docs/adr/0009-admission-defenses.md`의 한계
  절). 두 속도 상한 모두 키는 동일하다(IPv4 /32, IPv6 /64. IPv4-mapped IPv6 주소는 IPv4로 정규화해 센다). 2초 window에서
  지속 10/초까지는 항상 통과하고 window 하나 안에 몰린 순간 burst는 최대 20건까지 받아준 뒤 그
  이상을 거부한다. 두 축의 기본값이 같다는 것은 검증 축이 미검증 축을 통과한 것보다 많은 시도를
  볼 수 없다는 뜻이고, 그래서 기본 설정에서 `validated_rate_limited` 거부는 거의 나오지 않는다.
  검증 축은 운영자가 `validated_rate_per_source`를 미검증 축보다 낮게 줄 때만 따로 작동한다.
  quinn의 NEW_TOKEN(validation token)을 채택해 재접속 Initial이 Retry 없이 검증된 상태로 들어오게
  되면 검증 축이 그 경로의 유일한 문지기가 되므로, 그때 기본값을 다시 정한다. 세 값 모두 `0`은
  "무제한"이 아니라 "기본값"이며 방어선을 끄는 설정은 없다.
  상한 초과는 자원 생성 전 거부이고 클라이언트에게는 `CONNECTION_FAILED`(retryable)로 보인다 —
  handshake도, 세션도, task도 만들어지지 않는다. `retry_token_lifetime`(quinn 기본 15초)은 이
  방어선의 대상이 아니다 — 시도 *속도*를 제한하는 것은 이 rate limiter이지 토큰 수명이 아니다.
- 거부는 audit에 구조적으로만 남는다: `action="connect"`, `resource`는 `"rate_limited"`(주소
  미검증)·`"at_capacity"`(handshake 동시성 상한)·`"validated_rate_limited"`(검증된 Initial,
  source당) 중 하나, `principal`/`auth_path`는 `"-"`. 각 category 첫 행에 실리는 `peer_addr`는
  `rate_limited`의 경우 주소 검증 이전에 관측된 값이라 스푸핑 가능하다. 상관관계 확인용일 뿐
  발신자 증명은 아니다(`validated_rate_limited`/`at_capacity`는 검증된 주소이므로 이 제약이 없다).
  `Retry` 발급 자체는 audit하지 않으며 창(10초)당 category별 1행 + 요약 1행으로 집계된다 — flood가
  audit flood가 되지 않는다.
- **신뢰 철회로 닫은 연결(`docs/adr/0031-cert-rotation-revocation.md` 결정 8).** 실행 중인 프로세스가 `trust.toml`의 변경으로 확립된 연결을 닫으면 연결 수준 deny 한 줄을 남긴다: `action="connect"`, `decision="deny"`, `request_id="-"`, `rule`은 `null`, `principal`·`auth_path`는 연결을 수립했을 때의 값, `peer_addr`는 연결의 현재 주소, `role` 키 없음. `resource`는 `"trust_withdrawn"`(신뢰 자격을 잃음: 검증 거부, `auth_path` 변화, pairing 창, 판정 불능)과 `"grants_reduced"`(신뢰는 남았고 role grant가 줄어듦) 중 하나다. 어느 pin이 어떻게 바뀌었는지는 싣지 않는다. 닫는 쪽이 먼저고 audit이 나중이라, audit 쓰기가 실패해도 연결은 이미 닫혀 있다(로그 한 줄만 남는다). 키 집합은 바뀌지 않는다.
- **세션·exec·터널·연결 quota(`docs/adr/0010-resource-quotas.md`).** `[serve]`의
  11개 키 모두 `0`은 "무제한"이 아니라 "기본값"이며 방어선을 끄는 설정은 없다. 알 수 없는
  `[serve]` 키는 오류 없이 무시된다. 상한 키 하나를 잘못 쓰면 그 상한은 오류 없이 기본값으로
  남는다. `max_sessions`(기본
  256)는 전체 principal을 합친 live 세션 수의 전역 상한, `max_sessions_per_principal`(기본 32)는
  opener별 세션 상한이다. `max_exec_per_principal`(기본 32)는 principal별로 동시에 진행
  중인(ticket 발급 시점부터 완료까지, redeem 여부와 무관) `exec.run` 상한이고 `max_exec`(기본
  256)는 그 위에 얹히는 host 전역 exec 상한이다(principal 축보다 먼저 검사된다). exec 쿼터는
  미상환 exec 티켓도 센다(티켓 TTL로 유계). `max_tunnel_streams_per_principal`(기본 256)은
  principal별로 동시에 열린 로컬 포워드(`-L`, `TCP_CONNECT`) 스트림 수의 상한이고
  `max_tunnel_streams_per_forward`(기본 64)는 같은 principal이 같은 목적지(`host:port`)로 여는
  스트림 수의 더 좁은 상한이다. 둘 다 dial 전에 검사되며 초과는 dial을 0건으로 유지한 채
  `RESOURCE_EXHAUSTED`로 거부된다. `max_remote_forwards_per_principal`(기본 16)은 principal별로
  동시에 열려 있는 remote-forward(`-R`) listener 수의 상한이고 loopback 강제를 통과한 뒤·소켓을
  bind하기 직전에 검사된다. `max_connections_per_principal`(기본 32)과 `max_connections`(기본
  512)는 각각 principal별·accept arm 전역 동시 연결 수의 상한이다. **"전역"은 프로세스가 아니라
  accept arm 단위**다: `qsh serve` 호스트의 accept loop과 `qsh listen` 컨트롤러는 각자 독립된
  512를 가지며 reverse target이 그 listener로 거는 outbound 연결은 이 상한에 잡히지 않는다(그
  개수는 operator가 설정한 listener 수로만 늘어나고 peer가 늘릴 수 없다). 신원이 아직 확정되지
  않은 pairing 연결에는 별도 고정 상한(동시 8개, 설정 불가)이 있다.
  `max_file_transfers_per_principal`(기본 4)과 `max_file_transfers`(기본 64)는 각각 principal별·accept arm 전역으로 동시에 열려 있는 `file.read`/`file.write` 전송 수의 상한이다(ADR-0029 결정 12). slot은 ticket 발급 시점(열린 fd가 ticket에 묶이는 때)부터 전송이 끝나거나 ticket이 만료될 때까지 잡히고, 인가와 상태 경로 검사 뒤·파일을 열기 전에 검사한다. host 축이 principal 축보다 먼저다. `file.list`와 `file.mkdir`은 남기는 자원이 없어 세지 않는다. `qsh serve --to`도 같은 `[serve]` 키를 쓴다. **ACL 판정이 quota보다
  먼저다.** 인가되지 않은 principal은 quota가 이미 포화돼 있어도 여전히 `PERMISSION_DENIED`를
  보며 그 응답만으로는 quota 상태를 유추할 수 없다(연결 축은 ACL choke point가 없으므로 예외 —
  mTLS pin/CA 검증 자체가 그 경계다). 상한 초과는 자원(세션·child process·터널 스트림·listener·
  연결·열린 파일) 생성 전 거부다. 세션·exec·remote-forward listener·파일 전송·(pairing 아닌) 연결 축 거부는
  클라이언트에게 `RESOURCE_EXHAUSTED`(`retryable: true`)로 보인다. 터널 축(`TCP_CONNECT`)은
  control 응답이 아니라 스트림 자체의 `ConnectResult{ok:false, code:"RESOURCE_EXHAUSTED",
  message}`와 스트림 stop code `0x200D`로 답한다. 이 프레임에는 `retryable` 필드가 없다 —
  `qsh.cli/v1` 실패 봉투 전반의 규칙이 아니라 이 프레임 하나만의 fallback이다(§3.2). 재시도
  가능 여부는 클라이언트가 `code`로부터 `ErrorCode::default_retryable()`을 스스로 판단한다.
  pairing 연결 축 거부만
  다르다 — 신원이 아직 없어 오류 프레임을 실을 control 스트림 자체가 없으므로 proof를 읽지도
  않고 연결을 즉시 닫는다(non-distinguishing: invite 존재 여부를 구별해 주지 않는다). 세션
  quota는 살아 있는 세션 자체를 센다. 세션이 `session.close`나 attach 없는 TTL 만료로 broker
  registry에서 제거될 때까지 slot을 점유하며 attach 중이든 detach된 상태로 백그라운드에서 계속
  실행 중이든 점유량은 같다(detach는 quota를 풀어주지 않는다). 거부는 audit에 구조적으로만
  남는다: `action`은 `"session.open"`(세션)·`"exec.run"`(exec 2종)·`"forward.local"`(터널
  2종)·`"forward.remote"`(remote-forward listener)·`"connect"`(연결 3종, `handshake_rejected`가
  이미 쓰는 것과 같은 단어)·`"file.transfer"`(파일 전송 2종) 중 하나이고 `resource`는 `"quota_sessions_host"`·
  `"quota_sessions_principal"`·`"quota_exec_principal"`·`"quota_exec_host"`·
  `"quota_tunnels_principal"`·`"quota_tunnels_forward"`·`"quota_remote_forwards_principal"`·
  `"quota_connections_principal"`·`"quota_connections_host"`·`"quota_connections_pairing"`·
  `"quota_files_principal"`·`"quota_files_host"` 가운데 하나다. `peer_addr`는 각 거부가 실제로 관측된 peer 주소를 담는다(요약 행만 여러 peer를
  합치므로 `"-"`로 남는다). `request_id`는 control 요청(세션·exec·`RemoteForwardOpen`·파일 op)에 대한
  거부는 그 요청의 실제 id를, 대응하는 control 요청이 없는 데이터 스트림(터널)·연결 축 거부는
  `authorize_stream`의 connection-level 거부와 같은 sentinel `"-"`를 싣는다. 어느 축이든
  admission과 같은 10초 창으로 집계하지만 창 키는 category 하나가 아니라 `(category, principal)`이다
  (`quota.rs`가 `admission.rs`의 `WindowState`를 재사용하되 category마다 principal별 창 맵을 둔다).
  그래서 한 principal이 열어 둔 창이 다른 principal의 첫 거부를 흡수하지 않고, 요약 행의
  `principal`은 그 창을 채운 principal 본인이다. 창 맵은 두 겹으로 묶는다. 닫힌 창은 요약 행을 낸
  뒤 맵에서 지우고, category당 principal 창은 64개까지만 둔다. 그 위로 넘치는 principal의 거부는
  category마다 하나뿐인 overflow 창으로 모이며 그 요약 행의 `principal`만 `"-"`다. 창 하나가 내는
  행이 첫 행 1 + 요약 1이므로 category당 행 상계는 창 주기마다 `2 × (min(principal 수, 64) + 1)`행이다.
- **`-R` accept도 터널 스트림 축에 계수된다.** `-L`뿐 아니라 `-R` 리스너로 들어오는
  TCP accept도 `max_tunnel_streams_per_forward`·`max_tunnel_streams_per_principal`에 그대로
  잡힌다: `serve_remote_forward`가 accept 직후·`open_bi` 전에 두 상한을 예약하고, 초과분은
  QUIC 스트림을 전혀 열지 않은 채 TCP를 즉시 닫는다. 이때 audit는 `quota_tunnels_forward`/
  `quota_tunnels_principal`로 남고 `request_id`는 대응하는 control 요청이 없으므로 `"-"`,
  `peer_addr`는 거부된 그 TCP accept의 peer 주소다.
- **Audit sink가 degraded인 동안은 fail-closed다.** 치명적 쓰기 실패(디스크 풀 등)로
  audit sink가 degraded로 latch되면 그 동안의 `session.open`/`session.attach`(resume token 재부착 포함)과
  세션 쓰기는 감사 없는 allow를 만들지 않기 위해 `PERMISSION_DENIED`로 거부된다(e2e 테스트
  `crates/qsh-cli/tests/it/adversarial_load.rs`의
  `session_open_fails_closed_when_a_freshly_restarted_writer_cannot_create_the_audit_log`,
  `52639fc`) — 이는 버그가 아니라 의도된 fail-closed다. sink가 회복되면 같은 세션의
  재부착은 다시 성공한다.
- **Audit 로그의 디스크 부피도 유계다(M5, `docs/adr/0010-resource-quotas.md`).** 거부 flood가
  audit flood가 되지 않는 것은 위의 10초 창 집계가 category당 `2 × (min(principal 수, 64) + 1)`행으로
  행 *수*를 묶기 때문이고, 그 위에 회전·retention이 디렉터리 총 *부피* 자체를 묶는다 — `[audit].max_bytes`(기본
  64 MiB)에 도달한 로그는 회전되고 `[audit].retain`(기본 5)개까지만 보관되므로, audit 디렉터리의
  총 바이트는 `max_bytes × (retain + 1)`(활성 로그 1개 + 보관된 회전분)을 넘지 않는다. 다만 이
  행 상계는 category당 최대
  `2 × (min(principal 수, 64) + 1)`행이다 — 총 부피는 여전히 위 산식대로 유계이지만, principal을
  계속 바꿔 가며 거부당하는 flood는 같은 부피 상한 안에 더 많은 행을 채워 오래된 거부 레코드를
  예전보다 빨리 retention 밖으로 밀어낸다. 즉 이 조건에서 짧아지는 것은 감사 이력이 실제로 남는
  *기간*이지 디렉터리 총 바이트가 아니다.
- **`qsh serve`/`qsh listen`만 이 audit.log를 쓰는 것은 아니다.** `qsh trust rename`(§6.11)은
  로컬 CLI 프로세스에서 실행되면서도 `[audit].path`/`Paths::audit_log()`가 가리키는 바로 그
  파일에 `action: "trust.rename"` 레코드 하나를 그 writer의 lock 아래 append하며, append에
  실패하면 이름을 바꾸지 않고 fail closed한다.

**수명 줄.** `qsh serve`는 `qsh serve: listening on {addr}`와 `qsh serve: shutting down` 옆에 tracing target `qsh::lifecycle`의 한 줄 JSON 수명 줄을 함께 낸다(ADR-0023 결정 21). 첫 키는 `lifecycle`이고 값은 `listening`, `shutting_down`, `drained`, `tunnel_opened`, `tunnel_ended` 다섯이다. 모든 줄이 `at`(RFC3339, 초 단위)과 `process`(`serve`, `listen`, `serve_to`, `tunnel`)를 싣는다. `tunnel_*` 줄은 `tunnel_id`, `mode`, `supervise`(bool)를 더 싣고, `tunnel_ended`는 `code`와 알 수 있으면 `cause`(§6.13의 고정 어휘)를 싣는다. `drained`는 SIGTERM 드레인이 끝나면 `shutting_down`보다 먼저 한 줄 나오고 `sessions_closed`(드레인이 닫은 세션 수), `detached_closed`(그중 붙은 소비자가 없던 수), `timed_out`(bool, 60초 `DRAIN_TIMEOUT`에 걸려 나머지를 두고 나왔는지)를 더 싣는다. 세션 id, 명령, PTY 내용은 싣지 않는다. 주소, bind 주소, 토큰, 오류 본문은 어느 줄에도 싣지 않는다. 주소는 사람용 줄에 이미 있다. 사람용 줄의 바이트는 바뀌지 않으며 이 줄은 그 뒤에 온다. 기본 verbosity에서 보이고 `--quiet`에서만 꺼진다. `qsh.cli/v1`/`qsh.event/v1` 밖의 열린 어휘이고 stdout에는 쓰지 않는다(§2.2). `listening`은 `process: serve`로, 종료 신호를 받아 멈출 때의 `shutting_down`과 `drained`도 같은 값으로 나온다.

재시작 고지. `qsh serve`는 기동할 때 `qsh serve: listening on {addr}`와 `qsh serve: identity …` 줄 뒤에 사람용 한 줄 `qsh serve: sessions live inside this process; a restart drops every detached session`을 stderr에 낸다. 세션은 이 프로세스 안에 살아서 서비스 매니저의 재시작이 detach된 세션을 전부 지우기 때문이다(ADR-0003, `docs/deploy/service.md`). 앞선 줄들의 바이트와 순서는 바뀌지 않으므로 `listening on` 접두로 주소를 읽는 하네스는 영향이 없다. `--quiet`이면 내지 않는다. `qsh serve --to`는 런타임이 올라온 시점에 같은 문면을 `qsh serve:`(숨김 alias `qsh reverse`는 `qsh reverse:`) 접두로 낸다. `qsh listen`은 세션을 호스팅하지 않으므로 내지 않는다.

### 6.13 장기 실행 모드: `qsh listen` / `qsh serve --to`

`qsh listen`(controller)과 `qsh serve --to <listener>`(target)는 §2.4가 명시하는 장기 실행 모드다 — 단일 요청/응답 JSON 계약이 없고 operation 목록(§2.4)에 포함되지 않는다. target 쪽 이름은 `qsh reverse <controller>`에서 개명됐다(ROADMAP M9 (b), ADR-0012 결정 2/4) — controller/target이라는 두 역할 이름 자체는 바뀌지 않는다: controller는 listener이자 client 역할을, target은 host 머신 역할을 한다.

**역할 표(ADR-0012 결정 1).** 두 축 — 셸을 내주느냐/얻느냐, 인바운드를 받느냐/밖으로 dial하느냐 — 이 명령 넷을 정한다:

| | 인바운드를 받는다 | 밖으로 dial한다 |
|---|---|---|
| 셸을 내준다(host) | `qsh serve` | `qsh serve --to` |
| 셸을 얻는다(client) | `qsh listen` | `qsh <name>`, `qsh exec` |

listener는 중계기가 아니라 사람이 앉아 있는 client 머신이고, 그래서 공인 도달 가능해야 한다. 각 장비의 `acl.toml`은 그 장비로 들어오는 요청만 통제한다.

```bash
qsh listen [--bind <ip:port>]
qsh serve --to <listener|host:port> [--name <name>]
```

**구 표기 alias.** `qsh reverse <controller> [--offered-name <name>]`는 숨김 서브커맨드로 남아 있으며 경고 없이 v1 내내 그대로 동작한다(ADR-0012 결정 4) — `qsh --help`의 `Commands:` 목록에서만 빠질 뿐, `qsh reverse --help`와 `qsh reverse <controller>` 자체는 이전과 동일하게 파싱되고 실행된다. `qsh serve --to`의 `--name`이 `qsh reverse`의 `--offered-name`에 대응한다. `--to`는 `--bind`와 함께 줄 수 없다 — 함께 주면 clap 파싱 오류(exit `2`)가 아니라 `INVALID_ARGUMENT`(exit `255`, envelope 없음, §2.2)다. `--name`을 `--to` 없이 주는 것도 같은 방식으로 거부한다 — `INVALID_ARGUMENT`(exit `255`): 이름은 outbound에서만 의미가 있으므로 조용히 무시하는 대신 fail closed한다.

- **Controller reachability 요구.** `qsh listen`은 target이 dial할 수 있는 주소에서 실행돼야 한다 — 역방향은 NAT 뒤 target을 도달 가능하게 만들 뿐, controller 자신은 여전히 direct-reachable해야 한다(relay·NAT traversal은 M3의 명시적 out-of-scope, ROADMAP.md M3). 이 요구의 정본 문안은 `qsh-core::doctor::CONTROLLER_UNREACHABLE`(`crates/qsh-core/src/doctor.rs`)이며, `qsh serve --to`(구 `qsh reverse`)의 연결 실패 경로가 그 invocation 생애주기 동안 stderr에 **정확히 한 번**(백오프 재시도마다 반복하지 않는다) 렌더한다:

  > Reverse attach needs a directly reachable UDP path from the target to the controller. QSH provides no relay, NAT traversal, or discovery — that is out of scope for P0.
  >
  > Put the controller on a publicly routable address, a forwarded port, or an existing overlay such as WireGuard or Tailscale. If the controller itself is behind NAT, M3 has no answer for that.

  같은 상수를 `qsh listen` 시작 배너, `README.md`의 "Known limitations", 그리고 이 절이 함께 소비한다 — 문안 정본이 여러 벌 생기지 않는다. `qsh doctor`(§6.17)도 `code: "controller_unreachable"`을 그대로 소비한다.
- `--bind`의 우선순위: CLI flag > `[listen].bind` > 기본값 `[::]:4433` — `qsh serve`(§6.12)와 **기본값이 같다**. 한 머신에서 두 역할을 겸하려면 명시적 `--bind`가 필요하고, 충돌은 조용한 오작동이 아니라 즉시·명시적 실패(stderr 진단 + exit `255`)다. 실패 문면의 관측절(`cannot listen on {bind}: {err}`) 뒤에 처방이 붙는다 — 정확히 "Nothing is being served. `qsh serve` and `qsh listen` both default to port 4433, so one machine running both needs an explicit bind for at least one of them. Re-run with `--bind <ip:port>` on a free port."다(`qsh_core::serve::BIND_UNAVAILABLE_REMEDY`, ADR-0014 결정 9). `qsh serve`(§6.12)의 같은 실패도 이 상수를 공유하므로 문안 정본은 여기 하나다.
- **stateless reset key(ADR-0036).** `qsh listen`도 인바운드 서버 endpoint라서 `qsh serve`와 같은 `config_dir/stateless_reset.key`를 같은 규칙으로 읽고 만든다(§6.12). 두 프로세스는 서로 다른 포트에 bind하므로 키를 나눠 써도 한쪽이 만든 token이 다른 쪽 연결에 닿지 않는다. 키 파일 진단은 `qsh listen: ` 접두로 stderr에 한 번 나가고 정책 진단과 같은 콜백을 지나므로 `on_bound`보다 먼저 나온다. `qsh serve --to`는 서버 endpoint가 없어서 이 파일을 읽지 않는다.
- **keep-alive 간격(ADR-0021 결정 1).** `qsh listen`은 `[transport].keep_alive_ms`(§6.12, 기본 15000, `1000..=20000`)를 받는 모든 연결에 적용하고, `qsh serve --to`는 controller에 dial한 등록 연결에 적용한다. 범위 밖이면 두 모드 모두 clamp 없이 기동 전에 `CONFIG_ERROR`(`retryable: false`)로 거절하며, 파일은 기동 때 한 번만 읽으므로 바꾸면 재시작해야 한다. 각 프로세스가 자기 `config.toml`을 읽어서 target과 controller는 따로 정한다.
- **경로 감시(ADR-0021 결정 4, ADR-0041).** `qsh listen`의 등록 연결 감시와 `qsh serve --to`의 등록 연결 감시는 대화형 attach와 다른 기본을 쓴다. `[recovery]`(§6.12)의 `probe_interval_ms`(250, attach와 공유)·`reverse_min_dead_after_ms`(기본 4250)·`reverse_strikes`(기본 3)를 읽고 `P×S+D ≤ 5000`, `S ≥ 2`, `50 ≤ P ≤ D`이다. 등록이 끊기면 그 위의 역방향 터널이 재생 없이 모두 끝나고 기다리는 사람이 없어서, 이슈 #10이 잰 최장 업링크 손실 구간(3.6초)을 넘기도록 기본 침묵 하한이 attach의 1초보다 길다. 일반 `min_dead_after_ms`와 `strikes`는 이 연결에 닿지 않는다. 범위 밖이면 두 모드 모두 clamp 없이 기동 전에 `CONFIG_ERROR`(`retryable: false`)로 거절하고 파일은 기동 때 한 번만 읽는다. 기본이 상한에 닿아 있으므로 `reverse_strikes`만 올리거나 `reverse_min_dead_after_ms`만 올리면 거절된다. 둘을 함께 맞추고, 공유 `probe_interval_ms`를 250보다 올릴 때도 같다. target과 controller가 각자 값을 정하지만 한쪽만 느슨하게 하면 다른 값을 쓰는 상대가 `CLOSE_CODE_PATH_DEAD`로 연결을 끊으므로, 양 끝을 같이 올려야 효과가 있다. 진짜로 죽은 등록이 `stale`로 표시되고 target이 재dial하기까지는 약 3.25초 늦어진다. 이 감지 시간은 등록이 쓰이는 동안의 값이다(ADR-0041 결정 8). 쓰임으로 세는 것은 `Ping`/`Pong`이 아닌 control message와 양 끝에서 터널 splice가 옮기는 바이트이고, 마지막 쓰임으로부터 15초(`active_window`) 안이면 probe가 250ms 간격으로 나가 마지막 생존 증거 뒤 4.25~4.5초에 판정이 선다. 15초 넘게 아무것도 나르지 않은 등록은 probe가 5초 간격(idle beat)으로 나가므로 `(strikes + 1) × 5초`, 기본 20초 안팎(최대 25초)에 서고 `P×S+D`는 적용되지 않는다. 터널 트래픽이 다시 흐르면 곧바로 250ms 간격으로 돌아온다. idle beat와 `active_window`는 설정이 없다.
- **정책 파일 진단.** `qsh serve`(§6.12)와 동일한 규율이다 — `qsh listen`/`qsh serve --to`(구 `qsh reverse`) 둘 다 시작 시 `acl.toml`을 1회 읽는다. 파일이 없으면 행이 없는 정책으로 시작하고 trust role이 그대로 동작하며, 파싱 불가면 role을 포함해 리소스를 생성하지 않고 도달하는 모든 인가 판정이 항상 `deny`다(`docs/design/architecture.md` §6). 운영자에게는 stderr에 없을 때 한 줄을, 파싱 불가일 때 파일 경로, `CONFIG_ERROR` 코드, 최소 정책 예시를 담은 진단 블록을 한 번 출력하고(§6.12와 같은 평문 — `StartupDiagnostic::render`, tracing JSON 라인이 아니다), 자동 생성은 하지 않는다. `qsh listen`은 controller로서 `host.reverse` 등록 요청을, `qsh serve --to`는 target으로서 그 연결 위에서 relay되는 세션 op을 각각 자기 자신의 `acl.toml`로 평가한다. `qsh serve`의 페어링 성공 시 pin 고지(§6.11)가 "행이 있나"를 묻는 근거도 여기 §6.13이 서술하는 것과 같은 시점 위험을 진다 — 정책은 프로세스 기동 시 1회만 읽히므로, 그 뒤에 `acl.toml`을 편집해도 재시작 전까지는 반영되지 않는다. 그 고지의 관측절은 §6.11이 서술하듯 pin된 이름이 자칭인지 `--as`-지정인지에 따라 "pinned a new peer under the name it sent for itself because the invite carried no --as:"(`PAIRING_PINNED_SELF_ASSERTED`) 또는 "pinned a new peer under the name the invite assigned with --as:"(`PAIRING_PINNED_INVITE_ASSIGNED`)로 갈리고, 이어지는 " \"<name>\". " 뒤로는 role 절("Its trust role is"(`PAIRING_ROLE_LEAD`)로 시작하는 문장, role이 `none`이면 정확히 "Its trust role is `none`, so the role grants no action."(`PAIRING_ROLE_NONE`)), 행 절(행이 없으면 정확히 "No `[[acl]]` row names it, so only the role decides."(`PAIRING_ACL_ROW_ABSENT`), 행이 이미 있으면 "An `[[acl]]` row already names it, so that row's grants are added to the role's, including any you did not mean for this device."(`PAIRING_ACL_ROW_PRESENT`)), 확인 절("A role change applies from the next request; an acl.toml change needs a restart of this `qsh serve`. Check with:"(`PAIRING_CHECK_LEAD`) 뒤에 'qsh acl check' 명령)이 차례로 온다 — 문안 정본은 §6.11 하나이고 이 절은 그 상수를 재인용할 뿐이다. `qsh listen`/`qsh serve --to`는 pairing 교환 자체를 갖지 않으므로(트래픽은 항상 인바운드 `qsh serve`가 받는다) 이 고지가 여기서 발화하지는 않는다.
- 시작 시 실제로 bind된 주소와 등록 이벤트(`registered|denied|replaced|lost|expired|retry|wake`)를 stderr에 구조화 진단(tracing target `qsh::reverse`, 한 줄 JSON, payload·토큰 field 없음)으로 출력한다 — stdout에는 §2.2 규칙에 따라 한 바이트도 쓰지 않는다. 이 진단은 `qsh.cli/v1`/`qsh.event/v1` 계약에 속하지 않는 열린 어휘다(issue #4 item 6). `denied`/`lost`/`retry`는 실패·유실 사유를 `cause` 필드(고정 9값 — `resolve`/`dial_timeout`/`refused`/`tls_rejected`/`registration_denied`/`peer_closed`/`path_dead`/`idle_timeout`/`local`. `tls_rejected`는 handshake 거부 외에 신뢰 철회로 닫힌 연결(close 코드 `0x1005`, 어느 쪽이 닫았든)도 가리키며, 이 경우 재dial은 일시 유실용 빠른 경로가 아니라 handshake 거부와 같은 일반 backoff로 간다(ADR-0031 결정 7). `idle_timeout`은 QUIC idle timeout 만료이며 상대가 보낸 path-dead close나 자기 쪽 경로 감시 판정과 구별된다. 실패 지점에서 분류되며 주소·토큰·peer가 보낸 오류 본문은 절대 담지 않는다)로 함께 내고, `registered`/`replaced`/`expired`는 이 필드를 생략한다. controller 주소가 여러 개로 resolve되는 경우(issue #4 item 2) 한 번의 접속 시도는 최대 4개까지 순서대로 dial을 시도하며, 그중 전부가 실패했을 때의 `cause`와 그 실패까지 걸린 `since_registered_ms`는 마지막으로 시도한 주소 하나의 실패만을 서술한다 — 그 이전에 실패한 주소들은 이 진단 줄에 남지 않는다. 모든 레코드는 RFC3339 `at` 필드를 갖는다 — 초 단위 정밀도이고(`crate::config::now_rfc3339`), wall-clock 기록일 뿐 정렬 키가 아니다(같은 `lost`/`retry` 쌍처럼 짧은 간격으로 이어지는 레코드는 `at`이 같은 초로 겹칠 수 있으며, 순서가 필요하면 stderr에 실제로 쓰인 `qsh::reverse` 줄 순서를 봐야 한다). `retry`는 언제나 `fingerprint`를 생략하고(그 시점에는 아직 TLS 핸드셰이크가 없어 알 수 없다), `lost`와 그 직후의 `retry`는 그 등록이 살아 있던 기간을 `since_registered_ms`(ms)로 함께 내는 반면 등록이 성립한 적 없는 `retry`(가령 `dial_and_register` 자체가 실패한 경우)는 이 필드도 생략한다 — 어느 쪽이든 `null`이 아니라 키 자체가 없다. `cause`가 `path_dead`인 `lost`는 그 판정을 이 프로세스의 경로 감시가 직접 내렸을 때만 `srtt_ms`(판정 시점의 smoothed RTT, ms)와 `silence_ms`(그 감시가 경로의 생존을 마지막으로 확인한 뒤 흐른 시간, ms)를 함께 싣는다. 둘 다 정수이고 payload는 없다. 상대가 보낸 path-dead close로 분류된 `path_dead`, 다른 모든 `cause`, `retry`와 나머지 이벤트에는 `null`이 아니라 키 자체가 없다. `silence_ms`는 제어 메시지뿐 아니라 UDP datagram 수신도 생존 증거로 세어, 그 가운데 가장 늦은 시각부터 잰다(`docs/design/protocol.md` §10). 제어 스트림의 `Pong`이 늦어도 datagram이 도착하는 동안은 침묵이 다시 0에서 시작하므로, 패킷은 계속 왔는데 침묵이 길게 찍히는 값은 나오지 않는다. datagram은 틱마다 한 번 표본으로 읽으므로 실제보다 최대 한 틱(기본 250ms) 짧게 나올 수 있고, 기본 설정에서는 `silence_ms`가 1000 이상이다. 경로 감시가 자기 tick이 한 `probe_interval`(기본 250ms) 이상 늦게 발화한 것을 보면 그 지연은 프로세스가 돌지 못한 시간이지 경로의 침묵이 아니므로 침묵에서 덜어내고, 그 tick은 지연만큼 더 쌓인 침묵이 아니면 사망을 선언하지 않는다(ADR-0042 결정 1). 그래서 `silence_ms`는 이 프로세스가 깨어서 본 침묵이다. 같은 줄에는 `tick_gap_ms`(정수, ms)가 `srtt_ms`·`silence_ms`와 함께 실린다. 이름과 달리 tick 사이의 간격이 아니라, 그 침묵 동안 이 감시의 tick이 잔 beat보다 가장 늦게 발화한 양(`간격 - 잔 beat`)이다. 대기 cadence는 빼므로 정상 프로세스는 활성이든 유휴(5초 beat)든 0 언저리이고 몇 초라면 그 프로세스가 굶고 있었다는 뜻이다. 존재 규칙은 `srtt_ms`와 같다. 양쪽 감시가 같은 등록을 보므로 한쪽이 먼저 판정하면 다른 쪽은 그 close를 읽어 이 필드 없이 `path_dead`로 분류한다. `wake`는 target(`qsh serve --to`)만 내는 이벤트로, 절전에서 깨어난 것을 감지했음을 뜻하며 `slept_ms`(ms)와 `at`만 싣는다(`host`는 다른 줄과 같고 `fingerprint`·`delay_ms`·`cause`·`since_registered_ms`는 없다). target은 wake를 받으면 backoff를 `backoff_initial_ms`부터 다시 세고, 진행 중인 재접속 대기를 끊어 곧바로 재dial한다. wake 뒤 60초(단조 시계) 동안은 재접속 지연이 `max(backoff_initial_ms, 2000)`ms를 넘지 않고, 설정한 `backoff_max_ms`가 그보다 작으면 그 값이 상한이다. 이 60초 창은 wake에만 열리고 유실에는 열리지 않는다. 유실 뒤 첫 재dial의 지연은 끝난 등록이 얼마나 살았는지에 따라 갈린다(ADR-0042 결정 2). 60초(`since_registered_ms` 60000) 이상 살았으면 `backoff_initial_ms`다. 60초가 못 되어 끝난 등록이 연속되면 첫 번째는 같고 두 번째부터 유실마다 두 배가 되어 `max(backoff_initial_ms, 8000)`ms에서 멈춘다(`backoff_max_ms`가 그보다 작으면 그 값이고, 위 wake 창 안에서는 창의 상한이 먼저 닿는다). 60초 넘게 산 등록이 끝나거나 wake가 오면 연속 횟수가 0으로 돌아간다. dial 실패가 이어질 때의 지수 backoff는 이와 별개로 그대로다. 이 지연은 그 `retry` 줄의 `delay_ms`로 읽는다. `[reverse]` 키와 기본값은 그대로다(ADR-0023 결정 20).
- **`cause=local`의 뜻과 나오는 자리(이슈 #11 요청 3, ADR-0042).** `local`은 "이 프로세스 쪽에서 났거나 위 값 어디에도 못 넣는 끝"이라는 마지막 칸이다. 시간 초과는 담지 않는다. dial이나 `Hello` 응답이 시간 안에 오지 않으면 `dial_timeout`, 연결이 45초 침묵하면 `idle_timeout`, 경로 감시가 죽었다고 판정하면 `path_dead`이고, 상대의 close·stateless reset은 `peer_closed`(상대의 `CLOSE_CODE_PATH_DEAD`는 `path_dead`)다. 그래서 호스트가 부하로 굶는 상황은 이 넷으로 보이고, `local`이 거기서 나오는 것은 기대된 모습이 아니다. `local`이 반복해서 나오면 아래 자리 가운데 하나가 실제로 실패하고 있다는 뜻이고, 같은 시각 stderr의 `registration attempt failed`·`connection to the controller ended` 경고 본문이 어느 자리인지 가린다. 나오는 자리는 `crates/qsh-core/src/reverse/`의 분류 함수 전부이며 정확히 아래다.
  - `qsh serve --to`의 `retry`(등록이 서기 전이라 `since_registered_ms`가 없다): `hosts.toml`을 읽지 못함, controller 이름에 알려진 주소가 `hosts.toml`에도 trust pin에도 없음, dial용 endpoint를 만들지 못함(UDP 소켓·TLS 설정 단계), `Hello` 교환이 프로토콜에서 어긋남(첫 메시지가 `Hello`가 아님, 공통 wire minor 없음, 연결 오류가 없는 스트림 오류), 아래 "연결 종료 이유" 집합.
  - `qsh serve --to`의 `lost`(등록이 선 뒤): 아래 "연결 종료 이유" 집합, control 스트림 처리가 연결 오류가 아닌 오류로 끝남(프레이밍·디코드 오류, 연결 오류 없는 스트림 오류), 그 처리 task의 패닉이나 취소.
  - `qsh listen`의 `lost`: control 스트림 읽기·쓰기가 연결 오류 없는 오류로 끝남(상대가 보낸 wire 오류 응답, 지원하지 않는 상대, 프로토콜을 어긴 상대, 프레이밍 오류), 아래 "연결 종료 이유" 집합. `denied`는 늘 `registration_denied`라 `local`이 나오지 않는다.
  - 연결 종료 이유: quinn의 `LocallyClosed`(이 쪽이 닫은 연결이며 닫는 경로 대부분은 `lost` 줄을 내지 않는다), `ConnectionClosed`(상대의 QUIC 스택이 전송 계층 오류로 끊음), `TransportError`, `VersionMismatch`, `CidsExhausted`. `ApplicationClosed`(`peer_closed`, 코드가 `CLOSE_CODE_PATH_DEAD`면 `path_dead`), `TimedOut`(`idle_timeout`), `Reset`(`peer_closed`)은 이 집합에 들지 않는다.
  - 이슈 #11의 laptop `local` 둘(부하 평균 50 이상 호스트, 등록이 70초 가까이 산 뒤): 그 빌드는 `Reset`과 `Hello` 응답 시간 초과도 `local`로 냈다. 로그만으로는 어느 쪽이었는지 가리지 못하지만, hub가 `path_dead`로 닫은 뒤 한참 늦게 `local`이 찍힌 모양은 hub가 이미 버린 연결에 대한 stateless reset과 맞는다. 이 빌드부터 두 경우는 `peer_closed`와 `dial_timeout`이다.
- **수명 줄.** `qsh listen`은 사람용 `listening on` 줄과 `shutting down` 줄 옆에, `qsh serve --to`(숨김 alias `qsh reverse` 포함)는 stderr에 tracing target `qsh::lifecycle`의 한 줄 JSON 수명 줄을 함께 낸다(ADR-0023 결정 21). 첫 키는 `lifecycle`이고 값은 `listening`, `shutting_down`, `drained`, `tunnel_opened`, `tunnel_ended` 다섯이다. 모든 줄이 `at`(RFC3339, 초 단위)과 `process`(`serve`, `listen`, `serve_to`, `tunnel`)를 싣는다. `tunnel_*` 줄은 `tunnel_id`, `mode`, `supervise`(bool)를 더 싣고, `tunnel_ended`는 `code`와 알 수 있으면 `cause`(§6.13의 고정 어휘)를 싣는다. `drained`의 필드는 §6.12가 적은 대로이며 세션을 호스팅하는 `qsh serve --to`만 내고 `qsh listen`은 내지 않는다. 주소, bind 주소, 토큰, 오류 본문은 어느 줄에도 싣지 않는다. 주소는 사람용 줄에 이미 있다. 사람용 줄의 바이트는 바뀌지 않으며 이 줄은 그 뒤에 온다. 기본 verbosity에서 보이고 `--quiet`에서만 꺼진다. `qsh.cli/v1`/`qsh.event/v1` 밖의 열린 어휘이고 stdout에는 쓰지 않는다(§2.2). `qsh listen`은 `process: listen`, `qsh serve --to`는 `process: serve_to`다. target에는 사람용 `listening` 줄이 없으므로 `serve_to`의 `listening`은 런타임이 올라와 첫 dial을 시작하는 시점을 뜻하고 controller와의 등록 성공을 뜻하지 않는다. 등록 상태는 위 `qsh::reverse` 줄이 말한다.
- `qsh serve --to <listener>`의 `<listener>`는 이름을 먼저, 주소를 다음으로 시도하는 2단계로 해석된다(ADR-0014 결정 7): 먼저 §6.8과 동일한 host→주소 해석(`hosts.toml` 우선, 없으면 `trust.toml`의 pinned peer)으로 trust store alias를 찾고, 그 이름이 없을 때만 리터럴을 정규화해(포트 없으면 4433 보충, §6.11) `trust.toml`의 pin 중 정규화된 주소가 일치하는 것을 찾는다 — 정확히 하나가 일치하면 그 peer의 이름이 controller key가 되고, 둘 이상이면 `INVALID_ARGUMENT`(first-wins 없음), 하나도 없으면 이름 조회 쪽의 오류(보통 `HOST_NOT_FOUND`)로 실패한다. 이름이 주소보다 항상 우선한다 — 주소처럼 생긴 이름으로 pin된 peer(`"192.0.2.10:4433"`)는 그 주소에 실제로 있는 다른 peer가 아니라 자기 자신으로 해석된다. 주소 해석으로 포트가 채워졌을 때만(§6.11과 동일한 `ADDRESS_PORT_ASSUMED_NOTICE`) stderr에 한 번 알린다. 등록에 성공하면 그 연결 위에서 host 역할로 동작하며, 서비스하는 세션은 `qsh serve`(인바운드)와 같은 broker·writer lease 규율을 그대로 따른다. **관찰 가능한 차이는 writer lease를 쥐는 connection이 상주 `qsh listen` 데몬이 유지하는 역방향 connection에 결합된다는 점이다** — 그 connection이 죽으면(재접속 루프가 새 connection을 세우기 전) lease는 forward 세션과 동일하게 자동 해제된다(architecture.md §3).
- **Windows.** `qsh listen`과 `qsh serve --to`(그리고 숨김 alias `qsh reverse`)는 Windows에서도 unix와 같은 규율로 동작한다(ADR-0035 결정 1·14). 데몬의 localctl 끝점은 UDS 대신 named pipe `\\.\pipe\qsh-<scope>-<pid>`다. `qsh listen`은 그 이름을 QUIC listener보다 먼저 선점하므로, 이미 누가 쥔 이름이면 UDP 포트를 열기 전에 기동이 실패한다. `qsh serve --to`는 `qsh serve`와 같은 host 역할을 내며 ConPTY 세션, `exec`, 파일 op, 터널을 모두 받는다(ADR-0035 결정 3·25·26). `--to` 리터럴 자체의 대상 해석(`HOST_NOT_FOUND`/`INVALID_ARGUMENT`, §6.8과 같은 이름-그다음-주소 2단계)은 어느 OS에서나 dial 전에 먼저 실패할 수 있다. `qsh hosts`는 forward host와 데몬이 쥔 reverse 항목을 함께 돌려주고, 데몬이 없으면 reverse 항목만 빠질 뿐 오류가 아니다.
- **Windows의 종료.** 두 모드는 `Ctrl-C`와 콘솔 닫힘 이벤트(창 닫기, 로그오프, 시스템 종료, `CTRL_BREAK`)를 종료 요청으로 받는다. 콘솔이 닫히는 경우 운영체제는 핸들러가 돌아오면 프로세스를 끝내므로, 핸들러는 등록을 닫고 정리가 끝날 때까지 최대 4초를 붙든다. 그 안에 끝나면 target은 `CONNECTION_CLOSE`를 보내서 controller가 45초 idle timeout을 기다리지 않고 바로 `stale`로 바꾼다. 강제 종료(`taskkill /f`)는 이 정리를 건너뛰므로 controller는 idle timeout 또는 경로 감시로 알아챈다.
- **Windows의 half-close(ADR-0035 결정 14).** byte 모드 named pipe에는 쓰기 방향만 닫는 방법이 없어서, Windows conduit은 framed `qsh.local.v1` 메시지(`LocalHello`, ack, `StreamHeader`)가 끝나고 raw byte 구간이 시작된 뒤부터 양쪽 방향을 chunk로 나른다. chunk는 4바이트 big-endian 길이 뒤에 그 길이만큼의 바이트가 오는 모양이고, 길이 0은 쓰는 쪽이 자기 방향을 끝냈다는 표시(end chunk)다. 길이 상한은 65536이며 그보다 큰 길이와 end chunk 뒤의 바이트는 프로토콜 오류로 보고 I/O 오류와 같게 conduit을 abort로 끊는다. 그래서 reverse route의 `-L` 연결에서 로컬 앱이 쓰기만 닫으면 그 닫기가 목적지에 닿고 목적지는 그 뒤에도 응답할 수 있으며, 목적지가 먼저 끝내는 반대 경우도 같다. unix의 UDS는 half-close를 하므로 raw byte를 chunk 없이 그대로 나른다. 정의는 `docs/design/protocol.md` §11-3의 "raw 구간의 chunk framing"이다.
- **방화벽 첫 허용 프롬프트(ADR-0035 결정 25).** Windows Defender 방화벽은 고정 UDP 포트를 와일드카드 주소(`[::]:4433` 같은 non-loopback bind)로 여는 `qsh serve`와 `qsh listen`이 처음 뜰 때 허용 여부를 묻는다. 묻는 단위는 실행 파일 경로라서 같은 경로의 `qsh.exe`는 한 번이고 다른 경로로 옮기거나 다시 설치하면 다시 묻는다. 같은 장비 안의 loopback 연결만 쓰면 허용하지 않아도 되고, 다른 장비가 닿으려면 사설 네트워크에서 허용하는 것으로 LAN의 peer에게는 충분하다. 허용하지 않으면 상대의 패킷이 방화벽에서 조용히 버려져, peer 장비에서 이 host를 향해 돌린 `qsh doctor <host>`가 `udp_egress_blocked`(§6.17)를 낼 수 있다. `qsh serve --to`는 밖으로 dial만 하고 loopback bind(`-L`·`-D`의 listener)도 묻지 않으므로 해당하지 않는다. named pipe는 방화벽을 지나지 않는다. qsh는 방화벽 규칙을 만들거나 바꾸지 않는다.
- **코드 pairing은 이 두 모드에 닿지 않는다(ADR-0013).** 초대 코드의 상환 창구(`SharedInviteStore`)는 인바운드 `qsh serve`의 기동 경로에만 배선돼 있어 `qsh listen`도 `qsh serve --to`도 열지 않는다. 따라서 `pair invite`/`pair accept`로는 controller도 target도 pin할 수 없고, 어느 방향이든 §6.11의 인증서 파일 교환(`qsh identity export` + `qsh trust add --cert-file`)이 그 경로다. 상환 창구를 `qsh listen`에도 열지는 ADR-0015가 다뤘으나 2026-10-12에 기각됐다(만들지 않는다).
- 연결이 죽은 등록은 `state:"stale"`로 표시됐다가 `[listen].stale_retention`(기본 120s, `docs/design/protocol.md` §11-4)이 지나면 목록에서 제거된다.
- **Controller 측 writer lease 결합.** live 역방향 등록으로 뜨는 host를 향한 controller 쪽의 `qsh session ...`(value op 6종: open/get/list/read/write/resize/close)는 그 명령을 실행한 CLI 프로세스 자신의 QUIC connection이 아니라, 상주 `qsh listen` 데몬이 target과 유지하는 그 **하나의** reverse connection을 `LOCAL_CONTROL` conduit(`docs/design/protocol.md` §11-3)으로 relay해서 나간다. **대화형 attach(`qsh <name>`/`qsh attach <name>/<id>`)도 이 경로를 탄다.** `Ops::session_attach`는 route-aware해졌다(`Ops::connect`로 host route를 먼저 resolve하고, 그 결과가 live 역방향 등록이면 forward의 `connect_target`이 아니라 이 §의 `LOCAL_CONTROL` conduit으로 향한다); ticket을 실제로 redeem하는 data 스트림도 이제 `LOCAL_STREAM` conduit(위 conduit 모델 문단, `docs/design/protocol.md` §11-3)로 역방향에서 열린다 — 데몬은 그 conduit 위에서 `LocalHello`/`LocalHelloAck` 교환 뒤 wire `StreamHeader{SESSION_DATA, ticket}`를 받아 host의 QUIC connection 위에 새 bidi stream을 열고 그 뒤로는 순수 byte splice로만 동작한다(SessionFrame을 파싱하지도, payload를 로그하지도 않는다). 아래 lease 결합 규칙은 지금 이 value op·stream op 양쪽 모두에 참이다: 위 항목의 "writer lease를 쥐는 connection이 데몬의 reverse connection에 결합된다"는 target 쪽 서술의 controller 쪽 대응이다 — target이 실제로 보는 유일한 connection은 데몬의 것이므로, **writer lease는 데몬의 connection에 묶이지, lease를 요청한 CLI 프로세스 자체에는 묶이지 않는다.** 그 CLI 프로세스가 죽어도(터미널 종료, `Ctrl-C`, 비정상 종료) 데몬의 reverse connection이 살아 있는 한 lease는 자동 해제되지 않는다 — forward 세션(§5, architecture.md §3)의 "소유 connection이 죽으면 lease가 자동 해제"라는 기대가 reverse 경로에서는 CLI 프로세스 단위가 아니라 데몬 connection 단위로 적용된다는 뜻이다. **동시 attach 격리.** 이 lease를 실제로 쥐는지 판정하는 identity는 물리 connection(`ctx.connection_id()`)이 아니라 그 attach가 redeem한 단발성 ticket에서 유도된다(`WriterLease::take_owned`) — 그렇지 않으면 한 데몬을 거치는 모든 local CLI가 같은 물리 connection을 공유하는 탓에 서로 다른 두 attach가 같은 identity로 오인되어 조용히 lease를 공동 소유하고 (`no_steal`이 걸려 있어도) 서로의 keystroke를 같은 PTY에 섞어 넣는다. 반면 `no_steal`이 충돌 여부를 판단하는 기준은 여전히 **principal뿐**이다(architecture.md §3(b)). reverse 경로에서 한 데몬을 relay로 쓰는 모든 local CLI 프로세스는 — 어느 프로세스가 열었든 — 항상 그 데몬의 reverse connection과 같은 controller principal로 인증되므로, "타 principal이 lease를 쥐고 있다"는 `no_steal` 충돌의 전제 자체가 reverse 경로 안에서는 성립하지 않는다(`session.write`가 opener 결합 때문에 이미 이 규칙을 재현할 수 없는 것과 같은 이유, 바로 위 architecture.md §3(b) 인용). 즉 죽은 CLI가 남긴 lease는 자동 해제되지 않지만, 다음 attach는 대화형이든 `no_steal`을 쓰는 자동화든 관계없이 항상 그 lease를 이어받는다 — `SESSION_CONFLICT`는 이 reverse 시나리오에서는 발생하지 않는다.
- **`exec`도 이 conduit 모델을 탄다 (issue #5).** 라이브 역방향 등록으로 뜨는 host를 향한 `qsh exec`는 §6.1·§6.8의 라우팅 우선순위로 그 등록을 골라 잡으면 위와 같은 두 conduit을 그대로 쓴다 — control 요청(`ExecStart`)은 `LOCAL_CONTROL` conduit으로, 그 exec의 data(`StreamHeader{EXEC_DATA, ticket}` 후 framed `Stdin`/`StdinEof`/`Stdout`/`Stderr`/`ExecExit`, protocol.md §7)는 데몬이 relay하는 `LOCAL_STREAM` conduit(`docs/design/protocol.md` §11-3)으로 나간다 — `SESSION_DATA`와 같은 자리에 나란히 선다. 로컬 UDS 쪽에서 그 conduit이 EOF로 닫히면(exec 클라이언트 프로세스가 종료되거나 drop되거나 취소됨 — stdin을 닫는 것은 `StdinEof` 프레임이 따로 나르므로 여기 해당하지 않는다) 데몬은 host 쪽 QUIC stream을 정상 종료가 아니라 reset으로 옮긴다 — `ExecFrame`은 `StdinEof`로 EOF를 명시적으로 표현하는 framed 프로토콜이라, clean stream close는 host의 exec 실행기에 아무 의미도 없기 때문이다. exec가 §6.1 라우팅으로 그 등록을 고르는 시점에 이미 stale이면 `HOST_NOT_FOUND`(`details.reason: "reverse_registration_stale"`, §6.1)로 실패한다. 라우팅 이후 — `ExecStart` 발급과 `LOCAL_STREAM`의 `EXEC_DATA` 상환 사이에 — 등록이 바뀌면 같은 `HOST_NOT_FOUND`이되 `details`는 없고, `retryable`은 그 사이에 무슨 일이 있었는지로 갈린다. 등록이 다른 generation·fingerprint로 다시 살아난 경우는 세션 쪽 자체 검사(`Session::open_local_data_link`, `crates/qsh-core/src/client/mod.rs`)가 잡아 `retryable: true`다. 등록이 아예 사라져 데몬이 `LOCAL_STREAM` hello에 자기 자신의 `HostNotFound`로 답한 경우는(`crate::localctl::daemon`) `ErrorCode::HostNotFound`의 기본값을 그대로 물려받아 `retryable: false`다.

- **역방향 attach도 forward와 같은 `Reconnect` 추상으로 복구한다.** `LOCAL_STREAM`/`LOCAL_CONTROL` conduit 위의 역방향 attach는 데몬의 reverse connection이 끊기면 `LocalReconnect`로 같은 세션에 resume한다(`crates/qsh-core/src/ops/session/reconnect.rs`, `docs/design/protocol.md` §10). 세션 자체는 forward와 똑같이 broker가 쥐고 있어 connection 수명과 분리돼 있다(architecture.md §3). 이 동작은 `a_severed_reverse_path_resumes_the_same_session_under_a_live_cli_attach`(`crates/qsh-testkit/tests/it/reverse_resume_chaos.rs`)와 `crates/qsh-cli/tests/it/reverse_blackout.rs`가 고정한다.
- **Tunnel(`-R`)도 같은 결합을 따른다.** 위 두 항목이 세션의 writer lease/attach에 대해 말하는 "데몬의 reverse connection에 결합된다"는 성질은 `-R`이 연 target 쪽 listener에도 그대로 적용된다 — §6.9·§6.14의 예외 문단이 다룬다.

### 6.14 Holder lifetime

터널의 local listener(`-L`) 또는 remote 등록(`-R`, host가 bind)은 그것을 연 CLI 프로세스가 살아 있는 동안만 존재한다 — 터널 전용의 별도 client daemon은 두지 않는다: `qsh serve`/`qsh listen`(§6.12·§6.13)과 달리 터널은 그 자체로 장기 실행 모드가 아니라, 터널을 연 **interactive foreground 프로세스**(대화형 `qsh [user@]host -L …/-R …` 또는 foreground로 유지되는 `qsh tunnel open --json`)에 수명이 결합된다. (아래 reverse route `-R` 예외는 이 규칙을 어기지 않는다 — 새 daemon을 두는 것이 아니라, session op이 이미 §6.13에서 쓰는 **기존** `qsh listen` 데몬의 reverse connection을 carrier로 재사용할 뿐이다.) 그 프로세스가 끝나거나(Ctrl-C, 터미널 종료) 밑에 깔린 QUIC connection이 죽으면, 그 프로세스가 쥔 모든 터널이 함께 끝난다 — 진행 중이던 개별 TCP 연결은 끊기고, local listener/remote 등록 자체가 재수립 없이 사라진다(§7 대화형 attach의 세션과 달리, 터널 listener/등록은 connection 수명과 분리되지 않는다 — splice된 개별 TCP 연결의 생존 여부는 M4 이후 splice 구현 단계의 몫이다). 다시 쓰려면 새 `tunnel.open`이 필요하다. 다만 `--supervise`를 준 터널은 이 규칙의 예외다(`--supervise` 예외는 아래 문단).

**예외 — `--supervise`(M12, ADR-0023).** `--supervise <ms>`를 준 `--local`/`--dynamic`/`--remote` 터널은 밑의 connection이 죽어도 끝나지 않는다. 터널을 연 프로세스 안의 supervisor가 처음 해석한 주소로 다시 dial한다. 로컬 listener는 같은 주소에 bind된 채 남고 `tunnel_id`도 바뀌지 않는다. `--remote`는 남길 로컬 listener가 없다. 등록은 그것을 만든 connection과 함께 사라지므로, 새 carrier 위에서 먼저 직전 `forward_id`를 `RemoteForwardClose`로 닫고(성공과 `INVALID_ARGUMENT`의 "no such forward_id"를 둘 다 "이미 없다"로 읽는다) 이어 같은 `bind_host`·`forward_host`·`forward_port`와 처음 얻은 `actual_port`로 `RemoteForwardOpen`을 새 `claim_token`과 함께 다시 보낸다. close 뒤에도 bind가 `CONNECTION_FAILED`로 실패하면 200ms 간격으로 open만 3번까지 다시 보내고, 그래도 실패하면 그 시도는 실패다. 재발행은 peer의 정책(`forward.remote`, loopback 강제, quota)을 처음 open과 똑같이 거친다(결정 7-4, 8). 포트를 되찾지 못하거나(그 사이 다른 principal이 잡았다) 정책이 재발행을 거부하면(예: `PERMISSION_DENIED`) 터널은 끝난다. 재발행마다 peer가 새 `forward_id`를 주므로 `-R` 터널의 `tunnel_id`는 바뀐다(결정 13). 최초 봉투는 처음 값을 그대로 두고, 현재 값은 `reestablished` 줄의 `tunnel_id`(직전 값은 `previous_tunnel_id`)와 reverse route의 `qsh tunnels`에서 본다. 최초 `tunnel_id`로 `qsh tunnel close`를 하면 더는 그 id가 없으므로 `closed: false`다. connection이 끊겼다고 판정된 순간부터 새 연결은 대기열 없이 거절된다. `-L`은 accept한 뒤 RST로 닫고, `-D`는 SOCKS `CONNECT`에 REP `0x01`을 보낸다. `--accept-hold <ms>`를 함께 준 터널만 예외다. 재수립 시도가 진행 중이거나 다음 시도가 그 기한 안에 시작되면 새 연결을 최대 `<ms>`(상한 2000) 동안 붙들고, 그동안 어느 carrier로도 바이트를 보내지 않는다. carrier가 되돌아오면 accept 순서대로 새 carrier에 싣고, 기한이 먼저 오면 위와 같이 거절한다. 동시에 붙드는 연결은 터널당 64개까지다(§6.9). 이미 splice 중인 연결은 건드리지 않는다. 옛 connection이 살아나면 그 연결도 살고, 죽으면 기본 모드와 똑같이 reset된다. `trust remove`는 이미 살아 있는 connection을 2초 안에 닫고(§6.11, ADR-0031), 터널은 그 connection을 잃은 것으로 보고 재수립으로 간다. 재수립의 handshake가 거절되면 터널은 예산 안에서 재시도하다 `gave_up`으로 끝난다(§6.9). 닫힘 자체가 `lost` 줄을 만든다. 새 connection은 peer의 TLS fingerprint가 처음 open의 값과 같고, `-D`라면 `dial-filter.v1`도 그대로 있을 때만 carrier가 된다. 다르면 요청을 하나도 보내지 않고 각각 `AUTH_FAILED`, `UNSUPPORTED`로 끝난다. 재수립마다 peer가 `TCP_CONNECT`를 스트림 단위로 다시 인가하므로 재시작한 peer의 ACL이 좁아졌다면 그 첫 요청이 `PERMISSION_DENIED`로 터널을 끝낸다. reverse route에서는 carrier가 이 머신 자신의 `qsh listen` 데몬으로 향하는 `LOCAL_CONTROL` conduit과 그 등록이다. 다시 세울 때는 데몬에 다시 묻고(`LocalHello.host`, 같은 소켓이면 `known_generation`, `wait_ms`는 남은 예산과 60초 중 작은 값), 같은 이름의 forward pin은 후보로 보지 않는다(ADR-0023 결정 22). 돌아온 등록의 peer fingerprint가 처음 open의 값과 다르면 요청을 하나도 보내지 않고 `AUTH_FAILED`로 끝난다(결정 7-2). accept마다 `LOCAL_STREAM` ack의 fingerprint와 generation을 확인된 carrier의 것과 비교하고, 다르면 `StreamHeader`를 보내기 전에 그 accept를 거절하며 carrier를 잃은 것으로 보고 다시 세운다(결정 7-5). 데몬 쪽 오류는 `HOST_NOT_FOUND`, `TIMEOUT`, `CONNECTION_FAILED`만 재시도하고 나머지는 터널을 끝낸다(결정 9). peer의 host-local dial filter 거절은 peer의 정책 거부로 세지 않는다. 총 끊김 시간이 `--supervise` 예산을 넘기면 stderr에 `gave_up` 줄을 쓰고, 이어 오류를 stderr에 렌더하고, listener를 놓은 뒤 exit `255`로 끝난다. stdout에는 최초 봉투 한 줄 뒤로 아무것도 나가지 않는다. supervised 모드에서만 SIGINT·SIGTERM handler를 두며(Windows에서는 SIGTERM이 없으므로 Ctrl-C, `CTRL_BREAK`, 콘솔 닫힘·로그오프·종료가 같은 정지 요청이고, 콘솔 닫힘은 정리가 끝날 때까지 최대 4초 기다린다), 신호를 받으면 유실 중이든 아니든 감독을 멈추고 listener를 놓은 뒤 exit `0`으로 끝난다. 살아 있는 carrier가 있는 `--remote`는 끝내기 전에 best-effort `RemoteForwardClose`를 보내되 응답을 1초 넘게 기다리지 않는다(결정 11).

reverse route의 `--remote`에는 운영자 닫기가 하나 더 있다(결정 14). claim 시도가 대기 없이 곧바로 돌아왔는데 `LOCAL_CONTROL`이 살아 있으면 supervisor는 데몬의 `LocalHostList`와 `LocalTunnelList`를 한 번씩 본다. host가 확인된 generation 그대로 `reachable`이고 현재 `forward_id`만 목록에 없으면 누군가 `qsh tunnel close`를 한 것으로 본다. 이때 `closed` 줄을 쓰고, 다시 열지 않고, exit `0`으로 끝난다. 등록이 바뀌었거나 사라졌으면 유실이고 재수립으로 간다. 데몬이 답하지 못하거나 목록에 여전히 있으면 아무 결론도 내리지 않는다. 기본 모드의 신호 동작은 그대로다. Windows에서도 두 요청이 named pipe 위에서 같은 값을 돌려주므로 이 판별은 그대로이고, 데몬이 재시작하면 reverse 등록과 그 위의 터널이 모두 끝나는 점도 unix와 같다.

`--supervise`의 한계는 셋이 더 있다(ADR-0023 결과 절). 최초 open의 실패는 감독하지 않는다. `--supervise`를 줘도 최초 open은 재시도 없이 지금의 봉투와 exit `255`로 끝나고, 부팅 직후처럼 그 시점에 peer나 target이 없으면 `--wait`와 service manager 재시작에 맡긴다. 최초 open의 route는 §6.1의 우선순위를 그대로 따르므로 주소가 남은 forward pin이 있으면 reverse 전용 host도 forward route로 열리려 한다. reverse route로 열려면 그 host의 pin에 주소를 두지 않는다. 절전 복귀 감지는 벽시계와 단조 시계의 차이를 쓴다. 단조 시계 표본은 macOS·Linux에서 tokio의 `Instant`이고, Windows에서는 절전과 최대 절전 중 흐른 시간을 빼도록 문서화된 `QueryUnbiasedInterruptTime`이다. 그래서 세 OS 모두 `wake` 줄이 나오고 backoff가 즉시 다시 시도한다(ADR-0035 결정 15). 실제 절전 복귀는 사람 캠페인이 본다.

supervisor는 stderr에 tracing target `qsh::tunnel::supervise`의 한 줄 JSON 진단을 낸다. 첫 키는 `supervise`이고 값은 `lost`, `retry`, `reestablished`, `gave_up`, `wake`, `closed` 여섯이다. `closed`는 위 운영자 닫기에서만 나온다. 모든 줄이 `at`(RFC3339, 초 단위), `tunnel_id`, `mode`, `route`(`forward` 또는 `reverse`)를 싣는다. reverse route의 줄은 별칭 `host`를 더 싣고, `reestablished`는 새 `generation`도 싣는다. `--remote`의 `reestablished`는 새 `forward_id`를 `tunnel_id`로, 직전 값을 `previous_tunnel_id`로 싣는다. `LOCAL_CONTROL`이 끝난 `lost`에는 `cause`가 없다. `lost`와 `retry`는 §6.13의 고정 어휘에서 고른 `cause`를 싣고, `retry`는 여기에 `attempt`, `code`, `outage_ms`를 더한다. `reestablished`와 `gave_up`은 `outage_ms`를, `wake`는 `slept_ms`를 싣는다. `outage_ms`는 절전한 시간을 뺀 누적 끊김 시간이다. 주소, 토큰, payload, peer가 보낸 오류 본문은 어느 줄에도 싣지 않는다. 기본 verbosity에서 보이고 `--quiet`에서만 꺼지며, `QSH_LOG`나 `RUST_LOG`를 명시하면 그 값이 이 target도 다스린다. `qsh.cli/v1` 계약 밖의 열린 어휘다.

**수명 줄.** `--supervise`와 무관하게 모든 `qsh tunnel open` holder가 stderr에 tracing target `qsh::lifecycle`의 한 줄 JSON 수명 줄을 함께 낸다(ADR-0023 결정 21). 첫 키는 `lifecycle`이고 값은 `listening`, `shutting_down`, `tunnel_opened`, `tunnel_ended` 넷이다. 모든 줄이 `at`(RFC3339, 초 단위)과 `process`(`serve`, `listen`, `serve_to`, `tunnel`)를 싣는다. `tunnel_*` 줄은 `tunnel_id`, `mode`, `supervise`(bool)를 더 싣고, `tunnel_ended`는 `code`와 알 수 있으면 `cause`(§6.13의 고정 어휘)를 싣는다. 주소, bind 주소, 토큰, 오류 본문은 어느 줄에도 싣지 않는다. 주소는 사람용 줄에 이미 있다. 사람용 줄의 바이트는 바뀌지 않으며 이 줄은 그 뒤에 온다. 기본 verbosity에서 보이고 `--quiet`에서만 꺼진다. `qsh.cli/v1`/`qsh.event/v1` 밖의 열린 어휘이고 stdout에는 쓰지 않는다(§2.2). `tunnel_opened`는 봉투를 쓰고 flush한 뒤, 사람용 `holding` 줄 앞에 나온다. `tunnel_ended`는 터널이 스스로 끝났을 때만 나오며 사람용 오류 줄과 같은 사건을 가리킨다. 신호로 멈춘 supervised 터널은 `tunnel_ended` 대신 `shutting_down`(`process: tunnel`)을 낸다. supervised 터널이 예산을 다 써서 끝날 때는 `cause`가 없다.

이 예외는 forward route의 `--local`과 `--dynamic`에만 있다. `--remote`와 reverse route는 아직 `UNSUPPORTED`이고(§6.9), 그 터널은 위 규칙대로 connection과 함께 끝난다.

**예외 — reverse route 위의 `-R`.** 위 규칙은 그 tunnel의 control 요청(`RemoteForwardOpen`)을 **어느 QUIC connection이 실어 날랐는가**를 홀더로 삼는다는 관찰로 다시 읽을 수 있다 — forward route에서는 CLI 프로세스가 직접 dial한 connection이 그것이므로 둘의 수명이 그냥 같다. reverse route에서는 다르다: CLI 프로세스는 QUIC connection을 전혀 쥐지 않고 상주 `qsh listen` 데몬의 `LOCAL_CONTROL` conduit(§6.13)으로 `RemoteForwardOpen`을 relay할 뿐이며, 실제로 그 요청을 나르는 것은 그 CLI가 아니라 **데몬이 유지하는 하나의 reverse connection**이다. target 쪽에서 그 listener를 실제로 등록해 두는 표는 `Server::remote_forwards`다(`crates/qsh-core/src/server/mod.rs`) — `forward_id`를 key로 하는 flat map이고, 각 항목은 그것을 연 **principal**(`RemoteForwardEntry::owner`)과 그것을 실어 나른 connection의 `conn_id`를 함께 기록한다. 이 둘은 서로 다른 축이다: `tunnel.close`(`RemoteForwardClose`, 위 §6.9)로 **명시적으로 닫을 권한**은 owner principal 축이라 그 principal의 **어느 live connection**에서 요청해도 자신이 연 forward를 닫을 수 있다. 반면 connection이 **죽어서** 정리되는 경로는 지금도 `conn_id` 축이다 — `Server::purge_connection`이 그 connection이 연 forward를 통째로 걷어간다(purge). 그래서 아래에서 말하는 "이 connection이 살아 있는 동안"이라는 listener 수명 자체는 지금도 맞다(그 connection이 죽으면 listener도 함께 죽는다) — 바뀐 것은 "**다른** connection에서 닫을 권한이 있는가"가 connection이 아니라 principal로 판정된다는 축 하나뿐이다. 그래서 reverse route 위의 `-R`은 그것을 연 CLI 프로세스가 죽어도(Ctrl-C, 터미널 종료) target의 listener는 살아남는다 — 죽는 것은 reverse connection 자체가 끊어질 때뿐이다(`docs/design/protocol.md` §11-3의 `forward_id`→conduit 등록표 문단). 다만 그 CLI가 지녔던 `LOCAL_STREAM` claim conduit도 함께 죽으므로, target이 그 뒤 여는 `TCP_ACCEPTED`는 데몬에서 받을 conduit이 없어 즉시 reset된다 — listener는 살아 있지만 그 accept를 로컬 목적지로 이어줄 소비자가 없는 상태이며, 이 상태를 해소하려면(=다시 claim하려면) 새 `tunnel.open`으로 같은 `forward_id`를 재등록하는 op이 필요하다 — 그런 op은 없다(구현하려면 `RemoteForwardOpen`이 기존 `forward_id`를 받아들이는 새 wire 의미가 필요하다). 유일한 회복 경로는 `qsh tunnel close <id>`(§6.9)로 등록 자체를 닫아 target의 listener까지 해제하고, 새 `forward_id`로 처음부터 `-R`을 다시 여는 것뿐이다 — 같은 포트를 재사용하려는 claim conduit 재수립은 아니다. 그 CLI가 `--supervise` 없이 아직 살아 있는 holder라면 다른 프로세스의 `qsh tunnel close`로 등록이 사라진 것을 claim 시도가 대기 없이 `TIMEOUT`으로 돌아오는 것으로 알아채고 `CONNECTION_FAILED`로 끝난다(exit `255`, 사람용 오류 줄과 `tunnel_ended`, 이 end는 `LOCAL_CONTROL` conduit이 끝나는 것과 같은 취급이다). 같은 `forward_id`를 200ms마다 다시 claim하며 남지 않는다. `--supervise`의 운영자 닫기(위 결정 14, exit `0`)와 달리 닫기와 등록 교체를 가르는 조회는 하지 않는다. `-L`은 이 예외에 해당하지 않는다 — reverse route에서도 local listener(bind)는 여전히 그것을 연 CLI 프로세스 자신의 소켓이고, 데몬은 그 위를 오가는 개별 `TCP_CONNECT` 스트림의 carrier일 뿐 listener의 홀더가 아니다. `LocalForward::run`은 listener 자체의 치명적 오류에만 반환하므로(`crates/qsh-core/src/tunnel/local.rs`) 등록이 stale이 되어 있는 동안에도 listener 소켓은 bind된 채 남고, 그 사이 accept된 개별 연결만 초기화된다(§6.1의 `reverse_registration_stale`, `abort_local`) — 이 점만 떼어 보면 `LocalForward`는 reverse connection이나 등록 상태에 결합된 적이 없다. 하지만 그렇다고 `qsh tunnel open -L` 프로세스 전체가 살아남는다는 뜻은 아니다 — 이 절 첫 문단의 일반 규칙("밑에 깔린 QUIC connection이 죽으면, 그 프로세스가 쥔 모든 터널이 함께 끝난다")은 reverse route 위의 `-L`에도 예외 없이 적용된다: `TunnelHold::hold`(`crates/qsh-core/src/ops/tunnel.rs`)는 listener 오류뿐 아니라 그 등록을 실어 나르는 `LOCAL_CONTROL` conduit의 종료(`Connected::wait_dead`)도 함께 기다리므로, 등록이 stale이 되어 데몬이 그 conduit을 끝내면 hold는 그 즉시 `CONNECTION_FAILED`로 끝나고 프로세스가 종료되며 listener도 함께 사라진다. 위에서 말한 `LocalForward`의 개별-연결 복원력은 그 프로세스가 여전히 살아 있는 동안에만 관측 가능한 성질이고, target이 재등록해도 이미 끝난 프로세스는 되살아나지 않으므로 다시 열려면 새 `tunnel.open`이 필요하다 — `-R`과 달리 `-L`은 재등록만으로 스스로 복구되지 않는다.

Windows에서도 이 예외는 같다. 데몬이 reverse connection을 쥐고, CLI는 데몬의 named pipe `LOCAL_CONTROL`로 `RemoteForwardOpen`을 relay한다. CLI 프로세스가 죽어도 target의 listener는 살아남고 데몬이 죽거나 reverse connection이 끊겨야 함께 죽는다. reverse route의 `-L` 연결에서 로컬 앱의 쓰기 닫기도 unix와 같이 목적지에 전해진다(§6.13).

### 6.15 `qsh acl check`

```bash
qsh acl check --principal <principal> --action <action> [--resource <resource>] [--path <abs_path>] [--auth-path pin|ca] [--owner <principal>] [--owner-auth-path pin|ca] --json
```

`acl.check`는 §2.4·§2.5가 명시하듯 **로컬 operation**이다 — 원격 peer가 요청할 수 없고, 이 머신 자신의 `acl.toml`을 이 머신에서 조회한다. 원격으로 정책 조회를 허용하면 그 자체가 capability 열거 oracle이 되기 때문이다(`docs/ROADMAP.md` M5 감사 개정 ③). `qsh serve`/`qsh listen`/`qsh serve --to`(구 표기 `qsh reverse`)가 실제로 강제하는 것과 **같은 평가기**를 호출하므로) 이 명령의 결과는 실제 enforcement 결과의 신뢰할 수 있는 예측이다 — 재시작 전 정책을 검증하는 용도(§6.12·§6.13의 정책 파일 진단 문단)로 쓴다. 이 예측에는 한계가 둘 있다. `policy.state`는 파일이 없는 경우(`missing`)와 읽을 수 없거나 파싱에 실패한 경우(`invalid`)를 가르지만, 파싱 실패의 상세(어떤 rule의 어떤 토큰이 문제였는지)는 `acl check`가 아니라 §6.12·§6.13의 시작 진단이 정본이다 — `acl check` 자신은 그 상세를 출력하지 않는다. 그리고 enforcement에는 이 평가기 위에 fail-closed 층이 하나 더 있어서, audit 기록 자체가 실패하면 `allow` 판정이 `deny`로 뒤집히고 세션 소유자 조회가 실패해도 `deny`로 처리된다(`crates/qsh-core/src/server/mod.rs`) — 그래서 `acl check`의 `allow` 예측은 실제 운영 상태에 따라 `deny`로 뒤집힐 수 있지만, `deny` 예측이 `allow`로 뒤집히는 일은 없다.

인자:

- `--principal <principal>` (필수): 평가할 principal 문자열(`device:<name>` | `user:<name>` | `fp:sha256:<base64>`, `docs/PRD.md` §9). 모양이 셋 중 어느 것과도 맞지 않으면 `INVALID_ARGUMENT`.
- `--action <action>` (필수): PRD §9의 11종 action 중 하나(닷 표기, 예 `session.open`). 어휘에 없는 값은 `INVALID_ARGUMENT`(정책 로더가 잘못된 wildcard 패턴을 거부하는 것과 같은 층 — 오타가 조용히 통과하지 않는다).
- `--resource <resource>` (선택): action이 겨냥하는 리소스 식별자. 생략하면 리소스 개념이 없는 action으로 평가한다.
- `--path <abs_path>` (`file.read`·`file.write`에는 필수, 다른 action에는 금지): 그 action이 겨냥하는 원격 경로(ADR-0029 결정 19). 파일 action은 경로마다 판정되므로 `--path` 없이는 `INVALID_ARGUMENT`이고, 파일 action이 아닌 action에 주어도 `INVALID_ARGUMENT`다. 모양 검사는 파일 op과 같다(NUL·UTF-8·4096바이트, 절대 경로이거나 `~`·`~/…`·home 기준 상대 경로). 모양을 어긴 값은 `INVALID_ARGUMENT`이고 어느 오류 메시지도 경로를 되풀이하지 않는다. 이 검사는 `acl.toml`을 읽기 전에 한다. 정규화(`..`·symlink 해석)는 enforcement와 같은 순서로 한다. 주체에게 그 파일 action의 근거(그 action을 주는 role, 또는 `paths`가 있는 행)가 있을 때만 파일시스템을 보고, 근거가 없으면 경로를 건드리지 않는다. 정규화가 실패하면 경로 없이 판정하므로 어느 행도 덮지 못하고 `deny`다. 파일 op이 없는 플랫폼에서는 `--path`를 모양 검사 없이 받고 같은 방식으로 `deny`를 낸다.
- `--auth-path <pin|ca>` (선택): 생략 시 `acl.toml` 자체의 기본값(`"pin"`)을 적용한 것과 동일하게 평가한다.
- `--owner <principal>` (선택, additive): `--resource`의 소유자 principal. `scope = "owned"`(rule의 기본값) 행이 실제로 적용되려면 소유자가 있어야 하므로, `--owner` 없이는 그런 행이 항상 "소유자 없는 리소스"로 평가되어 무조건 통과한다 — enforcement가 소유자를 아는 상황(예: 이미 열린 세션에 대한 `session.control`)을 재현하려면 필요하다. 생략하면 이전과 동일하게 `--resource`를 소유자 없는 리소스로 평가한다.
- `--owner-auth-path <pin|ca>` (선택, `--owner`와 함께일 때만 의미 있음): `--owner`가 인증했다고 가정할 auth path. 생략 시 `"pin"`. 접힘은 enforcement가 실제로 쓰는 프로덕션 `opener_key`(`crates/qsh-core/src/acl/mod.rs`)를 그대로 호출해 만들며, 그 내부 인코딩은 CLI 표면이나 계약에 절대 노출되지 않는다 — `--owner`/`--owner-auth-path`는 그 인코딩 이전의 평문 principal/auth-path 문자열이다. `--owner` 없이 `--owner-auth-path`만 단독으로 주는 것은 clap이 usage 오류로 거부한다(exit `2`) — `--escape-char`/`-L`이 `target` 없이는 거부되는 것(§7)과 같은 `requires` 관계다.

`data`는 `AclCheckData`(`crates/qsh-proto/src/types.rs`)다:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "acl.check",
  "ok": true,
  "data": {
    "principal": "user:dave",
    "action": "exec.run",
    "resource": "exec",
    "auth_path": "pin",
    "decision": "allow",
    "rule": 0,
    "granted_by": "acl",
    "policy": {
      "path": "/Users/dave/.config/qsh/acl.toml",
      "rules": 2,
      "loaded": true,
      "state": "loaded"
    }
  }
}
```

`decision`은 `Host.connection_mode`와 같은 열린 문자열 규율(§10)로 `"allow"`/`"deny"`다. `rule`은 매칭된 정책 행의 배열 index이며, 아무 행도 매칭하지 않았거나(항상 `"deny"`를 동반), 정책이 로드되지 않았거나, 판정 근거가 role인 경우 `null`이 아니라 필드 자체가 나타나지 않는다(`owner`/`owner_auth_path` 생략과 같은 규율 — `qsh.cli/v1`은 additive-only, `CLAUDE.md`). `policy.loaded`는 `acl.toml`이 행으로 로드됐는지만 말하고, 그 상태의 뜻은 `policy.state`(열린 문자열)가 가른다.

| `policy.state` | `loaded` | 판정 |
|---|---|---|
| `loaded` | `true` | role과 행의 합집합 |
| `missing` | `false` | 행 없는 정책으로 친다. role만 허용할 수 있다 |
| `invalid` | `false` | 모든 요청이 `"deny"`다. role grant도 거부한다 |

`qsh acl check`는 `missing`·`invalid`를 오류로 만들지 않는다 — 조회는 성공했고(`ok: true`), 다만 조회된 사실이 그 상태일 뿐이다(§6.12·§6.13의 정책 파일 진단).

`path`(additive)는 `--path`를 받은 그대로 echo하고, `canonical_path`(additive)는 정규화가 돌아 성공했을 때만 나오는 정규화된 경로다. 둘 다 파일 action이 아니면 필드 자체가 나타나지 않는다. role만 그 파일 action을 주는 경우에도 정규화가 돌므로 `canonical_path`가 나온다(질의는 로컬이고, 근거를 role까지 세는 §6.19의 `effective_actions`와 같은 기준이다. enforcement의 ACL 단계는 role-only allow를 정규화하지 않는다). `canonical_path`가 없는 `deny`는 정규화가 돌지 않았거나 실패했다는 뜻이다. `paths`가 덮는 경로에서는 `"allow"`와 `rule`이 나오고, role이 주는 경우에는 `"allow"`에 `role`이 나온다. 이 질의는 상태 경로 검사와 열린 핸들 재검증을 돌리지 않는다. 그래서 `"allow"`는 "ACL이 허용한다"는 뜻이지 "호스트가 열어 준다"는 보장이 아니다. qsh 자신의 상태 경로는 `"allow"`여도 enforcement에서 거절된다.

`owner`/`owner_auth_path`(additive)는 `--owner`/`--owner-auth-path`를 그대로 echo하며, 둘 다 생략됐을 때는 필드 자체가 나타나지 않는다(`qsh.cli/v1`은 additive-only, `CLAUDE.md`).

**role 차원(ADR-0045 결정 10).** `acl check`는 enforcement와 같은 role 해석을 한다. principal이 `device:<name>`이고 `--auth-path`가 `pin`(기본값)이면 이 머신의 `trust.toml`에서 그 이름의 pin을 찾아 그 pin의 role로 평가 단계 ⓡ(§6.11의 role 표)을 돈다. 로컬 질의라 연결 fingerprint가 없으므로 pin 자신의 fingerprint를 쓴다. `data`에 optional 필드가 셋 는다.

- `role`: 평가에 쓴 role(`full` | `exec` | `tunnel` | `read-only` | `reverse` | `none`, 열린 문자열). `role` 키가 없는 pin(ADR-0045 이전의 pin)은 `none`과 똑같이 판정되므로 `"none"`으로 나온다. 그 이름의 pin이 없거나, 경로가 `ca`이거나, principal이 `device:`가 아니거나, `trust.toml`을 파싱할 수 없으면 필드가 생략된다. 마지막 경우는 돌고 있는 `qsh serve`가 role grant를 멈추는 상태와 같은 답이다(§6.12). `policy.state`가 `invalid`여도 pin의 role은 그대로 나오지만 판정은 `"deny"`다.
- `granted_by`: `"role"` | `"acl"`. `decision`이 `"allow"`일 때만 나온다. role과 행이 둘 다 허용할 수 있으면 `"role"`이다. 순서를 고정해야 audit 레코드와 이 출력이 같은 근거를 말한다. `"role"`이면 `rule`이 없고, `"acl"`이면 `rule`이 행 index다.
- `policy.state`: 위 표.

"가정한 role로 판정해 보기"에 해당하는 `--role` 플래그는 없다. 지금의 role은 `qsh trust list`가, role별 action은 §6.11의 표와 `acl show`(§6.19)가 보여 준다. role은 판정마다 `trust.toml`에서 읽으므로 `qsh trust set-role`의 결과는 재시작 없이 이 출력에 바로 나타나고, 돌고 있는 `qsh serve`/`qsh listen`도 다음 요청부터 같은 답을 낸다.

`--principal`/`--action`이 잘못된 모양이 아닌 한 `acl.check` 자체는 실패하지 않는다(exit `0`, §4). human mode 출력은 한 줄 요약(`allow`/`deny` + 근거 `role <role>` 또는 `rule <index>`, 근거 없는 `deny`이고 `policy.loaded`가 `false`이면 "no policy loaded")이다.

### 6.16 `qsh cert` — private CA

```bash
qsh cert init --json
qsh cert issue --json
```

이 device를 자기 자신의 private CA로 만드는 두 명령이다([ADR-0008](adr/0008-private-ca-cert-issuance.md)). intermediate 없이 self-signed root 하나가 device leaf를 직접 서명하는 구조이며, `qsh trust add`/`pair accept`(§6.11)가 다루는 "각 device를 개별로 pin"하는 모델과는 별도의, 병행 가능한 신뢰 축이다 — 한 device가 어느 CA의 root를 신뢰하면 그 CA가 서명한 모든 device를 개별 pin 없이 신뢰한다.

`cert.init`은 `<config_dir>/ca/`(0700)에 `ca.pem`(root 인증서)과 `ca.key`(PKCS#8 PEM private key, 0600)를 생성한다. `identity/`(§6.11의 device identity)와 의도적으로 분리된 디렉터리다 — 이 device가 *서명할 수 있는지*는 이 device *자신이 누구인지*와 다른 threat이기 때문이다. 이미 root가 있으면 새로 만들지 않고 기존 root를 `created: false`로 반환한다(멱등).

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "cert.init",
  "ok": true,
  "data": {
    "fingerprint": "sha256:BASE64FINGERPRINT",
    "config_dir": "/Users/dave/.config/qsh",
    "created": true
  }
}
```

`cert.issue`는 이 device의 **로컬 identity만**을 발급 대상으로 한다(ADR §5 — 다른 device나 user cert 발급은 범위 밖이고 CSR 흐름도 만들지 않는다, ADR-0016 기각) — 이미 있는 device identity(`qsh init`으로 만든 keypair·`device_id`)를 CA로 "승격"한다: 같은 keypair, 같은 `qsh://device/<device_id>` SAN을 CA 서명으로 다시 감싸 `identity/device.pem`을 그 자리에서 교체한다. keypair가 그대로이므로 이 device를 이미 fingerprint로 pin해 둔 다른 peer가 있어도 그 pin은 깨지지 않는다 — fingerprint는 인증서 전체가 아니라 SPKI(공개키)에서만 계산되기 때문이다(architecture.md §5). CA root는 `trust.toml [[ca]]`에 이름 `"local"`로 등록된다(`qsh trust add`와 같은 append-only·dedup 선례 — Step 2).

`qsh init`(§6.11)을 먼저 실행하지 않았거나 `qsh cert init`을 먼저 실행하지 않았으면, 어느 쪽도 조용히 만들어 주지 않고 `CONFIG_ERROR`로 실패한다 — 어느 리소스도 그 전제조건이 충족되기 전에 만들어지지 않는다(§11의 원칙).

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "cert.issue",
  "ok": true,
  "data": {
    "device_id": "device_01K0EXAMPLE",
    "fingerprint": "sha256:BASE64FINGERPRINT",
    "issued": true,
    "ca": {
      "name": "local",
      "fingerprint": "sha256:BASE64FINGERPRINT",
      "created": true
    }
  }
}
```

`cert.issue`는 두 축이 각각 독립적으로 멱등이다. leaf 재발급 축은 `issued`로 나타난다 — 이미 이 CA가 발급한 leaf라면 다시 서명하지 않고 `issued: false`를 반환한다(`fingerprint`는 이전 호출과 동일). `trust.toml [[ca]]` 등록 축은 `ca.created`/`ca.updated`로 나타나며, `trust.add`(§6.11)와 정확히 같은 모양이다 — 새 이름이면 `created: true`(이때 `updated`는 필드 자체가 생략된다), 이미 등록된 이름에 같은 root PEM이면 순수 no-op(`created: false, updated: false`), 같은 이름에 root가 달라졌으면(로컬 CA를 지우고 다시 `cert init`한 경우뿐이다) `updated: true`로 그 자리에서 덮어쓴다.

**partner의 CA root를 신뢰하려면.** `qsh cert`는 이 device 자신의 CA만 다룬다 — 상대 device가 발급한 CA root를 이 device의 `trust.toml`에 등록하는 op은 아직 없다(ADR §5, out-of-band로 상대의 `ca.pem`을 전달받아 `trust.toml`의 `[[ca]]` 표에 직접 적어 넣는 것이 M7 시점의 유일한 경로다). `trust.toml` 자체는 `qsh cert`가 만들었든 operator가 손으로 적었든 구분 없이 평가한다(trust/mod.rs).

**`acl.toml` 작성 시 주의.** CA로 인증한 principal을 허용하려는 `[[acl]]` 행은 `auth_path = "ca"`를 **명시**해야 한다 — 이 field를 생략하면 `"pin"`으로 기본값이 매겨져(§6.15의 `--auth-path` 문단과 같은 기본값) CA로만 인증한 peer는 그 행에 조용히 매칭되지 않는다(default-deny이므로 결과는 `PERMISSION_DENIED`).

pin(`AuthPath::Pin`)과 CA(`AuthPath::Ca`) 양쪽 모두 principal은 똑같이 `device:<id>` 모양이다 — 구별의 근거는 principal이 아니라 audit 기록의 `auth_path`뿐이다(ADR §6).

### 6.17 `qsh doctor` — 배포 진단

```bash
qsh doctor [host] --json
```

`doctor.run`은 §2.4·§2.5가 이미 예약해 둔 대로 **로컬 operation**이다 — 원격 peer가 요청할 수 없고, 이 머신 자신의 identity·ACL 정책·audit 로그·trust store·시계·(best-effort) 네트워크 도달성을 조회해 하나의 report로 묶는다. 인자 없는 `qsh doctor`는 outbound controller(`[serve].to`, 없으면 구 `[reverse].controller`)가 설정돼 있으면 그 연결성만 점검하고, `qsh doctor <host>`는 그 pinned host를 추가로 점검한다 — `qsh capabilities [host]`(§6.10)와 같은 UX 형태다.

**`--fail-on`을 주지 않으면 exit code는 항상 `0`이다 — finding은 data이지 실패가 아니다.** `qsh acl check`(§6.15, L845)의 선례를 그대로 확장한다: `deny`나 "정책 없음"조차 `acl check` 자체를 실패로 만들지 않듯, `doctor.run`도 아무리 심각한 finding이 나와도 조회 자체는 성공이다(`ok: true`). 건강도는 `data.overall`이 담는다. `doctor.run`이 `Err`(exit `255`)로 실패하는 경우는 doctor 자신이 조회를 시작할 조건조차 없을 때뿐이다 — 대표적으로 `qsh init`을 아직 실행하지 않아 device identity가 없는 경우, 또는 `config.toml`/`hosts.toml`/`trust.toml`이 파싱조차 되지 않는 경우(각 로더가 이미 `CONFIG_ERROR`로 잡는다 — doctor가 별도 code로 다시 잡지 않는다). output mode에 따라 이 규칙이 달라지지 않는다(§4).

`data`는 `DoctorData`(`crates/qsh-proto/src/types.rs`)다:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "doctor.run",
  "ok": true,
  "data": {
    "overall": "warn",
    "findings": [
      {
        "code": "cert_expiring_soon",
        "status": "warn",
        "detail": "A certificate this device relies on expires within 30 days. (this device's own leaf certificate, not_after unix: 1780000000)",
        "remedy": "`qsh cert issue` only re-issues a leaf this CA has not signed yet; on one it already signed, or on the CA root, it and `qsh cert init` are no-ops. Renew ahead of the deadline by removing `identity/` or `ca/` from the config directory and re-running `qsh init`/`qsh cert init` — peers must then re-pin."
      },
      {
        "code": "trust_remove_scope",
        "status": "info",
        "detail": "trust.toml has at least one pinned peer. Removing a pin or lowering its role closes that peer's established connections. It applies to new connections from the next handshake, and to connections held open by a running `qsh serve`, `qsh listen` or `qsh serve --to` within 2 seconds. It applies on this device only; no other device is told. It does not end sessions: a session on a closed connection is detached, and a peer that is still trusted can reconnect and resume it.",
        "remedy": "Trust is withdrawn per device: run the same `qsh trust remove` (or `qsh trust set-role`) on every other device that trusts the peer. To end the peer's sessions as well, close them with `qsh session close`."
      }
    ]
  }
}
```

`overall`은 `Host.connection_mode`와 같은 열린 문자열 규율(§10)로 `"ok"`/`"warn"`/`"error"`다 — `findings` 중 가장 심각한 `status`를 반영한다(`"error"` > `"warn"` > 그 외 `"ok"`). `"info"`만 있거나 `findings`가 비어 있으면 `"ok"`다. `overall`은 개별 finding에는 원칙적으로 나타나지 않는다 — 통과한 점검은 finding 자체를 만들지 않으므로("findings 모델": 재사용 상수 3종이 전부 실패-명명 문자열이라, 통과까지 담으려면 별도 subject-code 어휘가 이중으로 필요해진다), 통과 가시성은 `overall`과 human 렌더의 요약 줄로 얻는다.

`findings`의 각 원소(`DoctorFinding`)는 다음 field를 갖는다:

- `code`: 아래 표의 잠금 어휘(snake_case) 중 하나. shipped 후 **추가만** 가능하다 — 삭제·의미 변경은 `qsh.cli/v1` 위반이라 `/v2`가 필요하다(§10 additive-only 규율).
- `status`: `"warn"`/`"error"`/`"info"` 중 하나 — `"ok"`는 여기 나타나지 않는다.
- `detail`: 무엇이 관측됐는지에 대한 사람이 읽을 수 있는 설명(해석된 경로, 관측된 만료 시각 등). 시크릿·PTY/명령 payload는 절대 담지 않는다(`CLAUDE.md`의 보안 기본값).
- `remedy`: 실행 가능한 다음 행동 한 줄. 없으면 필드 자체가 생략된다(additive-optional, `CapabilitiesData.host`와 같은 규율).

**28종 진단 코드** (재사용 5종·신설 23종 — `EXPECTED_DOCTOR_CODES`(`crates/qsh-core/src/doctor.rs`)가 확정한 잠금 어휘, `config_unknown_key`는 `6d8de8c`가, M9의 8종은 `963809e`+`699af37`이 더했다 — 범위 (h)의 7종 + `host_pinned_without_address` — `acl_forward_socks_ineffective`는 ADR-0019 결과 절 R6의 후속이고 `service_restart_drops_sessions`는 M13 graceful re-exec H1이, `trust_pin_role_unset`은 ADR-0045 결정 12(M15)가, `acl_file_paths_missing`은 ADR-0029 결정 19(M15)가, `keystore_session_bound`는 ADR-0032 결정 15(M17)가, `logon_task_session_scoped`는 ADR-0035 결정 27(M19)이 더했다. 코드 집합은 세 OS에서 같고, Windows 빌드도 28종을 모두 안다. `keystore_session_bound`는 macOS와 Linux에서만 나오고(Windows의 `Password` 주체 작업은 Credential Manager를 읽는 것으로 실측돼 내지 않는다), `logon_task_session_scoped`는 Windows에서만 낸다. 이 장비의 상태를 읽는 진단(identity·trust·config·acl 계열)은 Windows client에서도 다른 OS와 같은 조건으로 나온다. 장비 환경을 읽는 세 코드만 환경에 따라 갈린다: `qsh_path_shadowed`는 Windows에서 `qsh.exe`를 `PATH`에서 찾고, `bindv6only_blocks_ipv4`는 `IPV6_V6ONLY`를 끄려는 시도 뒤에도 IPv6 소켓이 IPv6 전용으로 남는 OS에서 `[::]` bind에 대해서만 나오며(ADR-0046, Windows에서도 기본 상태에서는 나오지 않는다), `service_not_registered`는 Windows에서 작업 정의 파일(`<config_dir>\service\qsh-<mode>.task.xml`)이 없을 때 나오고, `logon_task_session_scoped`는 Windows에서만 나온다):

| `code` | `status` | 무엇을 점검하는가 |
|---|---|---|
| `controller_unreachable` | error | outbound controller(`[serve].to`, 없으면 구 `[reverse].controller`)가 설정돼 있으면 그 dial이 실패 — reverse는 relay·NAT traversal이 없다(M3 out-of-scope, §6.13). 문면은 `qsh_core::doctor::CONTROLLER_UNREACHABLE`을 그대로 재사용한다(§6.13과 동일 정본) |
| `udp_egress_blocked` | error | `host` 인자로 준 일반 대상으로 보낸 QUIC version-negotiation probe(미지원 버전의 long-header 패킷, 1200바이트 이상)가 응답 없이 침묵 타임아웃 — 방화벽이 UDP를 막고 있거나, 그 주소에 QUIC listener가 없을 수 있다(오래된 endpoint). QSH는 TCP fallback이 없다(ADR-0043). 상대가 `qsh serve`나 `qsh listen`을 처음 띄운 Windows 장비이고 방화벽에서 허용하지 않았다면 같은 침묵이 나오므로, `remedy`가 이 경우를 한 문장으로 안내한다(code 집합은 그대로, 위 방화벽 항목은 §6.13) |
| `no_route` | error | 일반 대상으로의 probe가 OS 레벨에서 즉시 거부됨(경로 자체가 없음) — 침묵 타임아웃(`udp_egress_blocked`)과 구분된다 |
| `peer_untrusted` | error | `hosts.toml`이 이름을 알지만 `trust.toml`에 그 이름의 pin이 없음 — 그 이름으로 연결하면 `TRUST_REQUIRED`로 실패할 운명이다(정적 교차대조, 위양성 없음) |
| `cert_expired` | error | device leaf(`identity/device.pem`) 또는 CA root(`ca/ca.pem`)의 `not_after`가 이미 지났음 — `detail`이 어느 쪽인지 밝힌다 |
| `cert_expiring_soon` | warn | 같은 인증서의 `not_after`가 30일 이내(만료 전)임 — `cert_expired`와 같은 인증서에 대해 상호배타 |
| `keystore_unavailable` | warn | 플랫폼 키스토어(macOS Keychain / Linux Secret Service / Windows Credential Manager)에 도달 불가 — 이미 file store(0600)로 정상 동작 중이므로 기능에는 지장 없음(read-only probe, 실제 키 저장소를 바꾸지 않는다) |
| `keystore_session_bound` | warn | `identity.key_store`가 `platform`이고 이 머신에서 추론한 run mode의 서비스가 로그인 세션 밖에서 도는 상시 기동 형태로 설치돼 있음. 상시 기동 형태는 macOS에서 같은 mode의 LaunchDaemon 파일(`/Library/LaunchDaemons/io.qsh.<mode>.plist`), Linux에서 linger 파일(`/var/lib/systemd/linger/$USER`)과 등록된 user unit의 조합이며 둘 다 파일 존재만 읽고 `launchctl`·`systemctl`을 부르지 않는다. Keychain과 Secret Service는 로그인 세션에 딸려 있어서 부팅 때 뜬 서비스가 개인키를 읽지 못할 수 있다. 세 mode(`serve`, `listen`, `reverse`)의 유닛 어느 것이어도 낸다. Windows에서는 내지 않는다. 같은 mode의 `\qsh\qsh-<mode>` 작업을 `Password` 주체로 등록해도 그 작업이 Credential Manager 항목을 읽는다는 것을 실측했다(대화형 세션 없이 기동한 `qsh serve`가 같은 fingerprint로 개인키를 읽었고 `qsh doctor`·`qsh identity export`도 같았다, ADR-0032 결정 15의 2026-10-25 개정, ADR-0035 결정 12). `remedy`는 `qsh identity move-key --to file`이고, device_id·인증서·fingerprint가 바뀌지 않아 상대 장비의 pin과 ACL 행이 그대로 유효하다고 알린다 |
| `clock_skew` | warn 또는 error | 로컬 시계가 device cert의 backdated `not_before`보다 과거 — `qsh init` 시 준 5분 backdate 여유(`CERT_BACKDATE_MINUTES`)를 넘으면 error, 그 안이면 warn |
| `audit_path_unwritable` | error | 설정된 `[audit].path`를 append로 열 수 없음 — fail-closed로 privileged operation(`session.open`/`exec.run`/`host.reverse`)이 전부 거부되는 상태. 문면은 `qsh_core::doctor::AUDIT_PATH_UNWRITABLE`을 재사용한다 |
| `acl_policy_missing` | error | `acl.toml`이 없고 요청을 인가할 다른 근거도 없음. `trust.toml`에 role이 `none`이 아닌 pin이 하나도 없고, 그런 role을 실은 살아 있는 초대(미상환이고 10분 안)도 없을 때만 낸다. `qsh serve`/`qsh listen`(§6.12·§6.13)의 시작 진단과 같은 검사·같은 code(`ACL_POLICY_MISSING_CODE`)를 쓰지만, 시작 진단은 이 상태를 한 줄로만 알리고 "모두 거부"를 알리는 일은 doctor가 맡는다. role pin이나 role 초대가 하나라도 있으면 침묵한다. `remedy`는 `qsh trust set-role <name> full`로 장비를 들이거나 `acl.toml`을 직접 쓰라고 안내한다(ADR-0045 결정 12). 등급은 모든 장비에서 `error`다. `qsh setup client`의 `complete` 판정만 이 code를 세지 않는다(§6.20, ADR-0038). |
| `acl_policy_invalid` | error | `acl.toml`이 있지만 파싱/검증에 실패함. 같은 시작 진단(`ACL_POLICY_INVALID_CODE`)을 재사용한다. 조건은 그대로이고 role과 무관하게 낸다. 파싱되지 않는 `acl.toml`은 role로 받은 권한도 거부하기 때문이다. `detail`이 시작 진단과 같은 banner(경로·오류 코드·오류 상세·예시)를 담고 그 뒤에 "role grants are refused too while acl.toml cannot be parsed"를 덧붙인다(ADR-0045 결정 12) |
| `qsh_path_shadowed` | warn | `$PATH`에서 지금 실행 중인 바이너리(`current_exe`)보다 앞서는 다른 `qsh` 실행파일이 있음 — 맨몸 `qsh`를 실행하면 그 다른 바이너리가 대신 뜬다 |
| `config_unknown_key` | warn | `config.toml`에 `Config`가 모르는 키 경로가 있어 조용히 무시되고 있음(§2.3의 "알 수 없는 키는 오류 없이 무시된다" 계약 그대로 — `deny_unknown_fields`는 쓰지 않는다). 상한 키 이름 오타면 그 상한은 기본값으로 남는다. `detail`이 문제의 키 경로를 밝힌다 |
| `trust_pin_role_unset` | info | `trust.toml`의 `[[peer]]` 중 `role` 키가 없는 것마다 finding 하나. ADR-0045 이전에 만든 pin이 모두 여기에 든다. 이 pin은 role `none`으로 판정되어 `acl.toml` 행으로만 인가된다. 동작을 바꾸지 않으므로 info다. `detail`은 pin 이름(`(peer: <name>)`)만 싣고 주소·fingerprint는 싣지 않는다. `remedy`는 `qsh trust set-role <name> <role>`로 role을 주거나 `none`으로 명시하라고 안내한다(ADR-0045 결정 12) |
| `trust_remove_scope` | info | `trust.toml`에 pin이 하나라도 있으면 상시 노출되는 고지. 신뢰를 좁히는 명령의 유효 범위(§6.11, ADR-0031 결정 9)를 세 문장으로 다시 알려준다: 새 연결에는 다음 handshake부터, 실행 중인 `qsh serve`·`qsh listen`·`qsh serve --to`가 연 연결에는 2초 안에 적용되고, 이 장비에서만 적용되며, 세션은 끝내지 않는다. remedy는 신뢰가 장비마다 따로 거두어진다는 것과 다른 장비에서도 같은 명령을 실행하라는 안내, 세션을 끝내려면 `qsh session close`를 쓰라는 안내다. code·status·노출 조건은 M7에서 고정된 그대로다 |
| `service_not_registered` | info | 이 머신에서 추론한 run mode(`listen`/`reverse`/`serve`, 우선순위 `[listen]` > `[serve].to` > 구 `[reverse].controller` > `serve`)에 대응하는 플랫폼 서비스 유닛이 등록돼 있지 않음 — macOS는 `~/Library/LaunchAgents/io.qsh.<mode>.plist`나 `/Library/LaunchDaemons/io.qsh.<mode>.plist` 중 하나가 있으면 등록된 것으로 보고(두 경로 모두 파일 존재만 읽고 `launchctl`을 부르지 않는다, ADR-0032 결정 14), Linux는 `~/.config/systemd/user/qsh-<mode>.service`를, Windows는 `<config_dir>\service\qsh-<mode>.task.xml`(작업 정의 파일)을 확인한다(그 밖의 플랫폼에서는 뜨지 않는다). `qsh service install --activate`(§6.18)로 유닛을 생성하고 등록하라고 안내한다(플래그 없는 `install`은 파일만 쓰므로 `docs/deploy/service.md`의 레시피로 직접 시작하는 길도 함께 안내한다) |
| `systemd_linger_disabled` | warn | Linux에서만, 그리고 해당 mode의 유닛이 이미 등록된 경우에만 도달한다 — `/var/lib/systemd/linger/$USER` 파일 존재 여부만 읽는다(subprocess 없음). 못 읽으면 "unknown"으로 취급해 finding을 내지 않는다 |
| `launchagent_session_scoped` | warn | macOS에서만, 해당 mode의 LaunchAgent가 등록돼 있고 같은 mode의 LaunchDaemon 파일이 없을 때 뜨는 구조적 고지 — 사용자 LaunchAgent는 로그인 세션 안에서만 돌고 로그아웃하면 멈춘다. `remedy`는 로그인 세션 밖에서 돌리려면 `docs/deploy/service.md`의 LaunchDaemon 레시피를 root로 한 번 실행하라고 안내한다(qsh는 그 파일을 쓰지 않는다). 같은 mode의 LaunchDaemon 파일이 있으면 침묵한다(ADR-0032 결정 14). code와 수준은 그대로다 |
| `logon_task_session_scoped` | warn | Windows에서만, 이 머신에서 추론한 run mode의 작업 `\qsh\qsh-<mode>`가 작업 스케줄러에 등록돼 있고 주체가 `InteractiveToken`일 때 뜨는 구조적 고지 — 그 작업은 사용자가 로그온해 있는 동안만 돌고 로그오프하면 멈춘다. 등록 여부와 주체는 작업 스케줄러 COM API(`ITaskService` → `IRegisteredTask`의 정의 주체)로 읽고 프로세스를 띄우지 않으며, 못 읽으면 아무것도 내지 않는다. 등록돼 있지 않거나 주체가 `Password`(상시 기동 변형)이면 침묵한다. 작업 정의 파일이 아니라 스케줄러가 답하므로 파일 유무와 무관하다. `remedy`는 `docs/deploy/service.md`의 상시 기동 변형을 안내한다(qsh는 그 작업을 등록하지 않는다, ADR-0032 결정 12) |
| `service_restart_drops_sessions` | info | 세션을 호스팅하는 mode(`serve`, `reverse`)에 대응하는 서비스 유닛이 이 머신에 등록돼 있으면 뜨는 구조적 고지다. `listen`은 세션을 갖지 않아 뜨지 않는다. 서비스 매니저의 재시작은 프로세스와 함께 detach된 세션을 전부 지운다(ADR-0003). 유닛 검출은 `service_not_registered`와 같은 경로(LaunchAgent, macOS에서 사람이 깐 LaunchDaemon 파일, systemd user unit, Windows의 작업 정의 파일)를 읽고, 유닛이 없으면 이 행이 아니라 `service_not_registered`만 나온다. remedy는 `qsh sessions`로 지워질 세션을 확인하라고 안내하고 `docs/deploy/service.md`의 Notes for both와 README Known limitations를 가리킨다 |
| `bindv6only_blocks_ipv4` | warn | 유효 bind 주소가 IPv6 wildcard이고, 새 IPv6 UDP 소켓에서 `IPV6_V6ONLY`를 끈 뒤 다시 읽은 값이 여전히 켜져 있거나 끄기 호출이 실패하는 경우(ADR-0046) — `Listener::bind`는 `dual_stack_v6=true`로 best-effort로 끄므로 OS 기본값과는 관계가 없고, 끌 수 없는 OS에서만 `[::]:4433` listener가 IPv4 peer를 조용히 거부한다 |
| `acl_principal_unmatched` | error | `trust.toml`이 pin한 peer 중 `auth_path = "pin"`인 `acl.toml` 행 어디에도 매칭되지 않는 것이 있음. `device:<name>`·`fp:sha256:<fingerprint>` 두 후보 다 확인한다. role이 `none`이 아닌 pin은 세지 않는다. 행이 없어도 role로 인가되기 때문이다. `acl.toml`이 없거나 파싱되지 않으면 이 검사는 돌지 않는다. `PEER_UNTRUSTED`와 같은 이유로 error다: 이름이 특정된 실제 peer가 모든 요청에서 확실히 거부될 상태이기 때문이다(`docs/adr/0017-acl-toml-not-written.md` 결정 2, ADR-0045 결정 12) |
| `acl_ca_auth_path_missing` | warn | `trust.toml`에 `[[ca]]`가 하나 이상 있는데 `acl.toml` 어디에도 `auth_path = "ca"` 행이 없음. `acl.toml`이 아예 없는 경우에도 낸다. CA 경로에는 role이 없어서(ADR-0045 결정 4), role pin이 `acl_policy_missing`을 침묵시켜도 CA 경로가 조용히 막힌 사실을 알릴 곳은 이 code뿐이다. peer 단위가 아니라 파일 전체 수준의 거친 검사다(CA 인증 principal은 `device:<id>` 모양이라 미리 열거할 수 없다). `acl_principal_unmatched`와 달리 warn이다: CA는 준비됐지만 아직 아무것도 그것에 의존한다고 증명되지 않은 잠재적 공백이기 때문이다(`docs/adr/0017-acl-toml-not-written.md` 결정 2) |
| `host_pinned_without_address` | warn | `host_list`가 아는 이름(trust pin 또는 `hosts.toml` 항목)에 두 출처 어디서도 주소가 없고 현재 유지 중인 reverse 등록(live·stale 불문)도 없음 — `--address` 없이 `--fingerprint`만으로 pin해 아직 phone-home하지 않은 순정 reverse 대상은 정상적인 일시 상태이므로 error가 아니라 warn이다. 그 이름의 reverse 등록이 하나라도 있으면(live든 stale이든) 뜨지 않는다 |
| `config_serve_to_conflict` | error | `[serve].to`와 구 `[reverse].controller`가 둘 다 설정돼 있고 값이 다름 — 그 상태에서 `qsh serve`/`qsh service install`은 `CONFIG_ERROR`로 fail closed한다(ADR-0012 결정 5). doctor는 exit `0`을 유지한 채 finding으로만 알린다. 두 값이 같으면 통과이므로 뜨지 않는다 |
| `acl_forward_socks_ineffective` | warn | `acl.toml` 행의 `allow`가 `forward.socks`를 exact로 적었는데 같은 principal 문자열과 같은 `auth_path`(생략이면 `pin`)를 가진 행 어디에도 `forward.local`(exact 또는 `forward.*`)이 없음 — `forward.socks`는 늘 거부되고 `-D`는 CONNECT마다 `forward.local`로 인가되므로(ADR-0019 결정 6·14) 그 행은 `-D`를 허락하지 못한다. 행의 다른 action은 여전히 동작하고 깨지는 것은 `-D` 의도 하나라 `acl_principal_unmatched`의 error보다 한 단계 낮은 warn이다. `detail`은 행의 배열 index와 `auth_path`만 싣고 principal 문자열은 싣지 않는다. 판정 단위가 principal 문자열 일치라서 같은 peer를 `device:<name>` 행과 `fp:sha256:<fingerprint>` 행으로 나눠 적은 정책은 다른 행이 `forward.local`을 줘도 짚힌다(한계이며 `message`에도 적힌다). 정책이 없거나 파싱에 실패하면 침묵한다(그 상태는 `acl_policy_missing`·`acl_policy_invalid`가 알린다) |
| `acl_file_paths_missing` | warn | `acl.toml` 행의 `allow`가 `file.read`·`file.write`·`file.*` 중 하나를 적었는데 그 행에 `paths`가 없음 — 행은 `paths` 안에서만 파일 접근을 주므로(ADR-0029 결정 4) 파일 접근을 하나도 주지 못한다. 행의 다른 action은 그대로 동작하므로 error가 아니라 warn이다. `detail`은 행의 배열 index와 `auth_path`만 싣고 principal 문자열은 싣지 않는다. `device:<name>`을 적은 `pin` 경로 행은 같은 이름의 pin이 role `full`이면 침묵한다(role이 파일을 열어 주므로 어긋나는 의도가 없다). 정책이 없거나 파싱에 실패하면 침묵한다(그 상태는 `acl_policy_missing`·`acl_policy_invalid`가 알린다). `remedy`는 `paths`를 더하거나 `qsh trust set-role <name> full`로 role을 주라고 안내하고 재시작 고지로 끝난다 |

**role 관련 문안.** 위 표의 role 문구는 `crates/qsh-core/src/doctor.rs`의 상수가 정본이고, 아래가 그 문면이다.

  > `trust_pin_role_unset`의 `message`: This trust.toml pin has no role key, so it counts as role none and is authorized only by acl.toml rows.
  >
  > `trust_pin_role_unset`의 `remedy`: Give it a role with `qsh trust set-role {name} <role>`, or record that it stays row-only with `qsh trust set-role {name} none`.
  >
  > `acl_policy_missing`의 `remedy` 머리: admit a device by role with `qsh trust set-role <name> full`, or write acl.toml
  >
  > `acl_policy_invalid`의 `detail` 꼬리: role grants are refused too while acl.toml cannot be parsed

**상시 기동 관련 문안.** `keystore_session_bound`, `launchagent_session_scoped`, `logon_task_session_scoped`의 문면은 `crates/qsh-core/src/doctor.rs`의 상수가 정본이고, 아래가 그 문면이다(ADR-0032 결정 14·15, ADR-0035 결정 27).

  > `keystore_session_bound`의 `message`: This device's private key lives in the OS credential store, which belongs to a login session, while the service is installed to run without one. After a reboot the service may be unable to read its key until someone logs in.
  >
  > `keystore_session_bound`의 `remedy`: Run `qsh identity move-key --to file` to keep the key in the 0600 key file. The device id, certificate and fingerprint do not change, so peers' pins and ACL rows stay valid.
  >
  > `launchagent_session_scoped`의 `message`: qsh's service is registered as a user LaunchAgent, which only runs inside an active login session and stops at logout. No LaunchDaemon for this mode is installed on this machine.
  >
  > `launchagent_session_scoped`의 `remedy`: To keep it running with nobody logged in, run the LaunchDaemon recipe in docs/deploy/service.md once, as root. Otherwise keep a session logged in.
  >
  > `logon_task_session_scoped`의 `message`: The scheduled task for this machine's run mode runs as an interactive-token task, which exists only while you are logged on. It starts at logon and stops when your session ends.
  >
  > `logon_task_session_scoped`의 `remedy`: To keep it running with nobody logged on, register the always-on variant described in docs/deploy/service.md (a BootTrigger and a stored-password principal, registered from an elevated prompt).

`trust.toml`이 읽히지 않거나 파싱되지 않으면 doctor는 finding 없이 `CONFIG_ERROR`로 끝나고(위 `Err` 경우), 그 `message` 끝에 다음 문구가 붙는다. 같은 실패가 실행 중인 `qsh serve`/`qsh listen`에서는 role 판정을 멈추게 하기 때문이다(ADR-0045 결정 4·12). 이 때문에 새 code는 없다.

  > a running qsh serve/listen refuses role grants until this file parses again (pin authentication keeps using the last good snapshot)

**`acl_ca_auth_path_missing` 문안.** 이 진단의 정본 문안은 `qsh_core::doctor::ACL_CA_AUTH_PATH_MISSING`(`crates/qsh-core/src/doctor.rs`, ADR-0017 결정 2)이고, 그 `message`/`remedy` 두 필드는 각각 다음과 같다. 실제 렌더되는 `detail`은 이 `message` 뒤에 `minimal example:` 블록을 덧붙인 값이다(`crates/qsh-core/src/ops/doctor.rs`의 `doctor_acl_findings`):

  > trust.toml has a CA root, but no acl.toml row sets auth_path = "ca". Any peer authenticating via that CA is denied (default-deny) until one does.
  >
  > Add an [[acl]] row with auth_path = "ca" (ADR-0017), then restart serve/listen — acl.toml is only read once at process start.

**`acl_file_paths_missing` 문안.** 정본은 `qsh_core::doctor::ACL_FILE_PATHS_MISSING`(`crates/qsh-core/src/doctor.rs`, ADR-0029 결정 19)이고 `message`/`remedy`는 각각 다음과 같다. 실제 `detail`은 이 `message` 뒤에 ` (row: <index>, auth_path: <pin|ca>)`를 붙인 값이다:

  > This row's allow names a file action (file.read, file.write or file.*), but the row has no paths. A row grants file access only inside its paths (ADR-0029), so it grants none; its other actions are unaffected.
  >
  > Add paths = ["/absolute/dir"] to that row, or give the device a role that opens files with `qsh trust set-role <name> full`, then restart serve/listen — acl.toml is only read once at process start.

**연결성 진단의 우선순위 규칙.** 한 probe 실패는 항상 code 하나만 낸다: probe 대상이 outbound controller(`[serve].to`, 없으면 구 `[reverse].controller`)면 결과와 무관하게 `controller_unreachable`이고, `host` 인자로 준 일반 대상이면 침묵 타임아웃은 `udp_egress_blocked`, OS의 즉시 거부(경로 없음)는 `no_route`다 — 세 code가 한 실패에 동시에 나오는 일은 없다.

**`--fail-on <warn|error>` (ADR-0027).** CI 게이트용 옵션이다. 주지 않으면 exit code와 stdout이 이 옵션이 생기기 전과 바이트 단위로 같다. 주면 조회가 성공한 뒤 `findings`에 임계 이상 `status`가 하나라도 있을 때만 exit `1`로 끝난다. `warn`은 `status`가 `"warn"`이나 `"error"`인 finding이 있을 때, `error`는 `"error"`인 finding이 있을 때 걸린다(순서는 `data.overall`과 같다). `"info"` finding은 `trust_remove_scope`처럼 상시 뜨는 고지라서 임계로 받지 않으며, `info`나 그 밖의 값은 clap이 exit `2`로 거절한다. envelope은 임계에 걸려도 그대로다: `ok: true`이고 `data.overall`과 `data.findings`를 모두 싣는다. 그래서 `ok: true`와 exit `1`의 조합은 정상이며, `ok: false`는 여전히 exit `255`와만 짝을 이룬다. doctor가 조회를 시작하지 못하는 경우(위 `Err`)는 `--fail-on`과 무관하게 exit `255`다. 따라서 `255`는 "판정할 수 없었다", `1`은 "판정했고 걸렸다"로 읽는다. human과 `--json`에서 같은 finding 집합이 같은 exit를 낸다(§4). JSON 모양은 바뀌지 않는다.

### 6.18 `qsh service` — 플랫폼 서비스 유닛 관리 (ROADMAP M9 (g))

```bash
qsh service install [--activate] [--json]
qsh service uninstall [--deactivate] [--json]
qsh service status [--live] [--json]
```

세 subcommand 모두 위치 인자를 받지 않고, 플래그는 각자 하나뿐이다(ADR-0032 결정 1).
`--activate`는 `install`만, `--deactivate`는 `uninstall`만, `--live`는 `status`만
받으며 다른 subcommand에 붙이면 clap이 exit 2로 거절한다. dotted 이름은 `service.install`·
`service.uninstall`·`service.status`이며(§2.4), 셋 다 §2.5의 "인가 불요" 행이
명시하듯 local operation이라 원격 peer가 요청할 수 없다 — `service.install`은
그럼에도 이 머신 상태를 바꾸므로 §2.5 post-table 문단이 `trust.rename`과 나란히
드는 두 번째 예시다.

**대상 run mode.** 세 op 모두 관리하는 대상은 이 머신에서 추론한 run mode 하나뿐이다
— `doctor.run`의 `service_not_registered`(§6.17)와 같은 추론 규칙, 같은
우선순위(`[listen]` 존재 > `[serve].to` 설정 > 구 `[reverse].controller` 설정 >
어느 쪽도 없으면 `serve`)를 그대로 재사용한다. `[serve].to`와 구
`[reverse].controller`가 둘 다 설정돼 있고 값이 다르면 §6.17의
`config_serve_to_conflict`와 동일하게 `CONFIG_ERROR`로 fail closed하고 아무것도
쓰지 않는다(ADR-0012 결정 5) — 두 값이 같으면 정상 진행한다. 이 순서는 세 op
모두에 똑같이 적용되므로, 읽기만 하는 `status`도 예외가 아니다: 같은 충돌
상태에서는 `install`/`uninstall`과 똑같이 `CONFIG_ERROR`를 반환한다.

**유닛 경로와 `<mode>` 토큰.** macOS는
`~/Library/LaunchAgents/io.qsh.<mode>.plist`, Linux(systemd user unit)는
`~/.config/systemd/user/qsh-<mode>.service`, Windows(작업 스케줄러 작업 정의
파일)는 `<config_dir>\service\qsh-<mode>.task.xml`(기본 `%USERPROFILE%\.config\qsh\service\`)다. `<mode>`는 추론한 `serve`/
`listen`/`reverse` 그대로다. `reverse` 유닛은 파일 이름과 label만 `reverse`를
쓰고, 실제로 실행하는 인자는 숨김 alias `qsh reverse`가 아니라 `qsh serve --to
<controller>`다(§6.13) — 유닛 자신의 argv는 항상 고정이며 `--bind`·`--name`·
config·verbosity 플래그가 끼어들 여지가 없고, qsh는 이 경로에서도 자기 자신을
데몬화하지 않는다(§6.12의 "Foreground 전용" 원칙 그대로 — 서비스 매니저가
프로세스를 띄우고 재시작을 맡는다).

**플래그가 없으면 `status`는 존재 여부만 보고 `install`·`uninstall`은 유닛 파일만
쓴다.** 플래그 없이 부르면 서비스 매니저(`launchctl`·`systemctl`·`schtasks`)를 한 번도
부르지 않는다. `status`는 유닛 파일이 그 경로에 있는지만 확인하고, `install`은 파일만
쓰고 `uninstall`은 파일만 지운다. 이 동작은 플래그를 도입하기 전과 같고
`config.toml`이나 환경 변수로 플래그의 기본값을 줄 수 없다(ADR-0032 결정 1). 매니저를
부르는 길은 세 플래그뿐이며 각각 `docs/deploy/service.md`의 레시피와 같은 argv를
실행한다(문서와 코드는 테스트로 대조한다, 결정 11). `status`와 `uninstall`도
`install`과 똑같이 "오늘" 추론한 run mode만 본다 — mode가 바뀌면(예: `config.toml`을
고쳐 `[listen]`을 추가) 세 op 모두 새 mode의 경로로 옮겨간다.

**`install --activate`.** 감사 기록을 남기고 유닛 파일을 쓴 뒤에만 마지막 단계로
매니저를 부른다. 감사 기록이나 유닛 파일 쓰기가 실패하면 매니저는 부르지 않는다.
launchd는 `launchctl print gui/<uid>/io.qsh.<mode>`로 등록 여부를 묻고(종료 코드
0이면 이미 올라가 있음), 없을 때만 `launchctl bootstrap gui/<uid> <유닛 경로>`를
실행한다. systemd는 `systemctl --user is-active qsh-<mode>.service`로 먼저 묻고
`daemon-reload`와 `enable --now`를 차례로 실행한다. 이미 떠 있는 유닛은 어느
매니저에서도 재시작하지 않으며(결정 4) 바뀐 바이너리 경로는 다음 재시작 때
적용된다. 활성화가 실패해도 쓴 유닛 파일은 남고 오류 메시지가 그 사실과 다시 실행할
명령을 알린다. 작업 스케줄러는 먼저 COM으로 같은 이름의 작업이 `Password` 주체로
등록돼 있는지 읽고(아래 상시 기동 형태), 아니면 `schtasks /Create /F /TN
\qsh\qsh-<mode> /XML <작업 정의 파일>`을 실행한 뒤 작업이 실행 중이 아닐 때만
`schtasks /Run /TN \qsh\qsh-<mode>`를 이어서 실행한다. 작업 정의는 스케줄러 안에
저장되므로 바뀐 바이너리 경로가 반영되려면 실행 중이어도 `/Create /F`가 돌아야
하고, 실측에서 `/Create /F`는 실행 중인 인스턴스를 멈추지 않았다(같은 프로세스가
계속 돌았다). 그래서 실행 중일 때는 `/Create`만 부르고 `activation`은
`already_active`이며 새 경로는 다음 시작에 적용된다.

**`uninstall --deactivate`.** 유닛 파일을 지우기 전에 매니저에서 내린다(결정 5).
launchd는 `launchctl print`로 등록 여부를 묻고 등록돼 있을 때만 `launchctl bootout
gui/<uid>/io.qsh.<mode>`를 실행한다. systemd는 유닛 파일이 있으면
`systemctl --user disable --now qsh-<mode>.service`를 실행한다. 판정은 실행 여부가
아니라 등록 여부다. 내리기가 실패하면 유닛 파일을 지우지 않고 남겨서 같은 명령을
다시 실행할 수 있게 한다. 작업 스케줄러는 `schtasks /Query /TN \qsh\qsh-<mode>`의
종료 코드 0을 등록으로 보고, 등록돼 있으면 COM으로 읽은 상태가 실행 중일 때만
`schtasks /End /TN \qsh\qsh-<mode>`를 실행한 뒤 `schtasks /Delete /F /TN
\qsh\qsh-<mode>`를 실행한다. 등록돼 있지 않으면 부르는 것이 `/Query` 하나뿐이고
`deactivation`은 `not_active`다. **`--deactivate` 없는 `uninstall`은 실행 중인 유닛을
그대로 두고 파일만 지운다.**

**`status --live`.** 유닛 파일이 있을 때 종료 코드 하나(launchd `launchctl print`,
systemd `systemctl --user is-active`)만 읽고 stdout은 읽지 않는다(결정 6). 유닛
파일이 없으면 매니저를 부르지 않고 `active: false`다. 작업 스케줄러는 `schtasks`가
아니라 작업 스케줄러 COM의 상태값 하나(`TASK_STATE_RUNNING`인지)만 읽는다.
`schtasks /Query`의 종료 코드는 등록 여부만 알려 주고 실행 상태는 지역화된 본문에만
있어서, 출력을 파싱하지 않는다는 규칙을 지키는 길이 이것뿐이다.

**매니저 호출의 공통 규칙.** 호출 하나의 기한은 30초이고(결정 8) 인자 배열로 직접
실행하며 shell을 거치지 않는다. 사용자가 입력한 문자열은 argv에 들어가지 않는다 —
`<mode>`는 닫힌 집합(`serve`/`listen`/`reverse`), uid와 유닛 경로는 qsh가 만든
값이다(결정 3). 실패는 기존 코드만 쓴다: 매니저 실행 파일(Windows는 `schtasks.exe`)을 찾지 못하면
`UNSUPPORTED`, 기한을 넘기면 `TIMEOUT`, 그 밖의 비정상 종료와 실행 실패는
`INTERNAL`이고 `error.details.step`(`activate`·`deactivate`·`live`)과, 종료했다면
`exit_code`가 따라온다. 메시지에는 stderr의 첫 줄만 512바이트까지 실린다. 감사 기록은
op당 한 건이며 매니저 호출마다 남기지 않는다(결정 7). 작업 스케줄러 COM 읽기가
실패해도 같은 `INTERNAL`(해당 `step`)이고, 읽지 못한 채로는 `/Create`·`/End`·
`/Delete`를 부르지 않는다. `InteractiveToken` 작업은 로그온한 대화형 세션이 있어야
시작되므로 ssh로만 들어간 Windows에서는 `schtasks /Run`이 0이 아닌 종료로 끝나 같은
`INTERNAL`이 된다. qsh는 다른 주체나 로그온 유형으로 등록해 우회하지 않는다.

**사람이 깐 macOS LaunchDaemon 상시 형태(결정 18).** `/Library/LaunchDaemons/io.qsh.<mode>.plist`가
있으면 `install --activate`는 유닛 파일만 쓰고 매니저를 부르지 않으며
`activation`은 `always_on_present`다. `uninstall --deactivate`는 per-user 형태만
내리고 상시 형태는 그 형태의 해제 레시피(`docs/deploy/service.md`)에 맡기며
`deactivation`은 `always_on_present`다. `status --live`는 상시 형태의
`launchctl print system/io.qsh.<mode>` 종료 코드 하나를 root 없이 읽는다(macOS 27.0.1에서
확인). 0이면 적재된 서비스라 `active: true`, 113이면 적재되지 않은 label이라 `active: false`다.
그 밖의 종료 코드는 모호한 답이므로 "실행 중 아님"으로 읽지 않고
`INTERNAL`(`details.step: "live"`, `details.exit_code`)로 끝나며 메시지가 `sudo launchctl print system/io.qsh.<mode>`를
안내한다.
`status`의 `exists`는 이 파일을 보지 않고 LaunchAgent 경로만 본다. LaunchDaemon은 사람이 설치한
파일이고 `service.*` op이 관리하는 대상이 아니다. `qsh doctor`는 이 파일을 등록된 유닛으로 읽되
파일 존재만 보고 `launchctl`을 부르지 않는다(§6.17, 결정 14).

**Windows 작업 스케줄러 (ADR-0035 결정 27).** Windows의 "유닛"은 작업 정의 XML 파일
하나다. `install`은 이 파일을 소유자 전용 DACL로 쓴다. 내용은 고정이다. 현재
사용자의 로그온에 걸린 `LogonTrigger`(1분 간격 무기한 `Repetition`), 그 사용자의
`InteractiveToken`·`LeastPrivilege` 주체(암호를 저장하지 않고 관리자 권한도 묻지
않는다), `MultipleInstancesPolicy=IgnoreNew`, `ExecutionTimeLimit=PT0S`, 배터리
조건 없음, `RestartOnFailure`(1분), 그리고 `current_exe()` 절대 경로로
`service run <mode>`를 실행하는 동작 하나다(`reverse`는 뒤에 controller 리터럴이
붙는다). 사용자는 SID로 적으므로 계정 이름의 표기나 지역화에 기대지 않는다. 파일은
UTF-16 little-endian에 BOM이다(`schtasks /Create /XML`이 받는 인코딩을 실측해 정했다,
`docs/deploy/service.md`). 작업 이름은 `\qsh\qsh-<mode>`다. `status`는 파일
존재만 보고 `uninstall`은 파일만 지우며, 둘 다 `schtasks`나 스케줄러를 부르지
않는다. `install`은 감사 기록 한 건을 남긴 뒤에 파일을 쓴다. 플래그가 없으면 qsh는
작업을 등록하지 않는다 — `--activate`를 주거나, `docs/deploy/service.md`의
`schtasks /Create /F /TN \qsh\qsh-<mode> /XML <file>` 레시피를 사람이 실행한다.
`--activate`·`--deactivate`·`--live`의 호출은 위 문단과 같고 `manager`는
`"task_scheduler"`다. 상시 기동(`BootTrigger`·`LogonType=Password`) 변형은 관리자
프롬프트에서 사람이 등록하며 qsh는 그 작업을 쓰거나 등록하지 않는다(ADR-0032
결정 12).

**사람이 깐 Windows 상시 기동 형태(결정 18).** 같은 이름 `\qsh\qsh-<mode>` 작업이
`Password` 주체로 등록돼 있으면 `install --activate`는 파일만 쓰고 `schtasks`를 부르지
않으며 `activation`은 `always_on_present`다. `/Create /F`가 그 정의를 기본(로그온 범위)
정의로 덮어쓰기 때문이다. `uninstall --deactivate`도 `/End`·`/Delete`를 부르지 않고
파일만 지우며 `deactivation`은 `always_on_present`다. `status --live`의 `active`는 그
작업의 실행 여부다. 주체는 작업이 qsh가 쓴 파일에서 등록됐는지와 무관하게 COM으로
읽는다. 상시 기동 형태의 해제는 `docs/deploy/service.md`의 해제 명령을 사람이 친다.

작업이 실행하는 숨김 `qsh service run <mode> [controller]`(`serve`·`listen`·`reverse`,
clap `hide = true`라 `--help`와 `docs/man/`에 나오지 않고 `reverse`만 controller를
받는다)는 콘솔에서 떨어지고(`FreeConsole`) stdout·stderr를
`<state_dir>\log\<mode>.out.log`·`<mode>.err.log`로 덧붙이도록 돌린 뒤(소유자 전용
DACL, unix에서는 0600) `qsh serve`·`qsh listen`·`qsh serve --to`와 같은 진입 함수를
부른다. 모든 플랫폼에서 파싱하고 같은 리디렉션을 하지만 launchd·systemd 유닛은
부르지 않는다. 장기 실행 모드이므로 stdout에는 아무것도 쓰지 않고, 로그를 열지
못하면 리디렉션 전의 stderr에 오류를 내고 exit `255`다.

**`UNSUPPORTED` — macOS/Linux/Windows 외 모든 대상.** 다른 어떤 것도 읽거나 쓰기 전에
가장 먼저 판정되며, 문면은 다음을 그대로 쓴다:

> `qsh service` manages user service units for launchd (macOS), systemd (Linux) and the Task Scheduler (Windows) only; unit installation on this platform is P1 and not implemented. Nothing was written. `docs/deploy/service.md` has a hand-written unit for each supported manager.

**`acl.toml`을 쓰지 않는다.** `service install`은 유닛 파일만 쓰고 인가 정책에는
관여하지 않는다(ADR-0017 결정 1, `docs/adr/0017-acl-toml-not-written.md`) —
새로 등록한 유닛이 실제로 뜬 뒤 원격 peer를 받으려면 `acl.toml`은 여전히 따로
손으로 갖춰야 한다.

**바이너리 경로를 다시 잡는다.** 재실행할 때마다 `install`은 그 시점의
`current_exe()`를 다시 읽어 유닛에 고정한다 — 바이너리를 옮긴(`brew upgrade`로
Cellar 경로가 바뀌는 등) 뒤 `qsh service install`을 다시 실행하면 유닛의 경로가
새 위치로 갱신된다. 절대 경로는 그대로 쓰고(symlink를 `canonicalize`하지 않는다),
상대 경로일 때만 절대 경로로 정규화한다. 이 "symlink 보존" 성질은 macOS의
`current_exe()` 구현에 한정된다 — Linux는 `readlink("/proc/self/exe")`로 커널이
이미 완전히 풀어준 경로를 돌려주므로, 심볼릭 링크로 설치된 Linux 바이너리는
애초에 그 대상 경로가 유닛에 고정된다. 두 플랫폼 모두 바이너리를 옮기거나
가리키는 대상을 바꾼 뒤 `qsh service install`을 다시 실행하는 것이 갱신 경로다.

**단위 디렉터리 권한.** `install`은 유닛 파일의 부모 디렉터리(macOS
`~/Library/LaunchAgents`, Linux `~/.config/systemd/user`, Windows
`<config_dir>\service`)와, macOS에서는 `~/Library/Logs/qsh`도 없을 때만 만든다 —
이미 있는 디렉터리의 모드는 절대 건드리지 않는다(`~/Library/LaunchAgents`는 다른
애플리케이션의 LaunchAgent도 함께 담는, qsh가 소유하지 않는 디렉터리이기
때문이다. Windows의 `<config_dir>\service`는 qsh 소유이므로 소유자 전용으로
만든다). 유닛 파일 자체는 항상 0600(Windows는 소유자 전용 DACL)으로 쓴다.

세 op의 `data`는 각각 `ServiceInstallData`/`ServiceUninstallData`/
`ServiceStatusData`(`crates/qsh-proto/src/types/service.rs`)다:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "service.install",
  "ok": true,
  "data": {
    "manager": "launchd",
    "mode": "serve",
    "path": "/Users/YOU/Library/LaunchAgents/io.qsh.serve.plist",
    "created": true
  }
}
```

`manager`는 `"launchd"`/`"systemd"`/`"task_scheduler"`(cfg만으로 결정, 프로브 없음). `mode`는 위에서
추론한 `<mode>` 토큰. `path`는 그 유닛의 절대 경로. `created`(install)는 이번
호출 **전에** 그 경로가 없었는지만 보고하며, `install`은 매번 다시 렌더링해
덮어쓴다 — 이미 있어도 `created: false`로 성공하는 것은 손으로 고친 유닛을
복구하는 경로다. `removed`(uninstall)는 `trust.remove`와 같은 관례로, 유닛이
이미 없으면 오류가 아니라 `removed: false`로 성공한다. `installed`(status)는
`path.exists()` 그대로다.

플래그가 더하는 필드는 모두 선택이고 플래그를 주지 않으면 키 자체가 없다
(additive-only, 결정 7):

| 필드 | op | 값 |
|---|---|---|
| `activation` | `install --activate` | `"started"`(매니저에 등록하고 시작함), `"already_active"`(이미 떠 있어 재시작하지 않음), `"always_on_present"`(상시 형태가 있어 매니저를 부르지 않음) |
| `deactivation` | `uninstall --deactivate` | `"stopped"`(등록돼 있어 내림), `"not_active"`(등록돼 있지 않아 내리기 호출 없음), `"always_on_present"`(상시 형태가 있어 per-user 형태만 내림) |
| `active` | `status --live` | `true`/`false`(종료 코드 0 여부) |

§6.12의 "Foreground 전용" 원칙과 이 절의 관계: `qsh service install`이 만드는
것은 그 foreground 프로세스를 대신 실행해 주는 서비스 유닛이지, qsh 자신의
데몬화가 아니다 — qsh 바이너리 자체는 이 경로에서도 재실행·백그라운드 전환을
전혀 하지 않는다.

### 6.19 `qsh acl show`

```bash
qsh acl show --principal <principal> [--auth-path pin|ca] --json
```

한 principal에 대해 이 머신의 `acl.toml`이 무엇을 허용하는지 한 번에 요약한다([ADR-0025](adr/0025-acl-show-read-only.md)). `acl check`가 (principal, action, resource) 삼중 하나에 답한다면 `acl show`는 "이 principal이 지금 무엇을 할 수 있는가"에 답한다. `--resource`와 `--owner` 축은 없다. 그 질문은 `acl check`(§6.15)가 이미 답한다.

- `--principal <principal>` (필수): `device:<name>` | `user:<name>` | `fp:sha256:<base64>`. 이 어휘 밖의 모양은 `INVALID_ARGUMENT`다.
- `--auth-path <pin|ca>` (선택): principal이 인증했다고 가정할 auth path. 생략하면 `"pin"`으로 평가하고 `auth_path_defaulted`가 `true`다. `pin`·`ca` 밖의 값은 `INVALID_ARGUMENT`다.

`acl.show`는 §2.4·§2.5가 명시하듯 **로컬 operation**이다. 원격 peer가 요청할 수 없고 wire 메시지도 만들지 않는다. 원격에서 남의 정책을 열람할 수 있으면 그것이 곧 capability 열거 oracle이 되고, 집합을 통째로 돌려주는 `acl show`는 `acl check`보다 oracle로서 효율이 높기 때문이다(ADR-0025 결정 4). 읽기 전용이며 `acl.toml`을 쓰지 않고 자동 생성하지도 않는다(ADR-0017 결정 1). 호출마다 파일을 다시 읽는다.

`data`는 `AclShowData`(`crates/qsh-proto/src/types/acl.rs`)다:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "acl.show",
  "ok": true,
  "data": {
    "principal": "device:laptop",
    "auth_path": "pin",
    "auth_path_defaulted": true,
    "policy": {
      "path": "/Users/dave/.config/qsh/acl.toml",
      "rules": 2,
      "loaded": true,
      "state": "loaded"
    },
    "matching_rules": [
      { "index": 0, "allow": ["forward.*", "session.open"], "auth_path": "pin", "scope": "owned" },
      { "index": 1, "allow": ["exec.run"], "auth_path": "pin", "scope": "any" }
    ],
    "effective_actions": ["exec.run", "session.open", "forward.local", "forward.remote"]
  }
}
```

- `matching_rules`는 principal 정확 일치와 `auth_path` 일치(평가 순서 ②)를 통과하고 action 패턴이 어휘의 어떤 action이든 덮는(③) 행을 파일 순서로 담는다. 행마다 `index`(`acl.toml`의 배열 index, `acl check`의 `rule`과 같은 값), `allow`(패턴을 적힌 그대로. `exec.run` 같은 exact와 `forward.*` 같은 family 둘 다), `auth_path`(적지 않은 행은 `"pin"`), `scope`(`"owned"` | `"any"`, 열린 문자열)를 낸다. 매칭 판정은 `decide`와 같은 helper를 쓰고 두 번째 구현이 없다. 행이 `paths`를 적었으면 `paths`(optional)가 항목을 적힌 그대로 담는다(ADR-0029 결정 19). 키가 없는 행은 필드 자체가 나타나지 않는다. 파일 action을 적고 `paths`가 없는 행은 파일 접근을 주지 않으므로 호스트가 그 행에 `file_paths_missing: true`(optional, additive, false면 필드 자체가 나타나지 않음)를 싣고, human 출력은 이 필드를 보고 그 행 밑에 `grants no file access: the row has no paths` 줄을 낸다. 렌더러는 ACL 문법을 판정하지 않는다. `paths`가 있는 행은 `paths:` 줄에 항목을 나열한다.
- `role`(optional)과 `role_actions`(optional)는 principal의 pin role과 그 role이 주는 action이다(ADR-0045 결정 11). 해석은 `acl check`(§6.15)와 같다. principal이 `device:<name>`이고 경로가 `pin`이면 이 머신의 `trust.toml`에서 그 이름의 pin을 찾고, `role` 키가 없는 pin은 `"none"`으로 나온다. 그 이름의 pin이 없거나 경로가 `ca`이거나 `trust.toml`을 파싱할 수 없으면 두 필드가 모두 생략된다. `role_actions`는 §6.11 role 표의 그 role 행을 표 순서 그대로 담는다. `role`이 `none`이면 `role_actions`는 빈 배열이다.
- `effective_actions`는 `Action::ALL` 11종마다 enforcement가 쓰는 평가기(`Policy::decide`)를 role을 입력으로 줘서 소유자 없는 리소스로 불러 allow가 난 action만 어휘 순서로 모은 것이다. 그래서 role이 주는 action과 매칭 행이 주는 action의 합집합이고, `acl check`가 같은 정책 아래 action마다 내는 판정과 어긋나지 않는다. 합집합은 이 필드의 원래 뜻("이 principal이 지금 할 수 있는 것")을 따른 것이다. `matching_rules`는 행만 담는다. 파일 action(`file.read`·`file.write`)은 경로 없이는 판정할 수 없으므로 이 집합에서는 경로와 무관한 근거로 센다. role이 그 action을 주거나 주체를 고르는 행이 `paths`와 함께 그 action을 주면 포함하고, 어느 경로가 열리는지는 `matching_rules`의 `paths`와 `acl check --path`(§6.15)가 답한다.
- 항상-deny action(`forward.socks`)은 어떤 행이 적어도(`forward.*` 같은 family 패턴 포함) 이 집합에 나오지 않는다. 평가기가 규칙보다 먼저 막기 때문이다. 그런 행은 `matching_rules`에는 나타난다. `file.read`·`file.write`를 적은 행이 `paths`를 가지면 이 집합에 들고, `paths`가 없으면 들지 않는다(그 행은 `matching_rules`에 `file_paths_missing`으로 나온다).
- 소유자 없는 리소스를 가정한 집합이므로, `scope = "owned"` 행은 소유된 리소스(열린 세션 등)에서 이 집합의 부분집합만 허용한다. 소유된 리소스에 대해 이 집합은 **상한**이다. 이 사실은 산문이라 JSON에 싣지 않고 human 출력과 이 문장이 맡는다.
- `auth_path`를 적지 않은 `[[acl]]` 행은 `"pin"`을 받아 CA로 인증한 peer에게 매칭되지 않는다. `--auth-path`를 생략하면 `"pin"`으로 평가한다는 사실과 함께 human 출력이 고지하고, JSON에서는 `auth_path_defaulted: true`가 같은 사실을 구조로 싣는다(ADR-0025 결정 5).
- role과 행은 반영 시점이 다르다. role은 판정마다 `trust.toml`에서 읽으므로 `qsh trust set-role`과 `qsh trust remove`는 돌고 있는 `qsh serve`/`qsh listen`에 다음 요청부터 반영되고(재시작 불필요), role을 낮추거나 pin을 지우면 그 peer의 이미 확립된 연결도 2초 안에 닫힌다(§6.11). 행은 아래 문단대로 재시작이 필요하다. human 출력은 role 줄을 principal 줄 바로 다음에 내고, 이 비대칭을 두 줄로 나눠 적는다(role 쪽은 "a role change takes effect on the next request, without a restart.", 행 쪽은 아래 `ACL_RESTART_NOTICE`).
- `acl.toml`은 프로세스 시작 시 한 번만 읽힌다. 이 명령은 호출마다 파일을 읽으므로 방금 고친 행도 보이지만 돌고 있는 `qsh serve`/`qsh listen`은 아직 모른다. human 출력은 이 사실을 `ACL_RESTART_NOTICE` 상수(`restart serve/listen — acl.toml is only read once at process start.`)를 바이트 그대로 한 줄로 찍어 알린다. 같은 상수를 doctor의 `acl_principal_unmatched`·`acl_ca_auth_path_missing` remedy가 꼬리로 쓴다(ADR-0025 결정 6). 이 문장은 산문이라 JSON에 싣지 않는다. 싣으면 append-only fixture가 문면을 `qsh.cli/v1`로 얼린다.

`policy.state`(열린 문자열)는 `acl.toml`의 상태를 셋으로 가른다. 뜻은 `acl check`(§6.15)의 표와 같다.

- `loaded`: 행과 role의 합집합.
- `missing`(`loaded: false`): 파일이 없다. 행 없는 정책으로 치므로 `matching_rules`는 빈 배열이고 `effective_actions`는 role이 주는 action이다.
- `invalid`(`loaded: false`): 파싱에 실패했거나 권한 때문에 읽지 못했다. `matching_rules`와 `effective_actions`가 모두 빈 배열이고 규칙 내용은 한 줄도 나오지 않는다. role grant까지 거부하므로 `role_actions`가 있어도 `effective_actions`는 비어 있다.

`acl show`는 어느 상태도 오류로 만들지 않는다. 조회는 성공했고(`ok: true`, exit `0`) 조회된 사실이 그 상태일 뿐이다. 파싱 실패의 상세는 §6.12·§6.13의 시작 진단이 정본이다. 그리고 enforcement에는 이 평가기 위에 fail-closed 층이 하나 더 있어서(§6.15) `effective_actions`에 든 action이 운영 상태에 따라 실제로는 거부될 수 있다. 반대 방향, 즉 이 명령이 빼먹은 action이 실제로 허용되는 일은 없다.

`--principal`이나 `--auth-path`가 잘못된 모양이 아닌 한 `acl.show` 자체는 실패하지 않는다(exit `0`, §4). human mode 출력은 principal 한 줄, role 한 줄, 매칭 행 목록(또는 정책 상태를 말하는 한 줄), 실효 action 한 줄, 그 뒤 고지 줄들이다.

### 6.20 `qsh setup`

```bash
qsh setup host --peer <name> [--peer-cert <path|->] [--forward] [--service] [--peer-role <role>] --json
qsh setup host --to <alias> --address <addr> --peer-cert <path|-> [--forward] [--service] [--peer-role <role>] --json
qsh setup client <name> --address <addr> [<code> | --code-stdin | --peer-cert <path|->] [--peer-role <role>] --json
qsh setup listener --peer <name> --peer-cert <path|-> [--service] [--peer-role <role>] --json
```

이 머신을 한 역할로 세운다([ADR-0024](adr/0024-setup-orchestrator.md)). 기존 op을 정해진 순서로 부르는 오케스트레이터이고 새 능력은 없다. 상태를 바꾸는 호출은 `identity.init`, `trust.invite`, `trust.accept`, `trust.add`, `service.install`뿐이며 그 밖에 `doctor.run`을 부른다. `acl.toml`, `config.toml`, `hosts.toml`은 쓰지 않는다. 넣을 `[[acl]]` 행을 인쇄하고 `acl.check`로 확인할 뿐이다. 자동 신뢰는 없어서 pin의 근거는 초대 코드와 인증서 파일 둘뿐이다. `qsh serve`, `qsh listen`, 대화형 세션은 띄우지 않고 서비스 유닛도 활성화하지 않는다(§6.18). §2.5의 "인가 불요" local operation이며 원격 peer가 요청할 수 없고 wire 메시지도 없다.

`setup`은 `qsh <name>`의 host 별칭으로도 읽힐 수 있다. 이 서브커맨드가 그 별칭보다 먼저 잡히므로 `setup`이라는 이름의 host에는 `qsh attach setup` 같은 명시 형태로 닿는다.

**역할.**

| 호출 | `role` | 대응 모드 | pin 수단 | `acl.toml` 행의 allow |
|---|---|---|---|---|
| `setup host --peer <name>` | `host` | `qsh serve` | 초대(`--as <name>` 고정) 또는 `--peer-cert` | `serve` 목록(`exec.run`, `session.*`) |
| `setup host --to <alias> --address <addr> --peer-cert` | `host_to` | `qsh serve --to <alias>` | `--peer-cert` + 주소 | `serve` 목록 |
| `setup client <name> --address <addr>` | `client` | `qsh <name>` | 초대 코드 또는 `--peer-cert` + 주소 | 없음 |
| `setup listener --peer <name> --peer-cert` | `listener` | `qsh listen` | `--peer-cert` | `host.reverse` |

**`--peer-role <role>`** ([ADR-0045](adr/0045-trust-roles.md) 결정 8·14). 이 실행이 쓰는 pin(또는 초대)의 trust role이다. 값은 §6.11의 여섯 role 중 하나이고 모르는 값은 `INVALID_ARGUMENT`(exit `255`)다. 위치 인자 `<role>`이 이미 장비의 역할을 뜻해서 `--role`이 아니라 `--peer-role`이다. 네 호출 모두에서 받고, 생략하면 역할마다 기본값이 정해진다.

| 호출 | 기본 `--peer-role` | 누구에게 적용되나 |
|---|---|---|
| `setup host --peer` | `full` | 이 장비가 발급하는 초대(또는 `--peer-cert`로 쓰는 pin) |
| `setup host --to` | `full` | listener pin. controller가 중계하는 요청을 target이 그 principal로 인가한다 |
| `setup listener` | `reverse` | target pin |
| `setup client` | `none` | server pin. 다이얼만 하는 장비다 |

`--peer-role`이 `none`이 아니면 `acl` 단계는 `done`이다. `detail`이 어느 pin 또는 초대가 어느 role과 그 action을 받는지 적고, `acl_rows`는 나가지 않으며 `acl.toml`은 읽지도 쓰지도 않는다. 이미 같은 이름의 pin이 있고 그 role(`role` 키가 없으면 `none`)이 요청한 role과 다르면 `acl` 단계는 `pending`이고 `detail`과 `next`가 `qsh trust set-role <name> <role>`을 안내한다. `trust add`와 초대 상환은 기존 pin의 role을 바꾸지 않기 때문이다(§6.11). `--peer-role none`이면 지금까지처럼 동작한다. `acl` 단계는 `[[acl]]` 행을 인쇄하고 `acl.toml`을 검증하며 pin은 role `none`으로 쓴다. role이 있는 실행에서는 doctor의 `acl_policy_missing`이 §6.17의 조건대로 나오지 않으므로 `complete` 판정 문장은 그대로 `acl.toml` 없이도 `true`가 될 수 있다. 단독 명령 `steps[].command`는 `none`이 아닌 role이면 끝에 ` --role <role>`을 붙인다.

`--forward`는 `host`와 `host_to`에서만 받고 allow 목록에 `forward.local`을 더한다. `--service`는 `host`, `host_to`, `listener`에서만 받는다. 코드와 `--peer-cert`를 함께 주거나, 위치 코드와 `--code-stdin`을 함께 주거나, `--peer`와 `--to`를 함께 주거나, 역할에 없는 플래그를 주면 clap 인자 사용 오류로 exit `2`다.

**단계 id 어휘.** 닫힌 목록이고 추가만 허용한다.

| id | 하는 일 |
|---|---|
| `identity` | 이 장치의 신원을 만든다(`identity.init`, 멱등) |
| `mode_config` | `config.toml`이 역할에 맞는 실행 모드를 고르는지 읽어서 확인한다 |
| `acl` | `acl.toml`이 의도한 action을 허용하는지 `acl.check`로 확인한다. 읽기 전용. `--peer-role`이 `none`이 아니면 확인하지 않고 pin·초대가 받는 role을 적는다 |
| `pin_cert` | 인증서 파일로 상대를 pin한다(`trust.add`, 항상 `cert_pem`을 채운다) |
| `pair` | 초대 코드를 상환해 상대를 pin한다(`trust.accept`) |
| `invite` | pin 이름을 고정한 초대를 발급한다(`trust.invite --as <name>`) |
| `service` | 서비스 유닛 파일을 쓴다(`service.install`). `--service`가 있을 때만. Windows에서는 작업 스케줄러 작업 정의 파일(§6.18)을 쓸 뿐 작업을 등록하지 않는다 |
| `doctor` | 진단을 돌린다(`doctor.run`) |

**단계 순서.** `host`는 `identity`, `mode_config`, `acl`, `service`, `invite`(또는 `pin_cert`), `doctor`. `host_to`는 `identity`, `pin_cert`, `mode_config`, `acl`, `service`, `doctor`. `client`는 `identity`, `pair`(또는 `pin_cert`), `doctor`. `listener`는 `identity`, `pin_cert`, `mode_config`, `acl`, `service`, `doctor`. `mode_config`와 `acl`은 읽기만 하므로 앞 단계가 `pending`이어도 평가한다.

**Windows host(ADR-0035 결정 1·25·27).** `setup host`와 `setup host --to`는 Windows에서 다른 OS와 같은 단계를 같은 순서로 돌고 Windows 전용 거부나 건너뜀이 없다. `--service`가 있으면 `service` 단계는 `done`이다. `UNSUPPORTED`를 `skipped`로 보는 분기는 서비스 매니저가 없는 플랫폼에만 남고, Task Scheduler는 매니저로 치기 때문이다. 쓰는 것은 `host`에서 `serve`, `host --to`에서 `reverse` mode의 작업 정의 파일(`<config_dir>\service\qsh-<mode>.task.xml`, §6.18)뿐이고 작업 스케줄러에는 등록하지 않는다(`result`에 `activation`이 없다). 등록은 `next`가 안내하는 `qsh service install --activate`가 한다. 다른 장비가 이 host에 닿으려면 `qsh serve`가 UDP 포트를 처음 열 때 뜨는 방화벽 프롬프트에서 사설 네트워크를 허용해야 한다(§6.13의 "방화벽 첫 허용 프롬프트"). `host --to`는 밖으로 dial만 하므로 묻지 않는다.

**단계 상태 어휘.** 닫힌 목록이고 추가만 허용한다.

| status | 뜻 |
|---|---|
| `done` | 이번 실행에서 실행했거나 이번에 충족됐다 |
| `already` | 이미 충족돼 실행하지 않았다 |
| `pending` | 사람이 할 일이 남았다(`detail`에 적는다) |
| `blocked` | 앞 단계가 `pending`이라 실행하지 않았다 |
| `skipped` | 플래그로 제외했거나 이 플랫폼이 지원하지 않는다 |

`data`는 `SetupRunData`(`crates/qsh-proto/src/types/setup.rs`)다.

```json
{
  "role": "host",
  "complete": false,
  "steps": [
    { "id": "identity", "status": "already", "command": "qsh init" },
    { "id": "acl", "status": "pending", "command": "edit acl.toml", "detail": "...", "result": [ { "...": "acl.check data, action 순서" } ] }
  ],
  "acl_rows": "[[acl]]\nprincipal = \"device:laptop\"\n...",
  "next": ["save the rows in `acl_rows` to acl.toml, then run `qsh setup` again"]
}
```

`steps[].command`는 그 단계와 같은 일을 하는 단독 명령이라 `qsh setup` 없이도 손으로 따라 할 수 있다. `steps[].result`는 그 단계가 부른 op의 `data`를 그대로 담는다. `invite`는 `trust.invite`의 `data`(초대 코드 포함)이고 `acl`은 action 순서를 따른 `acl.check` `data` 배열이다. 초대 코드는 `host`의 `invite` 단계 `result`에만 나가고 키 재료는 어느 출력에도 나가지 않는다. `--peer-role none`에서 `acl` 단계가 충족일 때마다 `detail`에 재시작 고지(`ACL_RESTART_NOTICE`)가 붙는다. role 실행에서는 role이 재시작 없이 반영되므로 붙지 않는다. `qsh setup`은 떠 있는 `serve`를 알 수 없기 때문이다. `--peer-role none`의 `host`에서는 만료되지 않은 `assigned_name` 없는 초대가 살아 있으면 `acl` 단계를 충족으로 보지 않고 `detail`이 10분 TTL을 적는다. `complete`는 `pending`·`blocked`가 없고, doctor의 `findings`에 `status: "error"`인 원소가 없을 때만 `true`다. 단, 역할의 면제 목록에 든 `code`는 세지 않는다(ADR-0038). 면제 목록은 `client`가 `acl_policy_missing` 하나이고 `host`·`host_to`·`listener`는 비어 있다. `acl_policy_invalid`와 그 밖의 `acl_*` 진단은 면제하지 않는다. 면제는 판정만 바꾼다. doctor 단계의 `result`는 `doctor.run`의 `data` 그대로라서 `overall: "error"`와 `acl_policy_missing` finding을 담은 채 나가고, 면제가 일어난 실행에서는 그 단계 `detail`이 이 사실을 한 문장으로 덧붙인다. `acl.toml`은 여전히 쓰지 않고 ACL은 default-deny 그대로이므로, `client`의 `complete: true`는 "이 장비가 `<name>`으로 다이얼할 준비를 마쳤다"를 뜻하고 인바운드를 받을 준비를 뜻하지 않는다. `host`에서 `complete`는 상대가 연결했다는 뜻이 아니다.

**입력과 프롬프트.** `--json`/`--jsonl`은 프롬프트를 열지 않는다. 첫 단계 전에 필수 입력의 존재, 이름 규칙, 주소 형식, `--peer-cert`의 PEM 구조와 코드 형식을 모두 검사하고, 하나라도 빠졌거나 틀리면 아무것도 쓰지 않고 `INVALID_ARGUMENT`(exit `255`)다. 이 규칙은 human mode에서 표준입력이 터미널이 아니거나 `--peer-cert -`가 표준입력을 쓸 때도 같다. human mode는 터미널이면 빠진 입력을 stderr 프롬프트로 묻는다. 묻는 것은 역할, pin 이름, 초대 코드(에코 없음), `acl.toml` 저장 확인(저장 뒤 Enter로 다시 확인), `--service`가 없을 때의 서비스 유닛 설치 여부(기본 아니오) 다섯뿐이다. 주소와 인증서 경로는 플래그로만 받는다.

**exit.** 부른 op이 하나도 실패하지 않았으면 `0`이고, `pending` 단계가 남아 있어도 `0`이며 `complete: false`가 그 사실을 담는다. 부른 op이 실패하면 `255`와 오류 envelope이고 `code`와 `retryable`은 그 op의 값 그대로다. `error.details.step`이 실패한 단계 id를, `error.details.steps`가 그때까지의 단계 id와 상태만 담는다(`result` 없음). service op의 `UNSUPPORTED`는 오류가 아니라 `service` 단계 `skipped`다. 이미 끝난 단계는 되돌리지 않고 같은 명령을 다시 부르면 이어서 진행한다. 쓰는 단계가 모두 `already`나 `skipped`인 재실행은 어떤 파일도 바꾸지 않는다. 예외는 상환 전 `host` 재실행으로, 새 초대를 발급한다. clap 인자 사용 오류는 `2`다.

### 6.21 `qsh cp`

```bash
qsh cp [-r] [-p] [-q] [--no-clobber] [--json | --jsonl] SRC... DST
qsh cp ./build.tar.zst personal-mac:/srv/builds/
qsh cp -r ./site personal-mac:/srv/www/
qsh cp dave@personal-mac:out/app.log ./logs/
```

scp와 같은 인자 문법으로 이 머신과 qsh host 하나 사이에서 파일을 복사한다(ADR-0029). `qsh cp`는 qsh host하고만 말한다. scp 프로토콜이나 sftp와는 호환되지 않고 인자 문법이 같을 뿐이다. envelope의 `command`는 `file.copy`다. 이 operation은 client가 `file.read`와 `file.write`를 엮는 합성 local operation이라서 wire 메시지도 ACL 행도 없고 원격 peer가 요청할 수 없다(§2.4, §2.5의 "인가 불요" 행).

파일과 디렉터리 트리(`-r`)를 복사한다.

**operand.** 첫 `/`보다 앞에 `:`가 있고 그 앞의 host 부분이 비어 있지 않으면 `[user@]host:path`인 원격 operand다. IPv6는 `[::1]:path`처럼 대괄호로 싼다. `./a:b`는 로컬 파일이고 `host:`는 원격 계정의 home 디렉터리다. 원격 경로는 절대 경로, home 기준 상대 경로(`dir/x`), `~`, `~/x`를 받는다. `~name`은 `INVALID_ARGUMENT`다. home은 host가 serve 계정의 passwd 항목에서 구하고 환경 변수 `HOME`은 쓰지 않는다. 경로 끝의 `/`는 "디렉터리여야 한다"는 단언이다. `-`(stdin/stdout)는 받지 않는다.

한 호출의 구성은 둘 중 하나다. SRC가 모두 로컬이고 DST가 원격이거나(put), SRC가 모두 같은 host의 원격이고 DST가 로컬이다(get). 원격↔원격, 로컬과 원격이 섞인 SRC, host가 둘 이상인 호출은 아무것도 하기 전에 `INVALID_ARGUMENT`이고 exit `2`다. 결과 위치는 scp와 같다. SRC가 둘 이상이면 DST는 이미 있는 디렉터리여야 하고, SRC가 하나이고 DST가 이미 있는 디렉터리면 그 안에 SRC의 마지막 성분 이름으로 놓는다. 그렇지 않으면 DST가 새 이름이다.

host 이름은 `qsh exec`와 같은 규칙으로 해석한다(§6.1, live reverse 등록이 우선). 사람 모드에서 그 이름이 어디에도 등록돼 있지 않으면 `qsh cp`는 `HOST_NOT_FOUND`로 끝나기 전에 ssh 부트스트랩을 먼저 돌리고 복사를 이어 간다(§7 "이름이 없을 때의 자동 부트스트랩", ADR-0029 결정 2). `--json`/`--jsonl`과 `[ssh].bootstrap = "off"`에서는 돌리지 않는다. `user@`는 `qsh [user@]host`와 같은 뜻의 단언이다. host는 ACL 판정 뒤에 serve 계정의 login name과 대조해 다르면 `UNSUPPORTED`로 답한다.

**플래그.**

| 플래그 | 뜻 |
|---|---|
| `-p` | 파일 mode와 수정 시각을 옮긴다. 접근 시각과 소유자는 옮기지 않는다. 없으면 mode는 `원본 mode & ~umask`, 수정 시각은 쓴 시각이다 |
| `-q` | 진행 표시와 human 요약 줄을 끈다(전역 `--quiet`) |
| `--no-clobber` | 이미 있는 대상 파일을 덮지 않고 그 항목을 `skipped`(reason `exists`)로 건너뛴다 |
| `-r` | 디렉터리를 재귀로 복사한다. 아래 "재귀 복사" 문단. 파일 SRC는 `-r`이 있어도 파일 하나의 복사다 |

그 밖의 scp 플래그(`-P`, `-i`, `-o`, `-F`, `-J`, `-l`, `-c`, `-C`, `-S`, `-B`, `-3`, `-4`, `-6`, `-T`, `-O`, `-s` 등)는 무시하지 않고 거부한다. 복사를 시작하기 전에 stderr에 "scp option -P is not supported by qsh cp" 뜻의 한 줄을 내고 exit `2`로 끝난다. stdout에는 어떤 출력 모드에서도 아무것도 쓰지 않는다.

**권한 범위.** 파일 action을 주는 길은 pin의 role과 `acl.toml` 행(`paths`)이고 둘은 합집합이다(§6.11, §6.15, ADR-0045). `full` role은 serve 계정이 접근할 수 있는 경로 전부에서 qsh 자신의 상태 경로(ADR-0029 결정 5)를 뺀 범위에 `file.read`와 `file.write`를 준다. `~/.bashrc`, `~/.ssh/authorized_keys`, systemd user unit 디렉터리처럼 나중에 실행되는 파일에도 쓸 수 있으므로 `file.write`는 사실상 `exec.run`과 같은 힘이다. `full`은 이미 `exec.run`을 주므로 이 사실은 `full`의 힘에 아무것도 더하지 않는다. 쓰는 범위를 좁히려면 `full`을 쓰지 않고 role `none`에 `paths`가 있는 행을 얹는다. 행의 `paths`가 같은 파일을 덮으면 같은 힘이 되는 점은 같다.

**capability와 route.** 협상된 capability 집합에 `file.v1`이 없으면 요청을 보내기 전에 `UNSUPPORTED`다. 역방향 route(live reverse 등록)에서는 control 요청이 `LOCAL_CONTROL`로, 데이터가 `LOCAL_STREAM`으로 `qsh listen` 데몬을 거쳐 target에 가고, capability는 데몬이 relay한 target의 집합으로 확인한다. 이때의 `UNSUPPORTED` 문면은 원인 둘, 곧 target이 `file.v1` 이전 버전이거나 로컬 데몬이 업그레이드 전부터 떠 있었다는 점을 짚는다. 인가와 상태 경로 판정은 어느 route에서나 파일을 쥔 쪽(`qsh serve`, `qsh serve --to`)이 한다.

**전송.** 파일마다 `FILE_DATA` 스트림이 하나이고 최대 2개(`FILE_COPY_PARALLEL`)가 동시에 돈다. 한 연결이 PTY 등 다른 스트림과 같이 쓰이는 동안 대역 0(`PRIORITY_TUNNEL`)과 송신 깊이 상한, 정체 장부(ADR-0037)가 PTY echo를 보호한다. get의 로컬 쓰기는 DST 디렉터리 fd 기준의 `*at` 호출로 한다. 임시 파일 `.<name>.qsh-<16hex>.part`에 쓰고 BLAKE3와 크기를 검증한 뒤 `fsync`하고, `renameat`(`--no-clobber`면 `linkat`과 `unlinkat`)으로 제자리에 놓은 다음 디렉터리를 `fsync`한다. 실패하거나 중단된 전송은 임시 파일까지 지운다. DST 디렉터리 아래에 이미 있는 symlink는 따라가지 않고 그 항목을 `INVALID_ARGUMENT`로 실패시킨다(DST로 직접 준 경로는 사용자가 고른 것이므로 따라간다). 재개는 없고, 연결이 죽으면 진행 중인 파일은 `CONNECTION_FAILED`로 끝난다. 원격이 주는 이름과 크기는 믿지 않는다(ADR-0029 결정 22).

**재귀 복사(`-r`).** SRC가 디렉터리면 트리를 통째로 옮긴다. 결과 위치는 `cp -r`·`scp -r`과 같다. DST가 이미 있는 디렉터리면 그 안에 SRC의 마지막 성분 이름으로 놓고, 없으면 DST가 새 이름이다. `.`나 `dir/.`처럼 이름이 없는 SRC는 이름 없이 내용만 DST 안으로 복사한다. 이미 있는 디렉터리에는 합쳐 넣고(`directories`는 새로 만든 것만 센다) 파일은 덮는다(`--no-clobber`면 건너뛴다).

순회는 항상 client가 한다(ADR-0029 결정 20). 디렉터리를 이름 바이트 순서로 깊이 우선으로 걷고 부모를 자식보다 먼저 만든다. get은 `file.list` 페이지를 받아 로컬 디렉터리를 `mkdirat`으로 만들고, put은 로컬 트리를 걸으며 `file.mkdir`로 원격 디렉터리를 만든 뒤 파일을 `file.write`한다. 디렉터리는 owner rwx를 켠 mode로 만들어 읽기 전용 원본 디렉터리도 채울 수 있고, `-p`를 주면 원본 mode에 owner rwx를 더한 mode가 된다. 트리 안에서 만난 symlink는 따라가지도 복사하지도 않고 `skipped`(reason `symlink`)로 보고한다. 명령줄에 준 최상위 SRC가 symlink면 끝까지 따라간다. FIFO·소켓·장치 같은 특수 파일은 그 항목만 `INVALID_ARGUMENT`로 실패하고 순회는 계속된다. 이름이 UTF-8이 아니어서 나열할 수 없는 원격 이름(`unlistable`)은 그 디렉터리의 실패 항목 하나로 센다. 4096바이트를 넘는 경로는 그 항목의 실패다. 한 디렉터리의 항목이 `FILE_LIST_DIR_MAX`(65536)를 넘으면 그 디렉터리가 `RESOURCE_EXHAUSTED`로 실패한다.

get에서 host가 돌려준 이름은 믿지 않는다(결정 22). 이름이 비었거나 255바이트를 넘거나 `/`·NUL을 품거나 `.`·`..`이면 그 항목은 `INVALID_ARGUMENT`(side `local`)로 실패하고 로컬에는 아무것도 만들지 않는다. 로컬 경로는 이미 열린 디렉터리 fd 안에 검증한 이름 하나를 만드는 방식으로만 생기므로, 어떤 문자열도 로컬 경로를 벗어나게 하지 못한다.

파일 전송은 위의 둘 병렬 그대로 돌고 디렉터리 생성과 목록 조회는 순서대로 한다. host가 quota로 거절하면(`RESOURCE_EXHAUSTED`) 이 호출 자신의 전송 하나가 끝나기를 기다렸다가 다시 시도하고, 자기 전송이 없는데도 거절되면 그 항목의 실패다(결정 12). 연결 수준 실패는 순회를 멈추고 그 순간 남은 항목(디렉터리는 하나로 센다)을 `not_attempted`로 센다. 트리 전체의 원자성은 없다. host는 요청마다 audit 한 줄을 남기므로(목록 페이지, 디렉터리, 파일) 파일 수천 개 트리는 줄 수천 개다.

첫 Ctrl-C는 연결을 만드는 중(dial, handshake)이면 거기서 시도를 접고, 전송 중이면 진행 중인 스트림을 reset하고 임시 파일을 지운다. 어느 쪽이든 남은 항목을 시도하지 않고 `CANCELED`와 exit `255`로 끝난다. 둘째 Ctrl-C는 정리를 기다리지 않고 exit `255`로 프로세스를 바로 끝낸다. 이때는 이 머신의 임시 파일이 남을 수 있다(host의 임시 파일은 연결이 끊기면 host가 지운다). 첫 Ctrl-C 뒤 연결을 닫기 전에 host가 보낸 프레임이 하나 도착하기를 최대 2초 기다린다. 전송 중에 닫으면 QUIC 구현이 혼잡 윈도가 찬 동안 `CONNECTION_CLOSE`를 보내지 않아 host가 닫힘을 모른 채 유휴 시간 초과(45초)까지 임시 파일을 쥐기 때문이다. host가 응답하지 않으면 2초 뒤에 그냥 닫는다.

**출력.** human 모드는 stderr가 TTY일 때 파일별 진행 표시를 stderr에 그리고(`-q`로 끈다), 끝나면 stdout에 요약 한 줄(파일 수, 바이트, 시간, 건너뜀과 실패 수)을 쓴다. 복사가 실패하면 human 모드는 실패한 항목마다 stderr에 한 줄(경로와 사유)을 쓰고 끝에 `qsh: N of M entries failed (CODE)` 한 줄로 닫는다. 이 줄은 항목의 문장을 되풀이하지 않는다. 항목 실패 없이 멈춘 복사(Ctrl-C, capability)는 멈춘 이유가 뒤에 붙는다. machine 모드는 진행 표시를 내지 않는다. `--json`은 envelope 하나다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "file.copy",
  "ok": true,
  "data": {
    "host": "personal-mac",
    "direction": "get",
    "files": 1,
    "directories": 0,
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
}
```

`direction`은 `get` 또는 `put`이다. `entries`는 항목 하나당 한 원소이고 `status`는 `copied`, `created`(디렉터리), `skipped`(`reason`: `exists`, `symlink`), `failed`(`code`와 `message`) 중 하나다. 열린 문자열이다. 원소는 처음 `COPY_JSON_ENTRIES_MAX`(1000)개까지만 싣고 넘으면 `entries_truncated`가 `true`다. `remote_path`와 `local_path`는 operand에서 파생한 문자열 그대로이고 host가 해석한 정규 경로가 아니다. `mode`는 10진 정수다. `blake3`는 전송한 바이트의 BLAKE3-256 소문자 hex 64자라서 사용자가 원본과 대조할 수 있다.

`--jsonl`은 항목이 끝나는 대로 `file.entry` event 한 줄(§10)을 stdout에 쓰고, 마지막 줄은 `--json`과 같은 envelope이다(성공이면 `entries`는 빈 배열). event는 `schema`가 `qsh.event/v1`이고 envelope은 `qsh.cli/v1`이라 그 필드로 가른다. event의 `type` 뒤 필드는 `entries[]` 원소와 같다.

**부분 실패.** scp와 같이 한 항목의 실패가 나머지를 멈추지 않는다(SRC가 여럿이면 `-r` 없이도 일어난다). 연결 수준의 실패(`CONNECTION_FAILED`, `CANCELED`, capability `UNSUPPORTED`, 인증 오류)는 남은 항목을 시도하지 않고 멈추고, 시도하지 못한 수를 `not_attempted`로 센다. 끝난 항목은 되돌리지 않는다. 모든 항목이 `copied`, `created`, `skipped`이면 exit `0`이고, 하나라도 `failed`이거나 중간에 멈췄으면 exit `255`이며 envelope은 `ok: false`다.

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "file.copy",
  "ok": false,
  "error": {
    "code": "INVALID_ARGUMENT",
    "message": "1 of 2 entries failed: no such file or directory",
    "retryable": false,
    "details": {
      "copied": 1,
      "created": 0,
      "skipped": 0,
      "failed": 1,
      "not_attempted": 0,
      "failures": [
        { "side": "local", "path": "./missing.txt", "code": "INVALID_ARGUMENT" }
      ],
      "failures_truncated": false
    }
  }
}
```

`error.code`는 첫 `failed` 항목의 code이고 연결 수준 실패로 멈췄으면 그 code다. `retryable`은 멈춘 이유가 `CONNECTION_FAILED`일 때만 `true`다. `failures`는 처음 `COPY_JSON_FAILURES_MAX`(64)개의 `{side, path, code}`이고 `side`는 이 머신에서 실패했으면 `local`, host가 거절하거나 실패했으면 `remote`다. 파일 하나의 복사가 실패해도 같은 모양이다. 인자 오류는 복사를 시작하기 전에 exit `2`로 끝나고 아무것도 바꾸지 않는다.

**오류 코드.** 새 `ErrorCode`는 없다.

| 상황 | code |
|---|---|
| operand 구성 오류, `~name`, `-`, 원본 없음, 정규 파일이 아님, 대상이 디렉터리, symlink 대상, 크기·해시 불일치(`file.write`), 이름 검증 실패, scp 플래그 | `INVALID_ARGUMENT` |
| ACL deny, 상태 경로 판정, 재검증 불일치, OS의 `EACCES`/`EPERM` | `PERMISSION_DENIED`(균일한 문면) |
| quota, 여유 공간, `ENOSPC`, 정체 장부의 끊음, 한 디렉터리의 항목 수 상한 | `RESOURCE_EXHAUSTED` |
| 크기·해시 불일치(`file.read`, client 판정) | `REMOTE_ERROR` |
| connection 유실 | `CONNECTION_FAILED`(`retryable: true`) |
| peer에 `file.v1` 없음, `user@` 불일치 | `UNSUPPORTED` |
| Ctrl-C(연결을 만드는 중이든 전송 중이든) | `CANCELED` |

`ENOENT`(원본 없음의 `INVALID_ARGUMENT`)는 ACL과 상태 경로 판정을 모두 통과한 경로에서만 드러난다. 그래서 파일 존재 여부를 오류 차이로 알아낼 수 있는 범위는 그 principal이 닿는 범위 안으로 한정된다.

**Windows.** Windows client의 `qsh cp`는 unix client와 같은 operand 문법·`-r`·`-p`·`--no-clobber`·오류 의미로 동작한다(ADR-0035 결정 1·26, ADR-0029 결정 2·7·22·23). 다른 점은 둘이다. 첫째, operand 문법의 드라이브 문자 규칙이다. 첫 구분자(`/` 또는 `\`) 앞에서 한 글자와 `:`로 시작하는 operand(`C:\x`, `c:x`)는 로컬 경로이고, 한 글자 이름의 host는 `user@`를 붙이거나(`me@c:path`) 대괄호로 싸야(`[c]:path`) 원격 operand가 된다. unix client에는 이 규칙이 없고 한 글자 host도 그대로 받는다. 둘째, get의 로컬 쓰기다. 목적지 디렉터리를 연 핸들 아래에서 소유자 전용 DACL의 임시 파일을 만들고, 이름 바꿈 직전에 그 보호를 풀어 디렉터리가 물려주는 ACL을 받게 한다(unix가 `0600`으로 만든 뒤 `mode & ~umask`를 주는 것의 짝이다). 모드 비트는 만들어 낸 값이라 파일은 읽기 전용 속성이 있으면 `0o444`, 없으면 `0o644`, 디렉터리는 `0o755`이고, 원격 모드의 소유자 쓰기 비트가 꺼졌을 때만 읽기 전용 속성을 쓰며 다른 비트는 쓰지 않는다. `-p`는 수정 시각을 옮긴다. 마지막 구성 요소가 심볼릭 링크나 junction이면 따르지 않고 `INVALID_ARGUMENT`로 거절한다(unix의 `O_NOFOLLOW`에 해당한다).

**Windows host.** Windows host(`qsh serve`, `qsh serve --to`)도 `file.v1`을 광고하고 네 op와 `FILE_DATA`를 처리한다. 판정 순서는 unix host와 같다(형식 검사, ACL, `user@` hint, 상태 경로 판정, quota, 열기와 재검증, ADR-0029 결정 8). 다른 점은 아래와 같다(ADR-0035 결정 26).

- 원격 경로는 `/`와 `\`를 같은 구분자로 읽는다. 드라이브 절대 경로(`C:\data\a.txt`, `C:/data/a.txt`)이거나, `~`·빈 경로(wire에는 `~`로 간다)·상대 경로이며 후자는 serve 계정의 프로필 디렉터리(`GetUserProfileDirectoryW`) 기준이다. `%USERPROFILE%`은 보지 않는다. `acl.toml`의 `paths`는 `C:/data` 모양이다(결정 23).
- UNC(`\\server\share\x`)와 장치 이름 공간(`\\?\C:\x`, `\\.\pipe\x`)은 host가 네트워크 공유나 장치에 peer 대신 닿게 되므로 ACL보다 앞서 `INVALID_ARGUMENT`이고 audit 줄이 남지 않는다. 드라이브 없는 경로(`\x`, `/x`), 드라이브 상대 경로(`C:x`), 드라이브 자리 밖의 `:`(NTFS 대체 데이터 스트림 `x:s`), 예약 장치 이름(`CON`, `NUL.txt`), 끝의 점이나 공백, 예약 문자도 같다.
- 정규화는 `.`과 `..`을 먼저 어휘적으로 접고(Win32가 문자열에 하는 일과 같다) 존재하는 가장 긴 접두를 최종 경로(`GetFinalPathNameByHandle`, `\\?\` 접두를 뗀 것)로 푼 뒤 나머지를 붙인다. 그래서 junction이나 symlink 뒤의 `..`은 링크의 어휘적 부모를 가리킨다(unix는 링크가 가리키는 곳의 부모). 결과가 드라이브 경로가 아니면(UNC 공유나 드라이브 문자 없는 볼륨으로 나가는 링크) 거절한다.
- 상태 경로 판정과 보호 집합의 대조는 구성 요소 단위로 대소문자를 무시한다. 열기는 `FILE_FLAG_OPEN_REPARSE_POINT`로 하고, 마지막 구성 요소가 symlink나 junction이면 거절하며, 열린 핸들의 최종 경로가 요청한 경로와 다르면(중간 구성 요소가 교체됨) 같은 균일한 `PERMISSION_DENIED`이고 audit에는 ACL 줄 뒤에 deny 한 줄이 남는다. 보호 파일의 대조는 `(dev, ino)` 대신 파일 신분(`FILE_ID_INFO`, 없으면 64비트 인덱스)으로 한다.
- 쓰기의 임시 파일은 목적지 디렉터리 핸들 아래에서 소유자 전용 DACL로 만들고, 이름 바꿈 직전에 그 보호를 풀어 디렉터리가 물려주는 ACL을 받게 한다. 읽기 전용 속성은 모드의 소유자 쓰기 비트가 꺼졌을 때만 쓰고, 읽기 전용 파일도 unix rename처럼 교체한다. 읽기와 목록의 모드는 만들어 낸 값(파일 `0o444`/`0o644`, 디렉터리 `0o755`)이다. 여유 공간은 `GetDiskFreeSpaceExW`로 잰다.
- `file.list`의 이름은 UTF-16에서 UTF-8로 바뀌므로 읽을 수 없는 이름(`unlistable`)이 생기지 않는다.

### 6.22 `qsh audit`

```bash
qsh audit [--since <RFC3339|N[smhd]>] [--until <RFC3339>] [--principal <p>] [--action <a>] [--resource <r>] [--decision allow|deny] [--limit <N>] [--json]
qsh audit --decision deny --since 24h
qsh audit --principal device:laptop --action file.write --limit 20 --json
```

이 장비 자신의 audit 로그를 조회한다([ADR-0033](adr/0033-session-audit-management.md)). 로그는 `qsh serve`, `qsh listen`, `qsh serve --to`가 인가 판정마다 한 줄씩 남기는 JSONL이다(`docs/design/architecture.md` §6). envelope의 `command`는 `audit.query`다. 이 조회는 항상 이 프로세스가 도는 장비의 로컬 로그를 읽으므로 forward host로 쓰는 장비, reverse listener로 쓰는 장비, reverse target으로 쓰는 장비 어느 쪽에서도 같은 명령과 같은 `data`를 낸다. 세 프로세스가 남긴 레코드는 한 파일에 같은 모양으로 들어 있다. Linux·macOS·Windows에서 같다. 로그 경로는 각 플랫폼의 state dir이다(Windows는 ADR-0035 결정 13). 읽을 파일이 정하는 것은 `config.toml`의 `[audit].path`(생략하면 `<state_dir>/audit.log`)와 `[audit].retain`이다.

- `--since <RFC3339|N[smhd]>`: 이 시각 이후(그 시각 포함)의 레코드. RFC 3339 시각이거나 지금부터 거슬러 올라가는 간격(`90s`, `15m`, `24h`, `7d`)이다. 이 밖의 모양은 `INVALID_ARGUMENT`다.
- `--until <RFC3339>`: 이 시각 이전(그 시각 포함)의 레코드. 간격 표기는 받지 않는다.
- `--principal`, `--action`, `--resource`: 해당 필드와 문자열이 **정확히 일치**하는 레코드. 부분 일치와 패턴은 없다.
- `--decision <allow|deny>`: 이 밖의 값은 `INVALID_ARGUMENT`다.
- `--limit <N>`: 돌려줄 레코드의 최대 개수. 범위는 1부터 1000까지이고 기본은 100이다. 0이거나 1000을 넘으면 `INVALID_ARGUMENT`다. clap은 숫자 모양만 보고 범위는 `qsh-core`가 판정하므로 사용법 오류(exit `2`)가 아니라 `INVALID_ARGUMENT`(exit `255`)가 난다.
- 여러 필터는 AND다. 결과는 최신이 먼저다. `--follow`는 없다.

원격 peer가 부를 수 없는 **로컬 operation**이다(§2.4·§2.5). `qsh audit <host>` 형태는 없고, 다른 호스트의 audit이 필요하면 그 호스트에 로그인해 거기서 이 명령을 친다. 새 ACL action을 요구하지 않고 wire 메시지도 localctl 요청도 만들지 않는다.

`data`는 `AuditQueryData`(`crates/qsh-proto/src/types/audit.rs`)다:

```json
{
  "schema": "qsh.cli/v1",
  "request_id": "01K0EXAMPLE",
  "command": "audit.query",
  "ok": true,
  "data": {
    "records": [
      {
        "ts": "2026-10-16T01:02:03Z",
        "request_id": "7",
        "principal": "device:laptop",
        "action": "file.write",
        "resource": "/srv/builds/app.tar.zst",
        "decision": "deny",
        "rule": null,
        "auth_path": "pin",
        "peer_addr": "100.64.0.7:51234"
      }
    ],
    "skipped_lines": 0,
    "oldest_ts": "2026-10-09T08:00:00Z",
    "truncated": false
  }
}
```

- `records`의 각 항목은 로그에 저장된 구조 필드를 필드 단위로 옮긴 `AuditRecordView`다: `ts`, `request_id`, `principal`, `action`, `resource`, `decision`, `rule`, `auth_path`, `peer_addr`와, 창 요약 레코드에만 있는 `count`, 레코드에 키가 있을 때만 나오는 `role`(ADR-0045 결정 16). 필드가 없는 키는 필드 자체가 나타나지 않는다. 새 필드를 만들거나 값을 가공·보강하지 않는다(DNS 역조회, 별칭 해석 없음). 레코드 타입에 argv·PTY 바이트·키 재료를 담을 필드가 없으므로 출력에도 없다.
- `skipped_lines`는 읽은 모든 파일에서 쓸 수 없던 줄의 수다. 쓰는 도중이거나 잘린 줄, JSON으로 파싱되지 않는 줄, 한 줄이 64 KiB를 넘는 줄을 센다. 이런 줄의 내용은 오류에도 출력에도 싣지 않는다.
- `oldest_ts`는 읽은 파일 전체에서 가장 오래된 레코드의 `ts`다. 필터와 무관하고, 읽은 레코드가 하나도 없으면 `null`이다. 이 호스트가 얼마나 오래된 audit을 보존하는지 읽는 수단이다.
- `truncated`는 `--limit` 때문에 필터에 맞는 레코드가 더 있는데 잘렸을 때만 `true`다.

**읽기만 한다.** 활성 로그와 회전분을 읽기 전용으로 열고, writer의 파일 락을 잡지 않고, 잘린 꼬리를 고치지도 않는다. 실행 중인 `qsh serve`가 쓰거나 회전하는 도중에도 막히지 않고 writer의 회전을 막지도 않는다(Windows는 `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`로 연다). 회전 중에는 같은 레코드가 두 번 보이거나 한 줄이 잘려 `skipped_lines`로 셀 수 있다. 정확한 개수가 아니라 막지 않는 쪽을 택한 것이다. 로그 파일이 없으면 오류가 아니라 빈 결과(`records: []`, `oldest_ts: null`)다. 읽을 수 없으면(권한, I/O, 일반 파일이 아님) `INTERNAL`이고 메시지에는 경로와 오류 종류만 담긴다. `config.toml`을 읽을 수 없으면 기존 `CONFIG_ERROR`다. 기본 경로로 대신 읽지 않는다. `[audit].path`를 옮긴 장비에서 엉뚱한 파일을 읽게 되기 때문이다.

**audit을 남기지 않는다.** 조회는 audit 레코드를 쓰지 않는다. 읽기가 로그를 키우면 조회를 반복하는 것만으로 회전과 보존 기간이 밀리고, writer가 degraded(큐 포화, 디스크 만실)로 굳은 상태에서는 fail-closed 규칙 때문에 조회가 거부되어 가장 필요한 순간에 쓸 수 없기 때문이다. 그래서 writer가 degraded여도 읽는다(`acl.show`·`acl.check`가 읽기라서 audit을 쓰지 않는 선례와 같다).

**지우는 명령이 없다.** audit 레코드를 지우거나 줄이는 명령은 없다. `qsh audit` 아래의 삭제·압축·내보내며 지우기도 없고 시간 기반 보존(N일 지난 레코드 삭제)도 없다. 개수 기반 회전(`[audit].max_bytes`, `[audit].retain`)이 유일한 삭제이고 그 의미와 기본값은 바뀌지 않는다. 더 오래 보존해야 하면 회전분이 밀려나기 전에 운영자가 qsh 밖에서 로그 파일을 복사한다. 보존 지평은 `oldest_ts`로 읽는다. 이 사실을 알려 주는 doctor 진단은 없다.

**human mode** 출력은 stdout에 표 하나(`TS`, `DECISION`, `PRINCIPAL`, `ACTION`, `RESOURCE`, `RULE`, `AUTH_PATH`, `PEER`, `ROLE`, `COUNT`)이고 최신이 먼저다. 맞는 레코드가 없으면 `no audit records` 한 줄이다. `request_id`는 표에 싣지 않고 `--json`에서 본다. 표 뒤의 요약은 stderr에 `qsh:` 접두의 줄로 나간다(§2.2의 stdout 순수성): `oldest_ts`를 알리는 줄(레코드가 없으면 그 사실을 알리는 줄), `truncated`일 때 `--limit`을 올리거나 필터를 좁히라는 줄, `skipped_lines`가 0이 아닐 때 그 개수를 알리는 줄이다. 줄의 내용은 어디에도 찍지 않는다. 지원 출력 모드는 human과 `--json`이다. `--jsonl`은 다른 value operation처럼 `--json`과 같은 한 줄을 낸다.

실패와 종료 코드는 §4를 따른다. 필터 값이 잘못되면 `INVALID_ARGUMENT`, 로그를 읽을 수 없으면 `INTERNAL`, `config.toml`이 잘못되면 `CONFIG_ERROR`다. 새 `ErrorCode`는 없다. 오류 문면은 관찰, 영향, 다음 명령 세 부분을 가진다(예: `audit limit 5000 is out of range (expected 1..=1000), so nothing was read; run \`qsh audit --limit 1000\` or a smaller value`).

Windows named pipe localctl(ADR-0035 결정 14)에도 이 op의 요청이 없다. localctl 소스 전체를 훑는 `audit_query_has_no_wire_message_and_no_localctl_request`가 pipe transport 파일도 덮고, `localctl_request_enum_has_no_audit_variant_on_any_platform`이 요청 enum이 닫혀 있음을 모든 OS에서 지킨다.

## 7. Human interactive mode

다음 명령은 위의 session operation을 조합한 편의 인터페이스다.

```bash
qsh dave@personal-mac
qsh attach <session-ref>
qsh personal-mac -L 8080:localhost:3000
qsh personal-mac -R 9000:localhost:9000
```

Interactive mode는 terminal raw mode, window resize와 signal forwarding을 처리한다. 세션 생성·읽기·쓰기의 권한과 동작은 machine-readable command와 동일하다.

**Machine output mode가 없다.** 이 두 form의 stdout은 원격 터미널의 byte 그 자체이므로(§2.2) envelope가 들어갈 자리가 없다 — `qsh serve`(§6.12)와 같은 이유로 예외다. `--json`/`--jsonl`을 붙이면 **세션을 만들기 전에** `INVALID_ARGUMENT` error envelope 한 줄과 exit `255`(§4)로 거부한다. 기계 소비자는 같은 일을 `qsh session open --json` + `qsh session read --follow --jsonl` + `qsh session write`로 조합한다(§7.1).

**Windows host의 세션(ADR-0035 결정 20·21).** 상대가 Windows host여도 같은 form과 같은 operation이다. 호스트는 세션마다 ConPTY 하나와 Job Object 하나를 만들고, 자식은 `qsh serve`를 실행한 계정으로 돈다(user switching은 없다). 자식의 환경은 `qsh serve` 프로세스 환경이 아니라 그 계정의 사용자 환경 블록이다. 그 위에 `TERM`(없으면 `xterm-256color`), serve 환경의 locale·시간대(`LANG`·`LANGUAGE`·`TZ`·`LC_*`), client가 보낸 `env`가 차례로 얹히고, client가 덮어쓸 수 없는 이름(`HOME`·`USER`·`LOGNAME`·`SHELL`·`PATH`·`USERPROFILE`·`USERNAME`·`USERDOMAIN`·`HOMEDRIVE`·`HOMEPATH`·`COMSPEC`·`SystemRoot`·`QSH_SIGNAL_EVENT_USR1`·`QSH_SIGNAL_EVENT_USR2`, 이름의 대소문자는 가리지 않음)은 마지막에 다시 적용된다. 마지막 둘은 호스트가 세션마다 만드는 이름 있는 자동 리셋 이벤트(`Local\qsh-sig-<128비트 난수 hex>-usr1`·`-usr2`, 소유자 전용 DACL)의 이름이고, 자식이 그 이름으로 이벤트를 열어 기다리면 `session close --signal USR1|USR2`(§6.7)가 그 이벤트를 `SetEvent`한다. 환경변수가 둘 늘었을 뿐 wire와 `qsh.cli/v1`은 그대로다. `argv`가 비면 `COMSPEC`(없으면 `%SystemRoot%\System32\cmd.exe`)이 전체 경로로 실행되고 작업 디렉터리는 `USERPROFILE`이다. `argv[0]`은 호스트의 작업 디렉터리나 호스트 `PATH`가 아니라 자식의 `PATH`와 시스템 디렉터리에서만 찾으며, 못 찾으면 세션을 만들지 않는다. `user@host`의 `user`는 호스트 토큰의 계정 이름(`user` 또는 `DOMAIN\user`)과 대소문자 무시로 같아야 하고, 다르면 세션을 만들기 전에 `UNSUPPORTED`(`user switching is not supported`)다.

**Windows host의 `exec`(ADR-0035 결정 3·20·22).** `exec.run`은 세션과 같은 환경 규칙을 쓰되 의사 콘솔이 없다. 자식의 stdin·stdout·stderr는 소유자 전용 DACL과 128비트 난수 이름의 named pipe이고, 자식은 이 세 핸들만 상속한다(`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`). 환경은 계정의 사용자 환경 블록 위에 client `env`가 얹히고, unix `exec`와 같게 `TERM`이 없고 serve 환경의 locale·시간대(`LANG`·`LANGUAGE`·`TZ`·`LC_*`)도 넘어가지 않으며(대화형 세션과 달리; client가 `--env`로 보낸 것은 넘어간다), 세션과 같은 pinned key가 마지막에 다시 적용되며(`QSH_SIGNAL_EVENT_*`는 `exec`에 없으므로 자식 환경에도 없다), 사용자 블록에 없는 pinned key는 자식에도 없다. `argv`가 비었거나 NUL을 담고 있으면 자식을 만들기 전에 종료 코드 `126`이고, `argv[0]`은 자식의 `PATH`와 시스템 디렉터리에서만 찾으며 못 찾으면 종료 코드 `127`이다(unix와 같은 in-band 보고). 자식은 `CREATE_NO_WINDOW`로 뜬다.

**Windows 콘솔.** 대화형 form이 Windows에서 따르는 규칙이다(ADR-0035 결정 5~8). 클라이언트는 입력 핸들을 VT 입력 모드(줄 편집, 에코, 시스템 Ctrl-C 처리를 끄고 `ENABLE_VIRTUAL_TERMINAL_INPUT`을 켬)로, 출력 핸들을 VT 처리 모드로 바꾸고 콘솔 코드 페이지를 UTF-8(65001)로 맞춘다. 키는 해석하지 않으므로 Ctrl-C는 `0x03` 바이트로 원격에 가고 해석은 원격 PTY가 한다. Windows host의 pseudo-console이 출력에 실어 보내는 win32 input mode 요청(`CSI ? 9001 h`/`l`)은 클라이언트가 콘솔에 쓰기 전에 지운다(목록에 섞여 있으면 그 번호만 뺀다). 이 요청이 로컬 콘솔에 닿으면 콘솔이 입력 바이트 대신 키 레코드 시퀀스를 돌려주어 줄 첫머리의 `~d`를 알아볼 수 없기 때문이다. 다른 모드 요청은 그대로 흐른다. 바꾼 모드와 코드 페이지는 정상 종료, 오류, panic, 콘솔 창 닫기·`CTRL_BREAK`·로그오프·종료 어느 경로에서든 원래대로 돌려 놓는다. 닫기·로그오프·종료 이벤트는 unix의 SIGHUP과 같이 detach로 처리하므로 세션은 서버에 남는다. Windows는 핸들러가 돌아오는 순간 시스템이 프로세스를 끝내므로, 클라이언트는 모드를 복원한 뒤 QUIC 연결을 먼저 닫고 그 전송이 끝날 때까지(최대 4초) 핸들러를 붙잡는다. 그래서 호스트는 연결 유실이 아니라 정상 detach로 세션을 보고 다른 콘솔에서 곧 이어 붙을 수 있다. `-L`/`-R`/`-D` companion flag와 resume은 unix와 같은 규칙이다. 출력 핸들에 VT 처리를 켤 수 없는 conhost(Windows 10 1809 미만)이면 `session.open`을 보내기 전에 `UNSUPPORTED`로 끝나고 message가 Windows 10 1809를 적는다. 표준입력이 콘솔이 아니면(파이프, 리디렉션, 파이프를 주는 mintty 계열 터미널) unix의 비 tty 경로와 같이 raw 모드도 escape 처리도 없이 바이트를 그대로 흘린다. mintty 계열(Git Bash)에서 대화형으로 쓰려면 Windows Terminal에서 실행하거나 `winpty qsh ...`로 부른다. 창 크기는 이벤트 없이 200 ms마다 콘솔 창 영역을 읽어 바뀔 때만 `session.resize`로 보낸다. `SessionOpen.term`은 `TERM`이 있으면 그 값이고, 없으면(Windows의 일반 상태) 콘솔 입출력이 모두 VT로 켜졌을 때 `xterm-256color`다.

**전달되는 환경변수.** 대화형 form은 로컬 터미널을 재현하는 데 필요한 것만 보낸다: `TERM`은 `SessionOpen.term`으로, locale(`LANG`, `LANGUAGE`, `LC_ALL`, `LC_CTYPE`, `LC_COLLATE`) 중 클라이언트 프로세스에 설정된 것은 `SessionOpen.env` overlay로 전달한다(architecture.md §4). 이는 **대화형 form 한정** 동작이다 — `qsh session open`·`qsh exec`는 호출자가 명시한 `--env`만 보내며, 클라이언트 프로세스의 환경을 암묵적으로 상속시키지 않는다. `HOME`/`USER`/`LOGNAME`/`SHELL`/`PATH`는 어느 경로에서도 호스트가 고정한다.

**시스템 ssh를 부르는 규칙(ADR-0044).** pin이 없는 대상에 시스템 ssh를 한 번 거쳐 양쪽 pin을 세우는 경로가 공유하는 ssh 쪽 규칙이다. 설정은 §6.12의 `[ssh]`다.

- **`<dest>` 검증.** `[user@]host`를 마지막 `@`에서 자른다(위 `qsh [user@]host`와 같은 규칙). `-`로 시작하거나 `ssh://` 꼴이거나 비어 있으면 ssh를 부르기 전에 `INVALID_ARGUMENT`다. 이 검증은 ssh에 넘기는 operand에 대한 것이고 pin 이름과는 따로다. 이 장비가 원격을 pin하는 이름은 `--as`가 있으면 그 값, 없으면 host 부분 그대로이고(`hostname`이 아니다) 어느 쪽이든 pin 이름 규칙(§6.11 `--as`와 같다, `/` 금지)을 통과해야 한다. 그래서 host 부분이 그 규칙에 걸리는 `Host` 별칭도 `--as`를 주면 쓸 수 있고, 주지 않으면 ssh를 부르기 전에 `INVALID_ARGUMENT`다.
- **ssh 호출 둘.** `ssh -G -- <dest>`는 설정만 평가한다(네트워크 없음). 출력은 64 KiB까지 읽고 `hostname`·`user`·`proxyjump`·`proxycommand` 네 키만 꺼낸다. `user`는 어디에도 저장하지 않는다. 응답자 호출은 `ssh -T -a -x -o ClearAllForwardings=yes -o RemoteCommand=none -o RequestTTY=no -o PermitLocalCommand=no [-o BatchMode=yes] -- <dest> <remote_qsh> pair ssh-respond`로 고정이다. `StrictHostKeyChecking`을 비롯한 그 밖의 설정은 사용자의 ssh 설정 그대로 둔다.
- **`<remote_qsh>` 인용.** `[A-Za-z0-9_./~+:\\-]`만으로 된 값은 그대로, 그 밖의 문자가 있으면 POSIX 작은따옴표로 감싼다. 빈 값과 제어 문자는 `INVALID_ARGUMENT`다.
- **터미널과 `BatchMode`.** ssh의 stderr와 제어 터미널은 그대로 물려받아 암호·passphrase·host key 확인을 ssh가 직접 묻는다. `BatchMode=yes`는 `--json`/`--jsonl`이거나 stdin이 터미널이 아닐 때만 붙는다. 응답자의 `hello`를 기다리는 시간은 사람 모드에서 제한이 없고 `BatchMode`에서는 60초이며, 그 뒤 메시지마다 30초다(넘으면 `TIMEOUT`, `details.reason: "bootstrap_timeout"`). ssh 프롬프트에서 Ctrl-C로 ssh가 끝나면 `CANCELED`이고 아무것도 쓰지 않는다.
- **종료 코드 사상.** 응답자의 `hello` 전에 ssh가 끝나면 종료 코드로 갈린다. 127(`cmd.exe` 배치의 9009 포함)은 `REMOTE_ERROR`(`details.reason: "remote_qsh_missing"`)이고 message가 `--remote-qsh`와 `[ssh].remote_qsh`를 안내한다. 원격 기본 셸이 `cmd.exe`이면 ssh의 종료 코드가 9009가 아니라 1이므로, 1이면서 ssh가 relay한 stderr의 어떤 줄이 `'<원격 qsh 이름>'`(기본 `qsh`, `--remote-qsh`·`[ssh].remote_qsh`를 준 경우 그 값이나 그 basename)으로 시작할 때도 같은 사상이다(`details.remote_exit: 1`). 이 판정은 ANSI 이스케이프와 줄 앞 공백을 걷은 마지막 4 KiB만 본다. 2는 `UNSUPPORTED`(`"remote_qsh_too_old"`), 그 밖의 1은 `REMOTE_ERROR`(`"remote_command_failed"`, `details.remote_exit`)다. 원격 기본 셸이 PowerShell이면 `qsh`가 없을 때도 1이고 stderr가 `qsh:`로 시작해 위 판정에 걸리지 않으므로 message가 `qsh.exe`를 원격 `PATH`에 두거나 전체 경로를 주라고 안내한다. 255는 `CONNECTION_FAILED`(`"ssh_failed"`, `details.ssh_exit`)이고 ssh가 stderr에 쓴 원인은 다시 해석하지 않는다. ssh의 stderr는 사용자 stderr로 바이트 그대로 즉시 흐르고, 분류용 꼬리는 메모리에만 있다가 버려지며 envelope·로그·audit에 들어가지 않는다. ssh 실행 파일이 없으면 `CONFIG_ERROR`(`"ssh_not_found"`)이고 Windows에서는 선택적 기능 "OpenSSH Client"를 안내한다. 줄 형식 위반은 `REMOTE_ERROR`(`"bootstrap_protocol"`)다. 모든 `details.reason`은 기존 코드에 붙는 선택 필드다.
- **로그.** 단계와 결과 코드만 남긴다. 응답자 앞에 오는 접두 없는 줄(원격 rc 출력)은 개수만 세고, ssh의 stderr는 로그로 복사하지 않는다. qsh는 SSH 개인키·암호·agent 소켓을 읽지 않는다.

**이름이 없을 때의 자동 부트스트랩(ADR-0044 결정 2·3·13·16·22).** `qsh [user@]host`(`-L`/`-R`을 곁들인 형태 포함)와 `qsh cp`가 받은 이름이 §6.1의 첫 `HOST_NOT_FOUND` 갈래에 해당하면, 오류로 끝내지 않고 `qsh pair ssh <dest>`와 같은 부트스트랩(정방향, 기본 플래그)을 먼저 돌린 뒤 원래 명령을 그대로 이어 간다. `<dest>`는 사용자가 친 `[user@]host`다. 발동은 아래가 모두 참일 때만이다.

- 사람 모드다. `--json`/`--jsonl`에서는 ssh를 부르지 않고 지금처럼 `HOST_NOT_FOUND`다. 이 두 표면의 machine 모드는 암묵적으로 ssh를 부르지 않는다.
- 이름이 `hosts.toml`에도, `trust.toml`의 pin에도, reverse 등록(live와 stale 모두)에도 없다. pin이 하나라도 있으면 ssh는 다시 불리지 않는다.
- `config.toml`의 `[ssh].bootstrap`이 `"off"`가 아니다(기본 `"auto"`, §6.12). `"off"`면 발동하지 않고 `HOST_NOT_FOUND`다.
- 이름이 ssh operand와 pin 이름 규칙(위 `<dest>` 검증)을 통과한다. 통과하지 못하면 발동하지 않고 원래 명령의 `HOST_NOT_FOUND`가 난다.

`qsh exec`, `qsh session open`, `qsh tunnel open`, `qsh sessions`는 기계 지향 표면이라 사람 모드에서도 발동하지 않는다. 자동 경로는 역방향(`--reverse --to`)을 고르지 않는다. 이름만으로는 어느 쪽이 dial하는지 알 수 없기 때문이다(결정 22).

ssh를 부르기 전에 stderr에 한 줄을 쓴다: `qsh: no qsh pin for "<host>"; setting one up over ssh (ssh <dest>); set [ssh].bootstrap = "off" to disable`. `--quiet`는 이 줄을 끄지 않는다(ssh가 불린다는 경고다). 이어서 `qsh pair ssh`가 사람 모드에서 쓰는 pin 안내 줄이 stderr에 나가고 `--quiet`는 이 줄들을 끈다. stdout은 원래 명령의 것만 쓴다. 자동 경로는 확인용 dial을 하지 않는다. 원래 명령의 연결이 곧 확인이다(결정 13). 원격 응답자가 serve 포트에서 아무것도 보지 못했다고 보고했으면(`serve_listening: false`) 양쪽 pin을 쓴 채로 원래 명령이 dial 없이 `CONNECTION_FAILED`(`details.reason: "remote_serve_not_listening"`)로 끝나고 pin은 남는다. 부트스트랩이 다른 오류로 실패하면 그 오류가 곧 명령의 오류이고 원래 명령은 시작하지 않는다.

터미널 순서는 이렇다. 대화형 form은 ssh 자식이 끝나고 pin이 선 뒤에야 raw 모드에 들어간다. ssh가 암호·passphrase·host key 질문을 하는 동안 터미널은 cooked 상태 그대로다(결정 16). `qsh cp`도 ssh가 끝난 뒤에 복사를 시작한다. 부트스트랩 중 Ctrl-C는 ssh를 끝내고 `CANCELED`로 아무것도 쓰지 않으며 원래 명령도 시작하지 않는다. stdin이 터미널이 아니면 ssh에 `BatchMode=yes`가 붙는다(위 "터미널과 `BatchMode`"). 이 분기는 Windows 빌드에도 같다(ADR-0044 결정 25, ADR-0035 결정 1). ssh 자식은 콘솔을 물려받고, 그 사이 입력 핸들은 cooked 모드(줄 편집, 에코, 시스템 Ctrl-C 처리)이며 VT 입력 모드는 ssh가 끝난 뒤 대화형 attach가 켠다. 부트스트랩 중 Ctrl-C는 ssh를 끝내고 `CANCELED`로 끝난다. Windows 장비를 대상으로 하는 자동 부트스트랩도 원격 응답자(`qsh pair ssh-respond`)가 같은 순서로 답하므로 다른 OS와 같이 pin을 세우고 원래 명령(attach, `qsh cp`)이 이어진다. 원격 기본 셸이 `cmd.exe`이고 `qsh.exe`를 찾지 못하면 종료 코드 9009(`remote_qsh_missing`), PowerShell이면 1(`remote_command_failed`와 `qsh.exe` `PATH`·`--remote-qsh` 안내)이다.

**`user@`의 의미.** 원격 셸은 항상 **`qsh serve`를 실행한 OS 계정**으로 실행된다 — MVP에는 user switching이 없고, ACL principal은 항상 인증서에서 나온다(§2.5, protocol.md §3). `user@`는 SSH 근육 기억을 위해 받아들이며 생략해도 된다(`qsh personal-mac`). 지정하면 `SessionOpen`에 선택 hint로 전달되고, 호스트는 그 값이 serve 계정의 login name과 다르면 세션을 만들지 않고 `UNSUPPORTED`(message: user switching is not supported)로 거부한다 — fail closed. 즉 `user@`는 "이 계정이어야 한다"는 단언이지 계정 선택이 아니다(PRD §6). 검사 순서는 **ACL `session.open` → `user` hint → spawn**이다: 인가되지 않은 peer는 hint 값과 무관하게 항상 `PERMISSION_DENIED`를 받고(계정명 비노출, audit는 ACL 판정만 기록), `UNSUPPORTED`는 인가된 peer에게만 반환된다. 비교는 serve 계정의 login name과 정확 일치(case-sensitive)다. `user@`는 `qsh [user@]host` 형태(`-L`/`-R` 플래그를 동반한 경우 포함 — 모두 `SessionOpen`을 보낸다)에서만 받으며, `qsh exec`/`qsh session open`/`qsh tunnel open`은 bare host만 받는다.

**`hosts.toml`의 `user` 기본값.** `user@`를 명시하지 않았고 그 host 이름에 `hosts.toml`이 `user`를 설정해 뒀다면 그 값이 hint로 채워진다 — ssh_config의 `User` directive와 같은 위치의 편의 기능이다. 명시적으로 준 `user@`가 있으면 그것이 항상 이긴다(`hosts.toml`의 값은 덮어쓰지 않는다). 이 기본값 채움은 `qsh [user@]host`뿐 아니라 `qsh session open`을 포함해 `SessionOpen`을 보내는 모든 경로에 동일하게 적용된다 — 위 문단의 검사(ACL → user hint → spawn, 불일치 시 `UNSUPPORTED`)는 hint의 출처가 명시값이든 `hosts.toml` 기본값이든 완전히 동일하게 작동한다.

**`-L`/`-R`은 이 대화형 form의 companion flag이지 별도 명령이 아니다.** `qsh [user@]host -L …`/`-R …`는 여전히 대화형 셸을 여는 `qsh [user@]host` 그 자체이며 — 위 문단대로 `SessionOpen`을 보내고 §4의 exit code 규칙을 그대로 따르는 실제 interactive 세션이 열린다 — 거기에 하나 이상의 터널(§6.9)이 **곁들여** 열릴 뿐이다. `-L`/`-R`이 세션 없이 터널만 여는 경로는 없다: 터널만 필요하고 셸은 필요 없으면 machine-mode `qsh tunnel open --json`(§6.9)을 쓴다 — 이쪽은 `SessionOpen`을 전혀 보내지 않고 `tunnel.open` 하나만 나간다. 두 경로 모두 홀더는 그 명령을 실행한 foreground CLI 프로세스다(§6.14).

**Detach와 escape 시퀀스.** SSH와 같은 방식의 tilde escape를 쓴다. escape 문자는 **행의 시작에서만** 인식되며, 그 외 위치의 `~`는 그대로 원격 PTY로 전달된다. raw mode에는 line discipline이 없으므로 "행의 시작"은 *세션 시작 직후이거나, 클라이언트가 마지막으로 원격에 전달한 byte가 CR(`\r`, 0x0D) 또는 LF(`\n`, 0x0A)인 상태*로 정의한다.

| 입력 | 동작 |
|---|---|
| `~d` | detach — local client만 종료하고 세션은 계속 실행된다 |
| `~.` | detach와 동일 — **세션을 죽이지 않는다.** 세션은 설계상 client보다 오래 산다(PRD §8); 종료는 `qsh session close <session-ref>`(§6.7)로 한다 |
| `~~` | 리터럴 `~` 하나를 전송 |
| `~?` | escape 도움말을 **stderr**에 출력 |

이 표가 전부이며 다른 시퀀스(`~^Z`, `~#`, `~&` 등)는 없다. 행 시작의 escape 문자 1 byte는 다음 byte가 올 때까지 로컬에 보류되고 전달되지 않는다; 표에 없는 두 번째 byte가 오면 escape 문자와 그 byte를 **둘 다 그대로** 원격에 전달하고 상태를 초기화한다(ssh와 동일 — 입력이 조용히 사라지지 않는다). escape 처리는 **local stdin이 TTY일 때만** 활성이다 — pipe/file stdin에서는 `--escape-char`와 무관하게 꺼지고 모든 byte가 그대로 전달된다(`qsh session write` 경로에는 애초에 escape 처리가 없다).

escape 문자는 `--escape-char <c>`로 바꿀 수 있고 `--escape-char none`은 escape 처리를 끈다(그때 detach 수단은 client 프로세스 종료뿐이며 세션은 여전히 유지된다). 기본값은 `~`. `--escape-char`는 `qsh [user@]host`와 `qsh attach`에만 붙는 flag이며 값은 **단일 출력 가능한(printable, 공백·제어문자 제외) ASCII 문자** 또는 `none`이다(그 외는 `INVALID_ARGUMENT`, exit `2`) — 행 시작에서 눈에 보이지 않는 byte가 입력을 삼키는 일이 없도록 하는 제한이다; 설정 파일 기본값은 M2에 없다. escape 시퀀스는 client 로컬에서 소비되고 원격으로 전달되지 않는다.

### 7.1 Value operation과 stream operation

QSH operation은 두 종류로 나뉜다.

- **Value operation**: 단일 요청에 단일 응답을 반환하는 일반 RPC. `session.read`, `session.write`를 비롯해 이 문서 대부분의 command가 여기 속한다.
- **Stream operation**: 하나의 duplex byte channel을 열고 유지하는 operation. `session.attach`가 유일한 stream op이며, resume(`last_sequence` 기반) semantics를 갖는 duplex channel을 반환한다.

`qsh dave@personal-mac`와 `qsh attach <session-ref>` 같은 interactive attach는 내부적으로 이 `session.attach` 하나의 streaming operation 위에 구현된다. `session.read`/`session.write`는 machine-facing value operation으로 별도 존재하며, `--follow --jsonl`(§6.4)도 같은 streaming source에서 값을 공급받는다. attach와 read/write 사이에 별도 business logic은 없다.

`tunnel.open`(§6.9)은 이 분류에서 value operation이다 — envelope은 터널이 열렸다는 사실과 메타데이터(`Tunnel`)만 한 번 반환하고 즉시 끝난다. 터널을 오가는 실제 TCP payload는 JSON envelope 층에 전혀 노출되지 않는 wire-level data 스트림(`TCP_CONNECT`/`TCP_ACCEPTED`, protocol.md §7·§9)이며, `session.attach`와 달리 이 문서의 stream operation 개념에 속하지 않는다 — 이 streaming byte channel은 `qsh-core`가 로컬 TCP 연결과 host 사이에서 직접 splice하고, CLI operation 계층은 그 존재를 모른다.

## 8. MCP server (철회, ADR-0011)

내장 MCP stdio adapter(`qsh mcp`, 이 절의 옛 §8.1-§8.4가 기술하던 tool mapping·지속 출력·보안 경계)는 제거됐다(ADR-0011) — 근거와 대안은 그 ADR을 참고한다. 에이전트 연동 면은 이 문서의 `qsh.cli/v1` JSON/JSONL CLI 하나로 좁혀졌다: §6.4의 long-poll cursor(`--after`/`--ctl-after`, 계약 타입으로는 `SessionReadReq.after_sequence`/`ctl_after`)가 예전 MCP adapter의 `read_session`과 같은 값을 그대로 낸다. 원격 stdio MCP 서버를 계속 띄워야 하면 `qsh exec host -- <server>`로 그 프로세스 자체를 실행한다 — qsh는 다시 순수 transport로 돌아가고 MCP framing은 그 프로세스의 stdio 안에 남는다.

## 9. Timeout과 cancellation

- 모든 blocking machine operation은 `--timeout <milliseconds>`를 지원한다.
- `session read --wait`은 long-poll 대기 시간이며 전체 command timeout과 구분한다.
- SIGINT는 현재 local operation을 취소한다.
- Interactive attach의 SIGINT는 기본적으로 remote PTY로 전달하며, detach는 행 시작의 `~d`(또는 `~.`) escape 시퀀스로 한다(§7, `--escape-char`로 변경·비활성화). detach는 세션을 종료하지 않는다.
- `session read --wait`를 취소해도(로컬 프로세스 종료·SIGINT) session·PTY·writer lease는 그대로 유지된다: 취소는 이 요청의 응답 전달을 끊을 뿐이다. host 내부에 남은 대기는 wait clamp까지 자연 소멸하며, 그 결과는 어느 client에서도 관측되지 않는다.

## 10. Compatibility policy

- `qsh.cli/v1`과 `qsh.event/v1`에는 optional field를 추가할 수 있다. `qsh.event/v1`에는 새 event `type`도 추가할 수 있으며, 소비자는 알 수 없는 `type`을 무시해야 한다(§6.4).
- `file.entry`(`qsh.event/v1`)는 `qsh cp --jsonl`(§6.21)이 항목 하나가 끝날 때마다 쓰는 event다. 세션에 속하지 않으므로 §6.4의 session event 집합에 들지 않고, 필드는 `schema`, `type`, 그리고 `file.copy` `entries[]` 원소의 필드다. session event만 아는 소비자에게는 알 수 없는 `type`이라 무시 대상이다.
- `reason`·`state`·`error.code`처럼 값 집합이 열린 문자열 field에는 새 값을 추가할 수 있다. 소비자는 알 수 없는 값을 오류 없이 처리해야 한다(`ErrorCode` 미지 코드 pass-through와 같은 원칙, §3.3).
- Field 삭제, type 변경과 의미 변경은 `/v2`가 필요하다.
- Deprecated field는 최소 두 minor release 동안 유지한다.
- `qsh schema --json`으로 지원 version과 deprecation을 조회할 수 있어야 한다.
- 숨김 서브커맨드 표기의 수명은 §6.13/§6.11이 정한다.

## 11. 구현 제약

- Human renderer와 JSON renderer는 같은 Rust typed operation을 호출한다.
- Renderer 내부에 인증·ACL·session logic을 구현하지 않는다.
- JSON mode를 test fixture로 사용해 schema compatibility를 검증한다.
- JSONL event는 한 줄에 하나의 완전한 JSON object이며 중간에 plain text를 삽입하지 않는다.
- Streaming backpressure가 remote PTY를 무제한으로 memory에 적재하게 해서는 안 된다.

