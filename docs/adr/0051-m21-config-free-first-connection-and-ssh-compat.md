# ADR-0051: M21의 범위. `qsh host` 한 줄이 SSH로 원격 qsh를 갖추고 필요할 때 뜨는 serve를 띄워 QUIC로 붙으며, `alias ssh=qsh`의 흔한 쓰임새를 같은 뜻으로 받는다

날짜: 2026-11-05
상태: 승인됨 (2026-11-05, 사용자 결정. 범위 승인, `~.`은 "ssh처럼 끝낸다")

개정 관계: ADR-0050 결정 5의 M21을 구체화한다. 다음 결정을 개정한다.
- ADR-0044 결정 14·26(원격에 qsh를 설치하거나 serve를 띄우지 않는다), 결정 13(`remote_serve_not_listening`으로 끝낸다), 결정 2(자동 부트스트랩이 서는 조건)
- ADR-0032 결정 1(`install`은 기본으로 활성화하지 않는다), 결정 16과 "대안과 기각 사유"의 `--system` 기각(상시 기동 레시피를 자동화하지 않는다)
- `docs/CLI.md` §4의 사용법 오류 종료 코드(루트 ssh 형식에 한해)와 §7의 `user@` 의미

ADR-0017·0025(`acl.toml`은 손으로 쓰고 다시 읽지 않는다)는 개정하지 않는다. 세밀한 권한의 CLI 경로는 `trust.toml`에 둔다(결정 8). ADR-0015(listener 코드 pairing)도 다시 열지 않는다.

## 맥락

ADR-0050은 P2의 세 원칙을 정했다. 설정 파일 손편집 없는 기본, 대화형 질문과 같은 답의 플래그, `alias ssh=qsh` 호환이다. 지금 qsh가 이 원칙에서 벗어나는 곳은 네 갈래다(2026-11-05 코드·문서 조사).

1. **원격 준비.** ADR-0044의 SSH 부트스트랩은 pin만 세운다. 원격에 qsh가 없으면 `remote_qsh_missing`, serve가 떠 있지 않으면 `remote_serve_not_listening`으로 끝나고, 사람이 원격에 들어가 설치하고 `qsh serve`나 `qsh service install --activate`를 따로 돌려야 한다. mosh는 같은 자리에서 SSH로 `mosh-server`를 띄우고 끝낸다.
2. **SSH 문법.** 통하는 것은 `qsh [user@]host`, `-L`/`-R`/`-D`, `-v`, `-q`뿐이다. `qsh host cmd`는 clap 사용법 오류(종료 2)이고 `qsh exec host -- argv`로 써야 하며, 그 argv는 셸을 거치지 않는다. `-l -p -i -o -F -t -T -N -f -4 -6 -C`이 없고, `~/.ssh/config`는 부트스트랩의 `ssh -G` 한 번에만 쓰인다. 하위 명령 이름(`host`, `hosts`, `setup`, `audit` 등)은 같은 이름의 호스트를 가린다.
3. **상시 serve.** `service install`은 유닛 파일만 쓰고 `--activate`를 붙여야 켜진다. 로그인 밖에서 살리는 일(linger, LaunchDaemon, `Password` 작업)은 문서 레시피를 사람이 손으로 따른다. `serve --to`의 `--bind`와 `--to`는 유닛 argv에 들어가지 않아 `config.toml`을 손으로 고쳐야 한다. qsh에는 설정 키를 쓰는 명령이 없다.
4. **권한과 재페어링.** 역할(ADR-0045)보다 세밀한 권한은 `acl.toml` 손편집과 serve 재시작이 필요하다. 원격을 다시 설치해 키가 바뀌면 `pin_conflict`나 `SESSION_CONFLICT`로 막히고, 고치는 길은 `trust remove`뿐이다(threat model h7).

## 결정

### 첫 접속: SSH 부트스트랩이 원격을 갖춘다

1. **흐름.** pin이 없는 이름으로 `qsh [user@]host`(명령, `-L`/`-R`/`-D`, `qsh cp` 포함)를 부르면 다음 순서로 간다. 바뀌는 곳은 ③·④·⑤다.
   1. `ssh -G`로 대상을 푼다(ADR-0044 결정 4 그대로).
   2. 이 장비에 identity가 없으면 만든다(ADR-0044 결정 18 그대로).
   3. 원격 qsh를 찾는다. 없으면 결정 3대로 설치를 묻는다.
   4. 원격 응답자가 pin을 세우고, 같은 사용자의 serve가 없으면 결정 2의 필요할 때 뜨는 serve를 띄운 뒤 실제로 묶인 주소를 알린다.
   5. 이 장비가 pin과 주소를 쓰고 ssh를 닫은 뒤 QUIC로 붙는다.

   묻는 것은 ③의 설치 하나다. 원격 pin의 역할은 ADR-0044대로 `full`이다(ssh 로그인이 곧 그 계정의 셸 권한이므로).

2. **필요할 때 뜨는 serve(on-demand serve).**
   - 응답자가 `qsh serve --on-demand`(숨김 플래그)를 세션에서 떼어 띄운다. unix는 `setsid`와 이중 fork에 표준 입출력을 닫고, Windows는 결정 2의 마지막 항목을 따른다.
   - 이 serve는 세션(떼어 둔 세션 포함)이나 연결이 하나라도 있는 동안 산다. 마지막 세션이 끝나고 연결이 없는 채로 `on_demand_idle`(기본 10분)이 지나면 SIGTERM drain과 같은 절차로 끝난다. 떠서 아무도 붙지 않은 경우도 같다. 상시 유닛으로 뜬 serve는 이 규칙을 따르지 않는다.
   - 같은 사용자의 serve가 이미 떠 있으면 새로 띄우지 않는다. 판정은 `state_dir/serve.json`(pid, 묶은 주소, 모드, 시작 시각. 0600, `FileLock`)으로 하고, UDP bind 시험(ADR-0044 결정 10)은 이 파일이 없을 때의 보조다.
   - 포트는 `[serve].bind`의 포트(기본 4433)를 먼저 쓴다. 다른 계정이 쥐고 있으면 60001~60999 가운데 빈 포트를 쓴다. mosh와 같은 범위라 방화벽 규칙을 같이 쓸 수 있다. 실제 주소는 `result` 줄에 싣고 이 장비의 pin 주소가 된다.
   - **로그아웃에서 살아남기.** macOS는 세션에서 떼어 낸 자식을 sshd가 거두지 않는다. Linux는 logind `KillUserProcesses=yes`이고 linger가 꺼진 계정이면 ssh 세션이 끝날 때 serve도 죽는다. 이 경우 응답자가 알아채 `result`에 `serve_session_scoped: true`를 싣고, 이 장비는 "원격 serve가 ssh 세션과 함께 끝난다. 세션을 남기려면 원격에서 `qsh service install --always-on`" 한 줄을 stderr에 낸다. 연결 자체는 그대로 진행한다. Windows OpenSSH는 세션 자식을 kill-on-close Job Object에 넣고 그 Job은 breakaway를 허용하므로(개정 이력 2026-11-05 측정), 응답자는 `CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`으로 serve를 띄운다. breakaway가 거부되는 sshd(Job에 `BREAKAWAY_OK`가 없음)면 Linux와 같은 경고를 낸다. 세 OS가 같은 결과(ssh 세션이 끝나도 serve가 남음)를 내는 것이 DoD이고, 측정 결과는 ADR 개정으로 남긴다.

3. **원격 qsh 설치(동의 필요).**
   - 원격 qsh가 없으면(`remote_qsh_missing`) TTY에서 묻는다. "host에 qsh가 없다. qsh vX.Y.Z를 `~/.local/bin`에 설치할까? [Y/n]". 같은 답을 주는 플래그는 `--install-remote`, `--no-install-remote`다. TTY가 아니거나 `--json`/`--jsonl`이면 묻지 않고 지금처럼 `remote_qsh_missing`으로 끝난다(플래그를 주면 설치).
   - 설치하는 버전은 이 장비의 qsh와 같은 태그다. 원격 OS·아키텍처는 같은 ssh 연결에서 `uname -sm`(Windows는 `cmd /c ver`와 `PROCESSOR_ARCHITECTURE`)으로 알아낸다.
   - 경로는 둘이고 이 순서로 시도한다. (가) 원격이 그 태그의 `install.sh`/`install.ps1`을 받아 돌린다(`QSH_VERSION` 고정, `SHA256SUMS` 검사, 가능하면 provenance 검사. 기존 설치기 그대로). (나) 원격이 GitHub에 닿지 않으면 이 장비가 해당 자산을 받아 `SHA256SUMS`와 `gh attestation`으로 확인한 뒤 ssh 표준입력으로 보낸다. 원격은 임시 파일에 받아 sha256을 다시 맞춘 뒤 원자적으로 옮긴다.
   - sudo는 쓰지 않는다. 설치 위치는 사용자 홈이고, 설치 뒤 응답자는 절대 경로로 부른다(비대화형 셸의 PATH 문제를 피한다). 그 경로는 pin의 `remote_qsh`에 적어 다음 부트스트랩이 쓴다.
   - 원격 qsh가 이 장비보다 낮은 버전이면(`remote_qsh_too_old`) 같은 질문으로 업그레이드를 묻는다. 이미 떠 있는 serve는 건드리지 않는다. 새 바이너리는 그 serve가 다음에 뜰 때 쓰인다.

4. **재접속 때의 되살리기.** pin이 있는 이름으로 붙다가 연결이 실패하고(`CONNECTION_FAILED`, `TIMEOUT`, `udp_egress_blocked`가 아닌 무응답) 그 pin이 SSH 부트스트랩으로 세운 것이면, ssh로 다시 들어가 serve만 되살린다(pin은 그대로 확인만 한다). 묶인 주소가 바뀌었으면 pin 주소를 고친다. 이 단계에는 질문이 없다. `--json`/`--jsonl`에서도 돌고(ssh가 BatchMode로 돈다), `--no-ssh`나 `[ssh].bootstrap = "off"`로 끈다. mosh의 "매번 ssh로 서버를 띄운다"를 실패할 때만 하는 셈이다.

5. **원격 pin 교체.** 원격을 다시 설치해 원격 키가 바뀌었거나 이 장비 키가 바뀌어 pin이 어긋나면, TTY에서 옛 fingerprint와 새 fingerprint를 함께 보여 주고 "pin을 바꿀까? [y/N]"를 묻는다. 기본은 아니오다. 플래그는 `--replace-pin`이다. 바꾸는 근거는 ssh 로그인과 ssh host key 검증이다(threat model A16과 같은 신뢰). 원격 쪽 응답자도 같은 커밋 메시지에 `replace: true`가 오면 그 장비의 옛 pin을 지우고 새 pin을 쓴다. 두 쪽 모두 감사 기록을 저장 전에 남긴다(B21 규율). h7은 SSH 경로에서 닫힌다. 초대 코드 경로(ADR-0002)는 바뀌지 않는다.

### SSH 명령 호환

6. **문법.** 루트 명령은 `qsh [ssh 옵션] [user@]host [command [arg...]]`다.
   - **명령이 붙으면** ssh처럼 인자를 공백으로 이어 한 문자열로 만들고 원격 계정의 로그인 셸에 `-c`로 넘긴다(Windows는 기본 셸 규칙, OpenSSH와 같음). exec 열기 메시지에 선택 필드 `shell_command`를 더한다(wire additive, `docs/design/protocol.md` §16.4). `qsh exec host -- argv`의 셸 없는 argv 의미는 그대로다.
   - **PTY.** 명령이 없으면 PTY 세션, 있으면 PTY 없는 exec가 기본이다. `-t`는 명령에 PTY를 주어 떼어 둘 수 있는 세션으로 연다. `-T`는 명령이 없을 때 로그인 셸을 PTY 없이 연다. `-tt`는 ssh처럼 TTY가 아닐 때도 PTY를 강제한다.
   - **이름 충돌.** 첫 위치 인자가 하위 명령 이름이면 하위 명령으로 읽는다. 같은 이름의 호스트는 `user@host`, `-l user host`, `qsh -- host`, `~/.ssh/config` 별칭 가운데 하나로 부른다. 하위 명령을 더 만들 때는 흔한 호스트 이름과 겹치지 않게 고른다. `xtask`의 이름 목록 테스트가 이를 고정한다.

7. **옵션.** 원칙은 **ssh 옵션은 ssh 경로를 설명한다**이다. `alias ssh=qsh`에서 `-p 2222`는 sshd의 포트이고 qsh의 UDP 포트가 아니다. qsh는 자기 경로(UDP 주소)를 부트스트랩에서 알아내 pin에 적는다.

   | 옵션 | 뜻 |
   |---|---|
   | `-l user`, `-p port`, `-i file`, `-F file`, `-o Key=Val`, `-C`, `-4`/`-6`의 ssh 쪽 | 부트스트랩과 되살리기 때의 ssh 명령줄에 그대로 넘긴다. ssh가 모르는 키는 ssh가 거부한다 |
   | `-4`/`-6` | QUIC 쪽에서도 주소 family를 거른다 |
   | `-o`의 `ConnectTimeout`, `BatchMode`, `ServerAliveInterval`, `ServerAliveCountMax` | QUIC 쪽에도 같은 뜻으로 적용한다(연결 시한, 질문 금지, keep-alive, 끊김 판정) |
   | `-o ProxyJump`, `-J` | 부트스트랩 ssh에는 넘긴다. QUIC 경로의 점프는 M26 전까지 `UNSUPPORTED`이고, ssh로만 닿는 host는 결정 4의 되살리기도 같은 점프로 간다 |
   | `-A` | M25 전까지 `UNSUPPORTED` |
   | `-N` | 셸 없이 `-L`/`-R`/`-D`만 연다(`qsh tunnel open`과 같은 동작) |
   | `-f` | 인증과 forward가 서면 배경으로 간다. unix는 fork, Windows는 떼어 낸 자식 재실행. 배경 프로세스의 진단은 `-E`가 없으면 버린다 |
   | `-E file` | 진단 로그를 파일로 보낸다 |
   | `-e char` | `--escape-char`의 짧은 이름 |
   | `-X`, `-Y`, `-W`, `-M`, `-S`, `-O`, `-w`, `-b`, `-B`, `-c`, `-m`, `-Q` | 이름을 대고 거부한다(`UNSUPPORTED`, 종료 255). `-W`는 ADR-0011대로 기각 |

   `-l`과 `user@`는 이제 원격 **계정을 고른다**. on-demand serve는 그 ssh 계정으로 뜨기 때문이다. 상시 serve가 다른 계정으로 떠 있는 host에 다른 `user@`로 붙으면, 지금은 `UNSUPPORTED`로 끝나지만 앞으로는 결정 2의 포트 규칙대로 그 계정의 on-demand serve를 띄운다. 계정마다 serve가 따로 뜨고, pin도 `user@host`마다 따로 선다.

8. **`~/.ssh/config`.** 이름 해석은 qsh pin과 `hosts.toml`을 먼저 보고, 없으면 `ssh -G`가 푼 `HostName`·`User`·`Port`·`ProxyJump`로 부트스트랩한다(지금과 같다). pin 이름은 입력한 별칭이다(ADR-0044 결정 7). qsh가 `ssh_config`를 직접 파싱하지 않는 결정(ADR-0044 결정 4)은 유지한다. ssh가 없으면 pin이 있는 이름만 쓸 수 있다.

9. **종료 상태와 escape.**
   - 원격 종료 코드 0~254는 그대로, qsh 자신의 실패는 255(지금과 같다). 루트 ssh 형식의 사용법 오류도 ssh처럼 255로 끝낸다. 하위 명령의 사용법 오류는 2 그대로다(`docs/CLI.md` §4 개정).
   - `~.`은 ssh처럼 **연결을 끊고 원격 셸을 끝낸다**. 떼어 두고 나가는 것은 `~d`다. 지금 `~.`이 하는 떼어 두기는 세션이 쌓이는 원인이 되고, `alias ssh=qsh` 사용자의 손버릇과 뜻이 다르다. `~^Z`(일시 정지)와 `~#`(forward 목록), `~&`(배경으로)는 더한다. `~C`·`~R`은 거부 메시지와 함께 넘긴다.

### 설정 없는 운영

10. **`qsh config get|set|unset|list`.** `config.toml`의 모든 키에 CLI 경로를 둔다. 주석과 순서를 보존하는 편집(`toml_edit`)을 `config.toml.lock` `FileLock` 아래에서 하고, 쓰기 전에 같은 검증(`Config::load`의 범위 검사)을 통과해야 저장한다. 시작할 때만 읽는 키를 바꾸면 "다음 시작부터 적용" 한 줄을 낸다. 로컬 op이고 권한 검사 대상이 아니다(`docs/CLI.md` §2.5). 새 설정 키는 이 명령으로 쓸 수 있어야 한다는 것을 테스트가 고정한다.

11. **`service install`.**
    - 기본으로 활성화한다. 이미 켜진 유닛은 다시 시작하지 않는다(ADR-0032 결정 4 유지). ADR-0032가 활성화를 기본으로 두지 않은 이유는 "새로고침이 세션을 지운다"였는데, 켜진 유닛을 다시 시작하지 않는 결정 4가 있으므로 기본 활성화로 지워지는 세션은 없다. `--no-activate`가 파일만 쓰는 옛 동작이고, `--activate`는 숨김 alias로 남긴다.
    - `--to`, `--bind`, `--name`을 받는다. 값은 유닛 argv가 아니라 결정 10의 경로로 `config.toml`에 쓴다(유닛 argv 고정, ADR-0032 유지). 모드 추론(`infer_run_mode`)도 그대로다.
    - `--always-on`은 로그인 밖 기동을 OS의 동의 절차로 켠다. Linux는 `loginctl enable-linger`(polkit이 묻는다), macOS는 `sudo`로 LaunchDaemon 레시피, Windows는 관리자 콘솔에서 `schtasks /RU <계정> /RP *`로 `Password` 작업을 등록한다(암호는 schtasks가 직접 묻고 qsh는 보지 않는다). 관리자 콘솔이 아니면 그 사실과 다시 돌릴 명령을 낸다. 키가 `platform` 저장소에 있어 로그인 밖에서 열리지 않는 OS(macOS, Linux)면 먼저 "키를 파일 저장소로 옮길까? [Y/n]"를 묻는다(플래그 `--move-key`). 해제는 `service uninstall --always-on`이다. 레시피는 `docs/deploy/service.md`의 것과 같은 바이트를 쓰고, 문서 fence 대조 테스트가 이를 고정한다. ADR-0032 결정 16("자동화하지 않는다")을 개정한다.

12. **세밀한 권한은 `trust.toml`로.** `qsh trust allow <name> <action>... [--path <glob>...] [--scope any]`와 `qsh trust deny <name> <action>...`이 pin 항목의 `grants`·`paths`·`scope` 키를 쓴다. 판정은 role 단계 바로 뒤, `acl.toml` 행 앞의 "pin grant 단계"다. `trust.toml`은 이미 잠금, 감사 후 저장, 1초 다시 읽기, 권한 축소 때 연결 닫기(ADR-0031)를 갖고 있어 serve를 다시 시작할 필요가 없다. 행동 어휘는 `Action::ALL`, `forward.socks`는 줄 수 없다(항상 거부 게이트 유지). CA 인증 peer와 이름이 다시 pin된 peer는 옛 grant를 쓸 수 없다(B16·B17과 같은 규칙). `acl.toml`은 손으로 쓰는 파일로 남고 ADR-0017·0025는 그대로다.

### 질문과 플래그

13. 이 마일스톤이 더하는 질문은 아래가 전부다. 질문은 `qsh-core`의 한 레지스트리에 이름을 올리고, 테스트가 질문마다 플래그가 있음과 `--json`/`--jsonl`·비TTY에서 질문이 나오지 않음을 고정한다.

    | 질문 | 플래그 | 비대화형 기본 |
    |---|---|---|
    | 원격에 qsh 설치 | `--install-remote` / `--no-install-remote` | 설치 안 함 |
    | 원격 qsh 업그레이드 | `--install-remote` | 안 함, `remote_qsh_too_old` |
    | pin 교체 | `--replace-pin` | 안 함, `pin_conflict` |
    | always-on 전에 키 옮기기 | `--move-key` | 안 함, `keystore_session_bound` 오류 |

    ssh 자신의 질문(암호, passphrase, host key)은 ssh가 터미널에서 직접 묻는다(ADR-0044 결정 16 그대로).

### 계약과 wire

14. 모두 additive다.
    - 부트스트랩 줄(`docs/design/protocol.md` §17): `hello`에 `on_demand: true`(응답자 능력), `commit`에 `ensure_serve`, `replace`, `result`에 `serve_bind`(실제 주소), `serve_started`, `serve_session_scoped`. 새 필드를 모르는 옛 응답자에게는 보내지 않는다(§17.3).
    - exec 열기: `shell_command`(결정 6). 옛 host는 `UNSUPPORTED`로 답하고 이 장비는 "원격 qsh가 오래돼 셸 명령을 못 받는다, `--install-remote`" 를 낸다.
    - `qsh.cli/v1`: 새 op `config.get`·`config.set`·`config.unset`·`config.list`·`trust.allow`·`trust.deny`, `service.install`의 `always_on` 필드, `pair.ssh`의 `installed`·`serve_started` 필드. 기존 fixture는 고치지 않고 새 fixture를 더한다. 기본 활성화로 `service.install`의 출력에 `activation`이 늘 실리는 것도 additive다.
    - 새 오류 코드는 없다. 새 `details.reason`은 `serve_session_scoped`, `remote_install_failed`, `remote_arch_unsupported`다.

### 수용 기준(M21 DoD)

15. 1. **설정 없는 첫 접속.** qsh가 없는 깨끗한 Linux, macOS, Windows host에 ssh만 되는 상태에서, 깨끗한 client가 `qsh host` 한 줄과 설치 질문 하나로 셸에 닿는다. 어느 쪽에서도 설정 파일을 열지 않는다. 자동 테스트(테스트킷의 가짜 ssh와 로컬 설치 자산)가 세 OS CI에서 이 흐름을 돌린다.
    2. **로그아웃 뒤 생존과 되살리기.** ssh 세션이 끝난 뒤에도 on-demand serve와 떼어 둔 세션이 남고, idle 시한 뒤 serve가 끝난 다음 `qsh host`가 질문 없이 되살려 붙는다. Linux·macOS는 CI, Windows는 결정 2의 측정을 실장비에서 한 번 기록한다.
    3. **`alias ssh=qsh` 표.** 결정 6~9의 표를 한 줄씩 테스트로 고정한다(argv → ssh 명령줄·QUIC 동작·종료 코드). `ssh_golden`의 대조 방식을 넓힌다.
    4. **설정 없는 운영.** `qsh config set`으로 쓴 값이 `qsh doctor`의 `config_unknown_key` 없이 읽히고, `service install`이 기본으로 켜고, `--always-on`이 세 OS에서 레시피와 같은 바이트를 낸다(레시피 실행 자체는 사람 회차 하나로 기록).
    5. **권한.** `trust allow`가 serve 재시작 없이 다음 요청에 적용되고, `trust deny`가 열린 연결을 닫는다. 판정 엔진 대조 테스트(B7)에 grant 단계를 더한다.
    6. **질문 레지스트리 테스트**가 결정 13을 고정한다.
    7. threat model에 아래 결과 절의 행이 고정 테스트와 함께 들어간다.

## 근거

- **mosh의 방식이 맞다.** 사람이 원격에 들어가 서비스를 등록하는 단계가 "새 SSH"로 받아들여지는 데 가장 큰 마찰이다. mosh는 ssh 로그인 하나를 신뢰 근거로 삼아 서버를 띄우고, 그래서 설정이 없다. qsh는 이미 같은 근거로 pin을 세운다(ADR-0044, A16). 같은 연결에서 serve까지 띄우는 것은 신뢰 경계를 넓히지 않는다. ssh 로그인이 이미 그 계정의 셸이다.
- **세션 보존을 놓치지 않는다.** mosh 서버는 클라이언트 하나에 묶여 끝나면 사라진다. qsh의 on-demand serve는 떼어 둔 세션이 남는 동안 살고 여러 장비가 붙을 수 있으므로, qsh의 고유 가치(연결과 세션 수명 분리)를 그대로 지닌다.
- **ssh 옵션을 ssh 경로에 적용하는 규칙**이 두 의미 체계를 한 줄로 화해시킨다. `-p`, `-l`, `-i`, `-o`가 사용자가 기대한 그 sshd에 정확히 가고, QUIC 주소는 사용자가 몰라도 된다.
- **`~.`의 뜻을 맞춘다.** ADR-0050 결정 2가 "같은 글자가 다른 뜻이던 곳은 SSH 쪽 뜻으로" 정했다. 떼어 두기는 `~d`로 남아 기능을 잃지 않는다.
- **`trust.toml`에 grant를 두는 이유.** `acl.toml` 쓰기가 기각된 이유(잠금 없음, 손으로 연 편집기와의 경합, 재시작 전 무반영)는 `trust.toml`에 해당하지 않는다. ADR-0045가 role을 같은 이유로 거기 두었다.
- **기본 활성화가 안전한 이유**는 결정 11에 적었다. 위험했던 것은 재시작이고, 재시작은 여전히 하지 않는다.

## 대안과 기각 사유

- **원격 설치를 하지 않고 안내만 한다(ADR-0044 결정 14 유지).** 원칙 1(설정 없는 기본)을 어긴다. 동의를 묻는 질문 하나와 고정 버전·체크섬 검사로 위험을 줄인다. 기각.
- **이 장비의 바이너리를 그대로 원격에 복사한다.** OS·아키텍처가 같을 때만 되고, provenance 확인 경로가 없다. (나) 경로로 받은 릴리스 자산을 보내는 것으로 대신한다. 기각.
- **mosh처럼 접속마다 ssh로 serve를 띄운다.** 매번 ssh 왕복(암호·2FA 포함)이 붙고, ssh가 막혀 있고 QUIC만 열린 경로를 못 쓴다. 실패할 때만 되살린다(결정 4). 기각.
- **`qsh ssh` 하위 명령으로 호환 모드를 분리한다.** ADR-0050이 기각했다.
- **`acl.toml`을 CLI로 쓴다.** ADR-0017·0025를 다시 열어야 하고 손편집 파일과의 경합이 남는다. 결정 12로 대신한다. 기각.
- **`~.`을 떼어 두기로 유지한다.** `alias ssh=qsh`에서 뜻이 다르고, 지운 줄 안 세션이 남는다. 기각.
- **on-demand serve를 OS 서비스 매니저로 띄운다(`systemd-run --user`, launchd 일회성 작업).** Linux에서 linger 없이는 같은 문제로 죽고 OS마다 방식이 갈린다. 떼어 낸 자식을 기본으로 하고, Windows만 측정 결과에 따라 작업 스케줄러를 쓴다. 기각.

## 결과

- 개정: ADR-0044(결정 2·13·14·26), ADR-0032(결정 1·16, `--system` 기각 절), `docs/CLI.md` §4·§6.11·§6.18·§7, `docs/design/protocol.md` §17, `docs/deploy/service.md`, PRD §7의 해당 줄은 ADR-0050이 이미 바꿨다.
- 새 threat model 행:
  - 원격 설치 무결성: 고정 태그, `SHA256SUMS`, (나) 경로의 provenance 확인과 원격 재확인. ssh host key 검증에 기댄다(A16과 같은 근거).
  - on-demand serve 노출: 원격 계정이 동의 없이 UDP 포트를 연다는 점. 설치 질문에 "serve를 띄운다"를 함께 적고, idle 종료로 노출 시간을 줄인다. 포트 범위 60001~60999의 다른 서비스와 충돌하지 않는다.
  - pin 교체: ssh 경로에서만, TTY 확인이나 명시 플래그로만, 감사 후 저장. 조용한 교체는 없다(A7, A12 유지).
  - pin grant: role과 같은 B16·B17·B21 규칙, `forward.socks` 금지.
  - `config set`: 로컬 op, 권한 검사 대상 아님(B13). 원격 파일 쓰기는 여전히 qsh 설정 경로에 닿지 않는다(B22).
- 남는 위험: logind가 사용자 프로세스를 죽이는 Linux에서 always-on 없이 쓰면 ssh 세션과 함께 serve가 끝난다(경고로 알림). Windows의 첫 on-demand serve는 Defender 방화벽 허용 질문을 볼 데스크톱 세션이 없을 수 있다. 이때 `udp_egress_blocked`의 remedy가 `qsh service install --always-on`(관리자 콘솔에서 방화벽 규칙도 만든다)을 가리킨다.
- 크기: ADR-0050의 4ew보다 크다. 추정 5ew로 고친다. 스텝 순서는 측정(Windows sshd Job Object, logind) → `config` 명령 → SSH 문법과 옵션 표 → `shell_command` → on-demand serve와 `serve.json` → 부트스트랩의 serve 띄우기·되살리기 → 원격 설치 → pin 교체 → `service install` 기본 활성화와 `--always-on` → `trust allow` → 문서·man·threat model 순이다.

## 개정 이력

- 2026-11-05 (결정 2 측정, 에이전트). 세션에서 떼어 낸 자식이 ssh 세션 끝을 견디는지 쟀다.
  - macOS 27.2(Dave-MBP16, sshd): fork 뒤 `setsid()`한 자식이 ssh 종료 뒤에도 부모 1로 남았다. macOS에는 `setsid` 명령이 없으므로 qsh는 libc 호출로 한다.
  - Windows 11 Pro 25H2(Dave-Windows, Win32-OpenSSH): ssh 세션의 프로세스는 Job 안에 있고 제한 플래그가 `0x2800`(`KILL_ON_JOB_CLOSE`와 `BREAKAWAY_OK`)이다. `Start-Process`로 띄운 자식과 `Win32_Process.Create`로 띄운 자식은 ssh가 끝나자 사라졌다. `CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`으로 띄운 자식은 ssh 종료 뒤 1분 넘게 세션 0(Services)에 남았다. 결정 2의 Windows 경로를 breakaway로 고정하고 작업 스케줄러 대안을 뺐다.
  - Linux(Dave-Windows-WSL, Ubuntu 24.04, systemd 255): `KillUserProcesses`가 배포판 기본값 `no`이고, 이 계정은 linger가 켜져 있다. `KillUserProcesses=yes` 배포판의 판정(`loginctl show-user -p KillUserProcesses -p Linger`)과 경고는 결정 2대로 두고, CI는 기본값 경로를 본다.
