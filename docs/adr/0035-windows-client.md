# ADR-0035: Windows client는 직접 연결 client 명령과 콘솔 raw 모드 대화형 attach까지 연다. host 역할과 localctl 대체는 열지 않는다

날짜: 2026-10-11
상태: 제안됨

개정 관계: 새 ADR이다. `docs/ROADMAP.md` M19(§5)가 이 번호를 Windows client 착수 ADR로 예약했다. 다른 ADR의 결정을 뒤집지 않는다. ADR-0007(resume token custody)에는 "Windows에서 `resume.json`의 기밀성"이라는 빈칸을 채우는 구현을 더한다. ADR-0043(TCP fallback 철회)로 transport는 QUIC 하나이므로 Windows 방화벽·프록시 환경을 위한 우회 경로는 이 ADR의 범위가 아니다. 계약 문서로는 `docs/CLI.md` §4·§6.9·§6.13·§6.17·§7에 Windows 문장을 더하고 `docs/design/architecture.md` §7·§8, `docs/design/threat-model.md` §3·§4, README Known limitations와 `docs/ROADMAP.md` §3 가드레일 표의 Windows 행을 고친다.

## 맥락

`docs/PRD.md` §7은 Windows client를 P1, Windows host를 P2에 둔다. 오늘 Windows 빌드는 CI에서 컴파일되고 portable 테스트를 도는 수준이다(`ci.yml`의 `test`·`clippy` Windows leg, `release.yml`의 `x86_64-pc-windows-msvc` zip). 지원 약속은 아니다. 실제로 Windows에서 되는 것과 안 되는 것은 이렇다.

- `exec`, `trust`, `identity`, `tunnel open`(`-L`/`-R`/`-D`), `session` value op는 터미널이나 UDS에 기대지 않아 그대로 돈다. `release_smoke`의 `#[cfg(not(unix))]` 쌍둥이가 `init` → `trust` → `exec --json` 왕복까지 본다.
- 대화형 attach(`tui::run`)는 `#[cfg(not(unix))]`에서 `UNSUPPORTED`다. raw 모드는 `nix` termios, 크기는 `TIOCGWINSZ`, resize는 `SIGWINCH`라서 `crates/qsh-cli/src/tui/term.rs`와 `tui/unix.rs`가 통째로 unix 전용이다. `docs/design/architecture.md` §8은 crossterm을 "TUI는 키를 파싱하지 않고 raw byte를 흘려야 한다"는 이유로 채택하지 않았고, 그 이유는 Windows에서도 그대로다.
- localctl(UDS)은 `localctl/` 모듈 트리 전체가 Windows에서 컴파일되지 않는다. 그래서 `qsh listen`/`qsh serve --to`는 `UNSUPPORTED`(`docs/CLI.md` §6.13)이고, `qsh hosts`는 forward host만 낸다. 터널은 열린 프로세스에만 산다(`docs/CLI.md` §6.14).
- 키·상태 파일의 권한이 없다. `ensure_private_dir_io`와 `write_private_file_io`는 `cfg(not(unix))`에서 `create_dir_all`과 모드 없는 임시 파일 + rename(`fsutil::write_atomically`)으로 떨어져, 파일은 상위 디렉터리의 상속 ACL을 받는다. `crates/qsh-core/src/resume.rs` 모듈 doc은 이 상태를 적고 `resume.json`의 기밀성을 Windows client P1의 일부로 둔다.
- keystore는 Windows에서 stub이다. 모든 연산이 `KeyStoreError::Unavailable`을 내므로 `auto`는 파일 모드로 떨어진다(`identity/keystore.rs`). 파일 모드의 개인키는 위 상속 ACL에 놓인다.
- 초대 코드를 터미널에서 받는 프롬프트는 에코 억제가 없어 `UNSUPPORTED`다(`NO_TERMINAL_ECHO_SUPPRESSION`).
- Windows host(ConPTY 백엔드)는 PTY 백엔드(`pty/posix.rs`)가 `#[cfg(unix)]`이고 `pty::factory()`가 비unix에서 `UnsupportedFactory`를 돌려줘서 없고 P2다. `qsh serve`는 Windows에서 뜨지만 PTY 세션을 열 수 없고 `exec`와 터널만 낸다.

`docs/ROADMAP.md` §5.4 위험 5는 비교 표본이 없는 Windows 산정을 "ADR이 명령 집합을 좁히고 첫 스텝 뒤 다시 매긴다"로 다루기로 했다. 이 ADR의 중심 결정은 좁히는 선이다. 설계를 가르는 사실은 셋이다.

- 대화형 attach가 이 마일스톤의 가치 대부분이다. 나머지 명령은 이미 돌고, 모자란 것은 기밀성과 콘솔이다.
- Windows에는 host가 없으므로 Windows 러너 안에서 대화형 attach를 끝까지 돌릴 상대가 없다. 대화형 종단 확인은 사람 캠페인(`docs/ROADMAP.md` §5.5)이 맡고, CI는 콘솔 계층을 따로 고정해야 한다.
- localctl 대체(named pipe)는 소비자가 `qsh hosts`의 reverse 항목, reverse route attach·exec, `qsh tunnels`의 데몬 항목뿐이다. 전부 Windows에서 데몬이 없으면 비어 있는 목록이다. 생산자(`qsh listen`)가 P2라 소비자만 열어도 쓸 곳이 없다.

## 결정

### A. 명령 집합

1. Windows client가 여는 명령은 다음이다. 전부 직접 연결(direct route)만 쓴다.
   - `qsh init`, `qsh identity export`, `qsh trust add|add-ca|list|rename|remove`, `qsh trust ssh-preview`
   - `qsh pair accept`(초대 코드는 인자 또는 `--code-stdin`의 파이프·파일 입력, 결정 11)
   - `qsh exec`
   - `qsh session open|get|read|write|resize|close`, `qsh sessions`, `qsh tunnels`, `qsh tunnel close`와 대화형 `qsh [user@]host`, `qsh attach <session-ref>`(결정 5~8)
   - `qsh tunnel open --local|--remote|--dynamic`과 대화형 `-L`/`-R`/`-D`(터널을 연 프로세스가 holder인 모델 그대로)
   - `qsh doctor`, `qsh setup client`, `qsh acl check`, `qsh acl show`, `qsh hosts`, `qsh host`, `qsh schema|capabilities|version`
2. 열지 않는 명령은 리소스를 만들기 전에 `UNSUPPORTED`와 exit `255`로 끝난다. 대상은 아래 명령이다.
   - `qsh listen`, `qsh serve --to`, 숨김 alias `qsh reverse`(오늘 동작 그대로)
   - `qsh service install|uninstall|status`(M9가 고정한 동작 그대로)
   - `qsh pair invite`와 `qsh setup host|listener`(상환 창구를 여는 host 쪽 명령이라 host 역할과 함께 P2)
   - 인바운드 `qsh serve`는 Windows에서 막지 않는다. 오늘처럼 뜨되 PTY 세션 요청에는 `UNSUPPORTED`로 답하고 `exec`와 터널만 낸다. 지원 약속은 아니며 테스트 상대(`release_smoke`, 결정 13)로만 쓴다. README는 이 사실을 "host 역할은 P2이며 이 모양은 지원 범위가 아니다"로 적는다.
3. 위 두 목록을 테스트가 고정한다. `crates/qsh-cli/tests/exit_code_matrix.rs`에 `cfg(windows)` 행을 더해 2번의 각 명령이 `UNSUPPORTED`/exit `255`로 끝나고 상태 디렉터리에 아무것도 만들지 않음을 단언한다. 열린 명령의 동작은 기존 테스트가 Windows leg에서 돈다. `cfg(unix)`로 빠져 있던 테스트 중 POSIX 신호·process-group이 아닌 이유로 빠진 것은 이 마일스톤에서 `cfg(windows)` 쌍둥이를 갖거나 빠진 이유를 주석으로 남긴다.

### B. 콘솔과 대화형 attach

4. Windows 콘솔 제어는 `windows-sys`의 Win32 콘솔 API를 `qsh-cli`의 `tui/`에 직접 쓴다. crossterm은 채택하지 않는다(`docs/design/architecture.md` §8의 이유 유지). `qsh-core`는 콘솔을 모른다. 대화형 루프는 `tui/unix.rs`에서 플랫폼 중립 부분(escape 처리, 이벤트 루프, 스레드 구성, 종료 코드 매핑)을 꺼내 작은 터미널 trait(raw 모드 guard, 창 크기 조회, stdin 읽기, 끊김 신호)에 올리고, unix와 Windows가 각자 구현한다. 이 추출은 unix 동작을 바꾸지 않는다.
5. raw 모드는 입력 핸들에서 `ENABLE_LINE_INPUT`, `ENABLE_ECHO_INPUT`, `ENABLE_PROCESSED_INPUT`을 끄고 `ENABLE_VIRTUAL_TERMINAL_INPUT`을 켠다. 출력 핸들은 `ENABLE_VIRTUAL_TERMINAL_PROCESSING`과 `DISABLE_NEWLINE_AUTO_RETURN`을 켠다. 입출력 코드 페이지는 UTF-8(65001)로 바꾸고 원래 값과 두 핸들의 원래 모드를 저장한다. 키는 파싱하지 않는다. VT 입력이 만든 바이트를 그대로 원격 PTY로 보낸다(`docs/CLI.md` §7). 행 시작 escape 처리는 unix와 같은 코드가 한다. `Ctrl-C`는 `ENABLE_PROCESSED_INPUT`이 꺼져 있으므로 `0x03` 바이트로 원격에 간다.
6. 복원은 모든 종료 경로에서 일어난다. 정상 종료와 오류 종료는 guard의 `Drop`, panic은 전역 slot을 쓰는 panic hook, 콘솔 창 닫기·`CTRL_BREAK`·로그오프·종료(`SetConsoleCtrlHandler`가 받는 `CTRL_CLOSE_EVENT`·`CTRL_BREAK_EVENT`·`CTRL_LOGOFF_EVENT`·`CTRL_SHUTDOWN_EVENT`)는 핸들러가 맡는다. 복원 함수는 멱등이다(unix의 `restore`와 같은 규율). 핸들러가 받은 이벤트는 unix의 SIGHUP/SIGTERM과 같이 detach로 처리한다. 세션은 서버에 남는다(`docs/CLI.md` §7).
7. 콘솔을 준비하지 못하면 세션을 열기 전에 끝낸다. 출력 핸들에 VT 처리를 켤 수 없는 환경(Windows 10 1809 미만의 conhost)이면 `UNSUPPORTED`로 끝나고, 메시지는 최소 버전을 적는다. 이 판정은 `session.open`보다 먼저이므로 호스트에 고아 세션이 생기지 않는다. stdin이 콘솔이 아닌 경우(파이프, 파일 리디렉션, Git Bash의 mintty처럼 pty 대신 파이프를 주는 터미널)는 unix의 비 tty 경로와 같다. raw 모드도 escape 처리도 없이 바이트를 그대로 흘린다(`docs/CLI.md` §7). README는 mintty 계열에서는 `winpty`나 Windows Terminal을 쓰라고 적는다.
8. resize는 이벤트 없이 폴링한다. `WINDOW_BUFFER_SIZE_EVENT`는 `ReadConsoleInput`으로만 오고 그것은 바이트 그대로 읽는 입력 경로와 충돌한다. 전용 스레드가 200 ms마다 `GetConsoleScreenBufferInfo`의 창 영역(`srWindow`) 크기를 읽어 직전 값과 다를 때만 `session.resize`를 보낸다. 최초 크기는 `session.open`에 싣는다. 폴링 간격은 상수로 두고 설정 키는 만들지 않는다. `SessionOpen.term`은 `TERM`이 있으면 그 값, 없으면(Windows의 일반 상태) 7번의 VT 입출력이 켜졌을 때 `xterm-256color`다. locale 환경변수는 Windows에 보통 없으므로 있을 때만 보낸다(`docs/CLI.md` §7 전달 목록의 기존 규칙).

### C. 파일 권한, keystore, 경로

9. 소유자 전용 DACL을 만드는 단일 모듈을 `qsh-core`(`fsutil` 하위)에 둔다. 만드는 쪽은 프로세스 토큰의 사용자 SID로 보호된(protected, 상속 차단) DACL 하나를 쓴다. 파일은 소유자 SID에 `FILE_ALL_ACCESS` ACE 하나, 디렉터리는 같은 SID에 `OBJECT_INHERIT | CONTAINER_INHERIT` ACE 하나다. 파일과 임시 파일은 `CreateFileW`의 `SECURITY_ATTRIBUTES`로 만드는 순간부터 이 DACL을 갖는다. 만든 뒤에 `icacls`로 고치지 않는다(생성과 설정 사이에 상속 ACL로 읽히는 구간이 생기고, 외부 프로세스·로캘에 기대게 된다). 기존 `ensure_private_dir_io`, `write_private_file_io`, resume 저장소의 임시 파일 생성이 `cfg(windows)` 분기에서 이 모듈을 부른다. 대상은 qsh가 Windows에서 쓰는 파일과 디렉터리 전부다. 곧 `identity/device.pem`·`device.key`(파일 모드), `trust.toml`, `config.toml`(쓰는 경우), `resume.json`과 그 `.tmp`·`.lock`, 그리고 config·state 디렉터리다.
10. DACL을 적용하지 못하면 파일을 만들지 않고 fail closed한다. SID 조회 실패, ACL을 지원하지 않는 파일시스템(FAT/exFAT, 일부 네트워크 공유)이 이유다. 오류는 기존 `config_io_error`의 `CONFIG_ERROR`이고 메시지에 경로와 원인을 담는다. 이미 있는 파일이 옛 빌드의 상속 ACL로 만들어졌다면 다음 쓰기(임시 파일 + rename)가 소유자 전용 DACL로 바꿔 놓는다. 읽기 전용 경로는 열 때 ACL을 검사하지 않는다. unix가 `acl.toml` 외에는 읽을 때 모드를 검사하지 않는 것과 같다(README Known limitations의 "Windows ACL checking is out of scope"는 host의 `acl.toml` 이야기라 그대로다).
11. 초대 코드를 터미널 프롬프트로 받는 경로는 Windows에서 `UNSUPPORTED`로 유지한다(`NO_TERMINAL_ECHO_SUPPRESSION`). `qsh pair accept <address> <code>`의 인자와 `--code-stdin`의 파이프·파일 입력은 연다. `--code-stdin`의 stdin이 콘솔이면 같은 `UNSUPPORTED`다(오늘은 콘솔 stdin도 에코를 끄지 않은 채 받아들이므로 `docs/CLI.md` §6.11대로 이 결정이 새로 막는 동작이다). 콘솔 에코 억제는 결정 5의 모드 비트로 구현할 수 있지만 CI가 콘솔 stdin을 만들 수 없어 에코가 실제로 꺼졌는지 단언할 방법이 없다. 단언할 수 없는 비밀 입력 경로는 열지 않는다. 열지 말지는 에코 억제를 ConPTY로 검증하는 후속 결정으로 미룬다(대안 절).
12. keystore는 Windows Credential Manager를 `platform` store로 붙인다. keyring-core 계열 store crate 하나를 `cfg(windows)` 의존으로 더하고, `auto`는 다른 OS와 같이 platform을 먼저 시도하고 `Unavailable`이면 파일 모드(결정 9의 DACL)로 떨어진다. store 호출은 다른 플랫폼과 같이 연산마다 열고 전역 기본 store를 등록하지 않는다. 개인키 blob은 Credential Manager의 크기 상한 안이다. 이 crate가 존재하지 않거나 `deny.toml`(license·advisory)을 못 넘으면 Windows `platform`은 지금처럼 `Unavailable`로 두고 `auto`가 파일 모드를 쓰도록 이 결정의 후반을 접는다. 이 판정은 첫 스텝에서 하고 접으면 이 ADR을 개정한다. 실제 store 왕복은 CI가 못 보므로 다른 플랫폼과 같이 릴리스 전 수동 단계다(`docs/design/testing.md` L1 「플랫폼 키스토어 릴리스 전 수동 단계」에 Windows 줄을 더한다).
13. config·state 경로는 ssh 스타일 예측 가능성을 따른다(`docs/design/architecture.md` §7). Windows에서도 `%USERPROFILE%\.config\qsh`와 `%USERPROFILE%\.local\state\qsh`이고 `QSH_CONFIG_DIR`·`QSH_STATE_DIR`·`XDG_*` 우선순위는 그대로다(`Paths::from_env`의 `home_dir()`가 이미 플랫폼 홈을 고른다). `%APPDATA%`와 `%LOCALAPPDATA%`는 쓰지 않는다. runtime dir은 만들지 않는다(결정 14).

### D. localctl, service, supervise

14. localctl 대체 IPC(named pipe 등)는 이 마일스톤에서 열지 않는다. 생산자인 `qsh listen`/`qsh serve --to`가 Windows에 없으므로 소비자가 읽을 데몬이 없다. 따라서 `qsh hosts`는 forward host만, `qsh tunnels`는 빈 목록, `qsh tunnel close <id>`는 이 프로세스 밖의 터널을 찾지 못하는 멱등 응답을 낸다(`docs/CLI.md` §6.9, §6.13의 Windows 문장을 이에 맞춰 한 줄씩 보강). reverse route를 향한 `qsh exec`·`session`·attach는 라우팅 단계에서 reverse 등록을 찾지 못하고 forward 해석으로 간다. 이 동작은 이미 코드가 그렇다. 이 동작을 `cfg(windows)` 테스트 하나가 고정한다. Windows host(P2)가 설 때 named pipe와 DACL 거부 모델을 새 ADR로 연다.
15. `qsh tunnel open --supervise`는 Windows에서 그대로 열린다. supervisor는 터널을 연 프로세스 안에 있고 UDS를 쓰지 않는다. 절전 감지는 wall clock과 monotonic clock을 비교하는데 Windows의 monotonic clock이 절전 중 멈추는지는 확인된 적이 없다(README Known limitations). 이 ADR은 그 확인을 계약으로 삼지 않는다. 멈추지 않는다면 절전 감지는 일반 dead-path 감지로 대신되고 `qsh.event/v1`의 `wake` 이벤트가 안 나올 뿐 터널 복구는 된다. 캠페인 문서(결정 17)에 Windows 절전 회차 한 줄을 더해 사람이 한 번 확인한다. 결과는 README 문장을 확정하는 데만 쓴다.

### E. 출고, CI, 문서

16. release 자산은 `qsh-<tag>-x86_64-pc-windows-msvc.zip`을 유지하고 구성(`qsh.exe` 하나, man 페이지 없음)과 `SHA256SUMS`·attestation 대상도 그대로다. 설치 스크립트(`install.sh`)는 Windows 경로를 갖지 않고 README가 zip 수동 설치를 적는 지금 형태를 유지한다. 코드 서명(Authenticode)은 이 마일스톤에 넣지 않는다. 자산은 서명되지 않으며 SmartScreen 경고가 뜰 수 있음을 `RELEASE-NOTES.md`와 README가 적는다. 아키텍처는 x86_64 하나다. `aarch64-pc-windows-msvc`는 열지 않는다.
17. CI의 `windows-latest` leg은 다음을 더한다.
    - 결정 9~10의 DACL 단언 테스트. 소유자 전용 DACL로 `identity/device.key`, `trust.toml`, `resume.json`을 만들고 `GetNamedSecurityInfoW`로 읽어 SE_DACL_PROTECTED, ACE 하나, 그 SID가 토큰 사용자, 접근 마스크가 `FILE_ALL_ACCESS`임을 단언한다. 적용 실패를 주입한 변형에서는 대상 파일이 만들어지지 않음을 단언한다.
    - 결정 4~8의 콘솔 계층 테스트. 테스트 바이너리가 ConPTY(`portable-pty`의 Windows 백엔드)를 열고 그 안에서 콘솔 probe(`qsh-testkit`의 작은 실행 파일)를 띄운다. probe는 raw 모드 진입 후 입력 바이트가 가공 없이 읽히는지, ConPTY 크기를 바꾸면 폴링이 한 번만 `resize` 콜백을 부르는지, 정상·강제 종료 뒤 콘솔 모드가 원래 값으로 돌아오는지를 stdout으로 보고한다. 모드 비트 계산(원래 모드에서 raw 모드를 만드는 순수 함수)은 단위 테스트가 따로 고정한다.
    - `release_smoke`의 `cfg(not(unix))` 쌍둥이를 넓힌다. 기존 `init` → `trust` → `exec --json`에 `doctor --json`과 `tunnel open --local`의 TCP echo 왕복을 더한다. 상대는 같은 바이너리의 인바운드 `qsh serve`다(결정 2). PTY·detach·attach 축은 Windows에 host가 없어 뺀다. 이 쌍둥이가 만든 파일에도 결정 9의 DACL 단언을 건다.
    - clippy는 이미 Windows를 돈다. `cargo xtask arch`의 의존 방향 규칙은 바뀌지 않는다(`windows-sys`는 `qsh-core`와 `qsh-cli`가 `cfg(windows)`로만 의존한다).
18. 사람 캠페인 문서 `docs/campaigns/p1-windows-client.md`를 M19 구현 마지막 스텝 전에 사전 고정해 커밋한다. 회차는 Windows Terminal과 conhost 각각에서 Linux host와 macOS host로 붙어 (1) bash/zsh 입력과 한글·이모지 출력, (2) vim 전체 화면과 종료 뒤 화면 복원, (3) 창 크기 변경 전파, (4) `~d` detach 뒤 `qsh attach` resume, (5) 콘솔 창 닫기 뒤 세션 생존과 터미널 모드 복원, (6) `Ctrl-C` 전달, (7) 결정 15의 절전 회차를 본다. 합격 기준은 캠페인 문서가 정한다. 이 회차는 마일스톤을 막지 않고 P1 완료 선언을 막는다(`docs/ROADMAP.md` §5.5).
19. 문서 개정은 `docs/design/threat-model.md` §3에 진입점 행("Windows 콘솔 입력", 로컬 사용자, VT 입력 바이트는 키 해석 없이 원격으로 가며 해석하는 쪽은 원격 PTY)을 더하고 §4 D(정보노출)에 DACL 통제와 결정 17의 핀 테스트를 올린다. `docs/design/architecture.md` §7에 Windows 경로 줄, §8에 `windows-sys` 행과 keystore 행의 Windows 항목을 고친다. `docs/CLI.md` §6.11·§6.12·§6.13·§6.14의 Windows 관련 문장과 §7에 새로 더할 Windows 지원 범위 문장, README Known limitations와 `docs/ROADMAP.md` §3 Windows 행, `crates/qsh-core/src/resume.rs` 모듈 doc의 "inherited directory ACL" 문단을 새 범위에 맞춘다.

## 근거

가치 대부분이 대화형 attach에 있고 그 비용도 거기에 있어서 선을 거기까지 긋는다. 나머지 명령은 이미 돌고 모자란 것은 기밀성(DACL)과 콘솔(raw 모드, resize)이다. host 역할과 localctl을 같이 열면 소비자만 있고 생산자가 없는 IPC를 만들고 그 위에 DACL 거부 테스트까지 지게 된다. `docs/ROADMAP.md` §5.4 위험 5가 말한 "좁힌다"는 이 둘을 빼는 것이다.

crossterm을 쓰지 않는 이유는 architecture §8이 이미 댔다. 이벤트 루프와 키 파서는 raw byte 전달과 충돌한다. Win32 콘솔 API는 VT 입력 모드(`ENABLE_VIRTUAL_TERMINAL_INPUT`) 덕에 입력을 이미 xterm 바이트열로 준다. unix의 termios raw 모드와 같은 일을 하는 모드 비트 몇 개가 전부다. 원격 PTY가 해석한다는 점도 같아서 escape 처리 코드를 공유할 수 있다.

resize를 폴링으로 하는 이유는 입력 읽기와 충돌하지 않는 방법이 이것뿐이어서다. 이벤트를 받으려면 `ReadConsoleInput`으로 입력을 레코드 단위로 읽어야 하는데, 그러면 VT 모드가 만든 바이트를 레코드의 문자로 다시 조립하게 되어 "바이트를 그대로"라는 규율이 깨진다. 200 ms는 사람이 창을 끄는 속도에서 체감 지연이 없고 비용은 값이 안 바뀐 동안 시스템 호출 하나다.

DACL을 만드는 순간에 거는 이유는 임시 파일이 rename 전에 상속 ACL로 읽힐 수 있어서다. resume token은 연결이 죽은 뒤에도 사는 유일한 자격이므로(ADR-0007) 이 구간이 곧 노출이다. 소유자 SID 하나만 두는 것은 unix 0600과 대응한다. 관리자는 소유권을 가져올 수 있으므로 같은 사용자의 다른 프로세스와 다른 사용자를 막는 모델이라는 점이 unix 0600과 같다.

초대 코드 에코를 열지 않는 이유는 검증 가능성이다. 모드 비트는 쉽지만 "에코가 꺼졌다"를 단언하는 CI 수단이 없다. 이 프로젝트는 비밀이 스크롤백에 남는 경로를 테스트 없이 열지 않는다(`NO_TERMINAL_ECHO_SUPPRESSION`의 기존 판단). 인자와 파이프 입력이 열려 있어 Windows 사용자는 pairing을 막히지 않는다.

Credential Manager를 붙이는 것은 다른 OS와 같은 기본값(`auto` = platform 우선)을 주기 위해서고, 붙이지 못해도 파일 모드가 DACL로 보호되므로 최악의 경우에도 기밀성은 같다. 그래서 결정 12는 접을 수 있게 써 두었다.

## 대안과 기각 사유

- **Windows host(ConPTY 백엔드)를 함께 연다.** 기각한다. PRD §7이 P2로 두었고 PTY 코드 전체가 `cfg(unix)`다. 이 ADR의 범위가 아니고, 열면 Windows 러너에서 대화형 attach를 자체 종단 테스트할 수 있다는 이점이 있다. 그 이점은 P2 ADR에서 얻는다.
- **crossterm으로 콘솔을 다룬다.** 기각한다. architecture §8의 이유와 Windows API 표면을 키 이벤트 계층까지 끌어오는 비용 때문이다.
- **named pipe로 localctl을 Windows에 연다.** 기각한다. 생산자가 없다(맥락). 다른 사용자 접속 거부 테스트와 pipe DACL까지 지는 비용 대비 쓰이는 곳이 없다. 열 때는 Windows host와 함께 새 ADR로 연다.
- **`WINDOW_BUFFER_SIZE_EVENT`로 resize를 받는다.** 기각한다. 입력을 레코드로 읽게 되어 바이트 그대로 전달 규율이 깨진다.
- **`icacls`나 PowerShell로 ACL을 설정한다.** 기각한다. 생성과 설정 사이에 노출 구간이 생기고 외부 프로세스·로캘 의존이 들어온다.
- **상속 ACL을 그대로 둔다.** 기각한다. 사용자 프로필 아래 상속은 대개 소유자·SYSTEM·Administrators라서 일견 안전해 보이지만 프로필 디렉터리나 `QSH_STATE_DIR`를 다른 곳으로 둔 경우 보장이 없고, 보장이 환경에 달린 기밀성은 테스트로 고정할 수 없다. ROADMAP DoD도 소유자 전용을 요구한다.
- **`%APPDATA%`/`%LOCALAPPDATA%`에 둔다.** 기각한다. ssh 스타일 예측 가능성(`.config/qsh`)을 세 OS에서 맞추는 쪽이 문서와 지원 비용이 낮고, OpenSSH for Windows도 `%USERPROFILE%\.ssh`를 쓴다. `%APPDATA%`는 로밍 프로필로 복제될 수 있어 키 파일에는 오히려 나쁘다. 사용자가 원하면 `QSH_CONFIG_DIR`로 옮길 수 있다.
- **초대 코드 콘솔 프롬프트를 지금 연다.** 기각한다(근거 절). ConPTY 기반 에코 검증 테스트가 서면 후속 ADR 없이 `NO_TERMINAL_ECHO_SUPPRESSION`의 조건만 바꾸는 작은 변경으로 열 수 있다.
- **Windows 러너 안에서 대화형 attach를 종단 테스트한다.** 현재는 기각한다. 상대가 될 host가 Windows에 없고, GHA 러너끼리는 UDP 경로가 없다. 콘솔 계층은 ConPTY probe로, 종단은 사람 캠페인으로 나눠 고정한다. WSL 배포판을 러너에 띄우는 방법은 러너 이미지 의존이 커서 여기서는 채택하지 않는다.
- **Authenticode 서명과 winget·scoop·MSI를 이번에 넣는다.** 기각한다. 서명 인증서 발급·보관 절차(`docs/deploy/release-secrets.md`)가 먼저 필요하고 Windows 자산이 한 번도 사람 확인을 받지 않았다. 캠페인 합격 뒤에 별도 항목으로 연다.
- **doctor에 Windows 파일 ACL 점검 finding을 더한다.** 이번에는 넣지 않는다. 읽을 때 검사하지 않는 unix와 같은 규율을 유지하고 `EXPECTED_DOCTOR_CODES`를 늘리지 않는다. 옛 빌드의 느슨한 파일은 다음 쓰기에서 고쳐진다(결정 10). 요구가 관측되면 additive finding으로 연다.

## 결과

- 고정할 테스트(이름은 구현 시 확정, 위치만 정한다).
  - `crates/qsh-cli/tests/exit_code_matrix.rs`의 `cfg(windows)` 행: 결정 2의 각 명령이 `UNSUPPORTED`/exit `255`이고 리소스를 만들지 않음. 터미널 초대 코드 프롬프트와 콘솔 stdin의 `--code-stdin`이 `UNSUPPORTED`, 파이프 입력은 성공.
  - `qsh-core`의 Windows DACL 테스트(결정 9~10): 보호·단일 ACE·소유자 SID·접근 마스크, 적용 실패 주입 시 파일 부재, 옛 상속 ACL 파일이 다음 쓰기에서 교체됨.
  - `qsh-cli`의 콘솔 모드 계산 단위 테스트와 `qsh-testkit` ConPTY probe 테스트(결정 17): raw 입력 무가공, resize 폴링 한 번, 모드 복원, 비 콘솔 stdin의 verbatim 경로, VT를 켤 수 없을 때 `session.open` 이전 `UNSUPPORTED`.
  - 결정 14의 `hosts`/`tunnels`/`tunnel close`/reverse 해석 동작을 고정하는 `cfg(windows)` 테스트.
  - `release_smoke`의 `cfg(not(unix))` 쌍둥이 확장(결정 17).
  - unix 회귀: 터미널 trait 추출(결정 4) 뒤에도 `tui_expect`와 기존 attach 테스트가 그대로 초록이어야 한다.
- `qsh.cli/v1`, `qsh.event/v1`, wire 프로토콜, `ErrorCode`, capability 문자열, `EXPECTED_DOCTOR_CODES`는 바뀌지 않는다. 새 fixture도 없다(fixture는 OS 공통이고 Windows 행은 위 매트릭스 테스트가 맡는다). doctor는 localctl·service·host 역할에 기대는 finding을 Windows에서 내지 않을 뿐 어휘를 늘리지 않는다. 이 부분이 현재 코드와 어긋나면 첫 스텝에서 드러나므로 그때 이 ADR을 개정한다.
- 의존 추가: `windows-sys`(`qsh-core`, `qsh-cli`의 `cfg(windows)`), Windows keystore store crate 하나(결정 12), 개발 의존으로 `portable-pty`(`qsh-testkit`, Windows; 워크스페이스 의존으로는 이미 있고 `qsh-core`에서 unix 전용으로 쓴다). `deny.toml` 통과가 조건이다. `cargo xtask arch`는 바뀌지 않는다.
- 문서 개정은 결정 19의 목록이 전부다. 새 `docs/campaigns/p1-windows-client.md`가 생긴다. `docs/man/`은 clap 트리가 안 바뀌므로 변하지 않는다.
- 크기: `docs/ROADMAP.md` M19의 4.7~7.0ew를 4.3~6.9ew로 다시 매긴다. ADR 0.3 / 콘솔 모듈 1.0~1.6 / 터미널 trait 추출 0.5~0.8 / DACL 모듈과 fail closed 0.8~1.3 / keystore 0.2~0.5 / ConPTY probe를 포함한 테스트 0.8~1.2 / CI·release smoke 0.3~0.5 / 문서·threat model·캠페인 사전 고정 0.3~0.5 / 마감 0.1~0.2. 비교 표본이 없는 산정이라 신뢰도는 낮다. 첫 스텝은 가장 불확실한 콘솔 probe와 터미널 trait 추출이고, 그 뒤 이 절과 `docs/ROADMAP.md` §5.2·§5.4 위험 5를 다시 매긴다.
- 승인되면 `docs/ROADMAP.md` M19의 착수 조건이 풀린다(M18의 착수 조건이 닫히지 않았으면 M19를 먼저 연다는 조건은 그대로다).
