# P1 Windows 캠페인 — 실제 Windows 장비에서 CI가 못 보는 것을 확인한다 (M19 몫)

상태: 기준 사전 고정(M19 몫). 회차는 아직 돌지 않았다. 대상 태그가 없다. host 회차 W2, W3b, W7은 자리만 있고 M20이 더해 다시 고정한다(§4.12, ADR-0035 결정 18).

## 1. 목적과 지위

ADR-0035는 Windows를 Linux·macOS와 같은 기능으로 연다. M19는 client 쪽(콘솔 raw 모드 attach, named pipe localctl과 `qsh listen` 데몬, Credential Manager, 작업 스케줄러 서비스, Authenticode 서명, 설치 경로 셋)을 연다. `windows-latest` 다리의 CI가 같은 러너 안 loopback으로 정방향·역방향 종단을 돌리므로(ADR-0035 결정 17) 이 캠페인은 CI가 볼 수 없는 것만 본다. 예를 들면 실제 터미널의 렌더링과 IME, 노트북 덮개, 둘째 사용자 계정, 로그온·로그오프·재부팅에 걸린 작업의 수명, 두 장비 사이의 UDP, 실제 서명과 SmartScreen, 패키지 관리자다.

CI가 이미 맡는 것은 여기서 다시 하지 않는다. 대표적으로 콘솔 모드 비트와 복원 경로(`windows_attach::`), pipe의 DACL·SID 대조·이름 선점 거부(`pipe_server_drops_a_client_with_another_sid_before_reading_a_frame`, `pipe_bind_fails_when_the_name_already_exists`), 절전 표본의 단조성(`windows_wake_sample_is_monotonic`), Credential Manager의 러너 왕복(`credential_manager_round_trip_on_the_runner`), `install.ps1`의 체크섬 선행(`install_ps1_verifies_the_checksum_before_extracting`), 서명 판정 함수(`windows_signature_check_fails_on_an_unsigned_binary`), 가짜 ssh 위의 Windows 자동 부트스트랩(`auto_bootstrap_keeps_the_console_cooked_until_ssh_exits_on_windows`)이다. 이 문서의 회차는 그 테스트가 대신 볼 수 없는 실제 환경의 동작이다.

지위는 `docs/campaigns/p1-ssh-bootstrap.md`와 같다. `docs/ROADMAP.md` §5.1 원칙 6에 따라 M19의 DoD는 이 문서가 사전 고정돼 커밋되는 데까지이고, 회차는 §5.5의 사람 몫이다. 마일스톤을 막지 않고 P1 완료 선언을 막는다. 판정은 합격/불합격이고, PASS가 기록되기 전에는 해당 기능이 실제 Windows에서 동작한다고 적지 않는다. 자동 테스트로 대신하지 않는다. 시간을 재지 않으며 합격은 아래 확인의 충족이다. 형식은 `docs/campaigns/p1-ssh-bootstrap.md`, `docs/campaigns/p1-supervise-wake.md`, `docs/campaigns/m10-clean-vm.md`를 따른다.

회차 이름은 ADR-0035 결정 18의 번호를 그대로 쓴다. 번호가 비는 자리는 host 회차이고 M20이 채운다.

| 회차 | 내용 | 몫 |
|---|---|---|
| W1 | Windows Terminal과 conhost에서 Linux·macOS host로 attach | M19 |
| W2 | Linux·macOS client가 Windows host(`qsh serve`)에 attach | M20 자리 |
| W3a | Windows `qsh listen` ← Linux·macOS `qsh serve --to` (attach, `cp`, 터널) | M19 |
| W3b | Linux·macOS `qsh listen` ← Windows `qsh serve --to` | M20 자리 |
| W4 | 절전 복귀 | M19 |
| W5 | 둘째 Windows 계정의 pipe 접속 거부와 이름 선점 거부 | M19 |
| W6 | 로그온 작업의 로그온 기동, 강제 종료 뒤 재기동, 로그오프 정지 | M19 |
| W7 | `qsh pair ssh`·`--reverse`가 Windows OpenSSH Server를 상대로 pin을 세움 | M20 자리 |
| W8 | Credential Manager 왕복 | M19 |
| W9 | Windows on ARM에서 W1 축약 | M19 |
| W10 | 상시 기동 변형의 로그오프·재부팅 생존과 `logon_task_session_scoped` 소멸 | M19 |
| W11 | 서명 주체·SmartScreen, `install.ps1`·`scoop install`·`winget install` | M19 |
| W12 | Windows client 자동 부트스트랩(`qsh box`, `qsh cp`) | M19 |

W12는 ADR-0035 결정 18의 번호가 아니다. `docs/campaigns/p1-ssh-bootstrap.md`의 R5가 요건 4와 6(`qsh box`의 대화형 attach와 `qsh cp`)을 M19로 미뤘고, R5의 문면은 고치지 않는 대신 그 몫을 W12가 받는다.

## 2. 선행 조건

### 2.1 대상 태그

회차는 Windows 자산이 붙은 태그를 대상으로 한다. 아래가 모두 성립해야 하고, 태그가 없는 동안 회차는 열리지 않는다.

- 그 태그의 release run이 초록이다.
- 그 태그의 `SHA256SUMS`에 `qsh-<tag>-x86_64-pc-windows-msvc.zip`, `qsh-<tag>-aarch64-pc-windows-msvc.zip` 줄이 있고 release에 `install.ps1` 자산이 있다. `release` job의 `Check every target is published` 스텝이 이 사실을 붉게 만들지만 회차 시작 전에 사람이 한 번 더 본다.
- W11은 서명된 태그에서만 돈다. 그 태그의 release run에서 `Sign the binary (windows)`, `Sign install.ps1`, `Verify the signature (windows)` 스텝이 건너뛰어지지 않고 초록이다. 서명 시크릿 없이 찍은 태그(run 요약에 `Unsigned release` 경고가 있다)에서는 W11을 돌지 않는다. 그 태그에서 W11을 돌려 나온 기록은 무효다. 다른 회차는 서명 여부와 무관하다.
- W11의 scoop·winget 변형은 해당 패키지 관리자에 그 태그의 매니페스트가 올라 있어야 돈다(§4.9). 올라 있지 않으면 그 변형은 "보류"다.

### 2.2 장비

| 이름 | 조건 |
|---|---|
| W | 실제 Windows 10 1809 이상 또는 Windows 11 장비. x86_64. Windows Terminal이 설치돼 있고, 기본 탑재 `ssh.exe`(선택적 기능 OpenSSH Client)가 있다. PowerShell 7(`pwsh`)이 있다. W4는 노트북이어야 한다 |
| 계정 B | W5 전용. W에 만드는 둘째 표준(비관리자) 로컬 계정. 만드는 데 관리자 권한이 한 번 든다. 회차 W2와 무관하다 |
| L | Linux 장비. 대상 태그의 `qsh`가 `PATH`에 있고(`ssh L 'command -v qsh'`로 확인) 진짜 `sshd`가 돈다. `qsh init`이 끝나 있다. W에서 UDP 4433이 닿는다 |
| M | macOS 장비. L과 같은 조건. 기본 셸은 zsh |
| W-ARM | W9 전용. Windows on ARM 장비(Windows 11 ARM64) |

W와 L, W와 M은 서로 다른 장비다. 한 장비 안의 loopback은 회차로 세지 않는다. L과 M은 같은 날 같은 대상 태그의 바이너리를 쓴다. W3a는 W가 L 또는 M에서 UDP로 닿는 주소를 가져야 한다. 처음 `qsh listen`을 띄울 때 Windows Defender 방화벽이 허용 여부를 물으면 사설 네트워크에서 허용하고 그 사실을 비고에 적는다(`docs/CLI.md` §6.13).

### 2.3 클린의 정의

회차 시작 때 W에는 다음이 없다.

- `%USERPROFILE%\.config\qsh`와 `%USERPROFILE%\.local\state\qsh` 전체. 특히 `identity`, `trust.toml`, `hosts.toml`, `config.toml`, `service`, `log`가 없다.
- Credential Manager의 `*.qsh` 대상 항목(`cmdkey /list | Select-String '\.qsh'`가 비어 있다).
- 작업 스케줄러의 `\qsh\` 폴더(`Get-ScheduledTask -TaskPath '\qsh\'`가 비어 있다).
- 이전 `qsh.exe`. 대상 태그의 자산 하나만 `PATH`에서 해석된다(`Get-Command qsh -All`로 확인).

회차마다 시작 전에 `qsh version`과 `winver`(또는 `[Environment]::OSVersion`), 터미널 종류를 비고에 적는다. 회차를 끝낸 뒤에는 §4가 적은 정리 절차로 W를 클린으로 되돌린다. 회차 사이에 만들어 둔 pin을 재사용하는 회차는 그 사실을 비고에 적는다.

### 2.4 대상 고정

첫 회차를 돌기 전에 아래를 채우고 이후 바꾸지 않는다. 다른 태그로 다시 도는 회차는 새 줄을 더한다.

| 항목 | 값 |
|---|---|
| 대상 태그 | |
| 태그의 커밋 SHA | |
| release run | |
| `SHA256SUMS`의 x86_64 zip 줄 | |
| `SHA256SUMS`의 aarch64 zip 줄 | |
| `SHA256SUMS`의 `install.ps1` 줄 | |
| 서명 스텝 세 개가 초록인가 (W11 대상 여부) | |
| `WINDOWS_SIGN_EXPECTED_SUBJECT` 값 (저장소 변수, 시크릿 아님) | |

이 문서를 고정한 커밋의 해시는 `docs/ROADMAP.md` §5.5의 Windows 행에 main 세션이 적는다.

## 3. 공통 요건과 도구

### 3.1 공통 요건

모든 회차의 행은 아래 셋을 만족해야 하고, 그 위에 §4가 적은 회차별 확인이 모두 PASS여야 PASS다. 회차를 돌면서 늘리지 않는다.

| # | 요건 | 어디에 기록하는가 |
|---|---|---|
| 1 | 시작 상태가 §2.3과 같다 | 비고 |
| 2 | 바이너리가 대상 태그의 자산이다. 소스에서 빌드한 것이 아니다. zip의 해시가 `SHA256SUMS`의 줄과 같고(`Get-FileHash <zip> -Algorithm SHA256`) 쓴 `qsh.exe`의 sha256이 그 zip 안 `qsh.exe`와 같다 | 비고 |
| 3 | 판정에 쓴 명령과 출력 원문이 비고에 있다. 비밀(초대 코드, passphrase, 암호)은 적지 않는다 | 비고 |

### 3.2 도구

회차가 부르는 PowerShell 조각이다. 모두 PowerShell 7에서 돈다.

TCP echo 서버(W3a의 `-R` 확인, 대상 포트 7777):

```powershell
$l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 7777)
$l.Start()
while ($true) {
    $c = $l.AcceptTcpClient()
    $s = $c.GetStream()
    $b = New-Object byte[] 4096
    while (($n = $s.Read($b, 0, 4096)) -gt 0) { $s.Write($b, 0, $n) }
    $c.Close()
}
```

echo 확인 클라이언트(`<port>`에 터널의 로컬 포트):

```powershell
$c = [System.Net.Sockets.TcpClient]::new('127.0.0.1', <port>)
$s = $c.GetStream()
$b = [System.Text.Encoding]::UTF8.GetBytes("hello-qsh`n")
$s.Write($b, 0, $b.Length)
Start-Sleep -Milliseconds 500
$buf = New-Object byte[] 64
$n = $s.Read($buf, 0, 64)
[System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
$c.Close()
```

listener 탐침(W4, 1초마다 포트가 bind돼 있는지 적는다. Windows는 닫힌 loopback 포트의 연결 거절을 2초가량 지나서야 알리므로 연결을 열지 않고 소켓 표를 읽는다):

```powershell
while ($true) {
    $r = if (Get-NetTCPConnection -State Listen -LocalPort 1080 -ErrorAction SilentlyContinue) { 'listening' } else { 'absent' }
    '{0:F3} {1}' -f ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000), $r
    Start-Sleep -Seconds 1
}
```

CONNECT 탐침(W4, `<addr>`은 hub 쪽에서만 닿고 HTTP로 응답하는 주소):

```powershell
while ($true) {
    $t = '{0:F3}' -f ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000)
    & curl.exe --socks5-hostname 127.0.0.1:1080 -m 1 -sS -o NUL http://<addr>/ 2>$null
    "$t $LASTEXITCODE"
    Start-Sleep -Milliseconds 200
}
```

망 복귀 탐침(W4, hub로 0.2초마다 한 번 보낸다):

```powershell
while ($true) {
    $ok = Test-Connection -TargetName <hub 주소> -Count 1 -TimeoutSeconds 1 -Quiet
    '{0:F3} {1}' -f ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000), $ok
    Start-Sleep -Milliseconds 200
}
```

## 4. 회차

한 회차 안의 "변형"은 따로 PASS 행을 가져야 하는 조합이다. 변형별 확인 문자(a, b, …)는 회차 표의 "확인" 열에 `a=PASS b=FAIL` 꼴로 적는다.

### 4.1 W1 — 정방향 대화형 attach (Windows Terminal과 conhost, Linux와 macOS host)

변형은 넷이다. 터미널 {Windows Terminal, conhost} × host {L, M}. conhost는 `Win+R`에 `conhost.exe pwsh.exe`를 쳐서 연다(기본 터미널이 Windows Terminal이어도 이 창은 conhost가 직접 호스트한다). 변형마다 창을 새로 연다.

준비는 이렇다. W에서 `qsh init`을 하고, 호스트에서 `qsh serve`를 띄운 채 `qsh pair invite`를 쳐서 코드를 받는다. W에서 `qsh pair accept <호스트 주소> --as box`를 코드 없이 치고, 프롬프트에 코드를 입력한다. 이미 pin이 있는 변형(같은 host의 두 번째 터미널)은 이 단계를 건너뛰고 비고에 적는다. 시작 전에 `chcp`의 출력(코드 페이지 번호)을 적는다.

| 확인 | 합격 기준 |
|---|---|
| a. 코드 프롬프트 | `qsh pair accept`가 코드를 묻는 동안 입력한 글자가 화면에 나타나지 않는다. 끝난 뒤 `qsh trust list`에 `box`가 있고 프롬프트가 정상으로 돌아온다. pin을 새로 세운 변형에서만 본다. 재사용한 변형은 "해당 없음"으로 적는다 |
| b. 입력과 출력 | `qsh box`가 셸 프롬프트까지 간다(L은 bash, M은 zsh). `echo 한글 테스트 😀`의 출력이 입력과 같고, 한글을 입력하다 Backspace로 한 글자를 지우면 그 글자 하나만 지워지며, 위쪽 화살표로 직전 명령이 나오고 Tab 완성이 동작한다. `sleep 100`을 Ctrl-C로 끊으면 `sleep`만 끊기고 셸은 남는다 |
| c. 전체 화면 프로그램 | `vim`을 열어 한글을 입력하고 창 크기를 줄였다 늘렸다 한다. 창을 줄이면 `stty size`가 낸 두 수가 줄고(창을 닫지 않은 채 `:!stty size`로 본다) 늘리면 늘며, vim의 하단 줄이 창의 마지막 행에 있다. `:q!` 뒤 vim을 열기 전의 화면(직전 출력과 프롬프트)이 복원된다 |
| d. 종료와 모드 복원 | 행 시작에서 `~d`를 치면 PowerShell 프롬프트로 돌아오고, 입력이 에코되며, 줄 편집과 위쪽 화살표 history가 동작하고, `chcp`의 출력이 시작 전과 같다. `qsh attach <session-ref>`로 다시 붙은 뒤 `Ctrl+Break`(노트북은 `Fn`과의 조합)를 눌러도 같은 결과다. `Ctrl+Break`를 쓰는 이유는 창 닫기와 같은 `CTRL_CLOSE_EVENT`·`CTRL_BREAK_EVENT` 핸들러를 거치지만 창이 남아 모드를 눈으로 볼 수 있기 때문이다(ADR-0035 결정 6) |
| e. 창 닫기 뒤 세션 생존 | `while true; do date; sleep 1; done`을 돌리는 세션에서 콘솔 창(Windows Terminal은 탭)의 닫기 단추를 누른다. 다른 콘솔에서 10초 안에 `qsh sessions box --writer none`에 그 세션이 나온다. writer가 없다는 것은 연결 유실이 아니라 정상 detach라는 뜻이다(`docs/CLI.md` §7 Windows 콘솔). `qsh attach <session-ref>`로 다시 붙으면 `date` 루프가 계속 돌고 새 줄의 시각이 현재 시각이다 |

정리는 `qsh session close <session-ref>`로 열어 둔 세션을 닫고, 호스트에서 `qsh serve`를 끈다. pin은 다음 변형이 재사용해도 된다.

### 4.2 W3a — Windows `qsh listen` ← Linux·macOS `qsh serve --to`

변형은 둘이다. target {L, M}. W가 controller(`qsh listen`)이고 target이 W로 dial한다. 두 장비 사이의 실제 UDP 경로를 쓴다(W와 target이 같은 LAN이나 overlay에 있다).

준비는 이렇다. W에서 `qsh listen`을 띄운다. W가 target에서 닿는 주소를 `ADDR`이라 한다. W의 `%USERPROFILE%\.ssh\config`에 `Host box`로 target을 적고 W에서 `qsh pair ssh box --reverse --to ADDR`를 돌린다(target의 `sshd`를 쓴다). 결과의 `next_command`를 target에서 그대로 친다. target 방화벽에서 UDP 4433 인바운드를 막은 채로 돌린다. 코드 pairing은 `qsh listen`에 닿지 않으므로(`docs/CLI.md` §6.13) ssh를 쓸 수 없으면 `qsh identity export`와 `qsh trust add --cert-file`로 서로 pin한다.

| 확인 | 합격 기준 |
|---|---|
| a. 등록 | W의 `qsh hosts`에 `box`가 `connection_mode: reverse`, `state: reachable`로 오른다 |
| b. attach | W에서 `qsh box`로 셸이 열린다. W1의 b, d 확인(입력·출력, `~d`와 모드 복원)을 이 경로에서 한 번 더 한다. `qsh sessions box`가 세션을 보여 준다 |
| c. `cp` | `qsh cp C:\...\payload.bin box:/tmp/payload.bin`으로 올리고 `qsh cp box:/tmp/payload.bin .`으로 내려받는다. 앞뒤 파일의 sha256(`Get-FileHash`)이 같다. 작은 디렉터리를 `qsh cp -r`로도 한 번 옮긴다. 드라이브 문자 operand(`C:\...`)가 원격 host 이름으로 해석되지 않는다 |
| d. 터널 | target에서 `nc -lk 127.0.0.1 7000` 같은 echo 서버를 띄우고 W에서 `qsh tunnel open box --local 127.0.0.1:18080:127.0.0.1:7000 --json`을 돌려 §3.2의 echo 확인 클라이언트가 같은 바이트를 받는다. 반대 방향은 W에서 §3.2의 echo 서버(7777)를 띄우고 `qsh tunnel open box --remote 19000:127.0.0.1:7777 --json`을 돌려 target에서 `127.0.0.1:19000`에 붙어 echo를 받는다. `--remote` 터널은 `qsh tunnels`에 나오고 `qsh tunnel close <tunnel-id>`(봉투의 `tunnel_id`)로 닫히며 닫으면 target의 19000 포트가 사라진다. `--local` 터널은 `tunnel open`을 돌린 프로세스를 Ctrl-C로 끝내면 사라진다(`docs/CLI.md` §6.14) |
| e. 데몬 재시작 | W의 `qsh listen`을 Ctrl-C로 끄면 target의 stderr에 `lost`가 나오고, 다시 띄우면 target이 `registered`를 낸다. 2분 안에 W의 `qsh hosts`에 `box`가 다시 `reachable`로 오른다 |

정리는 열어 둔 터널과 세션을 닫고 `qsh listen`을 끄고 target의 `qsh serve --to`를 끈다. W5가 이 구성을 이어 쓰므로 W5를 돌 계획이면 `qsh listen`을 끄지 않고 둔다.

### 4.3 W4 — 절전 복귀

W는 노트북이다. `docs/campaigns/p1-supervise-wake.md`의 회차 1과 2를 Windows에서 되풀이한다. 변형은 둘이다. 덮개를 10분 닫기와 20초 닫기. 변형마다 같은 동작을 5번 반복한다(5는 `docs/campaigns/p1-supervise-wake.md` §3이 고정한 최소값이고 여기서도 같다).

터널은 이렇게 연다. hub는 L이고 `qsh serve`가 떠 있으며 W의 `box`가 L이다. `--accept-hold`는 주지 않는다.

```powershell
qsh tunnel open box --dynamic 1080 --supervise 300000 2> supervise.log
```

사건 전에 §3.2의 listener 탐침, CONNECT 탐침, 망 복귀 탐침을 각각 파일로 돌려 둔다. 사건은 덮개를 닫아서 만든다. 닫은 시각과 연 시각은 손목시계나 휴대폰으로 UTC 초 단위로 적는다. 깨어난 직후 OS가 화면을 켜지 않아도 되도록 전원 설정에서 덮개를 닫을 때의 동작이 "절전"인지 먼저 확인하고 `powercfg /query SCHEME_CURRENT SUB_BUTTONS` 출력을 비고에 적는다. 망 복귀 시각은 망 복귀 탐침의 첫 `True` 줄이다.

| 확인 | 합격 기준 |
|---|---|
| a. `wake` 줄 | 반복마다 stderr(`supervise.log`)에 `wake` 줄이 하나 나오고 `slept_ms`가 실제로 잠든 시간(적어 둔 닫은 시각과 연 시각의 차)과 10초 이하 또는 10% 이하(둘 중 큰 쪽)로 가깝다. 교차 확인으로 System 이벤트 로그의 `Microsoft-Windows-Power-Troubleshooter` 이벤트 1(`Sleep Time`·`Wake Time`)이 있으면 같이 적는다. 이 확인이 `QueryUnbiasedInterruptTime`이 잠든 시간을 빼는지를 본다(ADR-0035 결정 15) |
| b. listener 생존 | listener 탐침에 `absent`가 한 줄도 없다 |
| c. 복귀 속도 | 망 복귀 시각으로부터 첫 성공 CONNECT(종료 코드 0)까지가 변형 안 5회의 중앙값 2초 이하, 최댓값 4초 이하다 |
| d. 진단 충분성 | 끊김 시간이 `lost`, `wake`, `reestablished` 줄만으로 계산된다. `reestablished.outage_ms`는 잠든 시간을 뺀 값이다(`docs/CLI.md` §6.14). `gave_up`이 나온 반복이 없다 |

b, c, d의 수치와 판정 방식은 `docs/campaigns/p1-supervise-wake.md` §6과 같고 그 문서의 §7 기록표를 쓴다. 반복 기록표는 이 문서의 비고 문단에 붙인다.

정리는 터널 프로세스를 Ctrl-C로 끝낸다.

### 4.4 W5 — 둘째 Windows 계정의 pipe 접속 거부와 이름 선점 거부

W3a의 구성(`qsh listen`이 떠 있고 target이 등록돼 있다)을 이어 쓴다. 이 구성의 계정을 A라 한다. 준비로 관리자 프롬프트에서 둘째 표준 계정을 만든다(`net user qshtest2 <암호> /add`). 그 계정(B)으로 `runas /user:%COMPUTERNAME%\qshtest2 pwsh.exe`로 창을 연다. B에서 `qsh init`을 한다.

A의 pipe 이름은 `\\.\pipe\qsh-<scope>-<pid>`다(ADR-0035 결정 14). B의 창에서 이름을 읽는다.

```powershell
[System.IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -like '*qsh-*' }
```

| 확인 | 합격 기준 |
|---|---|
| a. 이름 공간 분리 | B에서 위 열거가 A의 pipe 이름을 보여 줄 수 있어도, B의 `qsh hosts`와 `qsh tunnels`는 A의 데몬이 쥔 reverse 항목을 하나도 내지 않고 오류 없이(exit 0) 끝난다. A의 `qsh hosts`에는 `box`가 그대로 `reachable`이다 |
| b. 접속 거부 | B에서 A의 pipe(`<name>`은 열거한 이름)에 붙으려는 시도가 접근 거부 계열 오류로 끝나고 멈추지 않는다 |
| c. 이름 선점 거부 | B에서 A의 pipe 이름으로 서버 인스턴스를 만들려는 시도가 실패한다. `CREATED`가 찍히면 FAIL이다 |
| d. 공존 | B가 `qsh listen --bind 127.0.0.1:4434`를 띄우면 정상 기동하고 pipe 열거에 `scope`가 다른 이름이 하나 더 생긴다. 그동안 A의 `qsh hosts`와 target의 등록이 영향을 받지 않는다 |
| e. 파일 DACL | A에서 `icacls "$env:USERPROFILE\.config\qsh\trust.toml"`의 출력에 A 계정 하나의 ACE만 있고 상속 표시 `(I)`가 붙은 줄이 없다 |

b와 c의 시도는 이렇게 한다.

```powershell
$name = '<열거한 pipe 이름에서 \\.\pipe\ 뒤의 부분>'
$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, [System.IO.Pipes.PipeDirection]::InOut)
try { $c.Connect(2000); 'CONNECTED' } catch { $e = $_.Exception.GetBaseException(); $e.GetType().Name + ': ' + $e.Message }
try {
    $s = New-Object System.IO.Pipes.NamedPipeServerStream($name, [System.IO.Pipes.PipeDirection]::InOut, 4)
    'CREATED'
} catch { $e = $_.Exception.GetBaseException(); $e.GetType().Name + ': ' + $e.Message }
```

b는 `CONNECTED`가 찍히면 FAIL이고 오류 이름과 문구를 비고에 적는다. 이 시도는 계정 B가 하는 OS 수준 거부를 본다. `qsh listen`이 이미 쥔 이름이면 UDP 포트를 열기 전에 기동이 실패하는 경로는 CI(`pipe_bind_fails_when_the_name_already_exists`)가 맡는다.

정리는 B의 `qsh listen`을 끄고 관리자 프롬프트에서 `net user qshtest2 /delete`로 계정을 지운 뒤 `C:\Users\qshtest2` 프로필 디렉터리를 지운다.

### 4.5 W6 — 로그온 작업의 수명

기본 작업(`InteractiveToken`)의 로그온 기동, 강제 종료 뒤 재기동, 로그오프 정지를 본다. 작업은 서버 mode(`serve`)로 연다. `config.toml`에 `[listen]`이나 `[serve].to`가 없으면 추론되는 mode가 `serve`다(`docs/CLI.md` §6.18). 작업 정의와 등록 명령은 `docs/deploy/service.md`의 Task Scheduler 절이 정본이다. W의 `qsh init`이 끝나 있고 L이 W를 pin하고 있다. W에서 `qsh serve`를 잠시 띄워 `qsh pair invite`를 치고, L에서 `qsh pair accept <W 주소> --as w`를 친 뒤 W의 `qsh serve`를 끈다. 이 qsh.exe 경로를 허용하는 Windows Defender 방화벽 인바운드 규칙이 준비 단계에서 이미 만들어져 있어야 한다(처음 `qsh serve`를 띄울 때 나오는 허용 프롬프트에 사설 네트워크로 답해 둔다, `docs/CLI.md` §6.13). 로그온·부팅 작업이 qsh를 띄울 때는 프롬프트에 답할 사용자가 없어, 규칙이 없으면 인바운드가 막혀 b가 엉뚱한 이유로 FAIL한다.

등록은 일반(비상승) 프롬프트에서 한다.

```powershell
qsh service install
schtasks /Create /F /TN \qsh\qsh-serve /XML "$env:USERPROFILE\.config\qsh\service\qsh-serve.task.xml"
Get-ScheduledTask -TaskPath '\qsh\' -TaskName 'qsh-serve' | Select-Object TaskName, State
```

작업이 띄운 프로세스는 이렇게 본다. 명령줄에 `service run serve`가 있는 프로세스가 작업의 것이다.

```powershell
Get-CimInstance Win32_Process -Filter "Name='qsh.exe'" | Select-Object ProcessId, CommandLine
Get-NetUDPEndpoint -LocalPort 4433 | Select-Object LocalAddress, LocalPort, OwningProcess
Get-Content "$env:USERPROFILE\.local\state\qsh\log\serve.err.log" -Tail 5
```

| 확인 | 합격 기준 |
|---|---|
| a. 등록 | 위 `schtasks /Create`가 관리자 권한 없이 종료 코드 0으로 끝난다. `qsh service status`가 유닛 파일이 있다고 답한다(`schtasks`를 부르지 않는다) |
| b. 로그온 기동 | 로그오프 뒤 다시 로그온하면 2분 안에 `service run serve` 프로세스가 하나 뜨고 UDP 4433을 쥔다. `serve.err.log`에 `{"lifecycle":"listening","at":"<RFC3339>","process":"serve"}` 기동 기록(`docs/CLI.md` §6.13·§6.14, stderr로 같은 로그 파일에 들어간다)이 있고 그 `at`이 로그온 시각 뒤다(로그는 이어 붙으므로 로그온 이후 처음 나온 `listening` 기록을 본다; 사람용 `listening on` 줄에는 시각이 없어 기준으로 쓰지 않는다). L에서 `qsh capabilities w`가 성공한다. 콘솔 창이 로그온 직후 잠깐 보였다 사라지는 것은 허용하고 비고에 적는다 |
| c. 강제 종료 뒤 재기동 | 그 프로세스를 `Stop-Process -Id <pid> -Force`로 죽이면 2분 안에 다른 pid의 `service run serve` 프로세스가 하나 다시 뜨고 4433을 쥔다. 두 프로세스가 동시에 있는 순간이 없다(`IgnoreNew`) |
| d. 로그오프 정지 | 로그오프하면 30초 안에 `qsh.exe`의 `service run serve` 프로세스가 없고 4433을 쥔 프로세스가 없다. 다른 계정의 창이나 원격 셸에서 위 두 명령으로 본다. L에서 `qsh capabilities w`가 `CONNECTION_FAILED`로 끝난다 |
| e. 진단 | 작업이 등록된 동안 `(qsh doctor --json \| ConvertFrom-Json).data.findings`에 `code`가 `logon_task_session_scoped`(status `warn`)와 `service_restart_drops_sessions`(status `info`)인 항목이 있다 |

정리는 아래 순서다. 작업을 등록 해제한 뒤 파일을 지운다(`qsh service uninstall`은 파일만 지우고 등록된 작업은 건드리지 않는다).

```powershell
schtasks /End /TN \qsh\qsh-serve
schtasks /Delete /F /TN \qsh\qsh-serve
qsh service uninstall
```

정리 뒤 `qsh doctor`에서 `logon_task_session_scoped`가 사라지고 `service_not_registered`가 나타나는지도 비고에 적는다.

### 4.6 W8 — Credential Manager 왕복

클린 W에서 `qsh init --key-store platform --json`을 돌린다. 출력의 `device_id`와 `fingerprint`, `key_store`를 적는다. 이후 `qsh identity export`가 같은 인증서를 낸다.

| 확인 | 합격 기준 |
|---|---|
| a. 항목 생성 | `data.key_store`가 `platform`이고 `cmdkey /list \| Select-String '<device_id>'`에 대상 `<device_id>.qsh` 항목이 보인다. `identity\device.key` 파일이 없다 |
| b. 파일로 이동 | `qsh identity move-key --to file` 뒤 `cmdkey` 항목이 사라지고 `identity\device.key`가 있으며 `icacls`가 소유자 계정 하나의 ACE만 보인다. `qsh init --json`을 다시 돌리면(멱등) `key_store`가 `file`이고 `device_id`와 `fingerprint`가 a와 같다 |
| c. 되돌림 | `qsh identity move-key --to platform` 뒤 항목이 다시 보이고 `device.key`가 없으며 `device_id`와 `fingerprint`가 그대로다 |
| d. 재부팅 뒤 | 재부팅하고 로그온한 뒤 `qsh init --json`의 `key_store`가 `platform`이고 `fingerprint`가 같다(`CRED_PERSIST_LOCAL_MACHINE`). `qsh doctor`에 `keystore_unavailable`이 없다 |

`cmdkey`의 출력은 지역화될 수 있으므로 항목은 대상 이름 문자열로 찾는다. 정리는 `qsh identity move-key --to file`로 항목을 지운 뒤 `%USERPROFILE%\.config\qsh`를 지운다. 항목이 남았으면 `cmdkey /delete:<device_id>.qsh`로 지운다.

### 4.7 W9 — Windows on ARM에서 W1 축약

W-ARM에서 `install.ps1`로 설치한다.

```powershell
$env:QSH_VERSION = '<대상 태그>'
irm https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.ps1 | iex
```

| 확인 | 합격 기준 |
|---|---|
| a. 자산 선택 | 설치 출력에 `detected target: aarch64-pc-windows-msvc`가 있고 `qsh version`이 대상 태그를 낸다. `qsh` 프로세스를 띄워 둔 동안 작업 관리자 자세히 탭의 "아키텍처" 열이 `ARM64`다 |
| b. attach | Windows Terminal에서 L로 `qsh box`가 셸 프롬프트까지 간다. pin은 W1 준비와 같이 세운다. W1의 b 확인(한글 입출력, Ctrl-C) |
| c. 전체 화면 | W1의 c 확인(vim 전체 화면과 복원, 창 크기 변경) |
| d. 창 닫기 | W1의 e 확인(창 닫기 뒤 세션 생존) |

conhost 변형과 macOS host, 역방향은 이 회차에서 보지 않는다. 정리는 W1과 같다.

### 4.8 W10 — 상시 기동 변형

로그온 작업(W6)과 달리 상시 기동 변형은 `BootTrigger`와 `LogonType=Password`로 로그오프와 재부팅 뒤에도 돈다. 이 회차는 클린 W(§2.3)에서 서버 mode로 돌고, 관리자 프롬프트와 계정 암호가 필요하다. 만드는 법과 등록 명령은 `docs/deploy/service.md`의 "Always-on" 절이 정본이다. 요약하면 `qsh-serve.task.xml`을 `qsh-serve.always-on.xml`로 복사해 `LogonTrigger`를 `BootTrigger`로 바꾸고 주체의 `LogonType`을 `Password`로 바꾼 뒤(UTF-16 BOM 유지) 관리자 프롬프트에서 다음을 친다. 암호는 프롬프트로 받으므로 셸 history와 파일에 남지 않는다. 이 qsh.exe 경로를 허용하는 Windows Defender 방화벽 인바운드 규칙이 준비 단계에서 이미 만들어져 있어야 한다(처음 `qsh serve`를 띄울 때 나오는 허용 프롬프트에 사설 네트워크로 답해 둔다, `docs/CLI.md` §6.13). 로그온·부팅 작업이 qsh를 띄울 때는 프롬프트에 답할 사용자가 없어, 규칙이 없으면 인바운드가 막혀 c가 엉뚱한 이유로 FAIL한다.

```powershell
schtasks /Create /F /TN \qsh\qsh-serve /XML "$env:USERPROFILE\.config\qsh\service\qsh-serve.always-on.xml" /RU <DOMAIN>\<계정> /RP *
```

변형은 둘이다. 개인키 저장소 {file, platform}. 변형 A는 `qsh init --key-store file`, 변형 B는 `qsh init --key-store platform`이다. W6의 정리는 identity와 `trust.toml`, L의 W pin을 남기고 `qsh init`은 이미 있는 identity 위에서 아무것도 바꾸지 않으므로(멱등, `docs/CLI.md` §6.11), 변형마다 §2.3의 클린 W에서 시작한다. `%USERPROFILE%\.config\qsh`와 `%USERPROFILE%\.local\state\qsh`를 지우고 `cmdkey /list | Select-String '\.qsh'`가 비어 있는지 본 뒤 그 변형의 `qsh init --key-store <file|platform> --json`을 돌려 출력의 `key_store`가 변형과 같은지 확인한다. 이어 W6 준비와 같은 방법으로 L이 W를 새로 pin하게 하고(L의 이전 W pin은 지우거나 `--as`로 다른 이름을 쓴다), 일반 프롬프트에서 `qsh service install`을 돌려 `qsh-serve.task.xml`을 만든다. 확인 a가 기본 작업을 먼저 요구하므로 W6의 `schtasks /Create /F /TN \qsh\qsh-serve /XML ...` 명령으로 기본 작업을 등록해 둔 상태에서 확인 a를 시작한다.

| 확인 | 합격 기준 |
|---|---|
| a. 경고 소멸 | 기본 작업을 먼저 등록한 상태에서 `qsh doctor --json`에 `logon_task_session_scoped`가 있다. 위 `/Create /F`로 상시 기동 변형을 같은 이름에 덮어 등록한 뒤에는 그 항목이 없다 |
| b. 로그오프 생존 | `schtasks /Run /TN \qsh\qsh-serve` 뒤 모든 세션을 로그오프한다. 5분 뒤에도 L의 `qsh capabilities w`가 성공한다 |
| c. 재부팅 생존 | W를 재부팅하고 로그온하지 않은 채 5분 기다린다(자동 로그온이 꺼져 있다). 그 뒤 L의 `qsh capabilities w`가 성공한다. 로그온한 뒤 `serve.err.log`에서 재부팅 이후 처음 나온 `{"lifecycle":"listening",...,"process":"serve"}` 기록(`docs/CLI.md` §6.13·§6.14; `serve.err.log`는 이어 붙으므로 b 단계의 이전 기록은 건너뛴다)의 `at`이 `(Get-CimInstance Win32_OperatingSystem).LastBootUpTime` 뒤이고 로그온 시각보다 앞이다 |
| d. 키 읽기 | 변형 B에만 적용한다. 변형 A는 "해당 없음"으로 적는다. 변형 B에서 b, c가 성립한다. 성립하지 않고 `serve.err.log`에 개인키를 읽지 못했다는 오류가 있으면 이 확인은 FAIL이고 분류는 제품 결함이다(§6). 이 확인은 ADR-0035 결정 12의 가정, 곧 `Password` 주체의 작업이 Credential Manager 항목을 읽는다는 가정을 실측한다 |

정리는 `schtasks /Delete /F /TN \qsh\qsh-serve`, 복사한 `.always-on.xml` 삭제, `qsh service uninstall`이다. 변형 B를 마친 뒤에는 `qsh identity move-key --to file`로 Credential Manager 항목을 지우고 `%USERPROFILE%\.config\qsh`를 지운다(W8의 정리와 같다).

### 4.9 W11 — 서명, SmartScreen, 설치 경로 셋

서명된 태그(§2.1)에서만 돈다. 변형은 넷이다. 서명 주체는 §2.4에 적은 `WINDOWS_SIGN_EXPECTED_SUBJECT` 값이다.

**W11a 브라우저 다운로드.** 클린 W에서 Edge로 release 페이지의 `qsh-<tag>-x86_64-pc-windows-msvc.zip`을 받아 탐색기의 "모두 압축 풀기"로 푼다(웹에서 받았다는 표시가 풀린 파일에 이어진다).

| 확인 | 합격 기준 |
|---|---|
| a1. 서명 상태 | `Get-AuthenticodeSignature .\qsh.exe \| Format-List Status, SignerCertificate, TimeStamperCertificate`에서 `Status`가 `Valid`이고 서명자 주체가 기대한 값이며 `TimeStamperCertificate`가 비어 있지 않다 |
| a2. 속성 창 | 탐색기에서 `qsh.exe` 속성의 "디지털 서명" 탭에 서명자 이름과 타임스탬프가 나온다 |
| a3. SmartScreen | 탐색기에서 `qsh.exe`를 더블클릭해 실행했을 때 "알 수 없는 게시자"를 내는 SmartScreen 창이 뜨지 않는다. 평판 경고가 게시자 이름과 함께 뜨면 그 사실을 비고에 적되 이 확인은 PASS로 본다 |
| a4. 해시 | zip의 sha256이 `SHA256SUMS`의 줄과 같다 |

**W11b `install.ps1`.** W에서 아래를 돈다.

```powershell
$env:QSH_VERSION = '<대상 태그>'
irm https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.ps1 | iex
Get-AuthenticodeSignature "$env:USERPROFILE\.local\bin\qsh.exe" | Format-List Status, SignerCertificate, TimeStamperCertificate
```

`irm ... | iex`는 main 브랜치의 `install.ps1`을 실행한다(README와 같다). 서명된 릴리스 자산은 b2가 따로 확인한다. 별도로 release의 `install.ps1` 자산을 받아 `Get-AuthenticodeSignature .\install.ps1`도 본다.

| 확인 | 합격 기준 |
|---|---|
| b1. 설치 | 스크립트가 관리자 권한을 요구하지 않고 끝난다. 설치된 `qsh.exe`의 서명이 a1과 같은 기준을 만족한다 |
| b2. 스크립트 서명 | release 자산 `install.ps1`의 `Status`가 `Valid`이고 서명자 주체가 기대한 값이며 타임스탬프가 있다 |
| b3. 체크섬 | 설치 출력에서 `verifying checksum` 줄이 `unpacking` 줄보다 앞에 있다 |

**W11c scoop.** 아래를 돈다.

```powershell
scoop bucket add qsh https://github.com/DaveDev42/scoop-bucket
scoop install qsh
Get-AuthenticodeSignature "$env:USERPROFILE\scoop\apps\qsh\current\qsh.exe" | Format-List Status, SignerCertificate, TimeStamperCertificate
qsh version
```

| 확인 | 합격 기준 |
|---|---|
| c1. 설치 | `scoop install`이 해시 검증을 지나 끝나고 `qsh version`이 대상 태그를 낸다 |
| c2. 서명 | 설치된 `qsh.exe`가 a1과 같은 기준을 만족한다 |
| c3. 같은 바이트 | 설치된 `qsh.exe`의 sha256이 W11a의 zip 안 `qsh.exe`와 같다 |
| c4. man 없음 | scoop이 `man/*.1`을 링크하거나 PATH에 올리지 않았다(zip 전체가 `apps\qsh\current`에 풀리므로 파일이 있는 것은 허용한다) |

**W11d winget.** 아래를 돈다.

```powershell
winget install DaveDev42.qsh
Get-AuthenticodeSignature (Get-Command qsh).Source | Format-List Status, SignerCertificate, TimeStamperCertificate
qsh version
```

| 확인 | 합격 기준 |
|---|---|
| d1. 설치 | `winget install`이 끝나고 새 터미널에서 `qsh version`이 대상 태그를 낸다 |
| d2. 서명 | 설치된 `qsh.exe`가 a1과 같은 기준을 만족한다 |
| d3. 같은 바이트 | 설치된 `qsh.exe`의 sha256이 W11a의 zip 안 `qsh.exe`와 같다 |

W11c와 W11d의 매니페스트는 첫 매니페스트가 수락되기 전에는 없다(README의 단서). 없는 변형은 "보류"로 적고 캠페인은 그 변형이 PASS할 때까지 열려 있다. 정리는 `scoop uninstall qsh`, `winget uninstall DaveDev42.qsh`, `install.ps1`이 둔 `%USERPROFILE%\.local\bin\qsh.exe`와 사용자 `PATH` 항목을 지우는 것이다.

### 4.10 W12 — Windows client 자동 부트스트랩

`docs/campaigns/p1-ssh-bootstrap.md` R5가 미룬 요건 4와 6을 Windows에서 본다. 장비는 W와 L(또는 M)이다. 원격 쪽 조건은 그 문서 §2.2의 장비 B와 같다. 진짜 `sshd`가 돌고, 대상 태그의 `qsh`가 비대화형 ssh 셸의 `PATH`에 있고, `qsh init`이 끝나 있고, `qsh serve`가 떠 있고 UDP 4433이 W에서 닿는다. W는 클린이다(§2.3, 특히 identity가 없는 상태에서 시작하는 것이 요점이다). W의 `%USERPROFILE%\.ssh\config`에 `Host box` / `HostName <원격>` 줄을 둔다. 원격 `~/.bashrc`에 `echo QSH-RC-SENTINEL-<난수>` 한 줄을 넣어 rc 출력이 부트스트랩 스트림 앞에 섞이게 한다(p1-ssh-bootstrap §3.1과 같다). 암호 걸린 키를 `ssh-add` 없이 쓴다. 회차가 끝나면 이 줄을 지운다.

| 확인 | 합격 기준 |
|---|---|
| a. 발동과 ssh 프롬프트 | W에서 `qsh box`를 치면 stderr에 `qsh: no qsh pin for "box"; setting one up over ssh (ssh box); set [ssh].bootstrap = "off" to disable` 한 줄이 나오고, 이어 `ssh.exe`가 같은 콘솔에서 passphrase(또는 host key 확인)를 직접 묻는다. 입력한 글자는 ssh의 규칙대로 에코되지 않으며 qsh가 가로채지 않는다 |
| b. pin | 끝난 뒤 W의 `qsh trust list`에 `box`가 role `none`으로 있고, 원격의 `qsh trust list`에 W의 항목이 role `full`에 주소가 비어 있다 |
| c. 종점 | 바로 이어서 `qsh box`의 셸 프롬프트까지 간다. 한글을 입력해 에코가 맞고 `~d`로 빠져나오면 콘솔이 cooked 모드로 돌아온다(입력 에코, 줄 편집). ssh가 묻는 동안 콘솔이 cooked였다는 것은 a의 에코 없는 입력과 이 확인이 함께 보여 준다(`auto_bootstrap_keeps_the_console_cooked_until_ssh_exits_on_windows`의 실제 콘솔 쪽 확인) |
| d. 재실행 | `qsh box`를 다시 치면 ssh를 부르지 않고 바로 접속한다. 두 번째 실행 동안 W에서 `Get-Process ssh -ErrorAction SilentlyContinue`가 비어 있고, 원격 `sshd` 로그에 그 시각의 접속 기록이 없다 |
| e. `qsh cp` 한 번 | W에서만 `qsh trust remove box`로 pin을 지우고(원격은 정리하지 않는다) 100 KiB가량의 파일을 `qsh cp C:\...\payload.bin box:/tmp/payload.bin`으로 올린다. 같은 고지 줄과 ssh 프롬프트가 나오고 ssh가 끝난 뒤에야 복사가 시작된다. 원격의 sha256과 W의 sha256이 같고 `qsh cp box:/tmp/payload.bin .`으로 내려받은 파일도 같다 |
| f. 비밀 | e의 `qsh cp`를 `qsh -vv cp … 2> boot.log`로 돌렸을 때 `Select-String -SimpleString 'QSH-RC-SENTINEL' boot.log`와 입력한 passphrase 문자열의 검색이 0건이다. `qsh audit --json` 출력에서도 0건이다. ssh 프롬프트가 stderr 리디렉션 때문에 보이지 않았다면 그 사실을 적고 f만 따로 `qsh -vv`를 리디렉션 없이 돌려 터미널 출력으로 센다 |

정리는 원격의 sentinel 줄 삭제, 원격의 pin 제거(`qsh trust remove <W 이름>`), W의 `%USERPROFILE%\.config\qsh` 삭제다.

### 4.11 판정에서 제외되는 것

Windows host가 필요한 모든 것은 이 문서의 M19 판정에 들지 않는다. 구체적으로는 Windows 장비에 `cmd.exe`·PowerShell·Windows 빌드 `vim`으로 attach하는 것, Windows host를 대상으로 하는 `qsh cp`, Windows host의 응답자(`qsh pair ssh-respond`)를 상대로 하는 `qsh pair ssh`와 `--reverse`, Linux·macOS `qsh listen` ← Windows `qsh serve --to`다. M19에서 Windows host는 PTY 세션과 `file.v1`을 `UNSUPPORTED`로 답한다(README Known limitations).

### 4.12 M20 자리

아래 셋은 M20이 이 문서에 더하고, M20의 마지막 구현 단위보다 앞서 다시 고정한다(ADR-0035 결정 18). M20이 회차를 더해도 이 문서 §1~§4.11의 문면과 §5의 규칙은 바뀌지 않는다. 바뀌는 것은 §1 표의 "M20 자리"가 "M20"으로 바뀌는 것과 새 회차 절, §5의 회차 목록 한 줄이다.

- W2. Linux·macOS client가 Windows host(`qsh serve`)에 붙어 `cmd.exe`·PowerShell·Windows 빌드 `vim` 전체 화면, 한글 입출력, resize, `Ctrl-C`.
- W3b. Linux·macOS `qsh listen` ← Windows `qsh serve --to`의 attach·`cp`·터널.
- W7. `qsh pair ssh`와 `--reverse`가 Windows OpenSSH Server를 상대로 pin을 세움(ADR-0035 결정 25).

## 5. 판정 규칙

> W1, W3a, W4, W5, W6, W8, W9, W10, W11, W12가 각각 한 번 이상 회차 표에 PASS로 기록되고, W1은 네 변형 모두에, W3a는 두 변형 모두에, W10은 두 변형 모두에, W11은 네 변형 모두에 PASS 행이 있다. 각 PASS 행에 대상 태그, §3.1의 공통 요건, 그 회차의 확인 문자가 모두 채워져 있다.

풀어 적으면 이렇다.

- PASS인 행은 §4가 그 변형에 적은 확인이 전부 PASS다. "해당 없음"으로 적을 수 있는 확인은 §4가 그렇게 허용한 것(W1의 a, 변형 A의 W10 d)뿐이다.
- 같은 회차·변형의 FAIL 행은 표에 남는다. 제품 결함을 고쳐 새 태그로 다시 돌린 행이 PASS면 그 변형은 PASS로 센다(최신의 무효 아닌 행이 판정한다). 고치기 전의 태그에서 나온 PASS는 새 태그의 FAIL을 덮지 못한다.
- "보류"(W11c·W11d의 매니페스트 없음)와 "무효"는 PASS가 아니다. 보류가 남아 있는 동안 캠페인은 열려 있다.
- W2, W3b, W7은 M20이 더하기 전에는 판정에 들지 않는다.

## 6. 사후 변경 금지와 실패 시 처분

§3의 공통 요건, §4의 회차 구성과 합격 기준, §5의 판정 규칙은 이 문서가 처음 커밋된 그대로 남는다. 회차를 돌다가 기준이 부족해 보여도 그 회차 중에는 고치지 않는다. FAIL한 행은 표에 FAIL로 남는다.

FAIL이 나오면 원인을 분류한다.

- 제품 결함 (attach 뒤 콘솔 모드가 복원되지 않았다, 창을 닫았는데 세션이 detach되지 않았다, pipe가 다른 계정에 열렸다, 작업이 재기동하지 않았다, 서명 주체가 어긋난다, `Password` 주체 작업이 개인키를 읽지 못하는데 `keystore_session_bound`가 Windows에서 나오지 않는다). 이슈로 올리고 고친 뒤 새 태그로 다시 돈다. 찍은 태그는 옮기지 않는다. W10d가 FAIL이면 고침의 일부는 Windows에서도 `keystore_session_bound`를 내는 것이다(`docs/CLI.md` §6.17, ADR-0035 결정 12).
- ssh 호환 결함 (W12). `docs/campaigns/p1-ssh-bootstrap.md` §6의 규칙을 따른다. 두 장비의 `ssh -V`와 거부 문구 원문을 이슈에 붙이고, 가짜 `ssh` 하네스에 같은 재현을 더하는 것이 고침의 일부다.
- 환경 잡음 (§2.3의 클린이 아니었다, 방화벽이 회차 설계 밖이었다, 덮개를 닫아도 절전하지 않고 화면만 꺼졌다, 서명하지 않은 태그에서 W11을 돌았다). 그 행은 PASS도 FAIL도 아닌 무효로 적고 세지 않는다.

## 7. 회차 표

| 회차 | 변형 | 날짜(UTC) | 대상 태그 | 장비 (W / host, OS 빌드, 터미널) | 확인 | 결과 | 기록자 |
|---|---|---|---|---|---|---|---|

열 채우는 법: `확인`에는 §4가 그 변형에 적은 문자를 모두 `a=PASS b=FAIL` 꼴로 적는다. `결과`는 그 문자가 모두 PASS(허용된 "해당 없음" 제외)일 때만 `PASS`다. 변형이 없는 회차는 `변형` 칸에 `-`를 적는다. 행마다 비고 문단을 표 아래에 회차·변형을 머리에 달아 잇는다. 비고에는 `qsh version`, `winver`, 터미널 종류, 호스트의 `qsh version`, 명령과 출력 원문, 막힌 지점의 원문 에러, 정리를 했는지를 적는다. W4는 반복 기록표(`docs/campaigns/p1-supervise-wake.md` §7)를, W5는 pipe 시도의 출력 원문을, W6은 `Get-CimInstance`와 `Get-NetUDPEndpoint` 출력을, W10은 부팅 시각과 `serve.err.log` 줄을 붙인다.

## 관련 문서

`docs/adr/0035-windows-client.md`(결정 5~8·11·12·14·15·16·17·18·27, 결과 절), `docs/adr/0032-service-manager-activation.md`(결정 12·15), `docs/adr/0044-ssh-bootstrap.md`(결정 2·13·16·22·25), `docs/CLI.md` §6.9·§6.13·§6.14·§6.17·§6.18·§7, `docs/deploy/service.md`(Task Scheduler 절), `docs/deploy/release-secrets.md`(Windows 서명 시크릿), `docs/design/testing.md`(플랫폼 키스토어 릴리스 전 수동 단계, Windows 줄), `docs/campaigns/p1-ssh-bootstrap.md`(R5와 W12, 형식), `docs/campaigns/p1-supervise-wake.md`(W4의 판정과 기록표), `docs/campaigns/m10-clean-vm.md`·`docs/campaigns/p1-aarch64-musl.md`(형식).
