# P1 Windows 캠페인 — 실제 Windows 장비에서 CI가 못 보는 것을 확인한다 (M19 몫)

상태: 기준 사전 고정(M19 몫). host 회차 W2, W3b, W7은 M20이 더해 다시 고정했다(§4.12~§4.14, ADR-0035 결정 18). W11은 2026-10-19 ADR-0035 개정 이력(Authenticode 서명 철회, 이어 scoop·winget 철회)에 따라 서명 확인과 scoop·winget 변형을 빼고 `cargo install` 변형을 더해 다시 고정했다(§2.1, §4.9). 회차가 돌기 전의 재고정이라 §6의 사후 변경 금지에 걸리지 않는다. 대상 태그는 `v0.5.0`이다(§2.4). 2026-10-21 에이전트가 W8과 W11 b·c를 돌렸다(§7). ADR-0046(Windows 기본 bind의 IPv4 수용)과 W11c c1의 수정을 담은 `v0.5.1`을 2026-10-22 대상 태그 줄로 더했다(§2.4). W2·W3a·W3b·W7과 W11c 재실행은 이 태그에서 돈다.

## 1. 목적과 지위

ADR-0035는 Windows를 Linux·macOS와 같은 기능으로 연다. M19는 client 쪽(콘솔 raw 모드 attach, named pipe localctl과 `qsh listen` 데몬, Credential Manager, 작업 스케줄러 서비스, 설치 경로)를 연다. `windows-latest` 다리의 CI가 같은 러너 안 loopback으로 정방향·역방향 종단을 돌리므로(ADR-0035 결정 17) 이 캠페인은 CI가 볼 수 없는 것만 본다. 예를 들면 실제 터미널의 렌더링과 IME, 노트북 덮개, 둘째 사용자 계정, 로그온·로그오프·재부팅에 걸린 작업의 수명, 두 장비 사이의 UDP, 미서명 바이너리에 대한 SmartScreen, 패키지 관리자다.

CI가 이미 맡는 것은 여기서 다시 하지 않는다. 대표적으로 콘솔 모드 비트와 복원 경로(`windows_attach::`), pipe의 DACL·SID 대조·이름 선점 거부(`pipe_server_drops_a_client_with_another_sid_before_reading_a_frame`, `pipe_bind_fails_when_the_name_already_exists`), 절전 표본의 단조성(`windows_wake_sample_is_monotonic`), Credential Manager의 러너 왕복(`credential_manager_round_trip_on_the_runner`), `install.ps1`의 체크섬 선행(`install_ps1_verifies_the_checksum_before_extracting`), 가짜 ssh 위의 Windows 자동 부트스트랩(`auto_bootstrap_keeps_the_console_cooked_until_ssh_exits_on_windows`)이다. 이 문서의 회차는 그 테스트가 대신 볼 수 없는 실제 환경의 동작이다.

지위는 `docs/campaigns/p1-ssh-bootstrap.md`와 같다. `docs/ROADMAP.md` §5.1 원칙 6에 따라 M19의 DoD는 이 문서가 사전 고정돼 커밋되는 데까지이고, 회차는 §5.5의 사람 몫이다. 마일스톤을 막지 않고 P1 완료 선언을 막는다. 판정은 합격/불합격이고, PASS가 기록되기 전에는 해당 기능이 실제 Windows에서 동작한다고 적지 않는다. 자동 테스트로 대신하지 않는다. 시간을 재지 않으며 합격은 아래 확인의 충족이다. 형식은 `docs/campaigns/p1-ssh-bootstrap.md`, `docs/campaigns/p1-supervise-wake.md`, `docs/campaigns/m10-clean-vm.md`를 따른다.

회차 이름은 ADR-0035 결정 18의 번호를 그대로 쓴다. 번호가 비는 자리는 host 회차이고 M20이 채운다.

| 회차 | 내용 | 몫 |
|---|---|---|
| W1 | Windows Terminal과 conhost에서 Linux·macOS host로 attach | M19 |
| W2 | Linux·macOS client가 Windows host(`qsh serve`)에 attach | M20 |
| W3a | Windows `qsh listen` ← Linux·macOS `qsh serve --to` (attach, `cp`, 터널) | M19 |
| W3b | Linux·macOS `qsh listen` ← Windows `qsh serve --to` | M20 |
| W4 | 절전 복귀 | M19 |
| W5 | 둘째 Windows 계정의 pipe 접속 거부와 이름 선점 거부 | M19 |
| W6 | 로그온 작업의 로그온 기동, 강제 종료 뒤 재기동, 로그오프 정지 | M19 |
| W7 | `qsh pair ssh`·`--reverse`가 Windows OpenSSH Server를 상대로 pin을 세움 | M20 |
| W8 | Credential Manager 왕복 | M19 |
| W9 | Windows on ARM에서 W1 축약 | M19 |
| W10 | 상시 기동 변형의 로그오프·재부팅 생존과 `logon_task_session_scoped` 소멸 | M19 |
| W11 | 미서명 SmartScreen 경고, `install.ps1`·`cargo install --locked --git` | M19 |
| W12 | Windows client 자동 부트스트랩(`qsh box`, `qsh cp`) | M19 |

W12는 ADR-0035 결정 18의 번호가 아니다. `docs/campaigns/p1-ssh-bootstrap.md`의 R5가 요건 4와 6(`qsh box`의 대화형 attach와 `qsh cp`)을 M19로 미뤘고, R5의 문면은 고치지 않는 대신 그 몫을 W12가 받는다.

## 2. 선행 조건

### 2.1 대상 태그

회차는 Windows 자산이 붙은 태그를 대상으로 한다. 아래가 모두 성립해야 하고, 태그가 없는 동안 회차는 열리지 않는다.

- 그 태그의 release run이 초록이다.
- 그 태그의 `SHA256SUMS`에 `qsh-<tag>-x86_64-pc-windows-msvc.zip`, `qsh-<tag>-aarch64-pc-windows-msvc.zip` 줄이 있고 release에 `install.ps1` 자산이 있다. `release` job의 `Check every target is published` 스텝이 이 사실을 붉게 만들지만 회차 시작 전에 사람이 한 번 더 본다.
- W11은 서명 여부를 따지지 않는다. Windows 자산은 미서명으로 배포한다(ADR-0035 개정 이력, 2026-10-19).
- W11의 `cargo install` 변형은 그 태그가 `DaveDev42/qsh` 저장소에 푸시돼 있어야 돈다(`--tag`로 고른다). scoop·winget 배포는 철회했다(ADR-0035 개정 이력, 2026-10-19).

### 2.2 장비

| 이름 | 조건 |
|---|---|
| W | 실제 Windows 10 1809 이상 또는 Windows 11 장비. x86_64. Windows Terminal이 설치돼 있고, 기본 탑재 `ssh.exe`(선택적 기능 OpenSSH Client)가 있다. PowerShell 7(`pwsh`)이 있다. W4는 노트북이어야 한다 |
| 계정 B | W5 전용. W에 만드는 둘째 표준(비관리자) 로컬 계정. 만드는 데 관리자 권한이 한 번 든다. 회차 W2와 무관하다 |
| L | Linux 장비. 대상 태그의 `qsh`가 `PATH`에 있고(`ssh L 'command -v qsh'`로 확인) 진짜 `sshd`가 돈다. `qsh init`이 끝나 있다. W에서 UDP 4433이 닿는다. W 안의 WSL2 배포판도 L로 쓸 수 있다(아래 문단) |
| M | macOS 장비. L과 같은 조건. 기본 셸은 zsh |
| W-ARM | W9 전용. Windows on ARM 장비(Windows 11 ARM64) |

W와 L, W와 M은 서로 다른 장비다. 한 장비 안의 loopback은 회차로 세지 않는다. 예외가 하나 있다. W에 깔린 WSL2 배포판은 L이 될 수 있다. WSL2는 W와 커널도 IP 스택도 따로 쓰는 VM이라 그 사이의 연결은 loopback이 아니다. 이때 W는 WSL2 배포판 자신의 주소(그 배포판의 Tailscale 주소처럼 VM 밖에서 그 VM으로 들어가는 주소)로 닿아야 하고, WSL의 `localhost` 포워딩을 거친 연결은 세지 않는다. 그 행의 장비 칸과 비고에는 L이 W 안의 WSL2이고 두 물리 장비 사이의 네트워크 경로는 거치지 않았다고 적는다. 물리 경로는 같은 회차의 M 변형이 본다. 이 예외는 2026-10-26 사용자 승인으로 더했다. §2는 §6의 사후 변경 금지 대상(§3~§5)이 아니고, L 변형은 이때까지 한 번도 돌지 않았다. L과 M은 같은 날 같은 대상 태그의 바이너리를 쓴다. W3a는 W가 L 또는 M에서 UDP로 닿는 주소를 가져야 한다. 처음 `qsh listen`을 띄울 때 Windows Defender 방화벽이 허용 여부를 물으면 사설 네트워크에서 허용하고 그 사실을 비고에 적는다(`docs/CLI.md` §6.13).

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
| 대상 태그 | `v0.5.0` |
| 태그의 커밋 SHA | `1c653e0b6046fcdfb15ffa1781c4e9d69fa44d8b` |
| release run | 39354944687 |
| `SHA256SUMS`의 x86_64 zip 줄 | `7b9653a6e3899581664ec615508af72f16267367f613457a5c42c94c9609bc5d  qsh-v0.5.0-x86_64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 aarch64 zip 줄 | `0beef1310347d76552395f0e384666a7ccc6b150f25a647543a414e4a8ffaa42  qsh-v0.5.0-aarch64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 `install.ps1` 줄 | `eef4c2dd497798c0ee4d8f4d0cfd6e8f076f14d886ab6cab664c449c0824db05  install.ps1` |
| 대상 태그 | `v0.5.1` |
| 태그의 커밋 SHA | `b4639a896a6e4728d3e8787c522cab3ae4466a74` |
| release run | 39723802624 |
| `SHA256SUMS`의 x86_64 zip 줄 | `3a0305b61c33155d433e69ecfcc9d2b2eb24038ffdd835d2fd8bea94d1d65e4e  qsh-v0.5.1-x86_64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 aarch64 zip 줄 | `c3011a549be110bc50735d26310f85d34ba199ee9caa71cc92dee66d86d762f7  qsh-v0.5.1-aarch64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 `install.ps1` 줄 | `eef4c2dd497798c0ee4d8f4d0cfd6e8f076f14d886ab6cab664c449c0824db05  install.ps1` |
| 대상 태그 | `v0.5.2` |
| 태그의 커밋 SHA | `42407678cafa4c1fa0ca30e8f9df619f57b8d335` |
| release run | 40103741549 |
| `SHA256SUMS`의 x86_64 zip 줄 | `954c8f0d2332630a06ca3ad8dfc9912e134f2acd37a0d071b4f4b966c413f914  qsh-v0.5.2-x86_64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 aarch64 zip 줄 | `3945d0952cceb0932401ceed3d49b089c488f61defffd1bc5111353bf6ab582d  qsh-v0.5.2-aarch64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 `install.ps1` 줄 | `eef4c2dd497798c0ee4d8f4d0cfd6e8f076f14d886ab6cab664c449c0824db05  install.ps1` |
| 대상 태그 | `v0.5.3` |
| 태그의 커밋 SHA | `061bec3acb4dbf8ffe36c59747034cbb409bea94` |
| release run | 40170789979 |
| `SHA256SUMS`의 x86_64 zip 줄 | `41444f592bf6e21b5e046615a3c5235118f01f6719c29ad8b2681ec0889e609d  qsh-v0.5.3-x86_64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 aarch64 zip 줄 | `ad41e7c85abc70adfc29370532faabd22124547e29b52e8916ea21e33d13c172  qsh-v0.5.3-aarch64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 `install.ps1` 줄 | `eef4c2dd497798c0ee4d8f4d0cfd6e8f076f14d886ab6cab664c449c0824db05  install.ps1` |
| 대상 태그 | `v0.5.4` |
| 태그의 커밋 SHA | `2385c7d05d0f2e7cbfdf52e17b1e28140cbd5b24` |
| release run | 40282863613 |
| `SHA256SUMS`의 x86_64 zip 줄 | `0551a71dd59a005dde14b75674488a711cf7240aa47b1b71ea70e0b45dfa3ae6  qsh-v0.5.4-x86_64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 aarch64 zip 줄 | `02e772d78568c8a364ec3e66413d3ec733445bd88c26b10c21cb48e14cdf5fd3  qsh-v0.5.4-aarch64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 `install.ps1` 줄 | `eef4c2dd497798c0ee4d8f4d0cfd6e8f076f14d886ab6cab664c449c0824db05  install.ps1` |
| 대상 태그 | `v0.5.5` |
| 태그의 커밋 SHA | `297398663304b7ba6a65d70f206f9af40690375d` |
| release run | 40292583227 |
| `SHA256SUMS`의 x86_64 zip 줄 | `11208080c347a28c152f7b4b09d29bfefa58449e801a958ac41aaf4533374283  qsh-v0.5.5-x86_64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 aarch64 zip 줄 | `9a860fb45826c6b9c9ad2cf9392acf1c13ef1a5d1691d1c152e586dca5042f3c  qsh-v0.5.5-aarch64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 `install.ps1` 줄 | `eef4c2dd497798c0ee4d8f4d0cfd6e8f076f14d886ab6cab664c449c0824db05  install.ps1` |
| 대상 태그 | `v0.5.6` |
| 태그의 커밋 SHA | `184fce2c2e106853ea6793e2f6c5a96d3a709e44` |
| release run | 40334776944 |
| `SHA256SUMS`의 x86_64 zip 줄 | `c0af7b568de05b0dfe5463458cb850f64f80218deeaffae86b3a8242c7efd178  qsh-v0.5.6-x86_64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 aarch64 zip 줄 | `fb2ecb738be7003f3e89b60d91875f8ff4097ee2e2da6ecc480acff47291341f  qsh-v0.5.6-aarch64-pc-windows-msvc.zip` |
| `SHA256SUMS`의 `install.ps1` 줄 | `eef4c2dd497798c0ee4d8f4d0cfd6e8f076f14d886ab6cab664c449c0824db05  install.ps1` |

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

### 4.9 W11 — 미서명 SmartScreen 경고, 설치 경로

Windows 자산은 서명하지 않는다(ADR-0035 개정 이력, 2026-10-19). 이 회차는 미서명이 안내한 대로(README Known limitations) 동작하는지와 설치 경로(`install.ps1`, `cargo install`)가 바이너리를 설치하는지를 본다. 변형은 셋이다. scoop·winget은 ADR-0035 개정 이력(2026-10-19)으로 철회했다.

**W11a 브라우저 다운로드.** 클린 W에서 Edge로 release 페이지의 `qsh-<tag>-x86_64-pc-windows-msvc.zip`을 받아 탐색기의 "모두 압축 풀기"로 푼다(웹에서 받았다는 표시가 풀린 파일에 이어진다).

| 확인 | 합격 기준 |
|---|---|
| a1. SmartScreen | 탐색기에서 `qsh.exe`를 더블클릭하면 게시자가 "알 수 없는 게시자"인 SmartScreen 창이 뜨고, "추가 정보 → 실행"으로 실행할 수 있다. Smart App Control이 켜져 있어 실행이 막히면 그 사실을 비고에 적고 이 확인은 "해당 없음"으로 적는다(막힘은 README가 안내하는 동작이다) |
| a2. 실행 | 터미널에서 `qsh version`이 대상 태그를 낸다 |
| a3. 해시 | zip의 sha256이 `SHA256SUMS`의 줄과 같다 |

**W11b `install.ps1`.** W에서 아래를 돈다.

```powershell
$env:QSH_VERSION = '<대상 태그>'
irm https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.ps1 | iex
qsh version
```

`irm ... | iex`는 main 브랜치의 `install.ps1`을 실행한다(README와 같다).

| 확인 | 합격 기준 |
|---|---|
| b1. 설치 | 스크립트가 관리자 권한을 요구하지 않고 끝나고, 새 터미널에서 `qsh version`이 대상 태그를 낸다 |
| b2. 체크섬 | 설치 출력에서 `verifying checksum` 줄이 `unpacking` 줄보다 앞에 있다 |

**W11c `cargo install`.** 클린 W에서 rustup(MSVC 툴체인)과 Visual Studio Build Tools의 "Desktop development with C++" 워크로드가 갖춰져 있고 `qsh`가 `PATH`에 없는 상태에서 일반(비관리자) PowerShell로 아래를 돈다. README의 줄은 기본 브랜치를 설치하므로 대상 태그를 `--tag`로 고정한다.

```powershell
cargo install --locked --git https://github.com/DaveDev42/qsh --tag <대상 태그> qsh-cli
qsh version
```

| 확인 | 합격 기준 |
|---|---|
| c1. 설치 | 관리자 권한 없이 빌드와 설치가 끝나고(비고에 소요 시간과 추가로 설치해야 했던 도구를 적는다), 새 터미널에서 `qsh version`이 대상 태그와 태그의 커밋 SHA(§2.4)를 낸다 |
| c2. 위치 | `Get-Command qsh`가 `%USERPROFILE%\.cargo\bin\qsh.exe`를 가리킨다 |

정리는 `cargo uninstall qsh-cli`와 `install.ps1`이 둔 `%USERPROFILE%\.local\bin\qsh.exe`, 사용자 `PATH` 항목을 지우는 것이다.

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

### 4.12 W2 — Linux·macOS client가 Windows host(`qsh serve`)에 attach

변형은 둘이다. client {L, M}. Windows host는 WH라 부른다(실제 Windows 11 x86_64 장비, §2.3의 클린). WH와 client는 서로 다른 장비이고 사이의 UDP는 실제 망을 지난다. WH에는 Windows Terminal이 있고, Windows용 `vim.exe`가 `PATH`에 있고, PowerShell 7(`pwsh`)이 있다. WH에서 `qsh init --json`을 마쳐 두고 그 출력의 `fingerprint`를 적어 둔다. client는 대상 태그의 `qsh`가 `PATH`에 있고 `qsh init`이 끝나 있다.

방화벽 준비는 이렇다. 이 회차는 WH의 방화벽에 qsh용 허용 규칙이 없는 채로 시작한다(`Get-NetFirewallApplicationFilter -Program <qsh.exe 전체 경로>`가 비어 있다). WH가 Windows Server 2022 이상 장비면 같은 회차를 client L로 한 번 더 돌고 그 행을 "Server"라고 변형 칸에 적는다. 이 행은 참고 행이라 §5의 판정에는 필요하지 않다. 장비가 없으면 돌지 않고 비워 둔다.

pin은 양쪽에서 직접 세운다. 방화벽 확인 a가 허용 전에 닿지 않는 상태를 먼저 봐야 하므로 코드 pairing(UDP로 닿아야 한다)을 쓰지 않는다. client에서 `qsh trust add win --address <WH 주소>:4433 --fingerprint <WH의 fingerprint>`를 친다. 이 명령은 연결하지 않고 pin만 쓴다. 이어 client에서 `qsh identity export --out client.pem`으로 인증서를 받아 WH로 옮기고 WH에서 `qsh trust add client --cert-file client.pem --role full`을 친다.

| 확인 | 합격 기준 |
|---|---|
| a. 방화벽 첫 허용 프롬프트 | WH에서 `qsh serve`를 처음 띄우면 Windows Defender 방화벽이 허용 여부를 묻고 창이 가리키는 프로그램이 그 `qsh.exe` 경로다. 허용하기 전에(취소하거나 창을 둔 채로) client에서 `qsh doctor win --json`을 돌리면 `data.findings`에 `udp_egress_blocked`가 있고 그 `remedy`가 상대 Windows 방화벽을 안내한다. 사설 네트워크에서 허용한 뒤 같은 명령에는 그 finding이 없다. `qsh serve`를 끄고 같은 경로에서 다시 띄우면 묻지 않는다. 같은 `qsh.exe`를 다른 경로로 복사해 거기서 띄우면 다시 묻는다. 허용하지 않은 새 경로에서 `qsh serve --to <client 주소>:4433`(연결은 실패해도 된다)과 `qsh serve --bind 127.0.0.1:4434`를 띄우면 묻지 않는다. 마지막으로 이 프롬프트의 시점과 단위, `udp_egress_blocked`와의 관계가 `README.md` Known limitations의 Windows 방화벽 문장과 `docs/CLI.md` §6.13의 방화벽 항목, `qsh doctor`의 `remedy` 문구와 어긋나지 않는다. 어긋남은 비고에 원문으로 적는다 |
| b. attach와 한글 입출력 | client에서 `qsh win`이 `cmd.exe` 프롬프트까지 간다. `echo 한글 테스트`의 출력이 입력과 같고 한글을 입력하다 Backspace로 지우면 한 글자만 지워진다. `ping -t 127.0.0.1`을 Ctrl-C로 끊으면 `ping`만 끊기고 `cmd.exe`는 남는다. `powershell.exe`(또는 `pwsh`)를 쳐서 들어가 `'한글 테스트 😀'`의 출력이 같고 위쪽 화살표로 직전 명령이 나온다 |
| c. 전체 화면 | PowerShell 안에서 `vim`을 열어 한글을 입력하고 client 창을 줄였다 늘린다. 창 크기를 바꾼 뒤 vim에서 `:echo &columns &lines`가 새 크기를 내고 vim의 하단 줄이 창의 마지막 행에 있다. `cmd.exe`에서도 `mode con`의 `Columns`·`Lines`가 새 크기를 낸다. `:q!` 뒤 vim을 열기 전의 화면이 복원된다 |
| d. 새 세션의 셸 | `qsh session open win --json -- pwsh -NoLogo`로 PowerShell 7 세션을 열고 `qsh attach <session-ref>`로 붙는다. 프롬프트에서 `ping -t 127.0.0.1`을 돌려 두고, `$env:QSH_SIGNAL_EVENT_USR1`이 비어 있지 않은지 다른 PowerShell 세션 하나를 열어 본다. `$env:USERPROFILE`은 WH 계정의 프로필 디렉터리다. |
| e. `~d`와 resume | 행 시작에서 `~d`를 치면 client 셸 프롬프트로 돌아오고 종료 코드는 0이다. `qsh sessions win`에 그 세션이 있고 `qsh attach <session-ref>`로 붙으면 detach 전의 화면 내용이 보이고 d에서 돌려 둔 `ping -t`의 새 출력이 이어진다 |
| f. 신호 | 터미널 하나에서 `qsh session open win --json -- ping -t 127.0.0.1`을 열고 다른 터미널에서 `qsh session read <session-ref> --follow --jsonl`을 돌려 둔다. `qsh session close <session-ref> --signal INT`를 치면 follow 쪽에 `session.exit`가 오고 `signal`이 `SIGINT`이며 이어서 `session.closed`가 온다. 이어 `qsh session open win --json -- pwsh -NoProfile -Command '[System.Threading.EventWaitHandle]::OpenExisting($env:QSH_SIGNAL_EVENT_USR1).WaitOne() \| Out-Null; Write-Output got-usr1'`로 세션을 열고 같은 방식으로 follow를 돌린 뒤 `qsh session close <session-ref> --signal USR1`을 치면 출력에 `got-usr1`이 오고 `session.exit`의 `exit_code`가 0이며 `signal`이 `null`이다(ADR-0047, 아래 문단). |

f의 USR1 기준은 2026-10-26에 사용자 승인으로 고쳤다. 처음 기준은 `exit_code` 0과 `signal` `SIGUSR1`을 함께 요구했는데 `docs/CLI.md` §6.4가 둘 중 하나만 채우게 하므로 어느 구현으로도 나올 수 없었다. v0.5.4의 W2 L 회차가 `"exit_code":null,"signal":"SIGUSR1"`을 냈고, unix host는 같은 프로그램에 `exit_code` 0과 `signal` `null`을 내므로 ADR-0047이 Windows를 unix에 맞췄다. §4는 §6의 사후 변경 금지에 걸리므로 이 정정은 그 금지에 대한 사용자 승인 예외로 기록한다. 고치기 전 기준으로 돈 v0.5.4 행은 §6대로 FAIL로 남는다.

b와 c는 client마다 따로 돌고, 창 크기는 줄이고 늘리기를 각각 두 번 한다. 한글은 client 터미널의 IME로 직접 친다.

정리는 열어 둔 세션을 `qsh session close`로 닫고 `qsh serve`를 끈 뒤 WH에서 이 회차가 만든 방화벽 규칙을 지운다(`Get-NetFirewallApplicationFilter -Program <경로> | Get-NetFirewallRule | Remove-NetFirewallRule`, 복사해 둔 `qsh.exe`마다). 비고에는 프롬프트의 원문과 창이 가리킨 경로, `qsh doctor win --json`의 허용 전후 출력, WH가 Windows 11인지 Server인지를 적는다.

### 4.13 W3b — Linux·macOS `qsh listen` ← Windows `qsh serve --to`

변형은 둘이다. controller {L, M}. WH(실제 Windows 11 x86_64, §2.3의 클린)가 target으로 controller에 dial한다. 두 장비 사이의 실제 UDP 경로를 쓴다. 이 회차는 WH의 방화벽에 qsh용 허용 규칙이 없는 채로 돈다. `qsh serve --to`는 dial만 하므로 규칙이 없어도 동작해야 하고, 그 사실이 이 회차의 확인 a다. WH의 `qsh init`을 마쳐 두고 controller에서 UDP 4433이 WH에서 닿는다.

pin은 W3a의 대체 경로와 같다. WH의 `qsh identity export --out win.pem`을 controller로 옮겨 controller에서 `qsh trust add win --cert-file win.pem --role reverse`를 치고, controller의 `qsh identity export --out ctl.pem`을 WH로 옮겨 WH에서 `qsh trust add ctl --address <controller 주소>:4433 --cert-file ctl.pem --role full`을 친다. controller에서 `qsh listen`을 띄우고 WH에서 `qsh serve --to ctl`을 띄운다. WH에서 `qsh serve --to`를 띄우는 `qsh.exe`는 이 장비에서 `qsh serve`나 `qsh listen`을 띄운 적이 없는 경로의 것이다.

| 확인 | 합격 기준 |
|---|---|
| a. 등록과 방화벽 | controller의 `qsh hosts`에 `win`이 `connection_mode: reverse`, `state: reachable`로 오른다. 그동안 WH에 방화벽 허용 프롬프트가 뜨지 않았고 `Get-NetFirewallApplicationFilter -Program <qsh.exe 전체 경로>`가 비어 있다 |
| b. attach | controller에서 `qsh win`으로 `cmd.exe` 프롬프트가 열리고 `echo 한글 테스트`의 출력이 같다. `~d`로 빠져나온 뒤 `qsh sessions win`에 세션이 보이고 `qsh attach <session-ref>`로 다시 붙는다. W2의 c 확인(vim 전체 화면과 resize)을 이 경로에서 한 번 더 한다 |
| c. `cp` | 올리기와 내려받기를 모두 본다. controller에서 `qsh cp ./payload.bin win:C:/Users/Public/payload.bin`으로 올리고 `qsh cp win:C:/Users/Public/payload.bin ./back.bin`으로 내려받는다(드라이브 경로는 슬래시로 적는다). 앞뒤 파일의 sha256이 같다. `qsh cp -r`로 작은 디렉터리를 한 번 옮기고 `qsh cp ./payload.bin win:`으로 WH 프로필 디렉터리에 올려도 된다. 소유자 쓰기 비트를 끈 파일(`chmod 444`)을 `qsh cp -p`로 올리면 WH에서 `attrib`에 읽기 전용 특성(`R`)이 보이고, 같은 이름으로 다시 올리면 교체된다. `qsh cp -p win:<그 파일> .`로 내려받은 파일의 모드는 `0444`다. `qsh cp ./payload.bin 'win:\\server\share\x'`는 WH에서 아무것도 만들지 않은 채 `INVALID_ARGUMENT`로 끝난다 |
| d. 터널 | `-R`: controller에서 `socat TCP-LISTEN:7000,bind=127.0.0.1,fork EXEC:cat` 같은 echo 서버를 띄우고 `qsh tunnel open win --remote 19000:127.0.0.1:7000 --json`(대화형 form의 `-R`과 같은 인자)을 돌린 뒤 WH에서 §3.2의 echo 확인 클라이언트(`<port>`는 19000)가 같은 바이트를 받는다. `-L`: WH에서 §3.2의 echo 서버(7777)를 띄우고 controller에서 `qsh tunnel open win --local 127.0.0.1:18080:127.0.0.1:7777 --json`을 돌려 `printf 'hello-qsh\n' \| nc -w1 127.0.0.1 18080`이 `hello-qsh`를 받는다. `--remote` 터널은 `qsh tunnels`에 나오고 `qsh tunnel close <tunnel-id>`로 닫으면 WH의 19000 포트가 사라진다(`Get-NetTCPConnection -State Listen -LocalPort 19000`). `--local` 터널은 `tunnel open`을 Ctrl-C로 끝내면 사라진다 |
| e. controller 재시작 | controller의 `qsh listen`을 Ctrl-C로 끄면 WH의 stderr에 `lost`가 나오고, 다시 띄우면 WH가 `registered`를 낸다. 2분 안에 controller의 `qsh hosts`에 `win`이 다시 `reachable`로 오른다 |

정리는 열어 둔 터널과 세션을 닫고 `qsh listen`과 WH의 `qsh serve --to`를 끈다. 비고에는 WH의 방화벽 규칙 조회 출력과 `qsh hosts`의 `win` 행 원문, 터널 확인의 출력을 붙인다.

### 4.14 W7 — `qsh pair ssh`와 `--reverse`가 Windows OpenSSH Server를 상대로 pin을 세움

변형은 둘이다. 원격 기본 셸 {A: `cmd.exe`, B: PowerShell}. 원격 장비는 WR이라 부른다(실제 Windows 11 x86_64 또는 Windows Server 2022 이상, §2.3의 클린). 주도하는 장비는 client {L, M}이고 변형마다 어느 쪽이든 하나를 쓴다. 한 변형 안에서 정방향과 `--reverse`를 모두 본다.

WR 쪽 준비는 이렇다. 관리자 프롬프트에서 선택적 기능 OpenSSH Server를 켠다.

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
Get-NetFirewallRule -Name '*ssh*' | Select-Object Name, Enabled, Direction
```

마지막 줄에서 TCP 22 인바운드 규칙이 켜져 있는지 본다. 없으면 만든다(`New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow`). 정방향은 WR의 `qsh serve`가 UDP 4433으로 닿아야 하므로 WR에서 `qsh serve`를 한 번 띄워 방화벽 프롬프트에 사설 네트워크로 허용해 둔다(`docs/CLI.md` §6.13). 역방향은 WR이 client로 dial하므로 이 규칙이 필요 없고, client에서 `qsh listen`이 UDP 4433으로 WR에서 닿는다. WR에서 `qsh init`을 마친다. client의 `~/.ssh/config`에 `Host winbox` / `HostName <WR 주소>` / `User <WR 계정>`을 적고 `ssh winbox`가 비밀번호나 공개 키로 먼저 로그인되는지 본다(관리자 계정의 공개 키는 `C:\ProgramData\ssh\administrators_authorized_keys`에 둔다). `qsh.exe`는 WR의 ssh 로그인 셸에서 `PATH`로 풀려야 한다(`ssh winbox where qsh`가 변형 A에서, `ssh winbox 'Get-Command qsh'`가 변형 B에서 경로를 낸다). 변형 B는 WR에서 기본 셸을 바꾼다.

```powershell
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -PropertyType String -Force -Value 'C:\Program Files\PowerShell\7\pwsh.exe'
```

기본 셸을 바꾼 뒤에는 새 ssh 연결을 연다(`ssh winbox '$PSVersionTable.PSVersion.Major'`가 7을 낸다). 변형 A는 이 값이 없는 기본 상태다.

| 확인 | 합격 기준 |
|---|---|
| a. 정방향 pin | WR에서 `qsh serve`가 떠 있는 채로 client에서 `qsh pair ssh winbox --json`이 종료 코드 0이다. 봉투의 `data.direction`이 `forward`, `data.verified`가 `true`이고 client의 `qsh trust list`에 `winbox`가 role `none`으로, WR의 `qsh trust list`에 client의 항목이 role `full`에 주소가 비어 있는 채로 있다. 이어 `qsh exec winbox --json -- cmd /c ver`가 성공한다 |
| b. serve 없이 | a의 pin을 양쪽에서 지우고(`qsh trust remove`, 이름은 `qsh trust list`로 본다) WR의 `qsh serve`를 끈 채로 같은 명령을 다시 친다. 종료 코드 0, `data.verified`가 `false`이고 `verify_error`가 있으며 pin은 양쪽에 서 있다. `verify_error`의 원문은 비고에 적는다. 이 확인은 응답자가 쓰는 UDP bind 시험(`serve_listening`)을 실제 Windows에서 본다 |
| c. 역방향 pin | b의 pin을 양쪽에서 지운 뒤 client에서 `qsh listen`을 띄우고 다른 터미널에서 `qsh pair ssh winbox --reverse --to <client 주소>:4433 --json`을 친다. 종료 코드 0, `data.direction`이 `reverse`, `data.verified`가 `false`이고 `data.next_command`가 `qsh serve --to <이름>`이다. client의 pin은 role `reverse`에 주소가 비어 있고, WR의 pin은 role `full`에 주소가 `--to` 값이다. `next_command`를 WR에서 그대로 치면 2분 안에 client의 `qsh hosts`에 `winbox`가 `connection_mode: reverse`, `state: reachable`로 오른다. 이 상태에서 `qsh exec winbox --json -- cmd /c ver`가 성공한다 |
| d. `PATH`에 `qsh`가 없을 때 | c가 끝나면 WR의 `qsh serve --to`를 끄고 양쪽 pin을 지운다. WR에서 `qsh.exe`를 `PATH`에 없는 디렉터리로 옮기고(경로를 적어 둔다) client에서 `qsh pair ssh winbox --json`을 친다. 변형 A는 오류 코드가 `REMOTE_ERROR`이고 `details.reason`이 `remote_qsh_missing`이며 message가 `--remote-qsh`와 `[ssh].remote_qsh`를 안내한다. 변형 B는 `REMOTE_ERROR`에 `details.reason`이 `remote_command_failed`, `details.remote_exit`가 1이고 message가 `qsh.exe`를 원격 `PATH`에 두거나 전체 경로를 주라고 안내한다. 어느 쪽이든 client에 `winbox` pin이 생기지 않는다 |
| e. 전체 경로 | d의 상태에서 `qsh pair ssh winbox --remote-qsh 'C:\Tools\qsh\qsh.exe' --json`(옮긴 경로를 적는다. 공백이 없는 경로를 쓴다)이 a와 같은 결과로 끝난다 |
| f. 비밀 | a와 c를 `qsh -vv pair ssh …`로 돌린 출력과 `qsh audit --json` 출력에서, 입력한 passphrase나 암호가 있으면 그 문자열의 검색이 0건이다 |

정리는 WR에서 `qsh serve`와 `qsh serve --to`를 끄고 `qsh trust remove`로 이 회차의 pin을 지우며(client 쪽도 같다), 옮긴 `qsh.exe`를 되돌리고, 변형 B를 끝낸 뒤 `Remove-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell`로 기본 셸을 되돌린다. 이 회차를 위해 켠 OpenSSH Server를 끄려면 `Stop-Service sshd`와 `Set-Service -Name sshd -StartupType Disabled`를 쓴다. 비고에는 `ssh -V`(client)와 WR의 OpenSSH Server 버전(`Get-WindowsCapability -Online -Name OpenSSH.Server*`), 기본 셸 설정, 각 확인의 봉투 원문, d의 거부 문구 원문을 적는다.

## 5. 판정 규칙

> W1, W2, W3a, W3b, W4, W5, W6, W7, W8, W9, W10, W11, W12가 각각 한 번 이상 회차 표에 PASS로 기록되고, W1은 네 변형 모두에, W2는 두 변형 모두에, W3a는 두 변형 모두에, W3b는 두 변형 모두에, W7은 두 변형 모두에, W10은 두 변형 모두에, W11은 세 변형 모두에 PASS 행이 있다. 각 PASS 행에 대상 태그, §3.1의 공통 요건, 그 회차의 확인 문자가 모두 채워져 있다.

풀어 적으면 이렇다.

- PASS인 행은 §4가 그 변형에 적은 확인이 전부 PASS다. "해당 없음"으로 적을 수 있는 확인은 §4가 그렇게 허용한 것(W1의 a, 변형 A의 W10 d)뿐이다.
- 같은 회차·변형의 FAIL 행은 표에 남는다. 제품 결함을 고쳐 새 태그로 다시 돌린 행이 PASS면 그 변형은 PASS로 센다(최신의 무효 아닌 행이 판정한다). 고치기 전의 태그에서 나온 PASS는 새 태그의 FAIL을 덮지 못한다.
- "보류"와 "무효"는 PASS가 아니다. 보류가 남아 있는 동안 캠페인은 열려 있다.

## 6. 사후 변경 금지와 실패 시 처분

§3의 공통 요건, §4의 회차 구성과 합격 기준, §5의 판정 규칙은 이 문서가 처음 커밋된 그대로 남는다. 회차를 돌다가 기준이 부족해 보여도 그 회차 중에는 고치지 않는다. FAIL한 행은 표에 FAIL로 남는다.

FAIL이 나오면 원인을 분류한다.

- 제품 결함 (attach 뒤 콘솔 모드가 복원되지 않았다, 창을 닫았는데 세션이 detach되지 않았다, pipe가 다른 계정에 열렸다, 작업이 재기동하지 않았다, `Password` 주체 작업이 개인키를 읽지 못하는데 `keystore_session_bound`가 Windows에서 나오지 않는다). 이슈로 올리고 고친 뒤 새 태그로 다시 돈다. 찍은 태그는 옮기지 않는다. W10d가 FAIL이면 고침의 일부는 Windows에서도 `keystore_session_bound`를 내는 것이다(`docs/CLI.md` §6.17, ADR-0035 결정 12).
- ssh 호환 결함 (W12). `docs/campaigns/p1-ssh-bootstrap.md` §6의 규칙을 따른다. 두 장비의 `ssh -V`와 거부 문구 원문을 이슈에 붙이고, 가짜 `ssh` 하네스에 같은 재현을 더하는 것이 고침의 일부다.
- 환경 잡음 (§2.3의 클린이 아니었다, 방화벽이 회차 설계 밖이었다, 덮개를 닫아도 절전하지 않고 화면만 꺼졌다). 그 행은 PASS도 FAIL도 아닌 무효로 적고 세지 않는다.

## 7. 회차 표

| 회차 | 변형 | 날짜(UTC) | 대상 태그 | 장비 (W / host, OS 빌드, 터미널) | 확인 | 결과 | 기록자 |
|---|---|---|---|---|---|---|---|
| W8 | - | 2026-10-21 | `v0.5.0` | Dave-Windows / 없음, Windows 11 Pro 25H2 빌드 26200.9457, 대화형 로그온 세션의 비관리자 예약 작업(pwsh 7) | a=PASS b=PASS c=PASS d=미실행 | 무효 | Claude(에이전트) |
| W8 | - | 2026-10-21 | `v0.5.0` | Dave-Windows / 없음, Windows 11 Pro 25H2 빌드 26200.9457, 대화형 로그온 세션의 비관리자 예약 작업(pwsh 7) | a=PASS b=PASS c=PASS d=미실행 | 보류 | Claude(에이전트) |
| W8 | - | 2026-10-23 | `v0.5.1` | Dave-Windows / 없음, Windows 11 Pro 25H2 빌드 26200.9457, 대화형 로그온 세션의 비관리자 예약 작업(pwsh 7) | a=PASS b=PASS c=PASS d=PASS | PASS | Claude(에이전트) |
| W11 | b | 2026-10-21 | `v0.5.0` | Dave-Windows / 없음, Windows 11 Pro 25H2 빌드 26200.9457, 대화형 로그온 세션의 비관리자 예약 작업(pwsh 7) | b1=PASS b2=PASS | PASS | Claude(에이전트) |
| W11 | c | 2026-10-21 | `v0.5.0` | Dave-Windows / 없음, Windows 11 Pro 25H2 빌드 26200.9457, 대화형 로그온 세션의 비관리자 예약 작업(pwsh 7) | c1=FAIL c2=FAIL | 무효 | Claude(에이전트) |
| W11 | c | 2026-10-21 | `v0.5.0` | Dave-Windows / 없음, Windows 11 Pro 25H2 빌드 26200.9457, 대화형 로그온 세션의 비관리자 예약 작업(pwsh 7) | c1=FAIL c2=PASS | FAIL | Claude(에이전트) |
| W11 | c | 2026-10-22 | `v0.5.1` | Dave-Windows / 없음, Windows 11 Pro 25H2 빌드 26200.9457, 대화형 로그온 세션의 비관리자 예약 작업(pwsh 7) | c1=PASS c2=PASS | PASS | Claude(에이전트) |
| W3b | M | 2026-10-24 | `v0.5.2` | Dave-Windows / Dave-MacMini(macOS 27.0.1 arm64), Windows 11 Pro 25H2 빌드 26200.9711, controller 터미널은 expect 5.45의 pty(`TERM=xterm-256color`, UTF-8 로캘) | a=PASS b=PASS c=PASS d=PASS e=PASS | PASS | Claude(에이전트) |
| W7 | A | 2026-10-24 | `v0.5.2` | Dave-Windows / Dave-MacMini(macOS 27.0.1 arm64), Windows 11 Pro 25H2 빌드 26200.9711, WR 기본 셸 `cmd.exe`, client는 ssh 비대화형 셸 | a=보류 b=PASS c=PASS d=FAIL e=보류 f=보류 | FAIL | Claude(에이전트) |
| W7 | B | 2026-10-24 | `v0.5.2` | Dave-Windows / Dave-MacMini(macOS 27.0.1 arm64), Windows 11 Pro 25H2 빌드 26200.9711, WR 기본 셸 PowerShell 7, client는 ssh 비대화형 셸 | a=보류 b=PASS c=PASS d=PASS e=보류 f=보류 | 보류 | Claude(에이전트) |
| W7 | A | 2026-10-25 | `v0.5.3` | Dave-Windows / Dave-MacMini(macOS 27.0.1 arm64), Windows 11 Pro 25H2 빌드 26200.9711, WR 기본 셸 `cmd.exe`, client는 ssh 비대화형 셸 | a=보류 b=PASS c=PASS d=PASS e=보류 f=보류 | 보류 | Claude(에이전트) |
| W7 | A | 2026-10-25 | `v0.5.3` | Dave-Windows / Dave-MacMini(macOS 27.0.1 arm64), Windows 11 Pro 25H2 빌드 26200.9711, WR 기본 셸 `cmd.exe`, client는 ssh 비대화형 셸, WR `qsh serve` 방화벽 허용 | a=PASS b=PASS c=PASS d=PASS e=PASS f=PASS | PASS | Claude(에이전트) |
| W7 | B | 2026-10-25 | `v0.5.3` | Dave-Windows / Dave-MacMini(macOS 27.0.1 arm64), Windows 11 Pro 25H2 빌드 26200.9711, WR 기본 셸 PowerShell 7, client는 ssh 비대화형 셸, WR `qsh serve` 방화벽 허용 | a=PASS b=PASS c=PASS d=PASS e=PASS f=PASS | PASS | Claude(에이전트) |
| W3b | L | 2026-10-26 | `v0.5.3` | Dave-Windows / Dave-Windows-WSL(같은 박스의 WSL2, Ubuntu 24.04.5, 커널 6.18.54.1-microsoft-standard-WSL2, §2.2의 WSL2 예외), Windows 11 Pro 25H2 빌드 26200.9711, controller 터미널은 expect 5.45.4의 pty(`TERM=xterm-256color`, UTF-8 로캘) | a=PASS b=PASS c=PASS d=PASS e=PASS | PASS | Claude(에이전트) |
| W2 | L | 2026-10-26 | `v0.5.4` | Dave-Windows / Dave-Windows-WSL(같은 박스의 WSL2, Ubuntu 24.04.5, 커널 6.18.54.1-microsoft-standard-WSL2, client), Windows 11 Pro 25H2 빌드 26200.9711, client 터미널은 expect가 연 pty | a=FAIL b=PASS c=PASS d=PASS e=PASS f=FAIL | FAIL | Claude(에이전트) |
| W2 | L | 2026-10-26 | `v0.5.5` | Dave-Windows / Dave-Windows-WSL(같은 박스의 WSL2, Ubuntu 24.04.5, 커널 6.18.54.1-microsoft-standard-WSL2, client, §2.2의 WSL2 예외), Windows 11 Pro 25H2 빌드 26200.9711, client 터미널은 expect 5.45.4가 연 pty | a=PASS b=PASS c=PASS d=PASS e=PASS f=PASS | PASS | Claude(에이전트) |
| W2 | M | 2026-10-26 | `v0.5.5` | Dave-Windows / Dave-MacMini(macOS 27.0.1 arm64 빌드 26A434, client), Windows 11 Pro 25H2 빌드 26200.9711, client 터미널은 macOS 기본 expect 5.45가 연 pty(b의 이모지 단계만 Python pty) | a=PASS b=PASS c=PASS d=PASS e=PASS f=PASS | PASS | Claude(에이전트) |
| W3a | L | 2026-10-26 | `v0.5.5` | Dave-Windows(controller) / Dave-Windows-WSL(같은 박스의 WSL2, Ubuntu 24.04.5, 커널 6.18.54.1-microsoft-standard-WSL2, §2.2의 WSL2 예외), Windows 11 Pro 25H2 빌드 26200.9711, W 터미널은 WSL에서 연 `ssh -tt`의 ConPTY(conhost, 셸 `cmd.exe`, Python pty와 tmux로 구동) | a=PASS b=FAIL c=PASS d=PASS e=PASS | FAIL | Claude(에이전트) |
| W3a | M | 2026-10-26 | `v0.5.5` | Dave-Windows(controller) / Dave-MacMini(macOS 27.0.1 arm64 빌드 26A434), Windows 11 Pro 25H2 빌드 26200.9711, W 터미널은 L과 같은 `ssh -tt` ConPTY | a=PASS b=FAIL c=PASS d=PASS e=PASS | FAIL | Claude(에이전트) |
| W5 | - | 2026-10-26 | `v0.5.5` | Dave-Windows, Windows 11 Pro 25H2 빌드 26200.9711, A는 관리자 계정 `dave`의 ssh 세션, B는 임시 표준 계정(`qshtest2`, d는 `qshtest5`)으로 같은 장비의 Windows OpenSSH Server(`127.0.0.2:22`)에 키로 로그온한 세션 | a=PASS b=PASS c=PASS d=PASS e=PASS | PASS | Claude(에이전트) |
| W3a | L | 2026-10-26 | `v0.5.6` | v0.5.5 L 행과 같은 구성, b만 다시 돎 | b=PASS (a·c·d·e는 v0.5.5 행) | PASS | Claude(에이전트) |
| W3a | M | 2026-10-26 | `v0.5.6` | v0.5.5 M 행과 같은 구성, b만 다시 돎 | b=PASS (a·c·d·e는 v0.5.5 행) | PASS | Claude(에이전트) |
| W12 | - | 2026-10-30 | `v0.5.6` | Dave-Windows / Dave-Windows-WSL 위 docker 컨테이너(Ubuntu 24.04, 자체 netns와 `sshd`, §2.2의 WSL2 예외), Windows 11 Pro 25H2 빌드 26200.9711, WSL에서 연 `ssh -tt`의 ConPTY(cmd.exe, Python pty로 구동) | a=PASS b=PASS c=PASS d=PASS e=PASS f=PASS | PASS | Claude(에이전트) |

열 채우는 법: `확인`에는 §4가 그 변형에 적은 문자를 모두 `a=PASS b=FAIL` 꼴로 적는다. `결과`는 그 문자가 모두 PASS(허용된 "해당 없음" 제외)일 때만 `PASS`다. 변형이 없는 회차는 `변형` 칸에 `-`를 적는다. 행마다 비고 문단을 표 아래에 회차·변형을 머리에 달아 잇는다. 비고에는 `qsh version`, `winver`, 터미널 종류, 호스트의 `qsh version`, 명령과 출력 원문, 막힌 지점의 원문 에러, 정리를 했는지를 적는다. W4는 반복 기록표(`docs/campaigns/p1-supervise-wake.md` §7)를, W5는 pipe 시도의 출력 원문을, W6은 `Get-CimInstance`와 `Get-NetUDPEndpoint` 출력을, W10은 부팅 시각과 `serve.err.log` 줄을 붙인다.

회차 공통 비고. 이 일곱 행은 에이전트(Claude)가 돌렸다. W 자체만 쓰는 회차라 host가 없다. 에이전트는 Dave-Windows에 OpenSSH로 들어갔다. ssh 세션의 토큰은 관리자 권한이고, 그 세션은 Credential Manager를 쓰지 못한다(`qsh init --key-store platform`이 `Windows ERROR_NO_SUCH_LOGON_SESSION`, `auto`는 같은 경고를 내고 파일 저장소로 내려간다). 그래서 판정에 쓴 명령은 모두 dave의 활성 대화형 로그온 세션에 `New-ScheduledTaskPrincipal -LogonType Interactive -RunLevel Limited`로 등록한 일회용 예약 작업 안에서 돌렸다. 작업 출력의 첫 줄에 `IsInRole('Administrators')`가 `False`로 찍혔고, 작업은 끝나고 지웠다. `-LogonType S4U -RunLevel Limited`는 이 장비에서 관리자 토큰(`True`)을 받아 회차에 쓰지 않았다. 터미널 렌더링을 보는 확인은 이 행들에 없다. zip `qsh-v0.5.0-x86_64-pc-windows-msvc.zip`의 sha256 `7b9653a6e3899581664ec615508af72f16267367f613457a5c42c94c9609bc5d`이 §2.4의 줄과 같고, 안의 `qsh.exe`의 sha256은 `322650C9152DFA5A924A0A7B3A938E9B06A67AC623261E674B36689B12C19980`이다. `qsh version`은 `qsh 0.5.0 (1c653e0b6046fcdfb15ffa1781c4e9d69fa44d8b)`.

**W8 첫 행(무효).** 시작 전 클린 확인을 ssh 세션에서 했는데, 그 세션의 Credential Manager 보기는 대화형 세션과 달라 비어 보였다. 대화형 세션에는 `.qsh` 대상 항목이 25개 남아 있었다. `device_test_<ulid>` 18개는 2026-10-20의 Credential Manager 동시 실행 재현(`b7ed672`)이 남긴 것이고, `device_<ulid>` 7개는 2026-10-18 에이전트 확인이 남긴 것이다. §2.3이 깨진 시작이라 §6의 환경 잡음으로 무효다. 확인 문자는 그 시도의 결과를 적었고 d는 돌지 않았다. 항목 25개는 지웠다.

**W8 둘째 행(보류).** 클린 확인을 같은 대화형 작업 안에서 했다. config·state 디렉터리 없음, `cmdkey` `.qsh` 0개, `\qsh\` 작업 0개, `Get-Command qsh -All` 0개. a: `qsh init --key-store platform --json`의 `data.key_store`가 `platform`, `device_id` `device_01M5EQ26JXSPBSRJGNJBPRH9ZE`, fingerprint `sha256:eXQQpJOZlll3COSCiHmJtFfhRVoi8VPj+XXGUizi71U=`. `cmdkey`에 `Target: LegacyGeneric:target=device_01M5EQ26JXSPBSRJGNJBPRH9ZE.qsh`이 보이고 `device.key`는 없다. b: `qsh identity move-key --to file` 뒤 `cmdkey` 항목이 없고 `device.key`가 있으며 `icacls`가 `Dave-Windows\dave:(F)` 한 줄이다. 다시 돌린 `qsh init --json`은 `"created":false`, `"key_store":"file"`, 같은 `device_id`와 fingerprint다. c: `--to platform` 뒤 항목이 다시 보이고 `device.key`가 없으며 `key_store`가 `platform`, `device_id`와 fingerprint가 그대로다. `qsh identity export`의 출력은 a·b·c에서 바이트가 같다. d는 재부팅이 필요한데 이 장비의 재부팅은 같은 박스의 WSL 세션과 진행 중인 fuzz 실행을 끊어 돌지 않았다. `qsh doctor --json`의 코드는 `acl_policy_missing`, `service_not_registered`, `bindv6only_blocks_ipv4`이고 `keystore_unavailable`이 없다. 마지막 `bindv6only_blocks_ipv4`가 ADR-0046의 출발점이다. 정리: `move-key --to file`, config·state 디렉터리 삭제, `cmdkey` `.qsh` 0개.

**W8 셋째 행(PASS).** 대상 태그 `v0.5.1`(§2.4 둘째 묶음). 클린 확인은 같은 대화형 작업 안에서 했다. config·state 디렉터리 없음, `cmdkey` `.qsh` 0개, `\qsh\` 작업 0개, `Get-Command qsh -All` 0개. zip `qsh-v0.5.1-x86_64-pc-windows-msvc.zip`의 sha256 `3a0305b61c33155d433e69ecfcc9d2b2eb24038ffdd835d2fd8bea94d1d65e4e`이 §2.4의 줄과 같고, 안의 `qsh.exe` sha256은 `190A6D1A109D86009FABB646E7AEEBC0EB74BE9ED9AB6F0149AFE06D3186F870`이다. `qsh version`은 `qsh 0.5.1 (b4639a896a6e4728d3e8787c522cab3ae4466a74)`. a: `qsh init --key-store platform --json`의 `data.key_store`가 `platform`, `device_id` `device_01M5K35Y33F2PVNPRQ8HEMX1VB`, fingerprint `sha256:y+N4ClZ6ckHkTX+zI+FFybNANJ04AXM6kzKDeGeHSrY=`. `cmdkey`에 `Target: LegacyGeneric:target=device_01M5K35Y33F2PVNPRQ8HEMX1VB.qsh`이 보이고 `device.key`는 없다. b: `qsh identity move-key --to file` 뒤 항목이 없고 `device.key`가 있으며 `icacls`가 `Dave-Windows\dave:(F)` 한 줄이다. 다시 돌린 `qsh init --json`은 `"created":false`, `"key_store":"file"`, 같은 `device_id`와 fingerprint다. c: `--to platform` 뒤 항목이 다시 보이고 `device.key`가 없으며 `key_store`가 `platform`, `device_id`와 fingerprint가 그대로다. `qsh identity export`의 출력은 a·b·c에서 바이트가 같다. c 뒤 `qsh doctor --json`의 코드는 `acl_policy_missing`, `service_not_registered`다. `v0.5.0` 행에 있던 `bindv6only_blocks_ipv4`가 없어 ADR-0046이 이 장비에서 효과를 냈다. a~c는 2026-10-23 00:3x UTC에 돌렸고, 에이전트가 `shutdown /r /t 60`으로 재부팅했다. dave가 콘솔에 로그온한 뒤(09:42 KST) d를 같은 작업 방식으로 돌렸다. d: 부팅 시각 `2026-10-23 00:42:21Z`, `qsh init --json`이 `"created":false`, `"key_store":"platform"`, 같은 `device_id`와 fingerprint다. `cmdkey`에 같은 대상이 보이고 `device.key`는 없다. doctor 코드는 `acl_policy_missing`, `service_not_registered`이고 `keystore_unavailable`이 없다. 정리: `move-key --to file`, config·state 디렉터리 삭제, `cmdkey` `.qsh` 0개, 압축 해제 디렉터리 삭제.

**W11 b.** 작업 안에서 `$env:QSH_VERSION='v0.5.0'; irm https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.ps1 | iex`. 출력 순서는 `downloading …`, `verifying checksum`, `unpacking`이고 끝 줄은 `installed qsh v0.5.0 to C:\Users\dave\.local\bin\qsh.exe`. 관리자 권한을 묻지 않았다. 새 ssh 세션에서 `qsh version`이 `qsh 0.5.0 (1c653e0b6046fcdfb15ffa1781c4e9d69fa44d8b)`를 냈고, 설치된 exe의 sha256이 zip 안 `qsh.exe`와 같다. `%USERPROFILE%\.local\bin`은 이미 사용자 `PATH`에 있어서 HKCU `Path`가 전후로 같았다. 정리: `.local\bin\qsh.exe`와 man 디렉터리 삭제.

**W11 c 첫 행(무효).** `cargo install --locked --git https://github.com/DaveDev42/qsh --tag v0.5.0 qsh-cli`가 14.7초 만에 `LINK : fatal error LNK1181: cannot open input file 'kernel32.lib'`로 끝났다. 이 장비의 Windows SDK 10.0.26100.0에서 `Lib\10.0.26100.0\um\x64`에 `kernel32.lib`가 빠져 있었다(477개 파일, arm64·x86에는 있음). §4.9의 전제(MSVC 툴체인과 Build Tools가 갖춰져 있다)가 깨진 시작이라 무효다. 에이전트가 SDK 번들 `winsdksetup.exe /repair`(10.0.26100.7705)로 고쳤고 그 뒤 481개가 됐다.

**W11 c 둘째 행(FAIL).** 같은 명령이 비관리자 토큰으로 139초에 끝났다(cargo 1.98.1, rustc 1.98.1, Build Tools 17.14.41, `RUSTC_WRAPPER=sccache`). 끝 줄은 `Installed package `qsh-cli v0.5.0 (https://github.com/DaveDev42/qsh?tag=v0.5.0#1c653e0b)` (executable `qsh.exe`)`. 새 ssh 세션에서 `Get-Command qsh`가 `C:\Users\dave\.cargo\bin\qsh.exe`를 가리켜 c2는 PASS다. `qsh version`은 `qsh 0.5.0`만 내고 커밋을 내지 않아 c1이 FAIL이다. `build.commit`이 CI가 넣는 `QSH_BUILD_COMMIT`에서만 오기 때문이다. §6의 제품 결함으로 분류한다. 고친 뒤 새 태그에서 다시 돈다. 정리: `cargo uninstall qsh-cli`, `Get-Command qsh` 0개.

**W11 c 셋째 행(PASS).** 대상 태그 `v0.5.1`(§2.4 둘째 묶음). 앞 행과 같은 장비·같은 작업 방식이고, 작업 출력 첫 줄의 `IsInRole('Administrators')`가 `False`, 시작 전 `Get-Command qsh -All`이 0개다. `cargo install --locked --git https://github.com/DaveDev42/qsh --tag v0.5.1 qsh-cli`가 93초에 끝났다(cargo 1.98.1, rustc 1.98.1, 추가로 설치한 도구 없음). 끝 줄은 `Installed package `qsh-cli v0.5.1 (https://github.com/DaveDev42/qsh?tag=v0.5.1#b4639a89)` (executable `qsh.exe`)`. 새 ssh 세션에서 `qsh version`이 `qsh 0.5.1 (b4639a896a6e4728d3e8787c522cab3ae4466a74)`를 냈고 §2.4의 커밋과 같아 c1은 PASS다. `Get-Command qsh`가 `C:\Users\dave\.cargo\bin\qsh.exe`를 가리켜 c2도 PASS다. 설치된 exe의 sha256은 `9591A80E4CF70D2FF4A7A1318077789672C04D23063B2C20018F98E22F86DD50`이다(로컬 빌드라 zip 안 exe와 다르다). 정리: `cargo uninstall qsh-cli`, `Get-Command qsh` 0개.

**v0.5.2 회차 공통 비고(W3b M, W7 A·B).** 에이전트(Claude)가 돌렸다. W는 Dave-Windows(`winver` 대신 attach 배너 `Microsoft Windows [Version 10.0.26200.9711]`, Windows 11 Pro 25H2), 상대 장비는 Dave-MacMini(macOS 27.0.1, arm64)다. 두 장비는 Tailscale로 이어져 있고 판정에 쓴 UDP 경로는 Dave-Windows 100.97.123.120 ↔ Dave-MacMini 100.98.191.17이다. Dave-MacMini에는 사람이 쓰는 qsh(`/opt/homebrew/bin/qsh`, `serve`가 UDP 4433, `listen`이 UDP 4434)가 돌고 있어서 회차용 controller는 `~/qsh-campaign` 아래의 별도 바이너리와 `QSH_CONFIG_DIR`·`QSH_STATE_DIR`로 따로 세웠고, controller `qsh listen`은 `[::]:4435`에 띄웠다. 그래서 §4.13·§4.14의 `<controller 주소>:4433`은 `100.98.191.17:4435`로 읽는다. 포트 번호만 다르고 경로는 같다. controller의 tarball `qsh-v0.5.2-aarch64-apple-darwin.tar.gz` sha256 `6e3d5b5cef919edcbd5e063d11363af07456fcb062be426322b75aca51522e35`이 `SHA256SUMS`와 같고 `qsh version`은 `qsh 0.5.2 (42407678cafa4c1fa0ca30e8f9df619f57b8d335)`다. W의 zip sha256이 §2.4 셋째 묶음의 줄과 같고 안의 `qsh.exe` sha256은 `02CFEADFACEC5EABB6B4A6ED9D9976E006743266E58CE841033C4EC2DFA5AB59`, `qsh version`은 controller와 같다. 시작 전 클린 확인은 dave의 대화형 로그온 세션 작업 안에서 했다. config·state 디렉터리 없음, `cmdkey` `.qsh` 0개, `\qsh\` 작업 0개, `Get-Command qsh -All` 0개. 에이전트는 W에 OpenSSH로 들어갔고, Credential Manager를 쓰거나 세션 1에 남아야 하는 명령(`qsh init`, `qsh serve --to`, 정리의 `identity move-key`)은 W8과 같은 `-LogonType Interactive -RunLevel Limited` 일회용 작업으로 돌렸다(첫 줄 `IsInRole('Administrators')`가 `False`). 한글은 IME가 아니라 expect가 UTF-8 바이트로 보냈다.

**W3b M.** controller 쪽 identity는 `--key-store file`, W 쪽은 기본(`platform`)이다. pin은 §4.13의 대체 경로대로 `identity export` 파일을 옮겨 세웠다(controller `win` role `reverse`, W `ctl` 주소 `100.98.191.17:4435` role `full`). W의 `qsh serve --to ctl`은 `C:\qsh-w3b\qsh.exe`(이 장비에서 `serve`나 `listen`을 띄운 적 없는 경로)이고 stderr에 `{"event":"registered","host":"ctl",…}`가 나왔다. a: controller `qsh hosts --json`의 `win` 행 원문은 `{"address":"[::ffff:100.97.123.120]:55575","connection_mode":"reverse","device_id":"sha256:Ng8TJF7zWLFxO90hiCIIQR94zvvAJbKZHg2jskxhHCM=","name":"win","state":"reachable"}`. `@(Get-NetFirewallApplicationFilter -Program C:\qsh-w3b\qsh.exe).Count`가 `0`이고, 바탕화면 스크린숏에 방화벽 프롬프트가 없었다. b: `qsh win`이 `C:\Users\dave>` 프롬프트를 열고 `echo 한글 테스트`의 출력이 `한글 테스트`로 같다(로그의 바이트가 UTF-8 `ed 95 9c ea b8 80 …`). 같은 세션에서 `pwsh -NoLogo -NoProfile`, `& 'C:\Program Files\Vim\vim.exe' -u NONE -N`(vim 9.1을 회차용으로 `winget install --id vim.vim --scope machine`으로 깔았고 시스템 `PATH`에는 넣지 않았다)으로 vim을 열고 `i한글 입력 테스트`를 친 뒤 pty 크기를 24×80, 40×120, 30×90, 45×140으로 바꿨다. 매번 `:echo &columns &lines`가 `80 24`, `120 40`, `90 30`, `140 45`로 답했고, pyte로 다시 그린 화면에서 상태 줄(`1,21-15 All`)이 마지막 행에 있었다. `:q!` 뒤 화면은 vim 이전의 cmd·pwsh 줄로 돌아왔다. pwsh를 나와 26×82, 44×132에서 `mode con`이 `Lines: 26`/`Columns: 82`, `Lines: 44`/`Columns: 132`를 냈다. `~d`로 빠져나온 뒤 `qsh sessions win --json`에 `"state":"running"`인 세션이 있었고 `qsh attach win/01M5QB1AN014262WNNZ61VXTN4`가 이전 화면(`before-detach-marker`)을 다시 그리고 `echo after-reattach`에 답했다. c: 5 MiB 무작위 파일을 `qsh cp ./payload.bin win:C:/Users/Public/payload.bin`으로 올리고 `qsh cp win:C:/Users/Public/payload.bin ./back.bin`으로 내려받아 sha256이 둘 다 `6860a52fe9227eb7aea055f0923dbb2e7bf93468a431449f0b8ecf4f614605fd`다. `qsh cp -r ./tree win:C:/Users/Public/qshtree`가 디렉터리 2개와 파일 2개를 만들었고, `qsh cp ./payload.bin win:`은 `remote_path` `~/payload.bin`으로 `C:\Users\dave\payload.bin`에 올렸다. `chmod 444` 파일을 `qsh cp -p`로 올리자 `attrib`이 `A    R               C:\Users\Public\ro.bin`이고, 내용을 바꿔 같은 이름으로 다시 올리자 봉투가 `"overwritten":true`, W의 `type`이 새 내용을 냈다. `qsh cp -p win:C:/Users/Public/ro.bin ./dl/`의 모드는 `444`다. `qsh cp ./payload.bin 'win:\\server\share\x' --json`은 `INVALID_ARGUMENT`(`"message":"1 of 1 entries failed: UNC and device paths are not supported"`, `"copied":0,"created":0`)로 끝났다. d: controller에 §4.13의 socat 대신 perl `IO::Socket::INET` echo 서버(127.0.0.1:7000)를 띄웠다(이 장비에 socat이 없다). `qsh tunnel open win --remote 19000:127.0.0.1:7000 --json`의 봉투는 `{"actual_port":19000,"bind":"127.0.0.1:19000","forward_to":"127.0.0.1:7000","host":"win","mode":"remote","tunnel_id":"01M5QB4Y8Y55YSBRN549B6PKQA"}`이고, W의 §3.2 echo 확인 클라이언트가 `hello-qsh`를 받았다. 그동안 `Get-NetTCPConnection -State Listen -LocalPort 19000`은 `127.0.0.1 19000`, 소유 프로세스 `qsh`(serve --to)였다. `qsh tunnels --json`에 그 터널이 있었고 `qsh tunnel close 01M5QB4Y8Y55YSBRN549B6PKQA --json`이 `"closed":true`를 낸 뒤 같은 조회가 0개였다. 판정 밖의 관찰 하나: `tunnel close` 직후부터 `--supervise` 없는 holder 프로세스가 `reverse TCP_ACCEPTED claim failed, retrying … TIMEOUT` 경고를 200ms마다 내며 끝나지 않았다. ADR-0023 2026-10-25 개정 이력과 테스트 `reverse_tunnel::an_unsupervised_reverse_remote_holder_ends_when_another_client_closes_the_tunnel`이 이것을 고친다. `-L`: W에서 §3.2 echo 서버(7777)를 띄우고 controller에서 `qsh tunnel open win --local 127.0.0.1:18080:127.0.0.1:7777 --json`(봉투 `"mode":"local","actual_port":18080`)을 돌려 `printf 'hello-qsh\n' | nc -w1 127.0.0.1 18080`이 `hello-qsh`를 받았다. expect로 Ctrl-C(`\003`)를 보내자 프로세스가 exit 0으로 끝났고 `nc -z 127.0.0.1 18080`이 실패했다. e: controller `qsh listen`에 SIGINT를 보내자 controller stderr에 `qsh listen: shutting down`, W의 stderr에 `{"event":"lost","host":"ctl",…,"cause":"peer_closed","at":"2026-10-24T16:20:06Z",…}`이 나왔다. 16:20:41에 다시 띄우자 W가 `{"event":"registered","host":"ctl",…,"at":"2026-10-24T16:20:43Z"}`를 냈고 16:20:46에 controller `qsh hosts`의 `win`이 `reverse`/`reachable`이었다. 정리: 세션은 `exit`로 끝났고 터널 0개, `qsh listen`과 W의 `qsh serve --to` 종료, W에서 `identity move-key --to file` 뒤 config·state 디렉터리 삭제, `cmdkey` `.qsh` 0개, `C:\qsh-w3b`·`C:\Users\Public`의 회차 파일·`C:\Users\dave\payload.bin` 삭제, vim 제거(`winget uninstall`, 남은 `C:\Program Files\Vim\_vimrc` 삭제). controller의 회차 config·state도 지웠다.

**W7 공통(A·B).** WR은 Dave-Windows, client는 Dave-MacMini다. client `ssh -V`는 `OpenSSH_10.6p1, OpenSSL 4.0.3 29 Sep 2026`, WR은 `Get-WindowsCapability -Online -Name OpenSSH.Server*`가 `OpenSSH.Server~~~~0.0.1.0 Installed`, `sshd.exe` 제품 버전 `OpenSSH_9.5p2 for Windows`이고 sshd는 회차 전부터 `Running`/`Automatic`이었다. `Get-NetFirewallRule -Name '*ssh*'`는 `OpenSSH-Server-In-TCP False Inbound`인데 Tailscale 경로로 TCP 22가 닿아 규칙을 만들지 않았다. client의 `~/.ssh/config`는 사람이 쓰는 파일이라 고치지 않고, 회차 config의 `[ssh].program`을 `/usr/bin/ssh -F ~/qsh-campaign/ssh_config "$@"` 래퍼로 두고 그 파일에 `Host winbox` / `HostName dave-windows.tail91e9e.ts.net` / `User dave`(공개 키 로그인)를 적었다. client identity는 `--key-store file`이고 passphrase가 없으며 ssh도 공개 키로 들어가서 입력한 암호나 passphrase가 없다. WR의 `qsh.exe`는 사용자 `PATH`에 있는 `C:\Users\dave\.local\bin`에 두었고 `ssh winbox where qsh`가 `C:\Users\dave\.local\bin\qsh.exe`를, 변형 B에서 `(Get-Command qsh).Source`가 같은 경로를 냈다. WR `qsh init --json`은 대화형 작업 안에서 `"key_store":"platform"`, fingerprint `sha256:s+lo6ebRIaYr9lKwkg9J6tPa7/+nF1Ce++5bFyIPucQ=`. a와 e는 WR의 `qsh serve`가 UDP 4433으로 닿아야 하는데, 이 장비에서 방화벽 허용 프롬프트를 사람 대신 누르거나 규칙을 만들지 않는다는 회차 밖 제약이 있어 돌지 않았다(보류). f는 a를 포함해야 해서 보류이고, c의 `qsh -vv pair ssh … --reverse` stderr와 `qsh audit --json`에서 `PRIVATE KEY|passphrase|password` 검색은 A·B 모두 0건이었다. client의 `qsh listen`은 `[::]:4435`라 `--to`는 `100.98.191.17:4435`다.

**W7 A.** `HKLM:\SOFTWARE\OpenSSH`에 `DefaultShell` 값이 없는 기본 상태다. b: `qsh pair ssh winbox --json`이 종료 코드 0, `"direction":"forward"`, `"verified":false`, `"verify_error":{"code":"CONNECTION_FAILED","details":{"reason":"remote_serve_not_listening"},"message":"the remote reported that no `qsh serve` is listening on its serve port, so no connection was tried; both pins stay in place, and once the remote runs `qsh serve` (or `qsh service install`) `qsh winbox` connects","retryable":true}`. client pin `winbox` role `none` 주소 `dave-windows.tail91e9e.ts.net:4433`, WR pin `Dave-MacMini` role `full` 주소 빈 값. c: 양쪽 pin을 지운 뒤 `qsh -vv pair ssh winbox --reverse --to 100.98.191.17:4435 --json`이 종료 코드 0, `"direction":"reverse"`, `"verified":false`, `"next_command":"qsh serve --to Dave-MacMini"`. client pin role `reverse` 주소 빈 값, WR pin role `full` 주소 `100.98.191.17:4435`. WR에서 `qsh serve --to Dave-MacMini`를 띄운 16:23:49부터 5초 안에 `qsh hosts`가 `{"address":"[::ffff:100.97.123.120]:58276","connection_mode":"reverse",…,"name":"winbox","state":"reachable"}`이고 `qsh exec winbox --json -- cmd /c ver`가 `"remote_exit_code":0`, stdout `Microsoft Windows [Version 10.0.26200.9711]`이다. d: serve를 끄고 양쪽 pin을 지운 뒤 `qsh.exe`를 `C:\Tools\qsh\qsh.exe`로 옮겼다(`where qsh` 없음). `qsh pair ssh winbox --json`은 `{"code":"REMOTE_ERROR","message":"the remote command failed before answering, so nothing was written on either side; if the remote default shell is PowerShell, a missing qsh looks like this (exit 1): put qsh.exe on the remote PATH or pass its full path with --remote-qsh / [ssh].remote_qsh, then run this again","retryable":false,"details":{"reason":"remote_command_failed","remote_exit":1}}`로 끝났고 ssh가 옮긴 원격 stderr는 `'qsh' is not recognized as an internal or external command,` / `operable program or batch file.`이다. client에 pin은 생기지 않았다. 합격 기준의 `remote_qsh_missing`이 아니라 FAIL이다. 원인은 ADR-0044 결정 14의 전제(기본 셸이 `cmd.exe`이면 없는 명령의 종료 코드가 9009)가 이 장비에서 틀린 것이다. `ssh winbox nosuchcmdxyz`의 종료 코드가 1이고 `Start-Process cmd.exe -ArgumentList '/c','nosuchcmdxyz' -Wait -PassThru`의 `ExitCode`도 1이다. 9009는 cmd 안의 `ERRORLEVEL`일 뿐 `cmd.exe /c` 프로세스의 종료 코드가 아니다. §6의 ssh 호환 결함으로 분류하고 고침은 ADR-0044 2026-10-25 개정 이력에 있다. e는 보류지만 같은 상태에서 `qsh pair ssh winbox --remote-qsh 'C:\Tools\qsh\qsh.exe' --json`이 b와 같은 봉투(종료 코드 0, `"verified":false`, `remote_serve_not_listening`)로 끝나 전체 경로 자체는 통했다.

**W7 B.** WR에서 `New-ItemProperty`와 같은 값(`reg add HKLM\SOFTWARE\OpenSSH /v DefaultShell /t REG_SZ /d "C:\Program Files\PowerShell\7\pwsh.exe"`)을 넣고 새 연결의 `$PSVersionTable.PSVersion.Major`가 `7`이었다. `qsh.exe`는 `C:\Users\dave\.local\bin`으로 되돌렸다. b·c는 A와 같은 봉투 모양이다(b `remote_serve_not_listening`, c `"next_command":"qsh serve --to Dave-MacMini"`, pin role·주소도 A와 같다). c에서 serve를 띄운 16:25:35부터 6초 안에 `winbox`가 `reverse`/`reachable`이었고 `qsh exec winbox --json -- cmd /c ver`가 `"remote_exit_code":0`이다. d: `qsh.exe`를 다시 `C:\Tools\qsh\qsh.exe`로 옮긴 뒤(`Get-Command qsh -All` 0개) `qsh pair ssh winbox --json`이 `{"code":"REMOTE_ERROR",…,"details":{"reason":"remote_command_failed","remote_exit":1}}`이고 message는 A의 d와 같은 문장이며 `qsh.exe`를 원격 `PATH`에 두거나 전체 경로를 주라고 안내한다. 원격 stderr는 `qsh: The term 'qsh' is not recognized as a name of a cmdlet, function, script file, or executable program.`이다. client에 pin은 생기지 않았다. e(보류)의 같은 명령은 A와 같이 종료 코드 0으로 끝났다. 정리(A·B 공통): 양쪽 `qsh trust remove`, client `qsh listen`과 WR `qsh serve --to` 종료, `Remove-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell`(뒤의 `reg query`에 `DefaultShell` 없음), WR에서 `identity move-key --to file` 뒤 config·state 디렉터리와 `C:\Tools\qsh`(`C:\Tools`는 회차 전부터 있던 디렉터리라 남김) 삭제, `cmdkey` `.qsh` 0개, `Get-Command qsh -All` 0개. sshd는 회차 전 상태(`Running`/`Automatic`) 그대로 두었다.

**W7 A 둘째 행(v0.5.3).** 대상 태그 `v0.5.3`(§2.4 넷째 묶음)에서 첫 행의 d FAIL을 고친 `b525e2c`를 확인하려고 A만 다시 돌렸다. 장비, 경로, controller `qsh listen`의 `[::]:4435`, 회차 config의 ssh 래퍼와 `Host winbox`는 v0.5.2 회차와 같다. 다만 v0.5.2 회차 비고의 client `ssh -V`는 대화형 셸 `PATH`의 Homebrew ssh를 적은 것이고, 래퍼가 실제로 부르는 `/usr/bin/ssh`는 `OpenSSH_10.3p1, LibreSSL 3.3.6`이다. 이 행과 v0.5.2 W7 두 행 모두 판정에 쓰인 ssh는 이쪽이다. controller tarball `qsh-v0.5.3-aarch64-apple-darwin.tar.gz` sha256 `85941a95d328f32879bb6093259023e7c2e2d3ead8a00b7c96c86160e55ae850`이 `SHA256SUMS`와 같고 `qsh version`은 `qsh 0.5.3 (061bec3acb4dbf8ffe36c59747034cbb409bea94)`다. client identity와 회차 config는 v0.5.2 회차의 것을 다시 썼고(`--key-store file`, 시작 시 pin 0개), WR 쪽은 v0.5.2 정리 뒤 클린 상태에서 새로 세웠다. 시작 전 클린 확인(대화형 작업 안): config·state 디렉터리 없음, `cmdkey` `.qsh` 0개, `\qsh\` 작업 0개, `Get-Command qsh -All` 0개, `DefaultShell` 값 없음. 같은 작업에서 zip sha256 `41444F59…C13C172`이 §2.4 넷째 묶음과 같고, 안의 `qsh.exe` sha256 `F8EEEE9D77D64684536D2FF7A7204A00216698DAF7E8E088028911ED866FF325`을 `C:\Users\dave\.local\bin`에 두었다. `qsh init --json`은 `"key_store":"platform"`, fingerprint `sha256:Y3ns0xc5012XVkN+RzB/eDmKm2SiVP05134tZdyOXuw=`이고 작업 첫 줄 `admin=False`다. b: `qsh pair ssh winbox --json`이 종료 코드 0, `"direction":"forward"`, `"verified":false`, `verify_error` `CONNECTION_FAILED`/`remote_serve_not_listening`으로 첫 행과 같은 봉투다. client pin `winbox` role `none` 주소 `dave-windows.tail91e9e.ts.net:4433`, WR pin `Dave-MacMini` role `full` 주소 빈 값. c: 양쪽 pin을 지운 뒤 `qsh -vv pair ssh winbox --reverse --to 100.98.191.17:4435 --json`이 종료 코드 0, `"direction":"reverse"`, `"next_command":"qsh serve --to Dave-MacMini"`. client pin role `reverse` 주소 빈 값, WR pin role `full` 주소 `100.98.191.17:4435`. WR에서 대화형 작업으로 `qsh serve --to Dave-MacMini`를 띄운 07:10:05(serve의 `registered` 줄)부터 3초 안에 `qsh hosts`가 `winbox`를 `reverse`/`reachable`(`[::ffff:100.97.123.120]:63654`)로 냈고, `qsh exec winbox --json -- cmd /c ver`가 `"remote_exit_code":0`, stdout `Microsoft Windows [Version 10.0.26200.9711]`이다. c의 `-vv` stderr와 `qsh audit --json`에서 `PRIVATE KEY|passphrase|password` 검색은 0건이다. d: serve를 끄고 양쪽 pin을 지운 뒤 `qsh.exe`를 `C:\Tools\qsh\qsh.exe`로 옮겼다(`where qsh` 없음). `qsh pair ssh winbox --json`이 종료 코드 255, `{"code":"REMOTE_ERROR",…,"retryable":false,"details":{"reason":"remote_qsh_missing","remote_exit":1}}`로 끝났고, message는 원격 셸이 qsh를 찾지 못해 양쪽에 아무것도 쓰지 않았다며 `--remote-qsh`나 `[ssh].remote_qsh`를 안내한다. 합격 기준의 `remote_qsh_missing`이다. 원격 stderr `'qsh' is not recognized as an internal or external command,` / `operable program or batch file.`은 ssh 자체 경고 줄과 함께 qsh stderr로 그대로 나왔고, client와 WR 모두 pin 0개다. e는 첫 행과 같은 이유로 보류이고, 같은 상태에서 `--remote-qsh 'C:\Tools\qsh\qsh.exe'`가 `"ok":true`, `"direction":"forward"`로 끝나 전체 경로는 통했다. a와 f도 첫 행과 같은 이유로 보류라 이 행의 결과는 보류다. 정리: 양쪽 `qsh trust remove`, client의 회차 `qsh listen`과 WR `qsh serve --to` 종료, WR에서 대화형 작업으로 `identity move-key --to file`(`"moved":true`, `"stale_entry_left":false`) 뒤 config·state 디렉터리와 `C:\Tools\qsh` 삭제(`C:\Tools`에는 회차 전부터 있던 항목만 남음), `cmdkey` `.qsh` 0개, `Get-Command qsh -All` 0개, `\qsh\` 작업 0개, `reg query`에 `DefaultShell` 없음. 사람이 쓰는 Dave-MacMini의 `qsh serve`·`qsh listen`·`qsh tunnel open`은 건드리지 않았다.

**W7 A 셋째 행과 W7 B 둘째 행(v0.5.3, 방화벽 허용).** 둘째 행을 마친 뒤 사용자가 WR의 방화벽 허용 프롬프트를 직접 누르기로 해서, 같은 날 같은 태그로 A와 B를 a부터 f까지 다시 돌렸다. 장비, 경로, 회차 config, client identity(`--key-store file`, 시작 시 pin 0개), client `/usr/bin/ssh`(`OpenSSH_10.3p1, LibreSSL 3.3.6`), controller `qsh listen`의 `[::]:4435`는 둘째 행과 같다. WR은 둘째 행 정리 뒤의 클린에서 다시 세웠다(대화형 작업 안 확인: config·state 디렉터리 없음, `cmdkey` `.qsh` 0개, `\qsh\` 작업 0개, `Get-Command qsh -All` 0개, `DefaultShell` 값 없음, 첫 줄 `admin=False`). zip sha256은 §2.4 넷째 묶음과 같고, 안의 `qsh.exe`(sha256 `F8EEEE9D…866FF325`)를 `C:\Tools\qsh\qsh.exe`와 `C:\Users\dave\.local\bin\qsh.exe` 두 곳에 두었다. 방화벽 허용은 실행 파일 경로마다 붙고 e는 `PATH` 밖의 경로로 a와 같은 결과를 내야 하므로, WR의 `qsh serve`와 `qsh serve --to`는 회차 내내 `C:\Tools\qsh\qsh.exe`로 띄우고 `PATH`의 사본은 `pair ssh` 응답자용으로만 썼다. d의 "옮긴 경로"는 `.local\bin` 사본을 지워 `C:\Tools\qsh\qsh.exe`만 남긴 상태다. `qsh init --json`은 `"key_store":"platform"`, fingerprint `sha256:hHIcm+GevvN9sziOIVXXQJqimuaJ5yAw+RKYB/R7LUk=`. 방화벽: 회차 전 `Get-NetFirewallApplicationFilter`에 두 경로의 규칙이 없었고, 프로필 셋 모두 `NotifyOnListen` `True`, Tailscale·Ethernet 어댑터는 `Private`였다. 대화형 작업으로 `C:\Tools\qsh\qsh.exe serve`를 띄우자(`listening on [::]:4433`) 6초 안에 Windows Security 대화상자가 떴다. 제목 줄 "Windows Security", 본문 "Do you want to allow public and private networks to access this app?" / "Windows Firewall has blocked some features of qsh.exe on all public and private networks.", 앱 이름 `qsh.exe`, Publisher `Unknown`(미서명, ADR-0035 개정 이력 2026-10-19), "Show more" 링크, 단추 Allow·Cancel이고 네트워크 종류 체크박스는 없다. 사용자가 Allow를 누른 뒤 `C:\tools\qsh\qsh.exe`에 `qsh`라는 이름의 인바운드 Allow 규칙이 TCP와 UDP로 하나씩, 둘 다 Profile `Private, Public`으로 생겼다. 그래서 §4.14 준비의 "사설 네트워크로 허용"은 이 빌드에서 고를 수 없고, `docs/CLI.md` §6.13과 README 안내를 v0.61에서 이 화면에 맞췄다. 에이전트는 규칙을 만들거나 바꾸지 않았다.

A(`DefaultShell` 없음). a: `qsh serve`가 떠 있는 채로 `qsh -vv pair ssh winbox --json`이 종료 코드 0, `"direction":"forward"`, `"verified":true`. client pin `winbox` role `none` 주소 `dave-windows.tail91e9e.ts.net:4433`, WR pin `Dave-MacMini` role `full` 주소 빈 값. `qsh exec winbox --json -- cmd /c ver`가 `"remote_exit_code":0`, stdout `Microsoft Windows [Version 10.0.26200.9711]`. b: 양쪽 pin을 지우고 serve를 끈 뒤 같은 명령이 종료 코드 0, `"verified":false`, `verify_error` `{"code":"CONNECTION_FAILED","details":{"reason":"remote_serve_not_listening"},…,"retryable":true}`(message는 첫 행에 적은 원문과 같다)이고 pin은 양쪽에 서 있다. c: 양쪽 pin을 지운 뒤 `qsh -vv pair ssh winbox --reverse --to 100.98.191.17:4435 --json`이 종료 코드 0, `"direction":"reverse"`, `"verified":false`, `"next_command":"qsh serve --to Dave-MacMini"`. client pin role `reverse` 주소 빈 값, WR pin role `full` 주소 `100.98.191.17:4435`. 대화형 작업으로 `qsh serve --to Dave-MacMini`를 띄운 10:09:47(`registered`)부터 3초 안에 `winbox`가 `reverse`/`reachable`이고 `qsh exec winbox --json -- cmd /c ver`가 `"remote_exit_code":0`이다. 같은 작업에서 e에 쓸 `qsh serve`도 함께 띄웠다. d: `serve --to`를 끄고 양쪽 pin을 지운 뒤 `.local\bin` 사본을 지웠다(`where qsh` 없음). `qsh pair ssh winbox --json`이 종료 코드 255, `REMOTE_ERROR`, `details` `{"reason":"remote_qsh_missing","remote_exit":1}`, message는 둘째 행과 같은 문장(`--remote-qsh`와 `[ssh].remote_qsh` 안내)이다. 원격 stderr `'qsh' is not recognized as an internal or external command,` / `operable program or batch file.`이 qsh stderr로 나왔고 양쪽 pin 0개다. e: 같은 상태에서 `qsh pair ssh winbox --remote-qsh 'C:\Tools\qsh\qsh.exe' --json`이 종료 코드 0, `"direction":"forward"`, `"verified":true`, pin은 a와 같고 `qsh exec winbox --json -- cmd /c ver`가 성공했다. f: 입력한 passphrase나 암호가 없다(ssh는 공개 키, client 키는 passphrase 없는 파일). a와 c의 `-vv` stderr(합 22줄)와 `qsh audit --json`에서 `PRIVATE KEY|passphrase|password` 검색은 0건이다.

B. 양쪽 pin을 지우고 `.local\bin` 사본을 되돌린 뒤 `reg add HKLM\SOFTWARE\OpenSSH /v DefaultShell /t REG_SZ /d "C:\Program Files\PowerShell\7\pwsh.exe" /f`를 넣었다. 새 연결의 `$PSVersionTable.PSVersion.Major`가 `7`, `(Get-Command qsh).Source`가 `C:\Users\dave\.local\bin\qsh.exe`. a~c는 A와 같은 봉투와 pin 모양이다(a `"verified":true`와 exec 성공, b `remote_serve_not_listening`, c `next_command` `qsh serve --to Dave-MacMini`, `registered` 10:10:51부터 3초 안에 `reverse`/`reachable`과 exec 성공). d: `.local\bin` 사본을 지운 뒤(`Get-Command qsh -All` 0개) 종료 코드 255, `{"code":"REMOTE_ERROR","message":"the remote command failed before answering, so nothing was written on either side; if the remote default shell is PowerShell, a missing qsh looks like this (exit 1): put qsh.exe on the remote PATH or pass its full path with --remote-qsh / [ssh].remote_qsh, then run this again","retryable":false,"details":{"reason":"remote_command_failed","remote_exit":1}}`. 원격 stderr는 `qsh: The term 'qsh' is not recognized as a name of a cmdlet, function, script file, or executable program.`과 그 뒤 안내 한 줄이고 양쪽 pin 0개다. e는 A와 같이 `"verified":true`와 exec 성공, f는 a·c `-vv` stderr와 audit에서 0건이다.

정리(A·B): 양쪽 `qsh trust remove`, client의 회차 `qsh listen`과 WR의 `qsh serve`·`qsh serve --to` 종료, `Remove-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell`(뒤의 `reg query`에 값 없음), WR에서 대화형 작업으로 `identity move-key --to file`(`"moved":true`, `"stale_entry_left":false`) 뒤 config·state 디렉터리와 `C:\Tools\qsh` 삭제(`C:\Tools`에는 회차 전부터 있던 항목만 남음), `cmdkey` `.qsh` 0개, `Get-Command qsh -All` 0개, `\qsh\` 작업 0개. sshd는 회차 전 상태 그대로다. 방화벽 규칙 두 개(`C:\tools\qsh\qsh.exe`, TCP·UDP, 이름 `UDP Query User{…}`·`TCP Query User{…}`)는 사용자가 지우라고 한 뒤 `Remove-NetFirewallRule`로 지웠다(뒤의 조회 0개). 사람이 쓰는 Dave-MacMini의 `qsh serve`·`qsh listen`·`qsh tunnel open`은 건드리지 않았다.

**W3b L(v0.5.3, WSL2 controller).** 에이전트(Claude)가 돌렸다. §2.2의 WSL2 예외(2026-10-26 사용자 승인)를 처음 쓴 행이다. W는 Dave-Windows(Windows 11 Pro 25H2 빌드 26200.9711, Tailscale 100.97.123.120), L은 같은 박스의 WSL2 배포판 Dave-Windows-WSL(Ubuntu 24.04.5, 커널 6.18.54.1-microsoft-standard-WSL2, NAT 모드, 자체 tailscaled의 Tailscale 주소 100.67.177.13)이다. W의 `qsh serve --to`는 `localhost` 포워딩이 아니라 WSL2 배포판 자신의 Tailscale 주소로 dial했고, controller `qsh hosts`의 `win` 주소가 `[::ffff:100.97.123.120]:…`이었다. 두 물리 장비 사이의 네트워크 경로는 거치지 않았다. 그 경로는 W3b M 행(v0.5.2, Dave-MacMini)이 봤다. L에는 사람이 쓰는 qsh(`~/.local/bin/qsh` 0.4.3, `qsh serve`가 UDP 4433)가 돌고 있어서 회차용 controller는 별도 바이너리와 `QSH_CONFIG_DIR`·`QSH_STATE_DIR`로 세우고 `qsh listen --bind "[::]:4435"`로 띄웠다. 그래서 §4.13의 `<controller 주소>:4433`은 `100.67.177.13:4435`로 읽는다. 같은 이유로 `ssh L 'command -v qsh'`는 사람이 쓰는 0.4.3을 가리키지만 이 회차는 L의 ssh를 쓰지 않는다. L의 `sshd`는 `active`다. controller tarball `qsh-v0.5.3-x86_64-unknown-linux-gnu.tar.gz` sha256 `3972853995f18ea56e176ef3c3a556770cdd573a82b788e32074c5d262414827`이 `SHA256SUMS`와 같고 `qsh version`은 `qsh 0.5.3 (061bec3acb4dbf8ffe36c59747034cbb409bea94)`다. W의 zip sha256 `41444f592bf6e21b5e046615a3c5235118f01f6719c29ad8b2681ec0889e609d`가 §2.4 넷째 묶음의 줄과 같고, 안의 `qsh.exe` sha256은 `F8EEEE9D77D64684536D2FF7A7204A00216698DAF7E8E088028911ED866FF325`, `qsh version`은 controller와 같다. 시작 전 클린 확인: ssh 세션에서 `Get-Command qsh -All` 0개, config·state 디렉터리 없음, `\qsh\` 작업 0개, qsh 프로세스 0개, 대화형 작업 안에서 `cmdkey` `.qsh` 0개. W의 `qsh init`(기본 `platform`), `identity export`, `trust add`, `qsh serve --to ctl` 시작은 W3b M과 같은 `-LogonType Interactive -RunLevel Limited` 일회용 작업 하나로 돌렸다(첫 줄 `IsInRole('Administrators')`가 `False`). controller identity는 `--key-store file`, pin은 controller `win` role `reverse`, W `ctl` 주소 `100.67.177.13:4435` role `full`이다. W의 `qsh serve --to ctl`은 `C:\qsh-w3bl\qsh.exe`(이 장비에서 `serve`나 `listen`을 띄운 적 없는 경로)이고 stderr에 `{"event":"registered","host":"ctl",…,"at":"2026-10-26T04:53:26Z"}`가 나왔다. a: controller `qsh hosts --json`의 `win` 행 원문은 `{"address":"[::ffff:100.97.123.120]:61925","connection_mode":"reverse","device_id":"sha256:hslZY/Eye0ZNuRlC6NnB2mq6mFQjPEP0xP6At4ZKwog=","name":"win","state":"reachable"}`. `@(Get-NetFirewallApplicationFilter -Program C:\qsh-w3bl\qsh.exe).Count`가 등록 직후와 회차 끝 모두 `0`이고, `serve --to` 시작 25초 뒤 대화형 세션에서 찍은 바탕화면 스크린숏과 창 제목 목록에 방화벽 프롬프트가 없었다(스크린숏은 사람의 화면이 찍혀 있어 보관하지 않았다). b: `qsh win`이 cmd 프롬프트를 열고 `echo 한글 테스트`의 출력이 같다(로그에 UTF-8 `ed 95 9c ea b8 80`). 같은 세션에서 `pwsh -NoLogo -NoProfile`, `& 'C:\Program Files\Vim\vim.exe' -u NONE -N`(vim을 회차용으로 `winget install --id vim.vim --scope machine`으로 깔았다)으로 vim을 열고 `i한글 입력 테스트`를 친 뒤 pty를 24×80, 40×120, 30×90, 45×140으로 바꿨다. 매번 `:echo &columns &lines`가 `80 24`, `120 40`, `90 30`, `140 45`로 답했고, pyte로 다시 그린 화면에서 상태 줄(`1,21-15 All`)이 마지막 행(23, 39, 29, 44)에 있었다. pwsh를 나와 26×82, 44×132에서 `mode con`이 `Lines: 26`/`Columns: 82`, `Lines: 44`/`Columns: 132`를 냈다. `~d`로 빠져나온 뒤(종료 코드 0) `qsh sessions win --json`에 `"state":"running"`인 `win/01M5V8XG8CANDK1ZHQZRKPF7W0`가 있었고 `qsh attach`가 이전 화면(`before-detach-marker`)을 다시 그리고 `echo after-reattach`에 답했다. c: 5 MiB 무작위 파일을 `qsh cp ./payload.bin win:C:/Users/Public/payload.bin`으로 올리고 `qsh cp win:C:/Users/Public/payload.bin ./back.bin`으로 내려받아 sha256이 둘 다 `d378cc4b4584ca780bcd2a83fc0a83043e6e3bc3da00a47bbf170fa707e2488c`이고 W의 `Get-FileHash`도 같다. `qsh cp -r ./tree win:C:/Users/Public/qshtree`가 디렉터리 2개와 파일 2개를 만들었고, `qsh cp ./payload.bin win:`은 `remote_path` `~/payload.bin`으로 `C:\Users\dave\payload.bin`에 올렸다(해시 같음). `chmod 444` 파일을 `qsh cp -p`로 올리자 `attrib`이 `A    R               C:\Users\Public\ro.bin`이고, 내용을 바꿔 다시 올리자 봉투가 `"overwritten":true`, W의 `Get-Content`가 새 내용을 냈다. `qsh cp -p win:C:/Users/Public/ro.bin ./dl/`의 모드는 `444`다. `qsh cp ./payload.bin 'win:\\server\share\x' --json`은 `INVALID_ARGUMENT`(`"message":"1 of 1 entries failed: UNC and device paths are not supported"`, `"copied":0,"created":0`)로 끝났다. d: controller에 `socat TCP-LISTEN:7000,bind=127.0.0.1,reuseaddr,fork EXEC:cat`을 띄우고 `qsh tunnel open win --remote 19000:127.0.0.1:7000 --json`의 봉투가 `{"actual_port":19000,"bind":"127.0.0.1:19000","forward_to":"127.0.0.1:7000","host":"win","mode":"remote","tunnel_id":"01M5V8ZJMTJC0DEXZE5QW7YYM7"}`, W의 §3.2 echo 확인 클라이언트가 `hello-qsh`를 받았다. 그동안 `Get-NetTCPConnection -State Listen -LocalPort 19000`은 `127.0.0.1 19000`, 소유 프로세스 `qsh`(serve --to의 pid)였다. `qsh tunnels --json`에 그 터널이 있었고 `qsh tunnel close 01M5V8ZJMTJC0DEXZE5QW7YYM7 --json`이 `"closed":true`를 낸 뒤 같은 조회가 0개, `qsh tunnels`가 빈 목록이었다. `--supervise` 없는 holder는 v0.5.3의 고침대로 스스로 끝났다(`{"lifecycle":"tunnel_ended",…,"code":"CONNECTION_FAILED"}`, 끝 줄 `the tunnel was closed: its registration is gone from the daemon`). `-L`: W에서 §3.2 echo 서버(7777)를 띄우고 controller에서 `qsh tunnel open win --local 127.0.0.1:18080:127.0.0.1:7777 --json`(봉투 `"mode":"local","actual_port":18080`)을 돌려 `printf 'hello-qsh\n' | nc -w1 127.0.0.1 18080`이 `hello-qsh`를 받았다. expect로 Ctrl-C를 보내자 exit 0으로 끝났고 `nc -z 127.0.0.1 18080`이 실패했다. e: controller `qsh listen`에 SIGINT를 보내자 controller stderr에 `qsh listen: shutting down`, W의 stderr에 `{"event":"lost","host":"ctl",…,"cause":"peer_closed","at":"2026-10-26T04:55:55Z",…}`이 나왔다. 04:56:04에 다시 띄우자 W가 `{"event":"registered","host":"ctl",…,"at":"2026-10-26T04:56:08Z"}`를 냈고 04:56:10에 controller `qsh hosts`의 `win`이 `reverse`/`reachable`이었다. 판정 밖의 관찰 하나: d의 `tunnel close` 뒤 holder가 끝나면서 stderr의 `tunnel_ended` 줄과 끝 줄 사이에 `thread 'tokio-rt-worker' … panicked at …/tokio-1.53.3/src/runtime/task/core.rs:427:22: JoinHandle polled after completion`을 냈다. 터널과 포트는 기준대로 사라졌고 프로세스도 끝났다. claim 실패 뒤 200ms backoff 중 루프가 abort되면 drop reaper가 이미 끝난 `JoinHandle`을 다시 await하던 것이 원인이고, `c8b04ea`(테스트 `tunnel::remote::tests::aborting_a_claim_loop_during_its_retry_backoff_does_not_repoll_a_resolved_handle`)가 고쳤다. 정리: 세션은 `exit`로 끝났고 터널 0개, controller `qsh listen`·socat과 W의 `qsh serve --to` 종료, W에서 대화형 작업으로 `identity move-key --to file`(`"moved":true`, `"stale_entry_left":false`) 뒤 config·state 디렉터리 삭제, `cmdkey` `.qsh` 0개, `\qsh\` 작업 0개, qsh 프로세스 0개, `C:\qsh-w3bl`·`C:\Users\Public`의 회차 파일·`C:\Users\dave\payload.bin` 삭제, vim 제거(`winget uninstall`, 남은 `C:\Program Files\Vim\_vimrc` 삭제), `Get-Command qsh -All` 0개. 방화벽 규칙은 만들지도 지우지도 않았다. controller의 회차 config·state도 지웠고, L에서 사람이 쓰는 `qsh serve`(UDP 4433)는 건드리지 않았다.

**W2 L(v0.5.4, WSL2 client).** 에이전트(Claude)가 돌렸다. §2.2의 WSL2 예외로 L은 Dave-Windows-WSL이고, client는 WH의 Tailscale 주소 100.97.123.120:4433으로 dial했다(두 물리 장비 사이의 경로는 W2 M 몫). L의 사람이 쓰는 qsh와 섞이지 않도록 client는 별도 바이너리와 `QSH_CONFIG_DIR`·`QSH_STATE_DIR`를 썼고 `qsh version`은 `qsh 0.5.4 (2385c7d05d0f2e7cbfdf52e17b1e28140cbd5b24)`다. WH의 zip sha256 `0551A71DD59A005DDE14B75674488A711CF7240AA47B1B71EA70E0B45DFA3AE6`이 §2.4 v0.5.4 줄과 같고 `C:\qsh-w2\qsh.exe` sha256은 `4675214E70B1A5D9FC797710CCFD50955E81502D269BF962D508A6E50D653283`, `qsh version`은 client와 같다. 시작 전 확인: 대화형 작업 안에서 `cmdkey` `.qsh` 0개, config·state 디렉터리 없음. WH의 `qsh init --json`(대화형 비관리자 작업, `admin=False`)이 `fingerprint` `sha256:oDXlPoltRfyraB4YolX8SREEDvMn6C3uIi5Mln8gyQ4=`를 냈고, pin은 절차대로 client `trust add win --address 100.97.123.120:4433 --fingerprint …`와 WH `trust add client --cert-file client.pem --role full`로 세웠다. `Get-NetFirewallApplicationFilter -Program C:\qsh-w2\qsh.exe`는 시작 때 비어 있었다.

a: 첫 시도는 무효다. 07:16:33에 serve가 뜨고 사용자가 07:16:40에 Allow를 눌러, 허용 전 `qsh doctor`를 돌릴 틈이 없었다. 사용자 승인으로 그 경로의 규칙 둘을 `Remove-NetFirewallRule`로 지우고 07:25:13에 같은 경로에서 다시 띄웠다. 방화벽 로그(`Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`)에 07:25:14 `id=2097 rule=qsh app=C:\qsh-w2\qsh.exe action=2 profiles=6 by=C:\WINDOWS\System32\svchost.exe`가 두 줄 남았고, 규칙 이름은 `UDP Query User{64BA3EAF-…}C:\qsh-w2\qsh.exe`와 `TCP Query User{98C11678-…}C:\qsh-w2\qsh.exe`, 둘 다 `qsh | Inbound | Block | Private, Public`이다. 프롬프트가 뜨는 순간 Windows가 그 경로에 차단 규칙을 먼저 만든다는 뜻이다. 대화상자는 "Windows Security / Do you want to allow public and private networks to access this app? / Windows Firewall has blocked some features of qsh.exe on all public and private networks."이고 Show more가 `C:\qsh-w2\qsh.exe`를 가리켰다(사용자 확인). 허용 전 client의 `qsh doctor win --json`에 `{"code":"udp_egress_blocked","status":"error",…}`가 있었고 `remedy`는 "Open outbound UDP (default port 4433) on this machine's firewall. If the target is a Windows machine running `qsh serve` or `qsh listen`, its Windows Defender Firewall drops inbound UDP until qsh is allowed there; allowing it on private networks is enough for peers on the same network. Until the path is open, an existing overlay such as WireGuard or Tailscale is the only workaround."였다. 07:28:56 Allow 뒤 `id=2099 … action=3 … by=C:\Windows\System32\dllhost.exe`로 두 규칙이 `Allow | Private, Public`이 됐고 같은 doctor에 그 finding이 없었다. 07:30:25에 serve를 끄고 같은 경로에서 다시 띄우자 프롬프트도 새 규칙도 없었다(스크린숏, 로그). 같은 파일을 `C:\qsh-w2b\qsh.exe`로 복사해 `serve --bind [::]:4436`을 띄우자 07:30:59에 다시 차단 규칙 둘과 프롬프트가 나왔다(Show more가 `C:\qsh-w2b\qsh.exe`). 사용자가 Cancel을 누른 뒤에도 규칙은 Block 그대로였고, 같은 fingerprint로 4436을 가리키는 pin `win6`의 `qsh doctor win6`가 `udp_egress_blocked`를 냈다. 새 경로 `C:\qsh-w2c\qsh.exe`의 `serve --bind 127.0.0.1:4434`와 `serve --to w2to`(L의 `100.67.177.13:4435`로 pin한 더미 alias, `0.0.0.0:51539`에서 dial해 `CONNECTION_FAILED … dial_timeout`)는 묻지 않았고 그 경로의 규칙은 0개였다. 처음 `serve --to 100.67.177.13:4435`는 `HOST_NOT_FOUND`(pin되지 않은 주소)로 dial 전에 끝나 다시 돌렸다. 시점과 단위, `--to`와 loopback은 README Known limitations와 `docs/CLI.md` §6.13과 맞았다. `remedy`의 두 문장이 어긋났다. "allowing it on private networks is enough for peers on the same network"는 25H2 대화상자에 사설만 고르는 선택이 없어 따를 수 없다. "Until the path is open, an existing overlay such as WireGuard or Tailscale is the only workaround"는 이 회차의 client가 이미 Tailscale로 닿고 있었는데도 막혔으므로 Windows 대상에는 틀리다. 그래서 a는 FAIL이고, `32f5b69`가 remedy를 고쳤다(overlay 우회는 이 장비의 egress에만 걸고, Windows 대상은 overlay 트래픽도 막히며 25H2의 Allow가 두 프로필을 연다고 적음, 테스트 `doctor_docs::udp_egress_blocked_remedy_matches_the_windows_firewall_section`).

b~f는 L에서 expect로 돌렸다. 한글은 IME가 아니라 UTF-8 바이트로 보냈고, 창 크기는 expect pty의 `stty rows/columns`로 바꿨다. WH 계정의 pwsh 프로필 프롬프트는 `~` 줄 다음 `$ `이다. b: `qsh win`이 `C:\Users\dave>`까지 갔고 `echo 한글 테스트`의 출력이 같다. `echo 한글테스`에서 Backspace를 세 번 보내자 `한글테스`→`한글테`→`한글`로 한 글자씩 지워졌다. `ping -t 127.0.0.1`을 Ctrl-C로 끊자 통계와 `Control-C`가 나오고 `echo cmd-alive-marker`가 답했다. `pwsh -NoLogo -NoProfile` 안에서 `'한글 테스트 😀'`의 출력이 같고 위쪽 화살표가 그 명령을 되살렸다. 첫 시도에서는 `qsh: the writer lease moved to device:client` 안내가 한 줄을 차지해 ConPTY의 절대 좌표 출력이 한 행 어긋나 보였고, `cls` 뒤 다시 한 실행은 바로 그렸다. c: pwsh에서 `$env:PATH = 'C:\Program Files\Vim;' + $env:PATH`(vim은 회차용 `winget install`) 뒤 `vim -u NONE -N`, `i한글 입력 테스트`. 24×80, 40×120, 30×90, 45×140마다 `:echo &columns &lines`가 `80 24`, `120 40`, `90 30`, `140 45`였고 pyte로 다시 그린 화면에서 vim 하단 줄이 마지막 행(23, 39, 29, 44)에 있었다. cmd의 `mode con`은 26×82, 44×132, 24×80, 40×120에서 같은 `Lines`·`Columns`를 냈다. `:q!` 뒤 vim 전 화면(`PRE-VIM-MARKER` 포함)이 그대로 돌아왔다. d: `qsh session open win --json -- pwsh -NoLogo`가 `win/01M5VK38Y15K86PKC6Q0F052V9`를 열었고, attach 뒤 `$env:USERPROFILE`이 `C:\Users\dave`, `ping -t 127.0.0.1`이 돌았다. 다른 세션의 PowerShell에서 `$env:QSH_SIGNAL_EVENT_USR1`이 `Local\qsh-sig-4932b4e2d3287668fa12238fb8d6bf43-usr1`이었다. e: 행 시작의 `~d`로 `qsh attach`가 종료 코드 0으로 끝났고 `qsh sessions win`에 그 세션이 `running`이었다. 떨어져 있는 8초 동안 ping의 순번이 566에서 958로 늘었고, 다시 붙자 detach 전의 `$env:USERPROFILE`·`ping -t` 줄과 응답 18줄이 보이고 새 응답이 이어졌다. 재생 화면 중간에 앞선 client 안내(`writer lease moved`, `was released`)가 섞여 나왔다. f: INT(`win/01M5VK7A7MHEZSEQ5HERJ897G1`)는 follow에 `{"type":"session.exit",…,"sequence":527,"exit_code":null,"signal":"SIGINT"}` 다음 `{"type":"session.closed",…,"reason":"closed"}`가 와 맞았다. USR1(`win/01M5VK7KX4WVYPC0GNSPNC788N`)은 출력에 `got-usr1`이 오고 `{"type":"session.exit",…,"sequence":107,"exit_code":null,"signal":"SIGUSR1"}`, `session.closed`가 왔다. 두 번 더(`win/01M5VK88317WNT9BNJG2GJR0GB`, `win/01M5VK8HFBD7Q594C19PX8VSE0`) 같았다. 당시 기준의 `exit_code` 0이 아니어서 f는 FAIL이다. host는 종료 코드 0과 `SIGUSR1`을 함께 넘기고 client가 `docs/CLI.md` §6.4의 배타 규칙으로 `exit_code`를 비운 것이고, unix host는 같은 프로그램에 `exit_code` 0과 `signal` `null`을 낸다. ADR-0047이 Windows를 unix에 맞추고 f의 USR1 기준을 고쳤다(§4.12 아래 문단). 회차 뒤 `qsh sessions win`은 `no sessions`였다. W2 L은 고친 태그로 처음부터 다시 돈다(새 `qsh.exe` 경로라 a의 시작 조건이 다시 선다). WH의 정리는 그 회차 뒤에 한 번에 한다.

**W2 L·M(v0.5.5).** 에이전트(Claude)가 돌렸다. 대상 태그 `v0.5.5`(§2.4 여섯째 묶음). v0.5.4 행의 비고는 WH 정리를 재회차 뒤로 미룬다고 적었지만, §2.3 클린으로 시작하려고 회차 전에 정리했다. 대화형 작업에서 `identity move-key --to file`로 Credential Manager 항목을 거두고(`cmdkey` `.qsh` 1개에서 0개) config·state를 지웠으며, 관리자 ssh 세션에서 `C:\qsh-w2`·`C:\qsh-w2b` 경로의 규칙 넷을 지웠다. 같은 날 사용자 지시로 `C:\users\public` 아래 예전 테스트 바이너리를 가리키던 규칙 92개와 그 폴더도 지워, 회차 시작 때 이름에 qsh가 든 방화벽 프로그램 필터는 하나도 없었다. 시작 전 확인은 대화형 작업 안에서 했다. `cmdkey` `.qsh` 0개, config·state 디렉터리 없음, `\qsh\` 작업 0개, `Get-Command qsh -All` 0개, qsh 프로세스 0개. WH의 zip sha256 `11208080C347A28C152F7B4B09D29BFEFA58449E801A958AC41AAF4533374283`이 §2.4 v0.5.5 줄과 같고, `C:\qsh-w2d\qsh.exe` sha256은 `354D184588224A45B991F68B6B21349A5C078FFC42310A353A12ABA4CF556FAA`, `qsh version`은 `qsh 0.5.5 (297398663304b7ba6a65d70f206f9af40690375d)`다. `qsh init --json`(대화형 비관리자 작업)의 `fingerprint`는 `sha256:+bLhP9fdsX2V1ox1CGSgL0eWYylgfaUgWxLCoQs9tR8=`, `key_store`는 `platform`이다. L client는 v0.5.4 회차의 별도 config(같은 identity)를 이어 쓰고 v0.5.5 바이너리로 바꿨다. M client는 `~/qsh-campaign`의 별도 바이너리·config(file key store)를 v0.5.5로 바꿨다. pin은 절차대로 양쪽 client의 `trust add win --address 100.97.123.120:4433 --fingerprint …`와 WH의 `trust add client`(L)·`trust add clientm`(M) `--cert-file … --role full`로 세웠다. 둘 다 WH의 Tailscale 주소로 dial했고, M은 다른 물리 장비라 실제 망을 지난다.

a는 두 client가 함께 봤다. 프롬프트는 WH마다 한 번만 뜨는 사건이라 L과 M이 같은 serve 기동을 관찰했다. 08:44:57에 `C:\qsh-w2d\qsh.exe serve`(대화형 작업)가 `[::]:4433`을 열자 같은 초에 svchost가 Block 규칙 둘(이벤트 2097, TCP·UDP, Private·Public)을 만들고 "Windows Security" 창이 떴다. 창은 v0.5.4 때와 같은 "Do you want to allow public and private networks to access this app?"이고, Show more가 가리킨 경로는 `C:\qsh-w2d\qsh.exe`였다(사용자 확인). 창을 둔 채 08:45:07에 L과 M에서 `qsh doctor win --json`을 돌리자 둘 다 `udp_egress_blocked`가 있었고, remedy는 "… If the target is a Windows machine running `qsh serve` or `qsh listen`, its Windows Defender Firewall drops inbound UDP, overlay traffic included, until that qsh.exe path is allowed there. Older allow dialogs offer a Private-only choice; on Windows 11 25H2 Allow opens both the Private and Public profiles (docs/CLI.md §6.13)."였다. 11:57:01에 사용자가 Allow를 누르자 dllhost가 두 규칙을 Allow로 바꿨고(이벤트 2099), 같은 명령에서 L과 M 모두 `udp_egress_blocked`가 사라졌다. serve를 끄고 11:57:33에 같은 경로에서 다시 띄우자 창도 새 이벤트도 없었다. 11:57:54에 같은 바이너리(sha256 같음)를 `C:\qsh-w2e`에 복사해 `serve --bind [::]:4436`으로 띄우자 Block 규칙 둘과 창이 다시 생겼고, 창을 둔 채 L의 `qsh doctor win6`(4436)에 `udp_egress_blocked`가 있었다. 사용자는 Cancel을 누르려다 Allow를 눌렀다(12:00:19, 이벤트 2099). 기준은 다시 묻는지까지라 판정에는 닿지 않는다. 12:00:54에 셋째 사본 `C:\qsh-w2f`에서 `serve --to w2to`(가짜 fingerprint의 pin, 100.67.177.13:4435)를, 12:01:05에 `serve --bind 127.0.0.1:4434`를 띄웠다. 둘 다 창이 없었고 그 경로의 규칙은 0개였다. `--to`는 stderr에 `dial_timeout` 재시도를 냈고 loopback은 `127.0.0.1:4434`에 묶였다. 문서 대조: README Known limitations와 `docs/CLI.md` §6.13(v0.62)의 방화벽 문장, 위 remedy가 이번 관찰(경로 단위, 첫 non-loopback bind 때 즉시 Block, overlay로 온 패킷도 허용 전에는 버려짐, 25H2 Allow가 두 프로필을 엶)과 어긋나지 않는다.

b~f는 L과 M을 같은 WH serve(pid 27184)에 동시에 돌렸다. 각 client는 자기가 연 세션만 닫았다. 결과는 두 client에서 같았다. b: `qsh win`이 `C:\Users\dave>`까지 갔고 `echo 한글 테스트`가 그대로 나왔다. `echo 한글테스` 뒤 Backspace를 칠 때마다 `echo 한글테`, `echo 한글`로 한 글자씩 지워졌다. `ping -t 127.0.0.1`은 Ctrl-C에 `Ping statistics`와 `Control-C`를 내고 끝났고 이어 친 `echo`에 cmd가 답했다. `pwsh -NoLogo -NoProfile`에서 `'한글 테스트 😀'`가 같게 나왔고 위쪽 화살표가 직전 명령을 불렀다. M의 macOS 기본 expect(Tcl 8.5)는 BMP 밖 문자를 실어 보내지 못해 😀가 `ð`로 바뀌었으므로, 그 단계만 원시 UTF-8 바이트를 보내고 기록하는 Python pty 스크립트로 다시 했다. 화면은 v0.5.4 때처럼 `cls` 뒤에 봤다. c: pwsh 안 `vim -u NONE -N`에서 24×80, 40×120, 30×90, 45×140마다 `:echo &columns &lines`가 `80 24`, `120 40`, `90 30`, `140 45`였고, pyte로 다시 그린 화면에서 vim 하단 줄이 마지막 행(23, 39, 29, 44)에 있었다. cmd의 `mode con`은 26×82, 44×132, 24×80, 40×120에서 같은 `Lines`·`Columns`를 냈다. `:q!` 뒤 vim 전 화면(`PRE-VIM-MARKER` 포함)이 돌아왔다. d: `qsh session open win --json -- pwsh -NoLogo`로 연 세션(L `win/01M5W1RP35E32CA77NMJZFXNKK`, M `win/01M5W20EJ5NDW6S7GDNB554TEX`)에 attach해 `$env:USERPROFILE`이 `C:\Users\dave`, `ping -t 127.0.0.1`이 돌았다. 다른 세션의 `$env:QSH_SIGNAL_EVENT_USR1`은 L `Local\qsh-sig-3292c4878b69a011b0d3248d6e33fb37-usr1`, M `Local\qsh-sig-7b2d8ba692c028edc546cd97413c5bc5-usr1`이었다. 하네스의 프롬프트 정규식 둘은 v0.5.4 때처럼 프로필 프롬프트(`~` 다음 줄 `$ `)를 `PS …>`로 기대해 FAIL을 찍었지만 로그에 명령과 출력이 그대로 있어 기준과 무관하다. e: 행 시작의 `~d`로 `qsh attach`가 종료 코드 0으로 끝났고 `qsh sessions win`에 그 세션이 `running`이었다. 다시 붙자 detach 전의 `$env:USERPROFILE`·`ping -t` 줄과 응답이 보이고 새 응답이 이어졌다. v0.5.4 때처럼 재생 화면 중간에 writer lease 안내가 섞였다. f: INT(L `win/01M5W1WGYXBWTAV5NFPSEESMRB`, M `win/01M5W24DPYX2SXGACW13KQTW21`)는 follow에 `{"type":"session.exit",…,"sequence":576,"exit_code":null,"signal":"SIGINT"}` 다음 `{"type":"session.closed",…,"reason":"closed"}`가 왔다. USR1은 client마다 세 번 돌렸다(L `win/01M5W1WX9QWC09FDZCASN87FA1`·`win/01M5W1X3N395TAAYYMA33MXGJY`·`win/01M5W1X9YZRVV5BYH5RJ2XRMD3`, M `win/01M5W24QADNPH53VP0RS631KJ4`·`win/01M5W2511YJEVA15DE77Z5EA0P`·`win/01M5W25AQ044EF8NZWHYEJ6XSK`). 여섯 번 모두 출력에 `got-usr1`이 오고 `{"type":"session.exit",…,"sequence":107,"exit_code":0,"signal":null}`, 이어 `session.closed`가 왔다. 하네스 문제 둘은 판정 밖이다. L·M 모두 b의 마지막 `exit` 단계에서 cmd 프롬프트 정규식이 버퍼에 남은 `PS C:\Users\dave>`에 먼저 맞아 expect가 멈췄다. 해당 실행을 끊고 세션을 닫은 뒤 대기를 넣거나 그 단계를 나눠 다시 돌렸다. M의 b에서 `exit`가 종료 코드 254를 낸 것은 인자 없는 `exit`가 직전 ERRORLEVEL(Ctrl-C의 `0xC000013A`)을 돌려준 것이다. 새 `qsh win`의 `exit`는 0, `exit 5`는 5였다.

정리: 열린 세션을 닫고 WH의 serve를 끈 뒤, 대화형 작업에서 `identity move-key --to file`로 Credential Manager 항목을 거두고(1개에서 0개) config·state를 지웠다. 관리자 ssh 세션에서 `C:\qsh-w2d`·`C:\qsh-w2e`·`C:\qsh-w2f`의 규칙을 지우고(`C:\qsh-w2f`는 처음부터 0개) 세 폴더를 지웠다. 회차용 vim은 `winget uninstall`로 지우고 남은 `C:\Program Files\Vim\_vimrc`를 폴더째 지웠다. 두 client의 `win`·`win6` pin을 지웠다.

**W3a L·M(v0.5.5).** 에이전트(Claude)가 돌렸다. 대상 태그 `v0.5.5`(§2.4 여섯째 묶음). W는 Dave-Windows(Tailscale 100.97.123.120)이고 L(WSL2, 100.67.177.13)과 M(Dave-MacMini, 100.98.191.17)을 한 `qsh listen`에 동시에 붙였다. 그래서 host 이름은 `box` 대신 `boxl`·`boxm`이고, b~d는 두 에이전트가 포트와 경로를 나눠 동시에 돌렸다(L은 문서의 18080·7000·7777·19000, M은 18081·7001·7778·19001). 시작 전 확인: 이름에 qsh가 든 방화벽 필터 0개, `cmdkey` `.qsh` 0개, config·state 없음, `\qsh\` 작업 0개, qsh 프로세스 0개. W의 zip sha256 `11208080C347A28C152F7B4B09D29BFEFA58449E801A958AC41AAF4533374283`이 §2.4 v0.5.5 줄과 같고 `C:\qsh-w3\qsh.exe` sha256은 `354D184588224A45B991F68B6B21349A5C078FFC42310A353A12ABA4CF556FAA`, 세 장비의 `qsh version`이 `qsh 0.5.5 (297398663304b7ba6a65d70f206f9af40690375d)`다. W의 `qsh init`은 `--key-store file`이다(`fingerprint` `sha256:hk3lhD+k/aanfxdWABIYT0pCrlUhZ577Qwa0+r+xr8s=`). 회차의 명령을 대화형 작업이 아닌 ssh 세션에서 내야 했고, Credential Manager는 그 세션에서 쓸 수 없다. `qsh listen`의 첫 바인드(`[::]:4433`)에서 방화벽이 12:20:06에 Block 규칙을 만들었고(이벤트 2097) 사람이 프롬프트의 Allow를 누르자 13:01:53에 Allow로 바뀌었다(이벤트 2099, TCP·UDP 인바운드, Private·Public). 두 target 모두 사람이 쓰는 qsh(L `~/.local/bin/qsh` 0.4.3, M `/opt/homebrew/bin/qsh`)가 UDP 4433에서 `qsh serve`로 돌고 있어 §4.2의 "target 방화벽에서 UDP 4433 인바운드를 막은 채로"는 지키지 못했다. 대신 target의 회차용 qsh는 별도 바이너리와 `QSH_CONFIG_DIR`·`QSH_STATE_DIR`을 거는 래퍼(`qshw`)로 세웠고, `serve --to`는 임시 포트로만 dial한다. pin은 W의 ssh config에 `Host boxl`·`Host boxm`을 적고 `qsh pair ssh boxl --reverse --to 100.97.123.120:4433 --remote-qsh <L의 qshw> --json`(M도 같은 꼴)로 세웠다. 결과는 `"direction":"reverse"`, peer role `reverse`, remote `DAVE-WINDOWS` role `full`, `next_command` `qsh serve --to DAVE-WINDOWS`였다. Tailscale SSH가 100.x의 22번을 가로채 `authorized_keys`의 강제 명령은 듣지 않으므로 `--remote-qsh`로 래퍼를 가리켰다. 판정 밖의 관찰 하나: 이 `qsh pair ssh`를 pty 없는 Windows OpenSSH 세션(`ssh dave-windows '…'`)에서 내면 `< NUL`을 붙여도 hello 단계에서 `bootstrap_timeout`으로 끝났고, `ssh -tt`로 연 세션에서는 끝까지 갔다. sshd의 pty 없는 세션이 물려준 `<guid>_POSIX_FD_STATE` 환경 변수를 qsh가 띄운 `ssh.exe`가 그대로 믿어 생긴 것이고, qsh 없이 같은 세션에서 `ssh -T -o BatchMode=yes -- boxl echo hi | findstr hi`만 쳐도 멈췄다. 그 변수를 비우면 `pair ssh`가 0.37초에 끝났다. a: 두 target의 stderr에 `{"event":"registered","host":"DAVE-WINDOWS",…,"at":"2026-10-26T13:08:55Z"}`가 나왔고 W의 `qsh hosts --json`이 `boxl` `[::ffff:100.67.177.13]:55637`, `boxm` `[::ffff:100.98.191.17]:55602`를 둘 다 `"connection_mode":"reverse","state":"reachable"`로 냈다. b: W 터미널은 Windows Terminal이 아니라 WSL에서 연 `ssh -tt`의 ConPTY(conhost, 셸 `cmd.exe`)다. `qsh boxl`·`qsh boxm`이 zsh 프롬프트까지 갔다(두 target의 로그인 셸이 zsh다). `echo 한글 테스트`의 출력이 같고, `echo 한글테스트`에서 Backspace 한 번이 `한글테스`를 남겼다. 위쪽 화살표는 두 target 모두 zsh에 걸린 Atuin 검색 화면을 열어 직전 명령을 보였고 Enter로 그 명령이 돌았다. Tab은 `ls /etc/host`에서 `host.conf hostname hosts hosts.allow hosts.deny`, `ls /tm`에서 `ls /tmp/`가 됐다. `sleep 100`은 Ctrl-C에 끊기고 셸이 남았다. host 쪽 `printf '\xf0\x9f\x98\x80 emoji-out\n'`은 W에 `😀 emoji-out`으로 그려졌다. 기준에 어긋난 것은 이모지 입력이다. `echo 한글 테스트 😀`를 원시 UTF-8 바이트(`f0 9f 98 80`)로 보내자 두 target 모두 `한글 테스트 ��`(U+FFFD)를 냈다. 같은 ssh 세션에서 `pwsh`의 `[Console]::ReadLine()`은 같은 입력을 `F0-9F-98-80`으로 받았으므로, 잃는 곳은 콘솔이 아니라 `qsh.exe`가 raw 모드에서 코드 페이지 65001로 `ReadFile`하는 경로다. conhost가 UTF-16 코드 단위를 하나씩 UTF-8로 바꾸면서 서로게이트 쌍이 깨진다. 그래서 b는 FAIL이다. W1 d 부분: `~d`가 `qsh: detached; the session keeps running`을 내고 cmd 프롬프트로 돌아왔고, 입력이 에코되며 cmd의 위쪽 화살표 history가 `chcp`를 되살렸고, `chcp`는 시작 전과 같은 `Active code page: 437`이었다. `qsh attach <session-ref>` 뒤 `~d`도 같았다. `Ctrl+Break`는 ssh pty로 보낼 수 없어 돌리지 못했다. `qsh sessions boxl`·`qsh sessions boxm`이 그 세션을 `running`, writer `device:DAVE-WINDOWS`로 보였다. attach 때마다 `qsh: the writer lease moved to device:DAVE-WINDOWS`가 한 번에서 세 번 찍혔다. c: L은 3,145,729바이트, M은 3 MiB 무작위 파일을 올리고 내려받았다. `Get-FileHash`가 원본과 왕복본에서 같았고(L `F26C15650BA3AE261ECEBBF6CE651ECACBDB907B599A944071A6DAE096857FCE`, M `069750240DA6465B4F23FAF9635C973F6CC7D85718AB784FD0A1172D49E4080B`) target의 `sha256sum`·`shasum -a 256`도 같았다. 파일 두 개짜리 디렉터리를 `qsh cp -r`로 양쪽 방향으로 옮겼다(`2 files copied`, 하위 디렉터리와 한글 내용 그대로). `C:\qsh-w3\L\dir\a.txt` 같은 operand는 봉투에서 `local_path`로 갔고 host는 `boxl`이었다. `C:nosuchfile.bin`과 `D:\nosuch.bin`도 로컬 경로로 읽혀 각각 로컬 `no such file or directory`와 장치 준비 안 됨 오류가 났고, 두 operand가 다 `C:\…`면 `no operand names a remote host (host:path)`였다. 판정 밖의 관찰 하나: 로컬 원본이 없는 업로드의 오류 문구가 `qsh: /tmp/w3a-L/x -> C:payload-nonexist: no such file or directory (INVALID_ARGUMENT)`로 화살표가 원격에서 로컬을 가리켰다. d: `--local`은 target의 Python echo 서버로 §3.2 확인 클라이언트가 `hello-qsh`를 받았고, holder를 Ctrl-C로 끝내자 W의 그 포트 listener가 0개였다. `--remote`는 W의 §3.2 echo 서버로 target에서 `b'hello-qsh\n'`을 받았다. `qsh tunnels`가 그 터널(L `01M5W5PQBCTDAFSQS1XP65JKA2`, M `01M5W5NW0HT1QA52PG61NTZVXV`)을 보였고 `qsh tunnel close <tunnel-id>` 뒤 target의 19000·19001 listener가 사라졌다(`ss`, `lsof`, M은 접속 `Connection refused`). holder는 `tunnel_ended`, `CONNECTION_FAILED`, `the tunnel was closed: its registration is gone from the daemon`을 내고 끝났다. `--local` holder가 도는 동안 `qsh tunnels`가 `no tunnels`인 것은 `docs/CLI.md` §6.9대로다. holder와 W 쪽 echo 서버는 pty 없는 ssh에서 띄우면 ssh가 끝날 때 같이 죽어서 `ssh -tt` 안에서 돌렸다. e: 13:19:03에 W의 `qsh listen`을 Ctrl-C로 끄자 W에 `qsh listen: shutting down`, 두 target의 stderr에 `{"event":"lost","host":"DAVE-WINDOWS",…,"cause":"peer_closed","at":"2026-10-26T13:19:03Z",…}`가 나왔다. 13:19:28에 다시 띄우자 두 target이 13:19:29에 `registered`를 냈고, 이어 본 W의 `qsh hosts`에서 `boxl`·`boxm`이 둘 다 `reverse`/`reachable`이었다. b의 이모지 입력을 고친 태그로 b를 다시 돈다. 그 전까지 이 구성(`C:\qsh-w3\qsh.exe` 경로와 방화벽 허용, pin, target의 `serve --to`)은 남겨 둔다.

**W5(v0.5.5).** 에이전트(Claude)가 돌렸다. 대상 태그 `v0.5.5`. W3a v0.5.5의 구성을 그대로 이어 썼다. A의 `C:\qsh-w3\qsh.exe listen`은 pid 60248이었고, target 이름은 `box` 대신 `boxl`·`boxm`이다. B 계정은 사용자 승인을 받아 회차용으로 만들었다. 암호는 스크립트 메모리에서만 만들고 어디에도 쓰지 않았다. ssh 세션에는 `runas` 창이 없어서 B의 명령은 같은 장비의 Windows OpenSSH Server에 B로 키 로그온해서 냈다. `localhost`·`127.0.0.1`의 22번은 WSL 쪽 relay로 가서 `127.0.0.2`를 썼다. `whoami`는 `dave-windows\qshtest2`(d는 `dave-windows\qshtest5`)였고, `whoami /groups`에 Administrators가 없었다. B의 `qsh init`은 `--key-store file`이다. 시도했다 버린 경로: ssh 세션에서 `Start-Process -Credential`로 띄운 B 프로세스는 `-LoadUserProfile` 없이는 `0xC0000142`(STATUS_DLL_INIT_FAILED)로 바로 죽었다. 암호 로그온은 sshd 설정이 `PasswordAuthentication no`라 쓸 수 없었다. d의 B 프로필은 `userenv!CreateProfile`로 hive를 로드하지 않고 만들었다. 열거한 A의 pipe 이름은 `\\.\pipe\qsh-0b9375101ef3f308-60248` 하나다. a: B의 `qsh hosts`가 `no hosts`, `qsh tunnels`가 `no tunnels`를 내고 둘 다 exit 0이었다(`--json`은 `"hosts":[]`, `"tunnels":[]`). B의 열거에는 A의 pipe 이름이 보였다. 그동안 A의 `qsh hosts`는 `boxl`·`boxm`을 `reverse reachable`로 냈다. b: B의 `Connect(2000)`가 11 ms 만에 `UnauthorizedAccessException: Access to the path is denied.`로 끝났다. c: B의 `NamedPipeServerStream` 생성이 같은 `UnauthorizedAccessException`으로 실패했고 `CREATED`는 찍히지 않았다. d: B의 `qsh listen --bind 127.0.0.1:4434`가 `qsh listen: listening on 127.0.0.1:4434`와 `{"lifecycle":"listening","at":"2026-10-26T13:46:49Z","process":"listen"}`을 냈고, 8초와 38초에 살아 있었다. 그동안 열거에 `\\.\pipe\qsh-22a0bb9456b1d54f-36824`가 하나 더 있었고 scope가 A와 달랐다. B의 listen을 멈추자 그 이름이 사라졌다. 13:47:07과 13:47:28에 본 A의 `qsh hosts`는 `boxl`·`boxm` 모두 `reachable`이었다. 두 target의 stderr에는 13:19:29의 `registered` 뒤로 새 줄이 없었다. e: A의 `icacls "%USERPROFILE%\.config\qsh\trust.toml"`이 `Dave-Windows\dave:(F)` 한 줄만 냈고 `(I)`가 붙은 줄은 없었다. 정리: B 프로세스, 회차 폴더(`C:\qsh-w5`·`C:\qsh-w5d`·`C:\qsh-w5e`·`C:\qsh-w5f`), 키 쌍, 계정 넷(`qshtest2`~`qshtest5`)을 지웠다. `Start-Process`로 생긴 `qshtest3`의 프로필도 지웠다. `qshtest2`와 `qshtest5`의 프로필(`C:\Users\qshtest2`·`C:\Users\qshtest5`)은 sshd 로그온이 끝난 뒤에도 hive가 `Loaded=True`로 남아 `Remove-CimInstance`가 "being used by another process"로 실패했다. 재부팅이나 로그오프 뒤에 지운다. 방화벽 규칙은 새로 생기지 않았다. 회차 내내 A의 listen과 두 target의 등록은 그대로였다.

**W3a L·M(v0.5.6).** 에이전트(Claude)가 돌렸다. 대상 태그 `v0.5.6`(§2.4 일곱째 묶음). v0.5.5 회차가 b에서 FAIL이라 이모지 입력을 고친 태그(54ce6c5)로 b만 다시 돌았다. a·c·d·e는 v0.5.5 행의 결과를 그대로 쓴다. 구성은 v0.5.5 회차를 그대로 이었다. `C:\qsh-w3\qsh.exe`를 같은 경로에서 v0.5.6 바이너리로 바꿨고(sha256 `9CF921DEB27917598D516C920398C485F262D73C7C7E0F6D804C1E1BB03EF7FA`), 방화벽 Allow 규칙 두 개가 경로 기준이라 그대로 남아 새 프롬프트가 뜨지 않았다. target 두 곳의 회차용 바이너리도 v0.5.6으로 바꿨고, 세 장비의 `qsh version`은 `qsh 0.5.6 (184fce2c2e106853ea6793e2f6c5a96d3a709e44)`이다. W의 `qsh listen`을 다시 띄우자 두 target이 14:12:56~57에 `registered`를 냈다. b: 터미널은 v0.5.5와 같은 `ssh -tt` ConPTY다. L은 14:13:35~14:16:14, M은 14:13:39~14:15:13에 돌았다. `echo 한글 테스트 😀`의 원시 UTF-8 입력이 두 target 모두에서 `한글 테스트 😀`로 나왔다. host에서 본 바이트는 L이 `… 20 f0 9f 98 80`, M이 `od`로 `20 f0 9f 98 80 0a`였다. 한글 입력, Backspace, 위쪽 화살표, Tab 완성, `sleep 100`의 Ctrl-C, host 쪽 이모지 출력, `~d` 뒤 cmd 프롬프트 복귀와 `chcp` 437 유지, `qsh attach`는 v0.5.5와 같았다. `qsh sessions boxl`·`qsh sessions boxm`이 그 세션(`boxl/01M5W8YX83J3PMVPMJZ9VGPMP6`, `boxm/01M5W8YZG9P1G8CC4C7VVA9XQE`)을 보였고, 확인 뒤 두 세션을 닫았다. `Ctrl+Break`는 이번에도 ssh pty로 보낼 수 없어 돌리지 못했다. attach 때마다 writer lease 안내가 찍히는 것도 같았다. 정리(W3a와 W5 공통): W의 listen과 두 target의 `serve --to`를 멈췄다. W에서는 `C:\qsh-w3\qsh.exe`의 방화벽 규칙 두 개, `%USERPROFILE%\.config\qsh`, `%USERPROFILE%\.local\state\qsh`, `C:\qsh-w3`를 지웠다. ssh config는 회차 전 백업으로 되돌렸다. 끝난 뒤 이름에 qsh가 든 방화벽 필터 0개, qsh 프로세스 0개, `cmdkey` `.qsh` 0개였다. L의 회차 디렉터리와 `expect` 패키지, M의 `~/qsh-campaign`도 지웠다. 사람이 쓰는 qsh(L `~/.local/bin/qsh`, M `/opt/homebrew/bin/qsh`와 그 config)는 건드리지 않았다. W5의 프로필 `C:\Users\qshtest2`·`C:\Users\qshtest5`는 정리 때 다시 지워 봤지만 여전히 `Loaded=True`라 실패했다. 2026-10-29 09:00 Dave-Windows를 재부팅했고, 부팅 뒤 SYSTEM 일회용 작업이 09:02:27에 두 프로필을 지웠다. 같은 때 남아 있던 W 밖 회차의 `C:\Users\qshpwtest`(`Loaded=False`)도 지웠다. 끝난 뒤 `C:\Users`에 qsh로 시작하는 폴더와 프로필이 0개이고, 일회용 작업 둘과 그 스크립트도 남지 않았다.

**W12(v0.5.6).** 에이전트(Claude)가 돌렸다. 대상 태그 `v0.5.6`(§2.4 일곱째 묶음). 같은 날 같은 구성으로 `docs/campaigns/p1-ssh-bootstrap.md` R5를 먼저 돌렸고, 그 뒤 W와 B의 상태를 비우고 이 회차를 돌았다. 원격 B는 Dave-Windows-WSL 위 docker 컨테이너다. ubuntu:24.04에 `openssh-server`와 릴리스 자산 `qsh-v0.5.6-x86_64-unknown-linux-gnu.tar.gz`(sha256 `ac9c782a6b1b277841c5c43af0c0bf3fe29bfdfd683e97d1cceda12cec45e8c5`, `SHA256SUMS`와 같다)를 얹었다. 비root 사용자 `qshuser`, 키 인증만(`PasswordAuthentication no`), `/usr/local/bin/qsh`가 비대화형 ssh `PATH`에 있고 `qsh init`을 마쳤으며 `qsh serve`가 떠 있다. `~/.bashrc` 첫 줄은 `echo QSH-RC-SENTINEL-<난수>`다. 컨테이너는 자기 netns와 `sshd`를 가지지만 W와 같은 박스 안이라 두 물리 장비 사이의 네트워크 경로는 거치지 않았다. W는 WSL의 Tailscale 주소 `100.67.177.13`으로 닿았고 localhost 포워딩은 쓰지 않았다. 포트 이탈: WSL의 UDP 4433은 사람이 쓰는 `qsh serve`가 잡고 있어 B의 serve를 `[serve].bind = "0.0.0.0:4436"`에 두고 `-p 4436:4436/udp -p 2422:22/tcp`로 publish했다. W는 부트스트랩 hello의 `serve_bind`로 4436을 알았다. W의 `%USERPROFILE%\.ssh\config`에 더한 줄은 `Host box` / `HostName 100.67.177.13` / `Port 2422` / `User qshuser` / `IdentityFile C:/Users/dave/.ssh/qshc-w12_ed25519` / `IdentitiesOnly yes` / `UserKnownHostsFile C:/Users/dave/.ssh/qshc-w12_known_hosts`다. 마지막 줄은 사람의 `known_hosts`를 건드리지 않으려고 더했다. 키는 W에서 만든 passphrase 걸린 ed25519이고, passphrase는 에이전트 스크립트 메모리에만 두고 ssh 프롬프트에 pty로 입력했다. ssh-agent 서비스는 `Stopped`, `ssh-add -l`은 `Error connecting to agent`였다. 호스트 키는 R5에서 수락해 이 회차의 ssh는 passphrase만 물었다. 시작 상태는 §2.3 클린이다. R5가 만든 W의 `%USERPROFILE%\.config\qsh`를 지우고 B에서 `qsh trust remove DAVE-WINDOWS`를 했다(`no trusted peers`). `cmdkey` `.qsh` 0개, `\qsh\` 작업 0개, qsh 프로세스 0개였다. zip `qsh-v0.5.6-x86_64-pc-windows-msvc.zip`의 sha256 `c0af7b568de05b0dfe5463458cb850f64f80218deeaffae86b3a8242c7efd178`이 §2.4의 줄과 같고 `C:\qsh-w12\qsh.exe`의 sha256 `9CF921DEB27917598D516C920398C485F262D73C7C7E0F6D804C1E1BB03EF7FA`이 zip 안 파일과 같다. W와 B의 `qsh version`은 `qsh 0.5.6 (184fce2c2e106853ea6793e2f6c5a96d3a709e44)`이고 `where qsh`는 `C:\qsh-w12\qsh.exe` 하나다(`PATH`는 구동 세션 안에서만 바꿨다). `chcp`는 437이다. 첫 시도는 구동 세션에 R5의 `QSH_LOG=debug`가 남아 있어 passphrase 프롬프트에서 Ctrl-C로 끊었다(`qsh: ssh failed (exit 255)`). 변수를 비우고 W의 `.config\qsh`를 다시 지운 뒤 처음부터 돌았고, 그때까지 B에는 pin이 없었다. 아래는 그 뒤의 기록이다. a: `qsh box`의 stderr 첫 줄이 `qsh: no qsh pin for "box"; setting one up over ssh (ssh box); set [ssh].bootstrap = "off" to disable`였다. 이어 `WARN platform key store unavailable, falling back to file store reason=Windows ERROR_NO_SUCH_LOGON_SESSION`이 나왔다(ssh 세션에서는 Credential Manager를 쓸 수 없다). 그다음 같은 콘솔에서 ssh가 `Enter passphrase for key 'C:/Users/dave/.ssh/qshc-w12_ed25519':`를 직접 물었고, 입력한 passphrase는 pty 전사에 한 번도 나타나지 않았다. 입력 뒤 `qsh: created this machine's qsh identity first, as `qsh init` would (the bootstrap needs one)`, `qsh: pinned "box" ... role none`, `qsh: pinned this machine on box as "DAVE-WINDOWS". Its trust role is `full`...`가 나왔다. b: W의 `qsh trust list`가 `box  sha256:VowhN/GKZf5Sls7LOJGeiQEWgJCcFYl/eMIeTaih/4E=  100.67.177.13:4436  none  2026-10-30T05:42:44Z`, B가 `DAVE-WINDOWS  sha256:lLdzrjco5T1QYSXbld2lKU4Slu/PluWTruaBh6JhmaQ=  (주소 없음)  full  2026-10-30T05:42:44Z`였다. c: 바로 이어 셸 프롬프트 `qshuser@325a8dfe0782:~$`까지 갔다. 그 앞의 sentinel 줄은 B의 대화형 bash가 `.bashrc`를 읽으며 찍은 것이다. `echo 한글 테스트`가 `한글 테스트`로 나왔고 `echo 한글테스트`에서 Backspace 한 번이 `한글테스`를 남겼다. 행 시작의 `~d`가 `qsh: detached; the session keeps running`을 내고 cmd 프롬프트로 돌아왔으며, 그 뒤 `echo 에코확인 cooked`가 입력하는 대로 에코됐고 위쪽 화살표가 직전 명령을 불러왔다. d: `qsh box`를 다시 치자 고지 줄도 프롬프트도 없이 바로 셸이 열렸다. 그동안 `Get-Process ssh`는 0개였고, B의 sshd 로그의 `Accepted publickey`는 전후 3건 그대로였다. B의 `qsh audit`에 05:44:05Z의 `session.open`과 `session.attach`가 `auth_path: pin`으로 남았다. e: W에서만 `qsh trust remove box`(`removed box`)를 하고 100 KiB 무작위 파일(`C:\qsh-w12\payload.bin`, sha256 `31d40eaef800755e0b506d4d8257b8ede19c69bc1fc54449cfdcbcc9d6607cca`)을 `qsh cp C:\qsh-w12\payload.bin box:/tmp/payload.bin`으로 올렸다. 같은 고지 줄과 ssh의 passphrase 프롬프트가 나왔고, 그 시점에 B의 `/tmp/payload.bin`은 아직 없었다(`ls: cannot access`). 입력 뒤 `qsh: pinned "box" ...`, `qsh: this machine was already pinned on box as "DAVE-WINDOWS"; that pin was left as it is`, `1 file copied, 100.0 KiB in 0.1s`가 나왔다. B의 `sha256sum`이 같은 해시였고, `qsh cp box:/tmp/payload.bin .`로 받은 파일도 `certutil -hashfile`에서 같았다. f: W의 pin을 다시 지우고 `qsh -vv cp C:\qsh-w12\payload.bin box:/tmp/payload2.bin 2> C:\qsh-w12\boot.log`로 돌렸다. ssh 프롬프트는 리디렉션과 상관없이 콘솔에 보였다. `boot.log`는 14줄이고 부트스트랩 쪽 줄은 `stage="spawned" batch_mode=false`, `stage="hello" skipped_lines=1 skipped_bytes=33`이다. 33바이트는 sentinel 줄의 길이이고 줄 자체는 없다. §4.10이 적은 `Select-String -SimpleString`은 pwsh 7에 없는 매개변수라(`A parameter cannot be found that matches parameter name 'SimpleString'`) `-SimpleMatch`로 찾았고 `QSH-RC-SENTINEL`이 0건이었다. passphrase는 에이전트 메모리 안에서 `boot.log`, `qsh audit --json` 출력(`records: []`), W의 `.config\qsh`와 `.local\state\qsh`의 모든 파일, pty 전사 전체를 찾았고 0건이었다. B의 `payload2.bin` sha256도 같았다. 정리: B 컨테이너와 이미지(sentinel 줄, B의 pin과 세션 포함)를 지웠다. W에서는 `%USERPROFILE%\.config\qsh`, `.local\state\qsh`, `C:\qsh-w12`, 임시 키 쌍과 별도 `known_hosts`를 지웠다. ssh config는 백업으로 되돌렸고 sha256이 회차 전과 같은 `242E0A315DA2495C519CA55863EB4815CF2350B3A39FA0B4F5477A3C840F7613`이다. 끝난 뒤 qsh 프로세스 0개, `cmdkey` `.qsh` 0개, `\qsh\` 작업 0개, 이름에 qsh가 든 방화벽 필터 0개였다. 사람이 쓰는 qsh(WSL `~/.local/bin/qsh`, UDP 4433 serve)는 건드리지 않았다.

## 관련 문서

`docs/adr/0035-windows-client.md`(결정 5~8·11·12·14·15·16·17·18·27, 결과 절), `docs/adr/0032-service-manager-activation.md`(결정 12·15), `docs/adr/0044-ssh-bootstrap.md`(결정 2·13·16·22·25), `docs/CLI.md` §6.9·§6.13·§6.14·§6.17·§6.18·§7, `docs/deploy/service.md`(Task Scheduler 절), `docs/deploy/release-secrets.md`(scoop·winget 시크릿), `docs/design/testing.md`(플랫폼 키스토어 릴리스 전 수동 단계, Windows 줄), `docs/campaigns/p1-ssh-bootstrap.md`(R5와 W12, 형식), `docs/campaigns/p1-supervise-wake.md`(W4의 판정과 기록표), `docs/campaigns/m10-clean-vm.md`·`docs/campaigns/p1-aarch64-musl.md`(형식).
