# P1 SSH 부트스트랩 캠페인 — 실제 OpenSSH 위에서 `qsh box`부터 셸 프롬프트까지 (M16 (a))

상태: 기준 사전 고정. 회차는 아직 돌지 않았다. 대상 태그가 없다. M16 (a)의 구현 마지막 스텝(자동 발동) 전에 이 문서를 고정한다.

## 1. 목적과 지위

ADR-0044는 시스템 `ssh`를 한 번 거쳐 양쪽 pin을 세우는 부트스트랩(`qsh pair ssh`, 그리고 미등록 이름에 대한 `qsh [user@]host`와 `qsh cp`의 자동 발동)을 정했다. CI 테스트는 가짜 `ssh` 하네스(`crates/qsh-testkit`의 `qsh-fake-ssh`)로 인자, stdio, 종료 코드, 취소를 끝에서 끝까지 건다. 하네스가 흉내 내지 못하는 것은 실제 OpenSSH의 동작이다. `ProxyJump`, `ssh-agent`, 암호 걸린 키의 터미널 프롬프트, host key 확인, 설정 파일의 `RemoteCommand`와 `-o RemoteCommand=none`의 충돌 같은 것들이다. 이 문서는 그 부분을 사람이 확인하는 절차다.

판정은 합격/불합격이다. PASS가 기록되기 전에는 SSH 부트스트랩이 실제 OpenSSH 위에서 동작한다고 적지 않는다. 자동 테스트로 대신하지 않는다.

이 캠페인은 `docs/campaigns/m10-clean-vm.md`와 `docs/campaigns/p1-aarch64-musl.md`의 형식을 따른다. 시간을 재지 않는다. 합격은 시간이 아니라 아래 요건의 충족이다.

## 2. 선행 조건

### 2.1 대상 태그

회차는 M16 (a)의 자동 발동(`qsh [user@]host`·`qsh cp`의 미등록 이름, ADR-0044 결정 2)까지 담긴 태그를 대상으로 한다. 그 태그의 release run이 초록이고 `SHA256SUMS`에 대상 플랫폼의 자산이 있어야 한다. 태그가 없는 동안 회차는 열리지 않는다.

### 2.2 장비

| 역할 | 조건 |
|---|---|
| client (장비 A) | Linux 또는 macOS. 대상 태그의 `qsh`가 `PATH`에 있고, 한 번도 설정한 적이 없다(§2.3). 시스템 `ssh`는 OpenSSH 7.6 이상이다 |
| remote (장비 B) | Linux 또는 macOS. 진짜 `sshd`가 돈다. 대상 태그의 `qsh`가 비대화형 ssh 셸의 `PATH`에 있다(`ssh B 'command -v qsh'`로 확인). `qsh init`이 끝나 있다. 정방향 회차(R1~R3)에서는 `qsh serve`가 떠 있고 UDP 4433이 A에서 닿는다 |
| 점프 호스트 (장비 C) | R1만 쓴다. B로 ssh할 수 있는 별도 `sshd` |
| Windows client (장비 W) | R5만 쓴다. Windows 10 1809 이상, 기본 탑재 `ssh.exe`, Windows 자산이 붙은 태그 |

A와 B는 서로 다른 장비다. 한 장비 안의 loopback ssh는 회차로 세지 않는다. 컨테이너나 VM은 그것이 별도 네트워크 스택과 별도 `sshd`를 가지면 회차로 센다.

### 2.3 클린의 정의

회차 시작 때 장비 A에는 다음이 없다.

- `$XDG_CONFIG_HOME/qsh`(보통 `~/.config/qsh`)와 `$XDG_STATE_HOME/qsh` 전체. 특히 `identity`, `trust.toml`, `hosts.toml`, `config.toml`이 없다. 이 회차는 identity가 없는 상태에서 시작하는 것이 요점이다(ADR-0044 결정 18).
- OS 자격 증명 저장소의 `service=qsh` 항목.
- 장비 B의 `trust.toml`에 A의 fingerprint(회차 전에는 알 수 없으므로 B의 `trust.toml`이 비어 있거나 다른 장비만 담는지로 본다)가 있는 pin.

B에서는 회차마다 `qsh trust list`를 시작 전과 끝난 뒤에 적는다.

## 3. 공통 요건

R1~R4는 아래 여섯을 모두 만족해야 PASS다. 여섯은 이 문서가 커밋된 시점에 고정됐고 회차를 돌면서 늘리지 않는다. R5는 §4의 R5 항목이 따로 정한다.

| # | 요건 | 어디에 기록하는가 |
|---|---|---|
| 1 | 시작 상태가 §2.3과 같다 | 회차 표 "클린" 열 |
| 2 | 시스템 ssh가 터미널에서 직접 묻는다. 암호, passphrase, host key 확인 중 그 회차가 만드는 것이 qsh 출력이 아니라 ssh 자신의 프롬프트로 나타났다 | 회차 표 "ssh 프롬프트" 열 |
| 3 | 양쪽 `trust.toml`이 기대한 모양이다(R별 기대는 §4). 정방향이면 A의 pin은 role `none`이고 B의 pin은 role `full`에 주소가 비어 있다. 역방향이면 A의 pin은 주소 없이 `reverse`이고 B의 pin은 A의 `--to` 주소와 `full`이다 | 회차 표 "pin" 열 |
| 4 | 결과 명령이 끝까지 간다. 정방향은 셸 프롬프트까지, 역방향은 B의 `qsh serve --to`가 등록해 A의 `qsh hosts`에 live로 오르고 A에서 셸이 열리는 데까지 | 회차 표 "종점" 열 |
| 5 | 비밀이 qsh 쪽에 남지 않는다. `QSH_LOG=debug`로 한 번 더 돌린 출력과 A의 `audit.log`에서 passphrase, 암호, `SSH_AUTH_SOCK` 값, 원격 `~/.bashrc`가 찍은 sentinel 문자열(§3.1)이 `grep`으로 0건이다 | 회차 표 "비밀" 열 |
| 6 | 두 번째 실행이 ssh를 부르지 않는다. 같은 명령(`qsh box`)을 다시 치면 pin이 있으므로 ssh 프로세스가 뜨지 않고 바로 접속한다(`ps`나 sshd 로그로 확인) | 회차 표 "재실행" 열 |

### 3.1 sentinel

B의 `~/.bashrc`(비대화형 ssh 셸이 읽는 파일)에 `echo QSH-RC-SENTINEL-<난수>`를 한 줄 넣어 rc 출력이 부트스트랩 스트림 앞에 섞이게 한다. 이 줄이 있어도 부트스트랩은 성공해야 하고(ADR-0044 결정 11) 그 문자열이 qsh 출력과 로그에 나타나지 않아야 한다(요건 5). 회차가 끝나면 이 줄을 지운다.

## 4. 회차

각 회차는 요건 여섯을 채우고, 아래의 추가 확인을 한다.

**R1 정방향, ProxyJump.** A의 `~/.ssh/config`에 `Host box` / `HostName B` / `ProxyJump C`를 둔다. 먼저 `qsh pair ssh box --json`을 돌려 `data.ssh_proxied`가 `true`인지 본다. A에서 B의 UDP 4433이 직접 닿으면 `data.verified`가 `true`여야 한다. 직접 닿지 않으면 `verified: false`이고 `verify_error.message`에 ProxyJump를 쓰지 않는다는 말이 있어야 한다(ADR-0044 결정 6). 두 경우 중 어느 쪽이었는지 비고에 적는다. 그다음 B 쪽을 정리하지 않고 `qsh trust remove box`만 A에서 하고, `qsh box`로 자동 발동 경로를 한 번 더 밟는다(고지 줄, ssh, 셸).

**R2 정방향, ssh-agent.** passphrase가 걸린 키를 `ssh-add`로 agent에 올린 상태(`ssh-add -l`에 키가 보임)에서 `qsh box`를 친다. ssh 프롬프트가 passphrase를 묻지 않아야 하고, 호스트 키를 처음 보면 확인만 묻는다. qsh 프로세스가 agent 소켓을 열지 않았다는 증거로 부트스트랩이 도는 동안 `lsof -U -a -p <qsh pid>`에 `SSH_AUTH_SOCK` 경로가 없음을 적는다(그 소켓을 여는 것은 자식 ssh뿐이다).

**R3 정방향, 암호 걸린 키.** agent를 쓰지 않고(`SSH_AUTH_SOCK` 해제), 키에 passphrase가 걸려 있고, 암호 로그인은 꺼 둔 상태에서 `qsh box`를 친다. ssh가 터미널에 passphrase를 묻고 사람이 입력한다. 입력 중 qsh가 글자를 가로채거나 에코를 켜지 않는다. 끝나면 셸 프롬프트까지 간다. 같은 상태에서 `qsh pair ssh box --json`을 돌리면 `BatchMode=yes`라 프롬프트 없이 곧바로 실패하고(`details.reason`은 `ssh_failed`) 프롬프트 줄이 stdout에 나타나지 않는다. 이 실패에서 양쪽 `trust.toml`이 바뀌지 않았음을 적는다.

**R4 역방향.** A에서 `qsh listen`을 띄운다(B가 A로 닿는 주소를 `ADDR`이라 한다). `qsh pair ssh box --reverse --to ADDR`를 돌린다. 결과는 `verified: false`, `verify_error` 없음, `next_command`가 `qsh serve --to <이름>`이다. B의 pin은 `ADDR`과 `full`이고 A의 pin은 주소 없이 `reverse`다. A의 `audit.log`에 `action: "pair.ssh"`, `role: "reverse"` 레코드가 한 줄 있다. B에서 `next_command`를 그대로 친다. A의 `qsh hosts`에 `connection_mode: reverse`, `state: reachable`로 오르고 `qsh box`로 셸이 열린다. 이 경로에서 B는 UDP를 열어 두지 않아도 된다(B 방화벽에서 4433 인바운드를 막은 채로 돌린다).

**R5 Windows client, 명시 `qsh pair ssh`.** Windows 자산이 붙은 태그에서만 돈다. 장비 W의 `ssh.exe`로 `qsh pair ssh box`를 친다. ssh 프롬프트가 같은 콘솔에서 뜨고, 끝나면 양쪽 pin이 정방향 모양(요건 3)이다. 이 회차에는 요건 1~3과 5만 적용한다. Windows의 대화형 attach와 `qsh cp`는 M19이므로 요건 4와 6의 `qsh box`는 이 회차에서 보지 않고 `data.verified`가 `true`인 확인 dial까지를 종점으로 본다(B에서 `qsh serve`가 떠 있고 UDP 4433이 W에서 닿는 상태). Windows 대화형 회차는 M19의 `docs/campaigns/p1-windows.md`가 이어받는다. 대상 태그에 Windows 자산이 없으면 이 행은 "해당 없음"으로 적고 M19로 넘긴다.

## 5. 판정 규칙

> R1~R4가 각각 한 번 이상 회차 표에 PASS로 기록되고, 각 행에 대상 태그와 §3의 여섯 열이 모두 채워져 있다. Windows 자산이 있는 태그라면 R5도 PASS다.

풀어 적으면 이렇다.

- 회차 표에서 R1, R2, R3, R4 각각에 `결과 = PASS`인 행이 하나 이상 있다.
- PASS인 행은 §3의 요건 여섯(R5는 해당 요건)이 모두 PASS이고 대상 태그와 두 장비의 `ssh -V`가 비고에 있다.
- 한 회차라도 FAIL이면 캠페인은 FAIL이다. 통과한 회차만 세지 않는다.

## 6. 사후 변경 금지와 실패 시 처분

§3의 요건, §4의 회차 구성, §5의 판정 규칙은 이 문서가 처음 커밋된 그대로 남는다. 회차를 돌다가 기준이 부족해 보여도 그 회차 중에는 고치지 않는다. FAIL한 회차는 표에 FAIL로 남고 뒤에 PASS한 회차가 그 행을 지우지 않는다.

FAIL이 나오면 원인을 분류한다.

- 제품 결함 (고지 줄이 없다, 비밀이 로그에 남았다, 충돌인데 덮어썼다, 역방향 pin의 모양이 다르다). 이슈로 올리고 고친 뒤 새 태그로 다시 돈다. 찍은 태그는 옮기지 않는다.
- ssh 호환 결함 (`-o RemoteCommand=none`이 어떤 설정과 충돌한다, 특정 OpenSSH 버전이 고정 인자를 거부한다). 제품 결함으로 분류하되 두 장비의 `ssh -V`와 거부 문구 원문을 이슈에 붙인다. 가짜 `ssh` 하네스에 같은 재현을 더하는 것이 고침의 일부다.
- 환경 잡음 (§2.3의 클린이 아니었다, B의 `qsh`가 비대화형 셸의 `PATH`에 없었다, UDP 경로를 막은 방화벽이 회차 설계 밖이었다). 그 회차는 PASS도 FAIL도 아닌 무효로 적고 세지 않는다.

## 7. 회차 표

| 회차 | 날짜(UTC) | 대상 태그 | A / B (OS, `ssh -V`) | 클린 | ssh 프롬프트 | pin | 종점 | 비밀 | 재실행 | 결과 | 기록자 |
|---|---|---|---|---|---|---|---|---|---|---|---|

열 채우는 법: `클린`부터 `재실행`까지는 `PASS`나 `FAIL` 중 하나다. `결과`는 그 여섯 열이 모두 PASS일 때만 `PASS`다(R5는 해당 열만). 행마다 비고 문단을 표 아래에 회차 번호를 머리에 달아 잇는다. 비고에는 두 장비의 `ssh -V`, 쓴 `~/.ssh/config` 줄, 명령과 출력 원문, 양쪽 `qsh trust list`의 전후, R1에서 직접 닿았는지 여부, R2의 `lsof` 출력, 막힌 지점의 원문 에러를 적는다.

## 관련 문서

`docs/adr/0044-ssh-bootstrap.md`(결정 2, 6, 11, 16, 18~22, 결과 절), `docs/CLI.md` §6.11·§7, `docs/design/testing.md`(가짜 `ssh` 하네스), `docs/design/threat-model.md` §4 A16·B30~B32·D15·E15·E16, `docs/campaigns/m10-clean-vm.md`·`docs/campaigns/p1-aarch64-musl.md`(형식).
