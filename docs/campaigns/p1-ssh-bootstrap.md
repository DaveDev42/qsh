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
| R1 | 2026-10-30 | `v0.5.6` | A: Ubuntu 24.04 컨테이너 `qshc-a`, `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024` / B: Ubuntu 24.04 컨테이너 `qshc-b`, 같은 `ssh -V` (점프 C `qshc-c`) | FAIL | PASS | PASS | PASS | PASS | PASS | 무효 | Claude(에이전트) |
| R2 | 2026-10-30 | `v0.5.6` | A: Ubuntu 24.04 컨테이너 `qshc-a`, `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024` / B: Ubuntu 24.04 컨테이너 `qshc-b`, 같은 `ssh -V` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | Claude(에이전트) |
| R3 | 2026-10-30 | `v0.5.6` | A: Ubuntu 24.04 컨테이너 `qshc-a`, `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024` / B: Ubuntu 24.04 컨테이너 `qshc-b`, 같은 `ssh -V` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | Claude(에이전트) |
| R4 | 2026-10-30 | `v0.5.6` | A: Ubuntu 24.04 컨테이너 `qshc-a`, `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024` / B: Ubuntu 24.04 컨테이너 `qshc-b`, 같은 `ssh -V` | FAIL | PASS | PASS | PASS | PASS | PASS | 무효 | Claude(에이전트) |
| R5 | 2026-10-30 | `v0.5.6` | W: Dave-Windows(Windows 11 Pro 25H2 빌드 26200.9711), `OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2` / B: Dave-Windows-WSL 위 Ubuntu 24.04 컨테이너, `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024` | PASS | PASS | PASS | PASS | PASS | 해당 없음 | PASS | Claude(에이전트) |
| R1 | 2026-10-30 | `v0.5.6` | A: Ubuntu 24.04 컨테이너 `qshc-a`, `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024` / B: Ubuntu 24.04 컨테이너 `qshc-b`, 같은 `ssh -V` (점프 C `qshc-c`, 같은 `ssh -V`) | PASS | PASS | PASS | PASS | PASS | PASS | PASS | Claude(에이전트) |
| R4 | 2026-10-30 | `v0.5.6` | A: Ubuntu 24.04 컨테이너 `qshc-a`, `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024` / B: Ubuntu 24.04 컨테이너 `qshc-b`, 같은 `ssh -V` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | Claude(에이전트) |

열 채우는 법: `클린`부터 `재실행`까지는 `PASS`나 `FAIL` 중 하나다. `결과`는 그 여섯 열이 모두 PASS일 때만 `PASS`다(R5는 해당 열만). 행마다 비고 문단을 표 아래에 회차 번호를 머리에 달아 잇는다. 비고에는 두 장비의 `ssh -V`, 쓴 `~/.ssh/config` 줄, 명령과 출력 원문, 양쪽 `qsh trust list`의 전후, R1에서 직접 닿았는지 여부, R2의 `lsof` 출력, 막힌 지점의 원문 에러를 적는다.

**공통 구성(R1~R4, v0.5.6).** 에이전트(Claude)가 돌렸다. 장비는 Dave-Windows-WSL(커널 6.18.54.1-microsoft-standard-WSL2) 위의 docker 컨테이너이고, 모두 사용자 네트워크 `qshc-net`에 있으며 각자 네트워크 스택과 `sshd`를 가진다(§2.2). 호스트로 publish한 포트는 없다. 이미지는 ubuntu:24.04에 OpenSSH와 릴리스 자산 `qsh-v0.5.6-x86_64-unknown-linux-gnu.tar.gz`(sha256 `ac9c782a6b1b277841c5c43af0c0bf3fe29bfdfd683e97d1cceda12cec45e8c5`, `SHA256SUMS`와 같다)를 얹었고 소스 빌드는 쓰지 않았다. 세 컨테이너의 `qsh version`은 `qsh 0.5.6 (184fce2c2e106853ea6793e2f6c5a96d3a709e44)`, `ssh -V`는 `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024`다. B(`qshc-b`)는 키 인증만 받고(`PasswordAuthentication no`, `KbdInteractiveAuthentication no`) `ssh B 'command -v qsh'`가 `/usr/local/bin/qsh`이며, `qsh init`을 마쳤고 `~/.bashrc` 맨 위에 `echo QSH-RC-SENTINEL-<난수>` 한 줄이 있다. 사람이 하는 passphrase 입력과 host key의 `yes`는 모두 에이전트가 expect로 pty에 입력했다. passphrase는 expect 메모리에만 두었다. 처음 만든 이미지는 설치 때 생긴 host key를 컨테이너들이 함께 써서, 다시 돈 R1·R4는 시작할 때 host key를 새로 만드는 이미지로 돌았다. R2·R3는 B만 ssh 상대로 써서 이 공유가 판정에 닿지 않는다. 하네스 오류(expect 스크립트의 Tcl 오류, B의 `qsh serve` 누락)로 끝까지 못 간 시도는 회차 전 단계에서 버렸고 표에 적지 않았다. 회차가 끝난 뒤 `qshc-*` 컨테이너, 네트워크, 이미지(sentinel 줄 포함)를 지웠다.

**R1 첫 행(무효).** A의 `~/.ssh/config`는 `Host box` / `HostName qshc-b` / `ProxyJump dave@qshc-c`다. 클린한 A의 빈 `known_hosts`에서 `qsh pair ssh box --json`을 치자 C의 host key 확인이 터미널에 떴고, 이어 B의 host key는 BatchMode라 묻지 못하고 `Host key verification failed.`로 끝났다. 출력은 `{"ok":false,"error":{"code":"CONNECTION_FAILED","message":"ssh failed (exit 255); its own error message is above","retryable":true,"details":{"reason":"ssh_failed","ssh_exit":255}}}`이고 B의 `trust.toml`은 그대로였지만, A에는 identity가 생겼다. 평범한 `ssh box`로 B의 host key를 받은 뒤 같은 명령을 다시 돌려 `verified: true`를 얻고 나머지 단계도 모두 통과했지만, 그 실행은 identity가 있는 A에서 시작해(`identity_created: false`) §2.3 클린이 아니었다. 원인은 하네스가 B의 host key를 회차 전에 A에 넣어 두지 않은 것이라 §6의 환경 잡음으로 무효다. 같은 날 다시 돌았다(아래 R1 둘째 행).

**R2.** A의 `~/.ssh/config`는 `Host box` / `HostName qshc-b`다. 시작 때 A의 `~/.config/qsh`와 `~/.local/state/qsh`가 없었고 A·B 모두 `no trusted peers`였다. passphrase 걸린 ed25519 키를 `eval $(ssh-agent -s)`(`SSH_AUTH_SOCK=/tmp/ssh-aNkGL0zGBKeC/agent.35`) 뒤 `ssh-add`로 올렸고 `ssh-add -l`에 `256 SHA256:... dave@qshc-a (ED25519)`가 보였다. `qsh box`가 고지 줄 `qsh: no qsh pin for "box"; setting one up over ssh (ssh box); set [ssh].bootstrap = "off" to disable`을 낸 뒤 ssh가 host key 확인(`Are you sure you want to continue connecting (yes/no/[fingerprint])?`)만 물었고 passphrase는 묻지 않았다. 그 프롬프트가 떠 있는 동안 `lsof -U -a -p <qsh pid>`는 `qsh 346 dave 7u/8u/10u/16u unix ... type=STREAM (CONNECTED)` 네 줄로, 이름 없는 소켓쌍뿐이고 `SSH_AUTH_SOCK` 경로가 없었다. 셸에 닿은 뒤 다시 잰 `lsof`도 같았다. ssh-agent 자신은 `/proc` 접근이 막혀(setgid) lsof가 보여 주지 못해 양성 대조는 만들지 못했고, 자식 ssh가 agent 소켓을 여는 순간도 표본에 잡히지 않았다. 이어 `qsh: created this machine's qsh identity first, as `qsh init` would (the bootstrap needs one)`가 나오고 B의 셸 프롬프트까지 갔다. pin은 A `box sha256:dZ7F+Q... qshc-b:4433 none`, B `qshc-a sha256:JEA+jt... (주소 없음) full`이다. 재실행 동안 `ps`에는 `ssh-agent`와 `qsh box`만 있었고 B의 sshd `Accepted publickey`는 전후 1건 그대로였다. 비밀: 양쪽 pin을 지우고 `QSH_LOG=debug qsh pair ssh box > dbg.out 2>&1`(17줄)을 돌렸다. sentinel과 `SSH_AUTH_SOCK` 값의 `grep -cF`가 0건이고, passphrase는 expect 로그와 qsh의 config·state 디렉터리에서 0건이다. A는 client라 `audit.log`가 없다.

**R3.** A에서 `unset SSH_AUTH_SOCK`을 했고 `ssh-add -l`은 `Could not open a connection to your authentication agent.`였다. 시작 상태와 `~/.ssh/config`는 R2와 같다. `qsh box`에서 host key 확인에 이어 ssh가 `Enter passphrase for key '/home/dave/.ssh/id_ed25519':`를 직접 물었다. 그동안 pty 상태는 `ssh pid 53 tty pts/0: icanon -echo`였고 자식 명령줄은 `ssh -T -a -x -o ClearAllForwardings=yes -o RemoteCommand=none -o RequestTTY=no -o PermitLocalCommand=no -- box qsh pair ssh-respond`였다. expect 로그에 passphrase가 한 번도 나타나지 않았다. 입력 뒤 identity 생성 고지, pin 두 줄, B의 셸 프롬프트까지 갔다. pin은 A `box sha256:4M1bUM... qshc-b:4433 none`, B `qshc-a sha256:E1sUjH... (주소 없음) full`이다. 그 뒤 양쪽 pin을 지우고 같은 상태에서 `qsh pair ssh box --json`을 stdout과 stderr를 나눠 돌렸다. `rc=255`, stdout은 `{"ok":false,"error":{"code":"CONNECTION_FAILED","message":"ssh failed (exit 255); its own error message is above","retryable":true,"details":{"reason":"ssh_failed","ssh_exit":255}}}` 한 줄이고 프롬프트 줄은 0개였다. stderr는 `Pseudo-terminal will not be allocated because stdin is not a terminal.`과 `dave@qshc-b: Permission denied (publickey).`다. 이 실패 전후 A·B 모두 `no trusted peers`였다. 재실행에서는 passphrase 프롬프트 없이 바로 셸이 열렸고 sshd `Accepted publickey`가 전후 1건 그대로였다. 비밀: `QSH_LOG=debug`로 사람 모드 `qsh pair ssh box`를 한 번 더 돌렸고(`stage="spawned" batch_mode=false`) sentinel과 passphrase가 dbg.out, 실패 출력, expect 로그, qsh의 config·state 디렉터리에서 0건이다.

**R4 첫 행(무효).** B에 `iptables -A INPUT -p udp --dport 4433 -j DROP`을 걸고 serve를 띄우지 않은 채, 빈 `known_hosts`에서 §4에 없는 `--json`을 붙여 `qsh pair ssh box --reverse --to qshc-a:4433 --json`을 쳤다. BatchMode라 host key를 묻지 못하고 `Host key verification failed.`, `details.reason: ssh_failed`로 끝났고 A에 identity가 생겼다. 평범한 `ssh box`로 host key를 받은 뒤 다시 돌린 실행은 나머지 확인을 모두 통과했지만 identity가 있는 A에서 시작했고, 요건 2의 프롬프트도 qsh가 띄운 ssh가 아니라 평범한 ssh 호출에서 나왔다. R1 첫 행과 같은 하네스 원인이라 무효다.

**R1 둘째 행.** 회차 전 준비로 A에서 `ssh-keyscan -t ed25519 qshc-b >> ~/.ssh/known_hosts`를 해 B의 host key만 넣었고 C의 것은 넣지 않았다. 시작 때 A의 `~/.config/qsh`와 `~/.local/state/qsh`가 없었고 A·B 모두 `no trusted peers`였다. `~/.ssh/config`는 R1 첫 행과 같다. `qsh pair ssh box --json`(stdout은 파일, stderr는 터미널)에서 qsh가 띄운 ssh가 `The authenticity of host 'qshc-c (10.27.3.4)' can't be established. ... Are you sure you want to continue connecting (yes/no/[fingerprint])?`를 터미널에서 직접 물었다. `--json`이라 붙은 BatchMode가 ProxyJump의 자식 ssh에는 넘어가지 않은 것이다. 프롬프트는 터미널로만 나갔고 stdout 파일에 그 줄은 0개였다. stdout은 `{"ok":true,"data":{"created":true,"direction":"forward","identity_created":true,"peer":{"address":"qshc-b:4433","name":"box","role":"none",...},"remote":{"created":true,"name":"qshc-a","role":"full"},"ssh_proxied":true,"verified":true}}`, `rc=0`이다. A에서 B의 UDP 4433이 직접 닿는 갈래라 `verified: true`이고 `verify_error`는 없다. pin은 A `box sha256:1Inxso... qshc-b:4433 none`, B `qshc-a sha256:iBjTVV... (주소 없음) full`이다. 이어 B는 그대로 두고 A에서 `qsh trust remove box`만 한 뒤 `qsh box`를 쳤다. 고지 줄, ssh, `qsh: pinned "box" on this machine at qshc-b:4433. ...`, `qsh: this machine was already pinned on box as "qshc-a"; that pin was left as it is`, `qsh: ssh reached box through ProxyJump or ProxyCommand, but qsh dials qshc-b directly (it has no relay)...`가 차례로 나오고 B의 셸 프롬프트 `dave@qshc-b:~$`까지 갔다(`ON-qshc-b-dave`). 재실행 동안 `ps`에 ssh가 없었고 sshd `Accepted publickey`는 B 2건, C 2건으로 전후가 같았다. 비밀: 양쪽 pin을 지우고 `QSH_LOG=debug qsh pair ssh box > dbg.out 2>&1`(18줄, `stage="hello" skipped_lines=1 skipped_bytes=31`)을 돌렸고 sentinel이 0건이다. 키는 passphrase 없는 키이고 agent를 쓰지 않아 그 두 검색은 해당 없음이며, A에는 `audit.log`가 없다.

**R4 둘째 행.** 시작 때 A에는 `~/.config/qsh`, `~/.local/state/qsh`, `~/.ssh/known_hosts`가 없었고 A·B 모두 `no trusted peers`였다. B에 `iptables -A INPUT -p udp --dport 4433 -j DROP`을 걸었고 `qsh serve`는 없었다. `ADDR`은 `qshc-a:4433`이다. 사람 모드로 `qsh pair ssh box --reverse --to qshc-a:4433`를 치자 qsh가 띄운 ssh가 `The authenticity of host 'qshc-b (10.27.3.3)' can't be established. ... Are you sure you want to continue connecting (yes/no/[fingerprint])?`를 직접 물었다. 출력은 `pinned box (sha256:EBZoo4...) role reverse` / `remote: pinned qshc-a role full` / `next, on the remote: qsh serve --to qshc-a`와 identity 생성·pin·`nothing was started on box` 안내 줄이다. pin은 A `box sha256:EBZoo4... (주소 없음) reverse`, B `qshc-a sha256:+kwfyv... qshc-a:4433 full`이다. A의 `audit.log`에 `{"principal":"device:box","action":"pair.ssh","resource":"box","decision":"allow","auth_path":"local","role":"reverse"}` 한 줄이 있다. §4의 JSON 필드를 보려고 같은 명령을 `--json`으로 다시 쳤고 `{"ok":true,"data":{"created":false,"direction":"reverse","identity_created":false,"next_command":"qsh serve --to qshc-a","peer":{"address":"","name":"box","role":"reverse",...},"remote":{"created":false,"name":"qshc-a","role":"full"},"ssh_proxied":false,"verified":false}}`이 나왔다. `verify_error`는 없고 `pair.ssh` 레코드는 여전히 한 줄이다. `qsh listen`은 identity가 없으면 거부해 pair 뒤에 띄웠다(`listening on [::]:4433`). B에서 `qsh serve --to qshc-a`를 치자 listen 로그에 `{"event":"registered","host":"box",...}`가 올랐다. 그동안 B의 `/proc/net/udp`에 4433 소켓이 없었고 DROP 규칙의 카운터는 0 패킷이었다. A의 `qsh hosts`는 `box  reverse  reachable  [::ffff:10.27.3.3]:46513`(`--json`은 `"connection_mode":"reverse","state":"reachable"`)이고 `qsh box`로 B의 셸이 열렸다. `audit.log`에는 `pair.ssh` 다음에 `host.reverse` 한 줄(`auth_path: pin`, `role: reverse`)이 더 있다. 재실행 동안 `ps`에 `qsh listen`과 `qsh box`만 있었고 sshd `Accepted publickey`가 전후 2건 그대로였다. 비밀: 양쪽 pin을 지우고 `QSH_LOG=debug qsh pair ssh box --reverse --to qshc-a:4433 > dbg.out 2>&1`(10줄, `stage="spawned" batch_mode=false`)을 돌렸고 sentinel이 dbg.out, `audit.log`, listen 로그에서 0건이다.

**R5.** 에이전트(Claude)가 돌렸다. 구성과 해시, 클린 확인, W의 `Host box` 줄은 `docs/campaigns/p1-windows.md` §7의 W12(v0.5.6) 비고와 같다. B는 Dave-Windows-WSL 위 docker 컨테이너이고 W와 같은 박스 안이다. WSL의 UDP 4433은 사람이 쓰는 `qsh serve`가 잡고 있어 B의 serve를 UDP 4436에 두고 TCP 2422(ssh)와 함께 WSL의 Tailscale 주소 `100.67.177.13`으로 publish했다. W의 ssh-agent 서비스는 `Stopped`, `SSH_AUTH_SOCK`은 비어 있었다. 터미널은 WSL에서 연 `ssh -tt`의 ConPTY(cmd.exe)이고 ssh는 `C:\Windows\System32\OpenSSH\ssh.exe`다. 시작 때 B는 `no trusted peers`였고 W에는 config·state 디렉터리가 없었다. 먼저 친 `qsh pair ssh box --json`은 BatchMode라 처음 보는 host key를 묻지 못하고 `Host key verification failed.`와 `{"ok":false,"error":{"code":"CONNECTION_FAILED","message":"ssh failed (exit 255); its own error message is above","details":{"reason":"ssh_failed","ssh_exit":255}}}`로 끝났다. §4의 R5 문면대로 사람 모드 `qsh pair ssh box`를 치자 같은 콘솔에서 ssh가 `Are you sure you want to continue connecting (yes/no/[fingerprint])?`를 물었고, 보인 지문 `SHA256:X4Xp5bTF3crqbL/W5ul+6KVBFAhQgGP6hsb6kIPPKzs`가 B의 host key와 같았다. 이어 `Enter passphrase for key 'C:/Users/dave/.ssh/qshc-w12_ed25519':`가 떴고 입력한 passphrase는 pty 전사에 나타나지 않았다. 출력은 `pinned box (sha256:VowhN/GKZf5Sls7LOJGeiQEWgJCcFYl/eMIeTaih/4E=) [100.67.177.13:4436] role none` / `remote: pinned DAVE-WINDOWS role full` / `verified`다. W의 identity는 ssh 세션에서 Credential Manager를 못 써 file store로 갔다(`WARN platform key store unavailable, falling back to file store reason=Windows ERROR_NO_SUCH_LOGON_SESSION`). pin은 W `box ... 100.67.177.13:4436 none`, B `DAVE-WINDOWS sha256:TmXOTpNpvvBz7pIQ2ssBzvWYfYOGKUKqnUQOYRa7lPM= (주소 없음) full`이다. 종점은 `verified`이고, 덧붙여 `qsh exec box -- echo r5-dial`이 `r5-dial`을 냈다. 비밀: `QSH_LOG=debug`로 `qsh pair ssh box > r5d.out 2> r5d.err`를 한 번 더 돌렸다(`already pinned ...`, `verified`). `r5d.err`에는 `stage="spawned" batch_mode=false`, `stage="hello" skipped_lines=1 skipped_bytes=33`이 있고, sentinel과 passphrase가 `r5d.err`, `r5d.out`, `qsh audit --json` 출력(`records: []`), W의 config·state 디렉터리 전체에서 0건이다. W에는 `audit.log`가 생기지 않았다. 요건 4와 6은 R5가 보지 않아 재실행 열은 해당 없음이다.

**판정(2026-10-30).** R1~R4가 각각 PASS 행을 하나씩 가지고, Windows 자산이 있는 `v0.5.6`의 R5도 PASS다. FAIL 행이 없어 §5에 따라 캠페인은 PASS다. 무효 두 행은 세지 않는다. 장비가 모두 한 물리 박스 위의 컨테이너인 점은 §2.2가 허용하는 구성이지만, 두 물리 장비 사이의 실제 네트워크와 사람의 손 입력은 이 회차들이 보지 않았다.

## 관련 문서

`docs/adr/0044-ssh-bootstrap.md`(결정 2, 6, 11, 16, 18~22, 결과 절), `docs/CLI.md` §6.11·§7, `docs/design/testing.md`(가짜 `ssh` 하네스), `docs/design/threat-model.md` §4 A16·B30~B32·D15·E15·E16, `docs/campaigns/m10-clean-vm.md`·`docs/campaigns/p1-aarch64-musl.md`(형식).
