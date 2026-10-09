# P1 aarch64 musl 스모크 캠페인 (M13 (c))

상태: 기준 사전 고정. 회차는 아직 돌지 않았다. 대상 태그가 없고, `release.yml`의 `aarch64-unknown-linux-musl` leg은 사람이 돌리는 dispatch run에서 처음 빌드된다.

## 1. 목적과 지위

`docs/ROADMAP.md` M13 범위 (c)는 `release.yml`에 `aarch64-unknown-linux-musl` 자산을 더하고 설치 스크립트가 `QSH_LIBC=musl`일 때 그 자산을 고르게 한다. 이 문서는 그 자산이 구형 glibc를 쓰는 arm64 배포판에서 실제로 설치되고 도는지 사람이 확인하는 절차다. `docs/campaigns/m10-clean-vm.md`가 x86_64 musl 자산을 같은 방식으로 판정했고 이 문서는 그 형식을 이어받는다.

이 캠페인은 M10 DoD 3의 분모를 바꾸지 않는다. DoD 3은 `x86_64-unknown-linux-musl` 한정이고 `docs/campaigns/m10-clean-vm.md`는 이 문서가 생겨도 한 바이트도 바뀌지 않는다. 이 문서의 회차 기록이 곧 M13 (c)의 사람 몫 판정이다.

CI에서는 이미 `release.yml`의 `build` job이 새 leg에서 세 가지를 본다. 빌드, `Static-link evidence (musl)` 스텝, `Release smoke (functional)` 스텝(`QSH_SMOKE_STRICT=1`). 이 캠페인은 GitHub Release에 붙어 나간 자산을 아무것도 설치된 적 없는 구형 glibc arm64 머신에 설치 스크립트로 받아, 정적 링크 증거와 기능 스모크 네 축(§5)을 손으로 다시 밟는다. 러너에는 최신 glibc와 toolchain이 있고 대상 머신에는 없다. 그 차이가 정적 링크 주장이 맞는지 드러내는 자리다.

## 2. 선행 조건

### 2.1 대상 태그

회차는 아래 둘이 모두 성립하는 태그를 대상으로 한다.

- 그 태그의 release run에서 `aarch64-unknown-linux-musl` leg의 `Static-link evidence (musl)`와 `Release smoke (functional)`가 초록이다.
- 그 태그의 `SHA256SUMS`에 `qsh-<tag>-aarch64-unknown-linux-musl.tar.gz` 줄이 있다. `release` job의 `Check every target is published` 스텝이 이 사실을 붉게 만들지만 회차 시작 전에 사람이 한 번 더 본다.

이 leg이 들어오기 전에 찍힌 태그는 대상이 아니다. 그런 태그에서 `QSH_LIBC=musl`로 aarch64 설치를 돌리면 설치 스크립트가 `no aarch64 musl asset is published for <tag>; unset QSH_LIBC to install the glibc build`로 끝난다. 이 문구를 보는 것은 회차가 아니고 설치 스크립트 분기의 관측일 뿐이다.

### 2.2 대상 배포판

구형의 기준은 대상 태그의 `aarch64-unknown-linux-gnu` 자산이 요구하는 glibc보다 낮은 glibc다. 그 자산은 `ubuntu-24.04-arm` 러너에서 빌드되므로 요구 glibc는 2.39까지 올라갈 수 있다. 회차 전에 gnu 자산을 받아 `objdump -T qsh | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1`로 실제 요구 버전을 재고 비고에 적는다.

| # | 이미지 | glibc | 비고 |
|---|---|---|---|
| 1 | Debian 10 arm64 | 2.28 | 기본 대상. 지원이 끝난 배포판이라 `archive.debian.org`를 써야 할 수 있다 |
| 2 | CentOS 7 aarch64 | 2.17 | 더 낮은 선이 필요할 때 |

최소 하나를 돈다. 어느 쪽이든 회차 표의 플랫폼 열에 배포판 이름과 `ldd --version`의 첫 줄을 그대로 적는다. 대조로 같은 이미지에서 gnu 자산을 실행하면 동적 링커가 거부해야 한다. 거부하지 않으면 그 이미지는 구형 glibc가 아니므로 회차로 세지 않는다.

아키텍처는 실제 aarch64여야 한다. x86_64 호스트에서 qemu-user로 돌린 aarch64 이미지는 회차로 세지 않는다. 동적 링커의 거부와 정적 바이너리의 실행이 모두 에뮬레이터를 거치면 판정이 흐려진다.

### 2.3 클린의 정의

`docs/campaigns/m10-clean-vm.md` §2.3을 그대로 적용한다. 회차마다 이미지에서 새로 띄우고 끝나면 버린다.

## 3. 회차 요건 다섯

모든 회차가 아래 다섯을 만족해야 PASS로 적을 수 있다. 다섯은 이 문서가 커밋된 시점에 고정됐고 회차를 돌면서 늘리지 않는다.

| # | 요건 | 어디에 기록하는가 |
|---|---|---|
| 1 | 설치된 실행 파일의 sha256 | 회차 표 "바이너리 sha256" 열 |
| 2 | 설치 경로. `QSH_LIBC=musl`로 실행한 설치 스크립트 | 회차 표 "설치 경로" 열 |
| 3 | 정적 링크 판정 (§4) | 회차 표 "정적 링크" 열 |
| 4 | 기능 스모크 네 축의 수동 재현 (§5) | 회차 표 "스모크 네 축" 열 |
| 5 | gnu 자산의 거부 대조 (§2.2) | 회차 표 "gnu 거부" 열 |

sha256은 설치된 바이너리에서 직접 잰다(`sha256sum "$(command -v qsh)"`). 아카이브 해시와 같을 필요는 없다. 아카이브 해시를 대조했다면 그 사실을 비고에 적는다.

## 4. 정적 링크의 조작적 정의

두 조건이 모두 맞아야 PASS다. 판정 방식은 `docs/campaigns/m10-clean-vm.md` §5와 같다.

첫째, 동적 의존이 없다. `ldd "$(command -v qsh)"`가 정적 PIE면 `statically linked`, 정적 non-PIE면 `not a dynamic executable`을 낸다. 두 문구 어느 쪽이든 PASS로 세되 무엇이 나왔는지 그대로 적는다. 라이브러리 경로가 한 줄이라도 나오면 FAIL이다. `readelf -d "$(command -v qsh)" | grep NEEDED`가 한 줄이라도 나오면 FAIL이다.

둘째, 바이너리가 aarch64 ELF다. `file "$(command -v qsh)"`의 출력에 `ARM aarch64`가 있어야 한다. x86_64 자산이 잘못 들어간 경우를 거르기 위한 조건이다.

`docs/design/testing.md`의 M10 musl 바이너리 RSS 주장 범위 문단이 적듯 musl 바이너리에는 `docs/PRD.md` §13의 idle 30 MB를 주장하지 않는다. 이 회차에서 RSS를 재지 않는다.

## 5. 기능 스모크 네 축

`docs/campaigns/m10-clean-vm.md` §6.0부터 §6.5까지를 그대로 밟는다. 임시 홈과 설정 디렉터리 export, `init --key-store file`, 양방향 trust, `exec --json` 왕복, PTY 셸과 detach와 재부착의 순서와 확인 항목이 모두 같다. 이 문서는 그 절차를 복제하지 않는다. 절차가 바뀌면 그 문서가 기준이다.

## 6. 판정 규칙

> 구형 glibc arm64 회차 1건이 회차 표에 PASS로 기록되고, 그 행에 바이너리 sha256과 설치 경로가 있다.

풀어 적으면 이렇다.

- 회차 표에 `결과 = PASS`인 행이 최소 1건 있다.
- 그 행의 설치 경로가 `QSH_LIBC=musl`로 실행한 설치 스크립트다. 수동 다운로드만 밟은 행은 설치 스크립트의 aarch64 분기를 재지 못하므로 이 조건을 채우지 못한다.
- 정적 링크, 스모크 네 축, gnu 거부가 모두 PASS다.
- sha256 64자와 설치 경로가 비어 있지 않다.

한 회차라도 FAIL이면 캠페인은 FAIL이다. 통과한 회차만 세지 않는다.

## 7. 사후 변경 금지와 실패 시 처분

§3의 요건 다섯, §4의 판정 정의, §6의 판정 규칙은 이 문서가 처음 커밋된 그대로 남는다. 회차를 돌다가 기준이 부족해 보여도 그 회차 중에는 고치지 않는다. FAIL한 회차는 표에 FAIL로 남고 뒤에 PASS한 회차가 그 행을 지우지 않는다.

FAIL이 나오면 원인을 분류한다.

- 릴리스 결함 (자산이 빠졌다, 동적 의존이 있다, x86_64 바이너리가 들어갔다). 워크플로나 코드를 고치고 새 태그를 찍어 처음부터 다시 돈다. 찍은 태그는 옮기지 않는다.
- 제품 결함 (설치는 됐는데 네 축 중 하나가 qsh 자신의 문제로 실패했다). 이슈로 올리고 고친 뒤 새 태그로 재측정한다.
- 환경 잡음 (이미지가 클린하지 않았다, gnu 자산이 거부되지 않아 구형 glibc가 아니었다, 에뮬레이터 위에서 돌았다). 그 회차는 PASS도 FAIL도 아닌 무효로 적고 세지 않는다.

## 8. 회차 표

| 회차 | 날짜(UTC) | 플랫폼/이미지 | 설치 경로 | 바이너리 sha256 | 정적 링크 | 스모크 네 축 | gnu 거부 | 결과 | 기록자 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-10-09 | Debian 10 aarch64 (컨테이너, Dave-MBP16 colima dockerd, 네이티브 arm64), `ldd (Debian GLIBC 2.28-10+deb10u3) 2.28` | curl (`QSH_LIBC=musl`) | f793ad1b9f52741860fc6e1bf81b44ff8d858d3bef3a8f810def25ad20fc6ee3 | PASS | PASS | PASS | PASS | Claude(에이전트) |

열 채우는 법은 `docs/campaigns/m10-clean-vm.md` §8과 같다. `정적 링크`, `스모크 네 축`, `gnu 거부`는 `PASS`나 `FAIL` 중 하나이고, `결과`는 세 열이 모두 PASS이고 sha256과 설치 경로가 비어 있지 않을 때만 `PASS`다. 행마다 비고 문단을 표 아래에 회차 번호를 머리에 달아 잇는다. 비고에는 대상 태그와 그 태그가 가리키는 커밋, release run id, gnu 자산이 요구한 glibc 최고 버전, `ldd --version` 첫 줄, `ldd`와 `file` 출력 원문, gnu 자산을 실행했을 때 동적 링커의 거부 문구, 막힌 지점의 원문 에러를 적는다.

**회차 1.** 대상 태그 `v0.4.3` → `f7ed074`(`f7ed07464f9e2db3cf1e96710c9662a4225b443b`), release run 37713234863. 기록자 열은 회차를 돌린 사람을 적게 돼 있지만 이 회차는 에이전트(Claude)가 돌렸다. `docs/campaigns/m10-clean-vm.md` 회차 1·2와 같이 VM이 아니라 이미지에서 막 띄운 컨테이너를 회차로 셌고, 캠페인을 닫을 때 사람이 다시 볼 항목이다. 환경은 Dave-MBP16의 colima dockerd에서 `--platform linux/arm64`로 띄운 `debian:10`이고 Apple silicon 위의 네이티브 arm64다(qemu 에뮬레이션이 아니다). `uname -m`은 `aarch64`, `ldd --version` 첫 줄은 `ldd (Debian GLIBC 2.28-10+deb10u3) 2.28`. `sources.list`를 `archive.debian.org`로 바꾸고 `curl ca-certificates tmux binutils file`을 더 설치했다. 시작 전 `which -a qsh` 0건, qsh 상태 디렉터리와 `QSH_*` 환경변수 없음.

gnu 거부(§2.2): `QSH_LIBC` 없이 `QSH_VERSION=v0.4.3`으로 설치하자 스크립트가 `detected target: aarch64-unknown-linux-gnu`을 찍었다. 이 자산이 요구하는 glibc 최고 버전은 `objdump -T` 기준 `GLIBC_2.39`다. 실행하자 동적 링커가 `` /lib/aarch64-linux-gnu/libm.so.6: version `GLIBC_2.29' not found (required by /root/.local/bin/qsh) ``를 포함해 `GLIBC_2.29`·`2.30`·`2.32`·`2.33`·`2.34`·`2.38`·`2.39` 여덟 줄을 내고 exit 1로 거부했다. 대조용 바이너리와 man 페이지를 지웠다.

설치와 정적 링크: `QSH_LIBC=musl QSH_VERSION=v0.4.3`으로 같은 curl 한 줄을 돌렸다. 스크립트는 `detected target: aarch64-unknown-linux-musl`, `verifying checksum`, `warning: provenance not verified: 'gh' (GitHub CLI) is not installed. Installing on the SHA256SUMS check alone.`, `installed qsh v0.4.3 to /root/.local/bin/qsh`, `installed 51 man page(s)`를 찍었다. `ldd`는 `not a dynamic executable`, `readelf -d`에 `NEEDED` 행 없음, `file`은 `ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked`. `qsh --version`은 `qsh 0.4.3`, `.data.build.commit`은 `f7ed07464f9e2db3cf1e96710c9662a4225b443b`.

스모크 네 축은 `docs/campaigns/m10-clean-vm.md` §6.0~§6.5를 tmux 창 둘에서 loopback으로 밟았다. 축 3의 `exec`는 exit 7과 stdout 한 줄의 순수 JSON을 냈고, 축 4는 `~d` 분리 뒤 `qsh attach`로 같은 세션에 붙어 `QSH-SMOKE-REATTACH-OK`를 받았다. 첫 시도는 회차 밖의 하네스 결함으로 버렸다. 스모크 드라이버의 fingerprint 정규식이 hex만 받아서 base64인 qsh fingerprint를 놓쳤다. 컨테이너를 새로 띄워 준비부터 다시 밟은 결과만 이 행에 적었다. 끝나고 컨테이너를 지웠다.

## 관련 문서

`docs/ROADMAP.md` M13(범위 (c)), `docs/campaigns/m10-clean-vm.md`(§2.3, §5, §6, §8~§11의 형식과 절차), `docs/design/testing.md`(L9/L10의 M10 musl 바이너리 RSS 주장 범위), `crates/qsh-cli/tests/release_smoke.rs`(네 축의 CI 대응물), `scripts/README.md`(설치 스크립트와 `QSH_LIBC`).
