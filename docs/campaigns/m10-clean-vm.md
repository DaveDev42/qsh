# M10 클린 VM 스모크 캠페인 (DoD 1·2·3)

상태: 기준 확정. 태그 `v0.3.0`으로 §2.2 표의 Linux 플랫폼 셋(3·4·5번)을 §8의 회차 1·2·3으로 돌아 셋 다 PASS했고 macOS 둘(§2.2 표의 1·2번)은 아직 돌지 않았다. `v0.3.0`은 Apple 시크릿 없이 찍힌 태그라 §2.1에 따라 DoD 2를 판정하지 않는다. 그래서 이 태그로는 캠페인이 PASS로 닫히지 않고, 서명·공증이 붙은 다음 태그에서 다섯 회차를 다시 돈다.

## 1. 목적과 지위

`docs/ROADMAP.md` M10의 수용 기준은 세 문장이다.

> 클린 macOS arm64/x86_64·Linux arm64/x86_64에서 brew/curl 설치 → 동작. Gatekeeper가 notarized 바이너리를 차단하지 않음. musl static 바이너리가 구형 glibc 배포판에서 실행.

같은 절의 2026-08-21 감사 개정이 "동작"을 다시 정의한다.

> "동작"의 정의는 `version --json`이 아니라 **기능 스모크**다: init → trust → `exec --json` 왕복 + PTY 셸 획득 + detach→attach resume이 배포되는 release 프로파일 바이너리로 통과.

이 문서는 그 세 문장을 사람이 클린 VM에서 실행할 수 있는 절차로 옮긴다. `docs/campaigns/m8-soak.md`나 `docs/campaigns/m2-mobility.md`와 달리 참고 자료가 아니다. `docs/campaigns/m9-stopwatch.md`와 같은 자리다: 이 캠페인의 회차 기록이 곧 M10 DoD 1·2·3의 판정이다.

CI가 이미 하는 일과 이 캠페인이 하는 일은 다르다. `release.yml`의 `build` job은 자기가 방금 빌드한 바이너리를 자기 러너에서 `Release smoke (functional)` 스텝으로 돌린다(`release_smoke_covers_init_trust_exec_pty_detach_and_reattach`, 커밋 `152dd78`). 이 캠페인은 GitHub Release에 붙어 나간 자산을 아무것도 설치된 적 없는 머신에 내려받아 설치한 뒤 같은 네 축을 손으로 다시 밟는다. 러너에는 toolchain과 캐시와 이미 신뢰받은 실행 이력이 있고 클린 VM에는 없다. 그 차이가 Gatekeeper 판정과 glibc 의존을 드러내는 자리다.

## 2. 선행 조건

### 2.1 첫 M10 태그

회차는 아래 넷이 전부 얹힌 트리에 찍힌 태그를 대상으로 한다.

- musl leg (`x86_64-unknown-linux-musl`, 커밋 `168e00c`). `Static-link evidence (musl)` 스텝이 로그에 서야 한다.
- darwin 두 leg의 Developer ID 서명과 공증 (커밋 `c61111b`). `Check for Apple signing secrets` 스텝이 `All six Apple signing secrets are set; signing and notarizing.`을 찍어야 한다.
- provenance attestation (커밋 `d7bede7`). `release` job의 `Attest build provenance` 스텝.
- unix 아카이브의 man page와 tap formula의 `man1.install` 한 줄. 이 항목이 아직 main에 없는 태그로 도는 경우 §7의 `man qsh` 관측은 `해당 없음`이다.

`docs/ROADMAP.md` M10 태그 정책이 "M10 첫 태그는 클린 VM 캠페인 PASS 트리"라고 적고 같은 정책이 "서명·공증이 붙은 첫 태그가 DoD 2 판정 대상"이라고 적는다. 두 문장은 순환이 아니다. 실제 순서는 이렇다.

1. 위 넷이 얹힌 main에 태그를 찍는다.
2. `release.yml`이 돌아 자산과 `SHA256SUMS`가 GitHub Release에 붙는다.
3. 이 캠페인의 회차를 그 자산으로 돈다.
4. 전건 PASS면 그 태그가 M10 태그다. 한 건이라도 FAIL이면 §10에 따라 고치고 **새 태그를 찍는다**. 찍은 태그는 옮기지 않는다.

Apple 시크릿 여섯이 아직 등록되지 않은 태그로는 DoD 2를 판정하지 않는다. 그 경우 태그 run 로그에 `::warning title=Unsigned release::`가 남고 macOS 자산은 ad-hoc 서명이다. 시크릿의 이름과 발급처는 `docs/deploy/release-secrets.md`에 있다.

### 2.2 클린 VM 다섯

| # | 회차 | 대상 자산 | 왜 필요한가 |
|---|---|---|---|
| 1 | macOS arm64 | `qsh-<tag>-aarch64-apple-darwin.tar.gz` | DoD 1 + DoD 2 + brew 버전 일치 |
| 2 | macOS x86_64 | `qsh-<tag>-x86_64-apple-darwin.tar.gz` | DoD 1 + DoD 2 |
| 3 | Linux aarch64 (glibc) | `qsh-<tag>-aarch64-unknown-linux-gnu.tar.gz` | DoD 1 |
| 4 | Linux x86_64 (glibc) | `qsh-<tag>-x86_64-unknown-linux-gnu.tar.gz` | DoD 1 |
| 5 | 구형 glibc x86_64 | `qsh-<tag>-x86_64-unknown-linux-musl.tar.gz` | DoD 3 |

1부터 4까지가 `docs/ROADMAP.md` M10 수용 기준 첫 문장의 네 플랫폼이고 5가 셋째 문장의 musl 회차다.

**macOS x86_64는 실제 Intel 하드웨어여야 한다.** Apple silicon에서 Rosetta로 돌린 x86_64 바이너리는 Gatekeeper 판정 경로가 달라 이 회차로 세지 않는다.

**Windows는 다섯에 없다.** `x86_64-pc-windows-msvc` 자산은 릴리스에 붙지만 수용 기준 어느 문장도 Windows를 부르지 않고, Windows host 자체가 `docs/ROADMAP.md` §3 가드레일의 유예 항목이다. `release.yml`의 windows leg은 `release_smoke_covers_init_trust_and_exec_on_a_platform_without_a_pty_client`로 `exec --json`까지만 검증하며 그 커버리지가 Windows 클라이언트에 대해 이 마일스톤이 주장하는 전부다.

**구형 glibc 이미지의 조건.** x86_64이고 glibc가 2.28 이하여야 한다. Debian 10 (glibc 2.28)을 기본으로 하고 더 낮은 선이 필요하면 CentOS 7 (glibc 2.17)을 쓴다. 어느 쪽을 썼든 회차 표의 "플랫폼/이미지" 열에 배포판 이름과 `ldd --version`의 첫 줄을 그대로 적는다. 대조로 그 이미지에서 gnu 자산을 실행하면 동적 링커가 거부해야 한다. 거부하지 않으면 그 이미지는 "구형 glibc"가 아니므로 회차로 세지 않는다.

이 회차를 curl 설치 경로로 밟으려면 `QSH_LIBC=musl`을 먼저 export해야 한다. `scripts/install.sh`의 기본값은 `gnu`이므로 이 옵트인 없이 돌리면 그 이미지의 동적 링커가 거부할 gnu 자산을 그대로 받는다. 대조용으로 같은 이미지에서 gnu 자산의 거부를 확인하려면 `QSH_LIBC`를 두지 않고 같은 설치를 한 번 더 돌린다.

### 2.3 "클린"의 조작적 정의

회차 시작 전 그 VM에서 아래가 전부 사실이어야 한다. 가장 확실한 보장은 회차마다 스냅숏에서 새로 띄우고 끝나면 버리는 것이다.

- `qsh`가 `PATH` 어디에도 없다 (`which -a qsh`가 0건).
- `$XDG_CONFIG_HOME/qsh`(보통 `~/.config/qsh`)와 `$XDG_STATE_HOME/qsh`(보통 `~/.local/state/qsh`)가 없다.
- `$QSH_CONFIG_DIR`/`$QSH_STATE_DIR`가 설정돼 있지 않다(설정돼 있으면 그 경로가 두 XDG 경로를 이긴다).
- OS 자격 증명 저장소에 `service=qsh` 항목이 없다.
- 잔존 `qsh serve` / `qsh serve --to` / `qsh listen` 프로세스가 없고 이전 회차가 `qsh service install`로 남긴 `~/Library/LaunchAgents/io.qsh.*.plist`(macOS)나 `~/.config/systemd/user/qsh-*.service`(Linux)도 없다. `$XDG_RUNTIME_DIR/qsh`(보통 `/run/user/<uid>/qsh`, `qsh listen`이 쓰는 소켓 디렉터리)에도 잔존물이 없다.
- macOS라면 이 바이너리에 대한 Gatekeeper 평가 캐시가 없다. 같은 VM을 재사용하면 이전 회차의 승인이 남아 DoD 2 판정이 무의미해진다. macOS 방화벽이 켜져 있으면 첫 `exec`나 대화형 접속에서 "Do you want the application qsh to accept incoming network connections?" 모달이 뜰 수 있다(README Known limitations, qsh QUIC 클라이언트 소켓이 와일드카드 주소를 바인드하기 때문). 허용을 눌러도 Gatekeeper 평가와는 무관해 DoD 2 회차를 오염시키지 않지만, 떴다는 사실은 비고에 적는다.

## 3. 회차 요건 여섯 (실행 전에 고정)

모든 회차가 아래 여섯을 만족해야 그 회차를 PASS로 적을 수 있다. 여섯은 이 문서가 커밋된 시점에 고정됐고 회차를 돌면서 늘리지 않는다.

| # | 요건 | 어디에 기록하는가 |
|---|---|---|
| 1 | 바이너리 sha256 | 회차 표 "바이너리 sha256" 열 |
| 2 | 설치 경로 (brew / curl 스크립트 / 수동 다운로드) | 회차 표 "설치 경로" 열 |
| 3 | DoD 2 판정 (§4) | 회차 표 "DoD 2" 열 |
| 4 | DoD 3 판정 (§5) | 회차 표 "DoD 3" 열 |
| 5 | 기능 스모크 네 축의 수동 재현 (§6) | 회차 표 "스모크 네 축" 열 |
| 6 | brew 회차에서 설치된 버전이 태그와 같은지 확인 (§7) | 회차 표 "brew 버전 일치" 열 |

**1번의 규율은 `docs/campaigns/m8-soak.md` §7에서 승계한다.** 한 회차 안에서는 같은 sha256의 바이너리만 쓴다. 한 회차가 두 설치 경로를 밟았는데 두 경로가 같은 자산을 내려받았다면 sha256이 같아야 하고 다르면 그것은 한 회차가 아니라 두 회차다. 행을 나눈다.

sha256은 설치된 바이너리에서 직접 잰다.

```bash
# macOS
shasum -a 256 "$(command -v qsh)"
# Linux
sha256sum "$(command -v qsh)"
```

이 값이 릴리스의 `SHA256SUMS` 행과 같을 필요는 없다. `SHA256SUMS`는 아카이브의 해시이고 위 값은 그 안의 실행 파일의 해시다. 회차 표에는 **설치된 실행 파일의** sha256을 적고 아카이브 해시를 대조했다면 그 사실을 비고에 적는다.

## 4. DoD 2의 조작적 정의: Gatekeeper

DoD 2의 문면은 "Gatekeeper가 notarized 바이너리를 차단하지 않음"이다. 이 절이 그 "차단하지 않음"을 무엇으로 재는지 고정한다.

### 4.1 판정 경로는 수동 다운로드 하나뿐이다

macOS 두 회차에서 DoD 2는 **quarantine 속성이 살아 있는 수동 다운로드 경로**로만 판정한다. curl 설치 경로와 brew 설치 경로는 판정 경로가 아니다.

- **curl 경로가 아닌 이유.** `scripts/install.sh`가 설치 직후 `xattr -d com.apple.quarantine`를 best effort로 건다. 그 스크립트 자신의 주석이 "curl does not set com.apple.quarantine, but a proxy or a download-then-run detour can"이라고 적고 실패를 무시한다(`2>/dev/null || true`). 속성이 떨어진 파일은 Gatekeeper를 부르지 않으므로 그 경로의 성공은 서명에 대해 아무것도 증명하지 않는다.
- **brew 경로가 아닌 이유.** Homebrew는 자기가 내려받은 tarball을 자기 방식으로 다루고 Cellar 아래에 풀어 심볼릭 링크를 건다. 그 과정이 quarantine 속성을 어떻게 다루는지는 Homebrew의 구현 사항이지 이 릴리스의 계약이 아니다. brew 회차는 §7의 버전 일치만 본다.

따라서 macOS 회차는 브라우저로 GitHub Release 페이지에서 자산을 직접 내려받는다. `curl`이나 `wget`으로 받으면 quarantine이 붙지 않으므로 그 파일로는 판정할 수 없다. 내려받은 뒤 속성이 실제로 붙었는지 먼저 확인한다.

```bash
xattr -p com.apple.quarantine ~/Downloads/qsh-<tag>-<target>.tar.gz
```

출력이 없으면 그 파일은 판정 대상이 아니다. 다시 받는다.

### 4.2 판정 셋

압축을 풀고 실행 파일을 `PATH`에 놓은 뒤 셋을 전부 본다. 셋 다 만족해야 DoD 2 PASS다.

**(1) `spctl`** 가 `accepted`와 `source=Notarized Developer ID`를 낸다.

```bash
spctl -a -vvv -t execute "$(command -v qsh)"
```

기대 출력은 두 줄이다. 첫 줄이 `<경로>: accepted`이고 다음 줄이 `source=Notarized Developer ID`다. `rejected`거나 `source=Unnotarized Developer ID`거나 `source=no usable signature`면 FAIL이다. 판정 대상이 `.app`이 아니라 tar.gz 안의 맨 실행 파일이므로, `rejected` 뒤에 `the code is valid but does not seem to be an app`이 붙는 경우는 번들이 아니라는 사실을 보고하는 것일 뿐일 수 있다. 그 문구가 보이면 즉시 FAIL로 적지 말고 `codesign`·`notarytool`의 나머지 두 근거와 함께 비고에 원문을 옮기고, 첫 회차에서 판정 방식을 확정해 이후 회차에 적용한다. 출력을 요약하지 말고 회차 표 비고에 그대로 옮긴다.

**(2) `codesign`** 이 Developer ID와 hardened runtime과 timestamp를 보고한다.

```bash
codesign -dv --verbose=4 "$(command -v qsh)" 2>&1
```

`codesign -d`는 stdout에 아무것도 쓰지 않으므로 `2>&1`이 필요하다. 넷을 확인한다. `Authority=Developer ID Application: …` / `TeamIdentifier=` 뒤에 10자 팀 ID(`not set`이면 ad-hoc이다) / `flags=`에 `runtime` 포함 / `Timestamp=` 행 존재. `Signature=adhoc`이 보이면 그 태그는 서명되지 않은 것이므로 회차가 아니라 릴리스를 다시 찍어야 한다.

**(3) release run 로그**의 `Notarize` 스텝이 `notarytool status=Accepted`를 찍는다.

`release.yml`의 `Notarize` 스텝은 `xcrun notarytool submit --wait`의 JSON `status`를 읽어 `notarytool status=<status> id=<uuid>` 한 줄을 찍고 `Accepted`가 아니면 `::error title=Notarization failed::`로 붉힌다. 회차 표 비고에 그 run id와 status 줄을 적는다. `--wait`의 exit code만으로는 판정할 수 없다는 것이 그 스텝의 주석이 적는 이유이고 `docs/design/testing.md`의 CI 규율 절도 같은 세 문자열(`Authority=Developer ID Application`, `flags=…(runtime)`, `notarytool`의 `status=Accepted`)을 근거로 든다.

### 4.3 stapler가 없다는 사실과 그 결과

`docs/ROADMAP.md` M10 결정 기록 Q2는 macOS 배포 형식을 tar.gz로 유지하고 공증만 더하기로 정했다. `xcrun stapler`는 `.app`, `.dmg`, `.pkg`에만 티켓을 붙이고 tar.gz 안의 맨 실행 파일은 그 대상이 아니므로 `release.yml`의 `Notarize` 스텝은 stapler를 부르지 않는다. 그 결과로 Gatekeeper는 첫 실행 때 Apple에 온라인으로 물어 공증을 확인한다. **Apple에 닿을 수 없는 머신에서 하는 첫 실행은 이 캠페인이 판정하지 않는다.** 그 경로는 미검증 잔여 위험으로 남고 README의 Install 절이 같은 사실을 적는다(Known limitations 절은 Developer ID와 ad-hoc 서명을 구분하는 방법만 적는다). 회차는 네트워크가 살아 있는 VM에서 돈다. 오프라인 판정을 굳이 관측했다면 비고에 적되 회차 판정에는 반영하지 않는다.

### 4.4 Linux 회차의 DoD 2

Gatekeeper는 macOS 기제다. Linux 세 회차의 "DoD 2" 열은 `해당 없음`으로 적는다. 빈칸으로 두지 않는다.

## 5. DoD 3의 조작적 정의: musl static

구형 glibc 회차 하나가 DoD 3을 판정한다. 둘 다 만족해야 PASS다.

**(1) 동적 의존이 없다.**

```bash
ldd "$(command -v qsh)"
```

정적 non-PIE라면 `not a dynamic executable`이 나오고 exit code가 0이 아니다. 정적 PIE라면 `statically linked`가 나오고 exit code가 0이다. 커밋 `168e00c`의 실측으로 이 빌드는 **정적 PIE**이므로 `statically linked`가 기대 출력이다. 두 문구 어느 쪽이든 PASS로 세되 무엇이 나왔는지 그대로 적는다. 라이브러리 경로가 한 줄이라도 나오면 FAIL이다.

`readelf`가 있으면 같은 것을 더 단단하게 본다. 이것이 `release.yml`의 `Static-link evidence (musl)` 스텝이 쓰는 불변이다.

```bash
readelf -d "$(command -v qsh)" | grep NEEDED || echo "no DT_NEEDED"
```

`NEEDED` 항목이 하나라도 있으면 FAIL이다.

**(2) 기능 스모크 네 축이 그 이미지에서 통과한다.** §6을 그대로 밟는다.

`docs/design/testing.md`의 M10 musl 바이너리 RSS 주장 범위 문단이 적듯, musl 바이너리에는 `docs/PRD.md` §13의 idle 30 MB를 주장하지 않는다. 이 회차에서 RSS를 재지 않는다.

## 6. 기능 스모크 네 축의 수동 재현

네 축은 `docs/ROADMAP.md` M10 수용 기준의 2026-08-21 감사 개정이 정의하고 `crates/qsh-cli/tests/release_smoke.rs`의 `release_smoke_covers_init_trust_exec_pty_detach_and_reattach`가 CI에서 돌리는 것과 같다. 여기서는 사람이 손으로 같은 순서를 밟는다.

이 절은 **한 VM 안에서 loopback으로** 호스트 역할과 클라이언트 역할을 둘 다 세운다. 두 장비 사이의 첫 연결 UX를 재는 것은 `docs/campaigns/m7-stopwatch.md`와 `docs/campaigns/m9-stopwatch.md`의 일이고 이 캠페인이 묻는 것은 "이 플랫폼에 설치된 이 바이너리가 네 축을 다 도는가"다.

### 6.0 실 프로필을 건드리지 않는 준비

**§6의 네 축을 밟는 동안에는 아래 export 없이 `qsh`를 실행하지 않는다.** 회차용 임시 홈과 설정 디렉터리를 먼저 만든다. 두 셸을 열고 각각에서 한 번씩 돌린다.

터미널 A (호스트 역할):

```bash
export QSH_ROUND="$(mktemp -d)"
export HOME="$QSH_ROUND/host-home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_STATE_HOME="$HOME/.local/state"
export XDG_RUNTIME_DIR="$QSH_ROUND/host/run"
export QSH_CONFIG_DIR="$QSH_ROUND/host/config"
export QSH_STATE_DIR="$QSH_ROUND/host/state"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR" "$QSH_CONFIG_DIR" "$QSH_STATE_DIR"
echo "$QSH_ROUND"
```

터미널 B (클라이언트 역할): 같은 `QSH_ROUND` 값을 손으로 넣고 `host`를 `client`로 바꾼다.

```bash
export QSH_ROUND="<터미널 A가 찍은 경로>"
export HOME="$QSH_ROUND/client-home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_STATE_HOME="$HOME/.local/state"
export XDG_RUNTIME_DIR="$QSH_ROUND/client/run"
export QSH_CONFIG_DIR="$QSH_ROUND/client/config"
export QSH_STATE_DIR="$QSH_ROUND/client/state"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR" "$QSH_CONFIG_DIR" "$QSH_STATE_DIR"
```

`$XDG_RUNTIME_DIR`를 따로 지정하는 이유는 qsh에 그 축의 `QSH_*` 오버라이드가 일부러 없어서다. 지정하지 않으면 VM이 logind 아래일 때 `qsh listen`이 실 프로필의 `/run/user/<uid>/qsh`에 소켓을 남긴다.

`--key-store file`을 모든 `init`에 붙인다. OS 자격 증명 저장소(macOS Keychain, Linux Secret Service)를 건드리지 않기 위해서다(`docs/CLI.md` §6.11의 `--key-store <auto|platform|file>`). 회차가 끝나면 `rm -rf "$QSH_ROUND"` 하나로 흔적이 사라진다.

### 6.1 축 1: init

터미널 A와 B에서 각각 한 번씩.

```bash
qsh init --key-store file --json
```

확인할 것: 두 출력의 `.data.fingerprint`가 `sha256:`으로 시작하고 서로 다르다. 두 값을 적어 둔다. 호스트 쪽을 `<HOST_FP>`, 클라이언트 쪽을 `<CLIENT_FP>`라 한다.

### 6.2 축 2: 양방향 trust

`acl.toml`은 손으로 쓴다. `qsh` 어느 명령도 이 파일을 생성하지 않는다(ADR-0017 결정 1). `serve` 시작 전에 존재해야 하고 hot reload가 없다.

터미널 A:

```bash
cat > "$QSH_CONFIG_DIR/acl.toml" <<'EOF'
[[acl]]
principal = "device:laptop"
allow = ["exec.run", "session.open", "session.list", "session.attach", "session.control"]
EOF
chmod 600 "$QSH_CONFIG_DIR/acl.toml"

qsh trust add laptop --fingerprint <CLIENT_FP> --json
qsh serve --bind 127.0.0.1:4433
```

마지막 명령은 포그라운드로 남는다. 시작 시 stderr에 `qsh serve: listening on …`과 `qsh serve: identity …` 두 줄이 뜬다.

터미널 B:

```bash
qsh trust add box --address 127.0.0.1:4433 --fingerprint <HOST_FP> --json
qsh trust list --json
```

확인할 것: `trust list --json`의 `.data.peers`에 이름 `box`인 항목이 있고 그 `fingerprint`가 `<HOST_FP>`와 같다.

### 6.3 축 3: `exec --json` 왕복

터미널 B:

```bash
qsh exec box --json -- sh -c 'echo out; echo err >&2; exit 7'
echo "process exit: $?"
```

확인할 것 (`docs/CLI.md` §6.8):

- 프로세스 exit code가 `7`이다. `0`이면 원격 exit code가 실제로 돌아오지 않은 것이므로 FAIL이다.
- `.schema`가 `qsh.cli/v1`, `.command`가 `exec.run`, `.ok`가 `true`.
- `.data.remote_exit_code`가 `7`, `.data.signal`이 `null`, `.data.duration_ms`가 정수.
- `.data.stdout_b64`를 디코드하면 `out` 한 줄(끝에 개행 포함), `.data.stderr_b64`를 디코드하면 `err` 한 줄(끝에 개행 포함). 개행을 빼고 바이트 단위로 비교하면 정상 회차도 FAIL로 보인다.
- stdout 한 줄이 순수 JSON이다. 진단이나 로그가 같은 줄에 섞이면 그 자체가 FAIL이다(`docs/CLI.md` §2.2).

### 6.4 축 4: PTY 셸, detach, 재부착

터미널 B:

```bash
qsh box
```

원격 프롬프트가 뜨면 마커를 왕복시킨다. 마커 사이에 빈 따옴표를 끼우는 이유는 타이핑한 줄의 터미널 에코가 기대값과 일치하지 않게 하기 위해서다. 원격 셸이 실제로 실행한 출력만 조건을 채운다. `release_smoke_covers_init_trust_exec_pty_detach_and_reattach`가 같은 형태를 쓴다.

```
echo QSH-SMOKE''-OK
```

`QSH-SMOKE-OK`가 되돌아오면 줄 맨 앞에서 `~d`를 친다(`docs/CLI.md` §7). `detached`가 뜨고 클라이언트가 exit 0으로 빠지며 터미널이 원래 모드로 돌아온다. 돌아오지 않아 입력이 보이지 않거나 개행이 깨지면 FAIL이다.

같은 터미널에서 세션이 살아 있는지 본다.

```bash
qsh sessions box --json
```

확인할 것: `.data.sessions`가 1건이고 그 `state`가 `running`이다. `session_ref` 값을 적어 둔다.

재부착한다.

```bash
qsh attach <session_ref>
```

**detach 전과 다른 마커**를 왕복시킨다. 같은 마커를 쓰면 화면에 다시 그려진 옛 출력만으로도 통과해 버려서 이 축이 재는 것이 사라진다.

```
echo QSH-SMOKE-REATTACH''-OK
exit
```

`QSH-SMOKE-REATTACH-OK`가 되돌아온 뒤 `exit`로 셸이 끝나고 클라이언트가 exit 0으로 빠지며 터미널이 복원된다.

재부착 직후 detach 전 마커가 다시 그려지는지 여부는 이 캠페인의 판정 대상이 아니다. `release_smoke_covers_init_trust_exec_pty_detach_and_reattach`도 그것을 단언하지 않는다.

### 6.5 정리와 실패 처리

터미널 A에서 `qsh serve`를 Ctrl-C로 끄고 두 터미널에서 `rm -rf "$QSH_ROUND"`.

네 축 중 하나라도 실패하면 그 회차는 FAIL이다. 어느 축에서 어떤 문구로 멈췄는지를 회차 표 비고에 원문 그대로 적는다. 요약하거나 다시 돌려 통과한 결과로 갈아 끼우지 않는다.

## 7. brew 회차 요건

brew 경로는 **macOS arm64 회차에서만** 성립한다. tap의 `Formula/qsh.rb`는 `aarch64-apple-darwin` 자산 하나를 가리키고, `release.yml`의 `Bump homebrew-tap formula` 스텝이 다시 쓰는 URL도 그 자산 하나로 하드코딩돼 있다. README의 Homebrew 절이 같은 사실을 "Apple silicon only for now"로 적는다. 나머지 네 회차의 "brew 버전 일치" 열은 `해당 없음`이다.

macOS arm64 회차 하나에서 §4의 DoD 2와 이 절의 brew 버전 일치를 둘 다 판정하려면 스냅숏을 나눈다. 스냅숏 A에서 §4.1의 수동 다운로드 경로를 먼저 밟아 DoD 2 셋을 판정하고 그 VM을 버린다. 스냅숏 B를 새로 띄워 brew만 설치하고 이 절의 버전 확인을 한다. 같은 VM에서 brew를 먼저 밟으면 §2.3이 적듯 그 설치가 Gatekeeper 평가 캐시를 남겨 뒤이은 수동 다운로드 판정이 무의미해진다. 두 스냅숏 모두 §8에 별도 행으로 적는다. 두 스냅숏이 받은 것이 같은 릴리스 자산이라 바이너리 sha256이 같으면(§3의 규율), 수동 다운로드 행의 "brew 버전 일치"와 brew 행의 "DoD 2"는 `해당 없음`으로 적는다.

macOS x86_64 회차는 brew가 없으므로 스냅숏을 나누지 않는다. §4.1의 수동 다운로드로 DoD 2를 먼저 판정하고, 같은 VM에서 이어 `curl` 경로를 밟아 §9가 요구하는 설치 경로를 채운다. 순서를 바꾸면 안 된다. `scripts/install.sh`가 quarantine 속성을 떼므로 curl을 먼저 밟은 뒤의 수동 다운로드 판정은 §2.3의 클린 조건을 잃는다.

```bash
brew install DaveDev42/tap/qsh
qsh version --json
```

확인할 것: `.data.version`이 태그에서 앞의 `v`를 뗀 문자열과 같다. 태그가 `v0.3.0`이면 `0.3.0`이다. `.data.build.commit`이 있으면 그 값이 태그가 가리키는 커밋과 같은지도 본다(`docs/CLI.md` §6.10). 이 조회는 설정을 쓰지 않으므로 §6.0의 임시 홈 없이 돌려도 된다.

**이 요건이 있는 이유.** `homebrew-tap` job의 `Check out the tap`과 `Bump homebrew-tap formula` 두 스텝이 `continue-on-error: true`다. 그 스텝이 실패해도 release job은 이미 성공했으므로 릴리스 전체가 초록으로 끝나고 tap의 formula만 조용히 옛 버전에 머문다. 사람이 보지 않으면 드러나지 않는 실패다. 버전이 어긋나면 tap 저장소에서 수동으로 bump한 뒤 회차를 다시 돌리고 그 사실을 비고에 적는다. tap 저장소의 커밋은 이 저장소의 게이트 밖이라 CI가 대신 봐 주지 않는다.

**관측 항목 (요건이 아니다): `man qsh`.** unix 아카이브가 `man/*.1`을 싣고 formula가 `man1.install Dir["man/*.1"]`을 갖는 태그라면, brew로 설치한 뒤 `man qsh`가 떠야 한다. §3의 요건 여섯에는 들어가지 않으므로 이 관측이 실패해도 회차 판정은 바뀌지 않는다. 뜨면 `뜸`, 안 뜨면 `안 뜸`, 그 태그의 아카이브에 man page 자체가 없으면 `해당 없음`을 비고에 적는다.

## 8. 회차 표

| 회차 | 날짜(UTC) | 플랫폼/이미지 | 설치 경로 | 바이너리 sha256 | DoD 2 | DoD 3 | 스모크 네 축 | brew 버전 일치 | 결과 | 기록자 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-09-26 | Ubuntu 24.04 x86_64 (컨테이너, Dave-Windows-WSL dockerd) | curl | 43cd8ed3a884c83ef456a32c9422069234cde9c515e0a68b9d1b8e9a1852231f | 해당 없음 | 해당 없음 | PASS | 해당 없음 | PASS | Claude(에이전트) |
| 2 | 2026-09-26 | Debian 10 x86_64 (컨테이너, Dave-Windows-WSL dockerd), `ldd (Debian GLIBC 2.28-10+deb10u3) 2.28` | curl (`QSH_LIBC=musl`) | 3a339bdd818a1d8b1804874773403fa3955ceba3978a49fd3337adfd818ce5f0 | 해당 없음 | PASS | PASS | 해당 없음 | PASS | Claude(에이전트) |
| 3 | 2026-09-26 | Ubuntu 24.04 aarch64 (lima VM, Dave-MBP16) | curl | bb8c2e9e74e4592505e9d4cc909b2a912cf683f38f16a997f3b6b3cfc5d4458f | 해당 없음 | 해당 없음 | PASS | 해당 없음 | PASS | Claude(에이전트) |

열 채우는 법.

- **회차**: 1부터 정수로 순서대로 매긴다. macOS arm64처럼 한 플랫폼이 스냅숏 둘로 나뉘면(§7) 두 행 모두 새 번호를 받는다. 재태그로 다시 도는 회차는 이어서 번호를 매긴다.
- **플랫폼/이미지**: `macOS 15.2 arm64 (M1)`처럼 OS 이름과 버전과 아키텍처. 구형 glibc 회차는 배포판 이름과 `ldd --version` 첫 줄을 같이 적는다.
- **설치 경로**: `brew`, `curl`, `수동 다운로드` 중 그 회차가 실제로 밟은 것. §7이 요구하는 macOS arm64의 두 스냅숏처럼 한 VM 안에서 순서상 섞으면 안 되는 경우는 행을 나눈다. 같은 VM 안에서 밟은 것이 정말 둘 이상이면 쉼표로 잇되 §3의 sha256 규율을 지킨다.
- **바이너리 sha256**: 설치된 실행 파일의 해시 64자 전체. 앞 12자로 줄이지 않는다.
- **DoD 2 / DoD 3 / 스모크 네 축**: `PASS`, `FAIL`, `해당 없음` 셋 중 하나. **brew 버전 일치**: `<설치된 버전> = <태그>` 또는 `불일치: …` 또는 `해당 없음`. **결과**: 요건 1·2(바이너리 sha256, 설치 경로)가 비어 있지 않고 요건 3~6 중 `해당 없음`이 아닌 항목이 전부 PASS일 때만 `PASS`. **기록자**: 회차를 실제로 돌린 사람.

행마다 비고를 붙인다. 비고는 표 아래에 회차 번호를 머리에 단 문단으로 이어 적는다. 비고에 들어가는 것: 대상 태그와 그 태그가 가리키는 커밋, release run id, `spctl` 출력 원문, `codesign -dv` 출력의 `Authority`·`TeamIdentifier`·`flags` 행, `notarytool status=` 줄, `ldd` 출력 원문, `man qsh` 관측, 막힌 지점의 원문 에러.

**회차 1·2·3 공통.** 세 회차는 2026-09-26 같은 날 병렬로 돌았고, 번호는 축 4의 세션이 만들어진 순서다. 셋 다 대상 태그 `v0.3.0` → `891c407`, release run 36254706923이다. 기록자 열은 회차를 돌린 사람을 적게 돼 있지만 세 회차 모두 에이전트(Claude)가 돌렸다. 회차 1·2는 VM이 아니라 이미지에서 막 띄운 컨테이너다. §2.3의 조건은 컨테이너에서도 그대로 확인할 수 있어서 회차로 셌다. 이 두 판단은 캠페인을 닫을 때 사람이 다시 볼 항목이다. 네 축은 모두 §6.0의 export를 건 tmux 창 둘에서 loopback으로 밟았고 `init`마다 `--key-store file`을 붙였다. 접속할 때마다 stderr에 `qsh: the writer lease moved to device:laptop`이 떴지만 판정 문자열과는 관계없었다.

**회차 1.** 대상 태그 `v0.3.0` → `891c407`. Dave-Windows-WSL의 dockerd에서 `ubuntu:24.04` 이미지로 새로 띄운 컨테이너이고, `curl ca-certificates tmux procps` 넷만 더 설치했다. 시작 전에 `which -a qsh`가 0건이었고 `~/.config/qsh`와 `~/.local/state/qsh`는 없었다. 설치는 README의 `curl -fsSL https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.sh | sh`를 환경변수 없이 실행했다. 설치 스크립트가 찍은 진행 출력은 로그에 잡히지 않았으므로 설치 성공은 설치 뒤 상태로 판단했다. `qsh --version`이 `qsh 0.3.0`, `qsh version --json`의 `.data.build.commit`이 `891c407e80863507cb3fea975fec1fe83c248e51`이고 실행 파일은 스크립트 기본 위치인 `/root/.local/bin/qsh`에 있었다. 수동 다운로드는 밟지 않았고 아카이브 해시를 따로 대조하지도 않았다. `ldd`는 gnu 빌드대로 `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`에 동적 링크돼 있었다. DoD 3과는 관계없다. 끝나고 컨테이너를 `docker rm -f`로 지웠다.

**회차 2.** 대상 태그 `v0.3.0` → `891c407`. 같은 dockerd에서 `debian:10`으로 새로 띄운 컨테이너다. Debian 10은 지원이 끝난 배포판이라 `sources.list`를 `archive.debian.org`로 바꿨다. `procps`가 끌어오는 `libtinfo6`·`libncurses6`·`libncursesw6`가 이미지의 `+deb10u5`와 보관소의 `+deb10u2` 사이에서 어긋나서 이 셋은 `+deb10u2`로 내려서 설치했다. qsh를 설치하기 전 준비 단계의 일이다. 대조로 `QSH_LIBC` 없이 같은 설치를 먼저 돌리자 gnu 바이너리는 `` version `GLIBC_2.29' not found ``부터 `GLIBC_2.39`까지 여덟 줄을 내고 exit 1로 거부됐다(§2.2). 이 대조용 바이너리를 지운 뒤 `QSH_LIBC=musl`을 export하고 같은 한 줄로 설치했다. 스크립트는 `detected target: x86_64-unknown-linux-musl`을 찍고 `SHA256SUMS`로 아카이브를 대조한 뒤 `/root/.local/bin/qsh`에 설치했다. `qsh --version`은 `qsh 0.3.0`, `.data.build.commit`은 `891c407e80863507cb3fea975fec1fe83c248e51`이었다. DoD 3의 근거는 셋이다. `ldd`가 `statically linked`를 냈고, `readelf -d`에 `NEEDED` 행이 없었고(`readelf`는 `binutils`를 더 설치해서 돌렸다), 네 축이 이 musl 바이너리로 통과했다. 끝나고 컨테이너를 지웠다.

**회차 3.** 대상 태그 `v0.3.0` → `891c407`. Dave-MBP16에서 lima(VZ)로 띄운 `template:ubuntu-24.04` VM이고, 호스트 디렉터리는 마운트하지 않았다(`--mount-none`). `curl`·`ca-certificates`·`tmux`는 이미지에 이미 있었다. 시작 전에 `which -a qsh`가 0건이었다. `QSH_VERSION=v0.3.0`을 주고 같은 curl 한 줄로 설치했다. 스크립트는 `detected target: aarch64-unknown-linux-gnu`을 찍고 `SHA256SUMS` 대조를 통과한 뒤 `~/.local/bin/qsh`에 설치했다. `qsh --version`은 `qsh 0.3.0`, `.data.build.commit`은 `891c407e80863507cb3fea975fec1fe83c248e51`이었다. 수동 다운로드는 밟지 않았다. 끝나고 `limactl delete -f`로 VM을 지웠다.

## 9. 판정 규칙

> 네 플랫폼 전부 PASS와 구형 glibc musl 회차 1건 PASS가 회차 표에 기록되고, 각 행에 바이너리 sha256과 설치 경로가 있다.

이것이 캠페인 PASS의 전부다. 풀어 적으면 이렇다.

- §2.2의 회차 1부터 4까지가 각각 최소 1행씩 `결과 = PASS`이고, 그 행의 설치 경로에 `brew` 또는 `curl` 중 최소 하나가 있다. `docs/ROADMAP.md` M10 수용 기준이 요구하는 것이 brew/curl 설치이기 때문에, 수동 다운로드만 밟은 행은 이 조건을 채우지 못한다.
- §2.2의 회차 5가 최소 1행 `결과 = PASS`이고 그 행의 `DoD 3 = PASS`. 이 행의 설치 경로에도 `curl`(§2.2의 `QSH_LIBC=musl`)이나 `수동 다운로드` 중 최소 하나가 있어야 한다.
- macOS 두 회차의 `DoD 2 = PASS`. §7이 적듯 이 판정은 §4.1의 수동 다운로드 경로로 밟은 행에서만 나온다.
- macOS arm64 회차의 `brew 버전 일치`가 일치. §7이 적듯 이 판정은 brew로 밟은 행에서만 나온다.
- PASS로 세는 모든 행에 sha256 64자와 설치 경로가 비어 있지 않다.

캠페인 PASS가 곧 `docs/ROADMAP.md` M10 DoD 1·2·3의 판정이고, PASS한 트리가 M10 태그의 대상이다.

한 회차라도 FAIL이면 캠페인은 FAIL이다. 통과한 회차만 세지 않는다.

## 10. 사후 변경 금지와 실패 시 처분

> 캠페인 자체가 DoD 1·2·3의 판정이다. 사후에 기준을 늘리거나 실패한 회차를 빼지 않는다.

§3의 요건 여섯, §4와 §5의 판정 정의, §9의 판정 규칙은 이 문서가 처음 커밋된 그대로 남는다. 회차를 돌다가 기준이 부족해 보여도 그 회차 중에는 고치지 않는다. FAIL한 회차는 표에 FAIL로 남고 뒤에 PASS한 회차가 그 행을 지우지 않는다.

FAIL이 나오면 먼저 원인을 분류한다.

- **릴리스 결함** (서명이 없다, 공증이 `Accepted`가 아니다, 자산이 빠졌다, musl 바이너리에 동적 의존이 있다). 워크플로나 코드를 고치고 **새 태그**를 찍은 뒤 그 태그로 다섯 회차를 처음부터 다시 돈다. 찍은 태그는 옮기지 않는다(`docs/ROADMAP.md` M10 태그 정책). 옛 태그의 회차 행은 지우지 않고 §8의 회차 번호로 구분된 채 남는다. 대상 태그와 그 태그가 가리키는 커밋은 그 회차의 비고 문단 첫 줄에 적는다.
- **제품 결함** (설치는 됐는데 네 축 중 하나가 qsh 자신의 문제로 실패했다). 이슈로 올리고 고친 뒤 새 태그로 재측정한다. 캠페인 문서는 손대지 않는다.
- **환경 잡음** (VM이 클린하지 않았다, 포트가 점유돼 있었다, quarantine이 안 붙은 파일로 DoD 2를 재려 했다). 그 회차는 PASS도 FAIL도 아닌 **무효**로 적고 세지 않는다. §2.3을 다시 확인하고 새 회차로 대체한다.

## 11. 기록 방식

- 회차를 돌면서 §8의 표에 행을 추가하고 그 아래 비고 문단을 잇는다. 이 문서 자체가 기록 장소이고 별도 파일을 만들지 않는다. 커밋 하나에 회차 하나가 원칙이고 같은 날 여러 회차를 돌았으면 하나로 묶어도 된다.
- 캠페인이 PASS로 닫히면 그 사실과 근거 행을 `docs/ROADMAP.md` M10 절의 마감 노트에서 인용한다.
- 다음 라운드(새 태그로 다시 도는 경우)는 이 문서를 재사용한다. §8의 표를 늘리고 §9를 다시 계산한다. `docs/campaigns/m8-soak.md` §9와 같은 방식이다.

## 관련 문서

`docs/ROADMAP.md` M10(범위, 수용 기준과 2026-08-21 감사 개정, 결정 기록 Q2·Q3·Q4, 태그 정책), `docs/PRD.md` §13·§16, `docs/CLI.md` §2.2(stdout 순수성)·§6.2(`sessions`)·§6.8(`exec`)·§6.10(`version`)·§6.11(`--key-store`)·§7(대화형 모드와 `~d`), `docs/deploy/release-secrets.md`(Apple 시크릿 여섯, `HOMEBREW_TAP_DEPLOY_KEY`), `docs/design/testing.md`(CI 규율의 macOS 서명·공증 불릿, musl RSS 주장 범위), `docs/campaigns/m8-soak.md`(sha256 규율과 재사용 형식), `docs/campaigns/m9-stopwatch.md`(게이트형 캠페인의 형식 선례), `crates/qsh-cli/tests/release_smoke.rs`(네 축의 CI 대응물), `scripts/README.md`(installer와 `gh attestation verify --signer-workflow`).
