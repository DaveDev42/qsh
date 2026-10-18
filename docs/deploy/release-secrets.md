# 릴리스 시크릿

이 문서는 시크릿의 **이름**, 무엇인지, 어디서 발급하는지, 회전 절차만 적는다. 값은 어디에도 적지 않는다 — 실제 값은 GitHub 저장소 Settings → Secrets and variables → Actions에만 있다.

## Apple 서명·공증 시크릿 여섯

`release.yml`의 build job이 darwin 두 leg(`macos-14`/`macos-15-intel`)에서 읽는다. 전부-또는-전무 — 여섯 중 몇 개만 설정되면 태그 push는 `::error::`로 붉고, 브랜치 `workflow_dispatch`는 `::warning::`을 내고 서명·공증을 건너뛴다. 붉히지 않으면 그 run의 자산이 서명 없이 GitHub Release에 그대로 올라가기 때문이고(`homebrew-tap` job이 같은 자산으로 tap formula를 bump한다), 브랜치 dispatch가 경고로 그치는 이유는 그 결과물이 버려지고 사람이 시크릿을 하나씩 넣는 도중일 수 있기 때문이다. 여섯 다 없으면(0개) 태그는 `::warning title=Unsigned release::`를 내고 green을 유지한다 — Apple 자격이 오기 전에도 태그 릴리스가 막히지 않아야 한다는 계획의 불변이다.

| 이름 | 무엇인지 | 어디서 발급 |
|---|---|---|
| `APPLE_API_KEY_ID` | App Store Connect API 키의 Key ID | App Store Connect → Users and Access → Integrations |
| `APPLE_API_ISSUER_ID` | 같은 API 키의 Issuer ID | App Store Connect → Users and Access → Integrations |
| `APPLE_API_PRIVATE_KEY` | API 키 본문(`.p8` 파일 내용 그대로) | 키 발급 시 1회 다운로드 — 재다운로드 불가, 분실 시 키를 폐기하고 새로 발급 |
| `APPLE_CERT_P12` | Developer ID Application 서명 인증서를 base64로 인코딩한 값 | Apple Developer → Certificates, Identifiers & Profiles → Certificates에서 발급한 `.p12`를 아래 명령으로 인코딩 |
| `APPLE_CERT_PASSWORD` | 위 `.p12`를 내보낼 때 지정한 암호 | 내보내기(export) 시점에 사람이 직접 정한다 |
| `APPLE_TEAM_ID` | Apple Developer Team ID (10자 영숫자) | Apple Developer 계정의 Membership 페이지 |

`.p12`를 base64로 만드는 명령:

```bash
base64 -i DeveloperIDApplication.p12 | tr -d '\n' > cert.p12.b64
```

`APPLE_CERT_P12` 시크릿에는 `cert.p12.b64`의 내용을 그대로 붙여 넣는다(개행 없이).

**회전.** `APPLE_CERT_P12`/`APPLE_CERT_PASSWORD`는 인증서를 재발급하거나 만료(5년)될 때 위 명령을 다시 밟아 갈아 끼운다. `APPLE_API_KEY_ID`/`APPLE_API_ISSUER_ID`/`APPLE_API_PRIVATE_KEY`는 API 키를 폐기·재발급할 때 셋을 함께 갈아 끼운다 — 셋은 한 키의 서로 다른 조각이라 따로 회전할 수 없다. `APPLE_TEAM_ID`는 팀을 옮기지 않는 한 바뀌지 않는다. 여섯 중 하나를 회전하면 나머지 다섯은 그대로 두어도 되고(all-or-nothing은 최초 설정에 적용되는 규칙이지 회전마다 여섯을 다시 넣으라는 뜻이 아니다), 회전 뒤 첫 dispatch run으로 여전히 여섯 다 유효한지 확인한다.

서명 identity 자체(개인키·인증서)는 이 여섯 시크릿에 포함되지 않는다 — `release.yml`은 `APPLE_CERT_P12`를 임시 키체인에 import한 뒤 `security find-identity`로 그 키체인에서 SHA-1 해시를 읽어 서명에 쓰고, job이 끝나면 키체인을 지운다(`release.yml`의 `Import the Developer ID certificate`·`Delete the signing keychain` 스텝 참고).

## Windows

Windows 자산(`qsh.exe`와 `install.ps1`)은 결정에 따라 서명하지 않으므로(ADR-0035 개정 이력, 2026-10-19) 필요한 시크릿이 없다.

## 패키지 관리자 시크릿 둘 (scoop, winget)

`release.yml`의 `scoop-bucket`·`winget` job이 읽는다. 둘 다 `homebrew-tap`과 같은 모양이다. 태그 push에서만 돌고 prerelease 태그(`v0.3.1-rc.2`처럼 `-`가 든 태그)에서는 job 자체를 건너뛴다. rc 버전으로 `microsoft/winget-pkgs`에 PR이 열리거나 scoop `checkver`가 rc를 최신으로 잡는 일을 막기 위해서다(`homebrew-tap`은 이 규칙이 없다). 시크릿 게이트는 그 뒤 단계다. 시크릿이 없으면 존재 여부 플래그(`has-key`, `has-pat`)가 `false`가 되어 뒤 스텝이 전부 건너뛰어지며 job은 green이다. job 수준 `continue-on-error`라서 패키지 관리자 쪽 실패(첫 매니페스트가 아직 없음, PR 거절)가 이미 출고된 GitHub Release를 붉히지 않는다. 두 매니페스트는 같은 템플릿(`packaging/scoop/qsh.json.in`, `packaging/winget/*.yaml.in`)을 `scripts/release/render-manifests.sh`로 채워 만든다. 해시는 발행된 릴리스의 `SHA256SUMS`에서 읽고, 두 Windows zip 중 하나라도 줄이 없거나 해시가 64자리 hex가 아니면 렌더가 실패한다. 매니페스트는 `man/*.1`을 설치하지 않는다. scoop과 winget portable에는 man 경로 규약이 없고, 같은 내용은 `qsh help`가 준다.

| 이름 | 무엇인지 | 비고 |
|---|---|---|
| `SCOOP_BUCKET_DEPLOY_KEY` | `DaveDev42/scoop-bucket`에 쓰기 권한으로 등록한 배포 키의 개인키 절반(키 제목 예: "qsh release.yml bucket bump"). `scoop-bucket` job이 태그마다 `bucket/qsh.json`을 새 버전·URL·해시로 다시 써서 `main`에 push한다. | 그 저장소 하나로만 범위가 좁고 만료가 없다. `bucket/qsh.json`은 템플릿에서 통째로 쓰므로 tap과 달리 첫 릴리스에 손으로 올릴 파일이 없다. 없으면 job은 green인 채 건너뛴다. |
| `WINGET_PAT` | `microsoft/winget-pkgs` 포크에서 PR을 열 수 있는 GitHub 토큰. `winget` job이 `wingetcreate update DaveDev42.qsh --submit`으로 갱신 PR을 연다. 환경변수 `WINGET_CREATE_GITHUB_TOKEN`으로만 넘기고 명령행에는 싣지 않는다. | 포크 쓰기와 PR 생성에만 범위를 좁힌다. 병합은 winget 쪽 검증이 정한다. 없으면 job은 green인 채 건너뛴다. |

사람이 하는 일은 이 둘이 전부가 아니다.

- 저장소 `DaveDev42/scoop-bucket` 생성, 배포 키 등록, 개인키 절반을 `SCOOP_BUCKET_DEPLOY_KEY`로 설정. 에이전트는 이 저장소에 쓰지 않는다.
- `DaveDev42.qsh`의 첫 winget 매니페스트 제출. `wingetcreate update`는 이미 있는 패키지를 갱신하므로 첫 제출 전에는 `winget` job의 update 스텝이 실패하고(`continue-on-error`로 green), 첫 제출은 사람이 한다. 첫 태그의 `SHA256SUMS`로 `sh scripts/release/render-manifests.sh <tag> SHA256SUMS <출력 디렉터리>`를 돌리면 `<출력 디렉터리>/winget/`에 job이 쓰는 것과 같은 세 파일이 나오고(`winget` job도 같은 파일을 `winget-manifests` artifact로 남긴다), 이를 `wingetcreate submit`으로 올린다. 병합되기 전까지 README의 `scoop install`·`winget install` 줄은 "after the first manifest is accepted" 단서를 달고 있다.

**회전.** 배포 키는 저장소의 배포 키를 지우고 새 키를 등록한 뒤 `SCOOP_BUCKET_DEPLOY_KEY`만 갈아 끼운다. PAT는 만료되면 새로 발급해 `WINGET_PAT`만 갈아 끼운다. 회전 뒤 다음 태그(또는 같은 태그의 job 재실행)로 push·PR이 성공하는지 본다. 값은 이 문서에도 커밋에도 적지 않는다.

## 그 밖의 릴리스 시크릿

| 이름 | 무엇인지 | 비고 |
|---|---|---|
| `HOMEBREW_TAP_DEPLOY_KEY` | `DaveDev42/homebrew-tap`에 쓰기 권한으로 등록한 배포 키(deploy key)의 개인키 절반. `release.yml`의 `homebrew-tap` job이 태그 push마다 tap의 `Formula/qsh.rb`를 새 버전·URL·sha256으로 bump하는 데 쓴다. | 그 저장소 하나로만 범위가 좁고 만료가 없다. 없으면 `homebrew-tap` job은 green인 채 건너뛴다. |
| `CARGO_REGISTRY_TOKEN` | crates.io publish 토큰. | CI는 이 토큰을 쓰지 않는다 — `cargo publish`는 사람이 로컬에서 실행하는 단계다(되돌릴 수 없어서다: yank는 되지만 삭제는 안 된다). CI가 돌리는 `cargo publish --dry-run`(퍼블리시 게이트, 커밋 `faf10bd`)은 토큰이 없어도 돈다. |

## Provenance attestation은 시크릿이 필요 없다

`actions/attest-build-provenance`는 GitHub Actions의 OIDC 신원 토큰으로 서명하므로 저장소 시크릿을 하나도 쓰지 않는다.
