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

## Windows 서명 시크릿 넷과 변수 하나

`release.yml`의 build job이 Windows 두 leg(`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`)에서 읽는다. 서명은 SSL.com eSigner(클라우드 HSM)로 하고, `qsh.exe`(두 아키텍처)와 release 자산 `install.ps1`에 Authenticode 서명을 건다. 게이트는 Apple과 같은 전부-또는-전무이고 같은 스크립트(`scripts/release/secret-gate.sh`)가 판정한다. 넷이 모두 있으면 서명하고 검증 스텝이 돈다. 하나도 없으면(0개) 서명과 검증을 건너뛰고, 태그 push는 `::warning title=Unsigned release::`를 내고 green을 유지한다. 일부만 있으면 태그 push는 `::error::`로 붉고, 브랜치 `workflow_dispatch`는 `::warning::`을 내고 건너뛴다. 이유는 Apple 절과 같다.

| 이름 | 종류 | 무엇인지 | 어디서 발급 |
|---|---|---|---|
| `WINDOWS_SIGN_ESIGNER_USERNAME` | 시크릿 | SSL.com 계정 사용자 이름 | SSL.com 계정 |
| `WINDOWS_SIGN_ESIGNER_PASSWORD` | 시크릿 | 같은 계정의 암호 | SSL.com 계정 |
| `WINDOWS_SIGN_ESIGNER_CREDENTIAL_ID` | 시크릿 | 코드 서명 인증서의 eSigner credential ID | SSL.com 대시보드의 인증서 주문 상세, 또는 CodeSignTool의 `get_credential_ids` |
| `WINDOWS_SIGN_ESIGNER_TOTP_SECRET` | 시크릿 | 무인 서명용 OAuth TOTP 시크릿 | eSigner 자동 서명을 켤 때 SSL.com이 QR 코드와 함께 한 번 보여주는 문자열 |
| `WINDOWS_SIGN_EXPECTED_SUBJECT` | 변수(Variables 탭) | 서명 검증이 기대하는 인증서 주체. 전체 주체(`CN=…, O=…, C=…`)나 공통 이름 하나 | 서명된 파일에서 읽는다: `(Get-AuthenticodeSignature qsh.exe).SignerCertificate.Subject` |

변수는 비밀이 아니다(서명된 모든 파일에 그대로 들어 있다). 그래서 시크릿이 아니라 저장소 변수에 둔다. 값이 비어 있으면 `scripts/release/verify-signature.ps1`이 검증을 통과시키지 않고 오류로 끝낸다. 시크릿 넷은 있는데 이 변수가 없는 설정이 서명 검증을 빈 껍데기로 만들지 않게 하기 위해서다.

서명 주체가 유지보수자 본인 이름으로 보이도록 SSL.com의 개인 신원 검증(individual validation) 코드 서명 인증서를 쓴다. 개인키는 SSL.com의 클라우드 HSM에 있고 이 저장소나 러너에는 들어오지 않는다. 시크릿 넷은 그 HSM에 서명을 요청하는 자격일 뿐이다. 서명에는 SHA-256 다이제스트와 RFC 3161 타임스탬프(`http://ts.ssl.com`)가 붙고, 타임스탬프가 있어야 인증서가 만료된 뒤에도 서명이 유효하다. 검증 스텝은 `signtool verify /pa /v`로 신뢰 사슬을, `Get-AuthenticodeSignature`로 상태 `Valid`·주체·타임스탬프 존재를 확인한다.

**회전.** 암호를 바꾸면 `WINDOWS_SIGN_ESIGNER_PASSWORD`만 갈아 끼운다. TOTP 시크릿은 SSL.com에서 자동 서명을 다시 켜면 새로 발급되므로 `WINDOWS_SIGN_ESIGNER_TOTP_SECRET`만 갈아 끼운다. 인증서를 재발급하거나 갱신하면 credential ID와 주체가 바뀔 수 있으므로 `WINDOWS_SIGN_ESIGNER_CREDENTIAL_ID`와 `WINDOWS_SIGN_EXPECTED_SUBJECT`를 함께 확인한다. Apple 절과 같이 하나를 회전하면 나머지는 그대로 두어도 되고(전부-또는-전무는 최초 설정에 적용되는 규칙이다), 회전 뒤 첫 dispatch run으로 넷이 여전히 유효한지 확인한다. 값은 이 문서에도 커밋에도 적지 않는다.

## 그 밖의 릴리스 시크릿

| 이름 | 무엇인지 | 비고 |
|---|---|---|
| `HOMEBREW_TAP_DEPLOY_KEY` | `DaveDev42/homebrew-tap`에 쓰기 권한으로 등록한 배포 키(deploy key)의 개인키 절반. `release.yml`의 `homebrew-tap` job이 태그 push마다 tap의 `Formula/qsh.rb`를 새 버전·URL·sha256으로 bump하는 데 쓴다. | 그 저장소 하나로만 범위가 좁고 만료가 없다. 없으면 `homebrew-tap` job은 green인 채 건너뛴다. |
| `CARGO_REGISTRY_TOKEN` | crates.io publish 토큰. | CI는 이 토큰을 쓰지 않는다 — `cargo publish`는 사람이 로컬에서 실행하는 단계다(되돌릴 수 없어서다: yank는 되지만 삭제는 안 된다). CI가 돌리는 `cargo publish --dry-run`(퍼블리시 게이트, 커밋 `faf10bd`)은 토큰이 없어도 돈다. |

## Provenance attestation은 시크릿이 필요 없다

`actions/attest-build-provenance`는 GitHub Actions의 OIDC 신원 토큰으로 서명하므로 저장소 시크릿을 하나도 쓰지 않는다.
