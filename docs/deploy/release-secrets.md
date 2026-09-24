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

## 그 밖의 릴리스 시크릿

| 이름 | 무엇인지 | 비고 |
|---|---|---|
| `HOMEBREW_TAP_DEPLOY_KEY` | `DaveDev42/homebrew-tap`에 쓰기 권한으로 등록한 배포 키(deploy key)의 개인키 절반. `release.yml`의 `homebrew-tap` job이 태그 push마다 tap의 `Formula/qsh.rb`를 새 버전·URL·sha256으로 bump하는 데 쓴다. | 그 저장소 하나로만 범위가 좁고 만료가 없다. 없으면 `homebrew-tap` job은 green인 채 건너뛴다. |
| `CARGO_REGISTRY_TOKEN` | crates.io publish 토큰. | CI는 이 토큰을 쓰지 않는다 — `cargo publish`는 사람이 로컬에서 실행하는 단계다(되돌릴 수 없어서다: yank는 되지만 삭제는 안 된다). CI가 돌리는 `cargo publish --dry-run`(퍼블리시 게이트, 커밋 `faf10bd`)은 토큰이 없어도 돈다. |

## Provenance attestation은 시크릿이 필요 없다

`actions/attest-build-provenance`는 GitHub Actions의 OIDC 신원 토큰으로 서명하므로 저장소 시크릿을 하나도 쓰지 않는다.
