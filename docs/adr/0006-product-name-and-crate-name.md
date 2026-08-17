# ADR-0006: 제품명은 `qsh` 유지, crates.io 패키지명만 `qsh-cli`로 분리

날짜: 2026-08-17
상태: 승인됨

## 맥락

M0 진행 중 이름 충돌 조사를 신규로 수행했다(§18 원안에는 없었으나 조사 결과 확정이 필요해진 항목). 조사 결과:

- **crates.io**: 패키지명 `qsh`는 이미 동일 컨셉의 활성 프로젝트인 `haukened/quicshell`이 선점하고 있다.
- **Debian/Ubuntu apt**: `gridengine-client` 패키지가 이미 `/usr/bin/qsh` 경로를 점유하고 있다(Sun Grid Engine 계열 도구의 qsh는 job 제출 명령).
- **npm**: 패키지명 `qsh`가 이미 존재한다.
- **Homebrew, Arch(AUR/pacman), Nix**: `qsh` 이름이 깨끗하다(충돌 없음).
- 로컬 개발 환경 PATH 상에는 `qsh` 이름 충돌이 없음을 확인했다.

제품명/바이너리명을 바꿀지, 그대로 두고 배포 채널별로 대응할지 결정이 필요했다.

## 결정

- **제품명과 바이너리명은 `qsh`를 그대로 유지**한다.
- **crates.io 패키지명만 `qsh-cli`로 분리**하고, `[[bin]] name = "qsh"`로 설정해 `cargo install qsh-cli`로 설치해도 실행 바이너리는 여전히 `qsh`가 되도록 한다.
- **주 배포 채널은 Homebrew tap과 curl\|sh 설치 스크립트**로 삼는다(둘 다 이름 충돌 없음, PRD §17 "단일 바이너리" 원칙과도 맞음).
- `qsh doctor`에 **PATH 상에 다른 `qsh` 바이너리가 있는지 경고**하는 체크를 추가한다(Debian `gridengine-client` 사용자 등 실제 충돌 환경 대응).
- `crates.io`의 `haukened/quicshell`에 `qsh` crate 이름 양도를 문의하는 것은 **선택적 후속 작업**으로 남긴다(P0 범위 아님).
- PRD §16 위험 표의 "`qsh` 기존 명령과 충돌" 항목에 이번 조사 결과를 반영한다.

## 근거

- 제품명을 바꾸면 README, 문서, 브랜딩, 사용자 인지(이미 PRD/CLI.md 전체가 `qsh` 기준으로 작성됨)까지 전부 재작업해야 하는 큰 비용이 드는 반면, 실제 충돌은 "동시 설치 시 PATH 우선순위" 문제일 뿐 기술적으로 해결 가능하다.
- crates.io는 패키지명(publish 대상)과 바이너리명(`[[bin]] name`)이 독립적이다. `qsh-cli`라는 패키지명으로 배포해도 사용자가 최종적으로 실행하는 명령은 `qsh`로 동일하다 — 즉 이 분리는 사용자에게 보이지 않는다.
- 주 배포 채널(Homebrew, curl\|sh)은 애초에 crates.io 패키지명에 의존하지 않으므로, crates.io 충돌이 실사용자 경험에 미치는 영향은 제한적이다(`cargo install`은 Rust 개발자 대상 보조 채널).
- Debian `/usr/bin/qsh` 충돌은 실제 파일시스템 경로 충돌이라 crate 이름과 무관하게 남는 문제다 — 이건 이름 변경으로도 해결되지 않고(사용자가 어차피 `qsh`라는 명령을 치고 싶어함), 오히려 `qsh doctor`로 진단하고 문서화하는 것이 실질적 해법이다.
- haukened/quicshell는 활성 프로젝트이므로 crate 이름 강탈(license 위반 소지 없는 범위 내 대체 이름 사용)이 더 안전하고 정중한 선택이다. 양도 문의는 관계 구축이 필요한 별도 트랙이라 P0 blocking이 아니다.

## 대안과 기각 사유

- **제품명 자체를 변경**(예: `qshell`, `qssh` 등): 기각. 이미 두 스펙 문서(PRD, CLI.md) 전체가 `qsh` 기준으로 작성되어 있고, 브랜딩 재작업 비용이 실제 충돌 규모에 비해 과도하다. 짧은 2글자 이름의 프리미엄(SSH처럼 타이핑하기 쉬움)을 포기할 이유가 부족하다.
- **crates.io 패키지명도 `qsh`로 강행 시도(선점자에게 양도 요청 선행)**: 기각. 양도 협상은 시간이 불확실하고 P0 일정을 blocking할 수 없다. `qsh-cli` + `[[bin]] name = "qsh"`로 즉시 문제를 우회할 수 있으므로 협상을 P0의 전제조건으로 둘 이유가 없다.
- **Debian 진출 시 바이너리명을 `qsh2` 등으로 변경**: 기각(현재는). 실사용자에게 노출되는 이름을 낮은 확률의 배포판별 충돌 때문에 바꾸는 것은 손실이 크다. 대신 `qsh doctor`로 충돌을 진단해 사용자가 alias 등으로 스스로 해결하게 한다. 필요해지면 재검토.

## 결과

- `crates/qsh-cli/Cargo.toml`의 `[package] name = "qsh-cli"`, `[[bin]] name = "qsh"`로 M0 스캐폴드에서 설정해야 한다.
- README.md와 설치 안내는 Homebrew tap / curl\|sh를 주 채널로 명시하고, `cargo install qsh-cli`는 보조 채널로 언급한다.
- `qsh-core/doctor.rs`는 PATH 스캔으로 다른 `qsh` 실행파일 존재 여부와 경로를 human/JSON 양쪽으로 보고해야 한다(P0 범위).
- PRD §16 위험 표를 이번 조사 결과(구체적 충돌처: crates.io `haukened/quicshell`, Debian `gridengine-client`, npm)로 갱신해야 한다.
- 후속 과제(비차단): haukened/quicshell에 crate 이름 양도 문의.
