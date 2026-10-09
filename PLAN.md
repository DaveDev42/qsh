# PLAN.md — 자리표시자: M14 착수 대기 (ADR-0028 미작성)

M13(측정·배포 기반)은 2026-10-08 닫혔다(`docs/ROADMAP.md` M13 마감 노트). 그 계획은 `docs/history/m13-plan.md`로 옮겼다. 순서상 다음인 M14(TCP/TLS fallback)는 착수 ADR인 ADR-0028이 승인돼야 연다(`docs/ROADMAP.md` M14 착수 조건, §5.1 원칙 2). ADR-0028은 아직 초안도 없으므로 이 파일은 M13 마감 공통 절차(`docs/ROADMAP.md` §2)와 `CLAUDE.md` Session onboarding 2에 따라 사람 몫만 추적하는 자리표시자다. 에이전트가 승인 없이 열 수 있는 다음 일은 둘이다. ADR-0028 초안을 `제안됨`으로 올리는 것과, M14 착수 조건이 승인 전에 열어 두는 (a) `Transport`/`StreamMux` 추상(동작 변경 없는 리팩터)이다. 승인은 사용자가 정한다. 승인되면 이 파일을 M14 실행 계획으로 전면 교체한다.

## 0. 열린 사람 몫

여기 적힌 항목은 이 파일이 다음 계획으로 바뀔 때 그대로 승계한다. 상태 표시는 M13 계획 §0의 마감 시점 상태를 옮긴 것이다.

### 0.1 P0에서 열린 채 넘어온 일곱

- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** 기준은 `docs/campaigns/m10-clean-vm.md`. v0.3.0 Linux 세 회차 PASS(`69a6414`)에 더해 v0.4.3 Ubuntu 24.04 x86_64 회차 4가 PASS다(2026-10-09, 에이전트). macOS arm64·x86_64 두 회차가 남았다. 둘 다 클린 macOS VM과 Gatekeeper 판정이 필요하다. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 서명·공증이 붙은 태그는 `v0.4.0`부터 있다. 회차는 `docs/campaigns/m10-clean-vm.md`. 소유: 사람.
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** `x86_64-unknown-linux-musl` 한정. 근거 행은 이미 있다. Debian 10(glibc 2.28) 회차 2(v0.3.0)와 회차 5(v0.4.3, 2026-10-09)가 `DoD 3 = PASS`다. 이 DoD는 캠페인 §9 판정과 함께 닫히므로 macOS 두 회차를 기다린다. 두 회차 모두 에이전트가 컨테이너에서 돌렸으니, 캠페인을 닫을 때 사람이 이것을 회차로 셀지 다시 본다(§8 회차 1·2·3 공통 비고). 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** 기준은 `docs/campaigns/m7-stopwatch.md`. 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** 기준은 `docs/campaigns/m2-mobility.md`. M18의 착수 조건. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** 기준은 `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 소유: 사람.

### 0.2 P1 마일스톤이 만든 사람 몫 (`docs/ROADMAP.md` §5.5)

- [ ] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 기록 자리는 `docs/campaigns/m8-fuzz.md`. 출처 M11. 소유: 사람.
- [ ] **`p1-supervise-wake` 회차 넷.** 기준은 `docs/campaigns/p1-supervise-wake.md`. 출처 M12. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 기준은 `docs/campaigns/p1-setup-stopwatch.md`(ADR-0024 결정 12). 출처 M12. PASS가 기록되기 전에는 이슈 #3 완료 기준 첫 줄이 충족됐다고 적지 않는다. 소유: 사람.
- [x] **`aarch64-unknown-linux-musl` 구형 glibc 판정.** 기준은 `docs/campaigns/p1-aarch64-musl.md`. 2026-10-09 회차 1이 PASS다. v0.4.3, Debian 10 arm64(glibc 2.28), Dave-MBP16 colima의 네이티브 arm64 컨테이너에서 에이전트가 돌렸다. §6 판정 규칙을 채웠다. 컨테이너를 회차로 센 판단은 m10-clean-vm과 같고 사람이 다시 볼 항목이다. 출처 M13.

## 1. 마일스톤 밖에서 미룬 유지보수

2026-10-08 의존성 갱신(`9714cf6`~`ec68cb6`)이 일부러 남긴 셋이다. 어느 것도 마일스톤 DoD가 아니다.

- `keyring` 3.6 → 4.x. 4.x는 기능 플래그와 기본 저장소 선택을 다시 설계했고 키 재료를 다룬다. 실제 Keychain과 Secret Service에서 손으로 확인해야 해서 CI만으로는 판정할 수 없다. 별도 변경으로 한다.
- `release.yml`의 액션(`actions/checkout`, `actions/download-artifact` v7 → v8 등). 서명·공증·provenance는 태그 run으로만 확인된다. `download-artifact` v8은 digest 불일치를 기본으로 오류 처리하고 zip이 아닌 파일을 풀지 않으므로 태그 run 하나로 확인한 뒤 올린다.
- Rust 툴체인 1.98.1 → 1.99.0(`rust-toolchain.toml`). 새 clippy lint를 `-D warnings`로 한 번 훑어야 한다.
