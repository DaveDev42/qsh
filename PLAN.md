# PLAN.md — 자리표시자: M14 착수 대기 (ADR-0028 제안됨)

M13(측정·배포 기반)은 2026-10-08 닫혔다(`docs/ROADMAP.md` M13 마감 노트). 순서상 다음인 M14(TCP/TLS fallback)는 착수 ADR인 ADR-0028이 승인돼야 연다(`docs/ROADMAP.md` M14 착수 조건, §5.1 원칙 2). ADR-0028은 2026-10-09 `제안됨`으로 올랐고 승인 전이므로, 이 파일은 `CLAUDE.md` Session onboarding 2에 따라 사람 몫만 추적하는 자리표시자다. M14 (a)의 `Transport`/`StreamMux` 추상은 승인 전에 열 수 있는 몫이라 2026-10-09 착지했다(`e5a62a5`~`7ca3947`, 모양은 ADR-0028 결정 0). 에이전트가 승인 없이 할 수 있는 M14 일은 더 없고 승인은 사용자가 정한다. 승인되면 이 파일을 M14 실행 계획으로 전면 교체한다.

## 0. 열린 사람 몫

여기 적힌 항목은 이 파일이 다음 계획으로 바뀔 때 그대로 승계한다.

### 0.1 P0에서 열린 일곱

- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** 기준은 `docs/campaigns/m10-clean-vm.md`. Linux 회차는 PASS(v0.3.0 세 회차 `69a6414`, v0.4.3 Ubuntu 24.04 x86_64 회차 4, 2026-10-09). macOS arm64·x86_64 두 회차가 남았고 둘 다 클린 macOS VM과 Gatekeeper 판정이 필요하다. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 서명·공증 태그는 `v0.4.0`부터 있다. 회차는 `docs/campaigns/m10-clean-vm.md`. 소유: 사람.
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** `x86_64-unknown-linux-musl` 한정. Debian 10(glibc 2.28) 회차 2(v0.3.0)와 회차 5(v0.4.3, 2026-10-09)가 `DoD 3 = PASS`다. 캠페인 §9 판정과 함께 닫히므로 macOS 두 회차를 기다린다. 두 회차 모두 에이전트가 컨테이너에서 돌렸으니, 캠페인을 닫을 때 사람이 이것을 회차로 셀지 다시 본다. 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** 기준은 `docs/campaigns/m7-stopwatch.md`(예행 1회만 끝남). 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** 기준은 `docs/campaigns/m2-mobility.md`. M18의 착수 조건. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 검증 계약(SC7).** 저장소 밖 조직 액션. 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** 기준은 `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 소유: 사람.

### 0.2 P1 마일스톤이 만든 사람 몫 (`docs/ROADMAP.md` §5.5)

- [ ] **`parse_openssh_key` fuzz 타깃의 누적 72 fuzz-hours.** 기록 자리는 `docs/campaigns/m8-fuzz.md`. 출처 M11. 소유: 사람.
- [ ] **`p1-supervise-wake` 회차 넷.** 기준은 `docs/campaigns/p1-supervise-wake.md`. 출처 M12. 소유: 사람.
- [ ] **`p1-setup-stopwatch` 3회.** 기준은 `docs/campaigns/p1-setup-stopwatch.md`(ADR-0024 결정 12). 출처 M12. PASS가 기록되기 전에는 이슈 #3 완료 기준 첫 줄이 충족됐다고 적지 않는다. 소유: 사람.
- [x] **`aarch64-unknown-linux-musl` 구형 glibc 판정.** 2026-10-09 회차 1 PASS(`docs/campaigns/p1-aarch64-musl.md`). 컨테이너를 회차로 센 판단은 m10-clean-vm과 같고 사람이 다시 볼 항목이다.

## 1. 유지보수에서 남은 확인

- [ ] macOS Keychain 왕복. `keyring-core` 1과 플랫폼 store crate로 옮긴 변경(`08a6173`)의 Linux Secret Service 왕복은 확인했지만, macOS 쪽은 Dave-MBP16이 오프라인이라 못 했다. 다음 태그 전에 `docs/design/testing.md` L1의 수동 단계로 돌린다.
- [ ] 다음 태그 run에서 `release.yml` 액션 갱신(`1557f50`) 뒤의 서명·공증·provenance를 확인한다.

## 2. 테스트 환경

nextest의 간헐 실패 원인은 호스트 nftables에 남은 `inet dave_mosh` 표였다. 이 표가 loopback UDP 60000~61000을 버려서 ephemeral 범위(32768~60999)와 겹쳤고 bind(0) QUIC endpoint의 약 4%가 닿지 않았다. 호스트는 dave-environment `c6c5359c`가 고쳤다. 저장소 쪽은 `414f1fd`가 막는다. loopback UDP 자가 점검이 같은 상황을 즉시 원인과 함께 실패시키고, `scripts/test/nextest-ns.sh`가 격리 네트워크 namespace에서 스위트를 돌리며, 긴 TMPDIR에서는 nextest setup script가 unix 소켓 경로를 줄인다(`docs/design/testing.md` CI 규율).
