# PLAN.md — P1 계획 미정 (사용자 결정 대기)

M10 마감 감사가 2026-09-25에 끝나면서 M10판 계획은 `docs/history/m10-plan.md`로 갔다. 파이프라인은 전부 착지했고 DoD 1·2·3은 사람 회차를 기다린 채 열려 있다. M10은 P0의 마지막 마일스톤이므로 이 자리를 이어받을 다음 마일스톤 계획이 자동으로 정해지지 않는다. **P1 계획을 열지, 연다면 무엇을 P1 첫 마일스톤으로 둘지는 사용자 결정이다.** M10판 계획 §5 #8이 이 항목을 사용자 결정으로 남겼고 이 문서는 그 결정을 대신하지 않는다. 결정이 나기 전까지 이 파일이 하는 일은 하나다. 마일스톤 계획이 들고 있던 "열린 사람 몫"을 떨어뜨리지 않는 것.

`docs/ROADMAP.md`가 여전히 P0 MVP까지의 canonical 마일스톤 기록이고 P0 완료 선언의 조건은 그 문서에 고정돼 있다.

## 0. 열린 사람 몫 일곱 (P0 MVP 완료 선언의 전제)

- [ ] **M10 DoD 1 — 클린 네 플랫폼 설치와 기능 스모크.** 기준은 `docs/campaigns/m10-clean-vm.md`에 사전 고정. 소유: 사람.
- [ ] **M10 DoD 2 — Gatekeeper가 notarized 바이너리를 차단하지 않음.** 선행: Apple 시크릿 여섯 등록과 서명·공증이 붙은 첫 태그. 판정은 같은 캠페인 §4.2. 소유: 사람(등록·회차).
- [ ] **M10 DoD 3 — musl static 바이너리가 구형 glibc 배포판에서 실행.** 판정은 같은 캠페인 §5. 소유: 사람.
- [ ] **M7 DoD 1 — SC1 스톱워치 baseline 3회.** 기준은 `docs/campaigns/m7-stopwatch.md`. 예행 1회만 끝났다. M9 DoD 1의 비교 대상이라 그보다 먼저 온다. 소유: 사람.
- [ ] **M8 DoD 3 — 실기기 mobility 60회 이상.** 기준은 `docs/campaigns/m2-mobility.md`. 소유: 사람.
- [ ] **M8 DoD 4 — wire freeze 발효와 독립 리뷰 계약(SC7).** `docs/design/protocol.md` §16의 상태가 아직 "초안 — 발효 전"이다. 발효 소커밋에 딸린 잔여 셋(CLOSE `0x1003` 이중 이름 처분, README Security posture 한 줄, DoD 4 문구)도 같이 온다. 저장소 밖 조직 액션이다. 소유: 운영자.
- [ ] **M9 DoD 1 — SC1 스톱워치 재측정 3회.** 기준은 `docs/campaigns/m9-stopwatch.md`. M7 DoD 1에 종속. 소유: 사람.

## 1. P1으로 귀속된 항목 (계획이 열릴 때의 입력)

- graceful re-exec H1·H1b·H2 (`docs/design/reexec-estimate.md` 2026-09-24 추기), H4·H5 (같은 문서 §4)
- `ControlLink`/`DataLink` enum → trait 전환 (ADR-0005의 P0 부채, M3부터 연쇄 이월)
- 느린 파일·터널 stream의 저속·역압 축 (M10판 계획 §4의 2026-09-25 확정 문단)
- nightly perf job (`docs/design/testing.md`의 CI 규율 절. trend 저장소 결정이 선행)
- 옛 계획·ADR 줄 번호 인용의 일괄 정리 (2026-09-24 실측 엄격 793건)
- TOFU와 pin 방향 축(ADR-0017 결정 5), listener 대상 초대 상환(ADR-0015), CSR 기반 다대 CA 서명(ADR-0016)
- cert rotation/revocation UX, doctor `--fail-on`, `aarch64-unknown-linux-musl`
- 제안 ADR 넷의 배치: 0021·0022·0025는 "M10 이후 또는 P1", 0026은 P1(ADR 본문이 이미 P1으로 못박았다)
- `docs/CLI.md` 상태 헤더의 기계 핀 (M10판 계획 §6 xii가 후보로만 남겼다)
- 공개 크레이트 tarball의 test 타깃 `exclude` 여부 (M10판 계획의 crates.io 착지 추기가 남긴 것)
- M10판 계획 §3의 나머지 유예 전건: README 서사·구조 전면 재작성(M9 DoD 1 뒤), 서비스 매니저 실호출, qsh 자체 데몬화, `.pkg` 배포 형식, `scripts/install.sh`의 provenance 자동 검증, curl 설치 경로의 man 설치, 그리고 `docs/ROADMAP.md` §3 가드레일 표의 항목 전부
