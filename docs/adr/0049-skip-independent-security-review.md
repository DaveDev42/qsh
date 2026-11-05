# ADR-0049: 독립 보안 리뷰(SC7)를 마감 조건에서 빼고 wire freeze를 발효한다

날짜: 2026-11-05
상태: 승인됨 (2026-11-05, 사용자 결정 "독립 보안 리뷰는 스킵. 그냥 마감 조건에서 빼. 우리가 검토한 것으로 충분해.")

개정 관계: `docs/PRD.md` §15의 일곱째 성공 기준("공개 beta 전에 protocol과 key lifecycle의 독립 보안 review를 완료한다")을 바꾼다. `docs/ROADMAP.md` M8 DoD 4(프로토콜 스펙 freeze 후 독립 리뷰 계약)를 이 ADR로 닫는다. `docs/design/protocol.md` §16의 발효 조건인 "SC7 운영자 판정"을 이 결정으로 채운다. 판정은 §16 머리의 (나)(예약 없이 freeze만 진행)이고, 리뷰는 뒤에 예약하지도 않는다.

## 맥락

PRD §15는 공개 beta 전에 외부 독립 보안 리뷰를 요구했고, ROADMAP은 그 리뷰를 M8 DoD 4로 두고 리드타임 때문에 wire format을 리뷰 약 6주 전에 freeze하게 했다. 리뷰 계약은 저장소 밖 조직 액션이라 M8 마감 뒤로 이월됐고(ROADMAP M8 마감 노트), 그동안 protocol.md §16의 wire freeze도 "초안 — 발효 전"으로 그 판정을 기다렸다. README의 Status 문단은 이 두 가지를 "not for production use"의 사유로 적었다.

리뷰에는 비용이 들고, 이 프로젝트의 제약은 지출 없음이다. 한편 프로젝트 안의 검토는 쌓여 있다. threat model(`docs/design/threat-model.md`)의 위협·통제·고정 테스트 행, parser 타깃당 72 fuzz-hours 이상(`docs/campaigns/m8-fuzz.md`), 24h soak와 적대적 부하 하네스(`docs/campaigns/m8-soak.md`, `docs/campaigns/m8-adversarial-load.md`), 단일 choke point의 default-deny 권한과 fail-closed 감사 기록이 그것이다.

## 결정

1. 독립 보안 리뷰는 하지 않는다. SC7은 마감 조건에서 빠진다. P0 MVP 완료 선언에 필요한 사람 회차는 일곱에서 여섯이 된다(ROADMAP "현재 위치" 아래 절).
2. PRD §15의 일곱째 항목은 "공개 beta 전에 protocol과 key lifecycle을 threat model, fuzz, soak, 적대적 부하 캠페인으로 검토한다. 외부 독립 리뷰는 요구하지 않는다(ADR-0049)."로 바꾼다. 이 검토는 이미 기록이 있으므로 새 작업을 만들지 않는다.
3. `docs/design/protocol.md` §16 wire format freeze는 이 ADR을 담은 커밋 날짜로 발효한다. §16.10 절차의 2~4(상태와 일자·커밋, README 한 줄, PRD 문장 개정)를 같은 변경에서 한다. 발효 뒤의 변경 규율은 §16.4·§16.5 그대로다.
4. README의 Status 문단에서 외부 리뷰를 기다린다는 사유를 지운다. "not for production use"는 남은 사람 회차가 열려 있는 동안 유지한다.

## 근거

- 사용자가 결정했다. 지출 없음 제약 아래에서 외부 리뷰는 일정도 비용도 잡을 수 없는 항목이라 마감을 무기한 붙잡는다.
- freeze는 리뷰 일정을 위해 기다리던 것이고, 리뷰가 없으면 기다릴 이유가 없다. additive-only 규율은 발효 전에도 이미 지켜 왔다(ADR-0019 결정 4, ADR-0048).

## 대안과 기각 사유

- **리뷰를 뒤로 미루고 SC7을 유지한다.** 마감 조건이 영영 열린 채 남는다. 기각.
- **무료 자발 리뷰(커뮤니티, 지인)로 SC7을 채운다.** 기간과 범위를 보장할 수 없고 "독립 리뷰"로 칠지의 판정이 또 남는다. 기각. 그런 리뷰가 생기면 받는 것은 막지 않는다.

## 결과

- `docs/PRD.md` §15 일곱째 문장, `docs/ROADMAP.md` 현재 위치 절·M8 DoD 4·위험 표, `docs/design/protocol.md` §16 머리와 §16.10, `README.md` Status 문단과 Security posture, `PLAN.md`의 M8 DoD 4 항목을 고친다.
- 외부 시각의 검증이 없다는 잔여 위험은 `docs/design/threat-model.md`의 잔여 위험 절에 적는다.
