# ADR-0002: 기본 pairing UX로 일회용 invite code 채택

날짜: 2026-08-17
상태: 승인됨

## 맥락

QSH는 password 인증을 지원하지 않고 상호 TLS와 pinned certificate(또는 private CA)로만 인증한다(PRD §9). 신규 두 장비가 서로를 처음 신뢰하게 만드는 pairing UX를 정해야 한다. 성공 기준(PRD §15, SC1)은 "신규 두 장비의 최초 연결을 5분 이내에 완료"다. 후보는 fingerprint 수동 확인, 일회용 pairing code, QR 코드 세 가지였다.

## 결정

기본 pairing UX는 `qsh trust invite`가 발급하는 **고엔트로피 일회용 invite code(10분 TTL)** 로 한다. 양측은 TLS exporter 기반 channel binding으로 HMAC proof를 교환해 중간자 없이 양방향 pin을 한 번에 설정한다.

- **Fingerprint 수동 확인**(`qsh trust add --fingerprint`)은 스크립트/프로비저닝용 1급 fallback으로 유지한다(Ansible, cloud-init 등 사람이 개입하지 않는 경로).
- **QR 코드**는 P1로 연기한다.
- `--json` 모드에서는 대화형 prompt 대신 `TRUST_REQUIRED` 오류 + 관찰된 fingerprint를 `details`에 반환한다(CLI.md §2.1 규칙과 일치).

## 근거

- Invite code + TLS exporter channel binding은 사람이 긴 fingerprint 문자열을 눈으로 대조할 필요 없이, 짧은 코드 하나로 MITM에 안전한 양방향 신뢰를 수립한다 — SC1(5분 이내)에 가장 근접한 UX다.
- Channel binding(TLS exporter)을 사용하므로 invite code 자체가 도청되어도 별도 채널(코드 교환)과 TLS 세션이 암호학적으로 결합되어 재생/중계 공격에 안전하다.
- Fingerprint 방식은 사람이 개입하지 않는 자동 프로비저닝(cloud-init 등)에서 여전히 필요하다 — invite code는 대화형 흐름을 전제하므로 대체 불가.
- QR은 부가 편의 기능이며 별도 스캐너/카메라 의존성을 요구해 P0 범위를 벗어난다. invite code 문자열을 QR로 인코딩하는 것은 나중에 UX layer만 추가하면 된다.

## 대안과 기각 사유

- **Fingerprint 수동 확인을 기본값으로**: 기각. 사람이 SHA-256 fingerprint 전체 또는 축약형을 육안 대조해야 해 실수 위험이 크고 5분 목표에 불리하다. 대신 스크립트/헤드리스 경로의 1급 fallback으로는 유지한다.
- **QR 코드를 P0에 포함**: 기각. 카메라/스캐너 의존, 두 장비 다 화면이 없는 헤드리스 서버 시나리오(주 사용자 페르소나 중 인프라 운영자)에 맞지 않는다. P1에서 invite code의 대체 encoding으로 추가.
- **중앙 pairing 서버/QR 릴레이**: 기각. PRD의 direct-first, relay 없는 MVP 원칙(§4, §17)에 정면으로 위배된다.

## 결과

- `qsh trust invite` / `qsh trust accept <code>` 명령과 TLS exporter 기반 HMAC proof 교환 로직을 `qsh-core::trust` 모듈([architecture.md](../design/architecture.md) §5)에 구현해야 한다.
- Pairing 로직은 `TrustEvaluator` trait을 통해 `QshPeerVerifier`(ADR와 무관하게 이미 결정된 pin-or-CA 검증기)와 연결된다.
- `--json` 경로는 대화형 prompt를 절대 열지 않고 `TRUST_REQUIRED` + `details.fingerprint`를 반환해야 한다 — CLI.md §11(frontend에 인증 로직 금지)과 일치.
- P1 백로그: QR 인코딩(invite code를 QR로 표시/스캔), pairing 만료·재발급 UX 개선.
