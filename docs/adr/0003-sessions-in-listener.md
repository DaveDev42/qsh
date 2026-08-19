# ADR-0003: PTY 세션을 MVP에서 `qsh serve` 프로세스 내부에 둔다

날짜: 2026-08-17
상태: 승인됨

## 맥락

QSH의 핵심 차별점은 PTY 세션 수명이 QUIC connection 수명과 분리되는 것이다(PRD §4 "연결과 세션의 분리"). Detached PTY(연결이 끊긴 뒤에도 살아있는 child process)를 어디서 관리할지 정해야 한다: `qsh serve` listener 프로세스 자체 안에 둘지, 별도 supervisor 프로세스로 분리할지.

Supervisor 분리는 listener 재시작/업그레이드 중에도 세션이 생존한다는 장점이 있지만, IPC 설계, 프로세스 수명 관리, 업그레이드 오케스트레이션(소켓 handoff, graceful drain 등)의 구현 비용이 크다.

## 결정

MVP(P0)에서는 PTY 세션을 `qsh serve` 프로세스 내부에서 관리한다. 대신 향후 별도 supervisor로 drop-in 교체 가능하도록 지금 두 가지 seam을 구축한다:

1. Broker를 `SessionBackend` trait 뒤에 둔다. 이 trait은 transport 타입을 import하지 않는다(프로세스 경계를 넘어갈 수 있는 추상화를 유지하기 위함).
2. Per-process UDS(Unix Domain Socket) 제어 소켓 계층(`localctl.rs`)을 미리 깔아, tunnel 관리 등 로컬 제어를 이미 프로세스 간 IPC 형태로 처리한다.

Listener 재시작 시 세션 손실은 문서화된 알려진 제한(PRD §16과 일치)으로 남기고, SIGTERM에는 drain 처리(진행 중 세션에 종료 유예)로 대응한다.

## 근거

- Supervisor 분리는 IPC 프로토콜, 소켓 handoff, 버전 skew 처리 등 상당한 엔지니어링 비용을 수반하며 MVP 전에는 과잉이다. M0~M1 목표는 리스크 척추(identity/mTLS/QUIC/framing/dispatch/ACL/JSON envelope)를 관통하는 walking skeleton이지 프로세스 아키텍처 최적화가 아니다.
- `SessionBackend` trait으로 broker를 격리해두면, 나중에 supervisor를 붙일 때 `qsh serve`의 나머지 코드(dispatch, ACL, transport)를 바꾸지 않고 trait 구현체만 교체하면 된다.
- UDS 제어 소켓을 지금 깔아두면 로컬 IPC 코드 경로(직렬화, 프레이밍, 권한 확인)가 이미 프로세스 경계를 넘는 형태로 검증되어, 향후 supervisor로의 전환이 "새 프로토콜 설계"가 아니라 "같은 프로토콜을 다른 프로세스로 옮기는 작업"이 된다.
- PRD §16 위험 표가 이미 "Listener 재시작으로 세션 손실"을 알려진 위험으로 명시하고 "초기 제한 명시, 추후 supervisor 검토"로 대응 방향을 정해뒀다 — 이 ADR은 그 결정을 구체화한다.

## 대안과 기각 사유

- **별도 supervisor 프로세스로 처음부터 분리**: 기각. IPC·업그레이드 오케스트레이션 비용이 M0~M2 일정(`docs/ROADMAP.md` 참고)에 비해 과도하다. 이 복잡도는 세션 생존성이 실사용에서 검증된 뒤 투자하는 것이 합리적이다.
- **세션을 아예 프로세스 재시작 시 버리는 것으로 확정(seam 없이)**: 기각. 나중에 supervisor를 붙이려면 broker 전체를 다시 설계해야 하는 함정에 빠진다. Trait seam의 비용은 낮고, 없으면 나중에 큰 재작업이 된다.
- **systemd socket activation 등 OS 레벨 프로세스 관리에 의존**: 기각. macOS/Linux 양쪽에서 이식성 있는 방식이 아니고, PRD §12가 QSH 경계 밖으로 명시한 "조직 계정과 중앙 관리"와 달리 이건 QSH 코어 책임이라 OS 기능에 위임할 수 없다.

## 결과

- `qsh-core/broker/`는 `SessionBackend` trait의 in-process 구현체 하나만 P0에서 제공한다.
- `SessionBackend` trait 시그니처는 transport crate(`qsh-transport`)를 import할 수 없다 — 의존 방향(`qsh(bin) → qsh-core → qsh-transport → qsh-proto`)과 arch-lint(xtask)로 강제한다.
- `localctl.rs`(UDS 제어 소켓)는 M2(session broker)와 함께 도입하며, tunnel 관리 등 로컬 제어 기능이 이를 통해 노출된다.
  - **추기 (2026-08-18, M2 계획 시):** 도입 시점을 **M3(역방향)** 로 늦춘다. M2 범위(ROADMAP)에 localctl이 없고 첫 소비자는 M3의 controller측 `qsh attach <reverse-host>` — CLI 프로세스가 상주 `qsh listen` 데몬과 UDS IPC로 통신하는 경로(protocol.md §11-3) — 이며 `qsh tunnels`(M4)는 그 다음 소비자이므로, M2에서 소비자 없는 IPC 계층을 미리 까는 것은 검증되지 않은 코드만 늘린다. 결정 자체(seam 2종)는 유지되며, M2는 seam 1(`SessionBackend`의 transport import 0 — arch-lint 확장으로 CI 검사)만 이행한다. 위 문장의 "M2"는 이 추기로 대체된다.
  - **추기 (2026-08-19, M3 Step 1 계약 확정 시):** 위 추기의 예시 `qsh attach <reverse-host>`는 `docs/CLI.md` §7 확정 이전의 표기였다 — 현재 계약에서는 `qsh <name>`(신규 세션)/`qsh attach <session-ref>`(재attach) 두 form이다(`docs/CLI.md` §7; `session-ref`는 `Ops`가 조립하는 opaque 값이며 호출자가 host와 session ID를 조합해 만들지 않는다 — §5, ADR-0007). 결정 자체(localctl 도입 시점, seam 2종)는 재론하지 않는다 — 표기만 정정한다.
- Listener 재시작으로 인한 세션 손실은 README/PRD에 알려진 제한으로 명시하고, SIGTERM 수신 시 drain(신규 attach 거부 + 기존 연결 정상 종료 유예) 로직을 구현해야 한다. drain은 세션을 살려 두지 않는다 — 모든 세션에 close 절차를 적용하고 `session.closed{reason:"closed"}`를 보낸 뒤 종료한다(CLI.md §6.12, 2026-08-18 명확화).
- Supervisor 분리는 P1 이후 후보로 남긴다.
