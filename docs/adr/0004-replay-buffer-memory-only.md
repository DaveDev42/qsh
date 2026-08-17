# ADR-0004: Replay buffer는 memory-only ring으로 시작한다

날짜: 2026-08-17
상태: 승인됨

## 맥락

PTY 세션은 output sequence 기반 replay buffer를 유지해 재접속 시 마지막으로 확인한 지점부터 output을 복구한다(PRD §8, §13). 기본 buffer 크기는 세션당 8MB(설정 가능)다. Buffer 구현을 memory-only ring으로 할지, encrypted disk spool까지 허용할지 결정해야 한다.

Buffer 범위를 벗어난 read 요청은 QSH가 누락 구간을 숨기지 않고 gap event로 명시한다는 계약(PRD §8, CLI.md §6.4 `session.gap`)이 이미 있다 — 즉 "overflow로 인한 손실"은 프로토콜 레벨에서 이미 정상적으로 처리되는 경로다.

## 결정

Replay buffer는 **memory-only ring**(기본 8MB)으로 구현하며, `ReplayStore` trait 뒤에 격리한다. Encrypted disk spool은 P1로 연기하고, 도입한다면 "프로세스 생존 중에만 유효한 ephemeral key" 방식의 opt-in으로 검토한다.

## 근거

- Gap 계약이 이미 overflow를 "올바른 손실"로 만든다 — 클라이언트는 gap event를 받아 명시적으로 인지하므로, buffer를 늘려도 정합성 문제가 생기지 않고 단지 gap이 덜 발생할 뿐이다. Disk spool 없이도 안전하다.
- Encrypted disk spool은 spool 파일에 대한 key 관리 표면(키 생성, 저장, rotation, 삭제, 파일 권한)을 새로 추가한다 — QSH의 "로그에 key, PTY 내용을 기본 저장하지 않는다"(PRD §9)는 보안 원칙과 정면으로 긴장 관계에 있고, PTY 내용이 디스크에 남는 것 자체가 새로운 공격 표면이자 개인정보 위험이다.
- 이 비용 대비 이득이 미미하다: 8MB memory ring도 이미 상당한 replay 여유를 제공하고(전형적 텍스트 터미널 output 기준 수십 초~수 분 분량), disk spool이 막아주는 것은 "매우 긴 단절 + 매우 활발한 output"이라는 좁은 케이스뿐이다.
- Memory-only는 구현이 단순하고 fsync/디스크 I/O로 인한 PTY 저지연 요구(p95 <10ms)에 대한 리스크가 없다.

## 대안과 기각 사유

- **Encrypted disk spool을 P0에 포함**: 기각. Key 관리 표면 추가 비용이 이득 대비 크고, PTY 평문 내용을 디스크에 남기는 것은 보안 원칙과 충돌한다. MVP 범위를 벗어난다.
- **평문 disk spool(암호화 없이)**: 기각. 명백히 PRD §9 보안 요구사항 위반 — 논의 대상조차 아니다.
- **Buffer 크기를 무제한/매우 크게(예: 100MB+) 하여 disk 없이 gap을 사실상 없애기**: 기각. Idle listener 메모리 목표(30MB 이하, PRD §13)와 충돌하고, 세션 수가 많아지면 메모리 사용량이 선형으로 증가해 memory-starved 환경(예: 소형 VPS)에서 위험하다. 8MB 기본값 + 설정 가능이 더 안전한 기본선이다.

## 결과

- `qsh-core/broker/`의 `ReplayRing`은 `ReplayStore` trait 뒤에 위치해야 한다 — 향후 disk spool 구현체를 trait 구현체 교체만으로 추가할 수 있게.
- 기본 buffer 크기 8MB, 세션별 설정 가능(config.rs)으로 구현한다.
- `session.gap` event(CLI.md §6.4)가 buffer overflow의 유일하고 명시적인 신호여야 하며, 이를 숨기는 어떤 fallback도 있어서는 안 된다.
- P1 백로그: ephemeral-key encrypted disk spool을 opt-in 기능으로 재검토.
