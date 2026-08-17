# Architecture Decision Records

QSH의 아키텍처/설계 결정을 기록한다. 각 ADR은 맥락, 결정, 근거, 대안과 기각 사유, 결과를 담는다.

| 번호 | 제목 | 상태 |
|---|---|---|
| [0001](0001-custom-quic-protocol.md) | Custom QUIC application protocol 채택 | 승인됨 |
| [0002](0002-pairing-invite-code.md) | 기본 pairing UX로 일회용 invite code 채택 | 승인됨 |
| [0003](0003-sessions-in-listener.md) | PTY 세션을 MVP에서 `qsh serve` 프로세스 내부에 둔다 | 승인됨 |
| [0004](0004-replay-buffer-memory-only.md) | Replay buffer는 memory-only ring으로 시작한다 | 승인됨 |
| [0005](0005-tcp-fallback-p1.md) | TCP/TLS fallback은 P1 유지, transport 추상화는 P0 산출물 | 승인됨 |
| [0006](0006-product-name-and-crate-name.md) | 제품명은 `qsh` 유지, crates.io 패키지명만 `qsh-cli`로 분리 | 승인됨 |
