# ADR-0018: 터널 수명은 v1 내내 QUIC connection에 결합하고, forward-route live carrier와 `-R` 자동 재발행은 P1로 둔다

날짜: 2026-09-09
상태: 승인됨

## 맥락

M4 Step 8이 확정한 resume 의미론은 두 갈래다. path migration(IP 변경, Wi-Fi↔테더링)은 connection이 살아 있으므로 터널을 투명하게 살려 보내고, connection 손실 뒤의 resume은 세션만 살리며 터널 스트림은 깨끗이 끝낸다(`docs/ROADMAP.md` M4 마감 노트). `crates/qsh-testkit/tests/tunnel_chaos.rs`의 `a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes`가 이 갈래를 테스트로 고정하고, `README.md` Known limitations와 `docs/CLI.md` §6.14 Holder lifetime이 사용자에게 같은 말을 한다.

그 위에 두 요구가 남아 있었다. 하나는 **forward-route live carrier**로, `-L` listener를 쥔 CLI 프로세스가 resume에 성공하면 그 뒤 들어오는 새 TCP 연결을 새 connection으로 실어 나르자는 것이다. 다른 하나는 **`-R` 자동 재발행**으로, reverse route 위의 `-R`이 reverse connection과 함께 죽었을 때 데몬이 재등록 직후 `RemoteForwardOpen`을 다시 내자는 것이다. M4가 M5 입력으로 넘겼고 M5는 범위 밖으로 판정해 ROADMAP §3 표에 M8 소유로 올렸다. M7 이월 표의 ix, M8 PLAN §6.4 ix가 같은 항목이고, M8 Step 5 (a)는 "의미론 재설계라 새 ADR 선행"으로 Step 6에 이관했다. wire freeze(Step 7) 전에 결정해야 하는 이유는 `-R` 자동 재발행이 `RemoteForwardOpen`이 기존 `forward_id`를 받아들이는 새 wire 의미를 요구하기 때문이다(CLI.md §6.14 예외 문단).

## 결정

1. **v1의 터널 수명은 지금 그대로 QUIC connection에 결합한다.** `-L` listener는 프로세스 수명, `-L` forward와 `-R` 등록은 그것을 실어 나른 connection 수명이다. connection 손실 뒤 resume은 세션만 복구하고 터널은 새 `tunnel.open`으로 다시 연다. `tunnel_chaos.rs`의 개정 강제 트랩은 v1 내내 유지한다.
2. **forward-route live carrier는 구현하지 않는다.** `-L` listener를 쥔 프로세스는 resume 뒤에도 그 listener로 들어오는 새 연결에 reset을 돌려준다. 사용자 처방은 지금 README가 적은 대로 forward 재시작이다.
3. **`-R` 자동 재발행은 P1 백로그로 옮긴다.** wire freeze에 `RemoteForwardOpen`의 `forward_id` 재수락 의미를 넣지 않는다. 필요해지면 v1 이후 additive 필드(예: `reclaim: bool`)로 넣을 수 있고, freeze가 그 길을 막지 않는다는 점만 protocol.md의 freeze 문면에 한 줄로 적는다.
4. ROADMAP §3 표의 이 행과 PLAN §6.4 ix는 이 ADR로 닫는다. protocol.md·README·CLI.md의 현행 서술은 이미 이 결정과 같으므로 개정하지 않는다.

## 결과

- 터널 recovery 의미론이 M4 이후 한 번도 바뀌지 않은 채 freeze에 들어간다. 세션은 replay ring으로 resume하고 터널은 하지 않는다는 비대칭이 v1의 계약이다.
- 모바일 사용자에게 가장 흔한 사고(네트워크 전환)는 path migration이 처리하므로 터널도 살아남는다. 터널이 끊기는 것은 connection 자체가 죽는 경우(장시간 sleep, idle timeout 초과)뿐이고, 그때는 셸도 resume 배너를 띄우므로 사용자가 forward를 다시 여는 시점을 안다.
- `qsh tunnels`가 데몬이 실제로 쥔 터널만 보고한다는 규칙(CLI.md §6.9)이 그대로 유지된다. 자동 재발행이 없으니 "등록돼 있다고 보고되지만 claim conduit이 없는" 상태를 데몬이 스스로 만들 일도 없다.
- P1에서 `-R` 재발행을 넣을 때 필요한 것은 wire 필드 하나와 데몬의 재등록 훅 하나다. freeze가 additive 확장을 허용하므로 v2 wire가 필요하지 않다.

## 대안

- **live carrier 구현.** `-L` 경로에서 listener와 forward를 분리해 resume 뒤 새 connection에 다시 붙이는 것. 구현 자체는 클라이언트 로컬이라 wire 변경이 없지만, `tunnel_chaos.rs`의 트랩과 README·CLI.md §6.14의 문면을 다 뒤집어야 하고, 세션과 달리 in-flight TCP 연결은 어차피 살리지 못하므로 사용자가 얻는 것은 "listener를 다시 띄우지 않아도 된다" 하나다. wire freeze 전 일정에 넣을 가치가 그만큼은 아니다.
- **`-R` 자동 재발행을 지금 넣기.** `RemoteForwardOpen`이 기존 `forward_id`를 재수락하는 의미와, 데몬이 재등록 직후 그것을 재발행하는 훅이 필요하다. 소유 principal 축(M5 Step 5)과 `conn_id` purge 축이 교차하는 지점이라 F5 리뷰가 다시 필요하고, Step 7 threat model이 그 전에 나와야 한다. 순서가 맞지 않는다.
- **터널을 broker 관리 리소스로 승격.** 세션처럼 resume 대상으로 만드는 것. architecture.md가 터널을 broker 밖 별도 서브시스템으로 둔 결정(M4)을 뒤집는 재설계라 M8 범위가 아니다.
