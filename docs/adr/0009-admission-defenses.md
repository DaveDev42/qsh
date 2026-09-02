# ADR-0009: 미검증 Initial은 항상 Retry로 되돌리고, admission은 handshake 상한과 source별 rate limit으로 자원 생성 전에 결정한다

날짜: 2026-09-02
상태: 승인됨

## 맥락

QSH 데몬(`qsh serve`, `qsh listen`)은 인터넷에 직접 노출되는 QUIC 리스너다. M1 이후 `Listener::accept`(`crates/qsh-transport/src/endpoint.rs`)는 `quinn::Incoming`을 그대로 `accept().await`했다 — `retry`/`refuse`/`ignore`/`remote_address_validated` 호출이 0건이었고 `bind_inner`는 `max_incoming`·`incoming_buffer_size(_total)`을 quinn 기본값(65536 / 10 MiB / 100 MiB)에 그대로 뒀다. `Server::run`과 `Listen::run`(둘 다 인터넷 노출 accept 루프)은 각 `Incoming`마다 무상한으로 task를 spawn했다.

이 상태에서 스푸핑된 출발지 하나가 보내는 QUIC Initial 패킷 하나는 서버에게 slab slot + 유도된 Initial 키 + 최대 10 MiB의 후속 버퍼를 강제할 수 있고 그 비용은 패킷 발신자가 실제로 그 주소에 존재하는지와 무관하다 — 왕복이 필요 없다. `receive_window`(연결 전체 unacked 상한)도 quinn 기본값 `VarInt::MAX`(무제한)로 남아 있었다. `docs/ROADMAP.md` M8 DoD 2는 이 감사 라인을 명시한다: 세션당 buffer ≤ 8 MB, accept 동시성 상한, source별 rate limit.

`PLAN.md` M8 Step 2는 이 갭에 대한 방어선 ①②(주소 검증 + accept 상한)를 요구했다. 조사(44개 fact, file:line 검증)와 설계 제안(`scratchpad/step2-design.md`, 21k자)을 거쳐 이 ADR이 확정하는 결정에 이르렀다.

## 결정

**1. 주소 검증되지 않은 모든 `Incoming`은 부하와 무관하게 무조건 Retry로 되돌린다.**

`!remote_address_validated()`이면 항상 `incoming.retry()`를 호출한다 — 부하 상태를 조건으로 걸지 않는다. Retry는 QUIC 프로토콜 자체의 주소 검증 왕복(스푸핑된 출발지는 왕복을 완성할 수 없어 서버 쪽에 상태를 전혀 남기지 못한다)이며 quinn이 `clean_up_incoming`으로 slab slot과 버퍼를 즉시 회수한다. 정상 클라이언트가 새 연결마다 지불하는 비용은 왕복 1회뿐이고 이미 확립된 연결의 migration은 새 `Incoming`을 만들지 않으므로 전혀 영향받지 않는다.

**2. accept 동시성 상한 — handshake 중인 연결 수를 `Semaphore`로.**

`qsh_core::admission::Gate`가 `tokio::sync::Semaphore`(`try_acquire_owned`)로 "handshake 중"(admission부터 `Incoming::accept()` 완료까지) 연결 수를 센다. 완료(성공이든 실패든) 즉시 permit을 해제하며 — `serve_connection` 이전, `accept_and_serve_permitted`의 `drop(permit)` — 확립된 장수명 연결은 handshake 슬롯을 계속 점유하지 않는다. 상한 도달 시 `refuse()`(주소 검증된 peer에게 빠르고 구별 가능한 실패를 준다 — `ignore()`는 정상 클라이언트를 10 s 타임아웃까지 방치한다). 기본값 `[serve].max_concurrent_handshakes = 64`(localctl `MAX_CONCURRENT_LOCALCTL_HANDSHAKES` 선례와 동일 크기).

**3. source별 rate limit — 4×1024×2세대 count-min sketch, 행별 독립 시드.**

주소 미검증 Initial만 대상. 키: IPv4 /32, IPv6 /64(privacy extension이 하위 64비트를 회전하는 정상 호스트를 과분류하지 않으면서 공격자가 /64 하나로 무한히 많은 키를 자칭하지 못하게). 4행 × 1024열 × 2세대(현재+이전 windowed epoch) `AtomicU32` = 32 KiB 고정 — 스푸핑 가능한 키로 자라는 테이블(LRU HashMap 등) 자체가 DoS 벡터이기 때문에 고정 크기·할당-free를 택한다. 각 행은 독립적으로 시드된 해시(`std::collections::hash_map::RandomState` per row)를 쓴다 — 공격자가 한 행의 해시를 관측·역산해 정상 source와 충돌하는 키를 사전 계산해도 나머지 3행까지 동시에 충돌시키지 못하면 오탐을 유발할 수 없다.

epoch 길이는 2 s, 기본값 `[serve].handshake_rate_per_source = 10`/s(지속), window당 최대 20건(burst) — Step 2 검증 라운드(F2)가 잡은 수정이다. 최초 설계는 `EPOCH = 1 s`에 임계값 `rate × 2`(burst multiplier)를 썼는데, 슬라이딩-윈도우 추정치가 1 s epoch 위에서 "이전 epoch 가중치 + 현재 epoch 누적"으로 굴러가는 이상 이 조합은 *지속* 20/s를 무기한 통과시킨다 — "기본 10/초, burst 2배"라는 CLI.md 문면이 실제로는 지속 상한을 2배로 풀어버리는 셈이었다. 고쳐서 `EPOCH = 2 s`, 임계값을 `rate_per_source × EPOCH.as_secs()`(=20)로 두면 지속 10/s 소스는 매 epoch 20건을 쌓아 임계값 경계에 놓이고(정확히 상한에서 지속하는 소스는 도착 지터에 따라 간헐적으로 걸릴 수 있다 — 상한이란 그런 것이다), epoch 하나 안에 몰아친 순간 burst도 같은 20건까지는 받아준 뒤 그 이상을 버린다. 정상 클라이언트의 재접속 케이던스(`REDIAL_DEADLINE` 2 s, 3회 ≈ 7 s에 dial 3건 이하)는 이 임계와 한 자릿수 차이다 — "단위를 맞춘" 수정이지 별도 burst multiplier 상수가 필요했던 게 아니다(`BURST_MULTIPLIER`는 삭제). 초과 시 `ignore()`(이미 abusive로 판단한 미검증 주소에는 바이트를 전혀 보내지 않는다).

**4. 순서(§4) — 자원을 생성하기 전에 거부가 결정된다.**

```
L0  quinn 사전 차단(무료): 짧은 Initial 폐기, max_incoming/incoming_buffer_size(_total) 포화 시
    Initial을 키 유도 없이 무시
L1  listener.accept() → Incoming (slab slot + Initial 키는 이미 quinn이 소비)
L2  미검증이면: rate-limit(key(peer))
      초과 → incoming.ignore()  → 집계 audit "rate_limited"
      통과 → incoming.retry()   → audit 없음
L3  검증됨이면: semaphore.try_acquire_owned()
      실패 → incoming.refuse()  → 집계 audit "at_capacity"
L4  tokio::spawn(handshake) → permit은 handshake 완료 즉시 해제, serve 이전
L5  [Step 3 훅] 세션/터널 쿼터 — ACL allow 뒤, 자원 spawn 전. 여기서 만들지 않는다.
```

거부 경로 어디에서도 task·연결·세션·fd가 생성되지 않는다. rate-limit이 semaphore보다 먼저다 — 스푸핑된 source가 permit을 절대 소비하지 못하게.

**5. audit — 구조적 필드만, 창(10 s)당 category별 "첫 건 즉시 + 요약 1행" 집계.**

`AuditRecord::handshake_rejected` 재사용, 신규 category `"rate_limited"`/`"at_capacity"`. 신규 필드 `count: Option<u32>`(additive, `skip_serializing_if`) — 창의 첫 거부는 실제 관측된 `peer_addr`와 함께 즉시 기록하고 같은 창의 이후 거부는 카운터만 증가시키다가, `peer_addr = "-"`, `count = Some(억제된 건수)`인 요약 레코드 1행으로 닫힌다. Retry 발급 자체는 audit하지 않는다 — Retry는 거부가 아니라 프로토콜 challenge이며 이를 감사하면 그 자체가 audit-flood 벡터다. `tracing::warn!`도 같은 억제를 따른다.

창을 닫는 경로는 둘이며 어느 쪽이 먼저 와도 된다. Step 2 검증 라운드(P1-3/F1)가 추가한 두 번째 경로가 핵심이다. ① lazy flush: 같은 category의 다음 거부가 창 만료 뒤에 도착하면 그 거부 자체가 이전 창을 닫으며 요약을 만든다(최초 설계 그대로). ② bounded flush: 두 accept 루프(`Server::run`/`Listen::run`) 각각의 `select!`에 `tokio::time::interval(AUDIT_AGGREGATION_WINDOW)`를 심어 그 tick(`MissedTickBehavior::Delay`)마다 `Gate::flush_expired(now)`를 호출한다. 루프 종료(shutdown) 시에도 1회 더 호출한다. lazy flush만 있던 최초 설계는 "flood가 완전히 멎으면 마지막 창의 count가 영원히 안 나올 수 있다"는 결함이 있었다 — 운영자가 가장 보고 싶은 순간(flood가 방금 끝났다)이 정확히 빠지는 경우다. `flush_expired`가 이를 닫는다: flood가 멎어도 최대 한 tick(`AUDIT_AGGREGATION_WINDOW`, 10 s) 안에 그 창의 요약이 나온다. 두 경로는 같은 창 상태(`Mutex<WindowState { start, suppressed }>`, category당 하나)를 공유하므로 경쟁하지 않는다 — 어느 쪽이 먼저 락을 잡아 창을 닫든 나머지 한쪽은 그 다음 거부/tick에서 새 창을 연다.

**6. 오류 표면 — 기존 `ErrorCode::ConnectionFailed`를 유지, 사람용 메시지만 개선.**

`DialError::Refused` 신설(`ConnectionClosed(0x2)`에서 분류) — 매핑되는 `ErrorCode`/`retryable`은 `DialError::Failed`와 동일(`ConnectionFailed`, `true`)하므로 `qsh.cli/v1`의 `code`/`retryable`은 이 변경으로 바뀌지 않는다. 바뀌는 것은 사람이 읽는 메시지뿐("host refused the connection (at capacity or rate-limiting new connections); retry shortly"). `qsh doctor`에는 신규 finding code를 추가하지 않는다 — doctor는 로컬 연산이고 원격 host의 포화는 로컬에서 관측 불가능하다.

**7. `[serve]`의 `0`은 "기본값", 결코 "무제한"이 아니다 — 이 방어선을 끄는 설정은 없다.**

`max_concurrent_handshakes`/`handshake_rate_per_source` 둘 다 `replay_bytes`/`close_grace_ms`와 같은 규율을 따른다: config의 `0`은 default로 치환되고 명시적으로 무제한을 표현할 방법이 없다.

**8. `qsh listen`은 `[serve]`의 값을 상속한다 — `[listen]` 자체 admission 키는 없다.**

reverse target 등록 accept 루프(`crates/qsh-core/src/reverse/listen.rs`)도 동일하게 인터넷에 노출되므로 같은 `Gate` 타입·같은 순서를 쓴다. 별도 키가 필요해지면 그때 추가한다.

## 근거

- 부하 게이트(포화 상태에서만 Retry) 대안은 부트스트랩 문제가 있다 — 신호가 오르는 시점에는 이미 공격자가 우리에게 키 유도와 최대 10 MiB 버퍼링을 강제한 뒤다. 무조건 Retry는 이 창을 아예 없앤다. 진짜 포화 대응은 한 층 아래 quinn의 `max_incoming`(공짜, 키 유도 이전)이 이미 담당한다.
- mobility 비용(신규 연결당 1 RTT)은 M2 캠페인이 기록한 지배 항(재수립에 4-5 s, OS 경로 재수립)에 비하면 몇 % 수준이다 — 실측은 아니며 M8 ≥60회 전환 캠페인이 최종 판정이다. 그 캠페인이 RTT 비용이 실제로 문제라고 보이면, load-gated retry(부하 임계 이상에서만 Retry)를 config-gated escape hatch로 도입할 수 있다 — 이번 단계에서는 만들지 않는다.
- count-min sketch(고정 크기)는 스푸핑 가능한 키로 자라는 어떤 자료구조도 그 자체로 DoS 표면이 된다는 원칙을 지킨다. 검증된 peer는 sketch를 완전히 우회하므로(cap만 적용) 오탐의 영향 범위는 미검증 Initial로 국한된다.
- NEW_TOKEN 기반 주소 검증은 이 워크스페이스에서 사용 불가능하다 — `default-features = false`로 quinn을 빌드해 `bloom`이 꺼져 있고(`sent: 0`, `NoneTokenLog`), 설령 켜져도 토큰이 클라이언트 IP에 결속돼 Wi-Fi↔tethering 전환에 무용하다. Retry(RFC 9000 §8.1.2) 기반 검증만 계획에 남는다.

## 대안과 기각 사유

- `AdmissionPolicy` trait을 `qsh-transport`에 배치: 기각. config·audit·rate-limit 상태를 glue crate로 끌어들여 아키텍처 매트릭스(`qsh-transport` → `qsh-proto`만)를 위반한다. 대신 transport는 메커니즘(`remote_address_validated`/`retry`/`refuse`/`ignore`)만 노출하고 `qsh-core::admission::Gate`가 결정·config·audit을 소유한다.
- 부하 게이트(load-gated retry): 기각(이번 단계). 부트스트랩 문제(위 근거) 때문에, 그리고 매 테스트가 시간·이력에 의존하게 만들기 때문에. escape hatch로만 기록.
- LRU/`Mutex<HashMap>` rate limiter: 기각. 소규모 정상 케이스에는 정확하지만 hot path에서 할당·lock을 유발하고 스푸핑 flood 하에서 eviction이 정상 항목을 밀어낸다.
- NEW_TOKEN 기반 주소 검증: 기각. 이 빌드에서 사용 불가능(`bloom` off)하고 가능하더라도 IP 결속이 mobility와 근본적으로 상충한다.
- `count`를 `resource` 문자열에 접붙이기(`"at_capacity_x137"`): 기각. `resource`가 "구조적 category 어휘"라는 규율을 깨고 어휘를 열거 불가능하게 만든다. 대신 `count: Option<u32>` 신규 필드(additive).
- `ignore()`를 cap 초과 시에도 사용: 기각. 이미 주소 검증된 peer는 진짜이므로, 정상 클라이언트를 10 s 타임아웃까지 방치하는 대신 `refuse()`로 빠르고 구별 가능한 실패를 준다.

## 한계

- Retry 토큰 재전송(P2-3, Step 3 입력). quinn 기본 `retry_token_lifetime = 15 s`는 이번 ADR에서 건드리지 않는다. 실제 주소를 쓰는 공격자는 왕복 1회로 유효한 Retry 토큰을 얻고 그 토큰을 15 s 동안 재전송해 매번 주소-검증된(sketch를 완전히 우회하는) `Incoming`을 만들어낼 수 있다 — quinn-proto에 토큰 재사용 로그가 없기 때문이다(`TokenPayload::Retry` 검증은 주소 일치와 수명만 본다; `check_and_insert` 재사용 방지는 `TokenPayload::Validation` 경로에만 있고 그 경로는 `bloom` feature가 꺼져 있어 이 빌드에서 도달 불가). 그렇게 확보한 검증된 시도들이 경합하는 대상은 여전히 64개짜리 handshake permit pool뿐이다. 회귀는 아니다. Step 2 이전에는 주소 검증도, 동시성 상한도 없었으니 순수하게 더 엄격해졌다. 증폭도 없다(주소가 실제이므로 응답이 요청보다 크지 않다). 다만 CLI.md §6.12의 rate-limit 문장은 주소 미검증 Initial에만 적용되며 검증된 시도의 *속도* 자체를 막는 장치는 오늘 없다 — 이는 Step 3(세션·터널 쿼터)이 물려받을 입력으로 여기 명시해 둔다.
- `rate_limited` 첫 행의 `peer_addr`는 미검증 주소다(P3-3). §5의 요약 레코드는 `peer_addr = "-"`로 스푸핑 우려를 원천 차단하지만 같은 창의 *첫* 거부는 실제 관측된 `peer_addr`를 그대로 싣는다 — `rate_limited` category에서 이 값은 정의상 주소-검증 *이전* 단계에서 관측된 것이라 스푸핑 가능하다. 창당 1회로 유계이고 페이로드가 아니므로 CLAUDE.md의 "키 자료·PTY 내용 무기록" 규율 위반은 아니지만 운영자가 이 필드를 "공격자의 실제 주소"로 오독하지 않도록 여기 명시한다 — 상관관계 확인(같은 IP가 반복 등장하는지 등)에는 쓸 수 있지만 발신자 신원의 증명은 아니다. (`at_capacity` category의 첫 행은 반대다 — 그 지점에 도달한 peer는 이미 주소 검증을 통과했으므로 관측값을 신뢰할 수 있다.)

## 결과

- `crates/qsh-transport/src/endpoint.rs`: `Incoming`에 `remote_address_validated`/`may_retry`/`retry`/`refuse`/`ignore`/`remote_address` 추가. 세 admission 상한을 한 함수 `server_config(..)`로 모아 `bind_inner`와 그 pin 테스트가 같은 생성 지점을 쓰게 했다 — `max_incoming = 4096`(고정 상수, config 비의존), `incoming_buffer_size = 64 KiB`(실측 4,800 B의 ~13.6배, quinn 기본 10 MiB의 1/160), `incoming_buffer_size_total = 16 MiB`(`INCOMING_BUFFER_SIZE × 256`, `const_min` 산술 없이 명시 상수). `transport_config()`가 `receive_window = min(TUNNEL_STREAM_RECEIVE_WINDOW × MAX_CONCURRENT_BIDI_STREAMS, 8 MiB) = 8 MiB`를 설정한다(ROADMAP M8 DoD 2).

  `incoming_buffer_size_total`은 최초 설계·구현 라운드에서 실질적으로 no-op이었다(P2-2). `const_min(INCOMING_BUFFER_SIZE × MAX_INCOMING, 100 MiB) = const_min(256 MiB, 100 MiB) = 100 MiB` — 즉 이 필드에 실제로 적용된 값은 quinn 자신의 기본값(100 MiB) 그대로였고 M8 Step 2가 실제로 좁힌 것은 `max_incoming`과 `incoming_buffer_size` 둘뿐이었다. `MAX_INCOMING`으로부터 유도하는 대신 16 MiB를 명시 상수로 박은 것이 Step 2 검증 라운드의 수정이다 — retry-always 하에서 `Incoming`은 accept 루프 한 반복 안에서 동기적으로 해소되므로(수락 결정과 quinn의 `retry`/`refuse`/`ignore`/`accept` 호출 사이에 `.await`가 없다) 다수 `Incoming`이 동시에 버퍼를 크게 쌓아 둘 창 자체가 거의 없고 그럼에도 100 MiB짜리 공격자-영향 가능 버퍼를 ROADMAP M8 DoD 2의 idle-listener ≤30 MB 소크 상한 옆에 그대로 둘 수는 없었다.

  한도를 넘으면 quinn은 무엇을 하는가(벤더링된 `quinn-proto-0.11.16` 소스로 확인, `~/.cargo/registry/src/*/quinn-proto-0.11.16/src/endpoint.rs:218-227`, `handle_first_packet`의 `RouteDatagramTo::Incoming` 분기): `incoming_buffer.total_bytes + datagram_len <= incoming_buffer_size` 그리고 `all_incoming_buffers_total_bytes + datagram_len <= incoming_buffer_size_total` 둘 다 통과해야 후속 datagram을 그 `Incoming`의 버퍼에 넣는다 — 어느 한쪽이라도 넘으면 그 datagram은 조용히 버려진다(에러 없음, 이미 만들어진 `Incoming`이나 그 안에 쌓인 데이터는 그대로). 즉 한도 초과의 비용은 그 한 datagram뿐이고 정상 클라이언트라면 그 재전송이 버려진 뒤 자기 loss-recovery 타이머로 다시 보낼 뿐이다 — 일반적인 패킷 손실과 같은 결과다.
- `crates/qsh-core/src/admission.rs`(신규): `Gate`(clock 주입, `decide()` 순수 함수 + semaphore + sketch), `Decision`(`Retry`/`Ignore`/`Refuse`/`Admit`), `RejectReason`(`RateLimited`/`AtCapacity`). `Server::run`/`Listen::run` 둘 다 `admit()`을 통해 소비한다.
- `crates/qsh-core/src/config.rs`: `ServeConfig`에 `max_concurrent_handshakes`(기본 64)·`handshake_rate_per_source`(기본 10) 추가, `replay_bytes`와 동일한 `0 ⇒ default` 규율.
- `crates/qsh-core/src/audit.rs`: `AuditRecord.count: Option<u32>`(additive), `AuditRecord::handshake_rejected_summary` 생성자 신설.
- `crates/qsh-transport/src/endpoint.rs` + `qsh-core/src/ops/{mod,exec}.rs`: `DialError::Refused` 신설, `ErrorCode::ConnectionFailed`/`retryable: true` 유지.
- `docs/CLI.md` §6.12, `docs/design/architecture.md`(config map, audit 필드 목록), `docs/design/protocol.md`(TLS/admission 절에 Retry-always 한 문장) 갱신.
- Step 3가 물려받는 것: L5 훅(세션/터널 쿼터, `server/mod.rs:1041`·`:2532`·`:2626`), slow-loris(handshake 후 established 연결 수 무상한) — 이 ADR의 범위 밖으로 명시적으로 남긴다.
- 지속 flood 하의 RSS/fd 상한, 실제 soak 판정은 Step 4의 적대적 부하 하네스가 담당한다 — 이 ADR과 Step 2의 테스트는 각 메커니즘이 트리거·회복된다는 것만 증명한다.
