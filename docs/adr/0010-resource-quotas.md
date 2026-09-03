# ADR-0010: 세션·exec·터널·연결 quota는 인가 이후·자원 생성 이전에 결정하고, 살아 있는 자원 자체를 계수한다

날짜: 2026-09-03
상태: 승인됨

---

이 ADR은 M8 Step 3a와 3b를 모두 담는다. 3a가 세션 전역·세션 principal별·exec principal별·검증된
시도 rate의 4개 축을 냈다. 3b가 나머지 여섯(exec 전역, 터널 스트림 2종, remote forward listener,
연결 전역·principal, pairing 고정 상한)을 채워 결정 표의 10개 키가 전부 구현으로 닫혔다.

## 맥락

`qsh serve`/`qsh listen`은 M8 Step 2(ADR-0009)로 handshake 단계의 스푸핑 방어선을 얻었다. 주소
미검증 Initial은 항상 Retry로 되돌리고 동시 handshake 수와 미검증 source의 시도 속도를 상한 이하로
묶는다. 그 방어선은 handshake가 끝나는 순간 멈춘다. ADR-0009 한계 절이 명시하듯, 실제 주소를 쓰는
peer가 Retry 왕복 1회로 유효한 토큰을 얻으면 quinn 기본 `retry_token_lifetime`(15 s) 동안 그 토큰을
재전송해 매번 주소-검증된 `Incoming`을 만들 수 있다. 그렇게 검증까지 마친 peer가 인가(ACL)까지
통과하면 그다음부터는 아무 상한도 없었다. pinned(또는 CA 신뢰된) 단일 principal이 `session.open`을
무제한으로 열어 세션마다 PTY·process group을 spawn시키거나, `exec.run`을 무제한으로 발급해 미상환
ticket 뒤에서 자식 프로세스를 무상한으로 fork시킬 수 있었다. 두 경우 모두 ACL은 이 principal이
`session.open`/`exec.run`을 할 자격이 있는지는 답하지만 몇 개까지인지는 답하지 않는다. 인가와 용량은
서로 다른 질문이고 M8 Step 2 이전까지 후자에 답하는 층이 아예 없었다.

`PLAN.md` M8 Step 3은 이 갭에 대한 방어선 ③(세션·터널 quota)을 요구한다. 조사(132 fact)와 설계
제안(`scratchpad/step3-design.md`)을 opus 적대적 검토(`step3-critique.md`, P1 4·P2 10·P3 4)에 부친 뒤
main 세션이 그 결과를 재판정했다(`scratchpad/plan-step3-verdict.md`). 구현은 3a(세션·exec quota +
검증된 시도 rate + 문서·fixture)와 3b(터널·연결 quota)로 나누어 각각 Step 2와 같은 리듬으로 진행한다.
이 문서는 그 판정과 3a 구현이 실제로 낸 결과를 기록한다.

## 결정

### 1. 배치 — 전부 `qsh-core`, 새 계층 없음

| 구성 요소 | 크레이트/모듈 | 비고 |
|---|---|---|
| `QuotaKind`·`QuotaLimits`·`Quotas`·`ExecPermit` | `qsh-core::quota`(신규) | ADR-0009의 `admission::Gate`와 같은 층 |
| 세션 quota 판정 지점 | `qsh-core::broker::mod` (`reserve_slot`, `SessionSlot`) | broker registry 락 아래, `factory.create` 앞 |
| exec quota 판정 지점 | `qsh-core::server::mod` (`handle_exec_start`) | ACL 판정 뒤, ticket 발급 앞 |
| audit 생성자 | `qsh-core::audit` (`quota_rejected`/`quota_rejected_summary`) | `handshake_rejected`류와 동형 |
| config 키 | `qsh-core::config::ServeConfig` | `replay_bytes`류와 같은 `0`=기본값 규율 |

`qsh-cli`·`qsh-transport`는 이 결정에 관여하지 않는다. ADR-0009가 이미 확정한 "인가·용량 로직은
`qsh-core`에만" 원칙을 그대로 잇기 때문이다(재론할 근거가 없어 대안은 검토하지 않았다).

### 2. 키·기본값 — 10개, 3a가 4개를 낸다

| 키 | 기본값 | 축 | 상태 |
|---|---|---|---|
| `max_sessions` | 256 | 전역 세션 수 | **3a 완료** |
| `max_sessions_per_principal` | 32 | principal별 세션 수 | **3a 완료** |
| `max_exec_per_principal` | 32 | principal별 미완료 `exec.run` 수 | **3a 완료** |
| `validated_rate_per_source` | 10/s | 검증된 Initial의 source별 시도 속도(P2-3, admission 축) | **3a 완료** |
| `max_exec` | 256(0=기본) | 전역 미완료 `exec.run` 수, 카테고리 `quota_exec_host`, 검사 순서는 세션과 같이 전역 → principal | **3b 완료** |
| `max_tunnel_streams_per_principal` | 256 | principal별 동시 터널 스트림 수 | **3b 완료** |
| `max_tunnel_streams_per_forward` | 64 | `-R` 등록 하나당 동시 스트림 수 | **3b 완료** |
| `max_remote_forwards_per_principal` | 16 | principal별 동시 `-R` 등록 수 | **3b 완료** |
| `max_connections_per_principal` | 32 | principal별 established 연결 수(accept arm 단위, §근거) | **3b 완료** |
| `max_connections` | 512 | 전역 established 연결 수(accept arm 단위, §근거) | **3b 완료** |

`max_exec`는 `max_connections`와 같은 aggregate bound 묶음으로 3b에서 구현한다; 3a 커밋 범위는 넓히지
않는다. main-session arbitration S5 handoff에서 짚었듯 CA posture에서 principal 수가 무계라 principal별
상한만으로는 전역 exec 자식 수에 aggregate bound가 없다. 세션은 `max_sessions`로 이미 전역 유계인데
exec만 비어 있던 간극이다.

전역 연결 상한(`max_connections`)이 왜 필요한지는 §근거에서 다룬다. principal별 상한만으로는 닫히지
않는 카디널리티 문제다.

`validated_rate_per_source`는 `admission::Gate`의 두 번째(독립) count-min sketch로 3a에서 이미
구현됐다(P2-3). `quota.rs`가 소유하는 4개 키와 자료구조는 다르지만 커밋 분할(중재 1)이 이 키를 3a
범위로 배정했으므로 이 표에 함께 싣는다.

pairing 연결은 별도 config 키를 두지 않는다: 고정 상수 `MAX_CONCURRENT_PAIRING_CONNECTIONS = 8`(3b)을
쓴다. pairing 연결은 `PAIRING_TIMEOUT`(10 s) × 2로 이미 시간상 유계이므로 principal별 상한이 아니라
미검증 상대가 열 수 있는 유일한 연결 클래스를 무상한으로 두지 않는다는 별도 근거로 정당화된다. 초과는
`serve_connection`(outer)의 pairing 분기가 `serve_connection_inner`를 부르기도 전에 거부한다. proof를
읽지도, 프레임도 쓰지도 않고 `conn.close(CLOSE_CODE_RESOURCE_EXHAUSTED = 0x1003, b"at capacity")`로
즉시 닫는다(§6).

### 3. RAII permit과 registry 파생 계수 — 별도 카운터 금지

세션 수는 broker registry를 스캔해서 얻는다(`reserve_session`, `broker/mod.rs:160`). registry 자체가
진실이고 별도의 `AtomicUsize` 카운터를 두지 않는다. 세션이 열려 있는 한(어태치 여부와 무관, "4. 세션
quota의 계수 대상" 참고) 그 세션은 registry에 남아 있다. `session.close`·TTL reaper·`purge_connection`이
registry에서 그 항목을 제거하는 순간이 곧 quota 해제 순간이다. 해제를 위한 별도 로직은 없다.

exec quota는 반대 형태다: 살아 있는 예약(`ExecPermit`, `quota.rs:321`)을 RAII로 센다. 미상환 ticket
수는 세지 않는다. `Quotas::reserve_exec`가 principal당 카운터를 증가시키며 `ExecPermit`을 발급하고
`ExecPermit::drop`이 감소시킨다. 명시적 "release" 호출은 없다. `PendingExec`(`server/mod.rs:257`)가
그 permit을 ticket 발급 시점부터 소유하므로 이 permit이 실제로 드롭되는 경로는 셋뿐이다: ticket
자연 만료(`tickets.retain`), `purge_connection`의 강제 제거, `redeem_ticket`이 넘긴 값을
`run_exec(..).await` 종료 뒤 그 arm이 드롭. 셋 다 그 `PendingExec`/`Ticket` 값 자체가 사라진다는
같은 사건이고 경로만 다를 뿐이다. `run_exec`은 spawn 실패도 `Ok(ExecOutcome{exit_code: 126/127})`로
보고한다(`Err`이 아니다). 그래서 "spawn 실패 시 release"와 "정상 종료 시 release"는 코드 경로도
드롭 시점도 동일하다. 둘을 구별하는 별도 로직은 없다.

`PendingExec::permit`(`server/mod.rs:257`)은 `Option<ExecPermit>`이 아니라 `ExecPermit` 필드로
선언돼 있다. 이 선언 자체가 컴파일 타임 보장이다. 이 값을 만드는 유일한 생성자가
`Quotas::reserve_exec` 성공 반환뿐이므로 permit 없이 `PendingExec`를 만드는 코드는 애초에
컴파일되지 않는다. 티켓은 permit 없이 존재할 수 없다. 이 제약은 타입 자체의 형태이지 런타임
불변식이 아니다.

계수 시점은 ticket 발급이지 redeem이 아니다("계수는 살아 있는 자식"이라는 요구를 "제출된 요청"
쪽으로 당겼다). 이 결과 `max_exec_per_principal`(기본 32)은 principal 전체의 연결을 가로지르는 상한이
되고 `MAX_PENDING_TICKETS_PER_CONN`(32, 연결별)과 두 숫자가 우연히 같다. 한 principal이 두 연결에서
각각 32개씩 미상환 ticket을 쥐는 조합은 이제 불가능하다. 의도된 결과다.

### 4. 세션 quota의 계수 대상 — attach 여부는 무관

detach된 세션(백그라운드에서 계속 실행 중이나 아무 conduit도 붙어 있지 않은 상태)은 attach된 세션과
동일하게 quota를 점유한다. registry가 진실이라는 결정(§3)의 직접 귀결이다. registry는 attach 상태를
따로 추적하지 않는다. quota가 attach 여부를 술어로 넣으려면 registry 스캔과 별개로 conduit 결합
상태를 다시 조회해야 하는데 그럴 이유가 없다. 세션이 quota를 놓는 유일한 사건은 registry에서 그
항목이 사라질 때(close/reap/purge)다. 붙어 있던 마지막 conduit이 끊긴 순간은 그 사건이 아니다.

### 5. 순서 — ACL 뒤, 자원 생성 앞

```
session.open:       Authorizer::check → Broker::reserve_slot(registry 락 아래, factory.create 앞) → SessionActor::create
exec.run:            Authorizer::check → drain 게이트 → Quotas::reserve_exec(전역 → principal) → issue_ticket
TCP_CONNECT(터널):    authorize_and_dial_tunnel의 ACL(forward.local) → 목적지 모양 검사(host 길이) → Quotas::reserve_tunnel_stream(principal → forward 키) → dialer.dial
RemoteForwardOpen:    authorize_and_bind_remote_forward의 ACL(forward.remote) → loopback·모양 검사 → Quotas::reserve_remote_forward(principal) → binder.bind
연결(host/principal):  accept(신원 확정, mTLS pin/CA) → Quotas::reserve_connection(전역 → principal) → handshake::respond의 local_hello 콜백 첫 줄(reverse 등록 거부 검사보다 앞) → Hello 프레임
연결(pairing):        accept(신원 = Principal::Pairing) → Quotas::reserve_pairing_connection(고정 8) → 실패 시 proof도 읽지 않고 즉시 close(§6)
```

인가되지 않은 principal은 quota가 이미 포화돼 있어도 여전히 `PERMISSION_DENIED`를 본다. quota
판정이 ACL 판정보다 먼저 도달할 경로가 없다(`saturated_quota_still_answers_permission_denied_to_
an_unauthorized_principal`, `server/mod.rs:4659`). 어느 진입점에서도 quota 거부는 자원(PTY·자식
프로세스)이 생성되기 전에 결정된다. `refused_open_never_calls_the_source_factory`
(`broker/mod.rs:1720`)가 이를 직접 고정한다.

와이어로 나가는 거부 메시지는 자원 종류별로 고정된 문구다("session quota exceeded"/"exec quota
exceeded"). 세션이 전역 축에서 막혔는지 principal 축에서 막혔는지는 이 문구에 실리지 않고 감사
레코드의 `resource` 필드(`quota_sessions_host`/`quota_sessions_principal`/`quota_exec_principal`
등)에만 나타난다.

`Broker::open`/`open_as`는 `open_with_opener`를 통하지 않고 자체적으로 `factory.create`를 호출하는
경로였으므로, quota 판정 자체를 `factory.create` 앞으로 옮겼다. `reserve_slot`(`broker/mod.rs:536`)이
`registry` 락 아래에서 전역 → principal 순으로 검사한 뒤, 통과하면 그 자리에서 in-flight 카운터를
올리고 `SessionSlot`(`broker/mod.rs:199`)을 돌려준다. registry 스캔과 카운터 증가가 `registry` 락을
쥔 채로 원자적으로 끝나므로, 두 concurrent 호출이 모두 아직 안 찼다고 읽고 둘 다 `factory.create`로
진입하는 경합이 없다. `SessionSlot`은 `open_with_opener_reserved`의 registry insert가 성공하는 순간
`consume`으로 자신을 소비한다. 그 전에 끝나는 다른 모든 경로(`factory.create` 실패, `SessionActor::
create` 실패, 동시 `close_all`, panic unwind)는 `Drop`이 같은 자리에서 예약을 반납한다. 예약 없이
`factory.create`를 호출하는 경로 자체가 남아 있지 않다.

### 6. wire 매핑 — 변경 0, 기존 어휘 재사용

| 실패 | `ErrorCode` | `retryable` | stop code | 상태 |
|---|---|---|---|---|
| `BrokerError::QuotaExceeded(_)` (session.open) | `ResourceExhausted` | `true` | 해당 없음(응답 프레임) | **3a 완료**(`server/mod.rs` `broker_error`) |
| exec quota 거부 (exec.run) | `ResourceExhausted` | `true` | 해당 없음(응답 프레임) | **3a 완료**(`handle_exec_start`) |
| `TCP_CONNECT` quota 거부(터널 스트림) | `ResourceExhausted` | 해당 없음(`ConnectResult`에 필드 없음) | `RESET_CODE_RESOURCE_EXHAUSTED = 0x200D`(기존 `0x2001/0x2003/0x2007/0x200A/0x200B/0x200C`와 겹치지 않는 다음 값) | **3b 완료**(`authorize_and_dial_tunnel`) |
| `RemoteForwardOpen` quota 거부(listener) | `ResourceExhausted` | `true` | 해당 없음(응답 프레임) | **3b 완료**(`authorize_and_bind_remote_forward`) |
| 연결(전역/principal) quota 거부 | `ResourceExhausted` | `true` | 해당 없음(응답 프레임 — `handshake::respond`의 `local_hello` 콜백, reverse 등록 거부 선례와 같은 경로) | **3b 완료**(`serve_connection` outer, `Listen::decide_registration`) |
| pairing 연결(고정 8) quota 거부 | 해당 없음(프레임 없음) | 해당 없음 | `conn.close(CLOSE_CODE_RESOURCE_EXHAUSTED = 0x1003, b"at capacity")` — proof를 읽지 않고 즉시 종료, protocol.md §10-2/§15.5의 non-distinguishing 규율상 no-match와 구별되지 않아야 하므로 프레임을 쓰지 않는다 | **3b 완료**(`serve_connection` outer, pairing 분기) |

`qsh.cli/v1`·`qsh.event/v1` 계약은 3a에서 한 글자도 바뀌지 않았고 3b도 마찬가지다. `Response.Error`는
이미 `RESOURCE_EXHAUSTED`를 실을 수 있었다. 여기서는 새 발신자(터널·listener·연결 quota)가 그 기존
표현을 재사용할 뿐이다. `RESET_CODE_RESOURCE_EXHAUSTED = 0x200D`는 `TCP_CONNECT` 계열 stop code
0(검토 P3-15가 지적한 "peer가 dial 실패로 오독" 문제)을 없애려고 신설했다. `qsh-transport`는 이 값을
모른다. `qsh-core`가 `conn.close`/스트림 stop에 넘기는 리터럴일 뿐이다. `CLOSE_CODE_RESOURCE_
EXHAUSTED = 0x1003`도 같은 자리(연결 close 코드 상수 옆, `qsh-core::server`)에 나란히 둔다. 두 값
모두 `docs/design/protocol.md`에 additive로 등재됐다(M8 Step 3b 문서 스테이지가 마쳤다).

### 7. audit 창 구조 — admission과 공용 형태, 별도 인스턴스

`quota.rs`는 `admission.rs`의 `WindowState`/`AuditWindow`를 `pub(crate)`로 승격시켜 그대로
재사용한다(`Gate` 자체는 손대지 않는다). 창당(10 s) category별로 첫 건을 즉시 기록하고 요약 1행을
남긴다는 집계 규율은 같되, admission의 `windows`와 quota의 `windows`는 완전히 분리된 인스턴스다(같은
`Mutex` 아래 있지 않다). 닫는 경로도 admission과 같은 둘: ① lazy(다음 거부가 만료된 창을 만나면 그
거부가 요약을 만들며 새 창을 연다), ② bounded(`Server::run`의 주기 tick이 `flush_expired`를 부른다).
닫는 경로 ③은 `purge_connection`(연결 종료 시점에 그 연결이 연 창을 즉시 닫는다, §9)과 reverse
target arm의 자체 주기 tick(target.rs의 serve loop, accept-loop가 없는 그 arm에는 ②가 없으므로)
이다. ③은 정합 스윕에서 배선됐다(§한계, 정정).

`Gate::record_rejection`은 최대 2건(요약+신규 첫 건)을 함께 반환한다. `Quotas::record_rejection`은
설계가 요구한 `Option<AuditRecord>` 반환형에 맞추려고 그와는 다른 모양을 택했다. 정확히는 이런
형태다. 완전히 새 창이면 진짜 첫 건을 반환하고 창이 살아 있으면 카운터만 올린 뒤 `None`을 낸다.
창이 만료된 채 도착하면 옛 창의 요약을 반환하고 그 자리에서 새 창을 열되 이번 거부 자체는 새 창의
(계수 안 된) 첫 사건으로만 남는다. 창을 닫아 부피를 유계로 만드는 본연의 임무(지속 부하 아래)는
그대로 지킨다. 다만 그 만료 경계에 정확히 걸리는 고립된 거부 1건은 자기 자신의 audit 행을 얻지
못하고 이력만 남긴 채 사라질 수 있다. 지속 flood를 억제하는 대가로 이 트레이드오프를 감당했다.

### 8. 두 sketch의 케이던스 산식과 ADR-0009 근거 문면의 좁힘

**ADR-0009 근거 절의 문장을 좁힌다.** 원문: "검증된 peer는 sketch를 완전히 우회하므로(cap만 적용)
오탐의 영향 범위는 미검증 Initial로 국한된다"(`0009-admission-defenses.md:69`). P2-3이 검증된 축에
독립적인 sketch를 신설한 이상 이 문장은 더 이상 참이 아니다. 검증을 마친 peer는 미검증 sketch만
우회할 뿐, 자신의 sketch(검증된 축)는 새로 통과해야 한다. 정상 pinned peer가 sketch 충돌로
`refuse()`될 수 있다는 실패 모드가 이제 존재한다. ADR-0009가 명시적으로 배제해 둔 바로 그 모드다.
ADR-0010은 이 문장을 다음으로 좁힌다: "검증된 peer는 미검증 sketch를 우회한다. 자신이 속하는 검증된
sketch의 4행 독립 시드 오탐 확률은 아래 산식으로 유계다 — 영(0)이 아니라 무시 가능(negligible) 수준."

**잔여 오탐 확률(검증 축, 4행 재계산).** 두 sketch 모두 같은 모양(4행 × 1024열, 행별 독립 시드)이므로
계산도 동일하다. 정상 peer의 카운터가 억울하게 올라가려면 공격자가 정상 principal의 실제 dial과 같은
sketch 키(같은 /32 또는 /64)로 충돌하는 key를 4행 모두에서 동시에 맞혀야 한다. 한 행의 충돌 확률을
행당 버킷 수(1024)의 역수로 근사하면(균등 해시 가정, `RandomState`가 행마다 독립 시드이므로 행간
상관 없음) 행 하나 충돌 ≈ 1/1024, 4행 동시 충돌 ≈ (1/1024)⁴ ≈ 8.67 × 10⁻¹³이다. 지속 flood 물량이
V건이면 기댓값은 V × 8.67 × 10⁻¹³이다. 이 워크스페이스가 다루는 어떤 현실적 V(초당 수만
건이라도)에서도 무시 가능하다. 이 계산은 ADR-0009가 원래 미검증 sketch에 대해 이미 세워 둔 근거를 검증
sketch에 그대로 재적용한다. P2-3은 바로 이 독립성을 지키려고 별도 sketch 인스턴스를 썼다. 공유
sketch였다면 미검증 flood가 sketch 충돌을 통해 검증 축의 예산까지 깎을 수 있었다.

**두 축의 케이던스.** 정상 신규 연결 1건은 두 sketch에 각각 정확히 1건씩 적립된다. Retry 왕복
구조상 필연이다: 주소 검증 전의 최초 Initial이 미검증 sketch에 1건, Retry 왕복을 마친 뒤의 Initial이
검증 sketch에 1건. 두 축의 임계값이 동일(2 s epoch당 20건, 지속 10/s)하므로 정상 트래픽에서는 두 축이
같은 속도로 채워지고 어느 쪽도 먼저 걸리지 않는다. "한 소스가 지속 10/s로 dial할 때 두 축 모두
통과한다"(`one_source_dialing_at_a_sustained_rate_passes_both_axes_across_epochs`,
`admission.rs`)가 이를 고정한다. `validated_rate_threshold_matches_the_documented_sustained_rate`는
검증 축 단독·단일 epoch만 고정하므로 이 쌍둥이 관계의 근거가 아니다(M8 Step 3a 정합 스윕 F3
지적으로 정정). 갈라지는 지점은 ADR-0009 한계 절이 명시한 retry-token 재사용이다: 실제 주소를 쓰는
공격자가 왕복 1회로 얻은 토큰을 15 s 동안 재전송하면, 재전송은 이미 주소-검증된 상태로 도착하므로
미검증 sketch는 최초 1건 이후 전혀 건드리지 않는다. 검증 sketch에는 매 재전송이 1건씩 계속 쌓인다.
검증 축은 정확히 이 패턴 때문에 존재한다. 미검증 축 혼자서는 구조적으로 이 패턴을 볼 수 없다.
NAT(같은 /32 IPv4·같은 /64 IPv6) 뒤 동시 클라이언트 N명은 두 축 모두에서 같은 키를 공유한다. 각자의
개인 dial 빈도가 낮아도 합이 상한을 넘으면 두 축이 동시에 걸린다. 이는 미검증 축에 ADR-0009부터 있던
특성이고 검증 축 신설이 새로 만든 문제가 아니다.

### 9. 락 규율

**1차 규율: 제거 대상은 가드 밑에서 모으고 드롭은 가드 밖에서 한다.** `tickets.lock()` 안에서
`extract_tickets`(`server/mod.rs`)로 조건에 맞는 `Ticket`들을 `HashMap`에서 뽑아 별도 컬렉션에
담아 반환한다. 락을 놓은 *뒤에* 그 컬렉션을 드롭한다. 세 지점(`issue_ticket`·
`pending_tickets_for`의 만료분 정리, `purge_connection`의 연결 종료 정리)이 모두 같은 모양이다.
`remote_forwards`의 연결 종료 정리도 동일 패턴이다(`forwards.lock()` 안에서 모으고 락 밖에서
`abort()`). 뽑힌 `Ticket`은 내부에 `ExecPermit`이 들어 있을 수 있고 그 `Drop`이 `Quotas`의 락을
잡는다. 이 규율은 `tickets`/`forwards` 가드가 걸려 있는 동안 그 `Drop`을 절대 실행하지 말라고
요구한다.

**2차 방어선: `Quotas`의 `Mutex<QuotaState>`(`quota.rs:151`)와 `AuditWindow`의
`Mutex<WindowState>`는 admission의 `WindowState`와 동형이다. 최말단(leaf) 락이라 그 아래 다른
락을 잡지 않는다. `std::sync::Mutex`이므로 `.await`를 락 보유 중에 건널 방법 자체가 없다(타입으로
강제).** 1차 규율이 지켜지는 한 이 락 순서 보장은 쓰일 일이 없지만 두 규율은 서로 다른 것을
막는다. 1차는 다른 가드 밑에서 quota 락을 아예 타지 않는다는 배치 규율이다. 2차는 혹시 타더라도
락 순서 역전은 없다는 구조적 보장이다. 3b가 비최말단 락을 잠그는 `Drop`(예: 새
tunnel/connection permit)을 추가할 때, 그 신규 코드가 1차 규율을 안 지키더라도(가드 안에서
드롭) 2차 방어선 덕에 데드락은 나지 않는다. 다만 그 경우도 1차 규율을 지키는 쪽이 기본이다.

`purge_connection`은 `quota_housekeeping`(→ `Quotas::flush_expired`)도 함께 호출한다(design
§2.4 경로 ③). 이 호출이 연결 종료 시점에 그 연결이 열어 둔 쿼터 거부 창을 즉시 닫아 요약을 감사
로그로 내보낸다.

### 10. §6.4 이월 i·ix

verdict 판정 13을 그대로 따른다: i(bounded pull executor + `RESOURCE_EXHAUSTED`, 측정 512 천장)는
클라이언트 로컬 자원의 문제라 Step 3의 몫은 어휘 정합(`RESOURCE_EXHAUSTED`·`retryable: true`·
`details`를 로컬에서만 채운다)뿐이다. executor 상한 자체의 구현은 Step 5로 이월한다. ix(forward-
route live carrier·`-R` 자동 재발행)는 quota가 생성만 게이트하고 복구 의미론과는 직교하는 문제라
Step 5로 이월한다. 다만 3b의 permit 해제가 `purge_connection`에 묶여 있어 resume 뒤 재발행이
permit을 다시 얻을 수 있다. 이는 3b의 I6 계열 테스트가 확인한다.

## 근거

- 세션 수를 registry에서 파생시키는 결정(§3)은 ADR-0009의 "스푸핑 가능한 키로 자라는 자료구조 자체가
  DoS 표면"이라는 원칙과 다른 이유로 같은 결론에 이른다. 여기서는 스푸핑이 아니라 이중 진실(registry와
  별도 카운터가 어긋날 수 있는 상태)을 피한다. 별도 카운터는 매 open/close마다 두 곳을 일관되게
  갱신해야 한다. 그 중 한쪽만 갱신되는 편집이 가능해지는 순간(`concurrent_opens_
  never_exceed_the_cap`이 고정하려는 바로 그 성질) 정확성이 코드 리뷰에 의존한다.
- exec quota를 RAII permit으로 두는 이유는 정확히 그 반대다. exec 자원(자식 프로세스)에는 registry
  같은 단일 진실 저장소가 없고 ticket map·redeem 경로·정리 경로가 이미 여러 곳에 흩어져 있다. 그런
  자원에서는 값이 스코프를 벗어나면 반드시 해제된다는 타입 시스템의 보장이 모든 정리 경로가 explicit
  release를 잊지 않는다는 코드 리뷰의 보장보다 싸다.
- ACL을 quota보다 먼저 두는 순서는 임의가 아니다. 거꾸로 두면 미인가 principal의 요청이 quota 판정으로
  이 host가 지금 포화 상태인지를 관측하는 oracle이 된다. `docs/design/architecture.md` §6의
  "거부 문면 균일성" 원칙과 같은 이유다. 무엇을 노출하는지가 판정 자체보다 먼저 결정돼야 한다.
- wire 변경을 0으로 유지하는 이유는 ADR-0009의 §6 "기존 오류 코드를 유지, 사람용 메시지만 개선"과
  같다. `qsh.cli/v1`이 additive-only라는 계약(`CLAUDE.md`)은 새 실패 모드마다 새 코드를 만들라고
  요구하지 않는다. 기존 어휘로 표현 가능하면 그것을 재사용하라는 뜻이다. `RESOURCE_EXHAUSTED(retryable:
  true)`는 이미 `qsh.cli/v1`이 정의해 둔 정확한 의미("지금은 안 되지만 다시 시도하면 될 수 있다")와
  들어맞는다.
- 전역 연결 상한(`max_connections`)을 두는 이유: `Principal::User`는 CA 서명 SAN에서 유도되므로 CA를
  쥔 쪽은 이름을 무한히 만들 수 있다. principal별 상한만으로는 principal 카디널리티 자체에 대한 상한이
  없고 어느 자원 축에도 aggregate bound가 생기지 않는다. 모든 터널 스트림·listener·세션 open은 살아
  있는 연결을 전제하므로, 전역 연결 상한 하나가 나머지 축의 곱을 유한하게 만든다. 같은 이유로
  `max_exec`(전역 exec 상한, §결정 2)도 두었다. principal별 상한만으로는 서로 다른 principal 수만큼
  전역 자식 프로세스 수가 늘어날 수 있었다(§한계 옛 항목). 그 간극에, 세션이 `max_sessions`로 이미
  두고 있던 종류의 전역 유계를 exec에도 준다.
- `Broker::reserve_slot`은 `registry` 락 아래에서 검사와 in-flight 카운터 증가를 한 번에 끝낸다(§5).
  그 앞에 있던 비예약 fast path가 남기던 잔여 경합을 구조적으로 없애기 위해서다. 두 concurrent 호출이
  아직 안 찼다는 같은 스냅샷을 각자 읽고 둘 다 통과하는 창 자체가 없어야 `factory.create`가 실
  자원(PTY 포함)을 만들었다가 버리는 경로가 생기지 않는다. M8 Step 3a 정합 스윕(F5, main-session
  arbitration item 1)이 이 재구조화로 그 경합을 닫았다.

## 한계

- **(해소됨, M8 Step 3a 정합 스윕)** ~~`purge_connection`이 `Quotas::flush_expired`를 부르지
  않는다~~ — 정합 스윕에서 `purge_connection`이 `Server::quota_housekeeping`을 호출하도록(§9),
  reverse target arm이 자체 주기 tick을 두도록(§7 닫는 경로 ③) 배선했다. `reverse_target_flushes_
  the_per_principal_summary_on_the_periodic_tick`(`crates/qsh-testkit/tests/quota.rs`)이 target
  arm의 주기 tick 경로를 직접 고정한다.
- **(해소됨, F2 conformance)** ~~`Quotas::record_rejection`의 만료-경계 사건 손실~~ —
  `record_rejection`이 최대 2건(stale 창 summary + 새 창 first)을 반환하도록 정정되어 창이 막
  만료된 순간 도착한 고립된 거부도 자기 자신의 audit 행을 얻는다(§7).
- **(해소됨, 3b)** ~~exec quota는 principal 축만 있다~~ — `max_exec`(기본 256, 카테고리
  `quota_exec_host`)가 세션과 같은 전역 → principal 순서로 `reserve_exec`에 들어오므로 서로 다른
  principal 다수가 각자의 32 한도 안에서 발급해도 전역 미완료 `exec.run` 수 자체가 256을 넘지
  않는다.
- 검증 sketch의 잔여 오탐은 유계일 뿐 0은 아니다(§8). (1/1024)⁴의 사건이 실제로 벌어지면 정상
  pinned peer가 `refuse()`될 수 있다. 확률이 무시 가능하다는 것과 발생하지 않는다는 것은 다른
  주장이다. 재현되면 `validated_sketch_storage_pointers`(`#[cfg(test)]`)가 남긴 진단 통로로 원인을
  규명할 수 있다. 다만 프로덕션 재현 로그에서 어느 4개 키가 충돌했는지 사후 복원할 방법은 없다
  (ADR-0009의 설계 선택 그대로, sketch 자체가 카운터일 뿐 키를 보존하지 않는다).

## 후속

3b가 이 문서를 완성했다. 결정 표의 옛 "3b에서 완성 예정" 행 여섯(`max_exec` 포함)이 실제 구현으로
채워졌다. wire 매핑 표에는 `RESET_CODE_RESOURCE_EXHAUSTED = 0x200D`와 `CLOSE_CODE_RESOURCE_EXHAUSTED
= 0x1003`가 실제 상수로 등재됐고 `MAX_CONCURRENT_PAIRING_CONNECTIONS = 8`이 코드에 있다. `docs/
CLI.md`·`docs/design/architecture.md`·`docs/design/protocol.md`·`crates/qsh-proto/proto/qsh/wire/
v1.proto`도 M8 Step 3b 문서 스테이지에서 이미 갱신됐다(`crates/qsh-core/tests/quota_docs.rs`가
doc-contract로 고정).

이 문서는 M8 Step 3b 마감 커밋에서 `docs/adr/`에 배치됐고 `docs/adr/README.md` 색인에 등재됐다. §6.4 이월
i·ix(이 문서의 §10)의 소유 스텝은 `PLAN.md` §6.4 표가 Step 5로 적고 있다.
