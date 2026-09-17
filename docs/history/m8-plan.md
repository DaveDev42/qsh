# M8 계획 — Hardening (감사 기록)

M8 실행 계획 원문이다. 2026-09-16에 main이 `PLAN.md`를 M9 계획으로 교체하면서 M8 본문을 남기지 않았으므로, 2026-09-15에 M8 계획으로 정리해 둔 판본을 그대로 여기에 둔다. 새 판정을 여기에 덧붙이지 않는다. M8에서 열린 채 넘어간 DoD 넷(M8 DoD 2·3·4, M7 DoD 1)은 `PLAN.md` §0.2(M9판)가 들고 있고, M8 마감 판정은 그 넷이 닫힐 때 `docs/ROADMAP.md`에 적는다. 옛 `§6.0–§6.5` 인용의 대응표는 바로 아래 문단에 있다.

M7 계획을 `docs/history/m7-plan.md`로 옮기고 M8 계획을 본문으로 올렸다(2026-09-15). 구속 근거: `docs/ROADMAP.md` M8 절(범위·감사 개정 ①②③④·DoD·적대적 부하 하네스), §3 유예 가드레일 표의 M8 소유 행, §4 리스크 1·4·5, `docs/design/protocol.md` §7(터널 무상한 갭)·§15, `docs/PRD.md` SC3/SC7. 이 계획과 `docs/ROADMAP.md`의 편집은 main 세션 전용이다.

M7 잔여 두 건은 여기서 사라지지 않는다. DoD 1 스톱워치 3회와 SC7 예약은 사람이 해야 하는 항목이라 `docs/ROADMAP.md` M7 절이 계속 들고 있고, 근거 문서는 `docs/campaigns/m7-stopwatch.md`와 아래 §1이다.

**절 번호 대응.** 옛 §6.0–§6.5를 인용한 문서가 있어 적어 둔다 — §6.0→§1, §6.1→§2, §6.2→§3, §6.3→§4, §6.4→§5, §6.5→§6. `PLAN.md M5 Step 3`처럼 마일스톤을 붙인 인용은 그 마일스톤 판본을 가리킨다: M7판은 `docs/history/m7-plan.md`, M2–M6판은 git 이력에 있다.
## 1. 착수 전 에스컬레이션 — SC7

`docs/history/m7-plan.md` §5.6은 "SC7이 계속 미완이면 M8 착수 전 운영자 에스컬레이션 필수"라고 정했고, M8을 여는 지금이 그 시점이다. 상태를 있는 그대로 적는다.

- **외부 보안 리뷰 예약은 M5→M6→M7 3연속 미완**이다. 저장소 안에서 완결할 수 없는 조직 액션이라 에이전트가 대신할 수 없다.
- 조건은 ROADMAP §4 리스크 5: 리뷰 시작 ~6주 전에 wire format을 freeze한다. **지금 예약해도 freeze는 이미 리뷰 일정을 밀어내는 쪽**이다 — 리드타임이 남아 있지 않다.
- 결과적으로 남는 선택지는 둘뿐이다. (가) 지금 예약하고 wire freeze(§3 Step 7)를 예약일 기준 6주 전으로 앞당긴다. (나) 예약 없이 freeze만 진행하고 리뷰를 M9로 미룬다 — 이 경우 SC7은 릴리스 게이트에서 빠지므로 PRD 개정이 따라야 한다.
- **판단은 운영자 몫**이고 코드 작업으로 대체되지 않는다. 이 항목이 미해결인 채로 §3 Step 7(wire freeze)을 넘기지 않는다.

## 2. DoD 체크리스트 (ROADMAP M8)

- [x] **DoD 1 — fuzz**: parser 타깃당 누적 ≥72 fuzz-hours 무crash. 기록은 `docs/campaigns/m8-fuzz.md`(타깃 16개 전부가 대상; Step 7b의 stateful `broker_ops`는 분모 밖, 같은 문서 §8). **2026-09-11 마감** — 배치 2(나머지 8종) 72 h 완료·crash 0(09-10), 배치 1(decode_* 8종)은 실효 59.1~65.6 h에 보충 회차 `m8-fuzz-20260910-1505` 13 h를 더해 72.1~78.6 h·crash 0(09-11). 판정은 Step 1 (a)의 종료 기록과 캠페인 문서 §5.
- [ ] **DoD 2 — soak**: 24h/100-session에서 idle listener ≤30MB, 세션당 buffer ≤8MB, 사이클 중 fd 무증가(누수 0; steady 4등분 성장 ≤ +2, boot→idle 일회성 warm-up은 정보성).
- [ ] **DoD 3 — 실기기 mobility**: Wi-Fi↔테더링 ≥60회(macOS+Linux) 자동 유지+resume ≥95%, migrated/resumed 분해 보고. 통과 기준은 사전 정의(idle timeout에 기대지 않는 2초 내 재dial). **사람이 실행한다.**
- [ ] **DoD 4 — wire freeze 후 독립 리뷰 계약** (SC7 — §1 참조). 문면 초안은 완료(Step 7, 2026-09-10, `protocol.md` §16 "초안 — 발효 전") — 발효와 리뷰 계약은 §1 판정 대기.
- [x] **DoD 5 (감사 개정) — 적대적 부하 하네스**: 스푸핑 Initial flood·대량 연결·principal당 세션 폭주 각각에서 선언된 상한이 실제로 강제되고, 부하 중·후 idle listener RSS/fd가 soak과 같은 bound를 지키며, 기존 세션의 PTY echo가 살아 있음. **2026-09-08 마감** — Step 4a·4b·4c, 커밋 2f52958. 판정과 실측은 Step 4의 (a)-추기 세 블록에 있다.

## 3. 실행 단계 (PR 단위)

### Step 1 — fuzz 인프라: 타깃 + corpus + CI smoke

`crates/qsh-proto`가 CLAUDE.md가 지목한 fuzz 표면이다. DoD 1이 벽시계 시간을 요구하므로 M8에서 가장 먼저 세운다.

- 제약: `rust-toolchain.toml`이 stable 1.97.1로 고정돼 있고 cargo-fuzz는 nightly가 필요하다. `fuzz/`를 워크스페이스 **밖**(자체 빈 `[workspace]` 테이블)에 두어 기존 게이트 6종을 건드리지 않는다. `xtask arch`는 워크스페이스 멤버만 순회하므로 영향이 없다 — 추론이 아니라 실행으로 확인한다.
- 타깃 단위는 **파서 표면 단위**다. DoD가 "타깃당" 시간을 세므로 타깃 집합 자체가 계약이다.
- corpus seed는 기존 테스트·fixture의 실제 값에서 뽑는다.
- CI는 결정적인 `-runs=` 고정 횟수 smoke만 돌린다. 72시간 누적은 CI가 아니라 §4의 별도 실행이다.
- 완료 기준: 전 타깃 build+run, libFuzzer 커버리지 카운터가 seed 이상으로 움직임, 게이트 6종 불변.

**(a)-추기 — Step 1 착륙 판정 (2026-09-02).**

착륙물: `fuzz/`(워크스페이스 밖, 자체 빈 `[workspace]`) 타깃 16종 + curated seed 110 파일 + `.github/workflows/fuzz-smoke.yml` + `fuzz/README.md`. 타깃 구성 — 바이트 디코더 8(`frame_decoder` 상태 기계, `decode_control`·`hello`·`exec_frame`·`session_frame`·`stream_header`·`connect_result`, `decode_local_hello`·`local_admin_request`), 문자열 파서 5(`parse_invite_code`·`parse_forward_spec`·`fingerprint_principal`·`valid_host_name`·`valid_forward_id`), 술어 1(`sanitize_peer_text`), JSON 1(`json_request_types` — MCP `arguments`→`types::*Req` 12종, selector byte). `cargo metadata`로 워크스페이스 비멤버 확인, `xtask arch` OK — 추론이 아니라 실행 결과다.

1라운드 조사(3분할, 후보 26개) → 구축(14 타깃) → 검증 2건 병렬. 실행 검증은 14 타깃 전부를 빈 corpus에서 50k runs 돌려 cov 0→N(최소 38, 최대 902)을 확인했고 dud 0. 적대적 리뷰 6항목 중 채택 4: ① `ConnectResult` 디코더 누락(`tunnel/local.rs:518`, `-L` dial 응답을 티켓 없이 wire에서 바로 읽는 유일한 스트림) → 타깃 추가. ② MCP 인자 JSON 역직렬화 미커버(`mcp/mod.rs:411`) — 구축 에이전트가 "JSON은 in-repo 파스 지점 없음"이라 제외했는데 그 근거가 이 경로엔 안 맞았다 → 타깃 추가, `SessionAttachReq`는 MCP 라우팅이 없어 제외(grep으로 확인). ③ corpus 정책 — 측정 실행이 체크인 디렉터리에 2,498개 SHA1-이름 파일을 써넣어 8.3 MB로 불었고 README는 "grown corpus를 유지하라"는 반대 정책을 적고 있었다. 판정: **체크인은 curated seed만, 장기 실행은 쓰기용 grown dir을 첫 인자로**(libFuzzer는 첫 corpus dir에 쓴다) → 2,498개 삭제, README 정책 재작성, 72h 레시피의 하드코딩 14-이름 루프를 `$(cargo fuzz list)`로. ④ CI matrix 14-leg가 같은 크레이트를 14번 sanitizer 빌드하고 타깃 추가 시 조용히 누락 → 단일 job + `cargo fuzz list` 루프 + 실패 수집 후 non-zero exit. 리뷰의 "구축 보고가 corpus 리셋을 거짓 주장" 지적은 병렬 검증의 경쟁 산물(실행 검증 에이전트가 자기 run으로 다시 불렸다고 스스로 보고)이라 사실 판정은 기각, 정책 결정은 그대로 채택. false target·input mapping 지적 0건.

2라운드 검증: 신규 2 타깃 빈 corpus 50k runs cov 0→269 / 0→826, selector 12종을 `mcp/mod.rs` `tool::<…Req>()` 등록과 교차 대조해 일치, `actionlint` 통과, corpus 110 파일·40-hex 이름 0개, 게이트 6종 green(nextest 1342 불변).

main 세션 독립 검증: `frame_decoder`(바이트 보존 단언이 `HEADER_LEN`=4와 일치, `Err` 후 조기 반환은 "oversize 헤더 이후 복구 불가" 계약과 정합, payload 선할당은 명시 단언 대신 rss 상한이 담당)·`fingerprint_principal`·신규 2건을 직접 읽음. 변이 검사 2건 — **MUT-F1** `next_frame`에 `len == 0x1337` panic 주입 → `frame_decoder`가 120 s 캡 안에 검출, 아티팩트 오프셋 6에 `00 00 13 37`(seed에 없는 값을 변이로 합성 — 타깃이 파서에 닿는다는 실증). **MUT-F2** `sanitize_peer_text`에 `ESC [` panic 주입 → `decode_connect_result`가 즉시 검출, 단 아티팩트가 ANSI seed 그 자체라 seed-hit(crash 표면화 경로의 증명이지 탐색력의 증명은 아님). 두 파일 모두 cp 백업과 바이트 동일 복원, `crates/` diff 0줄.

의도적 미커버(기록): `SessionEvent`·`ErrorCode`의 JSON `Deserialize` — 워크스페이스 안에 비테스트 파스 지점이 없다(직접 grep 확인). `resume.rs:375-408`의 salvage JSON 파서 — 로컬 파일이고 qsh-proto 밖이라 이번 타깃 집합 밖, 단 fuzz가 결함을 잘 찾는 모양의 코드라 Step 5(soak)에서 재검토.

CI 마감(`d87e76b`): CI run 33601462030 11 job 전부 success(`test (windows-latest)` 포함 — 로컬에서 미검증으로 남긴 G6를 CI가 확인), fuzz-smoke run 33601462001 success, step 로그에서 16 타깃 전부 `Done 4096 runs`, crash/`SUMMARY:` 0건. **Step 1 마감.**

다음: 이 커밋을 push한 뒤 fuzz 호스트(Dave-Windows-WSL, 8 vCPU / 31 GB, cargo-fuzz 0.13.2 설치 완료)에 clone하고 72 h 시계를 돌린다. 16 타깃 × 72 h를 8 코어로 돌리면 2 배치 = 최소 144 h 벽시계.

**72 h 시계 시작 기록.** 커밋 `d87e76b`, 호스트 Dave-Windows-WSL, run-id `m8-fuzz-20260902-1600`, 시작 2026-09-02T16:01:37+09:00, 16 타깃을 8 워커로 2 배치(`-max_total_time=259200 -rss_limit_mb=1536`, grown corpus는 `~/fuzz/grown/<t>`를 첫 인자로 두어 체크인 seed는 읽기 전용). 1차 배치 종료 예정 09-05 16:01, 2차 배치 종료 예정 09-08 16:01 이후. 기동 직후 실측: `decode_control` 7.1M execs / 170k exec/s / cov 1873 / RSS 541 MB, load 6.2, 가용 메모리 16 GB. 로그·exit 코드는 호스트 `~/fuzz/logs/m8-fuzz-20260902-1600/`. DoD 1 판정은 `exits.txt`의 16행 전부 `exit=0`이고 어떤 로그에도 `SUMMARY:`/`deadly signal`/`Test unit written`이 없을 때.

**72 h 시계 경과 기록 (2026-09-07).** 1차 배치(decode_* 8종)는 09-05 새벽 호스트(WSL VM) 재시작으로 끊겼다. `exits.txt`에 exit 행이 없고 launcher도 함께 죽었다. 로그 마지막 수정 시각으로 센 타깃당 실효 시간은 59.1~65.6 h(부족분 6.4~12.9 h), 실행 수는 2.0B(`decode_control`, 큰 입력이라 8.6k exec/s)~44.8B, crash·artifact 0, OOM 없음. grown corpus는 `~/fuzz/grown/<t>`에 1.3~13 MB로 남았다. 2차 배치(fingerprint_principal, frame_decoder, json_request_types, parse_forward_spec, parse_invite_code, sanitize_peer_text, valid_forward_id, valid_host_name)는 커밋 `ab8a82f`, run-id `m8-fuzz-20260907-1450`, 시작 2026-09-07T14:47:53+09:00으로 돌고 있고 종료 예정은 09-10 14:48이다. `run72.sh`가 둘째 인자로 타깃 파일을 받게 고쳐 부분 집합을 돌린다. 2차가 끝나면 1차 부족분을 grown corpus에서 이어 타깃당 약 13 h 더 돌려 DoD 1을 닫는다. 누적 fuzz-hours 정의상 이어 돌린 시간은 유효하다. 09-05 재시작 원인은 미확인이다(Windows 업데이트 추정).

**72 h 시계 경과 기록 (2026-09-10).** 2차 배치(`m8-fuzz-20260907-1450`)가 09-10 14:47:55에 끝났다. `exits.txt` 8행 전부 `exit=0`(각 259,202 s), 어느 로그에도 `Test unit written`·`deadly signal`·`SUMMARY:`가 없고 artifact 파일도 없다. 실행 수는 31.6B(`frame_decoder`)~139.1B(`valid_forward_id`), exec/s 121.9k~536.7k, peak RSS 517~782 MB(`-rss_limit_mb=1536` 아래). 1차 부족분은 같은 날 15:05:21에 `m8-fuzz-20260910-1505`로 이어 돌리기 시작했다. 대상은 decode_* 8종, 커밋 `ab8a82f`(2차와 같은 빌드), `-max_total_time=46800`(13 h, 최대 부족분 12.89 h를 덮는 균일값), grown corpus는 첫 인자로 그대로 재사용. 런처는 `run72.sh`에서 `git pull`을 뺀 `run-cont.sh`. 종료 예정 09-11 04:05이고, 그때 `exits.txt` 8행 `exit=0`과 로그 엄격 grep 0건이면 DoD 1이 닫힌다. 타깃별 수치는 `docs/campaigns/m8-fuzz.md` §5.

**72 h 시계 종료 기록 (2026-09-11).** 보충 회차(`m8-fuzz-20260910-1505`)가 09-11 04:05:23에 끝났다. `exits.txt` 8행 전부 `exit=0`(각 46,802 s), 어느 로그에도 엄격 grep 4종이 없고 artifact 파일도 없다. 실행 수는 1.4B(`decode_control`)~13.9B(`decode_connect_result`), exec/s 29.1k~297.5k, peak RSS 512~795 MB(`-rss_limit_mb=1536` 아래). 누적은 배치 1 실효 59.1~65.6 h + 13.0 h = 72.1~78.6 h/타깃이라 최소값도 72 h를 넘는다. 16 타깃 전부 누적 ≥72 fuzz-hours·crash 0 — DoD 1을 §2에서 닫았다. 타깃별 수치는 `docs/campaigns/m8-fuzz.md` §5 "배치 1 보충".

### Step 2 — 적대적 부하 방어선 ①②: 주소 검증 + accept 상한

감사 개정 ①②. 인터넷에 직접 노출되는 데몬에 현재 방어선이 없다.

- `Incoming::retry()` 주소 검증 — 스푸핑 Initial 1패킷당 상태 생성 차단.
- accept 동시성 상한 + source rate limit.
- 초과는 거부이며 **자원 생성 전에** 결정한다(CLAUDE.md: 인가 성공 전 자원 생성 금지와 같은 규율).

**(a)-추기 — Step 2 설계 판정 (2026-09-02).** 조사 3분할(44 facts) → opus 설계 제안(scratchpad `step2-design.md`, 21k자)을 다음과 같이 판정한다.

현행 확인: `Listener::accept`(`qsh-transport/src/endpoint.rs:700`)는 `quinn::Incoming`을 그대로 `accept().await` — retry/refuse/ignore/`remote_address_validated` 호출 0건. `bind_inner`(`:670`)는 `max_incoming`·`incoming_buffer_size(_total)`·`retry_token_lifetime`을 quinn 기본(65536 / 10 MiB / 100 MiB / 15 s)으로 둔다. `Server::run`(`server/mod.rs:1854`)과 **`Listen::run`(`reverse/listen.rs:3442`) — 인터넷 노출 accept 루프가 둘**이고 둘 다 무상한 spawn. `quinn::Incoming` drop은 암묵적 `refuse()`라 "침묵"은 반드시 명시 `ignore()`. NEW_TOKEN은 `default-features=false`로 bloom이 꺼져 있고 IP 바인딩이라 mobility에 무용 — 계획에서 제외.

| 결정 | 판정 | 근거 |
|---|---|---|
| 계층 | transport = 메커니즘 노출(`remote_address_validated`/`may_retry`/`retry`/`refuse`/`ignore` + bind 상한), core `admission::Gate` = 결정·config·audit | 아키텍처 매트릭스. `AdmissionPolicy` trait을 transport에 넣는 대안은 config·audit·상태를 glue에 끌어들여 기각 |
| Retry 트리거 | **무조건**(`!remote_address_validated()`이면 항상) | 부하 게이트는 신호가 오르기 전에 이미 키 유도·10 MiB 버퍼 상태를 만든다(부트스트랩 문제). 포화 대응은 한 층 아래 quinn `max_incoming`이 담당. 비용은 신규 연결당 1 RTT, migration 무영향 — m2 캠페인 지배 항이 OS 경로 재수립 4–5 s라 몇 % 수준. **판정은 M8 ≥60회 캠페인**. 부하 게이트 Option B는 escape hatch로만 기록, 구현 안 함 |
| Retry audit | 없음 | Retry는 거부가 아니라 프로토콜 challenge — audit하면 그게 ④의 audit flood |
| 동시성 상한 | handshake 중인 연결 수를 `Semaphore` `try_acquire_owned`로(localctl `MAX_CONCURRENT_LOCALCTL_HANDSHAKES` 선례), 상한 도달 시 `refuse()`, `[serve].max_concurrent_handshakes` 기본 64, `0`=기본값(끄는 설정 없음) | 이 지점에 오는 peer는 주소 검증됨 → 빠르고 구별 가능한 실패가 맞다. `ignore()`는 정상 클라이언트를 10 s 타임아웃까지 방치, accept-후-close는 TLS 전체를 지불 |
| source rate limit | **count-min sketch**(4행×1024열×2세대 `AtomicU32`, 32 KiB 고정), 키 IPv4 /32·IPv6 /64, `[serve].handshake_rate_per_source` 기본 10/s burst 2×, 초과 시 `ignore()`. **추가 요구: 행별 독립 시드 해시**(공격자가 정상 source와 충돌하는 키를 사전 계산 못 하게) | 스푸핑 가능한 키로 자라는 테이블(LRU HashMap)은 그 자체가 DoS 벡터이고 flood 하에서 eviction이 정상 항목을 밀어낸다. 검증된 peer는 sketch를 우회하므로 충돌 오탐은 미검증 Initial에만 걸린다 |
| 순서 | L0 quinn 사전 차단 → L1 accept → L2 미검증이면 rate-limit(초과 ignore / 통과 retry) → L3 검증됨이면 semaphore(실패 refuse) → L4 spawn·TLS | 거부 경로 어디서도 task·연결·세션·fd 생성 없음 |
| audit | `AuditRecord::handshake_rejected` 재사용, category `rate_limited`/`at_capacity`, **`count: Option<u32>` 필드 추가**(additive, `skip_serializing_if`), 창(10 s)당 category별 "첫 건 즉시 + 요약 1행" 집계, `tracing::warn!`도 같은 억제 | ④ 연쇄 차단. architecture.md:87 필드 목록 동일 PR에서 갱신. `resource` 문자열에 count를 접붙이는 대안은 어휘를 열거 불가로 만들어 기각 |
| 오류 표면 | `DialError::Refused`(`ConnectionClosed(0x2)`) 신설, **`ErrorCode::ConnectionFailed` 유지**(retryable), 사람용 메시지만 개선. doctor 코드 추가 없음 | JSON `code`/`retryable` 불변 → `qsh.cli/v1` 무변경. doctor는 로컬 연산이라 원격 포화를 관측 못 함 |
| `receive_window: VarInt::MAX` | **Step 2로 흡수** — 유한값, DoD 2 "세션당 buffer ≤8 MB" 이하. 구체값은 `stream_receive_window`×동시 스트림 상한에서 도출해 근거와 함께 추기 | ROADMAP 감사 문장에 같이 있고, 이 step이 만지는 파일 한 줄 |
| `incoming_buffer_size(_total)` | **측정 선행** — accept를 고의 지연시켜 정상 mTLS handshake가 실제 버퍼하는 바이트를 재고 ≥8× 로 설정. 측정 불가면 quinn 기본 유지하고 기록 | 설계자 스스로 "숫자를 눈감고 고르지 말라" |
| `qsh listen` 루프 | 같은 `Gate` 타입, `[serve]` 값 상속(`[listen]` 별도 키 없음) | 누가 요구하기 전까지 |
| config 문서 | CLI.md §6.12 인라인 bullet 2개(`[serve]` 표는 없음 — 기존 관행), architecture.md:95 config map 갱신 | additive |
| ADR | **ADR-0009 작성** — retry-always·/64 키·"0=기본값, off 없음"·audit 집계. 에이전트가 scratchpad에 초안, main 세션이 검토 후 `docs/adr/`에 배치 | 재론이 아니라 신규 결정이지만 미래 세션이 찾을 자리가 필요 |
| Step 3 훅 | `server/mod.rs:1041`(session open)·`:2532`/`:2626`(tunnel/rfwd authorize) — ACL allow 뒤, 자원 spawn 전. slow-loris(handshake 후 established 무상한)도 Step 3 | 기록만 |

테스트(설계 §8 그대로): transport 4(`fresh_incoming_is_unvalidated`·`retry_forces_a_validated_second_incoming`·`retry_on_validated_incoming_errs`·`server_config_sets_admission_bounds`), core 단위 6(cap/permit 해제/창 회복/ipv6 /64/**forged cardinality 하 상수 크기**/오탐률 <1 %), 통합 4(`admission_cap_refuses_and_creates_nothing`·`legitimate_client_connects_after_flood_subsides`·`admission_rejection_audit_is_aggregated`·`spoofed_initial_flood_creates_no_state` — loopback은 source IP를 못 바꾸므로 키 검증은 단위 테스트 몫이라는 한계 명시). 지속 flood·RSS/fd bound·quota 상호작용은 Step 4.

**(a)-추기 — Step 2 검증 라운드 판정 (2026-09-02, main 세션).** 구현 증분 15 M + 2 신규(`admission.rs` 721줄, `qsh-testkit/tests/admission.rs`), 신규 테스트 18건(1342→1360), 게이트 6종 green, 적합성 검토 무이탈. `incoming_buffer_size`는 지연 accept 측정 4,800 B(5/5 재현)에 13.6× 여유로 64 KiB. opus 적대적 검증(변이 14건 주입·전건 `cmp` 원복, 트리가 구현자 파일 목록과 일치) **11/14 검출 — 방어선 셋이 무증상으로 지워지고 pin 하나가 순환**. 여기에 main 세션 자체 발견 2건(F1·F2). **P1 3 / P2 3 / P3 7 + 가설 3 — 커밋 불가, 수정 라운드.** 판정:

1. **P1-1 `Listen::admit` 무커버리지(M6b 생존: gate를 통째로 우회해도 1151/1151 통과)** — 이행. `ReverseHarness`(`qsh-testkit/src/reverse.rs`)가 실제 `Listen::run`을 돌리므로 쓸 수 있었던 테스트다. Listen 상한 거부 + audit 통합 테스트 신설. `write_admission_audit`의 두 사본(`server/mod.rs`·`listen.rs`)은 한 정의로 합친다 — 독립적으로 변이 가능한 계약 사본을 두지 않는다.
2. **P1-2 L2→L3 순서 미고정(M4 생존: 미검증 peer가 permit을 먼저 잡아도 951/951)** — 이행. cap=0에서 미검증 peer는 `Retry`(`Refuse` 아님)이고 `available_permits()`가 불변인 단위 테스트. 이 순서가 스푸핑 flood의 permit 고갈과 위조 주소로의 `CONNECTION_REFUSED` 반사를 막는 유일한 장치다.
3. **P1-3 요약 행 미검증(M7b 생존) + F1 lazy flush** — 이행, 한 묶음. 현행은 요약을 "다음 거부가 창 만료 뒤에 도착할 때"만 내보내므로 flood가 멎으면 마지막 창의 count는 영원히 안 나온다 — 운영자가 가장 보고 싶은 순간이 빠진다. `Gate::flush_expired(now) -> Vec<AuditRecord>` 신설, 두 accept 루프가 `select!` 주기 tick(`AUDIT_AGGREGATION_WINDOW`)마다 호출하고 루프 종료 시 1회 더. 창 상태는 `Mutex<WindowState { start, suppressed }>` 하나로(P3-4의 원자 카운터 drift 동시 해소). 테스트: `TestClock` 단위(거부 n건 → 창 경과 → 요약 1행, `count = n-1`, `peer_addr = "-"`), 통합 2(Server·Listen 각 1 — flood 중단 후 요약 행이 창+여유 안에 파일에 나타남, 상한 20 s 폴링).
4. **F2 rate 의미론(main 세션)** — 이행. `EPOCH = 1 s`·임계 `rate × 2`는 슬라이딩 창 위에서 **지속 20/s를 통과**시킨다 — CLI.md의 "기본 10/초, burst 2배"와 어긋난다. `EPOCH = 2 s`, 임계 `rate × EPOCH.as_secs()`(= 20): 지속 10/s, 순간 최대 20. 문서·ADR 문면도 그렇게. 회복 테스트는 flood 중단 후 2×EPOCH 대기, probe 간격 ≥ EPOCH. reconnect 케이던스(`REDIAL_DEADLINE` 2 s, 3회 ≈ 7 s에 dial ≤3)는 임계와 한 자릿수 차이라 무관.
5. **P2-1 bind 상한 pin이 순환(M12 생존: 생산 경로의 setter 셋을 지워도 991/991)** — 이행. 테스트가 `ServerConfig`를 자기 손으로 다시 만들어 그 Debug 문자열을 단언하고 있었다. `pub(crate) fn server_config(...)` 단일 생성 지점을 `bind_inner`와 테스트가 같이 호출.
6. **P2-2 `INCOMING_BUFFER_SIZE_TOTAL`이 quinn 기본 100 MiB와 동일(무효)** — 이행. retry-always로 Incoming은 accept 루프 한 반복 안에서 동기 해소되므로 합계 버퍼는 루프가 바쁜 찰나에만 자란다 — 100 MiB를 DoD 2의 idle-listener 30 MB 옆에 둘 수 없다. **16 MiB 명시**(64 KiB × 256). 상한 초과 시 quinn 동작(drop/refuse)은 fixer가 vendored 소스로 확인해 주석과 ADR에 적는다.
7. **P2-3 Retry 토큰 15 s 재사용 → 검증된 시도의 rate는 아무것도 안 막는다** — **Step 3 입력**, Step 2 범위 밖. 실 주소의 공격자가 1 RTT로 토큰을 얻어 15 s 동안 재사용하면 sketch를 우회해 permit 64개를 놓고 경합한다. 검증 peer에 sketch를 다시 걸면 L3 의미(Refuse 대상)가 바뀌고 그건 쿼터 step의 설계 대상이다. 회귀 아님(Step 2 이전보다 엄격히 낫다), 증폭 없음(주소가 실제). `retry_token_lifetime`은 quinn 기본 유지. ADR 한계 절 + Step 3 항목에 명기.
8. **P3-1 dead code(`RejectReason::as_index`, `Index<RejectReason> for [AuditWindow; 2]`)** — 삭제. 3번의 `WindowState` 개편에 흡수.
9. **P3-2 `connection_receive_window_never_exceeds_the_roadmap_dod_bound`가 `min(x, 8 MiB) ≤ 8 MiB`(M11에서 안 울림)** — 삭제, ≤8 MiB 단언은 실제 pin(`transport_config_sets_connection_receive_window`)에 합친다.
10. **P3-3 `rate_limited` 첫 행의 `peer_addr`는 주소 미검증** — 코드 유지, 문서화. 와이어 관측값이라 구조 정보이고 pcap 대조에 필요하다. CLI.md §6.12·ADR에 "rate_limited의 peer_addr는 미검증 주소 — 발신자 증명이 아니다"를 명기.
11. **P3-4 창 카운터 drift** — 3번에 흡수.
12. **P3-5 코드 주석 8곳이 아직 없는 ADR을 가리킴** — main 세션이 그 이름 그대로 `docs/adr/0009-admission-defenses.md`에 배치. 코드 무변경.
13. **P3-6 chaos 하네스(`accept_observed`)가 gate 우회** — 의도된 seam, 유지. retry-always × 경로 단절(M2 시나리오)은 **Step 4 입력**.
14. **P3-7 `spoofed_initial_flood_creates_no_state`는 quinn AEAD drop 검증**(M1·M4 하에서도 통과) — `host_survives_garbage_initial_flood`로 개명, doc comment에 "gate 커버리지 아님"을 명기. host 안정성 테스트로는 유효하니 파일은 유지.
15. **H1 `measure_incoming_buffered_bytes_during_delayed_accept`의 `measured × 8 ≤ 64 KiB`는 벽시계 의존**(측정 4,800 = PTO 재전송 4회, 단언 여유 1.7×) — 단언을 `0 < measured ≤ INCOMING_BUFFER_SIZE`로. 그것이 이 설정의 실제 의미(정상 클라이언트를 굶기지 않는다)다. 8× 여유는 측정값과 함께 주석으로. H2(주석이 공격 여유처럼 읽히는 문제 — 실제로는 정상 클라이언트 기아 여유)도 같은 주석에서 바로잡는다.
16. **H3 §6.12 어휘 doc 대조 테스트 부재** — 이행. `doctor_docs.rs` 선례대로 `admission_docs.rs`: category 2종·config 키 2종·기본값이 CLI.md에 있는지.

수정 라운드 규율은 전과 같다 — 변이 원복은 `cp` 백업 + `cmp`, PLAN/ROADMAP/adr 무편집(ADR 초안은 scratchpad에서 갱신), 게이트 6종 green + nextest 수치, fixer는 반박 가능. 마감 후 main 세션이 위험 diff(두 루프 배선·`WindowState`·`server_config`)를 직접 읽고 독립 변이 1건 이상 찍는다.

**(a)-추기 — Step 2 수정 라운드 마감 (2026-09-03, main 세션).** 수정 라운드는 fixer(sonnet, 반박 가능)가 16항목을 전부 이행했고 적합성 검토(opus)는 16/16 무이탈. 게이트 6종 green, nextest 1360→1366(+2 skipped). 바뀐 것: `Gate::flush_expired`와 `Mutex<WindowState>`로 창 상태를 한 곳에 모음, 두 accept 루프의 `select!`에 주기 tick(10 s)을 두고 루프 종료 시 flush 1회 더, `EPOCH = 2 s`·임계 `rate × 2`, `pub(crate) fn server_config` 단일 생성 지점, `INCOMING_BUFFER_SIZE_TOTAL` 16 MiB(quinn은 합계 초과 시 새 Incoming을 drop — `quinn-proto-0.11.16/src/endpoint.rs:218-227`), `write_admission_audit` 한 정의(`audit.rs:304`), Listen 상한·집계 통합 테스트, `admission_docs.rs`, `host_survives_garbage_initial_flood` 개명, H1 단언 `0 < measured ≤ INCOMING_BUFFER_SIZE`. P2-3·P3-6은 Step 3·4 항목에 이월 입력으로 적었다.

적대적 검증 2라운드(opus, 변이 17건). 1라운드 생존 4건(M4·M6b·M7b·M12)은 전부 검출. 신규 변이 가운데 N1–N5·N8·N9·N11·X1 검출, **N6(루프 종료 flush 삭제)·N7(16 MiB→100 MiB)·N10(`suppressed` 미초기화)·X3(permit을 연결 종료까지 보유) 4건 생존**, X2(lazy 요약 push 삭제)는 하네스 중단으로 미완. 검증자가 X2 도중 "[Request interrupted]"로 재시작돼 처음부터 다시 돌기 시작했기에 main 세션이 워크플로를 정지시키고 트리를 백업(`mut3/`)과 `cmp`·diff sha로 대조한 뒤 전임자 transcript로 표를 확정했다(`step2-adversarial-2.md`). 생존 4건은 모두 코드는 맞고 pin이 없는 종류라 수정 대신 pin 라운드로 돌렸다.

pin 라운드(sonnet). 단위 1건 `gate_record_rejection_and_flush_expired_both_reset_suppressed_not_just_report_it`(N10 두 초기화 경로 + X2), `server_config_sets_admission_bounds`에 리터럴 단언 3개(N7: 16 MiB·64 KiB·4096), 통합 3건 — `admission_permit_is_released_at_handshake_end_not_connection_end`(X3), `admission_on_exit_flush_reports_suppressed_rejections_at_shutdown`과 그 Listen 쌍둥이(N6). 변이 6건(N10a·N10b·X2·N7·X3·N6×2) 전건 FAIL 뒤 원복 PASS. N6 테스트는 첫 판이 틀렸다: `tokio::time::interval`은 첫 tick을 즉시 발화해 tick이 t0·t0+10·t0+20에 오는데, 즉시 dial하면 창 만료점(t0+ε+10)이 두 번째 tick과 밀리초 차라 스케줄링 지터가 결과를 정했다(계측으로 확인, 변이 생존). 첫 dial을 4 s 늦춰(`WINDOW_OPEN_DELAY_FROM_LOOP_START`) 창을 t0+4에 열고 t0+15.5에 종료하니 양쪽 여유가 4 s 이상이다. 느린 머신에서 종료가 늦어지면 세 번째 tick이 대신 flush해 통과하므로 flaky가 아니라 판별력만 잃는 방향. X3의 Listen 쌍둥이는 `ReverseHarness::start_with_admission`이 빈 trust store를 고정해 mTLS 연결을 못 만들어 생략(테스트 doc에 명기, 하네스 시그니처 변경은 별건). 3 crate nextest 1001 passed / 2 skipped.

main 세션 검토. 두 루프 배선(`accept()` 단일 await의 취소 안전성, `select!` 브랜치 셋, 종료 시 flush→drain→close→wait_idle), `WindowState` 로직(mutex 아래 `.await` 없음), `server_config`, 하네스 `start_with_admission` 두 벌을 직접 읽었다. 독립 변이 스팟체크 2건(X3: `drop(permit)`을 `serve_connection` 뒤로 / N6-Listen: `Listen::run` 종료 flush 삭제) — 둘 다 변이 상태에서 FAIL(`admission.rs:621`·`:764` 단언), `cp` 원복 뒤 PASS, 트리는 `mut4` 백업과 `cmp` 일치. ADR-0009는 `docs/adr/0009-admission-defenses.md`에 배치하고 README 색인에 추가했다(초안은 humanize-korean light 경로로 다듬음 — 볼드 48→16, 코드 식별자·수치 무변경). 최종 게이트 6종 green, nextest 1370 passed / 2 skipped(1366→1370, pin 4건). 커밋 후 CI green이 Step 2 마감이다.

CI 마감(`1b34912`): CI run 33667720455 success, fuzz-smoke run 33667720360 success(2026-09-03). Step 2 Done.

### Step 3 — 적대적 부하 방어선 ③: 세션·터널 쿼터

- `[serve].max_sessions`, principal별 세션 쿼터.
- **터널 전용 할당량** — principal별·forward별 동시 `TCP_CONNECT` 스트림 수, remote-forward listener 개수 상한. `docs/design/protocol.md` §7이 명시하고 M4·M5 어느 쪽도 만들지 않은 무상한 갭을 여기서 인수한다.
- 초과는 `RESOURCE_EXHAUSTED`(CLI.md §3.3 기정의 어휘 — 새 코드를 만들지 않는다).
- **Step 2 이월 P2-3** — Retry 토큰은 15 s 재사용 가능해 검증된 시도의 rate는 sketch를 우회한다(실 주소 공격자가 1 RTT로 토큰을 얻어 permit 64개를 놓고 경합). 검증 peer 기준 rate·쿼터와 `retry_token_lifetime`을 여기서 설계한다. ADR-0009 한계 절 참조.

**(a)-추기 — Step 3 설계 판정 (2026-09-03, main 세션).** 조사 3분할(`step3-facts-A/B/C.md`, 132 facts) → opus 설계(`step3-design.md`, 48k자) → opus 적대적 검토(`step3-critique.md`, P1 4·P2 10·P3 4)를 판정한다. 검토의 사실 주장은 main 세션이 코드에서 다시 확인했다(`is_connection_refused`는 `ConnectionClosed` 0x2만, `CLOSE_CODE_REPLACED = 0x1003`, `AcceptDisposition::Fatal => return`, `Broker::open`/`open_with`의 우회, `fixtures.rs`의 `DEFERRED`, stop code `_ => 0`).

설계의 뼈대는 채택한다: 전부 `qsh-core`, 세션 계수는 broker registry 파생(별도 카운터 금지), 쿼터 지점은 `Broker::open_as` 첫 줄(`factory.create` 앞), 터널 permit은 스플라이스 수명, listener permit은 `RemoteForwardEntry` 소유, wire 변경 0(`Response.Error`·`ConnectResult.code`가 이미 `RESOURCE_EXHAUSTED`를 실을 수 있다), `retryable: true` 통일, `0`=기본값, audit는 `quota_*` category로 첫 건 + 요약(창 구조 공용화·인스턴스 분리), reverse target은 `host_runtime` 상속을 테스트로 고정, P2-3은 검증된 주소 축의 별도 sketch를 permit 앞에, `retry_token_lifetime`은 quinn 기본 유지, ADR-0010 신설. 설계의 중재 요청 10건은 2·3·4·6·7·8·9를 권고안대로 수용하고 1·5·10은 아래처럼 고쳐 수용한다.

1. **커밋 분할(중재 1)** — 수용. 3a: 세션 쿼터 + exec 상한 + P2-3 검증 rate + config·문서 골격 + fixture. 3b: 터널 2종 + 연결 상한(전역·principal·pairing) + 나머지 문서. 각 커밋이 Step 2와 같은 리듬(구현 → opus 변이 검증 → 수정 → pin → main 검토·독립 변이 → 게이트 → 커밋 → CI)을 따로 돈다. ADR-0010 초안은 3a에서 scratchpad에 쓰고 3b 마감 때 main 세션이 배치한다. 코드 주석은 3a부터 `docs/adr/0010-resource-quotas.md`를 가리켜도 된다(Step 2 선례).
2. **연결 상한의 거부 표면(검토 P1 1·2·3)** — 설계 §2.2의 `CLOSE_CODE_AT_CAPACITY` + `DialError::Refused` 합류는 기각. 0x1003은 이미 `CLOSE_CODE_REPLACED`이고 그 시점엔 QUIC handshake가 끝나 `dial()`이 `Ok`를 돌려준 뒤라 `classify_dial_failure`가 돌지 않는다. `handshake::respond`의 거부 콜백(reverse 등록 거부 선례 `server/mod.rs:2093-2100`, `REJECTION_DRAIN_TIMEOUT`으로 프레임 전달 보장)에서 `wire::Error::new(ErrorCode::ResourceExhausted, …, true)`를 돌려준다. 클라이언트는 `map_hello_error`로 `RESOURCE_EXHAUSTED`·`retryable: true`를 그대로 보고 transport 변경은 0이다. permit은 pairing 분기 뒤·`local_hello` 전송 전에 획득하고 `purge_connection` 뒤에 놓는다(설계 §2.3의 순서 그대로). 이로써 pairing 계수 모순(P1 1)도 사라진다.
3. **전역 연결 상한(검토 P2 7)** — 설계 §2.6의 이월을 기각하고 이번 스텝(3b)에 넣는다. `Principal::User`는 CA 서명 SAN에서 오므로 CA를 쥔 쪽이 이름을 무한히 만들 수 있고 principal별 상한만으로는 어느 축에도 aggregate bound가 없다. `[serve].max_connections` 기본 512(전역, established·인증 완료 기준). 모든 터널 스트림·listener·세션 open은 살아 있는 연결을 요구하므로 이 하나가 나머지 축의 곱을 유한하게 만든다 — ADR-0010 결정 근거에 "CA posture 하에서 principal 카디널리티는 무한"을 명기하고 §2.1 메모리 상한 논증을 이 상한 위에 다시 쓴다.
4. **pairing 연결(검토 P2 8)** — 면제 근거를 "`PAIRING_TIMEOUT`(10 s) ×2로 유계"로 정정하고 고정 상수 `MAX_CONCURRENT_PAIRING_CONNECTIONS = 8`(config 키 없음)을 둔다. 초과는 아무것도 만들지 않고 거부하며 표면은 pairing respond 경로의 거부 콜백이다. 미검증 상대가 열 수 있는 유일한 연결 클래스를 무상한으로 두지 않는다.
5. **exec 동시성(검토 P2 5)** — 3a에 `[serve].max_exec_per_principal` 기본 32를 넣는다. 티켓 예산은 미상환분만 세므로 상환 루프에서 principal당 자식 프로세스가 무상한이다. 순서는 ACL → 쿼터 → spawn, 계수는 살아 있는 자식(RAII permit, 자식 회수 시 drop), category `quota_exec_principal`. 키는 8개가 아니라 9개다: `max_sessions` 256, `max_sessions_per_principal` 32, `max_exec_per_principal` 32, `max_tunnel_streams_per_principal` 256, `max_tunnel_streams_per_forward` 64, `max_remote_forwards_per_principal` 16, `max_connections_per_principal` 32, `max_connections` 512, `validated_rate_per_source` 10.
6. **터널 키 크기(검토 P2 6)** — 모양 검사에 host 길이 ≤ 255를 추가(`InvalidArgument`, `RESET_CODE_BAD_HEADER`). 불변식 문면은 "엔트리 수 ≤ 상한 그리고 키 크기 ≤ N바이트". dial 타임아웃 동안 permit이 살아 있는 것은 의도다 — in-flight dial도 fd 후보라 세야 한다.
7. **listener 자기종료 누수(검토 P2 9)** — `serve_remote_forward`가 `Fatal`로 끝날 때 자기 엔트리를 registry에서 지우는 경로(oneshot 또는 완료 감시)를 넣고 U11에 "fatal accept로 listener가 죽은 뒤 재개방 가능"을 추가한다. EMFILE에서 자기유발 영구 거부가 되는 경로를 남기지 않는다.
8. **락 규율(검토 P2 10)** — ADR-0010에 못 박는다: 쿼터 락은 최말단, 그 아래 다른 락 없음, `.await` 금지(Step 2 `WindowState`와 동형). `purge_connection`은 제거한 엔트리를 `Vec`에 모아 가드 밖에서 drop한다.
9. **stop code(검토 P3 15)** — `RESET_CODE_RESOURCE_EXHAUSTED` 신설(기존 `RESET_CODE_*`·hub `0x200B`와 겹치지 않는 값), protocol.md §7 코드 표에 등재, I4가 값을 단언한다. 0으로 떨어뜨리면 peer가 쿼터 거부를 dial 실패로 읽는다.
10. **ADR-0009 근거 문면(검토 P3 16·17)** — ADR-0010에 "0009 근거 절의 '검증된 peer는 sketch를 우회한다' 문장을 좁힌다"를 결정으로 적고 4행 독립 시드의 잔여 오탐 확률을 검증 축에서 다시 계산한다. 정상 dial 1건 = 두 sketch 각 1건 산식과 NAT /32 뒤 동시 클라이언트 가정을 함께 적고 U18 쌍둥이로 "한 소스가 지속 10/s로 dial할 때 두 축 모두 통과"를 고정한다.
11. **테스트 추가(검토 P2 12·13·14, P3 18)** — ① `saturated_quota_still_answers_permission_denied_to_an_unauthorized_principal`, `quota_rejection_still_leaves_the_acl_allow_audit_line`(ACL → 쿼터 순서 pin). ② `Broker::open`/`open_with`를 공통 예약 헬퍼로 재구현하고 "세 진입점 모두 `factory.create` 전에 예약"을 U3 쌍둥이로. ③ `detached_session_still_holds_quota`. ④ `admission_docs.rs`를 `RejectReason::ALL` 순회로 바꾸고 `validated_rate_per_source` 키·기본값 단언 추가, CLI.md §6.12의 "미검증 Initial의 source당" 문장 정정. 설계 §4.7의 구현자 직접 변이 4건(U3·U15·I4·I10)에 U11 fatal 케이스와 순서 pin ①을 더한다.
12. **fixture(검토 P2 11)** — `error.RESOURCE_EXHAUSTED.json` 추가는 `fixtures.rs`의 `DEFERRED` 항목 제거·`REQUIRED_FIXTURES` 등록·`max_sessions_per_principal = 1` config를 세운 Sandbox golden 1건을 수반한다. 변경 파일 표에 넣는다.
13. **§5 이월 i·ix(검토 P1 4)** — i(bounded pull executor + `RESOURCE_EXHAUSTED`, 측정 512 천장)는 클라이언트 로컬 자원이라 Step 3의 몫은 어휘 정합(`RESOURCE_EXHAUSTED`·`retryable: true`·`details`는 로컬에서만)뿐이고 executor 상한 자체는 ii·iii(호출당 런타임·fd 증가)와 같은 변경이므로 Step 5로 보낸다. ix(forward-route live carrier·`-R` 자동 재발행)는 쿼터가 생성만 게이트하고 복구 의미론과 직교하므로 Step 5로 보낸다 — 단 3b의 permit 해제가 `purge_connection`에 묶여 있어 resume 뒤 재발행이 permit을 다시 얻을 수 있음을 I6 계열 테스트가 보인다. §5 표의 소유 step을 이 판정대로 고친다.
14. **Step 4 인계** — 설계 §5의 인계 목록에서 전역 연결 상한 항목은 빠지고(3b에서 이행), 나머지(지속 부하 RSS/fd bound, principal당 폭주 하 PTY echo 최종 판정, audit 부피 실측, P3-6 케이던스 겹침, listener당 동시 accept 무상한)는 그대로 Step 4다.

구현 규율은 Step 2와 같다 — 변이 원복은 `cp` 백업 + `cmp`, PLAN/ROADMAP/adr 무편집(ADR 초안은 scratchpad), 게이트 6종 green + nextest 수치 대조, fixer는 반박 가능, 마감 후 main 세션이 위험 diff(예약 헬퍼·permit 수명·거부 콜백·락 순서)를 직접 읽고 독립 변이 1건 이상 찍는다.

**(a)-추기 — Step 3a 구현 라운드 판정 (2026-09-03, main 세션).**

구현은 단일 구현자로 시작했다가 네 번 죽었다. 코드가 아니라 컨텍스트가 원인이었다. 누적 도구 출력이 340~500 KB에 이르면 다음 요청이 정확히 180초 뒤에 끊기고 런타임이 에이전트를 다시 띄우는데, 그 반복이 네 번을 넘기자 워크플로우를 멈췄다. 이후 작업을 S1~S5 다섯 단계로 쪼개고 단계마다 읽기 예산을 200~250 KB로 못 박은 뒤 PROGRESS.md로 인수인계하게 했다. 이 형태로는 한 번도 끊기지 않았다. 같은 규율을 이번 판정 뒤의 fixer에도 적용했다.

정합 스윕(F1~F10)은 10건 전부 고쳤다. main 판정 라운드는 아홉 항목을 닫았다. 세션 열기 전에 슬롯을 먼저 예약하는 in-flight `SessionSlot`(항목 1), 티켓 스윕 세 지점의 "가드 아래 수집, 밖에서 drop"(항목 2), exec 경로에서 ACL을 티켓 예산보다 앞세운 것(항목 3), `record_rejection`이 오래된 창의 summary와 새 first 행을 최대 두 건 함께 돌려주는 것(항목 4), `purge_connection`과 reverse target 주기 틱의 flush 배선(항목 5), 그리고 reverse 틱 테스트·ADR §9 재작성·ENOENT e2e·LEAK 20회 루프·문서 갱신(A~E)이다. 판정 5는 한 가지를 고친다. 쿼터 키는 아홉이 아니라 열이다. 호스트 전역 `[serve].max_exec`(기본 256, 범주 `quota_exec_host`)를 열 번째로 두되 구현은 3b로 넘긴다.

적대적 라운드는 opus 둘이 사설 복사본에서 돌렸다. A(보안 순서·자원 수명)가 아홉 건, B(동시성·케이던스·계약)가 열두 건을 냈고 두 쌍(A4=B3, A5=B8)이 겹쳤다. 기각은 없다. 실제 코드 결함은 셋이다. `session.open`이 아직 ACL보다 먼저 티켓 예산을 검사하고 있었고(A1, exec에만 고쳤던 것), reverse target의 SIGTERM arm이 마지막 감사 창을 flush하지 않고 돌아갔으며(B5), exec 거부가 "session quota exceeded"라는 메시지를 달고 나갔다(B7). 나머지는 전부 핀 공백이다. 기존 동시성 테스트가 current-thread 런타임이라 실제로는 직렬로 돌았다는 A3가 대표적인데, main이 독립으로 넣은 변이(in-flight 카운트 무시)도 쿼터 계열 34건을 모두 통과해 같은 공백을 확인했다. 작은 코드 변경 둘은 `as u32` 절단 제거(A8)와 만료 티켓을 하우스키핑 틱에서도 스윕하도록 한 것(A9)이다. 판정 전문은 스크래치패드 MAIN-ARBITRATION.md에 있다.

fixer는 네 단계로 돌렸다. 두 번째 단계가 도구 호출 125회 즈음에 다시 끊겨 런타임이 세 번 재시작했는데, 워크플로우를 멈추고 트리에 남은 것을 main이 직접 목록으로 만들어 인수인계 파일에 적은 뒤 남은 몫만 주고 재개했다. 결과는 판정 21건 전부 반영이고 이탈은 하나다. session.open의 티켓 예산을 exec처럼 드레인 게이트 앞이 아니라 attach처럼 뒤에 두었는데, ACL이 먼저라는 성질은 셋 다 같으므로 그대로 둔다. 새 테스트는 열다섯이고 그중 넷은 변이로 죽는 것을 확인했다. in-flight 예약을 지우면 경쟁 테스트가 2 대 1로 실패하고, 티켓 스윕을 retain으로 바꾸면 트립와이어가 위반 4건을 세며, host_runtime의 from_serve를 default로 바꾸면 config 기반 exec 테스트가 실패하고, CLI.md §6.12 문장을 지우면 문서 테스트가 실패한다. main은 F2의 종료 arm·하우스키핑·트립와이어와 브로커 예약·exec permit·감사 창 코드를 직접 읽었다. 락 순서는 registry→in_flight, tickets→quota로 한 방향이다.

nextest는 베이스라인 1370에서 main 판정 라운드 종료 시 1415, 적대적 fixer 뒤 1430 passed / 2 skipped다. 게이트 여섯은 fixer 4단계에서 첫 실행에 전부 rc=0이었다. quota 스위트를 main이 다섯 번 더 돌렸더니 LEAK 표지가 한 번, 이번엔 `exec_run_past_the_quota_answers_resource_exhausted_end_to_end`에서 나왔다. 하네스는 자식 프로세스를 만들지 않으므로 B11이 짚은 클라이언트 엔드포인트 해체가 원인의 전부는 아니다. Step 4의 부하 하네스 항목에 nextest LEAK 원인 규명을 넣는다.

CI는 2e5d581에서 한 번 빨갰다. testkit quota 테스트의 `FramedStream` import가 unix 전용 테스트에서만 쓰여 Windows clippy가 미사용 import로 잡았고, 같은 런의 Windows test 잡은 install-action의 bash 시작 실패였다. import를 그 테스트 안의 전체 경로 호출로 바꾼 0e1a4aa에서 CI와 fuzz-smoke가 모두 green이다. 로컬 G6 게이트는 core와 cli만 win-gnu로 check하고 있었으므로 workspace 전체 win-gnu clippy를 추가해 같은 구멍을 로컬에서 먼저 잡는다. Step 3a는 여기서 닫는다.

**(a)-추기 — Step 3b 구현 라운드 판정 (2026-09-04, main 세션).**

구현은 3a의 교훈대로 처음부터 열 스테이지(S1·S2·S2E·S3·S3E·S4·S4E·S5·S6·S7)로 쪼개 순차로 돌렸고 스테이지마다 도구 호출 70회를 넘기지 못하게 하고 PROGRESS-3b.md로 인수인계했다. 착수 전 개방질문 일곱(Q1~Q7)을 main이 먼저 판정했고(R1~R7), 진행 중에 둘이 더 생겼다. S2가 터널 거부의 `request_id`에 0을 넣은 것은 실제 id와 구별되지 않아 `Option<u64>`로 바꾸고 `None`을 `"-"`로 적게 했다(R9). S3가 쓴 Fatal 자기제거 테스트는 tokio가 쥔 listener의 fd를 `libc::close`로 직접 닫아 EBADF를 유도했는데, 이중 close와 Windows clippy 적색이 겹쳐 기각하고 `run_remote_forward_accept_loop`를 future 제네릭으로 바꿔 즉시 끝나는 future와 `pending()` future로 자기제거를 고정했다(R10). S3는 그 테스트가 실제로 걸려 한 번 멈췄고 판정 뒤 재개했다.

판정 중 설계에 남는 것은 넷이다. pairing 초과 거부는 proof를 읽지 않고 프레임도 쓰지 않은 채 `CLOSE_CODE_RESOURCE_EXHAUSTED`(0x1003)로 즉시 닫는다(R2). 상한이 막으려는 작업을 초과 연결에 쓰지 않는다는 원칙이고 protocol.md §15.5의 응답 규율 표는 proof 평가 뒤의 이야기라 손대지 않았다. 연결 permit은 outer `serve_connection`에서 inner 진입 전에 얻고 `purge_connection` 뒤에 놓는다(R3). `max_connections`의 "전역"은 프로세스가 아니라 inbound accept arm 단위다(R6). `qsh serve`의 accept 루프와 `qsh listen` 컨트롤러가 각각 512를 갖고 reverse target이 listener로 거는 outbound 연결은 세지 않는다. 그 수는 operator가 정한 listener 수라 peer가 늘릴 수 없기 때문이다. `quota_rejected` 감사행의 `peer_addr`는 첫 건 행에 실값을 적고 요약 행만 `"-"`로 남긴다(R4).

적대적 라운드는 3a와 같이 opus 둘이 사설 복사본에서 돌렸다. A(보안 순서·자원 수명)가 다섯 건, B(동시성·케이던스·계약)가 열세 실험에서 아홉 건을 냈고 기각은 없다. 실제 코드 결함은 하나뿐인데 둘 다 찾았다(A2=B5). `Listen::decide_registration`이 quota 거부를 ACL 판정보다 먼저 돌려줘서 인가되지 않은 peer도 컨트롤러가 가득 찼는지를 응답 코드로 알 수 있었다. 거부 검사를 `admit()` 뒤로 옮겨 idle이든 full이든 미인가 peer는 `PERMISSION_DENIED`만 본다. 나머지는 핀 공백이다. permit이 되돌아오는 행동 테스트가 세 arm 모두 없었고(A1), `purge_connection` 뒤에 permit을 놓는다는 순서가 소스 텍스트 트립와이어로만 고정돼 있어 `drop(permit.take())`를 앞에 끼워도 살아남았다(B3). B3는 텍스트 테스트를 지우고 permit을 `purge_connection(conn_id, held)`의 값 인자로 넘겨 타입이 순서를 강제하게 했다. 그 밖에 `remote_forwards` 락의 `NonLeafGuard`(A4), 감사행 `peer_addr`·`request_id` 필드 단언(B1·B2), `Listen::run` 틱의 flush 회귀 테스트(B4), 터널 축 거부는 `ConnectResult`라 `retryable` 필드가 없다는 문서 정정과 quota_docs 핀(B6), 알 수 없는 `[serve]` 키가 조용히 무시된다는 문장(B7), testkit 대기 여유값의 `AUDIT_WINDOW_SLACK` 통합(B9)이다. B8의 stress 실측은 결함 없음이다.

fixer는 다섯 단계(F0~F4)로 돌렸다. F0는 판정 전에 생겼다. 첫 전체 게이트에서 reverse_tunnel의 두 테스트가 새 remote-forward 상한(기본 16)에 걸렸는데, 그 테스트들은 parked claim 상한 32까지 한 principal로 forward를 연다. main은 컨트롤러 `Listen`의 quota를 올리라고 지시했지만 F0는 `reserve_remote_forward`의 유일한 production 호출처를 따라가 실제 게이트가 target 쪽 `Server`임을 보이고 하네스 헬퍼가 target의 `[serve]` 설정을 덮어쓰게 했다. 그때 fail-fast가 뒤의 97건을 가렸으므로 게이트 스크립트에 `--no-fail-fast`를 넣었다. F3는 B2의 묶음을 반박했다. main은 remote-forward 축의 `request_id`를 `"-"`로 묶었지만 `authorize_and_bind_remote_forward`가 `Some(request_id)`를 넘기므로 control 요청(세션·exec·remote-forward)은 실제 id, 데이터 스트림과 연결 축만 `"-"`가 맞고 R9 원문도 그렇다. 반박을 수용해 실제 동작대로 핀을 박았다. pairing 축은 in-crate 감사행 테스트가 없어 B1·B2 핀을 못 박았고 Step 4로 넘긴다. F4는 A·B의 변이 다섯을 다시 넣어 전부 죽는 것을 확인했다. 그중 B3 변이는 컴파일 오류(E0382)로 죽는다. 새 테스트는 qsh-core 846→851, testkit 212→213이다.

main은 위험 diff(예약 헬퍼·permit 수명·거부 콜백·락 순서)를 직접 읽고 변이 둘을 찍었다. principal별 비교를 off-by-one으로 바꾼 것은 두 테스트가 잡았다. `decide_registration`의 거부 분기에서 `registry.rollback`을 지운 것은 살아남았다. F2가 개명한 `..._without_registering` 테스트가 `registry().get("adv-fixer")`를 봤는데 `admit()`이 등록하는 키는 offered name이 아니라 핀된 device name(`"laptop"`)이라 단언이 공허했다. 단언을 `snapshot().is_empty()`로 바꾸고 살아 있는 등록 한 건을 `conns.publish`로 올린 뒤 거부된 재등록이 그 행을 같은 generation으로 되돌리는지도 같은 테스트에 넣었다. 처음엔 `conns`를 안 올려 `rollback_target`의 phantom-host 가드가 행을 지웠는데, 그건 3b 결함이 아니라 기존 설계다.

문서는 ADR-0010을 `docs/adr/0010-resource-quotas.md`로 배치하고 CLI.md §6.12·protocol.md 코드 표·architecture.md를 갱신했다. Step 4로 넘기는 것은 넷이다. `deny_unknown_fields` 채택 또는 `qsh doctor`의 unknown-key 경고, pairing testkit 하네스 공용화와 pairing 축 감사 핀, nextest LEAK 원인 규명(B가 한 번 본 `846 passed (1 leaky)` 포함), 그리고 remote-forward 기본 상한 16이 testkit의 parked claim 상한 32보다 작아 테스트가 설정을 덮어써야 한다는 관계다.

nextest는 3a 마감 1430에서 1473 passed / 2 skipped다. 게이트 여섯은 F0 뒤 두 번째 전체 실행에서 전부 rc=0이다. CI는 74a728f에서 CI·fuzz-smoke 둘 다 첫 실행에 green이다. Step 3b는 여기서 닫는다.

### Step 4 — 적대적 부하 하네스 (DoD 5) + audit 수명주기 부하 검증

협조적 soak과 **별도 게이트**다. 감사 개정 ④의 연쇄(스푸핑 flood → 세션 없는 audit 쓰기 → 디스크 만실 → resume 실패)가 차단되는지를 본다. Step 2·3이 선언한 상한이 실제로 강제되는지를 이 하네스가 판정한다.

- **Step 2 이월 P3-6** — retry-always × 경로 단절(chaos 하네스 `accept_observed` seam, M2 시나리오): Retry 왕복 중 경로가 끊길 때 재시도·reconnect 케이던스가 rate 임계와 어떻게 겹치는지.

**(a)-추기 — Step 4 설계 판정 (2026-09-04, main 세션).** 조사 3분할(`step4/facts-A/B/C.md`) → opus 설계(`step4/design.md`, 266줄) → opus 적대적 검토(`step4/critique.md`, P1 5·P2 7·P3 5)를 판정한다. 판정 전문은 스크래치패드 `step4/ARBITRATION-4.md`(J1~J17)에 있다.

설계의 뼈대는 채택한다. PR 게이트에는 in-process 축소판(T1)만 두고 실측(RSS/fd/echo p95/audit 부피, T2)은 서브프로세스 `qsh serve`를 잰다. 신규 config 키는 0이다. 검토가 뒤집은 P1 다섯은 전부 수용한다. 시나리오 1의 source 64개 × 1회는 rate 임계(10/s × 2 s epoch = 20)를 못 넘겨 아무 거부도 나오지 않으므로 source 8개 × 40회로 뒤집는다. 시나리오 2의 64 동시 dial은 한 source라 quota보다 admission에 먼저 걸리므로 config로 두 rate 키를 200으로 열어 quota 축만 잰다. T1 시나리오 2는 admission과 quota를 함께 받는 하네스 생성자가 없어 하나 추가한다. P3-6 시나리오는 LoopbackHarness에 제품 재연결 루프가 없어 resume_chaos 형태로 다시 짜고 migration을 끈다. RSS 30 MB 임계는 debug가 아니라 release 바이너리에 건다.

설계와 검토가 같이 틀린 곳이 하나 있다. 둘 다 `-R` listener의 accept가 무상한이어도 QUIC 스트림 상한 1024가 유계를 준다고 봤다. 그 상한은 스트림만 막고 accept된 TCP fd와 태스크는 EMFILE까지 쌓인다. `accept_disposition`은 EMFILE을 Backoff로 분류하므로 listener는 살지만 프로세스 fd가 바닥난다. `-R` 포트는 인증 없이 도달할 수 있는 유일한 자원 생성 경로다. ADR-0010의 원칙대로 accept 직후 `open_bi` 전에 기존 터널 스트림 permit(`max_tunnel_streams_per_forward` 64·principal별 256)을 예약하고 거부면 TCP를 즉시 닫는다. 새 키도 wire 변경도 없다. ADR-0010에는 "forward별"의 `-R` 정의를 추기한다.

나머지 결정은 이렇다. T2는 acceptance job이 아니라 별도 워크플로 `load.yml`(fuzz-smoke와 같은 지위, `ci-ok` 비의존, push main + dispatch)에서 release 빌드로 돈다. testing.md가 절대 수치를 필수 경로에 두지 말라고 적었기 때문이다. echo 임계는 같은 실행 baseline p95의 3배 또는 50 ms 중 큰 값이다. T1의 echo는 PTY가 아니라 pipe라 그렇게 부른다. 감사 개정 ④ 연쇄는 창 주기마다 category당 2 × (min(principal 수, 64) + 1)행 상계(닫힌 창은 요약 뒤 삭제, category당 principal 창 64개 + overflow 1개)와 회전·retention 부피 유계 두 겹으로 고리 1–2 사이에서 끊기고 degraded audit 하 attach 거부는 의도된 fail-closed로 문서에 적는다. `deny_unknown_fields`는 CLI.md 계약 위반이라 기각하고 doctor `config_unknown_key`는 손목록 없이 round-trip 키 차집합으로 Step 4에서 넣는다. pairing 하네스는 testkit으로 승격해 감사 핀 2건을 박는다. nextest LEAK은 실험 3종을 돌리고 `leak-timeout`을 명시한다. reverse Listen 축은 T1 축소판 1건을 더하고 T2는 forward listener만 잰다.

라운드는 셋이다. 4a는 in-process 하네스와 핀(leak-timeout, 하네스 생성자, T1 6건, P3-6 케이던스 2변형, pairing 승격·핀), 4b는 강제 공백 2건(`-R` accept permit, doctor unknown-key)과 문서, 4c는 실측 T2와 load.yml·캠페인 문서다. 각 라운드가 Step 2·3과 같은 리듬을 따로 돈다.

**(a)-추기 — Step 4a 구현 라운드 판정 (2026-09-04, main 세션).**

4a는 설계 판정의 첫 라운드로, in-process 하네스(T1)와 유닛 테스트만 다뤘다. 산출은 `LoopbackHarness::start_with_admission_and_quotas`, `PairingHarness`(pairing_loopback.rs의 사설 `PairingHost`를 qsh-testkit/src/pairing.rs로 승격, 보류 pairing 연결 n개 헬퍼 포함), quota.rs의 flood 하 echo 생존 테스트 3건(연결 flood·같은 principal 세션 flood·Listen 축 flood), pairing_quota.rs의 감사 핀 2건(peer_addr 실값, request_id "-"), server/mod.rs의 attach·write 두 축 fail-closed 테스트, admission.rs의 세대 롤오버 테스트, admission_retry_sever.rs의 재dial 케이던스 테스트와 ops/session.rs의 backoff 스케줄 유닛 테스트, .config/nextest.toml의 leak-timeout 명시다. 구현 워크플로우는 다섯 스테이지(S1 LEAK 실험·baseline, S2 하네스와 T1 테스트, S3 케이던스, S4 pairing 승격, S5 검증)로 돌았고 S5의 변이 4건 중 3건이 예측대로 죽었다.

적대 라운드는 opus 둘이 각자 사설 워크트리(HEAD 위에 4a diff 적용)에서 변이 실험을 하며 돌았고 둘 다 amber였다. 핵심은 S3가 넣은 프로세스 전역 재dial 플로어 `MIN_REDIAL_INTERVAL`이다. A는 8개 동시 호출 실험으로 그 플로어가 자기 doc이 약속한 동시 호출 직렬화를 하지 않음을 보였고(7개가 113ms에 함께 풀림), B는 전역 잠금이 다른 호스트로 붙은 세션까지 직렬화하고 그 대기가 `time_to_recovery_ms` 밖에 놓인다고 짚었다. main은 플로어를 철회했다. 그 상수의 존재 이유였던 "40회/4ms"가 `recover()`를 backoff 없이 맨손으로 도는 테스트 자신의 루프에서 나온 값이고 제품 경로 `recover_attach`는 `RecoveryConfig::backoff` 0/200/800ms로 이미 시도를 띄워 2초 창에 최대 4회만 들어가기 때문이다. J6의 조건은 제품 케이던스에 대해 판정했어야 했다.

그 밖에 수용한 지적. `authorize_owned`의 fail-closed 분기는 853개 테스트 어디에서도 검증되지 않았다(변이 생존) → write 축 테스트를 추가해 죽였다. 롤오버 테스트는 저장소 포인터와 permit만 보아 `Sketch::advance_to`를 통째로 끄는 변이가 살아남았다 → 홍수 한복판의 합법 source가 Retry이고 지속 source가 Ignore 됐다가 EPOCH 두 번 뒤 Retry로 복귀하는 단언을 더해 죽였다. pairing 하네스의 50ms 고정 sleep은 testing.md의 sleep 금지에 걸려 `Quotas` 핸들 폴링으로 바꿨다. 연결 flood는 순차 dial이라 마지막 슬롯 경합이 없었고 `JoinSet` 동시 dial로 바꿨다. echo 테스트 두 건의 무기한 await는 2s·5s timeout으로 감쌌다. `#![cfg(unix)]`는 근거가 없어 지웠고 `recover`의 rustdoc이 새 상수에 흡수된 사고는 상수 철회로 함께 해소됐다.

fixer의 반박은 전부 수용했다. qsh-testkit에 전방 경로 `Ops` 하네스가 없어(attach_recovery.rs는 qsh-cli에 있고 `qsh serve` 자식 프로세스를 쓴다) 제품 attempt 루프를 그대로 구동할 수 없으므로 e2e는 제품 진입점 `recover()`를 스케줄 간격으로 돌리고 스케줄 값은 유닛 테스트가 지키는 분할로 갔다. fast-fail e2e 변형은 관측 seam이 없어 두지 않았다. `admission::EPOCH`가 private이라 유닛 테스트 안에 값을 다시 세웠다. `futures`가 qsh-testkit 의존성이 아니라 `JoinSet`을 썼다. S5 반박 둘도 수용한다. J15의 M1 예측 대상은 `gate_state_and_permits_survive_generation_rollovers_under_sustained_forged_flood`가 아니라 기존 `validated_rate_rejection_never_dips_the_permit_pool_even_transiently`가 맞다. J12의 H1·H2 코드 실험은 0/115 재현 상황에서 정보를 주지 않고 `LoopbackHarness`는 자식 프로세스를 만들지 않아 nextest의 leaky 판정 경로가 성립하지 않으므로 "재현 불가, 기제상 성립 어려움"으로 닫는다. 3a의 1회 관측은 미해명으로 남긴다.

변이 실증은 S5 4건(M2·M5·M8 kill, M1은 예측 테스트 생존이나 crate 안 기존 테스트가 잡음), F1 3건(backoff 0, blackhole 제거, attempts 1), F2 2건(`|| recorded.is_err()` 제거, `advance_to` return), F4 독립 재현 3건, main 독립 1건(quota.rs `reserve_connection`의 `>=`를 `>`로 → 동시 flood 테스트가 admitted 1로 잡음)이다. CI 플레이크(run 33801780928, macOS test 잡)는 `abort_local`의 `set_zero_linger`가 보내는 RST가 비동기 connect의 writable 확인보다 먼저 닿아 connect 자체가 ECONNRESET을 돌려준 것으로, tunnel_loopback.rs와 tunnel/local.rs의 테스트가 그 모양도 거부로 허용하게 고쳤다. 재실행은 green이었다.

4b(-R accept permit, doctor `config_unknown_key`, architecture.md·CLI.md, ADR-0010 추기)와 4c(adversarial_load.rs, load.yml, 캠페인 문서, testing.md L9/L10, Dave-Windows-WSL 실측)는 설계 판정 그대로다. B가 남긴 "CI 3 OS의 신규 테스트 개별 시간"은 4a 커밋의 CI에서 읽어 4b 판정에 적는다.

게이트는 fmt, clippy -D warnings(host와 x86_64-pc-windows-gnu), xtask arch, cargo deny, nextest 1483 passed / 2 skipped(`--test-threads=1`, 934초)로 닫았다. win-gnu clippy가 한 번 빨갰는데, quota.rs의 Listen 축 테스트가 unix 전용 `Listen::control_hub`·`ConduitInbound`를 쓰는 탓이라 그 테스트에 `#[cfg(unix)]`를 달고 `wait_for` import를 함수 안으로 옮겼다. 커밋 3213796은 CI(run 33827723206)와 fuzz-smoke 둘 다 첫 실행에 green이다. Step 4a는 여기서 닫는다.

**(a)-추기 — Step 4b 구현 라운드 판정 (2026-09-07, main 세션).**

4b는 설계 판정의 둘째 라운드로, 강제 공백 두 건과 문서를 다뤘다. 첫째는 `-R` 리스너의 accept permit이다. `serve_remote_forward`가 accept 직후 `open_bi` 전에 `Quotas::reserve_tunnel_stream(owner, forward_key)`를 부르고 거부면 QUIC 스트림 없이 TCP를 닫으며 `quota_tunnels_forward`/`quota_tunnels_principal` 감사 행(request_id "-", peer_addr는 TCP peer)을 남긴다. owner는 등록 principal의 `opener_key`, forward_key는 `rfwd:` 접두어를 붙인 등록 `forward_id`다. permit은 splice 태스크 안으로 옮겨져 `accept_one`이 돌아올 때 반납된다. 둘째는 `qsh doctor`의 `config_unknown_key`(14번째 진단 코드)다. 손목록 없이 config.toml 원본의 리프 키 경로와 로드된 `Config`를 재직렬화한 리프 키 경로의 차집합으로 구하고 그러려고 `Config`와 다섯 섹션에 `Serialize`를 달았다(출력 경로 없음, 계약 무변경). 문서는 architecture.md 63행의 `-L`/`-R` 대칭 두 문단, CLI.md §6.12 불릿 둘과 doctor 진단 표 행, reverse_tunnel.rs 헬퍼 doc이다. 구현 워크플로우는 네 스테이지(S1 permit, S2 doctor, S3 문서, S4 검증)로 돌았고 S4의 변이 5건이 전부 죽었다.

적대 라운드는 opus 둘이 돌았고 둘 다 amber였다. P1 세 건이 핵심이다. B는 in-crate permit 테스트가 20회 중 4회 깨진다는 것을 보였다. `held.len()`을 즉시 단언하는데 permit 반납이 태스크 종료와 경쟁하기 때문이다. B는 또 "before any QUIC stream opens"라는 테스트 이름을 어떤 단언도 뒷받침하지 않는다고 짚었다. 예약을 `open_stream` 뒤로 옮겨도 그 테스트가 통과한다(E7). A와 B가 함께 doctor가 문서화된 serde alias(`resume_ttl_secs`)를 unknown으로 오탐한다는 것을 잡았다. 재직렬화는 정식 이름만 내므로 차집합에 alias가 남는다. P2로는 e2e가 permit 소유자 principal을 검증하지 않는 것, `-R`의 principal 축 테스트 부재, "RESET 없음/clean EOF" 문구가 바이트를 먼저 보낸 클라이언트에서 성립하지 않는 것(커널 RST), `doc_default_after`가 첫 등장만 보아 architecture.md 신규 문단이 config 지도의 기본값 검증을 가린 것(E8 변이 생존), lockstep 테스트가 한 방향뿐인 것, malformed TOML 분기 테스트 부재가 있었다.

판정은 전부 수용했다. alias 오탐은 A의 권장안대로 차집합 후보마다 그 키 하나만 담은 최소 TOML 문서를 `Config`로 역직렬화해 결과가 `Config::default()`와 다르면 "다른 이름으로 인식되는 키"로 보고 제외한다. 플레이크는 즉시 상계·5 s 폴링·폴링 뒤 상계의 세 단언으로 갈랐고 20회 반복 20/20이다. 순서 성질은 forward 축 cap 0(강제 거부, server/mod.rs 8209행 선례)으로 TCP 20개를 열고 요청자의 `accept_bi`가 500 ms 안에 아무것도 받지 않음을 단언하는 테스트로 고정했다. principal 축은 cap 2 테스트를, e2e에는 owner principal 단언(`Pin:device:laptop`)을 넣었다. 거부 관측은 `Ok(0)`/ConnectionReset/ConnectionAborted 셋으로 넓혔다. forward 키는 `remote_forward_quota_key` 헬퍼로 `rfwd:` 접두어를 구조화했고 `doc_default_after`는 모든 등장이 같은 기본값을 가리켜야 통과한다. lockstep 테스트는 `ServeConfig` 16필드 struct literal(`..Default::default()` 없이)로 양방향이 됐다.

fixer 반박은 이렇게 처리했다. qsh-core 테스트는 qsh-testkit의 `wait_for`를 못 쓴다(역의존 금지)는 것과, 순서 테스트에서 `held` 빈 벡터 단언을 생략하고 프로브 자체를 관측점으로 삼은 것은 수용했다. F1이 `tunnel_streams_per_principal_in_use`를 `#[cfg(test)] pub(crate)`로 올린 것도 수용했고 main은 같은 근거로 쌍둥이 `tunnel_streams_per_forward_in_use`도 `#[cfg(test)] pub(crate)`로 내렸다. J13이 pub의 근거로 든 "testkit e2e가 관측한다"가 실제 e2e에서는 감사 행과 TCP 거부로 대신 관측돼 크레이트 밖 호출부가 0건이기 때문이다. F2는 착수 시점에 항목 전부가 이미 구현돼 있었다고 적었는데, 이는 하네스가 F2 인스턴스를 세 번 재시작한 흔적이다(앞 인스턴스가 쓰고 죽었다). `cargo doc -D warnings`는 F2와 무관한 33개 파일의 기존 intra-doc 링크 경고 125~150건 때문에 크레이트 단위로 걸 수 없어 Step 5로 넘긴다. F4의 "known_leaf_paths grep 1건"은 테스트 함수 이름이라 결함이 아니다.

수용하되 코드는 바꾸지 않은 지적. 거부 감사 창의 키가 category 하나라 무인증 `-R` flood 중 같은 category의 다른 principal 거부는 요약 행으로만 남는다(A-P2-4). ADR-0010 추기에 한 문장으로 적고 창 키에 principal을 넣는 것은 Step 5로 넘긴다. 거부 경로가 `Quotas` 뮤텍스를 accept마다 두 번 잡는 것(A-P2-5)은 4c 시나리오 13 진단에 flood 중 `session.open` p95를 더해 본다. 기본값 64 경로는 4c T2 시나리오 13이 유일한 관측점이고 B가 제안한 단언 7개(512 동시 dial, 성립 64, 거부 448, fd 델타 ≤ 64+8, 종료 뒤 fd 복귀, principal cap 4 변형에서 category 전환)를 그대로 쓴다(B-P2-6). S2가 적은 doctor 테스트 192 s는 다른 빌드와 겹친 산물이라(B 재측정 3.5 s) CI 예산 근거로 쓰지 않는다(B-P3-3).

변이 실증은 S4 5건(M7 예약 삭제, M10 permit 즉시 drop, M11 감사 삭제, M9 차집합 공집합, M12 코드 표 삭제), F1 3건(principal 축 `if false`, E7 순서 변경, owner 상수화), F2 2건(alias 필터 무력화, lockstep 기대집합 키 제거), F3 1건(E8), F4 독립 재현 6건(위 셋에 alias 무력화·E8·`ServeConfig` 필드 추가), main 독립 2건(alias 프로브의 `!=`를 `==`로 → alias·typo 테스트 둘 다 실패, permit 즉시 drop → cap 테스트 실패)이다. 전부 죽었고 전부 cmp로 원복을 확인했다.

B가 남긴 CI 3 OS의 신규 테스트 개별 시간은 4a 커밋 3213796의 run 33827723206에서 읽었다. test 잡 벽시계는 ubuntu 3m31s, ubuntu-arm 3m34s, windows 3m45s, macos 4m40s다. 4a 신규 테스트 중 가장 긴 재dial 케이던스 테스트는 네 OS 모두 3.25~3.31 s, 나머지는 1.3 s 아래다. 4c의 T1 시간 예산은 이 수치를 기준으로 한다.

라운드 중 사고 하나. 첫 F4 인스턴스가 cargo 빌드 넷을 동시에 띄웠고 그 뒤 호스트 load가 190~320으로 올라 ps·top까지 멈췄다(09-04 저녁부터 09-07 새벽). 원인은 동시 빌드 자체보다 170 GB 빌드 디렉터리를 Spotlight(`LegacyImporterHost` 47개)와 `syspolicyd`가 95% 찬 디스크 위에서 계속 훑은 것이다. 재부팅 없이 풀린 뒤 `target`을 `target.noindex`로 옮기고 심링크를 뒀다(`.git/info/exclude`에 등록, 커밋 대상 아님). F4는 cargo를 한 번에 하나씩만 띄우는 규칙으로 다시 돌렸다. ADR-0010의 추기(`## 추기 — Step 4 (2026-09)`)는 A-P3-6의 사실 점검을 반영해 main이 놓았다.

게이트는 fmt, clippy -D warnings(host와 x86_64-pc-windows-gnu), xtask arch, cargo deny, nextest 1496 passed / 2 skipped(`--test-threads=1`, 895초)로 닫았다. 커밋 6d8de8c는 CI(run 34094633762)와 fuzz-smoke(run 34094633780) 둘 다 첫 실행에 green이다. Step 4b는 여기서 닫는다.

**(a)-추기 — Step 4c 구현 라운드 판정 + DoD 5 마감 (2026-09-08, main 세션).**

4c는 설계 판정의 셋째 라운드로, DoD 5의 T2 적대 부하 스위트와 그 실행 자리를 만들었다. 브리프 `$SP/step4/BRIEF-4c.md`의 개방질문 일곱은 ARBITRATION-4.md에 이렇게 닫았다. 게이트는 새 환경변수 `QSH_LOAD_STRICT`/`QSH_LOAD_BIN`이고 `#[ignore]`나 `cargo xtask load`는 쓰지 않는다. 30 MB는 release 빌드 idle listener 기준이며 부하 중 상한은 `30 MB + 8 MB × 살아 있는 세션 수`, 하한 단언(`2 MiB < rss`, `fd >= 3`)을 둔다. 시나리오 3의 세션 수는 8이다. CLI.md §6.12에 audit 부피 상계 문장(`max_bytes × (retain + 1)`)을 더하고 `quota_docs.rs`에 핀을 붙인다. 시나리오 1은 bind에 실패한 source를 빼고 진행하되 성립 source가 2 미만이면 실패한다. DoD 5 판정은 main이 Dave-Windows-WSL 실측으로 닫고 load.yml은 회귀 감시자다. nextest.toml 주석은 주어를 4a의 in-process 하네스로 좁히고 doctor 진단 개수는 CLI.md 두 자리를 14로 고쳐 `doctor_docs.rs`가 `EXPECTED_DOCTOR_CODES.len()`과 대조한다.

구현 워크플로우는 다섯 스테이지(S1 측정 헬퍼와 서브프로세스 하네스, S2 시나리오 1·2·3, S3 시나리오 12·13과 진단 A-P2-4/A-P2-5, S4 load.yml과 문서, S5 게이트와 핸드오프)로 돌았다. 서브프로세스 `qsh serve`는 `Sandbox::command_with_bin`과 `ServeGuard::start_with_bin`으로 release 바이너리를 고른다. 시나리오 1의 raw flood client는 소스 주소를 고르는 검증 없는 rustls endpoint라 `qsh-testkit::raw_quic`에 두고 qsh-cli에는 quinn/rustls dev-dep을 넣지 않았다. macOS에는 `/proc`도 `127.0.0.0/8` 다중화도 없어 strict 실행은 전부 WSL에서 했고 WSL에는 fuzz 워커 여덟 개가 8 vCPU를 상시 점유하고 있어 그 위에서 잰 값이다.

적대 라운드는 opus 둘(A 테스트 강도·변이, B 견고성·CI·계약)이 돌았고 둘 다 amber였다. 수용한 것은 시나리오 3의 부하 중 RSS·fd 단언과 200 ms 간격 `RssPeakSampler`(A1·A2·A12·B2, 부하가 끝난 뒤 잰 값은 peak가 아니다), nextest `[profile.load]`(A7·B1·B3), 시나리오 1의 회복 단계(A9), 시나리오 12를 집계 12a와 회전·retention 12b로 나누는 것(A4·A5·A6·B5), 회전 실패 fail-closed 12c 시도(A17), 시나리오 2의 세는 dial 재시도 제거와 30 s 타임아웃(A16·B4), raw UDP 부단계의 워커 차단 해소(B12), `poll_stable` async화(A13), verdict를 단언 뒤에 계산(B6), `classify`에 BrokenPipe(B9), `RLIMIT_NOFILE` 가드(B10), flood client 이동(B13), 문서 핀 강화(B7·B8)와 주석·문서 정정 여섯이다. 기각은 셋이다. echo p95 임계 `max(baseline × 3, 50 ms)`의 50 ms는 제품 절대 상한이고 상대 팔을 좁히면 CI 잡음에 깨진다(A3, 대신 진단에 `load/baseline` 비율을 남긴다). "accept 이전 거부"는 qsh-core 단위 테스트가 소유하고 e2e는 개수·fd·audit 요약만 고정한다(A10). 기본값에서 `validated_rate_limited`가 도달 불가라는 관측은 테스트가 아니라 제품 문제라 시나리오 1의 `validated_rate_per_source=3`은 두고 admission 기본값 재검토를 Step 5로 올린다(A8).

수정 라운드는 F1a(시나리오 1·2, flood client 이동, profile.load, load.yml), F1b(시나리오 3·13, common 헬퍼, classify, RLIMIT 가드, verdict 블록), F2a·F2b·F2c(시나리오 12, 핀, 문서), F3·F3b(게이트, WSL 20회, 지정 변이 실증, 핸드오프)로 돌았다. 하네스가 긴 스테이지를 두 번 도중에 끊어 F2를 셋으로 쪼갰다. 12b 재구성 중 `negotiate_session`이 Hello 교환만 하고 `session.open`을 보내지 않아 허용 행이 한 줄도 안 쓰인다는 것을 찾아 `session_open`/`session_close` RPC 쌍으로 바꿨고 `audit.log.lock` 사이드카를 회전 파일로 세던 오검출도 잡았다. 12c는 A17의 `chmod 500` 구성으로는 writer가 rename 실패를 비치명으로 다루도록 설계돼 있어 fail-closed 관측 지점에 닿지 않는다는 것을 두 번 실측하고 브리프 §4.6의 예외 조항대로 뺐다. fail-closed 계약 자체는 4a의 단위 테스트 `session_open_fails_closed_when_the_audit_sink_cannot_record_an_allow`가 여전히 고정한다.

반박으로 남은 것은 하나다. 12a에 대한 지정 변이 `AUDIT_AGGREGATION_WINDOW` 10 s→1 s가 F2a와 F2c의 두 독립 재구성에서 모두 NOT KILLED다. F2c는 held 연결 16개 위에서 Initial 제한 아래 5/s로 12 s 이상 dial해 거부를 연속으로 만들었는데도 상계가 죽지 않았다. 최초 burst 뒤 quota 거부 감사 행이 더 안 나오는 현상이 원인 후보이고 근본 원인은 못 잡았다. `window_is_fresh` 상시 true 변이는 죽는다(rows 226 > bound 6). 이 항목은 Step 5에서 동적 계측으로 규명한다.

지정 변이 다섯은 넷이 KILLED다. `Sketch::advance_to` 첫 줄 `return;`은 시나리오 1 회복 단계가, retention 무력화는 12b가, `RssPeakSampler` 상시 0은 시나리오 3 하한이, `reserve_connection`의 host-cap `if false`는 시나리오 2가 잡는다(`left: 32, right: 16`, 1.1 s). 다섯째가 위의 집계 창 변이다. 스테이지별 변이는 S2·S3·F1a·F1b·F2a·F2b·F2c가 각자 표로 남겼고 전부 cmp로 원복을 확인했다.

WSL 실측. RUN 9 같은 깨끗한 회차에서 시나리오 2는 RSS baseline 15.5 MB, 부하 중 peak 24.1 MB, idle 24.1 MB(상한 30 MB)이고 시나리오 3은 peak 16.2 MB(상한 96 MB), idle 16.2 MB다. A-P2-5 진단(512 accept flood 중 `session.open` p95)은 8.3 ms(30 표본)라 `Quotas` 뮤텍스를 accept마다 두 번 잡는 비용은 지금 의미가 없다. 그런데 strict 전 스위트 20회 반복은 200건 중 170 pass, 실패 30건이 전부 `dial: Timeout(30s)` 클래스이고 단언 불일치는 0건이다. 시나리오 2가 19/20회로 지배적이다. 서버 stderr를 tee한 진단 세 번 중 두 번은 서버가 31 s 동안 시작 로그 두 줄 외에 아무것도 남기지 않았고 한 번은 같은 batch의 dial 여덟 중 일곱을 4 ms 안에 거부한 뒤 하나만 30 s 동안 응답이 없었다. 커널 UDP 수신 오류 카운터는 늘지 않았다. `admission.rs`와 `quota.rs`에는 tracing 호출이 한 줄도 없어 handshake 이전 판정(Retry/Ignore/Refuse/Admit)은 로그 레벨과 무관하게 보이지 않는다. 원인은 못 잡았고 가설(fuzz 워커와 dial 동시성이 겹친 스케줄링 지연)만 남긴다.

DoD 5는 여기서 닫는다. 근거는 RSS·fd·echo p95·audit 부피의 단언이 WSL 실측에서 한 번도 깨지지 않았다는 것이고 남은 것은 부하 아래 dial 정지라는 별개의 질문이다. 그 질문은 Step 5로 넘긴다. GHA 첫 load.yml 실행이 경합 없는 환경의 답이다. CI(run 34148240314)와 fuzz-smoke(run 34148240184)는 첫 실행에 green이고, load.yml 첫 실행(run 34148240215, ubuntu-24.04 4 vCPU, `ulimit -n` 65536)은 10 tests run, 10 passed, 43.0 s로 WSL의 깨끗한 회차(43.3 s)와 같다. 그 러너에서 시나리오 2는 baseline 15.0 MB, peak 23.2 MB, idle 23.2 MB, 시나리오 3은 peak 15.6 MB에 echo p95가 baseline 0.33 ms, 부하 중 0.67 ms(임계 50 ms), A-P2-5는 8.7 ms다. WSL의 dial 정지는 경합 없는 러너에서 재현되지 않았다.

Step 5 이월 항목. admission·quota 판정 지점에 카운터성 tracing과 서버 하트비트를 넣고 하네스에 dial별 송수신 시각을 남긴다. 집계 창 변이 미검출의 근본 원인. `session.open` 뒤 `session.close`가 미상환 티켓을 해제하지 않아 한 연결이 `MAX_PENDING_TICKETS_PER_CONN`(32)에서 막히는 관측(12b·12c 모두 부딪혔다)이 의도인지 확인. 12c를 실제로 `degraded`에 닿는 구성(활성 파일 자체의 권한 제거나 재시작)으로 다시 만들 것. admission 기본값 재검토(A8). 거부 감사 창 키에 principal(A-P2-4). `cargo doc -D warnings`의 기존 링크 경고. doctor 테스트 SLOW 원인.

게이트는 fmt, clippy -D warnings(host와 x86_64-pc-windows-gnu), xtask arch, cargo deny, nextest 1500 passed / 2 skipped(`--test-threads=1`, 938초)로 닫았다. 커밋은 2f52958이다. Step 4는 4a·4b·4c로 여기서 닫는다.

### Step 5 — 24h/100-session soak + fd/메모리 게이트 (DoD 2)

M7 이월 부채가 여기서 만난다: bounded pull executor 부재(측정된 512 천장), pull당 fd 선형 증가, 고아 `.tmp{pid}-{N}` 미청소. soak이 이것들을 드러내는 자리다.

**(a) 착수 판정 (2026-09-08, main 세션).** 인벤토리(`$SP/step5/INVENTORY-5.md`)가 리더 다섯의 보고를 합치며 찾은 충돌 셋이 설계를 정했다. 100세션은 기본값과 충돌한다. `max_sessions_per_principal` 32(`config.rs:601`)와 `MAX_PENDING_TICKETS_PER_CONN` 32(`server/mod.rs:159`)가 걸린다. soak config에서 principal당 상한을 128로 올리고 세션은 attach까지 해서 ticket을 redeem한다. T2의 상한 공식 `30 MB + 8 MB × N`은 N=100에서 830 MB라 판정력이 없다. 세션당 buffer는 기울기 `(peak − baseline) / N ≤ 8 MiB`로 판정하고 상한 공식은 보조 기록으로 둔다. DoD 2의 fd는 listener 프로세스이고 M7 이월 (iii)은 클라이언트 `dial_peer`(`ops/session.rs:1115`)라 pid가 다르다. 하네스는 두 프로세스를 다 샘플링하고 사이클 세션은 `Ops::connect_target` 실경로로 연다.

하네스는 하이브리드다. 측정 헬퍼를 `qsh-testkit`으로 승격하고(4c의 `raw_quic.rs` 전례), `crates/qsh-cli/tests/soak.rs` 하나가 env로 길이·세션 수·샘플 간격을 받는다. 짧은 모드(120 s / 8세션)는 `[profile.load]`에서 load.yml의 회귀 감시자가 되고 24h 모드는 `scripts/soak/run.sh`가 `[profile.soak]`(slow-timeout 경고만)로 전용 호스트에서 기동해 CSV를 남기며 `scripts/soak/summarize.py`가 판정한다. 판정 기준은 `docs/campaigns/m8-soak.md`에 실행 전 고정한다. GHA job 상한 6시간과 Linux 전용 측정(`common/mod.rs:906-933`) 때문에 24h 런은 Dave-Windows-WSL에서 돌고 fuzz 2차 배치와 1차 부족분 재개가 끝난 뒤 단독 점유로 시작한다. 4c의 dial timeout 오염을 되풀이하지 않기 위해서다.

범위 조정. (i) bounded pull executor는 ADR-0011이 Step 6에서 `crates/qsh-cli/src/mcp/`를 지우면 고칠 자리와 재현 경로가 함께 사라지므로 Step 6 뒤로 미룬다. (ix) forward-route live carrier는 protocol.md·README·`tunnel_chaos.rs:299` 단언을 뒤집는 의미론 재설계라 Step 6(freeze 선행 정리)으로 옮기고 새 ADR을 선행한다. doctor 진단은 신설하지 않는다. 4c 이월 중 (a) 계측만 soak 체인에 들어가고 (b)(c)(d)(e)(g)는 24h 대기 시간에 처리하는 병행 정리 묶음이며 (f) cargo doc 경고 149건은 Step 6이다.

| 하위 | 내용 | 완료 기준 |
|---|---|---|
| 5a | `Gate::decide`·`reserve_connection` 카운터 + trace 이벤트, accept 루프 1 s 하트비트(debug), T2 per-dial 타임스탬프 | 분기별 카운터 유닛 테스트, `QSH_LOG=debug`에서 하트비트 |
| 5b | 헬퍼 승격 + `soak.rs` + `[profile.soak]` + CSV | macOS skip green, WSL 짧은 모드 strict 3/3 |
| 5c | `scripts/soak/`, `docs/campaigns/m8-soak.md`, testing.md, load.yml | summarize.py가 합성 CSV로 표를 낸다 |
| 5d | (ii) `exec_run` 런타임 공유, (iv) atomic-rename 헬퍼 통합 + 죽은 pid `.tmp` 스윕 | 회귀 테스트, win-gnu check |
| 5e | 24h 런 + 캠페인 기록 + DoD 2 판정 | §2 DoD 2 체크 |
| 5f | soak이 드러낸 수정((iii) 등) | 재실행 24h에서 fd 회귀선 기울기 0 |

**(a)-추기 — 5a–5d 구현·검증 라운드 판정 (2026-09-08, main 세션).** 착수 판정의 설계는 그대로 섰다. 하이브리드 하네스(`soak.rs` 하나, 실행기 둘)와 `qsh-testkit::procstat` 승격, `[profile.soak]`의 slow-timeout 경고만 의미론은 S0에서 실측으로 확인했다(1 s period가 4 s sleep 테스트를 죽이지 않고 SLOW 경고만 반복). 24h 런의 실제 상한은 `run.sh`의 outer timeout이 맡는다. 판정식은 `docs/campaigns/m8-soak.md` §3에 실행 전 고정했다. 착수 판정의 두 시계열 판정에 셋을 더했다. listener·self fd는 boot→idle_end 비교가 아니라 steady 4분위 첫/마지막 최댓값 +2로 본다(WSL 실측의 self fd +4가 세션 open/attach의 일회성 warm-up이라 (iii)이 재는 사이클 중 성장과 다르다). echo p95는 ramp 직후 baseline의 3배와 50 ms 중 큰 값이고 baseline은 CSV의 ramp 행에 실어 `summarize.py`도 같은 값을 쓴다. 세션 라운드 5 s 데드라인은 `SESSION_STALLED`로 잡는다. TTL reap 판정 시각은 `resume_ttl + REAPER_TICK`이다.

구현 중 S4가 찾은 사실 하나. atomic-rename은 `config.rs`와 `resume.rs`에 두 벌이었고 ticket 카운터도 둘이었다. `fsutil::write_atomically`로 합치고 카운터를 하나로 두었다. 파일명 `.tmp{pid}-{ticket}`은 crash-safety 테스트가 핀한 계약이라 그대로다. 스윕은 1h+ESRCH 또는 24h 규칙이다. 24h 쪽은 적대 검토 A가 지적한 재부팅 뒤 pid 재사용과 non-unix의 liveness 부재를 한 임계로 덮는다.

검증 라운드. opus 3인 적대 검토(A 변이 9건 중 7 kill, B·C 코드 검토)와 sonnet 수정 F1–F3. 채택 항목은 `$SP/step5/ARBITRATION-5.md`에 표로 남겼다. blocker 둘은 Windows `set_modified`가 읽기 핸들에 `SetFileTime`을 걸어 CI가 붉어지는 것(C1)과 100세션이 `max_connections_per_principal` 기본값 32에 걸리는 것(B1, cap을 `max(64, 2N)`·`max(512, 4N)`으로). 기각은 C11(`.tmp` 접두 강화)과 A8의 디렉터리별 throttle(엔트리 열 개 read_dir 한 번을 막으려 전역 상태를 두지 않는다), A10의 곱셈 백오프(24h 로그에서 5 s 하트비트는 생존 증거)다.

WSL 실측(fuzz 포화 중)과 판정. 짧은 모드 strict에서 dial `ConnectionFailed` 10 s 2회는 4c와 같은 환경 클래스라 하네스가 3회 시도(1 s 백오프)로 흡수하고 제품 타임아웃은 두었다. T2도 5/10으로 같은 클래스. 5b의 완료 기준 "WSL strict 3/3"은 미충족으로 두고 fuzz 종료(2차 09-10 14:48 + 1차 부족분 ~13h/타깃) 뒤 단독 점유에서 다시 잰다. 깨끗한 환경의 답은 load.yml의 soak 스텝이다. 5a·5c·5d는 완료. §5의 ii·iv는 5d로 닫는다. (iii)은 24h 런이 `FD_GROWTH_CLIENT`를 내는지로 판정한다.

이월. summarize.py에 echo baseline 플래그 override가 남아 있으나 기본은 ramp 행이다. 4c 이월 (b)(c)(d)(e-1)(e-2)(g)는 24h 대기 중 병행 정리 묶음 그대로다. d01987f의 macOS `tunnel_chaos` flake(fault 주입 전 ECONNRESET)는 1회라 §6에 올리지 않았다. 재발하면 올린다.

load.yml 첫 실행(run 34203445617)과 F4. b9e67b1의 GHA soak 짧은 모드는 T2 4/4에 RSS(idle_end 20.2 MiB, 세션당 1.1 MiB)·fd·TTL reap을 다 통과하고 echo 축 하나에서 떨어졌다. steady 창 59개 중 2개(첫 steady 창 129.5 ms, cycle 2 직후 114.6 ms)가 50 ms를 넘었고 나머지는 중앙값 1.2 ms다. 세션 교체 순간의 스파이크지 저하가 아니어서 창별 최댓값 규칙을 위반 창 비율 규칙(`ECHO_SPIKE_FRACTION_MAX` 10%, 태그 `ECHO_DEGRADED`)으로 바꿨다. 최댓값·초과 창 수·첫/마지막 4분위 중앙값은 정보로 남겨 24h 뒤 저하 규칙의 입력으로 쓴다. DoD 2에는 echo 항목이 없으니 DoD 판정은 바뀌지 않는다. 스파이크가 세션 spawn과 겹치는 것은 5f 후보로 `docs/campaigns/m8-soak.md` §7에 적었다.

병행 정리 라운드 1((c)(g)(d)+(b-0), 2026-09-08). BRIEF-PB의 Q1~Q6 판정은 `$SP/step5/ARBITRATION-5.md`에 있다. Q1 admission 기본값은 바꾸지 않는다. 에이전트의 동시 `qsh exec` burst가 같은 source에서 오고 미검증 축이 이미 10/s·burst 20으로 그 source를 묶고 있어 검증 축을 낮춰 얻는 방어가 없다. quinn NEW_TOKEN을 켜 재접속 Initial이 Retry 없이 검증 상태로 들어오게 되면 그때 다시 정한다. Q2 audit 창 principal 분리는 라운드 2에서 상한 두 겹(닫힌 창 삭제, 카테고리당 principal 창 64개와 overflow 창 `"-"`)과 같이 간다. Q3 (b) 변이 실측은 WSL 단독 점유 때다. 구현은 셋이다. (c) `session.close`가 그 세션의 미상환 티켓을 어느 연결의 것이든 푼다. 기존 테스트 3건의 기대를 새 규칙으로 고치고 교차 연결 테스트를 더했다. (g) DNS resolve를 `DOCTOR_PROBE_TIMEOUT` 안에 묶었다(detached 스레드, spawn 실패는 오류). doctor SLOW의 원인은 검토자가 실측으로 뒤집었다. `Ops::doctor`가 identity의 keystore 종류와 무관하게 `PlatformKeyStore`를 만들어 macOS Keychain을 쳤고 서명 없는 테스트 바이너리에서는 그 한 번이 20 s였다. 이제 identity의 `key_store` 종류대로 실제 store를 진단하고 doctor 테스트 43건은 313 s에서 3.2 s가 됐다. (d) 12c는 "active 파일 없는 audit 디렉터리 `chmod 500` 위 writer 재시작" 구성으로 degraded 래치에 닿았다. 래치 변이로 죽는 것을 확인했고 strict 축에 넣었으며 root면 skip이다. (b-0) `AUDIT_AGGREGATION_WINDOW`를 `pub`으로 넓혀 12a의 하드코딩 10.0을 상수로 바꿨다. CLI.md의 close 문단과 §6.12 degraded 문장에 `session.open`을 더했다.

### Step 6 — wire freeze 선행 정리

freeze 이후에는 고칠 수 없는 것들을 먼저 처리한다.

- handshake matrix에 **ALPN 불일치** 케이스 추가 — "application 상태 생성 전 실패" 불변식을 의존성 상속이 아니라 테스트로 고정한다.
- device 개인키 프로세스 상주 사본에 `Zeroizing`.
- TUI 펌프 스레드 spawn 실패 panic 제거.
- pairing device_name 길이 상한(현재 `CONTROL_FRAME_MAX` 256 KiB로만 묶임)과 Unicode bidi-override·homoglyph 스푸핑 — `docs/design/protocol.md` §15.5가 M8 백로그로 기록한 2건.
- **MCP 어댑터 제거(ADR-0011, 2026-09-07 확정).** `qsh mcp` 서브커맨드, `crates/qsh-cli/src/mcp/`, `mcp_conformance.rs`, rmcp·schemars 핀, xtask arch의 `MCP_DIR` 규칙, `docs/man/qsh-mcp.1`을 지우고 PRD·CLI.md §8·ROADMAP M6·architecture.md·testing.md·README·CLAUDE.md·`docs/campaigns/m6-mcp.md`를 맞춘다. `tools_list.json`은 append-only라 두고 같은 디렉터리 README로 은퇴를 적는다. qsh-core의 `qsh mcp` 언급 주석은 서술만 바꾼다. Step 7 threat model 전에 끝낸다.
- **forward-route live carrier·`-R` 자동 재발행(M7 이월 ix, Step 5 (a)가 이관).** 현행 의미론은 "연결 손실→resume에서 터널 스트림은 깨끗이 종료"이고 `tunnel_chaos.rs`의 `a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes`가 이를 고정한다. 뒤집으려면 새 ADR과 `docs/design/protocol.md`·README Known limitations 개정이 먼저다. freeze 전에 결정한다.
- bounded pull executor(M7 이월 i) 재질문 — MCP 제거 뒤 `Ops` facade에 로컬 동시성 상한이 여전히 필요한지.
- `cargo doc --workspace --no-deps` 경고 149건(`rustdoc::private_intra_doc_links`·미해결 링크 위주) 정리 — Step 5 인벤토리가 새로 확인한 항목.
- **서비스 unit 예시 문서(ROADMAP M9 추가 범위, 2026-09-07).** `docs/deploy/service.md`에 `qsh serve`/`qsh listen`/`qsh reverse`용 launchd LaunchAgent plist와 systemd user unit 예시를 싣는다. 로그 경로, `KeepAlive`/`Restart=always`, `loginctl enable-linger`, LaunchAgent가 로그인 세션 안에서만 뜬다는 제약, WSL의 `systemd=true` 조건을 적는다. README Install 절에서 링크한다. 구현(`qsh service`)은 M9다.

**(a) 착수·완료 판정 (2026-09-10, main 세션).** 브리프(`$SP/step6/BRIEF-6.md`)가 위 항목 12개를 스테이지 아홉(S1~S9)으로 나눴다. 문서 스테이지는 병렬, Rust 스테이지는 한 트리에서 순차로 돌렸고 cargo 파일 락이 직렬화를 맡았다. 설계 판정은 넷이다. forward-route는 ADR-0018로 확정했다. v1 터널 수명은 connection에 결합하고 live carrier는 구현하지 않으며 `-R` 자동 재발행은 P1이다. freeze 문면은 additive 확장(`reclaim` 류 필드)을 막지 않는다고 적는다. ROADMAP §3 행과 아래 §5 ix가 이것으로 닫힌다. bounded pull executor(§5 i)는 ADR-0011로 종결한다. MCP 어댑터가 사라지면서 512 천장의 재현 경로가 사라졌고 `session_read` 호출처는 CLI `run_session_read`와 서버 핸들러 둘뿐이라 `Ops` facade에 로컬 동시성 상한을 둘 자리가 없다. trust store·invites 잠금(§5 vi·vii)은 M7 Step 7-1이 이미 닫았다. `TrustStore::lock`이 `ops/mod.rs:548`·`:575`·`:699`, `InviteStore::lock`이 `ops/mod.rs:607`·`trust/pairing.rs:587`에서 read-modify-write 전체를 덮는다. 렌즈 1이 재확인했다. device_name 규칙은 `wire::validate_device_name` 한 표로 두고 `valid_host_name`(offered_name, ASCII)과는 64바이트 상한만 공유한다. homoglyph는 탐지하지 않고 §15.4의 fingerprint 병기를 방어선으로 적었다.

받아들인 잔여 셋. `qsh mcp`는 이제 clap 오류가 아니라 대화형 호스트 `mcp`로 파싱돼 `HOST_NOT_FOUND`(exit 255)다. 서브커맨드를 예약해 두지 않는다. `Zeroizing`은 `LocalIdentity.key_pkcs8_der`까지이고 rustls로 넘어가는 사본은 rustls-pki-types 1.15.1에 `impl Drop`이 없어 그대로다(주석에 기록, 업스트림 이슈는 열지 않았다). ALPN 불일치는 클라이언트가 다른 ALPN을 내는 case18 하나다. 서버 accept가 `HandshakeErr`이고 `lookup_pin` 호출이 0회이며 클라이언트가 정확히 `no_application_protocol`(0x100+120)을 받는다는 세 단언으로 "application 상태 생성 전 실패"가 고정된다. 서버 측 케이스는 같은 불변식의 거울이라 넣지 않았다.

검증은 opus 렌즈 셋(삭제 완전성·계약 안정성 / 하드닝 정확성 / 문서 정합)과 픽서 둘, 재검증 하나다. 변이 실험은 렌즈 1이 1건(지운 `MCP_DIR` ban을 되살리면 arch-lint FAIL), 렌즈 3이 2건(`qsh-mcp.1`을 되살리면 man 집합 게이트 FAIL, gnu 타깃 doc은 에러 8건), 렌즈 2가 8건이다. 8건 중 a1·a2(case18)·b1·b2(bidi 표·64바이트)·c1(Debug에 키 필드)·e1(`user@` 스트립 제거)은 기대대로 FAIL했고 d1·d2(TUI 펌프 spawn panic 복원, `drop(raw)` 순서)는 PASS로 새어 나갔다. 렌즈 2가 든 이유는 테스트가 테스트 더블 자신만 단언했기 때문이다. 픽서 B가 `PumpHandle` 시임(write/try_write/try_resize/detach 4개)으로 두 펌프를 제네릭화해 실제 spawn 경로가 테스트를 타게 했고 재검증이 d1을 다시 적용해 FAIL을 확인했다. d2는 `run()` 전체를 태워야 잡히는 e2e 무게라 단위테스트로 못 잡는다. 해당 분기 위에 그 사실을 주석으로 남겼다. 렌즈 2가 찾은 `"dave@"`/`"@"`의 빈 별칭은 `hint_alias`가 `None`을 돌려주고 `empty_host_name_error()`(`INVALID_ARGUMENT`)로 떨어진다. 같은 힌트를 쓰는 `qsh exec` 경로(`resolve_peer_address`)도 같은 헬퍼로 묶었다. 렌즈 3의 P1은 새 doc 스텝이 windows-latest에서 무조건 깨진다는 것이었다. `if:`로 ubuntu에 좁히면 Windows 전용 doc 경고는 영영 안 잡히므로 cfg(unix) 항목을 가리키던 링크 12건을 평문 코드로 풀고 4개 러너 전부 유지했다. 로컬 `--target x86_64-pc-windows-gnu` doc이 rc 0이다. `qsh reverse`의 clap 설명은 Step 6 범위 밖 선재 결함이지만 `service.md`가 노출해 지금 고쳤다. M9 개명(ADR-0012) 때 다시 바뀐다.

지운 것의 크기. `mcp/mod.rs` 915줄, `mcp_conformance.rs` 1880줄, Cargo.lock 194줄, man 페이지 1장. `fixtures/mcp/tools_list.json`은 append-only 규칙대로 남고 같은 디렉터리 README가 은퇴를 적는다. cargo doc 경고는 158건(브리프 시점 재측정)에서 0으로, 문장은 건드리지 않고 링크 표기만 고쳤다. 게이트는 fmt, clippy `-D warnings`, xtask arch, cargo deny, win-gnu check+doc, host doc `-D warnings`, nextest 1527 passed(2 skipped)다.

이월. Step 7 freeze 문면에 ADR-0018 결정 3(additive `reclaim` 경로)을 반영한다. 24h soak·Round 3은 WSL fuzz 2차 배치 종료 후다. 재검증이 남긴 P3 하나. `hint_alias`가 벗긴 별칭을 trim하지 않아 `"dave@ nowhere"`의 remedy에 공백 낀 별칭이 실린다. `@` 없는 `" nowhere"`도 같은 모양이라 선재 성질이고, 별칭이 `valid_host_name`을 못 넘으면 remedy 대신 `INVALID_ARGUMENT`로 보내는 규칙 하나로 두 경로를 정리할 자리다(Step 7 전 소정리). MCP 이름은 코드에서 `xtask/src/arch.rs`의 CRLF 테스트 doc 주석 한 곳에 역사 서술로 남는다.

### Step 7 — wire format freeze + threat model + OSS-Fuzz 제출

§1의 SC7 판단이 선행 조건이다. freeze 문면은 `docs/design/protocol.md`에 박고, threat model은 새 문서로 낸다.

**(a) 착수 판정 (2026-09-10, main 세션).** 인벤토리(`$SP/step7/INVENTORY-7.md`, 리더 다섯과 합성·비평 각 하나)가 산출물 여섯을 확정했다. freeze 문면(protocol.md §16 신설, §9는 "`.proto` 계약 (v1)"로 개명), threat model(`docs/design/threat-model.md`), OSS-Fuzz 제출물 초안(`fuzz/oss-fuzz/`), fuzz 캠페인 기록의 승격(`docs/campaigns/m8-fuzz.md` — Step 1 기록은 아래에 그대로 남긴다), LICENSE 실물 파일(`Cargo.toml`의 `MIT OR Apache-2.0` 선언만 있고 루트에 파일이 없었다), Step 6 이월 소정리(`hint_alias`). SC7은 §1대로 운영자 판정이 아직 없다. 문면은 (가)(나) 어느 쪽이든 같으므로(차이는 PRD·DoD 4 문구뿐) §16을 "상태: 초안 — 발효 전"으로 완성해 두고 발효(일자·커밋 기입)는 판정 뒤 소커밋으로 한다. §1의 "넘기지 않는다"는 발효를 뜻한다고 읽는다.

판정 여덟. wire major(ALPN `qsh/N`)와 `qsh.cli/vN`·`qsh.event/vN`은 독립 트랙이다. QUIC RESET/CLOSE 코드값은 wire 계약이 아니되 진단 상관관계를 위해 major 안에서 재배치하지 않는다. `WIRE_MINOR_VERSIONS`는 v1 내내 `[0]`이고 minor 축은 예약만 한다. additive 협상은 capability 문자열 몫이다. 예약 번호(`reserved 25`, `ATTACH_MODE_RO = 2`)를 그 예약 대상으로 채우는 것은 additive다. `StreamKind` 0은 유효 kind가 아니다. stateful broker fuzzer(ROADMAP M8 범위, protocol.md §13 4번과 testing.md L8 `broker_ops`)는 Step 7에 넣지 않고 Step 7b로 바로 뒤에 붙인다. 주입 가능 `Clock`은 이미 있다. perf 게이트(Step 8)는 Step 7 뒤다. OSS-Fuzz의 `primary_contact`, google/oss-fuzz PR 제출은 사용자 액션이고 저장소는 이미 public이다.

threat model은 인벤토리의 위협 표(A 스푸핑부터 G 가용성까지 41행: 위협·통제·근거·핀 테스트·잔여 위험)와 갭 세 표를 본문으로 삼는다. 통제는 있는데 되돌려도 깨지는 테스트가 없던 0-RTT 금지 다섯 상수는 config 필드를 직접 단언하는 유닛으로 닫는다. per-conduit inflight 캡, `trust remove` 뒤 기존 연결 유지, `session.control close`의 owner scope 예외는 기존 테스트를 특정하거나 최소 테스트를 더한다. doctor 진단 2종은 M9 소유라 잔여 위험으로만 적는다. 테스트는 있는데 문서가 없던 다섯(audit torn-write 복구, audit 파일 락, localctl 쓰레기 피어 생존, localctl의 resume token 부재, ring tail-chunk coalescing)은 threat model 서술로 흡수한다.

**(a)-추기 — Step 7 완료 판정 (2026-09-10, main 세션).** 구현은 Workflow 9 에이전트(S1 freeze 문면·S3 캠페인 문서·S4 OSS-Fuzz·S5 코드를 sonnet 넷이 병렬로, 그 뒤 S2 threat model을 opus가, 게이트, V1/V2/V3 opus 렌즈), 수정 라운드는 Workflow 7 에이전트(F-A/F-B/F-C sonnet → 게이트 → R1/R2/R3 opus). 산출물 여섯이 전부 착지했다. protocol.md §16(초안 — 발효 전, §16.1–16.10)과 §9 개명·§13 재작성, `docs/design/threat-model.md`(자산·주체·진입점, 위협 표 51행 — 인벤토리 rev.2의 50행에 localctl euid 게이트 B9를 더했다 — 갭 g1–g5, 역갭 r1–r5, 잔여 h1–h15, 운영 가정, 비목표, 유지 규율; README·architecture.md §6·testing.md·CLAUDE.md 문서 맵에서 링크), `docs/campaigns/m8-fuzz.md`(DoD 1의 "parser 타깃" = 16개 전부로 고정, 배치 1/2 기록 이관), `fuzz/oss-fuzz/` 4파일 + `scripts/fuzz/oss-fuzz-local.sh`(로컬 실행 16 바이너리 + seed corpus zip 16), `LICENSE-MIT`·`LICENSE-APACHE`(anyhow 1.0.104 본문, README License 절), 코드 소정리 둘(`hint_alias` trim + `valid_host_name` 3-way `HintAlias`, 0-RTT/resumption 다섯 값을 실제 rustls config에서 읽는 유닛 — threat model g5를 닫는다). 신규 테스트 6, 픽스처 불변. `crates/**` 밖에서 바뀐 코드 파일은 `fuzz/fuzz_targets/json_request_types.rs`의 모듈 주석(MCP 어댑터 제거 뒤 문면)뿐이다.

렌즈가 잡은 것과 처분. V1(freeze 문면) P2 3·P3 4 — §16.2 `session_id` 행이 `valid_host_name`을 가리켰고(실제 검증기는 `server/mod.rs:4074`), "세션 id는 모양부터 검사한다"는 §7이 아니라 §9이며, `offered_name`의 빈 문자열 예외(controller가 이름을 정하는 정상 경로, `registry.rs:486`)가 빠져 얼리는 수용 집합이 실제보다 좁았다. V2(threat model·코드) P2 2·P3 1 — threat-model.md의 architecture.md·README 인용 15곳이 S2 자신의 편집(+2·+1줄)에 밀려 있었고, localctl의 accept 시 euid 검사(`daemon.rs:1460,1805`, 핀 테스트 셋)가 통제·테스트 다 있는데 표에 없었다. V3(OSS-Fuzz·라이선스) P1 1·P2 3·P3 4 — `build.sh`의 errexit이 shebang에만 있어 `bash build.sh`로 부르는 로컬 하네스가 false green을 냈고(S4 1회차 로그가 실증: 빌드가 죽고 `cp` 16회 실패인데 rc 0), 타깃 목록 하드코딩이 `cargo fuzz list` 규율과 어긋났으며, `-O` 단독은 debug assertion과 overflow check를 끄고, Dockerfile이 aws-lc-sys의 cmake 의존을 준비하지 않았다. 전건 채택해 고쳤고, V2-3(hint_alias의 trim이 조회 키가 아니라 remedy 문면에만 걸린다)만 이름 정규화 정책이라 M9로 이월했다. 위협 표는 BRIEF의 "41행"이 아니라 인벤토리 rev.2의 50행이 맞았다(A9·B8·C10·D7·E8과 대조군이 그 증분).

변이 증거 여덟. `hint_alias`의 trim+검증 가드를 되돌리면 신규 5건이 전부 FAIL하고 기존 3건은 PASS(과결합 없음). 0-RTT 다섯 값(`enable_early_data`, `resumption`, `max_early_data_size`, `send_tls13_tickets`, `session_storage`)을 각각 독립으로 뒤집으면 매번 해당 단언에서 FAIL — 이 유닛은 단언값이 아니라 실제 config를 읽는다. per-conduit 캡을 +1 완화하면 g1이 인용한 `cap_exhausted_on_one_conduit_does_not_affect_another`가 FAIL. 수정 라운드 재검에서 `peer_is_authorized`를 항상 true로 바꾸면 B9가 인용한 `:1935`가 FAIL하고 `:2255`는 그대로 PASS다 — 그 테스트는 거부 판정을 `Ok(false)`로 주입해 "프레임을 읽지 않고 닫는다"만 고정하므로, B9 행에 이 구분을 적었다. 원복은 전부 백업 사본과 `cmp` 동일을 main이 재확인했다.

재검 R1/R2/R3(opus)은 셋 다 fix-then-pass, 남긴 것은 P3 여덟(둘은 같은 스크래치패드 문면)이다. 리포에 닿은 넷은 main이 직접 고쳤다 — §16.3/§16.5의 CLOSE 대역 정의 위치가 `0x1004`(`reverse/listen.rs:132`·`reverse/target.rs:205`)를 빠뜨려 네 경로로 채웠고, `0x1003`이 `RESOURCE_EXHAUSTED`(`server/mod.rs:153`)와 `REPLACED`(`reverse/listen.rs:112`) 두 이름에 겹친 사실을 §16.5 끝에 적었으며, `device_name` 인용을 doc comment 줄에서 `validate_device_name`(`wire.rs:393`)으로 옮겼고, B9 핀 테스트 칸에 `:2255`의 범위를 적었다. OSS-Fuzz 쪽은 README의 build.sh 설명이 V3-2/V3-3 이후 낡아 있던 것과 `mapfile`이 bash 4 빌트인이라 macOS `/bin/bash` 3.2에서 죽는 것 — `while read` 루프로 바꿨다. 전부 문서·스크립트라 게이트 재실행 없이 `linkcheck.py`·`r2-cite.py`(threat-model.md 인용 198건 problems 0)·`bash -n`·shellcheck만 다시 돌렸다.

게이트: fmt·clippy·arch·deny·win-gnu check·doc(host+win-gnu, `-D warnings`)·nextest `--test-threads=1` **1533 passed / 2 skipped**(기준선 1527 + 신규 6). macOS syspolicyd가 새로 빌드된 테스트 바이너리를 45분간 붙들어 `--list`가 멈춘 것처럼 보였지만 기다리면 지나간다.

이월과 사용자 액션. §16 발효는 §1 SC7 판정이 기록되는 소커밋에서 한다 — 상태 줄·일자·커밋, README Security posture 한 줄, DoD 4 문구, (나)면 `docs/PRD.md:311`. OSS-Fuzz는 `primary_contact` 실주소 기입, google/oss-fuzz PR, `infra/helper.py build_image qsh && build_fuzzers qsh` 검증(첫 실패 후보는 aws-lc-sys)이 사람 몫이다. WSL 배치 2(`m8-fuzz-20260907-1450`, 종료 예정 2026-09-10 14:48 KST) 결과를 확인해 m8-fuzz.md §4와 DoD 1을 닫고, 배치 1 부족분(타깃당 6.4~12.9h)을 재실행한다. Step 7b stateful broker fuzzer(`broker_ops`, `Clock` 주입 있음)는 이 뒤에 바로 붙이고 Step 8 perf 게이트는 그 뒤다. M9 이월 둘 — hint_alias 조회 키 trim(hosts.toml/trust.toml 이름 정규화와 함께), doctor `acl_principal_unmatched`/`acl_ca_auth_path_missing`(threat model g4). CLOSE `0x1003`의 이중 이름은 §16 발효 소커밋에서 값을 갈라 둘지 정한다 — 발효 전이라 §16.5의 "major 안 재배치 금지"에 걸리지 않는다. 코드 doc의 `BRIEF-7 §2.5` 인용은 Step 6이 남긴 `BRIEF-6` 관례를 따른 것이라 저장소 밖 문서 참조라는 점만 P3로 적어 둔다.

**(a)-추기 — Step 7b 완료 판정 (2026-09-10, main 세션).** 인벤토리 Workflow(R1 broker API·R2 ring fuzz·R3 문서 계약·R4 서버 사용처 + opus 비판 렌즈)가 설계 갈림길 여덟(Q1–Q8)과 P1 3·P2 10·P3 9를 올렸고 main이 전건 처분한 뒤 구현 Workflow(S1 core+하네스 sonnet/high → S2 fuzz 타깃 → S3 문서 → 게이트 → V1 하네스·변이 / V2 리팩터·계약 / V3 인프라 opus 렌즈 셋), 고침 Workflow 둘(Fix-A opus·Fix-B sonnet ∥ → Fix-C → 게이트 → V1′ 변이 재측정 ∥ V2′ 재검; Fix-D → V3′)로 닫았다. 착지한 것: `TtlWindow`(`session.rs`, `attached/closing/state/ttl_base` 네 값의 순수 `reap_reason`/`deadline` — `SessionHandle`은 한 줄 위임이라 행동 불변, 유닛 3), 하네스 `crates/qsh-core/tests/support/broker_ops_harness.rs`(고정 바이트 포맷 19 op, `arbitrary` 없음, `ModelSession` 오라클 — 시퀀스·control id·`ctl_after`·gap/byte-identity·메모리 상한·lease 전이·resume verify/rotate·TTL/reap), 17번째 타깃 `fuzz/fuzz_targets/broker_ops.rs`(`#[path]`로 하네스를 fuzz→crates 한 방향 include), 회귀 재생 `crates/qsh-core/tests/broker_ops_corpus.rs`(`fuzz/corpus/broker_ops/` 이름 있는 seed 15개를 매 nextest에 두 번씩 재생, `#[ignore] regenerate_seeds`가 seed를 다시 쓴다, 파일명 가드), 문서(protocol.md §13-6·§16.9 괄호, testing.md L2 clock 용례·L8 행·:124 정정, m8-fuzz.md §8 신설(DoD 1 분모 16 불변), fuzz/README 절 신설·`grep -v broker_ops` 루프·Cargo.lock 범위, oss-fuzz README 17·portable-pty 정정, threat-model :73, README :469, architecture §3), `.gitattributes`에 `fuzz/corpus/** -text`.

렌즈가 잡은 것과 처분. V1 P2 5·P3 4 — `deadline` 오라클이 `TtlWindow::deadline` 자신을 불러 자기참조였고(M4가 corpus 재생에서 GREEN), `Cursor`의 `ctl_after`에 오라클이 없었으며(M1 GREEN), `ReadAt`이 control을 버려 위조 금지가 offset 커서 경로를 안 덮었고, Spent 토큰이 센티널이라 역실험 R1(모델의 spent 기록 삭제)이 아무 단언도 안 깨뜨렸고, `sync_expiry`의 None arm이 하네스에서 도달 불가였다. V2 P1 1·P2 6·P3 3 — corpus 오염, m8-fuzz `## 8.` 중복, §2/§3/§7의 16, 하네스 줄 인용 2건이 `TtlWindow` +42줄에 밀림, testing.md:124가 protocol.md:344와 모순, §16.9 등식, 원래 불변식 목록에서 `default deny 유지`가 조용히 빠짐. V3 P1 1·P2 1·P3 3 — corpus에 fuzzer 산출 hex 이름 451개(원인은 main의 S2 브리프가 `cargo fuzz run broker_ops corpus/broker_ops`를 그대로 지시한 것 — README가 금지하는 "체크인 corpus를 첫 인자로"), oss-fuzz README의 portable-pty 전제 뒤집힘(Linux도 unix라 실제로 빌드된다, keyring도), fuzz/README "unaffected"가 절반만 참(nextest가 corpus 데이터를 읽는다), fuzz lock 117 패키지가 deny 밖, `.gitattributes`. 전건 채택. 451개는 지우되 V1의 반론(이름 있는 seed가 `take_owned` bit1을 한 번도 안 켜 M10/M12를 기계 입력만 잡았다)을 받아 seed를 8→15로 늘렸고, 재생 테스트가 hex 이름을 보면 붉어지게 했다.

main의 오판 하나를 Fix-A가 잡았다. G-5 근거로 적은 "reap은 살아남는 세션의 deadline만 맵에 넣는다"는 틀렸다 — `broker/mod.rs:837-838`은 doomed까지 전량을 넣고 `sync_expiry`(:870) 한 번만 부르며 doomed는 close(:878) 뒤 `forget`(:885)한다. 하네스가 doomed를 맵에서 빼는 것은 production 한 pass의 재현이 아니라 None arm(세션이 이미 레지스트리를 떠난 credential)을 확실히 태우는 유효한 API 사용이고, `purge_expired`는 production reaper가 부르지 않는 호출인데 하네스가 일부러 더했다(M9의 관측 경로가 바로 그 호출). 관측 가능한 갈림은 하나 — `closing`이라 doom을 면했지만 TTL이 지난 슬롯의 credential을 하네스는 그 자리에서 지우고 production은 `forget`까지 남긴다(어차피 `verify` freshness에 걸려 못 쓴다). 표 18행·fuzz 타깃·README 문면을 이 사실대로 다시 적었다(라운드 2).

변이 증거. 두 칸은 V1이 지적한 대로 (a′) `nextest -p qsh-core -E 'not binary(broker_ops_corpus)'` / (b) `-E 'binary(broker_ops_corpus)'`다(브리프의 "(a) GREEN/(b) RED"는 b⊂a라 문면상 불가능). 고침 전: M3(denied rotate가 축 덮어씀)·M10(`release_connection`이 `conn` 매칭)·M12(lease가 `physical: owner`)만 (a′) GREEN/(b) RED — 추가 검출력 3, 그러나 M1(`ctl_after` 전진 삭제)·M9(purge 경계 +1ms)·M11(rotate가 옛 `expires_at` 이월)은 어디서도 안 잡혔고 M4(`deadline`의 attached 분기 삭제)는 S1의 유닛만 잡았다. 고침 후 V1′ 재측정: 여덟 전부 (b) RED — M1 `:538`(seed 13), M3 `:1109`, M4 `:1169`, M9·M11 `:1211`(seed 11의 1ms 경계·seed 12), M10 `:926`·M12 `:893`(seed 9), 신규 M13(두 세대 지난 토큰이 계속 verify — `Entry`에 stale 해시를 달아 직전 세대는 죽게 두는 설계) `:1027`(seed 14). hex 451개를 지운 뒤에도 M3/M10/M12는 RED다. 원복은 매번 `cp`+`cmp`(V1 4/4, Fix-A 4/4, V1′ 4/4), `git checkout` 0회. G-8 메모리 상한(`entry_count ≤ live control + Σ ceil(len/chunk_max)`, `ring.rs:348-357`·`:363-378`·`:409-417`에서 유도)은 증명이 아니라 논증 + 1,684,976회 fuzz 오탐 0이 근거다.

게이트: fmt·clippy·arch·deny·win-gnu check·doc(host+win-gnu, `-D warnings`)·nextest `--test-threads=1` **1537 passed / 3 skipped**(기준선 1533 + `TtlWindow` 유닛 3 + corpus 재생 1; skipped +1은 `regenerate_seeds`의 `#[ignore]`). 라운드 2(문면·seed 15) 뒤 fmt·clippy(workspace, all-targets)·qsh-core nextest 920 passed / 3 skipped·fuzz build·4096회·linkcheck를 다시 돌렸고, 커밋 직전 워크스페이스 nextest를 main이 한 번 더 돌렸다. `cargo fuzz list` 17. `oss-fuzz-local.sh` 17 바이너리 + zip 17. 결정론은 종료 코드가 아니라 20회 출력의 정규화 sha 동일로 봤다. `fuzz-smoke.yml`은 `cargo fuzz list` 동적 순회라 수정 없이 새 타깃을 돈다 — 콜드 빌드 크레이트 145→180, 로컬 1m11s→2m38s, 4 vCPU 러너 콜드 캐시 회차 +4~6분 추정(실측 아님). `cargo deny --manifest-path fuzz/Cargo.toml check advisories` rc 0(로컬 1회).

이월. `broker_ops`는 DoD 1 분모(파서 16) 밖이고 자기 예산(CI 스모크 + WSL 전용 회차, m8-fuzz.md §8 기록)을 따른다 — 회차는 반드시 scratch 디렉터리를 첫 인자로(`cargo fuzz run broker_ops /var/fuzz/grown/broker_ops corpus/broker_ops`). M9 이월 셋 — `resume.rs:320-321` `purge_expired` doc("Called by the same reaper pass…")이 HEAD부터 틀림, fuzz lock의 `cargo deny` CI 스텝(지금은 README에 범위 밖 명시만), fuzz 크레이트가 edition 2021이라 하네스에 let-chain을 못 쓴다(두 크레이트 동시 컴파일). Q2의 `SessionHandle` 입력 축(attach 토큰 실물 동작)은 범위 밖으로 남긴다. 주석의 `BRIEF-7b`/`ARBITRATION-7b` 인용은 Step 6·7 관례대로 저장소 밖 문서 참조다.

### Step 8 — perf 게이트

**(a) 범위 판정 (2026-09-10, main 세션).** M8은 새 perf 수치를 세우지 않는다. `docs/ROADMAP.md:110`의 "perf 게이트"는 M4가 확정한 두 게이트(`docs/PRD.md:284` PTY p95 < RTT+10ms, `:285` throughput ≥ raw-quinn 80%)를 M8 HEAD에서 다시 세우고 그 자리를 문서로 확정하는 일이다. 근거 셋. M8 DoD(`docs/ROADMAP.md:112-113`)에 perf 항목이 없어 §2 체크리스트에도 번호가 없다. 두 수치는 M4 마감 노트(`docs/ROADMAP.md:80`, acceptance run 32986938847)가 이미 닫았고 지금도 `ci.yml` `acceptance` job이 `QSH_ACCEPTANCE_STRICT=1`로 PR마다 단언한다(`ci-ok` 필수). `docs/design/testing.md`가 남긴 "perf job은 아직"이라는 상태 서술이 요구하는 nightly 형태는 `.github/workflows/load.yml` 머리말이 같은 저장소 안에서 이미 기각했다 — trend 저장소가 없는 schedule은 소음만 더한다. 인벤토리는 `$SP/step8/`(R1 요구 수치·R2 기존 게이트·R3 M4 이력·R4 soak 상태 + opus CRITIQUE-8)이고, 후보 A(기록만)/B(재확인 + 대조)/C(PRD §13 전부) 중 B를 택했다. C는 `docs/PRD.md:289`의 30분 단절 축 하나 때문에 벽시계가 하나 더 붙어 마감이 종속된다.

M8이 실제로 재야 할 것은 Step 2·3이 데이터 경로에 넣은 방어선(주소 검증·accept 상한·세션/터널 쿼터)의 perf 비용이다. M4 정본은 그 이전 트리의 수치다. 여기에 둘을 덧붙인다. acceptance job은 dev 프로필로 돈다(`ci.yml` acceptance 스텝에 `--release`가 없고 루트 `Cargo.toml`에 프로필 오버라이드가 없다) — T2·soak이 릴리스 바이너리를 요구하는 것과 달라 릴리스 수치를 한 번 나란히 남긴다. `docs/ROADMAP.md:78`의 M4 DoD 문면은 아직 "1GB 포화 터널"인데 실제 게이트는 15초 시간유계 + `MIN_SAMPLES=200`(`crates/qsh-testkit/tests/tunnel_echo_under_load.rs`)이라 구속 문서를 구현에 맞춘다. 방어선은 config에 off 스위치가 없으므로("0/unset ⇒ default, never unlimited", `config.rs`·`admission.rs`·`quota.rs`) 대조는 설정이 아니라 트리 비교(Step 2 착륙 직전 커밋 worktree)로 하고, 그보다 먼저 두 게이트의 하네스가 그 방어선을 실제로 지나는지 코드로 판정한다.

**(b) 산출물.** 새 테스트·새 워크플로 0. ① 문서·주석 정정 — `docs/PRD.md:305`/`:306` 스테일 인용(실제 `:286`/`:287`) 10줄과 `ci.yml:179-182` 스테일 인용(`ci-ok` needs 실제 줄) 2줄, `docs/design/testing.md`의 perf job 상태 문장, `docs/ROADMAP.md:78` 마감 노트 추기와 `:110` 범위 문구. ② 실측 기록 — dev/release/방어선 세 축의 throughput 비율과 echo p95를 (d)에 남긴다. ③ M8 HEAD acceptance run 하나를 이 Step의 정본으로 지정한다.

**(c) 이월.** nightly perf job은 M10으로 넘긴다. 조건은 trend 저장소이고, 그것이 없는 채로 schedule을 붙이면 `load.yml`이 적은 소음 문제를 되풀이한다. `docs/PRD.md:289`(30분 단절 후 TTL 내 복구)와 `:290`(느린 파일·터널 stream이 PTY를 block하지 않음)의 직접 증거는 이 Step 범위 밖이며 M10 릴리스 게이트 입력으로 남긴다 — `:290`은 file transfer 표면이 v1에 없어(`docs/ROADMAP.md` M4 명시적 out) 대역 스트림 대체 하네스가 필요하고, `:289`는 M3의 60초 blackout 게이트(`reverse_blackout.rs`)의 30배 길이라 acceptance job에 못 들어간다.

**(d) 완료 판정.** 정본 acceptance run에서 throughput 비율 ≥ 0.80과 echo p95 < 측정 RTT + 10ms가 둘 다 서고 run id가 이 절에 적혀 있다. 릴리스 대조와 방어선 대조 수치가 이 절에 남아 있고 어느 쪽도 게이트를 넘지 않는다. 문서 정정이 같은 커밋에 들어가 있다. Step 8은 DoD 번호를 갖지 않으므로 §2에 줄을 더하지 않는다 — 판정은 이 (d)가 전부다.

**(a)-추기 — 실측과 판정 (2026-09-10, main 세션).** 구현 Workflow는 S1 sonnet(스테일 인용 12줄 + `testing.md` perf job 문장) → S2 sonnet/high(실측) → 게이트 → opus 검증 넷이다. S2는 Dave-MBP16(M1 Max, rustc 1.97.1, 커밋 dc01e04 트리)에서 세 구성을 각 3회 돌렸다(`$SP/step8/MEASURE-8.md`, 원 로그 `logs/`). 먼저 경로 판정. 두 하네스는 `LoopbackHarness::start_inner`(`crates/qsh-testkit/src/loopback.rs`)로 모이고, 그 안에서 프로덕션 `DEFAULT_*` 상수의 admission Gate와 `QuotaLimits::default()`를 쥔 `Server::run`(실제 accept 루프, `crates/qsh-core/src/server/mod.rs`)이 뜬다 — 방어선을 지난다. 그래서 대조는 Step 2 착륙 직전 커밋 `b0da849`(`admission.rs` 부재)를 worktree로 꺼내 release로 돌렸다.

| 구성 | throughput 비율 (3회) | raw / tunnel MiB/s | echo p95 여유 ms (3회) |
|---|---|---|---|
| dev (acceptance 구성) | 0.934 / 0.826 / 0.850 | 54~55 / 45~51 | 6.81 / 5.02 / 5.60 |
| release, HEAD | 0.998 / 0.950 / 0.947 | 108~111 / 102~108 | 2.18 / 2.14 / 2.21 |
| release, `b0da849` (방어선 이전) | 0.993 / 0.964 / 0.953 | 94~107 / 90~106 | 2.23 / 2.98 / 2.42 |

판정. 아홉 회차 전부 비율 ≥ 0.80, p95 여유 < 10ms. release는 dev보다 처리량이 두 배, p95 여유는 절반 이하로 더 넉넉하다 — dev 게이트가 보수적인 쪽이므로 릴리스 승격은 하지 않는다(Q2, `ci-ok` 필수 경로 비용). 방어선 전후는 회차 간 변동 폭 안에서 겹친다. 방어선이 얹은 것은 연결당 admission `decide` 한 번과 세션당 quota reserve 한 번이고 스플라이스 핫패스 밖이며, 이 하네스가 여는 연결·세션 수는 상한 근처에도 못 간다. dev 2회차 0.826이 아홉 회차 중 기준에 가장 가깝다 — 공유 러너에서 0.80 아래로 떨어지는 flake가 나올 수 있는 값이라 §6 감시 항목에 둔다. 유보 둘. 하네스는 RTT 자체를 찍지 않고 `elapsed − rtt` 여유만 남기므로 표의 p95는 여유값이다(DoD 4 판정식과 같은 수치). 연결 수립은 프로덕션 accept 루프를 지나지만 세션 백엔드는 `PipeFactory`, 포워드는 `LocalForwardHandle`이라 여기 echo는 실 PTY가 아닌 pipe echo다 — `testing.md`가 T1/T2를 가르는 것과 같은 유보이고, 실 PTY 축은 T2 시나리오 3과 soak echo 창 규칙이 release `qsh serve`에서 잰다. 정본 acceptance run: CI run 34452985893(커밋 `b4977d7`, acceptance job 102792774171, 2026-09-10 08:05 UTC) — `QSH_ACCEPTANCE_STRICT=1`로 `tunnel_throughput_meets_raw_quinn_ratio`(6.3s)와 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`(15.6s)가 둘 다 PASS. nextest는 통과한 테스트의 stdout을 남기지 않으므로 이 run의 실측값은 로그에 없고, 위 로컬 표가 수치 기록이다. (d)의 조건이 이 run으로 섰다.

### Step 9 — 실기기 mobility 캠페인 ≥60회 (DoD 3, 사람 몫)

M2가 20회를 조기 측정해 SC4/SC5를 실기기로 확인했고 SC3 판정을 N≥60으로 미뤄뒀다. M2 기록의 이월 1건 — 예산 내 복구 1/10의 지배 요인이 Tailscale underlay 재경로(~4–5 s)였고 qsh 자체 resume은 233–1076 ms — 를 이 캠페인이 분해 보고로 갈라야 한다.

### Step 10 — 마감

**(a) 선행 감사 (2026-09-10, main 세션).** 마감 공통 절차(`docs/ROADMAP.md` §2) 두 검사를 DoD 1~4가 열린 채로 먼저 돌렸다. 인벤토리 5(CLI.md·PRD.md·ADR·README·M8 증거) → opus 대조 → 반박 검증 2(지적 26건 전부 반영) → fixer 순이고 결과는 `$SP/step10/TAG-AUDIT.md`·`I4-readme.md`다. 절차 1(구속 문서 태그 대조): 대조 문장 62건 — 검증 43, 후속 마일스톤 명시 유예 11, 열린 DoD 종속 7, 대조 대상 아님 2(ADR-0015·0016은 예약됨이라 결정 절이 비어 있다), 충돌 1. 충돌 1은 `docs/CLI.md` §6.12 audit fail-closed 문장 — op 어휘에 없는 `session.resume`을 열거했다(정본 `crates/qsh-core/src/acl/registry.rs`; resume은 token을 실은 `session.attach`). 문면을 고쳤다. 열린 DoD 종속 7건은 PRD:222(DoD 1)·:286·:287(DoD 2)·:307(DoD 3)·:311(DoD 4), ADR-0009:68(DoD 3)·:99 후반절의 24h soak 판정(DoD 2)이며 해당 DoD가 닫히는 순간 검증으로 옮긴다. 추기 09-11: DoD 1이 닫혀 PRD:222를 검증으로 옮겼다 — 검증 44, 열린 DoD 종속 6. 절차 2(README 동기화): 대조 20항목 중 불일치 5 — 상태 문단과 Roadmap 표의 M8 누락, quota Known limitations가 이미 착륙한 방어선을 "없다"고 서술, audit fail-closed 열거가 `session.attach`·세션 쓰기를 빼 실제 거부 범위보다 좁음, Development 절이 게이트가 아닌 `cargo test`를 대안으로 제시 — 전부 고쳤다. 부수 정정 셋: `docs/CLI.md` §6.12 quota 키 수 10→9(`crates/qsh-core/tests/quota_docs.rs` 핀과 일치), `docs/ROADMAP.md` M9 명시적 out의 pin 방향 축 예약처(ADR-0017이 아니라 번호 미배정 별도 ADR — ADR-0017 결정 5), ROADMAP M10 수용 기준에 PRD:289/:290 이관 행(PLAN.md가 M9판으로 교체돼도 귀속이 남도록). `docs/campaigns/m8-adversarial-load.md` §5 환경 표도 채웠다(RUN 9 당시 미기록 값은 재조회 표시).

**(b) 마감 커밋에 남긴 것.** DoD 1·2·3·4 체크박스와 위 7건의 검증 이동. `docs/CLI.md:3` 상태 헤더(v0.10 = M3 Step 8에서 멈춰 M5~M8 개정 이력이 없다 — 한 줄 개정). ROADMAP M8 마감 노트(초안 `TAG-AUDIT.md` §7: 절차 1·2 수치, ADR-0009:99의 RSS/fd 축은 DoD 5로 닫히고 24h 판정은 DoD 2 소관이라는 분리, ADR-0014는 `제안됨` 상태 그대로 M9 S10 귀속). ROADMAP M8 ✅와 PLAN.md 전면 교체(M9 계획). notarization 착수는 Apple 계정이 필요한 사람 몫이라 M10 리드타임 항목으로 표기만 한다.

**(c) 완료 판정.** §2 DoD 1~5 전부 `[x]`, 절차 1 충돌 0, 절차 2 불일치 0, ROADMAP M8 마감 노트가 run id·캠페인 문서를 인용, 마감 커밋 CI green.

## 4. 실행 환경

72시간 fuzz 누적과 24h soak은 heavy compute다. 로컬 개발 머신이 아니라 전용 호스트에서 돌린다(전역 지침의 머신 라우팅). 캠페인 기록은 M2·M6·M7 선례대로 `docs/campaigns/`에 사전 정의 후 실행한다.

## 5. M7에서 이월된 항목

| # | 항목 | 소유 step |
|---|---|---|
| i | bounded pull executor + `RESOURCE_EXHAUSTED` (측정된 512 천장) | 종결 (Step 6 (a) 2026-09-10: ADR-0011로 MCP 어댑터가 사라져 512 천장의 재현 경로가 없다. `session_read` 호출처는 CLI `run_session_read`와 서버 핸들러뿐 — 판정 13) |
| ii | `Ops::exec`(`ops/exec.rs:81`) 호출당 `new_multi_thread()` 런타임 | Step 5 (5d 완료 2026-09-08: `exec_run`이 `connect_runtime()`을 공유) |
| iii | pull당 fd 선형 증가 | Step 5 (5e 24h 런의 `FD_GROWTH_CLIENT` 판정 대기 — steady 4분위 규칙) |
| iv | 고아 `.tmp{pid}-{N}` 청소 부재 | Step 5 (5d 완료 2026-09-08: `fsutil::write_atomically` 통합 + `sweep_stale_temp_files`, 1h+ESRCH 또는 24h) |
| v | `qsh trust add dave@box --address …` 오도 제안 | Step 6 (완료 2026-09-10: `ops/host.rs` `hint_alias`가 `user@`를 벗기고 빈 별칭은 `INVALID_ARGUMENT`, `qsh host get`·`qsh exec` 두 경로 공유. 테스트 `host_not_found_message_never_leaks_a_user_at_prefix` 외 4건) |
| vi | trust store read-modify-write 잠금 부재 | 종결 (M7 Step 7-1이 이미 닫음, Step 6 렌즈 1 재확인 2026-09-10: `TrustStore::lock` `ops/mod.rs:548`·`:575`·`:699`) |
| vii | invites.toml CLI/데몬 lock-free 창 | 종결 (M7 Step 7-1이 이미 닫음, Step 6 렌즈 1 재확인 2026-09-10: `InviteStore::lock` `ops/mod.rs:607`·`trust/pairing.rs:587`) |
| viii | device_name 길이 상한 + Unicode bidi/homoglyph 스푸핑 | Step 6 (완료 2026-09-10: `wire::validate_device_name` — 1..=64바이트, 제어·bidi·zero-width 거부, `PairingError::InvalidDeviceName`; homoglyph는 탐지 대신 fingerprint 병기, protocol.md §15.5 표) |
| ix | forward-route live carrier·`-R` 자동 재발행 (ROADMAP §3 표가 M8 소유로 등재) | 종결 (ADR-0018, 2026-09-10: v1 터널 수명은 connection에 결합, live carrier 미구현, `-R` 자동 재발행 P1 — 판정 13) |
| x | `ControlLink`/`DataLink` enum → trait 전환 (ADR-0005 P0 부채, M3→M7 연쇄 이월) | P1 재기록 — M8도 트리거하지 않음 |

## 6. 리스크

- **SC7 리드타임은 이미 만료**다(§1). wire freeze 일정이 조직 액션에 묶여 있다.
- **perf 게이트 flake 여지 (2026-09-10, Step 8).** 로컬 dev 프로필 실측에서 throughput 비율이 0.826까지 내려간 회차가 있었다(기준 0.80). 공유 러너 acceptance job이 0.80 아래로 떨어지면 제품 회귀보다 러너 변동을 먼저 의심하고 재실행 한 번으로 가른다. release 프로필은 0.947 이상이라 여유가 있다.
- **DoD 1·2·3은 전부 벽시계**다. 압축되지 않으므로 순서가 곧 일정이다 — Step 1을 가장 먼저 세운 이유.
- **graceful re-exec(fd 보존 handoff)** 는 ROADMAP §4 리스크 4가 M8 stretch로 비용 산정만 요구한다. 구현은 범위 밖. **산정 완료(2026-09-10)** — `docs/design/reexec-estimate.md`(리더 5 → opus 패널 3 → judge → 반박 검증 2 → fixer, 지적 22건 반영). 결론은 M8 구현 0. 값싼 선행 조치 H0(`docs/deploy/service.md`의 재시작 고지, `docs/CLI.md` §6.12 한 줄)는 같은 커밋에서 반영했고, H4(execve 제자리 handoff 4.2ew)·H5(supervisor 분리 6.5ew)는 P1 결정 입력으로 남긴다.
- **notarization은 M10이 아니라 M8 중 시작**(ROADMAP M10 크기 주석). 리드타임 항목이라 §1과 같은 성질이다.
- **CI flake (2026-09-02, run 33601809635, docs-only 커밋 `b0da849`)** — `qsh-cli::attach_ops::a_teardown_waits_out_a_detach_that_is_still_flushing`이 `ubuntu-24.04-arm` leg에서만 `left: Applied, right: Unconfirmed`로 실패, 재실행 통과. 테스트는 host를 SIGSTOP한 뒤 detach flush가 ack를 못 받아 `Unconfirmed`이길 기대하는데, 빠른 러너에서는 SIGSTOP 전에 이미 쓴 바이트의 ack가 도착해 `Applied`가 된다 — 제품 결함이 아니라 테스트의 순서 가정(정지 → 쓰기가 아니라 쓰기 → 정지). Step 2 착륙 후 별도 소커밋으로 결정론화(ack가 불가능한 상태를 먼저 만들고 나서 쓰기). **해결(2026-09-03)**: 다시 보니 테스트는 이미 정지 → 쓰기 순서였다. 진짜 원인은 SIGSTOP의 비동기성 — `kill`은 신호를 큐에 넣고 바로 돌아오고, 멀티스레드 대상은 한 스레드가 신호를 꺼내 group stop을 실행하기 전까지 나머지 스레드(QUIC 소켓을 돌리는 tokio 워커)가 계속 돈다. 그 틈에 host가 "two\n"을 ack하면 `Applied`. 테스트는 `waitpid(host, WUNTRACED)`로 스레드 그룹 전체가 멈춘 것을 커널이 보고한 뒤에 쓴다(직접 자식이고 그 구간에 다른 reaper 없음 확인). 로컬 20/20.
