# QSH 로드맵

**상태:** 확정 (구현과 어긋나는 내용을 발견하면 이 문서를 먼저 갱신한다)
**작성일:** 2026-08-17 · **개정:** 2026-08-21 — 프로덕션 준비도 감사(HEAD `1d5d1b0`) 반영: M3/M5/M7/M8/M9 범위·수용 기준 증보, "마일스톤 마감 공통 절차" 신설. 새 마일스톤은 만들지 않았다 — 감사가 찾은 갭 전부를 기존 마일스톤에 명시 귀속시킨 것이 이 개정의 전부다. · **개정 2:** 2026-09-09 — 사람용 CLI 설계(design.html, 2026-09-08) 확정 결정 반영: 신규 `M9 — 사람용 표면`(4.3ew)을 M8과 구 M9 사이에 신설하고, 구 `M9 — 릴리스`는 `M10 — 릴리스`로 번호만 옮긴다. notarization 리드타임이 CLI 설계 일정을 막지 않게 하려는 결정(ADR-0012~0017, DECISIONS.md Q1). · **개정 3:** 2026-09-19 — 사용자 결정으로 SOCKS `-D`를 P1에서 M9 범위로 당긴다(ADR-0019).
**현재 위치:** M10(릴리스) 실행 중 — 계획은 `PLAN.md`. M9는 코드 스텝과 마감 감사를 마쳤고 DoD 1(SC1 스톱워치 재측정 3회, `docs/campaigns/m9-stopwatch.md`, M7 DoD 1 baseline에 종속)만 사람 몫으로 열려 있다. M8은 코드 스텝을 마쳤고 DoD 1(파서 타깃당 누적 ≥72 fuzz-hours, crash 0 — 2026-09-11 마감, `docs/campaigns/m8-fuzz.md`), DoD 2(24h/100-session soak — 2026-09-21 마감, `docs/campaigns/m8-soak.md` run #6 PASS), DoD 5(적대적 부하 하네스 — 2026-09-08 마감, `docs/campaigns/m8-adversarial-load.md`)는 닫혔다. 열린 채 M10으로 넘어간 넷(`PLAN.md` §0.2)은 M7 DoD 1 스톱워치 3회 측정(`docs/campaigns/m7-stopwatch.md`, 예행 1회만 끝났다), M8 DoD 3(실기기 mobility ≥60회), M8 DoD 4(wire freeze 발효 + 독립 리뷰 계약), 그리고 위의 M9 DoD 1이다. SC7 외부 보안 리뷰 예약은 M5→M6→M7→M8 네 번째 이월이고 wire freeze 리드타임은 이미 만료됐다. M7판 계획은 `docs/history/m7-plan.md`, M8판은 `docs/history/m8-plan.md`, M9판은 `docs/history/m9-plan.md`에 있다.

이 문서는 P0 MVP까지의 canonical 마일스톤 기록이다. 각 마일스톤의 "수용 기준"이 곧 그 마일스톤의 **완료 정의(Definition of Done)** 다 — 수용 기준을 통과하는 테스트/시연 없이는 마일스톤을 닫지 않는다. SC 번호는 PRD §15 성공 기준의 순번이다 (SC1: 신규 두 장비 5분 내 연결, SC2: 한 명령 접속, SC3: 네트워크 전환 ≥95% 유지/resume, SC4: resume 가능한 단절에서 output 무손실, SC5: client crash가 remote PTY를 죽이지 않음, SC6: 모든 privileged op의 ACL 추적성, SC7: 공개 beta 전 독립 보안 리뷰).

총 크기: 약 31.5–32 engineer-weeks (1인 기준) — 기존 24.5ew에 신규 M9(사람용 표면, 4.3ew)를 더한 28.8ew에, 2026-09-19에 M9로 당긴 SOCKS `-D` 1.6~2.0ew(추정)와 2026-09-24 M10 갱신분(1.5 → 2.6ew)을 더한 값.

## 1. 시퀀싱 원칙

순서 자체가 설계 결정이다. 근거를 잊으면 순서를 다시 흔들게 되므로 기록해 둔다.

1. **Typed op layer와 JSON envelope는 M1부터.** 나중에 붙이면 사람용 경로와 기계용 경로가 각자 오류 체계·타임아웃 모델·`session_ref` 파서·ACL 호출 지점을 길러버리고, 재통합 작업은 영원히 우선순위에서 밀린다. CLI.md §11이 요구하는 "세 frontend가 같은 typed operation을 호출"은 첫 코드부터 지켜야 지켜진다.
2. **Walking skeleton은 PTY가 아니라 exec.** `qsh init → serve → exec --json`이 identity·mTLS·QUIC·framing·op dispatch·ACL chokepoint·JSON envelope·exit code라는 리스크 척추 전체를 관통하면서도 expect 하네스 없이 CI에서 완전 자동화된다. PTY는 같은 척추 위에 터미널 서브시스템 전체를 얹는 일이라 검증 인프라가 먼저 필요하다.
3. **PTY 세션 모델은 headless로 먼저 검증.** CLI.md가 `session open/read/write/resize/close`를 기계 명령으로 정의해 준 덕분에, termios 코드를 한 줄도 쓰기 전에 broker 전체를 JSON 명령으로 검증할 수 있다. TUI는 이미 검증된 broker의 얇은 소비자로 나중에 얹는다.
4. **역방향(M3)이 터널(M4)보다 먼저.** 터널은 role 모델(연결 방향과 세션 역할의 분리) 위에 얹힌다. 터널을 정방향 전용으로 먼저 만들면 역방향 도입 시 재작업이 된다. `-R` over reverse connection이 진짜 흥미로운 케이스다.
5. **ACL은 두 단계로 분리.** 인가 **지점**(`Authorizer::check()` chokepoint, 모든 op 앞)은 M1부터 존재하고(초기 정책: pinned peer 전부 허용), 정책 **엔진**(TOML, principal/wildcard 매칭)은 M5에서 채운다. 지점을 늦게 넣으면 전 op를 다시 감사해야 하고, 그건 보안 리뷰가 반드시 찾아내는 결함이다.
6. **Chaos 하네스는 M2에서 resume과 함께 구축.** resume 정확성은 fault 주입 없이 테스트 불가능하고, SC3은 PRD에서 가장 위험한 숫자다. 측정 도구는 측정 대상과 같이 만든다 (M8은 캠페인 실행이지 도구 개발이 아니다).
7. **M1부터 지켜야 할 선행 불변식** (기능은 나중이어도 구조는 지금): (a) 모든 출력 바이트는 생성 지점에서 sequence 태깅 (M2 replay의 전제), (b) 모든 op 앞에 `Authorizer::check(principal, action, resource)` 호출 + audit 기록, (c) connection 방향(initiator/responder)과 세션 역할(controller/target)을 독립 축으로 유지 (M3 reverse의 전제).

## 2. 마일스톤

### 마일스톤 마감 공통 절차 (2026-08-21 감사 개정)

모든 마일스톤은 자신의 수용 기준에 더해 다음 두 검사를 통과해야 닫힌다. 근거: M2가 자기 계약 두 건(SIGTERM drain — `docs/CLI.md` §6.12의 "(M2, ADR-0003)" 태그 문장, exec 환경 위생 — 같은 문서의 pinned env 문장)을 어긴 채 Done으로 표시될 수 있었던 구조적 원인은, DoD 목록과 구속 문서의 마일스톤 태그를 대조하는 절차가 없었다는 것이다.

1. **구속 문서 태그 대조** — `docs/CLI.md`·`docs/PRD.md`·`docs/adr/`에서 이 마일스톤 번호가 태그되었거나 이 마일스톤이 구현한 기능을 계약으로 확정한 문장을 전수 대조해, 각각이 (i) DoD 항목으로 검증되었거나 (ii) 후속 마일스톤에 명시 귀속된 유예임을 확인한다. 어느 쪽도 아닌 문장이 하나라도 있으면 마일스톤을 닫지 않는다.
2. **README 동기화** — README(SC1의 산출물)의 기능 목록·Known limitations·인터임 위험 고지를 마일스톤 종료 시점의 실제 동작·권한과 일치시킨다. 인터임 고지가 실제 권한보다 좁으면 그 자체가 결함이다.

### M0 — 결정·스캐폴드·CI ✅ 완료 (2026-08-17)

- **범위:** 설계 결정 6건 확정(ADR-0001~0006), 스펙 개정(PRD v0.3, CLI v0.2), cargo workspace 5 crate + xtask arch-lint, CI 4-target matrix, README/CLAUDE.md, `qsh version --json` 수직 절편.
- **수용 기준 (달성):** 4-target CI 구성, arch-lint가 의존 위반 시 실패(주입 테스트로 확인), 23개 테스트 green, `version --json`이 `qsh.cli/v1` envelope 출력.
- **크기:** 1ew

### M1 — Walking skeleton ✅ 완료 (2026-08-18)

- **범위:** `qsh init`(device identity 생성, keystore auto/platform/file + headless fallback), `qsh serve`(QUIC listener), `qsh trust add --fingerprint`, `qsh exec host --json -- cmd`. QUIC + TLS 1.3 상호 인증(pinned cert), frame codec 실사용, typed op layer(`version.get`/`exec.run`/`identity.init`/`trust.*`; schema.get 계약은 CLI.md에 존재하나 구현은 M7), JSON envelope·exit code 계약(§4), `Authorizer::check()` chokepoint(임시 allow-all-pinned) + op별 audit line, localhost 통합 하네스. hosts.toml 기반 host directory(M7)가 도입되기 전까지 `qsh exec <host>`의 host→주소 해석은 trust store(trust.toml)의 pinned peer(name→address)가 단일 출처다.
- **명시적 out:** PTY, 세션, resume, private CA, invite code pairing, 터널, reverse, 정책 파일.
- **수용 기준 (DoD, 달성):**
  - `qsh exec host --json -- sh -c 'echo out; echo err >&2; exit 7'` → 프로세스 exit 7, `ok:true`, 올바른 `stdout_b64`/`stderr_b64`/`remote_exit_code:7` — `crates/qsh-cli/tests/exec_e2e.rs`(실 subprocess) + `crates/qsh-testkit/tests/exec_loopback.rs`(in-process).
  - 비신뢰 peer로 같은 명령 → exit 255 + `AUTH_FAILED` — 같은 파일; host audit.log에 handshake deny 기록.
  - Handshake matrix 16종 전부 기대 결과 — `crates/qsh-transport/tests/handshake_matrix.rs`.
  - `-v` 진단은 stderr에만, stdout은 파싱 가능한 JSON 하나 — `crates/qsh-cli/tests/jsonl_purity.rs`.
  - 부수 산출: golden fixture(`crates/qsh-cli/tests/fixtures/cli-v1/`, schemars 스키마 검증 + ErrorCode 도달성), exit-code matrix(`exit_code_matrix.rs`) — 모두 CI 4-target matrix에서 실행.
- **착수 시 읽을 문서:** `docs/design/protocol.md`(ALPN, frame, verifier, keep-alive), `docs/design/architecture.md`(ops layer, identity/keystore, config 경로), `docs/design/testing.md`(L0/L1/L3/L6), `docs/CLI.md` §2–§4·§6.8과 init/trust 계약, ADR-0001/0002/0006.
- **크기:** 3ew

### M2 — 세션 broker + PTY + resume ✅ 완료 (2026-08-19)

- **범위:** (a) headless broker — 세션 registry, ReplayRing(누적 byte offset sequence), writer lease, resume TTL, gap 산출 + `session.open/get/read/write/resize/close`·`session.list` op, (b) POSIX PTY(setsid, controlling tty, resize, signal, reaping, login shell env) + 대화형 TUI(`qsh user@host`, `qsh attach`, detach key), (c) connection migration(`rebind`) + resume(`session.attach` + resume token + last_seq) + replay/dedup + `session.gap` 이벤트. **chaos proxy 하네스**(`docs/design/testing.md` L4)와 recovery 텔레메트리(`recovery ∈ {migrated,resumed,failed}` + time-to-recovery)를 같이 구축.
- **명시적 out:** reverse, 터널, ACL 정책 파일, multi-attach, local echo prediction.
- **수용 기준 (DoD, 달성):**
  - Property test: 임의의 append/read interleaving에서 gap 이벤트가 없는 한 반환 바이트 연결 == 원본 stream suffix (byte-identical, 무손실·무중복) — SC4의 property 표현. (`crates/qsh-core/src/broker/ring.rs`의 naive-`Vec`-oracle property + stateful follower property.)
  - `qsh user@host`로 실제 셸 사용 가능 — bash/zsh, vim, tmux, `claude`가 동작하고 resize 전파. (`crates/qsh-cli/tests/tui_expect.rs` strict 모드 17/17 — 2026-08-19 수동 certify가 5종 정본, CI `acceptance` job이 bash/zsh/vim/tmux 상시 게이트.)
  - **클라이언트를 `yes` 실행 중 `kill -9` → reattach → last_seq부터 이어붙인 결과가 기준 stream과 byte-identical** (SC4). remote PTY와 자식 프로세스는 클라이언트 사망에 생존 (SC5). (`crates/qsh-cli/tests/session_kill9.rs` — 실제 attach 프로세스 SIGKILL, ring 밖 producer-corpus oracle 포함.)
  - Chaos proxy `repath()` → connection migration으로 세션 무중단; `sever()` → 2초 내 재dial + resume. (`crates/qsh-cli/tests/attach_recovery.rs` — driver 자신의 `qsh::recovery` 레코드로 단언, `DETECTION_CEILING`으로 감지 예산의 순환 참조 차단.)
  - 실기기 Wi-Fi↔테더링 전환 20회 수동 캠페인, recovery 필드 기록 (SC3 조기 측정). (2026-08-19 수행, `docs/campaigns/m2-mobility.md` — path 사망 10회 전부 자동 resume·세션 사망 0·gap 0으로 SC4/SC5 실기기 확인; 예산 내 복구 1/10은 Tailscale underlay 재경로(~4–5 s)가 지배 요인으로 M8 백로그 이관, qsh 자체 resume은 233–1076 ms. SC3 판정은 M8 N ≥ 60.)
- **사후 감사 (2026-08-21):** 완료 표시 후 감사에서 M2 귀속 계약 부채 2건 발견 — ① `qsh serve`의 SIGTERM graceful drain 미구현(`docs/CLI.md` §6.12 "(M2, ADR-0003)" 문장 위반; SIGTERM 시 PTY 자식이 고아로 살아남음이 실측 확인됨), ② `exec.run`이 serve 프로세스 환경을 `env_clear` 없이 상속하고 client가 `PATH`를 지정할 수 있음(같은 문서의 "호스트가 고정한다" 문장 위반). 상환은 M3의 감사 개정분(PLAN.md Step 3.5)이 소유한다. 재발 방지가 위 "마일스톤 마감 공통 절차" 1번이다.
- **크기:** 5ew

### M3 — 역방향 ✅ 완료 (2026-08-24)

- **범위:** `qsh listen`(controller), `qsh reverse controller`(target, 등록 + heartbeat + 백오프 재접속), `host.reverse` ACL action 검사 지점, reverse host가 `hosts`에 `connection_mode:"reverse"`로 표시, `qsh attach <name>`이 역방향 연결 위에서 동작. 연결 방향/세션 역할 축 실사용.
- **감사 개정 (2026-08-21) 추가 범위:** ① **M2 계약 부채 상환** — `qsh serve`(및 M3의 두 상주 모드) SIGTERM graceful drain(`docs/CLI.md` §6.12 문장의 이행)과 `exec.run` 환경 위생(`env_clear` + 호스트 고정 key 재적용). ② **세션 소유권 P0** — `session.control` action(write/resize)을 세션 opener principal에 결합. PRD §6이 조회·읽기·종료는 교차 기기 ACL 범위로 명시 허용하므로 결합 대상은 control 값 op뿐이다. M5 정책 어휘(resource-ownership 축)의 선행 결정이며, M5로 미루면 정책 어휘가 소유자 개념 없이 먼저 굳는다.
- **명시적 out:** relay, NAT traversal, discovery.
- **수용 기준 (DoD):** NAT 뒤 target이 `qsh reverse` → controller에서 `qsh attach`로 target의 셸 획득. target 네트워크를 60초 차단 → 재등록되고 **같은 세션**이 resume. `qsh hosts --json`이 forward/reverse를 함께 반환(§6.1). controller reachability 요구가 docs와 doctor 메시지에 명시.
  - **(감사 개정)** 자식 셸이 살아 있는 `qsh serve`에 SIGTERM → 전 세션 close 절차 → `session.closed{reason:"closed"}` 송신 → drain 완료 후 잔존 자식 process group 0 (L5 실프로세스 테스트). `exec.run` 자식에서 serve 환경 마커가 보이지 않고 client의 `PATH` 지정이 무시됨.
  - **(감사 개정)** 타 principal 세션에 대한 `session.write/resize`가 거부되고 audit에 deny가 남음(소유권 P0). 병렬 동시 등록(같은/다른 fingerprint)·병렬 다중 세션 경합 테스트가 존재 — 순차 시나리오만으로 마일스톤을 닫지 않는다.
- **크기:** 2ew + 0.5ew(감사 개정분)

### M4 — 터널 ✅ 완료 (2026-08-27)

- **범위:** `-L`/`-R`, `qsh tunnel open/close`, `qsh tunnels`. TCP 연결당 QUIC stream 1개, stream 우선순위로 PTY 보호, remote forward는 loopback bind만(§9). forward/reverse 연결 양쪽에서 동작.
- **명시적 out:** SOCKS `-D`(P1), file copy, UDP forwarding.
- **수용 기준 (DoD):** `-L 8080:localhost:3000` 후 `curl localhost:8080` 도달. `-R` non-loopback bind 요청이 **거부**되는 명시적 테스트. Throughput ≥ 동일 프로세스에서 측정한 raw-quinn 기준의 80%. **1GB 포화 터널과 병행한 PTY echo p95 < RTT + 10ms** (§13). `-D 1080` → `UNSUPPORTED` + "P1" 메시지.
- **크기:** 2ew
- **마감 노트 (2026-08-27):** DoD 5항목 전건 테스트 증거로 통과(PLAN.md M4판 §1 체크리스트 — perf 게이트 정본은 CI `acceptance` run 32986938847). 마감 절차 1·2(태그 대조·README 동기화) 완료 — 구속 문서 충돌 0건. Step 8이 확정한 resume 의미론: migration(path rebind)은 터널을 투명 생존시키고, 연결 손실→resume에서 터널 스트림은 깨끗이 종료된다(세션만 §10 resume). **forward-route live carrier**(-L forward가 recovery 후에도 신규 연결을 서비스) 는 구현하지 않기로 확정하고 M5 입력으로 명시 이관 — 근거는 PLAN.md M4판 Step 8 (a)-추기(git 이력). M8 Step 8 추기(2026-09-10): DoD의 "1GB 포화 터널" 문면은 M4 Step 7 구현에서 15초 시간유계 + 최소 200표본(`crates/qsh-testkit/tests/tunnel_echo_under_load.rs`의 `MEASUREMENT_DURATION`·`MIN_SAMPLES`)으로 대체됐다 — 포화 상태를 유지한 채 재는 것이 목적이고 1GB는 그 수단이었으므로 게이트의 뜻은 같다. 문면은 이 추기로 갈음하고 DoD 줄은 고치지 않는다. M9 추기(2026-09-19): 사용자 결정으로 `-D`를 구현한다(ADR-0019). 위 DoD의 `-D 1080` → `UNSUPPORTED` 항목은 M4 시점의 기록으로 남기고, 현재 계약은 ADR-0019와 `docs/CLI.md` §6.9가 정한다.

### M5 — ACL 정책 + audit ✅ 완료 (2026-08-28)

- **범위:** TOML 정책 로더, principal 매칭(fingerprint·CA 발급 user/device), action wildcard(`session.*` 형태, 후행 `.*`만), default-deny, PRD §9 action 전체(미구현 기능의 `forward.socks`/`file.*`는 정의하되 항상 deny — 2026-09-21 주: `-D`가 오른 뒤 `forward.socks`는 미구현이 아니라 설계상 항상 deny다, ADR-0019 결정 6·8c603bc), `qsh acl check`, 전 privileged op의 구조화 audit.
- **감사 개정 (2026-08-21) 추가 범위:** ① **audit 수명주기** — "audit 완전성"에서 한 걸음 더: `[audit]` config(회전·크기 상한·retention), 런타임 스레드 밖 비동기 쓰기(현재 동기 blocking I/O), 디스크 만실 시 fail-closed 정책(현재 ENOSPC fail-open). ② **resource-ownership 축** — M3가 넣은 opener-principal P0 결합을 정책 어휘로 승격(리소스에 소유자 개념, 정책이 owner 기준으로 매칭 가능). ③ **거부 메시지 균일성** — deny 응답이 거부된 action/capability를 노출하지 않게 통일. 선례는 `reverse/admit.rs`의 단일 문면 테스트이고, 현재 forward 경로(`server/mod.rs`)의 deny 메시지는 action 이름을 노출한다 — interim allow-all에서는 정보량 0이지만 M5 정책이 켜지는 순간 capability 열거 oracle이 된다.
- **수용 기준 (DoD):** `qsh acl check` 결과 == 실제 enforcement 결과 (같은 코드 경로임을 표 기반 테스트로 증명). **op registry를 열거해 audit 레코드 없는 op가 있으면 실패하는 테스트** (SC6). Property test: 임의 정책에서 어떤 rule도 커버하지 않는 action은 반드시 Deny.
  - **(감사 개정)** 모든 `PERMISSION_DENIED` 응답 문면이 동일함을 op 전수로 단언하는 테스트. audit 수명주기 동작 테스트(회전 트리거·상한 준수·디스크 만실 fail-closed).
- **크기:** 2ew + 0.5ew(감사 개정분 — M3 선례 형식, PLAN.md M5판 §4.3 제안 수용)
- **마감 노트 (2026-08-28):** DoD 5항목 전건 이름 붙은 테스트로 통과 — ① `acl check` 동치는 `acl_check_equivalence.rs` 9행 3-way 표(check·실거동·audit 레코드)와 `Policy::decide`의 `pub(crate)` 좁힘(비테스트 호출 지점 정확히 2곳)이라는 구조 증명, ② SC6 op registry는 `acl_registry.rs` 3층(CLI.md §2.5 양방향 대조·`Body` variant 전수 분류·13행 실구동 audit 단언) + `acl_registry_audit.rs`(실 QUIC 필요 3행), ③ property test는 `policy.rs`의 naive-coverage-oracle proptest, ④ 문면 균일성은 `acl_uniformity.rs`의 `DENY_SEAMS` 14행 전수(항상-deny 3종은 wire op 부재로 행 없음 — 명시 예외), ⑤ audit 수명주기는 `audit/writer.rs`의 회전·retention·queue 포화·ENOSPC fail-closed 4종. 마감 절차의 태그 대조·README 동기화·정본-구현 최종 대조에서 구속 문서 충돌 0건. enforcement는 Step 6a에서 acl.toml 정책으로 전환됐고 `AllowAllPinned`은 `#[cfg(test)]` 전용으로 강등. M4 이관 (v)(forward-route live carrier·`-R` 자동 재발행 부재)는 §3 유예 가드레일 표에 M8 소유로 등재(이 커밋). **SC7 외부 보안 리뷰 예약은 코드 밖 조직 액션이라 이 저장소에서 완결 불가 — 미완 상태로 명시 이월, 운영자 확인 필요**(리뷰는 wire freeze(M8) 6주 전 예약이 조건, §4 리스크 5).

### M6 — MCP adapter ✅ 완료 (2026-08-31)

- **범위:** `qsh mcp` stdio, CLI.md §8.2의 tool 12종, tool schema는 CLI와 **동일한 Rust 타입에서 생성**(schemars), long-poll `read_session`, 취소 시맨틱(§8.4), interactive prompt 금지.
- **수용 기준 (DoD):** stdio conformance 하네스(initialize → tools/list == checked-in fixture → open/write/read/close 시나리오). Claude Code 실접속으로 원격 명령 실행. `read_session` 취소 후 세션 상태 `running` 유지. adapter의 의존성 ban(arch-lint)으로 subprocess/CLI 재파싱 원천 봉쇄. `-vv`에도 stdout에 JSON-RPC 외 바이트 0.
- **크기:** 1.5ew
- **마감 노트 (2026-08-31):** DoD 5항목 전건 이름 붙은 증거로 통과 — ① conformance 하네스는 `mcp_conformance.rs`(raw JSON-RPC client, PLAN 4.1 #5 결정대로 rmcp client 비사용): initialize→`tools/list`==`fixtures/mcp/tools_list.json`(12종, `REQUIRED_MCP_FIXTURES` 양방향 set-equality 등록) + open/write/read/close·exec·tunnel 실구동 12종 전수, ② Claude Code 실접속은 `docs/campaigns/m6-mcp.md` — 사전 고정 C1–C5를 2회차 연속 충족, 회차 2는 stream-json의 MCP 프레임 원문으로 nonce 왕복 byte-exact 판정, ③ 취소는 `cancelling_a_pending_read_session_leaves_the_session_running_and_writable`(취소 후 `running`·writer lease 생존·수신 프레임 전수 id-핀·종료 후 stdout 정적) — rmcp 3.1.4 `local_ct_pool` 구조 보장으로 어댑터 취소 코드 0줄, ④ arch-lint ban은 xtask `ModuleBan`에 `crates/qsh-cli/src/mcp/` 스코프 3토큰(`std::process`·`Command::new`·`Stdio::piped`) + 단위 테스트 4건, ⑤ stdout 순수성은 `-vv` 실측 테스트 2건 + rmcp debug-log 페이로드 유출 차단(`rmcp=warn` 클램프, PTY b64·argv가 stderr에도 안 나감). 어댑터에 플랫폼 분기 0(stdio-only 설계 그대로), Windows ungated 성공 경로 2건(list_hosts·list_sessions). 발견·수정된 프로덕션 결함 2건: stdin EOF 후 blocking pool join으로 종료 최대 60s 지연(→`shutdown_timeout(500ms)`, 29.7s→5.5s), forward tunnel `close` 응답의 진실성(→qsh-core `TunnelHoldRegistry`, closed:true == listener 해제 보장). M7 이월: long-poll 취소의 자원 비해제 + 동시성 무상한(400 폴 → 4,412 threads/372MB 실측, PLAN.md M6판 Step 4 판정 ⑤), `acl_check` tool 노출 결정, `action_of` enum화, `trust add`의 address 갱신 경로 부재(캠페인 백로그), rmcp minor 업그레이드 시 `local_ct_pool` 재검증. **SC7 외부 보안 리뷰 예약은 여전히 운영자 액션 미완 — 재이월**(M8 wire freeze 리드타임 소진 중). 마감 태그 대조에서 남긴 판정 2건: §8.3 "다양한 MCP client에서 동일하게 동작"은 표준 JSON-RPC 설계 논증 + client 2종(raw 하네스·Claude Code) 실증으로 지지 — 멀티클라이언트 실측은 DoD 문면 밖이라 추가 조치 없음; §10 "기존 argument 재해석 금지"는 기계 게이트 없이 L7 fixture diff 리뷰 규율로 방어(L6과 동형) — 기계화 비채택.
- **철회 (2026-09-07, [ADR-0011](adr/0011-remove-mcp-adapter.md)):** 내장 MCP 어댑터는 M8 Step 6에서 제거한다. 에이전트 연동 면은 `qsh.cli/v1` JSON CLI 하나로 통일한다. 이 절은 역사 기록으로 남긴다. **제거 완료 (2026-09-10, M8 Step 6):** `qsh mcp`·`crates/qsh-cli/src/mcp/`·`mcp_conformance.rs`·rmcp 의존·xtask arch `MCP_DIR` 규칙·`docs/man/qsh-mcp.1`이 사라졌고 `fixtures/mcp/tools_list.json`만 append-only 규칙대로 남았다.

### M7 — Trust UX·profiles·doctor 🔄 기능 완료 (2026-09-01) · DoD 1 잔여

- **범위:** invite code pairing(ADR-0002: 단회용·10분 TTL·TLS exporter channel binding), private CA(`qsh cert`), host profile/config, `qsh doctor`(UDP probe·경로·cert 만료·keystore·PATH 상 타 qsh 경고 등), `qsh capabilities`/`qsh schema --json`, 첫 실행 경험, man page·설치 문서.
- **감사 개정 (2026-08-21) 추가 범위:** ① **`trust remove`의 유효 범위 결정** — 현재 semantics(살아 있는 연결에는 무효, 다음 handshake부터 적용)를 즉시 종료로 바꾸거나, 현행 유지를 선택하면 그 사실을 구속 문서·README·doctor가 명시 고지한다. 유예된 revocation UX(아래 명시적 out)와 별개로, **유예 기간의 실제 동작을 문서화하는 것은 유예할 수 없다.** ② pairing 안내 문구에 대역 외 fingerprint 대조 경로("이 지문을 다른 채널로 상대와 대조하라")를 포함. ③ `qsh version --json`에 빌드/커밋 식별자 추가(additive).
- **명시적 out:** cert rotation/revocation UX, background service 설치, QR.
- **수용 기준 (DoD):** **스톱워치 테스트 — 한 번도 설정한 적 없는 두 장비가 README만 보고 `qsh user@host`까지 5분 이내, 독립 3회 측정·기록** (SC1, SC2). doctor가 UDP 차단/경로 없음/비신뢰 peer/만료 cert/keystore 부재(headless)/clock skew를 각각 실행 가능한 메시지 + 안정된 JSON code로 진단. `qsh capabilities --json` == checked-in fixture (scope-creep tripwire).
  - **(감사 개정)** `trust remove` 후 기존 연결·신규 handshake 각각의 동작이 테스트로 고정되고 문서·doctor 고지와 일치.
- **크기:** 2.5ew

### M8 — Hardening 🔄 진행 중 (DoD 1·2·5 완료 · DoD 3·4 진행)

- **범위:** cargo-fuzz 타깃 + corpus + OSS-Fuzz 제출, stateful broker fuzzer, 24h soak, fd/메모리 누수 게이트, **실기기 mobility 캠페인**, perf 게이트(M4 게이트의 M8 HEAD 재확인 + 릴리스·방어선 대조 기록 — PLAN.md M8 Step 8; nightly perf job은 M10), threat model 문서, **wire format freeze**, 외부 보안 리뷰 착수.
- **감사 개정 (2026-08-21) 추가 범위 — 적대적 부하 게이트:** 인터넷에 직접 노출되는 데몬에 현재 방어선이 하나도 없다(주소 검증 없음·연결 수 무제한·세션 수 무제한·`receive_window: VarInt::MAX`). ① `Incoming::retry()` 주소 검증(스푸핑 Initial 1패킷당 상태 생성 차단), ② accept 동시성 상한과 source rate limit, ③ `[serve].max_sessions`와 principal별 세션 쿼터, 그리고 **터널 전용 할당량**(principal별·forward별 동시 `TCP_CONNECT` 스트림 수, remote-forward listener 개수 상한 — `docs/design/protocol.md` §7이 명시하는, M4·M5 어느 쪽도 만들지 않는 무상한 갭을 이 항목이 인수한다) — 초과는 `RESOURCE_EXHAUSTED`(CLI.md §3.3 기정의 어휘), ④ M5가 구현한 audit 수명주기의 부하 하 검증(스푸핑 flood → 세션 없는 audit 쓰기 → 디스크 만실 → resume 실패 연쇄의 차단). 그 외: handshake matrix에 **ALPN 불일치** 케이스 추가(§4의 "application 상태 생성 전 실패" 불변식을 의존성 상속이 아니라 테스트로 고정 — wire freeze 전에), device 개인키 프로세스 상주 사본의 `Zeroizing` 적용, TUI 펌프 스레드 spawn 실패 panic 제거(보안 리뷰 준비 항목).
- **수용 기준 (DoD):** parser 타깃당 누적 ≥72 fuzz-hours 무crash. 24h/100-session soak: idle listener ≤30MB, 세션당 buffer ≤8MB, 사이클 중 fd 무증가(누수 0 — boot→idle 일회성 warm-up은 정보성). **실기기 Wi-Fi↔테더링 ≥60회(macOS+Linux)에서 자동 유지+resume ≥95%, migrated/resumed 분해 보고** (SC3 — 통과 기준은 사전 정의: idle timeout에 기대지 않는 2초 내 재dial). 프로토콜 스펙 freeze 후 독립 리뷰 계약 (SC7 — 리뷰는 리드타임이 있으므로 M5 시점에 예약).
  - **(감사 개정)** **적대적 부하 하네스** — 협조적 soak과 별도 게이트: 스푸핑 Initial flood·대량 연결·principal당 세션 폭주 각각에서 선언된 상한이 실제로 강제되고(`RESOURCE_EXHAUSTED`/거부), 부하 중·후 idle listener RSS/fd가 soak과 같은 bound를 지키며, 기존 세션의 PTY echo가 살아 있음.
- **크기:** 3ew

### M9 — 사람용 표면 🔄 기능 완료 (2026-09-24) · DoD 1 잔여

- **범위:** 신규 두 장비가 README만 보고 5분 안에 붙는 경로(SC1)의 마찰 축소. (a) **이름 결정권 이동** — `pair invite --as N` / `pair accept --as N`(신설. `TrustInviteData.assigned_name`과 `TrustInviteReq`/`TrustAcceptReq`의 `as_name`이 additive로 붙고, accept 결과는 기존 `TrustAcceptData.peer.name`이 그대로 담는다)로 pin하는 쪽이 상대 이름을 정한다. wire 자칭 값은 오늘의 `device_id` 그대로 두어 기존 fixture는 불변이다(근거: ADR-0012). (b) **역방향 개명** — `qsh reverse <controller>` → `qsh serve --to <listener|host:port> [--name N]`(신설), `qsh listen`은 유지. `--to`는 인바운드 bind를 하지 않는 순수 outbound 모드이고 `--bind`와 함께 주면 `INVALID_ARGUMENT`다. 구 표기(`trust invite`/`trust accept`/`qsh reverse`)는 v1 내내 숨김 alias로 남기고 `[serve].to`와 구 `[reverse].controller` config 키를 이중으로 읽는다(근거: ADR-0012). (c) **파일 교환 프로비저닝** — `identity export`(신설, leaf cert PEM 단독 출력) + `trust add --cert-file <pem>`(신설, leaf 단일 PEM만 허용, 체인/번들은 `INVALID_ARGUMENT`)를 코드 페어링과 동급 1급 경로로 승격한다(근거: ADR-0013, ADR-0002 개정). (d) **주소 기본값** — 포트 생략 시 4433을 파서와 조회 양쪽에서 채운다(파일은 불변, 근거: ADR-0014). (e) `trust add-ca`(신설)로 `[[ca]]` 수기 편집을 없앤다. (f) `trust rename`(신설) — 재시작 불요, 다음 handshake부터 적용, audit 기록. (g) `qsh service install|uninstall|status [--json]`(신설). `[serve].to`(또는 구 `[reverse].controller`)면 `serve --to` 모드, `[listen]`만 있으면 `listen` 모드, 아니면 `serve` 모드로 추론하고, Windows에서는 이 세 모드 중 어느 쪽이든 unit을 쓰기 전에 `UNSUPPORTED`를 낸다. macOS는 사용자 LaunchAgent(`~/Library/LaunchAgents/io.qsh.<mode>.plist`, `KeepAlive`), Linux는 systemd user unit(`~/.config/systemd/user/qsh-<mode>.service`, `Restart=always`), 그 외/매니저 없음은 `UNSUPPORTED`; unit 인자는 고정, qsh 자체 데몬화(CLI.md §6.12 foreground 전용)는 바꾸지 않는다 — ROADMAP 2026-09-07 추가 범위를 이 마일스톤이 계승한다. unit 예시 문서 `docs/deploy/service.md`는 M8 Step 6 문서 라운드에서 먼저 낸다. (h) `doctor` 진단 7종 추가 — 서비스 미등록, systemd linger 미설정, macOS LaunchAgent가 로그인 세션 안에서만 사는 한계, `bindv6only`, `acl_principal_unmatched`, `acl_ca_auth_path_missing`, `[serve].to`와 구 `[reverse].controller`의 값 충돌(`EXPECTED_DOCTOR_CODES`·CLI.md §6.17 표를 같은 커밋에서 갱신). (i) 실패 문면 8종의 관측·영향·다음 명령 규율(원격 오류·콘솔 진단 분리를 예외 축으로 명시). (j) `pair accept`의 `code`를 선택 인자로 바꾼다. TTY면 에코 없는 프롬프트, 파이프면 `--code-stdin`, `--json`/`--jsonl`에서는 프롬프트 없이 `INVALID_ARGUMENT`(근거: ADR-0013 결정 8). 로직은 qsh-core `Ops`에 두고 CLI는 렌더만 한다(기존 아키텍처 규칙 재확인, 신규 예외 없음). (k) **SOCKS `-D`**(2026-09-19 사용자 결정으로 P1에서 당겨 왔다, 근거: ADR-0019) — client가 loopback listener에서 SOCKS5 CONNECT를 받아 CONNECT마다 기존 `TCP_CONNECT` 스트림을 열고, host는 그 스트림을 `forward.local`로 인가한다. wire 추가는 capability `dial-filter.v1`로 보호되는 `StreamHeader` 필드 하나이고, 그 필드가 켜지면 host가 해석 결과의 loopback·link-local 주소로는 연결하지 않는다. JSON에는 새 op `tunnel.dynamic`이 붙는다.
- **명시적 out:** TOFU(client가 미지 peer를 자동 pin) — `trust.toml` 양방향 구조상 outbound pin이 상대의 inbound 인증까지 통과시키는 문제가 있어 pin 방향 축을 별도 ADR로 예약한다(번호 미배정 — ADR-0017 결정 5가 그 자리를 미룬다). listener 대상 초대 상환("listener pairing")은 예약(ADR-0015). CSR 기반 다대 CA 서명도 예약(ADR-0016)이며, 현행 `qsh cert issue`(M7)는 로컬 device 승격만 유지한다. README 전면 재작성은 SC1 baseline 재측정 뒤로 미룬다(DoD 참고).
- **수용 기준 (DoD):**
  - SC1 스톱워치 재측정 — 새 표면으로 독립 3회, 5분 이내, `docs/campaigns/m7-stopwatch.md` 선례 형식을 계승한 캠페인 문서로 baseline(M7 DoD 1 측정치, Q4에 따라 현행 표면으로 먼저 잰다) 대비 단축 기록.
  - doctor 신규 8종(범위 (h)의 7종에 2026-09-24 이슈 처리 기록의 `host_pinned_without_address`를 더한 수)이 각각 안정된 code로 진단되는 것을 실행 가능한 메시지와 함께 테스트로 고정하고, `EXPECTED_DOCTOR_CODES`와 CLI.md §6.17 표를 같은 커밋에서 갱신.
  - SOCKS `-D` — 실제 `curl --socks5-hostname`이 qsh SOCKS listener를 통과하는 acceptance 테스트가 CI에서 건너뛰지 않고 초록이다. host-local 필터 거부와 ACL 거부가 각각 테스트로 고정되고, 옛 거절 계약을 고정하던 fixture는 한 바이트도 바뀌지 않는다(2026-09-19 추가).
  - 문구 표본 8종(§6 문구 규칙 — forward loopback 처방, `-D` 거절 문구(capability 부재, 2026-09-19 개정 — 옛 "현행 유지 문구". 역방향 거절은 2026-09-20 ADR-0020이 걷었다), 재상환 실패의 host 전용 진단, 초대 출력의 후보 주소 열거, 포트 충돌 `--bind` 처방, 페어링 직후 pin 이름·매칭 규칙 부재 고지, `auth_path` 누락 host 진단, `assuming port 4433` 한 줄)이 축자 테스트로 고정.
  - 숨김 alias(구 서브커맨드·config 키)와 config 이중 읽기가 왕복 테스트로 검증 — 구 표기 호출이 신 표기와 동일 op에 도달하고 신구 config 키가 동시에 있을 때의 우선순위가 고정된다.
  - 신규 op마다 새 JSON fixture 파일을 추가하고 `REQUIRED_FIXTURES`(`crates/qsh-cli/tests/fixtures.rs`)에 등록한다. 기존 fixture는 한 바이트도 고치지 않는다. `cli_v1` 스키마도 신규 op마다 schemars 타입, `cli_v1_data_schema` arm, `CLI_V1_SCHEMA_COMMANDS` 등록, 렌더러(human/JSON) 둘, CLI.md 문서 행, man 항목이 모두 존재함을 등록 완전성 테스트로 확인(M5 `acl_registry` 선례 형식).
  - 마일스톤 마감 공통 절차(§2) 1·2 — 구속 문서 태그 대조, README 동기화(단 전면 재작성은 위 명시적 out).
- **크기:** 4.3ew (S1 포트 정규화 0.3 / S2 code 선택화·프롬프트 0.2 / S3 문구 8종·acl_docs·acl_uniformity 0.5 / S4 doctor 7종·동결 set 0.5 / S5 `serve --to`·v1 내내 유지하는 alias·config 이중 읽기·PRD 0.5 / S6 `identity export`·`--cert-file`·`add-ca` 0.7 / S7 `pair … --as`·`trust rename` 0.5 / S8 `qsh service` 0.4 / S9 계약 문서(CLI.md·PRD.md·man) 반영 0.4 — README 전면 재작성 제외 / S10 ADR 0.3: 0012·0013·0014·0017은 확정 반영, 0015·0016 신규 작성). 2026-09-19 추가: SOCKS `-D` 1.6~2.0ew(추정, 측정값 아님 — 내역은 ADR-0019 결과 절).
- **결정 기록 (2026-09-09, 사용자 확정):**
  - Q1 마일스톤 배치 — 쪼개서 M9 앞에 신설, 릴리스는 M10으로 민다. notarization의 Apple 계정 리드타임이 CLI 설계 일정을 인질로 잡지 않도록.
  - Q2 역방향 이름 — `qsh reverse <c>` → `qsh serve --to <listener|host:port>`, `qsh listen` 유지. 구 표기는 v1 내내 숨김 alias, config는 `[serve].to`와 구 키 이중 읽기.
  - Q3 이름 결정권 — `pair invite --as` / `pair accept --as` 채택. pin 쪽이 이름을 정하고 wire 자칭 값은 `device_id` 그대로.
  - Q4 SC1 시점 — 현행 표면으로 먼저 baseline 3회 측정 후, 새 표면으로 재측정해 DoD에서 비교한다.
  - Q5 둘째 터미널 마찰 — `qsh service install` 안내 + 데몬 부재 진단으로 해결. `serve --pair`는 기각(10분 초대를 상시 데몬 stderr에 노출하고 잠금 없는 `invites.toml`에 writer를 하나 더 만들기 때문).
- **이슈 처리 기록 (2026-09-24):** GitHub 이슈 #3·#4는 M9 범위 (a)~(k) 어디에도 없어 M9 크기 내역 밖의 결함 수정으로 처리했다(커밋 ea8fcb6·46cfda8·fab8563·dd086e1·56d16b1·c9113cc, `docs/history/m9-plan.md`의 2026-09-24 항목). 이미 출고된 표면의 결함 다섯 건을 main에 올렸고, 남은 항목은 제안 ADR 넷(0021·0022·0025·0026)으로 적었다. 마일스톤 상태와 DoD는 바뀌지 않는다.
- **마감 노트 (2026-09-24):** DoD 2~7 전건 충족 — DoD 2(doctor 신규 8종, 동결 set은 22종이 됐다)는 `DiagnosticId` 22 variant와 `EXPECTED_DOCTOR_CODES`(`crates/qsh-core/src/doctor.rs`)가 정렬 배열로 대응하고 신규 8종(`service_not_registered`·`systemd_linger_disabled`·`launchagent_session_scoped`·`bindv6only_blocks_ipv4`·`acl_principal_unmatched`·`acl_ca_auth_path_missing`·`host_pinned_without_address`(`963809e`)·`config_serve_to_conflict`(`699af37`))이 `expected_doctor_codes_matches_every_diagnostic_id_variant_exactly`·`cli_md_prose_doctor_code_count_matches_expected_len` 등으로 고정된다. DoD 3(문구 8종)은 `failure_text_discipline.rs`·`tunnel_docs.rs`의 축자 대조 일곱에 `acl_ca_auth_path_missing` 독립 핀 `cli_md_quotes_the_acl_ca_auth_path_missing_diagnostic_verbatim`(`fb3bda6`)이 더해진다. DoD 4(숨김 alias·config 이중 읽기)는 `#[command(hide = true)]` 3곳과 `resolve_serve_mode`·`config_outbound_target`(`crates/qsh-core/src/serve.rs`)의 단일 지점 수렴이 근거다. DoD 5(신규 op 등록 완전성)는 `REQUIRED_FIXTURES` 57 entry와 fixture 파일 57개의 1:1 대응, `layer_2_every_schema_command_has_all_six_faces`가 근거다. DoD 6(마감 공통 절차 1·2)은 이 감사 자체가 산출물이다. DoD 7(SOCKS `-D`)은 `ci.yml` acceptance job의 `socks_curl`(`QSH_ACCEPTANCE_STRICT: curl`)과 `dash_d_over_reverse_filters_loopback_and_the_target_sees_no_accept`(`crates/qsh-testkit/tests/dynamic_reverse.rs`)가 근거다. DoD 1(SC1 스톱워치 재측정 3회)만 사람 몫으로 열려 있다. 절차 1은 대조 문장 144건 — 검증 126, 후속 마일스톤 명시 유예 4, 열린 DoD 종속 3, 대조 대상 아님 7, 충돌 4(전건 고침, `edcb754`·`1786bff`·`446c5e3`). 감사 뒤 같은 부류 둘을 더 찾아 고쳤다 — M10 M8 이관 행의 PRD 줄 번호 오조준(`5daee3d`)과 `scripts/`의 서명·notarization M9 오기 셋(`21d3507`). 절차 2는 대조 항목 14개 중 불일치 2(README Status 산문과 Roadmap 표 M9 행 — 이 마감 커밋이 닫는다). 잔여 귀속: threat-model의 M9 표면 커버리지는 M10 수용 기준의 M9 이관 항목으로, M8 잔여 셋(CLOSE `0x1003` 이중 이름 처분·README Security posture 한 줄·DoD 4 문구)은 M8 소관으로, `crates/` 코드 주석의 옛 계획·ADR 줄 번호 인용은 부채로 남는다. 감사 커밋: `1b6683d`·`edcb754`·`1786bff`·`4a04c9d`·`446c5e3`·`da38b15`·`fb3bda6`·`9cea01f`·`0c5e43c`·`d82f7a6`·`8164405`·`5daee3d`·`21d3507`. CI run 35999353718·36000049248. 크기: 4.3ew + SOCKS `-D` 1.6~2.0ew(추정) 내역 S1~S10과 SOCKS `-D` 스텝·마감 스텝까지 전부 착지.

### M10 — 릴리스

- **범위:** 설치 스크립트/cargo-dist 검토, Homebrew tap, macOS codesign + notarization, musl static Linux 빌드, SLSA provenance, 클린 VM smoke, beta 문서. crates.io publish gate 해제(`qsh-cli`).
  - **(스켈레톤 조기 반영 2026-09-16)** Homebrew tap(`DaveDev42/homebrew-tap`, `Formula/qsh.rb`)과 release.yml의 tap 자동 bump job(`homebrew-tap`)은 다음 태그 전에 미리 배선해뒀다. tap 쪽 쓰기는 2026-09-18부터 fine-grained PAT 대신 tap 저장소에 등록한 write deploy key(시크릿 `HOMEBREW_TAP_DEPLOY_KEY`)로 하고, `Formula/qsh.rb`는 2026-09-21 사람이 tap에 밀어 넣었으므로 job은 다음 태그부터 자동으로 돈다(version/url/sha256 세 줄을 job이 다시 쓴다). 다음 태그는 `v0.1.0-alpha.3`이 아니라 `v0.2.0`이다 — 2026-09-21 사용자 결정으로 SOCKS `-D`(M9 Step 12, ADR-0019·0020)가 오른 main에 찍는다(`PLAN.md` §7). **찍었다(2026-09-21):** `v0.2.0` = `2907488`(`chore(release): 버전을 0.2.0으로 올린다`), release run 35579517383의 빌드 5·release·homebrew-tap 잡이 전부 성공해 GitHub Release에 자산 5개 + SHA256SUMS가 붙었고 tap `Formula/qsh.rb`는 job이 0.2.0으로 다시 썼다(tap 커밋 397b2a3). M10 DoD(codesign, notarization, musl static, SLSA provenance, release 프로파일 기능 스모크)는 그 태그로도 여전히 미완이다.
- **수용 기준 (DoD):** 클린 macOS arm64/x86_64·Linux arm64/x86_64에서 brew/curl 설치 → 동작. Gatekeeper가 notarized 바이너리를 차단하지 않음. musl static 바이너리가 구형 glibc 배포판에서 실행.
  - **(감사 개정 2026-08-21)** "동작"의 정의는 `version --json`이 아니라 **기능 스모크**다: init → trust → `exec --json` 왕복 + PTY 셸 획득 + detach→attach resume이 배포되는 release 프로파일 바이너리로 통과. 근거: 현재 CI의 전 기능 테스트는 dev 프로파일이고 release 바이너리는 기능 테스트 0건으로 출고된다. release 태그 전 CI에서 `--release` 프로파일 통합 테스트를 최소 1회 돌린다.
  - **(M8 이관 2026-09-10)** `docs/PRD.md` §13의 '30분 단절 후에도 TTL 내 세션 복구' 항목과 '느린 파일·터널 stream이 PTY stream을 block하지 않아야 함' 항목의 직접 증거는 릴리스 게이트에서 판정한다 — 후자는 파일 전송 표면이 v1에 없어 대역 스트림 대체 하네스가 필요하고, 전자는 M3 60초 blackout 게이트의 30배 길이라 acceptance job에 못 들어간다(docs/history/m8-plan.md의 perf 게이트 스텝 (c) 이월 문단).
  - **(M9 이관 2026-09-24)** `docs/design/threat-model.md` §3 진입점·§4 위협 표가 M9 사람용 표면 명령(`pair invite|accept --as`, `identity export`, `trust add --cert-file`, `trust add-ca`, `trust rename`, `service install|uninstall|status`)을 다룬다. 그 문서 §0이 "다음 개정으로 미룬다"고 스스로 적어 둔 유예를 M9 마감 감사(마감 공통 절차 1)가 마일스톤 귀속으로 바꾼 것이다. `-D`는 잔여 위험 h16~h22로 이미 다뤄져 대상이 아니다.
- **크기:** 2.6ew(추정, 2026-09-24 갱신) — 최초 1.5ew는 2026-08-17 추정이고 그 뒤 감사 개정의 기능 스모크, M8 이관 둘, M9 이관 하나가 예산 갱신 없이 얹혔다. notarization은 Apple 계정 리드타임 — M8 중 시작.
- **검토 항목(2026-09-07, ADR-0011):** `-W`(ProxyCommand형 stdio와 원격 TCP의 브리지) 필요 여부. `qsh exec`의 pipe stdin 전달과 `-L`로 부족한 사용례가 있을 때만 추가하고 없으면 기각한다.
- **결정 기록 (2026-09-24, main 세션 — 사용자 전면 자율 지시):**
  - Q1 release 스모크 leg — darwin 2 + linux-gnu 2 네이티브 러너 전부와, musl leg이 선 뒤 그 leg에서도 같은 스모크를 `QSH_SMOKE_STRICT=1`로 돌린다. Windows leg은 init → trust → `exec --json` 왕복까지고 PTY·detach/attach 축은 뺀다. `load.yml`에도 같은 스텝을 더한다.
  - Q2 macOS 배포 형식 — tar.gz를 유지하고 공증만 더한다. `.pkg`는 만들지 않는다. 단일 실행 파일은 stapler 대상이 아니라 오프라인 판정이 미보장임을 캠페인 문서에 적는다. Gatekeeper 판정은 수동 다운로드 경로에서 `spctl`·`codesign`·`notarytool` 셋으로 고정한다.
  - Q3 musl — `x86_64-unknown-linux-musl` 하나만 만든다. aarch64 musl은 P1로 적되 네이티브 러너로 값싸게 더할 수 있다는 점을 남긴다. jemalloc·aws-lc-rs가 musl에서 막히면 각각 `target_env = "gnu"` 축소와 ADR 선행으로 대응한다.
  - Q4 man page — Homebrew formula만 설치한다. unix 아카이브에 `man/*.1`을 더하고 tap formula에 `man1.install Dir["man/*.1"]` 한 줄을 더한다. README는 'Homebrew installs them; the curl installer does not'로 고친다.
  - Q5 beta — 선언하지 않는다. ROADMAP M10 범위의 'beta 문서'는 릴리스 문서로 만들고 README의 'Not for production use'는 유지하되 사유를 SC7과 열린 사람 캠페인으로 좁힌다.
  - Q6 옛 계획 인용 — 기존 인용 754건(crates/)·33건(docs/)·6건(xtask/)은 부채로 남기고 새 인용은 만들지 않는다. M2~M6 계획 다섯을 `docs/history/`로 복원한다.
  - Q7 fuzz deny — `fuzz-smoke.yml`에 `cargo deny --manifest-path fuzz/Cargo.toml check advisories` 한 스텝만 더한다. licenses/bans는 켜지 않는다.
  - Q8 crates.io — publish gate 해제는 M10 안에 두되 실제 `cargo publish`는 클린 VM 캠페인 PASS 뒤에 사람이 실행한다. 에이전트 몫은 메타데이터·`publish` 값·`deny.toml` 주석·CI dry-run 4건이다.
- **태그 정책 (2026-09-24, M9 계획 §7에서 이관):** 태그는 판정 근거 회차가 실제로 돈 트리에 찍고, 찍은 태그는 옮기지 않는다. 태그 push가 `release.yml`을 구동한다. M10 첫 태그는 클린 VM 캠페인 PASS 트리이고, 서명·공증이 붙은 첫 태그가 DoD 2(Gatekeeper) 판정 대상이다.

## 3. 유예 가드레일 (P1/P2 경계)

작동 원리: **"ACL action과 오류 경로만 정의하고 구현하지 않는다."** 이름 붙은 "아직 아님"은 단순 부재보다 scope creep에 훨씬 강하다.

| 유예 기능 | 압력원 | 가드레일 |
|---|---|---|
| TCP/TLS fallback (P1) | doctor가 "UDP 차단"을 보고하는 순간 | transport 추상화는 P0에 있으나 **TCP 코드는 0줄**. doctor 메시지가 "P1 예정"을 명시 (ADR-0005) |
| SOCKS `-D` (P1 → M9 범위로 승격, 2026-09-19 → [ADR-0019](adr/0019-socks-dynamic-forward.md)) | 스펙 예시에 존재 | M9가 구현한다. `-D`는 CONNECT마다 `forward.local`로 인가된다. `forward.socks` action은 어휘에 남고 여전히 항상 deny다. 이 토큰을 적은 기존 `acl.toml`이 파싱 오류로 전부 거부 상태가 되지 않게 하려는 것이다 |
| File copy (P1) | `file.read/write` action이 §9에 존재 | action만 정의, op 미등록, capabilities에 미광고 |
| Windows (P1 client / P2 host) | 외부 기여 PR | PTY 코드에 `#![cfg(unix)]`. CI는 `windows-latest`에서 build/clippy/portable 테스트만 돌려 컴파일 회귀를 막는다(POSIX 시그널·process-group 테스트는 `cfg(unix)`). 지원 약속 아님 — README.md Known limitations에 명시 |
| Multi-attach read-only (P2) | broker에서 거의 공짜로 나옴 — 그래서 위험 | **관찰자(observer) 개념 자체를 만들지 않는다.** writer lease는 P0 필수, 두 번째 attach 정책은 lease 규칙만 따름 |
| Local echo prediction (P2) | mosh 대비 지연 불평 | P0는 실제 PTY 지연을 측정·공개해 데이터로 대화 (§13의 10ms 예산) |
| Relay (§14, 별도 제품) | "작은 relay 하나면" | P0 의무는 세션 identity와 transport 분리뿐(resume이 이미 강제). **`--relay` flag는 stub조차 없음** |
| Forward-route live carrier·`-R` 자동 재발행 (M8 소유 → [ADR-0018](adr/0018-tunnel-lifetime-bound-to-connection.md)로 종결) | 터널이 recovery 후에도 신규 연결을 서비스하길 기대 | 연결 손실→resume에서 터널 스트림은 깨끗이 종료된다는 현행 의미론을 M4가 테스트로 고정(`tunnel_chaos.rs`의 개정 강제 트랩)했고 README Known limitations가 고지한다. M4 마감 노트가 M5 입력으로 이관, M5가 범위 밖 판정 후 여기 등재(PLAN.md M5판 §3 (v)). **M8 Step 6(2026-09-09)이 ADR-0018로 확정: v1 터널 수명은 connection에 결합, live carrier는 구현하지 않으며 `-R` 자동 재발행은 P1(freeze는 additive 확장을 막지 않는다).** |
| Cert rotation UX (P1) | 만료 | P0: 만료 30일 전 doctor 경고만 |
| Service 설치 (P1 → M9 범위로 승격, 2026-09-07; 2026-09-09 마일스톤 분리 후에도 신설 M9 소속) | 상시 실행 요구 | M8까지는 unit 예시 문서(`docs/deploy/service.md`, M8 Step 6)만 제공하고 `qsh service install`은 신설 M9(사람용 표면) 범위 항목대로 구현한다 |
| **메타 가드레일** | — | `qsh capabilities --json` == fixture 테스트: 새 capability는 fixture diff로만 추가 가능 (리뷰 가능한 산출물). + ErrorCode 전수 도달성 테스트: 존재하지만 만들 수 없는 코드 금지 |

## 4. 일정 리스크 5건

1. **SC3(≥95% mobility)은 CI로 측정 불가능한 측정 문제이고, 통과 기준이 미정의면 그 자체가 리스크.** 대응: chaos proxy + recovery 텔레메트리를 M2에 구축, M2 말 실기기 20회 조기 측정, "idle timeout이 늦게 터져서 기술적으로 통과"를 배제하는 기준(재dial 2초)을 지금 명문화, M8에 ≥60회 본 캠페인.
2. **PTY/터미널 정확성은 추정을 거부하는 long tail.** 대응: M2b를 명명된 수용 세트(bash/zsh+vim+tmux+claude)로 timebox, "terminal quirks" 백로그를 마일스톤 밖에 유지, expect 하네스를 초기에 구축해 수정마다 회귀 테스트가 싸게 남게.
3. **Identity·keystore·pairing이 SC1(간판 숫자)의 critical path.** headless Linux에 Secret Service 부재 → file fallback + doctor 보고 필수, macOS 미서명 바이너리의 Keychain 재프롬프트가 dev loop을 괴롭힘. 대응: keystore fallback을 M1의 명명된 task로, 스톱워치 테스트를 M7 한 번이 아니라 조기·반복 실행.
4. **In-listener 세션과 listener 재시작/업그레이드의 충돌은 구조적.** 대응: ADR-0003의 `SessionBackend` seam을 처음부터 순수하게 유지(CI로 transport import 금지 확인), graceful re-exec(fd 보존 handoff)을 M8 stretch로 비용 산정. **비용 산정 완료(2026-09-10, `docs/design/reexec-estimate.md`):** 후보 H0(고지)~H5(supervisor 분리) 여섯을 ew로 매겼다 — M8 구현 0, H0 고지는 같은 커밋에서 반영, H1·H1b·H2는 M9 후보, H4 execve 제자리 handoff 4.2ew와 H5 supervisor 분리 6.5ew는 P1로 넘기고 P1 진입 시 세션이 어느 프로세스에 사는지를 먼저 고른다.
5. **SC7 보안 리뷰와 notarization은 리드타임 함정.** 대응: 리뷰는 M5 시점에 예약하고 wire format을 리뷰 ~6주 전에 freeze, notarization은 M10이 아니라 M8 중 시작.
