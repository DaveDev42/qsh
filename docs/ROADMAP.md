# QSH 로드맵

**상태:** 확정 (구현과 어긋나는 내용을 발견하면 이 문서를 먼저 갱신한다)
**작성일:** 2026-08-17 · **개정:** 2026-08-21 — 프로덕션 준비도 감사(HEAD `1d5d1b0`) 반영: M3/M5/M7/M8/M9 범위·수용 기준 증보, "마일스톤 마감 공통 절차" 신설. 새 마일스톤은 만들지 않았다 — 감사가 찾은 갭 전부를 기존 마일스톤에 명시 귀속시킨 것이 이 개정의 전부다. · **개정 2:** 2026-09-09 — 사람용 CLI 설계(design.html, 2026-09-08) 확정 결정 반영: 신규 `M9 — 사람용 표면`(4.3ew)을 M8과 구 M9 사이에 신설하고, 구 `M9 — 릴리스`는 `M10 — 릴리스`로 번호만 옮긴다. notarization 리드타임이 CLI 설계 일정을 막지 않게 하려는 결정(ADR-0012~0017, DECISIONS.md Q1). · **개정 3:** 2026-09-19 — 사용자 결정으로 SOCKS `-D`를 P1에서 M9 범위로 당긴다(ADR-0019).
**현재 위치:** P1을 열었다(2026-09-26 사용자 결정). 첫 마일스톤은 M11(이슈 후속과 ACL 가시성)이고 실행 계획은 `PLAN.md`다. P1 마일스톤 아홉(M11~M19)은 §5에 있고, P1이 새로 만드는 사람 몫은 §5.5에 모은다. P0 MVP 완료 선언은 아직이다. M10까지의 에이전트 몫은 전부 착지했고 사람 회차 일곱이 닫힐 때 선언한다. 열린 일곱은 M10 DoD 1·2·3(`docs/campaigns/m10-clean-vm.md` 회차 표), M7 DoD 1(SC1 baseline 3회, `docs/campaigns/m7-stopwatch.md`, 예행 1회만 끝났다), M8 DoD 3(실기기 mobility ≥60회, `docs/campaigns/m2-mobility.md`), M8 DoD 4(wire freeze 발효와 독립 검증 계약, SC7), M9 DoD 1(SC1 재측정 3회, `docs/campaigns/m9-stopwatch.md`, M7 DoD 1에 종속)이다. 일곱은 P1과 별개로 `PLAN.md`가 사람 몫으로 계속 추적한다. 이 중 M8 DoD 3은 M18의 착수 조건이고, M9 DoD 1은 M12 (b)가 사전 고정하는 `qsh setup` 캠페인의 비교 기준이다. M8 DoD 1·2·5는 닫혔다(`docs/campaigns/m8-fuzz.md`, `docs/campaigns/m8-soak.md` run #6 PASS, `docs/campaigns/m8-adversarial-load.md`). M2~M10판 계획은 `docs/history/`에 아홉 파일로 있다.

이 문서는 P0 MVP(M0~M10)와 P1(M11~M19)의 canonical 마일스톤 기록이다. P2(`docs/PRD.md` §7 P2 목록)는 이 문서가 다루지 않는다. 각 마일스톤의 "수용 기준"이 곧 그 마일스톤의 **완료 정의(Definition of Done)** 다 — 수용 기준을 통과하는 테스트/시연 없이는 마일스톤을 닫지 않는다. SC 번호는 PRD §15 성공 기준의 순번이다 (SC1: 신규 두 장비 5분 내 연결, SC2: 한 명령 접속, SC3: 네트워크 전환 ≥95% 유지/resume, SC4: resume 가능한 단절에서 output 무손실, SC5: client crash가 remote PTY를 죽이지 않음, SC6: 모든 privileged op의 ACL 추적성, SC7: 공개 beta 전 독립 보안 리뷰).

**P0 MVP 완료 선언의 조건 (2026-09-25 고정).** M0부터 M10까지의 코드·계약·파이프라인 스텝 중 에이전트 몫은 전부 착지했다. 남은 계약 편집 셋은 M8 DoD 4의 wire freeze 발효 소커밋에 묶여 있다. P0 MVP는 사람이 돌려야 닫히는 회차 일곱이 전부 PASS로 기록될 때 완료로 선언하고 그 선언은 이 문서의 "현재 위치" 줄과 이 문단에 같이 적는다. 일곱은 M10 DoD 1·2·3(`docs/campaigns/m10-clean-vm.md` 회차 표), M7 DoD 1(`docs/campaigns/m7-stopwatch.md`), M8 DoD 3(`docs/campaigns/m2-mobility.md`), M8 DoD 4(wire freeze 발효와 SC7 독립 리뷰 계약. 저장소 밖 조직 액션이라 캠페인 문서가 없다), M9 DoD 1(`docs/campaigns/m9-stopwatch.md`)이다. 선언 전에 "beta"나 그에 준하는 어휘를 쓰지 않는다. PRD §15가 공개 beta 전 독립 보안 리뷰를 요구하고 그것이 위 일곱 중 하나다. 일곱이 다 닫히는 날에는 이 문단 아래에 `**P0 MVP 완료 (날짜).**`로 시작하는 문단을 더해 각 캠페인 문서와 회차 번호를 적고 P0 범위(`docs/PRD.md` §7 P0 표)를 닫는다. P1은 2026-09-26 사용자 결정으로 열었고 P0 완료 선언과 독립적으로 진행한다(§5).

총 크기: 약 31.5–32 engineer-weeks (1인 기준) — 기존 24.5ew에 신규 M9(사람용 표면, 4.3ew)를 더한 28.8ew에, 2026-09-19에 M9로 당긴 SOCKS `-D` 1.6~2.0ew(추정)와 2026-09-24 M10 갱신분(1.5 → 2.6ew)을 더한 값.

P1 총 크기: 약 29~48ew(1인 기준, 추정)에 ADR이 서야 산정할 수 있는 항목 다섯(M16의 구현 셋, M17 (d)의 구현, M18의 보안 가산분)이 더해진다. 내역은 §5.2.

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

### M10 — 릴리스 🔄 파이프라인 완료 (2026-09-25) · DoD 1·2·3 잔여

- **범위:** 설치 스크립트/cargo-dist 검토, Homebrew tap, macOS codesign + notarization, musl static Linux 빌드, SLSA provenance, 클린 VM smoke, beta 문서. crates.io publish gate 해제(`qsh-cli`).
  - **(스켈레톤 조기 반영 2026-09-16)** Homebrew tap(`DaveDev42/homebrew-tap`, `Formula/qsh.rb`)과 release.yml의 tap 자동 bump job(`homebrew-tap`)은 다음 태그 전에 미리 배선해뒀다. tap 쪽 쓰기는 2026-09-18부터 fine-grained PAT 대신 tap 저장소에 등록한 write deploy key(시크릿 `HOMEBREW_TAP_DEPLOY_KEY`)로 하고, `Formula/qsh.rb`는 2026-09-21 사람이 tap에 밀어 넣었으므로 job은 다음 태그부터 자동으로 돈다(version/url/sha256 세 줄을 job이 다시 쓴다). 다음 태그는 `v0.1.0-alpha.3`이 아니라 `v0.2.0`이다 — 2026-09-21 사용자 결정으로 SOCKS `-D`(M9 Step 12, ADR-0019·0020)가 오른 main에 찍는다(이 절의 태그 정책 항목). **찍었다(2026-09-21):** `v0.2.0` = `2907488`(`chore(release): 버전을 0.2.0으로 올린다`), release run 35579517383의 빌드 5·release·homebrew-tap 잡이 전부 성공해 GitHub Release에 자산 5개 + SHA256SUMS가 붙었고 tap `Formula/qsh.rb`는 job이 0.2.0으로 다시 썼다(tap 커밋 397b2a3). M10 DoD(codesign, notarization, musl static, SLSA provenance, release 프로파일 기능 스모크)는 그 태그로도 여전히 미완이다.
- **수용 기준 (DoD):** 클린 macOS arm64/x86_64·Linux arm64/x86_64에서 brew/curl 설치 → 동작. Gatekeeper가 notarized 바이너리를 차단하지 않음. musl static 바이너리가 구형 glibc 배포판에서 실행.
  - **(감사 개정 2026-08-21)** "동작"의 정의는 `version --json`이 아니라 **기능 스모크**다: init → trust → `exec --json` 왕복 + PTY 셸 획득 + detach→attach resume이 배포되는 release 프로파일 바이너리로 통과. 근거: 현재 CI의 전 기능 테스트는 dev 프로파일이고 release 바이너리는 기능 테스트 0건으로 출고된다. release 태그 전 CI에서 `--release` 프로파일 통합 테스트를 최소 1회 돌린다.
  - **(M8 이관 2026-09-10)** `docs/PRD.md` §13의 '30분 단절 후에도 TTL 내 세션 복구' 항목과 '느린 파일·터널 stream이 PTY stream을 block하지 않아야 함' 항목의 직접 증거는 릴리스 게이트에서 판정한다 — 후자는 파일 전송 표면이 v1에 없어 대역 스트림 대체 하네스가 필요하고, 전자는 M3 60초 blackout 게이트의 30배 길이라 acceptance job에 못 들어간다(docs/history/m8-plan.md의 perf 게이트 스텝 (c) 이월 문단).
  - **(M10 확정 2026-09-25)** 위 둘 중 '느린 파일·터널 stream이 PTY stream을 block하지 않아야 함'은 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`(`crates/qsh-testkit/tests/tunnel_echo_under_load.rs`)가 판정한다 — `ci.yml`의 acceptance job이 `QSH_ACCEPTANCE_STRICT`로 상시 돌리는 그 테스트이고, 새 게이트는 만들지 않았다. 덮는 축은 포화(고속) 하나이며 저속·역압 축은 잔여 위험으로 P1에 남는다(`docs/design/testing.md` L9/L10).
  - **(M10 확정 2026-09-25)** '30분 단절 후에도 TTL 내 세션 복구'는 `a_real_30_minute_blackout_is_resumed_within_the_ttl`(`crates/qsh-cli/tests/reverse_blackout.rs`)의 dispatch 회차 run 36033815282가 판정한다 — `long.yml`의 `workflow_dispatch` 전용 job이고 PR 게이트가 아니다(`docs/design/testing.md`의 CI 규율). 1800초 전면 차단 뒤 같은 `session_ref`가 보존된 ring과 함께 재부착되고, 차단 전 표지가 replay되며 `Gap`은 0건이고, 재부착 뒤 타이핑한 표지가 되돌아온다. 같은 회차가 기록하는 사실 하나: 출고 기본값에서 차단을 붙들고 있던 attach 자신은 30분을 버티지 못하고 포기하며, PRD 항목이 요구하는 것은 그 attach의 생존이 아니라 TTL 안의 세션 복구다.
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
- **마감 노트 (2026-09-25):** DoD 4~7 전건 충족, DoD 1·2·3은 사람 회차를 기다린 채 열려 있다. DoD 4(release 프로파일 기능 스모크)는 `crates/qsh-cli/tests/release_smoke.rs`의 `release_smoke_covers_init_trust_exec_pty_detach_and_reattach`와 `#[cfg(not(unix))]` 쌍둥이가 `QSH_SMOKE_BIN`으로 출고 바이너리를 구동하고(`152dd78`), `release.yml`의 build job과 `load.yml`이 `QSH_SMOKE_STRICT=1`로 그것을 돌리는 것이 근거다(`0350438`, dispatch run 36040085569의 여섯 leg). DoD 5(PRD §13 두 항목)는 `a_real_30_minute_blackout_is_resumed_within_the_ttl`의 1800초 dispatch 회차 run 36033815282와 `ci.yml` acceptance job이 상시 돌리는 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`가 근거다(`c2cb64e`). DoD 6(threat-model의 M9 사람용 표면)은 §3 진입점 여섯 행과 §4 위협 열아홉 행, §5 g6·g7, §7 h23~h27이 근거이고 §0의 M10 유예 문장은 걷혔다(`7119c91`). 같은 작업이 후보 둘을 문서가 아니라 코드로 닫았다. `trust add-ca`의 라벨 검증 공유와 `CERT_PEM_MAX`(64 KiB) 입력 상한이다(`381b42c`, `docs/CLI.md` §6.11). DoD 7(마감 공통 절차 1·2)은 이 감사 자체가 산출물이다. 파이프라인 쪽 착지: musl static 자산(`168e00c`), Developer ID 서명·공증 경로(`c61111b`·`cf24287`, 시크릿 여섯이 전부-또는-전무이고 0개면 브랜치는 조용히 건너뛴다), build provenance attestation(`d7bede7`, `dist/*` 전 자산과 `SHA256SUMS`), unix 아카이브의 man 페이지와 tap formula의 `man1.install`(`b38ed80`, tap 커밋 `0407d57`), fuzz 락의 deny advisories(`159e1fa`), crates.io publish gate 해제와 `publish-dry-run` 잡(`faf10bd`, CI run 36023113620), 클린 VM 캠페인 기준(`18f29f0`), 릴리스 노트 `RELEASE-NOTES.md`와 README 문면(`c7a4a9e`). `cargo publish`는 실행하지 않았다. ROADMAP M10 결정 기록 Q8대로 클린 VM 캠페인 PASS 뒤에 사람이 토큰으로 실행하는 단계이고 DoD 어디에도 없다. 절차 1은 대조 문장 76건. 검증 23, 후속 마일스톤 명시 유예 4, 열린 DoD 종속 24, 대조 대상 아님 22, 충돌 3(전건 고침, `5518607`·`c14f139`). 절차 2는 대조 항목 18개(루트 README 15와 `scripts/README.md` 3) 중 불일치 2(`scripts/README.md`의 man 페이지·provenance 태그 앵커 두 문장. `0e8e9e5`가 README와 같은 `v0.2.0` 앵커로 맞췄다). 잔여 귀속: DoD 1·2·3은 `docs/campaigns/m10-clean-vm.md`의 회차 표가 채워질 때 닫힌다. M7 DoD 1·M8 DoD 3·M8 DoD 4·M9 DoD 1 넷은 그대로 열린 채 승계된다. nightly perf job과 느린 스트림의 저속·역압 축과 `crates/` 코드 주석의 옛 계획·ADR 줄 번호 인용은 P1 몫이다. `-W`는 기각했다(ADR-0011 결과 절 2026-09-25 추기). 감사 커밋: `5518607`·`c14f139`·`0e7969c`·`0e8e9e5`. CI run 36068891182(2차 시도. 1차는 macos-14 leg에서 `a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes`가 터널 정리 15초 상한에 걸렸고, 문서만 바뀐 커밋이라 실패 잡만 재실행했다). 크기: 2.6ew 내역 전부 착지.
- **이슈 처리 기록 (2026-09-26):** GitHub 이슈 #5(`qsh exec`가 이름을 forward 주소록에서만 찾아 살아 있는 역방향 등록을 쓰지 못하던 결함)는 M10 범위 밖의 결함 수정으로 처리했다(커밋 74a4d4c, `docs/CLI.md` v0.13 §6.1·§6.8·§6.13). wire는 바뀌지 않았고 controller의 `qsh listen`이 이 빌드 이상이어야 역방향 exec가 된다(`RELEASE-NOTES.md`). 클린 VM 회차는 아직 돌지 않았으므로 첫 태그 트리가 이 수정을 담는다. 마일스톤 상태와 DoD는 바뀌지 않는다.
- **첫 태그 기록 (2026-09-26):** 사용자가 2026-09-26에 M10 파이프라인의 첫 태그를 승인했다. `v0.3.0` = `891c407`(`chore(release): 버전을 0.3.0으로 올린다`)이고 이슈 #3·#4·#5 수정분이 이 트리에 들어 있다. release run 36254706923의 빌드 여섯·release·homebrew-tap 잡이 모두 성공해 GitHub Release에 자산 여섯과 `SHA256SUMS`가 붙었고, tap `Formula/qsh.rb`는 잡이 0.3.0으로 다시 썼다(tap 커밋 `f66f76d`). Apple 시크릿 여섯이 아직 등록되지 않아 두 darwin leg은 `::warning title=Unsigned release::`를 남기고 ad-hoc 서명으로 나갔다. 그래서 이 태그로는 DoD 2를 판정하지 않는다(`docs/campaigns/m10-clean-vm.md` §2.1). 같은 날 에이전트가 이 태그로 클린 회차 셋(Linux x86_64 glibc, 구형 glibc musl, Linux aarch64 glibc)을 돌려 셋 다 PASS했고 캠페인 문서 §8의 회차 1·2·3에 적었다. 이 태그로는 캠페인이 닫히지 않는다. 시크릿이 등록된 뒤 서명·공증이 붙은 새 태그를 찍고 다섯 회차를 그 태그로 다시 돈다. 그 태그가 캠페인 PASS 트리일 때 M10 태그가 된다(이 절의 태그 정책). 마일스톤 상태와 DoD는 바뀌지 않는다.

## 3. 유예 가드레일 (P1/P2 경계)

작동 원리: **"ACL action과 오류 경로만 정의하고 구현하지 않는다."** 이름 붙은 "아직 아님"은 단순 부재보다 scope creep에 훨씬 강하다.

| 유예 기능 | 압력원 | 가드레일 |
|---|---|---|
| TCP/TLS fallback (P1) | doctor가 "UDP 차단"을 보고하는 순간 | transport 추상화는 P0에 있으나 **TCP 코드는 0줄**. doctor 메시지가 "P1 예정"을 명시 (ADR-0005). → M14 |
| SOCKS `-D` (P1 → M9 범위로 승격, 2026-09-19 → [ADR-0019](adr/0019-socks-dynamic-forward.md)) | 스펙 예시에 존재 | M9가 구현한다. `-D`는 CONNECT마다 `forward.local`로 인가된다. `forward.socks` action은 어휘에 남고 여전히 항상 deny다. 이 토큰을 적은 기존 `acl.toml`이 파싱 오류로 전부 거부 상태가 되지 않게 하려는 것이다 |
| File copy (P1) | `file.read/write` action이 §9에 존재 | action만 정의, op 미등록, capabilities에 미광고. → M15 |
| Windows (P1 client / P2 host) | 외부 기여 PR | PTY 코드에 `#![cfg(unix)]`. CI는 `windows-latest`에서 build/clippy/portable 테스트만 돌려 컴파일 회귀를 막는다(POSIX 시그널·process-group 테스트는 `cfg(unix)`). 지원 약속 아님 — README.md Known limitations에 명시. (P1 client → M19 / P2 host) |
| Multi-attach read-only (P2) | broker에서 거의 공짜로 나옴 — 그래서 위험 | **관찰자(observer) 개념 자체를 만들지 않는다.** writer lease는 P0 필수, 두 번째 attach 정책은 lease 규칙만 따름 |
| Local echo prediction (P2) | mosh 대비 지연 불평 | P0는 실제 PTY 지연을 측정·공개해 데이터로 대화 (§13의 10ms 예산) |
| Relay (§14, 별도 제품) | "작은 relay 하나면" | P0 의무는 세션 identity와 transport 분리뿐(resume이 이미 강제). **`--relay` flag는 stub조차 없음** |
| Forward-route live carrier·`-R` 자동 재발행 (M8 소유 → [ADR-0018](adr/0018-tunnel-lifetime-bound-to-connection.md)로 종결) | 터널이 recovery 후에도 신규 연결을 서비스하길 기대 | 연결 손실→resume에서 터널 스트림은 깨끗이 종료된다는 현행 의미론을 M4가 테스트로 고정(`tunnel_chaos.rs`의 개정 강제 트랩)했고 README Known limitations가 고지한다. M4 마감 노트가 M5 입력으로 이관, M5가 범위 밖 판정 후 여기 등재(PLAN.md M5판 §3 (v)). **M8 Step 6(2026-09-09)이 ADR-0018로 확정: v1 터널 수명은 connection에 결합, live carrier는 구현하지 않으며 `-R` 자동 재발행은 P1(freeze는 additive 확장을 막지 않는다).** → M12. ADR-0023이 ADR-0018 결정 2·3을 명시적으로 켠 터널에 한해 개정하고 결정 1은 유지한다 |
| Cert rotation UX (P1) | 만료 | P0: 만료 30일 전 doctor 경고만. → M16 |
| Service 설치 (P1 → M9 범위로 승격, 2026-09-07; 2026-09-09 마일스톤 분리 후에도 신설 M9 소속) | 상시 실행 요구 | M8까지는 unit 예시 문서(`docs/deploy/service.md`, M8 Step 6)만 제공하고 `qsh service install`은 신설 M9(사람용 표면) 범위 항목대로 구현한다 |
| **메타 가드레일** | — | `qsh capabilities --json` == fixture 테스트: 새 capability는 fixture diff로만 추가 가능 (리뷰 가능한 산출물). + ErrorCode 전수 도달성 테스트: 존재하지만 만들 수 없는 코드 금지 |

SSH 키 가져오기 → M11 (c). ADR-0026 결과 절이 요구한 가드레일 행은 P1 착수로 M11 범위 항목이 됐다.

## 4. 일정 리스크 5건

1. **SC3(≥95% mobility)은 CI로 측정 불가능한 측정 문제이고, 통과 기준이 미정의면 그 자체가 리스크.** 대응: chaos proxy + recovery 텔레메트리를 M2에 구축, M2 말 실기기 20회 조기 측정, "idle timeout이 늦게 터져서 기술적으로 통과"를 배제하는 기준(재dial 2초)을 지금 명문화, M8에 ≥60회 본 캠페인.
2. **PTY/터미널 정확성은 추정을 거부하는 long tail.** 대응: M2b를 명명된 수용 세트(bash/zsh+vim+tmux+claude)로 timebox, "terminal quirks" 백로그를 마일스톤 밖에 유지, expect 하네스를 초기에 구축해 수정마다 회귀 테스트가 싸게 남게.
3. **Identity·keystore·pairing이 SC1(간판 숫자)의 critical path.** headless Linux에 Secret Service 부재 → file fallback + doctor 보고 필수, macOS 미서명 바이너리의 Keychain 재프롬프트가 dev loop을 괴롭힘. 대응: keystore fallback을 M1의 명명된 task로, 스톱워치 테스트를 M7 한 번이 아니라 조기·반복 실행.
4. **In-listener 세션과 listener 재시작/업그레이드의 충돌은 구조적.** 대응: ADR-0003의 `SessionBackend` seam을 처음부터 순수하게 유지(CI로 transport import 금지 확인), graceful re-exec(fd 보존 handoff)을 M8 stretch로 비용 산정. **비용 산정 완료(2026-09-10, `docs/design/reexec-estimate.md`):** 후보 H0(고지)~H5(supervisor 분리) 여섯을 ew로 매겼다 — M8 구현 0, H0 고지는 같은 커밋에서 반영, H1·H1b·H2는 M9 후보, H4 execve 제자리 handoff 4.2ew와 H5 supervisor 분리 6.5ew는 P1로 넘기고 P1 진입 시 세션이 어느 프로세스에 사는지를 먼저 고른다. **P1 귀속(2026-09-26):** H1·H1b는 M13, H2·H4·H5와 세션 거처 결정은 M18이 가진다(§5).
5. **SC7 보안 리뷰와 notarization은 리드타임 함정.** 대응: 리뷰는 M5 시점에 예약하고 wire format을 리뷰 ~6주 전에 freeze, notarization은 M10이 아니라 M8 중 시작.

## 5. P1 마일스톤

P1은 2026-09-26 사용자 결정으로 열었다. 같은 날 ADR-0021·0022·0025·0026이 승인됐다. P0 완료 선언(이 문서 머리의 조건 문단)은 P1과 독립적으로 사람 회차 일곱이 닫힐 때 한다. §2의 "마일스톤 마감 공통 절차" 1·2는 P1 마일스톤에도 적용한다. 크기는 전부 추정이고 1인 기준 ew다.

### 5.1 P1 시퀀싱 원칙

1. 이슈가 남긴 승인 ADR을 먼저 구현하고, 이슈가 남긴 제안 ADR을 그다음에 둔다. 이슈 #3·#4의 항목은 ADR-0021·0022·0025·0026(승인)과 ADR-0023·0024(제안)로 모양이 거의 정해졌다. 모양이 정해진 일을 먼저 끝내야 뒤의 설계 라운드가 그 결과를 입력으로 쓴다. M11은 승인 ADR만 다루고 M12는 제안 ADR 둘을 다룬다.
2. 계약·wire를 건드리는 항목은 ADR 승인 전에 구현 스텝을 열지 않는다. 아홉 마일스톤 중 일곱(M12, M14~M19)이 제안 ADR이나 새 ADR의 승인을 착수 조건으로 삼는다. M11과 M13은 승인 없이 열린다. 다만 M13 (b)가 흐름 제어 설계 변경을 부르면 그 항목만 ADR을 기다리고, M13 (d)는 ADR-0027을 기다린다. P1 일정은 사용자 승인이 가장 크게 좌우한다. 승인이 늦는 마일스톤은 기다리게 두고 순서상 다음 마일스톤을 먼저 연다.
3. 측정 도구를 기능보다 먼저 세운다. 느린 스트림의 저속·역압 축과 야간 성능 추세(M13)가 TCP fallback(M14)과 파일 복사(M15)보다 앞선다. 두 기능 모두 PTY 우선순위 보장(`tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`가 지키는 것)을 흔들 수 있고 흔들렸는지를 재는 도구가 먼저 있어야 한다.
4. transport 추상을 세운 뒤 TCP를 붙이고, 파일 복사는 그 뒤에 둔다. `qsh-transport`의 `Transport`/`StreamMux` 추상이 TCP fallback의 선행 정리다. 파일 복사는 두 transport 위에서 한 번에 검증되도록 TCP 뒤에 둔다.
5. 신뢰의 방향을 정한 뒤 pairing을 넓힌다. pin 방향 축(ADR-0017 결정 5가 미룬 후속 ADR)이 listener pairing(ADR-0015)의 결정 하나를 좌우한다. `qsh setup`(M12)은 오늘 있는 pairing 경로만 조립하고, M16이 새 경로를 열면 ADR-0024 결정 2의 역할 표에 행을 더하는 식으로 뒤따른다.
6. 사람 회차는 마일스톤 DoD에 넣지 않는다. DoD는 캠페인 문서가 사전 고정돼 커밋되는 데까지다. 회차 기록은 §5.5에 모으고 P1 완료를 선언할 때의 조건으로 둔다. P0의 M7~M10은 회차를 DoD에 넣었기 때문에 "기능 완료 · DoD 잔여"로 멈춰 있다. 사람 회차를 착수 조건으로 거는 마일스톤은 M18 하나다(M8 DoD 3). 조건이 닫히지 않았으면 M18을 건너 M19를 먼저 열고, 건너뛴 사실을 이 절에 날짜와 함께 적는다.

### M11 — 이슈 후속과 ACL 가시성

- **범위:** 이슈 #3·#4가 남긴 항목 중 승인 ADR로 모양이 정해졌거나 새 결정 없이 끝낼 수 있는 것. 이 마일스톤에는 사용자 승인을 기다리는 항목이 없다.
  - (a) `cause` 어휘 분리(ADR-0021 결정 7의 선행 조건). `classify_connection_error`(`crates/qsh-core/src/reverse/mod.rs`)는 quinn idle timeout(`ConnectionError::TimedOut`)을 상대가 보낸 `CLOSE_CODE_PATH_DEAD`와 같은 `path_dead`로 적고, 자기 쪽 `PathWatch` 판정(`reverse/target/mod.rs`, `reverse/listen/registration.rs`)도 `path_dead`를 낸다. 함수의 doc comment가 이 합침을 의도로 적고 있어서 결정 7이 요구하는 "어느 타이머로 죽었는가"를 현장 로그로 가를 수 없다. `TimedOut`에 새 값 `idle_timeout`을 주고 `PathWatch` 판정은 `path_dead`에 남긴다. `qsh::reverse` 줄은 계약이 아니므로(ADR-0022 결정 5, `docs/CLI.md` §6.13) `qsh.cli/v1`·fixture·wire는 바뀌지 않는다. §6.13의 "고정 8값" 문장과 함수 doc의 "fixed eight-value vocabulary"는 같은 커밋에서 9값으로 고친다. 통합 테스트에는 제약이 하나 있다. 역방향 두 자리는 `PathWatchConfig::default()`를 박고 있어 약 1초 안에 판정하고(ADR-0021 맥락 절), idle timeout은 45초 고정이다(ADR-0021 결정 2). `#[cfg(test)]` 전용 주입으로 두 자리의 `PathWatchConfig`에서 `min_dead_after`를 idle 45초보다 크게 둔다. `cfg(test)` 코드는 바이너리에 들어가지 않으므로 ADR-0021 결정 4의 config 개방이 아니고, 모듈 doc에 그렇게 적는다. 약 50초짜리 crate 내부 테스트를 `QSH_ACCEPTANCE_SLOW` 아래 `ci.yml` acceptance job에서 돌리고, 대안은 `load.yml`이다.
  - (b) `qsh acl show`(ADR-0025). 결정 2~6의 모양이다. `qsh acl show --principal <p> [--auth-path pin|ca]`, 매칭 행과 실효 action 집합 출력, `Policy::decide` 재사용, 인가 불요 local op, `auth_path` 기본값 고지. ADR-0017 결정 2의 재시작 remedy는 아직 상수가 아니다. `crates/qsh-core/src/doctor.rs`의 `acl_principal_unmatched`와 `acl_ca_auth_path_missing` remedy가 "then restart serve/listen — acl.toml is only read once at process start."를 각자 문자열 안에 품고 있다. 이 절을 상수 하나로 뽑아 두 진단과 `acl show`가 함께 쓴다. M12 (b)의 `qsh setup`도 이 상수를 쓴다.
  - (c) `qsh init --import-ssh-key <path>`(ADR-0026). 결과 절이 정한 모양이다. 명시적으로 켜는 플래그, 평문 Ed25519 파일 하나, qsh fingerprint와 SSH fingerprint 나란히 출력, `authorized_keys` 이행은 출력만 하는 미리보기(결정 4), 자동 pin 없음, `acl.toml` 쓰기 없음. 파서는 신뢰할 수 없는 입력을 읽으므로 `qsh-proto`에 두고 fuzz 타깃을 하나 더한다(ADR-0001 규율). identity가 이미 있는 장비에서는 `init`의 멱등 경로(`created: false`)를 타지 않고 오류로 끝난다. ADR-0026 맥락 절이 적듯 이미 있는 키를 갈아 끼우는 일은 가져오기가 아니라 rotation(M16 (d))이다.
  - (d) doctor 진단 1종(ADR-0019 결과 절 R6). `allow`가 `forward.socks`를 적었지만 `forward.local`(또는 `forward.*`)로는 덮이지 않는 `[[acl]]` 행을 짚는다. `forward.socks`는 어떤 op도 인가하지 않으므로(ADR-0019 결정 6) 이 행은 `-D`를 의도했지만 효과가 없다.
  - (e) 문서 갭. README에 한 장비를 두 별칭으로 pin하는 배치(inbound `qsh serve` 주소 별칭과 `qsh serve --to`로 등록되는 이름)를 설명하는 절, 더 긴 정전을 `[listen].stale_retention`으로 덮는 운영 안내(`backoff_max_ms`의 배수 하한 관계 포함, `crates/qsh-core/src/config.rs`의 `ListenConfig::stale_retention`). 두 별칭 절은 `SharedTrustStore::lookup_pin`(`crates/qsh-core/src/trust/mod.rs`)의 성질을 그대로 적어야 한다. 이 함수는 fingerprint가 같은 첫 항목을 돌려주고 handshake마다 파일을 다시 읽는다. 그래서 inbound principal은 `trust.toml`에서 먼저 나오는 이름이고, 두 번째 이름으로 쓴 `[[acl]]` 행은 inbound에서 매칭되지 않으며, 파일 순서를 바꾸면 재시작 없이 principal이 바뀐다. README는 "ACL 행은 먼저 나오는 이름으로 쓰고 두 번째 이름은 outbound dial 별칭으로만 쓴다"고 안내하고, 이 배치를 정식으로 푸는 자리가 M16 (a)임을 적는다. `docs/CLI.md` §6.13의 주소 상한 문장은 이미 있다("최대 4개까지 순서대로 dial").
- **명시적 out:** `qsh acl grant`/`revoke`(ADR-0025가 기각), 원격 ACL 미리보기(ADR-0025 결정 4), 암호화된 SSH 키·ssh-agent·RSA/ECDSA(ADR-0026이 별도 결정으로 분리), supervised tunnel과 `qsh setup`(M12), push health 표면(ADR-0022 결정 3의 관측 트리거 전), `HOST_NOT_FOUND` 구제 문면 교체(§5.3), ADR-0021 결정 1·4의 구현(M13 (k)).
- **수용 기준 (DoD):**
  - (a) 단위 테스트가 `classify_connection_error`의 세 갈래를 고정한다. `TimedOut`은 `idle_timeout`, `CLOSE_CODE_PATH_DEAD`를 실은 `ApplicationClosed`는 `path_dead`, 그 밖의 `ApplicationClosed`는 `peer_closed`다. 범위에서 고른 방식의 통합 테스트에서 target의 `lost`·`retry` 줄과 controller의 `lost` 줄이 `cause: "idle_timeout"`을 낸다. `run_target_lost_and_retry_lines_report_a_silent_path_as_path_dead`는 고치지 않고 초록이다. fixture·wire·`qsh.cli/v1` diff 0.
  - (b) `acl.show` op이 등록 완전성을 갖춘다. 새 fixture를 `REQUIRED_FIXTURES`에 등재하고, schemars 타입·`cli_v1_data_schema` arm·`CLI_V1_SCHEMA_COMMANDS`·human/JSON 렌더러·`docs/CLI.md` §2.5 local-only 행과 명령 절·man 페이지가 모두 있음을 `layer_2_every_schema_command_has_all_six_faces`가 확인한다. `acl_check_equivalence.rs`가 표 기반 정책마다 `acl show`의 실효 집합과 `Action::ALL` 각각에 대한 `acl check` 판정이 일치함을 단언한다. 동치만으로는 둘이 같이 틀려도 초록이므로 ADR-0025가 적은 성질 둘을 따로 고정한다. `acl.toml`이 없을 때와 파싱에 실패했을 때 실효 집합은 공집합이고 출력이 "정책 없음"을 알린다. `forward.*`나 `file.*`를 적은 행에서도 `forward.socks`·`file.read`·`file.write`는 실효 집합에 없다. 원격 peer가 이 op을 부를 wire 메시지가 없음을 op registry 분류 테스트가 확인한다. 재시작 문구 상수를 두 doctor 진단과 `acl show`가 함께 쓰고, `acl show`의 human 출력과 두 doctor remedy가 그 상수를 바이트 단위로 담는다. `Policy::decide`는 `pub(crate)`이고 비테스트 호출 지점은 셋이며, 그 메서드의 doc과 `acl_check_equivalence.rs` 모듈 doc의 "두 호출 지점" 산문이 같은 커밋에서 셋으로 바뀐다.
  - (c) 평문 Ed25519 OpenSSH 개인키 하나로 identity가 만들어지고 출력(human·JSON)에 qsh fingerprint와 SSH fingerprint가 나란히 나온다. 거절 코드는 이렇게 고정한다. 암호화된 키·RSA·ECDSA는 `UNSUPPORTED`, 손상된 입력은 `INVALID_ARGUMENT`, identity가 이미 있는 장비는 `INVALID_ARGUMENT`이고 message가 오늘 되는 복구 경로(`identity/`를 치우고 다시 가져온 뒤 peer가 다시 pin)를 적고, 제자리 교체는 M16 (d)의 rotation으로 남는다. 각 거절은 fixture로 등재되고 identity 파일을 남기지 않으며, 이미 있던 identity 파일과 keystore는 바이트 단위로 같다. 가져오기와 `authorized_keys` 미리보기 전후로 `trust.toml`과 `acl.toml`이 바이트 단위로 같다. 미리보기는 필요한 pin과 `[[acl]]` 행을 출력만 하고 어떤 파일도 쓰지 않는다. 손상 입력 테스트가 입력 바이트가 message, `details`, 로그 어디에도 실리지 않음을 단언하고, 개인키 버퍼는 `Zeroizing`에 둔다(`crates/qsh-core/src/resume.rs`의 토큰 위생과 같은 규율). JSON 추가 필드는 optional이고 기존 `identity.init` fixture는 한 바이트도 바뀌지 않는다. 새 fuzz 타깃이 fuzz-smoke에서 돌고, `fuzz/README.md`·`docs/design/testing.md` L8의 타깃 개수와 `docs/design/protocol.md` §13의 타깃 개수(18종)·나머지 파서 타깃 수가 같은 커밋에서 바뀐다. M8 DoD 1의 분모(파서 16종)는 그대로다. README Known limitations에 공유 키의 잔여 위험을 적는다. M16 (d)의 rotation이 착지하기 전까지 SSH 키가 새면 복구 수단은 재 init과 재 pairing뿐이다. 새 의존이 `cargo deny check`를 통과하고 `checked_in_man_pages_match_the_generator`가 초록이다.
  - (d) 새 진단이 안정된 code와 실행 가능한 remedy로 테스트에 고정되고, `EXPECTED_DOCTOR_CODES`가 22종에서 23종이 된다. 같은 커밋에서 `docs/CLI.md` §6.11의 "진단 코드 N종", §6.17의 "N종 진단 코드"와 표, `crates/qsh-core/src/doctor.rs` 모듈 doc의 "22 variants"가 함께 바뀐다(`expected_doctor_codes_matches_every_diagnostic_id_variant_exactly`, `cli_md_prose_doctor_code_count_matches_expected_len`).
  - (e) 두 별칭 절이 적는 동작을 먼저 테스트로 확인한다. 같은 fingerprint를 두 이름으로 pin하면 inbound principal이 `trust.toml`에서 먼저 나오는 이름이고, 두 번째 이름의 `[[acl]]` 행은 inbound에서 매칭되지 않으며, 순서를 바꾸면 재시작 없이 principal이 바뀐다. `acl_principal_unmatched`가 두 번째 이름을 어떻게 세는지 확인해 README 절에 적는다. 테스트 이름을 README 절 근처 주석이나 커밋 본문에 남긴다.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 2.8~4.1ew. (a) 0.6~0.9(어휘 값 하나, 분류 지점 하나, 테스트 전용 주입 두 자리 또는 load 테스트, 문서 두 곳) / (b) 0.55~0.8(신규 local op 하나의 등록 완전성과 재시작 문구 상수 추출. `docs/ROADMAP.md` M9 크기 줄의 op 신설 항목이 항목당 0.4~0.7ew였던 것에 비춘 규모) / (c) 1.2~1.8(신규 파서와 fuzz 타깃, 새 의존 심사, init 경로 분기와 기존 identity 거절, 미리보기, 거절 fixture) / (d) 0.15~0.25 / (e) 0.1~0.15 / 마감 0.2.
- **결정 기록 (2026-09-27, main 세션이 사용자 전면 자율 지시에 따라 정함):**
  - Q1 supervised tunnel과 `qsh setup`의 자리. 둘 다 승인 대기 중인 제안 ADR이라 M12로 묶는다. M11은 승인을 기다리지 않고 닫힌다.
  - Q2 SSH 키 가져오기의 순서. ADR-0026 결과 절은 rotation ADR이 먼저 서면 가져오기가 그 두 번째 키 경로에 얹힌다고 적는다. rotation 설계(M16 (d))는 아직 한 줄도 없으므로 기다리지 않고 M11에서 한다. 그 사이의 잔여 위험은 README가 고지하고, M16 DoD가 가져온 키로 만든 identity의 rotation을 요구한다.
  - Q3 `forward.local`이 빠진 행을 짚는 별도 진단은 만들지 않는다. 터널 권한이 없는 principal은 정상 배치라서 의도 신호 없이 짚으면 잡음이 된다. 의도가 드러나는 경우(`forward.socks`를 적은 행)는 (d)가 잡고, 나머지는 (b)의 `acl show`와 기존 `qsh acl check --action forward.local`(`docs/CLI.md` §6.15)이 답한다.
  - Q4 `acl show`의 우선순위. ADR-0025 결정 7은 배치를 "M10 이후 또는 P1"로 두었다. 2026-09-26 사용자 지시("전부 다 진행")가 P1을 열어 그 배치를 정한다.
  - Q5 identity가 이미 있는 장비에서 `--import-ssh-key`는 성공 응답(`created: false`)이 아니라 오류다. 성공으로 돌려주면 운영자는 SSH 키를 들여왔다고 믿고 옛 fingerprint로 계속 쓰게 되어 ADR-0026 결정 3이 막으려던 원인 없는 default-deny가 생긴다.

### M12 — 이슈 설계 ADR 구현(supervised tunnel, `qsh setup`)

- **범위:** 이슈 #4 항목 5b와 이슈 #3의 온보딩 흐름. 두 설계는 2026-09-26에 제안 ADR로 나왔고 이 마일스톤은 승인 뒤의 구현이다.
  - (a) supervised tunnel mode(ADR-0023). 산정 전제는 기본 동작을 바꾸지 않고 명시적으로 켜는 모드(opt-in)다. ADR-0023 초안은 터널을 연 프로세스가 연결 유실 뒤 로컬 listener를 쥔 채 스스로 재수립하는 모양을 고른다. ADR-0018과의 관계는 이렇다. ADR-0023은 ADR-0018 결정 2·3을 켠 터널에 한해 개정하고 결정 1은 유지한다. wire 위의 터널 객체(`forward_id`, 스트림마다의 splice)는 여전히 connection 수명에 묶이고, 켠 터널이 하는 일은 결정 1이 처방한 "새 `tunnel.open`"을 프로세스가 스스로 하는 것이다. ADR-0018 제목과 결정 1의 "v1 내내"가 wire 위 터널 객체의 수명을 가리킨다는 해석은 ADR-0023 맥락 절이 한 문장으로 적는다. `docs/adr/README.md`의 0023 행 설명("ADR-0018 결정 2·3을 개정")은 이 관계와 맞으므로 그대로 둔다. 재수립은 매번 처음부터 인가를 거치고, 진행 중이던 TCP 연결은 살리지 않는다.
  - (b) `qsh setup`(ADR-0024). 초안의 모양은 새 판정 로직이 없는 오케스트레이터다. dotted op 이름은 `setup.run`이고 인가 불요 local op이며, 상태를 바꾸는 호출은 기존 `Ops` 메서드 `identity_init`, `trust_invite`, `trust_accept`, `trust_add`, `service_install`과 audit 경로를 점검하는 `doctor`뿐이고, 읽기는 `trust_list`, `acl_check`, `service_status`, `Ops::config()`와 ADR-0024가 신설하는 초대 읽기 도우미 하나다. `acl.toml`은 쓰지 않고 넣을 행을 인쇄한다(ADR-0017 결정 1). machine mode에서는 그 행이 envelope의 문자열 필드 `acl_rows`로 나가고 stdout은 순수 JSON이다. 자동 신뢰는 없다(ADR-0017 결정 5). `--json`/`--jsonl`에서 프롬프트를 열지 않고 빠진 입력은 쓰기 전에 `INVALID_ARGUMENT`다(ADR-0024 결정 7, `docs/CLI.md` §6.11과 같은 규율). SC1 측정은 착수 조건이 아니라 사후 판정이다(ADR-0024 결정 12).
- **착수 조건:** (a)는 ADR-0023 승인, (b)는 ADR-0024 승인. 둘 다 승인 전이면 M13을 먼저 연다(§5.1 원칙 2). 하나만 승인됐으면 그 항목을 진행하고 다른 하나는 승인될 때 이어서 하거나 다음 마일스톤으로 이월해 이 절에 적는다.
- **명시적 out:** supervision을 기본값으로 켜는 것, `forward_id` 재claim 같은 wire 필드(ADR-0023 초안은 쓰지 않는다), 진행 중 TCP 연결의 생존, 서비스 유닛 활성화(M17 (a)), `acl.toml`을 쓰는 어떤 동작, 관측한 fingerprint를 y/n으로 확인받아 pin하는 경로(ADR-0024 결정 6), 새 pairing 경로(M16).
- **수용 기준 (DoD):**
  - (a) ADR-0023이 `승인됨`이고 개정 관계 절이 ADR-0018 결정 1을 유지 항목으로 이름 짓는다. 켜지 않은 터널에서 `a_dead_connection_ends_the_tunnel_cleanly_while_the_pty_session_resumes`와 `tunnel_open_local_over_reverse_ends_when_the_registration_drops`가 고치지 않은 채 초록이다. 켠 터널은 chaos `sever()` 뒤에도 로컬 listener가 살아 있고, 재수립 뒤 들어온 새 TCP 연결이 목적지에 닿는다.
  - (a) 재수립마다 admission, mTLS, `forward.local`/`forward.remote` 인가를 다시 거친다. 그 권한을 뺀 `acl.toml`로 재시작한 peer에 대해서는 재수립이 `PERMISSION_DENIED`로 끝나고 peer audit에 deny가 남는다. 재수립 전에 `trust remove`된 peer로는 handshake가 거부된다.
  - (a) 재수립이 다른 principal의 자원을 닫거나 넘겨받는 경로가 없다. `RemoteForwardClose`는 `authorize_owned`(`crates/qsh-core/src/server/reverse.rs`)를 거치므로 `Scope::Owned` 행 아래에서 다른 principal이 보낸 close는 `PERMISSION_DENIED`이고 그 listener가 남는다는 것을 테스트가 고정한다. purge된 connection의 `forward_id`를 닫는 경계 사례는 "no such forward_id"로 끝난다. 유실 구간에 다른 principal이 같은 포트를 먼저 bind하면 켠 터널은 그 포트를 되찾으려 하지 않고 끝난다. reverse route에서 같은 이름으로 다른 fingerprint가 재등록하면 재확인 전의 accept가 한 바이트도 relay되지 않고 터널이 끝난다. `docs/design/threat-model.md` §4 A·B에 재dial 시 peer 치환과 재발행 소유 행이 이 테스트 이름과 함께 오른다. `scope = "any"` 행을 가진 principal은 오늘도 남의 forward를 닫을 수 있으므로 켠 터널이 새 권한을 만들지 않는다는 점도 같은 행에 적는다.
  - (a) `trust remove` 뒤에도 이미 살아 있는 연결 위의 켠 터널은 계속 돈다(`TrustRemoveScope` remedy가 적는 현행 범위). 이 사실과, 끊김 순간 진행 중이던 TCP 연결은 살리지 못한다는 사실이 `docs/CLI.md` §6.9·§6.14와 README Known limitations에 적힌다. 기존 연결의 강제 종료는 M16 (d)가 다룬다.
  - (a) ADR-0023 초안은 wire를 바꾸지 않는다. 최종 ADR이 wire 필드를 더한다면 capability로 보호되고, decode 경로가 기존 fuzz 타깃에 걸리며, freeze 발효 전이면 `docs/design/protocol.md` §16.1 목록을 같은 커밋에서 고친다.
  - (b) ADR-0024가 `승인됨`이다. 네 역할의 모든 분기 테스트가 끝난 뒤 `acl.toml`이 없거나 실행 전과 바이트 단위로 같다. `setup.run`이 원격 op을 새로 만들지 않음을 op registry 테스트가 확인한다. 인쇄된 행을 그대로 파일에 넣으면 `qsh acl check`가 의도한 action을 allow로 판정한다. machine mode의 stdout은 envelope 한 줄이고 프롬프트가 열리지 않으며 입력이 빠지면 어떤 파일도 생기기 전에 `INVALID_ARGUMENT`다. 재시작 고지는 M11 (b)의 상수와 바이트 단위로 같다. `crates/qsh-core/src/setup/`이 `cargo xtask arch`의 디렉터리 범위 금지 대상에 오르고 자기 테스트가 있다. 등록 완전성, fixture 등재, `docs/CLI.md` §2.4·§2.5·신설 절, man 재생성을 갖춘다.
  - (b) `qsh setup`의 첫 코드 커밋보다 먼저, 그 커밋의 부모 SHA가 `docs/campaigns/m9-stopwatch.md` §8의 m9 재측정 칸 "qsh 커밋 SHA"에 고정된다(ADR-0024 결정 12). README의 `qsh setup` 절은 그 고정 뒤에 붙는다. `qsh setup` 경로로 SC1 스톱워치 3회를 재는 캠페인 문서(`docs/campaigns/p1-setup-stopwatch.md`)가 사전 고정돼 커밋된다. 회차는 §5.5의 사람 몫이고 이 DoD에 들지 않는다. PASS가 기록되기 전에는 이슈 #3 완료 기준 첫 줄이 충족됐다고 적지 않는다.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 3.8~5.3ew. (a) ADR 마무리 0.2 + 구현 1.5~2.5(ADR-0019 SOCKS `-D` 1.6~2.0ew 유추) + 소유·재확인 테스트와 threat model 0.2~0.3 / (b) ADR 마무리 0.1 + 구현 1.6~2.0(ADR-0024 결과 절의 내역) / 마감 0.2.
- **결정 기록 (초안, M12를 열 때 확정):**
  - Q1 `qsh setup`은 SC1 재측정을 기다리지 않는다. ADR-0024 결정 12가 측정을 사후 판정으로 옮기고 M9 재측정의 대상 트리를 SHA로 고정하기 때문이다. 사용자가 결정 12 없이 ADR-0024를 승인하면 (b)는 M9 DoD 1 기록을 착수 조건으로 갖고, 기다리는 동안 다음 마일스톤을 먼저 연다.
  - Q2 두 설계를 한 마일스톤에 묶는 이유. 둘 다 같은 날 나온 이슈발 제안 ADR이고 승인 시점이 비슷하다. 묶으면 M11이 승인과 무관하게 닫힌다.
  - Q3 supervised tunnel이 기본 동작을 바꾸는 쪽으로 결정되면 기존 트랩 테스트의 개정이 그 결정의 시행 지점이 되고 크기를 다시 매긴다.

### M13 — 측정·배포 기반

- **범위:** 뒤 마일스톤이 회귀를 잴 수 있게 하는 측정 도구, P0 릴리스 라인에서 P1로 넘어온 배포·운영 항목, ADR-0021의 관측 게이트 뒤 구현.
  - (a) 야간 성능 추세(nightly perf job). 절대 throughput과 포화 상태의 echo p95 추세를 쌓는다. 쌓을 저장소를 먼저 정한다. 저장소 없이 job만 세우지 않는다(`docs/design/testing.md` CI 규율 절).
  - (b) 느린 스트림의 저속·역압 축. 포화(고속) 축은 M10이 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`로 닫았다. 소비자가 읽지 않는 터널 스트림 여럿이 동시에 정체할 때 PTY 스트림이 막히지 않는지를 새 하네스로 잰다. 예상 결과는 붉음이다. `crates/qsh-transport/src/endpoint.rs`에서 `TUNNEL_STREAM_RECEIVE_WINDOW`는 2 MiB이고 `CONNECTION_RECEIVE_WINDOW`는 8 MiB이므로, 읽히지 않는 스트림 넷이 각 2 MiB를 채우면 연결 수준 credit이 소진되어 PTY 스트림도 멈춘다. 8 MiB는 그 상수의 doc이 적듯 M8 DoD 2의 "세션당 buffer ≤ 8 MB"에서 왔다. 연결 window를 키우면 그 상한과 어긋나고, 스트림 window를 줄이면 `tunnel_throughput` 비율 게이트(≥80%)와 `docs/design/protocol.md` §12가 기각한 128 KiB 사례로 돌아간다. 그래서 수정은 상수 조정이 아니라 splice 설계 변경(예: 수신 스트림을 앱 쪽 유계 버퍼로 비우고 그 버퍼가 차면 그 스트림만 reset)일 가능성이 크다.
  - (c) `aarch64-unknown-linux-musl` 자산. x86_64 musl 레시피를 네이티브 arm 러너에 복제한다(M10 결정 기록 Q3). `scripts/install.sh`의 기본값은 `QSH_LIBC=gnu`이고 이 기본은 바꾸지 않는다. 바뀌는 곳은 aarch64에서 `QSH_LIBC=musl`을 준 분기 하나다. 오늘 그 분기는 "no aarch64 musl asset is published"로 끝난다.
  - (d) `qsh doctor --fail-on <severity>`. `docs/CLI.md` §6.17이 additive 후보로 적어 둔 플래그. 임계를 넘었을 때의 exit 값은 §4 표를 건드리는 계약 결정이라 ADR-0027로 먼저 정한다. §4의 `255`는 "연결, 인증, 정책 등 QSH runtime 실패"이므로 envelope이 `ok: true`인 채로 `255`를 내면 두 신호가 어긋난다. 초안은 envelope에 `ok: true`와 findings를 그대로 내고 exit만 §4에 additive로 더한 새 값 하나로 바꾸자고 제안한다.
  - (e) graceful re-exec H1(관측). `docs/design/reexec-estimate.md` §3의 H1 행. SIGTERM drain 요약, doctor 진단 1종, 배너.
  - (f) H1b(stateless reset key 고정). 같은 표의 H1b 행. 재시작 뒤 클라이언트가 45초 idle timeout이 아니라 다음 패킷 1 RTT로 단절을 안다. 같은 행의 "잃는 것" 칸이 적듯 세션은 여전히 죽는다. H1b가 바꾸는 것은 감지 지연이지 recovery 분류가 아니다. reset key는 새면 off-path에서 연결을 끊을 수 있는 비밀이라 보관 위치와 함께 파일 권한과 읽기 실패 시 동작을 정한다.
  - (g) 공개 크레이트 tarball의 test 타깃 `exclude` 정책 확정.
  - (h) `scripts/install.sh`의 provenance 검증. 초안의 제안은 fail closed 쪽이다. 검증 도구가 없으면 `SHA256SUMS` 검증까지 하고 provenance 미검증을 경고하며, 둘 다 건너뛰는 것은 명시 플래그로만 한다.
  - (i) curl 설치 경로의 man 페이지 설치.
  - (j) `docs/CLI.md` 상태 헤더의 기계 핀. 무엇을 고정할지부터 정하고, 0.3ew 안에 정하지 못하면 기각으로 기록한다.
  - (k) ADR-0021 결정 1·4 구현(관측 게이트). 결정 7은 `cause`가 실제 사인을 보인 뒤에 구현하라고 한다. M11 (a)가 담긴 빌드로 현장에서 모인 `lost`/`retry` 줄의 `cause` 분포를 사람이 기록한 것(이슈 #4 코멘트 또는 캠페인 문서, §5.5)이 착수 조건이다. `idle_timeout`이 관측되면 결정 1과 4를, 관측 기록이 있는데 `idle_timeout`이 한 번도 없으면 결정 1만 구현한다(결정 7 본문의 분기).
- **착수 조건:** 마일스톤 자체는 없다. (b)의 수정이 설계 선택을 부르면 그 ADR 승인이 수정의 조건이다. (d)는 ADR-0027 승인. (k)는 관측 기록이고, M13 마감까지 기록이 없으면 (k)는 M13을 막지 않고 그 사실과 이월 대상 마일스톤을 이 절에 적는다.
- **명시적 out:** H2·H4·H5(M18), H3(`docs/design/reexec-estimate.md` §4가 기각), `.pkg` 배포 형식(§5.3), `docs/campaigns/m10-clean-vm.md`의 수정.
- **수용 기준 (DoD):**
  - (a) 저장소 선택과 보존 기간, 그리고 회귀 판정 임계(예: 직전 N회 중앙값 대비 하락률)가 `docs/design/testing.md` CI 규율 절에 적힌다. 예약 실행이 회차마다 데이터 점을 하나씩 더한다. 인위적 지연을 주입한 회차 하나가 그 임계로 job을 붉게 만드는 것을 run id로 기록한다. 이 job은 PR 게이트가 아니다.
  - (b) 소비자가 읽지 않는 터널 스트림 넷 이상이 동시에 정체한 상태에서 PTY echo p95가 M4 예산(측정 RTT + 10ms) 안에 있고 PTY 출력이 계속 진행함을 새 testkit 테스트가 단언한다. 이 테스트는 `ci.yml` acceptance job에서 strict로 돈다. 수정은 M8 DoD 2의 세션당 buffer 상한(8 MB)과 `tunnel_throughput` 비율(≥80%)을 둘 다 지켜야 하고 두 게이트가 고치지 않은 기준으로 초록이다. 수정이 설계 선택이면 ADR이 먼저 선다.
  - (c) `release.yml`이 `aarch64-unknown-linux-musl` 자산을 네이티브 arm 러너에서 만들고 그 leg에서 `release_smoke_covers_init_trust_exec_pty_detach_and_reattach`가 `QSH_SMOKE_STRICT=1`로 초록이다. 자산이 `SHA256SUMS`와 provenance attestation에 들어간다. 설치 스크립트는 aarch64에서 `QSH_LIBC=musl`일 때 대상 태그의 `SHA256SUMS`에 그 자산이 있으면 고르고, 없으면 지금처럼 끝난다. 기본값(`gnu`)의 선택은 바뀌지 않음을 설치 스크립트 테스트가 고정한다. 그래서 M10 회차가 쓰는 태그에서 설치 동작이 바뀌지 않는다. 이 자산의 구형 glibc 판정은 새 캠페인 문서에 사전 고정한다. `docs/campaigns/m10-clean-vm.md`는 건드리지 않는다(§3 요건 여섯은 그 문서가 커밋된 시점에 고정됐다). 회차는 §5.5.
  - (d) ADR-0027이 `승인됨`이다. `--fail-on`을 주지 않으면 exit code와 stdout이 오늘과 바이트 단위로 같다. 주면 임계 이상 finding이 있을 때 ADR-0027이 정한 값으로 끝나고 envelope의 `ok` 값과 exit의 관계가 `docs/CLI.md` §4·§6.17에 적힌다. §6.17의 "`--fail-on` 플래그는 아직 없다" 문단이 교체되고 man 페이지가 재생성된다. JSON 모양이 바뀌면 새 fixture를 등재하고 기존 fixture는 그대로다.
  - (e) SIGTERM drain이 닫은 세션 수를 구조적 로그 한 줄로 남기고(payload 없음), 새 doctor 진단이 착지 순서대로 다음 개수로 `EXPECTED_DOCTOR_CODES`에 오른다. M11 (d)와 같은 산문 세 곳(`docs/CLI.md` §6.11·§6.17, `doctor.rs` 모듈 doc)이 같은 커밋에서 바뀐다.
  - (f) testkit에서 `qsh serve`를 재시작했을 때 attach 중이던 클라이언트가 재시작 뒤 첫 패킷에 stateless reset을 받아 `REDIAL_DEADLINE`(2초) 안에 단절을 확정하고, 45초 idle timeout을 기다리지 않은 채 세션 소실을 결정적인 오류로 보고함을 테스트가 고정한다. 그 오류는 `docs/design/protocol.md` §10-2의 비구별성 규칙과 `docs/CLI.md` §6.3·§6.4의 현행 attach 실패 코드를 따른다. reset key 파일은 0600이다. 읽을 수 없거나 형식이 틀린 파일을 만나면 조용히 새 키를 만들지 않는다. 기동을 `CONFIG_ERROR`로 거절할지, 이번 기동만 쓰는 임시 키와 기동 진단으로 갈지를 골라 커밋에 적는다. reset key는 로그와 audit 어디에도 나오지 않는다. `docs/design/threat-model.md` §4 D·G에 키 유출 행이 오른다. wire diff 0.
  - (g)~(j) 각각 결정이 커밋에 남고, (g)는 `publish-dry-run`이, (h)·(i)는 설치 스크립트 테스트와 `scripts/README.md`·README 문면이, (j)는 핀 테스트 또는 기각 기록이 근거다.
  - (k) 구현했다면 새 설정 값의 검증이 `ReverseConfig::backoff`와 같은 fail-closed `CONFIG_ERROR` 패턴이고, 설정이 없을 때 동작이 오늘과 같다. ADR-0021 결정 6의 문서 자리(`docs/design/protocol.md` §1·§2·§11-4, `docs/design/architecture.md` §7, `docs/CLI.md`)가 같은 커밋에서 바뀐다. `[recovery]` 상한은 `crates/qsh-cli/tests/reverse_blackout.rs`·`crates/qsh-cli/tests/attach_recovery.rs`·`crates/qsh-testkit/tests/reverse_resume_chaos.rs`의 `detection_budget`에서 역산하고, 세 테스트와 `a_real_60_second_blackout_survives_and_resumes_the_same_session`이 고치지 않은 예산으로 초록이다.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 3.1~6.1ew. (a) 저장소 조사 0.2 + job과 임계 0.3~0.6 / (b) 0.5~2.0(하단은 하네스만, 상단은 splice 설계 변경과 ADR) / (c) 0.2~0.3(M10 결정 기록 Q3이 "값싸다"고 적은 복제와 새 캠페인 문서) / (d) ADR 0.1 + 0.25~0.45(22종 진단에 심각도 필터 하나와 exit 매핑) / (e) 0.25(`reexec-estimate.md` §3 표의 상한) / (f) 0.3~0.45(같은 표의 0.2~0.3에 키 파일 권한과 threat model) / (g) 0.1~0.2 / (h) 0.2~0.3 / (i) 0.1~0.2 / (j) 0.1~0.3 / (k) 0.35~0.5(ADR-0021 결과 절의 0.3~0.4에 문서 자리와 예산 테스트 대조) / 마감 0.1~0.2.

### M14 — TCP/TLS fallback

- **범위:** UDP가 막힌 망에서 같은 application protocol을 TLS-over-TCP 위에서 돌린다(ADR-0005).
  - (a) `qsh-transport`의 `Transport`/`StreamMux` 추상. ADR-0005가 P0 산출물로 요구하고 M3부터 미이행으로 남은 trait이다(`docs/history/m3-plan.md`). 연결, `open_bi`/`accept_bi`, 순서 보장 바이트 스트림, 우선순위 힌트, 연결 오류 분류를 추상으로 세우고 quinn 구현을 그 뒤로 옮긴다. `qsh-transport/src/lib.rs`가 이미 TCP 구현이 "the same `Connection`/framed-stream surface" 뒤에 붙는다고 적는다. 오늘 `qsh-core`는 quinn 타입을 직접 쓴다. `reverse::classify_connection_error`가 `qsh_transport::ConnectionError`(quinn 재수출)를 매칭하고, `tunnel/splice.rs`·`tunnel/local.rs`·`reverse/listen.rs`가 `quinn::{RecvStream, SendStream}`을 가져오며, 테스트를 포함해 16개 파일에 `quinn::` 참조가 57곳 있다. 이 자리들을 transport 중립 타입으로 바꾼다. `ControlLink`/`DataLink`(`crates/qsh-core/src/client/link.rs`)는 축이 다른 enum이라 건드릴 이유가 생길 때만 다룬다.
  - (b) 착수 ADR(ADR-0028). ADR-0005는 "P1에 한다"와 "wire 변경 없이 TLS over TCP + 소형 mux"까지만 정했다. 남은 결정은 이렇다. transport 선택 정책(명시 옵션인지, UDP probe 실패 뒤 자동인지), TCP listener 포트와 bind(기본은 설정이나 플래그로 켤 때만 bind하고 기본 bind를 고른다면 그 이유와 threat model 행), mux 설계와 그것이 `docs/design/protocol.md` §16.2 상호운용 계약 표의 새 행이 되는지, connection migration이 없는 TCP의 recovery 경로(항상 resume), 선두 차단(head-of-line blocking) 아래에서 PTY 우선순위를 어디까지 약속하는지, `[transport].keep_alive_ms`(ADR-0021 결정 1)가 TCP 경로에서 무엇을 뜻하는지, 자동 전환을 고를 때의 강제 downgrade 처분.
  - (c) 구현. client dial·host listener·mux, ADR-0009 admission 방어선과 ADR-0010 quota의 TCP 쪽 적용, capability 광고, doctor의 UDP 차단 진단 remedy(`crates/qsh-core/src/doctor.rs`의 "QSH has no TCP fallback (P1, ADR-0005)")를 실행 가능한 다음 명령으로 교체.
  - (d) threat model. `docs/design/threat-model.md` §3 진입점과 §4 위협 표에 TCP listener와 mux 파서를 더한다.
- **착수 조건:** (b)의 ADR 승인 전에는 (c)를 열지 않는다. (a)는 동작 변경 없는 리팩터라 승인 전에 열 수 있다.
- **명시적 out:** QUIC 없이 TCP만 쓰는 모드를 기본값으로 삼는 것, relay(PRD §14 별도 제품), ADR-0021 결정 1·4의 구현(M13 (k)).
- **수용 기준 (DoD):**
  - (a) 전환 커밋은 테스트 파일을 import 경로와 타입 이름 외에는 고치지 않고 전체 스위트가 초록이다. `qsh-core`의 비테스트 코드에 `quinn::` 경로가 남지 않거나, 남는 자리를 ADR-0028이 사유와 함께 목록으로 적는다. `cargo xtask arch`가 `qsh-transport`의 session·ACL 무지식 규칙을 계속 강제한다.
  - (b) ADR-0028이 `승인됨`이다.
  - (c) exec 왕복, PTY 세션 open/attach, `-L`/`-R`/`-D` 터널의 핵심 e2e가 두 transport 매트릭스에서 모두 초록이다. chaos 하네스가 UDP를 전부 버리는 상태에서 ADR이 정한 정책대로 TCP로 연결되고, 클라이언트 `kill -9` 뒤 reattach 결과가 기준 stream과 byte-identical이다(SC4의 TCP 판). 두 transport 위에서 application frame 바이트가 같음을 단언하는 테스트가 있다. `load.yml`의 적대적 부하 시나리오에 TCP handshake flood가 더해져 선언된 상한이 강제된다. 포화 터널 아래 PTY echo p95를 TCP 경로에서도 같은 하네스로 재고, ADR이 정한 예산 또는 "예산 없음"과 그 고지를 테스트와 README Known limitations에 고정한다. `capabilities.json` golden은 `QSH_UPDATE_FIXTURES=1`로 재생성하고 계약 변경과 같은 무게로 다룬다. doctor의 UDP 차단 remedy 문면이 축자 테스트로 고정된다.
  - (c) TCP 경로의 client·server TLS 설정이 QUIC 경로와 같은 `QshPeerVerifier`(pin → CA → 거부), 0-RTT·ticket·resumption 금지(`docs/design/protocol.md` §16.2의 0-RTT 행), ALPN `qsh/1`을 쓴다는 것을 `crates/qsh-transport/tests/loopback.rs`와 같은 형식의 단언으로 고정한다.
  - (c) mux codec은 `qsh-proto`의 sans-IO 모듈이고 fuzz 타깃이 하나 는다. `fuzz/README.md`와 `docs/design/protocol.md` §13의 개수 문장이 같은 커밋에서 바뀐다. 새 타깃의 누적 fuzz는 §5.5.
  - (d) threat model의 새 행이 핀 테스트 이름을 갖는다. TCP listener가 기본으로 bind되지 않는다는 것(또는 ADR이 고른 기본 bind의 이유)이 행에 적힌다. 자동 전환을 골랐다면 UDP를 막는 on-path 공격자가 migration 없는 경로를 강제할 수 있다는 사실이 §7 잔여 위험에 오른다.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 4.3~6.9ew. (a) 1.0~1.8(transport 추상 신설과 `qsh-core`의 quinn 직접 참조 16개 파일 이전) / (b) 0.3 / (c) 2.5~4.0(두 번째 transport 구현과 테스트 매트릭스 배증. ADR-0005 근거 문단의 서술을 M2~M3급 규모로 환산) + mux codec의 `qsh-proto` 배치와 fuzz 타깃 0.2~0.3 / (d) 0.2~0.3 / 마감 0.1~0.2.

### M15 — 스트리밍 파일 복사

- **범위:** PRD P1 목록의 streaming file copy. `file.read`/`file.write` action은 M5부터 어휘에만 있고 항상 deny다(§3 가드레일 표). 이 마일스톤이 op을 등록하고 항상-deny를 걷는다. 착수 ADR(ADR-0029)이 정할 것은 명령 이름과 모양, 청크·부분 전송·재개 여부, 무결성 확인, ACL resource 모델(경로를 resource로 쓸지와 소유 축), 경로 제약(symlink, 상위 경로 이탈, 덮어쓰기), 동시 전송 quota, audit 레코드의 필드 집합(경로와 크기를 싣는지), 역방향 route 지원 여부다.
  - 이 ADR이 반드시 담아야 하는 결정이 하나 있다. `file.write`는 `qsh serve`의 uid로 파일을 쓰고, 그 uid는 `acl.toml`, `trust.toml`, `invites.toml`, identity와 keystore, `resume.json`, audit 로그를 쓸 수 있다. `file.write`가 `acl.toml`에 닿으면 원격 peer가 ACL writer가 되어 ADR-0017 결정 1과 ADR-0025 결정 1이 닫은 자리를 원격 op이 우회한다. `trust.toml`은 더 나쁘다. `SharedTrustStore::lookup_pin`이 handshake마다 파일을 다시 읽으므로(`crates/qsh-core/src/trust/mod.rs`) 원격 쓰기 하나가 재시작 없이 새 pin을 심는다. audit 로그를 덮어쓰면 SC6 추적성이 지워진다. 그래서 qsh의 config·data·state·runtime 디렉터리(`docs/design/architecture.md` §7의 경로 전부, 곧 `config.toml`, `acl.toml`, `trust.toml`, `invites.toml`, `hosts.toml`, identity·keystore 파일, `resume.json`, audit 경로, localctl 소켓 디렉터리, M13 (f)의 reset key 파일)는 ACL 행과 무관하게 `file.read`/`file.write`의 대상에서 항상 거부한다. 판정은 symlink를 해석한 뒤의 정규 경로로 한다. 이 성질은 ACL 행으로 열 수 없어야 한다.
- **착수 조건:** ADR-0029 승인. M13 (b)의 역압 하네스가 선 뒤.
- **명시적 out:** 디렉터리 동기화(rsync류), UDP forwarding, 원격 파일 브라우징.
- **수용 기준 (DoD):**
  - 큰 파일 왕복이 해시 기준으로 byte-identical이다. forward route와(ADR이 포함하면) reverse route, QUIC과 TCP 두 transport 모두에서다.
  - 행이 없으면 deny다. 새 두 seam이 `DENY_SEAMS`에 행으로 오르고 `acl_uniformity.rs`가 문면 균일성을 단언한다. `acl_registry.rs`의 항상-deny 예외 목록에서 `file.read`/`file.write`가 빠지고 `forward.socks`만 남는다. `acl_check_equivalence.rs` 표에 두 action 행이 더해진다.
  - `allow = ["file.*"]` 행이 있어도 qsh 자신의 상태 경로에 대한 `file.read`/`file.write`가 `PERMISSION_DENIED`이고 파일 바이트가 그대로임을 핀 테스트가 단언한다. 적어도 `acl.toml`, `trust.toml`, identity 파일, audit 로그를 덮고, 그 경로를 가리키는 symlink와 `..`로 이탈하는 경로 두 우회도 같은 결과임을 단언한다.
  - 인가 전 자원 생성이 없다. deny된 `file.write` 뒤 목적지와 그 디렉터리에 새 파일·임시 파일이 없고 기존 파일은 바이트 단위로 같다.
  - 동시 전송 quota가 ADR-0010의 모양으로 인가 뒤·열기 전에 결정되고, `crates/qsh-core/tests/quota_registry.rs`에 행이 오르며 `quota_docs.rs`가 문서의 거부 범주와 기본값을 확인한다.
  - audit 레코드의 필드 집합이 ADR-0029가 고정한 대로이고, 파일 내용 바이트가 어떤 필드에도 들어갈 수 없음을 `record_has_only_structural_fields`(`crates/qsh-core/src/audit/tests.rs`)와 같은 형식의 테스트가 고정한다.
  - 파일 복사와 PTY echo를 동시에 돌린 상태에서 M13 (b) 하네스가 같은 예산으로 초록이다.
  - 신규 op마다 fixture 등재와 등록 완전성(`layer_2_every_schema_command_has_all_six_faces`), `capabilities.json` golden 재생성, 새 wire op의 decode 경로가 fuzz 타깃에 걸림, freeze 발효 전이면 `docs/design/protocol.md` §16.1 목록 동시 갱신.
  - `docs/design/threat-model.md` §3에 파일 op 진입점이, §4 B에 상태 경로 쓰기·경로 이탈·덮어쓰기 위협 행이 핀 테스트와 함께 오른다.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 2.7~4.0ew. ADR 0.3 + 구현 2.0~3.0(새 op 둘, 렌더러 두 벌, fixture, capabilities, 전송 프로토콜, ACL 전수 테스트 갱신. `docs/ROADMAP.md` M9 크기 줄의 op 신설 항목 0.4~0.7ew에 스트리밍 설계를 얹은 배수) + 상태 경로 거부·인가 전 자원·quota·audit 테스트 0.3~0.5 / 마감 0.1~0.2.

### M16 — 신뢰의 방향과 수명

- **범위:** 결정 절이 비어 있는 신뢰 축 넷을 의존 순서대로 닫는다.
  - (a) pin 방향 축(ADR-0030). ADR-0017 결정 5가 번호 없이 미룬 후속 ADR이다. `trust.toml`의 pin은 방향을 구분하지 않아서 outbound pin이 inbound 인증까지 통과시킨다. 방향 필드와 기존 pin의 이행 정책(오늘과 같은 양방향으로 읽기)을 정한다. TOFU를 여는지는 이 ADR이 정하고, 열지 않으면 ADR-0017 결정 5가 유지된다. M11 (e)의 두 별칭 배치를 정식으로 푸는 자리도 여기다. 이 ADR은 이 변경이 `docs/design/protocol.md` §16.2가 동결하는 TLS 검증 경로(pin → CA → 거부)의 의미 변경인지, 로컬 trust 입력의 변경인지를 결정 항목으로 삼는다. §16.5는 앞의 것을 major bump 사유로 둔다.
  - (b) listener 대상 초대 상환(ADR-0015). 예약 ADR의 비어 있는 결정 일곱을 처음 채운다. 방향 축과의 관계는 (a)의 결과를 입력으로 쓴다. 결정 4가 `qsh serve --to`의 코드 수용을 고르면 ADR-0014 결정 7(승인됨)의 개정 ADR이 먼저 선다(ADR-0015 결정 4 본문). 상환 창구가 `qsh listen`에 열리면 `qsh setup`의 `listener`와 `host --to` 역할이 그 경로를 additive로 얻는다(ADR-0024 결정 2의 역할 표).
  - (c) CSR 기반 다대 CA 서명(ADR-0016). 비어 있는 결정 여덟을 처음 채운다. 결정 2(파일 교환인지 네트워크 경로인지)가 규모를 가른다. ADR-0008 결정 5가 P1로 남긴 원격 프로비저닝이 여기 속한다. 결정 4는 ADR-0008 결정 3이 P1로 미룬 user cert 발급을 이 ADR에서 같이 다룰지 별도 ADR로 남길지를 정하고, 어느 쪽이든 그 결론을 적는다.
  - (d) cert rotation/revocation UX(ADR-0031). revocation 전파를 정한다. qsh에는 오늘 revocation 전파가 없어서(ADR-0026 근거 절) UX만 먼저 내면 "revoke했다"는 출력과 실제 강제가 어긋난다. M7 감사 개정이 고정한 `trust remove`의 유효 범위와 같은 문면 규율을 쓴다. `trust remove` 뒤 이미 살아 있는 연결의 강제 종료(`TrustRemoveScope` remedy의 "(P1)")도 여기서 정한다. (a)와 같이 §16.2 검증 경로와의 관계를 결정 항목으로 삼는다.
- **착수 조건:** 네 ADR 각각의 승인이 그 항목 구현의 조건이다. (b)는 (a) 승인 뒤에 결정한다.
- **명시적 out:** 조직 계정·중앙 관리(PRD §12 경계 밖), SSH 공개키를 principal로 쓰는 것(ADR-0026이 거부).
- **수용 기준 (DoD):**
  - ADR-0030·0031이 `승인됨`이고, ADR-0015·0016은 결정 절이 전부 채워져 `승인됨`이다.
  - (a)·(d) ADR이 §16.2와의 관계를 적은 대로 §16.2 행에 해석 한 줄이 붙는다. freeze 발효 전이면 같은 커밋에서, 발효 뒤면 §16.4 규칙 안에서 해명한다.
  - (a) 방향 필드가 없는 기존 `trust.toml`이 오늘과 같은 판정을 내는 것을 테스트가 고정하고, outbound 전용 pin이 inbound handshake에서 거부되고 audit에 남는다. `direction`에 모르는 값이 적힌 pin은 조용히 양방향으로 읽지 않고 fail closed한다(그 pin을 무시하고 기동 진단을 내거나 `CONFIG_ERROR`, ADR이 고른다).
  - (b)·(c) 구현 항목마다 handshake matrix와 페어링 테스트에 행이 더해지고, 페어링 직후 pin 이름·매칭 규칙 고지(ADR-0017 결정 3의 문구 규율)가 새 경로에도 나온다.
  - (d) rotation 뒤 옛 cert로의 handshake 동작과 revoke 뒤 기존 연결·신규 handshake 동작이 각각 테스트로 고정되고 문서·doctor 고지와 일치한다. `trust remove`의 기존 연결 처리를 ADR이 정한 대로 테스트가 고정하고 `TrustRemoveScope` remedy 문면이 그 결정에 맞게 바뀐다. M11 (c)로 가져온 키로 만든 identity도 rotation된다. 만료 30일 전 doctor 경고(P0)는 유지된다.
  - 새 명령·필드는 fixture 등재와 등록 완전성, man 재생성을 갖춘다. `docs/design/threat-model.md` §3·§4가 새 경로를 다룬다.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 확정분 2.4~3.5ew + ADR 결정 뒤 재산정 셋. (a) ADR 0.2~0.3 / (b) 결정 절 작성 0.3~0.5 / (c) 결정 절 작성 0.3 / (d) ADR 0.2 + rotation UX 1.0~1.5(로컬 CA 재발급 흐름 재사용 전제) + `trust remove` 강제 종료 0.3~0.5 / 마감 0.1~0.2. (a)·(b)·(c)의 구현은 결정 절이 비어 있어 지금 매길 수 없다. ADR-0014 결정 7 개정이 필요해지면 0.2를 더한다. 재산정 합이 4ew를 넘으면 이 마일스톤을 둘로 나눈다.

### M17 — 운영 표면

- **범위:** 사람 회차와 무관하게 열 수 있는 운영·문서 항목.
  - (a) 서비스 매니저 실호출(ADR-0032). `launchctl bootstrap`/`systemctl --user enable`을 명시적 플래그로만 부른다. `docs/CLI.md` §6.18은 `service install`이 유닛 파일만 쓴다고 계약하고, ADR-0024 결정 11은 활성화를 §6.18을 개정하는 별도 결정으로 남겼다. 이 ADR이 그 결정이다.
  - (b) README 서사·구조 전면 재작성. M9는 측정 대상 문서(README "First run" 절)를 회차 전에 바꾸지 않으려고 이 일을 SC1 재측정 뒤로 미뤘다. M12 (b)가 M9 재측정의 대상 트리를 `docs/campaigns/m9-stopwatch.md` §8에 SHA로 고정하고 `qsh setup` 캠페인도 대상 트리를 고정하므로, 두 고정 뒤에는 재작성이 측정을 흔들지 않는다. M9 DoD 1 결과가 그때 기록돼 있으면 서사의 입력으로 쓴다.
  - (c) QR pairing. 근거는 PRD §17 확정된 결정의 "QR pairing은 P1이다"이고 PRD §7 P1 목록에는 없다. P1 안에서 QR을 읽을 소비자가 있는지부터 확인한다. mobile client SDK는 P2다. 소비자가 없으면 구현하지 않고, PRD §17의 그 확정 결정 문장을 P2로 옮기는 개정을 사용자에게 올린다.
  - (d) 세션 및 audit 관리 개선(PRD §7 P1, 범위 ADR-0033). PRD는 항목 이름만 두었다. 범위 ADR이 무엇을 개선하는지 정한다(세션 목록 필터, audit 조회, retention 정책 등 후보). 결정 항목에 다음을 미리 넣는다. audit 조회는 인가 불요 local op이고 wire 메시지를 만들지 않는다(원격에서 부를 수 있으면 ADR-0022 결정 4·ADR-0025 결정 4가 적은 열거 oracle이 된다). audit 레코드의 삭제·축약은 원격 op으로 만들지 않는다(SC6 추적성). 조회 출력은 기존 구조 필드만 싣는다. 텔레메트리 줄의 계약 승격 여부(`crates/qsh-core/src/telemetry.rs` 모듈 doc: "That promotion is a P1 decision")도 이 ADR이 정한다.
- **착수 조건:** (a)는 ADR-0032 승인, (b)는 M12 (b)의 두 SHA 고정, (d)는 ADR-0033 승인. 사람 회차를 기다리는 항목은 없다.
- **명시적 out:** `acl.toml`을 쓰는 어떤 동작(ADR-0017 결정 1, ADR-0025 결정 1), 핫 리로드, 로그인 세션 밖 상시 기동(systemd linger 자동 설정, macOS LaunchDaemon), qsh 자체 데몬화(§5.3).
- **수용 기준 (DoD):**
  - (a) ADR-0032가 `승인됨`이다. 플래그 없이는 매니저를 부르지 않는다. 부를 때의 명령 인자가 `docs/deploy/service.md`의 안내와 같음을 문서-코드 대조 테스트가 고정한다. 테스트는 실제 매니저를 부르지 않는다. §6.18과 man이 같은 커밋에서 바뀐다.
  - (b) 마감 공통 절차 2(README 동기화)를 전면 재작성판에 대해 수행한다. 재작성 커밋이 두 SHA 고정 커밋보다 뒤다.
  - (c) 구현했다면 fixture와 등록 완전성, 구현하지 않았다면 PRD §17 개정 결정이 기록된다.
  - (d) ADR-0033이 `승인됨`이다. 범위 ADR이 정한 항목마다 테스트와 fixture 등록 완전성을 갖추고, audit 조회 op에 대응하는 wire 메시지가 없음을 op registry 분류 테스트가 확인한다.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 1.3~2.5ew + (d) 구현 미산정. (a) ADR 0.2 + 구현 0.3~0.5 / (b) 0.5~0.8 / (c) 0~0.5(구현하지 않으면 0) / (d) 범위 ADR 0.2~0.3 / 마감 0.1~0.2.

### M18 — 세션 거처

- **범위:**
  - (a) 세션 거처 결정 ADR(ADR-0034). 세션이 어느 프로세스에 사는지를 고른다. 후보는 H4(listener 제자리 execve handoff), H5(단일 supervisor, ADR-0003 seam), 세션당 홀더 프로세스 셋이다. 세 번째 후보는 `docs/design/reexec-estimate.md` §4가 비용을 매기지 않았다고 스스로 적은 갭이라 이 ADR이 매긴다. H3은 기각된 채 둔다. 이 ADR은 두 가지를 더 결정 항목으로 삼는다. 하나는 `docs/design/reexec-estimate.md` §5의 보안 비용 중 고른 후보에 해당하는 것(H4 스냅숏 통로의 스크럽·수신자 검증, H5·홀더 소켓의 권한 모델)의 채택안과 크기다. 다른 하나는 ADR-0004가 P1에 배정한 encrypted disk spool 재검토다. H4의 임시 파일 통로와 H5의 프로세스 분리가 같은 질문을 받기 때문이다. 도입하지 않기로 하면 이 ADR이 ADR-0004 결과 절의 백로그 줄을 닫고, PRD §17의 "P1 이후" 문장과 ADR-0004의 어긋남을 같은 자리에서 정리한다.
  - (b) 선택한 후보의 구현. H4를 고르면 재바인드가 같은 fd로 남는지 확인하는 실측 1건이 먼저다(같은 문서 §3).
  - (c) H2(인스턴스 식별값의 `Hello` additive). (a)의 ADR이 필요하다고 판정할 때만 한다. 같은 문서 §3이 이 거래의 값어치가 자명하지 않다고 적었다.
- **착수 조건:** M8 DoD 3(실기기 mobility ≥60회, `docs/campaigns/m2-mobility.md`)이 기록된다. ADR-0003이 별도 supervisor 선분리를 기각하며 적은 "세션 생존성이 실사용에서 검증된 뒤 투자"가 이 조건이다. (a) 승인 전에는 (b)를 열지 않는다.
- **명시적 out:** Windows host PTY 백엔드(P2), 여러 세션 상태 경로를 동시에 유지하는 것(H4와 H5를 둘 다 하는 것), 세션·audit 관리 개선(M17 (d)).
- **수용 기준 (DoD):**
  - ADR-0034가 `승인됨`이다.
  - 계획된 업그레이드 뒤 PTY 자식과 프로세스 트리, `session_ref`가 살아 있고 같은 `session_ref`로 reattach된다. H5나 세션당 홀더를 골랐다면 `qsh serve` crash 재시작에도 같다. 잃는 상태(ADR이 고른 후보의 "잃는 것" 칸)가 문서와 테스트로 고정된다.
  - 업그레이드 창에 붙어 있던 클라이언트가 `REDIAL_DEADLINE`(2초) 안에 복구되어 `Recovery::Failed`로 분류되지 않는다.
  - `docs/design/protocol.md` §10-2의 비구별성 계약을 지키는 테스트가 고치지 않은 채 초록이다.
  - `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`와 `load.yml` T2 echo 판정이 고치지 않은 예산으로 초록이다. 예산 재협상이 필요하면 그것 자체가 ADR 결정이다.
  - H4를 골랐다면 exec 전에 bind 가능성과 정책 유효성을 미리 검사하는 단계가 있다. 새 이미지와 그 뒤 spawn되는 PTY 자식의 `environ`에 스냅숏 변수가 없음을 단언하고, 상속 fd 묶음이 자기에게 온 것인지 확인하는 수신자 검증을 테스트한다.
  - H5나 세션당 홀더를 골랐다면 새 소켓이 0700 디렉터리·0600 소켓·첫 바이트를 읽기 전 euid 대조를 갖춤을 localctl 테스트(`crates/qsh-core/src/localctl/daemon.rs`)와 같은 형식으로 단언하고, 그 IPC가 `docs/design/threat-model.md` §3에 진입점으로 오른다.
  - 어느 후보든 resume 해시가 디스크에 남지 않는다. 남는 설계라면 ADR-0004를 개정하는 ADR이 먼저 선다.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 4.4~8.6ew + §5 보안 가산 미산정. (a) ADR 0.3~0.5(세 번째 후보 산정과 spool 재검토 포함) / (b) H4 4.2(4.0~4.8) 또는 H5 6.5(5.4~7.6), `docs/design/reexec-estimate.md` §3 표 / (c) 0~0.3 / 마감 0.1~0.2. `reexec-estimate.md` §5는 H4의 4.2ew에 스냅숏 통로 검증·스크럽 비용이 들어 있지 않고 H5에는 소켓 권한 모델을 다시 세우는 비용을 가산해야 한다고 적는다. 이 가산분은 ADR-0034가 채택안을 고른 뒤 매기고 이 절에 적는다. 세 번째 후보를 고르면 (b) 전체를 다시 매긴다.

### M19 — Windows client

- **범위:** PRD P1의 Windows client. 착수 ADR(ADR-0035)이 Windows에서 여는 명령 집합을 정한다. 산정 전제는 client 역할만이다. `init`, `trust`/`pair accept`, `exec`, 대화형 attach, forward route의 `-L`/`-D`, `doctor`. host 역할(`serve`, `serve --to`)은 P2이고, `listen`과 그 데몬이 필요한 reverse route 소비는 ADR이 정한다. 콘솔 raw 모드와 VT 입력, `SIGWINCH` 없는 resize 전파, UDS 없는 환경에서 localctl 소비자의 처리, 키·상태 파일의 권한 모델, keystore 경로가 필요하다. `crates/qsh-core/src/resume.rs` 모듈 doc은 Windows에서 `resume.json`이 상속 디렉터리 ACL로 만들어진다고 적고 그 기밀성을 Windows client P1의 일부로 둔다. resume token은 ADR-0007의 custody 대상이다. 초대 코드 프롬프트는 에코 억제가 없어 오늘 Windows에서 `UNSUPPORTED`다(`crates/qsh-core/src/ops/mod.rs`의 `NO_TERMINAL_ECHO_SUPPRESSION`).
- **착수 조건:** ADR-0035 승인. M18의 착수 조건이 닫히지 않았으면 M19를 먼저 연다.
- **명시적 out:** Windows host와 ConPTY 백엔드(P2), Windows에서의 `qsh service`(M9가 `UNSUPPORTED`로 고정).
- **수용 기준 (DoD):**
  - `ci.yml`의 `windows-latest` leg이 build/clippy/portable 테스트를 넘어 ADR이 정한 명령의 기능 테스트를 돈다.
  - `release_smoke`의 `#[cfg(not(unix))]` 쌍둥이가 ADR이 정한 범위까지 넓어진다.
  - identity 키, `resume.json`, `trust.toml`이 소유자 전용 DACL로 만들어짐을 Windows leg 테스트가 단언한다. DACL을 설정할 수 없으면 파일을 만들지 않고 fail closed한다.
  - localctl을 대체하는 IPC(named pipe 등)를 연다면 다른 사용자의 접속이 거부됨을 테스트한다. 열지 않는다면 그 명령이 `UNSUPPORTED`로 끝남을 fixture로 고정한다.
  - 에코 없는 초대 코드 입력을 지원할지, 현행 `UNSUPPORTED`를 유지하고 `--code-stdin`만 열지를 ADR이 정하고 테스트가 그 결정을 고정한다.
  - `docs/design/threat-model.md` §3에 Windows client 진입점이 오른다.
  - Windows client에서 Linux·macOS host로 붙는 대화형 셸(bash/zsh, vim, resize, detach→attach resume)을 사람이 확인하는 캠페인 문서가 `docs/campaigns/`에 사전 고정돼 커밋된다. 회차는 §5.5.
  - README Known limitations와 §3 가드레일 표의 Windows 행이 새 지원 범위와 일치한다.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 4.7~7.0ew. ADR 0.3 + 구현 4.0~6.0(콘솔 입출력과 resize, localctl 대체, 권한 모델, 테스트 이중화) + DACL·IPC 거부 테스트 0.3~0.5 / 마감 0.1~0.2. 비교 표본이 없어 신뢰도가 가장 낮은 산정이다.

### 5.2 P1 크기 합

| 마일스톤 | 크기(ew) | 착수 조건 |
|---|---|---|
| M11 이슈 후속과 ACL 가시성 | 2.8~4.1 | 없음 |
| M12 이슈 설계 ADR 구현 | 3.8~5.3 | ADR-0023, ADR-0024 승인(항목별) |
| M13 측정·배포 기반 | 3.1~6.1 | 없음. (d)는 ADR-0027, (k)는 `cause` 관측 기록 |
| M14 TCP/TLS fallback | 4.3~6.9 | ADR-0028 승인((c)부터) |
| M15 스트리밍 파일 복사 | 2.7~4.0 | ADR-0029 승인, M13 (b) |
| M16 신뢰의 방향과 수명 | 2.4~3.5 + 재산정 셋 | ADR 넷(예약 둘 포함) 승인 |
| M17 운영 표면 | 1.3~2.5 + 미산정 하나 | ADR-0032·0033 승인(항목별), M12 (b)의 SHA 고정 |
| M18 세션 거처 | 4.4~8.6 + 미산정 하나 | M8 DoD 3 기록, ADR-0034 승인 |
| M19 Windows client | 4.7~7.0 | ADR-0035 승인 |
| 합 | 약 29~48 + 미산정 다섯 | |

### 5.3 P1 밖으로 보낸다

| 항목 | 이유 |
|---|---|
| SOCKS `-D` | 이미 M9에서 출고했다(ADR-0019·0020, `socks_curl`). PRD P1 목록의 해당 줄은 M9 이동을 적고 있다 |
| `Host.lost_at`(ADR-0022 baseline) | `46cfda8`로 이미 착지했다 |
| `qsh.event/v1`의 `reverse.*` type(ADR-0022 결정 3) | 착수 조건인 관측 트리거(폴링이 놓치는 전이 보고, stderr를 읽을 수 없는 배치)가 아직 없다. 트리거가 관측되면 그때 열린 마일스톤에 이 문서 개정으로 넣는다 |
| 옛 계획·ADR 줄 번호 인용의 일괄 정리 | M10 결정 기록 Q6이 부채로 남기고 새 인용을 만들지 않기로 했다. 일괄 치환이 불가능한 코드 주석이 대부분이라 파일을 만질 때 국소로 고친다 |
| H3 소켓만 넘기는 handoff | `docs/design/reexec-estimate.md` §4가 기각했다. H1b가 같은 값을 더 싸게 낸다 |
| `HOST_NOT_FOUND` 구제 문면의 `qsh reverse <controller>` 교체 | 문면이 append-only golden fixture 다섯(`error.HOST_NOT_FOUND.{unconfigured,pinned_no_address,exec_pinned_no_address,reverse_stale,exec_reverse_stale}.json`)에 들어 있어 고치면 fixture 편집이 된다. 숨김 alias는 v1 내내 동작하므로(ADR-0012) 안내가 틀린 것은 아니다. `qsh.cli/v2` 또는 fixture 규칙 예외를 정하는 ADR이 설 때 다시 연다 |
| `qsh acl grant`/`revoke`, 원격 ACL 미리보기 | ADR-0025가 기각했다(결정 1, 결정 4) |
| 암호화된 SSH 키, ssh-agent, OS keychain에서 가져오기, RSA/ECDSA | ADR-0026이 별도 결정으로 분리했다. 새 ADR 없이는 열지 않는다 |
| `SessionSignal`(wire 예약 번호 25) | `crates/qsh-proto/proto/qsh/wire/v1.proto` 주석이 P1로 적었지만 PRD P1 목록에 없고 요구가 관측된 적 없다. 번호는 예약된 채 남고, `docs/design/protocol.md` §16.4가 그 번호를 채우는 것을 허용 변경으로 두므로 나중에 여는 비용이 낮다 |
| `-L`의 non-loopback bind | `crates/qsh-core/src/tunnel/local.rs` 모듈 doc이 "필요 시 P1"로 적었다. 로컬 bind를 넓히는 것은 이 장비의 다른 사용자와 LAN에 진입점을 여는 일이라 기본 거부를 둔다. 요구가 오면 ADR로 연다 |
| qsh 자체 데몬화 | `docs/CLI.md` §6.12가 foreground 전용을 계약으로 두고 서비스 유닛(M9)과 M17 (a)가 상시 기동을 맡는다 |
| `.pkg` 배포 형식 | M10 결정 기록 Q2가 tar.gz와 공증으로 정했다 |
| `-W` | 기각했다(ADR-0011 결과 절 2026-09-25 추기) |
| UDP forwarding | PRD P1 목록에 없다(M4 명시적 out) |
| relay | PRD §14 별도 제품. §3 가드레일대로 `--relay` stub도 없다 |
| P2 전부 | local echo prediction, read-only multi-attach, jump chaining, agent forwarding, Windows host, mobile client SDK(`docs/PRD.md` §7 P2) |
| P0 사람 회차 일곱 | P0 완료 선언의 조건이고 `PLAN.md`가 사람 몫으로 추적한다. P1 마일스톤이 아니다. M8 DoD 3은 M18의 착수 조건으로, M9 DoD 1은 `qsh setup` 캠페인의 비교 기준으로만 인용한다 |

### 5.4 P1 일정 리스크

1. **사용자 승인.** 승인이 필요한 ADR이 열다섯 건 안팎이다. 제안 ADR 둘(0023, 0024), 예약 ADR 둘의 결정 절(0015, 0016), 새 ADR 아홉(0027~0035), 조건부 둘(M13 (b)의 흐름 제어 설계, ADR-0014 결정 7 개정). 대응: 마일스톤마다 ADR 초안을 첫 스텝으로 두고, 승인을 기다리는 동안 순서상 다음 마일스톤의 ADR 없는 스텝을 연다.
2. **SC7 범위가 P1 표면만큼 넓어진다.** M8 DoD 4의 독립 검증 계약이 아직 없는데 P1은 wire 필드(H2, ADR-0023이 고를 수도 있는 필드), 새 transport(M14), 새 op(M12, M15)를 더한다. 대응: freeze 발효 전에는 `docs/design/protocol.md` §16.1 목록을, 발효 뒤에는 §16.4 규칙을 같은 커밋에서 지키고, threat model 행을 각 마일스톤 DoD에 넣었다.
3. **흐름 제어 수정이 M15를 늦춘다.** M13 (b)는 붉게 나올 가능성이 크고, 고칠 공간이 M8 DoD 2 상한과 `tunnel_throughput` 비율에 묶여 있어 splice 설계 변경이 될 수 있다. M15의 착수 조건이 M13 (b)이므로 (b)의 상단(2.0ew와 ADR 승인)이 M15 착수를 그만큼 민다. 대응: (b)를 M13의 첫 스텝으로 두고, 설계 변경이 필요하다고 판정되면 그날 ADR 초안을 올린다.
4. **TCP 경로의 PTY 우선순위.** 선두 차단 아래에서 M4 echo 예산이 성립하지 않을 가능성이 크다. 대응: ADR-0028이 예산을 먼저 정하고 README가 고지한다.
5. **M18의 echo 회귀와 IPC 보안.** H5는 대화형 echo가 로컬 IPC를 한 번 더 지나고 resume token custody(ADR-0007)와 부딪힐 수 있다. 대응: ADR-0034가 세 후보를 같은 표로 비교하고, 기존 echo 예산을 고치지 않는 것과 소켓 권한 모델을 DoD로 둔다.
6. **Windows 산정 신뢰도.** 비교 표본이 없다. 대응: ADR-0035가 명령 집합을 좁히고, 첫 스텝 뒤 다시 매겨 이 절에 적는다.
7. **P1 사람 몫이 쌓인다.** §5.5의 회차는 마일스톤을 막지 않지만 P1 완료 선언을 막는다. 대응: 캠페인 문서를 해당 마일스톤 DoD에서 사전 고정해 두어 사람이 언제든 돌릴 수 있게 한다.

### 5.5 P1 사람 몫

마일스톤 DoD에 들지 않는다. P1 완료를 선언할 때의 조건이다.

| 항목 | 사전 고정 문서 | 만드는 마일스톤 | 선행 |
|---|---|---|---|
| `qsh setup` 경로 SC1 스톱워치 3회 | `docs/campaigns/p1-setup-stopwatch.md` | M12 (b) | 같은 날 같은 진행자의 m9 3회. M9 DoD 1 공식 회차가 그날 있으면 재사용(ADR-0024 결정 12) |
| `cause` 분포 관측 기록 | 이슈 #4 코멘트 또는 캠페인 문서 | M11 (a) 빌드 | M13 (k)의 착수 조건 |
| `aarch64-unknown-linux-musl` 구형 glibc 판정 | M13 (c)의 새 캠페인 문서 | M13 (c) | aarch64 musl 자산이 붙은 태그 |
| 새 파서 fuzz 타깃의 누적 72시간 | `docs/campaigns/m8-fuzz.md` 형식 | M11 (c) SSH 키 파서, M14 mux codec, M15의 새 decode 타깃 | 공개 beta 전(`docs/design/protocol.md` §13) |
| Windows 대화형 셸 확인 | M19의 캠페인 문서 | M19 | Windows 자산이 붙은 태그 |
