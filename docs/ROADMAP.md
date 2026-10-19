# QSH 로드맵

**상태:** 확정. 구현과 어긋나는 내용을 발견하면 이 문서를 먼저 갱신한다. 개정 기록은 git 이력에 있다.

**현재 위치:** P1을 열었다(2026-09-26 사용자 결정). M11~M13은 닫혔고 M14(TCP/TLS fallback)는 2026-10-11 철회했다(ADR-0043, (a) transport facade만 남김). 2026-10-12 사용자 결정으로 P1을 다시 짰다. pin 방향(ADR-0030), listener pairing(ADR-0015), CSR(ADR-0016)은 기각했고 QR pairing과 P2 mobile client SDK는 폐기했다. 대신 역할 기반 권한(ADR-0045)과 SSH 부트스트랩(ADR-0044)을 새로 두고, 파일 복사를 scp 호환 `qsh cp`로(ADR-0029 개정), rotation·revocation을 "trust를 거두면 열린 연결도 닫는다"로(ADR-0031 축소) 바꿨다. 남은 마일스톤의 착수 ADR(M15 ADR-0045·0029, M16 ADR-0044·0031, M17 ADR-0032·0033, M19·M20 ADR-0035)은 2026-10-14 사용자 위임 결정("전부 다 알아서 진행해")으로 모두 `승인됨`이다. ADR이 필요 없는 M17 (b) README 재작성은 착지했다(`2fc879b`). M18은 M8 DoD 3이 기록돼야 열린다(§5.1 원칙 6). M15(역할 기반 권한과 scp 호환 파일 복사)와 M16(SSH 부트스트랩과 신뢰 철회)은 2026-10-15, M17(운영 표면)은 2026-10-16 닫혔다. M18은 착수 조건(M8 DoD 3)이 닫히지 않아 건넜고(§5.1 원칙 6), M19(Windows client)와 M20(Windows host)은 2026-10-18 닫혔다. 이로써 P1 마일스톤 가운데 에이전트가 열 수 있는 것은 모두 닫혔고 지금 열린 마일스톤은 없다. M18은 여전히 착수 조건(M8 DoD 3)을 기다려 건넌 상태이고(§5.1 원칙 6), 그 회차가 기록되면 M18 계획이 `PLAN.md` 자리표시자를 대체한다. 그때까지 `PLAN.md` §0이 남은 사람 몫이다. P0 MVP 완료 선언은 아직이다. 에이전트 몫은 전부 착지했고 사람 회차 일곱이 닫힐 때 선언한다(아래 "P0 MVP 완료 선언의 조건"). P1이 만든 사람 몫은 §5.5에 있다.

이 문서는 P0 MVP(M0~M10)와 P1(M11~M20)의 canonical 마일스톤 기록이다. P2(`docs/PRD.md` §7 P2 목록)는 다루지 않는다. 각 마일스톤의 "수용 기준"이 곧 완료 정의(Definition of Done)이고, 수용 기준을 통과하는 테스트나 시연 없이는 마일스톤을 닫지 않는다. SC 번호는 PRD §15 성공 기준의 순번이다(SC1: 신규 두 장비 5분 내 연결, SC2: 한 명령 접속, SC3: 네트워크 전환 ≥95% 유지/resume, SC4: resume 가능한 단절에서 output 무손실, SC5: client crash가 remote PTY를 죽이지 않음, SC6: 모든 privileged op의 ACL 추적성, SC7: 공개 beta 전 독립 보안 리뷰).

닫힌 마일스톤의 절은 범위, 결과, 열린 DoD, 코드·문서가 인용하는 번호(DoD 번호, 범위 글자, 결정 기록 Q)만 남겼다. 단계별 서술과 감사 경위는 git 이력에 있다. 지운 M2~M13판 계획의 원문은 커밋 해시로 인용한다(`docs/history/m<N>-plan.md`): M2~M6 `2473c88`, M7 `69dd788`, M8 `52639fc`, M9 `b9a621b`, M10 `98d62fe`, M11 `6ee63c3`, M12 `3acdb1a`, M13 `b70be6b`, M15 `7cbeced`, M16 `66b6f4d`, M17 `047db25`, M19 `d853388`, M20 `addffb5`.

## P0 MVP 완료 선언의 조건

M0부터 M10까지의 코드·계약·파이프라인 스텝 중 에이전트 몫은 전부 착지했다. 남은 계약 편집 셋은 M8 DoD 4의 wire freeze 발효 소커밋에 묶여 있다. P0 MVP는 사람이 돌려야 닫히는 회차 일곱이 전부 PASS로 기록될 때 완료로 선언하고, 그 선언은 "현재 위치"와 이 절에 같이 적는다. 선언 전에는 "beta"나 그에 준하는 어휘를 쓰지 않는다. PRD §15가 공개 beta 전 독립 보안 리뷰를 요구하고 그것이 아래 일곱 중 하나다. 일곱이 다 닫히는 날 이 절 아래에 `**P0 MVP 완료 (날짜).**`로 시작하는 문단을 더해 각 캠페인 문서와 회차 번호를 적고 P0 범위(`docs/PRD.md` §7 P0 표)를 닫는다. P1은 이 선언과 독립적으로 진행한다(§5).

| 열린 DoD | 내용 | 기록 자리 | 비고 |
|---|---|---|---|
| M10 DoD 1 | 클린 네 플랫폼 설치와 기능 스모크 | `docs/campaigns/m10-clean-vm.md` 회차 표 | Linux 회차는 PASS, macOS 두 회차가 남았다 |
| M10 DoD 2 | Gatekeeper가 notarized 바이너리를 차단하지 않음 | 같은 문서 | 서명·공증 태그는 `v0.4.0`부터 있다 |
| M10 DoD 3 | musl static 바이너리가 구형 glibc 배포판에서 실행 | 같은 문서 | 근거 회차는 있고 캠페인 §9 판정과 함께 닫힌다 |
| M7 DoD 1 | SC1 스톱워치 baseline 3회 | `docs/campaigns/m7-stopwatch.md` | 예행 1회만 끝났다 |
| M8 DoD 3 | 실기기 mobility ≥60회 | `docs/campaigns/m2-mobility.md` | M18의 착수 조건 |
| M8 DoD 4 | wire freeze 발효와 독립 검증 계약(SC7) | 저장소 밖 조직 액션이라 캠페인 문서가 없다 | 소유: 운영자 |
| M9 DoD 1 | SC1 재측정 3회 | `docs/campaigns/m9-stopwatch.md` | M7 DoD 1에 종속. `qsh setup` 캠페인의 비교 기준 |

총 크기: P0는 약 31.5~32 engineer-weeks(1인 기준). P1은 약 41~67ew(추정, 2026-10-12·13 재기획 반영, M17 (d) 구현은 ADR-0033이 1.2~1.8ew로 산정)에, ADR이 서야 산정할 수 있는 M18의 보안 가산분이 더해진다. 내역은 §5.2.

## 1. 시퀀싱 원칙

순서 자체가 설계 결정이다. 근거를 잊으면 순서를 다시 흔들게 되므로 기록해 둔다.

1. **Typed op layer와 JSON envelope는 M1부터.** 나중에 붙이면 사람용 경로와 기계용 경로가 각자 오류 체계, 타임아웃 모델, `session_ref` 파서, ACL 호출 지점을 길러 버리고 재통합은 영원히 우선순위에서 밀린다. CLI.md §11이 요구하는 "세 frontend가 같은 typed operation을 호출"은 첫 코드부터 지켜야 지켜진다.
2. **Walking skeleton은 PTY가 아니라 exec.** `qsh init → serve → exec --json`은 identity, mTLS, QUIC, framing, op dispatch, ACL chokepoint, JSON envelope, exit code라는 리스크 척추 전체를 관통하면서도 expect 하네스 없이 CI에서 완전 자동화된다. PTY는 같은 척추 위에 터미널 서브시스템 전체를 얹는 일이라 검증 인프라가 먼저 필요하다.
3. **PTY 세션 모델은 headless로 먼저 검증.** CLI.md가 `session open/read/write/resize/close`를 기계 명령으로 정의한 덕분에 termios 코드를 한 줄도 쓰기 전에 broker 전체를 JSON 명령으로 검증할 수 있다. TUI는 검증된 broker의 얇은 소비자로 나중에 얹는다.
4. **역방향(M3)이 터널(M4)보다 먼저.** 터널은 role 모델(연결 방향과 세션 역할의 분리) 위에 얹힌다. 정방향 전용으로 먼저 만들면 역방향을 넣을 때 재작업이 된다. `-R` over reverse connection이 진짜 흥미로운 케이스다.
5. **ACL은 두 단계로 분리.** 인가 지점(`Authorizer::check()` chokepoint, 모든 op 앞)은 M1부터 존재하고(초기 정책: pinned peer 전부 허용), 정책 엔진(TOML, principal/wildcard 매칭)은 M5에서 채운다. 지점을 늦게 넣으면 전 op를 다시 감사해야 하고 그건 보안 리뷰가 반드시 찾아내는 결함이다.
6. **Chaos 하네스는 M2에서 resume과 함께 구축.** resume 정확성은 fault 주입 없이 테스트할 수 없고 SC3은 PRD에서 가장 위험한 숫자다. 측정 도구는 측정 대상과 같이 만든다. M8은 캠페인 실행이지 도구 개발이 아니다.
7. **M1부터 지켜야 할 선행 불변식** (기능은 나중이어도 구조는 지금): (a) 모든 출력 바이트는 생성 지점에서 sequence 태깅(M2 replay의 전제), (b) 모든 op 앞에 `Authorizer::check(principal, action, resource)` 호출과 audit 기록, (c) connection 방향(initiator/responder)과 세션 역할(controller/target)을 독립 축으로 유지(M3 reverse의 전제).

## 2. 마일스톤

### 마일스톤 마감 공통 절차

모든 마일스톤은 자신의 수용 기준에 더해 다음 두 검사를 통과해야 닫힌다. 2026-08-21 프로덕션 준비도 감사가 만든 절차다. M2가 자기 계약 두 건(SIGTERM drain, exec 환경 위생)을 어긴 채 Done으로 표시될 수 있었던 원인은 DoD 목록과 구속 문서의 마일스톤 태그를 대조하는 절차가 없었다는 것이다.

1. **구속 문서 태그 대조.** `docs/CLI.md`, `docs/PRD.md`, `docs/adr/`에서 이 마일스톤 번호가 태그되었거나 이 마일스톤이 구현한 기능을 계약으로 확정한 문장을 전수 대조해, 각각이 (i) DoD 항목으로 검증되었거나 (ii) 후속 마일스톤에 명시 귀속된 유예임을 확인한다. 어느 쪽도 아닌 문장이 하나라도 있으면 닫지 않는다.
2. **README 동기화.** README의 기능 목록, Known limitations, 인터임 위험 고지를 마일스톤 종료 시점의 실제 동작·권한과 일치시킨다. 인터임 고지가 실제 권한보다 좁으면 그 자체가 결함이다.

### M0 — 결정·스캐폴드·CI ✅ 완료 (2026-08-17)

- **범위:** 설계 결정 6건(ADR-0001~0006), 스펙 개정(PRD v0.3, CLI v0.2), cargo workspace 5 crate와 xtask arch-lint, CI 4-target matrix, `qsh version --json` 수직 절편.
- **결과:** arch-lint가 의존 위반 시 실패(주입 테스트로 확인), 테스트 23개 green. **크기:** 1ew

### M1 — Walking skeleton ✅ 완료 (2026-08-18)

- **범위:** `qsh init`(device identity, keystore auto/platform/file + headless fallback), `qsh serve`, `qsh trust add --fingerprint`, `qsh exec host --json -- cmd`. QUIC + TLS 1.3 상호 인증(pinned cert), typed op layer, JSON envelope·exit code 계약(§4), `Authorizer::check()` chokepoint(임시 allow-all-pinned)와 op별 audit line, localhost 통합 하네스. hosts.toml(M7) 전까지 host→주소 해석은 trust store(trust.toml)의 pinned peer가 단일 출처다.
- **명시적 out:** PTY, 세션, resume, private CA, invite code pairing, 터널, reverse, 정책 파일.
- **DoD (달성):** 1 `exec`가 exit 7과 올바른 `stdout_b64`/`stderr_b64`/`remote_exit_code`를 낸다(`exec_e2e.rs`, `exec_loopback.rs`). 2 비신뢰 peer는 exit 255 + `AUTH_FAILED`이고 host audit.log에 handshake deny가 남는다. 3 handshake matrix 16종 전부 기대 결과(`crates/qsh-transport/tests/handshake_matrix.rs`). 4 `-v` 진단은 stderr에만, stdout은 JSON 하나(`jsonl_purity.rs`). 5 golden fixture와 exit-code matrix가 CI 4-target에서 돈다.
- **크기:** 3ew

### M2 — 세션 broker + PTY + resume ✅ 완료 (2026-08-19)

- **범위:** (a) headless broker(세션 registry, ReplayRing, writer lease, resume TTL, gap, `session.*` op), (b) POSIX PTY와 대화형 TUI(`qsh user@host`, `qsh attach`, detach key), (c) connection migration(`rebind`)과 resume(`session.attach` + resume token + last_seq), replay/dedup, `session.gap` 이벤트. chaos proxy 하네스(`docs/design/testing.md` L4)와 recovery 텔레메트리를 같이 구축.
- **명시적 out:** reverse, 터널, ACL 정책 파일, multi-attach, local echo prediction.
- **수용 기준 (달성):** 1 ReplayRing property test(무손실·무중복, SC4). 2 실제 셸 사용(bash/zsh/vim/tmux, resize 전파, `tui_expect.rs`). 3 클라이언트를 `yes` 실행 중 `kill -9` 후 reattach한 결과가 기준 stream과 byte-identical이고 PTY 자식은 생존(SC4·SC5, `session_kill9.rs`). 4 chaos `repath()`는 migration으로 무중단, `sever()`는 2초 내 재dial + resume(`attach_recovery.rs`). 5 실기기 Wi-Fi↔테더링 20회 조기 측정(`docs/campaigns/m2-mobility.md`: path 사망 10회 전부 자동 resume, 세션 사망 0, gap 0. 예산 내 복구 1/10은 Tailscale underlay 재경로가 지배 요인. SC3 판정은 M8 N ≥ 60).
- **사후 감사 (2026-08-21):** 계약 부채 2건 발견. serve의 SIGTERM graceful drain 미구현(`docs/CLI.md` §6.12)과 `exec.run`의 환경 상속(같은 문서의 pinned env). 상환은 M3 감사 개정분이 맡았다.
- **크기:** 5ew

### M3 — 역방향 ✅ 완료 (2026-08-24)

- **범위:** `qsh listen`(controller), `qsh reverse controller`(target, 등록 + heartbeat + 백오프 재접속), `host.reverse` ACL action, `hosts`의 `connection_mode:"reverse"`, 역방향 위의 `qsh attach <name>`. 감사 개정분: ① M2 계약 부채 상환(SIGTERM drain, `exec.run` 환경 위생), ② 세션 소유권 P0(`session.control`의 write/resize를 opener principal에 결합. 조회·읽기·종료는 PRD §6대로 교차 기기 범위).
- **명시적 out:** relay, NAT traversal, discovery.
- **DoD (달성):** 1 NAT 뒤 target이 `qsh reverse` → controller의 `qsh attach`로 셸 획득. 2 target 네트워크 60초 차단 후 재등록되고 같은 세션이 resume(`reverse_blackout.rs`). 3 `qsh hosts --json`이 forward/reverse를 함께 반환(§6.1). 4 controller reachability 요구가 docs와 doctor 메시지에 명시. 5 SIGTERM 후 잔존 자식 process group 0, `exec.run` 환경에 serve 마커 없음. 6 타 principal 세션의 `session.write/resize` 거부와 audit deny, 병렬 등록·다중 세션 경합 테스트.
- **크기:** 2ew + 0.5ew

### M4 — 터널 ✅ 완료 (2026-08-27)

- **범위:** `-L`/`-R`, `qsh tunnel open/close`, `qsh tunnels`. TCP 연결당 QUIC stream 1개, stream 우선순위로 PTY 보호, remote forward는 loopback bind만(§9).
- **명시적 out:** SOCKS `-D`, file copy, UDP forwarding.
- **DoD (달성):** 1 `-L` 후 `curl` 도달. 2 `-R` non-loopback bind 거부. 3 throughput ≥ raw-quinn 기준의 80%. 4 포화 터널과 병행한 PTY echo p95 < RTT + 10ms(§13). 5 `-D` → `UNSUPPORTED`(M4 시점 기록. 현재 계약은 ADR-0019와 `docs/CLI.md` §6.9). perf 게이트 정본은 CI acceptance run 32986938847.
- **마감 노트:** DoD 4의 "1GB 포화 터널" 문면은 M4 Step 7 구현에서 15초 시간유계 + 최소 200표본으로 대체됐다(`tunnel_echo_under_load.rs`의 `MEASUREMENT_DURATION`·`MIN_SAMPLES`). 포화를 유지한 채 재는 것이 목적이고 1GB는 수단이었으므로 게이트의 뜻은 같다. resume 의미론은 이렇게 확정됐다. migration은 터널을 투명하게 살리고, 연결 손실 후 resume에서 터널 스트림은 깨끗이 종료된다(ADR-0018). forward-route live carrier는 구현하지 않기로 했다(§3 가드레일 표).
- **크기:** 2ew

### M5 — ACL 정책 + audit ✅ 완료 (2026-08-28)

- **범위:** TOML 정책 로더, principal 매칭(fingerprint, CA 발급 user/device), 후행 `.*` action wildcard, default-deny, PRD §9 action 전체(`forward.socks`/`file.*`는 정의하되 항상 deny. `-D`가 오른 뒤에도 `forward.socks`는 설계상 항상 deny다, ADR-0019 결정 6), `qsh acl check`, 전 privileged op의 구조화 audit. 감사 개정 ① audit 수명주기(`[audit]` 회전·상한·retention, 비동기 쓰기, 디스크 만실 fail-closed), ② resource-ownership 축(M3의 opener 결합을 정책 어휘로 승격), ③ 거부 메시지 균일성(deny 응답이 거부된 action을 노출하지 않음. capability 열거 oracle 차단).
- **DoD (달성):** `acl check` == 실제 enforcement(`acl_check_equivalence.rs` 표 기반 3-way), op registry 전수 audit 단언(SC6, `acl_registry.rs`), 임의 정책에서 미커버 action은 Deny(property test), 모든 `PERMISSION_DENIED` 문면 동일(`acl_uniformity.rs`의 `DENY_SEAMS` 전수), audit 수명주기 동작 테스트.
- **마감 노트:** 구속 문서 충돌 0건. `AllowAllPinned`은 `#[cfg(test)]` 전용으로 강등됐다. SC7 외부 보안 리뷰 예약은 코드 밖 조직 액션이라 이월됐고 M8 DoD 4에 속한다.
- **크기:** 2ew + 0.5ew

### M6 — MCP adapter ✅ 완료 (2026-08-31) · 철회 (2026-09-07)

- **범위·결과:** `qsh mcp` stdio와 tool 12종, 동일 Rust 타입에서 생성한 schema, conformance 하네스, Claude Code 실접속 캠페인 2회차 PASS(캠페인 기록 `95d8e8a`의 `docs/campaigns/m6-mcp.md`, 2026-10-10 삭제). **크기:** 1.5ew
- **철회:** 내장 MCP 어댑터는 [ADR-0011](adr/0011-remove-mcp-adapter.md)로 M8 Step 6에서 제거했다(2026-09-10 완료). 에이전트 연동 면은 `qsh.cli/v1` JSON CLI 하나다. `fixtures/mcp/tools_list.json`만 append-only 규칙대로 남았다.

### M7 — Trust UX·profiles·doctor 🔄 기능 완료 (2026-09-01) · DoD 1 잔여

- **범위:** invite code pairing(ADR-0002), private CA(`qsh cert`), host profile/config, `qsh doctor`, `qsh capabilities`/`qsh schema --json`, 첫 실행 경험, man page. 감사 개정분: ① `trust remove`의 유효 범위(현행 유지하되 구속 문서·README·doctor가 명시 고지), ② pairing 안내에 대역 외 fingerprint 대조 문구, ③ `qsh version --json`에 빌드/커밋 식별자(additive).
- **명시적 out:** cert rotation/revocation UX, background service 설치, QR.
- **DoD:** 1 스톱워치 테스트(한 번도 설정한 적 없는 두 장비가 README만 보고 `qsh user@host`까지 5분 이내, 독립 3회. SC1·SC2). **열림, 위 표.** 2 doctor가 UDP 차단·경로 없음·비신뢰 peer·만료 cert·keystore 부재·clock skew를 안정된 JSON code로 진단(달성). 3 `qsh capabilities --json` == checked-in fixture(달성). 4 `trust remove` 후 기존 연결·신규 handshake 동작이 테스트로 고정되고 문서·doctor 고지와 일치(달성, `trust_lifecycle_live.rs`).
- **크기:** 2.5ew

### M8 — Hardening 🔄 진행 중 (DoD 1·2·5 완료 · DoD 3·4 열림)

- **범위:** cargo-fuzz 타깃과 corpus, stateful broker fuzzer, 24h soak, 누수 게이트, 실기기 mobility 캠페인, perf 게이트 재확인, threat model, wire format freeze, 외부 보안 리뷰 착수. 감사 개정 적대적 부하 게이트: ① `Incoming::retry()` 주소 검증, ② accept 동시성 상한과 source rate limit, ③ `[serve].max_sessions`와 principal별 세션 쿼터, 터널 전용 할당량(초과는 `RESOURCE_EXHAUSTED`. `docs/design/protocol.md` §7의 무상한 갭 인수), ④ audit 수명주기의 부하 하 검증. 그 외 handshake matrix에 ALPN 불일치 케이스, 개인키 `Zeroizing`, TUI 펌프 스레드 panic 제거.
- **DoD:** 1 parser 타깃당 누적 ≥72 fuzz-hours 무crash(달성, `docs/campaigns/m8-fuzz.md`). 2 24h/100-session soak: idle listener ≤30MB, 세션당 buffer ≤8MB, fd 무증가(달성, `docs/campaigns/m8-soak.md` run #6 PASS). 3 실기기 Wi-Fi↔테더링 ≥60회(macOS+Linux)에서 자동 유지+resume ≥95%, migrated/resumed 분해 보고(SC3. 통과 기준은 idle timeout에 기대지 않는 2초 내 재dial). **열림, 위 표.** 4 프로토콜 스펙 freeze 후 독립 리뷰 계약(SC7. 리드타임이 있어 wire freeze ~6주 전 예약). **열림, 위 표.** 5 적대적 부하 하네스: 스푸핑 Initial flood, 대량 연결, principal당 세션 폭주에서 선언된 상한이 강제되고 idle RSS/fd가 soak bound를 지키며 기존 세션의 echo가 산다(달성, `docs/campaigns/m8-adversarial-load.md`).
- **크기:** 3ew

### M9 — 사람용 표면 🔄 기능 완료 (2026-09-24) · DoD 1 잔여

- **범위:** SC1 마찰 축소. (a) 이름 결정권 이동(`pair invite|accept --as N`, ADR-0012). (b) 역방향 개명(`qsh serve --to <listener|host:port> [--name N]` 신설, `qsh listen` 유지. 구 표기와 `[reverse].controller`는 v1 내내 숨김 alias와 이중 읽기. `--to`와 `--bind` 동시 지정은 `INVALID_ARGUMENT`). (c) 파일 교환 프로비저닝(`identity export`, `trust add --cert-file`, ADR-0013). (d) 포트 생략 시 4433 기본값(ADR-0014). (e) `trust add-ca`. (f) `trust rename`. (g) `qsh service install|uninstall|status`(macOS LaunchAgent, Linux systemd user unit, Windows와 매니저 없음은 `UNSUPPORTED`. qsh 자체 데몬화는 하지 않는다). (h) doctor 진단 7종 추가(서비스 미등록, systemd linger, LaunchAgent 세션 한계, `bindv6only`, `acl_principal_unmatched`, `acl_ca_auth_path_missing`, `config_serve_to_conflict`). (i) 실패 문면 8종의 관측·영향·다음 명령 규율. (j) `pair accept`의 `code`를 선택 인자로(TTY는 무에코 프롬프트, 파이프는 `--code-stdin`, machine mode는 `INVALID_ARGUMENT`. ADR-0013 결정 8). (k) SOCKS `-D`(2026-09-19 사용자 결정으로 P1에서 당김, ADR-0019. capability `dial-filter.v1`, 새 op `tunnel.dynamic`). 로직은 qsh-core `Ops`에 두고 CLI는 렌더만 한다.
- **명시적 out:** TOFU(pin 방향 축 ADR 필요, M16 (a)), listener pairing(ADR-0015), CSR 기반 다대 CA 서명(ADR-0016), README 전면 재작성(M17 (b)). 앞의 셋은 2026-10-12 폐기했다(ADR-0030·0015·0016 기각, §5.3).
- **DoD:** 1 SC1 스톱워치 재측정, 새 표면으로 독립 3회, 5분 이내, `docs/campaigns/m7-stopwatch.md` 형식 계승, baseline(M7 DoD 1) 대비 단축 기록. **열림, 위 표.** 2 doctor 신규 8종(범위 (h)의 7종 + `host_pinned_without_address`)이 안정된 code로 고정되고 `EXPECTED_DOCTOR_CODES`와 CLI.md §6.17이 같이 갱신(달성, 동결 set 22종). 3 문구 표본 8종 축자 테스트(달성). 4 숨김 alias와 config 이중 읽기의 왕복 테스트(달성). 5 신규 op마다 새 fixture, `REQUIRED_FIXTURES` 등재, schemars 타입·렌더러·CLI.md·man이 모두 있음을 등록 완전성 테스트로 확인(달성). 6 마감 공통 절차 1·2(달성). 7 SOCKS `-D`: 실제 `curl --socks5-hostname` acceptance(`socks_curl`)가 CI에서 건너뛰지 않고 초록이고 host-local 필터 거부와 ACL 거부가 고정(달성).
- **결정 기록 (2026-09-09, 사용자 확정):** Q1 마일스톤 배치: M9 앞에 신설하고 릴리스는 M10으로 민다(notarization 리드타임이 CLI 설계 일정을 막지 않게). Q2 역방향 이름: `qsh serve --to`, `qsh listen` 유지, 구 표기는 v1 내내 숨김 alias. Q3 이름 결정권: `pair invite|accept --as`, wire 자칭 값은 `device_id` 그대로. Q4 SC1 시점: 현행 표면으로 baseline 3회를 먼저 재고 새 표면으로 재측정해 DoD에서 비교한다. Q5 둘째 터미널 마찰: `qsh service install` 안내와 데몬 부재 진단으로 푼다. `serve --pair`는 기각(10분 초대를 상시 데몬 stderr에 노출하고 `invites.toml`에 writer를 하나 더 만든다).
- **마감 노트 (2026-09-24):** DoD 2~7 충족, CI run 35999353718·36000049248. 마감 절차 1은 대조 문장 144건에서 충돌 4건을 전부 고쳤다. 이슈 #3·#4의 결함 수정 다섯 건은 M9 범위 밖으로 처리했고(`ea8fcb6`~`c9113cc`), 남은 항목은 제안 ADR 넷(0021·0022·0025·0026)이 됐다.
- **크기:** 4.3ew + SOCKS `-D` 1.6~2.0ew(추정)

### M10 — 릴리스 🔄 파이프라인 완료 (2026-09-25) · DoD 1·2·3 잔여

- **범위:** 설치 스크립트, Homebrew tap(`DaveDev42/homebrew-tap`, release.yml의 `homebrew-tap` job이 version/url/sha256을 다시 쓴다), macOS codesign + notarization, musl static Linux 빌드, SLSA provenance, 클린 VM smoke, 릴리스 문서, crates.io publish gate 해제.
- **DoD:** 1 클린 macOS arm64/x86_64·Linux arm64/x86_64에서 brew/curl 설치 후 동작. **열림, 위 표.** 2 Gatekeeper가 notarized 바이너리를 차단하지 않음. **열림, 위 표.** 3 musl static 바이너리가 구형 glibc 배포판에서 실행. **열림, 위 표.** 4 "동작"의 정의는 `version --json`이 아니라 기능 스모크(init → trust → `exec --json` 왕복 + PTY 셸 + detach→attach resume)이고, release 프로파일 바이너리로 통과(달성, `release_smoke.rs`의 `release_smoke_covers_init_trust_exec_pty_detach_and_reattach`를 `release.yml` build job과 `load.yml`이 `QSH_SMOKE_STRICT=1`로 구동). 5 PRD §13 두 항목의 릴리스 게이트 판정(달성): '느린 터널이 PTY를 block하지 않음'은 `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`(`ci.yml` acceptance 상시. 포화 축 하나만 덮고 저속·역압 축은 M13 (b)가 닫았다), '30분 단절 후 TTL 내 세션 복구'는 `a_real_30_minute_blackout_is_resumed_within_the_ttl`의 dispatch run 36033815282가 판정. 6 threat-model에 M9 사람용 표면 반영(달성). 7 마감 공통 절차 1·2(달성).
- **결정 기록 (2026-09-24, main 세션, 사용자 전면 자율 지시):**
  - Q1 release 스모크 leg: darwin 2 + linux-gnu 2 네이티브 러너 전부와 musl leg을 `QSH_SMOKE_STRICT=1`로 돌린다. Windows leg은 init → trust → `exec --json` 왕복까지고 PTY·detach/attach 축은 뺀다. `load.yml`에도 같은 스텝을 둔다.
  - Q2 macOS 배포 형식: tar.gz를 유지하고 공증만 더한다. `.pkg`는 만들지 않는다. 단일 실행 파일은 stapler 대상이 아니라 오프라인 판정이 미보장임을 캠페인 문서에 적고, Gatekeeper 판정은 수동 다운로드 경로에서 `spctl`·`codesign`·`notarytool` 셋으로 고정한다.
  - Q3 musl: `x86_64-unknown-linux-musl` 하나만 만든다. aarch64 musl은 P1(M13 (c)로 착지).
  - Q4 man page: Homebrew formula만 설치한다. unix 아카이브에 `man/*.1`을 더하고 tap formula에 `man1.install` 한 줄을 둔다. curl 설치 경로는 M13 (i).
  - Q5 beta: 선언하지 않는다. README의 'Not for production use'는 유지하되 사유를 SC7과 열린 사람 캠페인으로 좁힌다.
  - Q6 옛 계획 인용: 기존 인용은 부채로 남기고 새 인용은 만들지 않는다. (2026-10-10 개정: `docs/history/` 전체를 지우고 인용은 커밋 해시로 옮겼다.)
  - Q7 fuzz deny: `fuzz-smoke.yml`에 `cargo deny --manifest-path fuzz/Cargo.toml check advisories` 한 스텝만 더한다.
  - Q8 crates.io: publish gate 해제는 M10 안에서, 실제 `cargo publish`는 클린 VM 캠페인 PASS 뒤에 사람이 실행한다.
- **태그 정책 (2026-09-24):** 태그는 판정 근거 회차가 실제로 돈 트리에 찍고, 찍은 태그는 옮기지 않는다. 태그 push가 `release.yml`을 구동한다. M10 첫 태그는 클린 VM 캠페인 PASS 트리이고, 서명·공증이 붙은 첫 태그가 DoD 2 판정 대상이다.
- **태그 기록:**

  | 태그 | 커밋 | release run | 비고 |
  |---|---|---|---|
  | `v0.2.0` (2026-09-21) | `2907488` | 35579517383 | SOCKS `-D` 포함. tap 커밋 `397b2a3` |
  | `v0.3.0` (2026-09-26) | `891c407` | 36254706923 | Apple 시크릿 미등록으로 ad-hoc 서명이라 DoD 2 판정 대상 아님. Linux 클린 회차 셋 PASS(`m10-clean-vm.md` §8). tap `f66f76d` |
  | `v0.4.0` (2026-10-02) | `75cdebc` | 36964938589 | 서명·공증이 붙은 첫 태그. aarch64 musl leg 포함 |
  | `v0.4.2` (2026-10-06) | `a5d3895` | 37402762387 | 이슈 #10·#11, M13 (k), ADR-0041·0042 |
  | `v0.4.3` (2026-10-08) | `f7ed074` | 37713234863 | 의존성 갱신과 M13 마감. CI run 37712425579 |

  서명 태그의 darwin 자산은 `SHA256SUMS` 일치, Developer ID 서명(hardened runtime, 타임스탬프), `spctl`의 `source=Notarized Developer ID`, `gh attestation verify` 통과를 확인했다.
- **마감 노트 (2026-09-25):** DoD 4~7 충족, DoD 1·2·3은 사람 회차를 기다린다. 파이프라인은 musl 자산(`168e00c`), Developer ID 서명·공증(`c61111b`·`cf24287`, 시크릿 여섯이 전부-또는-전무이고 0개면 조용히 건너뛴다), provenance attestation(`d7bede7`), man 페이지(`b38ed80`), fuzz 락의 deny advisories(`159e1fa`), publish gate 해제와 `publish-dry-run` 잡(`faf10bd`), 클린 VM 캠페인 기준(`18f29f0`), `RELEASE-NOTES.md`(`c7a4a9e`)로 착지했다. `cargo publish`는 실행하지 않았다(Q8). `-W`는 기각했다(ADR-0011 결과 절). CI run 36068891182.
- **이슈 처리 (2026-09-26):** 이슈 #5(`qsh exec`가 살아 있는 역방향 등록을 쓰지 못함)는 M10 범위 밖 결함 수정이다(`74a4d4c`, `docs/CLI.md` §6.1·§6.8·§6.13).
- **크기:** 2.6ew

## 3. 유예 가드레일 (P1/P2 경계)

작동 원리: "ACL action과 오류 경로만 정의하고 구현하지 않는다." 이름 붙은 "아직 아님"은 단순 부재보다 scope creep에 훨씬 강하다.

| 유예 기능 | 압력원 | 가드레일 |
|---|---|---|
| TCP/TLS fallback (철회, ADR-0043) | doctor가 "UDP 차단"을 보고하는 순간 | 만들지 않는다. transport facade는 남지만 TCP 코드는 0줄이고, doctor 메시지와 README는 "예정"이 아니라 범위 밖이라고 적는다. 다시 열려면 ADR-0043을 개정하는 새 ADR |
| SOCKS `-D` (M9로 승격, 2026-09-19, [ADR-0019](adr/0019-socks-dynamic-forward.md)) | 스펙 예시에 존재 | M9가 구현했다. `-D`는 CONNECT마다 `forward.local`로 인가된다. `forward.socks` action은 어휘에 남고 여전히 항상 deny다. 이 토큰을 적은 기존 `acl.toml`이 파싱 오류로 전부 거부 상태가 되지 않게 하려는 것이다 |
| File copy (P1) | `file.read/write` action이 §9에 존재 | action만 정의, op 미등록, capabilities에 미광고. → M15 (scp 호환 `qsh cp`, ADR-0029) |
| Windows (P1 client M19 · host M20) | 외부 기여 PR | client는 M19(Authenticode 서명과 scoop·winget은 2026-10-19 철회, ADR-0035 개정 이력), host(ConPTY 백엔드와 Job Object, 세션 신호 사상, host 쪽 `exec`·`cp`, audit 잠금, `acl.toml` DACL 경고, `setup host`·`pair invite`·`pair ssh-respond`)는 M20 착지(둘 다 2026-10-18). 플랫폼 차이는 없다(ADR-0035 결과 절). CI의 `windows-latest` leg은 clippy·nextest 전체와 PTY를 포함한 정방향·역방향 Windows 종단을 돈다. 남은 것은 `p1-windows` 사람 회차와 서명·배포 준비(§5.5) |
| Multi-attach read-only (P2) | broker에서 거의 공짜로 나옴, 그래서 위험 | 관찰자(observer) 개념 자체를 만들지 않는다. writer lease는 P0 필수이고 두 번째 attach 정책은 lease 규칙만 따른다 |
| Local echo prediction (P2) | mosh 대비 지연 불평 | P0는 실제 PTY 지연을 측정·공개해 데이터로 대화한다(§13의 10ms 예산) |
| Relay (§14, 별도 제품) | "작은 relay 하나면" | P0 의무는 세션 identity와 transport 분리뿐(resume이 이미 강제). `--relay` flag는 stub조차 없다 |
| Forward-route live carrier·`-R` 자동 재발행 ([ADR-0018](adr/0018-tunnel-lifetime-bound-to-connection.md)로 종결) | 터널이 recovery 후에도 신규 연결을 서비스하길 기대 | v1 터널 수명은 connection에 결합되고 live carrier는 구현하지 않는다(M4가 `tunnel_chaos.rs`의 트랩으로 고정, README Known limitations가 고지). ADR-0023(2026-09-30 승인)이 명시적으로 켠 터널(`--supervise`)에 한해 ADR-0018 결정 2·3을 개정하고 결정 1은 유지한다. forward route의 `-L`/`-D`는 M12 첫 단위, reverse route와 `-R`은 둘째 단위로 착지했다 |
| Cert rotation UX (폐기, 2026-10-12) | 만료 | 만료 30일 전 doctor 경고만 둔다. rotation·revocation 목록은 만들지 않고, `trust remove` 뒤 열린 연결을 닫는 것만 M16 (b)(ADR-0031 축소판)가 한다 |
| Service 설치 (M9로 승격, 2026-09-07) | 상시 실행 요구 | M9가 `qsh service install`을 구현했고 unit 예시는 `docs/deploy/service.md`. 서비스 매니저 실호출은 M17 (a)가 명시적 플래그(`--activate`·`--deactivate`·`--live`)로 착지했다(ADR-0032). Windows 작업 스케줄러 분기는 M19 착지(`8c5ef13`·`357fd58`) |
| SSH 키 가져오기 | 기존 키 재사용 요구 | ADR-0026. P1 착수로 M11 (c) 범위가 됐고 구현했다 |
| **메타 가드레일** | | `qsh capabilities --json` == fixture 테스트: 새 capability는 fixture diff로만 추가 가능(리뷰 가능한 산출물). + ErrorCode 전수 도달성 테스트: 존재하지만 만들 수 없는 코드 금지 |

## 4. 일정 리스크 5건

1. **SC3(≥95% mobility)은 CI로 측정할 수 없는 측정 문제이고, 통과 기준이 미정의면 그 자체가 리스크.** 대응: chaos proxy와 recovery 텔레메트리를 M2에 구축, M2 말 실기기 20회 조기 측정, "idle timeout이 늦게 터져서 기술적으로 통과"를 배제하는 기준(재dial 2초)을 명문화, M8에 ≥60회 본 캠페인.
2. **PTY/터미널 정확성은 추정을 거부하는 long tail.** 대응: M2b를 명명된 수용 세트(bash/zsh+vim+tmux+claude)로 timebox, "terminal quirks" 백로그를 마일스톤 밖에 유지, expect 하네스를 초기에 구축.
3. **Identity·keystore·pairing이 SC1(간판 숫자)의 critical path.** headless Linux에 Secret Service가 없어 file fallback과 doctor 보고가 필요하고, macOS 미서명 바이너리의 Keychain 재프롬프트가 dev loop을 괴롭힌다. 대응: keystore fallback을 M1의 명명된 task로, 스톱워치 테스트를 M7 한 번이 아니라 조기·반복 실행.
4. **In-listener 세션과 listener 재시작/업그레이드의 충돌은 구조적.** 대응: ADR-0003의 `SessionBackend` seam을 순수하게 유지하고 graceful re-exec 비용을 산정했다(`docs/design/reexec-estimate.md`, H0~H5). H1·H1b는 M13에서 착지했고 H2·H4·H5와 세션 거처 결정은 M18이 가진다.
5. **SC7 보안 리뷰와 notarization은 리드타임 함정.** 대응: 리뷰는 M5 시점에 예약하고 wire format을 리뷰 ~6주 전에 freeze한다. notarization은 M10에서 마쳤다(`v0.4.0`부터). 리뷰 예약은 M8 DoD 4로 아직 열려 있다.

## 5. P1 마일스톤

P1은 2026-09-26 사용자 결정으로 열었다. §2의 "마일스톤 마감 공통 절차" 1·2는 P1 마일스톤에도 적용한다. 크기는 전부 추정이고 1인 기준 ew다.

### 5.1 P1 시퀀싱 원칙

1. 이슈가 남긴 승인 ADR을 먼저 구현하고, 제안 ADR을 그다음에 둔다. 모양이 정해진 일을 먼저 끝내야 뒤의 설계 라운드가 그 결과를 입력으로 쓴다. (M11, M12로 소화했다.)
2. 계약·wire를 건드리는 항목은 ADR 승인 전에 구현 스텝을 열지 않는다. 승인이 늦는 마일스톤은 기다리게 두고 순서상 다음 마일스톤을 먼저 연다.
3. 측정 도구를 기능보다 먼저 세운다. 느린 스트림의 저속·역압 축과 야간 성능 추세(M13)가 파일 복사(M15)보다 앞선다. 파일 복사는 PTY 우선순위 보장(`tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms`가 지키는 것)을 흔들 수 있고, 흔들렸는지를 재는 도구가 먼저 있어야 한다.
4. (철회) transport 추상 뒤에 TCP를 붙이고 파일 복사를 두 transport에서 검증한다는 원칙이었다. ADR-0043이 TCP fallback을 철회해 파일 복사는 QUIC 하나에서 검증한다.
5. 권한 모델을 먼저 단순화한 뒤 신뢰 경로를 넓힌다. ADR-0045의 role이 M15에서 서야 M16의 SSH 부트스트랩(ADR-0044)이 원격 pin에 role을 쓸 수 있고, `qsh cp`(ADR-0029)도 role이 파일 권한을 준다는 전제 위에 선다. 2026-10-12 이전의 원칙(신뢰의 방향을 정한 뒤 pairing을 넓힌다)은 pin 방향 축·listener pairing이 폐기되며 대상을 잃었다. `qsh setup`은 새 경로가 열리면 ADR-0024 결정 2의 역할 표에 행을 더하는 식으로 뒤따른다.
6. 사람 회차는 마일스톤 DoD에 넣지 않는다. DoD는 캠페인 문서가 사전 고정돼 커밋되는 데까지다. 회차 기록은 §5.5에 모으고 P1 완료를 선언할 때의 조건으로 둔다. P0의 M7~M10은 회차를 DoD에 넣었기 때문에 "기능 완료 · DoD 잔여"로 멈춰 있다. 사람 회차를 착수 조건으로 거는 마일스톤은 M18 하나다(M8 DoD 3). 조건이 닫히지 않았으면 M18을 건너 M19를 먼저 열고, 건너뛴 사실을 이 절에 날짜와 함께 적는다. **2026-10-16:** M17이 닫힌 날 M8 DoD 3이 기록되지 않아 M18을 건너 M19를 먼저 열었다. M18은 그 회차가 기록되면 M19·M20과 무관하게 열 수 있다.
7. 정방향과 역방향은 같은 기능을 갖고, 이 동등은 Linux·macOS·Windows 모두에서 성립한다. 예외는 없다(PRD §4, 2026-10-13 사용자 결정). P1 기능은 마일스톤 안에서 두 route를 함께 착지시키고, DoD가 두 route 모두에서 같은 테스트를 요구한다. 플랫폼 간 차이는 M19·M20이 메운다. 한쪽 방향이나 한 플랫폼만 여는 설계는 두지 않는다.

### M11 — 이슈 후속과 ACL 가시성 ✅ 완료 (2026-09-30)

- **범위:** 이슈 #3·#4가 남긴 항목 중 승인 ADR로 모양이 정해졌거나 새 결정 없이 끝낼 수 있는 것. (a) `cause` 어휘 분리(`TimedOut`에 `idle_timeout`, `PathWatch` 판정은 `path_dead` 유지. ADR-0021 결정 7의 선행 조건). (b) `qsh acl show`(ADR-0025)와 재시작 문구 상수 추출. (c) `qsh init --import-ssh-key <path>`(ADR-0026, 평문 Ed25519만, 파서는 `qsh-proto`와 fuzz 타깃). (d) doctor 진단 1종(`forward.socks`를 적었으나 `forward.local`로 덮이지 않는 `[[acl]]` 행, ADR-0019 R6). (e) 문서 갭(한 장비를 두 별칭으로 pin하는 배치, `[listen].stale_retention` 운영 안내).
- **명시적 out:** `qsh acl grant`/`revoke`, 원격 ACL 미리보기, 암호화된 SSH 키·ssh-agent·RSA/ECDSA, supervised tunnel과 `qsh setup`(M12), push health 표면, `HOST_NOT_FOUND` 구제 문면 교체(§5.3), ADR-0021 결정 1·4(M13 (k)).
- **DoD (달성):** (a) `classify_connection_error` 세 갈래 고정, fixture·wire·`qsh.cli/v1` diff 0. (b) `acl.show` 등록 완전성과 `acl_check_equivalence.rs` 동치, 정책 없음의 공집합, 재시작 상수의 바이트 일치. (c) 평문 Ed25519 가져오기, 거절 코드 고정, 기존 identity는 오류, `trust.toml`·`acl.toml` 불변, 입력 바이트 비노출, 새 fuzz 타깃. (d) 진단이 22종에서 23종. (e) 두 별칭 동작을 테스트로 먼저 확인.
- **결정 기록 (2026-09-27):** Q1 supervised tunnel과 `qsh setup`은 승인 대기 중이라 M12로 묶는다. Q2 SSH 키 가져오기는 rotation(M16 (d))을 기다리지 않고 M11에서 하고 잔여 위험은 README가 고지한다. Q3 `forward.local`이 빠진 행을 짚는 별도 진단은 만들지 않는다(터널 권한 없는 principal은 정상 배치). Q4 `acl show`는 P1 착수로 우선순위가 정해졌다. Q5 identity가 이미 있는 장비의 `--import-ssh-key`는 성공 응답이 아니라 오류다. `--profile load` 대안은 쓰지 않았다.
- **크기:** 2.8~4.1ew

### M12 — 이슈 설계 ADR 구현(supervised tunnel, `qsh setup`) ✅ 완료 (2026-10-01)

- **범위:** (a) supervised tunnel mode(ADR-0023). `qsh tunnel open --supervise <ms>`로 켜는 모드이고 기본 동작은 바뀌지 않는다. 재수립은 매번 인가를 처음부터 거치고 wire, `.proto`, fixture, capability 문자열은 바뀌지 않는다. 두 단위로 착지했다(결정 24). 첫 단위는 forward route의 `--local`·`--dynamic`과 이슈 #6의 wake 감지기, 빠른 창, `--accept-hold`, `qsh::lifecycle` 줄. 둘째 단위는 reverse route 전부와 `--remote`. (b) `qsh setup`(ADR-0024). 새 판정 로직이 없는 오케스트레이터이고 `setup.run`은 인가 불요 local op이다. `acl.toml`은 쓰지 않고 넣을 행을 인쇄한다. 자동 신뢰는 없다. SC1 측정은 착수 조건이 아니라 사후 판정(결정 12).
- **명시적 out:** supervision 기본값화, 대화형 form의 `--supervise`, `forward_id` 재claim wire 필드, 진행 중 TCP 연결의 생존, 플랫폼 절전 통지, `docs/CLI.md` §6.1 우선순위 변경(M16 (a)), 서비스 유닛 활성화(M17 (a)), `acl.toml`을 쓰는 동작, fingerprint y/n 확인 pin, 새 pairing 경로(M16), README "First run" 개편.
- **DoD (달성):** (a) 켜지 않은 터널의 기존 트랩 테스트가 고치지 않은 채 초록이고 켠 터널은 `sever()` 뒤에도 listener가 산다. 이슈 #6 수용 테스트 셋(`supervised_forward_carrier_is_declared_lost_within_two_seconds_of_an_injected_wake`, `serve_to_target_probes_and_redials_at_once_after_an_injected_wake`, `supervised_dynamic_listener_stays_bound_through_a_50_second_blackhole_and_connects_after_it`). 재수립마다 admission·mTLS·`forward.local`/`forward.remote` 인가를 다시 거친다. 재수립이 다른 principal의 자원을 닫거나 넘겨받지 못한다(`authorize_owned`). `trust remove` 뒤에도 살아 있는 연결 위의 터널은 계속 돈다(현행 범위, CLI.md §6.9·§6.14와 README에 고지). (a)가 낸 `crates/qsh-proto/proto/`·fixture diff 0. (b) `acl.toml` 불변, 원격 op 신설 없음, 인쇄한 행을 넣으면 `acl check`가 allow, machine mode stdout은 envelope 한 줄, `crates/qsh-core/src/setup/`이 `cargo xtask arch` 디렉터리 금지 대상. `qsh setup` 첫 코드 커밋보다 먼저 측정 대상 트리 SHA가 `docs/campaigns/m9-stopwatch.md` §8에 고정된다(부모 SHA를 적는 고정 커밋, 직계 자식이 첫 코드 커밋. ADR-0024 결정 12). 캠페인 문서 `docs/campaigns/p1-setup-stopwatch.md`와 `docs/campaigns/p1-supervise-wake.md`가 사전 고정돼 커밋됨(회차는 §5.5). 안정성: 타이밍 민감 테스트는 부하 아래 50회 연속 초록(`scripts/stress/run.sh`).
- **결정 기록 (2026-09-30):** Q1 `qsh setup`은 SC1 재측정을 기다리지 않는다(SHA 고정으로 푼다). Q2 두 설계를 한 마일스톤에 묶는 이유는 같은 날 승인됐고 코드가 겹치지 않기 때문이다. Q3 supervised tunnel은 기본 동작을 바꾸지 않는 쪽이다(ADR-0023 결정 1). Q4 안정성은 부하 아래 50회 반복으로 판정하고 벽시계 상한은 주입 시계 층에서 고정한다.
- **마감 노트 (2026-10-01):** 전 DoD 충족. (a) 첫 단위 `7206ee0`~`ab05a27`, 둘째 단위 `10d14cf`·`f328958`·`51d76ae`, (b) `6ee63c3` → `1a7798d` → `e0a25a2` 순서. CI run 36762190646, load 36762190837, fuzz-smoke 36762190529. 부하 아래 50/50 통과(`51d76ae` 트리 134개, `ed905e8` 트리 추가분과 setup 테스트 16개). 고정 테스트 하나(`local_forward_primitive_over_reverse_survives_a_registration_drop_and_self_heals_per_connection`)의 대기 조건을 `26cc30d`가 바꿨고 단언은 그대로다.
- **크기:** 5.1~6.1ew

### M13 — 측정·배포 기반 ✅ 완료 (2026-10-08)

- **범위:** (a) 야간 성능 추세(nightly perf job, 저장소는 `perf-data` 브랜치). (b) 느린 스트림의 저속·역압 축(소비자가 읽지 않는 터널 스트림 여럿이 정체해도 PTY가 막히지 않는지, 새 하네스). (c) `aarch64-unknown-linux-musl` 자산(`QSH_LIBC=musl`일 때만 선택, 기본 `gnu`는 불변). (d) `qsh doctor --fail-on <severity>`(ADR-0027). (e) graceful re-exec H1(관측). (f) H1b(stateless reset key 고정). (g) 공개 크레이트 tarball의 test 타깃 `exclude` 정책. (h) `scripts/install.sh`의 provenance 검증. (i) curl 설치 경로의 man 페이지. (j) `docs/CLI.md` 상태 헤더의 기계 핀. (k) ADR-0021 결정 1·4 구현(관측 게이트).
- **명시적 out:** H2·H4·H5(M18), H3(`docs/design/reexec-estimate.md` §4가 기각), `.pkg`(§5.3), `docs/campaigns/m10-clean-vm.md` 수정.
- **DoD (달성):** (a) 저장소·보존·회귀 임계가 `docs/design/testing.md` CI 규율에 적히고, 주입 회차 run 37668749102(`inject_delay_ms=20`)가 throughput 56.4%와 echo p95 225.5%로 `perf-judge: RED`를 냈다(PR 게이트 아님). (b) 읽지 않는 스트림 넷 이상이 정체한 상태에서 PTY echo p95가 M4 예산 안이고 출력이 진행함을 testkit 테스트가 단언(acceptance strict). 수정은 M8 DoD 2의 8 MB 상한과 `tunnel_throughput` ≥80%를 둘 다 지킨다. (c) `v0.4.2` release run 37402762387의 `aarch64-unknown-linux-musl` leg strict 스모크 PASS, `SHA256SUMS`와 attestation. (d) ADR-0027 승인, `--fail-on` 없으면 exit·stdout 불변. (e) SIGTERM drain 요약 로그와 doctor 진단. (f) stateless reset 후 `REDIAL_DEADLINE`(2초) 안에 단절 확정, reset key 파일 0600, 로그·audit 비노출, wire diff 0. (g)~(j) 각각 결정이 커밋에 남음((j)는 기각하지 않고 핀으로 고정). (k) 이슈 #10의 `cause` 분포(`idle_timeout` 0, `path_dead` 지배)를 근거로 결정 1(`18cd299`)과 결정 4(`cbf0564`)를 구현. ADR-0041(`bf0d7e5`)이 역방향 등록 연결의 기본 감지를 4.25초로 갈랐으므로 "설정이 없을 때 동작이 오늘과 같다"는 대화형 attach와 supervised 터널에 선다(`v0.4.2`).
- **마감 노트 (2026-10-08):** 사람 몫 `p1-aarch64-musl` 회차는 §5.5에 있다. 같은 날 의존성을 갱신했다(`9714cf6`~`ec68cb6`). 800줄을 넘은 파일의 인라인 테스트 모듈을 sibling `tests.rs`로 옮겼다(`d28adba`~`4fcdc77`, 테스트 이름·개수 불변).
- **크기:** 3.1~6.1ew

### M14 — TCP/TLS fallback ⛔ 철회 (2026-10-11)

- **결정:** 2026-10-11 사용자 결정으로 TCP/TLS fallback을 만들지 않는다(ADR-0043). 착수 ADR이던 ADR-0028은 기각했다. migration 없는 경로, 선두 차단 아래 PTY 예산 없음, 두 배가 되는 테스트 매트릭스와 새 공격면이 "UDP가 막힌 망에서도 연결은 된다"는 값보다 크다고 봤다. UDP가 막힌 망은 범위 밖이고 README가 SSH·overlay 우회를 안내한다. 마일스톤 번호 M15~M19는 그대로 둔다.
- **남긴 것:** (a) `qsh-transport`의 transport 중립 facade. 착지 2026-10-09, `e5a62a5`~`7ca3947`, 모양은 ADR-0028 결정 0. `qsh-core`·`qsh-cli`에 quinn 의존과 `quinn::` 경로가 없고 `cargo xtask arch`가 잠근다. 처리량 비율과 포화 터널 PTY echo p95는 기준선 범위 안이다. ADR-0043 결정 3이 이 경계를 유지하고, ADR-0028 결과 절이 적은 테스트 접근자 교체 편집을 받아들였다. doctor `udp_egress_blocked`의 message는 ADR-0043을 가리킨다.
- **크기:** (a) 1.0~1.8ew 소진. 나머지 3.3~5.1ew는 P1 합에서 뺐다.

### M15 — 역할 기반 권한과 scp 호환 파일 복사 ✅ 완료 (2026-10-15)

- **범위:** 2026-10-12 사용자 결정("권한 설정을 보다 간소화", "scp 명령어와 호환")으로 다시 짰다.
  - (a) 역할 기반 권한(ADR-0045). trust pin에 role(`full`·`exec`·`tunnel`·`read-only`·`reverse`·`none`) 하나를 두어 신뢰 등록이 곧 권한 부여가 되게 한다. role grant와 `acl.toml` 행은 합집합이고 `acl.toml`은 세밀한 제어용 선택 사항이 된다. role 키가 없는 기존 pin은 `acl.toml`만 따르고(업그레이드로 권한이 넓어지지 않음), 파싱할 수 없는 `acl.toml`은 role grant까지 거부한다. `trust set-role`과 `--role` 플래그를 더하고 `acl show`/`acl check`/doctor가 role을 보여 준다. ADR-0017·0024·0025·0038의 관련 결정을 개정한다.
  - (b) scp 호환 파일 복사(ADR-0029 개정판). `qsh cp [-r] [-p] [-q] [--no-clobber] SRC... DST`, 인자 문법은 `[user@]host:path`, 로컬↔원격 한 방향. 디렉터리 순회는 client가 하고 wire에는 `file.read`/`file.write`에 더해 `file.list`·`file.mkdir`가 오른다. `full` role은 serve 계정이 닿는 경로 전부를 준다. `[[acl]]` `paths`는 행으로 파일 권한을 줄 때만 쓴다.
  - 이 ADR이 반드시 담아야 하는 결정이 하나 있다. `file.write`는 `qsh serve`의 uid로 파일을 쓰고, 그 uid는 `acl.toml`, `trust.toml`, `invites.toml`, identity와 keystore, `resume.json`, audit 로그를 쓸 수 있다. `file.write`가 `acl.toml`에 닿으면 원격 peer가 ACL writer가 되어 ADR-0017 결정 1과 ADR-0025 결정 1이 닫은 자리를 원격 op이 우회한다. `trust.toml`은 더 나쁘다. pin과 role이 판정마다 다시 읽히므로 원격 쓰기 하나가 재시작 없이 새 pin이나 `full` role을 심는다. audit 로그를 덮어쓰면 SC6 추적성이 지워진다. 그래서 qsh의 config·data·state·runtime 디렉터리(`docs/design/architecture.md` §7의 경로 전부, 곧 `config.toml`, `acl.toml`, `trust.toml`, `invites.toml`, `hosts.toml`, identity·keystore 파일, `resume.json`, audit 경로, localctl 소켓 디렉터리, M13 (f)의 reset key 파일)는 role·ACL 행과 무관하게 `file.*`의 대상에서 항상 거부한다. 판정은 symlink를 해석한 뒤의 정규 경로로 한다. 이 성질은 role로도 행으로도 열 수 없어야 한다.
- **착수 조건:** ADR-0045 승인((a), 충족 2026-10-14), ADR-0029 승인((b), 충족 2026-10-14). (b)는 (a)의 role 판정 위에 선다. M13 (b)의 역압 하네스가 선 뒤(충족).
- **명시적 out:** 디렉터리 동기화(rsync류), 원격↔원격 복사, 재개, UDP forwarding, 원격 파일 브라우징, role 추가·매핑 변경(새 ADR), Windows의 파일 op·`qsh cp`(ADR-0029 결정 23: Windows client는 M19, Windows host는 M20).
- **DoD (달성):**
  - (a) ADR-0045가 `승인됨`이다. role 키가 없는 기존 `trust.toml`이 오늘과 같은 판정을 내고, 새 pin은 role 키를 명시하며, 모르는 role 값은 `CONFIG_ERROR`로 fail closed함을 테스트가 고정한다. `acl.toml` 세 상태(있음·없음·파싱 불가)마다 role grant의 동작이 ADR대로임을 oracle 테스트가 고정하고, `acl_check_equivalence.rs`와 `acl_uniformity.rs`가 role 경로를 포함한다. role로 allow된 요청의 audit 레코드가 근거를 싣는다.
  - (b) 큰 파일과 디렉터리 트리 왕복이 해시 기준으로 byte-identical이다. forward route와 reverse route 모두에서다(§5.1 원칙 7, transport는 QUIC 하나, ADR-0043). 트리 안 symlink와 특수 파일 처리, 부분 실패의 exit code와 JSON 레코드가 ADR대로다. 지원하지 않는 scp 플래그는 exit 2다.
  - 권한이 없으면 deny다. 새 seam이 `DENY_SEAMS`에 행으로 오르고 `acl_uniformity.rs`가 문면 균일성을 단언한다. `acl_registry.rs`의 항상-deny 예외 목록에서 `file.read`/`file.write`가 빠지고 `forward.socks`만 남는다.
  - `full` role과 `allow = ["file.*"]` 행 어느 쪽으로도 qsh 자신의 상태 경로에 대한 `file.*`가 `PERMISSION_DENIED`이고 파일 바이트가 그대로임을 핀 테스트가 단언한다. 적어도 `acl.toml`, `trust.toml`, `invites.toml`, identity 파일, audit 로그를 덮고, 그 경로를 가리키는 symlink와 `..`로 이탈하는 경로 두 우회도 같은 결과임을 단언한다.
  - 인가 전 자원 생성이 없다. deny된 `file.write`·`file.mkdir` 뒤 목적지와 그 디렉터리에 새 파일·임시 파일·디렉터리가 없고 기존 파일은 바이트 단위로 같다.
  - 동시 전송 quota가 ADR-0010의 모양으로 인가 뒤·열기 전에 결정되고, `crates/qsh-core/tests/quota_registry.rs`에 행이 오르며 `quota_docs.rs`가 문서의 거부 범주와 기본값을 확인한다.
  - audit 레코드의 필드 집합이 ADR-0029·0045가 고정한 대로이고, 파일 내용 바이트가 어떤 필드에도 들어갈 수 없음을 `record_has_only_structural_fields`(`crates/qsh-core/src/audit/tests.rs`)와 같은 형식의 테스트가 고정한다.
  - 파일 복사와 PTY echo를 동시에 돌린 상태에서 M13 (b) 하네스가 같은 예산으로 초록이다.
  - 신규 op·명령마다 fixture 등재와 등록 완전성(`layer_2_every_schema_command_has_all_six_faces`), `capabilities.json` golden 재생성, man 재생성, 새 wire op의 decode 경로가 fuzz 타깃에 걸림, freeze 발효 전이면 `docs/design/protocol.md` §16.1 목록 동시 갱신.
  - `docs/design/threat-model.md` §3에 파일 op 진입점과 role 경로가, §4 B에 상태 경로 쓰기·경로 이탈·덮어쓰기·신뢰 등록이 권한 부여가 되는 위협 행이 핀 테스트와 함께 오른다.
  - 안정성: M15가 더한 타이밍 민감 테스트는 부하 아래 50회 연속 초록(`scripts/stress/run.sh`), 지연 단언(복사 중 PTY echo p95)은 부하 없이 `-j 1`로 50회 연속 초록.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **(a) 착지 (2026-10-14):** Step 2~8(`2d52a0f`..`85ea34f`)과 Windows 보정 `eb4216e`. CI run `38471301026` 초록, 타이밍 민감 테스트 부하 아래 50/50(`scripts/stress/m15.filter`), `crates/qsh-proto/proto`와 `capabilities.json` diff 0(ADR-0045 결정 17). 잔여 위험 다섯은 `docs/design/threat-model.md` §7. (b)는 아래 마감 노트.
- **마감 노트 (2026-10-15):** 전 DoD 충족. (b) Step 9~16 `bd0ae57`·`3855954`·`a86123d`·`f64f3ba`·`16388d9`·`b1fcf3a`·`1a4af3b`·`08f663c`, 태그 대조 drift `ce0a84c`, Windows·macOS·의존성 보정 `668214b`·`1d02860`·`a9748a4`·`dbd6a5b`·`5f0b838`. CI run `38614653051`(acceptance 포함) 초록. 부하 아래 `scripts/stress/m15.filter` 50/50(156개, Dave-Windows-WSL 8 vCPU), 지연 단언 `m15-latency.filter` 셋은 부하 없이 `-j 1`로 50/50. wire 변경은 `a86123d`(`FileReadOpen`·`FileWriteOpen`·`FileListOpen`·`FileMkdirOpen`과 `FILE_DATA`) 하나다. Windows는 `file.v1`을 광고하지 않고 네 op에 `UNSUPPORTED`로 답한다(M19·M20). 같은 기간 통합 테스트를 crate당 바이너리 하나(`tests/it`)로 합쳤다(`8a557c2`). 사람 몫 `decode_file_frame` 누적 fuzz-hours는 §5.5. 계획 원문은 `7cbeced`(코드 인용은 같은 스텝 번호의 `1a4af3b`).
- **크기:** 7.0~10.5ew. (a) ADR-0045 2.7~4.2(trust.toml role 키, 평가 단계 하나, `trust set-role`, acl show/check·doctor 변경, fixture 아홉) / (b) ADR-0029 4.3~6.3(2026-10-11 초안 3.3~5.0에 재귀 복사 1.0~1.3). 4ew를 넘으므로 (a)와 (b)를 순서대로 따로 닫아도 된다.

### M16 — SSH 부트스트랩과 신뢰 철회 ✅ 완료 (2026-10-15)

- **범위:** 2026-10-12 사용자 결정("기존 SSH의 설정과 키를 활용해서 바로 qsh가 동작할 수 있게")으로 다시 짰다. 이전 범위의 pin 방향 축(ADR-0030), listener 초대 상환(ADR-0015), CSR 다대 CA 서명(ADR-0016)은 기각했고, rotation·revocation(ADR-0031)은 (b) 하나로 줄였다.
  - (a) SSH 부트스트랩(ADR-0044). pin이 없는 대상에 `qsh <dest>`(와 `qsh cp`)를 부르면 시스템 `ssh`를 한 번 거쳐 원격의 숨김 응답자 `qsh pair ssh-respond`와 fingerprint를 교환하고 양쪽 pin을 쓴 뒤 QUIC로 접속한다. `~/.ssh/config`, ssh-agent, 암호 걸린 키, known_hosts는 ssh가 처리하고 qsh는 `ssh -G`로 HostName만 읽는다. 원격 pin은 ADR-0045 role `full`(`--role`로 바꿈), 이 장비 쪽 pin은 role `none`이다. 명시 명령은 `qsh pair ssh`(op `pair.ssh`)다. 역방향 구도는 `qsh pair ssh <dest> --reverse --to <이 장비의 주소>`가 같은 절차로 연다(원격 pin `full`, 이 장비 쪽 pin `reverse`). 원격 설치와 serve 기동은 대신하지 않는다.
  - (b) trust 철회 시 열린 연결 닫기(ADR-0031 축소판). `trust remove`나 role 축소 뒤 `qsh serve`·`qsh listen`·`qsh serve --to`가 2초 안에 살아 있는 연결을 재검증해 신뢰를 잃었거나 권한이 줄어든 연결을 닫는다. `TrustRemoveScope` remedy의 "(P1)"이 여기서 풀린다.
- **착수 조건:** ADR-0044·0031 승인(충족 2026-10-14), 그리고 M15 (a)(ADR-0045 role) 착지(충족 2026-10-14, `85ea34f`). (a)는 원격 pin에 role을 쓰고 (b)는 role grant 축소를 비교한다.
- **명시적 out:** 조직 계정·중앙 관리(PRD §12 경계 밖), SSH 공개키를 principal로 쓰는 것(ADR-0026이 거부), 원격 qsh 설치·serve 기동, `StrictHostKeyChecking` 덮어쓰기, revocation 목록·rotation 문서·`trust rotate`·CA 발급 인증서 개별 revoke(2026-10-12 폐기).
- **수용 기준 (DoD):**
  - ADR-0044·0031이 `승인됨`이다.
  - (a) 가짜 `ssh` 실행 파일로 부트스트랩을 끝까지 돌리는 테스트가 양쪽 pin(이름, 주소, role)과 이어진 handshake를 고정한다. pin 충돌은 아무것도 쓰지 않고 끝나고, role 없는 기존 원격 pin을 `full`로 넓히지 않으며, 원격 audit를 쓸 수 없으면 pin도 쓰지 않음을 테스트가 단언한다. `--json`/`--jsonl`에서는 자동 발동하지 않고 ssh 자식이 BatchMode로 뜬다. `--reverse` 부트스트랩 뒤 원격이 `serve --to`로 등록하면 reverse route 위의 attach·exec·`qsh cp`가 정방향과 같은 테스트를 통과한다. stdio 줄 파서는 `qsh-proto`에 있고 fuzz 타깃 `parse_ssh_bootstrap_line`이 걸린다. 키 재료와 rc 출력이 로그에 남지 않는다.
  - (b) `trust remove` 뒤 기존 연결이 2초 안에 CLOSE로 끝나고 audit 한 줄이 남음을 테스트가 고정한다(`an_established_connection_survives_the_hosts_trust_remove`는 반대 단언으로 바뀐다). role 축소 뒤 연결 처리, trust.toml 파싱 실패 중 처분이 ADR대로다. `TrustRemoveScope` message·remedy와 `docs/CLI.md` §6.11·§6.17 문면이 같은 커밋에서 바뀐다. 만료 30일 전 doctor 경고(P0)는 유지된다.
  - 새 명령·필드는 fixture 등재와 등록 완전성, man 재생성을 갖춘다. 부트스트랩 직후 pin 이름·role 고지가 나온다. `docs/design/threat-model.md` §3·§4가 ssh 신뢰 승계와 연결 재검증을 다룬다.
  - 안정성: M16이 더한 타이밍 민감 테스트는 부하 아래 50회 연속 초록(`scripts/stress/run.sh`), 실제 시계 2초 단언이 부하 아래에서 흔들리면 그 테스트만 부하 없이 `-j 1`로 50회 연속 초록이고 주입 시계 테스트가 계약을 고정한다.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **마감 노트 (2026-10-15):** 전 DoD 충족. (b) 신뢰 철회 Step 2·3 `fd92130`·`029c83b`(연결 512개가 한 번의 변경에 240ms 안에 닫힘), (a) SSH 부트스트랩 Step 4~9 `aba7bd6`·`6db09a3`·`ddb39fb`·`6445922`·`e8cd7a3`·`7c43332`, 마감 절차 1·2 `b880aab`. CI run `38704818413`(acceptance 포함) 초록. 부하 아래 `scripts/stress/m16.filter` 50/50(195개, Dave-Windows-WSL 8 vCPU). 새 지연 단언이 없어 `m16-latency.filter`는 두지 않았다. `19cc424..b880aab`의 wire(`crates/qsh-proto/proto`, `wire.rs`, `local.rs`)와 `capabilities.json` diff는 0이다. ADR-0031 결정 7의 `listen` 문장은 착지 동작(닫힌 등록은 Stale로 남음)에 맞춰 개정 이력과 함께 고쳤다. Windows 귀속은 자동 발동 M19, 응답자 M20, `serve --to`·`listen` 재검증 쌍둥이 M19·M20이다(ADR-0035 개정 이력). 사람 몫 `parse_ssh_bootstrap_line` 누적 fuzz-hours와 실제 OpenSSH 회차(`docs/campaigns/p1-ssh-bootstrap.md`)는 §5.5. 계획 원문은 `66b6f4d`.
- **크기:** 3.6~5.6ew. (a) ADR-0044 2.6~4.0(`--reverse` 포함, ADR-0045 role 몫 제외) / (b) ADR-0031 축소판 0.9~1.35 / 마감 0.1~0.2.

### M17 — 운영 표면 ✅ 완료 (2026-10-16)

- **범위:** 사람 회차와 무관하게 열 수 있는 운영·문서 항목.
  - (a) 서비스 매니저 실호출(ADR-0032). `launchctl bootstrap`/`systemctl --user enable`을 명시적 플래그로만 부른다. `docs/CLI.md` §6.18은 `service install`이 유닛 파일만 쓴다고 계약하고, ADR-0024 결정 11은 활성화를 §6.18을 개정하는 별도 결정으로 남겼다. 이 ADR이 그 결정이다. 2026-10-13 개정으로 플랫폼마다 사람이 치는 상시 기동 레시피(Linux linger, macOS LaunchDaemon, Windows 상시 기동 작업)와 doctor 인식, `keystore_session_bound`, 개인키를 store 사이에서 옮기는 `qsh identity move-key`가 (a)에 들어온다. ADR-0032 결정 3 표의 작업 스케줄러(Windows) 열은 M17 (a)가 `ManagerRunner`와 실행 상태 질의 seam만 세우고, Windows 분기의 구현은 M19(ADR-0035 크기에 포함)가 한다. 사람이 설치한 상시 기동 형태(macOS LaunchDaemon, Windows `Password` 주체 작업)를 `--activate`/`--deactivate`가 건드리지 않는 규칙(ADR-0032 결정 18)도 (a) 범위다.
  - (b) README 서사·구조 전면 재작성. M9는 측정 대상 문서(README "First run" 절)를 회차 전에 바꾸지 않으려고 이 일을 SC1 재측정 뒤로 미뤘다. M12 (b)가 M9 재측정의 대상 트리를 `docs/campaigns/m9-stopwatch.md` §8에 SHA로 고정하고 `qsh setup` 캠페인도 대상 트리를 고정하므로, 두 고정 뒤에는 재작성이 측정을 흔들지 않는다. M9 DoD 1 결과가 그때 기록돼 있으면 서사의 입력으로 쓴다. **착지 (2026-10-11):** `2fc879b`. First run 절차와 테스트가 고정한 문구는 그대로다.
  - (c) QR pairing. **폐기 (2026-10-12 사용자 결정):** P1 안에 QR을 읽을 소비자가 없음을 확인했고(2026-10-11, M19는 콘솔 client), 소비자로 상정했던 P2 mobile client SDK도 폐기했다. PRD §17의 확정 결정은 "QR pairing은 만들지 않는다"로 바뀌었고 ADR-0002의 해당 줄도 맞췄다.
  - (d) 세션 및 audit 관리 개선(PRD §7 P1, 범위 ADR-0033). PRD는 항목 이름만 두었다. 범위 ADR이 무엇을 개선하는지 정한다(세션 목록 필터, audit 조회, retention 정책 등 후보). 결정 항목에 다음을 미리 넣는다. audit 조회는 인가 불요 local op이고 wire 메시지를 만들지 않는다(원격에서 부를 수 있으면 ADR-0022 결정 4·ADR-0025 결정 4가 적은 열거 oracle이 된다). audit 레코드의 삭제·축약은 원격 op으로 만들지 않는다(SC6 추적성). 조회 출력은 기존 구조 필드만 싣는다. 텔레메트리 줄의 계약 승격 여부(`crates/qsh-core/src/telemetry.rs` 모듈 doc: "That promotion is a P1 decision")도 이 ADR이 정한다.
- **착수 조건:** (a)는 ADR-0032 승인(충족 2026-10-14), (b)는 M12 (b)의 두 SHA 고정, (d)는 ADR-0033 승인(충족 2026-10-14). 사람 회차를 기다리는 항목은 없다.
- **명시적 out:** `acl.toml`을 쓰는 어떤 동작(ADR-0017 결정 1, ADR-0025 결정 1), 핫 리로드, 로그인 세션 밖 상시 기동의 자동 설정(어느 플랫폼에서도 qsh가 linger·LaunchDaemon·Windows 상시 기동 작업을 대신 설정하지 않는다. 레시피와 doctor finding은 (a) 범위다), qsh 자체 데몬화(§5.3).
- **수용 기준 (DoD):**
  - (a) ADR-0032가 `승인됨`이다. 플래그 없이는 매니저를 부르지 않는다. 부를 때의 명령 인자가 `docs/deploy/service.md`의 안내와 같음을 문서-코드 대조 테스트가 고정한다. 테스트는 실제 매니저를 부르지 않는다. §6.18과 man이 같은 커밋에서 바뀐다. LaunchDaemon 펜스가 LaunchAgent 렌더러와 같은 인자를 쓴다는 것을 문서-코드 대조 테스트가 고정한다. `keystore_session_bound`와 `identity.move_key`는 테스트와 fixture 등록 완전성을 갖추고, `move-key`가 fingerprint를 바꾸지 않음을 테스트가 확인한다.
  - (b) 마감 공통 절차 2(README 동기화)를 전면 재작성판에 대해 수행한다. 재작성 커밋이 두 SHA 고정 커밋보다 뒤다.
  - (c) PRD §17 개정 결정이 기록된다(2026-10-12 폐기로 충족).
  - (d) ADR-0033이 `승인됨`이다. 범위 ADR이 정한 항목마다 테스트와 fixture 등록 완전성을 갖추고, audit 조회 op에 대응하는 wire 메시지가 없음을 op registry 분류 테스트가 확인한다.
  - 안정성: M17이 더한 타이밍 민감 테스트는 부하 아래 50회 연속 초록(`scripts/stress/run.sh`, `scripts/stress/m17.filter`).
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 3.3~4.9ew. (a) ADR 0.3 + 구현 1.0~1.5 / (b) 0.5~0.8(착지) / (c) 0(폐기) / (d) 범위 ADR 0.2~0.3 + 구현 1.2~1.8(ADR-0033) / 마감 0.1~0.2.
- **마감 노트 (2026-10-16):** 전 DoD 충족. (a) 서비스 매니저 실호출 `1790cad`, `qsh identity move-key` `5100fdc`, LaunchDaemon 레시피·doctor 상시 기동 인식·`keystore_session_bound`(진단 27종) `2a92a45`. (d) `qsh sessions` 필터 `b0169d7`, audit 읽기 코어 `e47ffd9`, `qsh audit`(`audit.query`, local-only) `55b1a2e`. 마감 절차 1·2 `f87692e`. CI run 38782168398(acceptance 포함) 초록. 부하 아래 `scripts/stress/m17.filter` 50/50(95개, Dave-Windows-WSL 8 vCPU). 지연 예산 단언이 없어 `m17-latency.filter`는 두지 않았다. `1790cad^..f87692e`의 wire(`crates/qsh-proto/proto`, `wire.rs`, `local.rs`)와 `capabilities.json` diff는 0이고 새 `ErrorCode`도 없다. acceptance의 `file_copy_echo_under_load`(`2a92a45`)와 `tunnel_throughput`(`55b1a2e`)이 한 번씩 러너 잡음으로 떨어졌고 재실행에서 초록이었다. Windows 귀속은 작업 스케줄러 분기·`TaskStateQuery` COM 구현·`keystore_session_bound` 실측·`move-key`의 Credential Manager와 DACL·named pipe의 `audit.query` 비노출 행·세션 필터 데몬 fan-out 쌍둥이가 M19, PTY 세션 e2e와 host audit 잠금이 M20이다(ADR-0032 결정 10·15, ADR-0035 결정 9·12·14·24·25·27·28). M17이 만든 §5.5 사람 몫은 없다. 실제 Keychain·Secret Service 위 `move-key` 왕복은 `docs/design/testing.md` L1의 릴리스 전 수동 단계이고, root 없는 `launchctl print system/…` 확인(ADR-0032 결정 18)은 M19 계획 §1이 이어 추적한다. 계획 원문은 `047db25`.

### M18 — 세션 거처

- **범위:**
  - (a) 세션 거처 결정 ADR(ADR-0034). 세션이 어느 프로세스에 사는지를 고른다. 후보는 H4(listener 제자리 execve handoff), H5(단일 supervisor, ADR-0003 seam), 세션당 홀더 프로세스 셋이다. 세 번째 후보는 `docs/design/reexec-estimate.md` §4가 비용을 매기지 않았다고 스스로 적은 갭이라 이 ADR이 매긴다. H3은 기각된 채 둔다. 이 ADR은 두 가지를 더 결정 항목으로 삼는다. 하나는 `docs/design/reexec-estimate.md` §5의 보안 비용 중 고른 후보에 해당하는 것(H4 스냅숏 통로의 스크럽·수신자 검증, H5·홀더 소켓의 권한 모델)의 채택안과 크기다. 다른 하나는 ADR-0004가 P1에 배정한 encrypted disk spool 재검토다. H4의 임시 파일 통로와 H5의 프로세스 분리가 같은 질문을 받기 때문이다. 도입하지 않기로 하면 이 ADR이 ADR-0004 결과 절의 백로그 줄을 닫고, PRD §17의 "P1 이후" 문장과 ADR-0004의 어긋남을 같은 자리에서 정리한다.
  - (b) 선택한 후보의 구현. H4를 고르면 재바인드가 같은 fd로 남는지 확인하는 실측 1건이 먼저다(같은 문서 §3).
  - (c) H2(인스턴스 식별값의 `Hello` additive). (a)의 ADR이 필요하다고 판정할 때만 한다. 같은 문서 §3이 이 거래의 값어치가 자명하지 않다고 적었다.
- **착수 조건:** M8 DoD 3(실기기 mobility ≥60회, `docs/campaigns/m2-mobility.md`)이 기록된다. ADR-0003이 별도 supervisor 선분리를 기각하며 적은 "세션 생존성이 실사용에서 검증된 뒤 투자"가 이 조건이다. (a) 승인 전에는 (b)를 열지 않는다.
- **명시적 out:** Windows host PTY 백엔드(M20), 여러 세션 상태 경로를 동시에 유지하는 것(H4와 H5를 둘 다 하는 것), 세션·audit 관리 개선(M17 (d)).
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
- **크기:** 4.4~8.6ew + 보안 가산 미산정. (a) ADR 0.3~0.5(세 번째 후보 산정과 spool 재검토 포함) / (b) H4 4.2(4.0~4.8) 또는 H5 6.5(5.4~7.6), `docs/design/reexec-estimate.md` §3 표 / (c) 0~0.3 / 마감 0.1~0.2. `reexec-estimate.md` §5는 H4의 4.2ew에 스냅숏 통로 검증·스크럽 비용이 들어 있지 않고 H5에는 소켓 권한 모델을 다시 세우는 비용을 가산해야 한다고 적는다. 이 가산분은 ADR-0034가 채택안을 고른 뒤 매기고 이 절에 적는다. 세 번째 후보를 고르면 (b) 전체를 다시 매긴다.

### M19 — Windows client ✅ 완료 (2026-10-18)

- **범위:** PRD P1의 Windows client와 Windows 공통 기반. 연결 방향과 플랫폼에 관계없이 같은 기능을 연다(`docs/PRD.md` §4, §5.1 원칙 7, 2026-10-13 사용자 결정 "정방향, 역방향, 모든 플랫폼에서 평등한 기능 지원", 같은 날 "원칙에 예외는 없다"). client 쪽은 `init`, `trust`/`pair accept`(콘솔 프롬프트 포함)/`pair ssh [--reverse]`, `exec`, 대화형 attach, `-L`/`-R`/`-D`, `qsh cp`, `doctor`, `qsh listen`과 `setup listener`, `hosts`·`tunnels`의 데몬 항목이다. 공통 기반은 콘솔 raw 모드와 VT 입력, resize 폴링, named pipe localctl(소유자 전용 DACL, 이름 선점 거부, 양방향 SID 확인), 키·상태·audit 파일의 소유자 전용 DACL, Credential Manager keystore, `QueryUnbiasedInterruptTime` 기반 절전 감지다. `qsh service`와 `--service`의 작업 스케줄러 로그온 작업 백엔드(숨김 `qsh service run`, linger에 대응하는 상시 기동 레시피, `logon_task_session_scoped`)도 여기서 연다. 출고는 x86_64·aarch64 zip(man 페이지 포함), `install.ps1`, Authenticode 서명(SSL.com eSigner)과 CI 서명 검증, scoop bucket과 winget 매니페스트다. 역방향 CI를 위해 `qsh serve --to`의 Windows 게이트를 먼저 걷는다. PTY 세션은 M20까지 `UNSUPPORTED`이고 지원 약속이 아니다. ADR-0035 결정 1 목록의 `qsh identity move-key`(Credential Manager)와 `qsh audit`, 그리고 M16·M17이 넘긴 Windows 쌍둥이(신뢰 철회 `listen`·`serve --to` 재검증, 세션 필터의 데몬 fan-out, named pipe의 `audit.query` 비노출, Windows client 자동 부트스트랩)도 이 범위다. Windows client의 대화형 attach 종단은 Windows host PTY가 없으므로 Linux 테스트 host를 상대로 돈다.
- **착수 조건:** ADR-0035 승인(충족 2026-10-14). M18의 착수 조건이 닫히지 않았으면 M19를 먼저 연다. `qsh cp`와 `pair ssh` 항목은 ADR-0029·ADR-0044 착지 뒤에 열린다. 서명 스텝의 실서명은 사람 몫(인증서와 시크릿, §5.5)이 준비되어야 돈다. 그 전까지는 게이트가 경고와 함께 건너뛴다.
- **명시적 out:** host 역할 전부(M20): ConPTY 백엔드, PTY 세션, `setup host`, `pair invite`, `pair ssh-respond`, host 쪽 `cp`. MSI 설치 관리자는 macOS·Linux도 OS 패키지를 만들지 않으므로 만들지 않는다.
- **수용 기준 (DoD):**
  - `ci.yml`의 `windows-latest` leg이 Windows `qsh listen` ← Windows `qsh serve --to`의 실제 CLI로 역방향 종단(`exec`, 터널 echo, `hosts`의 reverse 항목, 데몬 재시작 뒤 재등록)을 돌고, ConPTY probe로 콘솔 계층(raw 입력, resize 폴링, 모드 복원, 초대 코드 에코 부재)을 단언한다.
  - identity 키, `resume.json`, `trust.toml`, audit 로그, `stateless_reset.key`가 소유자 전용 DACL로 만들어짐을 Windows leg 테스트가 단언한다. DACL을 설정할 수 없으면 파일을 만들지 않고 fail closed한다.
  - named pipe localctl이 이름 선점 시 기동 실패, 보호 DACL, 주입한 SID 불일치 거부(서버·클라이언트)를 Windows leg 테스트로 단언한다.
  - Windows 작업 정의가 `docs/deploy/service.md` Windows 절의 펜스와 바이트 단위로 같고, `logon_task_session_scoped`의 세 경우를 가짜 COM 주입 테스트가 고정한다.
  - `exit_code_matrix.rs`에서 client 쪽과 서비스 명령에 Windows 전용 `UNSUPPORTED` 행이 없다.
  - `release.yml`의 Windows leg이 Authenticode 서명 뒤 `signtool verify`·`Get-AuthenticodeSignature`로 상태·주체·타임스탬프를 검증하고, zip의 `man/`이 `docs/man/`과 같음을 대조한다. scoop·winget job이 `homebrew-tap`과 같은 게이트로 돈다. (2026-10-19 사용자 결정으로 Authenticode 서명과 그 검증, scoop·winget job은 철회됐다. ADR-0035 개정 이력. zip의 `man/` 대조는 그대로다.)
  - `docs/design/threat-model.md` §3에 Windows 콘솔 입력, named pipe, 작업 정의 진입점이, §4에 pipe 선점·다른 사용자 접속 위협이 오른다.
  - CI가 볼 수 없는 회차(실제 터미널 렌더링, 두 장비 사이 역방향, 절전 복귀, 둘째 계정 거부, 로그온 작업과 상시 기동 변형의 수명, Windows OpenSSH Server 상대 `pair ssh`, Credential Manager, Windows on ARM, SmartScreen과 세 설치 경로)를 사람이 확인하는 캠페인 문서 `docs/campaigns/p1-windows.md`가 사전 고정돼 커밋된다. 회차는 §5.5.
  - README Known limitations·설치 절과 §3 가드레일 표의 Windows 행이 새 범위와 일치한다.
  - ADR-0032 Windows 열(작업 스케줄러 argv와 실행 상태 질의)의 핀 테스트가 Windows leg에서 초록이고, `qsh identity move-key`가 Credential Manager와 파일 store 사이를 왕복해도 fingerprint가 바뀌지 않음을 Windows leg 테스트가 고정한다(ADR-0032 결정 10·15, ADR-0035).
  - Windows client의 `qsh cp`는 드라이브 문자 operand와 로컬 쓰기 규칙을 단위·통합 테스트가 고정한다. Windows host 상대 `cp` 종단은 Windows host의 파일 op와 함께 M20 DoD가 맡는다(ADR-0029 결정 23, ADR-0035 결정 26).
  - M16·M17이 넘긴 Windows 쌍둥이(위 범위 문장의 목록)가 Windows leg에서 초록이다.
  - 안정성: M19가 더한 타이밍 민감 테스트는 Linux와 Windows 각각에서 부하 아래 50회 연속 초록(`scripts/stress/run.sh`, `scripts/stress/m19.filter`).
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 7.7~12.9ew(ADR-0035 세 번째 개정 2026-10-13). 비교 표본이 없어 신뢰도가 낮다. 첫 스텝은 콘솔 probe·터미널 trait 추출과 `cfg(unix)` 게이트 제거이고, 그 뒤 다시 매긴다.
- **마감 노트 (2026-10-18):** 전 DoD 충족. 터미널 trait과 콘솔 계층 `e385279`·`bafc604`, 소유자 전용 DACL `e5ee456`, Credential Manager `7faad6c`, named pipe localctl `21dbb48`, Windows reverse와 정방향·역방향 종단 `fd4ac19`, 절전 감지·supervise·신뢰 철회·세션 필터 쌍둥이 `fced1a8`, client 기능 동등(대화형 attach, `-D`, `qsh cp` client, 자동 부트스트랩, `pair ssh --reverse`, doctor, `release_smoke`) `1d413e1`, 작업 스케줄러 서비스 백엔드 `8c5ef13`, ADR-0032 Windows 열 `357fd58`, aarch64 자산·`install.ps1`·Authenticode 서명 검증 `c1c860d`, 캠페인 문서 `ad409e0`, scoop·winget job `784f93b`, 마감 절차 1·2 `04abb92`. 보정은 `2590967`·`f5a75d7`·`d1ff674`(cargo deny의 zbus 5 계열 unmaintained 권고 예외). CI run 38983382108(acceptance 포함) 초록. 부하 아래 `scripts/stress/m19.filter`는 Linux(Dave-Windows-WSL 8 vCPU) 93개 50/50, Windows(Dave-Windows) 130개 중 qsh-cli `it` 62개만 49/50이고 나머지는 50/50이다. 떨어진 한 번(1회차의 `auto_bootstrap_keeps_the_console_cooked_until_ssh_exits_on_windows`)은 그 테스트만 다시 50회 돌려 50/50이었다. `e385279^..357fd58`의 wire(`crates/qsh-proto/proto`, `wire.rs`, `local.rs`)와 `capabilities.json` diff는 0이고 새 `ErrorCode`도 없다. `exit_code_matrix.rs`의 client 쪽과 서비스 명령에는 Windows 전용 `UNSUPPORTED` 행이 없다. 남은 Windows 행은 host 쪽 `session open`과 `cp` 두 행(Windows host가 `file.v1`을 광고하지 않아 생김)이고 M20 DoD가 받는다. 결정 4 실측으로 실행 중인 작업은 `/Create`만 받는다. `Password` 주체 작업의 Credential Manager 읽기는 잴 수 없어 `keystore_session_bound`를 보수적으로 낸다(ADR-0032 2026-10-17 두 번째 개정). DoD 6의 실서명 run과 scoop·winget 실제 갱신은 2026-10-19 사용자 결정으로 서명과 두 패키지 관리자가 철회되어 없어졌다(ADR-0035 개정 이력). M19가 만든 §5.5 사람 몫은 `p1-windows` 회차(사전 고정 `ad409e0`)와 서명·배포 준비 두 행이다. 계획 원문은 `d853388`.

### M20 — Windows host ✅ 완료 (2026-10-18)

- **범위:** PRD P1의 Windows host. 정방향 `qsh serve`와 역방향 `qsh serve --to`의 PTY 세션을 ConPTY 백엔드로 연다(Job Object로 트리 종료, 사용자 환경 블록과 고정 키, `COMSPEC` 기본 셸, `user@` 비교). 세션 신호 일곱을 Windows 사건으로 사상한다(`CTRL_C`/`CTRL_BREAK`/`CTRL_CLOSE`, `TerminateJobObject`, `Usr1`·`Usr2` 세션 이벤트). host 쪽 `exec`의 Job Object와 환경 고정, audit writer 잠금·재검증, `acl.toml` DACL 경고, `setup host`, `pair invite`, `pair ssh-respond`(ADR-0044), host 쪽 `qsh cp`(ADR-0029)도 이 마일스톤이다.
- **착수 조건:** M19 닫힘. `qsh cp`와 `pair ssh-respond`는 ADR-0029·ADR-0044 착지 뒤에 열린다.
- **명시적 out:** 없음. 사용자 전환과 utmp 기록은 unix에도 없으므로 같은 선이다.
- **수용 기준 (DoD):**
  - `pty/tests.rs`의 Windows 쌍둥이가 spawn·resize·종료 코드·Job Object 트리 종료·신호 일곱의 사상과 escalation·환경 고정을 단언한다.
  - `ci.yml`의 `windows-latest` leg이 같은 러너에서 정방향(`qsh serve` ← `qsh`)과 역방향(`qsh listen` ← `qsh serve --to`)을 같은 케이스 목록으로 돈다: `exec`, 터널 echo, ConPTY 안의 대화형 attach와 detach 뒤 resume, Windows host 상대 `qsh cp`(M19 DoD에서 옮겨 옴).
  - `release_smoke`의 `#[cfg(not(unix))]` 쌍둥이가 PTY 축을 포함해 unix 쪽과 같은 축으로 넓어진다.
  - `exit_code_matrix.rs`에 Windows 전용 `UNSUPPORTED` 행이 하나도 없고, `session close --signal`의 허용 값 일곱이 Windows host에서 exit `0`인 행이 있다(ADR-0035 결정 3).
  - threat model의 PTY 행에 ConPTY와 Job Object가, E에 `acl.toml` DACL 경고가 오른다.
  - 캠페인 문서에 host 회차(Linux·macOS client → Windows host, Windows target의 역방향, Windows OpenSSH Server 상대 `pair ssh`)가 더해져 다시 고정된다.
  - 안정성: M20이 더한 타이밍 민감 테스트는 Linux와 Windows 각각에서 부하 아래 50회 연속 초록(`scripts/stress/run.sh`, `scripts/stress/m20.filter`).
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 3.6~6.3ew. ConPTY 백엔드(1.2~2.0)가 가장 불확실하므로 첫 스텝은 ConPTY 시제품이고, 그 뒤 다시 매긴다.
- **마감 노트 (2026-10-18):** 전 DoD 충족. ConPTY 시제품 `d538468`(overlapped named pipe 배치, `JOB_LIST`), ConPTY 백엔드와 PTY 세션의 두 route `bd4b272`, 세션 신호 일곱과 `qsh internal console-ctrl`·`QSH_SIGNAL_EVENT_USR1`·`USR2` `a475f08`, host `exec`의 Job Object `038f74e`, audit sidecar `LockFileEx`·`FileIdInfo`·`acl.toml` DACL 경고 `8598bb9`, host 파일 op와 `file.v1` 광고 `3f2c0d6`(CI 보정 `c7d9b78`), `setup host`·`pair invite` `34bb7ac`, Windows 응답자 `7fbd9d0`, 캠페인 host 회차 재고정 `048df57`, 실제 ConPTY host 상대 PTY 종단·`release_smoke` PTY 축·`cfg(unix)` 쌍둥이 전수 `e39c15c`, 마감 절차 1·2 `4f32462`. CI run 39118529274(acceptance 포함)·load 39118529239·fuzz-smoke 39118529234 초록. 부하 아래 `scripts/stress/m20.filter`는 Linux(Dave-Windows-WSL 8 vCPU) 29개 50/50, Windows(Dave-Windows)는 스텝마다 더한 테스트를 50회씩 돌려 모두 50/50(합 221개)이다. `d538468^..e39c15c`의 `crates/qsh-proto/proto`, `local.rs`, `capabilities.json` diff는 0이고 `wire.rs`는 `LOCAL_CAPABILITIES` 통합(Windows 빌드도 `file.v1` 광고)뿐이며 새 `ErrorCode`는 없다. `exit_code_matrix.rs`의 Windows 갈래는 `--signal` 일곱 값이 exit `0`인 `cfg(windows)` 블록 하나다. M10 결정 기록 Q1의 Windows release 스모크 축(PTY·detach/attach 제외)은 M20이 PTY 축을 더해 unix 쪽과 같아졌다(`release_smoke_covers_init_trust_exec_doctor_tunnel_and_a_pty_session_on_windows`). 착지 형태의 편차는 ADR-0035 개정 이력 2026-10-18 줄들(결정 5·17·20~26)과 ADR-0044 개정 이력 2026-10-18 줄이 적는다. 고친 결함 둘: Windows client가 Windows host 세션에 붙으면 host 의사 콘솔의 win32 input mode 요청이 로컬 콘솔에 닿아 줄 첫머리 `~d`가 듣지 않던 것(`tui/vt_filter.rs`), 둘째 Ctrl-C가 리스너 없는 틈에 오면 `STATUS_CONTROL_C_EXIT`로 끝나던 것. 역방향 route에서 client 콘솔을 닫아도 writer lease가 데몬 연결에 남는 것은 모든 OS에 같은 `docs/CLI.md` §6.13 계약이다. 마감 커밋 `258e0bb`의 CI에서 `trust_withdrawal::listen::listen_closes_a_withdrawn_peer_that_stopped_reading_the_control_stream`이 한 번 8초 안에 닫히지 않았고 재실행(run 39135082029)은 초록이며, 부하 아래 50/50으로 재현되지 않아 `PLAN.md` §1에 열어 뒀다. 2026-10-19 `448d69a`가 테스트 쪽 원인(흐름에 막힌 peer가 닫힘 패킷 한 장을 놓치면 keep-alive 15초까지 모름)을 고쳐 닫았다. M20이 만든 §5.5 사람 몫은 `p1-windows` host 회차 W2·W3b·W7(재고정 `048df57`)이다. 계획 원문은 `addffb5`.

### 5.2 P1 크기 합

| 마일스톤 | 크기(ew) | 상태 / 착수 조건 |
|---|---|---|
| M11 이슈 후속과 ACL 가시성 | 2.8~4.1 | 완료 |
| M12 이슈 설계 ADR 구현 | 5.1~6.1 | 완료 |
| M13 측정·배포 기반 | 3.1~6.1 | 완료 |
| M14 TCP/TLS fallback | 1.0~1.8 | 철회(ADR-0043). (a)만 착지 |
| M15 역할 기반 권한과 scp 호환 파일 복사 | 7.0~10.5 | ADR-0045·0029 승인됨 2026-10-14, M13 (b) 충족 |
| M16 SSH 부트스트랩과 신뢰 철회 | 3.6~5.6 | 완료 2026-10-15. 0015·0016·0030은 기각 |
| M17 운영 표면 | 3.3~4.9 | 완료 2026-10-16 |
| M18 세션 거처 | 4.4~8.6 + 미산정 하나 | M8 DoD 3 기록, ADR-0034 승인. 2026-10-16 건넘(§5.1 원칙 6) |
| M19 Windows client | 7.7~12.9 | 완료 2026-10-18 |
| M20 Windows host | 3.6~6.3 | 완료 2026-10-18 |
| 합 | 약 41~67 + 미산정 하나 | |

### 5.3 P1 밖으로 보낸다

| 항목 | 이유 |
|---|---|
| SOCKS `-D` | 이미 M9에서 출고했다(ADR-0019·0020, `socks_curl`) |
| `Host.lost_at`(ADR-0022 baseline) | `46cfda8`로 이미 착지했다 |
| `qsh.event/v1`의 `reverse.*` type(ADR-0022 결정 3) | 착수 조건인 관측 트리거(폴링이 놓치는 전이 보고, stderr를 읽을 수 없는 배치)가 아직 없다. 트리거가 관측되면 그때 열린 마일스톤에 이 문서 개정으로 넣는다 |
| 옛 계획·ADR 줄 번호 인용의 일괄 정리 | M10 결정 기록 Q6이 부채로 남기고 새 인용을 만들지 않기로 했다. 코드 주석이 대부분이라 파일을 만질 때 국소로 고친다 |
| H3 소켓만 넘기는 handoff | `docs/design/reexec-estimate.md` §4가 기각했다. H1b가 같은 값을 더 싸게 낸다 |
| `HOST_NOT_FOUND` 구제 문면의 `qsh reverse <controller>` 교체 | 문면이 append-only golden fixture 다섯(`error.HOST_NOT_FOUND.{unconfigured,pinned_no_address,exec_pinned_no_address,reverse_stale,exec_reverse_stale}.json`)에 들어 있어 고치면 fixture 편집이 된다. 숨김 alias는 v1 내내 동작하므로(ADR-0012) 안내가 틀린 것은 아니다. `qsh.cli/v2` 또는 fixture 규칙 예외를 정하는 ADR이 설 때 다시 연다 |
| `qsh acl grant`/`revoke`, 원격 ACL 미리보기 | ADR-0025가 기각했다(결정 1, 결정 4) |
| 암호화된 SSH 키, ssh-agent, OS keychain에서 가져오기, RSA/ECDSA | ADR-0026이 별도 결정으로 분리했다. 새 ADR 없이는 열지 않는다. ADR-0044 부트스트랩은 시스템 ssh를 부르므로 이런 키로도 qsh 신뢰를 세울 수 있지만, 그 키를 qsh identity로 가져오는 것은 여전히 열지 않는다 |
| `SessionSignal`(wire 예약 번호 25) | `v1.proto` 주석이 P1로 적었지만 PRD P1 목록에 없고 요구가 관측된 적 없다. 번호는 예약된 채 남고 `docs/design/protocol.md` §16.4가 채우는 것을 허용 변경으로 두므로 나중에 여는 비용이 낮다 |
| `-L`의 non-loopback bind | `crates/qsh-core/src/tunnel/local.rs` 모듈 doc이 "필요 시 P1"로 적었다. 로컬 bind를 넓히는 것은 이 장비의 다른 사용자와 LAN에 진입점을 여는 일이라 기본 거부를 둔다. 요구가 오면 ADR로 연다 |
| qsh 자체 데몬화 | `docs/CLI.md` §6.12가 foreground 전용을 계약으로 두고 서비스 유닛(M9)과 M17 (a)가 상시 기동을 맡는다 |
| `.pkg` 배포 형식 | M10 결정 기록 Q2가 tar.gz와 공증으로 정했다 |
| `-W` | 기각했다(ADR-0011 결과 절 2026-09-25 추기) |
| UDP forwarding | PRD P1 목록에 없다(M4 명시적 out) |
| relay | PRD §14 별도 제품. §3 가드레일대로 `--relay` stub도 없다 |
| TCP/TLS fallback | ADR-0043이 철회했다(2026-10-11). M14 (a)의 transport facade만 남았다 |
| DNS-over-HTTPS 강제 모드(이슈 #8) | ADR-0039가 P2 후보로 두었다. PRD §4·§12와 `docs/design/threat-model.md` §9의 web PKI 비목표를 먼저 고쳐야 연다. 그때까지는 IP 리터럴 주소가 DNS를 거치지 않는 우회다 |
| ECH(이슈 #9) | ADR-0040 결정 3이 착수 조건을 정했다. rustls 정식 릴리스에 서버 쪽 ECH가 들어오고 quinn 0.11이 그 설정을 막지 않음을 테스트로 확인해야 연다. 2026-10-01 기준 rustls 0.23.45와 0.24.0-dev.1 모두 클라이언트 쪽만 있다. hostname SNI를 보내지 않는 결정 2는 M13에서 구현했다 |
| P2 전부 | local echo prediction, read-only multi-attach, jump chaining, agent forwarding(`docs/PRD.md` §7 P2) |
| pin 방향 축, listener 초대 pairing, CSR 다대 CA 서명, QR pairing, revocation 목록·rotation 문서·`trust rotate`, mobile client SDK | 2026-10-12 사용자 결정으로 폐기했다(ADR-0030·0015·0016 기각, ADR-0031 축소). 1인·소수 장비 사용에 가치가 낮고, 장비 신뢰 부트스트랩은 SSH 부트스트랩(ADR-0044)이 맡는다. mobile은 Rust client cross-compile로 충분하다 |
| P0 사람 회차 일곱 | P0 완료 선언의 조건이고 `PLAN.md`가 사람 몫으로 추적한다. P1 마일스톤이 아니다. M8 DoD 3은 M18의 착수 조건으로, M9 DoD 1은 `qsh setup` 캠페인의 비교 기준으로만 인용한다 |

### 5.4 P1 일정 리스크

1. **사용자 승인.** 착수 ADR 여섯(0029, 0031~0033, 0035, 0044, 0045)은 2026-10-14 모두 승인됐다. 남은 것은 조건부 하나(0034, M18)다. 대응: 마일스톤마다 ADR 초안을 첫 스텝으로 두고, 승인을 기다리는 동안 순서상 다음 마일스톤의 ADR 없는 스텝을 연다.
2. **SC7 범위가 P1 표면만큼 넓어진다.** M8 DoD 4의 독립 검증 계약이 아직 없는데 P1은 wire 필드(H2), 새 op(M15)를 더한다. 대응: freeze 발효 전에는 `docs/design/protocol.md` §16.1 목록을, 발효 뒤에는 §16.4 규칙을 같은 커밋에서 지키고, threat model 행을 각 마일스톤 DoD에 넣었다.
3. (해소) TCP 경로의 PTY 우선순위. ADR-0043이 TCP fallback을 철회해 위험이 사라졌다. 번호는 인용 때문에 남긴다.
4. **M18의 echo 회귀와 IPC 보안.** H5는 대화형 echo가 로컬 IPC를 한 번 더 지나고 resume token custody(ADR-0007)와 부딪힐 수 있다. 대응: ADR-0034가 세 후보를 같은 표로 비교하고, 기존 echo 예산을 고치지 않는 것과 소켓 권한 모델을 DoD로 둔다.
5. **Windows 산정 신뢰도.** 비교 표본이 없다. 대응: M19(client)와 M20(host)으로 나누고, 각 첫 스텝(M19 콘솔 probe·게이트 제거, M20 ConPTY 시제품) 뒤 다시 매겨 이 절에 적는다. M20 ConPTY 시제품(`d538468`, 2026-10-18)은 overlapped named pipe 배치가 첫 시도에 서서 읽기 스레드 대체 비용이 들지 않았고, M20 크기 3.6~6.3ew를 그대로 둔다. 남은 불확실성은 Server 2022 러너의 `JOB_LIST`와 신호 사건 실측(ADR-0035 결정 22)이다.
6. **P1 사람 몫이 쌓인다.** §5.5의 회차는 마일스톤을 막지 않지만 P1 완료 선언을 막는다. 대응: 캠페인 문서를 해당 마일스톤 DoD에서 사전 고정해 사람이 언제든 돌릴 수 있게 한다.

### 5.5 P1 사람 몫

마일스톤 DoD에 들지 않는다. P1 완료를 선언할 때의 조건이다.

| 항목 | 사전 고정 문서 | 만드는 마일스톤 | 선행 / 상태 |
|---|---|---|---|
| `qsh setup` 경로 SC1 스톱워치 3회 | `docs/campaigns/p1-setup-stopwatch.md`(사전 고정 `43da2fb`) | M12 (b) | 같은 날 같은 진행자의 m9 3회. M9 DoD 1 공식 회차가 그날 있으면 재사용(ADR-0024 결정 12). M15 Step 7(ADR-0045 `--peer-role`) 이후 트리는 ACL 단계가 `done`으로 끝나는 절차를 잰다. 회차 미실행 |
| supervised tunnel 절전·망 전환 회차 넷 | `docs/campaigns/p1-supervise-wake.md`(사전 고정 `ab05a27`) | M12 (a) | 첫 단위가 담긴 태그. 넷째 회차(`serve --to` 재등록과 hub의 supervised reverse route)는 둘째 단위가 담긴 태그(ADR-0023 결과 절). 회차 미실행 |
| `cause` 분포 관측 기록 | 이슈 #10 본문과 2026-10-04T14:48Z 코멘트 | M11 (a) 빌드 | 기록됨, M13 (k) 착지 |
| `aarch64-unknown-linux-musl` 구형 glibc 판정 | `docs/campaigns/p1-aarch64-musl.md` | M13 (c) | PASS (2026-10-09 회차 1, v0.4.3, Debian 10 arm64 glibc 2.28, 에이전트가 네이티브 arm64 컨테이너에서 실행). 컨테이너를 회차로 센 판단은 m10-clean-vm과 같고 사람이 다시 볼 항목 |
| 새 파서 fuzz 타깃의 누적 72시간 | `docs/campaigns/m8-fuzz.md` 형식 | M11 (c) SSH 키 파서, M15의 새 decode 타깃 `decode_file_frame`, M16 (a) `parse_ssh_bootstrap_line`(`aba7bd6`, smoke 20,000 runs만) | 공개 beta 전(`docs/design/protocol.md` §13). 열림 |
| SSH 부트스트랩 실제 OpenSSH 회차(ProxyJump, ssh-agent, 암호 걸린 키, `--reverse` 한 회) | `docs/campaigns/p1-ssh-bootstrap.md`(사전 고정 `e8cd7a3`) | M16 (a) | M16 (a)가 담긴 태그(`7c43332` 이후). 열림, 회차 0 |
| Windows client·host 확인 | `docs/campaigns/p1-windows.md`(M19 사전 고정 `ad409e0`, M20이 host 회차 W2·W3b·W7을 더해 다시 고정 `048df57`, 서명 철회로 W11을 회차 전 재고정 `b25b843`, scoop·winget 철회로 W11을 cargo 변형으로 재고정 `e35f7c7`) | M19·M20 | Windows 자산이 붙은 태그 |
| Windows 배포 준비 | ADR-0035 결정 16 | M19 | 2026-10-19 사용자 결정으로 서명·scoop·winget을 철회해 닫힘. 설치 경로는 release zip, `install.ps1`, `cargo install --locked --git` |
