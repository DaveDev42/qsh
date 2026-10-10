# QSH 로드맵

**상태:** 확정. 구현과 어긋나는 내용을 발견하면 이 문서를 먼저 갱신한다. 개정 기록은 git 이력에 있다.

**현재 위치:** P1을 열었다(2026-09-26 사용자 결정). M11~M13은 닫혔고 M14(TCP/TLS fallback)는 2026-10-11 철회했다(ADR-0043, (a) transport facade만 남김). 남은 마일스톤의 착수 ADR은 2026-10-11 전부 `제안됨`으로 올라 사용자 승인을 기다린다. M15 ADR-0029, M16 ADR-0030·0031·0016(0015는 0030 승인 뒤), M17 ADR-0032·0033, M19 ADR-0035다. ADR이 필요 없는 M17 (b) README 재작성은 착지했다(`2fc879b`). M17 (c)는 P1 안에 QR 소비자가 없다고 확인했고 PRD §17 문장을 P2로 옮기는 개정이 사용자 결정을 기다린다. M18은 M8 DoD 3이 기록돼야 열린다(§5.1 원칙 6). 승인 전까지 에이전트가 더 할 P1 일은 없고 `PLAN.md`는 사람 몫을 추적하는 자리표시자다. P0 MVP 완료 선언은 아직이다. 에이전트 몫은 전부 착지했고 사람 회차 일곱이 닫힐 때 선언한다(아래 "P0 MVP 완료 선언의 조건"). P1이 만든 사람 몫은 §5.5에 있다.

이 문서는 P0 MVP(M0~M10)와 P1(M11~M19)의 canonical 마일스톤 기록이다. P2(`docs/PRD.md` §7 P2 목록)는 다루지 않는다. 각 마일스톤의 "수용 기준"이 곧 완료 정의(Definition of Done)이고, 수용 기준을 통과하는 테스트나 시연 없이는 마일스톤을 닫지 않는다. SC 번호는 PRD §15 성공 기준의 순번이다(SC1: 신규 두 장비 5분 내 연결, SC2: 한 명령 접속, SC3: 네트워크 전환 ≥95% 유지/resume, SC4: resume 가능한 단절에서 output 무손실, SC5: client crash가 remote PTY를 죽이지 않음, SC6: 모든 privileged op의 ACL 추적성, SC7: 공개 beta 전 독립 보안 리뷰).

닫힌 마일스톤의 절은 범위, 결과, 열린 DoD, 코드·문서가 인용하는 번호(DoD 번호, 범위 글자, 결정 기록 Q)만 남겼다. 단계별 서술과 감사 경위는 git 이력에 있다. 지운 M2~M13판 계획의 원문은 커밋 해시로 인용한다(`docs/history/m<N>-plan.md`): M2~M6 `2473c88`, M7 `69dd788`, M8 `52639fc`, M9 `b9a621b`, M10 `98d62fe`, M11 `6ee63c3`, M12 `3acdb1a`, M13 `b70be6b`.

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

총 크기: P0는 약 31.5~32 engineer-weeks(1인 기준). P1은 약 31~49ew(추정)에, ADR이 서야 산정할 수 있는 다섯 항목(M16의 구현 셋, M17 (d)의 구현, M18의 보안 가산분)이 더해진다. 내역은 §5.2.

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
- **명시적 out:** TOFU(pin 방향 축 ADR 필요, M16 (a)), listener pairing(ADR-0015), CSR 기반 다대 CA 서명(ADR-0016), README 전면 재작성(M17 (b)).
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
| File copy (P1) | `file.read/write` action이 §9에 존재 | action만 정의, op 미등록, capabilities에 미광고. → M15 |
| Windows (P1 client / P2 host) | 외부 기여 PR | PTY 백엔드(`pty/posix.rs`)는 `#[cfg(unix)]`이고 비unix에서 `pty::factory()`가 `UnsupportedFactory`를 돌려준다. CI는 `windows-latest`에서 build/clippy/portable 테스트만 돌려 컴파일 회귀를 막는다. 지원 약속 아님. README Known limitations에 명시. → M19 / P2 |
| Multi-attach read-only (P2) | broker에서 거의 공짜로 나옴, 그래서 위험 | 관찰자(observer) 개념 자체를 만들지 않는다. writer lease는 P0 필수이고 두 번째 attach 정책은 lease 규칙만 따른다 |
| Local echo prediction (P2) | mosh 대비 지연 불평 | P0는 실제 PTY 지연을 측정·공개해 데이터로 대화한다(§13의 10ms 예산) |
| Relay (§14, 별도 제품) | "작은 relay 하나면" | P0 의무는 세션 identity와 transport 분리뿐(resume이 이미 강제). `--relay` flag는 stub조차 없다 |
| Forward-route live carrier·`-R` 자동 재발행 ([ADR-0018](adr/0018-tunnel-lifetime-bound-to-connection.md)로 종결) | 터널이 recovery 후에도 신규 연결을 서비스하길 기대 | v1 터널 수명은 connection에 결합되고 live carrier는 구현하지 않는다(M4가 `tunnel_chaos.rs`의 트랩으로 고정, README Known limitations가 고지). ADR-0023(2026-09-30 승인)이 명시적으로 켠 터널(`--supervise`)에 한해 ADR-0018 결정 2·3을 개정하고 결정 1은 유지한다. forward route의 `-L`/`-D`는 M12 첫 단위, reverse route와 `-R`은 둘째 단위로 착지했다 |
| Cert rotation UX (P1) | 만료 | P0: 만료 30일 전 doctor 경고만. → M16 |
| Service 설치 (M9로 승격, 2026-09-07) | 상시 실행 요구 | M9가 `qsh service install`을 구현했고 unit 예시는 `docs/deploy/service.md`. 서비스 매니저 실호출은 M17 (a) |
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
5. 신뢰의 방향을 정한 뒤 pairing을 넓힌다. pin 방향 축(ADR-0017 결정 5가 미룬 후속 ADR)이 listener pairing(ADR-0015)의 결정 하나를 좌우한다. `qsh setup`은 오늘 있는 pairing 경로만 조립하고, M16이 새 경로를 열면 ADR-0024 결정 2의 역할 표에 행을 더하는 식으로 뒤따른다.
6. 사람 회차는 마일스톤 DoD에 넣지 않는다. DoD는 캠페인 문서가 사전 고정돼 커밋되는 데까지다. 회차 기록은 §5.5에 모으고 P1 완료를 선언할 때의 조건으로 둔다. P0의 M7~M10은 회차를 DoD에 넣었기 때문에 "기능 완료 · DoD 잔여"로 멈춰 있다. 사람 회차를 착수 조건으로 거는 마일스톤은 M18 하나다(M8 DoD 3). 조건이 닫히지 않았으면 M18을 건너 M19를 먼저 열고, 건너뛴 사실을 이 절에 날짜와 함께 적는다.

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

### M15 — 스트리밍 파일 복사

- **범위:** PRD P1 목록의 streaming file copy. `file.read`/`file.write` action은 M5부터 어휘에만 있고 항상 deny다(§3 가드레일 표). 이 마일스톤이 op을 등록하고 항상-deny를 걷는다. 착수 ADR(ADR-0029)이 정할 것은 명령 이름과 모양, 청크·부분 전송·재개 여부, 무결성 확인, ACL resource 모델(경로를 resource로 쓸지와 소유 축), 경로 제약(symlink, 상위 경로 이탈, 덮어쓰기), 동시 전송 quota, audit 레코드의 필드 집합(경로와 크기를 싣는지), 역방향 route 지원 여부다.
  - 이 ADR이 반드시 담아야 하는 결정이 하나 있다. `file.write`는 `qsh serve`의 uid로 파일을 쓰고, 그 uid는 `acl.toml`, `trust.toml`, `invites.toml`, identity와 keystore, `resume.json`, audit 로그를 쓸 수 있다. `file.write`가 `acl.toml`에 닿으면 원격 peer가 ACL writer가 되어 ADR-0017 결정 1과 ADR-0025 결정 1이 닫은 자리를 원격 op이 우회한다. `trust.toml`은 더 나쁘다. `SharedTrustStore::lookup_pin`이 handshake마다 파일을 다시 읽으므로(`crates/qsh-core/src/trust/mod.rs`) 원격 쓰기 하나가 재시작 없이 새 pin을 심는다. audit 로그를 덮어쓰면 SC6 추적성이 지워진다. 그래서 qsh의 config·data·state·runtime 디렉터리(`docs/design/architecture.md` §7의 경로 전부, 곧 `config.toml`, `acl.toml`, `trust.toml`, `invites.toml`, `hosts.toml`, identity·keystore 파일, `resume.json`, audit 경로, localctl 소켓 디렉터리, M13 (f)의 reset key 파일)는 ACL 행과 무관하게 `file.read`/`file.write`의 대상에서 항상 거부한다. 판정은 symlink를 해석한 뒤의 정규 경로로 한다. 이 성질은 ACL 행으로 열 수 없어야 한다.
- **착수 조건:** ADR-0029 승인. M13 (b)의 역압 하네스가 선 뒤(충족).
- **명시적 out:** 디렉터리 동기화(rsync류), UDP forwarding, 원격 파일 브라우징.
- **수용 기준 (DoD):**
  - 큰 파일 왕복이 해시 기준으로 byte-identical이다. forward route와(ADR이 포함하면) reverse route 모두에서다(transport는 QUIC 하나, ADR-0043).
  - 행이 없으면 deny다. 새 두 seam이 `DENY_SEAMS`에 행으로 오르고 `acl_uniformity.rs`가 문면 균일성을 단언한다. `acl_registry.rs`의 항상-deny 예외 목록에서 `file.read`/`file.write`가 빠지고 `forward.socks`만 남는다. `acl_check_equivalence.rs` 표에 두 action 행이 더해진다.
  - `allow = ["file.*"]` 행이 있어도 qsh 자신의 상태 경로에 대한 `file.read`/`file.write`가 `PERMISSION_DENIED`이고 파일 바이트가 그대로임을 핀 테스트가 단언한다. 적어도 `acl.toml`, `trust.toml`, identity 파일, audit 로그를 덮고, 그 경로를 가리키는 symlink와 `..`로 이탈하는 경로 두 우회도 같은 결과임을 단언한다.
  - 인가 전 자원 생성이 없다. deny된 `file.write` 뒤 목적지와 그 디렉터리에 새 파일·임시 파일이 없고 기존 파일은 바이트 단위로 같다.
  - 동시 전송 quota가 ADR-0010의 모양으로 인가 뒤·열기 전에 결정되고, `crates/qsh-core/tests/quota_registry.rs`에 행이 오르며 `quota_docs.rs`가 문서의 거부 범주와 기본값을 확인한다.
  - audit 레코드의 필드 집합이 ADR-0029가 고정한 대로이고, 파일 내용 바이트가 어떤 필드에도 들어갈 수 없음을 `record_has_only_structural_fields`(`crates/qsh-core/src/audit/tests.rs`)와 같은 형식의 테스트가 고정한다.
  - 파일 복사와 PTY echo를 동시에 돌린 상태에서 M13 (b) 하네스가 같은 예산으로 초록이다.
  - 신규 op마다 fixture 등재와 등록 완전성(`layer_2_every_schema_command_has_all_six_faces`), `capabilities.json` golden 재생성, 새 wire op의 decode 경로가 fuzz 타깃에 걸림, freeze 발효 전이면 `docs/design/protocol.md` §16.1 목록 동시 갱신.
  - `docs/design/threat-model.md` §3에 파일 op 진입점이, §4 B에 상태 경로 쓰기·경로 이탈·덮어쓰기 위협 행이 핀 테스트와 함께 오른다.
  - 마일스톤 마감 공통 절차(§2) 1·2.
- **크기:** 2.7~4.0ew. ADR 0.3 + 구현 2.0~3.0(새 op 둘, 렌더러 두 벌, fixture, capabilities, 전송 프로토콜, ACL 전수 테스트 갱신. M9 크기 줄의 op 신설 항목 0.4~0.7ew에 스트리밍 설계를 얹은 배수) + 상태 경로 거부·인가 전 자원·quota·audit 테스트 0.3~0.5 / 마감 0.1~0.2.

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
  - (b) README 서사·구조 전면 재작성. M9는 측정 대상 문서(README "First run" 절)를 회차 전에 바꾸지 않으려고 이 일을 SC1 재측정 뒤로 미뤘다. M12 (b)가 M9 재측정의 대상 트리를 `docs/campaigns/m9-stopwatch.md` §8에 SHA로 고정하고 `qsh setup` 캠페인도 대상 트리를 고정하므로, 두 고정 뒤에는 재작성이 측정을 흔들지 않는다. M9 DoD 1 결과가 그때 기록돼 있으면 서사의 입력으로 쓴다. **착지 (2026-10-11):** `2fc879b`. First run 절차와 테스트가 고정한 문구는 그대로다.
  - (c) QR pairing. 근거는 PRD §17 확정된 결정의 "QR pairing은 P1이다"이고 PRD §7 P1 목록에는 없다. P1 안에서 QR을 읽을 소비자가 있는지부터 확인한다. mobile client SDK는 P2다. 소비자가 없으면 구현하지 않고, PRD §17의 그 확정 결정 문장을 P2로 옮기는 개정을 사용자에게 올린다. **확인 (2026-10-11):** P1 안에 소비자가 없다(M19는 콘솔 client이고 `pair accept` 프롬프트를 쓴다). 개정안: PRD §17의 "QR pairing은 P1이다"를 "QR pairing은 P2이다. 읽는 소비자가 mobile client SDK(P2)뿐이라 P1에서는 구현하지 않고, invite code를 QR로 인코딩하는 표시 계층은 그때 additive로 더한다"로 바꾸고 PRD §7 P2에 항목을 더하며 ADR-0002의 "P1 백로그" 줄을 맞춘다. 사용자 결정 대기.
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
- **크기:** 4.4~8.6ew + 보안 가산 미산정. (a) ADR 0.3~0.5(세 번째 후보 산정과 spool 재검토 포함) / (b) H4 4.2(4.0~4.8) 또는 H5 6.5(5.4~7.6), `docs/design/reexec-estimate.md` §3 표 / (c) 0~0.3 / 마감 0.1~0.2. `reexec-estimate.md` §5는 H4의 4.2ew에 스냅숏 통로 검증·스크럽 비용이 들어 있지 않고 H5에는 소켓 권한 모델을 다시 세우는 비용을 가산해야 한다고 적는다. 이 가산분은 ADR-0034가 채택안을 고른 뒤 매기고 이 절에 적는다. 세 번째 후보를 고르면 (b) 전체를 다시 매긴다.

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

| 마일스톤 | 크기(ew) | 상태 / 착수 조건 |
|---|---|---|
| M11 이슈 후속과 ACL 가시성 | 2.8~4.1 | 완료 |
| M12 이슈 설계 ADR 구현 | 5.1~6.1 | 완료 |
| M13 측정·배포 기반 | 3.1~6.1 | 완료 |
| M14 TCP/TLS fallback | 1.0~1.8 | 철회(ADR-0043). (a)만 착지 |
| M15 스트리밍 파일 복사 | 2.7~4.0 (ADR-0029 초안은 2.8~4.2) | ADR-0029 승인 (제안됨 2026-10-11, M13 (b)는 충족) |
| M16 신뢰의 방향과 수명 | 2.4~3.5 + 재산정 셋 | ADR 넷 승인. 0030·0031·0016 제안됨(2026-10-11), 0015는 0030 승인 뒤 |
| M17 운영 표면 | 1.3~2.5 + 미산정 하나 | (b) 착지, (c) 소비자 없음 확인. ADR-0032·0033 승인(제안됨 2026-10-11) |
| M18 세션 거처 | 4.4~8.6 + 미산정 하나 | M8 DoD 3 기록, ADR-0034 승인 |
| M19 Windows client | 4.7~7.0 (ADR-0035 초안은 4.3~6.9) | ADR-0035 승인 (제안됨 2026-10-11) |
| 합 | 약 28~44 + 미산정 다섯 | |

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
| 암호화된 SSH 키, ssh-agent, OS keychain에서 가져오기, RSA/ECDSA | ADR-0026이 별도 결정으로 분리했다. 새 ADR 없이는 열지 않는다 |
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
| P2 전부 | local echo prediction, read-only multi-attach, jump chaining, agent forwarding, Windows host, mobile client SDK(`docs/PRD.md` §7 P2) |
| P0 사람 회차 일곱 | P0 완료 선언의 조건이고 `PLAN.md`가 사람 몫으로 추적한다. P1 마일스톤이 아니다. M8 DoD 3은 M18의 착수 조건으로, M9 DoD 1은 `qsh setup` 캠페인의 비교 기준으로만 인용한다 |

### 5.4 P1 일정 리스크

1. **사용자 승인.** 승인이 필요한 ADR이 남아 있다. 예약 ADR 둘의 결정 절(0015, 0016), 새 ADR 일곱(0029~0035), 조건부 하나(ADR-0014 결정 7 개정). 대응: 마일스톤마다 ADR 초안을 첫 스텝으로 두고, 승인을 기다리는 동안 순서상 다음 마일스톤의 ADR 없는 스텝을 연다.
2. **SC7 범위가 P1 표면만큼 넓어진다.** M8 DoD 4의 독립 검증 계약이 아직 없는데 P1은 wire 필드(H2), 새 op(M15)를 더한다. 대응: freeze 발효 전에는 `docs/design/protocol.md` §16.1 목록을, 발효 뒤에는 §16.4 규칙을 같은 커밋에서 지키고, threat model 행을 각 마일스톤 DoD에 넣었다.
3. (해소) TCP 경로의 PTY 우선순위. ADR-0043이 TCP fallback을 철회해 위험이 사라졌다. 번호는 인용 때문에 남긴다.
4. **M18의 echo 회귀와 IPC 보안.** H5는 대화형 echo가 로컬 IPC를 한 번 더 지나고 resume token custody(ADR-0007)와 부딪힐 수 있다. 대응: ADR-0034가 세 후보를 같은 표로 비교하고, 기존 echo 예산을 고치지 않는 것과 소켓 권한 모델을 DoD로 둔다.
5. **Windows 산정 신뢰도.** 비교 표본이 없다. 대응: ADR-0035가 명령 집합을 좁히고, 첫 스텝 뒤 다시 매겨 이 절에 적는다.
6. **P1 사람 몫이 쌓인다.** §5.5의 회차는 마일스톤을 막지 않지만 P1 완료 선언을 막는다. 대응: 캠페인 문서를 해당 마일스톤 DoD에서 사전 고정해 사람이 언제든 돌릴 수 있게 한다.

### 5.5 P1 사람 몫

마일스톤 DoD에 들지 않는다. P1 완료를 선언할 때의 조건이다.

| 항목 | 사전 고정 문서 | 만드는 마일스톤 | 선행 / 상태 |
|---|---|---|---|
| `qsh setup` 경로 SC1 스톱워치 3회 | `docs/campaigns/p1-setup-stopwatch.md`(사전 고정 `43da2fb`) | M12 (b) | 같은 날 같은 진행자의 m9 3회. M9 DoD 1 공식 회차가 그날 있으면 재사용(ADR-0024 결정 12). 회차 미실행 |
| supervised tunnel 절전·망 전환 회차 넷 | `docs/campaigns/p1-supervise-wake.md`(사전 고정 `ab05a27`) | M12 (a) | 첫 단위가 담긴 태그. 넷째 회차(`serve --to` 재등록과 hub의 supervised reverse route)는 둘째 단위가 담긴 태그(ADR-0023 결과 절). 회차 미실행 |
| `cause` 분포 관측 기록 | 이슈 #10 본문과 2026-10-04T14:48Z 코멘트 | M11 (a) 빌드 | 기록됨, M13 (k) 착지 |
| `aarch64-unknown-linux-musl` 구형 glibc 판정 | `docs/campaigns/p1-aarch64-musl.md` | M13 (c) | PASS (2026-10-09 회차 1, v0.4.3, Debian 10 arm64 glibc 2.28, 에이전트가 네이티브 arm64 컨테이너에서 실행). 컨테이너를 회차로 센 판단은 m10-clean-vm과 같고 사람이 다시 볼 항목 |
| 새 파서 fuzz 타깃의 누적 72시간 | `docs/campaigns/m8-fuzz.md` 형식 | M11 (c) SSH 키 파서, M15의 새 decode 타깃 | 공개 beta 전(`docs/design/protocol.md` §13). 열림 |
| Windows 대화형 셸 확인 | M19의 캠페인 문서 | M19 | Windows 자산이 붙은 태그 |
