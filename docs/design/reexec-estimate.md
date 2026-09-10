# graceful re-exec(fd 보존 handoff) 비용 산정

**작성일:** 2026-09-10 (M8 stretch) · **기준 트리:** `2e9c3c9`

ROADMAP §4 리스크 4(`docs/ROADMAP.md:166`)가 M8 stretch로 요구한 산정이다. 구현 제안이 아니라 P1 결정의 입력이고, 코드는 읽기만 했다. 인용 없는 수치는 추정이다. 줄 번호 인용은 기준 트리 시점의 것이라 뒤 커밋에서 어긋날 수 있다.

## §1 문제 정의

종료 경로는 세션 정리를 목적으로 설계됐다. `Server::run`은 `drain()`을 먼저 돌리고 endpoint를 닫는다(`crates/qsh-core/src/server/mod.rs:2461-2469` — endpoint를 먼저 닫으면 `session.closed`를 실을 control stream이 끊긴다). `drain()`은 신규 open/attach를 거부한 뒤(`server/mod.rs:1307-1322`, `:1281-1293`) 세션마다 HUP→TERM→KILL을 돌리고(`broker/session.rs:1261-1300`), `close_all`이 id마다 `resume.forget`을 부른다(`broker/mod.rs:796-807`). 상태를 어떻게 보존하든 이 줄을 우회하지 않으면 재부착이 성립하지 않는다. detach하고 fd만 넘기는 분기는 없다.

정상 SIGTERM은 감지가 빠르다 — `session.closed` 뒤 CONNECTION_CLOSE가 나가는 순서는 코드로 고정돼 있다(`server/mod.rs:2461-2469`). 다만 깨끗함은 보장이 아니다: 전달은 `DRAIN_FLUSH_GRACE` 500ms 창에 얹혀 있고 drain 전체는 `DRAIN_TIMEOUT` 60초에서 포기하며(`:84`, `:107`, `:1309-1321`), 막힌 소비자 아래에서는 셸이 프로세스보다 오래 살 수 있다(`README.md:511-523`). `MAX_IDLE_TIMEOUT` 45초(`crates/qsh-transport/src/endpoint.rs:28`)는 크래시에만 해당한다. 결함은 감지 속도만이 아니라 셸·scrollback·터널이 전부 사라진다는 것. 재바인드도 상속을 전제하지 않는다(`SO_REUSEADDR`/`SO_REUSEPORT` 미설정, `endpoint.rs:468-494`).

재시작 후 서비스 복귀까지도 0이 아니다: exec + bind + `acl.toml`·identity 재로드가 걸리고, 플랫폼 키스토어를 쓰면 그 재로드는 blocking이다(`identity/mod.rs:170-174`, macOS 미서명 빌드는 Keychain 재프롬프트 가능 — `docs/ROADMAP.md:165`). §3 각 후보의 "단절 시간" 열이 이 항목까지 포함한다.

## §2 옮겨야 하는 상태

| 항목 | 성질 | 넘길 수 있나 | 못 넘기면 |
|---|---|---|---|
| PTY master fd | fd | 가능. CLOEXEC 해제 선행(`pty/posix.rs:181-183`,`:416`) | 셸이 죽는다. 리스크의 본체 |
| 자식 pid·pgid | 데이터+소유권 | 값은 가능, `waitpid` 소유권은 execve 제자리 교체에서만(pid 보존) | `ECHILD`로 exit를 영원히 모르고 both-null 보고(`pty/posix.rs:672-681`) |
| quinn 연결 상태 | 메모리 전용 | 불가. 직렬화 API 없음(`endpoint.rs:903-909`의 `quinn::Endpoint::new`가 받는 것은 config·소켓·runtime뿐이다) | 연결 전손. 모든 후보의 전제 |
| replay ring 바이트 | 메모리 전용(ADR-0004) | 포기 안전. `end: u64`만 시딩 | scrollback 전손 + `gap` 1회(`broker/ring.rs:430-436`) — 승인된 경로 |
| resume 4값(hash·peer·expires·stream) | 데이터+해시 | 가능. 평문 미보관이라 재발급 불필요(`broker/resume.rs:246-268`) | 재부착 불가 = 목적 소멸 |
| `applied_input` | 데이터 | 가능(`broker/session.rs:184`) | exactly-once가 경계에서 조용히 깨진다 |
| writer lease | 데이터 일부 | principal만. `conn`/`physical`은 프로세스-로컬(`broker/lease.rs:27-29`, `:53`·`:61`) | 원래 writer가 아닌 쪽이 lease를 먼저 집는다 |
| `TtlWindow` | 데이터, `Instant` 변환 | attached는 RAII라 정수로만(`broker/session.rs:200-235`,`:784-799`) | TTL 오작동. `ttl_base=now` 리셋으로 회피(안전 쪽 오차) |
| closed 세션 60초 창 | 데이터 | 포기 가능 | late reader가 `SESSION_NOT_FOUND`(`broker/mod.rs:59-64`) |
| 세션 수 쿼터 | 파생값 | 세션 재시딩에 따라옴(`broker/mod.rs:536-552`가 registry를 매번 순회해 센다, 별도 카운터 없음) | 없음 |
| admission rate 창 | 메모리 전용 | 재시딩 불필요 | throttle 소스가 한 창 free pass(`admission.rs:404-408`) |
| 채널·태스크·`Notify` | 메모리 전용 | 재생성 | 없음 |
| 터널·forward | 연결 결합 | 살릴 필요 없음(ADR-0018) | 다시 열어야 한다. 오늘도 같다 |
| `exec.run` | 연결 결합 | 살릴 필요 없음(`server/mod.rs:2286-2299`의 `purge_connection`이 ticket·`ExecPermit`을 회수) | 다시 열어야 한다. 오늘도 같다 |
| identity·ACL·audit·config | 디스크 | 재로드 가능. 단 키 로드는 OS credential store에서 블록하고(`identity/mod.rs:170-174`) macOS 미서명 빌드에서는 재프롬프트 가능(`docs/ROADMAP.md:165`) | pin은 불변, 대신 handoff 창에 블로킹 로드 1회 |

## §3 접근 후보

| 후보 | 얻는 것 | 잃는 것 | 단절 시간 | 손대는 모듈 | ew | 플랫폼 | 리스크 |
|---|---|---|---|---|---|---|---|
| H0 고지만 | `qsh service install` 경로에서 crash-restart가 세션을 지운다는 사실을 만난다 | 세션은 죽는다 | 오늘과 동일(§1) | `deploy/service.md`, `CLI.md:768` | 0.1 | 무관 | 낮음 |
| H1 관측(drain 요약·doctor 1종·배너) | 무엇이 지워졌는지 로그·진단에 남는다 | 같음 | 오늘과 동일(§1) | `server/mod.rs`, `doctor.rs`, `ops/doctor.rs` | 0.25 (S4·S8이 같은 라운드로 열려 unit 검출을 재사용할 수 있으면 0.15 — 그 동시성이 깨지면 검출부터 새로 써서 0.25 상한, PANEL-A §H1) | unit 검출 2갈래 | remedy에 실행 가능한 다음 명령을 못 쓰면 M9 (i) 규율과 어긋난다 |
| H1b stateless reset key 고정 | crash·계획 재시작 모두에서 감지가 다음 패킷 1 RTT(오늘은 최대 45초, `endpoint.rs:28`), `Recovery::Failed` 분류에서 벗어난다 | 세션은 여전히 죽는다 | 다음 패킷(타이핑 즉시, idle이면 keep-alive 15초 이내, `endpoint.rs:26`) | `qsh-transport`의 `EndpointConfig`(오늘 `default()`, `endpoint.rs:904`)와 키 파생 1곳 | 0.2–0.3 | 무관 | 키 보관 위치 결정 1건, wire 변경 0, RFC 9000 §10.3 준수 |
| H2 인스턴스 식별값을 `Hello`에 additive | "TTL 만료"와 "호스트 재시작"을 클라이언트가 구별한다 | 같음 | 오늘과 동일(§1) | `wire/v1.proto`, `handshake.rs`, `resume.rs`, `client/reconnect.rs` | 0.3 | 없음 | freeze는 additive를 막지 않는다(protocol.md §16.4, `docs/ROADMAP.md:156`)고, 애초에 아직 발효 전이다(protocol.md:441 — 발효 조건은 `PLAN.md` §6.0 SC7 판정). 실비용은 두 개다 — 새 op의 decode 경로가 §13 fuzz 타깃에 걸리는지 확인(protocol.md:525), 발효 전이면 §16.1 동결 대상 목록을 같은 커밋에서 갱신. 값이 uptime을 누설하면 fingerprint 재료라는 항목은 그대로 남는다 |
| H3 소켓만 넘기고 연결 단절 | 재시작 창의 handshake가 포트 hole을 안 만난다. 같은 통로로 reset key를 넘기면 H1b와 같은 1 RTT 감지도 가능(quinn-proto `reset_key`) | H1b가 프로세스 경계 없이 같은 값을 0.2–0.3ew에 낸다 | 오늘과 동일(§1) | `endpoint.rs`, core 신규 모듈, 시그널, fd 상속 프로토콜 | 1.0 (0.8–1.2) | unix cfg | H1b 대비 잔여 값 없음 — 두 프로세스·fd 전달 프로토콜·반쪽 재exec 실패 모드만 추가된다. 문서 개정만이면 0.15–0.2ew |
| H4 execve 제자리 세션 handoff | PTY 자식·프로세스 트리·cwd·실행 중 작업, 세션 id, opener, dedup 축, resume 유효성 | scrollback, 화면 재도포, lease 바인딩, 터널, exec.run, TTL 정확도. crash 재시작은 못 덮는다 | 1 RTT — 단, execve 직전 `listener.close`로 CONNECTION_CLOSE를 명시 전송하고 `wait_idle`은 건너뛰는 것이 전제. 이 한 단계를 빼면 45초(`endpoint.rs:28`)이고 `REDIAL_DEADLINE` 2초 기준상 `Recovery::Failed`로 분류된다(`client/reconnect.rs:52-61`) | 신규 `handoff/`, `pty/posix.rs` adopt, `broker/*`, `server/mod.rs`, `serve.rs`, `quota.rs` | 4.2 (4.0–4.8) | unix 전용. Windows는 PTY 백엔드 부재(`pty/mod.rs:45-49`)로 이중 부채 | 멀티스레드 exec 선행조건(audit flush·blocking write·execv 실패 fallback, `pty/mod.rs:36-43`) 누락 시 재현 어려운 손실. 더 무겁게는: exec 성공 후의 실패는 롤백이 없다 — 구 이미지가 없으므로 bind 실패(특정 주소 `--bind`, `docs/CLI.md:761-765`)나 `acl.toml` 무효(같은 문서 §6.12: 뜨고 bind하지만 전건 deny)는 세션이 살아 있으나 아무도 붙을 수 없는 상태로 끝나고, 고치는 유일한 방법인 재시작이 그 세션을 죽인다. exec 전에 bind 가능성과 정책 유효성을 미리 검사하는 단계가 필수 항목이고, exec 창의 localctl 조회는 데몬 없음으로 보인다(`localctl/client.rs:1294-1302`) |
| H5 supervisor 분리(ADR-0003 seam) | H4 전부 + scrollback(gap 없음) + closed 창 + crash 재시작도 덮는다 | 연결·터널·exec.run. supervisor 재시작은 여전히 전멸 | supervisor 생존 시 1 RTT, supervisor 재시작 시 H4와 같은 45초(동일 전제) | `SessionBackend`의 동기 잔여 메서드 async화(데이터 경로 `pull`/`write`/`resize` 계열은 이미 `BoxFuture` — `broker/mod.rs:921-925`가 IPC 교체를 이유로 적어 둔 그대로이고, 남은 것은 `open`/`get`/`attach`/`issue_resume` 계열 제어면), 호출 지점 20곳, 신규 `qsh.super.v1`+daemon, 방어선 재배치 | 6.5 (5.4–7.6) | unix cfg — Windows 부채 없음 | `handle_session_attach`(`server/mod.rs:1986-2192`)가 순서에 의존하는 관문 10여 개를 복합 op으로 접으며 protocol.md §10-2 비구별성을 깨기 쉽다. 대화형 echo가 UDS+protobuf를 추가 통과 → M4·M8 echo 예산 재협상 |

패널이 갈렸던 지점 하나는 판정된다. R2·R5는 두 프로세스 문제로 놓아 `waitpid` 소유권을 최대 비용으로 꼽았으나, `execve` 제자리 교체는 pid·pgid를 보존하므로 그 항목과 SCM_RIGHTS 프로토콜·`SO_REUSEPORT` 레이스가 함께 사라진다(POSIX 규약). 같은 이유로 H3은 H4의 선행 단계가 아니다 — execve는 CLOEXEC가 켜진 소켓을 커널이 닫게 두고 같은 프로세스 안에서 순차 재바인드한다(socket2가 Linux는 `SOCK_CLOEXEC`, macOS는 `fcntl(FD_CLOEXEC)`로 건다 — socket2 0.6.4 `src/socket.rs:747-761`, `:773-792`. `quinn::Endpoint::new` 이후까지 같은 fd로 남는지는 미확인 — 재바인드 실패가 비가역이므로 H4 착수 전 실측 1건이 선행 조건이다).

갈린 채 남는 지점 둘. (가) H4 대 H5의 순서. H4는 계획된 업그레이드만 덮고 필드의 주된 재시작 원인은 `Restart=always`/`KeepAlive`의 crash 재시작이다(`docs/ROADMAP.md:118` (g)) — H5 우선을 지지한다. 반면 H5는 echo 회귀와 토큰 custody 충돌(§6)을 안고, ADR-0003:30이 별도 supervisor 선분리를 기각하며 "세션 생존성이 실사용에서 검증된 뒤 투자"를 이미 판단으로 적었다. (나) H2의 값어치. 0.3ew를 문면 하나에 쓰는 거래가 자명하지 않고, wire 변경 0인 대안(재dial 후 cert는 같은데 세션이 없다는 사실만으로 추정 문면)이 남아 있다.

## §4 권고

M8 구현은 0. seam 보강도 M8에서 하지 않는다 — H5가 요구하는 trait async화는 supervisor 없이도 값이 있으나, attach 원자성이 `server/mod.rs:2075-2078`의 `SESSION_NOT_FOUND` 도달불가 근거이자 protocol.md §10-2 계약이므로 wire freeze·SC7 창에 넣을 작업이 아니다.

값싼 선행 조치는 H0 하나다. 패널 셋이 독립적으로 같은 항목에 닿았다. `docs/deploy/service.md:171-181`이 `Restart=always`/`KeepAlive`를 설명하면서 그 재시작이 detached 세션을 전부 지운다는 사실을 말하지 않고 README를 인용하지도 않는다(`README.md:511-523`은 이미 정확하다). H4를 채택해도 H4는 계획된 재시작만 덮으므로 이 고지는 남는다. `service.md`가 M8 Step 6 산출물이라 M8 문서 라운드가 열려 있으면 가장 싸고, 닫혔으면 M9 S9. 이 산정과 같은 커밋에서 반영했다.

배치: H1 → M9, S4와 S8 사이(두 라운드가 열린 자리면 0.15ew, M9 DoD의 "doctor 신규 7종"을 8종으로 같은 커밋에서 갱신). H1b → M9 배치 여부는 별도 판단이 필요하다(0.2–0.3ew, crash 재시작의 사용자 가시 정지를 45초에서 1 RTT로 낮추는 값이 H0/H1의 "고지만"보다 크다). H2 → M9(M10은 1.5ew에 notarization 리드타임이 걸려 있다). H3 → 기각. 이유는 가치 0이 아니라 H3이 내는 값(포트 hole 제거, reset key 이전으로 감지 1 RTT) 전부를 H1b가 프로세스 경계 없이 0.2~0.3ew에 내기 때문이다 — 두 프로세스·fd 전달 프로토콜·반쪽 재exec 실패 모드를 1.0ew에 사서 얻을 잔여 값이 없다. H4/H5 → P1, M10 이후. 둘 다 하는 것은 세션 상태를 두 경로로 유지하는 일이고 H5를 하면 H4는 대부분 불필요해지므로, P1 진입 시 세션이 어느 프로세스에 사는지를 고르는 단일 결정이 선행 조건이다 — 후보는 H4(listener 제자리)·H5(단일 supervisor) 둘만이 아니라 세션당 홀더 프로세스(sshd의 세션 리더 형태: 단일 실패점이 없고, ring이 listener RSS 예산 밖으로 나가 `docs/design/testing.md:128`의 idle 30MiB 판정을 재정의하지 않아도 되지만, 프로세스·fd 수가 세션 수에 비례한다)도 있다. ADR-0003이 기각한 것은 socket activation 의존과 "처음부터 별도 supervisor 분리"뿐이고(`docs/adr/0003-sessions-in-listener.md:28-32`) 이 세 번째 형태를 판단한 기록은 없다 — 이 산정은 그 비용을 매기지 않았고, 매기지 않은 것 자체가 이 문서의 갭이다. 이 산정은 어느 쪽이든 그 결정의 입력이다. H4가 M9 전체(4.3ew)와, H5가 최대 마일스톤 M2(5ew)와 맞먹어 어느 쪽도 기존 마일스톤에 끼우지 못한다.

## §5 보안 비용

상태를 옮기는 통로 자체의 권한 모델은 §2가 무엇을 옮기는지는 정리해도 어떤 통로로 옮기는지는 정하지 않는다. 통로마다 값이 다르다.

- **H4 스냅숏 통로.** env 변수는 스냅숏(세션 id, opener 키, resume 해시)이 새 이미지의 `environ`에 남아 이후 spawn되는 PTY 자식에게 상속될 수 있어 스크럽 단계가 필수다. 임시 파일은 resume 해시를 디스크에 남겨 ADR-0004의 memory-only 규율과 같은 질문을 다시 받는다. 상속 fd는 systemd `LISTEN_PID` 관례에 해당하는 "이 fd 묶음이 나에게 온 것인지" 수신자 검증이 필요하다. 셋 중 하나를 채택안으로 고르고 그 검증·스크럽 비용을 H4의 ew에 명시 가산해야 한다 — 현재 4.2ew에는 이 항목이 들어 있지 않다.
- **H5 supervisor 소켓.** PTY master를 넘기는 통로이므로 붙을 수 있는 자가 곧 셸을 가져가는 자다 — localctl보다 높은 표면이다. localctl은 같은 문제를 0700 디렉터리·0600 소켓·프레임 1바이트 읽기 전 euid 대조로 풀었고(`localctl/mod.rs:11-19`, `localctl/daemon.rs:62-95`) 그 비용이 이미 코드에 지불돼 있다 — 새 supervisor 표면에서 같은 권한 모델을 다시 세우는 비용을 H5의 ew에 가산해야 한다. §6은 평문 토큰 custody만 다루고 이 층(소켓 접근 자체)은 건드리지 않는다.

## §6 유보·불확실성

ew 신뢰도는 중간 이하다. 앵커는 ROADMAP M0–M10 열한 개(`docs/ROADMAP.md:36`–`:140`)이고 그중 M0–M8은 이미 착륙한 실적이지만, LOC/ew 환산은 M3(`:72`)·M8(`:114`) 두 표본에서 뽑아 1.5k–3k로 두 배 벌어진다. H0–H2는 M9 S단계와 직접 대응해 ±30% 안으로 보지만, H4의 4.2와 H5의 6.5는 그 환산에 두 겹 의존해 밴드 하한이 낙관일 수 있다. 단계별 분해는 다음과 같다(`docs/ROADMAP.md:127`의 M9 항목별 형식과 같은 단위) — H4: B1 0.4 / B2 0.4 / B3 0.4 / B4 0.45 / B5 0.5 / B6 0.3 / B7 0.5 / B8 0.6. H5: C0 0.3 … C7 1.0–1.5 / C8 0.4.

플랫폼 미확인: launchd `KeepAlive` throttle과 systemd `RestartSec` 기본값을 확인하지 못해 H3이 줄이는 포트 hole의 상대 크기를 판정할 수 없다(H3 기각은 그 판정이 아니라 H1b가 같은 값을 더 싸게 낸다는 우위에 서 있다). macOS/Linux의 PTY EOF·reap 타이밍 차이가 adopt 직후 창에서 다르게 나타날 가능성은 실측으로만 닫힌다. exec 중 자식이 죽으면 SIGCHLD 기본 처분이 무시라 새 이미지의 1회 reap sweep이 필수인데 그 창의 폭은 측정하지 않았다.

H4의 최대 미확인은 4.2ew에서 끝나지 않는다는 점이다. snapshot 필드 목록은 사람이 유지하고, 세션에 상태가 하나 붙을 때마다 넣지 않으면 handoff에서만 조용히 사라진다 — 컴파일·테스트·CI가 녹색인 채로. arch-lint·fixture append-only·`ErrorCode` 전수 도달성과 달리 "옮길 필드냐 재생성 대상이냐"는 기계가 판단하지 못한다. 여기에 더해 execve가 CLOEXEC 소켓을 커널이 닫게 두고 재바인드한다는 전제 자체가 `quinn::Endpoint::new` 이후까지는 미확인이다(§3 말미) — 재바인드 실패는 비가역이므로 실측 1건이 착수 전 선행 조건이다.

H5의 최대 미확인 둘. 대화형 출력 전체가 UDS 프레임+protobuf를 추가 통과하는 회귀 폭을 숫자로 내지 못했다(오늘 그 자리는 in-process `Mutex<Box<dyn ReplayStore>>` 하나, `broker/session.rs:245`). M4 acceptance echo와 M8 T2 PTY echo 예산이 그 경로를 지나고, 예산을 넘으면 설계가 fd 직접 전달로 회귀해 이 후보의 이점 자체가 사라진다. 그리고 resume registry가 supervisor로 가면 평문 토큰이 로컬 IPC를 건너는데, `localctl/mod.rs:81-88`이 모듈 불변식으로 금지하고 `crates/qsh-testkit/tests/resume_secrecy.rs`가 L6 규율로 지키는 바로 그 경로다. 새 conduit이라 형식적으로는 적용되지 않지만 금지의 이유(ADR-0007 custody)는 conduit 이름과 무관하고, 보안 리뷰가 이 경로를 거부하면 H5 전체가 성립하지 않는다.

Windows는 어느 후보에서도 P0 범위 밖이다. H3·H4는 PTY 백엔드 부재(`pty/mod.rs:45-49`)로 이중 부채, H5는 `#[cfg(unix)]` 컴파일 아웃으로 새 부채가 없다.

## §7 계약 문서 변경 목록

H0–H2는 기존 단언을 뒤집지 않는다.

| 후보 | 문서 |
|---|---|
| H0 | `docs/deploy/service.md:171-181`(단락 추가), `docs/CLI.md:768`(서비스 매니저 경로 한 줄) |
| H1 | +`docs/CLI.md` §6.17 표 1행, `EXPECTED_DOCTOR_CODES` 1항목(additive-only) |
| H2 | +`docs/design/protocol.md` §9, `docs/CLI.md` §6.4·§6.12 문면, `qsh.cli/v1` fixture 신규 1건(기존 무변경) |
| H3 | `docs/deploy/service.md:178-181`("never re-execs" — 정면 모순, 1순위), `docs/CLI.md:769`(SIGTERM=drain-and-die와 새 신호 분기), `:765`(foreground 전용 예외), `docs/ROADMAP.md:166`, `PLAN.md:739`, 신규 ADR 1건(ADR-0003:30-32 socket activation 기각 재검토) |
| H4 | H3 6건 + `README.md:511-523`(계획된 재시작만 예외로 조건부 재작성), `docs/CLI.md` §6.4(adopt 세션의 exit가 both-null로 격하되지 않는다는 단언)·§6.3(handoff가 resume 트리거, `gap` 1회가 정상), 정책 재로드 계약(`serve.rs:170-175`와 §6.12/§6.13의 "시작 시 1회, hot-reload 없음"이 사실상 재로드가 되므로 invalid면 handoff 거부), `quota.rs:67` "별도 카운터 없음" 불변식, `docs/PRD.md:321`·`:337`, `docs/design/architecture.md:60`·`:131`, `[serve]` 신규 키의 구버전 `config_unknown_key` 상호작용. ADR-0004·ADR-0018은 개정 불필요(ring 바이트를 쓰지 않아 ADR-0004 준수, 터널은 살리지 않는다). 신규 ADR 1건 |
| H5 | H4 목록에서 `docs/CLI.md:769`는 개정이 아니라 조항 신설, `README.md:511-523`은 "supervisor가 살아 있는 한 resume 지점"으로 뒤집힘, `docs/PRD.md:321`은 문구가 맞고 상태만 갱신. 추가로 `localctl/mod.rs:81-88` 토큰 금지 재획정, `docs/design/protocol.md` §11-3(로컬 IPC 표면 둘), `docs/design/testing.md:128`의 "idle listener ≤30MiB"를 두 프로세스 합으로 재정의, ADR-0004에 "어느 프로세스의 메모리인가" 각주, `service.md`에 "listener 재시작은 세션을 죽이지 않지만 supervisor 재시작은 죽인다"는 역방향 고지, `architecture.md:60`·`docs/PRD.md:337`의 "drop-in 교체" 표현 정정(호출 형태가 동기·RAII·다중 호출 원자성에 묶여 실제로는 drop-in이 아니다). 신규 ADR 2건 |
