# ADR-0046: IPv6 wildcard listener는 dual-stack으로 연다

날짜: 2026-10-21
상태: 승인됨 (2026-10-21, 2026-10-14 사용자 위임 결정 "전부 다 알아서 진행해"에 따른 에이전트 결정)

개정 관계: ADR-0014 결정 8(bind 기본값 `[::]:4433`과 우선순위)은 그대로 둔다. 이 ADR은 그 기본값으로 연 소켓이 IPv4 peer를 받는지를 정한다. ADR-0035(Windows client)와 M20 Windows host의 "Linux·macOS와 같은 기능" 원칙을 bind 계층에 적용한다. `docs/CLI.md` doctor 표의 `bindv6only_blocks_ipv4` 행의 발생 조건을 바꾼다. 코드 이름과 등급은 그대로다.

## 맥락

`qsh serve`와 `qsh listen`의 bind 기본값은 `[::]:4433`이다(`crates/qsh-core/src/serve.rs`의 `DEFAULT_BIND`). `Listener::bind`는 `bind_tuned_udp_socket(addr, dual_stack_v6=false)`로 소켓을 열고 `IPV6_V6ONLY`를 건드리지 않는다. 그래서 IPv4 peer를 받는지는 OS 기본값에 달려 있다.

- Linux는 `net.ipv6.bindv6only=0`이 기본이라 `[::]` 소켓이 IPv4 peer도 받는다. 그 peer는 IPv4-mapped 주소(`::ffff:a.b.c.d`)로 보인다.
- Windows는 새 IPv6 소켓이 `IPV6_V6ONLY=1`로 열린다. 기본 `qsh serve`와 `qsh listen`이 IPv4 peer를 조용히 거부한다.

M9가 이 차이를 doctor `bindv6only_blocks_ipv4`(warn)로 알렸고, M20은 Windows에서 그 경고가 나온다는 사실을 `docs/CLI.md`에 적었다. 2026-10-21 Dave-Windows(Windows 11 25H2, 빌드 26200)에서 v0.5.0의 `qsh doctor`가 이 경고를 실제로 냈다. Tailscale 같은 overlay 주소(100.64.0.0/10)와 대부분의 LAN 주소는 IPv4다. 따라서 기본 설정의 Windows host는 `p1-windows` W2·W3a·W3b·W7의 흔한 구성에서 연결을 받지 못한다. 경고를 내는 것만으로는 같은 기능이 되지 않는다.

client 쪽 `Dialer::dial`과 이동 뒤 재bind(`PathBinder`)는 이미 `dual_stack_v6=true`로 `IPV6_V6ONLY`를 best-effort로 푼다. quinn의 `Endpoint::client`를 따른 것이다. 서버 쪽만 quinn `Endpoint::server`의 선례를 따라 풀지 않았다.

## 결정

1. `Listener::bind`(와 `bind_with_reset_key`)는 IPv6 주소에 bind할 때 `IPV6_V6ONLY`를 best-effort로 끈다. client와 같은 `dual_stack_v6=true` 경로다. `qsh serve`, `qsh listen`, `qsh pair ssh-respond`의 UDP bind 시험이 모두 이 경로를 탄다. IPv4 주소에 bind하는 동작은 바뀌지 않는다.
2. 끄기가 실패해도 bind는 실패시키지 않는다. 예를 들어 OS가 dual-stack을 지원하지 않는 경우다. 소켓은 IPv6 전용으로 남고, 결정 3의 doctor 경고가 그 상태를 알린다.
3. doctor `bindv6only_blocks_ipv4`는 유효 bind 주소가 IPv6 wildcard이고, 새 IPv6 UDP 소켓에서 `IPV6_V6ONLY`를 끈 뒤 다시 읽은 값이 여전히 켜져 있을 때만 나온다. 끄기 호출 자체가 실패한 경우도 같다. 이제 OS 기본값은 이 진단과 관계가 없다. 코드 이름, 등급(warn), `EXPECTED_DOCTOR_CODES`의 개수는 그대로다. remedy는 IPv4 주소를 명시해 bind하라는 안내로 유지한다.
4. IPv4 peer는 Windows에서도 Linux와 같이 IPv4-mapped 주소로 보인다. 이 ADR은 peer 주소의 표기를 정규화하지 않는다. Linux에서 이미 오래 쓰인 표기이고, 주소를 정규화할지는 따로 결정할 일이다.
5. 회귀 테스트는 loopback만 쓴다. bind 도우미가 IPv6 loopback 주소로 연 소켓의 `IPV6_V6ONLY`가 꺼져 있는지 본다. `Listener::bind`가 그 도우미를 `dual_stack_v6=true`로 부르는지도 본다. wildcard bind와 실제 IPv4 peer의 수용은 `p1-windows` W2·W3a·W3b가 실제 장비로 본다.

## 근거

- 같은 기본 설정이 OS마다 다른 도달성을 내면 사용자는 설정 실수와 제품 결함을 가를 수 없다. Linux 기본 동작(dual-stack)이 이미 표준처럼 쓰이므로, 다른 OS를 그쪽에 맞추는 것이 기존 사용자에게 가장 작은 변화다.
- client가 이미 같은 best-effort 처리를 한다. 서버만 OS 기본값에 맡길 이유가 남아 있지 않다.
- IPv4-mapped 주소는 Linux host에서 이미 모든 IPv4 peer가 쓰는 표기다. Windows에서 같은 표기가 새로 나타나도 새 코드 경로가 생기지 않는다.

## 대안과 기각 사유

- **기본 bind를 `0.0.0.0:4433`으로 바꿈:** 기각. IPv6 peer를 잃고, ADR-0014 결정 8을 개정해야 하며, Linux 사용자의 지금 동작을 바꾼다.
- **IPv4 소켓과 IPv6 소켓 두 개를 bind:** 기각. endpoint와 연결 이동 처리가 둘로 갈라지고, Linux에서 dual-stack `[::]`와 `0.0.0.0`의 같은 포트가 충돌한다.
- **경고만 유지하고 Windows 문서에 `--bind 0.0.0.0:4433`을 안내:** 기각. 같은 기능 원칙에 어긋나고, 기본값으로 서비스를 등록한 사용자가 경고를 볼 때까지 모른다.

## 결과

- 바꾸는 파일: `crates/qsh-transport/src/endpoint.rs`(`Listener::bind` 경로와 도우미 문서), `crates/qsh-core/src/doctor/probe.rs`(probe 조건), `docs/CLI.md` doctor 표의 `bindv6only_blocks_ipv4` 행과 28종 문단의 Windows 문장, `RELEASE-NOTES.md`의 다음 태그 절.
- wire와 JSON 계약은 바뀌지 않는다. doctor 코드 집합도 그대로다.
- 이 수정이 담긴 태그가 나오기 전의 Windows host 회차(`p1-windows` W2·W3b·W7)와 Windows `qsh listen` 회차(W3a)는 IPv4 경로에서 실패할 수 있다. 그런 행은 `p1-windows` §6의 제품 결함으로 분류하고 새 태그로 다시 돈다.
