# ADR-0039: DNS-over-HTTPS 강제 모드는 P1에 넣지 않는다. P2 후보로 두고 착수할 때의 모양(해석 seam 하나, IP 리터럴 bootstrap, fail closed `doh-only`)만 지금 고정한다

날짜: 2026-10-01
상태: 제안됨

개정 관계: 새 ADR이다. 다른 ADR을 개정하지 않는다. 착수하려면 `docs/PRD.md` §4("Provider agnostic")와 §12("QSH 밖에서 해결하는 것")의 문장, `docs/design/threat-model.md` §9의 "web PKI" 비목표를 먼저 고쳐야 한다(결정 1·7). 예약 번호(0027~0035) 밖의 새 번호다.

## 맥락

GitHub 이슈 #8은 qsh가 쓰는 이름 해석을 DNS-over-HTTPS(DoH)로 강제하는 모드를 요청한다. 동기는 macOS의 기업 VPN이다. VPN이 시스템 resolver를 붙잡으면 직접 UDP 경로가 살아 있어도 controller 이름이 풀리지 않거나 VPN 쪽 주소로 풀려서 역방향 등록과 재접속이 늦어지거나 멈춘다. 이슈가 요구하는 것은 `--doh <URL>`과 `--doh-only`, 시스템 DNS 기본 유지, `system`/`doh`/`doh-only` 세 정책, 모든 해석 지점의 공용 구현, 질의 내용을 남기지 않는 구조화 진단, bootstrap·인증서 검증·프록시·captive 망에 대한 문서다. DoH는 이름 해석만 바꾸고 peer 인증은 바꾸지 않아야 한다는 조건도 붙어 있다.

오늘 qsh의 이름 해석은 전부 OS resolver(`getaddrinfo`)로 간다. 경로는 `tokio::net::lookup_host`이거나 동기 `std::net::ToSocketAddrs`다. 해석 지점은 다음과 같다(2026-10-01 `0063c18` 기준).

| 용도 | 위치 | 해석기 |
|---|---|---|
| client가 peer에 dial (attach, exec, supervise 재수립) | `crates/qsh-core/src/ops/mod.rs`의 `resolve_all`. 호출자는 `ops/session/reader.rs`, `ops/exec.rs`, `ops/tunnel/supervise.rs` | `tokio::net::lookup_host`. 테스트 seam은 `AddressResolver` trait와 `SystemResolver` |
| 역방향 target이 controller에 등록 (`qsh serve --to`) | `crates/qsh-core/src/reverse/target/mod.rs`의 `dial_and_register`. 시도마다 새로 해석한다 | 같은 `resolve_all` |
| fingerprint probe와 `pair accept` | `ops/probe.rs`, `ops/trust.rs`의 `resolve_one` | 같은 `resolve_all`의 첫 주소 |
| host 쪽 터널 목적지 (`-L`, `-D`의 `TCP_CONNECT`) | `crates/qsh-core/src/tunnel/dial.rs`의 `Resolver` trait와 `TokioResolver` | `tokio::net::lookup_host` |
| `-R` bind 주소 | `crates/qsh-core/src/tunnel/remote.rs`의 `BindHostResolver`와 `SystemResolver` | `tokio::net::lookup_host` |
| doctor 연결성 probe | `crates/qsh-core/src/ops/doctor.rs`의 `blocking_resolve`. `DOCTOR_PROBE_TIMEOUT`으로 묶인다 | `std::net::ToSocketAddrs` |
| `serve`/`listen` bind spec | `crates/qsh-core/src/serve.rs`, `reverse/listen.rs`의 `resolve_bind` | `std::net::ToSocketAddrs` |

seam은 이미 세 개(`AddressResolver`, `Resolver`, `BindHostResolver`)로 갈라져 있고 doctor와 bind 해석은 seam 밖에 있다. 두 해석기 모두 입력이 IP 리터럴이면 DNS를 부르지 않는다. tokio 1.53.1의 `ToSocketAddrsPriv for str`이 먼저 `SocketAddr`로 파싱해 보고, 성공하면 blocking resolver로 가지 않는다.

이슈의 증상이 어디에 걸리는지도 확인했다. `docs/CLI.md` §6.1에 따라 attach의 자동 재접속은 최초 attach 때 해석한 주소를 계속 쓰고 다시 해석하지 않는다. 그래서 DoH는 attach 재접속을 바꾸지 못한다. 시도마다 해석하는 경로는 역방향 target 등록과 supervise 재수립이고, 해석 실패는 오늘도 `qsh::reverse` 진단 줄의 `cause: "resolve"`로 따로 분류된다(`docs/CLI.md` §6.13).

신원과의 관계는 이미 정해져 있다. `docs/design/protocol.md` §3은 SNI와 hostname을 검증에 쓰지 않고, principal은 인증서 pin이나 private CA 체인에서만 나온다. 위조된 DNS 응답은 엉뚱한 주소로 dial하게 만들 뿐이고 그 상대는 pin 검증에서 거부된다. DNS 응답의 무결성은 qsh에서 인증 속성이 아니고 가용성 속성이다. DoH가 주는 값은 둘이다. VPN이 붙잡은 resolver를 우회하는 가용성, 그리고 on-path 관찰자에게 평문 DNS로 hostname이 새지 않는 프라이버시다.

제품 범위 쪽 사실은 이렇다. `docs/PRD.md` §4는 "특정 VPN, tunnel, DNS 또는 identity provider와 직접 통합하지 않는다"고 적고, §12는 "DNS와 service discovery"를 QSH 밖에서 해결하는 것으로 둔다. §7의 P1·P2 목록 어디에도 resolver 항목이 없다. `docs/ROADMAP.md` §5의 M11~M19와 예약 ADR 0028~0035에도 없다.

보안 문서 쪽 사실도 있다. `docs/design/threat-model.md` §9와 `docs/design/protocol.md` §3은 "web PKI root는 어떤 경로로도 로드하지 않는다"를 비목표로 못박았다. 공개 DoH 서버의 인증서는 거의 언제나 web PKI로 발급된 것이라 DoH 클라이언트는 그 root를 어딘가에서 읽어야 한다.

후보 crate를 lockfile과 `deny.toml`에 대어 봤다.

- `hickory-resolver` 0.26.3(MIT OR Apache-2.0, MSRV 1.88)은 `https-aws-lc-rs` feature로 DoH를 켠다. 그 아래 `hickory-net` 0.26.3은 `rustls` 0.23.23 이상, `quinn` 0.11, `aws-lc-rs`, `tokio-rustls` 0.26, `h2` 0.4, `http` 1에 기대고, 이 저장소의 `Cargo.lock`(rustls 0.23.45, quinn 0.11.12, aws-lc-rs 1.18.1)과 같은 줄이다. 두 번째 TLS 스택이나 `openssl`(`deny.toml`이 금지)은 들어오지 않는다. 기본 feature `system-config`는 `resolv-conf`, `system-configuration` 등을 끌어오므로 `default-features = false`로 끈다.
- hickory의 `NameServerConfig`는 서버 주소를 `ip: IpAddr`로만 받고 DoH 연결은 `ConnectionConfig::https(server_name, path)`로 TLS 이름과 경로를 따로 받는다. DoH 서버 자신의 hostname을 해석하는 경로가 라이브러리에 없다. bootstrap은 처음부터 IP 리터럴이다.
- root 저장소 후보 둘 중 `webpki-roots` 1.0.9는 `CDLA-Permissive-2.0`이라 `deny.toml`의 `[licenses].allow`에 없다. `rustls-platform-verifier` 0.7.1은 MIT OR Apache-2.0이고 Linux에서는 `rustls-native-certs`, macOS에서는 Security.framework를 쓴다. 다만 wasm32 대상 의존성으로 `webpki-root-certs`(역시 `CDLA-Permissive-2.0`)를 달고 있고, `deny.toml`의 `[graph] targets = []`는 모든 target을 검사하므로 `cargo deny check`가 그 줄에서 걸릴 수 있다. 구현할 때 실제로 돌려 확인해야 하고, 걸리면 `targets`를 좁히거나 라이선스를 허용 목록에 더하는 결정이 따로 필요하다.

마지막으로 `config.toml`의 모르는 키는 오류 없이 무시되고 doctor가 `config_unknown_key` warn으로만 알린다(`docs/CLI.md` §2.3, §6.17). 강제 모드 키를 잘못 쓰면 조용히 시스템 DNS로 돌아간다. fail open 방향의 함정이다.

## 결정

1. DoH 모드는 P1에 넣지 않는다. PRD §4와 §12가 DNS 통합을 제품 밖에 두고 있고, 이슈의 증상은 오늘도 코드 변경 없이 피할 수 있다(결정 2). P2 후보로 올릴지는 사용자가 정한다. 올린다면 `docs/PRD.md` §7 P2 목록에 한 줄을 더하고 §4·§12 문장을 "qsh는 DNS를 대신하지 않지만, 명시적으로 켠 경우 자기 이름 해석을 DoH로 보낼 수 있다"로 고친 뒤에 착수한다. 그때까지 플래그도 config 키도 예약하지 않는다. 예약 플래그는 그 자체로 `UNSUPPORTED`를 내는 계약 표면이 되기 때문이다.

2. 지금 쓸 수 있는 우회를 문서에 적는다. `hosts.toml`과 `trust.toml`의 주소, `[serve].to`에 IP 리터럴을 쓰면 qsh는 그 dial에서 resolver를 부르지 않는다(맥락의 tokio 파싱 사실). 주소가 자주 바뀌어 이름이 필요한 경우는 OS 쪽 암호화 DNS 설정(macOS의 암호화 DNS 프로파일, Linux의 `systemd-resolved` DoT 등)이 PRD의 경계와 맞는 답이다. 이 문서 변경은 이 ADR이 승인되면 P1 안에서 바로 할 수 있고, 아래 결정 3~10과 독립이다.

3. 착수한다면 해석 seam을 하나로 모은다. `qsh-core`에 이름 해석 trait 하나를 두고 맥락 표의 일곱 지점이 모두 그것만 부른다. 오늘의 `AddressResolver`, `Resolver`, `BindHostResolver` 셋은 이 trait로 합친다. `xtask arch`에 seam 모듈 밖의 `tokio::net::lookup_host`와 `ToSocketAddrs` 직접 호출을 금지하는 규칙을 더해 새 해석 지점이 seam을 우회하지 못하게 한다. DoH 구현은 `qsh-core`에 둔다. `qsh-transport`는 quinn/rustls glue만 맡고, DoH의 TLS는 qsh peer 연결과 무관한 별도 클라이언트이기 때문이다.

4. 모드는 셋이고 프로세스 하나에 하나다.

   | 모드 | 거동 |
   |---|---|
   | `system` (기본) | 오늘과 같다. 이 모드에서는 hickory 코드 경로를 타지 않는다 |
   | `doh` | DoH로 먼저 묻는다. DoH가 타임아웃·HTTP 오류·형식 오류로 실패하면 그 질의에 한해 시스템 resolver로 한 번 더 묻고, fallback 사실과 사유를 진단 줄로 남긴다 |
   | `doh-only` | DoH만 쓴다. 실패하면 해석 실패로 끝나고 시스템 resolver를 부르지 않는다. 이 모드에서 qsh 프로세스가 내는 평문 DNS 패킷은 0이다 |

   IP 리터럴과 `localhost`(RFC 6761)는 어느 모드에서도 프로세스 밖으로 나가지 않는다.

5. bootstrap은 IP 리터럴로만 한다. DoH 엔드포인트는 URL(`https://` 전용, 경로 생략 시 `/dns-query`)과 그 서버의 IP 목록으로 준다. URL의 host가 이름이면 그 이름은 TLS 서버 이름으로만 쓰고 해석하지 않는다. IP 목록이 비었거나 URL이 `https`가 아니면 기동 때 `CONFIG_ERROR`(`retryable: false`)로 거절한다. 어느 모드에서도 DoH 서버 이름을 시스템 DNS로 풀지 않는다. `doh-only`에서 그렇게 하면 결정 4의 "평문 0"이 깨지고, `doh`에서만 허용하면 두 모드의 bootstrap 규칙이 갈라진다.

6. 표면은 `config.toml`의 `[resolver]` 표(`mode`, `doh_url`, `doh_ips`, `doh_timeout_ms`)와 전역 플래그 `--doh <URL>`, `--doh-only`다. 우선순위는 다른 키와 같이 CLI 플래그 > config > 기본값이다. `doh_timeout_ms`의 범위 검증은 ADR-0021 결정 1과 같은 모양으로 범위를 벗어나면 clamp하지 않고 `CONFIG_ERROR`다. 맥락 끝의 오타 함정에는 두 겹으로 대응한다. `qsh serve`와 `qsh listen`은 기동 진단 줄에 실효 resolver 모드를 적는다. 그리고 `[resolver]` 표가 있는데 `mode`가 없거나 모르는 값이면 config 로더가 `CONFIG_ERROR`로 거절한다. 기동도 doctor도 같은 로더를 타므로 둘 다 실패로 끝난다. 표가 아예 없을 때만 조용히 `system`이다.

7. DoH 서버 인증서는 OS trust store로 검증한다(`rustls-platform-verifier`). 그 root는 resolver 클라이언트의 rustls 설정에만 실리고 `QshPeerVerifier`는 그것을 보지 않는다. qsh peer 검증의 규칙(pin → private CA → 거부, web PKI 미적재)은 그대로다. 선택 키 `doh_spki_pins`를 주면 platform 검증에 더해 SPKI pin도 요구한다. 착수 전에 `docs/design/threat-model.md` §9의 "web PKI" 비목표를 "qsh peer 검증에는 web PKI root를 싣지 않는다. DoH resolver 연결은 이 ADR이 정한 예외다"로 고친다. DoH 응답은 어느 경우에도 신원에 들어가지 않는다. 악의적인 DoH 서버가 할 수 있는 일은 오늘 평문 DNS 위조와 같은 오도뿐이고 pin 검증이 막는다.

8. 실패는 기존 재시도 경로에 들어간다. 질의 하나는 `doh_timeout_ms`(기본 5000)로 묶이고, 타임아웃·HTTP 오류·형식 오류·bootstrap 연결 실패는 모두 오늘의 해석 실패와 같은 `CONNECTION_FAILED`가 된다. 새 `ErrorCode`는 만들지 않는다. 역방향 target에서는 `cause: "resolve"`로 기록되고 backoff를 그대로 탄다. supervise도 같다. HTTP 프록시(`HTTPS_PROXY` 등)는 지원하지 않고 무시한다. captive portal이나 DoH를 막는 기업망에서 `doh-only`는 실패로 끝나는 것이 의도된 동작이다.

9. 진단은 질의 내용을 담지 않는다. resolver 진단 줄(tracing target `qsh::resolver`, stderr 한 줄 JSON)은 모드, 엔드포인트 URL, 시도한 bootstrap IP, 타임아웃, 결과 분류(`ok`/`timeout`/`http_status`/`malformed`/`connect`/`fallback`)만 싣고 질의한 이름과 응답 주소는 싣지 않는다. 이 줄은 `qsh::reverse`처럼 계약 밖의 열린 어휘다. doctor는 진단 code 하나 `resolver_doh_unreachable`를 더한다. `[resolver]`가 `doh`나 `doh-only`일 때 설정된 엔드포인트에 고정 이름 하나를 질의해 실패하면 낸다. 등급은 `doh-only`에서 `error`, `doh`에서 `warn`이다. 고정 이름은 `docs/CLI.md`에 적는 상수다.

10. 터널 목적지 해석도 같은 모드를 따른다. host 쪽 `-L`·`-D` 목적지 해석이 `doh-only`에서 시스템 DNS를 쓰면 "평문 0"이 깨지기 때문이다. 대가로 사내 split-horizon 이름은 공개 DoH 서버에서 풀리지 않는다. 이 한계는 `docs/CLI.md` §6.9와 README에 적는다. `-R` bind와 `serve`/`listen` bind spec은 결정 4의 IP 리터럴·`localhost` 예외로 사실상 영향이 없다.

## 근거

이슈가 실제로 겪는 문제는 OS resolver의 가용성이다. qsh의 신원은 DNS와 무관하게 설계되어 있어서 DoH가 막아 주는 보안 위협이 없다. 남는 가치는 가용성과 hostname 프라이버시인데, 둘 다 IP 리터럴 주소나 OS 쪽 암호화 DNS로 오늘 얻을 수 있다. 반면 비용은 작지 않다. 의존성 트리(hickory 두 crate와 HTTP/2 스택, platform verifier)가 늘고, web PKI를 바이너리에 처음 들여오고, PRD의 제품 경계 문장 두 개를 고쳐야 한다. P1은 이미 아홉 마일스톤과 사람 회차를 안고 있다(`docs/ROADMAP.md` §5.2, §5.5). 이 조합이면 지금 구현할 이유보다 미룰 이유가 크다.

그래도 모양을 지금 고정하는 것은 두 가지 함정을 미리 막기 위해서다. 하나는 해석 지점이 seam 셋과 seam 밖 둘로 흩어진 오늘 상태에서 DoH를 일부 지점에만 붙이는 것이다. 그러면 `doh-only`의 "평문 0"이 거짓이 된다(결정 3·10). 다른 하나는 bootstrap에서 DoH 서버 이름을 시스템 DNS로 푸는 것이다. 편해 보이지만 강제 모드의 약속을 첫 패킷부터 깬다(결정 5).

## 대안

- 기본값을 DoH로 둔다. 기각한다. PRD §4의 provider agnostic 원칙과 정면으로 부딪히고, 사내 split DNS로만 풀리는 controller 이름을 쓰는 사용자를 깨뜨린다. 이슈도 시스템 DNS 기본 유지를 요구한다.
- P1 안에 넣어 바로 구현한다. 기각을 권한다. 결정 2의 우회로 증상이 해소되고, PRD 경계와 threat-model 비목표를 고치는 결정이 먼저다. 사용자가 P1에 넣기로 하면 결정 3~10이 그대로 구현 범위가 되고, M14(TCP fallback) 뒤에 두는 것이 맞다. TCP fallback도 UDP가 막힌 기업망을 겨냥하므로 두 기능의 doctor 진단과 문서를 함께 설계하는 편이 싸다.
- `reqwest` 등 HTTP 클라이언트로 RFC 8484 메시지를 직접 만든다. 기각한다. DNS 메시지 파서를 직접 들이면 신뢰할 수 없는 입력을 읽는 새 표면이 생기고 ADR-0001 규율대로 fuzz 타깃까지 늘어난다. hickory는 그 파서를 이미 갖고 있다.
- DoT(853/TCP)나 DoQ(UDP)를 쓴다. 지금은 기각한다. 기업망은 443/TCP를 가장 덜 막는다. DoQ는 qsh 자신과 같은 UDP 운명을 진다. hickory가 둘 다 지원하므로 나중에 모드 값을 additive로 더할 수 있다.
- DoH 서버 이름을 `doh` 모드에서만 시스템 DNS로 bootstrap한다. 기각한다. 결정 5의 근거대로 두 모드의 규칙이 갈라지고, 이름을 풀려고 시도하는 순간이 곧 이슈가 피하려는 VPN resolver 경로다.
- `webpki-roots`를 정적으로 묶는다. 기각한다. `CDLA-Permissive-2.0`이 `deny.toml` 허용 목록 밖이고, 바이너리에 박힌 root는 릴리스 주기만큼 낡는다.
- DoH 서버를 SPKI pin으로만 인증한다. 기본으로는 기각한다. 공개 resolver는 키를 예고 없이 돌리므로 pin만 두면 운영이 부서지기 쉽다. 결정 7의 선택 키로만 남긴다.
- host마다 resolver를 다르게 둔다(`hosts.toml` 항목별 `resolver`). 기각한다. 같은 이름이 경로마다 다르게 풀리는 상태를 진단하기 어렵고, 이슈의 요구는 프로세스 단위다.

## 결과

- 이 ADR이 승인되면 P1 안에서 하는 일은 결정 2의 문서 변경 하나다. README "Known limitations"와 `docs/CLI.md` §6.1(주소 해석 시점 문단)에 IP 리터럴 우회와 OS 암호화 DNS 안내를 더한다. `qsh.cli/v1`, wire, fixture는 바뀌지 않는다. `docs/ROADMAP.md` §5.3("P1 밖으로 보낸다") 표에 이 항목을 이 ADR 인용과 함께 한 줄 더하는 것은 메인 세션이 한다.
- P2로 올리기로 하면 착수 전에 고칠 문서다. `docs/PRD.md` §4·§7 P2·§12, `docs/design/threat-model.md` §3(새 진입점: resolver로 나가는 HTTPS 연결), §4(새 행: DoH 응답 오도는 pin이 막는다, DoH 장애는 가용성 위협), §9(결정 7의 문장), `docs/design/architecture.md`(해석 seam), `deny.toml`(맥락의 라이선스 확인 결과).
- 구현이 갚아야 할 계약 변경이다. 모두 additive다. `config.toml`의 `[resolver]` 표, 전역 플래그 둘과 man 페이지 재생성(`cargo xtask man`), `docs/CLI.md` §6.17 진단 코드 표와 `EXPECTED_DOCTOR_CODES`에 `resolver_doh_unreachable` 하나, §6.9의 split-horizon 한계 문장. `ErrorCode`와 `qsh.cli/v1` envelope 필드는 늘지 않는다.
- 구현이 갚아야 할 테스트다. 이름은 구현 시 확정한다.
  - `doh_resolves_through_a_testkit_doh_server`: testkit이 private CA로 띄운 DoH 서버(테스트 전용 root 주입)로 해석과 dial이 성공한다.
  - `doh_only_emits_no_system_resolver_call`: `doh-only`에서 seam 뒤 시스템 해석기 stub의 호출 횟수가 0이다. 실패 경로(타임아웃, 형식 오류)에서도 0이다.
  - `doh_timeout_is_bounded_and_classified_as_resolve`, `doh_malformed_response_is_classified_as_resolve`, `doh_http_error_is_classified_as_resolve`.
  - `doh_bootstrap_requires_ip_literals`: IP 목록 없는 설정과 `http://` URL이 `CONFIG_ERROR`다.
  - `doh_mode_falls_back_once_and_reports_why`: `doh`에서 DoH 실패 뒤 시스템 해석기를 한 번 부르고 `fallback` 진단 줄을 남긴다.
  - `system_mode_is_byte_identical_to_today`: `[resolver]`가 없을 때 seam이 오늘의 해석기만 부른다.
  - `reverse_target_registers_and_reconnects_under_doh_only`: 역방향 target이 `doh-only`로 등록하고 controller 재시작 뒤 다시 등록한다(이슈 #8의 첫 수용 기준).
  - `resolver_diagnostics_never_carry_the_query_name`: 진단 줄에 질의 이름과 응답 주소가 없다.
  - `xtask arch` 규칙의 자체 테스트: seam 밖 `lookup_host` 호출이 걸린다.
- 크기는 1.5~2.5ew로 추정한다. 측정값이 아니다. seam 통합 0.4~0.6, hickory 연결과 bootstrap·모드 0.5~0.8, doctor와 진단 0.2~0.3, testkit DoH 서버와 테스트 0.4~0.8이다.
