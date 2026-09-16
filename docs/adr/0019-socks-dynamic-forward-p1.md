# ADR-0019: SOCKS(`-D`)는 v1 내내 P1로 두고, 구현 조건은 미결 질문으로 남긴다

날짜: 2026-09-17
상태: 제안됨 (`docs/adr/README.md:3`의 어휘 정의대로 "결정 절은 다 냈으나 사용자 확정 전 초안"이다. 같은 상태의 선례는 ADR-0014, `docs/adr/README.md:20`.)

## 맥락

`-D`(SOCKS5 dynamic forwarding)는 P0에서 flag만 파싱되고 항상 `UNSUPPORTED`로 거절된다.

현행 상태를 적어 둔 곳은 여럿이다. `docs/PRD.md:136`이 사용 예 옆에 "P1 — SOCKS5, 플래그는 예약만 되어 있음"이라 적고, `docs/PRD.md:161`이 P1 절의 유예 기능 목록에 SOCKS5 dynamic forwarding을 올리고, `docs/PRD.md:198`이 §9 action 어휘에 `forward.socks`를 `forward.local`/`forward.remote`와 나란히 두고, `docs/PRD.md:259`가 "`-D`는 P0에서 flag parsing만 되며 실제 구현은 P1"이라 쓴다. `docs/ROADMAP.md:77`이 M4의 명시적 out으로, `docs/ROADMAP.md:78`이 M4 DoD로 `-D 1080` → `UNSUPPORTED` + "P1" 메시지를 요구하고, §3 유예 가드레일 표의 "SOCKS `-D` (P1)" 행(`docs/ROADMAP.md:152`)이 가드레일 전문을 적는다. `docs/CLI.md:118`이 `forward.socks`를 향후 예약 action으로, `docs/CLI.md:180`이 `UNSUPPORTED` 어휘의 예시로 `-D`를 들고, `docs/CLI.md:507`(§6.9, 절 머리는 `docs/CLI.md:473`)이 거절 문면과 두 spelling, 값 미파싱, `--json` 우선순위까지 축자로 규정한다.

이 등재 자체는 결정의 근거가 아니다. `docs/PRD.md:158`의 절 표제는 "P1 — 실사용 확장"이고 어디에도 "v1에서 당겨오지 못한다"는 문장이 없다. 같은 목록의 `docs/PRD.md:165`("background service 설치와 자동 시작")은 이미 v1 안으로 당겨져 M9 (g) `qsh service install`이 됐고(`docs/ROADMAP.md:118`), 유예 가드레일 표의 해당 행이 그 승격을 명시적으로 기록한다(`docs/ROADMAP.md:160`). P1 목록은 현행 상태의 기술이지 자기강제력이 있는 구속이 아니다. 아래 미결 질문 1(목적지 ACL 문법 부재)과 2(역방향 egress)가 이 결정을 실제로 지탱한다.

질문이 다시 올라온 이유는 M9의 DoD와 배포 형태 변화다.

`docs/ROADMAP.md:123`이 문구 표본 8종 중 하나로 "`-D` 현행 유지 문구"를 축자 테스트로 고정하라고 요구한다. 문면을 쓰려면 "왜 여전히 유예인가"가 인용 가능한 형태로 있어야 하는데, 오늘 그 근거는 ROADMAP 표 한 행뿐이고 ADR은 없다.

M9 (g) `qsh service install`(`docs/ROADMAP.md:118`)은 macOS LaunchAgent와 systemd user unit으로 상시 실행 host를 만든다. 장비 여러 대에 같은 방식으로 깔리는 fleet 형태다. 상시 host가 사내망에 하나 서 있으면 그것을 범용 egress proxy로 쓰자는 요구가 따라온다. 이 요구의 구체적 형태는 2026-09-16 설계 검토가 기록한 것이고 저장소 안의 사실은 아니다.

기업망 쪽 사실관계는 SOCKS와 무관하다. qsh 연결은 전부 QUIC/UDP이고 TCP 코드가 0줄이라(`docs/ROADMAP.md:151`, ADR-0005), TLS를 열어 보는 검사 프록시가 중간에 끼어들 여지가 구조적으로 없다. 그런 망은 대신 UDP를 막고, doctor가 그것을 `udp_egress_blocked`로 보고한다(`crates/qsh-core/src/doctor.rs:156-160`; message가 "QSH has no TCP fallback (P1, ADR-0005) — every QSH connection is QUIC over UDP, so this is a hard stop"을 그대로 적고(`:159`) remedy는 방화벽 개방 또는 WireGuard/Tailscale 오버레이다(`:160`)). peer 인증은 mTLS이고 검증 경로는 pin → CA → 거부 순서로 `QshPeerVerifier`에 있으며(`docs/design/architecture.md:78`), fingerprint 표기는 SPKI SHA-256이다(`docs/design/architecture.md:76`). SOCKS를 qsh 위에 얹어도 이 구도는 바뀌지 않는다. 차단 지점은 UDP egress이고 SOCKS는 그 위에서 도는 payload다.

## 결정

1. `-D`/SOCKS는 v1 내내 P1로 둔다. 오늘의 거절 경로를 그대로 유지한다. 두 spelling 모두 파싱만 되고(대화형 `qsh host -D …`는 `crates/qsh-cli/src/cli.rs:124`·`:129`, `qsh tunnel open --dynamic`은 `crates/qsh-cli/src/cli.rs:392-393`), 거절은 `Ops` 호출 이전에 일어난다(`crates/qsh-cli/src/main.rs:507-508`과 `:766-767`이 `dynamic_forward_unsupported()`를 부르고 그 자리에서 반환하므로 연결·세션·listener가 하나도 생기지 않는다. 함수 doc이 같은 말을 적는다: `crates/qsh-core/src/ops/tunnel.rs:110-122`). 문면은 단일 상수 하나다(`crates/qsh-core/src/ops/tunnel.rs:107-108`, `:123-124`). 이 유지의 근거는 미결 질문 1·2에 답이 없는 상태이고 P1 목록 등재는 근거로 세지 않는다(맥락 3번째 문단).

2. 가드레일 넷을 v1 내내 유지한다.
   - (a) flag는 파싱되고 값은 전혀 파싱되지 않는다. 어떤 값을 주든 같은 `UNSUPPORTED` 한 건으로 수렴한다(`docs/CLI.md:507`).
   - (b) `forward.socks`는 Action 어휘에 있으나(`crates/qsh-core/src/acl/mod.rs:111`, 문자열은 `:152`) 어떤 규칙으로도 허용될 수 없다. `Action::is_always_denied`가 규칙을 보기도 전에 판정하는 gate이고(`crates/qsh-core/src/acl/mod.rs:169-172`), 평가 순서 1번이 그것이다(`crates/qsh-core/src/acl/policy.rs:10-14`, 구현은 `:211-218`). `allow = ["forward.*"]`가 삼키지 못한다.
   - (c) 이 action을 구동할 wire op이 0건이다. `ALWAYS_DENIED_NO_OP`이 그 부재와 사유를 표로 남기고(`crates/qsh-core/src/acl/registry.rs:391-396`), `DENY_SEAMS`(정의는 `crates/qsh-core/src/acl/registry.rs:95`)는 이 셋을 제외하며 그 제외 사유가 모듈 doc에 적혀 있다(`crates/qsh-core/src/acl/registry.rs:31-34`).
   - (d) capabilities에 광고하지 않는다. `LOCAL_CAPABILITIES`는 exec/session/resume.v1 셋뿐이고(`crates/qsh-proto/src/wire.rs:59`) fixture가 그것을 고정한다(`crates/qsh-cli/tests/fixtures/cli-v1/capabilities.json`, 메타 가드레일은 `docs/ROADMAP.md:161`).

3. 이미 테스트로 못 박힌 것 위에 새 계약 면을 만들지 않는다. 오늘 고정되어 있는 것은 golden fixture의 전체 봉투 동치(`crates/qsh-cli/tests/fixtures/cli-v1/error.UNSUPPORTED.json`, 등록은 `crates/qsh-cli/tests/fixtures.rs:113`, 대조는 `:317`), 두 spelling의 exit 255·`ok:false`·`UNSUPPORTED`·"P1" 포함 검사(`crates/qsh-cli/tests/dynamic_forward_stub.rs:53-65`, 헬퍼 doc `:42-51`, 파일 머리 `:1-24`가 `--json`과의 우선순위까지 규정), 문면이 README와 CLI.md에 축자로 남아 있는지 보는 문서-상수 대조(`crates/qsh-core/tests/tunnel_docs.rs:42-58`, 대상은 `README.md`(`:44`)와 `docs/CLI.md`(`:53`) 둘뿐), 항상-deny 3종의 단위·property test(`crates/qsh-core/src/acl/policy.rs:318`과 `:792`), registry 커버리지 앵커(`crates/qsh-core/src/acl/registry.rs:473-492`)다.

   같은 약속이 man page 두 곳에도 있고 그쪽에는 문서-상수 대조가 없다. `docs/man/qsh-tunnel-open.1:27`("Parses, but always answers `UNSUPPORTED` before opening a connection to `host` … implementation is P1")과 `docs/man/qsh.1:40`("P0 always refuses it with `UNSUPPORTED` before this session (or anything else on the command line) is opened — implementation is P1")이다. 후자의 "or anything else on the command line"은 `--json` 우선순위와 어긋난다. 그 우선순위는 `docs/CLI.md:507`과 `crates/qsh-cli/tests/dynamic_forward_stub.rs:9-15`가 규정한다. 대화형 form에 `--json`이 함께 오면 `-D`가 아니라 §7의 `INVALID_ARGUMENT`가 먼저 나온다.

   M9 (i)가 요구하는 "`-D` 현행 유지 문구"는 이 자산 위에 사람용 문면 하나를 더 얹는 일이고 새 표면이 아니다.

4. 유예 기간에 v1 wire에 SOCKS 자리를 미리 뚫지 않는다. `StreamKind`에 값을 예약해 두지 않는다. 오늘의 멤버는 0값 포함 다섯이고(`crates/qsh-proto/proto/qsh/wire/v1.proto:544-550`, 0값이 유효 kind가 아닌 이유는 `docs/design/protocol.md:521`), 그 집합 전체가 §16.1 동결 표의 한 행이다(`docs/design/protocol.md:462`). `Tunnel.mode`가 열린 문자열이라 미래 mode가 additive로 들어올 수 있다는 사실은 그대로 둔다(`crates/qsh-proto/src/types.rs:785`, 테스트가 "future SOCKS-adjacent mode"까지 명시해 고정한다: `crates/qsh-proto/src/types.rs:1722-1739`).

5. `-W`와 묶어 M10에서 함께 본다. `-W`는 ADR-0011 결정 5가 만들지 않기로 하고 M10 검토 항목으로 넘긴 것이다(`docs/adr/0011-remove-mcp-adapter.md:20`, ROADMAP 쪽 기록은 `docs/ROADMAP.md:143`). 둘 다 터널 표면을 일반 프록시로 확장하는 같은 축이라 따로 판정하면 같은 질문을 두 번 하게 된다. `docs/ROADMAP.md:143`은 오늘 `-W`만 적으므로 이 결정이 발효되면 그 행에 `-D`를 더한다.

6. 아래 "미결 질문" 절은 이 ADR이 확정하는 설계가 아니다. `docs/adr/README.md:3`이 정의한 ADR 절 구성(맥락·결정·근거·대안과 기각 사유·결과)에 없는 절이고 구현을 하기로 결정할 때 그 결정이 답해야 하는 항목만 적는다. 어느 항목도 결정으로 읽지 않는다. 특히 미결 질문 1(목적지 ACL 문법)과 2(역방향 egress)에 답이 없는 한 어떤 구현도 역방향 route에서 켜질 수 없다.

## 결과

- 유예 이유가 ROADMAP 표 한 행에서 문서로 올라온다. M9 (i)의 문면을 쓰는 사람이 인용할 대상이 생기고, DoD의 축자 테스트가 근거 없는 문장을 고정하는 일을 피한다.
- 사용자가 잃는 것은 목적지를 미리 정하지 않는 프록시 하나다. v1에서는 목적지마다 `-L`을 열어야 한다. 브라우저를 사내망 쪽으로 돌리는 용례는 오버레이로 처리하게 되는데 doctor의 처방이 이미 같은 도구(WireGuard/Tailscale)를 가리킨다(`crates/qsh-core/src/doctor.rs:160`).
- 실행 비용이 없다. 코드 변경 0줄이고 결정 3이 열거한 fixture·ACL·registry 테스트가 그대로 남는다. 바뀌는 문서는 셋이다. `docs/ROADMAP.md:152` 표 행이 이 ADR을 링크하고(선례: 같은 표의 ADR-0018 행, `docs/ROADMAP.md:158`), `docs/ROADMAP.md:143`의 M10 검토 항목에 `-D`가 더해지고(결정 5), `docs/adr/README.md` 색인에 0019 행이 들어간다. 색인 행은 같은 커밋에 넣어야 한다. `docs/ROADMAP.md:119`가 TOFU/pin 방향 축을 위해 번호 미배정 ADR 자리를 예약해 두었고 ADR-0017 결정 5(`docs/adr/0017-acl-toml-not-written.md:40`)가 그 자리를 미뤄 두었으므로, 색인에 등재되지 않은 0019는 두 제안이 같은 번호를 집는 경로가 된다.
- 기업망 사용성은 SOCKS로 개선되지 않는다. `udp_egress_blocked`가 뜨는 망에서는 `-D`가 있어도 붙는 연결이 0건이다. 막힌 것이 UDP/4433 자체이기 때문이다.
- P1에서 구현으로 뒤집을 때 wire 쪽 경로는 하나만 열려 있다. §16.4가 허용하는 additive 변경 목록(`docs/design/protocol.md:488-494`)에 "동결된 enum에 새 값 추가"가 없다. 그 목록이 실제로 허용하는 것은 새 `message`, 기존 oneof의 새 필드 번호, 예약 번호를 그 예약 대상으로 채우기, 새 capability 문자열과 그에 딸린 새 optional message(`:492`), 새 `ErrorCode` 문자열(`:493`), ADR-0018 결정 3의 `reclaim` 류 필드다. §16.5 금지 목록(`docs/design/protocol.md:496-501`)에도 enum 값 추가가 없으니 이것은 허용도 금지도 아닌 공백이다. 코드가 그 공백을 좁힌다. 모르는 kind는 조용히 무시되지 않고 스트림을 깬다(`crates/qsh-core/src/server/mod.rs:3809-3816`이 `RESET_CODE_BAD_HEADER`로 reset하고 `crates/qsh-proto/src/wire.rs:680-682`의 `stream_kind()`가 미지 값에 `None`을 준다). 무손실 passthrough가 있는 `ErrorCode`와 성격이 다르다. 따라서 결정 4를 뒤집을 때 쓸 수 있는 additive 지렛대는 가드레일 (d)가 이미 쥐고 있는 capability 문자열이고, enum 값 추가가 가능한지는 §16 발효 판정에 딸린다. §16 자체가 아직 "초안 — 발효 전"이다(`docs/design/protocol.md:441`, 발효 절차는 §16.10 `:527-530`).
- JSON 쪽 additive 여지는 `Tunnel.mode` 하나로 제한된다. 열린 문자열 field에 새 값을 더하는 것은 `docs/CLI.md:1136`이 허용한다. 같은 타입의 나머지 필드는 그렇지 않다. `forward_to`는 `Option`이 아니고 `skip_serializing_if`도 없으며 doc이 "the dial target"이라 못 박는다(`crates/qsh-proto/src/types.rs:788-791`). `TunnelOpenReq`의 `forward_host`/`forward_port`도 필수이고 `bind`만 `Option`이다(`crates/qsh-proto/src/types.rs:819-820`·`:826`·`:828`). 이 세 필드를 `Option`으로 바꾸는 것은 type 변경이고 빈 문자열이나 0을 "SOCKS라서 없음"으로 재해석하는 것은 의미 변경이라, 둘 다 `docs/CLI.md:1137`이 `/v2`를 요구하는 사유다.
- ACL 어휘에 `forward.socks`가 남아 있는 한 registry 커버리지 테스트(`crates/qsh-core/src/acl/registry.rs:473-492`)가 계속 그 행의 부재 사유를 요구한다. 구현을 켜는 순간 이 테스트가 빨개지는 것이 정상이며, 그것이 "action이 실제로 구동 가능해졌다"는 알람이다.
- M9 (i) 작업은 결정 3이 기록한 man page 공백을 어떻게 다룰지 정해야 한다. `crates/qsh-core/tests/tunnel_docs.rs`의 문서-상수 대조를 `docs/man/qsh.1`·`docs/man/qsh-tunnel-open.1`까지 확장할지, 공백을 기록만 하고 넘길지 둘 중 하나다. `docs/man/qsh.1:40`의 `--json` 우선순위 어긋남도 같은 작업에서 고칠 수 있다.

## 대안

- 지금 구현한다. 기각한다. 미결 질문 1이 `acl.toml` 계약 변경을 요구하고 미결 질문 2가 host 쪽 새 스위치를 요구한다. 둘 다 별도 결정인데 그 앞에 구현을 놓으면, default-deny 자세가 "SOCKS 허용 = 그 host 망 전체 egress 허용" 하나로 되돌아간다.
- `qsh mcp`처럼 표면을 깨끗이 지운다. 기각한다. ADR-0011의 대안 절 첫 항목이 바로 `-D`를 반례로 들어 "스텁은 'P1에 온다'는 약속의 표현"이라 적었고(`docs/adr/0011-remove-mcp-adapter.md:33`), PRD·CLI.md·ROADMAP 세 구속 문서가 `-D`를 P1로 약속한다. MCP와 달리 SOCKS는 돌아올 여지가 있다.
- `-D`를 "여러 `-L`의 축약"으로 재해석해 목적지 고정형으로 낸다. 기각한다. SOCKS 클라이언트는 프록시에 목적지를 런타임에 넘기므로 목적지를 미리 고정하면 브라우저나 SSH `ProxyCommand` 같은 실제 소비자가 붙지 않는다. `-L` 여러 개에 새 이름을 붙이는 것뿐이고, 얻는 것 없이 표면만 늘어난다.
- 정방향에서만 먼저 켜고 역방향은 금지한다. 기각하지 않고 미결 질문 2의 단계적 경로로 남긴다. 다만 정방향만 켜더라도 미결 질문 1의 목적지 문법은 그대로 필요하다. 정방향 host도 자기 망으로 나가는 무제한 egress가 되기 때문이다.

## 미결 질문 (구현 결정이 답해야 할 것)

결정 6이 적은 대로 이 절에는 결정이 없다. 각 항목은 질문과 후보이고, 고르는 것은 구현을 하기로 하는 결정의 몫이다.

1. 목적지를 ACL로 제한할 문법을 어디에 어떤 모양으로 만드는가. 오늘 `Rule`은 principal·auth_path·allow·scope 넷뿐이고(`crates/qsh-core/src/acl/policy.rs:123-137`), `Policy::decide`가 자원에서 보는 것은 `owner` 하나다(`crates/qsh-core/src/acl/policy.rs:233-236`; `ResourceRef`는 `id`와 `owner` 둘을 들고 있다, `crates/qsh-core/src/acl/mod.rs:286-293`). 즉 `crates/qsh-core/src/server/mod.rs:3335`의 `format_host_port`가 만든 `host:port` 문자열은 판정에 쓰이지 않고 audit에만 남는다. `-L`은 목적지 제한을 정책 엔진 소관으로 명시적으로 넘겨 놨지만(`crates/qsh-core/src/server/mod.rs:3287-3290`: "restricting destinations is the policy engine's job (M5), not this code's") 그 문법은 아직 존재하지 않는다. SOCKS는 목적지가 런타임에 임의로 정해지는 것이 본질이므로, 목적지 allow-list 문법 없이 SOCKS를 허용하면 그 host가 닿는 망 전체로 나가는 무제한 egress를 허용하는 셈이다. 문법 신설은 `acl.toml` 계약 변경이라 별도 ADR 몫이고 SOCKS 구현의 선행 조건이다.

2. 역방향 route에서 SOCKS를 켤 수 있는가, 켠다면 무엇이 그것을 끄고 있는가. 역방향 위의 `-L`은 controller가 `TCP_CONNECT`를 여는 쪽이고 target이 dial한다(`docs/design/protocol.md:313`). 같은 구도로 controller 쪽에 SOCKS listener를 놓으면 target이 자기 망에 대한 범용 egress proxy가 된다. 사내 노트북이 `serve --to`(M9 (b), `docs/ROADMAP.md:118`)로 등록된 target이면, controller를 쥔 쪽은 그 노트북이 닿는 망 전체에 임의 포트로 나갈 수 있다. 오늘 이것이 성립하지 않는 이유는 목적지마다 `-L`을 명시적으로 열어야 하고 그 목적지가 ACL 자원 문자열이자 audit 대상이기 때문이다(`crates/qsh-core/src/server/mod.rs:3342`의 `authorize_stream`이 allow와 deny 양쪽 결과를 audit에 쓴다. 주석은 `:3337-3341`). 미결 질문 1의 목적지 문법과 역방향 route에서 SOCKS를 기본 off로 두는 host 쪽 스위치가 둘 다 있어야 역방향에서 켤 수 있다. 그 스위치가 어느 계약 면에 사는지도 미결이다. `[serve].max_tunnel_streams_per_forward`/`per_principal`(`docs/design/protocol.md:84`) 같은 config 키 쪽이 선례이고, 미결 질문 1과 같은 성격의 인가 문법이라면 `acl.toml`과 함께 그 ADR 몫이다.

3. stream kind를 새로 만드는가 `TCP_CONNECT`를 재사용하는가. 이 선택이 나머지 대부분의 전제다.
   - 선택지 A: `StreamKind`에 값을 하나 더한다. host 쪽에 새 dispatch 분기와 새 ACL seam이 생기고 그 seam이 `forward.socks`를 처음으로 구동 가능하게 만든다. `ALWAYS_DENIED_NO_OP`에서 그 행을 빼고(`crates/qsh-core/src/acl/registry.rs:391-396`) `DENY_SEAMS`(`:95`)에 행을 더하고 `Action::is_always_denied`에서 `ForwardSocks`를 떼야 하며(`crates/qsh-core/src/acl/mod.rs:169-172`), 그러면 `crates/qsh-core/src/acl/policy.rs:318`·`:792`와 `crates/qsh-core/src/acl/registry.rs:473-492`이 함께 빨개진다. 값 번호는 여기서 고르지 않는다. 결과 절이 적은 대로 동결된 enum에 값을 더하는 것이 §16.4 허용 목록에 없고(`docs/design/protocol.md:488-494`), 번호 배정과 그 허용 여부 판정은 구현 PR과 §16 발효 판정(`docs/design/protocol.md:441`, `:527-530`)의 몫이다.
   - 선택지 B: 기존 `TCP_CONNECT`를 재사용한다. wire는 건드리지 않는다. SOCKS5 CONNECT 협상을 client 쪽에서 끝내고 목적지 `host`/`port`만 `StreamHeader`에 실으면 host 쪽 경로는 오늘의 `-L`과 동일하다(`crates/qsh-proto/proto/qsh/wire/v1.proto:552-560`, `docs/design/protocol.md:73`). 대가로 권한 분리를 잃는다. host 쪽 판정이 `forward.local`로 떨어지고 `forward.socks`는 영구히 구동 불가능한 action으로 남는다. "SOCKS를 `-L`과 별개 권한으로 줄 수 있어야 한다"는 요구가 실제로 있는지가 A와 B를 가르는 질문이다.

4. SOCKS listener를 기존 `tunnel.open`/`Tunnel`로 표현하는가 별도 op으로 내는가. 기존 필드를 재해석하는 길은 선택지가 아니다. 결과 절이 적은 대로 `forward_to`/`forward_host`/`forward_port`는 필수 필드이고(`crates/qsh-proto/src/types.rs:788-791`·`:826`·`:828`) SOCKS listener에는 단일 dial target이 없어, `Option`화는 type 변경, 빈 값 재해석은 의미 변경이라 둘 다 `docs/CLI.md:1137`상 `/v2` 사유다. `mode`에 값을 더하는 것만 `docs/CLI.md:1136`의 열린 문자열 규칙 안에 있다.

5. listener의 bind 규율과 지원 command 집합을 무엇으로 두는가. 같은 쪽·같은 층의 선례는 `-L`의 client 쪽 listener다. 모듈 doc이 규율과 이유를 함께 적는다. "The listener binds loopback, full stop: with no `bind:` prefix it defaults to `127.0.0.1`, and an explicit non-loopback `bind:` is refused rather than honored". 이유도 같은 doc에 있다. 로컬 forward 포트는 이 머신의 credential로 peer와 말하므로 LAN 인터페이스에 노출하면 그 망의 모든 host가 인가를 우회한다(`crates/qsh-core/src/tunnel/local.rs:20-27`). 오류 등급은 `ErrorCode::InvalidArgument`이고 `UNSUPPORTED`가 아니다(`crates/qsh-core/src/tunnel/local.rs:119-124`). 두 variant 모두 pre-listener라 실패하면 아무것도 bind되지 않는다(`:115-116`). 해석 지점은 `loopback_bind_addr`(`crates/qsh-core/src/tunnel/local.rs:604-615`)이고 호출은 `:225`다. `-R`의 loopback 강제(`docs/design/protocol.md:90`)는 host 쪽, control 왕복 뒤의 판정이므로 보조 비교로만 쓴다. loopback 전용을 채택하면 딸려 오는 것이 하나 있다. `-D`의 인자 모양은 이미 `[bind:]port`로 문서화돼 있고(`docs/CLI.md:507`, `crates/qsh-cli/src/cli.rs:125`의 `value_name = "SPEC"`) P0에서는 값이 전혀 파싱되지 않으므로, 비-loopback `bind:` 접두가 `INVALID_ARGUMENT`가 되는 것은 이미 문서에 있는 인자 모양에 새 거절을 얹는 일이고 `docs/CLI.md` 개정이 따른다. command 집합 쪽 후보는 CONNECT만 받고 BIND와 UDP ASSOCIATE는 SOCKS5 REP `0x07`(command not supported)로 답하는 것, 인증 method는 no-auth 하나만 광고하는 것이다. 후자의 근거 후보는 loopback 전용 소켓에 자체 인증을 더해도 같은 uid 안에서는 의미가 없다는 것이고 localctl이 UDS accept 시점에 same-uid peer credential을 확인하는 축(`docs/design/protocol.md:315`)과 성격이 같다.

6. REP 코드 매핑을 무엇으로 두는가. SOCKS5 응답은 REP 1바이트뿐이라 qsh의 `ErrorCode`(`crates/qsh-proto/src/error.rs:36-68`)가 한 바이트로 접힌다. 오늘 dial 경로는 resolve 실패에 `HostNotFound`를, connect 실패에 `ConnectionFailed`를 낸다(`crates/qsh-core/src/tunnel/dial.rs:59-63`; 실제 resolve는 `:145`의 `lookup_host`로 host 쪽에서 일어나므로 원격 DNS다). 후보 매핑은 `HostNotFound` → `0x04`(host unreachable), `ConnectionFailed` → `0x05`(connection refused), `PermissionDenied` → `0x02`(connection not allowed by ruleset), `ResourceExhausted` → `0x01`(general failure), `InvalidArgument` → 명령이면 `0x07`·주소 형식이면 `0x08`, 그 외 → `0x01`이다. 접혀 사라지는 정보를 stderr 진단으로만 남기고 stdout에 쓰지 않는 것도 같은 결정에 딸린다. 어느 매핑을 고르든 구현 PR이 축자 테스트로 고정할 대상이며, `ConnectResult{ok:false, code}`의 code 어휘가 CLI.md §3.3에서 온다는 규칙(`docs/design/protocol.md:78`)이 그 입력이다.

7. quota 축을 그대로 쓰는가. `Quotas::reserve_tunnel_stream`이 `(principal, host:port)` 축으로 `[serve].max_tunnel_streams_per_forward`(기본 64)와 `max_tunnel_streams_per_principal`(기본 256)을 ACL 이후·dial 이전에 검사한다(`crates/qsh-core/src/server/mod.rs:3352-3361`, 호출은 `:3361`, 규칙은 `docs/design/protocol.md:84`, 맵 정의는 `crates/qsh-core/src/quota.rs:296-302`). SOCKS는 목적지가 흩어지므로 per-forward 축이 사실상 무력해지고 per-principal 축이 유일한 실효 상한이 된다. 구현 PR이 이 비대칭을 의식해야 하고 SOCKS 활성 시 per-principal 기본값을 따로 둘지가 질문으로 남는다. 역방향 relay에는 hub 상한(`MAX_TUNNEL_STREAMS_PER_HUB` = 64, `docs/design/protocol.md:315`)이 추가로 걸린다.

8. `-W`와의 선후를 어떻게 두는가. ADR-0011 결정 5가 `-W`를 만들지 않기로 하고 M10 검토로 넘겼다(`docs/adr/0011-remove-mcp-adapter.md:20`, `docs/ROADMAP.md:143`). `-W`는 stdio와 원격 TCP를 잇는 브리지 하나이고 목적지가 호출 시점에 고정되므로 미결 질문 1·2가 걸리지 않는다. SOCKS보다 훨씬 싸다. M10에서 프록시류 표면을 볼 때 `-W`를 먼저 판정하고 `-W`로 해결되지 않는 용례만 SOCKS 쪽에 남기는 순서가 후보다.

9. 크기 산정. 2026-09-16 설계 검토가 2.4~3.2ew로 잡았고 저장소 문서에 근거가 없다. 단위는 ROADMAP과 같은 ew이며 비교 대상은 M9 4.3ew(`docs/ROADMAP.md:127`), M8 3ew(`docs/ROADMAP.md:114`), M10 1.5ew(`docs/ROADMAP.md:142`)다. 내역은 client 쪽 SOCKS5 상태기계와 REP 매핑, 목적지 ACL 문법 신설, 역방향 스위치와 그 테스트, fixture·`cli_v1` schema·man·CLI.md 반영이다. 목적지 문법을 별도 ADR과 별도 PR로 떼면 그 몫은 여기서 빠진다.
