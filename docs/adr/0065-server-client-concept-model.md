# ADR-0065: qsh는 server와 client 두 개념으로 설명한다. 역방향(reverse)은 고급 fallback으로 내린다. 1단계는 문서와 도움말만 고치고, 제거 여부(2단계)는 사용을 확인한 뒤로 미룬다

날짜: 2026-11-13
상태: 승인됨 (2026-11-13 Dave 결정. "iroh든 ut든 이런 transport를 사용하면 언제든 서로 상대방에게 연결을 걸 수 있게 되니까, forward, reverse가 아니라 server, client 개념으로 다시 단순화")

개정 이력: 2026-11-14에 [ADR-0066](0066-doctor-device-mode.md)이 server·client 개념을 `qsh doctor`의 보고에 연결했다. doctor가 장비를 client 또는 server로 판정하고 `data.mode`로 말하며, client 전용 장비에서는 인바운드 점검을 하지 않는다. 결정 5가 말한 "계약 변경을 하지 않는다"는 1단계의 문서·도움말 범위에 대한 것이고 이 변경은 additive다. 결정과 본문은 고치지 않았다.

개정 관계: 동작과 계약을 고치는 ADR이 아니다. 다음 서술의 틀(무엇이 기본이고 무엇이 예외인가)만 고친다.
- ADR-0012 결정 1의 역할 표(셸을 내주느냐/얻느냐 × 인바운드를 받느냐/밖으로 dial하느냐). 표 자체는 정확하고 그대로 두지만, 사용자에게 먼저 보이는 설명이 아니라 고급 절의 정의로 옮긴다.
- ADR-0059의 "한 `qsh listen` 프로세스가 인바운드 `qsh serve`도 겸한다"는 합친 endpoint의 동기. 합친 모드는 역방향 등록을 받는 장비가 정방향도 받기 위한 길이었다. 기본 경로(`qsh serve`)에서는 이 합치기가 필요 없다.
- ADR-0061의 "iroh relay route는 직결이 막힌 망을 위한 선택 사항"이라는 위치. ADR-0063이 기본으로 켠 뒤로 relay는 선택 사항이 아니라 장비끼리 닿는 기본 경로의 일부다(결정 2).

개정하지 않는 것: `qsh.cli/v1`·`qsh.event/v1` 계약과 fixture, ALPN `qsh/1`과 wire(`docs/design/protocol.md` §16 freeze), `Hello.reverse`와 capability, `ErrorCode`와 role·액션 어휘(`host.reverse`, role `reverse` 포함), 기본 거부와 단일 choke point, 모든 명령과 플래그의 동작(`qsh listen`, `qsh serve --to`, `qsh reverse` 숨김 alias, `[listen]`·`[serve].to` 키 포함), 홀펀칭의 중개자 규칙(ADR-0054 결정 20), doctor 문안(`CONTROLLER_UNREACHABLE` 포함).

## 맥락

qsh는 처음에 직결(direct dial)만 있었다. 연결을 거는 쪽이 도달 가능한 주소를 알아야 했으므로 NAT 뒤 장비는 상대에게 걸 수 없었고, 그 대책으로 정방향(client가 host에 dial)과 역방향(host가 controller에 dial해 등록하고 controller가 그 연결 위에서 client 노릇을 함)을 둘 다 일급으로 만들었다(PRD §4 "연결 방향과 역할의 분리", ADR-0012). 문서와 도움말은 지금도 이 두 방향이 먼저 나오고, 사용자는 `serve`, `listen`, `serve --to`, controller, target, host, client 일곱 어휘를 알아야 한다.

그 뒤 경로가 바뀌었다.
- ADR-0061·0062가 키로 주소를 정하는 iroh route를 더했다. pin의 `key`가 곧 endpoint 주소이고, relay(HTTPS, TCP 443)로는 항상 닿으며 직결이 되면 같은 연결 안에서 직결로 승격한다.
- ADR-0063이 데몬의 iroh endpoint를 기본으로 켜고 pin을 이름·키·role만으로 서게 했다. ADR-0064는 데몬이 공유기에 포트 매핑을 요청하게 해서 완전 대칭 NAT 뒤의 상대도 직결로 서게 했다.
- Dave의 말처럼 iroh든 앞으로 더할 ut든 키 기반 transport를 쓰면 어느 장비든 상대에게 언제든 연결을 걸 수 있다. 연결을 누가 시작하느냐가 도달 가능성을 가르지 않는다.

그러면 역방향이 풀던 문제("NAT 뒤 장비에 걸 수 없다")는 기본 경로가 이미 푼다. 남는 것은 그 경로가 막힌 경우뿐이다. 개념을 둘로 줄이고 나머지를 예외로 내리자는 것이 이 결정이다.

## 결정

1. **개념은 server와 client 둘이다.**
   - server는 `qsh serve`다. 장비마다 하나를 두고, 신뢰한 peer의 연결을 받아 셸·exec·터널·파일을 내준다. 인가는 지금처럼 pin의 role과 `acl.toml`이 정한다.
   - client는 `qsh <host>`, `qsh exec`, `qsh tunnel`, `qsh cp`, `qsh attach` 같은 명령이다. server에 연결을 걸어 쓴다.
   - 한 장비가 server이면서 client인 것은 평범한 일이다. 어느 장비의 server든 신뢰한 다른 장비의 client가 걸 수 있다.
2. **연결 방향은 도달 가능성을 정하지 않는다.** pin에 `key`가 있으면 relay로는 항상 닿고, 직결·홀펀칭·포트 매핑이 되면 직결로 선다. "NAT 뒤라서 걸 수 없으니 방향을 뒤집는다"는 기본 안내가 아니다. 가장 짧은 설정은 `trust.toml`의 pin 하나(이름, 키, role)다(ADR-0063).
3. **역방향은 고급 fallback이다.** `qsh listen`, `qsh serve --to`, `qsh reverse`(숨김 alias), controller 등록, 합친 endpoint(ADR-0059)가 여기에 든다. 다음 경우에만 안내한다.
   - 망이 relay(TCP 443 HTTPS)를 막아서 키만으로는 닿지 못하는 경우. 이때 target이 controller의 공인 UDP 주소로 dial한다.
   - 설정이 `[iroh].enable = false`이거나 상대가 iroh를 쓰지 않는 peer인 경우(사설 CA 모드는 iroh route가 `UNSUPPORTED`, ADR-0061 결정 4).
   - 특정 장비를 거치는 jump 체인(iroh route로 hop을 열지 못한다, ADR-0061 결정 14)이나 그 장비를 홀펀칭 중개자로 쓰는 구성(ADR-0054 결정 20, ADR-0056).
4. **문서 구성.** `docs/PRD.md`, `docs/CLI.md`, `README.md`는 처음에 server와 client만 설명하고, 역방향은 "고급: 역방향 fallback"이라는 제목 아래에 둔다. 도움말(`qsh serve --help`, `qsh listen --help`, `qsh serve --to`)은 listen과 `--to`가 "상대끼리 iroh로 닿지 못할 때의 fallback"임을 첫머리에 적는다. controller·target은 고급 절 안의 용어로 남긴다.
5. **1단계의 범위는 문서와 도움말이다.** 코드 제거, 동작 변경, 계약 변경(`qsh.cli/v1`, fixture, wire, JSON 필드, 오류 코드, doctor 문안)은 하지 않는다. 명령·플래그·설정 키는 하나도 사라지거나 뜻이 바뀌지 않는다. `docs/CLI.md`는 절 번호와 계약 문장을 그대로 두고 머리말과 제목, 도입 문단만 고친다.
6. **2단계(제거할지 정하기)는 미룬다.** 지금은 판단할 증거가 없다. 사용을 확인한 뒤 새 ADR로 정한다. 제거를 정당화하려면 다음이 모두 필요하다.
   - Dave의 장비에서 역방향을 실제로 쓰는지: 허브 장비 audit의 `host.reverse` 허용 기록, 상시 `qsh listen`·`qsh serve --to` 프로세스와 service unit(`qsh service status`), `[listen]`·`[serve].to` 설정이 일정 기간 없다는 확인.
   - relay가 막힌 망이나 iroh를 못 쓰는 peer에서 역방향이 유일하게 연결을 살린 사례가 없다는 확인(그 반대의 사례가 하나라도 있으면 fallback으로 남긴다).
   - 홀펀칭 중개자(ADR-0054)와 jump(ADR-0056)가 listener에 기대는 부분의 대체 경로. 중개자를 다른 것으로 바꿀 수 없으면 `qsh listen`은 남는다.
   - 공용 n0 relay에 대한 의존 판단(ADR-0062: 약관·rate limit이 바뀔 수 있다). 자체 relay를 쓰는 구성이 안정적인지.
   - wire freeze(`docs/design/protocol.md` §16) 영향. `Hello.reverse`, capability, 액션 `host.reverse`, role `reverse`는 wire와 `qsh.cli/v1` 계약이므로 코드를 지워도 wire 쪽은 남길 가능성이 높다. 그 판단도 새 ADR에서 한다.
   - 제거하지 않기로 하는 결론도 열려 있다. 그 경우 이 ADR의 1단계 문서 구성이 최종 모양이다.

## 근거

- 사용자가 외워야 하는 모델이 둘이면 첫 사용이 짧아진다. 역방향 어휘 다섯은 대부분의 사용자에게 필요 없다.
- 기본 경로가 이미 방향 문제를 푼다. 같은 목적의 기능이 둘이면 문서의 앞자리를 기본 경로가 가져야 한다.
- 코드를 지우지 않으므로 위험이 없다. 합친 endpoint, 홀펀칭 중개자, jump, 서비스 유닛, 자동화가 기대는 동작이 그대로다. 되돌릴 것도 없다.
- 제거는 증거로 정한다. 지금 알고 있는 것은 "iroh가 기본이 됐다"이지 "역방향이 안 쓰인다"가 아니다. relay가 막힌 망(회사망 등)에서는 역방향이 유일한 길일 수 있다.

## 결과

- 처음 읽는 사람은 server와 client만 보면 된다. 역방향 절은 필요할 때 찾아 읽는다.
- `qsh --help`와 `qsh serve|listen --help`의 첫 줄이 바뀌고 man 페이지(`docs/man/`)가 다시 생성된다. 도움말 문구를 고정한 golden 시험은 없다. fixture는 건드리지 않는다.
- ADR-0012 결정 1의 역할 표, PRD §4와 §6의 "정방향/역방향" 소제목, CLI.md §6.12·§6.13의 도입 문단과 README의 Reverse connections 절이 이 틀에 맞춰 다시 배치된다. 계약 문장은 그대로다.
- 2단계가 열리기 전까지 역방향 기능의 유지 비용(합친 endpoint, 감시 예산, registry)은 그대로 든다.

## 기각한 대안

- **지금 역방향을 제거한다.** 사용을 확인하지 않았고 wire freeze, 홀펀칭 중개자, jump, relay가 막힌 망이 걸려 있다. 결정 6이 이 판단을 따로 둔다.
- **아무것도 바꾸지 않고 문서에 iroh 얘기만 더한다.** 역방향 어휘가 계속 앞에 나오고 모델이 셋(정방향, 역방향, relay)이 된다.
- **명령 이름을 바꾼다**(`qsh listen`을 `qsh fallback-listen`으로 등). 계약 변경이고 ADR-0012가 정한 이름 규약과 숨김 alias 약속을 다시 건드린다. 1단계 범위 밖이다.
- **`qsh listen`과 `serve --to`를 `qsh --help` 목록에서 숨긴다.** 사용자가 fallback이 필요할 때 찾을 수 없게 된다. 목록에는 두고 설명만 낮춘다.

## 개정 이력

- 2026-11-13 승인. 1단계(문서·도움말)만 적용한다. 2단계 판정은 사용 확인 뒤 별도 ADR로 한다.
