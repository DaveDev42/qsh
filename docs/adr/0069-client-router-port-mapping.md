# ADR-0069: client의 iroh endpoint도 공유기에 포트 매핑을 요청한다

날짜: 2026-11-23
상태: 승인됨 (2026-11-23 Dave 결정. 집 client에서 Office로 가는 연결이 모두 relay였다는 기록을 근거로, client endpoint도 짧은 수명 매핑을 요청하는 안을 선택)

개정 관계: ADR-0064 결정 3("client endpoint는 매핑하지 않는다")과 기각한 대안 "client endpoint도 매핑하기"를 고친다. 데몬 쪽 결정 1·2·4~7은 그대로다.

## 맥락

ADR-0064는 client가 매핑해도 얻는 것이 없다고 봤다. client는 상대가 먼저 보낼 일이 없다는 이유였다. 현장 기록은 그렇지 않다는 것을 보인다.

- **연결 종류별 경로(conn-watch 표본, 2026-11-17~23).** Office(완전 대칭 NAT 뒤, ADR-0064 맥락)가 집 데몬(고정 `[iroh].bind_port`와 매핑)으로 여는 새 연결은 750회 중 668회 직결이었다. 같은 집의 client가 Office로 여는 `qsh exec`는 Dave-Windows-WSL에서 2,507회, Dave-MBP16에서 1,578회 모두 relay였고 직결은 0회였다.
- **원인.** 직결이 서려면 대칭 NAT 쪽이 상대의 고정된 외부 주소로 먼저 보내고 그 패킷이 상대 NAT를 통과해야 한다. 데몬은 매핑이 그 주소와 통과를 둘 다 준다. client는 명령마다 임의 포트로 열리고(`bind_client`, `crates/qsh-transport/src/iroh_backend/endpoint.rs`) 매핑이 없다. 집 공유기는 안에서 먼저 보낸 적 없는 주소·포트에서 온 패킷을 버린다. client는 Office가 쓸 포트를 예측할 수 없으니 먼저 길을 열 수도 없다. 결과는 대칭 NAT 두 개 사이와 같다.
- **iroh hole punching은 양쪽이 보낸다.** 상대가 먼저 보낼 일이 없다는 ADR-0064의 전제는 틀렸다. client가 relay로 붙은 뒤 iroh는 양쪽 후보 주소를 relay로 교환하고, 양쪽이 서로의 후보로 보낸다. client의 후보에 매핑 주소가 있으면 Office가 그리로 보낸 패킷이 공유기를 통과한다. 데몬 쪽에서 실측한 효과(ADR-0064 43/50, 위 668/750)와 같은 구조다.
- **jump로는 풀리지 않는다.** `-J <데몬 host>`는 hop이 UDP를 임시 소켓으로 옮길 뿐 hop 데몬의 매핑된 endpoint로 다음 hop을 열지 않고(`crates/qsh-core/src/server/jump.rs`, ADR-0056), 주소 없는 iroh pin은 hop과 대상 어느 쪽으로도 쓸 수 없다(ADR-0061 결정 14).

## 결정

1. **client의 iroh endpoint도 매핑을 요청한다.** `bind_client`로 여는 endpoint는 `[iroh].portmap`이 `true`이면(기본) 데몬과 같은 qsh portmapper client(PCP·NAT-PMP 우선, ADR-0064 2026-11-17 개정)로 자기 IPv4 UDP 포트의 매핑을 요청하고, 받은 외부 주소를 후보에 더한다. `portmap = false`면 지금처럼 요청하지 않는다. client 명령은 명령마다 설정을 읽으므로 이 키의 client 쪽 효과는 다음 명령부터다.
2. **매핑은 연결을 기다리게 하지 않는다.** dial은 지금처럼 relay와 알려진 후보로 바로 시작한다. 매핑이 서면 그 주소가 후보에 더해지고 iroh가 직결로 올린다. 매핑이 늦거나 안 서면 relay에 머문다. 매핑 대기 때문에 명령의 첫 바이트가 늦어지면 안 된다.
3. **끝날 때 지운다.** client 매핑의 수명과 갱신은 데몬과 같은 portmapper 기본값(PCP 1시간, NAT-PMP·UPnP 2시간, 수명의 절반에서 갱신)이다. endpoint를 닫을 때 지운다. 비정상 종료에서는 공유기가 그 수명이 지난 뒤에 지운다.
4. **게이트웨이가 공유기가 아니면 아무 일도 없다.** NAT 모드 VM(WSL2 기본 NAT 등)의 기본 게이트웨이는 호스트의 가상 NAT이라 PCP·NAT-PMP에 답하지 않는다. 그런 client는 지금처럼 relay다. 이 ADR은 그 경우를 고치지 않는다.
5. **시험은 공유기에 묻지 않는다.** ADR-0064 결정 7을 client에도 적용한다. 손으로 만든 client 설정의 기본값은 `false`이고 설정 파일에서 오는 값만 기본 `true`다.

## 근거

- 기록상 relay에 묶인 연결은 모두 집 client에서 Office로 가는 쪽이다. 매핑이 데몬 쪽에서 만든 효과를 client에 그대로 주는 가장 작은 변경이다.
- 공유기 표에 항목이 명령마다 생기는 비용은 종료 시 삭제로 줄인다. PCP·NAT-PMP 요청은 게이트웨이로 가는 UDP 한두 개다. SSDP(UPnP)는 v0.9.1 portmapper client가 PCP·NAT-PMP를 먼저 묻고 실패할 때만 쓴다.
- 인가는 달라지지 않는다. client endpoint는 inbound 연결을 받지 않는다. 매핑은 자기가 연 연결의 경로 후보를 하나 더할 뿐이다.

## 결과

- **공유기에 짧은 항목이 생긴다.** client가 도는 동안 UDP 매핑 하나가 생기고 끝나면 지워진다. 같은 LAN의 다른 장비가 게이트웨이 표에서 볼 수 있다.
- **짧은 명령은 효과가 적다.** 매핑과 직결 승격(수백 ms~수 초)보다 먼저 끝나는 `qsh exec ... true`는 relay로 끝날 수 있다. 대화형 세션, 터널, 파일 복사처럼 오래 가는 연결이 얻는다.
- **현장 확인.** 착지 뒤 Dave-MBP16(집)과 Dave-Windows에서 Office로 여는 연결의 직결 비율을 다시 재고 개정 이력에 적는다. Dave-Windows-WSL은 결정 4로 relay가 남는다.
- **고칠 문서.** `docs/CLI.md` §6.23의 `[iroh].portmap` 설명, `docs/design/architecture.md`의 portmap 절, `docs/design/threat-model.md`의 매핑 행.

## 기각한 대안

- **`-J`가 hop 데몬의 iroh endpoint로 다음 hop을 열게 하기.** hop이 QUIC을 직접 맺고 그 위로 client의 안쪽 QUIC을 실어야 해서 ADR-0056의 "hop은 패킷을 만들지 않는다"를 뒤집는다. 새 stream 종류와 capability가 필요하고, ADR-0061 결정 14가 요구한 iroh 위 QUIC-in-QUIC 시험도 남아 있다. 장비가 어디 있든 직결 한 hop을 주는 장점은 크지만 비용이 이 ADR보다 훨씬 크다.
- **client가 같은 장비의 데몬 endpoint를 빌려 쓰기.** 데몬이 도는 장비에서만 효과가 있고, 데몬 키와 client 키를 섞는 인증 변경이 따른다. Dave-MBP16은 데몬을 돌리지 않는다.
- **WSL을 mirrored 네트워킹으로 바꾸기.** qsh가 아니라 배치(`.wslconfig`)의 결정이고, 결정 1이 착지한 뒤에야 효과가 있다. 따로 정한다.

## 개정 이력

- 2026-11-23 초안.
- 2026-11-23 승인(Dave 결정, "모두 다 진행해줘"). WSL mirrored 전환과 relay 선택은 배치 쪽에서 따로 진행한다.
- 2026-11-23 결정 3을 고쳤다. 초안의 수명 10분은 `portmapper` 0.19.3이 수명을 상수로 박아 두고(`pcp.rs` 1시간, `nat_pmp.rs`·`upnp.rs` 2시간) 설정으로 받지 않아 지금 의존성으로 만들 수 없다. crate를 고치거나 iroh와 묶인 버전을 올리는 대신 기본 수명과 종료 시 삭제를 받아들인다. 비정상 종료한 client의 항목은 공유기에 최대 2시간 남는다.
