# ADR-0064: 데몬의 iroh endpoint는 기본으로 공유기에 포트 매핑을 요청한다(UPnP·NAT-PMP·PCP)

날짜: 2026-11-13
상태: 승인됨 (2026-11-13 Dave 결정. 실측에서 포트 매핑을 켠 probe는 MacMini와 Toss가 43/50 직결로 섰고 qsh는 구조상 0%여서, 데몬 endpoint가 공유기에 매핑을 요청하는 것을 기본으로 켜고 client endpoint는 켜지 않는다고 선택)

개정 관계: ADR-0054 결정 8의 "공유기에 묻는 프로토콜(UPnP·NAT-PMP·PCP)도 쓰지 않는다"와 기각한 대안의 "UPnP·NAT-PMP·PCP로 공유기에 포트를 연다"(M24 밖으로 미룸)를 데몬의 iroh endpoint에 한해 고친다. ADR-0061은 iroh를 기본 빌드에 넣으면서(결정 13) `Cargo.toml`의 기능 목록에서 portmapper를 뺐는데, 그 목록에 `portmapper`를 더한다. ADR-0061의 결정 본문은 바뀌지 않는다. 펀칭(`punch.v1`)의 범위와 방식, 나머지 결정은 그대로다. 같은 결정의 나머지와 ADR-0061·0062·0063의 다른 결정도 그대로다.

## 맥락

2026-11-13 현장 측정이다. 회사 Mac(Toss)은 TITAN 뒤에 있고, TITAN은 주소와 포트 모두에 따라 매핑이 달라지고 필터링도 하며 포트를 임의로 고르는 완전 대칭 NAT다. 이 망의 장비는 상대가 먼저 보낸 패킷이 없으면 자기 공인 포트를 상대에게 알릴 수도 없고, 상대가 그 포트를 맞힐 수도 없다. 그래서 두 끝이 동시에 보내는 펀칭(ADR-0054)이 서지 않는다(ADR-0054 결정 23의 기대 표에서 (symmetric, port_restricted)와 (symmetric, symmetric)이 실패하는 이유와 같다).

같은 날 두 가지를 실측했다.

- **iroh 기본 기능을 모두 켠 probe(`iroh-probe`)**: MacMini와 Toss 사이가 50회 중 43회 직결로 섰다. iroh의 portmapper가 MacMini 쪽 공유기에서 UPnP/NAT-PMP/PCP로 매핑을 받아 그 주소를 후보로 알렸고, 대칭 NAT 뒤의 상대가 그 주소로 먼저 보낼 수 있었기 때문이다.
- **qsh 0.8.0**: iroh를 `default-features = false`로 들여서 portmapper가 빠져 있다(`Cargo.lock`에 `portmapper`가 없다). 데몬이 알리는 주소는 인터페이스 주소(`Local`)와 relay의 주소 발견이 알려 준 공인 주소(`Qad`) 둘뿐이고, 대칭 NAT 뒤의 상대에게 `Qad` 주소는 닫혀 있다. 직결은 구조상 0%였다.

ADR-0054는 공유기에 묻는 프로토콜을 M24 밖으로 미뤘다. 이유는 공유기 설정을 바꾸는 부수효과가 있고 집 밖 망에서는 대개 없다는 것이었다. 둘 다 사실이다. 그러나 이 결정이 막으려던 일은 이 측정으로 값을 갖게 됐다. 상시 떠 있는 데몬이 집이나 사무실의 공유기 뒤에 있는 경우에는 매핑이 대칭 NAT 뒤의 client가 직결로 서는 유일한 방법이다.

## 결정

1. **데몬의 iroh endpoint는 공유기에 포트 매핑을 요청한다.** `qsh serve`와 `qsh listen`(합친 모드 포함)이 띄우는 endpoint는 iroh의 portmapper(UPnP, NAT-PMP, PCP)로 자기 IPv4 UDP 포트의 매핑을 공유기에 요청하고, 받은 외부 주소를 다른 후보 주소와 함께 상대에게 알린다. 대칭 NAT 뒤의 상대가 그 주소로 먼저 보내 직결로 승격한다. 매핑은 iroh의 portmapper가 갱신하고(요청 수명은 UPnP 2시간, PCP 1시간이고 절반이 지나면 갱신한다), endpoint가 닫히면 해제한다. 프로세스가 죽으면 공유기에서 수명이 끝나면서 사라진다.
2. **`[iroh].portmap`(bool)이 스위치이고 없으면 `true`다.** `portmap = false`를 적으면 공유기에 아무것도 묻지 않는다. 이 키는 데몬이 시작할 때 한 번 읽는다(`applies_from: next_start`). `[iroh].enable = false`나 `serve`·`listen`에 준 전역 `--no-iroh`는 endpoint 자체가 없으므로 매핑도 없다. 그 경우 `portmap`은 읽어도 쓰이지 않는다.
3. **client endpoint는 매핑하지 않는다.** 명령마다 새 임의 키로 열리는 client endpoint(`bind_client`)는 `[iroh].portmap`과 관계없이 portmapper를 `Disabled`로 명시해서 연다. iroh의 `portmapper` 기능을 빌드에 넣으면 portmapper 설정의 기본값이 `Enabled`가 되므로 설정을 비워 두지 않고 항상 값을 넘긴다. `qsh serve --to`의 등록 dial과 `qsh exec`·`qsh attach` 같은 명령의 relay route는 모두 client endpoint다.
4. **portmapper는 IPv4만 매핑하고 relay가 있을 때만 돈다.** iroh는 net report를 돌릴 때 매핑을 요청하는데, relay가 하나도 없으면 net report를 돌리지 않는다. 그러나 iroh는 소켓을 열 때 IPv4 포트를 portmapper에 알리고 portmapper는 그것만으로 매핑을 시작하므로(relay가 없어도 SSDP 질의가 나간다), relay가 없는 endpoint에는 qsh가 `Disabled`를 넘긴다. 데몬은 기본 relay가 있으므로 매핑을 요청한다.
5. **평소 장비의 새 동작은 LAN 트래픽 하나다.** 데몬이 시작하고 망이 바뀔 때 기본 게이트웨이에 UPnP(SSDP 멀티캐스트 239.255.255.250:1900과 게이트웨이의 HTTP 제어), NAT-PMP(UDP 5351), PCP(UDP 5351)를 보낸다. 게이트웨이가 아무것도 지원하지 않으면 응답이 없을 뿐이고 데몬은 평소대로 뜬다(iroh가 비동기로 돈다). 공유기가 승인하면 공유기의 매핑 표에 `iroh-portmap` 설명의 항목이 생긴다.
6. **reflexive keeper는 매핑 주소를 건드리지 않는다.** `reflexive.rs`는 `add_external_addr`·`remove_external_addr`로 iroh의 설정된 외부 주소 집합만 고친다. iroh는 알릴 주소 집합을 portmapper 주소, net report 주소, 인터페이스 주소, 설정된 주소 순으로 쌓고 같은 소켓 주소는 먼저 들어간 종류를 유지하므로, 매핑 주소는 `Portmapped`로 남고 keeper가 같은 주소를 쥐고 있어도 가려지거나 지워지지 않는다. 코드 변경은 필요 없고 이 성질을 `reflexive.rs`와 `portmap.rs`의 주석에 적는다.
7. **시험은 공유기에 묻지 않는다.** `IrohConfig::portmap`의 기본값은 `false`이고 `IrohServe::default`·`new`·`with_relays`도 `false`다. 손으로 만든 설정은 게이트웨이를 건드리지 않는다. 설정 파일에서 오는 값(`iroh_serve_from_config`, `IrohSettings::server_config`)만 기본 `true`이고, 그 경로를 타는 시험은 `enable = false`를 쓰거나 `portmap = false`로 낮춘다. 시험이 확인하는 것은 설정이 endpoint builder까지 가는 배선이다(`iroh_backend::portmap` 단위 시험, `iroh_backend::an_endpoint_without_a_relay_never_maps_a_router_port`, `iroh_settings::portmap_reaches_the_daemon_endpoint_and_no_client`, `iroh_serve::portmap_follows_the_config_and_a_disabled_endpoint_has_none`). 실제 공유기와의 협상은 시험하지 않고 현장 측정으로 확인한다.

## 근거

- 매핑이 대칭 NAT 뒤의 상대가 먼저 보낼 수 있게 하는 유일한 방법이고, 현장 측정이 그 효과를 보였다(43/50 대 0).
- 데몬만 요청하는 이유: 데몬은 오래 떠 있고 상대가 찾아오는 쪽이라 외부 주소를 알릴 가치가 있다. client는 명령 하나가 끝나면 사라지므로 공유기 표에 항목을 남길 이유가 없다.
- 기본으로 켜는 이유: 이 기능이 필요한 사람은 대개 "직결이 안 서는 이유"를 모르는 사람이고, 설정을 적어야 켜지는 기능은 ADR-0063이 줄이려던 설정 짐을 다시 늘린다. 꺼야 하는 환경(공유기에 항목이 생기면 안 되는 망, SSDP가 경보를 내는 보안 장비, 이 기능 자체가 막힌 망)은 키 하나로 끈다.
- 인가는 달라지지 않는다. 매핑은 도달 가능한 주소를 하나 더 만들 뿐이고, 그 주소로 온 연결도 같은 endpoint와 같은 pin·role·ACL·admission을 거친다(ADR-0061 결정 3·4).

## 결과

- **새 의존.** `portmapper` 0.19.3, `igd-next` 0.17.1(과 그 아래 `attohttpc`, `h2`, `xml-rs`, `xmltree`)이 빌드에 들어온다. `portmapper`와 `igd-next`는 MIT 또는 Apache-2.0이고 나머지도 MIT 또는 Apache-2.0인데, igd-next의 동기 HTTP 클라이언트 `attohttpc`만 MPL-2.0이다. MPL-2.0은 파일 단위 copyleft라서 crates.io의 원본을 고치지 않고 쓰는 한 소스를 계속 구할 수 있게 두는 것 외에 의무가 없고, `deny.toml`의 `[licenses].exceptions`에 `attohttpc` 하나만 허용한다(다른 MPL-2.0 의존은 계속 실패한다). 새 advisory는 없다.
- **공유기의 상태가 바뀐다.** 데몬이 도는 동안 공유기에 UDP 매핑 항목 하나가 생긴다(UPnP가 켜져 있거나 PCP·NAT-PMP를 받는 공유기). 이것이 매핑의 의도된 부수효과이고, 같은 LAN의 다른 장비는 게이트웨이 표에서 이를 볼 수 있다. 데몬을 끌 때 해제하고, 비정상 종료는 공유기의 수명(최대 2시간)이 처리한다.
- **LAN에 보이는 트래픽이 생긴다.** 기본 게이트웨이로 가는 UPnP·NAT-PMP·PCP 요청이다. 호스트 방화벽이나 macOS의 로컬 네트워크 권한 프롬프트가 이를 물을 수 있다. `portmap = false`로 끈다.
- **직결이 서는 망이 늘어난다.** 공유기가 UPnP나 PCP·NAT-PMP를 허용하는 집·사무실의 데몬은 대칭 NAT 뒤의 client와도 직결로 선다. CGNAT 뒤나 공유기가 이를 막은 망에서는 달라지지 않고 relay로 남는다.
- 이전 버전과의 호환: wire와 `qsh.cli/v1` 필드는 그대로다. `config.toml`에 새 키 하나(`[iroh].portmap`)가 더해지고, 이 키를 모르는 이전 버전은 무시한다(`config_unknown_key`로 알린다).
- 남는 위험: 공유기가 승인한 매핑은 데몬 소켓으로 가는 UDP 패킷을 LAN 밖에서 받게 하므로, 그 포트의 노출은 relay 없이 직결 UDP를 여는 것과 같다. 노출되는 면은 QUIC handshake(미검증 Initial의 admission 방어, ADR-0009)와 pin 검사이고 새 면은 없다(`docs/design/threat-model.md` D32, h71).

## 기각한 대안

- **기본을 끄고 `portmap = true`를 적게 하기.** 필요한 사람이 그 키를 모른다. 현장 장비가 설정 없이 닿게 한다는 ADR-0063의 방향과도 어긋난다.
- **client endpoint도 매핑하기.** 명령마다 공유기 표에 항목이 생기고 SSDP 질의가 명령마다 나간다. client는 상대가 먼저 보낼 일이 없어서 얻는 것이 없다.
- **qsh 자체 UPnP·NAT-PMP 구현.** iroh가 이미 같은 코드를 net report와 연동해서 돌린다. 따로 만들면 알림 집합과 갱신을 다시 맞춰야 한다.
- **펀칭(`punch.v1`)의 일부로 넣기.** 매핑은 중개자와 무관하게 endpoint 하나가 하는 일이고 iroh route에서만 쓰인다. ADR-0054의 신호·후보 모델과 섞지 않는다.

## 개정 이력

- 2026-11-13 승인(Dave 결정). 위 실측이 근거다. `iroh-probe`의 43/50은 iroh 기본 기능으로 만든 별도 프로그램의 수치이고, qsh 바이너리로 같은 쌍을 다시 재는 것은 이 ADR이 착지한 뒤의 현장 확인 항목으로 남긴다.
- 2026-11-13 결정 4와 7의 근거를 고쳤다(결정 내용은 그대로). iroh는 relay가 없어도 소켓을 열 때 portmapper에 포트를 알려 매핑을 시작하므로 "relay가 없으면 요청하지 않는다"를 iroh에 맡길 수 없다. 시험이 relay를 끈 endpoint로 매핑을 켜 보다가 SSDP 질의가 실제 LAN으로 나가는 것을 `strace`로 확인했다. 같은 방법으로 시험 전체를 돌려 `raw_endpoint`(`iroh_identity`)도 iroh 기본값으로 SSDP를 보내던 것을 찾아 `Disabled`로 고쳤다. 이제 qsh가 relay가 없는 endpoint에 `Disabled`를 넘기고, 매핑이 켜지는 경우는 `iroh_backend::portmap::tests` 단위 시험이 고정한다.
