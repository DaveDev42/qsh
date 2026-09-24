# ADR-0015: listener를 상대로 한 초대 코드 pairing

날짜: 2026-09-09
상태: 예약됨

## 맥락

`qsh trust invite`는 초대를 발급하는 쪽이 셸을 내주는 쪽, 즉 `qsh serve`를 띄우는 host라고 전제한다. `crates/qsh-core/src/trust/pairing.rs`의 `SharedInviteStore::redeem`은 들어오는 연결의 증명을 검증해 신뢰를 등재하는 흐름이고, 이 상환은 인바운드 QUIC 연결을 받는 프로세스 안에서만 일어난다.

새 M9 표면(2026-09-09의 결정 기록(저장소 밖) Q2)에서 `qsh serve --to <listener>`는 셸을 내주는 쪽(host)이 셸을 얻는 쪽인 client 머신(listener)으로 나가는 outbound 연결을 여는 역방향 구도를 만든다. listener는 `qsh listen`으로 인바운드를 받는 쪽이다. 이 구도에서 target(셸을 내주는 쪽, `serve --to`를 부르는 쪽)이 listener를 처음 신뢰하려면 오늘은 코드 pairing이 아니라 파일 교환을 쓴다. listener에서 `qsh identity export`, target에서 `qsh trust add --cert-file`(ADR-0013이 이 경로를 정했고 M9에서 출고됐다).

코드 pairing이 listener 상대로 안 되는 이유는 상환 주체가 host 프로세스로 고정돼 있어서다. listener는 `qsh listen`을 실행하지 `qsh serve`를 실행하지 않으므로 `trust invite`가 여는 상환 창구를 가질 방법이 현재 없다. 이 ADR은 그 창구를 listener 쪽에도 열지, 연다면 어떤 모양일지를 정하기 위한 자리다.

## 결정

미정. 다음을 정해야 한다.

1. 이 창구가 아직 필요한지. ADR-0013이 연 파일 교환 경로(`qsh identity export` + `qsh trust add --cert-file`)가 M9에서 실제로 출고됐고, README `Known limitations`와 `docs/CLI.md` §6.11·§6.13이 "listener는 코드 pairing 대상이 아니다, 대신 인증서 파일로 pin하라"를 문서화된 처방으로 싣는다. 그 처방이 실사용에서 충분하다고 관측되면 아래 대안의 첫째가 그대로 답이다. 이 질문에 먼저 답해야 나머지가 의미를 갖는다.
2. 상환 주체를 host 프로세스에서 분리할지, 아니면 `qsh listen`도 자기 상환 창구를 갖게 할지. 후자라면 `SharedInviteStore`가 host·listener 두 프로세스 종류에서 각각 열리는 것을 감당해야 하는지, 아니면 별도 저장소 파일이 필요한지.
3. 초대를 누가 발급하는지. 셸을 내주는 쪽(`qsh serve --to`를 부르는 host)이 발급해 listener가 상환하는 구도가 될지, listener가 발급해 host가 상환하는 구도가 될지. 두 구도는 "누가 코드를 아는 사람을 신뢰하는가"라는 신뢰 방향이 다르다.
4. `qsh serve --to`가 시작 시점에 상대를 이미 pin하고 있어야 한다는 현행 제약을 유지할지. ADR-0014 결정 7이 그 인자를 이름→주소 2단계로만 해석하고 어느 쪽으로도 핀된 peer를 찾지 못하면 실패하게 못 박았으므로, 코드 하나로 최초 접속과 신뢰 등재를 동시에 하려면 그 결정의 개정이 선행돼야 한다. 개정한다면 `--to`가 주소 대신 코드를 받는 별도 인자 모양이 필요한지도 함께 정한다.
5. TTL·1회성·CSPRNG 비밀 같은 기존 초대의 보안 속성을 listener 쪽 창구도 그대로 상속하는지, 신뢰 방향이 다르므로 별도로 다시 검토해야 하는지.
6. 이름 결정권을 누가 갖는지. ADR-0012 결정 6이 이름을 pin하는 쪽에 주고, `pair invite --as`가 발급 시점에·`pair accept --as`가 상환 시점에 그 값을 정하게 했다. listener 쪽 창구도 같은 `qsh pair` 그룹과 같은 `--as` 규율을 쓰는지, listener 전용 서브커맨드가 필요한지. 잘못 붙은 이름의 사후 교정은 `trust rename`이 이미 맡는다.
7. pin 방향 축과의 관계. ADR-0017 결정 5가 `trust.toml`에 방향(`direction = "outbound"`)이 없다는 사실을 번호 미배정 후속 ADR로 미뤄 뒀는데, listener 상대 pairing은 host가 outbound로만 쓰는 pin을 새로 만드는 경로다. 방향 축이 먼저 정해져야 하는지, 아니면 이 ADR이 방향 없는 오늘의 pin 위에서 결론을 낼 수 있는지.

## 결과

미정. 결정 이후 `docs/CLI.md`의 pairing 절(§6.11)과 `crates/qsh-core/src/trust/pairing.rs`에 영향이 예상되고, 질문 4가 개정을 부르면 ADR-0014 결정 7도 함께 움직인다. 구체 범위는 결정 이후 정한다.

## 대안

- 현행 유지(파일 교환만). listener 상대 pairing을 영구히 지원하지 않는다. 이 경우 §6.13과 README의 Known limitations에 "listener는 코드 pairing 대상이 아니다"와 그 대체 경로를 명시하는 것으로 충분하고 별도 구현은 없다. M9가 그 명시와 대체 경로를 둘 다 출고했으므로 이 대안은 오늘의 트리 상태 그대로다.
- listener 전용 새 상환 메커니즘을 신설한다. host 상환 코드를 건드리지 않는 대신 표면이 하나 늘고 두 상환 경로를 나란히 유지해야 한다.

두 대안 중 어느 쪽도 이 시점에 채택하지 않는다. 위 질문에 답한 뒤 이 ADR을 개정한다.
