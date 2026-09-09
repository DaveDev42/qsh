# ADR-0015: listener 를 상대로 한 초대 코드 pairing

날짜: 2026-09-09
상태: 예약됨

## 맥락

`qsh trust invite`는 초대를 발급하는 쪽이 셸을 내주는 쪽, 즉 `qsh serve`를 띄우는 host라고 전제한다. `crates/qsh-core/src/trust/pairing.rs`의 `SharedInviteStore::redeem`은 들어오는 연결의 증명을 검증해 신뢰를 등재하는 흐름이고, 이 상환은 인바운드 QUIC 연결을 받는 프로세스 안에서만 일어난다.

새 M9 표면(DECISIONS.md Q2)에서 `qsh serve --to <listener>`는 셸을 내주는 쪽(host)이 셸을 얻는 쪽인 client 머신(listener)으로 나가는 outbound 연결을 여는 역방향 구도를 만든다. listener는 `qsh listen`으로 인바운드를 받는 쪽이다. 이 구도에서 target(셸을 내주는 쪽, `serve --to`를 부르는 쪽)이 listener를 처음 신뢰하려면 오늘은 코드 pairing이 아니라 파일 교환을 쓴다. listener에서 `qsh identity export`, target에서 `qsh trust add --cert-file`(ADR-0013이 이 경로를 다룬다).

코드 pairing이 listener 상대로 안 되는 이유는 상환 주체가 host 프로세스로 고정돼 있어서다. listener는 `qsh listen`을 실행하지 `qsh serve`를 실행하지 않으므로 `trust invite`가 여는 상환 창구를 가질 방법이 현재 없다. 이 ADR은 그 창구를 listener 쪽에도 열지, 연다면 어떤 모양일지를 정하기 위한 자리다.

## 결정

미정. 다음을 정해야 한다.

1. 상환 주체를 host 프로세스에서 분리할지, 아니면 `qsh listen`도 자기 상환 창구를 갖게 할지. 후자라면 `InviteStore`가 host·listener 두 프로세스 종류에서 각각 열리는 것을 감당해야 하는지, 아니면 별도 저장소 파일이 필요한지.
2. 초대를 누가 발급하는지. target(셸을 내주는 쪽)이 발급해 listener가 상환하는 구도가 될지, 아니면 listener가 발급해 target이 상환하는 기존 구도를 유지한 채 방향만 뒤집을지. 두 구도는 "누가 코드를 아는 사람을 신뢰하는가"라는 신뢰 방향이 다르다.
3. `serve --to`가 시작 시점에 listener 신원을 이미 알아야 하는지(현재 파일 교환 경로처럼), 아니면 코드 하나로 최초 접속과 신뢰 등재를 동시에 해낼 수 있는지. 후자라면 `--to`가 주소 대신 코드를 받는 별도 인자 모양이 필요한지.
4. TTL·1회성·CSPRNG 비밀 같은 기존 `trust invite`의 보안 속성(pairing.rs 문서 주석)을 listener 쪽 창구도 그대로 상속하는지, 신뢰 방향이 다르므로 별도로 다시 검토해야 하는지.
5. 이 흐름이 `pair invite --as` / `pair accept --as`(DECISIONS.md Q3) 개명과 같은 서브커맨드를 쓸지, listener 전용 서브커맨드가 필요한지.

## 결과

미정. 결정 이후 `docs/CLI.md`의 pairing 절과 `crates/qsh-core/src/trust/pairing.rs`에 영향이 예상되나 구체 범위는 결정 이후 정한다.

## 대안

- 현행 유지(파일 교환만). listener 상대 pairing을 영구히 지원하지 않는다. 이 경우 §6.13과 README의 Known limitations에 "listener는 코드 pairing 대상이 아니다"를 명시하는 것으로 충분하고 별도 구현은 없다.
- listener 전용 새 상환 메커니즘을 신설한다. host 상환 코드를 건드리지 않는 대신 표면이 하나 늘고 두 상환 경로를 나란히 유지해야 한다.

두 대안 중 어느 쪽도 이 시점에 채택하지 않는다. 위 질문에 답한 뒤 이 ADR을 개정한다.
