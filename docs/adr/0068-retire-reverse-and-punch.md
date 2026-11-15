# ADR-0068: 역방향 연결과 qsh 자체 홀펀칭을 걷는다. NAT 통과는 iroh에 맡기고, 명령·설정·wire·계약 어휘는 `qsh.cli/v1` 안에서 `UNSUPPORTED`로 남긴다

날짜: 2026-11-15
상태: 승인됨 (2026-11-15 Dave 결정. 선택지 "다음 마이너에서 제거"를 골랐고, 홀펀칭이 함께 꺼진다는 조사 결과에 "qsh가 정방향·역방향·홀펀칭을 신경 쓸 필요가 있나, iroh의 홀펀칭에 의존해도 된다"고 답했다)

개정 관계: [ADR-0065](0065-server-client-concept-model.md) 결정 6이 미룬 2단계를 이 ADR이 정한다. ADR-0065 결정 6의 셋째 항목("중개자를 다른 것으로 바꿀 수 없으면 `qsh listen`은 남는다")을 뒤집는다. 중개자를 대체하지 않고 qsh 자체 홀펀칭을 함께 걷기 때문이다. [ADR-0054](0054-m24-hole-punching.md)(홀펀칭)는 결정 9가 정한 "꺼짐" 동작으로 영구히 고정된다. [ADR-0059](0059-combined-listen-serve-endpoint.md)(listen과 serve를 합친 endpoint)는 은퇴한다. [ADR-0023](0023-tunnel-supervise.md)의 역방향 대기 경로, [ADR-0056](0056-m26-jump-chaining.md)의 역방향 운반체, [ADR-0012](0012-human-surface-naming.md) 결정 4·5의 `listen`·`serve --to` 표면이 함께 은퇴한다. 각 ADR에는 개정 이력 한 줄만 더하고 본문은 고치지 않는다.

## 맥락

- 역방향 연결(`qsh listen`, `qsh serve --to`, 숨김 alias `qsh reverse`, controller 등록, reverse registry, `host.reverse` 라우팅)은 NAT 뒤 장비에 연결을 걸 수 없던 시절의 해법이다.
- ADR-0061~0064가 키로 주소를 정하는 iroh route를 기본으로 켰다. relay(TCP 443)로는 항상 닿고, iroh의 홀펀칭과 데몬의 포트 매핑으로 직결이 선다. 연결 방향이 도달 가능성을 가르지 않는다(ADR-0065 결정 2).
- ADR-0065 결정 6이 요구한 사용 증거.
  - 허브(MacMini) audit에서 마지막 `host.reverse` 허용은 2026-11-12, 지금은 은퇴한 Office reverse 링크다. WSL과 Office의 audit에는 한 건도 없다.
  - fleet에서 `qsh listen`이나 `qsh serve --to`를 상시 돌리는 장비는 없다. `-R`(`forward.remote`)은 정방향 연결 위의 터널이라 계속 쓰고, 이 ADR과 무관하다.
- 조사 결과 qsh 자체 홀펀칭(ADR-0054)은 역방향 등록에 기댄다. 중개자 R이 대상 B의 살아 있는 역방향 등록을 쥐어야 하고, 대상은 `serve --to` 호스트로 한정돼 있다. 역방향을 걷으면 qsh 홀펀칭도 설 수 없다. 2026-11-12 이후 fleet에서는 이미 쓸 수 없는 상태였다.
- Dave의 판단: qsh가 연결 방향과 NAT 통과를 직접 다룰 필요가 없다. iroh의 NAT 통과에 맡긴다.

## 결정

1. **걷는 기능.**
   - 역방향 연결 전부: `qsh listen`(`--serve` 포함), `qsh serve --to`·`--name`, 숨김 `qsh reverse`, controller 등록과 registry, `host.reverse` 라우팅, 역방향 경로의 세션·exec·터널·`-R` claim·agent forwarding·jump 운반체, ADR-0023의 역방향 대기(`--wait`의 `reverse_registration_stale` 재시도), listen과 serve를 합친 endpoint(ADR-0059).
   - qsh 자체 홀펀칭: 중개자(R)와 대상(B)의 서비스, client의 punch route, `--rendezvous`.
   - 역방향 전용 표면: `qsh setup listener`, `qsh setup host --to`, `qsh pair ssh --reverse`, `qsh service install`의 `listen`·`reverse` 모드, localctl 데몬(`qsh.local.v1`의 데몬·클라이언트·프레임·mux). agent forwarding이 쓰는 `localctl/transport/`는 남긴다.
2. **남는 것.** `qsh serve`와 모든 client 명령, 주소로 직접 dial하는 기본 경로, iroh route와 그 NAT 통과·relay 장애 전환·포트 매핑(ADR-0061~0064), `-R`(`forward.remote`), `qsh serve`를 거치는 jump(ADR-0056). jump에서 사라지는 것은 역방향으로만 닿던 hop뿐이다. iroh hop은 지금처럼 `UNSUPPORTED`다(ADR-0061 결정 14).
3. **명령과 플래그는 파싱하고 `UNSUPPORTED`를 낸다.**
   - 결정 1의 명령·플래그는 clap에 남는다. `Ops`를 거쳐 `UNSUPPORTED`(exit 255, `retryable: false`)를 내고, `details.reason`은 `"reverse_retired"`다.
   - 메시지는 명령마다 대안을 하나 말한다. 기본 꼴: "`qsh listen`은 v0.9.0에서 걷혔다(ADR-0068). 대상에서 `qsh serve`를 돌리고 이 장비에 그 키를 pin하면(`qsh trust add <name> --key …`) 열린 포트 없이 iroh route로 닿는다. `-R` 터널은 그대로다." `listen --serve`에는 "`[listen].bind`는 `[serve].bind`로 옮긴다"를 더한다.
   - `--rendezvous`도 같은 규칙으로 `UNSUPPORTED`다. `--no-punch`, `[punch].mode`, `qsh trust rendezvous`는 파싱하고 아무 일도 하지 않는다(꺼짐이 이미 결과이므로 오류로 만들지 않는다).
   - `qsh listen`과 `qsh setup listener`는 도움말에서 숨긴다. man 페이지 생성기가 그 둘의 `.1`을 더 내지 않는다. ADR-0012 결정 4의 약속(v1 안에서 파싱된다)은 지킨다.
4. **설정 키.**
   - `[listen]`, `[serve].to`, `[serve].name`, `[reverse]`, `[transport].reverse_min_dead_after_ms`, `[transport].reverse_strikes`는 읽기 전용 형태로 파싱만 한다. `config_unknown_key`로 떨어뜨리지 않는다.
   - doctor 코드 `reverse_config_retired`(warn)를 새로 둔다. 남은 키 이름과 남은 `listen`·`reverse` 서비스 유닛을 말한다. `EXPECTED_DOCTOR_CODES`에 더한다.
   - fail closed: `[serve].to`나 `[reverse].controller`가 있는 설정으로 `qsh serve`를 띄우면 `UNSUPPORTED`로 멈춘다. 밖으로만 걸던 장비가 말없이 `[::]:4433`을 여는 일을 막는다.
   - `config set`으로 이 키를 쓰면 `UNSUPPORTED`, `config unset`은 정리를 위해 허용한다.
   - ADR-0066의 server 징후에서 남은 `[listen]`·`[reverse]` 표는 빠진다. `mode_basis` 낱말은 그대로다.
5. **`qsh.cli/v1` 계약.**
   - 필드는 지우지 않는다. `connection_mode: "reverse"`와 `lost_at` 같은 값은 더 나오지 않을 뿐이다. `docs/CLI.md` §5의 값 목록에 "v0.9.0부터 나오지 않는다"를 적는다.
   - trust role `reverse`와 ACL action `host.reverse`는 어휘에 남는다. 그 값을 쓴 `trust.toml`·`acl.toml`이 계속 파싱되어야 하기 때문이다(파싱 실패는 모든 peer의 거부로 이어진다). 그 role과 action은 이제 효과가 없다.
   - doctor 코드는 하나도 빼지 않는다. `controller_unreachable`, `config_serve_to_conflict`, `listen_serve_ignores_serve_bind`, `serve_unit_beside_listen_serve`, `punch_*`는 목록에 남고 더 나오지 않는다.
   - fixture는 그대로 `REQUIRED_FIXTURES`에 남는다. 걷힌 명령을 실제로 돌려 만들던 golden 시험은 고정 fixture를 읽어 타입으로 풀어 보는 시험으로 바꾼다. 메시지가 `qsh reverse`를 안내하던 fixture는 새 접미사 fixture를 더하고 옛 것은 고치지 않는다. 새 fixture: `error.UNSUPPORTED.reverse_retired.json`, `doctor_reverse_config_retired.json`.
6. **wire.** `Hello.reverse`, `ReverseRegistration`, `RemoteForwardOpen`의 claim token, punch 메시지, `CAP_PUNCH_V1`, 닫힘 코드 `CLOSE_CODE_REPLACED`·`CLOSE_CODE_PATH_DEAD`는 `docs/design/protocol.md` §16의 freeze대로 남는다. 코드는 지워도 번호와 의미는 재사용하지 않는다. `qsh serve`는 이미 `Hello.reverse`에 `UNSUPPORTED`로 답하므로(§11) 옛 `serve --to`가 보는 동작이 바뀌지 않는다. 홀펀칭은 ADR-0054 결정 9의 꺼짐 동작으로 답한다(`PunchRequest`에 `UNSUPPORTED`, `PunchOffer`에 `TARGET_UNSUPPORTED`). 모든 빌드가 `punch.v1` capability를 그대로 광고하므로 golden `capabilities.json`은 바뀌지 않는다. 그 광고가 지금은 "알아듣지만 하지 않는다"는 뜻이라는 것을 protocol.md에 적는다.
7. **서비스 유닛.** `qsh service status`와 `qsh service uninstall`은 남은 `listen`·`reverse` 유닛을 계속 알아보고 지울 수 있다. 새로 설치는 하지 않는다.
8. **받아들이는 위험.**
   - relay(TCP 443)가 막힌 망에서는 iroh route가 서지 않는다. 주소로 직접 닿지 못하는 장비라면 qsh로는 닿을 길이 없다. 역방향과 qsh 홀펀칭이 하던 fallback이 사라진다.
   - 공용 n0 relay에 대한 의존이 커진다(ADR-0062: 약관·rate limit이 바뀔 수 있다). 대안은 자체 relay(`[iroh].relay_url`)다.
   - `tunnel.list`와 `tunnel.close`는 localctl 데몬이 쥔 역방향 터널만 다뤘으므로 빈 결과와 not-found만 낸다. 명령과 계약은 남는다.
9. **순서.** v0.9.0 한 마이너 안에서 PR 단위로 나눈다. 각 단계는 커밋 전 검사 일곱 개를 초록으로 둔다.
   1. 앞문을 닫는다. CLI와 `Ops`가 `UNSUPPORTED`를 내고, `qsh serve`가 남은 역방향 설정을 거절하고, `reverse_config_retired`와 새 fixture를 더하고, 명령을 숨기고 man을 다시 만든다. `qsh listen`을 실제로 돌리는 qsh-cli 시험을 지우거나 고정 fixture 시험으로 바꾸고 `ci.yml`의 해당 항목을 뺀다.
   2. 홀펀칭을 영구히 끈다. client route, B 쪽 거절, punch route와 netsim 수용 시험, `punch-netns` job을 걷는다. proto와 fuzz target `punch_candidates`는 남긴다.
   3. 순수 이동. forward 코드가 쓰는 `ReconnectCause`·`classify_connection_error`와 닫힘 코드 상수를 중립 모듈로 옮긴다. 동작은 바뀌지 않는다.
   4. core의 역방향 코드를 지운다(`reverse/`, 합친 endpoint 분기, supervise reverse, `tunnel/remote.rs`의 claim 경로, jump의 데몬 운반체, testkit harness와 그 시험). `xtask/src/arch.rs`의 `reverse/registry.rs` 금지 규칙을 같은 커밋에서 뺀다.
   5. localctl 데몬·클라이언트·프레임·mux, `qsh.local.v1`, fuzz target `decode_local_admin_request`·`decode_local_hello`를 지운다. `host_list`와 `tunnel.list`를 정방향만 보게 한다. `arch.rs`의 localctl 금지 규칙을 같은 커밋에서 고친다.
   6. 설정 정리(읽기 전용 파싱, `[transport].reverse_*`)와 ADR-0066 징후.
   7. 문서. PRD, CLI.md(§6.13은 번호를 두고 은퇴 안내만 남긴다), protocol.md(§11은 "은퇴, wire는 남는다", §19는 휴면), architecture, threat-model(지운 시험을 가리키던 행은 다른 시험을 가리키거나 은퇴로 표시), testing, deploy/service, README, `fuzz/README.md`, RELEASE-NOTES v0.9.0. 캠페인 기록은 고치지 않고 역사 메모만 더한다. 관련 ADR에 개정 이력 한 줄씩.

## 근거

- 사용 증거가 ADR-0065 결정 6의 첫 조건을 채운다. 역방향은 2026-11-12 이후 쓰이지 않았다.
- 기본 경로(iroh)가 역방향과 qsh 홀펀칭이 풀던 문제를 푼다. 같은 목적의 기능 셋을 유지하는 비용(합친 endpoint, 감시 예산, registry, localctl 데몬, 중개자)이 코드 약 18천 줄과 시험 약 16천 줄이다.
- relay가 막힌 망의 fallback이 사라지는 것은 Dave가 받아들인 위험이다. 그런 망에서 역방향이 유일하게 연결을 살린 사례는 fleet 기록에 없다.
- `qsh.cli/v1`을 깨지 않는다. 지우는 것은 동작이고, 계약의 낱말(명령, 플래그, 필드, role, action, doctor 코드, wire 값)은 남는다. 그래서 `/v2`가 필요 없다.

## 결과

- 처음 쓰는 사람이 볼 개념은 `qsh serve`와 client 명령, pin 하나다.
- 옛 스크립트가 `qsh listen`이나 `qsh serve --to`를 부르면 대안을 말하는 `UNSUPPORTED`를 받는다. 남은 설정은 doctor가 짚고, `qsh serve`는 위험한 조합에서 멈춘다.
- CI의 필수 검사 목록에서 걷힌 시험 이름이 빠진다. 저장소 설정의 필수 검사(`punch-netns` 등)는 Dave가 고친다. CLAUDE.md의 수용 시험 목록은 main 세션이 고친다.
- 다시 역방향이 필요해지면 새 ADR로 연다. wire와 어휘가 남아 있으므로 같은 번호를 다시 쓸 수 있다.

## 개정 이력

- 2026-11-15 1단계 구현(`0b8f8a73`)에서 설정 키 이름을 바로잡았다. 결정 4의 `[transport].reverse_min_dead_after_ms`·`reverse_strikes`는 실제로 `[recovery]` 표의 키이고, `[serve].name`은 설정 키가 없고 CLI 플래그 `--name`만 있다. 결정의 뜻은 그대로다.
