# ADR-0063: 데몬은 iroh endpoint를 기본으로 띄우고, pin은 이름과 키만으로 선다. 설정 파일 없이 장비가 서로 닿는다

날짜: 2026-11-13
상태: 승인됨 (2026-11-13 Dave 결정. "qsh 설정파일이 너무 복잡하고 짜증나. 보다 단순화 할 수 없어?" 질문에 기본값을 바꿔 일반적인 장비는 `config.toml`도 `acl.toml`도 없이, `trust.toml`의 pin은 이름·키·role만으로 되게 하자고 선택)

개정 관계: ADR-0061 결정 2의 "`[iroh].enable`이 꺼져 있는 것이 기본이다"와 결정 1의 "`routes`가 없는 pin은 relay에 접속하지 않는다" 중 주소 없이 키만 있는 pin의 경우를 고친다. ADR-0062 결정 3(기본 relay는 n0 공용 relay 넷)은 그대로다. ADR-0045의 판정 순서와 default-deny는 건드리지 않는다. 같은 결정의 나머지와 ADR-0061·0062의 다른 결정은 그대로다.

## 맥락

지금 WSL 장비 하나의 설정은 다음과 같다.

```toml
# config.toml
[identity]
key_store = "file"
[serve]
bind = "[::]:4433"
[iroh]
enable = true
relay_url = "https://aps1-1.relay.n0.iroh.link"
```

```toml
# trust.toml
[[peer]]
name = "toss"
fingerprint = "sha256:..."
address = ""
added_at = "2026-11-13T00:00:00Z"
role = "tunnel"
routes = ["iroh"]
key = "<64자리 hex>"
```

`config.toml`의 네 항목은 `[serve].bind`(기본 `[::]:4433`)와 relay URL(기본 n0 relay 넷)을 빼면 모두 의미가 있는 설정이 아니라 기본값을 다시 적은 것이거나(`bind`), 켜야만 동작해서 적은 것(`enable`)이다. pin은 `fingerprint`가 `key`의 해시이므로 같은 정보를 두 번 적고, 주소가 없는 pin의 `routes = ["iroh"]`는 이미 `ops/mod.rs`의 `iroh_only_pin`이 "주소 없는 iroh pin은 relay로만 닿는다"고 다루는 동작을 다시 적은 것이다. `address = ""`와 `added_at`은 값이 없는 칸이다. 장비마다 이 파일을 손으로 맞추는 일이 설정의 복잡함 대부분이다.

## 결정

1. **데몬은 iroh endpoint를 기본으로 띄운다.** `[iroh].enable`이 없으면 `true`다. `qsh serve`와 `qsh listen`(`--serve` 포함)이 시작할 때 endpoint를 하나 더 띄우고 기본 relay에 home을 건다. `enable = false`를 명시하면 이전처럼 endpoint도 소켓도 만들지 않고 어떤 relay에도 접속하지 않는다(ADR-0061 결정 2의 보장은 "꺼 둔 설정"에 대해 그대로다). 전역 `--no-iroh`를 `serve`·`listen`에 주면 그 실행에 한해 같은 효과다(저장하지 않는다. `Ops::daemon_config`가 `iroh.enable`만 `false`로 덮는다). `enable`을 적지 않아 기본으로만 켜진 endpoint는 못 띄워도(예: 신원 키가 Ed25519가 아니거나 고정 `bind_port`가 쓰이는 중이다) 호스트를 멈추지 않고 stderr에 이유 한 줄을 낸다. 사용자가 `enable = true`를 적었다면 이전처럼 `CONFIG_ERROR`로 멈춘다(`IrohServe::optional`). `qsh serve --to`는 endpoint를 띄우지 않고 등록 dial의 route를 `[iroh].mode`와 controller pin이 정하는 것이 그대로다. `qsh serve --on-demand`(SSH 부트스트랩이 한 세션을 위해 띄우는 도우미)는 어떤 경우에도 endpoint를 띄우지 않는다.
2. **pin은 `key` 하나로 선다.** `trust.toml`의 `[[peer]]`는 `fingerprint`와 `key` 가운데 하나만 있으면 된다. `key`가 있으면 `fingerprint`는 그 키의 SPKI SHA-256으로 유도한다(`qsh_transport::fingerprint_of_ed25519_key`, iroh EndpointId를 qsh 지문으로 옮기는 같은 코드). 둘 다 있으면 일치해야 하고, 다르면 지금처럼 파일 전체가 `CONFIG_ERROR`다. 둘 다 없으면 `CONFIG_ERROR`다. 메모리의 `TrustPeer`와 `qsh.cli/v1`의 `trust.list` 출력에는 유도한 `fingerprint`가 그대로 실린다(additive 규칙, 필드 변경 없음).
3. **나머지 칸의 기본값.** `address`가 없으면 빈 주소다. `added_at`이 없으면 빈 문자열이다. `routes`가 없으면 키가 있고 주소가 없는 pin은 `["iroh"]`, 그 밖의 pin은 빈 목록(이전과 같은 직결·펀칭만)이다. 파일에 `routes`를 적으면 빈 목록도 그대로 이긴다. 주소가 있는 pin의 기본 route 목록은 달라지지 않는다. 키만 있는 pin이 relay로 닿는다는 점은 "아무 pin도 relay에 접속하지 않는다"는 ADR-0061의 기본값을 이 경우에 한해 바꾸는 것이고, 이 장비가 dial할 때 n0 relay에 접속한다.
4. **쓰는 쪽은 가장 짧은 형태로 쓴다.** `trust add`, `trust iroh`, 페어링, SSH 부트스트랩, dial 때 키 채움이 새로 만들거나 바꾼 pin은 빈 `address`와 `added_at`을 쓰지 않고, 기본값과 같은 `routes`를 쓰지 않고, `key`가 있으면 `fingerprint`를 쓰지 않는다. 기본값과 다른 `routes`(주소 없는 pin의 `routes = []`처럼 꺼 둔 경우)는 반드시 쓴다. 읽은 그대로인 pin은 읽은 표를 그대로 다시 쓴다. 다른 pin을 쓰려고 파일을 저장해도 손대지 않은 pin의 칸이 줄지 않고, 바뀐 pin도 그 표가 적고 있던 `fingerprint`·`address`·`added_at`·`routes`는 그대로 둔다(`TrustStore`가 읽은 표를 이름으로 기억한다). 연결에서 배운 키(직결·펀칭, 페어링)가 채워질 때 `routes`가 비어 있던 주소 없는 pin은 새 기본값(`["iroh"]`)을 따른다. `trust add --cert-file`이 인증서에서 채운 키는 연결에서 배운 것이 아니므로 `routes = []`를 적어 그 pin이 relay로 dial되지 않던 이전 동작을 지킨다(`qsh.cli/v1` 고정 fixture `trust.add.cert_file`이 `routes` 없는 응답을 요구하는 것과도 맞는다).
5. **role이 평소의 권한 설정이고 `acl.toml`은 선택이다.** `acl.toml`이 없으면 규칙이 없을 뿐이고 pin의 role은 그대로 동작한다(ADR-0045, CLAUDE.md의 보안 기본값). `acl.toml`은 role이 주는 것보다 세밀하게 나누거나 role 밖의 작업을 허용할 때만 쓴다. 인가 의미는 바뀌지 않는다. 기본 거부, role이 없는 pin은 grant 없음, 판정 순서(항상 거부 → role → pin grants → `acl.toml`)는 그대로다.
6. **기본값을 바꾸지 않은 것.** `[serve].bind`의 기본값은 `[::]:4433`로 이미 이 값이다. `[identity].key_store`의 기본값은 `auto`(플랫폼 저장소, 쓸 수 없으면 파일로 대체하고 알린다)이고 `file`이 아니다. 키 저장소는 보안 선택이고 `qsh init` 때 한 번 정해 `identity.toml`에 남으므로 이 ADR은 바꾸지 않는다. 헤드리스 장비는 `auto`가 파일로 대체하므로 `config.toml`에 적을 필요가 없다.

## 결과

- 평소 장비는 `config.toml`과 `acl.toml`이 없다. pin은 `name`, `key`, `role` 세 줄이다.

  ```toml
  [[peer]]
  name = "toss"
  key  = "<iroh endpoint key>"
  role = "tunnel"
  ```

- 데몬은 기본으로 공용 relay(기본 n0 넷 중 가장 빠른 하나)에 TCP 443 연결을 하나 계속 유지한다. 방화벽이 바깥 TCP 443을 막은 망이나 relay 접속을 허용하지 않는 정책에서는 `[iroh].enable = false`로 끈다. relay에 닿지 못해도 데몬은 뜬다(`iroh_serve::without_an_iroh_serve_there_is_no_endpoint_and_no_relay_contact`의 대조군이 받지 않는 relay URL로 띄운다). 직결 UDP 경로와 인가 판정은 endpoint 유무와 무관하다. n0 공용 relay는 속도 제한이 있고 조건이 바뀔 수 있다(ADR-0061 결정 10).
- 이전 버전이 쓴 파일은 모두 같은 뜻으로 읽힌다(바뀌는 것은 아래 한 경우다). 반대로 새 버전이 쓴 짧은 pin은 v0.7.x 이하에서 읽히지 않는다(`fingerprint`가 필수였으므로 파일 전체가 `CONFIG_ERROR`). 같은 `trust.toml`을 여러 버전이 읽는 환경은 읽는 쪽을 모두 올린 뒤에 새 pin을 쓴다.
- 이전에 주소 없이 `key`만 있고 `routes`가 없던 pin(직결로 접속한 client-only pin에 키가 채워진 경우)은 이제 relay로 dial 가능한 pin으로 읽힌다. 그 이름으로 `qsh exec`를 하면 이전의 `HOST_NOT_FOUND` 대신 relay dial을 시도한다. 막으려면 pin에 `routes = []`를 적는다.
- doctor·감사·`serve.json`의 모양은 그대로이고, `serve.json`의 `iroh` 객체가 기본으로 생긴다.

## 기각한 대안

- **`enable` 대신 `config.toml`이 없으면 켜기.** 파일 유무로 기본값이 갈리면 `[serve]` 하나를 적은 장비가 조용히 relay 접속을 잃는다. 키 하나(`[iroh].enable`)의 기본값을 바꾸는 쪽이 설명할 것이 하나다.
- **`fingerprint`를 없애고 `key`만 두기.** `fingerprint`는 사설 CA가 아닌 일반 직결 pin의 유일한 식별자이고(주소로 접속한 뒤 TOFU로 얻는다), 키는 iroh 키가 되는 Ed25519 신원에서만 나온다. 둘 다 받는다.
- **파일의 모든 pin을 저장할 때 짧은 형태로 다시 쓰기.** 사람이 손으로 맞춘 파일이 `trust add` 한 번에 전부 바뀐다. 읽은 표를 그대로 두는 비용이 작다(결정 4).
- **`trust add --key` 추가.** 요청 형(`TrustAddReq`)에 필드를 더하는 일이라 이 ADR에서 하지 않는다. 필요하면 별도 결정으로 한다.
