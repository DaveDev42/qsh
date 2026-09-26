# ADR-0024: `qsh setup`은 기존 op을 정해진 순서로 부르는 오케스트레이터로 신설한다. `acl.toml`은 쓰지 않고 넣을 행을 인쇄한 뒤 `acl check`로 확인하며, 자동 신뢰는 없다

날짜: 2026-09-26
상태: 제안됨

개정 관계: ADR-0025 결정 7의 마지막 문장("이슈 #3의 온보딩 흐름 전체가 그렇듯 … SC1 재측정이 어디에서 시간을 쓰는지 보여준 뒤에 우선순위가 정해진다") 가운데 `qsh setup`에 해당하는 부분만 개정한다. `qsh setup`의 착수는 SC1 재측정을 기다리지 않고, 효과는 결정 12의 캠페인이 사후에 판정한다. `acl show`의 배치는 건드리지 않는다. 그 밖의 기존 ADR은 대체하거나 개정하지 않는다. ADR-0012 결정 1·6·8과 대안 절의 `serve --pair` 기각, ADR-0013 결정 4·8, ADR-0014 결정 7, ADR-0015(예약), ADR-0017 결정 1·3·5, ADR-0025 결정 6을 전제로 삼는다.

## 맥락

이슈 #3의 완료 기준 초안 첫 줄은 "빈 두 머신에서 문서 없이 안내 명령만 따라 첫 셸 접속까지 5분 이내"다. 제안 절은 `qsh setup` 또는 guided `qsh init`이 신원 생성, 역할 선택, 다음 명령과 빠진 조건 출력을 맡고 재실행에 안전하며 JSON을 지원하기를 요구한다. 같은 이슈가 새 자동 신뢰는 넣지 말라고 적는다.

오늘의 첫 연결 경로는 README "First run" 절의 fingerprint 손대조 경로이고 `docs/campaigns/m9-stopwatch.md` §6 표의 여덟 단계다. host `qsh init`, `acl.toml` 손 작성, `qsh serve`, client `qsh init`, 두 화면의 fingerprint 대조, client `trust add`, host `trust add`, `qsh dave@box` 순이다. `docs/campaigns/m7-stopwatch.md` §9의 예행에서 기계 시간 합은 0.65~0.72초로 5분 예산의 0.25% 미만이었다. 예산은 사실상 전부 사람 시간이다. 그 가운데 `acl.toml` 손 작성은 M9에서도 바뀌지 않았고(`m9-stopwatch.md` §6), fingerprint 대조는 README가 스스로 최대 병목으로 인정한다(`m9-stopwatch.md` §4). 실측치는 아직 없다. M7 DoD 1과 M9 DoD 1은 둘 다 열려 있다(`docs/ROADMAP.md` 현재 위치).

이 설계를 묶는 확정 사항은 다음과 같다.

- ADR-0017 결정 1. 그 ADR의 사람용 표면이 신설한 명령은 어느 것도 `acl.toml`을 쓰지 않는다. `PolicySource::load`는 프로세스 시작 시 1회만 읽고 핫 리로드가 없다. `qsh setup`은 그 표면 밖의 새 명령이므로 같은 규칙을 이 ADR이 스스로 정한다(결정 3).
- ADR-0017 결정 5와 `m9-stopwatch.md` §7. TOFU는 넣지 않는다. `trust.toml`의 pin은 방향을 가리지 않아 client 쪽 자동 pin이 같은 상대의 inbound 인증까지 연다.
- ADR-0012 결정 8과 대안 절. 둘째 터미널 마찰은 `qsh service install`로 풀고, 장기 실행 `serve`가 초대 발급까지 겸하는 `serve --pair`는 초대 비밀이 상시 프로세스의 출력에 섞이고 발급과 상환이 한 프로세스에 겹쳐서 기각했다.
- ADR-0013과 `docs/CLI.md` §6.11·§6.13. 초대 코드의 상환 창구는 인바운드 `qsh serve`에만 있고, `qsh listen`과 `qsh serve --to` 쪽 peer는 인증서 파일 교환(`identity export` + `trust add --cert-file`)으로 pin한다. listener 상대 페어링은 ADR-0015로 예약돼 있다. 같은 이름이 다른 fingerprint로 이미 pin돼 있으면 `trust add --cert-file`은 아무것도 쓰지 않고 성공처럼 돌아온다(ADR-0013 결정 4).
- ADR-0014 결정 7. `qsh serve --to <alias>`는 별칭을 `hosts.toml`이나 trust pin의 주소로 풀고, 주소가 없으면 `HOST_NOT_FOUND`다.
- `docs/CLI.md` §2.1과 §6.18. `--json`/`--jsonl`은 interactive prompt를 열지 않는다. `service install`은 유닛 파일만 쓰고 활성화는 사람이 `docs/deploy/service.md`의 레시피로 한다.

조립할 부품은 이미 `qsh-core`의 `Ops`에 있다. `identity_init`은 멱등이다(`created: false`). `trust_invite`/`trust_accept`는 `--as`로 pin 이름을 pin하는 쪽이 정한다(ADR-0012 결정 6). `invites.toml`은 코드 대신 `mac_key`만 저장하므로 발급한 코드는 다시 보여 줄 수 없고 10분 뒤 만료된다(`INVITE_TTL`). `trust_add`는 `cert_pem`을 받고, `cert_pem`과 `fingerprint`가 둘 다 없으면 주소로 다이얼해 fingerprint를 관측한다. `acl_check`는 호출마다 `acl.toml`을 다시 읽고 `serve`/`listen`과 같은 평가기를 쓴다(§6.15). `doctor`는 22종 진단을 내고 exit가 항상 `0`이다(§6.17). service op은 run mode를 `[listen]` > `[serve].to` > 구 `[reverse].controller` > `serve` 순으로 추론하고 그 mode의 유닛을 쓴다. 예시 행 생성기 `policy_example_rows(names, role)`(`crates/qsh-core/src/acl/load.rs`)는 역할별 allow 목록(`serve`는 `exec.run`과 `session.*` 넷, `listen`은 `host.reverse`)으로 이름마다 `[[acl]]` 행을 만든다.

pin 조회에는 설계가 피해야 할 성질이 하나 있다. `SharedTrustStore::lookup_pin`(`crates/qsh-core/src/trust/mod.rs`)은 fingerprint가 같은 첫 항목을 찾는다. 한 fingerprint가 두 이름으로 pin되면 principal은 저장 순서상 앞 이름으로만 해석되고 뒤 이름을 가리키는 `[[acl]]` 행은 매칭되지 않는다. 이슈 #3이 짚은 `macmini`/`macmini-ctl` 두 별칭 배치가 이 경우다.

순서에 관한 기록도 있다. 이슈 #3의 2026-09-24 코멘트는 `qsh setup`을 M9 DoD 1의 SC1 재측정 뒤에 결정한다고 적었고, ADR-0025 결정 7도 온보딩 흐름의 우선순위를 재측정 뒤로 미뤘다. 2026-09-26 사용자는 P1 계획을 열고 진행하라고 지시했다. 이 ADR은 설계를 먼저 내고 측정을 사후 판정으로 옮기자고 제안한다(결정 12). 그 순서 변경은 이 ADR이 승인될 때 확정된다.

## 결정

1. `qsh setup <role>`을 신설하고 dotted operation 이름은 `setup.run`으로 한다. `docs/CLI.md` §2.5의 "인가 불요" 행에 더하는 local operation이고 원격 peer가 요청할 수 없다. `setup.run`은 새 능력을 만들지 않는다. 상태를 바꾸는 호출은 기존 `Ops` 메서드 `identity_init`, `trust_invite`, `trust_accept`, `trust_add`, `service_install`, 그리고 audit 경로를 점검하는 `doctor`뿐이다. 읽기는 `trust_list`, `acl_check`, `service_status`, `Ops::config()`와 결정 5가 신설하는 초대 읽기 도우미 하나다. 판단 로직은 `crates/qsh-core/src/setup/` 디렉터리 모듈에 둔다. 읽기 전용 `Ops::setup_plan`이 현재 상태에서 단계 목록과 각 단계의 상태를 계산하고, `Ops::setup_step`이 단계 하나를 위 메서드로 실행한다. `qsh-cli`는 계획을 렌더하고, 계획이 요구한 입력만 받아 넘기고, 다음 단계를 부른다. 어떤 단계를 언제 실행할지, 이미 끝났는지, 막혔는지는 CLI가 판단하지 않는다. wire 메시지, capability, `ErrorCode`, doctor 진단 코드는 하나도 늘지 않는다.

2. 역할은 ADR-0012 결정 1의 어휘를 그대로 쓴다. 역할마다 pin 수단이 정해져 있다.

   | 호출 | 대응 모드 | pin 수단 | `acl.toml` 행의 allow |
   |---|---|---|---|
   | `qsh setup host --peer <name> [--peer-cert <path\|->]` | `qsh serve` | `trust_invite --as <name>`, 또는 `trust_add` + `cert_pem` | `serve` 목록 |
   | `qsh setup host --to <alias> --address <addr> --peer-cert <path\|->` | `qsh serve --to <alias>` | `trust_add` + `cert_pem` + 주소 | `serve` 목록 |
   | `qsh setup client <name> --address <addr> [<code> \| --code-stdin \| --peer-cert <path\|->]` | `qsh <name>` | `trust_accept --as <name>`, 또는 `trust_add` + `cert_pem` + 주소 | 없음 |
   | `qsh setup listener --peer <name> --peer-cert <path\|->` | `qsh listen` | `trust_add` + `cert_pem` | `host.reverse` |

   `host --to`의 `--to`는 주소가 아니라 pin 이름이다. 그 이름이 그 장비 `acl.toml` 행의 principal이고, `--address`가 그 pin에 주소를 남겨 `qsh serve --to <alias>`가 ADR-0014 결정 7대로 풀린다. `listener`와 `host --to`에서는 페어링을 쓰지 않는다. 상환 창구를 `qsh listen`에 여는 문제는 ADR-0015의 몫이고 `qsh setup`이 우회해 열지 않는다. 코드 입력과 `--peer-cert`는 서로 다른 pin 수단이라 함께 줄 수 없다. 함께 주면 인자 사용 오류(exit 2)다. `--forward`(결정 4)와 `--service`(결정 7)는 해당하는 역할에서만 받는다. 다른 역할에 주면 인자 사용 오류다. 역할 인자 없이 부르면 human mode에서는 역할을 묻고 machine mode에서는 `INVALID_ARGUMENT`다.

3. `qsh setup`은 `acl.toml`, `config.toml`, `hosts.toml`을 쓰지 않는다. 셋 다 사람이 손으로 쓰는 파일이다. 쓰는 파일은 결정 1의 메서드가 오늘 이미 쓰는 것으로 한정한다. identity 파일(또는 key store), `trust.toml`, `invites.toml`, 서비스 유닛 파일(launchd의 로그 디렉터리 포함), `audit.log`(doctor 점검이 없으면 만들고 `service_install`이 기록 하나를 남긴다)다. 이 경계는 `cargo xtask arch`가 강제한다. `crates/qsh-core/src/setup/`을 디렉터리 범위 금지 대상에 더하고 금지 토큰은 `acl_file`, `fs::write`, `File::create`, `OpenOptions`, `write_private_file`, `write_atomically`, `.save(`, `probe_fingerprint` 여덟으로 한다. `acl.toml` 경로는 `acl_check` 결과의 `policy.path`에서 얻어 출력에만 쓴다. `trust_add`는 `cert_pem`이 없으면 스스로 탐침할 수 있어 토큰 금지만으로는 그 경로가 닫히지 않으므로, `qsh setup`이 만드는 `TrustAddReq`는 항상 `cert_pem`을 채운다.

4. ACL 단계는 넣을 행을 인쇄하고 검증만 한다. 행은 `policy_example_rows`로 만든다. principal은 `device:<name>`이고 name은 결정 2 표의 pin 이름이다. `host`와 `host --to`는 `serve` 목록, `listener`는 `host.reverse`다. host 두 역할에 `--forward`를 주면 `forward.local`을 목록에 더한다. `-L`과 `-D`가 같은 action으로 인가되기 때문이다(ADR-0019 결정 6). 이 확장은 allow 목록에 action 하나를 더하는 방식으로 하고 `Role`에 variant를 더하지 않는다. `Role`은 `load_or_deny`의 시작 진단에도 쓰인다. doctor의 `acl_principal_unmatched`·`acl_ca_auth_path_missing` 예시 행 문면은 바뀌지 않는다.

   검증은 목록의 action마다 `acl_check`(`--auth-path pin`)를 부른다. 전부 `allow`면 충족이다. `policy.loaded: false`이거나 하나라도 `deny`면 미충족이고 단계 상태는 `pending`이며 `detail`에 거부된 action을 적는다. human mode는 "`acl.toml`을 저장한 뒤 Enter"를 묻고 다시 검증한다. machine mode는 기다리지 않고 `pending`으로 돌려준다.

   돌고 있는 `serve`/`listen`은 기동 시 읽은 정책을 쓰고 `qsh setup`은 떠 있는 `serve`를 알아낼 방법이 없다. 그래서 이 단계가 충족(`done` 또는 `already`)일 때마다 재시작 고지를 붙인다. 문면은 ADR-0025 결정 6이 doctor의 두 remedy(`crates/qsh-core/src/doctor.rs`)에서 뽑기로 한 상수다. 구현 시점에 그 상수가 없으면 `qsh setup` 구현이 문면을 바꾸지 않고 먼저 뽑는다.

5. `host` 역할에서 행이 pin보다 먼저 생기는 순서의 위험을 닫는다. 이 역할은 행을 쓰게 한 뒤 초대를 발급하므로 ADR-0017 결정 3이 적은 조건, 즉 아직 아무도 pin하지 않은 이름에 행이 이미 있는 상태를 스스로 만든다. 규칙 둘로 막는다. `qsh setup`이 발급하는 초대는 항상 `--as <name>`을 단다. 그 초대를 상환한 상대는 자칭 이름과 무관하게 `<name>`으로 pin된다. 그리고 ACL 단계는 만료되지 않았고 `assigned_name`이 없는 미상환 초대가 하나라도 있으면 충족으로 보지 않는다. 그런 초대를 상환한 상대가 `<name>`을 자칭하면 그 행을 그대로 얻기 때문이다. 이때 `detail`은 초대 TTL(10분)이 지나면 풀린다는 사실을 적는다. 상환 창구가 인바운드 `qsh serve`에만 있으므로 이 규칙은 `host` 역할에만 적용한다. 초대는 `qsh-core`에 신설하는 읽기 도우미가 센다. 살아 있는 미상환 초대 수를 `assigned_name`별로만 돌려주고 `mac_key`는 노출하지 않는다.

6. 자동 신뢰는 없다. `qsh setup`이 pin을 만드는 근거는 초대 코드와 인증서 파일 둘뿐이다. 관측한 fingerprint를 보여 주고 확인받아 pin하는 경로는 두지 않는다. 기존 `qsh trust add`의 y/N 수동 대조(ADR-0002)는 그대로 남지만, 안내된 기본 경로가 한 번 확인이면 대조 없이 넘기게 되어 TOFU와 다를 바 없다. 결정 3의 `probe_fingerprint` 금지와 `cert_pem` 규칙이 이 경로를 코드에서 막는다.

   fingerprint는 다음처럼 확인하고, 모호하면 fail closed한다.
   - `--peer-cert`가 있으면 쓰기 전에 PEM에서 fingerprint를 계산한다. 같은 이름이 다른 fingerprint로 pin돼 있거나(ADR-0013 결정 4의 조용한 no-op), 같은 fingerprint가 다른 이름으로 pin돼 있으면 `trust_add`를 부르지 않는다. 단계는 `pending`이고 `detail`에 기존 이름과 `qsh trust remove`/`qsh trust rename` 안내를 적는다. 이름과 fingerprint가 모두 같으면 `already`다.
   - 페어링(`client`의 `pair`)은 다이얼 전에 fingerprint를 알 수 없다. 이름이 이미 pin돼 있으면 다이얼하지 않고 `already`로 보며 `detail`에 fingerprint는 비교하지 않았다고 적는다. `trust_accept` 뒤 `trust_list`에서 같은 fingerprint가 다른 이름에도 걸려 있으면 `pair`는 `pending`이다. 사람의 기존 pin을 건드리므로 되돌리지는 않는다.
   - `host`의 초대는 `qsh setup`이 끝난 뒤 `qsh serve` 안에서 상환되므로 `qsh setup`이 볼 수 없다. 그 시점의 고지는 ADR-0017 결정 3의 responder 고지가 맡는다.

7. machine mode(`--json`)는 envelope 하나를 stdout에 내고 프롬프트를 열지 않는다. `setup.run`은 value operation이고 `--jsonl`은 다른 value operation과 같이 다룬다. 입력은 전부 플래그와 표준입력에서 받고, 첫 단계 전에 필수 입력의 존재, 이름 규칙, 주소 형식, `--peer-cert`의 PEM 구조(`trust_add`와 같은 검증)를 한꺼번에 본다. 하나라도 빠졌거나 틀리면 아무것도 쓰지 않고 `INVALID_ARGUMENT`다. 초대 코드는 위치 인자나 `--code-stdin`으로 받고 `docs/CLI.md` §6.11의 규칙을 그대로 따른다. machine mode에서 표준입력이 터미널인 `--code-stdin`은 `INVALID_ARGUMENT`이고, 위치 인자와 `--code-stdin`을 함께 주면 exit 2다. 서비스 단계는 `--service`를 줄 때만 실행하고, 없으면 `skipped`다. machine mode는 `qsh serve`·`qsh listen`·대화형 세션 어느 것도 띄우지 않는다.

   human mode는 빠진 입력을 stderr 프롬프트로 묻는다. 묻는 것은 역할, pin 이름, 초대 코드(`pair accept`와 같은 에코 없는 프롬프트), `acl.toml` 저장 확인, `--service`가 없을 때의 서비스 유닛 설치 여부(기본 아니오) 다섯뿐이다. 주소와 인증서 경로는 플래그로만 받는다. 표준입력이 터미널이 아니거나 `--peer-cert -`가 표준입력을 쓰면 프롬프트를 열 수 없다. 이때 빠진 입력은 `INVALID_ARGUMENT`이고(§6.11의 `pair accept`와 같은 규율), ACL 단계와 서비스 단계는 machine mode와 같이 동작한다.

8. 단계 순서는 역할마다 고정이다.

   | 역할 | 순서 |
   |---|---|
   | `host` | `identity` → `mode_config` → `acl` → `service` → `invite`(또는 `pin_cert`) → `doctor` |
   | `host --to` | `identity` → `pin_cert` → `mode_config` → `acl` → `service` → `doctor` |
   | `client` | `identity` → `pair`(또는 `pin_cert`) → `doctor` |
   | `listener` | `identity` → `pin_cert` → `mode_config` → `acl` → `service` → `doctor` |

   `acl`이 `invite`보다 앞인 이유는 결정 5다. `mode_config`와 `acl`이 `service`보다 앞인 이유는 `service_install`이 추론한 mode의 유닛을 쓰고, 그 유닛이 활성화되는 순간 정책이 1회 읽히기 때문이다. 단계 상태 어휘는 `done`(이번에 실행하거나 이번에 충족됨), `already`(이미 충족돼 실행하지 않음), `pending`(사람이 할 일이 남음), `blocked`(앞 단계가 `pending`이라 실행하지 않음), `skipped`(플래그로 제외했거나 플랫폼이 지원하지 않음) 다섯이다. `mode_config`와 `acl`은 읽기만 하므로 앞 단계가 `pending`이어도 평가한다. 그래야 사람이 고칠 것이 한 실행에 모두 드러난다. 단계 id 어휘는 `identity`, `mode_config`, `acl`, `pin_cert`, `pair`, `invite`, `service`, `doctor` 여덟이다. 두 어휘 모두 doctor 코드와 같이 닫힌 목록으로 두고 추가만 허용한다.

   `mode_config`는 `Ops::config()`를 service op과 같은 추론 함수로 읽으므로 플랫폼과 무관하게 돈다. `host`는 `serve`, `listener`는 `listen`이어야 한다. `host --to`는 `reverse`이고 outbound 대상(`[serve].to` 또는 구 `[reverse].controller`)이 `--to`와 같아야 한다. 다르면 `pending`이고 `detail`에 `config.toml`에서 더하거나 뺄 줄을 적으며 파일은 쓰지 않는다. `service`는 `service_status`가 설치됐다고 답하면 유닛을 다시 쓰지 않는다. 유닛에 박힌 실행 파일 경로와 controller는 비교할 수 없으므로 `detail`에 설정이나 바이너리 위치를 바꿨다면 `qsh service install`을 다시 부르라고 적는다. service op이 `UNSUPPORTED`를 내는 플랫폼에서 `service`는 `skipped`다. `pin_cert`·`pair`의 `already`는 결정 6을 따르고, `invite`는 `--peer` 이름이 이미 pin돼 있으면 `already`다.

   쓰는 단계(`identity`, `pin_cert`, `pair`, `invite`, `service`)가 모두 `already`나 `skipped`인 재실행은 config 디렉터리와 유닛 경로의 어떤 파일도 바이트 단위로 바꾸지 않는다. 예외는 상환 전의 `host` 재실행 하나다. 이전 코드를 다시 보여 줄 수 없으므로 새 코드를 발급하고 `invites.toml`을 쓴다. 이전 코드도 같은 `assigned_name`을 달고 있어 두 번째 상환은 `SESSION_CONFLICT`로 끝나며(`docs/CLI.md` §6.11), `detail`에 아직 살아 있는 같은 이름의 코드 수를 적는다.

9. `data`는 `SetupRunData`다. 필드는 `role`, `complete`, `steps`, `acl_rows`(선택), `next`다. `steps`의 원소는 `id`, `status`, `command`, `detail`(선택), `result`(선택)를 갖는다. `command`는 그 단계와 같은 일을 하는 단독 명령이다. 사람이 손으로 따라 할 수 있고, Ansible 같은 수동 프로비저닝 경로가 `qsh setup` 없이도 그대로 남는다. `result`는 그 단계가 부른 op의 `data`를 그대로 담는다. `invite`는 `TrustInviteData`, `acl`은 action 순서를 따른 `AclCheckData` 배열이다. 같은 값의 진실 소스를 둘로 만들지 않는다(ADR-0012 결정 6과 같은 규율). `acl_rows`는 결정 4의 인쇄 텍스트다. `next`는 이 실행 뒤 사람이 칠 명령 목록이다. `qsh serve`(또는 `docs/deploy/service.md`의 활성화 레시피), 상대 장비에서 칠 `qsh setup client …`, 첫 셸 `qsh <name>` 같은 것이 들어간다. `complete`는 `pending`·`blocked` 단계가 없고 doctor의 `overall`이 `"error"`가 아닐 때만 `true`다. 뜻은 "이 장비에서 `qsh setup`이 할 일이 없다"이다. `host`는 상대의 상환을 볼 수 없으므로 첫 셸의 성공을 뜻하지는 않는다.

   초대 코드는 `host` 역할의 이 실행 자신의 출력에만 나간다. 오늘 `qsh pair invite`가 내는 것과 같은 자리이고 상시 프로세스의 로그에는 가지 않는다. 키 재료는 어느 출력에도 나가지 않는다.

10. exit code는 `docs/CLI.md` §4의 세 값만 쓴다. 부른 op이 하나도 실패하지 않았으면 `0`이다. `pending` 단계가 남아 있어도 `0`이고 `data.complete: false`가 그 사실을 담는다. 사람이 해야 할 일이 남은 것은 실패가 아니라 데이터라는, `acl.check`와 `doctor.run`의 선례를 따른다. 부른 op이 실패하면 `255`와 오류 envelope이다. 예외는 service op의 `UNSUPPORTED` 하나이고 결정 8대로 `skipped`가 된다. `code`와 `retryable`은 그 op이 낸 값을 바꾸지 않고, `details.step`에 실패한 단계 id를, `details.steps`에 그때까지의 단계 id와 상태만 additive로 더한다. `details.steps`에는 `result`를 싣지 않아 초대 코드가 오류 details에 남지 않는다. 이미 끝난 단계는 되돌리지 않고, 같은 명령을 다시 부르면 이어서 진행한다. clap이 잡는 인자 문법 오류와 결정 2·7의 인자 사용 오류는 `2`다. 결정 7의 입력 누락·형식 오류 `INVALID_ARGUMENT`는 다른 op과 같이 envelope을 내고 `255`다.

11. `qsh setup`이 하지 않는 일을 적어 둔다.
    - `qsh serve`·`qsh listen`을 띄우거나 그 프로세스로 바뀌지 않는다. 초대 발급과 장기 실행 serve를 한 프로세스에 묶는 것은 ADR-0012가 `serve --pair`에서 기각한 모양이다.
    - 서비스 유닛을 활성화하지 않는다. §6.18의 "유닛 파일만 쓴다" 계약을 바꾸지 않고 활성화 명령은 `next`에 적는다. 활성화까지 맡기려면 §6.18을 개정하는 별도 결정이 필요하다.
    - `acl show`(ADR-0025)에 기대지 않는다. 검증은 이미 있는 `acl_check`로 한다. `acl show`가 착지하면 human 렌더가 그 출력을 곁들일 수 있지만 이 ADR의 결정은 그것 없이 완결된다.
    - SSH 키를 가져오지 않는다(ADR-0026). P2 항목에도 닿지 않는다.

12. 측정은 착수를 막지 않고 검증으로 둔다. M9 DoD 1은 M9 표면을 재야 하므로 `docs/campaigns/m9-stopwatch.md` §8 표의 m9 재측정 칸 "qsh 커밋 SHA"를 `qsh setup` 첫 코드 커밋의 부모로 고정하고, 그 열 제목의 "현재 바이너리"를 고정 트리로 고친다. 그 트리의 바이너리와 README "First run" 절이 M9 재측정의 대상이다. §7이 README나 제품 수정을 요구하면 고정 트리에 그 수정만 얹은 트리를 새 대상으로 삼고 그 SHA를 §8에 적는다. 그러면 `qsh setup` 착지와 README 개편이 M7·M9 캠페인의 측정 대상을 바꾸지 않고, 두 캠페인의 §5 기준도 그대로다.

    `qsh setup`의 효과는 새 캠페인 문서 `docs/campaigns/p1-setup-stopwatch.md`가 잰다. 형식은 `m9-stopwatch.md`의 §3~§8을 계승하고 자동 신뢰 배제(§7)도 포함한다. 이슈 #3 완료 기준 첫 줄대로 대상 문서는 없다. 피실험자는 §3 조건의 두 장비와 "두 장비에서 `qsh setup`을 실행하고 그 안내만 따른다"는 지시 한 줄만 받고, 그 뒤로는 `qsh setup`의 프롬프트, 인쇄된 행, `next`만 따른다. 타이머 종료는 첫 원격 프롬프트다. 3회 전부 300초 이내이고 중앙값이 비교 세트 m9 3회의 중앙값보다 짧으면 합격이다. 비교 세트는 같은 진행자가 같은 날 잰 m9 3회다. M9 DoD 1 공식 회차가 그날이면 그 세트를 쓰고, 아니면 그날 고정 트리로 m9 3회를 따로 잰다. 단계 기록표는 사람 구간(행 붙여 넣기, 코드 옮기기, `qsh serve` 기동)과 기계 구간을 나눠 적는다. 이 캠페인은 사람 몫이다. PASS가 기록되기 전에는 `qsh setup`이 이슈 #3 완료 기준 첫 줄을 충족했다고 적지 않는다.

## 근거

기계 시간이 예산의 0.25% 미만이라 새 로직으로 줄일 기계 시간이 없다. 줄일 수 있는 것은 사람 구간이고, `m9-stopwatch.md` §6 표의 사람 구간이 이 결정들과 이렇게 대응한다. fingerprint 대조와 양쪽 `trust add`(5·6·7행)는 초대 코드 한 번 옮기기로 바뀐다. 코드 하나가 양쪽을 동시에 pin하기 때문이다. `acl.toml` 작성(2행)은 없앨 수 없다. 결정 4가 그 구간을 "무엇을 적을지 찾아 옮겨 적기"에서 "인쇄된 행 붙여 넣기와 자동 검증"으로 줄인다. 초대는 `qsh serve` 기동 전에 발급되므로 host 쪽은 `qsh setup`이 끝난 터미널에서 `qsh serve`를 띄우면 된다. 그래서 `qsh setup`은 오케스트레이터 이상일 필요가 없고, 오케스트레이터로 두면 이미 테스트로 고정된 op들의 계약을 그대로 물려받는다.

## 대안

- `qsh setup`이 확인 프롬프트를 거쳐 `acl.toml`에 행을 직접 쓴다. 기각한다. ADR-0025가 `acl grant`를 기각한 이유와 같다. `acl.toml`에는 `trust.toml`의 `FileLock` 같은 잠금 규율이 없어 사람이 편집기로 열어 둔 파일을 덮어쓸 수 있고, 기동 시 1회 로드 때문에 "썼다"는 출력과 실제 강제 사이에 재시작 하나만큼의 간극이 남는다.
- `qsh init`을 guided로 넓힌다(이슈 #3이 적은 다른 이름). 기각한다. `identity.init`은 멱등 op이고 `data` 모양이 fixture 둘(`identity.init.created.json`, `identity.init.existing.json`)로 고정돼 있으며 프로비저닝 스크립트가 그대로 부른다. 역할·pin·ACL 흐름을 얹으면 같은 op의 뜻이 플래그에 따라 달라진다.
- human mode에서 모든 단계가 끝나면 그 프로세스가 `qsh serve`로 이어서 뜬다. 기각한다. 명령 하나를 줄이지만 `serve --pair`와 같은 모양이고(ADR-0012 대안 절), 이 ADR은 그 기각을 다시 열지 않는다.
- 관측한 fingerprint를 보여 주고 y/N으로 확인받아 pin하는 단계를 둔다. 기각한다. 결정 6의 이유대로 안내된 기본 경로의 한 번 확인은 대조 없이 넘기게 되고, ADR-0017 결정 5와 `m9-stopwatch.md` §7이 5분을 자동 신뢰로 맞추는 것을 금지한다.
- 서비스 유닛 활성화까지 한다. 이 ADR에서는 하지 않는다. `service.install`의 계약(§6.18)을 바꾸는 일이라 별도 결정이 필요하다.
- SC1 재측정이 끝날 때까지 설계를 미룬다. 기각한다. 측정은 없어지지 않고 결정 12가 순서를 "측정 뒤 설계"에서 "설계 뒤 측정으로 판정"으로 바꾼다. 결정 12 없이 승인되면 `qsh setup` 착수는 M9 DoD 1 기록을 기다린다.
- `scripts/` 아래 셸 스크립트로 안내한다. 기각한다. `qsh.cli/v1` JSON 계약을 낼 수 없고 판단 로직이 `Ops` 밖에 생기며 플랫폼마다 따로 유지해야 한다.
- human mode 전용으로 만든다. 기각한다. 이슈 #3이 JSON 출력을 요구하고, 에이전트용 표면은 JSON CLI 하나다(ADR-0011).
- `listener` 역할에서 초대 코드를 쓸 수 있게 `qsh listen`에 상환 창구를 연다. 기각한다. ADR-0015가 예약한 결정이다.
- 한 장비를 forward와 reverse 두 별칭으로 자동 pin한다. 기각한다. 첫 항목 조회 때문에 두 번째 이름의 `[[acl]]` 행이 조용히 죽는다. 두 별칭 배치 안내는 README와 `docs/CLI.md`가 따로 다룰 일이다.

## 결과

- `docs/CLI.md`가 바뀐다. §2.4 목록과 §2.5 "인가 불요" 행에 `setup.run`을 더하고, §6.18 뒤에 `qsh setup` 절을 신설한다. 번호는 ADR-0025의 `acl show` 절과의 착지 순서로 정한다. 새 절은 결정 2의 역할 표, 결정 8의 어휘 표, 결정 10의 exit 규칙, 그리고 `setup`이라는 host 별칭이 이 서브커맨드에 가려진다는 사실을 담는다. §4의 exit code 표는 바뀌지 않는다. `qsh.cli/v1`은 additive로만 는다. `docs/PRD.md` §11 명령 체계 표에 `qsh setup` 행이 는다.
- `crates/qsh-proto`에 `SetupRunReq`·`SetupRunData`·`SetupStep`이 붙는다. fixture는 append만 한다. 예컨대 `setup.run.host_pending_acl.json`, `setup.run.client_complete.json`, `error.INVALID_ARGUMENT.setup_missing_input.json`을 더하고 `REQUIRED_FIXTURES`에 등록한다. `layer_2_every_schema_command_has_all_six_faces`가 새 command를 덮고, `crates/qsh-core/tests/acl_registry.rs`의 "인가 불요" 목록에 `setup.run`이 는다. `capabilities.json`은 wire capability 목록이라 바뀌지 않고 `docs/design/protocol.md` §16에 닿는 변경도 없다.
- 이 결정을 고정할 테스트다. 이름은 구현 시 확정한다.
  - `setup_never_writes_acl_toml_in_any_role`: 네 역할 각각, `acl.toml`이 없을 때와 있을 때 모두 실행 뒤 존재 여부와 바이트가 같다.
  - `setup_rerun_after_completion_changes_no_file`: 쓰는 단계가 모두 `already`나 `skipped`인 재실행 뒤 config 디렉터리와 유닛 경로의 모든 파일 바이트가 같다.
  - `setup_machine_mode_rejects_missing_input_before_any_write`: `--json`에서 필수 입력이 빠지거나 PEM이 틀리면 `INVALID_ARGUMENT`이고 파일이 하나도 생기지 않으며 stdout은 envelope 한 줄이다.
  - `setup_invite_always_carries_assigned_name`, `setup_acl_step_pending_while_unassigned_invite_is_live`: 결정 5.
  - `setup_refuses_second_name_for_pinned_fingerprint`, `setup_pin_cert_pending_on_fingerprint_mismatch`, `setup_pair_pending_on_duplicate_fingerprint`: 결정 6.
  - `setup_trust_add_always_carries_cert_pem`: 결정 3의 탐침 차단.
  - `setup_mode_config_pending_on_wrong_run_mode`: 결정 8. `[serve].to`가 `--to`와 다른 경우를 포함한다.
  - `setup_output_never_carries_key_material`: 모든 역할의 stdout·stderr와 오류 envelope에 키 재료가 없고, 초대 코드는 `host`의 `invite` 단계 `result`에만 있다.
  - `setup_step_vocabulary_matches_cli_md`: 단계 id·상태 어휘와 `docs/CLI.md` 새 절 표의 일치. `crates/qsh-core/tests/doctor_docs.rs`의 잠금 어휘 규율을 따른다.
  - `xtask/src/arch.rs`의 `crates/qsh-core/src/setup/` 금지 토큰 여덟과 `broker/` 중첩 디렉터리 자기 테스트 형식의 자기 테스트. 새 범위이므로 그 파일이 경고한 `//` 주석 제거 방식을 다시 확인한다.
  - 재시작 상수를 뽑은 뒤에도 doctor 두 remedy의 문면이 바이트 단위로 같고, `--forward` 확장 뒤에도 `minimal_policy_example_fills_in_actual_pinned_peer_names` 등 기존 예시 행 테스트가 그대로 초록이다.
- `docs/man/`에 `qsh-setup` 계열 페이지가 생긴다. `cargo xtask man`으로 생성하고 `checked_in_man_pages_match_the_generator`가 대조한다.
- `docs/design/threat-model.md` §3 진입점 표에 local-only 행 하나가 는다. §7 잔여 위험에 둘을 적는다. 하나는 사람이 `qsh setup` 밖에서 `--as` 없는 초대를 TTL 안에 새로 발급하는 경우다. 다른 하나는 `host` 역할의 상환 뒤 생긴 fingerprint 중복으로, `qsh setup`은 보지 못하고 ADR-0017 결정 3의 responder 고지로만 드러난다.
- `pair` 단계의 다이얼은 오늘의 `pair accept`처럼 `--timeout`이 없다. `docs/CLI.md` §9와 어긋나는 기존 공백을 물려받을 뿐 넓히거나 닫지 않는다.
- README는 결정 12의 SHA 고정 뒤에 `qsh setup` 절을 얻는다. 그 전에 "First run" 절을 고치면 M9 재측정의 대상 문서가 바뀐다.
- `docs/adr/README.md` 색인에 0024 행을 더하고 표 아래의 "0024는 번호만 예약" 문장에서 0024를 뺀다.
- 마일스톤 배치는 P1이고 구체적인 자리는 `docs/ROADMAP.md` §5의 M12 (b)다. M7 DoD 1과 M9 DoD 1은 이 ADR과 독립적으로 사람 몫으로 남는다.
- 이 ADR이 승인되면 이슈 #3 2026-09-24 코멘트의 "남은 결정" 항목(`qsh setup`)이 닫힌다. 완료 기준 초안 네 줄과의 관계는 이렇다. 5분 기준은 결정 12의 캠페인 PASS로만 닫힌다. 멱등·default-deny·fail closed는 위 테스트가 고정한다. "비밀 출력 없음"은 키 재료에 한해 `setup_output_never_carries_key_material`이 고정하고, 초대 코드는 설계상 발급한 실행의 출력에만 나간다(결정 9). 수동 프로비저닝 경로 유지는 결정 9의 `command` 필드와 결정 3의 파일 경계가 지킨다. 네 경로 진단 기준의 `-D` 갈래는 `--forward` 검증이 setup 안에서만 일부 덮고, doctor가 `forward.local` 누락을 첫 CONNECT 전에 잡지 못하는 공백은 그대로 남는다.
- 구현 크기는 1.6~2.0ew로 추정한다. 측정값이 아니다. 내역은 `qsh-core` setup 모듈과 계획·단계 실행, 초대 읽기 도우미, 재시작 상수 추출 0.6~0.7, CLI 렌더와 프롬프트 0.3, 계약 타입·fixture·CLI.md·PRD·man 0.2, 테스트와 arch 금지 0.4~0.5, README·캠페인 문서 0.1~0.3이다.
