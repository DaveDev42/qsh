# M2 mobility campaign — Wi-Fi ↔ tethering, N = 20

> **상태: NOT YET RUN.** 아래 20행 표는 **비어 있다**. 이 문서는 기록 **템플릿**이며,
> 캠페인 자체는 사람 조작자(실기기 라디오 토글)와 **두 번째 실호스트**(`qsh serve`)가
> 있어야 수행된다. 표가 채워지고 §7 요약이 작성되기 전까지 `PLAN.md` Step 9 (d)와
> `docs/ROADMAP.md` M2 DoD 5번은 **미충족**이다. 어떤 체크박스도 이 문서 때문에
> 통과 처리되어서는 안 된다.

## 1. 목적

`docs/PRD.md` §15 SC3(네트워크 전환 시 세션 생존)의 **조기 실측**이다. CI의 chaos
proxy(`docs/design/testing.md` L4)는 PR 회귀 게이트이고, 실제 인터페이스 전환에서
나오는 수치는 이 캠페인만이 준다 — `repath()`/`sever()`는 실기기 전환이 서버에게
보이는 *모습*을 재현할 뿐, 라디오 down/up·DHCP·NAT 재바인딩의 실제 지연은 재현하지
않는다.

이 캠페인은 **합격/불합격 게이트가 아니다**(`PLAN.md` Step 9 (a)). 실패 회차는 M2를
막지 않고 M8 백로그 항목으로 남는다. 본 캠페인(N ≥ 60, ≥ 95%)은 **M8**이며 이
문서를 그대로 재사용한다 — §6의 표를 60행 이상으로 늘리고 §7 요약을 다시 계산하면
된다(파일은 `docs/campaigns/m8-mobility.md`로 복사, 이 문서는 M2 기록으로 보존).

## 2. 전제 조건 (정확히 이대로)

1. **두 번째 호스트가 `qsh serve`를 실행 중이어야 한다.** 노트북 자신이 아니라 별도
   장비여야 한다 — 전환 대상이 노트북의 링크이므로 loopback은 이 시험을 무의미하게
   만든다. 그 호스트는 노트북이 **양쪽 경로(Wi-Fi, 테더링)에서 모두** 도달할 수 있는
   주소에 있어야 한다.
   ```
   host$ qsh serve --bind 0.0.0.0:4433
   ```
2. **핀 고정된 trust 항목**이 노트북에 있어야 한다(`docs/CLI.md` §6.11). M2의 ACL
   자세는 allow-all-pinned이므로, 핀이 없으면 세션 자체가 열리지 않는다.
   ```
   laptop$ qsh trust add campaign-host --address <host>:4433 --fingerprint sha256:... --json
   laptop$ qsh trust list --json
   ```
3. **격리 프로필 + `key_store = "file"`.** 캠페인은 재dial·재attach를 20회 이상
   반복하므로 macOS 미서명 바이너리의 Keychain 재프롬프트가 측정을 오염시킨다
   (`PLAN.md` §4 감시 항목). 전용 프로필을 쓰고 platform keystore를 쓰지 않는다.
   ```
   laptop$ export QSH_CONFIG_DIR="$HOME/.qsh-campaign/config"
   laptop$ export QSH_STATE_DIR="$HOME/.qsh-campaign/state"
   laptop$ mkdir -p "$QSH_CONFIG_DIR" "$QSH_STATE_DIR"
   laptop$ printf '[identity]\nkey_store = "file"\n' > "$QSH_CONFIG_DIR/config.toml"
   laptop$ qsh identity init --key-store file --json
   ```
   `resume.json`은 `$QSH_STATE_DIR`에 생기며 0600이다. **토큰 값을 이 문서에 옮겨
   적지 않는다** — 기록 대상은 `session_ref`뿐이다.
4. **세션을 여는 장비와 attach하는 장비가 같아야 한다.** resume credential은 세션을
   연 peer identity에 묶여 있다(`docs/CLI.md` §6.3, ADR-0007). 다른 노트북에서
   attach하면 원격 요청 전에 로컬 `SESSION_NOT_FOUND`(`reason: "no_resume_token"`)로
   실패한다 — 이는 캠페인 실패가 아니라 조작 실수다.
5. **stderr를 파일로 캡처하고, 기본 verbosity로 실행한다.** recovery 텔레메트리는
   stderr 전용 한 줄 JSON이다(`docs/CLI.md` §6.4, `docs/design/testing.md` L4):
   target `qsh::recovery`, level INFO, 필드 `recovery` / `time_to_recovery_ms` /
   `session_ref`. `--quiet`를 붙이면 이 줄이 사라져 캠페인이 무의미해진다.
6. **테더링이 실제로 대안 경로여야 한다.** 전환 전에 Wi-Fi를 끈 상태에서 호스트에
   도달되는지 한 번 손으로 확인한다(`qsh sessions campaign-host --json`). 폰이
   caller-side NAT 뒤라 호스트에 닿지 못하면 모든 회차가 `failed`로 나오고, 그것은
   qsh가 아니라 시험 환경의 결함이다 — 비고란에 그렇게 적는다. 스크립트도 여기를
   거든다: macOS 스크립트는 테더 service가 *비활성*이면 exit 3으로 거부하고, Linux
   스크립트는 테더 device가 `connected`가 아니거나 `--tether-iface`가 아예 없으면
   경고를 찍는다. 다만 실제 도달성은 여전히 사람이 확인해야 한다.

## 3. 사전 정의된 합격/불합격 기준 (실행 **전에** 고정)

`docs/design/testing.md` L4 인용: *"통과 기준은 사전 정의: idle timeout이 뒤늦게
터져서 복구되는 것은 통과가 아니다 — path 사망 감지 후 **2초 내 재dial + resume**이
목표"*.

| 분류 | 정의 |
|---|---|
| `migrated` | QUIC connection migration으로 같은 연결이 새 경로에서 계속됐다. 재dial 없음, resume 없음. **PASS** (예산 내인 경우) |
| `resumed` | 연결이 죽고 클라이언트가 재dial → `session.attach` → replay로 세션을 이어받았다. **PASS** (예산 내인 경우) |
| `failed` | 위 둘 중 어느 것도 예산 안에 일어나지 않았다. 세션이 끊겼거나, 조작자가 개입해야 했거나, 예산을 넘겨 복구됐다. **FAIL** |

- **예산: `time_to_recovery_ms` ≤ 2000.** 측정 시점은 클라이언트의 path 사망 감지
  시각이며 라디오 토글 시각이 아니다(스크립트가 찍는 `switch_issued_ms`는 상관용
  보조 정보일 뿐 측정치가 아니다).
- **idle timeout에 기대어 늦게 복구된 회차는 `failed`로 분류한다.** quinn의 idle
  timeout은 45초이므로 "결국 돌아왔다"는 관측은 통과 근거가 되지 못한다. 실무
  판정: `time_to_recovery_ms > 2000`이면 텔레메트리가 `resumed`라고 말하더라도
  **표의 recovery 열에는 `failed`로 적고** 비고에 원 분류와 실제 ms를 남긴다.
  `scripts/mobility/summarize.py`는 같은 회차를 `over_budget`으로 세며, 성공 수에
  절대 합산하지 않는다.
- **`time_to_recovery_ms`가 없거나 숫자가 아닌 복구 회차는 `unverified`다.** 계약상
  이 필드는 항상 존재하는 `u64`이므로(qsh-core `RecoveryReport::to_json_line`),
  값이 없다는 것은 캡처/파싱이 실제 emitter와 어긋났다는 뜻이다. 측정되지 않은
  복구는 예산 내 복구가 아니다 — `summarize.py`는 이를 `unverified`로 따로 세고
  `within_budget`에도 그 비율의 분자에도 넣지 않는다. `unverified`가 0이 아니면
  **먼저 캡처를 고치고 다시 돌린다**. 그 상태의 수치는 판정 근거가 아니다.
- **gap**: `session.gap` event가 관측되면 `gap?` 열에 `yes`. gap은 그 자체로
  불합격이 아니지만(replay ring 밖으로 밀린 정상 동작) 회차의 성격이 다르므로
  반드시 기록한다. gap 없이 바이트가 유실됐다면 그것은 SC4 위반이며 캠페인 결과가
  아니라 **버그 리포트**다.
- **한 회차 = 한 전환**(한 방향). 20행 = 20회 전환이며, 스크립트의 `--iterations 10`이
  왕복 10회 = 전환 20회를 만든다. 표의 `run` 열은 스크립트 기록줄의 **`transition`**
  필드(1부터 단조 증가, 전환 1회당 1)다. 기록줄의 `run` 필드는 *왕복* 번호(1..10)로
  다른 값이니 혼동하지 않는다.

## 4. 조작 절차

```bash
# 0. 전제 조건 (§2) 완료. 아래는 전부 노트북에서.
cd <repo>

# 1. 캠페인 프로필 환경변수 export (§2.3)

# 2. 대화형 세션을 열고 stderr를 캡처한다. 기본 verbosity, --quiet 금지.
#    session_ref는 stderr 첫 줄들과 `qsh sessions` 로 확인해 표에 적는다.
#    recovery 줄에는 시각 필드가 없다(RecoveryReport::to_json_line은
#    recovery/time_to_recovery_ms/session_ref 세 필드뿐). 시각으로 대응시키고
#    싶으면 캡처 자체에 타임스탬프를 붙인다 — summarize.py는 줄 앞의 접두사를
#    건너뛰고 첫 '{' 부터 파싱하므로 아래 형태 그대로 집계된다.
qsh dave@campaign-host 2> mobility-stderr.log
#    (선택) 타임스탬프를 붙여 캡처하려면:
#    qsh dave@campaign-host 2> >(while IFS= read -r l; do \
#        printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$l"; done > mobility-stderr.log)

# 2b. gap 관측 채널. `session.gap`은 대화형 TUI에 인라인 주석으로만 뜬다
#     ("output was dropped; the session resumed at offset N") — stderr 캡처에도
#     summarize.py에도 나오지 않는다. gap? 열을 채우려면 세션 자체를 기록해야
#     한다: `script -q mobility-tty.log qsh dave@campaign-host 2> mobility-stderr.log`
#     (또는 tmux `pipe-pane`). 나중에:
#         grep -n "output was dropped" mobility-tty.log

# 3. 다른 터미널에서, 세션 안에서 확인 가능한 부하를 걸어 둔다.
#    (세션 안에서) while true; do date -u +%H:%M:%S.%3N; sleep 0.2; done
#    출력이 끊긴 구간과 replay 이후 연속성을 눈으로 확인할 수 있다.

# 4. 또 다른 터미널에서 전환 스크립트를 돌린다.
#    먼저 반드시 --dry-run 으로 대상 인터페이스를 확인한다.
scripts/mobility/switch-macos.sh --dry-run --iterations 10
scripts/mobility/switch-macos.sh --iterations 10 --settle 8 --log mobility-switch.log
#   Linux:
scripts/mobility/switch-linux.sh --dry-run --iterations 10
scripts/mobility/switch-linux.sh --iterations 10 --settle 8 --log mobility-switch.log

# 5. 끝나면 세션을 detach(~d)하고 텔레메트리를 집계한다.
scripts/mobility/summarize.py mobility-stderr.log
scripts/mobility/summarize.py --json mobility-stderr.log > mobility-summary.json

# 6. §6 표를 채우고 §7 요약을 적는다. 대응은 **순서(ordinal)**로 한다:
#    n번째 qsh::recovery 줄 = mobility-switch.log 의 transition=n 기록줄.
#    (recovery 줄 자체에는 시각이 없다. 2단계에서 타임스탬프를 붙여 캡처했다면
#     switch_issued_ms 와 교차 검증할 수 있으나, 기준은 순서다.)
#    한 전환이 recovery 줄을 하나도 만들지 않았다면 그 자체가 관측이다 —
#    해당 행 recovery=failed, 비고에 "no telemetry line"이라고 적고, 이후
#    행들의 순서 대응이 한 칸 밀리지 않게 여기서 다시 맞춘다.
```

주의:

- 스크립트는 종료 시(정상 종료·Ctrl-C·오류 모두) 원래 Wi-Fi 전원/라디오 상태를
  trap으로 복구한다. 그래도 캠페인 종료 후 링크 상태를 눈으로 확인한다.
- `--settle`은 조작자가 관측할 시간을 벌기 위한 값이며 측정 예산과 무관하다. 8초는
  2초 예산의 4배로, 복구가 끝난 뒤 다음 전환이 오도록 잡은 값이다.
- 회차 도중 세션이 완전히 죽으면(`failed`) 그 회차를 기록하고 세션을 새로 열어
  이어서 진행한다. 새 세션의 `session_ref`를 비고에 적는다.

## 5. 환경 기록 (캠페인 시작 시 채운다)

| 항목 | 값 |
|---|---|
| 날짜 (UTC) | _(미기재)_ |
| 조작자 | _(미기재)_ |
| 클라이언트 장비 / OS | _(미기재)_ |
| 서버 장비 / OS / `qsh serve` bind | _(미기재)_ |
| qsh 커밋 SHA | _(미기재)_ |
| Wi-Fi SSID / 대역 | _(미기재)_ |
| 테더링 방식 (USB / 개인용 핫스팟) / 캐리어 | _(미기재)_ |
| 스크립트 호출 (정확한 명령줄) | _(미기재)_ |
| stderr 캡처 파일 | _(미기재)_ |

## 6. 회차 기록 (20행 — **아직 채워지지 않음**)

`recovery` 열은 §3의 사전 정의 기준을 적용한 **최종 분류**다(예산 초과는 `failed`).
`time_to_recovery_ms`는 텔레메트리 원값을 그대로 적는다.

| run | platform | direction | recovery | time_to_recovery_ms | gap? | notes |
|---:|---|---|---|---:|---|---|
| 1 |  |  |  |  |  |  |
| 2 |  |  |  |  |  |  |
| 3 |  |  |  |  |  |  |
| 4 |  |  |  |  |  |  |
| 5 |  |  |  |  |  |  |
| 6 |  |  |  |  |  |  |
| 7 |  |  |  |  |  |  |
| 8 |  |  |  |  |  |  |
| 9 |  |  |  |  |  |  |
| 10 |  |  |  |  |  |  |
| 11 |  |  |  |  |  |  |
| 12 |  |  |  |  |  |  |
| 13 |  |  |  |  |  |  |
| 14 |  |  |  |  |  |  |
| 15 |  |  |  |  |  |  |
| 16 |  |  |  |  |  |  |
| 17 |  |  |  |  |  |  |
| 18 |  |  |  |  |  |  |
| 19 |  |  |  |  |  |  |
| 20 |  |  |  |  |  |  |

열 정의:

- **run** — 1..20, 전환 1회당 1행. 스크립트 기록줄의 `transition` 필드와 같은 값
  (기록줄의 `run` 필드는 왕복 번호이므로 다른 값이다).
- **platform** — `macos` / `linux` (전환을 수행한 클라이언트).
- **direction** — `wifi->tether` / `tether->wifi`.
- **recovery** — `migrated` / `resumed` / `failed` (§3의 최종 분류).
- **time_to_recovery_ms** — 텔레메트리 원값. `failed`로 텔레메트리가 값을 주지
  않은 경우 `-`.
- **gap?** — `session.gap` 관측 여부 (`yes` / `no`). 관측 채널은 §4 2b의 TTY
  기록뿐이다 — TUI 인라인 주석("output was dropped; the session resumed at
  offset N"). TTY를 기록하지 않았다면 이 열은 `-`로 두고 비고에 "not captured"라고
  적는다. 빈칸이나 `no`로 채우지 않는다.
- **notes** — 예산 초과 시 원 분류와 ms, 세션 재생성, 환경 이상 등.

## 7. 요약 (표가 채워진 뒤 작성 — **아직 미작성**)

`scripts/mobility/summarize.py mobility-stderr.log`의 출력을 그대로 붙이고, 아래를
채운다.

| 지표 | 값 |
|---|---|
| 전환 총수 (N) | _(미기재, 목표 20)_ |
| `migrated` | _(미기재)_ |
| `resumed` | _(미기재)_ |
| `failed` | _(미기재)_ |
| 예산(2000 ms) 내 복구 비율 | _(미기재)_ |
| `unverified` (측정 불가) | _(미기재, 0이 아니면 캡처 결함)_ |
| time-to-recovery p50 / p90 / p95 / max (ms) | _(미기재)_ |
| gap 발생 회차 수 | _(미기재)_ |

서술로 남길 것:

- migrated 대 resumed의 분해가 예상과 맞는가 — Wi-Fi off는 소켓이 죽으므로 대개
  `resumed`, 경로가 살아 있는 채 주소만 바뀌는 경우가 `migrated`다. 전부 `resumed`면
  migration 경로가 실기기에서 한 번도 타지 않았다는 뜻이며 그 자체로 기록할 가치가
  있다.
- `failed` 회차의 원인 분류(도달 불가한 테더 경로 / 예산 초과 / 세션 소실) — 각각
  **M8 백로그 항목**으로 옮기고 이슈 링크를 적는다. M2를 막지 않는다.
- 이 20회로 SC3의 95%를 판정하지 않는다(표본 부족). 판정은 M8의 N ≥ 60이다.

## 8. M8 재사용

M8은 이 문서를 템플릿으로 복사해 **N ≥ 60**으로 수행한다(`docs/ROADMAP.md` M8
수용 기준). 바뀌는 것은 행 수와 §7의 판정 문장(그때는 ≥ 95%가 실제 게이트다)뿐이며,
§2 전제 조건·§3 사전 정의 기준·§4 절차·스크립트는 그대로 쓴다. 기준을 M8에서
새로 정하지 않는 것이 이 문서의 존재 이유다.
