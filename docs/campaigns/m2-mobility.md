# M2 mobility campaign — Wi-Fi ↔ tethering, N = 20

> **상태: 수행 완료 (2026-08-19, N = 20).** §5–§7이 실측 기록이다. 결과 요약:
> path 사망 10회 전부 자동 resume으로 세션 생존·output 무손실(SC4·SC5 실기기
> 확인), 그러나 2초 예산 내 복구는 10회 중 1회 — 초과분의 지배 요인은 qsh가 아니라
> **Tailscale underlay 재경로(~4–5 s)** 다(§7 서술). 이 캠페인은 합격 게이트가
> 아니며(§1), 실패 회차 원인은 §7 끝의 M8 백로그로 이관됐다.

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
- **`time_to_recovery_ms`는 사용자 체감 단절이 아니다 — 반드시 감지 지연을 더해
  보고한다.** 클럭이 *감지 시점*에서 시작하므로(`crates/qsh-core/src/telemetry.rs`
  의 `RecoveryTimer`는 driver가 path 사망을 판정한 뒤에 시작한다), 실제 단절은

  > **사용자 체감 단절 ≈ 감지 지연 + `time_to_recovery_ms`**

  다. 감지 지연은 `PathWatchConfig`(`crates/qsh-core/src/client/pathwatch.rs`)가
  정하며, 세션이 **활성**인지 **유휴**인지에 따라 두 값이다:

  | cadence | 조건 | probe 간격 | 감지 지연 (3 strikes, 침묵 하한 1 s) |
  |---|---|---:|---:|
  | active | 마지막 사용자 활동/트래픽 이후 `active_window`(15 s) 이내 | 250 ms | **~1 s** |
  | idle | 그보다 오래 조용했던 attach | 5 s | **최대 ~15 s** |

  §4 절차는 세션 안에 0.2 s 주기 부하를 걸어 두므로(3단계) 이 캠페인의 회차는
  **active cadence(~1 s)** 로 도는 것이 정상이다. 즉 예산 내 회차의 실제 체감
  단절은 대략 `1000 + time_to_recovery_ms` ms다. §7 요약에 **두 값을 합쳐 적는다**
  — `time_to_recovery_ms`만 보고하면 SC3을 과소보고하게 된다. 부하를 걸지 않은
  채(또는 15 s 넘게 조용한 상태에서) 전환한 회차가 있다면 그 회차는 idle cadence로
  돌았을 수 있으므로 비고에 적고 체감 단절에 ~15 s를 쓴다.
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
#     한다. 이때 stderr 리다이렉트는 반드시 `script`의 **안쪽**에 둔다 — BSD
#     `script`(macOS)는 명령의 stdin/stdout/stderr를 전부 자기 pty에 붙이므로,
#     바깥에 둔 `2>`는 script 자신의 stderr만 잡고 qsh의 텔레메트리는 전부
#     tty 로그로 섞여 들어간다(= mobility-stderr.log가 0바이트가 되고 모든
#     회차가 "no telemetry line"이 된다):
#         script -q mobility-tty.log sh -c 'exec qsh dave@campaign-host 2> mobility-stderr.log'
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
| 날짜 (UTC) | 2026-08-19 07:59:58 – 08:02:35 (전환 20회, 2 m 37 s) |
| 조작자 | Dave |
| 클라이언트 장비 / OS | Dave-MBP16 (Apple M1 Max) / macOS (Darwin 27.0.0) |
| 서버 장비 / OS / `qsh serve` bind | Dave-Windows-WSL (WSL2 Ubuntu, 7950X) / `qsh serve --bind 0.0.0.0:4433` (tmux, 전용 캠페인 프로필) |
| qsh 커밋 SHA | 바이너리 양단 `37dd5ea` (release), 문서·스크립트 `ff433dc` |
| Wi-Fi SSID / 대역 | 홈 Wi-Fi, en0 172.31.44.37 (SSID는 macOS가 비공개 처리 — 조작자 확인) |
| 테더링 방식 / 캐리어 | iPhone **USB 테더**(개인용 핫스팟, en10 192.0.0.2) / 캐리어 IPv6 prefix `2001:2d8::/32` 관측 |
| **경로 토폴로지 (중요)** | 클라이언트→서버 접속이 **Tailscale(utun) 경유** (`dave-windows-wsl.tail91e9e.ts.net`). QUIC 4-tuple이 tailnet 주소로 고정되어 물리 경로 전환이 QUIC에는 blackhole→복구로만 보인다 — §7 서술 참조 |
| 스크립트 호출 (정확한 명령줄) | `scripts/mobility/switch-macos.sh --iterations 10 --settle 8 --log mobility-switch.log` |
| stderr 캡처 파일 | `mobility-stderr.log` (28 레코드) + `mobility-switch.log` (20 전환) + `mobility-tty.log` (TTY 기록, 701 KB) — 타임스탬프 미부착 캡처(§7 방법론 한계) |

## 6. 회차 기록 (20행 — 2026-08-19 실측)

`recovery` 열은 §3의 사전 정의 기준을 적용한 **최종 분류**다(예산 초과는 `failed`).
`time_to_recovery_ms`는 텔레메트리 원값(다시도 회차는 **마지막 resumed 시도**의
값, 시도 사슬은 notes)이다. 이 캠페인의 레코드는 **시도 단위**로 나왔다(사슬
`failed → failed → resumed` = path 사망 1회에 복구 시도 3회) — 28 레코드가 10개
그룹으로 묶이며, 그룹↔전환 대응은 §7 방법론 절의 ordinal 규칙을 따른다.
`tether->wifi` 10회는 경로가 아예 절단되지 않아(USB 경로 유효 유지) 레코드 0건
— §3의 세 범주 어디에도 속하지 않는 **무중단 유지(held)** 로, `-`로 적고 §7에서
설명한다.

| run | platform | direction | recovery | time_to_recovery_ms | gap? | notes |
|---:|---|---|---|---:|---|---|
| 1 | macos | wifi->tether | failed | 233 | no | 시도 3회 f2001→f2002→r233, 감지 후 총 ≈4.24 s > 2 s. 원분류 resumed |
| 2 | macos | tether->wifi | - | - | no | held — 경로 미절단, 레코드 0건(정상). PRD SC3의 "자동 유지" |
| 3 | macos | wifi->tether | resumed | 385 | no | 단일 시도, **예산 내 ✓** (직전 사망로 underlay가 warm이었던 것으로 추정) |
| 4 | macos | tether->wifi | - | - | no | held |
| 5 | macos | wifi->tether | failed | 307 | no | f2002→f2001→r307, 총 ≈4.31 s |
| 6 | macos | tether->wifi | - | - | no | held |
| 7 | macos | wifi->tether | failed | 1020 | no | f2002→f2001→r1020, 총 ≈5.02 s |
| 8 | macos | tether->wifi | - | - | no | held |
| 9 | macos | wifi->tether | failed | 323 | no | f2001→f2002→r323, 총 ≈4.33 s |
| 10 | macos | tether->wifi | - | - | no | held |
| 11 | macos | wifi->tether | failed | 1055 | no | f2002→f2001→r1055, 총 ≈5.06 s |
| 12 | macos | tether->wifi | - | - | no | held |
| 13 | macos | wifi->tether | failed | 332 | no | f2002→f2003→r332, 총 ≈4.34 s |
| 14 | macos | tether->wifi | - | - | no | held |
| 15 | macos | wifi->tether | failed | 568 | no | f2001→f2001→r568, 총 ≈4.57 s |
| 16 | macos | tether->wifi | - | - | no | held |
| 17 | macos | wifi->tether | failed | 1008 | no | f2001→f2001→r1008, 총 ≈5.01 s |
| 18 | macos | tether->wifi | - | - | no | held |
| 19 | macos | wifi->tether | failed | 1076 | no | f2001→f2001→r1076, 총 ≈5.08 s |
| 20 | macos | tether->wifi | - | - | no | held. 세션은 캠페인 후 2.5 h 더 부하 유지 후 조작자가 정상 종료 (SC5 위반 없음) |

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

## 7. 요약 (2026-08-19 작성)

`scripts/mobility/summarize.py mobility-stderr.log` 출력 그대로:

```
recovery events: 28
  migrated     0  (  0.0%)
  resumed     10  ( 35.7%)
  failed      18  ( 64.3%)

budget: 2000 ms (docs/design/testing.md L4 — re-dial + resume)
  within budget    10  ( 35.7% of all events)
  over budget       0   <- FAIL per the pre-defined criterion

time to recovery (ms, recovered events only)
  min 233   max 1076
  p50 385   p90 1055   p95 1076   p99 1076
```

summarize는 **레코드(=복구 시도) 단위**로 센다. 전환 단위 집계는 아래와 같다
(28 레코드 = path 사망 10회 × 시도 1–3회; §6 참조):

| 지표 | 값 |
|---|---|
| 전환 총수 (N) | 20 (wifi->tether 10, tether->wifi 10) |
| `migrated` | 0 (토폴로지상 도달 불가 — 아래 서술) |
| `resumed` (예산 내, 전환 단위) | 1 (run 3) |
| `failed` (예산 초과, 전환 단위) | 9 — 전부 wifi->tether, 전부 시도 3회 사슬 |
| **held** (무중단 유지, §3 범주 외) | 10 — 전부 tether->wifi |
| 예산(2000 ms) 내 복구 비율 | path 사망 기준 1/10 (10%) · PRD SC3 어법("자동 유지 또는 resume") 기준 **11/20 (55%)** |
| `unverified` (측정 불가) | 0 (캡처 정상) |
| time-to-recovery p50 / p90 / p95 / max (ms) | 385 / 1055 / 1076 / 1076 (min 233; resumed 시도 단위) |
| 감지 cadence | 전 회차 active (세션 내 0.2 s 부하 유지, §4 3단계 수행) |
| **사용자 체감 단절** (추정 = 감지 ~1 s + 시도 사슬 합) | held 0 s · run 3 ≈ 1.4 s · failed 회차 ≈ 5.2–6.1 s |
| gap 발생 회차 수 | 0 (TTY 기록 grep — `output was dropped` 0건) |

### 서술

- **세션은 한 번도 죽지 않았다.** path 사망 10회 전부 조작자 개입 없이 자동
  resume됐고, 같은 `session_ref` 하나가 캠페인 전체(그리고 이후 2.5 h 추가 부하)를
  관통했다. gap 0건 — **SC4(무손실)·SC5(생존)의 실기기 확인**이다. TTY 기록의
  원격 타임스탬프 스트림은 캠페인 창 내 최대 간격 0.221 s(부하 루프 주기)로
  결손이 없다.
- **migrated 0의 이유는 토폴로지다.** 접속이 Tailscale(utun) 경유라 QUIC 4-tuple이
  tailnet 주소로 고정된다 — 물리 인터페이스가 바뀌어도 QUIC 관점의 주소 변화가
  없으므로 connection migration 경로는 실기기에서 **한 번도 타지 않았다**(§5의
  예상대로). M8 캠페인은 direct-address 토폴로지를 병행해야 migration 분해를 처음
  관측한다.
- **failed 9회의 지배 요인은 qsh 밖에 있다.** 각 사망에서 2 s 복구 시도창이 2회
  만료된 뒤 3번째에 성공했다 — Tailscale underlay가 en0→en10로 WireGuard 경로를
  재수립하는 데 ~4–5 s가 걸렸고, 그동안은 재dial도 같은 utun을 지나므로 성공할 수
  없다. underlay가 살아난 뒤의 qsh 자체 복구는 233–1076 ms로 전부 예산 내다.
  분류: 도달 불가한 테더 경로 0 / **예산 초과 9** / 세션 소실 0.
- **tether->wifi 10회가 전부 held인 것도 토폴로지의 귀결이다.** Wi-Fi 복귀 시
  USB 경로가 그대로 유효하므로 underlay가 옮겨갈 이유가 없고, path 사망 자체가
  없다. §3 분류표에는 이 결과를 담을 범주가 없다 — 실측이 드러낸 기준의 공백이며,
  PRD SC3 어법으로는 "자동 유지" 성공에 해당한다.
- 이 20회로 SC3의 95%를 판정하지 않는다(표본 부족·단일 토폴로지). 판정은 M8의
  N ≥ 60이다.

### 방법론 노트 (M8이 반복하지 말 것)

- **레코드는 시도 단위다.** `recover()`가 시도마다 한 줄을 찍으므로 "n번째 줄 =
  전환 n"의 1:1 ordinal 규칙(§4 6단계)은 이 데이터에 적용 불가였다. 그룹핑(사슬의
  마지막 resumed가 그룹 종료) 후 그룹↔사망 전환을 ordinal로 대응시켰다. run 1↔3
  경계는 이 규칙의 유일한 불확실 지점(단일 시도 그룹 r385가 run 1의 2차 사망일
  가능성)이며, 표는 보수적 해석을 적었다. **M8은 타임스탬프 부착 캡처(§4 2단계
  선택지)를 필수로** 하여 `switch_issued_ms`와 교차 검증하라.
- **TTY 기록의 원격 타임스탬프로 체감 단절을 측정할 수 없다.** 원격 루프는 경로
  사망 중에도 계속 돌고 밀린 출력이 replay로 전부 도착하므로, 스탬프 연속성은
  체감 단절이 아니라 무손실의 증거다. 체감 단절 행이 추정치인 이유다.
- **호스트 시계 sawtooth를 스탬프 이상으로 오독하지 말 것.** 부하 상태의
  WSL2 VM 시계가 ~30 s 주기로 ~2.3–2.5 s 스냅백하는 것을 관측했고(독립 프로브:
  65 s 동안 realtime-vs-monotonic −2.493 s 점프 1회), TTY 기록의 주기적 역행·중복
  3건·비순차 단발은 전부 이것으로 설명된다. qsh 시퀀스 이상이 아니다.

### M8 백로그 (이 캠페인이 만든 항목)

1. **VPN-underlay 재경로가 2 s 예산을 지배** — M8 캠페인에 direct-address
   토폴로지 병행 + 재시도 정책(시도창 길이 vs 횟수) 재검토.
2. **migration 경로 실기기 미실행** — direct 토폴로지에서만 관측 가능(위 1과 동일
   실행에서 해소).
3. **§3 분류에 `held`(무중단) 범주 추가** — tether->wifi류 무사망 전환의 정식 자리.
4. **타임스탬프 부착 캡처를 필수화** — 그룹↔전환 ordinal 모호성 제거.
5. TUI가 자기 attach의 lease 획득을 "writer lease moved"로 표시(cosmetic, Step 6
   산물) — 억제 조건 추가.

## 8. M8 재사용

M8은 이 문서를 템플릿으로 복사해 **N ≥ 60**으로 수행한다(`docs/ROADMAP.md` M8
수용 기준). 바뀌는 것은 행 수와 §7의 판정 문장(그때는 ≥ 95%가 실제 게이트다)뿐이며,
§2 전제 조건·§3 사전 정의 기준·§4 절차·스크립트는 그대로 쓴다. 기준을 M8에서
새로 정하지 않는 것이 이 문서의 존재 이유다.
