# M8 adversarial-load campaign — T2 실측 이상 규모 N

## 1. 목적

`.github/workflows/load.yml`은 고정된 N(source 8개, dial 64개, TCP 512개)으로
`crates/qsh-cli/tests/adversarial_load.rs`를 push(main)마다 자동으로 돌리는
단일 판정이다. 이 자동 실행은 회귀 감시자이지 규모 탐색이 아니다 — bound가
실제로 어디서 깨지기 시작하는지는 사람이 더 큰 N을 손으로 돌려야 보인다.

이 캠페인은 그 자리다. `docs/campaigns/m2-mobility.md`가 CI chaos proxy로는
못 재는 실기기 네트워크 전환 지연을 손으로 잰 것과 같은 지위로, 이 문서는
load.yml이 고정한 N 이상에서 RSS·fd·echo p95 bound가 얼마나 여유가 있는지
사람이 손으로 재고 기록한다. `docs/design/testing.md` L9/L10 인용대로 절대
수치는 공유 러너의 flake로 무시 습관을 만들 수 있으므로 PR 필수 게이트에는
두지 않는다는 것과 같은 이유다.

M2 mobility 캠페인과 마찬가지로 이 문서는 **합격/불합격 게이트가 아니다** —
실패 회차가 M8을 막지 않는다. DoD 5(`docs/ROADMAP.md:113`) 자체의 판정은
main이 Dave-Windows-WSL에서 돌린 실측(`ARBITRATION-4.md` "4c 구현 판정" Q5)이
닫으며, load.yml은 그 뒤로도 계속 도는 회귀 감시자다.

## 2. 전제 조건

1. **Linux.** 시나리오 1의 `127.0.0.0/8` source 다중화(alias 없이 전역
   bind)와 `/proc` 기반 RSS/fd 리더(`crates/qsh-cli/tests/common/mod.rs`의
   `rss_kib`/`open_fd_count`) 둘 다 Linux 전용이다. macOS는 `127.0.0.2` bind
   가 `Errno 49`로 실패하고 `/proc`이 없어 strict 실행 자체가 성립하지
   않는다.
2. **release 빌드.** `cargo build --release -p qsh-cli`로 먼저 만든 바이너리
   를 `QSH_LOAD_BIN`으로 가리킨다. debug 바이너리의 RSS/fd 모양은 DoD 5가
   재는 대상이 아니다.
3. **`ulimit -n` 확인.** 시나리오 13이 512개 TCP를 동시에 연다. 값이 낮으면
   (예: 1024 언저리) 여유가 얇으므로 실행 전에 `ulimit -n`을 확인하고 회차
   기록에 남긴다.
4. **다른 빌드와 겹치지 않는 상태.** cargo는 호스트당 한 번에 하나만 돈다.
   동시 빌드가 호스트 load를 밀어 올리면 echo p95 같은 상대 지표가 그
   경합으로 흔들린다 — echo 임계는 baseline도 같은 실행에서 재므로 경합
   자체가 잘못된 판정을 만들지는 않지만, 원인 분석이 어려워진다.
5. 저장소를 clone한 그 트리에서 그대로 돈다 — 이 캠페인은 개발 편의를 위한
   rsync 동기화 없이, 대상 호스트에 `git clone`한 사본을 그 자리에서 빌드하고
   실행하는 것을 기준 절차로 삼는다(다른 macOS 세션이 이 트리를 편집 중이면
   그 편집과 겹치지 않게 별도 clone을 쓴다).

## 3. 사전 정의된 합격/불합격 기준 (실행 전에 고정)

`docs/PRD.md:305`("Idle listener 메모리: 30MB 이하 **목표**")와
`docs/ROADMAP.md:112`("Idle listener RSS ≤ 30MB")가 이 수치의 상류다. PRD가
"목표"라고 적은 것을 그대로 받아, 실패했을 때 코드가 아니라 임계 자체를
의심할 여지를 열어 둔다.

| 축 | 기준 |
|---|---|
| idle RSS (부하 종료·세션 전부 close 후) | `2 MiB < rss <= 30 MB` |
| 부하 중 RSS | `30 MB + 8 MB × 살아 있는 세션 수` 이하 (시나리오 3처럼 세션 수가 작으면 이 상한은 사실상 느슨하다 — §6 참고) |
| fd (부하 종료 후) | 델타 `<= 0`, 하한 `fd >= 3` |
| fd (부하 중, 시나리오 13만) | baseline 대비 델타 `<= 64 + 8` |
| echo p95 | `max(같은 실행 baseline p95 × 3, 50 ms)` 이하, 절대 p95도 함께 기록 |
| audit 행 수 (시나리오 12a) | `floor(T/10)` 이상 `(ceil(T/10) + 1) × category수 × 2` 이하 (T=플러드 지속 초, 10초 창, 종료 flush 1창 포함, `[audit]`은 기본값이라 회전은 일어나지 않는다) |
| audit 디렉터리 부피 (시나리오 12b) | `[audit].max_bytes × ([audit].retain + 1)` 이하, **단 회전이 실제로 일어났음을 먼저 확인**(`audit.log.1` 존재) — 회전 없이 좁은 상계만 통과하는 것은 무의미하다(4c 적대 검토 A4) |
| 상한 강제 카운트 | 성립/거부 수가 config 값과 정확히 일치 (예: 시나리오 13 기본 forward cap 64 → 성립 정확히 64) |

시나리오 12c(감사 회전 실패 fail-closed, A17)는 4c-F2에서 시도됐다가 빠졌다.
`chmod 500`으로 상태 디렉터리 쓰기 권한만 없애는 구성은 `rotate_files`의
rename만 막을 뿐, 이미 열려 있는 파일 핸들의 append는 디렉터리 권한과
무관하게 계속 성공한다(`audit/writer.rs`의 `rotate()`가 rename 실패를
의도적으로 non-fatal로 다루는 F6 규율) — degraded 래치에 애초에 닿지 않는다.
실측에서는 session open/attach/close 반복이 감사 상태와 무관한 커넥션당
티켓 상한(`Server::MAX_PENDING_TICKETS_PER_CONN`, 32)에 먼저 걸렸다. 필수
판정(4a의 in-crate fail-closed 유닛 테스트)은 이 축소와 무관하다.

이 표는 `crates/qsh-cli/tests/adversarial_load.rs`의 단언과 동일하다 — 캠페인은
같은 판정을 더 큰 N으로 반복하는 것이지 새 기준을 세우는 것이 아니다.

## 4. 실행 절차

```bash
git clone <repo-url> qsh-load-campaign
cd qsh-load-campaign
ulimit -n          # §5 환경 기록에 채운다 (전제 조건 3항의 그 확인)
nproc
cat /proc/sys/net/core/rmem_max
cargo build --release -p qsh-cli
QSH_LOAD_STRICT=1 QSH_LOAD_BIN=$(pwd)/target/release/qsh \
  cargo nextest run -p qsh-cli --test adversarial_load --profile load --no-fail-fast
```

더 큰 N으로 손으로 반복하려면 `adversarial_load.rs`의 시나리오별 상수(source
수·dial 수·TCP 수)를 임시로 올려 재컴파일한 뒤 같은 명령을 돈다 — 이 변경은
캠페인 실행 전용이며 커밋하지 않는다. 각 회차마다 §6 표의 한 행을 채운다.

플레이크가 나오면 원인(코드 회귀인지 호스트 경합인지)을 20회 반복으로
가른다 — `S3`가 WSL fuzz 워커 포화와 순수 dial 타임아웃을 이 방법으로
구분한 선례를 그대로 따른다(`PROGRESS-4.md` Stage 4c-S3).

## 5. 환경 기록 (캠페인 시작 시 채운다)

| 항목 | 값 |
|---|---|
| 날짜 (UTC) | |
| 조작자 | |
| 호스트 / OS / 커널 | |
| `ulimit -n` | |
| `nproc` | |
| `net.core.rmem_max` | |
| qsh 커밋 SHA | |
| 바이너리 경로 | |

## 6. 회차 기록

시나리오별로 한 행. RSS/fd/echo 열은 `adversarial_load.rs`의 실패 메시지
형식(§3.6, `scenario {n} {name}: {관측} vs {임계} ({판정})`)을 그대로 옮긴다.

| 회차 | 시나리오 | N (source/dial/TCP) | 성립/거부 | RSS baseline/peak/idle (KiB) | fd baseline/peak/after | echo baseline/load p95 (ms) | 판정 | 비고 |
|---:|---|---|---|---|---|---|---|---|
| | 1 스푸핑 flood | | | | | - | | |
| | 2 연결 flood | | | | | - | | |
| | 3 세션 flood | | | | | | | |
| | 12a 감사 행 수 | | | (rows: ) | | - | | |
| | 12b 감사 회전·부피 | | | (rotated?/dir bytes: ) | | - | | |
| | 13 `-R` accept | | | | | - | | A-P2-5 p95: |

시나리오 3의 부하 중 RSS 판정은 세션 수가 8뿐이라 사실상 느슨하다(§3의
"부하 중 RSS" 기준) — 의미 있는 판정은 부하 후 idle 30 MB 쪽이다. 시나리오
3의 echo p95가 이 캠페인의 유일한 절대 성능 관측이며 baseline·부하 중 값을
모두 적는다.

## 7. 요약

회차 실행 뒤 다음을 적는다.

- 시나리오별 pass/fail과, fail이면 관측값이 임계를 얼마나 넘겼는지.
- RSS 30 MB(idle)에 대해 실측이 그 근처인지 여유가 큰지 — 여유가 크면 Step
  5에서 임계를 좁힐 근거가 되고, 근접하거나 넘으면 Step 5 재조정 대상이다.
- fd 델타가 0을 넘긴 회차가 있었는지(있었다면 그 자체가 버그 리포트다 — 이
  캠페인은 그 판정을 완화하지 않는다).
- 큰 N에서 새로 관측된 실패 모드(있다면).

## 8. 재사용

M2 mobility 캠페인처럼 이 문서는 다음 라운드에서 표를 늘리고 §7을 다시
계산해 재사용한다. 새 시나리오가 추가되면(Step 5) §3의 표와 §6의 열을
그 시나리오만큼 늘린다.
