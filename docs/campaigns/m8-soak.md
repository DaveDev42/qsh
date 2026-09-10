# M8 soak 캠페인 — 24h/100-session (DoD 2)

## 1. 목적

`crates/qsh-cli/tests/soak.rs`는 두 속도로 도는 한 시나리오다. 짧은 모드
(기본 120s/8세션)는 `[profile.load]`로 `.github/workflows/load.yml`이
push(main)마다 자동으로 돌리는 회귀 감시자다. 24h/100-session 모드는
`[profile.soak]`로 GHA 6h 상한 밖에서, 사람이 전용 호스트에 붙어 도는
캠페인이다 — `docs/campaigns/m2-mobility.md`가 CI로는 못 재는 실기기
전환 지연을 손으로 재는 것과 같은 지위이고, `m8-adversarial-load.md`가
load.yml 고정 N 이상을 손으로 재는 것과 같은 골격을 이 문서가 그대로
따른다.

M2/adversarial-load와 마찬가지로 이 문서는 **합격/불합격 게이트가 아니다**
— 회차 실패가 M8을 막지 않는다. `docs/ROADMAP.md`의 DoD 2 자체 판정은
main이 Dave-Windows-WSL 단독 점유에서 돌린 24h 실측(BRIEF-5.md §1.1 5e,
이 워크플로 밖)이 닫는다. 이 문서는 그 실측의 절차·사전 판정·기록 자리다.

## 2. 전제 조건

1. **Linux.** RSS/fd 리더(`qsh_testkit::procstat`의 `rss_kib`/
   `open_fd_count`)는 `/proc` 기반이라 Linux 전용이다. macOS에서
   `QSH_LOAD_STRICT`를 켜면 soak 테스트가 명시적으로 실패한다(스킵이
   아니다) — 이 캠페인은 애초에 Linux 호스트 전용이다.
2. **release 빌드.** `cargo build --release -p qsh-cli`로 만든 바이너리를
   `QSH_LOAD_BIN`으로 가리킨다. `scripts/soak/run.sh`는 이 바이너리를
   빌드하지 않는다 — 24h 내내 같은 바이너리(같은 sha256)로 재야 회차
   중간에 빌드가 바뀌는 변수를 없앨 수 있어서, 빌드는 절차의 별도 단계다.
3. **`ulimit -n` 확인.** 100세션 규모 + 사이클 재접속이 fd를 계속
   회전시킨다. `run.sh`가 `ulimit -n 65536`을 시도하지만 실패해도 죽지
   않으므로(권한 없는 셸일 수 있음), 실제 적용된 값을 `env.txt`에서
   확인하고 회차 기록에 남긴다.
4. **다른 빌드/soak과 겹치지 않는 상태.** WSL 규칙(§4)대로 cargo는 호스트당
   한 번에 하나만 돈다. 24h 동안 그 호스트에서 다른 cargo 작업을 돌리지
   않는다.
5. **fuzz 워커 종료 후.** 실행 호스트가 Dave-Windows-WSL이면 `cargo fuzz`/
   `*-fuzz` 프로세스 8개가 이미 그 호스트의 CPU를 점유하고 있을 수 있다
   — kill/renice는 절대 하지 않는다(하드 룰). soak 24h 런은 그 fuzz 라운드가
   자연 종료된 뒤에 시작한다(BRIEF-5.md §2 Q5).
6. **저장소 상태.** `run.sh`가 `env.txt`에 `git rev-parse HEAD`와 working
   tree clean/dirty 여부를 자동 기록한다 — dirty면 회차 기록에 그 사실이
   그대로 남는다(가리지 않는다).

## 3. 사전 정의된 합격/불합격 기준 (실행 전에 고정)

이 표는 `crates/qsh-cli/tests/soak.rs`(BRIEF-5.md §4.4)와
`scripts/soak/summarize.py`가 **동일하게** 계산한다 — 캠페인은 같은 판정을
24h/100세션 규모로 반복하는 것이지 새 기준을 세우는 것이 아니다. 테스트
바이너리 자신은 짧은 런 안에서 판단 가능한 축만 강한 assert로 검사하고,
표본이 많이 필요한 두 축(세션당 buffer 보조·RSS 추세)은 24h CSV를 받는
`summarize.py`가 마저 판단한다.

| 축 | 판정 | 판정 주체 |
|---|---|---|
| idle listener RSS | `baseline_rss <= 30 MiB`, `idle_end_rss <= 30 MiB` | soak.rs (assert) + summarize.py |
| 세션당 buffer | `(peak_rss − baseline_rss) / N <= 8 MiB` | summarize.py (assert). 보조 기록: `peak_rss <= 30 MiB + 8 MiB × N` |
| RSS 추세 | ramp 이후 steady 구간 회귀선 기울기 `< 1 MiB/h` | summarize.py (assert, steady 구간이 1h 미만이면 기록만) |
| listener fd (baseline/idle_end) | `idle_end_fds <= baseline_fds + 2` | soak.rs (assert) + summarize.py |
| listener fd (steady quarters) | steady 마지막 1/4 구간 fd 최댓값 `<= 첫 1/4 최댓값 + 2`. 위반은 `FD_GROWTH_LISTENER`로 표기 | soak.rs (`judge_fd_quarters`, assert) + summarize.py 양쪽 동일 구현(`quarter_split`). steady 표본이 `MIN_QUARTER_SAMPLES`(8) 미만이면 양쪽 다 위반 대신 기록만 남긴다 |
| self(테스트 프로세스) fd | steady 마지막 1/4 fd 최댓값 `<= 첫 1/4 최댓값 + 2`(사이클링 도중의 증가만 잰다). 위반은 `FD_GROWTH_CLIENT`로 표기(M7 carryover (iii) 재현) | soak.rs (`judge_fd_quarters`, assert, strict) + summarize.py. listener fd 축과 같은 `MIN_QUARTER_SAMPLES` 다운그레이드 규칙을 공유한다 |
| echo p95 | steady 창 중 p95가 bound(`max(3 × ramp 직후 baseline p95, 50 ms)`)를 넘는 창의 비율이 `ECHO_SPIKE_FRACTION_MAX`(10%)를 넘으면 위반이고 태그는 `ECHO_DEGRADED`다. bound는 고정 50ms가 아니라 이 런 자신의 ramp 직후 baseline에 대한 적응형 상한이다(공유 러너의 절대치 flake를 피하려는 T2 `adversarial_load.rs` 패턴과 같다). baseline을 못 구하면 50ms 바닥값으로 대체한다. 최댓값, 초과 창 수, steady 첫/마지막 1/4 구간 중앙값은 위반 여부와 무관하게 정보로만 기록한다(24h 저하 규칙을 세울 입력, ARBITRATION-5 "load.yml 첫 GHA soak 실행 판정") | soak.rs(`judge_echo_windows`, assert) + summarize.py(assert. CSV의 `phase == ramp` 행에서 baseline을 자동으로 구하고 `--echo-baseline-ms`를 주면 그 값이 우선한다) |
| TTL reap | `resume_ttl_secs + REAPER_TICK`(30s)이 지난 뒤에도 `abandoned_live != 0`이면 위반. 그 전에는 "아직 판정 대상 아님"으로 기록만 한다 — `DRAIN_WAIT`(≈`REAPER_TICK`+`CLOSED_RETENTION`, `qsh_core::broker`의 두 pub const 합)와는 다른, TTL 정책 자체의 만료 시각 기준이다 | soak.rs (`ttl_reap_deadline`, assert) + summarize.py (`--resume-ttl-secs`로 같은 식을 계산; 안 주면 예전처럼 무조건 `abandoned_live == 0` 체크로 폴백) |
| 세션 정지(SESSION_STALLED) | 한 세션의 write→echo 한 라운드가 `SESSION_ROUND_DEADLINE`(5s)을 넘기면 그 세션을 끊고 카운트한다. 카운트가 1 이상이면 위반 | soak.rs (assert)만. CSV에 세션별 정지 이력이 없어 summarize.py는 판단하지 않는다 |

`docs/PRD.md:286`("Idle listener 메모리 30 MB 이하 **목표**")와
`docs/ROADMAP.md:112`("Idle listener RSS ≤ 30 MB", DoD 2 본문)가 이 30 MiB의
상류다. 세션당 8 MiB는 `docs/PRD.md:287`의 세션당 replay buffer 설정값에서
빌린 것이지 실측된 RSS 증분이 아니다 — `m8-adversarial-load.md` §3와 같은
출처, 같은 유보.

self fd 축은 boot baseline과 drain idle_end를 직접 비교하지 않는다 — ramp의
세션 open/attach 자체가 남기는 일회성 fd 비용(런타임 warm-up)까지 같이
잡혀 (iii)이 실제로 재는 "사이클링 도중의 증가"와 다른 것을 재기 때문이다.
그 boot→idle_end 델타는 soak.rs stderr와 summarize.py 출력 양쪽에
정보성으로만 찍힌다 — 절대 위반으로 세지 않는다.

**dial 재시도.** ramp에서 세션을 열 때와 사이클이 세션을 교체할 때, 재시도
가능한(`retryable: true`) `ConnectionFailed`/`Timeout` `OpError`는 최초
시도를 포함해 1초 간격으로 최대 3회까지 시도한다(재시도 자체는 최대
2회다) — fuzz로 포화된 호스트에서 dial 왕복이 qsh-core의 기존 10초
타임아웃을 이따금 못 맞추는 것을 흡수하기 위해서다(qsh-core의 10초
타임아웃 자체는 건드리지 않는다). 재시도 횟수는 verdict에 정보성으로
찍힐 뿐 그 자체로는 위반이 아니다 — 3회 시도를 다 쓰고도 실패해야
비로소 그 세션의 open/cycle이 실패로 처리된다.

세션 정지(SESSION_STALLED) 축은 한 세션의 write→echo 왕복 한 라운드가
`SESSION_ROUND_DEADLINE`(5s)을 넘기면 그 세션은 거기서 끊기고
`dead_sessions` 카운터가 올라간다. 이 카운터가 1 이상이면 verdict는
무조건 FAIL이다(soak.rs만 판단한다. CSV에는 세션별 정지 이력이 없어
summarize.py는 이 축을 보지 않는다).

## 4. 실행 절차

호스트는 Dave-Windows-WSL(`dave-windows-wsl.tail91e9e.ts.net`), 시점은 그
호스트의 fuzz 라운드가 끝난 뒤(§2.5)다.

```bash
# 로컬(Mac)에서: 작업 트리를 WSL로 동기화 (target/.git 제외, incremental 캐시 재사용)
#
# macOS 체크아웃에서는 target이 target.noindex(Spotlight 인덱싱 회피용
# macOS 관행 — 흔히 185 GB급 빌드 캐시)로의 심볼릭 링크다. --exclude target은
# 그 링크 자체만 걸러내고 target.noindex라는 실제 디렉터리는 그대로 걸어
# 들어가 rsync가 사실상 끝나지 않으니, --exclude target.noindex를 반드시
# 같이 준다(PROGRESS-5.md S5에서 17분+ 걸려도 안 끝나는 것으로 실측됨).
rsync -a --delete --exclude target --exclude target.noindex --exclude .git \
  ./ dave-windows-wsl.tail91e9e.ts.net:~/Projects/github.com/qsh-4c/

# WSL에서: 빌드는 nice, cargo는 한 번에 하나만
ssh dave-windows-wsl.tail91e9e.ts.net
cd ~/Projects/github.com/qsh-4c
nice -n 10 cargo build --release -p qsh-cli

export QSH_LOAD_BIN=$(pwd)/target/release/qsh
scripts/soak/run.sh --duration 86400 --sessions 100 --out /tmp/soak-$(date -u +%Y%m%dT%H%M%SZ)
```

`run.sh`가 하는 일(`scripts/soak/run.sh` 참고):

1. `env.txt`에 `uname -a`, `nproc`, `uptime`, `ulimit -n`, `git rev-parse
   HEAD`, working tree clean/dirty, 바이너리 경로와 sha256을 적는다.
2. `QSH_SOAK_DURATION_SECS=86400 QSH_SOAK_SESSIONS=100`(그 외
   `QSH_SOAK_*`는 BRIEF-5.md §4.2 기본값 — 필요하면 호출 전에 개별
   env로 덮어쓴다)과 `QSH_LOAD_STRICT=1`로 `cargo nextest run --profile
   soak -p qsh-cli --test soak`을 돌리고 `run.log`에 tee한다. 이 전체
   실행을 `timeout $((QSH_SOAK_DURATION_SECS + 1800))`으로 감싼다.
3. 테스트가 쓴 `samples.csv`를 `scripts/soak/summarize.py`에 넘겨
   §3 표를 계산·출력하고, 0h/1h/6h/12h/24h 스냅숏 행을 함께 찍는다
   (`summary.txt`).
4. 테스트 exit code와 summarize.py exit code 중 하나라도 0이 아니면
   `run.sh`도 exit 1로 끝난다.

`[profile.soak]`(`.config/nextest.toml`)은 `slow-timeout = { period =
"3600s" }`이고 `terminate-after`가 없다 — 실측 확인 결과(PROGRESS-5.md S0
Q9) 이 조합은 SLOW 경고만 반복해서 찍을 뿐 24h 테스트를 중간에 kill하지
않는다. 이 프로파일 자체는 강제 종료를 안 하므로, 진짜 멈춘 런을 잡는
바깥 상한은 `run.sh`가 두는 `timeout $((QSH_SOAK_DURATION_SECS +
1800))`이다. 의도한 duration에 boot·ramp·drain과 summarize.py 실행
여유분 30분(1800s)을 더한 값이고, 이 시간을 넘기면 `cargo nextest run`
전체가 강제 종료된다.

## 5. 환경 기록 (실행 시작 시 채운다 — 대부분 `env.txt`가 자동으로 채운다)

| 항목 | 값 |
|---|---|
| 날짜 (UTC) | |
| 조작자 | main (Dave-Windows-WSL 단독 점유 실측, BRIEF-5.md §1.1 5e) |
| 호스트 / OS / 커널 | |
| `ulimit -n` | |
| `nproc` | |
| qsh 커밋 SHA | |
| working tree 상태 (clean/dirty) | |
| 바이너리 경로 / sha256 | |
| fuzz 라운드 종료 시각 (이 런 시작 전) | |
| `QSH_SOAK_*` 오버라이드 (기본값과 다르면) | |

## 6. 스냅숏 기록 (0h/1h/6h/12h/24h — `summary.txt`에서 그대로 옮긴다)

| hour | t_secs | phase | listener_rss_kib | listener_fds | self_rss_kib | self_fds | live_sessions | cycles | echo_p95_ms | abandoned_live |
|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | | | | | | | | | | |
| 1 | | | | | | | | | | |
| 6 | | | | | | | | | | |
| 12 | | | | | | | | | | |
| 24 | | | | | | | | | | |

## 7. §3 표 회차 기록

| 회차 | idle RSS baseline/idle_end (KiB) | 세션당 buffer (KiB) | RSS 추세 (MiB/h) | listener fd baseline/idle_end | self fd 1/4 구간 델타 | echo p95 최댓값 (ms) | TTL reap (abandoned_live) | 판정 | 비고 |
|---:|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | |

`FAIL`이면 `summarize.py`가 찍는 위반 문구를 "비고"에 그대로 옮긴다 —
특히 self fd 위반이 `FD_GROWTH_CLIENT` 태그를 달고 있으면 M7 carryover
(iii)가 24h 규모에서도 재현됐다는 뜻이므로 그 수치(델타, 첫/마지막 1/4
구간 최댓값)를 반드시 옮긴다. `run.log`의 `dial_retries=N` 정보성 줄도
"비고"에 옮긴다 — 0이 아니면 그 규모의 dial 재시도가 있었다는 뜻이지만,
그 자체는 위반이 아니다(3회 시도를 다 쓰고 실패한 경우만 그 세션의
open/cycle 자체가 실패로 집계된다). `run.log`의 `dead_sessions=N`도
"비고"에 옮긴다. 이쪽은 정보성이 아니다. 1 이상이면 SESSION_STALLED
위반이 verdict FAIL의 근거 중 하나라는 뜻이다.

GHA 첫 실행(run 34203445617, b9e67b1)에서는 steady 창 2개(129.5 ms,
114.6 ms, 59개 중)가 사이클의 세션 교체(close + dial/open/attach)
직후에 튀었다. 옛 규칙(창별 p95 최댓값 `<= bound`)은 이 스파이크 하나로
그 회차를 위반 처리했지만, 새 비율 규칙(2/59 = 3.4%, 10% 미만)으로는
위반이 아니다(ARBITRATION-5). 이 상관 관계는 5f 후보로 "비고"에 남겨
둔다. listener가 PTY spawn(openpty/fork/exec) 동안 런타임을 막는지는
24h 데이터가 쌓인 뒤에 본다.

## 8. 요약

회차 실행 뒤 다음을 적는다.

- §3 축별 pass/fail과, fail이면 관측값이 임계를 얼마나 넘겼는지.
- idle RSS 30 MiB에 대해 실측이 여유가 큰지 근접한지 — 근접하거나 넘으면
  Step 5 이후 재조정 대상이다(짧은 모드 CI 회귀 감시자의 임계 자체는
  그대로 두고, 이 캠페인 기록만으로 판단한다).
- self fd가 늘었다면((iii) 재현) 수치와, M7 carryover 수정((iv) 외 나머지)
  이 그 수치를 얼마나 줄였는지(재실행 회차가 있다면).
- TTL reap이 abandon 시점부터 정확히 몇 초 뒤에 `abandoned_live`를 0으로
  만들었는지(§6 스냅숏 행에서 `resume_ttl_secs`와 대조).
- 24h 내내 나온 새 실패 모드(있다면) — 특히 `run.log`의 SLOW 경고 빈도가
  비정상적으로 늘었는지(호스트 경합 신호).

## 9. 재사용

`m2-mobility.md`/`m8-adversarial-load.md`처럼 이 문서는 다음 라운드에서
§6/§7의 표를 늘리고 §8을 다시 계산해 재사용한다. `QSH_SOAK_*` 파라미터가
바뀌면(예: 세션 수를 200으로) §5 환경 기록에 그 오버라이드를 남기고 새
행으로 구분한다.
