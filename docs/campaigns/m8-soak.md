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
main이 Dave-Windows-WSL 단독 점유에서 돌린 24h 실측(이 워크플로 밖)이
닫는다. 이 문서는 그 실측의 절차·사전 판정·기록 자리다.

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
   자연 종료된 뒤에 시작한다.
6. **저장소 상태.** `run.sh`가 `env.txt`에 `git rev-parse HEAD`와 working
   tree clean/dirty 여부를 자동 기록한다 — dirty면 회차 기록에 그 사실이
   그대로 남는다(가리지 않는다).
7. **리스너 rate limit 상향은 하네스가 자동으로 한다.** `soak.rs`가 쓰는
   listener `config.toml`은 `handshake_rate_per_source`/
   `validated_rate_per_source`를 `(2×N).max(64)`로 올린다(N=100이면
   200/s). 하네스가 N세션 전부를 같은 소스 IP(127.0.0.1)에서 dial하다
   보니, 제품 기본값(10/s, burst 20/2s)을 그대로 두면 ramp 구간의 burst가
   per-source 핸드셰이크 rate limiter에 걸려 예산 초과분 Initial이
   조용히 `Ignore`되고 클라이언트에는 "no response within 10s"만 보인다.
   제품 기본값 자체는 손대지 않는다 — 단일 소스가 제한당하는 건
   프로덕션에서 의도된 동작이고(`docs/history/m8-plan.md` §3 Step 5), 이 상향은 신뢰된
   테스트 드라이버인 하네스 자신의 리스너 설정에만 적용된다.
8. **loopback UDP가 ephemeral 범위 안에서 막혀 있지 않은지 확인한다.**
   `run.sh`가 시작 직후 `scripts/soak/preflight_udp.py`로
   `/proc/sys/net/ipv4/ip_local_port_range` 전 구간을 고르게 샘플링해
   127.0.0.1 UDP 왕복을 실제로 찔러 본다. 막힌 창을 찾으면 즉시 실패하고
   회차를 열지 않는다 — run #5가 겪은 DIAL_EXHAUSTED(§8 "run #5 결과")가
   호스트 nftables 규칙 때문이었던 것과 같은 사고를 24시간 뒤가 아니라
   시작 전 몇 초 안에 잡기 위해서다. `/proc`가 없는 호스트에서는 확인을
   건너뛰고 진행한다.
9. **막힌 창이 있는 호스트에서는 네트워크 네임스페이스 안에서 돌린다.**
   nftables 테이블은 netns마다 별개라 새로 만든 네임스페이스에는 그 규칙이
   없고, 만드는 데 권한도 필요 없다. 호스트의 방화벽 규칙은 손대지 않는다 —
   그 규칙은 호스트 소유자의 결정이고 다른 용도로 의도된 예약일 수 있다.

   ```sh
   unshare -rn sh -c 'ip link set lo up; exec scripts/soak/run.sh …'
   ```

   `-r`이 user namespace를 함께 만들어 `ip link`를 쓸 수 있게 한다. `net`만
   분리하므로 PID는 호스트에서 그대로 보이고 §6 감시 항목의 `pgrep`·RSS·fd
   수집이 다 살아 있다. 네임스페이스는 프로세스와 함께 사라져 호스트에
   남는 것이 없다. 위 8번 preflight가 이 조건을 기계로 지킨다 — 호스트
   netns에서 그냥 부르면 exit 2로 회차를 열지 않고, 네임스페이스 안에서
   부르면 통과한다. netns는 RSS·버퍼·fd 어느 판정 축에도 영향이 없고
   qsh와 무관한 호스트 artifact 하나를 제거할 뿐이므로, 이 회차 조건을
   여기에 전제로 적고 §5 기록에 남긴다.

## 3. 사전 정의된 합격/불합격 기준 (실행 전에 고정)

이 표는 `crates/qsh-cli/tests/soak.rs`와
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
| listener fd (baseline/idle_end) | boot→idle_end 델타는 정보성 기록만 — 첫 세션 open의 일회성 lazy warm-up(감사·resolver·keystore·io-driver)이라 위반 아님. soak.rs는 `open_fd_targets`로 idle_end fd 인벤토리도 같이 찍어 델타가 그 lazy 세트임을 로그로 보인다. 누수는 아래 steady quarters가 잡는다 | soak.rs (eprintln) + summarize.py (note) |
| listener fd (steady quarters) | steady 마지막 1/4 구간 fd 최댓값 `<= 첫 1/4 최댓값 + 2`. 위반은 `FD_GROWTH_LISTENER`로 표기 | soak.rs (`judge_fd_quarters`, assert) + summarize.py 양쪽 동일 구현(`quarter_split`). steady 표본이 `MIN_QUARTER_SAMPLES`(8) 미만이면 양쪽 다 위반 대신 기록만 남긴다 |
| self(테스트 프로세스) fd | steady 마지막 1/4 fd 최댓값 `<= 첫 1/4 최댓값 + 2`(사이클링 도중의 증가만 잰다). 위반은 `FD_GROWTH_CLIENT`로 표기(M7 carryover (iii) 재현) | soak.rs (`judge_fd_quarters`, assert, strict) + summarize.py. listener fd 축과 같은 `MIN_QUARTER_SAMPLES` 다운그레이드 규칙을 공유한다 |
| echo p95 | steady 창 중 p95가 bound(`max(3 × ramp 직후 baseline p95, 50 ms)`)를 넘는 창의 비율이 `ECHO_SPIKE_FRACTION_MAX`(10%)를 넘으면 위반이고 태그는 `ECHO_DEGRADED`다. bound는 고정 50ms가 아니라 이 런 자신의 ramp 직후 baseline에 대한 적응형 상한이다(공유 러너의 절대치 flake를 피하려는 T2 `adversarial_load.rs` 패턴과 같다). baseline을 못 구하면 50ms 바닥값으로 대체한다. 최댓값, 초과 창 수, steady 첫/마지막 1/4 구간 중앙값은 위반 여부와 무관하게 정보로만 기록한다(24h 저하 규칙을 세울 입력. 비율 규칙 자체는 첫 GHA soak 실행을 판정하면서 정했다) | soak.rs(`judge_echo_windows`, assert) + summarize.py(assert. CSV의 `phase == ramp` 행에서 baseline을 자동으로 구하고 `--echo-baseline-ms`를 주면 그 값이 우선한다) |
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
# 같이 준다(실측: 17분이 넘어도 끝나지 않았다).
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
   `QSH_SOAK_*`는 `scripts/soak/run.sh`가 채우는 기본값 — 필요하면 호출 전에 개별
   env로 덮어쓴다)과 `QSH_LOAD_STRICT=1`로 `cargo nextest run --profile
   soak -p qsh-cli --test soak`을 돌리고 `run.log`에 tee한다. 이 전체
   실행을 `timeout $((QSH_SOAK_DURATION_SECS + 1800))`으로 감싼다.
3. 테스트가 쓴 `samples.csv`를 `scripts/soak/summarize.py`에 넘겨
   §3 표를 계산·출력하고, 0h/1h/6h/12h/24h 스냅숏 행을 함께 찍는다
   (`summary.txt`).
4. 테스트 exit code와 summarize.py exit code 중 하나라도 0이 아니면
   `run.sh`도 exit 1로 끝난다.

`[profile.soak]`(`.config/nextest.toml`)은 `slow-timeout = { period =
"3600s" }`이고 `terminate-after`가 없다 — 실측 확인 결과 이 조합은 SLOW 경고만 반복해서 찍을 뿐 24h 테스트를 중간에 kill하지
않는다. 이 프로파일 자체는 강제 종료를 안 하므로, 진짜 멈춘 런을 잡는
바깥 상한은 `run.sh`가 두는 `timeout $((QSH_SOAK_DURATION_SECS +
1800))`이다. 의도한 duration에 boot·ramp·drain과 summarize.py 실행
여유분 30분(1800s)을 더한 값이고, 이 시간을 넘기면 `cargo nextest run`
전체가 강제 종료된다.

## 5. 환경 기록 (실행 시작 시 채운다 — 대부분 `env.txt`가 자동으로 채운다)

| 항목 | 값 |
|---|---|
| 날짜 (UTC) | 2026-09-16T10:05:00Z |
| 조작자 | main (Dave-Windows-WSL 단독 점유 실측) |
| 호스트 / OS / 커널 | Linux Dave-Windows-WSL 6.18.33.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux |
| `ulimit -n` | 65536 |
| `nproc` | 8 |
| qsh 커밋 SHA | dd66e0fb3ba316f130f93ee7ff847a6635b74140 |
| working tree 상태 (clean/dirty) | clean |
| 바이너리 경로 / sha256 | /home/dave/Projects/github.com/qsh/target/release/qsh / 85f7074630c8681d527381550ec9dd68707a0c884c16219d3d10ec0019cbe65d |
| fuzz 라운드 종료 시각 (이 런 시작 전) | 기록 없음 — `env.txt`에 해당 필드가 없다. `uptime`이 "up 13 min"으로 찍혀 있어, 이 런은 fuzz 라운드 종료 뒤가 아니라 호스트 재부팅 직후(§2.5 전제와 다른 경로)에 시작됐다. |
| `QSH_SOAK_*` 오버라이드 (기본값과 다르면) | DURATION_SECS=86400, SESSIONS=100(§4 절차의 표준 24h/100-session 호출값), SAMPLE_SECS=5, CYCLE_SECS=60, CYCLE_FRACTION=0.1, ABANDON=5, RESUME_TTL_SECS=600. `env.txt` 실측값 그대로다 — 어느 값이 기본값이고 어느 값이 오버라이드인지 가르는 대조표가 저장소에 없어 전부 나열했다. |

## 6. 스냅숏 기록 (0h/1h/6h/12h/24h — `summary.txt`에서 그대로 옮긴다)

| hour | t_secs | phase | listener_rss_kib | listener_fds | self_rss_kib | self_fds | live_sessions | cycles | echo_p95_ms | abandoned_live |
|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 1 | boot | 14236 | 11 | 12488 | 14 | 0 | 0 | None | 0 |
| 1 | 3603 | steady | 124304 | 116 | 561760 | 110 | 95 | 59 | 1.347 | 0 |
| 6 | 21601 | steady | 129228 | 114 | 562804 | 110 | 95 | 359 | 1.165 | 0 |
| 12 | 43203 | steady | 134132 | 120 | 565576 | 111 | 95 | 719 | 1.318 | 0 |
| 24 | 86388 | steady | 128176 | 112 | 567880 | 109 | 95 | 1438 | 1.146 | 0 |

## 7. §3 표 회차 기록

| 회차 | idle RSS baseline/idle_end (KiB) | 세션당 buffer (KiB) | RSS 추세 (MiB/h) | listener fd baseline/idle_end | self fd 1/4 구간 델타 | echo p95 최댓값 (ms) | TTL reap (abandoned_live) | 판정 | 비고 |
|---:|---|---|---|---|---|---|---|---|---|
| 5 | 14236 / 30244 | 1266.3 (peak=140868) | -0.0480 | 11 / 19 | -1 | 15.847 | 0 | FAIL | 트리 dd66e0f, 바이너리 sha256 85f7074630c8681d527381550ec9dd68707a0c884c16219d3d10ec0019cbe65d. 실행 시간 86636.283s(설정 86400s+drain, ≈24h04m). soak.rs 자체 verdict FAIL — DIAL_EXHAUSTED: 8건(사이클 교체 dial이 재시도 3회 모두 소진, slot 81×2·43·54·94·50·15·93). dial_retries=1138(정보성), dead_sessions=0(SESSION_STALLED 없음), listener fd quarters 델타=-1·self fd quarters 델타=-1(둘 다 allowance +2 이내, 위반 아님). summarize.py는 §3 세 축(idle RSS·세션당 buffer·RSS 추세) 기준 pass. run.sh 결합 verdict는 FAIL(test exit=100, summarize exit=0) — DIAL_EXHAUSTED>0은 `soak.rs`가 별도로 거는 축이고 §3 사전 기준 9행에는 없으며 DoD 2 세 축과도 별개다. 그 축의 원인은 이 호스트의 nftables 규칙 `inet dave_mosh`(`udp dport 60000-61000 drop`, loopback 예외 없음)로 규명됐다 — 제품 결함이 아니다. 근거와 재현은 §8 "run #5 결과" 참고. |

`FAIL`이면 `summarize.py`가 찍는 위반 문구를 "비고"에 그대로 옮긴다 —
특히 self fd 위반이 `FD_GROWTH_CLIENT` 태그를 달고 있으면 M7 carryover
(iii)가 24h 규모에서도 재현됐다는 뜻이므로 그 수치(델타, 첫/마지막 1/4
구간 최댓값)를 반드시 옮긴다. `run.log`의 `dial_retries=N` 정보성 줄도
"비고"에 옮긴다 — 0이 아니면 그 규모의 dial 재시도가 있었다는 뜻이지만,
그 자체는 위반이 아니다(3회 시도를 다 쓰고 실패한 경우만 그 세션의
open/cycle 자체가 실패로 집계된다). `run.log`의 `dead_sessions=N`도
"비고"에 옮긴다. 이쪽은 정보성이 아니다. 1 이상이면 SESSION_STALLED
위반이 verdict FAIL의 근거 중 하나라는 뜻이다. `run.log`의
`dial_exhausted=N`도 같이 옮긴다 — 1 이상이면 사이클 교체 dial이 재시도
3회를 다 쓰고 스킵됐다는 뜻으로(DIAL_EXHAUSTED, verdict FAIL 근거), 다만
런 자체는 죽지 않고 drain까지 이어져 CSV가 끝까지 닫혔다는 뜻이기도
하다.

GHA 첫 실행(run 34203445617, b9e67b1)에서는 steady 창 2개(129.5 ms,
114.6 ms, 59개 중)가 사이클의 세션 교체(close + dial/open/attach)
직후에 튀었다. 옛 규칙(창별 p95 최댓값 `<= bound`)은 이 스파이크 하나로
그 회차를 위반 처리했지만, 새 비율 규칙(2/59 = 3.4%, 10% 미만)으로는
위반이 아니다. 이 상관 관계는 5f 후보로 "비고"에 남겨
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

### run #5 결과 (2026-09-16 10:05 UTC 시작, dd66e0f)

§3의 판정 축 중 idle listener RSS(14236/30244 KiB, bound 30720 KiB), 세션당
buffer(1266.3 KiB, bound 8192 KiB), RSS 추세(-0.0480 MiB/h, bound <1.0),
listener/self fd quarters 델타(둘 다 -1, allowance +2), echo p95 스파이크
(0/14198 창, 0.0%, allowance 10%)와 최댓값(15.847ms, bound 50ms), TTL
reap(아래 참고)은 전부 pass다. summarize.py는 이 CSV 기반 축만 보고
verdict를 pass로 찍는다.

soak.rs 자신의 assert 목록에는 CSV에 없는 축이 하나 더 있다. 사이클
교체 dial 8건이 재시도 3회를 전부 소진했고(DIAL_EXHAUSTED — slot 81이
두 번, 43·54·94·50·15·93이 한 번씩), 이 축이 soak.rs 자체 verdict를
FAIL로 만든다. dial_retries=1138은 정보성 집계이고 dead_sessions=0이라
SESSION_STALLED는 걸리지 않았다. run.sh는 nextest exit code와
summarize.py exit code를 OR로 묶으므로(test exit=100, summarize
exit=0), 이 회차의 결합 verdict는 FAIL이다.

idle_end RSS 30244 KiB는 bound 30720 KiB(30 MiB)까지 476 KiB(1.5%)만
남아 근접한 편이다. Step 5 이후 재조정 대상 후보로 남긴다(짧은 모드 CI
회귀 감시자 임계 자체는 이 기록만으로 바꾸지 않는다). self fd quarters
델타는 -1이라, M7 carryover (iii)는 이번 24h 규모에서 재현되지 않았다.

TTL reap 판정선은 resume_ttl_secs(600s)+REAPER_TICK(30s)=630s다.
`samples.csv` 기준으로 5개 abandon 세션은 늦어도 ramp 첫 표본(t=50s)에
이미 abandoned_live=5로 잡혔고, steady 구간 내내 5를 유지하다 t=648s
표본까지도 5, t=661s 표본에서 0으로 떨어져 그 뒤 끝까지(드레인 포함)
0을 유지한다. 판정선 630s 부근에서 반영된 것으로, 위반은 없다.

이전 두 회차(#3, #4)는 각각 t≈14,800s(4.1h), t≈16,085s(4.47h)에
Windows Update 트리거 재부팅으로 죽어 verdict 자체가 없었다. run #5는
이 재시도 계열에서 처음 24h 전체(86636.283s)를 완주한 회차이자,
DIAL_EXHAUSTED가 assert 위반으로 처음 관측된 회차다. `env.txt`는 호스트가
재부팅 13분 뒤(load average 0.96/1.36/0.95, 8 vCPU)에 시작됐다고
기록하는데, fuzz 워커로 포화된 상태가 아니다 — pre-jemalloc 시기의
이전 24h 완주 라운드(DECISION-24h-soak.md, DIAL_EXHAUSTED×6)가 "fuzz
경합, 환경 문제"로 트리아지된 조건과 다른데도 그보다 많은 ×8이 나온
셈이다.

실패 메시지의 출처는 한 곳뿐이다. 1146개 실패 줄 전부가
`DialError::Timeout` 문면(`qsh-core/src/ops/exec.rs:252-255`,
`qsh-transport/src/endpoint.rs:32`의 10s `DEFAULT_DIAL_TIMEOUT`)이고,
`Refused`는 run.log에 0건이다. admission 계층에서 `Refuse`를 내는 축
(`validated_rate_per_source`, `max_concurrent_handshakes`)은 즉시
`CONNECTION_CLOSE`를 보내 client에 구별되는 메시지를 남기므로, 이 축들이
원인이었다면 로그 문면이 달랐어야 한다. 침묵하는 코드 경로는
`handshake_rate_per_source`의 `Decision::Ignore`
(`qsh-core/src/admission.rs:499-519`) 하나인데, 이 회차 설정값은 200/s이고
실제 교체 dial은 ≈0.17/s다.

관측 공백을 같이 기록해 둔다. `ServeGuard::start_with_bin`
(`crates/qsh-cli/tests/common/mod.rs:119`)이 서버 서브프로세스에서
`QSH_LOG`를 `env_remove`하므로, admission 결정별 카운터는 이 회차에
아예 수집되지 않았다. 위 문단의 admission 관련 판단은 설정 headroom
계산에서 나온 것이고 관측된 카운터가 근거가 아니다. 다음 회차는 listener의
admission 결정 로그를 남기도록 해서 이 축을 추론이 아니라 계측으로
가릴 수 있게 한다.

태그 대상 트리 감사: `git diff dd66e0f..525a2a5`는
`.github/workflows/release.yml`·`Cargo.lock`·`README.md`·`docs/ROADMAP.md`
4개 파일만 건드리고, transport·admission·config·quota·server·broker·serve와
`crates/qsh-cli/tests/soak.rs`에는 변경이 0줄이다. 이 회차가 관측한 동작은
현재 트리에 그대로 남아 있다.

DIAL_EXHAUSTED의 근본 원인은 이 호스트의 방화벽 규칙이다. 제품 결함이
아니고 하네스 결함도 아니다.

WSL 호스트에 사용자가 만들어 둔 nftables 테이블 `inet dave_mosh`가 있고,
그 input 체인의 마지막 규칙이 `udp dport 60000-61000 drop`이다. 앞선 두
규칙이 Tailscale 주소(`100.64.0.0/10`, `fd7a:115c:a1e0::/48`)에서 온 것만
accept 하므로 loopback 트래픽에는 예외가 없다. 이 호스트의 ephemeral 범위는
`32768-60999`(`/proc/sys/net/ipv4/ip_local_port_range`)이고, 그중 약 1000개
(≈3.5%)가 막힌 창에 들어간다. `dial_inner`
(`crates/qsh-transport/src/endpoint.rs`)가 dial 마다 새 ephemeral 소켓을
bind 하므로 매 dial이 이 3.5%를 두 번 굴린다 — client 쪽 포트가 걸리면 그
dial의 응답이 사라지고, 리스너가 `--bind 127.0.0.1:0`으로 받은 포트가
걸리면 그 리스너로 가는 모든 dial이 수명 내내 죽는다. 두 배라 관측 실패율이
5.75~7.4%로 나온다.

확증은 셋이고 서로 독립이다. 첫째, `lo` 패킷 캡처에서 실패 flow 899개 중
"리스너가 한 번도 응답하지 않은" 것이 0개다 — 리스너는 매번 응답했고
응답이 소켓에 닿기 전 input hook에서 사라졌다. 그래서 client 쪽 문면
("no response ... within 10s")은 소켓 관점에서 정확했다. 둘째, 포트 구간별
실패율이 92.9% 대 0%로 갈린다. 셋째, 리스너가 우연히 60693에 bind 된 회차에
릴리스 바이너리로 `qsh exec`를 5번 부르면 5번 다 같은 envelope으로
실패한다(soak 하네스 없이, 동시성 1, `CONNECTION_FAILED` /
"no response from 127.0.0.1:60693 within 10s"). 결정적 재현이다.

뒤이어 둘이 더 붙었다. 넷째, 캡처를 바이트 단위로 디코드하니 사라지는
패킷의 종류가 특정된다. 리스너는 실패 dial의 모든 client Initial에 새
stateless Retry를 답한다(ADR-0009 설계 그대로, 캐시된 상태 없음). client는
그 Retry를 한 번도 못 받아 토큰 없는 원본 Initial을 PTO 사다리(0s, ~1s,
~3s, ~7s, ~10s)로만 재전송하고, 성공 flow가 1ms 안에 하는 "토큰 붙이고
`dcid`를 Retry의 `scid`로 교체"를 끝까지 하지 않는다. 실패 flow 어디에도
`Handshake`·`0-RTT`·`VersionNegotiation` 패킷이 없다. 즉 단방향으로,
client의 ephemeral 포트를 목적지로 하는 Retry만 전량 소실된다. 실패 서명
`duration=10.001s c2l=8 l2c=5`의 패킷 수가 그 사다리의 산술이다. 다섯째,
같은 호스트에서 `unshare -rn` + `ip link set lo up`으로 만든 네트워크
네임스페이스 안은 nft 룰셋이 비어 있고 127.0.0.1 UDP 왕복이
45000·60500·60999·61001 네 포트 전부 통과한다. 호스트 netns에서는
60500·60999만 막힌다. 규칙 창과 정확히 일치하는 대조다.

이 판정은 회차 자료로만 내릴 수 있는 것이 아니었다. run #5 이후 같은
호스트에서 돌린 재현 실험 넷(E1 35/480=7.29%, E2b 9/136=6.62%,
E6 18/313=5.75%, E7 5/5=100%)이 근거이고, 회차 원래 값 7.405%를 E1·E2b가
양쪽에서 감싼다. 커널 UDP 오류 카운터(`NoPorts`·`InErrors`·`RcvbufErrors`·
`SndbufErrors`·`InCsumErrors`·`MemErrors`)는 네 실험 모두 델타 정확히 0이라
버퍼·백로그 드롭도 아니다.

같은 규칙이 이 호스트의 일반 테스트도 깬다. `cargo nextest run --workspace`
한 번이 단일 리스너 통합 테스트 넷(`acl_enforcement`·`attach_recovery`·
`exit_code_matrix`·`jsonl_purity`)을 같은 문면으로 떨어뜨렸다. GitHub 호스팅
CI가 같은 트리에서 전 플랫폼 attempt 1 녹색인 이유도 이것이다 — 그 러너에는
이 규칙이 없다.

그래서 이 축은 제품 추적 항목이 아니다. 이전 회차의 "환경(fuzz 경합)" 판정과
결론은 같지만 근거가 다르다 — 경합이 아니라 방화벽이고, 부하와 무관하게
dial 단위로 독립이며, 재부팅 직후 idle 호스트에서도 같은 비율로 난다.

다음 회차의 전제 조건이 둘 늘어난다. 하나는 확인이다 — 회차 시작 전에
loopback UDP가 ephemeral 범위 전체에서 필터링되지 않는지 본다(§2 8번,
`scripts/soak/preflight_udp.py`). 다른 하나는 우회다 — 막힌 창이 남아 있는
호스트에서는 네트워크 네임스페이스 안에서 회차를 돌린다(§2 9번). 규칙
자체를 어떻게 할지는 이 호스트 소유자의 결정이다. 범위를 좁히거나 옮기거나
loopback 예외를 두는 것 중 하나이고, `qsh` 프로세스가 자기 소켓 수준에서
피할 수 있는 것은 아니다(bind 는 OS가 주는 `:0` 포트다). netns 는 그
프로세스 수준의 우회가 아니라 규칙이 존재하지 않는 별개의 네트워크 스택을
쓰는 것이고, 권한 없이 만들 수 있으며 호스트 설정을 바꾸지 않는다.

## 9. 재사용

`m2-mobility.md`/`m8-adversarial-load.md`처럼 이 문서는 다음 라운드에서
§6/§7의 표를 늘리고 §8을 다시 계산해 재사용한다. `QSH_SOAK_*` 파라미터가
바뀌면(예: 세션 수를 200으로) §5 환경 기록에 그 오버라이드를 남기고 새
행으로 구분한다.
