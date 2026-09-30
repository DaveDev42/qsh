# P1 supervised tunnel 절전·망 전환 캠페인

상태: 기준 확정, 회차 미실행. 넷째 회차는 reverse route supervisor가 착지한 트리에서만 돈다(§3).

## 1. 목적과 지위

ADR-0023 결과 절의 캠페인 항목이 이 문서의 근거다. 이슈 #6이 보고한 토폴로지, 곧 macOS 노트북이 전체 터널 VPN 뒤에서 뚜껑을 닫았다 여는 상황에서 `qsh tunnel open --supervise`가 약속한 동작을 실기기로 잰다. CI의 주입 테스트(`supervised_forward_carrier_is_declared_lost_within_two_seconds_of_an_injected_wake`, `supervised_dynamic_listener_stays_bound_through_a_50_second_blackhole_and_connects_after_it`)는 시계와 망을 흉내 낸다. 실제 절전에서 VPN이 다시 올라오는 지연과 OS가 소켓을 다루는 방식은 이 캠페인만 준다.

지위는 `docs/campaigns/m9-stopwatch.md`와 다르다. 그 캠페인은 마일스톤 DoD였지만 이 캠페인은 아니다. `docs/ROADMAP.md` §5.1 원칙 6에 따라 M12의 DoD는 이 문서가 사전 고정돼 커밋되는 데까지이고, 회차는 §5.5의 사람 몫이다. 판정 기준(§6)은 회차를 돌리기 전에 고정하며 사후에 조정하지 않는다. 기준을 못 맞춘 회차는 §8의 처분을 따른다.

## 2. 토폴로지와 전제 조건

| 역할 | 장비 | 실행하는 것 |
|---|---|---|
| 노트북 | macOS 노트북 한 대 | 전체 터널 VPN 접속. 회차 1~3은 `qsh tunnel open`을 돌린다. 회차 4는 `qsh serve --to hub`를 돌린다. |
| hub | VPN 너머의 상시 장비 | `qsh serve`와 `qsh listen`. 회차 4는 여기서 `qsh tunnel open`을 돌린다. |

전제는 이렇다.

- 노트북에서 hub는 `trust.toml` 항목(이하 `hub`)으로 핀 고정돼 있고 hub의 `acl.toml`이 노트북에 `forward.local`을 허락한다. `-D`도 이 action으로 인가된다(`docs/CLI.md` §2.5). 회차 4는 노트북이 hub에 `serve --to`로 등록할 수 있어야 하고, 노트북 쪽 `acl.toml`이 hub의 `--local`을 허락해야 한다.
- 노트북과 hub 모두 이 캠페인 전용 프로필을 쓰고 `key_store = "file"`로 둔다. Keychain 재프롬프트가 측정을 오염시키기 때문이다(`docs/campaigns/m2-mobility.md` §2 3번과 같은 이유).
- 두 장비의 시계는 NTP로 맞춘다. 한 회차의 시각 기록은 가능하면 한 장비의 시계로 모은다(§5).
- `qsh`는 측정 대상 태그의 바이너리 하나만 `$PATH`에서 해석된다.
- 회차마다 `qsh tunnel open`은 새 프로세스로 시작하고 stderr를 회차별 파일로 뺀다. 기본 verbosity를 그대로 둔다. `--quiet`는 `qsh::tunnel::supervise` 줄을 끄므로 쓰지 않는다(`docs/CLI.md` §6.14).
- 노트북의 전원 설정에서 "전원 어댑터 연결 시 자동 절전 금지" 같은 예외가 켜져 있으면 끈다. `pmset -g`로 `sleep`과 `womp`를 회차 기록에 적는다.

## 3. 회차 넷

회차마다 같은 동작을 5번 반복한다. 반복 횟수 5는 §6의 중앙값과 최댓값이 의미를 갖는 최소값으로 이 문서가 고정한 값이다.

| 회차 | 사건 | 터널 | 재현 |
|---|---|---|---|
| 1 | 뚜껑 10분 닫기 | 노트북에서 `--dynamic` | §4의 절전 재현에 600초 |
| 2 | 뚜껑 20초 닫기 | 노트북에서 `--dynamic` | §4의 절전 재현에 20초 |
| 3 | 깨어 있는 동안 VPN underlay 전환 | 노트북에서 `--dynamic` | Wi-Fi에서 테더링으로(또는 반대로) 전환. 절전 없음 |
| 4 | 노트북 `qsh serve --to`의 깨어남 뒤 재등록과 hub 쪽 supervised reverse route `--local` | hub에서 `--local` | §4의 절전 재현에 600초. 측정은 hub 기준 |

회차 1~3의 터널은 노트북에서 이렇게 연다.

```bash
qsh tunnel open hub --dynamic 1080 --supervise 300000 2> supervise.log
```

`--accept-hold`는 주지 않는다. 주면 끊긴 동안의 accept가 거절 대신 붙들려 §6 판정 1의 탐침이 의미를 잃는다. `--accept-hold`의 동작은 CI(`accept_hold_dispatches_a_held_connect_once_the_carrier_is_confirmed`와 그 곁의 테스트)가 맡는다.

회차 4는 노트북에서 `qsh serve --to hub`를 돌리고, hub에서 `qsh tunnel open <노트북 별칭> --local 127.0.0.1:18080:127.0.0.1:<노트북 쪽 echo 포트> --supervise 300000 2> supervise.log`를 돌린다. 노트북 쪽에는 `nc -lk`류의 echo 서버를 미리 띄운다.

**넷째 회차는 reverse route supervisor가 착지한 트리에서만 돈다.** 첫 단위만 착지한 트리에서는 reverse route에 `--supervise`를 주면 연결 전에 `UNSUPPORTED`로 끝난다(ADR-0023 결정 24). 그 트리에서 넷째 회차를 돌려 나온 기록은 무효다. 회차 1~3은 첫 단위가 담긴 태그로 돌 수 있다. 회차 4의 기록 칸에는 측정한 태그와 커밋을 적는다.

## 4. 절전 재현 절차

사람이 뚜껑을 여닫아도 되지만, 시간을 고정하려면 OS의 예약 기능을 쓴다. `<s>`는 잠든 시간(초)이다.

| 장비 | 명령 |
|---|---|
| macOS | `sudo pmset relative wake <s>` 를 먼저 실행하고, 이어서 `pmset sleepnow` |
| Linux | `sudo rtcwake -m mem -s <s>` |

순서를 지킨다. `pmset relative wake`가 깨울 시각을 예약하고 `pmset sleepnow`가 잠재운다. 예약 없이 잠그면 사람이 깨울 때까지 시간이 흘러 회차 1과 2의 길이가 재현되지 않는다. 깨어난 직후 OS는 화면을 켜지 않을 수 있으므로 자동 로그인 없이도 VPN 클라이언트가 스스로 재접속하는 설정인지 회차 전에 한 번 확인한다. 회차 3은 절전 없이 Wi-Fi를 끄고 테더링을 켜는 식으로 underlay를 바꾼다.

## 5. 측정

모든 시각은 epoch 초로 소수 셋째 자리까지 적는다.

### 5.1 망 복귀 시각

망 복귀 시각은 VPN 너머 hub로 200ms마다 보내는 ping의 첫 응답 시각이다. 사건(절전, 전환)이 시작되기 전에 ping을 띄워 두고 사건 뒤 처음 응답이 돌아온 줄의 시각을 읽는다. 짧은 간격을 root에게만 허락하는 시스템이 있어 명령에 `sudo`를 붙였다.

```bash
sudo ping -i 0.2 <hub의 VPN 주소> \
  | python3 -u -c 'import sys,time; [print(f"{time.time():.3f} {l}", end="") for l in sys.stdin]' \
  > ping.log
```

사건 중에는 ping이 응답을 받지 못하므로, 응답 줄이 끊겼다가 다시 나오는 첫 줄이 복귀다. 회차 4는 ping을 hub에서 노트북의 VPN 주소로 보내고, 같은 hub 시계로 아래 탐침을 돌린다.

### 5.2 탐침 둘

listener 포트 탐침은 1초마다 listener 포트에 TCP 연결을 열어 결과를 적는다. connection refused와 그 밖의 결과(성공, RST, 타임아웃)를 구분해야 해서 shell의 `nc -z` 대신 이렇게 한다.

```bash
python3 -u -c '
import socket,time
while True:
    s=socket.socket(); s.settimeout(1)
    try: s.connect(("127.0.0.1",1080)); r="ok"
    except ConnectionRefusedError: r="refused"
    except Exception as e: r=type(e).__name__
    finally: s.close()
    print(f"{time.time():.3f} {r}", flush=True)
    time.sleep(1)
' > probe.log
```

회차 4는 포트를 `18080`으로 바꾼다. 사건 시작 전부터 끝난 뒤 30초까지 돌린다.

CONNECT 탐침은 망 복귀 뒤 새 연결이 성공하는 시각을 잰다. 회차 1~3은 SOCKS CONNECT, 회차 4는 `--local` 포트에 붙어 echo가 돌아오는지를 본다.

```bash
while :; do
  t=$(python3 -c 'import time;print(f"{time.time():.3f}")')
  curl --socks5-hostname 127.0.0.1:1080 -m 1 -sS -o /dev/null http://<hub 쪽에서만 닿는 주소>/ 2>/dev/null
  echo "$t $?"
  sleep 0.2
done > connect.log
```

성공 시각은 사건 뒤 처음 종료 코드 0이 찍힌 줄의 시각이다. 종료 코드 0이 나오려면 대상 주소가 응답해야 하므로 hub 쪽에서 응답하는 임의의 HTTP 포트를 고른다.

## 6. 판정 기준 (실행 전에 고정, 사후 조정 없음)

| # | 판정 | 기준 |
|---|---|---|
| 1 | listener 생존 | listener 포트에 붙는 1초 주기 탐침이 한 번도 connection refused를 받지 않는다 |
| 2 | 복귀 속도 | 망 복귀 뒤 새 SOCKS CONNECT의 성공 시각이 망 복귀 시각으로부터, 회차 안 반복의 중앙값 2초 이하, 최댓값 4초 이하다 |
| 3 | 진단 충분성 | 끊김 시간이 stderr의 `lost`, `wake`, `reestablished` 줄만으로 계산된다 |

판정 2의 4초는 최악의 합이다. 복귀 직전에 시작한 재dial이 패킷을 잃어 `REDIAL_DEADLINE` 2초로 끝나고 다음 시도가 `FAST_CAP` 2초 뒤에 오는 경우다. 이 값을 넘는 반복이 하나라도 있으면 그 회차는 판정 2에서 FAIL이다.

판정 1은 반복 전체를 합쳐 본다. refused가 한 줄이라도 있으면 그 회차는 FAIL이다. 탐침이 RST나 타임아웃을 받는 것은 판정 1 위반이 아니다. 이 판정은 listener가 bind된 채 남아 있는지만 묻는다.

판정 3은 끊김 시간을 이렇게 계산한다. `lost` 줄과 그 뒤의 `reestablished` 줄을 짝지어, `reestablished.outage_ms`를 끊김 시간으로 적는다. 중간에 `wake` 줄이 있으면 그 `slept_ms`도 함께 적는다. `outage_ms`는 절전한 시간을 이미 뺀 값이다(`docs/CLI.md` §6.14). 이 세 종류의 줄 밖에서 값을 가져와야 했던 반복(다른 로그나 패킷 캡처로 끊김을 재구성한 경우)이 하나라도 있으면 판정 3은 FAIL이다. `gave_up`이 나온 반복도 FAIL로 적고 원인을 비고에 쓴다.

회차 PASS는 판정 셋을 모두 만족하는 것이고 캠페인 PASS는 돈 회차가 모두 PASS인 것이다. 회차 4는 §3의 조건을 채운 트리에서 돌았을 때만 센다.

## 7. 기록 템플릿

회차마다 설정을 먼저 적는다.

| 항목 | 값 |
|---|---|
| 회차 | 1 / 2 / 3 / 4 |
| 날짜 | |
| qsh 태그와 커밋 SHA | |
| 노트북 OS와 VPN 제품 | |
| `pmset -g`의 `sleep`, `womp` | |
| underlay (Wi-Fi, 테더링 등) | |
| 실행한 명령 원문 | |

**회차 N 반복 기록표**

| 반복 | 사건 시작 | 망 복귀 시각 | 첫 성공 CONNECT 시각 | 복귀 뒤 소요(ms) | 탐침 refused 횟수 | `lost.at` | `wake.slept_ms` | `reestablished.at` | `reestablished.outage_ms` | 비고 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | | | | | | | | | | |
| 2 | | | | | | | | | | |
| 3 | | | | | | | | | | |
| 4 | | | | | | | | | | |
| 5 | | | | | | | | | | |

| 회차 요약 | 값 |
|---|---|
| 복귀 뒤 소요 중앙값(ms) | |
| 복귀 뒤 소요 최댓값(ms) | |
| refused 합계 | |
| 판정 1 (refused 0회) | PASS / FAIL |
| 판정 2 (중앙값 2초 이하, 최댓값 4초 이하) | PASS / FAIL |
| 판정 3 (세 종류 줄만으로 계산) | PASS / FAIL |
| 회차 PASS / FAIL | |
| `gave_up`이나 예상 밖의 `retry` 원인 | |

## 8. FAIL의 처분

이 캠페인은 마일스톤을 막지 않는다. 실패한 회차는 원인을 기록표 비고에 원문으로 남기고 별도 이슈로 올린다. 판정 기준은 고치지 않는다. 기준이 틀렸다고 판단되면 ADR-0023을 고치는 새 ADR을 제안하고 그 승인 뒤에 이 문서를 고쳐 새 회차를 돈다.
