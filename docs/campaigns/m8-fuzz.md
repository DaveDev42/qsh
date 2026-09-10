# M8 fuzz campaign — 72h/target 무crash (DoD 1)

## 1. 목적과 지위

`.github/workflows/fuzz-smoke.yml`은 push/PR마다 전 타깃을 결정적
`-runs=<N>`으로만 돌리는 build-and-crash-check다 — 72시간 누적은 CI가 아니라
사람이 전용 호스트에서 background로 도는 별도 실행이다(`fuzz/README.md`
"The 72-hour accumulation"). 이 문서는 그 실행의 기록 자리로,
`m8-adversarial-load.md`·`m8-soak.md`가 잡은 캠페인 문서 골격(전제 조건 →
사전 고정 기준 → 실행 절차 → 회차 기록 → 요약)을 그대로 따른다.

M2/adversarial-load/soak과 같은 지위 — 이 문서는 **합격/불합격 게이트가
아니다**. `docs/ROADMAP.md`의 DoD 1 자체 판정은 본문 §5의 기록이 exit
코드와 로그로 닫으며, `fuzz-smoke.yml`은 그 뒤로도 계속 도는 회귀 감시자다.

## 2. DoD 1의 "parser 타깃" 정의 (고정)

`docs/ROADMAP.md` DoD 1: "parser 타깃당 누적 ≥72 fuzz-hours 무crash." 이
문구의 "parser 타깃"을 여기서 고정한다 — M8 Step 1이 등록한 파서
`[[bin]]` 16개 전부다(이후 Step 7b가 더한 stateful `broker_ops`는 §8,
DoD 1 밖):

- 바이트 디코더 8: `decode_control`·`decode_hello`·`decode_exec_frame`·
  `decode_session_frame`·`decode_stream_header`·`decode_connect_result`·
  `decode_local_hello`·`decode_local_admin_request`
- 상태기계 1: `frame_decoder`
- 술어 2: `valid_host_name`·`valid_forward_id`
- 변환기 1: `sanitize_peer_text`
- 문자열 파서 3: `parse_invite_code`·`parse_forward_spec`·
  `fingerprint_principal`
- JSON 1: `json_request_types`

`sanitize_peer_text`·`valid_host_name`·`valid_forward_id`는 엄밀히는
파서가 아니라 판별식(술어 둘)과 변환기(하나)이지만, DoD 1 카운트에
**포함한다** — Step 1이 세운 72h 실행 자체가 처음부터 이 셋을 나머지
13개와 같은 배치 규율로 돌렸고(§4 배치 2가 이 셋을 포함), "parser 타깃"과
"72h 시계를 도는 타깃"을 별도 부분집합으로 나눌 근거가 운영 기록 어디에도
없다. 곧 16 = DoD 1이 세는 타깃 수다. 아래 §3 표의 "분류" 열이 각 타깃의
실제 성격(디코더/상태기계/술어/변환기/문자열 파서/JSON)을, "DoD 1 포함"
열이 이 카운트 참여 여부(전부 예)를 각각 밝힌다.

## 3. 타깃 표

`fuzz/Cargo.toml`의 파서 `[[bin]]` 16개, 각 타깃 파일 첫 doc 주석에서 covers
열을 옮겼다.

| 타깃 | 분류 | 대상 코드 | covers | DoD 1 포함 |
|---|---|---|---|---|
| `frame_decoder` | 상태기계 | `crates/qsh-proto/src/frame.rs` | `FrameDecoder::push`/`next_frame`/`take_remaining`, 임의 순서로 트리클되는 바이트 스트림 시뮬레이션 | 예 |
| `decode_control` | 바이트 디코더 | `crates/qsh-proto/src/wire.rs` | `decode_msg::<ControlMessage>` — control 스트림 oneof 전체 | 예 |
| `decode_hello` | 바이트 디코더 | `wire.rs` | `decode_msg::<Hello>` 단독 | 예 |
| `decode_exec_frame` | 바이트 디코더 | `wire.rs` | `decode_msg::<ExecFrame>` — EXEC_DATA 스트림 oneof | 예 |
| `decode_session_frame` | 바이트 디코더 | `wire.rs` | `decode_msg::<SessionFrame>` + `.validate()` | 예 |
| `decode_stream_header` | 바이트 디코더 | `wire.rs` | `decode_msg::<StreamHeader>` + `.stream_kind()` | 예 |
| `decode_connect_result` | 바이트 디코더 | `wire.rs` | `decode_msg::<ConnectResult>` + `sanitize_peer_text` 체이닝 | 예 |
| `decode_local_hello` | 바이트 디코더 | `crates/qsh-proto/src/local.rs` | `decode_local::<LocalHello>` | 예 |
| `decode_local_admin_request` | 바이트 디코더 | `local.rs` | `decode_local::<LocalAdminRequest>` | 예 |
| `sanitize_peer_text` | 변환기 | `wire.rs` | ANSI/OSC 스트리퍼, 제어 바이트 미치환·문자 유실 없음 단언 | 예 |
| `valid_host_name` | 술어 | `wire.rs` | reverse 타깃 이름 형태 검사 | 예 |
| `valid_forward_id` | 술어 | `wire.rs` | opaque forward 토큰 형태 검사 | 예 |
| `parse_invite_code` | 문자열 파서 | `crates/qsh-proto/src/pairing.rs` | Crockford Base32 초대 코드 디코드 | 예 |
| `parse_forward_spec` | 문자열 파서 | `wire.rs` | `-L`/`-R` forward-spec 문법 | 예 |
| `fingerprint_principal` | 문자열 파서 | `crates/qsh-transport/src/identity.rs` | `Fingerprint::from_str`·`Principal::from_str` | 예 |
| `json_request_types` | JSON | `crates/qsh-proto/src/types.rs` | `qsh_proto::types::*Req` 12종(에이전트가 `--json`으로 주는 요청 타입) `serde_json::from_slice` | 예 |

curated seed 110개(`fuzz/corpus/<target>/`)는 이 16 타깃 각각에 대응한다
(`fuzz/README.md` "Corpus" 절 — grown corpus는 체크인되지 않는다).

## 4. 실행 절차

호스트는 Dave-Windows-WSL(`dave-windows-wsl.tail91e9e.ts.net`, 8 vCPU /
31 GB, `cargo-fuzz` 0.13.2). 8코어로 16 타깃 각각 72h를 채우려면 배치를
둘로 나눠야 하므로(코어당 타깃 하나씩 동시 8개, 2배치 = 최소 144h
벽시계), 배치마다 run-id를 `m8-fuzz-<YYYYMMDD>-<HHMM>`(호스트 기동 시각
기준)로 붙인다.

```bash
cd fuzz
mkdir -p ~/fuzz/grown ~/fuzz/logs/<run-id>
for t in <이 배치의 타깃 이름들>; do
  cargo fuzz run "$t" ~/fuzz/grown/"$t" corpus/"$t" \
    -- -max_total_time=259200 -rss_limit_mb=1536 \
    > ~/fuzz/logs/<run-id>/"$t".log 2>&1 &
done
wait
```

`-max_total_time=259200`(=72h, 초 단위), `-rss_limit_mb=1536`. 로그는
`~/fuzz/logs/<run-id>/<target>.log`. DoD 1 판정은 그 배치의 `exits.txt`
16행(또는 배치 분할이면 그 배치 몫)이 전부 `exit=0`이고 어느 로그에도
`SUMMARY:`/`deadly signal`/`Test unit written`이 없을 때다. 체크인
`corpus/<target>/`은 읽기 전용 두 번째 인자로만 주고, grown corpus(첫
인자)가 실행 중 발견한 커버리지 확장 입력을 받는다(`fuzz/README.md`
"Corpus" 절과 동일 규율).

## 5. 기록

### 배치 1 — decode_* 8종

커밋 `d87e76b`, 호스트 Dave-Windows-WSL, run-id `m8-fuzz-20260902-1600`,
대상 `decode_control`·`decode_hello`·`decode_exec_frame`·
`decode_session_frame`·`decode_stream_header`·`decode_connect_result`·
`decode_local_hello`·`decode_local_admin_request`, 시작
2026-09-02T16:01:37+09:00. 기동 직후 실측: `decode_control` 7.1M execs /
170k exec/s / cov 1873 / RSS 541 MB, load 6.2, 가용 메모리 16 GB.

**09-05 새벽 호스트(WSL VM) 재시작으로 중단**(원인 미확인, Windows 업데이트
추정). `exits.txt`에 exit 행이 없고 launcher도 함께 죽었다. 로그 마지막
수정 시각으로 센 타깃당 실효 시간은 59.1~65.6h, **부족분 6.4~12.9h/타깃**.
실행 수는 2.0B(`decode_control`, 큰 입력이라 8.6k exec/s)~44.8B. crash·
artifact 0건, OOM 없음. grown corpus는 `~/fuzz/grown/<t>`에 1.3~13 MB로
남았다.

### 배치 2 — 나머지 8종

커밋 `ab8a82f`, run-id `m8-fuzz-20260907-1450`, 대상 `fingerprint_principal`·
`frame_decoder`·`json_request_types`·`parse_forward_spec`·
`parse_invite_code`·`sanitize_peer_text`·`valid_forward_id`·
`valid_host_name`, 시작 2026-09-07T14:47:53+09:00, 종료
2026-09-10T14:47:55+09:00. `run72.sh`가 둘째 인자로 타깃 파일을 받게 고쳐
부분집합을 돌린다.

`exits.txt` 8행 전부 `exit=0 secs=259202`, 마지막 줄
`DONE 2026-09-10T14:47:55+09:00`. 엄격 grep(`Test unit written`/
`deadly signal`/`SUMMARY: libFuzzer`/`out-of-memory`)은 8 로그 전부
0건이고 크래시 artifact 파일도 0개다. `json_request_types` 로그에
`timeout` 문자열이 잡히는 건 libFuzzer timeout이 아니라 요청 타입의
사전 필드 이름 `timeout_ms` 때문이다.

| 타깃 | runs | exec/s 평균 | cov | peak RSS |
|---|---|---|---|---|
| fingerprint_principal | 66,924,261,203 | 258,194 | 408 | 530 MB |
| frame_decoder | 31,592,470,495 | 121,884 | 159 | 517 MB |
| json_request_types | 32,600,404,805 | 125,772 | 3151 | 782 MB |
| parse_forward_spec | 32,172,011,895 | 124,119 | 294 | 653 MB |
| parse_invite_code | 87,849,677,445 | 338,924 | 85 | 526 MB |
| sanitize_peer_text | 42,459,844,850 | 163,810 | 112 | 548 MB |
| valid_forward_id | 139,115,028,629 | 536,707 | 38 | 583 MB |
| valid_host_name | 132,605,606,771 | 511,593 | 39 | 578 MB |

범위: 31.6B(`frame_decoder`)~139.1B(`valid_forward_id`) runs, exec/s
121.9k~536.7k, peak RSS 517~782 MB — `-rss_limit_mb=1536` 아래다.
grown corpus 파일 수(`~/fuzz/grown/<t>`): fingerprint_principal 228,
frame_decoder 144, json_request_types 4885, parse_forward_spec 256,
parse_invite_code 141, sanitize_peer_text 125, valid_forward_id 35,
valid_host_name 47.

**배치 2 판정: 8 타깃 72h 누적 충족, crash 0.**

### 배치 1 보충 — decode_* 8종 이어 돌리기

커밋 `ab8a82f`(배치 2와 같은 빌드, `cargo fuzz build` 0.98초로
재컴파일 없음), run-id `m8-fuzz-20260910-1505`. 런처는
`~/fuzz/run-cont.sh`로, `run72.sh`와 같은 규율(grown corpus를 첫
인자로, 체크인 seed는 읽기 전용 둘째 인자, `-rss_limit_mb=1536
-print_final_stats=1`, 타깃별 로그와 exit 행)을 따르되 두 가지가
다르다 — `git pull`이 없고, `-max_total_time`을 셋째 인자로 받는다.
`nohup setsid`로 분리 기동했다.

대상은 decode_* 8종(`decode_control`·`decode_hello`·
`decode_exec_frame`·`decode_session_frame`·`decode_stream_header`·
`decode_connect_result`·`decode_local_hello`·
`decode_local_admin_request`), `-max_total_time=46800`(13h). 위
배치 1 기록의 부족분(로그 mtime 기준 6.4~12.9h/타깃, 정확히는
6.35~12.89h)을 한 값으로 덮는 균일 13h다. 시작
2026-09-10T15:05:21+09:00, 종료 예정 2026-09-11T04:05+09:00.

기동 50초 실측: 8 프로세스 각 CPU 95%, RSS 441~493 MB, exec/s
73k(`decode_control`)~262k. `build.txt`에 `Permission denied` 두
줄이 있는데 cargo 전역 registry 캐시 auto-clean이 `rusb-0.9.4`
예제 파일 삭제에 실패한 경고이고 fuzz 빌드·타깃과는 무관하다.

결과는 확인 대기.

## 6. 남은 것

- 보충 회차(`m8-fuzz-20260910-1505`) 종료 확인 — `exits.txt` 8행
  `exit=0`, 로그 엄격 grep 0건, 누적 = 배치 1 실효 시간 + 13h ≥ 72h.
- 위가 닫히면 DoD 1 체크(`docs/ROADMAP.md`) — 16 타깃 전부 72h 누적,
  crash 0건.
- stateful broker fuzzer(`fuzz_session_machine`/`broker_ops`)는 이 16
  타깃 집합 밖이다 — Step 7b가 착지해 §8에 기록하며, DoD 1의 "parser
  타깃당" 카운트(분모 16) 밖이라 이 캠페인의 완료 조건과 무관하다.

## 7. OSS-Fuzz 제출과의 관계

이 문서가 기록하는 로컬 72h 실행과 별개로, 같은 타깃 전량(현재 17종 —
파서 16 + `broker_ops`)을 continuous fuzzing 서비스로 넘기는 준비물이
`fuzz/oss-fuzz/`에 있다(`project.yaml`·
`Dockerfile`·`build.sh`, 로컬 검증은 `scripts/fuzz/oss-fuzz-local.sh`).
제출(google/oss-fuzz로 PR)은 사람이 하는 별도 액션이고 절차는
`fuzz/oss-fuzz/README.md`에 있다 — 이 문서의 배치 기록과 그쪽 제출 상태는
독립적으로 갱신된다.

## 8. Stateful 타깃 `broker_ops` (DoD 1 밖)

`broker_ops`(M8 Step 7b, `fuzz/fuzz_targets/broker_ops.rs`)는 §2가 고정한
16 타깃 집합에 들지 않는다 — DoD 1의 "parser 타깃당" 분모는 이 문서
전체에서 16으로 그대로 둔다(§6 항목도 같은 뜻). `broker_ops`는
`.github/workflows/fuzz-smoke.yml`의 build-and-crash-check 스모크에는
`cargo fuzz list`가 동적으로 잡아내 자동으로 들어가지만, 이 문서가 기록하는
72h 누적 회차는 별도다 — 돌리게 되면 아래 표에 배치 3으로 기록한다(지금은
헤더만, 아직 실행 회차 없음):

| run-id | 시작 | 종료 | grown corpus | crash | 판정 |
|---|---|---|---|---|---|
| — | — | — | — | — | 미실행 |

## 9. 재사용

`m2-mobility.md`/`m8-adversarial-load.md`/`m8-soak.md`처럼 다음 배치가
생기면 §5에 새 배치 절을 더하고 §6을 다시 계산한다. 타깃 집합이 바뀌면
(`fuzz/Cargo.toml`에 `[[bin]]` 추가/제거) §2·§3을 갱신한다 — canonical
타깃 이름 목록은 이 문서가 아니라 `fuzz/Cargo.toml`이고, 이 문서는 그것을
따라간다.
