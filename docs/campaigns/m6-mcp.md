# M6 MCP 실접속 캠페인 — Claude Code → `qsh mcp` → 원격 명령 실행

## 1. 목적과 지위

ROADMAP M6 DoD 2("Claude Code 실접속으로 원격 명령 실행")의 실측 기록이다. M2 mobility 캠페인과 달리 이 캠페인은 참고 자료가 아니라 **DoD 그 자체 — 합격/불합격 게이트다**. conformance 하네스(raw JSON-RPC)가 계약 준수를 이미 전수 검증했으므로, 여기서 보는 것은 하나다: SDK 기반 실제 MCP client(Claude Code)가 `qsh mcp`에 붙어 실제 qsh host에서 명령을 실행하고 결과를 받아오는가.

- 대상 커밋: 실행 기록(§6)에 기입. 로컬 빌드 바이너리(`cargo build --release -p qsh-cli`)를 쓴다 — 다운로드 릴리스가 아니므로 quarantine/Gatekeeper 개입 없음.
- 토폴로지: 한 머신, loopback QUIC. client/host는 `QSH_CONFIG_DIR`/`QSH_STATE_DIR`로 격리된 별도 identity. `qsh mcp` 프로세스는 **client** sandbox env로 뜬다(MCP 전용 env var는 없다 — `Ops::from_env()` 그대로).
- 원격성에 대해: loopback도 M2–M5가 검증한 것과 동일한 QUIC wire 경로다. 물리적 원격 host 검증은 M2 캠페인이 이미 수행했고, M6 DoD 2의 신규 검증 대상은 MCP client 경로이지 네트워크 경로가 아니다.

## 2. 전제 조건 (정확히 이대로)

1. `cargo build --release -p qsh-cli` 완료, `QSH=<repo>/target/release/qsh`.
2. 캠페인 루트: `CAMP=$HOME/.qsh-m6-campaign` (실행 후 통째로 삭제).
3. 양쪽 identity 모두 `--key-store file` 강제 — 기본값 `auto`는 macOS Keychain 대화상자를 열 수 있다(M2 캠페인 §2.3과 동일한 이유).
4. host 쪽 `acl.toml`은 **`exec.run` 하나만** 허용한다(최소 권한 — 이 캠페인의 pass 기준이 exec뿐이므로). qsh는 acl.toml을 만들어 주지 않는다(default-deny) — 운영자가 직접 쓰고 `chmod 600`.
5. `qsh serve`는 `--bind 127.0.0.1:0`(ephemeral)로 띄우고 stderr의 `qsh serve: listening on <addr>` 줄에서 실제 포트를 읽는다 — 고정 포트 충돌 방지.
6. Claude Code는 headless(`claude -p`)로, `--mcp-config`에 client sandbox env를 주입한 qsh 서버 항목을 넣고 `--allowedTools`를 `mcp__qsh__exec`로 한정한다.

## 3. 사전 정의된 합격/불합격 기준 (실행 전에 고정)

| # | 기준 | 판정 |
|---|---|---|
| C1 | Claude Code가 `qsh mcp`와 initialize 핸드셰이크를 완료하고 `exec` tool을 인지·호출한다 | tool call이 실제 발생하면 충족(핸드셰이크 실패 시 tool 자체가 노출되지 않는다) |
| C2 | `exec` tool call(host alias + `argv: ["/bin/echo", "<marker>"]`)의 응답에 `isError`가 없거나 false이고 `structuredContent.remote_exit_code == 0` | 응답 JSON으로 판정 |
| C3 | `structuredContent.stdout_b64`를 디코드하면 정확히 `<marker>\n` | marker는 실행 시각 기반 nonce — 캐시·재사용 불가 |
| C4 | host `acl.toml`은 `exec.run`만 허용한 상태로 전 과정 통과 | 파일 내용을 기록에 첨부 |
| C5 | `claude` 종료 후 `qsh mcp` 프로세스가 잔존하지 않는다 | `pgrep -f "qsh mcp"` 0건 |

판정 예산: `claude -p` 호출 전체가 5분 안에 끝나야 한다. 시간 초과, `PERMISSION_DENIED`(acl 누락 증상), `TRUST_REQUIRED`(pin 누락 증상), tool 미노출(핸드셰이크 실패 증상) 중 어느 것이든 **불합격**이며, 원인을 고쳐 재실행하는 경우 회차를 새로 기록한다. 사후 기준 완화는 없다.

## 4. 조작 절차

```bash
# 0. 빌드와 변수
cargo build --release -p qsh-cli
QSH="$PWD/target/release/qsh"
CAMP="$HOME/.qsh-m6-campaign"
MARKER="m6-mcp-$(date +%s)"
mkdir -p "$CAMP"/{client,host}/{config,state}

# 1. identity 2개 생성 (파일 키스토어 강제, fingerprint 기록)
QSH_CONFIG_DIR=$CAMP/client/config QSH_STATE_DIR=$CAMP/client/state \
  "$QSH" init --json --key-store file        # -> CLIENT_FP
QSH_CONFIG_DIR=$CAMP/host/config QSH_STATE_DIR=$CAMP/host/state \
  "$QSH" init --json --key-store file        # -> HOST_FP

# 2. host 쪽 trust pin + acl.toml — 반드시 serve 시작 **전에** (실측 교훈:
#    host는 trust/acl을 시작 시 읽고 hot-reload하지 않는다 — 순서가 뒤면
#    모든 op이 PERMISSION_DENIED)
QSH_CONFIG_DIR=$CAMP/host/config QSH_STATE_DIR=$CAMP/host/state \
  "$QSH" trust add laptop --fingerprint "$CLIENT_FP" --json
cat > "$CAMP/host/config/acl.toml" <<ACL
[[acl]]
principal = "device:laptop"
allow = ["exec.run"]
ACL
chmod 600 "$CAMP/host/config/acl.toml"

# 3. host를 loopback ephemeral 포트에 bind (stderr에서 포트 파싱)
QSH_CONFIG_DIR=$CAMP/host/config QSH_STATE_DIR=$CAMP/host/state \
  "$QSH" serve --bind 127.0.0.1:0 2> "$CAMP/serve.log" &
# serve.log의 "qsh serve: listening on 127.0.0.1:<PORT>" 대기 -> PORT

# 4. client 쪽 pin — 포트를 안 다음에 (실측 교훈: 이미 있는 peer에
#    trust add를 다시 실행하면 created:false로 기존 address가 유지된다 —
#    주소 갱신 용도로 재실행하지 말 것)
QSH_CONFIG_DIR=$CAMP/client/config QSH_STATE_DIR=$CAMP/client/state \
  "$QSH" trust add box --address "127.0.0.1:$PORT" --fingerprint "$HOST_FP" --json

# 5. CLI sanity (MCP 이전에 wire 경로부터 확인 — 실패 시 MCP 쪽 원인과 분리)
QSH_CONFIG_DIR=$CAMP/client/config QSH_STATE_DIR=$CAMP/client/state \
  "$QSH" exec box --json -- /bin/echo "sanity-$MARKER"

# 6. Claude Code MCP 설정
cat > "$CAMP/mcp.json" <<MCP
{"mcpServers": {"qsh": {"command": "$QSH", "args": ["mcp"],
  "env": {"QSH_CONFIG_DIR": "$CAMP/client/config", "QSH_STATE_DIR": "$CAMP/client/state"}}}}
MCP

# 7. 캠페인 본 실행 — Claude Code headless
claude -p "Call the qsh MCP tool 'exec' with arguments {\"host\": \"box\", \"argv\": [\"/bin/echo\", \"$MARKER\"]}. Then report verbatim: remote_exit_code, and the base64-decoded stdout_b64." \
  --mcp-config "$CAMP/mcp.json" --allowedTools "mcp__qsh__exec" \
  --output-format json > "$CAMP/claude-transcript.json" 2> "$CAMP/claude.log"

# 8. 판정 자료 수집 + 정리
pgrep -f "qsh mcp" || echo "no residual qsh mcp"     # C5
kill %1                                               # serve 종료 (SIGTERM drain)
# 기록 후: rm -rf "$CAMP"
```

## 5. 예상 실패 신호 (사전 등재)

- 모든 tool call이 `PERMISSION_DENIED` → 4단계 acl.toml 누락/오기(§2.4). `qsh mcp`는 시작 시 ACL을 진단하지 않는다 — host의 거부가 tool 응답으로만 드러난다.
- `TRUST_REQUIRED` → 3단계 pin 누락 또는 fingerprint 불일치.
- Claude Code가 qsh tool을 모른다 → 핸드셰이크 실패(mcp.json 경로/env 오기, stdout 오염). stderr는 `$CAMP/claude.log`·`qsh mcp` stderr로 교차 확인.
- `EADDRINUSE` → 2단계에서 ephemeral 포트를 쓰지 않았을 때만 발생 가능.

## 6. 환경 기록

| 항목 | 값 |
|---|---|
| 날짜(UTC) | 2026-08-30 |
| 조작자 | Claude (자율 세션), 운영자 계정 dave / Dave-MBP16 |
| 장비/OS | MacBook Pro (M1 Max), macOS 27.0 (Darwin 27.0.0) |
| qsh 커밋 SHA | 2f5d21a (릴리스 빌드) |
| Claude Code 버전 | 2.1.251, headless `claude -p` |
| 캡처 파일 | 판정 프레임은 본문 §7에 그대로 인용, sandbox(`$CAMP`)는 기록 후 삭제 |

## 7. 실행 기록

| 회차 | C1 | C2 | C3 | C4 | C5 | 판정 | 비고 |
|---|---|---|---|---|---|---|---|
| 1 | ✓ | ✓ | ✓ | ✓ | ✓ | **PASS** | marker `m6-mcp-1788113069`, 14.9s/4턴. C3 증거는 모델 보고(자기일관 b64 인용) — 검증 프레임은 회차 2에서 원문 확보 |
| 2 | ✓ | ✓ | ✓ | ✓ | ✓ | **PASS** | marker `m6-mcp-r2-1788113200`, 11.6s. `--output-format stream-json`으로 MCP 프레임 원문 캡처(아래) |

회차 2의 검증 프레임 원문 — 모델 서술이 아니라 stream-json의 tool_use/tool_result 이벤트 그대로:

```
TOOL_USE: mcp__qsh__exec {"host": "box", "argv": ["/bin/echo", "m6-mcp-r2-1788113200"]}
TOOL_RESULT(verbatim): "{\"duration_ms\":2,\"remote_exit_code\":0,\"signal\":null,
  \"stderr_b64\":\"\",\"stdout_b64\":\"bTYtbWNwLXIyLTE3ODgxMTMyMDAK\"}"
```

`bTYtbWNwLXIyLTE3ODgxMTMyMDAK`를 독립 계산한 `base64("m6-mcp-r2-1788113200\n")`과 대조 — byte-exact 일치 (C3). host `acl.toml`은 전 과정에서 `principal = "device:laptop"` / `allow = ["exec.run"]` 한 블록, 0600 (C4). 두 회차 모두 종료 후 `pgrep -f "qsh mcp"` 0건 (C5). CLI sanity(`qsh exec box --json`)는 회차에 앞서 wire 경로를 별도 확인했다(`remote_exit_code:0`).

## 8. 요약

DoD 2 충족 — Claude Code(2.1.251)가 실제 MCP client로 `qsh mcp`에 stdio 접속해 initialize 핸드셰이크를 마치고 `exec` tool로 원격(loopback QUIC) host에서 명령을 실행했으며, nonce marker가 MCP 프레임 원문 기준 byte-exact로 왕복했다. 사전 고정한 C1–C5 전부 2회차 연속 충족, 판정 예산(5분) 대비 실측 15초 내.

방법론 노트(다음 마일스톤이 반복하지 말 것):
- 최초 절차 초안은 serve를 trust/acl보다 먼저 시작하도록 적었다가 sanity 단계에서 `PERMISSION_DENIED`로 실패했다. host는 trust/acl을 **시작 시 1회** 읽는다 — §4는 실측 순서로 정정됐고, 본 실행(claude 호출) 이전 단계라 회차 판정에는 포함하지 않았다.
- `qsh trust add`는 기존 peer에 대해 `created:false`로 끝나며 address를 갱신하지 않는다. 포트가 바뀐 뒤 pin을 다시 실행하는 것은 무효 — 처음부터 포트 확정 후 pin해야 한다.
- headless `claude -p`는 stdin이 열려 있으면 3초 경고를 낸다 — `< /dev/null` 리다이렉트로 제거.

백로그(이 캠페인이 만든 항목): `trust add`의 address 갱신 경로 부재(update 서브커맨드 또는 `--address` 덮어쓰기 결정)는 M7 doctor·capabilities 정비 입력으로 넘긴다.
