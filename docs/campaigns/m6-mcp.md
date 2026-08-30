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

# 2. host를 loopback ephemeral 포트에 bind (stderr에서 포트 파싱)
QSH_CONFIG_DIR=$CAMP/host/config QSH_STATE_DIR=$CAMP/host/state \
  "$QSH" serve --bind 127.0.0.1:0 2> "$CAMP/serve.log" &
# serve.log의 "qsh serve: listening on 127.0.0.1:<PORT>" 대기 -> PORT

# 3. 상호 pin (fingerprint 명시 = 완전 비대화형, CLI.md §6.11)
QSH_CONFIG_DIR=$CAMP/host/config QSH_STATE_DIR=$CAMP/host/state \
  "$QSH" trust add laptop --fingerprint "$CLIENT_FP" --json
QSH_CONFIG_DIR=$CAMP/client/config QSH_STATE_DIR=$CAMP/client/state \
  "$QSH" trust add box --address "127.0.0.1:$PORT" --fingerprint "$HOST_FP" --json

# 4. host acl.toml — exec.run만 (qsh는 이 파일을 만들어 주지 않는다)
cat > "$CAMP/host/config/acl.toml" <<ACL
[[acl]]
principal = "device:laptop"
allow = ["exec.run"]
ACL
chmod 600 "$CAMP/host/config/acl.toml"

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

## 6. 환경 기록 (실행 시 채운다)

| 항목 | 값 |
|---|---|
| 날짜(UTC) | — |
| 조작자 | — |
| 장비/OS | — |
| qsh 커밋 SHA | — |
| Claude Code 버전 | — |
| 캡처 파일 | — |

## 7. 실행 기록

| 회차 | C1 | C2 | C3 | C4 | C5 | 판정 | 비고 |
|---|---|---|---|---|---|---|---|
| 1 | — | — | — | — | — | — | — |

## 8. 요약

(실행 후 기입)
