# ADR-0011: 내장 MCP 어댑터(`qsh mcp`)를 제거하고 에이전트 연동은 JSON CLI와 exec stdio로 한다

날짜: 2026-09-07
상태: 승인됨

## 맥락

M6는 `qsh mcp`를 stdio MCP 서버로 넣었다(ROADMAP M6, CLI.md §8, PRD의 "선택적 MCP server"). tool 12종은 JSON CLI의 op와 1:1이고 같은 `Ops`를 부르는 얇은 어댑터다(`crates/qsh-cli/src/mcp/`, 915줄). 어댑터에는 로직이 없고 xtask arch가 subprocess 실행과 CLI 출력 재파싱을 막는다.

2026-09-07 검토에서 이 어댑터가 제품의 핵심과 겹치지 않는다고 정리했다. qsh의 값은 연결 수명과 분리된 세션, resume, 터널, ACL과 감사에 있고 그 전부가 `qsh.cli/v1` JSON 계약으로 이미 노출돼 있다. `session read --after --ctl-after --wait`는 MCP `read_session`과 같은 두 값 cursor long-poll이고 `--follow --jsonl`은 스트리밍이다. 세션은 broker 소유라 CLI 프로세스가 끝나도 산다. 재attach는 `session_ref`만으로 하며 resume 토큰은 flock으로 직렬화된 상태 파일이 든다(ADR-0007). 원격에 있는 stdio MCP 서버는 `qsh exec host -- <server>`로 탈 수 있다(CLI.md exec 절, pipe stdin은 EOF까지 원격 명령에 전달). 외부 MCP 서버가 qsh 위에서 필요한 것은 전부 CLI 계약으로 얻는다.

내장 어댑터에는 비용이 있다. rmcp를 정확한 버전으로 핀하고 schemars 핀을 끌고 온다(공급망 표면. API churn 리스크는 `crates/qsh-cli/Cargo.toml` 주석과 ROADMAP 리스크 4에 적혀 있다). CLI.md §8이라는 별도 계약 면, `tools_list.json` golden, conformance 하네스, man page, 캠페인 문서를 유지해야 한다. M8 Step 7의 threat model은 이 표면까지 적어야 한다. TUI나 CLI 도구를 MCP tool로 감싸는 일은 처음부터 qsh 밖의 일이고 그 일을 하는 별도 MCP remote는 qsh를 CLI로 부르면 된다.

## 결정

1. `qsh mcp` 서브커맨드와 `crates/qsh-cli/src/mcp/`를 제거한다. rmcp와 schemars 의존성을 뺀다. xtask arch의 MCP 규칙(`MCP_DIR`), `crates/qsh-cli/tests/mcp_conformance.rs`, `docs/man/qsh-mcp.1`을 지운다.
2. 에이전트와 자동화의 연동 면은 `qsh.cli/v1` JSON/JSONL CLI 하나다. PRD의 "선택적 MCP server" 역할, CLI.md §8, ROADMAP M6 범위는 이 ADR로 철회한다. M6의 완료 표시는 역사로 두고 마감 노트에 철회를 적는다.
3. `crates/qsh-cli/tests/fixtures/mcp/tools_list.json`은 append-only 규칙대로 지우지 않는다. 읽는 테스트가 없어지므로 같은 디렉터리에 `README.md`를 두어 은퇴 사실과 이 ADR을 적는다.
4. 터널 홀더 의미는 CLI.md §6.14 그대로다. 터널은 그것을 연 `qsh tunnel open` 프로세스가 홀더이고 여러 호출에 걸쳐 터널을 들고 있으려면 외부 소비자가 그 프로세스를 살려 둔다. 내장 어댑터가 하던 장기 실행 서버 안의 tunnel hold는 외부로 이전된다. `Ops::tunnel_open`과 `TunnelHold`는 CLI와 testkit이 쓰므로 남긴다. 어댑터만 쓰던 `Ops` API가 있으면 제거 라운드에서 같이 지운다.
5. `-W`(ProxyCommand형 stdio와 원격 TCP의 브리지)는 만들지 않는다. `qsh exec`와 `-L`로 부족한 사용례가 나올 때 M9에서 검토한다(ROADMAP M9).
6. 실행 시점은 M8 Step 6(wire freeze 선행 정리)이다. Step 7 threat model이 지울 표면을 적지 않게 한다. Step 4c와 Step 5는 MCP와 무관해 순서를 바꾸지 않는다.

## 결과

- 잃는 것은 추가 설치 없는 1st-party MCP 서버 하나다. Claude Code 같은 에이전트는 Bash로 `qsh … --json`을 부르거나 별도 MCP remote를 쓴다.
- `qsh.cli/v1`과 `qsh.event/v1` 봉투는 바뀌지 않는다. MCP는 자기 wire(JSON-RPC)를 썼지 JSON 봉투의 필드가 아니었으므로 additive-only 규칙에 걸리지 않는다. 서브커맨드 제거는 alpha 단계의 CLI 표면 변경이고 이 ADR이 그 근거다.
- 바뀌는 문서: PRD(61·68·154·237~255·273·289·352행 부근), CLI.md §8과 §6.4·§7의 MCP 언급, ROADMAP M6 마감 노트와 M9 범위, `docs/design/architecture.md`의 어댑터 절, `docs/design/testing.md`의 golden 규율 예시, ADR-0007의 MCP 언급(사실 서술이라 각주로 처리), README, CLAUDE.md의 MCP 규칙 두 줄과 문서 지도, `docs/campaigns/m6-mcp.md`(역사로 유지, 머리에 철회 주석).
- qsh-core의 `resume.rs`, `ops/mod.rs`, `ops/tunnel.rs`에 있는 `qsh mcp` 언급 주석은 "장기 실행 외부 프로세스" 서술로 바꾼다. 동작 변경은 없다.
- 폴링 read마다 새 프로세스와 새 QUIC 연결이 든다. `--wait` 상한이 60 s라 빈도는 낮고 내장 어댑터가 한 연결을 재사용하던 이점은 여기서 잃는다.

## 대안

- `qsh mcp`를 `-D`처럼 `UNSUPPORTED` 스텁으로 남긴다. 기각한다. 스텁은 "P1에 온다"는 약속의 표현인데 MCP는 돌아오지 않는다. alpha라 깨끗이 지운다.
- 어댑터를 별도 crate로 분리해 유지한다. 기각한다. 유지 비용과 threat model 표면이 그대로다.
- 그대로 유지한다. 기각한다. 맥락에 적은 대로 CLI 계약이 같은 일을 이미 한다.
