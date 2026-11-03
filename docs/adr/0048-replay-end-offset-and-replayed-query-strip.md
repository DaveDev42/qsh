# ADR-0048: attach는 재생분의 끝 offset을 알려 주고, 대화형 렌더러는 재생분의 터미널 질의를 지운다

날짜: 2026-11-03
상태: 승인됨 (2026-11-03, 사용자 결정 "승인")

개정 관계: `SessionAttached`(protocol.md §9)에 additive 필드 7을 더한다. ADR-0019 결정 4(기존 message에 새 필드 번호)의 길을 쓴다. 재생 자체의 의미(protocol.md §8, `[replay_from, …)`의 byte-exact 재전송)는 바꾸지 않는다.

## 맥락

2026-11-03 캠페인 W1(`docs/campaigns/p1-windows.md` §7 "W1 관측", `v0.5.7`)에서 네 변형 모두 `qsh attach`로 다시 붙을 때마다 원격 셸 입력에 `^[[23;1R^[[41;1R^[[>0;10;1c^[[?12;2$y` 같은 바이트가 들어갔다. Windows Terminal에서는 `^[]10;rgb:cccc/cccc/cccc^[\` 같은 OSC 10/11 응답도 섞였다. 셸 프롬프트에서는 `command not found` 줄이 되고, 다시 붙은 직후 친 명령의 앞부분이 먹히기도 했다.

원인은 이렇다. 세션 앞부분에서 TUI(Atuin, 셸 프롬프트 플러그인, vim)가 낸 터미널 질의(CPR `CSI 6 n`, DA2 `CSI > c`, DECRQM `CSI ? Ps $ p`, OSC 10/11 `?`)가 ring에 그대로 남는다. 재부착하면 client가 그 재생분을 로컬 터미널에 쓰고, 로컬 터미널은 질의에 답한다. client의 입력 펌프는 그 답을 키 입력으로 원격 PTY에 보낸다. 질의를 낸 프로그램은 이미 오래전에 답을 받았거나 사라졌으므로, 새 답은 받을 곳이 없는 쓰레기 입력이 된다.

client 쪽 렌더러(`crates/qsh-cli/src/tui/session_loop.rs`의 `pump_events`)는 Windows의 `CSI ? 9001 h/l` 말고는 아무것도 거르지 않는다. 그렇다고 출력 전체에서 질의를 지우면 실행 중인 TUI의 질의에 답이 가지 않아 그 TUI가 멈추거나 기능을 끈다. 재생분과 라이브 출력을 가르는 경계가 필요한데, 오늘 client는 그 경계를 모른다. `SessionAttached`는 `replay_from`(재생 시작)만 싣고 끝은 싣지 않는다.

## 결정

1. `SessionAttached`에 `uint64 output_end = 7`을 더한다. 호스트가 attach를 승인한 순간의 세션 출력 끝 누적 offset(`last_sequence`)이다. `[replay_from, output_end)`가 재생분이고 그 뒤는 라이브다.
2. 기본값 0은 "경계 모름"이다. 이 필드를 모르는 구 호스트가 보낸 attach에서 client는 출력 전부를 라이브로 보고 아무것도 지우지 않는다. 오늘 동작과 같다. 구 client는 필드를 버리고 오늘처럼 동작한다. 양쪽 어느 조합에서도 기본값의 의미가 오늘 동작이므로, ADR-0019 결정 4가 요구하는 capability 확인은 새 capability 문자열 없이 성립한다고 본다. 받는 쪽이 필드를 모를 때 일어나는 일이 곧 오늘 동작이고, 보내는 쪽이 받는 쪽의 이해에 기대는 의미가 없기 때문이다.
3. 대화형 form의 렌더러만 재생분에서 터미널 질의를 지운다. 대상은 DSR·CPR(`CSI n`, `CSI ? n`), DA1·DA2·DA3(`CSI c`, `CSI > c`, `CSI = c`, `ESC Z`), XTVERSION(`CSI > q`), DECRQM(`CSI Ps $ p`, `CSI ? Ps $ p`), kitty 키보드 질의(`CSI ? u`), 창 보고 질의(`CSI t`의 11, 13~16, 18~21), 색·클립보드 질의(`OSC 4`·`5`·`10`~`19`·`52`의 `?`), DECRQSS·XTGETTCAP(`DCS $ q`, `DCS + q`)다. 다른 제어 시퀀스(SGR, 커서 이동, 모드 설정, 제목, 색 설정, sixel 같은 다른 DCS)는 그대로 쓴다.
4. wire와 ring은 byte 그대로다. `--json`/`--jsonl`의 `session.output`, `session read`는 바뀌지 않는다. `qsh.cli/v1`·`qsh.event/v1`에 필드가 늘지 않는다.
5. 청크 경계에 걸친 질의는 다음 청크와 이어 판정한다. 재생분 끝에서 잘린 시퀀스는 라이브 출력 뒤로 붙잡지 않고 곧바로 내보낸다.

## 근거

- 재생분의 질의는 이미 답을 받은 과거 사건이다. 다시 답할 이유가 없고, 다시 답하면 입력이 오염된다.
- 경계를 호스트가 알려 주면 정확하다. 호스트는 attach를 승인하는 바로 그 순간에 `last_sequence`를 갖고 있다.
- 렌더러 단 필터는 9001 필터(ADR-0035 결정 5~8)와 같은 자리, 같은 성격이다. 세션·ACL 로직이 끼지 않는다.

## 대안과 기각 사유

- **출력 전체에서 질의를 지운다.** 실행 중인 TUI의 질의에 답이 가지 않는다. 기각.
- **재부착 뒤 일정 시간 stdin을 버린다.** 시간 기반이라 경합이 남고, 사람이 친 키도 먹으며, 느린 터미널의 답은 여전히 샌다. 기각.
- **attach 전에 `session.list`로 `last_sequence`를 읽어 경계로 쓴다.** wire는 그대로지만 왕복이 하나 늘고, `session.list` 권한 없이 attach만 허용된 peer(ADR-0045 role)는 경계를 얻지 못한다. list와 attach 사이의 출력은 라이브로 분류돼 그 구간의 질의가 새어 나갈 수 있다. 정확한 경계를 얻는 길이 있는데 근사를 택할 이유가 없다. 기각.
- **새 capability 문자열로 필드를 보호한다.** 결정 2의 이유로 보호할 의미가 없고, `capabilities.json` golden과 광고 집합만 늘어난다. 기각.

## 결과

- `crates/qsh-proto/proto/qsh/wire/v1.proto`의 `SessionAttached`에 필드 7, `crates/qsh-core/src/server/sessions.rs`가 채우고 `SessionAttachStream::replay_end()`가 노출한다.
- `crates/qsh-cli/src/tui/replay_filter.rs`(`ReplayFilter`)가 `pump_events`에서 9001 `ModeFilter` 앞에 선다.
- 테스트: `replay_filter` 단위 테스트, `tui_expect::a_reattach_does_not_forward_replayed_terminal_queries`(재생분의 `ESC[6n`은 pty에 닿지 않고 라이브 질의는 닿는다).
- 문서: `docs/CLI.md` 대화형 form 절의 "재생된 출력의 터미널 질의" 문단, `docs/design/protocol.md` §9의 `SessionAttached` 주석.
- 구 호스트에 붙은 새 client는 오늘처럼 새어 나간다. 고치려면 호스트를 올려야 한다.
