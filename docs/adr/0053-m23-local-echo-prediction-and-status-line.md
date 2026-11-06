# ADR-0053: M23의 범위. 대화형 client는 M22의 화면 모델 위에 입력한 글자를 먼저 그리고, host가 알려 주는 입력 반영 지점(`ScreenEcho`)으로 맞았는지 판정해 틀리면 걷어 낸다. 응답이 끊기면 같은 화면 위에 연결 상태 줄을 겹쳐 그린다

날짜: 2026-11-07
상태: 제안됨

개정 관계: ADR-0050 결정 5의 M23을 구체화한다. 다음을 개정한다.
- ADR-0052 결정 12 (d)와 결정 15. 예측 손잡이의 입력 `User`에 사용자 고정값(`--predict`)을 더하고, `[transport].adaptive = "off"`여도 `--predict=always`가 이긴다(결정 11).
- ADR-0052 결정 9와 `docs/design/protocol.md` §4(capability 하나), §9(새 message 하나), §18.6(`DatagramFrame` 종류 13), 새 §18.12(입력 반영 지점).

개정하지 않는 것: `screen.v1`·`datagram.v1`의 뜻, `ScreenUpdate`의 정규 바이트와 `state_hash`(`docs/design/protocol.md` §18.2·§18.4), 상태 번호 규칙(§18.5), 입력 무손실·무중복과 attach 축(§10-5, PRD §8), path 사망 감지의 cadence와 예산(§10, ADR-0021, ADR-0042), 바이트 경로와 `qsh.cli/v1`·`qsh.event/v1`의 바이트 계약.

## 맥락

ADR-0050은 M23을 "M22 화면 모델 위의 mosh식 예측. 확인 전 글자는 밑줄로 그리고, echo-off 구간·전체 화면 앱·연속 오예측에서는 끈다. 응답이 끊기면 '마지막 응답 N초 전' 줄을 띄우고 입력은 받아 둔다"로 정했다. M22가 깔아 둔 것은 다음이다.

- host 에뮬레이터와 상태 번호, 구조화된 셀 차이(ADR-0052 결정 2·5, `docs/design/protocol.md` §18.1~§18.5).
- client의 `ClientScreen`(조각 조립, 적용, hash 대조)과 `ScreenRenderer`(직전에 그린 프레임과의 셀 차이만 쓴다)가 `qsh-core`에 있고, attach driver의 `ScreenSink`가 둘을 쥔다(§18.10). 렌더러의 정확성은 로컬 터미널 모델(두 번째 `HostScreen`)로 고정돼 있다(`local_terminal_follows_the_host`).
- 적응 정책의 예측 손잡이: `srtt > 30 ms`면 `Display`, `< 20 ms`면 `Off`, `> 80 ms`면 `Underline`, `< 50 ms`면 `Display`로 내린다(ADR-0052 결정 12 (d), `PREDICT_ON_ABOVE` 등 네 상수). 값은 계산만 하고 아무도 쓰지 않는다. `SessionAttachStream::adapt_report()`가 그 값을 내놓는다.
- 입력은 세션 data 스트림의 `Input{input_seq, data}`가 정본이고 datagram 사본이 손실 아래 지연을 줄인다(결정 8). 끊긴 동안의 입력은 64 KiB까지 버퍼에 남아 resume 뒤 정확히 한 번 적용된다(§10-5).
- path 사망은 활동 중 250 ms cadence의 control `Ping`과 인증된 frame 카운터로 약 1초 안에 판정하고(§10 "Path 사망 감지", `PathWatch`), 그 뒤 재dial과 resume이 2초 예산 안에 돈다.

빠진 것은 둘이다.

1. **키 입력의 에코는 RTT를 기다린다.** ADR-0052의 측정(q4)에서 에코 p50은 RTT에 머물고 꼬리는 손실 아래 RTO를 따라 늘었다(RTT 150 ms·손실 3~5%에서 p99 502~654 ms). 화면 동기화는 홍수 뒤 지연과 HOL을 없앴지만 한 글자의 왕복은 줄이지 못한다. 줄이는 방법은 로컬에서 먼저 그리는 것뿐이다.
2. **끊긴 동안 아무것도 보이지 않는다.** 감지와 복구는 빠르지만, 복구가 길어지면(망이 아예 없음, 잠에서 깨어남, 2초 예산 뒤의 재시도) 사용자는 멈춘 화면만 본다. 화면 경로에서는 렌더러가 로컬 터미널 전체를 쥐고 있어서 stderr 한 줄을 끼워 넣을 자리도 없다.

### mosh의 방식 (개념만, 코드·문안은 쓰지 않는다)

mosh client는 출력 가능한 키를 누르면 서버의 응답 전에 커서 자리에 그 글자를 그린다. 서버는 화면 상태마다 "이 상태는 client 입력 몇 번까지를, 앱이 반응할 시간을 준 뒤에 반영했다"는 번호를 함께 보낸다. client는 그 번호를 넘은 예측을 실제 화면과 견주어 맞으면 지우고(서버 화면이 같은 글자를 보여 준다) 틀리면 걷어 낸다. Enter나 제어 키처럼 결과를 짐작할 수 없는 키 뒤의 예측은 새 묶음(epoch)으로 넣고, 그 묶음의 예측 하나가 서버 화면으로 확인되기 전에는 그리지 않는다. 그래서 암호처럼 에코가 없는 입력은 Enter 뒤에 오는 한 그려지지 않는다. 지연이 크거나 확인이 늦은 예측은 밑줄로 표시해 아직 확정이 아님을 알린다. 연결이 오래 조용하면 화면 맨 윗줄에 마지막 응답 이후의 시간을 띄운다.

qsh는 같은 생각을 따르되 qsh의 조건에 맞게 바꾼다. host는 PTY의 termios를 읽을 수 있으므로 echo-off를 추측하지 않고 알린다(결정 6). 입력 번호는 mosh의 상태 번호 대신 §10-5의 누적 입력 offset을 쓴다. 판정 신호는 화면 갱신과 따로 오는 작은 message이고, 화면이 바뀌지 않아도(암호 입력) 판정할 수 있다.

## Dave가 정할 것

1. **기본값.** `[interactive].predict`의 기본을 `auto`(정책 손잡이를 따라 RTT 30 ms 위에서 켬)로 둘지 `never`로 둘지. **추천은 `auto`.** 화면 동기화가 기본 `auto`이고(ADR-0052 Dave 결정 2), 예측은 그 위에서만 돌며 LAN·loopback(srtt < 20 ms)에서는 그리지 않는다. 오예측 비용은 한 RTT 동안 보였다가 걷히는 글자이고, 연속 오예측은 스스로 끈다(결정 7). `never`면 mosh 수준 사용성이라는 P2 목표(ADR-0050 결정 1)를 기본에서 얻지 못한다.
2. **상태 줄의 자리.** 창의 맨 윗줄(mosh와 같다)인지 맨 아랫줄인지. **추천은 맨 윗줄.** 셸 프롬프트와 커서는 대개 아래쪽에 있어서 아랫줄은 지금 입력하는 줄을 가린다. 커서가 맨 윗줄에 있을 때만 아랫줄로 옮긴다(결정 9).
3. **넓은 글자(한글) 예측.** 동아시아 넓은 글자(폭 2)를 예측할지. **추천은 예측한다.** 한글 입력이 Dave의 흔한 경로이고, host 에뮬레이터(`vt100`)와 client가 같은 `unicode-width` 표를 쓰면 폭이 어긋나지 않는다. 폭이 모호한 글자, 결합 문자, ZWJ·이모지 조합, variation selector는 예측하지 않는다(결정 4). 어긋나면 그 행의 예측이 틀린 것으로 판정돼 걷히고 연속 오예측 규칙이 끈다.
4. **옛 host(M22, `screen-echo.v1` 없음).** 예측을 끌지, 판정 신호 없이 시간 제한으로 예측할지. **추천은 끈다.** 판정 신호가 없으면 에코하지 않는 입력(암호)을 "아직 안 왔다"와 구별할 수 없어서, 그려진 예측을 언제 걷을지 시간으로만 정해야 한다. 상태 줄은 client만으로 돌므로 옛 host에서도 켠다.

## 결정

### 범위

1. **예측과 상태 줄은 화면 동기화 attach에만 있다.** ADR-0052 결정 1이 화면 경로로 보내는 대화형 attach(로컬 stdin·stdout이 TTY, 사람 모드)가 대상이고, 정방향과 역방향 route 모두다. 바이트 경로(`--screen-sync=off`, `screen.v1`이 없는 host, `session.open` 없이 만든 세션, TTY가 아닌 stdout)에는 예측도 상태 줄도 없다. 그 경로는 PTY 바이트를 그대로 쓰므로 겹쳐 그릴 화면 모델이 없다. `--json`/`--jsonl`, `session read`, exec, 터널, `qsh cp`는 바뀌지 않는다.

### 층 배치

2. **예측 엔진은 `qsh-core`의 client 화면 모델 옆에 있다.**
   - 새 모듈 `crates/qsh-core/src/client/predict.rs`의 `Predictor`는 I/O도 시계도 없는 상태 기계다. 입력은 `on_input(bytes, input_end, now)`, `on_state(&ScreenState, state_num, now)`, `on_echo(ScreenEcho)`, `on_policy(Prediction)`, `on_link(LinkStatus)`이고 출력은 `overlay() -> Overlay`(덧그릴 셀 목록과 예측 커서)다. `now`는 호출자가 넘긴다. 그래서 표 테스트와 proptest가 시간을 만들어 몬다.
   - `ScreenRenderer`는 `draw`가 받는 상태에 `Overlay`와 상태 줄을 합성한 프레임을 그린다(`Frame::fit` 뒤의 합성 단계). `ClientScreen`이 든 host 상태와 그 `state_hash` 대조는 합성과 무관하다. 겹친 것은 렌더러가 "로컬 터미널에 지금 있는 것"으로만 기억하고, 겹침이 빠진 다음 프레임은 셀 차이로 host 셀을 되쓴다.
   - `ScreenSink`가 `Predictor`와 상태 줄 상태를 함께 쥔다. attach driver는 input pump가 `Input`을 보내는 자리에서 `on_input`을 부르고 곧바로 다시 그려, 예측한 글자를 `qsh.event/v1`의 `Output` 이벤트(§18.10과 같은 내부 경로)로 frontend에 낸다. host 왕복을 기다리지 않는 것이 이 마일스톤의 이득이다.
   - `qsh-cli`는 지금처럼 이벤트의 바이트를 터미널에 쓰기만 한다. 새로 하는 일은 플래그와 설정 키를 `ScreenAttach`에 실어 넘기는 것과, 상태 줄의 안내에 쓸 escape 문자를 함께 넘기는 것뿐이다. escape 처리(`~.` 등)는 CLI의 입력 스레드에 그대로 있고, 보류된 `~`는 `Ops`에 닿지 않으므로 예측되지 않는다.
   - `xtask arch`의 금지는 새 경로에도 그대로 걸린다(`crates/qsh-core/src/`의 `quinn::` 금지). 새 금지 경로는 더하지 않는다.

### 판정 신호

3. **host가 입력 반영 지점을 알린다: `ScreenEcho`.** 기존 정보로는 판정할 수 없다. `InputAck`는 host가 PTY에 쓴 offset일 뿐 앱이 그 입력에 반응한 화면이 어느 상태인지 말하지 않고, 화면이 바뀌지 않는 입력(암호, 아무 반응 없는 키)은 새 `ScreenUpdate`도 만들지 않는다(§18.5). 그래서 wire에 message 하나를 더한다.
   - `message ScreenEcho { uint64 state_num = 1; uint64 input_seq = 2; TtyEcho tty = 3; }`, `enum TtyEcho { TTY_ECHO_UNKNOWN = 0; TTY_ECHO_KERNEL = 1; TTY_ECHO_APP = 2; TTY_ECHO_SECRET = 3; }`.
   - 뜻: "host가 이 frame을 만든 시각 t에 이 attach가 보는 화면은 상태 `state_num`이었고, 이 attach 축의 누적 입력 offset `input_seq` 앞의 바이트는 모두 `t - ECHO_GRACE` 전에 PTY에 쓰였다. `tty`는 t에 읽은 PTY의 에코 상태다." `input_seq`는 `Input.input_seq`와 같은 누적 offset(§10-5)이다. `ECHO_GRACE`는 50 ms에서 시작하고 결정 16의 시험으로 세 OS에서 확정해 개정 이력에 적는다.
   - host는 attach마다 PTY에 쓴 입력의 (끝 offset, 쓴 시각)을 64개까지 들고, 넘치면 가장 오래된 둘을 합친다(시각은 늦은 쪽). 스트림 정본과 datagram 사본(ADR-0052 결정 8)이 같은 축을 쓰므로 어느 쪽으로 적용됐든 같다.
   - **보내는 때.** 화면 동기화 attach에서, 협상된 교집합에 `screen-echo.v1`이 있을 때만 보낸다. (a) `ScreenUpdate`를 보낼 때마다 같은 운반체로 그 뒤에 하나(그 갱신의 `new_num`), (b) 화면이 바뀌지 않았어도 `input_seq`나 `tty`가 앞으로 가면 하나. (b)는 입력을 쓴 시각 + `ECHO_GRACE`에 타이머로 깬다. 값이 직전과 같으면 보내지 않는다. 한 attach에서 화면 주기(ADR-0052 결정 12 (b)) 하나에 하나까지로 합친다.
   - **운반체.** 늘 세션 data 스트림(`SessionFrame.screen_echo = 10`)으로 보내고, datagram 운반체가 살아 있으면 `DatagramFrame` 종류 13(`ScreenEcho screen_echo = 13`)으로도 먼저 한 번 보낸다. message가 varint 셋이라 스트림 비용은 작고, 손실 아래서는 datagram 쪽이 먼저 닿는다. client는 두 길 중 `(state_num, input_seq)`가 더 앞선 것을 쓰고 뒤처진 것은 버린다. datagram은 ADR-0052 결정 7대로 channel id로 식별하고 어떤 자원도 만들지 않는다.
   - **tty 읽기.** Linux·macOS host는 PTY master에서 `tcgetattr`로 `ECHO`와 `ICANON`을 읽는다. `ECHO`가 켜져 있으면 `KERNEL`(커널이 에코한다), `ECHO`와 `ICANON`이 모두 꺼져 있으면 `APP`(readline·zle처럼 앱이 스스로 에코한다), `ECHO`가 꺼지고 `ICANON`이 켜져 있으면 `SECRET`(getpass·sudo·ssh의 암호 입력)이다. Windows host(ConPTY)는 앱의 콘솔 모드를 바깥에서 읽을 수 없어 늘 `UNKNOWN`이다. 읽기 실패도 `UNKNOWN`이다.
   - **client의 검사.** `state_num`이 이미 적용한 상태보다 앞서 있으면 그 상태를 적용할 때까지 들고 있는다(하나만, 더 새것이 오면 바꾼다). `input_seq`가 client가 보낸 offset보다 크면 거짓 신호로 보고 버리고 센다(`echo_rejected`). 연결을 끊지 않는다.

### 무엇을 예측하나

4. **예측하는 키와 그 모양.** `Predictor`는 `Ops`로 가는 입력 바이트를 UTF-8로 읽어 다음만 예측한다.
   - **출력 가능한 글자.** 폭 1 글자, 그리고 `unicode-width`가 폭 2로 세는 동아시아 넓은 글자(Dave가 정할 것 3). 커서 자리에 글자를 놓고, 커서 오른쪽에 비어 있지 않은 셀이 있으면 그 셀들을 글자 폭만큼 오른쪽으로 민다(줄 편집기의 삽입). 밀려서 행 끝을 넘는 셀은 버린다. 글자의 속성은 커서 왼쪽 셀의 속성을 빌린다. 판정은 글자만 견주고 속성은 견주지 않는다(문법 강조가 색을 바꾼다).
   - **Backspace**(0x7f, 0x08). 예측 커서가 0열보다 오른쪽이고 왼쪽 셀이 같은 행에 있을 때만 커서를 한 글자 왼쪽으로 옮기고 그 글자를 지우며 오른쪽 셀을 당긴다. 이전 행으로 넘어가지 않는다.
   - **왼쪽·오른쪽 화살표**(`CSI D`·`CSI C`, 응용 커서 모드의 `SS3 D`·`SS3 C`). 같은 행 안에서만 커서를 옮긴다. 오른쪽은 다음 셀이 비어 있지 않을 때만이다(줄 편집기는 입력 끝을 넘어가지 않는다).
   - 그 밖의 모든 것은 예측하지 않고 **epoch를 끊는다**: Enter, Tab, 제어 문자, 위·아래 화살표, Home·End·Delete, 기능 키, 그 밖의 escape 시퀀스, 폭이 모호한 글자, 결합 문자, ZWJ·이모지 조합, variation selector, 잘못된 UTF-8. 읽기 경계에 걸친 UTF-8은 다음 읽기까지 모았다가 판단한다.
   - **예측하지 않는 자리.** 커서가 마지막 열에 있을 때(다음 글자가 줄을 넘길 수 있다) 그 키는 예측하지 않고 epoch를 끊는다. 넓은 글자가 들어갈 자리가 모자랄 때도 같다.
   - **붙여넣기.** 한 번의 읽기에 글자가 4개를 넘거나 bracketed paste 표시(`CSI 200~` … `CSI 201~`) 안의 바이트는 예측하지 않고 epoch를 끊는다.
   - 예측은 attach당 256개까지다. 넘으면 그 뒤로는 예측하지 않고 epoch를 끊는다.

5. **epoch.** 예측은 epoch에 속한다. 처음 예측과 epoch를 끊은 뒤의 예측은 **임시** epoch에 들어가고, 임시 epoch의 예측은 계산하고 판정하지만 그리지 않는다. 그 epoch의 예측 하나가 host 화면으로 확인되면 epoch가 **확정**되고 그때부터 그 epoch의 예측을 그린다. 그래서 Enter 뒤의 첫 글자는 한 RTT 뒤에 보이고 나머지는 바로 보인다. 에코가 없는 입력(암호 등)은 확인되지 않으므로 Enter 뒤에 오는 한 끝까지 그려지지 않는다. 다음도 epoch를 끊는다.
   - host 상태가 예측하지 않은 곳으로 커서를 옮겼을 때(프롬프트가 새로 그려졌다, 출력이 화면을 밀었다). 남은 예측은 버리고 오예측으로 세지 않는다.
   - 예측이 틀렸다고 판정됐을 때(결정 6).
   - 연결이 바뀌어 새 leg의 첫 전체 화면을 그릴 때. 이때 끊긴 동안 입력해 그려 둔 예측은 버리지 않고 새 leg의 `ScreenEcho`로 판정한다. 끊긴 동안의 입력은 §10-5대로 resume 뒤 정확히 한 번 적용되므로 같은 offset으로 판정할 수 있다.

6. **확인과 철회.** 각 예측은 (행, 열, 글자, 그 키의 끝 입력 offset `input_end`, epoch)를 갖는다. 새 host 상태를 적용하거나 `ScreenEcho`를 받을 때마다 아직 판정하지 않은 예측을 다음 순서로 본다.
   - **확인.** host 상태의 그 셀 글자가 예측 글자와 같으면 확인이다. 예측을 지운다(host 셀이 같은 글자를 보여 준다). `ScreenEcho`를 기다리지 않는다.
   - **틀림.** 받은 `ScreenEcho`의 `input_seq`가 `input_end` 이상이고, client가 그 `state_num` 이상의 상태를 적용했는데 셀이 다르면 틀림이다. 그 예측과 같은 epoch의 뒤 예측, 그 뒤 epoch의 예측을 모두 버린다(뒤 예측의 자리가 이 예측에 기대기 때문이다). 오예측 수를 하나 올리고 epoch를 끊는다.
   - **대기.** 둘 다 아니면 그대로 그린다. 시간으로 걷어 내지 않는다. 끊긴 동안에는 대기가 길어지고 상태 줄(결정 9)이 그 사실을 알린다.
   - 예측 커서도 같은 규칙이다. host 커서가 예측 커서와 같고 `input_seq ≥ input_end`면 확인, 다르면 틀림이다.
   - 철회는 다시 그리기 한 번이다. 버린 예측의 셀은 다음 프레임에서 host 셀로 되쓰이고, 렌더러의 셀 차이(§18.10)가 바뀐 셀만 쓰며 여러 구간이면 그리는 동안 커서를 숨긴다. 화면을 지우지 않으므로 깜빡임은 걷어 낸 셀에 그친다.

### 끄는 조건

7. **예측을 그리지 않는 때.** 아래 차단은 `--predict`의 어느 값에서든 걸린다. 걸리면 남은 예측을 모두 버리고 다음 키부터 임시 epoch로 시작한다.
   - `tty`가 `SECRET`인 동안. 그 `ScreenEcho`를 받는 즉시 버리고 다시 그린다.
   - host 상태가 대체 화면, 커서 숨김, 마우스 보고 모드 중 하나인 동안(전체 화면 앱). 응용 커서 키·응용 키패드는 차단하지 않는다(zsh가 켠다).
   - 이 attach가 writer lease를 갖지 않는 동안(read-only attach는 입력이 적용되지 않는다).
   - host가 `screen-echo.v1`을 광고하지 않을 때(Dave가 정할 것 4).
   - **연속 오예측.** 확인 없이 오예측이 3번 이어지면 그리기를 멈춘다(정지). 정지 중에도 예측은 계산하고 판정한다. 그려지지 않은 예측이 연속 4번 확인되면 정지를 푼다. 숫자는 `MISPREDICT_SUSPEND = 3`, `REENABLE_CONFIRMS = 4`로 두고 표 테스트로 고정한다.
   - 정책이 `Off`일 때(결정 8). 이때도 예측은 계산한다. 결정 8의 늦은 확인 규칙이 그것을 쓴다.

### 그리기

8. **정책과 밑줄.** 그릴지와 어떻게 그릴지는 `Knobs.prediction`(ADR-0052 결정 12 (d))과 엔진의 관측이 함께 정한다.
   - `Off`면 그리지 않고, `Display`면 셀의 빌린 속성 그대로, `Underline`이면 거기에 밑줄 비트(§18.1의 8)를 더해 그린다. 정책 값은 `PolicyMonitor`(정방향)가 1초마다 내는 그대로이고, 문턱과 hysteresis는 ADR-0052의 네 상수다.
   - **늦은 확인.** 확인까지 250 ms를 넘긴 예측이 하나라도 나오면 정책 값과 관계없이 `Underline`으로 그린다. 그 뒤 연속 10개가 `PREDICT_ON_ABOVE`(30 ms) 안에 확인되면 정책 값으로 돌아간다. 손실 아래 꼬리 지연(ADR-0052 q4)은 srtt가 낮은 경로에서도 생기기 때문이다. `GLITCH_AFTER = 250 ms`, `GLITCH_REPAIR = 10`.
   - 상태 줄이 떠 있는 동안 그리는 예측은 모두 밑줄이다.
   - **역방향 route.** client에 QUIC 연결이 없어 `PolicyMonitor`가 돌지 않는다(ADR-0052 개정 이력 2026-11-07). 그 route에서는 `Input`을 보낸 시각부터 그 offset을 덮는 `InputAck`가 오기까지를 RTT 표본으로 삼아 EWMA를 내고, 그 값을 `srtt`로 넣은 `adapt::decide`로 같은 손잡이를 얻는다. 정방향·역방향이 같은 기능을 갖는다는 원칙(`docs/ROADMAP.md` §6.1 원칙 2)을 지키기 위해서다.
   - **history와 스크롤백.** 예측은 창의 셀에만 겹치고 history(§18.11)에는 들어가지 않는다. `ScreenRenderer::history`가 행을 스크롤백에 넣고 다시 그릴 때 겹침도 다시 합성한다. host 출력이 화면을 밀어 커서 행이 바뀌면 결정 5대로 epoch가 끊기므로 예측한 글자가 스크롤백으로 밀려 올라가는 일은 없다. 로컬 창이 host 화면보다 좁아 예측 열이 잘리면 그 셀은 그리지 않는다(§18.10의 자르기).

### 연결 상태 줄

9. **내용, 나타나는 때, 자리.**
   - **진실의 원천.** `qsh-core`가 attach마다 `LinkStatus{last_reply, waiting_since, recovering: Option<attempt>}`를 든다. `last_reply`는 `PathWatch`가 마지막으로 인증된 inbound(frame 카운터, `Pong`, 세션 트래픽, §10)를 본 시각이고, `waiting_since`는 그 뒤 보낸 것(probe 또는 입력) 가운데 답이 없는 가장 오래된 것의 시각, `recovering`은 recovery 루프가 도는 동안의 시도 번호다. 역방향 route는 같은 값을 그 route의 watchdog과 recovery 루프가 채운다. `SessionAttachStream::link_status()`로 읽을 수 있고 `adapt_report()` 옆에 둔다. 상태 줄은 이 값만 그린다.
   - **나타나는 때.** recovery가 돌고 있거나, `now - waiting_since ≥ max(2 s, 4 × srtt)`일 때. 조용한 idle 셸은 보낸 것이 없으므로 답을 기다리지 않고, 그래서 5초 cadence의 idle probe 사이에 줄이 뜨지 않는다. srtt를 모르면(첫 표본 전, 역방향의 첫 InputAck 전) 2초다.
   - **사라지는 때.** 인증된 inbound가 오고 recovery가 돌지 않으면 바로 지운다. 새 leg로 넘어갔으면 그 leg의 첫 전체 화면을 그릴 때 지운다.
   - **내용.** CLI의 사람용 문구와 같은 영어로 한 줄이다. recovery 전에는 `qsh: last reply 3s ago`, recovery 중에는 `qsh: last reply 9s ago, reconnecting (attempt 2)`이고, escape 문자가 있으면 `; ~. to quit, ~d to detach`를 붙인다(`--escape-char`가 바꾼 문자를 쓴다). 초는 정수로 내리고, 줄은 1초마다 다시 그린다. 창 폭에 맞게 오른쪽을 자르고, 창이 20열보다 좁으면 그리지 않는다. 반전 속성으로 창 폭 전체를 채운다. 줄의 글자는 모두 로컬 상태에서 나오고 peer 문자열을 싣지 않는다.
   - **자리.** 창의 맨 윗줄에 겹친다(Dave가 정할 것 2). host 커서(또는 예측 커서)가 맨 윗줄에 있으면 맨 아랫줄에 겹친다. 겹침은 결정 2의 합성 단계에서 들어가므로 `ClientScreen`의 상태와 hash는 건드리지 않고, 지울 때는 그 행의 host 셀이 셀 차이로 되쓰인다. 대체 화면에서도 같다.
   - **다시 그리기.** 상태 줄이 떠 있는 동안 attach driver가 1초 타이머로 `ScreenSink`를 깨워 줄만 다시 그린다. host 갱신이 없어도 숫자가 간다.
   - **끊긴 동안의 입력.** 새로 버퍼를 두지 않는다. 입력은 지금처럼 미ack 버퍼(64 KiB 상한, §10-5)에 남고 resume 뒤 한 번만 적용된다. 확정 epoch 안에서 친 글자는 예측으로 밑줄을 그어 보인다. 상한을 넘으면 지금처럼 오류로 끝난다.

10. **끄는 손잡이.** `--status-line=on|off`, 키 `[interactive].status_line`(기본 `on`). `off`면 줄을 그리지 않는다. `LinkStatus`와 recovery 동작은 그대로다.

### 사용자 표면

11. **플래그와 설정 키.** ADR-0050 결정 2대로 플래그와 `qsh config` 키를 함께 둔다. 둘 다 `qsh [user@]host`와 `qsh attach`에만 붙고(`--screen-sync`와 같다), 명령마다 읽는 키라 `applies_from`이 없다.
    - `--predict=auto|always|never`, 키 `[interactive].predict`(기본 `auto`, Dave가 정할 것 1). `auto`는 결정 8의 정책 값을 따른다. `always`는 srtt와 `[transport].adaptive`에 관계없이 적어도 `Display`로 그리고 밑줄은 결정 8의 규칙대로다. `never`는 `Predictor`를 만들지 않는다.
    - `--predict`는 `adapt::User`에 실린다(새 필드 `prediction: Option<PredictPin>`). `decide`가 그 값을 반영하고 `reasons`에 `user_override`를 넣으므로 `qsh::adapt` 줄과 `adapt_report()`가 실제 동작과 같은 값을 보인다. 결정 7의 차단은 이 고정 밖이다.
    - `always`인데 예측을 할 수 없으면(바이트 경로, `screen-echo.v1` 없는 host) raw 모드에 들어가기 전에 stderr 한 줄 `qsh: --predict=always has no effect: <reason>`을 쓰고 계속한다. 새 오류 코드와 `details.reason`은 없다. 기계 모드에는 이 플래그가 없다.
    - 읽히지 않는 `config.toml`이면 `[interactive].screen_sync`와 같은 규칙으로 플래그를 준 경우를 빼고 `CONFIG_ERROR`다.

12. **보이는 곳.**
    - `qsh doctor <host>`는 새 info 코드 `screen_echo_unsupported`(peer가 `screen.v1`은 광고하지만 `screen-echo.v1`은 광고하지 않음)를 낸다. `EXPECTED_DOCTOR_CODES`에 더한다. `DoctorData.transport.prediction`은 이미 있다.
    - 새 tracing target `qsh::predict`는 엔진 상태가 바뀔 때(그림 켬·끔·정지·정지 풂, 차단 사유) 한 줄 JSON을 남긴다. 확인·오예측·`echo_rejected` 개수와 사유만 담고, 글자·행·열·입력 바이트는 담지 않는다. `qsh::adapt`처럼 기본 verbosity에서 꺼져 있고 `-v`나 `QSH_LOG=qsh::predict=info`가 켠다.
    - `docs/CLI.md` §7(두 플래그와 상태 줄), §6.23(키 둘), §6.17(doctor 코드)을 고치고 `cargo xtask man`으로 man page를 다시 만든다.

13. **JSON 추가는 모두 additive다.** `capabilities` 결과의 새 문자열 `screen-echo.v1`(`capabilities.json` golden을 `QSH_UPDATE_FIXTURES=1`로 다시 만들고 계약 변경과 같은 무게로 본다), `config.list`의 새 키 둘, doctor 코드 하나. 기존 fixture는 고치지 않는다. `--json`/`--jsonl`의 stdout은 지금처럼 JSON뿐이고, 예측과 상태 줄은 기계 모드에 나타나지 않는다.

### 플랫폼

14. **세 OS가 같다.**
    - client는 Linux·macOS·Windows에서 같은 `Predictor`와 렌더러를 쓴다. Windows 콘솔은 VT 처리 모드로 렌더러 바이트를 해석하고, 키 입력은 `utf16_input`이 UTF-8과 VT 시퀀스로 바꾼 뒤 `Ops`에 넘기므로 예측 입력도 같은 바이트다. 밑줄(SGR 4)과 반전(SGR 7)은 Windows Terminal과 conhost가 모두 그린다.
    - host는 Linux·macOS에서 결정 3의 termios 판정을 쓰고, Windows(ConPTY)에서는 `tty`가 늘 `UNKNOWN`이라 암호 보호는 epoch 규칙(결정 5)에만 기댄다. ConPTY는 한 키에도 행을 다시 그리거나 커서를 옮겨 쓸 수 있으므로, Windows host의 cmd.exe와 pwsh(PSReadLine)에서 예측이 확인되는지를 결정 16이 따로 시험한다. 확인되지 않으면 연속 오예측 규칙이 끈다. 그래도 화면은 틀리지 않는다.

### 위협 모델

15. **예측은 비밀을 새로 드러내지 않는다.**
    - 예측이 그리는 글자는 사용자가 방금 친 입력이고 host는 이미 그 바이트를 받는다. 새로 노출될 수 있는 상대는 로컬 화면을 보는 사람과 화면 녹화다. `tty = SECRET`(Unix host)과 임시 epoch(모든 host)가 암호 입력을 그리지 않게 하고, 예측 셀은 스크롤백에 들어가지 않는다(결정 8).
    - 적대적 host는 `ScreenEcho`로 예측을 오래 남기거나 틀렸다고 판정하게 할 수 있지만, 바꿀 수 있는 것은 사용자 자신의 입력이 로컬에 보이는 시점뿐이다. 예측의 글자는 로컬 입력에서만 나오고 peer가 내용을 넣을 수 없다. `input_seq`가 보낸 offset을 넘는 신호는 버리고 센다.
    - 새 로그는 `qsh::predict`의 개수와 사유뿐이고 PTY 내용과 입력 바이트를 담지 않는다. 감사 기록에 새 필드는 없다. 상태 줄은 로컬 상태만 그린다.
    - 자원: client 예측 256개, 보류한 `ScreenEcho` 하나, host의 입력 시각 표 attach당 64개. 상한 시험을 둔다.
    - 파서 표면: `ScreenEcho`는 protobuf message라 기존 두 fuzz 타깃이 덮고, 엔진은 새 상태 기계 fuzz 타깃을 둔다(결정 16의 10).

### 수용 기준(M23 DoD)

16. 1. **고지연에서 바로 보인다.** testkit chaos proxy(L4)에 단방향 150 ms(RTT 300 ms)를 걸고, `a_predicted_keystroke_is_drawn_before_the_echo_arrives`가 셸 프롬프트에서 확정 epoch의 키 50개를 친다. 키를 `Ops`에 넘긴 때부터 그 글자가 client의 로컬 터미널 모델(M22 렌더러 시험의 두 번째 `HostScreen`)에 보이기까지 p95 ≤ 20 ms이고, 그동안 셀에 밑줄이 있으며, 확인 뒤에는 밑줄 없이 host 셀과 같다. 예측을 끈(`never`) 같은 시나리오의 값(≥ 300 ms)을 함께 기록한다. `QSH_ACCEPTANCE_SLOW`에서 돈다.
    2. **철회 뒤 화면은 host와 같다.** `local_terminal_matches_the_host_once_predictions_resolve`(proptest, L2)가 임의의 키 열과 임의의 host 반응(그대로 에코, 에코 없음, 다른 글자로 에코, 늦은 에코, 커서 이동, 화면 밀기, 대체 화면 전환)을 섞는다. 모든 입력이 `ScreenEcho`로 판정된 뒤 로컬 터미널 모델의 셀과 커서가 host 상태와 같고(`state_hash` 대조), 어느 시점에서든 겹침 밖의 셀은 host와 같다.
    3. **오예측은 한 번의 판정으로 걷힌다.** `a_misprediction_is_rolled_back_within_one_echo`가 입력을 `*`로 에코하는 시험 도우미에서, 틀린 예측이 host 상태와 그 `ScreenEcho`를 받은 뒤 첫 그리기에서 사라지는 것을 본다. `three_wrong_epochs_suspend_display_until_four_confirmations`가 결정 7의 정지와 풀림을 표로 고정한다.
    4. **암호는 그려지지 않는다.** `secret_input_is_never_drawn`(Linux·macOS host)이 `stty -echo; read`(ECHO 끔, ICANON 켬) 아래에서 친 글자가 client가 낸 어떤 그리기 바이트에도 나타나지 않고 `tty = SECRET`이 오는 것을 본다. `a_tentative_epoch_is_never_drawn`(세 OS의 host)은 에코하지 않는 시험 도우미에서 Enter 뒤 친 글자가 한 번도 그려지지 않는 것을 본다.
    5. **차단 표.** `prediction_gates`가 결정 4와 7의 각 조건(대체 화면, 커서 숨김, 마우스 모드, bracketed paste, 긴 읽기, 모호한 폭·결합 문자, 마지막 열, read-only attach, `never`, `screen-echo.v1` 없음)을 한 행씩, 결정 8의 정책 값·늦은 확인·상태 줄 밑줄을 한 행씩 고정한다. `docs/design/testing.md` L2에 올린다.
    6. **상태 줄.** `status_line_appears_during_a_blackhole_and_clears_on_recovery`가 활동 중인 attach에 chaos proxy `blackhole`을 10초 건다. 줄이 `max(2 s, 4 × srtt)` + 1초 안에 로컬 터미널 모델의 맨 윗줄에 나타나고 초가 줄지 않으며, recovery 중에는 `reconnecting`이 붙고, 풀린 뒤 첫 인증된 inbound(또는 새 leg의 첫 전체 화면)에서 1초 안에 사라지며, 그 뒤 로컬 모델이 host 상태와 같다. 같은 시험이 끊긴 동안 친 입력이 resume 뒤 한 번만 적용되고 그동안 밑줄로 보였음을 단언한다. `idle_attach_shows_no_status_line`은 5초 idle cadence 사이에 줄이 뜨지 않는 것을, `status_line_off_draws_nothing`은 `off`를 본다. 역방향 route에서 같은 blackhole 시험 하나(`reverse_status_line_appears_during_a_blackhole`)를 돈다.
    7. **옛 peer와 바이트 경로.** testkit의 capability 가림으로 `a_host_without_screen_echo_gets_no_predictions`(M22 host, 상태 줄은 뜬다)와 `a_client_without_screen_echo_gets_no_screen_echo_frames`를 돈다. `--screen-sync=off`와 `screen.v1` 없는 host에서는 `Predictor`도 상태 줄도 없고, 기존 바이트 경로 시험(`off_keeps_the_byte_path` 등)과 fixture가 diff 없이 통과한다.
    8. **wire 고정.** `screen_echo_is_sent_after_input_even_when_the_screen_does_not_change`(암호 경우의 (b) 경로), `screen_echo_follows_each_screen_update_on_the_same_carrier`, `a_screen_echo_beyond_the_sent_input_is_rejected_and_counted`, 그리고 tty 판정 세 값의 Unix 유닛(`tty_echo_reads_echo_and_icanon_from_the_pty`)이 있다. `ECHO_GRACE`를 확정한 값이 개정 이력과 이 시험에 함께 적힌다.
    9. **계약.** `capabilities.json` golden 재생성, `config.list`의 두 키(`every_config_key_is_settable`), `EXPECTED_DOCTOR_CODES`의 `screen_echo_unsupported`, man page(`checked_in_man_pages_match_the_generator`)가 초록이다.
    10. **fuzz.** `decode_session_frame`과 `decode_datagram_frame`이 `ScreenEcho`(종류 13 포함)를 덮도록 corpus와 문서를 고치고, 새 상태 기계 타깃 `client_predictor`(임의의 입력 바이트, 상태, `ScreenEcho`를 섞어 먹이고 겹침이 화면 안에 있고 예측 수가 상한 안이며 모든 입력이 판정된 뒤 겹침이 비는지 본다)를 더해 `fuzz/README.md`의 목록과 개수를 고친다.
    11. **성능 회귀 없음.** loopback의 `tunnel_echo_under_load`(p95 < 10 ms)와 야간 `screen_cat_ratio`(하한 0.5, ADR-0052 결정 18의 11)가 그대로 통과한다. srtt < 20 ms에서 예측은 그리지 않으므로 loopback 에코 경로의 바이트는 `ScreenEcho` frame만 늘어난다.
    12. **세 OS.** 1, 3, 4의 `a_tentative_epoch_is_never_drawn`, 6, 7은 Linux·macOS·Windows CI에서 돈다. Windows host는 cmd.exe와 pwsh에서 1과 3을 통과한다(`windows_host_predictions_confirm_in_cmd_and_pwsh`).
    13. threat model에 결정 15의 행이 고정 테스트와 함께 들어간다.

## 근거

- **판정 신호를 wire에 두는 이유.** client가 가진 것(화면 갱신, `InputAck`)으로는 "아직 에코가 안 왔다"와 "에코가 오지 않는다"를 가를 수 없다. 앞의 것은 기다려야 하고 뒤의 것은 걷어 내야 한다. 시간 제한으로 가르면 느린 경로에서는 맞는 예측을 걷고 빠른 경로에서는 암호 글자를 오래 남긴다. host는 입력을 언제 썼는지 알고, 그 뒤 일정 시간이 지난 화면이 무엇인지 안다. 그 사실 하나를 실어 보내면 판정이 경로 지연과 무관해진다.
- **`ScreenUpdate`에 필드를 더하지 않고 message를 따로 두는 이유.** 에코가 없는 입력은 화면을 바꾸지 않아 갱신이 없다(§18.5). 판정이 가장 필요한 경우가 갱신이 없는 경우다. 또 `ScreenUpdate`의 정규 바이트는 hash와 묶여 있어 바꾸려면 새 capability가 필요하다(§18 머리). 상태 번호를 가리키는 작은 message 하나가 두 경우를 다 덮고 기존 부호화를 건드리지 않는다.
- **capability로 막는 이유.** 옛 client의 data 스트림 reader는 모르는 oneof를 건너뛰므로 받아도 깨지지 않는다. 그래도 §16.4의 규칙은 광고하지 않은 peer에게 새 message를 보내지 않는 것이고, client는 host가 신호를 보낼지 알아야 예측을 켤지 정할 수 있다.
- **termios를 읽는 이유.** 암호 입력은 거의 모두 `ECHO`를 끄고 `ICANON`을 켠 상태다(getpass, sudo, ssh). readline·zle·vim은 둘 다 끈다. host는 PTY master에서 이 비트를 읽을 수 있으므로 추측할 필요가 없다. mosh에는 이 신호가 없어 epoch 규칙만 쓴다. qsh는 두 겹을 쓰고, termios가 없는 Windows host에서는 epoch 규칙이 남는다.
- **예측을 `qsh-core`에 두는 이유.** 엔진은 화면 상태, 입력 offset, 정책 값, 연결 상태를 모두 읽고 판정 결과가 렌더러의 합성으로 간다. 이것은 frontend가 아니라 화면 모델의 일이고, `qsh-cli`에 두면 화면 로직이 frontend에 생긴다(`docs/design/architecture.md` §1의 층 규칙). 렌더러가 이미 `qsh-core`에 있으므로 겹침을 합성하는 자리도 거기다.
- **합성으로 그리는 이유.** 겹침을 `ClientScreen`의 상태에 쓰면 hash 대조가 틀리고 host와의 동기화가 깨진다. 렌더러는 이미 "로컬 터미널에 있는 것"과 "그려야 할 것"의 차이만 쓰므로, 그려야 할 것에 겹침을 더하고 빼는 것만으로 철회와 상태 줄 지우기가 된다. 새 그리기 경로가 필요 없고 M22의 로컬 터미널 모델 시험을 그대로 쓴다.
- **상태 줄 기준을 "답 없는 기다림"으로 두는 이유.** idle 셸은 5초마다 probe하므로 마지막 inbound가 5초 전인 것은 정상이다. 마지막 응답 시각만 보면 idle 셸에 줄이 깜빡인다. 보낸 것에 답이 없는 시간을 재면 idle에서는 뜨지 않고 타이핑 중에는 바로 뜬다. 2초 하한은 path 사망 감지(약 1초)와 재dial 예산(2초) 안에 끝나는 복구를 대개 보이지 않게 둔다.
- **늦은 확인 규칙을 엔진에 두는 이유.** `adapt::decide`는 연결 통계의 순수 함수이고(ADR-0052 결정 12), 키 하나의 확인 지연은 연결 통계가 아니다. srtt가 낮아도 손실 아래 꼬리가 생기므로, 정책 값을 바닥으로 두고 엔진이 관측한 지연으로 밑줄만 올린다. doctor와 `qsh::adapt`가 보이는 값은 정책 값 그대로다.

## 대안과 기각 사유

- **판정 신호 없이 시간 제한으로 걷어 낸다.** wire가 바뀌지 않지만 예측을 언제 걷을지가 경로 지연에 묶이고, 에코 없는 입력을 시간 제한만큼 그려 둔다. 기각(옛 host에서는 예측을 끈다, Dave가 정할 것 4).
- **`ScreenUpdate` 안에 `input_seq`를 넣는다.** 화면이 바뀌지 않는 입력을 판정하지 못하고 정규 바이트의 부호화를 바꾼다. 기각.
- **`InputAck`에 화면 상태 번호를 붙인다.** `InputAck`는 PTY에 쓴 시점에 나가므로 앱이 반응할 시간을 담지 못하고, 바이트 경로와 같이 쓰는 frame의 뜻이 갈린다. 기각.
- **에코를 시간이 아니라 "다음 PTY 출력"으로 판정한다.** 앱이 입력과 무관한 출력을 내면(시계, 진행 표시) 판정이 틀리고, 출력이 없으면 판정이 오지 않는다. 기각.
- **termios 없이 mosh처럼 epoch 규칙만 쓴다.** Windows host는 그렇게 된다. Unix host에서 확정 epoch 안에 나타난 암호 프롬프트를 첫 글자 전에 알 수 있는 길을 버릴 이유가 없다. 기각.
- **qsh-cli가 stdin을 보고 바로 로컬 터미널에 글자를 쓴다.** 왕복은 더 짧지만 렌더러가 터미널에 무엇이 있는지 잊어 셀 차이가 틀리고, 화면 로직이 frontend로 나간다. 기각.
- **위·아래 화살표, Tab, Enter도 예측한다.** 결과가 셸 기록과 완성 목록에 달려 있어 대개 틀리고, 틀린 예측의 철회가 여러 행에 걸친다. Enter는 epoch를 끊는 쪽이 암호 보호의 바탕이기도 하다. 기각.
- **대체 화면(vim 입력 모드 등)에서도 예측한다.** 전체 화면 앱은 커서를 자주 옮기고 자기 방식으로 다시 그려 오예측이 잦다. ADR-0050 M23 행이 전체 화면 앱에서 끈다고 정했다. 기각.
- **상태 줄을 stderr 한 줄로 쓴다.** 화면 경로에서는 렌더러가 로컬 터미널 전체를 쥐고 있어 그 줄이 다음 그리기에 덮이거나 셀 차이를 어긋나게 한다. 기각.
- **바이트 경로에도 상태 줄을 띄운다.** 겹칠 화면 모델이 없어 PTY 바이트 사이에 우리 바이트를 끼우면 앱의 화면을 망가뜨린다. 바이트 경로는 지금 동작 그대로 둔다. 기각.

## 결과

- 개정할 문서: `docs/design/protocol.md` §4(`screen-echo.v1`), §9(`ScreenEcho`, `TtyEcho`, `SessionFrame` 10), §18.6(종류 13), 새 §18.12(입력 반영 지점: 뜻, 보내는 때, 운반체, tty 판정, client 검사), §18.10(겹침 합성과 상태 줄). `docs/design/architecture.md`(client 화면 모델 옆의 `Predictor`, `LinkStatus`). `docs/design/testing.md` L2·L4·L8. `docs/CLI.md` §7, §6.23, §6.17. ADR-0052 결정 12 (d)와 결정 15에 이 ADR을 가리키는 개정 이력 줄을 더한다. `fuzz/README.md`.
- 새 threat model 행:
  - 정보노출: 예측이 로컬 화면에 그리는 사용자 입력. `tty = SECRET`과 임시 epoch가 암호를 그리지 않고, 예측 셀은 스크롤백에 남지 않는다. `qsh::predict`는 개수와 사유만 담는다.
  - 적대적 host의 `ScreenEcho`: 바꿀 수 있는 것은 사용자 자신의 입력이 보이는 시점뿐이다. 보낸 offset을 넘는 값은 버리고 센다.
  - 자원: 예측 256개, 보류 `ScreenEcho` 하나, host 입력 시각 표 64개. 상한 시험.
  - 파서 표면: `ScreenEcho` decode(기존 두 타깃)와 `client_predictor` 타깃.
- 남는 위험:
  - Windows host는 termios가 없어 암호 보호가 epoch 규칙뿐이다. 확정 epoch 안에서 커서를 옮기지 않고 나타나는 비밀 입력(드물다)은 첫 글자가 한 번의 판정까지(대략 RTT + `ECHO_GRACE`) 보일 수 있다.
  - Unix host에서도 앱이 `ECHO`를 끄기 전에 사용자가 미리 친 글자(type-ahead)는 확정 epoch에 있으면 그려질 수 있다. 프롬프트가 커서를 옮기면 epoch가 끊기므로 대개 막힌다.
  - 폭 판정이 host 에뮬레이터와 로컬 터미널에서 다르면 그 행의 예측이 틀리고 걷힌다(ADR-0052의 남는 위험과 같다).
  - Enter 뒤 첫 글자는 한 RTT를 기다린다(임시 epoch의 대가).
- 크기: ADR-0050의 3ew에 역방향 route의 RTT 표본과 Windows ConPTY 확인이 더해져 추정 3.5ew로 고친다. 스텝 순서는 `Predictor`와 표 테스트, proptest(wire 없이 가짜 `ScreenEcho`로) → 렌더러 합성과 로컬 터미널 모델 시험 → `screen-echo.v1`·`ScreenEcho`와 host 입력 시각 표, tty 판정, fuzz → attach driver 연결과 정책 값, 늦은 확인 → `LinkStatus`와 상태 줄, 역방향 → 플래그·설정 키·doctor·`qsh::predict` → 수용 시험(chaos, 세 OS, Windows host) → 문서·man·threat model 순이다. 계약·wire를 건드리는 스텝은 이 ADR이 승인되기 전에 열지 않는다(ADR-0050 결정 7). 앞의 두 스텝은 wire 없이 열 수 있다.

## 개정 이력

- 2026-11-07 초안(에이전트). Dave가 정할 것 네 항목은 추천만 적었다.
