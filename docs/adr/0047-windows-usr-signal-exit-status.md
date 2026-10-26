# ADR-0047: Windows host에서 USR1·USR2 뒤 스스로 끝난 세션은 종료 코드를 싣는다

날짜: 2026-10-26
상태: 승인됨 (2026-10-26, 사용자 결정 "unix에 맞춤")

개정 관계: ADR-0035 결정 22의 종료 상태 항목("qsh가 위 사상으로 보낸 사건 뒤에 세션이 끝났으면 `signal`에 그 단계의 신호 이름을 싣는다")을 `Usr1`·`Usr2`에 한해 바꾼다. 일곱 신호 각각의 첫 단계, escalation, 이름 있는 이벤트의 이름·DACL·환경변수는 그대로다. `docs/CLI.md` §6.4의 "`exit_code`와 `signal`은 둘 중 하나만 채워진다"도 그대로다.

## 맥락

ADR-0035 결정 22는 Windows host가 신호 대신 사건을 보내고, 그 사건 뒤에 세션이 끝나면 `session.exit`의 `signal`에 그 단계의 신호 이름을 싣게 했다. ConPTY 백엔드는 프로그램의 종료 코드와 마지막으로 보낸 단계의 신호를 함께 broker에 넘긴다. client의 `Ops` 계층은 §6.4대로 `signal`이 있으면 `exit_code`를 비운다.

2026-10-26 캠페인 W2 L(`docs/campaigns/p1-windows.md` §4.12 f, v0.5.4)에서 `QSH_SIGNAL_EVENT_USR1` 이벤트를 기다렸다가 `got-usr1`을 찍고 스스로 0으로 끝나는 PowerShell 세션에 `session close --signal USR1`을 보냈다. 세 번 모두 `session.exit`는 `"exit_code":null,"signal":"SIGUSR1"`이었다.

같은 프로그램을 unix host에서 돌리면 SIGUSR1 처리기가 신호를 받고 프로그램이 `exit 0`으로 끝나므로 `waitpid`는 정상 종료를 돌려주고, `session.exit`는 `"exit_code":0,"signal":null`이다. 두 OS가 같은 프로그램 모양에 다른 답을 낸다. 회차 기준 f는 `exit_code` 0과 `SIGUSR1`을 함께 요구했는데, 이는 §6.4의 배타 규칙 때문에 어느 구현으로도 나올 수 없다.

`Int`·`Quit`·`Hup`·`Term`·`Kill`의 사건은 처리기가 없는 프로그램을 끝낸다. unix에서 처리기 없는 프로세스가 신호로 죽는 것과 같은 자리라서, 그 뒤의 종료에 신호 이름을 싣는 것은 결정 22의 의도대로다. `Usr1`·`Usr2`의 `SetEvent`는 어떤 프로그램도 끝내지 못한다. 이 사건 뒤에 세션이 끝났다면 언제나 프로그램이 이벤트를 받아 스스로 끝낸 것이고, unix로 치면 처리기가 있는 경우다.

## 결정

1. Windows host에서 세션의 자식이 끝났을 때 qsh가 마지막으로 전달한 단계가 `Usr1`이나 `Usr2`면, 종료 상태는 프로그램 자신의 것이다. `exit_code`에 종료 코드를 싣고 `signal`은 비운다.
2. `Usr1`·`Usr2` 뒤 유예 안에 끝나지 않아 escalation이 `Hup`(의사 콘솔 닫기)이나 `Kill`을 보냈으면 마지막 단계는 그것이므로 지금처럼 `SIGHUP`·`SIGKILL`이 실린다.
3. `Int`·`Quit`·`Hup`·`Term`·`Kill` 뒤의 종료는 결정 22 그대로 그 단계의 신호 이름을 싣는다.
4. wire `Exit`, `qsh.event/v1`, `qsh.cli/v1`의 모양은 바뀌지 않는다. 값의 조합도 §6.4가 이미 허용하는 것(정상 종료)이다.

## 근거

- 같은 프로그램이 같은 신호를 받고 같은 방식으로 끝났을 때 두 host OS가 같은 `session.exit`를 내야 agent가 OS를 가리지 않고 스크립트를 쓸 수 있다.
- `signal`은 소비자에게 "프로세스가 신호로 끝났다"는 뜻이다(§6.4, 대화형 종료 코드 `128 + signo`, §6.1). 끝낼 수 없는 사건에 그 이름을 다는 것은 이 뜻과 어긋난다.
- 프로그램이 이벤트를 받았다는 증거는 프로그램 자신의 출력과 종료 코드가 남긴다. escalation 전에 끝났다는 것은 `signal`이 `null`이고 `SIGHUP`·`SIGKILL`이 아니라는 것으로 드러난다.

## 대안과 기각 사유

- 동작은 두고 회차 기준만 `exit_code` null·`SIGUSR1`로 고친다. 비용은 가장 작지만 두 OS의 차이가 계약에 남는다. 사용자가 기각했다.
- `exit_code`와 `signal`을 함께 싣는다. §6.4의 배타 규칙을 바꾸는 계약 변경이라 `/v2` 없이는 할 수 없다.
- `Int`·`Quit`도 종료 코드로 판정한다(`STATUS_CONTROL_C_EXIT`면 `SIGINT`, 아니면 종료 코드). 처리기 유무를 종료 코드로 추정하는 것이라 프로그램이 그 값을 직접 돌려주면 틀린다. 이 ADR의 범위 밖이다.

## 결과

- 바꾸는 파일: `crates/qsh-core/src/pty/conpty.rs`(종료 상태 조립)와 그 Windows 테스트, `docs/CLI.md` §6.7 Windows host 문단, ADR-0035 개정 이력, `docs/campaigns/p1-windows.md` §4.12 f의 기준, `RELEASE-NOTES.md`의 다음 태그 절.
- 이 수정이 담긴 태그 전의 W2 f 행은 USR1 항목에서 기준과 다르다. 그 행은 비고에 이 ADR을 적고 새 태그로 f를 다시 돈다.
