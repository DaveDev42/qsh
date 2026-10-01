# ADR-0027: `qsh doctor --fail-on <warn|error>`는 임계 이상 finding이 있으면 envelope을 그대로 둔 채 exit만 `1`로 바꾼다

날짜: 2026-10-01
상태: 승인됨 (2026-10-01 사용자 확정)

개정 관계: 새 ADR이다. `docs/adr/README.md`의 예약 목록이 P1 계획(`docs/ROADMAP.md` §5) 시점에 이 번호를 `doctor --fail-on`의 exit 규칙 자리로 잡아 두었고, 이 문서가 그 자리를 채운다. 계약 문서로는 `docs/CLI.md` §4의 일반 명령 exit 표에 행 하나를 더하고 §6.17의 두 문단을 고친다. 다른 ADR을 개정하지 않는다.

## 맥락

`docs/CLI.md` §6.17은 `qsh doctor`의 exit code를 "항상 `0`"으로 못박는다. finding은 data이지 실패가 아니라는 이유이고, `qsh acl check`가 `deny`에도 exit `0`을 내는 선례(§6.15)를 넓힌 것이다. 건강도는 `data.overall`이 `"ok"`/`"warn"`/`"error"`로 담는다. doctor 자신이 조회를 시작하지 못할 때(identity가 없거나 `config.toml`·`hosts.toml`·`trust.toml`이 파싱되지 않을 때)만 `Err`와 exit `255`로 끝난다. 같은 절 끝 문단은 "`--fail-on` 플래그는 아직 없다"고 적고 그것을 향후 additive 확장 후보로 남겼다.

지금 CI나 배포 스크립트가 doctor를 게이트로 쓰려면 stdout JSON을 받아 `data.overall`을 직접 읽어야 한다. 셸 한 줄로 끝날 일에 JSON 파서가 끼는 셈이다. `docs/ROADMAP.md` M13 범위 (d)는 이 플래그를 넣되, 임계를 넘었을 때의 exit 값이 §4 표를 건드리는 계약 결정이므로 ADR로 먼저 정하라고 적는다.

설계를 가르는 사실은 이렇다.

- §4 일반 명령 표에 있는 값은 `0`, `2`, `255` 셋뿐이다. `2`는 clap의 CLI syntax·argument 오류이고 `255`는 "연결, 인증, 정책 등 QSH runtime 실패"다. `qsh exec`와 대화형 세션은 원격 exit code `0..=254`를 그대로 넘기지만, 그것은 원격 프로세스의 값이지 qsh가 매기는 값이 아니다. `crates/qsh-cli/src`에는 `1`을 직접 내는 경로가 없다.
- envelope의 `ok`는 operation이 성공했는지를 말하고, `ok: false`는 `ErrorCode` enum(`qsh-proto`)의 값 하나를 `error.code`로 요구한다(§3.2). doctor의 finding 어휘(`EXPECTED_DOCTOR_CODES`, 23종)는 `ErrorCode`가 아니다.
- `DoctorFinding.status`는 `"warn"`/`"error"`/`"info"` 셋이다. `"info"`는 구조적 고지다. `trust_remove_scope`는 pin이 하나라도 있으면 늘 뜨고 `service_not_registered`는 유닛이 없는 머신이면 늘 뜬다. `data.overall`도 `"info"`를 `"ok"`로 접는다.
- §4 마지막 문단은 출력 모드에 따라 exit 의미가 달라지면 안 된다고 적고, `crates/qsh-cli/tests/exit_code_matrix.rs`가 그 문장을 두 출력 모드의 표 테스트로 고정한다.

## 결정

1. `qsh doctor`에 `--fail-on <warn|error>`를 additive로 더한다. 주지 않으면 exit code와 stdout이 오늘과 바이트 단위로 같다. 이 플래그가 바꾸는 것은 프로세스 exit 하나이고 조회 동작, finding 집합, 렌더 결과는 바꾸지 않는다.

2. 임계 어휘는 `warn`과 `error` 둘이다. `--fail-on warn`은 `status`가 `"warn"`이나 `"error"`인 finding이 하나라도 있으면, `--fail-on error`는 `"error"`인 finding이 하나라도 있으면 걸린다. 순서는 `data.overall`이 이미 쓰는 `"error"` > `"warn"`을 그대로 따른다. `info`와 그 밖의 값은 clap이 exit `2`로 거절한다. `info`를 받지 않는 이유는 위 맥락대로 `"info"` finding이 상시 고지라서, 임계로 받으면 대부분의 머신에서 게이트가 늘 붉기 때문이다.

3. 임계에 걸리면 exit는 `1`이다. `docs/CLI.md` §4 일반 명령 표에 코드 `1`, 의미 "`qsh doctor --fail-on`의 임계 이상 finding이 있음(operation 자체는 성공)"인 행을 더한다. 이 값은 doctor의 `--fail-on` 경로에서만 쓴다.

4. 임계에 걸려도 envelope은 오늘과 같다. `ok: true`이고 `data.overall`과 `data.findings`를 빠짐없이 싣는다. `ok`는 operation의 성공을, exit `1`은 "조회는 성공했고 임계 이상 finding이 있다"를 말한다. 그래서 `ok: true`와 exit `1`의 조합은 정상이다. `ok: false`는 여전히 exit `255`와만 짝을 이룬다.

5. doctor가 조회를 시작하지 못하는 경우는 `--fail-on`과 무관하게 지금처럼 `Err`, `ok: false`, exit `255`다. 임계 판정은 조회가 성공한 뒤에만 한다. 그래서 exit `255`를 보면 "판정할 수 없었다", exit `1`을 보면 "판정했고 걸렸다"로 읽을 수 있다.

6. 출력 모드에 따라 이 규칙이 달라지지 않는다. human, `--json` 어느 쪽이든 같은 finding 집합에 같은 exit를 낸다(§4 마지막 문단).

7. JSON 모양은 바꾸지 않는다. 새 필드도 새 fixture도 없다. 임계 판정 함수(finding 목록과 임계를 받아 걸리는지 답하는 함수 하나)는 `qsh-core`에 두고, `qsh-cli`는 clap 정의와 그 답을 exit로 옮기는 매핑만 갖는다(`docs/design/architecture.md` §1).

## 근거

`1`은 §4 일반 명령 표에서 비어 있는 값이다. `0`, `2`, `255` 어느 것과도 겹치지 않고 qsh가 스스로 `1`을 내는 경로도 지금 없으니, 새 값의 뜻이 다른 신호와 섞일 일이 없다. 린터와 검사 도구가 "실행은 끝났고 문제를 찾았다"를 알릴 때 흔히 쓰는 값이기도 해서 CI 작성자는 문서를 찾지 않고도 뜻을 짐작한다. 무엇보다 `1`은 `255`와 떨어져 있다. 스크립트가 "doctor가 돌지 못했다"와 "doctor가 문제를 찾았다"를 exit만으로 가를 수 있어야 한다. 앞의 것은 설정 자체가 망가진 상태이고 뒤의 것은 조치할 finding이 있는 상태라 대응이 다르다.

envelope을 `ok: true`로 두는 이유는 §6.17이 세운 "finding은 data" 모델을 깨지 않기 위해서다. `ok: false`로 바꾸면 `error.code`에 `ErrorCode` 값이 하나 필요하고, 그러면 새 `ErrorCode`를 만들거나 뜻이 다른 기존 값을 빌려야 한다. 오류 envelope은 `data`를 싣지 않으므로(§3.2) finding 목록도 잃는다. 게이트에 걸린 CI는 그 목록부터 보고 싶어 한다.

## 대안

- 임계에 걸리면 exit `255`를 낸다. 기각한다. `docs/ROADMAP.md` M13 범위 (d)가 짚은 대로, `255`는 §4에서 "연결, 인증, 정책 등 QSH runtime 실패"라서 envelope이 `ok: true`인 채로 `255`를 내면 두 신호가 서로 다른 말을 한다. 스크립트는 doctor가 돌지 못한 경우와 finding이 있는 경우를 exit로 가를 수 없게 된다.
- 임계에 걸리면 `ok: false`와 오류 envelope을 낸다. 기각한다. 근거 절의 이유 그대로다. `ErrorCode`에 새 값이 필요하고 finding 목록이 `data`와 함께 사라진다. §6.17이 exit `0`을 고른 이유("아무리 심각한 finding이 나와도 조회 자체는 성공이다")와도 어긋난다.
- `1` 대신 다른 빈 값(예: `3`)을 쓴다. 채택하지 않는다. 겹침만 피한다면 어느 빈 값이든 결정 3의 성질을 갖지만 `1`만큼 널리 읽히는 관례가 없다. 사용자가 `1`이 셸 래퍼나 다른 도구의 일반 실패와 섞이는 것을 더 무겁게 본다면 이 안으로 바꿀 수 있다. 그때 바뀌는 것은 결정 3의 값과 §4 행 하나다.
- 심각도마다 다른 exit를 낸다(`warn`이면 `1`, `error`면 또 다른 값). 기각한다. 임계는 호출자가 이미 골랐으므로 exit가 한 번 더 심각도를 나눌 필요가 없다. 어느 finding이 걸렸는지는 stdout의 `findings`가 말한다. 값이 둘이면 §4 표에 두 행이 늘고 `2`(syntax 오류)를 피해 번호를 골라야 한다.
- `data.fail_on` 같은 echo 필드를 더해 이번 호출의 임계를 envelope에도 싣는다. 이번 결정에서는 넣지 않는다. additive 규칙 안이라 가능하지만 호출자는 자기가 준 임계를 이미 알고, 넣으면 새 fixture와 그것을 재현하는 `golden_*` 테스트가 따라온다. 판정 결과(걸렸는지)를 JSON만으로 읽어야 하는 소비자가 나타나면 그때 additive로 더한다.
- `info`도 임계로 받는다. 기각한다. 결정 2의 이유 그대로다. `trust_remove_scope`와 `service_not_registered`처럼 상시 뜨는 고지가 있어 게이트가 늘 붉고, 늘 붉은 게이트는 곧 무시된다.

## 결과

- `docs/CLI.md` §4 일반 명령 표에 `1` 행이 는다. §6.17의 "exit code는 항상 `0`이다" 문단에 `--fail-on` 예외를 한 문장 더하고, "`--fail-on` 플래그는 아직 없다" 문단을 결정 1~6의 동작 설명으로 바꾼다. 상태 헤더에 이 변경을 적는다.
- `crates/qsh-cli/tests/exit_code_matrix.rs`에 `--fail-on` 행이 는다. 기존 `Succeeds(i32)` 모양이 `ok: true`와 0이 아닌 exit를 이미 표현하므로 표의 틀은 바뀌지 않는다.
- clap 트리가 바뀌므로 `cargo xtask man`으로 `docs/man/qsh-doctor.1`을 다시 만들고, `checked_in_man_pages_match_the_generator`가 그 diff를 확인한다.
- `crates/qsh-cli/tests/fixtures/`는 바뀌지 않는다. 기존 doctor fixture는 `--fail-on` 없는 호출이라 결정 1대로 바이트가 같다.
- `qsh.cli/v1`, `ErrorCode`, wire 프로토콜에 변화가 없다. `docs/design/protocol.md` §16의 동결 대상에 걸리는 항목도 없다.
- 결정 3의 `1`이 승인 과정에서 다른 값으로 바뀌면 구현 쪽 테스트 이름에 들어간 값도 같이 바꾼다.
- 이 ADR이 승인되면 `docs/ROADMAP.md` M13 착수 조건의 (d) 항목이 풀린다.
