# ADR-0033: 세션 및 audit 관리 개선은 세션 목록 필터와 읽기 전용 로컬 `qsh audit`까지로 하고, audit 삭제 경로와 텔레메트리 계약 승격은 만들지 않는다

날짜: 2026-10-11
상태: 제안됨

개정 관계: 새 ADR이다. `docs/PRD.md` §7 P1의 "세션 및 audit 관리 개선"은 항목 이름만 있고 범위가 없었다. `docs/ROADMAP.md` M17 (d)가 범위 ADR을 요구하고, 이 문서가 그것이다. `docs/CLI.md` §2.4(operation 이름 목록), §2.5(인가 불요 행), §6.2(세션 조회)를 개정하고 새 절을 하나 더한다. `crates/qsh-core/src/telemetry.rs` 모듈 doc의 "That promotion is a P1 decision"을 이 ADR의 결정으로 닫는다. 다른 ADR을 개정하지 않는다.

## 맥락

PRD가 이 항목에 붙인 이름은 둘, 세션 관리와 audit 관리다. 오늘의 표면은 이렇다.

- 세션은 `qsh sessions [host]`(`session.list`)가 전부 돌려주고, 거르는 방법이 없다. 목록은 호스트 쪽에서 ACL `session.list` 범위로 만들어지며, 다른 장비가 연 세션도 함께 보인다. 다만 attach는 세션을 연 장비에서만 된다(`docs/CLI.md` §6.2). 그래서 "내가 다시 붙을 수 있는 세션"과 "그냥 보이는 세션"이 한 표에 섞인다.
- audit은 `$XDG_STATE_HOME/qsh/audit.log`의 JSONL 파일이고, 읽는 명령이 없다. 운영자는 파일을 직접 `grep`/`jq`한다. 회전은 `[audit].max_bytes`(기본 64 MiB)와 `[audit].retain`(기본 5)이 정하고, 오래된 회전분은 개수 상한으로 지워진다(`docs/design/architecture.md` §6·§7, ADR-0010).
- 텔레메트리는 `qsh::recovery` 등 stderr의 단일 줄 JSON이고 `qsh.event/v1`이 아니다. 모듈 doc은 계약으로 올리는 것을 "P1 결정"으로 남겼다.

설계를 가르는 사실은 이렇다.

- 원격에서 부를 수 있는 조회는 열거 oracle이다. ADR-0022 결정 4가 역방향 등록 조회에, ADR-0025 결정 4가 `acl.show`에 같은 이유로 "인가 불요 local op, wire 메시지 없음"을 적었다. audit은 어느 principal이 언제 무엇을 시도했고 거부됐는지를 담으므로 정찰 값이 정책 조회보다 낮지 않다.
- audit의 존재 이유는 SC6 추적성이다. `docs/ROADMAP.md` M15 범위의 `file.write` 대상 거부 결정이 audit 경로를 원격 쓰기에서 항상 막는 것도 같은 이유다. 지우거나 줄이는 경로가 원격에 하나라도 생기면 "모든 privileged op이 흔적을 남긴다"는 성질이 약해진다.
- `AuditRecord`는 타입에 payload를 실을 자리가 없다(`docs/design/threat-model.md` F2). 필드는 `ts`, `request_id`, `principal`, `action`, `resource`, `decision`, `rule`, `auth_path`, `peer_addr`, `count`다. 조회 출력이 이 집합을 넘으면 F2의 성질이 조회 쪽에서 깨진다.
- audit writer는 fail-closed이고 큐 포화나 디스크 만실이면 인가 자체가 거부된다(`architecture.md` §6, threat-model C8). 그 상태에서 운영자가 가장 먼저 필요한 것이 audit 조회다.
- 로컬 op 중 audit을 남기는 것은 `trust.rename`과 `service.install`/`uninstall`뿐이고(F5), 나머지 trust 조작이 audit을 남기지 않는 것은 별도 잔여 위험이다(threat-model h26). 이 ADR의 범위가 아니다.

## 결정

범위는 네 가지다. 세션 목록 필터(1~3), audit 조회(4~9), retention(10~11), 텔레메트리 승격 여부(12).

1. `qsh sessions`에 필터 `--state <값>`, `--writer <principal|none>`, `--attachable`을 더한다. 여러 개를 주면 AND다. `--state`는 §5 Session의 `state`(열린 문자열)와 정확 일치하고, 모르는 값은 오류가 아니라 빈 결과다. `--writer none`은 `writer: null`을 가리킨다. `--attachable`은 이 장비의 resume 상태 파일에 그 세션의 credential이 있는 세션만 남긴다(attach가 `no_resume_token`으로 실패하지 않을 세션).

2. 필터는 클라이언트 `Ops`가 호스트의 응답을 받은 뒤 적용한다. `SessionListReq`와 wire 메시지는 바뀌지 않고, 호스트가 돌려주는 집합은 오늘의 ACL `session.list` 범위 그대로다. 필터는 보이는 것을 줄일 뿐 넓히지 않으므로 인가 모델을 건드리지 않는다. host 없는 fan-out(`data.unreachable`)의 의미도 그대로다. 필터가 모든 세션을 걸러내도 도달 실패는 가려지지 않는다.

3. 필터 결과의 JSON 모양은 `{"sessions": […]}`로 같고 새 필드를 더하지 않는다. human 렌더는 필터가 걸려 있을 때 stderr에 "N개 중 M개 표시" 한 줄을 낸다(§2.2의 stdout 순수성). `--attachable` 판정은 `session_ref`당 한 번 상태 파일을 읽는 것이고 token 값은 어디에도 싣지 않는다(ADR-0007).

4. audit 조회는 새 op `audit.query`이고 CLI는 `qsh audit`이다. 인가 불요 local operation이다. 원격 peer가 요청할 수 없고 wire 메시지를 만들지 않는다. `docs/CLI.md` §2.4 목록과 §2.5 "인가 불요" 행에 `audit.query`를 `acl.show` 옆에 더하며, 원격에서 부를 수 있으면 곧 열거 oracle이 된다는 이유를 ADR-0022 결정 4·ADR-0025 결정 4와 같은 문장으로 적는다. 이 op은 ACL action을 새로 요구하지 않는다. `qsh-proto`의 프레임 enum에도 대응하는 variant가 없고, localctl 데몬의 UDS 요청으로도 노출하지 않는다.

5. 인자는 `--since <RFC3339|N[smhd]>`, `--until <RFC3339>`, `--principal`, `--action`, `--resource`, `--decision <allow|deny>`, `--limit <N>`이다. 문자열 필터는 정확 일치이고 여러 개는 AND다. `--limit`의 기본은 100, 최대는 1000이며 넘으면 `INVALID_ARGUMENT`다. 결과는 최신이 먼저다. `--follow`는 두지 않는다.

6. 조회는 활성 로그와 보관된 회전분을 모두 읽고(개수는 `[audit].retain`이 정한다), 읽기만 한다. writer의 파일 락을 잡지 않고, torn write 복구(`RotatingAuditSink`의 절단)를 흉내 내지 않으며, 어떤 파일도 열기 모드로 쓰지 않는다. 파싱되지 않는 줄(쓰는 도중이거나 잘린 줄)은 건너뛰고 그 수만 센다. 줄의 내용은 오류에도 출력에도 싣지 않는다. 로그 파일이 없으면 오류가 아니라 빈 결과다. 읽을 수 없으면(권한 거부, I/O) `INTERNAL`이고 메시지에 경로와 오류 종류만 싣는다.

7. 조회는 audit 레코드를 남기지 않는다. 이유는 둘이다. 읽기가 로그를 키우면 조회를 반복하는 것만으로 회전과 retention이 밀리고, audit이 degraded(큐 포화·디스크 만실)로 latch된 상태에서는 fail-closed 규칙 때문에 조회 자체가 거부돼 가장 필요한 순간에 쓸 수 없게 된다. `acl.show`와 `acl.check`가 읽기라서 audit을 쓰지 않는 선례와 같다.

8. 출력은 기존 구조 필드만 싣는다. `qsh-proto`에 `AuditRecordView`(`ts`, `request_id`, `principal`, `action`, `resource`, `decision`, `rule`, `auth_path`, `peer_addr`, `count`)를 두고, `qsh-core`의 `AuditRecord`에서 필드 단위로 옮긴다. 필드 집합이 같음을 테스트가 고정한다(F2의 확장). 새 필드를 만들지 않고, `resource`는 이미 저장된 구조적 식별자 그대로 보이며 가공이나 보강(DNS 역조회, 이름 해석)을 하지 않는다.

9. `data`의 모양은 `{"records": [AuditRecordView, …], "skipped_lines": N, "oldest_ts": "…"|null, "truncated": bool}`이다. `oldest_ts`는 읽은 파일 전체에서 가장 오래된 레코드의 `ts`로, 운영자가 이 호스트의 보존 지평을 읽는 수단이다. `truncated`는 `--limit` 때문에 더 있는 레코드가 잘렸을 때 `true`다. 지원 출력 모드는 human과 `--json`이다.

10. audit 레코드를 지우거나 줄이는 op은 만들지 않는다. 원격 op은 말할 것도 없고 로컬 `qsh audit` 하위의 삭제·축약·압축도 없다(SC6 추적성). 오늘의 개수 기반 회전·retention이 유일한 삭제이고, `[audit].max_bytes`·`retain`의 의미와 기본값은 바뀌지 않는다. 시간 기반 retention(N일 지난 레코드 삭제)은 만들지 않는다. 더 긴 보존이 필요하면 회전분이 밀리기 전에 운영자가 qsh 밖에서 복사한다. 이 사실을 `docs/CLI.md` 새 절이 적는다.

11. retention 가시성은 결정 9의 `oldest_ts`로 갈음하고 새 doctor finding은 만들지 않는다. `audit_path_unwritable`(기존)이 쓰기 실패를 이미 잡는다.

12. 텔레메트리 줄(`qsh::recovery`)은 `qsh.event/v1`로 올리지 않는다. stderr의 단일 줄 JSON으로 남는다. 이 ADR이 승인되면 `telemetry.rs` 모듈 doc의 "That promotion is a P1 decision"을 "ADR-0033 결정 12가 승격하지 않기로 했다"는 인용으로 바꾼다. 재검토 조건은 저장소 안의 소비자가 stderr grep 대신 구조화된 스트림을 필요로 한다고 관측된 때이고, 그때는 ADR-0022 결정 3이 역방향 health에 둔 순서(필요가 관측된 뒤 `qsh.event/v1`에 additive로 연다)를 따른다. 다른 stderr 진단 줄(`qsh::lifecycle`, `qsh::reverse`, `qsh::tunnel::supervise`)은 이 ADR이 건드리지 않는다.

## 근거

세션 필터를 클라이언트에서 적용하는 이유는 호스트가 보내는 집합이 ACL이 이미 정한 범위이기 때문이다. 호스트에서 거르면 `SessionListReq`를 바꿔야 하고, 필터를 인식하는 호스트와 못 하는 호스트가 섞인 fleet에서 같은 명령의 결과가 달라진다. 클라이언트 적용은 어느 호스트에도 같은 의미이고 additive 규칙 안에 머문다. `--attachable`은 유일하게 클라이언트 쪽에만 있는 사실(resume credential 보유)을 쓰는 필터라서, 서버 필터로는 만들 수도 없다.

audit 조회를 로컬로 못 박는 이유는 `acl.check`·`acl.show`와 같다. 원격에서 남의 audit을 열람할 수 있으면 principal과 거부 이력이 곧 정책 열거 수단이 된다. 로컬 사용자는 이미 같은 계정으로 파일을 읽을 수 있으므로 로컬 op은 새 능력을 주지 않고 `grep`을 계약된 모양으로 옮길 뿐이다. 그래서 이 op은 인가 모델의 바깥이 아니라 "파일을 이미 읽을 수 있는 사람에게 같은 내용을 구조화해서 주는" 위치에 있다.

조회가 audit을 쓰지 않는 결정은 fail-closed 위에서 일관된다. 쓰기 경로가 막힌 상태에서도 읽기가 되어야 운영자가 원인을 본다. 읽기에 락과 복구를 붙이지 않는 것도 같은 방향이다. 복구는 writer의 일이고, 읽기가 파일을 고치기 시작하면 "읽기 전용"이라는 성질이 사라진다.

삭제 경로를 만들지 않는 것은 SC6의 정의에서 나온다. 압축이나 시간 기반 삭제는 "운영자 편의"로 보이지만, 로컬이라도 qsh가 audit을 지우는 명령을 갖는 순간 그 명령을 원격에서 부르게 만드는 다음 변경이 한 걸음 거리가 된다. 지금의 개수 기반 회전은 디스크 예산을 유계로 만들려는 필요(ADR-0010)에서 생긴 하나의 예외이고, 이 ADR은 그 예외를 넓히지 않는다. `oldest_ts`가 그 예외의 효과를 운영자에게 보이게 한다.

텔레메트리를 승격하지 않는 것은 모듈 doc 자신의 이유("아직 모양을 배우는 중인 필드 집합을 얼린다")가 아직 유효해서다. 이 줄을 읽는 쪽은 M8 캠페인 스크립트처럼 stderr를 `grep`하는 사람이고, 구조화 스트림을 필요로 하는 저장소 내 소비자는 관측되지 않았다. `qsh.event/v1`은 additive-only라서 한 번 올리면 되돌릴 수 없다.

## 대안과 기각 사유

- 세션 필터를 호스트에서 적용한다(`SessionListReq`에 필터 필드). 기각한다. 결정 2의 이유 외에도 wire 변경이 필요하고, `--attachable`은 서버가 알 수 없다.
- `qsh audit`을 원격 호스트에도 부를 수 있게 한다(`qsh audit <host>`). 기각한다. 결정 4의 이유 그대로 열거 oracle이다. 원격 호스트의 audit이 필요한 운영자는 그 호스트에 로그인해 거기서 `qsh audit`을 친다. 관리 편의를 원하는 사람은 새 ACL action을 만들자고 할 수 있지만, 그것은 ADR-0022·ADR-0025가 닫은 판단을 뒤집는 별도 ADR의 일이다.
- 조회가 자기 자신을 audit에 남긴다. 기각한다. 결정 7의 이유다. "누가 audit을 읽었는가"가 필요해지면, 로컬 사용자가 이미 파일을 읽을 수 있다는 사실(OS 권한이 경계)과 맞지 않는다는 점을 먼저 풀어야 한다.
- `qsh audit prune`/`export --delete` 같은 로컬 정리 명령. 기각한다. 결정 10의 이유다.
- 시간 기반 retention(`[audit].retain_days`). 기각한다. 레코드 삭제 규칙이 하나 더 늘고, 두 규칙의 상호작용(회전분 개수와 일수)이 SC6 판단을 복잡하게 한다. 현재 개수 기반은 `max_bytes × (retain + 1)`로 총량이 유계다.
- 새 doctor finding(`audit_retention_short` 등)을 추가한다. 기각한다. 짧다/길다의 임계가 임의적이다. 사실(`oldest_ts`)을 보이고 판단은 사람이 하게 한다.
- 텔레메트리 줄을 `qsh.event/v1`로 올린다. 이번에는 채택하지 않는다. 결정 12의 이유다. 소비자가 관측되면 additive로 올린다.
- 조회 출력에 `peer_addr`의 역조회, principal 별칭 해석, `resource`의 호스트 이름 보강을 넣는다. 기각한다. 결정 8이 새 정보를 만들지 않는 조회를 요구하고, 보강은 조회 시점의 상태(trust store)에 따라 같은 레코드가 다르게 보이게 만든다.

## 결과

- 계약 문서: `docs/CLI.md` §2.4·§2.5에 `audit.query`가 오르고, §6.2에 필터 세 개의 서술이 들어가며, `qsh audit`의 새 절(§6.20 뒤에 붙는다. ADR-0029의 `qsh file` 절도 같은 자리를 쓰므로 번호는 착륙 순서대로 구현 때 매긴다)이 서고, 버전 헤더가 갱신된다. `docs/design/threat-model.md`에 새 진입점 행(`qsh audit`, 로컬 읽기, 열거 oracle 방지)과 F2의 필드 전수 테스트 확장이 오른다. `cargo xtask man`으로 `qsh-audit.1`이 생기고 `qsh-sessions.1`이 바뀌며, `checked_in_man_pages_match_the_generator`가 확인한다.
- 고정할 테스트(이름은 구현 때 확정):
  - 분류: `crates/qsh-core/tests/op_registration_completeness.rs`와 `crates/qsh-core/tests/acl_registry.rs`가 `audit.query`를 local-only로 분류하고, 프레임 enum에 대응 variant가 없음을 단언한다(M17 DoD (d)).
  - `audit_query_has_no_wire_message_and_no_localctl_request`, `audit_record_view_fields_equal_audit_record_fields`.
  - `audit_query_reads_active_and_rotated_files_newest_first`, `audit_query_filters_are_and_combined`, `audit_query_limit_above_the_cap_is_invalid_argument`.
  - `audit_query_skips_a_torn_line_and_counts_it_without_echoing_it`, `audit_query_does_not_modify_the_log`(바이트 단위 불변), `audit_query_works_while_the_audit_sink_is_degraded`, `audit_query_writes_no_audit_record`, `audit_query_on_a_missing_log_is_empty_not_an_error`.
  - `audit_query_oldest_ts_matches_the_oldest_retained_record`.
  - 삭제 부재: audit 로그를 수정하는 op이 `ops/` 아래에 `audit.query` 말고 없음을 단언하는 분류 테스트 한 건(SC6).
  - 세션: `sessions_filter_state_writer_attachable_and_combined`, `sessions_filter_does_not_change_the_wire_request`, `sessions_filter_keeps_unreachable_in_fan_out`, `sessions_attachable_never_prints_the_resume_token`.
  - 텔레메트리: `telemetry.rs` 모듈 doc의 인용 갱신 외에 코드 변화가 없다.
- fixture: `crates/qsh-cli/tests/fixtures/cli-v1/`에 `audit.query` 성공 envelope(비어 있지 않은 것과 `truncated: true`인 것)과 필터를 건 `session.list` 하나를 append하고 `REQUIRED_FIXTURES`에 등록한다. 기존 fixture는 바뀌지 않는다. `qsh.cli/v1`은 additive만이고 `ErrorCode`와 wire 프로토콜은 변하지 않는다. `qsh-proto`에 타입이 하나 늘고 스키마(`schema.get`)에 반영된다.
- 아키텍처 규칙: 조회 로직과 필터는 `qsh-core`의 `Ops`에 두고, `qsh-cli`는 clap과 렌더만 갖는다. 새 의존 방향은 없다.
- 크기는 ADR 0.2~0.3ew에 구현이 약 1.2~1.8ew다(ROADMAP은 구현 미산정이라 이 문서가 처음 매긴 값이다). 내역은 `audit.query`(읽기, 필터, proto 타입, CLI, 문서, fixture, 테스트) 0.9~1.3, 세션 필터 0.3~0.5, 텔레메트리 인용 갱신 0.05다.
- 이 ADR이 `승인됨`이 되면 M17 (d)의 착수 조건이 풀린다. 범위 밖으로 남는 것은 h26(trust 조작의 audit 소급 확장)과 세션 상태의 영속화(`docs/ROADMAP.md` M18)다.
