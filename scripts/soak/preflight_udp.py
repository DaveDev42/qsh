#!/usr/bin/env python3
"""preflight_udp.py — loopback UDP 차단 구간 사전 점검.

scripts/soak/run.sh가 24h soak을 시작하기 전에 부른다. 목적은 run #5가
겪은 실패를 되풀이하지 않는 것이다. 그 회차는 제품 결함이 아니라 호스트
nftables 규칙(`inet dave_mosh`, `udp dport 60000-61000 drop`, loopback
예외 없음)이 원인이었다 — 판정 근거 다섯 갈래는
docs/campaigns/m8-soak.md §8 "run #5 결과"에 있다. 같은 종류의 규칙이
남아 있으면 24시간을 태우기 전에 여기서 잡는다.

점검 방법은 실제 송수신이다. `/proc/sys/net/ipv4/ip_local_port_range`가
알려주는 ephemeral 범위 전체에서 포트를 고르게 뽑고, 그 포트에 소켓을
bind한 뒤 127.0.0.1로 UDP 한 조각을 보내 받아 본다. nft나 iptables 규칙을
읽지 않는다 — 방화벽 구현이 무엇이든, 정책을 몰라도 실제 왕복이 되는지만
본다. 권한도 필요 없다.

샘플링 간격 계산. 범위 크기를 R, 표본 수를 N이라 하면 양 끝을 포함해
고르게 N개 뽑았을 때 인접 표본 간격은 gap = ceil(R / (N-1))이다. 길이가
gap 이상인 연속 차단 구간은 이 균등 grid를 반드시 하나는 물기 때문에
(비둘기집 원리), 표본 위치가 무작위가 아니라 균등하다는 전제 아래 "높은
확률"이 아니라 "gap 이하로 좁은 구간은 놓칠 수 없다"는 확정 진술이다.
STRIDE_TARGET_PORTS를 300으로 두면 흔한 Linux 기본 ephemeral 범위
(32768-60999, R=28232)에서 gap이 300 안팎(표본 약 96개)으로 나오고, run
#5가 실제로 겪은 약 1000포트 차단 구간(60000-61000)을 잡을 확률은 1.0
(확정)이다 — 3배 넘는 여유다. 어느 호스트가 ephemeral 범위를 극단적으로
넓게 잡아 MAX_SAMPLES 상한에 걸리면 gap이 1000을 넘을 수 있고, 그때는
무작위 정렬을 가정한 근사치 min(1.0, 1000/gap)로 낮아진 확률을 같이
찍는다(아래 catch_probability_1000).

표본 하나가 EADDRINUSE로 막히면(다른 프로세스가 그 순간 그 포트를 쓰는
중) 판정에서 빼고 건너뛴다 — 사용 중이라는 것 자체는 차단과 무관한 정상
상태다. 건너뛴 표본이 너무 많아 판정 신뢰가 떨어지면 실패로 찍지 않고
"확인 불가"로 내려 진행한다. `/proc`가 없는 호스트(Linux가 아니거나 제한된
네임스페이스)에서도 마찬가지로 "확인 불가"만 찍고 통과시킨다 — 이 점검이
셀 수 없다는 이유로 24h 런 자체를 막지 않는다.

Exit code: 0 = 통과(막힌 포트 없음, 또는 확인 불가로 내려 진행) / 1 = 막힌
포트를 실제로 찾음. run.sh는 이 값을 그대로 자기 exit code로 올린다.

Stdlib only. Usage: scripts/soak/preflight_udp.py (인자 없음)
"""

from __future__ import annotations

import socket
import sys

STRIDE_TARGET_PORTS = 300  # 관측된 차단 구간(~1000포트)의 1/3 이하로 grid 간격을 좁힌다
MIN_SAMPLES = 32
MAX_SAMPLES = 256
PROBE_TIMEOUT_SECS = 0.2
PROBE_ATTEMPTS = 2  # 첫 시도 타임아웃만으로 차단을 확정하지 않는다
PAYLOAD = b"qsh-soak-preflight"


def _ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def read_ephemeral_range() -> tuple[int, int] | None:
    path = "/proc/sys/net/ipv4/ip_local_port_range"
    try:
        with open(path, "r", encoding="ascii") as f:
            raw = f.read().split()
        lo, hi = int(raw[0]), int(raw[1])
        if lo <= 0 or hi <= lo:
            return None
        return lo, hi
    except (OSError, ValueError, IndexError):
        return None


def sample_ports(lo: int, hi: int) -> list[int]:
    span = hi - lo + 1
    if span <= 1:
        return [lo]
    n = _ceil_div(span, STRIDE_TARGET_PORTS) + 1
    n = max(MIN_SAMPLES, min(MAX_SAMPLES, n))
    ports = {lo + round(i * (span - 1) / (n - 1)) for i in range(n)}
    return sorted(ports)


def probe_port(port: int) -> str:
    """포트 하나를 실제로 왕복시켜 본다. "ok" | "blocked" | "skipped"(사용 중, 판정 제외)."""
    for _attempt in range(PROBE_ATTEMPTS):
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            recv_sock.bind(("127.0.0.1", port))
        except OSError:
            recv_sock.close()
            return "skipped"
        recv_sock.settimeout(PROBE_TIMEOUT_SECS)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            send_sock.sendto(PAYLOAD, ("127.0.0.1", port))
            data, _addr = recv_sock.recvfrom(64)
            if data == PAYLOAD:
                return "ok"
        except (socket.timeout, OSError):
            pass
        finally:
            send_sock.close()
            recv_sock.close()
    return "blocked"


def main() -> int:
    rng = read_ephemeral_range()
    if rng is None:
        print(
            "preflight_udp: 확인 불가 — /proc/sys/net/ipv4/ip_local_port_range를 "
            "읽을 수 없다(Linux가 아니거나 제한된 네임스페이스). loopback UDP "
            "필터링 점검을 건너뛰고 진행한다.",
            file=sys.stderr,
        )
        return 0

    lo, hi = rng
    span = hi - lo + 1
    ports = sample_ports(lo, hi)
    n = len(ports)
    gap = _ceil_div(span, n - 1) if n > 1 else span
    catch_probability_1000 = 1.0 if gap <= 1000 else min(1.0, 1000 / gap)

    blocked: list[int] = []
    skipped = 0
    for port in ports:
        result = probe_port(port)
        if result == "blocked":
            blocked.append(port)
        elif result == "skipped":
            skipped += 1

    checked = n - skipped
    if checked == 0 or skipped > n // 2:
        print(
            f"preflight_udp: 확인 불가 — ephemeral 범위 {lo}-{hi}에서 표본 {n}개 중 "
            f"{skipped}개가 다른 프로세스 점유로 판정에서 빠졌다(신뢰 부족). 진행한다.",
            file=sys.stderr,
        )
        return 0

    if blocked:
        print(
            "preflight_udp: 실패 — loopback UDP가 다음 포트로 가는 왕복에서 막혔다: "
            + ", ".join(str(p) for p in blocked),
            file=sys.stderr,
        )
        print(
            f"preflight_udp: ephemeral 범위 {lo}-{hi} 중 {n}개 표본(간격 ~{gap}, "
            f"1000포트 구간 포착 확률 {catch_probability_1000:.3f})으로 찾았다.",
            file=sys.stderr,
        )
        print(
            "preflight_udp: 이건 이 호스트의 방화벽 설정 문제다 — qsh 결함이 아니다. "
            "loopback UDP를 이 포트 구간에서 막는 규칙(nftables/iptables 등)을 좁히거나 "
            "loopback 예외를 추가하면 풀린다. 규칙을 손댈 수 없거나 손대지 않기로 "
            "했다면 회차를 네트워크 네임스페이스 안에서 돌려라 — nft 테이블은 "
            "netns마다 별개다: "
            "unshare -rn sh -c 'ip link set lo up; exec scripts/soak/run.sh …'. "
            "근거와 절차: docs/campaigns/m8-soak.md §2(8·9번)과 §8 'run #5 결과'.",
            file=sys.stderr,
        )
        return 1

    print(
        f"preflight_udp: 통과 — ephemeral 범위 {lo}-{hi} 중 {n}개 표본(간격 ~{gap}) "
        "전부 loopback UDP 왕복 성공."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
