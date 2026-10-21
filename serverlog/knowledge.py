"""메시지 패턴 → (해설, 권장 조치). 진단이 아니라 점검 출발점으로 쓰는 힌트.

벤더 공통으로 통하는 표현만 둔다. 벤더 고유 문구는 각 파서의 KNOWLEDGE 에 둔다.
"""

import re

KNOWLEDGE = [
    (re.compile(r"processor \d+ is operating in a Degraded State|CPU.*(throttl|degraded)", re.I),
     "CPU가 성능 저하(Degraded) 상태로 들어갔다가 복구되는 것을 반복합니다. "
     "흔한 원인은 과열에 따른 스로틀링(PROCHOT), 전원(VR) 이상, 전력 제한(Power Capping)입니다.",
     "같은 시각의 CPU 온도·팬 이벤트를 확인하고, 히트싱크 장착 상태와 서멀 컴파운드, "
     "팬, 주변 온도를 점검하세요. BIOS/UEFI·BMC 펌웨어 업데이트와 전원 정책 설정도 확인하세요."),
    (re.compile(r"OverTemp .*non-recoverable", re.I),
     "온도 센서가 복구 불가(non-recoverable) 임계치를 넘었습니다. 하드웨어 보호를 위해 "
     "전원이 차단됐을 수 있습니다.",
     "해당 부품의 히트싱크·팬·통풍 경로를 점검하고, 이벤트 직후 전원 이벤트를 확인하세요."),
    (re.compile(r"OverTemp|over temperature|Temp .*(critical|non-critical)", re.I),
     "온도 임계치 관련 이벤트입니다.",
     "팬 상태와 주변 온도, 공기 흐름(블랭크 패널, 케이블 정리)을 점검하세요."),
    (re.compile(r"(Event Log|SEL) is (almost )?full|log is full", re.I),
     "BMC 이벤트 로그가 가득 찼습니다. 오래된 이벤트가 덮어써져 유실됐을 수 있습니다.",
     "로그를 백업한 뒤 BMC에서 이벤트 로그를 지우세요(Clear)."),
    (re.compile(r"PSU Mismatch|Power Supply .*mismatch", re.I),
     "설치된 전원 공급 장치(PSU)끼리 정격 용량이나 종류가 서로 다릅니다.",
     "양쪽 PSU의 부품 번호와 정격 출력을 확인하고 같은 모델로 맞추세요."),
    (re.compile(r"Power Supply \d+ has lost input|PSU.*lost input", re.I),
     "전원 공급 장치에 입력 전원이 끊긴 적이 있습니다.",
     "전원 케이블 연결과 PDU/UPS 상태, 같은 시각의 정전·작업 이력을 확인하세요."),
    (re.compile(r"Redundancy Degraded|Non-redundant|redundancy lost", re.I),
     "전원 등 이중화 구성이 깨진 상태입니다. 남은 쪽이 고장 나면 서비스가 멈출 수 있습니다.",
     "PSU 두 개가 모두 장착·급전되고 있는지 확인하세요."),
    (re.compile(r"(Power Supply|PSU).*(fail|removed|absent)", re.I),
     "전원 공급 장치 이상입니다.",
     "PSU 상태 LED, 전원 케이블, 입력 전원을 확인하세요."),
    (re.compile(r"Vol(tage)? Fault|Volt.*(critical|non-recoverable)", re.I),
     "시스템보드 전압 이상이 감지됐습니다. 전원부(VR)나 PSU 문제일 수 있습니다.",
     "같은 시각의 PSU 이벤트를 함께 보고, 반복되면 시스템보드 점검을 요청하세요."),
    (re.compile(r"(DIMM|Memory).*(error|fail|disabled|uncorrectable|correctable)", re.I),
     "메모리 오류 이벤트입니다.",
     "해당 DIMM의 슬롯 위치를 확인하고, 반복되면 교체를 검토하세요."),
    (re.compile(r"Fan .*(fail|fault|less than|lower)", re.I),
     "팬 속도 저하 또는 고장입니다.",
     "해당 팬을 다시 장착하거나 교체하세요."),
]


def lookup(msg, extra=()):
    """extra(벤더 전용)를 먼저 보고, 없으면 공통 해설에서 찾는다."""
    for rx, why, action in list(extra) + KNOWLEDGE:
        if rx.search(msg):
            return why, action
    return None, None
