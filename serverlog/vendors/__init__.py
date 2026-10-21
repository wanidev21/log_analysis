"""벤더별 파서 등록부.

새 형식을 지원하려면 이 폴더에 모듈을 만들고 PARSERS 에 추가한다.
모듈이 갖춰야 할 것 (lenovo_imm2.py 참고):

    KEY          고유 키 (예: "dell_idrac_tsr")
    VENDOR       벤더 이름 (예: "Dell")
    NAME         형식 이름 (예: "iDRAC TSR")
    PRODUCTS     대상 제품 설명
    INPUT_FILES  분석에 쓰는 파일 목록 (덤프 루트 기준, '*' 사용 가능)
    KNOWLEDGE    [(정규식, 해설, 권장 조치), ...]  벤더 전용 메시지 해설 (없으면 [])
    detect(root) -> int        이 형식이면 양수 점수, 아니면 0
    parse(root, name) -> dict  공통 형식 덤프 (core.py 맨 위 설명 참고)

압축 해제(.tgz/.zip/.tzz 등)와 압축 안의 압축은 core 가 처리하므로 파서는 풀린 폴더만 다룬다.
같은 벤더의 여러 세대가 형식을 공유하면 _lenovo.py 처럼 공통 모듈로 묶는다.
"""

from . import lenovo_imm2, lenovo_xcc

PARSERS = [lenovo_imm2, lenovo_xcc]


def detect(root):
    """가장 높은 점수를 받은 파서를 돌려준다. 없으면 None."""
    best, best_score = None, 0
    for p in PARSERS:
        score = p.detect(root)
        if score > best_score:
            best, best_score = p, score
    return best


def input_patterns():
    seen = []
    for p in PARSERS:
        for f in p.INPUT_FILES:
            if f not in seen:
                seen.append(f)
    return seen


def supported():
    return [{"key": p.KEY, "vendor": p.VENDOR, "name": p.NAME, "products": p.PRODUCTS}
            for p in PARSERS]
