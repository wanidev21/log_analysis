"""서버 로그 분석기 (ServerLog Analyzer).

서버 관리 컨트롤러(BMC) 서비스 덤프를 읽어 요약·이상 징후·타임라인 리포트를 만든다.
벤더별 형식은 serverlog/vendors/ 의 파서가 맡는다.
"""

__version__ = "0.6.0"
APP_NAME = "서버 로그 분석기"
