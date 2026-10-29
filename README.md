# 서버 로그 분석기

HW 로그에는 재부팅 사실만 남고 원인이 보이지 않는 경우, OS 기록까지 연결해 초기 점검 방향을 잡기 위해 만들었습니다. 원인 후보는 수집 기록에 따른 추정이며 엔지니어가 근거를 확인해야 합니다.

### 주요 기능

- Lenovo IMM2·XCC 덤프와 Linux OS 로그 분석
- 원인 후보·중단·복구를 시간순으로 연결
- 이벤트 검색·등급·출처 필터와 단일 HTML 보고서

## 내려받기

```sh
git clone https://github.com/wanidev21/log_analysis.git
cd log_analysis
```

엔지니어 PC에서 BMC 덤프와 Linux 로그를 분석하는 도구입니다. 이 폴더 전체만 있으면 실행할 수 있으며 설치 검증기는 필요하지 않습니다. Python 3.8 이상이 필요합니다.

## Windows에서 실행

`서버 로그 분석기.bat`을 더블클릭하세요. 브라우저가 열리면 로그 파일이나 폴더를 끌어다 놓습니다. 실행 오류는 폴더 안의 `launcher-error.log`에서 확인할 수 있습니다.

## Linux 또는 macOS PC에서 실행

```sh
sh ./launch_log_analyzer.sh
```

명령으로 분석할 수도 있습니다.

```sh
python3 serverlog.py /path/to/logs -o reports --open
```

분석은 PC 안에서 수행하며, 웹 실행 결과는 이 폴더의 `reports/`에 저장됩니다. 다른 PC로 옮길 때는 폴더 전체를 복사하세요. `servercommon/`은 실행에 필요한 공통 규칙입니다.

상세 설명: [사용 설명서](MANUAL.md)

## 검증 범위

개발·검증 중인 도구입니다. 실제 장애 유형과 추가 OS 자료에 대한 검증이 필요하며, 판정은 엔지니어의 근거 검토를 돕는 용도입니다.

## 개발용 테스트

```sh
python -m unittest discover -s tests -v
```

테스트는 Python 3.8 이상에서 실행합니다. 실제 고객 로그·접속 정보는 포함하지 않습니다.
공통 분류 규칙인 `servercommon/`도 이 저장소에 포함되어 있으므로 다른 도구 저장소가 필요하지 않습니다.
