#!/bin/sh
# Linux/macOS PC용 웹 화면 실행기. 공백이 있는 경로도 지원한다.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 2
if command -v python3 >/dev/null 2>&1; then
    exec python3 "$SCRIPT_DIR/launch_log_analyzer.py" "$@"
fi
printf '%s\n' 'Python 3.8 or newer is required.' >&2
exit 2
