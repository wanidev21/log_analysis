"""PC용 실행기. 작업 폴더와 무관하게 로그 분석기의 웹 화면을 연다."""
import os
import sys


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    for stream in (sys.stdout, sys.stderr):
        if stream and not stream.isatty() and hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    try:
        if sys.version_info < (3, 8):
            raise RuntimeError("Python 3.8 or newer is required.")
        from serverlog_web import main as launch
        return launch()
    except Exception as e:
        import traceback
        try:
            with open(os.path.join(root, 'launcher-error.log'), 'w', encoding='utf-8') as f:
                f.write(traceback.format_exc())
        except OSError:
            pass
        message = 'ServerLog Analyzer could not start.\n%s\nSee launcher-error.log in the application folder.' % e
        if sys.platform == 'win32':
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, message, 'ServerLog Analyzer', 0x10)
        elif sys.stderr:
            print(message, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
