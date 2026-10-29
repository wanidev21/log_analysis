"""로그 분석기와 설치 검증기가 공유하는 Linux 메시지 분류 규칙."""

import re

OUTCOME, CAUSE, RESOLVE, ACTION, BOOT, LOGIN = "outcome", "cause", "resolve", "action", "boot", "login"

# ---------------------------------------------------------------- 분류 규칙
# (정규식, 역할, 분류, 등급). "프로세스: 메시지" 문자열에 대해 위에서부터 먼저 맞는 것을 쓴다.
R = re.compile
OS_RULES = [
    (R(r"^kernel: Linux version"), BOOT, "os_boot", "I"),
    (R(r"Reached target Shutdown|systemd-shutdown|Shutting down\.|System is (rebooting|powering down)|"
       r"reboot: (Restarting system|Power down)|shutdown\[\d*\]?: shutting down|rsyslogd.*exiting on signal 15|"
       r"Power key pressed"), ACTION, "os_shutdown", "I"),
    (R(r"sudo:.*COMMAND=\S*\b(reboot|shutdown|poweroff|halt|init [06]|systemctl (reboot|poweroff|halt|kexec))"),
     ACTION, "os_reboot_cmd", "I"),
    (R(r"Kernel panic|kernel BUG at|Oops:|general protection fault|hard LOCKUP|NMI watchdog: (BUG|Watchdog detected)"
       r"|watchdog: BUG"), CAUSE, "kernel", "E"),
    (R(r"soft lockup|blocked for more than \d+ seconds|rcu_sched (self-)?detected stall"), CAUSE, "kernel", "W"),
    (R(r"^kernel: WARNING: CPU: \d+ PID"), CAUSE, "kernel", "W"),
    (R(r"Machine check events logged|mce: \[Hardware Error\]|\[Hardware Error\]"), CAUSE, "hw", "E"),
    (R(r"EDAC.*\b(UE|[Uu]ncorrected|[Uu]ncorrectable)\b"), CAUSE, "memory", "E"),
    (R(r"EDAC.*\b(CE|[Cc]orrected|[Cc]orrectable)\b.*error|EDAC.*error"), CAUSE, "memory", "W"),
    (R(r"temperature above threshold|cpu clock throttled|Package temperature"), CAUSE, "thermal", "W"),
    (R(r"Out of memory|oom-kill|invoked oom-killer"), CAUSE, "oom", "E"),
    (R(r"remaining active paths: 0|All paths are down|no active paths|Buffer I/O error|\bI/O error\b|"
       r"blk_update_request|rejecting I/O to offline device|Medium Error|Unrecovered read error|"
       r"device offline"), CAUSE, "storage", "E"),
    (R(r"Failing path|path is down|checker failed path|remaining active paths: [1-9]|"
       r"couldn't get asymmetric access state|timing out command|SCSI error|task abort"), CAUSE, "storage", "W"),
    (R(r"reinstated|Reinstating path|path is up"), RESOLVE, "storage", "I"),
    (R(r"NIC Link is Down|Link is Down|link status definitely down|link status down|lost carrier"),
     CAUSE, "network", "W"),
    (R(r"NIC Link is Up|Link is Up|link status definitely up|link status up"), RESOLVE, "network", "I"),
    (R(r"^mmfs\w*: \[[EX]\]|^mmsysmon: \[E\]"), CAUSE, "app", "E"),
    (R(r"^mmfs\w*: \[W\]|^mmsysmon: \[W\]"), CAUSE, "app", "W"),
    (R(r"^systemd: Stopping (?!.*(Slice|Session|user@|getty|Cleanup|Read-Ahead|Load/Save|Rotate|Reload|"
       r"sysstat|Timer|Daily|Monitoring of LVM|Hostname Service|Network Manager Script|Fingerprint|"
       r"Locale Service|Time & Date|Authorization Manager|PackageKit|Disk Manager|"
       r"Accounts Service|Daemon for power management|Login Service))(.+)\.\.\.$"),
     ACTION, "service_stop", "I"),
    (R(r"^sshd: Accepted \S+ for \S+ from"), LOGIN, "login", "I"),
]
# 역할은 없지만 흐름에서 참고하는 줄 (같은 커널 경고가 예전에도 있었다는 abrt 기록 등)
OS_KEEP_EXTRA = [R(r"abrt-server: DUP_OF_DIR: .*oops-(\d{4}-\d\d-\d\d)")]

CAT_LABEL = {"kernel": "커널", "hw": "하드웨어(MCE)", "oom": "메모리 부족(OOM)", "network": "네트워크",
             "app": "애플리케이션", "storage": "디스크", "memory": "메모리", "thermal": "과열"}


def classify_line(proc, msg):
    text = "%s: %s" % (proc, msg)
    for rx, role, cat, sev in OS_RULES:
        if rx.search(text):
            return role, cat, sev
    for rx in OS_KEEP_EXTRA:
        if rx.search(text):
            return None, None, "I"
    return False
