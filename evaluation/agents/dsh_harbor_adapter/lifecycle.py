import json, subprocess
from pathlib import Path

STATUSES={0:"COMPLETED",1:"NONZERO_EXIT",2:"STARTUP_FAILURE",3:"TIMEOUT",4:"MISSING_EVENT_LOG",5:"MALFORMED_EVENT_LOG",6:"PARTIAL_ARTIFACT",7:"FORCED_CLEANUP"}

def classify(returncode=None, *, startup=False, timeout=False, event_log=None, artifacts_complete=True, forced_cleanup=False):
    if startup: return STATUSES[2]
    if timeout: return STATUSES[3]
    if forced_cleanup: return STATUSES[7]
    if returncode not in (0,None): return STATUSES[1]
    if event_log is None or not Path(event_log).exists(): return STATUSES[4]
    try:
        for line in Path(event_log).read_text().splitlines(): json.loads(line)
    except Exception: return STATUSES[5]
    if not artifacts_complete: return STATUSES[6]
    return STATUSES[0]

def run_fixture(argv, timeout):
    try: return subprocess.run(argv,capture_output=True,text=True,timeout=timeout,check=False)
    except FileNotFoundError: return None
    except subprocess.TimeoutExpired: return "TIMEOUT"
