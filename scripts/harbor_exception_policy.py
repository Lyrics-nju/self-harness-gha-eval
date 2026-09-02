#!/usr/bin/env python3
"""Structured Harbor 0.21.0 synthetic diagnostic policy, version 1.0.0."""
from __future__ import annotations
import json,re
from pathlib import Path

POLICY_VERSION='1.0.0'
TEXT_SIGNAL=re.compile(r'\b(?:traceback|exception|errors?)\b',re.I)

def diagnose(process_exit: int, result: dict|None, stdout: str='', stderr: str='', artifact_complete: bool=True, phase_status: dict|None=None) -> dict:
    phase_status=phase_status or {}
    text_signal=bool(TEXT_SIGNAL.search(stdout+'\n'+stderr))
    if result is None or 'exception_info' not in result:
        structured='PARSER_AMBIGUOUS'
    else:
        exc=result.get('exception_info')
        if exc is None or exc=='': structured='NO_EXCEPTION'
        elif isinstance(exc,dict) and exc.get('severity')=='nonfatal': structured='STRUCTURED_NONFATAL_EXCEPTION'
        elif isinstance(exc,dict) and exc.get('exception_type'): structured='STRUCTURED_FATAL_EXCEPTION'
        else: structured='PARSER_AMBIGUOUS'
    reward=None
    if isinstance(result,dict): reward=((result.get('verifier_result') or {}).get('rewards') or {}).get('reward')
    dimensions={'process_exit_ok':process_exit==0,'raw_reward':reward,'structured_exception_status':structured,
      'task_network_ok':phase_status.get('task_network_ok'),'oracle_network_ok':phase_status.get('oracle_network_ok'),
      'verifier_network_ok':phase_status.get('verifier_network_ok'),'artifact_complete':artifact_complete,
      'synthetic_assertions_ok':reward==1,'text_only_exception_signal':text_signal and structured=='NO_EXCEPTION'}
    if structured=='PARSER_AMBIGUOUS' or not artifact_complete: classification='PARSER_AMBIGUOUS'
    elif structured=='STRUCTURED_FATAL_EXCEPTION': classification='TRUE_FATAL_HARBOR_EXCEPTION'
    elif structured=='STRUCTURED_NONFATAL_EXCEPTION' and process_exit==0 and reward==1: classification='NONFATAL_HARBOR_EXCEPTION_WITH_SUCCESS'
    elif process_exit==0 and reward==1 and structured=='NO_EXCEPTION' and text_signal: classification='TEXT_MATCH_FALSE_POSITIVE'
    elif process_exit==0 and reward==1 and structured=='NO_EXCEPTION': classification='CLEAN_SUCCESS'
    else: classification='OTHER_EVIDENCE_BACKED_FAILURE'
    return {'policy_version':POLICY_VERSION,**dimensions,'diagnostic_classification':classification}

def load_result(path: Path):
    try: return json.loads(path.read_text())
    except (OSError,ValueError): return None
