#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, sys
from pathlib import Path

root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('m1b17i_task_policy',root/'scripts'/'m1b17i_task_policy.py'); assert spec and spec.loader
p=importlib.util.module_from_spec(spec); sys.modules[spec.name]=p; spec.loader.exec_module(p)

assert p.INDICES==(0,22,44,66,88); print('PASS frozen_indices')
assert len(p.TASKS)==5 and len(set(p.TASKS))==5; print('PASS five_unique_tasks')
assert p.TASKS==tuple(sorted(p.TASKS,key=lambda s:s.encode())); print('PASS selected_order')
assert p.TASKS[0]=='terminal-bench/adaptive-rejection-sampler'; print('PASS index_zero_17h')
assert p.TASK_COUNT==89; print('PASS task_count')
assert len(p.DIGEST)==64 and int(p.DIGEST,16)>=0; print('PASS immutable_digest')
assert p.DATASET=='terminal-bench/terminal-bench-2-1'; print('PASS canonical_dataset')
try: p.select(list(p.TASKS)); raise AssertionError('short list accepted')
except ValueError: print('PASS reject_wrong_population')
ids=[p.TASKS[0]]+[f'terminal-bench/b{i:02d}' for i in range(21)]+[p.TASKS[1]]+[f'terminal-bench/f{i:02d}' for i in range(21)]+[p.TASKS[2]]+[f'terminal-bench/n{i:02d}' for i in range(21)]+[p.TASKS[3]]+[f'terminal-bench/s{i:02d}' for i in range(21)]+[p.TASKS[4]]
assert p.select(ids)==list(p.TASKS); print('PASS select_frozen_positions')
drift=ids.copy(); drift[44]='terminal-bench/make-drift'
try: p.select(drift); raise AssertionError('selection drift accepted')
except ValueError: print('PASS reject_selection_drift')
print('M1B17I_TASK_SELECTION=10/10 PASS')
