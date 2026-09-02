#!/usr/bin/env bash
set -euo pipefail
gate=${1:?gate}; count=${2:?count}; out=${3:?CSV}
mkdir -p "$(dirname "$out")" work/gha/jobs work/gha/streams reports/harbor_trials
[ -f "$out" ] || printf 'gate,index,job_name,trial_name,harbor_process_exit,raw_reward,structured_exception_status,exception_info_present,task_network_status,oracle_network_status,verifier_network_status,artifact_complete,synthetic_assertions_status,text_only_exception_signal,normalizer_outcome,success,curl_exit_35,tls_failure,dns_failure\n' > "$out"
for i in $(seq 1 "$count"); do
  job="gha-synthetic-${gate}-$(printf '%02d' "$i")"; stdout="work/gha/streams/${job}.stdout"; stderr="work/gha/streams/${job}.stderr"
  set +e
  harbor run --path gha/synthetic-direct --agent oracle --env docker --n-concurrent 1 --n-attempts 1 --max-retries 0 --job-name "$job" --jobs-dir work/gha/jobs --yes >"$stdout" 2>"$stderr"
  rc=$?; set -e
  mapfile -t trials < <(find "work/gha/jobs/$job" -mindepth 1 -maxdepth 1 -type d | sort)
  [ "${#trials[@]}" -eq 1 ] || { printf 'Expected exactly one trial for %s; got %s\n' "$job" "${#trials[@]}" >&2; exit 1; }
  trial=${trials[0]}; evidence="reports/harbor_trials/$job"
  python3 scripts/capture_harbor_diagnostic.py --trial "$trial" --stdout "$stdout" --stderr "$stderr" --exit "$rc" --out "$evidence"
  python3 evaluation/normalize_outcome_v2.py "$trial" --output "$evidence/normalizer_v2.json"
  set +e
  row=$(python3 - "$gate" "$i" "$job" "$evidence/fresh_trial_evidence.json" "$evidence/normalizer_v2.json" "$trial" <<'PY'
import csv,io,json,re,sys
from pathlib import Path
gate,index,job,ep,np,trial=sys.argv[1:]; e=json.loads(Path(ep).read_text()); n=json.loads(Path(np).read_text())
text='\n'.join(p.read_text(errors='replace') for p in Path(trial).rglob('*') if p.is_file())
e35=len(re.findall(r'curl[^\n]*exit(?: code)?[=: ]+35|CURLE_SSL_CONNECT_ERROR',text,re.I)); tls=len(re.findall(r'TLS|SSL connect error',text,re.I)); dns=len(re.findall(r'could not resolve|temporary failure in name resolution',text,re.I))
status=e['structured_exception_status']; present=status not in ('NO_EXCEPTION','PARSER_AMBIGUOUS')
ok=(e['process_exit_ok'] and e['raw_reward']==1 and status=='NO_EXCEPTION' and e['task_network_ok'] is True and e['oracle_network_ok'] is True and e['verifier_network_ok'] is True and e['artifact_complete'] is True and e['synthetic_assertions_ok'] is True and n['outcome']=='PASS' and not (e35 or tls or dns))
vals=[gate,index,job,e['trial_name'],e['harbor_exit_code'],e['raw_reward'],status,present,e['task_network_ok'],e['oracle_network_ok'],e['verifier_network_ok'],e['artifact_complete'],e['synthetic_assertions_ok'],e['text_only_exception_signal'],n['outcome'],int(ok),e35,tls,dns]
s=io.StringIO(); csv.writer(s,lineterminator='').writerow(vals); print(s.getvalue()); raise SystemExit(0 if ok else 1)
PY
  ); pyrc=$?; set -e
  printf '%s\n' "$row" >> "$out"; [ "$pyrc" -eq 0 ] || exit 1
done
