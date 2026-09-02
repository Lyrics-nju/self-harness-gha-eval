#!/usr/bin/env bash
set -euo pipefail
stage=${1:?stage}; metric=${2:?metric}; out=${3:?output}; detail=${4:-df --output=avail -B1 /}
free=$(df --output=avail -B1 / | tail -1 | tr -d ' ')
printf '%s,%s,%s,%s\n' "$stage" "$metric" "$free" "$detail" >> "$out"
