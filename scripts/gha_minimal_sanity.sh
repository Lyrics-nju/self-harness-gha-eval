#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports work/sanity
printf 'operation,endpoint_class,target,transport_ok,curl_exit_code,http_status,final_operation_result\n' > reports/diagnostic_network_sanity.csv
for i in 1 2; do
 set +e; status=$(curl -sS -L --retry 0 --connect-timeout 15 --max-time 90 -o /dev/null -w '%{http_code}' https://github.com/); rc=$?; set -e
 result=FAIL; [ "$rc" -eq 0 ] && [ "$status" = 200 ] && result=PASS
 printf '%s,generic_https,https://github.com/,%s,%s,%s,%s\n' "$i" "$([ "$rc" -eq 0 ] && echo true || echo false)" "$rc" "$status" "$result" >> reports/diagnostic_network_sanity.csv
 [ "$result" = PASS ]
done
docker version > reports/diagnostic_docker_sanity.txt
docker run --rm hello-world >> reports/diagnostic_docker_sanity.txt
for i in 3 4; do
 set +e; output=$(docker run --rm curlimages/curl:8.10.1 -sS -L --retry 0 --connect-timeout 15 --max-time 90 -D - -o /dev/null -w '__STATUS__=%{http_code}' https://registry-1.docker.io/v2/ 2>work/sanity/registry.err); rc=$?; set -e
 printf '%s\n' "$output" | sed '/__STATUS__=/d' > work/sanity/registry.headers; status=$(printf '%s\n' "$output" | sed -n 's/^__STATUS__=//p' | tail -1); status=${status:-0}
 set +e; fields=$(python3 scripts/docker_endpoint_policy.py docker_registry_v2 "$rc" "$status" work/sanity/registry.headers); policy_rc=$?; set -e
 final=$(printf '%s' "$fields" | awk -F, '{print $NF}'); transport=$(printf '%s' "$fields" | cut -d, -f1)
 printf '%s,docker_registry_v2,https://registry-1.docker.io/v2/,%s,%s,%s,%s\n' "$i" "$transport" "$rc" "$status" "$final" >> reports/diagnostic_network_sanity.csv
 [ "$policy_rc" -eq 0 ]
done
docker run --rm curlimages/curl:8.10.1 -sS -fL --retry 0 --connect-timeout 15 --max-time 90 https://github.com/ >/dev/null
echo CONTAINER_HTTPS_PASS >> reports/diagnostic_docker_sanity.txt
