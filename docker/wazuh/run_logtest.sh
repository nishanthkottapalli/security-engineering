#!/usr/bin/env bash
set -euo pipefail
mkdir -p /lab/output

run_case() {
  local name=$1
  local file=$2
  local expected=$3
  local output="/lab/output/wazuh-${name}.txt"
  echo "Running Wazuh case: ${name}"
  /var/ossec/bin/wazuh-logtest -q < "$file" | tee "$output"
  if [[ "$expected" == "present" ]]; then
    grep -Eq "(^|[^0-9])100111([^0-9]|$)" "$output" || {
      echo "Expected correlation rule 100111 did not fire for ${name}" >&2
      exit 1
    }
  else
    if grep -Eq "(^|[^0-9])100111([^0-9]|$)" "$output"; then
      echo "Unexpected correlation rule 100111 fired for ${name}" >&2
      exit 1
    fi
  fi
}

run_case positive /lab/fixtures/ssh_compromise.log present
run_case failures-only /lab/fixtures/ssh_failures_only.log absent
run_case different-source /lab/fixtures/ssh_different_source.log absent

echo "Wazuh decoder and correlation tests passed."
