#!/usr/bin/env bash
# Print the workflow run that produced the newest report week before DATE (default: the newest
# week), read from the data branch. Weeks recorded before run provenance existed fall back to the
# last successful non-pull-request run that started before that week's data was generated.

set -euo pipefail

data=${1:?usage: $0 DATA_DIR [DATE]}
date=${2:-9999-12-31}
repository=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}
script_dir=$(cd "$(dirname "$0")" && pwd)

[[ -f "$data/index.json" ]] || exit 0
baseline=$(python3 "$script_dir/supply_chain_scan.py" baseline --data-dir "$data" --date "$date")
run_id=$(jq -r '.run_id // empty' <<<"$baseline")
generated=$(jq -r '.generated_at // empty' <<<"$baseline")
if [[ -z "$run_id" && -n "$generated" ]]; then
  generated=$(date -u -d "$generated" +%Y-%m-%dT%H:%M:%SZ)
  run_id=$(gh run list --repo "$repository" --workflow supply-chain-report.yml --branch main --status success \
    --limit 50 --json databaseId,event,createdAt \
    --jq "[.[] | select(.event != \"pull_request\" and .createdAt <= \"$generated\")][0].databaseId // empty")
fi
echo "$run_id"
