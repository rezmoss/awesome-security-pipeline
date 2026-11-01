#!/usr/bin/env bash
# Gather the supply-chain data branch and, when this run did not produce them, the latest
# scan artifacts (SBOMs, Grype reports, sbomlyze diffs) from the last default-branch run.

set -euo pipefail

root=${1:?usage: $0 OUTPUT_DIR}
repository=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}
mkdir -p "$root"

fetch_branch() {
  local branch=$1 destination=$2
  mkdir -p "$destination"
  if git ls-remote --exit-code --heads origin "$branch" >/dev/null; then
    git fetch --quiet --depth=1 origin "$branch"
    git archive FETCH_HEAD | tar -x -C "$destination"
    echo "Loaded $branch"
  else
    echo "No $branch branch yet"
  fi
}

latest_run() {
  local workflow=$1
  gh run list --repo "$repository" --workflow "$workflow" --branch main --status success \
    --limit 10 --json databaseId,event \
    --jq '[.[] | select(.event != "pull_request")][0].databaseId // empty'
}

fetch_branch supply-chain-data "$root/supply-chain-data"

if [[ ! -d "$root/supply-chain-artifacts" ]]; then
  run_id=$(latest_run supply-chain-report.yml)
  if [[ -n "$run_id" ]] && gh run download "$run_id" --repo "$repository" \
      --pattern "supply-chain-shard-*" --dir "$root/supply-chain-artifacts" 2>/dev/null; then
    echo "Loaded supply-chain artifacts from run $run_id"
  fi
fi
