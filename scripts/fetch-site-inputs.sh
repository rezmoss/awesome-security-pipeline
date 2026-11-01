#!/usr/bin/env bash
# Gather everything the Pages site needs: both data branches and, for whichever report the
# current workflow did not produce, the latest artifacts from its last default-branch run.
# A Pages deployment replaces the whole site, so every deploy must include both reports.

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

fetch_branch sbom-benchmark-data "$root/benchmark-data"
fetch_branch supply-chain-data "$root/supply-chain-data"

if [[ ! -d "$root/benchmark-artifacts" ]]; then
  run_id=$(latest_run sbom-benchmark.yml)
  if [[ -n "$run_id" ]] && gh run download "$run_id" --repo "$repository" \
      --name "sbom-benchmark-$run_id" --dir "$root/benchmark-run" 2>/dev/null; then
    mv "$root/benchmark-run/sbomlyze" "$root/benchmark-artifacts" 2>/dev/null || mkdir -p "$root/benchmark-artifacts"
    rm -rf "$root/benchmark-run"
    echo "Loaded benchmark artifacts from run $run_id"
  fi
fi

if [[ ! -d "$root/supply-chain-artifacts" ]]; then
  run_id=$(latest_run supply-chain-report.yml)
  if [[ -n "$run_id" ]] && gh run download "$run_id" --repo "$repository" \
      --pattern "supply-chain-shard-*" --dir "$root/supply-chain-artifacts" 2>/dev/null; then
    echo "Loaded supply-chain artifacts from run $run_id"
  fi
fi
