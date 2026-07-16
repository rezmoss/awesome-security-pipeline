#!/usr/bin/env bash

set -euo pipefail

install_dir=${1:-}
metadata_file=${2:-}

if [[ -z "$install_dir" || -z "$metadata_file" ]]; then
  echo "usage: $0 INSTALL_DIR METADATA_FILE" >&2
  exit 2
fi

for command in curl gh install jq sha256sum tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command not found: $command" >&2
    exit 2
  fi
done

mkdir -p "$install_dir" "$(dirname "$metadata_file")"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
records="$work_dir/records.jsonl"
: > "$records"

release_json() {
  local repository=$1
  local response=""
  local error_file="$work_dir/gh-api-error.log"
  local attempt delay effective_url tag

  for attempt in 1 2 3; do
    if response=$(gh api \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "repos/$repository/releases/latest" 2>"$error_file") \
      && jq -e '.tag_name and (.assets | type == "array")' \
        <<<"$response" >/dev/null; then
      jq -c \
        --arg repository "$repository" \
        '. + {_benchmark_repository: $repository, _benchmark_source: "github-api"}' \
        <<<"$response"
      return 0
    fi

    if [[ $attempt -lt 3 ]]; then
      delay=$((attempt * 3))
      echo "GitHub API release lookup failed for $repository (attempt $attempt/3); retrying in ${delay}s" >&2
      sleep "$delay"
    fi
  done

  echo "GitHub API unavailable for $repository; resolving the latest release through github.com" >&2
  effective_url=$(curl --fail --silent --show-error --location \
    --retry 5 --retry-all-errors --retry-delay 3 --retry-max-time 180 \
    --output /dev/null --write-out '%{url_effective}' \
    "https://github.com/$repository/releases/latest")

  if [[ "$effective_url" != "https://github.com/$repository/releases/tag/"* ]]; then
    echo "unexpected latest-release redirect for $repository: $effective_url" >&2
    return 1
  fi

  tag=${effective_url##*/}
  if [[ -z "$tag" ]]; then
    echo "latest-release redirect did not contain a tag for $repository" >&2
    return 1
  fi

  jq -cn \
    --arg repository "$repository" \
    --arg tag "$tag" \
    '{tag_name: $tag, published_at: null, assets: [], _benchmark_repository: $repository, _benchmark_source: "github-redirect"}'
}

asset_url() {
  local release=$1
  local name=$2
  local url repository tag

  url=$(jq -r --arg name "$name" \
    '[.assets[] | select(.name == $name) | .browser_download_url] | first // empty' \
    <<<"$release")
  if [[ -n "$url" ]]; then
    printf '%s\n' "$url"
    return 0
  fi

  repository=$(jq -er '._benchmark_repository' <<<"$release")
  tag=$(jq -er '.tag_name' <<<"$release")
  printf 'https://github.com/%s/releases/download/%s/%s\n' "$repository" "$tag" "$name"
}

download_asset() {
  local release=$1
  local name=$2
  local destination=$3
  local url
  url=$(asset_url "$release" "$name")
  curl --fail --silent --show-error --location --retry 3 \
    --retry-all-errors --retry-delay 2 --retry-max-time 120 \
    --output "$destination" "$url"
}

record_tool() {
  local id=$1
  local repository=$2
  local tag=$3
  local published_at=$4
  local asset=$5
  local digest=$6
  local verification=$7
  local release_lookup=$8

  jq -cn \
    --arg id "$id" \
    --arg repository "$repository" \
    --arg version "$tag" \
    --arg published_at "$published_at" \
    --arg asset "$asset" \
    --arg sha256 "$digest" \
    --arg verification "$verification" \
    --arg release_lookup "$release_lookup" \
    '{id: $id, repository: $repository, version: $version, published_at: (if $published_at == "" then null else $published_at end), asset: $asset, sha256: $sha256, verification: $verification, release_lookup: $release_lookup}' \
    >> "$records"
}

install_syft() {
  local repository=anchore/syft
  local release tag version published_at archive checksums digest release_lookup
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  version=${tag#v}
  published_at=$(jq -r '.published_at // ""' <<<"$release")
  release_lookup=$(jq -r '._benchmark_source' <<<"$release")
  archive="syft_${version}_linux_amd64.tar.gz"
  checksums="syft_${version}_checksums.txt"

  download_asset "$release" "$archive" "$work_dir/$archive"
  download_asset "$release" "$checksums" "$work_dir/$checksums"
  (cd "$work_dir" && grep "  $archive$" "$checksums" | sha256sum --check --strict)
  tar -xzf "$work_dir/$archive" -C "$install_dir" syft
  chmod 0755 "$install_dir/syft"
  digest=$(sha256sum "$work_dir/$archive" | awk '{print $1}')
  record_tool syft "$repository" "$tag" "$published_at" "$archive" "$digest" upstream-checksum "$release_lookup"
}

install_trivy() {
  local repository=aquasecurity/trivy
  local release tag version published_at archive checksums digest release_lookup
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  version=${tag#v}
  published_at=$(jq -r '.published_at // ""' <<<"$release")
  release_lookup=$(jq -r '._benchmark_source' <<<"$release")
  archive="trivy_${version}_Linux-64bit.tar.gz"
  checksums="trivy_${version}_checksums.txt"

  download_asset "$release" "$archive" "$work_dir/$archive"
  download_asset "$release" "$checksums" "$work_dir/$checksums"
  (cd "$work_dir" && grep "  $archive$" "$checksums" | sha256sum --check --strict)
  tar -xzf "$work_dir/$archive" -C "$install_dir" trivy
  chmod 0755 "$install_dir/trivy"
  digest=$(sha256sum "$work_dir/$archive" | awk '{print $1}')
  record_tool trivy "$repository" "$tag" "$published_at" "$archive" "$digest" upstream-checksum "$release_lookup"
}

install_cdxgen() {
  local repository=cdxgen/cdxgen
  local release tag published_at asset checksum_asset digest release_lookup
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  published_at=$(jq -r '.published_at // ""' <<<"$release")
  release_lookup=$(jq -r '._benchmark_source' <<<"$release")
  asset=cdxgen-linux-amd64
  checksum_asset="$asset.sha256"

  download_asset "$release" "$asset" "$work_dir/$asset"
  download_asset "$release" "$checksum_asset" "$work_dir/$checksum_asset"
  (cd "$work_dir" && sha256sum --check --strict "$checksum_asset")
  install -m 0755 "$work_dir/$asset" "$install_dir/cdxgen"
  digest=$(sha256sum "$work_dir/$asset" | awk '{print $1}')
  record_tool cdxgen "$repository" "$tag" "$published_at" "$asset" "$digest" upstream-checksum "$release_lookup"
}

install_microsoft_sbom_tool() {
  local repository=microsoft/sbom-tool
  local release tag published_at asset digest release_lookup
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  published_at=$(jq -r '.published_at // ""' <<<"$release")
  release_lookup=$(jq -r '._benchmark_source' <<<"$release")
  asset=sbom-tool-linux-x64

  download_asset "$release" "$asset" "$work_dir/$asset"
  install -m 0755 "$work_dir/$asset" "$install_dir/sbom-tool"
  digest=$(sha256sum "$work_dir/$asset" | awk '{print $1}')
  record_tool microsoft-sbom-tool "$repository" "$tag" "$published_at" "$asset" "$digest" recorded-only "$release_lookup"
}

install_cyclonedx_cli() {
  local repository=CycloneDX/cyclonedx-cli
  local release tag published_at asset digest release_lookup
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  published_at=$(jq -r '.published_at // ""' <<<"$release")
  release_lookup=$(jq -r '._benchmark_source' <<<"$release")
  asset=cyclonedx-linux-x64

  download_asset "$release" "$asset" "$work_dir/$asset"
  install -m 0755 "$work_dir/$asset" "$install_dir/cyclonedx"
  digest=$(sha256sum "$work_dir/$asset" | awk '{print $1}')
  record_tool cyclonedx-cli "$repository" "$tag" "$published_at" "$asset" "$digest" recorded-only "$release_lookup"
}

install_syft
install_trivy
install_cdxgen
install_microsoft_sbom_tool
install_cyclonedx_cli

jq -s \
  --arg resolved_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  '{schema_version: 1, release_policy: "latest-stable", resolved_at: $resolved_at, tools: .}' \
  "$records" > "$metadata_file"

echo "Installed SBOM benchmark tools in $install_dir"
jq -r '.tools[] | "- \(.id): \(.version) [\(.verification)]"' "$metadata_file"
