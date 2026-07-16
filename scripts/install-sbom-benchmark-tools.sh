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
  local attempt delay

  for attempt in 1 2 3 4 5; do
    if response=$(gh api \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "repos/$repository/releases/latest" 2>"$error_file") \
      && jq -e '.tag_name and (.assets | type == "array")' \
        <<<"$response" >/dev/null; then
      printf '%s\n' "$response"
      return 0
    fi

    if [[ $attempt -lt 5 ]]; then
      delay=$((attempt * 3))
      echo "GitHub release lookup failed for $repository (attempt $attempt/5); retrying in ${delay}s" >&2
      sleep "$delay"
    fi
  done

  echo "GitHub release lookup failed for $repository after 5 attempts" >&2
  cat "$error_file" >&2
  return 1
}

asset_url() {
  jq -er --arg name "$2" '.assets[] | select(.name == $name) | .browser_download_url' <<<"$1"
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

  jq -cn \
    --arg id "$id" \
    --arg repository "$repository" \
    --arg version "$tag" \
    --arg published_at "$published_at" \
    --arg asset "$asset" \
    --arg sha256 "$digest" \
    --arg verification "$verification" \
    '{id: $id, repository: $repository, version: $version, published_at: $published_at, asset: $asset, sha256: $sha256, verification: $verification}' \
    >> "$records"
}

install_syft() {
  local repository=anchore/syft
  local release tag version published_at archive checksums digest
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  version=${tag#v}
  published_at=$(jq -r '.published_at' <<<"$release")
  archive="syft_${version}_linux_amd64.tar.gz"
  checksums="syft_${version}_checksums.txt"

  download_asset "$release" "$archive" "$work_dir/$archive"
  download_asset "$release" "$checksums" "$work_dir/$checksums"
  (cd "$work_dir" && grep "  $archive$" "$checksums" | sha256sum --check --strict)
  tar -xzf "$work_dir/$archive" -C "$install_dir" syft
  chmod 0755 "$install_dir/syft"
  digest=$(sha256sum "$work_dir/$archive" | awk '{print $1}')
  record_tool syft "$repository" "$tag" "$published_at" "$archive" "$digest" upstream-checksum
}

install_trivy() {
  local repository=aquasecurity/trivy
  local release tag version published_at archive checksums digest
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  version=${tag#v}
  published_at=$(jq -r '.published_at' <<<"$release")
  archive="trivy_${version}_Linux-64bit.tar.gz"
  checksums="trivy_${version}_checksums.txt"

  download_asset "$release" "$archive" "$work_dir/$archive"
  download_asset "$release" "$checksums" "$work_dir/$checksums"
  (cd "$work_dir" && grep "  $archive$" "$checksums" | sha256sum --check --strict)
  tar -xzf "$work_dir/$archive" -C "$install_dir" trivy
  chmod 0755 "$install_dir/trivy"
  digest=$(sha256sum "$work_dir/$archive" | awk '{print $1}')
  record_tool trivy "$repository" "$tag" "$published_at" "$archive" "$digest" upstream-checksum
}

install_cdxgen() {
  local repository=cdxgen/cdxgen
  local release tag published_at asset checksum_asset digest
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  published_at=$(jq -r '.published_at' <<<"$release")
  asset=cdxgen-linux-amd64
  checksum_asset="$asset.sha256"

  download_asset "$release" "$asset" "$work_dir/$asset"
  download_asset "$release" "$checksum_asset" "$work_dir/$checksum_asset"
  (cd "$work_dir" && sha256sum --check --strict "$checksum_asset")
  install -m 0755 "$work_dir/$asset" "$install_dir/cdxgen"
  digest=$(sha256sum "$work_dir/$asset" | awk '{print $1}')
  record_tool cdxgen "$repository" "$tag" "$published_at" "$asset" "$digest" upstream-checksum
}

install_microsoft_sbom_tool() {
  local repository=microsoft/sbom-tool
  local release tag published_at asset digest
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  published_at=$(jq -r '.published_at' <<<"$release")
  asset=sbom-tool-linux-x64

  download_asset "$release" "$asset" "$work_dir/$asset"
  install -m 0755 "$work_dir/$asset" "$install_dir/sbom-tool"
  digest=$(sha256sum "$work_dir/$asset" | awk '{print $1}')
  record_tool microsoft-sbom-tool "$repository" "$tag" "$published_at" "$asset" "$digest" recorded-only
}

install_cyclonedx_cli() {
  local repository=CycloneDX/cyclonedx-cli
  local release tag published_at asset digest
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  published_at=$(jq -r '.published_at' <<<"$release")
  asset=cyclonedx-linux-x64

  download_asset "$release" "$asset" "$work_dir/$asset"
  install -m 0755 "$work_dir/$asset" "$install_dir/cyclonedx"
  digest=$(sha256sum "$work_dir/$asset" | awk '{print $1}')
  record_tool cyclonedx-cli "$repository" "$tag" "$published_at" "$asset" "$digest" recorded-only
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
