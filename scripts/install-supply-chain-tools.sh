#!/usr/bin/env bash

set -euo pipefail

install_dir=${1:-}
metadata_file=${2:-}
shift 2 || true
# Optional tool list; defaults to every tool the supply-chain report uses.
tools=("$@")
if [[ ${#tools[@]} -eq 0 ]]; then
  tools=(syft grype osv-scanner govulncheck zizmor scorecard cosign slsa-verifier sbomlyze)
fi

if [[ -z "$install_dir" || -z "$metadata_file" ]]; then
  echo "usage: $0 INSTALL_DIR METADATA_FILE [TOOL...]" >&2
  exit 2
fi

for command in curl gh go install jq sha256sum tar; do
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
        '. + {_release_repository: $repository, _release_source: "github-api"}' \
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
    '{tag_name: $tag, published_at: null, assets: [], _release_repository: $repository, _release_source: "github-redirect"}'
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

  repository=$(jq -er '._release_repository' <<<"$release")
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
  release_lookup=$(jq -r '._release_source' <<<"$release")
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

install_sbomlyze() {
  # sbomlyze is maintained by this repository's maintainer; it is used only for SBOM diffs
  # and minimum-element checks.
  local repository=rezmoss/sbomlyze
  local release tag version published_at archive checksums digest release_lookup
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  version=${tag#v}
  published_at=$(jq -r '.published_at // ""' <<<"$release")
  release_lookup=$(jq -r '._release_source' <<<"$release")
  archive="sbomlyze_${version}_Linux_x86_64.tar.gz"
  checksums="checksums.txt"

  download_asset "$release" "$archive" "$work_dir/$archive"
  download_asset "$release" "$checksums" "$work_dir/sbomlyze-$checksums"
  (cd "$work_dir" && grep "  $archive$" "sbomlyze-$checksums" | sha256sum --check --strict)
  gh attestation verify "$work_dir/$archive" \
    --repo "$repository" \
    --signer-workflow "$repository/.github/workflows/release.yml" >/dev/null
  tar -xzf "$work_dir/$archive" -C "$install_dir" sbomlyze
  chmod 0755 "$install_dir/sbomlyze"
  digest=$(sha256sum "$work_dir/$archive" | awk '{print $1}')
  record_tool sbomlyze "$repository" "$tag" "$published_at" "$archive" "$digest" upstream-checksum+attestation "$release_lookup"
}

install_grype() {
  local repository=anchore/grype
  local release tag version published_at archive checksums digest release_lookup
  release=$(release_json "$repository")
  tag=$(jq -r '.tag_name' <<<"$release")
  version=${tag#v}
  published_at=$(jq -r '.published_at // ""' <<<"$release")
  release_lookup=$(jq -r '._release_source' <<<"$release")
  archive="grype_${version}_linux_amd64.tar.gz"
  checksums="grype_${version}_checksums.txt"

  download_asset "$release" "$archive" "$work_dir/$archive"
  download_asset "$release" "$checksums" "$work_dir/$checksums"
  (cd "$work_dir" && grep "  $archive$" "$checksums" | sha256sum --check --strict)
  tar -xzf "$work_dir/$archive" -C "$install_dir" grype
  chmod 0755 "$install_dir/grype"
  digest=$(sha256sum "$work_dir/$archive" | awk '{print $1}')
  record_tool grype "$repository" "$tag" "$published_at" "$archive" "$digest" upstream-checksum "$release_lookup"
}

asset_digest() {
  # GitHub records a SHA-256 digest for every release asset; used where no checksum file exists.
  local release=$1 name=$2
  jq -r --arg name "$name" '[.assets[] | select(.name == $name) | .digest // empty] | first // empty' <<<"$release" \
    | sed 's/^sha256://'
}

verify_checksum_line() {
  local directory=$1 checksums=$2 name=$3
  (cd "$directory" && grep -E "[[:space:]]\*?$name\$" "$checksums" | sed 's/\*//' | sha256sum --check --strict)
}

verify_github_digest() {
  local release=$1 name=$2 file=$3 expected
  expected=$(asset_digest "$release" "$name")
  if [[ -z "$expected" ]]; then
    echo "no published digest for $name" >&2
    return 1
  fi
  echo "$expected  $file" | sha256sum --check --strict
}

release_fields() {
  # Sets: release tag version published_at release_lookup
  release=$(release_json "$1")
  tag=$(jq -r '.tag_name' <<<"$release")
  version=${tag#v}
  published_at=$(jq -r '.published_at // ""' <<<"$release")
  release_lookup=$(jq -r '._release_source' <<<"$release")
}

install_osv_scanner() {
  local repository=google/osv-scanner release tag version published_at release_lookup
  release_fields "$repository"
  download_asset "$release" osv-scanner_linux_amd64 "$work_dir/osv-scanner_linux_amd64"
  download_asset "$release" osv-scanner_SHA256SUMS "$work_dir/osv-scanner_SHA256SUMS"
  verify_checksum_line "$work_dir" osv-scanner_SHA256SUMS osv-scanner_linux_amd64
  install -m 0755 "$work_dir/osv-scanner_linux_amd64" "$install_dir/osv-scanner"
  record_tool osv-scanner "$repository" "$tag" "$published_at" osv-scanner_linux_amd64 \
    "$(sha256sum "$work_dir/osv-scanner_linux_amd64" | awk '{print $1}')" upstream-checksum "$release_lookup"
}

install_zizmor() {
  local repository=zizmorcore/zizmor release tag version published_at release_lookup
  local archive=zizmor-x86_64-unknown-linux-gnu.tar.gz
  release_fields "$repository"
  download_asset "$release" "$archive" "$work_dir/$archive"
  verify_github_digest "$release" "$archive" "$work_dir/$archive"
  tar -xzf "$work_dir/$archive" -C "$install_dir" zizmor
  chmod 0755 "$install_dir/zizmor"
  record_tool zizmor "$repository" "$tag" "$published_at" "$archive" \
    "$(sha256sum "$work_dir/$archive" | awk '{print $1}')" github-asset-digest "$release_lookup"
}

install_scorecard() {
  local repository=ossf/scorecard release tag version published_at release_lookup
  release_fields "$repository"
  local archive="scorecard_${version}_linux_amd64.tar.gz"
  download_asset "$release" "$archive" "$work_dir/$archive"
  download_asset "$release" scorecard_checksums.txt "$work_dir/scorecard_checksums.txt"
  verify_checksum_line "$work_dir" scorecard_checksums.txt "$archive"
  tar -xzf "$work_dir/$archive" -C "$install_dir" scorecard
  chmod 0755 "$install_dir/scorecard"
  record_tool scorecard "$repository" "$tag" "$published_at" "$archive" \
    "$(sha256sum "$work_dir/$archive" | awk '{print $1}')" upstream-checksum "$release_lookup"
}

install_cosign() {
  local repository=sigstore/cosign release tag version published_at release_lookup
  release_fields "$repository"
  download_asset "$release" cosign-linux-amd64 "$work_dir/cosign-linux-amd64"
  download_asset "$release" cosign_checksums.txt "$work_dir/cosign_checksums.txt"
  verify_checksum_line "$work_dir" cosign_checksums.txt cosign-linux-amd64
  install -m 0755 "$work_dir/cosign-linux-amd64" "$install_dir/cosign"
  record_tool cosign "$repository" "$tag" "$published_at" cosign-linux-amd64 \
    "$(sha256sum "$work_dir/cosign-linux-amd64" | awk '{print $1}')" upstream-checksum "$release_lookup"
}

install_slsa_verifier() {
  local repository=slsa-framework/slsa-verifier release tag version published_at release_lookup
  release_fields "$repository"
  download_asset "$release" slsa-verifier-linux-amd64 "$work_dir/slsa-verifier-linux-amd64"
  verify_github_digest "$release" slsa-verifier-linux-amd64 "$work_dir/slsa-verifier-linux-amd64"
  install -m 0755 "$work_dir/slsa-verifier-linux-amd64" "$install_dir/slsa-verifier"
  record_tool slsa-verifier "$repository" "$tag" "$published_at" slsa-verifier-linux-amd64 \
    "$(sha256sum "$work_dir/slsa-verifier-linux-amd64" | awk '{print $1}')" github-asset-digest "$release_lookup"
}

install_govulncheck() {
  # Built from source through the Go module proxy, verified by the Go checksum database.
  # golang/vuln publishes module versions more often than GitHub releases, so use the module.
  local tag="" attempt
  for attempt in 1 2 3 4; do
    if tag=$(go list -m -json golang.org/x/vuln@latest | jq -r '.Version') && [[ -n "$tag" ]] \
      && GOBIN="$install_dir" go install "golang.org/x/vuln/cmd/govulncheck@$tag"; then
      break
    fi
    if [[ $attempt -eq 4 ]]; then
      echo "could not install govulncheck from the Go module proxy" >&2
      return 1
    fi
    echo "Go module proxy request failed (attempt $attempt/4); retrying in $((attempt * 10))s" >&2
    sleep $((attempt * 10))
  done
  record_tool govulncheck golang/vuln "$tag" "" "golang.org/x/vuln/cmd/govulncheck@$tag" \
    "" go-checksum-database go-module-proxy
}

for tool in "${tools[@]}"; do
  case "$tool" in
    syft) install_syft ;;
    sbomlyze) install_sbomlyze ;;
    grype) install_grype ;;
    osv-scanner) install_osv_scanner ;;
    zizmor) install_zizmor ;;
    scorecard) install_scorecard ;;
    cosign) install_cosign ;;
    slsa-verifier) install_slsa_verifier ;;
    govulncheck) install_govulncheck ;;
    *) echo "unknown tool: $tool" >&2; exit 2 ;;
  esac
done

jq -s \
  --arg resolved_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  '{schema_version: 1, release_policy: "latest-stable", resolved_at: $resolved_at, tools: .}' \
  "$records" > "$metadata_file"

echo "Installed supply-chain tools in $install_dir"
jq -r '.tools[] | "- \(.id): \(.version) [\(.verification)]"' "$metadata_file"
