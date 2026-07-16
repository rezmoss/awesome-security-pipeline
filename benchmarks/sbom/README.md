# SBOM compatibility benchmark

This benchmark runs Syft, Trivy, cdxgen, and Microsoft SBOM Tool against the same deterministic inputs, then validates and normalizes their output. It is designed to detect behavior changes and preserve comparable evidence over time, not to reward the largest component count.

## Fixtures

| Fixture | What it tests | Assertions |
|---|---|---|
| `go-direct-lockless` | Manifest discovery without a lockfile, vendor tree, or downloaded modules | Exact name and version of the declared Go dependency |
| `npm-lock-transitive` | npm lockfile parsing and transitive dependency retention | Exact names and versions plus the `is-odd → is-number` dependency edge |
| `pinned-container-image` | Container and operating-system package inventory from an immutable Linux/amd64 image | Valid document and at least one normalized component; inventories are retained for cross-tool and historical review |

The image fixture uses the immutable Linux/amd64 manifest resolved from the OCI index already pinned by the security demo's Dockerfile. Both digests are recorded in `fixtures.json`. The workflow pulls that exact platform manifest once and gives every generator the same local tag.

## Cadence and publication

- The full suite runs every Sunday and on relevant pull requests or pushes.
- Weekly results, raw SBOMs, and logs are retained as workflow artifacts for 90 days.
- The first scheduled run each month writes a compact normalized snapshot under `reports/sbom/history/`, updates the latest report and machine-readable result, and opens or updates one pull request for maintainer review.
- A manual workflow run can request a snapshot at any time. Publication is allowed only from the default branch.
- A missing expected component, generator failure, invalid document, or empty container inventory fails the regression gate. The monthly report PR is still created so the failure is reviewable rather than silently discarded.

Automated publication requires the repository's GitHub Actions policy to allow pull-request creation. If that policy is disabled, the benchmark and 90-day artifact still complete, but the publication job reports the permission failure.

Tool releases are resolved from each project's latest non-prerelease GitHub release at run time. Syft, Trivy, and cdxgen assets are verified with upstream SHA-256 files. Microsoft SBOM Tool and CycloneDX CLI do not currently attach separate checksum files; their downloaded SHA-256 digests are recorded in every result. Each historical snapshot therefore states exactly what was executed.

## Run locally

The automated installer targets an Ubuntu x64 runner and requires `gh`, `curl`, `jq`, `sha256sum`, and `tar`:

```bash
export GH_TOKEN="$(gh auth token)"
bash scripts/install-sbom-benchmark-tools.sh /tmp/sbom-tools /tmp/tool-metadata.json
export PATH="/tmp/sbom-tools:$PATH"

docker pull "$(jq -r '.fixtures[] | select(.kind == "image") | .source_image' benchmarks/sbom/fixtures.json)"
docker tag "$(jq -r '.fixtures[] | select(.kind == "image") | .source_image' benchmarks/sbom/fixtures.json)" sbom-benchmark:container

python3 scripts/sbom_benchmark.py \
  --config benchmarks/sbom/fixtures.json \
  --tool-metadata /tmp/tool-metadata.json \
  --output-dir /tmp/sbom-benchmark
```

The Python runner uses only the standard library. It exists because normalizing CycloneDX and SPDX, retaining complete component identities, comparing expected packages, collecting failures without stopping the matrix, and rendering deterministic JSON and Markdown are difficult to do safely with shell text processing. It is called directly by the GitHub Actions workflow and can also be run by maintainers.

## Evidence boundary

Raw generated SBOMs can contain absolute paths, tool-specific metadata, and large inventories, so they remain ephemeral workflow artifacts. Reviewed monthly history stores normalized component type, name, version, package URL, counts, timings, validation status, commands, release versions, and asset digests. No vulnerability or license-quality claim is inferred from SBOM generation alone.

Because this benchmark deliberately executes current upstream releases, the generator job receives only `contents: read`, checkout credentials are not persisted, and report publication happens in a separate job. The write-capable job consumes the runner's normalized JSON and Markdown; it does not execute the downloaded generator binaries.
