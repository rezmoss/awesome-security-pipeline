# SBOM compatibility benchmark

This benchmark runs Syft, Trivy, cdxgen, and Microsoft SBOM Tool against the same deterministic inputs, validates their output, scores it against an inventory read directly from each input, and publishes the results at **[rezmoss.github.io/awesome-security-pipeline/sbom-benchmark](https://rezmoss.github.io/awesome-security-pipeline/sbom-benchmark/)**. It is designed to show what each generator gets right and wrong on the same input and to detect behavior changes over time, not to reward the largest component count.

## Fixtures

| Fixture | What it tests | Ground truth |
|---|---|---|
| `go-direct-lockless` | Manifest discovery without a lockfile, vendor tree, or downloaded modules | The declared Go dependency; missing it fails the run |
| `npm-lock-transitive` | npm lockfile parsing and transitive dependency retention | Both locked packages and the `is-odd → is-number` edge; missing any fails the run |
| `pinned-container-image` | Container and operating-system package inventory from an immutable Linux/amd64 image | The 17 packages in the image's apk database (`/lib/apk/db/installed`) plus the Go toolchain from `/usr/local/go/VERSION` |

The image fixture uses the immutable Linux/amd64 manifest resolved from the OCI index already pinned by the security demo's Dockerfile. Both digests are recorded in `fixtures.json`. The workflow pulls that exact platform manifest once and gives every generator the same local tag.

The container ground truth is derived without any SBOM generator by [`scripts/derive_image_ground_truth.py`](../../scripts/derive_image_ground_truth.py), and every run re-derives it from the pulled image and fails if `fixtures.json` disagrees. When the pinned digest changes, regenerate it with `--write`.

## Scoring

For every fixture and generator the benchmark records:

- **Ground truth found:** expected identities matched by name and version (cosmetic `v`/`go` version prefixes are ignored).
- **Reported but not installed:** apk packages a generator lists for the image that are absent from its package database.
- **Missing identifiers:** package-level components without a package URL or without a version.
- **Minimum elements:** NTIA (2021), CISA (2025), and BSI TR-03183 checks on each document, computed by [sbomlyze](https://github.com/rezmoss/sbomlyze). *Disclosure: sbomlyze is maintained by this repository's maintainer.* It is used only for minimum-element checks and week-over-week drift classification, it is not ranked, and every score is published with its individual checks. Ground-truth scoring is done by this repository's own normalizer.
- **Change from the previous run:** package-level identities and dependency edges added or removed. File and cryptographic-asset entries are compared as a count and a digest so they do not hide package changes. sbomlyze additionally classifies version, integrity (hash changed without a version change), and metadata drift.

The run fails the regression gate when a generator or validator fails, a document is empty, a source-fixture identity or edge is missing, or a generator loses a container ground-truth identity that it found in the previous run. Known gaps that have always existed are reported, not failed.

## Cadence and publication

- The full suite runs every Sunday, on pushes to `main` that change the benchmark, and on relevant pull requests.
- Every run on `main` is recorded in the `sbom-benchmark-data` branch as one compact normalized JSON file and the site is rebuilt and deployed to GitHub Pages. Pull requests build a site preview artifact without publishing.
- The site has an overview of the latest run, a page per generator with its history, a history index, a frozen page per run, the latest generated SBOMs, sbomlyze HTML diffs, and the JSON data.
- Raw SBOMs and logs for every run are retained as workflow artifacts for 90 days.
- A failed run is still recorded and published, with the failures shown at the top of the page.

Tool releases are resolved from each project's latest non-prerelease GitHub release at run time. Syft, Trivy, cdxgen, and sbomlyze assets are verified with upstream SHA-256 files, and sbomlyze also with its GitHub build-provenance attestation. Microsoft SBOM Tool and CycloneDX CLI do not currently attach separate checksum files; their downloaded SHA-256 digests are recorded in every result. Each run therefore states exactly what was executed.

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

python3 scripts/sbomlyze_compare.py \
  --result /tmp/sbom-benchmark/result.json \
  --raw-dir /tmp/sbom-benchmark/raw \
  --output-dir /tmp/sbom-benchmark/sbomlyze

python3 scripts/publish_sbom_benchmark.py \
  --data-dir /tmp/sbom-data \
  --config benchmarks/sbom/fixtures.json \
  --result /tmp/sbom-benchmark/result.json \
  --sbomlyze /tmp/sbom-benchmark/sbomlyze/sbomlyze.json

python3 scripts/build_sbom_site.py \
  --data-dir /tmp/sbom-data \
  --config benchmarks/sbom/fixtures.json \
  --artifacts-dir /tmp/sbom-benchmark/sbomlyze \
  --output /tmp/sbom-site
```

Open `/tmp/sbom-site/sbom-benchmark/index.html` to view the result.

The Python scripts use only the standard library. The runner exists because normalizing CycloneDX and SPDX, retaining complete component identities, comparing expected packages, collecting failures without stopping the matrix, and rendering deterministic JSON and Markdown are difficult to do safely with shell text processing. It is called directly by the GitHub Actions workflow and can also be run by maintainers.

## Evidence boundary

Raw generated SBOMs can contain absolute runner paths, so the published copies replace them with placeholders such as `$REPOSITORY`. The data branch stores normalized package-level identities, scores, file and cryptographic-asset counts with a digest, commands, release versions, and asset digests. No vulnerability or license-quality claim is inferred from SBOM generation alone.

Because this benchmark deliberately executes current upstream releases, every downloaded binary runs only in the generator job, which receives `contents: read` and `actions: read` and does not persist checkout credentials. The jobs that write the data branch and deploy the site run only repository Python on the normalized JSON; they never execute the downloaded tools.
