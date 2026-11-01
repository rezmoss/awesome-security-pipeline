# Weekly supply-chain report

The [supply-chain report](https://rezmoss.github.io/awesome-security-pipeline/) scans every active tool in this catalog once a week and publishes what each one depends on, which known advisories match those dependencies, and what changed since the previous week. Each project has its own page with its full inventory, advisories, and history.

## What is scanned

- **Projects:** every entry in the README catalog above the *Legacy and Reference Tools* section. Adding or removing a catalog entry changes the next scan automatically.
- **Version:** the project's latest non-prerelease GitHub release tag. Projects without releases are scanned at their default branch and labelled as such. Monorepos whose latest release is not the catalogued tool are pinned to a tag pattern in [`release-tags.json`](release-tags.json).
- **Files:** only dependency manifests and lockfiles (for example `go.mod`, `package-lock.json`, `requirements*.txt`, `poetry.lock`, `Cargo.lock`, `pom.xml`, `composer.lock`) plus GitHub Actions workflows. Test, fixture, example, documentation, vendored, and benchmark directories are excluded because security tools ship deliberately vulnerable fixtures; including them inflated one scanner's matches from 10 to more than 2,000.

## How

1. A blobless, sparse checkout fetches only the selected files at the release tag. No project code is built or executed.
2. [Syft](https://github.com/anchore/syft) generates a CycloneDX SBOM.
3. [Grype](https://github.com/anchore/grype) matches the SBOM against its vulnerability database, which is updated at the start of every run.
4. [sbomlyze](https://github.com/rezmoss/sbomlyze) scores NTIA, CISA 2025, and BSI TR-03183 minimum elements and produces an HTML diff against the previous week's SBOM. *Disclosure: sbomlyze is maintained by this repository's maintainer.*
5. The publish step compares each project with its previous week: new release, dependencies added, removed, or upgraded, license changes, new and resolved advisories, and hashes that changed without a version change.

All tools are installed from their latest GitHub release and verified against upstream checksums (sbomlyze also against its build-provenance attestation). The scan jobs have read-only permissions; the job that writes the `supply-chain-data` branch only runs this repository's Python on the scan output.

## Reading the results

- An advisory match means a declared dependency version is listed as affected. It does not mean the tool is exploitable: the code may be unused, test-only, a development dependency, or not compiled into the released binary.
- Dependency counts include development, build, and CI dependencies declared in the scanned files.
- Results describe the release source, not a container image or binary built from it.

## Data

- Site: <https://rezmoss.github.io/awesome-security-pipeline/>
- `supply-chain-data` branch: `projects/<owner>__<repo>.json` (latest inventory, advisories, history) and `runs/<date>.json` (weekly summary).
- Raw SBOMs, Grype reports, and sbomlyze diffs for every run: workflow artifacts, retained for 90 days; the latest set is also on each project page.

## Run locally

```bash
python3 scripts/supply_chain_scan.py targets --output /tmp/targets.json --shards 1 --only gitleaks/gitleaks
python3 scripts/supply_chain_scan.py scan --targets /tmp/targets.json --shard 0 --output-dir /tmp/scan
python3 scripts/supply_chain_scan.py publish --shards-dir /tmp/scan --data-dir /tmp/data
python3 scripts/build_site.py --output /tmp/site --supply-chain-data /tmp/data --supply-chain-artifacts /tmp/scan
```

Requires `gh` (authenticated), `git`, `syft`, `grype`, and `sbomlyze` on `PATH`.
