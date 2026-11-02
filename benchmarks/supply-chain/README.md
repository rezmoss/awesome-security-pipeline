# Weekly supply-chain report

The [supply-chain report](https://rezmoss.github.io/awesome-security-pipeline/) scans every active tool in this catalog once a week and publishes what each one depends on, which known advisories match those dependencies, and what changed since the previous week. Each project has its own page with its full inventory, advisories, and history.

## What is scanned

- **Projects:** every entry in the README catalog above the *Legacy and Reference Tools* section. Adding or removing a catalog entry changes the next scan automatically.
- **Version:** the project's latest non-prerelease GitHub release tag. Projects without releases are scanned at their default branch and labelled as such. Monorepos whose latest release is not the catalogued tool are pinned to a tag pattern in [`release-tags.json`](release-tags.json).
- **Files:** only dependency manifests and lockfiles (for example `go.mod`, `package-lock.json`, `requirements*.txt`, `poetry.lock`, `Cargo.lock`, `pom.xml`, `composer.lock`) plus GitHub Actions workflows. Test, fixture, example, documentation, vendored, and benchmark directories are excluded because security tools ship deliberately vulnerable fixtures; including them inflated one scanner's matches from 10 to more than 2,000.

## How

1. A blobless, sparse checkout fetches only the selected files at the release tag. No project code is built or executed.
2. [Syft](https://github.com/anchore/syft) generates a CycloneDX SBOM.
3. [Grype](https://github.com/anchore/grype) matches the SBOM against its vulnerability database, updated at the start of every run. [OSV-Scanner](https://github.com/google/osv-scanner) scans the same files against the OSV database; Grype matches it also reports are marked as confirmed, and advisories only OSV reports are listed separately.
4. For Go tools, the Linux amd64 release binary is downloaded (and checked against GitHub's recorded digest), and [govulncheck](https://github.com/golang/vuln) analyzes it in binary mode. This reports the Go version the release was actually built with and which advisories have vulnerable functions compiled into the shipped binary. Grype's Go matches are annotated with whether their code is in the binary.
5. [zizmor](https://github.com/zizmorcore/zizmor) audits the release's GitHub Actions workflows offline; only medium- and high-confidence findings are reported.
6. [OpenSSF Scorecard](https://github.com/ossf/scorecard) results come from the OpenSSF public dataset when it is less than 30 days old. Otherwise this workflow runs the Scorecard CLI, limited by the GitHub API budget (about 100 calls per repository); earlier results are carried forward until refreshed. An optional `SCORECARD_TOKEN` repository secret raises the limit. The overview marks CLI scores with \* and carried-forward scores with †; hovering a score shows its source and date, and hovering a missing score shows why it is missing.
7. Release integrity: the same release file is checked for a Sigstore signature with [Cosign](https://github.com/sigstore/cosign) (on the file or on a signed checksums file that lists it), SLSA provenance with [slsa-verifier](https://github.com/slsa-framework/slsa-verifier), and GitHub artifact attestations with the [GitHub CLI](https://github.com/cli/cli). *Verified* requires the signing identity to be one of the project's own GitHub Actions workflows.
8. [sbomlyze](https://github.com/rezmoss/sbomlyze) scores NTIA, CISA 2025, and BSI TR-03183 minimum elements and produces an HTML diff against the previous week's SBOM. *Disclosure: sbomlyze is maintained by this repository's maintainer.*
9. Exploitation context: a read-only job downloads the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog and [FIRST EPSS](https://www.first.org/epss/) scores once per run. Each match's CVE aliases are looked up in both; the catalog version, release date, and SHA-256 of each file are recorded in the run's provenance, and both files are in the evidence release. If a download fails, the week is published without them and matches show "not checked".
10. The publish step compares each project with its previous week: new release, dependencies added, removed, or upgraded, license changes, new and resolved advisories, vulnerable functions added to or removed from the binary, Scorecard and release-verification changes, new workflow findings, advisories newly listed in KEV, and hashes that changed without a version change.

All tools are installed from their latest release and verified against upstream checksums, GitHub's recorded asset digest, or (for govulncheck) the Go checksum database. The scan jobs have read-only permissions; the job that writes the `supply-chain-data` branch only runs this repository's Python on the scan output.

## Reading the results

- An advisory match means a declared dependency version is listed as affected. It does not mean the tool is exploitable: the code may be unused, test-only, a development dependency, or not compiled into the released binary.
- Dependency counts include development, build, and CI dependencies declared in the scanned files.
- Dependency and advisory results describe the release source. The *In binary* column and section describe the shipped Linux binary of Go tools; other ecosystems are not analyzed for reachability.
- zizmor findings are patterns to review, not confirmed vulnerabilities.
- Scorecard scores reflect repository practices on the assessment date shown, which can be up to 30 days old.
- Severity columns count matches, not advisories: one advisory that affects two packages in a tool counts twice. *Unknown* includes Grype's unknown and negligible severities, so the columns add up to every match. *Vulnerable packages* counts distinct package versions with at least one match.
- KEV and EPSS describe a CVE in general (known exploitation somewhere; estimated probability of exploitation in the next 30 days). They say nothing about whether the tool exposes the vulnerable code. A match in a workflow file is a GitHub Action reference, not a dependency of the shipped tool.

## Advisory pages

Every matched advisory has a page at `advisories/<id>/` listing each catalog tool it matches, the package and version, the fixed version, where it is declared, and whether the vulnerable code is in the tool's release binary (Go tools only; others show *not analyzed*). GHSA, Go, and CVE ids that alias each other are merged into one page, named by the GHSA id when there is one. The [advisory index](https://rezmoss.github.io/awesome-security-pipeline/advisories/) sorts and filters by severity, number of tools, shipped code, KEV, and EPSS.

## Feeds, exports, and badges

- Atom feeds: `feed.xml` (one entry per weekly run) and `projects/<owner>/<repo>/feed.xml` (one entry per week in which that project changed).
- CSV: `data/projects.csv`, `data/matches.csv` (one row per project and advisory match), and `data/advisories.csv`. They are derived from the attested JSON when the site is built and are not attested themselves. Cells that a spreadsheet would read as a formula are prefixed with `'`.
- Badges: [shields.io endpoint](https://shields.io/badges/endpoint-badge) files at `badges/<owner>/<repo>/release.json` (release verification) and `badges/<owner>/<repo>/in-binary.json` (Go tools: advisories with vulnerable code in the binary). Each project page shows the Markdown to embed them.

## Data

- Site: <https://rezmoss.github.io/awesome-security-pipeline/>
- `supply-chain-data` branch: `projects/<owner>__<repo>.json` (latest inventory, advisories, history), `runs/<date>.json` (weekly summary with the workflow run, commit, runner image, and vulnerability-database versions that produced it), `runs/superseded/` (runs replaced by a re-run of the same week), and `SHA256SUMS`.
- Raw evidence for every week from 2026-11-08: an immutable GitHub release `report-<date>` (not marked latest) holding the SBOMs, Grype, OSV-Scanner, and govulncheck output, sbomlyze diffs, and release-integrity details, with the data branch's `SHA256SUMS`. The tag points at the data commit it belongs to. Workflow artifacts are also retained for 90 days, and the latest set is on each project page.

## Publishing rules

- Only the Sunday schedule and a manual dispatch with *publish* selected record data. Pull requests scan a four-project sample and build a preview; pushes to `main` only rebuild the site from the recorded data.
- A second run for the same week replaces it: the replaced summary moves to `runs/superseded/<date>/`, the change comparison still uses the previous week, and the re-run appears on the [corrections page](https://rezmoss.github.io/awesome-security-pipeline/corrections/) with its reason.
- The data branch and `report-*` tags are protected against force-push and deletion.

## Verifying the data

Every data file and evidence bundle has a [GitHub artifact attestation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations) from the report workflow, logged in the public Sigstore transparency log:

```bash
git clone --branch supply-chain-data https://github.com/rezmoss/awesome-security-pipeline.git report-data && cd report-data
gh attestation verify SHA256SUMS --repo rezmoss/awesome-security-pipeline \
  --signer-workflow rezmoss/awesome-security-pipeline/.github/workflows/supply-chain-report.yml
sha256sum -c SHA256SUMS
python3 ../scripts/supply_chain_scan.py verify --data-dir . --history --attestations   # from a checkout of this repository
```

`verify` recomputes each run summary from the project files, checks `SHA256SUMS`, confirms that every data commit only appended (earlier weeks never rewritten, nothing deleted) and that every evidence release tag is still in the branch history, and verifies the attestation. It runs before every publish and weekly in `supply-chain-verify.yml`. An attestation proves which workflow, commit, and run produced the bytes; it does not prove the scanners are right. See the [verification page](https://rezmoss.github.io/awesome-security-pipeline/verify/).

## Corrections

Every advisory match has a **Dispute** link that opens a prefilled [finding dispute](https://github.com/rezmoss/awesome-security-pipeline/issues/new?template=report-finding-dispute.yml) issue. A resolved dispute is recorded under `disputes` in [`corrections.json`](corrections.json) and shown on the match and on the corrections page; the match itself is never removed from the data.

Manual overrides are listed on the [corrections page](https://rezmoss.github.io/awesome-security-pipeline/corrections/): release tag pins ([`release-tags.json`](release-tags.json), each with a reason, date, and pull request), catalog exceptions, re-run weeks, and other corrections recorded in [`corrections.json`](corrections.json). A unit test fails if an override has no entry.

## Run locally

```bash
python3 scripts/supply_chain_scan.py targets --output /tmp/targets.json --shards 1 --only gitleaks/gitleaks
python3 scripts/supply_chain_scan.py scan --targets /tmp/targets.json --shard 0 --output-dir /tmp/scan
python3 scripts/supply_chain_scan.py enrich --output-dir /tmp/enrichment        # optional: KEV and EPSS
python3 scripts/supply_chain_scan.py publish --shards-dir /tmp/scan --data-dir /tmp/data --enrichment-dir /tmp/enrichment
python3 scripts/build_site.py --output /tmp/site --supply-chain-data /tmp/data --supply-chain-artifacts /tmp/scan
python3 scripts/supply_chain_scan.py verify --data-dir /tmp/data
```

Requires `gh` (authenticated), `git`, `go`, and the tools above on `PATH`; `scripts/install-supply-chain-tools.sh` installs them on Linux.
