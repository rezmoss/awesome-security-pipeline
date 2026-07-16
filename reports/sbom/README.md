# SBOM benchmark reports

These are maintainer-reviewed monthly snapshots from the [SBOM compatibility benchmark](../../benchmarks/sbom/README.md). The suite still runs weekly; raw SBOMs and logs remain workflow artifacts for 90 days, while normalized monthly evidence is retained here.

[Read the latest report](latest.md) · [Download the latest normalized JSON](latest.json)

## History

| Date | Status | Fixtures / tool runs | Tool versions | Report | Data |
|---|---|---:|---|---|---|
| 2026-07-16 | PASSED | 3 / 12 | syft v1.48.0, trivy v0.72.0, cdxgen v12.7.1, microsoft-sbom-tool v4.1.5, cyclonedx-cli v0.32.0 | [report](history/2026-07-16.md) | [JSON](history/2026-07-16.json) |

A passing snapshot means the configured commands completed, documents validated structurally, minimum inventory rules passed, and every configured identity was found. It is not a security certification, vulnerability assessment, license audit, or proof of complete component discovery.
