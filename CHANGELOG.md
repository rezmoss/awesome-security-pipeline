# Changelog

This file records user-visible releases of Awesome Security Pipeline.

## v1.0.0 — 2026-07-17

The first tested release turns the repository from a tool catalog into a runnable security-pipeline reference with reproducible evidence.

### Added

- A copyable GitHub Actions baseline using Gitleaks, Semgrep, OSV-Scanner, Trivy, Syft, and keyless Cosign.
- Parallel secrets, SAST, dependency, and configuration gates followed by one immutable image build, package analysis, and trusted-event signing.
- Per-job least-privilege permissions, pinned action revisions, checksum-verified tool downloads where upstream checksums are available, and native report retention.
- Safe synthetic fixtures for reproducing secret, SAST, dependency, container, and Kubernetes findings without shipping the fixtures in the demo image.
- A 10-minute quick start, project-type selection matrix, reference-stack rationale, and detailed implementation article.
- Open-source GitHub Actions security-tool and SBOM-generator comparisons with explicit methodology and limitations.
- A weekly SBOM compatibility benchmark with normalized monthly history, raw evidence retention, and regression checks.
- Weekly repository-maintenance classification with public active, stale, unmaintained, and archived definitions.

### Verified release evidence

- The complete seven-job trusted-push path [passed on GitHub-hosted runners in 2m21s](https://github.com/rezmoss/awesome-security-pipeline/actions/runs/29529702096).
- The run retained Gitleaks and Semgrep SARIF, OSV-Scanner JSON, Trivy configuration and image SARIF, the exported image and digest, a CycloneDX SBOM, and a Sigstore bundle.
- Keyless signing was limited to a trusted push and verified against the expected GitHub OIDC issuer, repository, workflow, and Git reference.
- The [SBOM compatibility benchmark](reports/sbom/latest.md) preserves exact tool versions, tested fixtures, normalized results, and interpretation limits.
- The catalog's [maintenance status](README.md#maintenance-status-updated-weekly) is generated from the objective rules in the [curation methodology](docs/methodology.md).

### Important limits

A passing pipeline is not proof that an application is secure or compliant. The demo is not a detection-rate benchmark, and an SBOM component count is not a completeness or quality score. Fork permissions, organization policy, application languages, artifact formats, vulnerability thresholds, and evidence-retention requirements must be evaluated before adapting the baseline to production.

