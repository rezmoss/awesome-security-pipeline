# Reference Stack Decision — Baseline GitHub Actions Pipeline

**Status:** Approved for implementation  
**Decision date:** July 16, 2026  
**Target:** A useful open-source baseline for a containerized application on GitHub Actions

This is a reference implementation, not a universal ranking. The baseline favors open-source availability, non-interactive CI use, maintained upstreams, complementary output, and a setup that readers can reproduce without commercial accounts.

For a side-by-side view of permissions, SARIF behavior, maintenance, licensing boundaries, strengths, and limitations, see the [GitHub Actions security-tools comparison](../comparisons/github-actions-security-tools.md).

## Selected controls

### Secrets — Gitleaks

Gitleaks is the default secrets scanner because it supports repository and history-oriented scanning, works locally and in CI, has a widely used open-source CLI, and can stop exposed credentials before later build stages. It will run first so an obvious secret failure prevents unnecessary downstream work. The workflow must use a pinned revision, scan the intended Git history depth, and demonstrate a synthetic credential rather than a real secret.

**Alternative:** TruffleHog when verified-secret checks, broader source coverage, or its detector model better matches the project. `detect-secrets` remains a strong alternative for teams that want a committed baseline and pre-commit-centered workflow.

### Static application security testing — Semgrep

Semgrep is the baseline SAST choice because its open-source engine runs across common languages, rules are inspectable, it is straightforward to demonstrate on a small multi-language fixture, and findings can participate in CI review workflows. The recipe will document exactly which rules are used and will not imply that a default ruleset provides complete vulnerability coverage.

**Alternative:** CodeQL for repositories that prioritize GitHub-native semantic analysis, supported languages, and code-scanning integration. CodeQL may become the default for a language-specific recipe where its analysis depth outweighs setup and platform constraints.

### Dependency vulnerability scanning — OSV-Scanner

OSV-Scanner is the baseline dependency scanner because it uses the open OSV vulnerability database, understands common lockfiles, is designed for automation, and keeps dependency analysis distinct from container-image analysis. The recipe will pin a version, retain machine-readable output where practical, and use an explicit failure threshold.

**Alternative:** Grype when the pipeline benefits from one scanner across filesystems, images, and SBOM inputs, or when its database and output integrations fit downstream workflows better.

### SBOM generation — Syft

Syft is selected to generate the software bill of materials because it supports source trees, filesystems, and container images and can emit standard formats such as CycloneDX and SPDX. Keeping generation separate from vulnerability scanning makes the artifact reusable for later policy, customer, and incident-response workflows. The generated SBOM will be retained as a CI artifact with its format and source clearly identified.

**Alternative:** cdxgen for CycloneDX-centered, application-source workflows and broad language-specific analysis; Microsoft SBOM Tool for teams standardized on its SPDX-oriented workflow; Trivy when reducing tool count matters more than separating generation from scanning.

### IaC and container scanning — Trivy

Trivy is selected for infrastructure configuration and container-image scanning because a single maintained open-source CLI covers both use cases and can produce automation-friendly findings. The recipe will run configuration scanning before deployment and image scanning after build, keeping their results and policy thresholds separate so users can understand what failed.

**Alternative:** Checkov or KICS for deeper or differently curated IaC policy coverage, and Grype for image/filesystem vulnerability scanning when it is already the dependency-scanning standard.

### Artifact signing and verification — Cosign

Cosign is selected for container signing because it supports keyless GitHub Actions workflows using short-lived OIDC identity and transparency-backed verification. This avoids placing a long-lived private signing key in repository secrets. The recipe will restrict signing to trusted events, request `id-token: write` only in the signing job, and document verification separately from signing.

**Alternative:** Notation for teams standardized on the Notary Project ecosystem or registries and policy systems built around Notation signatures.

### Result integration — SARIF upload

SARIF upload is selected as the common GitHub-facing result path for scanners that emit compatible output. It gives pull-request and repository-level visibility without making SARIF the only retained artifact. Each scanner's native or JSON output will be retained when it contains details lost in conversion.

**Alternative:** Native CI annotations and uploaded JSON/HTML artifacts when a tool lacks reliable SARIF output. GitLab security-report formats and external vulnerability-management systems belong in separate recipes rather than being forced into this GitHub baseline.

## Execution order

1. Pre-commit guidance: Gitleaks and optional local Semgrep checks.
2. Pull request: Gitleaks, Semgrep, OSV-Scanner, and Trivy configuration scanning.
3. Build: create the container image only after source/configuration gates pass.
4. Package: Syft SBOM, Trivy image scan, and SARIF/native artifact retention.
5. Trusted main/tag event: Cosign keyless signing and provenance/attestation.
6. Deploy/runtime handoff: verify the signed artifact and preserve inputs for later Kubernetes policy and runtime recipes.

## Baseline success criteria

- A fresh fork can run all non-signing checks without adding a paid service or secret.
- Synthetic fixtures trigger the expected check and clean revisions pass.
- Each job declares least-privilege permissions.
- Third-party actions use immutable commit SHAs; CLI versions are explicit.
- Security artifacts are named, retained, and documented.
- Median runtime target is 10 minutes or less on the demo application, excluding queue time.
