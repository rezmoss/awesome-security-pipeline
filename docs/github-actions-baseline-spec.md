# Build the tested GitHub Actions baseline security pipeline

## Goal

Create the first runnable reference recipe promised by Awesome Security Pipeline: a least-privilege GitHub Actions workflow that applies complementary open-source controls from pull request through signed package.

The approved tool decisions and alternatives are documented in `docs/reference-stack.md`.

## Required controls

- Gitleaks for secrets detection.
- Semgrep for baseline SAST, with CodeQL documented as an alternative.
- OSV-Scanner for dependency vulnerability scanning, with Grype documented as an alternative.
- Trivy for IaC/configuration and built-image scanning.
- Syft for a retained CycloneDX or SPDX SBOM.
- SARIF upload for tools with reliable compatible output, plus native output where conversion loses detail.
- Cosign keyless signing on trusted main/tag events only.

## Permissions

Start with `contents: read` and grant permissions per job rather than workflow-wide wherever possible.

- `security-events: write` only for jobs uploading SARIF.
- `id-token: write` only for the trusted signing/attestation job.
- `packages: write` only if the recipe publishes an image to GHCR.
- No write permission for workflows triggered from untrusted pull requests.

The recipe must explain why each non-read permission exists.

## Expected artifacts

- Secrets scan result or documented console result.
- Semgrep SARIF and native result where useful.
- OSV-Scanner machine-readable result.
- Trivy configuration SARIF/JSON.
- Built container image identified by immutable digest.
- Syft SBOM in a named CycloneDX or SPDX format.
- Trivy image SARIF/JSON.
- Cosign signature and verification instructions on eligible events.
- A concise job summary linking to retained artifacts.

Artifacts must have explicit names and retention periods and must not contain secrets.

## Failure behavior

- Synthetic committed credentials fail the secrets job before build.
- High-confidence SAST fixtures fail according to the documented ruleset.
- Dependency and image checks use an explicit severity/policy threshold; ignored findings require a versioned justification.
- IaC misconfigurations fail independently from image vulnerabilities.
- Signing never runs for untrusted pull requests and cannot turn a failed security gate green.
- Tool crashes, invalid output, and database-download failures fail visibly rather than being silently treated as a clean scan.

## Runtime target

The median end-to-end runtime on the demo application should be 10 minutes or less on GitHub-hosted runners, excluding queue time. Independent checks should run in parallel after a lightweight setup phase. Record cold and warm-cache timings before declaring the target met.

## Test application

Add a small, non-deployed demo application containing controlled fixtures for:

- a synthetic secret pattern;
- a deterministic SAST finding;
- a known vulnerable test dependency;
- an insecure IaC or container configuration;
- a container image with a measurable vulnerability result.

No real credential, active exploit service, malware, or internet-exposed vulnerable deployment is permitted. The fixture must document how to remove or remediate each finding so both failing and passing pipeline states can be reproduced.

## Acceptance criteria

- [ ] Workflow and demo fixture are committed under clear recipe/example paths.
- [ ] All third-party actions are pinned to full commit SHAs and all CLIs use explicit versions.
- [ ] Every job uses the minimum documented permissions.
- [ ] A fresh fork runs all non-signing checks without paid accounts or custom secrets.
- [ ] Each controlled fixture triggers the intended scanner.
- [ ] A remediated revision passes all required gates.
- [ ] SBOM, scan results, image digest, and job summary are retained and documented.
- [ ] Keyless signing runs only on a trusted main/tag event and has separate verification instructions.
- [ ] Cold and warm execution times are recorded; median target is evaluated honestly.
- [ ] README quick start explains setup, outputs, failure modes, limitations, and cleanup.
- [ ] At least three unaffiliated practitioners reproduce the workflow from a fresh fork before launch.
