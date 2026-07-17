# Building a Verified Open-Source Security Pipeline in GitHub Actions

**Tested:** July 16, 2026  
**Measured result:** [seven jobs passed in 2m21s](https://github.com/rezmoss/awesome-security-pipeline/actions/runs/29529702096)  
**Implementation:** [security-baseline.yml](../../.github/workflows/security-baseline.yml)

A list of security tools can tell you what exists. It does not tell you which controls should block a build, what evidence should survive the run, or when a workflow is trusted enough to sign an artifact.

We built a small open-source DevSecOps pipeline to answer those implementation questions. The GitHub Actions workflow uses Gitleaks for secrets, Semgrep for SAST, OSV-Scanner for dependency vulnerabilities, Trivy for configuration and image scanning, Syft for a CycloneDX SBOM, and Cosign for keyless signing. It needs no custom secret, cloud account, registry, or deployed service for the included demo.

The useful result is not that six tools can produce green checks. It is a pipeline contract: source gates run before the build, packaging operates on the exact exported image, every control retains reviewable evidence, and signing is isolated to trusted pushes.

## The pipeline contract

The workflow starts with `permissions: {}` and grants permissions per job. Four independent source checks run in parallel. The image build cannot begin until all four pass; SBOM generation and image scanning cannot begin until the build passes; keyless signing is available only after packaging on a trusted `main` or version-tag push.

| Stage | Control | Blocking policy | Retained evidence |
|---|---|---|---|
| Source | Gitleaks | Any non-allowlisted secret finding | Redacted SARIF |
| Source | Semgrep | Any finding from the committed high-confidence rules | SARIF |
| Dependencies | OSV-Scanner | Any published vulnerability in a discovered dependency | Native JSON |
| Configuration | Trivy | `HIGH` or `CRITICAL` Dockerfile/Kubernetes misconfiguration | SARIF |
| Build | Docker Buildx | Any source gate or build failure | Exported image tar and immutable digest |
| Package | Syft and Trivy | SBOM failure or fixed `HIGH`/`CRITICAL` image vulnerability | CycloneDX JSON and image SARIF |
| Trusted release | Cosign | Signing or exact-identity verification failure | Sigstore bundle |

All jobs have a ten-minute timeout. Scanner crashes, malformed output, and database-download failures fail the relevant job rather than being converted into an empty successful report. Reports are retained for 14 days in the demonstration workflow; production retention should follow the organization's investigation and release-evidence requirements.

## What the measured run showed

The [successful trusted-push run](https://github.com/rezmoss/awesome-security-pipeline/actions/runs/29529702096) began at 19:52:14 UTC and completed at 19:54:35 UTC on GitHub-hosted runners.

| Job | Observed job duration | Position in the dependency graph |
|---|---:|---|
| Dependencies / OSV-Scanner | 4s | Parallel source gate |
| Secrets / Gitleaks | 16s | Parallel source gate |
| IaC / Trivy configuration | 19s | Parallel source gate |
| SAST / Semgrep | 33s | Parallel source gate |
| Build / immutable image | 65s | After all source gates |
| Package / SBOM and image scan | 25s | After build |
| Release / keyless Cosign signature | 8s | After package, trusted push only |

The critical path was Semgrep setup, image build/export, package analysis, then signing—not the sum of every scanner duration. Parallel source gates kept the complete path to 2m21s even though the seven job durations total substantially more.

This is one small Go application on one hosted run, not a general performance benchmark. Repository size, languages, cache state, runner availability, registry access, and vulnerability-database downloads will change the result. The durable finding is architectural: independent source controls can run concurrently, while build, package, and signing stages should remain ordered around the artifact they evaluate.

The run retained the Gitleaks, Semgrep, OSV-Scanner, and Trivy configuration reports; the exported image and digest; the CycloneDX SBOM and Trivy image report; and the Cosign bundle. SARIF was also uploaded to GitHub code scanning where the event token allowed it.

## Five implementation decisions that mattered

### 1. Gate source before spending time on the image

Secrets, SAST, dependency, and configuration checks do not depend on a built container. Running them in parallel gives fast feedback and prevents a known-bad source revision from reaching the more expensive build and package stages.

The build job declares:

```yaml
needs: [secrets, sast, dependencies, iac]
```

Packaging then consumes the exported image from the build job rather than rebuilding it. The digest recorded during the build therefore identifies the same artifact used for SBOM generation, vulnerability scanning, and signing.

### 2. Separate scanning permission from result-publishing permission

CLI scanners need repository contents, not broad write access. The workflow removes default permissions globally and adds only what each job uses:

```yaml
permissions: {}

jobs:
  dependencies:
    permissions:
      contents: read

  sast:
    permissions:
      contents: read
      security-events: write

  sign:
    permissions:
      contents: read
      id-token: write
```

`security-events: write` exists to publish SARIF; it is not required to run Semgrep, Gitleaks, or Trivy. `id-token: write` exists only in the signing job so Cosign can request a short-lived GitHub OIDC identity. It is not granted to pull-request scanning jobs.

Fork pull requests normally do not receive the write token needed for third-party SARIF upload. The workflow still retains native reports as downloadable artifacts, so loss of the GitHub presentation layer does not erase the scanner evidence.

### 3. Keep native evidence even when SARIF is available

SARIF is useful for GitHub code-scanning presentation, but it is not a universal interchange format for every security decision. The baseline keeps OSV-Scanner JSON because it preserves advisory and package detail, keeps CycloneDX JSON because an SBOM is an inventory rather than a findings report, and keeps the Cosign bundle because signature verification requires identity material—not a code alert.

A green job without a usable output is difficult to review after the runner disappears. Named artifacts make the result inspectable and let later jobs consume the exact build output instead of recreating it.

### 4. Test detection without shipping vulnerable code

The [demo application](../../examples/security-demo/README.md) is a small Go service with no third-party Go dependency and a non-root `scratch` runtime image. Synthetic secret, SAST, vulnerable-dependency, and configuration examples live under `fixtures/`; they are never compiled into or copied into the image.

Each fixture has a direct reproduction command and expected non-zero result. The normal baseline remains green because controlled findings are isolated or explicitly allowlisted. To test a blocking path, copy one fixture into the corresponding scanned application path on a temporary branch, observe the expected failure, then revert it.

This avoids two misleading extremes: a permanently red demonstration that cannot prove the clean path, and a permanently green demonstration that never proves its rules detect anything.

### 5. Sign identity and artifact, not merely “the build”

Manual runs and pull requests intentionally skip signing. A trusted push to `main` or a `v*` tag signs the exported image tar with keyless Cosign, then verifies the bundle against the expected GitHub OIDC issuer and the exact repository, workflow, and Git ref identity.

Signing does not prove that an artifact is secure. It binds bytes to an identity under a declared event policy. If pull-request output can obtain the same trusted signing identity as a protected release, the cryptography is working but the trust design is not.

## The SBOM result changed how we interpret tool output

The baseline uses Syft because SBOM generation is kept separate from vulnerability policy. We also run a [weekly SBOM compatibility benchmark](../../reports/sbom/README.md) across Syft, Trivy, cdxgen, and Microsoft SBOM Tool so that the selection does not depend only on feature tables.

The first normalized snapshot ran all four generators against a lockless Go manifest, an npm lockfile with a known transitive edge, and one pinned Linux/amd64 container image. All 12 generator/fixture combinations passed their configured expectations, but container component counts ranged from 18 for Microsoft SBOM Tool to 375 for cdxgen. Dependency-edge counts ranged from 17 to 368.

Those differences are not a ranking. The generators model operating-system packages, application packages, files, cryptographic assets, subjects, and relationships differently. A larger SBOM is not automatically more complete or more useful.

The practical checks are narrower and reproducible:

- Did the generator preserve the exact direct and transitive package identities we planted?
- Did it retain the known `is-odd@3.0.1 → is-number@6.0.0` dependency edge?
- Did the document validate against its declared CycloneDX or SPDX structure?
- Can a version or configuration change be compared with the previous normalized snapshot?

That is why the repository publishes the [complete dated report](../../reports/sbom/latest.md), exact tool versions and release-asset digests, interpretation limits, and 90-day raw workflow evidence.

## How to adapt the baseline safely

Start by running the unchanged demonstration. It separates “the reference workflow works” from “our application-specific edits work.” The [10-minute quick start](../../README.md#10-minute-quick-start) requires only a fork with GitHub Actions enabled.

For another repository, copy:

```text
.github/workflows/security-baseline.yml
.gitleaks.toml
.semgrep/security-baseline.yml
examples/security-demo/
```

Then make deliberate changes in this order:

1. Replace `examples/security-demo/app` with the real source, manifest, configuration, and build paths.
2. Remove controls that do not apply. A non-containerized library does not need an image scan merely to make the workflow look complete.
3. Adjust rules and severity policy using reviewed findings, not by globally ignoring the first noisy run.
4. Preserve separate outputs for secrets, SAST, dependencies, configuration, image inventory, and signatures.
5. Keep `id-token: write` isolated to trusted signing events and verify the exact expected identity.
6. Re-run the synthetic fixtures or equivalent safe tests whenever rules, versions, paths, or failure thresholds change.

The [stack comparison](../../comparisons/github-actions-security-tools.md) explains where CodeQL can replace Semgrep, where Grype can replace or complement OSV-Scanner/Trivy, and when Syft or Cosign should be omitted entirely.

## What this pipeline does not prove

A successful run does not prove that the application is secure, that every dependency was discovered, or that every relevant vulnerability exists in an upstream database. It is not a compliance certification, a comparative detection benchmark, or evidence that this six-tool stack is correct for every project.

It does establish something smaller and operationally useful: one declared revision passed one reproducible set of source, dependency, configuration, image, inventory, and identity checks; the workflow retained the outputs needed to inspect that claim; and the signed artifact can be verified against a specific trusted workflow identity.

That is a stronger starting point than an untested tool checklist—and a much easier one to adapt, measure, and correct.

## Reproduce the result

- [Run the 10-minute quick start](../../README.md#10-minute-quick-start)
- [Inspect the complete workflow contract](../../examples/security-demo/README.md#workflow-contract)
- [Review the successful 2m21s run](https://github.com/rezmoss/awesome-security-pipeline/actions/runs/29529702096)
- [Compare the selected GitHub Actions tools](../../comparisons/github-actions-security-tools.md)
- [Inspect the latest SBOM compatibility evidence](../../reports/sbom/latest.md)
