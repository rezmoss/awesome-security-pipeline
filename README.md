# Awesome Security Pipeline

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)
[![License: CC0-1.0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg)](http://creativecommons.org/publicdomain/zero/1.0/)
[![Security Baseline](https://github.com/rezmoss/awesome-security-pipeline/actions/workflows/security-baseline.yml/badge.svg)](https://github.com/rezmoss/awesome-security-pipeline/actions/workflows/security-baseline.yml)

> The practical, continuously verified guide to selecting and implementing open-source security tools at every CI/CD pipeline stage.

<!-- catalog-stats:start -->**78 actively maintained tools · 15 legacy references · status and supply-chain checks refreshed weekly**<!-- catalog-stats:end -->

Start with a working pipeline, not an empty checklist. The included GitHub Actions baseline runs Gitleaks, Semgrep, OSV-Scanner, Trivy, Syft, and keyless Cosign against a safe demo, retains machine-readable evidence, and [passed end to end in 2m21s](https://github.com/rezmoss/awesome-security-pipeline/actions/runs/29529702096) on GitHub-hosted runners.

**Maintenance promise:** repository status is checked weekly, license and documentation evidence monthly, and the tested recipe after every relevant change and at least monthly. Classification rules and exceptions are public in the [methodology](docs/methodology.md).

[**Run the tested pipeline →**](#10-minute-quick-start) · [Choose controls for your project](#choose-your-baseline) · [Browse tools by pipeline stage](#tool-catalog) · [Read the verification methodology](docs/methodology.md)

**[Weekly supply-chain report →](https://rezmoss.github.io/awesome-security-pipeline/)** Every tool in this list is scanned each week at its latest release: dependencies and known vulnerabilities, vulnerable code in the shipped binary, release signature verification, OpenSSF Scorecard, a GitHub Actions workflow audit, and what changed since last week. [Method](benchmarks/supply-chain/README.md).

[![Security controls from commit through signed package](assets/security-pipeline-architecture.svg)](assets/security-pipeline-architecture.svg)

## Start here

| If you want to… | Start with |
|---|---|
| See a complete working implementation | [10-minute quick start](#10-minute-quick-start) |
| Understand the architecture and measured implementation findings | [Technical implementation article](docs/articles/verified-open-source-security-pipeline.md) |
| Understand every job, artifact, permission, and failure mode | [Security demo guide](examples/security-demo/README.md) |
| Review user-visible release changes and verification evidence | [Changelog](CHANGELOG.md) |
| Choose a smaller or more specialized stack | [Project-type selection matrix](#choose-your-baseline) |
| Compare GitHub Actions security tools and permissions | [Open-source stack comparison](comparisons/github-actions-security-tools.md) |
| Choose an SBOM generator and validation workflow | [SBOM tools comparison](comparisons/sbom-tools.md) |
| See every listed tool's dependencies, known vulnerabilities, and week-over-week changes | [Weekly supply-chain report](https://rezmoss.github.io/awesome-security-pipeline/) |
| Evaluate why these tools were selected | [Reference stack decision](docs/reference-stack.md) |
| Check how projects are selected and classified | [Curation and verification methodology](docs/methodology.md) |

## 10-minute quick start

The fastest safe trial is to run the committed demo in a fork. It requires only a GitHub account and GitHub Actions; it requires no cloud account, custom secret, registry, or deployment.

1. Fork this repository and enable GitHub Actions in the fork.
2. Open **Actions → Security Baseline → Run workflow** and select the default branch.
3. Confirm the Secrets, SAST, Dependencies, IaC, Build, and Package jobs pass.
4. Inspect the named scan reports, CycloneDX SBOM, exported image, and immutable digest under **Artifacts**.
5. To test keyless signing, push the unchanged workflow to the fork's default branch or a `v*` tag. Manual and pull-request runs intentionally skip signing.

To adapt the baseline in another repository, copy these paths first, then change the `examples/security-demo/app` scan and build paths to your application:

```text
.github/workflows/security-baseline.yml
.gitleaks.toml
.semgrep/security-baseline.yml
examples/security-demo/        # replace after the first green run
```

The default policy fails on detected secrets, configured high-confidence SAST findings, any published dependency vulnerability, and fixed HIGH/CRITICAL configuration or image findings. SARIF upload requires GitHub code scanning support; all reports remain downloadable workflow artifacts. See the [demo guide](examples/security-demo/README.md) before changing thresholds or permissions.

## Choose your baseline

Use the smallest set that covers the artifacts you actually ship. “Regulated” below is a starting architecture, not a compliance claim.

| Project type | Start with | Add when applicable | Why |
|---|---|---|---|
| Library | Gitleaks, Semgrep, OSV-Scanner | Syft for release SBOMs; Cosign for signed release files | Protect source and dependencies without container-only stages. |
| Web application | Gitleaks, Semgrep, OSV-Scanner | ZAP against a controlled test deployment | Combine source/dependency gates with explicit dynamic testing. |
| Container service | Tested baseline: Gitleaks, Semgrep, OSV-Scanner, Trivy, Syft, Cosign | Runtime detection such as Falco when operating the service | Cover source, image, SBOM, and signed-package risks. |
| Kubernetes service | Container-service baseline | Trivy manifest scanning, Kyverno or Gatekeeper admission policy, runtime detection | Separate build-time evidence from cluster admission and runtime controls. |
| Regulated project | Relevant baseline above with retained SARIF, SBOM, digest, and signature | Organization-specific policy, approvals, provenance, and evidence retention | Produce reviewable evidence while leaving control mapping to the applicable framework. |

## Contents

- [Start here](#start-here)
- [10-minute quick start](#10-minute-quick-start)
- [Choose your baseline](#choose-your-baseline)
<!-- catalog-toc:start -->
- [Tool catalog](#tool-catalog)
- [Pre-commit & Secrets Detection](#pre-commit--secrets-detection)
- [SBOM Generation](#sbom-generation)
- [Artifact Signing & Verification](#artifact-signing--verification)
- [Supply Chain Compliance](#supply-chain-compliance)
- [Software Composition Analysis (SCA)](#software-composition-analysis-sca)
- [Static Application Security Testing (SAST)](#static-application-security-testing-sast)
  - [Multi-language](#multi-language)
  - [Language-specific](#language-specific)
- [Infrastructure as Code Security](#infrastructure-as-code-security)
- [Container Security](#container-security)
  - [Image Scanning](#image-scanning)
  - [Runtime Security](#runtime-security)
- [Kubernetes Security](#kubernetes-security)
- [Policy as Code](#policy-as-code)
- [Secret Management](#secret-management)
- [API & Dynamic Testing (DAST)](#api--dynamic-testing-dast)
- [Cloud Security](#cloud-security)
- [Legacy and Reference Tools](#legacy-and-reference-tools)
<!-- catalog-toc:end -->
- [Contributing](#contributing)
- [License](#license)

---

<!-- catalog:start -->
## Tool catalog

Entries are organized by where they operate in a delivery pipeline. Status reflects repository activity, not security effectiveness; stars indicate adoption, not quality. Multi-purpose tools may appear in more than one category with a category-specific description.

**Status:** 🟢 Active (commit in the last 6 months) · 🟡 Stale (6–12 months) · 🔴 Unmaintained (over 12 months) · ⚪ Archived. Unmaintained and archived tools move to [Legacy](#legacy-and-reference-tools) automatically and return when they are active again. **Scorecard** (OpenSSF, out of 10) and **Release** (whether the Linux release file's signature, provenance, or attestation verifies) come from the [weekly supply-chain report](https://rezmoss.github.io/awesome-security-pipeline/); select a Scorecard value for the tool's full report. Every column is refreshed weekly from each tool's file in [`tools/`](tools/).

## Pre-commit & Secrets Detection

Catch secrets and credentials before they enter your repository.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**detect-secrets**](https://github.com/Yelp/detect-secrets) | Prevent secrets from entering codebases | 🟡&nbsp;Stale<br><sub>Apr 2026</sub> | 4.7k | [3.5](https://rezmoss.github.io/awesome-security-pipeline/projects/Yelp/detect-secrets/) | — |
| [**gitleaks**](https://github.com/gitleaks/gitleaks) | Detect and prevent secrets in git repos | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 30.6k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/gitleaks/gitleaks/) | Checksums |
| [**pre-commit**](https://github.com/pre-commit/pre-commit) | Manage multi-language pre-commit hooks | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 15.7k | [4.5](https://rezmoss.github.io/awesome-security-pipeline/projects/pre-commit/pre-commit/) | — |
| [**talisman**](https://github.com/thoughtworks/talisman) | Detect secrets with pre-push and pre-commit hooks | 🟡&nbsp;Stale<br><sub>Nov 2025</sub> | 2.1k | [3.3](https://rezmoss.github.io/awesome-security-pipeline/projects/thoughtworks/talisman/) | Checksums |
| [**trufflehog**](https://github.com/trufflesecurity/trufflehog) | Find credentials in git history and live systems | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 28.8k | [7.9](https://rezmoss.github.io/awesome-security-pipeline/projects/trufflesecurity/trufflehog/) | ✓&nbsp;Verified |

## SBOM Generation

Generate Software Bill of Materials for supply chain visibility.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**cdxgen**](https://github.com/CycloneDX/cdxgen) | Create CycloneDX SBOMs for various languages | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 1.1k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/CycloneDX/cdxgen/) | Checksums |
| [**cyclonedx-cli**](https://github.com/CycloneDX/cyclonedx-cli) | Inspect, convert, and merge CycloneDX SBOMs | 🟢&nbsp;Active<br><sub>Jul 2026</sub> | 552 | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/CycloneDX/cyclonedx-cli/) | — |
| [**sbom-tool**](https://github.com/microsoft/sbom-tool) | Generate SBOMs for build artifacts and source repositories | 🟢&nbsp;Active<br><sub>Sep 2026</sub> | 2.1k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/microsoft/sbom-tool/) | — |
| [**sbomlyze**](https://github.com/rezmoss/sbomlyze) | Compare SBOMs to detect supply-chain drift <sub>*Maintained by this list's maintainer.*</sub> | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 26 | [7.9](https://rezmoss.github.io/awesome-security-pipeline/projects/rezmoss/sbomlyze/) | ✓&nbsp;Verified |
| [**syft**](https://github.com/anchore/syft) | Generate SBOMs from container images and filesystems | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 9.8k | [8.7](https://rezmoss.github.io/awesome-security-pipeline/projects/anchore/syft/) | ✓&nbsp;Verified |

## Artifact Signing & Verification

Sign and verify container images and artifacts for supply chain security.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**cosign**](https://github.com/sigstore/cosign) | Sign and verify container images | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 6.4k | [8.2](https://rezmoss.github.io/awesome-security-pipeline/projects/sigstore/cosign/) | ✓&nbsp;Verified |
| [**notation**](https://github.com/notaryproject/notation) | Sign and verify OCI artifacts with Notary Project specifications | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 502 | [6.5](https://rezmoss.github.io/awesome-security-pipeline/projects/notaryproject/notation/) | Checksums |
| [**rekor**](https://github.com/sigstore/rekor) | Record signed artifacts in a tamper-resistant transparency log | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 1.2k | [8.6](https://rezmoss.github.io/awesome-security-pipeline/projects/sigstore/rekor/) | ✓&nbsp;Verified |

## Supply Chain Compliance

Audit and verify supply chain security against industry benchmarks.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**in-toto**](https://github.com/in-toto/in-toto) | Protect software supply-chain integrity with signed metadata | 🟢&nbsp;Active<br><sub>Aug 2026</sub> | 1.1k | [6.5](https://rezmoss.github.io/awesome-security-pipeline/projects/in-toto/in-toto/) | — |
| [**scorecard**](https://github.com/ossf/scorecard) | Measure open-source project security practices with OpenSSF checks | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 5.8k | [8.6](https://rezmoss.github.io/awesome-security-pipeline/projects/ossf/scorecard/) | ✓&nbsp;Verified |
| [**slsa-verifier**](https://github.com/slsa-framework/slsa-verifier) | Verify SLSA provenance for supply chain security | 🟢&nbsp;Active<br><sub>Aug 2026</sub> | 352 | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/slsa-framework/slsa-verifier/) | ✓&nbsp;Verified |

## Software Composition Analysis (SCA)

Scan dependencies for known vulnerabilities.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**bomber**](https://github.com/devops-kung-fu/bomber) | Scan SBOMs for vulnerabilities | 🟡&nbsp;Stale<br><sub>Feb 2026</sub> | 629 | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/devops-kung-fu/bomber/) | Checksums |
| [**dependency-track**](https://github.com/DependencyTrack/dependency-track) | Track components and analyze dependency risk from SBOMs | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 4.4k | [7.5](https://rezmoss.github.io/awesome-security-pipeline/projects/DependencyTrack/dependency-track/) | — |
| [**grype**](https://github.com/anchore/grype) | Scan filesystems and SBOMs for dependency vulnerabilities | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 13.2k | [7.9](https://rezmoss.github.io/awesome-security-pipeline/projects/anchore/grype/) | ✓&nbsp;Verified |
| [**osv-scanner**](https://github.com/google/osv-scanner) | Scan dependencies for vulnerabilities in the OSV database | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 11.3k | [8.6](https://rezmoss.github.io/awesome-security-pipeline/projects/google/osv-scanner/) | ✓&nbsp;Verified |
| [**safe-chain**](https://github.com/AikidoSec/safe-chain) | Block malicious packages during npm/pip install | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 1.8k | [4.5](https://rezmoss.github.io/awesome-security-pipeline/projects/AikidoSec/safe-chain/) | ✓&nbsp;Verified |
| [**snyk-cli**](https://github.com/snyk/cli) | Find and fix vulnerabilities in dependencies | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 5.7k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/snyk/cli/) | Checksums |
| [**trivy**](https://github.com/aquasecurity/trivy) | Scan operating-system and language dependencies for vulnerabilities | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 38.9k | [7.1](https://rezmoss.github.io/awesome-security-pipeline/projects/aquasecurity/trivy/) | ✓&nbsp;Verified |
| [**vet**](https://github.com/safedep/vet) | Enforce dependency policies and report supply-chain risks | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 1.1k | [7.4](https://rezmoss.github.io/awesome-security-pipeline/projects/safedep/vet/) | ✓&nbsp;Verified |

## Static Application Security Testing (SAST)

Analyze source code for security vulnerabilities.

### Multi-language

Tools that support multiple programming languages.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**bearer**](https://github.com/Bearer/bearer) | Trace sensitive data flows and detect security risks in code | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 2.8k | [6.3](https://rezmoss.github.io/awesome-security-pipeline/projects/Bearer/bearer/) | Checksums |
| [**codeql**](https://github.com/github/codeql) | Analyze code semantically with GitHub's query engine | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 10.3k | [5.8](https://rezmoss.github.io/awesome-security-pipeline/projects/github/codeql/) | — |
| [**semgrep**](https://github.com/semgrep/semgrep) | Scan source code with multi-language static-analysis rules | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 17.4k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/semgrep/semgrep/) | — |
| [**sonarqube**](https://github.com/SonarSource/sonarqube) | Inspect code continuously for quality and security issues | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 11.1k | [4.9](https://rezmoss.github.io/awesome-security-pipeline/projects/SonarSource/sonarqube/) | — |
| [**spotbugs**](https://github.com/spotbugs/spotbugs) | Find bug patterns in Java bytecode | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 4k | [4.6](https://rezmoss.github.io/awesome-security-pipeline/projects/spotbugs/spotbugs/) | — |

### Language-specific

Specialized tools for individual programming languages.

#### Python

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**bandit**](https://github.com/PyCQA/bandit) | Find common security issues in Python code | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 8.4k | [5.8](https://rezmoss.github.io/awesome-security-pipeline/projects/PyCQA/bandit/) | — |
| [**safety**](https://github.com/pyupio/safety) | Check Python dependencies for vulnerabilities | 🟢&nbsp;Active<br><sub>Sep 2026</sub> | 2k | [4.7](https://rezmoss.github.io/awesome-security-pipeline/projects/pyupio/safety/) | — |

#### JavaScript/Node.js

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**eslint-plugin-security**](https://github.com/eslint-community/eslint-plugin-security) | Detect security patterns in Node.js with ESLint rules | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 2.4k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/eslint-community/eslint-plugin-security/) | — |
| [**njsscan**](https://github.com/ajinabraham/njsscan) | Analyze Node.js applications with semantic SAST rules | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 458 | — | — |

#### Go

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**gosec**](https://github.com/securego/gosec) | Find security issues in Go source code | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 9k | [6.6](https://rezmoss.github.io/awesome-security-pipeline/projects/securego/gosec/) | ✓&nbsp;Verified |
| [**govulncheck**](https://github.com/golang/vuln) | Report reachable Go vulnerabilities in source and binaries | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 532 | [3.7](https://rezmoss.github.io/awesome-security-pipeline/projects/golang/vuln/) | — |

#### Ruby

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**brakeman**](https://github.com/presidentbeef/brakeman) | Scan Ruby on Rails applications with static analysis | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 7.3k | [6.0](https://rezmoss.github.io/awesome-security-pipeline/projects/presidentbeef/brakeman/) | — |

#### PHP

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**phpstan**](https://github.com/phpstan/phpstan) | Analyze PHP code without running it | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 14.1k | [4.8](https://rezmoss.github.io/awesome-security-pipeline/projects/phpstan/phpstan/) | — |
| [**psalm**](https://github.com/vimeo/psalm) | Analyze PHP code for type and security issues | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 5.9k | [4.7](https://rezmoss.github.io/awesome-security-pipeline/projects/vimeo/psalm/) | — |

#### Rust

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**cargo-audit**](https://github.com/RustSec/rustsec) | Audit Cargo.lock for crates with security vulnerabilities | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 2k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/RustSec/rustsec/) | — |

## Infrastructure as Code Security

Scan infrastructure configurations for security misconfigurations.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**cfn-lint**](https://github.com/aws-cloudformation/cfn-lint) | Lint AWS CloudFormation templates with security rules | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 2.6k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/aws-cloudformation/cfn-lint/) | — |
| [**checkov**](https://github.com/bridgecrewio/checkov) | Scan cloud infrastructure configurations | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 9.1k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/bridgecrewio/checkov/) | — |
| [**kics**](https://github.com/Checkmarx/kics) | Find security vulnerabilities and compliance issues in IaC | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 2.7k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/Checkmarx/kics/) | — |
| [**snyk-cli**](https://github.com/snyk/cli) | Scan infrastructure as code for security issues | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 5.7k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/snyk/cli/) | Checksums |
| [**trivy**](https://github.com/aquasecurity/trivy) | Scan Terraform, CloudFormation, and other IaC for misconfigurations | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 38.9k | [7.1](https://rezmoss.github.io/awesome-security-pipeline/projects/aquasecurity/trivy/) | ✓&nbsp;Verified |
| [**zizmor**](https://github.com/zizmorcore/zizmor) | Analyze GitHub Actions workflows for security issues | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 6.9k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/zizmorcore/zizmor/) | ✓&nbsp;Verified |

## Container Security

Secure container images and runtime environments.

### Image Scanning

Scan container images for vulnerabilities before deployment.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**clair**](https://github.com/quay/clair) | Analyze container images for known vulnerabilities | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 11.1k | [5.0](https://rezmoss.github.io/awesome-security-pipeline/projects/quay/clair/) | — |
| [**dive**](https://github.com/wagoodman/dive) | Inspect image layers and contents; it does not scan vulnerability databases | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 54.7k | — | — |
| [**docker-bench-security**](https://github.com/docker/docker-bench-security) | Check Docker deployment against CIS benchmarks | 🟢&nbsp;Active<br><sub>Jun 2026</sub> | 9.7k | [6.7](https://rezmoss.github.io/awesome-security-pipeline/projects/docker/docker-bench-security/) | — |
| [**dockle**](https://github.com/goodwithtech/dockle) | Lint container images for security best practices | 🟢&nbsp;Active<br><sub>Jul 2026</sub> | 3.3k | [4.1](https://rezmoss.github.io/awesome-security-pipeline/projects/goodwithtech/dockle/) | Checksums |
| [**grype**](https://github.com/anchore/grype) | Scan container images for operating-system and library vulnerabilities | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 13.2k | [7.9](https://rezmoss.github.io/awesome-security-pipeline/projects/anchore/grype/) | ✓&nbsp;Verified |
| [**hadolint**](https://github.com/hadolint/hadolint) | Lint Dockerfiles for security and build best practices | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 12.5k | [4.7](https://rezmoss.github.io/awesome-security-pipeline/projects/hadolint/hadolint/) | ✓&nbsp;Verified |
| [**trivy**](https://github.com/aquasecurity/trivy) | Scan container images for operating-system and library vulnerabilities | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 38.9k | [7.1](https://rezmoss.github.io/awesome-security-pipeline/projects/aquasecurity/trivy/) | ✓&nbsp;Verified |

### Runtime Security

Monitor and protect containers at runtime.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**falco**](https://github.com/falcosecurity/falco) | Detect runtime threats in cloud-native environments | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 9.5k | [7.5](https://rezmoss.github.io/awesome-security-pipeline/projects/falcosecurity/falco/) | — |
| [**sysdig-inspect**](https://github.com/draios/sysdig-inspect) | Visualize system calls and analyze containers | 🟢&nbsp;Active<br><sub>Jul 2026</sub> | 1k | — | — |
| [**tetragon**](https://github.com/cilium/tetragon) | Observe and enforce runtime security with eBPF | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 5.1k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/cilium/tetragon/) | — |
| [**tracee**](https://github.com/aquasecurity/tracee) | Trace Linux runtime activity and security events with eBPF | 🟢&nbsp;Active<br><sub>Sep 2026</sub> | 4.7k | [7.0](https://rezmoss.github.io/awesome-security-pipeline/projects/aquasecurity/tracee/) | Checksums |

## Kubernetes Security

Secure Kubernetes clusters, manifests, and workloads.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**kube-bench**](https://github.com/aquasecurity/kube-bench) | Check Kubernetes against CIS benchmarks | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 8.2k | [5.8](https://rezmoss.github.io/awesome-security-pipeline/projects/aquasecurity/kube-bench/) | Checksums |
| [**kube-linter**](https://github.com/stackrox/kube-linter) | Analyze Kubernetes YAML and Helm charts before deployment | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 3.5k | [7.4](https://rezmoss.github.io/awesome-security-pipeline/projects/stackrox/kube-linter/) | Signed |
| [**kubescape**](https://github.com/kubescape/kubescape) | Analyze Kubernetes security risk and configuration compliance | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 11.8k | [7.6](https://rezmoss.github.io/awesome-security-pipeline/projects/kubescape/kubescape/) | ✓&nbsp;Verified |
| [**KubeStellar Console**](https://github.com/kubestellar/console) | View security signals across multiple Kubernetes clusters | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 152 | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/kubestellar/console/) | ✓&nbsp;Verified |
| [**kyverno**](https://github.com/kyverno/kyverno) | Enforce policies with Kubernetes-native resources | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 8.3k | [7.8](https://rezmoss.github.io/awesome-security-pipeline/projects/kyverno/kyverno/) | ✓&nbsp;Verified |
| [**polaris**](https://github.com/FairwindsOps/polaris) | Validate Kubernetes best practices and policies | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 3.4k | [5.1](https://rezmoss.github.io/awesome-security-pipeline/projects/FairwindsOps/polaris/) | Signed |
| [**trivy-operator**](https://github.com/aquasecurity/trivy-operator) | Generate Kubernetes-native security reports | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 2k | [7.5](https://rezmoss.github.io/awesome-security-pipeline/projects/aquasecurity/trivy-operator/) | ✓&nbsp;Verified |

## Policy as Code

Define and enforce security policies as code across your infrastructure.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**conftest**](https://github.com/open-policy-agent/conftest) | Test configuration files against OPA policies | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 3.3k | [7.2](https://rezmoss.github.io/awesome-security-pipeline/projects/open-policy-agent/conftest/) | ✓&nbsp;Verified |
| [**gatekeeper**](https://github.com/open-policy-agent/gatekeeper) | Enforce OPA policies through Kubernetes admission control | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 4.3k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/open-policy-agent/gatekeeper/) | ✓&nbsp;Verified |
| [**opa**](https://github.com/open-policy-agent/opa) | Evaluate policy as code across application and infrastructure systems | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 12.4k | [8.0](https://rezmoss.github.io/awesome-security-pipeline/projects/open-policy-agent/opa/) | ✓&nbsp;Verified |

## Secret Management

Securely manage and distribute secrets in Kubernetes and GitOps workflows.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**external-secrets**](https://github.com/external-secrets/external-secrets) | Sync secrets from AWS/Vault/Azure into Kubernetes | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 6.9k | [8.3](https://rezmoss.github.io/awesome-security-pipeline/projects/external-secrets/external-secrets/) | — |
| [**infisical**](https://github.com/Infisical/infisical) | Manage application secrets with automation integrations | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 30.2k | [6.9](https://rezmoss.github.io/awesome-security-pipeline/projects/Infisical/infisical/) | — |
| [**sealed-secrets**](https://github.com/bitnami-labs/sealed-secrets) | Encrypt secrets locally, decrypt only in cluster | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 9.3k | [6.8](https://rezmoss.github.io/awesome-security-pipeline/projects/bitnami-labs/sealed-secrets/) | Signed |
| [**sops**](https://github.com/getsops/sops) | Encrypt structured files while preserving editor workflows | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 23.6k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/getsops/sops/) | ✓&nbsp;Verified |
| [**vault**](https://github.com/hashicorp/vault) | Manage secrets, encryption, and privileged access | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 36.5k | [6.5](https://rezmoss.github.io/awesome-security-pipeline/projects/hashicorp/vault/) | — |

## API & Dynamic Testing (DAST)

Test running applications for vulnerabilities.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**Dark-Moon**](https://github.com/ASCIT31/Dark-Moon) | Autonomous AI penetration testing platform that exercises running web, API, Active Directory and Kubernetes targets with proof of exploitation | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 1.2k | [3.8](https://rezmoss.github.io/awesome-security-pipeline/projects/ASCIT31/Dark-Moon/) | — |
| [**nikto**](https://github.com/sullo/nikto) | Scan web servers for dangerous files and known vulnerabilities | 🟢&nbsp;Active<br><sub>Aug 2026</sub> | 10.8k | [3.8](https://rezmoss.github.io/awesome-security-pipeline/projects/sullo/nikto/) | — |
| [**nuclei**](https://github.com/projectdiscovery/nuclei) | Scan applications and infrastructure with customizable templates | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 32.5k | [6.8](https://rezmoss.github.io/awesome-security-pipeline/projects/projectdiscovery/nuclei/) | Checksums |
| [**sqlmap**](https://github.com/sqlmapproject/sqlmap) | Detect and validate SQL injection vulnerabilities | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 38.8k | [4.9](https://rezmoss.github.io/awesome-security-pipeline/projects/sqlmapproject/sqlmap/) | — |
| [**wapiti**](https://github.com/wapiti-scanner/wapiti) | Scan web applications for vulnerabilities with black-box testing | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 1.9k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/wapiti-scanner/wapiti/) | — |
| [**zap**](https://github.com/zaproxy/zaproxy) | Scan web applications dynamically with OWASP ZAP | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 16.1k | [6.8](https://rezmoss.github.io/awesome-security-pipeline/projects/zaproxy/zaproxy/) | — |

## Cloud Security

Assess and audit cloud infrastructure security posture.

| Tool | What it does<br><img src="assets/blank.gif" width="700" height="1" alt=""> | Status | ★ | Scorecard | Release |
|:---|:---|:---|---:|:---|:---|
| [**cartography**](https://github.com/lyft/cartography) | Map infrastructure relationships and attack surface | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 4.2k | [8.1](https://rezmoss.github.io/awesome-security-pipeline/projects/lyft/cartography/) | — |
| [**cloudquery**](https://github.com/cloudquery/cloudquery) | Inventory cloud assets and analyze them with SQL | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 6.6k | [6.0](https://rezmoss.github.io/awesome-security-pipeline/projects/cloudquery/cloudquery/) | Checksums |
| [**cloudsplaining**](https://github.com/salesforce/cloudsplaining) | Assess AWS IAM policies for risky permissions | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 2.3k | [5.7](https://rezmoss.github.io/awesome-security-pipeline/projects/salesforce/cloudsplaining/) | — |
| [**prowler**](https://github.com/prowler-cloud/prowler) | Assess AWS, Azure, and GCP security configurations | 🟢&nbsp;Active<br><sub>Oct 2026</sub> | 15.2k | [report](https://rezmoss.github.io/awesome-security-pipeline/projects/prowler-cloud/prowler/) | — |
| [**steampipe**](https://github.com/turbot/steampipe) | Query cloud resources using SQL | 🟢&nbsp;Active<br><sub>Nov 2026</sub> | 8k | [6.8](https://rezmoss.github.io/awesome-security-pipeline/projects/turbot/steampipe/) | ✓&nbsp;Verified |

## Legacy and Reference Tools

These projects are kept for migration research and historical context, not recommended for new adoption. They are listed here because their repositories are archived or have had no commit for over 12 months. Prefer the alternative noted beside an entry or a maintained tool from the matching category above.

### Pre-commit & Secrets Detection

| Tool | What it did<br><img src="assets/blank.gif" width="600" height="1" alt=""> | Status | ★ | Use instead |
|:---|:---|:---|---:|:---|
| [**git-secrets**](https://github.com/awslabs/git-secrets) | Prevent committing AWS credentials and secrets | 🔴&nbsp;Unmaintained<br><sub>Sep 2025</sub> | 13.4k | — |
| [**whispers**](https://github.com/Skyscanner/whispers) | Identify hardcoded secrets in static code analysis | ⚪&nbsp;Archived<br><sub>Oct 2021</sub> | 506 | — |

### SBOM Generation

| Tool | What it did<br><img src="assets/blank.gif" width="600" height="1" alt=""> | Status | ★ | Use instead |
|:---|:---|:---|---:|:---|
| [**spdx-sbom-generator**](https://github.com/opensbom-generator/spdx-sbom-generator) | Generate SPDX format SBOMs from source code | ⚪&nbsp;Archived<br><sub>Jan 2025</sub> | 427 | — |
| [**tern**](https://github.com/tern-tools/tern) | Analyze container images for software composition | 🔴&nbsp;Unmaintained<br><sub>Dec 2023</sub> | 1k | — |

### Supply Chain Compliance

| Tool | What it did<br><img src="assets/blank.gif" width="600" height="1" alt=""> | Status | ★ | Use instead |
|:---|:---|:---|---:|:---|
| [**chain-bench**](https://github.com/aquasecurity/chain-bench) | Audit supply chain against CIS benchmarks | 🔴&nbsp;Unmaintained<br><sub>Jul 2024</sub> | 772 | — |

### Static Application Security Testing (SAST) › Multi-language

| Tool | What it did<br><img src="assets/blank.gif" width="600" height="1" alt=""> | Status | ★ | Use instead |
|:---|:---|:---|---:|:---|
| [**horusec**](https://github.com/ZupIT/horusec) | Analyze source code across multiple languages | 🔴&nbsp;Unmaintained<br><sub>Aug 2023</sub> | 1.3k | — |

### Static Application Security Testing (SAST) › Language-specific › Python

| Tool | What it did<br><img src="assets/blank.gif" width="600" height="1" alt=""> | Status | ★ | Use instead |
|:---|:---|:---|---:|:---|
| [**pyre-check**](https://github.com/facebook/pyre-check) | Analyze Python types and selected security properties | ⚪&nbsp;Archived<br><sub>Jun 2026</sub> | 7.2k | — |

### Infrastructure as Code Security

| Tool | What it did<br><img src="assets/blank.gif" width="600" height="1" alt=""> | Status | ★ | Use instead |
|:---|:---|:---|---:|:---|
| [**terrascan**](https://github.com/tenable/terrascan) | Detect compliance and security violations in IaC | ⚪&nbsp;Archived<br><sub>Nov 2025</sub> | 5.2k | — |
| [**tfsec**](https://github.com/aquasecurity/tfsec) | Scan Terraform code for security issues | 🔴&nbsp;Unmaintained<br><sub>May 2025</sub> | 7.1k | — |

### Container Security › Image Scanning

| Tool | What it did<br><img src="assets/blank.gif" width="600" height="1" alt=""> | Status | ★ | Use instead |
|:---|:---|:---|---:|:---|
| [**anchore-engine**](https://github.com/anchore/anchore-engine) | Analyze containers and evaluate image policies | ⚪&nbsp;Archived<br><sub>Jan 2023</sub> | 1.6k | [syft](https://github.com/anchore/syft), [grype](https://github.com/anchore/grype) |

### Kubernetes Security

| Tool | What it did<br><img src="assets/blank.gif" width="600" height="1" alt=""> | Status | ★ | Use instead |
|:---|:---|:---|---:|:---|
| [**kube-hunter**](https://github.com/aquasecurity/kube-hunter) | Hunt for security weaknesses in Kubernetes clusters | 🔴&nbsp;Unmaintained<br><sub>Mar 2024</sub> | 5.1k | — |
| [**kubiscan**](https://github.com/cyberark/KubiScan) | Scan Kubernetes RBAC for risky permissions | 🔴&nbsp;Unmaintained<br><sub>May 2025</sub> | 1.4k | — |

### Policy as Code

| Tool | What it did<br><img src="assets/blank.gif" width="600" height="1" alt=""> | Status | ★ | Use instead |
|:---|:---|:---|---:|:---|
| [**datree**](https://github.com/datreeio/datree) | Prevent Kubernetes misconfigurations | ⚪&nbsp;Archived<br><sub>Aug 2023</sub> | 6.3k | — |

### API & Dynamic Testing (DAST)

| Tool | What it did<br><img src="assets/blank.gif" width="600" height="1" alt=""> | Status | ★ | Use instead |
|:---|:---|:---|---:|:---|
| [**arachni**](https://github.com/Arachni/arachni) | Scan web applications for security issues | ⚪&nbsp;Archived<br><sub>Apr 2026</sub> | 4k | [zap](https://github.com/zaproxy/zaproxy), [nuclei](https://github.com/projectdiscovery/nuclei) |

### Cloud Security

| Tool | What it did<br><img src="assets/blank.gif" width="600" height="1" alt=""> | Status | ★ | Use instead |
|:---|:---|:---|---:|:---|
| [**ScoutSuite**](https://github.com/nccgroup/ScoutSuite) | Audit security configurations across multiple cloud providers | 🔴&nbsp;Unmaintained<br><sub>May 2024</sub> | 7.9k | — |

<!-- catalog:end -->

---

## Contributing

Contributions are welcome! Please read the [contribution guidelines](CONTRIBUTING.md) first.

**To add a tool**, add one JSON file in [`tools/`](tools/); the catalog above is generated from those files. **Before submitting:**
- Repository must be **at least 1 month old** (anti-spam requirement)
- Repository must have **at least 5 stars**
- Tool must have been **updated within the last 12 months**
- You must **disclose any affiliation** with the tool

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

## License

[![CC0](https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, the contributors have waived all copyright and related or neighboring rights to this work.
