# GitHub Actions Security Tools: Open-Source Stack Comparison

**Last verified:** July 16, 2026  
**Scope:** Gitleaks, Semgrep Community Edition, CodeQL, OSV-Scanner, Grype, Trivy, Syft, and Cosign

There is no single “GitHub Actions security scanner.” Secrets, source code, dependencies, infrastructure configuration, built images, software inventories, and release identity are different control points. A useful pipeline selects the smallest complementary set rather than running every tool against every target.

This comparison supports the repository's [tested GitHub Actions baseline](../.github/workflows/security-baseline.yml). Six components—Gitleaks, Semgrep CE, OSV-Scanner, Trivy, Syft, and Cosign—are recipe-tested here. CodeQL and Grype are documented alternatives, not independently tested results in this comparison.

## Quick selection

| Need | Start with | Choose the alternative when… |
|---|---|---|
| Scan Git history for secrets | Gitleaks | A later secrets-specific comparison demonstrates a better detector for your credential sources. |
| Inspect source with local, readable rules | Semgrep CE | Choose CodeQL when supported-language semantic analysis and GitHub-native results outweigh its platform and licensing constraints. |
| Check application lockfiles | OSV-Scanner | Choose Grype when one scanner must cover filesystems, images, and existing SBOMs. |
| Scan IaC and container images with one CLI | Trivy | Choose a specialized IaC tool for policy depth, or Grype when vulnerability/SBOM workflows are already standardized on Anchore formats. |
| Produce a reusable SBOM | Syft | Syft is not a vulnerability scanner; compare dedicated generators before selecting a required SBOM format. |
| Sign and verify a trusted release | Cosign | Cosign is not a scanner; use it only after defining trusted signing events and exact verification identity. |

For a non-containerized library, begin with Gitleaks, one SAST option, and one dependency scanner. Add Trivy, Syft, and Cosign only when the project ships a container or signed release artifact.

## Capability and output matrix

| Tool | Pipeline role | Primary targets | Native SARIF | Useful retained output | Tested here |
|---|---|---|---|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection | Git history, directories, stdin | Yes | SARIF or redacted JSON | Recipe-tested |
| [Semgrep CE](https://github.com/semgrep/semgrep) | Pattern and local data-flow SAST | Source code | Yes | SARIF plus local rule configuration | Recipe-tested |
| [CodeQL](https://github.com/github/codeql-action) | Semantic SAST | Supported source languages and build output | Yes; integrated automatically | Code-scanning alerts and SARIF diagnostics | Alternative only |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Dependency vulnerability scanning | Lockfiles, source manifests, SBOMs, images | Yes | JSON preserves complete OSV records; SARIF integrates with code scanning | Recipe-tested with JSON |
| [Grype](https://github.com/anchore/grype) | Package vulnerability scanning | Images, filesystems, SBOMs | Yes | JSON for full match detail; SARIF for GitHub | Alternative only |
| [Trivy](https://github.com/aquasecurity/trivy) | Vulnerability and misconfiguration scanning | Images, repositories, filesystems, IaC, SBOMs | Yes | Separate JSON/SARIF per scan type | Recipe-tested for IaC and image scanning |
| [Syft](https://github.com/anchore/syft) | Software inventory | Images, filesystems, archives | No; not a findings tool | CycloneDX, SPDX, or Syft JSON SBOM | Recipe-tested |
| [Cosign](https://github.com/sigstore/cosign) | Signing and verification | Images, blobs, attestations | No; not a findings tool | Sigstore bundle and verified identity | Recipe-tested for a blob bundle |

SARIF claims above come from each project's current documentation: [Gitleaks reporting](https://github.com/gitleaks/gitleaks#reporting), [Semgrep CLI `--sarif`](https://semgrep.dev/docs/cli-reference), [CodeQL Action](https://github.com/github/codeql-action), [OSV-Scanner output](https://google.github.io/osv-scanner/output/), [Grype CLI formats](https://oss.anchore.com/docs/reference/grype/cli/), and [Trivy reporting](https://trivy.dev/docs/latest/configuration/reporting/). Syft produces [SBOM formats](https://oss.anchore.com/docs/guides/sbom/formats/), while Cosign produces signatures and bundles through workflows such as the [Sigstore CI quickstart](https://docs.sigstore.dev/quickstart/quickstart-ci/).

## GitHub Actions permissions

The scanners do not need write access merely to inspect files on a runner. Repository permissions are introduced by checkout, publishing results, fetching OIDC identity, or pushing an artifact.

| Operation | Minimum job permission | Notes |
|---|---|---|
| Check out repository content | `contents: read` | Applies to any tool that scans a checked-out repository. |
| Run a CLI scanner and retain a workflow artifact | `contents: read` | Gitleaks, Semgrep CE, OSV-Scanner, Grype, and Trivy need no GitHub write scope for scanning. |
| Upload third-party SARIF to GitHub code scanning | `security-events: write` plus `contents: read` | GitHub also documents `actions: read` for private-repository SARIF workflows. |
| Run CodeQL advanced setup | `security-events: write` plus `contents: read` | CodeQL analysis uploads results as part of the action. |
| Generate an SBOM from checked-out source or a local image | `contents: read` | Syft itself does not need `security-events` or `id-token`. |
| Verify an existing Cosign bundle | `contents: read` when checkout is required | Offline/material availability depends on the bundle and verification mode; no OIDC token is needed to verify. |
| Create a keyless Cosign signature | `id-token: write`; add `contents: read` if checking out files | `id-token: write` permits requesting an OIDC token; it does not grant repository write access. |
| Push an image to GitHub Container Registry | `packages: write` | This is a registry-push permission, not a requirement for Cosign itself. |

GitHub recommends granting the `GITHUB_TOKEN` the minimum permissions required and increasing them per job. Its [workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax) also states that unspecified permissions become `none`. [SARIF upload documentation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file) requires `security-events: write`, while the [OIDC reference](https://docs.github.com/en/actions/reference/security/oidc) requires `id-token: write` to request a token.

Do not grant `id-token: write` to pull-request scanning jobs just because Cosign appears elsewhere in the workflow. Keep signing in a separate job restricted to trusted branches, tags, or protected environments. Fork pull requests normally cannot receive write permissions, so retain scanner-native reports even when SARIF upload is unavailable.

## Strengths and limitations

### Gitleaks

**Strengths:** scans Git history as well as directories; supports custom rules, baselines, redaction, and native SARIF; requires no service account when run as a pinned CLI.

**Limitations:** pattern and entropy detection cannot prove that every finding is a live credential or detect every provider-specific secret. Full-history scanning requires a non-shallow checkout and may add time on large repositories. Redact reports and logs even when fixtures are synthetic.

### Semgrep Community Edition

**Strengths:** local rules are readable and testable; the CLI runs without an account when supplied local configuration; `--error` provides explicit CI failure behavior and `--sarif` produces GitHub-compatible output. The engine repository is LGPL-2.1.

**Limitations:** Semgrep describes CE as limited to analysis within a single function or file; cross-file, cross-function, and additional language capabilities belong to its Pro engine. Coverage and noise depend on the selected rules. Semgrep-maintained community rules have their own Semgrep Rules License, so do not describe every engine/rule combination simply as LGPL. See the [CE and platform distinction](https://github.com/semgrep/semgrep#semgrep-ecosystem) and [rule-license change](https://semgrep.dev/blog/2024/important-updates-to-semgrep-oss/).

### CodeQL

**Strengths:** semantic and data-flow analysis, query suites, multiple build modes, and native GitHub code-scanning presentation. It is a strong choice for supported languages when a team wants deeper GitHub-native analysis.

**Limitations:** compiled-language extraction can require autobuild or explicit build steps. GitHub makes CodeQL free for public repositories, while private use requires the applicable GitHub Code Security entitlement. The action and standard query repository are MIT-licensed, but the underlying CodeQL CLI uses separate terms. Review the [CodeQL Action license boundary and build modes](https://github.com/github/codeql-action) and [CLI availability](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli) before calling the complete stack unrestricted open source.

### OSV-Scanner

**Strengths:** focuses on dependency identity from lockfiles, manifests, SBOMs, and supported artifacts; uses the open OSV advisory model; emits both detailed JSON and SARIF 2.1.0; documents distinct return codes for findings, general errors, and no-package conditions.

**Limitations:** results depend on supported package extraction and upstream advisory data. It is not a secrets, source-code, or IaC scanner. Some call analysis is language-specific, and network or cached-database strategy must be explicit. The committed baseline retains JSON for complete OSV detail even though current OSV-Scanner also supports SARIF.

### Grype

**Strengths:** scans images, filesystems, and existing SBOMs; supports SARIF, VEX filtering, fixed-state policies, KEV/EPSS-aware prioritization, and severity-based failure. It pairs naturally with Syft while also invoking Syft cataloging internally for direct targets.

**Limitations:** it needs a current vulnerability database and accurate package identification. CPE-based matches require more scrutiny than exact ecosystem matches. It does not replace SAST, secret detection, or IaC policy scanning. Keep JSON when reviewers need match type, ignored matches, or database detail that may not survive SARIF presentation.

### Trivy

**Strengths:** one CLI covers vulnerability, misconfiguration, secret, and license scanning across several target types; all four scanner types support SARIF; configuration and image scans can share installation and cache handling.

**Limitations:** broad scope makes it easy to combine unrelated findings and thresholds into an opaque job. Run IaC and image vulnerability scanning separately, identify enabled scanners, and record database/cache behavior. A single Trivy pass does not replace semantic SAST or release signing.

### Syft

**Strengths:** generates reusable CycloneDX, SPDX, Syft JSON, and other inventories from images and filesystems. Separating SBOM generation from vulnerability policy lets later scanners and incident-response workflows reuse the same evidence.

**Limitations:** an SBOM is an inventory, not a vulnerability result or security verdict. Standard formats may omit Syft-specific detail, so choose the schema and version for the downstream consumer and retain native JSON when full catalog evidence matters.

### Cosign

**Strengths:** keyless signing can bind an artifact to a short-lived GitHub OIDC identity without storing a long-lived private key. Bundles support later verification against an expected issuer and workflow identity.

**Limitations:** signing does not establish that an artifact is vulnerability-free. Keyless signing depends on trusted event selection, external Sigstore services, and strict verification policy. Never sign untrusted pull-request output with a trusted identity. Verification must check the expected issuer and certificate identity, not merely cryptographic validity.

## Maintenance and licensing snapshot

“Active” means the canonical repository was not archived and had a default-branch commit within 180 days on the verification date. It does not measure detection quality.

| Tool | Release verified | Repository status | License boundary |
|---|---|---|---|
| Gitleaks | [v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1), March 21, 2026 | Active | MIT |
| Semgrep CE | [v1.170.0](https://github.com/semgrep/semgrep/releases/tag/v1.170.0), July 15, 2026 | Active | LGPL-2.1 engine; separate community/proprietary rule and Pro-engine terms |
| CodeQL Action/CLI | [CodeQL bundle v2.26.1](https://github.com/github/codeql-action/releases/tag/codeql-bundle-v2.26.1), July 16, 2026 | Active | MIT action and standard queries; CLI subject to GitHub CodeQL terms |
| OSV-Scanner | [v2.4.0](https://github.com/google/osv-scanner/releases/tag/v2.4.0), June 18, 2026 | Active | Apache-2.0 |
| Grype | [v0.116.0](https://github.com/anchore/grype/releases/tag/v0.116.0), July 16, 2026 | Active | Apache-2.0 |
| Trivy | [v0.72.0](https://github.com/aquasecurity/trivy/releases/tag/v0.72.0), June 30, 2026 | Active | Apache-2.0 |
| Syft | [v1.48.0](https://github.com/anchore/syft/releases/tag/v1.48.0), July 16, 2026 | Active | Apache-2.0 |
| Cosign | [v3.1.1](https://github.com/sigstore/cosign/releases/tag/v3.1.1), June 9, 2026 | Active | Apache-2.0 |

Versions in the [tested baseline](../.github/workflows/security-baseline.yml) match this snapshot for its six selected components. A current release is not a reason to use an unpinned action or binary; pin immutable action revisions and verify downloaded release checksums where upstream supplies them.

## Method and limits

This is a role and integration comparison, not a detection benchmark. It uses:

1. canonical project documentation for targets, outputs, failure controls, and licensing boundaries;
2. GitHub's official documentation for workflow permissions, SARIF, code scanning, and OIDC;
3. canonical repository metadata and releases for maintenance status; and
4. the project's [2m21s successful baseline run](https://github.com/rezmoss/awesome-security-pipeline/actions/runs/29529702096) for the six recipe-tested components.

No claim is made about comparative detection rate, false-positive rate, or runtime because the eight tools do not perform the same job and CodeQL/Grype were not run against the committed fixtures for this page. Future category comparisons must use identical fixtures and declared versions before making those claims.

## Practical default

For a small container service on GitHub Actions:

1. run Gitleaks, Semgrep CE with committed local rules, OSV-Scanner, and Trivy configuration scanning in parallel;
2. build only after those gates pass;
3. generate a Syft SBOM and run a separate Trivy image scan;
4. retain native evidence even when uploading SARIF; and
5. sign only trusted branch or tag output with Cosign, then verify the exact GitHub workflow identity.

That default is implemented in the [security baseline workflow](../.github/workflows/security-baseline.yml), explained in the [demo guide](../examples/security-demo/README.md), and justified in the [reference-stack decision](../docs/reference-stack.md).
