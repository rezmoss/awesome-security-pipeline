# Awesome Security Pipeline

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)
[![License: CC0-1.0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg)](http://creativecommons.org/publicdomain/zero/1.0/)

> A curated list of open-source security tools organized by CI/CD pipeline stage.

Security shouldn't be an afterthought. This list organizes battle-tested security tools by where they fit in your pipeline, making it easy to build defense-in-depth from commit to production.

## Contents

- [Pre-commit & Secrets Detection](#pre-commit--secrets-detection)
- [SBOM Generation](#sbom-generation)
- [Software Composition Analysis (SCA)](#software-composition-analysis-sca)
- [Static Application Security Testing (SAST)](#static-application-security-testing-sast)
  - [Multi-language](#multi-language)
  - [Language Specific](#language-specific)
- [Infrastructure as Code Security](#infrastructure-as-code-security)
- [Container Security](#container-security)
  - [Image Scanning](#image-scanning)
  - [Runtime Security](#runtime-security)
- [Kubernetes Security](#kubernetes-security)
- [API & Dynamic Testing (DAST)](#api--dynamic-testing-dast)
- [Cloud Security](#cloud-security)
- [Reading the Badges](#reading-the-badges)
- [Contributing](#contributing)
- [License](#license)

---

## Pre-commit & Secrets Detection

Catch secrets and credentials before they enter your repository.

- [gitleaks](https://github.com/gitleaks/gitleaks) - Detect and prevent secrets in git repos. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/gitleaks/gitleaks) ![Last Commit](https://img.shields.io/github/last-commit/gitleaks/gitleaks)
- [trufflehog](https://github.com/trufflesecurity/trufflehog) - Find credentials in git history and live systems. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/trufflesecurity/trufflehog) ![Last Commit](https://img.shields.io/github/last-commit/trufflesecurity/trufflehog)
- [detect-secrets](https://github.com/Yelp/detect-secrets) - Prevent secrets from entering codebases. ![Unmaintained](https://img.shields.io/badge/status-unmaintained-red) ![Stars](https://img.shields.io/github/stars/Yelp/detect-secrets) ![Last Commit](https://img.shields.io/github/last-commit/Yelp/detect-secrets)
- [git-secrets](https://github.com/awslabs/git-secrets) - Prevent committing AWS credentials and secrets. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/awslabs/git-secrets) ![Last Commit](https://img.shields.io/github/last-commit/awslabs/git-secrets)
- [talisman](https://github.com/thoughtworks/talisman) - Pre-push and pre-commit hooks for secrets detection. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/thoughtworks/talisman) ![Last Commit](https://img.shields.io/github/last-commit/thoughtworks/talisman)
- [whispers](https://github.com/Skyscanner/whispers) - Identify hardcoded secrets in static code analysis. ![Archived](https://img.shields.io/badge/status-archived-lightgrey) ![Stars](https://img.shields.io/github/stars/Skyscanner/whispers) ![Last Commit](https://img.shields.io/github/last-commit/Skyscanner/whispers)

## SBOM Generation

Generate Software Bill of Materials for supply chain visibility.

- [syft](https://github.com/anchore/syft) - Generate SBOMs from container images and filesystems. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/anchore/syft) ![Last Commit](https://img.shields.io/github/last-commit/anchore/syft)
- [cdxgen](https://github.com/CycloneDX/cdxgen) - Create CycloneDX SBOMs for various languages. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/CycloneDX/cdxgen) ![Last Commit](https://img.shields.io/github/last-commit/CycloneDX/cdxgen)
- [cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli) - CLI for working with CycloneDX SBOMs. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/CycloneDX/cyclonedx-cli) ![Last Commit](https://img.shields.io/github/last-commit/CycloneDX/cyclonedx-cli)
- [spdx-sbom-generator](https://github.com/opensbom-generator/spdx-sbom-generator) - Generate SPDX format SBOMs from source code. ![Archived](https://img.shields.io/badge/status-archived-lightgrey) ![Stars](https://img.shields.io/github/stars/opensbom-generator/spdx-sbom-generator) ![Last Commit](https://img.shields.io/github/last-commit/opensbom-generator/spdx-sbom-generator)
- [tern](https://github.com/tern-tools/tern) - Software composition analysis for container images. ![Unmaintained](https://img.shields.io/badge/status-unmaintained-red) ![Stars](https://img.shields.io/github/stars/tern-tools/tern) ![Last Commit](https://img.shields.io/github/last-commit/tern-tools/tern)
- [sbom-tool](https://github.com/microsoft/sbom-tool) - Microsoft's scalable SBOM generation tool. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/microsoft/sbom-tool) ![Last Commit](https://img.shields.io/github/last-commit/microsoft/sbom-tool)

## Software Composition Analysis (SCA)

Scan dependencies for known vulnerabilities.

- [grype](https://github.com/anchore/grype) - Vulnerability scanner for container images and filesystems. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/anchore/grype) ![Last Commit](https://img.shields.io/github/last-commit/anchore/grype)
- [trivy](https://github.com/aquasecurity/trivy) - All-in-one security scanner for vulnerabilities and misconfigurations. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/aquasecurity/trivy) ![Last Commit](https://img.shields.io/github/last-commit/aquasecurity/trivy)
- [osv-scanner](https://github.com/google/osv-scanner) - Vulnerability scanner using the OSV database. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/google/osv-scanner) ![Last Commit](https://img.shields.io/github/last-commit/google/osv-scanner)
- [dependency-track](https://github.com/DependencyTrack/dependency-track) - Intelligent component analysis platform. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/DependencyTrack/dependency-track) ![Last Commit](https://img.shields.io/github/last-commit/DependencyTrack/dependency-track)
- [snyk-cli](https://github.com/snyk/cli) - Find and fix vulnerabilities in dependencies. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/snyk/cli) ![Last Commit](https://img.shields.io/github/last-commit/snyk/cli)
- [bomber](https://github.com/devops-kung-fu/bomber) - Scan SBOMs for vulnerabilities. ![Stale](https://img.shields.io/badge/status-stale-yellow) ![Stars](https://img.shields.io/github/stars/devops-kung-fu/bomber) ![Last Commit](https://img.shields.io/github/last-commit/devops-kung-fu/bomber)
- [vet](https://github.com/safedep/vet) - Policy-driven dependency vetting tool. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/safedep/vet) ![Last Commit](https://img.shields.io/github/last-commit/safedep/vet)
- [deps.dev](https://deps.dev) - Google's dependency insights service (API/Website).

## Static Application Security Testing (SAST)

Analyze source code for security vulnerabilities.

### Multi-language

Tools that support multiple programming languages.

- [semgrep](https://github.com/semgrep/semgrep) - Lightweight static analysis for many languages. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/semgrep/semgrep) ![Last Commit](https://img.shields.io/github/last-commit/semgrep/semgrep)
- [bearer](https://github.com/Bearer/bearer) - Code security scanner for data flows. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/Bearer/bearer) ![Last Commit](https://img.shields.io/github/last-commit/Bearer/bearer)
- [horusec](https://github.com/ZupIT/horusec) - Multi-language security analysis tool. ![Unmaintained](https://img.shields.io/badge/status-unmaintained-red) ![Stars](https://img.shields.io/github/stars/ZupIT/horusec) ![Last Commit](https://img.shields.io/github/last-commit/ZupIT/horusec)
- [codeql](https://github.com/github/codeql) - Semantic code analysis engine by GitHub. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/github/codeql) ![Last Commit](https://img.shields.io/github/last-commit/github/codeql)
- [sonarqube](https://github.com/SonarSource/sonarqube) - Continuous inspection of code quality and security. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/SonarSource/sonarqube) ![Last Commit](https://img.shields.io/github/last-commit/SonarSource/sonarqube)
- [spotbugs](https://github.com/spotbugs/spotbugs) - Static analysis tool for finding bugs in Java. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/spotbugs/spotbugs) ![Last Commit](https://img.shields.io/github/last-commit/spotbugs/spotbugs)

### Language Specific

Specialized tools for individual programming languages.

#### Python
- [bandit](https://github.com/PyCQA/bandit) - Security linter for Python code. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/PyCQA/bandit) ![Last Commit](https://img.shields.io/github/last-commit/PyCQA/bandit)
- [safety](https://github.com/pyupio/safety) - Check Python dependencies for vulnerabilities. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/pyupio/safety) ![Last Commit](https://img.shields.io/github/last-commit/pyupio/safety)
- [pyre-check](https://github.com/facebook/pyre-check) - Performant type checker with security analysis. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/facebook/pyre-check) ![Last Commit](https://img.shields.io/github/last-commit/facebook/pyre-check)

#### JavaScript/Node.js
- [njsscan](https://github.com/ajinabraham/njsscan) - Semantic SAST tool for Node.js applications. ![Unmaintained](https://img.shields.io/badge/status-unmaintained-red) ![Stars](https://img.shields.io/github/stars/ajinabraham/njsscan) ![Last Commit](https://img.shields.io/github/last-commit/ajinabraham/njsscan)
- [eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security) - ESLint rules for Node.js security. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/eslint-community/eslint-plugin-security) ![Last Commit](https://img.shields.io/github/last-commit/eslint-community/eslint-plugin-security)

#### Go
- [gosec](https://github.com/securego/gosec) - Security checker for Go source code. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/securego/gosec) ![Last Commit](https://img.shields.io/github/last-commit/securego/gosec)

#### Ruby
- [brakeman](https://github.com/presidentbeef/brakeman) - Static analysis for Ruby on Rails applications. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/presidentbeef/brakeman) ![Last Commit](https://img.shields.io/github/last-commit/presidentbeef/brakeman)

#### PHP
- [phpstan](https://github.com/phpstan/phpstan) - PHP static analysis tool. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/phpstan/phpstan) ![Last Commit](https://img.shields.io/github/last-commit/phpstan/phpstan)
- [psalm](https://github.com/vimeo/psalm) - Static analysis tool for PHP with security focus. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/vimeo/psalm) ![Last Commit](https://img.shields.io/github/last-commit/vimeo/psalm)

#### Rust
- [cargo-audit](https://github.com/RustSec/rustsec) - Audit Cargo.lock for crates with security vulnerabilities. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/RustSec/rustsec) ![Last Commit](https://img.shields.io/github/last-commit/RustSec/rustsec)

## Infrastructure as Code Security

Scan infrastructure configurations for security misconfigurations.

- [checkov](https://github.com/bridgecrewio/checkov) - Scan cloud infrastructure configurations. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/bridgecrewio/checkov) ![Last Commit](https://img.shields.io/github/last-commit/bridgecrewio/checkov)
- [tfsec](https://github.com/aquasecurity/tfsec) - Security scanner for Terraform code. ![Stale](https://img.shields.io/badge/status-stale-yellow) ![Stars](https://img.shields.io/github/stars/aquasecurity/tfsec) ![Last Commit](https://img.shields.io/github/last-commit/aquasecurity/tfsec)
- [terrascan](https://github.com/tenable/terrascan) - Detect compliance and security violations in IaC. ![Archived](https://img.shields.io/badge/status-archived-lightgrey) ![Stars](https://img.shields.io/github/stars/tenable/terrascan) ![Last Commit](https://img.shields.io/github/last-commit/tenable/terrascan)
- [kics](https://github.com/Checkmarx/kics) - Find security vulnerabilities and compliance issues in IaC. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/Checkmarx/kics) ![Last Commit](https://img.shields.io/github/last-commit/Checkmarx/kics)
- [trivy](https://github.com/aquasecurity/trivy) - Also scans IaC misconfigurations (Terraform, CloudFormation, etc.). ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/aquasecurity/trivy) ![Last Commit](https://img.shields.io/github/last-commit/aquasecurity/trivy)
- [snyk-iac](https://github.com/snyk/cli) - Infrastructure as Code security scanning. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/snyk/cli) ![Last Commit](https://img.shields.io/github/last-commit/snyk/cli)
- [cfn-lint](https://github.com/aws-cloudformation/cfn-lint) - AWS CloudFormation linter with security rules. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/aws-cloudformation/cfn-lint) ![Last Commit](https://img.shields.io/github/last-commit/aws-cloudformation/cfn-lint)

## Container Security

Secure container images and runtime environments.

### Image Scanning

Scan container images for vulnerabilities before deployment.

- [trivy](https://github.com/aquasecurity/trivy) - Comprehensive vulnerability scanner for containers. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/aquasecurity/trivy) ![Last Commit](https://img.shields.io/github/last-commit/aquasecurity/trivy)
- [grype](https://github.com/anchore/grype) - Vulnerability scanner for container images. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/anchore/grype) ![Last Commit](https://img.shields.io/github/last-commit/anchore/grype)
- [clair](https://github.com/quay/clair) - Vulnerability static analysis for containers. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/quay/clair) ![Last Commit](https://img.shields.io/github/last-commit/quay/clair)
- [anchore-engine](https://github.com/anchore/anchore-engine) - Container analysis and policy evaluation. ![Archived](https://img.shields.io/badge/status-archived-lightgrey) ![Stars](https://img.shields.io/github/stars/anchore/anchore-engine) ![Last Commit](https://img.shields.io/github/last-commit/anchore/anchore-engine) *(Migrate to [Syft](https://github.com/anchore/syft) + [Grype](https://github.com/anchore/grype))*
- [docker-bench-security](https://github.com/docker/docker-bench-security) - Check Docker deployment against CIS benchmarks. ![Unmaintained](https://img.shields.io/badge/status-unmaintained-red) ![Stars](https://img.shields.io/github/stars/docker/docker-bench-security) ![Last Commit](https://img.shields.io/github/last-commit/docker/docker-bench-security)
- [dockle](https://github.com/goodwithtech/dockle) - Container image linter for security best practices. ![Unmaintained](https://img.shields.io/badge/status-unmaintained-red) ![Stars](https://img.shields.io/github/stars/goodwithtech/dockle) ![Last Commit](https://img.shields.io/github/last-commit/goodwithtech/dockle)

### Runtime Security

Monitor and protect containers at runtime.

- [falco](https://github.com/falcosecurity/falco) - Cloud-native runtime security and threat detection. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/falcosecurity/falco) ![Last Commit](https://img.shields.io/github/last-commit/falcosecurity/falco)
- [tracee](https://github.com/aquasecurity/tracee) - Linux runtime security and forensics using eBPF. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/aquasecurity/tracee) ![Last Commit](https://img.shields.io/github/last-commit/aquasecurity/tracee)
- [tetragon](https://github.com/cilium/tetragon) - eBPF-based security observability and runtime enforcement. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/cilium/tetragon) ![Last Commit](https://img.shields.io/github/last-commit/cilium/tetragon)
- [sysdig-inspect](https://github.com/draios/sysdig-inspect) - System call visualization and container analysis. ![Unmaintained](https://img.shields.io/badge/status-unmaintained-red) ![Stars](https://img.shields.io/github/stars/draios/sysdig-inspect) ![Last Commit](https://img.shields.io/github/last-commit/draios/sysdig-inspect)

## Kubernetes Security

Secure Kubernetes clusters, manifests, and workloads.

- [kube-bench](https://github.com/aquasecurity/kube-bench) - Check Kubernetes against CIS benchmarks. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/aquasecurity/kube-bench) ![Last Commit](https://img.shields.io/github/last-commit/aquasecurity/kube-bench)
- [kubescape](https://github.com/kubescape/kubescape) - Kubernetes security risk analysis and compliance. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/kubescape/kubescape) ![Last Commit](https://img.shields.io/github/last-commit/kubescape/kubescape)
- [kube-linter](https://github.com/stackrox/kube-linter) - Static analysis for Kubernetes YAML and Helm charts. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/stackrox/kube-linter) ![Last Commit](https://img.shields.io/github/last-commit/stackrox/kube-linter)
- [kyverno](https://github.com/kyverno/kyverno) - Kubernetes native policy management. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/kyverno/kyverno) ![Last Commit](https://img.shields.io/github/last-commit/kyverno/kyverno)
- [polaris](https://github.com/FairwindsOps/polaris) - Validate Kubernetes best practices and policies. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/FairwindsOps/polaris) ![Last Commit](https://img.shields.io/github/last-commit/FairwindsOps/polaris)
- [trivy-operator](https://github.com/aquasecurity/trivy-operator) - Kubernetes-native security reports. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/aquasecurity/trivy-operator) ![Last Commit](https://img.shields.io/github/last-commit/aquasecurity/trivy-operator)
- [kubiscan](https://github.com/cyberark/KubiScan) - Scan Kubernetes RBAC for risky permissions. ![Stale](https://img.shields.io/badge/status-stale-yellow) ![Stars](https://img.shields.io/github/stars/cyberark/KubiScan) ![Last Commit](https://img.shields.io/github/last-commit/cyberark/KubiScan)
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) - Hunt for security weaknesses in Kubernetes clusters. ![Unmaintained](https://img.shields.io/badge/status-unmaintained-red) ![Stars](https://img.shields.io/github/stars/aquasecurity/kube-hunter) ![Last Commit](https://img.shields.io/github/last-commit/aquasecurity/kube-hunter)

## API & Dynamic Testing (DAST)

Test running applications for vulnerabilities.

- [zap](https://github.com/zaproxy/zaproxy) - OWASP ZAP web application security scanner. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/zaproxy/zaproxy) ![Last Commit](https://img.shields.io/github/last-commit/zaproxy/zaproxy)
- [nuclei](https://github.com/projectdiscovery/nuclei) - Fast and customizable vulnerability scanner. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/projectdiscovery/nuclei) ![Last Commit](https://img.shields.io/github/last-commit/projectdiscovery/nuclei)
- [nikto](https://github.com/sullo/nikto) - Web server scanner for dangerous files and vulnerabilities. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/sullo/nikto) ![Last Commit](https://img.shields.io/github/last-commit/sullo/nikto)
- [arachni](https://github.com/Arachni/arachni) - Feature-rich web application security scanner. ![Stale](https://img.shields.io/badge/status-stale-yellow) ![Stars](https://img.shields.io/github/stars/Arachni/arachni) ![Last Commit](https://img.shields.io/github/last-commit/Arachni/arachni) *(Consider [ZAP](https://github.com/zaproxy/zaproxy) or [Nuclei](https://github.com/projectdiscovery/nuclei) instead)*
- [wapiti](https://github.com/wapiti-scanner/wapiti) - Web application vulnerability scanner. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/wapiti-scanner/wapiti) ![Last Commit](https://img.shields.io/github/last-commit/wapiti-scanner/wapiti)
- [sqlmap](https://github.com/sqlmapproject/sqlmap) - Automatic SQL injection detection and exploitation. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/sqlmapproject/sqlmap) ![Last Commit](https://img.shields.io/github/last-commit/sqlmapproject/sqlmap)

## Cloud Security

Assess and audit cloud infrastructure security posture.

- [prowler](https://github.com/prowler-cloud/prowler) - AWS, Azure, and GCP security assessments. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/prowler-cloud/prowler) ![Last Commit](https://img.shields.io/github/last-commit/prowler-cloud/prowler)
- [cloudsplaining](https://github.com/salesforce/cloudsplaining) - AWS IAM security assessment tool. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/salesforce/cloudsplaining) ![Last Commit](https://img.shields.io/github/last-commit/salesforce/cloudsplaining)
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing tool. ![Unmaintained](https://img.shields.io/badge/status-unmaintained-red) ![Stars](https://img.shields.io/github/stars/nccgroup/ScoutSuite) ![Last Commit](https://img.shields.io/github/last-commit/nccgroup/ScoutSuite)
- [steampipe](https://github.com/turbot/steampipe) - Query cloud resources using SQL. ![Active](https://img.shields.io/badge/status-active-brightgreen) ![Stars](https://img.shields.io/github/stars/turbot/steampipe) ![Last Commit](https://img.shields.io/github/last-commit/turbot/steampipe)

---

## Reading the Badges

Each tool displays status and activity badges for transparency.

### Maintenance Status (Updated Weekly)

Status badges are **automatically updated every week** by our GitHub Action to reflect current maintenance status.

| Badge | Meaning |
|-------|---------|
| ![Active](https://img.shields.io/badge/status-active-brightgreen) | **Active** - Updated within the last 6 months |
| ![Stale](https://img.shields.io/badge/status-stale-yellow) | **Stale** - No updates in 6-12 months; use with caution |
| ![Unmaintained](https://img.shields.io/badge/status-unmaintained-red) | **Unmaintained** - No updates in 12+ months; consider alternatives |
| ![Archived](https://img.shields.io/badge/status-archived-lightgrey) | **Archived** - Repository has been archived by owner |
| ![Deprecated](https://img.shields.io/badge/status-deprecated-lightgrey) | **Deprecated** - Officially superseded; migration recommended |

### Activity Badges

| Badge | Meaning |
|-------|---------|
| ![Stars](https://img.shields.io/badge/stars-★-blue) | GitHub star count - indicates community adoption |
| ![Last Commit](https://img.shields.io/badge/last%20commit-date-green) | Last commit date - shows exact update time |

> **Tip:** While we update status badges weekly, always verify the "Last Commit" badge for the most current information before adopting a tool.

## Contributing

Contributions are welcome! Please read the [contribution guidelines](CONTRIBUTING.md) first.

**Before submitting:**
- Repository must be **at least 1 month old** (anti-spam requirement)
- Repository must have **at least 5 stars**
- Tool must have been **updated within the last 12 months**
- You must **disclose any affiliation** with the tool

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

## License

[![CC0](https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, the contributors have waived all copyright and related or neighboring rights to this work.
