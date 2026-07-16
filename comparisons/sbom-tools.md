# SBOM tools comparison: Syft vs Trivy vs cdxgen vs Microsoft SBOM Tool

Which open-source SBOM tool should you run in CI? The answer depends less on component count than on the artifact being described, the required standard, and what must happen after generation.

This comparison covers four generators—[Syft](https://github.com/anchore/syft), [Trivy](https://github.com/aquasecurity/trivy), [cdxgen](https://github.com/cdxgen/cdxgen), and [Microsoft SBOM Tool](https://github.com/microsoft/sbom-tool)—plus [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli), which operates on existing BOMs rather than discovering dependencies. All four generators were run against the same committed Go fixture on July 16, 2026.

For current evidence rather than this dated snapshot, use the [continuously verified SBOM compatibility benchmark](../benchmarks/sbom/README.md). It runs all four generators every week against lockless Go, direct/transitive npm lockfile, and pinned container fixtures; retains raw evidence for 90 days; and prepares a reviewed, normalized history snapshot each month under [SBOM benchmark reports](../reports/sbom/README.md).

## Quick selection

| Need | Practical starting point | Why |
|---|---|---|
| One generator for container images, filesystems, and archives | **Syft** | Purpose-built generator with CycloneDX, SPDX, native Syft JSON, and direct registry/archive inputs. |
| One security CLI for SBOM generation and later vulnerability or license scanning | **Trivy** | Generates standard SBOMs and can consume them in the same tool, reducing CI installation count. |
| CycloneDX-first application analysis across many language ecosystems | **cdxgen** | Broad source-oriented analysis, dependency relationships for supported manifests, and CycloneDX-specific profiles and utilities. |
| SPDX plus an inventory and hashes of the files being shipped | **Microsoft SBOM Tool** | Separates the build drop from source-component detection and validates the drop against the manifest. |
| Validate, convert, merge, diff, or sign existing CycloneDX documents | **CycloneDX CLI** | It is a lifecycle utility, not a dependency-discovery competitor. |
| Go-only module SBOM with ecosystem-specific modes | **cyclonedx-gomod** | A focused alternative when a general filesystem or container catalog is unnecessary. |

For this repository's container pipeline, **Syft remains the default**. The pipeline generates the SBOM from the built image, retains CycloneDX JSON as reusable evidence, and uses Trivy separately for vulnerability policy. That separation makes it clear whether generation or security evaluation failed.

## Capability matrix

| Tool | Primary inputs | Generated formats | Dependency discovery | Related operations |
|---|---|---|---|---|
| Syft 1.48.0 | Container registry/daemon, OCI and Docker archives, directories, files | CycloneDX JSON/XML; SPDX 2.2/2.3 JSON and tag-value; Syft JSON; GitHub dependency snapshot | Package catalogers across images and filesystems | Format conversion, multiple simultaneous outputs, attestations |
| Trivy 0.72.0 | Images, filesystems, root filesystems, repositories, VM images | CycloneDX JSON; SPDX JSON and tag-value | Package detection shared with Trivy's security scanners | Vulnerability and license scanning of SBOM input; image/configuration/secret scanning |
| cdxgen 12.7.1 | Local source, Git URL, package URL, container image/archive, root filesystem | CycloneDX JSON 1.4–1.7; SPDX 3.0.1 JSON-LD export | Language-aware manifest analysis; dependency tree for supported manifests including `go.mod` | Validation, conversion, signing, verification, evidence and specialized BOM profiles |
| Microsoft SBOM Tool 4.1.5 | Build drop plus source/component path; optional container images | SPDX 2.2 and SPDX 3.0 | Microsoft Component Detection over the build-component path | Shipped-file hashing, manifest validation, SPDX 2.2 redaction |
| CycloneDX CLI 0.32.0 | Existing CycloneDX or supported convertible BOM | Converts among CycloneDX JSON/XML/Protobuf/CSV and SPDX 2.3 JSON | **None**; it does not inspect package manifests | Validate, analyze, add files, merge, diff, sign, verify |

The capabilities above come from the projects' canonical documentation: [Syft sources](https://github.com/anchore/syft/wiki/Supported-Sources) and [outputs](https://github.com/anchore/syft/wiki/Output-Formats), [Trivy SBOM generation and scanning](https://trivy.dev/docs/latest/supply-chain/sbom/), [cdxgen usage](https://github.com/cdxgen/cdxgen#usage), [Microsoft generation and validation](https://github.com/microsoft/sbom-tool#run-the-tool), and [CycloneDX CLI commands](https://github.com/CycloneDX/cyclonedx-cli#commands).

## Reproducible source test

The following is the initial July 16 source snapshot that motivated the automated benchmark. Its results remain here for methodological transparency; the living reports are the source for later versions and fixtures.

### Fixture and controls

The common target was [`examples/security-demo/fixtures/dependencies/go.mod`](../examples/security-demo/fixtures/dependencies/go.mod). It declares one direct dependency:

```text
github.com/dgrijalva/jwt-go v3.2.0+incompatible
```

The fixture deliberately has no `go.sum`, vendor directory, downloaded module cache, compiled binary, or source import. This is a narrow manifest-discovery test: can the tool identify the one declared dependency, represent the subject, and produce a structurally valid document without build output? It is not a test of transitive resolution, license accuracy, container coverage, vulnerability detection, or large-repository throughput.

Test controls:

- pinned release binaries for macOS ARM64;
- the same copied fixture directory for every generator;
- default catalogers unless the command explicitly says otherwise;
- no license enrichment or vulnerability scan;
- cdxgen dependency installation disabled so it could not change the fixture;
- five warm timed runs after installation; and
- generator output kept outside the repository and parsed with `jq`.

The Syft, Trivy, and cdxgen release downloads were verified against upstream SHA-256 files. The Microsoft SBOM Tool and CycloneDX CLI releases did not publish separate checksum assets, so the test used the exact assets attached to their tagged GitHub releases. A production installation should prefer a package manager with integrity metadata or independently pin and verify an approved digest.

### Versions and environment

| Tool | Tested release | Release date | License | Standalone binary on test host |
|---|---|---:|---|---:|
| Syft | [1.48.0](https://github.com/anchore/syft/releases/tag/v1.48.0) | 2026-07-16 | Apache-2.0 | 83,187,047 bytes |
| Trivy | [0.72.0](https://github.com/aquasecurity/trivy/releases/tag/v0.72.0) | 2026-06-30 | Apache-2.0 | 161,232,466 bytes |
| cdxgen | [12.7.1](https://github.com/cdxgen/cdxgen/releases/tag/v12.7.1) | 2026-07-08 | Apache-2.0 | 174,139,151 bytes |
| Microsoft SBOM Tool | [4.1.5](https://github.com/microsoft/sbom-tool/releases/tag/v4.1.5) | 2025-12-15 | MIT | 86,337,712 bytes |
| CycloneDX CLI | [0.32.0](https://github.com/CycloneDX/cyclonedx-cli/releases/tag/v0.32.0) | 2026-05-14 | Apache-2.0 | 86,865,952 bytes |

The host was macOS 26.5.2 on ARM64. Binary size is installation context, not a quality score; other platforms and packaging methods differ.

### Commands

From the repository root, the fixture and generators were invoked as follows:

```bash
workdir="$(mktemp -d)"
fixture="$workdir/go-fixture"
cp -R examples/security-demo/fixtures/dependencies "$fixture"

syft scan "dir:$fixture" \
  --source-name vulnerable-dependency-fixture \
  --source-version 1.0.0 \
  -o cyclonedx-json=syft.cdx.json

trivy fs --format cyclonedx \
  --output trivy.cdx.json "$fixture"

cdxgen "$fixture" --type golang \
  --spec-version 1.6 \
  --no-install-deps --fail-on-error \
  --output cdxgen.cdx.json

mkdir -p microsoft-output
sbom-tool generate \
  -b "$fixture" -bc "$fixture" \
  -m microsoft-output \
  -pn vulnerable-dependency-fixture \
  -pv 1.0.0 -ps rezmoss \
  -nsb https://example.invalid/sbom \
  -mi SPDX:2.2
```

cdxgen was fixed to CycloneDX 1.6 to demonstrate an explicit compatibility choice; its current default is 1.7. Syft and Trivy emitted CycloneDX 1.7 by default. Microsoft SBOM Tool was tested in its default SPDX 2.2 mode, although the release also supports generation and validation of SPDX 3.0 with `-mi SPDX:3.0`.

### Results

| Result | Syft | Trivy | cdxgen | Microsoft SBOM Tool |
|---|---:|---:|---:|---:|
| Declared dependency found | Yes | Yes | Yes | Yes |
| Dependency version correct | Yes | Yes | Yes | Yes |
| Package URL present | Yes | Yes | Yes | Yes |
| Root/subject represented | Yes | Yes | Yes | Yes |
| Components/packages array | 2 | 3 | 1 | 2 |
| Dependency/relationship entries | 0 | 4 | 2 | 2 |
| Shipped files inventoried | Manifest represented as a component | No file inventory in this result | No | 1 file with SHA-1 and SHA-256 |
| Emitted file size | 1,458 bytes | 2,918 bytes | 2,738 bytes | 3,064 bytes |
| Median warm runtime | 0.61 s | 0.05 s | 0.53 s | 1.73 s |
| Independent structural validation | CycloneDX CLI passed | CycloneDX CLI passed | CycloneDX CLI passed | Native validator passed |

Raw component counts are **not rankings**. Syft represented the manifest file as a component, Trivy represented the manifest, root module, and dependency, cdxgen kept the root application in metadata and the dependency in `components`, and Microsoft represented the root package plus its dependency in SPDX. Counting those documents without normalizing their models would incorrectly imply that Trivy discovered more third-party software; every generator found exactly the same one declared dependency. Emitted file sizes also reflect each tool's serialization choices and are not a measure of completeness.

Likewise, the timing is only the median of five warm executions on a one-file fixture. It describes startup and tiny-input overhead on this host, not performance on a real monorepo or image. Network download, cache population, image extraction, language tooling, and enrichment can dominate production runtime.

### Validation commands

CycloneDX CLI successfully validated all three CycloneDX documents:

```bash
cyclonedx validate --input-file syft.cdx.json \
  --input-version v1_7 --fail-on-errors
cyclonedx validate --input-file trivy.cdx.json \
  --input-version v1_7 --fail-on-errors
cyclonedx validate --input-file cdxgen.cdx.json \
  --input-version v1_6 --fail-on-errors
```

Microsoft's validator confirmed the one shipped file, its hashes, and the presence of packages:

```bash
sbom-tool validate \
  -b "$fixture" \
  -m microsoft-output/_manifest \
  -o validation.json \
  -mi SPDX:2.2 -n
```

Validation proves that a document conforms to the expected structure and, for the Microsoft workflow, that recorded files still match the drop. It does not prove that the inventory is complete or that component identities are correct.

## Strengths and limitations

### Syft

Syft is the cleanest general-purpose choice when the primary job is package inventory. It accepts registry images without a local Docker daemon, saved Docker or OCI archives, directories, and individual files. It can write multiple formats in one invocation, including a rich native JSON document that preserves evidence not expressible in every interchange standard.

The tradeoff is intentional scope: Syft generates and converts SBOMs but does not decide vulnerability policy. Pair it with Grype, Trivy, or another consumer when findings must gate CI. Directory scans can also model source differently from an image scan, so generate the release SBOM from the artifact actually shipped whenever possible.

### Trivy

Trivy is compelling when a team already uses it for image, filesystem, configuration, or secret scanning. The tested command generated CycloneDX without downloading a vulnerability database; Trivy explicitly disables security scanning for that output unless scanners are requested. The resulting SBOM can later be passed to `trivy sbom` for vulnerability or license analysis.

That convenience couples generation and downstream analysis to Trivy-specific behavior. Trivy's documentation warns that scanning third-party SBOMs may be less accurate because its vulnerability logic uses custom properties, and CycloneDX XML input is not supported. Keep the original standard document and do not assume every consumer interprets vendor properties identically.

### cdxgen

cdxgen is the strongest fit here for CycloneDX-centered source analysis. It understands many package-manager manifests, preserves dependency trees for supported ecosystems including Go, and supports application, container, rootfs, cryptographic, operations, SaaS, and other BOM profiles. Its release also includes dedicated validation, conversion, signing, and verification commands.

That breadth increases setup and configuration surface. Some language modes require additional runtimes or plugins; the documentation calls out Java 21 for C and Python analysis. Automatic dependency installation is enabled by default for some project types, so CI that must not mutate or fetch during analysis should use `--no-install-deps` and test whether the resulting inventory still meets its needs. License lookup is separately opt-in and network-dependent.

### Microsoft SBOM Tool

Microsoft SBOM Tool is distinct because it asks two questions: which components were used to build the package, and which files are actually in the build drop? In this test it recorded both SHA-1 and SHA-256 for `go.mod`, related the root package to the Go dependency, emitted a sidecar checksum for the manifest, and successfully revalidated the drop.

It is SPDX-oriented and does not emit CycloneDX. Its required package, supplier, namespace, build-drop, and component-path inputs make the command more verbose, but they also force useful release identity. SPDX 2.2 redaction is supported; the project documentation says SPDX 3.0 redaction is not yet supported. Component accuracy depends on Microsoft Component Detection's support for the ecosystem and available build metadata.

### CycloneDX CLI

CycloneDX CLI should sit after a generator. It validates, analyzes, converts, merges, diffs, signs, verifies, or adds file records to existing BOMs. It does not inspect `go.mod`, a container image, or a package database to discover dependencies, so listing it beside generators without this distinction is misleading.

Conversion is useful for interoperability, but it cannot create missing evidence or make two standards semantically identical. Retain the generator's original document and treat converted output as a delivery format.

## Focused alternatives

- [CycloneDX Go Module](https://github.com/CycloneDX/cyclonedx-gomod) [1.10.0](https://github.com/CycloneDX/cyclonedx-gomod/releases/tag/v1.10.0) is a focused Go alternative with module, application, and binary-oriented modes. Prefer an ecosystem-specific generator when its build graph is the source of truth and broad filesystem or image cataloging is unnecessary.
- [Kubernetes SIGs bom](https://github.com/kubernetes-sigs/bom) [0.7.1](https://github.com/kubernetes-sigs/bom/releases/tag/v0.7.1) generates SPDX for container images, files, and directories and can work with OCI artifacts. Evaluate it when SPDX and Kubernetes release workflows are central requirements.
- Other [CycloneDX implementations](https://cyclonedx.org/tool-center/) target individual ecosystems. They are not automatically more accurate; compare them against the exact lockfile, build, and release artifact used by the project.

These alternatives were documentation-verified but were not run in the common fixture test, so no detection or runtime comparison is claimed.

## Practical CI rules

1. **Describe the shipped artifact.** A source-tree SBOM answers a different question from an image or release-archive SBOM. Generate after the build when the goal is customer, incident-response, or deployment evidence.
2. **Pin the tool and output specification.** A tool upgrade or default CycloneDX/SPDX version change can break downstream ingestion even when generation succeeds.
3. **Validate before publishing.** Fail CI on schema errors, then test the actual downstream consumer because structural validity does not guarantee ingestion compatibility.
4. **Retain the original.** Conversion can lose tool-specific evidence, relationships, or fields that have no exact equivalent.
5. **Separate inventory from vulnerability policy.** An SBOM records components; it is not proof that those components are safe, current, licensed for a use case, or even completely discovered.
6. **Test known fixtures.** Include at least one direct and one transitive dependency with known package URLs, plus an expected root subject. Assert identities and relationships rather than only a non-empty file.
7. **Record provenance.** Store the tool version, command, source artifact digest, timestamp, and workflow identity with the SBOM. Sign or attest only after the generation path is trusted.
8. **Do not rank by component count.** Normalize root components, files, operating-system packages, development dependencies, and duplicates before comparing inventories.

## Bottom line

Use **Syft** for a dedicated multi-artifact generator, **Trivy** to consolidate generation with an existing Trivy security workflow, **cdxgen** for CycloneDX-first application analysis, and **Microsoft SBOM Tool** for an SPDX release manifest tied to hashed build-drop files. Use **CycloneDX CLI** to test and transform the result, not to replace dependency discovery.

The repository's [tested security baseline](../.github/workflows/security-baseline.yml) follows the first pattern: Syft inventories the built image, Trivy evaluates image vulnerabilities separately, and the CycloneDX document is retained as an independent artifact.
