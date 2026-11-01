# SBOM compatibility benchmark — 2026-11-01

**Overall status:** PASS  
**Commit:** `65c4a40d60f3b6a8d5ad4328b8580393c722a62f`  
**Generated:** 2026-11-01T04:27:03+00:00  
**Release policy:** `latest-stable`  
**Tool releases resolved:** 2026-11-01T04:25:59Z

## Tool releases

| Tool | Version | Release asset SHA-256 | Verification |
|---|---:|---|---|
| syft | [v1.55.0](https://github.com/anchore/syft/releases/tag/v1.55.0) | `bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d` | upstream-checksum |
| trivy | [v0.76.1](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1) | `c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0` | upstream-checksum |
| cdxgen | [v13.6.0](https://github.com/cdxgen/cdxgen/releases/tag/v13.6.0) | `8b2df49fdea1b21094a7ad4be0d369fe477981a4f36d75f25805970c5b2f2764` | upstream-checksum |
| microsoft-sbom-tool | [v4.1.5](https://github.com/microsoft/sbom-tool/releases/tag/v4.1.5) | `bf5d4f99bc98c119d549d08fc02ae92598a7a42772f17317c01031a92632e05b` | recorded-only |
| cyclonedx-cli | [v0.33.1](https://github.com/CycloneDX/cyclonedx-cli/releases/tag/v0.33.1) | `bfc8b2538da86fe239bc53658bbb63c1c8c510a293c1e6891aa5bea5d3c58746` | recorded-only |

## Result summary

| Fixture | Tool | Status | Format | Components | Dependency edges | Expected | Runtime | Change |
|---|---|---|---|---:|---:|---:|---:|---|
| `go-direct-lockless` | syft | PASS | CycloneDX 1.7 | 3 | 0 | 1/1 | 1.417s | components +0/-0; edges +0/-0 |
| `go-direct-lockless` | trivy | PASS | CycloneDX 1.7 | 4 | 3 | 1/1 | 0.114s | components +0/-0; edges +0/-0 |
| `go-direct-lockless` | cdxgen | PASS | CycloneDX 1.6 | 2 | 1 | 1/1 | 1.368s | components +0/-0; edges +0/-0 |
| `go-direct-lockless` | microsoft-sbom-tool | PASS | SPDX 2.2 | 2 | 1 | 1/1 | 5.377s | components +0/-0; edges +0/-0 |
| `npm-lock-transitive` | syft | PASS | CycloneDX 1.7 | 5 | 2 | 2/2 | 1.166s | components +0/-0; edges +0/-0 |
| `npm-lock-transitive` | trivy | PASS | CycloneDX 1.7 | 4 | 3 | 2/2 | 0.114s | components +0/-0; edges +0/-0 |
| `npm-lock-transitive` | cdxgen | PASS | CycloneDX 1.6 | 3 | 2 | 2/2 | 0.919s | components +0/-0; edges +0/-0 |
| `npm-lock-transitive` | microsoft-sbom-tool | PASS | SPDX 2.2 | 4 | 3 | 2/2 | 2.773s | components +0/-0; edges +0/-0 |
| `pinned-container-image` | syft | PASS | CycloneDX 1.7 | 244 | 37 | n/a | 4.076s | components +0/-0; edges +0/-0 |
| `pinned-container-image` | trivy | PASS | CycloneDX 1.7 | 30 | 54 | n/a | 2.471s | components +0/-0; edges +0/-0 |
| `pinned-container-image` | cdxgen | PASS | CycloneDX 1.6 | 505 | 502 | n/a | 18.409s | components +249/-120; edges +473/-342 |
| `pinned-container-image` | microsoft-sbom-tool | PASS | SPDX 2.2 | 18 | 17 | n/a | 12.306s | components +0/-0; edges +0/-0 |

Changes compare normalized component identities with the reviewed snapshot from 2026-10-04. A count change is evidence to inspect, not automatically a regression.

## Fixture details

### go-direct-lockless

A lockless Go module with one declared direct dependency.

Expected identities: `github.com/dgrijalva/jwt-go@v3.2.0+incompatible` (direct).

#### syft — PASS

Command: `syft scan 'dir:$REPOSITORY/examples/security-demo/fixtures/dependencies' --source-name go-direct-lockless --source-version 1.0.0 -q -o 'cyclonedx-json=$OUTPUT_DIR/raw/go-direct-lockless/syft/sbom.cdx.json'`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| file | `$REPOSITORY/examples/security-demo/fixtures/dependencies/go.mod` | `—` | `—` |
| library | `github.com/dgrijalva/jwt-go` | `v3.2.0+incompatible` | `pkg:golang/github.com/dgrijalva/jwt-go@v3.2.0+incompatible` |
| file | `go-direct-lockless` | `1.0.0` | `—` |

#### trivy — PASS

Command: `trivy fs --quiet --format cyclonedx --output '$OUTPUT_DIR/raw/go-direct-lockless/trivy/sbom.cdx.json' '$REPOSITORY/examples/security-demo/fixtures/dependencies'`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| application | `$REPOSITORY/examples/security-demo/fixtures/dependencies` | `—` | `—` |
| library | `example.invalid/vulnerable-dependency-fixture` | `—` | `pkg:golang/example.invalid/vulnerable-dependency-fixture` |
| library | `github.com/dgrijalva/jwt-go` | `v3.2.0+incompatible` | `pkg:golang/github.com/dgrijalva/jwt-go@v3.2.0+incompatible` |
| application | `go.mod` | `—` | `—` |

#### cdxgen — PASS

Command: `cdxgen '$REPOSITORY/examples/security-demo/fixtures/dependencies' --type golang --spec-version 1.6 --no-install-deps --fail-on-error --output '$OUTPUT_DIR/raw/go-direct-lockless/cdxgen/sbom.cdx.json'`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| application | `example.invalid/vulnerable-dependency-fixture` | `—` | `pkg:golang/example.invalid/vulnerable-dependency-fixture` |
| library | `github.com/dgrijalva/jwt-go` | `v3.2.0+incompatible` | `pkg:golang/github.com/dgrijalva/jwt-go@v3.2.0+incompatible` |

#### microsoft-sbom-tool — PASS

Command: `sbom-tool generate -b '$REPOSITORY/examples/security-demo/fixtures/dependencies' -bc '$REPOSITORY/examples/security-demo/fixtures/dependencies' -m '$OUTPUT_DIR/raw/go-direct-lockless/microsoft-sbom-tool/manifest' -pn go-direct-lockless -pv 1.0.0 -ps rezmoss -nsb https://github.com/rezmoss/awesome-security-pipeline/sbom-benchmark -mi SPDX:2.2 -t '$OUTPUT_DIR/raw/go-direct-lockless/microsoft-sbom-tool/telemetry.json'`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| package | `github.com/dgrijalva/jwt-go` | `v3.2.0+incompatible` | `pkg:golang/github.com/dgrijalva/jwt-go@v3.2.0+incompatible` |
| package | `go-direct-lockless` | `1.0.0` | `pkg:swid/rezmoss/github.com/go-direct-lockless@1.0.0` |

### npm-lock-transitive

An npm v3 lockfile with one direct and one transitive dependency.

Expected identities: `is-odd@3.0.1` (direct), `is-number@6.0.0` (transitive).

Expected dependency edges: `is-odd@3.0.1 → is-number@6.0.0`.

#### syft — PASS

Command: `syft scan 'dir:$REPOSITORY/benchmarks/sbom/fixtures/npm-transitive' --source-name npm-lock-transitive --source-version 1.0.0 -q -o 'cyclonedx-json=$OUTPUT_DIR/raw/npm-lock-transitive/syft/sbom.cdx.json'`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| file | `$REPOSITORY/benchmarks/sbom/fixtures/npm-transitive/package-lock.json` | `—` | `—` |
| library | `is-number` | `6.0.0` | `pkg:npm/is-number@6.0.0` |
| library | `is-odd` | `3.0.1` | `pkg:npm/is-odd@3.0.1` |
| file | `npm-lock-transitive` | `1.0.0` | `—` |
| library | `sbom-transitive-fixture` | `1.0.0` | `pkg:npm/sbom-transitive-fixture@1.0.0` |

#### trivy — PASS

Command: `trivy fs --quiet --format cyclonedx --output '$OUTPUT_DIR/raw/npm-lock-transitive/trivy/sbom.cdx.json' '$REPOSITORY/benchmarks/sbom/fixtures/npm-transitive'`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| application | `$REPOSITORY/benchmarks/sbom/fixtures/npm-transitive` | `—` | `—` |
| library | `is-number` | `6.0.0` | `pkg:npm/is-number@6.0.0` |
| library | `is-odd` | `3.0.1` | `pkg:npm/is-odd@3.0.1` |
| application | `package-lock.json` | `—` | `—` |

#### cdxgen — PASS

Command: `cdxgen '$REPOSITORY/benchmarks/sbom/fixtures/npm-transitive' --type js --spec-version 1.6 --no-install-deps --fail-on-error --output '$OUTPUT_DIR/raw/npm-lock-transitive/cdxgen/sbom.cdx.json'`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| library | `is-number` | `6.0.0` | `pkg:npm/is-number@6.0.0` |
| library | `is-odd` | `3.0.1` | `pkg:npm/is-odd@3.0.1` |
| application | `sbom-transitive-fixture` | `1.0.0` | `pkg:npm/sbom-transitive-fixture@1.0.0` |

#### microsoft-sbom-tool — PASS

Command: `sbom-tool generate -b '$REPOSITORY/benchmarks/sbom/fixtures/npm-transitive' -bc '$REPOSITORY/benchmarks/sbom/fixtures/npm-transitive' -m '$OUTPUT_DIR/raw/npm-lock-transitive/microsoft-sbom-tool/manifest' -pn npm-lock-transitive -pv 1.0.0 -ps rezmoss -nsb https://github.com/rezmoss/awesome-security-pipeline/sbom-benchmark -mi SPDX:2.2 -t '$OUTPUT_DIR/raw/npm-lock-transitive/microsoft-sbom-tool/telemetry.json'`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| package | `is-number` | `6.0.0` | `pkg:npm/is-number@6.0.0` |
| package | `is-odd` | `3.0.1` | `pkg:npm/is-odd@3.0.1` |
| package | `npm-lock-transitive` | `1.0.0` | `pkg:swid/rezmoss/github.com/npm-lock-transitive@1.0.0` |
| package | `sbom-transitive-fixture` | `1.0.0` | `pkg:npm/sbom-transitive-fixture@1.0.0` |

### pinned-container-image

The pinned Linux/amd64 Go-on-Alpine image used by the security demo build stage.

#### syft — PASS

Command: `syft scan docker:sbom-benchmark:container -q -o 'cyclonedx-json=$OUTPUT_DIR/raw/pinned-container-image/syft/sbom.cdx.json'`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| file | `/bin/busybox` | `—` | `—` |
| file | `/etc/alpine-release` | `—` | `—` |
| file | `/etc/apk/keys/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub` | `—` | `—` |
| file | `/etc/apk/keys/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub` | `—` | `—` |
| file | `/etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub` | `—` | `—` |
| file | `/etc/apk/protected_paths.d/ca-certificates.list` | `—` | `—` |
| file | `/etc/busybox-paths.d/busybox` | `—` | `—` |
| file | `/etc/ca-certificates.conf` | `—` | `—` |
| file | `/etc/ca-certificates/update.d/certhash` | `—` | `—` |
| file | `/etc/crontabs/root` | `—` | `—` |
| file | `/etc/fstab` | `—` | `—` |
| file | `/etc/group` | `—` | `—` |

#### trivy — PASS

Command: `trivy image --quiet --format cyclonedx --output '$OUTPUT_DIR/raw/pinned-container-image/trivy/sbom.cdx.json' sbom-benchmark:container`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| operating-system | `alpine` | `3.24.1` | `—` |
| library | `alpine-baselayout` | `3.7.2-r1` | `pkg:apk/alpine/alpine-baselayout@3.7.2-r1?arch=x86_64&distro=3.24.1` |
| library | `alpine-baselayout-data` | `3.7.2-r1` | `pkg:apk/alpine/alpine-baselayout-data@3.7.2-r1?arch=x86_64&distro=3.24.1` |
| library | `alpine-keys` | `2.6-r0` | `pkg:apk/alpine/alpine-keys@2.6-r0?arch=x86_64&distro=3.24.1` |
| library | `alpine-release` | `3.24.1-r0` | `pkg:apk/alpine/alpine-release@3.24.1-r0?arch=x86_64&distro=3.24.1` |
| library | `apk-tools` | `3.0.6-r0` | `pkg:apk/alpine/apk-tools@3.0.6-r0?arch=x86_64&distro=3.24.1` |
| library | `busybox` | `1.37.0-r31` | `pkg:apk/alpine/busybox@1.37.0-r31?arch=x86_64&distro=3.24.1` |
| library | `busybox-binsh` | `1.37.0-r31` | `pkg:apk/alpine/busybox-binsh@1.37.0-r31?arch=x86_64&distro=3.24.1` |
| library | `ca-certificates` | `20260611-r0` | `pkg:apk/alpine/ca-certificates@20260611-r0?arch=x86_64&distro=3.24.1` |
| library | `ca-certificates-bundle` | `20260611-r0` | `pkg:apk/alpine/ca-certificates-bundle@20260611-r0?arch=x86_64&distro=3.24.1` |
| library | `libapk` | `3.0.6-r0` | `pkg:apk/alpine/libapk@3.0.6-r0?arch=x86_64&distro=3.24.1` |
| library | `libcrypto3` | `3.5.7-r0` | `pkg:apk/alpine/libcrypto3@3.5.7-r0?arch=x86_64&distro=3.24.1` |

#### cdxgen — PASS

Command: `cdxgen sbom-benchmark:container --type docker --spec-version 1.6 --no-install-deps --fail-on-error --output '$OUTPUT_DIR/raw/pinned-container-image/cdxgen/sbom.cdx.json'`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| file | `00-alpine.conf` | `—` | `pkg:generic/00-alpine.conf#usr/lib/sysctl.d/00-alpine.conf` |
| file | `20locale.sh` | `—` | `pkg:generic/20locale.sh#etc/profile.d/20locale.sh` |
| cryptographic-asset | `AC RAIZ FNMT-RCM` | `ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa` | `—` |
| cryptographic-asset | `AC RAIZ FNMT-RCM SERVIDORES SEGUROS` | `554153b13d2cf9ddb753bfbe1a4e0ae08d0aa4187058fe60a2b862b2e4b87bcb` | `—` |
| file | `AC_RAIZ_FNMT-RCM.crt` | `—` | `pkg:generic/AC_RAIZ_FNMT-RCM.crt#usr/share/ca-certificates/mozilla/AC_RAIZ_FNMT-RCM.crt` |
| file | `AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.crt` | `—` | `pkg:generic/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.crt#usr/share/ca-certificates/mozilla/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.crt` |
| cryptographic-asset | `ACCVRAIZ1` | `9a6ec012e1a7da9dbe34194d478ad7c0db1822fb071df12981496ed104384113` | `—` |
| file | `ACCVRAIZ1.crt` | `—` | `pkg:generic/ACCVRAIZ1.crt#usr/share/ca-certificates/mozilla/ACCVRAIZ1.crt` |
| file | `acpid` | `—` | `pkg:generic/acpid#etc/logrotate.d/acpid` |
| cryptographic-asset | `Actalis Authentication Root CA` | `55926084ec963a64b96e2abe01ce0ba86a64fbfebcc7aab5afc155b37fd76066` | `—` |
| file | `Actalis_Authentication_Root_CA.crt` | `—` | `pkg:generic/Actalis_Authentication_Root_CA.crt#usr/share/ca-certificates/mozilla/Actalis_Authentication_Root_CA.crt` |
| file | `afalg.so` | `—` | `pkg:generic/afalg.so#usr/lib/engines-3/afalg.so` |

#### microsoft-sbom-tool — PASS

Command: `sbom-tool generate -b '$OUTPUT_DIR/raw/pinned-container-image/microsoft-sbom-tool/drop' -bc '$OUTPUT_DIR/raw/pinned-container-image/microsoft-sbom-tool/components' -m '$OUTPUT_DIR/raw/pinned-container-image/microsoft-sbom-tool/manifest' -di sbom-benchmark:container -pn pinned-container-image -pv 1.0.0 -ps rezmoss -nsb https://github.com/rezmoss/awesome-security-pipeline/sbom-benchmark -mi SPDX:2.2 -t '$OUTPUT_DIR/raw/pinned-container-image/microsoft-sbom-tool/telemetry.json'`

Normalized inventory preview (the JSON result retains the complete inventory):

| Type | Name | Version | PURL |
|---|---|---|---|
| package | `alpine-baselayout` | `3.7.2-r1` | `—` |
| package | `alpine-baselayout-data` | `3.7.2-r1` | `—` |
| package | `alpine-keys` | `2.6-r0` | `—` |
| package | `alpine-release` | `3.24.1-r0` | `—` |
| package | `apk-tools` | `3.0.6-r0` | `—` |
| package | `busybox` | `1.37.0-r31` | `—` |
| package | `busybox-binsh` | `1.37.0-r31` | `—` |
| package | `ca-certificates` | `20260611-r0` | `—` |
| package | `ca-certificates-bundle` | `20260611-r0` | `—` |
| package | `libapk` | `3.0.6-r0` | `—` |
| package | `libcrypto3` | `3.5.7-r0` | `—` |
| package | `libssl3` | `3.5.7-r0` | `—` |

## Interpretation limits

- Component counts are not rankings; subjects, files, packages, and relationships are modeled differently.
- Runtime is diagnostic data from one GitHub-hosted run, not a general performance benchmark.
- Structural validation does not prove inventory completeness or identity accuracy.
- The benchmark does not evaluate vulnerabilities, license correctness, or policy suitability.
- Raw SBOMs and logs are retained with the workflow artifact; the normalized JSON is the durable comparison record.
