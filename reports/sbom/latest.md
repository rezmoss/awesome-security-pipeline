# SBOM compatibility benchmark — 2026-07-16

**Overall status:** PASS  
**Commit:** `bc92915ffb02b28c37eff1660f15ec80bee7a5b0`  
**Generated:** 2026-07-16T23:20:12+00:00  
**Release policy:** `latest-stable`  
**Tool releases resolved:** 2026-07-16T23:18:55Z

## Tool releases

| Tool | Version | Release asset SHA-256 | Verification |
|---|---:|---|---|
| syft | [v1.48.0](https://github.com/anchore/syft/releases/tag/v1.48.0) | `6cef9a7f37220d9067eaf9cfaaa2fce986e9f320a8d42cbc36658c99af78ea04` | upstream-checksum |
| trivy | [v0.72.0](https://github.com/aquasecurity/trivy/releases/tag/v0.72.0) | `bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea` | upstream-checksum |
| cdxgen | [v12.7.1](https://github.com/cdxgen/cdxgen/releases/tag/v12.7.1) | `317c2718c3ae4412a1700147af6468a1cedd83ae91bb9c252269033d37b3f88d` | upstream-checksum |
| microsoft-sbom-tool | [v4.1.5](https://github.com/microsoft/sbom-tool/releases/tag/v4.1.5) | `bf5d4f99bc98c119d549d08fc02ae92598a7a42772f17317c01031a92632e05b` | recorded-only |
| cyclonedx-cli | [v0.32.0](https://github.com/CycloneDX/cyclonedx-cli/releases/tag/v0.32.0) | `454879e6a4a405c8a13bff49b8982adcb0596f3019b26b0811c66e4d7f0783e1` | recorded-only |

## Result summary

| Fixture | Tool | Status | Format | Components | Dependency edges | Expected | Runtime | Change |
|---|---|---|---|---:|---:|---:|---:|---|
| `go-direct-lockless` | syft | PASS | CycloneDX 1.7 | 3 | 0 | 1/1 | 1.871s | baseline |
| `go-direct-lockless` | trivy | PASS | CycloneDX 1.7 | 4 | 3 | 1/1 | 0.064s | baseline |
| `go-direct-lockless` | cdxgen | PASS | CycloneDX 1.6 | 2 | 1 | 1/1 | 3.773s | baseline |
| `go-direct-lockless` | microsoft-sbom-tool | PASS | SPDX 2.2 | 2 | 1 | 1/1 | 5.328s | baseline |
| `npm-lock-transitive` | syft | PASS | CycloneDX 1.7 | 5 | 2 | 2/2 | 1.018s | baseline |
| `npm-lock-transitive` | trivy | PASS | CycloneDX 1.7 | 4 | 3 | 2/2 | 0.064s | baseline |
| `npm-lock-transitive` | cdxgen | PASS | CycloneDX 1.6 | 3 | 2 | 2/2 | 0.916s | baseline |
| `npm-lock-transitive` | microsoft-sbom-tool | PASS | SPDX 2.2 | 4 | 3 | 2/2 | 2.975s | baseline |
| `pinned-container-image` | syft | PASS | CycloneDX 1.7 | 244 | 37 | n/a | 4.878s | baseline |
| `pinned-container-image` | trivy | PASS | CycloneDX 1.7 | 30 | 54 | n/a | 2.622s | baseline |
| `pinned-container-image` | cdxgen | PASS | CycloneDX 1.6 | 375 | 368 | n/a | 25.496s | baseline |
| `pinned-container-image` | microsoft-sbom-tool | PASS | SPDX 2.2 | 18 | 17 | n/a | 12.204s | baseline |

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
| file | `00-alpine.conf` | `—` | `pkg:generic/00-alpine.conf?path=/usr/lib/sysctl.d/00-alpine.conf` |
| file | `20locale.sh` | `—` | `pkg:generic/20locale.sh?path=/etc/profile.d/20locale.sh` |
| cryptographic-asset | `AC RAIZ FNMT-RCM SERVIDORES SEGUROS` | `8e3f237813d3f3e2f5767bc2a694a7557f84bb79fd60ef1adc25afd0c1fc5ef6` | `—` |
| file | `AC_RAIZ_FNMT-RCM.crt` | `—` | `pkg:generic/AC_RAIZ_FNMT-RCM.crt?path=/usr/share/ca-certificates/mozilla/AC_RAIZ_FNMT-RCM.crt` |
| cryptographic-asset | `AC_RAIZ_FNMT-RCM.crt` | `aa18ea4c9a8441a461bb436a1c90beb994ac841980b8fd62c72de9a62ddf8ae3` | `—` |
| file | `AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.crt` | `—` | `pkg:generic/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.crt?path=/usr/share/ca-certificates/mozilla/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.crt` |
| cryptographic-asset | `ACCVRAIZ1` | `04846f73d9d0421c60076fd02bad7f0a81a3f11a028d653b0de53290e41dcead` | `—` |
| file | `ACCVRAIZ1.crt` | `—` | `pkg:generic/ACCVRAIZ1.crt?path=/usr/share/ca-certificates/mozilla/ACCVRAIZ1.crt` |
| file | `acpid` | `—` | `pkg:generic/acpid?path=/etc/logrotate.d/acpid` |
| cryptographic-asset | `Actalis Authentication Root CA` | `c6d25347727f267774611677588d76f8a54a6e14d3e99dd69ef2c20612ed87c5` | `—` |
| file | `Actalis_Authentication_Root_CA.crt` | `—` | `pkg:generic/Actalis_Authentication_Root_CA.crt?path=/usr/share/ca-certificates/mozilla/Actalis_Authentication_Root_CA.crt` |
| file | `afalg.so` | `—` | `pkg:generic/afalg.so?path=/usr/lib/engines-3/afalg.so` |

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
