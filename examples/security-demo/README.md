# Security Pipeline Demo

This small Go service demonstrates the baseline workflow without deploying a vulnerable application. The production-shaped application under `app/` has no third-party Go dependencies and builds into a non-root `scratch` container. Intentionally unsafe examples are isolated under `fixtures/` and are never compiled into or copied into the image.

## Layout

```text
app/                  Clean service scanned and packaged by the baseline
  deploy/             Hardened Kubernetes example used by configuration scanning
fixtures/
  secrets/            Synthetic, non-credential secret pattern
  sast/               Deterministic shell-command injection example
  dependencies/       Old test-only dependency with published advisories
  container/          Deliberately insecure Dockerfile
  iac/                Deliberately privileged Kubernetes pod
```

The fixture values are training data. They are not real credentials, are not used by the application, and must not be copied into production.

## Run the clean application

```bash
cd examples/security-demo/app
go test ./...
go run .
curl http://127.0.0.1:8080/healthz
```

The service binds to `127.0.0.1:8080` by default. Set `LISTEN_ADDR` explicitly when running it in a container.

## Build the image

```bash
docker build -t security-demo:local examples/security-demo/app
docker run --rm -p 127.0.0.1:8080:8080 -e LISTEN_ADDR=:8080 security-demo:local
```

The builder image is pinned to an OCI index digest. The final image is `scratch`, contains only the compiled service and CA certificates, and runs as UID/GID 65532.

## Reproduce expected fixture findings

Use the versions pinned in `.github/workflows/security-baseline.yml`.

### Gitleaks

The repository configuration allowlists the committed synthetic fixture so normal history scans remain green. The dedicated fixture configuration proves the rule detects it:

```bash
gitleaks dir examples/security-demo/fixtures/secrets \
  --config examples/security-demo/fixtures/secrets/gitleaks-fixture.toml \
  --redact --verbose
```

Expected result: non-zero exit with rule `demo-synthetic-secret`. Remediation: remove and rotate a real exposed credential; for this synthetic fixture, run normal scans with the root `.gitleaks.toml`.

### Semgrep

```bash
semgrep scan --config .semgrep/security-baseline.yml --error \
  examples/security-demo/fixtures/sast
```

Expected result: non-zero exit for `go-shell-command-injection`. Remediation: avoid `sh -c`; invoke a fixed executable with validated arguments.

### OSV-Scanner

```bash
osv-scanner scan source -r examples/security-demo/fixtures/dependencies
```

Expected result: non-zero exit with published advisories for the deliberately old test dependency. Remediation: update or remove the affected module and regenerate `go.sum`.

### Trivy configuration scanning

```bash
trivy config --severity HIGH,CRITICAL --exit-code 1 \
  examples/security-demo/fixtures
```

Expected result: non-zero exit for root/privileged container configuration. Remediation: use a non-root user, disable privilege escalation, drop capabilities, apply a seccomp profile, and avoid a writable root filesystem.

## Safe baseline behavior

The normal workflow:

- scans the full Git history with the root Gitleaks configuration;
- scans only `app/` with Semgrep, OSV-Scanner, and Trivy configuration scanning;
- builds the clean image only after source and configuration gates pass;
- generates a CycloneDX JSON SBOM and scans the built image separately;
- uploads native JSON and SARIF results with a 14-day retention period;
- signs the exported image tar with keyless Cosign only for trusted pushes to `main` or version tags.

Scanner crashes, invalid output, and failed database downloads are treated as failures. Fixture commands are expected to fail because detection is the success condition.

## Workflow contract

| Job | Gate | Retained output | Job permissions |
|---|---|---|---|
| Secrets | Any Gitleaks finding | SARIF, 14 days | `contents: read`, `security-events: write` |
| SAST | Any configured Semgrep error | SARIF, 14 days | `contents: read`, `security-events: write` |
| Dependencies | Any OSV vulnerability | OSV JSON, 14 days | `contents: read` |
| IaC | Trivy `HIGH` or `CRITICAL` misconfiguration | SARIF, 14 days | `contents: read`, `security-events: write` |
| Build | All four preceding gates must pass | Image tar and digest, 14 days | `contents: read` |
| Package | Fixed `HIGH` or `CRITICAL` OS/library vulnerability | CycloneDX JSON and image SARIF, 14 days | `contents: read`, `security-events: write` |
| Sign | Trusted `main` or `v*` push only | Sigstore bundle, 14 days | `contents: read`, `id-token: write` |

The workflow starts with `permissions: {}` and grants permissions per job. SARIF upload is skipped for pull requests originating from another repository because GitHub does not grant the required write token to untrusted fork code. Keyless signing is also skipped for pull requests and manual runs; no long-lived signing key is stored.

## Reproduce from a fresh fork

1. Fork the repository and enable GitHub Actions for the fork.
2. Open **Actions → Security Baseline → Run workflow**. This exercises every gate through image scanning; the signing job is intentionally skipped for a manual run.
3. Confirm that the run produces `gitleaks-report`, `semgrep-report`, `osv-scanner-report`, `trivy-configuration-report`, `security-demo-image`, and `security-demo-package-reports`.
4. To exercise keyless signing, merge the unchanged workflow into the fork's default `main` branch or push a `v*` tag. Confirm that `security-demo-signature` is produced and that the verification step accepts only the current repository, workflow, and Git ref identity.
5. Copy one fixture into the corresponding scanned `app/` path on a test branch to observe a blocking failure. Revert that test change after confirming the finding and follow the remediation guidance above.

Each job has a 10-minute timeout. Network or scanner failures fail closed, and packaging cannot begin until the source gates pass.
