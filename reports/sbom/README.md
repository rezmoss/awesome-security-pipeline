# SBOM benchmark reports

This directory contains reviewed monthly snapshots from the [SBOM compatibility benchmark](../../benchmarks/sbom/README.md).

No automated snapshot has been published yet. After the workflow is merged, run **SBOM Compatibility Benchmark** manually with **Publish a dated snapshot PR** enabled, or wait for the first scheduled Sunday of the next month. The bot will open a pull request containing:

- `latest.md` and `latest.json` for the current normalized result;
- immutable dated Markdown and JSON under `history/`; and
- this index updated with status, tested versions, fixtures, and links.

Weekly raw outputs and logs are available from each workflow run for 90 days. Only maintainer-reviewed monthly normalized snapshots become permanent repository history.
