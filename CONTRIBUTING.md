# Contributing to Awesome Security Pipeline

Thank you for your interest in contributing to this curated list of security tools for CI/CD pipelines!

## Guidelines

### What Makes a Tool Eligible

To be included in this list, a tool must meet the following criteria:

1. **Open Source** - The tool must be open source with a recognized OSI-approved license
2. **Actively Maintained** - Should have commits within the last 12 months (exceptions for stable, feature-complete tools)
3. **Pipeline-Focused** - Must be usable in automated CI/CD pipelines (CLI, API, or CI integration)
4. **Security-Related** - Must serve a security function (scanning, analysis, detection, compliance, etc.)
5. **Documented** - Must have basic documentation on installation and usage
6. **Stable** - Should be production-ready or at least beta quality (no alpha/experimental tools)

### Anti-Spam & Quality Requirements

To maintain the quality and integrity of this list, we have strict requirements to prevent spam and SEO abuse:

#### Repository Age Requirement
- **Minimum 1 month old**: The repository must have been created at least 1 month ago
- This prevents brand new projects from using this list for promotion
- Exceptions are rare and require maintainer approval with strong justification

#### Minimum Popularity Threshold
- **Minimum 5 GitHub stars**: The tool must have at least 5 stars
- This indicates some community interest and adoption
- Tools with fewer stars may be reconsidered once they reach this threshold

#### Legitimacy Checks
- Repository must have meaningful commit history (not just initial commits)
- Must have actual releases or tagged versions
- Must show evidence of real-world usage (issues, discussions, contributions from multiple users)
- README must contain substantive documentation, not just marketing copy

#### What We Consider Spam
The following will result in immediate rejection:
- Repositories created specifically to be listed here
- Tools with inflated/purchased stars
- Submissions from the tool author without disclosure
- Tools that are thin wrappers around other tools without significant value-add
- Repositories with no meaningful code or functionality
- Projects that exist primarily for SEO/backlink purposes
- Multiple submissions from the same person/organization in a short period

### What We're Looking For

- Tools that fill gaps in the current list
- Better alternatives to existing tools
- New categories of security tooling
- Corrections to descriptions or links

### What We're NOT Looking For

- Commercial/proprietary tools (even if they have a free tier)
- Tools that haven't been updated in 2+ years without good reason
- Duplicate tools that don't offer significant advantages
- Personal scripts or unmaintained forks
- Tools primarily designed for offensive security/red teaming
- Newly created repositories (< 1 month old)
- Low-adoption tools (< 5 stars)
- Self-promotional submissions without disclosure

## How to Contribute

### Adding a tool

The catalog is built from one JSON file per tool in [`tools/`](tools/); the README tables are generated from those files. **A pull request that adds a tool contains exactly one new file and nothing else.**

#### File name

`tools/<tool-id>.json`, where `<tool-id>` is the tool's name in lower case, with spaces replaced by `-`, using only letters, digits, `.`, `_`, and `-`. The id is also how other tool files refer to this tool (in `use_instead`).

| Tool name | File to add |
|---|---|
| gitleaks | `tools/gitleaks.json` |
| OWASP ZAP | `tools/owasp-zap.json` |
| kube-bench | `tools/kube-bench.json` |

If a file with that name already exists for a different project, add the owner as a prefix, for example `tools/example-org-scanner.json`.

#### Minimal example: `tools/gitleaks.json`

```json
{
  "listing": {
    "name": "gitleaks",
    "repository": "gitleaks/gitleaks",
    "categories": [
      {
        "category": "secrets",
        "description": "Detect and prevent secrets in git repos."
      }
    ],
    "disclosure": null,
    "use_instead": [],
    "exception": null
  }
}
```

#### Full example: every optional field, `tools/example-scanner.json`

```json
{
  "listing": {
    "name": "example-scanner",
    "repository": "example-org/example-scanner",
    "categories": [
      {
        "category": "sca",
        "description": "Scan dependency lockfiles for known vulnerabilities."
      },
      {
        "category": "container-image",
        "description": "Scan container images for vulnerable OS and language packages."
      }
    ],
    "disclosure": "Maintained by the contributor of this pull request",
    "use_instead": ["trivy", "grype"],
    "exception": null
  }
}
```

- Two `categories` entries list the tool in two sections, each with its own description.
- `disclosure` is required if you are affiliated with the tool; it appears next to the description.
- `use_instead` names up to three existing tool ids (file names in `tools/` without `.json`). It is shown if the tool ever moves to Legacy.
- Do not add an `automated` section; it is created and maintained by the weekly refresh.

#### Steps

1. Fork this repository and add the file. Do not edit `README.md`; the catalog part is regenerated automatically after merge.
2. Optionally check it locally: `python3 scripts/catalog.py validate`.
3. Open a pull request with a clear title and complete the PR template, including any affiliation.
4. Automated checks validate the file and the repository (see [Automated validation](#automated-validation)).

After merge, a workflow fills in the tool's status, stars, and last update and adds it to the README. The tool joins the [weekly supply-chain report](https://rezmoss.github.io/awesome-security-pipeline/) at the next weekly scan.

### Tool file fields

Only the `listing` section is written by contributors. The `automated` section (status, section, stars, last commit, report summary) is maintained by the weekly refresh, and pull requests that edit it are rejected.

| Field | Required | Meaning |
|---|---|---|
| `name` | Yes | Official tool name, as the project writes it |
| `repository` | Yes | Canonical GitHub repository, `owner/repo` |
| `categories` | Yes | One or more `{"category", "description"}` entries. A multi-purpose tool may be listed in more than one category with a category-specific description |
| `disclosure` | No | Affiliation note shown next to the description, for example `"Maintained by this list's maintainer"` |
| `use_instead` | No | Up to three alternatives for a tool that is (or may become) legacy, as tool ids: other file names in `tools/` without `.json` |
| `exception` | No | Reason a feature-complete tool without recent commits should stay in the active catalog; reviewed by the maintainer |

Descriptions are 10 to 160 characters, start with a verb, and cannot contain `|` or line breaks.

### Categories

Use one of these category ids (defined in [`tools/categories.json`](tools/categories.json)):

| Id | Category |
|---|---|
| `secrets` | Pre-commit & Secrets Detection |
| `sbom` | SBOM Generation |
| `signing` | Artifact Signing & Verification |
| `supply-chain` | Supply Chain Compliance |
| `sca` | Software Composition Analysis (SCA) |
| `sast-multi` | Static Application Security Testing (SAST) › Multi-language |
| `sast-python` | Static Application Security Testing (SAST) › Language-specific › Python |
| `sast-javascript` | Static Application Security Testing (SAST) › Language-specific › JavaScript/Node.js |
| `sast-go` | Static Application Security Testing (SAST) › Language-specific › Go |
| `sast-ruby` | Static Application Security Testing (SAST) › Language-specific › Ruby |
| `sast-php` | Static Application Security Testing (SAST) › Language-specific › PHP |
| `sast-rust` | Static Application Security Testing (SAST) › Language-specific › Rust |
| `iac` | Infrastructure as Code Security |
| `container-image` | Container Security › Image Scanning |
| `container-runtime` | Container Security › Runtime Security |
| `kubernetes` | Kubernetes Security |
| `policy` | Policy as Code |
| `secret-management` | Secret Management |
| `dast` | API & Dynamic Testing (DAST) |
| `cloud` | Cloud Security |

### Good Description Examples

- "Detect and prevent secrets from entering your codebase."
- "Generate SBOMs from container images and filesystems."
- "Scan Kubernetes clusters against CIS benchmarks."

### Bad Description Examples

- "The best SAST tool ever!" (marketing language)
- "A tool that helps developers find vulnerabilities in their code by scanning source files and identifying potential security issues across multiple programming languages" (too long)
- "Security scanner" (too vague)

## Suggesting a New Category

If you think a new category is needed:

1. Open an issue first to discuss
2. Propose at least 3 tools that would fit the category
3. Explain how it differs from existing categories

## Reporting Issues

- **Dead links**: Open an issue with the tool name and broken URL
- **Outdated information**: Open an issue with correct information
- **Tool no longer maintained**: Open an issue with evidence (last commit date, archived repo, etc.)

## Automated validation

Every pull request that changes `tools/` or `README.md` is checked automatically:

| Check | Requirement | Enforced |
|-------|-------------|----------|
| Tool file | Valid fields, known category, description length, no duplicate repository, `use_instead` points to existing tools | Yes |
| Generated sections | The README catalog is not edited by hand | Yes |
| Bot-maintained data | The `automated` section is unchanged | Yes |
| Repository exists | Must be accessible | Yes |
| Repository age | Minimum 1 month | Yes |
| Star count | Minimum 5 stars | Yes |
| Recent activity | Updated within 12 months | Yes |
| Not archived | Repository must be active | Yes |
| Has license | OSI-approved license required | Yes |
| Not a fork | Warning if forked | Warning only |

Pull requests that fail automated checks are not merged until the issues are resolved.

## Pull Request Process

1. Ensure your tool file passes the automated checks
2. One tool per PR (unless adding a new category)
3. Complete all checkboxes in the PR template
4. Disclose any affiliation with the tool
5. Provide a brief explanation of why the tool should be included
6. Wait for automated validation to pass
7. Be responsive to feedback

## Disclosure Requirements

**You must disclose if you are:**
- The author or maintainer of the tool
- An employee of the company that created the tool
- A paid contributor to the tool
- Have any financial interest in the tool's success

Undisclosed self-promotion will result in rejection and potential ban from future contributions.

## Code of Conduct

All participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Be respectful and constructive, disclose affiliations, and focus discussion on verifiable tool quality rather than personal preference. Conduct concerns must be reported through the private channel described there, not in a public issue.

## Maintenance status

A weekly workflow refreshes every tool file from GitHub and from the weekly supply-chain report, then regenerates the README and opens one pull request summarizing the changes:

| Status | Meaning | Section |
|--------|---------|---------|
| 🟢 Active | Commit in the last 6 months | Active catalog |
| 🟡 Stale | No commit for 6–12 months | Active catalog |
| 🔴 Unmaintained | No commit for over 12 months | Moved to Legacy, unless the tool has a documented `exception` |
| ⚪ Archived | Repository archived by its owner | Moved to Legacy |

A Legacy tool returns to the active catalog automatically once it has a commit within 12 months again.

## Questions?

Open an issue with the "question" label if you're unsure about anything.

---

Thank you for helping make this list better!
