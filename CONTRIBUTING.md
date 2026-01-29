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

### Adding a New Tool

1. Fork this repository
2. Add your tool in the appropriate category section
3. Follow the existing format exactly:

```markdown
- [Tool Name](https://github.com/org/repo) - Brief description (one sentence). ![Stars](https://img.shields.io/github/stars/org/repo) ![Last Commit](https://img.shields.io/github/last-commit/org/repo)
```

4. Keep descriptions concise (under 100 characters ideally)
5. Place the tool alphabetically within its category
6. Submit a pull request with a clear title
7. Complete all checkboxes in the PR template

### Format Requirements

- **Tool Name**: Use the official name, properly capitalized
- **URL**: Link to the main repository (prefer GitHub)
- **Description**: Start with a verb, end with a period, no marketing language
- **Badges**: Include both Stars and Last Commit badges using shields.io

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

## Automated Validation

All pull requests are automatically validated by our GitHub Action which checks:

| Check | Requirement | Auto-enforced |
|-------|-------------|---------------|
| Repository exists | Must be accessible | Yes |
| Repository age | Minimum 1 month | Yes |
| Star count | Minimum 5 stars | Yes |
| Recent activity | Updated within 12 months | Yes |
| Not archived | Repository must be active | Yes |
| Has license | OSI-approved license required | Yes |
| Format | Correct badge format | Yes |
| Not a fork | Warning if forked | Warning only |

PRs that fail automated checks will not be merged until issues are resolved.

## Pull Request Process

1. Ensure your PR follows all format requirements
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

- Be respectful and constructive
- No self-promotion without disclosure
- Focus on tool quality, not personal preferences
- Do not submit multiple tools in rapid succession
- Do not create fake accounts to submit tools

## Maintenance Status Indicators

Tools in the README have maintenance status indicators that are **automatically updated weekly** by our GitHub Action:

| Indicator | Meaning |
|-----------|---------|
| ![Active](https://img.shields.io/badge/status-active-brightgreen) | Actively maintained - updated within the last 6 months |
| ![Stale](https://img.shields.io/badge/status-stale-yellow) | Not updated in 6-12 months; use with caution |
| ![Unmaintained](https://img.shields.io/badge/status-unmaintained-red) | Not updated in 12+ months; consider alternatives |
| ![Archived](https://img.shields.io/badge/status-archived-lightgrey) | Repository has been archived by owner |

The Last Commit badge shows the actual last update date for transparency. Status badges are automatically refreshed every week.

## Questions?

Open an issue with the "question" label if you're unsure about anything.

---

Thank you for helping make this list better!
