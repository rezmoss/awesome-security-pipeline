# Curation and Verification Methodology

This document defines how Awesome Security Pipeline selects, classifies, tests, and re-verifies resources. Its purpose is to make inclusion decisions reproducible and to separate measured facts from maintainer judgment.

## Scope

The project covers open-source tools that can prevent, detect, explain, or enforce security controls in an automated software-delivery pipeline. A qualifying tool must have a usable CLI, API, reusable CI integration, or machine-readable output suitable for automation.

The core scope runs from pre-commit through pull request, build, package, deployment, and runtime. General security resources, offensive-only tooling, commercial-only products, and tools without a credible pipeline use case are outside the default scope.

## Eligibility rules

A new active-list entry must satisfy all of the following on the verification date:

1. **Open source:** the repository declares an OSI-approved license. A missing or ambiguous license is not treated as open source.
2. **Pipeline-relevant:** the tool has a documented CLI, API, CI integration, or machine-readable output that can be used non-interactively.
3. **Security-relevant:** its primary or clearly documented function contributes to prevention, detection, analysis, compliance, provenance, or enforcement.
4. **Documented:** a new user can locate installation and basic usage instructions.
5. **Established:** the repository is at least 30 days old and normally has at least five GitHub stars. Stars are an anti-spam threshold, not a quality score.
6. **Maintained:** the canonical repository is not archived and its default branch has a commit within the preceding 365 days.
7. **Canonical:** the link points to the upstream project rather than an unexplained fork or mirror.

Feature-complete tools with no recent commits may remain only as a documented exception or legacy reference. Commercial products with an open-source component are evaluated only on the capabilities available under the open-source license.

## Evidence hierarchy

Use evidence in this order:

1. Canonical repository metadata, license, releases, documentation, and default-branch history.
2. Reproducible local or CI test results maintained by this project.
3. Maintainer documentation or clarification.
4. Independent technical research with a disclosed method.
5. Community reports, used as leads that still require verification.

Badges, marketing pages, stars, forks, and social posts are not sufficient evidence of security effectiveness.

## Maintenance status

Status is calculated from the latest commit on the canonical repository's default branch at 00:00 UTC on the verification date.

| Status | Objective rule |
|---|---|
| Active | Not archived and latest default-branch commit is 180 days old or newer. |
| Stale | Not archived and latest default-branch commit is 181–365 days old. |
| Unmaintained | Not archived and latest default-branch commit is more than 365 days old. |
| Archived | GitHub reports the canonical repository as archived, regardless of commit date. |
| Deprecated | The upstream maintainers explicitly state that the project is deprecated or superseded. |
| Unknown | Repository metadata or commit history could not be verified. Unknown is never silently treated as active. |

An automated commit is still repository activity, but it does not by itself prove meaningful product maintenance. Before publishing ecosystem reports, unexpected activity changes are manually reviewed to distinguish releases and fixes from badge refreshes, mirrors, generated files, or dependency-only churn.

## Exceptions

Every exception must be written next to the affected entry or in a linked decision record and include:

- the rule being overridden;
- the reason the resource remains useful;
- the evidence supporting that judgment;
- the approving maintainer;
- the approval and next-review dates;
- a safer or maintained alternative when one exists.

Undocumented exceptions are defects. Exceptions expire at their next-review date and must be renewed or removed.

## Testing levels

The project distinguishes listing from testing:

| Level | Meaning |
|---|---|
| Listed | Eligibility and repository metadata were verified; functionality was not independently tested. |
| Smoke-tested | Installation and one documented command succeeded in a controlled environment. |
| Recipe-tested | The tool completed its role in a committed reference pipeline against the demo application. |
| Compared | Multiple tools were run against the same documented fixtures and evaluation criteria. |

Each tested result records the tool version or immutable revision, runner environment, fixture revision, command/configuration, runtime, expected findings, actual findings, outputs, limitations, and test date. A passing test demonstrates only the documented scenario; it is not a security certification or general endorsement.

## Placement and duplication

Each canonical repository has one inventory record. When a multi-purpose tool legitimately appears in several README categories, the inventory stores every placement explicitly. Repeated placement must add category-specific value; otherwise, the README should link to the primary entry rather than duplicate it.

Names and URLs are normalized case-insensitively for duplicate detection, while canonical capitalization is preserved for display. Entries within a category are ordered case-insensitively by display name unless a comparison table has a documented ranking method.

## Review cadence

| Check | Frequency |
|---|---|
| Repository accessibility, archived state, and default-branch activity | Weekly, automated |
| Broken links and structured-data consistency | Every pull request and weekly |
| License, canonical URL, and documentation availability | Monthly |
| Recipe smoke tests and pinned dependency checks | Every relevant change and at least monthly |
| Full inventory review | Quarterly |
| Methodology review | Every six months or after a material dispute |

The structured inventory's `last_verified` field records metadata verification, not a functional test. Test evidence uses a separate test date.

## Corrections and disputes

Anyone may submit a correction with a canonical source or reproducible result. Maintainer affiliation must be disclosed but does not invalidate a factual correction. Disputed comparisons remain labeled as disputed until the method or evidence is reconciled; they are not resolved using popularity alone.

Material corrections are recorded in commit history and, for published reports, in a visible corrections section.
