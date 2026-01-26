<!--
⚠️ PUBLIC REPOSITORY REMINDER ⚠️

This repository is PUBLIC. Please ensure your PR description:
- Does NOT include internal URLs, customer names, or proprietary information
- Does NOT reference internal systems, databases, or infrastructure details
- Does NOT include API keys, tokens, credentials, or secrets (even redacted)
- Does NOT mention specific customer issues or production incidents by name

Write as if the entire internet will read this (because they can!).
-->

**Problem**

Enter a description of the problem or need that this pull request addresses. If research
or a reproduction was involved in describing the problem, link to that research or
describe the reproduction.

<!--
Write a clear, high-level summary that explains:
- WHAT this PR achieves
- WHY you're making this change
- WHO will benefit from this change

Write for a PUBLIC audience: open source contributors, CLI users, future maintainers,
and anyone reviewing your work. Include enough context that someone unfamiliar
with P0's internal processes can understand the motivation and impact.

Good example:
"This PR adds OpenTelemetry span error tracking to SSH/SCP commands. Previously,
all spans appeared successful in telemetry even when operations failed, making
production debugging difficult. Now spans accurately reflect operation outcomes
with ERROR status for failures, enabling better observability."

Avoid:
- "Fixed the bug from ENG-1234" (no context; use Internal Reference section for ticket links)
- "Addresses issue reported by Acme Corp" (customer name; say "user-reported issue" instead)
- "Updates auth flow for prod-db-cluster" (internal system; say "database cluster" instead)
-->

**Change**

What does this pull request change (user-facing or not), and how does it solve the problem?

Check off any of the following areas of code that are modified:

- [ ] authentication / authorization
- [ ] workflow
- [ ] lifecycle SDK
- [ ] datastore abstractions

**Type of Change**

<!-- Mark the relevant option(s) -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Refactoring (code changes that neither fix bugs nor add features)
- [ ] Documentation update
- [ ] Dependency update
- [ ] Performance improvement
- [ ] Security fix

**Validation**

How do you know that this change solves the problem? Is testing manual, or are automated
tests included?

How do you know that this change does not introduce new issues? What do you expect to be
affected by this change? Identify any additional risks or risk-mitigation strategies associated with
this change.

**Tracking (optional)**

Link to Linear issue here.

**Implementation (optional)**

- What technical decisions or changes were necessary to make this change?
- What technical debt, if any, is introduced by this change? If so, include links to any existing follow-up tickets.

**Attachments (optional)**

Add any screenshots / video / etc. that may aid in review.

**Follow-up Work (optional)**

<!--
- What's intentionally out of scope?
- What technical debt remains?
- What could be improved later?
-->
