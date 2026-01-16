<!--
⚠️ PUBLIC REPOSITORY REMINDER ⚠️

This repository is PUBLIC. Please ensure your PR description:
- Does NOT include internal URLs, customer names, or proprietary information
- Does NOT reference internal systems, databases, or infrastructure details
- Does NOT include API keys, tokens, credentials, or secrets (even redacted)
- Does NOT mention specific customer issues or production incidents by name

Write as if the entire internet will read this (because they can!).
For internal context, use the "Internal Reference" section below.
-->

## Summary

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

## Changes Made

<!--
Provide a structured overview of what changed. Consider using:
- Bulleted lists for multiple changes
- Code examples for API changes
- Before/After comparisons for behavior changes
- File-level summaries for large PRs

If this is a large PR, consider organizing by component or feature area.

PUBLIC REPO: Use generic terms for internal systems (e.g., "backend API" not "api.p0.internal")
-->

## Testing

<!--
Explain how you verified this works:
- What tests did you add? (unit, integration, e2e)
- What manual testing did you perform?
- What edge cases did you consider?
- Did you test on multiple platforms/environments if relevant?

For CLI changes, include example commands you ran.

PUBLIC REPO: Redact real credentials, internal hostnames, account IDs, or API endpoints.
Use placeholders like "example-host" or "123456789012" for AWS account IDs.
-->

- [ ] Added/updated unit tests
- [ ] Added/updated integration tests
- [ ] Tested manually (describe scenarios below)

**Manual Testing:**

```bash
# Example commands you ran and their results
# Use generic examples: p0 ssh user@example-host, not real internal systems

```

## Type of Change

<!-- Mark the relevant option(s) -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Refactoring (code changes that neither fix bugs nor add features)
- [ ] Documentation update
- [ ] Dependency update
- [ ] Performance improvement
- [ ] Security fix

## Breaking Changes

<!--
If you marked "Breaking change" above, describe:
- What existing behavior changes
- Who will be affected
- How users should migrate
- Whether this requires a major version bump

If no breaking changes, you can delete this section or write "None."
-->

## Security Considerations

<!--
For a security-focused CLI, consider:
- Does this change handle credentials or sensitive data?
- Are there new attack vectors introduced?
- Does this change authentication or authorization flows?
- Are secrets properly protected (not logged, not committed)?
- Are there OWASP Top 10 concerns (XSS, injection, etc.)?

If not applicable, write "None" or delete this section.
-->

## Dependency Changes

<!--
If you added, removed, or upgraded dependencies:
- List the changes (use `yarn outdated` or `git diff package.json`)
- Explain why each change was necessary
- Note if you ran `yarn audit` to check for vulnerabilities
- For new dependencies, justify why we need them vs. implementing ourselves

Remember: Use devDependencies for build/test tools to minimize production bundle.

If no dependency changes, delete this section.
-->

## Related Issues

<!--
Link to PUBLIC GitHub issues or pull requests:
- Fixes #123
- Relates to #456
- Follow-up to PR #789

For internal P0 tickets (Linear, Jira, etc.), use the "Internal Reference" section below.
-->

## Internal Reference (Optional)

<!--
FOR P0 TEAM MEMBERS ONLY - This section is for internal tracking.

Link to internal issue tracking, design docs, or Slack threads:
- Linear: ENG-1234
- Design doc: [Internal link]
- Slack discussion: [Internal link]

External contributors: You can leave this section empty or delete it.

Note: While this is a public repo, having internal references here is acceptable
for tracking purposes. Just don't put sensitive details in this section - keep
those in internal systems and link to them instead.
-->

## Checklist

<!--
Complete this checklist before requesting review.
Mark items with [x] when complete.
-->

- [ ] Code follows the project's style guidelines (`yarn lint` passes)
- [ ] Self-review completed (read your own diff)
- [ ] Comments added for complex or non-obvious code
- [ ] Documentation updated (CLAUDE.md, README.md, etc.)
- [ ] Tests added/updated and passing (`yarn test`)
- [ ] No new warnings introduced
- [ ] Commit messages are clear and follow project conventions
- [ ] Branch is up to date with main/base branch
- [ ] **PUBLIC REPO: Reviewed PR description for internal URLs, customer names, credentials, or proprietary information**

## Screenshots / Logs (Optional)

<!--
For CLI changes that affect user output:
- Include terminal screenshots or command output
- Show before/after if behavior changed
- Demonstrate new features or fixes

PUBLIC REPO: Carefully review screenshots and logs before posting!
- Redact any credentials, tokens, API keys, or session IDs
- Remove internal hostnames, IP addresses, or system names
- Redact account IDs, user IDs, or email addresses
- Use example.com, placeholder IDs, or blur sensitive information

For non-visual changes, delete this section.
-->

## Reviewer Notes

<!--
Optional section for guidance to reviewers:
- What areas need extra scrutiny?
- What design decisions did you make and why?
- What alternative approaches did you consider?
- Are there parts you're uncertain about?

Being explicit about what you want feedback on leads to better reviews.

PUBLIC REPO: Keep discussion high-level. For detailed internal context,
discuss in internal channels (Slack, Linear) and reference the discussion
in the "Internal Reference" section.
-->

## Follow-up Work

<!--
Optional section for future improvements:
- What's intentionally out of scope?
- What technical debt remains?
- What could be improved later?

This shows you've thought about the bigger picture and helps track future work.
Delete if not applicable.
-->
