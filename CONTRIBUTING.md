# Contributing

sapper is a solo learning lab run like a production codebase on purpose. The process is part
of the project: issue-first work, pull requests into a protected main, squash merges, CI
guardrails that fail the build.

- Found a bug, or a claim in the docs that does not match reality? Open an issue with the
  evidence. Those are the most valuable contributions this repo can receive.
- Want to change code? Open an issue first so the change has a stated intent, then a small,
  self-contained PR. CI must pass; unformatted Terraform or a failed Checkov check fails the
  build.
- Vulnerabilities go through private vulnerability reporting, not public issues. See
  [SECURITY.md](./SECURITY.md).

The repo is built with AI agents in the loop under human review. `AI_USAGE.md` carries the
full disclosure.
