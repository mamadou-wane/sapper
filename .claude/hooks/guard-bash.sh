#!/bin/bash
# PreToolUse guard for agent Bash commands. AGENTS.md states these rules; this
# script enforces them behind the deny rules in settings.json, which cannot see
# through wrappers (make, -chdir) or into refspecs. Exit 2 blocks the call and
# feeds the reason back to the agent. Applies to agent tool calls only, never to
# the human's own shell.
set -u

INPUT=$(cat)
COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$COMMAND" ] && exit 0

block() {
  echo "Blocked: $1" >&2
  exit 2
}

# Commands that mutate the AWS account, including through wrappers the deny
# rules cannot see into (-chdir, make). Boundaries are command positions only,
# so prose mentioning these commands (commit messages, docs) does not trip it;
# env-prefixed and time/xargs-wrapped forms are caught by the deny rules, which
# strip those wrappers.
if printf '%s' "$COMMAND" | grep -Eq '(^|[;&|(`])[[:space:]]*(terraform|tofu)[[:space:]]+(-[^[:space:]]+[[:space:]]+)*(apply|destroy)\b'; then
  block "terraform apply/destroy mutates the AWS account. Produce a plan; the human applies (AGENTS.md)."
fi
if printf '%s' "$COMMAND" | grep -Eq '(^|[;&|(`])[[:space:]]*make[[:space:]]+(deploy|destroy)'; then
  block "make deploy/destroy runs terraform apply/destroy. The human applies (AGENTS.md)."
fi

# Pushes that would land on main. Branch pushes are allowed and still prompt via
# the ask rule in settings.json.
if printf '%s' "$COMMAND" | grep -Eq '(^|[;&|(`])[[:space:]]*git[[:space:]]([^|;&]*[[:space:]])?push\b'; then
  if printf '%s' "$COMMAND" | grep -Eq 'push[^|;&]*[[:space:]:/]main\b'; then
    block "push targets main. Work lands by pull request (AGENTS.md)."
  fi
  CURRENT_BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null || echo "")
  if [ "$CURRENT_BRANCH" = "main" ]; then
    block "push from main. Work lands by pull request from a branch (AGENTS.md)."
  fi
fi

exit 0
