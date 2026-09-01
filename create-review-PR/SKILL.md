---
name: create-review-PR
description: >
  Runs the full commit → push to origin → open PR against upstream → review PR bot comments workflow.
  Use this skill whenever the user says "commit and PR", "push and create a PR", "open a PR", "create a pull request",
  "commit, push, PR", or asks to take staged/unstaged changes all the way to a PR. Also trigger when the user says
  "review the PR bot comments", "check what the bot said", or "address bot feedback". The skill covers the entire
  lifecycle: crafting the commit message, pushing the branch, creating the PR with a structured description, waiting
  for the bot, and acting on its review comments — so invoke it even if the user only mentions one part of the chain.
---

# create-review-PR

This skill orchestrates the standard workflow for getting local changes into a pull request and handling automated
review feedback. It codifies four steps that belong together: commit, push, PR, and bot review.

---

## Step 1 — Commit

Before touching git, understand what you're committing.

1. Run `git status` (never `-uall`), `git diff`, and `git log --oneline -10` in parallel.
2. Identify changed files. Stage only the files relevant to the task — avoid `git add -A` or `git add .` unless the
   user explicitly approves; stray files like `.env` or large binaries can end up in commits that way.
3. Write a commit message that explains *why*, not *what*. One imperative subject line (≤72 chars), optionally
   followed by a blank line and a short body. Pass it via HEREDOC to avoid shell quoting issues:
   ```bash
   git commit -m "$(cat <<'EOF'
   Subject line here

   Optional body explaining motivation or context.
   EOF
   )"
   ```
4. If a pre-commit hook fails, fix the underlying issue and create a **new** commit — never `--amend` after a hook
   failure, as it would silently modify the previous commit.

---

## Step 2 — Push to origin

```bash
git push -u origin <branch-name>
```

Use `-u` so the branch tracks the remote going forward. If the push is rejected (non-fast-forward), investigate
before forcing — there may be upstream work to incorporate.

---

## Step 3 — Create PR against upstream

Identify the upstream remote (commonly named `upstream`, but verify with `git remote -v`). The PR head is
`<your-fork-user>:<branch>` and the base is upstream's default branch (usually `main`).

Determine whether there is a linked issue number — check the current branch name, recent commit messages, and anything the user mentioned. If an issue number is found, include a `Closes #<number>` line in the PR body and note it for the label step below.

```bash
gh pr create \
  --repo <upstream-owner>/<repo> \
  --head <fork-user>:<branch> \
  --base main \
  --title "<concise title ≤70 chars>" \
  --body "$(cat <<'EOF'
## Summary
- <bullet 1>
- <bullet 2>

## Test plan
- [ ] <what to verify>

Closes #<number>   ← omit this line if no issue number was found
EOF
)"
```

The title should be short and imperative. The body needs at minimum a Summary and Test plan section.

After creation, print the PR URL so the user can navigate to it.

**If a linked issue was found**, update its labels immediately after the PR is created:

```bash
UPSTREAM=$(git remote get-url upstream | sed 's|.*github[^/]*/||;s|\.git$||')
gh issue edit <number> \
  --repo "$UPSTREAM" \
  --remove-label ready-for-agent \
  --add-label ready-for-human
```

Skip this step if the issue does not have a `ready-for-agent` label (check with `gh issue view <number> --repo "$UPSTREAM" --json labels` first to avoid a no-op error).

---

## Step 4 — Review PR bot comments

PR bots typically post within 30–90 seconds of PR creation. After creating the PR:

1. Wait ~90 seconds, then fetch comments:
   ```bash
   gh pr view <PR-number> --repo <upstream-owner>/<repo> --comments
   ```
2. Read every bot comment carefully. Distinguish between:
   - **Summary/description bots** — informational only, no action needed unless the user wants to adopt the
     suggested description.
   - **Review/lint bots** — these flag actual issues (correctness, style, security, best practices). Treat their
     findings seriously and explain them to the user.
3. For each actionable finding, explain:
   - What the bot flagged
   - Why the concern is (or isn't) valid
   - What change would address it
4. If the findings are valid, apply fixes, commit them to the same branch, and push. The PR updates automatically.

**Important:** Bot comments can be wrong or overly conservative. Use judgment — don't mechanically apply every
suggestion. If a finding is debatable, surface it to the user rather than silently accepting or rejecting it.

---

## Repo topology

This project uses a fork-based workflow:
- `origin` — the user's personal fork
- `upstream` — the canonical repo (e.g., `github.tools.sap/CloudAndroidSDK/android-build`)

Always push branches to `origin` and open PRs targeting `upstream/main`.

---

## Checklist

- [ ] Staged only the intended files
- [ ] Commit message is imperative and explains the why
- [ ] Pushed with `-u` to origin
- [ ] PR created with Summary + Test plan sections
- [ ] `Closes #<number>` included in PR body if a linked issue was found
- [ ] `ready-for-agent` removed and `ready-for-human` added on the issue (if applicable)
- [ ] PR URL returned to user
- [ ] Waited ~60s, then fetched bot comments
- [ ] Each bot finding evaluated and explained or acted on
