# my-skills

A collection of Claude Code agent skills — self-contained automation scripts that Claude Code invokes when specific trigger conditions are met.

## Repository Structure

Each skill lives in its own subdirectory:

```
<skill-name>/
├── SKILL.md          # Manifest: name, description, trigger conditions
├── references/       # Supporting docs (schemas, API references, etc.)
└── scripts/          # Python entry point(s)
```

`SKILL.md` is the contract that tells Claude Code *when* to invoke the skill and *how*.

---

## Skills

### blackduck-audit

Automates commenting on BlackDuck BOM components after a scan. Reads project config from `bd-config.json`, fetches filtered BOM components, and applies standardized comments based on dependency type and upgrade guidance availability.

**Trigger words**: run a BlackDuck audit, process BD scan results, comment on vulnerability findings, `bd-audit`, `blackduck-audit`, `--component`, `delete-comments`, `ignore-commented`.

#### Setup

```bash
pip install requests
```

Copy the sample and fill in your values:

```bash
cp blackduck-audit/bd-config.json.sample bd-config.json
```

```json
{
  "baseUrl": "https://blackduck.example.com",
  "accessToken": "your-personal-access-token",
  "projectName": "my-android-project",
  "versionName": "1.0.0",
  "filters": {
    "reviewStatus": "NOT_REVIEWED"
  }
}
```

> `accessToken` is a BlackDuck personal access token — generate it from **BlackDuck UI → user icon → My Access Tokens**.  
> `projectName` and `versionName` must match exactly (case-sensitive).  
> `filters` is optional; omit or set to `{}` to fetch all BOM components.

Supported filter keys: `reviewStatus`, `policyStatus`, `approvalStatus`.

#### Usage

Invoke via Claude Code using natural language — do not run the script directly:

```
Run a BlackDuck audit using bd-config.json
Audit only the "lifecycle-runtime" component
Delete all existing BlackDuck comments
Ignore all commented BOM components
```

---

## Adding a New Skill

1. Create a subdirectory: `mkdir <skill-name>`
2. Add `SKILL.md` with the frontmatter Claude Code needs:

```markdown
---
name: <skill-name>
description: >
  One-paragraph description. Include trigger conditions explicitly so Claude
  Code knows when to invoke this skill.
---

# <Skill Title>

## Overview
...

## Setup
...

## Usage
...
```

3. Add your script(s) under `scripts/`.
4. Add any reference docs (schemas, API specs) under `references/`.
5. Register the skill path in your Claude Code settings so it's discoverable.
