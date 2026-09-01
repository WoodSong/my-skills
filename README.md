# my-skills

A collection of Claude Code agent skills — self-contained automation scripts that Claude Code invokes when specific trigger conditions are met.

All skills in this repo are **user-invoked only** (`disable-model-invocation: true`): Claude will never trigger them automatically. Use them via their `/skill-name` slash command.

## Install

### Option A: Install as a plugin (all skills at once)

```bash
git clone https://github.tools.sap/I062843/my-skills.git /tmp/my-skills
claude plugin add /tmp/my-skills
```

This registers all skills in the collection. After installing, run `/reload-plugins` in Claude Code to activate.

### Option B: Install individual skills

Download the `.skill` file for the skill you want, then:

```bash
npx skills add ./blackduck-audit.skill
```

Or install directly from this repo:

```bash
git clone https://github.tools.sap/I062843/my-skills.git /tmp/my-skills
npx skills add /tmp/my-skills/blackduck-audit.skill
```

---

## Skills

### `/blackduck-audit`

Automates commenting on BlackDuck BOM components after a scan. Reads project config from `bd-config.json`, fetches filtered BOM components, and applies standardized comments based on dependency type and upgrade guidance availability.

#### Setup

```bash
pip install requests
```

Copy the sample config and fill in your values:

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

> `accessToken` — generate from **BlackDuck UI → user icon → My Access Tokens**.  
> `projectName` and `versionName` must match exactly (case-sensitive).  
> `filters` is optional; omit or set to `{}` to fetch all BOM components.

Supported filter keys: `reviewStatus`, `policyStatus`, `approvalStatus`.

#### Usage

```
/blackduck-audit
/blackduck-audit --component lifecycle-runtime
/blackduck-audit --delete-comments
/blackduck-audit --ignore-commented
```

---

### `/create-review-PR`

Runs the full commit → push → open PR → review bot comments workflow in one shot.

#### Usage

```
/create-review-PR
```

---

### Explain series

Five skills for understanding code, errors, and technical documents.

| Slash command | What it does |
|---|---|
| `/explain-simple` | Plain-language breakdown with a concrete example or analogy |
| `/feynman-analogy` | Real-world analogy (kitchen, factory, city traffic…) mapped to the code |
| `/jargon-buster` | Translates the 3 most confusing terms in the input |
| `/arch-breakdown` | Why-How-What (Golden Circle) dissection of a design or proposal |
| `/devil-advocate` | Summarises the plan, then stress-tests it for edge cases and failure modes |

#### Usage

Pass the content directly as an argument:

```
/explain-simple <paste code or error here>
/feynman-analogy <paste architecture description>
/jargon-buster <paste jargon-heavy doc>
/arch-breakdown <paste design proposal>
/devil-advocate <paste code or plan>
```

Or invoke with no argument — Claude will use the current conversation context.

---

## Repository Structure

```
<skill-name>/
├── SKILL.md          # Manifest: name, description, trigger conditions
├── references/       # Supporting docs (schemas, API references, etc.)
└── scripts/          # Python entry point(s)

.claude-plugin/
├── plugin.json       # Plugin manifest (skill list, metadata)
└── marketplace.json  # Self-hosted marketplace entry
```

## Adding a New Skill

1. Create a subdirectory: `mkdir <skill-name>`
2. Add `SKILL.md`:

```markdown
---
name: <skill-name>
description: >
  One-paragraph description including trigger conditions.
disable-model-invocation: true
---
```

3. Add the path to `.claude-plugin/plugin.json` under `"skills"`.
4. Run `claude plugin validate .` to verify the manifest.
