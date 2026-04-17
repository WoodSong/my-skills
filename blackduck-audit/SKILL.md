---
name: blackduck-audit
description: >
  Automates BlackDuck scan audit for Android/Java projects. Reads connection config
  (base URL, access token, project name, version, filters) from bd-config.json, fetches
  filtered BOM components, and applies standardized comments based on match type and
  upgrade recommendation availability. Use when asked to run a BlackDuck audit, process
  BD scan results, comment on vulnerability findings, execute the bd-audit / blackduck-audit
  workflow, audit a specific component (--component), delete existing BD comments
  (delete-comments / --delete-comments), or ignore commented components
  (ignore-commented / --ignore-commented).
---

# BlackDuck Audit

## Overview

Automate commenting on BlackDuck BOM components after a scan. Config is read from
`bd-config.json`. The core script is `scripts/blackduck_audit.py`.

See `references/bd-config-schema.md` for the full config file schema and an example.

## Setup

```bash
pip install requests
```

## Running the Audit

```bash
# Add comments based on match type and upgrade guidance
python scripts/blackduck_audit.py --config bd-config.json

# Audit a specific component only (case-insensitive substring match on component name)
python scripts/blackduck_audit.py --config bd-config.json --component "lifecycle-runtime"

# Delete all existing comments from filtered BOM items
python scripts/blackduck_audit.py --config bd-config.json --delete-comments

# Delete comments for a specific component only
python scripts/blackduck_audit.py --config bd-config.json --delete-comments --component "lifecycle-runtime"

# Ignore all filtered BOM components that have at least one comment (bulk-adjustment API)
python scripts/blackduck_audit.py --config bd-config.json --ignore-commented
```

## Comment Logic (applied per BOM item, stop after first comment)

### Step 0 — Path root is demo/sample (checked BEFORE everything else)

Check the **root node** of the item's dependency path (from BDIO map):
- If root's `groupId` or `artifactId` contains `"demo"` or `"sample"` (case-insensitive):
  → comment `"used for {demo|sample}, will not ship to customer"` → **stop**

### Step 1 — Component's own upgrade guidance (applies to ALL match types)

Fetch upgrade guidance for the item:
- If both short-term and long-term are empty/unavailable:
  → comment `"the version of {component name version} is the latest one"` → **stop**

### Step 2 — Transitive Dependency only

For the item's direct dependency (node directly after SAP root, from BFS over BDIO):

1. If `groupId == "com.sap.cloud.android"`:
   → comment `"introduced by {groupId}:{artifactId}"` → **stop**

2. If groupId or artifactId contains `"test"`, `"gradle"`, or `"dokka"` (case-insensitive):
   → comment `"used for {test|build|doc}, will not ship to customer"` → **stop**
   - `"gradle"` → label `"build"`;  `"dokka"` → label `"doc"`;  `"test"` → label `"test"`

3. Fetch direct dep's upgrade guidance:
   - If both short-term and long-term are empty/unavailable:
     → comment `"the version of direct dependency {groupId:artifactId version} is the latest one"` → **stop**

## Key Implementation Notes

- `matchTypes` in the API response is a list; check for `TRANSITIVE` / `DIRECT` (uppercase substring) in joined string.
- "Not available at this time" check: treat missing/empty `versionName` field the same as the literal string.
- **Direct dependency** = node immediately after the SAP root in the BDIO dependency path (NOT the immediate BDIO parent). Built by BFS from root nodes in `build_direct_dep_map()`.
- BDIO zip URL: from `codelocations` endpoint → item with `"bdio"` in name → `_meta.links[rel=scan-data].href`.
- Upgrade guidance endpoint: `{componentVersionHref}/upgrade-guidance` — returns `shortTerm` and `longTerm` objects with a `versionName` field.
- Comment endpoint: `{itemHref}/comments` — POST `{"comment": "..."}`.
- After adding a comment to an item, immediately move to the next item (early return).
- Log at DEBUG level with timestamps; include function name and relevant variables.

## Adapting the Script

If the BlackDuck API response shape differs (field names, pagination), read
`scripts/blackduck_audit.py` and adjust the field accessors. The logic functions
(`_process_transitive`, `is_not_available`) are kept separate for easy patching
without touching the main loop.
