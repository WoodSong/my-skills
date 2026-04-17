# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repository Is

A collection of Claude Code **agent skills** — self-contained automation scripts invoked by the Claude Code skill runner. Each skill lives in its own subdirectory with a `SKILL.md` manifest and a `scripts/` directory.

## Invoking Skills

Skills are invoked by asking Claude Code using natural language that matches the trigger conditions in each skill's `SKILL.md`. Do **not** run the Python scripts directly.

Examples for `blackduck-audit`:

```
Run a BlackDuck audit using bd-config.json
Audit only the "lifecycle-runtime" component
Delete all existing BlackDuck comments
Ignore all commented BOM components
```

Claude Code will invoke the `blackduck-audit` skill automatically when it detects those trigger phrases.

Dependencies (installed once): `pip install requests`

## Skill Structure

Each skill follows this layout:

```
<skill-name>/
├── SKILL.md          # Skill manifest: trigger conditions, description, entry point
├── references/       # Supporting docs (schemas, API references)
└── scripts/          # Python entry point(s)
```

`SKILL.md` is the contract for when and how Claude Code invokes the skill. It defines the trigger keywords and the script to run.

## blackduck-audit Architecture

Single-file script (`blackduck_audit.py`, ~750 lines) with these layers:

**Auth & HTTP**: `authenticate()` exchanges a BD personal access token for a short-lived Bearer token. All BD API calls go through `bd_get()`.

**Dependency graph** (`build_direct_dep_map()`): Downloads a BDIO zip from the BD API, parses its JSON-LD graph, runs BFS from SAP root nodes, and produces a map of `component_gav → (root_package, direct_child_package)`. This is the most complex function — it determines the "direct dependency" for transitive components so comment logic can reference the right ancestor.

**Comment logic** (`process_item()`): Applies a priority-ordered 3-rule chain per BOM component (first match wins):
1. Path root is demo/sample → label as non-shipping
2. Component has no upgrade guidance → label as latest version
3. Transitive only: inspect direct dependency — SAP group → attribute to it; test/build/doc dep → label as non-shipping; direct dep also has no upgrade guidance → label that as latest

**Runtime config** (`bd-config.json`, not stored in repo): Contains `baseUrl`, `accessToken`, `projectName`, `versionName`, and optional `filters`. See `references/bd-config-schema.md` for the full schema.

**CLI modes** (mutually exclusive):
- Default: add comments to BOM components
- `--delete-comments`: remove existing comments
- `--ignore-commented`: bulk-ignore components that already have comments
- `--component NAME`: scope any mode to a single component (substring match)
