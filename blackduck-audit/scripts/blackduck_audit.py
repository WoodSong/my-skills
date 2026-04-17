#!/usr/bin/env python3
"""
BlackDuck Scan Audit Script

Reads configuration from bd-config.json, fetches filtered BOM components,
and applies automated comments based on match type and upgrade recommendation.

Usage:
    python blackduck_audit.py [--config bd-config.json]

API notes (discovered from live BD instance):
  - Auth: POST /api/tokens/authenticate with "Authorization: token <api_key>"
          returns bearerToken for all subsequent calls.
  - matchTypes values: FILE_DEPENDENCY_TRANSITIVE, FILE_DEPENDENCY_DIRECT
  - Direct dep info: parsed from BDIO scan data (child→parent map built at startup)
  - Upgrade guidance URL: item._meta.links[rel=upgrade-guidance] or
                          item.origins[].links[rel=upgrade-guidance]
  - Comments URL: item._meta.links[rel=comments]  (uses component-versions path)
  - inputExternalIds[0]: "groupId:artifactId:version" for the item itself
"""

import argparse
import io
import json
import sys
import logging
import zipfile
from collections import deque
from pathlib import Path
import requests

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(funcName)s: %(message)s",
)
log = logging.getLogger(__name__)

SAP_CLOUD_ANDROID_GROUP = "com.sap.cloud.android"
BDIO_HAS_DEPENDENCY = "https://blackducksoftware.github.io/bdio#hasDependency"
BDIO_DEPENDS_ON = "https://blackducksoftware.github.io/bdio#dependsOn"


def load_config(config_path: str) -> dict:
    path = Path(config_path)
    if not path.exists():
        log.error("Config file not found: %s", config_path)
        sys.exit(1)
    with open(path) as f:
        config = json.load(f)
    log.debug("Loaded config from %s", config_path)
    return config


def authenticate(base_url: str, api_token: str) -> str:
    """Exchange a BlackDuck API token for a session Bearer token."""
    url = f"{base_url.rstrip('/')}/api/tokens/authenticate"
    headers = {
        "Authorization": f"token {api_token}",
        "Accept": "application/vnd.blackducksoftware.user-4+json",
    }
    log.debug("Authenticating at %s", url)
    resp = requests.post(url, headers=headers, timeout=30)
    resp.raise_for_status()
    bearer = resp.json().get("bearerToken")
    if not bearer:
        log.error("No bearerToken in auth response: %s", resp.text)
        sys.exit(1)
    log.debug("Authentication successful")
    return bearer


def get_current_username(base_url: str, token: str) -> str:
    """Return the userName of the currently authenticated user."""
    data = bd_get(token, f"{base_url.rstrip('/')}/api/current-user",
                  accept="application/vnd.blackducksoftware.user-4+json")
    username = data.get("userName", "")
    log.debug("Current user: %s", username)
    return username


def bd_get(token: str, url: str, params: dict = None, accept: str = "application/json") -> dict:
    """Make an authenticated GET request. URL must be absolute."""
    headers = {"Authorization": f"Bearer {token}", "Accept": accept}
    log.debug("GET %s params=%s", url, params)
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_link(item: dict, rel: str) -> str:
    """Extract a named link href from _meta.links."""
    for link in item.get("_meta", {}).get("links", []):
        if link.get("rel") == rel:
            return link["href"]
    return ""


def get_origin_link(item: dict, rel: str) -> str:
    """Extract a named link href from the first origin's _meta.links."""
    for origin in item.get("origins", []):
        for link in origin.get("_meta", {}).get("links", []):
            if link.get("rel") == rel:
                return link["href"]
    return ""


def add_comment(token: str, comments_url: str, comment: str) -> None:
    """Add a comment to a BOM component."""
    log.debug("Commenting on %s: %s", comments_url, comment)
    resp = requests.post(
        comments_url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"comment": comment},
        timeout=30,
    )
    if resp.status_code not in (200, 201):
        log.error("Failed to add comment (%s): %s", resp.status_code, resp.text)
    else:
        log.debug("Comment added successfully")


def delete_all_comments(token: str, comments_url: str, component_label: str,
                        current_username: str = "") -> int:
    """Delete existing comments on a BOM component posted by current_username.
    If current_username is empty, deletes all comments. Returns number deleted."""
    try:
        data = bd_get(token, comments_url, {"limit": 100})
    except Exception as e:
        log.debug("Could not fetch comments for %s: %s", component_label, e)
        return 0

    deleted = 0
    for comment in data.get("items", []):
        if current_username:
            comment_user = comment.get("user", {}).get("userName", "")
            if comment_user != current_username:
                log.debug("Skipping comment by %s (not current user)", comment_user)
                continue
        comment_href = comment.get("_meta", {}).get("href", "")
        if not comment_href:
            continue
        resp = requests.delete(
            comment_href,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        if resp.status_code in (200, 204):
            deleted += 1
            log.debug("Deleted comment %s", comment_href)
        else:
            log.error("Failed to delete comment %s (%s): %s", comment_href, resp.status_code, resp.text)
    return deleted


def find_project_version_url(base_url: str, token: str, project_name: str, version_name: str) -> str:
    """Resolve project + version names to a project-version URL."""
    data = bd_get(token, f"{base_url.rstrip('/')}/api/projects", {"q": f"name:{project_name}"})
    for proj in data.get("items", []):
        if proj["name"] == project_name:
            proj_href = proj["_meta"]["href"]
            versions = bd_get(token, f"{proj_href}/versions", {"q": f"versionName:{version_name}"})
            for ver in versions.get("items", []):
                if ver["versionName"] == version_name:
                    log.debug("Found project version: %s", ver["_meta"]["href"])
                    return ver["_meta"]["href"]
    log.error("Project '%s' version '%s' not found", project_name, version_name)
    sys.exit(1)


def build_direct_dep_map(base_url: str, token: str, version_url: str) -> dict:
    """
    Build a map of component_gav (groupId:artifactId:version) → coords of the "direct
    dependency" (node directly after the SAP root in its dependency path).

    Algorithm:
    1. Parse BDIO to get a parent→children adjacency map.
    2. Identify root nodes: SAP nodes that have no parents.
    3. BFS from each root, recording for each visited node which direct child of that root
       leads to it.
    4. For each component version, store the best direct-child-of-root coords, preferring
       paths from non-demo SAP roots over demo SAP roots.

    Returns: {child_gav: coords_dict} where coords is the direct child of the best root.
    Using the full groupId:artifactId:version key avoids collisions between different
    versions of the same component (e.g. lifecycle-runtime 2.3.1 vs 2.10.0).
    """
    # Get codelocations for this project version
    codelocations = bd_get(token, f"{version_url}/codelocations")
    bdio_url = None
    # Prefer the codelocation named "bdio"; fall back to any that has a scan-data link
    for cl in codelocations.get("items", []):
        if "bdio" in cl.get("name", "").lower():
            bdio_url = get_link(cl, "scan-data")
            break
    if not bdio_url:
        for cl in codelocations.get("items", []):
            bdio_url = get_link(cl, "scan-data")
            if bdio_url:
                break

    if not bdio_url:
        log.warning("No BDIO scan data found — direct dep lookup unavailable")
        return {}

    log.debug("Fetching BDIO from %s", bdio_url)
    resp = requests.get(bdio_url, headers={"Authorization": f"Bearer {token}"}, timeout=60)
    if resp.status_code != 200:
        log.warning("Could not fetch BDIO (%s)", resp.status_code)
        return {}

    try:
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
    except Exception as e:
        log.warning("BDIO is not a zip: %s", e)
        return {}

    # Build adjacency: parent_id → list of child_ids
    children_of: dict = {}
    all_child_ids: set = set()
    for name in zf.namelist():
        if not name.endswith(".jsonld"):
            continue
        with zf.open(name) as f:
            try:
                data = json.load(f)
            except Exception as e:
                log.debug("Could not parse BDIO entry %s: %s", name, e)
                continue
        for node in data.get("@graph", []):
            parent_id = node.get("@id", "")
            for dep in node.get(BDIO_HAS_DEPENDENCY, []):
                for child_ref in dep.get(BDIO_DEPENDS_ON, []):
                    child_id = child_ref.get("@id", "")
                    if child_id:
                        children_of.setdefault(parent_id, []).append(child_id)
                        all_child_ids.add(child_id)

    # Root nodes: have children but no parents (not a child of anyone)
    all_parent_ids = set(children_of.keys())
    roots = all_parent_ids - all_child_ids
    log.debug("BDIO roots: %s", roots)

    # BFS from each root: for every reachable node record (root_coords, direct_child_coords, depth)
    # child_gav → best (root_coords, direct_child_coords, depth)
    # Priority: lower _parent_priority wins; among ties, shorter depth wins.
    result: dict = {}

    for root_id in roots:
        root_coords = _parse_bdio_id(root_id)
        if not root_coords:
            continue
        # BFS: queue entries are (node_id, direct_child_of_root_id, depth)
        queue = deque()
        visited = {root_id}
        for child_id in children_of.get(root_id, []):
            queue.append((child_id, child_id, 1))
            visited.add(child_id)
        while queue:
            node_id, direct_child_id, depth = queue.popleft()
            node_coords = _parse_bdio_id(node_id)
            direct_child_coords = _parse_bdio_id(direct_child_id)
            if node_coords and direct_child_coords:
                gav = node_coords["externalId"]  # groupId:artifactId:version
                existing = result.get(gav)
                new_prio = _parent_priority(root_coords)
                if existing is None:
                    result[gav] = (root_coords, direct_child_coords, depth)
                else:
                    old_prio = _parent_priority(existing[0])
                    old_depth = existing[2]
                    if new_prio < old_prio or (new_prio == old_prio and depth < old_depth):
                        result[gav] = (root_coords, direct_child_coords, depth)
            for child_id in children_of.get(node_id, []):
                if child_id not in visited:
                    visited.add(child_id)
                    queue.append((child_id, direct_child_id, depth + 1))

    # Flatten: child_gav → (root_coords, direct_child_coords)
    flat = {gav: (v[0], v[1]) for gav, v in result.items()}
    log.debug("Built direct dep map with %d entries", len(flat))
    return flat


def _parse_bdio_id(bdio_id: str) -> dict:
    """
    Parse a BDIO @id like 'http:maven/groupId/artifactId/version'
    Returns {"groupId": ..., "artifactId": ..., "version": ...} or None.
    """
    if not bdio_id or not bdio_id.startswith("http:maven/"):
        return None
    parts = bdio_id[len("http:maven/"):].split("/")
    if len(parts) < 2:
        return None
    return {
        "groupId": parts[0],
        "artifactId": parts[1],
        "version": parts[2] if len(parts) > 2 else "",
        "externalId": f"{parts[0]}:{parts[1]}:{parts[2]}" if len(parts) > 2 else f"{parts[0]}:{parts[1]}",
    }


def _parent_priority(coords: dict) -> int:
    """
    Lower number = higher priority (preferred root).
    Priority:
      0 — com.sap.cloud.android, non-demo/sample  (core SAP libraries)
      1 — com.sap.cloud.android, demo/sample       (demo apps)
      2 — any other group                           (third-party)
    """
    if coords.get("groupId") != SAP_CLOUD_ANDROID_GROUP:
        return 2
    if _is_demo_sample(coords.get("groupId", ""), coords.get("artifactId", "")):
        return 1
    return 0


def resolve_filter_values(token: str, version_url: str, filters: dict) -> list:
    """
    Resolve human-readable config filter keys/values to BD API filter=key:value strings.

    The BD API uses filter=<filterKey>:<filterValue> query params (repeatable).
    Filter keys differ from response field names — e.g. "bomInclusion" not "ignored",
    "policyRuleViolation" not "policyStatus".

    We discover available filter key/value pairs by GETting the static-filter and
    quick-filter links from the components endpoint _meta.links, then match the
    human-readable config values to the discovered filter values.

    Config key mapping:
      "Ignore" / "Not Ignored"       → bomInclusion filter, value matching "Not Ignored"
      "Policy Violations" / "In violation" → policyRuleViolation filter, matching "In violation"
    """
    if not filters:
        return []

    # Probe the endpoint (limit=1) to get filter links from _meta.links
    probe = bd_get(
        token, f"{version_url}/components", {"limit": 1},
        accept="application/vnd.blackducksoftware.bill-of-materials-6+json",
    )
    filter_links = [
        link["href"] for link in probe.get("_meta", {}).get("links", [])
        if link.get("rel") in ("static-filter", "quick-filter", "dynamic-filter")
    ]
    log.debug("Found %d filter links", len(filter_links))

    # Build a map: filterKey → {label → filterValue}
    # Each filter endpoint returns {"name": filterKey, "values": [{"key": filterValue, "label": ...}]}
    filter_catalog: dict[str, dict] = {}
    for furl in filter_links:
        try:
            fdata = bd_get(token, furl)
        except Exception as e:
            log.debug("Could not fetch filter link %s: %s", furl, e)
            continue
        fname = fdata.get("name", "")
        if not fname:
            continue
        label_to_key: dict[str, str] = {}
        for val in fdata.get("values", []):
            label_to_key[val.get("label", "").lower()] = val.get("key", "")
        filter_catalog[fname] = label_to_key
        log.debug("Filter catalog entry: %s → %s", fname, label_to_key)

    # Human-readable config → (filterKey, valueLabel)
    # bomInclusion: "not ignored" = false (show only non-ignored items)
    # bomPolicy: "in violation" = in_violation (show only policy-violating items)
    config_to_filter = {
        ("Ignore", "Not Ignored"):           ("bomInclusion", "Not Ignored"),
        ("Ignore", "Ignored"):               ("bomInclusion", "Ignored"),
        ("Policy Violations", "In violation"):     ("bomPolicy", "In violation"),
        ("Policy Violations", "Not in violation"): ("bomPolicy", "Not in violation"),
    }

    filter_params = []
    for cfg_key, cfg_value in filters.items():
        mapping = config_to_filter.get((cfg_key, cfg_value))
        if not mapping:
            log.debug("No BD filter mapping for config '%s':'%s', skipping", cfg_key, cfg_value)
            continue
        fkey, flabel = mapping
        catalog_entry = filter_catalog.get(fkey, {})
        fvalue = catalog_entry.get(flabel.lower())
        if not fvalue:
            # Fall back to exact value if label lookup fails
            log.warning("Filter value for '%s:%s' not found in catalog, using label as value", fkey, flabel)
            fvalue = flabel
        filter_params.append(f"{fkey}:{fvalue}")
        log.debug("Resolved filter: filter=%s:%s", fkey, fvalue)

    return filter_params


def get_bom_components(token: str, version_url: str, filters: dict) -> list:
    """Fetch BOM components with filters using the BD filter=key:value query param format."""
    filter_params = resolve_filter_values(token, version_url, filters)

    # BD API accepts repeated `filter` params; requests handles list values correctly
    params: dict = {"limit": 500, "offset": 0}
    if filter_params:
        params["filter"] = filter_params  # requests will send as ?filter=a:b&filter=c:d

    all_items = []
    while True:
        data = bd_get(
            token, f"{version_url}/components", params,
            accept="application/vnd.blackducksoftware.bill-of-materials-6+json",
        )
        items = data.get("items", [])
        all_items.extend(items)
        log.debug(
            "Fetched %d items (total so far: %d / totalCount: %d) appliedFilters=%s",
            len(items), len(all_items), data.get("totalCount", 0),
            data.get("appliedFilters", []),
        )
        if len(all_items) >= data.get("totalCount", 0):
            break
        params["offset"] += params["limit"]
    return all_items


def get_upgrade_guidance(token: str, item: dict) -> dict:
    """Fetch upgrade guidance using the link from _meta or origin links."""
    # Prefer the item-level upgrade-guidance link
    guidance_url = get_link(item, "upgrade-guidance") or get_origin_link(item, "upgrade-guidance")
    if not guidance_url:
        # Fall back to componentVersion href
        cv = item.get("componentVersion", "")
        if cv:
            guidance_url = f"{cv}/upgrade-guidance"
    if not guidance_url:
        return {}
    try:
        return bd_get(token, guidance_url)
    except Exception as e:
        log.debug("Could not fetch upgrade guidance: %s", e)
        return {}


def get_direct_dep_upgrade_guidance(token: str, base_url: str, parent_coords: dict) -> dict:
    """
    Fetch upgrade guidance for a direct dependency identified by BDIO coords.
    We look up the component version via the BD component search API.
    """
    group_id = parent_coords.get("groupId", "")
    artifact_id = parent_coords.get("artifactId", "")
    version = parent_coords.get("version", "")
    if not (group_id and artifact_id and version):
        return {}

    external_id = f"{group_id}:{artifact_id}:{version}"
    search_url = f"{base_url.rstrip('/')}/api/components"
    try:
        data = bd_get(token, search_url, {"q": f"id:{external_id}"})
        for comp in data.get("items", []):
            for ver_item in comp.get("versions", []):
                if ver_item.get("versionName") == version:
                    cv_href = ver_item.get("_meta", {}).get("href", "")
                    if cv_href:
                        return bd_get(token, f"{cv_href}/upgrade-guidance")
    except Exception as e:
        log.debug("Could not fetch direct dep upgrade guidance for %s: %s", external_id, e)
    return {}


def is_not_available(guidance: dict) -> bool:
    """Return True if both short-term and long-term upgrades are unavailable."""
    def _unavailable(rec):
        if not rec:
            return True
        version = rec.get("versionName", "") or rec.get("version", "")
        return not version

    return _unavailable(guidance.get("shortTerm")) and _unavailable(guidance.get("longTerm"))


def get_component_label(item: dict) -> str:
    return f"{item.get('componentName', 'unknown')} {item.get('componentVersionName', '')}".strip()


def get_item_external_id(item: dict) -> str:
    """Get the primary external ID (groupId:artifactId:version) for this item."""
    ids = item.get("inputExternalIds", [])
    if ids:
        return ids[0]
    # Fall back to origin
    for origin in item.get("origins", []):
        eid = origin.get("externalId", "")
        if eid:
            return eid
    return ""


def get_ga_from_external_id(external_id: str) -> str:
    """Extract groupId:artifactId from a full external ID."""
    parts = external_id.split(":")
    if len(parts) >= 2:
        return f"{parts[0]}:{parts[1]}"
    return external_id


def process_item(base_url: str, token: str, item: dict, direct_dep_map: dict) -> None:
    """Apply comment logic for a single BOM component item.

    Rule order (stop after first comment):
    0. Path root is demo/sample → "used for {demo|sample}, will not ship to customer"
    1. Component's own upgrade guidance N/A → "the version of X is the latest one"
    2. Transitive only — check direct dep:
       a. SAP group → "introduced by groupId:artifactId"
       b. test/gradle/dokka → "used for {test|build|doc}, will not ship to customer"
       c. Direct dep upgrade guidance N/A → "the version of direct dependency X is the latest one"
    """
    match_types = item.get("matchTypes", [])
    component_label = get_component_label(item)
    comments_url = get_link(item, "comments")

    if not comments_url:
        log.warning("No comments URL for %s, skipping", component_label)
        return

    log.debug("Processing: %s | matchTypes=%s", component_label, match_types)

    # Step 0: path root is demo/sample — checked before anything else
    external_id = get_item_external_id(item)  # groupId:artifactId:version
    entry = direct_dep_map.get(external_id)  # (root_coords, direct_child_coords) or None
    if entry:
        root_coords, direct_child_coords = entry
        kw = _is_demo_sample(root_coords.get("groupId", ""), root_coords.get("artifactId", ""))
        if kw:
            comment = f"used for {kw}, will not ship to customer"
            log.debug("Demo/sample path root → comment: %s", comment)
            add_comment(token, comments_url, comment)
            return

    # Step 1: component's own upgrade guidance (applies to all match types)
    guidance = get_upgrade_guidance(token, item)
    if is_not_available(guidance):
        comment = f"the version of {component_label} is the latest one"
        log.debug("Component upgrade N/A → comment: %s", comment)
        add_comment(token, comments_url, comment)
        return

    # Step 2: transitive — check direct dependency
    match_type_str = " ".join(match_types).upper() if isinstance(match_types, list) else (match_types or "").upper()
    direct_child = entry[1] if entry else None

    if "TRANSITIVE" in match_type_str and direct_child:
        parent_group = direct_child.get("groupId", "")
        parent_artifact = direct_child.get("artifactId", "")
        parent_version = direct_child.get("version", "")
        parent_label = f"{parent_group}:{parent_artifact} {parent_version}".strip()

        # 2a. SAP cloud android group
        if parent_group == SAP_CLOUD_ANDROID_GROUP:
            comment = f"introduced by {parent_group}:{parent_artifact}"
            log.debug("SAP group direct dep → comment: %s", comment)
            add_comment(token, comments_url, comment)
            return

        # 2b. Test / gradle / dokka related
        label = _is_test_gradle_dokka(parent_group, parent_artifact)
        if label:
            comment = f"used for {label}, will not ship to customer"
            log.debug("Test/gradle/dokka direct dep → comment: %s", comment)
            add_comment(token, comments_url, comment)
            return

        # 2c. Direct dep's own upgrade guidance N/A
        parent_guidance = get_direct_dep_upgrade_guidance(token, base_url, direct_child)
        if is_not_available(parent_guidance):
            comment = f"the version of direct dependency {parent_label} is the latest one"
            log.debug("Direct dep latest → comment: %s", comment)
            add_comment(token, comments_url, comment)
    else:
        log.debug("No further rules for matchType: %s", match_type_str)


_DEMO_SAMPLE_KEYWORDS = ("demo", "sample")

# keyword → label used in comment text
_KEYWORD_LABEL_MAP = {
    "test":   "test",
    "gradle": "build",
    "dokka":  "doc",
}


def _is_demo_sample(group_id: str, artifact_id: str) -> str:
    """Return 'demo' or 'sample' if the dep is demo/sample related, else empty string."""
    combined = f"{group_id} {artifact_id}".lower()
    for kw in _DEMO_SAMPLE_KEYWORDS:
        if kw in combined:
            return kw
    return ""


def _is_test_gradle_dokka(group_id: str, artifact_id: str) -> str:
    """
    Return the comment label if the dep is test/gradle/dokka related, else empty string.
    'gradle' → 'build', 'dokka' → 'doc', 'test' → 'test'.
    Checks both groupId and artifactId (lowercased).
    """
    combined = f"{group_id} {artifact_id}".lower()
    for kw, label in _KEYWORD_LABEL_MAP.items():
        if kw in combined:
            return label
    return ""


def ignore_commented_components(token: str, version_url: str, items: list,
                                current_username: str = "") -> None:
    """
    Ignore all filtered BOM components that have at least one comment from the current user.

    Uses the bulk-adjustment PATCH endpoint (max 100 components per request).
    """
    bulk_url = f"{version_url}/bulk-adjustment"
    accept = "application/vnd.blackducksoftware.bill-of-materials-7+json"

    to_ignore = []
    for item in items:
        component_label = get_component_label(item)
        comments_url = get_link(item, "comments")
        if not comments_url:
            continue
        try:
            data = bd_get(token, comments_url, {"limit": 100})
        except Exception as e:
            log.debug("Could not fetch comments for %s: %s", component_label, e)
            continue
        # Check if any comment is from the current user
        comments = data.get("items", [])
        if current_username:
            has_user_comment = any(
                c.get("user", {}).get("userName", "") == current_username
                for c in comments
            )
        else:
            has_user_comment = len(comments) > 0
        if has_user_comment:
            href = item.get("_meta", {}).get("href", "")
            if href:
                to_ignore.append((href, component_label))
                log.debug("Queued for ignore: %s", component_label)

    log.debug("Components with comments to ignore: %d", len(to_ignore))

    # Send in batches of 100
    BATCH_SIZE = 100
    total_ignored = 0
    for start in range(0, len(to_ignore), BATCH_SIZE):
        batch = to_ignore[start:start + BATCH_SIZE]
        hrefs = [h for h, _ in batch]
        labels = [l for _, l in batch]
        payload = {"components": hrefs, "ignored": True}
        log.debug("Bulk-ignoring batch of %d: %s", len(hrefs), labels)
        resp = requests.patch(
            bulk_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": accept,
                "Accept": accept,
            },
            json=payload,
            timeout=60,
        )
        if resp.status_code == 200:
            n = resp.json().get("numberOfManagedAdjustments", len(hrefs))
            total_ignored += n
            log.debug("Batch ignored %d component(s)", n)
        else:
            log.error("bulk-adjustment failed (%s): %s", resp.status_code, resp.text)

    log.debug("Ignore complete. %d component(s) marked as ignored.", total_ignored)


def main():
    parser = argparse.ArgumentParser(description="BlackDuck scan audit tool")
    parser.add_argument("--config", default="bd-config.json", help="Path to bd-config.json")
    parser.add_argument("--delete-comments", action="store_true",
                        help="Delete all existing comments from filtered BOM items instead of adding new ones")
    parser.add_argument("--ignore-commented", action="store_true",
                        help="Ignore all filtered BOM components that have at least one comment")
    parser.add_argument("--component", metavar="NAME",
                        help="Audit only the component(s) whose name contains this string (case-insensitive)")
    args = parser.parse_args()

    config = load_config(args.config)

    base_url = config["baseUrl"]
    api_token = config["accessToken"]
    project_name = config["projectName"]
    version_name = config["versionName"]
    filters = config.get("filters", {})

    log.debug("Audit: project=%s version=%s", project_name, version_name)

    token = authenticate(base_url, api_token)
    current_username = get_current_username(base_url, token)
    version_url = find_project_version_url(base_url, token, project_name, version_name)

    items = get_bom_components(token, version_url, filters)
    log.debug("Total BOM items fetched: %d", len(items))

    # Filter to a specific component if --component was given
    if args.component:
        needle = args.component.lower()
        items = [i for i in items if needle in i.get("componentName", "").lower()]
        log.debug("Filtered to %d item(s) matching --component '%s'", len(items), args.component)

    if args.delete_comments:
        total_deleted = 0
        for i, item in enumerate(items):
            component_label = get_component_label(item)
            log.debug("--- Deleting comments %d/%d: %s ---", i + 1, len(items), component_label)
            comments_url = get_link(item, "comments")
            if not comments_url:
                log.warning("No comments URL for %s, skipping", component_label)
                continue
            try:
                n = delete_all_comments(token, comments_url, component_label, current_username)
                total_deleted += n
                log.debug("Deleted %d comment(s) from %s", n, component_label)
            except Exception as e:
                log.error("Error deleting comments for %s: %s", component_label, e, exc_info=True)
        log.debug("Deletion complete. Removed %d comment(s) across %d items.", total_deleted, len(items))
        return

    if args.ignore_commented:
        ignore_commented_components(token, version_url, items, current_username)
        return

    log.debug("Building direct dependency map from BDIO...")
    direct_dep_map = build_direct_dep_map(base_url, token, version_url)

    for i, item in enumerate(items):
        log.debug("--- Item %d/%d ---", i + 1, len(items))
        try:
            process_item(base_url, token, item, direct_dep_map)
        except Exception as e:
            log.error("Error processing item %s: %s", get_component_label(item), e, exc_info=True)

    log.debug("Audit complete. Processed %d items.", len(items))


if __name__ == "__main__":
    main()
