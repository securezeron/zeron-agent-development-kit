"""
ZAK dep-patch tools — @zak_tool functions for dependency update management.

Provides tools for fetching package.json from GitHub, parsing dependency ranges,
querying npm registries, finding compatible semver updates, assessing risk via LLM,
and creating GitHub pull requests with the updates.
"""

from __future__ import annotations

import base64
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from zak.core.runtime.agent import AgentContext
from zak.core.tools.substrate import zak_tool


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z\-.]+))?"
    r"(?:\+(?P<build>[0-9A-Za-z\-.]+))?$"
)

_NON_REGISTRY_PATTERNS = [
    re.compile(r"^file:"),
    re.compile(r"^link:"),
    re.compile(r"^workspace:"),
    re.compile(r"^https?://"),
    re.compile(r"^git(\+https?|\+ssh)?://"),
    re.compile(r"^github:"),
    re.compile(r"/"),  # github shorthand like "user/repo"
]


def _parse_version(s: str) -> tuple[int, int, int] | None:
    """Parse a semver string into (major, minor, patch) or None."""
    m = _SEMVER_RE.match(s.strip())
    if not m:
        return None
    return int(m.group("major")), int(m.group("minor")), int(m.group("patch"))


def _is_prerelease(s: str) -> bool:
    """Check if a version string is a prerelease."""
    m = _SEMVER_RE.match(s.strip())
    return bool(m and m.group("pre"))


def _is_valid_semver(s: str) -> bool:
    """Check if a string is a valid semver."""
    return _SEMVER_RE.match(s.strip()) is not None


def _version_key(s: str) -> tuple[int, int, int]:
    """Return a sortable key for a version string."""
    v = _parse_version(s)
    return v if v else (0, 0, 0)


def _is_registry_range(range_str: str) -> bool:
    """Return True if the range looks like it comes from a registry (not git/file/etc.)."""
    return not any(p.search(range_str) for p in _NON_REGISTRY_PATTERNS)


def _get_range_type(range_str: str) -> str:
    """Classify a version range string."""
    if not _is_registry_range(range_str):
        return "non_registry"

    cleaned = range_str.strip()
    if cleaned.startswith("^"):
        return "caret"
    if cleaned.startswith("~"):
        return "tilde"
    if cleaned in ("*", "latest"):
        return "any"
    if "||" in cleaned or " - " in cleaned or ">=" in cleaned or "<=" in cleaned:
        return "complex"
    if _is_valid_semver(cleaned):
        return "exact"
    return "complex"


def _satisfies_range(
    version_str: str, range_str: str, range_type: str,
) -> bool:
    """Check if a version satisfies a semver range."""
    ver = _parse_version(version_str)
    if ver is None:
        return False

    if range_type == "any":
        return True

    # Strip prefix to get base version
    cleaned = range_str.lstrip("^~").strip()
    base = _parse_version(cleaned)
    if base is None:
        return False

    if range_type == "caret":
        # ^X.Y.Z: >= X.Y.Z and < next breaking change
        if ver < base:
            return False
        if base[0] > 0:
            return ver[0] == base[0]
        elif base[1] > 0:
            return ver[0] == 0 and ver[1] == base[1]
        else:
            return ver[0] == 0 and ver[1] == 0 and ver[2] == base[2]

    if range_type == "tilde":
        # ~X.Y.Z: >= X.Y.Z and < X.(Y+1).0
        if ver < base:
            return False
        return ver[0] == base[0] and ver[1] == base[1]

    # Complex ranges: cannot evaluate without a full parser
    return False


def _get_config(context: AgentContext, key: str, env_key: str, default: str = "") -> str:
    """Read config from context.metadata first, then fall back to env var."""
    val = context.metadata.get(key, "")
    if val:
        return str(val)
    return os.environ.get(env_key, default)


def _github_api_request(
    url: str, token: str, method: str = "GET", data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Make a GitHub REST API request."""
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"token {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "zak-dep-patch-agent")
    if data:
        req.add_header("Content-Type", "application/json")
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# @zak_tool functions
# ---------------------------------------------------------------------------


@zak_tool(
    name="fetch_package_json",
    description="Fetch package.json from a GitHub repository via REST API",
    action_id="fetch_package_json",
    tags=["supply_chain", "github", "read"],
)
def fetch_package_json(
    context: AgentContext,
    owner: str = "",
    repo: str = "",
    package_path: str = "",
) -> dict[str, Any]:
    """Fetch and parse package.json from a GitHub repository."""
    token = _get_config(context, "github_token", "GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GitHub token is required (metadata.github_token or GITHUB_TOKEN env)")

    # Resolve owner/repo from metadata if not passed directly
    if not owner or not repo:
        owner = _get_config(context, "owner", "")
        repo = _get_config(context, "repo", "")
    if not owner or not repo:
        repo_full = _get_config(context, "repo_full", "DEP_PATCH_REPO")
        if "/" in repo_full:
            owner, repo = repo_full.split("/", 1)
    if not owner or not repo:
        raise RuntimeError("Repository owner/repo is required")

    if not package_path:
        package_path = _get_config(context, "package_path", "DEP_PATCH_PATH", "package.json")

    api = "https://api.github.com"

    # Get default branch
    repo_data = _github_api_request(f"{api}/repos/{owner}/{repo}", token)
    default_branch = repo_data["default_branch"]

    # Fetch file
    encoded_path = urllib.parse.quote(package_path, safe="")
    file_data = _github_api_request(
        f"{api}/repos/{owner}/{repo}/contents/{encoded_path}?ref={default_branch}",
        token,
    )

    if file_data.get("type") != "file":
        raise RuntimeError(f"{package_path} is not a file")

    content_bytes = base64.b64decode(file_data["content"])
    parsed = json.loads(content_bytes.decode("utf-8"))

    return {
        "content": parsed,
        "sha": file_data["sha"],
        "default_branch": default_branch,
        "package_path": package_path,
    }


@zak_tool(
    name="parse_dependencies",
    description="Parse package.json dependencies and classify version ranges",
    action_id="parse_dependencies",
    tags=["supply_chain", "parse"],
)
def parse_dependencies(
    context: AgentContext, package_json: dict[str, Any],
) -> list[dict[str, Any]]:
    """Classify all dependencies by range type and updatability."""
    deps: list[dict[str, Any]] = []
    sections = ["dependencies", "devDependencies"]

    for section in sections:
        entries = package_json.get(section)
        if not entries or not isinstance(entries, dict):
            continue
        for name, range_str in entries.items():
            range_type = _get_range_type(str(range_str))
            deps.append({
                "name": name,
                "range": str(range_str),
                "range_type": range_type,
                "section": section,
                "is_updatable": range_type in ("caret", "tilde", "complex", "any"),
            })

    return deps


@zak_tool(
    name="fetch_registry_versions",
    description="Fetch available versions from npm registry for a package",
    action_id="fetch_registry_versions",
    tags=["supply_chain", "registry", "read"],
)
def fetch_registry_versions(
    context: AgentContext,
    package_name: str,
    registry_url: str = "",
    registry_token: str = "",
) -> dict[str, Any]:
    """Query npm (or private) registry for all available versions of a package."""
    if not registry_url:
        registry_url = _get_config(
            context, "registry_url", "REGISTRY_URL", "https://registry.npmjs.org",
        )
    if not registry_token:
        registry_token = _get_config(context, "registry_token", "REGISTRY_TOKEN")

    registry_url = registry_url.rstrip("/")
    url = f"{registry_url}/{package_name}"

    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.npm.install-v1+json")
    req.add_header("User-Agent", "zak-dep-patch-agent")
    if registry_token:
        req.add_header("Authorization", f"Bearer {registry_token}")

    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            versions = list((data.get("versions") or {}).keys())
            return {"versions": versions, "error": None}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"versions": [], "error": f'Package "{package_name}" not found in registry'}
        return {"versions": [], "error": f"Registry returned {e.code} for \"{package_name}\""}
    except Exception as e:
        return {"versions": [], "error": f"Registry error: {e}"}


@zak_tool(
    name="find_compatible_updates",
    description="Find the latest compatible version update within a semver range",
    action_id="find_compatible_updates",
    tags=["supply_chain", "semver"],
)
def find_compatible_updates(
    context: AgentContext,
    dep: dict[str, Any],
    available_versions: list[str],
) -> dict[str, Any]:
    """Find compatible updates for a dependency within its semver range."""
    name = dep["name"]
    range_str = dep["range"]
    range_type = dep.get("range_type", _get_range_type(range_str))

    # Exact or non-registry: no update
    if range_type in ("exact", "non_registry"):
        return {
            "name": name,
            "current_range": range_str,
            "current_version": range_str if range_type == "exact" else None,
            "latest_compatible": None,
            "new_range": None,
            "update_type": "locked" if range_type == "exact" else "skipped",
        }

    # Get minimum version from the range
    cleaned = range_str.lstrip("^~").strip()
    min_ver = _parse_version(cleaned)
    if min_ver is None:
        return {
            "name": name,
            "current_range": range_str,
            "current_version": None,
            "latest_compatible": None,
            "new_range": None,
            "update_type": "skipped",
        }
    min_ver_str = f"{min_ver[0]}.{min_ver[1]}.{min_ver[2]}"

    # Filter to valid, non-prerelease versions satisfying the range
    compatible = [
        v for v in available_versions
        if _is_valid_semver(v)
        and not _is_prerelease(v)
        and _satisfies_range(v, range_str, range_type)
    ]
    compatible.sort(key=_version_key)

    if not compatible:
        return {
            "name": name,
            "current_range": range_str,
            "current_version": min_ver_str,
            "latest_compatible": None,
            "new_range": None,
            "update_type": "none",
        }

    latest = compatible[-1]
    latest_ver = _parse_version(latest)

    # Check if there's actually an update
    if latest_ver == min_ver:
        return {
            "name": name,
            "current_range": range_str,
            "current_version": min_ver_str,
            "latest_compatible": latest,
            "new_range": None,
            "update_type": "none",
        }

    # Determine update type
    assert latest_ver is not None
    if latest_ver[0] > min_ver[0]:
        update_type = "major"
    elif latest_ver[1] > min_ver[1]:
        update_type = "minor"
    elif latest_ver[2] > min_ver[2]:
        update_type = "patch"
    else:
        update_type = "none"

    if update_type == "none":
        return {
            "name": name,
            "current_range": range_str,
            "current_version": min_ver_str,
            "latest_compatible": latest,
            "new_range": None,
            "update_type": "none",
        }

    # Build new range preserving prefix
    if range_type == "caret":
        new_range = f"^{latest}"
    elif range_type == "tilde":
        new_range = f"~{latest}"
    else:
        # Complex/any: keep original range, note the latest compatible
        new_range = range_str

    return {
        "name": name,
        "current_range": range_str,
        "current_version": min_ver_str,
        "latest_compatible": latest,
        "new_range": new_range,
        "update_type": update_type,
    }


@zak_tool(
    name="assess_update_risks",
    description="Assess risk of dependency updates using LLM",
    action_id="assess_update_risks",
    tags=["supply_chain", "risk", "llm"],
)
def assess_update_risks(
    context: AgentContext, updates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Assess risk of each dependency update using ZAK's configured LLM."""
    if not updates:
        return []

    # Get LLM client from DSL config
    try:
        from zak.core.llm.registry import get_llm_client

        llm_cfg: dict[str, Any] = {}
        if context.dsl.reasoning.llm:
            llm_block = context.dsl.reasoning.llm
            llm_cfg = (
                llm_block if isinstance(llm_block, dict)
                else llm_block.model_dump(exclude_none=True)
            )

        client = get_llm_client(
            provider=llm_cfg.get("provider"),
            model=llm_cfg.get("model"),
        )
    except Exception:
        return [
            {**u, "risk": "UNKNOWN", "risk_reason": "No LLM configured"}
            for u in updates
        ]

    # Build batch prompt (same as Node.js original)
    package_list = "\n".join(
        f"- {u['name']}: {u.get('current_version', '?')} -> "
        f"{u.get('latest_compatible', '?')} ({u.get('update_type', '?')} update)"
        for u in updates
    )

    prompt = (
        "You are a dependency update risk assessor. For each package update below, "
        "rate the risk as LOW, MEDIUM, or HIGH and give a brief reason (max 10 words).\n\n"
        "Consider:\n"
        "- Patch updates are generally LOW risk (bug fixes)\n"
        "- Minor updates may introduce new features but should be backward-compatible\n"
        "- Well-maintained popular packages are lower risk\n"
        "- Packages with many version jumps may carry more accumulated changes\n\n"
        f"Package updates:\n{package_list}\n\n"
        'Respond with a JSON object in this exact format:\n'
        '{"assessments": [{"name": "package-name", "risk": "LOW", '
        '"reason": "brief reason"}]}\n\n'
        "Include one entry per package. Use only LOW, MEDIUM, or HIGH for risk."
    )

    try:
        response = client.chat(
            messages=[{"role": "user", "content": prompt}],
            tools=[],
            temperature=0.2,
            max_tokens=2048,
        )

        content = response.content or ""
        assessments: list[dict[str, Any]] = []
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                assessments = parsed
            elif isinstance(parsed, dict):
                # Find first array value
                for v in parsed.values():
                    if isinstance(v, list):
                        assessments = v
                        break
        except (json.JSONDecodeError, TypeError):
            pass

        return [
            {
                **u,
                "risk": next(
                    (a.get("risk", "UNKNOWN") for a in assessments if a.get("name") == u["name"]),
                    "UNKNOWN",
                ),
                "risk_reason": next(
                    (a.get("reason", "Could not assess")
                     for a in assessments if a.get("name") == u["name"]),
                    "Could not assess",
                ),
            }
            for u in updates
        ]
    except Exception as e:
        return [
            {**u, "risk": "UNKNOWN", "risk_reason": f"LLM error: {e}"}
            for u in updates
        ]


@zak_tool(
    name="create_update_pr",
    description="Create a GitHub PR with dependency updates",
    action_id="create_update_pr",
    tags=["supply_chain", "github", "write"],
)
def create_update_pr(
    context: AgentContext,
    owner: str,
    repo: str,
    default_branch: str,
    branch_name: str,
    updated_package_json: dict[str, Any],
    original_sha: str,
    updates: list[dict[str, Any]],
    package_path: str = "package.json",
) -> dict[str, Any]:
    """Create a branch, commit updated package.json, and open a PR on GitHub."""
    token = _get_config(context, "github_token", "GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GitHub token is required")

    api = "https://api.github.com"

    # 1. Get latest commit SHA of the default branch
    ref_data = _github_api_request(
        f"{api}/repos/{owner}/{repo}/git/ref/heads/{default_branch}", token,
    )
    base_sha = ref_data["object"]["sha"]

    # 2. Create new branch
    _github_api_request(
        f"{api}/repos/{owner}/{repo}/git/refs",
        token,
        method="POST",
        data={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
    )

    # 3. Update package.json on the new branch
    updated_content = json.dumps(updated_package_json, indent=2) + "\n"
    encoded_content = base64.b64encode(updated_content.encode("utf-8")).decode("ascii")

    commit_msg = f"chore(deps): update {len(updates)} compatible dependencies"
    encoded_path = urllib.parse.quote(package_path, safe="")
    _github_api_request(
        f"{api}/repos/{owner}/{repo}/contents/{encoded_path}",
        token,
        method="PUT",
        data={
            "message": commit_msg,
            "content": encoded_content,
            "sha": original_sha,
            "branch": branch_name,
        },
    )

    # 4. Build PR body
    pr_body = _build_pr_body(updates)

    # 5. Create PR
    pr_data = _github_api_request(
        f"{api}/repos/{owner}/{repo}/pulls",
        token,
        method="POST",
        data={
            "title": commit_msg,
            "head": branch_name,
            "base": default_branch,
            "body": pr_body,
        },
    )

    return {"pr_url": pr_data["html_url"], "pr_number": pr_data["number"]}


def _build_pr_body(updates: list[dict[str, Any]]) -> str:
    """Build a markdown PR body with an update table."""
    risk_emoji = {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH"}

    rows = []
    for u in updates:
        risk = u.get("risk", "UNKNOWN")
        emoji = risk_emoji.get(risk, "UNKNOWN")
        reason = u.get("risk_reason", "—")
        rows.append(
            f"| {u['name']} | `{u.get('current_range', '')}` "
            f"| `{u.get('new_range', '')}` | {u.get('update_type', '')} "
            f"| {emoji} | {reason} |"
        )

    table = "\n".join(rows)
    return (
        f"## Dependency Updates\n\n"
        f"This PR updates {len(updates)} dependencies to their latest "
        f"compatible versions.\n\n"
        f"| Package | Previous | Updated | Type | Risk | Reason |\n"
        f"|---------|----------|---------|------|------|--------|\n"
        f"{table}\n\n"
        f"### How to verify\n"
        f"1. Review the changes above\n"
        f"2. Run `npm install` after merging\n"
        f"3. Run your test suite to confirm compatibility\n\n"
        f"---\n"
        f"*Generated by ZAK dep-patch-agent*"
    )
