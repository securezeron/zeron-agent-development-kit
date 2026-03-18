"""
Slopsquatting Detector tools — import extraction and package registry verification.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from zak.core.tools.substrate import zak_tool

# Python standard library modules (3.11+) — excluded from registry checks.
PYTHON_STDLIB = frozenset({
    "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio", "asyncore",
    "atexit", "audioop", "base64", "bdb", "binascii", "binhex", "bisect",
    "builtins", "bz2", "calendar", "cgi", "cgitb", "chunk", "cmath", "cmd",
    "code", "codecs", "codeop", "collections", "colorsys", "compileall",
    "concurrent", "configparser", "contextlib", "contextvars", "copy", "copyreg",
    "cProfile", "crypt", "csv", "ctypes", "curses", "dataclasses", "datetime",
    "dbm", "decimal", "difflib", "dis", "distutils", "doctest", "email",
    "encodings", "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
    "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt", "getpass",
    "gettext", "glob", "graphlib", "grp", "gzip", "hashlib", "heapq", "hmac",
    "html", "http", "idlelib", "imaplib", "imghdr", "imp", "importlib", "inspect",
    "io", "ipaddress", "itertools", "json", "keyword", "lib2to3", "linecache",
    "locale", "logging", "lzma", "mailbox", "mailcap", "marshal", "math",
    "mimetypes", "mmap", "modulefinder", "multiprocessing", "netrc", "nis",
    "nntplib", "numbers", "operator", "optparse", "os", "ossaudiodev",
    "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform",
    "plistlib", "poplib", "posix", "posixpath", "pprint", "profile", "pstats",
    "pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue", "quopri", "random",
    "re", "readline", "reprlib", "resource", "rlcompleter", "runpy", "sched",
    "secrets", "select", "selectors", "shelve", "shlex", "shutil", "signal",
    "site", "smtpd", "smtplib", "sndhdr", "socket", "socketserver", "sqlite3",
    "ssl", "stat", "statistics", "string", "stringprep", "struct", "subprocess",
    "sunau", "symtable", "sys", "sysconfig", "syslog", "tabnanny", "tarfile",
    "telnetlib", "tempfile", "termios", "test", "textwrap", "threading", "time",
    "timeit", "tkinter", "token", "tokenize", "tomllib", "trace", "traceback",
    "tracemalloc", "tty", "turtle", "turtledemo", "types", "typing",
    "unicodedata", "unittest", "urllib", "uu", "uuid", "venv", "warnings",
    "wave", "weakref", "webbrowser", "winreg", "winsound", "wsgiref",
    "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib",
    "_thread", "__future__",
})

# Node.js built-in modules — excluded from registry checks.
NODE_BUILTINS = frozenset({
    "assert", "buffer", "child_process", "cluster", "console", "constants",
    "crypto", "dgram", "dns", "domain", "events", "fs", "http", "http2",
    "https", "module", "net", "os", "path", "perf_hooks", "process",
    "punycode", "querystring", "readline", "repl", "stream", "string_decoder",
    "sys", "timers", "tls", "tty", "url", "util", "v8", "vm", "wasi",
    "worker_threads", "zlib",
})


def _extract_python_imports(source: str) -> list[str]:
    """Extract top-level package names from Python source code."""
    packages: set[str] = set()

    for line in source.splitlines():
        stripped = line.strip()
        # import X, import X as Y, import X.sub
        m = re.match(r"^import\s+([\w.]+)", stripped)
        if m:
            packages.add(m.group(1).split(".")[0])
            continue
        # from X import Y, from X.sub import Y
        m = re.match(r"^from\s+([\w.]+)\s+import\s+", stripped)
        if m:
            packages.add(m.group(1).split(".")[0])

    return sorted(packages - PYTHON_STDLIB)


def _extract_js_imports(source: str) -> list[str]:
    """Extract package names from JavaScript/TypeScript source code."""
    packages: set[str] = set()

    # require('pkg') or require("pkg")
    for m in re.finditer(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", source):
        packages.add(m.group(1))

    # import ... from 'pkg' / import 'pkg'
    for m in re.finditer(r"""import\s+.*?from\s+['"]([^'"]+)['"]""", source):
        packages.add(m.group(1))
    for m in re.finditer(r"""import\s+['"]([^'"]+)['"]""", source):
        packages.add(m.group(1))

    # Normalize: strip relative imports, extract top-level or scoped package name
    result: set[str] = set()
    for pkg in packages:
        if pkg.startswith("."):
            continue
        # Scoped packages: @scope/name
        if pkg.startswith("@"):
            parts = pkg.split("/")
            if len(parts) >= 2:
                result.add(f"{parts[0]}/{parts[1]}")
        else:
            result.add(pkg.split("/")[0])

    return sorted(result - NODE_BUILTINS)


@zak_tool(
    name="extract_imports",
    description="Extract all import/require package names from Python, JavaScript, or TypeScript source code",
    action_id="extract_imports",
    tags=["supply_chain", "parse", "imports"],
)
def extract_imports(source_code: str, file_path: str = "") -> dict[str, Any]:
    """Parse source code and return extracted third-party package names."""
    # Detect language from file extension or content heuristics
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""

    if ext in ("js", "jsx", "mjs", "cjs"):
        language = "javascript"
    elif ext in ("ts", "tsx", "mts"):
        language = "typescript"
    elif ext == "py":
        language = "python"
    elif "require(" in source_code or "import " in source_code and " from " in source_code:
        language = "javascript"
    else:
        language = "python"

    if language in ("javascript", "typescript"):
        packages = _extract_js_imports(source_code)
    else:
        packages = _extract_python_imports(source_code)

    return {
        "language": language,
        "file_path": file_path,
        "packages": packages,
        "count": len(packages),
    }


@zak_tool(
    name="check_pypi_package",
    description="Verify if a Python package exists on PyPI and check its registration age",
    action_id="check_pypi_package",
    tags=["supply_chain", "verify", "pypi"],
)
def check_pypi_package(package_name: str) -> dict[str, Any]:
    """Check a package against the PyPI JSON API."""
    import httpx

    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = httpx.get(url, timeout=10.0, follow_redirects=True)
        if resp.status_code == 404:
            return {
                "name": package_name,
                "exists": False,
                "registry": "pypi",
                "status": "phantom",
            }
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})

        # Parse upload time of the earliest release
        releases = data.get("releases", {})
        created = None
        for version_files in releases.values():
            for file_info in version_files:
                upload_time = file_info.get("upload_time")
                if upload_time:
                    dt = datetime.fromisoformat(upload_time).replace(tzinfo=timezone.utc)
                    if created is None or dt < created:
                        created = dt

        age_days = (datetime.now(timezone.utc) - created).days if created else -1
        suspicious = 0 < age_days < 30

        return {
            "name": package_name,
            "exists": True,
            "registry": "pypi",
            "summary": info.get("summary", ""),
            "created": created.isoformat() if created else None,
            "age_days": age_days,
            "status": "suspicious" if suspicious else "verified",
        }
    except httpx.HTTPStatusError:
        return {
            "name": package_name,
            "exists": False,
            "registry": "pypi",
            "status": "phantom",
        }
    except Exception as exc:
        return {
            "name": package_name,
            "exists": False,
            "registry": "pypi",
            "status": "error",
            "error": str(exc),
        }


@zak_tool(
    name="check_npm_package",
    description="Verify if a JavaScript/TypeScript package exists on npm and check its registration age",
    action_id="check_npm_package",
    tags=["supply_chain", "verify", "npm"],
)
def check_npm_package(package_name: str) -> dict[str, Any]:
    """Check a package against the npm registry API."""
    import httpx

    url = f"https://registry.npmjs.org/{package_name}"
    try:
        resp = httpx.get(url, timeout=10.0, follow_redirects=True)
        if resp.status_code == 404:
            return {
                "name": package_name,
                "exists": False,
                "registry": "npm",
                "status": "phantom",
            }
        resp.raise_for_status()
        data = resp.json()

        time_info = data.get("time", {})
        created_str = time_info.get("created")
        created = None
        if created_str:
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))

        age_days = (datetime.now(timezone.utc) - created).days if created else -1
        suspicious = 0 < age_days < 30

        return {
            "name": package_name,
            "exists": True,
            "registry": "npm",
            "description": data.get("description", ""),
            "created": created.isoformat() if created else None,
            "age_days": age_days,
            "status": "suspicious" if suspicious else "verified",
        }
    except httpx.HTTPStatusError:
        return {
            "name": package_name,
            "exists": False,
            "registry": "npm",
            "status": "phantom",
        }
    except Exception as exc:
        return {
            "name": package_name,
            "exists": False,
            "registry": "npm",
            "status": "error",
            "error": str(exc),
        }
