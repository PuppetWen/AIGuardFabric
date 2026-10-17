"""Check every sidebar URL and every referenced production JS/CSS chunk.

Usage: python scripts/verify-web-routes.py http://127.0.0.1:8081
This is a read-only deployment check. It does not sign in or execute UI actions.
"""

from __future__ import annotations

import re
import sys
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit


BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8081").rstrip("/")
ROOT = Path(__file__).resolve().parents[1]
# Vite fingerprints emitted chunks. A bare string such as G6's optional
# "./worker.js" fallback is not a bundled import and must not be fetched.
ASSET_REF = re.compile(r"(?:\./|/assets/)([A-Za-z0-9_.-]+-[A-Za-z0-9_-]{8}\.(?:js|css))")
HTML_ASSET = re.compile(r'(?:src|href)="(/assets/[A-Za-z0-9_.-]+\.(?:js|css))"')
NAV_PATH = re.compile(r"\bkey: '(/[^']*)', labelKey: 'nav\.")
ROUTE_PATH = re.compile(r'<Route\s+(?:index\s+)?path="([^"]+)"')
STATIC_LINK = re.compile(r'\b(?:to|href)="(/[^"\s]+)"')
TEMPLATE_LINK = re.compile(r'\b(?:to|href)=\{`(/[^`]+)`\}')
INTERPOLATION = re.compile(r'\$\{[^}]+\}')
ROUTE_PARAMETER = re.compile(r":[A-Za-z][A-Za-z0-9_]*")
SAMPLE_ID = "00000000-0000-0000-0000-000000000000"


def get(path: str) -> tuple[int, str, bytes]:
    request = urllib.request.Request(BASE + path, headers={"Accept": "*/*"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.headers.get_content_type(), response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get_content_type(), error.read()


def sidebar_paths() -> list[str]:
    source = (ROOT / "apps/web/src/components/AppLayout.tsx").read_text(encoding="utf-8")
    router = (ROOT / "apps/web/src/app/router.tsx").read_text(encoding="utf-8")
    public_routes = {path for path in ROUTE_PATH.findall(router) if path.startswith("/") and path != "/*"}
    paths = sorted(set(NAV_PATH.findall(source)) | public_routes)
    if len(paths) < 20:
        raise RuntimeError("Cannot extract the sidebar routes from AppLayout.tsx")
    return paths


def dynamic_paths() -> list[str]:
    source = (ROOT / "apps/web/src/app/router.tsx").read_text(encoding="utf-8")
    paths = ["/" + path.lstrip("/") for path in ROUTE_PATH.findall(source) if ":" in path]
    return sorted({ROUTE_PARAMETER.sub(SAMPLE_ID, path) for path in paths})


def check_client_links() -> list[str]:
    router = (ROOT / "apps/web/src/app/router.tsx").read_text(encoding="utf-8")
    patterns = [path if path.startswith("/") else "/" + path for path in ROUTE_PATH.findall(router) if path != "*"]
    patterns.append("/")
    compiled = [re.compile("^" + re.sub(r":[^/]+", "[^/]+", path) + "$") for path in patterns]
    failures: list[str] = []
    for source in (ROOT / "apps/web/src").rglob("*.tsx"):
        text = source.read_text(encoding="utf-8")
        links = STATIC_LINK.findall(text) + [INTERPOLATION.sub("example", item) for item in TEMPLATE_LINK.findall(text)]
        for link in links:
            path = urlsplit(link).path.rstrip("/") or "/"
            if path.startswith(("/api/", "/v1/", "/assets/")) and source.name == "HttpClientGuide.tsx":
                continue
            if not any(pattern.fullmatch(path) for pattern in compiled):
                failures.append(f"{source.relative_to(ROOT)}: {link} has no client route")
    return failures


def main() -> int:
    failures = check_client_links()
    status, kind, index = get("/")
    if status != 200 or kind != "text/html" or b'id="root"' not in index:
        print(f"FAIL /: HTTP {status}, Content-Type {kind}")
        return 1
    entry_assets = set(HTML_ASSET.findall(index.decode("utf-8", "replace")))
    if not any(path.endswith(".js") for path in entry_assets):
        print("FAIL /: no JavaScript entry in the HTML")
        return 1

    checked_paths = sidebar_paths() + dynamic_paths()
    for path in checked_paths:
        status, kind, body = get(path)
        if status != 200 or kind != "text/html" or b'id="root"' not in body:
            failures.append(f"{path}: HTTP {status}, Content-Type {kind}")
        elif set(HTML_ASSET.findall(body.decode("utf-8", "replace"))) != entry_assets:
            failures.append(f"{path}: HTML references a different build")

    # Asset detail routes share /assets/ with Vite's hashed build output.
    # A missing JS file must remain 404 rather than serving the SPA shell.
    status, kind, _ = get("/assets/route-check-missing.js")
    if status != 404:
        failures.append(f"missing static asset: HTTP {status}, Content-Type {kind}")

    pending = deque((path, "/") for path in entry_assets)
    visited: set[str] = set()
    while pending:
        path, parent = pending.popleft()
        if path in visited:
            continue
        visited.add(path)
        if len(visited) > 300:
            failures.append("More than 300 referenced assets; refusing an unbounded crawl")
            break
        status, kind, body = get(path)
        expected = "javascript" if path.endswith(".js") else "text/css"
        if status != 200 or expected not in kind:
            failures.append(f"{path} (referenced by {parent}): HTTP {status}, Content-Type {kind}")
            continue
        if path.endswith(".js"):
            for name in ASSET_REF.findall(body.decode("utf-8", "replace")):
                pending.append(("/assets/" + name, path))

    print(f"SPA routes: {len(checked_paths)}, build assets: {len(visited)}, client link failures: {len(failures)}")
    for failure in failures:
        print("FAIL " + failure)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
