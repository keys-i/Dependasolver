#!/usr/bin/env python3
"""Preview or install Dependasolver without a manually supplied PAT."""

import argparse
import base64
import html
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from string import Template

ROOT = Path(__file__).resolve().parent
CLIENT_ID = "DEPENDASOLVER_APP_CLIENT_ID"
PRIVATE_KEY = "DEPENDASOLVER_APP_PRIVATE_KEY"
PERMISSIONS = {"administration": "read", "pull_requests": "read"}
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}")


def repository(value):
    if not REPO.fullmatch(value) or value.split("/")[1] in {".", ".."}:
        raise argparse.ArgumentTypeError("Use an explicit OWNER/REPO.")
    return value


def source_ref(value):
    parts = value.split("@")
    if len(parts) != 2 or not re.fullmatch(r"[0-9a-fA-F]{40}", parts[1]):
        raise argparse.ArgumentTypeError("--solver-ref requires OWNER/REPO@40_CHARACTER_COMMIT_SHA.")
    repository(parts[0])
    return parts[0], parts[1].lower()


def checks(values):
    if not values or any(not value.strip() or not value.isprintable() for value in values):
        raise ValueError("Provide nonempty CI check names without control characters.")
    return list(dict.fromkeys(values))


def local_path(directory, name):
    root = Path(directory).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("--directory must be a directory.")
    path = root / name
    if not path.resolve().is_relative_to(root):
        raise ValueError(f"Refusing a path outside --directory: {name}")
    return path


def local_files(directory, source, required):
    ref = f"{source[0]}/.github/workflows/solve.yml@{source[1]}"
    caller = (ROOT / "templates/dependency.solver.yml").read_text()
    caller = caller.replace("__SOLVER_REF__", ref)
    caller = caller.replace("__REQUIRED_CHECKS__", json.dumps(required).replace("'", "''"))
    files = {local_path(directory, ".github/workflows/dependasolver.yml"): caller}
    paths = [local_path(directory, f".github/dependabot.{ext}") for ext in ("yml", "yaml")]
    if not any(path.exists() for path in paths):
        # ponytail: root npm/Actions only; configure nested/other ecosystems in Dependabot.
        ecosystems = ["github-actions"]
        if (Path(directory) / "package.json").is_file():
            ecosystems.append("npm")
        files[paths[0]] = "version: 2\nupdates:\n" + "".join(
            f"  - package-ecosystem: {ecosystem}\n    directory: /\n"
            "    schedule:\n      interval: weekly\n    open-pull-requests-limit: 3\n"
            for ecosystem in ecosystems
        )
    for path, content in files.items():
        if path.exists() and (not path.is_file() or path.read_text() != content):
            raise ValueError(f"Refusing to overwrite existing content: {path}")
    return files


def gh(arguments, *, data=None, missing=False):
    result = subprocess.run(
        ["gh", *arguments], input=data, text=True, capture_output=True, timeout=60
    )
    if result.returncode:
        if missing and re.search(r"\(HTTP 404\)", result.stderr):
            return None
        # API responses can contain credentials. Never include stdout/stderr here.
        raise RuntimeError("GitHub request failed; check CLI login and repository administration access.")
    return result.stdout


def api(endpoint, *, method="GET", payload=None, missing=False):
    arguments = ["api", "--method", method, endpoint]
    if payload is not None:
        arguments += ["--input", "-"]
    output = gh(arguments, data=None if payload is None else json.dumps(payload), missing=missing)
    return None if output is None or not output.strip() else json.loads(output)


def merged_checks(protection, required):
    current = (protection or {}).get("required_status_checks") or {}
    result = [
        {"context": item["context"], "app_id": item.get("app_id") or -1}
        for item in current.get("checks", [])
    ]
    present = {item["context"] for item in result}
    for name in [*current.get("contexts", []), *required]:
        if name not in present:
            result.append({"context": name, "app_id": -1})
            present.add(name)
    return result


def protect(endpoint, protection, required):
    status = {"strict": True, "checks": merged_checks(protection, required)}
    if protection is None:
        api(endpoint, method="PUT", payload={
            "required_status_checks": status,
            "enforce_admins": True,
            "required_pull_request_reviews": None,
            "restrictions": None,
        })
    else:
        # Subresources leave existing reviews, restrictions, and other rules intact.
        # A subresource failure must never trigger replacement of the parent policy.
        api(endpoint + "/required_status_checks", method="PATCH", payload=status)
        api(endpoint + "/enforce_admins", method="POST")


def manifest(repo, callback, name):
    return {
        "name": name,
        "url": f"https://github.com/{repo}",
        "description": "Dependabot updates without the babysitting, with compatibility checks and passing CI before auto-merge.",
        "public": False,
        "hook_attributes": {"active": False, "url": f"https://github.com/{repo}"},
        "redirect_url": callback,
        "default_permissions": PERMISSIONS,
        "default_events": [],
    }


def callback_code(path, route, state):
    parsed = urllib.parse.urlsplit(path)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    values = query.get("state", [])
    codes = query.get("code", [])
    if (parsed.path != route or len(values) != 1 or len(codes) != 1
            or not values[0].isascii() or not secrets.compare_digest(values[0], state)
            or not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", codes[0])):
        raise ValueError("Invalid App registration callback.")
    return codes[0]


def convert_manifest(code):
    request = urllib.request.Request(
        f"https://api.github.com/app-manifests/{code}/conversions",
        method="POST", data=b"", headers={"Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except (urllib.error.URLError, ValueError):
        raise RuntimeError("Could not complete App registration. Retry from GitHub's App settings.") from None


def setup_page(title, content, nonce):
    return Template((ROOT / "templates/setup.html").read_text()).substitute(
        title=html.escape(title), content=content, nonce=html.escape(nonce, quote=True),
        logo=base64.b64encode((ROOT / "assets/dependasolver.png").read_bytes()).decode(),
    )


def register_app(repo, owner_type):
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    route = "/callback/" + secrets.token_urlsafe(24)
    start = "/start/" + secrets.token_urlsafe(24)
    code = None

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_):
            pass  # Registration codes must not reach terminal/request logs.

        def do_GET(self):
            nonlocal code
            if self.headers.get("Host") != host:
                self.send_error(400)
                return
            if self.path == start:
                body = form
            else:
                try:
                    code = callback_code(self.path, route, state)
                except ValueError:
                    self.send_error(400)
                    return
                body = setup_page("App registered", "<p>Return to your terminal to finish installing Dependasolver.</p>", nonce)
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", f"default-src 'none'; img-src data:; style-src 'nonce-{nonce}'; form-action https://github.com; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(data)

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        host = f"127.0.0.1:{server.server_port}"
        app_name = "Dependasolver " + repo.split("/")[1][:12] + " " + secrets.token_hex(3)
        settings = "settings/apps/new" if owner_type == "User" else f"organizations/{repo.split('/')[0]}/settings/apps/new"
        action = f"https://github.com/{settings}?state={urllib.parse.quote(state)}"
        config = manifest(repo, f"http://{host}{route}", app_name)
        form = setup_page("Connect your repository", (
                f"<p>Create a private GitHub App for <strong>{html.escape(repo)}</strong> "
                "to check dependency updates before auto-merge.</p>"
                "<dl><div><dt>Administration</dt><dd>Read-only</dd></div>"
                "<div><dt>Pull requests</dt><dd>Read-only</dd></div></dl>"
                "<p>Your CI checks and review requirements still apply.</p>"
                f'<form method="post" action="{html.escape(action, quote=True)}">'
                f'<input type="hidden" name="manifest" value="{html.escape(json.dumps(config), quote=True)}">'
                '<button type="submit">Continue to GitHub</button></form>'
                '<p class="note">Select only this repository when GitHub asks where to install the App.</p>'), nonce)
        url = f"http://{host}{start}"
        print(f"Open {url} to approve App registration in GitHub.")
        webbrowser.open(url)
        server.timeout = 1
        deadline = time.monotonic() + 900
        while code is None and time.monotonic() < deadline:
            server.handle_request()
    if code is None:
        raise RuntimeError("App registration timed out; no repository settings were changed.")
    return convert_manifest(code)


def credentials(repo, app):
    client_id, pem, slug = (app.get(key) for key in ("client_id", "pem", "slug"))
    if (not isinstance(client_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", client_id)
            or not isinstance(pem, str) or "PRIVATE KEY-----" not in pem
            or not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9-]+", slug)):
        raise RuntimeError("App registration returned incomplete credentials.")
    fd, recovery = tempfile.mkstemp(prefix="dependasolver-app-", suffix=".pem")
    try:
        with os.fdopen(fd, "w") as file:
            file.write(pem)
        gh(["secret", "set", PRIVATE_KEY, "--repo", repo], data=pem)
        gh(["variable", "set", CLIENT_ID, "--repo", repo, "--body", client_id])
    except BaseException:
        print(f"App private key retained with owner-only permissions at {recovery}.")
        print(f"App Client ID: {client_id}. Complete both repository Actions credentials before retrying.")
        raise
    else:
        Path(recovery).unlink()
    print(f"Install the App with Only select repositories → {repo}.")
    webbrowser.open(f"https://github.com/apps/{slug}/installations/new")
    input("Press Enter after completing that installation in GitHub: ")


def install(repo, source, required, directory):
    files = local_files(directory, source, required)
    info = api(f"repos/{repo}")
    if (info.get("full_name", "").lower() != repo.lower()
            or info.get("permissions", {}).get("admin") is not True):
        raise RuntimeError("The explicit target repository requires administration access.")
    owner_type = info.get("owner", {}).get("type")
    if owner_type not in {"User", "Organization"}:
        raise RuntimeError("Only personal and organization repositories are supported.")
    source_file = api(f"repos/{source[0]}/contents/.github/workflows/solve.yml?ref={source[1]}")
    if source_file.get("type") != "file":
        raise RuntimeError("Publish the source workflow at the specified immutable commit first.")
    branch = urllib.parse.quote(info["default_branch"], safe="")
    endpoint = f"repos/{repo}/branches/{branch}/protection"
    protection = api(endpoint, missing=True)
    key = api(f"repos/{repo}/actions/secrets/{PRIVATE_KEY}", missing=True)
    client = api(f"repos/{repo}/actions/variables/{CLIENT_ID}", missing=True)
    if (key is None) != (client is None):
        raise RuntimeError("Incomplete App setup: configure both Actions credentials, or remove the incomplete pair before retrying.")
    if key is None:
        credentials(repo, register_app(repo, owner_type))
    else:
        print("Reusing the repository's existing Dependasolver App credentials.")
    # Re-read policy after browser approval; preserve changes made during setup.
    protection = api(endpoint, missing=True)
    protect(endpoint, protection, required)
    api(f"repos/{repo}", method="PATCH", payload={"allow_auto_merge": True, "allow_squash_merge": True})
    # Recheck after the browser flow so concurrent local work is never overwritten.
    files = local_files(directory, source, required)
    for path, content in files.items():
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        local_path(directory, str(path.relative_to(Path(directory).resolve())))
        with path.open("x") as file:
            file.write(content)
    print("Repository settings and App credentials are configured.")
    print(f"To add the smiling App badge, upload {ROOT / 'assets/dependasolver.png'} in the App's Display information settings.")
    print("Publish .github/workflows/dependasolver.yml to activate the solver.")
    print("The first workflow run verifies the App installation and protected checks.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=repository)
    parser.add_argument("--solver-ref", required=True, type=source_ref)
    parser.add_argument("--checks", required=True, nargs="+")
    parser.add_argument("--directory", type=Path, default=Path.cwd())
    parser.add_argument("--apply", action="store_true", help="Approve App setup, repository setting changes, and local caller creation.")
    args = parser.parse_args(argv)
    try:
        required = checks(args.checks)
        files = local_files(args.directory, args.solver_ref, required)
        print(json.dumps({"repository": args.repo, "source": "@".join(args.solver_ref),
                          "required_checks": required, "files": [str(path) for path in files],
                          "app_permissions": PERMISSIONS, "apply": args.apply}, indent=2))
        if args.apply:
            install(args.repo, args.solver_ref, required, args.directory)
        else:
            print("Preview complete. Add --apply to run setup.")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
