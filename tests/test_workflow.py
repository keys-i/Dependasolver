import json
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from textwrap import dedent

import unittest


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github/workflows"
workflow = (WORKFLOWS / "solve.yml").read_text()
reset = re.search(r"^        run: (gh .+--disable-auto)$", workflow, re.M).group(1)
assert workflow.index(reset) < workflow.index("id: app-token") < workflow.index("id: metadata")
app_step = workflow.split("id: app-token\n", 1)[1].split("      - name:", 1)[0]
assert "repositories: ${{ github.event.repository.name }}" in app_step
assert dict(re.findall(r"^          permission-([\w-]+): (\w+)$", app_step, re.M)) == {
    "administration": "read",
    "pull-requests": "read",
}
assert "skip-token-revoke" not in app_step
assert "DEPENDABOT_COMPAT_TOKEN" not in workflow
assert "github-token: ${{ steps.app-token.outputs.token }}" in workflow
assert "APP_TOKEN: ${{ steps.app-token.outputs.token }}" in workflow
script = dedent(workflow.split("        run: |\n", 1)[1])
assert script.count("gh ") == 2
contexts = ["build", "audit", "dependency-review"]

PROTECTION = {
    "enforce_admins": {"enabled": True},
    "required_status_checks": {"strict": True, "contexts": contexts},
}
HEAD = "a" * 40
PR_URL = "https://example.invalid/owner/repo/pull/7"

# Only fixture commands run: the real GitHub CLI is never invoked.
STUB = r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

root = Path(os.environ["RUNNER_TEMP"])
args = sys.argv[1:]
with (root / "calls").open("a") as log:
    log.write(json.dumps(args) + "\n")
if args[0] == "api":
    assert args == ["api", "repos/owner/repo/branches/release%2Fstable/protection"]
    assert os.environ["GH_TOKEN"] == "fixture-app"
    if os.environ["FAIL"] == "api":
        print((root / "protection").read_text())
        sys.exit(1)
    print((root / "protection").read_text())
elif args[:2] == ["pr", "merge"]:
    assert os.environ["GH_TOKEN"] == "fixture-workflow"
    disabling = args[-1] == "--disable-auto"
    if os.environ["FAIL"] == ("reset" if disabling else "merge"):
        sys.exit(1)
    (root / "enabled").write_text(json.dumps(not disabling))
else:
    raise AssertionError(args)
"""



class WorkflowTest(unittest.TestCase):
    def test_solver_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cli = root / "fixture-cli"
            cli.write_text(STUB)
            cli.chmod(0o700)
            shell = script.replace("gh ", f"{shlex.quote(str(cli))} ")

            def run(protection=PROTECTION, *, fail="", token="fixture-app", revalidate=False, eligible=True, required=contexts, required_json=None):
                (root / "protection").write_text(json.dumps(protection))
                (root / "calls").write_text("")
                (root / "enabled").write_text("true")
                commands = shell if eligible else ""
                if revalidate:
                    commands = "set -euo pipefail\n" + reset.replace("gh ", f"{shlex.quote(str(cli))} ") + "\n" + commands
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-c", commands],
                    env={
                        **os.environ,
                        "BASH_ENV": "/dev/null",
                        "GH_TOKEN": "fixture-workflow",
                        "APP_TOKEN": token,
                        "GH_REPO": "owner/repo",
                        "PR_URL": PR_URL,
                        "HEAD_SHA": HEAD,
                        "REQUIRED_CHECKS": json.dumps(required) if required_json is None else required_json,
                        "BASE_BRANCH": "release/stable",
                        "RUNNER_TEMP": str(root),
                        "FAIL": fail,
                    },
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
                return result.returncode, calls, result.stderr

            for checks in (
                {"strict": True, "contexts": contexts},
                {"strict": True, "checks": [{"context": name} for name in contexts]},
                {"strict": True, "contexts": contexts[:1], "checks": [{"context": name} for name in contexts[1:]]},
            ):
                code, calls, error = run({**PROTECTION, "required_status_checks": checks})
                assert code == 0, error
                assert len(calls) == 2 and calls[-1] == [
                    "pr", "merge", PR_URL, "--auto", "--squash", "--match-head-commit", HEAD
                ]
            for protection in (
                {},
                None,
                {**PROTECTION, "enforce_admins": {"enabled": False}},
                {**PROTECTION, "required_status_checks": None},
                {**PROTECTION, "required_status_checks": {"strict": False, "contexts": contexts}},
                *[
                    {**PROTECTION, "required_status_checks": {"strict": True, "contexts": [name for name in contexts if name != missing]}}
                    for missing in contexts
                ],
            ):
                code, calls, _ = run(protection)
                assert code != 0 and len(calls) == 1, (protection, calls)
            code, calls, _ = run(fail="api")
            assert code != 0 and len(calls) == 1
            code, calls, _ = run(token="")
            assert code != 0 and not calls
            code, calls, _ = run(fail="merge")
            assert code != 0 and len(calls) == 2
            # An already-enabled PR stays disabled if metadata fails or becomes ineligible.
            code, calls, _ = run(revalidate=True, eligible=False)
            assert code == 0 and calls == [["pr", "merge", PR_URL, "--disable-auto"]]
            assert json.loads((root / "enabled").read_text()) is False
            code, calls, _ = run(revalidate=True, fail="api")
            assert code != 0 and len(calls) == 2
            assert json.loads((root / "enabled").read_text()) is False
            code, calls, _ = run(revalidate=True)
            assert code == 0 and len(calls) == 3
            assert json.loads((root / "enabled").read_text()) is True
            code, calls, _ = run(revalidate=True, fail="reset")
            assert code != 0 and len(calls) == 1


            for required in ([], "build", None, {}, [""], ["   "], [7], ["missing"]):
                code, calls, _ = run(required=required)
                assert code != 0 and len(calls) == 1, (required, calls)
            code, calls, _ = run(required_json="{")
            assert code != 0 and len(calls) == 1

        assert "github.event_name == 'pull_request_target'" in workflow
        assert "skip-verification" not in workflow and "skip-commit-verification" not in workflow
        assert "actions/checkout" not in workflow
        assert "fromJSON(steps.metadata.outputs.compatibility-score || '0') >= 95" in workflow
        assert "fromJSON(steps.metadata.outputs.compatibility-score || '0') <= 100" in workflow
        assert "version-update:semver-major" not in workflow
        for path in WORKFLOWS.glob("*.yml"):
            for action in re.findall(r"uses: ([^#\s]+)", path.read_text()):
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), action

