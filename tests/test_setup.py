import argparse
import contextlib
import copy
import importlib.util
import io
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dependasolver_setup", ROOT / "setup.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
SOURCE = ("owner/dependasolver", "a" * 40)
PEM = "-----BEGIN PRIVATE KEY-----\nfixture-only\n-----END PRIVATE KEY-----\n"
APP = {"client_id": "Iv1.fixture", "pem": PEM, "slug": "dependasolver-fixture"}


class SetupTest(unittest.TestCase):
    def test_validation_and_preview_have_no_side_effects(self):
        for value in ("repo", "owner/..", "owner/repo/extra", "owner/repo;cmd", "owner/repo\n"):
            with self.assertRaises(argparse.ArgumentTypeError):
                setup.repository(value)
        for value in ("owner/repo@main", "owner/repo@" + "a" * 39, "owner/repo@" + "g" * 40):
            with self.assertRaises(argparse.ArgumentTypeError):
                setup.source_ref(value)
        for value in ([], [""], ["  "], ["test\ninjected"]):
            with self.assertRaises(ValueError):
                setup.checks(value)
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with (patch.object(setup.subprocess, "run", side_effect=AssertionError("subprocess")),
                  patch.object(setup.webbrowser, "open", side_effect=AssertionError("browser")),
                  patch.object(setup, "HTTPServer", side_effect=AssertionError("listener")),
                  patch.object(setup.urllib.request, "urlopen", side_effect=AssertionError("network")),
                  contextlib.redirect_stdout(output)):
                code = setup.main(["--repo", "owner/repo", "--solver-ref", "@".join(SOURCE),
                                   "--checks", "test", "audit", "--directory", directory])
            self.assertEqual(code, 0)
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertIn('"apply": false', output.getvalue())

    def test_files_preserve_config_and_reject_escape_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory).resolve()
            (root / "package.json").write_text("{}")
            files = setup.local_files(root, SOURCE, ["test's check", "audit"])
            caller = files[root / ".github/workflows/dependasolver.yml"]
            self.assertIn("@" + "a" * 40, caller)
            self.assertIn('required-checks: \'["test\'\'s check", "audit"]\'', caller)
            self.assertIn("package-ecosystem: npm", files[root / ".github/dependabot.yml"])
            (root / ".github").mkdir()
            (root / ".github/dependabot.yaml").write_text("preserve me")
            self.assertEqual(len(setup.local_files(root, SOURCE, ["test"])), 1)
            (root / ".github/workflows").mkdir()
            target = root / ".github/workflows/dependasolver.yml"
            target.write_text("unrelated work")
            with self.assertRaises(ValueError):
                setup.local_files(root, SOURCE, ["test"])
            self.assertEqual(target.read_text(), "unrelated work")
            target.unlink()
            (root / ".github/workflows").rmdir()
            (root / ".github/workflows").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                setup.local_files(root, SOURCE, ["test"])
            self.assertEqual(list(Path(outside).iterdir()), [])

    def test_protection_merges_bindings_without_replacing_other_rules(self):
        protection = {
            "required_status_checks": {"strict": False, "contexts": ["bound", "legacy"],
                                       "checks": [{"context": "bound", "app_id": 123}]},
            "required_pull_request_reviews": {"required_approving_review_count": 2},
            "restrictions": {"users": [{"login": "owner"}]},
            "required_signatures": {"enabled": True},
        }
        original = copy.deepcopy(protection)
        with patch.object(setup, "api") as api:
            setup.protect("protection", protection, ["bound", "test"])
        self.assertEqual(protection, original)
        self.assertEqual([call.args[0] for call in api.call_args_list],
                         ["protection/required_status_checks", "protection/enforce_admins"])
        self.assertEqual(api.call_args_list[0].kwargs["payload"], {
            "strict": True, "checks": [{"context": "bound", "app_id": 123},
                                      {"context": "legacy", "app_id": -1},
                                      {"context": "test", "app_id": -1}],
        })
        with patch.object(setup, "api", side_effect=RuntimeError("missing status subresource")) as api:
            with self.assertRaises(RuntimeError):
                setup.protect("protection", {"required_status_checks": None}, ["test"])
            self.assertEqual(api.call_count, 1)
            self.assertEqual(api.call_args.kwargs["method"], "PATCH")
        with patch.object(setup, "api") as api:
            setup.protect("protection", None, ["test"])
            self.assertEqual(api.call_args.kwargs["method"], "PUT")
            self.assertTrue(api.call_args.kwargs["payload"]["enforce_admins"])

    def test_manifest_callback_and_secret_routing(self):
        data = setup.manifest("owner/repo", "http://127.0.0.1:1234/callback", "fixture")
        self.assertEqual(data["default_permissions"], {"administration": "read", "pull_requests": "read"})
        self.assertFalse(data["public"])
        self.assertFalse(data["hook_attributes"]["active"])
        self.assertEqual(data["default_events"], [])
        valid = "/callback?state=expected&code=" + "a" * 40
        self.assertEqual(setup.callback_code(valid, "/callback", "expected"), "a" * 40)
        for value in (valid.replace("expected", "wrong"), valid.replace("expected", "☃"),
                      valid + "&state=expected", valid + "&state=",
                      valid + "&code=" + "b" * 40, valid.replace("/callback", "/elsewhere"),
                      "/callback?state=expected&code=bad/code", "/callback?code=" + "a" * 40):
            with self.assertRaises(ValueError):
                setup.callback_code(value, "/callback", "expected")
        with (patch.object(setup, "gh") as gh,
              patch.object(setup.webbrowser, "open") as browser,
              patch("builtins.input", return_value=""), contextlib.redirect_stdout(io.StringIO()) as output):
            setup.credentials("owner/repo", APP)
        self.assertEqual(gh.call_args_list[0].args[0], ["secret", "set", setup.PRIVATE_KEY, "--repo", "owner/repo"])
        self.assertEqual(gh.call_args_list[0].kwargs["data"], PEM)
        self.assertNotIn(PEM, str(gh.call_args_list[0].args))
        self.assertEqual(gh.call_args_list[1].args[0][-1], APP["client_id"])
        browser.assert_called_once_with("https://github.com/apps/dependasolver-fixture/installations/new")
        self.assertNotIn(PEM, output.getvalue())

    def test_failed_secret_upload_keeps_private_recovery_file(self):
        mkstemp = tempfile.mkstemp
        with tempfile.TemporaryDirectory() as directory:
            def recovery(**kwargs):
                return mkstemp(dir=directory, **kwargs)
            with (patch.object(setup.tempfile, "mkstemp", side_effect=recovery),
                  patch.object(setup, "gh", side_effect=RuntimeError("fixture failure")),
                  contextlib.redirect_stdout(io.StringIO()) as output):
                with self.assertRaises(RuntimeError):
                    setup.credentials("owner/repo", APP)
            files = list(Path(directory).glob("*.pem"))
            self.assertEqual(len(files), 1)
            self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
            self.assertEqual(files[0].read_text(), PEM)
            self.assertNotIn(PEM, output.getvalue())

    def test_cli_errors_do_not_expose_credentials_or_mask_403(self):
        with patch.object(setup.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, PEM, PEM)):
            with self.assertRaises(RuntimeError) as caught:
                setup.gh(["secret", "set", "NAME"], data=PEM)
            self.assertNotIn(PEM, str(caught.exception))
        for status in (403, 404):
            result = subprocess.CompletedProcess([], 1, "", f"gh: Not Found (HTTP {status})")
            with patch.object(setup.subprocess, "run", return_value=result):
                if status == 404:
                    self.assertIsNone(setup.api("fixture", missing=True))
                else:
                    with self.assertRaises(RuntimeError):
                        setup.api("fixture", missing=True)

    def test_install_preflights_source_reuses_credentials_and_rechecks_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            protections = iter([{"required_status_checks": None}, {
                "required_status_checks": {"strict": True, "checks": [{"context": "newly-added", "app_id": 88}]}
            }])
            def api(endpoint, **kwargs):
                calls.append((endpoint, kwargs))
                if kwargs.get("method", "GET") != "GET":
                    return {}
                if endpoint == "repos/owner/repo":
                    return {"full_name": "owner/repo", "permissions": {"admin": True},
                            "owner": {"type": "Organization"}, "default_branch": "release/stable"}
                if "/contents/" in endpoint:
                    return {"type": "file"}
                if endpoint.endswith("/protection"):
                    return next(protections)
                return {"name": "existing", "value": "Iv1.existing"}
            with (patch.object(setup, "api", side_effect=api),
                  patch.object(setup, "register_app", side_effect=AssertionError("existing App replaced")),
                  patch.object(setup, "gh", side_effect=AssertionError("real CLI")),
                  contextlib.redirect_stdout(io.StringIO())):
                setup.install("owner/repo", SOURCE, ["test"], directory)
            status = next(kwargs["payload"] for endpoint, kwargs in calls if endpoint.endswith("required_status_checks"))
            self.assertIn({"context": "newly-added", "app_id": 88}, status["checks"])
            self.assertTrue(any("release%2Fstable/protection" in endpoint for endpoint, _ in calls))
            self.assertTrue((Path(directory) / ".github/workflows/dependasolver.yml").is_file())
            self.assertTrue((Path(directory) / ".github/dependabot.yml").is_file())
        with tempfile.TemporaryDirectory() as directory:
            def unavailable(endpoint, **kwargs):
                if endpoint == "repos/owner/repo":
                    return {"full_name": "owner/repo", "permissions": {"admin": True},
                            "owner": {"type": "Organization"}}
                raise RuntimeError("source is unpublished")
            with (patch.object(setup, "api", side_effect=unavailable),
                  patch.object(setup, "register_app") as register):
                with self.assertRaises(RuntimeError):
                    setup.install("owner/repo", SOURCE, ["test"], directory)
                register.assert_not_called()
            self.assertEqual(list(Path(directory).iterdir()), [])
