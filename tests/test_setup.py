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
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dependasolver_setup", ROOT / "setup.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
SOURCE = ("owner/dependasolver", "a" * 40)
PEM = "-----BEGIN PRIVATE KEY-----\nfixture-only\n-----END PRIVATE KEY-----\n"
APP = {"client_id": "Iv1.fixture", "pem": PEM, "slug": "rady-fixture", "owner": {"login": "keys-i"}, "permissions": setup.PERMISSIONS}


class SetupTest(unittest.TestCase):
    def test_registration_form_and_callback_keep_browser_boundaries(self):
        for owner_type in ("User", "Organization"):
            tags = []

            class Page(HTMLParser):
                def handle_starttag(self, tag, attrs):
                    tags.append((tag, dict(attrs)))

            requests = []
            callback = None
            with (patch.object(setup, "HTTPServer") as listener,
                  patch.object(setup, "api", return_value={"type": owner_type, "login": "keys-i"}) as api,
                  patch.object(setup.webbrowser, "open") as browser,
                  patch.object(setup, "convert_manifest", return_value=APP) as convert,
                  contextlib.redirect_stdout(io.StringIO())):
                server = listener.return_value.__enter__.return_value
                server.server_port = 1234

                def request():
                    nonlocal callback
                    path = setup.urllib.parse.urlsplit(browser.call_args.args[0]).path if not requests else callback
                    host = "attacker.invalid" if len(requests) == 1 else "127.0.0.1:1234"
                    connection = Mock()
                    connection.makefile.return_value = io.BytesIO(
                        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                    chunks = []
                    connection.sendall.side_effect = chunks.append
                    listener.call_args.args[1](connection, ("127.0.0.1", 4321), server)
                    response = b"".join(chunks).decode()
                    requests.append(response)
                    if len(requests) == 1:
                        headers, body = response.split("\r\n\r\n", 1)
                        Page().feed(body)
                        form = next(attrs for tag, attrs in tags if tag == "form")
                        field = next(attrs for tag, attrs in tags if tag == "input")
                        style = next(attrs for tag, attrs in tags if tag == "style")
                        self.assertEqual(form["method"], "post")
                        route = "settings/apps/new" if owner_type == "User" else "organizations/keys-i/settings/apps/new"
                        self.assertTrue(form["action"].startswith(f"https://github.com/{route}?"))
                        self.assertIn("owned by <strong>keys-i</strong>", body)
                        self.assertEqual(field["name"], "manifest")
                        data = json.loads(field["value"])
                        self.assertEqual(data["default_permissions"], setup.PERMISSIONS)
                        self.assertTrue(data["public"])
                        self.assertIn("style-src 'nonce-" + style["nonce"] + "'", headers)
                        self.assertIn("default-src 'none'", headers)
                        self.assertNotIn("'unsafe-inline'", headers)
                        self.assertFalse(any(tag == "script" for tag, _ in tags))
                        state = setup.urllib.parse.parse_qs(setup.urllib.parse.urlsplit(form["action"]).query)["state"][0]
                        callback = setup.urllib.parse.urlsplit(data["redirect_url"]).path + "?state=" + state + "&code=" + "a" * 40

                server.handle_request.side_effect = request
                self.assertEqual(setup.register_app("owner/repo"), APP)
                convert.assert_called_once_with("a" * 40)
                self.assertEqual([call.args[0] for call in api.call_args_list],
                                 ["users/keys-i", "user"] if owner_type == "User" else ["users/keys-i"])
            self.assertIn("200 OK", requests[0])
            self.assertIn("400 Bad Request", requests[1])
            self.assertIn("App registered", requests[2])
            self.assertNotIn("<script>", setup.setup_page("<script>", "<p>Ready</p>", "fixture"))

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
                                   "--checks", "test", "audit", "--directory", directory, "--new-app"])
            self.assertEqual(code, 0)
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertIn('"apply": false', output.getvalue())
            self.assertIn('"app_owner": "keys-i"', output.getvalue())
            self.assertIn('"app_public": true', output.getvalue())
            self.assertIn('"new_app": true', output.getvalue())

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

    def test_new_app_bypasses_stale_entries_and_preserves_them_if_registration_fails(self):
        for registration_fails in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                calls = []
                def api(endpoint, **kwargs):
                    calls.append((endpoint, kwargs))
                    if kwargs.get("method", "GET") != "GET":
                        return {}
                    if endpoint == "repos/owner/repo":
                        return {"full_name": "owner/repo", "permissions": {"admin": True},
                                "owner": {"type": "Organization"}, "default_branch": "main"}
                    if "/contents/" in endpoint:
                        return {"type": "file"}
                    if endpoint.endswith("/protection"):
                        return None
                    raise AssertionError("Fresh registration must not look up old credential entries or an App slug.")
                with (patch.object(setup, "api", side_effect=api),
                      patch.object(setup, "register_app", return_value=APP,
                                   side_effect=RuntimeError("registration cancelled") if registration_fails else None) as register,
                      patch.object(setup, "gh") as gh,
                      patch.object(setup, "public_app", side_effect=AssertionError("existing App lookup")),
                      patch.object(setup.webbrowser, "open"), patch("builtins.input", return_value=""),
                      contextlib.redirect_stdout(io.StringIO())):
                    result = setup.main(["--repo", "owner/repo", "--solver-ref", "@".join(SOURCE),
                                         "--checks", "test", "--directory", directory, "--new-app", "--apply"])
                    register.assert_called_once_with("owner/repo")
                    if registration_fails:
                        self.assertEqual(result, 1)
                        gh.assert_not_called()
                        self.assertTrue(all(kwargs.get("method", "GET") == "GET" for _, kwargs in calls))
                        self.assertEqual(list(Path(directory).iterdir()), [])
                    else:
                        self.assertEqual(result, 0)
                        self.assertEqual([call.args[0][2] for call in gh.call_args_list],
                                         [setup.PRIVATE_KEY, setup.CLIENT_ID, setup.APP_SLUG])
                        self.assertEqual(gh.call_args_list[0].kwargs["data"], PEM)
                        self.assertTrue((Path(directory) / ".github/workflows/dependasolver.yml").is_file())

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
        self.assertEqual(data["default_permissions"], setup.PERMISSIONS)
        self.assertTrue(data["public"])
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
        self.assertEqual(gh.call_args_list[2].args[0],
                         ["variable", "set", setup.APP_SLUG, "--repo", "owner/repo", "--body", APP["slug"]])
        browser.assert_called_once_with("https://github.com/apps/rady-fixture/installations/new")
        self.assertNotIn(PEM, output.getvalue())

    def test_rady_credentials_use_a_separate_namespace(self):
        with (patch.object(setup, "gh") as gh,
              patch.object(setup.webbrowser, "open"), patch("builtins.input", return_value=""),
              contextlib.redirect_stdout(io.StringIO())):
            setup.credentials("owner/repo", APP, "rady")
        self.assertEqual([call.args[0][2] for call in gh.call_args_list],
                         ["RADY_APP_PRIVATE_KEY", "RADY_APP_CLIENT_ID", "RADY_APP_SLUG"])
        self.assertEqual(gh.call_args_list[0].kwargs["data"], PEM)
        self.assertIn("Rady", setup.setup_page("Ready", "", "fixture", "rady"))
        with tempfile.TemporaryDirectory() as directory:
            caller = setup.local_files(Path(directory), SOURCE, ["test"])[Path(directory).resolve() / ".github/workflows/dependasolver.yml"]
        self.assertIn("solver-ref: " + "@".join(SOURCE), caller)
        self.assertIn("vars.RADY_APP_CLIENT_ID", caller)
        self.assertIn("secrets.OPENAI_API_KEY", caller)
        self.assertNotIn("__SOURCE_REF__", caller)

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
                if endpoint.endswith(setup.APP_SLUG):
                    return {"value": APP["slug"]}
                return {"name": "existing", "value": APP["client_id"]}
            with (patch.object(setup, "api", side_effect=api),
                  patch.object(setup, "public_app", return_value=APP),
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

    def test_wrong_app_owner_and_public_lookup_fail_before_mutations(self):
        with (patch.object(setup, "gh") as gh, patch.object(setup.tempfile, "mkstemp") as recovery):
            for owner in ({"login": "other"}, {}, None):
                with self.assertRaisesRegex(RuntimeError, "registered under keys-i"):
                    setup.credentials("owner/repo", {**APP, "owner": owner})
            gh.assert_not_called()
            recovery.assert_not_called()
        with (patch.object(setup, "api", side_effect=[{"type": "User"}, {"login": "other"}]),
              patch.object(setup, "HTTPServer") as listener):
            with self.assertRaisesRegex(RuntimeError, "Sign in.*keys-i"):
                setup.register_app("owner/repo")
            listener.assert_not_called()
        with patch.object(setup.urllib.request, "urlopen") as urlopen:
            for slug in (None, "", "../elsewhere", "name?query"):
                with self.assertRaisesRegex(RuntimeError, setup.APP_SLUG):
                    setup.public_app(slug)
            urlopen.assert_not_called()
            urlopen.return_value.__enter__.return_value = io.BytesIO(json.dumps(APP).encode())
            self.assertEqual(setup.public_app(APP["slug"]), APP)
            request = urlopen.call_args.args[0]
            self.assertEqual(request.full_url, "https://api.github.com/apps/" + APP["slug"])
            self.assertIsNone(request.get_header("Authorization"))
            urlopen.side_effect = setup.urllib.error.URLError(PEM)
            with self.assertRaises(RuntimeError) as error:
                setup.public_app(APP["slug"])
            self.assertNotIn(PEM, str(error.exception))
        for app in ({**APP, "owner": {"login": "other"}}, {**APP, "client_id": "different"}):
            with tempfile.TemporaryDirectory() as directory:
                calls = []
                def api(endpoint, **kwargs):
                    calls.append((endpoint, kwargs))
                    if endpoint == "repos/owner/repo":
                        return {"full_name": "owner/repo", "permissions": {"admin": True},
                                "owner": {"type": "Organization"}, "default_branch": "main"}
                    if "/contents/" in endpoint:
                        return {"type": "file"}
                    return {"value": APP["slug"] if endpoint.endswith(setup.APP_SLUG) else APP["client_id"]}
                with (patch.object(setup, "api", side_effect=api),
                      patch.object(setup, "public_app", return_value=app),
                      patch.object(setup, "credentials") as credentials):
                    with self.assertRaises(RuntimeError):
                        setup.install("owner/repo", SOURCE, ["test"], directory)
                    credentials.assert_not_called()
                self.assertTrue(all(kwargs.get("method", "GET") == "GET" for _, kwargs in calls))
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_missing_app_permissions_fail_before_mutations(self):
        incomplete = {**APP, "permissions": {"administration": "read"}}
        with (patch.object(setup, "gh") as gh, patch.object(setup.tempfile, "mkstemp") as recovery):
            with self.assertRaisesRegex(RuntimeError, "Pull requests write"):
                setup.credentials("owner/repo", incomplete)
            gh.assert_not_called()
            recovery.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def api(endpoint, **kwargs):
                calls.append((endpoint, kwargs))
                if endpoint == "repos/owner/repo":
                    return {"full_name": "owner/repo", "permissions": {"admin": True}, "owner": {"type": "Organization"}, "default_branch": "main"}
                if "/contents/" in endpoint:
                    return {"type": "file"}
                return {"value": APP["slug"] if endpoint.endswith(setup.APP_SLUG) else APP["client_id"]}
            with (patch.object(setup, "api", side_effect=api), patch.object(setup, "public_app", return_value=incomplete),
                  patch.object(setup, "credentials") as credentials):
                with self.assertRaisesRegex(RuntimeError, "approve the installation"):
                    setup.install("owner/repo", SOURCE, ["test"], directory)
                credentials.assert_not_called()
            self.assertTrue(all(kwargs.get("method", "GET") == "GET" for _, kwargs in calls))
            self.assertEqual(list(Path(directory).iterdir()), [])
