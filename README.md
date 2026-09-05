# Dependasolver

Dependabot auto-merge with GitHub App authentication. No PAT or hosted service.

Requires Python 3.10+, `gh auth login --web`, repository admin access, and permission
to register/install an App. CI must already provide the checks listed below.

Publish this repository first, then replace `SOURCE_COMMIT` with its full commit SHA.
From the repository you want to configure:

```sh
python3 ../dependasolver/setup.py \
  --repo uqrealitylabs/eyslie \
  --solver-ref uqrealitylabs/dependasolver@SOURCE_COMMIT \
  --checks test audit dependency-review
```

This previews setup. Add `--apply` to run it, then complete GitHub's App prompts
for the target repository. Publish the generated `.github/workflows/dependasolver.yml`
to activate it. Use `--directory PATH` for another local checkout.

Setup stores App credentials, enables auto-merge, and requires up-to-date checks.
Existing protection and Dependabot configuration are preserved; reruns reuse credentials.
Classic branch protection is required. If GitHub rejects adding status checks to
existing protection that has none, enable required checks in branch settings and rerun.
Failed credential uploads retain a private recovery key at the printed path;
complete both Actions credentials before retrying.

Only verified Dependabot minor/patch updates with 95–100% compatibility and no
maintainer changes qualify. Required checks and reviews still apply.

Check locally: `python3 -m unittest discover -s tests -v`.

License: [GPL-3.0-only](LICENSE).
