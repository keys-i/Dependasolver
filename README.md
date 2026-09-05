# Dependasolver + Rady

Dependasolver reviews Dependabot PRs and gates auto-merge, while Rady reviews other PRs and helps you code locally

Reviews use the actual diff and CI results, with specific findings and plain Australian English

```sh
python3 setup.py --app dependasolver --repo OWNER/REPO \
  --solver-ref keys-i/dependasolver@SOURCE_COMMIT --checks test audit dependency-review
```

Use a published commit SHA, add `--apply`, then repeat with `--app rady` to register the second public App under **keys-i**. Requires Python 3.10+, GitHub CLI login and repository admin access. Publish the generated workflow and add the Actions secret `OPENAI_API_KEY` to enable reviews

For local coding, install [Codex CLI](https://developers.openai.com/codex/cli), run `codex login` or set `CODEX_API_KEY`, then

```sh
python3 /path/to/dependasolver/rady.py code "Fix the failing tests" --directory /path/to/project
```

Coding changes stay local for your review. PR reviews send diffs and check summaries to OpenAI and default to `gpt-5.4`; set `RADY_MODEL` to change it

[Existing installs and credentials](docs/UPGRADING.md) · [MIT](LICENSE)
