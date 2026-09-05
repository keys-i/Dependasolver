# Two bot identities

Keep the existing **Dependasolver** App for Dependabot PRs. Register a separate public **Rady** App under **keys-i** for other PRs. GitHub uses the authenticated App as the review author; a heading cannot change it, and App names/slugs must be available

Both Apps need **Administration, Contents, Checks and Commit statuses — read**, plus **Pull requests — write**. Approve the permission update on each installation and select only the repositories they should review. Do not give either App a branch-protection bypass

| App | Actions variables | Actions secret |
| --- | --- | --- |
| Dependasolver | `DEPENDASOLVER_APP_CLIENT_ID`, `DEPENDASOLVER_APP_SLUG` | `DEPENDASOLVER_APP_PRIVATE_KEY` |
| Rady | `RADY_APP_CLIENT_ID`, `RADY_APP_SLUG` | `RADY_APP_PRIVATE_KEY` |

Run setup with `--app dependasolver`, then `--app rady`, using the same repository, source SHA and required checks. Existing Apps are reused after their owner and permissions are verified. `--new-app` replaces credentials only for the selected identity

For an older caller, update it from `templates/dependency.solver.yml` first. Replace `__SOLVER_REF__` with `keys-i/dependasolver/.github/workflows/solve.yml@SHA`, `__SOURCE_REF__` with `keys-i/dependasolver@SHA`, and `__REQUIRED_CHECKS__` with your check names as JSON. Both pins must use the same published commit. Setup refuses to overwrite different local content

Add your OpenAI API key as the repository Actions secret **OPENAI_API_KEY** using GitHub Settings → Secrets and variables → Actions. Never commit it or paste it into a PR. A GitHub token cannot fund model requests; review runs use your OpenAI API billing. The optional Actions variable **RADY_MODEL** selects the model

Upload `assets/dependasolver.png` and `assets/rady.png` to their respective Apps. Publish the caller on the default branch to enable reviews

# Review behaviour

The reviewer reads diff patches and CI results without checking out or executing PR code. Reviews distinguish blockers, optional suggestions and unavailable evidence. Low compatibility is a signal to investigate, not proof of a specific bug

Only LOW-risk, complete reviews with all configured and protected checks passing can approve. Dependasolver also requires verified minor/patch metadata, no maintainer changes and 95–100% compatibility before enabling auto-merge. Scores below 80%, unknown scores, omitted patches and missing or failed checks hold approval. Branch protection remains the final merge gate

CI gets up to three minutes to finish. Use **Actions → Dependasolver and Rady → Run workflow** with the PR number to refresh the review afterwards. Manual Dependabot runs have no newly verified compatibility metadata, so they comment without approving or enabling auto-merge; the next Dependabot PR update refreshes that metadata

Local coding uses your Codex login or `CODEX_API_KEY`, a workspace-write sandbox and the repository's instructions. It edits and runs checks locally without automatically committing or pushing
