# Contributing

Use Python 3.10 or newer, Bash, and `jq` for the tests; no Python packages are needed. Keep changes focused and include a behavior test when the behavior changes.

Run the test suite before opening a pull request:

```sh
python3 -m unittest discover -s tests -v
```

For workflow changes, also run `actionlint .github/workflows/*.yml`. Open a pull request with a clear summary, test results, and any relevant issue link. Contributions are accepted under the [MIT License](LICENSE).
