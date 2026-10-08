# Contributing

Use a focused branch, run `./scripts/test.sh`, and format with Black and Ruff
before opening a pull request. Mock Mode (`WIFI_LAB_MOCK=1`) is mandatory for
tests: no test may require root, radio hardware, a GPU, or private captures.

Plugins must provide metadata and tests. Vendor profiles must be structured,
cite a source, state a confidence level, and never claim undocumented defaults.
Do not submit wordlists, captures, hashes, passwords, or personal databases.
