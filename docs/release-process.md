# Release process

Update the single version source in `pyproject.toml`, update `CHANGELOG.md`, run `./scripts/check-release.sh`, then create an annotated `vX.Y.Z` tag. The GitHub release workflow builds an artifact and checksum when repository release permissions are configured.
