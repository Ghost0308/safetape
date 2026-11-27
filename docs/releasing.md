# Releasing

Releases go to PyPI through trusted publishing. GitHub Actions proves to PyPI which workflow is running, so there's no PyPI token to store or leak. The workflow is [release.yml](../.github/workflows/release.yml).

## Once, before the first release

On PyPI, go to Your account, then Publishing, and add a pending publisher:

- PyPI project name: `safetape`
- Owner: `Ghost0308`
- Repository name: `safetape`
- Workflow name: `release.yml`
- Environment name: `pypi`

On GitHub, go to Settings, then Environments, open `pypi` (or create it) and add yourself as a required reviewer. Under deployment branches and tags, allow only tags matching `v*`. Then nothing gets published without a click from you.

## Each release

1. On a branch, set `__version__` in `src/safetape/__init__.py` and turn the top of `CHANGELOG.md` into a heading for that version.
2. Open a PR, wait for CI, and merge it with "Rebase and merge".
3. Tag the merged commit on main and push the tag:

   ```
   git switch main
   git pull
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. The Release workflow runs the tests, builds, checks the tag matches the version, then waits for you to approve the `pypi` environment. Approve it and the package goes up, with attestations.

If the tag and the version don't match, the build stops before anything is published. Delete the tag, fix the version and tag again.
