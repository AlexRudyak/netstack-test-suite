# Contributing

## Branches

- **`main`** — stable. Releases are tagged from here; the packaged
  executable is published from a `main` tag on the [Releases](../../releases) page.
- **`development`** — active work. Branch feature work off `development`
  and open a PR back into it; `development` is merged into `main` for a release.

## Commit messages

All commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```
type(scope): short description

Optional body explaining what and why.
```

Common types: `feat`, `fix`, `docs`, `test`, `build`, `chore`, `refactor`, `perf`, `ci`.
Scopes mirror the packages, e.g. `feat(packet-engine):`, `test(dut):`, `fix(gui):`.

## Before pushing

Run the framework self-tests (no DUT or elevated privileges required):

```bash
pip install -e ".[gui,dev]"
pytest tests_internal/
```

Every test under `tests/` must have an entry in [`src/catalog.py`](src/catalog.py)
(description + RFC + roles) — `tests_internal/test_catalog.py` enforces this,
so add the catalog entry alongside a new test.

## Releasing

1. Merge `development` into `main`.
2. Bump the version in [`pyproject.toml`](pyproject.toml).
3. Build the executable: `python -m PyInstaller NetstackTestSuite.spec --noconfirm`.
4. Tag and publish: `gh release create vX.Y.Z --title "vX.Y.Z" dist/NetstackTestSuite.exe`.
