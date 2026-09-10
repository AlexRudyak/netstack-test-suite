"""Self-validation for src/catalog.py — the per-test metadata that drives
the GUI descriptions and docs. Guards against drift between the catalog
and the actual test functions on disk via AST inspection (no imports, no
DUT)."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from src import catalog
from src.config import Role

pytestmark = [pytest.mark.internal]

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _functions_in(rel_path: str) -> set[str]:
    source = (_REPO_ROOT / rel_path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }


def test_catalog_entries_have_required_fields() -> None:
    for spec in catalog.CATALOG:
        assert spec.title.strip(), f"{spec.nodeid} missing title"
        assert spec.description.strip(), f"{spec.nodeid} missing description"
        assert spec.rfc.strip(), f"{spec.nodeid} missing rfc"
        assert spec.roles, f"{spec.nodeid} missing roles"
        assert all(isinstance(r, Role) for r in spec.roles)


def test_catalog_has_no_duplicate_nodeids() -> None:
    nodeids = [s.nodeid for s in catalog.CATALOG]
    assert len(nodeids) == len(set(nodeids)), "duplicate catalog entries"


def test_every_cataloged_test_exists_on_disk() -> None:
    """Each catalog entry must point at a real test file and function."""
    for spec in catalog.CATALOG:
        path = _REPO_ROOT / spec.rel_path
        assert path.exists(), f"{spec.nodeid}: file {spec.rel_path} does not exist"
        functions = _functions_in(spec.rel_path)
        assert spec.test in functions, f"{spec.nodeid}: function {spec.test} not found in {spec.rel_path}"


def test_every_test_function_is_cataloged() -> None:
    """Every test function under tests/ must have a catalog entry, so the
    GUI can describe it (and the two can't silently diverge)."""
    tests_root = _REPO_ROOT / "tests"
    uncataloged: list[str] = []
    for test_file in tests_root.rglob("test_*.py"):
        rel = test_file.relative_to(_REPO_ROOT).as_posix()
        cataloged = {s.test for s in catalog.specs_for_rel_path(rel)}
        for fn in _functions_in(rel):
            if fn not in cataloged:
                uncataloged.append(f"{rel}::{fn}")
    assert not uncataloged, "test functions missing from the catalog: " + ", ".join(uncataloged)


def test_lookup_helpers() -> None:
    spec = catalog.CATALOG[0]
    assert catalog.find_by_nodeid(spec.nodeid) is spec
    assert catalog.find_by_test(spec.rel_path, spec.test) is spec
    assert catalog.find_by_nodeid("tests/nope.py::nope") is None


def test_server_role_tests_are_present() -> None:
    """The suite must include server-role tests (the client/server
    expansion) — at least one per applicable module."""
    server_modules = {s.module for s in catalog.CATALOG if Role.SERVER in s.roles}
    assert {"tcp", "udp", "icmp"} <= server_modules


def test_file_and_test_tail_is_unique_across_the_catalog() -> None:
    """find_by_nodeid resolves prefixed node ids through a `<file>.py::<test>`
    index instead of scanning every spec. That index is only correct while
    the tail is unique — two files with the same stem and a same-named test
    would silently resolve to whichever was built last."""
    from src.catalog import _BY_SUFFIX

    assert len(_BY_SUFFIX) == len(catalog.CATALOG)


def test_find_by_nodeid_resolves_prefixed_and_windows_node_ids() -> None:
    """pytest can report an absolute path, and Windows reports backslashes."""
    spec = catalog.CATALOG[0]

    assert catalog.find_by_nodeid(spec.nodeid) is spec
    assert catalog.find_by_nodeid(f"/abs/checkout/{spec.nodeid}") is spec
    assert catalog.find_by_nodeid(spec.nodeid.replace("/", "\\")) is spec
    assert catalog.find_by_nodeid("tests/ip/test_nope.py::test_nope") is None
