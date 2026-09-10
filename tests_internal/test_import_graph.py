"""Guards the `src/` import graph against cycles.

A cycle here is not merely untidy: `src/proxy/__init__.py` used to
re-export names from `client.py`, which imports the `src.proxy` package
back. It survived only because `client.py` imported `tunnel` in the
submodule form, defended by a five-line comment. Nothing consumed the
re-exports, so the whole constraint existed to serve dead code.

The graph is built from the AST rather than by importing anything, so this
test needs no Qt, no Scapy and no DUT.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from src import paths

pytestmark = [pytest.mark.internal]


def _module_name(path: Path, root: Path) -> str:
    """`src/proxy/client.py` -> `src.proxy.client`; a package's
    `__init__.py` -> the package itself."""
    rel = path.relative_to(root.parent).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imported_src_modules(tree: ast.AST, own_package: str) -> set[str]:
    """Every `src.*` module this file imports, including the
    `from pkg import submodule` form, which imports `pkg.submodule`."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names if a.name.startswith("src"))
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import — resolve against this package
                base = own_package
            elif node.module and node.module.startswith("src"):
                base = node.module
            else:
                continue
            found.add(base)
            # `from src.proxy import tunnel` imports src.proxy.tunnel too.
            found.update(f"{base}.{a.name}" for a in node.names)
    return found


def _import_graph() -> dict[str, set[str]]:
    src_root = paths.project_root() / "src"
    files = {
        _module_name(p, src_root): p
        for p in src_root.rglob("*.py")
        if "__pycache__" not in p.parts
    }
    graph: dict[str, set[str]] = {}
    for name, path in files.items():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        own_package = name.rsplit(".", 1)[0] if "." in name else name
        # Keep only edges to modules that actually exist as files, so
        # `from src.config import Role` points at src.config, not src.config.Role.
        graph[name] = {m for m in _imported_src_modules(tree, own_package) if m in files} - {name}
    return graph


def _find_cycle(graph: dict[str, set[str]]) -> list[str] | None:
    """Depth-first search returning one cycle as a path, or None."""
    WHITE, GREY, BLACK = 0, 1, 2
    colour = dict.fromkeys(graph, WHITE)
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        colour[node] = GREY
        stack.append(node)
        for neighbour in sorted(graph[node]):
            if colour[neighbour] == GREY:
                return stack[stack.index(neighbour):] + [neighbour]
            if colour[neighbour] == WHITE:
                cycle = visit(neighbour)
                if cycle:
                    return cycle
        stack.pop()
        colour[node] = BLACK
        return None

    for node in sorted(graph):
        if colour[node] == WHITE:
            cycle = visit(node)
            if cycle:
                return cycle
    return None


def test_src_import_graph_has_no_cycles() -> None:
    cycle = _find_cycle(_import_graph())
    assert cycle is None, "import cycle in src/: " + " -> ".join(cycle or [])


def test_proxy_package_imports_nothing() -> None:
    """The re-exports are what created the cycle, and no caller used them.

    Checked against the source, not `vars(src.proxy)`: importing a
    submodule binds it as an attribute of its package, so the runtime
    namespace says nothing about what `__init__.py` itself does.

    If a genuine need for a package-level facade appears, add it here
    knowingly — but check `client.py` can still import `tunnel` normally.
    """
    init = paths.project_root() / "src" / "proxy" / "__init__.py"
    tree = ast.parse(init.read_text(encoding="utf-8"), filename=str(init))
    imports = [
        ast.unparse(node)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    assert imports == [], (
        f"src/proxy/__init__.py imports {imports} again — that is what made "
        "the package import client.py, which imports the package back. "
        "Import the submodule directly instead (see the module docstring)."
    )
