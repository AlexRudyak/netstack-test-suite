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


# Layer -> the layers it may depend on. Front ends (4) may reach into
# everything below them; everything below may only reach sideways or down.
# Same-layer edges are deliberately unchecked (e.g. nothing stops `gui`
# from importing `cli`, which doesn't happen but isn't the rule this guards
# — the rule that matters is "nothing below front ends imports upward").
#
# `src.reporting.models` and `src.run_artifacts` are pinned to layer 0
# ahead of the general `src.reporting` entry: both are shared, I/O-adjacent
# value shapes with no upward dependency of their own (the run-directory
# naming, the canonical result DTOs) that the engine, the orchestration
# layer, and the reporting layer all need to agree on — not orchestration
# or presentation logic themselves. A first pass placed them at layers 3
# and 2 respectively, by which module they happened to be defined in
# rather than what depends on them; running this test against the real
# graph found `packet_engine.interface -> reporting.models` and
# `reporting.{collector,report_data} -> run_artifacts`, both legitimate,
# which is what motivated pulling them down to the kernel tier.
_LAYER = {
    "src": 0,  # the empty package marker; `from src import paths` reaches it too
    "src.cli": 4,
    "src.gui": 4,
    "src.runner": 3,
    "src.collection_policy": 3,
    "src.reporting.models": 0,
    "src.reporting": 2,
    "src.plotting": 2,
    "src.packet_engine": 1,
    "src.proxy": 1,
    "src.custom_packet": 1,
    "src.utils": 1,
    "src.config": 0,
    "src.catalog": 0,
    "src.target_profiles": 0,
    "src.errors": 0,
    "src.paths": 0,
    "src.run_artifacts": 0,
}


def _layer_of(module: str) -> int:
    """The layer of `module`, matched by longest containing package prefix
    (`src.gui.report_panel` resolves via the `src.gui` entry)."""
    prefix = max((p for p in _LAYER if module == p or module.startswith(p + ".")), key=len)
    return _LAYER[prefix]


def test_no_upward_or_reverse_layer_imports() -> None:
    """`src/`'s five layers (config/domain, engine, output, orchestration,
    front ends) must only depend downward or sideways.

    A cycle-only guard would not catch this: `src.packet_engine` importing
    `src.gui` creates no cycle (gui already depends on packet_engine), so
    `test_src_import_graph_has_no_cycles` would pass while the engine layer
    quietly grew a dependency on Qt. This test checks direction, not just
    the absence of a loop.
    """
    graph = _import_graph()
    violations = sorted(
        f"{src} (layer {_layer_of(src)}) -> {dst} (layer {_layer_of(dst)})"
        for src, deps in graph.items()
        for dst in deps
        if _layer_of(src) < _layer_of(dst)
    )
    assert not violations, "layering violation(s):\n" + "\n".join(violations)


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
