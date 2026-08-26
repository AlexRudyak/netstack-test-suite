"""QTreeWidget: module → submodule → file → **test function** hierarchy,
with cascading checkboxes for run selection.

Structure comes from a filesystem walk of tests/ (not `pytest
--collect-only`, which would import every module and drag in DUT concerns
just to draw a picker). The per-file test functions and their
descriptions come from the test catalog (src/catalog.py), so selecting a
test can show exactly what it checks and its RFC connection.

Each node carries:
- a `target` (pytest path or nodeid, e.g. "tests/ip" or
  "tests/ip/test_x.py::test_a") used to build the run, and
- test nodes additionally carry their catalog `TestSpec` for the details
  panel.

Checkboxes cascade: checking a parent checks every descendant; a parent
shows a partial (tri-state) check when only some children are checked.
`checked_targets()` returns the minimal covering set (a checked node whose
parent is also fully checked is redundant — the parent's target covers it).
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem

from src import catalog, paths
from src.catalog import TestSpec

_TARGET_ROLE = Qt.ItemDataRole.UserRole
_SPEC_ROLE = Qt.ItemDataRole.UserRole + 1

_CHECKED = Qt.CheckState.Checked
_UNCHECKED = Qt.CheckState.Unchecked
_PARTIAL = Qt.CheckState.PartiallyChecked


class TestTreeWidget(QTreeWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setHeaderLabels(["Test"])
        self._populate()
        self.itemChanged.connect(self._on_item_changed)

    def _populate(self) -> None:
        self.clear()
        tests_root = paths.tests_root()
        if not tests_root.exists():
            return
        for module_dir in sorted(p for p in tests_root.iterdir() if p.is_dir() and not p.name.startswith("_")):
            module_item = self._make_item(module_dir.name, target=f"tests/{module_dir.name}")
            self.addTopLevelItem(module_item)
            self._populate_dir(module_dir, module_item, module=module_dir.name, submodule=None)
        self.expandToDepth(1)

    def _populate_dir(
        self, directory: Path, parent_item: QTreeWidgetItem, *, module: str, submodule: str | None
    ) -> None:
        for entry in sorted(directory.iterdir()):
            if entry.is_dir() and not entry.name.startswith("_"):
                sub_item = self._make_item(entry.name, target=f"tests/{module}/{entry.name}")
                parent_item.addChild(sub_item)
                self._populate_dir(entry, sub_item, module=module, submodule=entry.name)
            elif entry.is_file() and entry.name.startswith("test_") and entry.suffix == ".py":
                rel_path = entry.relative_to(paths.project_root()).as_posix()
                file_item = self._make_item(entry.stem, target=rel_path)
                parent_item.addChild(file_item)
                self._add_test_children(entry, file_item, rel_path=rel_path)

    def _add_test_children(self, file_path: Path, file_item: QTreeWidgetItem, *, rel_path: str) -> None:
        for spec in catalog.specs_for_rel_path(rel_path):
            test_item = self._make_item(spec.test, target=f"{rel_path}::{spec.test}")
            test_item.setData(0, _SPEC_ROLE, spec)
            test_item.setToolTip(0, f"{spec.title}\n{spec.rfc}\nroles: {spec.role_labels}")
            file_item.addChild(test_item)

    def _make_item(self, label: str, *, target: str) -> QTreeWidgetItem:
        item = QTreeWidgetItem([label])
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(0, _UNCHECKED)
        item.setData(0, _TARGET_ROLE, target)
        return item

    # --- checkbox cascade --------------------------------------------------

    def _on_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        if column != 0:
            return
        # Programmatic setCheckState re-emits itemChanged; block to avoid
        # recursion while we propagate down and roll up.
        self.blockSignals(True)
        try:
            state = item.checkState(0)
            if state != _PARTIAL:
                self._set_descendants(item, state)
            self._refresh_ancestors(item)
        finally:
            self.blockSignals(False)

    def _set_descendants(self, item: QTreeWidgetItem, state: Qt.CheckState) -> None:
        for i in range(item.childCount()):
            child = item.child(i)
            child.setCheckState(0, state)
            self._set_descendants(child, state)

    def _refresh_ancestors(self, item: QTreeWidgetItem) -> None:
        parent = item.parent()
        while parent is not None:
            states = [parent.child(i).checkState(0) for i in range(parent.childCount())]
            if all(s == _CHECKED for s in states):
                parent.setCheckState(0, _CHECKED)
            elif all(s == _UNCHECKED for s in states):
                parent.setCheckState(0, _UNCHECKED)
            else:
                parent.setCheckState(0, _PARTIAL)
            parent = parent.parent()

    # --- queries -----------------------------------------------------------

    @staticmethod
    def spec_of(item: QTreeWidgetItem | None) -> TestSpec | None:
        if item is None:
            return None
        data = item.data(0, _SPEC_ROLE)
        return data if isinstance(data, TestSpec) else None

    def checked_targets(self) -> list[str]:
        """Minimal set of pytest targets covering the checked selection: a
        fully-checked node whose parent is NOT fully checked (so the parent's
        broader target doesn't already cover it)."""
        targets: list[str] = []

        def walk(item: QTreeWidgetItem) -> None:
            parent = item.parent()
            parent_fully_checked = parent is not None and parent.checkState(0) == _CHECKED
            if item.checkState(0) == _CHECKED and not parent_fully_checked:
                targets.append(item.data(0, _TARGET_ROLE))
                return  # descendants are covered by this target
            for i in range(item.childCount()):
                walk(item.child(i))

        for i in range(self.topLevelItemCount()):
            walk(self.topLevelItem(i))
        return targets

    def checked_specs(self) -> list[TestSpec]:
        """Catalog specs of every checked *test-function* node (for the
        role-mismatch warning)."""
        specs: list[TestSpec] = []

        def walk(item: QTreeWidgetItem) -> None:
            if item.checkState(0) == _CHECKED:
                spec = self.spec_of(item)
                if spec is not None:
                    specs.append(spec)
            for i in range(item.childCount()):
                walk(item.child(i))

        for i in range(self.topLevelItemCount()):
            walk(self.topLevelItem(i))
        return specs
