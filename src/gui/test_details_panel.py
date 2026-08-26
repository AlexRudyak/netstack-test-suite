"""Shows the description, RFC connection, and applicable roles of the
test currently selected in the tree — driven by the catalog TestSpec."""
from __future__ import annotations

from PySide6.QtWidgets import QLabel, QTextEdit, QVBoxLayout, QWidget

from src.catalog import TestSpec

_PLACEHOLDER = "Select a test in the tree to see what it checks and its RFC connection."


class TestDetailsPanel(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._title = QLabel()
        self._title.setWordWrap(True)
        self._title.setStyleSheet("font-weight: bold;")
        self._meta = QLabel()
        self._meta.setWordWrap(True)
        self._meta.setStyleSheet("color: palette(mid);")
        self._description = QTextEdit()
        self._description.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.addWidget(self._title)
        layout.addWidget(self._meta)
        layout.addWidget(self._description)

        self.show_spec(None)

    def show_spec(self, spec: TestSpec | None) -> None:
        if spec is None:
            self._title.setText("")
            self._meta.setText("")
            self._description.setPlainText(_PLACEHOLDER)
            return
        self._title.setText(spec.title)
        self._meta.setText(
            f"RFC: {spec.rfc}    •    roles: {spec.role_labels}"
            + (f"    •    markers: {', '.join(spec.markers)}" if spec.markers else "")
        )
        self._description.setPlainText(f"{spec.description}\n\n{spec.nodeid}")
