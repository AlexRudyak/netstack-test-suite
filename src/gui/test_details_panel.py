"""Shows the description, RFC connection, and applicable roles of the
test currently selected in the tree — driven by the catalog TestSpec."""
from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLabel, QTextEdit, QVBoxLayout, QWidget

from src.catalog import TestSpec
from src.design_tokens import SPACE

_PLACEHOLDER = "Select a test in the tree to see what it checks and its RFC connection."

#: How many metadata chips the row can hold: RFC, roles, markers. Built
#: once and shown/hidden per selection, so the row never reflows the panel
#: as the selection moves.
_CHIP_SLOTS = 3


class TestDetailsPanel(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._title = QLabel()
        self._title.setWordWrap(True)
        self._title.setProperty("role", "subheading")

        # The metadata used to be one grey line of bullet-separated text.
        # As chips, each fact is a separate object the eye can land on —
        # and the markers chip is visibly absent rather than silently
        # truncated when a test carries none.
        self._chips = [QLabel() for _ in range(_CHIP_SLOTS)]
        chip_row = QHBoxLayout()
        chip_row.setSpacing(6)
        for chip in self._chips:
            chip.setProperty("role", "chip")
            chip_row.addWidget(chip)
        chip_row.addStretch(1)

        self._description = QTextEdit()
        self._description.setReadOnly(True)
        self._description.setProperty("role", "console")
        # Two or three lines of description, not a text editor's default
        # 12: the tree above it is what the panel is a caption for.
        self._description.setMinimumHeight(72)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 3, 0, 0)
        layout.setSpacing(SPACE)
        layout.addWidget(self._title)
        layout.addLayout(chip_row)
        layout.addWidget(self._description)

        self.show_spec(None)

    def show_spec(self, spec: TestSpec | None) -> None:
        if spec is None:
            self._title.setText("Test details")
            self._set_chips([])
            self._description.setPlainText(_PLACEHOLDER)
            return
        self._title.setText(spec.title)
        self._set_chips(
            [spec.rfc, f"roles: {spec.role_labels}"]
            + ([f"markers: {', '.join(spec.markers)}"] if spec.markers else [])
        )
        self._description.setPlainText(f"{spec.description}\n\n{spec.nodeid}")

    def _set_chips(self, texts: list[str]) -> None:
        for chip, text in zip(self._chips, texts + [""] * _CHIP_SLOTS):
            chip.setText(text)
            chip.setVisible(bool(text))
