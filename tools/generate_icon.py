"""Render packaging/icon.svg into the icon files the builds consume.

    python tools/generate_icon.py

Writes, from the one SVG source:
  packaging/icon.ico  — Windows: the exe's icon (PyInstaller) and the
                        installer's (Inno Setup). Multi-resolution, because
                        Explorer, the taskbar and Alt-Tab each pick a
                        different frame and a single 256px one scales badly.
  packaging/icon.png  — 512px, the Qt window icon. Used on every platform
                        for the title bar and task switcher, and it is what
                        Linux gets, having no .ico.

Both outputs are committed: a build must not need Qt or Pillow just to
have an icon, and the CI build machines never run this script.

Qt does the SVG rasterising (QSvgRenderer) so the gradients match what the
app itself would draw; Pillow only assembles the frames into the .ico
container, which Qt cannot write.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

from PIL import Image
from PySide6.QtCore import QBuffer, QByteArray, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "packaging" / "icon.svg"
#: Below this, the full mark's detail is sub-pixel and downsamples to a
#: smear, so the small frames come from a stripped variant of it instead.
SMALL_SOURCE = ROOT / "packaging" / "icon-small.svg"
SMALL_UP_TO = 24
ICO = ROOT / "packaging" / "icon.ico"
PNG = ROOT / "packaging" / "icon.png"

#: Frames Windows actually asks for: 16 (tree/list), 24-32 (desktop, Alt-Tab),
#: 48-64 (medium tiles), 128-256 (large tiles and the Explorer preview).
ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
PNG_SIZE = 512


def render(renderer: QSvgRenderer, size: int) -> Image.Image:
    """Rasterise the SVG at `size`x`size` onto transparency, as a PIL image."""
    image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    renderer.render(painter)
    painter.end()

    # Qt -> PIL via an in-memory PNG: the alternative, poking at the raw
    # ARGB32 buffer, has to get premultiplication and stride right by hand.
    # `data` is bound to a name rather than passed as a temporary, which
    # Python collects while the QBuffer still points at it (a hard crash,
    # not an exception).
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QBuffer.OpenModeFlag.WriteOnly)
    image.save(buffer, "PNG")
    buffer.close()
    return Image.open(io.BytesIO(data.data())).convert("RGBA")


def main() -> int:
    for source in (SOURCE, SMALL_SOURCE):
        if not source.exists():
            print(f"missing source: {source}", file=sys.stderr)
            return 1

    # Bound to a name deliberately: an unreferenced QGuiApplication is
    # collected while Qt is still using it, and the process dies mid-render.
    _app = QGuiApplication(sys.argv)  # QImage/QPainter need a live application
    renderers = {}
    for source in (SOURCE, SMALL_SOURCE):
        renderer = QSvgRenderer(str(source))
        if not renderer.isValid():
            print(f"not a readable SVG: {source}", file=sys.stderr)
            return 1
        renderers[source] = renderer

    frames = [
        render(renderers[SMALL_SOURCE if size <= SMALL_UP_TO else SOURCE], size)
        for size in ICO_SIZES
    ]
    # Pillow resamples from the largest frame unless every size is supplied;
    # append_images gives it our own crisp render of each instead.
    frames[-1].save(ICO, format="ICO", sizes=[(s, s) for s in ICO_SIZES], append_images=frames)
    render(renderers[SOURCE], PNG_SIZE).save(PNG, format="PNG")

    print(f"wrote {ICO.relative_to(ROOT)}  ({', '.join(f'{s}px' for s in ICO_SIZES)})")
    print(f"wrote {PNG.relative_to(ROOT)}  ({PNG_SIZE}px)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
