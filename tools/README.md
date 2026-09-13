# tools/ — repository maintenance scripts

Developer utilities that are not part of the shipped package (`src/`) and
not part of either test suite. Nothing here is imported at runtime.

| Script | Purpose |
|---|---|
| `generate_screenshots.py` | Regenerates every image in `docs/images/`. |
| `generate_icon.py` | Rebuilds `packaging/icon.ico` and `packaging/icon.png` from the SVG sources. |

## generate_screenshots.py

```bash
python tools/generate_screenshots.py
```

Requires the `gui` extra (`pip install -e ".[gui]"`). Needs **no** DUT, no
Administrator, and no live capture — it builds each widget directly, feeds
it a synthetic `TestRunResult`, and calls `QWidget.grab()`. Output is
deterministic, so a regenerated image only changes when the UI actually
changed.

Re-run it after any change to `src/gui/`, `src/plotting/`,
`src/reporting/` or `src/design_tokens.py`, and commit the regenerated
images with the code change. It calls `gui.theme.apply_theme` first, so
the images show the app as it ships rather than an unstyled build.

### What it produces

| Image | Source widget / function |
|---|---|
| `gui-main-window.png` | `MainWindow`, Live plot tab |
| `gui-main-window-log.png` | `MainWindow`, Log tab |
| `gui-dut-configuration.png` | `MainWindow._build_config_bar()` — both configuration cards |
| `gui-test-tree.png` | `TestTreeWidget` |
| `gui-test-details.png` | `TestDetailsPanel` |
| `gui-log-panel.png` | `LogPanel` |
| `gui-live-plot.png` | `RealtimePlotWidget` |
| `gui-report-panel.png` | `ReportPanel` |
| `gui-custom-packet.png` | `CustomPacketPanel`, generated payload mode |
| `gui-custom-packet-custom-payload.png` | `CustomPacketPanel`, Custom payload mode |
| `report-html.png` | `generate_html_report`, rendered via `QWebEngineView` |
| `chart-packet-timeline.png` | `render_packet_timeline` |
| `chart-pass-fail-summary.png` | `render_pass_fail_summary` |

### Conventions the script keeps

- **Real catalog nodeids.** The synthetic `TestRunResult` uses test ids that
  actually exist in [`src/catalog.py`](../src/catalog.py), so the report and
  the details panel render genuine descriptions and RFC clauses instead of
  the `(no catalog description)` fallback. If a cataloged test is renamed,
  update `sample_result()` too.
- **Documentation addresses only.** Targets sit in the RFC 5737
  `TEST-NET-1` range (`192.0.2.0/24`) so no real host is named in the docs.
- **A realistic outcome mix.** The sample run passes, fails, skips *and*
  errors, so screenshots exercise every code path in the log prefixes,
  report findings section and summary chart.

Adding a widget? Add a `shot_*` function and call it from `main()`, then
reference the image from the module's own `README.md`.

## generate_icon.py

```bash
python tools/generate_icon.py
```

Rasterises the app icon from its SVG sources into the two files the builds
consume, both of which are committed — a build machine must not need Qt or
Pillow just to have an icon:

| Output | Consumed by |
|---|---|
| `packaging/icon.ico` | The exe's own icon (`NetstackTestSuite.spec`, Windows only) and the installer's (`installer.iss`). Multi-resolution: 16, 20, 24, 32, 40, 48, 64, 128, 256px. |
| `packaging/icon.png` | The Qt window icon at runtime (`src/paths.app_icon`), on every platform — and the only one Linux gets, an ELF having no icon slot. |

There are **two** sources, and a change to the mark means editing both:

- [`packaging/icon.svg`](../packaging/icon.svg) — the full drawing, used
  for 32px and up.
- [`packaging/icon-small.svg`](../packaging/icon-small.svg) — the same mark
  stripped to what a 16px grid holds, used for 16–24px. Downsampling the
  full drawing that far turns its plate edges, packet and glow into one
  blue smear; this variant keeps the silhouette crisp.

Colours come from the same tokens as the app
([`src/design_tokens.py`](../src/design_tokens.py)) — copied as literals,
because an SVG cannot import Python. Re-check both sizes after any edit;
the small frames are the ones that break first.
