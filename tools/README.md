# tools/ — repository maintenance scripts

Developer utilities that are not part of the shipped package (`src/`) and
not part of either test suite. Nothing here is imported at runtime.

| Script | Purpose |
|---|---|
| `generate_screenshots.py` | Regenerates every image in `docs/images/`. |

## generate_screenshots.py

```bash
python tools/generate_screenshots.py
```

Requires the `gui` extra (`pip install -e ".[gui]"`). Needs **no** DUT, no
Administrator, and no live capture — it builds each widget directly, feeds
it a synthetic `TestRunResult`, and calls `QWidget.grab()`. Output is
deterministic, so a regenerated image only changes when the UI actually
changed.

Re-run it after any change to `src/gui/`, `src/plotting/` or
`src/reporting/`, and commit the regenerated images with the code change.

### What it produces

| Image | Source widget / function |
|---|---|
| `gui-main-window.png` | `MainWindow`, Live plot tab |
| `gui-main-window-log.png` | `MainWindow`, Log tab |
| `gui-dut-configuration.png` | `MainWindow._build_config_group()` |
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
