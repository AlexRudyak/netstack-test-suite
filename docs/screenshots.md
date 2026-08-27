# Screenshots

Every UI surface the suite presents, in one place. Each image is
**generated**, not hand-captured — see [Regenerating](#regenerating).

The data in these images is synthetic and the target address is inside the
RFC 5737 `TEST-NET-1` documentation range (`192.0.2.0/24`), so no real host
is ever named in the docs.

---

## GUI — `netstack-gui`

### Main window

The whole app mid-run: DUT configuration, test picker with per-test
description, live plot, and the run summary with report export.

![Main window](images/gui-main-window.png)

Module: [`src/gui/main_window.py`](../src/gui/README.md#main_windowpy)

### DUT configuration

Interface, target IP/MAC, target stack profile, role, the CIDR allow-list,
and the two gates a run passes through — vuln authorization and debug mode.

![DUT configuration](images/gui-dut-configuration.png)

### Test selection tree

Module → submodule → file → test function, with cascading checkboxes.
`icmp` is fully checked; `tcp` shows the tri-state box because only one
descendant is selected.

![Test tree](images/gui-test-tree.png)

Module: [`src/gui/test_tree_widget.py`](../src/gui/README.md#test_tree_widgetpy)

### Per-test details

Title, RFC clause, applicable roles, markers and full description for the
selected test — driven by [`src/catalog.py`](../src/catalog.py).

![Test details](images/gui-test-details.png)

Module: [`src/gui/test_details_panel.py`](../src/gui/README.md#test_details_panelpy)

### Live plot

Cumulative sent/received during a run. The gap between the curves is
probes that drew no reply.

![Live plot](images/gui-live-plot.png)

Module: [`src/plotting/realtime_plotter.py`](../src/plotting/README.md#realtime_plotterpy)

### Log panel

Preflight output followed by one line per test, prefixed
`PASS` / `FAIL` / `SKIP` / `ERR`.

![Log panel](images/gui-log-panel.png)

The main window switches to this tab when a run starts:

![Main window, Log tab](images/gui-main-window-log.png)

Module: [`src/gui/log_panel.py`](../src/gui/README.md#log_panelpy)

### Report panel

The run summary and the PDF/HTML export buttons.

![Report panel](images/gui-report-panel.png)

Module: [`src/gui/report_panel.py`](../src/gui/README.md#report_panelpy)

### Custom Packet

The GUI twin of `netstack-cli send` — L3/L4 fields plus an L7 payload mode
selector. Generated modes (Zeros / Ones / Random) show a size field:

![Custom Packet, Random mode](images/gui-custom-packet.png)

Selecting **Custom** swaps it for the text/hex/file sub-form:

![Custom Packet, Custom mode](images/gui-custom-packet-custom-payload.png)

Module: [`src/gui/custom_packet_panel.py`](../src/gui/README.md#custom_packet_panelpy)

---

## Reporting

### HTML report

The deliverable: findings first, each naming its RFC clause, what the test
checks, and what the DUT actually did.

![HTML report](images/report-html.png)

Module: [`src/reporting/html_report.py`](../src/reporting/README.md#html_reportpy)

### Static charts

Rendered by [`src/plotting/static_charts.py`](../src/plotting/README.md#static_chartspy)
and embedded in the PDF report.

| Packet timeline | Pass/fail summary |
|---|---|
| ![Packet timeline](images/chart-packet-timeline.png) | ![Pass/fail summary](images/chart-pass-fail-summary.png) |

---

## Regenerating

Screenshots rot the moment a widget changes, so they are produced by
building the real widgets, feeding them representative data, and calling
`QWidget.grab()`:

```bash
python tools/generate_screenshots.py
```

No DUT, no Administrator and no live capture are needed — the run data is
synthetic, so the output is deterministic and reviewable in a diff. Re-run
it after any change to `src/gui/`, `src/plotting/` or `src/reporting/`, and
commit the regenerated images alongside the code change.

See [`tools/README.md`](../tools/README.md) for what each shot covers.
