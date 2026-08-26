"""RFC 5681 slow start.

Observing genuine slow-start growth requires the DUT to be actively
sending a data stream (so cwnd growth can be measured across RTTs),
which depends on the DUT's *application* behavior on target_port, not
just its TCP stack — not something a protocol-conformance harness can
trigger generically without knowing what application the DUT exposes.

This is left as a structural placeholder showing where a slow-start
scenario plugs into the suite (congestion/ submodule, the established
connection fixture, target_profile for reference RTT/cwnd
characteristics) rather than a fabricated assertion. Point this at a
known DUT application and replace the skip with a real data-transfer-
driven cwnd growth measurement.
"""
from __future__ import annotations

import pytest

pytestmark = [pytest.mark.tcp, pytest.mark.congestion]


@pytest.mark.skip(
    reason="Requires the DUT to actively send an application data stream; "
    "see module docstring for what a live implementation needs."
)
def test_congestion_window_grows_across_initial_round_trips(established_tcp_connection, network_interface, dut_config) -> None:
    raise NotImplementedError
