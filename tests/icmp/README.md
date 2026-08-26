# tests/icmp — ICMP (RFC 792) conformance

Echo/Reply behavior in **both roles**, plus malformed-ICMP robustness.

## Files & test functions

| Test | Role | RFC | What it checks |
|---|---|---|---|
| `test_icmp_echo.py::test_echo_request_elicits_reply` | client | RFC 792 | The suite pings the DUT; expects a matching Echo Reply (id/seq/payload preserved). |
| `test_icmp_echo.py::test_server_responds_to_dut_echo` | server | RFC 792 | The DUT pings the suite; the suite replies and validates the DUT initiated — exercises the DUT's ping-client path. |
| `test_icmp_errors.py::test_truncated_icmp_does_not_crash_dut` | client | RFC 792 (robustness) | A truncated ICMP message is discarded without crashing the DUT (`vuln`). |

## Roles

This module demonstrates the client/server split (see
[`tests/README.md`](../README.md#roles-client--server)). Run the server
test with the DUT configured to ping this host:

```bash
netstack-cli run --module icmp --role server --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
```
