# src/custom_packet — ad-hoc packet craft & send

The manual "send one packet and see the response" feature, outside the
pytest-driven RFC-assertion suite. Backs the CLI `send` subcommand and the
GUI Custom Packet panel. Adds **no** packet-crafting logic of its own — it
composes `packet_engine.builders` + `packet_engine.payloads` and sends via
`packet_engine.interface`, so ad-hoc sends share the exact same wire path
and pcap capture as automated tests.

## Modules

| Module | Responsibility |
|---|---|
| `builder.py` | `CustomPacketSpec` + `build_custom_packet` |
| `sender.py` | `send_custom_packet` |

## builder.py

| Symbol | Description |
|---|---|
| `CustomPacketSpec` | dataclass describing one packet: `proto` (`"tcp"`/`"udp"`), `src_ip`/`dst_ip`, `src_port`/`dst_port`, `src_mac`/`dst_mac`, `ttl=64`, `tcp_flags="S"`, `payload_mode=RANDOM`, `payload_size=64`, `custom_payload=None`. |
| `build_custom_packet(spec) -> Packet` | Resolves the payload (`resolve_payload`), builds the TCP/UDP packet, wraps it in Ethernet. Raises `ValueError` on an unsupported proto. |

## sender.py

| Function | Signature | Description |
|---|---|---|
| `send_custom_packet` | `(spec, iface, *, timeout=2.0, capture_path=None) -> Packet \| None` | Builds the packet, opens a `NetworkInterface`, `send_receive`s it (logged under `test_nodeid="custom_packet"`), returns the reply or `None`. Optionally captures to pcap. |

## Related interfaces

- CLI: [`netstack-cli send`](../cli/README.md#send)
- GUI: [`custom_packet_panel.py`](../gui/README.md#custom_packet_panelpy)
