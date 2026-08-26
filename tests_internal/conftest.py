"""tests_internal has no fixtures of its own beyond pytest's built-ins
(tmp_path, monkeypatch) — that's the point: nothing here should need a
DUT, a real interface, or elevated privileges. Tests that need to fake
network I/O do so with monkeypatch directly against
src.packet_engine.interface's module-level Scapy function references.
"""
