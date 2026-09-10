"""Proxy-DUT testing: topology config, the echo backend, the tunnelling
client, and the traffic inducer.

Deliberately carries no re-exports. It used to list seven names, which made
`src/proxy/__init__` import `client.py`, which imports the `src.proxy`
package back — a real cycle that `client.py` only survived by importing
`tunnel` in the submodule form, with a five-line comment defending the
workaround. Nothing consumed the re-exports: every caller already imports
the submodule it needs directly.

Import what you need from the submodule (`from src.proxy.client import
ProxyClient`, `from src.proxy.config import ProxyMode`).
"""
