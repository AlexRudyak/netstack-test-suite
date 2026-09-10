"""Guards the exception hierarchy the entry-point boundary depends on.

`src/cli/main.py` catches `NetstackError` and nothing wider, so that a
deliberate failure becomes a message while a genuine bug keeps its
traceback. That only works while every deliberate failure actually derives
from the base — a new exception class that subclasses `RuntimeError`
directly (which all three of the originals did) would slip straight past
the boundary and print a traceback at the operator.

The census is done over the AST, so it needs no Scapy, no Qt and no DUT.
"""
from __future__ import annotations

import ast

import pytest

from src import errors, paths

pytestmark = [pytest.mark.internal]

# Exception classes defined outside src/errors.py that deliberately do not
# derive from NetstackError, with the reason. Empty today; an entry here is
# a decision, not an oversight.
_EXEMPT: dict[str, str] = {}


def test_every_declared_error_derives_from_the_base() -> None:
    for name in dir(errors):
        obj = getattr(errors, name)
        if isinstance(obj, type) and issubclass(obj, BaseException) and obj is not errors.NetstackError:
            assert issubclass(obj, errors.NetstackError), f"{name} is outside the hierarchy"


def test_every_error_carries_an_exit_code() -> None:
    """The CLI boundary reads `exit_code` off whatever it caught, so a class
    without one would exit with the base's default by accident rather than
    by choice."""
    for name in dir(errors):
        obj = getattr(errors, name)
        if isinstance(obj, type) and issubclass(obj, errors.NetstackError):
            assert isinstance(obj.exit_code, int), f"{name}.exit_code is not an int"
            assert obj.exit_code > 0, f"{name}.exit_code must be non-zero to signal failure"


def _exception_classes_in_src() -> list[tuple[str, str, list[str]]]:
    """(module, class name, base names) for every exception class under src/,
    excluding src/errors.py itself."""
    root = paths.project_root() / "src"
    found = []
    for path in sorted(root.rglob("*.py")):
        if path.name == "errors.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
            bases += [b.attr for b in node.bases if isinstance(b, ast.Attribute)]
            looks_like_an_error = node.name.endswith(("Error", "Exception")) or any(
                base.endswith(("Error", "Exception")) for base in bases
            )
            if looks_like_an_error:
                found.append((str(path.relative_to(root)), node.name, bases))
    return found


def test_no_module_declares_its_own_exception_outside_the_hierarchy() -> None:
    """Exception classes live in src/errors.py.

    Three used to be scattered across src/proxy, src/utils/permissions and
    src/utils/safety, each subclassing RuntimeError directly and sharing no
    base — which is exactly why no caller could catch "everything this
    package raises on purpose".
    """
    offenders = [
        f"{module}:{name} (bases: {bases or ['<none>']})"
        for module, name, bases in _exception_classes_in_src()
        if name not in _EXEMPT
    ]
    assert not offenders, (
        "Declare exception classes in src/errors.py so they share the "
        f"NetstackError base the CLI boundary catches: {offenders}"
    )


def test_the_three_original_names_are_still_importable_where_they_were() -> None:
    """Moving the classes must not move their import sites."""
    from src.proxy.client import ProxyTunnelError as from_client
    from src.proxy.handshakes import ProxyTunnelError as from_handshakes
    from src.utils.permissions import InsufficientPrivilegesError
    from src.utils.safety import UnauthorizedTargetError

    assert from_client is errors.ProxyTunnelError
    assert from_handshakes is errors.ProxyTunnelError
    assert InsufficientPrivilegesError is errors.InsufficientPrivilegesError
    assert UnauthorizedTargetError is errors.UnauthorizedTargetError


def test_proxy_tunnel_error_still_carries_details() -> None:
    """The conformance tests read `.details` to assert the DUT refused with
    a defined code rather than merely raising."""
    reply = object()
    exc = errors.ProxyTunnelError("refused", reply)

    assert exc.details is reply
    assert errors.ProxyTunnelError("nothing reported").details is None
