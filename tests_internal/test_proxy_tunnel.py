"""Wire-format tests for the proxy tunnel handshakes.

These assert the exact bytes the RFCs specify, so a regression in the
encoders/parsers is caught without a proxy, a socket, or a DUT:

- SOCKS5: RFC 1928 §3 (greeting/method selection), §4 (request), §6 (reply)
- SOCKS5 user/pass auth: RFC 1929 §2
- HTTP CONNECT: RFC 9110 §9.3.6, RFC 9112 §3.2.3
"""
from __future__ import annotations

import io

import pytest

from src.errors import ConfigurationError, ProtocolViolation
from src.proxy import tunnel

pytestmark = [pytest.mark.internal]


# --- SOCKS5 (RFC 1928) ------------------------------------------------------


def test_socks5_greeting_bytes_match_rfc1928() -> None:
    # VER=0x05, NMETHODS=0x01, METHODS=[0x00 no-auth]
    assert tunnel.build_socks5_greeting([tunnel.AUTH_NONE]) == b"\x05\x01\x00"
    # Offering no-auth and username/password
    assert tunnel.build_socks5_greeting(
        [tunnel.AUTH_NONE, tunnel.AUTH_USERNAME_PASSWORD]
    ) == b"\x05\x02\x00\x02"


def test_socks5_greeting_rejects_out_of_range_method_counts() -> None:
    """An encoder input error, not something the DUT sent — so it is a
    ConfigurationError, distinct from the ProtocolViolation the parsers
    raise for the peer's bytes."""
    with pytest.raises(ConfigurationError):
        tunnel.build_socks5_greeting([])
    with pytest.raises(ConfigurationError):
        tunnel.build_socks5_greeting([0x00] * 256)


def test_socks5_method_selection_parsing() -> None:
    assert tunnel.parse_socks5_method_selection(b"\x05\x00") == tunnel.AUTH_NONE
    assert tunnel.parse_socks5_method_selection(b"\x05\xff") == tunnel.AUTH_NO_ACCEPTABLE
    with pytest.raises(ValueError, match="0x05"):
        tunnel.parse_socks5_method_selection(b"\x04\x00")  # wrong version
    with pytest.raises(ValueError):
        tunnel.parse_socks5_method_selection(b"\x05")  # short


def test_socks5_connect_request_ipv4() -> None:
    # VER CMD RSV ATYP=IPv4 | 127.0.0.1 | port 80 (network byte order)
    assert tunnel.build_socks5_request("127.0.0.1", 80) == (
        b"\x05\x01\x00\x01" + b"\x7f\x00\x00\x01" + b"\x00\x50"
    )


def test_socks5_connect_request_domain_is_length_prefixed() -> None:
    request = tunnel.build_socks5_request("example.com", 443)
    assert request == (
        b"\x05\x01\x00\x03" + bytes([len("example.com")]) + b"example.com" + b"\x01\xbb"
    )


def test_socks5_connect_request_ipv6() -> None:
    request = tunnel.build_socks5_request("::1", 8080)
    assert request[:4] == b"\x05\x01\x00\x04"
    assert request[4:20] == b"\x00" * 15 + b"\x01"  # ::1 packed
    assert request[20:] == (8080).to_bytes(2, "big")


def test_socks5_udp_associate_command_byte() -> None:
    request = tunnel.build_socks5_request("127.0.0.1", 0, tunnel.CMD_UDP_ASSOCIATE)
    assert request[1] == tunnel.CMD_UDP_ASSOCIATE == 0x03


def test_socks5_reply_success_ipv4() -> None:
    raw = io.BytesIO(b"\x05\x00\x00\x01" + b"\x0a\x00\x00\x05" + b"\x1f\x90")
    reply = tunnel.read_socks5_reply(lambda n: raw.read(n))
    assert reply.succeeded
    assert reply.bound_host == "10.0.0.5"
    assert reply.bound_port == 8080


def test_socks5_reply_failure_codes_are_described() -> None:
    raw = io.BytesIO(b"\x05\x05\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
    reply = tunnel.read_socks5_reply(lambda n: raw.read(n))
    assert not reply.succeeded
    assert reply.reply_code == 0x05
    assert reply.message == "connection refused"


def test_socks5_reply_with_domain_bound_address() -> None:
    payload = b"\x05\x00\x00\x03" + bytes([3]) + b"abc" + b"\x00\x50"
    raw = io.BytesIO(payload)
    reply = tunnel.read_socks5_reply(lambda n: raw.read(n))
    assert reply.bound_host == "abc"
    assert reply.bound_port == 80


def test_socks5_reply_rejects_bad_version_and_atyp() -> None:
    bad_version = io.BytesIO(b"\x04\x00\x00\x01" + b"\x00" * 6)
    with pytest.raises(ValueError, match="0x05"):
        tunnel.read_socks5_reply(lambda n: bad_version.read(n))

    bad_atyp = io.BytesIO(b"\x05\x00\x00\x09" + b"\x00" * 6)
    with pytest.raises(ValueError, match="address type"):
        tunnel.read_socks5_reply(lambda n: bad_atyp.read(n))


def test_socks5_userpass_auth_uses_subnegotiation_version_1() -> None:
    # RFC 1929 §2: VER here is 0x01, *not* the SOCKS version 0x05.
    assert tunnel.build_socks5_userpass_auth("user", "pw") == (
        b"\x01" + bytes([4]) + b"user" + bytes([2]) + b"pw"
    )
    assert tunnel.parse_socks5_userpass_result(b"\x01\x00") is True
    assert tunnel.parse_socks5_userpass_result(b"\x01\x01") is False


# --- HTTP CONNECT (RFC 9110 §9.3.6, RFC 9112) -------------------------------


def test_http_connect_request_uses_authority_form_with_host_header() -> None:
    assert tunnel.build_http_connect_request("example.com", 443) == (
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    )


def test_http_connect_request_brackets_ipv6_authority() -> None:
    request = tunnel.build_http_connect_request("::1", 8080).decode()
    assert request.startswith("CONNECT [::1]:8080 HTTP/1.1\r\n")
    assert "Host: [::1]:8080\r\n" in request


def test_http_connect_any_2xx_establishes_the_tunnel() -> None:
    for status in (200, 201, 299):
        response = tunnel.parse_http_connect_response(
            f"HTTP/1.1 {status} Connection Established\r\n\r\n".encode()
        )
        assert response.tunnel_established, status


def test_http_connect_non_2xx_does_not_establish() -> None:
    response = tunnel.parse_http_connect_response(
        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"
    )
    assert not response.tunnel_established
    assert response.status == 407
    assert response.headers["proxy-authenticate"] == "Basic"


def test_http_connect_rejects_malformed_status_line() -> None:
    with pytest.raises(ValueError, match="malformed"):
        tunnel.parse_http_connect_response(b"NOT-HTTP 200 OK\r\n\r\n")
    with pytest.raises(ValueError, match="non-numeric"):
        tunnel.parse_http_connect_response(b"HTTP/1.1 TWOHUNDRED OK\r\n\r\n")


def test_read_http_response_head_stops_at_blank_line() -> None:
    """The tunnel becomes opaque right after the header block, so the reader
    must not consume relayed payload bytes."""
    stream = io.BytesIO(b"HTTP/1.1 200 OK\r\n\r\nRELAYED-PAYLOAD")
    head = tunnel.read_http_response_head(lambda n: stream.read(n))
    assert head == b"HTTP/1.1 200 OK\r\n\r\n"
    assert stream.read() == b"RELAYED-PAYLOAD"  # untouched


def test_read_http_response_head_raises_on_early_close() -> None:
    stream = io.BytesIO(b"HTTP/1.1 200 OK\r\n")
    with pytest.raises(ConnectionError):
        tunnel.read_http_response_head(lambda n: stream.read(n))


# --- Who was wrong: us, or the DUT? ---------------------------------------
# Every parse failure here describes bytes the DUT sent, which is a test
# result. Every encode failure describes our own input. Raised as bare
# ValueErrors they were indistinguishable, so tests/proxy/ could not assert
# "the DUT violated RFC 1928" apart from "our parser crashed".


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda: tunnel.parse_http_connect_response(b""), id="empty-http"),
        pytest.param(
            lambda: tunnel.parse_http_connect_response(b"NOTHTTP 200 OK\r\n\r\n"),
            id="bad-status-line",
        ),
        pytest.param(
            lambda: tunnel.parse_http_connect_response(b"HTTP/1.1 2O0 OK\r\n\r\n"),
            id="non-numeric-status",
        ),
        pytest.param(
            lambda: tunnel.parse_socks5_method_selection(b"\x04\x00"), id="wrong-socks-version"
        ),
        pytest.param(
            lambda: tunnel.parse_socks5_method_selection(b"\x05"), id="short-method-selection"
        ),
        pytest.param(
            lambda: tunnel.parse_socks5_userpass_result(b"\x01"), id="short-auth-result"
        ),
    ],
)
def test_the_dut_s_bad_bytes_are_a_protocol_violation(call) -> None:
    with pytest.raises(ProtocolViolation):
        call()


def test_a_protocol_violation_is_still_a_value_error() -> None:
    """Existing handlers catch ValueError around these calls."""
    with pytest.raises(ValueError):
        tunnel.parse_socks5_method_selection(b"\x04\x00")


def test_our_own_bad_input_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError):
        tunnel.build_socks5_userpass_auth("", "secret")
    with pytest.raises(ConfigurationError):
        tunnel.encode_socks5_address("x" * 300, 80)


def test_a_truncated_socks5_domain_reply_is_not_an_index_error() -> None:
    """`read` is contracted to raise on a short read; a reader returning b""
    instead made this an IndexError no caller expects."""
    reads = iter([b"\x05\x00\x00\x03", b""])

    with pytest.raises(ConnectionError, match="domain length byte"):
        tunnel.read_socks5_reply(lambda n: next(reads))
