from src.target_profiles.base import Confidence, RangeField, TargetProfile

WINDOWS_PROFILE = TargetProfile(
    name="windows",
    source=(
        "Default TTL of 128 as shipped since Windows 2000/XP through "
        "current Windows Server/desktop releases. IP fragment reassembly "
        "timeout historically ~60s (varies by version). Initial TCP "
        "receive window auto-tuned since Vista, commonly 65535+ with "
        "window scaling. SYN-ACK retransmission defaults to 2 retries "
        "(TcpMaxConnectResponseRetransmissions) unless registry-tuned."
    ),
    default_ttl=RangeField(125, 128, Confidence.INFORMATIONAL),
    tcp_initial_window=RangeField(8192, 65535, Confidence.INFORMATIONAL),
    frag_reassembly_timeout_s=RangeField(45, 75, Confidence.INFORMATIONAL),
    syn_ack_retries=RangeField(2, 3, Confidence.INFORMATIONAL),
)
