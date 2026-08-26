from src.target_profiles.base import Confidence, RangeField, TargetProfile

LINUX_PROFILE = TargetProfile(
    name="linux",
    source=(
        "Default TTL (net.ipv4.ip_default_ttl=64), fragment reassembly "
        "timeout (net.ipv4.ipfrag_time=30s), and initial TCP window "
        "(tcp_rmem/tcp_wmem defaults, autotuned) as shipped by mainline "
        "Linux kernels. tcp_syn_retries default is 6 (kernel counts an "
        "initial send + 6 retries)."
    ),
    default_ttl=RangeField(60, 64, Confidence.INFORMATIONAL),
    tcp_initial_window=RangeField(14600, 65535, Confidence.INFORMATIONAL),
    frag_reassembly_timeout_s=RangeField(25, 35, Confidence.INFORMATIONAL),
    syn_ack_retries=RangeField(4, 6, Confidence.INFORMATIONAL),
)
