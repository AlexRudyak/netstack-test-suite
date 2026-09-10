from src.errors import ConfigurationError
from src.target_profiles.base import TargetProfile
from src.target_profiles.linux_profile import LINUX_PROFILE
from src.target_profiles.windows_profile import WINDOWS_PROFILE

_PROFILES: dict[str, TargetProfile] = {
    LINUX_PROFILE.name: LINUX_PROFILE,
    WINDOWS_PROFILE.name: WINDOWS_PROFILE,
}


def get_profile(name: str) -> TargetProfile:
    """The behavioral baseline to assert against, by `--target-stack` name.

    Raises ConfigurationError, not a bare ValueError: an unknown stack name
    is operator input, and this was the one lookup left outside the
    hierarchy after src/errors.py was introduced — its sibling,
    `platform_backend.get_backend`, already raises UnsupportedHostError.
    Both front ends constrain the choice, so this is reached when pytest is
    driven directly, where the message is all the operator gets.
    """
    try:
        return _PROFILES[name.lower()]
    except KeyError as exc:
        valid = ", ".join(sorted(_PROFILES))
        raise ConfigurationError(
            f"Unknown target stack {name!r}. Valid options: {valid}"
        ) from exc


def list_profiles() -> list[str]:
    return sorted(_PROFILES)
