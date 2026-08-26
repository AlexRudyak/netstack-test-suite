from src.target_profiles.base import TargetProfile
from src.target_profiles.linux_profile import LINUX_PROFILE
from src.target_profiles.windows_profile import WINDOWS_PROFILE

_PROFILES: dict[str, TargetProfile] = {
    LINUX_PROFILE.name: LINUX_PROFILE,
    WINDOWS_PROFILE.name: WINDOWS_PROFILE,
}


def get_profile(name: str) -> TargetProfile:
    try:
        return _PROFILES[name.lower()]
    except KeyError as exc:
        valid = ", ".join(sorted(_PROFILES))
        raise ValueError(f"Unknown target stack {name!r}. Valid options: {valid}") from exc


def list_profiles() -> list[str]:
    return sorted(_PROFILES)
