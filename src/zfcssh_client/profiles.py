PROFILE_TTLS = {
    "development": "12h",
    "zf_production": "4h",
    "oem_production": "4h",
    "field_operation": "8h",
    "claims_warranty": "2h",
    "end_of_life": "1h",
}


def default_ttl_for_profile(profile: str) -> str | None:
    return PROFILE_TTLS.get(profile)
