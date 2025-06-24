# tools/androguard/androguard_wrapper.py

try:
    # For older versions (androguard ≤3.x)
    from androguard.core.bytecodes.apk import APK
except ModuleNotFoundError:
    # For newer versions (androguard ≥4.x)
    from androguard.core.apk import APK


def extract_manifest_info(apk_path: str) -> dict:
    """
    Parses APK and returns key manifest and security-relevant data.
    """
    a = APK(apk_path)
    return {
        "package": a.package,
        "permissions": a.get_permissions(),
        "activities": a.get_activities(),
        "services": a.get_services(),
        "receivers": a.get_receivers(),
        "providers": a.get_providers(),
        "main_activity": a.get_main_activity(),
        "target_sdk_version": a.get_target_sdk_version(),
        "min_sdk_version": a.get_min_sdk_version(),
    }
