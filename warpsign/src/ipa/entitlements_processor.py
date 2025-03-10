from dataclasses import dataclass
from typing import Dict, List, Set
import json
from warpsign.logger import get_console


@dataclass
class Capability:
    """Represents an App Store capability"""

    id: str  # App Store Connect capability ID (e.g. "USERNOTIFICATIONS_COMMUNICATION")
    name: str  # Human readable name
    profile_keys: List[str]  # Associated entitlement keys
    description: str  # Human readable description


class EntitlementsProcessor:
    """Process entitlements and determine which capabilities to enable/remove"""

    def __init__(self, capabilities_data_or_path, profile_type: str = "development"):
        """Initialize with API data or path to capabilities.json"""
        self.console = get_console()
        self.capabilities: Dict[str, Capability] = {}  # entitlement key -> capability
        self.profile_type = profile_type.lower()

        if self.profile_type not in ["development", "adhoc"]:
            raise ValueError("Profile type must be either 'development' or 'adhoc'")

        # Accept either JSON path or raw data
        if isinstance(capabilities_data_or_path, str):
            with open(capabilities_data_or_path) as f:
                data = json.load(f)
        else:
            data = capabilities_data_or_path

        self._load_capabilities(data)

    def _extract_profile_keys(self, capability_data: dict) -> List[str]:
        """Recursively extract all profile keys from a capability's data"""
        profile_keys = []

        # Check direct entitlements
        for entitlement in capability_data.get("attributes", {}).get(
            "entitlements", []
        ):
            if profile_key := entitlement.get("profileKey"):
                profile_keys.append(profile_key)

        # Check settings and their options
        for setting in capability_data.get("attributes", {}).get("settings", []):
            # Check each option's entitlements
            for option in setting.get("options", []):
                for entitlement in option.get("entitlements", []):
                    if profile_key := entitlement.get("profileKey"):
                        profile_keys.append(profile_key)

        return profile_keys

    def _load_capabilities(self, data: dict) -> None:
        """Load and parse capabilities mapping"""
        # Build reverse mapping of entitlement keys to capabilities
        for capability in data["data"]:
            cap_id = capability["id"]
            attributes = capability["attributes"]

            # Only include iOS capabilities that support our profile type
            supports_ios = any(
                sdk.get("displayValue") == "iOS"
                for sdk in attributes.get("supportedSDKs", [])
            )

            # Check if capability supports our profile type
            supports_profile_type = any(
                (
                    self.profile_type == "development"
                    and dist.get("displayValue") == "Development"
                )
                or (
                    self.profile_type == "adhoc"
                    and dist.get("displayValue") == "Ad hoc"
                )
                for dist in attributes.get("distributionTypes", [])
            )

            if supports_ios and supports_profile_type:
                # Extract all profile keys for this capability
                profile_keys = self._extract_profile_keys(capability)

                if profile_keys:
                    # Map each profile key to this capability
                    for key in profile_keys:
                        self.capabilities[key] = Capability(
                            id=cap_id,
                            name=attributes.get("name", ""),
                            profile_keys=profile_keys,
                            description=attributes.get("description", ""),
                        )

    def process_entitlements(self, entitlements: Dict) -> tuple[Set[str], Set[str]]:
        """Process entitlements and return (capabilities_to_enable, entitlements_to_remove)"""
        capabilities_to_enable = set()
        entitlements_to_remove = set()

        # Core identifiers that should never be removed but still need remapping
        core_identifiers = {
            "application-identifier",
            "com.apple.developer.team-identifier",
            "keychain-access-groups",
        }

        # List of entitlements that should always be removed
        banned_entitlements = {
            "com.apple.developer.in-app-payments",
        }

        # Always remove banned entitlements
        for banned in banned_entitlements:
            if banned in entitlements:
                entitlements_to_remove.add(banned)

        # Examine each entitlement
        for key, value in entitlements.items():
            if key in core_identifiers:
                continue

            if capability := self.capabilities.get(key):
                capabilities_to_enable.add(capability.id)
            elif key not in banned_entitlements:  # Don't log banned entitlements
                entitlements_to_remove.add(key)

        return capabilities_to_enable, entitlements_to_remove
