from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, Optional, List, Tuple
import random
import string
from logger import get_console


class IDType(Enum):
    ICLOUD = auto()
    KEYCHAIN = auto()
    APP_GROUP = auto()
    BUNDLE = auto()


@dataclass
class IDMapping:
    original_id: str
    new_id: str
    id_type: IDType


class BundleMapping:
    def __init__(
        self,
        original_team_ids: List[
            str
        ],  # Changed from original_team_id to original_team_ids
        new_team_id: str,
        original_base_id: str,
        randomize: bool = True,
    ):
        self.console = get_console()
        self.team_id = new_team_id
        self.original_team_ids = original_team_ids  # Store all original team IDs
        self.original_main_bundle_id = original_base_id
        self.encode_ids = randomize
        self.mappings: Dict[str, IDMapping] = {}
        self.id_type_cache: Dict[str, IDType] = {}  # Cache for ID types
        self.force_original_id = False  # Track if we're using original IDs

        # Initialize main_bundle_id without using map_id
        if self.encode_ids:
            self.main_bundle_id = self.gen_random_id(original_base_id)
        else:
            self.main_bundle_id = original_base_id

        # Store the initial mapping
        self._store_mapping(original_base_id, self.main_bundle_id, IDType.BUNDLE)

    def _store_mapping(self, original_id: str, new_id: str, id_type: IDType) -> None:
        """Store mapping and cache ID type"""
        self.mappings[original_id] = IDMapping(original_id, new_id, id_type)
        self.id_type_cache[original_id] = id_type

    def detect_id_type(self, id_str: str, entitlements: Dict = None) -> IDType:
        """Determine the type of identifier with caching"""
        if id_str in self.id_type_cache:
            return self.id_type_cache[id_str]

        # Check if this ID is in keychain access groups entitlement
        if entitlements and "keychain-access-groups" in entitlements:
            keychain_groups = entitlements["keychain-access-groups"]
            if isinstance(keychain_groups, list) and id_str in keychain_groups:
                self.id_type_cache[id_str] = IDType.KEYCHAIN
                return IDType.KEYCHAIN

        # Standard prefix checks
        if id_str.startswith("iCloud.") or "icloud" in id_str.lower():
            id_type = IDType.ICLOUD
        elif id_str.startswith("group.") or "application-groups" in id_str:
            id_type = IDType.APP_GROUP
        else:
            id_type = IDType.BUNDLE

        self.id_type_cache[id_str] = id_type
        return id_type

    def gen_random_id(self, original_id: str) -> str:
        """Generate random ID maintaining exact length of each part"""
        if not self.encode_ids:
            return original_id

        parts = original_id.split(".")
        new_parts = []
        for part in parts:
            new_part = "".join(
                random.Random(part + self.team_id).choices(
                    string.ascii_lowercase + string.digits, k=len(part)
                )
            )
            new_parts.append(new_part)

        return ".".join(new_parts)

    def _handle_bundle_id(self, original_id: str) -> str:
        """Handle bundle ID generation with proper team ID and length preservation"""
        new_id = original_id

        # Check if ID starts with any known team ID
        if any(original_id.startswith(team_id) for team_id in self.original_team_ids):
            for orig_team_id in self.original_team_ids:
                if original_id.startswith(orig_team_id):
                    new_id = f"{self.team_id}{original_id[len(orig_team_id):]}"
                    break
        else:
            # Check if this is a component bundle ID
            if original_id.startswith(self.original_main_bundle_id):
                base_len = len(self.original_main_bundle_id)
                suffix = original_id[base_len:]  # Keep the dot if present
                new_id = f"{self.main_bundle_id}{suffix}"
            else:
                new_id = self.gen_random_id(original_id)

        # Ensure length preservation
        if len(new_id) != len(original_id):
            self.console.print(
                f"[yellow]Warning: Bundle ID length mismatch: {original_id} -> {new_id}"
            )
            if len(new_id) < len(original_id):
                new_id = new_id.ljust(len(original_id), "x")
            else:
                new_id = new_id[: len(original_id)]

        return new_id

    def map_id(self, original_id: str, id_type: IDType) -> str:
        """Map an ID based on its type"""
        # Special case: never remap com.apple.token
        if original_id == "com.apple.token":
            return original_id

        if not original_id or not self.encode_ids:
            return original_id

        # Return cached mapping if exists
        if original_id in self.mappings:
            return self.mappings[original_id].new_id

        new_id = original_id

        if id_type == IDType.ICLOUD:
            base_id = original_id.replace("iCloud.", "")
            new_base = self.gen_random_id(base_id)
            new_id = f"iCloud.{new_base}"

        elif id_type == IDType.KEYCHAIN:
            # Check against all possible original team IDs
            matched = False
            for orig_team_id in self.original_team_ids:
                if original_id.startswith(orig_team_id):
                    new_id = f"{self.team_id}{original_id[len(orig_team_id):]}"
                    matched = True
                    break
            if not matched:
                new_id = f"{self.team_id}.{original_id}"

        elif id_type == IDType.APP_GROUP:
            base_id = original_id.replace("group.", "")
            for orig_team_id in self.original_team_ids:
                if base_id.startswith(orig_team_id):
                    remaining = base_id[len(orig_team_id) :]
                    new_id = f"group.{self.team_id}{remaining}"
                    break
            else:
                new_base = self.gen_random_id(base_id)
                new_id = f"group.{new_base}"

        elif id_type == IDType.BUNDLE:
            new_id = self._handle_bundle_id(original_id)

        # Store mapping
        self._store_mapping(original_id, new_id, id_type)
        return new_id

    def map_bundle_id(self, original_id: str) -> str:
        """Public method to map any bundle identifier"""
        id_type = self.detect_id_type(original_id)
        return self.map_id(original_id, id_type)

    def map_entitlements(
        self,
        entitlements: Dict,
        override_bundle_id: Optional[str] = None,
    ) -> Dict:
        """
        Map entitlements with type-specific handling.
        override_bundle_id: If provided, this bundle ID will be used for application-identifier
        """
        result = entitlements.copy()

        # Application identifier - always use the override if provided
        if "application-identifier" in result:
            if override_bundle_id:
                # Always use the provided bundle ID (from Info.plist)
                result["application-identifier"] = (
                    f"{self.team_id}.{override_bundle_id}"
                )
            else:
                # Fallback to normal mapping
                bundle_id = result["application-identifier"].split(".", 1)[1]
                new_bundle_id = self.map_id(bundle_id, IDType.BUNDLE)
                result["application-identifier"] = f"{self.team_id}.{new_bundle_id}"

        # Team identifier
        result["com.apple.developer.team-identifier"] = self.team_id

        # Map aps-environment based on profile type
        if "aps-environment" in result:
            result["aps-environment"] = (
                "development" if self.profile_type == "development" else "production"
            )

        # Keychain groups
        if "keychain-access-groups" in result:
            groups = result["keychain-access-groups"]
            if isinstance(groups, list):
                result["keychain-access-groups"] = [
                    self.map_id(g, self.detect_id_type(g, entitlements)) for g in groups
                ]

        # App groups - always remap
        for key in ["com.apple.security.application-groups", "application-groups"]:
            if key in result:
                groups = result[key] if isinstance(result[key], list) else [result[key]]
                result[key] = [self.map_id(g, IDType.APP_GROUP) for g in groups]

        # iCloud containers - always remap
        for key in [
            "com.apple.developer.icloud-container-identifiers",
            "com.apple.developer.ubiquity-container-identifiers",
            "com.apple.developer.icloud-container-development-container-identifiers",
        ]:
            if key in result:
                containers = (
                    result[key] if isinstance(result[key], list) else [result[key]]
                )
                result[key] = [self.map_id(c, IDType.ICLOUD) for c in containers]

        # Handle ubiquity-kvstore-identifier, optionally using original IDs.
        if "com.apple.developer.ubiquity-kvstore-identifier" in result:
            kvstore_id = result["com.apple.developer.ubiquity-kvstore-identifier"]
            # Check if it's in format "TEAMID.x" where x is any single character
            parts = kvstore_id.split(".")
            if len(parts) == 2 and len(parts[1]) == 1:
                # It's a short format with single character - just replace team ID
                suffix = parts[1]
                result["com.apple.developer.ubiquity-kvstore-identifier"] = (
                    f"{self.team_id}.{suffix}"
                )
            elif "." in kvstore_id:  # If it's a full bundle ID format
                bundle_id = kvstore_id.split(".", 1)[1]
                new_bundle_id = self.map_id(bundle_id, IDType.BUNDLE)
                result["com.apple.developer.ubiquity-kvstore-identifier"] = (
                    f"{self.team_id}.{new_bundle_id}"
                )

        return result

    def get_binary_patches(self) -> Dict[str, str]:
        """Get all mappings that need binary patching"""
        patches = {}
        seen_values = set()

        # Always include team ID replacements first (longer IDs first)
        sorted_team_ids = sorted(self.original_team_ids, key=len, reverse=True)
        for orig_team_id in sorted_team_ids:
            if len(orig_team_id) == len(self.team_id):
                patches[orig_team_id] = self.team_id

        # Then add other registered identifier mappings
        if hasattr(self, "registered_identifiers"):
            for k, v in self.mappings.items():
                if k in self.registered_identifiers and len(k) == len(v.new_id):
                    # Skip main bundle ID mapping if we're using original IDs
                    if self.force_original_id and k == self.original_main_bundle_id:
                        continue
                    if v.new_id not in seen_values:
                        patches[k] = v.new_id
                        seen_values.add(v.new_id)

        # Don't include main bundle ID if force_original_id is True
        if self.force_original_id:
            patches.pop(self.original_main_bundle_id, None)

        return patches
