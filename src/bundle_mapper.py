from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, Optional, List, Tuple, Set
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
        original_team_ids: List[str],
        new_team_id: str,
        original_base_id: str,
        randomize: bool = True,
    ):
        self.console = get_console()
        self.team_id = new_team_id
        self.original_team_ids = original_team_ids
        self.original_main_bundle_id = original_base_id
        self.encode_ids = randomize
        self.mappings: Dict[str, IDMapping] = {}
        self.id_type_cache: Dict[str, IDType] = {}  # Cache for ID types
        self.force_original_id = False  # Track if we're using original IDs
        # Cache for random ID generation to avoid duplicating work
        self.random_id_cache: Dict[str, str] = {}
        # Set to store registered identifiers
        self.registered_identifiers: Set[str] = set()
        # Default profile type
        self.profile_type = "development"

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

    def _get_team_id_match(self, id_str: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Check if id_str starts with any team ID and return the matching team ID and remaining part
        Returns: (matching_team_id, remaining_part) or (None, None) if no match
        """
        for orig_team_id in self.original_team_ids:
            if id_str.startswith(orig_team_id):
                return orig_team_id, id_str[len(orig_team_id) :]
        return None, None

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

        # Check if this appears in iCloud container entitlements
        if entitlements:
            for icloud_key in [
                "com.apple.developer.icloud-container-identifiers",
                "com.apple.developer.ubiquity-container-identifiers",
                "com.apple.developer.icloud-container-development-container-identifiers",
            ]:
                if icloud_key in entitlements:
                    containers = entitlements[icloud_key]
                    if isinstance(containers, list) and id_str in containers:
                        self.id_type_cache[id_str] = IDType.ICLOUD
                        return IDType.ICLOUD

        # Standard prefix checks
        if id_str.startswith("iCloud."):
            id_type = IDType.ICLOUD
        elif "icloud" in id_str.lower():
            id_type = IDType.ICLOUD
        elif id_str.startswith("group."):
            id_type = IDType.APP_GROUP
        elif "application-groups" in id_str:
            id_type = IDType.APP_GROUP
        else:
            id_type = IDType.BUNDLE

        self.id_type_cache[id_str] = id_type
        return id_type

    def gen_random_id(self, original_id: str) -> str:
        """Generate random ID maintaining exact length of each part with caching"""
        if not self.encode_ids:
            return original_id

        # Check cache first
        cache_key = f"{original_id}:{self.team_id}"
        if cache_key in self.random_id_cache:
            return self.random_id_cache[cache_key]

        parts = original_id.split(".")
        new_parts = []
        for part in parts:
            new_part = "".join(
                random.Random(part + self.team_id).choices(
                    string.ascii_lowercase + string.digits, k=len(part)
                )
            )
            new_parts.append(new_part)

        result = ".".join(new_parts)
        # Cache the result for future use
        self.random_id_cache[cache_key] = result
        return result

    def _process_list_entitlement(
        self, entitlements: Dict, key: str, id_type: IDType
    ) -> None:
        """Process a list-type entitlement by mapping each value"""
        if key in entitlements:
            values = (
                entitlements[key]
                if isinstance(entitlements[key], list)
                else [entitlements[key]]
            )
            entitlements[key] = [self.map_id(v, id_type) for v in values]

    def _handle_bundle_id(self, original_id: str) -> str:
        """Handle bundle ID generation with proper team ID and length preservation"""
        # Check if ID starts with any known team ID
        team_id, remaining = self._get_team_id_match(original_id)
        if team_id:
            new_id = f"{self.team_id}{remaining}"
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
            # Generate a proper iCloud container ID
            if original_id.startswith("iCloud."):
                base_id = original_id.replace("iCloud.", "")
            else:
                # Check if starts with team ID
                team_id, remaining = self._get_team_id_match(original_id)
                if team_id:
                    base_id = remaining[1:]  # +1 for the dot
                else:
                    base_id = original_id

            # Generate random ID for the base part while preserving structure
            new_base = self.gen_random_id(base_id)

            # Always ensure iCloud container IDs start with iCloud.
            new_id = f"iCloud.{new_base}"

        elif id_type == IDType.KEYCHAIN:
            # Check against all possible original team IDs
            team_id, remaining = self._get_team_id_match(original_id)
            if team_id:
                new_id = f"{self.team_id}{remaining}"
            else:
                new_id = f"{self.team_id}.{original_id}"

        elif id_type == IDType.APP_GROUP:
            base_id = original_id.replace("group.", "")
            team_id, remaining = self._get_team_id_match(base_id)
            if team_id:
                new_id = f"group.{self.team_id}{remaining}"
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

        # Process list-type entitlements with consistent logic
        self._process_list_entitlement(
            result, "keychain-access-groups", IDType.KEYCHAIN
        )
        self._process_list_entitlement(
            result, "com.apple.security.application-groups", IDType.APP_GROUP
        )
        self._process_list_entitlement(result, "application-groups", IDType.APP_GROUP)

        # Process iCloud container entitlements
        for key in [
            "com.apple.developer.icloud-container-identifiers",
            "com.apple.developer.ubiquity-container-identifiers",
            "com.apple.developer.icloud-container-development-container-identifiers",
        ]:
            self._process_list_entitlement(result, key, IDType.ICLOUD)

        # Handle ubiquity-kvstore-identifier
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

        # Then add registered identifier mappings
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

    def extract_resources_from_entitlements(self, entitlements):
        """
        Extract and map app groups and iCloud containers from entitlements

        Returns:
            Tuple[set, set]: (app_groups, icloud_containers)
        """
        app_groups = set()
        icloud_containers = set()

        # Extract app groups
        if "com.apple.security.application-groups" in entitlements:
            groups = entitlements["com.apple.security.application-groups"]
            if isinstance(groups, list):
                for group in groups:
                    mapped_group = self.map_bundle_id(group)
                    app_groups.add(mapped_group)

        # Extract iCloud containers
        for key in [
            "com.apple.developer.icloud-container-identifiers",
            "com.apple.developer.ubiquity-container-identifiers",
            "com.apple.developer.icloud-container-development-container-identifiers",
        ]:
            if key in entitlements:
                containers = entitlements[key]
                if isinstance(containers, list):
                    for container in containers:
                        # Set the ID type explicitly to ICLOUD to ensure proper mapping
                        self.id_type_cache[container] = IDType.ICLOUD
                        mapped_container = self.map_id(container, IDType.ICLOUD)
                        icloud_containers.add(mapped_container)

        return app_groups, icloud_containers
