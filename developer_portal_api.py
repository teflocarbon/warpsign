import json
import requests
from typing import List, Dict, Optional, Union
from dataclasses import dataclass
from rich.table import Table
import os
from logger import get_console

console = get_console()

# Default settings for capabilities that require specific configurations
CAPABILITY_SETTINGS = {
    "ENABLED_FOR_MAC": [
        {"key": "ENABLED_FOR_MAC_APP_SETUP", "options": [{"key": "USE_IOS_APPID"}]}
    ],
    "PUSH_NOTIFICATIONS": [
        {
            "key": "PUSH_NOTIFICATION_FEATURES",
            "options": [{"key": "PUSH_NOTIFICATION_FEATURE_BROADCAST"}],
        }
    ],
    "APPLE_ID_AUTH": [
        {
            "key": "APPLE_ID_AUTH_APP_CONSENT",
            "options": [{"key": "PRIMARY_APP_CONSENT"}],
        }
    ],
    "DATA_PROTECTION": [
        {
            "key": "DATA_PROTECTION_PERMISSION_LEVEL",
            "options": [{"key": "COMPLETE_PROTECTION"}],
        }
    ],
    "ICLOUD": [{"key": "ICLOUD_VERSION", "options": [{"key": "XCODE_6"}]}],
}

# Capabilities that need additional relationship data
RELATIONSHIP_CAPABILITIES = {
    "ICLOUD": "cloudContainers",
    "APP_GROUPS": "appGroups",
}


@dataclass
class Team:
    team_id: str
    name: str
    status: str
    type: str
    roles: List[str]


@dataclass
class Certificate:
    id: str
    serial_number: str
    owner_id: str
    certificate_type: str
    name: str


@dataclass
class BundleId:
    id: str
    identifier: str
    name: str


@dataclass
class AppGroup:
    id: str  # applicationGroup in the response
    identifier: str
    name: str


@dataclass
class ICloudContainer:
    id: str
    identifier: str
    name: str


@dataclass
class Device:
    id: str
    name: str
    udid: str
    status: str
    device_class: str
    platform: str
    model: Optional[str]


@dataclass
class Profile:
    id: str
    profile_state: str
    name: str
    platform: str
    profile_type_label: str


@dataclass
class Entitlement:
    key: str
    name: str
    description: str
    value_type: str
    profile_key: str
    values: dict  # Keep raw JSON values


@dataclass
class Capability:
    id: str
    description: str
    optional: bool
    name: str
    entitlements: List[Entitlement]


@dataclass
class EntitlementValue:
    name: str


@dataclass
class AvailableEntitlement:
    id: str
    name: str
    description: str
    value_type: str
    profile_key: str
    supports_wildcard: bool
    values: dict
    distribution_types: List[EntitlementValue]
    is_required: bool = False  # Add field for isRequiredInPlist


@dataclass
class AvailableCapability:
    id: str
    name: str
    optional: bool
    description: str
    editable: bool
    supports_wildcard: bool
    entitlements: List[AvailableEntitlement]
    settings: Optional[list] = None  # Add settings field


class DeveloperPortalAPI:
    """Apple Developer Portal API client"""

    def __init__(self, auth_instance):
        """Initialize with an authenticated session"""
        self.auth = auth_instance
        self.session = auth_instance.session
        self.csrf = auth_instance.csrf
        self.csrf_ts = auth_instance.csrf_ts
        # Add default headers for all requests
        self.default_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Content-Type": "application/vnd.api+json",
            "X-Requested-With": "XMLHttpRequest",
            "X-HTTP-Method-Override": "GET",
        }
        self._entitlements_cache = {}  # Add cache for entitlements

    def list_teams(self) -> List[Team]:
        """List all teams the authenticated user has access to"""
        console.print("[blue]Fetching teams from Developer Portal...")

        # Teams endpoint needs different headers
        headers = {
            "Accept": "application/json, text/javascript",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }

        response = self.session.post(
            "https://developer.apple.com/services-account/QH65B2/account/getTeams",
            json={"includeInMigrationTeams": 1},
            headers=headers,
        )

        if response.status_code != 200:
            console.print(f"[red]Failed to fetch teams: {response.status_code}")
            return []

        data = response.json()
        if data.get("resultCode") != 0:
            console.print(f"[red]API error: {data}")
            return []

        teams = []
        for team in data.get("teams", []):
            teams.append(
                Team(
                    team_id=team["teamId"],
                    name=team["name"],
                    status=team["status"],
                    type=team["entityType"],
                    roles=team.get("userRoles", []),
                )
            )

        console.print(f"[green]Found {len(teams)} teams")
        return teams

    def list_certificates(self, team_id: str) -> List[Certificate]:
        """List all certificates for a team"""
        console.print(f"[blue]Fetching certificates for team {team_id}...")

        url = "https://developer.apple.com/services-account/v1/certificates"
        payload = {
            "urlEncodedQueryParams": "limit=1000&sort=displayName",
            "teamId": team_id,
        }
        headers = self.default_headers.copy()

        response = self.session.post(
            url,
            json=payload,
            headers=headers,
        )

        if response.status_code != 200:
            console.print(f"[red]Failed to fetch certificates: {response.status_code}")
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return []

        data = response.json()
        certificates = []

        for cert in data.get("data", []):
            attrs = cert["attributes"]
            certificates.append(
                Certificate(
                    id=cert["id"],
                    serial_number=attrs["serialNumber"],
                    owner_id=attrs["ownerId"],
                    certificate_type=attrs["certificateType"],
                    name=attrs["name"],
                )
            )

        console.print(f"[green]Found {len(certificates)} certificates")
        return certificates

    def list_bundle_ids(self, team_id: str) -> List[BundleId]:
        """List bundle IDs for a team"""
        console.print(f"[blue]Fetching bundle IDs for team {team_id}...")

        url = "https://developer.apple.com/services-account/v1/bundleIds"
        payload = {
            "urlEncodedQueryParams": "limit=1000&sort=name&filter[platform]=IOS,MACOS",
            "teamId": team_id,
        }
        headers = self.default_headers.copy()

        response = self.session.post(
            url,
            json=payload,
            headers=headers,
        )

        if response.status_code != 200:
            console.print(f"[red]Failed to fetch bundle IDs: {response.status_code}")
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return []

        data = response.json()
        bundle_ids = []

        for bundle in data.get("data", []):  # Remove slice
            attrs = bundle["attributes"]
            bundle_ids.append(
                BundleId(
                    id=bundle["id"],
                    identifier=attrs["identifier"],
                    name=attrs["name"],
                )
            )

        console.print(
            f"[green]Found {len(data.get('data', []))} bundle IDs (showing {len(bundle_ids)})"
        )
        return bundle_ids

    def list_app_group_ids(self, team_id: str) -> List[AppGroup]:
        """List app group IDs for a team"""
        console.print(f"[blue]Fetching app groups for team {team_id}...")

        # Updated headers to match the request
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
        }

        payload = f"onlyCountLists=true&pageSize=1000&pageNumber=1&sort=name%3Dasc&teamId={team_id}"

        response = self.session.post(
            "https://developer.apple.com/services-account/QH65B2/account/ios/identifiers/listApplicationGroups.action",
            data=payload,  # Use data instead of json for this endpoint
            headers=headers,
        )

        if response.status_code != 200:
            console.print(f"[red]Failed to fetch app groups: {response.status_code}")
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return []

        data = response.json()
        app_groups = []

        # Apply limit to the results
        for group in data.get("applicationGroupList", []):  # Remove slice
            app_groups.append(
                AppGroup(
                    id=group["applicationGroup"],
                    identifier=group["identifier"],
                    name=group["name"],
                )
            )

        console.print(
            f"[green]Found {len(data.get('applicationGroupList', []))} app groups (showing {len(app_groups)})"
        )
        return app_groups

    def list_icloud_container_ids(self, team_id: str) -> List[ICloudContainer]:
        """List iCloud container IDs for a team"""
        console.print(f"[blue]Fetching iCloud containers for team {team_id}...")

        url = "https://developer.apple.com/services-account/v1/cloudContainers"
        payload = {
            "urlEncodedQueryParams": "limit=1000",
            "teamId": team_id,
        }
        headers = self.default_headers.copy()

        response = self.session.post(
            url,
            json=payload,
            headers=headers,
        )

        if response.status_code != 200:
            console.print(
                f"[red]Failed to fetch iCloud containers: {response.status_code}"
            )
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return []

        data = response.json()
        containers = []

        # Apply limit to the results
        for container in data.get("data", []):  # Remove slice
            attrs = container["attributes"]
            containers.append(
                ICloudContainer(
                    id=container["id"],
                    identifier=attrs["identifier"],
                    name=attrs["name"],
                )
            )

        console.print(
            f"[green]Found {len(data.get('data', []))} iCloud containers (showing {len(containers)})"
        )
        return containers

    def list_devices(
        self, team_id: str, device_types: List[str] = None
    ) -> List[Device]:
        """
        List devices for a team
        device_types: List of device types to filter by (e.g. ['IPHONE', 'IPAD'])
        """
        console.print(f"[blue]Fetching devices for team {team_id}...")

        # Default to iOS devices if not specified
        if device_types is None:
            device_types = ["IPHONE", "IPAD"]

        url = "https://developer.apple.com/services-account/v1/devices"
        payload = {
            "urlEncodedQueryParams": "limit=1000&offset=0&filter[status]=ENABLED",
            "teamId": team_id,
        }
        headers = self.default_headers.copy()

        response = self.session.post(url, json=payload, headers=headers)

        if response.status_code != 200:
            console.print(f"[red]Failed to fetch devices: {response.status_code}")
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return []

        data = response.json()
        devices = []

        for device in data.get("data", []):
            attrs = device["attributes"]
            # Only include devices matching requested types
            if attrs["deviceClass"] in device_types:
                devices.append(
                    Device(
                        id=device["id"],
                        name=attrs["name"],
                        udid=attrs["udid"],
                        status=attrs["status"],
                        device_class=attrs["deviceClass"],
                        platform=attrs["platform"],
                        model=attrs.get("model"),  # model can be null
                    )
                )

        console.print(
            f"[green]Found {len(data.get('data', []))} devices (showing {len(devices)})"
        )
        return devices

    def list_profiles(self, team_id: str) -> List[Profile]:
        """List provisioning profiles for a team"""
        console.print(f"[blue]Fetching profiles for team {team_id}...")

        url = "https://developer.apple.com/services-account/v1/profiles"
        payload = {
            "urlEncodedQueryParams": "limit=1000&fields[profiles]=name,platform,platformName,profileTypeLabel,expirationDate,profileState&sort=name",
            "teamId": team_id,
        }
        headers = self.default_headers.copy()

        response = self.session.post(
            url,
            json=payload,
            headers=headers,
        )

        if response.status_code != 200:
            console.print(f"[red]Failed to fetch profiles: {response.status_code}")
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return []

        data = response.json()
        profiles = []

        for profile in data.get("data", []):  # Remove slice
            attrs = profile["attributes"]
            profiles.append(
                Profile(
                    id=profile["id"],
                    profile_state=attrs["profileState"],
                    name=attrs["name"],
                    platform=attrs["platform"],
                    profile_type_label=attrs["profileTypeLabel"],
                )
            )

        console.print(
            f"[green]Found {len(data.get('data', []))} profiles (showing {len(profiles)})"
        )
        return profiles

    def get_capabilities_for_bundle_id(
        self, team_id: str, bundle_id_resource_id: str
    ) -> List[Capability]:
        """Get capabilities and their entitlements for a bundle ID"""
        console.print(
            f"[blue]Fetching capabilities for bundle ID {bundle_id_resource_id}..."
        )

        url = f"https://developer.apple.com/services-account/v1/bundleIds/{bundle_id_resource_id}"
        params = {
            "fields[bundleIds]": "name,identifier,platform,seedId,wildcard,~permissions.delete,~permissions.edit",
            "include": "bundleIdCapabilities,bundleIdCapabilities.capability,bundleIdCapabilities.appGroups,bundleIdCapabilities.merchantIds,bundleIdCapabilities.cloudContainers,bundleIdCapabilities.certificates,bundleIdCapabilities.appConsentBundleId,bundleIdCapabilities.macBundleId,bundleIdCapabilities.relatedAppConsentBundleIds,bundleIdCapabilities.parentBundleId",
        }
        headers = self.default_headers.copy()

        response = self.session.post(
            url,
            params=params,
            json={"teamId": team_id},
            headers=headers,
        )

        if response.status_code != 200:
            console.print(f"[red]Failed to fetch capabilities: {response.status_code}")
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return []

        data = response.json()
        capabilities = []

        # Find capabilities in included array
        for item in data.get("included", []):
            if item.get("type") == "capabilities":
                attrs = item["attributes"]
                entitlements = []

                # Process entitlements
                for ent in attrs.get("entitlements", []):
                    entitlements.append(
                        Entitlement(
                            key=ent.get("key"),
                            name=ent.get("name"),
                            description=ent.get("description"),
                            value_type=ent.get("valueType"),
                            profile_key=ent.get("profileKey"),
                            values=ent.get("values", {}),  # Keep raw values
                        )
                    )

                capabilities.append(
                    Capability(
                        id=item["id"],
                        description=attrs.get("description"),
                        optional=attrs.get("optional", True),
                        name=attrs.get("name"),
                        entitlements=entitlements,
                    )
                )

        console.print(f"[green]Found {len(capabilities)} capabilities")
        return capabilities

    # HACK: Added return_raw parameter to fetch_available_user_entitlements
    # This is used to return raw data instead of processed objects.
    # This was used for entitlements_processor, which used to use the JSON capabilities.json

    def fetch_available_user_entitlements(
        self, team_id: str, return_raw: bool = False
    ) -> Union[List[AvailableCapability], dict]:
        """Fetch available user entitlements (with caching)"""
        # Check cache using just team_id since capabilities are user-wide
        if self._entitlements_cache:
            console.print("[cyan]Using cached user entitlements")
            return (
                self._entitlements_cache["raw"]
                if return_raw
                else self._entitlements_cache["processed"]
            )

        console.print("[blue]Fetching available user entitlements...")

        url = "https://developer.apple.com/services-account/v1/capabilities"
        params = {"filter[capabilityType]": "capability,service"}
        payload = {
            "urlEncodedQueryParams": "filter[platform]=IOS,MACOS",
            "teamId": team_id,
        }
        headers = self.default_headers.copy()

        response = self.session.post(
            url,
            params=params,
            json=payload,
            headers=headers,
        )

        if response.status_code != 200:
            console.print(
                f"[red]Failed to fetch available entitlements: {response.status_code}"
            )
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return [] if not return_raw else {}

        data = response.json()

        # Store both raw and processed data in cache
        self._entitlements_cache = {
            "raw": data,
            "processed": self._process_entitlements_data(data),
        }

        console.print("[green]Cached user entitlements")
        return data if return_raw else self._entitlements_cache["processed"]

    def _process_entitlements_data(self, data: dict) -> List[AvailableCapability]:
        """Process raw entitlements data into AvailableCapability objects"""
        capabilities = []
        for item in data.get("data", []):
            attrs = item["attributes"]
            distribution_types = [
                EntitlementValue(name=dist["name"])
                for dist in attrs.get("distributionTypes", [])
            ]

            entitlements = []
            for ent in attrs.get("entitlements", []):
                entitlements.append(
                    AvailableEntitlement(
                        id=ent.get("key"),
                        name=ent.get("name"),
                        description=ent.get("description"),
                        value_type=ent.get("valueType"),
                        profile_key=ent.get("profileKey"),
                        supports_wildcard=ent.get("supportsWildcard", False),
                        values=ent.get("values", {}),
                        distribution_types=distribution_types,
                        is_required=ent.get("isRequiredInPlist", False),
                    )
                )

            capabilities.append(
                AvailableCapability(
                    id=item["id"],
                    name=attrs.get("name"),
                    optional=attrs.get("optional", True),
                    description=attrs.get("description"),
                    editable=attrs.get("editable", False),
                    supports_wildcard=attrs.get("supportsWildcard", False),
                    entitlements=entitlements,
                    settings=attrs.get("settings"),
                )
            )
        return capabilities

    def set_entitlements_for_bundle_id(
        self,
        team_id: str,
        bundle_id_resource_id: str,
        bundle_identifier: str,
        capabilities_to_enable: List[str],
        group_ids: Dict[str, List[str]] = None,
    ) -> bool:
        """Set enabled capabilities for a bundle ID"""
        console.print(
            f"[blue]Setting capabilities for bundle ID {bundle_id_resource_id}..."
        )

        if not bundle_id_resource_id:
            console.print(f"[red]Invalid bundle ID resource ID")
            return False

        # First get all available capabilities to ensure we have a complete list
        # Changed to return processed objects instead of raw data
        available = self.fetch_available_user_entitlements(team_id, return_raw=False)

        group_ids = group_ids or {}

        # Create the relationships data with all capabilities
        capabilities_data = []
        for cap in available:
            # Only capabilities with optional=False are truly required
            is_required = not cap.optional

            # Enable if in list OR is truly required
            should_enable = cap.id in capabilities_to_enable or is_required

            if is_required:
                console.print(
                    f"[yellow]Note: Capability {cap.id} ({cap.name}) is required and will be enabled[/]"
                )
            elif should_enable:
                console.print(
                    f"[green]Enabling optional capability {cap.id} ({cap.name})[/]"
                )

            # Build capability data
            capability_data = {
                "type": "bundleIdCapabilities",
                "attributes": {
                    "enabled": should_enable,
                    "settings": (
                        CAPABILITY_SETTINGS.get(cap.id, []) if should_enable else []
                    ),
                },
                "relationships": {
                    "capability": {"data": {"type": "capabilities", "id": cap.id}}
                },
            }

            # Add relationship data for special capabilities if enabled
            if should_enable and cap.id in RELATIONSHIP_CAPABILITIES:
                relationship_type = RELATIONSHIP_CAPABILITIES[cap.id]
                if cap.id in group_ids and group_ids[cap.id]:
                    capability_data["relationships"][relationship_type] = {
                        "data": [
                            {"id": group_id, "type": relationship_type}
                            for group_id in group_ids[cap.id]
                        ]
                    }

            capabilities_data.append(capability_data)

        # Construct the full payload
        payload = {
            "data": {
                "type": "bundleIds",
                "id": bundle_id_resource_id,
                "attributes": {
                    "identifier": bundle_identifier,
                    "permissions": {"edit": True, "delete": True},
                    "seedId": team_id,
                    "name": bundle_identifier,  # Using identifier as name
                    "wildcard": False,
                    "teamId": team_id,
                },
                "relationships": {"bundleIdCapabilities": {"data": capabilities_data}},
            }
        }

        url = f"https://developer.apple.com/services-account/v1/bundleIds/{bundle_id_resource_id}"

        # This endpoint requires different headers so they are set here...
        # Not sure if this is necessary, but it's how the request is made in the browser
        headers = {
            "Host": "developer.apple.com",
            "Accept-Encoding": "en-US,en;q=0.5",
            "Referer": f"https://developer.apple.com/account/resources/identifiers/bundleId/edit/{bundle_id_resource_id}",
            "Origin": "https://developer.apple.com",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Content-Type": "application/vnd.api+json",
            "XMLHttpRequest": "XMLHttpRequest",
            "csrf": self.csrf,
            "csrf_ts": str(self.csrf_ts),
        }

        response = self.session.patch(
            url,
            json=payload,
            headers=headers,
        )

        if response.status_code != 200:
            console.print(f"[red]Failed to set capabilities: {response.status_code}")
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return False

        console.print(f"[green]Successfully updated capabilities")
        return True

    def register_bundle_id(
        self, team_id: str, identifier: str, name: str
    ) -> Optional[BundleId]:
        """Register a new bundle ID (or get existing)"""
        console.print(f"[blue]Registering bundle ID {identifier}...")

        # Try to create first
        url = "https://developer.apple.com/services-account/v1/bundleIds"
        payload = {
            "data": {
                "type": "bundleIds",
                "attributes": {
                    "identifier": identifier,
                    "name": name,
                    "seedId": team_id,
                    "teamId": team_id,
                },
                "relationships": {"bundleIdCapabilities": {"data": []}},
            }
        }

        headers = {
            "Host": "developer.apple.com",
            "Accept-Encoding": "en-US,en;q=0.5",
            "Origin": "https://developer.apple.com",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Content-Type": "application/vnd.api+json",
            "X-Requested-With": "XMLHttpRequest",
            "csrf": self.csrf,
            "csrf_ts": str(self.csrf_ts),
        }

        response = self.session.post(url, json=payload, headers=headers)

        # Handle different 409 responses
        if response.status_code == 409:
            data = response.json()
            if data.get("errors", [{}])[0].get("resultCode") == 9400:  # Already exists
                console.print(
                    f"[yellow]Bundle ID {identifier} exists, fetching existing one..."
                )
                # Get bundle directly by identifier
                url = "https://developer.apple.com/services-account/v1/bundleIds"
                payload = {
                    "urlEncodedQueryParams": f"filter[identifier]={identifier}",
                    "teamId": team_id,
                }
                response = self.session.post(
                    url, json=payload, headers=self.default_headers
                )

                if response.status_code == 200:
                    data = response.json()
                    bundles = data.get("data", [])
                    # Find exact match only
                    matching_bundle = next(
                        (
                            b
                            for b in bundles
                            if b["attributes"]["identifier"] == identifier
                        ),
                        None,
                    )
                    if matching_bundle:
                        attrs = matching_bundle["attributes"]
                        console.print(
                            f"[green]Found existing bundle ID with exact match: {attrs['identifier']}"
                        )
                        return BundleId(
                            id=matching_bundle["id"],
                            identifier=attrs["identifier"],
                            name=attrs["name"],
                        )
                    else:
                        console.print(
                            f"[red]No exact match found for bundle ID: {identifier}"
                        )
                        return None
            else:
                console.print(f"[red]Bundle ID registration failed: {data}")
                return None

        if response.status_code not in (200, 201):
            console.print(f"[red]Failed to register bundle ID: {response.status_code}")
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return None

        # Handle successful creation
        data = response.json()
        if "data" not in data:
            console.print("[red]Unexpected response format")
            return None

        bundle = data["data"]
        attrs = bundle["attributes"]
        console.print(
            f"[green]Successfully registered new bundle ID: {attrs['identifier']}"
        )
        return BundleId(
            id=bundle["id"],
            identifier=attrs["identifier"],
            name=attrs["name"],
        )

    def register_app_group(
        self, team_id: str, identifier: str, name: str
    ) -> Optional[AppGroup]:
        """Register a new app group (or get existing)"""
        console.print(f"[blue]Registering app group {identifier}...")

        url = "https://developer.apple.com/services-account/QH65B2/account/ios/identifiers/addApplicationGroup.action"
        payload = {
            "name": name,
            "identifier": identifier,
            "teamId": team_id,
        }
        headers = {
            "Host": "developer.apple.com",
            "Accept-Encoding": "en-US,en;q=0.5",
            "Origin": "https://developer.apple.com",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "csrf": self.csrf,
            "csrf_ts": str(self.csrf_ts),
        }

        response = self.session.post(url, data=payload, headers=headers)

        if response.status_code != 200:
            console.print(f"[red]Failed to register app group: {response.status_code}")
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return None

        data = response.json()

        user_string = data.get("userString", "")
        if "is not available. Please enter a different string." in user_string:
            console.print(
                f"[yellow]App group {identifier} already exists, fetching existing groups...[/]"
            )
            # Get all groups and find matching one
            all_groups = self.list_app_group_ids(team_id)
            matching_group = next(
                (group for group in all_groups if group.identifier == identifier), None
            )
            if matching_group:
                console.print("[green]Found existing app group[/]")
                return matching_group

            console.print("[red]Could not find existing app group[/]")
            return None

        elif data.get("resultCode") != 0:
            console.print(f"[red]API error: {data}")
            return None

        group_data = data.get("applicationGroup", {})
        return AppGroup(
            id=group_data["applicationGroup"],
            identifier=group_data["identifier"],
            name=group_data["name"],
        )

    def register_icloud_container(
        self, team_id: str, identifier: str, name: str
    ) -> Optional[ICloudContainer]:
        """Register a new iCloud container (or get existing)"""
        console.print(f"[blue]Registering iCloud container {identifier}...")

        url = "https://developer.apple.com/services-account/QH65B2/account/cloudContainer/addCloudContainer.action"
        payload = {
            "name": name,
            "identifier": identifier,
            "teamId": team_id,
        }
        headers = {
            "Host": "developer.apple.com",
            "Accept-Encoding": "en-US,en;q=0.5",
            "Origin": "https://developer.apple.com",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "csrf": self.csrf,
            "csrf_ts": str(self.csrf_ts),
        }

        response = self.session.post(url, data=payload, headers=headers)

        if response.status_code != 200:
            console.print(
                f"[red]Failed to register iCloud container: {response.status_code}"
            )
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return None

        data = response.json()
        user_string = data.get("userString", "")
        if "is not available. Please enter a different string." in user_string:
            console.print(
                f"[yellow]iCloud container {identifier} already exists, fetching existing containers...[/]"
            )
            # Get all containers and find matching one
            all_containers = self.list_icloud_container_ids(team_id)
            matching_container = next(
                (
                    container
                    for container in all_containers
                    if container.identifier == identifier
                ),
                None,
            )
            if matching_container:
                console.print("[green]Found existing iCloud container[/]")
                return matching_container

            console.print("[red]Could not find existing iCloud container[/]")
            return None

        elif data.get("resultCode") != 0:
            console.print(f"[red]API error: {data}")
            return None

        container_data = data.get("cloudContainer", {})
        return ICloudContainer(
            id=container_data["cloudContainer"],
            identifier=container_data["identifier"],
            name=container_data["name"],
        )

    def create_or_regen_provisioning_profile(
        self,
        team_id: str,
        profile_id: str,
        app_id_id: str,
        profile_name: str,
        certificate_ids: List[str],
        device_ids: List[str],
        distribution_type: str = "development",  # Changed default to development
    ) -> Optional[bytes]:  # Changed return type to bytes
        """Create or regenerate a provisioning profile and return its content"""
        console.print(f"[blue]Creating {distribution_type} profile:[/] {profile_name}")
        console.print(f"[cyan]Using {len(device_ids)} iOS devices")

        url = "https://developer.apple.com/services-account/QH65B2/account/ios/profile/regenProvisioningProfile.action"

        # Map profile type to Apple's internal values
        profile_type = {
            "development": "limited",
            "adhoc": "adhoc",
        }.get(distribution_type.lower(), "limited")

        payload = {
            "appIdId": app_id_id,
            "provisioningProfileId": profile_id,
            "distributionType": profile_type,  # Use mapped type
            "provisioningProfileName": profile_name,
            "certificateIds": ",".join(certificate_ids),
            "deviceIds": ",".join(device_ids),
            "teamId": team_id,
            "subPlatform": "",
            "isExcludeAudiences": "",
            "returnFullObjects": "false",
        }

        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "csrf": self.csrf,
            "csrf_ts": str(self.csrf_ts),
        }

        response = self.session.post(url, data=payload, headers=headers)

        if response.status_code != 200:
            console.print(f"[red]Failed to create profile: {response.status_code}")
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return None

        data = response.json()
        if data.get("resultCode") != 0:
            console.print(f"[red]API error: {data}")
            return None

        # Get the profile ID from the response
        profile_data = data.get("provisioningProfile", {})
        if not profile_data:
            console.print("[red]No profile data in response")
            return None

        profile_id = profile_data.get("provisioningProfileId")
        if not profile_id:
            console.print("[red]No profile ID in response")
            return None

        # Download the actual profile content
        console.print("[cyan]Downloading profile content...")
        return self.download_provisioning_profile(team_id, profile_id)

    def _handle_409_profile_error(
        self, response: requests.Response, team_id: str
    ) -> Optional[str]:
        """Handle 409 conflict errors for profiles
        Returns the profile ID if found, None otherwise"""
        try:
            error_data = response.json()
            if error_data.get("errors"):
                error = error_data["errors"][0]
                if error.get("resultCode") == 35:  # Duplicate profile name
                    # The error message contains the profile name
                    profile_name = error["detail"].split("'")[1]
                    console.print(f"[yellow]Profile '{profile_name}' already exists")

                    # Get existing profiles to find the ID
                    existing_profiles = self.list_profiles(team_id)
                    for profile in existing_profiles:
                        if profile.name == profile_name:
                            console.print("[green]Found existing profile")
                            return profile.id
        except:
            pass
        return None

    def download_provisioning_profile(
        self, team_id: str, profile_id: str
    ) -> Optional[bytes]:
        """Download a provisioning profile by its ID"""
        console.print(f"[blue]Downloading provisioning profile {profile_id}...")

        url = "https://developer.apple.com/services-account/QH65B2/account/ios/profile/downloadProfileContent"
        params = {"teamId": team_id, "provisioningProfileId": profile_id}
        headers = {
            "Accept": "*/*",  # Accept any content type since this is binary data
            "X-Requested-With": "XMLHttpRequest",
        }

        response = self.session.get(url, params=params, headers=headers)

        if response.status_code != 200:
            console.print(f"[red]Failed to download profile: {response.status_code}")
            try:
                console.print(f"[red]Error response: {response.text}")
            except:
                console.print("[red]Could not decode error response")
            return None

        # Return raw binary data
        return response.content
