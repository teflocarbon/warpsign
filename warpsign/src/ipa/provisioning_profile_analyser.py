import sys
from pathlib import Path
import plistlib
from asn1crypto.cms import ContentInfo
import json
from rich.console import Console
from rich.json import JSON

# Add the parent directory of 'src' to the system path.. kinda hacky but it works
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from warpsign.src.constants.capability_mappings import (
    CAPABILITY_MAPPING,
    SPECIAL_CAPABILITIES,
)


def dump_prov(prov_file: Path) -> dict:
    """Read a provisioning profile without using macOS security command"""
    with open(prov_file, "rb") as f:
        content_info = ContentInfo.load(f.read())
    signed_data = content_info["content"]
    # The actual plist is in the content of the first signer info
    plist_data = signed_data["encap_content_info"]["content"].native
    return plistlib.loads(plist_data)


def load_capabilities(cap_file: Path) -> dict:
    """Load and parse the capabilities.json file"""
    with open(cap_file, "r") as f:
        return json.load(f)


def validate_container_setup(
    entitlements: dict, capability_name: str
) -> tuple[bool, bool, str]:
    """Check if a capability is enabled and properly configured with containers"""

    def is_valid_container(container):
        """Check if container identifier is properly configured (not just a wildcard)"""
        return isinstance(container, str) and not container.endswith(".*")

    if capability_name == "App Groups":
        key = "com.apple.security.application-groups"
        if key in entitlements:
            groups = entitlements[key]
            if not groups or not isinstance(groups, list) or len(groups) == 0:
                return (
                    True,
                    True,
                    "App Groups enabled but no groups are configured. Contact the creator of the .mobileprovision file.",
                )
            if not all(is_valid_container(g) for g in groups):
                return (
                    True,
                    True,
                    "App Groups contains wildcards. Specific group identifiers must be configured.",
                )
            return True, False, ""
        return False, False, ""

    elif capability_name == "iCloud":
        icloud_keys = [
            "com.apple.developer.icloud-container-identifiers",
            "com.apple.developer.icloud-container-development-container-identifiers",
            "com.apple.developer.ubiquity-container-identifiers",
        ]

        # Check if any iCloud entitlement is present
        has_icloud = any(key in entitlements for key in icloud_keys)

        if has_icloud:
            # Check if all present containers have values
            for key in icloud_keys:
                if key in entitlements:
                    containers = entitlements[key]
                    if (
                        not containers
                        or not isinstance(containers, list)
                        or len(containers) == 0
                    ):
                        return (
                            True,
                            True,
                            "iCloud enabled but no containers are configured. Contact the creator of the .mobileprovision file.",
                        )
                    if not all(is_valid_container(c) for c in containers):
                        return (
                            True,
                            True,
                            "iCloud containers contain wildcards. Specific container identifiers must be configured. Contact the creator of the .mobileprovision file.",
                        )
            return True, False, ""
        return False, False, ""

    return False, False, ""


def check_capabilities(entitlements: dict) -> list:
    """Check which capabilities are enabled based on entitlements"""
    results = []

    for capability_name, entitlement_keys in CAPABILITY_MAPPING.items():
        if capability_name in ["App Groups", "iCloud"]:
            enabled, has_warning, warning_msg = validate_container_setup(
                entitlements, capability_name
            )
            is_special = capability_name in SPECIAL_CAPABILITIES
            results.append(
                (capability_name, enabled, is_special, has_warning, warning_msg)
            )
        else:
            enabled = any(key in entitlements for key in entitlement_keys)
            is_special = capability_name in SPECIAL_CAPABILITIES
            results.append((capability_name, enabled, is_special, False, ""))

    return results


def extract_app_groups(entitlements: dict) -> set:
    """Extract app group identifiers from provisioning profile"""
    groups = set()
    if "com.apple.security.application-groups" in entitlements:
        groups = set(entitlements["com.apple.security.application-groups"])
    return groups


def extract_icloud_containers(entitlements: dict) -> set:
    """Extract iCloud container identifiers from provisioning profile"""
    containers = set()
    icloud_keys = [
        "com.apple.developer.icloud-container-identifiers",
        "com.apple.developer.icloud-container-development-container-identifiers",
        "com.apple.developer.ubiquity-container-identifiers",
    ]

    for key in icloud_keys:
        if key in entitlements:
            containers.update(entitlements[key])
    return containers


def print_capability_summary(console: Console, capabilities: list) -> None:
    """Print summary of enabled capabilities and warnings"""
    total_capabilities = len(capabilities)
    enabled_capabilities = sum(1 for _, enabled, _, _, _ in capabilities if enabled)
    enabled_special = sum(
        1 for _, enabled, is_special, _, _ in capabilities if enabled and is_special
    )
    total_special = sum(1 for _, _, is_special, _, _ in capabilities if is_special)
    warning_count = sum(1 for _, _, _, has_warning, _ in capabilities if has_warning)

    console.print("\n[bold]Capabilities Summary:[/bold]")
    console.print(
        f"Total Capabilities Enabled: [green]{enabled_capabilities}[/green]/[blue]{total_capabilities}[/blue]"
    )
    console.print(
        f"Special Capabilities Enabled: [blue]{enabled_special}[/blue]/[blue]{total_special}[/blue]"
    )
    if warning_count > 0:
        console.print(
            f"[yellow]Warning: {warning_count} capabilities need attention[/yellow]"
        )


def print_capability_status(console: Console, capabilities: list) -> None:
    """Print detailed status of each capability"""
    console.print("\n[bold]Capabilities Status:[/bold]")
    console.print("-------------------")

    for name, enabled, is_special, has_warning, warning_msg in capabilities:
        if has_warning:
            status = "🟡"
        elif enabled:
            status = "🔵" if is_special else "🟢"
        else:
            status = "🔴"

        output = f"{status} {name}"
        if warning_msg:
            console.print(f"{output} - [yellow]{warning_msg}[/yellow]")
        else:
            console.print(output)


def print_profile_contents(console: Console, data: dict) -> None:
    """Print the full profile contents, excluding binary data"""
    console.print("\n[bold]Full Profile Contents:[/bold]")
    filtered_data = data.copy()
    if "DeveloperCertificates" in filtered_data:
        filtered_data["DeveloperCertificates"] = "<binary data removed>"
    if "DER-Encoded-Profile" in filtered_data:
        filtered_data["DER-Encoded-Profile"] = "<binary data removed>"
    console.print_json(json.dumps(filtered_data, default=str))


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} provisioning_profile.mobileprovision")
        sys.exit(1)

    profile = Path(sys.argv[1])
    if not profile.exists():
        print(f"Error: {profile} does not exist")
        sys.exit(1)

    console = Console()

    try:
        data = dump_prov(profile)
        entitlements = data.get("Entitlements", {})
        capabilities = check_capabilities(entitlements)

        print_capability_summary(console, capabilities)
        print_capability_status(console, capabilities)
        print_profile_contents(console, data)

    except Exception as e:
        console.print(f"[red]Error reading profile: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
