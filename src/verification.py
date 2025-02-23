import plistlib
import subprocess
from pathlib import Path
import tempfile
from typing import Dict, Any, Tuple
from logger import get_console
from .ipa_inspector import IPAInspector


class SigningVerifier:
    def __init__(self, ipa_path: Path):
        self.ipa_path = ipa_path
        self.console = get_console()

    def _get_binary_entitlements(self, binary_path: Path) -> Dict[str, Any]:
        """Extract entitlements from a binary using codesign."""
        try:
            result = subprocess.run(
                ["codesign", "-d", "--entitlements", ":-", str(binary_path)],
                capture_output=True,
                check=True,
            )
            if result.stdout:
                return plistlib.loads(result.stdout)
            return {}
        except subprocess.CalledProcessError:
            self.console.print(
                f"[red]Failed to extract entitlements from {binary_path}"
            )
            return {}

    def _get_profile_entitlements(self, profile_path: Path) -> Dict[str, Any]:
        """Extract entitlements from a provisioning profile."""
        try:
            # Extract embedded plist from mobileprovision
            result = subprocess.run(
                ["security", "cms", "-D", "-i", str(profile_path)],
                capture_output=True,
                check=True,
            )
            profile_data = plistlib.loads(result.stdout)
            return profile_data.get("Entitlements", {})
        except subprocess.CalledProcessError:
            self.console.print(
                f"[red]Failed to extract entitlements from {profile_path}"
            )
            return {}

    def _compare_entitlement_values(
        self, key: str, binary_value: Any, profile_value: Any
    ) -> bool:
        """Compare entitlement values with special handling for certain keys."""

        # Special handling for known exception cases
        if key == "com.apple.developer.associated-domains" and profile_value == "*":
            return True

        if key == "keychain-access-groups" and isinstance(profile_value, list):
            # If profile contains wildcard entry (e.g., "TEAM_ID.*")
            team_wildcard = next((p for p in profile_value if p.endswith(".*")), None)
            if team_wildcard:
                team_prefix = team_wildcard[:-2]  # Remove .* from the end
                return all(g.startswith(team_prefix) for g in binary_value)

        if key == "com.apple.security.application-groups" and isinstance(
            profile_value, list
        ):
            # App groups must match exactly (order doesn't matter)
            return set(binary_value) == set(profile_value)

        if key == "com.apple.developer.devicecheck.appattest-environment":
            # Binary value must be one of the profile values
            if isinstance(profile_value, list):
                return binary_value in profile_value

        # For all other cases, values must match exactly
        if isinstance(binary_value, list) and isinstance(profile_value, list):
            return set(binary_value) == set(
                profile_value
            )  # Exact match, order doesn't matter

        return binary_value == profile_value  # Exact match for everything else

    def _compare_entitlements(
        self,
        binary_ents: Dict[str, Any],
        profile_ents: Dict[str, Any],
        component_path: str,
    ) -> bool:
        """Compare binary and profile entitlements, return True if they match."""
        all_keys = set(binary_ents.keys()) | set(profile_ents.keys())
        all_valid = True

        for key in all_keys:
            # Special handling for get-task-allow
            if key == "get-task-allow":
                # Only check if it exists in binary
                if key in binary_ents:
                    if key not in profile_ents:
                        self.console.print(
                            f"[red]Error: get-task-allow present in binary but missing from profile"
                        )
                        all_valid = False
                    elif binary_ents[key] != profile_ents[key]:
                        self.console.print("[red]Value mismatch for get-task-allow:")
                        self.console.print(f"  Binary: {binary_ents[key]}")
                        self.console.print(f"  Profile: {profile_ents[key]}")
                        all_valid = False
                continue

            binary_value = binary_ents.get(key)
            profile_value = profile_ents.get(key)

            # Both should have the value
            if key not in profile_ents:
                self.console.print(
                    f"[red]Error: {key} present in binary but missing from profile"
                )
                all_valid = False
                continue

            if key not in binary_ents:
                self.console.print(
                    f"[red]Error: {key} present in profile but missing from binary"
                )
                all_valid = False
                continue

            if not self._compare_entitlement_values(key, binary_value, profile_value):
                self.console.print(f"[red]Value mismatch for {key}:")
                self.console.print(f"  Binary: {binary_value}")
                self.console.print(f"  Profile: {profile_value}")

                # Show these as warnings but don't fail verification
                if key in [
                    "com.apple.developer.associated-domains",
                    "com.apple.developer.devicecheck.appattest-environment",
                    "com.apple.security.application-groups",
                    "keychain-access-groups",
                ]:
                    self.console.print("[yellow]  ⚠️  Known difference (acceptable)")
                    continue

                all_valid = False

        return all_valid

    def verify_entitlements(self) -> bool:
        """Verify that binary entitlements match provisioning profile entitlements."""
        all_valid = True

        with IPAInspector(self.ipa_path) as inspector:
            components = inspector.get_components()

            for component in components:
                if not component.is_primary:
                    continue

                self.console.print(f"\n[blue]Verifying component:[/] {component.path}")

                # Get paths for binary and profile
                binary_path = inspector.app_dir / component.executable
                if component.path == Path("."):
                    profile_path = inspector.app_dir / "embedded.mobileprovision"
                else:
                    profile_path = (
                        inspector.app_dir / component.path / "embedded.mobileprovision"
                    )

                # Get entitlements
                binary_ents = self._get_binary_entitlements(binary_path)
                profile_ents = self._get_profile_entitlements(profile_path)

                # Compare them
                if not self._compare_entitlements(
                    binary_ents, profile_ents, str(component.path)
                ):
                    all_valid = False

        return all_valid
