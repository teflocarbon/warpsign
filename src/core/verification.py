import plistlib
import subprocess
from pathlib import Path
from typing import Dict, Any, Tuple, List
from logger import get_console

from src.ipa.ipa_inspector import IPAInspector


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

    def _is_critical_entitlement(self, key: str) -> bool:
        """Determine if an entitlement is critical and must match exactly."""
        critical_keys = [
            "application-identifier",
            "com.apple.developer.team-identifier",
            "aps-environment",
        ]
        return key in critical_keys

    def _compare_entitlement_values(
        self, key: str, binary_value: Any, profile_value: Any
    ) -> Tuple[bool, str]:
        """Compare entitlement values with special handling for certain keys.
        Returns (is_valid, message)
        """
        # Special handling for known cases
        if key == "com.apple.developer.icloud-services" and profile_value == "*":
            return True, "Profile allows all iCloud services (wildcard match)"

        if key == "com.apple.developer.associated-domains" and profile_value == "*":
            return True, "Profile allows all associated domains (wildcard match)"

        if key == "keychain-access-groups" and isinstance(profile_value, list):
            team_wildcard = next((p for p in profile_value if p.endswith(".*")), None)
            if team_wildcard:
                team_prefix = team_wildcard[:-2]  # Remove .* from the end
                if all(
                    g.startswith(team_prefix) or g == "com.apple.token"
                    for g in binary_value
                ):
                    return True, "Binary's keychain groups match profile's wildcard"
                return False, "Binary's keychain groups do not match profile's wildcard"
            if set(binary_value) == set(profile_value):
                return True, "Keychain groups match exactly"
            return False, "Keychain groups do not match exactly"

        if key == "com.apple.security.application-groups" and isinstance(
            profile_value, list
        ):
            if set(binary_value).issubset(set(profile_value)):
                return True, "Binary's app groups are a subset of profile's groups"
            return False, "Binary's app groups are not a subset of profile's groups"

        if key == "com.apple.developer.icloud-container-environment" and isinstance(
            profile_value, list
        ):
            if binary_value in profile_value:
                return (
                    True,
                    f"Binary's environment '{binary_value}' is allowed by profile",
                )
            return (
                False,
                f"Binary's environment '{binary_value}' not allowed by profile",
            )

        # Default comparison for other cases
        if isinstance(binary_value, list) and isinstance(profile_value, list):
            if set(binary_value) == set(profile_value):
                return True, "Values match (order independent)"
            return False, "List values do not match"

        if binary_value == profile_value:
            return True, "Values match exactly"
        return (
            False,
            f"Values do not match: binary={binary_value}, profile={profile_value}",
        )

    def _compare_entitlements(
        self,
        binary_ents: Dict[str, Any],
        profile_ents: Dict[str, Any],
        component_path: str,
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """Compare binary and profile entitlements, returning validity and results list."""
        all_keys = set(binary_ents.keys()) | set(profile_ents.keys())
        all_critical_valid = True
        results = []

        # Track matches for summary
        matched_count = 0
        critical_mismatches = []
        warnings = []

        for key in all_keys:
            binary_value = binary_ents.get(key)
            profile_value = profile_ents.get(key)

            if key not in profile_ents:
                result = {
                    "type": "error",
                    "key": key,
                    "message": f"Present in binary but missing from profile",
                    "binary_value": binary_value,
                    "profile_value": None,
                }
                results.append(result)

                if self._is_critical_entitlement(key):
                    all_critical_valid = False
                    critical_mismatches.append(key)
                else:
                    warnings.append(key)
                continue

            if key not in binary_ents:
                # Special handling for get-task-allow
                if key == "get-task-allow":
                    # Only record warning if get-task-allow is true in profile
                    if profile_value is True:
                        result = {
                            "type": "warning",
                            "key": key,
                            "message": "True in profile but missing from binary (development profile with distribution-signed binary?)",
                            "binary_value": None,
                            "profile_value": profile_value,
                        }
                        results.append(result)
                        warnings.append(key)
                    # Otherwise, it's normal for distribution builds and we can skip
                    continue

                result = {
                    "type": (
                        "warning" if not self._is_critical_entitlement(key) else "error"
                    ),
                    "key": key,
                    "message": f"Present in profile but missing from binary",
                    "binary_value": None,
                    "profile_value": profile_value,
                }
                results.append(result)

                if self._is_critical_entitlement(key):
                    all_critical_valid = False
                    critical_mismatches.append(key)
                else:
                    warnings.append(key)
                continue

            # Recursively compare nested dictionaries
            if isinstance(binary_value, dict) and isinstance(profile_value, dict):
                nested_valid, nested_results = self._compare_entitlements(
                    binary_value, profile_value, component_path
                )
                results.extend(nested_results)
                if not nested_valid:
                    all_critical_valid = False
                continue

            is_valid, message = self._compare_entitlement_values(
                key, binary_value, profile_value
            )
            if not is_valid:
                result = {
                    "type": (
                        "error" if self._is_critical_entitlement(key) else "warning"
                    ),
                    "key": key,
                    "message": message,
                    "binary_value": binary_value,
                    "profile_value": profile_value,
                }
                results.append(result)

                if self._is_critical_entitlement(key):
                    all_critical_valid = False
                    critical_mismatches.append(key)
                else:
                    warnings.append(key)
            else:
                result = {
                    "type": "match",
                    "key": key,
                    "message": message,
                }
                results.append(result)
                matched_count += 1

        # Add summary to results
        results.append(
            {
                "type": "summary",
                "matched_count": matched_count,
                "critical_mismatches": critical_mismatches,
                "warnings": warnings,
            }
        )

        return all_critical_valid, results

    def _verify_code_signature(self, path: Path) -> Tuple[bool, str]:
        """Verify the code signature of an app or component.
        Returns a tuple of (is_valid, error_message)
        """
        try:
            # Perform deep verification with strict checks
            subprocess.run(
                ["codesign", "--verify", "--deep", "--strict", str(path)],
                capture_output=True,
                check=True,
            )
            return True, ""
        except subprocess.CalledProcessError as e:
            error_output = e.stderr.decode("utf-8").strip()
            return False, error_output

    def verify_code_signatures(self) -> bool:
        """Verify all code signatures in the IPA to ensure integrity."""
        all_signatures_valid = True

        with IPAInspector(self.ipa_path) as inspector:
            app_dir = inspector.app_dir
            components = inspector.get_components()

            self.console.print(
                f"\n[bold blue]🔍 Verifying code signatures for {len(components)} components[/]"
            )
            self.console.print("=" * 80)

            # First verify the main app bundle
            is_valid, error = self._verify_code_signature(app_dir)
            if is_valid:
                self.console.print("[green]✓ Main app bundle signature is valid[/]")
            else:
                self.console.print(
                    f"[bold red]❌ Main app bundle signature invalid: {error}[/]"
                )
                all_signatures_valid = False

            # Then verify each component separately
            for idx, component in enumerate(components):
                component_name = (
                    component.path if str(component.path) != "." else "Main App Binary"
                )

                component_path = app_dir
                if component.path != Path("."):
                    component_path = app_dir / component.path

                binary_path = app_dir / component.executable

                # Verify the component's binary
                is_valid, error = self._verify_code_signature(binary_path)
                if is_valid:
                    self.console.print(
                        f"[green]✓ {component_name} signature is valid[/]"
                    )
                else:
                    self.console.print(
                        f"[bold red]❌ {component_name} signature invalid: {error}[/]"
                    )
                    all_signatures_valid = False

            # Final summary
            self.console.print("\n" + "=" * 80)
            if all_signatures_valid:
                self.console.print("[bold green]✓ All code signatures are valid[/]")
            else:
                self.console.print(
                    "[bold red]❌ Code signature verification failed - some resources may have been modified after signing[/]"
                )

        return all_signatures_valid

    def verify_entitlements(self) -> bool:
        """Verify that binary entitlements match provisioning profile entitlements."""
        all_critical_valid = True

        with IPAInspector(self.ipa_path) as inspector:
            components = inspector.get_components()
            primary_components = [c for c in components if c.is_primary]

            self.console.print(
                f"\n[bold blue]🔍 Verifying {len(primary_components)} primary components[/]"
            )
            self.console.print("=" * 80)

            for idx, component in enumerate(primary_components):
                component_name = (
                    component.path if str(component.path) != "." else "Main App"
                )

                # Print component header with clear separation
                self.console.print(
                    f"\n[bold cyan]Component {idx+1}/{len(primary_components)}: {component_name}[/]"
                )
                self.console.print("-" * 80)

                binary_path = inspector.app_dir / component.executable
                if component.path == Path("."):
                    profile_path = inspector.app_dir / "embedded.mobileprovision"
                else:
                    profile_path = (
                        inspector.app_dir / component.path / "embedded.mobileprovision"
                    )

                binary_ents = self._get_binary_entitlements(binary_path)
                profile_ents = self._get_profile_entitlements(profile_path)

                component_valid, results = self._compare_entitlements(
                    binary_ents, profile_ents, str(component.path)
                )

                # Process and display results
                summary = next((r for r in results if r["type"] == "summary"), {})
                matches = [r for r in results if r["type"] == "match"]
                errors = [r for r in results if r["type"] == "error"]
                warnings = [r for r in results if r["type"] == "warning"]

                # Show summary of matches
                matched_count = summary.get("matched_count", 0)
                if matched_count > 0:
                    self.console.print(
                        f"[green]✓ {matched_count} entitlements match correctly[/]"
                    )

                # Show errors (if any)
                for error in errors:
                    self.console.print(f"[bold red]❌ Error: {error['key']}[/]")
                    if error.get("binary_value") is not None:
                        self.console.print(f"   Binary: {error['binary_value']}")
                    if error.get("profile_value") is not None:
                        self.console.print(f"   Profile: {error['profile_value']}")
                    self.console.print(f"   {error['message']}")

                # Show warnings (if any)
                for warning in warnings:
                    self.console.print(f"[yellow]⚠️ Warning: {warning['key']}[/]")
                    if warning.get("binary_value") is not None:
                        self.console.print(f"   Binary: {warning['binary_value']}")
                    if warning.get("profile_value") is not None:
                        self.console.print(f"   Profile: {warning['profile_value']}")
                    self.console.print(f"   {warning['message']}")

                # Component result summary
                if not component_valid:
                    self.console.print(
                        f"[bold red]❌ Component has critical entitlement issues[/]"
                    )
                    all_critical_valid = False
                else:
                    if warnings:
                        self.console.print(
                            f"[bold yellow]⚠️ Component has {len(warnings)} non-critical warnings[/]"
                        )
                    else:
                        self.console.print(
                            f"[bold green]✓ Component entitlements valid[/]"
                        )

            # Final summary
            self.console.print("\n" + "=" * 80)
            if not all_critical_valid:
                self.console.print(
                    "[bold red]❌ Critical entitlement verification failed[/]"
                )
            else:
                self.console.print(
                    "[bold green]✓ Entitlement verification passed (no critical issues)[/]"
                )

        return all_critical_valid
