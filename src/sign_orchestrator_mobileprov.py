#!/usr/bin/env python3

import os
import sys
from pathlib import Path
import tempfile
import shutil
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from src.ipa_inspector import IPAInspector
from src.bundle_mapper import BundleMapping
from src.app_patcher import AppPatcher, PatchingOptions
from src.cert_handler import CertHandler
import plistlib
from logger import get_console
from src.provisioning_profile_analyser import (
    dump_prov,
    check_capabilities,
    print_capability_summary,
    print_capability_status,
    extract_app_groups,
    extract_icloud_containers,
)


class SignOrchestratorMobileProvision:
    def __init__(self, cert_type: str = "development", cert_dir: Path = None):
        """Initialize with optional profile type and certificate configuration"""
        self.console = get_console()
        self.patcher = None
        self.patching_options = None

        # Convert cert_dir to Path if it's a string
        if cert_dir:
            cert_dir = Path(cert_dir)

        # Initialize cert handler with configuration
        self.cert_handler = CertHandler(cert_type=cert_type, cert_dir=cert_dir)

        # Rest of initialization based on certificate type
        cert_name = self.cert_handler.cert_common_name
        if cert_name == "Apple Development":
            self.profile_type = "development"
        elif cert_name == "Apple Distribution":
            self.profile_type = "adhoc"
        else:
            raise ValueError(
                f"Invalid certificate type: {cert_name}. "
                "Certificate must be either 'Apple Development' or 'Apple Distribution'."
            )

        # Check for provisioning profile in the correct cert type directory
        self.profile_path = cert_dir / cert_type / "prov.mobileprovision"
        if not self.profile_path.exists():
            raise ValueError(
                f"Provisioning profile not found at: {self.profile_path}\n"
                f"Please place your provisioning profile in the {cert_type} directory."
            )

        self.console.print(f"Using certificate: {cert_name}")
        self.console.print(f"Profile type set to: {self.profile_type}")
        self.console.print(f"Using provisioning profile: {self.profile_path}")

        # Analyze provisioning profile first
        self.profile_entitlements, self.allowed_keys = (
            self._analyze_provisioning_profile(self.profile_path)
        )
        if not self.profile_entitlements:
            raise ValueError("Failed to read provisioning profile entitlements")

        # Get team ID from certificate's Organizational Unit
        self.team_id = self.cert_handler.cert_org_unit
        if not self.team_id:
            self.console.print("[red]Could not determine team ID from certificate")
            sys.exit(1)

        # Extract container IDs from profile
        self.app_groups = extract_app_groups(self.profile_entitlements)
        self.icloud_containers = extract_icloud_containers(self.profile_entitlements)

        if self.app_groups:
            self.console.print("[cyan]Found App Groups in profile:[/]")
            for group in self.app_groups:
                self.console.print(f"  • {group}")

        if self.icloud_containers:
            self.console.print("[cyan]Found iCloud Containers in profile:[/]")
            for container in self.icloud_containers:
                self.console.print(f"  • {container}")

    def _show_entitlements_mapping(self, original_ents, mapped_ents, removals=None):
        """Display entitlements mapping relationships"""
        self.console.print("[cyan]Original entitlements:[/]")
        self.console.print_json(json.dumps(original_ents, indent=4))

        if removals:
            self.console.print("\n[yellow]Removed entitlements:[/]")
            self.console.print_json(json.dumps(list(removals), indent=4))
            # Filter out removed entitlements
            mapped_ents = {k: v for k, v in mapped_ents.items() if k not in removals}

        self.console.print("\n[cyan]Final mapped entitlements:[/]")
        self.console.print_json(json.dumps(mapped_ents, indent=4))

    def _setup_dylibs(self, app_dir: Path) -> None:
        """Set up dylibs in app bundle before processing"""
        # Create Frameworks directory if it doesn't exist
        frameworks_dir = app_dir / "Frameworks"
        frameworks_dir.mkdir(exist_ok=True)

        # Handle plugins dylib
        if self.patching_options.inject_plugins_patcher:
            plugins_dylib = Path(__file__).parent / "patches" / "pluginsinject.dylib"
            if not plugins_dylib.exists():
                raise ValueError(f"Plugins patcher dylib not found: {plugins_dylib}")

            target_dylib = frameworks_dir / plugins_dylib.name
            if not target_dylib.exists():
                shutil.copy2(plugins_dylib, target_dylib)
                self.console.print(
                    f"[green]Copied {plugins_dylib.name} to Frameworks[/]"
                )

        # Handle home indicator dylib
        if self.patching_options.hide_home_indicator:
            home_dylib = (
                Path(__file__).parent / "patches" / "ForceHideHomeIndicator.dylib"
            )
            if not home_dylib.exists():
                raise ValueError(f"Home indicator dylib not found: {home_dylib}")

            target_dylib = frameworks_dir / home_dylib.name
            if not target_dylib.exists():
                shutil.copy2(home_dylib, target_dylib)
                self.console.print(f"[green]Copied {home_dylib.name} to Frameworks[/]")

    def _analyze_provisioning_profile(self, profile_path: Path) -> tuple[dict, set]:
        """Analyze a provisioning profile and return its entitlements and allowed keys"""
        try:
            self.console.print(
                f"\n[blue]Analyzing provisioning profile:[/] {profile_path}"
            )
            profile_data = dump_prov(profile_path)
            profile_entitlements = profile_data.get("Entitlements", {})

            # Get all entitlement keys from the profile
            allowed_keys = set(profile_entitlements.keys())

            # Check capabilities
            capabilities = check_capabilities(profile_entitlements)

            # Print summaries
            print_capability_summary(self.console, capabilities)
            print_capability_status(self.console, capabilities)

            return profile_entitlements, allowed_keys
        except Exception as e:
            self.console.print(f"[red]Error analyzing provisioning profile: {e}[/red]")
            return {}, set()

    def _filter_entitlements(self, original_ents: dict, allowed_keys: set) -> dict:
        """Filter entitlements to only keep those present in the provisioning profile"""
        filtered = {}
        removed = set()

        for key, value in original_ents.items():
            if key in allowed_keys:
                # Special handling for container-based entitlements
                if key == "com.apple.security.application-groups":
                    if not self.app_groups:
                        removed.add(key)
                        continue
                    # Only keep groups that exist in the profile
                    filtered[key] = [g for g in value if g in self.app_groups]
                    if not filtered[key]:  # If no groups remain, remove the key
                        del filtered[key]
                        removed.add(key)
                elif key in [
                    "com.apple.developer.icloud-container-identifiers",
                    "com.apple.developer.icloud-container-development-container-identifiers",
                    "com.apple.developer.ubiquity-container-identifiers",
                ]:
                    if not self.icloud_containers:
                        removed.add(key)
                        continue
                    # Only keep containers that exist in the profile
                    filtered[key] = [c for c in value if c in self.icloud_containers]
                    if not filtered[key]:  # If no containers remain, remove the key
                        del filtered[key]
                        removed.add(key)
                else:
                    filtered[key] = value
            else:
                removed.add(key)

        if removed:
            self.console.print("\n[yellow]Removing unauthorized entitlements:[/]")
            self.console.print(json.dumps(list(removed), indent=2))

        return filtered

    def _sign_components(
        self,
        inspector: IPAInspector,
        components,
        bundle_mapper,
        temp_path: Path,
    ):
        """Sign all components with proper entitlements"""
        # Update patcher's bundle mapper
        self.patcher.bundle_mapper = bundle_mapper

        # Continue with framework signing
        self.console.print("\n[blue]Signing frameworks[/]")
        # Sort components to prioritize injected dylibs
        framework_components = [c for c in components if not c.is_primary]

        # Define known dylibs
        KNOWN_DYLIBS = {
            "pluginsinject.dylib": "plugins dylib",
            "ForceHideHomeIndicator.dylib": "home indicator dylib",
        }

        # Sort components into dylibs and other frameworks
        dylibs = {
            name: next(
                (c for c in framework_components if c.executable.name == name), None
            )
            for name in KNOWN_DYLIBS.keys()
        }
        other_frameworks = [
            c for c in framework_components if c.executable.name not in KNOWN_DYLIBS
        ]

        # Sign dylibs first
        for dylib_name, component in dylibs.items():
            if component:
                binary_path = inspector.app_dir / component.executable
                self.console.print(
                    f"[blue]Signing {KNOWN_DYLIBS[dylib_name]}:[/] {binary_path}"
                )
                self.cert_handler.sign_binary(binary_path, None, False)

        # Handle remaining frameworks
        for component in other_frameworks:
            binary_path = inspector.app_dir / component.executable
            self.console.print(
                f"[blue]Patching and signing framework:[/] {binary_path}"
            )
            self.patcher.patch_app_binary(binary_path, bundle_mapper)
            self.cert_handler.sign_binary(binary_path, None, False)

        # Sort primary components by path depth (deepest first)
        primary_components = sorted(
            [c for c in components if c.is_primary],
            key=lambda c: len(c.path.parts),
            reverse=True,
        )

        # Sign primary components with their respective entitlements
        for component in primary_components:
            is_main_app = component.path == Path(".")

            # Show component info
            self.console.print(
                f"\n[blue]Signing {'main app' if is_main_app else 'component'}:[/] {component.path}"
            )

            binary_path = inspector.app_dir / component.executable

            # Copy provisioning profile for this component
            component_profile_path = (
                inspector.app_dir / component.path / "embedded.mobileprovision"
            )
            shutil.copy2(self.profile_path, component_profile_path)
            self.console.print(
                f"[green]Copied provisioning profile to:[/] {component_profile_path}"
            )

            # If component has entitlements, filter them based on profile
            if component.entitlements:
                final_ents = self._filter_entitlements(
                    component.entitlements, self.allowed_keys
                )
                # Show mapping of what we're keeping vs original
                self._show_entitlements_mapping(component.entitlements, final_ents)
            else:
                final_ents = self.profile_entitlements

            # Determine if this is the main binary
            is_main_binary = component.path == Path(".")

            # Create temporary entitlements file if we have entitlements
            if final_ents:
                ents_file = (
                    temp_path
                    / f"{'main' if is_main_app else component.path.name}_entitlements.plist"
                )
                with open(ents_file, "wb") as f:
                    plistlib.dump(final_ents, f)
            else:
                ents_file = None

            # Patch and sign binary
            self.patcher.patch_app_binary(
                binary_path,
                bundle_mapper,
                final_ents,
                is_main_binary=is_main_binary,
            )
            self.cert_handler.sign_binary(binary_path, ents_file, True)

    def _package_ipa(self, inspector: IPAInspector, temp_path: Path, output_path: Path):
        """Package the signed IPA"""
        self.patcher.clean_app_bundle(inspector.app_dir)

        # Create proper IPA structure
        self.console.print("\n[blue]Creating signed IPA[/]")

        # Create a temporary Payload directory
        payload_dir = temp_path / "Payload"
        payload_dir.mkdir(exist_ok=True)

        # Move the app into Payload directory
        app_name = inspector.app_dir.name
        shutil.move(str(inspector.app_dir), str(payload_dir / app_name))

        # Create IPA (zip the Payload directory)
        shutil.make_archive(
            output_path.with_suffix(""),
            "zip",
            temp_path,  # Zip from temp dir to include Payload folder
        )
        os.rename(output_path.with_suffix(".zip"), output_path)

        self.console.print(f"[green]Successfully signed IPA:[/] {output_path}")

    def sign_ipa(
        self, ipa_path: Path, output_path: Path, patching_options: PatchingOptions
    ):
        """Sign an IPA file using local mobile provisioning profiles"""
        self.console.print(f"[blue]Signing IPA:[/] {ipa_path}")
        self.patching_options = patching_options

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            with IPAInspector(ipa_path) as inspector:
                # Set up dylibs first if needed
                self._setup_dylibs(inspector.app_dir)

                # Initialize the patcher once with provided options
                self.patcher = AppPatcher(
                    inspector.app_dir,
                    self.patching_options,
                )

                # Get all team IDs from the app
                original_team_ids = inspector.get_team_ids()
                if not original_team_ids:
                    self.console.print(
                        "[red]No team IDs found in the IPA file. This will likely cause issues. Check the IPA file."
                    )

                # Create basic bundle mapper for binary patching
                bundle_mapper = BundleMapping(
                    original_team_ids=original_team_ids,
                    new_team_id=self.team_id,
                    original_base_id=inspector.get_main_app_bundle_id(),
                    randomize=False,
                )

                components = inspector.get_components()

                # Sign components
                self._sign_components(
                    inspector,
                    components,
                    bundle_mapper,
                    temp_path,
                )

                # Package signed IPA
                self._package_ipa(inspector, temp_path, output_path)
