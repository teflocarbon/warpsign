#!/usr/bin/env python3

import os
import sys
from pathlib import Path
import tempfile
from rich.console import Console
from rich.prompt import Confirm, Prompt
import subprocess
import shutil
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from ipa_inspector import IPAInspector
from bundle_mapper import BundleMapping, IDType
from entitlements_processor import EntitlementsProcessor
from app_patcher import AppPatcher, PatchingOptions
from developer_portal_api import DeveloperPortalAPI
from apple_account_login import AppleDeveloperAuth
from cert_handler import CertHandler
import plistlib


class LocalSigner:
    def __init__(self, profile_type: str = "development"):
        """Initialize with optional profile type (development or adhoc)"""
        self.console = Console()
        self.patcher = None  # Will be initialized in sign_ipa
        self.patching_options = None  # Will be set in sign_ipa

        # Initialize cert handler first since we need certificate info
        self.cert_handler = CertHandler()

        # Determine profile type based on certificate type
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

        self.console.print(f"Using certificate: {cert_name}")
        self.console.print(f"Profile type set to: {self.profile_type}")

        # Get team ID from certificate's Organizational Unit
        self.team_id = self.cert_handler.cert_org_unit
        if not self.team_id:
            self.console.print("[red]Could not determine team ID from certificate")
            sys.exit(1)

        # Initialize auth and API client
        self.auth = AppleDeveloperAuth()
        if not self.auth.authenticate(
            os.getenv("APPLE_ID"), os.getenv("APPLE_PASSWORD")
        ):
            self.console.print("[red]Authentication failed")
            sys.exit(1)

        self.api = DeveloperPortalAPI(self.auth)

    def _analyze_components(self, inspector: IPAInspector, temp_path: Path):
        """Analyze components and create bundle mapping plans"""
        components = inspector.get_components()
        main_bundle_id = inspector.get_main_app_bundle_id()
        original_team_ids = (
            inspector.get_team_ids()
        )  # Get all team IDs, there can be multiple.. for some reason..

        if not original_team_ids:
            Console().print(
                "[red]No team IDs found in the IPA file. This will likely cause issues. Check the IPA file."
            )

        # Set up bundle mapping with all team IDs
        bundle_mapper = BundleMapping(
            original_team_ids=original_team_ids,
            new_team_id=self.team_id,
            original_base_id=main_bundle_id,
            randomize=True,  # We can't sign with the original ID, so we randomize.
        )

        # Get capabilities data from API
        raw_caps = self.api.fetch_available_user_entitlements(
            self.team_id, return_raw=True
        )
        processor = EntitlementsProcessor(raw_caps, self.profile_type)

        # Collect info
        app_groups = set()
        icloud_containers = set()
        bundle_plans = []  # (component, new_bundle_id, capabilities, removals)

        # Analyze each component
        for component in components:
            if not component.is_primary:
                continue

            # Map bundle ID and analyze entitlements
            new_bundle_id = bundle_mapper.map_bundle_id(component.bundle_id)
            capabilities, removals = processor.process_entitlements(
                component.entitlements
            )

            # Collect groups and containers from entitlements
            for key, value in component.entitlements.items():
                if key == "com.apple.security.application-groups":
                    if isinstance(value, list):
                        for group in value:
                            # Use map_bundle_id for consistency
                            mapped_group = bundle_mapper.map_bundle_id(group)
                            app_groups.add(mapped_group)
                elif key in [
                    "com.apple.developer.icloud-container-identifiers",
                    "com.apple.developer.ubiquity-container-identifiers",
                ]:
                    if isinstance(value, list):
                        for container in value:
                            # Use map_bundle_id for consistency
                            mapped_container = bundle_mapper.map_bundle_id(container)
                            icloud_containers.add(mapped_container)

            # Store component plan
            bundle_plans.append((component, new_bundle_id, capabilities, removals))

        return components, bundle_mapper, bundle_plans, app_groups, icloud_containers

    def _register_app_resources(
        self,
        inspector: IPAInspector,
        components,
        bundle_plans,
        app_groups,
        icloud_containers,
        bundle_mapper,
    ):
        """Register app IDs and resources"""
        # Initialize registered identifiers set in bundle_mapper
        bundle_mapper.registered_identifiers = set()

        # Show registration summary first
        self.console.print("\n[blue][bold]Registration Summary[/]")
        if app_groups:
            self.console.print("[cyan]App Groups to Register:[/]", app_groups)
        if icloud_containers:
            self.console.print(
                "[cyan]iCloud Containers to Register:[/]", icloud_containers
            )

        # Track registered resources
        registered_groups = []
        registered_containers = []

        # Register shared resources first
        if app_groups:
            for group_id in app_groups:
                group = self.api.register_app_group(
                    self.team_id,
                    group_id,
                    f"WS App Group {group_id.replace('.', ' ')}",
                )
                if group:
                    registered_groups.append(group)
                    # Track the original and new group IDs
                    original_id = next(
                        (
                            k
                            for k, v in bundle_mapper.mappings.items()
                            if v.new_id == group_id
                        ),
                        None,
                    )
                    if original_id:
                        bundle_mapper.registered_identifiers.add(original_id)
                    bundle_mapper.registered_identifiers.add(group_id)

        if icloud_containers:
            for container_id in icloud_containers:
                container = self.api.register_icloud_container(
                    self.team_id,
                    container_id,
                    f"WS iCloud Container {container_id.replace('.', ' ')}",
                )
                if container:
                    registered_containers.append(container)
                    # Track the original and new container IDs
                    original_id = next(
                        (
                            k
                            for k, v in bundle_mapper.mappings.items()
                            if v.new_id == container_id
                        ),
                        None,
                    )
                    if original_id:
                        bundle_mapper.registered_identifiers.add(original_id)
                    bundle_mapper.registered_identifiers.add(container_id)

        # Register each app ID and set its capabilities
        for component, new_id, caps, _ in bundle_plans:
            if not component.is_primary:
                continue

            self.console.print(f"\n[yellow]Component:[/] {component.path}")
            self.console.print(f"[cyan]Bundle ID:[/] {new_id}")
            if caps:
                self.console.print(f"[cyan]Capabilities to Enable:[/] {sorted(caps)}")

            # Register the bundle ID
            display_name = "App Extension" if component.path != Path(".") else "App"
            bundle = self.api.register_bundle_id(
                self.team_id,
                new_id,
                f"WS {display_name} {new_id.split('.')[-1].replace('.', ' ')}",
            )

            if bundle:
                # Track the original and new bundle IDs
                original_id = next(
                    (
                        k
                        for k, v in bundle_mapper.mappings.items()
                        if v.new_id == new_id
                    ),
                    None,
                )
                if original_id:
                    bundle_mapper.registered_identifiers.add(original_id)
                bundle_mapper.registered_identifiers.add(new_id)

                # Track team ID mappings
                for orig_team_id in bundle_mapper.original_team_ids:
                    if orig_team_id in component.bundle_id:
                        bundle_mapper.registered_identifiers.add(orig_team_id)
                        bundle_mapper.registered_identifiers.add(self.team_id)

            else:
                self.console.print(
                    f"[red]Failed to register or find bundle ID: {new_id}"
                )
                continue

            # Set capabilities and associate resources
            if caps:
                # Create mapping of groups/containers for capabilities that need them
                group_ids = {}
                if "APP_GROUPS" in caps and registered_groups:
                    group_ids["APP_GROUPS"] = [g.id for g in registered_groups]
                if "ICLOUD" in caps and registered_containers:
                    group_ids["ICLOUD"] = [c.id for c in registered_containers]

                # Set entitlements
                if component.entitlements:
                    mapped_ents = bundle_mapper.map_entitlements(
                        component.entitlements,
                        force_original_id=False,  # This must be false, otherwise we'll try to sign with the original ID.
                    )
                if not self.api.set_entitlements_for_bundle_id(
                    self.team_id, bundle.id, new_id, caps, group_ids=group_ids
                ):
                    self.console.print(f"[red]Failed to set capabilities for {new_id}")

        # Log registered identifiers for debugging
        self.console.print("\n[blue]Registered identifiers for binary patching:")
        self.console.print(sorted(bundle_mapper.registered_identifiers))

    def _update_info_plists(
        self, inspector: IPAInspector, components, bundle_plans, bundle_mapper
    ):
        """Update Info.plist files with new bundle IDs and settings"""
        for component in components:
            if not component.is_primary:
                continue

            # Get component's bundle plan
            plan = next((p for p in bundle_plans if p[0] == component), None)
            if not plan:
                continue

            # Update Info.plist using patcher
            info_plist_path = inspector.app_dir / component.path / "Info.plist"
            self.console.print(f"[blue]Updating Info.plist:[/] {info_plist_path}")

            # Use the shared patcher instance
            self.patcher.patch_info_plist(
                info_plist_path,
                bundle_mapper=bundle_mapper,
                is_main_app=(component.path == Path(".")),
            )

    def _create_provisioning_profiles(
        self,
        inspector: IPAInspector,
        bundle_plans,
    ):
        """Create and install provisioning profiles"""
        for component, new_id, caps, _ in bundle_plans:
            if not component.is_primary:
                continue

            # Get the bundle ID resource
            bundle = next(
                b
                for b in self.api.list_bundle_ids(self.team_id)
                if b.identifier == new_id
            )

            # Create profile name with proper type
            profile_type = (
                "Development" if self.profile_type == "development" else "Ad Hoc"
            )
            profile_name = f"TS {new_id} {profile_type}"
            self.console.print(f"\n[blue]Creating profile:[/] {profile_name}")

            # Get devices and find matching certificate
            devices = [d.id for d in self.api.list_devices(self.team_id)]
            certs = [
                c
                for c in self.api.list_certificates(self.team_id)
                if c.serial_number == self.cert_handler.cert_serial
            ]
            if not certs:
                raise Exception(
                    f"Certificate with serial {self.cert_handler.cert_serial} not found"
                )

            # Create profile with proper distribution type
            profile_content = self.api.create_or_regen_provisioning_profile(
                team_id=self.team_id,
                profile_id="",  # Empty for new profile
                app_id_id=bundle.id,
                profile_name=profile_name,
                certificate_ids=[certs[0].id],
                device_ids=devices,
                distribution_type=self.profile_type,  # Use the selected profile type
            )

            # Save profile
            component_path = inspector.app_dir / component.path
            if component.path == Path("."):
                profile_path = inspector.app_dir / "embedded.mobileprovision"
            else:
                profile_path = component_path / "embedded.mobileprovision"

            with open(profile_path, "wb") as f:
                f.write(profile_content)
            self.console.print(f"[green]Profile saved:[/] {profile_path}")

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

    def _sign_components(
        self,
        inspector: IPAInspector,
        components,
        bundle_plans,
        bundle_mapper,
        temp_path: Path,
    ):
        """Sign all components with proper entitlements"""
        # Update patcher's bundle mapper
        self.patcher.bundle_mapper = bundle_mapper

        self.console.print("\n[blue]Signing frameworks[/]")
        # Sort components to prioritize pluginsinject.dylib
        framework_components = [c for c in components if not c.is_primary]
        plugins_dylib = next(
            (
                c
                for c in framework_components
                if c.executable.name == "pluginsinject.dylib"
            ),
            None,
        )
        other_frameworks = [
            c
            for c in framework_components
            if c.executable.name != "pluginsinject.dylib"
        ]

        # Handle plugins dylib first if present
        if plugins_dylib:
            binary_path = inspector.app_dir / plugins_dylib.executable
            self.console.print(f"[blue]Signing plugins dylib:[/] {binary_path}")
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

        # Sign all components in order
        for component in primary_components:
            # Get component's plan
            plan = next((p for p in bundle_plans if p[0] == component), None)
            if not plan:
                continue

            _, new_id, _, removals = plan
            is_main_app = component.path == Path(".")

            # Show component info
            self.console.print(
                f"\n[blue]Signing {'main app' if is_main_app else 'component'}:[/] {component.path}"
            )

            if component.entitlements:
                mapped_ents = bundle_mapper.map_entitlements(
                    component.entitlements,
                    force_original_id=True,
                )
                self._show_entitlements_mapping(
                    component.entitlements, mapped_ents, removals
                )

            binary_path = inspector.app_dir / component.executable

            # Map and filter entitlements
            filtered_ents = None
            if component.entitlements:
                mapped_ents = bundle_mapper.map_entitlements(component.entitlements)
                filtered_ents = {
                    k: v for k, v in mapped_ents.items() if k not in removals
                }

            # Patch and sign binary
            self.patcher.patch_app_binary(binary_path, bundle_mapper, filtered_ents)

            if filtered_ents:
                ents_file = (
                    temp_path
                    / f"{'main' if is_main_app else component.path.name}_entitlements.plist"
                )
                with open(ents_file, "wb") as f:
                    plistlib.dump(filtered_ents, f)
                self.cert_handler.sign_binary(binary_path, ents_file, True)
            else:
                self.cert_handler.sign_binary(binary_path, None, True)

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

    def _setup_plugins_dylib(self, app_dir: Path) -> None:
        """Set up plugins dylib in app bundle before processing"""
        if not self.patching_options.inject_plugins_patcher:
            return

        plugins_dylib = Path(__file__).parent / "patches" / "pluginsinject.dylib"
        if not plugins_dylib.exists():
            raise ValueError(f"Plugins patcher dylib not found: {plugins_dylib}")

        # Create Frameworks directory if it doesn't exist
        frameworks_dir = app_dir / "Frameworks"
        frameworks_dir.mkdir(exist_ok=True)

        # Copy dylib to Frameworks
        dylib_name = plugins_dylib.name
        target_dylib = frameworks_dir / dylib_name
        if not target_dylib.exists():
            shutil.copy2(plugins_dylib, target_dylib)
            self.console.print(f"[green]Copied {dylib_name} to Frameworks[/]")

    def sign_ipa(
        self, ipa_path: Path, output_path: Path, patching_options: PatchingOptions
    ):
        """Sign an IPA file using Developer Portal API"""
        self.console.print(f"[blue]Signing IPA:[/] {ipa_path}")
        self.patching_options = patching_options

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            with IPAInspector(ipa_path) as inspector:
                # Set up plugins dylib first if needed
                if self.patching_options.inject_plugins_patcher:
                    self._setup_plugins_dylib(inspector.app_dir)

                # Initialize the patcher once with provided options
                self.patcher = AppPatcher(
                    inspector.app_dir,
                    self.patching_options,
                )

                # Analyze and create plans
                (
                    components,
                    bundle_mapper,
                    bundle_plans,
                    app_groups,
                    icloud_containers,
                ) = self._analyze_components(inspector, temp_path)

                # Register app IDs and resources
                self._register_app_resources(
                    inspector,
                    components,
                    bundle_plans,
                    app_groups,
                    icloud_containers,
                    bundle_mapper,
                )

                # Update Info.plist files
                self._update_info_plists(
                    inspector, components, bundle_plans, bundle_mapper
                )

                # Create provisioning profiles.
                self._create_provisioning_profiles(inspector, bundle_plans)

                # Sign components
                self._sign_components(
                    inspector,
                    components,
                    bundle_plans,
                    bundle_mapper,
                    temp_path,
                )

                # Package signed IPA, sealing it with a kiss.
                self._package_ipa(inspector, temp_path, output_path)
