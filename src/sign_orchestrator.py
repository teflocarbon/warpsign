#!/usr/bin/env python3

import os
import sys
from pathlib import Path
import tempfile
from rich.prompt import Confirm, Prompt
import subprocess
import shutil
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from src.ipa_inspector import IPAInspector
from src.bundle_mapper import BundleMapping, IDType
from src.entitlements_processor import EntitlementsProcessor
from src.app_patcher import AppPatcher, PatchingOptions
from src.developer_portal_api import DeveloperPortalAPI
from src.apple_account_login import AppleDeveloperAuth
from src.cert_handler import CertHandler
from src.verification import SigningVerifier
import plistlib
from logger import get_console


class SignOrchestrator:
    def __init__(self, cert_type: str = "development", cert_dir: Path = None):
        """Initialize with optional profile type and certificate configuration"""
        self.console = get_console()
        self.patcher = None
        self.patching_options = None
        self.bundle_mapper = None  # Will be initialized during signing process

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

        self.console.print(f"Using certificate: {cert_name}")
        self.console.print(f"Profile type set to: {self.profile_type}")

        # Get team ID from certificate's Organizational Unit
        self.team_id = self.cert_handler.cert_org_unit
        if not self.team_id:
            self.console.print("[red]Could not determine team ID from certificate")
            sys.exit(1)

        # Initialize authentication and API client
        self._setup_authentication()

    def _setup_authentication(self) -> None:
        """Set up authentication using either session or password."""
        self.auth = AppleDeveloperAuth()

        # Get authentication credentials
        apple_id = os.getenv("APPLE_ID")
        apple_password = os.getenv("APPLE_PASSWORD")
        session_dir = os.getenv("WARPSIGN_SESSION_DIR")

        if not apple_id:
            self.console.print("[red]Error: APPLE_ID environment variable is not set")
            sys.exit(1)

        # Try loading existing session first if session directory is specified
        if session_dir:
            self.console.print(f"Attempting to load session from: {session_dir}")
            self.auth.email = apple_id
            try:
                self.auth.load_session()
                if self.auth.validate_token():
                    self.console.print("[green]Successfully loaded existing session!")
                    self.api = DeveloperPortalAPI(self.auth)
                    return
            except Exception as e:
                self.console.print(f"[yellow]Failed to load session: {e}")

        # Fall back to password auth if no valid session
        if not apple_password:
            self.console.print(
                "[red]Error: No valid session and APPLE_PASSWORD not set"
            )
            sys.exit(1)

        # Authenticate with password
        if not self.auth.authenticate(apple_id, apple_password):
            self.console.print("[red]Authentication failed")
            sys.exit(1)

        self.api = DeveloperPortalAPI(self.auth)

    def _analyze_components(self, inspector: IPAInspector, temp_path: Path):
        """Analyze components and create a single source of truth for bundle mapping"""
        components = inspector.get_components()
        main_bundle_id = inspector.get_main_app_bundle_id()
        original_team_ids = inspector.get_team_ids()

        if not original_team_ids:
            self.console.print(
                "[yellow]⚠️  Warning: No team IDs found in the IPA file. This will likely cause issues. Check the IPA file."
            )

        # Set up bundle mapping with all team IDs and profile type - SINGLE SOURCE OF TRUTH
        self.bundle_mapper = BundleMapping(
            original_team_ids=original_team_ids,
            new_team_id=self.team_id,
            original_base_id=main_bundle_id,
            randomize=self.patching_options.encode_ids,  # Use patching options to determine if we should randomize
        )
        # Apply patching options to bundle mapper
        self.bundle_mapper.force_original_id = self.patching_options.force_original_id
        # Set profile type for aps-environment mapping
        self.bundle_mapper.profile_type = self.profile_type

        # Initialize registered identifiers set in bundle_mapper
        self.bundle_mapper.registered_identifiers = set()

        # Get capabilities data from API
        raw_caps = self.api.fetch_available_user_entitlements(
            self.team_id, return_raw=True
        )
        processor = EntitlementsProcessor(raw_caps, self.profile_type)

        # Collect info
        app_groups = set()
        icloud_containers = set()
        bundle_plans = []  # (component, new_bundle_id, capabilities, removals)

        # Analyze each component and create a single mapping plan
        for component in components:
            if not component.is_primary:
                continue

            # Map bundle ID and analyze entitlements
            new_bundle_id = self.bundle_mapper.map_bundle_id(component.bundle_id)
            capabilities, removals = processor.process_entitlements(
                component.entitlements
            )

            # Extract resources from entitlements
            component_groups, component_containers = (
                self.bundle_mapper.extract_resources_from_entitlements(
                    component.entitlements
                )
            )

            # Add extracted resources to our collections
            app_groups.update(component_groups)
            icloud_containers.update(component_containers)

            # Store component plan
            bundle_plans.append((component, new_bundle_id, capabilities, removals))

        return components, bundle_plans, app_groups, icloud_containers

    def _register_app_resources(
        self,
        inspector: IPAInspector,
        components,
        bundle_plans,
        app_groups,
        icloud_containers,
    ):
        """Register app IDs and resources using the single bundle mapper"""
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
                            for k, v in self.bundle_mapper.mappings.items()
                            if v.new_id == group_id
                        ),
                        None,
                    )
                    if original_id:
                        self.bundle_mapper.registered_identifiers.add(original_id)
                    self.bundle_mapper.registered_identifiers.add(group_id)

        if icloud_containers:
            for container_id in icloud_containers:
                # At this point, all iCloud containers should already have the iCloud. prefix
                # from the proper mapping in _analyze_components
                if not container_id.startswith("iCloud."):
                    self.console.print(
                        f"[red]⚠️ Error: iCloud container without prefix: {container_id}, this should not happen[/]"
                    )
                    # Fix it just in case, but this is an error in our mapping logic
                    container_id = f"iCloud.{container_id.split('.')[-1]}"

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
                            for k, v in self.bundle_mapper.mappings.items()
                            if v.new_id == container_id
                        ),
                        None,
                    )
                    if original_id:
                        self.bundle_mapper.registered_identifiers.add(original_id)
                    self.bundle_mapper.registered_identifiers.add(container_id)

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
                        for k, v in self.bundle_mapper.mappings.items()
                        if v.new_id == new_id
                    ),
                    None,
                )
                if original_id:
                    self.bundle_mapper.registered_identifiers.add(original_id)
                self.bundle_mapper.registered_identifiers.add(new_id)

                # Track team ID mappings
                for orig_team_id in self.bundle_mapper.original_team_ids:
                    if orig_team_id in component.bundle_id:
                        self.bundle_mapper.registered_identifiers.add(orig_team_id)
                        self.bundle_mapper.registered_identifiers.add(self.team_id)

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

                # Set entitlements using the mapped entitlements from our single source of truth
                if component.entitlements:
                    mapped_ents = self.bundle_mapper.map_entitlements(
                        component.entitlements,
                    )

                if not self.api.set_entitlements_for_bundle_id(
                    self.team_id, bundle.id, new_id, caps, group_ids=group_ids
                ):
                    self.console.print(f"[red]Failed to set capabilities for {new_id}")

        # Log registered identifiers for debugging with arrows showing mappings
        self.console.print("\n[blue]Registered identifiers for binary patching:")

        # Display mapping pairs with arrows (avoiding duplicates)
        if (
            hasattr(self.bundle_mapper, "registered_identifiers")
            and self.bundle_mapper.registered_identifiers
        ):
            # Create a dictionary to store unique mappings
            unique_mappings = {}

            # First collect team ID mappings
            for orig_team_id in self.bundle_mapper.original_team_ids:
                if orig_team_id in self.bundle_mapper.registered_identifiers:
                    unique_mappings[orig_team_id] = self.team_id

            # Then collect all other registered mappings
            for original_id in self.bundle_mapper.registered_identifiers:
                # Skip team IDs as we already processed them
                if (
                    original_id in self.bundle_mapper.original_team_ids
                    or original_id == self.team_id
                ):
                    continue

                # Find the mapping for this ID
                mapping = self.bundle_mapper.mappings.get(original_id)
                if mapping and mapping.new_id != original_id:
                    unique_mappings[original_id] = mapping.new_id
                elif original_id in [
                    m.new_id for m in self.bundle_mapper.mappings.values()
                ]:
                    # This is a new ID that was registered
                    # Find its original ID if not already in our mappings
                    for orig, map_obj in self.bundle_mapper.mappings.items():
                        if (
                            map_obj.new_id == original_id
                            and orig not in unique_mappings
                            and orig not in unique_mappings.values()
                        ):
                            unique_mappings[orig] = original_id
                            break

            # Now display the unique mappings in sorted order
            for original_id in sorted(unique_mappings.keys()):
                new_id = unique_mappings[original_id]
                self.console.print(f"[cyan]{original_id}[/] -> [green]{new_id}[/]")
        else:
            self.console.print(
                "[yellow]No registered identifiers found for binary patching[/]"
            )

    def _update_info_plists(self, inspector: IPAInspector, components, bundle_plans):
        """Update Info.plist files using the single bundle mapper"""
        for component in components:
            if not component.is_primary:
                continue

            # Get component's bundle plan
            plan = next((p for p in bundle_plans if p[0] == component), None)
            if not plan:
                continue

            # Update Info.plist using patcher and our single bundle mapper
            info_plist_path = inspector.app_dir / component.path / "Info.plist"
            self.console.print(f"[blue]Updating Info.plist:[/] {info_plist_path}")

            self.patcher.patch_info_plist(
                info_plist_path,
                bundle_mapper=self.bundle_mapper,  # Use our single source of truth
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

    def _ensure_critical_entitlements(self, entitlements: dict, bundle_id: str) -> dict:
        """Check and add critical entitlements if missing"""
        critical_entitlements = {
            "application-identifier": f"{self.team_id}.{bundle_id}",
            "com.apple.developer.team-identifier": self.team_id,
        }

        missing = []
        for key, value in critical_entitlements.items():
            if key not in entitlements:
                missing.append(key)
                entitlements[key] = value

        if missing:
            self.console.print(
                f"[yellow]⚠️  Warning: Critical entitlements were missing: {', '.join(missing)}"
            )
            self.console.print(
                "[yellow]Note: This is unexpected. The application will have no entitlements! Essential entitlements have been automatically added to ensure the app is able to be installed."
            )

        return entitlements

    def _sign_components(
        self, inspector: IPAInspector, components, bundle_plans, temp_path: Path
    ):
        """Sign all components with proper entitlements using the single bundle mapper"""
        # No need to update patcher's bundle mapper as it's already set during creation

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
            self.patcher.patch_app_binary(binary_path, self.bundle_mapper)
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

            # Get the mapped bundle ID that matches the Info.plist
            mapped_bundle_id = self.bundle_mapper.map_bundle_id(component.bundle_id)

            binary_path = inspector.app_dir / component.executable

            # Map and filter entitlements using the consistent bundle ID
            filtered_ents = None
            if component.entitlements:
                # Use the single source of truth for entitlement mapping
                mapped_ents = self.bundle_mapper.map_entitlements(
                    component.entitlements,
                    override_bundle_id=mapped_bundle_id,  # Force use of mapped Info.plist bundle ID
                )
                filtered_ents = {
                    k: v for k, v in mapped_ents.items() if k not in removals
                }

                # Ensure critical entitlements are present - pass full bundle ID
                filtered_ents = self._ensure_critical_entitlements(
                    filtered_ents, mapped_bundle_id
                )

                self._show_entitlements_mapping(
                    component.entitlements, mapped_ents, removals
                )
            else:
                # If no entitlements at all, create minimal set with critical entitlements
                self.console.print(
                    "[yellow]⚠️  Warning: No entitlements found for component, creating minimal set"
                )
                # Pass full bundle ID here too
                filtered_ents = self._ensure_critical_entitlements({}, mapped_bundle_id)

            # Patch and sign binary with consistent bundle ID
            self.patcher.patch_app_binary(
                binary_path,
                self.bundle_mapper,
                filtered_ents,
                is_main_binary=is_main_app,
            )

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

    def _display_mapping_report(self, components):
        """Display a concise report of all ID mappings that will be applied"""
        self.console.print("\n[bold blue]===== ID Mapping Report =====[/]")

        # Display basic configuration
        self.console.print(
            f"[cyan]Team ID:[/] {' '.join(self.bundle_mapper.original_team_ids)} -> [green]{self.team_id}[/]"
        )
        if self.patching_options.force_original_id:
            self.console.print(
                "[yellow]Using original bundle ID in Info.plist for main app[/]"
            )

        # Bundle ID mappings - grouped by component type
        self.console.print("\n[bold cyan]Bundle ID Mappings:[/]")
        for component in [c for c in components if c.is_primary]:
            orig_id = component.bundle_id
            new_id = self.bundle_mapper.map_bundle_id(orig_id)

            # Add note for main app with force_original_id
            is_main_app = component.path == Path(".")
            if is_main_app and self.patching_options.force_original_id:
                display_id = orig_id
                note = " (preserved in Info.plist)"
            else:
                display_id = new_id
                note = ""

            path_display = (
                f"[{component.path}]" if component.path != Path(".") else "[Main App]"
            )
            self.console.print(
                f"{path_display} [cyan]{orig_id}[/] -> [green]{display_id}[/]{note}"
            )

        # Group other mappings by type for cleaner display
        all_mappings = {}
        for orig_id, mapping in self.bundle_mapper.mappings.items():
            # Skip team IDs and primary bundle IDs (already shown)
            if orig_id in self.bundle_mapper.original_team_ids:
                continue
            if orig_id in [c.bundle_id for c in components if c.is_primary]:
                continue

            # Group by type
            id_type = mapping.id_type.name
            if id_type not in all_mappings:
                all_mappings[id_type] = set()  # Use a set to avoid duplicates
            all_mappings[id_type].add((orig_id, mapping.new_id))

        # Display mappings by type (sorted by type name)
        for id_type, mappings in sorted(all_mappings.items()):
            if mappings:
                self.console.print(f"\n[bold cyan]{id_type} Mappings:[/]")
                # Display unique mappings, sorted by original ID
                for orig_id, new_id in sorted(mappings):
                    self.console.print(f"[cyan]{orig_id}[/] -> [green]{new_id}[/]")

        self.console.print("\n[bold blue]=============================\n[/]")

    def sign_ipa(
        self, ipa_path: Path, output_path: Path, patching_options: PatchingOptions
    ):
        """Sign an IPA file using Developer Portal API"""
        self.console.print(f"[blue]Signing IPA:[/] {ipa_path}")
        self.patching_options = patching_options

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            with IPAInspector(ipa_path) as inspector:
                # Set up dylibs first if needed
                self._setup_dylibs(inspector.app_dir)

                # Analyze and create plans - this creates our single source of truth for bundle mapping
                (
                    components,
                    bundle_plans,
                    app_groups,
                    icloud_containers,
                ) = self._analyze_components(inspector, temp_path)

                # Show comprehensive mapping report
                self._display_mapping_report(components)

                # Initialize the patcher with our single bundle mapper
                self.patcher = AppPatcher(
                    inspector.app_dir,
                    self.patching_options,
                    self.bundle_mapper,  # Pass our single source of truth
                )

                # Register app IDs and resources
                self._register_app_resources(
                    inspector,
                    components,
                    bundle_plans,
                    app_groups,
                    icloud_containers,
                )

                # Update Info.plist files
                self._update_info_plists(inspector, components, bundle_plans)

                # Create provisioning profiles
                self._create_provisioning_profiles(inspector, bundle_plans)

                # Sign components
                self._sign_components(
                    inspector,
                    components,
                    bundle_plans,
                    temp_path,
                )

                # Package signed IPA
                self._package_ipa(inspector, temp_path, output_path)

                # Verify the signed IPA
                verifier = SigningVerifier(output_path)
                if verifier.verify_entitlements():
                    self.console.print("[green]✓ Entitlements verification passed")
                else:
                    self.console.print(
                        "[yellow]⚠️  Entitlements verification found issues"
                    )
