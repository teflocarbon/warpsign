from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Set, Optional, Union
import plistlib
import subprocess
import shutil
from collections import OrderedDict
import lief
from lief import MachO
from enum import Enum, auto
from warpsign.logger import get_console

from warpsign.src.utils.icon_handler import IconHandler
from warpsign.src.core.bundle_mapper import BundleMapping, IDType


class StatusBarStyle(Enum):
    DEFAULT = "default"  # Don't modify
    HIDDEN = "hidden"  # Hide status bar
    LIGHT = "light"  # Light status bar for dark backgrounds
    DARK = "dark"  # Dark status bar for light backgrounds


class UIStyle(Enum):
    AUTOMATIC = "automatic"
    LIGHT = "light"
    DARK = "dark"


@dataclass
class PatchingOptions:
    """Configuration for app patching"""

    # Bundle identity
    bundle_id: Optional[str] = None  # New bundle ID (None = keep original)
    bundle_name: Optional[str] = None  # New display name (None = keep original)

    # ID handling
    encode_ids: bool = False  # Generate unique IDs
    patch_ids: bool = True  # Patch IDs into binaries
    force_original_id: bool = False  # Keep original bundle ID in Info.plist

    # Additional features
    patch_debug: bool = False  # Enable app debugging
    patch_all_devices: bool = False  # Support all devices
    patch_file_sharing: bool = False  # Enable file sharing
    patch_promotion: bool = False  # Enable ProMotion/120Hz
    patch_fullscreen: bool = False  # Force fullscreen on iPad
    patch_orientation: bool = False  # Force orientation support
    patch_game_mode: bool = False  # Enable game mode support
    icon_path: Optional[Path] = None  # New icon path (None = keep original)
    patch_status_bar: StatusBarStyle = StatusBarStyle.DEFAULT  # Status bar appearance
    patch_user_interface_style: UIStyle = UIStyle.AUTOMATIC  # Force UI style
    remove_url_schemes: bool = False  # Remove URL schemes registration

    # Plugins patcher
    inject_plugins_patcher: bool = False  # Enable plugins patcher injection
    hide_home_indicator: bool = False  # Hide home indicator on iPhone X and newer


class OrderPreservingDict(OrderedDict):
    """Special dictionary that preserves key order for plists"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __eq__(self, other):
        if isinstance(other, dict):
            return dict(self) == dict(other)
        return super().__eq__(other)


class AppPatcher:
    """Handles various app binary and plist patching operations"""

    def __init__(
        self,
        app_dir: Path,
        opts: PatchingOptions,
        bundle_mapper: Optional[BundleMapping] = None,
    ):
        self.app_dir = app_dir
        self.opts = opts
        self.console = get_console()
        self.bundle_mapper = bundle_mapper
        self.plugins_dylib = (
            Path(__file__).parent.parent / "patches" / "pluginsinject.dylib"
        )
        self.home_indicator_dylib = (
            Path(__file__).parent.parent / "patches" / "ForceHideHomeIndicator.dylib"
        )

        self.icon_handler = IconHandler()
        if opts.inject_plugins_patcher and not self.plugins_dylib.exists():
            raise ValueError(f"Plugins patcher dylib not found: {self.plugins_dylib}")

    def clean_app_bundle(self, app_dir: Path) -> None:
        """Remove unnecessary app bundle components"""
        self.console.log("[blue]Cleaning app bundle[/]")

        # Currently breaks codesigning as we're manipulating the codesignature afterwards.
        # We need to do this way earlier, not at the end.

        # Remove Watch app placeholder
        # for watch_name in ["com.apple.WatchPlaceholder", "Watch"]:
        #     watch_dir = app_dir / watch_name
        #     if watch_dir.exists():
        #         self.console.log(f"[green]Removing Watch placeholder:[/] {watch_dir}")
        #         shutil.rmtree(watch_dir)

        # Remove AppStore DRM leftovers

        sc_info = app_dir / "SC_Info"
        if sc_info.exists():
            self.console.log("[yellow]Warning: Found AppStore DRM metadata[/]")
            self.console.log("[yellow]Removing SC_Info - app may not be encrypted[/]")
            shutil.rmtree(sc_info)

    def _filter_replacements(self, replacements: Dict[str, str]) -> Dict[str, str]:
        """Filter replacement patterns based on configuration"""
        if not self.opts.force_original_id:
            return replacements

        filtered = {}
        original_bundle_id = getattr(self, "main_bundle_id", "")

        # Get original team IDs from bundle mapper if available
        original_team_ids = set()
        if hasattr(self, "bundle_mapper") and hasattr(
            self.bundle_mapper, "original_team_ids"
        ):
            original_team_ids = set(self.bundle_mapper.original_team_ids)

        for k, v in replacements.items():
            if (
                k.startswith(("iCloud.", "group."))  # iCloud and group IDs
                or (k.isupper() and k.isalnum() and len(k) == 10)  # Team IDs format
                or any(tid in k for tid in original_team_ids)  # Known team IDs
                or (
                    original_bundle_id and not k.startswith(original_bundle_id)
                )  # Non-bundle IDs
            ):
                filtered[k] = v

        return filtered

    def _get_allowed_id_types(self) -> Set[IDType]:
        """Get allowed ID types based on patching options"""
        # Always allow these types, regardless of force_original_id
        return {IDType.ICLOUD, IDType.KEYCHAIN, IDType.APP_GROUP}

    def patch_info_plist(
        self,
        info_plist: Path,
        bundle_mapper: Optional[BundleMapping] = None,
        is_main_app: bool = False,
    ) -> Dict:
        """Patch an Info.plist with configured options"""
        self.console.log(f"[blue]Patching Info.plist:[/] {info_plist}")

        with open(info_plist, "rb") as f:
            info = plistlib.load(f, dict_type=OrderPreservingDict)

        # Handle bundle mapping first (existing code)
        if bundle_mapper:
            # Handle bundle identifier
            if "CFBundleIdentifier" in info:
                old_bundle_id = info["CFBundleIdentifier"]
                id_type = bundle_mapper.detect_id_type(old_bundle_id)

                if id_type == IDType.BUNDLE and self.opts.force_original_id:
                    self.console.log(
                        "[yellow]Keeping original bundle identifier in Info.plist"
                    )
                    if is_main_app:
                        self.main_bundle_id = old_bundle_id
                else:
                    new_bundle_id = bundle_mapper.map_id(old_bundle_id, id_type)
                    info["CFBundleIdentifier"] = new_bundle_id
                    if is_main_app:
                        self.main_bundle_id = new_bundle_id

            # Handle associated domains and other identifiers
            for key, id_type in [
                ("com.apple.developer.associated-domains", IDType.BUNDLE),
                ("com.apple.security.application-groups", IDType.APP_GROUP),
                ("keychain-access-groups", IDType.KEYCHAIN),
                ("com.apple.developer.icloud-container-identifiers", IDType.ICLOUD),
            ]:
                if key in info:
                    values = info[key] if isinstance(info[key], list) else [info[key]]
                    if id_type in self._get_allowed_id_types():
                        info[key] = [bundle_mapper.map_id(v, id_type) for v in values]

        # Only apply device and file sharing patches to main app bundle
        # This can corrupt the plist for extensions and other bundles!
        if is_main_app:
            # Change icon if specified
            if self.opts.icon_path:
                if self.icon_handler.update_app_icon(
                    self.app_dir, self.opts.icon_path, info
                ):
                    self.console.log("[green]Successfully updated app icon")
                else:
                    self.console.log("[yellow]Failed to update app icon")

            # Change bundle display name if specified
            if self.opts.bundle_name:
                self.console.log(
                    f"[green]Setting app display name to:[/] {self.opts.bundle_name}"
                )
                info["CFBundleDisplayName"] = self.opts.bundle_name
                info["CFBundleName"] = self.opts.bundle_name

            # Device support patches
            if self.opts.patch_all_devices:
                self.console.log("[green]Enabling support for all devices")
                if "UISupportedDevices" in info:
                    self.console.log("[yellow]Removing UISupportedDevices restriction")
                    info.pop("UISupportedDevices")

                old_families = info.get("UIDeviceFamily", [1])
                info["UIDeviceFamily"] = [1, 2]  # iOS and iPadOS
                self.console.log(
                    f"[green]Setting UIDeviceFamily:[/] {old_families} -> [1, 2]"
                )

                old_min_ver = info.get("MinimumOSVersion", "Unknown")
                info["MinimumOSVersion"] = "10.0"
                self.console.log(
                    f"[green]Setting MinimumOSVersion:[/] {old_min_ver} -> 10.0"
                )

            # File sharing patches
            if self.opts.patch_file_sharing:
                self.console.log("[green]Enabling file sharing support")
                old_sharing = info.get("UIFileSharingEnabled", False)
                old_browser = info.get("UISupportsDocumentBrowser", False)
                old_inplace = info.get("LSSupportsOpeningDocumentsInPlace", False)

                info["UIFileSharingEnabled"] = True
                info["UISupportsDocumentBrowser"] = True
                info["LSSupportsOpeningDocumentsInPlace"] = True

                self.console.log(
                    f"[green]Setting UIFileSharingEnabled:[/] {old_sharing} -> True"
                )
                self.console.log(
                    f"[green]Setting UISupportsDocumentBrowser:[/] {old_browser} -> True"
                )
                self.console.log(
                    f"[green]Setting LSSupportsOpeningDocumentsInPlace:[/] {old_inplace} -> True"
                )

            # ProMotion / High Refresh Rate Support
            if self.opts.patch_promotion:
                self.console.log("[green]Enabling ProMotion/120Hz support")
                info["CADisableMinimumFrameDurationOnPhone"] = True
                info["CAHighFrameRateDisplay"] = True

            # Force iPad Fullscreen Mode
            if self.opts.patch_fullscreen:
                self.console.log("[green]Forcing iPad fullscreen mode")
                info["UIRequiresFullScreen"] = True
                info["UIStatusBarHidden"] = True
                info["UIViewControllerBasedStatusBarAppearance"] = False

            # Force iPhone/iPad Orientation
            if self.opts.patch_orientation:
                self.console.log("[green]Setting supported orientations")
                info["UISupportedInterfaceOrientations"] = [
                    "UIInterfaceOrientationPortrait",
                    "UIInterfaceOrientationLandscapeLeft",
                    "UIInterfaceOrientationLandscapeRight",
                    "UIInterfaceOrientationPortraitUpsideDown",
                ]
                # iPad-specific orientations
                info["UISupportedInterfaceOrientations~ipad"] = [
                    "UIInterfaceOrientationPortrait",
                    "UIInterfaceOrientationLandscapeLeft",
                    "UIInterfaceOrientationLandscapeRight",
                    "UIInterfaceOrientationPortraitUpsideDown",
                ]

            # Enable Game Mode Support
            if self.opts.patch_game_mode:
                self.console.log("[green]Enabling Game Mode support")
                info["GCSupportsGameMode"] = True

            # Status Bar Appearance
            if self.opts.patch_status_bar != StatusBarStyle.DEFAULT:
                self.console.log(
                    f"[green]Setting status bar style: {self.opts.patch_status_bar.value}"
                )
                if self.opts.patch_status_bar == StatusBarStyle.HIDDEN:
                    info["UIViewControllerBasedStatusBarAppearance"] = False
                    info["UIStatusBarHidden"] = True
                elif self.opts.patch_status_bar == StatusBarStyle.LIGHT:
                    info["UIViewControllerBasedStatusBarAppearance"] = False
                    info["UIStatusBarStyle"] = "UIStatusBarStyleLightContent"
                elif self.opts.patch_status_bar == StatusBarStyle.DARK:
                    info["UIViewControllerBasedStatusBarAppearance"] = False
                    info["UIStatusBarStyle"] = "UIStatusBarStyleDarkContent"

            # User Interface Style
            if self.opts.patch_user_interface_style != UIStyle.AUTOMATIC:
                self.console.log(
                    f"[green]Setting UI style: {self.opts.patch_user_interface_style.value}"
                )
                style_value = (
                    "Light"
                    if self.opts.patch_user_interface_style == UIStyle.LIGHT
                    else "Dark"
                )
                info["UIUserInterfaceStyle"] = style_value

            # Remove URL schemes if specified
            if self.opts.remove_url_schemes and "CFBundleURLTypes" in info:
                self.console.log("[green]Removing URL schemes registration")
                info.pop("CFBundleURLTypes")

        # Write changes back
        with open(info_plist, "wb") as f:
            plistlib.dump(info, f, sort_keys=False)

        # Rest of the existing code for binary patches
        if self.opts.patch_ids and bundle_mapper:
            replacements = bundle_mapper.get_binary_patches()
            if replacements:
                filtered_replacements = self._filter_replacements(replacements)
                if filtered_replacements:
                    self.console.log(
                        f"[blue]Binary patching Info.plist:[/] {info_plist}"
                    )
                    total_replacements = 0

                    # Sort by decreasing length to avoid partial matches
                    patterns = sorted(
                        filtered_replacements.items(),
                        key=lambda x: len(x[0]),
                        reverse=True,
                    )

                    for old, new in patterns:
                        self.console.log(f"[green]Replacing:[/] {old} -> {new}")
                        count = self.binary_replace(f"s/{old}/{new}/g", info_plist)
                        total_replacements += count
                        self.console.log(f"[blue]Made {count} replacements[/]")
                    self.console.log(
                        f"[blue]Total replacements in plist:[/] {total_replacements}"
                    )

        return info

    def binary_replace(self, pattern: str, file: Path) -> int:
        """Replace binary patterns in file and return count of replacements"""
        if not file.exists() or not file.is_file():
            raise Exception(f"File does not exist or is not a file: {file}")

        # Parse the perl-style pattern
        if not pattern.startswith("s/") or pattern.count("/") != 3:
            raise ValueError(f"Invalid pattern format: {pattern}")
        _, old, new, flags = pattern.split("/")

        # Read file as binary
        with open(file, "rb") as f:
            content = f.read()

        # Convert strings to bytes for binary replacement
        old_bytes = old.encode("utf-8")
        new_bytes = new.encode("utf-8")

        if len(old_bytes) != len(new_bytes):
            raise ValueError(
                f"Replacement lengths must match: {old} ({len(old_bytes)}) -> {new} ({len(new_bytes)})"
            )

        # Count occurrences before replacement
        count = content.count(old_bytes)

        if count > 0:
            # Perform replacement
            new_content = content.replace(old_bytes, new_bytes)

            # Write back only if changes were made
            with open(file, "wb") as f:
                f.write(new_content)

        return count

    def patch_binary(
        self,
        binary: Path,
        bundle_mapper: Union[BundleMapping, Dict[str, str]],
        entitlements: Dict = None,
    ) -> None:
        """Patch binary patterns in executable"""
        if not self.opts.patch_ids:
            self.console.log("[yellow]Binary patching disabled - skipping")
            return

        # Get filtered replacements
        if isinstance(bundle_mapper, BundleMapping):
            replacements = bundle_mapper.get_binary_patches()
        else:
            replacements = bundle_mapper

        # Apply the same filtering logic as used for plists
        filtered_patches = self._filter_replacements(replacements)

        # Verify all replacements are same length
        invalid = [
            f"{k} -> {v}" for k, v in filtered_patches.items() if len(k) != len(v)
        ]
        if invalid:
            raise ValueError(f"Replacement length mismatch: {', '.join(invalid)}")

        # Sort by decreasing length to avoid partial matches
        patterns = sorted(
            filtered_patches.items(), key=lambda x: len(x[0]), reverse=True
        )

        total_replacements = 0
        for old, new in patterns:
            self.console.log(f"[green]Replacing:[/] {old} -> {new}")
            count = self.binary_replace(f"s/{old}/{new}/g", binary)
            total_replacements += count
            self.console.log(f"[blue]Made {count} replacements[/]")

        self.console.log(f"[blue]Total replacements in binary:[/] {total_replacements}")

    def inject_dylib_with_lief(self, binary_path: Path, dylib_name: str) -> None:
        """Inject a dylib into a Mach-O binary using LIEF"""
        self.console.log(f"[blue]Injecting {dylib_name} with LIEF[/]")

        # Parse binary
        parsed = MachO.parse(str(binary_path))

        # Handle fat binary
        if isinstance(parsed, MachO.FatBinary):
            self.console.log("[blue]Found Fat Binary - processing all architectures")
            binaries = [parsed.at(i) for i in range(parsed.size)]
        else:
            binaries = [parsed]

        # Process each binary
        for binary in binaries:
            # Check encryption status
            if binary.has_encryption_info and binary.encryption_info.crypt_id != 0:
                self.console.log("[red]Error: Binary is encrypted![/]")
                self.console.log(
                    "[yellow]App must be decrypted first (check AppStore DRM)"
                )
                raise ValueError("Cannot modify encrypted binary")
            else:
                self.console.log("[green]Binary is not encrypted, proceeding")

            # Print and verify @rpath configuration
            rpath_found = False
            for rpath in binary.rpaths:
                if rpath.path == "@executable_path/Frameworks":
                    rpath_found = True

            if not rpath_found:
                dylib_path = f"@executable_path/Frameworks/{dylib_name}"
            else:
                dylib_path = f"@rpath/{dylib_name}"

            # Add LC_LOAD_DYLIB command using the determined rpath
            binary.add_library(dylib_path)

        # Write modified binary
        parsed.write(str(binary_path))
        self.console.log(f"[green]Injected {dylib_path} successfully[/]")

    def patch_app_binary(
        self,
        app_binary: Path,
        bundle_mapper: Optional[BundleMapping] = None,
        entitlements: Optional[Dict] = None,
        is_main_binary: bool = False,
    ) -> None:
        """Patch the main app binary"""
        self.console.log(
            f"[blue]Patching {'main' if is_main_binary else 'secondary'} binary:[/] {app_binary}"
        )

        # Update entitlements if provided
        if entitlements is not None:
            # Handle debug entitlement
            if self.opts.patch_debug:
                self.console.log("[green]Enabling app debugging")
                entitlements["get-task-allow"] = True
            else:
                self.console.log("[yellow]App debugging disabled")
                entitlements.pop("get-task-allow", None)

            # Write updated entitlements
            entitlements_path = app_binary.parent / "entitlements.plist"
            with open(entitlements_path, "wb") as f:
                plistlib.dump(entitlements, f)

        # Apply ID replacements if needed
        if self.opts.patch_ids and bundle_mapper:
            # Get patches from bundle mapper
            replacements = bundle_mapper.get_binary_patches()
            if replacements:
                self.patch_binary(app_binary, replacements)

        # Inject plugins patcher dylib if enabled (into all binaries)
        if self.opts.inject_plugins_patcher:
            dylib_name = self.plugins_dylib.name
            try:
                self.inject_dylib_with_lief(app_binary, dylib_name)
            except Exception as e:
                self.console.log(f"[red]Failed to inject plugins dylib: {e}[/]")
                raise

        # Inject home indicator dylib if enabled (only into main binary)
        if is_main_binary and self.opts.hide_home_indicator:
            dylib_name = self.home_indicator_dylib.name
            try:
                self.inject_dylib_with_lief(app_binary, dylib_name)
            except Exception as e:
                self.console.log(f"[red]Failed to inject home indicator dylib: {e}[/]")
                raise
