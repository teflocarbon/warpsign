#!/usr/bin/env python3

from pathlib import Path
import plistlib
import tempfile
import zipfile
import subprocess
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass


@dataclass
class AppComponent:
    """Represents a signable component in the app bundle"""

    path: Path  # Path relative to app root
    bundle_id: str  # Bundle identifier
    executable: Path  # Path to main executable
    entitlements: Dict[Any, Any]  # Current entitlements
    info_plist: Dict[Any, Any]  # Info.plist contents
    is_primary: bool  # True for .app/.appex, False for frameworks/dylibs

    def __post_init__(self):
        """Determine if this is a primary component needing full signing"""
        # Primary: main app binary or app extensions
        self.is_primary = (
            self.path == Path(".")  # Main app binary
            or self.path.suffix == ".appex"  # App extension
            or any(
                p.suffix == ".appex" for p in self.path.parents
            )  # Inside app extension
        )

        # Secondary: frameworks, dylibs, bundles get simple signing
        # No need to explicitly set False as it's the default.


def decode_clean(b: bytes) -> str:
    """Clean up command output"""
    return "" if not b else b.decode("utf-8").strip()


def run_process(
    *cmd: str, capture_output: bool = True, check: bool = True
) -> subprocess.CompletedProcess:
    """Run a process and return its output"""
    try:
        return subprocess.run(
            cmd, capture_output=capture_output, check=check, text=True
        )
    except subprocess.CalledProcessError as e:
        raise Exception(
            f"Process {cmd[0]} failed with status {e.returncode}\nOutput: {e.stdout}\nError: {e.stderr}"
        )


def codesign_dump_entitlements(executable: str) -> Dict[Any, Any]:
    """Dump entitlements from binary using ldid"""
    proc = run_process("ldid", "-e", executable)
    return plistlib.loads(proc.stdout.encode()) if proc.stdout else {}


def is_valid_team_id(team_id: str) -> bool:
    """Check if a string is a valid Apple Team ID (10 characters, alphanumeric)"""
    if not team_id or len(team_id) != 10:
        return False
    return all(c.isalnum() for c in team_id)


def extract_team_ids(
    entitlements: Dict[Any, Any], info_plist: Dict[Any, Any] = None
) -> List[str]:
    """Extract all possible team IDs from binary entitlements and Info.plist"""
    team_ids = set()

    # For some insane reason, we can have multiple team IDs in entitlements.
    # So we need to check all possible sources.

    # Get team identifier from entitlements
    if team_id := entitlements.get("com.apple.developer.team-identifier"):
        if is_valid_team_id(team_id):
            team_ids.add(team_id)

    # Get application identifier prefix from Info.plist
    if info_plist and (prefix := info_plist.get("AppIdentifierPrefix")):
        # Remove trailing dot if present
        team_id = prefix.rstrip(".")
        if is_valid_team_id(team_id):
            team_ids.add(team_id)

    # Get team ID from application identifier in entitlements
    if app_id := entitlements.get("application-identifier"):
        # Format is "TEAMID.bundle.id"
        team_id = app_id.split(".")[0]
        if is_valid_team_id(team_id):
            team_ids.add(team_id)

    # Get team ID from keychain access groups
    if keychain_groups := entitlements.get("keychain-access-groups", []):
        if isinstance(keychain_groups, list):
            for group in keychain_groups:
                if "." in group:
                    team_id = group.split(".")[0]
                    if is_valid_team_id(team_id):
                        team_ids.add(team_id)

    return sorted(list(team_ids))


class IPAInspector:
    def __init__(self, ipa_path: Path):
        self.ipa_path = ipa_path
        self.temp_dir = None
        self.app_dir = None
        self._components = None  # Cache for components

    def __enter__(self):
        """Extract IPA/app to temporary directory"""
        self.temp_dir = tempfile.mkdtemp()
        if self.ipa_path.suffix == ".ipa":
            with zipfile.ZipFile(self.ipa_path) as zf:
                zf.extractall(self.temp_dir)
            payload_dir = Path(self.temp_dir) / "Payload"
            self.app_dir = next(payload_dir.glob("*.app"))
        else:
            # Assume it's already an .app directory
            self.app_dir = self.ipa_path
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up temporary directory"""
        if self.temp_dir:
            from shutil import rmtree

            rmtree(self.temp_dir)

    def get_main_app_bundle_id(self) -> str:
        """Get the main app's bundle ID"""
        info_plist = self.app_dir / "Info.plist"
        if not info_plist.exists():
            raise Exception("No Info.plist found in main app bundle")

        with open(info_plist, "rb") as f:
            info = plistlib.load(f)

        return info["CFBundleIdentifier"]

    def get_components(self) -> List[AppComponent]:
        """Find all signable components in app bundle"""
        if self._components is not None:
            return self._components

        components: List[AppComponent] = []

        # Add main app binary first
        main_info_plist = self.app_dir / "Info.plist"
        with open(main_info_plist, "rb") as f:
            main_info = plistlib.load(f)

        executable_name = main_info.get("CFBundleExecutable")
        if executable_name:
            main_executable = self.app_dir / executable_name
            if main_executable.exists():
                try:
                    main_entitlements = codesign_dump_entitlements(str(main_executable))
                    print(
                        f"Successfully read entitlements from main binary: {main_executable}"
                    )
                except Exception as e:
                    print(f"Warning: Failed to dump entitlements for main binary: {e}")
                    main_entitlements = {}

                components.append(
                    AppComponent(
                        path=Path("."),  # Root of app
                        bundle_id=main_info["CFBundleIdentifier"],
                        executable=Path(executable_name),
                        entitlements=main_entitlements,
                        info_plist=main_info,
                        is_primary=True,  # Main app is always primary
                    )
                )

        # All component types - order matters for signing, otherwise it gets angry.
        component_patterns = [
            "**/*.framework",  # Frameworks
            "**/*.dylib",  # Dynamic libraries
            "**/PlugIns/*.bundle",  # Plugin bundles
            "**/*.appex",  # App extensions
            "*.app",  # Main app last
        ]

        all_components = []
        for pattern in component_patterns:
            all_components.extend(self.app_dir.glob(pattern))

        # Sort by depth for proper signing order, once agan order matters.
        all_components.sort(key=lambda p: len(str(p).split("/")), reverse=True)

        print(f"Found {len(all_components)} components in {self.app_dir}")

        for bundle in all_components:
            print(f"Inspecting bundle: {bundle}")

            # Handle secondary components (frameworks etc)
            if bundle.suffix not in [".app", ".appex"]:
                # For .dylib files, the path itself is the executable. How funky.
                if bundle.suffix == ".dylib":
                    executable_path = bundle
                else:
                    # For frameworks, use bundle/stem convention
                    executable_path = bundle / bundle.stem

                if not executable_path.exists():
                    continue

                try:
                    entitlements = codesign_dump_entitlements(str(executable_path))
                    print(f"Successfully read entitlements from {executable_path}")
                except Exception as e:
                    print(
                        f"Warning: Failed to dump entitlements for {executable_path}: {e}"
                    )
                    entitlements = {}

                components.append(
                    AppComponent(
                        path=bundle.relative_to(self.app_dir),
                        bundle_id=bundle.stem,  # Framework/dylib name as ID
                        executable=executable_path.relative_to(self.app_dir),
                        entitlements=entitlements,
                        info_plist={},  # Empty for secondary components
                        is_primary=False,
                    )
                )
                continue

            # Handle primary components (.app and .appex)
            info_plist_path = bundle / "Info.plist"
            if not info_plist_path.exists():
                print(f"No Info.plist found in {bundle}")
                continue

            with open(info_plist_path, "rb") as f:
                info = plistlib.load(f)

            executable_name = info.get("CFBundleExecutable")
            if not executable_name:
                print(f"No CFBundleExecutable in {info_plist_path}")
                continue

            executable_path = bundle / executable_name
            if not executable_path.exists():
                print(f"Executable not found: {executable_path}")
                continue

            try:
                entitlements = codesign_dump_entitlements(str(executable_path))
                print(f"Successfully read entitlements from {executable_path}")
            except Exception as e:
                print(
                    f"Warning: Failed to dump entitlements for {executable_path}: {e}"
                )
                entitlements = {}

            components.append(
                AppComponent(
                    path=bundle.relative_to(self.app_dir),
                    bundle_id=info["CFBundleIdentifier"],
                    executable=executable_path.relative_to(self.app_dir),
                    entitlements=entitlements,
                    info_plist=info,
                    is_primary=True,
                )
            )

        self._components = components
        return components

    def get_frameworks(self) -> List[Path]:
        """Get list of frameworks that need simple signing"""
        # These don't need to be registered on the Apple Developer Portal. They just need to be signed.
        framework_patterns = ["**/*.framework", "**/*.dylib", "**/PlugIns/*.bundle"]
        frameworks = []

        for pattern in framework_patterns:
            frameworks.extend(self.app_dir.glob(pattern))

        if frameworks:
            print(f"Found {len(frameworks)} frameworks/libraries to sign")
            for f in frameworks:
                print(f"Framework: {f.relative_to(self.app_dir)}")

        return frameworks

    def get_team_ids(self) -> List[str]:
        """Find all team IDs from app components"""
        # Did you know that an app can have multiple team IDs? Yeah, me neither.
        # If you ever need to test an app with multiple team IDs, Twitter is a good example.
        components = self.get_components()
        team_ids = set()

        # Check main app first
        main_app = next((c for c in components if c.path == Path(".")), None)
        if main_app:
            main_ids = extract_team_ids(main_app.entitlements, main_app.info_plist)
            team_ids.update(main_ids)
            if main_ids:
                print(f"Found team IDs from main app: {main_ids}")

        # Check other components
        for component in components:
            if component.path == Path("."):
                continue  # Skip main app as we already checked it
            component_ids = extract_team_ids(
                component.entitlements, component.info_plist
            )
            if component_ids:
                print(
                    f"Found team IDs from component {component.path}: {component_ids}"
                )
                team_ids.update(component_ids)

        return sorted(list(team_ids))

    # TODO: This isn't really needed?

    def get_team_id(self) -> Optional[str]:
        """Get primary team ID (maintaining backwards compatibility)"""
        team_ids = self.get_team_ids()
        if not team_ids:
            return None

        # Prefer team ID from main app's Info.plist AppIdentifierPrefix
        main_app = next((c for c in self.get_components() if c.path == Path(".")), None)
        if main_app and main_app.info_plist.get("AppIdentifierPrefix"):
            prefix = main_app.info_plist["AppIdentifierPrefix"].rstrip(".")
            if prefix in team_ids:
                return prefix

        # Fall back to first team ID found
        return team_ids[0]


# TODO: Would be better to move this to unit tests?


def main():
    """Test functionality with a sample IPA"""
    import sys

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} path/to/app.ipa")
        sys.exit(1)

    with IPAInspector(Path(sys.argv[1])) as inspector:
        if team_id := inspector.get_team_id():
            print(f"\nTeam ID: {team_id}")
        else:
            print("\nWarning: Could not determine team ID")
        print(f"\nInspecting {inspector.ipa_path}")
        for component in inspector.get_components():
            print(f"\nComponent: {component.path}")
            print(f"Bundle ID: {component.bundle_id}")
            print(f"Executable: {component.executable}")
            print("\nEntitlements:")
            import json

            print(json.dumps(component.entitlements, indent=2))


if __name__ == "__main__":
    main()
