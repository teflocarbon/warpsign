import argparse
from pathlib import Path
from typing import Optional
from warpsign.src.ipa.app_patcher import PatchingOptions, StatusBarStyle, UIStyle
from rich_argparse import RawDescriptionRichHelpFormatter  # Import the formatter


def create_parser():
    """Create and return an argument parser with signing arguments."""
    parser = argparse.ArgumentParser(
        prog="warpsign",
        description="Sign the proper way™",
        formatter_class=RawDescriptionRichHelpFormatter,
    )
    add_signing_arguments(parser)
    return parser


def add_signing_arguments(parser):
    """Add all signing-related arguments to an existing parser."""
    # Required argument
    parser.add_argument("ipa_path", type=Path, help="Path to the IPA file to sign")

    # Optional arguments for signing mode
    parser.add_argument(
        "--use-provisioning-profile",
        action="store_true",
        help="Use local provisioning profiles instead of Apple Developer Portal API [default: disabled]",
    )

    # Optional arguments for patching options
    parser.add_argument(
        "--bundle-name",
        type=str,
        help="Change the app's visible name [default: keep original]",
    )

    parser.add_argument(
        "--no-encode-ids",
        action="store_false",
        dest="encode_ids",
        help="Disable ID encoding (only use if you own the app) [default: enabled]",
    )

    parser.add_argument(
        "--no-patch-ids",
        action="store_false",
        dest="patch_ids",
        help="Disable binary and plist ID patching [default: enabled]",
    )

    parser.add_argument(
        "--force-original-id",
        action="store_true",
        help="Keep original bundle ID (may fix push, requires distribution cert) [default: disabled]",
    )

    parser.add_argument(
        "--patch-debug",
        action="store_true",
        help="Enable debug mode (requires development cert) [default: disabled]",
    )

    parser.add_argument(
        "--patch-all-devices",
        action="store_true",
        help="Enable support for all devices and lower minimum OS version [default: disabled]",
    )

    parser.add_argument(
        "--patch-file-sharing",
        action="store_true",
        help="Enable Files app and iTunes file sharing support [default: disabled]",
    )

    parser.add_argument(
        "--patch-promotion",
        action="store_true",
        help="Force ProMotion/120Hz support (may not work properly) [default: disabled]",
    )

    parser.add_argument(
        "--patch-fullscreen",
        action="store_true",
        help="Force fullscreen mode on iPad (disable multitasking) [default: disabled]",
    )

    parser.add_argument(
        "--patch-orientation",
        action="store_true",
        help="Enable all orientations (may cause crashes) [default: disabled]",
    )

    parser.add_argument(
        "--patch-game-mode",
        action="store_true",
        help="Enable Game Mode support [default: disabled]",
    )

    parser.add_argument(
        "--hide-home-indicator",
        action="store_true",
        help="Hide home indicator on iPhone X and newer devices [default: disabled]",
    )

    parser.add_argument(
        "--inject-plugins-patcher",
        action="store_true",
        help="Inject sideload fix patch dylib, similar to ID patching but dynamic [default: disabled]",
    )

    parser.add_argument(
        "--icon",
        type=Path,
        help="Path to new icon image (PNG recommended) [default: keep original]",
    )

    parser.add_argument(
        "--patch-status-bar",
        choices=["hidden", "light", "dark"],
        help="Set status bar style: hidden, light (for dark backgrounds), or dark (for light backgrounds) [default: unchanged]",
    )

    parser.add_argument(
        "--patch-user-interface-style",
        choices=["light", "dark"],
        help="Force Light or Dark mode [default: automatic]",
    )

    parser.add_argument(
        "--remove-url-schemes",
        action="store_true",
        help="Remove URL schemes registration [default: disabled]",
    )


def create_patching_options(args) -> PatchingOptions:
    """Convert parsed arguments to PatchingOptions"""
    return PatchingOptions(
        encode_ids=args.encode_ids,
        patch_ids=args.patch_ids,
        force_original_id=args.force_original_id,
        patch_debug=args.patch_debug,
        patch_all_devices=args.patch_all_devices,
        patch_file_sharing=args.patch_file_sharing,
        patch_promotion=args.patch_promotion,
        patch_fullscreen=args.patch_fullscreen,
        patch_orientation=args.patch_orientation,
        patch_game_mode=args.patch_game_mode,
        hide_home_indicator=args.hide_home_indicator,
        inject_plugins_patcher=args.inject_plugins_patcher,
        bundle_name=args.bundle_name,
        icon_path=args.icon,
        patch_status_bar=(
            StatusBarStyle(args.patch_status_bar)
            if args.patch_status_bar
            else StatusBarStyle.DEFAULT
        ),
        patch_user_interface_style=(
            UIStyle(args.patch_user_interface_style)
            if args.patch_user_interface_style
            else UIStyle.AUTOMATIC
        ),
        remove_url_schemes=args.remove_url_schemes,
    )
