import argparse
from pathlib import Path
from typing import Optional


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sign iOS applications with custom options.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Simple signing with defaults
    %(prog)s my-app.ipa

    # Enable debug mode (requires development certificate)
    %(prog)s my-app.ipa --patch-debug

    # Force original bundle ID for push notifications (requires distribution certificate)
    %(prog)s my-app.ipa --force-original-id

    # Enable file sharing and promotion support
    %(prog)s my-app.ipa --patch-file-sharing --patch-promotion
        """,
    )

    # Required argument
    parser.add_argument("ipa_path", type=Path, help="Path to the IPA file to sign")

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

    return parser
