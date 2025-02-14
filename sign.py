#!/usr/bin/env python3

import argparse
from pathlib import Path
import sys
from rich.console import Console
from app_patcher import PatchingOptions
from local_signer import LocalSigner
from apple_account_login import AppleDeveloperAuth
import os


def create_parser():
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
        "--patch-itunes-warning",
        action="store_true",
        help="Disable iTunes sync warning [default: disabled]",
    )

    return parser


def main():
    console = Console()
    parser = create_parser()
    args = parser.parse_args()

    # Verify IPA file exists
    if not args.ipa_path.exists():
        console.print(f"[red]Error:[/] IPA file not found: {args.ipa_path}")
        return 1

    # Verify authentication first

    # HACK: This fixes an issue with a session seemingly not working immediately after the user has authenticated.
    # by using the saved session information, we can avoid the issue.

    auth = AppleDeveloperAuth()
    if not auth.validate_token():
        console.print("[yellow]No valid authentication session found[/]")
        # Try to authenticate using environment variables
        if not auth.authenticate(os.getenv("APPLE_ID"), os.getenv("APPLE_PASSWORD")):
            console.print(
                "[red]Authentication failed. Please ensure you have valid credentials[/]"
            )
            console.print(
                "[yellow]Hint: Set APPLE_ID and APPLE_PASSWORD environment variables[/]"
            )
            return 1

        # Verify authentication was successful
        if not auth.get_bundle_ids():
            console.print("[red]Authentication succeeded but API access failed[/]")
            return 1

    console.print("[green]Authentication verified successfully[/]")

    # Create patching options from arguments
    options = PatchingOptions(
        encode_ids=args.encode_ids,
        patch_ids=args.patch_ids,
        force_original_id=args.force_original_id,
        patch_debug=args.patch_debug,
        patch_all_devices=args.patch_all_devices,
        patch_file_sharing=args.patch_file_sharing,
        patch_promotion=args.patch_promotion,
        patch_fullscreen=args.patch_fullscreen,
        patch_orientation=args.patch_orientation,
        patch_itunes_warning=args.patch_itunes_warning,
    )

    # Show configuration summary
    console.print("\n[bold blue]Signing Configuration:[/]")
    console.print(f"[cyan]Input IPA:[/] {args.ipa_path}")
    console.print("\n[cyan]Enabled Options:[/]")
    for key, value in vars(options).items():
        if value:
            console.print(f"  • {key.replace('_', ' ').title()}")

    # Confirm before proceeding
    if not console.input("\n[yellow]Press Enter to continue or Ctrl+C to cancel[/]"):
        try:
            # Initialize signer with authenticated session
            signer = LocalSigner()
            signer.auth_session = auth  # Pass the authenticated session to the signer
            output_path = args.ipa_path.with_name(f"{args.ipa_path.stem}-signed.ipa")
            signer.sign_ipa(args.ipa_path, output_path, options)
            return 0
        except Exception as e:
            console.print(f"\n[red]Error during signing:[/] {str(e)}")
            return 1
        finally:
            # Ensure cleanup happens
            try:
                signer.cert_handler.cleanup()
            except:
                pass


if __name__ == "__main__":
    sys.exit(main())
