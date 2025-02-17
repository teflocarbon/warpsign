#!/usr/bin/env python3

from pathlib import Path
import sys
from src.app_patcher import PatchingOptions
from src.local_signer import LocalSigner
from src.apple_account_login import AppleDeveloperAuth
import os
from arguments import create_parser, create_patching_options
from src.app_patcher import StatusBarStyle, UIStyle
import getpass
from logger import get_console


def main():
    console = get_console()
    parser = create_parser()

    # Fix for VS Code debug where arguments might be concatenated and escaped
    if len(sys.argv) == 2:
        # Remove escape characters and split on actual spaces
        arg = sys.argv[1].replace("\\ ", "__SPACE__")
        parts = arg.split(" ")
        parts = [p.replace("__SPACE__", " ").strip() for p in parts]
        # Replace the original arguments
        sys.argv[1:] = parts

    args = parser.parse_args()

    # Verify IPA file exists
    if not args.ipa_path.exists():
        console.print(f"[red]Error:[/] IPA file not found: {args.ipa_path}")
        return 1

    # Initialize authentication client
    auth = AppleDeveloperAuth()
    apple_id = os.getenv("APPLE_ID")
    apple_password = os.getenv("APPLE_PASSWORD")
    session_dir = os.getenv("WARPSIGN_SESSION_DIR")

    if not apple_id:
        console.print("[red]Error: APPLE_ID environment variable is not set[/]")
        return 1

    # Try loading existing session first if session directory is specified
    if session_dir:
        console.print(f"Attempting to load session from: {session_dir}")
        auth.email = apple_id
        try:
            auth.load_session()
            if auth.validate_token():
                console.print("[green]Successfully loaded existing session!")
            else:
                console.print("[yellow]Loaded session is invalid")
                if not apple_password:
                    console.print("[red]No valid session and APPLE_PASSWORD not set[/]")
                    return 1
        except Exception as e:
            console.print(f"[yellow]Failed to load session: {e}")
            if not apple_password:
                console.print("[red]No valid session and APPLE_PASSWORD not set[/]")
                return 1

    # If no valid session, try password authentication
    if not auth.validate_token():
        if not apple_password:
            if not session_dir:
                # Interactive mode - prompt for password
                apple_password = getpass.getpass("Enter Apple ID password: ")
            else:
                console.print("[red]No valid session and APPLE_PASSWORD not set[/]")
                return 1

        console.print(f"Authenticating with Apple ID: {apple_id}")
        if not auth.authenticate(apple_id, apple_password):
            console.print("[red]Authentication failed![/]")
            return 1

    # Verify API access
    if not auth.get_bundle_ids():
        console.print("[red]Authentication succeeded but API access failed[/]")
        return 1

    console.print("[green]Authentication verified successfully[/]")

    # Create patching options from arguments
    options = create_patching_options(args)

    # Show configuration summary
    console.print("\n[bold blue]Signing Configuration:[/]")
    console.print(f"[cyan]Input IPA:[/] {args.ipa_path}")
    console.print("\n[cyan]Enabled Options:[/]")

    # Get all options as a dictionary
    option_values = vars(options)

    # Define default values for enum options
    enum_defaults = {
        "patch_status_bar": StatusBarStyle.DEFAULT,
        "patch_user_interface_style": UIStyle.AUTOMATIC,
    }

    # Show only non-default boolean options and modified enum options
    for key, value in option_values.items():
        # Skip None values
        if value is None:
            continue
        # Handle boolean options
        if isinstance(value, bool) and value:
            console.print(f"  • {key.replace('_', ' ').title()}")
        # Handle enum options
        elif key in enum_defaults and value != enum_defaults[key]:
            console.print(f"  • {key.replace('_', ' ').title()}: {value.value}")
        # Handle string/path options if they are set
        elif key in ("bundle_name", "icon_path") and value:
            console.print(f"  • {key.replace('_', ' ').title()}: {value}")

    # Get certificate configuration
    cert_dir = os.getenv("WARPSIGN_CERT_DIR")
    cert_type = os.getenv("WARPSIGN_CERT_TYPE")

    # Determine certificate directory
    cert_dir_path = Path(cert_dir) if cert_dir else Path("certificates")

    # Check available certificate types
    dist_exists = (cert_dir_path / "distribution").exists()
    dev_exists = (cert_dir_path / "development").exists()

    # Only use env var if it matches an available cert type
    if cert_type:
        if cert_type == "distribution" and not dist_exists:
            console.print(
                "[yellow]Warning: Distribution certificate specified but not found[/]"
            )
            cert_type = None
        elif cert_type == "development" and not dev_exists:
            console.print(
                "[yellow]Warning: Development certificate specified but not found[/]"
            )
            cert_type = None

    # If no valid cert_type, determine from available certs
    if not cert_type:
        if dist_exists and dev_exists:
            if sys.stdin.isatty():  # Interactive mode
                from rich.prompt import Prompt

                cert_type = Prompt.ask(
                    "Select certificate type",
                    choices=["development", "distribution"],
                    default="distribution",
                )
            else:
                cert_type = "development"  # Default for non-interactive
        elif dist_exists:
            cert_type = "distribution"
        elif dev_exists:
            cert_type = "development"
        else:
            console.print("[red]Error: No certificates found[/]")
            return 1

    console.print(f"[blue]Using {cert_type} certificate[/]")

    # Confirm before proceeding
    if not console.input("\n[yellow]Press Enter to continue or Ctrl+C to cancel[/]"):
        try:
            # Initialize signer with authenticated session and certificate configuration
            signer = LocalSigner(cert_type=cert_type, cert_dir=cert_dir)
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
