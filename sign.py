#!/usr/bin/env python3

from pathlib import Path
import sys
from typing import Optional, Tuple
import os
from rich.prompt import Prompt

from src.app_patcher import PatchingOptions, StatusBarStyle, UIStyle
from src.sign_orchestrator import SignOrchestrator
from arguments import create_parser, create_patching_options
from logger import get_console
from src.authentication_helper import authenticate_with_apple


def parse_vscode_args(argv: list[str]) -> list[str]:
    """Handle VS Code debug argument concatenation."""
    if len(argv) == 2:
        arg = argv[1].replace("\\ ", "__SPACE__")
        parts = arg.split(" ")
        return [argv[0]] + [p.replace("__SPACE__", " ").strip() for p in parts]
    return argv


def verify_ipa_exists(ipa_path: Path, console) -> bool:
    """Verify IPA file exists and return status."""
    if not ipa_path.exists():
        console.print(f"[red]Error:[/] IPA file not found: {ipa_path}")
        return False
    return True


def determine_certificate_type(cert_dir_path: Path, console) -> Optional[str]:
    """Determine which certificate type to use based on available certificates."""
    dist_exists = (cert_dir_path / "distribution").exists()
    dev_exists = (cert_dir_path / "development").exists()

    cert_type = os.getenv("WARPSIGN_CERT_TYPE")

    # Validate environment variable setting
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

    # Determine certificate type if not set or invalid
    if not cert_type:
        if dist_exists and dev_exists:
            if sys.stdin.isatty():
                return Prompt.ask(
                    "Select certificate type",
                    choices=["development", "distribution"],
                    default="distribution",
                )
            return "development"  # Default for non-interactive
        elif dist_exists:
            return "distribution"
        elif dev_exists:
            return "development"

    return cert_type


def print_configuration_summary(console, args, options: PatchingOptions) -> None:
    """Print the configuration summary."""
    console.print("\n[bold blue]Signing Configuration:[/]")
    console.print(f"[cyan]Input IPA:[/] {args.ipa_path}")
    console.print("\n[cyan]Enabled Options:[/]")

    option_values = vars(options)
    enum_defaults = {
        "patch_status_bar": StatusBarStyle.DEFAULT,
        "patch_user_interface_style": UIStyle.AUTOMATIC,
    }

    for key, value in option_values.items():
        if value is None:
            continue
        if isinstance(value, bool) and value:
            console.print(f"  • {key.replace('_', ' ').title()}")
        elif key in enum_defaults and value != enum_defaults[key]:
            console.print(f"  • {key.replace('_', ' ').title()}: {value.value}")
        elif key in ("bundle_name", "icon_path") and value:
            console.print(f"  • {key.replace('_', ' ').title()}: {value}")


def setup_certificate_config() -> Tuple[Path, Optional[str]]:
    """Setup certificate configuration."""
    cert_dir = os.getenv("WARPSIGN_CERT_DIR")
    return Path(cert_dir) if cert_dir else Path("certificates")


def sign_application(
    signer: SignOrchestrator, input_path: Path, options: PatchingOptions
) -> bool:
    """Sign the application with provided options."""
    try:
        output_path = input_path.with_name(f"{input_path.stem}-signed.ipa")
        signer.sign_ipa(input_path, output_path, options)
        return True
    except Exception as e:
        get_console().print(f"\n[red]Error during signing:[/] {str(e)}")
        return False


def main() -> int:
    console = get_console()
    parser = create_parser()

    # Parse and fix arguments
    sys.argv = parse_vscode_args(sys.argv)
    args = parser.parse_args()

    # Verify IPA exists
    if not verify_ipa_exists(args.ipa_path, console):
        return 1

    # Authenticate with Apple
    auth = authenticate_with_apple(console, require_password=True)
    if not auth:
        return 1

    # Setup configuration
    options = create_patching_options(args)
    cert_dir_path = setup_certificate_config()

    # Determine certificate type
    cert_type = determine_certificate_type(cert_dir_path, console)
    if not cert_type:
        console.print("[red]Error: No certificates found[/]")
        return 1

    # Print configuration summary
    print_configuration_summary(console, args, options)
    console.print(f"[blue]Using {cert_type} certificate[/]")

    # Confirm and sign
    if console.input("\n[yellow]Press Enter to continue or Ctrl+C to cancel[/]"):
        return 1

    signer = SignOrchestrator(cert_type=cert_type, cert_dir=cert_dir_path)
    signer.auth_session = auth

    try:
        if sign_application(signer, args.ipa_path, options):
            return 0
        return 1
    finally:
        try:
            signer.cert_handler.cleanup()
        except:
            pass


if __name__ == "__main__":
    sys.exit(main())
