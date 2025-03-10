from pathlib import Path
import sys
import os

from warpsign.src.apple.apple_account_login import AppleDeveloperAuth
from warpsign.src.core.sign_orchestrator import SignOrchestrator
from warpsign.arguments import create_parser, create_patching_options
from warpsign.logger import get_console

REQUIRED_ENV_VARS = [
    "WARPSIGN_SESSION_DIR",
    "NON_INTERACTIVE",
    "APPLE_ID",
    "WARPSIGN_CERT_DIR",
    "WARPSIGN_CERT_TYPE",
]


def validate_environment():
    console = get_console()
    missing_vars = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]

    if missing_vars:
        console.print("[red]Error: Missing required environment variables:[/]")
        for var in missing_vars:
            console.print(f"  • {var}")
        return False

    if os.getenv("WARPSIGN_CERT_TYPE") not in ["development", "distribution"]:
        console.print(
            "[red]Error: WARPSIGN_CERT_TYPE must be 'development' or 'distribution'[/]"
        )
        return False

    return True


def main():
    console = get_console()

    if not validate_environment():
        return 1

    parser = create_parser()
    args = parser.parse_args()

    if not args.ipa_path.exists():
        console.print(f"[red]Error:[/] IPA file not found: {args.ipa_path}")
        return 1

    # Initialize authentication client
    auth = AppleDeveloperAuth()
    auth.email = os.getenv("APPLE_ID")

    # Load session (required in CI)
    console.print(f"Loading session from: {os.getenv('WARPSIGN_SESSION_DIR')}")
    auth.load_session()

    if not auth.validate_token():
        console.print("[red]Error: Invalid or expired session[/]")
        return 1

    if not auth.get_bundle_ids():
        console.print("[red]Error: API access failed[/]")
        return 1

    console.print("[green]Authentication verified successfully[/]")

    # Create patching options and initialize signer
    options = create_patching_options(args)
    signer = SignOrchestrator(
        cert_type=os.getenv("WARPSIGN_CERT_TYPE"),
        cert_dir=os.getenv("WARPSIGN_CERT_DIR"),
    )

    try:
        signer.auth_session = auth
        output_path = args.ipa_path.with_name(f"{args.ipa_path.stem}-signed.ipa")
        signer.sign_ipa(args.ipa_path, output_path, options)
        console.print(f"[green]Completed signed IPA:[/] {output_path}")
        return 0
    except Exception as e:
        console.print(f"[red]Error during signing:[/] {str(e)}")
        return 1
    finally:
        try:
            signer.cert_handler.cleanup()
        except:
            pass


if __name__ == "__main__":
    sys.exit(main())
