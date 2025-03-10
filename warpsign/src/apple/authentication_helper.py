import os
import sys
import getpass
from warpsign.logger import get_console
from warpsign.src.apple.apple_account_login import AppleDeveloperAuth
from warpsign.src.utils.config_loader import get_apple_credentials, get_session_dir


def authenticate_with_apple(
    console, require_password=False
) -> AppleDeveloperAuth | None:
    """Authenticate with Apple Developer account using config or interactive prompt."""
    auth = AppleDeveloperAuth()

    try:
        # Get credentials from config
        credentials = get_apple_credentials()
        apple_id = credentials["apple_id"]
        apple_password = credentials["apple_password"]
        session_dir = get_session_dir()
    except ValueError as e:
        console.print(f"[red]Error: {e}[/]")
        return None

    # Try loading existing session if session directory is specified
    if session_dir:
        console.print(f"Attempting to load session from: {session_dir}")
        auth.email = apple_id
        try:
            auth.load_session()
            if auth.validate_token():
                console.print("[green]Successfully loaded existing session!")
                return auth
            console.print("[yellow]Loaded session is invalid")
        except Exception as e:
            console.print(f"[yellow]Failed to load session: {e}")

    # Try password authentication if no valid session
    if not apple_password:
        # Inform users about setting password in the config
        console.print("[yellow]No Apple password found in configuration.[/]")
        console.print(
            f"[yellow]You can set your apple_password under `[apple]` in your config.toml file.[/]"
        )

        # Check if we're in non-interactive mode first
        if os.environ.get("NON_INTERACTIVE"):
            console.print(
                "[red]NON_INTERACTIVE mode detected. Cannot prompt for password.[/]"
            )
            return None
        # In interactive mode, always try to prompt for password
        try:
            apple_password = getpass.getpass("Enter Apple ID password: ")
        except (EOFError, KeyboardInterrupt):
            console.print("[red]Password input canceled[/]")
            return None
        except Exception:
            # If we can't get password for any reason
            if require_password:
                console.print(
                    "[red]No valid session and could not prompt for password[/]"
                )
                return None

    if apple_password:
        console.print(f"Authenticating with Apple ID: {apple_id}")
        if auth.authenticate(apple_id, apple_password):
            console.print("[green]Authentication verified successfully[/]")
            return auth
        console.print("[red]Authentication failed![/]")

    return auth if not require_password else None
