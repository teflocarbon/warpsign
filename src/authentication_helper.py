import os
import sys
import getpass
from src.apple_account_login import AppleDeveloperAuth
from logger import get_console


def authenticate_with_apple(
    console, require_password=False
) -> AppleDeveloperAuth | None:
    """Authenticate with Apple Developer account using environment variables or interactive prompt."""
    auth = AppleDeveloperAuth()
    apple_id = os.getenv("APPLE_ID")
    apple_password = os.getenv("APPLE_PASSWORD")
    session_dir = os.getenv("WARPSIGN_SESSION_DIR")

    if not apple_id:
        console.print("[red]Error: APPLE_ID environment variable is not set[/]")
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

        if not apple_password and session_dir and require_password:
            console.print("[red]No valid session and APPLE_PASSWORD not set[/]")
            return None

    # Try password authentication if no valid session
    if not apple_password and sys.stdin.isatty():
        apple_password = getpass.getpass("Enter Apple ID password: ")
    elif not apple_password and require_password:
        console.print("[red]No valid session and APPLE_PASSWORD not set[/]")
        return None

    if apple_password:
        console.print(f"Authenticating with Apple ID: {apple_id}")
        if auth.authenticate(apple_id, apple_password):
            console.print("[green]Authentication verified successfully[/]")
            return auth
        console.print("[red]Authentication failed![/]")

    return auth if not require_password else None
