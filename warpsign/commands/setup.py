import os
import shutil
import toml
from pathlib import Path
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.markdown import Markdown
from rich import box
from rich.table import Table
from warpsign.logger import get_console

console = get_console()


def ensure_directory_exists(directory_path):
    """Create directory if it doesn't exist."""
    if not directory_path.exists():
        directory_path.mkdir(parents=True, exist_ok=True)
        return False
    return True


def create_or_update_config(config_path):
    """Create or update the config file based on user input."""
    try:
        # Initialize an empty or load existing config
        config_data = {}
        if config_path.exists():
            try:
                config_data = toml.load(config_path)
            except Exception as e:
                console.print(
                    f"[yellow]Warning: Could not parse existing config: {e}[/yellow]"
                )
                if not Confirm.ask(
                    "Would you like to create a new configuration?", default=True
                ):
                    return False
                config_data = {}

        console.print(
            Panel(
                "Let's configure your WarpSign settings",
                style="bold green",
                box=box.ROUNDED,
            )
        )

        # Ask if user wants to use CI features
        use_ci = Confirm.ask(
            "\n[bold yellow]Do you want to use CI features for signing?[/bold yellow]",
            default=True,
        )

        # GitHub section - only if using CI
        if use_ci:
            console.print("\n[bold blue]GitHub Configuration[/bold blue]")
            console.print("This information is needed for CI signing capabilities.")

            # Initialize github section if it doesn't exist
            if "github" not in config_data:
                config_data["github"] = {}

            config_data["github"]["repo_owner"] = Prompt.ask(
                "Repository owner",
                default=config_data.get("github", {}).get("repo_owner", "XXXX"),
            )
            config_data["github"]["repo_name"] = Prompt.ask(
                "Repository name",
                default=config_data.get("github", {}).get("repo_name", "XXXX"),
            )

            # Handle GitHub token with masking
            current_token = config_data.get("github", {}).get("access_token", "")
            display_token = (
                "********" if current_token and current_token != "XXXX" else "XXXX"
            )

            entered_token = Prompt.ask(
                "GitHub access token",
                default=display_token,
                password=True,
            )

            if entered_token != "********":
                config_data["github"]["access_token"] = entered_token
        elif not config_path.exists():
            # For new configs, don't add github section if not using CI
            console.print("[dim]Skipping GitHub configuration.[/dim]")
        # For existing configs, we don't touch the github section if the user chose not to configure CI

        # Apple section - always needed
        console.print("\n[bold blue]Apple Developer Configuration[/bold blue]")

        # Initialize apple section if it doesn't exist
        if "apple" not in config_data:
            config_data["apple"] = {}

        config_data["apple"]["apple_id"] = Prompt.ask(
            "Apple ID (email)",
            default=config_data.get("apple", {}).get("apple_id", "changeme@apple.com"),
        )

        # Handle Apple password - only add if user wants to set it
        should_set_password = Confirm.ask(
            "Do you want to set your Apple ID password?", default=False
        )

        if should_set_password:
            config_data["apple"]["apple_password"] = Prompt.ask(
                "Apple ID password", password=True
            )
        elif "apple_password" in config_data.get("apple", {}):
            # If they don't want to set a password and there is one already in the config,
            # ask if they want to remove it
            if Confirm.ask("Remove existing password from config?", default=False):
                del config_data["apple"]["apple_password"]

        # Save the updated config
        with open(config_path, "w") as f:
            toml.dump(config_data, f)

        return True
    except Exception as e:
        console.print(f"[bold red]Error configuring settings: {e}[/bold red]")
        return False


def setup_directory_structure():
    """Set up the WarpSign directory structure."""
    base_dir = Path.home() / ".warpsign"
    cert_dir = base_dir / "certificates"
    dist_cert_dir = cert_dir / "distribution"
    dev_cert_dir = cert_dir / "development"
    config_path = base_dir / "config.toml"

    directories = [
        (base_dir, "WarpSign base directory"),
        (cert_dir, "Certificates directory"),
        (dist_cert_dir, "Distribution certificates"),
        (dev_cert_dir, "Development certificates"),
    ]

    # Create a table to display directory structure
    table = Table(title="Directory Structure", box=box.ROUNDED)
    table.add_column("Directory", style="cyan")
    table.add_column("Status", style="green")

    for dir_path, dir_desc in directories:
        existed = ensure_directory_exists(dir_path)
        status = "✓ Already exists" if existed else "✓ Created"
        table.add_row(str(dir_path), status)

    console.print(table)

    # Handle config file
    if config_path.exists():
        console.print(
            f"[yellow]Configuration file already exists at:[/yellow] {config_path}"
        )
        if Confirm.ask("Do you want to edit the existing configuration?", default=True):
            if create_or_update_config(config_path):
                console.print(
                    "[bold green]✓ Configuration updated successfully![/bold green]"
                )
            else:
                console.print("[bold red]Failed to update configuration.[/bold red]")
    else:
        console.print(
            f"[yellow]Creating new configuration file at:[/yellow] {config_path}"
        )
        if create_or_update_config(config_path):
            console.print(
                "[bold green]✓ Configuration created successfully![/bold green]"
            )
        else:
            console.print("[bold red]Failed to create configuration file.[/bold red]")


def run_setup_command(args):
    """Run the setup command."""
    console.print(
        Panel.fit(
            Text("WarpSign Setup Wizard", style="bold magenta"),
            subtitle="Let's get you ready to sign apps!",
            border_style="green",
            padding=(1, 9),
        )
    )

    setup_directory_structure()

    console.print("\n[bold green]Setup complete![/bold green]")

    console.print(
        Markdown(
            """
            **What's next?**
            
            - To sign an IPA file: `warpsign sign your-app.ipa`
            - To sign in a CI environment: `warpsign sign-ci --certificate distribution`
            - For more help: `warpsign --help`
            """
        )
    )

    return 0
