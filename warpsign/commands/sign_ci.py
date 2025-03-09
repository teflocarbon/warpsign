import sys
import base64
from pathlib import Path
from typing import Dict, Tuple, Optional
import toml
import requests
import argparse
import os

from warpsign.arguments import add_signing_arguments, create_patching_options
from warpsign.logger import get_console
from warpsign.src.apple.authentication_helper import authenticate_with_apple
from warpsign.src.ci.github import GitHubHandler
from warpsign.src.ci.litterbox import LitterboxUploader

console = get_console()


def load_config() -> dict:
    """Load and validate the configuration file."""
    config_path = Path.home() / ".warpsign" / "config.toml"
    if not config_path.exists():
        console.print(
            f"[red]Error: config.toml not found. Have you checked if '{config_path}' exists?[/]"
        )
        sys.exit(1)
    return toml.load(config_path)


def read_cert_and_password(cert_path: Path) -> Tuple[str, str]:
    """Read certificate and password from files."""
    cert_file = cert_path / "cert.p12"
    pass_file = cert_path / "cert_pass.txt"

    if not cert_file.exists() or not pass_file.exists():
        raise FileNotFoundError(f"Certificate files not found in {cert_path}")

    cert_content = base64.b64encode(cert_file.read_bytes()).decode("utf-8")
    password = pass_file.read_text().strip()

    return cert_content, password


def download_and_rename_ipa(signed_url: str, original_path: Path) -> Path:
    """Download the signed IPA and rename it with -signed suffix."""
    console.print("\nDownloading signed IPA...")
    signed_path = (
        original_path.parent / f"{original_path.stem}-signed{original_path.suffix}"
    )

    response = requests.get(signed_url, stream=True)
    response.raise_for_status()

    total_size = int(response.headers.get("content-length", 0))

    with console.status("[bold blue]Downloading...") as status:
        with open(signed_path, "wb") as f:
            if total_size == 0:
                f.write(response.content)
            else:
                downloaded = 0
                chunk_size = 1024 * 1024  # 1MB chunks
                for data in response.iter_content(chunk_size=chunk_size):
                    downloaded += len(data)
                    f.write(data)
                    percentage = (downloaded / total_size) * 100
                    downloaded_mb = downloaded / (1024 * 1024)
                    total_mb = total_size / (1024 * 1024)
                    status.update(
                        f"[bold blue]Downloaded: {downloaded_mb:.1f}MB / {total_mb:.1f}MB ({percentage:.1f}%)"
                    )

    console.print(f"\n[green]✓ Signed IPA downloaded to:[/] {signed_path}")
    return signed_path


def handle_authentication() -> Tuple[str, str, str, str]:
    """Handle Apple authentication and return necessary credentials."""
    auth = authenticate_with_apple(console, require_password=True)
    if not auth:
        sys.exit(1)

    cookie_path, session_path = auth._get_paths(auth.email)
    if not Path(cookie_path).exists() or not Path(session_path).exists():
        console.print("[red]Error: Authentication files not generated correctly[/]")
        sys.exit(1)

    console.print("\n[green]Authentication successful![/]")
    console.print(f"Cookies: {cookie_path}")
    console.print(f"Session: {session_path}")

    cookie_content = base64.b64encode(Path(cookie_path).read_bytes()).decode("utf-8")
    session_content = base64.b64encode(Path(session_path).read_bytes()).decode("utf-8")
    auth_id = auth._get_session_id(auth.email)

    return cookie_content, session_content, auth_id, auth.email


def setup_certificate_config() -> Path:
    """Setup certificate configuration."""
    cert_dir = os.getenv("WARPSIGN_CERT_DIR")
    return Path(cert_dir) if cert_dir else Path.home() / ".warpsign" / "certificates"


def upload_certificates(gh_secrets: GitHubHandler, config: dict) -> None:
    """Upload development and distribution certificates to GitHub secrets."""
    cert_dir_path = setup_certificate_config()

    # Ensure certificate directories exist
    dev_path = cert_dir_path / "development"
    dist_path = cert_dir_path / "distribution"

    # Check if certificate files exist
    if (
        not (dev_path / "cert.p12").exists()
        or not (dev_path / "cert_pass.txt").exists()
    ):
        console.print(
            f"[red]Error: Development certificate files not found in {dev_path}[/]"
        )
        sys.exit(1)

    if (
        not (dist_path / "cert.p12").exists()
        or not (dist_path / "cert_pass.txt").exists()
    ):
        console.print(
            f"[red]Error: Distribution certificate files not found in {dist_path}[/]"
        )
        sys.exit(1)

    # Upload development certificate
    dev_cert, dev_pass = read_cert_and_password(dev_path)
    gh_secrets.update_secret("DEVELOPMENT_CERT", dev_cert)
    gh_secrets.update_secret("DEVELOPMENT_CERT_PASSWORD", dev_pass)
    console.print("[green]Development certificate uploaded successfully![/]")

    # Upload distribution certificate
    dist_cert, dist_pass = read_cert_and_password(dist_path)
    gh_secrets.update_secret("DISTRIBUTION_CERT", dist_cert)
    gh_secrets.update_secret("DISTRIBUTION_CERT_PASSWORD", dist_pass)
    console.print("[green]Distribution certificate uploaded successfully![/]")


def build_signing_args(args) -> str:
    """Build signing arguments string from parsed arguments."""
    # We need to skip some keys that are used for other purposes. Some are
    # automatically included whilst others are internal only.
    skip_keys = {"ipa_path", "certificate", "encode_ids", "patch_ids", "command"}
    signing_args = []

    for key, value in vars(args).items():
        if key in skip_keys:
            continue
        if isinstance(value, bool) and value:
            signing_args.append(f"--{key.replace('_', '-')}")
        elif isinstance(value, (str, Path)) and value:
            signing_args.append(f"--{key.replace('_', '-')} {value}")

    return " ".join(signing_args)


def handle_workflow_execution(
    gh_secrets: GitHubHandler,
    workflow_inputs: Dict[str, str],
    github_config: dict,
    original_ipa_path: Path,
) -> None:
    """Handle workflow execution and result processing."""
    run_uuid = gh_secrets.trigger_workflow("sign.yml", workflow_inputs)
    console.print("[green]Successfully triggered signing workflow![/]")
    console.print("Waiting for workflow to complete...")

    try:
        console.print("\n[bold blue]Monitoring workflow execution...[/]")
        run = gh_secrets.wait_for_workflow("sign.yml", run_uuid)

        console.print("\n[bold blue]Fetching workflow outputs...[/]")
        outputs = gh_secrets.get_workflow_outputs(run["id"])

        if "url" in outputs and outputs["url"]:
            console.print(f"\n[green]✓ Signing completed successfully![/]")
            console.print(f"[green]Signed IPA available at:[/] {outputs['url']}")
            signed_path = download_and_rename_ipa(outputs["url"], original_ipa_path)
            console.print(
                f"\n[bold green]✓ All done![/] Your signed IPA is ready at: {signed_path}"
            )
        else:
            console.print(
                "[yellow]⚠ Warning: Workflow completed but could not find signed IPA URL[/]"
            )
            console.print(
                f"Please check the workflow logs: https://github.com/{github_config['repo_owner']}/{github_config['repo_name']}/actions/runs/{run['id']}"
            )

    except TimeoutError:
        console.print("[red]❌ Workflow timed out![/]")
        sys.exit(1)
    except Exception as e:
        console.print("[red]❌ Workflow failed![/]")
        console.print(str(e))
        sys.exit(1)


def main(parsed_args=None) -> int:
    """Main CI signing function that does the actual work.

    Args:
        parsed_args: Optional pre-parsed arguments (from CLI)
    """
    console.print("[bold blue]WarpSign CI[/]")

    # Args are provided from CLI. We don't support running this function directly anymore.
    args = parsed_args

    if args.icon:
        console.print("[red]Error: --icon is not supported with CI at the moment[/]")
        return 1

    try:
        # Load configuration and initialize GitHub handler
        config = load_config()
        github_config = config["github"]
        gh_secrets = GitHubHandler(
            github_config["repo_owner"],
            github_config["repo_name"],
            github_config["access_token"],
        )

        # Handle authentication
        cookie_content, session_content, auth_id, apple_id = handle_authentication()
        gh_secrets.update_secret("APPLE_AUTH_COOKIES", cookie_content)
        gh_secrets.update_secret("APPLE_AUTH_SESSION", session_content)
        gh_secrets.update_secret("APPLE_AUTH_ID", auth_id)
        console.print("[green]Successfully updated GitHub secrets![/]")

        # Upload certificates
        upload_certificates(gh_secrets, config)

        # Upload IPA and prepare workflow
        console.print("\nUploading IPA to litterbox...")
        uploader = LitterboxUploader()
        ipa_url = uploader.upload(args.ipa_path)
        console.print("[green]IPA uploaded successfully![/]")

        # Prepare and execute workflow
        workflow_inputs = {
            "ipa_url": ipa_url,
            "cert_type": args.certificate,
            "signing_args": build_signing_args(args),
            "apple_id": apple_id,
        }

        handle_workflow_execution(
            gh_secrets, workflow_inputs, github_config, Path(args.ipa_path)
        )
        console.print(
            f"\nYou can view the workflow details at: https://github.com/{github_config['repo_owner']}/{github_config['repo_name']}/actions"
        )
        return 0

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/]")
        return 1


def run_sign_ci_command(args):
    """Entry point for the sign-ci command from CLI"""
    # Just pass the parsed args to main
    return main(parsed_args=args)


# For direct script execution - route through the CLI
if __name__ == "__main__":
    from warpsign.cli import main as cli_main

    sys.exit(cli_main())
