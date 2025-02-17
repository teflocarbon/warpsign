#!/usr/bin/env python3

import sys
import os
import toml
import base64
from pathlib import Path
from src.apple_account_login import AppleDeveloperAuth
from src.github import GitHubHandler
from src.litterbox import LitterboxUploader
from arguments import create_parser
import shutil
import requests
from logger import get_console

console = get_console()


def load_config():
    config_path = Path(__file__).parent / "config.toml"
    if not config_path.exists():
        console.print("[red]Error: config.toml not found[/]")
        sys.exit(1)
    return toml.load(config_path)


def read_cert_and_password(cert_path: Path):
    cert_file = cert_path / "cert.p12"
    pass_file = cert_path / "cert_pass.txt"

    if not cert_file.exists() or not pass_file.exists():
        raise FileNotFoundError(f"Certificate files not found in {cert_path}")

    with open(cert_file, "rb") as f:
        cert_content = base64.b64encode(f.read()).decode("utf-8")

    with open(pass_file, "r") as f:
        password = f.read().strip()

    return cert_content, password


def create_ci_parser():
    parser = create_parser()
    # Add certificate type argument
    parser.add_argument(
        "--certificate",
        "-c",
        choices=["development", "distribution"],
        default="development",
        help="Certificate type to use for signing [default: development]",
    )
    return parser


def save_base64_file(content: str, filename: str):
    base64_dir = Path(__file__).parent / "base64"
    base64_dir.mkdir(exist_ok=True)

    file_path = base64_dir / filename
    with open(file_path, "w") as f:
        f.write(content)
    return file_path


def download_and_rename_ipa(signed_url: str, original_path: Path) -> Path:
    """Download the signed IPA and rename it to match the original with -signed suffix"""
    console.print("\nDownloading signed IPA...")

    # Create the new filename by adding -signed before the extension
    signed_path = (
        original_path.parent / f"{original_path.stem}-signed{original_path.suffix}"
    )

    # Download the file
    response = requests.get(signed_url, stream=True)
    response.raise_for_status()

    # Save the file with progress indication
    total_size = int(response.headers.get("content-length", 0))
    with open(signed_path, "wb") as f:
        if total_size == 0:
            f.write(response.content)
        else:
            downloaded = 0
            for data in response.iter_content(chunk_size=8192):
                downloaded += len(data)
                f.write(data)
                done = int(50 * downloaded / total_size)
                console.print(
                    f"\rProgress: [{'=' * done}{' ' * (50-done)}] {downloaded}/{total_size} bytes",
                    end="",
                )

    console.print(f"\n[green]✓ Signed IPA downloaded to:[/] {signed_path}")
    return signed_path


def main():
    console.print("[bold blue]WarpSign CI[/]")

    # Parse arguments first
    parser = create_ci_parser()
    args = parser.parse_args()

    # Load configuration
    config = load_config()
    github_config = config["github"]

    # Initialize GitHub secrets manager
    gh_secrets = GitHubHandler(
        github_config["repo_owner"],
        github_config["repo_name"],
        github_config["access_token"],
    )

    # Get Apple ID from environment or prompt
    apple_id = os.getenv("APPLE_ID")
    if not apple_id:
        console.print("[red]Error: APPLE_ID environment variable not set[/]")
        sys.exit(1)

    # Initialize authentication
    auth = AppleDeveloperAuth()
    auth.email = apple_id

    # Authenticate and generate session files
    if not auth.validate_token():
        apple_password = os.getenv("APPLE_PASSWORD")
        if not apple_password:
            console.print("[red]Error: No valid session and APPLE_PASSWORD not set[/]")
            sys.exit(1)

        console.print(f"Authenticating with Apple ID: {apple_id}")
        if not auth.authenticate(apple_id, apple_password):
            console.print("[red]Authentication failed![/]")
            sys.exit(1)

    # Get the session file paths
    cookie_path, session_path = auth._get_paths(apple_id)

    # Verify the files exist
    if not Path(cookie_path).exists() or not Path(session_path).exists():
        console.print("[red]Error: Authentication files not generated correctly[/]")
        sys.exit(1)

    console.print("\n[green]Authentication successful![/]")
    console.print("Session files generated at:")
    console.print(f"Cookies: {cookie_path}")
    console.print(f"Session: {session_path}")
    console.print("\nYou can now use these files in your GitHub Actions workflow.")

    # Update GitHub secrets with the session files
    try:
        with open(cookie_path, "rb") as f:
            cookie_content = base64.b64encode(f.read()).decode("utf-8")
        with open(session_path, "rb") as f:
            session_content = base64.b64encode(f.read()).decode("utf-8")

        # Get the auth ID from the AppleDeveloperAuth class
        auth_id = auth._get_session_id(apple_id)

        gh_secrets.update_secret("APPLE_AUTH_COOKIES", cookie_content)
        gh_secrets.update_secret("APPLE_AUTH_SESSION", session_content)
        gh_secrets.update_secret("APPLE_AUTH_ID", auth_id)

        console.print("[green]Successfully updated GitHub secrets![/]")
    except Exception as e:
        console.print(f"[red]Failed to update GitHub secrets: {str(e)}[/]")
        sys.exit(1)

    # After updating auth secrets, handle certificates
    try:
        cert_config = config["certificates"]
        dev_path = Path(cert_config["development_path"])
        dist_path = Path(cert_config["distribution_path"])

        # Handle development certificate
        dev_cert, dev_pass = read_cert_and_password(dev_path)
        gh_secrets.update_secret("DEVELOPMENT_CERT", dev_cert)
        gh_secrets.update_secret("DEVELOPMENT_CERT_PASSWORD", dev_pass)
        console.print("[green]Development certificate uploaded successfully![/]")

        # Handle distribution certificate
        dist_cert, dist_pass = read_cert_and_password(dist_path)
        gh_secrets.update_secret("DISTRIBUTION_CERT", dist_cert)
        gh_secrets.update_secret("DISTRIBUTION_CERT_PASSWORD", dist_pass)
        console.print("[green]Distribution certificate uploaded successfully![/]")

    except Exception as e:
        console.print(f"[red]Failed to update certificate secrets: {str(e)}[/]")
        sys.exit(1)

    # After certificates are uploaded, handle IPA upload and workflow dispatch
    try:
        # Upload to litterbox
        console.print("\nUploading IPA to litterbox...")
        uploader = LitterboxUploader()
        ipa_url = uploader.upload(args.ipa_path)
        console.print(f"[green]IPA uploaded successfully![/]")

        # Convert arguments to signing args string
        arg_dict = vars(args)
        signing_args = []
        for key, value in arg_dict.items():
            # Skip default values and specific keys we don't want to pass
            if key in (
                "ipa_path",
                "certificate",
                "encode_ids",  # Skip default values
                "patch_ids",  # Skip default values
            ):
                continue
            # Only include boolean flags if they're True and not default values
            if isinstance(value, bool):
                if value and key not in (
                    "encode_ids",
                    "patch_ids",
                ):  # Ensure we don't include defaults
                    signing_args.append(f"--{key.replace('_', '-')}")
            # Include non-boolean values if they're set
            elif isinstance(value, (str, Path)) and value:
                signing_args.append(f"--{key.replace('_', '-')} {value}")

        # Create workflow inputs dictionary
        workflow_inputs = {
            "ipa_url": ipa_url,
            "cert_type": args.certificate,
            "signing_args": " ".join(signing_args),
            "apple_id": apple_id,
        }

        # Trigger the workflow and wait for completion
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

                # Download and rename the signed IPA
                signed_path = download_and_rename_ipa(
                    outputs["url"], Path(args.ipa_path)
                )
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

        console.print(
            f"\nYou can view the workflow details at: https://github.com/{github_config['repo_owner']}/{github_config['repo_name']}/actions"
        )

    except Exception as e:
        console.print(f"[red]Failed to trigger workflow: {str(e)}[/]")
        sys.exit(1)


if __name__ == "__main__":
    main()
