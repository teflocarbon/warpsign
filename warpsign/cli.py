import argparse
import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme
from rich_argparse import RichHelpFormatter
from warpsign.arguments import add_signing_arguments
from warpsign.src.constants.cli_constants import (
    __version__,
    get_banner_text,
    APP_DESCRIPTION,
)


class WarpSignHelpFormatter(RichHelpFormatter):
    """Custom formatter for WarpSign CLI that enhances the output with rich styling."""

    def __init__(self, prog):
        super().__init__(prog, max_help_position=30, width=100)
        self.console = Console(
            theme=Theme(
                {
                    "command": "bold cyan",
                    "argument": "green",
                    "option": "yellow",
                    "version": "blue",
                    "title": "bold magenta",
                }
            )
        )

    def _format_usage(self, usage, actions, groups, prefix):
        # Override the usage to make it more colorful
        formatted = super()._format_usage(usage, actions, groups, prefix)
        return formatted

    def start_section(self, heading):
        # Make section headings more prominent
        heading_text = Text(heading, style="title")
        super().start_section(str(heading_text))


def display_banner():
    """Display a stylish banner for WarpSign."""
    console = Console()
    banner = get_banner_text()

    version_info = Text(f"v{__version__}", style="version")
    tagline = Text(APP_DESCRIPTION, style="italic")

    panel = Panel.fit(
        Text.assemble(banner, "\n", tagline, "\n", version_info),
        border_style="green",
        padding=(1, 2),
    )
    console.print(panel)


def main():
    # Display the banner before the help text
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        display_banner()

    parser = argparse.ArgumentParser(
        prog="warpsign",
        description=f"WarpSign: {APP_DESCRIPTION}",
        formatter_class=WarpSignHelpFormatter,
        add_help=True,
    )

    # Add version argument
    parser.add_argument(
        "--version", action="version", version=f"WarpSign {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command")

    # Sign command
    sign_parser = subparsers.add_parser(
        "sign",
        help="Sign an IPA file",
        formatter_class=WarpSignHelpFormatter,
        description="Sign an IPA file with your Apple Developer account and certificates.",
    )
    add_signing_arguments(sign_parser)

    # Sign CI command
    sign_ci_parser = subparsers.add_parser(
        "sign-ci",
        help="Sign an IPA file in CI environment",
        formatter_class=WarpSignHelpFormatter,
        description="Sign an IPA file with your Apple Developer account and certificates. No Mac required! 🚀",
    )
    add_signing_arguments(sign_ci_parser)
    sign_ci_parser.add_argument(
        "--certificate",
        "-c",
        choices=["development", "distribution"],
        required=True,
        help="Certificate type to use for signing",
    )

    # Setup command
    setup_parser = subparsers.add_parser(
        "setup",
        help="Setup WarpSign configuration",
        formatter_class=WarpSignHelpFormatter,
        description="Interactive wizard to set up WarpSign directories and configuration.",
    )

    args = parser.parse_args()

    if args.command == "sign":
        from warpsign.commands.sign import run_sign_command

        return run_sign_command(args)
    elif args.command == "sign-ci":
        from warpsign.commands.sign_ci import run_sign_ci_command

        return run_sign_ci_command(args)
    elif args.command == "setup":
        from warpsign.commands.setup import run_setup_command

        return run_setup_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
