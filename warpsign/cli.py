import argparse
import sys
from rich_argparse import RichHelpFormatter
from warpsign.arguments import add_signing_arguments


def main():
    parser = argparse.ArgumentParser(
        prog="warpsign",
        description="WarpSign: A tool for signing and managing iOS applications",
        formatter_class=RichHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    # Sign command
    sign_parser = subparsers.add_parser(
        "sign", help="Sign an IPA file", formatter_class=RichHelpFormatter
    )
    add_signing_arguments(sign_parser)

    # Sign CI command
    sign_ci_parser = subparsers.add_parser(
        "sign-ci",
        help="Sign an IPA file in CI environment",
        formatter_class=RichHelpFormatter,
    )
    add_signing_arguments(sign_ci_parser)
    sign_ci_parser.add_argument(
        "--certificate",
        "-c",
        choices=["development", "distribution"],
        default="development",
        help="Certificate type to use for signing [default: development]",
    )

    args = parser.parse_args()

    if args.command == "sign":
        from warpsign.commands.sign import run_sign_command

        return run_sign_command(args)
    elif args.command == "sign-ci":
        from warpsign.commands.sign_ci import run_sign_ci_command

        return run_sign_ci_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
