"""
Constants used in the CLI interface of WarpSign.
"""

from rich.text import Text

# Define version
__version__ = "0.1.0"


# Banner ASCII art
def get_banner_text():
    """Return the stylized banner text object."""
    banner = Text()
    banner.append(
        "██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗██╗ ██████╗ ███╗   ██╗\n",
        style="cyan",
    )
    banner.append(
        "██║    ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██║██╔════╝ ████╗  ██║\n",
        style="cyan",
    )
    banner.append(
        "██║ █╗ ██║███████║██████╔╝██████╔╝███████╗██║██║  ███╗██╔██╗ ██║\n",
        style="blue",
    )
    banner.append(
        "██║███╗██║██╔══██║██╔══██╗██╔═══╝ ╚════██║██║██║   ██║██║╚██╗██║\n",
        style="blue",
    )
    banner.append(
        "╚███╔███╔╝██║  ██║██║  ██║██║     ███████║██║╚██████╔╝██║ ╚████║\n",
        style="magenta",
    )
    banner.append(
        " ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝\n",
        style="magenta",
    )
    return banner


# Application description
APP_DESCRIPTION = "Sign the proper way™"
