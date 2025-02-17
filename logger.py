from rich.console import Console
from functools import lru_cache


@lru_cache(maxsize=1)
def get_console() -> Console:
    """Get or create the shared Console instance"""
    return Console()
