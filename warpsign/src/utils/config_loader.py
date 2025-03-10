import os
from pathlib import Path
import toml
from typing import Dict, Any, Optional


def get_config_path() -> Path:
    """Return the path to the configuration file."""
    return Path.home() / ".warpsign" / "config.toml"


def load_config() -> Dict[str, Any]:
    """Load configuration from TOML file."""
    config_path = get_config_path()
    if not config_path.exists():
        return {}

    try:
        return toml.load(config_path)
    except Exception as e:
        raise ValueError(f"Failed to load config: {e}")


def get_apple_credentials() -> Dict[str, Optional[str]]:
    """Get Apple credentials from config."""
    config = load_config()
    apple_config = config.get("apple", {})

    credentials = {
        "apple_id": apple_config.get("apple_id"),
        "apple_password": apple_config.get("apple_password"),
    }

    # Validate that at least apple_id is present
    if not credentials["apple_id"]:
        raise ValueError(
            f"Apple ID not found in config. Please add [apple] section with apple_id to {get_config_path()}"
        )

    return credentials


def get_session_dir() -> Optional[Path]:
    """Get session directory from config or environment."""
    # Check environment variable first
    env_session_dir = os.environ.get("WARPSIGN_SESSION_DIR")
    if env_session_dir:
        return Path(env_session_dir)

    # Fall back to config
    config = load_config()
    apple_config = config.get("apple", {})
    session_dir = apple_config.get("session_dir")

    if session_dir:
        return Path(session_dir)

    # Default to ~/.warpsign/sessions if not specified
    return Path.home() / ".warpsign" / "sessions"
