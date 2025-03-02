import subprocess
from pathlib import Path
import os
import stat
import requests
import tempfile
import platform
import sys


def get_platform_suffix():
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        system = "macos"
    if machine == "x86_64":
        machine = "amd64"
    if machine == "aarch64":
        machine = "arm64"

    suffix = f"{system}-{machine}"
    if system == "windows":
        suffix += ".exe"

    return suffix


class LitterboxUploader:
    def __init__(self):
        self.binary_path = Path(tempfile.gettempdir()) / "litterbox-uploader"
        self._ensure_binary()

    def _ensure_binary(self):
        if not self.binary_path.exists():
            suffix = get_platform_suffix()
            latest_url = (
                "https://github.com/teflocarbon/litterbox-rust-upload/releases/latest"
            )

            # Get the redirect URL to determine latest version
            response = requests.head(latest_url, allow_redirects=True)
            latest_version = response.url.split("/")[-1]

            # Construct binary URL
            binary_url = f"https://github.com/teflocarbon/litterbox-rust-upload/releases/download/{latest_version}/litterbox-rust-upload-{latest_version}-{suffix}"

            response = requests.get(binary_url)
            response.raise_for_status()

            with open(self.binary_path, "wb") as f:
                f.write(response.content)

            # Make executable
            current = os.stat(self.binary_path)
            os.chmod(self.binary_path, current.st_mode | stat.S_IEXEC)

    def upload(self, file_path: Path) -> str:
        result = subprocess.run(
            [str(self.binary_path), str(file_path)], capture_output=True, text=True
        )

        if result.returncode != 0:
            raise Exception(f"Upload failed: {result.stderr}")

        # Find the URL in the output
        for line in result.stdout.split("\n"):
            if "Upload successful:" in line:
                return line.split(": ")[1].strip()

        raise Exception("Could not find upload URL in output")
