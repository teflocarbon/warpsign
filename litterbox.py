import subprocess
from pathlib import Path
import os
import stat
import requests
import tempfile

LITTERBOX_URL = "https://github.com/teflocarbon/litterbox-rust-upload/releases/download/release/litterbox-rust-upload-macOS-arm64"


class LitterboxUploader:
    def __init__(self):
        self.binary_path = Path(tempfile.gettempdir()) / "litterbox-uploader"
        self._ensure_binary()

    def _ensure_binary(self):
        if not self.binary_path.exists():
            response = requests.get(LITTERBOX_URL)
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
