import os
import shutil
import subprocess
import uuid
from pathlib import Path

from warpsign.logger import get_console

console = get_console()


class CrocHandler:
    """Simple handler for croc file transfers."""

    def __init__(self):
        """Initialize the croc handler with a unique code."""
        # Generate a memorable code that's easy to type
        self.code = f"warpsign-{uuid.uuid4().hex[:8]}"
        self.process = None
        self.env = None

    @staticmethod
    def is_installed() -> bool:
        """Check if croc is installed on the system."""
        return shutil.which("croc") is not None

    def upload(self, file_path: Path) -> str:
        """Start a croc transfer process that stays alive while the main process waits.

        Args:
            file_path: Path to the file to transfer

        Returns:
            str: The croc code for receiving the file
        """
        if not self.is_installed():
            raise RuntimeError("Croc is not installed on this system")

        console.print(
            f"[bold blue]Initiating croc transfer with code: [green]{self.code}[/][/]"
        )

        # Get current environment variables and create a copy
        self.env = os.environ.copy()

        # Set CROC_SECRET environment variable for the code phrase
        self.env["CROC_SECRET"] = self.code

        # Start croc in the foreground with real-time output
        command = ["croc", "send", str(file_path)]

        console.print(f"[dim]Running: {' '.join(command)}[/]")
        console.print("[green]Starting file transfer - logs will appear below:[/]")
        console.print(f"[bold green]Transfer code: {self.code}[/]")

        # Start the process with the modified environment
        # We'll let it keep running and just pipe the output to console
        self.process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            env=self.env,
        )

        return self.code

    def stop(self):
        """Gracefully stop the croc transfer if it's still running."""
        if self.process and self.process.poll() is None:
            console.print("[yellow]Stopping croc transfer...[/]")
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                console.print("[red]Force killing croc process...[/]")
                self.process.kill()
