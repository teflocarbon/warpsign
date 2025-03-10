import os
import shutil
import subprocess
import uuid
import time
from pathlib import Path

from warpsign.logger import get_console

console = get_console()


class CrocHandler:
    """Handler for croc file transfers with support for both sending and receiving."""

    def __init__(self, code=None):
        """Initialize the croc handler with a unique code.

        Args:
            code: Optional croc code to use. If None, a new code will be generated.
        """
        # Generate a memorable code that's easy to type, or use provided code
        self.code = code or f"warpsign-{uuid.uuid4().hex[:8]}"
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

    def receive(self, output_dir: Path = None) -> Path:
        """Receive a file from croc using the code.

        Args:
            output_dir: Optional directory to save the file to.
                If None, saves to current directory.

        Returns:
            Path: Path to the received file
        """
        if not self.is_installed():
            raise RuntimeError("Croc is not installed on this system")

        console.print(
            f"[bold blue]Receiving file with croc code: [green]{self.code}[/][/]"
        )

        # Get current environment variables and create a copy
        self.env = os.environ.copy()

        # Set CROC_SECRET environment variable for the code phrase
        self.env["CROC_SECRET"] = self.code

        # Build the command
        command = ["croc", "--yes"]
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            command.extend(["--out", str(output_dir)])

        console.print(f"[dim]Running: {' '.join(command)}[/]")
        console.print("[green]Waiting for file transfer - logs will appear below:[/]")

        # Create a temp file to store output for parsing
        output_file = Path(f"/tmp/croc-{self.code}-output.txt")

        try:
            # Start the process and wait for it to complete
            console.print("[bold yellow]Waiting for CI to upload the signed IPA...[/]")

            result = subprocess.run(
                command, env=self.env, text=True, capture_output=True
            )

            # Write output to a file for debugging
            with open(output_file, "w") as f:
                f.write(result.stdout)
                f.write(result.stderr)

            # Check if the process succeeded
            if result.returncode != 0:
                console.print(
                    f"[red]Croc receive failed with code {result.returncode}[/]"
                )
                console.print(f"[red]Error: {result.stderr}[/]")
                raise RuntimeError(f"Croc receive failed: {result.stderr}")

            # Log the output
            console.print(result.stdout)

            # Parse the output to find the received file
            for line in result.stdout.splitlines():
                if "Received" in line and "written to" in line:
                    file_path_str = line.split("written to ")[-1].strip()
                    # Remove quotes if present
                    if file_path_str.startswith('"') and file_path_str.endswith('"'):
                        file_path_str = file_path_str[1:-1]
                    return Path(file_path_str)

            # If we can't find the file in the output, try to find any IPA in the output directory
            if output_dir:
                ipas = list(output_dir.glob("*.ipa"))
                if ipas:
                    return ipas[0]

            raise RuntimeError("Could not determine received file path")

        except subprocess.SubprocessError as e:
            console.print(f"[red]Error during file reception: {e}[/]")
            raise

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

    def stream_output(self):
        """Stream the output from the croc process to the console."""
        if not self.process:
            return

        while True:
            if self.process.poll() is not None:
                # Process finished
                break

            output = self.process.stdout.readline()
            if output:
                console.print(output.rstrip())

            # Sleep a bit to avoid hogging CPU
            time.sleep(0.1)
