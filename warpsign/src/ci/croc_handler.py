import os
import shutil
import subprocess
import uuid
import time
import random
import socket
from pathlib import Path
from typing import Optional

from warpsign.logger import get_console

console = get_console()


class CrocHandler:
    """Handler for croc file transfers with support for both sending and receiving.

    A unique relay port is required for each croc transfer.  We reserve a port from
    a predefined range and keep track of ports currently in use via a simple text file
    at ``~/.warpsign/used_ports.txt``.  This prevents multiple concurrent transfers
    on the same machine from attempting to bind to the same relay port.
    """

    # Range of ports to allocate from (inclusive)
    PORT_RANGE = (9000, 9999)

    # File used to persist the list of ports currently in use
    USED_PORTS_FILE = Path.home() / ".warpsign" / "used_ports.txt"

    def __init__(self, code: "Optional[str]" = None, port: "Optional[int]" = None):
        """Initialize the croc handler.

        Args:
            code: Optional croc code to use. If ``None`` a new code will be generated.
            port: Optional relay port to use. If ``None`` we will reserve a free port.
        """

        # Generate a memorable code that's easy to type, or use the provided code
        self.code = code or f"warpsign-{uuid.uuid4().hex}"

        # Reserve a port if one hasn't been supplied
        if port is None:
            self.port = self._reserve_port()
            self._port_reserved = True
        else:
            self.port = port
            self._port_reserved = False

        self.process: "Optional[subprocess.Popen]" = None
        self.env: "Optional[dict]" = None

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
        command = ["croc", "send", "--port", str(self.port), str(file_path)]

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
        command = ["croc", "--debug", "--yes"]
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            command.extend(["--out", str(output_dir)])

        console.print(f"[dim]Running: {' '.join(command)}[/]")
        console.print("[green]Waiting for file transfer - logs will appear below:[/]")

        try:
            # Start the process and wait for it to complete
            console.print("[bold yellow]Waiting for CI to upload the signed IPA...[/]")

            result = subprocess.run(
                command, env=self.env, text=True, capture_output=True
            )

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

        # Release the reserved port (if we allocated it)
        if getattr(self, "_port_reserved", False):
            try:
                self._release_port(self.port)
            except Exception:
                # Failure to release is non-fatal – log and continue
                console.print("[yellow]Warning: failed to release croc port[/]")

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

    # ---------------------------------------------------------------------
    # Port reservation helpers
    # ---------------------------------------------------------------------

    @classmethod
    def _load_used_ports(cls) -> set[int]:
        """Load the set of ports currently marked as used."""
        if not cls.USED_PORTS_FILE.exists():
            return set()
        try:
            with cls.USED_PORTS_FILE.open("r", encoding="utf-8") as f:
                return {int(line.strip()) for line in f if line.strip().isdigit()}
        except Exception:
            return set()

    @classmethod
    def _save_used_ports(cls, ports: set[int]):
        """Persist the supplied *ports* set back to the used ports file."""
        cls.USED_PORTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with cls.USED_PORTS_FILE.open("w", encoding="utf-8") as f:
            for p in sorted(ports):
                f.write(f"{p}\n")

    @classmethod
    def _is_port_open(cls, port: int) -> bool:
        """Check whether *port* is open (i.e. already bound) on localhost."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex(("127.0.0.1", port)) == 0

    @classmethod
    def _reserve_port(cls) -> int:
        """Reserve and return a free port within ``PORT_RANGE``.

        The chosen port is recorded in ``USED_PORTS_FILE`` in order to avoid
        collisions with other processes also using :pyclass:`CrocHandler`.
        """
        used_ports = cls._load_used_ports()

        attempts = 0
        max_attempts = (cls.PORT_RANGE[1] - cls.PORT_RANGE[0]) + 1
        while attempts < max_attempts:
            port = random.randint(*cls.PORT_RANGE)
            attempts += 1

            if port in used_ports or cls._is_port_open(port):
                continue

            # Mark as used and persist
            used_ports.add(port)
            cls._save_used_ports(used_ports)
            return port

        raise RuntimeError("Could not find a free port for croc")

    @classmethod
    def _release_port(cls, port: int):
        """Release *port* back to the pool of free ports."""
        used_ports = cls._load_used_ports()
        if port in used_ports:
            used_ports.remove(port)
            cls._save_used_ports(used_ports)
