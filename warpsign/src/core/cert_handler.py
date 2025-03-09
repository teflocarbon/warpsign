from pathlib import Path
from typing import Optional, Tuple, List
import subprocess
from warpsign.logger import get_console
import random
import string
import re
import tempfile
import os


class CertHandler:
    """Handles code signing certificates"""

    def __init__(self, cert_type: str = None, cert_dir: Optional[str | Path] = None):
        self.console = get_console()

        # Get certificate directory from environment or parameter, ensure it's a Path
        self.cert_dir = Path(cert_dir or os.getenv("WARPSIGN_CERT_DIR", "certificates"))

        # Get certificate type from environment or parameter
        self.cert_type = cert_type or os.getenv("WARPSIGN_CERT_TYPE", "development")
        if self.cert_type not in ["development", "distribution"]:
            raise ValueError(
                "Certificate type must be either 'development' or 'distribution'"
            )

        self.dist_cert: Optional[Path] = None
        self.keychain: Optional[str] = None
        self.signing_identity: Optional[str] = None
        self.cert_serial: Optional[str] = None
        self.cert_common_name: Optional[str] = None
        self.cert_org_unit: Optional[str] = None
        self.cert_org: Optional[str] = None

        # Clean up any old keychains first
        self._cleanup_old_keychains()

        # Load certificate and its password
        cert_dir = self.cert_dir / self.cert_type
        cert_pass_file = cert_dir / "cert_pass.txt"

        try:
            with open(cert_pass_file) as f:
                self.cert_password = f.read().strip()
        except FileNotFoundError:
            raise Exception(f"Certificate password file not found: {cert_pass_file}")

        self._load_certs()
        self._setup_keychain()

    def _load_certs(self) -> None:
        """Load certificates from specified directory"""
        cert_dir = self.cert_dir / self.cert_type
        if not cert_dir.exists():
            raise Exception(f"Certificate directory not found: {cert_dir}")

        cert = cert_dir / "cert.p12"
        if not cert.exists():
            raise Exception(f"Certificate not found: {cert}")

        self.dist_cert = cert
        self.console.log(f"[green]Loaded {self.cert_type} certificate:[/] {cert}")

    def _setup_keychain(self) -> None:
        """Create and configure temporary keychain"""
        password = "1234"  # Simple password for temp keychain
        self.keychain = (
            f"warpsign-{''.join(random.choices(string.ascii_lowercase, k=8))}"
        )
        self.console.log(f"\n[bold red]====== KEYCHAIN SETUP: {self.keychain} ======")

        # Get existing keychains
        self.console.log("[yellow]Getting existing keychains...")
        keychains = self._get_keychain_list()
        self.console.log(f"[blue]Found keychains:[/] {keychains}")

        # Create new keychain
        self.console.log(f"[yellow]Creating keychain: {self.keychain}")
        create_result = subprocess.run(
            ["security", "create-keychain", "-p", password, self.keychain],
            capture_output=True,
            text=True,
        )
        if create_result.returncode != 0:
            self.console.log(
                f"[red]Create failed:[/]\nstdout: {create_result.stdout}\nstderr: {create_result.stderr}"
            )

        # Unlock keychain
        self.console.log(f"[yellow]Unlocking keychain: {self.keychain}")
        unlock_result = subprocess.run(
            ["security", "unlock-keychain", "-p", password, self.keychain],
            capture_output=True,
            text=True,
        )
        if unlock_result.returncode != 0:
            self.console.log(
                f"[red]Unlock failed:[/]\nstdout: {unlock_result.stdout}\nstderr: {unlock_result.stderr}"
            )

        # Set as default keychain if running in GitHub Actions
        if os.getenv("USING_GH_ACTIONS") == "1":
            self.console.log(f"[yellow]Setting as default keychain: {self.keychain}")
            default_result = subprocess.run(
                ["security", "default-keychain", "-s", self.keychain],
                capture_output=True,
                text=True,
            )
            if default_result.returncode != 0:
                self.console.log(
                    f"[red]Setting default keychain failed:[/]\nstdout: {default_result.stdout}\nstderr: {default_result.stderr}"
                )

        # Set keychain settings with correct flags
        self.console.log(f"[yellow]Setting keychain settings: {self.keychain}")
        settings_result = subprocess.run(
            [
                "security",
                "set-keychain-settings",
                "-lut",  # lock on sleep, user lock, with timeout
                "21600",  # 6 hour timeout
                self.keychain,
            ],
            capture_output=True,
            text=True,
        )
        if settings_result.returncode != 0:
            self.console.log(
                f"[red]Settings failed:[/]\nstdout: {settings_result.stdout}\nstderr: {settings_result.stderr}"
            )

        # Import certificate with additional flags for codesign and security access
        self.console.log(f"[yellow]Importing certificate: {self.dist_cert}")
        import_result = subprocess.run(
            [
                "security",
                "import",
                str(self.dist_cert),
                "-k",
                self.keychain,
                "-f",
                "pkcs12",
                "-A",  # Allow all applications to access the keys
                "-T",  # Specify trusted applications
                "/usr/bin/codesign",
                "-T",
                "/usr/bin/security",
                "-P",
                self.cert_password,
            ],
            capture_output=True,
            text=True,
        )
        if import_result.returncode != 0:
            self.console.log(f"[red]Import failed:[/]\nstdout: {import_result.stdout}")

        # Allow codesign to access keychain without prompting - corrected version
        self.console.log("[yellow]Setting keychain partition list")
        partition_result = subprocess.run(
            [
                "security",
                "set-key-partition-list",
                "-S",
                "apple-tool:,apple:",  # Removed codesign: from partition list
                "-k",
                password,
                self.keychain,
            ],
            capture_output=True,
            text=True,
        )
        if partition_result.returncode != 0:
            self.console.log(
                f"[red]Partition list setup failed:[/]\nstdout: {partition_result.stdout}\nstderr: {partition_result.stderr}"
            )

        # Add to search list
        self.console.log(f"[yellow]Adding to keychain search list: {self.keychain}")
        keychains.append(self.keychain)
        search_result = subprocess.run(
            ["security", "list-keychains", "-d", "user", "-s", *keychains],
            capture_output=True,
            text=True,
        )
        if search_result.returncode != 0:
            self.console.log(
                f"[red]Search list update failed:[/]\nstdout: {search_result.stdout}\nstderr: {search_result.stderr}"
            )

        # Update keychain list with both the new keychain and login.keychain
        self.console.log("[yellow]Updating keychain list")
        subprocess.run(
            [
                "security",
                "list-keychains",
                "-d",
                "user",
                "-s",
                self.keychain,
                "login.keychain",
            ],
            check=True,
            capture_output=True,
        )

        # After certificate import, extract info and setup codesigning
        self._extract_certificate_info()
        self._setup_codesigning()

        self.console.log("[bold green]====== KEYCHAIN SETUP COMPLETE ======\n")

    def _extract_certificate_info(self) -> None:
        """Extract all certificate information from the keychain"""
        self.console.log("[yellow]Extracting certificate information...")

        result = subprocess.run(
            ["security", "find-certificate", "-a", "-p", self.keychain],
            capture_output=True,
            text=True,
            check=True,
        )

        # Write cert to temp file and extract all info while file is open
        with tempfile.NamedTemporaryFile(suffix=".pem", mode="w") as temp_pem:
            temp_pem.write(result.stdout)
            temp_pem.flush()

            # Extract serial number
            self._extract_serial_number(temp_pem.name)
            # Extract subject information
            self._extract_subject_info(temp_pem.name)

        # Log certificate information (no sensitive data)
        self._log_certificate_info()

    def _extract_serial_number(self, pem_path: str) -> None:
        """Extract certificate serial number"""
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-serial", "-in", pem_path],
            capture_output=True,
            text=True,
            check=True,
        )
        self.cert_serial = result.stdout.strip().split("=")[1]

    def _extract_subject_info(self, pem_path: str) -> None:
        """Extract and parse certificate subject information"""
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-in", pem_path],
            capture_output=True,
            text=True,
            check=True,
        )

        # Parse the subject string
        subject = result.stdout.strip()
        if subject.startswith("subject="):
            subject = subject[8:].strip()

        # Split fields by comma and parse each one
        fields = {}
        for field in subject.split(","):
            field = field.strip()
            if not field or "=" not in field:
                continue
            key, value = field.split("=", 1)
            fields[key.strip()] = value.strip()

        # Extract values
        if "CN" in fields:
            cn_value = fields["CN"]
            if ":" in cn_value:
                self.cert_common_name = cn_value.split(":")[0].strip()
            else:
                self.cert_common_name = cn_value
        if "OU" in fields:
            self.cert_org_unit = fields["OU"]
        if "O" in fields:
            self.cert_org = fields["O"]

    def _log_certificate_info(self) -> None:
        """Log extracted certificate information"""
        self.console.log(f"[green]Certificate information:[/]")
        self.console.log(f"[blue]Serial Number:[/] {self.cert_serial}")
        self.console.log(f"[blue]Common Name:[/] {self.cert_common_name}")
        self.console.log(f"[blue]Organizational Unit:[/] {self.cert_org_unit}")
        self.console.log(f"[blue]Organization:[/] {self.cert_org}")

    def _setup_codesigning(self) -> None:
        """Set up and test codesigning capability"""
        # Get codesigning identity
        self.console.log("[yellow]Getting codesigning identity...")
        result = subprocess.run(
            ["security", "find-identity", "-v", "-p", "codesigning", self.keychain],
            capture_output=True,
            text=True,
        )
        identities = re.findall(r'\d+\) ([A-F0-9]{40}) ".*?"', result.stdout)
        if not identities:
            self.console.log("[red]NO VALID CODESIGNING IDENTITY FOUND!")
            raise Exception("No valid code signing identity found in certificate")

        self.signing_identity = identities[0]
        self.console.log(f"[green]Got signing identity:[/] {self.signing_identity}")

        # Test codesign access
        self._test_codesign()

    def _test_codesign(self) -> None:
        """Test codesigning with a temporary file"""
        self.console.log("[yellow]Testing codesign access...")
        with tempfile.NamedTemporaryFile() as test_file:
            test_file.write(b"test")
            test_file.flush()
            try:
                test_result = subprocess.run(
                    ["codesign", "-s", self.signing_identity, test_file.name],
                    capture_output=True,
                    text=True,
                )
                self.console.log(f"[green]Codesign test succeeded[/]")
            except subprocess.CalledProcessError as e:
                self.console.log(
                    f"[red]Codesign test failed:[/]\nstdout: {e.stdout}\nstderr: {e.stderr}"
                )

    def cleanup(self, force: bool = False) -> None:
        """Explicitly clean up keychain - call this instead of relying on __del__"""
        if not self.keychain:
            return

        try:
            # Remove from search list
            keychains = self._get_keychain_list()
            keychains = [k for k in keychains if self.keychain not in k]
            subprocess.run(
                ["security", "list-keychains", "-d", "user", "-s", *keychains]
            )

            # Always delete the keychain
            subprocess.run(["security", "delete-keychain", self.keychain])
            self.console.log("[green]Cleaned up keychain[/]")
        except Exception as e:
            self.console.log(f"[red]Error during keychain cleanup:[/] {e}")

    def _get_keychain_list(self) -> List[str]:
        """Get list of current keychains"""
        result = subprocess.run(
            ["security", "list-keychains", "-d", "user"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [k.strip().strip('"') for k in result.stdout.splitlines()]

    def _cleanup_old_keychains(self) -> None:
        """Remove any existing warpsign keychains"""
        for keychain in self._get_keychain_list():
            if "warpsign-" in keychain:
                self.console.log(f"[yellow]Cleaning up old keychain:[/] {keychain}")
                try:
                    subprocess.run(
                        ["security", "delete-keychain", keychain], check=True
                    )
                except Exception as e:
                    self.console.log(
                        f"[red]Failed to delete keychain {keychain}:[/] {e}"
                    )

    def _run_codesign(
        self,
        binary: Path,
        entitlements: Optional[Path] = None,
    ) -> None:
        """Sign binary using codesign exactly like SignTools"""
        if not self.signing_identity:
            raise Exception("No signing identity available")

        # Exactly match SignTools codesign command (from sign-test.py)
        cmd = [
            "codesign",
            "--continue",
            "-f",
            "--no-strict",
            "-s",
            self.signing_identity,
        ]

        if entitlements:
            cmd.extend(["--entitlements", str(entitlements)])

        cmd.extend([str(binary)])  # Note: SignTools doesn't use --keychain flag

        self.console.log(f"[cyan]Running codesign command:[/] {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            if result.stdout:
                self.console.log(f"[green]Codesign output:[/]\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            error_msg = f"Codesign failed:\nCommand: {' '.join(cmd)}\nStdout: {e.stdout}\nStderr: {e.stderr}"
            self.console.log(f"[red]{error_msg}")
            raise Exception(error_msg)

    def sign_binary(
        self,
        binary: Path,
        entitlements: Optional[Path] = None,
        is_main_binary: bool = False,
    ) -> None:
        """Sign a binary with optional entitlements"""
        self.console.log(f"\n[blue]Signing binary:[/] {binary}")
        self._run_codesign(binary, entitlements)

    def verify_binary(self, binary: Path) -> None:
        """Verify binary signature"""
        try:
            subprocess.run(
                ["codesign", "--verify", "--deep", "--strict", str(binary)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.console.log(f"[green]Verified signature:[/] {binary}")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Signature verification failed: {e.stderr}")

    def _extract_cert_info(self) -> None:
        """This is now handled in _setup_keychain right after import"""
        pass
