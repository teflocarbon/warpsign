from pathlib import Path
from warpsign.logger import get_console
from warpsign.src.core.verification import SigningVerifier


class AppVerifier:
    """Main class for app verification that runs all verification checks."""

    def __init__(self, ipa_path: Path):
        self.ipa_path = ipa_path
        self.console = get_console()
        self.signing_verifier = SigningVerifier(ipa_path)

    def verify(self) -> bool:
        """Run all verification checks and return overall result."""
        self.console.print(f"[bold]Starting verification for {self.ipa_path.name}[/]\n")

        # Verify code signatures first
        signatures_valid = self.signing_verifier.verify_code_signatures()

        # Verify entitlements
        entitlements_valid = self.signing_verifier.verify_entitlements()

        # Overall verification result
        verification_passed = signatures_valid and entitlements_valid

        self.console.print("\n" + "=" * 80)
        if verification_passed:
            self.console.print("[bold green]✅ App verification PASSED[/]")
        else:
            self.console.print("[bold red]❌ App verification FAILED[/]")

            # Show specifics about what failed
            if not signatures_valid:
                self.console.print("[red]  - Code signature verification failed[/]")
                self.console.print(
                    "    Some resources may have been modified after signing."
                )

            if not entitlements_valid:
                self.console.print("[red]  - Entitlements verification failed[/]")
                self.console.print(
                    "    Binary entitlements don't match provisioning profile."
                )

        return verification_passed
