import subprocess

import pytest

from warpsign.src.core import cert_handler as cert_handler_module
from warpsign.src.core.cert_handler import CertHandler
from warpsign.src.core.sign_orchestrator import SignOrchestrator

KEYCHAIN_DIR = "/Users/test/Library/Keychains"
ORIGINAL_KEYCHAINS = [
    f"{KEYCHAIN_DIR}/login.keychain-db",
    f"{KEYCHAIN_DIR}/work.keychain-db",
    "/Library/Keychains/Custom.keychain",
]


class FakeSecurity:
    """Minimal stand-in for the macOS `security` CLI's user search list handling"""

    def __init__(self, search_list):
        self.search_list = list(search_list)
        self.deleted = []

    @staticmethod
    def _resolve(name):
        return name if "/" in name else f"{KEYCHAIN_DIR}/{name}-db"

    def run(self, cmd, *args, **kwargs):
        stdout = ""
        if cmd[:4] == ["security", "list-keychains", "-d", "user"]:
            if len(cmd) > 4 and cmd[4] == "-s":
                self.search_list = [self._resolve(k) for k in cmd[5:]]
            else:
                stdout = "".join(f'    "{k}"\n' for k in self.search_list)
        elif cmd[:2] == ["security", "create-keychain"]:
            # Like the real tool, creating a keychain also adds it to the search list
            self.search_list.append(self._resolve(cmd[-1]))
        elif cmd[:2] == ["security", "delete-keychain"]:
            self.deleted.append(cmd[2])
            self.search_list = [k for k in self.search_list if cmd[2] not in k]
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")


@pytest.fixture
def cert_dir(tmp_path):
    dev = tmp_path / "development"
    dev.mkdir()
    (dev / "cert.p12").write_bytes(b"not a real p12")
    (dev / "cert_pass.txt").write_text("password")
    return tmp_path


@pytest.fixture
def fake_security(monkeypatch):
    fake = FakeSecurity(ORIGINAL_KEYCHAINS)
    monkeypatch.setattr(cert_handler_module.subprocess, "run", fake.run)
    # Certificate parsing and codesign checks need real macOS tooling
    monkeypatch.setattr(CertHandler, "_extract_certificate_info", lambda self: None)
    monkeypatch.setattr(CertHandler, "_setup_codesigning", lambda self: None)
    return fake


def test_keychain_is_added_first_without_dropping_user_keychains(
    cert_dir, fake_security
):
    handler = CertHandler(cert_type="development", cert_dir=cert_dir)

    assert handler.keychain in fake_security.search_list[0]
    assert fake_security.search_list[1:] == ORIGINAL_KEYCHAINS


def test_cleanup_restores_original_search_list(cert_dir, fake_security):
    handler = CertHandler(cert_type="development", cert_dir=cert_dir)
    keychain = handler.keychain

    handler.cleanup()

    assert fake_security.search_list == ORIGINAL_KEYCHAINS
    assert keychain in fake_security.deleted
    # A second cleanup (e.g. from a finally block) is a no-op
    handler.cleanup()
    assert fake_security.deleted.count(keychain) == 1


def test_failed_setup_removes_keychain_and_restores_search_list(
    cert_dir, fake_security, monkeypatch
):
    def fail(self):
        raise Exception("No valid code signing identity found in certificate")

    monkeypatch.setattr(CertHandler, "_setup_codesigning", fail)

    with pytest.raises(Exception, match="No valid code signing identity"):
        CertHandler(cert_type="development", cert_dir=cert_dir)

    assert fake_security.search_list == ORIGINAL_KEYCHAINS
    assert len(fake_security.deleted) == 1


def test_orchestrator_cleans_up_keychain_when_authentication_exits(
    cert_dir, fake_security, monkeypatch
):
    def set_cert_info(self):
        self.cert_common_name = "Apple Development"
        self.cert_org_unit = "ZZZZZ99999"

    def exit_like_failed_auth(self):
        raise SystemExit(1)

    monkeypatch.setattr(CertHandler, "_extract_certificate_info", set_cert_info)
    monkeypatch.setattr(
        SignOrchestrator, "_setup_authentication", exit_like_failed_auth
    )

    with pytest.raises(SystemExit):
        SignOrchestrator(cert_type="development", cert_dir=cert_dir)

    assert fake_security.search_list == ORIGINAL_KEYCHAINS
    assert len(fake_security.deleted) == 1
