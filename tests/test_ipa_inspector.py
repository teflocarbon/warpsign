import plistlib
from pathlib import Path

import pytest

from warpsign.src.ipa import ipa_inspector
from warpsign.src.ipa.ipa_inspector import IPAInspector


@pytest.fixture(autouse=True)
def no_ldid(monkeypatch):
    """Component discovery is under test, not entitlement dumping"""
    monkeypatch.setattr(ipa_inspector, "codesign_dump_entitlements", lambda _: {})


def make_bundle(path: Path, executable: str, bundle_id: str = None) -> None:
    path.mkdir(parents=True)
    info = {"CFBundleExecutable": executable}
    if bundle_id:
        info["CFBundleIdentifier"] = bundle_id
    with open(path / "Info.plist", "wb") as f:
        plistlib.dump(info, f)
    (path / executable).write_bytes(b"binary")


def components_by_path(app: Path) -> dict:
    with IPAInspector(app) as inspector:
        return {str(c.path): c for c in inspector.get_components()}


def test_framework_inside_extension_is_not_primary(tmp_path):
    app = tmp_path / "Test.app"
    make_bundle(app, "Test", "com.example.test")
    make_bundle(app / "PlugIns/Widget.appex", "Widget", "com.example.test.widget")
    make_bundle(app / "PlugIns/Widget.appex/Frameworks/Inner.framework", "Inner")

    components = components_by_path(app)

    assert components["."].is_primary
    assert components["PlugIns/Widget.appex"].is_primary
    assert not components["PlugIns/Widget.appex/Frameworks/Inner.framework"].is_primary


def test_framework_executable_comes_from_info_plist(tmp_path):
    app = tmp_path / "Test.app"
    make_bundle(app, "Test", "com.example.test")
    make_bundle(app / "Frameworks/Foo.framework", "FooBinary")
    make_bundle(app / "Frameworks/Bar.framework", "Bar")

    components = components_by_path(app)

    assert components["Frameworks/Foo.framework"].executable == Path(
        "Frameworks/Foo.framework/FooBinary"
    )
    assert components["Frameworks/Bar.framework"].executable == Path(
        "Frameworks/Bar.framework/Bar"
    )


def test_framework_without_info_plist_uses_folder_name(tmp_path):
    app = tmp_path / "Test.app"
    make_bundle(app, "Test", "com.example.test")
    (app / "Frameworks/Legacy.framework").mkdir(parents=True)
    (app / "Frameworks/Legacy.framework/Legacy").write_bytes(b"binary")

    components = components_by_path(app)

    assert components["Frameworks/Legacy.framework"].executable == Path(
        "Frameworks/Legacy.framework/Legacy"
    )
