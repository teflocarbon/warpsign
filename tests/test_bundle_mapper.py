import plistlib
from pathlib import Path

from warpsign.src.core.bundle_mapper import BundleMapping
from warpsign.src.ipa.app_patcher import AppPatcher, PatchingOptions

ORIGINAL_TEAM_ID = "ABCDE12345"
NEW_TEAM_ID = "ZZZZZ99999"
MAIN_BUNDLE_ID = "com.example.app"


def make_mapper() -> BundleMapping:
    return BundleMapping(
        original_team_ids=[ORIGINAL_TEAM_ID],
        new_team_id=NEW_TEAM_ID,
        original_base_id=MAIN_BUNDLE_ID,
        randomize=True,
    )


def test_component_bundle_id_containing_icloud_stays_a_bundle_id():
    mapper = make_mapper()

    mapped = mapper.map_bundle_id("com.example.app.iCloudSync")

    assert not mapped.startswith("iCloud.")
    assert mapped == f"{mapper.main_bundle_id}.iCloudSync"


def test_app_group_containing_icloud_stays_an_app_group():
    mapper = make_mapper()
    group = "group.com.example.iCloudShare"
    entitlements = {"com.apple.security.application-groups": [group]}

    groups, containers = mapper.extract_resources_from_entitlements(entitlements)
    mapped_ents = mapper.map_entitlements(entitlements)

    assert containers == set()
    assert len(groups) == 1
    registered_group = groups.pop()
    assert registered_group.startswith("group.")
    # The group registered on the portal must match the one signed into the binary
    assert mapped_ents["com.apple.security.application-groups"] == [registered_group]


def test_icloud_containers_with_and_without_prefix_are_mapped_as_containers():
    mapper = make_mapper()
    entitlements = {
        "com.apple.developer.icloud-container-identifiers": [
            "iCloud.com.example.app",
            f"{ORIGINAL_TEAM_ID}.com.example.legacy",
        ],
        "com.apple.developer.ubiquity-container-identifiers": [
            f"{ORIGINAL_TEAM_ID}.com.example.legacy",
        ],
    }

    _, containers = mapper.extract_resources_from_entitlements(entitlements)
    mapped_ents = mapper.map_entitlements(entitlements)

    assert len(containers) == 2
    assert all(c.startswith("iCloud.") for c in containers)
    assert (
        set(mapped_ents["com.apple.developer.icloud-container-identifiers"])
        == containers
    )
    assert set(
        mapped_ents["com.apple.developer.ubiquity-container-identifiers"]
    ).issubset(containers)


def _write_info_plist(directory: Path, bundle_id: str) -> Path:
    info_plist = directory / "Info.plist"
    with open(info_plist, "wb") as f:
        plistlib.dump({"CFBundleIdentifier": bundle_id}, f)
    return info_plist


def test_info_plist_bundle_id_containing_icloud_is_mapped_as_bundle_id(tmp_path):
    mapper = make_mapper()
    info_plist = _write_info_plist(tmp_path, "com.example.app.iCloudSync")
    patcher = AppPatcher(tmp_path, PatchingOptions(encode_ids=True), mapper)

    patcher.patch_info_plist(info_plist, bundle_mapper=mapper, is_main_app=False)

    with open(info_plist, "rb") as f:
        bundle_id = plistlib.load(f)["CFBundleIdentifier"]
    assert bundle_id == f"{mapper.main_bundle_id}.iCloudSync"


def test_info_plist_keeps_original_bundle_id_with_force_original_id(tmp_path):
    mapper = make_mapper()
    info_plist = _write_info_plist(tmp_path, "com.example.app.iCloudSync")
    patcher = AppPatcher(
        tmp_path, PatchingOptions(encode_ids=True, force_original_id=True), mapper
    )

    patcher.patch_info_plist(info_plist, bundle_mapper=mapper, is_main_app=False)

    with open(info_plist, "rb") as f:
        bundle_id = plistlib.load(f)["CFBundleIdentifier"]
    assert bundle_id == "com.example.app.iCloudSync"
