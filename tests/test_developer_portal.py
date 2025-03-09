from rich.table import Table
import os
from apple.developer_portal_api import DeveloperPortalAPI
from apple.apple_account_login import AppleDeveloperAuth
from dotenv import load_dotenv
import random
from warpsign.logger import get_console

console = get_console()


def test_api():
    """Test the Developer Portal API implementation"""
    console.print("[yellow]Starting Developer Portal API test[/]")

    # Get credentials from environment or .env file
    try:
        load_dotenv()
    except ImportError:
        pass

    email = os.getenv("APPLE_ID")
    password = os.getenv("APPLE_PASSWORD")

    if not email or not password:
        console.print(
            "[red]Please set APPLE_ID and APPLE_PASSWORD environment variables or in .env file"
        )
        return

    # Initialize authentication
    auth = AppleDeveloperAuth()
    if not auth.authenticate(email, password):
        console.print("[red]Authentication failed")
        return

    # Create API client
    api = DeveloperPortalAPI(auth)

    # Test teams endpoint
    console.print("\n[cyan]Testing teams endpoint...[/]")
    teams = api.list_teams()

    if teams:
        # Create and display teams table
        table = Table(title="Teams")
        table.add_column("Team ID")
        table.add_column("Name")
        table.add_column("Status")
        table.add_column("Type")
        table.add_column("Roles")

        for team in teams:
            table.add_row(
                team.team_id, team.name, team.status, team.type, ", ".join(team.roles)
            )

        console.print(table)

        # Test certificates endpoint for first team
        console.print(
            f"\n[cyan]Testing certificates endpoint for {teams[0].team_id}...[/]"
        )
        certificates = api.list_certificates(teams[0].team_id)

        if certificates:
            # Create and display certificates table
            table = Table(title="Certificates")
            table.add_column("ID")
            table.add_column("Serial Number")
            table.add_column("Owner ID")
            table.add_column("Type")
            table.add_column("Name")

            for cert in certificates:
                table.add_row(
                    cert.id,
                    cert.serial_number,
                    cert.owner_id,
                    cert.certificate_type,
                    cert.name,
                )

            console.print(table)

        # Add bundle IDs test after certificates
        console.print(
            f"\n[cyan]Testing bundle IDs endpoint for {teams[0].team_id}...[/]"
        )
        all_bundle_ids = api.list_bundle_ids(teams[0].team_id)

        target_bundle = None
        if all_bundle_ids:
            # Search through all results for target
            for bundle in all_bundle_ids:
                if bundle.identifier == "com.changeme.test":
                    target_bundle = bundle
                    console.print("[green]Found target bundle: com.changeme.test[/]")
                    break

            # Only show first 10 in table
            table = Table(
                title=f"Bundle IDs (showing first 10 of {len(all_bundle_ids)})"
            )
            table.add_column("ID")
            table.add_column("Identifier")
            table.add_column("Name")

            for bundle in all_bundle_ids[:10]:
                table.add_row(
                    bundle.id,
                    bundle.identifier,
                    bundle.name,
                )

            console.print(table)

        # Add capabilities test for specific bundle
        if target_bundle:
            console.print(
                f"\n[cyan]Testing capabilities endpoint for {target_bundle.identifier}...[/]"
            )
            capabilities = api.get_capabilities_for_bundle_id(
                teams[0].team_id, target_bundle.id
            )

            if capabilities:
                # Create capabilities table
                table = Table(title=f"Capabilities for {target_bundle.identifier}")
                table.add_column("ID")
                table.add_column("Name")
                table.add_column("Optional")
                table.add_column("Entitlements")

                for cap in capabilities:
                    table.add_row(
                        cap.id,
                        cap.name,
                        str(cap.optional),
                        str(len(cap.entitlements)),
                    )

                console.print(table)

                # Show detailed entitlements for each capability that has them
                for cap in capabilities:
                    if cap.entitlements:
                        table = Table(title=f"Entitlements for {cap.name}")
                        table.add_column("Key")
                        table.add_column("Name")
                        table.add_column("Type")
                        table.add_column("Profile Key")
                        table.add_column("Values")

                        for ent in cap.entitlements:
                            table.add_row(
                                ent.key,
                                ent.name,
                                ent.value_type,
                                ent.profile_key,
                                (
                                    str(ent.values)[:50] + "..."
                                    if len(str(ent.values)) > 50
                                    else str(ent.values)
                                ),
                            )

                        console.print(table)

        # Add available entitlements test if we found our target bundle
        if target_bundle:
            console.print(
                f"\n[cyan]Testing available entitlements for {target_bundle.identifier}...[/]"
            )
            available = api.fetch_available_user_entitlements(
                teams[0].team_id, target_bundle.id
            )

            if available:
                # Create available capabilities table with all entries
                table = Table(
                    title=f"Available Capabilities for {target_bundle.identifier}"
                )
                table.add_column("ID")
                table.add_column("Name")
                table.add_column("Optional")
                table.add_column("Editable")
                table.add_column("Description", width=50)

                for cap in available:
                    table.add_row(
                        cap.id,
                        cap.name,
                        str(cap.optional),
                        str(cap.editable),
                        (
                            cap.description[:50] + "..."
                            if cap.description and len(cap.description) > 50
                            else ""
                        ),
                    )

                console.print(table)

                # Show all entitlements for each capability
                for cap in available:
                    if cap.entitlements:
                        console.print(
                            f"\n[bold cyan]Capability: {cap.name} ({cap.id})[/]"
                        )
                        console.print(f"[dim]Description: {cap.description}[/]")
                        if cap.settings:
                            console.print("[cyan]Settings:[/]")
                            console.print(cap.settings)

                        table = Table(show_header=True, box=None)
                        table.add_column("Type")
                        table.add_column("Entitlement Key")
                        table.add_column("Name")
                        table.add_column("Profile Key")
                        table.add_column("Value Type")
                        table.add_column("Values")
                        table.add_column("Distribution")

                        # Sort entitlements - primary ones (matching capability ID) first
                        sorted_ents = sorted(
                            cap.entitlements,
                            key=lambda x: (
                                (
                                    0 if x.id == cap.id else 1
                                ),  # Primary if ID matches capability ID
                                x.id,
                            ),
                        )

                        for ent in sorted_ents:
                            # Format values in a more readable way
                            values_str = str(ent.values)
                            if len(values_str) > 50:
                                values_str = values_str[:47] + "..."

                            # Primary if entitlement key matches capability ID
                            is_primary = ent.id == cap.id
                            type_str = (
                                "[green]PRIMARY[/]"
                                if is_primary
                                else "[blue]INTERNAL[/]"
                            )

                            table.add_row(
                                type_str,
                                ent.id,  # This is the entitlement key
                                ent.name,
                                f"[dim]{ent.profile_key}[/]",
                                ent.value_type,
                                values_str,
                                ", ".join(dt.name for dt in ent.distribution_types),
                            )

                        console.print(table)

        # Test setting capabilities if we found our target bundle
        if target_bundle and available:
            # Get all available capability IDs
            all_capability_ids = [cap.id for cap in available]

            # Always include APP_GROUPS and ICLOUD
            capabilities_to_enable = ["APP_GROUPS", "ICLOUD"]

            # Add 6 more random capabilities (excluding APP_GROUPS and ICLOUD)
            other_capabilities = [
                id for id in all_capability_ids if id not in capabilities_to_enable
            ]
            capabilities_to_enable.extend(
                random.sample(other_capabilities, min(6, len(other_capabilities)))
            )

            # Get app groups and iCloud containers
            app_groups = api.list_app_group_ids(teams[0].team_id)
            icloud_containers = api.list_icloud_container_ids(teams[0].team_id)

            # Select 2 random IDs from each if available
            group_ids = {}
            if app_groups:
                group_ids["APP_GROUPS"] = [
                    g.id for g in random.sample(app_groups, min(2, len(app_groups)))
                ]
            if icloud_containers:
                group_ids["ICLOUD"] = [
                    c.id
                    for c in random.sample(
                        icloud_containers, min(2, len(icloud_containers))
                    )
                ]

            console.print("\n[cyan]Testing capability setting...[/]")
            console.print("[green]Enabling these capabilities:[/]")
            for cap_id in capabilities_to_enable:
                # Find and print the capability name
                cap = next((cap for cap in available if cap.id == cap_id), None)
                if cap:
                    console.print(f"- {cap.name} ({cap.id})")

            if group_ids:
                console.print("\n[green]Using these group IDs:[/]")
                for cap_id, ids in group_ids.items():
                    console.print(f"- {cap_id}: {', '.join(ids)}")

            # Set the capabilities
            success = api.set_entitlements_for_bundle_id(
                teams[0].team_id,
                target_bundle.id,
                target_bundle.identifier,
                capabilities_to_enable,
                group_ids=group_ids,
            )

            if success:
                console.print("[green]Successfully updated capabilities![/]")
            else:
                console.print("[red]Failed to update capabilities[/]")

        # Add app groups test
        console.print(
            f"\n[cyan]Testing app groups endpoint for {teams[0].team_id}...[/]"
        )
        app_groups = api.list_app_group_ids(teams[0].team_id)

        if app_groups:
            table = Table(title=f"App Groups (showing first 10 of {len(app_groups)})")
            table.add_column("ID")
            table.add_column("Identifier")
            table.add_column("Name")

            for group in app_groups[:10]:
                table.add_row(
                    group.id,
                    group.identifier,
                    group.name,
                )

            console.print(table)

        # Add iCloud containers test
        console.print(
            f"\n[cyan]Testing iCloud containers endpoint for {teams[0].team_id}...[/]"
        )
        containers = api.list_icloud_container_ids(teams[0].team_id)

        if containers:
            table = Table(
                title=f"iCloud Containers (showing first 10 of {len(containers)})"
            )
            table.add_column("ID")
            table.add_column("Identifier")
            table.add_column("Name")

            for container in containers[:10]:
                table.add_row(
                    container.id,
                    container.identifier,
                    container.name,
                )

            console.print(table)

        # Add devices test
        console.print(f"\n[cyan]Testing devices endpoint for {teams[0].team_id}...[/]")
        devices = api.list_devices(teams[0].team_id)

        if devices:
            table = Table(title=f"Devices (showing first 10 of {len(devices)})")
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("UDID")
            table.add_column("Status")
            table.add_column("Class")
            table.add_column("Platform")
            table.add_column("Model")

            for device in devices[:10]:
                table.add_row(
                    device.id,
                    device.name,
                    device.udid,
                    device.status,
                    device.device_class,
                    device.platform,
                    device.model or "N/A",
                )

            console.print(table)

        # Add profiles test
        console.print(f"\n[cyan]Testing profiles endpoint for {teams[0].team_id}...[/]")
        profiles = api.list_profiles(teams[0].team_id)

        if profiles:
            table = Table(title=f"Profiles (showing first 10 of {len(profiles)})")
            table.add_column("ID")
            table.add_column("State")
            table.add_column("Name")
            table.add_column("Platform")
            table.add_column("Type")

            for profile in profiles[:10]:
                table.add_row(
                    profile.id,
                    profile.profile_state,
                    profile.name,
                    profile.platform,
                    profile.profile_type_label,
                )

            console.print(table)

            # Try downloading the first profile
            if profiles:
                console.print(
                    f"\n[cyan]Testing profile download for {profiles[0].id}..."
                )
                profile_data = api.download_provisioning_profile(
                    teams[0].team_id, profiles[0].id
                )
                if profile_data:
                    console.print(
                        f"[green]Successfully downloaded profile ({len(profile_data)} bytes)"
                    )
                    # Optionally save to file for testing
                    # with open(f"profile_{profiles[0].id}.mobileprovision", "wb") as f:
                    #     f.write(profile_data)

        # Add registration tests
        console.print("\n[cyan]Testing registration endpoints...[/]")

        # Add profile creation test
        console.print("\n[cyan]Testing profile creation...[/]")

        # Get all devices and filter for iOS devices
        devices = api.list_devices(teams[0].team_id)
        ios_devices = [d for d in devices if d.device_class in ("IPHONE", "IPAD")]

        if not ios_devices:
            console.print("[red]No iOS devices found - cannot create profile")
        else:
            # Get certificates and find a distribution cert
            certificates = api.list_certificates(teams[0].team_id)
            dist_certs = [
                c for c in certificates if "distribution" in c.certificate_type.lower()
            ]

            if not dist_certs:
                console.print(
                    "[red]No distribution certificates found - cannot create profile"
                )
            else:
                # Select random devices and cert
                selected_devices = random.sample(ios_devices, min(3, len(ios_devices)))
                selected_cert = random.choice(dist_certs)

                console.print("[green]Selected devices:")
                for device in selected_devices:
                    console.print(f"- {device.name} ({device.device_class})")
                console.print(f"[green]Selected certificate: {selected_cert.name}")

                # Create profile
                profile_data = api.create_or_regen_provisioning_profile(
                    team_id=teams[0].team_id,
                    profile_id="",  # Empty for new profile
                    app_id_id="LDAHL3T872",
                    profile_name="Test Profile 2",
                    certificate_ids=[selected_cert.id],
                    device_ids=[d.id for d in selected_devices],
                    distribution_type="adhoc",
                )

                if profile_data:
                    console.print("[green]Successfully created profile:")
                    console.print(
                        f"Profile ID: {profile_data.get('provisioningProfileId')}"
                    )
                    console.print(f"UUID: {profile_data.get('UUID')}")
                    console.print(f"Expires: {profile_data.get('dateExpire')}")

        # Test bundle ID registration
        test_bundle = api.register_bundle_id(
            teams[0].team_id,
            f"com.changeme.test",
            "Test Bundle ID",
        )
        if test_bundle:
            console.print("[green]Successfully registered bundle ID:")
            console.print(f"  ID: {test_bundle.id}")
            console.print(f"  Identifier: {test_bundle.identifier}")
            console.print(f"  Name: {test_bundle.name}")

        # Test app group registration
        test_group = api.register_app_group(
            teams[0].team_id,
            f"group.changeme.test",
            "Test App Group",
        )
        if test_group:
            console.print("[green]Successfully registered app group:")
            console.print(f"  ID: {test_group.id}")
            console.print(f"  Identifier: {test_group.identifier}")
            console.print(f"  Name: {test_group.name}")

        # Test iCloud container registration
        test_container = api.register_icloud_container(
            teams[0].team_id,
            f"iCloud.changeme.test",
            "Test iCloud Container",
        )
        if test_container:
            console.print("[green]Successfully registered iCloud container:")
            console.print(f"  ID: {test_container.id}")
            console.print(f"  Identifier: {test_container.identifier}")
            console.print(f"  Name: {test_container.name}")


if __name__ == "__main__":
    test_api()
