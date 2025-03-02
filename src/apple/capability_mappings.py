CAPABILITY_MAPPING = {
    "5G Network Slicing": [
        "com.apple.developer.networking.slicing.appcategory",
        "com.apple.developer.networking.slicing.trafficcategory",
    ],
    "Access Wi-Fi Information": ["com.apple.developer.networking.wifi-info"],
    "Accessibility Merchant API Control": [
        "com.apple.developer.accessibility.merchant-api-control"
    ],
    "App Attest": ["com.apple.developer.devicecheck.appattest-environment"],
    "App Groups": ["com.apple.security.application-groups"],
    "Apple Pay Later Merchandising": ["com.apple.developer.pay-later-merchandising"],
    "Apple Pay Payment Processing": ["com.apple.developer.in-app-payments"],
    "Associated Domains": [
        "com.apple.developer.associated-domains",
        "com.apple.developer.associated-domains.mdm-managed",
    ],
    "AutoFill Credential Provider": [
        "com.apple.developer.authentication-services.autofill-credential-provider"
    ],
    "ClassKit": ["com.apple.developer.ClassKit-environment"],
    "CarPlay Audio": [
        "com.apple.developer.carplay-audio",
        "com.apple.developer.playable-content",
    ],
    "CarPlay EV Charging": ["com.apple.developer.carplay-charging"],
    "CarPlay Communication": ["com.apple.developer.carplay-communication"],
    "CarPlay Navigation": ["com.apple.developer.carplay-maps"],
    "CarPlay Parking": ["com.apple.developer.carplay-parking"],
    "CarPlay Quick Food Ordering": ["com.apple.developer.carplay-quick-ordering"],
    "Communication Notifications": [
        "com.apple.developer.usernotifications.communication"
    ],
    "Critical Alerts": ["com.apple.developer.usernotifications.critical-alerts"],
    "Critical Messaging": ["com.apple.developer.messages.critical-messaging"],
    # "Custom Network Protocol": ["com.apple.developer.networking.custom-protocol"], # MacOS only
    "Data Protection": ["com.apple.developer.default-data-protection"],
    "Default Calling App": ["com.apple.developer.calling-app"],
    "Default Messaging App": ["com.apple.developer.messaging-app"],
    "Default Navigation App": ["com.apple.developer.navigation-app"],
    "Default Translation App": ["com.apple.developer.translation-app"],
    "DriverKit": [
        "com.apple.developer.driverkit",
        "com.apple.developer.driverkit.allow-third-party-userclients",
        "com.apple.developer.driverkit.communicates-with-drivers",
        "com.apple.developer.driverkit.family.audio",
        "com.apple.developer.driverkit.family.hid.device",
        "com.apple.developer.driverkit.family.hid.eventservice",
        "com.apple.developer.driverkit.family.midi",
        "com.apple.developer.driverkit.family.networking",
        "com.apple.developer.driverkit.family.scsicontroller",
        "com.apple.developer.driverkit.family.serial",
        "com.apple.developer.driverkit.transport.hid",
        "com.apple.developer.driverkit.transport.usb",
    ],
    "Extended Virtual Addressing": [
        "com.apple.developer.kernel.extended-virtual-addressing"
    ],
    "Family Controls": ["com.apple.developer.family-controls"],
    "FileProvider Testing Mode": ["com.apple.developer.fileprovider.testing-mode"],
    "Fonts": ["com.apple.developer.user-fonts"],
    # "FSKit Module": ["com.apple.developer.fskit.fsmodule"], # MacOS only
    "Game Center": ["com.apple.developer.game-center"],
    "Group Activities": ["com.apple.developer.group-session"],
    "Head Pose": ["com.apple.developer.coremotion.head-pose"],
    "HealthKit": [
        "com.apple.developer.healthkit",
        "com.apple.developer.healthkit.access",
        "com.apple.developer.healthkit.background-delivery",
    ],
    "HealthKit Recalibrate Estimates": [
        "com.apple.developer.healthkit.recalibrate-estimates"
    ],
    "HLS Interstitial Previews": [
        "com.apple.developer.coremedia.hls.interstitial-preview"
    ],
    "HomeKit": ["com.apple.developer.homekit"],
    "Hotspot": ["com.apple.developer.networking.HotspotConfiguration"],
    "iCloud": [
        "com.apple.developer.ubiquity-kvstore-identifier",
        "com.apple.developer.ubiquity-container-identifiers",
        "com.apple.developer.icloud-services",
        "com.apple.developer.icloud-container-environment",
        "com.apple.developer.icloud-container-identifiers",
        "com.apple.developer.icloud-container-development-container-identifiers",
    ],
    "ID Verifier": ["com.apple.developer.proximity-reader.identity.display"],
    "Increased Memory Limits": [
        "com.apple.developer.kernel.increased-debugging-memory-limit",
        "com.apple.developer.kernel.increased-memory-limit",
    ],
    "Inter-App Audio": ["inter-app-audio"],
    "Journaling": ["com.apple.developer.journal.allow"],
    "Low Latency HLS": ["com.apple.developer.coremedia.hls.low-latency"],
    "Manage Thread Network": [
        "com.apple.developer.networking.manage-thread-network-credentials"
    ],
    "Managed App Installation": [
        "com.apple.developer.managed-app-distribution.install-ui"
    ],
    # "Maps": ["com.apple.developer.maps"], # MacOS only
    "Matter Allow Setup Payload": ["com.apple.developer.matter.allow-setup-payload"],
    "MDM Manage Associated Domains": [
        "com.apple.developer.associated-domains.mdm-managed"
    ],
    "Media Device Discovery": ["com.apple.developer.media-device-discovery-extension"],
    # "Media Extension Format Reader": [
    #     "com.apple.developer.mediaextension.formatreader",
    # ], # MacOS only
    # "Media Extension Video Decoder": [
    #     "com.apple.developer.mediaextension.videodecoder",
    # ], # MacOS only
    "Messages Collaboration": ["com.apple.developer.shared-with-you.collaboration"],
    "Multicast": ["com.apple.developer.networking.multicast"],
    "Multipath": ["com.apple.developer.networking.multipath"],
    "Multitasking Camera Access": [
        "com.apple.developer.avfoundation.multitasking-camera-access"
    ],
    "Network Extensions": ["com.apple.developer.networking.networkextension"],
    "NFC Tag Reading": ["com.apple.developer.nfc.readersession.formats"],
    "Notification (NSE) Filtering": ["com.apple.developer.usernotifications.filtering"],
    "On Demand Install Capable for App Clip Extensions": [
        "com.apple.developer.on-demand-install-capable"
    ],
    "Personal VPN": ["com.apple.developer.networking.vpn.api"],
    "Push Notifications": ["com.apple.developer.aps-environment", "aps-environment"],
    "Push to Talk": ["com.apple.developer.push-to-talk"],
    "Sensitive Content Analysis": [
        "com.apple.developer.sensitivecontentanalysis.client"
    ],
    "Shallow Depth and Pressure": [
        "com.apple.developer.submerged-shallow-depth-and-pressure"
    ],
    "Shared with You": ["com.apple.developer.shared-with-you"],
    "Sign In with Apple": ["com.apple.developer.applesignin"],
    "SIM Inserted for Wireless Carriers": [
        "com.apple.developer.coretelephony.sim-inserted"
    ],
    "Siri": ["com.apple.developer.siri"],
    "Spatial Audio Profile": ["com.apple.developer.spatial-audio.profile-access"],
    "Sustained Execution": ["com.apple.developer.sustained-execution"],
    "System Extension": ["com.apple.developer.system-extension.install"],
    "Time Sensitive Notifications": [
        "com.apple.developer.usernotifications.time-sensitive"
    ],
    "User Management": ["com.apple.developer.user-management"],
    # "VMNet": ["com.apple.developer.networking.vmnet"], # MacOS only
    "Wallet": ["com.apple.developer.pass-type-identifiers"],
    "WeatherKit": ["com.apple.developer.weatherkit"],
    "Wireless Accessory Configuration": [
        "com.apple.external-accessory.wireless-configuration"
    ],
    # "Mac Catalyst": ["com.apple.developer.associated-application-identifier"], # MacOS only
}

SPECIAL_CAPABILITIES = {
    "CarPlay Audio",
    "CarPlay EV Charging",
    "CarPlay Communication",
    "CarPlay Navigation",
    "CarPlay Parking",
    "CarPlay Quick Food Ordering",
    "Critical Alerts",
    "Multicast",
    "Notification (NSE) Filtering",
}
