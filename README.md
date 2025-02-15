# 🔒 WarpSign

A lightning-fast iOS app signing solution that leverages the Apple Developer Portal API for seamless entitlements management and code signing.

![Status](https://img.shields.io/badge/status-beta-yellow)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue)

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [System Requirements](#-system-requirements)
- [Dependencies](#-dependencies)
- [Certificate Setup](#-certificate-setup)
- [Environment Setup](#-environment-setup)
- [Session Management](#-session-management)
- [Usage](#-usage)
- [Common Issues](#-common-issues)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

- 🚀 **Blazing Fast**: Sign apps in 30-60 seconds
- 🔑 **Smart Entitlements**: Automatically manages app entitlements based on your developer account capabilities
- 🔄 **Native API**: Direct Apple Developer Portal integration without Fastlane dependency
- 🛡️ **MFA Support**: Handles Apple Developer Portal login with 2FA authentication
- 🔧 **Binary Patching**: Fixes apps that require their original identifiers
- 📱 **Push Support**: Enable push notifications with distribution certificates

## 🎯 Based on SignTools-CI

This project is based on the fantastic [SignTools-CI](https://github.com/SignTools/SignTools-CI) by ViRb3. Without his work, this project would not have been possible. Many thanks! 🙏

## ⚠️ Requirements

- Paid Apple Developer Account
- Apple Developer or Distribution Certificate (generated via Developer Portal)
- Python 3.8 or higher
- macOS (Apple signing requirements)

> ⚠️ **Note**: Wildcard provisioning profiles and identifiers are not supported

## 💻 System Requirements

- macOS 11.0 or later (required for code signing)
- Command Line Tools for Xcode (run `xcode-select --install`)
- At least 1GB free disk space for temporary files
- Active internet connection for Developer Portal API access

## 📦 Dependencies

Install required packages:

```bash
pip install rich requests pysrp python-dotenv lief
```

Or use the requirements file:

```bash
pip install -r requirements.txt
```

## 📝 Certificate Setup

1. Create the following directory structure in your project root:

```
certificates/
├── development/
│   ├── cert.p12
│   └── cert_pass.txt
└── distribution/
    ├── cert.p12
    └── cert_pass.txt
```

2. Add your certificates and passwords:
   - Place your certificates as `cert.p12` in the respective folders
   - Create `cert_pass.txt` with your certificate password
   - Use development or distribution certificates from Apple Developer Portal

## 🔐 Environment Setup

Create a `.env` file in the project root:

```env
APPLE_ID=your.apple.id@example.com
APPLE_PASSWORD=your_apple_password
```

These credentials are used for Apple Developer Portal authentication.

## 🔑 Session Management

WarpSign stores authentication sessions in `~/.warpsign/sessions/` to avoid repeated login prompts. To force re-authentication, delete this directory:

```bash
rm -rf ~/.warpsign/sessions
```

## 🚀 Usage

Get help and see available options:

```bash
python3 sign.py --help
```

Basic signing:

```bash
python3 sign.py my-app.ipa
```

Enable debug mode (requires development certificate):

```bash
python3 sign.py my-app.ipa --patch-debug
```

Force original bundle ID for push notifications (requires distribution certificate):

```bash
python3 sign.py my-app.ipa --force-original-id
```

Enable file sharing and promotion support:

```bash
python3 sign.py my-app.ipa --patch-file-sharing --patch-promotion
```

## 🚨 Common Issues

- **Certificate Errors**: Try re-create your certificate, make sure it's exported with the private key.
- **Authentication Failed**: Check your Apple ID credentials and ensure 2FA is handled properly
- **Signing Failed**: Verify certificate passwords and ensure they haven't expired
- **Push Notifications**: Use `--force-original-id` with distribution certificates for push support

## 🤝 Contributing

Contributions are welcome! Feel free to:

- 🐛 Report bugs
- 💡 Suggest features
- 🔧 Submit pull requests

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0) - see the [LICENSE](LICENSE) file for details.

---

💫 Made with ❤️ in Australia for the iOS sideloading community
