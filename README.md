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
- 🖥️ **Flexible Signing**: Local signing on Mac or remote signing via CI - no Mac required!

## 🎯 Based on SignTools-CI

This project is based on the fantastic [SignTools-CI](https://github.com/SignTools/SignTools-CI) by ViRb3. Without his work, this project would not have been possible. Many thanks! 🙏

## ⚠️ Requirements

- **Paid Apple Developer Account**. Free accounts will never be supported.
- Apple Developer or Distribution Certificate (generated via Developer Portal)
- Python 3.8 or higher
- macOS (Apple signing requirements)

> [!WARNING]
> Wildcard provisioning profiles and identifiers are not supported

## 💻 System Requirements

### Local Signing

- macOS 11.0 or later (required for code signing)
- Command Line Tools for Xcode (run `xcode-select --install`)
- At least 1GB free disk space for temporary files
- Active internet connection for Developer Portal API access

> [!IMPORTANT]
> Whilst every attempt has been made throughout the script to limit the impact to your system, there is still modification of system resources such as the keychain. If you do not wish to have any such impact on your system, it's recommended to use the CI version.

### CI Signing

- Any operating system (Windows, macOS, or Linux)
- Python 3.8 or higher
- Active internet connection
- GitHub account with repository access

> [!IMPORTANT]
> CI signing is limited to files with a maximum of 1GB. At this time, they're also unable to use the `--icon` option.

## 📦 Dependencies

Install required packages:

Download all requirements using the requirements.txt file.

```bash
pip install -r requirements.txt
```

## 📝 Certificate Setup


> [!NOTE]
> #### If you don't have a certificate.
> - If you're using macOS, follow this [guide from Apple](https://developer.apple.com/help/account/create-certificates/create-developer-id-certificates/)
> - If you're using Windows. You can follow this [guide](https://mzansibytes.com/2021/08/28/create-apple-developer-certificates-on-windows/)
> - If you're using Linux. You can follow this [guide](https://gist.github.com/boodle/77436b2d9facb8e938ad)

> [!WARNING]
> You must have a password with your certificate.

This part assume that you have a working Apple Development and Apple Distribution certificate.

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

### CI Usage

1. Fork or use the template [warpsign-ci](https://github.com/teflocarbon/warpsign-ci). Make sure workflows are enabled under the Actions tab.

> [!WARNING]
> It's recommended to use a template rather than a fork, since a fork must be public and cannot be made private. The logs will output things like your Team ID and your name as an Apple Developer.

2. Copy `config.toml.sample` to `config.toml`:

```bash
cp config.toml.sample config.toml
```

3. Edit `config.toml` with your GitHub token and settings:

```toml
github_token = "your-github-token"
repository = "your-username/your-repo"
workflow = "sign.yml"
```

> [!IMPORTANT]
> It's recommended to use a `Fine-grained personal access token` from GitHub. You only need to enable Read/write access on Secret and Actions. If you don't know how to create a token, please read the [GitHub documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

4. Run the CI signing script:

```bash
python3 sign-ci.py my-app.ipa
```

## Examples

Show all available options

```bash
python3 sign.py -h
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
