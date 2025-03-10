# 🔒 WarpSign

A lightning-fast iOS app signing solution that leverages the Apple Developer Portal API for seamless entitlements management and code signing.

![Status](https://img.shields.io/badge/status-beta-yellow)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
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
- Python 3.10 or higher
- macOS (Apple signing requirements)

> [!WARNING]
> Wildcard provisioning profiles and identifiers are not supported

## 💻 System Requirements

### Local Signing

- macOS 11.0 or later (required for code signing)
- Command Line Tools for Xcode (run `xcode-select --install`)
- ldid (run `brew install ldid-procursus`)
- At least 1GB free disk space for temporary files
- Active internet connection for Developer Portal API access

> [!IMPORTANT]
> Whilst every attempt has been made throughout the script to limit the impact to your system, there is still modification of system resources such as the keychain. If you do not wish to have any such impact on your system, it's recommended to use the CI version.

### CI Signing

- Any operating system (Windows, macOS, or Linux)
- Python 3.10 or higher
- Active internet connection
- GitHub account with repository access

> [!IMPORTANT]
> CI signing is limited to files with a maximum of 1GB. At this time, they're also unable to use the `--icon` option.

## 📦 Installation

### Install pipx

First, install pipx which is used to install and run Python applications in isolated environments:

See the [pipx installation guide](https://github.com/pypa/pipx?tab=readme-ov-file#install-pipx) here.

### Install or Update WarpSign

```bash
pipx install --force https://github.com/teflocarbon/warpsign/archive/main.zip
```

For automated environments or advanced users:

```bash
pip install --force-reinstall https://github.com/teflocarbon/warpsign/archive/main.zip
```

## 🔐 Setup Wizard

The easiest way to set up WarpSign is to use the built-in setup wizard:

```bash
warpsign setup
```

This interactive wizard will guide you through:

- Uploading your development and distribution certificates
- Setting up your Apple ID credentials
- Configuring GitHub CI settings (if needed)
- Creating your configuration file

## 📝 Advanced Configuration

For advanced users who prefer manual configuration:

1. WarpSign stores configuration in `~/.warpsign/` directory
2. Sample configuration file is available at `warpsign/src/constants/config.toml.sample`
3. Certificates should be placed in:
   ```
   ~/.warpsign/certificates/
   ├── development/
   │   ├── cert.p12
   │   └── cert_pass.txt
   └── distribution/
       ├── cert.p12
       └── cert_pass.txt
   ```

> [!WARNING]
> You must have a password with your certificate.

## 🔑 Session Management

WarpSign stores authentication sessions in `~/.warpsign/sessions/` to avoid repeated login prompts. To force re-authentication, delete this directory:

```bash
rm -rf ~/.warpsign/sessions
```

## 🚀 Usage

Get help and see available options:

```bash
warpsign --help
```

Basic signing:

```bash
warpsign sign my-app.ipa
```

### CI Usage

1. Fork or use the template [warpsign-ci](https://github.com/teflocarbon/warpsign-ci). Make sure workflows are enabled under the Actions tab.

> [!WARNING]
> It's recommended to use a template rather than a fork, since a fork must be public and cannot be made private. The logs will output things like your Team ID and your name as an Apple Developer.

2. Set up your CI configuration using the setup wizard:

```bash
warpsign setup --ci
```

3. Run the CI signing:

```bash
warpsign sign-ci my-app.ipa
```

> [!IMPORTANT]
> It's recommended to use a `Fine-grained personal access token` from GitHub. You only need to enable Read/write access on Secret and Actions. If you don't know how to create a token, please read the [GitHub documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

## Examples

Show all available options:

```bash
warpsign sign --help
```

Enable debug mode (requires development certificate):

```bash
warpsign sign my-app.ipa --patch-debug
```

Force original bundle ID for push notifications (requires distribution certificate):

```bash
warpsign sign my-app.ipa --force-original-id
```

Enable file sharing and promotion support:

```bash
warpsign sign my-app.ipa --patch-file-sharing --patch-promotion
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
