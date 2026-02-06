# Apple Development Certificate Generator

A command-line tool for generating Apple Development signing certificates by creating a Certificate Signing Request (CSR), submitting it to the App Store Connect API, and bundling the signed certificate into multiple formats for use with Xcode and macOS Keychain.


## Features

- ✅ **Cross-platform**: Works on macOS, Linux, and Windows
- ✅ **No external dependencies**: Uses native Go cryptography libraries
- ✅ Interactive prompts for missing configuration (no hardcoding required)
- ✅ Optional password protection for all artifacts

## Prerequisites

- **Apple Developer Account** with API access enabled
- **App Store Connect API Key** (.p8 file) with certificate management permissions

### Getting an App Store Connect API Key

1. Log in to [App Store Connect](https://appstoreconnect.apple.com/)
2. Generate the certificate by navigating to **Users and Access** → **Keys** (under Integrations)
3. Download the `.p8` private key file (save it securely - you can't re-download it)
4. Note the **Key ID** and **Issuer ID** displayed on the page

## Installation

### As GitHub CLI Extension (Recommended)

Install via GitHub CLI:

```bash
gh extension install nsakaimbo/gh-setup-apple-codesign
```

Once installed, you can run the tool using:

```bash
gh setup-apple-codesign [flags]
```

Update to the latest version:

```bash
gh extension upgrade setup-apple-codesign
```

### From Source

```bash
git clone https://github.com/nsakaimbo/gh-setup-apple-codesign.git
cd gh-setup-apple-codesign
go build -o gh-setup-apple-codesign .
```

## Usage

### As GitHub CLI Extension

```bash
gh setup-apple-codesign [flags]
```

### As Standalone Binary

```bash
./gh-setup-apple-codesign [flags]
```

The tool will prompt interactively for any missing required values.

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `APPLE_API_KEY_ID` | Yes | Your Apple API Key ID (10 characters) |
| `APPLE_API_KEY_ISSUER_ID` | Yes | Your Apple API Issuer ID (UUID format) |
| `APPLE_API_PRIVATE_KEY_PATH` | Yes* | Path to your `.p8` private key file |
| `APPLE_API_PRIVATE_KEY` | Yes* | Private key content (PEM format) - alternative to `_PATH` |
| `CERT_COMMON_NAME` | No | Certificate Common Name (CN) |
| `CERT_ORGANIZATION` | No | Certificate Organization (O) |
| `CERT_COUNTRY` | No | Certificate Country Code (C) - 2 letters |
| `CERTIFICATE_PASSWORD` | No | Password to protect P12/PEM bundles |

*One of `APPLE_API_PRIVATE_KEY_PATH` or `APPLE_API_PRIVATE_KEY` must be provided.

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output <dir>` | `signing_artifacts` | Output directory for generated artifacts |
| `--force` | `false` | Overwrite existing artifacts without prompting |
| `--stub` | `false` | Enable stub mode (uses self-signed cert, no API calls) |
| `--help` | - | Show help message |

## Examples

### Interactive Mode (Recommended)

Simply run the tool and it will prompt for any missing values:

```bash
gh setup-apple-codesign
```

### With Environment Variables

```bash
export APPLE_API_KEY_ID="XXXXXXXXXX"
export APPLE_API_KEY_ISSUER_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export APPLE_API_PRIVATE_KEY_PATH="~/keys/AuthKey_XXXXXXXXXX.p8"
export CERT_COMMON_NAME="Apple Development: My Team"
export CERT_ORGANIZATION="My Company Inc"
export CERT_COUNTRY="US"

gh setup-apple-codesign --output ./my-certs
```

### With Password Protection

```bash
export CERTIFICATE_PASSWORD="my-secure-password"
gh setup-apple-codesign
```

### Test Mode (No Real API Calls)

```bash
gh setup-apple-codesign --stub
```

This generates a self-signed certificate locally without contacting Apple's API - useful for testing the tool or CI pipeline setup.

## Output Artifacts

The tool generates three files in the output directory:

| File | Format | Description |
|------|--------|-------------|
| `development_private.key` | PEM | RSA private key (encrypted if password provided) |
| `development_bundle.p12` | PKCS12 | Certificate + private key bundle for Keychain import |
| `development_bundle.pem` | PEM | Combined certificate + private key in PEM format |

## Importing to macOS Keychain

### Via Command Line

```bash
# Without password
security import signing_artifacts/development_bundle.p12 -k ~/Library/Keychains/login.keychain-db

# With password
security import signing_artifacts/development_bundle.p12 -k ~/Library/Keychains/login.keychain-db -P "your-password"
```

### Via Finder

1. Double-click `development_bundle.p12`
2. Enter the password if prompted
3. The certificate will be added to your login keychain

### Verify Import

```bash
security find-identity -v -p codesigning
```

You should see your new "Apple Development" certificate listed.

## Troubleshooting

### Error: "Private key file not found"

Ensure the path to your `.p8` file is correct. The tool supports `~` expansion:

```bash
export APPLE_API_PRIVATE_KEY_PATH="~/Downloads/AuthKey_XXXXXXXXXX.p8"
```

### Error: "Failed to upload CSR"

Check that:
- Your API key has certificate management permissions
- The API key hasn't been revoked
- Your Apple Developer Program membership is active
- Network connectivity to Apple's API is working

### Certificate Not Showing in Xcode

After importing to Keychain:
1. Restart Xcode
2. Go to **Xcode** → **Preferences** → **Accounts**
3. Select your Apple ID → **Manage Certificates**
4. The certificate should appear under "Apple Development"

## Testing

Run the test suite:

```bash
go test -v
```

## Security Notes

- **Private keys are sensitive**: Store them securely and never commit to version control
- **API keys have broad permissions**: Rotate them regularly and revoke unused keys
- **Password protection**: Use strong passwords when protecting certificate bundles
- **Stub mode**: Only use for testing - stub certificates won't work for real code signing
