# Android Signer

A pure-Rust library and CLI tool for parsing and signing Android App Bundles (.aab) and Android Packages (.apk).

This repository is a refactored and modernized fork of `google/pack`, decomposed into a Cargo workspace consisting of two crates:
- `android-signer-cli`: A standalone, statically-compiled command-line tool.
- `android-signer-lib`: A reusable Rust library crate for integrating Android signing capabilities into your own applications.

## Usage (CLI)

You can download pre-compiled binaries from the [Releases](https://github.com/TODO/releases) page for Windows, macOS, and Linux.

The CLI takes an input archive, a `.p12` keystore file, and the keystore password, then outputs a signed archive containing the v2/v3 signatures.

```bash
android-signer-cli --input app-release-unsigned.aab \
                   --output app-release-signed.aab \
                   --keystore my-release-key.p12 \
                   --password my-super-secret-password
```

By default it will look for `keystore.p12` and use `password` as the password.

### Supported Build Targets

- `x86_64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `x86_64-pc-windows-msvc`

## Usage (Library)

Add `android-signer-lib` to your `Cargo.toml`.

```toml
[dependencies]
android-signer-lib = "0.1"
```

Then you can use it in your code as follows:

```rust
use android_signer_lib::{crypto_keys::Keys, sign_apk_buffer};
use std::fs;

fn sign_my_app() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load Keys
    let p12_bytes = fs::read("my_keystore.p12")?;
    let keys = Keys::from_p12(&p12_bytes, "my_password")?;

    // 2. Read App Buffer
    let mut apk_buf = fs::read("unsigned.apk")?;

    // 3. Sign Archive
    let signed_buf = sign_apk_buffer(&mut apk_buf, &keys)?;
    
    // 4. Save
    fs::write("signed.apk", signed_buf)?;
    Ok(())
}
```

## Features
- **Zero dependencies** on the Android SDK, Java, or `apksigner`.
- Computes **APK Signature Scheme v2 and v3** blocks directly.
- Handles both `.apk` and `.aab` file structures natively.

## License

Apache License 2.0