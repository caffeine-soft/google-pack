use android_signer_lib::{crypto_keys::Keys, sign_apk_buffer};
use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to input .aab or .apk
    #[arg(short, long)]
    input: PathBuf,

    /// Path to save the signed file
    #[arg(short, long)]
    output: PathBuf,

    /// Path to the .p12 keystore
    #[arg(short, long, default_value = "keystore.p12")]
    keystore: PathBuf,

    /// Keystore password
    #[arg(short, long, default_value = "password")]
    password: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Read the keystore
    let keystore_bytes = fs::read(&args.keystore)
        .with_context(|| format!("Failed to read keystore at {:?}", args.keystore))?;

    // Extract keys
    let keys = if args
        .keystore
        .extension()
        .map_or(false, |ext| ext.eq_ignore_ascii_case("pem"))
    {
        let pem_str = String::from_utf8(keystore_bytes)
            .map_err(|_| anyhow::anyhow!("PEM keystore is not valid UTF-8"))?;
        Keys::from_combined_pem_string(&pem_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse PEM keystore: {}", e))?
    } else {
        Keys::from_p12(&keystore_bytes, &args.password)
            .map_err(|e| anyhow::anyhow!("Failed to parse keystore keys: {}", e))?
    };

    // Read the input archive
    let mut apk_buf = fs::read(&args.input)
        .with_context(|| format!("Failed to read input file at {:?}", args.input))?;

    // Sign the buffer
    let signed_buf = sign_apk_buffer(&mut apk_buf, &keys)
        .map_err(|e| anyhow::anyhow!("Failed to sign archive: {}", e))?;

    // Write to output
    fs::write(&args.output, signed_buf)
        .with_context(|| format!("Failed to write output file at {:?}", args.output))?;

    println!(
        "Successfully signed {:?} and saved to {:?}",
        args.input, args.output
    );

    Ok(())
}
