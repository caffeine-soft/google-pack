// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::error::Result;
use crypto_keys::Keys;
use deku::DekuContainerWrite;
use hasher::compute_top_level_hash;
use signing_block::compute_signing_block;
use zip_parser::find_offsets;
use zip_rebuilder::rebuild_zip_with_signing_block;

mod crypto;
pub mod crypto_keys;
pub mod error;
mod hasher;
mod signed_data_block;
mod signing_block;
mod signing_types;
pub mod v1_signing;
pub mod zip;
mod zip_parser;
mod zip_rebuilder;

use std::io::{Cursor, Read};

// APK Signature Scheme v2 based on https://source.android.com/docs/security/features/apksigning/v2
// APK Signature Scheme v3 based on https://source.android.com/docs/security/features/apksigning/v3
/// Signs a ZIP file buffer, adding an APK Signature Block before its Central Directory.
/// Can be used for APK files.
pub fn sign_apk_buffer(apk_buf: &mut [u8], keys: &Keys) -> Result<Vec<u8>> {
    // Dry-run the block to figure out how long it will be given our key
    let dry_run = compute_signing_block([0; 32], keys)?;
    let signing_block_size = dry_run.to_bytes()?.len();
    // Read ZIP file to find central directory
    let offsets = find_offsets(apk_buf)?;
    // SHA-256 hash of ZIP contents (accounting for APK Signing Block)
    let top_level_hash = compute_top_level_hash(apk_buf, &offsets, signing_block_size)?;
    // Compute again using the real hash this time
    let signing_block = compute_signing_block(top_level_hash, keys)?;
    // Build up the final zip file again
    rebuild_zip_with_signing_block(&offsets, apk_buf, signing_block)
}

/// Signs an Android App Bundle (.aab) format file in memory using v1 (JAR) signing.
pub fn sign_aab_buffer(aab_buf: &[u8], keys: &Keys) -> Result<Vec<u8>> {
    let cursor = Cursor::new(aab_buf);
    let mut archive = ::zip::ZipArchive::new(cursor)?;

    let mut files = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let path = file.name().to_string();

        // Skip existing signature files to allow resigning
        if path.starts_with("META-INF/")
            && (path.ends_with(".SF")
                || path.ends_with(".RSA")
                || path.ends_with(".DSA")
                || path.ends_with("MANIFEST.MF"))
        {
            continue;
        }

        // Directories shouldn't be read as files
        if file.is_dir() {
            continue;
        }

        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        files.push(crate::zip::File { path, data });
    }

    crate::v1_signing::add_v1_signature_files(&mut files, keys)?;

    let mut out_cursor = Cursor::new(Vec::new());
    crate::zip::zip_apk(&files, &mut out_cursor)?;

    Ok(out_cursor.into_inner())
}
