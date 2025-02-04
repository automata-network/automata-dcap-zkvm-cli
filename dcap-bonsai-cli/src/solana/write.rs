use super::receipt_to_proof;

use anyhow::Result;
use risc0_zkvm::{sha::Digestible, Receipt};
use std::{
    fs::{create_dir_all, File},
    io::Write,
    path::Path
};

// this method generates journal_digest.bin and compressed_proof.bin
pub fn generate_files_for_solana(receipt: &Receipt) -> Result<()> {
    let preston_dir_path = &format!("{}/solana-client/data", env!("CARGO_MANIFEST_DIR"));
    if !Path::new(preston_dir_path).exists() {
        create_dir_all(preston_dir_path)?;
        log::info!("Created path: {}", preston_dir_path);
    }
    
    // get the journal digest
    let journal_digest = receipt.journal.digest();
    let journal_digest_bytes = journal_digest.as_bytes();
    let journal_digest_dir_path = &format!("{}/journal_digest.bin", preston_dir_path);
    write_output(journal_digest_dir_path, journal_digest_bytes);
    log::info!(
        "The journal digest has been successfully written to {}",
        journal_digest_dir_path
    );

    // write the receipt
    let receipt_json = serde_json::to_vec(&receipt)?;
    let receipt_dir_path = &format!("{}/receipt.json", preston_dir_path);
    write_output(receipt_dir_path, &receipt_json);
    log::info!(
        "The receipt has been successfully written to {}",
        receipt_dir_path
    );

    // convert receipt to proof
    let proof = receipt_to_proof(&receipt.inner.groth16().unwrap().seal).unwrap();
    let proof_bytes = proof.to_bytes();

    let proof_dir_path = &format!("{}/proof.bin", preston_dir_path);
    write_output(proof_dir_path, &proof_bytes);
    log::info!(
        "The proof has been successfully written to {}",
        proof_dir_path
    );

    Ok(())
}

fn write_output(dir_path: &str, content: &[u8]) {
    let mut file = File::create(dir_path).unwrap();
    file.write_all(content)
        .expect(format!("Failed to write to {}", dir_path).as_str());
}