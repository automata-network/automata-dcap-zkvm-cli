use anyhow::Result;
use risc0_solana::{client::*, Proof};
use risc0_zkvm::{sha::Digestible, Receipt};

use std::{
    fs::{create_dir_all, File},
    io::Write,
    path::Path,
};

// this method generates claim_digest.bin and compressed_proof.bin
pub fn generate_files_for_solana(receipt: Receipt) -> Result<()> {
    let preston_dir_path = &format!("{}/solana-client/data", env!("CARGO_MANIFEST_DIR"));
    if !Path::new(preston_dir_path).exists() {
        create_dir_all(preston_dir_path)?;
        log::info!("Created path: {}", preston_dir_path);
    }

    // write the receipt
    let receipt_json = serde_json::to_vec(&receipt)?;
    let receipt_dir_path = &format!("{}/receipt.json", preston_dir_path);
    write_output(receipt_dir_path, &receipt_json);
    log::info!(
        "The receipt has been successfully written to {}",
        receipt_dir_path
    );

    // write the claim digest
    let claim_digest: [u8; 32] = receipt.inner.groth16()?.claim.digest().try_into()?;
    let claim_digest_dir_path = &format!("{}/claim_digest.bin", preston_dir_path);
    write_output(claim_digest_dir_path, &claim_digest);
    log::info!("Raw claim digest written to {}", claim_digest_dir_path);

    // write the compressed proof
    let proof_raw = &receipt.inner.groth16().unwrap().seal;
    let mut proof = Proof {
        pi_a: proof_raw[0..64].try_into()?,
        pi_b: proof_raw[64..192].try_into()?,
        pi_c: proof_raw[192..256].try_into()?,
    };
    proof.pi_a = negate_g1(&proof.pi_a)?;

    let compressed_proof_a = compress_g1_be(&proof.pi_a);
    let compressed_proof_b = compress_g2_be(&proof.pi_b);
    let compressed_proof_c = compress_g1_be(&proof.pi_c);

    let compressed_proof = [
        compressed_proof_a.as_slice(),
        compressed_proof_b.as_slice(),
        compressed_proof_c.as_slice(),
    ]
    .concat();

    let compressed_proof_dir_path = &format!("{}/compressed_proof.bin", preston_dir_path);
    write_output(compressed_proof_dir_path, &compressed_proof);
    log::info!("Compressed proof written to {}", compressed_proof_dir_path);

    Ok(())
}

fn write_output(dir_path: &str, content: &[u8]) {
    let mut file = File::create(dir_path).unwrap();
    file.write_all(content)
        .expect(format!("Failed to write to {}", dir_path).as_str());
}
