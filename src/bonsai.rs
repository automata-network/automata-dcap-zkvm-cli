use super::constants::DEFAULT_IMAGE_ID_HEX;

use alloy_primitives::FixedBytes;
use anyhow::{Context, Result};
use bonsai_sdk::alpha as bonsai_sdk;
use risc0_ethereum_contracts::groth16::Seal;
use risc0_zkvm::{compute_image_id, Receipt};
use std::{str::FromStr, time::Duration};

/// An implementation of a Prover that runs on Bonsai.
pub struct BonsaiProver {}
impl BonsaiProver {
    /// Generates a snark proof as a triplet (`Vec<u8>`, `FixedBytes<32>`,
    /// `Vec<u8>) for the given elf and input.
    pub fn prove(elf: Option<&[u8]>, input: &[u8]) -> Result<(Vec<u8>, FixedBytes<32>, Vec<u8>)> {
        let client = bonsai_sdk::Client::from_env(risc0_zkvm::VERSION)?;

        // Compute the image_id, then upload the ELF with the image_id as its key.
        let image_id_hex: String;
        match elf {
            Some(elf) => {
                let image_id = compute_image_id(elf)?;
                image_id_hex = image_id.to_string();
                client.upload_img(&image_id_hex, elf.to_vec())?;
            }
            None => {
                image_id_hex = String::from_str(DEFAULT_IMAGE_ID_HEX)?;
            }
        }

        println!("ImageID: {}", image_id_hex);

        // Prepare input data and upload it.
        let input_id = client.upload_input(input.to_vec())?;

        println!("InputID: {}", input_id);

        // Start a session running the prover.
        let session = client.create_session(image_id_hex, input_id, vec![])?;
        println!("Prove session created, uuid: {}", session.uuid);
        let _receipt = loop {
            let res = session.status(&client)?;
            if res.status == "RUNNING" {
                std::thread::sleep(Duration::from_secs(15));
                continue;
            }
            if res.status == "SUCCEEDED" {
                println!("Prove session is successful!");
                // Download the receipt, containing the output.
                let receipt_url = res
                    .receipt_url
                    .context("API error, missing receipt on completed session")?;

                let receipt_buf = client.download(&receipt_url)?;
                let receipt: Receipt = bincode::deserialize(&receipt_buf)?;

                break receipt;
            }

            panic!(
                "Workflow exited: {} - | err: {}",
                res.status,
                res.error_msg.unwrap_or_default()
            );
        };

        // Fetch the snark.
        let snark_session = client.create_snark(session.uuid)?;
        println!("Proof to SNARK session created, uuid: {}", snark_session.uuid);
        let snark_receipt = loop {
            let res = snark_session.status(&client)?;
            match res.status.as_str() {
                "RUNNING" => {
                    std::thread::sleep(Duration::from_secs(15));
                    continue;
                }
                "SUCCEEDED" => {
                    println!("Snark session is successful!");
                    break res.output.context("No snark generated :(")?;
                }
                _ => {
                    panic!(
                        "Workflow exited: {} err: {}",
                        res.status,
                        res.error_msg.unwrap_or_default()
                    );
                }
            }
        };

        let snark = snark_receipt.snark;

        let seal = Seal::abi_encode(snark).context("Read seal")?;
        let post_state_digest: FixedBytes<32> = snark_receipt
            .post_state_digest
            .as_slice()
            .try_into()
            .context("Read post_state_digest")?;
        let journal = snark_receipt.journal;

        Ok((journal, post_state_digest, seal))
    }
}
