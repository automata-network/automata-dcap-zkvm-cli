use std::{env, fs};

use sha2::{Digest, Sha256};

use anyhow::Result;
use dcap_sp1_solana_program::SP1Groth16Proof;
use sp1_sdk::SP1ProofWithPublicValues;

use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    transaction::Transaction,
};

use solana_rpc_client::rpc_client::RpcClient;

pub const PROGRAM_ID: &str = "2LUaFQTJ7F96A5x1z5sXfbDPM2asGnrQ2hsE6zVDMhXZ";

pub async fn run_verify_instruction(
    proof_with_public_values: SP1ProofWithPublicValues,
) -> Result<()> {
    // instantiate RPC client
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    println!("RPC URL: {}", rpc_url.as_str());
    let client = RpcClient::new(rpc_url);

    // instantiate payer
    let payer = load_payer()?;
    println!("Payer address: {}", payer.pubkey().to_string());

    // Compute the hash of the public inputs
    let public_values_hash = Sha256::digest(proof_with_public_values.public_values.as_slice());

    // build the instruction data
    let groth16_proof = SP1Groth16Proof {
        proof: proof_with_public_values.bytes(),
        sp1_public_inputs_hash: public_values_hash.to_vec(),
    };
    let program_id = Pubkey::from_str_const(PROGRAM_ID);

    // Estimated Compute Unit needed = 300k CU
    // Currently, the default limit is 200k CU
    // Therefore, we need to include the SetComputeUnitLimit instruction
    let estimated_compute_units: u32 = 300_000;
    let set_compute_unit_limit_instruction =
        ComputeBudgetInstruction::set_compute_unit_limit(estimated_compute_units);
    let instruction = Instruction::new_with_borsh(
        program_id,
        &groth16_proof,
        vec![AccountMeta::new(payer.pubkey(), false)],
    );

    // Create and send transaction
    let mut tx = Transaction::new_with_payer(
        &[set_compute_unit_limit_instruction, instruction],
        Some(&payer.pubkey()),
    );
    tx.sign(&[&payer], client.get_latest_blockhash()?);

    println!("Submitting instructions...");
    let signature = client.send_and_confirm_transaction(&tx)?;
    println!("Tx signature: {}", signature.to_string());

    Ok(())
}

fn load_payer() -> Result<Keypair> {
    // Warning: home_dir() is not correct for Windows OS
    let mut keypair_dir = env::home_dir().unwrap();

    keypair_dir.push(".config");
    keypair_dir.push("solana");
    keypair_dir.push("id.json");

    let keypair_read = fs::read_to_string(keypair_dir)?;
    let keypair_vec: Vec<u8> = serde_json::from_str(keypair_read.as_str())?;

    Ok(Keypair::from_bytes(&keypair_vec)?)
}
