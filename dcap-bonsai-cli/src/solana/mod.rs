pub mod write;

use risc0_zkvm::Receipt;
use risc0_solana::{client::negate_g1, Proof};

use std::{env, fs};
use anyhow::Result;
use automata_dcap_client::{
    create, get_index_from_create_output_account,
    verify::{self, ZkvmSelector},
};

use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    signer::{keypair::Keypair, Signer},
    transaction::Transaction
};

pub async fn run_verify_instruction(
    receipt: &Receipt,
) -> Result<()> {
    write::generate_files_for_solana(&receipt)?;

    // instantiate RPC client
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    println!("RPC URL: {}", rpc_url.as_str());
    let client = RpcClient::new(rpc_url);

    // instantiate payer
    let payer = load_payer()?;
    let payer_pubkey = payer.pubkey();
    println!("Payer address: {}", payer_pubkey.to_string());

    // extract the journal and proof from the receipt
    let journal_bytes = receipt.journal.bytes.as_slice();

    let proof = receipt_to_proof(&receipt.inner.groth16().unwrap().seal).unwrap();
    let proof_bytes = proof.to_bytes();

    // Tx 1: create and store the output
    let create_instruction = create::create_output_account_instruction(
        &client,
        &payer_pubkey,
        journal_bytes
    )?;
    let mut tx_1 = Transaction::new_with_payer(&[create_instruction], Some(&payer_pubkey));
    tx_1.sign(&[&payer], client.get_latest_blockhash()?);
    let sig_tx_1 = client.send_and_confirm_transaction(&tx_1)?;
    println!(
        "Created Output PDA Account, tx sig: {}",
        sig_tx_1.to_string()
    );

    // Tx 2: verify the proof
    let verify_instruction = verify::verify_proof_instruction(
        get_index_from_create_output_account(&client, &sig_tx_1)?,
        ZkvmSelector::RiscZero,
        &proof_bytes,
    )?;

    // Estimated Compute Unit needed = 320k CU
    // Currently, the default limit is 200k CU
    // Therefore, we need to include the SetComputeUnitLimit instruction
    let estimated_compute_units: u32 = 320_000;
    let set_compute_unit_limit_instruction =
        ComputeBudgetInstruction::set_compute_unit_limit(estimated_compute_units);

    let mut tx_2 = Transaction::new_with_payer(
        &[set_compute_unit_limit_instruction, verify_instruction],
        Some(&payer_pubkey),
    );
    tx_2.sign(&[&payer], client.get_latest_blockhash()?);
    let sig_tx_2 = client.send_and_confirm_transaction(&tx_2)?;
    println!("Proof verified, tx sig: {}", sig_tx_2.to_string());

    Ok(())
}

fn receipt_to_proof(seal: &[u8]) -> Result<Proof> {
    let mut proof = Proof {
        pi_a: seal[0..64].try_into()?,
        pi_b: seal[64..192].try_into()?,
        pi_c: seal[192..256].try_into()?,
    };
    proof.pi_a = negate_g1(&proof.pi_a)?;

    Ok(proof)
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

