use std::{env, fs};

use anyhow::Result;
use automata_dcap_client::{
    create, get_index_from_create_output_account,
    verify::{self, ZkvmSelector},
};
use sp1_sdk::SP1ProofWithPublicValues;

use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    signer::{keypair::Keypair, Signer},
    transaction::Transaction
};

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
    let payer_pubkey = payer.pubkey();
    println!("Payer address: {}", payer_pubkey.to_string());

    // Tx 1: create and store the output
    let create_instruction = create::create_output_account_instruction(
        &client,
        &payer_pubkey,
        proof_with_public_values.public_values.as_slice(),
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
        ZkvmSelector::SP1,
        proof_with_public_values.bytes().as_slice(),
    )?;

    // Estimated Compute Unit needed = 370k CU
    // Currently, the default limit is 200k CU
    // Therefore, we need to include the SetComputeUnitLimit instruction
    let estimated_compute_units: u32 = 370_000;
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
