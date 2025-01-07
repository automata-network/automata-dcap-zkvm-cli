use std::{env, fs};

use anyhow::Result;
use dcap_sp1_solana_program::SP1Groth16Proof;
use sp1_sdk::SP1ProofWithPublicValues;

use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    transaction::Transaction,
};

use solana_rpc_client::rpc_client::RpcClient;

pub const PROGRAM_ID: &str = "4S1YicT8oGzj38a98bhiMdfNDrvLkdb5TB5Uw2tZ8qmq";

pub async fn run_verify_instruction(
    vkey_hash: String,
    proof_with_public_values: SP1ProofWithPublicValues,
) -> Result<()> {
    // instantiate RPC client
    let rpc_url = String::from("https://api.devnet.solana.com");
    let client = RpcClient::new(rpc_url);

    // instantiate payer
    let payer = load_payer()?;
    println!("Payer address: {:?}", payer.pubkey().to_string());

    // build the instruction data
    let groth16_proof = SP1Groth16Proof {
        proof: proof_with_public_values.bytes(),
        sp1_public_inputs: proof_with_public_values.public_values.to_vec(),
        vkey_hash,
    };
    let program_id = Pubkey::from_str_const(PROGRAM_ID);

    let instruction = Instruction::new_with_borsh(
        program_id,
        &groth16_proof,
        vec![AccountMeta::new(payer.pubkey(), false)],
    );

    // Create and send transaction
    let mut tx = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    tx.sign(&[&payer], client.get_latest_blockhash()?);

    println!("data len: {}", tx.message_data().len());

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
