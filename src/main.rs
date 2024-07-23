use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::fs::read_to_string;
use std::path::PathBuf;

use app::bonsai::BonsaiProver;
use app::chain::{attestation::generate_attestation_calldata, get_evm_address_from_key, TxSender};
use app::collaterals::Collaterals;
use app::constants::*;
use app::output::VerifiedOutput;
use app::parser::get_pck_fmspc_and_issuer;
use app::remove_prefix_if_found;

use app::chain::pccs::{
    enclave_id::{get_enclave_identity, EnclaveIdType},
    fmspc_tcb::get_tcb_info,
    pcs::{get_certificate_by_id, IPCSDao::CA},
};

#[derive(Parser)]
#[command(name = "DcapBonsaiApp")]
#[command(version = "1.0")]
#[command(about = "Gets Bonsai Proof for DCAP QuoteV3 Verification and submits on-chain")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetches proof from Bonsai and sends them on-chain to verify DCAP quote
    Prove(DcapArgs),

    /// Computes the Image ID of the Guest application
    ImageId,

    /// De-serializes and prints information about the Output
    Deserialize(OutputArgs),
}

#[derive(Args)]
struct DcapArgs {
    /// The input quote provided as a hex string, this overwrites the --quote-path argument
    #[arg(short = 'q', long = "quote-hex")]
    quote_hex: Option<String>,

    /// Optional: The path to a quote.hex file. Default: /data/quote.hex or overwritten by the --quote-hex argument if provided.
    #[arg(short = 'p', long = "quote-path")]
    quote_path: Option<PathBuf>,

    /// Optional: A transaction will not be sent if left blank.
    #[arg(short = 'k', long = "wallet-key")]
    wallet_private_key: Option<String>,
}

#[derive(Args)]
struct OutputArgs {
    #[arg(short = 'o', long = "output")]
    output: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    env_logger::init();

    match &cli.command {
        Commands::Prove(args) => {
            // Step 0: Read quote
            println!("Begin reading quote and fetching the necessary collaterals...");
            let quote = get_quote(&args.quote_path, &args.quote_hex).expect("Failed to read quote");

            // Step 1: Determine quote version and TEE type
            let quote_version = u16::from_le_bytes([quote[0], quote[1]]);
            let tee_type = u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]);

            if quote_version < 3 || quote_version > 4 {
                panic!("Unsupported quote version");
            }

            if tee_type != SGX_TEE_TYPE && tee_type != TDX_TEE_TYPE {
                panic!("Unsupported tee type");
            }

            // Step 2: Load collaterals
            println!("Quote read successfully. Begin fetching collaterals from the on-chain PCCS");

            let (root_ca, root_ca_crl) = get_certificate_by_id(CA::ROOT).await?;
            if root_ca.is_empty() || root_ca_crl.is_empty() {
                panic!("Intel SGX Root CA is missing");
            } else {
                log::info!("Fetched Intel SGX RootCA and CRL");
            }

            let (fmspc, pck_type, pck_issuer) =
                get_pck_fmspc_and_issuer(&quote, quote_version, tee_type);

            let tcb_type: u8;
            if tee_type == TDX_TEE_TYPE {
                tcb_type = 1;
            } else {
                tcb_type = 0;
            }
            let tcb_version: u32;
            if quote_version < 4 {
                tcb_version = 2
            } else {
                tcb_version = 3
            }
            let tcb_info = get_tcb_info(tcb_type, fmspc.as_str(), tcb_version).await?;

            log::info!("Fetched TCBInfo JSON for FMSPC: {}", fmspc);

            let qe_id_type: EnclaveIdType;
            if tee_type == TDX_TEE_TYPE {
                qe_id_type = EnclaveIdType::TDQE
            } else {
                qe_id_type = EnclaveIdType::QE
            }
            let qe_identity = get_enclave_identity(qe_id_type, quote_version as u32).await?;
            log::info!("Fetched QEIdentity JSON");

            let (signing_ca, _) = get_certificate_by_id(CA::SIGNING).await?;
            if signing_ca.is_empty() {
                panic!("Intel TCB Signing CA is missing");
            } else {
                log::info!("Fetched Intel TCB Signing CA");
            }

            let (_, pck_crl) = get_certificate_by_id(pck_type).await?;
            if pck_crl.is_empty() {
                panic!("CRL for {} is missing", pck_issuer);
            } else {
                log::info!("Fetched Intel PCK CRL for {}", pck_issuer);
            }

            let collaterals = Collaterals::new(
                tcb_info,
                qe_identity,
                root_ca,
                signing_ca,
                root_ca_crl,
                pck_crl,
            );
            let serialized_collaterals = serialize_collaterals(&collaterals, pck_type);

            // Step 3: Generate the input to upload to Bonsai
            let input = generate_input(&quote, &serialized_collaterals);

            println!("All collaterals found! Begin uploading input to Bonsai...");

            let (output, post_state_digest, seal) = BonsaiProver::prove(None, &input).unwrap();

            let mut offset: usize = 0;
            let output_len = u16::from_le_bytes(output[offset..offset + 2].try_into().unwrap());
            offset += 2;
            let verified_output =
                VerifiedOutput::from_bytes(&output[offset..offset + output_len as usize]);
            offset += output_len as usize;
            let current_time = u64::from_le_bytes(output[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let tcbinfo_root_hash = &output[offset..offset + 32];
            offset += 32;
            let enclaveidentity_root_hash = &output[offset..offset + 32];
            offset += 32;
            let root_cert_hash = &output[offset..offset + 32];
            offset += 32;
            let signing_cert_hash = &output[offset..offset + 32];
            offset += 32;
            let root_crl_hash = &output[offset..offset + 32];
            offset += 32;
            let pck_crl_hash = &output[offset..offset + 32];

            println!("Verified Output: {:?}", verified_output);
            log::info!("Timestamp: {}", current_time);
            log::info!("TCB Info Root Hash: {}", hex::encode(&tcbinfo_root_hash));
            log::info!(
                "Enclave Identity Root Hash: {}",
                hex::encode(&enclaveidentity_root_hash)
            );
            log::info!("Root Cert Hash: {}", hex::encode(&root_cert_hash));
            log::info!("Signing Cert Hash: {}", hex::encode(&signing_cert_hash));
            log::info!("Root CRL hash: {}", hex::encode(&root_crl_hash));
            log::info!("PCK CRL hash: {}", hex::encode(&pck_crl_hash));

            println!("Journal: {}", hex::encode(&output));
            println!("Post-state-digest: {}", hex::encode(&post_state_digest));
            println!("seal: {}", hex::encode(&seal));

            let wallet_key = args.wallet_private_key.as_deref();
            match wallet_key {
                Some(wallet_key) => {
                    let calldata = generate_attestation_calldata(&output, &seal);

                    println!(
                        "Wallet found! Address: {}",
                        get_evm_address_from_key(wallet_key)
                    );

                    log::info!("Calldata: {}", hex::encode(&calldata));

                    // Send the calldata to Ethereum.
                    log::info!("Submitting proofs to on-chain DCAP contract to be verified...");
                    let tx_sender =
                        TxSender::new(DEFAULT_RPC_URL, wallet_key, DEFAULT_DCAP_CONTRACT)
                            .expect("Failed to create txSender");

                    let tx_receipt = tx_sender.send(calldata).await?;
                    let hash = tx_receipt.transaction_hash;
                    println!("Transaction hash: 0x{}", hex::encode(hash.as_slice()));
                }
                _ => {
                    log::info!("No wallet key provided");
                }
            }
        }
        Commands::ImageId => {
            let image_id = DEFAULT_IMAGE_ID_HEX;
            println!("ImageID: {}", image_id);
        }
        Commands::Deserialize(args) => {
            let output_vec =
                hex::decode(remove_prefix_if_found(&args.output)).expect("Failed to parse output");
            let deserialized_output = VerifiedOutput::from_bytes(&output_vec);
            println!("Deserialized output: {:?}", deserialized_output);
        }
    }

    println!("Job completed!");

    Ok(())
}

// Helper functions go here

fn get_quote(path: &Option<PathBuf>, hex: &Option<String>) -> Result<Vec<u8>> {
    let error_msg: &str = "Failed to read quote from the provided path";
    match hex {
        Some(h) => {
            let quote_hex = hex::decode(h)?;
            Ok(quote_hex)
        }
        _ => match path {
            Some(p) => {
                let quote_string = read_to_string(p).expect(error_msg);
                let processed = remove_prefix_if_found(&quote_string);
                let quote_hex = hex::decode(processed)?;
                Ok(quote_hex)
            }
            _ => {
                let default_path = PathBuf::from(DEFAULT_QUOTE_PATH);
                let quote_string = read_to_string(default_path).expect(error_msg);
                let processed = remove_prefix_if_found(&quote_string);
                let quote_hex = hex::decode(processed)?;
                Ok(quote_hex)
            }
        },
    }
}

// Modified from https://github.com/automata-network/dcap-rs/blob/b218a9dcdf2aec8ee05f4d2bd055116947ddfced/src/types/collaterals.rs#L35-L105
fn serialize_collaterals(collaterals: &Collaterals, pck_type: CA) -> Vec<u8> {
    // get the total length
    let total_length = 4 * 8
        + collaterals.tcb_info.len()
        + collaterals.qe_identity.len()
        + collaterals.root_ca.len()
        + collaterals.tcb_signing_ca.len()
        + collaterals.root_ca_crl.len()
        + collaterals.pck_crl.len();

    // create the vec and copy the data
    let mut data = Vec::with_capacity(total_length);
    data.extend_from_slice(&(collaterals.tcb_info.len() as u32).to_le_bytes());
    data.extend_from_slice(&(collaterals.qe_identity.len() as u32).to_le_bytes());
    data.extend_from_slice(&(collaterals.root_ca.len() as u32).to_le_bytes());
    data.extend_from_slice(&(collaterals.tcb_signing_ca.len() as u32).to_le_bytes());
    data.extend_from_slice(&(0 as u32).to_le_bytes()); // pck_certchain_len == 0
    data.extend_from_slice(&(collaterals.root_ca_crl.len() as u32).to_le_bytes());

    match pck_type {
        CA::PLATFORM => {
            data.extend_from_slice(&(0 as u32).to_le_bytes());
            data.extend_from_slice(&(collaterals.pck_crl.len() as u32).to_le_bytes());
        }
        CA::PROCESSOR => {
            data.extend_from_slice(&(collaterals.pck_crl.len() as u32).to_le_bytes());
            data.extend_from_slice(&(0 as u32).to_le_bytes());
        }
        _ => unreachable!(),
    }

    // collateral should only hold one PCK CRL

    data.extend_from_slice(&collaterals.tcb_info);
    data.extend_from_slice(&collaterals.qe_identity);
    data.extend_from_slice(&collaterals.root_ca);
    data.extend_from_slice(&collaterals.tcb_signing_ca);
    data.extend_from_slice(&collaterals.root_ca_crl);
    data.extend_from_slice(&collaterals.pck_crl);

    data
}

fn generate_input(quote: &[u8], collaterals: &[u8]) -> Vec<u8> {
    // get current time in seconds since epoch
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let current_time_bytes = current_time.to_le_bytes();

    let quote_len = quote.len() as u32;
    let intel_collaterals_bytes_len = collaterals.len() as u32;
    let total_len = 8 + 4 + 4 + quote_len + intel_collaterals_bytes_len;

    let mut input = Vec::with_capacity(total_len as usize);
    input.extend_from_slice(&current_time_bytes);
    input.extend_from_slice(&quote_len.to_le_bytes());
    input.extend_from_slice(&intel_collaterals_bytes_len.to_le_bytes());
    input.extend_from_slice(&quote);
    input.extend_from_slice(&collaterals);

    input.to_owned()
}
