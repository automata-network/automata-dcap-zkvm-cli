use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::fs::{read, read_to_string};
use std::path::PathBuf;
use x509_parser::prelude::*;

use app::bonsai::BonsaiProver;
use app::chain::{generate_calldata, get_evm_address_from_key, TxSender};
use app::constants;
use app::output::VerifiedOutput;

#[derive(Parser)]
#[command(name = "BonsaiApp")]
#[command(version = "1.0")]
#[command(about = "Gets Bonsai Proof and submits on-chain", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetches proof from Bonsai and sends them on-chain to verify DCAP quote
    Prove(DcapArgs),

    /// Generates the serialized input slice to be passed to the Guest application
    Serialize(DcapArgs),

    /// Computes the Image ID of the Guest application
    ImageId,
}

#[derive(Args)]
struct DcapArgs {
    /// The input quote provided as a hex string, this overwrites the --quote-path argument
    #[arg(short = 'q', long = "quote-hex")]
    quote_hex: Option<String>,

    /// Optional: The path to a quote.hex file. Default: /data/quote.hex or overwritten by the --quote-hex argument if provided.
    #[arg(short = 'p', long = "quote-path")]
    quote_path: Option<PathBuf>,

    /// Optional: The path to TCBInfo.json file. Default: /data/tcbinfoV2.json
    #[arg(short = 't', long = "tcb-path")]
    tcb_path: Option<PathBuf>,

    /// Optional: The path to QEIdentity.json file. Default: /data/qeidentityv2.json
    #[arg(short = 'e', long = "id-path")]
    qeid_path: Option<PathBuf>,

    /// Optional: The path to the TCB Signing Cert PEM file. Default: /data/signing_cert.pem
    #[arg(short = 's', long = "signing-path")]
    tcb_signing_pem_path: Option<PathBuf>,

    /// Optional: The path to RootCA DER file. Default: /data/Intel_SGX_Provisioning_Certification_RootCA.cer
    #[arg(short = 'r', long = "root-path")]
    root_ca_der_path: Option<PathBuf>,

    /// Optional: The path to PCK ProcessorCRL DER file. Default: /data/pck_processor_crl.der
    #[arg[long = "processor-crl-path"]]
    processor_crl_der_path: Option<PathBuf>,

    /// Optional: The path to PCK PlatformCRL DER file. Default: /data/pck_platform_crl.der
    #[arg[long = "platform-crl-path"]]
    platform_crl_der_path: Option<PathBuf>,

    /// Optional: The path to RootCRL DER file. Default: /data/intel_root_ca_crl.der
    #[arg[long = "root-crl-path"]]
    root_crl_der_path: Option<PathBuf>,

    /// Optional: A transaction will not be sent if left blank.
    #[arg(short = 'k', long = "wallet-key")]
    wallet_private_key: Option<String>,

    /// Optional: ChainID
    #[arg(long = "chain-id")]
    chain_id: Option<u64>,

    /// Optional: RPC URL
    #[arg(long = "rpc-url")]
    rpc_url: Option<String>,

    /// Optional: DCAP Contract address
    #[arg(long = "contract")]
    contract: Option<String>,
}

enum Collateral<'a> {
    Tcb(&'a Option<PathBuf>),
    Qeid(&'a Option<PathBuf>),
    Signing(&'a Option<PathBuf>),
    Root(&'a Option<PathBuf>),
    PlatformCrl(&'a Option<PathBuf>),
    ProcessorCrl(&'a Option<PathBuf>),
    RootCrl(&'a Option<PathBuf>),
}

fn main() {
    let cli = Cli::parse();

    env_logger::init();

    match &cli.command {
        Commands::Prove(args) => {
            let input = serialize_args_and_get_input(args);

            log::info!("Begin uploading input to Bonsai...");

            let (output, post_state_digest, seal) = BonsaiProver::prove(None, &input).unwrap();

            // manually parse the output
            let verified_output_bytes = &output[..135];
            let tcbinfo_root_hash = &output[143..175];
            let enclaveidentity_root_hash = &output[175..207];
            let root_cert_hash = &output[207..239];
            let signing_cert_hash = &output[239..271];
            let root_crl_hash = &output[271..303];
            let platform_crl_hash = &output[303..335];
            let processor_crl_hash = &output[335..367];

            log::info!("Verified Output: {:?}", VerifiedOutput::from_bytes(&verified_output_bytes));
            log::info!(
                "Timestamp: {}",
                u64::from_le_bytes(output[135..143].try_into().unwrap())
            );
            log::info!("TCB Info Root Hash: {}", hex::encode(&tcbinfo_root_hash));
            log::info!(
                "Enclave Identity Root Hash: {}",
                hex::encode(&enclaveidentity_root_hash)
            );
            log::info!("Root Cert Hash: {}", hex::encode(&root_cert_hash));
            log::info!("Signing Cert Hash: {}", hex::encode(&signing_cert_hash));
            log::info!("Root CRL hash: {}", hex::encode(&root_crl_hash));
            log::info!("Platform CRL hash: {}", hex::encode(&platform_crl_hash));
            log::info!("Processor CRL hash: {}", hex::encode(&processor_crl_hash));

            println!("Journal: {}", hex::encode(&output));
            println!("Post-state-digest: {}", hex::encode(&post_state_digest));
            println!("seal: {}", hex::encode(&seal));

            let wallet_key = args.wallet_private_key.as_deref();
            match wallet_key {
                Some(wallet_key) => {
                    let calldata = generate_calldata(&output, post_state_digest, &seal);

                    let chain_id: u64 =
                        args.chain_id.unwrap_or_else(|| constants::DEFAULT_CHAIN_ID);
                    let rpc_url = args
                        .rpc_url
                        .as_deref()
                        .unwrap_or_else(|| constants::DEFAULT_RPC_URL);
                    let dcap_contract = args
                        .contract
                        .as_deref()
                        .unwrap_or_else(|| constants::DEFAULT_DCAP_CONTRACT);

                    println!("Chain ID: {}", chain_id);
                    println!("DCAP Contract Address: {}", dcap_contract);
                    println!("Wallet address: {}", get_evm_address_from_key(wallet_key));

                    log::info!("Calldata: {}", hex::encode(&calldata));

                    // Send the calldata to Ethereum.
                    let tx_sender = TxSender::new(chain_id, rpc_url, wallet_key, dcap_contract)
                        .expect("Failed to create txSender");
                    let runtime = tokio::runtime::Runtime::new().unwrap();
                    let tx = runtime.block_on(tx_sender.send(calldata)).unwrap();
                    match tx {
                        Some(ref pending) => {
                            let hash = pending.transaction_hash;
                            println!("Transaction hash: 0x{}", hex::encode(hash.as_bytes()));
                        }
                        _ => {
                            unreachable!();
                        }
                    }
                }
                _ => {
                    log::info!("No wallet key provided");
                }
            }
        }
        Commands::ImageId => {
            let image_id = constants::DEFAULT_IMAGE_ID_HEX;
            // compute_image_id(DCAPV3_GUEST_ELF).expect("Failed to compute image ID...");
            println!("ImageID: {}", image_id);
        }
        Commands::Serialize(args) => {
            let input = serialize_args_and_get_input(args);
            let input_string = hex::encode(input);
            println!("{}", input_string);
        }
    }

    log::info!("Job completed!");
}

fn serialize_args_and_get_input(args: &DcapArgs) -> Vec<u8> {
    // Check path
    let tcb_path_final = get_collateral_path(Collateral::Tcb(&args.tcb_path));
    let qeid_path_final = get_collateral_path(Collateral::Qeid(&args.qeid_path));
    let signing_path_final = get_collateral_path(Collateral::Signing(&args.tcb_signing_pem_path));
    let root_path_final = get_collateral_path(Collateral::Root(&args.root_ca_der_path));
    let processor_crl_path_final =
        get_collateral_path(Collateral::ProcessorCrl(&args.processor_crl_der_path));
    let platform_crl_path_final =
        get_collateral_path(Collateral::PlatformCrl(&args.platform_crl_der_path));
    let root_crl_path_final = get_collateral_path(Collateral::RootCrl(&args.root_crl_der_path));

    let quote = get_quote(&args.quote_path, &args.quote_hex).unwrap();
    let tcbinfo_root = read(tcb_path_final).expect(&print_failed_to_read_collateral_msg("TCBInfo"));
    let enclaveidentity_root =
        read(qeid_path_final).expect(&print_failed_to_read_collateral_msg("QEIdentity.json"));
    let signing_cert_pem =
        read(signing_path_final).expect(&print_failed_to_read_collateral_msg("TCBSigning PEM"));
    let root_cert_der =
        read(root_path_final).expect(&print_failed_to_read_collateral_msg("RootCA DER"));
    let processor_crl_der = read(processor_crl_path_final)
        .expect(&print_failed_to_read_collateral_msg("Processor CRL DER"));
    let platform_crl_der = read(platform_crl_path_final)
        .expect(&print_failed_to_read_collateral_msg("Platform CRL DER"));
    let root_crl_der =
        read(root_crl_path_final).expect(&print_failed_to_read_collateral_msg("Root CRL DER"));

    let signing_cert_der = pem_to_der(&signing_cert_pem);

    // get current time in seconds since epoch
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let current_time_bytes = current_time.to_le_bytes();

    // TODO: serialize collateral to bytes
    let intel_collaterals_bytes = serialize_collaterals(
        &tcbinfo_root,
        &enclaveidentity_root,
        &root_cert_der,
        &signing_cert_der,
        &root_crl_der,
        &processor_crl_der,
        &platform_crl_der,
    );

    // ZL: perform a simple serialization of the inputs
    // [current_time: u64][quote_len: u32][intel_collaterals_len: u32][quote: var][intel_collaterals: var]
    let quote_len = quote.len() as u32;
    let intel_collaterals_bytes_len = intel_collaterals_bytes.len() as u32;
    let total_len = 8 + 4 + 4 + quote_len + intel_collaterals_bytes_len;

    log::info!("Quote len: {}", quote_len);
    log::info!("Collaterals len: {}", intel_collaterals_bytes_len);
    log::info!("Total: {}", total_len);

    let mut input = Vec::with_capacity(total_len as usize);
    input.extend_from_slice(&current_time_bytes);
    input.extend_from_slice(&quote_len.to_le_bytes());
    input.extend_from_slice(&intel_collaterals_bytes_len.to_le_bytes());
    input.extend_from_slice(&quote);
    input.extend_from_slice(&intel_collaterals_bytes);

    input.to_owned()
}

/// attempts to read file path from the user input
/// if not provided, the default path is returned
fn get_collateral_path(user_input_path: Collateral) -> PathBuf {
    match user_input_path {
        Collateral::Tcb(path) => path
            .clone()
            .unwrap_or_else(|| PathBuf::from(constants::DEFAULT_TCB_PATH)),
        Collateral::Qeid(path) => path
            .clone()
            .unwrap_or_else(|| PathBuf::from(constants::DEFAULT_QEID_PATH)),
        Collateral::Signing(path) => path
            .clone()
            .unwrap_or_else(|| PathBuf::from(constants::DEFAULT_TCB_SIGNING_PEM_PATH)),
        Collateral::Root(path) => path
            .clone()
            .unwrap_or_else(|| PathBuf::from(constants::DEFAULT_ROOT_CA_DER_PATH)),
        Collateral::ProcessorCrl(path) => path
            .clone()
            .unwrap_or_else(|| PathBuf::from(constants::DEFAULT_PROCESSOR_CRL_DER_PATH)),
        Collateral::PlatformCrl(path) => path
            .clone()
            .unwrap_or_else(|| PathBuf::from(constants::DEFAULT_PLATFORM_CRL_DER_PATH)),
        Collateral::RootCrl(path) => path
            .clone()
            .unwrap_or_else(|| PathBuf::from(constants::DEFAULT_ROOT_CA_CRL_DER_PATH)),
    }
}

// Modified from https://github.com/automata-network/dcap-rs/blob/5da0c884743be432e7fca5d6c7980b889f280666/src/types/mod.rs#L54-L124
fn serialize_collaterals(
    tcbinfo_bytes: &[u8],
    qeidentity_bytes: &[u8],
    root_ca_bytes: &[u8],
    signing_cert_bytes: &[u8],
    root_crl_bytes: &[u8],
    processor_crl_bytes: &[u8],
    platform_crl_bytes: &[u8],
) -> Vec<u8> {
    // get the total length
    let total_length = 4 * 8
        + tcbinfo_bytes.len()
        + qeidentity_bytes.len()
        + root_ca_bytes.len()
        + signing_cert_bytes.len()
        + 0
        + root_crl_bytes.len()
        + processor_crl_bytes.len()
        + platform_crl_bytes.len();

    // create the vec and copy the data
    let mut data = Vec::with_capacity(total_length);
    data.extend_from_slice(&(tcbinfo_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(&(qeidentity_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(&(root_ca_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(&(signing_cert_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(&(0 as u32).to_le_bytes());
    data.extend_from_slice(&(root_crl_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(&(processor_crl_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(&(platform_crl_bytes.len() as u32).to_le_bytes());

    data.extend_from_slice(&tcbinfo_bytes);
    data.extend_from_slice(&qeidentity_bytes);
    data.extend_from_slice(&root_ca_bytes);
    data.extend_from_slice(&signing_cert_bytes);
    data.extend_from_slice(&root_crl_bytes);
    data.extend_from_slice(&processor_crl_bytes);
    data.extend_from_slice(&platform_crl_bytes);

    data
}

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
                let default_path = PathBuf::from(constants::DEFAULT_QUOTE_PATH);
                let quote_string = read_to_string(default_path).expect(error_msg);
                let processed = remove_prefix_if_found(&quote_string);
                let quote_hex = hex::decode(processed)?;
                Ok(quote_hex)
            }
        },
    }
}

fn remove_prefix_if_found(h: &str) -> &str {
    if h.starts_with("0x") {
        &h[2..]
    } else {
        &h
    }
}

fn pem_to_der(pem_bytes: &[u8]) -> Vec<u8> {
    // convert from raw pem bytes to pem objects
    let pems = parse_pem(pem_bytes).unwrap();
    // convert from pem objects to der bytes
    // to make it more optimize, we'll read get all the lengths of the der bytes
    // and then allocate the buffer once
    let der_bytes_len: usize = pems.iter().map(|pem| pem.contents.len()).sum();
    let mut der_bytes = Vec::with_capacity(der_bytes_len);
    for pem in pems {
        der_bytes.extend_from_slice(&pem.contents);
    }
    der_bytes
}

fn parse_pem(raw_bytes: &[u8]) -> Result<Vec<Pem>, PEMError> {
    Pem::iter_from_buffer(raw_bytes).collect()
}

fn print_failed_to_read_collateral_msg(name: &str) -> String {
    format!("Failed to read: {}", name)
}
