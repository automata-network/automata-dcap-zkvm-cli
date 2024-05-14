use alloy_sol_types::{sol, SolInterface};
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::fs::{read, read_to_string};
use std::path::PathBuf;

use app::bonsai::BonsaiProver;
use app::chain::TxSender;
use app::constants;

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
    /// The input quote provided as a hex string
    #[arg(short = 'q', long = "quote-hex")]
    quote_hex: Option<String>,

    #[arg(short = 'p', long = "quote-path")]
    quote_path: Option<PathBuf>,

    /// The path to TCBInfo.json
    #[arg(short = 't', long = "tcb-path")]
    tcb_path: Option<PathBuf>,

    /// The path to QEIdentity.json
    #[arg(short = 'e', long = "id-path")]
    qeid_path: Option<PathBuf>,

    /// The path to TCBSigning PEM
    #[arg(short = 's', long = "signing-path")]
    tcb_signing_pem_path: Option<PathBuf>,

    /// The path to RootCA DER
    #[arg(short = 'r', long = "root-path")]
    root_ca_der_path: Option<PathBuf>,

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

sol! {
    interface IAttestation {
        function verifyAndAttestWithZKProof(bytes calldata journal, bytes32 post_state_digest, bytes calldata seal);
    }
}

enum Collateral<'a> {
    Tcb(&'a Option<PathBuf>),
    Qeid(&'a Option<PathBuf>),
    Signing(&'a Option<PathBuf>),
    Root(&'a Option<PathBuf>),
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Prove(args) => {
            // Check path
            let tcb_path_final = get_collateral_path(Collateral::Tcb(&args.tcb_path));
            let qeid_path_final = get_collateral_path(Collateral::Qeid(&args.qeid_path));
            let signing_path_final =
                get_collateral_path(Collateral::Signing(&args.tcb_signing_pem_path));
            let root_path_final = get_collateral_path(Collateral::Root(&args.root_ca_der_path));

            let quote = get_quote(&args.quote_path, &args.quote_hex).unwrap();
            let tcbinfo_root =
                read_to_string(tcb_path_final).expect("Failed to locate TCBInfo.json");
            let enclaveidentity_root =
                read_to_string(qeid_path_final).expect("Failed to locate QEIdentity.json");
            let signing_cert_pem =
                read(signing_path_final).expect("Failed to locate TCBSigningCert.pem");
            let root_cert_der = read(root_path_final).expect("Failed to locate RootCA.der");

            let input = to_input_slice(
                &quote,
                &tcbinfo_root,
                &enclaveidentity_root,
                &signing_cert_pem,
                &root_cert_der,
                true,
            );

            println!("Begin uploading input to Bonsai...");

            let (output, post_state_digest, seal) = BonsaiProver::prove(None, &input).unwrap();

            // manually parse the output
            let verified_output_bytes = &output[..135];
            let tcbinfo_root_hash = &output[135..167];
            let enclaveidentity_root_hash = &output[167..199];
            let signing_cert_hash = &output[199..231];
            let root_cert_hash = &output[231..263];

            println!("Verified Output: {:?}", verified_output_bytes);
            println!("TCB Info Root Hash: {:?}", tcbinfo_root_hash);
            println!(
                "Enclave Identity Root Hash: {:?}",
                enclaveidentity_root_hash
            );
            println!("Signing Cert Hash: {:?}", signing_cert_hash);
            println!("Root Cert Hash: {:?}", root_cert_hash);

            println!("Journal: {:?}", output);
            println!("Post-state-digest: {:?}", post_state_digest);
            println!("seal: {:?}", seal);

            // converts &Option<T> or Option<T> to Option<&T>
            let wallet_key = args.wallet_private_key.as_deref();
            match wallet_key {
                Some(wallet_key) => {
                    println!("Submitting proofs to on-chain DCAP contract to be verified...");
                    let calldata = IAttestation::IAttestationCalls::verifyAndAttestWithZKProof(
                        IAttestation::verifyAndAttestWithZKProofCall {
                            journal: output,
                            post_state_digest: post_state_digest,
                            seal: seal,
                        },
                    )
                    .abi_encode();

                    // TODO: at some point we need to define a mapping
                    // for the default values
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

                    // Send the calldata to Ethereum.
                    let tx_sender = TxSender::new(chain_id, rpc_url, wallet_key, dcap_contract)
                        .expect("Failed to create txSender");
                    let runtime = tokio::runtime::Runtime::new().unwrap();
                    let _ = runtime.block_on(tx_sender.send(calldata));
                }
                _ => {
                    println!("No wallet key provided");
                }
            }
        }
        Commands::ImageId => {
            let image_id = constants::DEFAULT_IMAGE_ID_HEX;
            // compute_image_id(DCAPV3_GUEST_ELF).expect("Failed to compute image ID...");

            println!("ImageID: {}", image_id);
        }
        Commands::Serialize(args) => {
            // Check path
            let tcb_path_final = get_collateral_path(Collateral::Tcb(&args.tcb_path));
            let qeid_path_final = get_collateral_path(Collateral::Qeid(&args.qeid_path));
            let signing_path_final =
                get_collateral_path(Collateral::Signing(&args.tcb_signing_pem_path));
            let root_path_final = get_collateral_path(Collateral::Root(&args.root_ca_der_path));

            let quote = get_quote(&args.quote_path, &args.quote_hex).unwrap();
            let tcbinfo_root =
                read_to_string(tcb_path_final).expect("Failed to locate TCBInfo.json");
            let enclaveidentity_root =
                read_to_string(qeid_path_final).expect("Failed to locate QEIdentity.json");
            let signing_cert_pem =
                read(signing_path_final).expect("Failed to locate TCBSigningCert.pem");
            let root_cert_der = read(root_path_final).expect("Failed to locate RootCA.der");

            let input = to_input_slice(
                &quote,
                &tcbinfo_root,
                &enclaveidentity_root,
                &signing_cert_pem,
                &root_cert_der,
                false,
            );
            let input_string = hex::encode(input);
            println!("{}", input_string);
        }
    }
}

fn get_quote(path: &Option<PathBuf>, hex: &Option<String>) -> Result<Vec<u8>> {
    match hex {
        Some(h) => {
            let quote_hex = hex::decode(h)?;
            Ok(quote_hex)
        }
        _ => match path {
            Some(p) => {
                let quote_string = read_to_string(p).expect("Failed to read quote from the provided path");
                let quote_hex = hex::decode(quote_string)?;
                Ok(quote_hex)
            }
            _ => {
                let default_path = PathBuf::from(constants::DEFAULT_QUOTE_PATH);
                let quote_string = read_to_string(default_path).expect("Failed to read quote from the provided path");
                let quote_hex = hex::decode(quote_string)?;
                Ok(quote_hex)
            }
        },
    }
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
    }
}

/// serializes params to input slice to upload to Bonsai
fn to_input_slice(
    quote: &[u8],
    tcbinfo_root: &String,
    enclaveidentity_root: &String,
    signing_cert_pem: &[u8],
    root_cert_der: &[u8],
    verbose: bool,
) -> Vec<u8> {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let current_time_bytes = current_time.to_le_bytes();
    let quote_len = (quote.len() as u32).to_le_bytes();
    let tcbinfo_root_len = (tcbinfo_root.as_bytes().len() as u32).to_le_bytes();
    let enclaveidentity_root_len = (enclaveidentity_root.as_bytes().len() as u32).to_le_bytes();
    let signing_cert_pem_len = (signing_cert_pem.len() as u32).to_le_bytes();
    let root_cert_der_len = (root_cert_der.len() as u32).to_le_bytes();

    if verbose {
        println!("Current Time: {:?}", current_time);
        println!("Quote Length: {:?}", quote_len);
        println!("TCB Info Root Length: {:?}", tcbinfo_root_len);
        println!(
            "Enclave Identity Root Length: {:?}",
            enclaveidentity_root_len
        );
        println!("Signing Cert Length: {:?}", signing_cert_pem_len);
        println!("Root Cert Length: {:?}", root_cert_der_len);

        println!(
            "total length: {:?}",
            current_time_bytes.len()
                + quote_len.len()
                + tcbinfo_root_len.len()
                + enclaveidentity_root_len.len()
                + signing_cert_pem_len.len()
                + root_cert_der_len.len()
                + quote.len()
                + tcbinfo_root.len()
                + enclaveidentity_root.len()
                + signing_cert_pem.len()
                + root_cert_der.len()
        );
    }

    let mut input: Vec<u8> = Vec::new();
    input.extend_from_slice(&current_time_bytes);
    input.extend_from_slice(&quote_len);
    input.extend_from_slice(&tcbinfo_root_len);
    input.extend_from_slice(&enclaveidentity_root_len);
    input.extend_from_slice(&signing_cert_pem_len);
    input.extend_from_slice(&root_cert_der_len);
    input.extend_from_slice(quote);
    input.extend_from_slice(tcbinfo_root.as_bytes());
    input.extend_from_slice(enclaveidentity_root.as_bytes());
    input.extend_from_slice(signing_cert_pem);
    input.extend_from_slice(root_cert_der);

    input.to_owned()
}
