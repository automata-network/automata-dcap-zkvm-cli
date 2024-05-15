use alloy_primitives::FixedBytes;
use alloy_sol_types::{sol, SolInterface};
use anyhow::Result;
use ethers::{
    core::k256::ecdsa::SigningKey,
    prelude::*,
    utils::{secret_key_to_address, to_checksum},
};

sol! {
    interface IAttestation {
        function verifyAndAttestWithZKProof(bytes calldata journal, bytes32 post_state_digest, bytes calldata seal);
    }
}

pub struct TxSender {
    chain_id: u64,
    client: SignerMiddleware<Provider<Http>, Wallet<k256::ecdsa::SigningKey>>,
    contract: Address,
}

impl TxSender {
    /// Creates a new `TxSender`.
    pub fn new(chain_id: u64, rpc_url: &str, private_key: &str, contract: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let wallet: LocalWallet = private_key.parse::<LocalWallet>()?.with_chain_id(chain_id);
        let client = SignerMiddleware::new(provider.clone(), wallet.clone());
        let contract = contract.parse::<Address>()?;

        Ok(TxSender {
            chain_id,
            client,
            contract,
        })
    }

    /// Send a transaction with the given calldata.
    pub async fn send(&self, calldata: Vec<u8>) -> Result<Option<TransactionReceipt>> {
        let tx = TransactionRequest::new()
            .chain_id(self.chain_id)
            .to(self.contract)
            .from(self.client.address())
            .data(calldata);

        let tx = self.client.send_transaction(tx, None).await?.await?;

        match tx {
            Some(ref pending) => {
                let hash = pending.transaction_hash;
                log::info!("Tx hash: {}", hash.to_string());
            },
            None => {
                panic!("Failed to send transaction");
            }
        }

        Ok(tx)
    }
}

pub fn generate_calldata(output: &[u8], post_state_digest: FixedBytes<32>, seal: &[u8]) -> Vec<u8> {
    let calldata = IAttestation::IAttestationCalls::verifyAndAttestWithZKProof(
        IAttestation::verifyAndAttestWithZKProofCall {
            journal: output.to_vec(),
            post_state_digest: post_state_digest,
            seal: seal.to_vec(),
        },
    )
    .abi_encode();

    calldata
}

pub fn get_evm_address_from_key(key: &str) -> String {
    let key_slice = hex::decode(key).unwrap();
    let signing_key = SigningKey::from_slice(&key_slice).expect("Invalid key");
    let address = secret_key_to_address(&signing_key);
    to_checksum(&address, None)
}
