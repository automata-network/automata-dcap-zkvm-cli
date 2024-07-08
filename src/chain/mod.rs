pub mod attestation;
pub mod seal;
pub mod pccs;

use anyhow::Result;

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::types::{TransactionReceipt, TransactionRequest},
    signers::{k256::ecdsa::SigningKey, local::PrivateKeySigner, utils::secret_key_to_address},
};

pub struct TxSender {
    rpc_url: String,
    wallet: EthereumWallet,
    contract: Address,
}

impl TxSender {
    /// Creates a new `TxSender`.
    pub fn new(
        rpc_url: &str,
        private_key: &str,
        contract: &str,
    ) -> Result<Self> {
        let contract = contract.parse::<Address>()?;

        let signer_key =
            SigningKey::from_slice(&hex::decode(private_key).unwrap()).expect("Invalid key");
        let wallet = EthereumWallet::from(PrivateKeySigner::from_signing_key(signer_key));

        Ok(TxSender {
            rpc_url: rpc_url.to_string(),
            wallet,
            contract,
        })
    }

    /// Send a transaction with the given calldata.
    pub async fn send(&self, calldata: Vec<u8>) -> Result<TransactionReceipt> {
        let rpc_url = self.rpc_url.parse()?;
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(&self.wallet)
            .on_http(rpc_url);

        // let markup_percentage: u128 = 120;
        // let fetched_gas_price = provider.get_gas_price().await?;
        // let final_gas_price = (fetched_gas_price * markup_percentage) / 100;

        let tx = TransactionRequest::default()
            .with_to(self.contract)
            .with_input(calldata);

        let receipt = provider
            .send_transaction(tx.clone())
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }
}

pub fn get_evm_address_from_key(key: &str) -> String {
    let key_slice = hex::decode(key).unwrap();
    let signing_key = SigningKey::from_slice(&key_slice).expect("Invalid key");
    let address = secret_key_to_address(&signing_key);
    address.to_checksum(None)
}
