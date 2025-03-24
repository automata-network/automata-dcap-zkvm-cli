pub const RISC_ZERO_VERSION_ENV_KEY: &str = "RISC_ZERO_VERSION";

// TEE Type
pub const SGX_TEE_TYPE: u32 = 0x00000000;
pub const TDX_TEE_TYPE: u32 = 0x00000081;

// Collateral Path Defaults
pub const DEFAULT_QUOTE_PATH: &str = "../data/quote.hex";

// Chain Defaults
pub const DEFAULT_RPC_URL: &str = "https://1rpc.io/ata/testnet";
pub const DEFAULT_DCAP_CONTRACT: &str = "0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF";
pub const DEFAULT_EXPLORER_URL: &str = "https://explorer-testnet.ata.network/tx";

// PCCS addresses
pub const ENCLAVE_ID_DAO_ADDRESS: &str = "0xd74e880029cd3B6b434f16beA5F53A06989458Ee";
pub const FMSPC_TCB_DAO_ADDRESS: &str = "0xd3A3f34E8615065704cCb5c304C0cEd41bB81483";
pub const PCS_DAO_ADDRESS: &str = "0xB270cD8550DA117E3accec36A90c4b0b48daD342";
pub const PCK_DAO_ADDRESS: &str = "0xa4615C2a260413878241ff7605AD9577feB356A5";