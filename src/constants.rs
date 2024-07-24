pub const RISC_ZERO_VERSION_ENV_KEY: &str = "RISC_ZERO_VERSION";

// ImageID
pub const DEFAULT_IMAGE_ID_HEX: &str = "3441cadfe031778d8486d6f5a804b9bdd81157220b83a5ce8601057b331d6b23";

// TEE Type
pub const SGX_TEE_TYPE: u32 = 0x00000000;
pub const TDX_TEE_TYPE: u32 = 0x00000081;

// Collateral Path Defaults
pub const DEFAULT_QUOTE_PATH: &str = "./data/quote.hex";
// pub const DEFAULT_TCB_PATH: &str = "./data/tcbinfov2.json";
// pub const DEFAULT_QEID_PATH: &str = "./data/qeidentityv2.json";
// pub const DEFAULT_TCB_SIGNING_PEM_PATH: &str = "./data/signing_cert.pem";
// pub const DEFAULT_ROOT_CA_DER_PATH: &str = "./data/Intel_SGX_Provisioning_Certification_RootCA.cer";
// pub const DEFAULT_PCK_CRL_DER_PATH: &str = "./data/pck_platform_crl.der";
// pub const DEFAULT_ROOT_CA_CRL_DER_PATH: &str = "./data/intel_root_ca_crl.der";

// Chain Defaults
pub const DEFAULT_RPC_URL: &str = "https://automata-testnet.alt.technology";
pub const DEFAULT_DCAP_CONTRACT: &str = "efE368b17D137E86298eec8EbC5502fb56d27832";

// PCCS addresses
pub const ENCLAVE_ID_DAO_ADDRESS: &str = "413272890ab9F155a47A5F90a404Fb51aa259087";
pub const FMSPC_TCB_DAO_ADDRESS: &str = "7c04B466DebA13D48116b1339C62b35B9805E5A0";
pub const PCS_DAO_ADDRESS: &str = "D0335cbC73CA2f8EDd98a2BE3909f55642F414D7";
pub const PCK_DAO_ADDRESS: &str = "6D4cA6AE5315EBBcb4331c82531db0ad8853Eb31";