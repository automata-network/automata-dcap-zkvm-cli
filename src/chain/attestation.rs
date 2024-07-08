use alloy::{primitives::Bytes, sol, sol_types::SolInterface};

sol! {
    interface IAttestation {
        function verifyAndAttestWithZKProof(bytes calldata journal, bytes calldata seal);
    }
}

pub fn generate_attestation_calldata(output: &[u8], seal: &[u8]) -> Vec<u8> {
    let calldata = IAttestation::IAttestationCalls::verifyAndAttestWithZKProof(
        IAttestation::verifyAndAttestWithZKProofCall {
            journal: Bytes::from(output.to_vec()),
            seal: Bytes::from(seal.to_vec())
        },
    )
    .abi_encode();

    calldata
}
