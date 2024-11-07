use alloy::{
    primitives::Bytes,
    sol,
    sol_types::{SolInterface, SolValue},
};

sol! {
    interface IAttestation {
        function verifyAndAttestWithZKProof(bytes calldata output, bytes calldata proof) returns (bool success, bytes memory output);
    }
}

pub fn generate_attestation_calldata(output: &[u8], proof: &[u8]) -> Vec<u8> {
    let mut proof_with_type: Vec<u8> = vec![1];
    proof_with_type.extend(proof.to_vec());
    let calldata = IAttestation::IAttestationCalls::verifyAndAttestWithZKProof(
        IAttestation::verifyAndAttestWithZKProofCall {
            output: Bytes::from(output.to_vec()),
            proof: Bytes::from(proof_with_type),
        },
    )
    .abi_encode();

    calldata
}

pub fn decode_attestation_ret_data(ret: Vec<u8>) -> (bool, Vec<u8>) {
    let (verified, output) = <(bool, Bytes)>::abi_decode_params(&ret, true).unwrap();
    (verified, output.to_vec())
}
