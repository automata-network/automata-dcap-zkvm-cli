use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
};
use sp1_solana::verify_proof;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

#[derive(BorshDeserialize, BorshSerialize)]
pub struct SP1Groth16Proof {
    pub vkey_hash: String,
    pub proof: Vec<u8>,
    pub sp1_public_inputs: Vec<u8>,
}

// The instruction data consists of:
// 32-bytes: VKEY hash of an SP1 Program
// remaining bytes are the BORSH serialized SP1Groth16Proof Object
pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Deserialize the SP1Groth16Proof from the instruction data.
    let groth16_proof = SP1Groth16Proof::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Get the SP1 Groth16 verification key from the `sp1-solana` crate.
    let vk = sp1_solana::GROTH16_VK_3_0_0_BYTES;

    // Verify the proof.
    verify_proof(
        &groth16_proof.proof,
        &groth16_proof.sp1_public_inputs,
        &groth16_proof.vkey_hash,
        vk,
    )
    .map_err(|_| ProgramError::InvalidInstructionData)?;

    msg!("Successfully verified proof!");

    Ok(())
}
