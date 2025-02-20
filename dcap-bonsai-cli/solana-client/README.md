# DCAP RiscZero Groth16 Verification on Solana

This document provides the instruction on how you can verify Groth16 proofs, generated from the DCAP Guest Program, on Solana.

This document assumes that you have already created the necessary artifacts, containing the `claim_digest` and `compressed_proof`in the `data` directory.

The artifacts will have to be pre-processed (mainly negating the `pi_a` value) before submitting the instruction to the [RiscZero Solana Program](https://github.com/risc0/risc0-solana/blob/main/examples/hello_example/program/src/lib.rs), which has been deployed to devnet at [`5HrF6mJAaSFdAym2xZixowzVifPyyzTuTs3viYKdjy4s`](https://explorer.solana.com/address/5HrF6mJAaSFdAym2xZixowzVifPyyzTuTs3viYKdjy4s?cluster=devnet).

The remainder of this document provides step-by-step instructions on how you can verify proofs on Solana.

## Pre-requisite:

Ensure everything listed below has been installed on your machine:

- [Solana CLI Tool](https://docs.anza.xyz/cli/install)
- [Node](https://nodejs.org/en/download)
- [Typescript and TSX](https://tsx.is/getting-started)
- [Yarn](https://classic.yarnpkg.com/lang/en/docs/install)

Once you have installed all of the packages described above, run the following command to install dependencies.

```bash
yarn install
```

---

## Set up Solana

You may skip this step, if this is not your first time running the Solana CLI on your machine.

- Generate the Keypair:

```bash
solana-keygen new
```

This should create an `id.json` file, containing the keypair.

To view the address of your Keypair, run this command:

```bash
solana-keygen pubkey
```

- Set the Keypair path:

```bash
solana config set --keypair <PATH TO KEYPAIR>
```

- Connect Solana to the `devnet` cluster

```bash
solana config set --url devnet
```

- To check your Solana configurations:

```bash
solana config get
```

Make sure that Solana is configured to connect to the devnet, and is using the intended Keypair.

Lastly, you need to make sure that your account is funded. You can do this either via the CLI or at https://faucet.solana.com/.

Run the following command:

```bash
solana airdrop <SOL-AMOUNT>
```

To check the balance of your account:

```bash
solana balance
```

## Submit the proofs for verification

Once you have configured Solana and funded your account, simply run the command below:

```bash
yarn start
```