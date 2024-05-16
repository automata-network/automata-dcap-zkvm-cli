# Bonsai CLI Guide

---

## Summary

This CLI tool is used to fetch SNARK proofs of execution on the DCAP Guest Application via Bonsai, and optionally submit them on-chain. The DCAP Guest Application proves that an Intel SGX DCAP quote has been successfully verified and the enclave which originated the quote is legitimate.

Follow these steps to get started with this tool:

0. Install [Rust](https://doc.rust-lang.org/book/ch01-01-installation.html)

1. Export `BONSAI_API_KEY` and `BONSAI_API_URL` values into the shell. If you don't have a Bonsai API key, send a [request](https://docs.google.com/forms/d/e/1FAIpQLSf9mu18V65862GS4PLYd7tFTEKrl90J5GTyzw_d14ASxrruFQ/viewform) for one.

```bash
export BONSAI_API_KEY="" # see form linked above
export BONSAI_API_URL="" # provided with your api key
```

2. Build the program.

```bash
cargo build --release
```

---

## CLI Commands

You may run the following command to see available commands.

```bash
./target/release/app run --help
```

Outputs:

```bash
Gets Bonsai Proof and submits on-chain

Usage: app <COMMAND>

Commands:
  prove      Fetches proof from Bonsai and sends them on-chain to verify DCAP quote
  serialize  Generates the serialized input slice to be passed to the Guest application
  image-id   Computes the Image ID of the Guest application
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

To get help on individual commands (e.g. `prove`), do the following:

```bash
./target/release/app prove --help
```

Output:

```bash
Fetches proof from Bonsai and sends them on-chain to verify DCAP quote

Usage: app prove [OPTIONS]

Options:
  -q, --quote-hex <QUOTE_HEX>
          The input quote provided as a hex string, this overwrites the --quote-path argument
  -p, --quote-path <QUOTE_PATH>
          Optional: The path to a quote.hex file. Default: /data/quote.hex or overwritten by the --quote-hex argument if provided
  -t, --tcb-path <TCB_PATH>
          Optional: The path to TCBInfo.json file. Default: /data/tcbinfoV2.json
  -e, --id-path <QEID_PATH>
          Optional: The path to QEIdentity.json file. Default: /data/qeidentityv2.json
  -s, --signing-path <TCB_SIGNING_PEM_PATH>
          Optional: The path to the TCB Signing Cert PEM file. Default: /data/signing_cert.pem
  -r, --root-path <ROOT_CA_DER_PATH>
          Optional: The path to RootCA DER file. Default: /data/Intel_SGX_Provisioning_Certification_RootCA.cer
      --processor-crl-path <PROCESSOR_CRL_DER_PATH>
          Optional: The path to PCK ProcessorCRL DER file. Default: /data/pck_processor_crl.der
      --platform-crl-path <PLATFORM_CRL_DER_PATH>
          Optional: The path to PCK PlatformCRL DER file. Default: /data/pck_platform_crl.der
      --root-crl-path <ROOT_CRL_DER_PATH>
          Optional: The path to RootCRL DER file. Default: /data/intel_root_ca_crl.der
  -k, --wallet-key <WALLET_PRIVATE_KEY>
          Optional: A transaction will not be sent if left blank
      --chain-id <CHAIN_ID>
          Optional: ChainID
      --rpc-url <RPC_URL>
          Optional: RPC URL
      --contract <CONTRACT>
          Optional: DCAP Contract address
  -h, --help
          Print help
```

---

## Get Started

You may either pass your quote as a hexstring with the `--quote-hex` flag, or as a stored hexfile in `/data/quote.hex`. If you store your quote elsewhere, you may pass the path with the `--quote-path` flag.

>
> [!NOTE]
> Beware that passing quotes with the `--quote-hex` flag overwrites passing quotes with the `--quote-path` flag.
>

It is also recommended to set the environment value `RUST_LOG=info` to view logs.

To begin, run the command below:

```bash
RUST_LOG=info ./target/release/app prove -k <ethereum-private-key>
```

>
> [!NOTE]
> Passing your wallet key is optional. If none is provided, the program simply ends by printing the journal, post state digest and seal values to the terminal, without sending a transaction to the verification contract.

You may obtain some Arbitrum Sepolia Testnet tokens [here](https://www.l2faucet.com/).
>