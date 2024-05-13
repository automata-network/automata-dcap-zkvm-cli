# Bonsai CLI Guide

---

## Summary

This CLI tool can be used to generate SNARK proofs on Bonsai, which then submits the proof of the Guest application on-chain.

To use this tool, you must:

1. configure `.env` to store `BONSAI_API_KEY` and `BONSAI_API_URL` values.

2. Make sure you are on the `/app` directory.

```bash
cd ./app
```

---

## CLI Commands

You may run the following command below, to see available commands.

```bash
cargo run -- --help
```

Outputs:

```bash
Gets Bonsai Proof and submits on-chain

Usage: app <COMMAND>

Commands:
  prove     Fetches proof from Bonsai and sends them on-chain to verify DCAP quote
  image-id  Computes the Image ID of the Guest application
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

To get help on individual commands (e.g. `prove`), do the following:

```bash
cargo run -- prove --help
```

Output:

```bash
Fetches proof from Bonsai and sends them on-chain to verify DCAP quote

Usage: cargo run -- prove [OPTIONS] --quote-hex <QUOTE_HEX> --tcb-path <TCB_PATH> --id-path <QEID_PATH> --signing-path <TCB_SIGNING_PEM_PATH> --root-path <ROOT_CA_DER_PATH>

Options:
      --quote-hex <QUOTE_HEX>                The input quote provided as a hex string
  -t, --tcb-path <TCB_PATH>                  The path to TCBInfo.json
  -e, --id-path <QEID_PATH>                  The path to QEIdentity.json
  -s, --signing-path <TCB_SIGNING_PEM_PATH>  The path to TCBSigning PEM
  -r, --root-path <ROOT_CA_DER_PATH>         The path to RootCA DER
  -k, --wallet-key <WALLET_PRIVATE_KEY>      Optional: A transaction will not be sent if left blank
  -h, --help                                 Print help
```

---