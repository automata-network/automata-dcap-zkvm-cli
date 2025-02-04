// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {
  Keypair,
  Connection,
  clusterApiUrl,
  TransactionInstruction,
  Transaction,
  sendAndConfirmTransaction,
  PublicKey,
  SystemProgram
} from "@solana/web3.js";
import fs from "fs";
import path from "path";
import os from "os";

const KEYPAIR_DIR = path.resolve(
  os.homedir(),
  ".config/solana/id.json"
);
const PROGRAM_KEYPAIR_PATH = path.resolve(
  __dirname,
  "deploy/program-keypair.json"
);
const PROOF_PATH = path.resolve(__dirname, "data/proof.bin");
const JOURNAL_DIGEST_PATH = path.resolve(__dirname, "data/journal_digest.bin");
const DCAP_IMAGE_ID = Buffer.from([ 194, 234, 254, 27, 160, 22, 16, 243, 183, 18, 129, 249, 221, 50, 128, 179, 61, 151, 55, 11, 182, 141, 58, 218, 41, 37, 211, 145, 190, 36, 94, 16 ]);

async function initConnection(localhost?: boolean): Promise<Connection> {
  let endpoint = localhost ? "http://127.0.0.1:8899" : clusterApiUrl("devnet");
  console.log("Connected endpoint: ", endpoint);
  return new Connection(endpoint, "confirmed");
}

async function loadProgramId(): Promise<PublicKey> {
  const secretKeyString = fs.readFileSync(PROGRAM_KEYPAIR_PATH, { encoding: "utf8" });
  const secretKey = Uint8Array.from(JSON.parse(secretKeyString));
  const programKeypair = Keypair.fromSecretKey(secretKey);
  return programKeypair.publicKey;
}

async function createPayerAccount(): Promise<Keypair> {
  const secretKeyhStr = fs.readFileSync(KEYPAIR_DIR, "utf8");
  const secretKey = new Uint8Array(JSON.parse(secretKeyhStr));
  return Keypair.fromSecretKey(secretKey);
}

async function verify_proof(
  connection: Connection,
  payer: Keypair,
  programId: PublicKey
): Promise<void> {
  const proof_data = fs.readFileSync(PROOF_PATH);

  const journal_digest = fs.readFileSync(JOURNAL_DIGEST_PATH);

  const instructionData = Buffer.concat([
    Buffer.from([133, 161, 141, 48, 120, 198, 88, 150]),
    proof_data,
    DCAP_IMAGE_ID,
    journal_digest
  ]);

  const verifyInstruction = new TransactionInstruction({
    keys: [{ pubkey: SystemProgram.programId, isSigner: false, isWritable: false }],
    programId,
    data: instructionData,
  });

  const transaction = new Transaction().add(
    verifyInstruction
  );

  try {
    const signature = await sendAndConfirmTransaction(connection, transaction, [payer], {
      skipPreflight: true,
      preflightCommitment: 'confirmed',
    });
    console.log("Transaction signature:", signature);
    console.log("Proof verified!");
  } catch (error) {
    console.error("Error in generate and verify operation:", error);
    throw error;
  }
}

async function main() {
  let useLocalhost = process.argv[2] ? true : false;

  console.log("Launching client...");
  const connection = await initConnection(useLocalhost);
  const programId = await loadProgramId();
  const payer = await createPayerAccount();

  console.log("--Pinging Program ", programId.toBase58());

  try {
    console.log("-- Verifying Proof");
    await verify_proof(connection, payer, programId);
  } catch (error) {
    console.error("Error in main execution:", error);
  }
}


main().then(
  () => process.exit(),
  (err) => {
    console.error(err);
    process.exit(-1);
  }
);