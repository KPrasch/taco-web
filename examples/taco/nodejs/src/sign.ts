/**
 * TACo Signing Example — Porter vs Direct-to-Ursula
 *
 * Demonstrates both signing paths with a single UserOperation:
 *   1. signUserOp       — routes through Porter (proxy relay)
 *   2. signUserOpDirect  — contacts Ursula nodes directly
 *
 * Both produce identical message hashes; Direct is typically faster
 * because it skips the Porter hop and uses pipelined requests.
 *
 * Usage:
 *   npx ts-node src/benchmark-signing.ts
 */
import {
  domains,
  getPorterUris,
  initialize,
  preheatSigningCohort,
  signUserOp,
  signUserOpDirect,
  UserOperationToSign,
} from '@nucypher/taco';
import * as dotenv from 'dotenv';
import { ethers } from 'ethers';

dotenv.config();

// ---------------------------------------------------------------------------
// Configuration (from .env or defaults)
// ---------------------------------------------------------------------------

const RPC_PROVIDER_URL =
  process.env.RPC_PROVIDER_URL ||
  'https://ethereum-sepolia-rpc.publicnode.com';
const DOMAIN = process.env.DOMAIN || domains.DEVNET;
const COHORT_ID = parseInt(process.env.COHORT_ID || '1', 10);
const CHAIN_ID = parseInt(process.env.CHAIN_ID || '11155111', 10); // Sepolia
const AA_VERSION = process.env.AA_VERSION || '0.8.0';

const USER_OP: UserOperationToSign = {
  sender: '0x1234567890123456789012345678901234567890',
  nonce: 1,
  callData: '0x',
  callGasLimit: 100000,
  verificationGasLimit: 100000,
  preVerificationGas: 21000,
  maxFeePerGas: 2000000000,
  maxPriorityFeePerGas: 1000000000,
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('Initializing taco...');
  await initialize();

  const provider = new ethers.providers.JsonRpcProvider(RPC_PROVIDER_URL);
  const network = await provider.getNetwork();
  if (network.chainId !== CHAIN_ID) {
    throw new Error(
      `Provider on chain ${network.chainId}, expected ${CHAIN_ID}`,
    );
  }

  const porterUris = await getPorterUris(DOMAIN);
  console.log(`Domain: ${DOMAIN}`);
  console.log(`Cohort: ${COHORT_ID}  Chain: ${CHAIN_ID}`);
  console.log(`Porter URIs: ${porterUris.join(', ')}`);

  // Pre-warm caches + TLS connections (benefits both paths)
  console.log('\nPreheating signing cohort (caches + TLS)...');
  await preheatSigningCohort(provider, DOMAIN, COHORT_ID, porterUris);
  console.log('  done.');

  // --- Porter path ---
  console.log('\nSigning via Porter...');
  const t0Porter = performance.now();
  const porterResult = await signUserOp(
    provider,
    DOMAIN,
    COHORT_ID,
    CHAIN_ID,
    USER_OP,
    AA_VERSION,
    undefined,
    porterUris,
  );
  const porterMs = performance.now() - t0Porter;

  // --- Direct path ---
  console.log('Signing via Direct...');
  const t0Direct = performance.now();
  const directResult = await signUserOpDirect(
    provider,
    DOMAIN,
    COHORT_ID,
    CHAIN_ID,
    USER_OP,
    AA_VERSION,
    undefined,
    porterUris,
  );
  const directMs = performance.now() - t0Direct;

  // --- Results ---
  const fmtMs = (ms: number) => `${(ms / 1000).toFixed(3)}s`;

  console.log('\n--- Results ---');
  console.log(`  Porter:  ${fmtMs(porterMs)}  hash=${porterResult.messageHash}`);
  console.log(`  Direct:  ${fmtMs(directMs)}  hash=${directResult.messageHash}`);

  if (porterResult.messageHash === directResult.messageHash) {
    console.log('\n  Hashes match.');
  } else {
    console.error('\n  WARNING: hashes differ!');
  }
}

main().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
