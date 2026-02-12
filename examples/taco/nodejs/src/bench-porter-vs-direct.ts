/**
 * Benchmark: Porter vs Direct-to-Ursula signing.
 *
 * Runs multiple iterations of each signing path and prints
 * mean / median / stdev / min / max statistics.
 *
 * Usage:
 *   npx ts-node src/bench-porter-vs-direct.ts
 *   npx ts-node src/bench-porter-vs-direct.ts --runs 10
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
// Stats
// ---------------------------------------------------------------------------

function mean(v: number[]): number {
  return v.reduce((a, b) => a + b, 0) / v.length;
}
function median(v: number[]): number {
  const s = [...v].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
function stdev(v: number[]): number {
  if (v.length < 2) return 0;
  const m = mean(v);
  return Math.sqrt(v.reduce((s, x) => s + (x - m) ** 2, 0) / (v.length - 1));
}
function fmtMs(ms: number): string {
  return `${(ms / 1000).toFixed(3)}s`;
}
function printStats(label: string, times: number[]) {
  console.log(
    `  ${label.padEnd(18)} mean=${fmtMs(mean(times))}  median=${fmtMs(median(times))}  stdev=${fmtMs(stdev(times))}  min=${fmtMs(Math.min(...times))}  max=${fmtMs(Math.max(...times))}  (n=${times.length})`,
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const numRuns = parseInt(
    process.argv.find((_, i, a) => a[i - 1] === '--runs') || '5',
    10,
  );

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
  console.log(`Runs: ${numRuns}`);

  // Warmup
  console.log('\nWarmup: preheat cohort (caches + TLS)...');
  try {
    await preheatSigningCohort(provider, DOMAIN, COHORT_ID, porterUris);
    await signUserOpDirect(
      provider, DOMAIN, COHORT_ID, CHAIN_ID, USER_OP, AA_VERSION,
      undefined, porterUris,
    );
    console.log('  done.\n');
  } catch (e) {
    console.log(`  warmup failed: ${e instanceof Error ? e.message : e}\n`);
  }

  console.log(`--------- Benchmark (${numRuns} runs each) ---------`);

  const porterTimes: number[] = [];
  const directTimes: number[] = [];

  for (let i = 0; i < numRuns; i++) {
    console.log(`\n--- Run ${i + 1}/${numRuns} ---`);

    // Porter path
    try {
      const t0 = performance.now();
      const result = await signUserOp(
        provider, DOMAIN, COHORT_ID, CHAIN_ID, USER_OP, AA_VERSION,
        undefined, porterUris,
      );
      const elapsed = performance.now() - t0;
      porterTimes.push(elapsed);
      console.log(
        `  Porter:  ${fmtMs(elapsed)}  hash=${result.messageHash.slice(0, 18)}...`,
      );
    } catch (e) {
      console.log(`  Porter:  FAILED - ${e instanceof Error ? e.message : e}`);
    }

    // Direct path
    try {
      const t0 = performance.now();
      const result = await signUserOpDirect(
        provider, DOMAIN, COHORT_ID, CHAIN_ID, USER_OP, AA_VERSION,
        undefined, porterUris,
      );
      const elapsed = performance.now() - t0;
      directTimes.push(elapsed);
      console.log(
        `  Direct:  ${fmtMs(elapsed)}  hash=${result.messageHash.slice(0, 18)}...`,
      );
    } catch (e) {
      console.log(`  Direct:  FAILED - ${e instanceof Error ? e.message : e}`);
    }
  }

  // Summary
  console.log(`\n${'='.repeat(60)}`);
  console.log(`  RESULTS (${numRuns} runs)`);
  console.log(`${'='.repeat(60)}`);

  if (porterTimes.length) printStats('Porter (proxy)', porterTimes);
  else console.log('  Porter: all runs failed');

  if (directTimes.length) printStats('Direct (Bob)', directTimes);
  else console.log('  Direct: all runs failed');

  if (porterTimes.length && directTimes.length) {
    const diff = mean(directTimes) - mean(porterTimes);
    const pct = (diff / mean(porterTimes)) * 100;
    console.log(
      `\n  Delta (Direct - Porter): ${diff > 0 ? '+' : ''}${fmtMs(diff)} (${pct > 0 ? '+' : ''}${pct.toFixed(1)}%)`,
    );
  }
}

main().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
