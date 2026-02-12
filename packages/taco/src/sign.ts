import {
  EncryptedThresholdSignatureRequest,
  EncryptedThresholdSignatureResponse,
  PackedUserOperationSignatureRequest,
  SessionSharedSecret,
  SessionStaticSecret,
  SignatureResponse,
  UserOperationSignatureRequest,
} from '@nucypher/nucypher-core';
import {
  ChecksumAddress,
  Domain,
  fromHexString,
  getPorterUris,
  isPackedUserOperation,
  PackedUserOperationToSign,
  PorterClient,
  SignerInfo,
  SigningCoordinatorAgent,
  toCorePackedUserOperation,
  toCoreUserOperation,
  toHexString,
  UserOperationToSign,
} from '@nucypher/shared';
import axios from 'axios';
import { ethers } from 'ethers';

import { Condition } from './conditions/condition';
import { ConditionExpression } from './conditions/condition-expr';
import { ConditionContext } from './conditions/context';

const ERR_INSUFFICIENT_SIGNATURES = (errors: unknown) =>
  `Threshold of signatures not met; TACo signing failed with errors: ${JSON.stringify(
    errors,
  )}`;
const ERR_MISMATCHED_HASHES = (
  hashToSignatures: Map<string, { [ursulaAddress: string]: TacoSignature }>,
) =>
  `Threshold of signatures not met; multiple mismatched hashes found: ${JSON.stringify(
    Object.fromEntries(hashToSignatures.entries()),
  )}`;

export type TacoSignature = {
  messageHash: string;
  signature: string;
  signerAddress: string;
};

export type SignResult = {
  messageHash: string;
  aggregatedSignature: string;
  signingResults: { [ursulaAddress: string]: TacoSignature };
};

function aggregateSignatures(
  signatures: TacoSignature[],
  threshold: number,
): string {
  // Aggregate hex signatures by concatenating them; being careful to sort
  //  and remove the '0x' prefix from each signature except the first one.

  // sort by signer address
  const sortedSignatures = [...signatures]
    .sort((a, b) =>
      a.signerAddress
        .toLowerCase()
        .localeCompare(b.signerAddress.toLowerCase()),
    )
    .map((sig) => sig.signature);

  const thresholdSignatures = sortedSignatures.slice(0, threshold);
  if (thresholdSignatures.length === 1) {
    return thresholdSignatures[0];
  }

  // Concatenate signatures
  const allBytes = thresholdSignatures.flatMap((sig) =>
    Array.from(fromHexString(sig)),
  );
  return `0x${toHexString(new Uint8Array(allBytes))}`;
}

async function makeSigningRequests(
  cohortId: number,
  chainId: number,
  signers: Array<SignerInfo>,
  userOp: UserOperationToSign | PackedUserOperationToSign,
  aaVersion: string,
  conditionContext?: ConditionContext,
): Promise<{
  sharedSecrets: Record<string, SessionSharedSecret>;
  encryptedRequests: Record<string, EncryptedThresholdSignatureRequest>;
}> {
  const coreContext = conditionContext
    ? await conditionContext.toCoreContext()
    : null;

  let signingRequest:
    | PackedUserOperationSignatureRequest
    | UserOperationSignatureRequest;
  if (isPackedUserOperation(userOp)) {
    const corePackedUserOp = toCorePackedUserOperation(userOp);
    signingRequest = new PackedUserOperationSignatureRequest(
      corePackedUserOp,
      cohortId,
      BigInt(chainId),
      aaVersion,
      coreContext,
    );
  } else {
    const coreUserOp = toCoreUserOperation(userOp);
    signingRequest = new UserOperationSignatureRequest(
      coreUserOp,
      cohortId,
      BigInt(chainId),
      aaVersion,
      coreContext,
    );
  }

  const ephemeralSessionKey = SessionStaticSecret.random();

  const sharedSecrets: Record<string, SessionSharedSecret> = Object.fromEntries(
    signers.map(({ provider, signingRequestStaticKey }) => {
      const sharedSecret = ephemeralSessionKey.deriveSharedSecret(
        signingRequestStaticKey,
      );
      return [provider, sharedSecret];
    }),
  );

  const encryptedRequests: Record<string, EncryptedThresholdSignatureRequest> =
    Object.fromEntries(
      Object.entries(sharedSecrets).map(([provider, sessionSharedSecret]) => {
        const encryptedRequest = signingRequest.encrypt(
          sessionSharedSecret,
          ephemeralSessionKey.publicKey(),
        );
        return [provider, encryptedRequest];
      }),
    );

  return { sharedSecrets, encryptedRequests };
}

/**
 * Signs a UserOperation.
 * @param provider - The Ethereum provider to use for signing.
 * @param domain - The TACo domain being used.
 * @param cohortId - The cohort ID that identifies the signing cohort.
 * @param chainId - The chain ID for the signing operation.
 * @param userOp - The UserOperation to be signed.
 * @param aaVersion - The AA version of the account abstraction to use for signing.
 * @param context - Optional condition context for the context variable resolution.
 * @param porterUris - Optional URIs for the Porter service. If not provided, will fetch the default URIs from the domain.
 * @returns A promise that resolves to a SignResult containing the message hash, aggregated signature, and signing results from the Porter service.
 * @throws An error if the signing process fails due to insufficient signatures or mismatched hashes.
 */
export async function signUserOp(
  provider: ethers.providers.Provider,
  domain: Domain,
  cohortId: number,
  chainId: number,
  userOp: UserOperationToSign | PackedUserOperationToSign,
  aaVersion: 'mdt' | '0.8.0' | string,
  context?: ConditionContext,
  porterUris?: string[],
): Promise<SignResult> {
  const porterUrisFull: string[] = porterUris
    ? porterUris
    : await getPorterUris(domain);
  const porter = new PorterClient(porterUrisFull);

  const signers = await SigningCoordinatorAgent.getParticipants(
    provider,
    domain,
    cohortId,
  );

  const threshold = await SigningCoordinatorAgent.getThreshold(
    provider,
    domain,
    cohortId,
  );

  const { sharedSecrets, encryptedRequests } = await makeSigningRequests(
    cohortId,
    chainId,
    signers,
    userOp,
    aaVersion,
    context,
  );

  // Build signing request for the user operation
  const { encryptedResponses, errors } = await porter.signUserOp(
    encryptedRequests,
    threshold,
  );
  if (Object.keys(encryptedResponses).length < threshold) {
    // not enough signatures returned
    throw new Error(ERR_INSUFFICIENT_SIGNATURES(errors));
  }

  const signaturesToAggregate = collectSignatures(
    encryptedResponses,
    sharedSecrets,
    threshold,
  );

  const aggregatedSignature = aggregateSignatures(
    Object.values(signaturesToAggregate),
    threshold,
  );

  return {
    messageHash: Object.values(signaturesToAggregate)[0].messageHash,
    aggregatedSignature,
    signingResults: signaturesToAggregate,
  };
}

export async function setSigningCohortConditions(
  provider: ethers.providers.JsonRpcProvider,
  domain: Domain,
  conditions: Condition,
  cohortId: number,
  chainId: number,
  signer: ethers.Signer,
): Promise<ethers.ContractTransaction> {
  // Convert Condition to ConditionExpression, then to JSON, then to bytes
  const conditionExpression = new ConditionExpression(conditions);
  const conditionsJson = conditionExpression.toJson();
  const conditionsBytes = ethers.utils.toUtf8Bytes(conditionsJson);

  // Set conditions on the SigningCoordinator contract
  return await SigningCoordinatorAgent.setSigningCohortConditions(
    provider,
    domain,
    cohortId,
    chainId,
    conditionsBytes,
    signer,
  );
}

function decryptSignatureResponses(
  encryptedResponses: Record<string, EncryptedThresholdSignatureResponse>,
  sharedSecrets: Record<string, SessionSharedSecret>,
): Record<string, TacoSignature> {
  const decryptedResponses: Record<string, SignatureResponse> =
    Object.fromEntries(
      Object.entries(encryptedResponses).map(
        ([ursulaAddress, encryptedResponse]) => [
          ursulaAddress,
          encryptedResponse.decrypt(sharedSecrets[ursulaAddress]),
        ],
      ),
    );

  const tacoSignatures: Record<string, TacoSignature> = Object.fromEntries(
    Object.entries(decryptedResponses).map(
      ([ursulaAddress, signatureResponse]) => [
        ursulaAddress,
        {
          messageHash: `0x${toHexString(signatureResponse.hash)}`,
          signature: `0x${toHexString(signatureResponse.signature)}`,
          signerAddress: signatureResponse.signer,
        },
      ],
    ),
  );

  return tacoSignatures;
}

function collectSignatures(
  encryptedResponses: Record<string, EncryptedThresholdSignatureResponse>,
  sharedSecrets: Record<string, SessionSharedSecret>,
  threshold: number,
): Record<string, TacoSignature> {
  const decryptedSignatures = decryptSignatureResponses(
    encryptedResponses,
    sharedSecrets,
  );

  const hashToSignatures: Map<
    string,
    Record<string, TacoSignature>
  > = new Map();

  // Single pass: decode signatures and populate signingResults
  for (const [ursulaAddress, signature] of Object.entries(
    decryptedSignatures,
  )) {
    // For non-optimistic: track hashes and group signatures for aggregation
    const hash = signature.messageHash;
    if (!hashToSignatures.has(hash)) {
      hashToSignatures.set(hash, {});
    }
    hashToSignatures.get(hash)![ursulaAddress] = signature;
  }

  // Find a hash that meets the threshold
  let signaturesToAggregate = undefined;
  for (const signatures of hashToSignatures.values()) {
    if (Object.keys(signatures).length >= threshold) {
      signaturesToAggregate = signatures;
      break;
    }
  }

  // Insufficient signatures for a message hash to meet the threshold
  if (!signaturesToAggregate) {
    // we have multiple hashes, which means we have mismatched hashes from different nodes
    //    we don't really expect this to happen (other than some malicious nodes)
    console.error(
      'Porter returned mismatched message hashes:',
      hashToSignatures,
    );
    throw new Error(ERR_MISMATCHED_HASHES(hashToSignatures));
  }

  return signaturesToAggregate;
}

// ---------------------------------------------------------------------------
// Direct-to-Ursula signing (Bob equivalent)
// ---------------------------------------------------------------------------

// --- TTL cache ---------------------------------------------------------------

class TtlCache<K extends string | number, V> {
  private entries = new Map<K, { value: V; expiresAt: number }>();
  constructor(private ttlMs: number) {}

  get(key: K): V | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: K, value: V): void {
    this.entries.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }

  has(key: K): boolean {
    return this.get(key) !== undefined;
  }

  clear(): void {
    this.entries.clear();
  }
}

// --- Module-level caches -----------------------------------------------------

const COHORT_TTL_MS = 5 * 60_000;  // 5 min — signers/threshold rarely change
const URI_TTL_MS = 5 * 60_000;     // 5 min — Ursula IPs rarely change
const CONN_TTL_MS = 4 * 60_000;    // 4 min — shorter than URI TTL to catch stale sockets

const cohortCache = new TtlCache<number, { signers: SignerInfo[]; threshold: number }>(COHORT_TTL_MS);
const ursulaUriCache = new TtlCache<ChecksumAddress, string>(URI_TTL_MS);
const warmConnCache = new TtlCache<string, true>(CONN_TTL_MS);

/** Clear all module-level signing caches. Intended for testing. */
export function clearSigningCaches(): void {
  cohortCache.clear();
  ursulaUriCache.clear();
  warmConnCache.clear();
}

async function getOrFetchCohort(
  provider: ethers.providers.Provider,
  domain: Domain,
  cohortId: number,
): Promise<{ signers: SignerInfo[]; threshold: number }> {
  const cached = cohortCache.get(cohortId);
  if (cached) return cached;
  const [signers, threshold] = await Promise.all([
    SigningCoordinatorAgent.getParticipants(provider, domain, cohortId),
    SigningCoordinatorAgent.getThreshold(provider, domain, cohortId),
  ]);
  const entry = { signers, threshold };
  cohortCache.set(cohortId, entry);
  return entry;
}

// --- HTTP helpers ------------------------------------------------------------

// Lazily resolved HTTPS agent for direct Ursula connections (Node.js only).
// Ursulas use self-signed TLS certificates requiring verification to be disabled.
// Dynamic import keeps the package browser-compatible (axios uses XHR/fetch there).
let _insecureHttpsAgent: object | undefined;
async function getInsecureHttpsAgent(): Promise<object | undefined> {
  if (!_insecureHttpsAgent) {
    try {
      const https = await import('https');
      _insecureHttpsAgent = new https.Agent({
        rejectUnauthorized: false,
        keepAlive: true,
      });
    } catch {
      // Not available (browser environment)
    }
  }
  return _insecureHttpsAgent;
}

async function requestSignatureFromUrsula(
  ursulaUri: string,
  encryptedRequest: EncryptedThresholdSignatureRequest,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<EncryptedThresholdSignatureResponse> {
  const resp = await axios.post(
    `${ursulaUri}/sign`,
    encryptedRequest.toBytes(),
    {
      responseType: 'arraybuffer',
      headers: { 'Content-Type': 'application/octet-stream' },
      timeout: timeoutMs,
      httpsAgent: await getInsecureHttpsAgent(),
      ...(signal ? { signal } : {}),
    },
  );
  return EncryptedThresholdSignatureResponse.fromBytes(
    new Uint8Array(resp.data),
  );
}

// --- Discovery & connection warming ------------------------------------------

/**
 * Pre-warm TLS connections to Ursulas so that subsequent /sign POSTs
 * skip the TCP+TLS handshake (~150-300ms saving per cold connection).
 * Fires a lightweight GET /health to each URI not already warm.
 * Returns a promise that resolves when all pings settle.
 */
async function warmConnections(uris: string[]): Promise<void> {
  const cold = uris.filter((u) => !warmConnCache.has(u));
  if (cold.length === 0) return;
  await Promise.allSettled(
    cold.map(async (uri) => {
      try {
        await axios.get(`${uri}/health`, {
          timeout: 3_000,
          httpsAgent: await getInsecureHttpsAgent(),
          validateStatus: () => true,
        });
        warmConnCache.set(uri, true);
      } catch {
        // Connection failed — don't mark as warmed
      }
    }),
  );
}

async function discoverUrsulaUris(
  signerAddresses: ChecksumAddress[],
  porterUris: string[],
): Promise<Record<ChecksumAddress, string>> {
  // Only fetch URIs for addresses missing or expired in cache
  const missing = signerAddresses.filter((a) => !ursulaUriCache.has(a));
  if (missing.length === 0) {
    return Object.fromEntries(
      signerAddresses.map((a) => [a, ursulaUriCache.get(a)!]),
    );
  }

  const porter = new PorterClient(porterUris);
  const ursulas = await porter.getUrsulas(missing.length, [], missing);

  for (const u of ursulas) {
    ursulaUriCache.set(u.checksumAddress as ChecksumAddress, u.uri);
  }

  const uriMap = Object.fromEntries(
    signerAddresses
      .filter((a) => ursulaUriCache.has(a))
      .map((a) => [a, ursulaUriCache.get(a)!]),
  );

  // Warm TLS connections for newly discovered URIs
  await warmConnections(Object.values(uriMap));

  return uriMap;
}

/**
 * Eagerly populates caches and pre-warms TLS connections for a signing cohort.
 * Call once on app startup or before a batch of signing operations so that
 * the first `signUserOpDirect` call pays no cold-start penalty.
 */
export async function preheatSigningCohort(
  provider: ethers.providers.Provider,
  domain: Domain,
  cohortId: number,
  porterUris?: string[],
): Promise<void> {
  const uris: string[] = porterUris ? porterUris : await getPorterUris(domain);

  const cached = await getOrFetchCohort(provider, domain, cohortId);
  const signerAddresses = cached.signers.map((s) => s.provider) as ChecksumAddress[];
  await discoverUrsulaUris(signerAddresses, uris);
}

/**
 * Signs a UserOperation by contacting Ursula nodes directly (bypassing Porter relay).
 * This is the "Bob equivalent" signing path — encrypted requests are POSTed
 * directly to each Ursula's /sign endpoint in parallel.
 *
 * @param provider - The Ethereum provider to use.
 * @param domain - The TACo domain being used.
 * @param cohortId - The cohort ID that identifies the signing cohort.
 * @param chainId - The chain ID for the signing operation.
 * @param userOp - The UserOperation to be signed.
 * @param aaVersion - The AA version of the account abstraction to use for signing.
 * @param context - Optional condition context for context variable resolution.
 * @param porterUris - Optional URIs for the Porter service (used only for Ursula discovery).
 * @param timeoutMs - Per-Ursula request timeout in milliseconds (default 15000).
 * @returns A promise that resolves to a SignResult.
 */
export async function signUserOpDirect(
  provider: ethers.providers.Provider,
  domain: Domain,
  cohortId: number,
  chainId: number,
  userOp: UserOperationToSign | PackedUserOperationToSign,
  aaVersion: 'mdt' | '0.8.0' | string,
  context?: ConditionContext,
  porterUris?: string[],
  timeoutMs: number = 15_000,
): Promise<SignResult> {
  const porterUrisFull: string[] = porterUris
    ? porterUris
    : await getPorterUris(domain);

  const { signers, threshold } = await getOrFetchCohort(provider, domain, cohortId);

  // Ensure URIs are cached (no-op after first call)
  const signerAddresses = signers.map((s) => s.provider) as ChecksumAddress[];
  const uriMap = await discoverUrsulaUris(signerAddresses, porterUrisFull);

  // Best-effort TLS re-warm for connections that may have gone idle.
  // Runs in the background — doesn't block the signing pipeline.
  void warmConnections(Object.values(uriMap));

  // Build the signing request object once (shared across all signers)
  const coreContext = context ? await context.toCoreContext() : null;
  let signingRequest:
    | PackedUserOperationSignatureRequest
    | UserOperationSignatureRequest;
  if (isPackedUserOperation(userOp)) {
    signingRequest = new PackedUserOperationSignatureRequest(
      toCorePackedUserOperation(userOp),
      cohortId, BigInt(chainId), aaVersion, coreContext,
    );
  } else {
    signingRequest = new UserOperationSignatureRequest(
      toCoreUserOperation(userOp),
      cohortId, BigInt(chainId), aaVersion, coreContext,
    );
  }

  const ephemeralSessionKey = SessionStaticSecret.random();
  const abortController = new AbortController();
  const encryptedResponses: Record<string, EncryptedThresholdSignatureResponse> = {};
  const sharedSecrets: Record<string, SessionSharedSecret> = {};
  const errors: Record<string, string> = {};
  let successCount = 0;
  let onThreshold: () => void;
  const thresholdReached = new Promise<void>((resolve) => { onThreshold = resolve; });

  // Pipeline: encrypt + fire each request immediately, don't batch
  const promises = signers
    .filter((s) => uriMap[s.provider as ChecksumAddress])
    .map(async ({ provider: address, signingRequestStaticKey }) => {
      const sharedSecret = ephemeralSessionKey.deriveSharedSecret(
        signingRequestStaticKey,
      );
      sharedSecrets[address] = sharedSecret;
      const encryptedRequest = signingRequest.encrypt(
        sharedSecret,
        ephemeralSessionKey.publicKey(),
      );
      // Fire immediately — don't wait for other encryptions
      try {
        const response = await requestSignatureFromUrsula(
          uriMap[address as ChecksumAddress],
          encryptedRequest,
          timeoutMs,
          abortController.signal,
        );
        encryptedResponses[address] = response;
        if (++successCount >= threshold) {
          abortController.abort();
          onThreshold();
        }
      } catch (e: unknown) {
        if (!abortController.signal.aborted) {
          const msg = e instanceof Error ? e.message : String(e);
          errors[address] = `${uriMap[address as ChecksumAddress]}: ${msg}`;
        }
      }
    });

  await Promise.race([Promise.allSettled(promises), thresholdReached]);

  if (Object.keys(encryptedResponses).length < threshold) {
    throw new Error(ERR_INSUFFICIENT_SIGNATURES(errors));
  }

  const signaturesToAggregate = collectSignatures(
    encryptedResponses,
    sharedSecrets,
    threshold,
  );

  const aggregatedSignature = aggregateSignatures(
    Object.values(signaturesToAggregate),
    threshold,
  );

  return {
    messageHash: Object.values(signaturesToAggregate)[0].messageHash,
    aggregatedSignature,
    signingResults: signaturesToAggregate,
  };
}
