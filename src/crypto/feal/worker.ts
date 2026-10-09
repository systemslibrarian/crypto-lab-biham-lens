import { attackStructures, decryptEquivalent, seededWords, verifyEquivalentKey } from './attack.js';
import type { Structures, Observation, EquivalentKey } from './attack.js';
import { join } from './feal.js';

type Start = { type: 'start'; runId: number; structures: Structures; seed: number };
type VerifyResponse = { type: 'verify-response'; runId: number; ciphertexts: bigint[] };
let pending: ((ciphertexts: bigint[]) => void) | null = null;
let pendingRun = -1;

self.onmessage = async (event: MessageEvent<Start | VerifyResponse>) => {
  const message = event.data;
  if (message.type === 'verify-response') {
    if (message.runId === pendingRun && pending) { const resolve = pending; pending = null; resolve(message.ciphertexts); }
    return;
  }
  const { runId, structures, seed } = message;
  try {
    const report = await attackStructures(structures, {
      onProgress: (stage) => self.postMessage({ type: 'progress', runId, stage }),
      yieldControl: () => new Promise((resolve) => setTimeout(resolve, 0)),
    });
    // Draw only after the attack has finished. Keep this stream separate from
    // plaintext collection and reject accidental repeats of queried blocks.
    const used = new Set([...structures.a, ...structures.b].flatMap((pair) => [pair.first.plaintext, pair.second.plaintext]));
    const next = seededWords(seed ^ 0x9e3779b9);
    const plaintexts: bigint[] = [];
    while (plaintexts.length < 64) {
      const p = join(next(), next());
      if (!used.has(p)) { used.add(p); plaintexts.push(p); }
    }
    pendingRun = runId;
    const ciphertexts = await new Promise<bigint[]>((resolve) => {
      pending = resolve;
      self.postMessage({ type: 'verify-request', runId, plaintexts });
    });
    if (ciphertexts.length !== 64) throw new Error('Fresh ciphertext oracle returned fewer than 64 blocks.');
    const fresh: Observation[] = plaintexts.map((plaintext, i) => ({ plaintext, ciphertext: ciphertexts[i] }));
    let verified = 0;
    let example: EquivalentKey | null = null;
    const stats = { fEvaluations: report.fEvaluations };
    for (const key of report.candidates) if (verifyEquivalentKey(key, fresh, stats)) { verified++; example ??= key; }
    const sample = example ? { plaintext: fresh[0].plaintext, ciphertext: fresh[0].ciphertext,
      decrypted: decryptEquivalent(fresh[0].ciphertext, example, stats) } : null;
    self.postMessage({ type: 'done', runId, stages: report.stages, fEvaluations: stats.fEvaluations, queried: report.queried,
      candidates: report.candidates.length, verified, example, sample });
  } catch (error) {
    self.postMessage({ type: 'error', runId, message: error instanceof Error ? error.message : String(error) });
  }
};
