import { encrypt4, decrypt4, hex32, hex64, parseHex64, split, traceFeal4 } from './crypto/feal/feal.js';
import { collectStructures, DIFFERENCE_A, GAMMA } from './crypto/feal/attack.js';
import type { Structures, FunnelStage, EquivalentKey } from './crypto/feal/attack.js';

const el = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
let collected: Structures | null = null;
let worker: Worker | null = null;
let runId = 0;
let fEvaluations = 0;
let queried = 0;

function key(): bigint | null { return parseHex64(el<HTMLInputElement>('fealKey').value.trim()); }
function plaintext(): bigint | null { return parseHex64(el<HTMLInputElement>('fealPlaintext').value.trim()); }
function setStatus(message: string): void { el('fealStatus').textContent = message; }
function setCounters(incomplete = false): void {
  el('fealQueried').textContent = `${queried} chosen plaintexts queried${incomplete ? ' · incomplete' : ''}`;
  el('fealOps').textContent = `${fEvaluations.toLocaleString()} F evaluations${incomplete ? ' · incomplete' : ''}`;
}
function clearVerdict(): void {
  const card = el('fealVerdict');
  card.hidden = true;
  card.classList.remove('ok', 'alarm');
  el('fealVerdictText').textContent = '';
  el('fealFreshCount').textContent = '';
  el('fealRecovered').textContent = '';
  el('fealFreshSample').hidden = true;
  for (const id of ['fealSamplePlaintext', 'fealSampleCiphertext', 'fealSampleDecrypted']) el(id).textContent = '';
}
function stopWorker(): void {
  if (worker) worker.terminate();
  worker = null;
  runId++;
  el<HTMLButtonElement>('fealCancel').disabled = true;
  el<HTMLButtonElement>('fealRun').disabled = !collected;
  el<HTMLButtonElement>('fealCollect').disabled = false;
}
function invalidate(reason: string): void {
  const hadRun = !!worker;
  stopWorker();
  collected = null;
  el<HTMLButtonElement>('fealRun').disabled = true;
  el('fealFunnel').replaceChildren();
  const evidence = el<HTMLDetailsElement>('fealEvidence');
  evidence.hidden = true;
  evidence.open = false;
  el<HTMLTableSectionElement>('fealPairs').querySelector('tbody')!.replaceChildren();
  clearVerdict();
  queried = 0; fEvaluations = 0;
  setCounters(hadRun);
  setStatus(reason);
}
function renderTrace(): void {
  const k = key(), p = plaintext();
  const claim = el('fealTraceClaim');
  const tbody = el<HTMLTableSectionElement>('fealTrace').querySelector('tbody')!;
  tbody.replaceChildren();
  if (k === null || p === null) {
    for (const id of ['fealPathInput', 'fealPathPre', 'fealPathOne', 'fealPathTwo']) el(id).textContent = '—';
    claim.textContent = 'Enter exactly 16 hex digits in both fields to compute the trace.';
    return;
  }
  const paired = p ^ DIFFERENCE_A;
  const [pLeft, pRight] = split(p), [qLeft, qRight] = split(paired);
  const rows = traceFeal4(p, paired, k);
  el('fealPathInput').textContent = `L ${hex32(pLeft ^ qLeft)} · R ${hex32(pRight ^ qRight)}`;
  el('fealPathPre').textContent = `L ${hex32(rows[0].deltaLeft)} · R ${hex32(rows[0].deltaRight)}`;
  el('fealPathOne').textContent = `L ${hex32(rows[1].deltaLeft)} · R ${hex32(rows[1].deltaRight)}`;
  el('fealPathTwo').textContent = hex32(rows[2].fDelta!);
  for (const row of rows) {
    const tr = document.createElement('tr');
    if (row.round === 2) tr.className = 'feal-highlight';
    for (const value of [row.round === 0 ? 'Pre-round' : `Round ${row.round}`, hex32(row.deltaLeft), hex32(row.deltaRight), row.fDelta === null ? '—' : hex32(row.fDelta)]) {
      const td = document.createElement('td'); td.textContent = String(value); tr.append(td);
    }
    tbody.append(tr);
  }
  claim.textContent = `Round 1 f output Δ = ${hex32(rows[1].fDelta!)} because the input-half differences cancel. Computed round 2 f output Δ = ${hex32(rows[2].fDelta!)}${rows[2].fDelta === GAMMA ? ' · probability 1 for the A input difference' : ''}.`;
}
function encryptBlock(): void {
  const k = key(), p = plaintext();
  if (k === null || p === null) {
    el('fealCipherStatus').textContent = 'Use exactly 16 hex digits for both key and plaintext.';
    el('fealCipherOutput').textContent = '';
    renderTrace();
    return;
  }
  const c = encrypt4(p, k);
  const roundTrip = decrypt4(c, k);
  el('fealCipherStatus').textContent = roundTrip === p ? 'Decrypt round-trip matched.' : 'Decrypt round-trip failed.';
  el('fealCipherOutput').textContent = `Ciphertext: ${hex64(c)} · Decrypted: ${hex64(roundTrip)}`;
  renderTrace();
}
function counts(): [number, number] | null {
  const a = Number(el<HTMLInputElement>('fealCountA').value), b = Number(el<HTMLInputElement>('fealCountB').value);
  return Number.isInteger(a) && Number.isInteger(b) && a >= 2 && b >= 1 && a <= 30 && b <= 30 ? [a, b] : null;
}
function seed(): number | null {
  const text = el<HTMLInputElement>('fealSeed').value.trim();
  return /^[0-9a-fA-F]{8}$/.test(text) ? parseInt(text, 16) >>> 0 : null;
}
function warning(): void {
  const c = counts();
  el('fealWarning').textContent = c && c[0] >= 6 && c[1] >= 4
    ? 'Default data: 6 A + 4 B pairs = 20 chosen plaintexts.'
    : 'Below 6 A + 4 B pairs, the search may take much longer or fail.';
}
function renderEvidence(structures: Structures): void {
  const details = el<HTMLDetailsElement>('fealEvidence');
  const tbody = el<HTMLTableSectionElement>('fealPairs').querySelector('tbody')!;
  tbody.replaceChildren();
  for (const [name, pairs] of [['A', structures.a], ['B', structures.b]] as const) {
    for (const pair of pairs) {
      const tr = document.createElement('tr');
      for (const value of [name, hex64(pair.first.plaintext), hex64(pair.second.plaintext), hex64(pair.first.ciphertext), hex64(pair.second.ciphertext)]) {
        const td = document.createElement('td'); td.textContent = value; tr.append(td);
      }
      tbody.append(tr);
    }
  }
  details.querySelector('summary')!.textContent = `Inspect ${structures.queried} oracle queries (${structures.a.length + structures.b.length} pairs)`;
  details.open = false;
  details.hidden = false;
}
function collect(): void {
  const k = key(), c = counts(), s = seed();
  if (k === null || !c || s === null) {
    invalidate('Use a 16-digit hex key, 8-digit hex seed, at least 2 A pairs and 1 B pair (maximum 30 each).');
    return;
  }
  stopWorker(); clearVerdict(); el('fealFunnel').replaceChildren();
  collected = collectStructures((p) => encrypt4(p, k), c[0], c[1], s);
  queried = collected.queried; fEvaluations = 0; setCounters();
  renderEvidence(collected);
  const allA = collected.a.every((pair) => traceFeal4(pair.first.plaintext, pair.second.plaintext, k)[2].fDelta === GAMMA);
  setStatus(`Collected ${c[0]} A + ${c[1]} B pairs. ${allA ? 'Every A pair computed round 2 f Δ = 02000000.' : 'A-pair characteristic failed; inspect the trace.'}`);
  el<HTMLButtonElement>('fealRun').disabled = !allA;
}
function renderFunnel(stage: FunnelStage): void {
  const item = document.createElement('div');
  const title = document.createElement('strong'); title.textContent = `Round ${stage.round}`;
  const count = document.createElement('span'); count.textContent = `${stage.survivors.toLocaleString()} survivors`;
  const work = document.createElement('small'); work.textContent = `${stage.fEvaluations.toLocaleString()} F evaluations`;
  item.append(title, count, work);
  el('fealFunnel').append(item);
  fEvaluations = stage.fEvaluations; setCounters();
  setStatus(`Filtered round ${stage.round}: ${stage.survivors.toLocaleString()} survivors.`);
}
function finish(payload: { candidates: number; verified: number; example: EquivalentKey | null; fEvaluations: number; queried: number;
  sample: { plaintext: bigint; ciphertext: bigint; decrypted: bigint } | null }): void {
  stopWorker();
  fEvaluations = payload.fEvaluations;
  setCounters();
  const card = el('fealVerdict');
  card.hidden = false;
  const success = payload.verified > 0 && payload.example !== null && payload.sample !== null && payload.sample.decrypted === payload.sample.plaintext;
  card.classList.add(success ? 'ok' : 'alarm');
  el('fealFreshCount').textContent = `64/64 fresh ciphertexts checked for each of ${payload.candidates.toLocaleString()} full candidates; ${payload.verified.toLocaleString()} equivalent keys verified. ${payload.queried} attack queries + 64 later verification queries.`;
  el('fealVerdictText').textContent = success ? 'decrypts unseen ciphertext' : 'rejected: wrong on fresh ciphertext';
  el('fealRecovered').textContent = success ?
    `Example equivalent material\nRound f-keys: ${payload.example!.rounds.map(hex32).join('  ')}\nWhitening combinations: ${hex32(payload.example!.whiteningLeft)}  ${hex32(payload.example!.whiteningRight)}` : '';
  if (success) {
    el('fealFreshSample').hidden = false;
    el('fealSamplePlaintext').textContent = hex64(payload.sample!.plaintext);
    el('fealSampleCiphertext').textContent = hex64(payload.sample!.ciphertext);
    el('fealSampleDecrypted').textContent = hex64(payload.sample!.decrypted);
  }
  setStatus(success ? 'Attack complete; fresh ciphertext verification passed.' : 'Attack rejected by fresh ciphertext verification.');
}
function fail(message: string): void {
  stopWorker();
  el('fealFunnel').replaceChildren(); clearVerdict();
  setCounters(true); setStatus(message);
}
function run(): void {
  if (!collected) { setStatus('Collect chosen plaintexts first.'); return; }
  if (key() === null || !counts() || seed() === null) { invalidate('Correct the key, counts, and seed, then collect again.'); return; }
  clearVerdict(); el('fealFunnel').replaceChildren();
  fEvaluations = 0; setCounters();
  const current = ++runId;
  worker = new Worker(new URL('./crypto/feal/worker.ts', import.meta.url), { type: 'module' });
  el<HTMLButtonElement>('fealRun').disabled = true;
  el<HTMLButtonElement>('fealCollect').disabled = true;
  el<HTMLButtonElement>('fealCancel').disabled = false;
  setStatus('Searching round 4 in the worker…');
  worker.onmessage = (event: MessageEvent) => {
    const message = event.data;
    if (message.runId !== current || !worker) return;
    if (message.type === 'progress') renderFunnel(message.stage);
    else if (message.type === 'verify-request') {
      const k = key();
      if (k === null) { fail('Key changed during verification.'); return; }
      worker.postMessage({ type: 'verify-response', runId: current, ciphertexts: (message.plaintexts as bigint[]).map((p) => encrypt4(p, k)) });
      setStatus('Checking every candidate against 64 fresh ciphertexts…');
    } else if (message.type === 'done') finish(message);
    else if (message.type === 'error') fail(message.message);
  };
  worker.onerror = () => fail('Worker failed; counters are incomplete.');
  worker.postMessage({ type: 'start', runId: current, structures: collected, seed: seed() });
}

export function initFealTab(): void {
  el<HTMLInputElement>('fealKey').addEventListener('input', () => { invalidate('Key changed. Collect new pairs.'); renderTrace(); el('fealCipherOutput').textContent = ''; });
  el<HTMLInputElement>('fealPlaintext').addEventListener('input', () => { renderTrace(); el('fealCipherOutput').textContent = ''; });
  for (const id of ['fealCountA', 'fealCountB', 'fealSeed']) el<HTMLInputElement>(id).addEventListener('input', () => { invalidate('Collection settings changed. Collect new pairs.'); warning(); });
  el<HTMLButtonElement>('fealEncrypt').addEventListener('click', encryptBlock);
  el<HTMLButtonElement>('fealCollect').addEventListener('click', collect);
  el<HTMLButtonElement>('fealRun').addEventListener('click', run);
  el<HTMLButtonElement>('fealCancel').addEventListener('click', () => { if (worker) fail('Attack cancelled; counters are incomplete.'); });
  warning(); encryptBlock(); setCounters();
}
