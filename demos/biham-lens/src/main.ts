/**
 * Main UI application for biham-lens
 *
 * Based on "Differential Cryptanalysis of DES-like Cryptosystems"
 * by Eli Biham and Adi Shamir, Journal of Cryptology, 1991
 */

import { generateKey, traceEncryption } from './crypto/spn.js';
import type { SPNKey, TraceStage } from './crypto/spn.js';
import { computeDDT, verifyDDTProperties } from './crypto/ddt.js';
import { getSbox, setSbox, getActiveSboxName } from './crypto/sbox.js';
import type { SboxName } from './crypto/sbox.js';
import {
  collectPairs,
  attackLastRound,
  identifyCorrectKey,
  getKeyRank,
  deriveCharacteristic,
} from './crypto/attack.js';
import type { AttackResult } from './crypto/attack.js';
import { seed as seedRng, getSeed as getRngSeed } from './crypto/rng.js';

// ============================================================================
// Application State
// ============================================================================

interface AppState {
  masterKey: number;
  spnKey: SPNKey;
  collectedPairs: Array<{ c1: number; c2: number }>;
  lastAttackResults: AttackResult[] | null;
  selectedInputDiff: number;
  selectedOutputDiff: number;
  lastOpCount: number;
  traceStages: TraceStage[];
  traceVisibleCount: number;
}

const state: AppState = {
  masterKey: 0x5A69,
  spnKey: null as any,
  collectedPairs: [],
  lastAttackResults: null,
  selectedInputDiff: 0x01,
  selectedOutputDiff: 0x0B,
  lastOpCount: 0,
  traceStages: [],
  traceVisibleCount: 1,
};

// ============================================================================
// Initialization
// ============================================================================

function initializeApp() {
  // Seed RNG from the input's default value so the first attack is reproducible.
  const seedInput = byId<HTMLInputElement>('seedInput');
  seedRng(parseInt(seedInput.value, 16) || 0x12345678);

  state.spnKey = generateKey(state.masterKey);
  setupEventListeners();
  syncSboxToggleUI();
  renderDDT();
  renderSBox();
  updateActiveSboxLabel();
  updateMasterKeyDisplay();
  updateHiddenK4();
  updatePairStatus();
  rebuildTrace();
  renderTracePipeline();
  showTimelineContent(0);
}

function byId<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el as T;
}

// ============================================================================
// Tab Management
// ============================================================================

function setupEventListeners() {
  const themeToggle = document.getElementById('themeToggle') as HTMLButtonElement | null;
  if (themeToggle) {
    updateThemeToggleUI();
    themeToggle.addEventListener('click', toggleTheme);
  }

  // Tabs (click + keyboard nav, WAI-ARIA pattern).
  const tabButtons = document.querySelectorAll('.tab-button');
  tabButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const tabName = button.getAttribute('data-tab')!;
      switchTab(tabName);
    });
  });

  const tabNav = document.querySelector('[role="tablist"]');
  if (tabNav) {
    tabNav.addEventListener('keydown', (e: Event) => {
      const event = e as KeyboardEvent;
      const tabs = Array.from(tabNav.querySelectorAll('[role="tab"]')) as HTMLElement[];
      const current = tabs.findIndex((t) => t.getAttribute('aria-selected') === 'true');
      let next = current;

      if (event.key === 'ArrowRight') {
        next = (current + 1) % tabs.length;
        event.preventDefault();
      } else if (event.key === 'ArrowLeft') {
        next = (current - 1 + tabs.length) % tabs.length;
        event.preventDefault();
      } else if (event.key === 'Home') {
        next = 0;
        event.preventDefault();
      } else if (event.key === 'End') {
        next = tabs.length - 1;
        event.preventDefault();
      }

      if (next !== current) {
        const tabName = tabs[next].getAttribute('data-tab')!;
        switchTab(tabName);
        tabs[next].focus();
      }
    });
  }

  // Attack tab.
  const p1Input = byId<HTMLInputElement>('p1');
  const p2Input = byId<HTMLInputElement>('p2');
  const outDiffInput = byId<HTMLInputElement>('outDiff');

  p1Input.addEventListener('input', onPlaintextChange);
  p2Input.addEventListener('input', onPlaintextChange);
  outDiffInput.addEventListener('input', onOutDiffChange);

  byId<HTMLButtonElement>('deriveDiff').addEventListener('click', deriveCharacteristicFromCipher);
  byId<HTMLButtonElement>('add100').addEventListener('click', () => collectAndAddPairs(100));
  byId<HTMLButtonElement>('add500').addEventListener('click', () => collectAndAddPairs(500));
  byId<HTMLButtonElement>('add1000').addEventListener('click', () => collectAndAddPairs(1000));
  byId<HTMLButtonElement>('clearPairs').addEventListener('click', clearAllPairs);
  byId<HTMLButtonElement>('runAttack').addEventListener('click', runAttackOnCollectedPairs);
  byId<HTMLButtonElement>('runSweep').addEventListener('click', runSweep);
  byId<HTMLButtonElement>('applySeed').addEventListener('click', applySeed);
  byId<HTMLButtonElement>('revealK4').addEventListener('click', revealK4);

  const gotoSbox = document.getElementById('gotoSboxLink');
  if (gotoSbox) {
    gotoSbox.addEventListener('click', (e) => {
      e.preventDefault();
      switchTab('sbox');
    });
  }

  // Trace tab.
  const traceP1 = byId<HTMLInputElement>('traceP1');
  const traceP2 = byId<HTMLInputElement>('traceP2');
  traceP1.value = p1Input.value;
  traceP2.value = p2Input.value;
  traceP1.addEventListener('input', () => {
    p1Input.value = traceP1.value;
    onPlaintextChange();
  });
  traceP2.addEventListener('input', () => {
    p2Input.value = traceP2.value;
    onPlaintextChange();
  });
  byId<HTMLButtonElement>('traceStep').addEventListener('click', traceStepForward);
  byId<HTMLButtonElement>('traceShowAll').addEventListener('click', traceShowAll);
  byId<HTMLButtonElement>('traceReset').addEventListener('click', traceResetClick);

  // S-box swap.
  byId<HTMLButtonElement>('useWeakSbox').addEventListener('click', () => switchSbox('weak'));
  byId<HTMLButtonElement>('useStrongSbox').addEventListener('click', () => switchSbox('strong'));

  // DDT click coupling.
  byId<HTMLButtonElement>('useInAttack').addEventListener('click', useDDTCellInAttack);

  // Timeline.
  for (let i = 0; i < 5; i++) {
    const step = document.getElementById(`timelineStep${i}`);
    if (step) step.addEventListener('click', () => showTimelineContent(i));
  }
}

function switchTab(tabName: string) {
  document.querySelectorAll('.tab-content').forEach((tab) => {
    tab.classList.remove('active');
    tab.setAttribute('aria-hidden', 'true');
  });
  document.querySelectorAll('.tab-button').forEach((btn) => {
    btn.classList.remove('active');
    btn.setAttribute('aria-selected', 'false');
    btn.setAttribute('tabindex', '-1');
  });

  const selectedTab = document.getElementById(tabName);
  if (selectedTab) {
    selectedTab.classList.add('active');
    selectedTab.removeAttribute('aria-hidden');
  }
  const selectedButton = document.querySelector(`.tab-button[data-tab="${tabName}"]`);
  if (selectedButton) {
    selectedButton.classList.add('active');
    selectedButton.setAttribute('aria-selected', 'true');
    selectedButton.setAttribute('tabindex', '0');
  }
}

// ============================================================================
// Theme Toggle
// ============================================================================

function toggleTheme() {
  const html = document.documentElement;
  const currentTheme = html.getAttribute('data-theme') || 'dark';
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', newTheme);
  localStorage.setItem('theme', newTheme);
  updateThemeToggleUI();
}

function updateThemeToggleUI() {
  const html = document.documentElement;
  const currentTheme = html.getAttribute('data-theme') || 'dark';
  const button = document.getElementById('themeToggle') as HTMLButtonElement | null;
  if (!button) return;
  if (currentTheme === 'dark') {
    button.textContent = '🌙';
    button.setAttribute('aria-label', 'Switch to light mode');
  } else {
    button.textContent = '☀️';
    button.setAttribute('aria-label', 'Switch to dark mode');
  }
}

// ============================================================================
// Plaintext and output-diff controls
// ============================================================================

function onPlaintextChange() {
  const p1Input = byId<HTMLInputElement>('p1');
  const p2Input = byId<HTMLInputElement>('p2');
  const p1 = parseInt(p1Input.value || '0', 16) & 0xFF;
  const p2 = parseInt(p2Input.value || '0', 16) & 0xFF;
  const diff = (p1 ^ p2) & 0xFF;

  byId('plainDiff').textContent = `0x${hex2(diff)}`;
  state.selectedInputDiff = diff;

  // Mirror to trace inputs if present.
  const tp1 = document.getElementById('traceP1') as HTMLInputElement | null;
  const tp2 = document.getElementById('traceP2') as HTMLInputElement | null;
  if (tp1 && document.activeElement !== tp1) tp1.value = p1Input.value;
  if (tp2 && document.activeElement !== tp2) tp2.value = p2Input.value;

  rebuildTrace();
  renderTracePipeline();

  // Changing input diff invalidates current pairs.
  if (state.collectedPairs.length > 0) {
    state.collectedPairs = [];
    state.lastAttackResults = null;
    hideResults();
    updatePairStatus();
  }
}

function onOutDiffChange() {
  const v = parseInt(byId<HTMLInputElement>('outDiff').value || '0', 16) & 0xFF;
  state.selectedOutputDiff = v;
  byId('characteristicStatus').textContent =
    `Target Δ before last S-box: 0x${hex2(v)} (manually set).`;
}

function applySeed() {
  const v = parseInt(byId<HTMLInputElement>('seedInput').value || '0', 16) | 0;
  seedRng(v);
  state.collectedPairs = [];
  state.lastAttackResults = null;
  updatePairStatus();
  hideResults();
  byId('attackStatus').textContent =
    `Seed reset to 0x${(getRngSeed()).toString(16).toUpperCase()}. Collect pairs and run again.`;
}

function revealK4() {
  byId('hiddenK4').textContent = `0x${hex2(state.spnKey.subkeys[4])}`;
  byId<HTMLButtonElement>('revealK4').style.display = 'none';
}

function updateMasterKeyDisplay() {
  byId('masterKeyDisplay').textContent =
    `0x${state.masterKey.toString(16).toUpperCase().padStart(4, '0')}`;
}

function updateHiddenK4() {
  byId('hiddenK4').textContent = '••';
  const btn = document.getElementById('revealK4') as HTMLButtonElement | null;
  if (btn) btn.style.display = '';
}

function updatePairStatus() {
  const status = byId('pairStatus');
  const needed = 500 - state.collectedPairs.length;
  if (needed <= 0) {
    status.textContent = `${state.collectedPairs.length} pairs collected. Ready to attack!`;
    status.style.color = 'var(--success)';
  } else {
    status.textContent = `${state.collectedPairs.length} pairs collected. Need ${needed} more for reliable recovery.`;
    status.style.color = 'var(--text-secondary)';
  }
}

function collectAndAddPairs(count: number) {
  const pairs = collectPairs(state.spnKey, state.selectedInputDiff, count);
  state.collectedPairs.push(...pairs);
  updatePairStatus();
}

function clearAllPairs() {
  state.collectedPairs = [];
  state.lastAttackResults = null;
  updatePairStatus();
  hideResults();
}

function hideResults() {
  const r = document.getElementById('resultsSection');
  if (r) r.style.display = 'none';
}

// ============================================================================
// Empirical characteristic derivation
// ============================================================================

function deriveCharacteristicFromCipher() {
  const ranked = deriveCharacteristic(state.spnKey, state.selectedInputDiff, 4000);
  const best = ranked[0];
  state.selectedOutputDiff = best.outputDiff;
  byId<HTMLInputElement>('outDiff').value = hex2(best.outputDiff);

  const second = ranked[1];
  const ratio = second ? (best.count / Math.max(second.count, 1)).toFixed(2) : '∞';
  byId('characteristicStatus').innerHTML =
    `Sampled 4 000 pairs through 3 rounds. Peak Δ = ` +
    `<span class="mono">0x${hex2(best.outputDiff)}</span> with probability ` +
    `<strong>${(best.probability * 100).toFixed(2)}%</strong> ` +
    `(${ratio}× the runner-up). The attack will target this differential.`;
}

// ============================================================================
// Attack execution
// ============================================================================

function runAttackOnCollectedPairs() {
  if (state.collectedPairs.length === 0) {
    byId('attackStatus').textContent = 'Please collect some pairs first.';
    return;
  }

  byId('attackStatus').textContent = 'Running attack...';

  const results = attackLastRound(state.collectedPairs, state.selectedOutputDiff);
  state.lastAttackResults = results;
  state.lastOpCount = state.collectedPairs.length * 256 * 2; // 2 partial decryptions per pair per candidate

  showAttackResults(results);
  updateOpCounter();

  byId('attackStatus').textContent =
    `Attack complete. Top candidate: 0x${hex2(results[0].candidateKey)}. ` +
    `${state.lastOpCount.toLocaleString()} partial decryptions performed.`;
}

function showAttackResults(results: AttackResult[]) {
  const resultsSection = byId('resultsSection');
  resultsSection.style.display = 'block';

  const recoveredKey = identifyCorrectKey(results);
  const correctK4 = state.spnKey.subkeys[4];
  const correctKeyRank = getKeyRank(results, correctK4);
  const margin = results.length > 1 ? results[0].biasCount - results[1].biasCount : results[0].biasCount;

  byId('recoveredKey').textContent = `0x${hex2(recoveredKey)}`;
  byId('correctKeyRank').textContent = String(correctKeyRank);
  byId('topBias').textContent = String(results[0].biasCount);
  byId('biasMargin').textContent = String(margin);

  drawBiasChart(results);

  const success = byId('successMessage');
  const failure = byId('failureMessage');
  if (recoveredKey === correctK4) {
    success.style.display = 'block';
    failure.style.display = 'none';
    byId('actualKey').textContent = `0x${hex2(correctK4)}`;
    byId('recoveredKeyText').textContent = `0x${hex2(recoveredKey)}`;
  } else {
    success.style.display = 'none';
    failure.style.display = 'block';
    byId('failureExplain').innerHTML =
      `Top candidate 0x${hex2(recoveredKey)} ≠ actual K₄ 0x${hex2(correctK4)} ` +
      `(rank ${correctKeyRank}). The chosen differential 0x${hex2(state.selectedInputDiff)}→` +
      `0x${hex2(state.selectedOutputDiff)} may be low-probability, or you need more pairs. ` +
      `Try <em>Derive empirically</em> in Step 1½, or add 500–1000 more pairs.`;
  }
}

function updateOpCounter() {
  byId('opCount').textContent = state.lastOpCount.toLocaleString();
  // Toy "differential cost" = candidate count × pairs.
  byId('diffToy').textContent =
    `256 × ${state.collectedPairs.length} = ${state.lastOpCount.toLocaleString()}`;
}

// ============================================================================
// Learning-curve sweep
// ============================================================================

function runSweep() {
  const sizes = [50, 100, 200, 500, 1000, 2000];
  const correctK4 = state.spnKey.subkeys[4];
  const points: { n: number; rank: number; bias: number }[] = [];

  // Use the seeded RNG so the sweep is deterministic given the current seed.
  for (const n of sizes) {
    const pairs = collectPairs(state.spnKey, state.selectedInputDiff, n);
    const results = attackLastRound(pairs, state.selectedOutputDiff);
    const rank = getKeyRank(results, correctK4);
    points.push({ n, rank, bias: results[0].biasCount });
  }

  // Make sure the results section is visible to display the chart.
  byId('resultsSection').style.display = 'block';
  drawSweepChart(points);

  byId('attackStatus').textContent =
    `Sweep complete. Ranks: ${points.map((p) => `${p.n}→${p.rank}`).join(', ')}`;
}

function drawSweepChart(points: { n: number; rank: number }[]) {
  const canvas = document.getElementById('sweepChart') as HTMLCanvasElement | null;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const width = canvas.width;
  const height = canvas.height;
  const padding = 40;
  const graphWidth = width - padding * 2;
  const graphHeight = height - padding * 2;

  ctx.fillStyle = 'rgba(15, 15, 30, 0.8)';
  ctx.fillRect(0, 0, width, height);

  ctx.strokeStyle = 'rgba(42, 42, 62, 0.5)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 5; i++) {
    const y = padding + (graphHeight / 5) * i;
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(width - padding, y);
    ctx.stroke();
  }

  const maxRank = Math.max(...points.map((p) => p.rank), 10);
  const dx = graphWidth / Math.max(points.length - 1, 1);

  ctx.strokeStyle = 'rgba(0, 217, 255, 0.9)';
  ctx.lineWidth = 2;
  ctx.beginPath();
  points.forEach((pt, i) => {
    const x = padding + dx * i;
    const y = padding + graphHeight * (pt.rank - 1) / Math.max(maxRank - 1, 1);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  ctx.fillStyle = 'rgba(0, 216, 111, 0.9)';
  points.forEach((pt, i) => {
    const x = padding + dx * i;
    const y = padding + graphHeight * (pt.rank - 1) / Math.max(maxRank - 1, 1);
    ctx.beginPath();
    ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fill();
  });

  ctx.fillStyle = 'rgba(224, 224, 243, 0.8)';
  ctx.font = '12px monospace';
  ctx.textAlign = 'center';
  points.forEach((pt, i) => {
    const x = padding + dx * i;
    ctx.fillText(`${pt.n}`, x, height - padding + 18);
    const y = padding + graphHeight * (pt.rank - 1) / Math.max(maxRank - 1, 1);
    ctx.fillText(`#${pt.rank}`, x, y - 8);
  });

  ctx.strokeStyle = 'rgba(160, 160, 176, 0.5)';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(padding, padding);
  ctx.lineTo(padding, height - padding);
  ctx.lineTo(width - padding, height - padding);
  ctx.stroke();

  ctx.fillStyle = 'rgba(160, 160, 176, 0.7)';
  ctx.font = '11px sans-serif';
  ctx.textAlign = 'left';
  ctx.fillText('rank of correct K₄ (1 = perfect)', padding, padding - 10);
  ctx.textAlign = 'center';
  ctx.fillText('pairs collected', width / 2, height - 6);
}

// ============================================================================
// Bias chart (top-10 candidates)
// ============================================================================

function drawBiasChart(results: AttackResult[]) {
  const canvas = document.getElementById('biasChart') as HTMLCanvasElement | null;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const top10 = results.slice(0, 10);
  const width = canvas.width;
  const height = canvas.height;
  const padding = 40;
  const graphWidth = width - padding * 2;
  const graphHeight = height - padding * 2;

  ctx.fillStyle = 'rgba(15, 15, 30, 0.8)';
  ctx.fillRect(0, 0, width, height);

  ctx.strokeStyle = 'rgba(42, 42, 62, 0.5)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 5; i++) {
    const y = padding + (graphHeight / 5) * i;
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(width - padding, y);
    ctx.stroke();
  }

  const maxBias = Math.max(...top10.map((r) => r.biasCount), 1);
  const barWidth = graphWidth / top10.length;
  top10.forEach((result, index) => {
    const barHeight = (result.biasCount / maxBias) * graphHeight;
    const x = padding + index * barWidth + barWidth * 0.1;
    const y = padding + graphHeight - barHeight;

    const isCorrect = result.candidateKey === state.spnKey.subkeys[4];
    ctx.fillStyle = isCorrect ? 'rgba(0, 216, 111, 0.85)' : 'rgba(0, 217, 255, 0.55)';
    ctx.fillRect(x, y, barWidth * 0.8, barHeight);

    ctx.fillStyle = 'rgba(224, 224, 243, 0.8)';
    ctx.font = '12px monospace';
    ctx.textAlign = 'center';
    ctx.fillText(hex2(result.candidateKey), x + barWidth * 0.4, height - padding + 18);
    ctx.fillText(result.biasCount.toString(), x + barWidth * 0.4, y - 5);
  });

  ctx.strokeStyle = 'rgba(160, 160, 176, 0.5)';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(padding, height - padding);
  ctx.lineTo(width - padding, height - padding);
  ctx.lineTo(width - padding, padding);
  ctx.stroke();

  ctx.fillStyle = 'rgba(160, 160, 176, 0.7)';
  ctx.font = '12px sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('Candidate K₄ (hex) — correct key shown in green', width / 2, height - 6);
}

// ============================================================================
// S-box swap
// ============================================================================

function switchSbox(name: SboxName) {
  if (getActiveSboxName() === name) return;
  setSbox(name);

  // The cipher changed, so everything stale must reset.
  state.spnKey = generateKey(state.masterKey);
  state.collectedPairs = [];
  state.lastAttackResults = null;

  syncSboxToggleUI();
  updateActiveSboxLabel();
  updateHiddenK4();
  renderDDT();
  renderSBox();
  hideResults();
  updatePairStatus();
  rebuildTrace();
  renderTracePipeline();

  byId('attackStatus').textContent =
    `S-box swapped to "${name}". Cipher reset; collect new pairs and run the attack to see ` +
    `whether the bias still separates from noise.`;
}

function syncSboxToggleUI() {
  const weak = byId<HTMLButtonElement>('useWeakSbox');
  const strong = byId<HTMLButtonElement>('useStrongSbox');
  const active = getActiveSboxName();
  weak.classList.toggle('active', active === 'weak');
  weak.setAttribute('aria-checked', String(active === 'weak'));
  strong.classList.toggle('active', active === 'strong');
  strong.setAttribute('aria-checked', String(active === 'strong'));
}

function updateActiveSboxLabel() {
  const label = byId('activeSboxLabel');
  label.textContent = getActiveSboxName() === 'weak' ? 'Weak (toy)' : 'Strong (PRESENT)';
}

// ============================================================================
// S-box visualization
// ============================================================================

function renderSBox() {
  const sbox = getSbox() as number[];
  const container = byId('sboxGrid');
  container.innerHTML = '';

  for (let i = 0; i < 16; i++) {
    const cell = document.createElement('div');
    cell.className = 'sbox-cell';
    cell.setAttribute('role', 'gridcell');
    cell.setAttribute(
      'aria-label',
      `S-box input ${i.toString(16).toUpperCase()}: output ${sbox[i].toString(16).toUpperCase()}`,
    );
    const output = sbox[i];
    const intensity = (output / 15) * 100;
    cell.style.background = `hsl(200, 70%, ${50 - intensity * 0.3}%)`;
    cell.textContent = output.toString(16).toUpperCase();
    container.appendChild(cell);
  }

  const ddt = computeDDT(sbox);
  const props = verifyDDTProperties(ddt);
  const contentDiv = byId('sboxAssessmentContent');
  contentDiv.innerHTML = `
    <p><strong>Max non-trivial DDT entry:</strong> ${props.maxDDTValue} (out of 16)</p>
    <p><strong>Assessment:</strong> ${
      props.isWeak
        ? 'Weak — this S-box leaks a high-probability differential the attack can exploit.'
        : 'Strong — the differential probability ceiling is ≤ 4/16, the lower bound for a 4-bit permutation.'
    }</p>
    <p><strong>Per-round differential probability ceiling:</strong> ≤ ${(props.maxDDTValue / 16).toFixed(2)} per active S-box.</p>
  `;
}

// ============================================================================
// DDT visualization
// ============================================================================

let lastDDTClick: { inputDiff: number; outputDiff: number; count: number } | null = null;

function renderDDT() {
  const sbox = getSbox() as number[];
  const ddt = computeDDT(sbox);
  const container = byId('ddtGrid');
  container.innerHTML = '';

  for (let inputDiff = 0; inputDiff < 16; inputDiff++) {
    for (let outputDiff = 0; outputDiff < 16; outputDiff++) {
      const count = ddt[inputDiff][outputDiff];

      const cell = document.createElement('div');
      cell.className = 'ddt-cell';
      cell.setAttribute('role', 'gridcell');
      cell.setAttribute(
        'aria-label',
        `Input diff 0x${inputDiff.toString(16).toUpperCase()}, output diff 0x${outputDiff
          .toString(16)
          .toUpperCase()}: count ${count}`,
      );
      cell.setAttribute('tabindex', '0');

      if (count === 0) cell.classList.add('ddt-0');
      else if (count <= 2) cell.classList.add('ddt-1-2');
      else if (count <= 4) cell.classList.add('ddt-3-4');
      else if (count <= 6) cell.classList.add('ddt-5-6');
      else cell.classList.add('ddt-7-plus');

      cell.textContent = count > 0 ? count.toString() : '·';
      cell.addEventListener('click', () => showDDTInfo(inputDiff, outputDiff, count));
      container.appendChild(cell);
    }
  }
  // Clear previously selected info, since the new DDT may have different counts.
  const infoDiv = document.getElementById('ddtClickInfo');
  if (infoDiv) infoDiv.style.display = 'none';
  lastDDTClick = null;
}

function showDDTInfo(inputDiff: number, outputDiff: number, count: number) {
  const infoDiv = byId('ddtClickInfo');
  infoDiv.style.display = 'block';

  byId('ddtInputDiff').textContent = `0x${inputDiff.toString(16).toUpperCase()}`;
  byId('ddtOutputDiff').textContent = `0x${outputDiff.toString(16).toUpperCase()}`;
  byId('ddtCount').textContent = count.toString();
  byId('ddtProb').textContent = `${((count / 16) * 100).toFixed(1)}%`;

  const exploitable = byId('ddtExploitable');
  const useBtn = byId<HTMLButtonElement>('useInAttack');
  if (inputDiff === 0) {
    exploitable.textContent = 'Trivial case (zero input difference).';
    exploitable.style.color = 'var(--text-secondary)';
    useBtn.style.display = 'none';
  } else if (count > 4) {
    exploitable.textContent =
      `Exploitable: probability ${((count / 16) * 100).toFixed(1)}% is unusually high (good S-boxes peak at 4/16).`;
    exploitable.style.color = 'var(--warning)';
    useBtn.style.display = '';
  } else if (count > 0) {
    exploitable.textContent = 'Usable but low-probability; the attack needs more pairs.';
    exploitable.style.color = 'var(--accent-tertiary)';
    useBtn.style.display = '';
  } else {
    exploitable.textContent = 'Impossible differential — this transition never occurs.';
    exploitable.style.color = 'var(--text-secondary)';
    useBtn.style.display = 'none';
  }

  lastDDTClick = { inputDiff, outputDiff, count };
}

function useDDTCellInAttack() {
  if (!lastDDTClick) return;
  // The DDT is over a single 4-bit S-box. Map its input/output diffs onto
  // the byte by placing them in the low nibble (so the high-nibble S-box
  // sees Δ=0 and the low-nibble S-box sees the chosen Δ).
  const byteIn = lastDDTClick.inputDiff & 0xF;
  const byteOut = lastDDTClick.outputDiff & 0xF;

  // Pick P1 = 0x00, P2 = byteIn so that P1 ⊕ P2 = byteIn.
  byId<HTMLInputElement>('p1').value = '00';
  byId<HTMLInputElement>('p2').value = hex2(byteIn);
  byId<HTMLInputElement>('outDiff').value = hex2(byteOut);
  state.selectedInputDiff = byteIn;
  state.selectedOutputDiff = byteOut;

  onPlaintextChange();
  onOutDiffChange();
  byId('characteristicStatus').innerHTML =
    `Seeded from DDT click: ΔIn=0x${hex2(byteIn)}, ΔOut=0x${hex2(byteOut)}. ` +
    `Note: this is a <em>single-round</em> differential; for 4 rounds you'll want to ` +
    `<em>derive empirically</em> to find the actual peak the attack should target.`;
  switchTab('attack');
}

// ============================================================================
// Differential trace
// ============================================================================

function rebuildTrace() {
  const p1 = parseInt(byId<HTMLInputElement>('p1').value || '0', 16) & 0xFF;
  const p2 = parseInt(byId<HTMLInputElement>('p2').value || '0', 16) & 0xFF;
  state.traceStages = traceEncryption(p1, p2, state.spnKey);
  state.traceVisibleCount = Math.min(state.traceVisibleCount, state.traceStages.length);
  if (state.traceVisibleCount < 1) state.traceVisibleCount = 1;
}

function renderTracePipeline() {
  const container = byId('tracePipeline');
  container.innerHTML = '';

  state.traceStages.forEach((stage, idx) => {
    const prev = idx > 0 ? state.traceStages[idx - 1] : null;
    const diffChanged = prev !== null && prev.diff !== stage.diff;
    const visible = idx < state.traceVisibleCount;

    const row = document.createElement('div');
    row.className = `trace-row kind-${stage.kind}` + (visible ? '' : ' hidden') +
      (diffChanged ? ' diff-changed' : '');
    row.setAttribute('role', 'listitem');

    // Stage label + tag.
    const labelCell = document.createElement('div');
    labelCell.className = 'stage-label';
    labelCell.textContent = stage.label;
    row.appendChild(labelCell);

    const tagCell = document.createElement('div');
    const tag = document.createElement('span');
    tag.className = `stage-tag ${stage.kind}`;
    tag.textContent = stage.kind === 'xor-key' ? 'XOR-K'
      : stage.kind === 'sbox' ? 'S-box'
      : stage.kind === 'permute' ? 'Permute' : 'Input';
    tagCell.appendChild(tag);
    row.appendChild(tagCell);

    // State pair.
    const statePair = document.createElement('div');
    statePair.className = 'state-pair';
    statePair.innerHTML = `P₁=<span class="mono">0x${hex2(stage.state1)}</span>` +
      ` &nbsp; P₂=<span class="mono">0x${hex2(stage.state2)}</span>`;
    row.appendChild(statePair);

    // Diff display: bits + numeric value + preservation marker.
    const diffRow = document.createElement('div');
    diffRow.className = 'diff-row';
    const bits = document.createElement('div');
    bits.className = 'diff-bits';
    for (let b = 7; b >= 0; b--) {
      const bit = (stage.diff >> b) & 1;
      const dot = document.createElement('div');
      dot.className = `bit ${bit ? 'active' : 'inactive'}`;
      dot.title = `bit ${b}: ${bit}`;
      bits.appendChild(dot);
    }
    diffRow.appendChild(bits);
    const val = document.createElement('span');
    val.className = 'diff-value';
    val.textContent = `Δ=0x${hex2(stage.diff)}`;
    diffRow.appendChild(val);
    if (prev) {
      const marker = document.createElement('span');
      if (stage.diff === prev.diff) {
        marker.className = 'diff-preservation-marker';
        marker.textContent = stage.kind === 'xor-key' ? '✓ Δ preserved (XOR rule)' : '= unchanged';
      } else {
        marker.className = 'diff-changed-marker';
        marker.textContent = '↯ Δ changed';
      }
      diffRow.appendChild(marker);
    }
    row.appendChild(diffRow);

    container.appendChild(row);
  });

  byId('traceStatus').textContent =
    `Stage ${state.traceVisibleCount - 1} of ${state.traceStages.length - 1} ` +
    `(${state.traceVisibleCount}/${state.traceStages.length} visible).`;
}

function traceStepForward() {
  if (state.traceVisibleCount < state.traceStages.length) {
    state.traceVisibleCount++;
    renderTracePipeline();
  }
}

function traceShowAll() {
  state.traceVisibleCount = state.traceStages.length;
  renderTracePipeline();
}

function traceResetClick() {
  state.traceVisibleCount = 1;
  renderTracePipeline();
}

// ============================================================================
// Timeline
// ============================================================================

const timelineContent = [
  {
    title: '1970s — NSA\'s Classified Secret',
    content: `
      <p>In the 1970s, the NSA recognized that the DES S-boxes had hidden vulnerabilities to differential attacks—techniques the NSA knew about but kept classified. The S-boxes were hardened specifically to resist differential cryptanalysis, though this fact remained secret.</p>
      <p>The design decisions appeared arbitrary to public cryptanalysts for nearly two decades, but they were actually countermeasures against attacks that wouldn't be discovered publicly until the 1990s.</p>
    `,
  },
  {
    title: '1990 — Biham & Shamir\'s Discovery',
    content: `
      <p>On June 18, 1990, Eli Biham and Adi Shamir published their paper introducing differential cryptanalysis to the world:</p>
      <p><strong>"Differential Cryptanalysis of DES-like Cryptosystems"</strong> (Journal of Cryptology, 1991)</p>
      <p>This was a watershed moment. Suddenly, the NSA's decades of secret knowledge became public. The 16-round DES, which was thought to be secure for another 20 years, could theoretically be broken in 2^48 operations instead of the full 2^56 brute force.</p>
    `,
  },
  {
    title: '1993 — Coppersmith Confirms NSA Foresight',
    content: `
      <p>Don Coppersmith of IBM published a paper revealing that the NSA had classified differential cryptanalysis in the 1970s and deliberately hardened DES against it.</p>
      <p>The NSA's foresight—building defenses against attacks that existed only in secret—became public validation. The DES S-boxes were not weak; they were prescient.</p>
      <p>This vindicated NSA design decisions that had seemed arbitrary in the 1970s.</p>
    `,
  },
  {
    title: '1998 — Biham Designs Serpent',
    content: `
      <p>As AES competition began, Eli Biham co-designed Serpent (with Ross Anderson and Lars Knudsen), specifically engineered to defeat differential cryptanalysis and other advanced attacks.</p>
      <p>Serpent's hallmark features:</p>
      <ul style="margin-left: 1rem; margin-top: 0.5rem;">
        <li>32 rounds (vs. AES's 10/12/14, DES's 16) — overkill against differential attacks</li>
        <li>Conservative S-box design — max DDT entry ≤ 4</li>
        <li>Linear transformation for perfect diffusion</li>
      </ul>
      <p>Serpent didn't win the AES competition (Rijndael did), but its conservative design philosophy is widely respected.</p>
    `,
  },
  {
    title: 'Today — The Legacy',
    content: `
      <p>Differential cryptanalysis remains one of the most important applications of statistical methods to cryptanalysis. Every modern block cipher is designed with differential attacks in mind.</p>
      <p><strong>Key lessons:</strong></p>
      <ul style="margin-left: 1rem; margin-top: 0.5rem;">
        <li>Secrets can be kept for decades (NSA knew differential cryptanalysis before DES was public)</li>
        <li>Mathematical insight outlasts secrecy — Biham & Shamir's work is permanent</li>
        <li>Good cipher design survives attacks: DES, with its NSA-hardened S-boxes, resisted the Biham-Shamir attack that should have broken it</li>
        <li>Defense is possible but requires foresight: Serpent's ultra-conservative design ensures safety</li>
      </ul>
    `,
  },
];

function showTimelineContent(step: number) {
  for (let i = 0; i < 5; i++) {
    const btn = document.getElementById(`timelineStep${i}`);
    if (btn) btn.classList.toggle('active', i === step);
  }
  const contentDiv = document.querySelector('.timeline-content') as HTMLElement | null;
  if (!contentDiv) return;
  const content = timelineContent[step];
  contentDiv.innerHTML = `<h4>${content.title}</h4>${content.content}`;
}

// ============================================================================
// Utilities
// ============================================================================

function hex2(n: number): string {
  return (n & 0xFF).toString(16).toUpperCase().padStart(2, '0');
}

// ============================================================================
// Boot
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  initializeApp();
  onPlaintextChange();
});
