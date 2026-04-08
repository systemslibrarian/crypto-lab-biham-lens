/**
 * Main UI application for biham-lens
 * 
 * Based on "Differential Cryptanalysis of DES-like Cryptosystems"
 * by Eli Biham and Adi Shamir, Journal of Cryptology, 1991
 */

import { generateKey, encrypt } from './crypto/spn.js';
import type { SPNKey } from './crypto/spn.js';
import { computeDDT, verifyDDTProperties } from './crypto/ddt.js';
import { getSbox } from './crypto/sbox.js';
import { collectPairs, attackLastRound, identifyCorrectKey, getKeyRank } from './crypto/attack.js';
import type { AttackResult } from './crypto/attack.js';

// ============================================================================
// Application State
// ============================================================================

interface AppState {
  // Cipher
  masterKey: number;
  spnKey: SPNKey;
  
  // Attack
  collectedPairs: Array<{ c1: number; c2: number }>;
  lastAttackResults: AttackResult[] | null;
  selectedInputDiff: number;
  selectedOutputDiff: number;
}

const state: AppState = {
  masterKey: 0x5A69,
  spnKey: null as any,
  collectedPairs: [],
  lastAttackResults: null,
  selectedInputDiff: 0x01,
  selectedOutputDiff: 0x0B,
};

// ============================================================================
// Initialization
// ============================================================================

function initializeApp() {
  state.spnKey = generateKey(state.masterKey);
  setupEventListeners();
  renderDDT();
  renderSBox();
  updatePairStatus();
}

// ============================================================================
// Tab Management
// ============================================================================

function setupEventListeners() {
  // Theme toggle
  const themeToggle = document.getElementById('themeToggle') as HTMLButtonElement;
  if (themeToggle) {
    updateThemeToggleUI();
    themeToggle.addEventListener('click', toggleTheme);
  }

  // Tab buttons
  const tabButtons = document.querySelectorAll('.tab-button');
  tabButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const tabName = button.getAttribute('data-tab')!;
      switchTab(tabName);
    });
  });

  // Keyboard navigation for tabs (WAI-ARIA tabs pattern)
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

  // Attack tab controls
  const p1Input = document.getElementById('p1') as HTMLInputElement;
  const p2Input = document.getElementById('p2') as HTMLInputElement;
  const add100 = document.getElementById('add100') as HTMLButtonElement;
  const add500 = document.getElementById('add500') as HTMLButtonElement;
  const add1000 = document.getElementById('add1000') as HTMLButtonElement;
  const clearPairs = document.getElementById('clearPairs') as HTMLButtonElement;
  const runAttack = document.getElementById('runAttack') as HTMLButtonElement;

  p1Input.addEventListener('change', updatePlaintextDisplay);
  p2Input.addEventListener('change', updatePlaintextDisplay);
  add100.addEventListener('click', () => collectAndAddPairs(100));
  add500.addEventListener('click', () => collectAndAddPairs(500));
  add1000.addEventListener('click', () => collectAndAddPairs(1000));
  clearPairs.addEventListener('click', clearAllPairs);
  runAttack.addEventListener('click', runAttackOnCollectedPairs);

  // Timeline steps
  for (let i = 0; i < 5; i++) {
    const step = document.getElementById(`timelineStep${i}`) as HTMLButtonElement;
    if (step) {
      step.addEventListener('click', () => showTimelineContent(i));
    }
  }

  // Trace controls
  const traceNext = document.getElementById('traceNext') as HTMLButtonElement;
  const traceReset = document.getElementById('traceReset') as HTMLButtonElement;
  if (traceNext) traceNext.addEventListener('click', traceNextStage);
  if (traceReset) traceReset.addEventListener('click', resetTrace);
}

function switchTab(tabName: string) {
  // Hide all tabs and update ARIA
  const tabs = document.querySelectorAll('.tab-content');
  tabs.forEach((tab) => {
    tab.classList.remove('active');
    tab.setAttribute('aria-hidden', 'true');
  });

  // Deactivate all buttons and update ARIA
  const buttons = document.querySelectorAll('.tab-button');
  buttons.forEach((btn) => {
    btn.classList.remove('active');
    btn.setAttribute('aria-selected', 'false');
    btn.setAttribute('tabindex', '-1');
  });

  // Show selected tab
  const selectedTab = document.getElementById(tabName);
  if (selectedTab) {
    selectedTab.classList.add('active');
    selectedTab.removeAttribute('aria-hidden');
  }

  // Activate selected button
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
  const button = document.getElementById('themeToggle') as HTMLButtonElement;
  
  if (button) {
    if (currentTheme === 'dark') {
      button.textContent = '🌙';
      button.setAttribute('aria-label', 'Switch to light mode');
    } else {
      button.textContent = '☀️';
      button.setAttribute('aria-label', 'Switch to dark mode');
    }
  }
}

// ============================================================================
// Attack Tab - Plaintext Display
// ============================================================================

function updatePlaintextDisplay() {
  const p1Input = document.getElementById('p1') as HTMLInputElement;
  const p2Input = document.getElementById('p2') as HTMLInputElement;
  const diffDisplay = document.getElementById('plainDiff') as HTMLElement;

  let p1 = parseInt(p1Input.value || '0', 16);
  let p2 = parseInt(p2Input.value || '0', 16);

  const diff = (p1 ^ p2) & 0xFF;
  diffDisplay.textContent = `0x${diff.toString(16).toUpperCase().padStart(2, '0')}`;
  
  state.selectedInputDiff = diff;
}

function updatePairStatus() {
  const status = document.getElementById('pairStatus') as HTMLElement;
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
  const resultsSection = document.getElementById('resultsSection') as HTMLElement;
  if (resultsSection) {
    resultsSection.style.display = 'none';
  }
}

// ============================================================================
// Attack Execution
// ============================================================================

function runAttackOnCollectedPairs() {
  if (state.collectedPairs.length === 0) {
    alert('Please collect some pairs first!');
    return;
  }

  const status = document.getElementById('attackStatus') as HTMLElement;
  status.textContent = 'Running attack...';

  // Run the attack
  const results = attackLastRound(state.collectedPairs, state.selectedOutputDiff);
  state.lastAttackResults = results;

  // Display results
  const resultsSection = document.getElementById('resultsSection') as HTMLElement;
  resultsSection.style.display = 'block';

  const recoveredKey = identifyCorrectKey(results);
  const correctKeyRank = getKeyRank(results, state.spnKey.subkeys[3]);

  const recoveredKeyEl = document.getElementById('recoveredKey') as HTMLElement;
  const correctKeyRankEl = document.getElementById('correctKeyRank') as HTMLElement;
  const topBiasEl = document.getElementById('topBias') as HTMLElement;

  recoveredKeyEl.textContent = `0x${recoveredKey.toString(16).toUpperCase().padStart(2, '0')}`;
  correctKeyRankEl.textContent = correctKeyRank.toString();
  topBiasEl.textContent = results[0].biasCount.toString();

  // Show success if we recovered the correct key
  if (recoveredKey === state.spnKey.subkeys[3]) {
    const successMsg = document.getElementById('successMessage') as HTMLElement;
    const actualKeyEl = document.getElementById('actualKey') as HTMLElement;
    const recoveredKeyTextEl = document.getElementById('recoveredKeyText') as HTMLElement;

    successMsg.style.display = 'block';
    actualKeyEl.textContent = `0x${state.spnKey.subkeys[3].toString(16).toUpperCase().padStart(2, '0')}`;
    recoveredKeyTextEl.textContent = `0x${recoveredKey.toString(16).toUpperCase().padStart(2, '0')}`;
  }

  // Draw bias chart
  drawBiasChart(results);

  status.textContent = `Attack complete. Top candidate: 0x${recoveredKey.toString(16).toUpperCase().padStart(2, '0')}`;
}

// ============================================================================
// Visualization - Bias Chart
// ============================================================================

function drawBiasChart(results: AttackResult[]) {
  const canvas = document.getElementById('biasChart') as HTMLCanvasElement;
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  // Take top 10 candidates
  const top10 = results.slice(0, 10);
  const width = canvas.width;
  const height = canvas.height;
  const padding = 40;
  const graphWidth = width - padding * 2;
  const graphHeight = height - padding * 2;

  // Clear canvas
  ctx.fillStyle = 'rgba(15, 15, 30, 0.8)';
  ctx.fillRect(0, 0, width, height);

  // Draw grid
  ctx.strokeStyle = 'rgba(42, 42, 62, 0.5)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 5; i++) {
    const y = padding + (graphHeight / 5) * i;
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(width - padding, y);
    ctx.stroke();
  }

  // Find max bias
  const maxBias = Math.max(...top10.map((r) => r.biasCount));

  // Draw bars
  const barWidth = graphWidth / top10.length;
  top10.forEach((result, index) => {
    const barHeight = (result.biasCount / maxBias) * graphHeight;
    const x = padding + index * barWidth + barWidth * 0.1;
    const y = padding + graphHeight - barHeight;

    // Get correct key rank
    const isCorrect = result.candidateKey === state.spnKey.subkeys[3];
    ctx.fillStyle = isCorrect ? 'rgba(0, 216, 111, 0.8)' : 'rgba(0, 217, 255, 0.6)';
    ctx.fillRect(x, y, barWidth * 0.8, barHeight);

    // Draw label
    ctx.fillStyle = 'rgba(224, 224, 243, 0.7)';
    ctx.font = '12px monospace';
    ctx.textAlign = 'center';
    ctx.fillText(result.candidateKey.toString(16).padStart(2, '0'), x + barWidth * 0.4, height - padding + 20);

    // Draw count
    ctx.fillText(result.biasCount.toString(), x + barWidth * 0.4, y - 5);
  });

  // Draw axes
  ctx.strokeStyle = 'rgba(160, 160, 176, 0.5)';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(padding, height - padding);
  ctx.lineTo(width - padding, height - padding);
  ctx.lineTo(width - padding, padding);
  ctx.stroke();

  // Labels
  ctx.fillStyle = 'rgba(160, 160, 176, 0.7)';
  ctx.font = '12px sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('Candidate Key (hex)', width / 2, height - 10);

  ctx.textAlign = 'right';
  ctx.fillText('Bias Count', 20, padding);
}

// ============================================================================
// S-box Visualization
// ============================================================================

function renderSBox() {
  const sbox = getSbox() as number[];
  const container = document.getElementById('sboxGrid') as HTMLElement;
  if (!container) return;

  container.innerHTML = ''; // Clear

  for (let i = 0; i < 16; i++) {
    const cell = document.createElement('div');
    cell.className = 'sbox-cell';
    cell.setAttribute('role', 'gridcell');
    cell.setAttribute('aria-label', `S-box input ${i.toString(16).toUpperCase()}: output ${sbox[i].toString(16).toUpperCase()}`);
    const output = sbox[i];
    const intensity = (output / 15) * 100;
    cell.style.background = `hsl(200, 70%, ${50 - intensity * 0.3}%)`;
    cell.textContent = output.toString(16).toUpperCase();
    container.appendChild(cell);
  }

  // S-box assessment
  const assessment = document.querySelector('#sbox .sbox-assessment') as HTMLElement;
  if (assessment) {
    const ddt = computeDDT(sbox);
    const props = verifyDDTProperties(ddt);
    const contentDiv = assessment.querySelector('#sboxAssessmentContent') as HTMLElement;
    if (contentDiv) {
      contentDiv.innerHTML = `
        <p><strong>Max DDT Entry:</strong> ${props.maxDDTValue} (out of 16)</p>
        <p><strong>Assessment:</strong> ${
          props.isWeak
            ? 'WEAK - This S-box has poor differential properties'
            : 'GOOD - This S-box resists differential attacks well'
        }</p>
        <p><strong>Differential Limit:</strong> Success probability ≤ ${(props.maxDDTValue / 16).toFixed(2)}</p>
      `;
    }
  }
}

// ============================================================================
// DDT Visualization
// ============================================================================

function renderDDT() {
  const sbox = getSbox() as number[];
  const ddt = computeDDT(sbox);
  const container = document.getElementById('ddtGrid') as HTMLElement;
  if (!container) return;

  container.innerHTML = ''; // Clear

  for (let inputDiff = 0; inputDiff < 16; inputDiff++) {
    for (let outputDiff = 0; outputDiff < 16; outputDiff++) {
      const count = ddt[inputDiff][outputDiff];

      const cell = document.createElement('div');
      cell.className = 'ddt-cell';
      cell.setAttribute('role', 'gridcell');
      cell.setAttribute('data-input', inputDiff.toString());
      cell.setAttribute('data-output', outputDiff.toString());
      cell.setAttribute('aria-label', `Input diff 0x${inputDiff.toString(16).toUpperCase()}, output diff 0x${outputDiff.toString(16).toUpperCase()}: count ${count}`);
      cell.setAttribute('tabindex', '0');

      // Color coding
      if (count === 0) {
        cell.classList.add('ddt-0');
      } else if (count <= 2) {
        cell.classList.add('ddt-1-2');
      } else if (count <= 4) {
        cell.classList.add('ddt-3-4');
      } else if (count <= 6) {
        cell.classList.add('ddt-5-6');
      } else {
        cell.classList.add('ddt-7-plus');
      }

      cell.textContent = count > 0 ? count.toString() : '·';

      cell.addEventListener('click', () => showDDTInfo(inputDiff, outputDiff, count));
      container.appendChild(cell);
    }
  }
}

function showDDTInfo(inputDiff: number, outputDiff: number, count: number) {
  const infoDiv = document.getElementById('ddtClickInfo') as HTMLElement;
  if (!infoDiv) return;

  infoDiv.style.display = 'block';

  document.getElementById('ddtInputDiff')!.textContent = `0x${inputDiff.toString(16).toUpperCase()}`;
  document.getElementById('ddtOutputDiff')!.textContent = `0x${outputDiff.toString(16).toUpperCase()}`;
  document.getElementById('ddtCount')!.textContent = count.toString();
  document.getElementById('ddtProb')!.textContent = `${((count / 16) * 100).toFixed(1)}%`;

  const exploitable = document.getElementById('ddtExploitable')!;
  if (inputDiff === 0) {
    exploitable.textContent = '✓ Trivial case (zero differential)';
    exploitable.style.color = 'var(--text-secondary)';
  } else if (count > 4) {
    exploitable.textContent =
      '⚠ This differential is exploitable (count > 4 is unusual for good S-boxes)';
    exploitable.style.color = 'var(--warning)';
  } else if (count > 0) {
    exploitable.textContent = '● This differential exists (usable in attacks)';
    exploitable.style.color = 'var(--accent-tertiary)';
  } else {
    exploitable.textContent = '✗ This differential is impossible';
    exploitable.style.color = 'var(--text-secondary)';
  }
}

// ============================================================================
// Differential Trace
// ============================================================================

let traceStep = 0;

function traceNextStage() {
  traceStep = (traceStep + 1) % 5;
  updateTraceDisplay();
}

function resetTrace() {
  traceStep = 0;
  updateTraceDisplay();
}

function updateTraceDisplay() {
  const p1Input = document.getElementById('p1') as HTMLInputElement;
  const p2Input = document.getElementById('p2') as HTMLInputElement;

  let p1 = parseInt(p1Input.value || '0', 16);
  let p2 = parseInt(p2Input.value || '0', 16);

  const diff = (p1 ^ p2) & 0xFF;

  // Update stage marker
  const stageNames = ['Input difference', 'After S-box (Round 1)', 'After Permutation (Round 1)', 'After S-box (Round 2)', 'After Permutation (Round 2)'];
  const stageStatus = document.getElementById('traceStage') as HTMLElement;
  if (stageStatus) {
    stageStatus.textContent = stageNames[traceStep] || 'Complete';
  }

  // Show appropriate information
  for (let i = 0; i < 5; i++) {
    const stageBits = document.getElementById(`stageBits${i}`) as HTMLElement;
    const stageValue = document.getElementById(`stageValue${i}`) as HTMLElement;
    const stageActive = document.getElementById(`stageActive${i}`) as HTMLElement;
    const stageProbability = document.getElementById(`stageProbability${i}`) as HTMLElement;

    if (i <= traceStep) {
      // Show this stage
      const currentDiff = i === 0 ? diff : diff; // Simplified for demo
      renderBitDisplay(stageBits, currentDiff);
      stageValue.textContent = `0x${currentDiff.toString(16).toUpperCase().padStart(2, '0')}`;
      stageActive.textContent = popcount(currentDiff).toString();
      stageProbability.textContent = stageNames[i].includes('Probability') ? '?' : '1.00';
    } else {
      // Hide future stages
      stageBits.innerHTML = '';
      stageValue.textContent = '?';
      stageActive.textContent = '—';
      stageProbability.textContent = '—';
    }
  }
}

function renderBitDisplay(container: HTMLElement, byte: number) {
  container.innerHTML = '';
  for (let i = 7; i >= 0; i--) {
    const bit = (byte >> i) & 1;
    const bitEl = document.createElement('div');
    bitEl.className = `bit ${bit ? 'active' : 'inactive'}`;
    bitEl.title = `Bit ${i}: ${bit}`;
    container.appendChild(bitEl);
  }
}

function popcount(x: number): number {
  let count = 0;
  while (x) {
    count += x & 1;
    x >>= 1;
  }
  return count;
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
  // Update active step
  for (let i = 0; i < 5; i++) {
    const btn = document.getElementById(`timelineStep${i}`) as HTMLElement;
    if (i === step) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  }

  // Update content
  const contentDiv = document.querySelector('.timeline-content') as HTMLElement;
  const content = timelineContent[step];
  contentDiv.innerHTML = `<h4>${content.title}</h4>${content.content}`;
}

// Show first timeline content on load
document.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => {
    showTimelineContent(0);
  }, 100);
});

// ============================================================================
// Initialization on DOM Ready
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  initializeApp();
  updatePlaintextDisplay();
  updateTraceDisplay();
});
