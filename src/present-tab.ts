import {
  SBOX,
  permutation,
  hex,
  parseHex,
  keySchedule80,
  trace80,
  encrypt80,
  decrypt80,
} from './crypto/present/present.js';
import { conditions123, pLayerSpread } from './crypto/present/analysis.js';
import { setSbox, getSbox, getActiveSboxName } from './crypto/sbox.js';
import type { UnwindRequest } from './crypto/present/worker.js';
const VECTORS = [
  [0n, 0n, 0x5579c1387b228445n],
  [0n, (1n << 80n) - 1n, 0xe72c46c0f5945049n],
  [(1n << 64n) - 1n, 0n, 0xa112ffc72f68417bn],
  [(1n << 64n) - 1n, (1n << 80n) - 1n, 0x3333dcd3213210d2n],
] as const;
const labels = [
  'Same box, full size',
  'The bit shuffle',
  'Key schedule',
  'Encrypt',
  'Why the small box works',
  'A round key exposes the key',
];
export function initPresentTab() {
  const panel = document.getElementById('present')!;
  panel.innerHTML = `<div class="tab-inner present-inner"><h2>PRESENT-80: from a small S-box to a full cipher</h2><p>The 'strong' S-box you can switch on in the S-box tab was not invented for this toy. It is the only S-box of PRESENT, a real 64-bit block cipher built for RFID tags and other tiny chips, and standardised in ISO/IEC 29192-2. PRESENT uses that one 4-bit box sixteen times per round, a bit shuffle instead of any arithmetic, and 31 rounds. This tab runs the real cipher and shows why one small S-box is enough.</p>
 <p class="present-scope">Teaching implementation, not production cryptography. PRESENT-80 only; the key-schedule exercise assumes K32 is already known and is not an attack that obtains it.</p>
 <div class="present-controls"><label>80-bit key (20 hex digits)<input id="present-key" type="text" value="00112233445566778899" autocomplete="off" title="Exactly 20 hex digits; no padding or truncation."></label><label>64-bit plaintext (16 hex digits)<input id="present-plaintext" type="text" value="0123456789ABCDEF" title="Exactly 16 hex digits."></label><button id="present-compute" class="btn btn-primary">Compute PRESENT trace</button><button id="present-zero" class="btn btn-secondary">Use published zero vector</button></div><p id="present-notice" role="status" aria-live="polite"></p>
 <nav class="present-steps" aria-label="PRESENT acts">${labels.map((x, i) => `<button class="present-step" data-act="${i + 1}" aria-pressed="${i === 0}">${i + 1}. ${x}</button>`).join('')}</nav>
 <section id="present-act1" class="present-act"><h3>1. Same box, full size</h3><p>A nibble is four bits. This one lookup replaces each of the sixteen nibbles in a block. The checks below enumerate all inputs and differences; they do not sample.</p><div id="present-sbox" class="present-cells"></div><div id="present-conditions" role="status" aria-live="polite"></div><details><summary>Inspect all difference counts and Walsh coefficients</summary><p>DDT rows are input differences, columns are output differences. The all-zero row is excluded from the maximum. Walsh entries sum +1 for matching masked parities and −1 for mismatches.</p><div id="present-ddt" class="present-scroll" tabindex="0" role="region" aria-label="PRESENT difference distribution table"></div><div id="present-walsh" class="present-scroll" tabindex="0" role="region" aria-label="PRESENT Walsh table"></div><p>Only conditions 1–3 from CHES 2007 §4.3 are asserted. The computed single-bit Walsh table contains zeros, so this lab does not assert condition 4 as printed.</p></details></section>
 <section id="present-act2" class="present-act" hidden><h3>2. The bit shuffle</h3><p>A permutation moves bits without changing their values. Number bits from 0 on the right to 63 on the left. Each output nibble receives bits from four different input nibbles.</p><details class="present-predict"><summary>Predict: where does bit 5 go?</summary><p id="present-bit5"></p></details><label>Highlight source S-box (0–15)<input id="present-box" type="number" min="0" max="15" value="1"></label><div id="present-wires"></div><div id="present-spread" role="status"></div><details open><summary>Exact bit map and S-box groups (text alternative)</summary><div id="present-map" class="present-map"></div></details></section>
 <section id="present-act3" class="present-act" hidden><h3>3. Step the 80-bit key register</h3><p>The round key takes the leftmost 64 bits. Then the register rotates left by 61, substitutes its leftmost nibble, and XORs the round number into bits 19…15. These reversible operations spread the master key through the rounds.</p><button id="present-key-prev" class="btn btn-secondary">Previous key step</button><button id="present-key-next" class="btn btn-secondary">Next key step</button><div id="present-key-step" role="status" aria-live="polite"></div><div id="present-keys" class="present-scroll" tabindex="0" role="region" aria-label="All 32 PRESENT round keys"></div></section>
 <section id="present-act4" class="present-act" hidden><h3>4. Encrypt through all 31 rounds</h3><p>Every row shows the actual state after adding the round key, substituting nibbles, and shuffling bits. After round 31 the cipher XORs K32 without another S-box or permutation.</p><div id="present-vectors" role="status"></div><p id="present-cipher" role="status" aria-live="polite"></p><div id="present-trace"></div></section>
 <section id="present-act5" class="present-act" hidden><h3>5. Why one four-bit box can spread a difference</h3><p>Choose a plaintext difference and count the active S-boxes in this particular pair. These observations are not a proof over all differential characteristics.</p><label>Plaintext XOR difference (16 hex digits)<input id="present-difference" type="text" value="0000000000000001"></label><button id="present-observe" class="btn btn-secondary">Trace this difference</button><div id="present-observed" role="status" aria-live="polite"></div><p>CHES 2007 Theorem 1 bounds every five-round characteristic by at least ten active S-boxes. That theorem is cited, not re-proved here. The computed S-box conditions and wiring checks are ingredients in its proof.</p><p id="present-bound"></p><p>The same S-box on 4 rounds of the toy already resisted 2,000 pairs.</p><p>A characteristic’s bound is not the total probability of a differential with many characteristics. Return to the <button id="present-toy" class="btn btn-secondary">Live Attack toy</button> to compare its smaller state and four rounds.</p></section>
 <section id="present-act6" class="present-act" hidden><h3>6. One round key is almost the whole key</h3><p>Suppose a last-round attack has already recovered K32. Its 64 bits leave only 16 bits of the final register unknown. Try all those suffixes, reverse the 31 key updates, and test each candidate against one known pair.</p><p>The main page derives K32 and the known pair from your visible key. The Worker receives only K32 and that pair; it does not receive the key. Only after the search does this page compare the surviving key with your input.</p><details class="present-predict"><summary>Predict: how many master keys will survive one pair?</summary><p>The search checks every suffix and reports the survivors. The default example has one, but the count is measured.</p></details><label>Known K32 (16 hex digits; editable)<input id="present-k32" type="text" title="Changing K32 retires the search. A mismatched value may have no surviving master key."></label><p id="present-pair"></p><button id="present-run" class="btn btn-primary">Run the 2¹⁶ unwind</button><button id="present-cancel" class="btn btn-secondary" disabled>Cancel unwind</button><p id="present-progress" role="status" aria-live="polite"></p><div id="present-fixture-checks" role="status"></div><div id="present-recovery" role="status" aria-live="polite"></div><div id="present-survivors"></div></section>
 <p>Sources: <a href="https://crypto.orange-labs.fr/papers/ches2007-450.pdf">Bogdanov et al., PRESENT, CHES 2007</a>, §3, §4.3, §5.1 and Appendix I. For AES key-schedule inversion see <a href="https://systemslibrarian.github.io/crypto-lab-glass-box/">Glass Box</a>. PRESENT-128 and a characteristic-search engine are not implemented here.</p></div>`;
  const el = <T extends HTMLElement = HTMLElement>(id: string) =>
      document.getElementById('present-' + id) as T,
    val = (id: string) => el<HTMLInputElement>(id).value,
    put = (id: string, s: string) => {
      el(id).textContent = s;
    };
  let worker: Worker | null = null,
    epoch = 0,
    tried = 0,
    step = 0,
    record:
      | {
          key: bigint;
          plaintext: bigint;
          ciphertext: bigint;
          keys: ReturnType<typeof keySchedule80>;
        }
      | undefined;
  const analysis = conditions123(),
    spread = pLayerSpread(),
    old = getActiveSboxName();
  setSbox('strong');
  const same = SBOX.every((x, i) => x === getSbox()[i]);
  setSbox(old);
  function checks(target: string, roundTrip?: boolean) {
    el(target).replaceChildren();
    const facts: [string, boolean][] = [
      [
        'published vectors',
        VECTORS.every(([p, k, c]) => encrypt80(p, k) === c && decrypt80(c, k) === p),
      ],
      ['S-box equals toy strong box', same],
      ['condition 1: max nonzero DDT ≤ 4', analysis.c1],
      ['condition 2: single-bit differences cannot stay single-bit', analysis.c2],
      ['condition 3: max |Walsh| ≤ 8', analysis.c3],
      ['observation 1: four distinct source boxes in the same group', spread.observation1],
      [
        'observation 3: four distinct destination boxes in four distinct groups',
        spread.observation3,
      ],
    ];
    if (roundTrip !== undefined) facts.push(['trace decrypts back', roundTrip]);
    for (const [name, ok] of facts) {
      const p = document.createElement('p');
      p.dataset.check = name;
      p.dataset.verdict = ok ? 'pass' : 'fail';
      p.className = ok ? 'present-ok' : 'present-alarm';
      p.textContent = `${ok ? '✓' : '⚠'} ${name}`;
      el(target).append(p);
    }
  }
  function table(values: number[][]) {
    return (
      '<table><thead><tr><th scope="col">mask / difference</th>' +
      Array.from({ length: 16 }, (_, i) => `<th scope="col">${i.toString(16)}</th>`).join('') +
      '</tr></thead><tbody>' +
      values
        .map(
          (row, i) =>
            `<tr><th scope="row">${i.toString(16)}</th>${row.map((x) => `<td>${x}</td>`).join('')}</tr>`,
        )
        .join('') +
      '</tbody></table>'
    );
  }
  el('sbox').innerHTML = SBOX.map(
    (x, i) => `<span>${i.toString(16).toUpperCase()} → ${x.toString(16).toUpperCase()}</span>`,
  ).join('');
  checks('conditions');
  put('bit5', `P(5) = ${permutation(5)}.`);
  el('ddt').innerHTML = table(analysis.ddt);
  el('walsh').innerHTML = table(analysis.walsh);
  put(
    'bound',
    `25 / 5 × 10 = ${(25 / 5) * 10} active boxes; ${(25 / 5) * 10} × log₂(${analysis.maxDdt}/16) = ${(25 / 5) * 10 * Math.log2(analysis.maxDdt / 16)}. Characteristic probability ≤ 2⁻¹⁰⁰ (under the paper’s characteristic model).`,
  );
  function drawWires() {
    const box = Number(val('box'));
    if (!Number.isInteger(box) || box < 0 || box > 15) {
      put('notice', 'Choose an S-box from 0 to 15.');
      return;
    }
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 660 240');
    svg.setAttribute('role', 'img');
    svg.setAttribute(
      'aria-label',
      `All 64 PRESENT wires, bit 63 on the left and bit 0 on the right on both rows; input before pLayer on top, output after pLayer below; highlighted source S-box ${box}. Exact mappings follow.`,
    );
    for (let i = 0; i < 64; i++) {
      const line = document.createElementNS(ns, 'line');
      line.setAttribute('x1', String(10 + (63 - i) * 10));
      line.setAttribute('x2', String(10 + (63 - permutation(i)) * 10));
      line.setAttribute('y1', '45');
      line.setAttribute('y2', '195');
      line.setAttribute('stroke', Math.floor(i / 4) === box ? '#ffd166' : '#85859d');
      line.setAttribute('stroke-width', Math.floor(i / 4) === box ? '3' : '1');
      svg.append(line);
    }
    const label = (text: string, x: number, y: number, anchor: string) => {
      const node = document.createElementNS(ns, 'text');
      node.setAttribute('x', String(x));
      node.setAttribute('y', String(y));
      node.setAttribute('text-anchor', anchor);
      node.setAttribute('fill', 'currentColor');
      node.textContent = text;
      svg.append(node);
    };
    label('input bit (before pLayer)', 330, 18, 'middle');
    label('output bit (after pLayer)', 330, 235, 'middle');
    for (const y of [36, 216]) {
      label('63', 10, y, 'start');
      label('0', 640, y, 'end');
    }
    el('wires').replaceChildren(svg);
    el('map').innerHTML = Array.from(
      { length: 16 },
      (_, b) =>
        `<p${b === box ? ' class="present-selected"' : ''}>S-box ${b}: ${Array.from({ length: 4 }, (_, j) => `${4 * b + j} → ${permutation(4 * b + j)}`).join('; ')}</p>`,
    ).join('');
    put(
      'spread',
      `Each source box sends its four bits to ${spread.output.join(', ')} distinct boxes respectively, in four distinct groups. Each destination receives from ${spread.input.join(', ')} distinct boxes, all in the same group (group = box index div 4).`,
    );
  }
  function drawVectors() {
    el('vectors').replaceChildren();
    for (const [plaintext, key, expected] of VECTORS) {
      const ciphertext = encrypt80(plaintext, key);
      const decrypted = decrypt80(ciphertext, key);
      const matches = ciphertext === expected && decrypted === plaintext;
      const row = document.createElement('p');
      row.className = matches ? 'present-vector present-ok' : 'present-vector present-alarm';
      row.dataset.verdict = matches ? 'pass' : 'fail';
      row.textContent = `Plaintext ${hex(plaintext)}; key ${hex(key, 20)}; computed ciphertext ${hex(ciphertext)}; decrypt-back ${hex(decrypted)}; ${matches ? '✓ matches CHES 2007 Appendix I' : '⚠ does not match'}`;
      el('vectors').append(row);
    }
  }

  drawWires();
  el('box').addEventListener('input', drawWires);
  function stop(reason = '') {
    if (worker) {
      worker.terminate();
      worker = null;
      put('progress', `${tried} candidates tried · incomplete. ${reason}`);
    }
    epoch++;
    el<HTMLButtonElement>('run').disabled = !record;
    el<HTMLButtonElement>('cancel').disabled = true;
  }
  function retire(reason: string) {
    stop(reason);
    record = undefined;
    el<HTMLButtonElement>('run').disabled = true;
    for (const id of [
      'keys',
      'key-step',
      'trace',
      'cipher',
      'pair',
      'fixture-checks',
      'recovery',
      'survivors',
      'observed',
    ])
      put(id, '');
    el('recovery').className = '';
    delete el('recovery').dataset.verdict;
    el<HTMLInputElement>('k32').value = '';
    put('notice', reason);
  }
  function drawKey() {
    if (!record) return;
    const row = record.keys[step],
      x = row.register,
      rot = ((x << 61n) | (x >> 19n)) & ((1n << 80n) - 1n),
      sub = (rot & ((1n << 76n) - 1n)) | (BigInt(SBOX[Number(rot >> 76n)]) << 76n);
    put(
      'key-step',
      `Round ${row.round}: register ${hex(x, 20)}; K${row.round} ${hex(row.key)}.${step < 31 ? ` Rotate left 61 → ${hex(rot, 20)}; S-box top nibble → ${hex(sub, 20)}; XOR ${row.round} << 15 → ${hex(record.keys[step + 1].register, 20)}.` : ' K32 is the final whitening key; no further update is required.'}`,
    );
  }
  function compute() {
    stop();
    try {
      const key = parseHex(val('key'), 20),
        plaintext = parseHex(val('plaintext'), 16),
        trace = trace80(plaintext, key),
        keys = keySchedule80(key);
      record = { key, plaintext, ciphertext: trace.ciphertext, keys };
      step = 0;
      put('notice', 'Trace computed. Values below belong to the current key and plaintext.');
      put('recovery', '');
      el('recovery').className = '';
      delete el('recovery').dataset.verdict;
      el('survivors').replaceChildren();
      el('keys').innerHTML =
        '<table><thead><tr><th scope="col">Round</th><th scope="col">80-bit register</th><th scope="col">64-bit key</th></tr></thead><tbody>' +
        keys
          .map(
            (r) =>
              `<tr><td>${r.round}</td><td>${hex(r.register, 20)}</td><td>${hex(r.key)}</td></tr>`,
          )
          .join('') +
        '</tbody></table>';
      drawKey();
      el('trace').innerHTML = trace.rows
        .map(
          (r) =>
            `<details><summary>Round ${r.round}: ${hex(r.permuted)}</summary><p>Input ${hex(r.input)}<br>Round key ${hex(r.key)}<br>After XOR ${hex(r.added)}<br>After S-box ${hex(r.sub)}<br>After bit permutation ${hex(r.permuted)}</p></details>`,
        )
        .join('');
      put(
        'cipher',
        `Plaintext ${hex(plaintext)}; key ${hex(key, 20)}; ciphertext ${hex(trace.ciphertext)}; final K32 ${hex(trace.finalKey)}.`,
      );
      drawVectors();
      checks('fixture-checks', decrypt80(trace.ciphertext, key) === plaintext);
      el<HTMLInputElement>('k32').value = hex(keys[31].key);
      put('pair', `Known pair: ${hex(plaintext)} → ${hex(trace.ciphertext)}.`);
      el<HTMLButtonElement>('run').disabled = false;
      observe();
    } catch (e) {
      retire((e as Error).message);
    }
  }
  function observe() {
    if (!record) return;
    try {
      const diff = parseHex(val('difference'), 16),
        a = trace80(record.plaintext, record.key),
        b = trace80(record.plaintext ^ diff, record.key);
      el('observed').innerHTML = a.rows
        .map((r, i) => {
          const d = r.added ^ b.rows[i].added;
          let active = 0;
          for (let n = 0; n < 16; n++) if (((d >> BigInt(4 * n)) & 15n) !== 0n) active++;
          return `<p>Round ${i + 1}: ${active} active S-boxes — observed for this pair; input difference ${hex(d)}.</p>`;
        })
        .join('');
    } catch (e) {
      put('observed', (e as Error).message);
    }
  }
  let signature = [val('key'), val('plaintext')].join('|');
  for (const id of ['key', 'plaintext'])
    el(id).addEventListener('input', () => {
      const next = [val('key'), val('plaintext')].join('|');
      if (next !== signature) {
        signature = next;
        retire('Key or plaintext changed: trace, round keys and recovery retired. Compute again.');
      }
    });
  el('compute').addEventListener('click', compute);
  el('observe').addEventListener('click', observe);
  el('key-next').addEventListener('click', () => {
    step = Math.min(31, step + 1);
    drawKey();
  });
  el('key-prev').addEventListener('click', () => {
    step = Math.max(0, step - 1);
    drawKey();
  });
  el('zero').addEventListener('click', () => {
    el<HTMLInputElement>('key').value = '0'.repeat(20);
    el<HTMLInputElement>('plaintext').value = '0'.repeat(16);
    signature = [val('key'), val('plaintext')].join('|');
    compute();
  });
  el('k32').addEventListener('input', () => {
    stop('K32 changed');
    put('recovery', 'K32 changed: prior result retired.');
    el('survivors').replaceChildren();
    el('recovery').className = '';
    delete el('recovery').dataset.verdict;
  });
  for (const button of panel.querySelectorAll<HTMLButtonElement>('.present-step'))
    button.addEventListener('click', () => {
      panel.querySelectorAll('.present-act').forEach((act, i) => {
        (act as HTMLElement).hidden = String(i + 1) !== button.dataset.act;
      });
      panel
        .querySelectorAll('.present-step')
        .forEach((b) => b.setAttribute('aria-pressed', String(b === button)));
    });
  el('toy').addEventListener('click', () => document.getElementById('tab-attack')!.click());
  el('run').addEventListener('click', () => {
    stop();
    if (!record) {
      put('notice', 'Compute the trace first.');
      return;
    }
    try {
      const k32 = parseHex(val('k32'), 16),
        version = epoch,
        r = record;
      worker = new Worker(new URL('./crypto/present/worker.ts', import.meta.url), {
        type: 'module',
      });
      tried = 0;
      put('progress', '0 / 65536 candidates tried · running');
      put('recovery', '');
      el('survivors').replaceChildren();
      delete el('recovery').dataset.verdict;
      el<HTMLButtonElement>('run').disabled = true;
      el<HTMLButtonElement>('cancel').disabled = false;
      worker.onmessage = (event) => {
        if (version !== epoch) return;
        const data = event.data;
        if (data.kind === 'progress') {
          tried = data.tried;
          put(
            'progress',
            `${tried} / 65536 candidates tried; ${data.survivors} survivors so far · running`,
          );
        } else if (data.kind === 'done') {
          tried = data.tried;
          put(
            'progress',
            `${tried} candidates tried; ${data.survivors.length} survivors. Worker ${(data.elapsedMs / 1000).toFixed(2)} s on this browser (not an attack-cost benchmark).`,
          );
          worker?.terminate();
          worker = null;
          el<HTMLButtonElement>('run').disabled = false;
          el<HTMLButtonElement>('cancel').disabled = true;
          const recovered = (data.survivors as bigint[]).some((candidate) => candidate === r.key);
          el('recovery').className = recovered ? 'present-alarm' : 'present-info';
          el('recovery').dataset.verdict = recovered
            ? 'recovered'
            : data.survivors.length
              ? 'other-candidates'
              : 'none';
          put(
            'recovery',
            recovered
              ? "⚠ DESIGN CHECKS PASS — AND ONE ROUND KEY GIVES THE MASTER KEY. PRESENT-80's key schedule does not keep the master key secret from anyone who learns a round key: K32 plus a 2¹⁶ search is the whole 80-bit key. That is why a last-round attack is a full break. This assumes the round key is already known."
              : data.survivors.length
                ? 'Info — matching candidates reproduce this pair, but none equals the visible master key. This assumes the round key is already known.'
                : 'Info — no master key reproduces this pair for the supplied K32.',
          );
          for (const candidate of data.survivors as bigint[]) {
            const p = document.createElement('p');
            p.className = 'present-survivor';
            p.dataset.key = hex(candidate, 20);
            p.textContent = `${hex(candidate, 20)} · ${candidate === r.key ? 'matches the visible key' : 'different matching candidate'}`;
            el('survivors').append(p);
          }
        } else {
          stop();
          put('notice', data.message);
        }
      };
      worker.onerror = () => {
        stop('Worker error');
        put('notice', 'Worker failed; recovery is incomplete.');
      };
      const request: UnwindRequest = {
        k32,
        pair: { plaintext: r.plaintext, ciphertext: r.ciphertext },
      };
      worker.postMessage(request);
    } catch (e) {
      put('notice', (e as Error).message);
    }
  });
  el('cancel').addEventListener('click', () => stop('Cancelled.'));
  for (const tab of document.querySelectorAll<HTMLButtonElement>('.tab-button')) {
    const leaving = () =>
      requestAnimationFrame(() => {
        if (!panel.classList.contains('active')) stop('Left PRESENT tab.');
      });
    tab.addEventListener('click', leaving);
    tab.addEventListener('keydown', leaving);
  }
  compute();
}
