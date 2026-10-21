# crypto-lab-biham-lens

## What It Is

**Differential cryptanalysis** is a chosen-plaintext attack on block ciphers that exploits how plaintext differences propagate through encryption to recover key material. Co-invented by Eli Biham and Adi Shamir in 1990, it fundamentally transformed cryptography by proving that large key sizes and block sizes alone do not guarantee security — the underlying mathematical structure must be carefully designed. The first two panels demonstrate a statistical attack on a simplified 4-round SPN. The FEAL-4 panel applies round peeling to a published cipher with a probability-1 differential.

The toy’s strong S-box is PRESENT’s S-box; the PRESENT tab runs the full PRESENT-80 cipher and its reversible key schedule.

## When to Use It

Differential cryptanalysis is relevant as a cryptanalytic tool in these scenarios:

- **Red-team cipher evaluation**: When assessing the strength of a new block cipher design, differential cryptanalysis is one of the first attacks to attempt; success indicates weak S-box selection or insufficient rounds. DES fell to this attack on 8 rounds out of 16.
- **Historical cipher analysis**: When reverse-engineering or analyzing older ciphers (pre-1990 designs) lacking differential resistance, this attack can break much of the cipher's strength faster than brute force.
- **Threshold security analysis**: When you have chosen-plaintext oracle access, a differential attack can beat exhaustive search by tens of bits — full 16-round DES falls to 2^47 chosen plaintexts against a 2^56 key space. (Do not read the toy cipher here as evidence of that: its 500–1000 pairs are compared against a 16-bit key space, where brute force wins outright. The demo exists to make the *mechanism* visible, not the saving.)
- **Academic cryptanalysis**: For understanding how AES and Serpent use S-boxes and diffusion, while ARX designs such as ChaCha use addition, rotation and XOR. Each design needs its own differential analysis.
- **When NOT to use this demonstration as evidence of a break**: the displayed chosen-plaintext attack needs its stated oracle access and differential. Strong S-boxes and additional rounds can raise attack cost, but neither an S-box bound nor a generic round-count threshold proves immunity. Feasibility requires analysis of the complete cipher and attack model.
- **Do NOT treat the toy 4-round SPN here as a real cipher**: it is a teaching demo built to make the attack visible, not production-strength cryptography.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-biham-lens](https://systemslibrarian.github.io/crypto-lab-biham-lens/)**

The interactive browser demo lets you collect ciphertext pairs from a toy 4-round SPN cipher and run a real last-round key recovery attack. You choose plaintext differences, collect ~500 ciphertext pairs corresponding to those differences, and the demo analyzes the statistical bias in the resulting pairs to recover the last round's 8-bit subkey. The demo includes visualizations of how differences propagate through S-box substitution and bit permutation, interactive exploration of the Difference Distribution Table (DDT), and a historical timeline of the attack's discovery and impact.

### FEAL-4 extension

The **3 · FEAL-4** tab encrypts 64-bit blocks with FEAL-4's published 64-bit key schedule, traces a chosen difference through its four Feistel rounds, and attacks an encryption oracle in a Web Worker. The default 6 A pairs and 4 B pairs query **20 chosen plaintexts**; an expandable table shows every plaintext pair and oracle reply. A funnel shows surviving partial keys as rounds 4, 3, 2, and 1 are peeled. Every full candidate is then tested against **64 fresh ciphertexts** that were generated after recovery. The verdict shows one fresh plaintext, its ciphertext, and decryption with an equivalent key. These 64 verification queries are separate from the 20 attack queries.

The result is **equivalent round-key and whitening material**, sufficient to decrypt unseen blocks. It is **not the 64-bit master key**: the attack never uses or inverts the key schedule. The FEAL engine is separate from the toy SPN engine because the latter ranks 256 subkeys by statistical bias, while FEAL filters a 32-bit effective round-key space by exact differences. Cipher output is cross-checked against [CrypTool 2's FEAL implementation](https://github.com/CrypToolProject/CrypTool-2/blob/main/CrypPlugins/FEAL/FEAL_Algorithms.cs). [Murphy's 1990 paper](https://doi.org/10.1007/BF00190801) describes master-key recovery with at most 20 chosen plaintexts; this panel uses a classroom round-peeling variant.

### PRESENT extension

The **PRESENT** tab runs all 31 rounds, all 32 round keys, the published S-box and bit permutation, and inverse decryption. Six acts enumerate the DDT and Walsh table, draw the 64 wires, step the register, trace encryption, distinguish observed differences from the cited five-round theorem, and recover the master key from **already known K32** plus one pair by searching all 65,536 suffixes in a cancellable Worker. The Worker receives no master key.

Theorem 1 is cited, not proved by the observed trace. Condition 4 as printed is not asserted: the computed single-bit Walsh entries include zero. Passing the design checks does not hide the master key from a holder of K32. This is a key-schedule consequence, not an attack obtaining the round key. PRESENT-128 is not implemented.

## What Can Go Wrong

Real failure modes and pitfalls in differential cryptanalysis and its defense:

- **Weak S-box selection**: DES's S-boxes were hardened against differential attacks by their IBM designers in the 1970s, under an NSA requirement that the reasoning stay classified; many S-box designs without this care exhibit high-probability differentials, allowing attacks with fewer than 500 pairs. The largest DDT entry across DES's 6→4-bit S-boxes is 16 out of 64 (a differential probability of 1/4); the toy 4-bit S-box in this demo peaks at 8 out of 16 (1/2), while the PRESENT S-box it can be swapped for peaks at 4 out of 16 (1/4), the best a 4-bit permutation can do.
- **Insufficient rounds**: Diffusion and additional active S-boxes can lower characteristic probabilities and raise data requirements; there is no universal per-round cost law. Serpent's 32 rounds were chosen for a substantial security margin, not a proof of immunity. See [the designers' proposal](https://www.cl.cam.ac.uk/archive/rja14/Papers/serpent.pdf).
- **Biased round key schedule**: If the round subkeys are derived deterministically from a master key with low entropy or poor diffusion, recovering one subkey may leak information about others, amplifying the attack. The attack assumes subkeys are independent for each round.
- **Implementation padding and oracle feedback**: If the target cipher implementation returns detailed error information (e.g., "decryption failed at S-box stage 2"), an attacker can narrow the search before the cryptanalysis step, reducing pairs needed further. Constant-time implementations resist such leakage.
- **Statistical correlation in pair collection**: If the ciphertext pairs are not collected uniformly at random (e.g., due to a biased pseudorandom number generator), the observed differential bias may be distorted, leading to incorrect key recovery or spurious high-ranking candidates.

## Real-World Usage

Systems and standards that must resist differential cryptanalysis or use concepts derived from it:

- **DES (1977)**: The IBM team that designed DES already knew differential cryptanalysis — internally, the "T attack" — and chose the S-boxes to resist it, with the NSA requiring that the criterion stay classified. Don Coppersmith, who did that S-box work, said so publicly in 1994 (*IBM Journal of Research and Development* 38(3)), four years after Biham and Shamir's independent rediscovery. Modern software implementations are still used for legacy compatibility, making them targets for differential attacks on reduced-round variants.
- **SERPENT cipher (1998)**: Co-designed by Ross Anderson, Eli Biham and Lars Knudsen, Serpent uses 32 rounds and S-boxes with a maximum DDT entry of 4 — roughly twice the rounds its designers argued were needed to put differential and linear attacks out of reach. That margin is a design argument rather than a proof of immunity, which is exactly the point: nobody can prove a cipher secure, so you buy rounds. It lost the AES competition to Rijndael but remains a reference design for differential-resistant ciphers.
- **Advanced Encryption Standard (AES / Rijndael, 2001)**: The winning AES design includes a strong S-box with minimal DDT entries (max 4) and multiple diffusion layers (MixColumns) per round to guarantee that differential characteristics cannot reach the final round with practical probability over 10 rounds of encryption.
- **SPECK and SIMON (NSA, 2013)**: These lightweight block-cipher families are studied using differential cryptanalysis. Neither uses a lookup-table S-box: SPECK uses addition, rotation and XOR; SIMON uses AND, rotation and XOR. Their round functions require analysis specific to those operations.
- **NIST Post-Quantum Cryptography Standards (2022–present)**: While primarily focused on lattice and code-based systems, standardization bodies explicitly evaluate lattice-based and permutation-based candidates for resistance to known attacks including differential-like statistical analysis, extending the lessons of differential cryptanalysis to the post-quantum era.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-biham-lens
cd crypto-lab-biham-lens
npm install
npm run dev
```

## Related Demos

- [crypto-lab-iron-serpent](https://systemslibrarian.github.io/crypto-lab-iron-serpent/) — the Serpent cipher, co-designed by Biham for differential resistance.
- [crypto-lab-padding-oracle](https://systemslibrarian.github.io/crypto-lab-padding-oracle/) — a different chosen-ciphertext attack on AES-CBC.
- [crypto-lab-collision-vault](https://systemslibrarian.github.io/crypto-lab-collision-vault/) — collision attacks on MD5 and SHA-1.
- [crypto-lab-vigenere-break](https://systemslibrarian.github.io/crypto-lab-vigenere-break/) — classical statistical cryptanalysis of the Vigenère cipher.
- [crypto-lab-enigma-forge](https://systemslibrarian.github.io/crypto-lab-enigma-forge/) — Enigma and the Bombe, a historical cryptanalysis story.

## Build & Verify

Verified on this revision: **38 unit tests passed, 0 failed, 0 skipped** (`node --import tsx --test`); **43 browser tests passed, 0 failed, 0 skipped, 0 flaky**, with `--retries=0`. The build also passes both publishing-command tests. The act-6 negative-claim test records Worker seconds as an annotation, not a performance gate.

```bash
npm ci
npm run typecheck
npm test
npm run build
npx playwright install chromium
npm run test:a11y -- --retries=0
node scripts/check-present-mutations.mjs
```

PRESENT uses [Bogdanov et al., CHES 2007](https://crypto.orange-labs.fr/papers/ches2007-450.pdf), §3, §4.3, §5.1, Appendix I. Published plaintext / key / ciphertext vectors:

| Plaintext | Key | Ciphertext |
|---|---|---|
| 0000000000000000 | 00000000000000000000 | 5579C1387B228445 |
| 0000000000000000 | FFFFFFFFFFFFFFFFFFFF | E72C46C0F5945049 |
| FFFFFFFFFFFFFFFF | 00000000000000000000 | A112FFC72F68417B |
| FFFFFFFFFFFFFFFF | FFFFFFFFFFFFFFFFFFFF | 3333DCD3213210D2 |

Labelled independent cross-checks (not published vectors): `0123456789ABCDEF / 00112233445566778899 → 1A6D783F0C184F4D`; `FEDCBA9876543210 / 0123456789ABCDEF0123 → CB7D344F360DE3B1`. The tests also check every permutation position, all byte-table inputs, every key-register reversal, exhaustive S-box facts, and three complete searches whose real suffixes are in the upper half. Browser tests recompute the cipher using a separate table-driven implementation, test fail-closed paths, and scan every act at desktop and 320px. Existing SPN and FEAL gates remain in place. Mutation evidence records builds, assertion kills, restored hashes and restored passing tests.


---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## Reduced-round ChaCha context

The live demo links [EUROCRYPT 2025 bit-puncturing research](https://eprint.iacr.org/2025/437), labels reduced-round results and paper estimates, and distinguishes them from full ChaCha20 and from the attacks these labs actually execute. No reduced-round cipher replaces normal encryption.
