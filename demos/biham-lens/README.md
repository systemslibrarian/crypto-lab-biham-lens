# biham-lens — Differential Cryptanalysis Demo

**[▶ Live Demo](https://systemslibrarian.github.io/crypto-lab-biham-lens/)**

---

## What It Is

Differential cryptanalysis is a chosen-plaintext attack technique that recovers secret key material from block ciphers by exploiting statistical biases in how XOR differences propagate through substitution and permutation layers. Invented by Eli Biham and Adi Shamir in 1990, it operates in the symmetric-key model — the attacker needs access to an encryption oracle but not the key itself. This demo implements the attack against a 4-round SPN (Substitution-Permutation Network) toy cipher with an 8-bit block size, 4-bit S-boxes, a bit permutation layer, and a 16-bit master key. The attack performs last-round key recovery by partially decrypting ciphertext pairs under each candidate subkey and counting how many produce the expected output difference.

## When to Use It

- **Evaluating a new block cipher design** — Differential cryptanalysis is the first attack to test against any proposed cipher; if the S-box Difference Distribution Table has entries above 2/n, the cipher may be vulnerable with fewer pairs than brute-force search.
- **Analyzing reduced-round variants** — When a cipher uses fewer rounds than recommended (as in this 4-round SPN), the differential probability through the full cipher stays high enough for practical key recovery with ~500 chosen-plaintext pairs.
- **Teaching how modern ciphers defend against attacks** — The DDT visualization and trace in this demo show exactly why AES and Serpent choose S-boxes with low maximum differential probability and why round counts matter.
- **Auditing S-box quality** — The Difference Distribution Table computed by `ddt.ts` reveals which input/output difference pairs have exploitable probability, directly measuring substitution-layer weakness.
- **When NOT to use it** — Differential cryptanalysis does not apply when you lack chosen-plaintext access to an encryption oracle, or when the target cipher has provably low maximum differential probability across its full round count (e.g., AES-128 with 10 rounds).

## Live Demo

**[▶ Launch Demo](https://systemslibrarian.github.io/crypto-lab-biham-lens/)**

The demo lets you run a real differential attack in the browser. In the **Live Attack** tab, you choose two plaintext values (hex bytes), collect 100–1000 ciphertext pairs from the toy SPN cipher, and execute last-round key recovery — the attack ranks all 256 candidate subkeys by bias count and identifies the correct one. The **Differential Trace** tab visualizes how XOR differences propagate through S-box substitution and bit permutation round by round. The **S-box Analysis** tab displays the full 16×16 Difference Distribution Table with clickable cells showing count, probability, and exploitability for each differential.

## What Can Go Wrong

- **Insufficient pair collection** — With fewer than ~500 chosen-plaintext pairs, the correct subkey's bias count may not separate from noise, causing the attack to return a wrong key candidate.
- **Weak differential characteristic selection** — If the chosen input difference does not correspond to a high-probability path through the S-box layers, the output difference distribution flattens and no candidate key stands out; the attacker must select differentials guided by the DDT.
- **Biased pair generation** — If the pseudorandom source generating plaintext pairs is biased or correlated, the observed differential counts become distorted, producing spurious high-ranking candidates or masking the correct key.
- **Key schedule leakage across rounds** — In this toy cipher the round subkeys are derived from a single 16-bit master key with low entropy; recovering the last-round subkey may leak information about other subkeys, allowing full key recovery — a design flaw absent in real ciphers with strong key schedules.
- **Assuming S-box uniformity without verification** — Deploying a cipher without computing its full DDT (as `ddt.ts` does) risks missing high-probability differentials; the NSA secretly verified DES S-box differential properties decades before the public discovery.

## Real-World Usage

- **DES (1977)** — The NSA hardened DES's S-boxes against differential cryptanalysis in secret; Biham and Shamir's 1990 public discovery confirmed that DES with fewer than 16 rounds is breakable by this technique.
- **AES / Rijndael (2001)** — The AES selection process required candidates to prove resistance to differential cryptanalysis; Rijndael's S-box has a maximum DDT entry of 4, ensuring no exploitable differential reaches through 10 rounds.
- **Serpent (1998)** — Co-designed by Eli Biham himself, Serpent uses 32 rounds and S-boxes with maximum DDT entry 4 to guarantee immunity to differential cryptanalysis even under optimistic attacker models.
- **PRESENT (2007)** — This lightweight block cipher for constrained IoT devices was specifically analyzed for differential resistance; its 4-bit S-box was chosen to minimize maximum differential probability across 31 rounds.
- **NIST Lightweight Cryptography (2023)** — The ASCON AEAD winner underwent extensive differential cryptanalysis evaluation during standardization, applying the same DDT-based S-box analysis principles demonstrated in this demo.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
