# crypto-lab-biham-lens

**Differential Cryptanalysis in the Browser** — An interactive demonstration of the breakthrough cryptanalytic technique that fundamentally changed our understanding of cipher security.

**[▶ Live Demo](https://systemslibrarian.github.io/crypto-lab-biham-lens/)**

---

## What It Is

**Differential cryptanalysis** is a chosen-plaintext attack on block ciphers that exploits statistical biases in how plaintext differences propagate through encryption to recover key material. Co-invented by Eli Biham and Adi Shamir in 1990, it fundamentally transformed cryptography by proving that large key sizes and block sizes alone do not guarantee security — the underlying mathematical structure must be carefully designed. This demo implements the attack on a simplified 4-round SPN (Substitution-Permutation Network) cipher, demonstrating how observed differences between ciphertext pairs can betray the last round's subkey through biased differential characteristics.

## When to Use It

Differential cryptanalysis is relevant as a cryptanalytic tool in these scenarios:

- **Red-team cipher evaluation**: When assessing the strength of a new block cipher design, differential cryptanalysis is one of the first attacks to attempt; success indicates weak S-box selection or insufficient rounds. DES fell to this attack on 8 rounds out of 16.
- **Historical cipher analysis**: When reverse-engineering or analyzing older ciphers (pre-1990 designs) lacking differential resistance, this attack can break much of the cipher's strength faster than brute force.
- **Threshold security analysis**: When you have known or chosen encryption oracle access, differential attacks require far fewer queries than exhaustive key search—roughly 500–1000 ciphertext pairs for a toy cipher, versus 2^128 queries for brute force.
- **Academic cryptanalysis**: For understanding how modern cipher designs (AES, Serpent, ChaCha) harden against this and related attacks through strong S-boxes and high round counts.
- **When NOT to use it**: Differential cryptanalysis does not apply to ciphers with provably strong S-box differential properties, ciphers with 30+ rounds of diffusion, or scenarios without chosen-plaintext access; in those cases, exhaustive key search or other attacks are more practical.

## Live Demo

The interactive browser demo at the link above lets you collect ciphertext pairs from a toy 4-round SPN cipher and run a real last-round key recovery attack. You choose plaintext differences, collect ~500 ciphertext pairs corresponding to those differences, and the demo analyzes the statistical bias in the resulting pairs to recover the last round's 8-bit subkey. The demo includes visualizations of how differences propagate through S-box substitution and bit permutation, interactive exploration of the Difference Distribution Table (DDT), and a historical timeline of the attack's discovery and impact.

## What Can Go Wrong

Real failure modes and pitfalls in differential cryptanalysis and its defense:

- **Weak S-box selection**: DES's S-boxes were hardened against differential attacks in secret by the NSA in the 1970s; many S-box designs without this care exhibit high-probability differentials, allowing attacks with fewer than 500 pairs. The max DDT entry of DES is 8, while poorly designed S-boxes can have DDT entries of 12 or more.
- **Insufficient rounds**: Each round of proper diffusion increases the minimum number of pairs required exponentially; DES with only 8 rounds is breakable by differential attacks in hours, while full 16-round DES requires impractically many pairs. Serpent uses 32 rounds specifically to guarantee immunity.
- **Biased round key schedule**: If the round subkeys are derived deterministically from a master key with low entropy or poor diffusion, recovering one subkey may leak information about others, amplifying the attack. The attack assumes subkeys are independent for each round.
- **Implementation padding and oracle feedback**: If the target cipher implementation returns detailed error information (e.g., "decryption failed at S-box stage 2"), an attacker can narrow the search before the cryptanalysis step, reducing pairs needed further. Constant-time implementations resist such leakage.
- **Statistical correlation in pair collection**: If the ciphertext pairs are not collected uniformly at random (e.g., due to a biased pseudorandom number generator), the observed differential bias may be distorted, leading to incorrect key recovery or spurious high-ranking candidates.

## Real-World Usage

Systems and standards that must resist differential cryptanalysis or use concepts derived from it:

- **DES (1977)**: The NSA hardened DES's S-boxes in secret to resist differential attacks; this was confirmed only in 1993 by Don Coppersmith, decades after Biham and Shamir's public discovery. Modern software implementations are still used for legacy compatibility, making them targets for differential attacks on reduced-round variants.
- **SERPENT cipher (1998)**: Co-designed by Eli Biham himself, Serpent uses 32 rounds (extreme redundancy) and carefully selected S-boxes to be provably immune to differential cryptanalysis even if the attacker has access to all round subkeys. It lost the AES competition to Rijndael but remains a reference design for differential-resistant ciphers.
- **Advanced Encryption Standard (AES / Rijndael, 2001)**: The winning AES design includes a strong S-box with minimal DDT entries (max 4) and multiple diffusion layers (MixColumns) per round to guarantee that differential characteristics cannot reach the final round with practical probability over 10 rounds of encryption.
- **SPECK and SIMON (NSA, 2013)**: These lightweight block ciphers for IoT devices are analyzed extensively for differential properties; the NSA's published security arguments include differential cryptanalysis proofs, confirming that round counts and S-box properties provide resistance.
- **NIST Post-Quantum Cryptography Standards (2022–present)**: While primarily focused on lattice and code-based systems, standardization bodies explicitly evaluate lattice-based and permutation-based candidates for resistance to known attacks including differential-like statistical analysis, extending the lessons of differential cryptanalysis to post-quantum era.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*