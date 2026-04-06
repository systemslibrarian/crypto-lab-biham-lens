# biham-lens — Differential Cryptanalysis Demo

**[▶ Live Demo](https://systemslibrarian.github.io/crypto-lab-biham-lens/)**

A browser-based interactive demonstration of **differential cryptanalysis**, the cryptanalytic breakthrough co-invented by **Eli Biham** (Technion, Israel) and **Adi Shamir** (Weizmann Institute, Israel) in 1990.

This demo showcases the attack against a simplified 4-round SPN (Substitution-Permutation Network) toy cipher using real arithmetic. The attack recovers the final round's subkey using chosen-plaintext pairs and statistical bias.

## What is Differential Cryptanalysis?

Differential cryptanalysis is a method of cryptanalysis that exploits how small differences in plaintext propagate through a cipher. By carefully choosing pairs of inputs that differ by a specific amount (a **difference**), an attacker can observe patterns in the output differences and extract key information.

This attack was the most important cryptanalytic advancement of the late 20th century, invalidating the assumption that cryptanalysis was purely academic and demonstrating that ciphers could have subtle weaknesses exploitable through statistical methods rather than brute force.

## Historical Significance

- **1970s**: The NSA secretly discovered differential cryptanalysis and hardened DES to resist it.
- **1990**: Biham & Shamir published their work, bringing the attack to public knowledge.
- **1993**: Don Coppersmith confirmed that the NSA's DES S-box design was specifically hardened against differential attacks—validating the NSA's decades of classified research.
- **1998**: Biham co-designed the Serpent cipher specifically to be immune to differential cryptanalysis.

## The Toy Cipher

The cipher used in this demo is a simplified 4-round SPN:

- **Block size**: 8 bits
- **S-box**: 4-bit substitution (applied twice per byte, one per nibble)
- **Permutation**: Bit-level diffusion across the 8-bit block
- **Key schedule**: Simple subkey generation from a 16-bit master key
- **Rounds**: 4 rounds

The S-box is:
```
Input:  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
Output: E  4  D  1  2  F  B  8  3  A  6  C  5  9  0  7
```

The permutation matrix maps bit positions [7,6,5,4,3,2,1,0] → [7,3,6,2,5,1,4,0].

## How the Attack Works

**Last-Round Key Recovery Technique** (Peel-Last-Round):

1. **Collect chosen-plaintext pairs** with a fixed XOR difference Δp
2. **Encrypt both** to get ciphertext pairs (c₁, c₂)
3. **For each candidate key k ∈ [0, 255]**:
   - Partially decrypt c₁ and c₂ by XORing with k
   - Invert the S-box to undo the last round's substitution
   - Check if the resulting difference matches the expected differential
   - Count how many pairs match (this is the **bias**)
4. **The candidate with highest bias** is the correct last-round key

Attack complexity: ~500 chosen-plaintext pairs are usually sufficient to reliably identify the correct subkey among 256 candidates.

## Features

### Tab 1: Live Attack
The interactive attack engine. You can:
- Choose plaintext difference
- Collect up to 2000 ciphertext pairs
- Run the attack and watch the bias distribution evolve
- See which candidate key is selected
- Verify successful recovery against the known secret key

### Tab 2: Differential Trace
Visualization of how XOR differences propagate through rounds:
- See how differences transform through S-boxes
- Observe diffusion via permutation
- Understand why differential cryptanalysis works

### Tab 3: S-box Analysis
Analysis of the S-box's differential properties:
- Interactive S-box grid
- Difference Distribution Table (DDT) — the core of differential cryptanalysis
- Click any DDT cell to see probability, count, and whether it's exploitable
- S-box strength assessment

### Tab 4: Historical Impact
- Timeline of the discovery and its implications
- Attribution to Biham & Shamir
- Connection to subsequent cipher designs

### Tab 5: Why Serpent Survived
- Comparison table: DES vs. AES vs. Serpent
- Why Serpent's extreme conservatism guarantees safety
- Portfolio connections to the broader crypto-compare story

## Mathematical Prerequisites

- **XOR difference**: Δx = x ⊕ x' (bitwise XOR of two inputs)
- **Difference Propagation**: How S(x) ⊕ S(x') relates to x ⊕ x'
- **Difference Distribution Table (DDT)**: For each input difference Δx and output difference Δy, count how many x ∈ [0,15] satisfy: S(x) ⊕ S(x ⊕ Δx) = Δy
- **Differential Probability**: How often a particular difference propagates through a component
- **Statistical Bias**: When the correct key is decrypted, the differences statistically match; wrong keys don't

## Running Locally

```bash
# Install dependencies
npm install

# Start dev server
npm run dev

# Build for production
npm run build
```

The app runs fully offline—no external dependencies at runtime.

## References

The original paper introducing differential cryptanalysis:

> **Eli Biham and Adi Shamir**  
> "Differential Cryptanalysis of DES-like Cryptosystems"  
> *Journal of Cryptology*, vol. 4, no. 1, pp. 3–72, 1991

## Attribution

- **Technique**: Differential Cryptanalysis (Biham & Shamir, 1990)
- **Serpent Cipher Design**: Eli Biham, Ross Anderson, Lars Knudsen (1998)
- **This Implementation**: Part of the crypto-compare portfolio

## Code Structure

```
src/
├── crypto/
│   ├── sbox.ts           # 4-bit S-box and inversion
│   ├── permutation.ts    # Bit permutation for diffusion
│   ├── spn.ts            # 4-round SPN cipher
│   ├── ddt.ts            # Difference Distribution Table computation
│   ├── characteristic.ts # Differential characteristic finding
│   └── attack.ts         # Last-round key recovery attack
├── __tests__/
│   ├── spn.test.ts       # Cipher tests
│   └── ddt.test.ts       # DDT tests
├── main.ts               # UI application
└── style.css             # Dark theme styling
```

## Implementation Notes

- **Vanilla TypeScript**: No external crypto libraries. All SPN operations, S-box, permutation, and DDT computation are implemented from first principles.
- **Real arithmetic**: The attack collects actual ciphertext pairs and performs real statistical analysis.
- **Educational**: The code is optimized for clarity and understanding, not performance.
- **Testable**: Round-trip tests verify correct encryption/decryption. DDT tests ensure proper differential analysis.

## A Note on Security

This toy cipher is **intentionally weak** for educational purposes. The 4 rounds, simple key schedule, and small block size make it vulnerable not just to differential attacks but to many other methods. Real ciphers use much larger block sizes (128+ bits), more rounds (10-32), and carefully designed S-boxes and linear layers.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
