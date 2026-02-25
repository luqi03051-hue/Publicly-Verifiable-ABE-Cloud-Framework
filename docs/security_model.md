# Security Model — PV-SR-ABE

## 1. Overview

The scheme achieves two formally proved security properties:

| Property | Game | Reduction |
|---|---|---|
| **IND-sCPA** | Indistinguishability under Selective CPA | q−1 assumption [Rouselakis-Waters 2013] |
| **Selective Public Verifiability** | No forgery of valid π without psk | q-BDHE assumption [Boneh-Boyen-Goh 2005] |

This document covers:
1. How hybrid encryption preserves the IND-sCPA guarantee
2. The formal security games as defined in the paper
3. The hardness assumptions and proof intuitions
4. Practical security properties of the AWS deployment

---

## 2. Security of the Hybrid Construction

The paper's scheme proves security for `PV-SR-ABE.Enc(M, mpk, policy, t')`. In this implementation, ABE encrypts only the session key:

```
CT_ABE = PV-SR-ABE.Enc(key_GT, mpk, policy, t')
C_AES  = AES-256-GCM.Enc(plaintext, DEK)
DEK    = SHA-256(serialize(key_GT))
```

**Claim:** If PV-SR-ABE is IND-sCPA secure and AES-256-GCM is IND-CPA secure, then the hybrid construction is IND-sCPA secure.

**Intuition:** An adversary who can distinguish encryptions of `M₀` vs `M₁` must either:
- Distinguish `C_AES = AES-GCM.Enc(M_b, DEK)` without knowing `DEK` → breaks AES-256-GCM IND-CPA, **or**
- Recover `key_GT` from `CT_ABE = PV-SR-ABE.Enc(key_GT, mpk, policy, t')` → breaks ABE IND-sCPA

Both are assumed computationally infeasible. Therefore the hybrid scheme inherits the full security of both components.

---

## 3. Participants and Trust Assumptions

| Party | Role | Trust Level |
|---|---|---|
| **PKG (Trusted Authority)** | Runs Setup(), UserKG(), TKeyUp(), Revoke() locally | Fully trusted; msk never leaves local machine |
| **Data Owner / Cloud** | Chooses policy; runs Encrypt(); stores bundle | Honest |
| **Untrusted Server (Lambda)** | Runs TranKG(), Transform(); stores ciphertexts | **Honest-but-curious** |
| **Public Verifier** | Runs Verify(); no private key needed | Any party; untrusted |
| **Data User** | Holds sk_ID; runs Decrypt() locally | Potentially adversarial |

**Critical isolation — enforced by code, not just policy:**
- Lambda never has access to `msk` (not stored in S3 or anywhere in AWS)
- `sk_ID` is delivered to users out-of-band (never via S3)
- `vk_ID` is fully public and can be distributed freely
- `psk_ID,S` is held by the user and sent to the server only for TranKG; it is a transformation key (not a decryption key)
- The server learns `π = e(u₀^r, g^s)` but this reveals nothing about the plaintext

---

## 4. Formal Security: IND-sCPA Game

### 4.1 Game Flow

```
Phase 0 — Initialization (Selective commit)
  A declares challenge access policy A* = (M*, ρ*) and time period t*
  BEFORE seeing any public parameters.
  This is the "selective" restriction of IND-sCPA.

Phase 1 — Setup
  C runs Setup(λ, U, T) → (mpk, msk).
  C sends mpk to A; keeps msk, empty R, empty st.

Phase 2 — Query Phase 1 (adaptive)
  A may issue:
  ┌─────────────────────────────────────────────────────────────┐
  │ Create(ID, S):    C returns psk_{ID,S}, vk_ID to A          │
  │                   (not sk_ID — that requires Corrupt query) │
  │ Corrupt(ID):      C returns sk_ID   [restriction below]     │
  │ TKeyUp(t):        C returns tuk_t                           │
  │ Revoke(ID, t):    C updates revocation list R               │
  └─────────────────────────────────────────────────────────────┘

Phase 3 — Challenge
  A outputs two equal-length messages M₀, M₁.
  In this implementation: A outputs two GT elements key_GT_0, key_GT_1.
  C samples b ←$ {0,1}.
  C returns (Hdr*, c*) = PV-SR-ABE.Enc(key_GT_b, mpk, A*, t*)

Phase 4 — Query Phase 2 (continued, same restrictions)

Phase 5 — Guess
  A outputs b' ∈ {0,1}.
  A wins if b' = b.
```

### 4.2 Restrictions at Challenge

**Type 1 adversary** (target user is revoked at or before t*):
- A *may* obtain `sk_{ID*}` via Corrupt(ID*)
- But A must have called Revoke(ID*, t) for t ≤ t*
- TranKG(psk_{ID*,S*}, tuk_{t*}) returns ⊥ → user cannot transform

**Type 2 adversary** (target user is not revoked):
- A may *not* obtain `sk_{ID*}` if S* ∈ A* and ID* not revoked before t*

### 4.3 Advantage

```
Adv^{IND-sCPA}_{PV-SR-ABE}(A) = |Pr[b' = b] − 1/2|
```

The scheme is IND-sCPA secure if this advantage is negligible in λ for all PPT adversaries A.

---

## 5. Formal Security: Selective Public Verifiability Game

```
Phase 0 — Initialization
  A declares challenge policy A* = (M*, ρ*) and time period t*.

Phase 1 — Setup
  C runs Setup(); sends mpk to A; keeps msk.
  C sends challenge (Hdr*, c*) = PV-SR-ABE.Enc(key_GT, mpk, A*, t*) to A.

Phase 2 — Queries (adaptive)
  ┌──────────────────────────────────────────────────────────────────────┐
  │ Create(ID, S):             C returns sk_ID, vk_ID, psk_{ID,S}        │
  │ TKeyUp(t):                 C returns tuk_t                           │
  │ Transform(ID,S,t*,c*):     C computes and returns π to A             │
  │ Revoke(ID, t):             C updates R                               │
  └──────────────────────────────────────────────────────────────────────┘

Phase 3 — Forgery
  A outputs a forged transformed ciphertext π* for (ID*, S*, t*).
  A wins if:
  • Verify(mpk, c*, π*, vk_{ID*}, ID*) = 1  (π* is valid)
  • (ID*, S*, t*, c*) was NOT queried in Transform
  • psk_{ID*,S*} was NOT returned in Create
```

### 5.1 Why Forgery is Hard

`π = e(u₀^r, g^s)` where `r` is embedded in `psk_{ID,S}` (unknown to adversary if Create was not queried) and `s` is the master secret from Encrypt. Without `r`, computing `e(u₀^r, g^s)` reduces to the q-BDHE problem.

### 5.2 Non-Replayability of π

Each user's `π` embeds a distinct `r` (chosen fresh during UserKG). An adversary cannot reuse `π_A` (computed for user A) to pass verification for user B:
- `Verify` computes `MR = C_MR · π^{ID} / pair(vk_{ID}, C_k0s)`
- `vk_{ID_B} = g₀^{β + r_B·ID_B} ≠ vk_{ID_A}`
- The recovered `MR'` will be wrong → H check fails

---

## 6. Hardness Assumptions

### Decisional (q−1) Assumption [Rouselakis-Waters 2013]

**Security reduces to:** distinguishing `e(g,g)^{s·a^{q+1}}` from a random GT element.

**Given:**
```
g, g^s,
g^{a^i}, g^{b_j}, g^{s·b_j}, g^{a^i·b_j}, g^{a^i·b_j^2}   ∀(i,j) ∈ [q,q]
g^{a^i·b_j·(b_j')^2}                                          ∀(i,j,j') ∈ [2q,q,q], j≠j'
g^{a^i·b_j}                                                   ∀(i,j) ∈ [2q,q], i≠q+1
g^{s·a^i·b_j·b_j'}, g^{s·a^i·b_j·(b_j')^2}                  ∀(i,j,j') ∈ [q,q,q], j≠j'
```
**Distinguish:** `T = e(g,g)^{s·a^{q+1}}` vs random `T ∈ GT`.

The simulator B embeds this challenge into `mpk` such that:
- All key/update queries can be answered without knowing `a^{q+1}`
- The challenge ciphertext uses `T` in the `Hdr` term `e(g,g)^{αs}·M_b`
- B's advantage = A's advantage / 2

### q-BDHE Assumption [Boneh-Boyen-Goh 2005]

**Security reduces to:** computing `e(g,f)^{a^{q+1}}`.

**Given:** `g, g^a, g^{a^2}, …, g^{a^q}, g^{a^{q+2}}, …, g^{a^{2q}}, f ∈ G`

**Success probability of reduction:**
```
Pr[Success] ≥ (1 − q_s/q) · (1/q) ≥ 1/(4·q_s)
```
where `q_s = q₁ + q₂` = number of Create + Transform queries.

In **charm-crypto with SS512 pairing**, both assumptions hold at approximately 80-bit security. For stronger guarantees, use `MNT224` (Type D, 112-bit) or `BN256` curves.

---

## 7. Collusion Resistance

Multiple users cannot combine their keys to satisfy a policy that neither satisfies individually.

**Mechanism:** Each `psk_{ID,S}` is bound to a fresh random `r ←$ Zp` chosen during UserKG. The TranKG computation requires consistent `r` across all path components. Mixing key material from two users with `r₁ ≠ r₂` causes the pairing product in Transform to yield a wrong π, which Verify rejects.

```python
# Collusion attempt: user A has attribute X, user B has attribute Y
# Policy requires (X and Y)
# A sends psk_A to server; B sends psk_B to server
# Server tries to combine in TranKG:
A_combined = psk_A["A_for_node_x"] * tuk_x["F"]
#          = (w^ID_A k)^{rx_A} · u0^{r_A} · (u1^t h1)^sx  [uses r_A]
# But attribute Y comes from psk_B with r_B ≠ r_A
# → the pairing product does not cancel correctly
# → π ≠ e(u0^r, g^s) for any consistent r
# → Verify(π) = 0
```

---

## 8. Verify-then-Decrypt: Security Benefit

The "verify-then-decrypt" order is critical. If the user decrypts first (as in traditional private verification), then:
- A malicious server can make the user waste computation on a tampered ciphertext
- A malicious user can falsely claim the server produced a wrong result (since only they can check)

With public verification:
- **Any third party** can verify that `π` is correct before the user even receives it
- The user only calls `decrypt()` after `verify()` returns True
- A malicious server's misbehaviour is **publicly provable**, not just user-visible

---

## 9. AWS Deployment Security Properties

### 9.1 What Lambda Can and Cannot Do

```
Lambda CAN:                          Lambda CANNOT:
──────────────────────────────────   ─────────────────────────────────────
Read mpk (from setup JSON)           Read msk (not in AWS at all)
Run Encrypt(mpk, policy, t')         Run UserKG() (no msk)
Run TranKG(mpk, psk, tuk_t)         Run TKeyUp() alone (no msk)
Run Transform(mpk, c, tk, ID)       Decrypt CT_ABE (no sk_id)
Compute π = e(u0^r, g^s)            Access sk_id files (never in S3)
Run Verify(mpk, c, π, vk_id, ID)    Learn plaintext from C_AES alone
Store {enc, aes} bundle to store    Forge valid π (q-BDHE hardness)
```
`pv_setup.json` (which contains `msk`) must **never** be uploaded to S3. Only `mpk` components need to be accessible to Lambda.

### 9.2 Key Material Lifecycle

```
pv_setup.json (msk+mpk)  ← LOCAL MACHINE ONLY
alice_user.json (sk_id, vk_id, psk_id_s)  ← delivered to user out-of-band
tuk_t1.json (tuk_t)  ← public; can be broadcast via S3 (read-only for Lambda)
keys/store/<uuid>.json (enc+aes bundle)  ← Lambda writes; user reads
```

### 9.3 Threat Model Summary

| Threat | Mitigation |
|---|---|
| Cloud reads `{enc, aes}` bundle | IND-sCPA: requires `sk_id` satisfying policy + time period |
| Cloud returns incorrect `π` | `verify()` catches it; H check fails with overwhelming probability |
| Cloud replays `π` from another user | User-specific `r` in `vk_id` check; fails for wrong ID |
| Revoked user attempts decryption | TranKG returns ⊥; no valid `tk` can be derived |
| User falsely claims wrong `π` | Any third party can independently re-run `verify()` with same inputs |
| Key collusion between users | Fresh `r` per `UserKG`; Lagrange combination fails for mixed keys |
| Adversary forges `π` without `psk` | q-BDHE hardness; `π = e(u₀^r, g^s)` requires knowing `r` |
| Docker image tampered | Use ECR image signing + Lambda code signing |
| `msk` exposure (PoC gap) | In production: store in HSM; never serialize to disk |

### 9.4 Data in Transit and at Rest

- All S3 transfers: HTTPS (TLS 1.2+); S3 SSE-S3 or SSE-KMS for at-rest encryption
- Lambda ↔ S3: VPC endpoint recommended to avoid public internet path
- `sk_id` and `vk_id` delivery: must use an out-of-band secure channel (e.g., SFTP, encrypted email, secure portal) — **never S3**
- CloudTrail enabled for full audit of all S3 and Lambda API calls
- `tuk_t` files: public (non-secret); can be distributed via S3 with appropriate read permissions

