# PV-SR-ABE: Public Verifiable Server-Aided Revocable Attribute-Based Encryption

> **Based on:** *"Public Verifiable Server-Aided Revocable Attribute-Based Encryption"*
> 
>
> This is a **real-world proof-of-concept** of the paper's scheme, adapted for AWS Lambda deployment.
> The paper's pairing-based ABE construction is restructured as a **hybrid encryption system**:
> AES-256-GCM encrypts the actual plaintext; the PV-SR-ABE scheme encrypts only the 32-byte DEK (session key).



## What Makes This Scheme Special: Public Verifiability

Unlike standard server-aided ABE, PV-SR-ABE adds a **"verify-then-decrypt"** paradigm:

```
Standard RABE:  Transform → Decrypt        (trust the server blindly)
PV-SR-ABE:      Transform → Verify → Decrypt  (anyone can check the server first)
```

The transformed ciphertext `π = e(u₀^r, g^s)` is publicly verifiable against a **public verification key** `vk_ID`. This means:
- The data user does not waste computation decrypting tampered results
- Any third party can audit server behaviour — no private key needed
- The server cannot reuse `π` for a different user (user-specific `r` prevents replay)


## Technical Stack

| Layer | Technology | Notes |
|---|---|---|
| ABE scheme | Custom PV-SR-ABE (this paper) | Public verifiability + user revocation |
| Pairing library | **PBC** (C, compiled in Docker) | Python has no native pairing |
| Python bindings | **charm-crypto** | Wraps PBC for Python |
| Big integers | **GMP** (C, compiled in Docker) | Required by PBC |
| Symmetric encryption | **AES-256-GCM** (`cryptography` lib) | Encrypts actual plaintext |
| Runtime | **Docker on AWS Lambda** | PBC must be pre-compiled |
| Storage | **Local object store** (simulates S3) | Versioned JSON files |

---

## File Reference

| File | Role |
|---|---|
| `pv_core.py` | **Core**: all 9 PV-SR-ABE algorithms, binary tree, LSSS, serialize helpers |
| `ta_local.py` | PKG CLI: Setup / UserKG / Revoke / TKeyUp |
| `lambda_encrypt.py` | Cloud encrypt: ABE wraps GT session key + AES-256-GCM, stores bundle |
| `client_decrypt.py` | Client: TranKG → Transform → Verify → Decrypt → AES-GCM |
| `lambda_handler.py` | **Lambda entry point** (deployed): S3 trigger → result JSON |
| `object_store.py` | FileObjectStore: versioned JSON files (PoC for S3) |
| `app.py` | Minimal standalone AES-GCM Lambda demo |
| `Dockerfile` | Container: Python 3.10 + GMP + PBC + charm-crypto (OpenSSL 1.1 fix) |
| `requirements.txt` | `boto3`, `cryptography<41`, `pyparsing` |
| `requirements-dev.txt` | `pytest==8.3.3`, `pytest-cov==5.0.0` |

```
keys/                  ← local key material (never commit to git)
  pv_setup.json        {curve, depth, mpk, msk, state:{bt, R, id_to_leaf}}
  <user>_user.json     {ID, S, leaf_nid, sk_id, vk_id, psk_id_s}
  tuk_t<N>.json        {t, tuk_t}
  store/<uuid>.json    {scheme, curve, enc, aes:{nonce, ct}}

tests/
  test_e2e_ok.py       ← happy path: full encrypt → verify → decrypt
  test_policy_fail.py  ← user lacks required attribute
  test_time_fail.py    ← TUK time period ≠ ciphertext time period
```

---

## Cryptographic Workflow

### 1. PKG Setup

```bash
python ta_local.py setup \
    --curve SS512 \
    --depth 4 \
    --out keys/pv_setup.json
# writes: keys/pv_setup.json  →  {curve, depth, mpk, msk, state}
# ⚠ contains msk — never upload to S3 or include in Docker image
```

### 2. Issue User Key

```bash
python ta_local.py userkg \
    --setup keys/pv_setup.json \
    --id    alice@example.com \
    --attrs "A,C" \
    --out   keys/alice_user.json
# delivers sk_id, vk_id, psk_id_s to user out-of-band (not via S3)
```

### 3. Cloud Encrypt (local CLI — full PV-SR-ABE path)

```bash
python lambda_encrypt.py \
    --setup     keys/pv_setup.json \
    --policy    "(A and C)" \
    --t         1 \
    --plaintext "confidential record" \
    --store_dir keys/store
# prints: <object_id>
# stores: keys/store/<object_id>.json  →  {enc:{Hdr,c}, aes:{nonce,ct}}
```

### 4. PKG Issues Time-Update Key

```bash
python ta_local.py tkeyup \
    --setup keys/pv_setup.json \
    --t     1 \
    --out   keys/tuk_t1.json
# broadcast tuk_t1.json to all servers (public, non-secret)
```

### 5. Revoke a User (optional)

```bash
python ta_local.py revoke \
    --setup keys/pv_setup.json \
    --id    bob@example.com \
    --t     2
# revoked at t=2; tkeyup for t≥2 will exclude bob from KUNodes
```

### 6. Client Decrypt (TranKG → Transform → Verify → Decrypt)

```bash
python client_decrypt.py \
    --setup     keys/pv_setup.json \
    --user      keys/alice_user.json \
    --tuk       keys/tuk_t1.json \
    --object_id <uuid-from-step-3> \
    --store_dir keys/store
# → [CLIENT] Verify PASSED
# → [CLIENT] Plaintext: confidential record
```

---

## Running Tests

```bash
# Install dev deps
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v

# Run inside Docker (no local PBC needed)
docker run --rm <ECR_URI>:latest \
    python -m pytest /var/task/tests/ -v
```

| Test | Scenario | Expected |
|---|---|---|
| `test_e2e_ok.py` | Attributes match policy, correct time period | Verify PASSED + plaintext recovered |
| `test_policy_fail.py` | User lacks required attribute | TranKG/Transform fails, decrypt aborts |
| `test_time_fail.py` | TUK period t=2, ciphertext period t=1 | TranKG returns ⊥ or Verify FAILED |

---

## Key Separation Guarantee

```
PKG (Local)         Cloud (Lambda)          Client (Local)
────────────────    ────────────────────    ────────────────────────────
Setup()             receives mpk only        receives sk_id, vk_id
UserKG()            runs Encrypt(mpk,…)      runs TranKG (locally)
TKeyUp()            runs Transform           runs Verify
Revoke()            stores {enc, aes}        runs Decrypt → plaintext
msk NEVER leaves    cannot KeyGen            cannot see msk
local machine       cannot Decrypt           decryption is always local
```

---

## CloudWatch Log (Warm Invocation)

```
{"operation": "verify", 
  "input_bucket": "your-demo-bucket",
  "input_key": "test.txt", 
  "output_bucket": "your-demo-bucket-output"}
Duration: 134.34 ms    Billed Duration: 1141 ms    Memory Size: 1024 MB
```

| Field              | Meaning |
|--------------------|---|
| `134.34 ms` actual | Actual computation/execution time (e.g., signature verification or processing time) |
| `1141 ms` billed   | Billed duration (includes approximately 1s of cold start/initialization time) |
| `1024 MB` memory   | Allocated memory size (actually used 86 MB) |

Use **Provisioned Concurrency** to eliminate cold starts for latency-sensitive deployments.
