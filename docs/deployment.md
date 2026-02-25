# Deployment Guide — PV-SR-ABE on AWS Lambda (Docker)

This document describes how the PV-SR-ABE research scheme is deployed as a practical cloud data-sharing system on AWS.

The goal of this deployment is not to build a full production service, but to demonstrate how a pairing-based cryptographic scheme with public verifiability and user revocation can operate inside a realistic serverless cloud environment.

---

## 1. System Deployment Philosophy

The original paper defines nine cryptographic algorithms:

- Setup / UserKG / TKeyUp / Revoke (PKG operations)
- Encrypt / Transform / Verify / Decrypt (data operations)
- TranKG (server key generation)

Real-world systems additionally require:

- large file / arbitrary-byte encryption
- runtime dependency management (native C libraries)
- cloud execution isolation and reproducibility

Therefore this project adopts:

- **Hybrid Encryption** (ABE wraps GT session key; AES-256-GCM encrypts data)
- **Containerised Runtime** (Docker image with PBC + charm-crypto pre-compiled)
- **Serverless Execution** (AWS Lambda Container Image, triggered by S3)

---

## 2. Hybrid Encryption Architecture

Direct ABE encryption over GT group elements cannot handle arbitrary-length data. Instead, the deployment uses a **KEM-DEM (Key Encapsulation Mechanism + Data Encryption Mechanism)** design.

### Encryption (Cloud / Data Owner)

```
key_GT  = group.random(GT)               ← random session key in GT
DEK     = SHA-256(serialize(key_GT))     ← 32-byte data encryption key
C_AES   = AES-256-GCM.Enc(plaintext, DEK)   ← DEM: encrypt data
CT_ABE  = PV-SR-ABE.Enc(key_GT, mpk, policy, t')  ← KEM: wrap session key
```

Stored bundle per object:
```
keys/store/<uuid>.json:
  enc:  {Hdr, ct}          ← ABE ciphertext (for TranKG + Verify + Decrypt)
  aes:  {nonce, ct}        ← AES-256-GCM encrypted payload
```

### Decryption (Client)

```
π       = Transform(mpk, ct, tk^S_{ID,t}, ID)     ← server computes
ok      = Verify(mpk, c, π, vk_ID, ID)            ← anyone verifies
key_GT  = Decrypt(mpk, sk_ID, π, Hdr, ID)         ← client decrypts ABE
DEK     = SHA-256(serialize(key_GT))
pt      = AES-256-GCM.Dec(C_AES, DEK)             ← recover plaintext
```

This preserves the full access-control and public verifiability semantics of the PV-SR-ABE scheme while enabling efficient encryption of arbitrary-length data.

---

## 3. Why Docker Deployment is Required

The PV-SR-ABE implementation is pairing-based and depends on native cryptographic libraries:

- **Charm-Crypto** (Python ABE framework)
- **PBC library** (C, Pairing-Based Cryptography)
- **GMP** (C, GNU Multiple Precision Arithmetic)
- **OpenSSL 1.1** (required by Charm-Crypto extensions)

AWS Lambda's standard Python runtime cannot reliably install and link these C extensions at deploy time. Additionally, PBC must be compiled for `x86_64 Linux` (the Lambda execution environment).

Therefore the entire cryptographic runtime is packaged as a Docker container image.

**Benefits:**
- deterministic runtime (same result local and cloud)
- stable native library linkage (OpenSSL 1.1 pinned in Dockerfile)
- portable research artifact (reproducible by any researcher)
- natively supported by Lambda Container Image support

---

## 4. AWS Architecture Overview

```
PKG (Local)         Data Owner              AWS Cloud
──────────────      ──────────────────      ─────────────────────────────────────
Setup()         →   mpk → S3 config/        Lambda Container (Docker)
UserKG()        →   sk_id, vk_id            ┌──────────────────────────────────┐
TKeyUp()            psk_id_s                │ ① S3 trigger → Lambda invoked   │
Revoke()            tuk_t → S3 config/      │ ② DEK = key_GT random            │
                                            │ ③ C_AES = AES-GCM.Enc(M, DEK)   │
                    plaintext → S3 inbox/   │ ④ CT_ABE = ABE.Enc(key_GT, mpk) │
                                            │ ⑤ store bundle → S3 outbox/     │
                                            └──────────────────────────────────┘
                    Client downloads bundle from S3
                    Client runs: TranKG → Transform → Verify → Decrypt
```

### Component Roles

| Component | Role |
|---|---|
| **S3 (input)** | Trigger source; plaintext upload |
| **S3 (output)** | Encrypted bundle storage (`{enc, aes}`) |
| **Lambda Container** | Runs Encrypt + stores result |
| **ECR** | Docker image registry |
| **CloudWatch** | Execution logging and audit |
| **Local machine** | PKG: Setup / UserKG / TKeyUp / Revoke |
| **Client device** | TranKG (local) + Verify + Decrypt |

---

## 5. Role Separation (Security Model)

### Trusted Authority / PKG (Local Machine)

**Runs:**
- `Setup(λ, U, T)` → generates `(mpk, msk)`
- `UserKG(mpk, msk, ID, S)` → issues `(sk_ID, vk_ID, psk_{ID,S})`
- `TKeyUp(mpk, msk, R, t)` → generates `tuk_t`
- `Revoke(ID, t, R, st)` → updates revocation list

**Responsibilities:**
- `msk` **never** leaves the local environment
- `sk_ID` delivered to users out-of-band (not via S3)
- `vk_ID` is public — freely distributable
- `tuk_t` is public — can be uploaded to S3 config bucket
- `psk_{ID,S}` delivered to user out-of-band; user sends to server for TranKG

### Cloud Server / Lambda (Honest-but-Curious)

**Allowed operations:**
- AES-256-GCM encryption of plaintext
- PV-SR-ABE encryption of session key
- Storage of `{enc, aes}` bundle
- `TranKG(mpk, psk_{ID,S}, tuk_t)` → `tk^S_{ID,t}` (with psk from user)
- `Transform(mpk, c, tk, ID)` → `π`

**Forbidden operations (by design):**
- `UserKG` (no msk)
- `Decrypt` (no sk_ID)
- Direct access to plaintext or session key

**The cloud stores ciphertext only.** It can compute the transformed ciphertext π but cannot learn the session key `key_GT` or plaintext from π alone.

### Data User / Client (Local)

**Client performs all sensitive operations locally:**
```
TranKG(mpk, psk_id_s, tuk_t)   ← locally (simulated in client_decrypt.py)
Transform(mpk, c, tk, ID)      ← locally
Verify(mpk, c, π, vk_id, ID)   ← locally (can also be done by third party)
Decrypt(mpk, sk_id, π, Hdr, ID) ← locally
AES-256-GCM.Dec(C_AES, DEK)    ← locally
```

**Decryption always occurs on the client device.** The cloud never receives `sk_ID` or the recovered `key_GT`.

---

## 6. Deployment Steps
### Step 1 — Build Docker Image

```bash
docker build -t pv-sr-abe:poc .
```

The image includes:
- Python 3.10 runtime
- GMP (C library)
- PBC 0.5.14 (compiled with OpenSSL 1.1)
- charm-crypto (built from source: `github.com/JHUISI/charm`)
- Project Python files

**OpenSSL note:** The Dockerfile pins OpenSSL 1.1 (`openssl11-devel`) to avoid the `EVP_MD_CTX_free` symbol error that occurs when PBC extensions link against a newer OpenSSL at runtime.

### Step 3 — Push Image to AWS ECR

```bash
REGION=ap-southeast-2
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

aws ecr create-repository --repository-name pv-sr-abe --region $REGION

aws ecr get-login-password --region $REGION \
  | docker login --username AWS --password-stdin \
    $ACCOUNT.dkr.ecr.$REGION.amazonaws.com

docker tag pv-sr-abe:poc \
    $ACCOUNT.dkr.ecr.$REGION.amazonaws.com/pv-sr-abe:poc

docker push $ACCOUNT.dkr.ecr.$REGION.amazonaws.com/pv-sr-abe:poc
```

### Step 4 — Create Lambda Function

Create Lambda using Container Image.

**Configuration:**
- Memory: ≥ 1024 MB (required for PBC pairing arithmetic over SS512)
- Timeout: ≥ 120 s (first Charm-Crypto import can be slow on cold start)
- Handler: `lambda_handler.handler`
- Environment: `OUTPUT_BUCKET=ade-abe-policy-output`

```bash
aws lambda create-function \
    --function-name pv-sr-abe-encrypt \
    --package-type  Image \
    --code          ImageUri=$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/pv-sr-abe:poc \
    --role          $LAMBDA_ROLE_ARN \
    --environment   "Variables={OUTPUT_BUCKET=your-demo-bucket}" \
    --timeout       120 \
    --memory-size   1024 \
    --region        $REGION
```

### Step 5 — Configure S3 Trigger

```bash
# Input bucket
aws s3 mb s3://ade-abe-policy-input --region $REGION

# Allow S3 to invoke Lambda
aws lambda add-permission \
    --function-name pv-sr-abe-encrypt \
    --statement-id  s3-trigger \
    --action        lambda:InvokeFunction \
    --principal     s3.amazonaws.com \
    --source-arn    arn:aws:s3:::your-demo-bucket

# Set S3 notification
aws s3api put-bucket-notification-configuration \
    --bucket your-demo-bucket \
    --notification-configuration '{
        "LambdaFunctionConfigurations": [{
            "LambdaFunctionArn": "'$LAMBDA_ARN'",
            "Events": ["s3:ObjectCreated:*"]
        }]
    }'
```

### Step 6 — Upload and Encrypt via S3 Trigger

```bash
# Upload plaintext file → triggers Lambda automatically
echo "confidential record" | \
    aws s3 cp - s3://ade-abe-policy-input/inbox/record.txt

# Lambda automatically:
#  ① reads plaintext from S3
#  ② generates random key_GT
#  ③ C_AES  = AES-GCM.Enc(M, DEK)
#  ④ CT_ABE = PV-SR-ABE.Enc(key_GT, mpk, policy, t')
#  ⑤ writes result.json to output bucket
```

### Step 7 — Local Encrypt (CLI path, full ABE)

```bash
python lambda_encrypt.py \
    --setup     keys/pv_setup.json \
    --policy    "(A and C)" \
    --t         1 \
    --plaintext "confidential record" \
    --store_dir keys/store
# → prints <object_id>
```

### Step 8 — Client Decrypt

```bash
python client_decrypt.py \
    --setup     keys/pv_setup.json \
    --user      keys/alice_user.json \
    --tuk       keys/tuk_t1.json \
    --object_id <uuid> \
    --store_dir keys/store
# → [CLIENT] Verify PASSED
# → [CLIENT] Plaintext: confidential record
```

### Step 9 — Observe CloudWatch Execution

```
START RequestId: …
Lambda handler invoked
bucket=ade-abe-policy-input, key=ipublic-verification.txt
wrote result to s3://your-demo-bucket/results/test.txt.result.json
END RequestId: …
Duration: 134.34 ms Billed Duration: 1141 ms Memory Size: 1024 MB Max Memory Used: 86 MB Init Duration: 1006.58 ms
```

---

## 7. Revocation Deployment

Revoking a user does not require re-encrypting existing data. Only future time-update keys exclude the revoked user.

```bash
# PKG: Revoke bob at time period t=2
python ta_local.py revoke \
    --setup keys/pv_setup.json \
    --id    bob@example.com \
    --t     2

# PKG: Issue new TUK for t=2 (excludes bob from KUNodes)
python ta_local.py tkeyup \
    --setup keys/pv_setup.json \
    --t     2 \
    --out   keys/tuk_t2.json

# bob's attempt to decrypt ciphertext encrypted at t'=2 will fail:
# TranKG returns ⊥ (bob's leaf not in KUNodes for t=2)
```


## 9. PoC Design Note

For simplicity and reproducibility, the PoC executes some operations locally that in a full deployment would be separated:

| PoC | Full Production |
|---|---|
| TranKG run locally in `client_decrypt.py` | TranKG run by cloud server; tk sent back to client |
| PKG keys stored in JSON file | PKG keys in HSM; operations via secure API |
| Object store = local JSON files | Object store = AWS S3 with versioning |
| Single Lambda for everything | Separate Encrypt Service / Verify Gateway / Update Service |

---

## 10. Deployment Outcome

This deployment demonstrates:
- transformation of a pairing-based academic cryptographic scheme into a working cloud system
- secure key isolation: `msk` never enters AWS; `sk_id` never enters S3
- publicly verifiable server computation: `Verify` can be run by any party
- efficient user revocation via binary tree KUNodes (O(|R| log N) TUK size)
- serverless cryptographic execution with Docker on AWS Lambda

**The cloud never gains access to plaintext or master secrets.**
