# -*- coding: utf-8 -*-
"""
lambda_encrypt.py  (Cloud role: Encrypt + store)
------------------------------------------------
Uses PV-SR-ABE from pv_core.py to encrypt a session key under an access
policy, then AES-GCM encrypts the actual plaintext with that session key.

Example:
  python lambda_encrypt.py \\
      --setup keys/pv_setup.json \\
      --policy "(A and B)" \\
      --t 4 \\
      --plaintext "hello world" \\
      --store_dir keys/store

Prints the object_id that client_decrypt.py needs.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import uuid
from typing import Any, Dict

from charm.toolbox.pairinggroup import PairingGroup, GT

import pv_core


# ── small I/O helpers ────────────────────────────────────────────────────────

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def _store_put(store_dir: str, obj_id: str, payload: Dict[str, Any]) -> str:
    os.makedirs(store_dir, exist_ok=True)
    path = os.path.join(store_dir, f"{obj_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


# ── crypto helpers ────────────────────────────────────────────────────────────

def _kdf(group: PairingGroup, key_gt: Any) -> bytes:
    """Derive a 32-byte AES key from a GT element via SHA-256."""
    return hashlib.sha256(group.serialize(key_gt)).digest()

def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Dict[str, str]:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:
        raise RuntimeError(
            "Missing dependency: install 'cryptography' (pip install cryptography)."
        ) from e

    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return {"nonce": _b64e(nonce), "ct": _b64e(ct)}


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="PV-SR-ABE encrypt")
    ap.add_argument("--setup",     default="keys/pv_setup.json",
                    help="Setup JSON produced by ta_local.py setup")
    ap.add_argument("--policy",    required=True,
                    help='Access policy string, e.g. "(A and B) or C"')
    ap.add_argument("--t",         type=int, required=True,
                    help="Time period t' for Encrypt")
    ap.add_argument("--plaintext", required=True,
                    help="Plaintext string to encrypt")
    ap.add_argument("--store_dir", default="keys/store",
                    help="Directory to store the ciphertext bundle")
    args = ap.parse_args()

    # Load public params (msk / st not needed for encryption)
    group, mpk, _msk, _st = pv_core.load_setup_json(args.setup)

    # 1) Sample a random GT session key; wrap it under PV-SR-ABE
    key_gt = group.random(GT)
    enc    = pv_core.encrypt_by_policy(
                 mpk, policy_str=args.policy, t_prime=args.t, msg=key_gt)

    # 2) Derive AES key and encrypt the plaintext
    dek = _kdf(group, key_gt)
    aes = _aes_gcm_encrypt(dek, args.plaintext.encode("utf-8"))

    # 3) Serialise ciphertext bundle and write to store
    obj_id = str(uuid.uuid4())
    bundle = {
        "scheme":    "PV-SR-ABE",
        "curve":     mpk["curve"],
        "setup_ref": args.setup,
        "enc":       pv_core.dump_encrypt(group, enc),
        "aes":       aes,
    }
    path = _store_put(args.store_dir, obj_id, bundle)

    # Print obj_id first so callers can capture it easily
    print(obj_id)
    print(f"[ENCRYPT] Bundle stored -> {path}  (policy='{args.policy}', t={args.t})")


if __name__ == "__main__":
    main()