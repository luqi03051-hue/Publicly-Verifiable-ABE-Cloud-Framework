# -*- coding: utf-8 -*-
"""
client_decrypt.py  (Client role: TranKG → Transform → Verify → Decrypt)
------------------------------------------------------------------------
Workflow:
  1. Load user key (psk_id_s, sk_id, vk_id) and time-update key (tuk_t).
  2. Run TranKG (server role, here simulated locally) to get tk^S_{ID,t}.
  3. Run Transform to get π = e(u0^r, g^s).
  4. Public-Verify the transformation result.
  5. Decrypt to recover the GT session key, then AES-GCM decrypt plaintext.

Example:
  python client_decrypt.py \\
      --setup    keys/pv_setup.json \\
      --user     keys/bob_user.json \\
      --tuk      keys/tuk_4.json \\
      --object_id <OID> \\
      --store_dir keys/store
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from typing import Any, Dict

from charm.toolbox.pairinggroup import PairingGroup

import pv_core


# ── small I/O helpers ────────────────────────────────────────────────────────

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def _store_get(store_dir: str, obj_id: str) -> Dict[str, Any]:
    path = os.path.join(store_dir, f"{obj_id}.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ── crypto helpers ────────────────────────────────────────────────────────────

def _kdf(group: PairingGroup, key_gt: Any) -> bytes:
    """Derive a 32-byte AES key from a GT element via SHA-256."""
    return hashlib.sha256(group.serialize(key_gt)).digest()

def _aes_gcm_decrypt(key: bytes, nonce_b64: str, ct_b64: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:
        raise RuntimeError(
            "Missing dependency: install 'cryptography' (pip install cryptography)."
        ) from e

    return AESGCM(key).decrypt(_b64d(nonce_b64), _b64d(ct_b64), None)


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="PV-SR-ABE decrypt")
    ap.add_argument("--setup",     default="keys/pv_setup.json",
                    help="Setup JSON produced by ta_local.py setup")
    ap.add_argument("--user",      required=True,
                    help="User key JSON produced by ta_local.py userkg")
    ap.add_argument("--tuk",       required=True,
                    help="Time-update key JSON produced by ta_local.py tkeyup")
    ap.add_argument("--object_id", required=True,
                    help="Object ID printed by lambda_encrypt.py")
    ap.add_argument("--store_dir", default="keys/store",
                    help="Directory that holds ciphertext bundles")
    args = ap.parse_args()

    # ── load all key material ─────────────────────────────────────────────────
    group, mpk, _msk, _st = pv_core.load_setup_json(args.setup)

    user = pv_core.load_user(group, pv_core.load_json(args.user))
    up   = pv_core.load_tuk(group,  pv_core.load_json(args.tuk))

    # ── load ciphertext bundle ────────────────────────────────────────────────
    bundle = _store_get(args.store_dir, args.object_id)
    enc    = pv_core.load_encrypt(group, bundle["enc"])

    # ── Step 2: TranKG (server role) ──────────────────────────────────────────
    # Intersect Path(θ) with KUNodes to build short-term transformation key.
    # tuk_t is accessed via up.tuk_t (TKeyUpResult dataclass).
    tk_res = pv_core.trankg(mpk, user.psk_id_s, up.tuk_t, t=enc.t_prime)
    if tk_res is None:
        raise SystemExit(
            "[CLIENT] TranKG returned ⊥  "
            "(user revoked, or time mismatch between tuk and ciphertext)"
        )

    # ── Step 3: Transform (server role) ───────────────────────────────────────
    # tk_res is a TranKGResult; pass tk_res.tk_id_t_s (the dict) to transform().
    tr = pv_core.transform(mpk, enc, tk_res.tk_id_t_s, ID=user.ID)
    if tr is None or not tr.ok:
        raise SystemExit(
            "[CLIENT] Transform failed  "
            "(policy not satisfied, or time period mismatch)"
        )

    # ── Step 4: Public Verify ─────────────────────────────────────────────────
    ok = pv_core.verify(mpk, enc, tr.pi, user.vk_id, ID=user.ID)
    if not ok:
        raise SystemExit(
            "[CLIENT] Verify FAILED  "
            "(cloud transformation is incorrect — aborting)"
        )
    print("[CLIENT] Verify PASSED")

    # ── Step 5: Decrypt → recover GT session key ──────────────────────────────
    key_gt = pv_core.decrypt(mpk, user.sk_id, tr.pi, enc.hdr, ID=user.ID)

    # ── Step 6: AES-GCM decrypt plaintext ─────────────────────────────────────
    dek = _kdf(group, key_gt)
    pt  = _aes_gcm_decrypt(dek, bundle["aes"]["nonce"], bundle["aes"]["ct"])

    print("[CLIENT] Plaintext:", pt.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()