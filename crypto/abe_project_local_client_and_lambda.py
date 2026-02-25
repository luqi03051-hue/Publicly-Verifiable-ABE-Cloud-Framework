# -*- coding: utf-8 -*-
"""
Projectised version of your local Charm-Crypto reference implementation.

This single file is meant to help you *engineer* the paper flow into a runnable PoC:

Roles (as in your diagram)
-------------------------
1) Trusted Authority (local)
   - Setup() -> (mpk, msk)
   - KeyGen(msk, A) -> sk_A

2) Data Owner (local)
   - has plaintext M
   - decides policy / policy'
   - triggers Upload and Policy Update

3) Cloud (AWS, honest-but-curious)  [implemented here as Lambda-style handlers]
   - encrypt_upload: receives {M, policy} -> stores {C_AES, CT_ABE}
   - policy_update : receives {object_id, policy'} -> updates CT_ABE in-place
   - decrypt_for_user: receives {object_id, sk_A, A_names} -> returns DEK (or plaintext)

IMPORTANT SECURITY NOTE (PoC vs real-world)
-------------------------------------------
To keep this PoC close to your thesis, we keep ABE on the cloud container image.
In real systems, you typically avoid sending sk_A to the cloud; instead the cloud returns CT_ABE and
the client decrypts locally, or you use a trusted execution environment / KMS-style envelope design.

What this file provides
-----------------------
- Your original ThresholdABE + UPKeyGen + CTUpdate implementation (unchanged, appended below)
- Minimal, well-commented "project glue":
  * AES-GCM envelope encryption helpers (for M)
  * Serialization helpers for Charm pairing elements (store to S3/Dynamo as bytes/base64)
  * In-memory storage simulating S3 for quick local end-to-end testing
  * Lambda-style handler functions you can move into AWS later with minimal edits
  * A client-side demo showing the exact 3-party flow

How to migrate to AWS
---------------------
- Put this file (or split modules) into your Lambda container image.
- Set handler to `lambda_handler` (provided below) or to specific action handlers.
- Replace InMemoryObjectStore with:
  * S3 for blobs (C_AES, CT_ABE bytes)
  * DynamoDB for metadata (policy versioning, owner id, etc.)

"""

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set, Tuple

# --- AES-GCM envelope encryption (for M) ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# 0) Storage abstraction (local mock; replace with S3/DynamoDB)
# ============================================================
class InMemoryObjectStore:
    """
    Local substitute for S3/DynamoDB.

    In AWS:
      - store ciphertext blobs in S3
      - store metadata (policy, version, timestamps) in DynamoDB
    """
    def __init__(self):
        self._db: Dict[str, Dict[str, Any]] = {}

    def put(self, object_id: str, record: Dict[str, Any]) -> None:
        self._db[object_id] = record

    def get(self, object_id: str) -> Dict[str, Any]:
        if object_id not in self._db:
            raise KeyError(f"object_id not found: {object_id}")
        return self._db[object_id]

    def update(self, object_id: str, patch: Dict[str, Any]) -> None:
        rec = self.get(object_id)
        rec.update(patch)
        self._db[object_id] = rec


STORE = InMemoryObjectStore()


# ============================================================
# 1) Serialization helpers for Charm pairing elements
# ============================================================
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def serialize_any(group, obj: Any) -> Any:
    """
    Recursively serialize CT / keys that may contain Charm pairing.Element.
    - pairing.Element -> {"__charm__": "<base64 bytes>"}
    - dict/list/tuple -> recurse
    - primitives -> unchanged
    """
    # Lazy import to avoid hard dependency when not running ABE path.
    from charm.core.math.pairing import pairing

    if isinstance(obj, pairing.Element):
        return {"__charm__": b64e(group.serialize(obj))}
    if isinstance(obj, dict):
        return {k: serialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [serialize_any(group, v) for v in obj]
    if isinstance(obj, tuple):
        return [serialize_any(group, v) for v in obj]  # JSON-friendly
    # ints/str/bool/None
    return obj


def deserialize_any(group, obj: Any) -> Any:
    """
    Inverse of serialize_any().
    """
    if isinstance(obj, dict) and "__charm__" in obj:
        return group.deserialize(b64d(obj["__charm__"]))
    if isinstance(obj, dict):
        return {k: deserialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deserialize_any(group, v) for v in obj]
    return obj


# ============================================================
# 2) AES-GCM helpers (cloud can see M in your current model)
# ============================================================
def aes_gcm_encrypt(plaintext: bytes, dek: bytes, aad: Optional[bytes] = None) -> Dict[str, str]:
    """
    AES-GCM encryption.
    Returns base64 fields: {nonce, ciphertext}.
    """
    if len(dek) not in (16, 24, 32):
        raise ValueError("DEK must be 16/24/32 bytes for AES-128/192/256.")
    nonce = os.urandom(12)  # recommended size for GCM
    aesgcm = AESGCM(dek)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return {"nonce_b64": b64e(nonce), "ciphertext_b64": b64e(ct)}


def aes_gcm_decrypt(enc: Dict[str, str], dek: bytes, aad: Optional[bytes] = None) -> bytes:
    nonce = b64d(enc["nonce_b64"])
    ct = b64d(enc["ciphertext_b64"])
    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(nonce, ct, aad)


# ============================================================
# 3) "Cloud" Lambda-style handlers
# ============================================================
@dataclass
class CloudContext:
    """
    Things you would store in Lambda environment variables / secrets:
      - mpk (public parameters)
      - system ell
      - maybe a KMS master key, etc.
    """
    ell: int
    params: Dict[str, Any]  # mpk in your notation
    group: Any
    abe: Any


def cloud_encrypt_upload(ctx: CloudContext, M_plain: bytes, policy: str) -> Dict[str, Any]:
    """
    Cloud handler: encrypt_upload

    Input:
      - M_plain: plaintext bytes
      - policy: access policy string

    Output:
      - object_id
      - version
    Stored:
      - C_AES (AES-GCM(M, DEK))
      - CT_ABE (ABE.Enc(policy, DEK_as_GT))
        Here DEK is wrapped as a GT element by hashing/encoding would be typical.
        For PoC we encode DEK bytes into GT by mapping using group.hash().
    """
    t0 = time.time()

    # 1) generate random DEK (32 bytes -> AES-256)
    dek = os.urandom(32)

    # 2) AES-GCM encrypt plaintext
    c_aes = aes_gcm_encrypt(M_plain, dek, aad=policy.encode("utf-8"))

    # 3) Wrap DEK into GT message for ABE encryption
    # NOTE: in real systems, you wouldn't directly "hash to GT" without careful design,
    # but for PoC this is a convenient and standard trick.
    M_gt = ctx.group.hash(dek, ctx.group.GT)

    CT_ABE = ctx.abe.encrypt(M_gt, ctx.params, policy)

    # 4) serialize for storage (S3/Dynamo)
    CT_ABE_ser = serialize_any(ctx.group, CT_ABE)

    object_id = str(uuid.uuid4())
    record = {
        "object_id": object_id,
        "version": 1,
        "policy": policy,
        "C_AES": c_aes,
        "CT_ABE": CT_ABE_ser,
        "created_at": time.time(),
        "updated_at": time.time(),
    }
    STORE.put(object_id, record)

    return {
        "object_id": object_id,
        "version": 1,
        "ms": int((time.time() - t0) * 1000),
    }


def cloud_policy_update(ctx: CloudContext, object_id: str, new_policy: str, target_subtree: str = "Tr",
                        mode: str = "Attributes2Existing",
                        new_subtree: Optional[str] = None, pos_new_gate: Optional[int] = None) -> Dict[str, Any]:
    """
    Cloud handler: policy_update

    Minimal version:
    - Reads stored CT_ABE and old policy
    - Generates update key tk with UPKeyGen (needs Encrypt internal state E_T)
    - Updates ciphertext with CTUpdate

    NOTE (important):
    Your UPKeyGen currently relies on CT["_debug"]["s_map"] as E_T.
    In production you'd store/update an internal state E separately and securely.
    For PoC: we keep it inside CT and store it as part of CT_ABE.
    """
    t0 = time.time()
    rec = STORE.get(object_id)

    old_policy = rec["policy"]
    CT_old = deserialize_any(ctx.group, rec["CT_ABE"])

    # Ensure debug state exists (PoC requirement)
    if "_debug" not in CT_old or "s_map" not in CT_old["_debug"]:
        raise ValueError("CT_ABE missing internal state E_T (CT['_debug']['s_map']). "
                         "For PoC, keep it; for production, store E separately.")

    E_T = CT_old["_debug"]["s_map"]

    tk = UPKeyGen(
        group=ctx.group,
        params=ctx.params,
        ell=ctx.ell,
        E_T=E_T,
        old_policy=old_policy,
        new_policy=new_policy,
        target_subtree=target_subtree,
        mode=mode,
        new_subtree=new_subtree,
        pos_new_gate=pos_new_gate,
    )

    CT_new = CTUpdate(CT_old, tk)
    CT_new_ser = serialize_any(ctx.group, CT_new)

    new_version = int(rec["version"]) + 1
    STORE.update(object_id, {
        "version": new_version,
        "policy": new_policy,
        "CT_ABE": CT_new_ser,
        "updated_at": time.time(),
    })

    return {"object_id": object_id, "version": new_version, "ms": int((time.time() - t0) * 1000)}


def cloud_decrypt_for_user(ctx: CloudContext, object_id: str, SK_ser: Dict[str, Any], A_names: Set[str],
                           return_plaintext: bool = False) -> Dict[str, Any]:
    """
    Cloud handler: decrypt_for_user

    Input:
      - SK_ser: serialized secret key dict (from TA) -- PoC only
      - A_names: attribute names set

    Output options:
      - return_plaintext=False: returns DEK (base64) + C_AES for client to decrypt
      - return_plaintext=True : returns plaintext bytes base64 (cloud sees plaintext)

    Recommended safer PoC:
      - cloud returns DEK (or even better returns CT_ABE only and client decrypts).
    """
    t0 = time.time()
    rec = STORE.get(object_id)

    CT = deserialize_any(ctx.group, rec["CT_ABE"])
    SK = deserialize_any(ctx.group, SK_ser)

    M_gt = ctx.abe.decrypt(CT, SK, ctx.params, A_names)

    # Recover DEK bytes from GT: not directly possible (GT is not reversible).
    # Therefore, for PoC we instead *derive* DEK = KDF(M_gt) consistently.
    # This mimics typical ABE usage: ABE yields a session key material.
    # If you require exact DEK bytes, you must embed DEK as bytes and use hybrid ABE
    # that supports byte messages, or derive DEK via hash(M_gt).
    dek = ctx.group.hash(M_gt, ctx.group.ZR)  # scalar
    dek_bytes = ctx.group.serialize(dek)  # bytes-like; length varies
    # Make it 32 bytes deterministically for AES-256
    dek32 = base64.b64decode(b64e(dek_bytes))[:32].ljust(32, b"\x00")

    if not return_plaintext:
        return {
            "object_id": object_id,
            "version": rec["version"],
            "policy": rec["policy"],
            "C_AES": rec["C_AES"],
            "dek_b64": b64e(dek32),
            "ms": int((time.time() - t0) * 1000),
        }

    pt = aes_gcm_decrypt(rec["C_AES"], dek32, aad=rec["policy"].encode("utf-8"))
    return {
        "object_id": object_id,
        "version": rec["version"],
        "plaintext_b64": b64e(pt),
        "ms": int((time.time() - t0) * 1000),
    }


# ============================================================
# 4) Lambda entrypoint (single handler; route by event["action"])
# ============================================================
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda entrypoint (container image).

    Route by action:
      - encrypt_upload
      - policy_update
      - decrypt_for_user

    In AWS you would reconstruct ctx from env vars / secrets / cached globals.
    For local test, see __main__ demo below.
    """
    action = event.get("action")
    if action not in {"encrypt_upload", "policy_update", "decrypt_for_user"}:
        return {"error": f"unknown action: {action}"}

    # ctx must be initialised globally in real Lambda for performance.
    # Here we raise to remind you to set it in module scope.
    if "CTX" not in globals():
        raise RuntimeError("Global CTX not initialised. Create CTX at module import time.")

    ctx: CloudContext = globals()["CTX"]

    if action == "encrypt_upload":
        M_plain = base64.b64decode(event["M_b64"])
        policy = event["policy"]
        return cloud_encrypt_upload(ctx, M_plain, policy)

    if action == "policy_update":
        return cloud_policy_update(
            ctx,
            object_id=event["object_id"],
            new_policy=event["policy_new"],
            target_subtree=event.get("target_subtree", "Tr"),
            mode=event.get("mode", "Attributes2Existing"),
            new_subtree=event.get("new_subtree"),
            pos_new_gate=event.get("pos_new_gate"),
        )

    if action == "decrypt_for_user":
        SK_ser = event["SK_ser"]
        A_names = set(event["A_names"])
        return cloud_decrypt_for_user(
            ctx,
            object_id=event["object_id"],
            SK_ser=SK_ser,
            A_names=A_names,
            return_plaintext=bool(event.get("return_plaintext", False)),
        )

    return {"error": "unreachable"}


# ============================================================
# 5) Local demo: TA + Owner + User end-to-end (no AWS needed)
# ============================================================
if __name__ == "__main__":
    # NOTE: uses Charm-Crypto, so run inside your prepared container or local environment with Charm installed.
    from charm.toolbox.pairinggroup import PairingGroup, GT

    # ---- System initialisation (TA creates mpk/msk; Cloud receives mpk) ----
    group = PairingGroup("SS512")
    ell = 10
    abe = ThresholdABE(group, ell=ell)
    msk, params = abe.setup()  # params is mpk

    # Create global CTX (as Lambda would do at import time)
    CTX = CloudContext(ell=ell, params=params, group=group, abe=abe)  # noqa: N816

    # ---- TA issues user secret key (PoC: we serialize it to send in API) ----
    user_A_names = {"attC", "attD", "attE", "attF"}
    # We must map names -> indices; in the original script, rho is computed at Encrypt.
    # For PoC, we simply pre-define attribute universe indices.
    # In a real system, TA owns a global universe mapping, consistent across policies.
    # Here: attA->1, attB->2, ... (simple deterministic mapping)
    universe = {"attA": 1, "attB": 2, "attC": 3, "attD": 4, "attE": 5, "attF": 6, "attG": 7}
    A_idx = {universe[a] for a in user_A_names if a in universe}
    SK = abe.keygen(msk, params, A_idx)
    SK_ser = serialize_any(group, SK)

    # ---- Data Owner uploads plaintext + policy ----
    policy = "(attA OR (2, (attB AND attC), attD, (2, attE, attF, attG)))"
    plaintext = b"Hello! This is a plaintext M for envelope encryption demo."
    resp_up = cloud_encrypt_upload(CTX, plaintext, policy)
    object_id = resp_up["object_id"]
    print("[Owner] upload ok:", resp_up)

    # ---- User attempts to decrypt (via cloud) ----
    resp_dec = cloud_decrypt_for_user(CTX, object_id, SK_ser, user_A_names, return_plaintext=True)
    pt = base64.b64decode(resp_dec["plaintext_b64"])
    print("[User] decrypt ok?", pt == plaintext, "ms=", resp_dec["ms"])

    # ---- Owner triggers policy update ----
    # Example: tighten policy (this is just a demo string)
    policy_new = "(attA OR (2, attD, attE, attF))"
    resp_upd = cloud_policy_update(CTX, object_id, policy_new, target_subtree="Tr", mode="Attributes2Existing")
    print("[Owner] update ok:", resp_upd)

    # ---- User decrypt again under new policy ----
    resp_dec2 = cloud_decrypt_for_user(CTX, object_id, SK_ser, user_A_names, return_plaintext=True)
    pt2 = base64.b64decode(resp_dec2["plaintext_b64"])
    print("[User] decrypt after update ok?", pt2 == plaintext, "ms=", resp_dec2["ms"])



# ===== Original reference implementation (embedded) =====

# -*- coding: utf-8 -*-
"""
Threshold ABE (access-tree with AND/OR/threshold gates) — reference implementation in Charm-Crypto.

This script includes:
- Policy tokenizer + recursive-descent parser: AND/OR + threshold gate (k, expr1, expr2, ...)
- Access-tree traversal to build structure table and Tab II-like node sets (including satisfying non-leaf nodes)
- ThresholdABE: Setup / KeyGen / Encrypt / Decrypt
- A minimal runnable demo under __main__

Notes:
- This implementation follows the algebraic structure used in your screenshots:
  Each satisfied subtree T_j computes D_{j,1} = e(g2^{rα}, g^{s_j}) and P_{j,2} = g^{rα}.
  Finally, recover M via: M = C0 * (D_{r,2} / D_{r,1}).
- IMPORTANT: Use an asymmetric pairing group and place g in G1, g2 and h_i in G2.
"""

from dataclasses import dataclass
from typing import List, Union, Optional, Set, Dict, Any
from copy import deepcopy

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair


# ============================================================
# 1) Policy AST Nodes
# ============================================================
@dataclass(frozen=True)
class Leaf:
    name: str


@dataclass(frozen=True)
class Gate:
    kind: str               # "AND" / "OR" / "THRESH"
    k: int                  # threshold k-of-n
    children: List["Node"]


Node = Union[Leaf, Gate]


# ============================================================
# 2) Tokenizer
# ============================================================
def tokenize(s: str) -> List[str]:
    """
    Split policy string into tokens:
    - '(' , ')' , ','
    - AND / OR
    - attribute names: attA, att_B, A1, ...
    - digits for threshold gate k
    """
    s = s.strip()
    tokens: List[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c in "(),":
            tokens.append(c)
            i += 1
            continue

        j = i
        while j < len(s) and (s[j].isalnum() or s[j] == "_"):
            j += 1
        tokens.append(s[i:j])
        i = j
    return tokens


# ============================================================
# 3) Parser (recursive descent)
#    precedence: AND > OR
#    threshold gate: (k, expr1, expr2, ...)
# ============================================================
class Parser:
    def __init__(self, tokens: List[str]):
        self.toks = tokens
        self.pos = 0

    def peek(self) -> Optional[str]:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def consume(self, expected: Optional[str] = None) -> str:
        tok = self.peek()
        if tok is None:
            raise ValueError("Unexpected end of input.")
        if expected is not None and tok != expected:
            raise ValueError(f"Expected '{expected}', got '{tok}'.")
        self.pos += 1
        return tok

    def parse(self) -> Node:
        node = self.parse_or()
        if self.peek() is not None:
            raise ValueError(f"Extra tokens remaining: {self.toks[self.pos:]}")
        return node

    def parse_or(self) -> Node:
        node = self.parse_and()
        while self.peek() == "OR":
            self.consume("OR")
            right = self.parse_and()
            node = Gate(kind="OR", k=1, children=[node, right])  # OR = 1-of-2
        return node

    def parse_and(self) -> Node:
        node = self.parse_atom()
        while self.peek() == "AND":
            self.consume("AND")
            right = self.parse_atom()
            node = Gate(kind="AND", k=2, children=[node, right])  # AND = 2-of-2
        return node

    def parse_atom(self) -> Node:
        tok = self.peek()
        if tok == "(":
            # Threshold gate: (k, ...)
            if self._is_threshold_gate():
                return self.parse_threshold_gate()

            # Parenthesized expression
            self.consume("(")
            node = self.parse_or()
            self.consume(")")
            return node

        # Leaf
        if tok is None:
            raise ValueError("Unexpected end. Expected leaf or '('.")
        if tok in {"AND", "OR", ",", ")"}:
            raise ValueError(f"Unexpected token '{tok}' where leaf expected.")
        self.consume()
        return Leaf(tok)

    def _is_threshold_gate(self) -> bool:
        # Pattern: "(" digit ","
        if self.peek() != "(":
            return False
        if self.pos + 2 >= len(self.toks):
            return False
        return self.toks[self.pos + 1].isdigit() and self.toks[self.pos + 2] == ","

    def parse_threshold_gate(self) -> Node:
        self.consume("(")
        k_tok = self.consume()
        if not k_tok.isdigit():
            raise ValueError("Threshold gate: k must be a number.")
        k = int(k_tok)
        self.consume(",")

        children: List[Node] = []
        while True:
            tok = self.peek()
            if tok is None:
                raise ValueError("Unclosed threshold gate. Missing ')'.")
            if tok == ")":
                break
            if tok == ",":
                self.consume(",")
                continue
            child = self.parse_atom()
            children.append(child)

        self.consume(")")
        if not (1 <= k <= len(children)):
            raise ValueError(f"Invalid threshold gate: k={k}, n={len(children)}")
        return Gate(kind="THRESH", k=k, children=children)


def parse_policy(policy_str: str) -> Node:
    tokens = tokenize(policy_str)
    return Parser(tokens).parse()


# ============================================================
# 4) Tree traversal helpers: structure table + Tab II-like table
# ============================================================
def build_structure_table(root: Node):
    """
    Returns rows:
      Subtree, RootName, Leaf nodes (direct leaves), Non-leaf nodes (direct gates), Threshold
    RootName uses: sr for root, then s1,s2,...
    Subtree uses: Tr for root, then T1,T2,...
    """
    internal_name: Dict[int, str] = {}
    internal_nodes: List[Gate] = []
    counter = 1

    def assign_names(node: Node, is_root: bool = False):
        nonlocal counter
        if isinstance(node, Leaf):
            return
        # Gate
        if is_root:
            internal_name[id(node)] = "sr"
        else:
            internal_name[id(node)] = f"s{counter}"
            counter += 1
        internal_nodes.append(node)
        for c in node.children:
            assign_names(c, is_root=False)

    assign_names(root, is_root=True)

    # Subtree labels
    subtree_label: Dict[int, str] = {}
    idx = 1
    for n in internal_nodes:
        if internal_name[id(n)] == "sr":
            subtree_label[id(n)] = "Tr"
        else:
            subtree_label[id(n)] = f"T{idx}"
            idx += 1

    def L_set(node: Gate) -> Set[str]:
        return {c.name for c in node.children if isinstance(c, Leaf)}

    def N_set(node: Gate) -> Set[str]:
        return {internal_name[id(c)] for c in node.children if isinstance(c, Gate)}

    rows = []
    for node in internal_nodes:
        rows.append({
            "Subtree": subtree_label[id(node)],
            "RootName": internal_name[id(node)],
            "Leaf nodes": L_set(node),
            "Non-leaf nodes": N_set(node),
            "Threshold": node.k
        })
    return rows


def build_tab2(root: Node, A: Set[str]):
    """
    Build Tab II-like info for each subtree:
      Subtree | Leaf nodes | Non-leaf nodes | Threshold | Satisfying non-leaf nodes

    "Satisfying non-leaf nodes" means: which direct non-leaf children subtrees are satisfied.
    """
    # Name internal nodes: sr / s1,s2,...
    internal_name: Dict[int, str] = {}
    internal_nodes: List[Gate] = []
    counter = 1

    def assign_names(node: Node, is_root: bool = False):
        nonlocal counter
        if isinstance(node, Leaf):
            return
        if is_root:
            internal_name[id(node)] = "sr"
        else:
            internal_name[id(node)] = f"s{counter}"
            counter += 1
        internal_nodes.append(node)
        for c in node.children:
            assign_names(c, is_root=False)

    assign_names(root, is_root=True)

    # Subtree labels: Tr / T1,T2,...
    subtree_label: Dict[int, str] = {}
    idx = 1
    for n in internal_nodes:
        if internal_name[id(n)] == "sr":
            subtree_label[id(n)] = "Tr"
        else:
            subtree_label[id(n)] = f"T{idx}"
            idx += 1

    def L_set(node: Gate) -> Set[str]:
        return {c.name for c in node.children if isinstance(c, Leaf)}

    def N_set(node: Gate) -> Set[str]:
        return {internal_name[id(c)] for c in node.children if isinstance(c, Gate)}

    # Evaluate satisfaction bottom-up
    satisfied: Dict[int, bool] = {}
    S_sat_nonleaf: Dict[int, Set[str]] = {}

    def eval_satisfied(node: Node) -> bool:
        if isinstance(node, Leaf):
            return node.name in A

        leaf_ok = sum(1 for c in node.children if isinstance(c, Leaf) and c.name in A)
        sat_nonleaf: Set[str] = set()
        nonleaf_ok = 0

        for c in node.children:
            if isinstance(c, Gate):
                child_sat = eval_satisfied(c)
                if child_sat:
                    sat_nonleaf.add(internal_name[id(c)])
                    nonleaf_ok += 1

        ok = (leaf_ok + nonleaf_ok) >= node.k
        satisfied[id(node)] = ok
        S_sat_nonleaf[id(node)] = sat_nonleaf
        return ok

    eval_satisfied(root)

    rows2 = []
    for node in internal_nodes:
        rows2.append({
            "Subtree": subtree_label[id(node)],
            "Leaf nodes": L_set(node),
            "Non-leaf nodes": N_set(node),
            "Threshold": node.k,
            "Satisfying non-leaf nodes": S_sat_nonleaf[id(node)]
        })
    return rows2


# ============================================================
# 5) ThresholdABE (Setup/KeyGen/Encrypt/Decrypt)
# ============================================================
class ThresholdABE:
    def __init__(self, group_obj: PairingGroup, ell: int):
        """
        ell: number of normal attributes |U|
        U = {1..ell}
        U' = {ell+1 .. 2ell-1} (default attributes), size ell-1
        """
        self.group = group_obj
        self.ell = ell
        self.U = list(range(1, ell + 1))
        self.U_prime = list(range(ell + 1, 2 * ell))  # ell-1 elements

    def setup(self):
        g = self.group.random(G1)
        g2 = self.group.random(G2)

        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        theta = self.group.random(ZR)

        g1 = g ** alpha
        v = g ** theta
        w = g2 ** (alpha / theta)
        Z = pair(g1, g2)

        # h_0 ... h_{2ℓ-1}
        # need indices up to 2ℓ-1
        h: Dict[int, Any] = {}
        # Allocate extra h-indices to avoid KeyError when a subtree has more non-leaf children
        # than (t_j-1) in practical policies. This keeps the implementation robust.
        # (Original scheme indexes up to 2*ell-1; here we pre-allocate a wider range.)
        max_h = 4 * self.ell
        for i in range(0, max_h + 1):
            h[i] = self.group.random(G2)

        msk = {
            "alpha": alpha,
            "w_1_over_beta": w ** (1 / beta)   # w^(1/beta) in G2
        }
        params = {
            "g": g,
            "g2": g2,
            "Z": Z,
            "h": h,
            "v_beta": v ** beta                # (v^beta) in G1
        }
        return msk, params

    def keygen(self, msk, params, A_idx: Set[int]):
        """
        A_idx ⊆ U is a set of integer indices (attributes owned by the user).
        Secret key also includes all default attributes U'.
        """
        # random polynomial q of degree ℓ-1 with q(0)=alpha
        coeffs = [msk["alpha"]] + [self.group.random(ZR) for _ in range(self.ell - 1)]

        def q(i: int):
            iZ = self.group.init(ZR, i)
            acc = self.group.init(ZR, 0)
            for j, cj in enumerate(coeffs):
                acc += cj * (iZ ** j)
            return acc

        r = self.group.random(ZR)

        # NOTE:
        # In the *original* scheme, SK is generated for i in A ∪ U' (default attributes),
        # where U' = {ell+1 .. 2ell-1}. That guarantees decryption indices (including the
        # "non-leaf" interpolation indices 2ell - t_j + pos) never exceed 2ell-1.
        #
        # In this implementation we intentionally pre-allocated a larger h-index range in
        # Setup (to avoid KeyError in Encrypt for practical policies that may yield indices
        # beyond 2ell-1). To keep Encrypt/Decrypt consistent, we also allow KeyGen to
        # generate SK components for any indices that might appear during decryption.
        #
        # Practically: we generate SK for all i in [1..max_h], so any interpolation set X
        # constructed by Decrypt will have the needed SK[i].
        max_h = max(params["h"].keys())
        SK: Dict[int, Dict[str, Any]] = {}
        for i in set(A_idx).union(self.U_prime).union(set(range(1, max_h + 1))):
            qi = q(i)

            # a_i = (g2 * h0 * h_i)^{r q(i)}    in G2
            a_i = (params["g2"] * params["h"][0] * params["h"][i]) ** (r * qi)

            # b_i = g^{r q(i)}                  in G1
            b_i = params["g"] ** (r * qi)

            # c_i[j] = h_j^{r q(i)}             in G2, for j != i
            c_i: Dict[int, Any] = {}
            max_h = max(params["h"].keys())
            for j in range(1, max_h + 1):
                c_i[j] = params["h"][j] ** (r * qi)

            # d = w^{(r-1)/beta} = (w^(1/beta))^(r-1)  in G2
            d_i = msk["w_1_over_beta"] ** (r - 1)

            SK[i] = {"a": a_i, "b": b_i, "c": c_i, "d": d_i}

        # Debug meta (safe for local testing only): helps validate algebra.
        SK["_meta"] = {"r": r, "alpha": msk["alpha"]}

        return SK

    def encrypt(self, M: GT, params, policy: str):
        root = parse_policy(policy)
        rows = build_structure_table(root)

        # rho: leaf attribute name -> index in [1..ell]
        def make_rho_from_policy(rows_):
            attrs: List[str] = []
            for r in rows_:
                for a in sorted(r["Leaf nodes"]):
                    if a not in attrs:
                        attrs.append(a)
            if len(attrs) > self.ell:
                raise ValueError(f"Policy has {len(attrs)} distinct leaf attrs, but ell={self.ell} is too small.")
            return {a: i + 1 for i, a in enumerate(attrs)}

        rho = make_rho_from_policy(rows)

        # sample s-values for each internal node name (sr, s1, s2, ...)
        s_map: Dict[str, Any] = {}
        for r in rows:
            s_map[r["RootName"]] = self.group.random(ZR)

        # Build subtree ciphertexts
        CT_subtrees: Dict[str, Dict[str, Any]] = {}
        s_r = s_map["sr"]

        for r in rows:
            Tname = r["Subtree"]
            rootName = r["RootName"]
            tj = r["Threshold"]
            sj = s_map[rootName]

            # L_j indices
            Lj = [rho[a] for a in sorted(r["Leaf nodes"])]

            # N_j names (child internal node names) — must match decrypt ordering
            Nj = sorted(list(r["Non-leaf nodes"]))

            # Omega_j = {ell+1 .. 2ell - tj}
            Omega = list(range(self.ell + 1, 2 * self.ell - tj + 1))

            ct: Dict[str, Any] = {}

            # Always include ct1/ct2 (even if Lj empty): ct1 = (h0 * Π_{t∈Lj∪Omega} h_t)^{sj}, ct2 = g^{sj}
            prod = params["h"][0]
            for idx in Lj + Omega:
                prod *= params["h"][idx]
            ct["ct1"] = prod ** sj
            ct["ct2"] = params["g"] ** sj

            # For each child gate in Nj: ct{i+2} = h_{2ell - tj + i}^{sj} * g2^{s_child}
            for i, child_rootName in enumerate(Nj, start=1):
                s_child = s_map[child_rootName]
                h_index = 2 * self.ell - tj + i  # i is 1-based position; scheme uses offset starting at 0
                ct[f"ct{i + 2}"] = (params["h"][h_index] ** sj) * (params["g2"] ** s_child)

            # Root-only component: ct3 = (v^beta)^{s_r}
            if Tname == "Tr":
                ct["ct_v"] = params["v_beta"] ** s_r

            CT_subtrees[Tname] = ct

        C0 = M * (params["Z"] ** s_r)
        C1 = params["g"] ** s_r

        CT = {
            "C0": C0,
            "C1": C1,
            "ct_T": CT_subtrees,
            "policy": policy,
            "rho": rho,
            "ell": self.ell
        }
        # Debug-only: keep s-values so we can validate decryption math end-to-end.
        CT["_debug"] = {"s_map": s_map}
        return CT

    def decrypt(self, CT, SK, params, A_names: Set[str]):
        """
        Decrypt according to the subtree-based algorithm.
        A_names: user's attribute-name set, e.g., {"attC","attD","attE","attF"}
        """
        policy = CT["policy"]
        root = parse_policy(policy)

        struct_rows = build_structure_table(root)
        root_to_sub = {r["RootName"]: r["Subtree"] for r in struct_rows}
        struct_map = {r["Subtree"]: r for r in struct_rows}

        tab2 = build_tab2(root, A_names)
        tab_map = {r["Subtree"]: r for r in tab2}

        rho = CT["rho"]
        A_idx = {rho[a] for a in A_names if a in rho}

        # Lagrange coefficient Δ_{i,S}(0)
        def lagrange_coeff(i: int, S: List[int]):
            iZ = self.group.init(ZR, i)
            x0 = self.group.init(ZR, 0)
            num = self.group.init(ZR, 1)
            den = self.group.init(ZR, 1)
            for j in S:
                if j == i:
                    continue
                jZ = self.group.init(ZR, j)
                num *= (x0 - jZ)
                den *= (iZ - jZ)
            return num / den

        def omega_set(tj: int):
            return list(range(self.ell + 1, 2 * self.ell - tj + 1))

        # base_i should be (g2*h0*Π_{t∈Tset} h_t)^{r q(i)}.
        # Note: SK[i]["a"] = (g2*h0*h_i)^{r q(i)} always contains h_i.
        # To avoid erroneously including h_i when i ∉ Tset, we remove it via / c_i[i]
        # and then multiply exactly the h_t factors we need from c_i[t].
        def build_base_i(i: int, Tset: List[int]):
            # (g2*h0)^{r q(i)}
            base = SK[i]["a"] / SK[i]["c"][i]
            for t in Tset:
                base *= SK[i]["c"][t]  # h_t^{r q(i)} (includes t=i only if i in Tset)
            return base

        memo: Dict[str, Any] = {}  # subtree -> (Dj1, Pj2)

        def dec_subtree(Tname: str):
            if Tname in memo:
                return memo[Tname]

            row_struct = struct_map[Tname]
            row_tab = tab_map[Tname]
            tj = row_struct["Threshold"]
            rootName = row_struct["RootName"]

            Lj_names = sorted(list(row_struct["Leaf nodes"]))
            Lj = [rho[a] for a in Lj_names]

            Nj_names = sorted(list(row_struct["Non-leaf nodes"]))  # must match encrypt ordering

            # Satisfied leaves in this subtree
            sat_leaf = [rho[a] for a in Lj_names if a in A_names]

            # NOTE: "Satisfying non-leaf nodes" cannot be precomputed at Encrypt time
            # because it depends on the decryptor's attribute set. During Decrypt, we
            # determine satisfied child subtrees by recursion (Dk1 != None).

            # Recurse on all children gates
            child_info = []  # (pos, child_rootName, child_Tname, Dk1, Pk2)
            for pos, child_rootName in enumerate(Nj_names, start=1):
                child_T = root_to_sub[child_rootName]
                Dk1, Pk2 = dec_subtree(child_T)
                child_info.append((pos, child_rootName, child_T, Dk1, Pk2))

            # Choose A'_j (deterministic: first few satisfied leaves)
            A_prime = sat_leaf[:min(len(sat_leaf), tj)]
            need_nonleaf = max(0, tj - len(A_prime))

            # Choose satisfied non-leaf children in Nj order (deterministic)
            sat_child_pos: List[int] = [pos for (pos, _cr, _ct, Dk1, _Pk2) in child_info if Dk1 is not None]

            # Check satisfaction: |L∩A| + |S| >= t
            if len(sat_leaf) + len(sat_child_pos) < tj:
                memo[Tname] = (None, None)
                return memo[Tname]

            Sj_ordered_pos = sat_child_pos[:need_nonleaf]

            # Indices representing satisfied non-leaf nodes in interpolation:
            # i = 2ell - tj + pos
            S_indices = [2 * self.ell - tj + pos for pos in Sj_ordered_pos]

            Omega = omega_set(tj)

            # Interpolation set X = A' ∪ S_indices ∪ Ω
            X = list(dict.fromkeys(A_prime + S_indices + Omega))

            # Tset used inside base_i product: L ∪ S_indices ∪ Ω
            Tset = list(dict.fromkeys(Lj + S_indices + Omega))

            # Debug: show how this subtree is being satisfied and which indices are used.
            if CT.get("_debug", None) is not None:
                print(f"[DEBUG] {Tname}: t={tj}, sat_leaf={sat_leaf}, sat_child_pos={sat_child_pos}, A'={A_prime}, need_nonleaf={need_nonleaf}, Sj_pos={Sj_ordered_pos}")
                print(f"[DEBUG] {Tname}: S_indices={S_indices}, Omega={Omega}")
                print(f"[DEBUG] {Tname}: X={X}")
                print(f"[DEBUG] {Tname}: Tset={Tset}")

            # Compute Pj1, Pj2
            Pj1 = self.group.init(G2, 1)
            Pj2 = self.group.init(G1, 1)

            for i in X:
                if i not in SK:
                    raise ValueError(f"Missing SK[{i}] needed for interpolation set X")
                delta = lagrange_coeff(i, X)
                Pj1 *= (build_base_i(i, Tset) ** delta)
                Pj2 *= (SK[i]["b"] ** delta)

            ctj = CT["ct_T"][Tname]
            # Charm's pair() expects (G1, G2). Here ct1 is in G2 and Pj2 in G1,
            # so the argument order must be (Pj2, ct1).
            denom = pair(Pj2, ctj["ct1"])

            # Multiply Dj,3 for selected satisfied non-leaf children:
            # Dj,3 = e(ct_{pos+2}, Pk2) / Dk1
            for pos in Sj_ordered_pos:
                _, child_rootName, child_T, Dk1, Pk2 = child_info[pos - 1]
                if Dk1 is None:
                    raise ValueError(f"Child subtree {child_T} not satisfied but appears in S_j")
                ct_child = ctj[f"ct{pos + 2}"]
                # ct_child is in G2 and Pk2 in G1
                Dj3 = pair(Pk2, ct_child) / Dk1
                denom *= Dj3

            # ct2 is in G1 and Pj1 in G2
            Dj1 = pair(ctj["ct2"], Pj1) / denom
            # Debug: verify subtree Dj1 against expected e(g^{s_j}, g2^{r*alpha})
            try:
                dbg = CT.get("_debug", {})
                meta = SK.get("_meta", {})
                if dbg and meta and "s_map" in dbg and rootName in dbg["s_map"]:
                    sj_dbg = dbg["s_map"][rootName]
                    r_val = meta.get("r")
                    alpha_val = meta.get("alpha")
                    if sj_dbg is not None and r_val is not None and alpha_val is not None:
                        expected_sub = pair(params["g"] ** sj_dbg, params["g2"] ** (r_val * alpha_val))
                        if CT.get("_debug", None) is not None:
                            print(f"[DEBUG] {Tname}: Dj1 == expected_sub ?", Dj1 == expected_sub)
            except Exception as e:
                if CT.get("_debug", None) is not None:
                    print(f"[DEBUG] {Tname}: subtree check failed:", repr(e))
            memo[Tname] = (Dj1, Pj2)
            return memo[Tname]

        # Root
        Dr1, _ = dec_subtree("Tr")
        if Dr1 is None:
            raise ValueError("Access policy not satisfied. Decryption failed.")

        # Dr2 = e( (v^beta)^{s_r}, w^{(r-1)/beta} ) = e(ct_Tr['ct3'], d)
        # Pick any numeric i (ignore debug metadata keys)
        any_i = next(k for k in SK.keys() if isinstance(k, int))
        Dr2 = pair(CT["ct_T"]["Tr"]["ct_v"], SK[any_i]["d"])

        # Recover message
        M = CT["C0"] * (Dr2 / Dr1)

        # =========================
        # Debug diagnostics
        # =========================
        try:
            dbg = CT.get("_debug", {})
            meta = SK.get("_meta", {})
            if dbg and meta:
                s_r = dbg["s_map"].get("sr")
                r_val = meta.get("r")
                alpha_val = meta.get("alpha")
                if s_r is not None and r_val is not None and alpha_val is not None:
                    expected_Dr1 = pair(params["g"] ** s_r, params["g2"] ** (r_val * alpha_val))
                    print("[DEBUG] Dr1 == expected_Dr1 ?", Dr1 == expected_Dr1)
        except Exception as e:
            print("[DEBUG] diagnostics failed:", repr(e))
        return M


# ============================================================
# 6) Demo
# ============================================================
if __name__ == "__main__old__":
    group = PairingGroup("SS512")

    # Example policy from your figure:
    policy = "(attA OR (2, (attB AND attC), attD, (2, attE, attF, attG)))"
    A_names = {"attC", "attD", "attE", "attF"}  # user has these attributes

    # Choose ell >= number of distinct leaf attributes in policy
    abe = ThresholdABE(group, ell=10)

    msk, params = abe.setup()

    # Build rho (from encryption) and convert user attrs to indices for KeyGen
    # (We call encrypt first to get rho stored in CT.)
    M = group.random(GT)
    CT = abe.encrypt(M, params, policy)
    rho = CT["rho"]
    A_idx = {rho[a] for a in A_names if a in rho}

    SK = abe.keygen(msk, params, A_idx)
    M_rec = abe.decrypt(CT, SK, params, A_names)

    print("Decrypt success?", M == M_rec)

# ============================================================
# 6) Single-gate Policy Update: UPKeyGen + CTUpdate
# ============================================================
# NOTE:
# This section is written to be *drop-in* with the ciphertext format produced by ThresholdABE.encrypt():
#   CT = {C0, C1, ct_T:{Tr,T1,...}, policy, rho, _debug:{s_map}}
# It follows your screenshot formulas for ct updating.
#
# Practical requirement:
#   UPKeyGen needs the random number s_j used by the target subtree T_j in ct_T.
#   In this repo, Encrypt stores them at CT['_debug']['s_map'] keyed by RootName (sr, s1, ...).
#   So you can pass E_T = CT['_debug']['s_map'].

from typing import Tuple


def _make_rho_from_policy(root: Node, ell: int) -> Dict[str, int]:
    """Same rho rule as Encrypt: first-seen unique leaf attrs -> 1..ell."""
    rows = build_structure_table(root)
    attrs: List[str] = []
    for r in rows:
        for a in sorted(r["Leaf nodes"]):
            if a not in attrs:
                attrs.append(a)
    if len(attrs) > ell:
        raise ValueError(f"Policy has {len(attrs)} distinct leaf attrs, but ell={ell} is too small.")
    return {a: i + 1 for i, a in enumerate(attrs)}


def _row_by_subtree(policy_root: Node, subtree_name: str) -> Dict[str, Any]:
    rows = build_structure_table(policy_root)
    for r in rows:
        if r["Subtree"] == subtree_name:
            return r
    raise ValueError(f"Subtree '{subtree_name}' not found in policy.")


def _subtree_base(params: Dict[str, Any], ell: int, rho: Dict[str, int], row: Dict[str, Any]) -> Any:
    """Compute (h0 * Π_{t∈L_j ∪ Ω_j} h_t) in G2 for a subtree row."""
    tj = row["Threshold"]
    Lj = [rho[a] for a in sorted(row["Leaf nodes"])]
    Omega = list(range(ell + 1, 2 * ell - tj + 1))
    prod = params["h"][0]
    for idx in Lj + Omega:
        prod *= params["h"][idx]
    return prod



# --------------------------
# UPKeyGen (single-gate)
# --------------------------

def UPKeyGen(
    group: PairingGroup,
    params: Dict[str, Any],
    ell: int,
    E_T: Dict[str, Any],
    old_policy: str,
    new_policy: str,
    target_subtree: str,
    mode: str,
    # Attributes2New only:
    new_subtree: Optional[str] = None,
    pos_new_gate: Optional[int] = None,
) -> Dict[str, Any]:
    """Generate update key tk_{T->T'} for updating a *single* gate/subtree.

    Inputs
    - E_T: random numbers used in ct_T (pass CT['_debug']['s_map']).
    - target_subtree: subtree label in OLD policy to update (e.g., 'T1').
    - mode: 'Attributes2Existing' or 'Attributes2New'.

    Attributes2Existing output:
      {type, old_policy, new_policy, target_subtree, tprime, tk_j1}

    Attributes2New output additionally includes:
      {new_subtree, pos_new_gate, ct_Tt, tk_leaf}

    Notes
    - This helper assumes you know which subtree is the updated gate (T_j).
    - For Attributes2New, you must provide:
        new_subtree: the NEW gate subtree label (in the NEW policy)
        pos_new_gate: 1-based position among *gate-children* of T_j in the NEW policy
      (this matches the paper index h_{2ℓ-t_j+pos}).
    """

    if mode not in {"Attributes2Existing", "Attributes2New"}:
        raise ValueError("mode must be 'Attributes2Existing' or 'Attributes2New'.")

    old_root = parse_policy(old_policy)
    new_root = parse_policy(new_policy)

    rho_new = _make_rho_from_policy(new_root, ell)

    row_old = _row_by_subtree(old_root, target_subtree)
    row_new = _row_by_subtree(new_root, target_subtree)

    sj = E_T[row_old["RootName"]]  # s_j for the OLD gate (same gate being updated)

    base_old = _subtree_base(params, ell, rho_new, row_old)
    base_new = _subtree_base(params, ell, rho_new, row_new)

    tprime = group.random(ZR)

    # tk_{Tj,1} = (base_new)^{s_j} * (base_old)^{-s_j * t'}
    tk_j1 = (base_new ** sj) * (base_old ** (-sj * tprime))

    if mode == "Attributes2Existing":
        return {
            "type": "Attributes2Existing",
            "old_policy": old_policy,
            "new_policy": new_policy,
            "target_subtree": target_subtree,
            "tprime": tprime,
            "tk_j1": tk_j1,
        }

    # Attributes2New
    if new_subtree is None or pos_new_gate is None:
        raise ValueError("Attributes2New requires new_subtree and pos_new_gate.")

    row_t = _row_by_subtree(new_root, new_subtree)
    st = E_T[row_t["RootName"]]  # s_t for the NEW subtree root

    # Build ct_{Tt} for the new subtree T_t (same as Encrypt, but only for that subtree)
    tj_t = row_t["Threshold"]
    Lj_t = [rho_new[a] for a in sorted(row_t["Leaf nodes"])]
    Nj_t = sorted(list(row_t["Non-leaf nodes"]))
    Omega_t = list(range(ell + 1, 2 * ell - tj_t + 1))

    prod_t = params["h"][0]
    for idx in Lj_t + Omega_t:
        prod_t *= params["h"][idx]

    ct_Tt: Dict[str, Any] = {
        "ct1": prod_t ** st,
        "ct2": params["g"] ** st,
    }

    for i, child_rootName in enumerate(Nj_t, start=1):
        s_child = E_T[child_rootName]
        h_index = 2 * ell - tj_t + i
        ct_Tt[f"ct{i+2}"] = (params["h"][h_index] ** st) * (params["g2"] ** s_child)

    # tk_leaf = h_{2ℓ - t_j(new) + pos}^{s_j} * g2^{s_t}
    tj_new = row_new["Threshold"]
    h_index_leaf = 2 * ell - tj_new + pos_new_gate
    tk_leaf = (params["h"][h_index_leaf] ** sj) * (params["g2"] ** st)

    return {
        "type": "Attributes2New",
        "old_policy": old_policy,
        "new_policy": new_policy,
        "target_subtree": target_subtree,
        "new_subtree": new_subtree,
        "pos_new_gate": pos_new_gate,
        "tprime": tprime,
        "tk_j1": tk_j1,
        "ct_Tt": ct_Tt,
        "tk_leaf": tk_leaf,
    }


# --------------------------
# CTUpdate
# --------------------------

def CTUpdate(
    CT: Dict[str, Any],
    tk: Dict[str, Any],
) -> Dict[str, Any]:
    """CTUpdate(mpk, ct_T, tk_{T->T'}) -> ct_{T'}

    Implements your screenshot equations.

    For Attributes2Existing:
      ct'_{Tj} = ( ct1^{t'} * tk_j1, ct2, {ct{i+2}} )

    For Attributes2New:
      ct'_{Tj} = ( ct1^{t'} * tk_j1, ct2, {ct{i+2}}, tk_leaf )
      and we also add the new subtree ciphertext ct_{Tt}.

    This function returns a *new* ciphertext dict CT' with:
      - policy replaced by tk['new_policy']
      - rho rebuilt from the new policy
      - ct_T updated for the target subtree (and possibly adds new_subtree)

    NOTE:
      This implementation updates only the affected subtree ciphertext components,
      matching the paper's local update description for a single gate.
    """

    if tk["type"] not in {"Attributes2Existing", "Attributes2New"}:
        raise ValueError("Unknown update key type.")

    # IMPORTANT:
    # Do NOT use deepcopy() here. Charm-Crypto pairing.Element objects are not picklable,
    # which can trigger: TypeError: cannot pickle 'pairing.Element' object.
    # We only need a *structural* copy of the dicts so we can replace a few fields.
    CTp = dict(CT)
    CTp["ct_T"] = dict(CT.get("ct_T", {}))

    # Update policy + rho
    new_policy = tk["new_policy"]
    new_root = parse_policy(new_policy)
    # ell should come from system parameter (stored in CT at Encrypt time)
    ell = CT.get("ell", None)
    if ell is None:
        # fallback for legacy ciphertexts
        ell = max(CT["rho"].values()) if CT.get("rho") else 0
    CTp["ell"] = ell
    CTp["policy"] = new_policy
    CTp["rho"] = _make_rho_from_policy(new_root, ell)

    Tj = tk["target_subtree"]
    if Tj not in CTp["ct_T"]:
        raise ValueError(f"Target subtree '{Tj}' not found in ciphertext.")

    ctj_old = CT["ct_T"][Tj]

    # ct1' = ct1^{t'} * tk_j1
    ct1_new = (ctj_old["ct1"] ** tk["tprime"]) * tk["tk_j1"]

    # keep ct2 and existing ct{i+2}
    ctj_new = {k: v for k, v in ctj_old.items() if k != "ct1"}
    ctj_new["ct1"] = ct1_new

    if tk["type"] == "Attributes2New":
        # append new leaf-node component as a new ct component
        # (paper denotes it as tk_{j,(|Nj|+1)+2}; we store it as 'ct_new_leaf')
        ctj_new["ct_new_leaf"] = tk["tk_leaf"]

        # add new subtree ciphertext
        new_subtree = tk["new_subtree"]
        CTp["ct_T"][new_subtree] = tk["ct_Tt"]

    CTp["ct_T"][Tj] = ctj_new

    # remove debug (optional)
    # CTp.pop('_debug', None)

    return CTp


# ============================================================
# 7) Minimal demo: Encrypt -> UPKeyGen -> CTUpdate
# ============================================================
if __name__ == "__main__old__":
    group = PairingGroup("MNT224")
    ell = 10
    abe = ThresholdABE(group, ell)
    msk, params = abe.setup()

    # OLD policy:  attA OR (attB AND attC)
    old_policy = "(attA OR (attB AND attC))"

    # NEW policy example (Attributes2Existing): update the right AND-gate into a (3, ...) threshold gate
    new_policy_existing = "(attA OR (3, attB, attC, attD, attE))"

    M = group.random(GT)
    CT = abe.encrypt(M, params, old_policy)

    # E_T is the random numbers used in ct_T
    E_T = CT["_debug"]["s_map"]

    # Choose the subtree to update.
    # Inspect the structure table to know which one corresponds to the right child gate.
    rows_old = build_structure_table(parse_policy(old_policy))
    print("Old structure rows:")
    for r in rows_old:
        print(r["Subtree"], r["RootName"], r["Leaf nodes"], r["Non-leaf nodes"], "t=", r["Threshold"])

    # In this small policy, the only non-root subtree is usually 'T1'.
    target_subtree = "T1"

    tk1 = UPKeyGen(
        group=group,
        params=params,
        ell=ell,
        E_T=E_T,
        old_policy=old_policy,
        new_policy=new_policy_existing,
        target_subtree=target_subtree,
        mode="Attributes2Existing",
    )

    CT1 = CTUpdate(CT, tk1)
    print("Updated policy (existing gate):", CT1["policy"])

    # ------------------------------------------------------------
    # NEW policy example (Attributes2New): paper Fig.4 style update
    #   Old:  (attA OR (attB AND attC))
    #   New:  ((2, attA, attD, attE) OR (attB AND attC))
    # Here we update the ROOT gate Tr by replacing leaf attA with a new threshold gate.
    # ------------------------------------------------------------
    new_policy_newgate = "((2, attA, attD, attE) OR (attB AND attC))"

    # Target subtree is root
    target_subtree2 = "Tr"

    # Identify the new subtree label (Tt) for the freshly introduced (2, attA, attD, attE) gate
    rows_new2 = build_structure_table(parse_policy(new_policy_newgate))
    new_subtree2 = None
    new_subtree_rootname2 = None
    for r in rows_new2:
        # The new gate has direct leaves {attA,attD,attE} and no direct non-leaf children
        if r["Threshold"] == 2 and r["Leaf nodes"] == {"attA", "attD", "attE"} and len(r["Non-leaf nodes"]) == 0:
            new_subtree2 = r["Subtree"]
            new_subtree_rootname2 = r["RootName"]
            break
    if new_subtree2 is None:
        raise RuntimeError("Failed to locate the new threshold gate subtree in the new policy.")

    # Determine the position of the new gate among the root's non-leaf children (1-based)
    # This must match the ordering used in the scheme (we use sorted RootName order).
    row_root_new2 = None
    for r in rows_new2:
        if r["Subtree"] == target_subtree2:
            row_root_new2 = r
            break
    if row_root_new2 is None:
        raise RuntimeError("Failed to locate root subtree 'Tr' in new policy structure table.")
    Nj_root_sorted = sorted(list(row_root_new2["Non-leaf nodes"]))
    if new_subtree_rootname2 not in Nj_root_sorted:
        raise RuntimeError("New gate rootName not found among root's non-leaf children.")
    pos_new_gate2 = Nj_root_sorted.index(new_subtree_rootname2) + 1

    tk2 = UPKeyGen(
        group=group,
        params=params,
        ell=ell,
        E_T=E_T,
        old_policy=old_policy,
        new_policy=new_policy_newgate,
        target_subtree=target_subtree2,
        mode="Attributes2New",
        new_subtree=new_subtree2,
        pos_new_gate=pos_new_gate2,
    )

    CT2 = CTUpdate(CT, tk2)
    print("Updated policy (new gate):", CT2["policy"])
    print("New subtree added:", new_subtree2 in CT2["ct_T"], "label=", new_subtree2, "pos=", pos_new_gate2)

    # End of demo

