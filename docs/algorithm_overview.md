# Algorithm Overview — PV-SR-ABE Implementation

All core algorithms are implemented in `pv_core.py`. This document maps the paper's theoretical algorithms to the actual code, using real function names and data structures.

---
## Binary Tree and KUNodes

### Data Structures

```python
@dataclass
class Node:
    nid:    str           # e.g. "root", "n_0_L", "n_0_R", "leaf_3"
    parent: Optional[Node]
    left:   Optional[Node]
    right:  Optional[Node]
    gx:     Optional[Any] # G element stored at this node (set during UserKG)

@dataclass
class BinaryTree:
    root:   Node
    leaves: List[Node]    # 2^depth leaves, left-to-right

# State object (kept by PKG)
st = {
    "depth":      4,              # tree depth
    "BT":         BinaryTree,    # the tree
    "R":          [(leaf, t), …], # revocation list: (leaf_node, time_period)
    "id_to_leaf": {"alice": "leaf_3", "bob": "leaf_7", …},
}
```

### KUNodes Algorithm

```python
def kunode(bt: BinaryTree, R: List[Tuple[Node,int]], t: int) -> List[Node]:
    """
    Returns minimal set Y of nodes such that:
    - Path(θ_i) ∩ Y ≠ ∅  for every non-revoked user i
    - Path(θ_j) ∩ Y  = ∅  for every revoked user j (revoked at t_j ≤ t)
    """
    X = set()   # ancestors of all revoked-by-t leaves
    for (leaf, t_r) in R:
        if t_r <= t:
            for node in path_to_root(bt, leaf):
                X.add(node.nid)

    Y = set()   # non-revoked children of revoked nodes
    for nid in X:
        node = find_node(bt, nid)
        if node.left  and node.left.nid  not in X:  Y.add(node.left)
        if node.right and node.right.nid not in X:  Y.add(node.right)

    if not Y:
        Y.add(bt.root)   # no revocations: root covers everyone
    return list(Y)
```

---

## LSSS and Policy Parsing

### Policy Grammar

```
policy ::= attr_name
         | "(" policy "and" policy ")"
         | "(" policy "or"  policy ")"

attr_name ::= [A-Za-z0-9_@.\-]+

# Examples:
#   "A"
#   "A and B"
#   "(A and B) or C"
#   "A and (B or C)"
```

### AST Nodes

```python
@dataclass(frozen=True)
class _Leaf:
    name: str              # attribute name string

@dataclass(frozen=True)
class _Gate:
    op:    str             # "AND" or "OR"
    left:  Any             # _Leaf or _Gate
    right: Any             # _Leaf or _Gate
```

### LSSS Construction

```python
def _policy_to_lsss(policy_str: str) -> Tuple[List[List[int]], List[str]]:
    """
    Convert AND/OR policy to monotone span program (M, rho).
    OR  gate: both children share the same label vector v
    AND gate: left  child gets (v ‖  1)
              right child gets (v ‖ -1)
    Returns:
        M:   l × n integer matrix (l = number of attributes in policy)
        rho: length-l list of attribute name strings
    """
```

### Secret Sharing

```python
def lsss_shares(group, M, s):
    # secret vector v = (s, 0, 0, …, 0) ∈ Zp^n
    # share λ_i = <M_i, v>  for each row i
    v = [s] + [group.init(ZR, 0)] * (n_cols - 1)
    return [inner_product(M[i], v) for i in range(len(M))]

def lsss_reconstruct(group, M, rho, S):
    # Find subset I ⊆ [l] with {ρ(i) : i∈I} ⊆ S and {M_i : i∈I} spans e_1
    # Solve for reconstruction coefficients {ω_i} via Gaussian elimination
    # Returns dict {i: ω_i} or None if S does not satisfy policy
```


## 1. Setup() → SetupResult

**Runs:** PKG local machine · **CLI:** `ta_local.py setup` · **Output:** `keys/pv_setup.json`

```python
def setup(curve: str = "SS512", depth: int = 4) -> SetupResult:
    group = PairingGroup(curve)

    # Random scalars
    alpha = group.random(ZR)
    beta  = group.random(ZR)

    # Random generators g, g0, k0; derive k = g0^{bq·...}
    g  = group.random(G1)
    u0 = group.random(G1)   # u0 chosen first

    # Construct g0, k0 satisfying e(g0, k0) = e(u0, g)
    # by choosing g0 = g^{a^q·b_q}, k0 = g^{b_q}
    # (in PoC: sample random g0, k0 and u0 such that constraint holds)
    g0 = group.random(G1)
    k0 = group.random(G1)
    # ... (constraint is verified after construction, resampled if needed)

    # All other mpk generators
    k, u, h, h0, u1, h1, w, v = [group.random(G1) for _ in range(8)]

    H = make_H(group)   # H: GT → G1 via group.hash

    mpk = {
        "g0": g0, "k": k, "k0": k0, "u": u, "h": h,
        "u0": u0, "h0": h0, "u1": u1, "h1": h1, "w": w, "v": v,
        "egg_a":  pair(g, g)**alpha,
        "eu0g_b": pair(u0, g)**beta,
        "H": H,
    }
    msk = {"alpha": alpha, "beta": beta}

    # Initialize binary tree and empty revocation list
    st = {
        "depth": depth,
        "BT": build_binary_tree(depth),
        "R": [],
        "id_to_leaf": {},
    }
    return SetupResult(curve=curve, mpk=mpk, msk=msk, st=st)
```

**Saved to `pv_setup.json`:** `{curve, depth, mpk: serialize_any(…), msk: serialize_any(…), state: {bt, R, id_to_leaf}}`

The PKG retains `msk`. In the PoC it is stored for reproducibility — see [Security Notes](#security-notes).

---

## 2. Userkg() → UserKeyResult

**Runs:** PKG · **CLI:** `ta_local.py userkg` · **Output:** `keys/<user>_user.json`

```python
@dataclass
class UserKeyResult:
    ID:       str                # identity string (hashed to ZR internally)
    S:        List[str]          # attribute set
    leaf_nid: str                # assigned leaf node ID in BT
    sk_id:    Tuple[Any, Any]    # (g^α·(u0^ID·h0)^r,  g^r)  ∈ G1²
    vk_id:    Any                # g0^(β+r·ID)  ∈ G1
    psk_id_s: Dict[str, Any]     # long-term transformation key (path-indexed)
```

```python
def userkg(mpk, msk, st, ID: str, S: List[str]) -> UserKeyResult:
    group = PairingGroup(mpk["curve"])
    id_zr = _id_to_zr(group, ID)   # Hash("ID:" + ID) → ZR

    r = group.random(ZR)   # FRESH per user — collusion resistance

    # Private key (for decryption only)
    sk_id = (
        g**msk["alpha"] * (mpk["u0"]**id_zr * mpk["h0"])**r,
        g**r,
    )

    # Public verification key (anyone can verify using this)
    vk_id = mpk["g0"] ** (msk["beta"] + r * id_zr)

    # Assign leaf node in binary tree
    leaf = assign_leaf(st, ID)

    # Long-term transformation key: one entry per node on Path(leaf → root)
    psk_id_s = {}
    for x in path_to_root(st["BT"], leaf):
        if x.gx is None:
            x.gx = group.random(G1)   # set once, stored persistently in BT

        rx  = group.random(ZR)
        psk_id_s[x.nid] = {
            # ((w^ID·k)^rx / gx) · u0^r
            "A": (mpk["w"]**id_zr * mpk["k"])**rx / x.gx * mpk["u0"]**r,
            "B": g**rx,                                  # g^rx
            "C": {                                       # per attribute τ∈S
                attr: {
                    "D": (mpk["u"]**attr_zr * mpk["h"])**rx_t * mpk["v"]**(-rx),
                    "E": g**rx_t,
                }
                for attr, rx_t in [(a, group.random(ZR)) for a in S]
            },
        }
    return UserKeyResult(ID=ID, S=S, leaf_nid=leaf.nid,
                         sk_id=sk_id, vk_id=vk_id, psk_id_s=psk_id_s)
```

**Why fresh `r` prevents collusion:** Each `sk_id` and `psk_id_s` are bound to the same fresh `r`. Combining key material from two users with `r₁ ≠ r₂` causes the pairing products in TranKG to mismatch, returning ⊥ or producing incorrect π.

---

## 3. Tkeyup() → TKeyUpResult

**Runs:** PKG · **CLI:** `ta_local.py tkeyup` · **Output:** `keys/tuk_t<N>.json`

```python
@dataclass
class TKeyUpResult:
    t:     int             # time period
    tuk_t: Dict[str, Any]  # {"Y": [node_ids], node_id: {"F": …, "G": …}, …}
```

```python
def tkeyup(mpk, msk, st, t: int) -> TKeyUpResult:
    group = PairingGroup(mpk["curve"])
    Y = kunode(st["BT"], st["R"], t)   # minimal cover set of non-revoked nodes

    tuk_t = {"Y": [x.nid for x in Y]}
    for x in Y:
        # gx must already be defined (set during UserKG for non-revoked users)
        sx = group.random(ZR)
        tuk_t[x.nid] = {
            "F": x.gx * (mpk["u1"]**t * mpk["h1"])**sx,  # gx·(u1^t·h1)^sx ∈ G1
            "G": g**sx,                                     # g^sx ∈ G1
        }
    return TKeyUpResult(t=t, tuk_t=tuk_t)
```

**Size:** `|Y| ≤ 2·|R|·log(N)` entries. With no revocations, `|Y| = 1` (root only).

---

## 4. Trankg() → TranKGResult / None

**Runs:** server · **Simulated in:** `client_decrypt.py`

```python
@dataclass
class TranKGResult:
    t:         int
    tk_id_t_s: Dict[str, Any]  # short-term transformation key components
```

```python
def trankg(mpk, psk_id_s, tuk_t, t: int) -> Optional[TranKGResult]:
    # Intersect Path(θ) = psk_id_s.keys() with KUNodes = tuk_t["Y"]
    path_nodes = set(psk_id_s.keys())
    ku_nodes   = set(tuk_t["Y"])
    intersect  = path_nodes & ku_nodes

    if not intersect:
        return None   # user is revoked (no common node)

    # Exactly one node x in the intersection
    nid = intersect.pop()
    psk_x = psk_id_s[nid]
    tuk_x = tuk_t[nid]

    tk_id_t_s = {
        "intersect_node": nid,
        # Combine: ((w^ID k)^rx/gx)·u0^r  ·  gx·(u1^t h1)^sx
        #        = (w^ID k)^rx · u0^r · (u1^t h1)^sx
        "A_combined": psk_x["A"] * tuk_x["F"],
        "B": psk_x["B"],   # g^rx
        "C_sx": tuk_x["G"],  # g^sx
        "C": psk_x["C"],   # per-attribute: {D: (u^Sτ h)^rx,τ · v^-rx,  E: g^rx,τ}
    }
    return TranKGResult(t=t, tk_id_t_s=tk_id_t_s)
```

---

## 5. Encrypt_by_policy() → EncryptResult

**Runs:** cloud (`lambda_encrypt.py`) · **Input:** `key_gt` is a random `GT` element (session key)

```python
@dataclass
class EncryptResult:
    t_prime:    int              # time period t'
    policy_str: str              # original policy string
    policy:     Tuple           # (M_matrix, rho_list)
    hdr:        Tuple           # (e(g,g)^{αs}·key_gt,  g^s,  h0^s)
    ct:         Dict[str, Any]  # ciphertext components
```

```python
def encrypt_by_policy(mpk, policy_str: str, t_prime: int, msg) -> EncryptResult:
    group  = PairingGroup(mpk["curve"])
    M, rho = _policy_to_lsss(policy_str)  # LSSS matrix + attribute labeling
    l, n   = len(M), len(M[0])

    s     = group.random(ZR)                  # master secret
    M_R   = group.random(GT)                  # random verification message
    svals = [group.random(ZR) for _ in range(l)]
    lam   = lsss_shares(group, M, s)          # shares λ_i = <M_i, (s,0,…)>

    # Header (for decryption, hides the real message)
    hdr = (
        mpk["egg_a"] ** s * msg,              # e(g,g)^{αs} · M  ∈ GT
        g ** s,                               # g^s             ∈ G1
        mpk["h0"] ** s,                       # h0^s            ∈ G1
    )

    # Ciphertext (for transformation and public verification)
    ct = {
        "C_MR":   mpk["eu0g_b"] ** s * M_R,  # e(u0,g)^{βs}·MR ∈ GT
        "C_HMR":  mpk["H"](M_R) ** s,        # H(MR)^s         ∈ G1
        "C_gs":   g ** s,                     # g^s             ∈ G1
        "C_ks":   mpk["k"] ** s,              # k^s             ∈ G1
        "C_k0s":  mpk["k0"] ** s,             # k0^s            ∈ G1
        "C_time": (mpk["u1"]**t_prime * mpk["h1"]) ** s,  # (u1^t' h1)^s
        "rows": [
            {
                "Clam":  mpk["w"]**lam[i] * mpk["v"]**svals[i],   # w^λi·v^si
                "Crho":  (mpk["u"]**attr_zr * mpk["h"])**(-svals[i]),
                "Csi":   g**svals[i],
                "attr":  rho[i],
            }
            for i, attr_zr in enumerate(_attr_to_zr(group, rho[i]) for rho[i] in rho)
        ],
    }
    return EncryptResult(t_prime=t_prime, policy_str=policy_str,
                         policy=(M, rho), hdr=hdr, ct=ct)
```

**Hybrid layer in `lambda_encrypt.py`:**
```python
key_gt = group.random(GT)                            # random session key ∈ GT
dek    = hashlib.sha256(group.serialize(key_gt)).digest()   # KDF → 32 bytes
enc    = pv_core.encrypt_by_policy(mpk, policy, t, key_gt)  # ABE on GT element
aes    = AESGCM(dek).encrypt(nonce, plaintext, None)         # AES-256-GCM
bundle = {"enc": dump_encrypt(group, enc), "aes": {"nonce": b64(nonce), "ct": b64(aes)}}
```

---

## 6. Transform() → TransformResult / None

**Runs:** untrusted server · **Simulated in:** `client_decrypt.py`

```python
@dataclass
class TransformResult:
    ok: bool
    pi: Any    # π = e(u0^r, g^s) ∈ GT
```

```python
def transform(mpk, enc: EncryptResult, tk_id_t_s, ID: str) -> Optional[TransformResult]:
    group  = PairingGroup(mpk["curve"])
    M, rho = enc.policy
    S = set(tk_id_t_s["C"].keys())

    # Check time period: t must equal t'
    # (enforced via the (u1^t h1)^s component in ct and (u1^t h1)^sx in tk)

    # Compute LSSS reconstruction coefficients
    omega = lsss_reconstruct(group, M, rho, S)
    if omega is None:
        return TransformResult(ok=False, pi=None)  # policy not satisfied

    # Pairing product over satisfied rows
    pairing_prod = group.init(GT, 1)
    for i in omega:
        attr  = rho[i]
        rx_i  = tk_id_t_s["C"][attr]
        row   = enc.ct["rows"][i]
        wi    = omega[i]
        pairing_prod *= (
            pair(rx_i["D"], row["Csi"]) *     # e((u^Sτ h)^rx,τ·v^-rx, g^si)
            pair(row["Crho"], rx_i["E"]) *    # e((u^ρ(i) h)^-si, g^rx,τ)
            pair(row["Clam"], tk_id_t_s["B"]) # e(w^λi·v^si, g^rx)
        ) ** wi
    # pairing_prod = e(w^s, g^rx)

    id_zr = _id_to_zr(group, ID)
    pi = (
        pair(tk_id_t_s["A_combined"], enc.ct["C_gs"])
        / (pairing_prod ** id_zr
           * pair(enc.ct["C_ks"], tk_id_t_s["B"])
           * pair(enc.ct["C_time"], tk_id_t_s["C_sx"]))
    )
    # π = e(u0^r, g^s)
    return TransformResult(ok=True, pi=pi)
```

---

## 7. Verify() → bool

**Runs:** any party (public) · **No private key required**

```python
def verify(mpk, enc: EncryptResult, pi, vk_id, ID: str) -> bool:
    group = PairingGroup(mpk["curve"])
    id_zr = _id_to_zr(group, ID)

    # Recover MR from π and vk_id using e(g0, k0) = e(u0, g):
    #   e(vk_id, C_k0s) = e(g0^{β+rID}, k0^s) = e(u0,g)^{(β+rID)s}
    #   numerator       = e(u0,g)^{βs·MR} · π^ID
    MR_candidate = (
        enc.ct["C_MR"] * pi ** id_zr
        / pair(vk_id, enc.ct["C_k0s"])
    )

    # Bilinear consistency check: e(g^s, H(MR)) = e(H(MR)^s, g)
    H_MR = mpk["H"](MR_candidate)
    lhs  = pair(enc.ct["C_gs"], H_MR)
    rhs  = pair(enc.ct["C_HMR"], g)
    return lhs == rhs
```

**Why this is public:** `vk_id` is a public key; `C_k0s`, `C_gs`, `C_HMR`, `C_MR` are all in the ciphertext. No secret key is accessed.

---

## 8. Decrypt() → GT element

**Runs:** data user · **Only called after `verify()` returns `True`**

```python
def decrypt(mpk, sk_id, pi, hdr, ID: str):
    group = PairingGroup(mpk["curve"])
    id_zr = _id_to_zr(group, ID)

    # sk_id = (g^α·(u0^ID·h0)^r,  g^r)
    sk0, sk1 = sk_id

    # Compute e(g,g)^{αs} from π and sk_id:
    #   pair(sk0, g^s) = e(g^α·(u0^ID h0)^r, g^s)
    #   pair(u0^s, g^r)^ID · pair(h0^s, g^r) = e(u0,g)^{rID·s} · e(h0,g)^{rs}
    # → pair(sk0, hdr[1]) / (π^ID · pair(hdr[2], sk1)) = e(g,g)^{αs}
    egg_as = pair(sk0, hdr[1]) / (pi ** id_zr * pair(hdr[2], sk1))

    # Recover session key: hdr[0] = e(g,g)^{αs} · M  →  M = hdr[0] / egg_as
    return hdr[0] / egg_as
```

**Client recovery in `client_decrypt.py`:**
```python
key_gt  = pv_core.decrypt(mpk, user.sk_id, tr.pi, enc.hdr, user.ID)
dek     = hashlib.sha256(group.serialize(key_gt)).digest()
pt      = AESGCM(dek).decrypt(nonce, aes_ct, None)
print("[CLIENT] Plaintext:", pt.decode())
```

---

## 9. Revoke()

**Runs:** PKG · **CLI:** `ta_local.py revoke`

```python
def revoke(st, ID: str, t: int) -> bool:
    leaf_nid = st["id_to_leaf"].get(ID)
    if leaf_nid is None:
        return False          # user never issued a key
    leaf = find_node(st["BT"], leaf_nid)
    st["R"].append((leaf, t)) # cumulative; persisted to pv_setup.json
    return True
```

Revocation is cumulative. A subsequent `tkeyup(t')` for any `t' ≥ t` will exclude this user's leaf from KUNodes, making TranKG return ⊥.

---

## 10. Serialization

```python
def serialize_any(group, obj):
    try:
        b = group.serialize(obj)    # charm element → bytes
        return {"__charm__": base64.b64encode(b).decode("ascii")}
    except:
        pass
    if isinstance(obj, dict):
        return {str(k): serialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [serialize_any(group, v) for v in obj]
    return obj   # int, str, float pass through

def deserialize_any(group, obj):
    if isinstance(obj, dict) and "__charm__" in obj:
        return group.deserialize(base64.b64decode(obj["__charm__"]))
    if isinstance(obj, dict):
        return {k: deserialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deserialize_any(group, v) for v in obj]
    return obj
```

**Critical constraint:** `group.serialize` / `group.deserialize` are bound to the specific `PairingGroup("SS512")` instance. Both cloud and client must load the same `curve` stored in `pv_setup.json`.

The binary tree `gx` values (set during UserKG) are serialized per-node in the `state.bt` snapshot. This ensures `tkeyup` always uses the same `gx` that was used in `userkg`, which is required for TranKG correctness.

