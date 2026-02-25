# -*- coding: utf-8 -*-
"""
pv_core.py  (PV-SR-ABE core) — corrected implementation
---------------------------------------------------------
Roles (paper):
  PKG   : Setup / UserKG / TKeyUp
  Server: TranKG / Transform
  Public: Verify
  Client: Decrypt

All algorithms are implemented strictly following the paper definitions:

  mpk = (G, g0, k, k0, u, h, u0, h0, u1, h1, w, v, e(g,g)^α, e(u0,g)^β, H)
  msk = (α, β, st)

  sk_ID  = (g^α (u0^ID h0)^r,  g^r)
  vk_ID  = g0^(β + r·ID)

  psk_{ID,S} = { ((w^ID k)^{rx} / gx) · u0^r,  g^{rx},
                 { (u^{Sτ} h)^{r_{x,τ}} · v^{-rx},  g^{r_{x,τ}} }_{τ∈S}
               }_{x∈Path(θ)}

  tuk_t  = { gx · (u1^t h1)^{sx},  g^{sx} }_{x∈KUNodes(BT,R,t)}

  tk^S_{ID,t} = ((w^ID k)^{rx} u0^r (u1^t h1)^{sx},  g^{rx},  g^{sx},
                 { (u^{Sτ} h)^{r_{x,τ}} · v^{-rx},  g^{r_{x,τ}} }_{τ∈S})
  (for the unique x ∈ Path(θ) ∩ KUNodes(BT,R,t))

  Encrypt: Hdr = (e(g,g)^{αs} M,  g^s,  h0^s)
           c   = (e(u0,g)^{βs} M_R,  H(M_R)^s,  g^s,  k^s,  k0^s,
                  (u1^{t'} h1)^s,
                  { w^{λi} v^{si},  (u^{ρ(i)} h)^{-si},  g^{si} }_{i∈[l]})

  Transform: for each ρ(i)∈S compute pairing product; then compute π
  Verify / Decrypt as in paper.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair

# Version tag — bump this when the file changes so you can verify the right file is loaded
_PV_CORE_VERSION = "2.0-fix-setup-constraint"


# ============================================================
# JSON / base64 / Charm serialization helpers
# ============================================================

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def save_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def serialize_any(group: PairingGroup, obj: Any) -> Any:
    """Recursively serialize Charm group elements to base64 JSON."""
    try:
        b = group.serialize(obj)
        return {"__charm__": _b64e(b)}
    except Exception:
        pass
    if isinstance(obj, dict):
        return {str(k): serialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [serialize_any(group, v) for v in obj]
    return obj

def deserialize_any(group: PairingGroup, obj: Any) -> Any:
    """Recursively deserialize base64 JSON back to Charm group elements."""
    if isinstance(obj, dict) and "__charm__" in obj:
        return group.deserialize(_b64d(obj["__charm__"]))
    if isinstance(obj, dict):
        return {k: deserialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deserialize_any(group, v) for v in obj]
    return obj


# ============================================================
# Helpers: hash label -> ZR,  hash element -> G1
# ============================================================

def _hash_to_zr(group: PairingGroup, label: str) -> Any:
    return group.hash(label, ZR)

def _id_to_zr(group: PairingGroup, ID: str) -> Any:
    return _hash_to_zr(group, "ID:" + ID)

def _attr_to_zr(group: PairingGroup, attr: str) -> Any:
    return _hash_to_zr(group, "ATTR:" + attr)

def make_H(group: PairingGroup):
    """Return H : GT -> G1 (hash function in the paper)."""
    def H(x: Any) -> Any:
        try:
            data = group.serialize(x)
        except Exception:
            data = str(x).encode("utf-8")
        return group.hash(data, G1)
    return H


# ============================================================
# Minimal AND/OR policy -> (M, rho) LSSS
# ============================================================

_TOKEN = re.compile(r"\s*(\(|\)|and|or|[A-Za-z0-9_@.\-]+)\s*", re.IGNORECASE)

@dataclass(frozen=True)
class _Leaf:
    name: str

@dataclass(frozen=True)
class _Gate:
    op: str   # "AND" or "OR"
    left: Any
    right: Any

def _tokenize(s: str) -> List[str]:
    toks = [m.group(1) for m in _TOKEN.finditer(s)]
    if not toks:
        raise ValueError("Empty policy")
    return toks

class _Parser:
    def __init__(self, toks: List[str]):
        self.toks = toks
        self.i = 0

    def peek(self) -> Optional[str]:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def eat(self, t: Optional[str] = None) -> str:
        cur = self.peek()
        if cur is None:
            raise ValueError("Unexpected end of policy")
        if t is not None and cur.lower() != t.lower():
            raise ValueError(f"Expected '{t}', got '{cur}'")
        self.i += 1
        return cur

    def parse(self):
        node = self.parse_or()
        if self.peek() is not None:
            raise ValueError(f"Extra tokens: {self.toks[self.i:]}")
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek() and self.peek().lower() == "or":
            self.eat("or")
            node = _Gate("OR", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_atom()
        while self.peek() and self.peek().lower() == "and":
            self.eat("and")
            node = _Gate("AND", node, self.parse_atom())
        return node

    def parse_atom(self):
        if self.peek() == "(":
            self.eat("(")
            node = self.parse_or()
            self.eat(")")
            return node
        return _Leaf(self.eat())

def _policy_to_lsss(policy_str: str) -> Tuple[List[List[int]], List[str]]:
    """
    Convert AND/OR policy string to (M, rho) monotone span program.
    OR  -> both children share the same vector
    AND -> left gets (v||1), right gets (v||-1)  [standard construction]
    """
    ast = _Parser(_tokenize(policy_str)).parse()

    def build(node, v: List[int]):
        if isinstance(node, _Leaf):
            return [v], [node.name], len(v)
        assert isinstance(node, _Gate)
        d = len(v)
        if node.op == "OR":
            M1, r1, d1 = build(node.left, v)
            M2, r2, d2 = build(node.right, v)
            if d1 != d2:
                raise ValueError("Dimension mismatch in OR node")
            return M1 + M2, r1 + r2, d1
        if node.op == "AND":
            vL = v + [1]
            vR = list(v) + [-1]
            M1, r1, d1 = build(node.left, vL)
            M2, r2, d2 = build(node.right, vR)
            if d1 != d2:
                raise ValueError("Dimension mismatch in AND node")
            return M1 + M2, r1 + r2, d1
        raise ValueError(f"Unsupported gate: {node.op}")

    M, rho, _ = build(ast, [1])
    return M, rho


# ============================================================
# LSSS secret sharing and reconstruction
# ============================================================

def lsss_shares(group: PairingGroup, M: List[List[int]], s: Any) -> List[Any]:
    """
    Share secret s using matrix M.
    Secret vector v = (s, 0, ..., 0).
    Share λ_i = <M_i, v> = M_i[0] * s.
    """
    n_cols = len(M[0]) if M else 1
    v_vec = [s] + [group.init(ZR, 0)] * (n_cols - 1)
    shares = []
    for row in M:
        acc = group.init(ZR, 0)
        for j, a in enumerate(row):
            acc = acc + group.init(ZR, int(a)) * v_vec[j]
        shares.append(acc)
    return shares

def lsss_reconstruct(group: PairingGroup, M: List[List[int]], rho: List[str],
                     S: Set[str]) -> Optional[Dict[str, Any]]:
    """
    Compute reconstruction coefficients {ω_i} such that
    Σ_{ρ(i)∈S} ω_i · M_i = e_1 = (1, 0, ..., 0).

    Algorithm (over rationals via Python Fraction, then convert to Charm ZR):
    We solve the transposed system:  M_sat^T · ω = e_1
    using Gaussian elimination on the augmented matrix [M_sat^T | e_1].
    This gives ω as the solution column directly.

    Returns {original_row_index: ω_i} or None if S doesn't satisfy the policy.
    """
    from fractions import Fraction

    # Collect satisfied rows
    sat = [(i, rho[i]) for i in range(len(rho)) if rho[i] in S]
    if not sat:
        return None

    n_sat  = len(sat)
    n_cols = len(M[0]) if M else 0

    # Build matrix A (n_cols × n_sat) = M_sat^T  over Fraction
    # A[r][c] = M[sat[c][0]][r]
    # We want to solve A · ω = e_1  (e_1 is n_cols-dim column vector)
    # Augmented system: [A | e_1]  (n_cols rows, n_sat+1 cols)
    aug = []
    for r in range(n_cols):
        row = [Fraction(M[sat[c][0]][r]) for c in range(n_sat)]
        rhs = Fraction(1) if r == 0 else Fraction(0)
        row.append(rhs)
        aug.append(row)

    # Gaussian elimination (forward + back-substitution) on aug
    # We pivot on columns 0..n_sat-1, across rows 0..n_cols-1
    pivot_row_for_col = {}   # col -> row where pivot was established
    cur_row = 0
    for col in range(n_sat):
        # Find pivot in this column at or below cur_row
        pivot = -1
        for r in range(cur_row, n_cols):
            if aug[r][col] != 0:
                pivot = r
                break
        if pivot < 0:
            continue
        aug[cur_row], aug[pivot] = aug[pivot], aug[cur_row]
        pivot_row_for_col[col] = cur_row
        piv_val = aug[cur_row][col]
        # Normalise pivot row
        aug[cur_row] = [x / piv_val for x in aug[cur_row]]
        # Eliminate this column in all other rows
        for r in range(n_cols):
            if r != cur_row and aug[r][col] != 0:
                factor = aug[r][col]
                aug[r] = [aug[r][k] - factor * aug[cur_row][k]
                          for k in range(n_sat + 1)]
        cur_row += 1

    # Extract ω: for each column c (variable ω_c),
    # if it has a pivot row, ω_c = aug[pivot_row][rhs_col]; else ω_c = 0
    # Then verify Σ ω_i M_i = e_1
    omega_frac = []
    for col in range(n_sat):
        if col in pivot_row_for_col:
            r = pivot_row_for_col[col]
            omega_frac.append(aug[r][n_sat])   # RHS entry of that pivot row
        else:
            omega_frac.append(Fraction(0))

    # Verify: Σ omega_frac[c] * M[sat[c][0]] =? e_1
    check = [Fraction(0)] * n_cols
    for c, (orig_i, _) in enumerate(sat):
        w = omega_frac[c]
        if w == 0:
            continue
        for r in range(n_cols):
            check[r] += w * Fraction(M[orig_i][r])
    if check[0] != Fraction(1) or any(check[r] != 0 for r in range(1, n_cols)):
        # S does not satisfy the policy (no valid reconstruction)
        return None

    # Convert Fraction -> Charm ZR
    def _frac_to_zr(f: "Fraction") -> Any:
        if f == 0:
            return group.init(ZR, 0)
        num_zr = group.init(ZR, int(abs(f.numerator)))
        if f.numerator < 0:
            num_zr = group.init(ZR, 0) - num_zr
        den_int = int(f.denominator)
        if den_int == 1:
            return num_zr
        den_zr = group.init(ZR, den_int)
        return num_zr * (den_zr ** -1)   # den^{-1} mod p via Charm

    omega = {}
    for c, (orig_i, _) in enumerate(sat):
        if omega_frac[c] != 0:
            omega[orig_i] = _frac_to_zr(omega_frac[c])
    return omega


# ============================================================
# Binary tree + KUNodes
# ============================================================

@dataclass
class Node:
    nid: str
    parent: Optional["Node"] = None
    left:   Optional["Node"] = None
    right:  Optional["Node"] = None
    gx: Any = None   # G1 element, assigned lazily

    def __hash__(self) -> int:
        return hash(self.nid)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Node) and self.nid == other.nid


@dataclass
class BinaryTree:
    root: Node
    leaves: List[Node]

    def allocate_leaf(self, label: str) -> Node:
        """Pick a deterministic leaf for the given label (PoC strategy)."""
        idx = int(hashlib.sha256(label.encode()).hexdigest(), 16) % len(self.leaves)
        return self.leaves[idx]


def build_full_binary_tree(depth: int) -> BinaryTree:
    if depth < 1:
        raise ValueError("depth must be >= 1")
    root = Node("root")
    level = [root]
    for _ in range(1, depth):
        nxt = []
        for n in level:
            n.left  = Node(n.nid + "L", parent=n)
            n.right = Node(n.nid + "R", parent=n)
            nxt.extend([n.left, n.right])
        level = nxt
    return BinaryTree(root=root, leaves=level)

def path_to_root(leaf: Node) -> List[Node]:
    out: List[Node] = []
    cur: Optional[Node] = leaf
    while cur is not None:
        out.append(cur)
        cur = cur.parent
    return out

def kunodes(bt: BinaryTree, R: List[Tuple[Node, int]], t: int) -> Set[Node]:
    """
    KUNodes(BT, R, t): minimal set of nodes covering all non-revoked users at time t.
    R is a list of (leaf_node, revocation_time).
    A user is revoked at time t if their revocation_time <= t.
    """
    X: Set[Node] = set()

    for leaf, ti in R:
        if ti <= t:
            for x in path_to_root(leaf):
                X.add(x)

    Y: Set[Node] = set()
    for x in X:
        if x.left  and x.left  not in X:
            Y.add(x.left)
        if x.right and x.right not in X:
            Y.add(x.right)

    if not Y:
        # No revocations: entire tree is available; use root as representative
        Y.add(bt.root)
    return Y


# ============================================================
# Scheme dataclasses
# ============================================================

@dataclass
class SetupResult:
    curve: str
    mpk: Dict[str, Any]
    msk: Dict[str, Any]
    st: Dict[str, Any]

@dataclass
class UserKeyResult:
    sk_id: Tuple[Any, Any]   # (sk1, sk2)
    vk_id: Any               # G1
    psk_id_s: Dict[str, Any] # long-term transformation key material
    leaf_nid: str
    ID: str
    S: List[str]

@dataclass
class TKeyUpResult:
    tuk_t: Dict[str, Any]
    t: int

@dataclass
class TranKGResult:
    tk_id_t_s: Dict[str, Any]
    t: int

@dataclass
class EncryptResult:
    t_prime: int
    policy_str: str
    policy: Dict[str, Any]    # {"M": [...], "rho": [...]}
    hdr: Tuple[Any, Any, Any] # (C_hat, C1, C2)
    ct: Dict[str, Any]

@dataclass
class TransformResult:
    ok: bool
    pi: Any   # GT element = e(u0^r, g^s)


# ============================================================
# Setup
# ============================================================

def _check_setup_constraint(mpk: Dict[str, Any]) -> bool:
    """
    Verify the critical Setup constraint: e(g0, k0) == e(u0, g).
    Call this after setup() or load_setup_json() to confirm correctness.
    """
    group = PairingGroup(mpk["curve"])
    lhs = pair(mpk["g0"], mpk["k0"])
    rhs = pair(mpk["u0"], mpk["g"])
    ok  = (lhs == rhs)
    if not ok:
        print("[CRITICAL] Setup constraint e(g0,k0)=e(u0,g) VIOLATED — regenerate keys!")
    return ok


def setup(curve: str = "SS512", depth: int = 4) -> SetupResult:
    """
    Setup(λ, U, T) -> (mpk, msk, st)

    mpk = (G, g0, k, k0, u, h, u0, h0, u1, h1, w, v, e(g,g)^α, e(u0,g)^β, H)
    msk = (α, β, st)

    Critical constraint from paper: e(g0, k0) = e(u0, g)
    We enforce this by setting g0 = g and k0 = u0.
    Then: e(g0, k0) = e(g, u0) = e(u0, g)  ✓
    """
    group = PairingGroup(curve)
    H = make_H(group)

    g  = group.random(G1)
    u0 = group.random(G1)
    u1 = group.random(G1)
    h0 = group.random(G1)
    h1 = group.random(G1)
    u  = group.random(G1)
    h  = group.random(G1)
    v  = group.random(G1)
    w  = group.random(G1)
    k  = group.random(G1)

    # Enforce paper constraint: e(g0, k0) = e(u0, g)
    # By setting g0 = g and k0 = u0:
    #   e(g, u0) = e(u0, g)  ✓  (bilinearity symmetry)
    g0 = g
    k0 = u0

    alpha = group.random(ZR)
    beta  = group.random(ZR)

    # e(g,g)^α  and  e(u0,g)^β  — precomputed for efficiency
    egg_alpha  = pair(g,  g)  ** alpha
    eu0g_beta  = pair(u0, g)  ** beta

    mpk = {
        "curve":     curve,
        "g":         g,
        "g0":        g0,
        "u0":        u0,
        "u1":        u1,
        "h0":        h0,
        "h1":        h1,
        "u":         u,
        "h":         h,
        "v":         v,
        "w":         w,
        "k":         k,
        "k0":        k0,
        "egg_alpha": egg_alpha,
        "eu0g_beta": eu0g_beta,
        "H":         H,   # not serialized; reconstructed on load
    }
    msk = {"alpha": alpha, "beta": beta, "g": g}

    bt = build_full_binary_tree(depth=depth)
    st = {
        "depth":      depth,
        "BT":         bt,
        "R":          [],   # list of (leaf_node, time)
        "id_to_leaf": {},   # ID -> leaf_nid
    }
    return SetupResult(curve=curve, mpk=mpk, msk=msk, st=st)


# ============================================================
# UserKG
# ============================================================

def userkg(mpk: Dict[str, Any], msk: Dict[str, Any], st: Dict[str, Any],
           ID: str, S: List[str]) -> UserKeyResult:
    """
    UserKG(mpk, msk, ID, S)

    sk_ID  = (g^α (u0^ID h0)^r,  g^r)
    vk_ID  = g0^(β + r·ID)

    psk_{ID,S}[x] for x ∈ Path(θ):
      A_x = (w^ID k)^{rx} · gx^{-1} · u0^r
      B_x = g^{rx}
      For each τ ∈ S:
        C_{x,τ} = (u^{Sτ} h)^{r_{x,τ}} · v^{-rx}
        D_{x,τ} = g^{r_{x,τ}}
    """
    group = PairingGroup(mpk["curve"])

    g  = mpk["g"]
    g0 = mpk["g0"]
    u0 = mpk["u0"]
    h0 = mpk["h0"]
    u  = mpk["u"]
    h  = mpk["h"]
    v  = mpk["v"]
    w  = mpk["w"]
    k  = mpk["k"]

    alpha  = msk["alpha"]
    beta   = msk["beta"]
    id_z   = _id_to_zr(group, ID)
    r      = group.random(ZR)

    # sk_ID = ( g^α · (u0^ID h0)^r,  g^r )
    sk1    = (g ** alpha) * ((u0 ** id_z) * h0) ** r
    sk2    = g ** r
    sk_id  = (sk1, sk2)

    # vk_ID = g0^(β + r·ID)
    vk_id  = g0 ** (beta + r * id_z)

    # Locate / allocate leaf for ID
    bt: BinaryTree = st["BT"]
    if ID in st["id_to_leaf"]:
        leaf_nid = st["id_to_leaf"][ID]
        theta    = _bt_find(bt, leaf_nid)
    else:
        theta            = bt.allocate_leaf(ID)
        st["id_to_leaf"][ID] = theta.nid

    # Build psk over Path(θ)
    psk_nodes: Dict[str, Any] = {}
    for x in path_to_root(theta):
        if x.gx is None:
            x.gx = group.random(G1)
        gx = x.gx

        rx    = group.random(ZR)
        wid_k = (w ** id_z) * k

        # A_x = (w^ID k)^{rx} · gx^{-1} · u0^r
        Ax = (wid_k ** rx) * (gx ** -1) * (u0 ** r)
        # B_x = g^{rx}
        Bx = g ** rx

        attr_comps: Dict[str, Any] = {}
        for tau in S:
            s_tau = _attr_to_zr(group, tau)
            rxt   = group.random(ZR)
            # C_{x,τ} = (u^{Sτ} h)^{r_{x,τ}} · v^{-rx}
            Cxt = ((u ** s_tau) * h) ** rxt * (v ** (-rx))
            # D_{x,τ} = g^{r_{x,τ}}
            Dxt = g ** rxt
            attr_comps[tau] = {"C": Cxt, "D": Dxt}

        psk_nodes[x.nid] = {
            "A":    Ax,
            "B":    Bx,
            "gx":   gx,
            "rx":   rx,   # kept for TranKG re-assembly
            "attrs": attr_comps,
        }

    psk_id_s = {
        "ID":    ID,
        "S":     list(S),
        "r":     r,       # kept for TranKG
        "theta": theta.nid,
        "nodes": psk_nodes,
    }
    return UserKeyResult(
        sk_id=sk_id, vk_id=vk_id, psk_id_s=psk_id_s,
        leaf_nid=theta.nid, ID=ID, S=list(S),
    )


# ============================================================
# TKeyUp
# ============================================================

def tkeyup(mpk: Dict[str, Any], msk: Dict[str, Any], st: Dict[str, Any],
           t: int) -> TKeyUpResult:
    """
    TKeyUp(mpk, msk, st, R, t)

    tuk_t = { gx · (u1^t h1)^{sx},  g^{sx} }_{x ∈ KUNodes(BT,R,t)}

    Paper formula: gx · (u1^t h1)^{sx}
    where gx is the node element stored during UserKG.
    """
    group = PairingGroup(mpk["curve"])
    bt: BinaryTree = st["BT"]
    R  = st["R"]   # list of (leaf_node, revocation_time)
    Y  = kunodes(bt, R, t)

    g  = mpk["g"]
    u1 = mpk["u1"]
    h1 = mpk["h1"]

    t_zr   = group.init(ZR, int(t))
    u1t_h1 = (u1 ** t_zr) * h1   # u1^t · h1

    tuk_nodes: Dict[str, Any] = {}
    for y in Y:
        if y.gx is None:
            # Should be pre-assigned during UserKG; generate if missing (edge case)
            y.gx = group.random(G1)
        sx = group.random(ZR)

        # Paper: F_y = gx · (u1^t h1)^{sx}
        Fy = y.gx * (u1t_h1 ** sx)
        # G_y = g^{sx}
        Gy = g ** sx

        tuk_nodes[y.nid] = {"F": Fy, "G": Gy}

    tuk_t = {"t": int(t), "Y": list(tuk_nodes.keys()), "nodes": tuk_nodes}
    return TKeyUpResult(tuk_t=tuk_t, t=int(t))


# ============================================================
# TranKG
# ============================================================

def trankg(mpk: Dict[str, Any], psk_id_s: Dict[str, Any],
           tuk_t: Dict[str, Any], t: int) -> Optional[TranKGResult]:
    """
    TranKG(mpk, psk_{ID,S}, tuk_t)

    Finds unique x ∈ Path(θ) ∩ KUNodes(BT,R,t).
    Computes short-term transformation key:

    tk^S_{ID,t} = (
      (w^ID k)^{rx} · u0^r · (u1^t h1)^{sx},   ← A combined
      g^{rx},                                     ← B
      g^{sx},                                     ← G (from tuk)
      { (u^{Sτ} h)^{r_{x,τ}} · v^{-rx},  g^{r_{x,τ}} }_{τ∈S}
    )

    Note: (u1^t h1)^{sx} is already embedded in tuk_t["F"] = gx·(u1^t h1)^{sx}.
    We recover (u1^t h1)^{sx} = F_y / gx (using stored gx).
    Then: A_combined = A_x · (u1^t h1)^{sx}
                     = [(w^ID k)^{rx}·gx^{-1}·u0^r] · [(F_y / gx)]
                     Wait — F_y = gx·(u1^t h1)^{sx}, so F_y/gx = (u1^t h1)^{sx}.
                     A_x · F_y/gx = (w^ID k)^{rx}·gx^{-1}·u0^r · (u1^t h1)^{sx}
                                  = (w^ID k)^{rx}·u0^r·(u1^t h1)^{sx} · gx^{-1}
    Actually the paper's tk^S_{ID,t} first component is:
      (w^ID k)^{rx} · u0^r · (u1^t h1)^{sx}
    which equals A_x * gx * (u1^t h1)^{sx} (since A_x = ... * gx^{-1}).
    So: tk_A = A_x * gx * (F_y / gx) = A_x * F_y.
    """
    group = PairingGroup(mpk["curve"])

    path_ids = set(psk_id_s["nodes"].keys())
    Y_ids    = set(tuk_t["Y"])
    inter    = sorted(path_ids & Y_ids)

    if not inter:
        print("[TranKG] No intersection: Path ∩ KUNodes = ∅  →  ⊥")
        return None

    # Paper guarantees exactly one intersection node
    z  = inter[0]
    pz = psk_id_s["nodes"][z]
    dz = tuk_t["nodes"][z]

    # tk_A = A_x · gx · F_y   (see note above)
    #       = (w^ID k)^{rx} · gx^{-1} · u0^r · gx · gx · (u1^t h1)^{sx}
    # Simplify: A_x * gx = (w^ID k)^{rx} · u0^r
    #           * F_y    = (w^ID k)^{rx} · u0^r · gx · (u1^t h1)^{sx}
    # Hmm — F_y = gx*(u1^t h1)^sx, A_x = (wIDk)^rx * gx^{-1} * u0^r
    # A_x * F_y = (wIDk)^rx * gx^{-1} * u0^r * gx * (u1^t h1)^sx
    #           = (wIDk)^rx * u0^r * (u1^t h1)^sx   ✓  (gx^{-1}*gx cancels)
    tk_A  = pz["A"] * dz["F"]   # (w^ID k)^{rx} · u0^r · (u1^t h1)^{sx}
    tk_B  = pz["B"]              # g^{rx}
    tk_G  = dz["G"]              # g^{sx}

    tk = {
        "ID":             psk_id_s["ID"],
        "S":              list(psk_id_s["S"]),
        "t":              int(t),
        "intersect_node": z,
        "A":  tk_A,
        "B":  tk_B,
        "G":  tk_G,
        "attrs": pz["attrs"],   # {τ: {"C": ..., "D": ...}}
    }
    return TranKGResult(tk_id_t_s=tk, t=int(t))


# ============================================================
# Encrypt
# ============================================================

def encrypt_by_policy(mpk: Dict[str, Any], policy_str: str,
                      t_prime: int, msg: Any) -> EncryptResult:
    """
    Encrypt(mpk, (M,ρ), t', M)

    Hdr = ( e(g,g)^{αs} · msg,  g^s,  h0^s )

    c = ( e(u0,g)^{βs} · M_R,         C0
          H(M_R)^s,                    CH
          g^s,                         Cg
          k^s,                         Ck
          k0^s,                        Ck0
          (u1^{t'} h1)^s,             Ct
          { w^{λi} · v^{si},           R1_i
            (u^{ρ(i)} h)^{-si},       R2_i
            g^{si} }_{i∈[l]}           R3_i  )
    """
    group = PairingGroup(mpk["curve"])
    H = mpk["H"]

    g  = mpk["g"]
    u0 = mpk["u0"]
    u1 = mpk["u1"]
    h0 = mpk["h0"]
    h1 = mpk["h1"]
    u  = mpk["u"]
    h  = mpk["h"]
    v  = mpk["v"]
    w  = mpk["w"]
    k  = mpk["k"]
    k0 = mpk["k0"]
    egg_alpha = mpk["egg_alpha"]
    eu0g_beta = mpk["eu0g_beta"]

    M_mat, rho = _policy_to_lsss(policy_str)
    if len(M_mat) != len(rho):
        raise ValueError("rho length mismatch with M rows")

    s       = group.random(ZR)
    lambdas = lsss_shares(group, M_mat, s)

    # Random masking element M_R ∈ GT
    M_R = group.random(GT)

    # Header
    C_hat = (egg_alpha ** s) * msg   # e(g,g)^{αs} · M  (actual message)
    C1    = g  ** s                   # g^s
    C2    = h0 ** s                   # h0^s
    hdr   = (C_hat, C1, C2)

    # Core ciphertext components
    C0  = (eu0g_beta ** s) * M_R          # e(u0,g)^{βs} · M_R
    CH  = H(M_R) ** s                      # H(M_R)^s
    Cg  = g  ** s                          # g^s  (same as C1; kept separately per paper)
    Ck  = k  ** s                          # k^s
    Ck0 = k0 ** s                          # k0^s
    t_zr = group.init(ZR, int(t_prime))
    Ct  = ((u1 ** t_zr) * h1) ** s        # (u1^{t'} h1)^s

    rows = []
    for i, attr_name in enumerate(rho):
        lam_i = lambdas[i]
        si    = group.random(ZR)
        rho_i = _attr_to_zr(group, attr_name)

        R1 = (w ** lam_i) * (v ** si)              # w^{λi} · v^{si}
        R2 = ((u ** rho_i) * h) ** (-si)           # (u^{ρ(i)} h)^{-si}
        R3 = g ** si                                # g^{si}
        rows.append({"attr": attr_name, "R1": R1, "R2": R2, "R3": R3})

    ct = {
        "C0":  C0,
        "CH":  CH,
        "Cg":  Cg,
        "Ck":  Ck,
        "Ck0": Ck0,
        "Ct":  Ct,
        "rows": rows,
    }
    return EncryptResult(
        t_prime=int(t_prime),
        policy_str=policy_str,
        policy={"M": M_mat, "rho": list(rho)},
        hdr=hdr,
        ct=ct,
    )


# ============================================================
# Transform
# ============================================================

def transform(mpk: Dict[str, Any], enc: Any,
              tk_id_t_s: Dict[str, Any], ID: str) -> Optional[TransformResult]:
    """
    Transform(mpk, c, tk^S_{ID,t}, ID)

    Step 1: verify t == t'
    Step 2: check S satisfies access policy (M,ρ)
    Step 3: compute pairing product for satisfied rows:
      ∏_{ρ(i)∈S} [ e((u^{Ai}h)^{r_{x,i}}·v^{-rx}, g^{si})
                  · e((u^{ρ(i)}h)^{-si}, g^{r_{x,i}})
                  · e(w^{λi}·v^{si}, g^{rx}) ]^{ω_i}
      = e(w^s, g^{rx})

    Step 4: compute π:
      π = e(A, g^s) / [ e(w^s, g^{rx})^{ID} · e(k^s, g^{rx}) · e((u1^t h1)^s, g^{sx}) ]
        = e(u0^r, g^s)
    """
    group = PairingGroup(mpk["curve"])

    # --- unpack enc
    if isinstance(enc, EncryptResult):
        tprime     = enc.t_prime
        ct         = enc.ct
        policy     = enc.policy
    elif isinstance(enc, dict):
        tprime     = enc.get("t_prime") or enc.get("t")
        ct         = enc.get("ct", {})
        policy     = enc.get("policy", {})
    else:
        print("[Transform] Unknown enc type")
        return None

    # --- time check
    if tprime is None:
        print("[Transform] enc missing t_prime")
        return None
    if int(tk_id_t_s["t"]) != int(tprime):
        print(f"[Transform] time mismatch: tk.t={tk_id_t_s['t']}, enc.t'={tprime}")
        return None

    # --- check policy satisfaction
    S_user   = set(tk_id_t_s.get("S", []))
    M_mat    = policy.get("M", [])
    rho_list = policy.get("rho", [])
    rows     = ct.get("rows", []) if isinstance(ct, dict) else []

    omega = lsss_reconstruct(group, M_mat, rho_list, S_user)
    if omega is None:
        print(f"[Transform] S={S_user} does not satisfy policy")
        return None

    # --- pairing product  ∏ [...]^{ω_i} = e(w^s, g^{rx})
    # Paper Transform formula:
    # ∏_{ρ(i)∈S} ( e((u^{Ai}·h)^{r_{x,i}}·v^{-rx}, g^{si})
    #             · e((u^{ρ(i)}h)^{-si}, g^{r_{x,i}})
    #             · e(w^{λi}·v^{si},   g^{rx}) )^{ω_i}
    #
    # In our encoding:
    #   tk attrs[τ]: C = (u^{Sτ}h)^{r_{x,τ}}·v^{-rx},  D = g^{r_{x,τ}}
    #   ct rows[i]:  R1 = w^{λi}·v^{si},  R2 = (u^{ρ(i)}h)^{-si},  R3 = g^{si}
    #   tk: B = g^{rx}

    g_rx = tk_id_t_s["B"]   # g^{rx}

    # Build lookup: attr -> tk attr components
    tk_attrs = tk_id_t_s.get("attrs", {})

    # Build lookup: attr -> ct row
    ct_row_by_attr: Dict[str, Any] = {}
    for row in rows:
        if isinstance(row, dict):
            ct_row_by_attr[row["attr"]] = row

    # Accumulate pairing product (start with GT identity = pair(g,g)^0)
    # We compute it as a running product
    prod_gt = None

    for i, attr_name in enumerate(rho_list):
        if i not in omega:
            continue
        wi = omega[i]
        if attr_name not in tk_attrs or attr_name not in ct_row_by_attr:
            print(f"[Transform] Missing components for attr={attr_name}")
            return None

        tk_C = tk_attrs[attr_name]["C"]   # (u^{Sτ}h)^{r_{x,τ}} · v^{-rx}
        tk_D = tk_attrs[attr_name]["D"]   # g^{r_{x,τ}}
        R1   = ct_row_by_attr[attr_name]["R1"]  # w^{λi} · v^{si}
        R2   = ct_row_by_attr[attr_name]["R2"]  # (u^{ρ(i)}h)^{-si}
        R3   = ct_row_by_attr[attr_name]["R3"]  # g^{si}

        # Triple pairing for row i
        p1 = pair(tk_C, R3)     # e((u^Aih)^{r_{x,i}}·v^{-rx},  g^{si})
        p2 = pair(R2,   tk_D)   # e((u^{ρ(i)}h)^{-si},           g^{r_{x,i}})
        p3 = pair(R1,   g_rx)   # e(w^{λi}·v^{si},               g^{rx})

        term = (p1 * p2 * p3) ** wi

        prod_gt = term if prod_gt is None else prod_gt * term

    if prod_gt is None:
        print("[Transform] Empty pairing product")
        return None

    # prod_gt should equal e(w^s, g^{rx})

    # --- compute π = e(u0^r, g^s)
    # tk_A = (w^ID k)^{rx} · u0^r · (u1^t h1)^{sx}
    # π = e(A, g^s) / [ e(w·k, g^{rx})^{ID·s... ]
    # Paper formula (simpler re-arrangement):
    #   π = e(A, Cg) / [ e(w^s, g^{rx})^{ID} · e(k^s, g^{rx}) · e(Ct, G) ]
    # where Cg = g^s, Ct = (u1^t h1)^s, G = g^{sx}, and prod_gt = e(w^s, g^{rx}).

    A  = tk_id_t_s["A"]   # (w^ID k)^{rx} · u0^r · (u1^t h1)^{sx}
    G  = tk_id_t_s["G"]   # g^{sx}
    Cg = ct["Cg"]          # g^s
    Ck = ct["Ck"]          # k^s
    Ct = ct["Ct"]          # (u1^{t'} h1)^s

    id_z = _id_to_zr(group, ID)

    # e(A, g^s)
    numer = pair(A, Cg)
    # denominator: e(w^s, g^{rx})^{ID} · e(k^s, g^{rx}) · e((u1^t h1)^s, g^{sx})
    denom = (prod_gt ** id_z) * pair(Ck, g_rx) * pair(Ct, G)

    pi = numer / denom   # should equal e(u0^r, g^s)

    return TransformResult(ok=True, pi=pi)


# ============================================================
# Verify
# ============================================================

def verify(mpk: Dict[str, Any], enc: EncryptResult,
           pi: Any, vk_id: Any, ID: str) -> bool:
    """
    Verify(mpk, c, π, vk_ID, ID)

    Paper formula:
      e(g^s, H( e(u0,g)^{βs}·M_R · e(u0^r,g^s)^{ID} / e(g0^{β+rID}, k0^s) ))
        == e(H(M_R)^s, g)

    With Setup constraint g0=g, k0=u0:
      e(vk_id, Ck0) = e(g^{β+rID}, u0^s) = e(u0,g)^{(β+rID)s}
      C0 * π^{ID}   = e(u0,g)^{βs}·M_R · e(u0,g)^{rIDs}
                    = e(u0,g)^{(β+rID)s} · M_R
      inner = M_R   ✓
    """
    group = PairingGroup(mpk["curve"])
    g   = mpk["g"]
    g0  = mpk["g0"]
    k0  = mpk["k0"]
    u0  = mpk["u0"]
    H   = mpk["H"]

    id_z = _id_to_zr(group, ID)

    C0   = enc.ct["C0"]
    Cg   = enc.ct["Cg"]
    Ck0  = enc.ct["Ck0"]
    CH   = enc.ct["CH"]

    # Diagnostic: always print Setup constraint check
    constraint_ok = (pair(g0, k0) == pair(u0, g))
    print(f"[Verify-DBG] e(g0,k0)==e(u0,g): {constraint_ok}")
    if not constraint_ok:
        print("[Verify-DBG] CRITICAL: Setup constraint violated — re-run 'ta_local.py setup'!")

    # Step 1: inner = (C0 · π^{ID}) / e(vk_ID, k0^s)  should equal M_R
    denom_v = pair(vk_id, Ck0)
    inner   = (C0 * (pi ** id_z)) / denom_v

    # Step 2: lhs = e(g^s, H(inner)),  rhs = e(H(M_R)^s, g)
    lhs = pair(Cg, H(inner))
    rhs = pair(CH, g)

    # Diagnostic: check bilinearity e(g^a, X) == e(X^a, g) in this group
    _a  = group.random(ZR)
    _X  = group.random(G1)
    _ok = (pair(g ** _a, _X) == pair(_X ** _a, g))
    print(f"[Verify-DBG] bilinearity e(g^a,X)==e(X^a,g): {_ok}")

    result = (lhs == rhs)
    print(f"[Verify] ID={ID}  result={'PASS' if result else 'FAIL'}")
    return result


# ============================================================
# Decrypt
# ============================================================

def decrypt(mpk: Dict[str, Any], sk_id: Tuple[Any, Any],
            pi: Any, hdr: Tuple[Any, Any, Any], ID: str) -> Any:
    """
    Decrypt(mpk, sk_ID, π, Hdr, ID)

    Recover e(g,g)^{αs}:
      e(sk1, C1) / (π^{ID} · e(C2, sk2))
      = e(g^α (u0^ID h0)^r, g^s) / (e(u0^r,g^s)^{ID} · e(h0^s, g^r))
      = e(g,g)^{αs} · e(u0^ID h0,g)^{rs} / (e(u0,g)^{rIDs} · e(h0,g)^{rs})
      = e(g,g)^{αs}

    Then msg = C_hat / e(g,g)^{αs}.
    """
    group = PairingGroup(mpk["curve"])
    id_z = _id_to_zr(group, ID)

    C_hat, C1, C2 = hdr
    sk1,   sk2    = sk_id

    egg_alpha_s = pair(sk1, C1) / ((pi ** id_z) * pair(C2, sk2))
    msg = C_hat / egg_alpha_s
    return msg


# ============================================================
# Revocation helpers
# ============================================================

def revoke(st: Dict[str, Any], ID: str, t: int) -> bool:
    """Add ID to revocation list with revocation time t. Returns True if found."""
    bt: BinaryTree = st["BT"]
    leaf_nid = st["id_to_leaf"].get(ID)
    if leaf_nid is None:
        print(f"[Revoke] ID={ID} not found in tree")
        return False
    leaf = _bt_find(bt, leaf_nid)
    st["R"].append((leaf, t))
    print(f"[Revoke] ID={ID} revoked at t={t}")
    return True


# ============================================================
# Serialization / persistence helpers
# ============================================================

def _bt_snapshot(bt: BinaryTree, group: Optional[PairingGroup] = None) -> Dict[str, Any]:
    """Snapshot the BT structure AND each node's gx element (if set).
    gx must be serialized so that tkeyup and userkg always use the same gx per node.
    """
    nodes = []
    def dfs(n: Optional[Node]):
        if n is None:
            return
        entry = {
            "nid":    n.nid,
            "parent": n.parent.nid if n.parent else None,
            "left":   n.left.nid   if n.left   else None,
            "right":  n.right.nid  if n.right  else None,
            "gx":     None,
        }
        if n.gx is not None and group is not None:
            try:
                entry["gx"] = _b64e(group.serialize(n.gx))
            except Exception:
                pass
        nodes.append(entry)
        dfs(n.left)
        dfs(n.right)
    dfs(bt.root)
    return {"nodes": nodes, "leaves": [x.nid for x in bt.leaves]}

def _bt_restore(snap: Dict[str, Any], group: Optional[PairingGroup] = None) -> BinaryTree:
    by_id: Dict[str, Node] = {}
    for row in snap["nodes"]:
        by_id[row["nid"]] = Node(row["nid"])
    for row in snap["nodes"]:
        n = by_id[row["nid"]]
        if row["parent"]: n.parent = by_id[row["parent"]]
        if row["left"]:   n.left   = by_id[row["left"]]
        if row["right"]:  n.right  = by_id[row["right"]]
        # Restore gx if present
        if group is not None and row.get("gx"):
            try:
                n.gx = group.deserialize(_b64d(row["gx"]))
            except Exception:
                pass
    root   = by_id["root"]
    leaves = [by_id[nid] for nid in snap["leaves"]]
    return BinaryTree(root=root, leaves=leaves)

def _bt_find(bt: BinaryTree, nid: str) -> Node:
    stack = [bt.root]
    while stack:
        n = stack.pop()
        if n.nid == nid:
            return n
        if n.left:  stack.append(n.left)
        if n.right: stack.append(n.right)
    raise KeyError(f"BT node not found: {nid}")


def export_setup_json(out_path: str, res: SetupResult) -> None:
    group = PairingGroup(res.curve)
    blob = {
        "curve": res.curve,
        "depth": res.st["depth"],
        "mpk":   serialize_any(group, {k: v for k, v in res.mpk.items() if k != "H"}),
        "msk":   serialize_any(group, res.msk),
        "state": {
            "bt":         _bt_snapshot(res.st["BT"], group),   # now includes gx
            "R":          [(leaf.nid, int(t)) for (leaf, t) in res.st["R"]],
            "id_to_leaf": dict(res.st["id_to_leaf"]),
        },
    }
    save_json(out_path, blob)

def load_setup_json(path: str) -> Tuple[PairingGroup, Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    blob   = load_json(path)
    curve  = blob["curve"]
    group  = PairingGroup(curve)
    mpk    = deserialize_any(group, blob["mpk"])
    msk    = deserialize_any(group, blob["msk"])
    mpk["curve"] = curve
    mpk["H"]     = make_H(group)

    bt = _bt_restore(blob["state"]["bt"], group)   # now restores gx per node
    st = {
        "depth":      int(blob.get("depth", 4)),
        "BT":         bt,
        "R":          [(_bt_find(bt, nid), int(t)) for (nid, t) in blob["state"]["R"]],
        "id_to_leaf": dict(blob["state"]["id_to_leaf"]),
    }

    # Verify Setup constraint: e(g0, k0) == e(u0, g)
    _check_setup_constraint(mpk)

    return group, mpk, msk, st


def dump_encrypt(group: PairingGroup, enc: EncryptResult) -> Dict[str, Any]:
    return {
        "t_prime":    enc.t_prime,
        "policy_str": enc.policy_str,
        "policy":     enc.policy,
        "hdr":        serialize_any(group, list(enc.hdr)),
        "ct":         serialize_any(group, enc.ct),
    }

def load_encrypt(group: PairingGroup, blob: Dict[str, Any]) -> EncryptResult:
    hdr_list = deserialize_any(group, blob["hdr"])
    ct       = deserialize_any(group, blob["ct"])
    return EncryptResult(
        t_prime=int(blob["t_prime"]),
        policy_str=blob["policy_str"],
        policy=blob["policy"],
        hdr=tuple(hdr_list),
        ct=ct,
    )

def dump_user(group: PairingGroup, user: UserKeyResult) -> Dict[str, Any]:
    return {
        "ID":       user.ID,
        "S":        user.S,
        "leaf_nid": user.leaf_nid,
        "sk_id":    serialize_any(group, list(user.sk_id)),
        "vk_id":    serialize_any(group, user.vk_id),
        "psk_id_s": serialize_any(group, user.psk_id_s),
    }

def load_user(group: PairingGroup, blob: Dict[str, Any]) -> UserKeyResult:
    sk_list  = deserialize_any(group, blob["sk_id"])
    vk_id    = deserialize_any(group, blob["vk_id"])
    psk_id_s = deserialize_any(group, blob["psk_id_s"])
    return UserKeyResult(
        sk_id=(sk_list[0], sk_list[1]),
        vk_id=vk_id,
        psk_id_s=psk_id_s,
        leaf_nid=blob["leaf_nid"],
        ID=blob["ID"],
        S=list(blob["S"]),
    )

def dump_tuk(group: PairingGroup, up: TKeyUpResult) -> Dict[str, Any]:
    return {"t": up.t, "tuk_t": serialize_any(group, up.tuk_t)}

def load_tuk(group: PairingGroup, blob: Dict[str, Any]) -> TKeyUpResult:
    return TKeyUpResult(tuk_t=deserialize_any(group, blob["tuk_t"]), t=int(blob["t"]))

def dump_tk(group: PairingGroup, tk: TranKGResult) -> Dict[str, Any]:
    return {"t": tk.t, "tk_id_t_s": serialize_any(group, tk.tk_id_t_s)}

def load_tk(group: PairingGroup, blob: Dict[str, Any]) -> TranKGResult:
    return TranKGResult(
        tk_id_t_s=deserialize_any(group, blob["tk_id_t_s"]),
        t=int(blob["t"]),
    )


# ============================================================
# Quick smoke test (run as script)
# ============================================================

def _smoke_test():
    print("=== PV-SR-ABE smoke test ===")
    from charm.toolbox.pairinggroup import PairingGroup, GT

    curve = "SS512"
    group = PairingGroup(curve)

    # 1. Setup
    print("[1] Setup ...")
    res = setup(curve=curve, depth=3)
    mpk, msk, st = res.mpk, res.msk, res.st

    # 2. UserKG
    print("[2] UserKG ...")
    S  = ["A", "B", "C"]
    ID = "alice"
    user = userkg(mpk, msk, st, ID, S)
    print(f"    leaf={user.leaf_nid}")

    # 3. TKeyUp  (no revocations)
    print("[3] TKeyUp t=1 ...")
    tup = tkeyup(mpk, msk, st, t=1)
    print(f"    KUNodes={tup.tuk_t['Y']}")

    # 4. TranKG
    print("[4] TranKG ...")
    tk_res = trankg(mpk, user.psk_id_s, tup.tuk_t, t=1)
    if tk_res is None:
        print("    FAIL: TranKG returned ⊥")
        return
    print(f"    intersect_node={tk_res.tk_id_t_s['intersect_node']}")

    # 5. Encrypt
    print("[5] Encrypt ...")
    msg = group.random(GT)
    policy = "A and B"
    enc = encrypt_by_policy(mpk, policy, t_prime=1, msg=msg)
    print(f"    policy='{policy}'  t'=1")

    # 6. Transform
    print("[6] Transform ...")
    tr = transform(mpk, enc, tk_res.tk_id_t_s, ID)
    if tr is None:
        print("    FAIL: Transform returned None")
        return
    print("    Transform OK")

    # 7. Verify
    print("[7] Verify ...")
    ok = verify(mpk, enc, tr.pi, user.vk_id, ID)
    print(f"    Verify={'PASS' if ok else 'FAIL'}")

    # 8. Decrypt
    print("[8] Decrypt ...")
    recovered = decrypt(mpk, user.sk_id, tr.pi, enc.hdr, ID)
    match = (recovered == msg)
    print(f"    Decrypt correct={match}")

    if ok and match:
        print("=== ALL TESTS PASSED ===")
    else:
        print("=== SOME TESTS FAILED ===")


if __name__ == "__main__":
    _smoke_test()