# -*- coding: utf-8 -*-
"""
ta_local.py  (PKG utilities for PV-SR-ABE)
-----------------------------------------
This replaces the old ta_local role for the *policy-updating* project.

Commands:
  python ta_local.py setup  --out keys/pv_setup.json --curve SS512 --depth 4
  python ta_local.py userkg --setup keys/pv_setup.json --id bob@example.com --attrs "A,C" --out keys/bob_user.json
  python ta_local.py revoke --setup keys/pv_setup.json --id alice@example.com --t 5
  python ta_local.py tkeyup --setup keys/pv_setup.json --t 4 --out keys/tuk_4.json

Notes:
- In a real system, msk never leaves the PKG.
  This PoC stores it in pv_setup.json for reproducibility.
- Revocation is cumulative: each call to 'revoke' appends to the list
  stored in pv_setup.json. TKeyUp always uses the current list.
"""

from __future__ import annotations

import argparse

import pv_core


def cmd_setup(args: argparse.Namespace) -> None:
    res = pv_core.setup(curve=args.curve, depth=args.depth)
    pv_core.export_setup_json(args.out, res)
    print(f"[PKG] Setup OK -> {args.out}")


def cmd_userkg(args: argparse.Namespace) -> None:
    group, mpk, msk, st = pv_core.load_setup_json(args.setup)
    attrs = [x.strip() for x in args.attrs.split(",") if x.strip()]

    user = pv_core.userkg(mpk, msk, st, ID=args.id, S=attrs)

    # Persist updated state (id->leaf mapping may have changed)
    res = pv_core.SetupResult(curve=mpk["curve"], mpk=mpk, msk=msk, st=st)
    pv_core.export_setup_json(args.setup, res)

    blob = pv_core.dump_user(group, user)
    pv_core.save_json(args.out, blob)
    print(f"[PKG] UserKG OK -> {args.out}  (leaf={user.leaf_nid})")


def cmd_revoke(args: argparse.Namespace) -> None:
    group, mpk, msk, st = pv_core.load_setup_json(args.setup)

    # Use the public revoke() helper from pv_core (handles leaf lookup internally)
    ok = pv_core.revoke(st, ID=args.id, t=int(args.t))
    if not ok:
        raise SystemExit(
            f"[PKG] Revoke FAILED: ID='{args.id}' has no allocated leaf. "
            "Run 'userkg' for this ID first."
        )

    # Persist updated revocation list
    res = pv_core.SetupResult(curve=mpk["curve"], mpk=mpk, msk=msk, st=st)
    pv_core.export_setup_json(args.setup, res)
    print(f"[PKG] Revoke OK -> ID={args.id} revoked at t={args.t}")


def cmd_tkeyup(args: argparse.Namespace) -> None:
    group, mpk, msk, st = pv_core.load_setup_json(args.setup)

    # pv_core.tkeyup now reads R from st["R"] internally (no R argument)
    up = pv_core.tkeyup(mpk, msk, st, t=int(args.t))

    pv_core.save_json(args.out, pv_core.dump_tuk(group, up))
    print(f"[PKG] TKeyUp OK -> {args.out}  (KUNodes={up.tuk_t['Y']})")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="PV-SR-ABE PKG command-line tool"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # --- setup ---
    s0 = sub.add_parser("setup", help="Run Setup and write keys/state to JSON")
    s0.add_argument("--curve", default="SS512", help="Pairing curve (default: SS512)")
    s0.add_argument("--depth", type=int, default=4, help="Binary tree depth (default: 4)")
    s0.add_argument("--out",   default="keys/pv_setup.json", help="Output path")
    s0.set_defaults(func=cmd_setup)

    # --- userkg ---
    s1 = sub.add_parser("userkg", help="Generate user secret/verification/PSK keys")
    s1.add_argument("--setup", default="keys/pv_setup.json", help="Setup JSON path")
    s1.add_argument("--id",    required=True, help="User identity string")
    s1.add_argument("--attrs", required=True, help='Comma-separated attributes, e.g. "A,B,C"')
    s1.add_argument("--out",   required=True, help="Output path for user key JSON")
    s1.set_defaults(func=cmd_userkg)

    # --- revoke ---
    s2 = sub.add_parser("revoke", help="Add a user to the revocation list")
    s2.add_argument("--setup", default="keys/pv_setup.json", help="Setup JSON path")
    s2.add_argument("--id",    required=True, help="User identity string to revoke")
    s2.add_argument("--t",     type=int, required=True, help="Revocation time period")
    s2.set_defaults(func=cmd_revoke)

    # --- tkeyup ---
    s3 = sub.add_parser("tkeyup", help="Generate time-based key update message")
    s3.add_argument("--setup", default="keys/pv_setup.json", help="Setup JSON path")
    s3.add_argument("--t",     type=int, required=True, help="Current time period")
    s3.add_argument("--out",   required=True, help="Output path for tuk JSON")
    s3.set_defaults(func=cmd_tkeyup)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()