import os
import sys
import subprocess
from pathlib import Path

import re

OID_RE = re.compile(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)

def parse_object_id(output: str) -> str:
    m = OID_RE.search(output)
    assert m, f"Cannot parse object_id from output:\n{output}"
    return m.group(1)

# Project root (inside container this is usually /var/task)
ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable

def _env():
    env = os.environ.copy()

    env["PYTHONPATH"] = ":".join([
        str(ROOT),
        "/var/task/lib/python3.10/site-packages",
        env.get("PYTHONPATH","")
    ])

    return env

def run(args, cwd=None) -> str:
    r = subprocess.run(args, cwd=cwd, env=_env(), capture_output=True, text=True)
    assert r.returncode == 0, (
        f"CMD failed:\n{args}\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
    )
    return r.stdout

def run_expect_fail(args, cwd=None) -> str:
    r = subprocess.run(args, cwd=cwd, env=_env(), capture_output=True, text=True)
    assert r.returncode != 0, (
        f"Expected fail but succeeded:\n{args}\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
    )
    return r.stdout + "\n" + r.stderr

def test_e2e_ok(tmp_path: Path):
    keys = tmp_path / "keys"
    store = keys / "store"
    keys.mkdir()
    store.mkdir()

    setup = keys / "pv_setup.json"
    user = keys / "user1.json"
    tuk  = keys / "tuk_t1.json"

    # 1) setup
    run([PY, str(ROOT / "ta_local.py"), "setup", "--out", str(setup)])

    # 2) UserKG
    run([PY, str(ROOT / "ta_local.py"), "userkg",
         "--setup", str(setup),
         "--id", "user1",
         "--attrs", "A,C",
         "--out", str(user)])

    # 3) Encrypt -> object_id
    out = run([PY, str(ROOT / "lambda_encrypt.py"),
               "--setup", str(setup),
               "--policy", "A",
               "--t", "1",
               "--plaintext", "hello world",
               "--store_dir", str(store)])
    object_id = parse_object_id(out)

    # 4) TKeyUp
    run([PY, str(ROOT / "ta_local.py"), "tkeyup",
         "--setup", str(setup),
         "--t", "1",
         "--out", str(tuk)])

    # 5) Client decrypt（verify + decrypt）
    out2 = run([PY, str(ROOT / "client_decrypt.py"),
                "--setup", str(setup),
                "--user", str(user),
                "--tuk", str(tuk),
                "--object_id", object_id,
                "--store_dir", str(store)])
    assert "Verify PASSED" in out2
    assert "Plaintext: hello world" in out2