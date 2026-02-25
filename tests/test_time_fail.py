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
    assert r.returncode == 0, f"CMD failed:\n{args}\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
    return r.stdout

def run_expect_fail(args, cwd=None) -> str:
    r = subprocess.run(args, cwd=cwd, env=_env(), capture_output=True, text=True)
    assert r.returncode != 0, f"Expected fail but succeeded:\n{args}\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
    return r.stdout + "\n" + r.stderr

def test_time_fail(tmp_path: Path):
    keys = tmp_path / "keys"
    store = keys / "store"
    keys.mkdir()
    store.mkdir()

    setup = keys / "pv_setup.json"
    user = keys / "user1.json"
    tuk_t2 = keys / "tuk_t2.json"

    # setup + user key
    run([PY, str(ROOT / "ta_local.py"), "setup", "--out", str(setup)])
    run([PY, str(ROOT / "ta_local.py"), "userkg",
         "--setup", str(setup),
         "--id", "user1",
         "--attrs", "A,C",
         "--out", str(user)])

    # Encrypt uses t=1
    out = run([PY, str(ROOT / "lambda_encrypt.py"),
               "--setup", str(setup),
               "--policy", "A",
               "--t", "1",
               "--plaintext", "hello world",
               "--store_dir", str(store)])
    object_id = parse_object_id(out)

    # KeyUp uses t=2 (intentional mismatch)
    run([PY, str(ROOT / "ta_local.py"), "tkeyup",
         "--setup", str(setup),
         "--t", "2",
         "--out", str(tuk_t2)])

    msg = run_expect_fail([PY, str(ROOT / "client_decrypt.py"),
                           "--setup", str(setup),
                           "--user", str(user),
                           "--tuk", str(tuk_t2),
                           "--object_id", object_id,
                           "--store_dir", str(store)])

    assert ("t mismatch" in msg.lower()) or ("Verify FAILED" in msg) or ("result=FAIL" in msg) or ("Verify PASSED" not in msg)