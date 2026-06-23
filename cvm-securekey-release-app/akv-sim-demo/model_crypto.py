#!/usr/bin/env python3
"""
Model weight encryptor/decryptor for the CVM<->CGPU binding PoC.

Encrypts/decrypts model files (e.g. Phi-4-mini *.safetensors) with AES-256-GCM
using a streaming, chunked container so multi-GB weights never need to fit in
memory all at once.

ROLES
-----
  encrypt : the "data owner" provisions encrypted weights. It reads the AES key
            directly from the simulator's key store (it owns the key).
  decrypt : the "confidential workload". It does NOT have the key. It obtains
            the key from the AKV simulator's /release endpoint by presenting the
            binding-gated MAA token exported by AzureAttestSKR -X. Decryption
            therefore succeeds ONLY if attestation + CGPU binding passed.

CONTAINER FORMAT (.enc)
-----------------------
  magic      : 8  bytes  = b"CGPUENC1"
  chunk_size : 4  bytes  big-endian (plaintext bytes per chunk)
  then repeated to EOF:
    nonce    : 12 bytes  (random per chunk)
    ct_len   : 4  bytes  big-endian length of the following field
    ct+tag   : ct_len bytes (AES-256-GCM ciphertext + 16-byte tag)
"""

import argparse
import base64
import glob
import os
import struct
import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: cryptography is required. Install with: pip install cryptography\n")
    raise

MAGIC = b"CGPUENC1"
DEFAULT_CHUNK = 64 * 1024 * 1024  # 64 MiB plaintext per chunk
HERE = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(HERE, ".sim-store", "aes_key.bin")


# ---------------------------------------------------------------------------
# Key acquisition.
# ---------------------------------------------------------------------------
def key_from_store():
    if not os.path.exists(KEY_PATH):
        raise FileNotFoundError(
            f"No data key at {KEY_PATH}. Run: python3 akv_simulator.py keygen")
    with open(KEY_PATH, "rb") as fh:
        return fh.read()


def key_from_simulator(sim_url, token_path, save_response=None):
    import json
    import urllib.request

    with open(token_path, "r", encoding="utf-8") as fh:
        token = fh.read().strip()
    if not token:
        raise ValueError(f"token file {token_path} is empty")

    body = json.dumps({"token": token}).encode("utf-8")
    req = urllib.request.Request(
        sim_url.rstrip("/") + "/release",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(
            f"simulator denied release (HTTP {exc.code}): {detail}") from exc

    if not payload.get("released"):
        raise RuntimeError(f"simulator denied release: {payload.get('reason')}")
    print("  [decrypt] simulator released key after verifying MAA token:")
    for k, v in (payload.get("verified_claims") or {}).items():
        print(f"             {k} = {v}")
    if save_response:
        # Persist the release response for the demo, with the actual key bytes
        # redacted (keep the fingerprint so the released key is still identifiable).
        redacted = dict(payload)
        if "key_b64" in redacted:
            redacted["key_b64"] = "<redacted: " + str(len(payload["key_b64"])) + " b64 chars>"
        with open(save_response, "w", encoding="utf-8") as fh:
            json.dump(redacted, fh, indent=2)
    return base64.b64decode(payload["key_b64"])


# ---------------------------------------------------------------------------
# Streaming AES-256-GCM container.
# ---------------------------------------------------------------------------
def encrypt_file(key, src, dst, chunk_size=DEFAULT_CHUNK):
    aes = AESGCM(key)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(MAGIC)
        fout.write(struct.pack(">I", chunk_size))
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, chunk, None)
            fout.write(nonce)
            fout.write(struct.pack(">I", len(ct)))
            fout.write(ct)


def decrypt_file(key, src, dst):
    aes = AESGCM(key)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        magic = fin.read(8)
        if magic != MAGIC:
            raise ValueError(f"{src}: bad magic (not a CGPUENC1 container)")
        (_chunk_size,) = struct.unpack(">I", fin.read(4))
        while True:
            nonce = fin.read(12)
            if not nonce:
                break
            if len(nonce) != 12:
                raise ValueError(f"{src}: truncated nonce")
            (ct_len,) = struct.unpack(">I", fin.read(4))
            ct = fin.read(ct_len)
            if len(ct) != ct_len:
                raise ValueError(f"{src}: truncated ciphertext")
            fout.write(aes.decrypt(nonce, ct, None))


# ---------------------------------------------------------------------------
# Commands.
# ---------------------------------------------------------------------------
def _targets(model_dir, patterns):
    files = []
    for pat in patterns:
        files.extend(glob.glob(os.path.join(model_dir, pat)))
    return sorted(set(files))


def cmd_encrypt(args):
    key = key_from_store()
    files = _targets(args.model_dir, args.patterns)
    if not files:
        sys.stderr.write(
            f"No files matching {args.patterns} under {args.model_dir}\n")
        return 1
    for src in files:
        dst = src + ".enc"
        print(f"  encrypt {os.path.basename(src)} -> {os.path.basename(dst)}")
        encrypt_file(key, src, dst)
        if args.remove_plaintext:
            os.remove(src)
            print(f"           removed plaintext {os.path.basename(src)}")
    print(f"Encrypted {len(files)} file(s).")
    return 0


def cmd_decrypt(args):
    if args.token and args.sim_url:
        key = key_from_simulator(args.sim_url, args.token,
                                 save_response=args.save_response or None)
    elif args.unsafe_key_from_store:
        key = key_from_store()
    else:
        sys.stderr.write(
            "ERROR: provide --token <file> and --sim-url <url> to obtain the key\n"
            "       from the AKV simulator (the gated path). For local testing\n"
            "       only, --unsafe-key-from-store bypasses attestation.\n")
        return 2

    files = _targets(args.model_dir, [p + ".enc" for p in args.patterns])
    if not files:
        sys.stderr.write(
            f"No *.enc files matching {args.patterns} under {args.model_dir}\n")
        return 1
    for src in files:
        dst = src[:-4]  # strip .enc
        print(f"  decrypt {os.path.basename(src)} -> {os.path.basename(dst)}")
        decrypt_file(key, src, dst)
    print(f"Decrypted {len(files)} file(s).")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Model AES-256-GCM crypto.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("encrypt", help="Encrypt model files (data-owner role).")
    pe.add_argument("--model-dir", required=True)
    pe.add_argument("--patterns", nargs="+",
                    default=["*.safetensors", "*.bin"])
    pe.add_argument("--remove-plaintext", action="store_true",
                    help="Delete plaintext after encrypting (demo realism).")
    pe.set_defaults(func=cmd_encrypt)

    pd = sub.add_parser("decrypt", help="Decrypt model files (workload role).")
    pd.add_argument("--model-dir", required=True)
    pd.add_argument("--patterns", nargs="+",
                    default=["*.safetensors", "*.bin"])
    pd.add_argument("--token", default="",
                    help="Path to the binding-gated MAA token (from -X).")
    pd.add_argument("--sim-url", default="http://127.0.0.1:9080",
                    help="AKV simulator base URL.")
    pd.add_argument("--save-response", default="",
                    help="Write the (key-redacted) release response JSON here.")
    pd.add_argument("--unsafe-key-from-store", action="store_true",
                    help="TEST ONLY: read key directly, bypassing attestation.")
    pd.set_defaults(func=cmd_decrypt)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
