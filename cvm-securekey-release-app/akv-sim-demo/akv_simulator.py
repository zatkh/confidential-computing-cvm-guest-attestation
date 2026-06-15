#!/usr/bin/env python3
"""
AKV simulator for the CVM<->CGPU binding PoC.

WHY THIS EXISTS
---------------
On this Azure Local node the *real* host-brokered AKV release leg (the IGVM
agent behind release_akv_key()) is broken: it returns the node's hardware AIK
identity instead of wrapped key material. Everything else in the chain is real
and verified:

  * SEV-SNP CVM attestation (MAA token)            -> REAL
  * CVM<->CGPU binding (NVIDIA GPU attestation)    -> REAL  (AzureAttestSKR -g)

This simulator replaces ONLY the broken host AKV-release leg. It does NOT fake
attestation: it independently VERIFIES the MAA JWT (signature against the MAA
JWKS + expiry + SEV-SNP release-policy claims) before releasing the AES key
that protects the model weights. Fidelity is "verify-only": the released key is
returned over localhost (no TPM wrapping), which is the agreed PoC scope.

  HONEST DEMO CONTRACT:
    The key is released if and only if:
      1. The AzureAttestSKR client passed the CVM<->CGPU binding gate
         (it only exports a token on exit 0), AND
      2. This simulator successfully verifies that exported MAA token.

USAGE
-----
  # 1) Provision the data-protection key inside the simulator's store.
  python3 akv_simulator.py keygen

  # 2) Run the release service (foreground).
  python3 akv_simulator.py serve --port 8080

  # The release endpoint:
  #   POST /release   body: { "token": "<MAA JWT>" }
  #   200 -> { "released": true,  "algorithm": "AES-256-GCM", "key_b64": "..." }
  #   403 -> { "released": false, "reason": "<why>" }
"""

import argparse
import base64
import json
import os
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import jwt  # PyJWT
    from jwt import PyJWKClient
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: PyJWT is required. Install with: pip install 'pyjwt[crypto]' requests\n"
    )
    raise

# ---------------------------------------------------------------------------
# Simulator state (the "AKV" side).
# ---------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
STORE_DIR = os.path.join(HERE, ".sim-store")
KEY_PATH = os.path.join(STORE_DIR, "aes_key.bin")  # the released data key
DEFAULT_POLICY_PATH = os.path.join(HERE, "release_policy.json")

# Default SEV-SNP release policy (mirrors the 3-claim policy on `mykey`).
DEFAULT_POLICY = {
    # The token issuer ("iss") must equal one of these MAA authorities.
    "authorities": [
        "https://ra26014b305c1c7c2c4521.eus2e.attest.azure.net"
    ],
    # All of these claims (dotted JSON paths) must equal the given values.
    "require_equals": {
        "x-ms-isolation-tee.x-ms-attestation-type": "sevsnpvm",
        "x-ms-isolation-tee.x-ms-sevsnpvm-is-debuggable": False,
        "x-ms-policy.edge-compliant-cvm": True,
    },
}


def load_policy(path):
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return DEFAULT_POLICY


def get_dotted(obj, dotted):
    node = obj
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None, False
        node = node[part]
    return node, True


# ---------------------------------------------------------------------------
# Key management.
# ---------------------------------------------------------------------------
def cmd_keygen(args):
    os.makedirs(STORE_DIR, exist_ok=True)
    if os.path.exists(KEY_PATH) and not args.force:
        print(f"Key already exists at {KEY_PATH} (use --force to regenerate).")
        return 0
    key = secrets.token_bytes(32)  # AES-256
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    print(f"Generated AES-256 data key -> {KEY_PATH}")
    print("Fingerprint (SHA-256 of key, first 16 hex):",
          _key_fingerprint(key))
    return 0


def _key_fingerprint(key):
    import hashlib
    return hashlib.sha256(key).hexdigest()[:16]


def load_key():
    if not os.path.exists(KEY_PATH):
        raise FileNotFoundError(
            f"No data key at {KEY_PATH}. Run: python3 akv_simulator.py keygen"
        )
    with open(KEY_PATH, "rb") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# MAA token verification (the real attestation gate).
# ---------------------------------------------------------------------------
class TokenRejected(Exception):
    pass


def verify_maa_token(token, policy, jwks_url, leeway=60):
    """Verify the MAA JWT signature + expiry + release-policy claims.

    Returns the decoded claims dict on success; raises TokenRejected otherwise.
    """
    # 1) Resolve the signing key from the MAA JWKS (by 'kid') and verify RS256.
    try:
        jwk_client = PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
    except Exception as exc:  # noqa: BLE001
        raise TokenRejected(f"could not resolve MAA signing key: {exc}") from exc

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512"],
            leeway=leeway,
            options={"verify_aud": False},  # MAA tokens often have no 'aud'
        )
    except Exception as exc:  # noqa: BLE001 (covers signature + expiry)
        raise TokenRejected(f"JWT verification failed: {exc}") from exc

    # 2) Issuer (authority) must match the policy.
    iss = claims.get("iss", "")
    authorities = policy.get("authorities") or []
    if authorities and iss not in authorities:
        raise TokenRejected(f"issuer '{iss}' not in allowed MAA authorities")

    # 3) Every required claim must be present and equal.
    for dotted, expected in policy.get("require_equals", {}).items():
        actual, found = get_dotted(claims, dotted)
        if not found:
            raise TokenRejected(f"required claim '{dotted}' missing")
        if actual != expected:
            raise TokenRejected(
                f"claim '{dotted}'={actual!r} != required {expected!r}"
            )

    return claims


# ---------------------------------------------------------------------------
# HTTP service.
# ---------------------------------------------------------------------------
def make_handler(policy, jwks_url, key):
    key_b64 = base64.b64encode(key).decode("ascii")
    key_fp = _key_fingerprint(key)

    class Handler(BaseHTTPRequestHandler):
        server_version = "AkvSimulator/1.0"

        def _send(self, code, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *fmt_args):  # quieter logging
            sys.stderr.write("[akv-sim] " + (fmt % fmt_args) + "\n")

        def do_GET(self):
            if self.path == "/health":
                self._send(200, {"status": "ok", "key_fingerprint": key_fp})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/release":
                self._send(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b"{}"
                req = json.loads(raw or b"{}")
            except Exception as exc:  # noqa: BLE001
                self._send(400, {"released": False,
                                 "reason": f"bad request: {exc}"})
                return

            token = (req.get("token") or "").strip()
            if not token:
                self._send(400, {"released": False,
                                 "reason": "missing 'token'"})
                return

            try:
                claims = verify_maa_token(token, policy, jwks_url)
            except TokenRejected as exc:
                self.log_message("RELEASE DENIED: %s", exc)
                self._send(403, {"released": False, "reason": str(exc)})
                return

            self.log_message(
                "RELEASE GRANTED: iss=%s vmid=%s",
                claims.get("iss", "?"),
                get_dotted(claims, "x-ms-isolation-tee.x-ms-sevsnpvm-vmid")[0],
            )
            self._send(200, {
                "released": True,
                "algorithm": "AES-256-GCM",
                "key_b64": key_b64,
                "key_fingerprint": key_fp,
                "verified_claims": {
                    "iss": claims.get("iss"),
                    "exp": claims.get("exp"),
                    "attestation_type": get_dotted(
                        claims, "x-ms-isolation-tee.x-ms-attestation-type")[0],
                    "is_debuggable": get_dotted(
                        claims,
                        "x-ms-isolation-tee.x-ms-sevsnpvm-is-debuggable")[0],
                    "edge_compliant_cvm": get_dotted(
                        claims, "x-ms-policy.edge-compliant-cvm")[0],
                },
            })

    return Handler


def cmd_serve(args):
    policy = load_policy(args.policy)
    jwks_url = args.jwks or (args.maa.rstrip("/") + "/certs" if args.maa else None)
    if not jwks_url:
        sys.stderr.write(
            "ERROR: provide --jwks <url> or --maa <base-url> for JWKS.\n")
        return 2
    key = load_key()
    handler = make_handler(policy, jwks_url, key)
    httpd = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"AKV simulator listening on http://{args.host}:{args.port}")
    print(f"  JWKS source : {jwks_url}")
    print(f"  policy      : authorities={policy.get('authorities')}")
    print(f"  required    : {policy.get('require_equals')}")
    print(f"  key fp      : {_key_fingerprint(key)}")
    print("  endpoints   : GET /health , POST /release {\"token\":\"<JWT>\"}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        httpd.server_close()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="AKV simulator (verify-only).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_keygen = sub.add_parser("keygen", help="Generate the AES-256 data key.")
    p_keygen.add_argument("--force", action="store_true",
                          help="Overwrite an existing key.")
    p_keygen.set_defaults(func=cmd_keygen)

    p_serve = sub.add_parser("serve", help="Run the release HTTP service.")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=9080)
    p_serve.add_argument("--maa", default=os.environ.get("SKR_MAA_URL", ""),
                         help="MAA base URL (JWKS = <maa>/certs).")
    p_serve.add_argument("--jwks", default="",
                         help="Explicit JWKS URL (overrides --maa).")
    p_serve.add_argument("--policy", default=DEFAULT_POLICY_PATH,
                         help="Release policy JSON (default: built-in 3-claim).")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
