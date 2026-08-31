#!/usr/bin/env python3
"""verify_receipt.py — check a Trinity authority receipt's Ed25519 signature.

    python3 verify_receipt.py --receipt RECEIPT.json --registry REGISTRY.json

Python standard library only. No pip installs, no network. Requires Python 3.6 or later;
verified on 3.12.

This is the SECOND, INDEPENDENT implementation. verify_receipt.exs is the reference. Two
implementations exist so an examiner who distrusts one can run the other, and so neither can drift
unnoticed — a shared corpus is run through both in CI and their verdicts must agree.

EXIT CODES — see README.md. `5` is shared with the VIRP verifier; the others are this project's
proposal and are PROVISIONAL pending reconciliation of the two vocabularies.

    0  verified               the signature is good under an independently supplied key
    1  signature invalid      THE RECEIPT IS BAD
    2  usage error            says nothing about the receipt
    5  trust not established   THE RECEIPT IS UNJUDGED
    6  key compromised        signature valid, signer trust degraded (PROVISIONAL)

PATTERN CREDIT — default-distrust posture, refusal with a distinct code when signer trust is not
established from bundle-local key material, flaws disclosed unprompted:

    Nathan Howard (Third Level IT / thirdlevel.ai)
    VIRP verifier, v0.1.0
    https://github.com/nhowardtli/virp/releases/tag/v0.1.0-verifier

HAND-ROLLED CRYPTO, DECLARED. The Ed25519 verification below is the RFC 8032 section 6 reference
construction, written out because Python's standard library has no Ed25519 and requiring a package
would break the no-installs property this file exists to provide. It is a NAMED EXCEPTION to the
rule against second implementations, and the exception is bounded by the cross-check corpus: this
file and verify_receipt.exs must agree on every case, including known-bad signatures, wrong keys
and truncated input. Verification only — this file never signs anything.
"""

import hashlib
import json
import sys

EXIT_VERIFIED, EXIT_INVALID, EXIT_USAGE, EXIT_NO_TRUST, EXIT_COMPROMISED = 0, 1, 2, 5, 6

# --- RFC 8032 Ed25519 verification -------------------------------------------------------------
P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, P - 2, P)


D = -121665 * _inv(121666) % P
I = pow(2, (P - 1) // 4, P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


BY = 4 * _inv(5)
B = [_xrecover(BY) % P, BY % P]


def _edwards(a, b):
    x1, y1 = a
    x2, y2 = b
    k = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k)
    return [x3 % P, y3 % P]


def _scalarmult(point, e):
    result = [0, 1]
    addend = point
    while e > 0:
        if e & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        e >>= 1
    return result


def _on_curve(point):
    x, y = point
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def _decode_point(raw):
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (raw[31] >> 7) & 1:
        x = P - x
    point = [x, y]
    if not _on_curve(point):
        raise ValueError("point is not on the curve")
    return point


def ed25519_verify(signature, message, public_key):
    """True when `signature` is a valid Ed25519 signature over `message` under `public_key`."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        r = _decode_point(signature[:32])
        a = _decode_point(public_key)
    except (ValueError, IndexError):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little")
    return _scalarmult(B, s) == _edwards(r, _scalarmult(a, h))


# --- verdicts ----------------------------------------------------------------------------------
def die(code, message, stream=sys.stderr):
    print(message, file=stream)
    sys.exit(code)


def b64(value):
    import base64

    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return None


def main(argv):
    opts = {}
    for i in range(0, len(argv) - 1, 2):
        if argv[i] in ("--receipt", "--registry"):
            opts[argv[i][2:]] = argv[i + 1]

    if "receipt" not in opts:
        die(EXIT_USAGE, "usage: verify_receipt.py --receipt RECEIPT.json --registry REGISTRY.json")

    # DEFAULT DISTRUST. Without an independently supplied registry there is no basis to judge the
    # receipt, and taking the key from the bundle would be checking a signature against a key the
    # same party supplied. That is a refusal, not a verdict — hence 5, not 1.
    if "registry" not in opts:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — no --registry was supplied.\n\n"
            "This verifier refuses to check a signature against key material that arrived with the\n"
            "receipt. A key obtained from the same download as the evidence proves nothing:\n"
            "whoever produced the bundle chose both halves.\n\n"
            "Supply a registry you obtained INDEPENDENTLY of this receipt. It is published in\n"
            "the public repository, where every append is a dated commit you can walk and\n"
            "tampering is detectable against any older clone.\n\n"
            "A second channel — a Zenodo deposit carrying a DOI — is INTENDED and NOT YET LIVE.\n"
            "When it exists you will be able to cross-check one against the other, and\n"
            "disagreement between them will itself be an alarm. Until then there is one channel,\n"
            "and this tool says so rather than implying a check you cannot perform.",
        )

    try:
        with open(opts["receipt"]) as handle:
            receipt = json.load(handle)
        with open(opts["registry"]) as handle:
            registry = json.load(handle)
    except (OSError, ValueError) as error:
        die(EXIT_USAGE, "cannot read input: %s" % error)

    payload, signature, key_id = (
        receipt.get("signed_payload"),
        receipt.get("signature"),
        receipt.get("key_id"),
    )
    if not all(isinstance(v, str) for v in (payload, signature, key_id)):
        die(EXIT_USAGE, "receipt must carry signed_payload, signature and key_id")

    # The receipt may carry a public_key. It is NEVER used.
    if isinstance(receipt.get("public_key"), str):
        print("note: the receipt carries a public_key; it is ignored. Trust comes from --registry.")

    entry = next(
        (e for e in registry.get("entries", []) if e.get("key_id") == key_id), None
    )

    if entry is None:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the registry does not name key_id %r.\n\n"
            "This is not a statement that the receipt is bad. It is a statement that the registry\n"
            "you supplied gives no basis to judge it. The verifier does not fall back to any other\n"
            "key." % key_id,
        )

    if entry.get("status") == "example":
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r is an example key, not a trust root.\n\n"
            "Example entries demonstrate the registry's schema. They are generated from a published\n"
            "string, so their private half is not secret and anything they sign proves nothing."
            % key_id,
        )

    expected_hash = receipt.get("receipt_hash")
    if isinstance(expected_hash, str):
        actual = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if actual != expected_hash:
            die(
                EXIT_INVALID,
                "SIGNATURE INVALID — the receipt's own receipt_hash does not match its signed bytes.",
            )

    raw_signature = b64(signature)
    raw_key = b64(entry.get("public_key") or "")
    if raw_signature is None or raw_key is None or not ed25519_verify(
        raw_signature, payload.encode("utf-8"), raw_key
    ):
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — the signature does not check out against the registry's public key.",
        )

    if entry.get("status") == "compromised":
        die(
            EXIT_COMPROMISED,
            "KEY COMPROMISED — the signature is cryptographically valid under key_id %r, but the\n"
            "registry marks that key compromised as of %s.\n\n"
            "WHAT THIS VERDICT CAN AND CANNOT ESTABLISH:\n\n"
            "  * The signature checks out against the published key.\n"
            "  * It does NOT establish that the issuer produced it. Anyone holding the compromised\n"
            "    private key could have.\n"
            "  * Separating a receipt signed BEFORE the compromise from one signed AFTER depends on\n"
            "    the signing time, which the receipt asserts about itself and an adversary holding\n"
            "    that key can backdate.\n\n"
            "Sound for honest history, advisory against a forger. Closing the gap requires anchoring\n"
            "signing times outside the issuing system; that is named future work.\n\n"
            "Exit code 6 is PROVISIONAL, pending reconciliation with the VIRP vocabulary."
            % (key_id, entry.get("status_changed_at")),
            stream=sys.stdout,
        )

    print(
        "VERIFIED — signature is valid under key_id %r (status: %s).\n\n"
        "A retired key verifies exactly like an active one. Rotation does not invalidate receipts\n"
        "already issued; only new signing stops.\n\n"
        "Note what this attests: the signed bytes carry the receipt's sequence and previous_hash, so\n"
        "a valid signature binds the receipt's POSITION IN ITS CHAIN as well as its content."
        % (key_id, entry.get("status"))
    )
    sys.exit(EXIT_VERIFIED)


if __name__ == "__main__":
    main(sys.argv[1:])
