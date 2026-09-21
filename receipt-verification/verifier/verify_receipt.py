#!/usr/bin/env python3
"""verify_receipt.py — check a Trinity authority receipt's Ed25519 signature.

    python3 verify_receipt.py --receipt RECEIPT.json --registry REGISTRY.json

Python standard library only. No pip installs, no network. Requires Python 3.6 or later;
verified on 3.12.

This is the SECOND, INDEPENDENT implementation. verify_receipt.exs is the reference. Two
implementations exist so an examiner who distrusts one can run the other, and so neither can drift
unnoticed — a shared corpus is run through both in CI and their verdicts must agree.

EXIT CODES AND EVERY VERDICT CASE ARE DEFINED IN ONE PLACE: VERDICTS.md, beside this file. It is
the single source, it is parsed by the cross-check test, and this header cites it rather than
restating it. Four copies of one rule is how the copies drift.

The numbers are frozen at 0, 1, 2, 5, 6 and no others may be introduced. `5` is shared with the
VIRP verifier; the rest are this project's proposal and are PROVISIONAL. The one distinction to
carry in your head while reading the code below: `1` accuses the receipt, `5` declines to judge it,
and collapsing them tells an examiner a receipt was forged when it was merely unverifiable.

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

THE RULE THIS FILE BOUNDS — the verifier-primitive rule (G-212, stated 2026-09-20). Nothing a
stranger is asked to check may
require a primitive this file cannot compute from the standard library: SHA-2/SHA-3/SHAKE, the
hand-written Ed25519 above, hash-based signatures. ML-DSA, BLS, pairing-based proofs, X.509 and
ECDSA are OUT — a construction that "gives the verifier X" adds a verification domain to a file
whose one stated exception is Ed25519. The import list below is the whole of what this file may
reach, and the cross-check test pins it exactly.

VERDICT CODES (2026-09-20, REQ-109; G-052 lifted). Every exit-1 and exit-5 message ends with a
line `verdict_code: <code>`, the same code verify_receipt.exs and the issuing tree name for that
input, written to STDERR with the message. The cross-check test compares the codes, not only the
exits, on every corpus row. Exit 0, 2 and 6 carry no code.
"""

import base64
import hashlib
import json
import re
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


# --- verdicts ------------------------------------------------------------------------------------
# Order, and the whole of it, is VERDICTS.md's "the order the checks run in". Every trust question
# precedes every accusation, because an accusation requires standing.
STATUSES = ("example", "active", "retired", "compromised")
ENVELOPE = ("signature", "key_id", "signed_payload", "receipt_hash")
IGNORED = ("public_key", "_note")
TS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def die(code, message, stream=sys.stderr, verdict_code=None):
    # stdout first: the public_key note is block-buffered on a pipe and would otherwise land
    # AFTER the verdict when a caller merges the streams (REQ-109, the reds review's M7)
    sys.stdout.flush()
    if verdict_code is not None:
        message = message + "\n\nverdict_code: " + verdict_code
    print(message, file=stream)
    stream.flush()
    sys.exit(code)


def b64(value):
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return None


def timestamp(value):
    """The instant, as a comparable tuple, or None when the form is not the accepted one.

    Only `YYYY-MM-DDTHH:MM:SSZ` is accepted. A verifier that accepts two spellings of an instant is
    a verifier whose two implementations eventually disagree about one of them, and the disagreement
    surfaces first on a real receipt rather than in the corpus. Not coerced, not guessed: refused.
    """
    if not isinstance(value, str) or not TS.match(value):
        return None
    return (value[0:4], value[5:7], value[8:10], value[11:13], value[14:16], value[17:19])


def tagged(value):
    """Type-tagged form, so equality never merges an int with a float or a bool with 1.

    VERDICTS.md's canonical encoding never merges integers and floats; Python's `==` does, and
    `True == 1` as well. Comparing untagged would make a contradiction invisible on exactly the
    values an adversary would choose.
    """
    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value)
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, list):
        return ("list", [tagged(v) for v in value])
    if isinstance(value, dict):
        return ("object", sorted((k, tagged(v)) for k, v in value.items()))
    return ("other", repr(value))


def main(argv):
    opts = {}
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag in ("--receipt", "--registry"):
            if index + 1 >= len(argv):
                die(EXIT_USAGE, "usage: %s requires a value" % flag)
            opts[flag[2:]] = argv[index + 1]
            index += 2
        else:
            index += 1

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
            verdict_code="registry_not_supplied",
        )

    try:
        with open(opts["receipt"]) as handle:
            receipt = json.load(handle)
        with open(opts["registry"]) as handle:
            registry = json.load(handle)
    except (OSError, ValueError) as error:
        die(EXIT_USAGE, "cannot read input: %s" % error)

    if not isinstance(receipt, dict):
        die(EXIT_USAGE, "the receipt must be a JSON object")

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

    entries = registry.get("entries")
    if not isinstance(entries, list):
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the registry carries no entries list.",
            verdict_code="registry_missing_key",
        )

    matches = [e for e in entries if isinstance(e, dict) and e.get("key_id") == key_id]

    if not matches:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the registry does not name key_id %r.\n\n"
            "This is not a statement that the receipt is bad. It is a statement that the registry\n"
            "you supplied gives no basis to judge it. The verifier does not fall back to any other\n"
            "key." % key_id,
            verdict_code="registry_missing_key",
        )

    # V-DUPKEY. Taking the first match would let DOCUMENT ORDER select the verdict, inside a file
    # whose governing rule is that entries are never removed or rewritten.
    if len(matches) > 1:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the registry names key_id %r %d times.\n\n"
            "The registry is append-only: an entry is never removed and never rewritten, so one\n"
            "key_id names one key. Two entries mean the file is internally inconsistent, and\n"
            "picking either one would let the ORDER of a document decide the verdict.\n"
            "Detected on key_id only. Two entries sharing a public key under DIFFERENT key_ids is\n"
            "not this error." % (key_id, len(matches)),
            verdict_code="registry_duplicate_key",
        )

    entry = matches[0]
    status = entry.get("status")

    # DEFAULT DENY. The registry defines exactly four statuses. Unknown standing is not good
    # standing, and a status this verifier cannot interpret is a reason to refuse, never to pass.
    if not isinstance(status, str) or status not in STATUSES:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r carries status %r.\n\n"
            "The registry defines exactly four: example, active, retired, compromised. A status\n"
            "outside that set, or absent, is standing this verifier cannot interpret. It refuses\n"
            "rather than treating the unrecognised as the benign." % (key_id, status),
            verdict_code="key_status_not_active",
        )

    if status == "example":
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r is an example key, not a trust root.\n\n"
            "Example entries demonstrate the registry's schema. They are generated from a published\n"
            "string, so their private half is not secret and anything they sign proves nothing."
            % key_id,
            verdict_code="key_is_example",
        )

    # The entry must hash to its own published fingerprint BEFORE anything it says is believed,
    # including its status and its window. An entry failing its own integrity check may have been
    # substituted, and reporting a benign story read out of it would be the wrong answer.
    # an absent or non-string public_key is a fingerprint failure (the Elixir verifier's and the
    # tree's order; the fix review's F2: `or ""` hashed to sha256("") and reached the key-length
    # site instead)
    published = entry.get("public_key")
    raw_key = b64(published) if isinstance(published, str) else None
    stated = entry.get("public_key_fingerprint")
    if raw_key is None or not isinstance(stated, str) or hashlib.sha256(raw_key).hexdigest() != stated:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r does not hash to its own published fingerprint.\n\n"
            "public_key_fingerprint is sha256 over the RAW key bytes, lowercase hex. This entry\n"
            "fails its own integrity check, so nothing it states — its status, its window, its key —\n"
            "can be relied on." % key_id,
            verdict_code="key_fingerprint_mismatch",
        )

    # REQ-109 (G-255): a public_key that is not 32 raw bytes is not an Ed25519 key. A defect in
    # the TRUST ROOT is a trust question, never an accusation of the receipt. The entry hashed
    # to its own fingerprint, so this is what the registry published.
    if len(raw_key) != 32:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r publishes a public_key of %d bytes; an Ed25519\n"
            "public key is 32.\n\n"
            "The entry hashes to its own fingerprint, so this is what the registry published: not\n"
            "a key this verifier can check a signature against. Nothing the receipt says is judged."
            % (key_id, len(raw_key)),
            verdict_code="key_public_key_malformed",
        )

    valid_from, valid_to = timestamp(entry.get("valid_from")), entry.get("valid_to")
    if valid_from is None:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — key_id %r has no usable valid_from.\n\n"
            "Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly. A window that cannot be read cannot\n"
            "place a receipt inside or outside it." % key_id,
            verdict_code="key_valid_from_unusable",
        )
    if valid_to is not None:
        valid_to = timestamp(valid_to)
        if valid_to is None:
            die(
                EXIT_NO_TRUST,
                "TRUST NOT ESTABLISHED — key_id %r has an unreadable valid_to.\n\n"
                "Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly, or null for a key still signing."
                % key_id,
            verdict_code="key_valid_to_unreadable",
        )

    try:
        signed = json.loads(payload)
        if not isinstance(signed, dict):
            signed = None
    except ValueError:
        signed = None

    occurred = timestamp(signed.get("occurred_at")) if signed else None
    if occurred is None:
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the signed bytes carry no readable occurred_at.\n\n"
            "occurred_at is the only signing time a receipt carries, and it is what the key's\n"
            "signing window is checked against. Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly;\n"
            "it is refused rather than coerced, so the two implementations cannot drift.",
            verdict_code="signed_occurred_at_unreadable",
        )

    # --- the receipt itself. Everything below accuses the receipt, so it runs only once the
    # --- registry has given us the standing to make an accusation.
    expected_hash = receipt.get("receipt_hash")
    if not isinstance(expected_hash, str):
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — the receipt carries no receipt_hash.\n\n"
            "A receipt states the digest of its own signed bytes. An absent field is not a check\n"
            "to be skipped; it is a receipt that declines to be held to anything.",
            verdict_code="receipt_hash_missing",
        )
    if hashlib.sha256(payload.encode("utf-8")).hexdigest() != expected_hash:
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — the receipt's own receipt_hash does not match its signed bytes.",
            verdict_code="receipt_hash_mismatch",
        )

    for key in receipt:
        if key in ENVELOPE or key in IGNORED or key not in signed:
            continue
        if tagged(receipt[key]) != tagged(signed[key]):
            die(
                EXIT_INVALID,
                "SIGNATURE INVALID — the receipt displays %r as %r, but the SIGNED bytes say %r.\n\n"
                "A reader takes the visible field for part of the receipt. The signature covers\n"
                "only the signed bytes, so a top-level field contradicting them is a claim no\n"
                "signature stands behind." % (key, receipt[key], signed[key]),
            verdict_code="displayed_field_mismatch",
        )

    # REQ-109 (G-255): a signature that does not decode or is not 64 raw bytes is MALFORMED --
    # the taxonomy's word, the Elixir verifier's and the issuing tree's; one that decodes and
    # fails the curve check is INVALID.
    raw_signature = b64(signature)
    if raw_signature is None or len(raw_signature) != 64:
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — malformed signature or key material.",
            verdict_code="signature_malformed",
        )
    if not ed25519_verify(raw_signature, payload.encode("utf-8"), raw_key):
        die(
            EXIT_INVALID,
            "SIGNATURE INVALID — the signature does not check out against the registry's public key.",
            verdict_code="signature_invalid",
        )

    # 6 asserts the signature IS cryptographically valid, so it cannot be reached over a failed
    # verification. It sits after the checks above for that reason and not by accident.
    if status == "compromised":
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

    # The window is half-open: valid_from <= occurred_at < valid_to. See VERDICTS.md for why the
    # published registries settle that convention rather than taste.
    if occurred < valid_from or (valid_to is not None and occurred >= valid_to):
        die(
            EXIT_NO_TRUST,
            "TRUST NOT ESTABLISHED — the receipt says it was signed at %s, outside key_id %r's\n"
            "signing window [%s, %s).\n\n"
            "A retired key's signatures survive its retirement; a signature dated after the window\n"
            "closed was never covered by that rule. The window is half-open, so an occurred_at\n"
            "equal to valid_to is outside it.\n\n"
            "Sound for honest history, advisory against a forger: occurred_at is asserted by the\n"
            "receipt, and an adversary holding the key can backdate it."
            % (
                signed.get("occurred_at"),
                key_id,
                entry.get("valid_from"),
                entry.get("valid_to"),
            ),
            verdict_code="signed_outside_key_validity",
        )

    print(
        "VERIFIED — signature is valid under key_id %r (status: %s).\n\n"
        "A retired key verifies exactly like an active one WITHIN ITS SIGNING WINDOW. Rotation does\n"
        "not invalidate receipts already issued; only new signing stops.\n\n"
        "Note what this attests: the signed bytes carry the receipt's sequence and previous_hash, so\n"
        "a valid signature binds the receipt's POSITION IN ITS CHAIN as well as its content."
        % (key_id, status)
    )
    sys.exit(EXIT_VERIFIED)


if __name__ == "__main__":
    main(sys.argv[1:])
