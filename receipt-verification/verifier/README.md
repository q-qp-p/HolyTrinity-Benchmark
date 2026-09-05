# Verify a Trinity authority receipt

```
elixir verify_receipt.exs --receipt RECEIPT.json --registry REGISTRY.json
python3 verify_receipt.py  --receipt RECEIPT.json --registry REGISTRY.json
```

No Mix project, no hex packages, no pip installs, **no network**. `verify_receipt.exs` needs
Elixir 1.17 / OTP 27 or later; `verify_receipt.py` needs Python 3.6 or later. Verified on Elixir
1.19.2 / OTP 28 and Python 3.12.

## The one thing to understand before running it

**Supply a registry you obtained independently of the receipt.** The verifier will not use key
material that arrived with the evidence — a receipt may carry a `public_key` field and it is
always ignored. A key from the same download as the receipt proves nothing, because whoever
produced the bundle chose both halves. Given no `--registry`, the verifier **refuses** and exits
`5` rather than reporting a verdict it has no basis for.

The registry is published in the public repository, where every append is a dated commit you can
walk and tampering is detectable against any older clone.

A second channel — a Zenodo deposit carrying a DOI — is **intended and not yet live.** When it
exists, cross-checking one against the other becomes available and **disagreement between them is
itself an alarm.** Until then there is one channel, and this document says so rather than sending
you to look for a mirror that is not there.

## Exit codes and verdicts

**`VERDICTS.md`, beside this file, is the single source.** It defines every code, every input
condition that produces it, and the order the checks run in, and the cross-check test parses it.
This README does not restate the table: four copies of one rule is how the copies drift.

The codes are frozen at `0 1 2 5 6`. The distinction to carry in your head is that **`1` accuses
the receipt and `5` declines to judge it**, and collapsing them tells an examiner a receipt was
**forged** when it was merely **unverifiable as presented**. Those demand opposite responses.

**`5` is shared with the VIRP verifier.** The others are this project's proposal and are
**provisional** pending reconciliation of the two vocabularies.

## What a verified signature actually attests

The signed bytes are the receipt's canonical payload, which carries `sequence` and `previous_hash`.
So a valid signature binds the receipt's **position in its chain**, not only its content: a
verified receipt is the nth in its scope and follows that predecessor. That is more than a
signature over content alone gives you.

## The signing scheme, so you can reimplement it

1. The receipt's `signed_payload` is a **canonical JSON** encoding: object keys sorted, duplicate
   normalized keys preserved rather than last-wins, strings byte-exact with no unicode
   normalization, integers and floats never merged, datetimes ISO 8601. It is stored as the literal
   byte string — **never re-serialize it**; that is the whole point of persisting it.
2. `receipt_hash` is SHA-256 over those bytes, lowercase hex.
3. `signature` is Ed25519 (RFC 8032) over those same bytes, base64.
4. `key_id` names the registry entry whose `public_key` checks it.

Verification, in the order `VERDICTS.md` fixes: look up `key_id` in the registry and refuse if it
is absent **or named more than once**; refuse an `example` entry, a status the registry does not
define, or an entry that **does not hash to its own `public_key_fingerprint`**; refuse a receipt
whose signed `occurred_at` is **outside the key's signing window** `[valid_from, valid_to)`; then
hold the receipt itself to its own `receipt_hash`, to **agreement between any visible top-level
field and the signed bytes**, and to the signature; then report by the entry's `status`.

Every trust question runs before every accusation, because an accusation requires standing.

## The compromised verdict states its own limit

A `compromised` key still produces cryptographically valid signatures. Separating a receipt signed
**before** the compromise from one signed **after** depends on knowing when it was signed — and the
signing time is asserted by the receipt, which an adversary holding that key can backdate.

So the verdict is **sound for honest history and advisory against a forger**, and the verifier says
so in its own output rather than only here. Closing the gap requires anchoring signing times
outside the issuing system (a transparency log, an RFC 3161 timestamp, a chain anchor). That is
**named future work, not a solved problem.**

## Two implementations, and why

`verify_receipt.exs` is the reference. `verify_receipt.py` exists so an examiner without an Elixir
toolchain is not excluded, and it carries a hand-written RFC 8032 verification because Python's
standard library has no Ed25519 and requiring a package would break the no-installs property.

That is a deliberate second implementation of one check. It is bounded by a **cross-check corpus**
run through both in CI — good signatures, tampered payloads, wrong keys, truncated signatures, an
example-key receipt that must be refused, and a receipt naming an unregistered key that must error
rather than fall back. **Their verdicts must match**, so neither can drift.

## This verifier is our artifact

An examiner who does not trust us has no reason to trust it either. Three things bound that:

* both files are short and dependency-free, so they can be read in full;
* the scheme is specified above, so it can be reimplemented from scratch and checked against both;
* two independent implementations agreeing is a stronger basis than either alone.

**Not yet reproducibly buildable.** These are scripts run by stock runtimes, so there is no build
to reproduce — but neither is there a signed release artifact you can pin. Stated because you would
otherwise have to find it out.

**There are now pins, and they are not signed artifacts.** Two annotated tags name immutable
points: `receipt-verification-r1` and `receipt-verification-r2`. Cite one of those rather than a
branch. **The sentence above stays true as written:** an annotated tag is not a GPG-signed release
artifact, no such artifact exists, and a tag can be moved by whoever holds the remote. What a tag
gives you is a fixed name for a commit you can diff against any older clone; what it does not give
you is a signature over that state.

## A limitation this verifier discloses rather than hides

**`key_id` is not inside the signed bytes.** A receipt names the registry entry that judges it, so
whoever presents a receipt selects which entry applies by editing an unsigned field. v1 trusts the
presenter's `key_id` to select the entry; **registries must therefore keep public keys unique per
entry**; v2 binds `key_id` into the signed bytes and closes it. Recorded as row `V-KEYSUB` in
`VERDICTS.md`, whose expected exit is the current behaviour so the limitation stays pinned rather
than forgotten.

## Pattern credit

The default-distrust posture, the refusal with a distinct exit code when signer trust is not
established from bundle-local key material, and the discipline of disclosing flaws unprompted are
taken from:

> **Nathan Howard** (Third Level IT / thirdlevel.ai)
> **VIRP verifier, v0.1.0** — <https://github.com/nhowardtli/virp/releases/tag/v0.1.0-verifier>
