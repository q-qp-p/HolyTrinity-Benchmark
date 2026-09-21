# Verdicts

**This file is the single source of truth for what each verifier exit code means and for which
input produces it.** `verify_receipt.py`, `verify_receipt.exs`, `README.md` and the cross-check
matrix all cite this table rather than restating it. Four copies of one rule is how the copies
drift; there is now one copy and three citations.

**Every trust question precedes every accusation, and `6` is asserted only over a signature that
has already verified.**

The cross-check test **parses this file**. A row with no fixture fails it, a fixture with no row
fails it, and an expected exit changed here without a matching code change fails it. The table is
executable documentation, not a description of it.

## The codes

They are frozen. `0 1 2 5 6`, and no others may be introduced (`docs/naming.md:41-42`).

| code | verdict | what it says about the receipt |
|---|---|---|
| `0` | verified | the signature is good under an independently supplied key whose standing the registry establishes |
| `1` | signature invalid | **the receipt is bad** — its own bytes, hash, fields or signature disagree |
| `2` | usage error | nothing about any receipt; the invocation was malformed |
| `5` | trust not established | **the receipt is unjudged** — no independent basis to judge it |
| `6` | key compromised | signature valid, signer trust degraded — **provisional** |

**`1` and `5` are deliberately different and must never be collapsed.** `1` accuses the receipt.
`5` declines to judge it. Reporting the second as the first tells an examiner a receipt was
**forged** when it was merely **unverifiable as presented**, and those demand opposite responses.
`5` is shared with the VIRP verifier; the others are this project's proposal and are provisional
pending reconciliation of the two vocabularies.

## How to read a row

`registry` and `receipt` are **closed vocabularies of tokens, never command lines.** The table can
name a situation; it can never name an invocation. Adding a token is deliberately a code change.

| token | in `registry` | in `receipt` |
|---|---|---|
| a path | `--registry <path>` | `--receipt <path>` |
| `corpus` | `--registry corpus/registry.json` | — |
| `duplicate` | `--registry corpus/registry-duplicate-key-id.json` | — |
| `live` | `--registry ../keys/registry.json` | — |
| `absent-from` | `--registry corpus/registry-absent-valid-from.json` | — |
| `null-from` | `--registry corpus/registry-null-valid-from.json` | — |
| `malformed-key` | `--registry corpus/registry-malformed-key.json` | — |
| `no-entries` | `--registry corpus/registry-no-entries.json` | — |
| `null-entries` | `--registry corpus/registry-null-entries.json` | — |
| `absent-key` | `--registry corpus/registry-absent-public-key.json` | — |
| `none` | the flag is omitted entirely | the flag is omitted entirely |
| `dangling` | — | `--receipt` supplied with no value after it |

Paths are relative to `verifier/`, which is where both verifiers are run from.

## The table

| id | receipt | registry | exit | verdict | why |
|---|---|---|---|---|---|
| V-VERIFIED | `corpus/verified.json` | `corpus` | `0` | verified | active key, inside its window, fingerprint matches, hash and signature agree |
| V-RETIRED-IN | `corpus/retired-key-in-window.json` | `corpus` | `0` | verified | a retired key's signatures survive its retirement; `occurred_at` is inside the signing window |
| V-KEYSUB | `corpus/key-substitution.json` | `corpus` | `0` | verified | ACCEPTED-KNOWN-LIMITATION, see below; `key_id` is outside the signed bytes so the presenter selects the judging entry |
| V-INVALID-SIG | `corpus/invalid-signature.json` | `corpus` | `1` | signature invalid | the payload gained a byte after signing; its own `receipt_hash` no longer matches its bytes |
| V-WRONG-KEY | `corpus/wrong-key.json` | `corpus` | `1` | signature invalid | signed by a key that is not the one the registry names for this `key_id` |
| V-TRUNCATED | `corpus/truncated.json` | `corpus` | `1` | signature invalid | the signature is not 64 bytes, which Ed25519 requires; MALFORMED, not merely invalid (`signature_malformed` in all three implementations since 2026-09-20, G-255) |
| V-HASH-ABSENT | `corpus/no-receipt-hash.json` | `corpus` | `1` | signature invalid | `receipt_hash` is absent, so the receipt states no digest to be held to; absence is a failure, not a skip |
| V-SIBLING | `corpus/sibling-contradiction.json` | `corpus` | `1` | signature invalid | a top-level field contradicts the same field inside the signed bytes |
| V-EXAMPLE-KEY | `corpus/example-key.json` | `corpus` | `5` | trust not established | an example entry is never a trust root; its private half is derived from a published string |
| V-UNKNOWN-KEYID | `corpus/unknown-key-id.json` | `corpus` | `5` | trust not established | the registry names no such `key_id`, and the verifier never falls back to another key |
| V-STATUS-UNKNOWN | `corpus/revoked-key.json` | `corpus` | `5` | trust not established | the entry's status is not one of the four the registry defines; unknown standing is not good standing |
| V-STATUS-ABSENT | `corpus/no-status-key.json` | `corpus` | `5` | trust not established | the entry carries no status at all; default deny |
| V-FINGERPRINT | `corpus/bad-fingerprint-key.json` | `corpus` | `5` | trust not established | the entry does not hash to its own published `public_key_fingerprint`, so nothing it says can be believed |
| V-WINDOW-AFTER | `corpus/expired-key.json` | `corpus` | `5` | trust not established | `occurred_at` is at or after `valid_to`; the key was not signing then |
| V-WINDOW-EDGE | `corpus/window-edge-key.json` | `corpus` | `5` | trust not established | `occurred_at` equals `valid_to` exactly; the window is half-open and excludes its upper bound |
| V-WINDOW-BEFORE | `corpus/window-before-key.json` | `corpus` | `5` | trust not established | `occurred_at` is before `valid_from`, a claim to have been signed in an era the key did not cover |
| V-BOUND-ABSENT | `corpus/verified.json` | `absent-from` | `5` | trust not established | the entry omits `valid_from`; a required bound that is missing makes the entry malformed and its era unjudgeable |
| V-BOUND-NULL | `corpus/verified.json` | `null-from` | `5` | trust not established | the entry's `valid_from` is null; a bound is open-ended only where the schema permits it, and it does not permit it here |
| V-KEY-MALFORMED | `corpus/verified.json` | `malformed-key` | `5` | trust not established | the entry hashes to its own fingerprint and its `public_key` is 31 raw bytes: what the registry published is not an Ed25519 key. A defect in the trust root is a trust question, never an accusation (before 2026-09-20 the Elixir verifier exited `1` here by accident — OTP's argument check caught by a rescue; G-255) |
| V-NO-ENTRIES | `corpus/verified.json` | `no-entries` | `5` | trust not established | the registry has no `entries` key; it gives no basis to judge anything, the same question as an unnamed `key_id` (G-253) |
| V-KEY-ABSENT | `corpus/verified.json` | `absent-key` | `5` | trust not established | the entry has no `public_key` and its fingerprint is sha256 of nothing: a fingerprint failure in all three (the fix review of REQ-109, F2: the Python coalesced the absent key to empty bytes and reached the key-length site) |
| V-INSTANT-UNREADABLE | `corpus/bad-occurred-at.json` | `corpus` | `5` | trust not established | the signed bytes carry an `occurred_at` that is not the accepted form; asked after the entry's window, before any accusation |
| V-BOUND-AND-INSTANT | `corpus/bad-occurred-at.json` | `absent-from` | `5` | trust not established | the entry's `valid_from` is absent AND the instant is unreadable: the window's bound is asked first, in all three (F2: the Elixir verifier asked the instant first) |
| V-NULL-ENTRIES | `corpus/verified.json` | `null-entries` | `5` | trust not established | the registry's `entries` is null; the Elixir verifier crashed on this shape before 2026-09-20 (a stack trace and the runtime's exit `1`) while the Python exited `5` — a divergence the exit-only cross-check saw only once the row existed (G-253) |
| V-RETIRED-OUT | `corpus/retired-key-out-of-window.json` | `corpus` | `5` | trust not established | retired key, `occurred_at` after `valid_to`; retirement refuses post-window signatures |
| V-DUPKEY | `corpus/verified.json` | `duplicate` | `5` | trust not established | the registry names one `key_id` more than once, so position would select the verdict; an internally inconsistent trust root gives no basis to judge |
| V-NO-REGISTRY | `corpus/verified.json` | `none` | `5` | trust not established | no registry supplied; a key arriving with the evidence establishes nothing |
| V-WRONG-REGISTRY | `corpus/verified.json` | `live` | `5` | trust not established | the published registry does not name this corpus `key_id`; a finding about the command line, not the receipt |
| V-COMPROMISED | `corpus/compromised-key.json` | `corpus` | `6` | key compromised | signature valid and in window, under a key the registry marks compromised |
| V-NO-RECEIPT | `none` | `corpus` | `2` | usage error | no `--receipt`; says nothing about any receipt |
| V-ARGV-ODD | `dangling` | `corpus` | `2` | usage error | `--receipt` with no value; a malformed invocation must not be read as a verdict |

## The order the checks run in, because two conditions can both be true

All three implementations (the two verifiers and the issuing tree's own verdict) evaluate in this
order and stop at the first that fires:

1. **`2`** — malformed invocation, unreadable input, or a receipt missing `signed_payload`,
   `signature` or `key_id`. Nothing was measured.
2. **`5`** — no registry; `key_id` absent from the registry; `key_id` present more than once;
   entry status missing or outside the defined four; status `example`; fingerprint absent or not
   matching `sha256(raw public_key bytes)` (an absent or non-string `public_key` is this case);
   the entry's `public_key` not 32 raw bytes (2026-09-20, G-255); the entry's `valid_from` or
   `valid_to` unreadable (the window's bounds, BEFORE the receipt's instant — 2026-09-20);
   `occurred_at` absent or not the accepted timestamp form. A registry with no `entries` list
   (absent, null or not a list) is "`key_id` absent from the registry".
3. **`1`** — `receipt_hash` absent or mismatched; a sibling field contradicting the signed bytes;
   signature failing to verify.
4. **`6`** — status `compromised`.
5. **`5`** — `occurred_at` outside `[valid_from, valid_to)`.
6. **`0`** — otherwise.

**Why every trust question precedes every accusation.** Steps 2 and 5 mean *we cannot judge this*;
step 3 means *this receipt is bad*. An accusation requires standing. Concretely: a good receipt
checked against the wrong registry must report `5`, and it only does so because the `key_id` lookup
runs before the hash and signature comparisons.

**Why `6` precedes the window.** Exit `6` states that the signature is cryptographically valid,
which cannot be said over a signature that failed to verify — so `6` is placed after step 3, never
before it.

## The signing window, stated once so the two implementations cannot drift

`valid_from` and `valid_to` are **the signing window** (`../keys/README.md`). They are compared
against `occurred_at`, taken from inside the signed bytes, which is the only signing time the
receipt carries.

**The interval is half-open: `valid_from <= occurred_at < valid_to`.** `valid_to: null` means no
upper bound. Three facts in the published registries settle the convention rather than taste:
`example_ed25519_v0` has `valid_from == valid_to`, and `keys/README.md` calls that window *closed*
with *no verifier accepts it as a trust root* — only half-open makes it genuinely empty;
`corpus_retired_v1`'s `valid_to` equals `corpus_active_v1`'s `valid_from`, and half-open gives
every instant at most one authorized key; and `valid_to` equals `status_changed_at`, the instant
signing stopped.

**Timestamps are accepted only as `YYYY-MM-DDTHH:MM:SSZ`.** Every timestamp in both registries and
every fixture already has exactly this form. A timestamp in any other form is **refused with `5`**,
never coerced and never guessed: a verifier that accepts two spellings of an instant is a verifier
whose two implementations will eventually disagree about one of them.

### Absent versus null, on each bound

**A bound is open-ended only where the registry's own schema permits it.**

| bound | absent | null | why |
|---|---|---|---|
| `valid_to` | open-ended | open-ended | the schema makes it optional; `keys/README.md` says it is null while a key is still signing |
| `valid_from` | **`5`** | **`5`** | the schema makes it required, so neither spelling of "missing" is a window |

**This is a deliberate divergence from the intuitive rule that null means open-ended on either
bound, and the reason is that the intuitive rule would put two authorities in conflict over one
file.** `lib/autonomous_agency/authority/key_registry.ex:16` lists `valid_from` in
`@required_fields` and **deliberately omits `valid_to`**, and its `present?/1` at `:94` returns
false for `nil` — so in-tree, an absent `valid_from` and a null one are **already** treated
identically, and both are invalid. A verifier that accepted `valid_from: null` as "no lower bound"
would accept a registry that `KeyRegistry.validate/1` rejects. Two authorities disagreeing about
the same file is the defect this table exists to remove, not one to introduce.

`V-BOUND-ABSENT` and `V-BOUND-NULL` pin both halves, so the seam where the two implementations
could drift — Python collapsing absent and null into `None`, Elixir splitting them across `nil` and
the `:null` atom that `:json.decode/1` produces — goes red rather than silent.

**This check is sound for honest history and advisory against a forger**, the same limit the
compromised verdict states: `occurred_at` is asserted by the receipt, and an adversary holding the
key can backdate it. Closing that gap needs a signing time anchored outside the issuing system.
That is named future work, not a solved problem.

## Two limitations this table records rather than hides

**V-KEYSUB — `key_id` is not inside the signed bytes.** A receipt names the registry entry that
judges it, so a presenter holding one signature can select which entry applies by editing an
unsigned field. In this corpus `corpus_active_v1` and `corpus_revoked_v1` carry the same public
key, and the same bytes verify under either. **Exit `0` is the documented v1 behaviour and the
matrix asserts it**, so the limitation is pinned rather than forgotten. It is unenforceable in v1
and is closed by the v2 preimage (domain separation), at which point the row's **v2 expectation**
becomes a non-zero exit. **The flip changes the v2 expectation only and never the v1 one:**
v1-format receipts keep exit `0` under this limitation permanently, and once v2 exists the matrix
asserts per format. Until then, **a production registry must never hold one public key under two
entries.**

**Duplicate detection is on `key_id` only.** V-DUPKEY fires when one `key_id` appears more than
once. **Duplicate public keys across distinct `key_id`s are not an error at the verifier and must
not become one** — that is the shape the reused-key fixtures in this corpus depend on. Why a real
registry must avoid them regardless is V-KEYSUB above, which is a different finding with a
different closer.

## One stricter rule considered and not adopted

A top-level field that appears **nowhere** in the signed payload is **ignored**, not refused. The
stricter rule — refuse any top-level field the signature does not cover — was considered and not
taken in this pass, because it exceeds the approved change set. It has a real argument behind it: a
receipt carrying `"approved_by": "alice"` at top level is covered by no signature, and an examiner
reading the JSON may take it for part of the receipt. The bound today is that the production export
emits exactly `signature`, `key_id`, `signed_payload`, `receipt_hash`
(`ops/verification/frozen_stranger_sequence.sh:126-133`, a frozen file). **Recorded here as a known
gap so that the weaker rule is a decision on the record and not an oversight.**

## `verdict_code` (added 2026-09-12, W2 of the hardening sprint)

The exit set above is unchanged. In addition, `verify_receipt.exs` now ends every `1` and `5`
message with a line `verdict_code: <code>` — one of the ten `:trust` codes (exit 5) or three
`:signature` codes (exit 1) in `AutonomousAgency.Authority.DenialTaxonomy` in the main tree,
one per failure site, so a caller can tell *which* trust question failed without matching prose.
The message bytes before that line are unchanged. `verify_receipt.py` does **not** emit it yet;
its failure sites are not one-to-one with the Elixir verifier's, and mapping them is a separate
cross-check, not a line to paste. Until then the code line is an Elixir-verifier feature and the
cross-check matrix compares exits only, as before.

**Correction, appended 2026-09-18 (REQ-097).** "Every `1` and `5` message" was not true of two
exit-1 sites: *the receipt's own `receipt_hash` does not match its signed bytes* and *the
signature does not check out against the registry's public key* ended without a code (the
count of three `:signature` codes above was taken by a regex that saw only single-line `fail(`
calls; there are five sites). Both now end with a line — `verdict_code: receipt_hash_mismatch`
and `verdict_code: signature_invalid` — and the taxonomy carries **five** `:signature` codes.
The exit codes and every message byte before the line are unchanged; the corpus replays with
identical exits. The main tree's own verdict (`AuthorityReceipts.signature_verdict/2`) now
implements this table's order and names the same codes, and runs the corpus above row by row.

**Parity, appended 2026-09-20 (REQ-109; G-052 lifted).** `verify_receipt.py` now ends every
exit-1 and exit-5 message with the same `verdict_code` line, written to stderr with the message
(stdout is flushed first, so the `public_key` note never lands after the verdict on a merged
stream). The cross-check compares the CODE on every row, three ways: the Elixir verifier, the
Python verifier and the main tree's verdict. Measured before the port, the three did not agree:
`V-TRUNCATED` was `signature_malformed` in the tree, `signature_invalid` in the Elixir verifier
(`:crypto.verify` returns false on 63 bytes), and codeless in the Python; a registry key that is
not 32 bytes was exit `1` `signature_malformed` in the Elixir verifier (OTP's raise, rescued) and
would have been `signature_invalid` in the Python; a null `entries` crashed the Elixir verifier.
The ruling (G-255, recorded in the private tree's gaps ledger; the owner may overrule before this
is released): a signature that does not decode or is not 64 raw bytes is `signature_malformed`
everywhere; a registry `public_key` that is not 32 raw bytes is exit `5` `key_public_key_malformed`
— the taxonomy's eleventh `:trust` code — and is asked right after the fingerprint; `entries`
absent, null or not a list is `registry_missing_key`. Three rows hold the ruling: `V-KEY-MALFORMED`,
`V-NO-ENTRIES`, `V-NULL-ENTRIES`. The "ten `:trust` codes" and "thirteen" above are the 2026-09-12
counts; the taxonomy holds eleven and five.

