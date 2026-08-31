# Receipt key registry

The public keys that verify Trinity authority receipts, and the rules that govern them.

**Obtain this file from a channel independent of the system whose receipts you are checking.** It
is published in this repository, where every append is a dated commit you can walk and tampering is
detectable against any older clone.

A second channel — a Zenodo deposit carrying a DOI that outlives the repository, the platform and
the project — is **intended and not yet live.** When it exists it will also let you cross-check one
channel against the other, and **disagreement between them is itself an alarm.** Until then there
is one channel. This paragraph previously claimed the mirror already existed; it did not, and a
reader following that claim would have found either nothing or an unrelated deposit — which the
sentence after it defines as an alarm. **A false claim of a second channel manufactures the alarm
it defines.**

A key obtained from the same download as the receipt establishes nothing. The verifier enforces
that: given only bundle-local key material it **refuses**, and exits non-zero, rather than
reporting a verdict it has no basis for.

## Format

```
key_id                  names which key signed a given receipt; receipts carry it
algorithm               ed25519
public_key              base64, 32 raw bytes
public_key_fingerprint  sha256 over the RAW key bytes, lowercase hex
valid_from / valid_to   the signing window; valid_to is null while active
status                  example | active | retired | compromised
status_changed_at       when the status last moved
```

## Append-only, and why it is not a convention

**An entry is never removed and never rewritten.** Only `status`, `valid_to` and
`status_changed_at` move.

Receipts signed under a retired key must verify forever. A rotation that invalidates prior receipts
is **evidence destruction by ops procedure** — worse than having no signatures at all, because it
converts routine key hygiene into silent deletion of the audit record. Deleting an entry
retroactively makes real evidence unverifiable.

`compromised` is deliberately distinct from `retired`. Collapsing them would either discard good
evidence — treating everything a compromised key ever signed as worthless — or launder bad, by
treating a compromised key as merely old.

## What losing a key means — the answer is a strength, not a caveat

An examiner assessing this scheme will ask what happens when a key is lost. **A lost signing key
destroys nothing.** Every receipt already issued stays verifiable under its published public key;
what stops is the ability to sign *new* ones. Recovery is to generate a new key, append it here,
and rotate.

This is materially different from the credential vault key, where loss makes stored ciphertext
permanently unreadable. Escrow the signing key, but do not treat rotation as catastrophic —
**treating rotation as catastrophic is how a compromised key stays in service**, and the
append-only property exists precisely so rotation is cheap and boring.

## The compromised verdict states its own limit

Distinguishing a receipt signed *before* a compromise from one signed *after* depends on knowing
when it was signed — and a receipt's signing time is asserted by the receipt, which an adversary
holding the compromised key can backdate. The compromised verdict is therefore **sound for honest
history and advisory against a forger**, and the verifier says so in its own output rather than
only here. Closing that gap requires anchoring signing times outside the system (a transparency
log, an RFC 3161 timestamp, a chain anchor); it is named future work, not a solved problem.

## Entry zero

The registry ships populated so its schema is demonstrated before a production key exists. Entry
zero is deterministically generated from a published string — anyone can reproduce it and confirm
it is not a secret — its validity window is closed, and its status is `example`. **No verifier
accepts it as a trust root.** It is replaced by entry one when a production key is generated.
