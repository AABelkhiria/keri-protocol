# KERI reply acceptance reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-22
- Sources: `src/keri/core/routing.py` (`Revery.acceptReply`), `src/keri/core/eventing.py`
  (`validateSigs`, `verifySigs`, `messagize`, `reply`)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes; `raw` is the same bytes as text and the two are cross-checked on load.

## Why keripy

The pinned signify-ts reference never decides whether a reply replaces an older one: KERIA does.
keripy's `Revery.acceptReply` is the reference for `src/event/reply/acceptance.rs`.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/acceptance_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/acceptance_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the decisions were recorded

The generator opens a temporary keripy `Habery` from a fixed salt and makes two real
transferable identifiers: `single`, one key, which then rotates and interacts, and `double`, two
keys with a threshold of two. A witness and a stranger are non-transferable keys from fixed seeds.
Every reply is a `/loc/scheme` reply stamped at one of three fixed seconds.

Each case runs keripy's `Revery.acceptReply` unmodified against that database. When a case has a
`prior`, keripy first accepts the prior reply, so it is stored exactly as keripy stores it, and the
new reply is then judged against it. `escrowReply` is the one method intercepted, to record that
keripy set the reply aside rather than storing it.

`signer_events` records both identifiers' key event logs, which the Rust test serves through
`SignerEvents` exactly as keripy reads them from its database.

## Contents

`cases` records nineteen decisions. Each has the authority, the prior reply if any (its bytes,
timestamp and the sequence number its signature group named), the new reply, keripy's result
(`accepted` and `escrowed`, or the error it raised) and the Rust outcome expected for the same
input:

- Transferable signer: accepted with no prior, later on the same event, and on a later event
  despite an earlier timestamp; stale at the same time, earlier on the same event, and on an
  earlier event despite a later timestamp; escrowed when the named event is unknown and when one of
  two required signatures is attached; accepted with both; skipped when signed by another
  identifier; and refused, as keripy raises `ValidationError`, when the named SAID is not the
  signer's event at that sequence number, when the named event is an interaction with no keys, and
  when no signature verifies.
- Non-transferable signer: accepted with no prior and when later; stale at the same time and when
  earlier; skipped when signed by another key or when the signature does not verify.

`reference_quirk_index_out_of_range` records keripy raising `IndexError` for a signature whose
index is past the end of the key list. The Rust port skips that signature and, with nothing else
in the group, refuses with `NoVerifiedSignatures`.

Rust tests consume the checked-in fixture and require neither Python nor network access.
