# KERI receipt-message reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-22
- Sources: `src/keri/core/eventing.py` (`receipt`, `messagize`), `src/keri/core/serdering.py`
  (`SerderKERI`, the `rct` field table)
- Binary fields: `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message bytes;
  `raw` is the same bytes as text and the two are cross-checked on load.

## Why keripy

The pinned signify-ts reference declares the `rct` ilk in its table but never constructs or reads
one: KERIA receipts events on its behalf (`fixtures/reply/README.md` records that finding). keripy
is the canonical implementation, so its `receipt` builder is the reference for
`src/event/receipt.rs`, and its `SerderKERI` field table is the reference for what the reader
refuses.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/receipt_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/receipt_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## Contents

Deterministic inputs: the receipted event is the exact inception event pinned in
`fixtures/attachment/v1.json`, so every receipt names its prefix and SAID; the witness uses the
seed byte sequence `0..31` (non-transferable, `B` prefix). Ed25519 signing is deterministic, so
`--check` needs no seeds beyond that.

`field_labels` records the five labels keripy writes, in order: `v`, `t`, `d`, `i`, `s`. The `d`
field is the receipted event's SAID, not a digest of the receipt.

`cases` records eight receipts, one per sequence number across every hexadecimal width keripy's
`Number` writes, from `0` to `2^128 - 1`: the exact bytes, the version string keripy sized, and
`read_back`, what keripy's `SerderKERI` reports when it parses the bytes again.

`signed_witness_receipt` is the receipt as a witness sends it: `messagize` attaches the witness's
indexed signature over the *event* as a `-B` group. The Rust test rebuilds it from the receipt
builder and the attachment builder and compares the whole message.

`rejected_cases` records four messages keripy's `SerderKERI` refuses with `ValidationError`
because their fields are not exactly the receipt's: an extra field, a missing sequence number,
`i` and `s` swapped, and an inception event's fields under the `rct` ilk. The Rust reader
refuses all four with `UnexpectedFieldLayout`.

Rust tests consume the checked-in fixture and require neither Python nor network access.
