# KERI query-message reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-22
- Sources: `src/keri/core/eventing.py` (`query`, `messagize`), `src/keri/core/serdering.py`
  (`SerderKERI`, the `qry` field table), `src/keri/app/agenting.py` (`WitnessInquisitor.query`),
  `src/keri/app/habbing.py` (`Hab.query`, `Hab.endorse`), `src/keri/app/indirecting.py` (the
  mailbox `Poller`)
- Binary fields: `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message bytes;
  `raw` is the same bytes as text and the two are cross-checked on load.

## Why keripy

The pinned signify-ts reference has no `qry` at all, not even in its ilk table: KERIA queries on
its behalf (`fixtures/reply/README.md` records that finding). keripy is the canonical
implementation, so its `query` builder is the reference for `src/event/query.rs`, its askers are
the reference for how the query block is laid out, and its `SerderKERI` field table is the
reference for what the reader refuses.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/query_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/query_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## Contents

Deterministic inputs: the identifier asked about is the exact inception event pinned in
`fixtures/attachment/v1.json`; the witness asked uses the seed byte sequence `0..31`
(non-transferable, `B` prefix); the transferable asker uses `64..95` (`D` prefix); every stamp is
`2021-01-01T00:00:00.000000+00:00`. Ed25519 signing is deterministic, so `--check` needs no seeds
beyond these.

`field_labels` records the seven labels keripy writes, in order: `v`, `t`, `d`, `dt`, `r`, `rr`,
`q`. Unlike a receipt, `d` is a SAID of the query itself, which keripy's `SerderKERI` verifies on
the way in.

`cases` records seven queries, one per way keripy's own askers compose the query block, each with
the exact bytes, the SAID, the version string, and `read_back`, what keripy reports when it parses
the bytes again:

- `logs_from_start` and `key_state`: `WitnessInquisitor.query` defaults, `s` and `fn` both `"0"`.
- `logs_from_sequence`: `SeqNoQuerier`, hexadecimal floors without leading zeros.
- `logs_with_anchor`: `AnchorQuerier`, an anchor seal under `a`.
- `mailbox`: the mailbox `Poller`, `pre` and `topics` first.
- `bare`: `Hab.query` with no modifiers, just `i` and `src`.
- `with_reply_route`: a non-empty `rr`, which no keripy asker sets but the builder accepts.

In every case keripy appends `i` and `src` after whatever the asker supplied, which is the order
`QueryArguments` writes.

`signed` is one key-state query the way keripy sends it, twice: `Hab.endorse` attaches a
last-establishment signature group (`-H`) for a transferable asker and a receipt couple (`-C`) for
a non-transferable one, both pipelined. The Rust test rebuilds each from the query builder and the
attachment builder and compares the whole message.

`rejected_cases` records four messages keripy's `SerderKERI` refuses with `ValidationError`: a
tampered SAID, an extra field, a missing query block, and a reply's fields under the `qry` ilk.
The Rust reader refuses the first with `Said` and the rest with `UnexpectedFieldLayout`.

`reference_quirk_any_stamp_is_written` records keripy writing a malformed stamp verbatim and
reading it back unchecked. The Rust reader refuses it with `Timestamp`.

Rust tests consume the checked-in fixture and require neither Python nor network access.
