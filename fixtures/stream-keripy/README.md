# KERI message stream reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-22
- Sources: `src/keri/core/parsing.py` (`Parser.msgParsator`), `src/keri/core/eventing.py`
  (`messagize`, `receipt`, `reply`, `query`), `src/keri/core/counting.py` (`CtrDex_1_0`)
- Binary fields: `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact stream bytes;
  `raw` is the same bytes as text and the two are cross-checked on load. Every signature, key,
  prefix and SAID is canonical unpadded URL-safe Base64 as keripy prints it.

## Why keripy

The pinned signify-ts reference never parses a KERI stream: KERIA does that on its behalf, so it
has no equivalent of `Parser`. keripy is the canonical implementation and the one KERIA is built
on, so its parser is the reference for `src/stream.rs`.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/stream_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/stream_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## Contents

Deterministic inputs: the event and controller signature are the exact pinned pair from
`fixtures/attachment/v1.json`; the two witnesses use the seed byte sequences `0..31` and `32..63`
(non-transferable, `B` prefixes); the transferable endorser uses `64..95` (`D` prefix); the
datetime is `2021-01-01T00:00:00.000000+00:00`. Ed25519 signing is deterministic, so `--check`
needs no seeds beyond these. `material` records the derived values, including the datetime's
qb64 form and the receipt, reply and query messages keripy built.

`cases` records twelve complete streams. Each was composed with keripy's own primitives and then
fed to keripy's parser, which dispatches what it extracted to its event, receipt, reply and query
processors; `keripy_dispatch` is that record, with the fake processors capturing every argument.
Every message also carries `expected`, the groups it was built from, so the Rust test checks both
that the parser reproduces the construction and that it agrees with keripy's extraction.

- `controller_only`, `controller_witness_receipt`, `pipelined_controller_witness`: the groups
  `messagize` emits (`-A`, `-B`, `-C`, `-V`).
- `receipt_quadruple` (`-D`), `first_seen_replay_couple` (`-E`), `seal_source_couple_and_triple`
  (`-G`, `-I`) and `pathed_material_group` (`-L`): groups `messagize` cannot emit, composed from
  keripy's `Counter`, `Prefixer`, `Seqner`, `Saider`, `Dater` and `Pather`, and accepted by its
  parser.
- `two_messages`: a plain message followed by a pipelined one, to pin where one message ends.
- `witness_receipt_message` (`rct` with `-B`), `reply_with_receipt_couple` (`rpy` with `-C`),
  `reply_with_event_seal_group_and_receipt_couple` (`rpy` with `-F` and `-C`) and
  `query_with_last_establishment_group` (`qry` with `-H`): the supporting messages a watcher or
  witness exchanges, with the signature groups keripy requires on each.

Two keripy rules shaped the cases. A key event (`icp`, `rot`, `ixn` and their delegated forms)
must carry a `-A` group or keripy's dispatcher refuses it after parsing, so every event case has
one and the `-F` and `-H` groups appear on a reply and a query instead. And keripy dispatches only
some of what it extracts: `-G` couples reach the event processor as a delegation seal, `-E`
couples as a first-seen record, while `-I` triples and `-L` material are kept for other message
kinds. `keripy_dispatch` therefore proves acceptance for every group and extraction for the ones
keripy forwards.

`rejected_cases` records six streams keripy refuses: a stream opening with a counter
(`ColdStartError`), the big attachment group `-0V` that `msgParsator` does not read
(`UnexpectedCountCodeError`), a `-B` group where a `-H` group requires `-A`
(`UnexpectedCountCodeError`), a pipelined frame that ends before its signature and one that holds
no counter (`SizedGroupError`), and a controller signature cut short, on which keripy's parser
yields for more bytes rather than failing (recorded as `WaitingForBytes`, the generator's name for
that state).

One keripy behaviour is recorded here rather than as a case: a `-C` receipt couple cut short makes
`msgParsator` loop forever, because the shortage `yield` inside `_nonTransReceiptCouples` is
consumed by the `for` loop that iterates it as if it were a couple. The Rust parser returns
`Truncated` for that input, which the unit tests pin.

Rust tests consume the checked-in fixture and require neither Python nor network access.
