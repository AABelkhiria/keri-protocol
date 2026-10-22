# KERI key-state reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-22
- Sources: `src/keri/core/eventing.py` (`state`, `incept`, `rotate`, `interact`, `reply`),
  `src/keri/db/basing.py` (`KeyStateRecord`, `StateEERecord`), `src/keri/app/watching.py`
  (`diffState`)
- Binary fields: none. `record_json` is the exact compact JSON of keripy's record, and the
  `ksn_reply` carries `raw_hex` cross-checked against `raw` on load.

## Why keripy

The pinned signify-ts reference only reads key states from KERIA: it never builds one, never
validates one, and never compares two. keripy's `state` is the builder whose checks
`KeyStateBuilder` applies, `KeyStateRecord` is the field layout `KeyStateRecord::from_sad` reads,
and `diffState` is the comparison `compare` makes.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/key_state_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/key_state_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## Contents

Deterministic inputs: controller, next-key, witness and delegator keys come from fixed seed byte
ranges; the identifier, its rotation and its interaction are real events keripy built from them;
every stamp is `2021-01-01T00:00:00.000000+00:00`.

`field_labels` and `establishment_labels` record the seventeen record labels and the four
latest-establishment labels, in the order keripy writes them.

`cases` records eleven records. Nine carry `inputs`, the exact arguments given to keripy's `state`,
which the Rust test feeds to `KeyStateBuilder` and compares against `record_json` byte for byte;
`record_json` must also read back through `KeyStateRecord::from_sad` into the same record:

- `inception_defaults`: every threshold left to keripy's defaults.
- `inception_witnessed`: three witnesses, threshold two.
- `inception_default_witness_threshold`: four witnesses with no threshold given.
- `rotation_with_cuts_and_adds` and `interaction_after_rotation`: the latest establishment event
  removed one witness and added another, and the interaction keeps pointing at it.
- `weighted_multisig`: a single-clause weighted signing threshold and a two-clause next threshold.
- `delegated_with_traits`: a delegated inception with `EO` and `DND`.
- `abandoned`: a rotation committing to no next keys, next threshold zero.
- `large_numbers`: a sequence number of `2^64` and a first-seen ordinal of `300`.

The last two, `inception_forked` and `other_identifier`, exist for the comparisons and are only
read back.

`ksn_reply` is the interaction's record the way a witness sends it, the `a` block of a
`/ksn/{witness}` reply.

`comparisons` records `diffState` over pairs of those records, local first: `even`,
`duplicitous` (same sequence number, different SAID), `ahead` and `behind`.
`comparison_of_different_identifiers` records keripy refusing two records of different identifiers
with `ValueError`; Rust refuses with `IdentifierMismatch`.

`rejected_cases` records eleven `state` calls keripy refuses with `ValueError`, each with its
inputs and the Rust error category the builder returns for the same inputs.

`reference_quirk_unreachable_ample_default` records that keripy's `state` assigns a simple-majority
witness threshold and then tests for `None` again before falling back to `ample`, which can
therefore never run: four witnesses default to two where `ample` would give three. The reachable
default is the one reproduced.

Rust tests consume the checked-in fixture and require neither Python nor network access.
