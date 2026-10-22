# KERI reply-route reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-22
- Sources: `src/keri/core/routing.py` (`Revery.processReply`, `Router`, `compile_uri_template`),
  `src/keri/core/eventing.py` (`Kevery.registerReplyRoutes` and the four `processReply…`
  handlers), `src/keri/kering.py` (`Roles`, `Schemes`)
- Binary fields: `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message bytes;
  `raw` is the same bytes as text and the two are cross-checked on load.

## Why keripy

The pinned signify-ts reference builds replies but never reads one: KERIA routes them. keripy's
path for an incoming reply is therefore the reference for `src/event/reply/route.rs` and for
`ReplyMessage::from_serialized`.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/reply_route_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/reply_route_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

Every reply is run through keripy's own code unmodified: `Revery.processReply` verifies the SAID,
the `Router` matches the route against the four templates `Kevery.registerReplyRoutes` registers,
and the matching `Kevery.processReply…` handler checks the attributes. Two things are replaced:
the database tables the handlers read and write, by empty tables that remember nothing, and
`acceptReply`, best-available-data acceptance, by one that accepts everything. BADA is not part of
what is tested here. `keripy_outcome` is what the handler then stored: the database keys and the
value, which is exactly what the Rust reader must extract.

## Contents

Deterministic inputs: the controller is a real self-addressing identifier keripy incepted from
fixed seeds; the witness and watcher are non-transferable keys from fixed seeds; every stamp is
`2021-01-01T00:00:00.000000+00:00`. `roles` and `schemes` record keripy's two tables.

`cases` records nine replies keripy accepts:

- `end_role_add_watcher`, `end_role_cut_witness`: `/end/role/add` and `/cut`.
- `loc_scheme_http`; `loc_scheme_https_uppercase_url`, whose URL scheme only matches once
  lowercased; `loc_scheme_without_url_scheme`, a URL with no scheme at all; and
  `loc_scheme_withdrawn`, an empty URL.
- `key_state_notice`: `/ksn/{witness}` carrying a key state record.
- `watcher_add_with_oobi`, `watcher_cut`: `/watcher/{watcher}/add` with an OOBI and `/cut`
  without.

The Rust test reads each one, compares the typed route against `keripy_outcome`, and rebuilds the
reply from the typed route to the same bytes.

`rejected_cases` records eleven replies keripy refuses, all with `ValidationError`, each mapped to
a Rust error category: a tampered SAID; a route no template matches; `/end/role/drop`; an uppercase
route the case-insensitive router matches but the handler refuses; a trailing slash; a watcher
action other than `add` or `cut`; an end role without `eid`; a capitalised role; the scheme `ftp`;
a URL naming another scheme; and `localhost:5642`, which Python's `urlsplit` reads as the scheme
`localhost`, so keripy refuses it for `http`. That last one is the reason the Rust reader follows
`urlsplit`'s rule rather than a stricter URL parser.

Rust tests consume the checked-in fixture and require neither Python nor network access.
