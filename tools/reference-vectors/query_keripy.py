"""Generates and checks query-message vectors from the pinned keripy.

signify-ts has no ``qry`` at all -- KERIA queries on its behalf -- so ``src/event/query.rs`` is
verified against keripy's ``query`` builder, the query blocks keripy's own askers compose
(``WitnessInquisitor.query``, ``Hab.query`` and the mailbox ``Poller``), and the field layout its
``SerderKERI`` enforces on the way back in. keripy is pinned in ``pyproject.toml`` and ``uv.lock``
beside this file; run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/query_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import json
import pathlib
import re
import sys

from keri.core import eventing, serdering
from keri.core.coring import MtrDex
from keri.core.eventing import SealLast
from keri.core.signing import Signer

from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-22"

# The exact inception event pinned in fixtures/attachment/v1.json: its prefix is what the queries
# ask about, and its SAID anchors the seal case.
EVENT = (
    '{"v":"KERI10JSON000125_","t":"icp","d":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL",'
    '"i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","s":"0","kt":1,'
    '"k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,'
    '"n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}'
)
WITNESS_SEED = bytes(range(0, 32))
ENDORSER_SEED = bytes(range(64, 96))
STAMP = "2021-01-01T00:00:00.000000+00:00"

VERSION_STRING = re.compile(rb"KERI10JSON[0-9a-f]{6}_")


def resize(raw):
    """Rewrites the version string of a hand-edited message so its size is right again."""
    return VERSION_STRING.sub(b"KERI10JSON%06x_" % len(raw), raw, count=1)


def read_back(raw):
    """What keripy makes of a query it reads from the wire."""
    serder = serdering.SerderKERI(raw=raw)
    ked = serder.ked
    return {"kind": serder.ilk, "said": serder.said, "route": ked["r"], "reply_route": ked["rr"],
            "timestamp": ked["dt"], "query": ked["q"]}


def query_case(name, route, block, reply_route=""):
    serder = eventing.query(route=route, replyRoute=reply_route, query=block, stamp=STAMP)
    return {
        "name": name,
        "route": route,
        "reply_route": reply_route,
        "timestamp": STAMP,
        "query_json": json.dumps(block, separators=(",", ":")),
        "said": serder.said,
        "version_string": serder.ked["v"],
        "raw": serder.raw.decode(),
        "raw_hex": serder.raw.hex(),
        "raw_byte_size": len(serder.raw),
        "read_back": read_back(serder.raw),
    }


def rejected_case(name, raw, rust_error_category):
    try:
        serdering.SerderKERI(raw=raw)
    except Exception as error:  # noqa: BLE001 - the error class is the datum being recorded
        return {
            "name": name,
            "raw": raw.decode(),
            "raw_hex": raw.hex(),
            "reference_error_category": type(error).__name__,
            "reference_error_message": str(error),
            "rust_error_category": rust_error_category,
        }
    raise AssertionError(f"reference unexpectedly accepted rejected case {name}")


def main():
    event = serdering.SerderKERI(raw=EVENT.encode())
    witness = Signer(raw=WITNESS_SEED, code=MtrDex.Ed25519_Seed, transferable=False)
    endorser = Signer(raw=ENDORSER_SEED, code=MtrDex.Ed25519_Seed, transferable=True)
    pre = event.pre
    wit = witness.verfer.qb64
    endorser_pre = endorser.verfer.qb64

    # The blocks keripy's askers compose. `Hab.query` appends `i` and `src` after whatever the
    # caller supplied, which is what fixes the key order below.
    def block(extra=None):
        composed = dict(extra or {})
        composed["i"] = pre
        composed["src"] = wit
        return composed

    cases = [
        # WitnessInquisitor.query defaults: sn='0', fn='0'.
        query_case("logs_from_start", "logs", block({"s": "0", "fn": "0"})),
        # SeqNoQuerier: a specific sequence number and first-seen floor, hex without leading zeros.
        query_case("logs_from_sequence", "logs", block({"s": "a", "fn": "3"})),
        # AnchorQuerier: an anchor seal to search for.
        query_case("logs_with_anchor", "logs", block({"s": "0", "fn": "0", "a": {"i": pre, "s": "1", "d": event.said}})),
        # KeyStateNoticer: route ksn with the inquisitor defaults.
        query_case("key_state", "ksn", block({"s": "0", "fn": "0"})),
        # Mailbox Poller: `pre` and `topics` first, then `i` and `src`.
        query_case("mailbox", "mbx", block({"pre": pre, "topics": {"/receipt": 0, "/replay": 2, "/reply": 0}})),
        # Hab.query with no modifiers at all.
        query_case("bare", "logs", block()),
        # A reply route, which no keripy asker sets but the builder accepts.
        query_case("with_reply_route", "logs", block(), reply_route="/log/processor"),
    ]

    # Queries as keripy sends them: `Hab.endorse` attaches a last-establishment group for a
    # transferable asker and a receipt couple for a non-transferable one, pipelined.
    serder = eventing.query(route="ksn", query=block({"s": "0", "fn": "0"}), stamp=STAMP)
    endorsed = bytes(eventing.messagize(serder, sigers=[endorser.sign(ser=serder.raw, index=0)],
                                        seal=SealLast(i=endorser_pre), pipelined=True))
    couple = witness.sign(ser=serder.raw)
    receipted = bytes(eventing.messagize(serder, cigars=[couple], pipelined=True))
    signed = {
        "query": serder.raw.decode(),
        "endorser_prefix": endorser_pre,
        "endorser_signature": endorser.sign(ser=serder.raw, index=0).qb64,
        "endorsed_raw": endorsed.decode(),
        "endorsed_raw_hex": endorsed.hex(),
        "witness_verfer": wit,
        "witness_signature": couple.qb64,
        "receipted_raw": receipted.decode(),
        "receipted_raw_hex": receipted.hex(),
    }

    base = serder.raw
    said = serder.said.encode()
    rejected = [
        rejected_case("tampered_said", base.replace(said, said[:-4] + b"AAAA"), "Said"),
        rejected_case("extra_field", resize(base.replace(b'"rr":""', b'"rr":"","x":1')), "UnexpectedFieldLayout"),
        rejected_case("missing_query_block", resize(base.replace(b',"q":{%s}}' % base.split(b'"q":{')[1][:-2], b"}")),
                      "UnexpectedFieldLayout"),
        rejected_case("reply_fields_under_the_query_ilk",
                      resize(base.replace(b'"rr":""', b'"a":{}').replace(b',"q":{', b',"x":{')), "UnexpectedFieldLayout"),
    ]

    # keripy writes whatever `stamp` it is given; the Rust reader validates the shape.
    garbage_stamp = eventing.query(route="logs", query=block(), stamp="yesterday")
    quirk = {
        "raw": garbage_stamp.raw.decode(),
        "note": "keripy's `query` writes the stamp verbatim and `SerderKERI` never checks it, so a"
                " malformed `dt` round-trips through keripy unnoticed. The Rust reader rejects it.",
        "rust_error_category": "Timestamp",
    }

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/eventing.py", "src/keri/core/serdering.py", "src/keri/app/agenting.py",
                    "src/keri/app/habbing.py", "src/keri/app/indirecting.py"],
        "event": EVENT,
        "witness_seed_hex": WITNESS_SEED.hex(),
        "endorser_seed_hex": ENDORSER_SEED.hex(),
        "field_labels": list(serder.ked.keys()),
        "cases": cases,
        "signed": signed,
        "rejected_cases": rejected,
        "reference_quirk_any_stamp_is_written": quirk,
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "query-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("query-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
