"""Generates and checks receipt-message vectors from the pinned keripy.

signify-ts declares the ``rct`` ilk but never builds or reads one -- KERIA receipts events on its
behalf -- so ``src/event/receipt.rs`` is verified against keripy's ``receipt`` builder and the
field layout its ``SerderKERI`` enforces on the way back in. keripy is pinned in
``pyproject.toml`` and ``uv.lock`` beside this file; run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/receipt_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import json
import pathlib
import re
import sys

from keri.core import eventing, serdering
from keri.core.coring import MtrDex
from keri.core.signing import Signer

from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-22"

# The exact inception event pinned in fixtures/attachment/v1.json: its prefix and SAID are what the
# receipts name, and the witness signs its bytes.
EVENT = (
    '{"v":"KERI10JSON000125_","t":"icp","d":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL",'
    '"i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","s":"0","kt":1,'
    '"k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,'
    '"n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}'
)
WITNESS_SEED = bytes(range(0, 32))

# Sequence numbers across the hexadecimal widths keripy's `Number` can write.
SEQUENCE_NUMBERS = [0, 1, 10, 255, 4096, 2**32, 2**64 - 1, 2**128 - 1]

VERSION_STRING = re.compile(rb"KERI10JSON[0-9a-f]{6}_")


def resize(raw):
    """Rewrites the version string of a hand-edited message so its size is right again."""
    return VERSION_STRING.sub(b"KERI10JSON%06x_" % len(raw), raw, count=1)


def read_back(raw):
    """What keripy makes of a receipt it reads from the wire."""
    serder = serdering.SerderKERI(raw=raw)
    return {"identifier": serder.pre, "sequence_number": serder.sn, "said": serder.said, "kind": serder.ilk}


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

    cases = []
    for sn in SEQUENCE_NUMBERS:
        receipt = eventing.receipt(pre=event.pre, sn=sn, said=event.said)
        cases.append({
            "name": f"sequence_{sn}",
            "identifier": event.pre,
            "sequence_number": sn,
            "sequence_hex": receipt.ked["s"],
            "said": event.said,
            "version_string": receipt.ked["v"],
            "raw": receipt.raw.decode(),
            "raw_hex": receipt.raw.hex(),
            "raw_byte_size": len(receipt.raw),
            "read_back": read_back(receipt.raw),
        })

    # A receipt the way a witness sends it: the message plus its indexed signature over the event.
    receipt = eventing.receipt(pre=event.pre, sn=0, said=event.said)
    wiger = witness.sign(ser=event.raw, index=0)
    signed = bytes(eventing.messagize(receipt, wigers=[wiger]))
    signed_case = {
        "receipt": receipt.raw.decode(),
        "witness_verfer": witness.verfer.qb64,
        "witness_signature": wiger.qb64,
        "raw": signed.decode(),
        "raw_hex": signed.hex(),
    }

    base = receipt.raw
    rejected = [
        rejected_case("extra_field", resize(base.replace(b'"s":"0"}', b'"s":"0","a":[]}')), "UnexpectedFieldLayout"),
        rejected_case("missing_sequence_number", resize(base.replace(b',"s":"0"}', b"}")), "UnexpectedFieldLayout"),
        rejected_case("fields_out_of_order",
                      resize(base.replace(b'"i":"%s","s":"0"' % event.pre.encode(), b'"s":"0","i":"%s"' % event.pre.encode())),
                      "UnexpectedFieldLayout"),
        rejected_case("inception_fields_under_the_receipt_ilk",
                      resize(EVENT.encode().replace(b'"t":"icp"', b'"t":"rct"')), "UnexpectedFieldLayout"),
    ]

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/eventing.py", "src/keri/core/serdering.py"],
        "event": EVENT,
        "witness_seed_hex": WITNESS_SEED.hex(),
        "field_labels": list(receipt.ked.keys()),
        "cases": cases,
        "signed_witness_receipt": signed_case,
        "rejected_cases": rejected,
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "receipt-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("receipt-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
