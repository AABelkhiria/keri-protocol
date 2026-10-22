"""Generates and checks message-stream vectors from the pinned keripy.

signify-ts never parses a KERI stream -- KERIA does that for it -- so the stream walker in
``src/stream.rs`` is verified against keripy's ``Parser.msgParsator``. Every case here is a
complete stream built with keripy's own primitives, then fed to keripy's parser, which records what
it dispatched to its event, receipt, reply and query processors. keripy is pinned in
``pyproject.toml`` and ``uv.lock`` beside this file; run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/stream_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import json
import pathlib
import sys

from keri import kering
from keri.core import eventing, parsing, serdering
from keri.core.coring import Dater, MtrDex, Pather, Prefixer, Saider, Seqner
from keri.core.counting import Codens, Counter
from keri.core.eventing import SealEvent, SealLast
from keri.core.indexing import Siger
from keri.core.signing import Signer

from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-22"

# The exact inception event and controller signature pinned in fixtures/attachment/v1.json and
# fixtures/attachment-keripy/v1.json, reused verbatim so the three fixtures describe one message.
EVENT = (
    '{"v":"KERI10JSON000125_","t":"icp","d":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL",'
    '"i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","s":"0","kt":1,'
    '"k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,'
    '"n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}'
)
CONTROLLER_SIGNATURE = (
    "AABB3MJGmBXxSEryNHw3YwZZLRl_6Ws4Me2WFq8PrQ6WlluSOpPqbwXuiG9RvNWZkqeW8A_0VRjokGMVRZ3m-c0I"
)

# Deterministic signers: two non-transferable witnesses and one transferable endorser.
WITNESS_SEEDS = [bytes(range(0, 32)), bytes(range(32, 64))]
ENDORSER_SEED = bytes(range(64, 96))
DATETIME = "2021-01-01T00:00:00.000000+00:00"
MAX_PARSER_STEPS = 64


def counter(name, count):
    """Encodes one KERI v1 counter by its code name."""
    return Counter(getattr(Codens, name), count=count, gvrsn=kering.Vrsn_1_0).qb64b


def seqner(sn):
    return Seqner(sn=sn).qb64b


def saider(said):
    return Saider(qb64=said).qb64b


def prefixer(pre):
    return Prefixer(qb64=pre).qb64b


class Capture:
    """Stands in for keripy's Kevery, Revery and Exchanger and records every dispatch."""

    def __init__(self):
        self.calls = []

    @staticmethod
    def _sigs(sigs):
        return [sig.qb64 for sig in sigs or []]

    @staticmethod
    def _cigars(cigars):
        return [{"verifier": cigar.verfer.qb64, "signature": cigar.qb64} for cigar in cigars or []]

    @staticmethod
    def _tsgs(tsgs):
        return [
            {
                "identifier": prefixer.qb64,
                "sequence_number": seqner.sn,
                "said": saider.qb64,
                "signatures": [sig.qb64 for sig in sigers],
            }
            for prefixer, seqner, saider, sigers in tsgs or []
        ]

    def processEvent(self, serder, sigers=None, wigers=None, delseqner=None, delsaider=None,
                     firner=None, dater=None, **kwa):
        self.calls.append({
            "method": "processEvent",
            "said": serder.said,
            "sigers": self._sigs(sigers),
            "wigers": self._sigs(wigers),
            "delegation_seal": (
                {"sequence_number": delseqner.sn, "said": delsaider.qb64} if delseqner is not None else None
            ),
            "first_seen": {"ordinal": firner.sn, "datetime": dater.dts} if firner is not None else None,
        })

    def processAttachedReceiptCouples(self, serder, cigars, **kwa):
        self.calls.append({"method": "processAttachedReceiptCouples", "cigars": self._cigars(cigars)})

    def processAttachedReceiptQuadruples(self, serder, trqs, **kwa):
        self.calls.append({
            "method": "processAttachedReceiptQuadruples",
            "quadruples": [
                {
                    "identifier": prefixer.qb64,
                    "sequence_number": seqner.sn,
                    "said": saider.qb64,
                    "signature": siger.qb64,
                }
                for prefixer, seqner, saider, siger in trqs
            ],
        })

    def processReceipt(self, serder, cigars=None, tsgs=None, wigers=None, **kwa):
        self.calls.append({
            "method": "processReceipt",
            "said": serder.said,
            "cigars": self._cigars(cigars),
            "tsgs": self._tsgs(tsgs),
            "wigers": self._sigs(wigers),
        })

    def processReply(self, serder, cigars=None, tsgs=None, **kwa):
        self.calls.append({
            "method": "processReply",
            "said": serder.said,
            "cigars": self._cigars(cigars),
            "tsgs": self._tsgs(tsgs),
        })

    def processQuery(self, serder, source=None, sigers=None, cigars=None, **kwa):
        self.calls.append({
            "method": "processQuery",
            "said": serder.said,
            "source": source.qb64 if source is not None else None,
            "sigers": self._sigs(sigers),
            "cigars": self._cigars(cigars),
        })


def drive(stream):
    """Runs keripy's parser over a whole stream and returns everything it dispatched.

    ``msgParsator`` yields when it wants more bytes; a complete stream never makes it yield, so a
    yield is reported as the parser waiting.
    """
    parser = parsing.Parser()
    ims = bytearray(stream)
    capture = Capture()
    while ims:
        generator = parser.msgParsator(ims=ims, framed=True, pipeline=False,
                                       kvy=capture, rvy=capture, exc=capture, local=False)
        for _ in range(MAX_PARSER_STEPS):
            try:
                next(generator)
            except StopIteration:
                break
        else:
            raise WaitingForBytes("keripy's parser is waiting for more bytes")
    return capture.calls


class WaitingForBytes(Exception):
    """keripy's parser yielded instead of finishing: the stream is incomplete."""


def expected(*, controller=(), witness=(), couples=(), quadruples=(), first_seen=(), transferable=(),
             last=(), seal_couples=(), seal_triples=(), pathed=(), pipelined=False):
    return {
        "pipelined": pipelined,
        "controller_signatures": list(controller),
        "witness_signatures": list(witness),
        "receipt_couples": list(couples),
        "receipt_quadruples": list(quadruples),
        "first_seen_replay_couples": list(first_seen),
        "transferable_signature_groups": list(transferable),
        "last_establishment_signature_groups": list(last),
        "seal_source_couples": list(seal_couples),
        "seal_source_triples": list(seal_triples),
        "pathed_material": list(pathed),
    }


def message(serder, attachments, expectation):
    raw = bytes(serder.raw) + bytes(attachments)
    return {
        "event": serder.raw.decode(),
        "attachments": bytes(attachments).decode(),
        "expected": expectation,
        "raw_byte_size": len(raw),
    }, raw


def case(name, messages):
    stream = b"".join(raw for _, raw in messages)
    return {
        "name": name,
        "raw": stream.decode(),
        "raw_hex": stream.hex(),
        "messages": [entry for entry, _ in messages],
        "keripy_dispatch": drive(stream),
    }


def rejected_case(name, stream, rust_error_category):
    try:
        drive(stream)
    except Exception as error:  # noqa: BLE001 - the error class is the datum being recorded
        return {
            "name": name,
            "raw": stream.decode(errors="replace"),
            "raw_hex": stream.hex(),
            "reference_error_category": type(error).__name__,
            "reference_error_message": str(error),
            "rust_error_category": rust_error_category,
        }
    raise AssertionError(f"reference unexpectedly accepted rejected case {name}")


def main():
    serder = serdering.SerderKERI(raw=EVENT.encode())
    controller = Siger(qb64=CONTROLLER_SIGNATURE)

    witnesses = [Signer(raw=seed, code=MtrDex.Ed25519_Seed, transferable=False) for seed in WITNESS_SEEDS]
    wigers = [signer.sign(ser=serder.raw, index=index) for index, signer in enumerate(witnesses)]
    cigars = [signer.sign(ser=serder.raw) for signer in witnesses]
    endorser = Signer(raw=ENDORSER_SEED, code=MtrDex.Ed25519_Seed, transferable=True)
    endorser_pre = endorser.verfer.qb64
    endorsement = endorser.sign(ser=serder.raw, index=0)
    dater = Dater(dts=DATETIME)

    def attachments_of(signed, message_serder=serder):
        return bytes(signed)[len(message_serder.raw):]

    def messagize(**kwa):
        return attachments_of(eventing.messagize(serder, **kwa))

    couples = [{"verifier": cigar.verfer.qb64, "signature": cigar.qb64} for cigar in cigars]
    quadruple = {"identifier": endorser_pre, "sequence_number": 0, "said": serder.said, "signature": endorsement.qb64}

    # Groups messagize cannot emit, composed from keripy's own primitives.
    receipt_quadruple = counter("TransReceiptQuadruples", 1) + prefixer(endorser_pre) + seqner(0) + saider(serder.said) + endorsement.qb64b
    first_seen = counter("FirstSeenReplayCouples", 1) + seqner(0) + dater.qb64b
    seal_couple = counter("SealSourceCouples", 1) + seqner(1) + saider(serder.said)
    seal_triple = counter("SealSourceTriples", 1) + prefixer(serder.pre) + seqner(2) + saider(serder.said)
    pathed_payload = Pather(bext="-").qb64b + counter("ControllerIdxSigs", 1) + controller.qb64b
    pathed = counter("PathedMaterialGroup", len(pathed_payload) // 4) + pathed_payload

    # Supporting messages: a witness receipt, a reply and a query.
    receipt = eventing.receipt(pre=serder.pre, sn=0, said=serder.said)
    reply = eventing.reply(route="/loc/scheme", data={"eid": witnesses[0].verfer.qb64, "scheme": "http",
                                                      "url": "http://127.0.0.1:5632/"}, stamp=DATETIME)
    reply_cigar = witnesses[0].sign(ser=reply.raw)
    reply_siger = endorser.sign(ser=reply.raw, index=0)
    reply_group = {"identifier": endorser_pre, "sequence_number": 0, "said": serder.said, "signatures": [reply_siger.qb64]}
    query = eventing.query(route="ksn", query={"i": serder.pre, "src": witnesses[0].verfer.qb64}, stamp=DATETIME)
    query_siger = endorser.sign(ser=query.raw, index=0)

    cases = [
        case("controller_only", [
            message(serder, messagize(sigers=[controller]), expected(controller=[controller.qb64])),
        ]),
        case("controller_witness_receipt", [
            message(serder, messagize(sigers=[controller], wigers=wigers, cigars=cigars[:1]),
                    expected(controller=[controller.qb64], witness=[w.qb64 for w in wigers], couples=couples[:1])),
        ]),
        case("pipelined_controller_witness", [
            message(serder, messagize(sigers=[controller], wigers=wigers[:1], pipelined=True),
                    expected(controller=[controller.qb64], witness=[wigers[0].qb64], pipelined=True)),
        ]),
        case("receipt_quadruple", [
            message(serder, messagize(sigers=[controller]) + receipt_quadruple,
                    expected(controller=[controller.qb64], quadruples=[quadruple])),
        ]),
        case("first_seen_replay_couple", [
            message(serder, messagize(sigers=[controller]) + first_seen,
                    expected(controller=[controller.qb64], first_seen=[{"ordinal": 0, "datetime": DATETIME}])),
        ]),
        case("seal_source_couple_and_triple", [
            message(serder, messagize(sigers=[controller]) + seal_couple + seal_triple,
                    expected(controller=[controller.qb64],
                             seal_couples=[{"sequence_number": 1, "said": serder.said}],
                             seal_triples=[{"identifier": serder.pre, "sequence_number": 2, "said": serder.said}])),
        ]),
        case("pathed_material_group", [
            message(serder, messagize(sigers=[controller]) + pathed,
                    expected(controller=[controller.qb64], pathed=[pathed_payload.decode()])),
        ]),
        case("two_messages", [
            message(serder, messagize(sigers=[controller]), expected(controller=[controller.qb64])),
            message(serder, messagize(sigers=[controller], wigers=wigers, pipelined=True),
                    expected(controller=[controller.qb64], witness=[w.qb64 for w in wigers], pipelined=True)),
        ]),
        case("witness_receipt_message", [
            message(receipt, attachments_of(eventing.messagize(receipt, wigers=wigers[:1]), receipt),
                    expected(witness=[wigers[0].qb64])),
        ]),
        case("reply_with_receipt_couple", [
            message(reply, attachments_of(eventing.messagize(reply, cigars=[reply_cigar]), reply),
                    expected(couples=[{"verifier": reply_cigar.verfer.qb64, "signature": reply_cigar.qb64}])),
        ]),
        case("reply_with_event_seal_group_and_receipt_couple", [
            message(reply, attachments_of(eventing.messagize(
                reply, sigers=[reply_siger], seal=SealEvent(i=endorser_pre, s="0", d=serder.said), cigars=[reply_cigar]), reply),
                    expected(transferable=[reply_group],
                             couples=[{"verifier": reply_cigar.verfer.qb64, "signature": reply_cigar.qb64}])),
        ]),
        case("query_with_last_establishment_group", [
            message(query, attachments_of(eventing.messagize(query, sigers=[query_siger], seal=SealLast(i=endorser_pre)), query),
                    expected(last=[{"identifier": endorser_pre, "signatures": [query_siger.qb64]}])),
        ]),
    ]

    event = serder.raw
    rejected = [
        rejected_case("stream_starts_with_counter",
                      counter("ControllerIdxSigs", 1) + controller.qb64b + event, "UnexpectedStreamStart"),
        rejected_case("big_attachment_group",
                      event + counter("BigAttachmentGroup", 1) + counter("ControllerIdxSigs", 0), "UnsupportedGroup"),
        rejected_case("witness_group_inside_last_establishment_group",
                      event + counter("TransLastIdxSigGroups", 1) + prefixer(endorser_pre)
                      + counter("WitnessIdxSigs", 1) + wigers[0].qb64b, "UnexpectedGroup"),
        rejected_case("pipelined_frame_without_its_signature",
                      event + counter("AttachmentGroup", 1) + counter("ControllerIdxSigs", 1), "Truncated"),
        rejected_case("non_counter_inside_pipelined_frame",
                      event + counter("AttachmentGroup", 2) + b"ABCDEFGH", "Cesr"),
        rejected_case("truncated_controller_signature",
                      event + counter("ControllerIdxSigs", 1) + controller.qb64b[:40], "Truncated"),
    ]

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/parsing.py", "src/keri/core/eventing.py", "src/keri/core/counting.py"],
        "material": {
            "event": EVENT,
            "controller_signature": CONTROLLER_SIGNATURE,
            "witness_seeds_hex": [seed.hex() for seed in WITNESS_SEEDS],
            "witness_verfers": [signer.verfer.qb64 for signer in witnesses],
            "endorser_seed_hex": ENDORSER_SEED.hex(),
            "endorser_prefix": endorser_pre,
            "datetime": DATETIME,
            "datetime_qb64": dater.qb64,
            "receipt_event": receipt.raw.decode(),
            "reply_event": reply.raw.decode(),
            "query_event": query.raw.decode(),
        },
        "cases": cases,
        "rejected_cases": rejected,
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "stream-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("stream-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
