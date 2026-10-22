"""Generates and checks key-state vectors from the pinned keripy.

signify-ts only reads key states from KERIA and never builds, validates or compares one, so
``src/event/key_state.rs`` is verified against keripy's ``state`` builder, its ``KeyStateRecord``
field layout, and ``diffState`` from ``keri.app.watching``. keripy is pinned in ``pyproject.toml``
and ``uv.lock`` beside this file; run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/key_state_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import json
import pathlib
import sys
from dataclasses import asdict

from keri.app.watching import diffState
from keri.core import eventing
from keri.core.coring import Diger, MtrDex
from keri.core.eventing import StateEstEvent
from keri.core.signing import Signer

from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-22"
STAMP = "2021-01-01T00:00:00.000000+00:00"


def signer(start, transferable=True):
    return Signer(raw=bytes(range(start, start + 32)), code=MtrDex.Ed25519_Seed, transferable=transferable)


def digest(verfer):
    return Diger(ser=verfer.qb64b).qb64


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def inputs_of(*, pre, sn, pig, dig, fn, eilk, keys, eevt, sith=None, ndigs=None, nsith=None, toad=None,
              wits=None, cnfg=None, dpre=None):
    """The arguments given to keripy's `state`, in the shape the Rust test feeds its builder."""
    return {
        "identifier": pre, "sequence_number": sn, "prior": pig, "said": dig, "first_seen": fn,
        "latest_kind": eilk, "keys": keys,
        "signing_threshold": compact(sith) if sith is not None else None,
        "next_digests": ndigs or [],
        "next_threshold": compact(nsith) if nsith is not None else None,
        "witness_threshold": toad, "witnesses": wits or [], "configuration": cnfg or [],
        "establishment": {"sequence_number": int(eevt.s, 16), "said": eevt.d, "removed": eevt.br, "added": eevt.ba},
        "delegator": dpre,
    }


def build(name, **kwa):
    """Runs keripy's `state` and returns the case name, its inputs and the record keripy built."""
    return name, inputs_of(**kwa), eventing.state(stamp=STAMP, **kwa)


def rejected(name, rust_error_category, **kwa):
    try:
        eventing.state(stamp=STAMP, **kwa)
    except Exception as error:  # noqa: BLE001 - the error class is the datum being recorded
        return {
            "name": name,
            "inputs": inputs_of(**kwa),
            "reference_error_category": type(error).__name__,
            "reference_error_message": str(error),
            "rust_error_category": rust_error_category,
        }
    raise AssertionError(f"reference unexpectedly accepted rejected case {name}")


def main():
    controllers = [signer(0), signer(32), signer(64)]
    nexts = [signer(96), signer(128), signer(160)]
    witnesses = [signer(192 + 4 * index, transferable=False).verfer.qb64 for index in range(4)]
    delegator = signer(224).verfer.qb64

    keys = [controllers[0].verfer.qb64]
    ndigs = [digest(nexts[0].verfer)]
    icp = eventing.incept(keys=keys, ndigs=ndigs, wits=witnesses[:3], toad=2, code=MtrDex.Blake3_256)
    pre = icp.pre
    rot = eventing.rotate(pre=pre, keys=[nexts[0].verfer.qb64], dig=icp.said, sn=1,
                          ndigs=[digest(nexts[1].verfer)], wits=witnesses[:3], cuts=[witnesses[0]],
                          adds=[witnesses[3]], toad=2)
    ixn = eventing.interact(pre=pre, dig=rot.said, sn=2)

    icp_ee = StateEstEvent(s="0", d=icp.said, br=[], ba=[])
    rot_ee = StateEstEvent(s="1", d=rot.said, br=[witnesses[0]], ba=[witnesses[3]])
    rotated_wits = [witnesses[1], witnesses[2], witnesses[3]]
    multi_keys = [controller.verfer.qb64 for controller in controllers]
    multi_digs = [digest(nxt.verfer) for nxt in nexts]

    built = [
        build("inception_defaults", pre=pre, sn=0, pig="", dig=icp.said, fn=0, eilk="icp", keys=keys,
              eevt=icp_ee, ndigs=ndigs),
        build("inception_witnessed", pre=pre, sn=0, pig="", dig=icp.said, fn=0, eilk="icp", keys=keys,
              eevt=icp_ee, ndigs=ndigs, wits=witnesses[:3], toad=2),
        build("inception_default_witness_threshold", pre=pre, sn=0, pig="", dig=icp.said, fn=0, eilk="icp",
              keys=keys, eevt=icp_ee, ndigs=ndigs, wits=witnesses),
        build("rotation_with_cuts_and_adds", pre=pre, sn=1, pig=icp.said, dig=rot.said, fn=1, eilk="rot",
              keys=[nexts[0].verfer.qb64], eevt=rot_ee, ndigs=[digest(nexts[1].verfer)], wits=rotated_wits, toad=2),
        build("interaction_after_rotation", pre=pre, sn=2, pig=rot.said, dig=ixn.said, fn=2, eilk="ixn",
              keys=[nexts[0].verfer.qb64], eevt=rot_ee, ndigs=[digest(nexts[1].verfer)], wits=rotated_wits, toad=2),
        build("weighted_multisig", pre=pre, sn=0, pig="", dig=icp.said, fn=0, eilk="icp", keys=multi_keys,
              eevt=icp_ee, sith=["1/2", "1/2", "1/2"], ndigs=multi_digs, nsith=[["1/2", "1/2"], ["1"]]),
        build("delegated_with_traits", pre=pre, sn=0, pig="", dig=icp.said, fn=0, eilk="dip", keys=keys,
              eevt=icp_ee, ndigs=ndigs, cnfg=["EO", "DND"], dpre=delegator),
        build("abandoned", pre=pre, sn=1, pig=icp.said, dig=rot.said, fn=1, eilk="rot",
              keys=[nexts[0].verfer.qb64], eevt=StateEstEvent(s="1", d=rot.said, br=[], ba=[])),
        build("large_numbers", pre=pre, sn=2**64, pig=rot.said, dig=ixn.said, fn=300, eilk="ixn",
              keys=[nexts[0].verfer.qb64], eevt=StateEstEvent(s="ffff", d=rot.said, br=[], ba=[]),
              ndigs=[digest(nexts[1].verfer)]),
    ]

    cases = [{
        "name": name,
        "inputs": inputs,
        "record_json": compact(asdict(record)),
    } for name, inputs, record in built]

    records = {name: record for name, _, record in built}

    # A key state as a witness sends it: the `a` block of a `/ksn/{witness}` reply.
    reply = eventing.reply(route=f"/ksn/{witnesses[1]}", data=asdict(records["interaction_after_rotation"]),
                           stamp=STAMP)
    ksn_reply = {"route": f"/ksn/{witnesses[1]}", "raw": reply.raw.decode(), "raw_hex": reply.raw.hex()}

    # diffState over the records above, local first.
    def diff(name, local, reported):
        result = diffState(witnesses[1], records[local], records[reported])
        return {"name": name, "local": local, "reported": reported, "state": str(result.state),
                "sequence_number": result.sn, "said": result.dig}

    duplicitous = eventing.state(pre=pre, sn=0, pig="", dig=rot.said, fn=0, eilk="icp", keys=keys, eevt=icp_ee,
                                 stamp=STAMP, ndigs=ndigs)
    records["inception_forked"] = duplicitous
    cases.append({"name": "inception_forked", "inputs": None, "record_json": compact(asdict(duplicitous))})
    stranger = eventing.state(pre=delegator, sn=0, pig="", dig=icp.said, fn=0, eilk="icp", keys=keys,
                              eevt=icp_ee, stamp=STAMP, ndigs=ndigs)
    records["other_identifier"] = stranger
    cases.append({"name": "other_identifier", "inputs": None, "record_json": compact(asdict(stranger))})

    comparisons = [
        diff("even", "inception_defaults", "inception_witnessed"),
        diff("duplicitous", "inception_defaults", "inception_forked"),
        diff("ahead", "inception_defaults", "rotation_with_cuts_and_adds"),
        diff("behind", "interaction_after_rotation", "rotation_with_cuts_and_adds"),
    ]
    try:
        diffState(witnesses[1], records["inception_defaults"], stranger)
    except ValueError as error:
        mismatch = {"local": "inception_defaults", "reported": "other_identifier",
                    "reference_error_category": type(error).__name__, "reference_error_message": str(error),
                    "rust_error_category": "IdentifierMismatch"}
    else:
        raise AssertionError("diffState accepted records of different identifiers")

    base = dict(pre=pre, sn=0, pig="", dig=icp.said, fn=0, eilk="icp", keys=keys, eevt=icp_ee, ndigs=ndigs)
    rejected_cases = [
        rejected("receipt_as_latest_event", "InvalidLatestEventKind", **{**base, "eilk": "rct"}),
        rejected("zero_signing_threshold", "SigningThresholdIsZero", **base, sith="0"),
        rejected("signing_threshold_above_keys", "SigningThresholdExceedsKeys", **base, sith="2"),
        rejected("next_threshold_above_digests", "NextThresholdExceedsDigests", **base, nsith="2"),
        rejected("duplicate_witness", "DuplicateWitness", **base, wits=[witnesses[0], witnesses[0]], toad=1),
        rejected("zero_witness_threshold_with_witnesses", "InvalidWitnessThreshold", **base, wits=witnesses[:3],
                 toad=0),
        rejected("witness_threshold_above_witnesses", "InvalidWitnessThreshold", **base, wits=witnesses[:3], toad=4),
        rejected("witness_threshold_without_witnesses", "InvalidWitnessThreshold", **base, toad=1),
        rejected("duplicate_cut", "DuplicateWitness",
                 **{**base, "eevt": StateEstEvent(s="0", d=icp.said, br=[witnesses[0], witnesses[0]], ba=[])}),
        rejected("duplicate_add", "DuplicateWitness",
                 **{**base, "eevt": StateEstEvent(s="0", d=icp.said, br=[], ba=[witnesses[0], witnesses[0]])}),
        rejected("cut_and_added", "ConflictingWitnessLists",
                 **{**base, "eevt": StateEstEvent(s="0", d=icp.said, br=[witnesses[0]], ba=[witnesses[0]])}),
    ]

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/eventing.py", "src/keri/db/basing.py", "src/keri/app/watching.py"],
        "timestamp": STAMP,
        "field_labels": list(asdict(records["inception_defaults"]).keys()),
        "establishment_labels": list(asdict(records["inception_defaults"])["ee"].keys()),
        "cases": cases,
        "ksn_reply": ksn_reply,
        "comparisons": comparisons,
        "comparison_of_different_identifiers": mismatch,
        "rejected_cases": rejected_cases,
        "reference_quirk_unreachable_ample_default": {
            "witnesses": 4,
            "keripy_default": int(records["inception_default_witness_threshold"].bt, 16),
            "note": "keripy's `state` assigns a simple-majority default to `toad` and then tests `toad is"
                    " None` again to fall back to `ample`, which can therefore never run. The reachable"
                    " default is reproduced: a majority, so two of four witnesses where `ample` would"
                    " give three.",
        },
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "key-state-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("key-state-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
