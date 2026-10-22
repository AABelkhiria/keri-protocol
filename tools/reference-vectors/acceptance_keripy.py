"""Generates and checks best-available-data acceptance vectors from the pinned keripy.

signify-ts never decides whether a reply replaces an older one; KERIA does. ``src/event/reply/
acceptance.rs`` is therefore verified against keripy's ``Revery.acceptReply``, run unmodified over
a real, temporary keripy database holding real identifiers. Only ``escrowReply`` is intercepted, to
record that keripy escrowed instead of storing. keripy is pinned in ``pyproject.toml`` and
``uv.lock`` beside this file; run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/acceptance_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import json
import pathlib
import sys

from keri.app import habbing
from keri.core import eventing, routing, serdering
from keri.core.coring import MtrDex, Prefixer, Saider, Seqner
from keri.core.eventing import SealEvent
from keri.core.signing import Salter, Signer

from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-22"
STAMPS = ["2021-01-01T00:00:00.000000+00:00", "2021-01-01T00:00:01.000000+00:00", "2021-01-01T00:00:02.000000+00:00"]
SALT = Salter(raw=b"0123456789abcdef").qb64


class Recording(routing.Revery):
    """keripy's Revery, recording an escrow instead of writing one."""

    def __init__(self, db):
        super().__init__(db=db)
        self.escrowed = False

    def escrowReply(self, **kwa):
        self.escrowed = True


class Signed:
    """One reply with the signatures keripy's `acceptReply` takes and the bytes they travel as."""

    def __init__(self, serder, *, cigars=None, tsg=None):
        self.serder = serder
        self.cigars = cigars or []
        self.tsgs = [tsg] if tsg else []
        if tsg:
            prefixer, seqner, saider, sigers = tsg
            message = eventing.messagize(serder, sigers=sigers,
                                         seal=SealEvent(i=prefixer.qb64, s=seqner.snh, d=saider.qb64))
        else:
            message = eventing.messagize(serder, cigars=self.cigars)
        self.raw = bytes(message)

    def record(self):
        return {
            "raw": self.raw.decode(),
            "raw_hex": self.raw.hex(),
            "timestamp": self.serder.ked["dt"],
            "establishment": self.tsgs[0][1].sn if self.tsgs else None,
        }


def location(authority, url, stamp):
    return eventing.reply(route="/loc/scheme", data={"eid": authority, "scheme": "http", "url": url}, stamp=stamp)


def by_hab(hab, serder, *, sn=None, said=None, sign_over=None, sigers=None):
    """Signs `serder` with `hab`'s current keys, naming its establishment event unless overridden."""
    kever = hab.kever
    sigers = sigers if sigers is not None else hab.sign(ser=(sign_over or serder).raw, indexed=True)
    tsg = (Prefixer(qb64=hab.pre), Seqner(sn=kever.lastEst.s if sn is None else sn),
           Saider(qb64=kever.lastEst.d if said is None else said), sigers)
    return Signed(serder, tsg=tsg)


def by_key(signer, serder, *, sign_over=None):
    return Signed(serder, cigars=[signer.sign(ser=(sign_over or serder).raw)])


def main():
    with habbing.openHby(name="acceptance", temp=True, salt=SALT) as hby:
        single = hby.makeHab(name="single", icount=1, isith="1", ncount=1, nsith="1", transferable=True)
        double = hby.makeHab(name="double", icount=2, isith="2", ncount=2, nsith="2", transferable=True)
        witness = Signer(raw=bytes(range(0, 32)), code=MtrDex.Ed25519_Seed, transferable=False)
        stranger = Signer(raw=bytes(range(32, 64)), code=MtrDex.Ed25519_Seed, transferable=False)
        pre, wit = single.pre, witness.verfer.qb64

        # Replies signed at the inception (sequence number 0).
        icp_said = single.kever.lastEst.d
        t0_sn0 = by_hab(single, location(pre, "http://a/", STAMPS[0]))
        t1_sn0 = by_hab(single, location(pre, "http://b/", STAMPS[1]))
        t1_sn0_other = by_hab(single, location(pre, "http://c/", STAMPS[1]))
        t2_sn0 = by_hab(single, location(pre, "http://d/", STAMPS[2]))
        bad_signature = by_hab(single, location(pre, "http://e/", STAMPS[1]),
                               sign_over=location(pre, "http://f/", STAMPS[1]))
        sigers = single.sign(ser=location(pre, "http://g/", STAMPS[1]).raw, indexed=True, indices=[5])
        index_out_of_range = by_hab(single, location(pre, "http://g/", STAMPS[1]), sigers=sigers)

        single.rotate()
        rot_said = single.kever.lastEst.d
        t0_sn1 = by_hab(single, location(pre, "http://h/", STAMPS[0]))
        unknown_event = by_hab(single, location(pre, "http://i/", STAMPS[1]), sn=9, said=rot_said)
        mismatched_said = by_hab(single, location(pre, "http://j/", STAMPS[1]), sn=0, said=rot_said)
        single.interact()
        ixn_said = single.kever.serder.said
        interaction = by_hab(single, location(pre, "http://k/", STAMPS[1]), sn=2, said=ixn_said)

        not_authority = by_hab(double, location(pre, "http://l/", STAMPS[1]))
        both = double.sign(ser=location(double.pre, "http://m/", STAMPS[1]).raw, indexed=True)
        below_threshold = by_hab(double, location(double.pre, "http://m/", STAMPS[1]), sigers=both[:1])
        full_threshold = by_hab(double, location(double.pre, "http://m/", STAMPS[1]), sigers=both)

        k_t0 = by_key(witness, location(wit, "http://o/", STAMPS[0]))
        k_t1 = by_key(witness, location(wit, "http://p/", STAMPS[1]))
        k_t1_other = by_key(witness, location(wit, "http://q/", STAMPS[1]))
        k_stranger = by_key(stranger, location(wit, "http://r/", STAMPS[1]))
        k_bad = by_key(witness, location(wit, "http://s/", STAMPS[1]), sign_over=location(wit, "http://t/", STAMPS[1]))

        def decide(name, authority, new, prior=None, rust_outcome=None, rust_error_category=None):
            revery = Recording(db=hby.db)
            osaider = None
            if prior is not None:
                if not revery.acceptReply(serder=prior.serder, saider=Saider(qb64=prior.serder.said),
                                          route="/loc/scheme", aid=authority, cigars=prior.cigars, tsgs=prior.tsgs):
                    raise AssertionError(f"case {name}: keripy refused the prior reply")
                osaider = Saider(qb64=prior.serder.said)
                revery = Recording(db=hby.db)
            case = {"name": name, "authority": authority, "prior": prior.record() if prior else None,
                    "new": new.record(), "rust_outcome": rust_outcome, "rust_error_category": rust_error_category}
            try:
                accepted = revery.acceptReply(serder=new.serder, saider=Saider(qb64=new.serder.said),
                                              route="/loc/scheme", aid=authority, osaider=osaider,
                                              cigars=new.cigars, tsgs=new.tsgs)
                case["keripy"] = {"accepted": accepted, "escrowed": revery.escrowed}
            except Exception as error:  # noqa: BLE001 - the error class is the datum being recorded
                case["keripy"] = {"error_category": type(error).__name__, "error_message": str(error)}
            return case

        cases = [
            decide("transferable_first", pre, t1_sn0, rust_outcome="Accepted"),
            decide("transferable_same_event_later", pre, t1_sn0, prior=t0_sn0, rust_outcome="Accepted"),
            decide("transferable_same_event_same_time", pre, t1_sn0_other, prior=t1_sn0, rust_outcome="Stale"),
            decide("transferable_same_event_earlier", pre, t0_sn0, prior=t1_sn0, rust_outcome="Stale"),
            decide("transferable_later_event_earlier_time", pre, t0_sn1, prior=t2_sn0, rust_outcome="Accepted"),
            decide("transferable_earlier_event_later_time", pre, t2_sn0, prior=t0_sn1, rust_outcome="Stale"),
            decide("transferable_unknown_event", pre, unknown_event, rust_outcome="MissingEstablishment"),
            decide("transferable_not_authority", pre, not_authority, rust_outcome="NotFromAuthority"),
            decide("transferable_below_threshold", double.pre, below_threshold, rust_outcome="BelowThreshold"),
            decide("transferable_full_threshold", double.pre, full_threshold, rust_outcome="Accepted"),
            decide("transferable_mismatched_said", pre, mismatched_said, rust_error_category="SignatureGroupMismatch"),
            decide("transferable_interaction_event", pre, interaction, rust_error_category="NoSigningKeys"),
            decide("transferable_bad_signature", pre, bad_signature, rust_error_category="NoVerifiedSignatures"),
            decide("non_transferable_first", wit, k_t1, rust_outcome="Accepted"),
            decide("non_transferable_later", wit, k_t1, prior=k_t0, rust_outcome="Accepted"),
            decide("non_transferable_same_time", wit, k_t1_other, prior=k_t1, rust_outcome="Stale"),
            decide("non_transferable_earlier", wit, k_t0, prior=k_t1, rust_outcome="Stale"),
            decide("non_transferable_not_authority", wit, k_stranger, rust_outcome="NotFromAuthority"),
            decide("non_transferable_bad_signature", wit, k_bad, rust_outcome="InvalidSignature"),
        ]
        quirk = decide("index_out_of_range", pre, index_out_of_range, rust_error_category="NoVerifiedSignatures")

        events = []
        for hab in (single, double):
            for message in hby.db.clonePreIter(pre=hab.pre):
                serder = serdering.SerderKERI(raw=bytes(message))
                events.append({"identifier": hab.pre, "sequence_number": serder.sn, "said": serder.said,
                               "raw": bytes(message)[:serder.size].decode()})

        fixture = {
            "schema_version": 1,
            "upstream": "https://github.com/WebOfTrust/keripy.git",
            "reference_sha": REFERENCE_SHA,
            "reference_version": REFERENCE_VERSION,
            "generated_on": GENERATED_ON,
            "sources": ["src/keri/core/routing.py", "src/keri/core/eventing.py"],
            "signer_events": events,
            "inception_said": icp_said,
            "cases": cases,
            "reference_quirk_index_out_of_range": {
                **quirk,
                "note": "keripy's `verifySigs` logs an index past the end of the key list and then indexes the"
                        " list with it anyway, so `acceptReply` raises `IndexError`. The Rust port skips the"
                        " signature; with no other signature in the group, nothing verifies.",
            },
        }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "acceptance-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("acceptance-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
