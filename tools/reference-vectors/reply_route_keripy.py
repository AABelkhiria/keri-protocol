"""Generates and checks reply-route vectors from the pinned keripy.

signify-ts builds replies but never reads one: KERIA routes them. ``src/event/reply/route.rs`` is
therefore verified against keripy's own path for an incoming reply: ``Revery.processReply`` checks
the SAID, the ``Router`` matches the route against the templates ``Kevery.registerReplyRoutes``
registers, and the matching ``Kevery.processReply…`` handler checks the attributes. Those three
run unmodified; only the storage they write to and best-available-data acceptance, which this
module does not port, are replaced by recorders. keripy is pinned in ``pyproject.toml`` and
``uv.lock`` beside this file; run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/reply_route_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import json
import pathlib
import sys
from dataclasses import asdict
from types import SimpleNamespace

from keri import kering
from keri.core import eventing, routing, serdering
from keri.core.coring import Diger, MtrDex
from keri.core.eventing import StateEstEvent
from keri.core.signing import Signer

from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-22"
STAMP = "2021-01-01T00:00:00.000000+00:00"


class Table:
    """Stands in for one keripy database table: empty, and remembers nothing."""

    def get(self, keys):
        return None

    def pin(self, keys, val):
        return True

    def getLast(self, keys, on=0):
        return None

    def getTopItemIter(self, keys=b""):
        return iter(())

    def getItemIter(self, keys=b""):
        return iter(())


class Handlers:
    """keripy's `Kevery` reply handlers, run unmodified over recording storage."""

    processReplyEndRole = eventing.Kevery.processReplyEndRole
    processReplyLocScheme = eventing.Kevery.processReplyLocScheme
    processReplyKeyStateNotice = eventing.Kevery.processReplyKeyStateNotice
    processReplyAddWatched = eventing.Kevery.processReplyAddWatched

    def __init__(self):
        self.outcome = None
        self.lax = True
        self.kevers = {}
        self.cues = SimpleNamespace(push=lambda cue: None)
        self.db = SimpleNamespace(eans=Table(), lans=Table(), knas=Table(), kels=Table(), wwas=Table(),
                                  habs=Table(), oobis=SimpleNamespace(pin=self.pin_oobi),
                                  getKeLast=lambda key: None)
        self.rvy = SimpleNamespace(acceptReply=lambda **kwa: True)
        self.oobi = None

    def pin_oobi(self, keys, val):
        self.oobi = keys[0]

    def updateEnd(self, keys, saider, allowed=None):
        self.outcome = {"handler": "end_role", "keys": list(keys), "allowed": allowed}

    def updateLoc(self, keys, saider, url):
        self.outcome = {"handler": "loc_scheme", "keys": list(keys), "url": url}

    def updateKeyState(self, aid, ksr, saider, dater):
        self.outcome = {"handler": "key_state_notice", "source": aid, "identifier": ksr.i, "said": ksr.d}

    def updateWatched(self, keys, saider, enabled=None):
        self.outcome = {"handler": "add_watched", "keys": list(keys), "enabled": enabled, "oobi": self.oobi}


def process(serder):
    """Runs one reply through keripy's `Revery.processReply` and returns what the handler stored."""
    handlers = Handlers()
    router = routing.Router()
    eventing.Kevery.registerReplyRoutes(handlers, router)
    routing.Revery.processReply(SimpleNamespace(rtr=router), serder, cigars=[], tsgs=[])
    if handlers.outcome is None:
        raise AssertionError("keripy accepted a reply without storing anything")
    return handlers.outcome


def reply(route, data):
    return eventing.reply(route=route, data=data, stamp=STAMP)


def case(name, route, data):
    serder = reply(route, data)
    return {
        "name": name,
        "route": route,
        "attributes_json": json.dumps(data, separators=(",", ":")),
        "said": serder.said,
        "raw": serder.raw.decode(),
        "raw_hex": serder.raw.hex(),
        "keripy_outcome": process(serder),
    }


def rejected_case(name, raw, rust_error_category):
    try:
        process(serdering.SerderKERI(raw=raw, verify=False))
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
    controller = Signer(raw=bytes(range(0, 32)), code=MtrDex.Ed25519_Seed, transferable=True)
    witness = Signer(raw=bytes(range(32, 64)), code=MtrDex.Ed25519_Seed, transferable=False).verfer.qb64
    watcher = Signer(raw=bytes(range(64, 96)), code=MtrDex.Ed25519_Seed, transferable=False).verfer.qb64
    nxt = Signer(raw=bytes(range(96, 128)), code=MtrDex.Ed25519_Seed, transferable=True)
    icp = eventing.incept(keys=[controller.verfer.qb64], ndigs=[Diger(ser=nxt.verfer.qb64b).qb64],
                          wits=[witness], toad=1, code=MtrDex.Blake3_256)
    cid = icp.pre
    state = eventing.state(pre=cid, sn=0, pig="", dig=icp.said, fn=0, eilk="icp", keys=[controller.verfer.qb64],
                           eevt=StateEstEvent(s="0", d=icp.said, br=[], ba=[]), stamp=STAMP,
                           ndigs=[Diger(ser=nxt.verfer.qb64b).qb64], wits=[witness], toad=1)

    cases = [
        case("end_role_add_watcher", "/end/role/add", {"cid": cid, "role": "watcher", "eid": watcher}),
        case("end_role_cut_witness", "/end/role/cut", {"cid": cid, "role": "witness", "eid": witness}),
        case("loc_scheme_http", "/loc/scheme", {"eid": witness, "scheme": "http", "url": "http://127.0.0.1:5642/"}),
        case("loc_scheme_https_uppercase_url", "/loc/scheme",
             {"eid": witness, "scheme": "https", "url": "HTTPS://witness.example.org/"}),
        case("loc_scheme_without_url_scheme", "/loc/scheme",
             {"eid": witness, "scheme": "tcp", "url": "//127.0.0.1:5632"}),
        case("loc_scheme_withdrawn", "/loc/scheme", {"eid": witness, "scheme": "http", "url": ""}),
        case("key_state_notice", f"/ksn/{witness}", asdict(state)),
        case("watcher_add_with_oobi", f"/watcher/{watcher}/add",
             {"cid": cid, "oid": cid, "oobi": f"http://127.0.0.1:5642/oobi/{cid}/witness/{witness}"}),
        case("watcher_cut", f"/watcher/{watcher}/cut", {"cid": cid, "oid": cid}),
    ]

    def raw(route, data):
        return reply(route, data).raw

    end_role = {"cid": cid, "role": "watcher", "eid": watcher}
    tampered = raw("/end/role/add", end_role)
    said = reply("/end/role/add", end_role).said.encode()
    rejected = [
        rejected_case("tampered_said", tampered.replace(said, said[:-4] + b"AAAA"), "Said"),
        rejected_case("unknown_route", raw("/end/roles/add", end_role), "UnknownReplyRoute"),
        rejected_case("unknown_end_role_action", raw("/end/role/drop", end_role), "UnknownReplyRoute"),
        rejected_case("uppercase_route", raw("/END/ROLE/add", end_role), "UnknownReplyRoute"),
        rejected_case("trailing_slash", raw("/loc/scheme/", {"eid": witness, "scheme": "http", "url": ""}),
                      "UnknownReplyRoute"),
        rejected_case("unknown_watcher_action", raw(f"/watcher/{watcher}/drop", {"cid": cid, "oid": cid}),
                      "UnknownReplyRoute"),
        rejected_case("end_role_without_endpoint", raw("/end/role/add", {"cid": cid, "role": "watcher"}),
                      "MissingAttribute"),
        rejected_case("capitalised_role", raw("/end/role/add", {**end_role, "role": "Watcher"}), "UnknownRole"),
        rejected_case("unknown_scheme", raw("/loc/scheme", {"eid": witness, "scheme": "ftp", "url": ""}),
                      "UnknownScheme"),
        rejected_case("url_with_another_scheme",
                      raw("/loc/scheme", {"eid": witness, "scheme": "http", "url": "https://x/"}), "UrlSchemeMismatch"),
        rejected_case("host_and_port_without_scheme",
                      raw("/loc/scheme", {"eid": witness, "scheme": "http", "url": "localhost:5642"}),
                      "UrlSchemeMismatch"),
    ]

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/eventing.py", "src/keri/core/routing.py", "src/keri/kering.py"],
        "timestamp": STAMP,
        "roles": list(kering.Roles),
        "schemes": list(kering.Schemes),
        "cases": cases,
        "rejected_cases": rejected,
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "reply-route-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("reply-route-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
