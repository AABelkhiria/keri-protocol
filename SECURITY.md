# Security Policy

## Supported versions

Security fixes go to the latest `0.x` release. Older `0.x` versions are not patched.

## Reporting a vulnerability

Please don't open a public issue for something you think is exploitable.

Use GitHub's [private vulnerability reporting][gh-pvr] on this repository instead: *Security* →
*Report a vulnerability*.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

Useful things to include: the version and platform you were using, something we can run to
reproduce it, and what you think the impact is. If secret material was involved, say so, but please
generate throwaway keys for the report. Never send real seeds, salts, private keys or passcodes.

## Threat model

Everything parsed from outside is assumed hostile: serialized messages and their version strings,
self-addressing data as JSON, SAIDs and identifier prefixes as qualified Base64, signing-threshold
text and JSON, timestamps, event-kind codes, routes, labels, and the sizes and counts any of them
declare.

This crate holds no secret material. Builders take public keys, digests and finished signatures;
signing stays with the caller and keri-cesr's `Signer`.

Given that, the implementation is built to hold up against a few specific things.

Malformed input shouldn't be able to panic or abort the process, so crate-owned code contains no
`unsafe`, `unwrap`, `expect`, panicking macro, or indexing that can fail, and every rejection is a
typed error. Length and sequence-number arithmetic is checked, and every parser enforces an
explicit ceiling (for example `MAX_SERIALIZED_BYTES`, `MAX_NESTING_DEPTH`,
`MAX_THRESHOLD_EXPRESSION_BYTES`, `MAX_THRESHOLD_WEIGHTS` and `MAX_BACKERS`) before it allocates
from a size the input declares.

Serialization is deterministic and strict: field order is the protocol's, the accepted JSON value
space is narrower than RFC 8259 so that byte parity is provable, version strings are recomputed
from the final bytes, and a message whose declared size, SAID or prefix does not match its bytes is
rejected rather than repaired. Thresholds are exact rationals; no floating point touches a protocol
value.

Where signify-ts and keripy disagree, or where signify-ts emits a structurally invalid message, the
unsafe behavior is refused and the refusal is pinned by a fixture rather than reproduced.

## Randomness

This crate takes no entropy and reads no clock. Nonces and timestamps are parameters, so every
message is reproducible from its inputs.

## Known limitations

This is a builder and verifier of individual messages, not a validator of logs. It does not accept
events into a key event log, derive key state, check witness receipts against a threshold, or
decide whether a delegation is approved. A verifier that trusts a message because its SAID and
prefix check out, without validating the log it belongs to, has not validated it.

Interoperability is pinned to signify-ts for everything it can emit and to keripy for the witness
and receipt attachment groups it cannot. Other implementations have not been tested against.

## Dependencies

The production dependencies are `keri-cesr`, with its `crypto` feature, written and maintained by
this crate's author, and `serde_json` with default features off. `cargo deny` and the resolved
graph get reviewed before each release.
