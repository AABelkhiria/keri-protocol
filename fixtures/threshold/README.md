# KERI signing-threshold reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-09
- Sources: `src/keri/core/tholder.ts`, `test/core/tholder.test.ts`
- Binary fields: lowercase hexadecimal; `limen_hex` is the UTF-8 byte encoding of reference-produced
  numeric CESR qualified Base64.

Generate from the repository root:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/threshold.mjs
```

The successful cases cover every form and satisfaction pattern in the pinned unit test, plus zero
numeric thresholds, exact decimal normalization, zero weights, and numeric limen output. Rust tests
consume the checked-in fixture and require neither Node nor network access.

The reference uses MathJS fractions but converts clause sums and satisfaction weights to JavaScript
numbers. Rust stores reduced `u128` rationals and performs checked exact addition. Individual KERI
weights are restricted to the protocol range `0..=1`; the reference accepts negative and
greater-than-one weights, which are recorded as unsafe compatibility divergences. Rust also rejects
partial hexadecimal parsing and out-of-range signature indices. The pinned reference emits numeric
limen but cannot reconstruct `Tholder` from its own output because its `CesrNumber` raw constructor
rejects; Rust safely completes strict numeric limen parsing. Weighted Bexter-backed limen remains
unimplemented in both ports.
