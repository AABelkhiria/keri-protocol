//! Property and invalid-near-miss coverage for key state records and their comparison.

use keri_cesr::crypto::digest::Digest;
use keri_cesr::crypto::verifier::VerificationKey;
use keri_protocol::event::EventError;
use keri_protocol::event::key_state::{
    FIELD_LABELS, KeyStateBuilder, KeyStateRecord, LatestEstablishment, StateComparison, compare,
};
use keri_protocol::event::kind::EventKind;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::Sad;
use keri_protocol::threshold::SigningThreshold;
use proptest::{prelude::*, test_runner::TestCaseError};

const STAMP: &str = "2021-01-01T00:00:00.000000+00:00";
const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
const OTHER_SAID: &str = "EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W";
const KEYS: [&str; 2] = [
    "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH",
    "DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ",
];
const WITNESSES: [&str; 3] = [
    "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",
    "BCmsuuFBvMrwsi4alNNNC8c2HlJtC_4SyJeUvJMilm3X",
    "BB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ",
];

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn kind_strategy() -> impl Strategy<Value = EventKind> {
    prop_oneof![
        Just(EventKind::Inception),
        Just(EventKind::Rotation),
        Just(EventKind::Interaction),
        Just(EventKind::DelegatedInception),
        Just(EventKind::DelegatedRotation),
    ]
}

fn record(
    sequence_number: u128,
    said: &str,
    kind: EventKind,
    keys: usize,
    witnesses: usize,
) -> Result<KeyStateRecord, TestCaseError> {
    let keys = KEYS
        .iter()
        .take(keys)
        .map(|key| VerificationKey::from_qb64(key))
        .collect::<Result<Vec<_>, _>>();
    let witnesses = WITNESSES
        .iter()
        .take(witnesses)
        .map(|witness| IdentifierPrefix::from_qb64(witness))
        .collect::<Result<Vec<_>, _>>();
    fail(
        KeyStateBuilder::new(
            fail(IdentifierPrefix::from_qb64(IDENTIFIER))?,
            sequence_number,
            fail(Said::from_qb64(said))?,
            kind,
            fail(Timestamp::parse(STAMP))?,
            fail(keys)?,
            LatestEstablishment::new(0, fail(Said::from_qb64(IDENTIFIER))?),
        )
        .next_digests(vec![fail(Digest::from_qb64(OTHER_SAID))?])
        .witnesses(fail(witnesses)?)
        .first_seen(sequence_number)
        .build(),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(160))]

    /// Every record the builder accepts writes the protocol field order and reads back into
    /// itself, and its defaults are the ones keripy applies.
    #[test]
    fn a_record_reads_back_into_itself(
        sequence_number in any::<u128>(),
        kind in kind_strategy(),
        keys in 1_usize..=2,
        witnesses in 0_usize..=3,
    ) {
        let built = record(sequence_number, IDENTIFIER, kind, keys, witnesses)?;
        let map = fail(built.to_sad())?;
        let labels: Vec<&str> = map.entries().map(|(label, _)| label).collect();
        prop_assert_eq!(labels, FIELD_LABELS);
        let bytes = fail(map.to_json_bytes())?;
        let read = fail(KeyStateRecord::from_sad(&fail(Sad::from_json_bytes(&bytes))?))?;
        prop_assert_eq!(&read, &built);

        let expected_signing = u128::try_from(keys).map_or(1, |count| count.div_ceil(2).max(1));
        prop_assert_eq!(built.signing_threshold().numeric_value(), Some(expected_signing));
        let expected_witness = u32::try_from(witnesses).map_or(0, |count| count.div_ceil(2));
        prop_assert_eq!(built.witness_threshold(), expected_witness);
    }

    /// The comparison is decided by sequence number first and SAID second, and is antisymmetric:
    /// swapping the two records swaps ahead and behind and keeps even and duplicitous.
    #[test]
    fn comparison_is_antisymmetric(local in 0_u128..8, reported in 0_u128..8, fork in any::<bool>()) {
        let local_record = record(local, IDENTIFIER, EventKind::Interaction, 1, 0)?;
        let reported_record = record(reported, if fork { OTHER_SAID } else { IDENTIFIER }, EventKind::Interaction, 1, 0)?;
        let forward = fail(compare(&local_record, &reported_record))?.comparison();
        let backward = fail(compare(&reported_record, &local_record))?.comparison();
        let expected = match local.cmp(&reported) {
            core::cmp::Ordering::Less => StateComparison::Ahead,
            core::cmp::Ordering::Greater => StateComparison::Behind,
            core::cmp::Ordering::Equal if fork => StateComparison::Duplicitous,
            core::cmp::Ordering::Equal => StateComparison::Even,
        };
        prop_assert_eq!(forward, expected);
        let mirrored = match expected {
            StateComparison::Ahead => StateComparison::Behind,
            StateComparison::Behind => StateComparison::Ahead,
            other => other,
        };
        prop_assert_eq!(backward, mirrored);
    }

    /// A signing threshold above the key count, or a witness threshold outside what the set
    /// allows, is refused however the rest of the record looks.
    #[test]
    fn unsatisfiable_thresholds_are_refused(extra in 1_u128..=8, witness_threshold in 0_u32..=6, witnesses in 0_usize..=3) {
        let keys = vec![fail(VerificationKey::from_qb64(KEYS[0]))?];
        let start = || -> Result<KeyStateBuilder, TestCaseError> {
            Ok(KeyStateBuilder::new(
                fail(IdentifierPrefix::from_qb64(IDENTIFIER))?,
                0,
                fail(Said::from_qb64(IDENTIFIER))?,
                EventKind::Inception,
                fail(Timestamp::parse(STAMP))?,
                keys.clone(),
                LatestEstablishment::new(0, fail(Said::from_qb64(IDENTIFIER))?),
            ))
        };
        let refused = matches!(
            start()?.signing_threshold(SigningThreshold::numeric(1 + extra)).build(),
            Err(EventError::SigningThresholdExceedsKeys { .. })
        );
        prop_assert!(refused, "a threshold above the key count was accepted");

        let witness_list = WITNESSES
            .iter()
            .take(witnesses)
            .map(|witness| IdentifierPrefix::from_qb64(witness))
            .collect::<Result<Vec<_>, _>>();
        let result = start()?.witnesses(fail(witness_list)?).witness_threshold(witness_threshold).build();
        let count = u32::try_from(witnesses).unwrap_or(u32::MAX);
        let fits = if count == 0 { witness_threshold == 0 } else { (1..=count).contains(&witness_threshold) };
        prop_assert_eq!(result.is_ok(), fits);
    }
}
