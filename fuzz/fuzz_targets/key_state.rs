#![no_main]
#![forbid(unsafe_code)]

use keri_protocol::event::key_state::{KeyStateRecord, compare};
use keri_protocol::serialization::Sad;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A key state arrives from a witness, a watcher or KERIA: anything the reader accepts must write
    // a map that reads back to the same record, and compare even against itself. The written map
    // need not equal the input: hexadecimal fields are accepted with leading zeros, as keripy
    // accepts them, and written canonically.
    if let Ok(map) = Sad::from_json_bytes(data) {
        if let Ok(record) = KeyStateRecord::from_sad(&map) {
            match record.to_sad() {
                Ok(written) => {
                    assert_eq!(
                        KeyStateRecord::from_sad(&written).ok().as_ref(),
                        Some(&record),
                        "a written key state did not read back"
                    );
                }
                Err(error) => panic!("a read key state failed to write: {error}"),
            }
            match compare(&record, &record) {
                Ok(difference) => assert_eq!(
                    difference.sequence_number(),
                    record.sequence_number(),
                    "a key state compared against itself reported another sequence number"
                ),
                Err(error) => panic!("a key state could not be compared with itself: {error}"),
            }
        }
    }
});
