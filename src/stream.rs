//! Inbound KERI message streams.
//!
//! A message travels as its serialized event followed by its CESR attachments, and a stream is one
//! or more messages back to back. [`attachment`](crate::attachment) composes the attachment half of
//! an outgoing message; this module is its inverse for incoming ones. [`Message::parse`] reads one
//! message off the front of a stream, [`Attachments::parse`] reads the counted groups behind an
//! event into typed signatures, couples and seals, and [`parse_stream`] walks a whole stream.
//!
//! This ports `msgParsator` from keripy's `src/keri/core/parsing.py`, the canonical KERI
//! implementation, for the text domain of the KERI v1 count codes. The pinned signify-ts reference
//! has no stream parser: it never receives a KERI stream because KERIA parses on its behalf, so
//! keripy is the reference here. Binary (`qb2`) attachment streams, which keripy also accepts,
//! are refused with [`StreamError::BinaryStreamUnsupported`].
//!
//! # Groups
//!
//! | Counter | Group | Elements per count |
//! |---|---|---|
//! | `-A` | controller indexed signatures | indexed signature |
//! | `-B` | witness indexed signatures | indexed signature |
//! | `-C` | non-transferable receipt couples | verification key, signature |
//! | `-D` | transferable receipt quadruples | prefix, sequence number, SAID, indexed signature |
//! | `-E` | first-seen replay couples | first-seen ordinal, datetime |
//! | `-F` | transferable indexed signature groups | prefix, sequence number, SAID, then a `-A` group |
//! | `-G` | seal source couples | sequence number, SAID |
//! | `-H` | transferable last-establishment signature groups | prefix, then a `-A` group |
//! | `-I` | seal source triples | prefix, sequence number, SAID |
//! | `-L` | pathed material | kept as raw bytes, sized in quadlets |
//! | `-V` | attachment group | frames every group above, sized in quadlets |
//!
//! Groups a key event log never carries, SAD path signature groups (`-J`, `-K`) and ESSR payloads
//! (`-Z`), are refused with [`StreamError::UnsupportedGroup`] rather than skipped: dropping a
//! signature group silently would turn a signed message into an unsigned one. Pathed material
//! (`-L`) belongs to exchange messages, whose embedded payloads are parsed by their own consumer,
//! and keripy keeps it opaque at this layer too.
//!
//! # Strictness
//!
//! A receipt couple whose key is transferable is rejected while parsing, as
//! [`ReceiptCouple::new`] rejects it while composing. keripy's parser accepts the couple and its
//! event processor rejects it one step later; the outcome is the same, the error arrives sooner.
//!
//! Nothing here verifies a signature or looks up key state. The parser establishes what a message
//! claims; a validator decides whether to believe it.

use core::fmt;
use std::error::Error;
use std::str::FromStr;

use keri_cesr::CesrError;
use keri_cesr::base64::encode_url_safe;
use keri_cesr::bytes::utf8_text;
use keri_cesr::counter::{Counter, CounterCode};
use keri_cesr::crypto::CryptoError;
use keri_cesr::crypto::signature::{IndexedSignature, UnindexedSignature};
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::matter::QualifiedMaterial;
use keri_cesr::sequence::SequenceNumber;

use crate::attachment::{AttachmentError, AttachmentFraming, ReceiptCouple, SealSourceCouple, SealSourceTriple};
use crate::event::{Timestamp, TimestampError};
use crate::prefix::{IdentifierPrefix, PrefixError};
use crate::said::{Said, SaidError};
use crate::serialization::{SerializationError, SerializedEvent, VersionError, VersionString};

/// The bytes every JSON message opens with, since the version field must come first.
const VERSION_FIELD_PREFIX: &[u8] = b"{\"v\":\"";
/// The CESR code of an ISO-8601 datetime primitive, keripy's `Dater`.
const DATETIME_CODE: &str = "1AAG";
/// Characters one quadlet of text-domain CESR occupies.
const QUADLET: usize = 4;
/// The longest count-code text an error carries back to the caller.
const MAX_REPORTED_CODE_CHARS: usize = 8;

const CONTROLLER_SIGNATURES: &str = CounterCode::CONTROLLER_INDEXED_SIGNATURES.as_str();
const WITNESS_SIGNATURES: &str = CounterCode::WITNESS_INDEXED_SIGNATURES.as_str();
const RECEIPT_COUPLES: &str = CounterCode::NON_TRANSFERABLE_RECEIPT_COUPLES.as_str();
const RECEIPT_QUADRUPLES: &str = CounterCode::TRANSFERABLE_RECEIPT_QUADRUPLES.as_str();
const FIRST_SEEN_COUPLES: &str = CounterCode::FIRST_SEEN_REPLAY_COUPLES.as_str();
const TRANSFERABLE_GROUPS: &str = CounterCode::TRANSFERABLE_INDEXED_SIGNATURE_GROUPS.as_str();
const SEAL_COUPLES: &str = CounterCode::SEAL_SOURCE_COUPLES.as_str();
const LAST_ESTABLISHMENT_GROUPS: &str = CounterCode::TRANSFERABLE_LAST_INDEXED_SIGNATURE_GROUPS.as_str();
const SEAL_TRIPLES: &str = CounterCode::SEAL_SOURCE_TRIPLES.as_str();
const PATHED_MATERIAL: &str = CounterCode::PATHED_MATERIAL_QUADLETS.as_str();
const ATTACHMENT_GROUP: &str = CounterCode::ATTACHED_MATERIAL_QUADLETS.as_str();

/// A transferable endorser's receipt of an event: who signed, from which establishment event, and
/// the indexed signature itself. One element of a `-D` group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptQuadruple {
    identifier: IdentifierPrefix,
    sequence_number: SequenceNumber,
    said: Said,
    signature: IndexedSignature,
}

impl ReceiptQuadruple {
    /// Builds a quadruple: `identifier`'s indexed `signature`, made with the keys of its
    /// establishment event at `sequence_number` with SAID `said`.
    #[must_use]
    pub const fn new(
        identifier: IdentifierPrefix,
        sequence_number: SequenceNumber,
        said: Said,
        signature: IndexedSignature,
    ) -> Self {
        Self {
            identifier,
            sequence_number,
            said,
            signature,
        }
    }

    /// Returns the endorser's identifier prefix.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns the sequence number of the endorser's establishment event whose keys signed.
    #[must_use]
    pub const fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number
    }

    /// Returns the SAID of that establishment event.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the endorser's indexed signature over the receipted event.
    #[must_use]
    pub const fn signature(&self) -> &IndexedSignature {
        &self.signature
    }
}

/// When an event was first seen by the party replaying it. One element of a `-E` group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstSeenReplayCouple {
    ordinal: SequenceNumber,
    timestamp: Timestamp,
}

impl FirstSeenReplayCouple {
    /// Builds a couple: the event was the `ordinal`th first seen, at `timestamp`.
    #[must_use]
    pub const fn new(ordinal: SequenceNumber, timestamp: Timestamp) -> Self {
        Self { ordinal, timestamp }
    }

    /// Returns the first-seen ordinal, the event's position in the replaying party's log.
    #[must_use]
    pub const fn ordinal(&self) -> SequenceNumber {
        self.ordinal
    }

    /// Returns the datetime the event was first seen.
    #[must_use]
    pub const fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }
}

/// A transferable signer's indexed signatures with the establishment event that authorises them.
/// One element of a `-F` group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferableSignatureGroup {
    identifier: IdentifierPrefix,
    sequence_number: SequenceNumber,
    said: Said,
    signatures: Vec<IndexedSignature>,
}

impl TransferableSignatureGroup {
    /// Returns the signer's identifier prefix.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns the sequence number of the establishment event whose keys signed.
    #[must_use]
    pub const fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number
    }

    /// Returns the SAID of that establishment event.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the indexed signatures, in attachment order.
    #[must_use]
    pub fn signatures(&self) -> &[IndexedSignature] {
        &self.signatures
    }
}

/// A transferable signer's indexed signatures, authorised by whatever its latest establishment
/// event is when the receiver verifies them. One element of a `-H` group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LastEstablishmentSignatureGroup {
    identifier: IdentifierPrefix,
    signatures: Vec<IndexedSignature>,
}

impl LastEstablishmentSignatureGroup {
    /// Returns the signer's identifier prefix.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns the indexed signatures, in attachment order.
    #[must_use]
    pub fn signatures(&self) -> &[IndexedSignature] {
        &self.signatures
    }
}

/// Every attachment group behind one message, typed, in the order the stream carried them within
/// each kind.
///
/// Groups of one kind may appear more than once in a stream; their elements are concatenated in
/// stream order, which is also what keripy does.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Attachments {
    raw: Vec<u8>,
    framing: AttachmentFraming,
    controller_signatures: Vec<IndexedSignature>,
    witness_signatures: Vec<IndexedSignature>,
    receipt_couples: Vec<ReceiptCouple>,
    receipt_quadruples: Vec<ReceiptQuadruple>,
    first_seen_replay_couples: Vec<FirstSeenReplayCouple>,
    transferable_signature_groups: Vec<TransferableSignatureGroup>,
    last_establishment_signature_groups: Vec<LastEstablishmentSignatureGroup>,
    seal_source_couples: Vec<SealSourceCouple>,
    seal_source_triples: Vec<SealSourceTriple>,
    pathed_material: Vec<Vec<u8>>,
}

impl Attachments {
    /// Parses the attachment groups at the front of `input`, stopping at the end of the input or
    /// where the next message begins.
    ///
    /// An input that starts with a message yields empty attachments and consumes nothing. A
    /// pipelined stream (`-V`) is read exactly to the end of its frame.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::Truncated`] when a group or its frame ends before its last element,
    /// [`StreamError::UnsupportedGroup`] for a count code this parser does not read,
    /// [`StreamError::UnexpectedGroup`] when a `-F` or `-H` group is not followed by a `-A` group,
    /// [`StreamError::BinaryStreamUnsupported`] for a binary-domain counter, and the wrapped
    /// primitive failures for malformed material inside a group.
    pub fn parse(input: &[u8]) -> Result<ParsedAttachments, StreamError> {
        match sniff(input) {
            Ok(_) | Err(StreamError::EmptyInput) => {}
            Err(error) => return Err(error),
        }
        let text = utf8_text(input).map_err(StreamError::cesr)?;
        let (attachments, consumed) = Self::parse_text(text)?;
        Ok(ParsedAttachments { attachments, consumed })
    }

    /// Parses `input` as exactly one run of attachment groups.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::TrailingMaterial`] when anything follows the groups, and otherwise
    /// the errors of [`Self::parse`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, StreamError> {
        let parsed = Self::parse(input)?;
        let length = input.len().saturating_sub(parsed.consumed);
        if length > 0 {
            return Err(StreamError::TrailingMaterial { length });
        }
        Ok(parsed.attachments)
    }

    fn parse_text(text: &str) -> Result<(Self, usize), StreamError> {
        let mut attachments = Self::default();
        match sniff(text.as_bytes()) {
            Ok(StreamStart::Message) | Err(StreamError::EmptyInput) => return Ok((attachments, 0)),
            Ok(StreamStart::Counter) => {}
            Err(error) => return Err(error),
        }

        let (counter, counter_length) = parse_counter(text)?;
        let consumed = if counter.code().as_str() == ATTACHMENT_GROUP {
            let frame_length = quadlets_to_chars(counter.count());
            let rest = tail(text, counter_length, "pipelined attachment group")?;
            let frame = rest.get(..frame_length).ok_or(StreamError::Truncated {
                context: "pipelined attachment group",
                available: rest.len(),
            })?;
            attachments.framing = AttachmentFraming::Pipelined;
            attachments.parse_groups(frame, true)?;
            counter_length + frame_length
        } else {
            attachments.parse_groups(text, false)?
        };
        attachments.raw = text.as_bytes().get(..consumed).unwrap_or_default().to_vec();
        Ok((attachments, consumed))
    }

    /// Parses counted groups from the front of `text` until it ends or, when not framed, until
    /// the next message starts. Returns how many characters were consumed.
    fn parse_groups(&mut self, text: &str, framed: bool) -> Result<usize, StreamError> {
        let mut cursor = 0;
        loop {
            let rest = tail(text, cursor, "attachment group")?;
            if rest.is_empty() || (!framed && rest.starts_with('{')) {
                return Ok(cursor);
            }
            let (counter, counter_length) = parse_counter(rest)?;
            let body = tail(rest, counter_length, "attachment group")?;
            let group_length = self.parse_group(counter, body)?;
            cursor += counter_length + group_length;
        }
    }

    /// Parses the elements of one group whose counter has already been read. Returns how many
    /// characters the elements occupy.
    fn parse_group(&mut self, counter: Counter, text: &str) -> Result<usize, StreamError> {
        let mut cursor = Cursor::new(text);
        let count = counter.count();
        match counter.code().as_str() {
            CONTROLLER_SIGNATURES => {
                for _ in 0..count {
                    self.controller_signatures.push(cursor.indexed_signature()?);
                }
            }
            WITNESS_SIGNATURES => {
                for _ in 0..count {
                    self.witness_signatures.push(cursor.indexed_signature()?);
                }
            }
            RECEIPT_COUPLES => {
                for _ in 0..count {
                    let verifier = cursor.verification_key()?;
                    let signature = cursor.unindexed_signature()?;
                    let couple = ReceiptCouple::new(verifier, signature).map_err(StreamError::attachment)?;
                    self.receipt_couples.push(couple);
                }
            }
            RECEIPT_QUADRUPLES => {
                for _ in 0..count {
                    self.receipt_quadruples.push(ReceiptQuadruple {
                        identifier: cursor.identifier()?,
                        sequence_number: cursor.sequence_number()?,
                        said: cursor.said()?,
                        signature: cursor.indexed_signature()?,
                    });
                }
            }
            FIRST_SEEN_COUPLES => {
                for _ in 0..count {
                    self.first_seen_replay_couples.push(FirstSeenReplayCouple {
                        ordinal: cursor.sequence_number()?,
                        timestamp: cursor.timestamp()?,
                    });
                }
            }
            TRANSFERABLE_GROUPS => {
                for _ in 0..count {
                    self.transferable_signature_groups.push(TransferableSignatureGroup {
                        identifier: cursor.identifier()?,
                        sequence_number: cursor.sequence_number()?,
                        said: cursor.said()?,
                        signatures: cursor.controller_signature_group()?,
                    });
                }
            }
            SEAL_COUPLES => {
                for _ in 0..count {
                    let sequence_number = cursor.sequence_number()?;
                    let said = cursor.said()?;
                    self.seal_source_couples
                        .push(SealSourceCouple::new(sequence_number, said));
                }
            }
            LAST_ESTABLISHMENT_GROUPS => {
                for _ in 0..count {
                    self.last_establishment_signature_groups
                        .push(LastEstablishmentSignatureGroup {
                            identifier: cursor.identifier()?,
                            signatures: cursor.controller_signature_group()?,
                        });
                }
            }
            SEAL_TRIPLES => {
                for _ in 0..count {
                    let identifier = cursor.identifier()?;
                    let sequence_number = cursor.sequence_number()?;
                    let said = cursor.said()?;
                    self.seal_source_triples
                        .push(SealSourceTriple::new(identifier, sequence_number, said));
                }
            }
            PATHED_MATERIAL => {
                self.pathed_material
                    .push(cursor.raw_quadlets(count, "pathed material group")?);
            }
            code => {
                return Err(StreamError::UnsupportedGroup {
                    code: bounded_code(code),
                });
            }
        }
        Ok(cursor.position())
    }

    /// Returns the exact bytes the groups occupied in the stream, including a pipelining frame.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Returns whether the groups were framed by an attachment-group counter.
    #[must_use]
    pub const fn framing(&self) -> AttachmentFraming {
        self.framing
    }

    /// Returns whether no group at all was attached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Returns the controller indexed signatures (`-A`).
    #[must_use]
    pub fn controller_signatures(&self) -> &[IndexedSignature] {
        &self.controller_signatures
    }

    /// Returns the witness indexed signatures (`-B`).
    #[must_use]
    pub fn witness_signatures(&self) -> &[IndexedSignature] {
        &self.witness_signatures
    }

    /// Returns the non-transferable receipt couples (`-C`).
    #[must_use]
    pub fn receipt_couples(&self) -> &[ReceiptCouple] {
        &self.receipt_couples
    }

    /// Returns the transferable receipt quadruples (`-D`).
    #[must_use]
    pub fn receipt_quadruples(&self) -> &[ReceiptQuadruple] {
        &self.receipt_quadruples
    }

    /// Returns the first-seen replay couples (`-E`).
    #[must_use]
    pub fn first_seen_replay_couples(&self) -> &[FirstSeenReplayCouple] {
        &self.first_seen_replay_couples
    }

    /// Returns the transferable indexed signature groups (`-F`).
    #[must_use]
    pub fn transferable_signature_groups(&self) -> &[TransferableSignatureGroup] {
        &self.transferable_signature_groups
    }

    /// Returns the transferable last-establishment signature groups (`-H`).
    #[must_use]
    pub fn last_establishment_signature_groups(&self) -> &[LastEstablishmentSignatureGroup] {
        &self.last_establishment_signature_groups
    }

    /// Returns the seal source couples (`-G`).
    #[must_use]
    pub fn seal_source_couples(&self) -> &[SealSourceCouple] {
        &self.seal_source_couples
    }

    /// Returns the seal source triples (`-I`).
    #[must_use]
    pub fn seal_source_triples(&self) -> &[SealSourceTriple] {
        &self.seal_source_triples
    }

    /// Returns each pathed material group (`-L`) as the raw text that followed its counter.
    #[must_use]
    pub fn pathed_material(&self) -> &[Vec<u8>] {
        &self.pathed_material
    }
}

/// Attachments read from the front of a stream, with how much of it they occupied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedAttachments {
    attachments: Attachments,
    consumed: usize,
}

impl ParsedAttachments {
    /// Returns the parsed attachments.
    #[must_use]
    pub const fn attachments(&self) -> &Attachments {
        &self.attachments
    }

    /// Returns how many bytes of the input the groups occupied.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Splits into the attachments and the consumed length.
    #[must_use]
    pub fn into_parts(self) -> (Attachments, usize) {
        (self.attachments, self.consumed)
    }
}

/// One message as it arrived: its event and the attachments that followed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    event: SerializedEvent,
    attachments: Attachments,
}

impl Message {
    /// Parses the message at the front of `input`: the event its version string sizes, then every
    /// attachment group up to the end of the input or the next message.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::EmptyInput`] for no input, [`StreamError::UnexpectedStreamStart`]
    /// when the input starts with neither a message nor a counter,
    /// [`StreamError::VersionFieldNotFirst`] when a message does not open with its version field,
    /// [`StreamError::Truncated`] when the version string or the event it sizes is cut short,
    /// [`StreamError::Serialization`] when the event itself is malformed, and the errors of
    /// [`Attachments::parse`] for the groups behind it.
    pub fn parse(input: &[u8]) -> Result<ParsedMessage, StreamError> {
        // Sniff the raw bytes first: a binary-domain stream is not UTF-8 and deserves its own error.
        sniff(input)?;
        let text = utf8_text(input).map_err(StreamError::cesr)?;
        let (message, consumed) = Self::parse_text(text)?;
        Ok(ParsedMessage { message, consumed })
    }

    /// Parses `input` as exactly one message.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::TrailingMaterial`] when anything follows the message's attachments,
    /// and otherwise the errors of [`Self::parse`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, StreamError> {
        let parsed = Self::parse(input)?;
        let length = input.len().saturating_sub(parsed.consumed);
        if length > 0 {
            return Err(StreamError::TrailingMaterial { length });
        }
        Ok(parsed.message)
    }

    fn parse_text(text: &str) -> Result<(Self, usize), StreamError> {
        match sniff(text.as_bytes())? {
            StreamStart::Message => {}
            StreamStart::Counter => {
                return Err(StreamError::UnexpectedStreamStart { byte: b'-' });
            }
        }
        let size = message_size(text.as_bytes())?;
        let event_bytes = text.as_bytes().get(..size).ok_or(StreamError::Truncated {
            context: "message body",
            available: text.len(),
        })?;
        let event = SerializedEvent::parse(event_bytes).map_err(StreamError::serialization)?;
        let rest = tail(text, size, "message body")?;
        let (attachments, consumed) = Attachments::parse_text(rest)?;
        Ok((Self { event, attachments }, size + consumed))
    }

    /// Returns the event.
    #[must_use]
    pub const fn event(&self) -> &SerializedEvent {
        &self.event
    }

    /// Returns the attachments.
    #[must_use]
    pub const fn attachments(&self) -> &Attachments {
        &self.attachments
    }

    /// Splits into the event and its attachments.
    #[must_use]
    pub fn into_parts(self) -> (SerializedEvent, Attachments) {
        (self.event, self.attachments)
    }
}

/// A message read from the front of a stream, with how much of it the message occupied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedMessage {
    message: Message,
    consumed: usize,
}

impl ParsedMessage {
    /// Returns the parsed message.
    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.message
    }

    /// Returns how many bytes of the input the message and its attachments occupied.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Splits into the message and the consumed length.
    #[must_use]
    pub fn into_parts(self) -> (Message, usize) {
        (self.message, self.consumed)
    }
}

/// Parses every message in `input`, in order.
///
/// # Errors
///
/// Returns the first failure of [`Message::parse`] over the stream; an empty input is
/// [`StreamError::EmptyInput`]. Nothing before the failing message is returned, because a stream
/// that fails to parse should be rejected whole rather than half-processed.
pub fn parse_stream(input: &[u8]) -> Result<Vec<Message>, StreamError> {
    sniff(input)?;
    let text = utf8_text(input).map_err(StreamError::cesr)?;
    let mut messages = Vec::new();
    let mut cursor = 0;
    while cursor < text.len() {
        let rest = tail(text, cursor, "message")?;
        let (message, consumed) = Message::parse_text(rest)?;
        messages.push(message);
        cursor += consumed;
    }
    if messages.is_empty() {
        return Err(StreamError::EmptyInput);
    }
    Ok(messages)
}

/// What the first byte of a stream says comes next, keripy's `sniff`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamStart {
    Message,
    Counter,
}

fn sniff(input: &[u8]) -> Result<StreamStart, StreamError> {
    let Some(&first) = input.first() else {
        return Err(StreamError::EmptyInput);
    };
    match first {
        b'{' => Ok(StreamStart::Message),
        b'-' => Ok(StreamStart::Counter),
        // The top three bits of a binary-domain counter are all set.
        byte if byte >> 5 == 0b111 => Err(StreamError::BinaryStreamUnsupported),
        byte => Err(StreamError::UnexpectedStreamStart { byte }),
    }
}

/// Reads the size a message's version string declares, which is where its attachments begin.
fn message_size(input: &[u8]) -> Result<usize, StreamError> {
    let header_length = VERSION_FIELD_PREFIX.len() + VersionString::FULL_SIZE;
    let Some(header) = input.get(..header_length) else {
        if !input.is_empty()
            && !VERSION_FIELD_PREFIX.starts_with(
                input
                    .get(..VERSION_FIELD_PREFIX.len().min(input.len()))
                    .unwrap_or_default(),
            )
        {
            return Err(StreamError::VersionFieldNotFirst);
        }
        return Err(StreamError::Truncated {
            context: "message version string",
            available: input.len(),
        });
    };
    if !header.starts_with(VERSION_FIELD_PREFIX) {
        return Err(StreamError::VersionFieldNotFirst);
    }
    let version_text = header.get(VERSION_FIELD_PREFIX.len()..).unwrap_or_default();
    let version_text = utf8_text(version_text).map_err(StreamError::cesr)?;
    let version = VersionString::from_str(version_text).map_err(StreamError::version)?;
    let size = usize::try_from(version.size()).map_err(|_| StreamError::Truncated {
        context: "message body",
        available: input.len(),
    })?;
    if input.len() < size {
        return Err(StreamError::Truncated {
            context: "message body",
            available: input.len(),
        });
    }
    Ok(size)
}

/// Parses the counter at the front of `text`, mapping an unknown code to an unsupported group.
fn parse_counter(text: &str) -> Result<(Counter, usize), StreamError> {
    match Counter::parse_qb64(text) {
        Ok(parsed) => Ok((parsed.counter(), parsed.consumed())),
        // A code the CESR table does not know is an unsupported group only if it is a count code
        // at all; anything else in a counter's place is malformed material.
        Err(CesrError::UnsupportedCode { code }) if code.starts_with('-') => Err(StreamError::UnsupportedGroup {
            code: bounded_code(&code),
        }),
        Err(error) => Err(StreamError::from_cesr(error, "counter", text.len())),
    }
}

/// Returns `text` from `start`, which the callers only ever compute from consumed lengths.
fn tail<'a>(text: &'a str, start: usize, context: &'static str) -> Result<&'a str, StreamError> {
    text.get(start..).ok_or(StreamError::Truncated {
        context,
        available: text.len().saturating_sub(start),
    })
}

const fn quadlets_to_chars(count: u32) -> usize {
    // A u32 count of quadlets fits a usize on every supported target.
    (count as usize) * QUADLET
}

fn bounded_code(code: &str) -> String {
    code.chars().take(MAX_REPORTED_CODE_CHARS).collect()
}

/// A position inside one group's text, advancing one primitive at a time.
struct Cursor<'a> {
    text: &'a str,
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(text: &'a str) -> Self {
        Self { text, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn rest(&self, context: &'static str) -> Result<&'a str, StreamError> {
        let rest = tail(self.text, self.position, context)?;
        if rest.is_empty() {
            return Err(StreamError::Truncated { context, available: 0 });
        }
        Ok(rest)
    }

    fn advance(&mut self, consumed: usize) {
        self.position += consumed;
    }

    fn indexed_signature(&mut self) -> Result<IndexedSignature, StreamError> {
        let context = "indexed signature";
        let rest = self.rest(context)?;
        let parsed =
            IndexedSignature::parse_qb64(rest).map_err(|error| StreamError::from_crypto(error, context, rest.len()))?;
        let (signature, consumed) = parsed.into_parts();
        self.advance(consumed);
        Ok(signature)
    }

    fn unindexed_signature(&mut self) -> Result<UnindexedSignature, StreamError> {
        let context = "receipt signature";
        let rest = self.rest(context)?;
        let parsed = UnindexedSignature::parse_qb64(rest)
            .map_err(|error| StreamError::from_crypto(error, context, rest.len()))?;
        let (signature, consumed) = parsed.into_parts();
        self.advance(consumed);
        Ok(signature)
    }

    fn verification_key(&mut self) -> Result<VerificationKey, StreamError> {
        let context = "verification key";
        let rest = self.rest(context)?;
        let parsed =
            VerificationKey::parse_qb64(rest).map_err(|error| StreamError::from_crypto(error, context, rest.len()))?;
        let (key, consumed) = parsed.into_parts();
        self.advance(consumed);
        Ok(key)
    }

    fn sequence_number(&mut self) -> Result<SequenceNumber, StreamError> {
        let context = "sequence number";
        let rest = self.rest(context)?;
        let parsed =
            SequenceNumber::parse_qb64(rest).map_err(|error| StreamError::from_cesr(error, context, rest.len()))?;
        let (sequence_number, consumed) = parsed.into_parts();
        self.advance(consumed);
        Ok(sequence_number)
    }

    /// Reads one qualified primitive and returns its text, for the types that parse whole values.
    fn primitive(&mut self, context: &'static str) -> Result<&'a str, StreamError> {
        let rest = self.rest(context)?;
        let parsed =
            QualifiedMaterial::parse_qb64(rest).map_err(|error| StreamError::from_cesr(error, context, rest.len()))?;
        let consumed = parsed.consumed();
        let text = rest.get(..consumed).ok_or(StreamError::Truncated {
            context,
            available: rest.len(),
        })?;
        self.advance(consumed);
        Ok(text)
    }

    fn identifier(&mut self) -> Result<IdentifierPrefix, StreamError> {
        let text = self.primitive("identifier prefix")?;
        IdentifierPrefix::from_qb64(text).map_err(StreamError::prefix)
    }

    fn said(&mut self) -> Result<Said, StreamError> {
        let text = self.primitive("self-addressing identifier")?;
        Said::from_qb64(text).map_err(StreamError::said)
    }

    /// Reads a datetime primitive: Base64 text with `:`, `.` and `+` spelled `c`, `d` and `p`.
    fn timestamp(&mut self) -> Result<Timestamp, StreamError> {
        let context = "datetime";
        let rest = self.rest(context)?;
        let parsed =
            QualifiedMaterial::parse_qb64(rest).map_err(|error| StreamError::from_cesr(error, context, rest.len()))?;
        let (material, consumed) = parsed.into_parts();
        let code = material.code().as_str();
        if code != DATETIME_CODE {
            return Err(StreamError::InvalidTimestampCode { code });
        }
        let text: String = encode_url_safe(material.raw())
            .chars()
            .map(|character| match character {
                'c' => ':',
                'd' => '.',
                'p' => '+',
                other => other,
            })
            .collect();
        let timestamp = Timestamp::parse(&text).map_err(StreamError::timestamp)?;
        self.advance(consumed);
        Ok(timestamp)
    }

    /// Reads the `-A` group that a transferable signature group must end with.
    fn controller_signature_group(&mut self) -> Result<Vec<IndexedSignature>, StreamError> {
        let rest = self.rest("counter")?;
        let (counter, counter_length) = parse_counter(rest)?;
        if counter.code().as_str() != CONTROLLER_SIGNATURES {
            return Err(StreamError::UnexpectedGroup {
                expected: CONTROLLER_SIGNATURES,
                found: counter.code().as_str(),
            });
        }
        self.advance(counter_length);
        let mut signatures = Vec::new();
        for _ in 0..counter.count() {
            signatures.push(self.indexed_signature()?);
        }
        Ok(signatures)
    }

    /// Takes `count` quadlets verbatim.
    fn raw_quadlets(&mut self, count: u32, context: &'static str) -> Result<Vec<u8>, StreamError> {
        let length = quadlets_to_chars(count);
        let rest = tail(self.text, self.position, context)?;
        let material = rest.get(..length).ok_or(StreamError::Truncated {
            context,
            available: rest.len(),
        })?;
        self.advance(length);
        Ok(material.as_bytes().to_vec())
    }
}

/// Stable stream-parsing failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum StreamError {
    /// The input holds no message at all.
    EmptyInput,
    /// The input starts with neither a JSON message nor a text-domain counter.
    UnexpectedStreamStart {
        /// The first byte of the input.
        byte: u8,
    },
    /// The input starts a binary-domain (`qb2`) counter, which this parser does not read.
    BinaryStreamUnsupported,
    /// A message does not open with its version field, so its size cannot be read.
    VersionFieldNotFirst,
    /// The input ends before the element being read is complete.
    Truncated {
        /// What was being read.
        context: &'static str,
        /// How many bytes were left to read it from.
        available: usize,
    },
    /// Something follows the message or groups when exactly one was expected.
    TrailingMaterial {
        /// How many bytes follow.
        length: usize,
    },
    /// A count code this parser does not read.
    UnsupportedGroup {
        /// The count code as it appeared, at most eight characters.
        code: String,
    },
    /// A group was followed by a different group than its structure requires.
    UnexpectedGroup {
        /// The count code the structure requires.
        expected: &'static str,
        /// The count code found instead.
        found: &'static str,
    },
    /// A first-seen replay couple's datetime does not carry the datetime code.
    InvalidTimestampCode {
        /// The code found.
        code: &'static str,
    },
    /// The message's version string could not be parsed.
    Version {
        /// Underlying version-string failure.
        source: Box<VersionError>,
    },
    /// The message body could not be parsed.
    Serialization {
        /// Underlying serialization failure.
        source: Box<SerializationError>,
    },
    /// A receipt couple is not a valid attachment.
    Attachment {
        /// Underlying attachment failure.
        source: Box<AttachmentError>,
    },
    /// An identifier prefix inside a group is invalid.
    Prefix {
        /// Underlying prefix failure.
        source: Box<PrefixError>,
    },
    /// A SAID inside a group is invalid.
    Said {
        /// Underlying SAID failure.
        source: Box<SaidError>,
    },
    /// A datetime inside a group is invalid.
    Timestamp {
        /// Underlying timestamp failure.
        source: Box<TimestampError>,
    },
    /// CESR material inside a group could not be parsed.
    Cesr {
        /// Underlying CESR failure.
        source: Box<CesrError>,
    },
    /// Cryptographic material inside a group could not be parsed.
    Crypto {
        /// Underlying cryptographic failure.
        source: Box<CryptoError>,
    },
}

impl StreamError {
    fn cesr(source: CesrError) -> Self {
        Self::Cesr {
            source: Box::new(source),
        }
    }

    /// Reports running out of input as truncation and anything else as a CESR failure.
    fn from_cesr(source: CesrError, context: &'static str, available: usize) -> Self {
        match source {
            CesrError::Truncated { .. } | CesrError::EmptyInput { .. } => Self::Truncated { context, available },
            other => Self::cesr(other),
        }
    }

    fn from_crypto(source: CryptoError, context: &'static str, available: usize) -> Self {
        match source {
            CryptoError::Cesr { source }
                if matches!(
                    source.as_ref(),
                    CesrError::Truncated { .. } | CesrError::EmptyInput { .. }
                ) =>
            {
                Self::Truncated { context, available }
            }
            other => Self::Crypto {
                source: Box::new(other),
            },
        }
    }

    fn version(source: VersionError) -> Self {
        Self::Version {
            source: Box::new(source),
        }
    }

    fn serialization(source: SerializationError) -> Self {
        Self::Serialization {
            source: Box::new(source),
        }
    }

    fn attachment(source: AttachmentError) -> Self {
        Self::Attachment {
            source: Box::new(source),
        }
    }

    fn prefix(source: PrefixError) -> Self {
        Self::Prefix {
            source: Box::new(source),
        }
    }

    fn said(source: SaidError) -> Self {
        Self::Said {
            source: Box::new(source),
        }
    }

    fn timestamp(source: TimestampError) -> Self {
        Self::Timestamp {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => formatter.write_str("stream holds no message"),
            Self::UnexpectedStreamStart { byte } => {
                write!(
                    formatter,
                    "stream starts with byte {byte:#04x}, neither a message nor a counter"
                )
            }
            Self::BinaryStreamUnsupported => formatter.write_str("binary-domain attachment streams are not supported"),
            Self::VersionFieldNotFirst => formatter.write_str("message does not open with its version field"),
            Self::Truncated { context, available } => {
                write!(formatter, "stream ends inside {context} with {available} bytes left")
            }
            Self::TrailingMaterial { length } => {
                write!(formatter, "{length} bytes follow the message")
            }
            Self::UnsupportedGroup { code } => write!(formatter, "count code {code:?} is not supported"),
            Self::UnexpectedGroup { expected, found } => {
                write!(formatter, "expected a {expected} group, found {found}")
            }
            Self::InvalidTimestampCode { code } => {
                write!(formatter, "datetime carries code {code} instead of {DATETIME_CODE}")
            }
            Self::Version { .. } => formatter.write_str("message version string is invalid"),
            Self::Serialization { .. } => formatter.write_str("message body is invalid"),
            Self::Attachment { .. } => formatter.write_str("receipt couple is invalid"),
            Self::Prefix { .. } => formatter.write_str("group holds an invalid identifier prefix"),
            Self::Said { .. } => formatter.write_str("group holds an invalid self-addressing identifier"),
            Self::Timestamp { .. } => formatter.write_str("group holds an invalid datetime"),
            Self::Cesr { .. } => formatter.write_str("group holds invalid CESR material"),
            Self::Crypto { .. } => formatter.write_str("group holds invalid cryptographic material"),
        }
    }
}

impl Error for StreamError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Version { source } => Some(source.as_ref()),
            Self::Serialization { source } => Some(source.as_ref()),
            Self::Attachment { source } => Some(source.as_ref()),
            Self::Prefix { source } => Some(source.as_ref()),
            Self::Said { source } => Some(source.as_ref()),
            Self::Timestamp { source } => Some(source.as_ref()),
            Self::Cesr { source } => Some(source.as_ref()),
            Self::Crypto { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment::{SignatureSeal, SignedMessageBuilder};

    const EVENT: &str = concat!(
        r#"{"v":"KERI10JSON000125_","t":"icp","d":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","#,
        r#""i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","s":"0","kt":1,"#,
        r#""k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,"#,
        r#""n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}"#
    );
    const SIGNATURE: &str = "AABB3MJGmBXxSEryNHw3YwZZLRl_6Ws4Me2WFq8PrQ6WlluSOpPqbwXuiG9RvNWZkqeW8A_0VRjokGMVRZ3m-c0I";
    const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
    const WITNESS_KEY: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const TRANSFERABLE_KEY: &str = "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const WITNESS_SIGNATURE: &str =
        "AACeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";
    const RECEIPT_SIGNATURE: &str =
        "0BCeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";
    /// keripy's `Dater(dts="2021-01-01T00:00:00.000000+00:00").qb64`.
    const DATETIME: &str = "1AAG2021-01-01T00c00c00d000000p00c00";

    fn event() -> Result<SerializedEvent, Box<dyn Error>> {
        Ok(SerializedEvent::parse(EVENT.as_bytes())?)
    }

    fn signature() -> Result<IndexedSignature, Box<dyn Error>> {
        Ok(IndexedSignature::from_qb64(SIGNATURE)?)
    }

    fn witness_signature() -> Result<IndexedSignature, Box<dyn Error>> {
        let key = VerificationKey::from_qb64(WITNESS_KEY)?;
        Ok(IndexedSignature::from_qb64(WITNESS_SIGNATURE)?.with_verifier(key)?)
    }

    fn receipt_couple() -> Result<ReceiptCouple, Box<dyn Error>> {
        let key = VerificationKey::from_qb64(WITNESS_KEY)?;
        Ok(ReceiptCouple::new(
            key,
            UnindexedSignature::from_qb64(RECEIPT_SIGNATURE)?,
        )?)
    }

    fn signed(framing: AttachmentFraming) -> Result<Vec<u8>, Box<dyn Error>> {
        let event = event()?;
        Ok(SignedMessageBuilder::new(&event)
            .controller_signatures(vec![signature()?])
            .witness_signatures(vec![witness_signature()?])
            .receipt_couples(vec![receipt_couple()?])
            .framing(framing)
            .build()?
            .into_bytes())
    }

    #[test]
    fn a_composed_message_parses_back_into_its_groups() -> Result<(), Box<dyn Error>> {
        for framing in [AttachmentFraming::Plain, AttachmentFraming::Pipelined] {
            let bytes = signed(framing)?;
            let message = Message::from_bytes(&bytes)?;
            assert_eq!(message.event().raw(), EVENT.as_bytes());
            let attachments = message.attachments();
            assert_eq!(attachments.framing(), framing);
            assert_eq!(attachments.raw(), bytes.get(EVENT.len()..).unwrap_or_default());
            assert_eq!(attachments.controller_signatures(), &[signature()?]);
            assert_eq!(attachments.witness_signatures().len(), 1);
            assert_eq!(
                attachments
                    .witness_signatures()
                    .first()
                    .map(IndexedSignature::qb64)
                    .transpose()?,
                Some(WITNESS_SIGNATURE.to_owned())
            );
            assert_eq!(attachments.receipt_couples(), &[receipt_couple()?]);
            assert_eq!(attachments.receipt_quadruples(), []);
            assert_eq!(attachments.pathed_material(), [] as [Vec<u8>; 0]);
        }
        Ok(())
    }

    #[test]
    fn seals_parse_into_their_own_groups() -> Result<(), Box<dyn Error>> {
        let event = event()?;
        let identifier = IdentifierPrefix::from_qb64(IDENTIFIER)?;
        let said = Said::from_qb64(IDENTIFIER)?;
        let sealed = SignedMessageBuilder::new(&event)
            .controller_signatures(vec![signature()?])
            .seal(SignatureSeal::Event {
                identifier: identifier.clone(),
                sequence_number: SequenceNumber::new(3),
                said,
            })
            .build()?;
        let message = Message::from_bytes(sealed.as_bytes())?;
        let groups = message.attachments().transferable_signature_groups();
        let group = groups.first().ok_or("no transferable group")?;
        assert_eq!(group.identifier(), &identifier);
        assert_eq!(group.sequence_number(), SequenceNumber::new(3));
        assert_eq!(group.said(), said);
        assert_eq!(group.signatures(), &[signature()?]);
        assert_eq!(message.attachments().controller_signatures(), []);

        let last = SignedMessageBuilder::new(&event)
            .controller_signatures(vec![signature()?])
            .seal(SignatureSeal::Last {
                identifier: identifier.clone(),
            })
            .build()?;
        let message = Message::from_bytes(last.as_bytes())?;
        let groups = message.attachments().last_establishment_signature_groups();
        let group = groups.first().ok_or("no last-establishment group")?;
        assert_eq!(group.identifier(), &identifier);
        assert_eq!(group.signatures(), &[signature()?]);
        Ok(())
    }

    #[test]
    fn seal_sources_and_first_seen_couples_parse() -> Result<(), Box<dyn Error>> {
        let said = Said::from_qb64(IDENTIFIER)?;
        let identifier = IdentifierPrefix::from_qb64(IDENTIFIER)?;
        let couple = SealSourceCouple::new(SequenceNumber::new(1), said);
        let triple = SealSourceTriple::new(identifier.clone(), SequenceNumber::new(2), said);
        let mut stream = EVENT.as_bytes().to_vec();
        stream.extend_from_slice(&couple.attachment(AttachmentFraming::Plain)?);
        stream.extend_from_slice(&triple.attachment(AttachmentFraming::Plain)?);
        stream.extend_from_slice(b"-EAB");
        stream.extend_from_slice(SequenceNumber::new(7).qb64()?.as_bytes());
        stream.extend_from_slice(DATETIME.as_bytes());

        let message = Message::from_bytes(&stream)?;
        let attachments = message.attachments();
        assert_eq!(attachments.seal_source_couples(), &[couple]);
        assert_eq!(attachments.seal_source_triples(), &[triple]);
        let first_seen = attachments
            .first_seen_replay_couples()
            .first()
            .ok_or("no first-seen couple")?;
        assert_eq!(first_seen.ordinal(), SequenceNumber::new(7));
        assert_eq!(first_seen.timestamp().as_str(), "2021-01-01T00:00:00.000000+00:00");
        Ok(())
    }

    #[test]
    fn a_stream_of_messages_splits_at_each_version_string() -> Result<(), Box<dyn Error>> {
        let mut stream = signed(AttachmentFraming::Plain)?;
        stream.extend_from_slice(EVENT.as_bytes());
        stream.extend_from_slice(&signed(AttachmentFraming::Pipelined)?);
        let messages = parse_stream(&stream)?;
        assert_eq!(messages.len(), 3);
        assert!(messages.get(1).is_some_and(|message| message.attachments().is_empty()));
        assert_eq!(
            messages.get(2).map(|message| message.attachments().framing()),
            Some(AttachmentFraming::Pipelined)
        );

        let parsed = Message::parse(&stream)?;
        assert_eq!(parsed.consumed(), signed(AttachmentFraming::Plain)?.len());
        assert!(matches!(
            Message::from_bytes(&stream),
            Err(StreamError::TrailingMaterial { .. })
        ));
        Ok(())
    }

    #[test]
    fn pathed_material_is_kept_opaque() -> Result<(), Box<dyn Error>> {
        let mut stream = EVENT.as_bytes().to_vec();
        stream.extend_from_slice(b"-AAB");
        stream.extend_from_slice(SIGNATURE.as_bytes());
        let pathed = format!("6AABAAA--AAB{SIGNATURE}");
        let quadlets = u32::try_from(pathed.len() / 4)?;
        stream.extend_from_slice(
            Counter::new(CounterCode::PATHED_MATERIAL_QUADLETS, quadlets)?
                .qb64()?
                .as_bytes(),
        );
        stream.extend_from_slice(pathed.as_bytes());
        let message = Message::from_bytes(&stream)?;
        assert_eq!(message.attachments().pathed_material(), &[pathed.into_bytes()]);
        assert_eq!(message.attachments().controller_signatures().len(), 1);
        Ok(())
    }

    #[test]
    fn malformed_streams_are_refused_with_the_right_error() -> Result<(), Box<dyn Error>> {
        assert!(matches!(parse_stream(b""), Err(StreamError::EmptyInput)));
        assert!(matches!(
            Message::parse(b"-AAB"),
            Err(StreamError::UnexpectedStreamStart { byte: b'-' })
        ));
        assert!(matches!(
            Message::parse(b"xyz"),
            Err(StreamError::UnexpectedStreamStart { byte: b'x' })
        ));
        assert!(matches!(
            Message::parse(&[0xF8, 0x00]),
            Err(StreamError::BinaryStreamUnsupported)
        ));
        assert!(matches!(
            Message::parse(br#"{"t":"icp"}"#),
            Err(StreamError::VersionFieldNotFirst)
        ));
        assert!(matches!(
            Message::parse(br#"{"v":"KERI10JSON0"#),
            Err(StreamError::Truncated {
                context: "message version string",
                ..
            })
        ));
        assert!(matches!(
            Message::parse(EVENT.get(..EVENT.len() - 1).unwrap_or_default().as_bytes()),
            Err(StreamError::Truncated {
                context: "message body",
                ..
            })
        ));

        let mut truncated = signed(AttachmentFraming::Plain)?;
        truncated.truncate(truncated.len() - 10);
        assert!(matches!(
            Message::parse(&truncated),
            Err(StreamError::Truncated {
                context: "receipt signature",
                ..
            })
        ));

        let mut unsupported = EVENT.as_bytes().to_vec();
        unsupported.extend_from_slice(b"-JAB");
        assert!(matches!(Message::parse(&unsupported), Err(StreamError::UnsupportedGroup { code }) if code == "-J"));
        let mut unknown = EVENT.as_bytes().to_vec();
        unknown.extend_from_slice(b"-0LAAAB");
        assert!(matches!(Message::parse(&unknown), Err(StreamError::UnsupportedGroup { code }) if code == "-0L"));

        let mut wrong_inner = EVENT.as_bytes().to_vec();
        wrong_inner.extend_from_slice(format!("-HAB{IDENTIFIER}-BAB{WITNESS_SIGNATURE}").as_bytes());
        assert!(matches!(
            Message::parse(&wrong_inner),
            Err(StreamError::UnexpectedGroup {
                expected: "-A",
                found: "-B"
            })
        ));

        let mut transferable = EVENT.as_bytes().to_vec();
        transferable.extend_from_slice(format!("-CAB{TRANSFERABLE_KEY}{RECEIPT_SIGNATURE}").as_bytes());
        assert!(matches!(
            Message::parse(&transferable),
            Err(StreamError::Attachment { .. })
        ));

        let mut wrong_code = EVENT.as_bytes().to_vec();
        wrong_code.extend_from_slice(format!("-EAB{}{IDENTIFIER}", SequenceNumber::new(0).qb64()?).as_bytes());
        assert!(matches!(
            Message::parse(&wrong_code),
            Err(StreamError::InvalidTimestampCode { code: "E" })
        ));

        let mut short_frame = EVENT.as_bytes().to_vec();
        short_frame.extend_from_slice(b"-VAX-AAB");
        assert!(matches!(
            Message::parse(&short_frame),
            Err(StreamError::Truncated {
                context: "pipelined attachment group",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn attachments_alone_parse_and_stop_at_a_message() -> Result<(), Box<dyn Error>> {
        let bytes = signed(AttachmentFraming::Plain)?;
        let attachments = bytes.get(EVENT.len()..).unwrap_or_default();
        let parsed = Attachments::from_bytes(attachments)?;
        assert_eq!(parsed.controller_signatures().len(), 1);

        let mut followed = attachments.to_vec();
        followed.extend_from_slice(EVENT.as_bytes());
        let parsed = Attachments::parse(&followed)?;
        assert_eq!(parsed.consumed(), attachments.len());
        assert!(matches!(
            Attachments::from_bytes(&followed),
            Err(StreamError::TrailingMaterial { .. })
        ));

        let parsed = Attachments::parse(EVENT.as_bytes())?;
        assert_eq!(parsed.consumed(), 0);
        assert!(parsed.attachments().is_empty());
        Ok(())
    }

    #[test]
    fn errors_carry_sources_and_readable_text() {
        let leaves = [
            StreamError::EmptyInput,
            StreamError::UnexpectedStreamStart { byte: b'x' },
            StreamError::BinaryStreamUnsupported,
            StreamError::VersionFieldNotFirst,
            StreamError::Truncated {
                context: "counter",
                available: 2,
            },
            StreamError::TrailingMaterial { length: 4 },
            StreamError::UnsupportedGroup { code: "-J".to_owned() },
            StreamError::UnexpectedGroup {
                expected: "-A",
                found: "-B",
            },
            StreamError::InvalidTimestampCode { code: "E" },
        ];
        for error in leaves {
            assert_ne!(error.to_string(), "");
            assert!(error.source().is_none());
        }
        let wrapped = StreamError::cesr(CesrError::NonCanonicalBase64);
        assert!(wrapped.source().is_some());
        assert_eq!(wrapped.to_string(), "group holds invalid CESR material");
    }
}
