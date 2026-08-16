use fact_core::{Hash, ObjectId};
use fact_crypto::SigningKey;
use rusqlite::{params, params_from_iter, types::Value, Connection};
#[cfg(debug_assertions)]
use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    HashAsc,
    LexicalBm25,
    SemanticCosine,
    ProviderScore,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decimal {
    negative: bool,
    integer: String,
    fraction: String,
}
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("invalid canonical decimal score")]
    Grammar,
    #[error("score exceeds profile scale")]
    Scale,
    #[error("score is outside profile range")]
    Range,
    #[error("profile requires score 0")]
    Sentinel,
    #[error("canonical markdown: {0}")]
    Markdown(#[from] fact_canonical::MarkdownError),
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("SQLite FTS5 is unavailable")]
    FtsUnavailable,
    #[error("invalid stored content hash")]
    StoredHash,
    #[error("invalid canonical query object")]
    InvalidQuery,
    #[error("invalid signed cursor")]
    InvalidCursor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileDescriptor {
    pub id: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub query_digest: Hash,
    pub coordinator_actor_id: ObjectId,
    pub input_commitment_hash: Hash,
    pub ordering_profile: String,
    pub search_profile: ProfileDescriptor,
    pub extraction_profile: ProfileDescriptor,
    pub next_offset: u64,
    pub preceding_score: Option<String>,
    pub preceding_object_hash: Option<Hash>,
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CursorExpectation<'a> {
    pub query_digest: Hash,
    pub coordinator_actor_id: ObjectId,
    pub input_commitment_hash: Hash,
    pub ordering_profile: &'a str,
    pub search_profile: &'a ProfileDescriptor,
    pub extraction_profile: &'a ProfileDescriptor,
    pub ledger: Option<[u8; 16]>,
}

pub fn encode_cursor(
    cursor: &Cursor,
    key: &SigningKey,
    ledger: Option<[u8; 16]>,
) -> Result<String, Error> {
    validate_cursor_values(cursor, None)?;
    let body = cursor_body(cursor);
    let payload =
        fact_canonical::encode(&serde_json::to_vec(&body).map_err(|_| Error::InvalidCursor)?)
            .map_err(|_| Error::InvalidCursor)?;
    let protected = fact_crypto::coordinator_protected(key.public_key(), "cursor", "0", ledger);
    let cose = fact_crypto::encode_sign1(&fact_crypto::sign1(&protected, &payload, key));
    Ok(base64url_encode(&cose))
}

pub fn decode_cursor(
    encoded: &str,
    public_key: [u8; 32],
    expected: &CursorExpectation<'_>,
    now: Option<&str>,
) -> Result<Cursor, Error> {
    let bytes = base64url_decode(encoded).ok_or(Error::InvalidCursor)?;
    let cose = fact_crypto::decode_sign1(&bytes).map_err(|_| Error::InvalidCursor)?;
    fact_crypto::validate_coordinator_protected(&cose, public_key, "cursor", "0", expected.ledger)
        .map_err(|_| Error::InvalidCursor)?;
    fact_crypto::verify_sign1(public_key, &cose).map_err(|_| Error::InvalidCursor)?;
    if fact_canonical::encode(&cose.payload).map_err(|_| Error::InvalidCursor)? != cose.payload {
        return Err(Error::InvalidCursor);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&cose.payload).map_err(|_| Error::InvalidCursor)?;
    let cursor = cursor_from_body(&value)?;
    validate_cursor_values(&cursor, now)?;
    if cursor.query_digest != expected.query_digest
        || cursor.coordinator_actor_id != expected.coordinator_actor_id
        || cursor.input_commitment_hash != expected.input_commitment_hash
        || cursor.ordering_profile != expected.ordering_profile
        || cursor.search_profile != *expected.search_profile
        || cursor.extraction_profile != *expected.extraction_profile
    {
        return Err(Error::InvalidCursor);
    }
    Ok(cursor)
}

fn cursor_body(cursor: &Cursor) -> serde_json::Value {
    serde_json::json!({
        "schema":"facts-protocol-cursor-v0",
        "query_digest":cursor.query_digest.hex(),
        "coordinator_actor_id":cursor.coordinator_actor_id.to_string(),
        "input_commitment_hash":cursor.input_commitment_hash.hex(),
        "ordering_profile":cursor.ordering_profile,
        "search_profile":{"id":cursor.search_profile.id,"version":cursor.search_profile.version},
        "extraction_profile":{"id":cursor.extraction_profile.id,"version":cursor.extraction_profile.version},
        "next_offset":cursor.next_offset,
        "preceding_score":cursor.preceding_score,
        "preceding_object_hash":cursor.preceding_object_hash.map(|hash| hash.hex()),
        "expires_at":cursor.expires_at,
    })
}

fn cursor_from_body(value: &serde_json::Value) -> Result<Cursor, Error> {
    let object = value.as_object().ok_or(Error::InvalidCursor)?;
    let required = [
        "schema",
        "query_digest",
        "coordinator_actor_id",
        "input_commitment_hash",
        "ordering_profile",
        "search_profile",
        "extraction_profile",
        "next_offset",
        "preceding_score",
        "preceding_object_hash",
        "expires_at",
    ];
    if object.len() != required.len() || required.iter().any(|field| !object.contains_key(*field)) {
        return Err(Error::InvalidCursor);
    }
    if object.get("schema").and_then(serde_json::Value::as_str) != Some("facts-protocol-cursor-v0")
    {
        return Err(Error::InvalidCursor);
    }
    let query_digest = object
        .get("query_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::InvalidCursor)?
        .parse::<Hash>()
        .map_err(|_| Error::InvalidCursor)?;
    let coordinator_actor_id = object
        .get("coordinator_actor_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::InvalidCursor)?
        .parse::<ObjectId>()
        .map_err(|_| Error::InvalidCursor)?;
    let input_commitment_hash = object
        .get("input_commitment_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::InvalidCursor)?
        .parse::<Hash>()
        .map_err(|_| Error::InvalidCursor)?;
    let ordering_profile = object
        .get("ordering_profile")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::InvalidCursor)?
        .to_owned();
    let profile = |field: &str| -> Result<ProfileDescriptor, Error> {
        let profile = object
            .get(field)
            .and_then(serde_json::Value::as_object)
            .ok_or(Error::InvalidCursor)?;
        if profile.len() != 2 {
            return Err(Error::InvalidCursor);
        }
        Ok(ProfileDescriptor {
            id: profile
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidCursor)?
                .to_owned(),
            version: profile
                .get("version")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidCursor)?
                .to_owned(),
        })
    };
    let search_profile = profile("search_profile")?;
    let extraction_profile = profile("extraction_profile")?;
    let preceding_score = optional_string(object.get("preceding_score"))?;
    let preceding_object_hash = optional_string(object.get("preceding_object_hash"))?
        .map(|value| value.parse::<Hash>().map_err(|_| Error::InvalidCursor))
        .transpose()?;
    let expires_at = optional_string(object.get("expires_at"))?;
    Ok(Cursor {
        query_digest,
        coordinator_actor_id,
        input_commitment_hash,
        ordering_profile,
        search_profile,
        extraction_profile,
        next_offset: object
            .get("next_offset")
            .and_then(serde_json::Value::as_u64)
            .ok_or(Error::InvalidCursor)?,
        preceding_score,
        preceding_object_hash,
        expires_at,
    })
}

fn optional_string(value: Option<&serde_json::Value>) -> Result<Option<String>, Error> {
    let value = value.ok_or(Error::InvalidCursor)?;
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(value.as_str().ok_or(Error::InvalidCursor)?.to_owned()))
    }
}

fn validate_cursor_values(cursor: &Cursor, now: Option<&str>) -> Result<(), Error> {
    if cursor.ordering_profile != "hash-asc-v0"
        && cursor.ordering_profile != "score-desc-hash-asc-v0"
    {
        return Err(Error::InvalidCursor);
    }
    match (&cursor.preceding_score, &cursor.preceding_object_hash) {
        (None, None) => {}
        (Some(score), Some(_)) => {
            parse_score(score).map_err(|_| Error::InvalidCursor)?;
            if cursor.ordering_profile == "hash-asc-v0" && score != "0" {
                return Err(Error::InvalidCursor);
            }
        }
        _ => return Err(Error::InvalidCursor),
    }
    if let Some(expires_at) = &cursor.expires_at {
        fact_core::validate_timestamp(expires_at).map_err(|_| Error::InvalidCursor)?;
        if now.is_some_and(|now| expires_at.as_str() <= now) {
            return Err(Error::InvalidCursor);
        }
    }
    Ok(())
}

fn base64url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((value >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(value & 63) as usize] as char);
        }
    }
    output
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xff) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    if bits >= 6 || accumulator != 0 {
        None
    } else {
        Some(output)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalQuery {
    pub bytes: Vec<u8>,
    pub digest: Hash,
}

/// Validate and canonicalize the v0 query object. The digest is over the
/// complete query with `prior_cursor` replaced by JSON null, so pagination
/// remains bound to one immutable query definition.
pub fn canonical_query(input: &[u8]) -> Result<CanonicalQuery, Error> {
    let bytes = fact_canonical::encode(input).map_err(|_| Error::InvalidQuery)?;
    if bytes != input {
        return Err(Error::InvalidQuery);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidQuery)?;
    let object = value.as_object().ok_or(Error::InvalidQuery)?;
    let required = [
        "schema",
        "query_type",
        "search_text",
        "ledger_ids",
        "object_types",
        "scope",
        "status",
        "relationships",
        "search_profile",
        "extraction_profile",
        "embedding_model",
        "ordering_profile",
        "page_size",
        "prior_cursor",
    ];
    if object.len() != required.len() || required.iter().any(|field| !object.contains_key(*field)) {
        return Err(Error::InvalidQuery);
    }
    if object.get("schema").and_then(serde_json::Value::as_str) != Some("facts-protocol-query-v0") {
        return Err(Error::InvalidQuery);
    }
    let query_type = object
        .get("query_type")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::InvalidQuery)?;
    if !["fact", "object", "history", "pending", "relationship"].contains(&query_type) {
        return Err(Error::InvalidQuery);
    }
    if !object
        .get("search_text")
        .is_some_and(|value| value.is_null() || value.is_string())
    {
        return Err(Error::InvalidQuery);
    }
    validate_sorted_ids(object.get("ledger_ids"))?;
    let object_types = object
        .get("object_types")
        .and_then(serde_json::Value::as_array)
        .ok_or(Error::InvalidQuery)?;
    let mut prior_type = None;
    for object_type in object_types {
        let object_type = object_type.as_str().ok_or(Error::InvalidQuery)?;
        if !fact_schema::OBJECT_TYPES.contains(&object_type)
            || prior_type.is_some_and(|prior| prior >= object_type)
        {
            return Err(Error::InvalidQuery);
        }
        prior_type = Some(object_type);
    }
    let scope = object
        .get("scope")
        .and_then(serde_json::Value::as_object)
        .ok_or(Error::InvalidQuery)?;
    if scope.len() != 4
        || [
            "actor_ids",
            "proposition_ids",
            "revision_ids",
            "deliberation_ids",
        ]
        .iter()
        .any(|field| !scope.contains_key(*field))
    {
        return Err(Error::InvalidQuery);
    }
    for field in [
        "actor_ids",
        "proposition_ids",
        "revision_ids",
        "deliberation_ids",
    ] {
        validate_sorted_ids(scope.get(field))?;
    }
    let status = object
        .get("status")
        .and_then(serde_json::Value::as_object)
        .ok_or(Error::InvalidQuery)?;
    let statuses = [
        "accepted",
        "rejected",
        "settled",
        "archived",
        "withdrawn",
        "divergent",
    ];
    if status.len() != statuses.len()
        || statuses.iter().any(|field| {
            !status
                .get(*field)
                .is_some_and(|value| value.is_null() || value.is_boolean())
        })
    {
        return Err(Error::InvalidQuery);
    }
    let relationships = object
        .get("relationships")
        .and_then(serde_json::Value::as_array)
        .ok_or(Error::InvalidQuery)?;
    let mut previous_relationship = None;
    for relationship in relationships {
        let relationship = relationship.as_object().ok_or(Error::InvalidQuery)?;
        if relationship.len() != 3
            || relationship
                .get("type")
                .and_then(serde_json::Value::as_str)
                .is_none()
            || !["in", "out", "either"].contains(
                &relationship
                    .get("direction")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidQuery)?,
            )
        {
            return Err(Error::InvalidQuery);
        }
        let other_object_id = relationship
            .get("other_object_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::InvalidQuery)?;
        parse_id(Some(other_object_id))?;
        let relationship_key = (
            relationship
                .get("type")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidQuery)?,
            relationship
                .get("direction")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidQuery)?,
            other_object_id,
        );
        if previous_relationship.is_some_and(|previous| previous >= relationship_key) {
            return Err(Error::InvalidQuery);
        }
        previous_relationship = Some(relationship_key);
    }
    validate_profile_object(object.get("search_profile"))?;
    validate_profile_object(object.get("extraction_profile"))?;
    let search_profile = object
        .get("search_profile")
        .and_then(serde_json::Value::as_object)
        .ok_or(Error::InvalidQuery)?;
    let search_profile_id = search_profile
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::InvalidQuery)?;
    let search_profile_version = search_profile
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::InvalidQuery)?;
    if search_profile_version != "0"
        || ![
            "hash-asc-v0",
            "lexical-bm25-v0",
            "semantic-cosine-v0",
            "provider-score-v0",
        ]
        .contains(&search_profile_id)
    {
        return Err(Error::InvalidQuery);
    }
    if let Some(model) = object.get("embedding_model") {
        if !model.is_null() {
            let model = model.as_object().ok_or(Error::InvalidQuery)?;
            if model.len() != 3
                || ["provider", "model", "version"].iter().any(|field| {
                    model
                        .get(*field)
                        .and_then(serde_json::Value::as_str)
                        .is_none()
                })
            {
                return Err(Error::InvalidQuery);
            }
        }
    }
    let expected_ordering = if matches!(
        query_type,
        "object" | "history" | "pending" | "relationship"
    ) {
        "hash-asc-v0"
    } else {
        "score-desc-hash-asc-v0"
    };
    let search_text_is_present = object
        .get("search_text")
        .and_then(serde_json::Value::as_str)
        .is_some();
    let embedding_is_present = object
        .get("embedding_model")
        .is_some_and(|value| !value.is_null());
    match search_profile_id {
        "hash-asc-v0" if query_type == "fact" || search_text_is_present || embedding_is_present => {
            return Err(Error::InvalidQuery)
        }
        "lexical-bm25-v0"
            if query_type != "fact" || !search_text_is_present || embedding_is_present =>
        {
            return Err(Error::InvalidQuery)
        }
        "semantic-cosine-v0" if !search_text_is_present || !embedding_is_present => {
            return Err(Error::InvalidQuery)
        }
        "provider-score-v0" if !embedding_is_present => return Err(Error::InvalidQuery),
        _ => {}
    }
    if query_type != "fact" && search_profile_id != "hash-asc-v0" {
        return Err(Error::InvalidQuery);
    }
    if object
        .get("ordering_profile")
        .and_then(serde_json::Value::as_str)
        != Some(expected_ordering)
        || !object
            .get("page_size")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|size| (1..=1000).contains(&size))
    {
        return Err(Error::InvalidQuery);
    }
    if !object
        .get("prior_cursor")
        .is_some_and(|value| value.is_null() || value.is_string())
    {
        return Err(Error::InvalidQuery);
    }
    let mut digest_value = value;
    digest_value["prior_cursor"] = serde_json::Value::Null;
    let digest_bytes = fact_canonical::encode(
        &serde_json::to_vec(&digest_value).map_err(|_| Error::InvalidQuery)?,
    )
    .map_err(|_| Error::InvalidQuery)?;
    Ok(CanonicalQuery {
        bytes,
        digest: Hash::digest(&digest_bytes),
    })
}

fn parse_id(value: Option<&str>) -> Result<(), Error> {
    value
        .ok_or(Error::InvalidQuery)?
        .parse::<fact_core::ObjectId>()
        .map_err(|_| Error::InvalidQuery)
        .map(|_| ())
}

fn validate_sorted_ids(value: Option<&serde_json::Value>) -> Result<(), Error> {
    let values = value
        .and_then(serde_json::Value::as_array)
        .ok_or(Error::InvalidQuery)?;
    let mut previous = None;
    for value in values {
        let text = value.as_str().ok_or(Error::InvalidQuery)?;
        parse_id(Some(text))?;
        if previous.is_some_and(|prior| prior >= text) {
            return Err(Error::InvalidQuery);
        }
        previous = Some(text);
    }
    Ok(())
}

fn validate_profile_object(value: Option<&serde_json::Value>) -> Result<(), Error> {
    let profile = value
        .and_then(serde_json::Value::as_object)
        .ok_or(Error::InvalidQuery)?;
    if profile.len() != 2
        || profile
            .get("id")
            .and_then(serde_json::Value::as_str)
            .is_none()
        || profile
            .get("version")
            .and_then(serde_json::Value::as_str)
            .is_none()
    {
        return Err(Error::InvalidQuery);
    }
    Ok(())
}

pub fn parse_score(text: &str) -> Result<Decimal, Error> {
    if text.is_empty() {
        return Err(Error::Grammar);
    }
    let (negative, body) = text.strip_prefix('-').map_or((false, text), |x| (true, x));
    let mut pieces = body.split('.');
    let integer = pieces.next().unwrap();
    let fraction = pieces.next();
    if pieces.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|c| c.is_ascii_digit())
        || (integer.len() > 1 && integer.starts_with('0'))
    {
        return Err(Error::Grammar);
    }
    let fraction = fraction.unwrap_or("");
    if text.contains('.')
        && (fraction.is_empty()
            || !fraction.bytes().all(|c| c.is_ascii_digit())
            || fraction.ends_with('0'))
    {
        return Err(Error::Grammar);
    }
    if negative && integer == "0" && fraction.chars().all(|c| c == '0') {
        return Err(Error::Grammar);
    }
    Ok(Decimal {
        negative,
        integer: integer.to_string(),
        fraction: fraction.to_string(),
    })
}
pub fn validate_score(profile: Profile, text: &str) -> Result<Decimal, Error> {
    let score = parse_score(text)?;
    match profile {
        Profile::HashAsc => {
            if text != "0" {
                return Err(Error::Sentinel);
            }
        }
        Profile::LexicalBm25 | Profile::ProviderScore => {
            if score.negative || score.integer.len() > 12 || score.fraction.len() > 6 {
                return Err(if score.fraction.len() > 6 {
                    Error::Scale
                } else {
                    Error::Range
                });
            }
        }
        Profile::SemanticCosine => {
            if score.negative
                || score.fraction.len() > 9
                || score.integer.as_str() > "1"
                || (score.integer == "1" && score.fraction.chars().any(|c| c != '0'))
            {
                return Err(if score.fraction.len() > 9 {
                    Error::Scale
                } else {
                    Error::Range
                });
            }
        }
    }
    Ok(score)
}
impl Decimal {
    pub fn cmp_numeric(&self, other: &Self) -> Ordering {
        if self.negative != other.negative {
            return if self.negative {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        };
        let sign = if self.negative { -1 } else { 1 };
        let i = trim_zero(&self.integer).cmp(trim_zero(&other.integer));
        let f = pad_cmp(&self.fraction, &other.fraction);
        let result = if i == Ordering::Equal { f } else { i };
        if sign < 0 {
            result.reverse()
        } else {
            result
        }
    }
}
fn trim_zero(s: &str) -> &str {
    let x = s.trim_start_matches('0');
    if x.is_empty() {
        "0"
    } else {
        x
    }
}
fn pad_cmp(a: &str, b: &str) -> Ordering {
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.as_bytes().get(i).copied().unwrap_or(b'0');
        let y = b.as_bytes().get(i).copied().unwrap_or(b'0');
        if x != y {
            return x.cmp(&y);
        }
    }
    Ordering::Equal
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ranked {
    pub hash: Hash,
    pub score: String,
}
pub fn order(profile: Profile, mut results: Vec<Ranked>) -> Result<Vec<Ranked>, Error> {
    for r in &results {
        validate_score(profile, &r.score)?;
    }
    results.sort_by(|a, b| {
        if profile == Profile::HashAsc {
            a.hash.cmp(&b.hash)
        } else {
            let sa = parse_score(&a.score).unwrap();
            let sb = parse_score(&b.score).unwrap();
            sb.cmp_numeric(&sa).then_with(|| a.hash.cmp(&b.hash))
        }
    });
    Ok(results)
}

pub const EXTRACTION_PROFILE: &str = "facts-markdown-extraction-v0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResult {
    pub ranked: Ranked,
    pub extraction_profile: &'static str,
}

#[cfg(debug_assertions)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LexicalIndexDebugMetrics {
    pub candidate_rows: u64,
    pub document_frequency_queries: u64,
    pub rebuilds: u64,
}

#[cfg(debug_assertions)]
struct LexicalIndexDebugMetricCounters {
    candidate_rows: Cell<u64>,
    document_frequency_queries: Cell<u64>,
    rebuilds: Cell<u64>,
}

#[cfg(debug_assertions)]
impl LexicalIndexDebugMetricCounters {
    const fn new() -> Self {
        Self {
            candidate_rows: Cell::new(0),
            document_frequency_queries: Cell::new(0),
            rebuilds: Cell::new(0),
        }
    }

    fn reset(&self) {
        self.candidate_rows.set(0);
        self.document_frequency_queries.set(0);
        self.rebuilds.set(0);
    }

    fn snapshot(&self) -> LexicalIndexDebugMetrics {
        LexicalIndexDebugMetrics {
            candidate_rows: self.candidate_rows.get(),
            document_frequency_queries: self.document_frequency_queries.get(),
            rebuilds: self.rebuilds.get(),
        }
    }
}

#[cfg(debug_assertions)]
thread_local! {
    static LEXICAL_INDEX_DEBUG_METRICS: LexicalIndexDebugMetricCounters = const { LexicalIndexDebugMetricCounters::new() };
}

pub struct LexicalIndex {
    conn: Connection,
}
impl LexicalIndex {
    pub fn open_memory() -> Result<Self, Error> {
        let conn = Connection::open_in_memory()?;
        let index = Self { conn };
        index.migrate()?;
        Ok(index)
    }

    #[cfg(debug_assertions)]
    pub fn reset_debug_metrics() {
        LEXICAL_INDEX_DEBUG_METRICS.with(LexicalIndexDebugMetricCounters::reset);
    }

    #[cfg(debug_assertions)]
    pub fn debug_metrics() -> LexicalIndexDebugMetrics {
        LEXICAL_INDEX_DEBUG_METRICS.with(LexicalIndexDebugMetricCounters::snapshot)
    }

    fn migrate(&self) -> Result<(), Error> {
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS search_document (content_hash BLOB PRIMARY KEY, extracted_text TEXT NOT NULL, token_count INTEGER NOT NULL, term_frequencies TEXT NOT NULL DEFAULT '{}'); CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(content_hash UNINDEXED, extracted_text, tokenize='unicode61');")?;
        let term_frequencies_present: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('search_document') WHERE name='term_frequencies'",
            [],
            |row| row.get(0),
        )?;
        if term_frequencies_present == 0 {
            self.conn.execute_batch(
                "ALTER TABLE search_document ADD COLUMN term_frequencies TEXT NOT NULL DEFAULT '{}';",
            )?;
        }
        let _ = self
            .conn
            .query_row("SELECT count(*) FROM search_fts", [], |r| {
                r.get::<_, i64>(0)
            })
            .map_err(|_| Error::FtsUnavailable)?;
        Ok(())
    }
    pub fn insert_markdown(&self, hash: Hash, markdown: &[u8]) -> Result<(), Error> {
        let tx = self.conn.unchecked_transaction()?;
        insert_markdown_tx(&tx, hash, markdown)?;
        tx.commit()?;
        Ok(())
    }
    pub fn rebuild(&self, documents: &[(Hash, Vec<u8>)]) -> Result<(), Error> {
        #[cfg(debug_assertions)]
        LEXICAL_INDEX_DEBUG_METRICS
            .with(|metrics| metrics.rebuilds.set(metrics.rebuilds.get() + 1));
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch("DELETE FROM search_fts; DELETE FROM search_document;")?;
        for (hash, markdown) in documents {
            insert_markdown_tx(&tx, *hash, markdown)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchResult>, Error> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let query_tokens = tokenize(query);
        if query_tokens.is_empty() {
            return Ok(Vec::new());
        }
        let unique = unique_tokens(query_tokens);
        let match_query = unique
            .iter()
            .map(|x| format!("\"{}\"", x.replace('"', "")))
            .collect::<Vec<_>>()
            .join(" AND ");
        let mut sql = "SELECT d.content_hash,d.term_frequencies,d.token_count
             FROM search_fts f
             JOIN search_document d ON d.content_hash=f.content_hash
             WHERE search_fts MATCH ?"
            .to_owned();
        let mut values = vec![Value::Text(match_query)];
        if limit != usize::MAX {
            sql.push_str(" ORDER BY bm25(search_fts) LIMIT ?");
            values.push(Value::Integer(limit.min(i64::MAX as usize) as i64));
        }
        let mut candidate_stmt = self.conn.prepare(&sql)?;
        let candidates = candidate_stmt
            .query_map(params_from_iter(values.iter()), |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        #[cfg(debug_assertions)]
        LEXICAL_INDEX_DEBUG_METRICS.with(|metrics| {
            metrics
                .candidate_rows
                .set(metrics.candidate_rows.get() + candidates.len() as u64);
        });
        let n = self
            .conn
            .query_row("SELECT count(*) FROM search_document", [], |r| {
                r.get::<_, i64>(0)
            })? as f64;
        let total_len = self.conn.query_row(
            "SELECT coalesce(sum(token_count),0) FROM search_document",
            [],
            |r| r.get::<_, i64>(0),
        )? as f64;
        let avgdl = if n == 0.0 { 1.0 } else { total_len / n };
        let document_frequencies = self.document_frequencies(&unique)?;
        let mut results = Vec::new();
        for (raw, term_frequencies, dl) in candidates {
            let hash: [u8; 32] = raw.try_into().map_err(|_| Error::StoredHash)?;
            let h = Hash::from_bytes(hash);
            let term_frequencies = parse_term_frequencies(&term_frequencies)?;
            let mut score = 0.0;
            for term in &unique {
                let tf = term_frequencies.get(term).copied().unwrap_or(0) as f64;
                if tf == 0.0 {
                    continue;
                }
                let df = *document_frequencies.get(term).unwrap_or(&0) as f64;
                let idf = (1.0 + (n - df + 0.5) / (df + 0.5)).ln();
                score += idf * (tf * 2.2) / (tf + 1.2 * (1.0 - 0.75 + 0.75 * dl as f64 / avgdl));
            }
            results.push(SearchResult {
                ranked: Ranked {
                    hash: h,
                    score: serialize_score(score),
                },
                extraction_profile: EXTRACTION_PROFILE,
            });
        }
        let mut ranked = results.into_iter().map(|x| x.ranked).collect::<Vec<_>>();
        ranked = order(Profile::LexicalBm25, ranked)?;
        if ranked.len() > limit {
            ranked.truncate(limit)
        }
        Ok(ranked
            .into_iter()
            .map(|r| SearchResult {
                ranked: r,
                extraction_profile: EXTRACTION_PROFILE,
            })
            .collect())
    }

    fn document_frequencies(&self, terms: &[String]) -> Result<HashMap<String, i64>, Error> {
        let mut frequencies = HashMap::with_capacity(terms.len());
        let mut statement = self
            .conn
            .prepare("SELECT count(*) FROM search_fts WHERE search_fts MATCH ?")?;
        for term in terms {
            #[cfg(debug_assertions)]
            LEXICAL_INDEX_DEBUG_METRICS.with(|metrics| {
                metrics
                    .document_frequency_queries
                    .set(metrics.document_frequency_queries.get() + 1);
            });
            let count = statement.query_row([format!("\"{}\"", term)], |row| row.get(0))?;
            frequencies.insert(term.clone(), count);
        }
        Ok(frequencies)
    }
}

fn insert_markdown_tx(
    tx: &rusqlite::Transaction<'_>,
    hash: Hash,
    markdown: &[u8],
) -> Result<(), Error> {
    fact_canonical::validate_canonical_markdown(markdown)?;
    let text = extract_markdown(markdown);
    let tokens = tokenize(&text);
    let term_frequencies =
        serde_json::to_string(&token_frequencies(&tokens)).map_err(|_| Error::InvalidQuery)?;
    tx.execute(
        "DELETE FROM search_fts WHERE content_hash=?",
        params![hash.as_bytes().as_slice()],
    )?;
    tx.execute("INSERT OR REPLACE INTO search_document(content_hash,extracted_text,token_count,term_frequencies) VALUES(?,?,?,?)",params![hash.as_bytes().as_slice(),text,tokens.len() as i64,term_frequencies])?;
    tx.execute(
        "INSERT INTO search_fts(content_hash,extracted_text) VALUES(?,?)",
        params![hash.as_bytes().as_slice(), tokens.join(" ")],
    )?;
    Ok(())
}

pub fn extract_markdown(markdown: &[u8]) -> String {
    let text = std::str::from_utf8(markdown).unwrap_or_default();
    let mut out = String::new();
    for line in text.lines() {
        let mut l = line.trim();
        if l.starts_with("```") || l.starts_with("~~~") {
            continue;
        }
        while let Some(x) = l.strip_prefix('#') {
            l = x.trim_start()
        }
        if let Some(x) = l.strip_prefix('>') {
            l = x.trim_start()
        }
        if l.starts_with('-') || l.starts_with('*') || l.starts_with('+') {
            l = l[1..].trim_start()
        }
        out.push_str(l);
        out.push(' ')
    }
    out
}
pub fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    for c in text.chars() {
        if c.is_alphanumeric() {
            for x in c.to_lowercase() {
                word.push(x)
            }
        } else if !word.is_empty() {
            tokens.push(std::mem::take(&mut word));
        }
    }
    if !word.is_empty() {
        tokens.push(word)
    }
    tokens
}
fn unique_tokens(mut tokens: Vec<String>) -> Vec<String> {
    tokens.sort();
    tokens.dedup();
    tokens
}
fn token_frequencies(tokens: &[String]) -> BTreeMap<String, u64> {
    let mut frequencies = BTreeMap::new();
    for token in tokens {
        *frequencies.entry(token.clone()).or_default() += 1;
    }
    frequencies
}
fn parse_term_frequencies(text: &str) -> Result<BTreeMap<String, u64>, Error> {
    serde_json::from_str(text).map_err(|_| Error::InvalidQuery)
}
fn serialize_score(score: f64) -> String {
    let scaled = round_half_even(score * 1_000_000.0) as u64;
    let integer = scaled / 1_000_000;
    let fraction = scaled % 1_000_000;
    if fraction == 0 {
        return integer.to_string();
    }
    let mut f = format!("{:06}", fraction);
    while f.ends_with('0') {
        f.pop();
    }
    format!("{}.{}", integer, f)
}
fn round_half_even(value: f64) -> f64 {
    let floor = value.floor();
    let frac = value - floor;
    if frac < 0.5 {
        floor
    } else if frac > 0.5 {
        floor + 1.0
    } else if (floor as u64) & 1 == 0 {
        floor
    } else {
        floor + 1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(n: u8) -> Hash {
        let mut b = [0; 32];
        b[31] = n;
        Hash::from_bytes(b)
    }
    #[test]
    fn grammar() {
        assert!(parse_score("-0").is_err());
        assert!(parse_score("1.200").is_err());
        assert!(parse_score("01").is_err());
        assert!(parse_score("1e2").is_err());
        assert!(validate_score(Profile::SemanticCosine, "1").is_ok());
        assert!(validate_score(Profile::SemanticCosine, "1.000000001").is_err())
    }

    #[test]
    fn canonical_query_binds_all_fields_but_not_cursor_position() {
        let query = serde_json::json!({
            "schema": "facts-protocol-query-v0",
            "query_type": "object",
            "search_text": null,
            "ledger_ids": [],
            "object_types": ["actor", "key"],
            "scope": {"actor_ids": [], "proposition_ids": [], "revision_ids": [], "deliberation_ids": []},
            "status": {"accepted":null,"rejected":null,"settled":null,"archived":null,"withdrawn":null,"divergent":null},
            "relationships": [],
            "search_profile": {"id":"hash-asc-v0","version":"0"},
            "extraction_profile": {"id":"facts-markdown-extraction-v0","version":"0"},
            "embedding_model": null,
            "ordering_profile": "hash-asc-v0",
            "page_size": 25,
            "prior_cursor": null
        });
        let first = canonical_query(&serde_json::to_vec(&query).unwrap()).unwrap();
        let mut history = query.clone();
        history["query_type"] = serde_json::Value::String("history".into());
        assert!(canonical_query(&serde_json::to_vec(&history).unwrap()).is_ok());
        let mut paged = query;
        paged["prior_cursor"] = serde_json::Value::String("opaque".into());
        let second = canonical_query(&serde_json::to_vec(&paged).unwrap()).unwrap();
        assert_eq!(first.digest, second.digest);
        assert_ne!(first.bytes, second.bytes);
    }

    #[test]
    fn canonical_query_rejects_unregistered_profiles_and_duplicate_relationships() {
        let mut query = serde_json::json!({
            "schema": "facts-protocol-query-v0",
            "query_type": "object",
            "search_text": null,
            "ledger_ids": [],
            "object_types": [],
            "scope": {"actor_ids": [], "proposition_ids": [], "revision_ids": [], "deliberation_ids": []},
            "status": {"accepted":null,"rejected":null,"settled":null,"archived":null,"withdrawn":null,"divergent":null},
            "relationships": [],
            "search_profile": {"id":"hash-asc-v0","version":"0"},
            "extraction_profile": {"id":"facts-markdown-extraction-v0","version":"0"},
            "embedding_model": null,
            "ordering_profile": "hash-asc-v0",
            "page_size": 25,
            "prior_cursor": null
        });
        query["search_profile"]["id"] = serde_json::Value::String("unknown-v0".into());
        assert!(canonical_query(&serde_json::to_vec(&query).unwrap()).is_err());

        let other = ObjectId::new_v7().to_string();
        let relationship = serde_json::json!({
            "type":"protocol:related",
            "direction":"out",
            "other_object_id":other
        });
        query["search_profile"]["id"] = serde_json::Value::String("hash-asc-v0".into());
        query["relationships"] = serde_json::json!([relationship.clone(), relationship]);
        assert!(canonical_query(&serde_json::to_vec(&query).unwrap()).is_err());
    }

    #[test]
    fn signed_cursor_binds_query_commitment_profiles_and_expiry() {
        let key = SigningKey::from_seed(&[7u8; 32]).unwrap();
        let search_profile = ProfileDescriptor {
            id: "lexical-bm25-v0".into(),
            version: "0".into(),
        };
        let extraction_profile = ProfileDescriptor {
            id: EXTRACTION_PROFILE.into(),
            version: "0".into(),
        };
        let cursor = Cursor {
            query_digest: h(1),
            coordinator_actor_id: ObjectId::new_v7(),
            input_commitment_hash: h(2),
            ordering_profile: "score-desc-hash-asc-v0".into(),
            search_profile: search_profile.clone(),
            extraction_profile: extraction_profile.clone(),
            next_offset: 25,
            preceding_score: Some("1.25".into()),
            preceding_object_hash: Some(h(3)),
            expires_at: Some("2026-07-27T13:00:00.000Z".into()),
        };
        let ledger = [4u8; 16];
        let encoded = encode_cursor(&cursor, &key, Some(ledger)).unwrap();
        let expectation = CursorExpectation {
            query_digest: h(1),
            coordinator_actor_id: cursor.coordinator_actor_id,
            input_commitment_hash: h(2),
            ordering_profile: "score-desc-hash-asc-v0",
            search_profile: &search_profile,
            extraction_profile: &extraction_profile,
            ledger: Some(ledger),
        };
        assert_eq!(
            decode_cursor(
                &encoded,
                key.public_key(),
                &expectation,
                Some("2026-07-27T12:00:00.000Z")
            )
            .unwrap(),
            cursor
        );
        assert!(matches!(
            decode_cursor(
                &encoded,
                key.public_key(),
                &CursorExpectation {
                    query_digest: h(9),
                    ..expectation.clone()
                },
                None
            ),
            Err(Error::InvalidCursor)
        ));
        assert!(matches!(
            decode_cursor(
                &encoded,
                key.public_key(),
                &CursorExpectation {
                    query_digest: h(1),
                    ..expectation
                },
                Some("2026-07-27T14:00:00.000Z")
            ),
            Err(Error::InvalidCursor)
        ));
    }
    #[test]
    fn numeric_order_and_hash_tie() {
        let x = order(
            Profile::LexicalBm25,
            vec![
                Ranked {
                    hash: h(2),
                    score: "1.2".into(),
                },
                Ranked {
                    hash: h(1),
                    score: "1.1".into(),
                },
                Ranked {
                    hash: h(3),
                    score: "2".into(),
                },
            ],
        )
        .unwrap();
        assert_eq!(
            x.into_iter().map(|r| r.hash).collect::<Vec<_>>(),
            vec![h(3), h(2), h(1)]
        );
        assert!(order(
            Profile::HashAsc,
            vec![Ranked {
                hash: h(2),
                score: "1".into()
            }]
        )
        .is_err())
    }

    #[test]
    fn fts5_index_is_rebuildable_and_scores_repeatably() {
        let index = LexicalIndex::open_memory().unwrap();
        let first = b"# Rust\nRust facts are signed.\n";
        let second = b"# SQLite\nSQLite stores facts.\n";
        let docs = vec![(h(1), first.to_vec()), (h(2), second.to_vec())];
        index.rebuild(&docs).unwrap();
        let one = index.search("RUST rust", 10).unwrap();
        let two = index.search("rust", 10).unwrap();
        assert_eq!(one, two);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].ranked.hash, h(1));
        assert_eq!(one[0].extraction_profile, EXTRACTION_PROFILE);
        assert!(validate_score(Profile::LexicalBm25, &one[0].ranked.score).is_ok());
        let term_frequencies: String = index
            .conn
            .query_row(
                "SELECT term_frequencies FROM search_document WHERE content_hash=?",
                [h(1).as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let term_frequencies = parse_term_frequencies(&term_frequencies).unwrap();
        assert_eq!(term_frequencies.get("rust"), Some(&2));
        assert_eq!(term_frequencies.get("facts"), Some(&1));
        assert!(index.insert_markdown(h(1), first).is_ok());
        assert_eq!(index.search("rust", 10).unwrap(), one);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn fts5_search_limits_candidates_and_caches_document_frequencies() {
        let index = LexicalIndex::open_memory().unwrap();
        let documents = (0..20)
            .map(|number| {
                (
                    h(number + 1),
                    format!("# Document {number}\ncommon alpha content {number}.\n").into_bytes(),
                )
            })
            .collect::<Vec<_>>();
        LexicalIndex::reset_debug_metrics();
        index.rebuild(&documents).unwrap();
        assert_eq!(LexicalIndex::debug_metrics().rebuilds, 1);

        LexicalIndex::reset_debug_metrics();
        let results = index.search("common alpha", 5).unwrap();
        assert_eq!(results.len(), 5);
        let metrics = LexicalIndex::debug_metrics();
        assert_eq!(metrics.candidate_rows, 5);
        assert_eq!(metrics.document_frequency_queries, 2);

        LexicalIndex::reset_debug_metrics();
        assert!(index.search("common alpha", 0).unwrap().is_empty());
        assert_eq!(
            LexicalIndex::debug_metrics(),
            LexicalIndexDebugMetrics::default()
        );
    }
}
