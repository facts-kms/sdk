use fact_core::Hash;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("duplicate content hash")]
    Duplicate,
    #[error("index out of bounds")]
    Index,
    #[error("invalid proof")]
    InvalidProof,
    #[error("content hash is already present")]
    Present,
}
fn leaf(h: &Hash) -> Hash {
    let mut x = Sha256::new();
    x.update([0]);
    x.update(h.as_bytes());
    Hash::from_bytes(x.finalize().into())
}
fn node(a: &Hash, b: &Hash) -> Hash {
    let mut x = Sha256::new();
    x.update([1]);
    x.update(a.as_bytes());
    x.update(b.as_bytes());
    Hash::from_bytes(x.finalize().into())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: Hash,
    pub sibling_left: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonInclusionProof {
    pub left: Option<(Hash, Vec<ProofStep>)>,
    pub right: Option<(Hash, Vec<ProofStep>)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleTree {
    pub leaves: Vec<Hash>,
    pub root: Hash,
}
impl MerkleTree {
    pub fn new(mut hs: Vec<Hash>) -> Result<Self, Error> {
        hs.sort();
        if hs.windows(2).any(|x| x[0] == x[1]) {
            return Err(Error::Duplicate);
        }
        let root = calc(&hs);
        Ok(Self { leaves: hs, root })
    }
    pub fn proof(&self, index: usize) -> Result<Vec<ProofStep>, Error> {
        if index >= self.leaves.len() {
            return Err(Error::Index);
        };
        proof(&self.leaves, index)
    }

    pub fn non_inclusion_proof(&self, target: Hash) -> Result<NonInclusionProof, Error> {
        let insertion = self
            .leaves
            .binary_search(&target)
            .unwrap_or_else(|index| index);
        if self.leaves.get(insertion) == Some(&target) {
            return Err(Error::Present);
        }
        Ok(NonInclusionProof {
            left: insertion.checked_sub(1).map(|index| {
                (
                    self.leaves[index],
                    self.proof(index).expect("neighbor index is in bounds"),
                )
            }),
            right: (insertion < self.leaves.len()).then(|| {
                (
                    self.leaves[insertion],
                    self.proof(insertion).expect("neighbor index is in bounds"),
                )
            }),
        })
    }
}
fn calc(hs: &[Hash]) -> Hash {
    if hs.is_empty() {
        return Hash::digest(&[]);
    }
    if hs.len() == 1 {
        return leaf(&hs[0]);
    }
    let k = largest_power_below(hs.len());
    node(&calc(&hs[..k]), &calc(&hs[k..]))
}
fn largest_power_below(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2
    }
    k
}
fn proof(hs: &[Hash], i: usize) -> Result<Vec<ProofStep>, Error> {
    if hs.len() <= 1 {
        return Ok(vec![]);
    }
    let k = largest_power_below(hs.len());
    if i < k {
        let mut p = proof(&hs[..k], i)?;
        p.push(ProofStep {
            sibling: calc(&hs[k..]),
            sibling_left: false,
        });
        Ok(p)
    } else {
        let mut p = proof(&hs[k..], i - k)?;
        p.push(ProofStep {
            sibling: calc(&hs[..k]),
            sibling_left: true,
        });
        Ok(p)
    }
}
pub fn verify(content_hash: Hash, proof: &[ProofStep], root: Hash) -> bool {
    let mut x = leaf(&content_hash);
    for s in proof {
        x = if s.sibling_left {
            node(&s.sibling, &x)
        } else {
            node(&x, &s.sibling)
        }
    }
    x == root
}

pub fn verify_non_inclusion(target: Hash, proof: &NonInclusionProof, root: Hash) -> bool {
    if let Some((left, steps)) = &proof.left {
        if *left >= target || !verify(*left, steps, root) {
            return false;
        }
    }
    if let Some((right, steps)) = &proof.right {
        if *right <= target || !verify(*right, steps, root) {
            return false;
        }
    }
    match (&proof.left, &proof.right) {
        (Some((left, _)), Some((right, _))) => left < right,
        (None, Some(_)) | (Some(_), None) => true,
        (None, None) => root == Hash::digest(&[]),
    }
}

const MAX_MANIFEST: usize = 512 * 1024 * 1024;
const MAX_OBJECT: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("invalid frame magic")]
    Magic,
    #[error("truncated frame")]
    Truncated,
    #[error("manifest or object exceeds profile limit")]
    TooLarge,
    #[error("manifest is not canonical JSON")]
    Manifest,
    #[error("manifest object_count does not match frames")]
    Count,
    #[error("objects are not sorted by content hash")]
    Order,
    #[error("duplicate object content hash")]
    Duplicate,
    #[error("invalid COSE object")]
    Cose,
    #[error("object content hash mismatch")]
    Hash,
    #[error("snapshot commitment does not bind the manifest and frames")]
    Commitment,
    #[error("I/O: {0}")]
    Io(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramedObjects {
    pub manifest: Vec<u8>,
    pub objects: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BorrowedFramedObjects<'a> {
    pub manifest: &'a [u8],
    pub objects: Vec<&'a [u8]>,
}

/// Derive a stable transport UUID for a bundle from its sorted raw content
/// hashes. The UUID is not protocol causality or ledger identity; it only
/// makes locally produced equivalent bundles byte-reproducible.
pub fn deterministic_bundle_id(objects: &[(Hash, Vec<u8>)]) -> uuid::Uuid {
    deterministic_bundle_id_from_hashes(objects.iter().map(|(hash, _)| *hash))
}

/// Derive a stable transport UUID for a bundle from raw content hashes without
/// requiring object bytes to be materialized.
pub fn deterministic_bundle_id_from_hashes<I>(hashes: I) -> uuid::Uuid
where
    I: IntoIterator<Item = Hash>,
{
    let mut sorted = hashes.into_iter().collect::<Vec<_>>();
    sorted.sort();
    let mut bytes = Vec::with_capacity(sorted.len() * 32);
    for hash in sorted {
        bytes.extend_from_slice(hash.as_bytes());
    }
    let digest = Hash::digest(&bytes);
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes[0..8].copy_from_slice(&[0x01, 0x90, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00]);
    uuid_bytes[8..].copy_from_slice(&digest.as_bytes()[..8]);
    uuid_bytes[6] = 0x70 | (digest.as_bytes()[6] & 0x0f);
    uuid_bytes[8] = 0x80 | (digest.as_bytes()[0] & 0x3f);
    uuid::Uuid::from_bytes(uuid_bytes)
}

pub fn encode_snapshot(
    manifest: &[u8],
    objects: &[(Hash, Vec<u8>)],
) -> Result<Vec<u8>, FrameError> {
    encode_framed(*b"FACTSNAP", manifest, objects)
}
pub fn encode_bundle(manifest: &[u8], objects: &[(Hash, Vec<u8>)]) -> Result<Vec<u8>, FrameError> {
    encode_framed(*b"FACTBNDL", manifest, objects)
}

/// Write a bundle frame for objects that are already sorted by content hash.
///
/// Unlike [`encode_bundle`], this does not collect or clone all object bytes.
/// The caller is responsible for supplying objects in strict content-hash
/// order.
pub fn write_bundle_sorted<W, I>(
    writer: W,
    manifest: &[u8],
    objects: I,
) -> Result<usize, FrameError>
where
    W: std::io::Write,
    I: IntoIterator<Item = (Hash, Vec<u8>)>,
{
    try_write_bundle_sorted(
        writer,
        manifest,
        objects.into_iter().map(Ok::<_, FrameError>),
    )
}

/// Write a bundle frame for a fallible source of sorted objects.
pub fn try_write_bundle_sorted<W, I, E>(writer: W, manifest: &[u8], objects: I) -> Result<usize, E>
where
    W: std::io::Write,
    I: IntoIterator<Item = Result<(Hash, Vec<u8>), E>>,
    E: From<FrameError>,
{
    try_write_framed_sorted(*b"FACTBNDL", writer, manifest, objects)
}

/// Write a bundle frame for borrowed objects that are already sorted by content
/// hash.
pub fn try_write_bundle_sorted_slices<'a, W, I, E>(
    writer: W,
    manifest: &[u8],
    objects: I,
) -> Result<usize, E>
where
    W: std::io::Write,
    I: IntoIterator<Item = Result<(Hash, &'a [u8]), E>>,
    E: From<FrameError>,
{
    try_write_framed_sorted_slices(*b"FACTBNDL", writer, manifest, objects)
}

fn encode_framed(
    magic: [u8; 8],
    manifest: &[u8],
    objects: &[(Hash, Vec<u8>)],
) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::with_capacity(12 + manifest.len());
    let mut sorted = objects
        .iter()
        .map(|(hash, bytes)| (*hash, bytes.as_slice()))
        .collect::<Vec<_>>();
    sorted.sort_by_key(|(hash, _)| *hash);
    try_write_framed_sorted_slices(
        magic,
        &mut out,
        manifest,
        sorted.into_iter().map(Ok::<_, FrameError>),
    )?;
    Ok(out)
}

fn try_write_framed_sorted<W, I, E>(
    magic: [u8; 8],
    mut writer: W,
    manifest: &[u8],
    objects: I,
) -> Result<usize, E>
where
    W: std::io::Write,
    I: IntoIterator<Item = Result<(Hash, Vec<u8>), E>>,
    E: From<FrameError>,
{
    let expected = check_manifest(magic, manifest, usize::MAX).map_err(E::from)?;
    writer
        .write_all(&magic)
        .map_err(|error| E::from(FrameError::Io(error.to_string())))?;
    writer
        .write_all(&(manifest.len() as u32).to_be_bytes())
        .map_err(|error| E::from(FrameError::Io(error.to_string())))?;
    writer
        .write_all(manifest)
        .map_err(|error| E::from(FrameError::Io(error.to_string())))?;
    let mut written = 12 + manifest.len();
    let mut count = 0usize;
    let mut previous = None;
    for item in objects {
        let (hash, object) = item?;
        if previous.is_some_and(|previous| previous >= hash) {
            return Err(if previous == Some(hash) {
                FrameError::Duplicate
            } else {
                FrameError::Order
            }
            .into());
        }
        check_object_hash(hash, &object).map_err(E::from)?;
        writer
            .write_all(&(object.len() as u64).to_be_bytes())
            .map_err(|error| E::from(FrameError::Io(error.to_string())))?;
        writer
            .write_all(&object)
            .map_err(|error| E::from(FrameError::Io(error.to_string())))?;
        written += 8 + object.len();
        previous = Some(hash);
        count += 1;
    }
    if count != expected {
        return Err(FrameError::Count.into());
    }
    Ok(written)
}

fn try_write_framed_sorted_slices<'a, W, I, E>(
    magic: [u8; 8],
    mut writer: W,
    manifest: &[u8],
    objects: I,
) -> Result<usize, E>
where
    W: std::io::Write,
    I: IntoIterator<Item = Result<(Hash, &'a [u8]), E>>,
    E: From<FrameError>,
{
    let expected = check_manifest(magic, manifest, usize::MAX).map_err(E::from)?;
    writer
        .write_all(&magic)
        .map_err(|error| E::from(FrameError::Io(error.to_string())))?;
    writer
        .write_all(&(manifest.len() as u32).to_be_bytes())
        .map_err(|error| E::from(FrameError::Io(error.to_string())))?;
    writer
        .write_all(manifest)
        .map_err(|error| E::from(FrameError::Io(error.to_string())))?;
    let mut written = 12 + manifest.len();
    let mut count = 0usize;
    let mut previous = None;
    for item in objects {
        let (hash, object) = item?;
        if previous.is_some_and(|previous| previous >= hash) {
            return Err(if previous == Some(hash) {
                FrameError::Duplicate
            } else {
                FrameError::Order
            }
            .into());
        }
        check_object_hash(hash, object).map_err(E::from)?;
        writer
            .write_all(&(object.len() as u64).to_be_bytes())
            .map_err(|error| E::from(FrameError::Io(error.to_string())))?;
        writer
            .write_all(object)
            .map_err(|error| E::from(FrameError::Io(error.to_string())))?;
        written += 8 + object.len();
        previous = Some(hash);
        count += 1;
    }
    if count != expected {
        return Err(FrameError::Count.into());
    }
    Ok(written)
}

pub fn decode_snapshot(bytes: &[u8]) -> Result<FramedObjects, FrameError> {
    decode_framed(*b"FACTSNAP", bytes)
}
pub fn decode_bundle(bytes: &[u8]) -> Result<FramedObjects, FrameError> {
    decode_framed(*b"FACTBNDL", bytes)
}

pub fn decode_snapshot_slices(bytes: &[u8]) -> Result<BorrowedFramedObjects<'_>, FrameError> {
    decode_framed_slices(*b"FACTSNAP", bytes)
}

pub fn decode_bundle_slices(bytes: &[u8]) -> Result<BorrowedFramedObjects<'_>, FrameError> {
    decode_framed_slices(*b"FACTBNDL", bytes)
}

fn decode_framed(magic: [u8; 8], bytes: &[u8]) -> Result<FramedObjects, FrameError> {
    if bytes.get(..8) != Some(&magic) {
        return Err(FrameError::Magic);
    }
    let mut p = 8;
    let manifest_len = read_u32(bytes, &mut p)? as usize;
    if manifest_len > MAX_MANIFEST {
        return Err(FrameError::TooLarge);
    };
    let manifest = read_exact(bytes, &mut p, manifest_len)?.to_vec();
    let value: serde_json::Value =
        serde_json::from_slice(&manifest).map_err(|_| FrameError::Manifest)?;
    if fact_canonical::encode(&manifest).map_err(|_| FrameError::Manifest)? != manifest {
        return Err(FrameError::Manifest);
    };
    let expected = check_manifest(magic, &manifest, usize::MAX)?;
    let mut objects = Vec::with_capacity(expected);
    let mut previous = None;
    for _ in 0..expected {
        let len = read_u64(bytes, &mut p)? as usize;
        if len > MAX_OBJECT {
            return Err(FrameError::TooLarge);
        };
        let object = read_exact(bytes, &mut p, len)?.to_vec();
        let hash = object_hash(&object)?;
        if previous.is_some_and(|h| h >= hash) {
            return Err(if previous == Some(hash) {
                FrameError::Duplicate
            } else {
                FrameError::Order
            });
        }
        previous = Some(hash);
        objects.push(object);
    }
    if p != bytes.len() {
        return Err(FrameError::Order);
    }
    if magic == *b"FACTBNDL" {
        validate_bundle_entries(&value, &objects)?;
    } else {
        validate_snapshot_commitment(&value, &objects)?;
    }
    Ok(FramedObjects { manifest, objects })
}

fn decode_framed_slices(
    magic: [u8; 8],
    bytes: &[u8],
) -> Result<BorrowedFramedObjects<'_>, FrameError> {
    if bytes.get(..8) != Some(&magic) {
        return Err(FrameError::Magic);
    }
    let mut p = 8;
    let manifest_len = read_u32(bytes, &mut p)? as usize;
    if manifest_len > MAX_MANIFEST {
        return Err(FrameError::TooLarge);
    };
    let manifest = read_exact(bytes, &mut p, manifest_len)?;
    let value: serde_json::Value =
        serde_json::from_slice(manifest).map_err(|_| FrameError::Manifest)?;
    if fact_canonical::encode(manifest).map_err(|_| FrameError::Manifest)? != manifest {
        return Err(FrameError::Manifest);
    };
    let expected = check_manifest(magic, manifest, usize::MAX)?;
    let mut objects = Vec::with_capacity(expected);
    let mut previous = None;
    for _ in 0..expected {
        let len = read_u64(bytes, &mut p)? as usize;
        if len > MAX_OBJECT {
            return Err(FrameError::TooLarge);
        };
        let object = read_exact(bytes, &mut p, len)?;
        let hash = object_hash(object)?;
        if previous.is_some_and(|h| h >= hash) {
            return Err(if previous == Some(hash) {
                FrameError::Duplicate
            } else {
                FrameError::Order
            });
        }
        previous = Some(hash);
        objects.push(object);
    }
    if p != bytes.len() {
        return Err(FrameError::Order);
    }
    if magic == *b"FACTBNDL" {
        validate_bundle_entries(&value, &objects)?;
    } else {
        validate_snapshot_commitment(&value, &objects)?;
    }
    Ok(BorrowedFramedObjects { manifest, objects })
}

fn validate_snapshot_commitment<T: AsRef<[u8]>>(
    manifest: &serde_json::Value,
    objects: &[T],
) -> Result<(), FrameError> {
    let commitment = manifest
        .get("commitment")
        .and_then(serde_json::Value::as_str)
        .and_then(decode_b64url)
        .ok_or(FrameError::Commitment)?;
    let cose = fact_crypto::decode_sign1(&commitment).map_err(|_| FrameError::Commitment)?;
    let payload = fact_canonical::encode(&cose.payload).map_err(|_| FrameError::Commitment)?;
    if payload != cose.payload {
        return Err(FrameError::Commitment);
    }
    let body: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|_| FrameError::Commitment)?;
    let body = body.as_object().ok_or(FrameError::Commitment)?;
    if !exact_fields(
        body,
        &[
            "schema",
            "coordinator_actor_id",
            "ledger_id",
            "scope",
            "scope_hash",
            "snapshot_id",
            "tree_profile",
            "root_hash",
            "object_count",
            "created_at",
            "previous_commitment_hash",
            "signing_key_fingerprint",
        ],
    ) || body.get("schema").and_then(serde_json::Value::as_str)
        != Some("facts-protocol-commitment-v0")
        || body.get("tree_profile").and_then(serde_json::Value::as_str)
            != Some("facts-protocol-merkle-v0")
        || body.get("previous_commitment_hash").is_some_and(|value| {
            !value.is_null()
                && value
                    .as_str()
                    .and_then(|value| value.parse::<Hash>().ok())
                    .is_none()
        })
    {
        return Err(FrameError::Commitment);
    }
    let ledger = manifest
        .get("ledger_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(FrameError::Commitment)?;
    if body.get("ledger_id").and_then(serde_json::Value::as_str) != Some(ledger)
        || body.get("scope") != manifest.get("scope")
        || body.get("object_count").and_then(serde_json::Value::as_u64)
            != Some(objects.len() as u64)
    {
        return Err(FrameError::Commitment);
    }
    ledger
        .parse::<fact_core::ObjectId>()
        .map_err(|_| FrameError::Commitment)?;
    if !valid_commitment_scope(body.get("scope"), ledger) {
        return Err(FrameError::Commitment);
    }
    body.get("coordinator_actor_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(FrameError::Commitment)?
        .parse::<fact_core::ObjectId>()
        .map_err(|_| FrameError::Commitment)?;
    fact_core::validate_timestamp(
        body.get("created_at")
            .and_then(serde_json::Value::as_str)
            .ok_or(FrameError::Commitment)?,
    )
    .map_err(|_| FrameError::Commitment)?;
    body.get("signing_key_fingerprint")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<Hash>().ok())
        .ok_or(FrameError::Commitment)?;
    let scope_bytes = fact_canonical::encode(
        &serde_json::to_vec(body.get("scope").ok_or(FrameError::Commitment)?)
            .map_err(|_| FrameError::Commitment)?,
    )
    .map_err(|_| FrameError::Commitment)?;
    if body.get("scope_hash").and_then(serde_json::Value::as_str)
        != Some(Hash::digest(&scope_bytes).hex().as_str())
    {
        return Err(FrameError::Commitment);
    }
    let tree = MerkleTree::new(
        objects
            .iter()
            .map(|object| object_hash(object.as_ref()))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(|_| FrameError::Commitment)?;
    if body.get("root_hash").and_then(serde_json::Value::as_str) != Some(tree.root.hex().as_str()) {
        return Err(FrameError::Commitment);
    }
    let mut preimage = serde_json::Value::Object(body.clone());
    preimage["snapshot_id"] = serde_json::Value::Null;
    let preimage =
        fact_canonical::encode(&serde_json::to_vec(&preimage).map_err(|_| FrameError::Commitment)?)
            .map_err(|_| FrameError::Commitment)?;
    if body.get("snapshot_id").and_then(serde_json::Value::as_str)
        != Some(Hash::digest(&preimage).hex().as_str())
    {
        return Err(FrameError::Commitment);
    }
    Ok(())
}

fn valid_commitment_scope(scope: Option<&serde_json::Value>, ledger: &str) -> bool {
    let Some(scope) = scope.and_then(serde_json::Value::as_object) else {
        return false;
    };
    let required = [
        "ledger_id",
        "snapshot_boundary",
        "query_digest",
        "object_types",
        "actor_ids",
        "proposition_ids",
        "revision_ids",
        "deliberation_ids",
        "filters",
    ];
    if !exact_fields(scope, &required)
        || scope.get("ledger_id").and_then(serde_json::Value::as_str) != Some(ledger)
        || !scope
            .get("filters")
            .is_some_and(serde_json::Value::is_object)
    {
        return false;
    }
    let valid_optional_hash = |value: &serde_json::Value| {
        value.is_null()
            || value
                .as_str()
                .and_then(|value| value.parse::<Hash>().ok())
                .is_some()
    };
    if !valid_optional_hash(scope.get("query_digest").unwrap()) {
        return false;
    }
    if !scope.get("snapshot_boundary").unwrap().is_null()
        && scope
            .get("snapshot_boundary")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<fact_core::ObjectId>().ok())
            .is_none()
    {
        return false;
    }
    let valid_ids = |field: &str| {
        let Some(values) = scope.get(field).and_then(serde_json::Value::as_array) else {
            return false;
        };
        let parsed = values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .and_then(|value| value.parse::<fact_core::ObjectId>().ok())
            })
            .collect::<Option<Vec<_>>>();
        parsed.is_some_and(|values| values.windows(2).all(|pair| pair[0] < pair[1]))
    };
    [
        "actor_ids",
        "proposition_ids",
        "revision_ids",
        "deliberation_ids",
    ]
    .iter()
    .all(|field| valid_ids(field))
        && scope
            .get("object_types")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|values| {
                let types = values
                    .iter()
                    .map(serde_json::Value::as_str)
                    .collect::<Option<Vec<_>>>();
                types.is_some_and(|types| {
                    types.windows(2).all(|pair| pair[0] < pair[1])
                        && types
                            .iter()
                            .all(|value| fact_schema::OBJECT_TYPES.contains(value))
                })
            })
}

fn decode_b64url(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        accumulator = (accumulator << 6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    (bits < 6 && accumulator == 0).then_some(output)
}

#[cfg(test)]
fn encode_b64url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        output.push(TABLE[((n >> 18) & 63) as usize] as char);
        output.push(TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(n & 63) as usize] as char);
        }
    }
    output
}
fn check_manifest(magic: [u8; 8], manifest: &[u8], count: usize) -> Result<usize, FrameError> {
    if manifest.len() > MAX_MANIFEST
        || fact_canonical::encode(manifest).map_err(|_| FrameError::Manifest)? != manifest
    {
        return Err(FrameError::Manifest);
    }
    let v: serde_json::Value =
        serde_json::from_slice(manifest).map_err(|_| FrameError::Manifest)?;
    let object_count = v
        .get("object_count")
        .and_then(|x| x.as_u64())
        .ok_or(FrameError::Manifest)?;
    if count != usize::MAX && object_count != count as u64 {
        return Err(FrameError::Count);
    }
    let object = v.as_object().ok_or(FrameError::Manifest)?;
    if magic == *b"FACTSNAP" {
        if !exact_fields(
            object,
            &[
                "schema",
                "protocol_version",
                "ledger_id",
                "scope",
                "filters",
                "commitment",
                "object_count",
                "profile",
            ],
        ) || object.get("schema").and_then(|x| x.as_str()) != Some("facts-protocol-snapshot-v0")
            || object.get("profile").and_then(|x| x.as_str()) != Some("facts-protocol-snapshot-v0")
            || object.get("protocol_version").and_then(|x| x.as_u64()) != Some(0)
            || object.get("ledger_id").and_then(|x| x.as_str()).is_none()
            || !object
                .get("scope")
                .is_some_and(serde_json::Value::is_object)
            || !object
                .get("filters")
                .is_some_and(serde_json::Value::is_object)
            || object.get("commitment").and_then(|x| x.as_str()).is_none()
        {
            return Err(FrameError::Manifest);
        }
    } else if !exact_fields(
        object,
        &[
            "schema",
            "protocol_version",
            "bundle_id",
            "ledger_id",
            "object_count",
            "objects",
            "dependency_refs",
            "sender_signature",
            "expected_commitment_hash",
            "base_commitment_hash",
        ],
    ) || object.get("schema").and_then(|x| x.as_str()) != Some("facts-protocol-bundle-v0")
        || object.get("protocol_version").and_then(|x| x.as_u64()) != Some(0)
        || object.get("bundle_id").and_then(|x| x.as_str()).is_none()
        || !object
            .get("objects")
            .is_some_and(serde_json::Value::is_array)
        || !object
            .get("dependency_refs")
            .is_some_and(serde_json::Value::is_array)
        || !object
            .get("sender_signature")
            .is_some_and(|x| x.is_null() || x.is_string())
        || !object
            .get("expected_commitment_hash")
            .is_some_and(|x| x.is_null() || x.is_string())
        || !object
            .get("base_commitment_hash")
            .is_some_and(|x| x.is_null() || x.is_string())
    {
        return Err(FrameError::Manifest);
    }
    if magic == *b"FACTBNDL" {
        canonical_v7_uuid(object.get("bundle_id")).ok_or(FrameError::Manifest)?;
        if object
            .get("ledger_id")
            .is_some_and(|value| !value.is_null())
            && canonical_v7_uuid(object.get("ledger_id")).is_none()
        {
            return Err(FrameError::Manifest);
        }
        if object
            .get("sender_signature")
            .and_then(|value| value.as_str())
            .is_some_and(|value| decode_b64url(value).is_none())
            || ["expected_commitment_hash", "base_commitment_hash"]
                .iter()
                .any(|field| {
                    object
                        .get(*field)
                        .and_then(|value| value.as_str())
                        .is_some_and(|value| value.parse::<Hash>().is_err())
                })
        {
            return Err(FrameError::Manifest);
        }
        let dependency_refs = object
            .get("dependency_refs")
            .and_then(|value| value.as_array())
            .ok_or(FrameError::Manifest)?
            .iter()
            .map(|value| {
                let value = value.as_object().ok_or(FrameError::Manifest)?;
                if !exact_fields(value, &["object_id", "content_hash"]) {
                    return Err(FrameError::Manifest);
                }
                let object_id =
                    canonical_v7_uuid(value.get("object_id")).ok_or(FrameError::Manifest)?;
                let content_hash = value
                    .get("content_hash")
                    .and_then(|value| value.as_str())
                    .and_then(|value| value.parse::<Hash>().ok())
                    .ok_or(FrameError::Manifest)?;
                Ok((object_id, content_hash))
            })
            .collect::<Result<Vec<_>, FrameError>>()?;
        if dependency_refs.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(FrameError::Order);
        }
    }
    Ok(object_count as usize)
}
fn exact_fields(object: &serde_json::Map<String, serde_json::Value>, fields: &[&str]) -> bool {
    object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
}
fn canonical_v7_uuid(value: Option<&serde_json::Value>) -> Option<uuid::Uuid> {
    let text = value?.as_str()?;
    let uuid = text.parse::<uuid::Uuid>().ok()?;
    (uuid.get_version_num() == 7
        && uuid.get_variant() == uuid::Variant::RFC4122
        && uuid.to_string() == text)
        .then_some(uuid)
}
fn validate_bundle_entries(
    manifest: &serde_json::Value,
    objects: &[impl AsRef<[u8]>],
) -> Result<(), FrameError> {
    let entries = manifest
        .get("objects")
        .and_then(|value| value.as_array())
        .ok_or(FrameError::Manifest)?;
    if entries.len() != objects.len() {
        return Err(FrameError::Count);
    }
    let mut expected = objects
        .iter()
        .map(|object| object_hash(object.as_ref()).map(|hash| hash.hex()))
        .collect::<Result<Vec<_>, _>>()?;
    expected.sort();
    let actual = entries
        .iter()
        .zip(objects)
        .map(|(entry, object)| {
            let entry = entry.as_object().ok_or(FrameError::Manifest)?;
            if !exact_fields(entry, &["object_id", "content_hash"]) {
                return Err(FrameError::Manifest);
            }
            let object_id = entry
                .get("object_id")
                .and_then(|value| value.as_str())
                .ok_or(FrameError::Manifest)?;
            let parsed_id = object_id
                .parse::<uuid::Uuid>()
                .map_err(|_| FrameError::Manifest)?;
            if parsed_id.get_version_num() != 7
                || parsed_id.get_variant() != uuid::Variant::RFC4122
                || parsed_id.to_string() != object_id
            {
                return Err(FrameError::Manifest);
            }
            let payload = fact_crypto::decode_sign1(object.as_ref())
                .map_err(|_| FrameError::Cose)?
                .payload;
            let value: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| FrameError::Manifest)?;
            if value.get("id").and_then(|value| value.as_str()) != Some(object_id) {
                return Err(FrameError::Manifest);
            }
            entry
                .get("content_hash")
                .and_then(|value| value.as_str())
                .ok_or(FrameError::Manifest)
                .map(str::to_owned)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if actual != expected {
        return Err(FrameError::Hash);
    }
    Ok(())
}
fn check_object_hash(hash: Hash, bytes: &[u8]) -> Result<(), FrameError> {
    if bytes.len() > MAX_OBJECT {
        return Err(FrameError::TooLarge);
    }
    if object_hash(bytes)? != hash {
        return Err(FrameError::Hash);
    }
    Ok(())
}
fn object_hash(bytes: &[u8]) -> Result<Hash, FrameError> {
    let c = fact_crypto::decode_sign1(bytes).map_err(|_| FrameError::Cose)?;
    if fact_canonical::encode(&c.payload).map_err(|_| FrameError::Cose)? != c.payload {
        return Err(FrameError::Cose);
    }
    fact_schema::validate_envelope(&c.payload).map_err(|_| FrameError::Cose)?;
    Ok(Hash::digest(&c.payload))
}
fn read_u32(b: &[u8], p: &mut usize) -> Result<u32, FrameError> {
    let x = read_exact(b, p, 4)?;
    Ok(u32::from_be_bytes(x.try_into().unwrap()))
}
fn read_u64(b: &[u8], p: &mut usize) -> Result<u64, FrameError> {
    let x = read_exact(b, p, 8)?;
    Ok(u64::from_be_bytes(x.try_into().unwrap()))
}
fn read_exact<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8], FrameError> {
    let end = p.checked_add(n).ok_or(FrameError::Truncated)?;
    let x = b.get(*p..end).ok_or(FrameError::Truncated)?;
    *p = end;
    Ok(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(n: u8) -> Hash {
        let mut b = [0u8; 32];
        b[31] = n;
        Hash::from_bytes(b)
    }
    #[test]
    fn vectors() {
        assert_eq!(
            MerkleTree::new(vec![]).unwrap().root.hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            MerkleTree::new(vec![h(1)]).unwrap().root.hex(),
            "1fd4247443c9440cb3c48c28851937196bc156032d70a96c98e127ecb347e45f"
        );
        let t = MerkleTree::new(vec![h(1), h(2), h(3)]).unwrap();
        assert_eq!(
            t.root.hex(),
            "93e34ecb30d456c2bb3903c45dd51d053db3e66522a0a2eaf5fafa58312ed037"
        );
        assert!(verify(h(3), &t.proof(2).unwrap(), t.root));
    }
    #[test]
    fn duplicates_rejected() {
        assert_eq!(MerkleTree::new(vec![h(1), h(1)]), Err(Error::Duplicate));
    }

    #[test]
    fn bundle_identity_is_stable_and_uuidv7() {
        let objects = vec![(h(2), vec![2]), (h(1), vec![1])];
        let first = deterministic_bundle_id(&objects);
        let second = deterministic_bundle_id(&[(h(1), vec![9]), (h(2), vec![8])]);
        let third = deterministic_bundle_id_from_hashes([h(2), h(1)]);
        assert_eq!(first, second);
        assert_eq!(first, third);
        assert_eq!(first.get_version_num(), 7);
        assert_eq!(first.to_string(), first.to_string().to_lowercase());
    }

    #[test]
    fn bundle_writer_matches_in_memory_encoder_for_sorted_objects() {
        let key = fact_crypto::SigningKey::from_seed(&[17u8; 32]).unwrap();
        let mut objects = [signed_actor(&key), signed_actor(&key)]
            .into_iter()
            .map(|bytes| {
                let payload = fact_crypto::decode_sign1(&bytes).unwrap().payload;
                (Hash::digest(&payload), bytes)
            })
            .collect::<Vec<_>>();
        objects.sort_by_key(|(hash, _)| *hash);
        let manifest = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-bundle-v0",
                "protocol_version":0,
                "bundle_id":deterministic_bundle_id_from_hashes(objects.iter().map(|(hash, _)| *hash)),
                "ledger_id":null,
                "object_count":objects.len(),
                "objects":objects.iter().map(|(hash, bytes)| {
                    let payload = fact_crypto::decode_sign1(bytes).unwrap().payload;
                    let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                    serde_json::json!({"object_id":value["id"],"content_hash":hash.hex()})
                }).collect::<Vec<_>>(),
                "dependency_refs":[],
                "sender_signature":null,
                "expected_commitment_hash":null,
                "base_commitment_hash":null
            }))
            .unwrap(),
        )
        .unwrap();

        let expected = encode_bundle(&manifest, &objects).unwrap();
        let mut written = Vec::new();
        let bytes = write_bundle_sorted(&mut written, &manifest, objects.clone()).unwrap();
        assert_eq!(bytes, expected.len());
        assert_eq!(written, expected);
        let mut borrowed_written = Vec::new();
        let borrowed_bytes = try_write_bundle_sorted_slices(
            &mut borrowed_written,
            &manifest,
            objects
                .iter()
                .map(|(hash, bytes)| Ok::<_, FrameError>((*hash, bytes.as_slice()))),
        )
        .unwrap();
        assert_eq!(borrowed_bytes, expected.len());
        assert_eq!(borrowed_written, expected);
        let borrowed = decode_bundle_slices(&written).unwrap();
        assert_eq!(borrowed.manifest, manifest.as_slice());
        assert_eq!(
            borrowed.objects,
            objects
                .iter()
                .map(|(_, bytes)| bytes.as_slice())
                .collect::<Vec<_>>()
        );

        objects.swap(0, 1);
        let mut invalid = Vec::new();
        assert_eq!(
            write_bundle_sorted(&mut invalid, &manifest, objects),
            Err(FrameError::Order)
        );
    }

    #[test]
    fn bundle_manifest_validates_protocol_scalars_and_dependency_order() {
        let manifest = |bundle_id: serde_json::Value,
                        dependency_refs: serde_json::Value,
                        sender_signature: serde_json::Value,
                        expected_commitment_hash: serde_json::Value| {
            fact_canonical::encode(
                &serde_json::to_vec(&serde_json::json!({
                    "schema":"facts-protocol-bundle-v0",
                    "protocol_version":0,
                    "bundle_id":bundle_id,
                    "ledger_id":null,
                    "object_count":0,
                    "objects":[],
                    "dependency_refs":dependency_refs,
                    "sender_signature":sender_signature,
                    "expected_commitment_hash":expected_commitment_hash,
                    "base_commitment_hash":null
                }))
                .unwrap(),
            )
            .unwrap()
        };
        let bundle_id = serde_json::json!("01900000-0000-7000-8000-abcdefabcdef");
        let valid = manifest(
            bundle_id.clone(),
            serde_json::json!([]),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        assert!(encode_bundle(&valid, &[]).is_ok());

        let uppercase = manifest(
            serde_json::json!(bundle_id.as_str().unwrap().to_ascii_uppercase()),
            serde_json::json!([]),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        assert_eq!(encode_bundle(&uppercase, &[]), Err(FrameError::Manifest));

        let unsorted = manifest(
            bundle_id,
            serde_json::json!([
                {"object_id":"01900000-0000-7000-8000-000000000002","content_hash":h(2).hex()},
                {"object_id":"01900000-0000-7000-8000-000000000001","content_hash":h(1).hex()}
            ]),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        assert_eq!(encode_bundle(&unsorted, &[]), Err(FrameError::Order));

        let invalid_signature = manifest(
            serde_json::json!("01900000-0000-7000-8000-abcdefabcdef"),
            serde_json::json!([]),
            serde_json::json!("not-base64url!"),
            serde_json::Value::Null,
        );
        assert_eq!(
            encode_bundle(&invalid_signature, &[]),
            Err(FrameError::Manifest)
        );
    }

    #[test]
    fn non_inclusion_proofs_use_immediate_neighbors() {
        let tree = MerkleTree::new(vec![h(1), h(3), h(5)]).unwrap();
        let proof = tree.non_inclusion_proof(h(4)).unwrap();
        assert_eq!(proof.left.as_ref().map(|entry| entry.0), Some(h(3)));
        assert_eq!(proof.right.as_ref().map(|entry| entry.0), Some(h(5)));
        assert!(verify_non_inclusion(h(4), &proof, tree.root));
        assert_eq!(tree.non_inclusion_proof(h(3)), Err(Error::Present));

        let empty = MerkleTree::new(vec![]).unwrap();
        let proof = empty.non_inclusion_proof(h(4)).unwrap();
        assert!(verify_non_inclusion(h(4), &proof, empty.root));
    }

    fn signed_actor(key: &fact_crypto::SigningKey) -> Vec<u8> {
        let payload = serde_json::json!({
            "id": uuid::Uuid::now_v7(),
            "object_type": "actor",
            "schema_version": "0",
            "actor_id": uuid::Uuid::now_v7(),
            "signing_key_id": uuid::Uuid::now_v7(),
            "created_at": "2026-07-27T12:00:00.000Z",
            "dependencies": [],
            "body": {
                "actor_type": "agent",
                "bootstrap_key_id": uuid::Uuid::now_v7(),
                "bootstrap_binding_id": uuid::Uuid::now_v7()
            }
        });
        let payload = fact_canonical::encode(&serde_json::to_vec(&payload).unwrap()).unwrap();
        let protected = fact_crypto::protocol_protected(key.public_key(), "actor", "0", None);
        fact_crypto::encode_sign1(&fact_crypto::sign1(&protected, &payload, key))
    }
    #[test]
    fn snapshot_frames_exact_cose_and_reject_trailing_bytes() {
        let key = fact_crypto::SigningKey::from_seed(&[9u8; 32]).unwrap();
        let id = uuid::Uuid::now_v7();
        let payload = serde_json::json!({
            "id": id,
            "object_type": "actor",
            "schema_version": "0",
            "actor_id": uuid::Uuid::now_v7(),
            "signing_key_id": uuid::Uuid::now_v7(),
            "created_at": "2026-07-27T12:00:00.000Z",
            "dependencies": [],
            "body": {
                "actor_type": "agent",
                "bootstrap_key_id": uuid::Uuid::now_v7(),
                "bootstrap_binding_id": uuid::Uuid::now_v7()
            }
        });
        let payload = fact_canonical::encode(&serde_json::to_vec(&payload).unwrap()).unwrap();
        let protected = fact_crypto::protocol_protected(key.public_key(), "actor", "0", None);
        let object = fact_crypto::encode_sign1(&fact_crypto::sign1(&protected, &payload, &key));
        let hash = Hash::digest(&payload);
        let snapshot_ledger = uuid::Uuid::now_v7();
        let scope = serde_json::json!({
            "ledger_id":snapshot_ledger,
            "snapshot_boundary":null,
            "query_digest":null,
            "object_types":[],
            "actor_ids":[],
            "proposition_ids":[],
            "revision_ids":[],
            "deliberation_ids":[],
            "filters":{}
        });
        let scope_hash =
            Hash::digest(&fact_canonical::encode(&serde_json::to_vec(&scope).unwrap()).unwrap())
                .hex();
        let mut commitment = serde_json::json!({
            "schema":"facts-protocol-commitment-v0",
            "coordinator_actor_id":uuid::Uuid::now_v7(),
            "ledger_id":snapshot_ledger,
            "scope":scope,
            "scope_hash":scope_hash,
            "snapshot_id":null,
            "tree_profile":"facts-protocol-merkle-v0",
            "root_hash":MerkleTree::new(vec![hash]).unwrap().root.hex(),
            "object_count":1,
            "created_at":"2026-07-27T12:00:00.000Z",
            "previous_commitment_hash":null,
            "signing_key_fingerprint":key.fingerprint().hex()
        });
        let preimage = fact_canonical::encode(&serde_json::to_vec(&commitment).unwrap()).unwrap();
        commitment["snapshot_id"] = serde_json::json!(Hash::digest(&preimage).hex());
        let commitment_payload =
            fact_canonical::encode(&serde_json::to_vec(&commitment).unwrap()).unwrap();
        let coordinator_protected = fact_crypto::coordinator_protected(
            key.public_key(),
            "commitment",
            "0",
            Some(*snapshot_ledger.as_bytes()),
        );
        let signed_commitment = fact_crypto::encode_sign1(&fact_crypto::sign1(
            &coordinator_protected,
            &commitment_payload,
            &key,
        ));
        let manifest = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-snapshot-v0",
                "protocol_version":0,
                "ledger_id":snapshot_ledger,
                "scope":scope,
                "filters":{},
                "commitment":encode_b64url(&signed_commitment),
                "object_count":1,
                "profile":"facts-protocol-snapshot-v0"
            }))
            .unwrap(),
        )
        .unwrap();
        let framed = encode_snapshot(&manifest, &[(hash, object.clone())]).unwrap();
        assert_eq!(&framed[..8], b"FACTSNAP");
        let decoded = decode_snapshot(&framed).unwrap();
        assert_eq!(decoded.manifest, manifest);
        assert_eq!(decoded.objects, vec![object]);
        let mut trailing = framed.clone();
        trailing.push(0);
        assert_eq!(decode_snapshot(&trailing), Err(FrameError::Order));
    }
}
