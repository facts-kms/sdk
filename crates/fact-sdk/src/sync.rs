//! Bundle import/export helpers.

use crate::{
    models::{ObjectSummary, OperationReceipt},
    Error, Result,
};

type DependencyRow = (uuid::Uuid, fact_core::Hash, String);

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ObjectValidationResult {
    pub valid: bool,
    pub signed: bool,
    pub object_type: String,
    pub canonical_bytes: usize,
    pub content_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ImportObjectsResult {
    pub imported: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content_hashes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportObjectResult {
    pub exported: bool,
    pub object_id: uuid::Uuid,
    #[serde(skip_serializing)]
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportBundleResult {
    pub exported: usize,
    pub bundle_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PagedExportObjectsResult {
    pub exported: usize,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing)]
    pub objects: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PagedExportBundleResult {
    pub exported: usize,
    pub bundle_bytes: usize,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ListObjectsOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    pub limit: usize,
}

impl Default for ListObjectsOptions {
    fn default() -> Self {
        Self {
            after: None,
            limit: 100,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PagedListObjectsResult {
    pub objects: Vec<ObjectSummary>,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ReadObjectResult {
    pub object_id: uuid::Uuid,
    pub content_hash: String,
    pub object_type: String,
    pub payload: serde_json::Value,
    #[serde(skip_serializing)]
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PullBundleResult {
    pub pulled: usize,
    pub bundle_bytes: usize,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing)]
    pub bundle: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct WrittenPullBundleResult {
    pub pulled: usize,
    pub bundle_bytes: usize,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PullBundleOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    pub max_objects: Option<usize>,
    pub max_object_bytes: Option<usize>,
}

/// Encode a canonical protocol pull request for remote sync transports.
pub fn encode_pull_request(
    ledger: uuid::Uuid,
    known: &std::collections::HashSet<fact_core::Hash>,
    cursor: Option<&str>,
) -> Result<Vec<u8>> {
    let mut known_object_hashes = known.iter().map(|hash| hash.hex()).collect::<Vec<_>>();
    known_object_hashes.sort();
    Ok(fact_canonical::encode(&serde_json::to_vec(
        &serde_json::json!({
            "schema":"facts-protocol-pull-v0",
            "scope":{
                "ledger_id":ledger,
                "snapshot_boundary":null,
                "query_digest":null,
                "object_types":[],
                "actor_ids":[],
                "proposition_ids":[],
                "revision_ids":[],
                "deliberation_ids":[],
                "filters":{}
            },
            "known_commitment_hash":null,
            "known_object_hashes":known_object_hashes,
            "limit":1000,
            "cursor":cursor,
            "prefer_snapshot":false
        }),
    )?)?)
}

/// Encode a canonical protocol fetch request for missing object hashes.
pub fn encode_fetch_request(hashes: &[fact_core::Hash]) -> Result<Vec<u8>> {
    let mut hashes = hashes.iter().map(|hash| hash.hex()).collect::<Vec<_>>();
    hashes.sort();
    Ok(fact_canonical::encode(&serde_json::to_vec(
        &serde_json::json!({
            "schema":"facts-protocol-fetch-v0",
            "ids":[],
            "hashes":hashes,
            "include_missing":true
        }),
    )?)?)
}

/// Return the HTTP Content-Digest header value for a protocol payload.
pub fn content_digest_header(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in digest.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        output.push(TABLE[((n >> 18) & 63) as usize] as char);
        output.push(TABLE[((n >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    format!("sha-256=:{output}:")
}

/// Decode signed COSE objects from a remote pull/fetch JSON response.
pub fn decode_remote_response_objects(
    response: &serde_json::Value,
    response_kind: &str,
) -> Result<Vec<(fact_core::Hash, Vec<u8>)>> {
    let wire_objects = response
        .get("objects")
        .or_else(|| response.get("body").and_then(|body| body.get("objects")))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            Error::Sync(format!(
                "remote {response_kind} response has no object list"
            ))
        })?;
    wire_objects
        .iter()
        .map(|wire| {
            let encoded = wire
                .get("cose_sign1")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    Error::Sync(format!("remote {response_kind} object has no cose_sign1"))
                })?;
            let cose_bytes = decode_b64url(encoded)
                .ok_or_else(|| Error::Sync("invalid remote COSE encoding".into()))?;
            let payload = fact_crypto::decode_sign1(&cose_bytes)?.payload;
            Ok((fact_core::Hash::digest(&payload), cose_bytes))
        })
        .collect()
}

/// Return missing dependency hashes referenced by signed object bytes.
pub fn missing_dependency_hashes(
    objects: &[Vec<u8>],
    present: &std::collections::HashSet<fact_core::Hash>,
    known: &std::collections::HashSet<fact_core::Hash>,
    inspected: &mut std::collections::HashSet<fact_core::Hash>,
) -> Result<Vec<fact_core::Hash>> {
    let mut requested = Vec::new();
    for bytes in objects {
        let cose = fact_crypto::decode_sign1(bytes)?;
        let value: serde_json::Value = serde_json::from_slice(&cose.payload)?;
        let dependencies = value
            .get("dependencies")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| Error::Sync("remote object has no dependencies array".into()))?;
        for dependency in dependencies {
            let hash = dependency
                .get("content_hash")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::Sync("remote dependency has no content_hash".into()))?
                .parse::<fact_core::Hash>()
                .map_err(|error| Error::Sync(error.to_string()))?;
            if !present.contains(&hash) && !known.contains(&hash) && inspected.insert(hash) {
                requested.push(hash);
            }
        }
    }
    requested.sort();
    Ok(requested)
}

/// Validate that a remote fetch response contains exactly the requested hashes.
pub fn validate_fetched_objects(
    requested: &[fact_core::Hash],
    objects: Vec<(fact_core::Hash, Vec<u8>)>,
) -> Result<Vec<(fact_core::Hash, Vec<u8>)>> {
    let requested = requested
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let mut fetched = std::collections::HashSet::new();
    for (hash, _) in &objects {
        if !requested.contains(hash) {
            return Err(Error::Sync(
                "remote fetch returned an unrequested object".into(),
            ));
        }
        fetched.insert(*hash);
    }
    if fetched.len() != requested.len() {
        return Err(Error::Sync(format!(
            "remote fetch did not return all dependencies (requested {}, received {})",
            requested.len(),
            fetched.len()
        )));
    }
    Ok(objects)
}

/// Export all signed objects needed to validate a ledger.
pub fn export_bundle(store: &fact_store::Store, ledger_id: uuid::Uuid) -> Result<Vec<Vec<u8>>> {
    collect_dependency_rows(store, ledger_id)?
        .into_iter()
        .map(|(object_id, _, _)| {
            store
                .get_cose_by_id_any(object_id.as_bytes())?
                .ok_or_else(|| Error::MissingObject(object_id.to_string()))
        })
        .collect()
}

/// Export a bounded page of signed objects needed to validate a ledger.
///
/// Use this instead of [`export_bundle`] for large ledgers when callers need
/// object frames in memory rather than a streamed bundle writer.
pub fn export_bundle_with_options(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
    options: PullBundleOptions,
) -> Result<PagedExportObjectsResult> {
    let (rows, complete, next_cursor) =
        collect_dependency_rows_with_options(store, ledger_id, options)?;
    let objects = rows
        .into_iter()
        .map(|(object_id, _, _)| {
            store
                .get_cose_by_id_any(object_id.as_bytes())?
                .ok_or_else(|| Error::MissingObject(object_id.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(PagedExportObjectsResult {
        exported: objects.len(),
        complete,
        next_cursor,
        objects,
    })
}

/// Write all signed objects needed to validate a ledger as a protocol bundle.
///
/// This keeps only bundle manifest rows in memory and streams COSE object bytes
/// to the writer in content-hash order.
pub fn write_bundle_from_store<W: std::io::Write>(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
    writer: W,
) -> Result<ExportBundleResult> {
    let rows = collect_dependency_rows(store, ledger_id)?;
    let manifest = encode_bundle_manifest(
        ledger_id,
        rows.iter().map(|(object_id, hash, _)| (*object_id, *hash)),
    )?;
    let exported = rows.len();
    let bundle_bytes = fact_commitment::try_write_bundle_sorted(
        writer,
        &manifest,
        rows.into_iter().map(|(object_id, hash, _)| {
            let bytes = store
                .get_cose_by_id_any(object_id.as_bytes())?
                .ok_or_else(|| Error::MissingObject(object_id.to_string()))?;
            Ok::<_, Error>((hash, bytes))
        }),
    )?;
    Ok(ExportBundleResult {
        exported,
        bundle_bytes,
    })
}

/// Write a bounded page of signed objects needed to validate a ledger as a
/// protocol bundle.
pub fn write_bundle_from_store_with_options<W: std::io::Write>(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
    options: PullBundleOptions,
    writer: W,
) -> Result<PagedExportBundleResult> {
    let (rows, complete, next_cursor) =
        collect_dependency_rows_with_options(store, ledger_id, options)?;
    let manifest = encode_bundle_manifest(
        ledger_id,
        rows.iter().map(|(object_id, hash, _)| (*object_id, *hash)),
    )?;
    let exported = rows.len();
    let bundle_bytes = fact_commitment::try_write_bundle_sorted(
        writer,
        &manifest,
        rows.into_iter().map(|(object_id, hash, _)| {
            let bytes = store
                .get_cose_by_id_any(object_id.as_bytes())?
                .ok_or_else(|| Error::MissingObject(object_id.to_string()))?;
            Ok::<_, Error>((hash, bytes))
        }),
    )?;
    Ok(PagedExportBundleResult {
        exported,
        bundle_bytes,
        complete,
        next_cursor,
    })
}

/// Write a protocol bundle containing only objects directly scoped to a ledger.
///
/// This is intended for closed fixture/export corpora where ledger-neutral
/// dependency expansion is not needed. General sync should use
/// [`write_bundle_from_store`] so validation dependencies are included.
pub fn write_ledger_bundle_from_store<W: std::io::Write>(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
    writer: W,
) -> Result<ExportBundleResult> {
    let rows = store.list_object_summaries(ledger_id.as_bytes())?;
    let manifest = encode_bundle_manifest(
        ledger_id,
        rows.iter().map(|row| (row.object_id, row.content_hash)),
    )?;
    let exported = rows.len();
    let bundle_bytes = fact_commitment::try_write_bundle_sorted(
        writer,
        &manifest,
        rows.into_iter().map(|row| {
            let bytes = store
                .get_cose_by_id(ledger_id.as_bytes(), row.object_id.as_bytes())?
                .ok_or_else(|| Error::MissingObject(row.object_id.to_string()))?;
            Ok::<_, Error>((row.content_hash, bytes))
        }),
    )?;
    Ok(ExportBundleResult {
        exported,
        bundle_bytes,
    })
}

/// Write a bounded page of directly ledger-scoped objects as a protocol
/// bundle. This intentionally skips ledger-neutral dependency expansion and is
/// suitable for closed fixture/export corpora.
pub fn write_ledger_bundle_from_store_with_options<W: std::io::Write>(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
    options: PullBundleOptions,
    writer: W,
) -> Result<PagedExportBundleResult> {
    let (rows, complete, next_cursor) =
        collect_ledger_rows_with_options(store, ledger_id, options)?;
    let manifest = encode_bundle_manifest(
        ledger_id,
        rows.iter().map(|row| (row.object_id, row.content_hash)),
    )?;
    let exported = rows.len();
    let bundle_bytes = fact_commitment::try_write_bundle_sorted(
        writer,
        &manifest,
        rows.into_iter().map(|row| {
            let bytes = store
                .get_cose_by_id(ledger_id.as_bytes(), row.object_id.as_bytes())?
                .ok_or_else(|| Error::MissingObject(row.object_id.to_string()))?;
            Ok::<_, Error>((row.content_hash, bytes))
        }),
    )?;
    Ok(PagedExportBundleResult {
        exported,
        bundle_bytes,
        complete,
        next_cursor,
    })
}

fn collect_ledger_rows_with_options(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
    options: PullBundleOptions,
) -> Result<(Vec<fact_store::ObjectSummaryRow>, bool, Option<String>)> {
    if options.max_objects == Some(0) {
        return Err(Error::Sync(
            "export object limit must be greater than zero".into(),
        ));
    }
    let mut rows = Vec::new();
    let mut object_bytes = 0usize;
    let mut complete = true;
    let mut after = options
        .after
        .as_deref()
        .map(|value| {
            value
                .parse::<fact_core::Hash>()
                .map_err(|error| Error::Sync(format!("invalid export cursor: {error}")))
        })
        .transpose()?;
    let mut last_cursor = after;
    loop {
        let page_limit = options
            .max_objects
            .map(|limit| limit.saturating_sub(rows.len()).saturating_add(1))
            .unwrap_or(512)
            .max(1);
        let page =
            store.list_object_summaries_page(ledger_id.as_bytes(), after.as_ref(), page_limit)?;
        if page.is_empty() {
            break;
        }
        let fetched = page.len();
        for row in page {
            if options.max_objects.is_some_and(|limit| rows.len() >= limit) {
                complete = false;
                return Ok((rows, complete, last_cursor.map(|hash| hash.hex())));
            }
            if let Some(limit) = options.max_object_bytes {
                let bytes = store
                    .get_cose_by_id(ledger_id.as_bytes(), row.object_id.as_bytes())?
                    .ok_or_else(|| Error::MissingObject(row.object_id.to_string()))?;
                if object_bytes + bytes.len() > limit {
                    if rows.is_empty() {
                        return Err(Error::Sync("next object exceeds export byte limit".into()));
                    }
                    complete = false;
                    return Ok((rows, complete, last_cursor.map(|hash| hash.hex())));
                }
                object_bytes += bytes.len();
            }
            last_cursor = Some(row.content_hash);
            rows.push(row);
        }
        if fetched < page_limit {
            break;
        }
        after = last_cursor;
    }
    Ok((rows, complete, None))
}

fn collect_dependency_rows(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
) -> Result<Vec<DependencyRow>> {
    Ok(collect_dependency_rows_with_options(store, ledger_id, PullBundleOptions::default())?.0)
}

fn collect_dependency_rows_with_options(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
    options: PullBundleOptions,
) -> Result<(Vec<DependencyRow>, bool, Option<String>)> {
    collect_pull_rows(store, ledger_id, &std::collections::HashSet::new(), options)
}

/// List signed objects in a ledger.
pub fn list_objects(store: &fact_store::Store, ledger: uuid::Uuid) -> Result<Vec<ObjectSummary>> {
    Ok(store
        .list_object_summaries(ledger.as_bytes())?
        .into_iter()
        .map(|row| ObjectSummary {
            object_id: row.object_id.to_string(),
            content_hash: row.content_hash.hex(),
            object_type: row.object_type,
        })
        .collect())
}

/// List a bounded page of signed objects in a ledger.
pub fn list_objects_page(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    options: ListObjectsOptions,
) -> Result<PagedListObjectsResult> {
    if options.limit == 0 {
        return Err(Error::Sync(
            "object list limit must be greater than zero".into(),
        ));
    }
    let after = options
        .after
        .as_deref()
        .map(|value| {
            value
                .parse::<fact_core::Hash>()
                .map_err(|error| Error::Sync(format!("invalid object list cursor: {error}")))
        })
        .transpose()?;
    let mut rows =
        store.list_object_summaries_page(ledger.as_bytes(), after.as_ref(), options.limit + 1)?;
    let complete = rows.len() <= options.limit;
    if !complete {
        rows.truncate(options.limit);
    }
    let next_cursor = (!complete)
        .then(|| rows.last().map(|row| row.content_hash.hex()))
        .flatten();
    let objects = rows
        .into_iter()
        .map(|row| ObjectSummary {
            object_id: row.object_id.to_string(),
            content_hash: row.content_hash.hex(),
            object_type: row.object_type,
        })
        .collect();
    Ok(PagedListObjectsResult {
        objects,
        complete,
        next_cursor,
    })
}

/// Read a signed object by object ID or content hash reference.
pub fn read_object(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    reference: &str,
) -> Result<ReadObjectResult> {
    let matches = store.resolve_object_reference(ledger.as_bytes(), reference, &[])?;
    let (object_id, content_hash, object_type) = match matches.as_slice() {
        [] => return Err(Error::MissingObject(reference.to_owned())),
        [object] => (
            object.object_id,
            object.content_hash,
            object.object_type.clone(),
        ),
        _ => return Err(Error::AmbiguousReference(reference.to_owned())),
    };
    let bytes = store
        .get_cose_by_id(ledger.as_bytes(), object_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject(object_id.to_string()))?;
    let cose = fact_crypto::decode_sign1(&bytes)?;
    let payload = serde_json::from_slice(&cose.payload)?;
    Ok(ReadObjectResult {
        object_id,
        content_hash: content_hash.hex(),
        object_type,
        payload,
        bytes,
    })
}

/// Validate canonical or signed object bytes.
pub fn validate_object_bytes(bytes: &[u8]) -> Result<ObjectValidationResult> {
    let (canonical, signed) = match fact_crypto::decode_sign1(bytes) {
        Ok(cose) => (cose.payload, true),
        Err(_) => {
            let canonical = fact_canonical::encode(bytes)?;
            if canonical != bytes {
                return Err(Error::Validation("unsigned object is not canonical".into()));
            }
            (bytes.to_vec(), false)
        }
    };
    if signed && fact_canonical::encode(&canonical)? != canonical {
        return Err(Error::Validation(
            "COSE embedded payload is not canonical".into(),
        ));
    }
    let object_type = fact_schema::validate_envelope(&canonical)?.as_str();
    Ok(ObjectValidationResult {
        valid: true,
        signed,
        object_type: object_type.into(),
        canonical_bytes: canonical.len(),
        content_hash: fact_core::Hash::digest(&canonical).hex(),
    })
}

/// Import one object, bundle, or snapshot into a store with authorization checks.
pub fn import_object_bytes(store: &fact_store::Store, bytes: &[u8]) -> Result<ImportObjectsResult> {
    if bytes.starts_with(b"FACTBNDL") || bytes.starts_with(b"FACTSNAP") {
        let objects = decode_bundle_or_snapshot_slices(bytes)?;
        let hashes = store.insert_authorized_bundle_slices_with_projected_mode(
            &objects,
            fact_store::ProjectedMode::Incremental,
        )?;
        Ok(ImportObjectsResult {
            imported: hashes.len(),
            content_hashes: hashes.into_iter().map(|hash| hash.hex()).collect(),
        })
    } else {
        let hash = store.insert_authorized_object_with_projected_mode(
            bytes,
            fact_store::ProjectedMode::Incremental,
        )?;
        Ok(ImportObjectsResult {
            imported: 1,
            content_hashes: vec![hash.hex()],
        })
    }
}

/// Export a single signed object from a ledger.
pub fn export_object(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    object_id: uuid::Uuid,
) -> Result<ExportObjectResult> {
    let bytes = store
        .get_cose_by_id(ledger.as_bytes(), object_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("object not found".into()))?;
    Ok(ExportObjectResult {
        exported: true,
        object_id,
        bytes,
    })
}

/// Decode signed objects from a bundle or snapshot.
pub fn decode_bundle_or_snapshot_objects(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    if bytes.starts_with(b"FACTBNDL") {
        fact_commitment::decode_bundle(bytes)
            .map(|bundle| bundle.objects)
            .map_err(|error| Error::Sync(error.to_string()))
    } else if bytes.starts_with(b"FACTSNAP") {
        fact_commitment::decode_snapshot(bytes)
            .map(|snapshot| snapshot.objects)
            .map_err(|error| Error::Sync(error.to_string()))
    } else {
        Err(Error::Validation(
            "sync push requires a FACTBNDL or FACTSNAP file".into(),
        ))
    }
}

/// Decode signed object frame slices from a bundle or snapshot without cloning
/// each object frame.
pub fn decode_bundle_or_snapshot_slices(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    if bytes.starts_with(b"FACTBNDL") {
        fact_commitment::decode_bundle_slices(bytes)
            .map(|bundle| bundle.objects)
            .map_err(|error| Error::Sync(error.to_string()))
    } else if bytes.starts_with(b"FACTSNAP") {
        fact_commitment::decode_snapshot_slices(bytes)
            .map(|snapshot| snapshot.objects)
            .map_err(|error| Error::Sync(error.to_string()))
    } else {
        Err(Error::Validation(
            "sync push requires a FACTBNDL or FACTSNAP file".into(),
        ))
    }
}

/// Import a FACTBNDL or FACTSNAP into a store.
pub fn push_bundle_to_store(
    store: &fact_store::Store,
    bytes: &[u8],
) -> Result<ImportObjectsResult> {
    let objects = decode_bundle_or_snapshot_slices(bytes)?;
    let hashes = store.insert_authorized_bundle_slices_with_projected_mode(
        &objects,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(ImportObjectsResult {
        imported: hashes.len(),
        content_hashes: hashes.into_iter().map(|hash| hash.hex()).collect(),
    })
}

/// Create a bundle of objects not present in the known hash set.
pub fn pull_bundle_from_store(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    known: &std::collections::HashSet<fact_core::Hash>,
) -> Result<PullBundleResult> {
    pull_bundle_from_store_with_options(store, ledger, known, PullBundleOptions::default())
}

/// Create a bundle of objects not present in the known hash set, bounded by
/// optional object-count or object-byte limits.
pub fn pull_bundle_from_store_with_options(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    known: &std::collections::HashSet<fact_core::Hash>,
    options: PullBundleOptions,
) -> Result<PullBundleResult> {
    let (rows, complete, next_cursor) = collect_pull_rows(store, ledger, known, options)?;
    let manifest = encode_bundle_manifest(
        ledger,
        rows.iter().map(|(object_id, hash, _)| (*object_id, *hash)),
    )?;
    let pulled = rows.len();
    let mut bundle = Vec::new();
    let bundle_bytes = fact_commitment::try_write_bundle_sorted(
        &mut bundle,
        &manifest,
        rows.into_iter().map(|(_, hash, _)| {
            let bytes = store
                .get_cose_by_hash_any(&hash)?
                .ok_or_else(|| Error::MissingObject(hash.hex()))?;
            Ok::<_, Error>((hash, bytes))
        }),
    )?;
    Ok(PullBundleResult {
        pulled,
        bundle_bytes,
        complete,
        next_cursor,
        bundle,
    })
}

/// Write a bundle of objects not present in the known hash set.
pub fn write_pull_bundle_from_store<W: std::io::Write>(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    known: &std::collections::HashSet<fact_core::Hash>,
    writer: W,
) -> Result<WrittenPullBundleResult> {
    write_pull_bundle_from_store_with_options(
        store,
        ledger,
        known,
        PullBundleOptions::default(),
        writer,
    )
}

/// Write a bundle of objects not present in the known hash set, bounded by
/// optional object-count or object-byte limits.
pub fn write_pull_bundle_from_store_with_options<W: std::io::Write>(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    known: &std::collections::HashSet<fact_core::Hash>,
    options: PullBundleOptions,
    writer: W,
) -> Result<WrittenPullBundleResult> {
    let (rows, complete, next_cursor) = collect_pull_rows(store, ledger, known, options)?;
    let manifest = encode_bundle_manifest(
        ledger,
        rows.iter().map(|(object_id, hash, _)| (*object_id, *hash)),
    )?;
    let pulled = rows.len();
    let bundle_bytes = fact_commitment::try_write_bundle_sorted(
        writer,
        &manifest,
        rows.into_iter().map(|(_, hash, _)| {
            let bytes = store
                .get_cose_by_hash_any(&hash)?
                .ok_or_else(|| Error::MissingObject(hash.hex()))?;
            Ok::<_, Error>((hash, bytes))
        }),
    )?;
    Ok(WrittenPullBundleResult {
        pulled,
        bundle_bytes,
        complete,
        next_cursor,
    })
}

fn collect_pull_rows(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    known: &std::collections::HashSet<fact_core::Hash>,
    options: PullBundleOptions,
) -> Result<(Vec<DependencyRow>, bool, Option<String>)> {
    if options.max_objects == Some(0) {
        return Err(Error::Sync(
            "pull object limit must be greater than zero".into(),
        ));
    }
    let mut rows = Vec::new();
    let mut seen = known.clone();
    let mut object_bytes = 0usize;
    let mut complete = true;
    let mut after = options
        .after
        .as_deref()
        .map(|value| {
            value
                .parse::<fact_core::Hash>()
                .map_err(|error| Error::Sync(format!("invalid pull cursor: {error}")))
        })
        .transpose()?;
    let mut last_cursor = after;
    loop {
        let remaining = options
            .max_objects
            .map(|limit| limit.saturating_sub(rows.len()))
            .unwrap_or(512);
        if remaining == 0 {
            complete = false;
            break;
        }
        let page_limit = options
            .max_objects
            .map(|_| remaining.saturating_add(1))
            .unwrap_or(512)
            .max(1);
        let mut root_page =
            store.list_object_summaries_page(ledger.as_bytes(), after.as_ref(), page_limit)?;
        if root_page.is_empty() {
            break;
        }
        let fetched = root_page.len();
        let has_more_roots = options
            .max_objects
            .is_some_and(|_| root_page.len() > remaining);
        if has_more_roots {
            root_page.truncate(remaining);
        }
        let root_cursor = root_page.last().map(|row| row.content_hash);
        let root_ids = root_page
            .iter()
            .map(|row| row.object_id)
            .collect::<Vec<_>>();
        let page = store.list_dependency_closure_for_objects(&root_ids)?;
        let page_start_rows = rows.len();
        for row @ (_, hash, _) in page {
            if after.is_some_and(|after| hash <= after) {
                continue;
            }
            if !seen.insert(hash) {
                last_cursor = Some(hash);
                continue;
            }
            if options.max_objects.is_some_and(|limit| rows.len() >= limit) {
                complete = false;
                return Ok((rows, complete, last_cursor.map(|hash| hash.hex())));
            }
            if let Some(limit) = options.max_object_bytes {
                let bytes = store
                    .get_cose_by_hash_any(&hash)?
                    .ok_or_else(|| Error::MissingObject(hash.hex()))?;
                if object_bytes + bytes.len() > limit {
                    if rows.is_empty() {
                        return Err(Error::Sync("next object exceeds pull byte limit".into()));
                    }
                    complete = false;
                    return Ok((rows, complete, last_cursor.map(|hash| hash.hex())));
                }
                object_bytes += bytes.len();
            }
            last_cursor = Some(hash);
            rows.push(row);
        }
        if rows.len() == page_start_rows {
            last_cursor = root_cursor;
        }
        if has_more_roots {
            complete = false;
            break;
        }
        if fetched < page_limit {
            break;
        }
        after = last_cursor;
    }
    Ok((
        rows,
        complete,
        (!complete)
            .then(|| last_cursor.map(|hash| hash.hex()))
            .flatten(),
    ))
}

/// Encode object bytes into a deterministic protocol bundle.
pub fn encode_bundle(
    ledger: uuid::Uuid,
    objects: &[(fact_core::Hash, Vec<u8>)],
) -> Result<Vec<u8>> {
    let mut objects = objects.iter().collect::<Vec<_>>();
    objects.sort_by_key(|(hash, _)| *hash);
    let entries = objects
        .iter()
        .map(|(hash, bytes)| {
            let id = fact_crypto::decode_sign1(bytes)
                .ok()
                .and_then(|cose| serde_json::from_slice::<serde_json::Value>(&cose.payload).ok())
                .and_then(|value| {
                    value
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                });
            Ok((
                id.ok_or_else(|| Error::Validation("missing object id".into()))?
                    .parse::<uuid::Uuid>()?,
                *hash,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let manifest = encode_bundle_manifest(ledger, entries)?;
    let mut bundle = Vec::new();
    fact_commitment::try_write_bundle_sorted_slices(
        &mut bundle,
        &manifest,
        objects
            .into_iter()
            .map(|(hash, bytes)| Ok::<_, fact_commitment::FrameError>((*hash, bytes.as_slice()))),
    )
    .map_err(|error| Error::Sync(error.to_string()))?;
    Ok(bundle)
}

fn encode_bundle_manifest<I>(ledger: uuid::Uuid, entries: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = (uuid::Uuid, fact_core::Hash)>,
{
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_by_key(|(_, hash)| *hash);
    Ok(fact_canonical::encode(&serde_json::to_vec(
        &serde_json::json!({
            "schema":"facts-protocol-bundle-v0",
            "protocol_version":0,
            "bundle_id":fact_commitment::deterministic_bundle_id_from_hashes(entries.iter().map(|(_, hash)| *hash)),
            "object_count":entries.len(),
            "ledger_id":ledger.to_string(),
            "objects":entries.iter().map(|(object_id, hash)| {
                serde_json::json!({"object_id":object_id,"content_hash":hash.hex()})
            }).collect::<Vec<_>>(),
            "dependency_refs":[],
            "sender_signature":null,
            "expected_commitment_hash":null,
            "base_commitment_hash":null
        }),
    )?)?)
}

/// Import a bundle with full authorization checks.
pub fn import_bundle(
    store: &fact_store::Store,
    objects: &[Vec<u8>],
) -> Result<Vec<OperationReceipt>> {
    let hashes = store.insert_authorized_bundle_with_projected_mode(
        objects,
        fact_store::ProjectedMode::Incremental,
    )?;
    objects
        .iter()
        .zip(hashes)
        .map(|(bytes, hash)| {
            let cose = fact_crypto::decode_sign1(bytes)?;
            let value: serde_json::Value = serde_json::from_slice(&cose.payload)
                .map_err(|error| Error::Validation(error.to_string()))?;
            Ok(OperationReceipt {
                object_id: value
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| Error::Validation("missing object id".into()))?
                    .to_owned(),
                content_hash: hash.hex(),
                object_type: value
                    .get("object_type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| Error::Validation("missing object type".into()))?
                    .to_owned(),
            })
        })
        .collect()
}

/// List objects that are pending because dependencies or authority are missing.
pub fn list_pending_objects(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
) -> Result<Vec<ObjectSummary>> {
    Ok(store
        .list_pending_objects(ledger_id.as_bytes())?
        .into_iter()
        .map(|(object_id, content_hash, object_type)| ObjectSummary {
            object_id: object_id.to_string(),
            content_hash: content_hash.hex(),
            object_type,
        })
        .collect())
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
mod tests {
    use super::*;
    use crate::workflow::{create_ledger, BootstrapLedgerInput};

    #[test]
    fn object_and_bundle_sync_workflows_round_trip() {
        let source = fact_store::Store::open_memory().unwrap();
        let bootstrap = create_ledger(
            &source,
            BootstrapLedgerInput {
                namespace: "local.sync-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed: [81; 32],
                nonce: [82; 16],
            },
        )
        .unwrap();
        let ledger = uuid::Uuid::parse_str(&bootstrap.ledger_id).unwrap();
        fact_store::Store::reset_debug_metrics();
        let objects = export_bundle(&source, ledger).unwrap();
        assert_eq!(objects.len(), 6);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects_with_dependencies, 0);
        assert!(metrics.list_dependency_closure_for_objects > 0);

        let validation = validate_object_bytes(&objects[0]).unwrap();
        assert!(validation.valid);
        assert!(validation.signed);

        let ledger_object = objects
            .iter()
            .find(|bytes| object_has_ledger(bytes))
            .unwrap();
        let first_id = object_id(ledger_object);
        let exported = export_object(&source, ledger, first_id).unwrap();
        assert_eq!(exported.object_id, first_id);
        assert_eq!(exported.bytes, *ledger_object);

        fact_store::Store::reset_debug_metrics();
        let listed = list_objects(&source, ledger).unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(fact_store::Store::debug_metrics().list_objects, 0);

        let first_page = list_objects_page(
            &source,
            ledger,
            ListObjectsOptions {
                after: None,
                limit: 2,
            },
        )
        .unwrap();
        assert_eq!(first_page.objects.len(), 2);
        assert!(!first_page.complete);
        let second_page = list_objects_page(
            &source,
            ledger,
            ListObjectsOptions {
                after: first_page.next_cursor.clone(),
                limit: 2,
            },
        )
        .unwrap();
        assert_eq!(second_page.objects.len(), 1);
        assert!(second_page.complete);
        assert!(second_page.next_cursor.is_none());
        let first_ids = first_page
            .objects
            .iter()
            .map(|object| object.object_id.clone())
            .collect::<std::collections::HashSet<_>>();
        assert!(second_page
            .objects
            .iter()
            .all(|object| !first_ids.contains(&object.object_id)));

        let read = read_object(&source, ledger, &first_id.to_string()).unwrap();
        assert_eq!(read.object_id, first_id);
        assert_eq!(
            read.object_type,
            read.payload["object_type"].as_str().unwrap()
        );
        assert_eq!(read.bytes, *ledger_object);

        let object_pairs = objects
            .iter()
            .map(|bytes| {
                let payload = fact_crypto::decode_sign1(bytes).unwrap().payload;
                (fact_core::Hash::digest(&payload), bytes.clone())
            })
            .collect::<Vec<_>>();
        let bundle = encode_bundle(ledger, &object_pairs).unwrap();
        assert_eq!(decode_bundle_or_snapshot_objects(&bundle).unwrap().len(), 6);
        assert_eq!(decode_bundle_or_snapshot_slices(&bundle).unwrap().len(), 6);

        let mut streamed_bundle = Vec::new();
        fact_store::Store::reset_debug_metrics();
        let streamed = write_bundle_from_store(&source, ledger, &mut streamed_bundle).unwrap();
        assert_eq!(streamed.exported, 6);
        assert_eq!(streamed.bundle_bytes, streamed_bundle.len());
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects_with_dependencies, 0);
        assert!(metrics.list_dependency_closure_for_objects > 0);
        assert_eq!(
            decode_bundle_or_snapshot_objects(&streamed_bundle)
                .unwrap()
                .len(),
            6
        );

        fact_store::Store::reset_debug_metrics();
        let exported_page = export_bundle_with_options(
            &source,
            ledger,
            PullBundleOptions {
                after: None,
                max_objects: Some(2),
                max_object_bytes: None,
            },
        )
        .unwrap();
        assert_eq!(exported_page.exported, 2);
        assert!(!exported_page.complete);
        assert!(exported_page.next_cursor.is_some());
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects_with_dependencies, 0);
        assert!(metrics.list_dependency_closure_for_objects > 0);
        let exported_hashes = exported_page
            .objects
            .iter()
            .map(|bytes| {
                let payload = fact_crypto::decode_sign1(bytes).unwrap().payload;
                fact_core::Hash::digest(&payload)
            })
            .collect::<std::collections::HashSet<_>>();
        let resumed_export = export_bundle_with_options(
            &source,
            ledger,
            PullBundleOptions {
                after: exported_page.next_cursor.clone(),
                max_objects: Some(2),
                max_object_bytes: None,
            },
        )
        .unwrap();
        let resumed_export_hashes = resumed_export
            .objects
            .iter()
            .map(|bytes| {
                let payload = fact_crypto::decode_sign1(bytes).unwrap().payload;
                fact_core::Hash::digest(&payload)
            })
            .collect::<std::collections::HashSet<_>>();
        assert!(exported_hashes.is_disjoint(&resumed_export_hashes));

        let mut paged_bundle = Vec::new();
        let paged_written = write_bundle_from_store_with_options(
            &source,
            ledger,
            PullBundleOptions {
                after: None,
                max_objects: Some(2),
                max_object_bytes: None,
            },
            &mut paged_bundle,
        )
        .unwrap();
        assert_eq!(paged_written.exported, 2);
        assert_eq!(paged_written.bundle_bytes, paged_bundle.len());
        assert!(!paged_written.complete);
        assert!(paged_written.next_cursor.is_some());
        assert_eq!(
            decode_bundle_or_snapshot_objects(&paged_bundle)
                .unwrap()
                .len(),
            2
        );

        let mut paged_ledger_bundle = Vec::new();
        fact_store::Store::reset_debug_metrics();
        let paged_ledger = write_ledger_bundle_from_store_with_options(
            &source,
            ledger,
            PullBundleOptions {
                after: None,
                max_objects: Some(2),
                max_object_bytes: None,
            },
            &mut paged_ledger_bundle,
        )
        .unwrap();
        assert_eq!(paged_ledger.exported, 2);
        assert!(!paged_ledger.complete);
        assert!(paged_ledger.next_cursor.is_some());
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects_with_dependencies, 0);
        assert_eq!(metrics.list_objects_with_dependencies_page, 0);
        assert_eq!(
            decode_bundle_or_snapshot_objects(&paged_ledger_bundle)
                .unwrap()
                .len(),
            2
        );
        let ledger_hashes = bundle_object_hashes(&paged_ledger_bundle);
        let mut resumed_ledger_bundle = Vec::new();
        let resumed_ledger = write_ledger_bundle_from_store_with_options(
            &source,
            ledger,
            PullBundleOptions {
                after: paged_ledger.next_cursor.clone(),
                max_objects: Some(2),
                max_object_bytes: None,
            },
            &mut resumed_ledger_bundle,
        )
        .unwrap();
        assert_eq!(resumed_ledger.exported, 1);
        assert!(resumed_ledger.complete);
        assert!(resumed_ledger.next_cursor.is_none());
        let resumed_ledger_hashes = bundle_object_hashes(&resumed_ledger_bundle);
        assert!(ledger_hashes.is_disjoint(&resumed_ledger_hashes));

        let target = fact_store::Store::open_memory().unwrap();
        let pushed = push_bundle_to_store(&target, &bundle).unwrap();
        assert_eq!(pushed.imported, 6);

        fact_store::Store::reset_debug_metrics();
        let pulled =
            pull_bundle_from_store(&source, ledger, &std::collections::HashSet::new()).unwrap();
        assert_eq!(pulled.pulled, 6);
        assert!(pulled.complete);
        assert_eq!(pulled.bundle_bytes, pulled.bundle.len());
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects_with_dependencies, 0);
        assert!(metrics.list_dependency_closure_for_objects > 0);
        assert_eq!(
            decode_bundle_or_snapshot_objects(&pulled.bundle)
                .unwrap()
                .len(),
            6
        );

        let mut written_pull = Vec::new();
        let written = write_pull_bundle_from_store(
            &source,
            ledger,
            &std::collections::HashSet::new(),
            &mut written_pull,
        )
        .unwrap();
        assert_eq!(written.pulled, 6);
        assert_eq!(written.bundle_bytes, written_pull.len());
        assert!(written.complete);
        assert_eq!(pulled.bundle, written_pull);
        assert_eq!(
            decode_bundle_or_snapshot_objects(&written_pull)
                .unwrap()
                .len(),
            6
        );
    }

    #[test]
    fn pull_bundle_from_store_supports_page_limits() {
        let source = fact_store::Store::open_memory().unwrap();
        let bootstrap = create_ledger(
            &source,
            BootstrapLedgerInput {
                namespace: "local.sync-sdk-limit-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed: [83; 32],
                nonce: [84; 16],
            },
        )
        .unwrap();
        let ledger = uuid::Uuid::parse_str(&bootstrap.ledger_id).unwrap();

        let pulled = pull_bundle_from_store_with_options(
            &source,
            ledger,
            &std::collections::HashSet::new(),
            PullBundleOptions {
                after: None,
                max_objects: Some(2),
                max_object_bytes: None,
            },
        )
        .unwrap();
        assert_eq!(pulled.pulled, 2);
        assert!(!pulled.complete);
        let cursor = pulled.next_cursor.clone().unwrap();
        assert_eq!(
            decode_bundle_or_snapshot_objects(&pulled.bundle)
                .unwrap()
                .len(),
            2
        );
        let first_hashes = bundle_object_hashes(&pulled.bundle);

        let resumed = pull_bundle_from_store_with_options(
            &source,
            ledger,
            &std::collections::HashSet::new(),
            PullBundleOptions {
                after: Some(cursor),
                max_objects: Some(2),
                max_object_bytes: None,
            },
        )
        .unwrap();
        assert!(resumed.pulled > 0);
        assert!(resumed.pulled <= 2);
        if resumed.complete {
            assert!(resumed.next_cursor.is_none());
        } else {
            assert!(resumed.next_cursor.is_some());
        }
        let resumed_hashes = bundle_object_hashes(&resumed.bundle);
        assert!(first_hashes.is_disjoint(&resumed_hashes));

        let first_object_size = source
            .list_objects_with_dependencies(ledger.as_bytes())
            .unwrap()
            .first()
            .and_then(|(_, hash, _)| source.get_cose_by_hash_any(hash).unwrap())
            .unwrap()
            .len();
        let error = pull_bundle_from_store_with_options(
            &source,
            ledger,
            &std::collections::HashSet::new(),
            PullBundleOptions {
                after: None,
                max_objects: None,
                max_object_bytes: Some(first_object_size - 1),
            },
        )
        .unwrap_err();
        assert!(matches!(error, Error::Sync(message) if message.contains("byte limit")));

        let mut written = Vec::new();
        let result = write_pull_bundle_from_store_with_options(
            &source,
            ledger,
            &std::collections::HashSet::new(),
            PullBundleOptions {
                after: None,
                max_objects: Some(2),
                max_object_bytes: None,
            },
            &mut written,
        )
        .unwrap();
        assert_eq!(result.pulled, 2);
        assert!(!result.complete);
        assert!(result.next_cursor.is_some());
        assert_eq!(
            decode_bundle_or_snapshot_objects(&written).unwrap().len(),
            2
        );
    }

    fn object_id(bytes: &[u8]) -> uuid::Uuid {
        let payload = fact_crypto::decode_sign1(bytes).unwrap().payload;
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        uuid::Uuid::parse_str(value["id"].as_str().unwrap()).unwrap()
    }

    fn bundle_object_hashes(bytes: &[u8]) -> std::collections::HashSet<fact_core::Hash> {
        decode_bundle_or_snapshot_objects(bytes)
            .unwrap()
            .into_iter()
            .map(|bytes| {
                let payload = fact_crypto::decode_sign1(&bytes).unwrap().payload;
                fact_core::Hash::digest(&payload)
            })
            .collect()
    }

    fn object_has_ledger(bytes: &[u8]) -> bool {
        let payload = fact_crypto::decode_sign1(bytes).unwrap().payload;
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        value.get("ledger_id").is_some()
    }
}
