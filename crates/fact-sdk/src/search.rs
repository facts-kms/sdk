//! Search helpers built on the deterministic local lexical index.

use crate::{
    environment::LedgerEntry,
    models::{ObjectSummary, SearchHit},
    proposition::parse_uuid7,
    Error, Result,
};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SearchFilter {
    pub ledger_id: uuid::Uuid,
    pub text: String,
    pub page_size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RevisionSearchFilter {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposition_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub include_effective: bool,
    pub include_pending: bool,
    pub page_size: usize,
}

impl RevisionSearchFilter {
    pub fn effective(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            proposition_id: None,
            status: None,
            include_effective: true,
            include_pending: false,
            page_size: 20,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DeliberationSearchFilter {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposition_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub include_comments: bool,
    pub page_size: usize,
}

impl DeliberationSearchFilter {
    pub fn comments(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            proposition_id: None,
            revision_id: None,
            status: None,
            include_comments: true,
            page_size: 20,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CommentSearchFilter {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposition_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliberation_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment_phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_comment_id: Option<uuid::Uuid>,
    pub page_size: usize,
}

impl CommentSearchFilter {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            proposition_id: None,
            revision_id: None,
            deliberation_id: None,
            comment_phase: None,
            parent_comment_id: None,
            page_size: 20,
        }
    }
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SearchResult {
    pub object_id: uuid::Uuid,
    pub reference: String,
    pub object_type: String,
    pub content_hash: String,
    pub score: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposition_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliberation_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub effective: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct QuerySearchResult {
    pub schema: String,
    pub query_digest: String,
    pub ledger_id: uuid::Uuid,
    pub input_commitment_hash: String,
    pub results: Vec<QuerySearchHit>,
    pub next_cursor: Option<String>,
    pub completeness: String,
    pub operational_scope: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct QuerySearchHit {
    pub object_id: uuid::Uuid,
    pub content_hash: String,
    pub object_type: String,
    pub score: String,
}

#[derive(Clone, Debug)]
struct SearchDocument {
    object_id: uuid::Uuid,
    object_type: String,
    content_hash: fact_core::Hash,
    summary: String,
    proposition_id: Option<uuid::Uuid>,
    revision_id: Option<uuid::Uuid>,
    deliberation_id: Option<uuid::Uuid>,
    status: Option<String>,
    effective: bool,
    comment_phase: Option<String>,
    parent_comment_id: Option<uuid::Uuid>,
}

/// Search markdown-bearing objects supplied by a caller-provided store.
pub fn search_markdown(store: &fact_store::Store, filter: &SearchFilter) -> Result<Vec<SearchHit>> {
    Ok(store
        .search_markdown_index(filter.ledger_id.as_bytes(), &filter.text, filter.page_size)?
        .into_iter()
        .map(|hit| SearchHit {
            content_hash: hit.content_hash.hex(),
            score: hit.score,
            extraction_profile: hit.extraction_profile.to_owned(),
        })
        .collect())
}

/// Search revision content, with pending/non-effective content exposed only when requested.
pub fn search_revisions(
    entry: &LedgerEntry,
    filter: &RevisionSearchFilter,
) -> Result<Vec<SearchResult>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    if filter.page_size == 0 {
        return Ok(Vec::new());
    }

    if !filter.text.trim().is_empty() {
        let candidate_limit = filter.page_size.saturating_mul(100).max(filter.page_size);
        let hits = store.search_markdown_index_by_type(
            ledger.as_bytes(),
            &filter.text,
            candidate_limit,
            &["revision"],
        )?;
        let mut hit_revision_ids = Vec::new();
        let mut seen_hit_revision_ids = HashSet::new();
        for hit in &hits {
            if seen_hit_revision_ids.insert(hit.object_id) {
                hit_revision_ids.push(hit.object_id);
            }
        }
        let effective_status_by_revision = store
            .effective_revision_status_rows(ledger.as_bytes(), &hit_revision_ids)?
            .into_iter()
            .map(|row| (row.revision_id, row.status))
            .collect::<HashMap<_, _>>();
        let mut results = Vec::new();
        for hit in hits {
            let effective_status = effective_status_by_revision.get(&hit.object_id).cloned();
            let effective = effective_status.is_some();
            let Some(row) =
                store.object_payload_by_id(ledger.as_bytes(), hit.object_id.as_bytes())?
            else {
                continue;
            };
            let Some(document) = revision_document(row, effective, effective_status)? else {
                continue;
            };
            if filter
                .proposition_id
                .is_none_or(|id| document.proposition_id == Some(id))
                && filter
                    .status
                    .as_ref()
                    .is_none_or(|status| document.status.as_ref() == Some(status))
                && ((document.effective && filter.include_effective)
                    || (!document.effective && filter.include_pending))
            {
                results.push(SearchResult {
                    object_id: document.object_id,
                    reference: crate::reference::short_uuid_reference(document.object_id),
                    object_type: document.object_type,
                    content_hash: hit.content_hash.hex(),
                    score: hit.score,
                    summary: document.summary,
                    proposition_id: document.proposition_id,
                    revision_id: document.revision_id,
                    deliberation_id: document.deliberation_id,
                    status: document.status,
                    effective: document.effective,
                });
                if results.len() >= filter.page_size {
                    break;
                }
            }
        }
        return Ok(results);
    }

    let mut documents = Vec::new();
    for row in store.list_revision_search_payloads_filtered(
        ledger.as_bytes(),
        filter.proposition_id.as_ref().map(uuid::Uuid::as_bytes),
        filter.status.as_deref(),
        filter.include_effective,
        filter.include_pending,
        filter.page_size,
    )? {
        let effective = row.effective_status.is_some();
        let Some(document) = revision_document(
            fact_store::ObjectPayloadRow {
                object_id: row.object_id,
                content_hash: row.content_hash,
                object_type: "revision".to_owned(),
                payload: row.payload,
            },
            effective,
            row.effective_status,
        )?
        else {
            continue;
        };
        if filter
            .status
            .as_ref()
            .is_none_or(|status| document.status.as_ref() == Some(status))
            && ((document.effective && filter.include_effective)
                || (!document.effective && filter.include_pending))
        {
            documents.push(document);
        }
    }
    ranked_search(&store, ledger, "", filter.page_size, documents)
}

/// Search deliberations and optionally their comments.
pub fn search_deliberations(
    entry: &LedgerEntry,
    filter: &DeliberationSearchFilter,
) -> Result<Vec<SearchResult>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    if filter.page_size == 0 {
        return Ok(Vec::new());
    }
    if filter.text.trim().is_empty() {
        let deliberation_rows = store.list_deliberation_search_rows_filtered(
            ledger.as_bytes(),
            filter.proposition_id.as_ref().map(uuid::Uuid::as_bytes),
            filter.revision_id.as_ref().map(uuid::Uuid::as_bytes),
            filter.status.as_deref(),
            filter.page_size,
        )?;
        let metadata = search_metadata(&store, ledger, &deliberation_rows)?;
        let deliberation_ids = deliberation_rows
            .iter()
            .map(|row| row.deliberation_id)
            .collect::<HashSet<_>>();
        let mut documents = deliberation_documents(&deliberation_rows, &metadata);
        if filter.include_comments && documents.len() < filter.page_size {
            let comment_rows =
                comment_rows_for_deliberations(&store, ledger, Some(&deliberation_ids))?;
            documents.extend(
                comment_documents(comment_rows, &metadata)?
                    .into_iter()
                    .filter(|document| {
                        document
                            .deliberation_id
                            .is_some_and(|id| deliberation_ids.contains(&id))
                    }),
            );
        }
        return ranked_search(&store, ledger, "", filter.page_size, documents);
    }
    let deliberation_rows = deliberation_rows_for_filter(
        &store,
        ledger,
        filter.proposition_id,
        filter.revision_id,
        None,
    )?;
    let metadata = search_metadata(&store, ledger, &deliberation_rows)?;
    let deliberation_ids = deliberation_rows
        .iter()
        .filter_map(|row| {
            let status = deliberation_status(&metadata, row.deliberation_id, Some(row.revision_id));
            (filter
                .status
                .as_ref()
                .is_none_or(|expected| status.as_ref() == Some(expected)))
            .then_some(row.deliberation_id)
        })
        .collect::<HashSet<_>>();

    let mut documents = Vec::new();
    if filter.text.trim().is_empty() {
        documents.extend(
            deliberation_rows
                .iter()
                .filter(|row| deliberation_ids.contains(&row.deliberation_id))
                .map(|row| SearchDocument {
                    object_id: row.deliberation_id,
                    object_type: "deliberation".to_owned(),
                    content_hash: row.content_hash,
                    summary: deliberation_status(
                        &metadata,
                        row.deliberation_id,
                        Some(row.revision_id),
                    )
                    .unwrap_or_else(|| "deliberation".to_owned()),
                    proposition_id: Some(row.proposition_id),
                    revision_id: Some(row.revision_id),
                    deliberation_id: Some(row.deliberation_id),
                    status: deliberation_status(
                        &metadata,
                        row.deliberation_id,
                        Some(row.revision_id),
                    ),
                    effective: metadata.effective_revision_ids.contains(&row.revision_id),
                    comment_phase: None,
                    parent_comment_id: None,
                }),
        );
    }
    if filter.include_comments {
        let comment_rows = comment_rows_for_deliberations(&store, ledger, Some(&deliberation_ids))?;
        documents.extend(
            comment_documents(comment_rows, &metadata)?
                .into_iter()
                .filter(|document| {
                    document
                        .deliberation_id
                        .is_some_and(|id| deliberation_ids.contains(&id))
                }),
        );
    }
    ranked_search(
        &store,
        ledger,
        filter.text.as_str(),
        filter.page_size,
        documents,
    )
}

/// Search deliberation comments.
pub fn search_comments(
    entry: &LedgerEntry,
    filter: &CommentSearchFilter,
) -> Result<Vec<SearchResult>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    if filter.page_size == 0 {
        return Ok(Vec::new());
    }
    if filter.text.trim().is_empty()
        && filter.proposition_id.is_none()
        && filter.revision_id.is_none()
        && filter.deliberation_id.is_none()
    {
        let comment_rows = store.list_deliberation_comment_payloads_page(
            ledger.as_bytes(),
            filter.comment_phase.as_deref(),
            filter.parent_comment_id.as_ref().map(uuid::Uuid::as_bytes),
            filter.page_size,
        )?;
        let deliberation_ids = comment_deliberation_ids(&comment_rows)?;
        let deliberation_rows =
            store.list_deliberation_projecteds_by_ids(ledger.as_bytes(), &deliberation_ids)?;
        let metadata = search_metadata(&store, ledger, &deliberation_rows)?;
        let documents = comment_documents(comment_rows, &metadata)?
            .into_iter()
            .filter(|document| comment_document_matches_filter(document, filter, None))
            .collect::<Vec<_>>();
        return ranked_search(&store, ledger, "", filter.page_size, documents);
    }
    let deliberation_rows = deliberation_rows_for_filter(
        &store,
        ledger,
        filter.proposition_id,
        filter.revision_id,
        filter.deliberation_id,
    )?;
    let metadata = search_metadata(&store, ledger, &deliberation_rows)?;
    let allowed_deliberations = deliberation_rows
        .iter()
        .map(|row| row.deliberation_id)
        .collect::<HashSet<_>>();
    if !filter.text.trim().is_empty() {
        let candidate_limit = filter.page_size.saturating_mul(100).max(filter.page_size);
        let mut results = Vec::new();
        for hit in store.search_markdown_index_by_type(
            ledger.as_bytes(),
            &filter.text,
            candidate_limit,
            &["deliberation_comment"],
        )? {
            let Some(row) =
                store.object_payload_by_id(ledger.as_bytes(), hit.object_id.as_bytes())?
            else {
                continue;
            };
            let Some(document) = comment_document(&metadata, row)? else {
                continue;
            };
            if !comment_document_matches_filter(&document, filter, Some(&allowed_deliberations)) {
                continue;
            }
            results.push(SearchResult {
                object_id: document.object_id,
                reference: crate::reference::short_uuid_reference(document.object_id),
                object_type: document.object_type,
                content_hash: hit.content_hash.hex(),
                score: hit.score,
                summary: document.summary,
                proposition_id: document.proposition_id,
                revision_id: document.revision_id,
                deliberation_id: document.deliberation_id,
                status: document.status,
                effective: document.effective,
            });
            if results.len() >= filter.page_size {
                break;
            }
        }
        return Ok(results);
    }
    let comment_rows = if filter.proposition_id.is_some()
        || filter.revision_id.is_some()
        || filter.deliberation_id.is_some()
    {
        comment_rows_for_deliberations(&store, ledger, Some(&allowed_deliberations))?
    } else {
        comment_rows_for_deliberations(&store, ledger, None)?
    };
    let documents = comment_documents(comment_rows, &metadata)?
        .into_iter()
        .filter(|document| comment_document_matches_filter(document, filter, None))
        .collect::<Vec<_>>();
    ranked_search(
        &store,
        ledger,
        filter.text.as_str(),
        filter.page_size,
        documents,
    )
}

/// Execute a canonical local facts-protocol query against a store.
pub fn query_search(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    input: &[u8],
) -> Result<QuerySearchResult> {
    let query = fact_search::canonical_query(input).map_err(|_| {
        Error::Validation("query must be an exact canonical facts-protocol-query-v0 object".into())
    })?;
    let value: serde_json::Value = serde_json::from_slice(&query.bytes)?;
    let query_type = value["query_type"].as_str().unwrap_or_default();
    if query_type != "object" && query_type != "fact" {
        return Err(Error::Validation(
            "local search currently supports query_type=object|fact".into(),
        ));
    }
    if !value["prior_cursor"].is_null() {
        return Err(Error::Validation(
            "local search does not accept signed prior_cursor values".into(),
        ));
    }
    let requested_types = value["object_types"]
        .as_array()
        .map(|types| {
            types
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let search_hits = if let Some(search_text) = value["search_text"].as_str() {
        Some(if query_type == "fact" {
            store.search_markdown_index_by_type(
                ledger.as_bytes(),
                search_text,
                usize::MAX,
                &["revision"],
            )?
        } else {
            store.search_markdown_index(ledger.as_bytes(), search_text, usize::MAX)?
        })
    } else {
        None
    };
    let search_scores = search_hits.as_ref().map(|hits| {
        hits.iter()
            .map(|result| (result.content_hash, result.score.clone()))
            .collect::<HashMap<_, _>>()
    });
    let accepted_knowledge_revision_ids = if query_type == "fact" {
        if let Some(hits) = search_hits.as_ref() {
            let mut revision_ids = Vec::new();
            let mut seen = HashSet::new();
            for hit in hits {
                if hit.object_type == "revision" && seen.insert(hit.object_id) {
                    revision_ids.push(hit.object_id);
                }
            }
            store
                .knowledge_effective_revision_ids_for_revisions(ledger.as_bytes(), &revision_ids)?
        } else {
            store.knowledge_effective_revision_ids(ledger.as_bytes())?
        }
        .into_iter()
        .collect::<HashSet<_>>()
    } else {
        HashSet::new()
    };
    let all = if query_type == "fact" && search_hits.is_some() {
        search_hits
            .as_ref()
            .into_iter()
            .flatten()
            .filter(|hit| hit.object_type == "revision")
            .map(|hit| (hit.object_id, hit.content_hash, hit.object_type.clone()))
            .collect::<Vec<_>>()
    } else if query_type == "fact" {
        store
            .list_object_summaries_by_type(ledger.as_bytes(), "revision")?
            .into_iter()
            .map(|row| (row.object_id, row.content_hash, row.object_type))
            .collect::<Vec<_>>()
    } else if requested_types.is_empty() {
        store
            .list_object_summaries(ledger.as_bytes())?
            .into_iter()
            .map(|row| (row.object_id, row.content_hash, row.object_type))
            .collect::<Vec<_>>()
    } else {
        let mut seen_types = HashSet::new();
        let mut rows = Vec::new();
        for object_type in &requested_types {
            if !seen_types.insert(*object_type) {
                continue;
            }
            rows.extend(
                store
                    .list_object_summaries_by_type(ledger.as_bytes(), object_type)?
                    .into_iter()
                    .map(|row| (row.object_id, row.content_hash, row.object_type)),
            );
        }
        rows
    };
    let mut objects = Vec::new();
    for (id, hash, object_type) in all {
        if !requested_types.is_empty() && !requested_types.contains(&object_type.as_str()) {
            continue;
        }
        if !search_scores
            .as_ref()
            .is_none_or(|scores| scores.contains_key(&hash))
        {
            continue;
        }
        if query_type == "fact" {
            if object_type != "revision" {
                continue;
            }
            if !accepted_knowledge_revision_ids.contains(&id) {
                continue;
            }
        }
        objects.push((id, hash, object_type));
    }
    if query_type == "fact" {
        objects.sort_by(|(_, left_hash, _), (_, right_hash, _)| {
            let left_score = search_scores
                .as_ref()
                .and_then(|scores| scores.get(left_hash))
                .and_then(|score| fact_search::parse_score(score).ok());
            let right_score = search_scores
                .as_ref()
                .and_then(|scores| scores.get(right_hash))
                .and_then(|score| fact_search::parse_score(score).ok());
            right_score
                .zip(left_score)
                .map_or(std::cmp::Ordering::Equal, |(right, left)| {
                    right.cmp_numeric(&left)
                })
                .then_with(|| left_hash.cmp(right_hash))
        });
    }
    let tree =
        fact_commitment::MerkleTree::new(objects.iter().map(|(_, hash, _)| *hash).collect())?;
    let page_size = value["page_size"].as_u64().unwrap() as usize;
    let results = objects
        .into_iter()
        .take(page_size)
        .map(|(id, hash, object_type)| QuerySearchHit {
            object_id: id,
            content_hash: hash.hex(),
            object_type,
            score: search_scores
                .as_ref()
                .and_then(|scores| scores.get(&hash))
                .cloned()
                .unwrap_or_else(|| "0".into()),
        })
        .collect::<Vec<_>>();
    Ok(QuerySearchResult {
        schema: "facts-protocol-result-set-v0".into(),
        query_digest: query.digest.hex(),
        ledger_id: ledger,
        input_commitment_hash: tree.root.hex(),
        results,
        next_cursor: None,
        completeness: "complete-deterministic-profile".into(),
        operational_scope: "local".into(),
    })
}

#[derive(Clone, Debug)]
struct SearchMetadata {
    deliberation_links: HashMap<uuid::Uuid, (uuid::Uuid, uuid::Uuid)>,
    effective_revision_ids: HashSet<uuid::Uuid>,
    effective_status_by_revision: HashMap<uuid::Uuid, String>,
    settled_deliberations: HashMap<uuid::Uuid, String>,
}

fn search_metadata(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberations: &[fact_store::DeliberationRow],
) -> Result<SearchMetadata> {
    let mut revision_ids = Vec::new();
    let mut seen_revision_ids = HashSet::new();
    for row in deliberations {
        if seen_revision_ids.insert(row.revision_id) {
            revision_ids.push(row.revision_id);
        }
    }
    let effective_rows = store.effective_revision_status_rows(ledger.as_bytes(), &revision_ids)?;
    let effective_revision_ids = effective_rows
        .iter()
        .map(|row| row.revision_id)
        .collect::<HashSet<_>>();
    let effective_status_by_revision = effective_rows
        .into_iter()
        .map(|row| (row.revision_id, row.status))
        .collect::<HashMap<_, _>>();
    let deliberation_links = deliberations
        .iter()
        .map(|row| (row.deliberation_id, (row.proposition_id, row.revision_id)))
        .collect::<HashMap<_, _>>();
    let settled_deliberations = settlement_statuses(store, ledger, deliberations)?;
    Ok(SearchMetadata {
        deliberation_links,
        effective_revision_ids,
        effective_status_by_revision,
        settled_deliberations,
    })
}

fn deliberation_rows_for_filter(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: Option<uuid::Uuid>,
    revision_id: Option<uuid::Uuid>,
    deliberation_id: Option<uuid::Uuid>,
) -> Result<Vec<fact_store::DeliberationRow>> {
    let rows = if let Some(deliberation_id) = deliberation_id {
        store
            .deliberation_projected(ledger.as_bytes(), deliberation_id.as_bytes())?
            .into_iter()
            .collect::<Vec<_>>()
    } else if let Some(proposition_id) = proposition_id {
        store.list_deliberation_projecteds_by_proposition(
            ledger.as_bytes(),
            proposition_id.as_bytes(),
        )?
    } else {
        store.list_deliberation_projecteds(ledger.as_bytes())?
    };
    Ok(rows
        .into_iter()
        .filter(|row| proposition_id.is_none_or(|id| row.proposition_id == id))
        .filter(|row| revision_id.is_none_or(|id| row.revision_id == id))
        .collect())
}

fn comment_rows_for_deliberations(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberation_ids: Option<&HashSet<uuid::Uuid>>,
) -> Result<Vec<fact_store::ObjectPayloadRow>> {
    let Some(deliberation_ids) = deliberation_ids else {
        return store
            .list_deliberation_objects_by_type(ledger.as_bytes(), "deliberation_comment")
            .map_err(Into::into);
    };
    let deliberation_ids = deliberation_ids.iter().copied().collect::<Vec<_>>();
    store
        .list_objects_by_deliberations(ledger.as_bytes(), &deliberation_ids, "deliberation_comment")
        .map_err(Into::into)
}

fn settlement_statuses(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberations: &[fact_store::DeliberationRow],
) -> Result<HashMap<uuid::Uuid, String>> {
    let deliberation_ids = deliberations
        .iter()
        .map(|row| row.deliberation_id)
        .collect::<Vec<_>>();
    let rows =
        store.list_settlement_payloads_by_deliberations(ledger.as_bytes(), &deliberation_ids)?;
    let statuses = rows
        .into_iter()
        .filter_map(|row| {
            let value = serde_json::from_slice::<serde_json::Value>(&row.payload).ok()?;
            Some((
                value["body"]["deliberation_id"].as_str()?.parse().ok()?,
                value["body"]["outcome"].as_str()?.to_owned(),
            ))
        })
        .collect::<HashMap<_, _>>();
    Ok(statuses)
}

fn deliberation_documents(
    rows: &[fact_store::DeliberationRow],
    metadata: &SearchMetadata,
) -> Vec<SearchDocument> {
    rows.iter()
        .map(|row| SearchDocument {
            object_id: row.deliberation_id,
            object_type: "deliberation".to_owned(),
            content_hash: row.content_hash,
            summary: deliberation_status(metadata, row.deliberation_id, Some(row.revision_id))
                .unwrap_or_else(|| "deliberation".to_owned()),
            proposition_id: Some(row.proposition_id),
            revision_id: Some(row.revision_id),
            deliberation_id: Some(row.deliberation_id),
            status: deliberation_status(metadata, row.deliberation_id, Some(row.revision_id)),
            effective: metadata.effective_revision_ids.contains(&row.revision_id),
            comment_phase: None,
            parent_comment_id: None,
        })
        .collect()
}

fn revision_document(
    row: fact_store::ObjectPayloadRow,
    effective: bool,
    effective_status: Option<String>,
) -> Result<Option<SearchDocument>> {
    let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
    let Some(content) = value["body"]["content"]["bytes"]
        .as_str()
        .and_then(decode_b64url)
    else {
        return Ok(None);
    };
    let proposition_id = value["body"]["proposition_id"]
        .as_str()
        .and_then(|value| value.parse::<uuid::Uuid>().ok());
    let status = if effective {
        effective_status
    } else {
        Some("pending".to_owned())
    };
    Ok(Some(SearchDocument {
        object_id: row.object_id,
        object_type: "revision".to_owned(),
        content_hash: row.content_hash,
        summary: crate::proposition::summary_for_markdown(&content),
        proposition_id,
        revision_id: Some(row.object_id),
        deliberation_id: None,
        status,
        effective,
        comment_phase: None,
        parent_comment_id: None,
    }))
}

fn comment_documents(
    rows: Vec<fact_store::ObjectPayloadRow>,
    metadata: &SearchMetadata,
) -> Result<Vec<SearchDocument>> {
    rows.into_iter()
        .filter_map(|row| comment_document(metadata, row).transpose())
        .collect()
}

fn comment_deliberation_ids(rows: &[fact_store::ObjectPayloadRow]) -> Result<Vec<uuid::Uuid>> {
    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    for row in rows {
        let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
        if let Some(deliberation_id) = value["body"]["deliberation_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
        {
            if seen.insert(deliberation_id) {
                ids.push(deliberation_id);
            }
        }
    }
    Ok(ids)
}

fn comment_document(
    metadata: &SearchMetadata,
    row: fact_store::ObjectPayloadRow,
) -> Result<Option<SearchDocument>> {
    let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
    let Some(content) = value["body"]["content"]["bytes"]
        .as_str()
        .and_then(decode_b64url)
    else {
        return Ok(None);
    };
    let deliberation_id = value["body"]["deliberation_id"]
        .as_str()
        .and_then(|value| value.parse::<uuid::Uuid>().ok());
    let (proposition_id, revision_id) = deliberation_id
        .and_then(|id| metadata.deliberation_links.get(&id).copied())
        .map_or((None, None), |(proposition, revision)| {
            (Some(proposition), Some(revision))
        });
    Ok(Some(SearchDocument {
        object_id: row.object_id,
        object_type: "deliberation_comment".to_owned(),
        content_hash: row.content_hash,
        summary: crate::proposition::summary_for_markdown(&content),
        proposition_id,
        revision_id,
        deliberation_id,
        status: deliberation_id.and_then(|id| deliberation_status(metadata, id, revision_id)),
        effective: revision_id.is_some_and(|id| metadata.effective_revision_ids.contains(&id)),
        comment_phase: value["body"]["comment_phase"].as_str().map(str::to_owned),
        parent_comment_id: value["body"]["parent_comment_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok()),
    }))
}

fn comment_document_matches_filter(
    document: &SearchDocument,
    filter: &CommentSearchFilter,
    allowed_deliberations: Option<&HashSet<uuid::Uuid>>,
) -> bool {
    filter
        .proposition_id
        .is_none_or(|id| document.proposition_id == Some(id))
        && filter
            .revision_id
            .is_none_or(|id| document.revision_id == Some(id))
        && filter
            .deliberation_id
            .is_none_or(|id| document.deliberation_id == Some(id))
        && filter
            .comment_phase
            .as_ref()
            .is_none_or(|phase| document.comment_phase.as_ref() == Some(phase))
        && filter
            .parent_comment_id
            .is_none_or(|parent| document.parent_comment_id == Some(parent))
        && allowed_deliberations.is_none_or(|allowed| {
            document
                .deliberation_id
                .is_some_and(|id| allowed.contains(&id))
        })
}

fn deliberation_status(
    metadata: &SearchMetadata,
    deliberation_id: uuid::Uuid,
    revision_id: Option<uuid::Uuid>,
) -> Option<String> {
    metadata
        .settled_deliberations
        .get(&deliberation_id)
        .cloned()
        .or_else(|| {
            revision_id
                .and_then(|revision| metadata.effective_status_by_revision.get(&revision))
                .cloned()
        })
        .or_else(|| Some("pending".to_owned()))
}

fn ranked_search(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    text: &str,
    page_size: usize,
    documents: Vec<SearchDocument>,
) -> Result<Vec<SearchResult>> {
    if text.trim().is_empty() {
        return Ok(documents
            .into_iter()
            .take(page_size)
            .map(|document| SearchResult {
                object_id: document.object_id,
                reference: crate::reference::short_uuid_reference(document.object_id),
                object_type: document.object_type,
                content_hash: document.content_hash.hex(),
                score: "1".to_owned(),
                summary: document.summary,
                proposition_id: document.proposition_id,
                revision_id: document.revision_id,
                deliberation_id: document.deliberation_id,
                status: document.status,
                effective: document.effective,
            })
            .collect());
    }
    let allowed_hashes = documents
        .iter()
        .map(|document| document.content_hash)
        .collect::<Vec<_>>();
    let by_hash = documents
        .into_iter()
        .map(|document| (document.content_hash, document))
        .collect::<HashMap<_, _>>();
    Ok(store
        .search_markdown_index_filtered(ledger.as_bytes(), text, page_size, &allowed_hashes)?
        .into_iter()
        .filter_map(|hit| {
            let document = by_hash.get(&hit.content_hash)?;
            Some(SearchResult {
                object_id: document.object_id,
                reference: crate::reference::short_uuid_reference(document.object_id),
                object_type: document.object_type.clone(),
                content_hash: hit.content_hash.hex(),
                score: hit.score,
                summary: document.summary.clone(),
                proposition_id: document.proposition_id,
                revision_id: document.revision_id,
                deliberation_id: document.deliberation_id,
                status: document.status.clone(),
                effective: document.effective,
            })
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

/// List propositions for callers that need to layer their own matching logic.
pub fn search_propositions(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
) -> Result<Vec<ObjectSummary>> {
    list_objects_by_type(store, ledger_id, "proposition")
}

/// Find a single proposition by full ID or unambiguous prefix.
pub fn find_proposition(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
    reference: &str,
) -> Result<Option<ObjectSummary>> {
    let matches = store
        .resolve_object_reference(ledger_id.as_bytes(), reference, &["proposition"])?
        .into_iter()
        .map(|item| ObjectSummary {
            object_id: item.object_id.to_string(),
            content_hash: item.content_hash.hex(),
            object_type: item.object_type,
        })
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err(crate::Error::AmbiguousReference(reference.to_owned()));
    }
    Ok(matches.into_iter().next())
}

fn list_objects_by_type(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
    object_type: &str,
) -> Result<Vec<ObjectSummary>> {
    Ok(store
        .list_object_summaries_by_type(ledger_id.as_bytes(), object_type)?
        .into_iter()
        .map(|row| ObjectSummary {
            object_id: row.object_id.to_string(),
            content_hash: row.content_hash.hex(),
            object_type: row.object_type,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        discussion::create_comment,
        proposition::{create_proposition, update_proposition_content, DecisionOutcome},
        workflow::{create_ledger, BootstrapLedgerInput},
    };

    fn entry() -> (tempfile::TempDir, LedgerEntry, [u8; 32]) {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [31; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.search-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce: [32; 16],
            },
        )
        .unwrap();
        let seed_file = temp.path().join("seed");
        (
            temp,
            LedgerEntry {
                name: "test".into(),
                ledger_id: bootstrap.ledger_id,
                database,
                actor_id: bootstrap.actor_id,
                key_id: bootstrap.key_id,
                seed_file,
                read_only: false,
            },
            seed,
        )
    }

    #[test]
    fn revision_search_requires_explicit_pending_opt_in() {
        let (_temp, entry, seed) = entry();
        let created = create_proposition(
            &entry,
            &seed,
            b"# Stable\n\nVisible accepted content.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        update_proposition_content(
            &entry,
            &seed,
            &crate::reference::short_uuid_reference(created.proposition_id),
            b"# Draft\n\nHidden pending vocabulary.\n",
        )
        .unwrap();

        fact_store::Store::reset_debug_metrics();
        let effective = search_revisions(
            &entry,
            &RevisionSearchFilter {
                text: "accepted".into(),
                proposition_id: Some(created.proposition_id),
                status: Some("accepted".into()),
                include_effective: true,
                include_pending: false,
                page_size: 10,
            },
        )
        .unwrap();
        assert_eq!(effective.len(), 1);
        assert!(effective[0].effective);
        assert_eq!(fact_store::Store::debug_metrics().list_effective_state, 0);

        fact_store::Store::reset_debug_metrics();
        let hidden_without_opt_in = search_revisions(
            &entry,
            &RevisionSearchFilter {
                text: "vocabulary".into(),
                proposition_id: Some(created.proposition_id),
                status: None,
                include_effective: true,
                include_pending: false,
                page_size: 10,
            },
        )
        .unwrap();
        assert!(hidden_without_opt_in.is_empty());
        assert_eq!(fact_store::Store::debug_metrics().list_effective_state, 0);

        fact_store::Store::reset_debug_metrics();
        let pending = search_revisions(
            &entry,
            &RevisionSearchFilter {
                text: "vocabulary".into(),
                proposition_id: Some(created.proposition_id),
                status: Some("pending".into()),
                include_effective: false,
                include_pending: true,
                page_size: 10,
            },
        )
        .unwrap();
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].effective);
        assert_eq!(pending[0].object_type, "revision");
        assert_eq!(fact_store::Store::debug_metrics().list_effective_state, 0);

        fact_store::Store::reset_debug_metrics();
        let listed = search_revisions(
            &entry,
            &RevisionSearchFilter {
                text: String::new(),
                proposition_id: Some(created.proposition_id),
                status: None,
                include_effective: true,
                include_pending: false,
                page_size: 10,
            },
        )
        .unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].effective);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_effective_state, 0);
        assert_eq!(metrics.list_revision_search_payloads, 0);
        assert_eq!(metrics.list_knowledge_effective_revision_ids, 0);
        assert_eq!(metrics.list_object_payloads_by_type, 0);

        let store = fact_store::Store::open(&entry.database).unwrap();
        fact_store::Store::reset_debug_metrics();
        let found = find_proposition(
            &store,
            parse_uuid7(&entry.ledger_id, "ledger").unwrap(),
            &crate::reference::short_uuid_reference(created.proposition_id),
        )
        .unwrap()
        .unwrap();
        assert_eq!(found.object_id, created.proposition_id.to_string());
        assert_eq!(fact_store::Store::debug_metrics().list_objects, 0);
    }

    #[test]
    fn comment_and_deliberation_search_can_scope_to_review_content() {
        let (_temp, entry, seed) = entry();
        let created =
            create_proposition(&entry, &seed, b"# Reviewable\n\nAccepted content.\n", None)
                .unwrap();
        create_comment(
            &entry,
            &seed,
            &crate::reference::short_uuid_reference(created.proposition_id),
            b"# Note\n\nConsensus keyword appears here.\n",
        )
        .unwrap();

        fact_store::Store::reset_debug_metrics();
        let comments = search_comments(
            &entry,
            &CommentSearchFilter {
                text: "consensus".into(),
                proposition_id: Some(created.proposition_id),
                revision_id: Some(created.revision_id),
                deliberation_id: Some(created.deliberation_id),
                comment_phase: Some("pre-settlement".into()),
                parent_comment_id: None,
                page_size: 10,
            },
        )
        .unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].object_type, "deliberation_comment");
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_effective_state, 0);
        assert_eq!(metrics.list_objects_by_deliberation, 0);
        assert_eq!(metrics.search_index_candidate_rows, 1);

        fact_store::Store::reset_debug_metrics();
        let unscoped_comments = search_comments(
            &entry,
            &CommentSearchFilter {
                text: "consensus".into(),
                proposition_id: None,
                revision_id: None,
                deliberation_id: None,
                comment_phase: Some("pre-settlement".into()),
                parent_comment_id: None,
                page_size: 10,
            },
        )
        .unwrap();
        assert_eq!(unscoped_comments.len(), 1);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_object_payloads_by_type, 0);
        assert_eq!(metrics.list_objects_by_deliberation, 0);
        assert_eq!(metrics.search_index_candidate_rows, 1);

        fact_store::Store::reset_debug_metrics();
        let listed_comments = search_comments(
            &entry,
            &CommentSearchFilter {
                text: String::new(),
                proposition_id: None,
                revision_id: None,
                deliberation_id: None,
                comment_phase: Some("pre-settlement".into()),
                parent_comment_id: None,
                page_size: 10,
            },
        )
        .unwrap();
        assert_eq!(listed_comments.len(), 1);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_effective_state, 0);
        assert_eq!(metrics.list_deliberation_objects_by_type, 0);
        assert_eq!(metrics.list_objects_by_deliberation, 0);

        fact_store::Store::reset_debug_metrics();
        let listed_deliberations = search_deliberations(
            &entry,
            &DeliberationSearchFilter {
                text: String::new(),
                proposition_id: None,
                revision_id: None,
                status: None,
                include_comments: true,
                page_size: 10,
            },
        )
        .unwrap();
        assert!(!listed_deliberations.is_empty());
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_effective_state, 0);
        assert_eq!(metrics.list_deliberation_projecteds, 0);

        fact_store::Store::reset_debug_metrics();
        let deliberations = search_deliberations(
            &entry,
            &DeliberationSearchFilter {
                text: "consensus".into(),
                proposition_id: Some(created.proposition_id),
                revision_id: Some(created.revision_id),
                status: Some("pending".into()),
                include_comments: true,
                page_size: 10,
            },
        )
        .unwrap();
        assert_eq!(deliberations.len(), 1);
        assert_eq!(
            deliberations[0].deliberation_id,
            Some(created.deliberation_id)
        );
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_effective_state, 0);
        assert_eq!(metrics.list_objects_by_deliberation, 0);
    }

    #[test]
    fn canonical_query_search_returns_result_set() {
        let (_temp, entry, seed) = entry();
        let created = create_proposition(
            &entry,
            &seed,
            b"# Queryable\n\nNeedle content.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        let store = fact_store::Store::open(&entry.database).unwrap();
        let query = fact_canonical::encode(
            serde_json::to_vec(&serde_json::json!({
                "schema": "facts-protocol-query-v0",
                "query_type": "fact",
                "search_text": "needle",
                "ledger_ids": [entry.ledger_id],
                "object_types": ["revision"],
                "scope": {
                    "actor_ids": [],
                    "proposition_ids": [],
                    "revision_ids": [],
                    "deliberation_ids": []
                },
                "status": {
                    "accepted": null,
                    "rejected": null,
                    "settled": null,
                    "archived": null,
                    "withdrawn": null,
                    "divergent": null
                },
                "relationships": [],
                "search_profile": {
                    "id": "lexical-bm25-v0",
                    "version": "0"
                },
                "extraction_profile": {
                    "id": "facts-markdown-extraction-v0",
                    "version": "0"
                },
                "embedding_model": null,
                "ordering_profile": "score-desc-hash-asc-v0",
                "page_size": 10,
                "prior_cursor": null
            }))
            .unwrap()
            .as_slice(),
        )
        .unwrap();
        fact_store::Store::reset_debug_metrics();
        let result = query_search(&store, entry.ledger_id.parse().unwrap(), &query).unwrap();
        assert_eq!(result.schema, "facts-protocol-result-set-v0");
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].object_id, created.revision_id);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_effective_state, 0);
        assert_eq!(metrics.list_knowledge_effective_revision_ids, 0);
        assert_eq!(metrics.list_object_payloads_by_type, 0);

        let object_query = fact_canonical::encode(
            serde_json::to_vec(&serde_json::json!({
                "schema": "facts-protocol-query-v0",
                "query_type": "object",
                "search_text": null,
                "ledger_ids": [entry.ledger_id],
                "object_types": [],
                "scope": {
                    "actor_ids": [],
                    "proposition_ids": [],
                    "revision_ids": [],
                    "deliberation_ids": []
                },
                "status": {
                    "accepted": null,
                    "rejected": null,
                    "settled": null,
                    "archived": null,
                    "withdrawn": null,
                    "divergent": null
                },
                "relationships": [],
                "search_profile": {
                    "id": "hash-asc-v0",
                    "version": "0"
                },
                "extraction_profile": {
                    "id": "facts-markdown-extraction-v0",
                    "version": "0"
                },
                "embedding_model": null,
                "ordering_profile": "hash-asc-v0",
                "page_size": 10,
                "prior_cursor": null
            }))
            .unwrap()
            .as_slice(),
        )
        .unwrap();
        fact_store::Store::reset_debug_metrics();
        let object_result =
            query_search(&store, entry.ledger_id.parse().unwrap(), &object_query).unwrap();
        assert!(!object_result.results.is_empty());
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects, 0);
        assert_eq!(metrics.list_object_payloads, 0);
        assert_eq!(metrics.list_object_payloads_by_type, 0);
    }
}
