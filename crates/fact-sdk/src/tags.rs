//! Proposition tag helpers backed by ledger-scoped extension events.

use crate::{
    environment::LedgerEntry,
    proposition::{
        list_propositions_page, parse_uuid7, resolve_any_proposition_item,
        search_proposition_content, ListPropositionStatus, ListPropositionsFilter,
        ListPropositionsPage, SearchResult,
    },
    relationship::{list_relationships, ListRelationshipsFilter},
    runtime::production_runtime,
    Error, Result,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use unicode_normalization::UnicodeNormalization;

const TAG_RELATIONSHIP: &str = "fact:tags";
const DEFAULT_TAG_TEXT_PAGE_SIZE: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagOperation {
    Show,
    Add,
    Remove,
    Set,
    Clear,
}

impl TagOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Show => "show",
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Set => "set",
            Self::Clear => "clear",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagSearchMatch {
    Any,
    All,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TagResult {
    pub proposition_id: uuid::Uuid,
    pub reference: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    pub operation: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TagSearchResult {
    pub proposition_id: uuid::Uuid,
    pub reference: String,
    pub status: String,
    pub summary: String,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TagListItem {
    pub tag: String,
    pub count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ExportTagsResult {
    pub exported: usize,
    pub bundle_bytes: usize,
    #[serde(skip_serializing)]
    pub bundle: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ImportTagsResult {
    pub imported: usize,
    pub skipped: usize,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct TagExtensionBundle {
    schema: String,
    extension: String,
    ledger_id: uuid::Uuid,
    events: Vec<serde_json::Value>,
}

pub fn show_tags(entry: &LedgerEntry, reference: &str) -> Result<TagResult> {
    let proposition_id = resolve_proposition(entry, reference)?;
    Ok(TagResult {
        proposition_id,
        reference: crate::reference::short_uuid_reference(proposition_id),
        tags: effective_tags(entry, proposition_id)?,
        changed: None,
        operation: TagOperation::Show.as_str().to_owned(),
    })
}

pub fn mutate_tags(
    entry: &LedgerEntry,
    _seed: &[u8; 32],
    reference: &str,
    operation: TagOperation,
    tags: &[String],
) -> Result<TagResult> {
    if entry.read_only {
        return Err(Error::ReadOnlyLedger);
    }
    let proposition_id = resolve_proposition(entry, reference)?;
    let current = effective_tag_set(entry, proposition_id)?;
    let requested = normalize_tags(tags)?;
    let desired = match operation {
        TagOperation::Show => current.clone(),
        TagOperation::Add => current.union(&requested).cloned().collect(),
        TagOperation::Remove => current.difference(&requested).cloned().collect(),
        TagOperation::Set => requested,
        TagOperation::Clear => BTreeSet::new(),
    };
    let changed = desired != current;
    if changed {
        let ledger_id = parse_uuid7(&entry.ledger_id, "ledger")?;
        let actor_id = parse_uuid7(&entry.actor_id, "actor")?;
        let signing_key_id = parse_uuid7(&entry.key_id, "key")?;
        let runtime = production_runtime();
        let store = fact_store::Store::open(&entry.database)?;
        store.insert_tag_extension_event(fact_store::TagExtensionEventInput {
            event_id: runtime.next_uuid_v7()?,
            ledger_id,
            proposition_id,
            actor_id,
            signing_key_id,
            operation: operation.as_str().to_owned(),
            tags: desired.iter().cloned().collect(),
            created_at: runtime.timestamp(),
        })?;
    }
    Ok(TagResult {
        proposition_id,
        reference: crate::reference::short_uuid_reference(proposition_id),
        tags: desired.into_iter().collect(),
        changed: Some(changed),
        operation: operation.as_str().to_owned(),
    })
}

pub fn list_tags(
    entry: &LedgerEntry,
    filter: ListPropositionsFilter,
    page: ListPropositionsPage,
) -> Result<Vec<TagListItem>> {
    let after = page.after.clone();
    let offset = page.offset;
    let limit = page.limit;
    let candidates = list_propositions_page(
        entry,
        filter,
        Some(ListPropositionsPage {
            offset: 0,
            limit: None,
            after,
        }),
    )?;
    let tag_sets = effective_tag_sets(entry)?;
    let mut counts = BTreeMap::<String, usize>::new();
    for item in candidates {
        let Some(item_tags) = tag_sets.get(&item.proposition_id) else {
            continue;
        };
        for tag in item_tags {
            *counts.entry(tag.clone()).or_default() += 1;
        }
    }
    Ok(counts
        .into_iter()
        .map(|(tag, count)| TagListItem { tag, count })
        .skip(offset)
        .take(limit.unwrap_or(usize::MAX))
        .collect())
}

pub fn search_tags(
    entry: &LedgerEntry,
    tags: &[String],
    match_mode: TagSearchMatch,
    filter: ListPropositionsFilter,
    page: ListPropositionsPage,
    text: Option<&str>,
) -> Result<Vec<TagSearchResult>> {
    let requested = normalize_tags(tags)?;
    if requested.is_empty() {
        return Err(Error::Validation(
            "tag search requires at least one tag".into(),
        ));
    }
    let tag_sets = effective_tag_sets(entry)?;
    if let Some(text) = text.map(str::trim).filter(|value| !value.is_empty()) {
        return search_tags_by_indexed_text(
            entry, text, &requested, match_mode, filter, page, &tag_sets,
        );
    }
    let after = page.after.clone();
    let offset = page.offset;
    let limit = page.limit;
    let candidates = list_propositions_page(
        entry,
        filter,
        Some(ListPropositionsPage {
            offset: 0,
            limit: None,
            after,
        }),
    )?;
    let mut matched_results = Vec::new();
    for item in candidates {
        let Some(item_tags) = tag_sets.get(&item.proposition_id) else {
            continue;
        };
        if tags_match(item_tags, &requested, match_mode) {
            matched_results.push(TagSearchResult {
                proposition_id: item.proposition_id,
                reference: item.reference,
                status: item.status,
                summary: item.summary,
                tags: item_tags.iter().cloned().collect(),
            });
        }
    }
    let results = matched_results
        .into_iter()
        .skip(offset)
        .take(limit.unwrap_or(usize::MAX))
        .collect();
    Ok(results)
}

pub fn export_tags(entry: &LedgerEntry) -> Result<ExportTagsResult> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let rows = store.list_tag_extension_events(ledger.as_bytes())?;
    let mut events = Vec::new();
    for event in &rows {
        events.push(serde_json::from_slice::<serde_json::Value>(&event.payload)?);
    }
    let bundle = serde_json::to_vec_pretty(&TagExtensionBundle {
        schema: "facts-extension-bundle-v0".to_owned(),
        extension: "fact.tags".to_owned(),
        ledger_id: ledger,
        events,
    })?;
    Ok(ExportTagsResult {
        exported: rows.len(),
        bundle_bytes: bundle.len(),
        bundle,
    })
}

pub fn import_tags(entry: &LedgerEntry, bundle: &[u8]) -> Result<ImportTagsResult> {
    if entry.read_only {
        return Err(Error::ReadOnlyLedger);
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let bundle: TagExtensionBundle = serde_json::from_slice(bundle)?;
    if bundle.schema != "facts-extension-bundle-v0"
        || bundle.extension != "fact.tags"
        || bundle.ledger_id != ledger
    {
        return Err(Error::Validation(
            "tag extension bundle does not match the selected ledger".into(),
        ));
    }
    let store = fact_store::Store::open(&entry.database)?;
    let mut imported = 0;
    let mut skipped = 0;
    for event in bundle.events {
        let payload = fact_canonical::encode(&serde_json::to_vec(&event)?)?;
        if store.import_tag_extension_event_payload(&payload)? {
            imported += 1;
        } else {
            skipped += 1;
        }
    }
    Ok(ImportTagsResult { imported, skipped })
}

pub fn search_proposition_content_by_tags(
    entry: &LedgerEntry,
    text: &str,
    status: Option<ListPropositionStatus>,
    effective: bool,
    page_size: usize,
    tags: &[String],
    match_mode: TagSearchMatch,
) -> Result<Vec<SearchResult>> {
    let requested = normalize_tags(tags)?;
    if requested.is_empty() {
        return Err(Error::Validation(
            "tag search requires at least one tag".into(),
        ));
    }
    if page_size == 0 {
        return Ok(Vec::new());
    }
    let tag_sets = effective_tag_sets(entry)?;
    let mut candidate_page_size = indexed_candidate_page_size(page_size, 0);
    let mut results = Vec::new();
    loop {
        let candidates =
            search_proposition_content(entry, text, status, effective, candidate_page_size)?;
        results.clear();
        let mut seen = HashSet::new();
        for item in &candidates {
            let Some(proposition_id) = item.proposition_id else {
                continue;
            };
            if !seen.insert(item.object_id) {
                continue;
            }
            let Some(item_tags) = tag_sets.get(&proposition_id) else {
                continue;
            };
            if tags_match(item_tags, &requested, match_mode) {
                results.push(item.clone());
                if results.len() >= page_size {
                    break;
                }
            }
        }
        if results.len() >= page_size
            || candidates.len() < candidate_page_size
            || candidate_page_size == usize::MAX
        {
            break;
        }
        candidate_page_size = grow_candidate_page_size(candidate_page_size);
    }
    results.truncate(page_size);
    Ok(results)
}

pub fn normalize_tags(tags: &[String]) -> Result<BTreeSet<String>> {
    let mut normalized = BTreeSet::new();
    for tag in tags {
        let tag = tag.trim().nfc().collect::<String>().to_lowercase();
        if tag.is_empty() {
            return Err(Error::Validation("tags must not be empty".into()));
        }
        if tag.chars().any(char::is_whitespace) {
            return Err(Error::Validation("tags must not contain whitespace".into()));
        }
        if !tag
            .chars()
            .all(|ch| ch.is_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':'))
        {
            return Err(Error::Validation(format!("invalid tag: {tag}")));
        }
        normalized.insert(tag);
    }
    Ok(normalized)
}

fn resolve_proposition(entry: &LedgerEntry, reference: &str) -> Result<uuid::Uuid> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    Ok(resolve_any_proposition_item(&store, ledger, reference)?.proposition_id)
}

fn effective_tags(entry: &LedgerEntry, proposition_id: uuid::Uuid) -> Result<Vec<String>> {
    Ok(effective_tag_set(entry, proposition_id)?
        .into_iter()
        .collect())
}

fn effective_tag_sets(entry: &LedgerEntry) -> Result<BTreeMap<uuid::Uuid, BTreeSet<String>>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let mut tag_sets = BTreeMap::<uuid::Uuid, BTreeSet<String>>::new();
    let mut extension_targets = BTreeSet::new();
    for proposition_id in store.list_tag_extension_targets(ledger.as_bytes())? {
        extension_targets.insert(proposition_id);
        tag_sets.entry(proposition_id).or_default();
    }
    for (proposition_id, tag) in store.list_projected_tags(ledger.as_bytes())? {
        tag_sets.entry(proposition_id).or_default().insert(tag);
    }
    let legacy = legacy_effective_tag_sets(entry)?;
    for (proposition_id, tags) in legacy {
        if !extension_targets.contains(&proposition_id) {
            tag_sets.insert(proposition_id, tags);
        }
    }
    Ok(tag_sets)
}

fn legacy_effective_tag_sets(
    entry: &LedgerEntry,
) -> Result<BTreeMap<uuid::Uuid, BTreeSet<String>>> {
    let records = list_relationships(
        entry,
        ListRelationshipsFilter {
            source_object_id: None,
            relationship: Some(TAG_RELATIONSHIP.to_owned()),
            target_object_id: None,
        },
    )?;
    let mut tag_sets = BTreeMap::new();
    for record in records {
        let Some(metadata) = record.metadata else {
            continue;
        };
        let Some(values) = metadata.get("tags").and_then(serde_json::Value::as_array) else {
            continue;
        };
        let tag_values = values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        tag_sets.insert(record.source_object_id, normalize_tags(&tag_values)?);
    }
    Ok(tag_sets)
}

fn search_tags_by_indexed_text(
    entry: &LedgerEntry,
    text: &str,
    requested: &BTreeSet<String>,
    match_mode: TagSearchMatch,
    filter: ListPropositionsFilter,
    page: ListPropositionsPage,
    tag_sets: &BTreeMap<uuid::Uuid, BTreeSet<String>>,
) -> Result<Vec<TagSearchResult>> {
    let needed = page
        .limit
        .unwrap_or(DEFAULT_TAG_TEXT_PAGE_SIZE)
        .saturating_add(page.offset)
        .max(1);
    let mut candidate_page_size = indexed_candidate_page_size(needed, page.offset);
    let mut matched_results = Vec::new();
    loop {
        let candidates =
            search_proposition_content(entry, text, filter.status, true, candidate_page_size)?;
        matched_results.clear();
        let mut seen = HashSet::new();
        for item in &candidates {
            let Some(proposition_id) = item.proposition_id else {
                continue;
            };
            if !seen.insert(proposition_id) {
                continue;
            }
            let Some(status) = item.status.as_ref() else {
                continue;
            };
            if filter.status.is_none() && !filter.all && status != "accepted" {
                continue;
            }
            let Some(item_tags) = tag_sets.get(&proposition_id) else {
                continue;
            };
            if tags_match(item_tags, requested, match_mode) {
                matched_results.push(TagSearchResult {
                    proposition_id,
                    reference: item.reference.clone(),
                    status: status.clone(),
                    summary: item.summary.clone(),
                    tags: item_tags.iter().cloned().collect(),
                });
            }
        }
        if matched_results.len() >= needed
            || candidates.len() < candidate_page_size
            || candidate_page_size == usize::MAX
        {
            break;
        }
        candidate_page_size = grow_candidate_page_size(candidate_page_size);
    }
    Ok(matched_results
        .into_iter()
        .skip(page.offset)
        .take(page.limit.unwrap_or(usize::MAX))
        .collect())
}

fn tags_match(
    item_tags: &BTreeSet<String>,
    requested: &BTreeSet<String>,
    match_mode: TagSearchMatch,
) -> bool {
    match match_mode {
        TagSearchMatch::Any => requested.iter().any(|tag| item_tags.contains(tag)),
        TagSearchMatch::All => requested.iter().all(|tag| item_tags.contains(tag)),
    }
}

fn indexed_candidate_page_size(page_size: usize, offset: usize) -> usize {
    page_size
        .saturating_add(offset)
        .saturating_mul(10)
        .max(page_size)
        .max(100)
}

fn grow_candidate_page_size(page_size: usize) -> usize {
    page_size.saturating_mul(2).max(page_size.saturating_add(1))
}

fn effective_tag_set(entry: &LedgerEntry, proposition_id: uuid::Uuid) -> Result<BTreeSet<String>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    if store
        .has_tag_extension_events_for_proposition(ledger.as_bytes(), proposition_id.as_bytes())?
    {
        return Ok(store
            .list_projected_tags_for_proposition(ledger.as_bytes(), proposition_id.as_bytes())?
            .into_iter()
            .collect());
    }
    legacy_effective_tag_set(entry, proposition_id)
}

fn legacy_effective_tag_set(
    entry: &LedgerEntry,
    proposition_id: uuid::Uuid,
) -> Result<BTreeSet<String>> {
    let records = list_relationships(
        entry,
        ListRelationshipsFilter {
            source_object_id: Some(proposition_id),
            relationship: Some(TAG_RELATIONSHIP.to_owned()),
            target_object_id: None,
        },
    )?;
    let mut tags = BTreeSet::new();
    for record in records {
        let Some(metadata) = record.metadata else {
            continue;
        };
        let Some(values) = metadata.get("tags").and_then(serde_json::Value::as_array) else {
            continue;
        };
        let tag_values = values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        tags = normalize_tags(&tag_values)?;
    }
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        environment::LedgerEntry,
        proposition::{create_proposition, DecisionOutcome},
        workflow::{create_ledger, BootstrapLedgerInput},
    };

    fn entry() -> (tempfile::TempDir, LedgerEntry, [u8; 32]) {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [51; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.tags-sdk-test".into(),
                created_at: "2026-08-11T12:00:00.000Z".into(),
                seed,
                nonce: [52; 16],
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
    fn tags_are_normalized_mutated_and_searched() {
        let (_temp, entry, seed) = entry();
        let created = create_proposition(
            &entry,
            &seed,
            b"# Tagged\n\nTag this proposition.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();

        let added = mutate_tags(
            &entry,
            &seed,
            &created.proposition_id.to_string(),
            TagOperation::Add,
            &["Policy".into(), "urgent".into(), "policy".into()],
        )
        .unwrap();
        assert_eq!(added.tags, vec!["policy", "urgent"]);
        assert_eq!(added.changed, Some(true));

        let repeated = mutate_tags(
            &entry,
            &seed,
            &created.proposition_id.to_string(),
            TagOperation::Add,
            &["policy".into()],
        )
        .unwrap();
        assert_eq!(repeated.tags, vec!["policy", "urgent"]);
        assert_eq!(repeated.changed, Some(false));

        let removed = mutate_tags(
            &entry,
            &seed,
            &created.proposition_id.to_string(),
            TagOperation::Remove,
            &["urgent".into()],
        )
        .unwrap();
        assert_eq!(removed.tags, vec!["policy"]);
        assert_eq!(
            show_tags(&entry, &created.proposition_id.to_string())
                .unwrap()
                .tags,
            vec!["policy"]
        );

        let found = search_tags(
            &entry,
            &["policy".into()],
            TagSearchMatch::All,
            ListPropositionsFilter {
                status: None,
                all: false,
            },
            ListPropositionsPage {
                offset: 0,
                limit: Some(100),
                after: None,
            },
            None,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].proposition_id, created.proposition_id);

        let listed = list_tags(
            &entry,
            ListPropositionsFilter {
                status: None,
                all: false,
            },
            ListPropositionsPage {
                offset: 0,
                limit: Some(100),
                after: None,
            },
        )
        .unwrap();
        assert_eq!(
            listed,
            vec![TagListItem {
                tag: "policy".into(),
                count: 1
            }]
        );

        let store = fact_store::Store::open(&entry.database).unwrap();
        let ledger = parse_uuid7(&entry.ledger_id, "ledger").unwrap();
        assert_eq!(
            store
                .list_tag_extension_events(ledger.as_bytes())
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            store
                .list_projected_tags_for_proposition(
                    ledger.as_bytes(),
                    created.proposition_id.as_bytes()
                )
                .unwrap(),
            vec!["policy"]
        );

        let exported = export_tags(&entry).unwrap();
        assert_eq!(exported.exported, 2);
        assert!(exported.bundle_bytes > 0);
        let imported = import_tags(&entry, &exported.bundle).unwrap();
        assert_eq!(imported.imported, 0);
        assert_eq!(imported.skipped, 2);
    }
}
