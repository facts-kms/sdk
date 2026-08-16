//! Ledger-scoped identity directory extension workflows.

use crate::{
    environment::LedgerEntry,
    identity::{create_identity_with_runtime, CreateIdentityInput},
    proposition::parse_uuid7,
    reference::short_uuid_reference,
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

const DIRECTORY_EXTENSION: &str = "fact.directory";
const DIRECTORY_BUNDLE_SCHEMA: &str = "facts-extension-bundle-v0";
const DIRECTORY_EVENT_SCHEMA: &str = "facts-extension-event-v0";
const ACTOR_TYPES: &[&str] = &["human", "agent", "service"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryAddInput {
    pub display_name: String,
    pub actor_id: Option<uuid::Uuid>,
    pub key_id: Option<uuid::Uuid>,
    pub alias: Option<String>,
    pub actor_type: Option<String>,
    pub role: Option<String>,
    pub source: Option<String>,
    pub verified_by: Option<String>,
    pub with_identity: bool,
    pub seed: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryRemoveInput {
    pub reference: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DirectoryAddResult {
    pub created: bool,
    pub identity_created: bool,
    pub display_name: String,
    pub actor_id: uuid::Uuid,
    pub actor_ref: String,
    pub key_id: Option<uuid::Uuid>,
    pub key_ref: Option<String>,
    pub alias: Option<String>,
    pub actor_type: Option<String>,
    #[serde(skip_serializing)]
    pub seed: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DirectoryRemoveResult {
    pub removed: bool,
    pub display_name: String,
    pub actor_id: uuid::Uuid,
    pub actor_ref: String,
    pub alias: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DirectoryEntry {
    pub display_name: String,
    pub actor_id: uuid::Uuid,
    pub actor_ref: String,
    pub key_id: Option<uuid::Uuid>,
    pub key_ref: Option<String>,
    pub alias: Option<String>,
    pub actor_type: Option<String>,
    pub role: Option<String>,
    pub source: Option<String>,
    pub verified_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DirectoryResolveResult {
    pub query: String,
    pub display_name: String,
    pub actor_id: uuid::Uuid,
    pub actor_ref: String,
    pub key_id: Option<uuid::Uuid>,
    pub key_ref: Option<String>,
    pub alias: Option<String>,
    pub actor_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ExportDirectoryResult {
    pub exported: usize,
    pub bundle_bytes: usize,
    #[serde(skip_serializing)]
    pub bundle: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ImportDirectoryResult {
    pub imported: usize,
    pub skipped: usize,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct DirectoryExtensionBundle {
    schema: String,
    extension: String,
    ledger_id: uuid::Uuid,
    events: Vec<serde_json::Value>,
}

pub fn add_directory_entry(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: DirectoryAddInput,
) -> Result<DirectoryAddResult> {
    let runtime = production_runtime();
    add_directory_entry_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn add_directory_entry_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: DirectoryAddInput,
    runtime: &dyn SdkRuntime,
) -> Result<DirectoryAddResult> {
    if entry.read_only {
        return Err(Error::ReadOnlyLedger);
    }
    let display_name = clean_required("display name", &input.display_name)?;
    let alias = input
        .alias
        .map(|value| clean_optional("alias", value))
        .transpose()?;
    let actor_type = input
        .actor_type
        .map(|value| clean_actor_type(&value))
        .transpose()?;
    let role = input
        .role
        .map(|value| clean_optional("role", value))
        .transpose()?;
    let source = input
        .source
        .map(|value| clean_optional("source", value))
        .transpose()?;
    let verified_by = input
        .verified_by
        .map(|value| clean_optional("verified_by", value))
        .transpose()?;
    let ledger_id = parse_uuid7(&entry.ledger_id, "ledger")?;
    let active_actor_id = parse_uuid7(&entry.actor_id, "actor")?;
    let active_key_id = parse_uuid7(&entry.key_id, "key")?;
    let store = fact_store::Store::open(&entry.database)?;
    let mut identity_created = false;
    let mut identity_seed = None;
    let (actor_id, key_id) = if input.with_identity {
        if input.actor_id.is_some() || input.key_id.is_some() {
            return Err(Error::Validation(
                "--with-identity omits --actor and --key".into(),
            ));
        }
        let actor_type = actor_type
            .clone()
            .ok_or_else(|| Error::Validation("--with-identity requires --type".into()))?;
        let new_seed = input.seed.unwrap_or(runtime.seed()?);
        let identity = create_identity_with_runtime(
            &store,
            CreateIdentityInput {
                namespace: "local.identity".to_owned(),
                seed: new_seed,
                actor_type,
            },
            runtime,
        )?;
        identity_created = true;
        identity_seed = Some(new_seed);
        (identity.actor_id, Some(identity.key_id))
    } else {
        let actor_id = input.actor_id.ok_or_else(|| {
            Error::Validation("directory add requires --actor or --with-identity".into())
        })?;
        if store.get_cose_by_id_any(actor_id.as_bytes())?.is_none() {
            return Err(Error::MissingObject(format!(
                "actor identity is not imported: {actor_id}"
            )));
        }
        let key_id = match input.key_id {
            Some(key_id) => Some(key_id),
            None => store
                .get_actor_key_binding_for_actor(actor_id.as_bytes())?
                .map(|(_, key_id)| key_id),
        };
        (actor_id, key_id)
    };
    if let Some(alias) = &alias {
        ensure_alias_unique(&store, ledger_id, alias, actor_id)?;
    }
    store.insert_directory_extension_event(fact_store::DirectoryExtensionEventInput {
        event_id: runtime.next_uuid_v7()?,
        ledger_id,
        actor_id: active_actor_id,
        signing_key_id: active_key_id,
        target_actor_id: actor_id,
        target_key_id: key_id,
        operation: "set-profile".to_owned(),
        display_name: Some(display_name.clone()),
        alias: alias.clone(),
        actor_type: actor_type.clone(),
        role,
        source,
        verified_by,
        created_at: runtime.timestamp(),
    })?;
    let _ = seed;
    Ok(DirectoryAddResult {
        created: true,
        identity_created,
        display_name,
        actor_id,
        actor_ref: short_uuid_reference(actor_id),
        key_id,
        key_ref: key_id.map(short_uuid_reference),
        alias,
        actor_type,
        seed: identity_seed,
    })
}

pub fn list_directory(entry: &LedgerEntry) -> Result<Vec<DirectoryEntry>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    store
        .list_projected_directory(ledger.as_bytes())?
        .into_iter()
        .map(projected_to_entry)
        .collect()
}

pub fn show_directory_entry(entry: &LedgerEntry, reference: &str) -> Result<DirectoryEntry> {
    let resolved = resolve_directory_reference(entry, reference)?;
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let row = store
        .get_projected_directory_by_actor(ledger.as_bytes(), resolved.actor_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject(format!("directory entry not found: {reference}")))?;
    projected_to_entry(row)
}

pub fn remove_directory_entry(
    entry: &LedgerEntry,
    input: DirectoryRemoveInput,
) -> Result<DirectoryRemoveResult> {
    if entry.read_only {
        return Err(Error::ReadOnlyLedger);
    }
    let runtime = production_runtime();
    let ledger_id = parse_uuid7(&entry.ledger_id, "ledger")?;
    let active_actor_id = parse_uuid7(&entry.actor_id, "actor")?;
    let active_key_id = parse_uuid7(&entry.key_id, "key")?;
    let resolved = resolve_directory_reference(entry, &input.reference)?;
    let store = fact_store::Store::open(&entry.database)?;
    store.insert_directory_extension_event(fact_store::DirectoryExtensionEventInput {
        event_id: runtime.next_uuid_v7()?,
        ledger_id,
        actor_id: active_actor_id,
        signing_key_id: active_key_id,
        target_actor_id: resolved.actor_id,
        target_key_id: resolved.key_id,
        operation: "remove".to_owned(),
        display_name: None,
        alias: None,
        actor_type: None,
        role: None,
        source: None,
        verified_by: None,
        created_at: runtime.timestamp(),
    })?;
    Ok(DirectoryRemoveResult {
        removed: true,
        display_name: resolved.display_name,
        actor_id: resolved.actor_id,
        actor_ref: resolved.actor_ref,
        alias: resolved.alias,
    })
}

pub fn resolve_directory_reference(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<DirectoryResolveResult> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let trimmed = reference.trim();
    if let Ok(actor_id) = parse_uuid7(trimmed, "actor") {
        return resolve_actor_row(&store, ledger, actor_id, trimmed);
    }
    let matches = store.list_projected_directory_by_alias_or_name(ledger.as_bytes(), trimmed)?;
    match matches.as_slice() {
        [row] => Ok(resolve_result_from_row(trimmed, row)),
        [] => {
            let actor_id = resolve_identity_object_reference(&store, trimmed, "actor")?;
            resolve_actor_row(&store, ledger, actor_id, trimmed)
        }
        rows => Err(Error::AmbiguousReference(format!(
            "{trimmed} matches {} directory entries; use an actor ID or unique alias",
            rows.len()
        ))),
    }
}

pub fn resolve_directory_actor_reference(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<uuid::Uuid> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let trimmed = reference.trim();
    if let Ok(actor_id) = parse_uuid7(trimmed, "actor") {
        return Ok(actor_id);
    }
    let matches = store.list_projected_directory_by_alias_or_name(ledger.as_bytes(), trimmed)?;
    match matches.as_slice() {
        [row] => Ok(row.target_actor_id),
        [] => resolve_identity_object_reference(&store, trimmed, "actor"),
        rows => Err(Error::AmbiguousReference(format!(
            "{trimmed} matches {} directory entries; use an actor ID or unique alias",
            rows.len()
        ))),
    }
}

pub fn resolve_directory_key_reference(entry: &LedgerEntry, reference: &str) -> Result<uuid::Uuid> {
    let store = fact_store::Store::open(&entry.database)?;
    let trimmed = reference.trim();
    if let Ok(key_id) = parse_uuid7(trimmed, "key") {
        return Ok(key_id);
    }
    resolve_identity_object_reference(&store, trimmed, "key")
}

pub fn export_directory(entry: &LedgerEntry) -> Result<ExportDirectoryResult> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let rows = store.list_directory_extension_events(ledger.as_bytes())?;
    let mut events = Vec::new();
    for row in &rows {
        events.push(serde_json::from_slice::<serde_json::Value>(&row.payload)?);
    }
    let bundle = serde_json::to_vec_pretty(&DirectoryExtensionBundle {
        schema: DIRECTORY_BUNDLE_SCHEMA.to_owned(),
        extension: DIRECTORY_EXTENSION.to_owned(),
        ledger_id: ledger,
        events,
    })?;
    Ok(ExportDirectoryResult {
        exported: rows.len(),
        bundle_bytes: bundle.len(),
        bundle,
    })
}

pub fn import_directory(entry: &LedgerEntry, bytes: &[u8]) -> Result<ImportDirectoryResult> {
    if entry.read_only {
        return Err(Error::ReadOnlyLedger);
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let bundle: DirectoryExtensionBundle = serde_json::from_slice(bytes)?;
    if bundle.schema != DIRECTORY_BUNDLE_SCHEMA
        || bundle.extension != DIRECTORY_EXTENSION
        || bundle.ledger_id != ledger
    {
        return Err(Error::Validation(
            "directory extension bundle does not match the selected ledger".into(),
        ));
    }
    let store = fact_store::Store::open(&entry.database)?;
    let mut imported = 0;
    let mut skipped = 0;
    for event in bundle.events {
        if event.get("schema").and_then(serde_json::Value::as_str) != Some(DIRECTORY_EVENT_SCHEMA) {
            return Err(Error::Validation(
                "directory extension bundle contains an invalid event".into(),
            ));
        }
        let payload = fact_canonical::encode(&serde_json::to_vec(&event)?)?;
        if store.import_directory_extension_event_payload(&payload)? {
            imported += 1;
        } else {
            skipped += 1;
        }
    }
    Ok(ImportDirectoryResult { imported, skipped })
}

fn resolve_actor_row(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor_id: uuid::Uuid,
    query: &str,
) -> Result<DirectoryResolveResult> {
    if let Some(row) =
        store.get_projected_directory_by_actor(ledger.as_bytes(), actor_id.as_bytes())?
    {
        return Ok(resolve_result_from_row(query, &row));
    }
    if store.get_cose_by_id_any(actor_id.as_bytes())?.is_none() {
        return Err(Error::MissingObject(format!(
            "actor identity not found: {actor_id}"
        )));
    }
    Ok(DirectoryResolveResult {
        query: query.to_owned(),
        display_name: format!("actor {}", short_uuid_reference(actor_id)),
        actor_id,
        actor_ref: short_uuid_reference(actor_id),
        key_id: store
            .get_actor_key_binding_for_actor(actor_id.as_bytes())?
            .map(|(_, key_id)| key_id),
        key_ref: store
            .get_actor_key_binding_for_actor(actor_id.as_bytes())?
            .map(|(_, key_id)| short_uuid_reference(key_id)),
        alias: None,
        actor_type: None,
    })
}

fn resolve_identity_object_reference(
    store: &fact_store::Store,
    reference: &str,
    object_type: &str,
) -> Result<uuid::Uuid> {
    let normalized = reference.trim().to_ascii_lowercase();
    let mut matches = Vec::new();
    for (id, _, kind) in store.list_identity_objects()? {
        if kind != object_type {
            continue;
        }
        let full = id.to_string();
        let short = short_uuid_reference(id);
        if full == normalized || full.starts_with(&normalized) || short == normalized {
            matches.push(id);
        }
    }
    match matches.as_slice() {
        [id] => Ok(*id),
        [] => Err(Error::MissingObject(format!(
            "no {object_type} identity matches reference {reference}"
        ))),
        _ => Err(Error::AmbiguousReference(reference.to_owned())),
    }
}

fn projected_to_entry(row: fact_store::ProjectedDirectoryRow) -> Result<DirectoryEntry> {
    Ok(DirectoryEntry {
        display_name: row.display_name,
        actor_id: row.target_actor_id,
        actor_ref: short_uuid_reference(row.target_actor_id),
        key_id: row.target_key_id,
        key_ref: row.target_key_id.map(short_uuid_reference),
        alias: row.alias,
        actor_type: row.actor_type,
        role: row.role,
        source: row.source,
        verified_by: row.verified_by,
    })
}

fn resolve_result_from_row(
    query: &str,
    row: &fact_store::ProjectedDirectoryRow,
) -> DirectoryResolveResult {
    DirectoryResolveResult {
        query: query.to_owned(),
        display_name: row.display_name.clone(),
        actor_id: row.target_actor_id,
        actor_ref: short_uuid_reference(row.target_actor_id),
        key_id: row.target_key_id,
        key_ref: row.target_key_id.map(short_uuid_reference),
        alias: row.alias.clone(),
        actor_type: row.actor_type.clone(),
    }
}

fn ensure_alias_unique(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    alias: &str,
    actor_id: uuid::Uuid,
) -> Result<()> {
    let matches = store.list_projected_directory_by_alias_or_name(ledger.as_bytes(), alias)?;
    if matches
        .iter()
        .any(|row| row.alias.as_deref() == Some(alias) && row.target_actor_id != actor_id)
    {
        return Err(Error::Conflict(format!(
            "directory alias already exists: {alias}"
        )));
    }
    Ok(())
}

fn clean_required(field: &str, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::Validation(format!("{field} must not be empty")));
    }
    Ok(value.to_owned())
}

fn clean_optional(field: &str, value: String) -> Result<String> {
    let value = clean_required(field, &value)?;
    if field == "alias"
        && !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(Error::Validation(
            "alias may contain only letters, numbers, '-', '_', '.', ':', or '/'".into(),
        ));
    }
    Ok(value)
}

fn clean_actor_type(value: &str) -> Result<String> {
    let value = value.trim().to_lowercase();
    if !ACTOR_TYPES.contains(&value.as_str()) {
        return Err(Error::Validation(
            "actor type must be human, agent, or service".into(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        environment::LedgerEntry,
        workflow::{create_ledger, BootstrapLedgerInput},
    };

    fn entry() -> (tempfile::TempDir, LedgerEntry, [u8; 32]) {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [71; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.directory-sdk-test".into(),
                created_at: "2026-08-11T12:00:00.000Z".into(),
                seed,
                nonce: [72; 16],
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
    fn directory_add_resolve_and_bundle_sync_work() {
        let (_temp, entry, seed) = entry();
        let added = add_directory_entry(
            &entry,
            &seed,
            DirectoryAddInput {
                display_name: "Research Agent".into(),
                actor_id: None,
                key_id: None,
                alias: Some("research-agent".into()),
                actor_type: Some("agent".into()),
                role: Some("research".into()),
                source: None,
                verified_by: None,
                with_identity: true,
                seed: Some([73; 32]),
            },
        )
        .unwrap();
        assert!(added.identity_created);
        assert_eq!(added.display_name, "Research Agent");
        assert_eq!(added.alias.as_deref(), Some("research-agent"));
        assert_eq!(added.actor_type.as_deref(), Some("agent"));
        assert!(added.seed.is_some());

        let listed = list_directory(&entry).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].display_name, "Research Agent");
        assert_eq!(listed[0].actor_id, added.actor_id);

        let resolved = resolve_directory_reference(&entry, "research-agent").unwrap();
        assert_eq!(resolved.actor_id, added.actor_id);
        assert_eq!(resolved.display_name, "Research Agent");

        let exported = export_directory(&entry).unwrap();
        assert_eq!(exported.exported, 1);
        assert!(exported.bundle_bytes > 0);
        let imported = import_directory(&entry, &exported.bundle).unwrap();
        assert_eq!(imported.imported, 0);
        assert_eq!(imported.skipped, 1);

        let store = fact_store::Store::open(&entry.database).unwrap();
        let ledger = parse_uuid7(&entry.ledger_id, "ledger").unwrap();
        assert_eq!(
            store
                .list_directory_extension_events(ledger.as_bytes())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .list_projected_directory(ledger.as_bytes())
                .unwrap()
                .len(),
            1
        );
    }
}
