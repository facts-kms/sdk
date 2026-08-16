//! Proposition lifecycle workflows.

use crate::{
    environment::LedgerEntry,
    proposition::{
        authority_dependency_for_actor, dependency_hash, dependency_value, parse_uuid7,
        resolve_any_proposition_item, signed_envelope,
    },
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PropositionLifecycleResult {
    pub created: bool,
    pub object_type: String,
    pub lifecycle_id: uuid::Uuid,
    pub operation: String,
    pub proposition_id: uuid::Uuid,
    pub content_hash: String,
}

pub fn withdraw_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    reason: &str,
) -> Result<PropositionLifecycleResult> {
    let runtime = production_runtime();
    withdraw_proposition_with_runtime(entry, seed, reference, reason, runtime.as_ref())
}

pub fn withdraw_proposition_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    reason: &str,
    runtime: &dyn SdkRuntime,
) -> Result<PropositionLifecycleResult> {
    create_proposition_lifecycle(
        entry,
        seed,
        reference,
        "withdrawal",
        "withdraw",
        reason,
        runtime,
    )
}

pub fn restore_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    reason: &str,
) -> Result<PropositionLifecycleResult> {
    let runtime = production_runtime();
    restore_proposition_with_runtime(entry, seed, reference, reason, runtime.as_ref())
}

pub fn restore_proposition_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    reason: &str,
    runtime: &dyn SdkRuntime,
) -> Result<PropositionLifecycleResult> {
    create_proposition_lifecycle(
        entry,
        seed,
        reference,
        "withdrawal",
        "restore",
        reason,
        runtime,
    )
}

pub fn archive_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    reason: &str,
) -> Result<PropositionLifecycleResult> {
    let runtime = production_runtime();
    archive_proposition_with_runtime(entry, seed, reference, reason, runtime.as_ref())
}

pub fn archive_proposition_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    reason: &str,
    runtime: &dyn SdkRuntime,
) -> Result<PropositionLifecycleResult> {
    create_proposition_lifecycle(
        entry, seed, reference, "archival", "archive", reason, runtime,
    )
}

pub fn unarchive_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    reason: &str,
) -> Result<PropositionLifecycleResult> {
    let runtime = production_runtime();
    unarchive_proposition_with_runtime(entry, seed, reference, reason, runtime.as_ref())
}

pub fn unarchive_proposition_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    reason: &str,
    runtime: &dyn SdkRuntime,
) -> Result<PropositionLifecycleResult> {
    create_proposition_lifecycle(
        entry,
        seed,
        reference,
        "archival",
        "unarchive",
        reason,
        runtime,
    )
}

fn create_proposition_lifecycle(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    dimension: &str,
    operation: &str,
    reason: &str,
    runtime: &dyn SdkRuntime,
) -> Result<PropositionLifecycleResult> {
    ensure_writable(entry)?;
    if reason.is_empty() {
        return Err(Error::Validation("reason is required".into()));
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let proposition = store
        .get_cose_by_id(ledger.as_bytes(), item.proposition_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("proposition object is unavailable".into()))?;
    let capability = lifecycle_capability(operation)?;
    let (authority, generated_authority) =
        lifecycle_authority_for_actor(&store, ledger, actor, key_id, &key, capability, runtime)?;
    let authorization_ref = authority["object_id"].clone();
    let predecessors = lifecycle_tips(&store, ledger, item.proposition_id, dimension)?;
    let mut dependencies = vec![dependency_value(&proposition, "proposition")?, authority];
    for predecessor in &predecessors {
        let predecessor_object = store
            .get_cose_by_id(ledger.as_bytes(), predecessor.as_bytes())?
            .ok_or_else(|| Error::MissingObject("lifecycle predecessor missing".into()))?;
        dependencies.push(dependency_value(
            &predecessor_object,
            "proposition-lifecycle-predecessor",
        )?);
    }
    let lifecycle_id = runtime.next_uuid_v7()?;
    let lifecycle = signed_envelope(
        lifecycle_id,
        ledger,
        "proposition_lifecycle",
        actor,
        key_id,
        serde_json::json!({
            "proposition_id":item.proposition_id,
            "dimension":dimension,
            "operation":operation,
            "predecessor_ids":predecessors,
            "authorization_ref":authorization_ref,
            "reason":reason
        }),
        dependencies,
        &key,
        runtime,
    )?;
    let hash = dependency_hash(&lifecycle)?;
    if generated_authority.is_empty() {
        store.insert_authorized_object_with_projected_mode(
            &lifecycle,
            fact_store::ProjectedMode::Incremental,
        )?;
    } else {
        let mut bundle = generated_authority;
        bundle.push(lifecycle);
        store.insert_authorized_bundle_with_projected_mode(
            &bundle,
            fact_store::ProjectedMode::Incremental,
        )?;
    }
    Ok(PropositionLifecycleResult {
        created: true,
        object_type: "proposition_lifecycle".into(),
        lifecycle_id,
        operation: operation.into(),
        proposition_id: item.proposition_id,
        content_hash: hash.hex(),
    })
}

fn lifecycle_capability(operation: &str) -> Result<&'static str> {
    match operation {
        "withdraw" | "restore" => Ok("withdraw"),
        "archive" | "unarchive" => Ok("archive"),
        _ => Err(Error::Validation(format!(
            "unsupported lifecycle operation {operation:?}"
        ))),
    }
}

fn lifecycle_authority_for_actor(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor: uuid::Uuid,
    key_id: uuid::Uuid,
    key: &fact_crypto::SigningKey,
    capability: &str,
    runtime: &dyn SdkRuntime,
) -> Result<(serde_json::Value, Vec<Vec<u8>>)> {
    if let Some(authority) = authority_dependency_for_actor(store, ledger, actor, capability)? {
        return Ok((authority, Vec::new()));
    }
    let Some(admin_authority) = authority_dependency_for_actor(store, ledger, actor, "admin")?
    else {
        return Err(Error::MissingObject(format!(
            "actor {actor} has no {capability} authority on ledger {ledger}"
        )));
    };
    let grant_id = runtime.next_uuid_v7()?;
    let grant = signed_envelope(
        grant_id,
        ledger,
        "authorization_grant",
        actor,
        key_id,
        serde_json::json!({
            "grant_id":grant_id,
            "granting_actor_id":actor,
            "receiving_actor_id":actor,
            "capabilities":[capability],
            "scope":{"type":"ledger"},
            "validity":null,
            "constraints":{},
            "predecessor_grant_id":null
        }),
        vec![admin_authority],
        key,
        runtime,
    )?;
    let grant_hash = dependency_hash(&grant)?;
    Ok((
        serde_json::json!({
            "object_id":grant_id,
            "content_hash":grant_hash.hex(),
            "role":format!("{capability}-authority")
        }),
        vec![grant],
    ))
}

fn lifecycle_tips(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: uuid::Uuid,
    dimension: &str,
) -> Result<Vec<uuid::Uuid>> {
    Ok(store.proposition_lifecycle_tip_ids(
        ledger.as_bytes(),
        proposition_id.as_bytes(),
        dimension,
    )?)
}

fn ensure_writable(entry: &LedgerEntry) -> Result<()> {
    if entry.read_only {
        Err(Error::ReadOnlyLedger)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proposition::{
            accept_proposition, create_proposition, list_propositions, ListPropositionStatus,
            ListPropositionsFilter,
        },
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
                namespace: "local.lifecycle-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
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
    fn proposition_lifecycle_transitions_update_effective_projected() {
        let (_temp, entry, seed) = entry();
        let proposition =
            create_proposition(&entry, &seed, b"# Lifecycle\n\nTrack state.\n", None).unwrap();
        accept_proposition(&entry, &seed, Some(&proposition.proposition_id.to_string())).unwrap();

        fact_store::Store::reset_debug_metrics();
        let withdrawn = withdraw_proposition(
            &entry,
            &seed,
            &proposition.proposition_id.to_string(),
            "pause",
        )
        .unwrap();
        assert_eq!(withdrawn.operation, "withdraw");
        let store = fact_store::Store::open(&entry.database).unwrap();
        let ledger = parse_uuid7(&entry.ledger_id, "ledger").unwrap();
        let withdrawn_roles = dependency_roles(
            &store
                .get_cose_by_id(ledger.as_bytes(), withdrawn.lifecycle_id.as_bytes())
                .unwrap()
                .unwrap(),
        );
        assert!(withdrawn_roles.contains(&"withdraw-authority".to_owned()));
        assert!(!withdrawn_roles.contains(&"admin-authority".to_owned()));
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.projected_rebuilds, 0);
        assert_eq!(metrics.list_lifecycle_rows, 0);
        let withdrawn_items = list_propositions(
            &entry,
            ListPropositionsFilter {
                status: Some(ListPropositionStatus::Withdrawn),
                all: false,
            },
        )
        .unwrap();
        assert_eq!(withdrawn_items.len(), 1);

        fact_store::Store::reset_debug_metrics();
        let restored = restore_proposition(
            &entry,
            &seed,
            &proposition.proposition_id.to_string(),
            "resume",
        )
        .unwrap();
        assert_eq!(restored.operation, "restore");
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.projected_rebuilds, 0);
        assert_eq!(metrics.list_lifecycle_rows, 0);
        let withdrawn_items = list_propositions(
            &entry,
            ListPropositionsFilter {
                status: Some(ListPropositionStatus::Withdrawn),
                all: false,
            },
        )
        .unwrap();
        assert!(withdrawn_items.is_empty());

        fact_store::Store::reset_debug_metrics();
        let archived = archive_proposition(
            &entry,
            &seed,
            &proposition.proposition_id.to_string(),
            "store",
        )
        .unwrap();
        assert_eq!(archived.operation, "archive");
        let archived_roles = dependency_roles(
            &store
                .get_cose_by_id(ledger.as_bytes(), archived.lifecycle_id.as_bytes())
                .unwrap()
                .unwrap(),
        );
        assert!(archived_roles.contains(&"archive-authority".to_owned()));
        assert!(!archived_roles.contains(&"admin-authority".to_owned()));
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.projected_rebuilds, 0);
        assert_eq!(metrics.list_lifecycle_rows, 0);
        let archived_items = list_propositions(
            &entry,
            ListPropositionsFilter {
                status: Some(ListPropositionStatus::Archived),
                all: false,
            },
        )
        .unwrap();
        assert_eq!(archived_items.len(), 1);

        fact_store::Store::reset_debug_metrics();
        let unarchived = unarchive_proposition(
            &entry,
            &seed,
            &proposition.proposition_id.to_string(),
            "visible again",
        )
        .unwrap();
        assert_eq!(unarchived.operation, "unarchive");
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.projected_rebuilds, 0);
        assert_eq!(metrics.list_lifecycle_rows, 0);
        let archived_items = list_propositions(
            &entry,
            ListPropositionsFilter {
                status: Some(ListPropositionStatus::Archived),
                all: false,
            },
        )
        .unwrap();
        assert!(archived_items.is_empty());

        let read_only = LedgerEntry {
            read_only: true,
            ..entry.clone()
        };
        assert!(matches!(
            withdraw_proposition(
                &read_only,
                &seed,
                &proposition.proposition_id.to_string(),
                "no write"
            ),
            Err(Error::ReadOnlyLedger)
        ));
    }

    fn dependency_roles(cose: &[u8]) -> Vec<String> {
        let payload = fact_crypto::decode_sign1(cose).unwrap().payload;
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        value["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|dependency| dependency["role"].as_str().map(str::to_owned))
            .collect()
    }
}
