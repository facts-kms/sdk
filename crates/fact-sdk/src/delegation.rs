//! Delegation creation and revocation workflows.

use crate::{
    environment::LedgerEntry,
    identity::root_grant,
    models::OperationReceipt,
    proposition::{dependency_value, parse_uuid7, signed_envelope},
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct DelegationInput {
    pub delegatee_actor_id: uuid::Uuid,
    pub capability: String,
    pub scope: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_delegation_id: Option<uuid::Uuid>,
    pub redelegable: bool,
    #[serde(default)]
    pub constraints: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DelegationRevocationInput {
    pub delegation_id: uuid::Uuid,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<uuid::Uuid>,
}

pub fn create_delegation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: DelegationInput,
) -> Result<OperationReceipt> {
    let runtime = production_runtime();
    create_delegation_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn create_delegation_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: DelegationInput,
    runtime: &dyn SdkRuntime,
) -> Result<OperationReceipt> {
    ensure_writable(entry)?;
    if input.capability.is_empty() {
        return Err(Error::Validation(
            "delegation capability is required".into(),
        ));
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let delegator = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let (_, root_grant) = root_grant(&store, ledger)?;
    let delegatee = store
        .get_cose_by_id_any(input.delegatee_actor_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("delegatee actor is not imported".into()))?;
    let delegatee_value: serde_json::Value =
        serde_json::from_slice(&fact_crypto::decode_sign1(&delegatee)?.payload)?;
    if delegatee_value["object_type"].as_str() != Some("actor") {
        return Err(Error::Validation(
            "delegatee reference is not an actor".into(),
        ));
    }
    let mut dependencies = vec![
        dependency_value(&root_grant, "admin-authority")?,
        dependency_value(&delegatee, "delegatee-actor")?,
    ];
    if let Some(parent_id) = input.parent_delegation_id {
        let parent = store
            .get_cose_by_id(ledger.as_bytes(), parent_id.as_bytes())?
            .ok_or_else(|| Error::MissingObject("parent delegation is unavailable".into()))?;
        dependencies.push(dependency_value(&parent, "parent-delegation")?);
    }
    let delegation_id = runtime.next_uuid_v7()?;
    let cose = signed_envelope(
        delegation_id,
        ledger,
        "delegation",
        delegator,
        key_id,
        serde_json::json!({
            "delegator_actor_id": delegator,
            "delegatee_actor_id": input.delegatee_actor_id,
            "capability": input.capability,
            "scope": input.scope,
            "validity": input.validity,
            "parent_delegation_id": input.parent_delegation_id,
            "redelegable": input.redelegable,
            "constraints": input.constraints,
        }),
        dependencies,
        &key,
        runtime,
    )?;
    let content_hash = store.insert_authorized_object_with_projected_mode(
        &cose,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(OperationReceipt {
        object_id: delegation_id.to_string(),
        content_hash: content_hash.hex(),
        object_type: "delegation".into(),
    })
}

pub fn revoke_delegation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: DelegationRevocationInput,
) -> Result<OperationReceipt> {
    let runtime = production_runtime();
    revoke_delegation_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn revoke_delegation_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: DelegationRevocationInput,
    runtime: &dyn SdkRuntime,
) -> Result<OperationReceipt> {
    ensure_writable(entry)?;
    if input.reason.is_empty() {
        return Err(Error::Validation(
            "delegation revocation reason is required".into(),
        ));
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let revoked = store
        .get_cose_by_id(ledger.as_bytes(), input.delegation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("delegation object is unavailable".into()))?;
    let (root_grant_id, _) = root_grant(&store, ledger)?;
    let authorization_ref = input.authorization_ref.unwrap_or(root_grant_id);
    let authorization = store
        .get_cose_by_id(ledger.as_bytes(), authorization_ref.as_bytes())?
        .ok_or_else(|| Error::MissingObject("authorization reference is unavailable".into()))?;
    let revocation_id = runtime.next_uuid_v7()?;
    let cose = signed_envelope(
        revocation_id,
        ledger,
        "delegation_revocation",
        actor,
        key_id,
        serde_json::json!({
            "revoked_delegation_id": input.delegation_id,
            "effective_at": runtime.timestamp(),
            "reason": input.reason,
            "authorization_ref": authorization_ref,
        }),
        vec![
            dependency_value(&revoked, "revoked-delegation")?,
            dependency_value(&authorization, "admin-authority")?,
        ],
        &key,
        runtime,
    )?;
    let content_hash = store.insert_authorized_object_with_projected_mode(
        &cose,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(OperationReceipt {
        object_id: revocation_id.to_string(),
        content_hash: content_hash.hex(),
        object_type: "delegation_revocation".into(),
    })
}

fn ensure_writable(entry: &LedgerEntry) -> Result<()> {
    if entry.read_only {
        return Err(Error::ReadOnlyLedger);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::{export_identity, import_identity},
        workflow::{create_ledger, BootstrapLedgerInput},
    };

    fn entry(root: &std::path::Path, name: &str, seed: [u8; 32], nonce: [u8; 16]) -> LedgerEntry {
        let database = root.join(format!("{name}.sqlite"));
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: format!("local.{name}"),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce,
            },
        )
        .unwrap();
        LedgerEntry {
            name: name.into(),
            ledger_id: bootstrap.ledger_id,
            database,
            actor_id: bootstrap.actor_id,
            key_id: bootstrap.key_id,
            seed_file: root.join(format!("{name}.seed")),
            read_only: false,
        }
    }

    #[test]
    fn delegation_create_and_revoke_work() {
        let temp = tempfile::tempdir().unwrap();
        let admin = entry(temp.path(), "admin", [61; 32], [62; 16]);
        let delegatee = entry(temp.path(), "delegatee", [63; 32], [64; 16]);
        let exported = export_identity(&delegatee).unwrap();
        let imported = import_identity(&admin, &exported.bundle).unwrap();
        assert_eq!(imported.imported, exported.objects);

        fact_store::Store::reset_debug_metrics();
        let delegation = create_delegation(
            &admin,
            &[61; 32],
            DelegationInput {
                delegatee_actor_id: delegatee.actor_id.parse().unwrap(),
                capability: "admin".into(),
                scope: serde_json::json!({"type":"ledger"}),
                validity: None,
                parent_delegation_id: None,
                redelegable: false,
                constraints: serde_json::Map::new(),
            },
        )
        .unwrap();
        assert_eq!(delegation.object_type, "delegation");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);

        fact_store::Store::reset_debug_metrics();
        let revocation = revoke_delegation(
            &admin,
            &[61; 32],
            DelegationRevocationInput {
                delegation_id: delegation.object_id.parse().unwrap(),
                reason: "superseded".into(),
                authorization_ref: None,
            },
        )
        .unwrap();
        assert_eq!(revocation.object_type, "delegation_revocation");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);
    }
}
