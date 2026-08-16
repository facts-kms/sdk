//! Relationship creation and read/list helpers.

use crate::{
    environment::LedgerEntry,
    models::OperationReceipt,
    proposition::{parse_uuid7, signed_envelope},
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ProtocolRelationshipInput {
    pub source_object_id: uuid::Uuid,
    pub relationship: String,
    pub target_object_ids: Vec<uuid::Uuid>,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ApplicationRelationshipInput {
    pub source_object_id: uuid::Uuid,
    pub relationship: String,
    pub target_object_ids: Vec<uuid::Uuid>,
    #[serde(default)]
    pub metadata: serde_json::Map<String, serde_json::Value>,
    pub shared: bool,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct RelationshipRecord {
    pub object_id: uuid::Uuid,
    pub reference: String,
    pub object_type: String,
    pub content_hash: String,
    pub created_at: String,
    pub actor_id: uuid::Uuid,
    pub source_object_id: uuid::Uuid,
    pub relationship: String,
    pub target_object_ids: Vec<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<bool>,
    pub body: serde_json::Value,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ListRelationshipsFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_object_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_object_id: Option<uuid::Uuid>,
}

pub fn create_protocol_relationship(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ProtocolRelationshipInput,
) -> Result<OperationReceipt> {
    let runtime = production_runtime();
    create_protocol_relationship_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn create_protocol_relationship_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ProtocolRelationshipInput,
    runtime: &dyn SdkRuntime,
) -> Result<OperationReceipt> {
    create_relationship(
        entry,
        seed,
        "protocol_relationship",
        serde_json::json!({
            "source_object_id": input.source_object_id,
            "relationship": input.relationship,
            "relationship_version": 0,
            "target_object_ids": input.target_object_ids,
        }),
        runtime,
    )
}

pub fn create_application_relationship(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ApplicationRelationshipInput,
) -> Result<OperationReceipt> {
    let runtime = production_runtime();
    create_application_relationship_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn create_application_relationship_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ApplicationRelationshipInput,
    runtime: &dyn SdkRuntime,
) -> Result<OperationReceipt> {
    create_relationship(
        entry,
        seed,
        "application_relationship",
        serde_json::json!({
            "source_object_id": input.source_object_id,
            "relationship": input.relationship,
            "target_object_ids": input.target_object_ids,
            "metadata": input.metadata,
            "shared": input.shared,
        }),
        runtime,
    )
}

pub fn list_relationships(
    entry: &LedgerEntry,
    filter: ListRelationshipsFilter,
) -> Result<Vec<RelationshipRecord>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let mut records = Vec::new();
    for row in store.list_relationship_payloads(
        ledger.as_bytes(),
        filter.source_object_id.as_ref().map(uuid::Uuid::as_bytes),
        filter.relationship.as_deref(),
        filter.target_object_id.as_ref().map(uuid::Uuid::as_bytes),
    )? {
        let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
        let Some(record) =
            relationship_record(row.object_id, row.content_hash, row.object_type, value)?
        else {
            continue;
        };
        records.push(record);
    }
    records.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.object_id.cmp(&right.object_id))
    });
    Ok(records)
}

pub fn read_relationship(
    entry: &LedgerEntry,
    relationship_id: uuid::Uuid,
) -> Result<RelationshipRecord> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let Some(payload) = store.get_payload(relationship_id.as_bytes())? else {
        return Err(Error::MissingObject(relationship_id.to_string()));
    };
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    if value["ledger_id"].as_str() != Some(&ledger.to_string()) {
        return Err(Error::MissingObject(relationship_id.to_string()));
    }
    let object_type = value["object_type"]
        .as_str()
        .ok_or_else(|| Error::Validation("relationship object is missing object_type".into()))?;
    if !matches!(
        object_type,
        "protocol_relationship" | "application_relationship"
    ) {
        return Err(Error::Validation(format!(
            "{relationship_id} is not a relationship object"
        )));
    }
    let content_hash = fact_core::Hash::digest(&payload);
    relationship_record(relationship_id, content_hash, object_type.to_owned(), value)?
        .ok_or_else(|| Error::MissingObject(relationship_id.to_string()))
}

fn create_relationship(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    object_type: &str,
    body: serde_json::Value,
    runtime: &dyn SdkRuntime,
) -> Result<OperationReceipt> {
    if entry.read_only {
        return Err(Error::ReadOnlyLedger);
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let object_id = runtime.next_uuid_v7()?;
    let cose = signed_envelope(
        object_id,
        ledger,
        object_type,
        actor,
        key_id,
        body,
        Vec::new(),
        &key,
        runtime,
    )?;
    let content_hash = store.insert_authorized_object_with_projected_mode(
        &cose,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(OperationReceipt {
        object_id: object_id.to_string(),
        content_hash: content_hash.hex(),
        object_type: object_type.to_owned(),
    })
}

fn relationship_record(
    object_id: uuid::Uuid,
    content_hash: fact_core::Hash,
    object_type: String,
    value: serde_json::Value,
) -> Result<Option<RelationshipRecord>> {
    let body = &value["body"];
    let Some(source_object_id) = body["source_object_id"]
        .as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
    else {
        return Ok(None);
    };
    let target_object_ids = body["target_object_ids"]
        .as_array()
        .ok_or_else(|| Error::Validation("relationship is missing target_object_ids".into()))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| Error::Validation("target object ID is not a string".into()))
                .and_then(|value| Ok(uuid::Uuid::parse_str(value)?))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(RelationshipRecord {
        object_id,
        reference: crate::reference::short_uuid_reference(object_id),
        object_type,
        content_hash: content_hash.hex(),
        created_at: value["created_at"].as_str().unwrap_or_default().to_owned(),
        actor_id: value["actor_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .ok_or_else(|| Error::Validation("relationship is missing actor_id".into()))?,
        source_object_id,
        relationship: body["relationship"]
            .as_str()
            .ok_or_else(|| Error::Validation("relationship is missing relationship".into()))?
            .to_owned(),
        target_object_ids,
        metadata: body["metadata"].as_object().cloned(),
        shared: body["shared"].as_bool(),
        body: body.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proposition::{create_proposition, DecisionOutcome},
        workflow::{create_ledger, BootstrapLedgerInput},
    };

    fn entry() -> (tempfile::TempDir, LedgerEntry, [u8; 32]) {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [41; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.relationship-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce: [42; 16],
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
    fn create_list_and_read_relationships() {
        let (_temp, entry, seed) = entry();
        let created = create_proposition(
            &entry,
            &seed,
            b"# Linked\n\nRelationship source.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();

        fact_store::Store::reset_debug_metrics();
        let protocol = create_protocol_relationship(
            &entry,
            &seed,
            ProtocolRelationshipInput {
                source_object_id: created.proposition_id,
                relationship: "protocol:references".into(),
                target_object_ids: vec![created.revision_id],
            },
        )
        .unwrap();
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);

        fact_store::Store::reset_debug_metrics();
        let application = create_application_relationship(
            &entry,
            &seed,
            ApplicationRelationshipInput {
                source_object_id: created.proposition_id,
                relationship: "related-to".into(),
                target_object_ids: Vec::new(),
                metadata: serde_json::Map::new(),
                shared: true,
            },
        )
        .unwrap();
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);

        let listed = list_relationships(
            &entry,
            ListRelationshipsFilter {
                source_object_id: Some(created.proposition_id),
                relationship: None,
                target_object_id: None,
            },
        )
        .unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed
            .iter()
            .any(|item| item.object_id.to_string() == protocol.object_id));
        assert!(listed
            .iter()
            .any(|item| item.object_id.to_string() == application.object_id));

        let read =
            read_relationship(&entry, uuid::Uuid::parse_str(&protocol.object_id).unwrap()).unwrap();
        assert_eq!(read.relationship, "protocol:references");
        assert_eq!(read.target_object_ids, vec![created.revision_id]);
    }
}
