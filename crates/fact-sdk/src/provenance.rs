//! Proposition provenance creation and read/list helpers.

use crate::{
    environment::LedgerEntry,
    models::OperationReceipt,
    proposition::{parse_uuid7, signed_envelope},
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum ProvenanceCopyMode {
    Snapshot,
    Reference,
}

impl ProvenanceCopyMode {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Reference => "reference",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ProvenanceInput {
    pub proposition_id: uuid::Uuid,
    pub source_ledger_id: uuid::Uuid,
    pub source_proposition_id: uuid::Uuid,
    pub source_revision_id: uuid::Uuid,
    pub source_content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_object_bundle: Option<String>,
    pub copy_mode: ProvenanceCopyMode,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ListProvenanceFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposition_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ledger_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_mode: Option<ProvenanceCopyMode>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ProvenanceRecord {
    pub object_id: uuid::Uuid,
    pub reference: String,
    pub content_hash: String,
    pub created_at: String,
    pub actor_id: uuid::Uuid,
    pub proposition_id: uuid::Uuid,
    pub source_ledger_id: uuid::Uuid,
    pub source_proposition_id: uuid::Uuid,
    pub source_revision_id: uuid::Uuid,
    pub source_content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_object_bundle: Option<String>,
    pub copy_mode: ProvenanceCopyMode,
}

pub fn create_provenance(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ProvenanceInput,
) -> Result<OperationReceipt> {
    let runtime = production_runtime();
    create_provenance_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn create_provenance_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ProvenanceInput,
    runtime: &dyn SdkRuntime,
) -> Result<OperationReceipt> {
    if entry.read_only {
        return Err(Error::ReadOnlyLedger);
    }
    if input.copy_mode == ProvenanceCopyMode::Snapshot && input.source_object_bundle.is_none() {
        return Err(Error::Validation(
            "source_object_bundle is required for snapshot provenance".into(),
        ));
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
        "proposition_provenance",
        actor,
        key_id,
        serde_json::json!({
            "proposition_id": input.proposition_id,
            "source_ledger_id": input.source_ledger_id,
            "source_proposition_id": input.source_proposition_id,
            "source_revision_id": input.source_revision_id,
            "source_content_hash": input.source_content_hash,
            "source_object_bundle": input.source_object_bundle,
            "copy_mode": input.copy_mode.as_str(),
        }),
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
        object_type: "proposition_provenance".into(),
    })
}

pub fn list_provenance(
    entry: &LedgerEntry,
    filter: ListProvenanceFilter,
) -> Result<Vec<ProvenanceRecord>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let mut records = Vec::new();
    for row in store.list_provenance_payloads(
        ledger.as_bytes(),
        filter.proposition_id.as_ref().map(uuid::Uuid::as_bytes),
        filter.source_ledger_id.as_ref().map(uuid::Uuid::as_bytes),
        filter.copy_mode.as_ref().map(ProvenanceCopyMode::as_str),
    )? {
        let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
        let record = provenance_record(row.object_id, row.content_hash, value)?;
        records.push(record);
    }
    records.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.object_id.cmp(&right.object_id))
    });
    Ok(records)
}

pub fn read_provenance(entry: &LedgerEntry, provenance_id: uuid::Uuid) -> Result<ProvenanceRecord> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let Some(payload) = store.get_payload(provenance_id.as_bytes())? else {
        return Err(Error::MissingObject(provenance_id.to_string()));
    };
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    if value["ledger_id"].as_str() != Some(&ledger.to_string())
        || value["object_type"].as_str() != Some("proposition_provenance")
    {
        return Err(Error::MissingObject(provenance_id.to_string()));
    }
    provenance_record(provenance_id, fact_core::Hash::digest(&payload), value)
}

pub fn create_proposition_provenance(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ProvenanceInput,
) -> Result<OperationReceipt> {
    create_provenance(entry, seed, input)
}

pub fn read_proposition_provenance(
    entry: &LedgerEntry,
    proposition_id: uuid::Uuid,
) -> Result<Vec<ProvenanceRecord>> {
    list_provenance(
        entry,
        ListProvenanceFilter {
            proposition_id: Some(proposition_id),
            source_ledger_id: None,
            copy_mode: None,
        },
    )
}

fn provenance_record(
    object_id: uuid::Uuid,
    content_hash: fact_core::Hash,
    value: serde_json::Value,
) -> Result<ProvenanceRecord> {
    let body = &value["body"];
    Ok(ProvenanceRecord {
        object_id,
        reference: crate::reference::short_uuid_reference(object_id),
        content_hash: content_hash.hex(),
        created_at: value["created_at"].as_str().unwrap_or_default().to_owned(),
        actor_id: parse_body_uuid(&value, "actor_id")?,
        proposition_id: parse_body_uuid(body, "proposition_id")?,
        source_ledger_id: parse_body_uuid(body, "source_ledger_id")?,
        source_proposition_id: parse_body_uuid(body, "source_proposition_id")?,
        source_revision_id: parse_body_uuid(body, "source_revision_id")?,
        source_content_hash: body["source_content_hash"]
            .as_str()
            .ok_or_else(|| Error::Validation("provenance is missing source_content_hash".into()))?
            .to_owned(),
        source_object_bundle: body["source_object_bundle"].as_str().map(ToOwned::to_owned),
        copy_mode: match body["copy_mode"]
            .as_str()
            .ok_or_else(|| Error::Validation("provenance is missing copy_mode".into()))?
        {
            "snapshot" => ProvenanceCopyMode::Snapshot,
            "reference" => ProvenanceCopyMode::Reference,
            value => {
                return Err(Error::Validation(format!(
                    "unknown provenance copy_mode {value}"
                )))
            }
        },
    })
}

fn parse_body_uuid(value: &serde_json::Value, field: &'static str) -> Result<uuid::Uuid> {
    value[field]
        .as_str()
        .ok_or_else(|| Error::Validation(format!("missing {field}")))?
        .parse()
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proposition::{create_proposition, DecisionOutcome},
        workflow::{create_ledger, BootstrapLedgerInput},
    };

    fn ledger_entry(
        database: std::path::PathBuf,
        seed: [u8; 32],
        nonce: [u8; 16],
        namespace: &str,
    ) -> LedgerEntry {
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: namespace.into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce,
            },
        )
        .unwrap();
        LedgerEntry {
            name: namespace.into(),
            ledger_id: bootstrap.ledger_id,
            database,
            actor_id: bootstrap.actor_id,
            key_id: bootstrap.key_id,
            seed_file: std::path::PathBuf::new(),
            read_only: false,
        }
    }

    #[test]
    fn provenance_create_list_and_read_work() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let source_seed = [51; 32];
        let dest_seed = [52; 32];
        let source = ledger_entry(database.clone(), source_seed, [53; 16], "local.source");
        let dest = ledger_entry(database, dest_seed, [54; 16], "local.dest");
        let source_proposition = create_proposition(
            &source,
            &source_seed,
            b"# Source\n\nCopied fact.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        let dest_proposition =
            create_proposition(&dest, &dest_seed, b"# Destination\n\nCopied fact.\n", None)
                .unwrap();
        let source_hash = source_proposition
            .content_hashes
            .first()
            .cloned()
            .unwrap_or_else(|| "00".repeat(32));

        fact_store::Store::reset_debug_metrics();
        let created = create_provenance(
            &dest,
            &dest_seed,
            ProvenanceInput {
                proposition_id: dest_proposition.proposition_id,
                source_ledger_id: source.ledger_id.parse().unwrap(),
                source_proposition_id: source_proposition.proposition_id,
                source_revision_id: source_proposition.revision_id,
                source_content_hash: source_hash,
                source_object_bundle: Some("AA".into()),
                copy_mode: ProvenanceCopyMode::Snapshot,
            },
        )
        .unwrap();
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);

        fact_store::Store::reset_debug_metrics();
        let listed = list_provenance(
            &dest,
            ListProvenanceFilter {
                proposition_id: Some(dest_proposition.proposition_id),
                source_ledger_id: Some(source.ledger_id.parse().unwrap()),
                copy_mode: Some(ProvenanceCopyMode::Snapshot),
            },
        )
        .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].object_id.to_string(), created.object_id);
        assert_eq!(
            fact_store::Store::debug_metrics().list_object_payloads_by_type,
            0
        );

        let read = read_provenance(&dest, created.object_id.parse().unwrap()).unwrap();
        assert_eq!(read.proposition_id, dest_proposition.proposition_id);
        assert_eq!(read.source_revision_id, source_proposition.revision_id);
    }
}
