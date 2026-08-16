//! Identity attestation workflows.

use crate::{
    environment::LedgerEntry,
    models::OperationReceipt,
    proposition::{dependency_value, parse_uuid7, signed_envelope},
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum AttestationSubjectType {
    Actor,
    Key,
}

impl AttestationSubjectType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Actor => "actor",
            Self::Key => "key",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AttestationValidity {
    pub valid_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct IdentityAttestationInput {
    pub subject_type: AttestationSubjectType,
    pub subject_id: uuid::Uuid,
    pub claim_type: String,
    pub claims: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
    pub validity: AttestationValidity,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct IdentityAttestationRecord {
    pub object_id: uuid::Uuid,
    pub reference: String,
    pub content_hash: String,
    pub created_at: String,
    pub actor_id: uuid::Uuid,
    pub subject_type: AttestationSubjectType,
    pub subject_id: uuid::Uuid,
    pub claim_type: String,
    pub claims: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
    pub validity: AttestationValidity,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ListIdentityAttestationsFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<AttestationSubjectType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_type: Option<String>,
}

pub fn create_identity_attestation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: IdentityAttestationInput,
) -> Result<OperationReceipt> {
    let runtime = production_runtime();
    create_identity_attestation_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn create_identity_attestation_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: IdentityAttestationInput,
    runtime: &dyn SdkRuntime,
) -> Result<OperationReceipt> {
    if entry.read_only {
        return Err(Error::ReadOnlyLedger);
    }
    if input.claim_type.is_empty() || input.claims.is_empty() {
        return Err(Error::Validation(
            "attestation claim_type and claims are required".into(),
        ));
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let subject = store
        .get_cose_by_id_any(input.subject_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("attestation subject is unavailable".into()))?;
    let object_id = runtime.next_uuid_v7()?;
    let cose = signed_envelope(
        object_id,
        ledger,
        "identity_attestation",
        actor,
        key_id,
        serde_json::json!({
            "subject_type": input.subject_type.as_str(),
            "subject_id": input.subject_id,
            "claim_type": input.claim_type,
            "claims": input.claims,
            "evidence_hash": input.evidence_hash,
            "validity": {
                "valid_from": input.validity.valid_from,
                "expires_at": input.validity.expires_at,
            },
        }),
        vec![dependency_value(&subject, "attestation-subject")?],
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
        object_type: "identity_attestation".into(),
    })
}

pub fn list_identity_attestations(
    entry: &LedgerEntry,
    filter: ListIdentityAttestationsFilter,
) -> Result<Vec<IdentityAttestationRecord>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let mut records = Vec::new();
    for row in store.list_identity_attestation_payloads(
        ledger.as_bytes(),
        filter
            .subject_type
            .as_ref()
            .map(AttestationSubjectType::as_str),
        filter.subject_id.as_ref().map(uuid::Uuid::as_bytes),
        filter.claim_type.as_deref(),
    )? {
        let record = attestation_record(
            row.object_id,
            row.content_hash,
            serde_json::from_slice::<serde_json::Value>(&row.payload)?,
        )?;
        records.push(record);
    }
    records.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.object_id.cmp(&right.object_id))
    });
    Ok(records)
}

pub fn read_identity_attestation(
    entry: &LedgerEntry,
    attestation_id: uuid::Uuid,
) -> Result<IdentityAttestationRecord> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let Some(payload) = store.get_payload(attestation_id.as_bytes())? else {
        return Err(Error::MissingObject(attestation_id.to_string()));
    };
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    if value["ledger_id"].as_str() != Some(&ledger.to_string())
        || value["object_type"].as_str() != Some("identity_attestation")
    {
        return Err(Error::MissingObject(attestation_id.to_string()));
    }
    attestation_record(attestation_id, fact_core::Hash::digest(&payload), value)
}

fn attestation_record(
    object_id: uuid::Uuid,
    content_hash: fact_core::Hash,
    value: serde_json::Value,
) -> Result<IdentityAttestationRecord> {
    let body = &value["body"];
    let subject_type = match body["subject_type"]
        .as_str()
        .ok_or_else(|| Error::Validation("attestation is missing subject_type".into()))?
    {
        "actor" => AttestationSubjectType::Actor,
        "key" => AttestationSubjectType::Key,
        value => return Err(Error::Validation(format!("unknown subject_type {value}"))),
    };
    Ok(IdentityAttestationRecord {
        object_id,
        reference: crate::reference::short_uuid_reference(object_id),
        content_hash: content_hash.hex(),
        created_at: value["created_at"].as_str().unwrap_or_default().to_owned(),
        actor_id: parse_uuid_field(&value, "actor_id")?,
        subject_type,
        subject_id: parse_uuid_field(body, "subject_id")?,
        claim_type: body["claim_type"]
            .as_str()
            .ok_or_else(|| Error::Validation("attestation is missing claim_type".into()))?
            .to_owned(),
        claims: body["claims"]
            .as_object()
            .ok_or_else(|| Error::Validation("attestation is missing claims".into()))?
            .clone(),
        evidence_hash: body["evidence_hash"].as_str().map(ToOwned::to_owned),
        validity: AttestationValidity {
            valid_from: body["validity"]["valid_from"]
                .as_str()
                .ok_or_else(|| Error::Validation("attestation is missing valid_from".into()))?
                .to_owned(),
            expires_at: body["validity"]["expires_at"]
                .as_str()
                .map(ToOwned::to_owned),
        },
    })
}

fn parse_uuid_field(value: &serde_json::Value, field: &'static str) -> Result<uuid::Uuid> {
    value[field]
        .as_str()
        .ok_or_else(|| Error::Validation(format!("missing {field}")))?
        .parse()
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{create_ledger, BootstrapLedgerInput};

    #[test]
    fn identity_attestation_create_list_and_read_work() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [71; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.attestation-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce: [72; 16],
            },
        )
        .unwrap();
        let entry = LedgerEntry {
            name: "test".into(),
            ledger_id: bootstrap.ledger_id,
            database,
            actor_id: bootstrap.actor_id.clone(),
            key_id: bootstrap.key_id,
            seed_file: temp.path().join("seed"),
            read_only: false,
        };
        let mut claims = serde_json::Map::new();
        claims.insert("name".into(), serde_json::Value::String("Example".into()));
        fact_store::Store::reset_debug_metrics();
        let created = create_identity_attestation(
            &entry,
            &seed,
            IdentityAttestationInput {
                subject_type: AttestationSubjectType::Actor,
                subject_id: bootstrap.actor_id.parse().unwrap(),
                claim_type: "display-name".into(),
                claims,
                evidence_hash: None,
                validity: AttestationValidity {
                    valid_from: "2026-07-30T12:00:00.000Z".into(),
                    expires_at: None,
                },
            },
        )
        .unwrap();
        assert_eq!(created.object_type, "identity_attestation");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);

        let listed = list_identity_attestations(
            &entry,
            ListIdentityAttestationsFilter {
                subject_type: Some(AttestationSubjectType::Actor),
                subject_id: Some(bootstrap.actor_id.parse().unwrap()),
                claim_type: Some("display-name".into()),
            },
        )
        .unwrap();
        assert_eq!(listed.len(), 1);
        let read = read_identity_attestation(&entry, created.object_id.parse().unwrap()).unwrap();
        assert_eq!(read.claim_type, "display-name");
    }
}
