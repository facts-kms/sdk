//! Decision creation helpers.

use crate::{
    environment::LedgerEntry,
    models::OperationReceipt,
    proposition::{dependency_value, parse_uuid7, signed_envelope},
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum DecisionValue {
    Accepted,
    Rejected,
}

impl DecisionValue {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DecisionInput {
    pub deliberation_id: uuid::Uuid,
    pub participant_actor_id: uuid::Uuid,
    pub value: DecisionValue,
    #[serde(default)]
    pub supersedes_decision_ids: Vec<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<uuid::Uuid>,
}

pub fn create_decision(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: DecisionInput,
) -> Result<OperationReceipt> {
    let runtime = production_runtime();
    create_decision_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn create_decision_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: DecisionInput,
    runtime: &dyn SdkRuntime,
) -> Result<OperationReceipt> {
    if entry.read_only {
        return Err(Error::ReadOnlyLedger);
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let deliberation = store
        .get_cose_by_id(ledger.as_bytes(), input.deliberation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("deliberation object is unavailable".into()))?;
    let mut dependencies = vec![dependency_value(&deliberation, "deliberation")?];
    for superseded_id in &input.supersedes_decision_ids {
        let superseded = store
            .get_cose_by_id(ledger.as_bytes(), superseded_id.as_bytes())?
            .ok_or_else(|| Error::MissingObject("superseded decision is unavailable".into()))?;
        dependencies.push(dependency_value(&superseded, "superseded-decision")?);
    }
    if let Some(authorization_id) = input.authorization_ref {
        let authorization = store
            .get_cose_by_id(ledger.as_bytes(), authorization_id.as_bytes())?
            .ok_or_else(|| Error::MissingObject("authorization reference is unavailable".into()))?;
        dependencies.push(dependency_value(&authorization, "decision-authority")?);
    }
    let decision_id = runtime.next_uuid_v7()?;
    let cose = signed_envelope(
        decision_id,
        ledger,
        "decision",
        input.participant_actor_id,
        key_id,
        serde_json::json!({
            "deliberation_id": input.deliberation_id,
            "participant_actor_id": input.participant_actor_id,
            "value": input.value.as_str(),
            "supersedes_decision_ids": input.supersedes_decision_ids,
            "authorization_ref": input.authorization_ref,
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
        object_id: decision_id.to_string(),
        content_hash: content_hash.hex(),
        object_type: "decision".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proposition::create_proposition,
        workflow::{create_ledger, BootstrapLedgerInput},
    };

    #[test]
    fn decision_create_uses_deliberation_dependency() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [101; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.decision-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce: [102; 16],
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
        let proposition =
            create_proposition(&entry, &seed, b"# Decision\n\nA decision.\n", None).unwrap();
        fact_store::Store::reset_debug_metrics();
        let decision = create_decision(
            &entry,
            &seed,
            DecisionInput {
                deliberation_id: proposition.deliberation_id,
                participant_actor_id: bootstrap.actor_id.parse().unwrap(),
                value: DecisionValue::Accepted,
                supersedes_decision_ids: Vec::new(),
                authorization_ref: None,
            },
        )
        .unwrap();
        assert_eq!(decision.object_type, "decision");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);
        let store = fact_store::Store::open(&entry.database).unwrap();
        let ledger: uuid::Uuid = entry.ledger_id.parse().unwrap();
        let participant_decisions = store
            .participant_decisions_for_deliberation(
                ledger.as_bytes(),
                proposition.deliberation_id.as_bytes(),
            )
            .unwrap();
        assert_eq!(participant_decisions.len(), 1);
        assert_eq!(
            participant_decisions[0].actor_id,
            bootstrap.actor_id.parse::<uuid::Uuid>().unwrap()
        );
        assert_eq!(
            participant_decisions[0].decision.as_deref(),
            Some("accepted")
        );
    }
}
