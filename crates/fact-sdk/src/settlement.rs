//! Standalone settlement helpers.

use crate::{
    environment::LedgerEntry,
    models::OperationReceipt,
    proposition::{
        active_participant_ids_for_settlement, canonical_decisions_for_deliberation,
        dependency_value, parse_uuid7, signed_envelope,
    },
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SettlementInput {
    pub deliberation_id: uuid::Uuid,
    pub revision_id: uuid::Uuid,
    #[serde(default)]
    pub producer_type: SettlementProducerType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_id: Option<uuid::Uuid>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum SettlementProducerType {
    #[default]
    Participant,
    Coordinator,
}

impl SettlementProducerType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Participant => "participant",
            Self::Coordinator => "coordinator",
        }
    }
}

pub fn create_settlement(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: SettlementInput,
) -> Result<OperationReceipt> {
    let runtime = production_runtime();
    create_settlement_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn create_settlement_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: SettlementInput,
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
    let deliberation = store
        .get_cose_by_id(ledger.as_bytes(), input.deliberation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("deliberation object is unavailable".into()))?;
    let deliberation_value: serde_json::Value =
        serde_json::from_slice(&fact_crypto::decode_sign1(&deliberation)?.payload)?;
    if deliberation_value["body"]["revision_id"].as_str() != Some(&input.revision_id.to_string()) {
        return Err(Error::Validation(
            "settlement revision does not match deliberation".into(),
        ));
    }
    let participants = active_participant_ids_for_settlement(
        &store,
        ledger,
        input.deliberation_id,
        &deliberation,
    )?;
    let mut decisions =
        canonical_decisions_for_deliberation(&store, ledger, input.deliberation_id)?;
    decisions.retain(|decision| participants.contains(&decision.participant_actor_id));
    decisions.sort_by_key(|decision| (decision.participant_actor_id, decision.decision_id));
    if decisions.len() != participants.len() {
        return Err(Error::Conflict(
            "settlement requires one applicable decision for every active participant".into(),
        ));
    }
    let accepted_count = decisions
        .iter()
        .filter(|decision| decision.value == "accepted")
        .count();
    let rejected_count = decisions
        .iter()
        .filter(|decision| decision.value == "rejected")
        .count();
    let outcome = if rejected_count == 0 {
        "accepted"
    } else {
        "rejected"
    };
    let decision_refs = decisions
        .iter()
        .map(|decision| {
            serde_json::json!({
                "decision_id": decision.decision_id,
                "content_hash": decision.content_hash.hex(),
                "participant_actor_id": decision.participant_actor_id,
            })
        })
        .collect::<Vec<_>>();
    let settlement_point = decisions
        .last()
        .ok_or_else(|| Error::Conflict("settlement requires at least one decision".into()))?;
    let mut dependencies = vec![dependency_value(&deliberation, "deliberation")?];
    for decision in &decisions {
        dependencies.push(dependency_value(&decision.cose, "decision")?);
    }
    let settlement_id = runtime.next_uuid_v7()?;
    let cose = signed_envelope(
        settlement_id,
        ledger,
        "settlement",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id": input.deliberation_id,
            "revision_id": input.revision_id,
            "decision_rule": {"id":"unanimity","version":0,"parameters":{}},
            "decision_refs": decision_refs,
            "participant_count": participants.len(),
            "decided_count": decisions.len(),
            "accepted_count": accepted_count,
            "rejected_count": rejected_count,
            "outcome": outcome,
            "causal_settlement_point": {
                "object_id": settlement_point.decision_id,
                "content_hash": settlement_point.content_hash.hex(),
                "role": "decision",
            },
            "producer_type": input.producer_type.as_str(),
            "producer_id": input.producer_id.unwrap_or(actor),
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
        object_id: settlement_id.to_string(),
        content_hash: content_hash.hex(),
        object_type: "settlement".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proposition::{dependency_value, signed_envelope},
        workflow::{create_ledger, BootstrapLedgerInput},
    };

    #[test]
    fn standalone_settlement_settles_existing_decision() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [91; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.settlement-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce: [92; 16],
            },
        )
        .unwrap();
        let entry = LedgerEntry {
            name: "test".into(),
            ledger_id: bootstrap.ledger_id.clone(),
            database,
            actor_id: bootstrap.actor_id.clone(),
            key_id: bootstrap.key_id.clone(),
            seed_file: temp.path().join("seed"),
            read_only: false,
        };
        let proposed = crate::proposition::create_proposition(
            &entry,
            &seed,
            b"# Settle\n\nStandalone decision.\n",
            None,
        )
        .unwrap();
        let ledger = parse_uuid7(&bootstrap.ledger_id, "ledger").unwrap();
        let actor = parse_uuid7(&bootstrap.actor_id, "actor").unwrap();
        let key_id = parse_uuid7(&bootstrap.key_id, "key").unwrap();
        let key = fact_crypto::SigningKey::from_seed(&seed).unwrap();
        let store = fact_store::Store::open(&entry.database).unwrap();
        let deliberation = store
            .get_cose_by_id(ledger.as_bytes(), proposed.deliberation_id.as_bytes())
            .unwrap()
            .unwrap();
        let runtime = crate::runtime::production_runtime();
        let decision_id = uuid::Uuid::now_v7();
        let decision = signed_envelope(
            decision_id,
            ledger,
            "decision",
            actor,
            key_id,
            serde_json::json!({
                "deliberation_id": proposed.deliberation_id,
                "participant_actor_id": actor,
                "value": "accepted",
                "supersedes_decision_ids": [],
                "authorization_ref": null,
            }),
            vec![dependency_value(&deliberation, "deliberation").unwrap()],
            &key,
            runtime.as_ref(),
        )
        .unwrap();
        store.insert_authorized_object(&decision).unwrap();

        fact_store::Store::reset_debug_metrics();
        let settlement = create_settlement(
            &entry,
            &seed,
            SettlementInput {
                deliberation_id: proposed.deliberation_id,
                revision_id: proposed.revision_id,
                producer_type: SettlementProducerType::Participant,
                producer_id: None,
            },
        )
        .unwrap();
        assert_eq!(settlement.object_type, "settlement");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);
        fact_store::Store::reset_debug_metrics();
        let effective = store
            .effective_state_for_proposition(ledger.as_bytes(), proposed.proposition_id.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(effective.proposition_id.uuid(), proposed.proposition_id);
        assert_eq!(effective.status, "accepted");
        assert_eq!(fact_store::Store::debug_metrics().list_effective_state, 0);
    }
}
