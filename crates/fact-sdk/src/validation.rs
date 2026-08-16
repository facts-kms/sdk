//! Validation helpers for protocol objects and canonical content.

use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SettlementValidationResult {
    pub valid: bool,
    pub object_type: String,
    pub content_hash: String,
}

/// Validate and canonicalize a protocol JSON envelope.
pub fn validate_object(payload: &[u8]) -> Result<fact_schema::ObjectType> {
    Ok(fact_schema::validate_envelope(payload)?)
}

/// Return canonical JSON bytes for an input JSON value.
pub fn canonical_json(input: &[u8]) -> Result<Vec<u8>> {
    Ok(fact_canonical::encode(input)?)
}

/// Return canonical Fact Markdown bytes.
pub fn canonical_markdown(input: &[u8]) -> Result<Vec<u8>> {
    Ok(fact_canonical::canonical_markdown(input)?)
}

/// Validate canonical Fact Markdown bytes.
pub fn validate_canonical_markdown(input: &[u8]) -> Result<()> {
    Ok(fact_canonical::validate_canonical_markdown(input)?)
}

/// Validate a settlement witness against participant decisions.
pub fn validate_settlement(
    participant_ids: &[fact_core::ObjectId],
    revision: fact_core::ObjectId,
    decisions: &[fact_state::Decision],
    refs: &[fact_state::SettlementDecisionRef],
    outcome: fact_state::SettlementOutcome,
) -> Result<fact_state::Evaluation> {
    fact_state::validate_settlement_witness(participant_ids, revision, decisions, refs, outcome)
        .map_err(|error| crate::Error::Validation(format!("settlement witness: {error:?}")))
}

/// Validate signed settlement object bytes for canonical payload and schema shape.
pub fn verify_settlement_object(bytes: &[u8]) -> Result<SettlementValidationResult> {
    let cose = fact_crypto::decode_sign1(bytes)?;
    let canonical = fact_canonical::encode(&cose.payload)?;
    if canonical != cose.payload {
        return Err(Error::Validation(
            "settlement payload is not canonical".into(),
        ));
    }
    let object_type = fact_schema::validate_envelope(&canonical)?;
    if object_type.as_str() != "settlement" {
        return Err(Error::Validation("object is not a settlement".into()));
    }
    Ok(SettlementValidationResult {
        valid: true,
        object_type: "settlement".into(),
        content_hash: fact_core::Hash::digest(&canonical).hex(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        settlement::{create_settlement, SettlementInput, SettlementProducerType},
        workflow::{
            create_decision, create_ledger, BootstrapLedgerInput, CastDecisionValue, DecisionInput,
        },
    };

    #[test]
    fn verifies_signed_settlement_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [111; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.settlement-validation-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce: [112; 16],
            },
        )
        .unwrap();
        let entry = crate::environment::LedgerEntry {
            name: "test".into(),
            ledger_id: bootstrap.ledger_id,
            database,
            actor_id: bootstrap.actor_id.clone(),
            key_id: bootstrap.key_id,
            seed_file: temp.path().join("seed"),
            read_only: false,
        };
        let proposition = crate::proposition::create_proposition(
            &entry,
            &seed,
            b"# Valid\n\nSettlement.\n",
            None,
        )
        .unwrap();
        create_decision(
            &entry,
            &seed,
            DecisionInput {
                deliberation_id: proposition.deliberation_id,
                participant_actor_id: bootstrap.actor_id.parse().unwrap(),
                value: CastDecisionValue::Accepted,
                supersedes_decision_ids: Vec::new(),
                authorization_ref: None,
            },
        )
        .unwrap();
        let settlement = create_settlement(
            &entry,
            &seed,
            SettlementInput {
                deliberation_id: proposition.deliberation_id,
                revision_id: proposition.revision_id,
                producer_type: SettlementProducerType::Participant,
                producer_id: None,
            },
        )
        .unwrap();
        let store = fact_store::Store::open(&entry.database).unwrap();
        let bytes = store
            .get_cose_by_id(
                uuid::Uuid::parse_str(&entry.ledger_id).unwrap().as_bytes(),
                uuid::Uuid::parse_str(&settlement.object_id)
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap()
            .unwrap();
        let result = verify_settlement_object(&bytes).unwrap();
        assert!(result.valid);
        assert_eq!(result.object_type, "settlement");
    }
}
