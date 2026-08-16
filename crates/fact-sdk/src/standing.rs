//! Standing participant change workflows.

use crate::{
    environment::LedgerEntry,
    models::OperationReceipt,
    proposition::{dependency_value, parse_uuid7, signed_envelope},
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum StandingParticipantOperation {
    Join,
    Leave,
}

impl StandingParticipantOperation {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Join => "join",
            Self::Leave => "leave",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct StandingParticipantChangeInput {
    pub proposition_id: uuid::Uuid,
    pub participant_actor_id: uuid::Uuid,
    pub operation: StandingParticipantOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_change_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<uuid::Uuid>,
}

pub fn create_standing_participant_change(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: StandingParticipantChangeInput,
) -> Result<OperationReceipt> {
    let runtime = production_runtime();
    create_standing_participant_change_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn create_standing_participant_change_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: StandingParticipantChangeInput,
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
    let proposition = store
        .get_cose_by_id(ledger.as_bytes(), input.proposition_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("proposition object is unavailable".into()))?;
    let participant = store
        .get_cose_by_id_any(input.participant_actor_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("participant actor is unavailable".into()))?;
    let (authorization_ref, authorization) = if let Some(id) = input.authorization_ref {
        let bytes = store
            .get_cose_by_id(ledger.as_bytes(), id.as_bytes())?
            .ok_or_else(|| Error::MissingObject("authorization reference is unavailable".into()))?;
        (id, bytes)
    } else {
        find_authority_grant(&store, ledger, actor, "deliberate")?
    };
    let mut dependencies = vec![
        dependency_value(&proposition, "proposition")?,
        dependency_value(&participant, "participant-actor")?,
        dependency_value(&authorization, "deliberate-authority")?,
    ];
    if let Some(predecessor_id) = input.predecessor_change_id {
        let predecessor = store
            .get_cose_by_id(ledger.as_bytes(), predecessor_id.as_bytes())?
            .ok_or_else(|| {
                Error::MissingObject("predecessor standing change is unavailable".into())
            })?;
        dependencies.push(dependency_value(&predecessor, "predecessor-change")?);
    }
    let change_id = runtime.next_uuid_v7()?;
    let body_authorization_ref = (actor != input.participant_actor_id).then_some(authorization_ref);
    let cose = signed_envelope(
        change_id,
        ledger,
        "standing_participant_change",
        actor,
        key_id,
        serde_json::json!({
            "proposition_id": input.proposition_id,
            "participant_actor_id": input.participant_actor_id,
            "operation": input.operation.as_str(),
            "predecessor_change_id": input.predecessor_change_id,
            "changed_by_actor_id": actor,
            "authorization_ref": body_authorization_ref,
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
        object_id: change_id.to_string(),
        content_hash: content_hash.hex(),
        object_type: "standing_participant_change".into(),
    })
}

pub fn update_standing_participants(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: StandingParticipantChangeInput,
) -> Result<OperationReceipt> {
    create_standing_participant_change(entry, seed, input)
}

pub fn update_standing_participants_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: StandingParticipantChangeInput,
    runtime: &dyn SdkRuntime,
) -> Result<OperationReceipt> {
    create_standing_participant_change_with_runtime(entry, seed, input, runtime)
}

fn find_authority_grant(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor: uuid::Uuid,
    capability: &str,
) -> Result<(uuid::Uuid, Vec<u8>)> {
    if let Some(row) = store
        .list_authority_grant_payloads(ledger.as_bytes(), actor.as_bytes(), capability)?
        .into_iter()
        .next()
    {
        let cose = store
            .get_cose_by_id(ledger.as_bytes(), row.object_id.as_bytes())?
            .ok_or_else(|| Error::MissingObject("authorization grant is unavailable".into()))?;
        return Ok((row.object_id, cose));
    }
    Err(Error::MissingObject(format!(
        "no {capability} authority grant is available"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposition::{create_proposition, DecisionOutcome};

    #[test]
    fn standing_participant_change_uses_deliberate_authority() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [81; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = crate::workflow::create_ledger(
            &store,
            crate::workflow::BootstrapLedgerInput {
                namespace: "local.standing-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce: [82; 16],
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
        let proposition = create_proposition(
            &entry,
            &seed,
            b"# Standing\n\nParticipant roster.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();

        fact_store::Store::reset_debug_metrics();
        let change = create_standing_participant_change(
            &entry,
            &seed,
            StandingParticipantChangeInput {
                proposition_id: proposition.proposition_id,
                participant_actor_id: bootstrap.actor_id.parse().unwrap(),
                operation: StandingParticipantOperation::Join,
                predecessor_change_id: None,
                authorization_ref: None,
            },
        )
        .unwrap();
        assert_eq!(change.object_type, "standing_participant_change");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);
    }
}
