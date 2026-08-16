use std::collections::HashMap;

use crate::{
    environment::LedgerEntry,
    proposition::{
        active_participants_for_deliberation, base64url, deliberation_for_revision,
        dependency_hash, dependency_value, parse_uuid7, participant_decision_status,
        related_objects_by_deliberation, resolve_any_proposition_item, revision_for_reference,
        signed_envelope,
    },
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

#[derive(Clone, Debug, serde::Serialize)]
pub struct DeliberationView {
    pub deliberation_id: uuid::Uuid,
    pub proposition_id: uuid::Uuid,
    pub body: serde_json::Value,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DeliberationRepairResult {
    pub created: bool,
    pub repair: bool,
    pub deliberation_id: uuid::Uuid,
    pub revision_id: uuid::Uuid,
    pub content_hash: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DeliberationSummary {
    pub deliberation_id: uuid::Uuid,
    pub reference: String,
    pub content_hash: String,
    pub proposition_id: uuid::Uuid,
    pub revision_id: serde_json::Value,
    pub status: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CommentResult {
    pub created: bool,
    pub object_type: String,
    pub comment_id: uuid::Uuid,
    pub deliberation_id: uuid::Uuid,
    pub content_hash: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CommentSummary {
    pub object_id: uuid::Uuid,
    pub reference: String,
    pub object_type: String,
    pub content_hash: String,
    pub created_at: serde_json::Value,
    pub actor_id: serde_json::Value,
    pub deliberation_id: serde_json::Value,
    pub parent_comment_id: serde_json::Value,
    pub summary: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ParticipantChangeResult {
    pub created: bool,
    pub object_type: String,
    pub operation: String,
    pub change_id: uuid::Uuid,
    pub deliberation_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitation_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predecessor_change_id: Option<uuid::Uuid>,
    pub content_hash: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DeliberationOpenResult {
    pub created: bool,
    pub object_type: String,
    pub object_id: uuid::Uuid,
    pub content_hash: String,
}

pub fn read_deliberation(entry: &LedgerEntry, reference: &str) -> Result<DeliberationView> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let deliberation_id = revision_for_reference(&store, ledger, item.proposition_id, reference)?
        .map(|revision| deliberation_for_revision(&store, ledger, item.proposition_id, revision))
        .transpose()?
        .flatten()
        .or(item.deliberation_id)
        .ok_or_else(|| Error::Message("proposition has no deliberation".into()))?;
    let payload = store
        .get_payload(deliberation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("deliberation payload missing".into()))?;
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    Ok(DeliberationView {
        deliberation_id,
        proposition_id: item.proposition_id,
        body: value["body"].clone(),
    })
}

pub fn open_missing_deliberation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
) -> Result<Option<DeliberationRepairResult>> {
    let runtime = production_runtime();
    open_missing_deliberation_with_runtime(entry, seed, reference, runtime.as_ref())
}

pub fn open_missing_deliberation_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    runtime: &dyn SdkRuntime,
) -> Result<Option<DeliberationRepairResult>> {
    ensure_writable(entry)?;
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let Some(revision_id) = revision_for_reference(&store, ledger, item.proposition_id, reference)?
    else {
        return Ok(None);
    };
    if deliberation_for_revision(&store, ledger, item.proposition_id, revision_id)?.is_some() {
        return Ok(None);
    }
    let revision = store
        .get_cose_by_id(ledger.as_bytes(), revision_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("revision object is unavailable".into()))?;
    let proposition = store
        .get_cose_by_id(ledger.as_bytes(), item.proposition_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("proposition object is unavailable".into()))?;
    let parent_revision_id = latest_revision_parent(&store, item.proposition_id, revision_id)?;
    let prior_deliberation_id = parent_revision_id
        .and_then(|parent| {
            deliberation_for_revision(&store, ledger, item.proposition_id, parent)
                .ok()
                .flatten()
        })
        .or(item.deliberation_id);
    let participants = prior_deliberation_id
        .map(|deliberation| active_participants_for_deliberation(&store, ledger, deliberation))
        .transpose()?
        .unwrap_or_else(|| vec![actor.to_string()]);
    let deliberation_id = runtime.next_uuid_v7()?;
    let deliberation = signed_envelope(
        deliberation_id,
        ledger,
        "deliberation",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id": deliberation_id,
            "proposition_id": item.proposition_id,
            "revision_id": revision_id,
            "extends_deliberation_id": prior_deliberation_id,
            "decision_rule":{"id":"unanimity","version":0,"parameters":{}},
            "join_policy":{"policy_version":0,"mode":"open","attestation_requirements":[]},
            "initial_participants": participants.iter().map(|actor_id| serde_json::json!({"actor_id":actor_id,"carried_decision_id":null})).collect::<Vec<_>>(),
            "roster_governance":null,
            "opening_actor_id":actor,
            "comments_closed_on_settlement":true
        }),
        vec![
            dependency_value(&proposition, "proposition")?,
            dependency_value(&revision, "revision")?,
        ],
        &key,
        runtime,
    )?;
    let hash = fact_store::Store::open(&entry.database)?
        .insert_authorized_object_with_projected_mode(
            &deliberation,
            fact_store::ProjectedMode::Incremental,
        )?;
    Ok(Some(DeliberationRepairResult {
        created: true,
        repair: true,
        deliberation_id,
        revision_id,
        content_hash: hash.hex(),
    }))
}

pub fn list_deliberations(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<Vec<DeliberationSummary>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let deliberations = store.list_deliberation_projecteds_by_proposition(
        ledger.as_bytes(),
        item.proposition_id.as_bytes(),
    )?;
    let deliberation_ids = deliberations
        .iter()
        .map(|row| row.deliberation_id)
        .collect::<Vec<_>>();
    let mut status_by_deliberation = HashMap::new();
    for row in
        store.list_settlement_payloads_by_deliberations(ledger.as_bytes(), &deliberation_ids)?
    {
        let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
        if let Some(outcome) = value["body"]["outcome"].as_str() {
            let Some(deliberation_id) = value["body"]["deliberation_id"]
                .as_str()
                .and_then(|id| uuid::Uuid::parse_str(id).ok())
            else {
                continue;
            };
            status_by_deliberation.insert(deliberation_id, outcome.to_owned());
        }
    }
    let mut values = Vec::new();
    for row in deliberations {
        let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
        let status = status_by_deliberation
            .get(&row.deliberation_id)
            .cloned()
            .unwrap_or_else(|| "pending".to_owned());
        values.push(DeliberationSummary {
            deliberation_id: row.deliberation_id,
            reference: crate::reference::short_uuid_reference(row.deliberation_id),
            content_hash: row.content_hash.hex(),
            proposition_id: item.proposition_id,
            revision_id: value["body"]["revision_id"].clone(),
            status,
        });
    }
    values.sort_by_key(|value| value.deliberation_id);
    Ok(values)
}

pub fn show_deliberation(entry: &LedgerEntry, reference: &str) -> Result<serde_json::Value> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let deliberation = resolve_deliberation_reference(entry, reference)?;
    show_deliberation_by_id(entry, ledger, deliberation)
}

pub fn show_deliberation_by_id(
    entry: &LedgerEntry,
    ledger: uuid::Uuid,
    deliberation: uuid::Uuid,
) -> Result<serde_json::Value> {
    let store = fact_store::Store::open(&entry.database)?;
    let payload = store
        .get_payload(deliberation.as_bytes())?
        .ok_or_else(|| Error::MissingObject("deliberation is not present in the ledger".into()))?;
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    Ok(serde_json::json!({
        "deliberation_id": deliberation,
        "deliberation": value,
        "comments": related_objects_by_deliberation(&store, ledger, deliberation, "deliberation_comment")?,
        "decisions": related_objects_by_deliberation(&store, ledger, deliberation, "decision")?,
        "participant_changes": related_objects_by_deliberation(&store, ledger, deliberation, "deliberation_participant_change")?,
        "settlements": related_objects_by_deliberation(&store, ledger, deliberation, "settlement")?,
        "participant_status": participant_decision_status(&store, ledger, deliberation)?,
    }))
}

pub fn create_comment(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    content: &[u8],
) -> Result<CommentResult> {
    let runtime = production_runtime();
    create_comment_with_runtime(entry, seed, reference, content, runtime.as_ref())
}

pub fn create_comment_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    content: &[u8],
    runtime: &dyn SdkRuntime,
) -> Result<CommentResult> {
    ensure_writable(entry)?;
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let deliberation_id = item
        .deliberation_id
        .ok_or_else(|| Error::Message("proposition has no deliberation".into()))?;
    let deliberation = store
        .get_cose_by_id(ledger.as_bytes(), deliberation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("deliberation object is unavailable".into()))?;
    let participant_change =
        latest_participant_change(&store, ledger, deliberation_id, actor, true)?;
    let comment_id = runtime.next_uuid_v7()?;
    let comment = signed_envelope(
        comment_id,
        ledger,
        "deliberation_comment",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id": deliberation_id,
            "content": {
                "media_type":"text/markdown; charset=utf-8; variant=fact-v0",
                "bytes":base64url(content),
                "hash":fact_core::Hash::digest(content).hex()
            },
            "parent_comment_id":null,
            "comment_phase":"pre-settlement"
        }),
        {
            let mut dependencies = vec![dependency_value(&deliberation, "deliberation")?];
            if let Some(participant_change) = participant_change {
                dependencies.push(dependency_value(&participant_change, "participant-change")?);
            }
            dependencies
        },
        &key,
        runtime,
    )?;
    let hash = dependency_hash(&comment)?;
    store.insert_authorized_object_with_projected_mode(
        &comment,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(CommentResult {
        created: true,
        object_type: "deliberation_comment".into(),
        comment_id,
        deliberation_id,
        content_hash: hash.hex(),
    })
}

pub fn list_comments(
    entry: &LedgerEntry,
    reference: &str,
    revision: Option<&str>,
) -> Result<Vec<CommentSummary>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let revision_id = if let Some(value) = revision {
        let ids = crate::proposition::list_revisions(entry, reference)?
            .into_iter()
            .filter_map(|revision_value| {
                revision_value["object_id"]
                    .as_str()
                    .and_then(|id| uuid::Uuid::parse_str(id).ok())
                    .filter(|id| id.to_string().starts_with(value))
            })
            .collect::<Vec<_>>();
        match ids.as_slice() {
            [id] => Some(*id),
            [] => None,
            _ => None,
        }
    } else {
        None
    };
    if let (Some(revision), None) = (revision, revision_id) {
        return Err(Error::Message(format!(
            "no unambiguous revision matches {revision}"
        )));
    }
    list_comments_for_proposition(&store, ledger, item.proposition_id, revision_id)
}

pub fn join_deliberation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    invitation_reference: &str,
) -> Result<ParticipantChangeResult> {
    let runtime = production_runtime();
    join_deliberation_with_runtime(
        entry,
        seed,
        reference,
        invitation_reference,
        runtime.as_ref(),
    )
}

pub fn join_deliberation_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    invitation_reference: &str,
    runtime: &dyn SdkRuntime,
) -> Result<ParticipantChangeResult> {
    ensure_writable(entry)?;
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let deliberation_id = item
        .deliberation_id
        .ok_or_else(|| Error::Message("proposition has no deliberation".into()))?;
    let deliberation = store
        .get_cose_by_id(ledger.as_bytes(), deliberation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("deliberation object is unavailable".into()))?;
    let authority = comment_authority(&store, ledger, actor)?;
    let invitation_id = resolve_invitation(&store, ledger, invitation_reference)?;
    let invitation = store
        .get_cose_by_id(ledger.as_bytes(), invitation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("participant invitation is unavailable".into()))?;
    validate_invitation(&invitation, actor, item.proposition_id, deliberation_id)?;
    let change_id = runtime.next_uuid_v7()?;
    let change = signed_envelope(
        change_id,
        ledger,
        "deliberation_participant_change",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id":deliberation_id,
            "participant_actor_id":actor,
            "operation":"join",
            "invitation_id":invitation_id,
            "admission_evidence":[],
            "carried_decision_id":null,
            "predecessor_change_id":null,
            "changed_by_actor_id":actor,
            "authorization_ref":null
        }),
        vec![
            dependency_value(&deliberation, "deliberation")?,
            dependency_value(&invitation, "participant-invitation")?,
            dependency_value(&authority, "participant-authority")?,
        ],
        &key,
        runtime,
    )?;
    let hash = dependency_hash(&change)?;
    store.insert_authorized_object_with_projected_mode(
        &change,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(ParticipantChangeResult {
        created: true,
        object_type: "deliberation_participant_change".into(),
        operation: "join".into(),
        change_id,
        deliberation_id,
        invitation_id: Some(invitation_id),
        predecessor_change_id: None,
        content_hash: hash.hex(),
    })
}

pub fn leave_deliberation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
) -> Result<ParticipantChangeResult> {
    let runtime = production_runtime();
    leave_deliberation_with_runtime(entry, seed, reference, runtime.as_ref())
}

pub fn leave_deliberation_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    runtime: &dyn SdkRuntime,
) -> Result<ParticipantChangeResult> {
    ensure_writable(entry)?;
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let deliberation_id = item
        .deliberation_id
        .ok_or_else(|| Error::Message("proposition has no deliberation".into()))?;
    let deliberation = store
        .get_cose_by_id(ledger.as_bytes(), deliberation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("deliberation object is unavailable".into()))?;
    if has_decision(&store, ledger, deliberation_id, actor)? {
        return Err(Error::Message(
            "cannot leave a deliberation after submitting a decision".into(),
        ));
    }
    let predecessor = latest_join_id(&store, ledger, deliberation_id, actor)?;
    let predecessor_object = predecessor
        .map(|id| {
            store
                .get_cose_by_id(ledger.as_bytes(), id.as_bytes())?
                .ok_or_else(|| {
                    Error::MissingObject("participant join object is unavailable".into())
                })
        })
        .transpose()?;
    let mut dependencies = vec![dependency_value(&deliberation, "deliberation")?];
    if let Some(predecessor_object) = predecessor_object.as_ref() {
        dependencies.push(dependency_value(
            predecessor_object,
            "participant-predecessor",
        )?);
    }
    let change_id = runtime.next_uuid_v7()?;
    let change = signed_envelope(
        change_id,
        ledger,
        "deliberation_participant_change",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id":deliberation_id,
            "participant_actor_id":actor,
            "operation":"leave",
            "invitation_id":null,
            "admission_evidence":[],
            "carried_decision_id":null,
            "predecessor_change_id":predecessor,
            "changed_by_actor_id":actor,
            "authorization_ref":null
        }),
        dependencies,
        &key,
        runtime,
    )?;
    let hash = dependency_hash(&change)?;
    store.insert_authorized_object_with_projected_mode(
        &change,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(ParticipantChangeResult {
        created: true,
        object_type: "deliberation_participant_change".into(),
        operation: "leave".into(),
        change_id,
        deliberation_id,
        invitation_id: None,
        predecessor_change_id: predecessor,
        content_hash: hash.hex(),
    })
}

pub fn active_participants(entry: &LedgerEntry, deliberation: uuid::Uuid) -> Result<Vec<String>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    active_participants_for_deliberation(&store, ledger, deliberation)
}

pub fn participant_changes(
    entry: &LedgerEntry,
    deliberation: uuid::Uuid,
) -> Result<Vec<serde_json::Value>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    related_objects_by_deliberation(
        &store,
        ledger,
        deliberation,
        "deliberation_participant_change",
    )
}

pub fn open_deliberation_for_revision(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    revision: uuid::Uuid,
) -> Result<DeliberationOpenResult> {
    let runtime = production_runtime();
    open_deliberation_for_revision_with_runtime(entry, seed, revision, runtime.as_ref())
}

pub fn open_deliberation_for_revision_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    revision: uuid::Uuid,
    runtime: &dyn SdkRuntime,
) -> Result<DeliberationOpenResult> {
    ensure_writable(entry)?;
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let revision_cose = store
        .get_cose_by_id(ledger.as_bytes(), revision.as_bytes())?
        .ok_or_else(|| Error::MissingObject("revision is not present in the ledger".into()))?;
    let revision_value: serde_json::Value =
        serde_json::from_slice(&fact_crypto::decode_sign1(&revision_cose)?.payload)?;
    if revision_value["object_type"] != "revision" {
        return Err(Error::Validation(
            "revision ID does not identify a revision object".into(),
        ));
    }
    let proposition = parse_uuid7(
        revision_value["body"]["proposition_id"]
            .as_str()
            .ok_or_else(|| Error::Validation("revision has no proposition_id".into()))?,
        "proposition",
    )?;
    let proposition_cose = store
        .get_cose_by_id(ledger.as_bytes(), proposition.as_bytes())?
        .ok_or_else(|| {
            Error::MissingObject("revision proposition is not present in the ledger".into())
        })?;
    let deliberation_id = runtime.next_uuid_v7()?;
    let object = signed_envelope(
        deliberation_id,
        ledger,
        "deliberation",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id":deliberation_id.to_string(),
            "proposition_id":proposition.to_string(),
            "revision_id":revision.to_string(),
            "extends_deliberation_id":null,
            "decision_rule":{"id":"unanimity","version":0,"parameters":{}},
            "join_policy":{"policy_version":0,"mode":"open","attestation_requirements":[]},
            "initial_participants":[{"actor_id":actor.to_string(),"carried_decision_id":null}],
            "roster_governance":null,
            "opening_actor_id":actor.to_string(),
            "comments_closed_on_settlement":true
        }),
        vec![
            dependency_value(&proposition_cose, "proposition")?,
            dependency_value(&revision_cose, "revision")?,
        ],
        &key,
        runtime,
    )?;
    let hash = store.insert_authorized_object_with_projected_mode(
        &object,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(DeliberationOpenResult {
        created: true,
        object_type: "deliberation".into(),
        object_id: deliberation_id,
        content_hash: hash.hex(),
    })
}

pub fn resolve_deliberation_reference(entry: &LedgerEntry, reference: &str) -> Result<uuid::Uuid> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let mut matches = store
        .resolve_object_reference(ledger.as_bytes(), reference, &["deliberation"])?
        .into_iter()
        .map(|item| item.object_id)
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [id] => Ok(*id),
        [] => Err(Error::MissingObject(format!(
            "no deliberation matches {reference}"
        ))),
        _ => Err(Error::AmbiguousReference(format!(
            "multiple deliberations match {reference}"
        ))),
    }
}

fn list_comments_for_proposition(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: uuid::Uuid,
    revision_id: Option<uuid::Uuid>,
) -> Result<Vec<CommentSummary>> {
    Ok(crate::proposition::list_comments_for_proposition_as_values(
        store,
        ledger,
        proposition_id,
        revision_id,
    )?
    .into_iter()
    .filter_map(|value| {
        Some(CommentSummary {
            object_id: value["object_id"].as_str()?.parse().ok()?,
            reference: value["reference"].as_str()?.to_owned(),
            object_type: value["object_type"].as_str()?.to_owned(),
            content_hash: value["content_hash"].as_str()?.to_owned(),
            created_at: value["created_at"].clone(),
            actor_id: value["actor_id"].clone(),
            deliberation_id: value["deliberation_id"].clone(),
            parent_comment_id: value["parent_comment_id"].clone(),
            summary: value["summary"].as_str()?.to_owned(),
        })
    })
    .collect())
}

fn latest_revision_parent(
    store: &fact_store::Store,
    proposition_id: uuid::Uuid,
    revision_id: uuid::Uuid,
) -> Result<Option<uuid::Uuid>> {
    let payload = store
        .get_payload(revision_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("revision payload is unavailable".into()))?;
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    if value["body"]["proposition_id"].as_str() != Some(&proposition_id.to_string()) {
        return Err(Error::Validation(
            "revision does not belong to the proposition".into(),
        ));
    }
    value["body"]["parent_revision_id"]
        .as_str()
        .map(str::parse)
        .transpose()
        .map_err(Into::into)
}

fn ensure_writable(entry: &LedgerEntry) -> Result<()> {
    if entry.read_only {
        Err(Error::ReadOnlyLedger)
    } else {
        Ok(())
    }
}

fn latest_participant_change(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberation_id: uuid::Uuid,
    actor: uuid::Uuid,
    join_or_leave: bool,
) -> Result<Option<Vec<u8>>> {
    let actor_text = actor.to_string();
    let id = store
        .list_objects_by_deliberation(
            ledger.as_bytes(),
            deliberation_id.as_bytes(),
            "deliberation_participant_change",
        )?
        .into_iter()
        .filter_map(|row| {
            let value = serde_json::from_slice::<serde_json::Value>(&row.payload).ok()?;
            let body = value.get("body")?;
            let operation = body.get("operation").and_then(serde_json::Value::as_str);
            (body
                .get("participant_actor_id")
                .and_then(serde_json::Value::as_str)
                == Some(actor_text.as_str())
                && (!join_or_leave || matches!(operation, Some("join") | Some("leave"))))
            .then_some((value["created_at"].as_str()?.to_owned(), row.object_id))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, id)| id);
    id.map(|id| {
        store
            .get_cose_by_id(ledger.as_bytes(), id.as_bytes())?
            .ok_or_else(|| Error::MissingObject("participant change object is unavailable".into()))
    })
    .transpose()
}

fn latest_join_id(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberation_id: uuid::Uuid,
    actor: uuid::Uuid,
) -> Result<Option<uuid::Uuid>> {
    let actor_text = actor.to_string();
    Ok(store
        .list_objects_by_deliberation(
            ledger.as_bytes(),
            deliberation_id.as_bytes(),
            "deliberation_participant_change",
        )?
        .into_iter()
        .filter_map(|row| {
            let value = serde_json::from_slice::<serde_json::Value>(&row.payload).ok()?;
            let body = value.get("body")?;
            (body
                .get("participant_actor_id")
                .and_then(serde_json::Value::as_str)
                == Some(actor_text.as_str())
                && body.get("operation").and_then(serde_json::Value::as_str) == Some("join"))
            .then_some((value["created_at"].as_str()?.to_owned(), row.object_id))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, id)| id))
}

fn has_decision(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberation_id: uuid::Uuid,
    actor: uuid::Uuid,
) -> Result<bool> {
    let actor_text = actor.to_string();
    Ok(store
        .list_objects_by_deliberation(ledger.as_bytes(), deliberation_id.as_bytes(), "decision")?
        .into_iter()
        .filter_map(|row| {
            let value = serde_json::from_slice::<serde_json::Value>(&row.payload).ok()?;
            Some(value["body"]["participant_actor_id"].as_str() == Some(actor_text.as_str()))
        })
        .any(|matches| matches))
}

fn comment_authority(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor: uuid::Uuid,
) -> Result<Vec<u8>> {
    let authority = store
        .list_authority_grant_payloads(ledger.as_bytes(), actor.as_bytes(), "comment")?
        .into_iter()
        .map(|row| row.object_id)
        .next()
        .ok_or_else(|| {
            Error::Authorization("active actor has no comment authority grant".into())
        })?;
    store
        .get_cose_by_id(ledger.as_bytes(), authority.as_bytes())?
        .ok_or_else(|| Error::MissingObject("comment authority grant is unavailable".into()))
}

fn resolve_invitation(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    invitation_reference: &str,
) -> Result<uuid::Uuid> {
    let invitation_matches = store
        .resolve_object_reference(
            ledger.as_bytes(),
            invitation_reference,
            &["participant_invitation"],
        )?
        .into_iter()
        .collect::<Vec<_>>();
    match invitation_matches.as_slice() {
        [item] => Ok(item.object_id),
        [] => Err(Error::MissingObject(format!(
            "no participant invitation matches reference {invitation_reference}"
        ))),
        _ => Err(Error::AmbiguousReference(format!(
            "invitation reference {invitation_reference} is ambiguous"
        ))),
    }
}

fn validate_invitation(
    invitation: &[u8],
    actor: uuid::Uuid,
    proposition_id: uuid::Uuid,
    deliberation_id: uuid::Uuid,
) -> Result<()> {
    let invitation_value: serde_json::Value =
        serde_json::from_slice(&fact_crypto::decode_sign1(invitation)?.payload)?;
    let invitation_body = &invitation_value["body"];
    let actor_text = actor.to_string();
    let deliberation_text = deliberation_id.to_string();
    let proposition_text = proposition_id.to_string();
    let invited_actor = invitation_body["invited_actor_id"]
        .as_str()
        .ok_or_else(|| Error::Validation("participant invitation has no invited actor".into()))?;
    if invited_actor != actor_text
        || (invitation_body["deliberation_id"].is_string()
            && invitation_body["deliberation_id"].as_str() != Some(deliberation_text.as_str()))
        || (invitation_body["proposition_id"].is_string()
            && invitation_body["proposition_id"].as_str() != Some(proposition_text.as_str()))
    {
        return Err(Error::Authorization(
            "participant invitation is not addressed to this deliberation and actor".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proposition::{create_proposition, dependency_value, signed_envelope},
        workflow::{create_ledger, BootstrapLedgerInput},
    };

    fn entry() -> (tempfile::TempDir, LedgerEntry, [u8; 32]) {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [21; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.discussion-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce: [22; 16],
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
    fn comment_lifecycle_and_deliberation_views_work() {
        let (_temp, entry, seed) = entry();
        let proposition =
            create_proposition(&entry, &seed, b"# Discuss\n\nReview this.\n", None).unwrap();
        let view = read_deliberation(&entry, &proposition.proposition_id.to_string()).unwrap();
        assert_eq!(view.deliberation_id, proposition.deliberation_id);

        fact_store::Store::reset_debug_metrics();
        let comment = create_comment(
            &entry,
            &seed,
            &proposition.proposition_id.to_string(),
            b"# Comment\n\nLooks good.\n",
        )
        .unwrap();
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);
        assert_eq!(comment.object_type, "deliberation_comment");
        let comments =
            list_comments(&entry, &proposition.proposition_id.to_string(), None).unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].summary, "Comment");

        fact_store::Store::reset_debug_metrics();
        let listed = list_deliberations(&entry, &proposition.proposition_id.to_string()).unwrap();
        assert_eq!(
            fact_store::Store::debug_metrics().list_objects_by_deliberation,
            0
        );
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, "pending");
        let shown = show_deliberation(&entry, &proposition.deliberation_id.to_string()).unwrap();
        assert_eq!(shown["comments"].as_array().unwrap().len(), 1);
        assert_eq!(shown["participant_status"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn join_leave_and_read_only_boundaries_are_enforced() {
        let (_temp, entry, seed) = entry();
        let proposition =
            create_proposition(&entry, &seed, b"# Join\n\nInvite participant.\n", None).unwrap();
        fact_store::Store::reset_debug_metrics();
        let (target_entry, target_seed) = create_invited_identity(
            &entry,
            &seed,
            proposition.proposition_id,
            proposition.deliberation_id,
        );
        assert_eq!(
            fact_store::Store::debug_metrics().list_object_payloads_by_type,
            0
        );

        fact_store::Store::reset_debug_metrics();
        let joined = join_deliberation(
            &target_entry,
            &target_seed,
            &proposition.proposition_id.to_string(),
            &target_entry.name,
        )
        .unwrap();
        assert_eq!(joined.operation, "join");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);

        let participants = active_participants(&entry, proposition.deliberation_id).unwrap();
        assert_eq!(participants.len(), 2);

        fact_store::Store::reset_debug_metrics();
        let left = leave_deliberation(
            &target_entry,
            &target_seed,
            &proposition.proposition_id.to_string(),
        )
        .unwrap();
        assert_eq!(left.operation, "leave");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);
        let participants = active_participants(&entry, proposition.deliberation_id).unwrap();
        assert_eq!(participants.len(), 1);

        let read_only = LedgerEntry {
            read_only: true,
            ..entry.clone()
        };
        assert!(matches!(
            create_comment(
                &read_only,
                &seed,
                &proposition.proposition_id.to_string(),
                b"# No\n"
            ),
            Err(Error::ReadOnlyLedger)
        ));
    }

    fn create_invited_identity(
        entry: &LedgerEntry,
        seed: &[u8; 32],
        proposition_id: uuid::Uuid,
        deliberation_id: uuid::Uuid,
    ) -> (LedgerEntry, [u8; 32]) {
        let ledger = parse_uuid7(&entry.ledger_id, "ledger").unwrap();
        let actor = parse_uuid7(&entry.actor_id, "actor").unwrap();
        let key_id = parse_uuid7(&entry.key_id, "key").unwrap();
        let key = fact_crypto::SigningKey::from_seed(seed).unwrap();
        let store = fact_store::Store::open(&entry.database).unwrap();
        let target_seed = [31; 32];
        let target_store = fact_store::Store::open_memory().unwrap();
        let target_bootstrap = target_store
            .bootstrap_ledger(
                "local.target-identity",
                "2026-07-30T12:00:00.000Z",
                target_seed,
                [32; 16],
            )
            .unwrap();
        store
            .insert_verified_bundle(&target_bootstrap.cose_objects[..3])
            .unwrap();
        let (_, root_grant) = crate::identity::root_grant(&store, ledger).unwrap();
        let runtime = production_runtime();
        let grant_id = uuid::Uuid::now_v7();
        let grant = signed_envelope(
            grant_id,
            ledger,
            "authorization_grant",
            actor,
            key_id,
            serde_json::json!({
                "grant_id":grant_id,
                "granting_actor_id":actor,
                "receiving_actor_id":target_bootstrap.actor_id,
                "capabilities":["comment"],
                "scope":{"type":"ledger"},
                "validity":null,
                "constraints":{},
                "predecessor_grant_id":null
            }),
            vec![dependency_value(&root_grant, "admin-authority").unwrap()],
            &key,
            runtime.as_ref(),
        )
        .unwrap();
        store.insert_authorized_object(&grant).unwrap();
        let deliberation = store
            .get_cose_by_id(ledger.as_bytes(), deliberation_id.as_bytes())
            .unwrap()
            .unwrap();
        let invitation_id = uuid::Uuid::now_v7();
        let invitation = signed_envelope(
            invitation_id,
            ledger,
            "participant_invitation",
            actor,
            key_id,
            serde_json::json!({
                "invitation_id":invitation_id,
                "proposition_id":proposition_id,
                "inviting_actor_id":actor,
                "invited_actor_id":target_bootstrap.actor_id,
                "participation_type":"standing",
                "constraints":{},
                "validity":null,
                "predecessor_invitation_id":null
            }),
            vec![dependency_value(&deliberation, "deliberation").unwrap()],
            &key,
            runtime.as_ref(),
        )
        .unwrap();
        store.insert_authorized_object(&invitation).unwrap();
        (
            LedgerEntry {
                name: invitation_id.to_string(),
                ledger_id: entry.ledger_id.clone(),
                database: entry.database.clone(),
                actor_id: target_bootstrap.actor_id.to_string(),
                key_id: target_bootstrap.key_id.to_string(),
                seed_file: entry.seed_file.clone(),
                read_only: false,
            },
            target_seed,
        )
    }
}
