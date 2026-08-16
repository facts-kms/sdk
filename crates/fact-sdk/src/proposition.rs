use crate::{
    environment::LedgerEntry,
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

type RelatedObject = (uuid::Uuid, fact_core::Hash, String, serde_json::Value);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionOutcome {
    Accepted,
    Rejected,
}

impl DecisionOutcome {
    fn as_status(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListPropositionStatus {
    Pending,
    Accepted,
    Rejected,
    Contested,
    Withdrawn,
    Archived,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListPropositionsFilter {
    pub status: Option<ListPropositionStatus>,
    pub all: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListPropositionsPage {
    pub offset: usize,
    pub limit: Option<usize>,
    pub after: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PropositionResult {
    pub proposition_id: uuid::Uuid,
    pub revision_id: uuid::Uuid,
    pub deliberation_id: uuid::Uuid,
    pub decision_id: Option<uuid::Uuid>,
    pub settlement_id: Option<uuid::Uuid>,
    pub status: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_revision_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_revision_effective: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_participant_count: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub content_hashes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ReconciliationConflictInput {
    pub revision_id: uuid::Uuid,
    pub deliberation_id: uuid::Uuid,
    pub settlement_id: uuid::Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RevisionConflictItem {
    pub revision_id: uuid::Uuid,
    pub status: String,
    pub tip: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub matched_reference: bool,
    pub deliberation_id: Option<uuid::Uuid>,
    pub settlement_id: Option<uuid::Uuid>,
    pub participant_count: usize,
    pub current_actor_pending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RevisionConflictResolutionInputs {
    pub conflict_triples: Vec<String>,
    pub resolved_tips: Vec<uuid::Uuid>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RevisionConflictGroup {
    pub proposition_id: uuid::Uuid,
    pub reference: String,
    pub summary: String,
    pub status: String,
    pub common_ancestor_revision_id: Option<uuid::Uuid>,
    pub conflicts: Vec<RevisionConflictItem>,
    pub resolution_inputs: RevisionConflictResolutionInputs,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ReconciliationInput {
    pub affected_proposition_id: uuid::Uuid,
    pub common_ancestor_revision_id: uuid::Uuid,
    pub conflicts: Vec<ReconciliationConflictInput>,
    pub detecting_actor_id: uuid::Uuid,
    pub resolution_mode: String,
    pub resolved_tip_ids: Vec<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_revision_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_revision_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markdown: Option<Vec<u8>>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ReconciliationResult {
    pub proposition_id: uuid::Uuid,
    pub revision_id: uuid::Uuid,
    pub deliberation_id: uuid::Uuid,
    pub conflict_set_hash: String,
    pub resolution_mode: String,
    pub selected_participant_count: usize,
    pub content_hashes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveContent {
    Keep { revision_id: uuid::Uuid },
    Derived { markdown: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveConflictInput {
    pub reference: Option<String>,
    pub content: ResolveContent,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ResolveConflictResult {
    pub resolved: bool,
    pub proposition_id: uuid::Uuid,
    pub revision_id: uuid::Uuid,
    pub deliberation_id: uuid::Uuid,
    pub status: String,
    pub resolution_mode: String,
    pub kept_revision_id: Option<uuid::Uuid>,
    pub merged_revision_ids: Vec<uuid::Uuid>,
    pub resolved_revision_ids: Vec<uuid::Uuid>,
    pub participant_ids: Vec<uuid::Uuid>,
    pub common_ancestor_revision_id: Option<uuid::Uuid>,
    pub pending_participant_count: usize,
    pub reconciliation_proposition_id: uuid::Uuid,
    pub result_revision_id: Option<uuid::Uuid>,
    pub content_hashes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DerivedRevisionInput {
    pub proposition_id: uuid::Uuid,
    pub parent_revision_id: uuid::Uuid,
    pub contributing_revision_ids: Vec<uuid::Uuid>,
    pub markdown: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PropositionListItem {
    pub proposition_id: uuid::Uuid,
    pub reference: String,
    pub status: String,
    pub summary: String,
    pub revision_id: Option<uuid::Uuid>,
    pub deliberation_id: Option<uuid::Uuid>,
    pub settlement_id: Option<uuid::Uuid>,
    pub effective_status: String,
    pub latest_revision_id: Option<uuid::Uuid>,
    pub latest_revision_status: String,
    pub pending_revision_id: Option<uuid::Uuid>,
    pub pending_deliberation_id: Option<uuid::Uuid>,
    pub pending_participant_count: usize,
    pub current_actor_pending: bool,
    pub has_pending_revision: bool,
}

#[derive(Clone, Debug)]
struct RevisionActivity {
    latest_revision_id: Option<uuid::Uuid>,
    latest_revision_status: String,
    pending_revision_id: Option<uuid::Uuid>,
    pending_deliberation_id: Option<uuid::Uuid>,
    pending_participant_count: usize,
    current_actor_pending: bool,
    has_pending_revision: bool,
}

type DecisionSettlementResult = (
    Option<uuid::Uuid>,
    Option<uuid::Uuid>,
    String,
    Option<usize>,
);

#[derive(Clone, Debug)]
pub(crate) struct CanonicalDecisionRecord {
    pub decision_id: uuid::Uuid,
    pub participant_actor_id: uuid::Uuid,
    pub value: String,
    pub content_hash: fact_core::Hash,
    pub cose: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SearchResult {
    pub object_id: uuid::Uuid,
    pub reference: String,
    pub content_hash: String,
    pub score: String,
    pub summary: String,
    pub proposition_id: Option<uuid::Uuid>,
    pub status: Option<String>,
    pub effective: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ResolvedContent {
    pub content: Vec<u8>,
    pub revision_id: uuid::Uuid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum ContentSelection {
    Effective,
    Pending,
    Latest,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct HistoryItem {
    pub object_id: uuid::Uuid,
    pub reference: String,
    pub object_type: String,
    pub content_hash: String,
    pub created_at: String,
    pub actor_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_display: Option<String>,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShowOverviewInput {
    pub reference: String,
    pub revision_limit: Option<usize>,
    pub comments_limit: Option<usize>,
    pub history_limit: Option<usize>,
    pub include_conflicts_all: bool,
    pub include_history: bool,
    pub include_content: bool,
    pub include_participants: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ShowMatchedObject {
    pub object_type: String,
    pub object_id: uuid::Uuid,
    pub object_ref: String,
    pub content_hash: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ShowPendingOverview {
    pub current_actor_pending: bool,
    pub actions: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ShowOverviewPage {
    pub revisions_limit: Option<usize>,
    pub comments_limit: Option<usize>,
    pub history_limit: Option<usize>,
    pub revisions_truncated: bool,
    pub comments_truncated: bool,
    pub history_truncated: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ShowOverview {
    pub query: String,
    pub matched: ShowMatchedObject,
    pub proposition: PropositionListItem,
    pub effective_revision: Option<serde_json::Value>,
    pub content: Option<String>,
    pub content_included: bool,
    pub tags: Vec<String>,
    pub conflicts: Vec<RevisionConflictGroup>,
    pub pending: ShowPendingOverview,
    pub revisions: Vec<serde_json::Value>,
    pub deliberations: Vec<serde_json::Value>,
    pub comments: Vec<serde_json::Value>,
    pub history: Vec<HistoryItem>,
    pub next: Vec<serde_json::Value>,
    pub page: ShowOverviewPage,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct HistoryPage {
    pub after: Option<String>,
    pub limit: Option<usize>,
}

pub fn create_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    markdown: &[u8],
    decision: Option<DecisionOutcome>,
) -> Result<PropositionResult> {
    let runtime = production_runtime();
    create_proposition_with_runtime(entry, seed, markdown, decision, runtime.as_ref())
}

pub fn create_proposition_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    markdown: &[u8],
    decision: Option<DecisionOutcome>,
    runtime: &dyn SdkRuntime,
) -> Result<PropositionResult> {
    create_proposition_with_runtime_and_projected_mode(
        entry,
        seed,
        markdown,
        decision,
        runtime,
        fact_store::ProjectedMode::Incremental,
    )
}

pub fn create_proposition_with_runtime_and_projected_mode(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    markdown: &[u8],
    decision: Option<DecisionOutcome>,
    runtime: &dyn SdkRuntime,
    projected_mode: fact_store::ProjectedMode,
) -> Result<PropositionResult> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let content = content_value(markdown);
    let proposition_id = runtime.next_uuid_v7()?;
    let revision_id = runtime.next_uuid_v7()?;
    let deliberation_id = runtime.next_uuid_v7()?;
    let (propose_authority, mut authority_objects, generated_propose_authority) =
        propose_authority_for_actor(&store, ledger, actor, key_id, &key, runtime)?;
    let deliberate_authority = deliberate_authority_for_actor(
        &store,
        ledger,
        actor,
        generated_propose_authority.then_some(&propose_authority),
    )?;
    let proposition = signed_envelope(
        proposition_id,
        ledger,
        "proposition",
        actor,
        key_id,
        serde_json::json!({"proposition_id":proposition_id,"purpose":"knowledge","initial_revision_id":revision_id,"initial_deliberation_id":deliberation_id}),
        vec![propose_authority],
        &key,
        runtime,
    )?;
    let proposition_hash = dependency_hash(&proposition)?;
    let revision = signed_envelope(
        revision_id,
        ledger,
        "revision",
        actor,
        key_id,
        serde_json::json!({"proposition_id":proposition_id,"revision_id":revision_id,"parent_revision_id":null,"content":content,"relationships":[],"reconciliation_manifest":null}),
        vec![
            serde_json::json!({"object_id":proposition_id,"content_hash":proposition_hash.hex(),"role":"proposition"}),
        ],
        &key,
        runtime,
    )?;
    let revision_hash = dependency_hash(&revision)?;
    let deliberation = signed_envelope(
        deliberation_id,
        ledger,
        "deliberation",
        actor,
        key_id,
        serde_json::json!({"deliberation_id":deliberation_id,"proposition_id":proposition_id,"revision_id":revision_id,"extends_deliberation_id":null,"decision_rule":{"id":"unanimity","version":0,"parameters":{}},"join_policy":{"policy_version":0,"mode":"open","attestation_requirements":[]},"initial_participants":[{"actor_id":actor,"carried_decision_id":null}],"roster_governance":null,"opening_actor_id":actor,"comments_closed_on_settlement":true}),
        vec![
            serde_json::json!({"object_id":proposition_id,"content_hash":proposition_hash.hex(),"role":"proposition"}),
            serde_json::json!({"object_id":revision_id,"content_hash":revision_hash.hex(),"role":"revision"}),
            deliberate_authority,
        ],
        &key,
        runtime,
    )?;
    let mut bundle = vec![deliberation, revision, proposition];
    bundle.append(&mut authority_objects);
    let content_hashes = store
        .insert_authorized_bundle_with_projected_mode(&bundle, projected_mode)?
        .into_iter()
        .map(|hash| hash.hex())
        .collect::<Vec<_>>();
    let (decision_id, settlement_id, status, pending_participant_count) =
        if let Some(outcome) = decision {
            create_decision_and_settlement(
                &store,
                ledger,
                actor,
                key_id,
                &key,
                deliberation_id,
                revision_id,
                outcome.as_status(),
                runtime,
                projected_mode,
            )?
        } else {
            (None, None, "pending".to_owned(), None)
        };
    Ok(PropositionResult {
        proposition_id,
        revision_id,
        deliberation_id,
        decision_id,
        settlement_id,
        status,
        summary: summary_for_markdown(markdown),
        previous_revision_id: None,
        previous_revision_effective: None,
        pending_participant_count,
        content_hashes,
    })
}

pub fn create_reconciliation_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ReconciliationInput,
) -> Result<ReconciliationResult> {
    let runtime = production_runtime();
    create_reconciliation_proposition_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn create_reconciliation_proposition_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ReconciliationInput,
    runtime: &dyn SdkRuntime,
) -> Result<ReconciliationResult> {
    if entry.read_only {
        return Err(Error::ReadOnlyLedger);
    }
    if input.conflicts.is_empty() {
        return Err(Error::Validation(
            "reconciliation requires at least one conflict".into(),
        ));
    }
    match input.resolution_mode.as_str() {
        "select" if input.selected_revision_id.is_some() && input.result_revision_id.is_none() => {}
        "derive" if input.selected_revision_id.is_none() && input.result_revision_id.is_some() => {}
        "reject-all"
            if input.selected_revision_id.is_none() && input.result_revision_id.is_none() => {}
        "select" | "derive" | "reject-all" => {
            return Err(Error::Validation(
                "resolution mode fields are inconsistent".into(),
            ));
        }
        _ => {
            return Err(Error::Validation(
                "resolution_mode must be `select`, `derive`, or `reject-all`".into(),
            ));
        }
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let (propose_authority, mut authority_objects, generated_propose_authority) =
        propose_authority_for_actor(&store, ledger, actor, key_id, &key, runtime)?;
    let deliberate_authority = deliberate_authority_for_actor(
        &store,
        ledger,
        actor,
        generated_propose_authority.then_some(&propose_authority),
    )?;
    let deliberate_authority_id = deliberate_authority["object_id"]
        .as_str()
        .ok_or_else(|| Error::Validation("deliberate authority has no object_id".into()))?
        .parse::<uuid::Uuid>()?;

    let affected_proposition = object_dependency(
        &store,
        ledger,
        input.affected_proposition_id,
        "affected-proposition",
    )?;
    let common_ancestor = object_dependency(
        &store,
        ledger,
        input.common_ancestor_revision_id,
        "common-ancestor-revision",
    )?;
    let mut dependencies = vec![
        affected_proposition.clone(),
        common_ancestor.clone(),
        propose_authority.clone(),
        deliberate_authority.clone(),
    ];
    let mut manifest_conflicts = Vec::new();
    let mut source_deliberation_ids = Vec::new();
    for conflict in &input.conflicts {
        dependencies.push(object_dependency(
            &store,
            ledger,
            conflict.revision_id,
            "conflicting-revision",
        )?);
        dependencies.push(object_dependency(
            &store,
            ledger,
            conflict.deliberation_id,
            "conflicting-deliberation",
        )?);
        dependencies.push(object_dependency(
            &store,
            ledger,
            conflict.settlement_id,
            "supporting-settlement",
        )?);
        let settlement_payload = store
            .get_payload(conflict.settlement_id.as_bytes())?
            .ok_or_else(|| {
                Error::MissingObject(format!(
                    "settlement {} is unavailable",
                    conflict.settlement_id
                ))
            })?;
        let settlement_value: serde_json::Value = serde_json::from_slice(&settlement_payload)?;
        let settlement_body = settlement_value
            .get("body")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| Error::Validation("settlement is missing body".into()))?;
        let outcome = settlement_body
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::Validation("settlement is missing outcome".into()))?;
        source_deliberation_ids.push(conflict.deliberation_id);
        manifest_conflicts.push(serde_json::json!({
            "revision_id": conflict.revision_id,
            "deliberation_id": conflict.deliberation_id,
            "settlement_id": conflict.settlement_id,
            "outcome": outcome,
        }));
    }
    manifest_conflicts.sort_by_key(|conflict| {
        (
            conflict["revision_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            conflict["deliberation_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    });
    for tip in &input.resolved_tip_ids {
        dependencies.push(object_dependency(&store, ledger, *tip, "resolved-tip")?);
    }
    if let Some(selected) = input.selected_revision_id {
        dependencies.push(object_dependency(
            &store,
            ledger,
            selected,
            "selected-revision",
        )?);
    }
    if let Some(result) = input.result_revision_id {
        dependencies.push(object_dependency(
            &store,
            ledger,
            result,
            "result-revision",
        )?);
    }

    let conflict_set_bytes =
        fact_canonical::encode(&serde_json::to_vec(&manifest_conflicts).map_err(Error::from)?)?;
    let conflict_set_hash = fact_core::Hash::digest(&conflict_set_bytes);
    let manifest = serde_json::json!({
        "affected_proposition_id": input.affected_proposition_id,
        "common_ancestor_revision_id": input.common_ancestor_revision_id,
        "conflicts": manifest_conflicts,
        "conflict_set_hash": conflict_set_hash.hex(),
        "detector_actor_id": input.detecting_actor_id,
        "resolution_mode": input.resolution_mode,
        "selected_revision_id": input.selected_revision_id,
        "result_revision_id": input.result_revision_id,
    });

    let proposition_id = runtime.next_uuid_v7()?;
    let revision_id = runtime.next_uuid_v7()?;
    let deliberation_id = runtime.next_uuid_v7()?;
    let proposition = signed_envelope(
        proposition_id,
        ledger,
        "proposition",
        actor,
        key_id,
        serde_json::json!({
            "proposition_id":proposition_id,
            "purpose":"reconciliation",
            "initial_revision_id":revision_id,
            "initial_deliberation_id":deliberation_id
        }),
        vec![propose_authority],
        &key,
        runtime,
    )?;
    let proposition_hash = dependency_hash(&proposition)?;
    let content = content_value(
        input
            .markdown
            .as_deref()
            .unwrap_or(b"# Reconciliation\n\nResolve structural conflict.\n"),
    );
    let revision = signed_envelope(
        revision_id,
        ledger,
        "revision",
        actor,
        key_id,
        serde_json::json!({
            "proposition_id":proposition_id,
            "revision_id":revision_id,
            "parent_revision_id":null,
            "content":content,
            "relationships":[],
            "reconciliation_manifest":manifest
        }),
        vec![
            serde_json::json!({"object_id":proposition_id,"content_hash":proposition_hash.hex(),"role":"proposition"}),
            affected_proposition,
            common_ancestor,
        ],
        &key,
        runtime,
    )?;
    let revision_hash = dependency_hash(&revision)?;
    dependencies.push(serde_json::json!({
        "object_id":proposition_id,
        "content_hash":proposition_hash.hex(),
        "role":"proposition"
    }));
    dependencies.push(serde_json::json!({
        "object_id":revision_id,
        "content_hash":revision_hash.hex(),
        "role":"revision"
    }));
    dedup_dependencies(&mut dependencies);
    let roster_governance = reconciliation_roster(
        &store,
        ledger,
        actor,
        deliberate_authority_id,
        &source_deliberation_ids,
    )?;
    let selected_participant_count = roster_governance
        .get("selected_participants")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    let initial_participants = roster_governance
        .get("selected_participants")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flat_map(|participants| participants.iter())
        .map(|participant| {
            serde_json::json!({
                "actor_id":participant["actor_id"],
                "carried_decision_id":null
            })
        })
        .collect::<Vec<_>>();
    let deliberation = signed_envelope(
        deliberation_id,
        ledger,
        "deliberation",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id":deliberation_id,
            "proposition_id":proposition_id,
            "revision_id":revision_id,
            "extends_deliberation_id":null,
            "decision_rule":{"id":"unanimity","version":0,"parameters":{}},
            "join_policy":{"policy_version":0,"mode":"open","attestation_requirements":[]},
            "initial_participants": initial_participants,
            "roster_governance":roster_governance,
            "opening_actor_id":actor,
            "comments_closed_on_settlement":true
        }),
        dependencies,
        &key,
        runtime,
    )?;
    let mut bundle = vec![deliberation, revision, proposition];
    bundle.append(&mut authority_objects);
    let content_hashes = store
        .insert_authorized_bundle_with_projected_mode(
            &bundle,
            fact_store::ProjectedMode::Incremental,
        )?
        .into_iter()
        .map(|hash| hash.hex())
        .collect::<Vec<_>>();
    Ok(ReconciliationResult {
        proposition_id,
        revision_id,
        deliberation_id,
        conflict_set_hash: conflict_set_hash.hex(),
        resolution_mode: input.resolution_mode,
        selected_participant_count,
        content_hashes,
    })
}

pub fn resolve_revision_conflict(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ResolveConflictInput,
) -> Result<ResolveConflictResult> {
    let runtime = production_runtime();
    resolve_revision_conflict_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn resolve_revision_conflict_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ResolveConflictInput,
    runtime: &dyn SdkRuntime,
) -> Result<ResolveConflictResult> {
    let groups = list_revision_conflicts(entry, input.reference.as_deref(), false)?;
    let group = match groups.as_slice() {
        [group] => group.clone(),
        [] => return Err(Error::Message("no revision conflicts".into())),
        _ => {
            return Err(Error::Message(
                "multiple revision conflicts; run `fact conflicts` and pass a reference to `fact resolve`"
                    .into(),
            ));
        }
    };
    let common_ancestor_revision_id = group.common_ancestor_revision_id.ok_or_else(|| {
        Error::Message(
            "revision conflict has no common ancestor; use `fact reconcile create`".into(),
        )
    })?;
    let conflicts = group
        .resolution_inputs
        .conflict_triples
        .iter()
        .map(|triple| parse_reconciliation_conflict_triple(triple))
        .collect::<Result<Vec<_>>>()?;
    if conflicts.len() < 2 {
        return Err(Error::Message(
            "revision conflict has no complete reconciliation inputs".into(),
        ));
    }
    let resolved_revision_ids = group.resolution_inputs.resolved_tips.clone();
    if resolved_revision_ids.len() < 2 {
        return Err(Error::Message(
            "revision conflict has fewer than two branch tips".into(),
        ));
    }
    let source_deliberation_ids = conflicts
        .iter()
        .map(|conflict| conflict.deliberation_id)
        .collect::<Vec<_>>();
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let store = fact_store::Store::open(&entry.database)?;
    let deliberate_authority = authority_dependency_for_actor(&store, ledger, actor, "deliberate")?
        .ok_or_else(|| {
            Error::MissingObject(format!(
                "actor {actor} has no deliberate authority on ledger {ledger}"
            ))
        })?;
    let deliberate_authority_id = deliberate_authority["object_id"]
        .as_str()
        .ok_or_else(|| Error::Validation("deliberate authority has no object_id".into()))?
        .parse::<uuid::Uuid>()?;
    let roster = reconciliation_roster(
        &store,
        ledger,
        actor,
        deliberate_authority_id,
        &source_deliberation_ids,
    )?;
    let participant_ids = roster
        .get("selected_participants")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flat_map(|participants| participants.iter())
        .filter_map(|participant| participant["actor_id"].as_str())
        .map(uuid::Uuid::parse_str)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let pending_participant_count = participant_ids.len();
    drop(store);

    let (resolution_mode, kept_revision_id, result_revision_id, reconciliation) = match input
        .content
    {
        ResolveContent::Keep { revision_id } => {
            if !resolved_revision_ids.contains(&revision_id) {
                return Err(Error::Message(
                    "--keep must reference one of the conflicting revisions".into(),
                ));
            }
            let kept = read_proposition_content(entry, &revision_id.to_string())?;
            let reconciliation = create_reconciliation_proposition_with_runtime(
                entry,
                seed,
                ReconciliationInput {
                    affected_proposition_id: group.proposition_id,
                    common_ancestor_revision_id,
                    conflicts,
                    detecting_actor_id: actor,
                    resolution_mode: "select".to_owned(),
                    resolved_tip_ids: resolved_revision_ids.clone(),
                    selected_revision_id: Some(revision_id),
                    result_revision_id: None,
                    markdown: Some(kept.content),
                },
                runtime,
            )?;
            ("select".to_owned(), Some(revision_id), None, reconciliation)
        }
        ResolveContent::Derived { markdown } => {
            let (result_revision_id, reconciliation) = create_derived_reconciliation_with_runtime(
                entry,
                seed,
                group.proposition_id,
                common_ancestor_revision_id,
                &conflicts,
                &resolved_revision_ids,
                actor,
                &markdown,
                runtime,
            )?;
            (
                "derive".to_owned(),
                None,
                Some(result_revision_id),
                reconciliation,
            )
        }
    };
    Ok(ResolveConflictResult {
        resolved: true,
        proposition_id: group.proposition_id,
        revision_id: reconciliation.revision_id,
        deliberation_id: reconciliation.deliberation_id,
        status: "pending".to_owned(),
        resolution_mode,
        kept_revision_id,
        merged_revision_ids: Vec::new(),
        resolved_revision_ids,
        participant_ids,
        common_ancestor_revision_id: Some(common_ancestor_revision_id),
        pending_participant_count,
        reconciliation_proposition_id: reconciliation.proposition_id,
        result_revision_id,
        content_hashes: reconciliation.content_hashes,
    })
}

#[allow(clippy::too_many_arguments)]
fn create_derived_reconciliation_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    affected_proposition_id: uuid::Uuid,
    common_ancestor_revision_id: uuid::Uuid,
    conflicts: &[ReconciliationConflictInput],
    resolved_revision_ids: &[uuid::Uuid],
    actor: uuid::Uuid,
    markdown: &[u8],
    runtime: &dyn SdkRuntime,
) -> Result<(uuid::Uuid, ReconciliationResult)> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let (propose_authority, mut authority_objects, generated_propose_authority) =
        propose_authority_for_actor(&store, ledger, actor, key_id, &key, runtime)?;
    let deliberate_authority = deliberate_authority_for_actor(
        &store,
        ledger,
        actor,
        generated_propose_authority.then_some(&propose_authority),
    )?;
    let deliberate_authority_id = deliberate_authority["object_id"]
        .as_str()
        .ok_or_else(|| Error::Validation("deliberate authority has no object_id".into()))?
        .parse::<uuid::Uuid>()?;

    let affected_proposition = store
        .get_cose_by_id(ledger.as_bytes(), affected_proposition_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("proposition object is unavailable".into()))?;
    let common_ancestor = store
        .get_cose_by_id(ledger.as_bytes(), common_ancestor_revision_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("parent revision object is unavailable".into()))?;
    let common_payload = store
        .get_payload(common_ancestor_revision_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("parent revision payload is unavailable".into()))?;
    let common_value: serde_json::Value = serde_json::from_slice(&common_payload)?;
    if common_value["body"]["proposition_id"].as_str() != Some(&affected_proposition_id.to_string())
    {
        return Err(Error::Validation(
            "parent revision belongs to a different proposition".into(),
        ));
    }

    let contributing_revision_ids = resolved_revision_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if contributing_revision_ids.len() < 2 {
        return Err(Error::Validation(
            "derived revision requires at least two distinct contributing revisions".into(),
        ));
    }

    let mut derived_dependencies = vec![
        dependency_value(&affected_proposition, "proposition")?,
        dependency_value(&common_ancestor, "parent-revision")?,
    ];
    for contributing_revision_id in &contributing_revision_ids {
        let payload = store
            .get_payload(contributing_revision_id.as_bytes())?
            .ok_or_else(|| {
                Error::MissingObject(format!(
                    "contributing revision {contributing_revision_id} is unavailable"
                ))
            })?;
        let value: serde_json::Value = serde_json::from_slice(&payload)?;
        if value["object_type"].as_str() != Some("revision")
            || value["body"]["proposition_id"].as_str()
                != Some(&affected_proposition_id.to_string())
        {
            return Err(Error::Validation(
                "contributing revision belongs to a different proposition".into(),
            ));
        }
        derived_dependencies.push(object_dependency(
            &store,
            ledger,
            *contributing_revision_id,
            "derived-from",
        )?);
    }
    dedup_dependencies(&mut derived_dependencies);

    let prior_deliberation_id = deliberation_for_revision(
        &store,
        ledger,
        affected_proposition_id,
        common_ancestor_revision_id,
    )?
    .ok_or_else(|| Error::Message("parent revision has no deliberation".into()))?;
    let participants = active_participants_for_deliberation(&store, ledger, prior_deliberation_id)?;
    let derived_revision_id = runtime.next_uuid_v7()?;
    let derived_relationships = serde_json::json!([
        {
            "relationship": "protocol:derived-from",
            "targets": contributing_revision_ids
        }
    ]);
    let derived_revision = signed_envelope(
        derived_revision_id,
        ledger,
        "revision",
        actor,
        key_id,
        serde_json::json!({
            "proposition_id": affected_proposition_id,
            "revision_id": derived_revision_id,
            "parent_revision_id": common_ancestor_revision_id,
            "content": content_value(markdown),
            "relationships": derived_relationships,
            "reconciliation_manifest": null
        }),
        derived_dependencies,
        &key,
        runtime,
    )?;
    let derived_revision_hash = dependency_hash(&derived_revision)?;
    let derived_deliberation_id = runtime.next_uuid_v7()?;
    let derived_deliberation_participants = participants
        .iter()
        .map(|actor| serde_json::json!({"actor_id": actor, "carried_decision_id": null}))
        .collect::<Vec<_>>();
    let prior_deliberation = store
        .get_cose_by_id(ledger.as_bytes(), prior_deliberation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("prior deliberation object is unavailable".into()))?;
    let derived_deliberation = signed_envelope(
        derived_deliberation_id,
        ledger,
        "deliberation",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id": derived_deliberation_id,
            "proposition_id": affected_proposition_id,
            "revision_id": derived_revision_id,
            "extends_deliberation_id": prior_deliberation_id,
            "decision_rule": {"id":"unanimity","version":0,"parameters":{}},
            "join_policy": {"policy_version":0,"mode":"open","attestation_requirements":[]},
            "initial_participants": derived_deliberation_participants,
            "roster_governance": null,
            "opening_actor_id": actor,
            "comments_closed_on_settlement": true
        }),
        vec![
            dependency_value(&affected_proposition, "proposition")?,
            serde_json::json!({"object_id":derived_revision_id,"content_hash":derived_revision_hash.hex(),"role":"revision"}),
            dependency_value(&prior_deliberation, "prior-deliberation")?,
        ],
        &key,
        runtime,
    )?;

    let mut manifest_conflicts = Vec::new();
    let mut source_deliberation_ids = Vec::new();
    let mut reconciliation_dependencies = vec![
        dependency_value(&affected_proposition, "affected-proposition")?,
        dependency_value(&common_ancestor, "common-ancestor-revision")?,
        propose_authority.clone(),
        deliberate_authority.clone(),
        serde_json::json!({"object_id":derived_revision_id,"content_hash":derived_revision_hash.hex(),"role":"result-revision"}),
    ];
    for conflict in conflicts {
        reconciliation_dependencies.push(object_dependency(
            &store,
            ledger,
            conflict.revision_id,
            "conflicting-revision",
        )?);
        reconciliation_dependencies.push(object_dependency(
            &store,
            ledger,
            conflict.deliberation_id,
            "conflicting-deliberation",
        )?);
        reconciliation_dependencies.push(object_dependency(
            &store,
            ledger,
            conflict.settlement_id,
            "supporting-settlement",
        )?);
        let settlement_payload = store
            .get_payload(conflict.settlement_id.as_bytes())?
            .ok_or_else(|| {
                Error::MissingObject(format!(
                    "settlement {} is unavailable",
                    conflict.settlement_id
                ))
            })?;
        let settlement_value: serde_json::Value = serde_json::from_slice(&settlement_payload)?;
        let settlement_body = settlement_value
            .get("body")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| Error::Validation("settlement is missing body".into()))?;
        let outcome = settlement_body
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::Validation("settlement is missing outcome".into()))?;
        source_deliberation_ids.push(conflict.deliberation_id);
        manifest_conflicts.push(serde_json::json!({
            "revision_id": conflict.revision_id,
            "deliberation_id": conflict.deliberation_id,
            "settlement_id": conflict.settlement_id,
            "outcome": outcome,
        }));
    }
    manifest_conflicts.sort_by_key(|conflict| {
        (
            conflict["revision_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            conflict["deliberation_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    });
    for tip in resolved_revision_ids {
        reconciliation_dependencies.push(object_dependency(&store, ledger, *tip, "resolved-tip")?);
    }

    let conflict_set_bytes =
        fact_canonical::encode(&serde_json::to_vec(&manifest_conflicts).map_err(Error::from)?)?;
    let conflict_set_hash = fact_core::Hash::digest(&conflict_set_bytes);
    let manifest = serde_json::json!({
        "affected_proposition_id": affected_proposition_id,
        "common_ancestor_revision_id": common_ancestor_revision_id,
        "conflicts": manifest_conflicts,
        "conflict_set_hash": conflict_set_hash.hex(),
        "detector_actor_id": actor,
        "resolution_mode": "derive",
        "selected_revision_id": null,
        "result_revision_id": derived_revision_id,
    });

    let reconciliation_proposition_id = runtime.next_uuid_v7()?;
    let reconciliation_revision_id = runtime.next_uuid_v7()?;
    let reconciliation_deliberation_id = runtime.next_uuid_v7()?;
    let reconciliation_proposition = signed_envelope(
        reconciliation_proposition_id,
        ledger,
        "proposition",
        actor,
        key_id,
        serde_json::json!({
            "proposition_id":reconciliation_proposition_id,
            "purpose":"reconciliation",
            "initial_revision_id":reconciliation_revision_id,
            "initial_deliberation_id":reconciliation_deliberation_id
        }),
        vec![propose_authority],
        &key,
        runtime,
    )?;
    let reconciliation_proposition_hash = dependency_hash(&reconciliation_proposition)?;
    let reconciliation_revision = signed_envelope(
        reconciliation_revision_id,
        ledger,
        "revision",
        actor,
        key_id,
        serde_json::json!({
            "proposition_id":reconciliation_proposition_id,
            "revision_id":reconciliation_revision_id,
            "parent_revision_id":null,
            "content":content_value(markdown),
            "relationships":[],
            "reconciliation_manifest":manifest
        }),
        vec![
            serde_json::json!({"object_id":reconciliation_proposition_id,"content_hash":reconciliation_proposition_hash.hex(),"role":"proposition"}),
            dependency_value(&affected_proposition, "affected-proposition")?,
            dependency_value(&common_ancestor, "common-ancestor-revision")?,
        ],
        &key,
        runtime,
    )?;
    let reconciliation_revision_hash = dependency_hash(&reconciliation_revision)?;
    reconciliation_dependencies.push(serde_json::json!({
        "object_id":reconciliation_proposition_id,
        "content_hash":reconciliation_proposition_hash.hex(),
        "role":"proposition"
    }));
    reconciliation_dependencies.push(serde_json::json!({
        "object_id":reconciliation_revision_id,
        "content_hash":reconciliation_revision_hash.hex(),
        "role":"revision"
    }));
    dedup_dependencies(&mut reconciliation_dependencies);
    let roster_governance = reconciliation_roster(
        &store,
        ledger,
        actor,
        deliberate_authority_id,
        &source_deliberation_ids,
    )?;
    let selected_participant_count = roster_governance
        .get("selected_participants")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    let reconciliation_participants = roster_governance
        .get("selected_participants")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flat_map(|participants| participants.iter())
        .map(|participant| {
            serde_json::json!({
                "actor_id":participant["actor_id"],
                "carried_decision_id":null
            })
        })
        .collect::<Vec<_>>();
    let reconciliation_deliberation = signed_envelope(
        reconciliation_deliberation_id,
        ledger,
        "deliberation",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id":reconciliation_deliberation_id,
            "proposition_id":reconciliation_proposition_id,
            "revision_id":reconciliation_revision_id,
            "extends_deliberation_id":null,
            "decision_rule":{"id":"unanimity","version":0,"parameters":{}},
            "join_policy":{"policy_version":0,"mode":"open","attestation_requirements":[]},
            "initial_participants": reconciliation_participants,
            "roster_governance":roster_governance,
            "opening_actor_id":actor,
            "comments_closed_on_settlement":true
        }),
        reconciliation_dependencies,
        &key,
        runtime,
    )?;

    let mut bundle = vec![
        derived_revision,
        derived_deliberation,
        reconciliation_deliberation,
        reconciliation_revision,
        reconciliation_proposition,
    ];
    bundle.append(&mut authority_objects);
    let content_hashes = store
        .insert_authorized_bundle_with_projected_mode(
            &bundle,
            fact_store::ProjectedMode::Incremental,
        )?
        .into_iter()
        .map(|hash| hash.hex())
        .collect::<Vec<_>>();
    Ok((
        derived_revision_id,
        ReconciliationResult {
            proposition_id: reconciliation_proposition_id,
            revision_id: reconciliation_revision_id,
            deliberation_id: reconciliation_deliberation_id,
            conflict_set_hash: conflict_set_hash.hex(),
            resolution_mode: "derive".to_owned(),
            selected_participant_count,
            content_hashes,
        },
    ))
}

pub fn accept_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: Option<&str>,
) -> Result<PropositionResult> {
    let runtime = production_runtime();
    accept_proposition_with_runtime(entry, seed, reference, runtime.as_ref())
}

pub fn accept_proposition_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: Option<&str>,
    runtime: &dyn SdkRuntime,
) -> Result<PropositionResult> {
    decide_proposition_with_runtime(entry, seed, reference, DecisionOutcome::Accepted, runtime)
}

pub fn reject_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: Option<&str>,
) -> Result<PropositionResult> {
    let runtime = production_runtime();
    reject_proposition_with_runtime(entry, seed, reference, runtime.as_ref())
}

pub fn reject_proposition_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: Option<&str>,
    runtime: &dyn SdkRuntime,
) -> Result<PropositionResult> {
    decide_proposition_with_runtime(entry, seed, reference, DecisionOutcome::Rejected, runtime)
}

pub fn decide_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: Option<&str>,
    outcome: DecisionOutcome,
) -> Result<PropositionResult> {
    let runtime = production_runtime();
    decide_proposition_with_runtime(entry, seed, reference, outcome, runtime.as_ref())
}

pub fn decide_proposition_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: Option<&str>,
    outcome: DecisionOutcome,
    runtime: &dyn SdkRuntime,
) -> Result<PropositionResult> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let items = pending_propositions(entry)?;
    let item = match resolve_proposition_item(&store, ledger, reference, &items) {
        Ok(item) => item,
        Err(original) => {
            if let Some(reference) = reference {
                if let Ok(candidate) = resolve_any_proposition_item(&store, ledger, reference) {
                    let metadata = indexed_metadata_for_proposition(
                        &store,
                        ledger,
                        candidate.proposition_id,
                        Some(actor),
                    )?;
                    let activity = revision_activity_from_indexed_metadata(&metadata);
                    if activity.latest_revision_status == "ambiguous" {
                        return Err(Error::Message(
                            "multiple revision tips exist; provide an unambiguous revision reference"
                                .into(),
                        ));
                    }
                    if activity.pending_revision_id.is_some()
                        && activity.pending_deliberation_id.is_none()
                    {
                        return Err(Error::Message(
                            "revision is awaiting deliberation; use an explicit deliberation repair command"
                                .into(),
                        ));
                    }
                    if activity.pending_revision_id.is_some() && !activity.current_actor_pending {
                        return Err(Error::Message(
                            "no pending action for the current actor".into(),
                        ));
                    }
                    return Err(Error::Message(
                        "proposition has no unsettled revision; its effective revision is already settled"
                            .into(),
                    ));
                }
            }
            return Err(original);
        }
    };
    let deliberation_id =
        item.pending_deliberation_id.ok_or_else(|| {
            Error::Message(if item.pending_revision_id.is_some() {
            "revision is awaiting deliberation; use an explicit deliberation repair command"
        } else {
            "proposition has no unsettled revision; its effective revision is already settled"
        }
        .into())
        })?;
    let revision_id = item.pending_revision_id.ok_or_else(|| {
        Error::Message(
            "proposition has no unsettled revision; its effective revision is already settled"
                .into(),
        )
    })?;
    let (decision_id, settlement_id, status, pending_participant_count) =
        create_decision_and_settlement(
            &store,
            ledger,
            actor,
            key_id,
            &key,
            deliberation_id,
            revision_id,
            outcome.as_status(),
            runtime,
            fact_store::ProjectedMode::Incremental,
        )?;
    Ok(PropositionResult {
        proposition_id: item.proposition_id,
        revision_id,
        deliberation_id,
        decision_id,
        settlement_id,
        status,
        summary: summary_for_revision(&store, Some(revision_id)),
        previous_revision_id: None,
        previous_revision_effective: None,
        pending_participant_count,
        content_hashes: Vec::new(),
    })
}

pub fn list_propositions(
    entry: &LedgerEntry,
    filter: ListPropositionsFilter,
) -> Result<Vec<PropositionListItem>> {
    list_propositions_page(entry, filter, None)
}

pub fn list_propositions_page(
    entry: &LedgerEntry,
    filter: ListPropositionsFilter,
    page: Option<ListPropositionsPage>,
) -> Result<Vec<PropositionListItem>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = (!entry.actor_id.is_empty())
        .then(|| parse_uuid7(&entry.actor_id, "actor"))
        .transpose()?;
    let store = fact_store::Store::open(&entry.database)?;
    let after = page
        .as_ref()
        .and_then(|page| page.after.as_deref())
        .map(|reference| resolve_proposition_cursor(&store, ledger, reference))
        .transpose()?;
    let mut items = Vec::new();
    let rows = if filter.status.is_none() && !filter.all {
        store.list_default_proposition_projecteds_page(
            ledger.as_bytes(),
            actor.as_ref().map(uuid::Uuid::as_bytes),
            after.as_ref().map(uuid::Uuid::as_bytes),
            page.as_ref().map(|page| page.offset).unwrap_or_default(),
            page.as_ref().and_then(|page| page.limit),
        )?
    } else {
        match filter.status {
            Some(ListPropositionStatus::Withdrawn) => store
                .list_lifecycle_proposition_projecteds_page(
                    ledger.as_bytes(),
                    actor.as_ref().map(uuid::Uuid::as_bytes),
                    fact_store::PropositionLifecycleFilter::Withdrawn,
                    after.as_ref().map(uuid::Uuid::as_bytes),
                    page.as_ref().map(|page| page.offset).unwrap_or_default(),
                    page.as_ref().and_then(|page| page.limit),
                )?,
            Some(ListPropositionStatus::Archived) => store
                .list_lifecycle_proposition_projecteds_page(
                    ledger.as_bytes(),
                    actor.as_ref().map(uuid::Uuid::as_bytes),
                    fact_store::PropositionLifecycleFilter::Archived,
                    after.as_ref().map(uuid::Uuid::as_bytes),
                    page.as_ref().map(|page| page.offset).unwrap_or_default(),
                    page.as_ref().and_then(|page| page.limit),
                )?,
            status => store.list_status_proposition_projecteds_page(
                ledger.as_bytes(),
                actor.as_ref().map(uuid::Uuid::as_bytes),
                status.map(search_status_name),
                after.as_ref().map(uuid::Uuid::as_bytes),
                page.as_ref().map(|page| page.offset).unwrap_or_default(),
                page.as_ref().and_then(|page| page.limit),
            )?,
        }
    };
    for row in rows {
        let status = row.status.clone();
        let show = if let Some(requested) = filter.status {
            match requested {
                ListPropositionStatus::Pending => status == "pending" || row.current_actor_pending,
                ListPropositionStatus::Accepted => status == "accepted",
                ListPropositionStatus::Rejected => status == "rejected",
                ListPropositionStatus::Contested => status == "contested" || status == "conflict",
                ListPropositionStatus::Withdrawn => row.withdrawal_status == "withdrawn",
                ListPropositionStatus::Archived => row.archival_status == "archived",
            }
        } else {
            filter.all || status == "accepted"
        };
        if !show {
            continue;
        }
        items.push(PropositionListItem {
            proposition_id: row.proposition_id,
            reference: crate::reference::short_uuid_reference(row.proposition_id),
            status,
            summary: row
                .summary_text
                .as_deref()
                .map(|text| summary_for_markdown(text.as_bytes()))
                .unwrap_or_else(|| {
                    summary_for_revision_payload(row.summary_revision_payload.as_deref())
                }),
            revision_id: row.revision_id,
            deliberation_id: row.deliberation_id,
            settlement_id: row.settlement_id,
            effective_status: row.effective_status,
            latest_revision_id: row.latest_revision_id,
            latest_revision_status: row.latest_revision_status,
            pending_revision_id: row.pending_revision_id,
            pending_deliberation_id: row.pending_deliberation_id,
            pending_participant_count: row.pending_participant_count,
            current_actor_pending: row.current_actor_pending,
            has_pending_revision: row.has_pending_revision,
        });
    }
    items.sort_by_key(|item| item.proposition_id);
    if let Some(after) = after {
        items.retain(|item| item.proposition_id > after);
    }
    Ok(items)
}

pub fn pending_propositions(entry: &LedgerEntry) -> Result<Vec<PropositionListItem>> {
    Ok(list_propositions(
        entry,
        ListPropositionsFilter {
            status: Some(ListPropositionStatus::Pending),
            all: false,
        },
    )?
    .into_iter()
    .filter(|item| item.current_actor_pending)
    .collect())
}

pub fn pending_proposition_count(entry: &LedgerEntry) -> Result<usize> {
    Ok(pending_propositions(entry)?.len())
}

pub fn read_proposition_content(entry: &LedgerEntry, reference: &str) -> Result<ResolvedContent> {
    read_proposition_content_with_selection(entry, reference, ContentSelection::Effective)
}

pub fn read_proposition_content_with_selection(
    entry: &LedgerEntry,
    reference: &str,
    selection: ContentSelection,
) -> Result<ResolvedContent> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let revision_id = match selection {
        ContentSelection::Effective => {
            if proposition_reference_matches(&store, ledger, reference)? {
                match effective_revision_for_proposition(&store, ledger, item.proposition_id)? {
                    Some(revision_id) => revision_id,
                    None => latest_revision_for_proposition(&store, ledger, item.proposition_id)?,
                }
            } else {
                match revision_for_reference(&store, ledger, item.proposition_id, reference)? {
                    Some(revision_id) => revision_id,
                    None => match effective_revision_for_proposition(
                        &store,
                        ledger,
                        item.proposition_id,
                    )? {
                        Some(revision_id) => revision_id,
                        None => {
                            latest_revision_for_proposition(&store, ledger, item.proposition_id)?
                        }
                    },
                }
            }
        }
        ContentSelection::Pending => indexed_metadata_for_proposition(
            &store,
            ledger,
            item.proposition_id,
            parse_uuid7(&entry.actor_id, "actor").ok(),
        )?
        .pending_revision_id
        .ok_or_else(|| Error::Message("proposition has no pending revision".into()))?,
        ContentSelection::Latest => {
            latest_revision_for_proposition(&store, ledger, item.proposition_id)?
        }
    };
    Ok(ResolvedContent {
        content: revision_content(&store, revision_id)?,
        revision_id,
    })
}

pub fn pending_proposition_content(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<ResolvedContent> {
    read_proposition_content_with_selection(entry, reference, ContentSelection::Pending)
}

pub fn latest_proposition_content(entry: &LedgerEntry, reference: &str) -> Result<Vec<u8>> {
    Ok(
        read_proposition_content_with_selection(entry, reference, ContentSelection::Latest)?
            .content,
    )
}
pub fn update_proposition_content(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    markdown: &[u8],
) -> Result<PropositionResult> {
    let runtime = production_runtime();
    update_proposition_content_with_runtime(entry, seed, reference, markdown, runtime.as_ref())
}

pub fn update_proposition_content_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    markdown: &[u8],
    runtime: &dyn SdkRuntime,
) -> Result<PropositionResult> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let parent_revision_id = latest_revision_for_proposition(&store, ledger, item.proposition_id)?;
    let proposition = store
        .get_cose_by_id(ledger.as_bytes(), item.proposition_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("proposition object is unavailable".into()))?;
    let parent_revision = store
        .get_cose_by_id(ledger.as_bytes(), parent_revision_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("parent revision object is unavailable".into()))?;
    let prior_deliberation_id =
        deliberation_for_revision(&store, ledger, item.proposition_id, parent_revision_id)?
            .or(item.deliberation_id)
            .ok_or_else(|| {
                Error::Message("proposition has no deliberation to carry forward".into())
            })?;
    let previous_revision_effective =
        effective_revision_for_proposition(&store, ledger, item.proposition_id)?
            == Some(parent_revision_id);
    let participants = active_participants_for_deliberation(&store, ledger, prior_deliberation_id)?;
    let propose_authority = authority_dependency_for_actor(&store, ledger, actor, "propose")?
        .ok_or_else(|| {
            Error::Authorization("active actor has no propose authority grant".into())
        })?;
    let deliberate_authority = authority_dependency_for_actor(&store, ledger, actor, "deliberate")?
        .ok_or_else(|| {
            Error::Authorization("active actor has no deliberate authority grant".into())
        })?;
    let revision_id = runtime.next_uuid_v7()?;
    let revision = signed_envelope(
        revision_id,
        ledger,
        "revision",
        actor,
        key_id,
        serde_json::json!({
            "proposition_id":item.proposition_id,
            "revision_id":revision_id,
            "parent_revision_id":parent_revision_id,
            "content":content_value(markdown),
            "relationships":[],
            "reconciliation_manifest":null
        }),
        vec![
            dependency_value(&proposition, "proposition")?,
            dependency_value(&parent_revision, "parent-revision")?,
            propose_authority,
        ],
        &key,
        runtime,
    )?;
    let deliberation_id = runtime.next_uuid_v7()?;
    let deliberation_participants = participants
        .iter()
        .map(|actor| serde_json::json!({"actor_id": actor, "carried_decision_id": null}))
        .collect::<Vec<_>>();
    let prior_deliberation = store
        .get_cose_by_id(ledger.as_bytes(), prior_deliberation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("prior deliberation object is unavailable".into()))?;
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
            "decision_rule": {"id":"unanimity","version":0,"parameters":{}},
            "join_policy": {"policy_version":0,"mode":"open","attestation_requirements":[]},
            "initial_participants": deliberation_participants,
            "roster_governance": null,
            "opening_actor_id": actor,
            "comments_closed_on_settlement": true
        }),
        vec![
            dependency_value(&proposition, "proposition")?,
            dependency_value(&revision, "revision")?,
            dependency_value(&prior_deliberation, "prior-deliberation")?,
            deliberate_authority,
        ],
        &key,
        runtime,
    )?;
    let content_hashes = store
        .insert_authorized_bundle_with_projected_mode(
            &[revision, deliberation],
            fact_store::ProjectedMode::Incremental,
        )?
        .into_iter()
        .map(|hash| hash.hex())
        .collect::<Vec<_>>();
    Ok(PropositionResult {
        proposition_id: item.proposition_id,
        revision_id,
        deliberation_id,
        decision_id: None,
        settlement_id: None,
        status: "pending".to_owned(),
        summary: summary_for_markdown(markdown),
        previous_revision_id: Some(parent_revision_id),
        previous_revision_effective: Some(previous_revision_effective),
        pending_participant_count: Some(participants.len()),
        content_hashes,
    })
}

pub fn create_derived_revision(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: DerivedRevisionInput,
) -> Result<PropositionResult> {
    let runtime = production_runtime();
    create_derived_revision_with_runtime(entry, seed, input, runtime.as_ref())
}

pub fn create_derived_revision_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: DerivedRevisionInput,
    runtime: &dyn SdkRuntime,
) -> Result<PropositionResult> {
    if input.contributing_revision_ids.len() < 2 {
        return Err(Error::Validation(
            "derived revision requires at least two contributing revisions".into(),
        ));
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let proposition = store
        .get_cose_by_id(ledger.as_bytes(), input.proposition_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("proposition object is unavailable".into()))?;
    let parent_revision = store
        .get_cose_by_id(ledger.as_bytes(), input.parent_revision_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("parent revision object is unavailable".into()))?;
    let parent_payload = store
        .get_payload(input.parent_revision_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("parent revision payload is unavailable".into()))?;
    let parent_value: serde_json::Value = serde_json::from_slice(&parent_payload)?;
    if parent_value["body"]["proposition_id"].as_str() != Some(&input.proposition_id.to_string()) {
        return Err(Error::Validation(
            "parent revision belongs to a different proposition".into(),
        ));
    }
    let contributing_revision_ids = input
        .contributing_revision_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if contributing_revision_ids.len() < 2 {
        return Err(Error::Validation(
            "derived revision requires at least two distinct contributing revisions".into(),
        ));
    }
    let mut dependencies = vec![
        dependency_value(&proposition, "proposition")?,
        dependency_value(&parent_revision, "parent-revision")?,
    ];
    for contributing_revision_id in &contributing_revision_ids {
        let payload = store
            .get_payload(contributing_revision_id.as_bytes())?
            .ok_or_else(|| {
                Error::MissingObject(format!(
                    "contributing revision {contributing_revision_id} is unavailable"
                ))
            })?;
        let value: serde_json::Value = serde_json::from_slice(&payload)?;
        if value["object_type"].as_str() != Some("revision")
            || value["body"]["proposition_id"].as_str() != Some(&input.proposition_id.to_string())
        {
            return Err(Error::Validation(
                "contributing revision belongs to a different proposition".into(),
            ));
        }
        dependencies.push(object_dependency(
            &store,
            ledger,
            *contributing_revision_id,
            "derived-from",
        )?);
    }
    dedup_dependencies(&mut dependencies);
    let prior_deliberation_id = deliberation_for_revision(
        &store,
        ledger,
        input.proposition_id,
        input.parent_revision_id,
    )?
    .ok_or_else(|| Error::Message("parent revision has no deliberation".into()))?;
    let participants = active_participants_for_deliberation(&store, ledger, prior_deliberation_id)?;
    let revision_id = runtime.next_uuid_v7()?;
    let relationships = serde_json::json!([
        {
            "relationship": "protocol:derived-from",
            "targets": contributing_revision_ids
        }
    ]);
    let revision = signed_envelope(
        revision_id,
        ledger,
        "revision",
        actor,
        key_id,
        serde_json::json!({
            "proposition_id": input.proposition_id,
            "revision_id": revision_id,
            "parent_revision_id": input.parent_revision_id,
            "content": content_value(&input.markdown),
            "relationships": relationships,
            "reconciliation_manifest": null
        }),
        dependencies,
        &key,
        runtime,
    )?;
    let revision_hash = dependency_hash(&revision)?;
    let deliberation_id = runtime.next_uuid_v7()?;
    let deliberation_participants = participants
        .iter()
        .map(|actor| serde_json::json!({"actor_id": actor, "carried_decision_id": null}))
        .collect::<Vec<_>>();
    let prior_deliberation = store
        .get_cose_by_id(ledger.as_bytes(), prior_deliberation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("prior deliberation object is unavailable".into()))?;
    let deliberation = signed_envelope(
        deliberation_id,
        ledger,
        "deliberation",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id": deliberation_id,
            "proposition_id": input.proposition_id,
            "revision_id": revision_id,
            "extends_deliberation_id": prior_deliberation_id,
            "decision_rule": {"id":"unanimity","version":0,"parameters":{}},
            "join_policy": {"policy_version":0,"mode":"open","attestation_requirements":[]},
            "initial_participants": deliberation_participants,
            "roster_governance": null,
            "opening_actor_id": actor,
            "comments_closed_on_settlement": true
        }),
        vec![
            dependency_value(&proposition, "proposition")?,
            serde_json::json!({"object_id":revision_id,"content_hash":revision_hash.hex(),"role":"revision"}),
            dependency_value(&prior_deliberation, "prior-deliberation")?,
        ],
        &key,
        runtime,
    )?;
    let content_hashes = store
        .insert_authorized_bundle_with_projected_mode(
            &[revision, deliberation],
            fact_store::ProjectedMode::Incremental,
        )?
        .into_iter()
        .map(|hash| hash.hex())
        .collect::<Vec<_>>();
    Ok(PropositionResult {
        proposition_id: input.proposition_id,
        revision_id,
        deliberation_id,
        decision_id: None,
        settlement_id: None,
        status: "pending".to_owned(),
        summary: summary_for_markdown(&input.markdown),
        previous_revision_id: Some(input.parent_revision_id),
        previous_revision_effective: None,
        pending_participant_count: Some(participants.len()),
        content_hashes,
    })
}

pub fn search_proposition_content(
    entry: &LedgerEntry,
    text: &str,
    status: Option<ListPropositionStatus>,
    effective: bool,
    page_size: usize,
) -> Result<Vec<SearchResult>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    if page_size == 0 {
        return Ok(Vec::new());
    }
    let candidate_limit = page_size.saturating_mul(100).max(page_size);
    let status_filter = status.map(search_status_name);
    let ranked_hits = if !effective && status_filter.is_none() {
        store.search_markdown_index_by_type(
            ledger.as_bytes(),
            text,
            candidate_limit,
            &["revision", "deliberation_comment"],
        )?
    } else {
        store.search_markdown_index_by_type(
            ledger.as_bytes(),
            text,
            candidate_limit,
            &["revision"],
        )?
    };
    let mut revision_hit_ids = Vec::new();
    let mut seen_revision_hit_ids = HashSet::new();
    for hit in &ranked_hits {
        if hit.object_type == "revision" && seen_revision_hit_ids.insert(hit.object_id) {
            revision_hit_ids.push(hit.object_id);
        }
    }
    let revision_metadata = store
        .effective_revision_search_rows(ledger.as_bytes(), &revision_hit_ids)?
        .into_iter()
        .map(|row| (row.revision_id, (row.proposition_id, row.status)))
        .collect::<HashMap<_, _>>();
    let mut results = Vec::new();
    for ranked in ranked_hits {
        let item_revision_metadata = if ranked.object_type == "revision" {
            let Some((proposition_id, status)) = revision_metadata.get(&ranked.object_id) else {
                continue;
            };
            if status_filter.is_some_and(|expected| status != expected) {
                continue;
            }
            Some((*proposition_id, status.clone()))
        } else if ranked.object_type == "deliberation_comment"
            && !effective
            && status_filter.is_none()
        {
            None
        } else {
            continue;
        };

        let Some(row) =
            store.object_payload_by_id(ledger.as_bytes(), ranked.object_id.as_bytes())?
        else {
            continue;
        };
        let proposition_id = item_revision_metadata
            .as_ref()
            .map(|(proposition_id, _)| *proposition_id);
        let status = item_revision_metadata
            .as_ref()
            .map(|(_, status)| status.clone());
        let is_effective = item_revision_metadata.is_some();
        results.push(SearchResult {
            object_id: row.object_id,
            reference: proposition_id
                .map(crate::reference::short_uuid_reference)
                .unwrap_or_else(|| crate::reference::short_uuid_reference(row.object_id)),
            content_hash: ranked.content_hash.hex(),
            score: ranked.score,
            summary: serde_json::from_slice::<serde_json::Value>(&row.payload)
                .ok()
                .and_then(|value| {
                    value["body"]["content"]["bytes"]
                        .as_str()
                        .and_then(decode_b64url)
                })
                .map(|bytes| summary_for_markdown(&bytes))
                .unwrap_or_else(|| "No summary".to_owned()),
            proposition_id,
            status,
            effective: is_effective,
        });
        if results.len() >= page_size {
            break;
        }
    }
    Ok(results)
}

pub fn find_propositions(entry: &LedgerEntry, text: &str) -> Result<Vec<SearchResult>> {
    search_proposition_content(entry, text, Some(ListPropositionStatus::Accepted), true, 20)
}

pub fn display_status(item: &PropositionListItem) -> String {
    if item.has_pending_revision {
        if item.effective_status == "accepted" {
            "accepted, update pending".to_owned()
        } else {
            format!("{}, update pending", item.effective_status)
        }
    } else {
        item.effective_status.clone()
    }
}

pub fn list_revisions(entry: &LedgerEntry, reference: &str) -> Result<Vec<serde_json::Value>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = (!entry.actor_id.is_empty())
        .then(|| parse_uuid7(&entry.actor_id, "actor"))
        .transpose()?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let metadata = indexed_metadata_for_proposition(&store, ledger, item.proposition_id, actor)?;
    let effective_revision = metadata.effective_revision_id;
    let revisions = store.list_revision_projecteds_by_proposition(
        ledger.as_bytes(),
        item.proposition_id.as_bytes(),
    )?;
    let child_counts = revisions
        .iter()
        .filter_map(|revision| revision.parent_revision_id)
        .fold(
            BTreeMap::<uuid::Uuid, usize>::new(),
            |mut counts, parent| {
                *counts.entry(parent).or_default() += 1;
                counts
            },
        );
    let activity = revision_activity_from_indexed_metadata(&metadata);
    let effective_status = Some(metadata.status.clone());
    Ok(revisions
        .into_iter()
        .map(|revision| {
            let object_id = revision.revision_id;
            let tip = !child_counts.contains_key(&object_id);
            let revision_status = if effective_revision == Some(object_id) {
                effective_status.clone().unwrap_or_else(|| "effective".to_owned())
            } else if tip {
                activity.latest_revision_status.clone()
            } else {
                "superseded".to_owned()
            };
            let value = serde_json::from_slice::<serde_json::Value>(&revision.payload)
                .unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "object_id":object_id,
                "reference":crate::reference::short_uuid_reference(object_id),
                "object_type":"revision",
                "content_hash":revision.content_hash.hex(),
                "created_at":value["created_at"],
                "actor_id":value["actor_id"],
                "parent_revision_id":revision.parent_revision_id,
                "effective":effective_revision == Some(object_id),
                "tip":tip,
                "status":revision_status,
                "latest":activity.latest_revision_id == Some(object_id),
                "pending_deliberation_id":if activity.pending_revision_id == Some(object_id) { activity.pending_deliberation_id } else { None },
                "pending_participant_count":if activity.pending_revision_id == Some(object_id) { activity.pending_participant_count } else { 0 },
                "current_actor_pending":if activity.pending_revision_id == Some(object_id) { activity.current_actor_pending } else { false },
                "child_count":child_counts.get(&object_id).copied().unwrap_or(0),
                "summary":value["body"]["content"]["bytes"].as_str().and_then(decode_b64url).map(|bytes| summary_for_markdown(&bytes)).unwrap_or_else(|| "No summary".to_owned())
            })
        })
        .collect())
}

pub fn list_revision_conflicts(
    entry: &LedgerEntry,
    reference: Option<&str>,
    all: bool,
) -> Result<Vec<RevisionConflictGroup>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = (!entry.actor_id.is_empty())
        .then(|| parse_uuid7(&entry.actor_id, "actor"))
        .transpose()?;
    let store = fact_store::Store::open(&entry.database)?;
    let referenced_revision = reference
        .map(|reference| resolve_revision_reference(&store, ledger, reference))
        .transpose()?
        .flatten();
    let propositions = if let Some(reference) = reference {
        vec![resolve_any_proposition_item(&store, ledger, reference)?]
    } else {
        list_propositions_page(
            entry,
            ListPropositionsFilter {
                status: None,
                all: true,
            },
            Some(ListPropositionsPage {
                offset: 0,
                limit: None,
                after: None,
            }),
        )?
    };
    let mut groups = Vec::new();
    for proposition in propositions {
        if let Some(group) = revision_conflict_group_for_proposition(
            &store,
            ledger,
            actor,
            &proposition,
            all,
            referenced_revision,
        )? {
            groups.push(group);
        }
    }
    groups.sort_by(|left, right| {
        left.proposition_id
            .cmp(&right.proposition_id)
            .then(left.status.cmp(&right.status))
    });
    Ok(groups)
}

pub fn inspect_proposition(entry: &LedgerEntry, reference: &str) -> Result<serde_json::Value> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let payload = store
        .get_payload(item.proposition_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("proposition is not present in the ledger".into()))?;
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    let metadata = indexed_metadata_for_proposition(&store, ledger, item.proposition_id, None)?;
    let activity = revision_activity_from_indexed_metadata(&metadata);
    let revisions = related_revisions_for_proposition(&store, ledger, item.proposition_id)?;
    let deliberations = related_deliberations_for_proposition(&store, ledger, item.proposition_id)?;
    Ok(serde_json::json!({
        "proposition":value,
        "effective_state":{
            "proposition_id": metadata.proposition_id,
            "status": metadata.status,
            "revision_id": metadata.effective_revision_id,
            "deliberation_id": metadata.effective_deliberation_id,
            "settlement_id": metadata.settlement_id,
            "withdrawal_status": metadata.withdrawal_status,
            "archival_status": metadata.archival_status
        },
        "revision_state": {
            "effective_status": metadata.status,
            "effective_revision": metadata.effective_revision_id,
            "latest_revision": activity.latest_revision_id,
            "latest_revision_status": activity.latest_revision_status,
            "pending_revision": activity.pending_revision_id,
            "pending_deliberation": activity.pending_deliberation_id,
            "pending_participant_count": activity.pending_participant_count,
            "current_actor_pending": activity.current_actor_pending,
            "has_pending_revision": activity.has_pending_revision
        },
        "revisions":revisions,
        "deliberations":deliberations,
        "comments":list_comments_for_proposition_as_values(&store, ledger, item.proposition_id, None)?
    }))
}

pub fn list_deliberations(entry: &LedgerEntry, reference: &str) -> Result<Vec<serde_json::Value>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    store
        .list_deliberation_projecteds_by_proposition(
            ledger.as_bytes(),
            item.proposition_id.as_bytes(),
        )?
        .into_iter()
        .map(|row| {
            let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
            Ok(serde_json::json!({
                "object_id": row.deliberation_id,
                "reference": crate::reference::short_uuid_reference(row.deliberation_id),
                "object_type": "deliberation",
                "content_hash": row.content_hash.hex(),
                "created_at": value["created_at"],
                "actor_id": value["actor_id"],
                "body": value["body"],
            }))
        })
        .collect()
}

pub fn list_comments(
    entry: &LedgerEntry,
    reference: &str,
    revision: Option<uuid::Uuid>,
) -> Result<Vec<serde_json::Value>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    list_comments_for_proposition_as_values(&store, ledger, item.proposition_id, revision)
}

pub fn show_proposition_overview(
    entry: &LedgerEntry,
    input: ShowOverviewInput,
) -> Result<ShowOverview> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = (!entry.actor_id.is_empty())
        .then(|| parse_uuid7(&entry.actor_id, "actor"))
        .transpose()?;
    let store = fact_store::Store::open(&entry.database)?;
    let proposition = resolve_any_proposition_item(&store, ledger, &input.reference)?;
    let metadata =
        indexed_metadata_for_proposition(&store, ledger, proposition.proposition_id, actor)?;
    let matched =
        matched_show_object(&store, ledger, &input.reference, proposition.proposition_id)?;

    let mut revisions = list_revisions(entry, &proposition.reference)?;
    revisions.sort_by(|left, right| {
        right["created_at"]
            .as_str()
            .cmp(&left["created_at"].as_str())
            .then_with(|| right["object_id"].as_str().cmp(&left["object_id"].as_str()))
    });
    let revisions_total = revisions.len();
    mark_highlighted(&mut revisions, matched.object_id);
    enrich_actor_fields(&store, ledger, &mut revisions)?;
    if let Some(limit) = input.revision_limit {
        revisions.truncate(limit);
    }

    let effective_revision = metadata
        .effective_revision_id
        .and_then(|revision_id| {
            revisions
                .iter()
                .find(|revision| json_uuid(&revision["object_id"]) == Some(revision_id))
                .cloned()
        })
        .or_else(|| {
            metadata.effective_revision_id.and_then(|revision_id| {
                let mut all_revisions = list_revisions(entry, &proposition.reference).ok()?;
                enrich_actor_fields(&store, ledger, &mut all_revisions).ok()?;
                all_revisions
                    .into_iter()
                    .find(|revision| json_uuid(&revision["object_id"]) == Some(revision_id))
            })
        });

    let mut comments =
        list_comments_for_proposition_as_values(&store, ledger, proposition.proposition_id, None)?;
    let comments_total = comments.len();
    mark_highlighted(&mut comments, matched.object_id);
    enrich_actor_fields(&store, ledger, &mut comments)?;
    if let Some(limit) = input.comments_limit {
        if comments.len() > limit {
            comments = comments.split_off(comments.len() - limit);
        }
    }

    let mut deliberations = list_deliberations(entry, &proposition.reference)?;
    mark_highlighted(&mut deliberations, matched.object_id);
    if input.include_participants {
        for deliberation in &mut deliberations {
            let Some(deliberation_id) = json_uuid(&deliberation["object_id"]) else {
                continue;
            };
            let participants =
                active_participants_for_deliberation(&store, ledger, deliberation_id)?
                    .into_iter()
                    .filter_map(|actor_id| uuid::Uuid::parse_str(&actor_id).ok())
                    .map(|actor_id| actor_reference_value(&store, ledger, actor_id))
                    .collect::<Result<Vec<_>>>()?;
            deliberation["participants"] = serde_json::Value::Array(participants);
        }
    }

    let conflicts = list_revision_conflicts(
        entry,
        Some(&proposition.reference),
        input.include_conflicts_all,
    )?;
    let tags = crate::tags::show_tags(entry, &proposition.reference)?.tags;
    let content = if input.include_content {
        Some(
            String::from_utf8_lossy(
                &read_proposition_content(entry, &proposition.reference)?.content,
            )
            .into_owned(),
        )
    } else {
        None
    };
    let history_limit = input.history_limit;
    let (history, history_total) = if input.include_history {
        let requested_limit = history_limit.map(|limit| limit.saturating_add(1));
        let mut all_history = history_ledger_page(
            entry,
            Some(&proposition.reference),
            Some(HistoryPage {
                after: None,
                limit: requested_limit,
            }),
        )?;
        let total = all_history.len();
        if let Some(limit) = history_limit {
            all_history.truncate(limit);
        }
        (all_history, total)
    } else {
        (Vec::new(), 0)
    };
    let actions = if proposition.current_actor_pending {
        vec![
            serde_json::json!({
                "action":"accept",
                "command":format!("fact accept {}", proposition.reference),
                "revision_id":proposition.pending_revision_id,
                "deliberation_id":proposition.pending_deliberation_id
            }),
            serde_json::json!({
                "action":"reject",
                "command":format!("fact reject {}", proposition.reference),
                "revision_id":proposition.pending_revision_id,
                "deliberation_id":proposition.pending_deliberation_id
            }),
        ]
    } else {
        Vec::new()
    };
    let next = if !conflicts.is_empty() {
        vec![serde_json::json!({
            "label":"resolve revision conflicts",
            "command":format!("fact resolve {}", proposition.reference)
        })]
    } else if actions.is_empty() {
        vec![serde_json::json!({
            "label":"no pending actions for you",
            "command":serde_json::Value::Null
        })]
    } else {
        actions
            .iter()
            .map(|action| {
                serde_json::json!({
                    "label":format!("{} proposition", action["action"].as_str().unwrap_or("decide")),
                    "command":action["command"]
                })
            })
            .collect()
    };

    Ok(ShowOverview {
        query: input.reference,
        matched,
        proposition,
        effective_revision,
        content,
        content_included: input.include_content,
        tags,
        conflicts,
        pending: ShowPendingOverview {
            current_actor_pending: metadata.current_actor_pending,
            actions,
        },
        revisions,
        deliberations,
        comments,
        history,
        next,
        page: ShowOverviewPage {
            revisions_limit: input.revision_limit,
            comments_limit: input.comments_limit,
            history_limit,
            revisions_truncated: input
                .revision_limit
                .is_some_and(|limit| revisions_total > limit),
            comments_truncated: input
                .comments_limit
                .is_some_and(|limit| comments_total > limit),
            history_truncated: input
                .history_limit
                .is_some_and(|limit| history_total > limit),
        },
    })
}

pub fn history_ledger(entry: &LedgerEntry, reference: Option<&str>) -> Result<Vec<HistoryItem>> {
    history_ledger_page(entry, reference, None)
}

pub fn history_ledger_page(
    entry: &LedgerEntry,
    reference: Option<&str>,
    page: Option<HistoryPage>,
) -> Result<Vec<HistoryItem>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let proposition = reference
        .map(|value| resolve_any_proposition_item(&store, ledger, value))
        .transpose()?
        .map(|item| item.proposition_id);
    let after = page
        .as_ref()
        .and_then(|page| page.after.as_deref())
        .map(|value| {
            value
                .parse::<fact_core::Hash>()
                .map_err(|error| Error::Validation(format!("invalid history cursor: {error}")))
        })
        .transpose()?;
    let limit = page
        .as_ref()
        .and_then(|page| page.limit)
        .filter(|limit| *limit != 0);
    let objects = if let Some(proposition_id) = proposition {
        let mut objects = scoped_history_objects(&store, ledger, proposition_id)?;
        if let Some(after) = after {
            objects.retain(|(_, hash, _, _)| *hash > after);
        }
        if let Some(limit) = limit {
            objects.truncate(limit);
        }
        objects
    } else if let Some(limit) = limit {
        store
            .list_object_payloads_page(ledger.as_bytes(), after.as_ref(), limit)?
            .into_iter()
            .map(|row| {
                let value =
                    serde_json::from_slice::<serde_json::Value>(&row.payload).unwrap_or_default();
                (row.object_id, row.content_hash, row.object_type, value)
            })
            .collect()
    } else {
        store
            .list_object_payloads(ledger.as_bytes())?
            .into_iter()
            .map(|row| {
                let value =
                    serde_json::from_slice::<serde_json::Value>(&row.payload).unwrap_or_default();
                (row.object_id, row.content_hash, row.object_type, value)
            })
            .collect()
    };
    Ok(objects
        .into_iter()
        .map(|(object_id, hash, object_type, value)| {
            let actor_id = value["actor_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok());
            let signing_key_id = value["signing_key_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok());
            let actor_display = actor_id.and_then(|id| {
                store
                    .get_projected_directory_by_actor(ledger.as_bytes(), id.as_bytes())
                    .ok()
                    .flatten()
                    .map(|row| row.display_name)
            });
            HistoryItem {
                reference: crate::reference::short_uuid_reference(object_id),
                object_id,
                object_type,
                content_hash: hash.hex(),
                created_at: value["created_at"].as_str().unwrap_or_default().to_owned(),
                actor_id,
                actor_display,
                signing_key_id,
                key_display: signing_key_id
                    .map(|id| format!("key {}", crate::reference::short_uuid_reference(id))),
                description: object_description(&value),
            }
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn create_decision_and_settlement(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor: uuid::Uuid,
    key_id: uuid::Uuid,
    key: &fact_crypto::SigningKey,
    deliberation_id: uuid::Uuid,
    revision_id: uuid::Uuid,
    outcome: &str,
    runtime: &dyn SdkRuntime,
    projected_mode: fact_store::ProjectedMode,
) -> Result<DecisionSettlementResult> {
    let deliberation = store
        .get_cose_by_id(ledger.as_bytes(), deliberation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("deliberation is unavailable".into()))?;
    let (decision_authority, generated_authority) =
        decision_authority_for_actor(store, ledger, actor, key_id, key, outcome, runtime)?;
    let authorization_ref = decision_authority["object_id"].clone();
    let mut decision_dependencies = vec![
        dependency_value(&deliberation, "deliberation")?,
        decision_authority,
    ];
    decision_dependencies.extend(deliberation_participant_change_dependencies(
        store,
        ledger,
        deliberation_id,
    )?);
    dedup_dependencies(&mut decision_dependencies);
    let decision_id = runtime.next_uuid_v7()?;
    let decision = signed_envelope(
        decision_id,
        ledger,
        "decision",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id":deliberation_id,
            "participant_actor_id":actor,
            "value":outcome,
            "supersedes_decision_ids":[],
            "authorization_ref":authorization_ref
        }),
        decision_dependencies,
        key,
        runtime,
    )?;
    if generated_authority.is_empty() {
        store.insert_authorized_object_with_projected_mode(&decision, projected_mode)?;
    } else {
        let mut bundle = generated_authority;
        bundle.push(decision.clone());
        store.insert_authorized_bundle_with_projected_mode(&bundle, projected_mode)?;
    }
    let participants =
        active_participant_ids_for_settlement(store, ledger, deliberation_id, &deliberation)?;
    let decisions = canonical_decisions_for_deliberation(store, ledger, deliberation_id)?;
    let decided_participants = decisions
        .iter()
        .map(|decision| decision.participant_actor_id)
        .collect::<HashSet<_>>();
    let pending_count = participants
        .iter()
        .filter(|participant| !decided_participants.contains(participant))
        .count();
    if pending_count > 0 {
        return Ok((
            Some(decision_id),
            None,
            "pending".to_owned(),
            Some(pending_count),
        ));
    }
    let active_participants = participants.into_iter().collect::<HashSet<_>>();
    let mut decisions = decisions;
    decisions.retain(|decision| active_participants.contains(&decision.participant_actor_id));
    decisions.sort_by_key(|decision| (decision.participant_actor_id, decision.decision_id));
    let accepted_count = decisions
        .iter()
        .filter(|decision| decision.value == "accepted")
        .count();
    let rejected_count = decisions
        .iter()
        .filter(|decision| decision.value == "rejected")
        .count();
    let final_status = if rejected_count == 0 {
        "accepted"
    } else {
        "rejected"
    };
    let decision_refs = decisions
        .iter()
        .map(|decision| {
            serde_json::json!({
                "decision_id":decision.decision_id,
                "content_hash":decision.content_hash.hex(),
                "participant_actor_id":decision.participant_actor_id
            })
        })
        .collect::<Vec<_>>();
    let settlement_point = decisions
        .last()
        .ok_or_else(|| Error::Conflict("settlement requires at least one decision".into()))?;
    let settlement_id = runtime.next_uuid_v7()?;
    let mut dependencies = vec![dependency_value(&deliberation, "deliberation")?];
    for decision in &decisions {
        dependencies.push(dependency_value(&decision.cose, "decision")?);
    }
    let settlement = signed_envelope(
        settlement_id,
        ledger,
        "settlement",
        actor,
        key_id,
        serde_json::json!({
            "deliberation_id":deliberation_id,
            "revision_id":revision_id,
            "decision_rule":{"id":"unanimity","version":0,"parameters":{}},
            "decision_refs":decision_refs,
            "participant_count":active_participants.len(),
            "decided_count":decisions.len(),
            "accepted_count":accepted_count,
            "rejected_count":rejected_count,
            "outcome":final_status,
            "causal_settlement_point":{"object_id":settlement_point.decision_id,"content_hash":settlement_point.content_hash.hex(),"role":"decision"},
            "producer_type":"participant",
            "producer_id":actor
        }),
        dependencies,
        key,
        runtime,
    )?;
    store.insert_authorized_object_with_projected_mode(&settlement, projected_mode)?;
    Ok((
        Some(decision_id),
        Some(settlement_id),
        final_status.to_owned(),
        Some(0),
    ))
}

fn decision_authority_for_actor(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor: uuid::Uuid,
    key_id: uuid::Uuid,
    key: &fact_crypto::SigningKey,
    outcome: &str,
    runtime: &dyn SdkRuntime,
) -> Result<(serde_json::Value, Vec<Vec<u8>>)> {
    let capability = match outcome {
        "accepted" => "accept",
        "rejected" => "reject",
        _ => {
            return Err(Error::Validation(format!(
                "unsupported decision outcome {outcome:?}"
            )))
        }
    };
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

fn deliberation_participant_change_dependencies(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberation_id: uuid::Uuid,
) -> Result<Vec<serde_json::Value>> {
    store
        .list_objects_by_deliberation(
            ledger.as_bytes(),
            deliberation_id.as_bytes(),
            "deliberation_participant_change",
        )?
        .into_iter()
        .map(|row| object_dependency(store, ledger, row.object_id, "participant-change"))
        .collect()
}

fn propose_authority_for_actor(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor: uuid::Uuid,
    key_id: uuid::Uuid,
    key: &fact_crypto::SigningKey,
    runtime: &dyn SdkRuntime,
) -> Result<(serde_json::Value, Vec<Vec<u8>>, bool)> {
    if let Some(authority) = authority_dependency_for_actor(store, ledger, actor, "propose")? {
        return Ok((authority, Vec::new(), false));
    }
    let Some(admin_authority) = authority_dependency_for_actor(store, ledger, actor, "admin")?
    else {
        return Err(Error::MissingObject(format!(
            "actor {actor} has no propose authority on ledger {ledger}"
        )));
    };
    let propose_grant_id = runtime.next_uuid_v7()?;
    let propose_grant = signed_envelope(
        propose_grant_id,
        ledger,
        "authorization_grant",
        actor,
        key_id,
        serde_json::json!({
            "grant_id":propose_grant_id,
            "granting_actor_id":actor,
            "receiving_actor_id":actor,
            "capabilities":["accept","archive","comment","deliberate","invite","propose","reject","withdraw"],
            "scope":{"type":"ledger"},"validity":null,"constraints":{},"predecessor_grant_id":null
        }),
        vec![admin_authority],
        key,
        runtime,
    )?;
    let propose_grant_hash = dependency_hash(&propose_grant)?;
    Ok((
        serde_json::json!({
            "object_id":propose_grant_id,
            "content_hash":propose_grant_hash.hex(),
            "role":"propose-authority"
        }),
        vec![propose_grant],
        true,
    ))
}

fn deliberate_authority_for_actor(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor: uuid::Uuid,
    generated_all_capability_authority: Option<&serde_json::Value>,
) -> Result<serde_json::Value> {
    if let Some(authority) = authority_dependency_for_actor(store, ledger, actor, "deliberate")? {
        return Ok(authority);
    }
    if let Some(authority) = generated_all_capability_authority {
        return Ok(authority.clone());
    }
    Err(Error::MissingObject(format!(
        "actor {actor} has no deliberate authority on ledger {ledger}"
    )))
}

fn object_dependency(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    object_id: uuid::Uuid,
    role: &str,
) -> Result<serde_json::Value> {
    let cose = store
        .get_cose_by_id(ledger.as_bytes(), object_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject(format!("object {object_id} is unavailable")))?;
    dependency_value(&cose, role)
}

fn parse_reconciliation_conflict_triple(triple: &str) -> Result<ReconciliationConflictInput> {
    let parts = triple.split(':').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(Error::Validation(format!(
            "conflict input must be REVISION:DELIBERATION:SETTLEMENT, got {triple:?}"
        )));
    }
    Ok(ReconciliationConflictInput {
        revision_id: parse_uuid7(parts[0], "conflict revision")?,
        deliberation_id: parse_uuid7(parts[1], "conflict deliberation")?,
        settlement_id: parse_uuid7(parts[2], "conflict settlement")?,
    })
}

fn dedup_dependencies(dependencies: &mut Vec<serde_json::Value>) {
    let mut seen = BTreeSet::new();
    dependencies.retain(|dependency| {
        dependency
            .get("object_id")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|id| seen.insert(id.to_string()))
    });
}

fn reconciliation_roster(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor: uuid::Uuid,
    authorization_ref: uuid::Uuid,
    source_deliberation_ids: &[uuid::Uuid],
) -> Result<serde_json::Value> {
    let mut candidates = BTreeMap::<uuid::Uuid, Vec<serde_json::Value>>::new();
    let mut source_ids = source_deliberation_ids.to_vec();
    source_ids.sort();
    source_ids.dedup();
    for source_id in &source_ids {
        let source_cose = store
            .get_cose_by_id(ledger.as_bytes(), source_id.as_bytes())?
            .ok_or_else(|| {
                Error::MissingObject(format!("deliberation {source_id} is unavailable"))
            })?;
        let source_hash = dependency_hash(&source_cose)?;
        let source_value: serde_json::Value =
            serde_json::from_slice(&fact_crypto::decode_sign1(&source_cose)?.payload)?;
        if source_value["object_type"].as_str() != Some("deliberation") {
            return Err(Error::Validation(
                "reconciliation source is not a deliberation".into(),
            ));
        }
        for participant in source_value["body"]["initial_participants"]
            .as_array()
            .ok_or_else(|| Error::Validation("deliberation is missing participants".into()))?
        {
            let participant_id = participant["actor_id"]
                .as_str()
                .ok_or_else(|| Error::Validation("participant is missing actor_id".into()))?
                .parse::<uuid::Uuid>()?;
            candidates
                .entry(participant_id)
                .or_default()
                .push(serde_json::json!({
                    "deliberation_id": source_id,
                    "membership_evidence": [{
                        "object_id": source_id,
                        "content_hash": source_hash.hex()
                    }]
                }));
        }
    }
    let candidate_union = candidates
        .iter()
        .map(|(actor_id, memberships)| {
            serde_json::json!({
                "actor_id": actor_id,
                "source_memberships": memberships,
            })
        })
        .collect::<Vec<_>>();
    let selected_participants = candidates
        .iter()
        .map(|(actor_id, memberships)| {
            serde_json::json!({
                "actor_id": actor_id,
                "selection_basis": "source_union",
                "source_deliberation_ids": memberships
                    .iter()
                    .map(|membership| membership["deliberation_id"].clone())
                    .collect::<Vec<_>>(),
                "admission_evidence": []
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "schema_version": 0,
        "selection_mode": "union_eligible",
        "source_deliberation_ids": source_ids,
        "candidate_union": candidate_union,
        "selected_participants": selected_participants,
        "excluded_candidates": [],
        "selection_authority": {
            "actor_id": actor,
            "authorization_ref": authorization_ref
        }
    }))
}

pub(crate) fn authority_dependency_for_actor(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor: uuid::Uuid,
    capability: &str,
) -> Result<Option<serde_json::Value>> {
    let mut matches = Vec::new();
    for row in
        store.list_authority_grant_payloads(ledger.as_bytes(), actor.as_bytes(), capability)?
    {
        let cose = store
            .get_cose_by_id(ledger.as_bytes(), row.object_id.as_bytes())?
            .ok_or_else(|| {
                Error::MissingObject("authorization grant object is unavailable".into())
            })?;
        matches.push((row.object_id, dependency_hash(&cose)?));
    }
    matches.sort_by_key(|(id, _)| *id);
    let Some((id, hash)) = matches.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(serde_json::json!({
        "object_id":id,
        "content_hash":hash.hex(),
        "role":format!("{capability}-authority")
    })))
}

fn resolve_proposition_item(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    reference: Option<&str>,
    pending: &[PropositionListItem],
) -> Result<PropositionListItem> {
    if reference.is_none() {
        return match pending {
            [item] => Ok(item.clone()),
            [] => Err(Error::Message("no unambiguous pending proposition".into())),
            _ => Err(Error::Message(
                "multiple pending propositions; provide a reference".into(),
            )),
        };
    }
    let reference = reference.unwrap();
    let reference_matches = store.resolve_object_reference(
        ledger.as_bytes(),
        reference,
        &["proposition", "revision"],
    )?;
    let matches = pending
        .iter()
        .filter(|item| {
            reference_matches.iter().any(|reference_match| {
                (reference_match.object_type == "proposition"
                    && reference_match.object_id == item.proposition_id)
                    || (reference_match.object_type == "revision"
                        && item.pending_revision_id == Some(reference_match.object_id))
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [item] => Ok(item.clone()),
        [] => Err(Error::Message(format!(
            "no pending proposition matches reference {reference}"
        ))),
        _ => Err(Error::AmbiguousReference(reference.to_owned())),
    }
}

pub(crate) fn resolve_any_proposition_item(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    reference: &str,
) -> Result<PropositionListItem> {
    let mut proposition_ids = BTreeSet::new();
    for reference_match in store.resolve_object_reference(ledger.as_bytes(), reference, &[])? {
        if reference_match.object_type == "proposition" {
            proposition_ids.insert(reference_match.object_id);
            continue;
        }
        if reference_match.object_type == "revision" {
            if let Some(proposition) =
                store.proposition_id_for_revision(reference_match.object_id.as_bytes())?
            {
                proposition_ids.insert(proposition);
            }
            continue;
        }
        if reference_match.object_type == "deliberation" {
            if let Some(proposition) =
                store.proposition_id_for_deliberation(reference_match.object_id.as_bytes())?
            {
                proposition_ids.insert(proposition);
            }
            continue;
        }
        let Some(payload) = store.get_payload(reference_match.object_id.as_bytes())? else {
            continue;
        };
        let value: serde_json::Value = serde_json::from_slice(&payload)?;
        if let Some(proposition) = value["body"]["proposition_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
        {
            proposition_ids.insert(proposition);
        } else if let Some(deliberation) = value["body"]["deliberation_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
        {
            if let Some(proposition) =
                store.proposition_id_for_deliberation(deliberation.as_bytes())?
            {
                proposition_ids.insert(proposition);
            }
        }
    }

    let mut matches = Vec::new();
    for proposition_id in proposition_ids {
        let payload = store
            .get_payload(proposition_id.as_bytes())?
            .ok_or_else(|| Error::MissingObject("proposition payload missing".into()))?;
        let value: serde_json::Value = serde_json::from_slice(&payload)?;
        let body = &value["body"];
        let initial_revision_id = body["initial_revision_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok());
        let initial_deliberation_id = body["initial_deliberation_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok());
        let metadata = indexed_metadata_for_proposition(store, ledger, proposition_id, None)?;
        let revision_id = metadata.effective_revision_id.or(initial_revision_id);
        let summary = summary_for_revision(store, revision_id);
        let activity = revision_activity_from_indexed_metadata(&metadata);
        matches.push(PropositionListItem {
            proposition_id,
            reference: crate::reference::short_uuid_reference(proposition_id),
            status: metadata.status.clone(),
            summary,
            revision_id,
            deliberation_id: metadata
                .effective_deliberation_id
                .or(initial_deliberation_id),
            settlement_id: metadata.settlement_id,
            effective_status: metadata.status,
            latest_revision_id: activity.latest_revision_id,
            latest_revision_status: activity.latest_revision_status,
            pending_revision_id: activity.pending_revision_id,
            pending_deliberation_id: activity.pending_deliberation_id,
            pending_participant_count: activity.pending_participant_count,
            current_actor_pending: false,
            has_pending_revision: activity.has_pending_revision,
        });
    }
    match matches.as_slice() {
        [item] => Ok(item.clone()),
        [] => Err(Error::MissingObject(format!(
            "no proposition matches reference {reference}"
        ))),
        _ => Err(Error::AmbiguousReference(reference.to_owned())),
    }
}

fn resolve_revision_reference(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    reference: &str,
) -> Result<Option<uuid::Uuid>> {
    let matches = store.resolve_object_reference(ledger.as_bytes(), reference, &["revision"])?;
    match matches.as_slice() {
        [] => Ok(None),
        [reference_match] => Ok(Some(reference_match.object_id)),
        _ => Err(Error::AmbiguousReference(reference.to_owned())),
    }
}

pub(crate) fn revision_for_reference(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: uuid::Uuid,
    reference: &str,
) -> Result<Option<uuid::Uuid>> {
    let mut matches = Vec::new();
    for reference_match in
        store.resolve_object_reference(ledger.as_bytes(), reference, &["revision"])?
    {
        if store.proposition_id_for_revision(reference_match.object_id.as_bytes())?
            == Some(proposition_id)
        {
            matches.push(reference_match.object_id);
        }
    }
    match matches.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(*id)),
        _ => Err(Error::AmbiguousReference(reference.to_owned())),
    }
}

fn proposition_reference_matches(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    reference: &str,
) -> Result<bool> {
    Ok(!store
        .resolve_object_reference(ledger.as_bytes(), reference, &["proposition"])?
        .is_empty())
}

fn resolve_proposition_cursor(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    reference: &str,
) -> Result<uuid::Uuid> {
    if let Ok(uuid) = parse_uuid7(reference, "after") {
        let Some(row) =
            store.object_summary_by_id(ledger.as_bytes(), uuid.as_bytes(), "proposition")?
        else {
            return Err(Error::MissingObject(reference.to_owned()));
        };
        return Ok(row.object_id);
    }
    let matches = store.resolve_object_reference(ledger.as_bytes(), reference, &["proposition"])?;
    match matches.as_slice() {
        [] => Err(Error::MissingObject(reference.to_owned())),
        [item] => Ok(item.object_id),
        _ => Err(Error::AmbiguousReference(reference.to_owned())),
    }
}

fn matched_show_object(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    reference: &str,
    proposition_id: uuid::Uuid,
) -> Result<ShowMatchedObject> {
    let matches = store.resolve_object_reference(ledger.as_bytes(), reference, &[])?;
    let mut candidates = Vec::new();
    for reference_match in matches {
        let owns_proposition = if reference_match.object_type == "proposition" {
            reference_match.object_id == proposition_id
        } else if reference_match.object_type == "revision" {
            store.proposition_id_for_revision(reference_match.object_id.as_bytes())?
                == Some(proposition_id)
        } else if reference_match.object_type == "deliberation" {
            store.proposition_id_for_deliberation(reference_match.object_id.as_bytes())?
                == Some(proposition_id)
        } else if let Some(payload) = store.get_payload(reference_match.object_id.as_bytes())? {
            let value: serde_json::Value = serde_json::from_slice(&payload)?;
            value["body"]["proposition_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                == Some(proposition_id)
                || value["body"]["deliberation_id"]
                    .as_str()
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    .and_then(|deliberation| {
                        store
                            .proposition_id_for_deliberation(deliberation.as_bytes())
                            .ok()
                            .flatten()
                    })
                    == Some(proposition_id)
        } else {
            false
        };
        if owns_proposition {
            candidates.push(ShowMatchedObject {
                object_type: reference_match.object_type,
                object_id: reference_match.object_id,
                object_ref: crate::reference::short_uuid_reference(reference_match.object_id),
                content_hash: reference_match.content_hash.hex(),
            });
        }
    }
    candidates.sort_by_key(|candidate| match candidate.object_type.as_str() {
        "proposition" => 0,
        "revision" => 1,
        "deliberation" => 2,
        "settlement" => 3,
        "deliberation_comment" => 4,
        _ => 5,
    });
    candidates
        .into_iter()
        .next()
        .ok_or_else(|| Error::MissingObject(format!("no object matches reference {reference}")))
}

fn mark_highlighted(values: &mut [serde_json::Value], object_id: uuid::Uuid) {
    for value in values {
        value["highlighted"] =
            serde_json::Value::Bool(json_uuid(&value["object_id"]) == Some(object_id));
    }
}

fn enrich_actor_fields(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    values: &mut [serde_json::Value],
) -> Result<()> {
    for value in values {
        let Some(actor_id) = json_uuid(&value["actor_id"]) else {
            continue;
        };
        value["author"] = actor_reference_value(store, ledger, actor_id)?;
    }
    Ok(())
}

fn json_uuid(value: &serde_json::Value) -> Option<uuid::Uuid> {
    value
        .as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
}

fn actor_reference_value(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor_id: uuid::Uuid,
) -> Result<serde_json::Value> {
    let directory =
        store.get_projected_directory_by_actor(ledger.as_bytes(), actor_id.as_bytes())?;
    Ok(serde_json::json!({
        "actor_id": actor_id,
        "actor_ref": crate::reference::short_uuid_reference(actor_id),
        "display_name": directory.as_ref().map(|row| row.display_name.clone()),
        "alias": directory.and_then(|row| row.alias)
    }))
}

fn indexed_metadata_for_proposition(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: uuid::Uuid,
    actor: Option<uuid::Uuid>,
) -> Result<fact_store::IndexedPropositionMetadata> {
    store
        .indexed_proposition_metadata(
            ledger.as_bytes(),
            proposition_id.as_bytes(),
            actor.as_ref().map(uuid::Uuid::as_bytes),
        )?
        .ok_or_else(|| Error::MissingObject("indexed proposition metadata is unavailable".into()))
}

fn revision_activity_from_indexed_metadata(
    metadata: &fact_store::IndexedPropositionMetadata,
) -> RevisionActivity {
    RevisionActivity {
        latest_revision_id: metadata.latest_revision_id,
        latest_revision_status: metadata.latest_revision_status.clone(),
        pending_revision_id: metadata.pending_revision_id,
        pending_deliberation_id: metadata.pending_deliberation_id,
        pending_participant_count: metadata.pending_participant_count,
        current_actor_pending: metadata.current_actor_pending,
        has_pending_revision: metadata.has_pending_revision,
    }
}

fn revision_conflict_group_for_proposition(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    actor: Option<uuid::Uuid>,
    proposition: &PropositionListItem,
    all: bool,
    referenced_revision: Option<uuid::Uuid>,
) -> Result<Option<RevisionConflictGroup>> {
    let metadata =
        indexed_metadata_for_proposition(store, ledger, proposition.proposition_id, actor)?;
    let revisions = store.list_revision_projecteds_by_proposition(
        ledger.as_bytes(),
        proposition.proposition_id.as_bytes(),
    )?;
    if revisions.is_empty() {
        return Ok(None);
    }
    let child_counts = revisions
        .iter()
        .filter_map(|revision| revision.parent_revision_id)
        .fold(
            BTreeMap::<uuid::Uuid, usize>::new(),
            |mut counts, parent| {
                *counts.entry(parent).or_default() += 1;
                counts
            },
        );
    let tips = revisions
        .iter()
        .filter(|revision| !child_counts.contains_key(&revision.revision_id))
        .map(|revision| revision.revision_id)
        .collect::<Vec<_>>();
    let current_conflict = tips.len() > 1
        || metadata.latest_revision_status == "ambiguous"
        || matches!(metadata.status.as_str(), "conflict" | "contested");
    if !all
        && metadata.status == "accepted"
        && metadata.effective_reason.starts_with("reconciliation-")
    {
        return Ok(None);
    }
    if !current_conflict && !all {
        return Ok(None);
    }
    if !current_conflict {
        return Ok(None);
    }
    let deliberations = store
        .list_deliberation_projecteds_by_proposition(
            ledger.as_bytes(),
            proposition.proposition_id.as_bytes(),
        )?
        .into_iter()
        .fold(
            BTreeMap::<uuid::Uuid, fact_store::DeliberationRow>::new(),
            |mut rows, row| {
                rows.insert(row.revision_id, row);
                rows
            },
        );
    let deliberation_ids = deliberations
        .values()
        .map(|row| row.deliberation_id)
        .collect::<Vec<_>>();
    let settlement_ids = store
        .list_settlement_payloads_by_deliberations(ledger.as_bytes(), &deliberation_ids)?
        .into_iter()
        .filter_map(|row| {
            let value = serde_json::from_slice::<serde_json::Value>(&row.payload).ok()?;
            Some((
                value["body"]["deliberation_id"].as_str()?.parse().ok()?,
                row.object_id,
            ))
        })
        .collect::<BTreeMap<uuid::Uuid, uuid::Uuid>>();
    let activity = revision_activity_from_indexed_metadata(&metadata);
    let conflict_revisions = revisions
        .iter()
        .filter(|revision| tips.contains(&revision.revision_id))
        .map(|revision| {
            let tip = !child_counts.contains_key(&revision.revision_id);
            let deliberation = deliberations.get(&revision.revision_id);
            let status = revision_conflict_status(&metadata, &activity, revision.revision_id, tip);
            RevisionConflictItem {
                revision_id: revision.revision_id,
                status,
                tip,
                matched_reference: referenced_revision == Some(revision.revision_id),
                deliberation_id: deliberation.map(|row| row.deliberation_id),
                settlement_id: deliberation
                    .and_then(|row| settlement_ids.get(&row.deliberation_id))
                    .copied(),
                participant_count: if activity.pending_revision_id == Some(revision.revision_id) {
                    activity.pending_participant_count
                } else {
                    0
                },
                current_actor_pending: activity.pending_revision_id == Some(revision.revision_id)
                    && activity.current_actor_pending,
            }
        })
        .collect::<Vec<_>>();
    if conflict_revisions.len() < 2 && !matches!(metadata.status.as_str(), "conflict" | "contested")
    {
        return Ok(None);
    }
    let common_ancestor_revision_id = common_revision_ancestor(&revisions, &tips);
    let conflict_triples = conflict_revisions
        .iter()
        .filter_map(|item| {
            Some(format!(
                "{}:{}:{}",
                item.revision_id, item.deliberation_id?, item.settlement_id?
            ))
        })
        .collect();
    let resolved_tips = conflict_revisions
        .iter()
        .filter(|item| item.tip)
        .map(|item| item.revision_id)
        .collect();
    Ok(Some(RevisionConflictGroup {
        proposition_id: proposition.proposition_id,
        reference: proposition.reference.clone(),
        summary: proposition.summary.clone(),
        status: if metadata.latest_revision_status == "ambiguous" {
            "ambiguous".to_owned()
        } else if matches!(metadata.status.as_str(), "conflict" | "contested") {
            metadata.status.clone()
        } else {
            "conflict".to_owned()
        },
        common_ancestor_revision_id,
        conflicts: conflict_revisions,
        resolution_inputs: RevisionConflictResolutionInputs {
            conflict_triples,
            resolved_tips,
        },
    }))
}

fn revision_conflict_status(
    metadata: &fact_store::IndexedPropositionMetadata,
    activity: &RevisionActivity,
    revision_id: uuid::Uuid,
    tip: bool,
) -> String {
    if metadata.effective_revision_id == Some(revision_id) {
        return metadata.status.clone();
    }
    if activity.pending_revision_id == Some(revision_id) {
        return "pending".to_owned();
    }
    if tip && activity.latest_revision_id == Some(revision_id) {
        return activity.latest_revision_status.clone();
    }
    if tip {
        return "ambiguous".to_owned();
    }
    "superseded".to_owned()
}

fn common_revision_ancestor(
    revisions: &[fact_store::RevisionRow],
    tips: &[uuid::Uuid],
) -> Option<uuid::Uuid> {
    if tips.len() < 2 {
        return None;
    }
    let parents = revisions
        .iter()
        .map(|revision| (revision.revision_id, revision.parent_revision_id))
        .collect::<BTreeMap<_, _>>();
    let first = revision_ancestor_distances(&parents, tips[0]);
    let common = tips
        .iter()
        .skip(1)
        .map(|tip| revision_ancestor_distances(&parents, *tip))
        .fold(first, |common, distances| {
            common
                .into_iter()
                .filter_map(|(revision, distance)| {
                    distances
                        .contains_key(&revision)
                        .then_some((revision, distance))
                })
                .collect()
        });
    common
        .into_iter()
        .min_by_key(|(_, distance)| *distance)
        .map(|(revision, _)| revision)
}

fn revision_ancestor_distances(
    parents: &BTreeMap<uuid::Uuid, Option<uuid::Uuid>>,
    tip: uuid::Uuid,
) -> BTreeMap<uuid::Uuid, usize> {
    let mut output = BTreeMap::new();
    let mut current = Some(tip);
    let mut distance = 0;
    while let Some(revision) = current {
        if output.insert(revision, distance).is_some() {
            break;
        }
        current = parents.get(&revision).copied().flatten();
        distance += 1;
    }
    output
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn effective_revision_for_proposition(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: uuid::Uuid,
) -> Result<Option<uuid::Uuid>> {
    Ok(
        indexed_metadata_for_proposition(store, ledger, proposition_id, None)?
            .effective_revision_id,
    )
}

fn latest_revision_for_proposition(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: uuid::Uuid,
) -> Result<uuid::Uuid> {
    let metadata = indexed_metadata_for_proposition(store, ledger, proposition_id, None)?;
    metadata.latest_revision_id.ok_or_else(|| {
        if metadata.latest_revision_status == "ambiguous" {
            Error::AmbiguousReference(
                "proposition has ambiguous revision heads; provide a revision reference".into(),
            )
        } else {
            Error::Message("proposition has no revision".into())
        }
    })
}

pub(crate) fn active_participants_for_deliberation(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberation: uuid::Uuid,
) -> Result<Vec<String>> {
    let participants = participant_decision_status(store, ledger, deliberation)?
        .into_iter()
        .filter(|participant| participant["active"].as_bool() == Some(true))
        .filter_map(|participant| participant["actor_id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    if participants.is_empty() {
        return Err(Error::Message(
            "proposition has no active participants to carry forward".into(),
        ));
    }
    Ok(participants)
}

pub(crate) fn active_participant_ids_for_settlement(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberation: uuid::Uuid,
    deliberation_cose: &[u8],
) -> Result<Vec<uuid::Uuid>> {
    let projected = store
        .participant_decisions_for_deliberation(ledger.as_bytes(), deliberation.as_bytes())?
        .into_iter()
        .filter(|participant| participant.active)
        .map(|participant| participant.actor_id)
        .collect::<Vec<_>>();
    if !projected.is_empty() {
        return Ok(projected);
    }
    let payload = fact_crypto::decode_sign1(deliberation_cose)?.payload;
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    let participants = value["body"]["initial_participants"]
        .as_array()
        .ok_or_else(|| Error::Validation("deliberation is missing participants".into()))?
        .iter()
        .map(|participant| {
            participant["actor_id"]
                .as_str()
                .ok_or_else(|| Error::Validation("participant is missing actor_id".into()))?
                .parse()
                .map_err(Error::from)
        })
        .collect::<Result<Vec<uuid::Uuid>>>()?;
    if participants.is_empty() {
        return Err(Error::Message(
            "proposition has no active participants to settle".into(),
        ));
    }
    Ok(participants)
}

pub(crate) fn canonical_decisions_for_deliberation(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberation: uuid::Uuid,
) -> Result<Vec<CanonicalDecisionRecord>> {
    let mut decisions = Vec::new();
    let mut superseded: HashSet<uuid::Uuid> = HashSet::new();
    for row in store.list_object_payloads_by_type(ledger.as_bytes(), "decision")? {
        let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
        let body = &value["body"];
        if body["deliberation_id"].as_str() != Some(&deliberation.to_string()) {
            continue;
        }
        if let Some(ids) = body["supersedes_decision_ids"].as_array() {
            for id in ids {
                if let Some(id) = id.as_str() {
                    superseded.insert(id.parse()?);
                }
            }
        }
        let cose = store
            .get_cose_by_id(ledger.as_bytes(), row.object_id.as_bytes())?
            .ok_or_else(|| Error::MissingObject("decision object is unavailable".into()))?;
        decisions.push(CanonicalDecisionRecord {
            decision_id: row.object_id,
            participant_actor_id: body["participant_actor_id"]
                .as_str()
                .ok_or_else(|| {
                    Error::Validation("decision is missing participant_actor_id".into())
                })?
                .parse()?,
            value: body["value"]
                .as_str()
                .ok_or_else(|| Error::Validation("decision is missing value".into()))?
                .to_owned(),
            content_hash: row.content_hash,
            cose,
        });
    }
    decisions.retain(|decision| !superseded.contains(&decision.decision_id));
    decisions.sort_by_key(|decision| (decision.participant_actor_id, decision.decision_id));
    Ok(decisions)
}

pub(crate) fn deliberation_for_revision(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: uuid::Uuid,
    revision_id: uuid::Uuid,
) -> Result<Option<uuid::Uuid>> {
    let matches = store.deliberation_id_for_revision(
        ledger.as_bytes(),
        proposition_id.as_bytes(),
        revision_id.as_bytes(),
    )?;
    match matches.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(*id)),
        _ => Err(Error::AmbiguousReference(format!(
            "revision {revision_id} has ambiguous deliberations"
        ))),
    }
}

fn related_revisions_for_proposition(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: uuid::Uuid,
) -> Result<Vec<RelatedObject>> {
    let mut result = store
        .list_revision_projecteds_by_proposition(ledger.as_bytes(), proposition_id.as_bytes())?
        .into_iter()
        .map(|row| {
            let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
            Ok((
                row.object_id,
                row.content_hash,
                "revision".to_owned(),
                value,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    sort_related_objects(&mut result);
    Ok(result)
}

fn related_deliberations_for_proposition(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: uuid::Uuid,
) -> Result<Vec<RelatedObject>> {
    let mut result = store
        .list_deliberation_projecteds_by_proposition(ledger.as_bytes(), proposition_id.as_bytes())?
        .into_iter()
        .map(|row| {
            let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
            Ok((
                row.object_id,
                row.content_hash,
                "deliberation".to_owned(),
                value,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    sort_related_objects(&mut result);
    Ok(result)
}

fn scoped_history_objects(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: uuid::Uuid,
) -> Result<Vec<RelatedObject>> {
    let mut result = Vec::new();
    if let Some(row) = store.object_payload_by_id(ledger.as_bytes(), proposition_id.as_bytes())? {
        result.push(object_payload_row_to_related(row)?);
    }

    result.extend(related_revisions_for_proposition(
        store,
        ledger,
        proposition_id,
    )?);
    let deliberations = store.list_deliberation_projecteds_by_proposition(
        ledger.as_bytes(),
        proposition_id.as_bytes(),
    )?;
    for deliberation in &deliberations {
        let value: serde_json::Value = serde_json::from_slice(&deliberation.payload)?;
        result.push((
            deliberation.object_id,
            deliberation.content_hash,
            "deliberation".to_owned(),
            value,
        ));
    }
    for row in store.list_relationship_payloads(
        ledger.as_bytes(),
        Some(proposition_id.as_bytes()),
        None,
        None,
    )? {
        result.push(object_payload_row_to_related(row)?);
    }

    let deliberation_ids = deliberations
        .iter()
        .map(|deliberation| deliberation.deliberation_id)
        .collect::<Vec<_>>();
    for row in store.list_objects_by_deliberations(
        ledger.as_bytes(),
        &deliberation_ids,
        "deliberation_comment",
    )? {
        result.push(object_payload_row_to_related(row)?);
    }
    for row in store.list_objects_by_deliberations(
        ledger.as_bytes(),
        &deliberation_ids,
        "deliberation_participant_change",
    )? {
        result.push(object_payload_row_to_related(row)?);
    }
    for decision in
        store.list_decision_rows_by_deliberations(ledger.as_bytes(), &deliberation_ids)?
    {
        let value: serde_json::Value = serde_json::from_slice(&decision.payload)?;
        result.push((
            decision.decision_id,
            decision.content_hash,
            "decision".to_owned(),
            value,
        ));
    }
    for row in
        store.list_settlement_payloads_by_deliberations(ledger.as_bytes(), &deliberation_ids)?
    {
        result.push(object_payload_row_to_related(row)?);
    }

    let mut seen = HashSet::new();
    result.retain(|(object_id, _, _, _)| seen.insert(*object_id));
    sort_related_objects(&mut result);
    Ok(result)
}

fn object_payload_row_to_related(row: fact_store::ObjectPayloadRow) -> Result<RelatedObject> {
    let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
    Ok((row.object_id, row.content_hash, row.object_type, value))
}

fn sort_related_objects(objects: &mut [RelatedObject]) {
    objects.sort_by(|left, right| {
        left.3["created_at"]
            .as_str()
            .cmp(&right.3["created_at"].as_str())
    });
}

pub(crate) fn list_comments_for_proposition_as_values(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    proposition_id: uuid::Uuid,
    revision_id: Option<uuid::Uuid>,
) -> Result<Vec<serde_json::Value>> {
    let deliberations = store
        .list_deliberation_projecteds_by_proposition(ledger.as_bytes(), proposition_id.as_bytes())?
        .into_iter()
        .filter(|row| revision_id.is_none_or(|revision_id| row.revision_id == revision_id))
        .collect::<Vec<_>>();
    let mut comments = Vec::new();
    for deliberation in deliberations {
        comments.extend(store.list_objects_by_deliberation(
            ledger.as_bytes(),
            deliberation.deliberation_id.as_bytes(),
            "deliberation_comment",
        )?);
    }
    let mut values = comments
        .into_iter()
        .map(|row| {
            let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
            Ok(serde_json::json!({
                "object_id":row.object_id,
                "reference":crate::reference::short_uuid_reference(row.object_id),
                "object_type":row.object_type,
                "content_hash":row.content_hash.hex(),
                "created_at":value["created_at"],
                "actor_id":value["actor_id"],
                "deliberation_id":value["body"]["deliberation_id"],
                "parent_comment_id":value["body"]["parent_comment_id"],
                "summary":value["body"]["content"]["bytes"].as_str().and_then(decode_b64url).map(|bytes| summary_for_markdown(&bytes)).unwrap_or_else(|| "No summary".to_owned())
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    values.sort_by(|left, right| {
        left["created_at"]
            .as_str()
            .cmp(&right["created_at"].as_str())
    });
    Ok(values)
}

pub(crate) fn related_objects_by_deliberation(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberation: uuid::Uuid,
    object_type_filter: &str,
) -> Result<Vec<serde_json::Value>> {
    store
        .list_objects_by_deliberation(
            ledger.as_bytes(),
            deliberation.as_bytes(),
            object_type_filter,
        )?
        .into_iter()
        .map(|row| serde_json::from_slice(&row.payload).map_err(Into::into))
        .collect()
}

pub(crate) fn participant_decision_status(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    deliberation: uuid::Uuid,
) -> Result<Vec<serde_json::Value>> {
    Ok(store
        .participant_decisions_for_deliberation(ledger.as_bytes(), deliberation.as_bytes())?
        .into_iter()
        .map(|participant| {
            serde_json::json!({
                "actor_id":participant.actor_id,
                "active":participant.active,
                "decision":participant.decision
            })
        })
        .collect())
}

pub(crate) fn summary_for_markdown(markdown: &[u8]) -> String {
    for line in String::from_utf8_lossy(markdown).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("```") {
            continue;
        }
        let summary = line.trim_start_matches('#').trim().trim_matches('*').trim();
        if !summary.is_empty() {
            return summary.chars().take(120).collect();
        }
    }
    "No summary".to_owned()
}

fn summary_for_revision(store: &fact_store::Store, revision: Option<uuid::Uuid>) -> String {
    revision
        .and_then(|revision| store.get_payload(revision.as_bytes()).ok().flatten())
        .and_then(|payload| serde_json::from_slice::<serde_json::Value>(&payload).ok())
        .and_then(|value| {
            value["body"]["content"]["bytes"]
                .as_str()
                .and_then(decode_b64url)
        })
        .map(|bytes| summary_for_markdown(&bytes))
        .unwrap_or_else(|| "No summary".to_owned())
}

fn summary_for_revision_payload(payload: Option<&[u8]>) -> String {
    payload
        .and_then(|payload| serde_json::from_slice::<serde_json::Value>(payload).ok())
        .and_then(|value| {
            value["body"]["content"]["bytes"]
                .as_str()
                .and_then(decode_b64url)
        })
        .map(|bytes| summary_for_markdown(&bytes))
        .unwrap_or_else(|| "No summary".to_owned())
}

fn object_description(value: &serde_json::Value) -> String {
    let body = &value["body"];
    if let Some(operation) = body["operation"].as_str() {
        return operation.to_owned();
    }
    if let Some(outcome) = body["outcome"].as_str() {
        return outcome.to_owned();
    }
    if let Some(value) = body["value"].as_str() {
        return format!("decision {value}");
    }
    if body["content"]["bytes"].is_string() {
        return body["content"]["bytes"]
            .as_str()
            .and_then(decode_b64url)
            .map(|bytes| summary_for_markdown(&bytes))
            .unwrap_or_else(|| value["object_type"].as_str().unwrap_or("object").to_owned());
    }
    value["object_type"].as_str().unwrap_or("object").to_owned()
}

fn revision_content(store: &fact_store::Store, revision_id: uuid::Uuid) -> Result<Vec<u8>> {
    let payload = store
        .get_payload(revision_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("revision payload missing".into()))?;
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    value["body"]["content"]["bytes"]
        .as_str()
        .and_then(decode_b64url)
        .ok_or_else(|| Error::Validation("revision has no Markdown content".into()))
}

fn content_value(markdown: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "media_type":"text/markdown; charset=utf-8; variant=fact-v0",
        "bytes":base64url(markdown),
        "hash":fact_core::Hash::digest(markdown).hex()
    })
}

pub(crate) fn parse_uuid7(value: &str, field: &str) -> Result<uuid::Uuid> {
    let uuid = uuid::Uuid::parse_str(value)?;
    if uuid.get_version_num() != 7 || uuid.to_string() != value {
        return Err(Error::Validation(format!(
            "{field} must be lowercase canonical UUIDv7"
        )));
    }
    Ok(uuid)
}

pub(crate) fn dependency_value(cose_bytes: &[u8], role: &str) -> Result<serde_json::Value> {
    let cose = fact_crypto::decode_sign1(cose_bytes)?;
    let value: serde_json::Value = serde_json::from_slice(&cose.payload)?;
    Ok(serde_json::json!({
        "object_id":value["id"],
        "content_hash":fact_core::Hash::digest(&cose.payload).hex(),
        "role":role
    }))
}

pub(crate) fn dependency_hash(cose_bytes: &[u8]) -> Result<fact_core::Hash> {
    Ok(fact_core::Hash::digest(
        &fact_crypto::decode_sign1(cose_bytes)?.payload,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn signed_envelope(
    id: uuid::Uuid,
    ledger: uuid::Uuid,
    object_type: &str,
    actor: uuid::Uuid,
    key_id: uuid::Uuid,
    body: serde_json::Value,
    dependencies: Vec<serde_json::Value>,
    key: &fact_crypto::SigningKey,
    runtime: &dyn SdkRuntime,
) -> Result<Vec<u8>> {
    let value = serde_json::json!({
        "id":id.to_string(),
        "ledger_id":ledger.to_string(),
        "object_type":object_type,
        "schema_version":"0",
        "actor_id":actor.to_string(),
        "signing_key_id":key_id.to_string(),
        "created_at":runtime.timestamp(),
        "dependencies":dependencies,
        "body":body
    });
    let payload = fact_canonical::encode(&serde_json::to_vec(&value)?)?;
    let protected = fact_crypto::protocol_protected(
        key.public_key(),
        object_type,
        "0",
        Some(*ledger.as_bytes()),
    );
    Ok(fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected, &payload, key,
    )))
}

pub(crate) fn base64url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((value >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(value & 63) as usize] as char);
        }
    }
    output
}

fn decode_b64url(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        accumulator = (accumulator << 6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    (bits < 6 && accumulator == 0).then_some(output)
}

fn search_status_name(status: ListPropositionStatus) -> &'static str {
    match status {
        ListPropositionStatus::Pending => "pending",
        ListPropositionStatus::Accepted => "accepted",
        ListPropositionStatus::Rejected => "rejected",
        ListPropositionStatus::Contested => "contested",
        ListPropositionStatus::Withdrawn => "withdrawn",
        ListPropositionStatus::Archived => "archived",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        lifecycle::{archive_proposition, withdraw_proposition},
        workflow::{create_ledger, BootstrapLedgerInput},
    };

    fn entry() -> (tempfile::TempDir, LedgerEntry, [u8; 32]) {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [11; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.proposition-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce: [12; 16],
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
    fn create_accept_list_read_and_search_proposition() {
        let (_temp, entry, seed) = entry();
        let created =
            create_proposition(&entry, &seed, b"# Coffee\n\nCoffee improves focus.\n", None)
                .unwrap();
        assert_eq!(created.status, "pending");
        assert_eq!(pending_propositions(&entry).unwrap().len(), 1);

        let accepted = accept_proposition(&entry, &seed, Some(&created.reference())).unwrap();
        assert_eq!(accepted.status, "accepted");
        fact_store::Store::reset_debug_metrics();
        let listed = list_propositions(
            &entry,
            ListPropositionsFilter {
                status: Some(ListPropositionStatus::Accepted),
                all: false,
            },
        )
        .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].summary, "Coffee");
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects, 0);
        assert_eq!(metrics.get_payload, 0);
        assert_eq!(metrics.list_effective_state, 0);

        fact_store::Store::reset_debug_metrics();
        let resolved = read_proposition_content(&entry, &created.reference()).unwrap();
        assert_eq!(resolved.revision_id, created.revision_id);
        assert_eq!(resolved.content, b"# Coffee\n\nCoffee improves focus.\n");
        assert_eq!(fact_store::Store::debug_metrics().list_effective_state, 0);

        fact_store::Store::reset_debug_metrics();
        let revisions = list_revisions(&entry, &created.reference()).unwrap();
        assert_eq!(revisions.len(), 1);
        assert_eq!(fact_store::Store::debug_metrics().list_effective_state, 0);

        fact_store::Store::reset_debug_metrics();
        let inspected = inspect_proposition(&entry, &created.reference()).unwrap();
        let expected_revision_id = created.revision_id.to_string();
        assert_eq!(
            inspected["revision_state"]["effective_revision"].as_str(),
            Some(expected_revision_id.as_str())
        );
        assert_eq!(fact_store::Store::debug_metrics().list_effective_state, 0);

        let found = find_propositions(&entry, "focus").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].proposition_id, Some(created.proposition_id));
        fact_store::Store::reset_debug_metrics();
        let repeated = find_propositions(&entry, "focus").unwrap();
        assert_eq!(repeated.len(), 1);
        assert_eq!(fact_store::Store::debug_metrics().search_index_rebuilds, 0);

        fact_store::Store::reset_debug_metrics();
        let history = history_ledger(&entry, Some(&created.reference())).unwrap();
        assert!(history
            .iter()
            .any(|item| item.object_type == "revision" && item.description == "Coffee"));
        assert!(history
            .iter()
            .any(|item| item.object_type == "settlement" && item.description == "accepted"));
        assert_eq!(
            fact_store::Store::debug_metrics().list_objects_by_deliberation,
            0
        );

        fact_store::Store::reset_debug_metrics();
        let unscoped_history = history_ledger(&entry, None).unwrap();
        assert!(!unscoped_history.is_empty());
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects, 0);
        assert_eq!(metrics.get_payload, 0);

        fact_store::Store::reset_debug_metrics();
        let paged_history = history_ledger_page(
            &entry,
            None,
            Some(HistoryPage {
                after: None,
                limit: Some(2),
            }),
        )
        .unwrap();
        assert_eq!(paged_history.len(), 2);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_object_payloads, 0);

        let resumed_history = history_ledger_page(
            &entry,
            None,
            Some(HistoryPage {
                after: paged_history.last().map(|item| item.content_hash.clone()),
                limit: Some(2),
            }),
        )
        .unwrap();
        assert!(paged_history.iter().all(|item| resumed_history
            .iter()
            .all(|next| next.object_id != item.object_id)));
    }

    #[test]
    fn list_propositions_page_limits_default_projected_rows() {
        let (_temp, entry, seed) = entry();
        let first = create_proposition(
            &entry,
            &seed,
            b"# First\n\nFirst accepted proposition.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        let second = create_proposition(
            &entry,
            &seed,
            b"# Second\n\nSecond accepted proposition.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        let third = create_proposition(
            &entry,
            &seed,
            b"# Third\n\nThird accepted proposition.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        let mut expected = [
            first.proposition_id,
            second.proposition_id,
            third.proposition_id,
        ];
        expected.sort();

        fact_store::Store::reset_debug_metrics();
        let page = list_propositions_page(
            &entry,
            ListPropositionsFilter {
                status: None,
                all: false,
            },
            Some(ListPropositionsPage {
                offset: 1,
                limit: Some(1),
                after: None,
            }),
        )
        .unwrap();

        assert_eq!(page.len(), 1);
        assert_eq!(page[0].proposition_id, expected[1]);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects, 0);
        assert_eq!(metrics.get_payload, 0);
        assert_eq!(metrics.list_effective_state, 0);

        let cursor_page = list_propositions_page(
            &entry,
            ListPropositionsFilter {
                status: None,
                all: false,
            },
            Some(ListPropositionsPage {
                offset: 0,
                limit: Some(1),
                after: Some(crate::reference::short_uuid_reference(expected[0])),
            }),
        )
        .unwrap();
        assert_eq!(cursor_page.len(), 1);
        assert_eq!(cursor_page[0].proposition_id, expected[1]);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn create_and_decide_proposition_use_incremental_projected() {
        let (_temp, entry, seed) = entry();

        fact_store::Store::reset_debug_metrics();
        let pending = create_proposition(
            &entry,
            &seed,
            b"# Pending\n\nCreated without a full projected rebuild.\n",
            None,
        )
        .unwrap();
        assert_eq!(pending.status, "pending");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);

        fact_store::Store::reset_debug_metrics();
        let accepted = accept_proposition(&entry, &seed, Some(&pending.reference())).unwrap();
        assert_eq!(accepted.status, "accepted");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);

        fact_store::Store::reset_debug_metrics();
        let decided = create_proposition(
            &entry,
            &seed,
            b"# Accepted\n\nCreated and accepted incrementally.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        assert_eq!(decided.status, "accepted");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn create_proposition_can_defer_projected_rebuild_for_bulk_callers() {
        let (_temp, entry, seed) = entry();
        create_proposition(&entry, &seed, b"# Bootstrap\n\nCreate grant.\n", None).unwrap();

        fact_store::Store::reset_debug_metrics();
        let created = create_proposition_with_runtime_and_projected_mode(
            &entry,
            &seed,
            b"# Deferred\n\nAccepted without immediate read-model rebuild.\n",
            Some(DecisionOutcome::Accepted),
            production_runtime().as_ref(),
            fact_store::ProjectedMode::Defer,
        )
        .unwrap();
        assert_eq!(created.status, "accepted");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);

        let store = fact_store::Store::open(&entry.database).unwrap();
        store.rebuild_projecteds().unwrap();
        let listed = list_propositions(
            &entry,
            ListPropositionsFilter {
                status: Some(ListPropositionStatus::Accepted),
                all: false,
            },
        )
        .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].proposition_id, created.proposition_id);
    }

    #[test]
    fn create_reconciliation_proposition_projects_manifest() {
        let (_temp, entry, seed) = entry();
        let source = create_proposition(
            &entry,
            &seed,
            b"# Source\n\nAccepted source.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        let settlement_id = source.settlement_id.expect("source settlement exists");
        #[cfg(debug_assertions)]
        fact_store::Store::reset_debug_metrics();
        let reconciliation = create_reconciliation_proposition(
            &entry,
            &seed,
            ReconciliationInput {
                affected_proposition_id: source.proposition_id,
                common_ancestor_revision_id: source.revision_id,
                conflicts: vec![ReconciliationConflictInput {
                    revision_id: source.revision_id,
                    deliberation_id: source.deliberation_id,
                    settlement_id,
                }],
                detecting_actor_id: entry.actor_id.parse().unwrap(),
                resolution_mode: "select".into(),
                resolved_tip_ids: vec![source.revision_id],
                selected_revision_id: Some(source.revision_id),
                result_revision_id: None,
                markdown: Some(b"# Reconcile\n\nSelect the source.\n".to_vec()),
            },
        )
        .unwrap();

        assert_eq!(reconciliation.resolution_mode, "select");
        assert_eq!(reconciliation.selected_participant_count, 1);
        #[cfg(debug_assertions)]
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);
        let connection = rusqlite::Connection::open(&entry.database).unwrap();
        let row: (String, Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT resolution_mode,affected_proposition_id,selected_revision_id FROM projected_reconciliation WHERE revision_id=?",
                [reconciliation.revision_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row.0, "select");
        assert_eq!(row.1, source.proposition_id.as_bytes());
        assert_eq!(row.2, source.revision_id.as_bytes());
        fact_store::Store::reset_debug_metrics();
        let found = search_proposition_content(&entry, "Reconcile", None, false, 20).unwrap();
        assert!(found
            .iter()
            .all(|item| item.proposition_id != Some(reconciliation.proposition_id)));
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_effective_state, 0);
        assert_eq!(metrics.list_object_payloads_by_type, 0);
    }

    #[test]
    fn create_derived_revision_records_contributing_revisions() {
        let (_temp, entry, seed) = entry();
        let created = create_proposition(
            &entry,
            &seed,
            b"# Derived\n\nBase.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        let branch_a = update_proposition_content(
            &entry,
            &seed,
            &created.proposition_id.to_string(),
            b"# Derived\n\nA.\n",
        )
        .unwrap();
        let branch_b = update_proposition_content(
            &entry,
            &seed,
            &created.proposition_id.to_string(),
            b"# Derived\n\nB.\n",
        )
        .unwrap();
        let derived = create_derived_revision(
            &entry,
            &seed,
            DerivedRevisionInput {
                proposition_id: created.proposition_id,
                parent_revision_id: created.revision_id,
                contributing_revision_ids: vec![branch_b.revision_id, branch_a.revision_id],
                markdown: b"# Derived\n\nA and B.\n".to_vec(),
            },
        )
        .unwrap();
        let store = fact_store::Store::open(&entry.database).unwrap();
        let payload = store
            .get_payload(derived.revision_id.as_bytes())
            .unwrap()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            value["body"]["parent_revision_id"].as_str(),
            Some(created.revision_id.to_string().as_str())
        );
        let targets = value["body"]["relationships"][0]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|target| target.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            targets,
            vec![
                branch_a.revision_id.to_string(),
                branch_b.revision_id.to_string()
            ]
        );
    }

    #[test]
    fn search_effective_accepted_excludes_withdrawn_propositions() {
        let (_temp, entry, seed) = entry();
        let created = create_proposition(
            &entry,
            &seed,
            b"# Withdrawn Search\n\nLifecycle needle remains accepted.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        withdraw_proposition(
            &entry,
            &seed,
            &created.reference(),
            "not currently applicable",
        )
        .unwrap();

        fact_store::Store::reset_debug_metrics();
        let found = search_proposition_content(
            &entry,
            "needle",
            Some(ListPropositionStatus::Accepted),
            true,
            20,
        )
        .unwrap();
        assert!(found.is_empty());
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_effective_state, 0);
        assert_eq!(metrics.list_object_payloads_by_type, 0);
    }

    #[test]
    fn search_effective_accepted_excludes_archived_propositions() {
        let (_temp, entry, seed) = entry();
        let created = create_proposition(
            &entry,
            &seed,
            b"# Archived Search\n\nLifecycle archive-token remains accepted.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        archive_proposition(&entry, &seed, &created.reference(), "kept for history").unwrap();

        fact_store::Store::reset_debug_metrics();
        let found = search_proposition_content(
            &entry,
            "archive-token",
            Some(ListPropositionStatus::Accepted),
            true,
            20,
        )
        .unwrap();
        assert!(found.is_empty());
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_effective_state, 0);
        assert_eq!(metrics.list_object_payloads_by_type, 0);
    }

    #[test]
    fn update_content_creates_pending_revision_over_effective_content() {
        let (_temp, entry, seed) = entry();
        let created = create_proposition(
            &entry,
            &seed,
            b"# Original\n\nFirst version.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        fact_store::Store::reset_debug_metrics();
        let revised = update_proposition_content(
            &entry,
            &seed,
            &created.reference(),
            b"# Revised\n\nSecond version.\n",
        )
        .unwrap();
        assert_eq!(revised.status, "pending");
        assert_eq!(revised.previous_revision_id, Some(created.revision_id));
        assert_eq!(revised.previous_revision_effective, Some(true));
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);
        let store = fact_store::Store::open(&entry.database).unwrap();
        let ledger = parse_uuid7(&entry.ledger_id, "ledger").unwrap();
        let revision_roles = dependency_roles(
            &store
                .get_cose_by_id(ledger.as_bytes(), revised.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        );
        assert!(revision_roles.contains(&"propose-authority".to_owned()));
        let deliberation_roles = dependency_roles(
            &store
                .get_cose_by_id(ledger.as_bytes(), revised.deliberation_id.as_bytes())
                .unwrap()
                .unwrap(),
        );
        assert!(deliberation_roles.contains(&"deliberate-authority".to_owned()));

        let effective = read_proposition_content(&entry, &created.reference()).unwrap();
        assert_eq!(effective.content, b"# Original\n\nFirst version.\n");
        let pending = read_proposition_content_with_selection(
            &entry,
            &created.reference(),
            ContentSelection::Pending,
        )
        .unwrap();
        assert_eq!(pending.revision_id, revised.revision_id);
        assert_eq!(pending.content, b"# Revised\n\nSecond version.\n");
        let latest = latest_proposition_content(&entry, &created.reference()).unwrap();
        assert_eq!(latest, b"# Revised\n\nSecond version.\n");
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

    #[test]
    fn pending_count_matches_visible_pending_actions() {
        let (_temp, entry, seed) = entry();
        let visible = create_proposition(
            &entry,
            &seed,
            b"# Visible\n\nNeeds a decision.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        update_proposition_content(
            &entry,
            &seed,
            &visible.proposition_id.to_string(),
            b"# Visible update\n\nStill actionable.\n",
        )
        .unwrap();
        let hidden = create_proposition(
            &entry,
            &seed,
            b"# Hidden\n\nWill be withdrawn before its update settles.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        update_proposition_content(
            &entry,
            &seed,
            &hidden.proposition_id.to_string(),
            b"# Hidden update\n\nShould not count as a visible pending action.\n",
        )
        .unwrap();
        withdraw_proposition(
            &entry,
            &seed,
            &hidden.proposition_id.to_string(),
            "not actionable",
        )
        .unwrap();

        let pending = pending_propositions(&entry).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].proposition_id, visible.proposition_id);
        assert_eq!(pending_proposition_count(&entry).unwrap(), pending.len());
    }

    #[test]
    fn list_revision_conflicts_reports_parallel_revision_tips() {
        let (_temp, entry, seed) = entry();
        let created = create_proposition(
            &entry,
            &seed,
            b"# Stable\n\nEffective version.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        let branch_one = update_proposition_content(
            &entry,
            &seed,
            &created.revision_id.to_string(),
            b"# Branch One\n\nPending branch.\n",
        )
        .unwrap();
        let ledger = parse_uuid7(&entry.ledger_id, "ledger").unwrap();
        let actor = parse_uuid7(&entry.actor_id, "actor").unwrap();
        let key_id = parse_uuid7(&entry.key_id, "key").unwrap();
        let key = fact_crypto::SigningKey::from_seed(&seed).unwrap();
        let store = fact_store::Store::open(&entry.database).unwrap();
        let proposition = store
            .get_cose_by_id(ledger.as_bytes(), created.proposition_id.as_bytes())
            .unwrap()
            .unwrap();
        let parent_revision = store
            .get_cose_by_id(ledger.as_bytes(), created.revision_id.as_bytes())
            .unwrap()
            .unwrap();
        let runtime = crate::runtime::production_runtime();
        let branch_revision_id = uuid::Uuid::now_v7();
        let branch_revision = signed_envelope(
            branch_revision_id,
            ledger,
            "revision",
            actor,
            key_id,
            serde_json::json!({
                "proposition_id": created.proposition_id,
                "revision_id": branch_revision_id,
                "parent_revision_id": created.revision_id,
                "content": content_value(b"# Branch Two\n\nAnother pending branch.\n"),
                "relationships": [],
                "reconciliation_manifest": null,
            }),
            vec![
                dependency_value(&proposition, "proposition").unwrap(),
                dependency_value(&parent_revision, "parent-revision").unwrap(),
            ],
            &key,
            runtime.as_ref(),
        )
        .unwrap();
        store.insert_authorized_object(&branch_revision).unwrap();

        let conflicts =
            list_revision_conflicts(&entry, Some(&created.proposition_id.to_string()), false)
                .unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].proposition_id, created.proposition_id);
        assert_eq!(
            conflicts[0].common_ancestor_revision_id,
            Some(created.revision_id)
        );
        let conflict_revision_ids = conflicts[0]
            .conflicts
            .iter()
            .map(|item| item.revision_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            conflict_revision_ids,
            BTreeSet::from([branch_one.revision_id, branch_revision_id])
        );
        assert_eq!(
            conflicts[0].resolution_inputs.resolved_tips,
            vec![branch_one.revision_id, branch_revision_id]
        );

        let revision_scoped =
            list_revision_conflicts(&entry, Some(&branch_revision_id.to_string()), false).unwrap();
        assert_eq!(revision_scoped.len(), 1);
        let matched = revision_scoped[0]
            .conflicts
            .iter()
            .filter(|item| item.matched_reference)
            .map(|item| item.revision_id)
            .collect::<Vec<_>>();
        assert_eq!(matched, vec![branch_revision_id]);
    }

    #[test]
    fn resolve_revision_conflict_derived_creates_atomic_reconciliation() {
        let (_temp, entry, seed) = entry();
        let created = create_proposition(
            &entry,
            &seed,
            b"# Stable\n\nEffective version.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        let branch_one = update_proposition_content(
            &entry,
            &seed,
            &created.revision_id.to_string(),
            b"# Branch One\n\nAccepted branch.\n",
        )
        .unwrap();
        accept_proposition(&entry, &seed, Some(&branch_one.revision_id.to_string())).unwrap();

        let ledger = parse_uuid7(&entry.ledger_id, "ledger").unwrap();
        let actor = parse_uuid7(&entry.actor_id, "actor").unwrap();
        let key_id = parse_uuid7(&entry.key_id, "key").unwrap();
        let key = fact_crypto::SigningKey::from_seed(&seed).unwrap();
        let store = fact_store::Store::open(&entry.database).unwrap();
        let proposition = store
            .get_cose_by_id(ledger.as_bytes(), created.proposition_id.as_bytes())
            .unwrap()
            .unwrap();
        let parent_revision = store
            .get_cose_by_id(ledger.as_bytes(), created.revision_id.as_bytes())
            .unwrap()
            .unwrap();
        let prior_deliberation = store
            .get_cose_by_id(ledger.as_bytes(), created.deliberation_id.as_bytes())
            .unwrap()
            .unwrap();
        let runtime = crate::runtime::production_runtime();
        let branch_two_revision_id = uuid::Uuid::now_v7();
        let branch_two_revision = signed_envelope(
            branch_two_revision_id,
            ledger,
            "revision",
            actor,
            key_id,
            serde_json::json!({
                "proposition_id": created.proposition_id,
                "revision_id": branch_two_revision_id,
                "parent_revision_id": created.revision_id,
                "content": content_value(b"# Branch Two\n\nAccepted branch.\n"),
                "relationships": [],
                "reconciliation_manifest": null,
            }),
            vec![
                dependency_value(&proposition, "proposition").unwrap(),
                dependency_value(&parent_revision, "parent-revision").unwrap(),
            ],
            &key,
            runtime.as_ref(),
        )
        .unwrap();
        let branch_two_deliberation_id = uuid::Uuid::now_v7();
        let branch_two_deliberation = signed_envelope(
            branch_two_deliberation_id,
            ledger,
            "deliberation",
            actor,
            key_id,
            serde_json::json!({
                "deliberation_id": branch_two_deliberation_id,
                "proposition_id": created.proposition_id,
                "revision_id": branch_two_revision_id,
                "extends_deliberation_id": created.deliberation_id,
                "decision_rule": {"id":"unanimity","version":0,"parameters":{}},
                "join_policy": {"policy_version":0,"mode":"open","attestation_requirements":[]},
                "initial_participants": [{"actor_id": actor, "carried_decision_id": null}],
                "roster_governance": null,
                "opening_actor_id": actor,
                "comments_closed_on_settlement": true
            }),
            vec![
                dependency_value(&proposition, "proposition").unwrap(),
                dependency_value(&branch_two_revision, "revision").unwrap(),
                dependency_value(&prior_deliberation, "prior-deliberation").unwrap(),
            ],
            &key,
            runtime.as_ref(),
        )
        .unwrap();
        store
            .insert_authorized_bundle(&[branch_two_revision, branch_two_deliberation])
            .unwrap();
        create_decision_and_settlement(
            &store,
            ledger,
            actor,
            key_id,
            &key,
            branch_two_deliberation_id,
            branch_two_revision_id,
            "accepted",
            runtime.as_ref(),
            fact_store::ProjectedMode::Incremental,
        )
        .unwrap();
        drop(store);

        let conflicts =
            list_revision_conflicts(&entry, Some(&created.proposition_id.to_string()), false)
                .unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].resolution_inputs.conflict_triples.len(), 2);

        let resolved = resolve_revision_conflict(
            &entry,
            &seed,
            ResolveConflictInput {
                reference: Some(branch_one.revision_id.to_string()),
                content: ResolveContent::Derived {
                    markdown: b"# Merged\n\nResolved branch content.\n".to_vec(),
                },
            },
        )
        .unwrap();
        assert!(resolved.resolved);
        assert_eq!(resolved.proposition_id, created.proposition_id);
        assert_eq!(resolved.resolution_mode, "derive");
        assert_eq!(resolved.kept_revision_id, None);
        assert!(resolved.result_revision_id.is_some());
        assert_eq!(
            resolved.common_ancestor_revision_id,
            Some(created.revision_id)
        );
        assert_eq!(resolved.pending_participant_count, 1);
        assert_ne!(
            resolved.reconciliation_proposition_id,
            created.proposition_id
        );
        let result_revision_id = resolved.result_revision_id.unwrap();
        let conn = rusqlite::Connection::open(&entry.database).unwrap();
        let projected: (Vec<u8>, String, Vec<u8>) = conn
            .query_row(
                "SELECT affected_proposition_id,resolution_mode,result_revision_id FROM projected_reconciliation WHERE revision_id=?",
                [resolved.revision_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(projected.0, created.proposition_id.as_bytes());
        assert_eq!(projected.1, "derive");
        assert_eq!(projected.2, result_revision_id.as_bytes());
        drop(conn);

        accept_proposition(&entry, &seed, Some(&result_revision_id.to_string())).unwrap();
        accept_proposition(
            &entry,
            &seed,
            Some(&resolved.reconciliation_proposition_id.to_string()),
        )
        .unwrap();
        assert!(
            list_revision_conflicts(&entry, Some(&created.proposition_id.to_string()), false)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            list_revision_conflicts(&entry, Some(&created.proposition_id.to_string()), true)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn effective_content_ignores_ambiguous_pending_revision_heads() {
        let (_temp, entry, seed) = entry();
        let created = create_proposition(
            &entry,
            &seed,
            b"# Stable\n\nEffective version.\n",
            Some(DecisionOutcome::Accepted),
        )
        .unwrap();
        update_proposition_content(
            &entry,
            &seed,
            &created.revision_id.to_string(),
            b"# Branch One\n\nPending branch.\n",
        )
        .unwrap();
        let ledger = parse_uuid7(&entry.ledger_id, "ledger").unwrap();
        let actor = parse_uuid7(&entry.actor_id, "actor").unwrap();
        let key_id = parse_uuid7(&entry.key_id, "key").unwrap();
        let key = fact_crypto::SigningKey::from_seed(&seed).unwrap();
        let store = fact_store::Store::open(&entry.database).unwrap();
        let proposition = store
            .get_cose_by_id(ledger.as_bytes(), created.proposition_id.as_bytes())
            .unwrap()
            .unwrap();
        let parent_revision = store
            .get_cose_by_id(ledger.as_bytes(), created.revision_id.as_bytes())
            .unwrap()
            .unwrap();
        let runtime = crate::runtime::production_runtime();
        let branch_revision_id = uuid::Uuid::now_v7();
        let branch_revision = signed_envelope(
            branch_revision_id,
            ledger,
            "revision",
            actor,
            key_id,
            serde_json::json!({
                "proposition_id": created.proposition_id,
                "revision_id": branch_revision_id,
                "parent_revision_id": created.revision_id,
                "content": content_value(b"# Branch Two\n\nAnother pending branch.\n"),
                "relationships": [],
                "reconciliation_manifest": null,
            }),
            vec![
                dependency_value(&proposition, "proposition").unwrap(),
                dependency_value(&parent_revision, "parent-revision").unwrap(),
            ],
            &key,
            runtime.as_ref(),
        )
        .unwrap();
        store.insert_authorized_object(&branch_revision).unwrap();

        let effective = read_proposition_content(&entry, &created.reference()).unwrap();
        assert_eq!(effective.revision_id, created.revision_id);
        assert_eq!(effective.content, b"# Stable\n\nEffective version.\n");
        assert!(matches!(
            read_proposition_content_with_selection(
                &entry,
                &created.reference(),
                ContentSelection::Latest,
            ),
            Err(Error::AmbiguousReference(_))
        ));
    }

    trait ShortReference {
        fn reference(&self) -> String;
    }

    impl ShortReference for PropositionResult {
        fn reference(&self) -> String {
            crate::reference::short_uuid_reference(self.proposition_id)
        }
    }
}
