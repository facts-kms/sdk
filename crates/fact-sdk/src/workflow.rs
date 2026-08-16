//! High-level workflow operations.

use crate::{
    models::OperationReceipt,
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

pub use crate::attestation::{
    create_identity_attestation, create_identity_attestation_with_runtime,
    list_identity_attestations, read_identity_attestation, AttestationSubjectType,
    AttestationValidity, IdentityAttestationInput, IdentityAttestationRecord,
    ListIdentityAttestationsFilter,
};
pub use crate::commitment::{
    create_commitment, create_inclusion_proof, create_non_inclusion_proof, verify_commitment,
    CommitmentResult, CommitmentVerificationResult, InclusionProofResult, InclusionProofStep,
    NonInclusionProofResult,
};
pub use crate::conformance::{
    materialize_conformance, run_conformance, ConformanceLeafCheck, ConformanceReport,
    MaterializeConformanceResult,
};
pub use crate::decision::{
    create_decision, create_decision_with_runtime, DecisionInput,
    DecisionValue as CastDecisionValue,
};
pub use crate::delegation::{
    create_delegation, create_delegation_with_runtime, revoke_delegation,
    revoke_delegation_with_runtime, DelegationInput, DelegationRevocationInput,
};
pub use crate::directory::{
    add_directory_entry, add_directory_entry_with_runtime, export_directory, import_directory,
    list_directory, remove_directory_entry, resolve_directory_actor_reference,
    resolve_directory_key_reference, resolve_directory_reference, show_directory_entry,
    DirectoryAddInput, DirectoryAddResult, DirectoryEntry, DirectoryRemoveInput,
    DirectoryRemoveResult, DirectoryResolveResult, ExportDirectoryResult, ImportDirectoryResult,
};
pub use crate::discussion::{
    active_participants, create_comment, create_comment_with_runtime, join_deliberation,
    join_deliberation_with_runtime, leave_deliberation, leave_deliberation_with_runtime,
    list_comments as list_deliberation_comments,
    list_deliberations as list_proposition_deliberations, open_deliberation_for_revision,
    open_deliberation_for_revision_with_runtime, open_missing_deliberation,
    open_missing_deliberation_with_runtime, participant_changes, read_deliberation,
    show_deliberation, show_deliberation_by_id, CommentResult, CommentSummary,
    DeliberationOpenResult, DeliberationRepairResult, DeliberationSummary, DeliberationView,
    ParticipantChangeResult,
};
pub use crate::identity::{
    create_identity, create_identity_grant, create_identity_grant_with_runtime,
    create_identity_with_runtime, export_identity, import_identity, revoke_identity_grant,
    revoke_identity_grant_with_runtime, rotate_identity_key, rotate_identity_key_with_runtime,
    CreateIdentityInput, CreateIdentityResult, ExportIdentityResult, IdentityGrantResult,
    IdentityRevocationResult, IdentityRotationResult, ImportIdentityResult,
};
pub use crate::invitation::{
    create_invitation, create_invitation_with_runtime, list_invitations, read_invitation,
    update_invitation_lifecycle, update_invitation_lifecycle_with_runtime,
    InvitationLifecycleResult, InvitationResult, ListInvitationsFilter,
};
pub use crate::lifecycle::{
    archive_proposition, archive_proposition_with_runtime, restore_proposition,
    restore_proposition_with_runtime, unarchive_proposition, unarchive_proposition_with_runtime,
    withdraw_proposition, withdraw_proposition_with_runtime, PropositionLifecycleResult,
};
pub use crate::objects::{
    create_actor_key_binding_object, create_actor_key_binding_object_with_runtime,
    create_actor_object, create_actor_object_with_runtime, create_key_object,
    create_key_object_with_runtime, ActorKeyBindingObjectInput, ActorObjectInput, KeyObjectInput,
};
pub use crate::proposition::{
    accept_proposition, accept_proposition_with_runtime, create_derived_revision,
    create_derived_revision_with_runtime, create_proposition, create_proposition_with_runtime,
    create_reconciliation_proposition, create_reconciliation_proposition_with_runtime,
    decide_proposition, decide_proposition_with_runtime, find_propositions, history_ledger,
    history_ledger_page, list_propositions, list_propositions_page, list_revision_conflicts,
    pending_proposition_content, pending_proposition_count, pending_propositions,
    read_proposition_content, read_proposition_content_with_selection, reject_proposition,
    reject_proposition_with_runtime, resolve_revision_conflict,
    resolve_revision_conflict_with_runtime, search_proposition_content, show_proposition_overview,
    update_proposition_content, update_proposition_content_with_runtime, ContentSelection,
    DecisionOutcome, DerivedRevisionInput, HistoryItem, HistoryPage, ListPropositionStatus,
    ListPropositionsFilter, ListPropositionsPage, PropositionListItem, PropositionResult,
    ReconciliationConflictInput, ReconciliationInput, ReconciliationResult, ResolveConflictInput,
    ResolveConflictResult, ResolveContent, ResolvedContent, RevisionConflictGroup,
    RevisionConflictItem, RevisionConflictResolutionInputs, SearchResult, ShowMatchedObject,
    ShowOverview, ShowOverviewInput, ShowOverviewPage, ShowPendingOverview,
};
pub use crate::provenance::{
    create_proposition_provenance, create_provenance, create_provenance_with_runtime,
    list_provenance, read_proposition_provenance, read_provenance, ListProvenanceFilter,
    ProvenanceCopyMode, ProvenanceInput, ProvenanceRecord,
};
pub use crate::relationship::{
    create_application_relationship, create_application_relationship_with_runtime,
    create_protocol_relationship, create_protocol_relationship_with_runtime, list_relationships,
    read_relationship, ApplicationRelationshipInput, ListRelationshipsFilter,
    ProtocolRelationshipInput, RelationshipRecord,
};
pub use crate::search::{
    query_search, search_comments, search_deliberations, search_revisions, CommentSearchFilter,
    DeliberationSearchFilter, QuerySearchHit, QuerySearchResult, RevisionSearchFilter,
    SearchResult as ObjectSearchResult,
};
pub use crate::settlement::{
    create_settlement, create_settlement_with_runtime, SettlementInput, SettlementProducerType,
};
pub use crate::standing::{
    create_standing_participant_change, create_standing_participant_change_with_runtime,
    update_standing_participants, update_standing_participants_with_runtime,
    StandingParticipantChangeInput, StandingParticipantOperation,
};
pub use crate::state::{rebuild_state, rebuild_state_at, StateRebuildResult};
pub use crate::sync::{
    decode_bundle_or_snapshot_objects, encode_bundle, export_object, import_object_bytes,
    list_objects, list_objects_page, pull_bundle_from_store, pull_bundle_from_store_with_options,
    push_bundle_to_store, read_object, validate_object_bytes, write_bundle_from_store,
    write_pull_bundle_from_store, write_pull_bundle_from_store_with_options, ExportBundleResult,
    ExportObjectResult, ImportObjectsResult, ListObjectsOptions, ObjectValidationResult,
    PagedListObjectsResult, PullBundleOptions, PullBundleResult, ReadObjectResult,
    WrittenPullBundleResult,
};
pub use crate::tags::{
    export_tags, import_tags, list_tags, mutate_tags, normalize_tags,
    search_proposition_content_by_tags, search_tags, show_tags, ExportTagsResult, ImportTagsResult,
    TagListItem, TagOperation, TagResult, TagSearchMatch, TagSearchResult,
};
pub use crate::validation::{verify_settlement_object, SettlementValidationResult};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct BootstrapLedgerInput {
    pub namespace: String,
    pub created_at: String,
    pub seed: [u8; 32],
    pub nonce: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct BootstrapLedgerOutput {
    pub ledger_id: String,
    pub genesis_id: String,
    pub actor_id: String,
    pub key_id: String,
    pub receipts: Vec<OperationReceipt>,
    pub cose_objects: Vec<Vec<u8>>,
}

/// Create the v0 bootstrap ledger object set in a store.
pub fn create_ledger(
    store: &fact_store::Store,
    input: BootstrapLedgerInput,
) -> Result<BootstrapLedgerOutput> {
    let runtime = production_runtime();
    create_ledger_with_runtime(store, input, runtime.as_ref())
}

/// Create the v0 bootstrap ledger object set using an explicit runtime for IDs.
pub fn create_ledger_with_runtime(
    store: &fact_store::Store,
    input: BootstrapLedgerInput,
    runtime: &dyn SdkRuntime,
) -> Result<BootstrapLedgerOutput> {
    let result = store.bootstrap_ledger_with_ids(
        &input.namespace,
        &input.created_at,
        input.seed,
        input.nonce,
        fact_store::BootstrapIds {
            ledger_id: runtime.next_uuid_v7()?,
            actor_id: runtime.next_uuid_v7()?,
            key_id: runtime.next_uuid_v7()?,
            binding_id: runtime.next_uuid_v7()?,
            grant_id: runtime.next_uuid_v7()?,
            assertion_id: runtime.next_uuid_v7()?,
            genesis_id: runtime.next_uuid_v7()?,
        },
    )?;
    let receipts = result
        .cose_objects
        .iter()
        .zip(result.object_hashes.iter())
        .map(|(bytes, hash)| {
            let cose = fact_crypto::decode_sign1(bytes)?;
            let value: serde_json::Value = serde_json::from_slice(&cose.payload)
                .map_err(|error| Error::Validation(error.to_string()))?;
            Ok(OperationReceipt {
                object_id: value
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| Error::Validation("missing object id".into()))?
                    .to_owned(),
                content_hash: hash.hex(),
                object_type: value
                    .get("object_type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| Error::Validation("missing object type".into()))?
                    .to_owned(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(BootstrapLedgerOutput {
        ledger_id: result.ledger_id.to_string(),
        genesis_id: result.genesis_id.to_string(),
        actor_id: result.actor_id.to_string(),
        key_id: result.key_id.to_string(),
        receipts,
        cose_objects: result.cose_objects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_ledger_bootstraps_signed_authority_cycle() {
        let store = fact_store::Store::open_memory().unwrap();
        let output = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed: [7; 32],
                nonce: [9; 16],
            },
        )
        .unwrap();

        assert_eq!(output.receipts.len(), 6);
        assert_eq!(output.cose_objects.len(), 6);
        let ledger_id = uuid::Uuid::parse_str(&output.ledger_id).unwrap();
        let objects = store.list_object_summaries(ledger_id.as_bytes()).unwrap();
        assert_eq!(objects.len(), 3);
        assert!(objects.iter().any(|object| object.object_type == "genesis"));
        assert!(store
            .list_identity_objects()
            .unwrap()
            .iter()
            .any(|(_, _, kind)| kind == "actor"));
    }
}
