use fact_core::Hash;
use rusqlite::{params, params_from_iter, types::Value, Connection, ErrorCode};
#[cfg(debug_assertions)]
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

const INDEXED_PROPOSITION_VERSION: &str = "indexed-proposition-v0";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("canonicalization: {0}")]
    Canonical(#[from] fact_canonical::Error),
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("object already exists")]
    Duplicate,
    #[error("canonical payload does not match COSE embedded payload")]
    PayloadMismatch,
    #[error("content hash mismatch")]
    HashMismatch,
    #[error("invalid object UUID field: {0}")]
    InvalidUuid(&'static str),
    #[error("invalid ledger namespace")]
    InvalidNamespace,
    #[error("schema: {0}")]
    Schema(#[from] fact_schema::Error),
    #[error("COSE: {0}")]
    Cose(#[from] fact_crypto::Error),
    #[error("invalid JSON metadata")]
    Metadata,
    #[error("signing key dependency is unavailable")]
    MissingKey,
    #[error("invalid object signature")]
    InvalidSignature,
    #[error("required dependency is unavailable")]
    MissingDependency,
    #[error("dependency content hash does not match stored object")]
    DependencyHashMismatch,
    #[error("invalid dependency record")]
    InvalidDependency,
    #[error("object ledger is unavailable")]
    MissingLedger,
    #[error("typed projected does not match canonical object")]
    ProjectedMismatch,
    #[error("derived state projected is invalid")]
    StateProjected,
    #[error("public key must contain exactly 32 bytes")]
    InvalidPublicKey,
    #[error("object is unauthorized at its causal point")]
    Unauthorized,
    #[error("authority validity is time-uncertain")]
    TimeUncertain,
    #[error("object lineage cannot establish the required target")]
    InvalidLineage,
    #[error("object is rejected by local protocol storage policy")]
    PolicyRejected,
    #[error("search index: {0}")]
    SearchIndex(&'static str),
    #[error("indexed proposition state is stale")]
    IndexedPropositionStale,
}
pub struct Store {
    conn: Connection,
}

/// Projected update strategy for transaction-level object inserts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectedMode {
    /// Update affected projecteds incrementally when supported. Object
    /// families without an incremental projector currently fall back to a full
    /// rebuild to preserve read-model correctness.
    Incremental,
    /// Rebuild all projecteds before the insert transaction commits.
    FullRebuild,
    /// Commit canonical objects without refreshing projecteds. Call
    /// [`Store::rebuild_projecteds`] before serving projected-backed reads.
    Defer,
}

#[cfg(debug_assertions)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreDebugMetrics {
    pub list_objects: u64,
    pub list_object_hashes: u64,
    pub get_payload: u64,
    pub list_effective_state: u64,
    pub list_knowledge_effective_revision_ids: u64,
    pub list_knowledge_proposition_ids: u64,
    pub list_revision_search_payloads: u64,
    pub list_deliberation_projecteds: u64,
    pub list_lifecycle_rows: u64,
    pub list_object_payloads: u64,
    pub list_object_payloads_by_type: u64,
    pub list_deliberation_objects_by_type: u64,
    pub list_markdown_documents: u64,
    pub list_objects_by_deliberation: u64,
    pub list_objects_with_dependencies: u64,
    pub list_objects_with_dependencies_page: u64,
    pub list_dependency_closure_for_objects: u64,
    pub search_index_rebuilds: u64,
    pub search_index_candidate_rows: u64,
    pub projected_rebuilds: u64,
}

#[cfg(debug_assertions)]
struct StoreDebugMetricCounters {
    list_objects: Cell<u64>,
    list_object_hashes: Cell<u64>,
    get_payload: Cell<u64>,
    list_effective_state: Cell<u64>,
    list_knowledge_effective_revision_ids: Cell<u64>,
    list_knowledge_proposition_ids: Cell<u64>,
    list_revision_search_payloads: Cell<u64>,
    list_deliberation_projecteds: Cell<u64>,
    list_lifecycle_rows: Cell<u64>,
    list_object_payloads: Cell<u64>,
    list_object_payloads_by_type: Cell<u64>,
    list_deliberation_objects_by_type: Cell<u64>,
    list_markdown_documents: Cell<u64>,
    list_objects_by_deliberation: Cell<u64>,
    list_objects_with_dependencies: Cell<u64>,
    list_objects_with_dependencies_page: Cell<u64>,
    list_dependency_closure_for_objects: Cell<u64>,
    search_index_rebuilds: Cell<u64>,
    search_index_candidate_rows: Cell<u64>,
    projected_rebuilds: Cell<u64>,
}

#[cfg(debug_assertions)]
impl StoreDebugMetricCounters {
    const fn new() -> Self {
        Self {
            list_objects: Cell::new(0),
            list_object_hashes: Cell::new(0),
            get_payload: Cell::new(0),
            list_effective_state: Cell::new(0),
            list_knowledge_effective_revision_ids: Cell::new(0),
            list_knowledge_proposition_ids: Cell::new(0),
            list_revision_search_payloads: Cell::new(0),
            list_deliberation_projecteds: Cell::new(0),
            list_lifecycle_rows: Cell::new(0),
            list_object_payloads: Cell::new(0),
            list_object_payloads_by_type: Cell::new(0),
            list_deliberation_objects_by_type: Cell::new(0),
            list_markdown_documents: Cell::new(0),
            list_objects_by_deliberation: Cell::new(0),
            list_objects_with_dependencies: Cell::new(0),
            list_objects_with_dependencies_page: Cell::new(0),
            list_dependency_closure_for_objects: Cell::new(0),
            search_index_rebuilds: Cell::new(0),
            search_index_candidate_rows: Cell::new(0),
            projected_rebuilds: Cell::new(0),
        }
    }

    fn reset(&self) {
        self.list_objects.set(0);
        self.list_object_hashes.set(0);
        self.get_payload.set(0);
        self.list_effective_state.set(0);
        self.list_knowledge_effective_revision_ids.set(0);
        self.list_knowledge_proposition_ids.set(0);
        self.list_revision_search_payloads.set(0);
        self.list_deliberation_projecteds.set(0);
        self.list_lifecycle_rows.set(0);
        self.list_object_payloads.set(0);
        self.list_object_payloads_by_type.set(0);
        self.list_deliberation_objects_by_type.set(0);
        self.list_markdown_documents.set(0);
        self.list_objects_by_deliberation.set(0);
        self.list_objects_with_dependencies.set(0);
        self.list_objects_with_dependencies_page.set(0);
        self.list_dependency_closure_for_objects.set(0);
        self.search_index_rebuilds.set(0);
        self.search_index_candidate_rows.set(0);
        self.projected_rebuilds.set(0);
    }

    fn snapshot(&self) -> StoreDebugMetrics {
        StoreDebugMetrics {
            list_objects: self.list_objects.get(),
            list_object_hashes: self.list_object_hashes.get(),
            get_payload: self.get_payload.get(),
            list_effective_state: self.list_effective_state.get(),
            list_knowledge_effective_revision_ids: self.list_knowledge_effective_revision_ids.get(),
            list_knowledge_proposition_ids: self.list_knowledge_proposition_ids.get(),
            list_revision_search_payloads: self.list_revision_search_payloads.get(),
            list_deliberation_projecteds: self.list_deliberation_projecteds.get(),
            list_lifecycle_rows: self.list_lifecycle_rows.get(),
            list_object_payloads: self.list_object_payloads.get(),
            list_object_payloads_by_type: self.list_object_payloads_by_type.get(),
            list_deliberation_objects_by_type: self.list_deliberation_objects_by_type.get(),
            list_markdown_documents: self.list_markdown_documents.get(),
            list_objects_by_deliberation: self.list_objects_by_deliberation.get(),
            list_objects_with_dependencies: self.list_objects_with_dependencies.get(),
            list_objects_with_dependencies_page: self.list_objects_with_dependencies_page.get(),
            list_dependency_closure_for_objects: self.list_dependency_closure_for_objects.get(),
            search_index_rebuilds: self.search_index_rebuilds.get(),
            search_index_candidate_rows: self.search_index_candidate_rows.get(),
            projected_rebuilds: self.projected_rebuilds.get(),
        }
    }
}

#[cfg(debug_assertions)]
thread_local! {
    static STORE_DEBUG_METRICS: StoreDebugMetricCounters = const { StoreDebugMetricCounters::new() };
}
struct ValidatedObject {
    id: Vec<u8>,
    ledger: Vec<u8>,
    object_type: String,
    schema: String,
    actor: Vec<u8>,
    key: Vec<u8>,
    canonical: Vec<u8>,
    hash: Hash,
    cose: Vec<u8>,
    dependencies: Vec<(Vec<u8>, Hash, String)>,
}
type StagedObjects = std::collections::HashMap<Vec<u8>, (Vec<u8>, Option<Vec<u8>>)>;
#[derive(Clone, Debug)]
pub struct BootstrapResult {
    pub ledger_id: uuid::Uuid,
    pub genesis_id: uuid::Uuid,
    pub actor_id: uuid::Uuid,
    pub key_id: uuid::Uuid,
    pub object_hashes: Vec<Hash>,
    pub cose_objects: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
pub struct BootstrapIds {
    pub ledger_id: uuid::Uuid,
    pub actor_id: uuid::Uuid,
    pub key_id: uuid::Uuid,
    pub binding_id: uuid::Uuid,
    pub grant_id: uuid::Uuid,
    pub assertion_id: uuid::Uuid,
    pub genesis_id: uuid::Uuid,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DeliberationProjected {
    pub deliberation_id: fact_core::ObjectId,
    pub revision_id: fact_core::ObjectId,
    pub participant_count: usize,
    pub applicable_decision_count: usize,
    pub consensus: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReconciliationEffectiveCandidate {
    affected_proposition: fact_core::ObjectId,
    common_ancestor: fact_core::ObjectId,
    resolution_mode: String,
    selected_revision: Option<fact_core::ObjectId>,
    result_revision: Option<fact_core::ObjectId>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct EffectiveProjected {
    pub proposition_id: fact_core::ObjectId,
    pub status: String,
    pub revision_id: Option<fact_core::ObjectId>,
    pub deliberation_id: Option<fact_core::ObjectId>,
    pub settlement_id: Option<fact_core::ObjectId>,
    pub withdrawal_status: String,
    pub archival_status: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropositionListProjected {
    pub proposition_id: uuid::Uuid,
    pub status: String,
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
    pub summary_text: Option<String>,
    pub summary_revision_payload: Option<Vec<u8>>,
    pub withdrawal_status: String,
    pub archival_status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedPropositionMetadata {
    pub proposition_id: uuid::Uuid,
    pub status: String,
    pub effective_reason: String,
    pub effective_revision_id: Option<uuid::Uuid>,
    pub effective_deliberation_id: Option<uuid::Uuid>,
    pub settlement_id: Option<uuid::Uuid>,
    pub latest_revision_id: Option<uuid::Uuid>,
    pub latest_revision_status: String,
    pub pending_revision_id: Option<uuid::Uuid>,
    pub pending_deliberation_id: Option<uuid::Uuid>,
    pub pending_participant_count: usize,
    pub current_actor_pending: bool,
    pub has_pending_revision: bool,
    pub withdrawal_status: String,
    pub archival_status: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropositionLifecycleFilter {
    Withdrawn,
    Archived,
}

struct IndexedPropositionListQuery<'a> {
    status: Option<&'a str>,
    include_pending_overlay: bool,
    withdrawal_status: Option<&'a str>,
    archival_status: Option<&'a str>,
    after_proposition: Option<&'a [u8; 16]>,
    offset: usize,
    limit: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectReferenceMatch {
    pub object_id: uuid::Uuid,
    pub content_hash: Hash,
    pub object_type: String,
    ledger_id: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionRow {
    pub revision_id: uuid::Uuid,
    pub proposition_id: uuid::Uuid,
    pub parent_revision_id: Option<uuid::Uuid>,
    pub content_hash: Hash,
    pub object_id: uuid::Uuid,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliberationRow {
    pub deliberation_id: uuid::Uuid,
    pub proposition_id: uuid::Uuid,
    pub revision_id: uuid::Uuid,
    pub settled: bool,
    pub content_hash: Hash,
    pub object_id: uuid::Uuid,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectPayloadRow {
    pub object_id: uuid::Uuid,
    pub content_hash: Hash,
    pub object_type: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectSummaryRow {
    pub object_id: uuid::Uuid,
    pub content_hash: Hash,
    pub object_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionSearchPayloadRow {
    pub object_id: uuid::Uuid,
    pub content_hash: Hash,
    pub payload: Vec<u8>,
    pub proposition_id: uuid::Uuid,
    pub effective_status: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleRow {
    pub object_id: uuid::Uuid,
    pub object_type: String,
    pub target_id: Option<uuid::Uuid>,
    pub dimension: Option<String>,
    pub operation: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenancePayloadRow {
    pub object_id: uuid::Uuid,
    pub content_hash: Hash,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagExtensionEventInput {
    pub event_id: uuid::Uuid,
    pub ledger_id: uuid::Uuid,
    pub proposition_id: uuid::Uuid,
    pub actor_id: uuid::Uuid,
    pub signing_key_id: uuid::Uuid,
    pub operation: String,
    pub tags: Vec<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagExtensionRow {
    pub event_id: uuid::Uuid,
    pub ledger_id: uuid::Uuid,
    pub proposition_id: uuid::Uuid,
    pub operation: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryExtensionEventInput {
    pub event_id: uuid::Uuid,
    pub ledger_id: uuid::Uuid,
    pub actor_id: uuid::Uuid,
    pub signing_key_id: uuid::Uuid,
    pub target_actor_id: uuid::Uuid,
    pub target_key_id: Option<uuid::Uuid>,
    pub operation: String,
    pub display_name: Option<String>,
    pub alias: Option<String>,
    pub actor_type: Option<String>,
    pub role: Option<String>,
    pub source: Option<String>,
    pub verified_by: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryExtensionRow {
    pub event_id: uuid::Uuid,
    pub ledger_id: uuid::Uuid,
    pub target_actor_id: uuid::Uuid,
    pub target_key_id: Option<uuid::Uuid>,
    pub operation: String,
    pub display_name: Option<String>,
    pub alias: Option<String>,
    pub actor_type: Option<String>,
    pub role: Option<String>,
    pub source: Option<String>,
    pub verified_by: Option<String>,
    pub created_at: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedDirectoryRow {
    pub ledger_id: uuid::Uuid,
    pub target_actor_id: uuid::Uuid,
    pub target_key_id: Option<uuid::Uuid>,
    pub display_name: String,
    pub alias: Option<String>,
    pub actor_type: Option<String>,
    pub role: Option<String>,
    pub source: Option<String>,
    pub verified_by: Option<String>,
    pub event_id: uuid::Uuid,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantDecisionRow {
    pub actor_id: uuid::Uuid,
    pub active: bool,
    pub decision: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionRow {
    pub decision_id: uuid::Uuid,
    pub deliberation_id: uuid::Uuid,
    pub participant_actor_id: uuid::Uuid,
    pub value: String,
    pub content_hash: Hash,
    pub payload: Vec<u8>,
    pub cose: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchIndexStatus {
    pub ledger_id: uuid::Uuid,
    pub canonical_document_count: usize,
    pub indexed_document_count: usize,
    pub stale: bool,
}

#[derive(Clone, Copy, Debug)]
struct SearchIndexMeta {
    canonical_document_count: i64,
    indexed_document_count: i64,
    total_token_count: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchIndexHit {
    pub object_id: uuid::Uuid,
    pub object_type: String,
    pub content_hash: Hash,
    pub score: String,
    pub extraction_profile: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveRevisionSearchRow {
    pub revision_id: uuid::Uuid,
    pub proposition_id: uuid::Uuid,
    pub status: String,
}

#[derive(Clone, Debug)]
struct RevisionProjectedRow {
    revision_id: uuid::Uuid,
    proposition_id: uuid::Uuid,
    parent_revision_id: Option<uuid::Uuid>,
    payload: Vec<u8>,
}

#[derive(Clone, Debug)]
struct DeliberationProjectedRow {
    deliberation_id: uuid::Uuid,
    proposition_id: uuid::Uuid,
    revision_id: uuid::Uuid,
    settled: bool,
}

#[derive(Clone, Debug)]
struct ConsensusProjectedRow {
    deliberation_id: uuid::Uuid,
    revision_id: uuid::Uuid,
    consensus: String,
}

struct PropositionActivityProjected {
    latest_revision_id: Option<uuid::Uuid>,
    latest_revision_status: String,
    pending_revision_id: Option<uuid::Uuid>,
    pending_deliberation_id: Option<uuid::Uuid>,
    pending_participant_count: usize,
    current_actor_pending: bool,
    has_pending_revision: bool,
}

struct MarkdownSearchDocument {
    object_id: uuid::Uuid,
    object_type: String,
    content_hash: Hash,
    payload: Vec<u8>,
    markdown: Vec<u8>,
}

/// Local SQLite durability policy. This affects persistence behavior only;
/// it never changes canonical object bytes or protocol state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    Normal,
    Full,
}

impl Store {
    #[cfg(debug_assertions)]
    pub fn reset_debug_metrics() {
        STORE_DEBUG_METRICS.with(StoreDebugMetricCounters::reset);
    }

    #[cfg(debug_assertions)]
    pub fn debug_metrics() -> StoreDebugMetrics {
        STORE_DEBUG_METRICS.with(StoreDebugMetricCounters::snapshot)
    }

    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        Self::open_with_durability(path, Durability::Normal)
    }
    pub fn open_with_durability(
        path: impl AsRef<std::path::Path>,
        durability: Durability,
    ) -> Result<Self, Error> {
        let c = Connection::open(path)?;
        Self::configure(&c, durability)?;
        let s = Self { conn: c };
        s.migrate()?;
        Ok(s)
    }
    pub fn open_memory() -> Result<Self, Error> {
        Self::open_memory_with_durability(Durability::Normal)
    }
    pub fn open_memory_with_durability(durability: Durability) -> Result<Self, Error> {
        let c = Connection::open_in_memory()?;
        Self::configure(&c, durability)?;
        let s = Self { conn: c };
        s.migrate()?;
        Ok(s)
    }
    pub fn backup_to(&self, path: impl AsRef<std::path::Path>) -> Result<(), Error> {
        self.conn.backup(rusqlite::DatabaseName::Main, path, None)?;
        Ok(())
    }
    pub fn restore_from(&mut self, path: impl AsRef<std::path::Path>) -> Result<(), Error> {
        self.conn.restore(
            rusqlite::DatabaseName::Main,
            path,
            None::<fn(rusqlite::backup::Progress)>,
        )?;
        self.migrate()
    }
    fn configure(c: &Connection, durability: Durability) -> Result<(), rusqlite::Error> {
        let synchronous = match durability {
            Durability::Normal => "NORMAL",
            Durability::Full => "FULL",
        };
        c.execute_batch(&format!(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous={synchronous}; PRAGMA busy_timeout=5000;"
        ))?;
        c.execute_batch(
            "CREATE VIRTUAL TABLE temp.__facts_fts5_capability_check USING fts5(value); DROP TABLE temp.__facts_fts5_capability_check;",
        )?;
        Ok(())
    }
    fn migrate(&self) -> Result<(), Error> {
        self.rename_legacy_projection_tables()?;
        self.conn
            .execute_batch(include_str!("../../../migrations/0001_initial.sql"))?;
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_migration (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL); INSERT OR IGNORE INTO schema_migration(version,applied_at) VALUES(1,'2026-07-27T00:00:00.000Z'); INSERT OR IGNORE INTO schema_migration(version,applied_at) VALUES(2,'2026-07-27T00:00:00.000Z');")?;
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS ledger (ledger_id BLOB PRIMARY KEY, namespace TEXT NOT NULL, protocol_version TEXT NOT NULL); CREATE TABLE IF NOT EXISTS protocol_object (object_id BLOB PRIMARY KEY, ledger_id BLOB, object_type TEXT NOT NULL, schema_version TEXT NOT NULL, actor_id BLOB NOT NULL, signing_key_id BLOB NOT NULL, payload BLOB NOT NULL, content_hash BLOB NOT NULL UNIQUE, cose BLOB NOT NULL); CREATE TABLE IF NOT EXISTS object_dependency (object_id BLOB NOT NULL REFERENCES protocol_object(object_id), dependency_id BLOB NOT NULL, content_hash BLOB NOT NULL, role TEXT NOT NULL, PRIMARY KEY(object_id,dependency_id)); CREATE TABLE IF NOT EXISTS key_material (key_id BLOB PRIMARY KEY, public_key BLOB NOT NULL); CREATE TABLE IF NOT EXISTS protocol_relationship (object_id BLOB PRIMARY KEY REFERENCES protocol_object(object_id), ledger_id BLOB, object_type TEXT NOT NULL, source_object_id BLOB NOT NULL, relationship TEXT NOT NULL, target_object_ids BLOB NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS object_receipt (receipt_id BLOB PRIMARY KEY, object_id BLOB NOT NULL, content_hash BLOB NOT NULL, disposition_code TEXT NOT NULL, evaluated_at TEXT NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_object (object_id BLOB PRIMARY KEY, ledger_id BLOB, object_type TEXT NOT NULL, content_hash BLOB NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_consensus (deliberation_id BLOB PRIMARY KEY, revision_id BLOB NOT NULL, participant_count INTEGER NOT NULL, applicable_decision_count INTEGER NOT NULL, consensus TEXT NOT NULL, projected_version TEXT NOT NULL); CREATE INDEX IF NOT EXISTS protocol_object_ledger ON protocol_object(ledger_id); CREATE INDEX IF NOT EXISTS protocol_object_type ON protocol_object(object_type); CREATE INDEX IF NOT EXISTS protocol_relationship_source ON protocol_relationship(source_object_id);")?;
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS projected_actor (actor_id BLOB PRIMARY KEY, actor_type TEXT NOT NULL, object_id BLOB NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_key (key_id BLOB PRIMARY KEY, purpose TEXT NOT NULL, public_key BLOB NOT NULL, object_id BLOB NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_binding (binding_id BLOB PRIMARY KEY, actor_id BLOB NOT NULL, key_id BLOB NOT NULL, permitted_purpose TEXT NOT NULL, object_id BLOB NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_authority (grant_id BLOB NOT NULL, capability TEXT NOT NULL, receiving_actor_id BLOB NOT NULL, scope TEXT NOT NULL, revoked INTEGER NOT NULL, object_id BLOB NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(grant_id,capability)); CREATE TABLE IF NOT EXISTS projected_revision (revision_id BLOB PRIMARY KEY, proposition_id BLOB NOT NULL, parent_revision_id BLOB, content_hash BLOB NOT NULL, object_id BLOB NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_deliberation (deliberation_id BLOB PRIMARY KEY, proposition_id BLOB NOT NULL, revision_id BLOB NOT NULL, settled INTEGER NOT NULL, object_id BLOB NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_deliberation_object (object_id BLOB PRIMARY KEY, ledger_id BLOB NOT NULL, deliberation_id BLOB NOT NULL, object_type TEXT NOT NULL, created_at TEXT NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_standing_change (object_id BLOB PRIMARY KEY, ledger_id BLOB NOT NULL, proposition_id BLOB NOT NULL, participant_actor_id BLOB NOT NULL, operation TEXT NOT NULL, predecessor_change_id BLOB, changed_by_actor_id BLOB NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_participant (deliberation_id BLOB NOT NULL, actor_id BLOB NOT NULL, active INTEGER NOT NULL, source_object_id BLOB, projected_version TEXT NOT NULL, PRIMARY KEY(deliberation_id,actor_id)); CREATE TABLE IF NOT EXISTS projected_decision (decision_id BLOB PRIMARY KEY, deliberation_id BLOB NOT NULL, participant_actor_id BLOB NOT NULL, value TEXT NOT NULL, supersedes TEXT NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_lifecycle (object_id BLOB PRIMARY KEY, object_type TEXT NOT NULL, target_id BLOB, dimension TEXT, operation TEXT NOT NULL, effective_at TEXT, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_attestation (object_id BLOB PRIMARY KEY, ledger_id BLOB NOT NULL, subject_type TEXT NOT NULL, subject_id BLOB NOT NULL, claim_type TEXT NOT NULL, created_at TEXT NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_invitation (object_id BLOB PRIMARY KEY, ledger_id BLOB NOT NULL, proposition_id BLOB, deliberation_id BLOB, invited_actor_id BLOB NOT NULL, created_at TEXT NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_relationship_target (object_id BLOB NOT NULL, target_object_id BLOB NOT NULL, PRIMARY KEY(object_id,target_object_id)); CREATE TABLE IF NOT EXISTS projected_provenance (object_id BLOB PRIMARY KEY, ledger_id BLOB NOT NULL, proposition_id BLOB NOT NULL, source_ledger_id BLOB NOT NULL, copy_mode TEXT NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_pending (pending_id BLOB PRIMARY KEY, object_id BLOB NOT NULL, kind TEXT NOT NULL, reason TEXT NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_reconciliation (revision_id BLOB PRIMARY KEY, affected_proposition_id BLOB NOT NULL, common_ancestor_revision_id BLOB NOT NULL, conflict_set_hash BLOB NOT NULL, resolution_mode TEXT NOT NULL, selected_revision_id BLOB, result_revision_id BLOB, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_roster (deliberation_id BLOB PRIMARY KEY, selection_mode TEXT NOT NULL, source_deliberation_ids TEXT NOT NULL, selected_participant_ids TEXT NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_export_object (ledger_id BLOB NOT NULL, object_id BLOB NOT NULL, content_hash BLOB NOT NULL, object_type TEXT NOT NULL, PRIMARY KEY(ledger_id,object_id)); CREATE TABLE IF NOT EXISTS extension_event (event_id BLOB PRIMARY KEY, ledger_id BLOB NOT NULL, extension_name TEXT NOT NULL, target_id BLOB NOT NULL, event_type TEXT NOT NULL, actor_id BLOB NOT NULL, signing_key_id BLOB NOT NULL, created_at TEXT NOT NULL, content_hash BLOB NOT NULL UNIQUE, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS projected_tag (ledger_id BLOB NOT NULL, proposition_id BLOB NOT NULL, tag TEXT NOT NULL, event_id BLOB NOT NULL, PRIMARY KEY(ledger_id,proposition_id,tag)); CREATE TABLE IF NOT EXISTS projected_directory (ledger_id BLOB NOT NULL, target_actor_id BLOB NOT NULL, target_key_id BLOB, display_name TEXT NOT NULL, alias TEXT, actor_type TEXT, role TEXT, source TEXT, verified_by TEXT, event_id BLOB NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(ledger_id,target_actor_id));")?;
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS projected_effective (proposition_id BLOB PRIMARY KEY, status TEXT NOT NULL, revision_id BLOB, deliberation_id BLOB, settlement_id BLOB, withdrawal_status TEXT NOT NULL DEFAULT 'active', archival_status TEXT NOT NULL DEFAULT 'visible', reason TEXT NOT NULL, projected_version TEXT NOT NULL);")?;
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS indexed_proposition (proposition_id BLOB PRIMARY KEY, ledger_id BLOB NOT NULL, status TEXT NOT NULL, effective_revision_id BLOB, effective_deliberation_id BLOB, settlement_id BLOB, withdrawal_status TEXT NOT NULL, archival_status TEXT NOT NULL, effective_reason TEXT NOT NULL, latest_revision_id BLOB, latest_revision_status TEXT NOT NULL, pending_revision_id BLOB, pending_deliberation_id BLOB, pending_participant_count INTEGER NOT NULL, has_pending_revision INTEGER NOT NULL, summary_text TEXT, summary_revision_id BLOB, indexed_version TEXT NOT NULL); CREATE TABLE IF NOT EXISTS indexed_proposition_meta (ledger_id BLOB PRIMARY KEY, proposition_count INTEGER NOT NULL, effective_count INTEGER NOT NULL, indexed_count INTEGER NOT NULL, stale_count INTEGER NOT NULL, indexed_version TEXT NOT NULL, refreshed_at TEXT NOT NULL);")?;
        for (column, definition) in [
            ("withdrawal_status", "TEXT NOT NULL DEFAULT 'active'"),
            ("archival_status", "TEXT NOT NULL DEFAULT 'visible'"),
        ] {
            let present: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('projected_effective') WHERE name=?",
                [column],
                |row| row.get(0),
            )?;
            if present == 0 {
                self.conn.execute_batch(&format!(
                    "ALTER TABLE projected_effective ADD COLUMN {column} {definition}"
                ))?;
            }
        }
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS search_document (content_hash BLOB PRIMARY KEY, ledger_id BLOB NOT NULL, object_id BLOB NOT NULL, object_type TEXT NOT NULL, extracted_text TEXT NOT NULL, token_count INTEGER NOT NULL, term_frequencies TEXT NOT NULL, extraction_profile TEXT NOT NULL); CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(ledger_id UNINDEXED, content_hash UNINDEXED, extracted_text, tokenize='unicode61'); CREATE TABLE IF NOT EXISTS search_index_meta (ledger_id BLOB PRIMARY KEY, canonical_document_count INTEGER NOT NULL, indexed_document_count INTEGER NOT NULL, total_token_count INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS search_term_stat (ledger_id BLOB NOT NULL, term TEXT NOT NULL, document_frequency INTEGER NOT NULL, PRIMARY KEY(ledger_id,term)); CREATE INDEX IF NOT EXISTS search_document_ledger_hash ON search_document(ledger_id,content_hash); CREATE INDEX IF NOT EXISTS search_document_ledger_type_hash ON search_document(ledger_id,object_type,content_hash); CREATE INDEX IF NOT EXISTS search_document_ledger_object ON search_document(ledger_id,object_id);")?;
        self.conn.execute_batch("CREATE INDEX IF NOT EXISTS protocol_object_ledger_hash ON protocol_object(ledger_id,content_hash); CREATE INDEX IF NOT EXISTS protocol_object_ledger_type_hash ON protocol_object(ledger_id,object_type,content_hash); CREATE INDEX IF NOT EXISTS protocol_object_ledger_type_id ON protocol_object(ledger_id,object_type,object_id); CREATE INDEX IF NOT EXISTS projected_revision_proposition_revision ON projected_revision(proposition_id,revision_id); CREATE INDEX IF NOT EXISTS projected_revision_parent ON projected_revision(parent_revision_id); CREATE INDEX IF NOT EXISTS projected_deliberation_proposition_revision ON projected_deliberation(proposition_id,revision_id); CREATE INDEX IF NOT EXISTS projected_deliberation_settled_proposition ON projected_deliberation(settled,proposition_id,revision_id,deliberation_id); CREATE INDEX IF NOT EXISTS projected_deliberation_object_filter ON projected_deliberation_object(ledger_id,deliberation_id,object_type); CREATE INDEX IF NOT EXISTS projected_deliberation_object_deliberation_type ON projected_deliberation_object(deliberation_id,object_type,object_id); CREATE INDEX IF NOT EXISTS projected_decision_deliberation_actor ON projected_decision(deliberation_id,participant_actor_id); CREATE INDEX IF NOT EXISTS projected_participant_deliberation_active ON projected_participant(deliberation_id,active); CREATE INDEX IF NOT EXISTS projected_lifecycle_target_dimension_type ON projected_lifecycle(target_id,dimension,object_type); CREATE INDEX IF NOT EXISTS projected_effective_status_lifecycle ON projected_effective(status,withdrawal_status,archival_status); CREATE INDEX IF NOT EXISTS projected_effective_default_list ON projected_effective(status,withdrawal_status,archival_status,proposition_id); CREATE INDEX IF NOT EXISTS projected_effective_revision_lifecycle ON projected_effective(revision_id,withdrawal_status,archival_status,proposition_id,status); CREATE INDEX IF NOT EXISTS projected_attestation_filter ON projected_attestation(ledger_id,subject_type,subject_id,claim_type); CREATE INDEX IF NOT EXISTS projected_invitation_proposition_actor ON projected_invitation(ledger_id,proposition_id,invited_actor_id); CREATE INDEX IF NOT EXISTS projected_invitation_deliberation_actor ON projected_invitation(ledger_id,deliberation_id,invited_actor_id); CREATE INDEX IF NOT EXISTS projected_relationship_target_target ON projected_relationship_target(target_object_id,object_id); CREATE INDEX IF NOT EXISTS projected_provenance_filter ON projected_provenance(ledger_id,proposition_id,source_ledger_id,copy_mode); CREATE INDEX IF NOT EXISTS projected_export_object_ledger_hash ON projected_export_object(ledger_id,content_hash); CREATE INDEX IF NOT EXISTS extension_event_ledger_extension_created ON extension_event(ledger_id,extension_name,created_at,event_id); CREATE INDEX IF NOT EXISTS extension_event_ledger_target ON extension_event(ledger_id,extension_name,target_id,created_at,event_id); CREATE INDEX IF NOT EXISTS projected_tag_ledger_tag ON projected_tag(ledger_id,tag,proposition_id); CREATE INDEX IF NOT EXISTS projected_directory_ledger_alias ON projected_directory(ledger_id,alias,target_actor_id); CREATE INDEX IF NOT EXISTS projected_directory_ledger_name ON projected_directory(ledger_id,display_name,target_actor_id); CREATE INDEX IF NOT EXISTS projected_directory_ledger_key ON projected_directory(ledger_id,target_key_id,target_actor_id); CREATE INDEX IF NOT EXISTS indexed_proposition_ledger_proposition ON indexed_proposition(ledger_id,proposition_id); CREATE INDEX IF NOT EXISTS indexed_proposition_default_list ON indexed_proposition(ledger_id,status,withdrawal_status,archival_status,proposition_id); CREATE INDEX IF NOT EXISTS indexed_proposition_lifecycle_list ON indexed_proposition(ledger_id,withdrawal_status,archival_status,proposition_id); CREATE INDEX IF NOT EXISTS indexed_proposition_pending_list ON indexed_proposition(ledger_id,has_pending_revision,proposition_id); CREATE INDEX IF NOT EXISTS indexed_proposition_effective_revision ON indexed_proposition(ledger_id,effective_revision_id,proposition_id); CREATE INDEX IF NOT EXISTS indexed_proposition_latest_revision ON indexed_proposition(ledger_id,latest_revision_id,proposition_id);")?;
        self.conn.execute_batch("CREATE INDEX IF NOT EXISTS projected_authority_actor_capability ON projected_authority(receiving_actor_id,capability,revoked,object_id);")?;
        self.backfill_indexed_proposition_meta()?;
        for object_type in fact_schema::OBJECT_TYPES {
            self.conn.execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS protocol_{object_type} (object_id BLOB PRIMARY KEY REFERENCES protocol_object(object_id), ledger_id BLOB, content_hash BLOB NOT NULL, payload BLOB NOT NULL);"
            ))?;
        }
        Ok(())
    }

    fn rename_legacy_projection_tables(&self) -> Result<(), Error> {
        for (legacy, renamed) in [
            ("projection_object", "projected_object"),
            ("projection_consensus", "projected_consensus"),
            ("projection_actor", "projected_actor"),
            ("projection_key", "projected_key"),
            ("projection_binding", "projected_binding"),
            ("projection_authority", "projected_authority"),
            ("projection_revision", "projected_revision"),
            ("projection_deliberation", "projected_deliberation"),
            (
                "projection_deliberation_object",
                "projected_deliberation_object",
            ),
            ("projection_standing_change", "projected_standing_change"),
            ("projection_participant", "projected_participant"),
            ("projection_decision", "projected_decision"),
            ("projection_lifecycle", "projected_lifecycle"),
            ("projection_attestation", "projected_attestation"),
            ("projection_invitation", "projected_invitation"),
            (
                "projection_relationship_target",
                "projected_relationship_target",
            ),
            ("projection_provenance", "projected_provenance"),
            ("projection_pending", "projected_pending"),
            ("projection_reconciliation", "projected_reconciliation"),
            ("projection_roster", "projected_roster"),
            ("projection_effective", "projected_effective"),
            ("projection_export_object", "projected_export_object"),
        ] {
            if self.table_exists(legacy)? && !self.table_exists(renamed)? {
                self.conn
                    .execute_batch(&format!("ALTER TABLE {legacy} RENAME TO {renamed};"))?;
            }
        }

        for table in [
            "projected_consensus",
            "projected_participant",
            "projected_effective",
        ] {
            if self.table_exists(table)?
                && self.column_exists(table, "projection_version")?
                && !self.column_exists(table, "projected_version")?
            {
                self.conn.execute_batch(&format!(
                    "ALTER TABLE {table} RENAME COLUMN projection_version TO projected_version;"
                ))?;
            }
        }

        self.conn.execute_batch(
            "DROP INDEX IF EXISTS projection_revision_proposition_revision;
             DROP INDEX IF EXISTS projection_revision_parent;
             DROP INDEX IF EXISTS projection_deliberation_proposition_revision;
             DROP INDEX IF EXISTS projection_deliberation_settled_proposition;
             DROP INDEX IF EXISTS projection_deliberation_object_filter;
             DROP INDEX IF EXISTS projection_deliberation_object_deliberation_type;
             DROP INDEX IF EXISTS projection_decision_deliberation_actor;
             DROP INDEX IF EXISTS projection_participant_deliberation_active;
             DROP INDEX IF EXISTS projection_lifecycle_target_dimension_type;
             DROP INDEX IF EXISTS projection_effective_status_lifecycle;
             DROP INDEX IF EXISTS projection_effective_default_list;
             DROP INDEX IF EXISTS projection_effective_revision_lifecycle;
             DROP INDEX IF EXISTS projection_attestation_filter;
             DROP INDEX IF EXISTS projection_invitation_proposition_actor;
             DROP INDEX IF EXISTS projection_invitation_deliberation_actor;
             DROP INDEX IF EXISTS projection_relationship_target_target;
             DROP INDEX IF EXISTS projection_provenance_filter;
             DROP INDEX IF EXISTS projection_export_object_ledger_hash;",
        )?;

        Ok(())
    }

    fn table_exists(&self, table: &str) -> Result<bool, Error> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
            [table],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn column_exists(&self, table: &str, column: &str) -> Result<bool, Error> {
        let mut statement = self
            .conn
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            if name == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn backfill_indexed_proposition_meta(&self) -> Result<(), Error> {
        let mut statement = self.conn.prepare(
            "SELECT l.ledger_id
             FROM ledger l
             LEFT JOIN indexed_proposition_meta meta ON meta.ledger_id=l.ledger_id
             WHERE meta.ledger_id IS NULL",
        )?;
        let ledgers = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        self.refresh_indexed_proposition_meta_for_ledgers(&ledgers)
    }

    fn refresh_indexed_proposition_meta_for_all_ledgers(&self) -> Result<(), Error> {
        let ledgers = self
            .conn
            .prepare("SELECT ledger_id FROM ledger")?
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        self.refresh_indexed_proposition_meta_for_ledgers(&ledgers)
    }

    fn refresh_indexed_proposition_meta_for_ledgers(
        &self,
        ledgers: &[Vec<u8>],
    ) -> Result<(), Error> {
        let mut statement = self.conn.prepare(
            "INSERT INTO indexed_proposition_meta(
                ledger_id,
                proposition_count,
                effective_count,
                indexed_count,
                stale_count,
                indexed_version,
                refreshed_at
             )
             VALUES(
                ?,
                (SELECT COUNT(*)
                 FROM protocol_object
                 WHERE ledger_id=? AND object_type='proposition'),
                (SELECT COUNT(*)
                 FROM projected_effective e
                 JOIN protocol_object p ON p.object_id=e.proposition_id
                 WHERE p.ledger_id=? AND p.object_type='proposition'),
                (SELECT COUNT(*)
                 FROM indexed_proposition
                 WHERE ledger_id=?),
                (SELECT COUNT(*)
                 FROM indexed_proposition
                 WHERE ledger_id=? AND indexed_version<>?),
                ?,
                datetime('now')
             )
             ON CONFLICT(ledger_id) DO UPDATE SET
                proposition_count=excluded.proposition_count,
                effective_count=excluded.effective_count,
                indexed_count=excluded.indexed_count,
                stale_count=excluded.stale_count,
                indexed_version=excluded.indexed_version,
                refreshed_at=excluded.refreshed_at",
        )?;
        for ledger in ledgers {
            statement.execute(params![
                ledger.as_slice(),
                ledger.as_slice(),
                ledger.as_slice(),
                ledger.as_slice(),
                ledger.as_slice(),
                INDEXED_PROPOSITION_VERSION,
                INDEXED_PROPOSITION_VERSION,
            ])?;
        }
        Ok(())
    }

    pub fn create_ledger(&self, ledger_id: &[u8; 16], namespace: &str) -> Result<(), Error> {
        let ledger_uuid = uuid::Uuid::from_bytes(*ledger_id);
        if ledger_uuid.get_version_num() != 7 || ledger_uuid.get_variant() != uuid::Variant::RFC4122
        {
            return Err(Error::InvalidUuid("ledger_id"));
        }
        if !valid_namespace(namespace) {
            return Err(Error::InvalidNamespace);
        }
        self.conn
            .execute(
                "INSERT INTO ledger(ledger_id,namespace,protocol_version) VALUES(?,?,?)",
                params![ledger_id.as_slice(), namespace, "0"],
            )
            .map(|_| ())
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(code, _) if code.extended_code == 1555 => {
                    Error::Duplicate
                }
                other => Error::Sql(other),
            })?;
        self.conn.execute(
            "INSERT OR IGNORE INTO search_index_meta(ledger_id,canonical_document_count,indexed_document_count,total_token_count) VALUES(?,?,?,?)",
            params![ledger_id.as_slice(), 0_i64, 0_i64, 0_i64],
        )?;
        self.conn.execute(
            "INSERT OR IGNORE INTO indexed_proposition_meta(ledger_id,proposition_count,effective_count,indexed_count,stale_count,indexed_version,refreshed_at) VALUES(?,?,?,?,?,?,datetime('now'))",
            params![
                ledger_id.as_slice(),
                0_i64,
                0_i64,
                0_i64,
                0_i64,
                INDEXED_PROPOSITION_VERSION
            ],
        )?;
        Ok(())
    }

    pub fn register_key(&self, key_id: &[u8; 16], public_key: &[u8]) -> Result<(), Error> {
        if public_key.len() != 32 {
            return Err(Error::InvalidPublicKey);
        }
        self.conn
            .execute(
                "INSERT INTO key_material(key_id,public_key) VALUES(?,?)",
                params![key_id.as_slice(), public_key],
            )
            .map(|_| ())
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(code, _)
                    if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY =>
                {
                    Error::Duplicate
                }
                other => Error::Sql(other),
            })
    }

    /// Resolve a stored public key by its protocol fingerprint for transport
    /// authentication. The fingerprint is not itself ledger authority.
    pub fn public_key_by_fingerprint(
        &self,
        fingerprint: &fact_core::Hash,
    ) -> Result<Option<[u8; 32]>, Error> {
        let mut statement = self.conn.prepare("SELECT public_key FROM key_material")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let bytes: Vec<u8> = row.get(0)?;
            if bytes.len() == 32 && fact_core::Hash::digest(&bytes) == *fingerprint {
                return Ok(Some(bytes.try_into().map_err(|_| Error::InvalidPublicKey)?));
            }
        }
        Ok(None)
    }

    /// Create the v0 single-writer bootstrap cycle in one SQLite transaction.
    /// The caller supplies all advisory/deterministic inputs so tests and
    /// independent implementations can reproduce the exact object bytes.
    pub fn bootstrap_ledger(
        &self,
        namespace: &str,
        created_at: &str,
        seed: [u8; 32],
        nonce: [u8; 16],
    ) -> Result<BootstrapResult, Error> {
        self.bootstrap_ledger_with_ids(
            namespace,
            created_at,
            seed,
            nonce,
            BootstrapIds {
                ledger_id: uuid::Uuid::now_v7(),
                actor_id: uuid::Uuid::now_v7(),
                key_id: uuid::Uuid::now_v7(),
                binding_id: uuid::Uuid::now_v7(),
                grant_id: uuid::Uuid::now_v7(),
                assertion_id: uuid::Uuid::now_v7(),
                genesis_id: uuid::Uuid::now_v7(),
            },
        )
    }

    /// Create the v0 single-writer bootstrap cycle using caller-provided IDs.
    ///
    /// This lets higher-level SDK runtimes provide deterministic IDs for
    /// replay while preserving the production [`Store::bootstrap_ledger`] API.
    pub fn bootstrap_ledger_with_ids(
        &self,
        namespace: &str,
        created_at: &str,
        seed: [u8; 32],
        nonce: [u8; 16],
        ids: BootstrapIds,
    ) -> Result<BootstrapResult, Error> {
        let BootstrapIds {
            ledger_id,
            actor_id,
            key_id,
            binding_id,
            grant_id,
            assertion_id,
            genesis_id,
        } = ids;
        let key = fact_crypto::SigningKey::from_seed(&seed).map_err(Error::Cose)?;
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.create_ledger(ledger_id.as_bytes(), namespace)?;
            self.register_key(key_id.as_bytes(), &key.public_key())?;
            let actor = make_signed(
                &key,
                serde_json::json!({"id":actor_id,"object_type":"actor","schema_version":"0","actor_id":actor_id,"signing_key_id":key_id,"created_at":created_at,"dependencies":[],"body":{"actor_type":"service","bootstrap_key_id":key_id,"bootstrap_binding_id":binding_id}}),
            )?;
            let key_object = make_signed(
                &key,
                serde_json::json!({"id":key_id,"object_type":"key","schema_version":"0","actor_id":actor_id,"signing_key_id":key_id,"created_at":created_at,"dependencies":[],"body":{"public_key":{"algorithm":"Ed25519","bytes":b64url(&key.public_key()),"fingerprint":key.fingerprint().hex()},"purpose":"signing"}}),
            )?;
            let binding = make_signed(
                &key,
                serde_json::json!({"id":binding_id,"object_type":"actor_key_binding","schema_version":"0","actor_id":actor_id,"signing_key_id":key_id,"created_at":created_at,"dependencies":[],"body":{"actor_id":actor_id,"key_id":key_id,"permitted_purpose":"signing","predecessor_binding_id":null}}),
            )?;
            let grant = make_signed(
                &key,
                serde_json::json!({"id":grant_id,"ledger_id":ledger_id,"object_type":"authorization_grant","schema_version":"0","actor_id":actor_id,"signing_key_id":key_id,"created_at":created_at,"dependencies":[],"body":{"grant_id":grant_id,"granting_actor_id":actor_id,"receiving_actor_id":actor_id,"capabilities":["admin"],"scope":{"type":"ledger"},"validity":null,"constraints":{},"predecessor_grant_id":null}}),
            )?;
            let assertion = make_signed(
                &key,
                serde_json::json!({"id":assertion_id,"ledger_id":ledger_id,"object_type":"namespace_assertion","schema_version":"0","actor_id":actor_id,"signing_key_id":key_id,"created_at":created_at,"dependencies":[],"body":{"namespace":namespace,"target_type":"ledger","target_id":ledger_id,"naming_authority_actor_id":actor_id,"validity":{"valid_from":created_at,"expires_at":null},"supersedes":null}}),
            )?;
            let refs = [
                (&actor, "bootstrap-actor"),
                (&key_object, "bootstrap-key"),
                (&binding, "bootstrap-binding"),
                (&grant, "root-grant"),
                (&assertion, "namespace-assertion"),
            ];
            let dependencies=refs.iter().map(|(bytes,role)|{let c=fact_crypto::decode_sign1(bytes).map_err(Error::Cose)?;let value:serde_json::Value=serde_json::from_slice(&c.payload).map_err(|_|Error::Metadata)?;Ok(serde_json::json!({"object_id":value["id"],"content_hash":fact_core::Hash::digest(&c.payload).hex(),"role":role}))}).collect::<Result<Vec<_>,Error>>()?;
            let genesis = make_signed(
                &key,
                serde_json::json!({"id":genesis_id,"ledger_id":ledger_id,"object_type":"genesis","schema_version":"0","actor_id":actor_id,"signing_key_id":key_id,"created_at":created_at,"dependencies":dependencies,"body":{"ledger_id":ledger_id,"protocol_version":"0","parameters":{"consensus_rule":"unanimity-v0","namespace_profile":"facts-namespace-v0","content_profile":"facts-protocol-markdown-v0"},"namespace":namespace,"bootstrap_actor":actor_id,"bootstrap_key":key_id,"bootstrap_binding":binding_id,"root_grant":grant_id,"nonce":b64url(&nonce),"initial_namespace_assertion":assertion_id}}),
            )?;
            let mut objects = vec![actor, key_object, binding, grant, assertion, genesis];
            let mut hashes = Vec::new();
            for bytes in &objects {
                hashes.push(self.insert_verified_object_in_transaction(bytes)?);
            }
            Ok(BootstrapResult {
                ledger_id,
                genesis_id,
                actor_id,
                key_id,
                object_hashes: hashes,
                cose_objects: std::mem::take(&mut objects),
            })
        })();
        match result {
            Ok(value) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(value)
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn insert_object(
        &self,
        id: &[u8],
        ledger: &[u8],
        kind: &str,
        schema: &str,
        actor: &[u8],
        key: &[u8],
        payload: &[u8],
        hash: &Hash,
        cose: &[u8],
    ) -> Result<(), Error> {
        let n=self.conn.execute("INSERT INTO protocol_object(object_id,ledger_id,object_type,schema_version,actor_id,signing_key_id,payload,content_hash,cose) VALUES(?,?,?,?,?,?,?,?,?)",params![id,ledger,kind,schema,actor,key,payload,hash.as_bytes(),cose]);
        match n {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.extended_code == 1555 || e.extended_code == 2067 =>
            {
                Err(Error::Duplicate)
            }
            Err(e) => Err(e.into()),
        }
    }
    pub fn get_payload(&self, id: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| metrics.get_payload.set(metrics.get_payload.get() + 1));
        self.conn
            .query_row(
                "SELECT payload FROM protocol_object WHERE object_id=?",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_cose_by_id(&self, ledger: &[u8], id: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.conn
            .query_row(
                "SELECT cose FROM protocol_object WHERE ledger_id=? AND object_id=?",
                params![ledger, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_cose_by_id_any(&self, id: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.conn
            .query_row(
                "SELECT cose FROM protocol_object WHERE object_id=?",
                [id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_cose_by_hash(&self, ledger: &[u8], hash: &Hash) -> Result<Option<Vec<u8>>, Error> {
        self.conn
            .query_row(
                "SELECT cose FROM protocol_object WHERE ledger_id=? AND content_hash=?",
                params![ledger, hash.as_bytes()],
                |r| r.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_cose_by_hash_any(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Error> {
        self.conn
            .query_row(
                "SELECT cose FROM protocol_object WHERE content_hash=?",
                [hash.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn genesis_root_grant_id(&self, ledger: &[u8; 16]) -> Result<Option<uuid::Uuid>, Error> {
        let payload = self
            .conn
            .query_row(
                "SELECT payload
                 FROM protocol_object
                 WHERE ledger_id=? AND object_type='genesis'
                 ORDER BY content_hash
                 LIMIT 1",
                [ledger.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        let value: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|_| Error::ProjectedMismatch)?;
        let root_grant_id = value["body"]["root_grant"]
            .as_str()
            .ok_or(Error::ProjectedMismatch)?;
        root_grant_id
            .parse::<uuid::Uuid>()
            .map(Some)
            .map_err(|_| Error::InvalidUuid("root_grant"))
    }

    pub fn list_objects(&self, ledger: &[u8]) -> Result<Vec<(uuid::Uuid, Hash, String)>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS
            .with(|metrics| metrics.list_objects.set(metrics.list_objects.get() + 1));
        let mut statement = self.conn.prepare(
            "SELECT object_id,content_hash,object_type FROM protocol_object WHERE ledger_id=? ORDER BY content_hash",
        )?;
        let rows = statement.query_map([ledger], |row| {
            let id: Vec<u8> = row.get(0)?;
            let hash: Vec<u8> = row.get(1)?;
            let object_type: String = row.get(2)?;
            let id = uuid::Uuid::from_slice(&id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;
            let hash: [u8; 32] = hash.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    "invalid hash length".into(),
                )
            })?;
            Ok((id, Hash::from_bytes(hash), object_type))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_object_hashes(&self, ledger: &[u8]) -> Result<Vec<Hash>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_object_hashes
                .set(metrics.list_object_hashes.get() + 1)
        });
        let mut statement = self.conn.prepare(
            "SELECT content_hash FROM protocol_object WHERE ledger_id=? ORDER BY content_hash",
        )?;
        let rows = statement.query_map([ledger], |row| {
            let hash: Vec<u8> = row.get(0)?;
            let hash: [u8; 32] = hash.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    "invalid hash length".into(),
                )
            })?;
            Ok(Hash::from_bytes(hash))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_objects_by_hashes(
        &self,
        ledger: &[u8; 16],
        hashes: &[Hash],
    ) -> Result<Vec<(uuid::Uuid, Hash, String)>, Error> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        for chunk in hashes.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT object_id,content_hash,object_type
                 FROM protocol_object
                 WHERE ledger_id=? AND content_hash IN ({placeholders})
                 ORDER BY content_hash"
            );
            let mut values = Vec::with_capacity(chunk.len() + 1);
            values.push(Value::Blob(ledger.to_vec()));
            values.extend(
                chunk
                    .iter()
                    .map(|hash| Value::Blob(hash.as_bytes().to_vec())),
            );
            let mut statement = self.conn.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                let id: Vec<u8> = row.get(0)?;
                let hash: Vec<u8> = row.get(1)?;
                let object_type: String = row.get(2)?;
                let id = uuid::Uuid::from_slice(&id).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })?;
                let hash: [u8; 32] = hash.try_into().map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Blob,
                        "invalid hash length".into(),
                    )
                })?;
                Ok((id, Hash::from_bytes(hash), object_type))
            })?;
            output.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        output.sort_by_key(|(_, hash, _)| *hash);
        Ok(output)
    }

    pub fn resolve_object_reference(
        &self,
        ledger: &[u8],
        reference: &str,
        allowed_types: &[&str],
    ) -> Result<Vec<ObjectReferenceMatch>, Error> {
        let normalized = reference.to_ascii_lowercase();
        let split_uuid_reference = split_uuid_reference_parts(&normalized);
        let object_id_range = split_uuid_reference
            .as_ref()
            .and_then(|(head, _)| hex_prefix_range::<16>(head))
            .or_else(|| uuid_hex_prefix_range(&normalized));
        let content_hash_range: Option<([u8; 32], [u8; 32])> = if normalized.contains('-') {
            None
        } else {
            hex_prefix_range(&normalized)
        };

        // `ledger_id` and `object_type` are deliberately left out of these
        // WHERE clauses and checked afterward in Rust instead. SQLite's
        // planner has no statistics indicating that the object_id/
        // content_hash range is far more selective than either column (a
        // single-ledger local store has one distinct `ledger_id`, and a
        // single `object_type` such as "proposition" can still match a large
        // fraction of the table), and picking either index over the primary
        // key / unique hash index turns this back into a large scan. The
        // range match is expected to return a handful of rows at most, so
        // filtering the rest in Rust keeps every candidate index seek.
        let mut matches = Vec::new();
        if let Some((low, high)) = object_id_range {
            let mut statement = self.conn.prepare(
                "SELECT object_id,content_hash,object_type,ledger_id FROM protocol_object \
                 WHERE object_id BETWEEN ? AND ?",
            )?;
            let rows = statement.query_map(
                params![low.as_slice(), high.as_slice()],
                object_reference_match,
            )?;
            matches.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        if let Some((low, high)) = content_hash_range {
            let mut statement = self.conn.prepare(
                "SELECT object_id,content_hash,object_type,ledger_id FROM protocol_object \
                 WHERE content_hash BETWEEN ? AND ?",
            )?;
            let rows = statement.query_map(
                params![low.as_slice(), high.as_slice()],
                object_reference_match,
            )?;
            matches.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        if let Some((_, tail)) = split_uuid_reference.as_ref() {
            matches.retain(|candidate| uuid_tail_prefix_matches(candidate.object_id, tail));
        }
        matches.retain(|candidate| {
            candidate.ledger_id.as_slice() == ledger
                && (allowed_types.is_empty()
                    || allowed_types.contains(&candidate.object_type.as_str()))
        });
        matches.sort_by(|a, b| {
            a.content_hash
                .cmp(&b.content_hash)
                .then_with(|| a.object_id.cmp(&b.object_id))
        });
        matches.dedup_by(|a, b| a.object_id == b.object_id);
        Ok(matches)
    }

    pub fn proposition_id_for_revision(
        &self,
        revision_id: &[u8; 16],
    ) -> Result<Option<uuid::Uuid>, Error> {
        self.conn
            .query_row(
                "SELECT proposition_id FROM projected_revision WHERE revision_id=?",
                [revision_id.as_slice()],
                |row| projected_uuid(row.get(0)?, "invalid proposition ID"),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_revision_projecteds_by_proposition(
        &self,
        ledger: &[u8; 16],
        proposition_id: &[u8; 16],
    ) -> Result<Vec<RevisionRow>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT r.revision_id,r.proposition_id,r.parent_revision_id,r.content_hash,r.object_id,r.payload
             FROM projected_revision r
             JOIN protocol_object p ON p.object_id=r.object_id
             WHERE p.ledger_id=? AND r.proposition_id=?
             ORDER BY r.revision_id",
        )?;
        let rows = statement.query_map(
            params![ledger.as_slice(), proposition_id.as_slice()],
            |row| {
                Ok(RevisionRow {
                    revision_id: projected_uuid(row.get(0)?, "invalid revision ID")?,
                    proposition_id: projected_uuid(row.get(1)?, "invalid proposition ID")?,
                    parent_revision_id: optional_projected_uuid(row.get(2)?)?,
                    content_hash: Hash::from_bytes(row.get::<_, Vec<u8>>(3)?.try_into().map_err(
                        |_| {
                            rusqlite::Error::FromSqlConversionFailure(
                                3,
                                rusqlite::types::Type::Blob,
                                "invalid content hash length".into(),
                            )
                        },
                    )?),
                    object_id: projected_uuid(row.get(4)?, "invalid revision object ID")?,
                    payload: row.get(5)?,
                })
            },
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_revision_search_payloads(
        &self,
        ledger: &[u8; 16],
        proposition_id: Option<&[u8; 16]>,
    ) -> Result<Vec<RevisionSearchPayloadRow>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_revision_search_payloads
                .set(metrics.list_revision_search_payloads.get() + 1);
        });
        let mut sql = "SELECT r.revision_id,r.content_hash,r.payload,r.proposition_id,e.status
             FROM projected_revision r
             JOIN protocol_object p ON p.object_id=r.object_id
             LEFT JOIN projected_effective e
               ON e.proposition_id=r.proposition_id AND e.revision_id=r.revision_id
             WHERE p.ledger_id=?"
            .to_owned();
        let mut values = vec![Value::Blob(ledger.to_vec())];
        if let Some(proposition_id) = proposition_id {
            sql.push_str(" AND r.proposition_id=?");
            values.push(Value::Blob(proposition_id.to_vec()));
        }
        sql.push_str(" ORDER BY r.revision_id");
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), |row| {
            Ok(RevisionSearchPayloadRow {
                object_id: projected_uuid(row.get(0)?, "invalid revision ID")?,
                content_hash: Hash::from_bytes(row.get::<_, Vec<u8>>(1)?.try_into().map_err(
                    |_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Blob,
                            "invalid content hash length".into(),
                        )
                    },
                )?),
                payload: row.get(2)?,
                proposition_id: projected_uuid(row.get(3)?, "invalid proposition ID")?,
                effective_status: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_revision_search_payloads_filtered(
        &self,
        ledger: &[u8; 16],
        proposition_id: Option<&[u8; 16]>,
        status: Option<&str>,
        include_effective: bool,
        include_pending: bool,
        limit: usize,
    ) -> Result<Vec<RevisionSearchPayloadRow>, Error> {
        if limit == 0 || (!include_effective && !include_pending) {
            return Ok(Vec::new());
        }
        let mut sql = "SELECT r.revision_id,r.content_hash,r.payload,r.proposition_id,e.status
             FROM projected_revision r
             JOIN protocol_object p ON p.object_id=r.object_id
             LEFT JOIN projected_effective e
               ON e.proposition_id=r.proposition_id AND e.revision_id=r.revision_id
             WHERE p.ledger_id=?"
            .to_owned();
        let mut values = vec![Value::Blob(ledger.to_vec())];
        if let Some(proposition_id) = proposition_id {
            sql.push_str(" AND r.proposition_id=?");
            values.push(Value::Blob(proposition_id.to_vec()));
        }
        match (include_effective, include_pending) {
            (true, false) => sql.push_str(" AND e.status IS NOT NULL"),
            (false, true) => sql.push_str(" AND e.status IS NULL"),
            _ => {}
        }
        if let Some(status) = status {
            if status == "pending" {
                match (include_effective, include_pending) {
                    (true, true) => sql.push_str(" AND (e.status='pending' OR e.status IS NULL)"),
                    (true, false) => sql.push_str(" AND e.status='pending'"),
                    (false, true) => {}
                    (false, false) => {}
                }
            } else {
                sql.push_str(" AND e.status=?");
                values.push(Value::Text(status.to_owned()));
            }
        }
        sql.push_str(" ORDER BY r.revision_id LIMIT ?");
        values.push(Value::Integer(limit.min(i64::MAX as usize) as i64));
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), |row| {
            Ok(RevisionSearchPayloadRow {
                object_id: projected_uuid(row.get(0)?, "invalid revision ID")?,
                content_hash: Hash::from_bytes(row.get::<_, Vec<u8>>(1)?.try_into().map_err(
                    |_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Blob,
                            "invalid content hash length".into(),
                        )
                    },
                )?),
                payload: row.get(2)?,
                proposition_id: projected_uuid(row.get(3)?, "invalid proposition ID")?,
                effective_status: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_object_payloads_by_type(
        &self,
        ledger: &[u8; 16],
        object_type: &str,
    ) -> Result<Vec<ObjectPayloadRow>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_object_payloads_by_type
                .set(metrics.list_object_payloads_by_type.get() + 1);
        });
        let mut statement = self.conn.prepare(
            "SELECT object_id,content_hash,object_type,payload
             FROM protocol_object
             WHERE ledger_id=? AND object_type=?
             ORDER BY content_hash",
        )?;
        let rows =
            statement.query_map(params![ledger.as_slice(), object_type], object_payload_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_object_payloads(&self, ledger: &[u8; 16]) -> Result<Vec<ObjectPayloadRow>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_object_payloads
                .set(metrics.list_object_payloads.get() + 1);
        });
        let mut statement = self.conn.prepare(
            "SELECT object_id,content_hash,object_type,payload
             FROM protocol_object
             WHERE ledger_id=?
             ORDER BY content_hash",
        )?;
        let rows = statement.query_map([ledger.as_slice()], object_payload_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_object_payloads_page(
        &self,
        ledger: &[u8; 16],
        after_content_hash: Option<&Hash>,
        limit: usize,
    ) -> Result<Vec<ObjectPayloadRow>, Error> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let after = after_content_hash.map(|hash| hash.as_bytes().to_vec());
        let mut statement = self.conn.prepare(
            "SELECT object_id,content_hash,object_type,payload
             FROM protocol_object
             WHERE ledger_id=?
               AND (? IS NULL OR content_hash>?)
             ORDER BY content_hash
             LIMIT ?",
        )?;
        let rows = statement.query_map(
            params![
                ledger.as_slice(),
                after.as_deref(),
                after.as_deref(),
                limit as i64
            ],
            object_payload_row,
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_object_summaries(&self, ledger: &[u8; 16]) -> Result<Vec<ObjectSummaryRow>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT object_id,content_hash,object_type
             FROM protocol_object
             WHERE ledger_id=?
             ORDER BY content_hash",
        )?;
        let rows = statement.query_map([ledger.as_slice()], object_summary_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_object_summaries_page(
        &self,
        ledger: &[u8; 16],
        after_content_hash: Option<&Hash>,
        limit: usize,
    ) -> Result<Vec<ObjectSummaryRow>, Error> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let after = after_content_hash.map(|hash| hash.as_bytes().to_vec());
        let mut statement = self.conn.prepare(
            "SELECT object_id,content_hash,object_type
             FROM protocol_object
             WHERE ledger_id=?
               AND (? IS NULL OR content_hash>?)
             ORDER BY content_hash
             LIMIT ?",
        )?;
        let rows = statement.query_map(
            params![
                ledger.as_slice(),
                after.as_deref(),
                after.as_deref(),
                limit as i64
            ],
            object_summary_row,
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_object_summaries_by_type(
        &self,
        ledger: &[u8; 16],
        object_type: &str,
    ) -> Result<Vec<ObjectSummaryRow>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT object_id,content_hash,object_type
             FROM protocol_object
             WHERE ledger_id=? AND object_type=?
             ORDER BY content_hash",
        )?;
        let rows =
            statement.query_map(params![ledger.as_slice(), object_type], object_summary_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn object_summary_by_id(
        &self,
        ledger: &[u8; 16],
        object_id: &[u8; 16],
        object_type: &str,
    ) -> Result<Option<ObjectSummaryRow>, Error> {
        self.conn
            .query_row(
                "SELECT object_id,content_hash,object_type
                 FROM protocol_object
                 WHERE ledger_id=? AND object_id=? AND object_type=?",
                params![ledger.as_slice(), object_id.as_slice(), object_type],
                object_summary_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn object_payload_by_id(
        &self,
        ledger: &[u8; 16],
        object_id: &[u8; 16],
    ) -> Result<Option<ObjectPayloadRow>, Error> {
        self.conn
            .query_row(
                "SELECT object_id,content_hash,object_type,payload
                 FROM protocol_object
                 WHERE ledger_id=? AND object_id=?",
                params![ledger.as_slice(), object_id.as_slice()],
                object_payload_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_provenance_payloads(
        &self,
        ledger: &[u8; 16],
        proposition_id: Option<&[u8; 16]>,
        source_ledger_id: Option<&[u8; 16]>,
        copy_mode: Option<&str>,
    ) -> Result<Vec<ProvenancePayloadRow>, Error> {
        let mut sql = "SELECT p.object_id,o.content_hash,p.payload
             FROM projected_provenance p
             JOIN protocol_object o ON o.object_id=p.object_id
             WHERE p.ledger_id=?"
            .to_owned();
        let mut values = vec![Value::Blob(ledger.to_vec())];
        if let Some(proposition_id) = proposition_id {
            sql.push_str(" AND p.proposition_id=?");
            values.push(Value::Blob(proposition_id.to_vec()));
        }
        if let Some(source_ledger_id) = source_ledger_id {
            sql.push_str(" AND p.source_ledger_id=?");
            values.push(Value::Blob(source_ledger_id.to_vec()));
        }
        if let Some(copy_mode) = copy_mode {
            sql.push_str(" AND p.copy_mode=?");
            values.push(Value::Text(copy_mode.to_owned()));
        }
        sql.push_str(" ORDER BY json_extract(CAST(p.payload AS TEXT),'$.created_at'), p.object_id");
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), |row| {
            Ok(ProvenancePayloadRow {
                object_id: projected_uuid(row.get(0)?, "invalid provenance object ID")?,
                content_hash: Hash::from_bytes(row.get::<_, Vec<u8>>(1)?.try_into().map_err(
                    |_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Blob,
                            "invalid hash length".into(),
                        )
                    },
                )?),
                payload: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_identity_attestation_payloads(
        &self,
        ledger: &[u8; 16],
        subject_type: Option<&str>,
        subject_id: Option<&[u8; 16]>,
        claim_type: Option<&str>,
    ) -> Result<Vec<ObjectPayloadRow>, Error> {
        let mut sql = "SELECT a.object_id,o.content_hash,o.object_type,a.payload
             FROM projected_attestation a
             JOIN protocol_object o ON o.object_id=a.object_id
             WHERE a.ledger_id=?"
            .to_owned();
        let mut values = vec![Value::Blob(ledger.to_vec())];
        if let Some(subject_type) = subject_type {
            sql.push_str(" AND a.subject_type=?");
            values.push(Value::Text(subject_type.to_owned()));
        }
        if let Some(subject_id) = subject_id {
            sql.push_str(" AND a.subject_id=?");
            values.push(Value::Blob(subject_id.to_vec()));
        }
        if let Some(claim_type) = claim_type {
            sql.push_str(" AND a.claim_type=?");
            values.push(Value::Text(claim_type.to_owned()));
        }
        sql.push_str(" ORDER BY a.created_at, a.object_id");
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), object_payload_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_invitation_payloads(
        &self,
        ledger: &[u8; 16],
        proposition_id: Option<&[u8; 16]>,
        deliberation_id: Option<&[u8; 16]>,
        invited_actor_id: Option<&[u8; 16]>,
    ) -> Result<Vec<ObjectPayloadRow>, Error> {
        let mut sql = "SELECT i.object_id,o.content_hash,o.object_type,i.payload
             FROM projected_invitation i
             JOIN protocol_object o ON o.object_id=i.object_id
             WHERE i.ledger_id=?"
            .to_owned();
        let mut values = vec![Value::Blob(ledger.to_vec())];
        if let Some(proposition_id) = proposition_id {
            sql.push_str(" AND i.proposition_id=?");
            values.push(Value::Blob(proposition_id.to_vec()));
        }
        if let Some(deliberation_id) = deliberation_id {
            sql.push_str(" AND i.deliberation_id=?");
            values.push(Value::Blob(deliberation_id.to_vec()));
        }
        if let Some(invited_actor_id) = invited_actor_id {
            sql.push_str(" AND i.invited_actor_id=?");
            values.push(Value::Blob(invited_actor_id.to_vec()));
        }
        sql.push_str(" ORDER BY i.created_at, i.object_id");
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), object_payload_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_relationship_payloads(
        &self,
        ledger: &[u8; 16],
        source_object_id: Option<&[u8; 16]>,
        relationship: Option<&str>,
        target_object_id: Option<&[u8; 16]>,
    ) -> Result<Vec<ObjectPayloadRow>, Error> {
        let mut sql = "SELECT r.object_id,o.content_hash,r.object_type,r.payload
             FROM protocol_relationship r
             JOIN protocol_object o ON o.object_id=r.object_id"
            .to_owned();
        if target_object_id.is_some() {
            sql.push_str(" JOIN projected_relationship_target rt ON rt.object_id=r.object_id");
        }
        sql.push_str(" WHERE r.ledger_id=?");
        let mut values = vec![Value::Blob(ledger.to_vec())];
        if let Some(source_object_id) = source_object_id {
            sql.push_str(" AND r.source_object_id=?");
            values.push(Value::Blob(source_object_id.to_vec()));
        }
        if let Some(relationship) = relationship {
            sql.push_str(" AND r.relationship=?");
            values.push(Value::Text(relationship.to_owned()));
        }
        if let Some(target_object_id) = target_object_id {
            sql.push_str(" AND rt.target_object_id=?");
            values.push(Value::Blob(target_object_id.to_vec()));
        }
        sql.push_str(" ORDER BY json_extract(CAST(r.payload AS TEXT),'$.created_at'), r.object_id");
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), object_payload_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_lifecycle_rows(
        &self,
        ledger: &[u8; 16],
        object_type: &str,
        target_id: Option<&[u8; 16]>,
    ) -> Result<Vec<LifecycleRow>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_lifecycle_rows
                .set(metrics.list_lifecycle_rows.get() + 1);
        });
        let mut sql =
            "SELECT l.object_id,l.object_type,l.target_id,l.dimension,l.operation,l.payload
             FROM projected_lifecycle l
             JOIN protocol_object p ON p.object_id=l.object_id
             WHERE p.ledger_id=? AND l.object_type=?"
                .to_owned();
        let mut values = vec![
            Value::Blob(ledger.to_vec()),
            Value::Text(object_type.to_owned()),
        ];
        if let Some(target_id) = target_id {
            sql.push_str(" AND l.target_id=?");
            values.push(Value::Blob(target_id.to_vec()));
        }
        sql.push_str(" ORDER BY l.object_id");
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), lifecycle_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_lifecycle_rows_for_targets(
        &self,
        ledger: &[u8; 16],
        object_type: &str,
        target_ids: &[uuid::Uuid],
    ) -> Result<Vec<LifecycleRow>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_lifecycle_rows
                .set(metrics.list_lifecycle_rows.get() + 1);
        });
        if target_ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = std::iter::repeat_n("?", target_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT l.object_id,l.object_type,l.target_id,l.dimension,l.operation,l.payload
             FROM projected_lifecycle l
             JOIN protocol_object p ON p.object_id=l.object_id
             WHERE p.ledger_id=? AND l.object_type=? AND l.target_id IN ({placeholders})
             ORDER BY l.object_id"
        );
        let mut values = vec![
            Value::Blob(ledger.to_vec()),
            Value::Text(object_type.to_owned()),
        ];
        values.extend(
            target_ids
                .iter()
                .map(|id| Value::Blob(id.as_bytes().to_vec())),
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), lifecycle_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn proposition_lifecycle_tip_ids(
        &self,
        ledger: &[u8; 16],
        proposition_id: &[u8; 16],
        dimension: &str,
    ) -> Result<Vec<uuid::Uuid>, Error> {
        let uuid_text = "lower(substr(hex(candidate.object_id),1,8)||'-'||substr(hex(candidate.object_id),9,4)||'-'||substr(hex(candidate.object_id),13,4)||'-'||substr(hex(candidate.object_id),17,4)||'-'||substr(hex(candidate.object_id),21,12))";
        let sql = format!(
            "WITH lifecycle AS (
                 SELECT l.object_id,l.payload
                 FROM projected_lifecycle l
                 JOIN protocol_object p ON p.object_id=l.object_id
                 WHERE p.ledger_id=?
                   AND l.object_type='proposition_lifecycle'
                   AND l.target_id=?
                   AND l.dimension=?
             )
             SELECT candidate.object_id
             FROM lifecycle candidate
             WHERE NOT EXISTS (
                 SELECT 1
                 FROM lifecycle source,
                      json_each(CAST(source.payload AS TEXT),'$.body.predecessor_ids') predecessor
                 WHERE lower(predecessor.value)={uuid_text}
             )
             ORDER BY candidate.object_id"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(
            params![ledger.as_slice(), proposition_id.as_slice(), dimension],
            |row| projected_uuid(row.get(0)?, "invalid lifecycle object ID"),
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn invitation_lifecycle_tip_ids(
        &self,
        ledger: &[u8; 16],
        invitation_id: &[u8; 16],
    ) -> Result<Vec<uuid::Uuid>, Error> {
        let uuid_text = "lower(substr(hex(candidate.object_id),1,8)||'-'||substr(hex(candidate.object_id),9,4)||'-'||substr(hex(candidate.object_id),13,4)||'-'||substr(hex(candidate.object_id),17,4)||'-'||substr(hex(candidate.object_id),21,12))";
        let sql = format!(
            "WITH lifecycle AS (
                 SELECT l.object_id,l.payload
                 FROM projected_lifecycle l
                 JOIN protocol_object p ON p.object_id=l.object_id
                 WHERE p.ledger_id=?
                   AND l.object_type='invitation_lifecycle'
                   AND l.target_id=?
             )
             SELECT candidate.object_id
             FROM lifecycle candidate
             WHERE NOT EXISTS (
                 SELECT 1
                 FROM lifecycle source,
                      json_each(CAST(source.payload AS TEXT),'$.body.predecessor_lifecycle_ids') predecessor
                 WHERE lower(predecessor.value)={uuid_text}
             )
             ORDER BY candidate.object_id"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(
            params![ledger.as_slice(), invitation_id.as_slice()],
            |row| projected_uuid(row.get(0)?, "invalid lifecycle object ID"),
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_authority_grant_payloads(
        &self,
        ledger: &[u8; 16],
        actor_id: &[u8; 16],
        capability: &str,
    ) -> Result<Vec<ObjectPayloadRow>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT a.object_id,p.content_hash,'authorization_grant',a.payload
             FROM projected_authority a
             JOIN protocol_object p ON p.object_id=a.object_id
             WHERE p.ledger_id=? AND a.receiving_actor_id=? AND a.capability=? AND a.revoked=0
             ORDER BY a.object_id",
        )?;
        let rows = statement.query_map(
            params![ledger.as_slice(), actor_id.as_slice(), capability],
            object_payload_row,
        )?;
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        if !rows.is_empty() {
            return Ok(rows);
        }

        let actor = uuid::Uuid::from_bytes(*actor_id).to_string();
        let rows = self
            .list_object_payloads_by_type(ledger, "authorization_grant")?
            .into_iter()
            .filter_map(|row| {
                let value = serde_json::from_slice::<serde_json::Value>(&row.payload).ok()?;
                let body = value.get("body")?;
                let receiving_actor = body
                    .get("receiving_actor_id")
                    .and_then(serde_json::Value::as_str)?;
                if receiving_actor != actor {
                    return None;
                }
                let has_capability = body
                    .get("capabilities")
                    .and_then(serde_json::Value::as_array)?
                    .iter()
                    .any(|item| item.as_str().is_some_and(|item| item == capability));
                has_capability.then_some(row)
            })
            .collect();
        Ok(rows)
    }

    pub fn list_deliberation_projecteds_by_proposition(
        &self,
        ledger: &[u8; 16],
        proposition_id: &[u8; 16],
    ) -> Result<Vec<DeliberationRow>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT d.deliberation_id,d.proposition_id,d.revision_id,d.settled,p.content_hash,d.object_id,d.payload
             FROM projected_deliberation d
             JOIN protocol_object p ON p.object_id=d.object_id
             WHERE p.ledger_id=? AND d.proposition_id=?
             ORDER BY d.deliberation_id",
        )?;
        let rows = statement.query_map(
            params![ledger.as_slice(), proposition_id.as_slice()],
            deliberation_row,
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_deliberation_projecteds(
        &self,
        ledger: &[u8; 16],
    ) -> Result<Vec<DeliberationRow>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_deliberation_projecteds
                .set(metrics.list_deliberation_projecteds.get() + 1);
        });
        let mut statement = self.conn.prepare(
            "SELECT d.deliberation_id,d.proposition_id,d.revision_id,d.settled,p.content_hash,d.object_id,d.payload
             FROM projected_deliberation d
             JOIN protocol_object p ON p.object_id=d.object_id
             WHERE p.ledger_id=?
             ORDER BY d.deliberation_id",
        )?;
        let rows = statement.query_map([ledger.as_slice()], deliberation_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_deliberation_search_rows_filtered(
        &self,
        ledger: &[u8; 16],
        proposition_id: Option<&[u8; 16]>,
        revision_id: Option<&[u8; 16]>,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<DeliberationRow>, Error> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut sql = "SELECT d.deliberation_id,d.proposition_id,d.revision_id,d.settled,p.content_hash,d.object_id,d.payload
             FROM projected_deliberation d
             JOIN protocol_object p ON p.object_id=d.object_id
             LEFT JOIN projected_effective e ON e.revision_id=d.revision_id
             WHERE p.ledger_id=?"
            .to_owned();
        let mut values = vec![Value::Blob(ledger.to_vec())];
        if let Some(proposition_id) = proposition_id {
            sql.push_str(" AND d.proposition_id=?");
            values.push(Value::Blob(proposition_id.to_vec()));
        }
        if let Some(revision_id) = revision_id {
            sql.push_str(" AND d.revision_id=?");
            values.push(Value::Blob(revision_id.to_vec()));
        }
        if let Some(status) = status {
            sql.push_str(
                " AND COALESCE((
                    SELECT json_extract(CAST(s.payload AS TEXT),'$.body.outcome')
                    FROM projected_deliberation_object s
                    WHERE s.ledger_id=d.ledger_id
                      AND s.deliberation_id=d.deliberation_id
                      AND s.object_type='settlement'
                    ORDER BY s.created_at, s.object_id
                    LIMIT 1
                ), e.status, 'pending')=?",
            );
            values.push(Value::Text(status.to_owned()));
        }
        sql.push_str(" ORDER BY d.deliberation_id LIMIT ?");
        values.push(Value::Integer(limit.min(i64::MAX as usize) as i64));
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), deliberation_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_deliberation_projecteds_by_ids(
        &self,
        ledger: &[u8; 16],
        deliberation_ids: &[uuid::Uuid],
    ) -> Result<Vec<DeliberationRow>, Error> {
        if deliberation_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        for chunk in deliberation_ids.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT d.deliberation_id,d.proposition_id,d.revision_id,d.settled,p.content_hash,d.object_id,d.payload
                 FROM projected_deliberation d
                 JOIN protocol_object p ON p.object_id=d.object_id
                 WHERE p.ledger_id=? AND d.deliberation_id IN ({placeholders})
                 ORDER BY d.deliberation_id"
            );
            let mut values = Vec::with_capacity(chunk.len() + 1);
            values.push(Value::Blob(ledger.to_vec()));
            values.extend(chunk.iter().map(|id| Value::Blob(id.as_bytes().to_vec())));
            let mut statement = self.conn.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(values.iter()), deliberation_row)?;
            output.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        output.sort_by_key(|row| row.deliberation_id);
        Ok(output)
    }

    pub fn deliberation_projected(
        &self,
        ledger: &[u8; 16],
        deliberation_id: &[u8; 16],
    ) -> Result<Option<DeliberationRow>, Error> {
        self.conn
            .query_row(
                "SELECT d.deliberation_id,d.proposition_id,d.revision_id,d.settled,p.content_hash,d.object_id,d.payload
                 FROM projected_deliberation d
                 JOIN protocol_object p ON p.object_id=d.object_id
                 WHERE p.ledger_id=? AND d.deliberation_id=?",
                params![ledger.as_slice(), deliberation_id.as_slice()],
                deliberation_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn deliberation_id_for_revision(
        &self,
        ledger: &[u8; 16],
        proposition_id: &[u8; 16],
        revision_id: &[u8; 16],
    ) -> Result<Vec<uuid::Uuid>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT d.deliberation_id
             FROM projected_deliberation d
             JOIN protocol_object p ON p.object_id=d.object_id
             WHERE p.ledger_id=? AND d.proposition_id=? AND d.revision_id=?
             ORDER BY d.deliberation_id",
        )?;
        let rows = statement.query_map(
            params![
                ledger.as_slice(),
                proposition_id.as_slice(),
                revision_id.as_slice()
            ],
            |row| projected_uuid(row.get(0)?, "invalid deliberation ID"),
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_objects_by_deliberation(
        &self,
        ledger: &[u8; 16],
        deliberation_id: &[u8; 16],
        object_type: &str,
    ) -> Result<Vec<ObjectPayloadRow>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_objects_by_deliberation
                .set(metrics.list_objects_by_deliberation.get() + 1);
        });
        let mut statement = self.conn.prepare(
            "SELECT d.object_id,p.content_hash,d.object_type,d.payload
             FROM projected_deliberation_object d
             JOIN protocol_object p ON p.object_id=d.object_id
             WHERE d.ledger_id=? AND d.deliberation_id=? AND d.object_type=?
             ORDER BY d.created_at, d.object_id",
        )?;
        let rows = statement.query_map(
            params![ledger.as_slice(), deliberation_id.as_slice(), object_type],
            object_payload_row,
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_objects_by_deliberations(
        &self,
        ledger: &[u8; 16],
        deliberation_ids: &[uuid::Uuid],
        object_type: &str,
    ) -> Result<Vec<ObjectPayloadRow>, Error> {
        if deliberation_ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = std::iter::repeat_n("?", deliberation_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT d.object_id,p.content_hash,d.object_type,d.payload
             FROM projected_deliberation_object d
             JOIN protocol_object p ON p.object_id=d.object_id
             WHERE d.ledger_id=? AND d.object_type=?
               AND d.deliberation_id IN ({placeholders})
             ORDER BY d.created_at, d.object_id"
        );
        let mut values = vec![
            Value::Blob(ledger.to_vec()),
            Value::Text(object_type.to_owned()),
        ];
        values.extend(
            deliberation_ids
                .iter()
                .map(|id| Value::Blob(id.as_bytes().to_vec())),
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), object_payload_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_deliberation_objects_by_type(
        &self,
        ledger: &[u8; 16],
        object_type: &str,
    ) -> Result<Vec<ObjectPayloadRow>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_deliberation_objects_by_type
                .set(metrics.list_deliberation_objects_by_type.get() + 1);
        });
        let mut statement = self.conn.prepare(
            "SELECT d.object_id,p.content_hash,d.object_type,d.payload
             FROM projected_deliberation_object d
             JOIN protocol_object p ON p.object_id=d.object_id
             WHERE d.ledger_id=? AND d.object_type=?
             ORDER BY d.created_at, d.object_id",
        )?;
        let rows =
            statement.query_map(params![ledger.as_slice(), object_type], object_payload_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_deliberation_comment_payloads_page(
        &self,
        ledger: &[u8; 16],
        comment_phase: Option<&str>,
        parent_comment_id: Option<&[u8; 16]>,
        limit: usize,
    ) -> Result<Vec<ObjectPayloadRow>, Error> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut sql = "SELECT d.object_id,p.content_hash,d.object_type,d.payload
             FROM projected_deliberation_object d
             JOIN protocol_object p ON p.object_id=d.object_id
             WHERE d.ledger_id=? AND d.object_type='deliberation_comment'"
            .to_owned();
        let mut values = vec![Value::Blob(ledger.to_vec())];
        if let Some(comment_phase) = comment_phase {
            sql.push_str(" AND json_extract(CAST(d.payload AS TEXT),'$.body.comment_phase')=?");
            values.push(Value::Text(comment_phase.to_owned()));
        }
        if let Some(parent_comment_id) = parent_comment_id {
            sql.push_str(" AND json_extract(CAST(d.payload AS TEXT),'$.body.parent_comment_id')=?");
            values.push(Value::Text(
                uuid::Uuid::from_bytes(*parent_comment_id).to_string(),
            ));
        }
        sql.push_str(" ORDER BY d.created_at, d.object_id LIMIT ?");
        values.push(Value::Integer(limit.min(i64::MAX as usize) as i64));
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), object_payload_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn participant_decisions_for_deliberation(
        &self,
        ledger: &[u8; 16],
        deliberation_id: &[u8; 16],
    ) -> Result<Vec<ParticipantDecisionRow>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT pp.actor_id,pp.active,pd.value
             FROM projected_participant pp
             JOIN projected_deliberation d ON d.deliberation_id=pp.deliberation_id
             JOIN protocol_object p ON p.object_id=d.object_id
             LEFT JOIN projected_decision pd ON pd.deliberation_id=pp.deliberation_id AND pd.participant_actor_id=pp.actor_id
             WHERE p.ledger_id=? AND pp.deliberation_id=?
             ORDER BY pp.actor_id",
        )?;
        let rows = statement.query_map(
            params![ledger.as_slice(), deliberation_id.as_slice()],
            |row| {
                Ok(ParticipantDecisionRow {
                    actor_id: projected_uuid(row.get(0)?, "invalid participant actor ID")?,
                    active: row.get::<_, i64>(1)? != 0,
                    decision: row.get(2)?,
                })
            },
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_decision_rows_by_deliberation(
        &self,
        ledger: &[u8; 16],
        deliberation_id: &[u8; 16],
    ) -> Result<Vec<DecisionRow>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT d.decision_id,d.deliberation_id,d.participant_actor_id,d.value,p.content_hash,d.payload,p.cose
             FROM projected_decision d
             JOIN protocol_object p ON p.object_id=d.decision_id
             WHERE p.ledger_id=? AND d.deliberation_id=?
             ORDER BY d.decision_id",
        )?;
        let rows = statement.query_map(
            params![ledger.as_slice(), deliberation_id.as_slice()],
            decision_row,
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_decision_rows_by_deliberations(
        &self,
        ledger: &[u8; 16],
        deliberation_ids: &[uuid::Uuid],
    ) -> Result<Vec<DecisionRow>, Error> {
        if deliberation_ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = std::iter::repeat_n("?", deliberation_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT d.decision_id,d.deliberation_id,d.participant_actor_id,d.value,p.content_hash,d.payload,p.cose
             FROM projected_decision d
             JOIN protocol_object p ON p.object_id=d.decision_id
             WHERE p.ledger_id=? AND d.deliberation_id IN ({placeholders})
             ORDER BY d.decision_id"
        );
        let mut values = vec![Value::Blob(ledger.to_vec())];
        values.extend(
            deliberation_ids
                .iter()
                .map(|id| Value::Blob(id.as_bytes().to_vec())),
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), decision_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_settlement_payloads_by_deliberations(
        &self,
        ledger: &[u8; 16],
        deliberation_ids: &[uuid::Uuid],
    ) -> Result<Vec<ObjectPayloadRow>, Error> {
        self.list_objects_by_deliberations(ledger, deliberation_ids, "settlement")
    }

    pub fn proposition_id_for_deliberation(
        &self,
        deliberation_id: &[u8; 16],
    ) -> Result<Option<uuid::Uuid>, Error> {
        self.conn
            .query_row(
                "SELECT proposition_id FROM projected_deliberation WHERE deliberation_id=?",
                [deliberation_id.as_slice()],
                |row| projected_uuid(row.get(0)?, "invalid proposition ID"),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn insert_tag_extension_event(
        &self,
        input: TagExtensionEventInput,
    ) -> Result<TagExtensionRow, Error> {
        let payload = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema": "facts-extension-event-v0",
                "extension": "fact.tags",
                "event_id": input.event_id,
                "ledger_id": input.ledger_id,
                "target_type": "proposition",
                "target_id": input.proposition_id,
                "event_type": input.operation,
                "actor_id": input.actor_id,
                "signing_key_id": input.signing_key_id,
                "created_at": input.created_at,
                "body": {
                    "tags": input.tags,
                },
            }))
            .map_err(|_| Error::Metadata)?,
        )?;
        let content_hash = Hash::digest(&payload);
        self.conn.execute(
            "INSERT INTO extension_event(event_id,ledger_id,extension_name,target_id,event_type,actor_id,signing_key_id,created_at,content_hash,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![
                input.event_id.as_bytes(),
                input.ledger_id.as_bytes(),
                "fact.tags",
                input.proposition_id.as_bytes(),
                input.operation,
                input.actor_id.as_bytes(),
                input.signing_key_id.as_bytes(),
                input.created_at,
                content_hash.as_bytes(),
                payload.as_slice(),
            ],
        )?;
        self.project_tag_extension_for_proposition(input.ledger_id, input.proposition_id)?;
        Ok(TagExtensionRow {
            event_id: input.event_id,
            ledger_id: input.ledger_id,
            proposition_id: input.proposition_id,
            operation: input.operation,
            tags: input.tags,
            created_at: input.created_at,
            payload,
        })
    }

    pub fn list_tag_extension_events(
        &self,
        ledger: &[u8; 16],
    ) -> Result<Vec<TagExtensionRow>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT event_id,ledger_id,target_id,event_type,created_at,payload
             FROM extension_event
             WHERE ledger_id=? AND extension_name='fact.tags'
             ORDER BY created_at,event_id",
        )?;
        let rows = statement.query_map([ledger.as_slice()], tag_extension_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_tag_extension_targets(&self, ledger: &[u8; 16]) -> Result<Vec<uuid::Uuid>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT DISTINCT target_id
             FROM extension_event
             WHERE ledger_id=? AND extension_name='fact.tags'
             ORDER BY target_id",
        )?;
        let rows = statement.query_map([ledger.as_slice()], |row| {
            projected_uuid(row.get(0)?, "invalid tag target ID")
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn has_tag_extension_events_for_proposition(
        &self,
        ledger: &[u8; 16],
        proposition_id: &[u8; 16],
    ) -> Result<bool, Error> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*)
             FROM extension_event
             WHERE ledger_id=? AND extension_name='fact.tags' AND target_id=?
             LIMIT 1",
            params![ledger.as_slice(), proposition_id.as_slice()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn list_projected_tags(
        &self,
        ledger: &[u8; 16],
    ) -> Result<Vec<(uuid::Uuid, String)>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT proposition_id,tag
             FROM projected_tag
             WHERE ledger_id=?
             ORDER BY proposition_id,tag",
        )?;
        let rows = statement.query_map([ledger.as_slice()], |row| {
            Ok((
                projected_uuid(row.get(0)?, "invalid proposition ID")?,
                row.get(1)?,
            ))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_projected_tags_for_proposition(
        &self,
        ledger: &[u8; 16],
        proposition_id: &[u8; 16],
    ) -> Result<Vec<String>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT tag
             FROM projected_tag
             WHERE ledger_id=? AND proposition_id=?
             ORDER BY tag",
        )?;
        let rows = statement.query_map(
            params![ledger.as_slice(), proposition_id.as_slice()],
            |row| row.get::<_, String>(0),
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn import_tag_extension_event_payload(&self, payload: &[u8]) -> Result<bool, Error> {
        let event = parse_tag_extension_event_payload(payload)?;
        let content_hash = Hash::digest(payload);
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO extension_event(event_id,ledger_id,extension_name,target_id,event_type,actor_id,signing_key_id,created_at,content_hash,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![
                event.event_id.as_bytes(),
                event.ledger_id.as_bytes(),
                "fact.tags",
                event.proposition_id.as_bytes(),
                event.operation,
                event.actor_id.as_bytes(),
                event.signing_key_id.as_bytes(),
                event.created_at,
                content_hash.as_bytes(),
                payload,
            ],
        )?;
        if inserted > 0 {
            self.project_tag_extension_for_proposition(event.ledger_id, event.proposition_id)?;
        }
        Ok(inserted > 0)
    }

    fn project_tag_extension_for_proposition(
        &self,
        ledger_id: uuid::Uuid,
        proposition_id: uuid::Uuid,
    ) -> Result<(), Error> {
        self.conn.execute(
            "DELETE FROM projected_tag WHERE ledger_id=? AND proposition_id=?",
            params![ledger_id.as_bytes(), proposition_id.as_bytes()],
        )?;
        let latest: Option<(uuid::Uuid, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT event_id,payload
                 FROM extension_event
                 WHERE ledger_id=? AND extension_name='fact.tags' AND target_id=?
                 ORDER BY created_at DESC,event_id DESC
                 LIMIT 1",
                params![ledger_id.as_bytes(), proposition_id.as_bytes()],
                |row| {
                    Ok((
                        projected_uuid(row.get(0)?, "invalid tag event ID")?,
                        row.get::<_, Vec<u8>>(1)?,
                    ))
                },
            )
            .optional()?;
        let Some((event_id, payload)) = latest else {
            return Ok(());
        };
        let value: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|_| Error::Metadata)?;
        let tags = value
            .get("body")
            .and_then(|body| body.get("tags"))
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::Metadata)?;
        for tag in tags {
            let tag = tag.as_str().ok_or(Error::Metadata)?;
            self.conn.execute(
                "INSERT OR REPLACE INTO projected_tag(ledger_id,proposition_id,tag,event_id) VALUES(?,?,?,?)",
                params![
                    ledger_id.as_bytes(),
                    proposition_id.as_bytes(),
                    tag,
                    event_id.as_bytes(),
                ],
            )?;
        }
        Ok(())
    }

    pub fn insert_directory_extension_event(
        &self,
        input: DirectoryExtensionEventInput,
    ) -> Result<DirectoryExtensionRow, Error> {
        let payload = directory_extension_payload(&input)?;
        let content_hash = Hash::digest(&payload);
        self.conn.execute(
            "INSERT INTO extension_event(event_id,ledger_id,extension_name,target_id,event_type,actor_id,signing_key_id,created_at,content_hash,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![
                input.event_id.as_bytes(),
                input.ledger_id.as_bytes(),
                "fact.directory",
                input.target_actor_id.as_bytes(),
                input.operation,
                input.actor_id.as_bytes(),
                input.signing_key_id.as_bytes(),
                input.created_at,
                content_hash.as_bytes(),
                payload.as_slice(),
            ],
        )?;
        self.project_directory_extension_for_actor(input.ledger_id, input.target_actor_id)?;
        Ok(DirectoryExtensionRow {
            event_id: input.event_id,
            ledger_id: input.ledger_id,
            target_actor_id: input.target_actor_id,
            target_key_id: input.target_key_id,
            operation: input.operation,
            display_name: input.display_name,
            alias: input.alias,
            actor_type: input.actor_type,
            role: input.role,
            source: input.source,
            verified_by: input.verified_by,
            created_at: input.created_at,
            payload,
        })
    }

    pub fn list_directory_extension_events(
        &self,
        ledger: &[u8; 16],
    ) -> Result<Vec<DirectoryExtensionRow>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT event_id,ledger_id,target_id,event_type,created_at,payload
             FROM extension_event
             WHERE ledger_id=? AND extension_name='fact.directory'
             ORDER BY created_at,event_id",
        )?;
        let rows = statement.query_map([ledger.as_slice()], directory_extension_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn import_directory_extension_event_payload(&self, payload: &[u8]) -> Result<bool, Error> {
        let event = parse_directory_extension_event_payload(payload)?;
        let content_hash = Hash::digest(payload);
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO extension_event(event_id,ledger_id,extension_name,target_id,event_type,actor_id,signing_key_id,created_at,content_hash,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![
                event.event_id.as_bytes(),
                event.ledger_id.as_bytes(),
                "fact.directory",
                event.target_actor_id.as_bytes(),
                event.operation,
                event.actor_id.as_bytes(),
                event.signing_key_id.as_bytes(),
                event.created_at,
                content_hash.as_bytes(),
                payload,
            ],
        )?;
        if inserted > 0 {
            self.project_directory_extension_for_actor(event.ledger_id, event.target_actor_id)?;
        }
        Ok(inserted > 0)
    }

    pub fn list_projected_directory(
        &self,
        ledger: &[u8; 16],
    ) -> Result<Vec<ProjectedDirectoryRow>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT ledger_id,target_actor_id,target_key_id,display_name,alias,actor_type,role,source,verified_by,event_id,payload
             FROM projected_directory
             WHERE ledger_id=?
             ORDER BY display_name,target_actor_id",
        )?;
        let rows = statement.query_map([ledger.as_slice()], projected_directory_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_projected_directory_by_actor(
        &self,
        ledger: &[u8; 16],
        actor_id: &[u8; 16],
    ) -> Result<Option<ProjectedDirectoryRow>, Error> {
        self.conn
            .query_row(
                "SELECT ledger_id,target_actor_id,target_key_id,display_name,alias,actor_type,role,source,verified_by,event_id,payload
                 FROM projected_directory
                 WHERE ledger_id=? AND target_actor_id=?",
                params![ledger.as_slice(), actor_id.as_slice()],
                projected_directory_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_projected_directory_by_alias_or_name(
        &self,
        ledger: &[u8; 16],
        value: &str,
    ) -> Result<Vec<ProjectedDirectoryRow>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT ledger_id,target_actor_id,target_key_id,display_name,alias,actor_type,role,source,verified_by,event_id,payload
             FROM projected_directory
             WHERE ledger_id=? AND (alias=? OR display_name=?)
             ORDER BY display_name,target_actor_id",
        )?;
        let rows = statement.query_map(
            params![ledger.as_slice(), value, value],
            projected_directory_row,
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_actor_key_binding_for_actor(
        &self,
        actor_id: &[u8; 16],
    ) -> Result<Option<(uuid::Uuid, uuid::Uuid)>, Error> {
        self.conn
            .query_row(
                "SELECT binding_id,key_id
                 FROM projected_binding
                 WHERE actor_id=?
                 ORDER BY binding_id DESC
                 LIMIT 1",
                [actor_id.as_slice()],
                |row| {
                    Ok((
                        projected_uuid(row.get(0)?, "invalid binding ID")?,
                        projected_uuid(row.get(1)?, "invalid key ID")?,
                    ))
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn project_directory_extension_for_actor(
        &self,
        ledger_id: uuid::Uuid,
        target_actor_id: uuid::Uuid,
    ) -> Result<(), Error> {
        self.conn.execute(
            "DELETE FROM projected_directory WHERE ledger_id=? AND target_actor_id=?",
            params![ledger_id.as_bytes(), target_actor_id.as_bytes()],
        )?;
        let latest: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT payload
                 FROM extension_event
                 WHERE ledger_id=? AND extension_name='fact.directory' AND target_id=?
                 ORDER BY created_at DESC,event_id DESC
                 LIMIT 1",
                params![ledger_id.as_bytes(), target_actor_id.as_bytes()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(payload) = latest else {
            return Ok(());
        };
        let event = parse_directory_extension_event_payload(&payload)?;
        if event.operation == "remove" {
            return Ok(());
        }
        let display_name = event.display_name.ok_or(Error::Metadata)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO projected_directory(ledger_id,target_actor_id,target_key_id,display_name,alias,actor_type,role,source,verified_by,event_id,payload) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            params![
                ledger_id.as_bytes(),
                target_actor_id.as_bytes(),
                event.target_key_id.map(|value| value.as_bytes().to_vec()),
                display_name,
                event.alias,
                event.actor_type,
                event.role,
                event.source,
                event.verified_by,
                event.event_id.as_bytes(),
                payload,
            ],
        )?;
        Ok(())
    }

    pub fn list_identity_objects(&self) -> Result<Vec<(uuid::Uuid, Hash, String)>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT object_id,content_hash,object_type FROM protocol_object WHERE ledger_id IS NULL OR length(ledger_id)=0 ORDER BY content_hash",
        )?;
        let rows = statement.query_map([], |row| {
            let id: Vec<u8> = row.get(0)?;
            let hash: Vec<u8> = row.get(1)?;
            let object_type: String = row.get(2)?;
            let id = uuid::Uuid::from_slice(&id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;
            let hash: [u8; 32] = hash.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    "invalid hash length".into(),
                )
            })?;
            Ok((id, Hash::from_bytes(hash), object_type))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// List a ledger's canonical objects together with the transitive signed
    /// dependencies required to validate them. Ledger-neutral identity
    /// objects are included when referenced by the ledger graph, while the
    /// ordinary ledger listing remains limited to ledger-scoped objects.
    pub fn list_objects_with_dependencies(
        &self,
        ledger: &[u8; 16],
    ) -> Result<Vec<(uuid::Uuid, Hash, String)>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_objects_with_dependencies
                .set(metrics.list_objects_with_dependencies.get() + 1);
        });
        self.ensure_export_projected(ledger)?;
        let mut statement = self.conn.prepare(
            "SELECT object_id,content_hash,object_type
             FROM projected_export_object
             WHERE ledger_id=?
             ORDER BY content_hash",
        )?;
        let rows = statement.query_map([ledger.as_slice()], |row| {
            let id: Vec<u8> = row.get(0)?;
            let hash: Vec<u8> = row.get(1)?;
            let object_type: String = row.get(2)?;
            let id = uuid::Uuid::from_slice(&id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;
            let hash: [u8; 32] = hash.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    "invalid hash length".into(),
                )
            })?;
            Ok((id, Hash::from_bytes(hash), object_type))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Page a ledger's canonical objects and validation dependencies in
    /// content-hash order. This is intended for bounded sync/export paths that
    /// should not materialize the full dependency closure before applying page
    /// limits.
    pub fn list_objects_with_dependencies_page(
        &self,
        ledger: &[u8; 16],
        after_content_hash: Option<&Hash>,
        limit: usize,
    ) -> Result<Vec<(uuid::Uuid, Hash, String)>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_objects_with_dependencies_page
                .set(metrics.list_objects_with_dependencies_page.get() + 1);
        });
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.ensure_export_projected(ledger)?;
        let after = after_content_hash.map(|hash| hash.as_bytes().to_vec());
        let mut statement = self.conn.prepare(
            "SELECT object_id,content_hash,object_type
             FROM projected_export_object
             WHERE ledger_id=? AND (? IS NULL OR content_hash>?)
             ORDER BY content_hash
             LIMIT ?",
        )?;
        let rows = statement.query_map(
            params![
                ledger.as_slice(),
                after.as_deref(),
                after.as_deref(),
                limit as i64
            ],
            |row| {
                let id: Vec<u8> = row.get(0)?;
                let hash: Vec<u8> = row.get(1)?;
                let object_type: String = row.get(2)?;
                let id = uuid::Uuid::from_slice(&id).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })?;
                let hash: [u8; 32] = hash.try_into().map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Blob,
                        "invalid hash length".into(),
                    )
                })?;
                Ok((id, Hash::from_bytes(hash), object_type))
            },
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_dependency_closure_for_objects(
        &self,
        object_ids: &[uuid::Uuid],
    ) -> Result<Vec<(uuid::Uuid, Hash, String)>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_dependency_closure_for_objects
                .set(metrics.list_dependency_closure_for_objects.get() + 1);
        });
        if object_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut closure = std::collections::HashSet::<Vec<u8>>::new();
        let mut frontier = object_ids
            .iter()
            .map(|object_id| object_id.as_bytes().to_vec())
            .filter(|object_id| closure.insert(object_id.clone()))
            .collect::<Vec<_>>();
        while !frontier.is_empty() {
            let take = frontier.len().min(256);
            let batch = frontier.drain(..take).collect::<Vec<_>>();
            let values_sql = std::iter::repeat_n("(?)", batch.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "WITH seed(object_id) AS (VALUES {values_sql})
                 SELECT d.dependency_id
                 FROM object_dependency d
                 JOIN seed s ON d.object_id=s.object_id"
            );
            let values = batch
                .iter()
                .map(|object_id| Value::Blob(object_id.clone()))
                .collect::<Vec<_>>();
            let mut statement = self.conn.prepare(&sql)?;
            let dependencies = statement
                .query_map(params_from_iter(values.iter()), |row| {
                    row.get::<_, Vec<u8>>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for dependency in dependencies {
                if closure.insert(dependency.clone()) {
                    frontier.push(dependency);
                }
            }
        }

        let mut rows = Vec::new();
        let mut object_ids = closure.into_iter().collect::<Vec<_>>();
        object_ids.sort();
        let mut statement = self
            .conn
            .prepare("SELECT content_hash,object_type FROM protocol_object WHERE object_id=?")?;
        for object_id in object_ids {
            let (hash, object_type): (Hash, String) =
                statement.query_row([object_id.as_slice()], |row| {
                    let hash: Vec<u8> = row.get(0)?;
                    let hash: [u8; 32] = hash.try_into().map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            "invalid hash length".into(),
                        )
                    })?;
                    Ok((Hash::from_bytes(hash), row.get(1)?))
                })?;
            let id = uuid::Uuid::from_slice(&object_id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;
            rows.push((id, hash, object_type));
        }
        rows.sort_by_key(|(_, hash, _)| *hash);
        Ok(rows)
    }

    pub fn list_pending_objects(
        &self,
        ledger: &[u8],
    ) -> Result<Vec<(uuid::Uuid, Hash, String)>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT p.object_id,p.content_hash,p.object_type FROM projected_pending q JOIN protocol_object p ON p.object_id=q.object_id WHERE p.ledger_id=? ORDER BY p.content_hash",
        )?;
        let rows = statement.query_map([ledger], |row| {
            let id: Vec<u8> = row.get(0)?;
            let hash: Vec<u8> = row.get(1)?;
            let object_type: String = row.get(2)?;
            let id = uuid::Uuid::from_slice(&id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;
            let hash: [u8; 32] = hash.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    "invalid hash length".into(),
                )
            })?;
            Ok((id, Hash::from_bytes(hash), object_type))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn list_effective_state(&self, ledger: &[u8]) -> Result<Vec<EffectiveProjected>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_effective_state
                .set(metrics.list_effective_state.get() + 1);
        });
        let mut statement = self.conn.prepare(
            "SELECT e.proposition_id,e.status,e.revision_id,e.deliberation_id,e.settlement_id,e.withdrawal_status,e.archival_status,e.reason FROM projected_effective e JOIN protocol_object p ON p.object_id=e.proposition_id WHERE p.ledger_id=? ORDER BY e.proposition_id",
        )?;
        let rows = statement.query_map([ledger], effective_projected_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn effective_state_for_proposition(
        &self,
        ledger: &[u8; 16],
        proposition_id: &[u8; 16],
    ) -> Result<Option<EffectiveProjected>, Error> {
        self.conn
            .query_row(
                "SELECT e.proposition_id,e.status,e.revision_id,e.deliberation_id,e.settlement_id,e.withdrawal_status,e.archival_status,e.reason
                 FROM projected_effective e INDEXED BY sqlite_autoindex_projected_effective_1
                 JOIN protocol_object p INDEXED BY sqlite_autoindex_protocol_object_1
                   ON p.object_id=e.proposition_id
                 WHERE p.ledger_id=? AND e.proposition_id=?",
                params![ledger.as_slice(), proposition_id.as_slice()],
                effective_projected_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn effective_state_for_propositions(
        &self,
        ledger: &[u8; 16],
        proposition_ids: &[uuid::Uuid],
    ) -> Result<Vec<EffectiveProjected>, Error> {
        if proposition_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        for chunk in proposition_ids.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT e.proposition_id,e.status,e.revision_id,e.deliberation_id,e.settlement_id,e.withdrawal_status,e.archival_status,e.reason
                 FROM projected_effective e INDEXED BY sqlite_autoindex_projected_effective_1
                 JOIN protocol_object p INDEXED BY sqlite_autoindex_protocol_object_1
                   ON p.object_id=e.proposition_id
                 WHERE p.ledger_id=? AND e.proposition_id IN ({placeholders})
                 ORDER BY e.proposition_id"
            );
            let mut values = Vec::with_capacity(chunk.len() + 1);
            values.push(Value::Blob(ledger.to_vec()));
            values.extend(chunk.iter().map(|id| Value::Blob(id.as_bytes().to_vec())));
            let mut statement = self.conn.prepare(&sql)?;
            let rows =
                statement.query_map(params_from_iter(values.iter()), effective_projected_row)?;
            output.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        Ok(output)
    }

    pub fn knowledge_effective_revision_ids(
        &self,
        ledger: &[u8; 16],
    ) -> Result<Vec<uuid::Uuid>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_knowledge_effective_revision_ids
                .set(metrics.list_knowledge_effective_revision_ids.get() + 1);
        });
        let mut statement = self.conn.prepare(
            "SELECT r.revision_id
             FROM projected_revision r
             JOIN projected_effective e ON e.proposition_id=r.proposition_id
             JOIN protocol_object p ON p.object_id=r.proposition_id
             WHERE p.ledger_id=?
               AND p.object_type='proposition'
               AND json_extract(p.payload,'$.body.purpose')='knowledge'
               AND e.revision_id=r.revision_id
               AND e.status='accepted'
               AND e.withdrawal_status='active'
               AND e.archival_status='visible'
             ORDER BY r.revision_id",
        )?;
        let rows = statement.query_map([ledger.as_slice()], |row| {
            projected_uuid(row.get(0)?, "invalid revision ID")
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn knowledge_effective_revision_ids_for_revisions(
        &self,
        ledger: &[u8; 16],
        revision_ids: &[uuid::Uuid],
    ) -> Result<Vec<uuid::Uuid>, Error> {
        if revision_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        for chunk in revision_ids.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT r.revision_id
                 FROM projected_revision r
                 JOIN projected_effective e ON e.proposition_id=r.proposition_id
                 JOIN protocol_object p ON p.object_id=r.proposition_id
                 WHERE p.ledger_id=?
                   AND p.object_type='proposition'
                   AND r.revision_id IN ({placeholders})
                   AND json_extract(p.payload,'$.body.purpose')='knowledge'
                   AND e.revision_id=r.revision_id
                   AND e.status='accepted'
                   AND e.withdrawal_status='active'
                   AND e.archival_status='visible'
                 ORDER BY r.revision_id"
            );
            let mut values = Vec::with_capacity(chunk.len() + 1);
            values.push(Value::Blob(ledger.to_vec()));
            values.extend(chunk.iter().map(|id| Value::Blob(id.as_bytes().to_vec())));
            let mut statement = self.conn.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                projected_uuid(row.get(0)?, "invalid revision ID")
            })?;
            output.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        output.sort();
        Ok(output)
    }

    pub fn knowledge_proposition_ids(&self, ledger: &[u8; 16]) -> Result<Vec<uuid::Uuid>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_knowledge_proposition_ids
                .set(metrics.list_knowledge_proposition_ids.get() + 1);
        });
        let mut statement = self.conn.prepare(
            "SELECT object_id
             FROM protocol_object
             WHERE ledger_id=?
               AND object_type='proposition'
               AND json_extract(payload,'$.body.purpose')='knowledge'
             ORDER BY object_id",
        )?;
        let rows = statement.query_map([ledger.as_slice()], |row| {
            projected_uuid(row.get(0)?, "invalid proposition ID")
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn knowledge_proposition_ids_for_propositions(
        &self,
        ledger: &[u8; 16],
        proposition_ids: &[uuid::Uuid],
    ) -> Result<Vec<uuid::Uuid>, Error> {
        if proposition_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        for chunk in proposition_ids.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT object_id
                 FROM protocol_object
                 WHERE ledger_id=?
                   AND object_type='proposition'
                   AND object_id IN ({placeholders})
                   AND json_extract(payload,'$.body.purpose')='knowledge'
                 ORDER BY object_id"
            );
            let mut values = Vec::with_capacity(chunk.len() + 1);
            values.push(Value::Blob(ledger.to_vec()));
            values.extend(chunk.iter().map(|id| Value::Blob(id.as_bytes().to_vec())));
            let mut statement = self.conn.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                projected_uuid(row.get(0)?, "invalid proposition ID")
            })?;
            output.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        output.sort();
        Ok(output)
    }

    pub fn effective_revision_search_row(
        &self,
        ledger: &[u8; 16],
        revision_id: &[u8; 16],
    ) -> Result<Option<EffectiveRevisionSearchRow>, Error> {
        self.conn
            .query_row(
                "SELECT e.revision_id,e.proposition_id,e.status
                 FROM projected_effective e
                 JOIN projected_revision r
                   ON r.revision_id=e.revision_id
                 JOIN protocol_object p ON p.object_id=r.object_id
                 WHERE p.ledger_id=?
                   AND e.revision_id=?
                   AND e.withdrawal_status='active'
                   AND e.archival_status='visible'",
                params![ledger.as_slice(), revision_id.as_slice()],
                |row| {
                    Ok(EffectiveRevisionSearchRow {
                        revision_id: projected_uuid(row.get(0)?, "invalid revision ID")?,
                        proposition_id: projected_uuid(row.get(1)?, "invalid proposition ID")?,
                        status: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn effective_revision_search_rows(
        &self,
        ledger: &[u8; 16],
        revision_ids: &[uuid::Uuid],
    ) -> Result<Vec<EffectiveRevisionSearchRow>, Error> {
        self.effective_revision_rows_for_ids(ledger, revision_ids, true)
    }

    pub fn effective_revision_status_rows(
        &self,
        ledger: &[u8; 16],
        revision_ids: &[uuid::Uuid],
    ) -> Result<Vec<EffectiveRevisionSearchRow>, Error> {
        self.effective_revision_rows_for_ids(ledger, revision_ids, false)
    }

    fn effective_revision_rows_for_ids(
        &self,
        ledger: &[u8; 16],
        revision_ids: &[uuid::Uuid],
        visible_only: bool,
    ) -> Result<Vec<EffectiveRevisionSearchRow>, Error> {
        if revision_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        for chunk in revision_ids.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let lifecycle_filter = if visible_only {
                " AND e.withdrawal_status='active'
                  AND e.archival_status='visible'"
            } else {
                ""
            };
            let sql = format!(
                "SELECT e.revision_id,e.proposition_id,e.status
                 FROM projected_effective e
                 JOIN projected_revision r
                   ON r.revision_id=e.revision_id
                 JOIN protocol_object p ON p.object_id=r.object_id
                 WHERE p.ledger_id=?
                   AND e.revision_id IN ({placeholders})
                   {lifecycle_filter}
                 ORDER BY e.revision_id"
            );
            let mut values = Vec::with_capacity(chunk.len() + 1);
            values.push(Value::Blob(ledger.to_vec()));
            values.extend(
                chunk
                    .iter()
                    .map(|revision_id| Value::Blob(revision_id.as_bytes().to_vec())),
            );
            let mut statement = self.conn.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                Ok(EffectiveRevisionSearchRow {
                    revision_id: projected_uuid(row.get(0)?, "invalid revision ID")?,
                    proposition_id: projected_uuid(row.get(1)?, "invalid proposition ID")?,
                    status: row.get(2)?,
                })
            })?;
            output.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        Ok(output)
    }

    pub fn list_default_proposition_projecteds(
        &self,
        ledger: &[u8; 16],
        actor: Option<&[u8; 16]>,
    ) -> Result<Vec<PropositionListProjected>, Error> {
        self.list_default_proposition_projecteds_page(ledger, actor, None, 0, None)
    }

    pub fn list_default_proposition_projecteds_page(
        &self,
        ledger: &[u8; 16],
        actor: Option<&[u8; 16]>,
        after_proposition: Option<&[u8; 16]>,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<Vec<PropositionListProjected>, Error> {
        self.list_indexed_proposition_projecteds_page(
            ledger,
            actor,
            IndexedPropositionListQuery {
                status: Some("accepted"),
                include_pending_overlay: false,
                withdrawal_status: None,
                archival_status: None,
                after_proposition,
                offset,
                limit,
            },
        )
    }

    /// Bounded proposition list backed by `indexed_proposition`.
    pub fn list_status_proposition_projecteds_page(
        &self,
        ledger: &[u8; 16],
        actor: Option<&[u8; 16]>,
        status: Option<&str>,
        after_proposition: Option<&[u8; 16]>,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<Vec<PropositionListProjected>, Error> {
        self.list_indexed_proposition_projecteds_page(
            ledger,
            actor,
            IndexedPropositionListQuery {
                status,
                include_pending_overlay: status == Some("pending"),
                withdrawal_status: None,
                archival_status: None,
                after_proposition,
                offset,
                limit,
            },
        )
    }

    pub fn list_lifecycle_proposition_projecteds_page(
        &self,
        ledger: &[u8; 16],
        actor: Option<&[u8; 16]>,
        lifecycle: PropositionLifecycleFilter,
        after_proposition: Option<&[u8; 16]>,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<Vec<PropositionListProjected>, Error> {
        let (withdrawal_status, archival_status) = match lifecycle {
            PropositionLifecycleFilter::Withdrawn => (Some("withdrawn"), None),
            PropositionLifecycleFilter::Archived => (None, Some("archived")),
        };
        self.list_indexed_proposition_projecteds_page(
            ledger,
            actor,
            IndexedPropositionListQuery {
                status: None,
                include_pending_overlay: false,
                withdrawal_status,
                archival_status,
                after_proposition,
                offset,
                limit,
            },
        )
    }

    fn list_indexed_proposition_projecteds_page(
        &self,
        ledger: &[u8; 16],
        actor: Option<&[u8; 16]>,
        query: IndexedPropositionListQuery<'_>,
    ) -> Result<Vec<PropositionListProjected>, Error> {
        self.ensure_indexed_proposition_fresh(ledger)?;
        let actor = actor.map(|actor| actor.to_vec());
        let mut filter_sql = String::new();
        let mut after_sql = "";
        let mut values = vec![Value::Blob(ledger.to_vec())];
        match (query.status, query.include_pending_overlay) {
            (Some(status), true) => {
                filter_sql.push_str(
                    " AND (i.status=? OR i.has_pending_revision=1)
                      AND i.withdrawal_status='active'
                      AND i.archival_status='visible'",
                );
                values.push(Value::Text(status.to_owned()));
            }
            (Some("contested"), false) => {
                filter_sql.push_str(
                    " AND (i.status='contested' OR i.status='conflict')
                      AND i.withdrawal_status='active'
                      AND i.archival_status='visible'",
                );
            }
            (Some(status), false) => {
                filter_sql.push_str(
                    " AND i.status=?
                      AND i.withdrawal_status='active'
                      AND i.archival_status='visible'",
                );
                values.push(Value::Text(status.to_owned()));
            }
            (None, _) => {}
        }
        if let Some(withdrawal_status) = query.withdrawal_status {
            filter_sql.push_str(" AND i.withdrawal_status=?");
            values.push(Value::Text(withdrawal_status.to_owned()));
        }
        if let Some(archival_status) = query.archival_status {
            filter_sql.push_str(" AND i.archival_status=?");
            values.push(Value::Text(archival_status.to_owned()));
        }
        if let Some(after) = query.after_proposition {
            after_sql = "AND i.proposition_id>?";
            values.push(Value::Blob(after.to_vec()));
        }
        let sql = format!(
            "WITH page AS (
                SELECT i.proposition_id
                FROM indexed_proposition i
                WHERE i.ledger_id=?
                  AND i.indexed_version='{INDEXED_PROPOSITION_VERSION}'
                  {filter_sql}
                  {after_sql}
                ORDER BY i.proposition_id
                LIMIT ? OFFSET ?
             )
                 SELECT i.proposition_id,
                        i.status,
                        COALESCE(i.effective_revision_id, i.latest_revision_id),
                        COALESCE(i.effective_deliberation_id, i.pending_deliberation_id),
                        i.settlement_id,
                        i.withdrawal_status,
                        i.archival_status,
                        i.latest_revision_id,
                        i.latest_revision_status,
                        NULL,
                        r.payload,
                        i.pending_revision_id,
                        i.pending_deliberation_id,
                        i.pending_participant_count,
                        CASE WHEN ? IS NULL THEN 0 ELSE EXISTS(
                            SELECT 1
                            FROM projected_participant pp
                            LEFT JOIN projected_decision pd
                              ON pd.deliberation_id=pp.deliberation_id
                             AND pd.participant_actor_id=pp.actor_id
                            WHERE pp.deliberation_id=i.pending_deliberation_id
                              AND pp.actor_id=?
                              AND pp.active=1
                              AND pd.decision_id IS NULL
                        ) END,
                        i.has_pending_revision
                 FROM page
             JOIN indexed_proposition i ON i.proposition_id=page.proposition_id
             LEFT JOIN projected_revision r
               ON r.revision_id=COALESCE(i.effective_revision_id, i.summary_revision_id)
             ORDER BY i.proposition_id"
        );
        push_page_values(
            &mut values,
            query.offset,
            Some(query.limit.unwrap_or(i64::MAX as usize)),
        );
        values.push(
            actor
                .as_deref()
                .map_or(Value::Null, |actor| Value::Blob(actor.to_vec())),
        );
        values.push(
            actor
                .as_deref()
                .map_or(Value::Null, |actor| Value::Blob(actor.to_vec())),
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values.iter()), default_proposition_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn ensure_indexed_proposition_fresh(&self, ledger: &[u8; 16]) -> Result<(), Error> {
        let Some((propositions, effective, indexed, stale, version)) = self
            .conn
            .query_row(
                "SELECT proposition_count,
                        effective_count,
                        indexed_count,
                        stale_count,
                        indexed_version
                 FROM indexed_proposition_meta
                 WHERE ledger_id=?",
                [ledger.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?
        else {
            return Err(Error::IndexedPropositionStale);
        };
        if propositions != effective
            || propositions != indexed
            || stale != 0
            || version != INDEXED_PROPOSITION_VERSION
        {
            return Err(Error::IndexedPropositionStale);
        }
        if propositions > 0 {
            let (has_protocol, has_effective, has_indexed): (i64, i64, i64) = self.conn.query_row(
                "SELECT
                    EXISTS(
                        SELECT 1
                        FROM protocol_object
                        WHERE ledger_id=? AND object_type='proposition'
                        LIMIT 1
                    ),
                    EXISTS(
                        SELECT 1
                        FROM projected_effective e
                        JOIN protocol_object p ON p.object_id=e.proposition_id
                        WHERE p.ledger_id=? AND p.object_type='proposition'
                        LIMIT 1
                    ),
                    EXISTS(
                        SELECT 1
                        FROM indexed_proposition
                        WHERE ledger_id=?
                        LIMIT 1
                    )",
                params![ledger.as_slice(), ledger.as_slice(), ledger.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            if has_protocol == 0 || has_effective == 0 || has_indexed == 0 {
                return Err(Error::IndexedPropositionStale);
            }
        }
        Ok(())
    }

    pub fn indexed_proposition_metadata(
        &self,
        ledger: &[u8; 16],
        proposition_id: &[u8; 16],
        actor: Option<&[u8; 16]>,
    ) -> Result<Option<IndexedPropositionMetadata>, Error> {
        self.ensure_indexed_proposition_fresh(ledger)?;
        let actor = actor.map(|actor| actor.to_vec());
        self.conn
            .query_row(
                "SELECT i.proposition_id,
                        i.status,
                        i.effective_reason,
                        i.effective_revision_id,
                        i.effective_deliberation_id,
                        i.settlement_id,
                        i.latest_revision_id,
                        i.latest_revision_status,
                        i.pending_revision_id,
                        i.pending_deliberation_id,
                        i.pending_participant_count,
                        CASE WHEN ? IS NULL THEN 0 ELSE EXISTS(
                            SELECT 1
                            FROM projected_participant pp
                            LEFT JOIN projected_decision pd
                              ON pd.deliberation_id=pp.deliberation_id
                             AND pd.participant_actor_id=pp.actor_id
                            WHERE pp.deliberation_id=i.pending_deliberation_id
                              AND pp.actor_id=?
                              AND pp.active=1
                              AND pd.decision_id IS NULL
                        ) END,
                        i.has_pending_revision,
                        i.withdrawal_status,
                        i.archival_status
                 FROM indexed_proposition i
                 WHERE i.ledger_id=?
                   AND i.proposition_id=?
                   AND i.indexed_version=?",
                params![
                    actor.as_deref(),
                    actor.as_deref(),
                    ledger.as_slice(),
                    proposition_id.as_slice(),
                    INDEXED_PROPOSITION_VERSION
                ],
                indexed_proposition_metadata_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn check_indexed_proposition_consistency(
        &self,
        ledger: &[u8; 16],
        actor: Option<&[u8; 16]>,
    ) -> Result<Vec<uuid::Uuid>, Error> {
        let indexed =
            self.list_status_proposition_projecteds_page(ledger, actor, None, None, 0, None)?;
        let legacy = self.list_proposition_projecteds(ledger, actor)?;
        let mut indexed = indexed
            .into_iter()
            .map(|row| (row.proposition_id, row))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut mismatches = Vec::new();
        for legacy in legacy {
            match indexed.remove(&legacy.proposition_id) {
                Some(row) if indexed_proposition_rows_match(&row, &legacy) => {}
                _ => mismatches.push(legacy.proposition_id),
            }
        }
        mismatches.extend(indexed.into_keys());
        Ok(mismatches)
    }

    pub fn list_proposition_projecteds(
        &self,
        ledger: &[u8; 16],
        actor: Option<&[u8; 16]>,
    ) -> Result<Vec<PropositionListProjected>, Error> {
        let mut propositions = std::collections::BTreeSet::<uuid::Uuid>::new();
        let mut proposition_statement = self
            .conn
            .prepare("SELECT object_id FROM protocol_object WHERE ledger_id=? AND object_type='proposition' ORDER BY object_id")?;
        let proposition_rows = proposition_statement.query_map([ledger.as_slice()], |row| {
            projected_uuid(row.get(0)?, "invalid proposition ID")
        })?;
        for row in proposition_rows {
            propositions.insert(row?);
        }

        let mut effective = std::collections::HashMap::new();
        for state in self.list_effective_state(ledger)? {
            effective.insert(state.proposition_id.uuid(), state);
        }

        let mut revisions_by_proposition =
            std::collections::HashMap::<uuid::Uuid, Vec<RevisionProjectedRow>>::new();
        let mut revision_payloads = std::collections::HashMap::<uuid::Uuid, Vec<u8>>::new();
        let mut revision_statement = self.conn.prepare(
            "SELECT r.revision_id,r.proposition_id,r.parent_revision_id,r.payload
             FROM projected_revision r
             JOIN protocol_object p ON p.object_id=r.object_id
             WHERE p.ledger_id=?
             ORDER BY r.revision_id",
        )?;
        let revision_rows = revision_statement.query_map([ledger.as_slice()], |row| {
            Ok(RevisionProjectedRow {
                revision_id: projected_uuid(row.get(0)?, "invalid revision ID")?,
                proposition_id: projected_uuid(row.get(1)?, "invalid proposition ID")?,
                parent_revision_id: optional_projected_uuid(row.get(2)?)?,
                payload: row.get(3)?,
            })
        })?;
        for row in revision_rows {
            let row = row?;
            revision_payloads.insert(row.revision_id, row.payload.clone());
            revisions_by_proposition
                .entry(row.proposition_id)
                .or_default()
                .push(row);
        }

        let mut deliberations_by_proposition =
            std::collections::HashMap::<uuid::Uuid, Vec<DeliberationProjectedRow>>::new();
        let mut deliberation_statement = self.conn.prepare(
            "SELECT d.deliberation_id,d.proposition_id,d.revision_id,d.settled
             FROM projected_deliberation d
             JOIN protocol_object p ON p.object_id=d.object_id
             WHERE p.ledger_id=?
             ORDER BY d.deliberation_id",
        )?;
        let deliberation_rows = deliberation_statement.query_map([ledger.as_slice()], |row| {
            Ok(DeliberationProjectedRow {
                deliberation_id: projected_uuid(row.get(0)?, "invalid deliberation ID")?,
                proposition_id: projected_uuid(row.get(1)?, "invalid proposition ID")?,
                revision_id: projected_uuid(row.get(2)?, "invalid revision ID")?,
                settled: row.get::<_, i64>(3)? != 0,
            })
        })?;
        for row in deliberation_rows {
            let row = row?;
            deliberations_by_proposition
                .entry(row.proposition_id)
                .or_default()
                .push(row);
        }

        let mut consensus_by_deliberation = std::collections::HashMap::new();
        let mut consensus_statement = self.conn.prepare(
            "SELECT c.deliberation_id,c.revision_id,c.consensus
             FROM projected_consensus c
             JOIN projected_deliberation d ON d.deliberation_id=c.deliberation_id
             JOIN protocol_object p ON p.object_id=d.object_id
             WHERE p.ledger_id=?",
        )?;
        let consensus_rows = consensus_statement.query_map([ledger.as_slice()], |row| {
            Ok(ConsensusProjectedRow {
                deliberation_id: projected_uuid(row.get(0)?, "invalid deliberation ID")?,
                revision_id: projected_uuid(row.get(1)?, "invalid revision ID")?,
                consensus: row.get(2)?,
            })
        })?;
        for row in consensus_rows {
            let row = row?;
            consensus_by_deliberation.insert(row.deliberation_id, row);
        }

        let mut active_participants =
            std::collections::HashMap::<uuid::Uuid, std::collections::HashSet<uuid::Uuid>>::new();
        let mut participant_statement = self.conn.prepare(
            "SELECT pp.deliberation_id,pp.actor_id
             FROM projected_participant pp
             JOIN projected_deliberation d ON d.deliberation_id=pp.deliberation_id
             JOIN protocol_object p ON p.object_id=d.object_id
             WHERE p.ledger_id=? AND pp.active=1",
        )?;
        let participant_rows = participant_statement.query_map([ledger.as_slice()], |row| {
            Ok((
                projected_uuid(row.get(0)?, "invalid deliberation ID")?,
                projected_uuid(row.get(1)?, "invalid actor ID")?,
            ))
        })?;
        for row in participant_rows {
            let (deliberation_id, actor_id) = row?;
            active_participants
                .entry(deliberation_id)
                .or_default()
                .insert(actor_id);
        }

        let mut decisions =
            std::collections::HashMap::<uuid::Uuid, std::collections::HashSet<uuid::Uuid>>::new();
        let mut decision_statement = self.conn.prepare(
            "SELECT pd.deliberation_id,pd.participant_actor_id
             FROM projected_decision pd
             JOIN projected_deliberation d ON d.deliberation_id=pd.deliberation_id
             JOIN protocol_object p ON p.object_id=d.object_id
             WHERE p.ledger_id=?",
        )?;
        let decision_rows = decision_statement.query_map([ledger.as_slice()], |row| {
            Ok((
                projected_uuid(row.get(0)?, "invalid deliberation ID")?,
                projected_uuid(row.get(1)?, "invalid actor ID")?,
            ))
        })?;
        for row in decision_rows {
            let (deliberation_id, actor_id) = row?;
            decisions
                .entry(deliberation_id)
                .or_default()
                .insert(actor_id);
        }

        let actor = actor.copied().map(uuid::Uuid::from_bytes);
        let mut rows = Vec::new();
        for proposition_id in propositions {
            let state = effective.get(&proposition_id);
            let revisions = revisions_by_proposition
                .get(&proposition_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let initial_revision_id = revisions
                .iter()
                .find(|revision| revision.parent_revision_id.is_none())
                .map(|revision| revision.revision_id)
                .or_else(|| revisions.iter().map(|revision| revision.revision_id).min());
            let revision_id = state
                .and_then(|state| state.revision_id.map(|id| id.uuid()))
                .or(initial_revision_id);
            let deliberations = deliberations_by_proposition
                .get(&proposition_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let initial_deliberation_id = revision_id.and_then(|revision_id| {
                deliberations
                    .iter()
                    .find(|deliberation| deliberation.revision_id == revision_id)
                    .map(|deliberation| deliberation.deliberation_id)
            });
            let (activity, summary_revision_id) = proposition_activity_from_projecteds(
                revisions,
                deliberations,
                &consensus_by_deliberation,
                &active_participants,
                &decisions,
                actor,
                revision_id,
            );
            rows.push(PropositionListProjected {
                proposition_id,
                status: state.map_or_else(|| "pending".to_owned(), |state| state.status.clone()),
                revision_id,
                deliberation_id: state
                    .and_then(|state| state.deliberation_id.map(|id| id.uuid()))
                    .or(initial_deliberation_id),
                settlement_id: state.and_then(|state| state.settlement_id.map(|id| id.uuid())),
                effective_status: state
                    .map_or_else(|| "pending".to_owned(), |state| state.status.clone()),
                latest_revision_id: activity.latest_revision_id,
                latest_revision_status: activity.latest_revision_status,
                pending_revision_id: activity.pending_revision_id,
                pending_deliberation_id: activity.pending_deliberation_id,
                pending_participant_count: activity.pending_participant_count,
                current_actor_pending: activity.current_actor_pending,
                has_pending_revision: activity.has_pending_revision,
                summary_text: None,
                summary_revision_payload: summary_revision_id
                    .and_then(|id| revision_payloads.get(&id).cloned()),
                withdrawal_status: state.map_or_else(
                    || "active".to_owned(),
                    |state| state.withdrawal_status.clone(),
                ),
                archival_status: state.map_or_else(
                    || "visible".to_owned(),
                    |state| state.archival_status.clone(),
                ),
            });
        }
        Ok(rows)
    }

    pub fn count_pending_propositions_for_actor(
        &self,
        ledger: &[u8; 16],
        actor: &[u8; 16],
    ) -> Result<usize, Error> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT d.proposition_id)
             FROM projected_deliberation d
             JOIN protocol_object p
               ON p.object_id=d.object_id
              AND p.ledger_id=?
             JOIN projected_participant pp
               ON pp.deliberation_id=d.deliberation_id
              AND pp.actor_id=?
              AND pp.active=1
             LEFT JOIN projected_decision pd
               ON pd.deliberation_id=pp.deliberation_id
              AND pd.participant_actor_id=pp.actor_id
             WHERE d.settled=0
               AND pd.decision_id IS NULL",
            params![ledger.as_slice(), actor.as_slice()],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Return canonical Markdown-bearing objects for a deterministic search
    /// projected. The object content hash, rather than the Markdown hash, is
    /// retained as the search-result identity.
    pub fn list_markdown_documents(
        &self,
        ledger: &[u8; 16],
    ) -> Result<Vec<(Hash, Vec<u8>)>, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .list_markdown_documents
                .set(metrics.list_markdown_documents.get() + 1);
        });
        let mut statement = self.conn.prepare(
            "SELECT content_hash,payload FROM protocol_object WHERE ledger_id=? AND object_type IN ('revision','deliberation_comment') ORDER BY content_hash",
        )?;
        let rows = statement.query_map([ledger.as_slice()], |row| {
            let hash: Vec<u8> = row.get(0)?;
            let payload: Vec<u8> = row.get(1)?;
            Ok((hash, payload))
        })?;
        let mut documents = Vec::new();
        for row in rows {
            let (hash, payload) = row?;
            let hash: [u8; 32] = hash.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    "invalid object hash length".into(),
                )
            })?;
            let value: serde_json::Value = serde_json::from_slice(&payload).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;
            let Some(bytes) = value
                .get("body")
                .and_then(|body| body.get("content"))
                .and_then(|content| content.get("bytes"))
                .and_then(serde_json::Value::as_str)
                .and_then(decode_b64url)
            else {
                continue;
            };
            documents.push((Hash::from_bytes(hash), bytes));
        }
        Ok(documents)
    }

    pub fn search_index_status(&self, ledger: &[u8; 16]) -> Result<SearchIndexStatus, Error> {
        let meta = self.search_index_meta(ledger)?;
        Ok(SearchIndexStatus {
            ledger_id: uuid::Uuid::from_bytes(*ledger),
            canonical_document_count: meta.canonical_document_count as usize,
            indexed_document_count: meta.indexed_document_count as usize,
            stale: meta.canonical_document_count != meta.indexed_document_count,
        })
    }

    fn search_index_meta(&self, ledger: &[u8; 16]) -> Result<SearchIndexMeta, Error> {
        if let Some(meta) = self
            .conn
            .query_row(
                "SELECT canonical_document_count,indexed_document_count,total_token_count
                 FROM search_index_meta
                 WHERE ledger_id=?",
                [ledger.as_slice()],
                |row| {
                    Ok(SearchIndexMeta {
                        canonical_document_count: row.get(0)?,
                        indexed_document_count: row.get(1)?,
                        total_token_count: row.get(2)?,
                    })
                },
            )
            .optional()?
        {
            return Ok(meta);
        }
        self.refresh_search_index_meta(ledger)
    }

    fn refresh_search_index_meta(&self, ledger: &[u8; 16]) -> Result<SearchIndexMeta, Error> {
        let canonical_document_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM protocol_object WHERE ledger_id=? AND object_type IN ('revision','deliberation_comment')",
            [ledger.as_slice()],
            |row| row.get(0),
        )?;
        let (indexed_document_count, total_token_count): (i64, i64) = self.conn.query_row(
            "SELECT COUNT(*),COALESCE(SUM(token_count),0) FROM search_document WHERE ledger_id=?",
            [ledger.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let meta = SearchIndexMeta {
            canonical_document_count,
            indexed_document_count,
            total_token_count,
        };
        self.store_search_index_meta(ledger, meta)?;
        Ok(meta)
    }

    fn store_search_index_meta(
        &self,
        ledger: &[u8; 16],
        meta: SearchIndexMeta,
    ) -> Result<(), Error> {
        self.conn.execute(
            "INSERT INTO search_index_meta(ledger_id,canonical_document_count,indexed_document_count,total_token_count)
             VALUES(?,?,?,?)
             ON CONFLICT(ledger_id) DO UPDATE SET
               canonical_document_count=excluded.canonical_document_count,
               indexed_document_count=excluded.indexed_document_count,
               total_token_count=excluded.total_token_count",
            params![
                ledger.as_slice(),
                meta.canonical_document_count,
                meta.indexed_document_count,
                meta.total_token_count
            ],
        )?;
        Ok(())
    }

    fn note_search_bearing_object(&self, object: &ValidatedObject) -> Result<(), Error> {
        if object.ledger.is_empty()
            || !matches!(
                object.object_type.as_str(),
                "revision" | "deliberation_comment"
            )
        {
            return Ok(());
        }
        self.conn.execute(
            "INSERT INTO search_index_meta(ledger_id,canonical_document_count,indexed_document_count,total_token_count)
             VALUES(?,?,?,?)
             ON CONFLICT(ledger_id) DO UPDATE SET
               canonical_document_count=search_index_meta.canonical_document_count+1",
            params![object.ledger.as_slice(), 1_i64, 0_i64, 0_i64],
        )?;
        Ok(())
    }

    pub fn rebuild_search_index(&self, ledger: &[u8; 16]) -> Result<SearchIndexStatus, Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .search_index_rebuilds
                .set(metrics.search_index_rebuilds.get() + 1);
        });
        let documents = self.markdown_search_documents(ledger)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM search_fts WHERE ledger_id=?",
            [ledger.as_slice()],
        )?;
        tx.execute(
            "DELETE FROM search_document WHERE ledger_id=?",
            [ledger.as_slice()],
        )?;
        tx.execute(
            "DELETE FROM search_term_stat WHERE ledger_id=?",
            [ledger.as_slice()],
        )?;
        let mut indexed_document_count = 0_i64;
        let mut total_token_count = 0_i64;
        let mut document_frequencies = HashMap::<String, i64>::new();
        for document in documents {
            let extracted_text = fact_search::extract_markdown(&document.markdown);
            let tokens = fact_search::tokenize(&extracted_text);
            indexed_document_count += 1;
            total_token_count += tokens.len() as i64;
            let term_frequency_map = token_frequencies(&tokens);
            for term in term_frequency_map.keys() {
                *document_frequencies.entry(term.clone()).or_default() += 1;
            }
            let term_frequencies = serde_json::to_string(&term_frequency_map)
                .map_err(|_| Error::SearchIndex("invalid term frequencies"))?;
            tx.execute(
                "INSERT INTO search_document(content_hash,ledger_id,object_id,object_type,extracted_text,token_count,term_frequencies,extraction_profile) VALUES(?,?,?,?,?,?,?,?)",
                params![
                    document.content_hash.as_bytes(),
                    ledger.as_slice(),
                    document.object_id.as_bytes(),
                    document.object_type,
                    extracted_text,
                    tokens.len() as i64,
                    term_frequencies,
                    fact_search::EXTRACTION_PROFILE,
                ],
            )?;
            tx.execute(
                "INSERT INTO search_fts(ledger_id,content_hash,extracted_text) VALUES(?,?,?)",
                params![
                    ledger.as_slice(),
                    document.content_hash.as_bytes(),
                    tokens.join(" ")
                ],
            )?;
        }
        {
            let mut statement = tx.prepare(
                "INSERT INTO search_term_stat(ledger_id,term,document_frequency) VALUES(?,?,?)",
            )?;
            for (term, document_frequency) in document_frequencies {
                statement.execute(params![ledger.as_slice(), term, document_frequency])?;
            }
        }
        tx.commit()?;
        let canonical_document_count = self.conn.query_row(
            "SELECT COUNT(*) FROM protocol_object WHERE ledger_id=? AND object_type IN ('revision','deliberation_comment')",
            [ledger.as_slice()],
            |row| row.get(0),
        )?;
        self.store_search_index_meta(
            ledger,
            SearchIndexMeta {
                canonical_document_count,
                indexed_document_count,
                total_token_count,
            },
        )?;
        self.search_index_status(ledger)
    }

    pub fn search_markdown_index(
        &self,
        ledger: &[u8; 16],
        query: &str,
        limit: usize,
    ) -> Result<Vec<SearchIndexHit>, Error> {
        self.search_markdown_index_with_filters(ledger, query, limit, None, &[])
    }

    pub fn search_markdown_index_by_type(
        &self,
        ledger: &[u8; 16],
        query: &str,
        limit: usize,
        object_types: &[&str],
    ) -> Result<Vec<SearchIndexHit>, Error> {
        self.search_markdown_index_with_filters(ledger, query, limit, None, object_types)
    }

    pub fn search_markdown_index_filtered(
        &self,
        ledger: &[u8; 16],
        query: &str,
        limit: usize,
        allowed_hashes: &[Hash],
    ) -> Result<Vec<SearchIndexHit>, Error> {
        self.search_markdown_index_with_filters(ledger, query, limit, Some(allowed_hashes), &[])
    }

    fn search_markdown_index_with_filters(
        &self,
        ledger: &[u8; 16],
        query: &str,
        limit: usize,
        allowed_hashes: Option<&[Hash]>,
        object_types: &[&str],
    ) -> Result<Vec<SearchIndexHit>, Error> {
        let mut meta = self.search_index_meta(ledger)?;
        if meta.canonical_document_count != meta.indexed_document_count {
            let status = self.rebuild_search_index(ledger)?;
            meta = SearchIndexMeta {
                canonical_document_count: status.canonical_document_count as i64,
                indexed_document_count: status.indexed_document_count as i64,
                total_token_count: self.search_index_meta(ledger)?.total_token_count,
            };
        }
        let allowed_hashes = allowed_hashes.map(|hashes| {
            hashes
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
        });
        let query_tokens = fact_search::tokenize(query);
        if query_tokens.is_empty() {
            return Ok(Vec::new());
        }
        let unique = unique_tokens(query_tokens);
        let match_query = unique
            .iter()
            .map(|term| format!("\"{}\"", term.replace('"', "")))
            .collect::<Vec<_>>()
            .join(" AND ");
        let mut sql =
            "SELECT d.content_hash,d.object_id,d.object_type,d.term_frequencies,d.token_count
             FROM search_fts f
             JOIN search_document d
               ON d.ledger_id=f.ledger_id AND d.content_hash=f.content_hash
             WHERE search_fts MATCH ? AND f.ledger_id=?"
                .to_owned();
        let mut values = vec![
            Value::Text(match_query),
            Value::Blob(ledger.as_slice().to_vec()),
        ];
        if !object_types.is_empty() {
            sql.push_str(" AND d.object_type IN (");
            sql.push_str(
                &std::iter::repeat_n("?", object_types.len())
                    .collect::<Vec<_>>()
                    .join(","),
            );
            sql.push(')');
            values.extend(
                object_types
                    .iter()
                    .map(|object_type| Value::Text((*object_type).to_owned())),
            );
        }
        if limit != usize::MAX {
            sql.push_str(" LIMIT ?");
            values.push(Value::Integer(limit.min(i64::MAX as usize) as i64));
        }
        let mut candidate_statement = self.conn.prepare(&sql)?;
        let candidates = candidate_statement
            .query_map(params_from_iter(values.iter()), |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .search_index_candidate_rows
                .set(metrics.search_index_candidate_rows.get() + candidates.len() as u64);
        });
        let document_count = meta.indexed_document_count as f64;
        let total_len = meta.total_token_count as f64;
        let avgdl = if document_count == 0.0 {
            1.0
        } else {
            total_len / document_count
        };
        let document_frequencies = self.search_document_frequencies(ledger, &unique)?;
        let mut ranked = Vec::new();
        let mut metadata_by_hash = HashMap::new();
        for (raw, object_id, object_type, term_frequencies, token_count) in candidates {
            let hash: [u8; 32] = raw
                .try_into()
                .map_err(|_| Error::SearchIndex("invalid hash"))?;
            let hash = Hash::from_bytes(hash);
            let object_id = uuid::Uuid::from_slice(&object_id)
                .map_err(|_| Error::SearchIndex("invalid object id"))?;
            if allowed_hashes
                .as_ref()
                .is_some_and(|allowed_hashes| !allowed_hashes.contains(&hash))
            {
                continue;
            }
            metadata_by_hash.insert(hash, (object_id, object_type));
            let term_frequencies = parse_term_frequencies(&term_frequencies)?;
            let mut score = 0.0;
            for term in &unique {
                let tf = term_frequencies.get(term).copied().unwrap_or(0) as f64;
                if tf == 0.0 {
                    continue;
                }
                let df = *document_frequencies.get(term).unwrap_or(&0) as f64;
                let idf = (1.0 + (document_count - df + 0.5) / (df + 0.5)).ln();
                score += idf * (tf * 2.2)
                    / (tf + 1.2 * (1.0 - 0.75 + 0.75 * token_count as f64 / avgdl));
            }
            ranked.push(fact_search::Ranked {
                hash,
                score: serialize_search_score(score),
            });
        }
        let mut ranked = fact_search::order(fact_search::Profile::LexicalBm25, ranked)
            .map_err(|_| Error::SearchIndex("invalid ranking"))?;
        if ranked.len() > limit {
            ranked.truncate(limit);
        }
        Ok(ranked
            .into_iter()
            .filter_map(|ranked| {
                let (object_id, object_type) = metadata_by_hash.remove(&ranked.hash)?;
                Some(SearchIndexHit {
                    object_id,
                    object_type,
                    content_hash: ranked.hash,
                    score: ranked.score,
                    extraction_profile: fact_search::EXTRACTION_PROFILE,
                })
            })
            .collect())
    }

    fn search_document_frequencies(
        &self,
        ledger: &[u8; 16],
        terms: &[String],
    ) -> Result<HashMap<String, i64>, Error> {
        if self.search_term_stats_populated(ledger)? {
            return self.search_term_frequencies_from_stats(ledger, terms);
        }
        self.rebuild_search_term_stats(ledger)?;
        self.search_term_frequencies_from_stats(ledger, terms)
    }

    fn search_term_stats_populated(&self, ledger: &[u8; 16]) -> Result<bool, Error> {
        let indexed_document_count = self.search_index_meta(ledger)?.indexed_document_count;
        if indexed_document_count == 0 {
            return Ok(true);
        }
        let term_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM search_term_stat WHERE ledger_id=?",
            [ledger.as_slice()],
            |row| row.get(0),
        )?;
        Ok(term_count != 0)
    }

    fn search_term_frequencies_from_stats(
        &self,
        ledger: &[u8; 16],
        terms: &[String],
    ) -> Result<HashMap<String, i64>, Error> {
        let mut frequencies = HashMap::with_capacity(terms.len());
        let mut statement = self.conn.prepare(
            "SELECT document_frequency
             FROM search_term_stat
             WHERE ledger_id=? AND term=?",
        )?;
        for term in terms {
            let count = statement
                .query_row(params![ledger.as_slice(), term], |row| row.get(0))
                .optional()?
                .unwrap_or(0);
            frequencies.insert(term.clone(), count);
        }
        Ok(frequencies)
    }

    fn rebuild_search_term_stats(&self, ledger: &[u8; 16]) -> Result<(), Error> {
        let mut statement = self.conn.prepare(
            "SELECT term_frequencies
             FROM search_document
             WHERE ledger_id=?",
        )?;
        let rows = statement.query_map([ledger.as_slice()], |row| row.get::<_, String>(0))?;
        let mut document_frequencies = HashMap::<String, i64>::new();
        for row in rows {
            let frequencies = parse_term_frequencies(&row?)?;
            for term in frequencies.keys() {
                *document_frequencies.entry(term.clone()).or_default() += 1;
            }
        }
        drop(statement);
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM search_term_stat WHERE ledger_id=?",
            [ledger.as_slice()],
        )?;
        {
            let mut statement = tx.prepare(
                "INSERT INTO search_term_stat(ledger_id,term,document_frequency) VALUES(?,?,?)",
            )?;
            for (term, document_frequency) in document_frequencies {
                statement.execute(params![ledger.as_slice(), term, document_frequency])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn markdown_search_documents(
        &self,
        ledger: &[u8; 16],
    ) -> Result<Vec<MarkdownSearchDocument>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT object_id,object_type,content_hash,payload FROM protocol_object WHERE ledger_id=? AND object_type IN ('revision','deliberation_comment') ORDER BY content_hash",
        )?;
        let rows = statement.query_map([ledger.as_slice()], |row| {
            Ok(MarkdownSearchDocument {
                object_id: uuid::Uuid::from_slice(&row.get::<_, Vec<u8>>(0)?).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })?,
                object_type: row.get(1)?,
                content_hash: Hash::from_bytes(row.get::<_, Vec<u8>>(2)?.try_into().map_err(
                    |_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Blob,
                            "invalid object hash length".into(),
                        )
                    },
                )?),
                payload: row.get(3)?,
                markdown: Vec::new(),
            })
        })?;
        let mut documents = Vec::new();
        for row in rows {
            let row = row?;
            let value: serde_json::Value =
                serde_json::from_slice(&row.payload).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })?;
            let Some(markdown) = value
                .get("body")
                .and_then(|body| body.get("content"))
                .and_then(|content| content.get("bytes"))
                .and_then(serde_json::Value::as_str)
                .and_then(decode_b64url)
            else {
                continue;
            };
            fact_canonical::validate_canonical_markdown(&markdown)
                .map_err(|_| Error::SearchIndex("noncanonical markdown document"))?;
            documents.push(MarkdownSearchDocument { markdown, ..row });
        }
        Ok(documents)
    }

    pub fn list_ledgers(&self) -> Result<Vec<(String, String)>, Error> {
        Ok(self
            .list_ledger_metadata()?
            .into_iter()
            .map(|(id, namespace, _)| (id, namespace))
            .collect())
    }

    pub fn list_ledger_metadata(&self) -> Result<Vec<(String, String, Option<Hash>)>, Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT ledger_id, namespace, (SELECT content_hash FROM protocol_object WHERE protocol_object.ledger_id=ledger.ledger_id AND object_type='genesis' ORDER BY content_hash LIMIT 1) FROM ledger ORDER BY ledger_id")?;
        let rows = stmt.query_map([], |r| {
            let id: Vec<u8> = r.get(0)?;
            let namespace: String = r.get(1)?;
            let genesis_hash: Option<Vec<u8>> = r.get(2)?;
            let genesis_hash = genesis_hash
                .map(|bytes| {
                    bytes.try_into().map(Hash::from_bytes).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Blob,
                            "invalid genesis hash length".into(),
                        )
                    })
                })
                .transpose()?;
            Ok((
                uuid::Uuid::from_slice(&id)
                    .map(|u| u.to_string())
                    .unwrap_or_default(),
                namespace,
                genesis_hash,
            ))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn count_consensus_projecteds(&self) -> Result<usize, Error> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM projected_consensus", [], |row| {
                    row.get(0)
                })?;
        Ok(count as usize)
    }

    pub fn count_effective_projecteds(&self) -> Result<usize, Error> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM projected_effective", [], |row| {
                    row.get(0)
                })?;
        Ok(count as usize)
    }

    /// Return a deterministic advisory timestamp for a commitment over the
    /// current canonical set. Using the latest signed object time keeps an
    /// unchanged commitment byte-stable across repeated HTTP requests.
    pub fn latest_object_created_at(&self, ledger: &[u8; 16]) -> Result<Option<String>, Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload FROM protocol_object WHERE ledger_id=?")?;
        let mut latest = None;
        for row in stmt.query_map([ledger.as_slice()], |r| r.get::<_, Vec<u8>>(0))? {
            let payload = row?;
            let value: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| Error::Metadata)?;
            let created_at = value
                .get("created_at")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::Metadata)?;
            if latest.as_deref().is_none_or(|current| created_at > current) {
                latest = Some(created_at.to_owned());
            }
        }
        Ok(latest)
    }

    pub fn get_ledger_metadata(
        &self,
        ledger_id: &[u8; 16],
    ) -> Result<Option<(String, Option<Hash>)>, Error> {
        self.conn
            .query_row(
                "SELECT namespace, (SELECT content_hash FROM protocol_object WHERE protocol_object.ledger_id=ledger.ledger_id AND object_type='genesis' ORDER BY content_hash LIMIT 1) FROM ledger WHERE ledger_id=?",
                [ledger_id.as_slice()],
                |row| {
                    let namespace: String = row.get(0)?;
                    let genesis_hash: Option<Vec<u8>> = row.get(1)?;
                    let genesis_hash = genesis_hash
                        .map(|bytes| {
                            bytes.try_into().map(Hash::from_bytes).map_err(|_| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    1,
                                    rusqlite::types::Type::Blob,
                                    "invalid genesis hash length".into(),
                                )
                            })
                        })
                        .transpose()?;
                    Ok((namespace, genesis_hash))
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Rebuild disposable projecteds from the immutable canonical object
    /// table, then verify every typed row remains byte-identical to its source.
    pub fn rebuild_projecteds(&self) -> Result<(), Error> {
        #[cfg(debug_assertions)]
        STORE_DEBUG_METRICS.with(|metrics| {
            metrics
                .projected_rebuilds
                .set(metrics.projected_rebuilds.get() + 1);
        });
        if !self.projected_object_matches_protocol()? {
            self.conn.execute_batch("DELETE FROM projected_object; INSERT INTO projected_object(object_id,ledger_id,object_type,content_hash,payload) SELECT object_id,ledger_id,object_type,content_hash,payload FROM protocol_object;")?;
            self.checkpoint_rebuild_wal()?;
        }
        for object_type in fact_schema::OBJECT_TYPES {
            let table = format!("protocol_{object_type}");
            let expected: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM protocol_object WHERE object_type=?",
                [object_type],
                |row| row.get(0),
            )?;
            let actual: i64 =
                self.conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
            if expected != actual {
                return Err(Error::ProjectedMismatch);
            }
        }
        let projected_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM projected_object", [], |row| {
                    row.get(0)
                })?;
        let canonical_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM protocol_object", [], |row| row.get(0))?;
        if projected_count != canonical_count {
            return Err(Error::ProjectedMismatch);
        }
        if !self.export_projected_matches_protocol()? {
            self.rebuild_export_projected()?;
            self.checkpoint_rebuild_wal()?;
        }
        if !self.domain_projecteds_are_complete()? {
            self.rebuild_domain_projecteds()?;
            self.checkpoint_rebuild_wal()?;
            self.rebuild_consensus()?;
            self.checkpoint_rebuild_wal()?;
        }
        self.rebuild_indexed_propositions()?;
        self.checkpoint_rebuild_wal()?;
        Ok(())
    }

    fn checkpoint_rebuild_wal(&self) -> Result<(), Error> {
        match self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
            Ok(()) => {}
            Err(rusqlite::Error::SqliteFailure(error, _))
                if matches!(
                    error.code,
                    ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
                ) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn export_projected_matches_protocol(&self) -> Result<bool, Error> {
        let (projected, canonical): (i64, i64) = self.conn.query_row(
            "SELECT
                (SELECT COUNT(*) FROM projected_export_object),
                (SELECT COUNT(*) FROM protocol_object WHERE ledger_id IS NOT NULL AND length(ledger_id)>0)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(projected == canonical)
    }

    fn projected_object_matches_protocol(&self) -> Result<bool, Error> {
        let (projected, canonical): (i64, i64) = self.conn.query_row(
            "SELECT
                (SELECT COUNT(*) FROM projected_object),
                (SELECT COUNT(*) FROM protocol_object)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(projected == canonical)
    }

    fn domain_projecteds_are_complete(&self) -> Result<bool, Error> {
        let (
            propositions,
            revisions,
            deliberations,
            effective,
            projected_revisions,
            projected_deliberations,
            consensus,
        ): (i64, i64, i64, i64, i64, i64, i64) = self.conn.query_row(
            "SELECT
                (SELECT COUNT(*) FROM protocol_object WHERE object_type='proposition'),
                (SELECT COUNT(*) FROM protocol_object WHERE object_type='revision'),
                (SELECT COUNT(*) FROM protocol_object WHERE object_type='deliberation'),
                (SELECT COUNT(*) FROM projected_effective),
                (SELECT COUNT(*) FROM projected_revision),
                (SELECT COUNT(*) FROM projected_deliberation),
                (SELECT COUNT(*) FROM projected_consensus)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )?;
        Ok(propositions > 0
            && propositions == effective
            && revisions == projected_revisions
            && deliberations == projected_deliberations
            && deliberations == consensus)
    }

    pub fn rebuild_indexed_propositions(&self) -> Result<(), Error> {
        self.drop_indexed_proposition_indexes()?;
        if self.has_unsettled_deliberations()? {
            self.rebuild_indexed_propositions_with_pending()?;
        } else {
            self.rebuild_indexed_propositions_without_pending()?;
        }
        self.create_indexed_proposition_indexes()?;
        self.refresh_indexed_proposition_meta_for_all_ledgers()?;
        Ok(())
    }

    fn has_unsettled_deliberations(&self) -> Result<bool, Error> {
        let unsettled: i64 = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM projected_deliberation WHERE settled=0 LIMIT 1)",
            [],
            |row| row.get(0),
        )?;
        Ok(unsettled != 0)
    }

    fn rebuild_indexed_propositions_without_pending(&self) -> Result<(), Error> {
        self.conn.execute_batch(
            "DELETE FROM indexed_proposition;
             INSERT INTO indexed_proposition(
                proposition_id,
                ledger_id,
                status,
                effective_revision_id,
                effective_deliberation_id,
                settlement_id,
                withdrawal_status,
                archival_status,
                effective_reason,
                latest_revision_id,
                latest_revision_status,
                pending_revision_id,
                pending_deliberation_id,
                pending_participant_count,
                has_pending_revision,
                summary_text,
                summary_revision_id,
                indexed_version
             )
             SELECT e.proposition_id,
                    p.ledger_id,
                    e.status,
                    e.revision_id,
                    e.deliberation_id,
                    e.settlement_id,
                    e.withdrawal_status,
                    e.archival_status,
                    e.reason,
                    e.revision_id,
                    e.status,
                    NULL,
                    NULL,
                    0,
                    0,
                    NULL,
                    e.revision_id,
                    'indexed-proposition-v0'
             FROM projected_effective e INDEXED BY sqlite_autoindex_projected_effective_1
             JOIN protocol_object p INDEXED BY sqlite_autoindex_protocol_object_1
               ON p.object_id=e.proposition_id
             WHERE p.ledger_id IS NOT NULL
               AND p.object_type='proposition';",
        )?;
        Ok(())
    }

    fn rebuild_indexed_propositions_with_pending(&self) -> Result<(), Error> {
        self.conn.execute_batch(
            "DELETE FROM indexed_proposition;
                 WITH revision_tips AS (
                    SELECT r.proposition_id,
                           r.revision_id
                    FROM projected_revision r
                    JOIN protocol_object p ON p.object_id=r.object_id
                    WHERE p.ledger_id IS NOT NULL
                      AND NOT EXISTS (
                        SELECT 1
                        FROM projected_revision child
                        WHERE child.parent_revision_id=r.revision_id
                      )
                 ),
                 pending_candidates AS (
                    SELECT tip.proposition_id,
                           tip.revision_id,
                           d.deliberation_id
                    FROM revision_tips tip
                    LEFT JOIN projected_deliberation d
                      ON d.revision_id=tip.revision_id
                     AND d.settled=0
                    WHERE d.deliberation_id IS NOT NULL
                       OR NOT EXISTS (
                         SELECT 1
                         FROM projected_deliberation any_deliberation
                         WHERE any_deliberation.revision_id=tip.revision_id
                       )
                 ),
                 pending AS (
                    SELECT proposition_id,
                           CASE WHEN COUNT(*) = 1 THEN MAX(revision_id) ELSE NULL END AS revision_id,
                           CASE WHEN COUNT(*) = 1 THEN MAX(deliberation_id) ELSE NULL END AS deliberation_id,
                           COUNT(*) AS tip_count
                    FROM pending_candidates
                    GROUP BY proposition_id
                 ),
                 pending_counts AS (
                SELECT pending.proposition_id,
                       COUNT(participant.actor_id) AS participant_count
                FROM pending
                LEFT JOIN projected_participant participant
                  ON participant.deliberation_id=pending.deliberation_id
                 AND participant.active=1
                GROUP BY pending.proposition_id
             ),
             indexed_rows AS (
                SELECT p.object_id AS proposition_id,
                       p.ledger_id AS ledger_id,
                       e.status AS status,
                       e.revision_id AS effective_revision_id,
                       e.deliberation_id AS effective_deliberation_id,
                       e.settlement_id AS settlement_id,
                           e.withdrawal_status AS withdrawal_status,
                           e.archival_status AS archival_status,
                           e.reason AS effective_reason,
                           CASE
                             WHEN pending.tip_count > 1 THEN NULL
                             ELSE COALESCE(pending.revision_id, e.revision_id)
                           END AS latest_revision_id,
                           CASE
                             WHEN pending.tip_count > 1 THEN 'ambiguous'
                             WHEN pending.revision_id IS NULL THEN e.status
                             ELSE 'pending'
                           END AS latest_revision_status,
                           pending.revision_id AS pending_revision_id,
                           pending.deliberation_id AS pending_deliberation_id,
                           COALESCE(pending_counts.participant_count, 0) AS pending_participant_count,
                           CASE
                             WHEN pending.tip_count IS NULL THEN 0
                             ELSE 1
                           END AS has_pending_revision,
                           NULL AS summary_text,
                           CASE
                             WHEN pending.tip_count > 1 THEN e.revision_id
                             ELSE COALESCE(pending.revision_id, e.revision_id)
                           END AS summary_revision_id
                    FROM protocol_object p
                JOIN projected_effective e ON e.proposition_id=p.object_id
                LEFT JOIN pending ON pending.proposition_id=p.object_id
                LEFT JOIN pending_counts ON pending_counts.proposition_id=p.object_id
                WHERE p.object_type='proposition'
                  AND p.ledger_id IS NOT NULL
             )
             INSERT INTO indexed_proposition(
                proposition_id,
                ledger_id,
                status,
                effective_revision_id,
                effective_deliberation_id,
                settlement_id,
                withdrawal_status,
                archival_status,
                effective_reason,
                latest_revision_id,
                latest_revision_status,
                pending_revision_id,
                pending_deliberation_id,
                pending_participant_count,
                has_pending_revision,
                summary_text,
                summary_revision_id,
                indexed_version
             )
             SELECT proposition_id,
                    ledger_id,
                    status,
                    effective_revision_id,
                    effective_deliberation_id,
                    settlement_id,
                    withdrawal_status,
                    archival_status,
                    effective_reason,
                    latest_revision_id,
                    latest_revision_status,
                    pending_revision_id,
                    pending_deliberation_id,
                    pending_participant_count,
                    has_pending_revision,
                    summary_text,
                    summary_revision_id,
                    'indexed-proposition-v0'
             FROM indexed_rows;",
        )?;
        Ok(())
    }

    fn drop_indexed_proposition_indexes(&self) -> Result<(), Error> {
        self.conn.execute_batch(
            "DROP INDEX IF EXISTS indexed_proposition_ledger_proposition;
             DROP INDEX IF EXISTS indexed_proposition_default_list;
             DROP INDEX IF EXISTS indexed_proposition_lifecycle_list;
             DROP INDEX IF EXISTS indexed_proposition_pending_list;
             DROP INDEX IF EXISTS indexed_proposition_effective_revision;
             DROP INDEX IF EXISTS indexed_proposition_latest_revision;",
        )?;
        Ok(())
    }

    fn create_indexed_proposition_indexes(&self) -> Result<(), Error> {
        self.conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS indexed_proposition_ledger_proposition ON indexed_proposition(ledger_id,proposition_id);
             CREATE INDEX IF NOT EXISTS indexed_proposition_default_list ON indexed_proposition(ledger_id,status,withdrawal_status,archival_status,proposition_id);
             CREATE INDEX IF NOT EXISTS indexed_proposition_lifecycle_list ON indexed_proposition(ledger_id,withdrawal_status,archival_status,proposition_id);
             CREATE INDEX IF NOT EXISTS indexed_proposition_pending_list ON indexed_proposition(ledger_id,has_pending_revision,proposition_id);
             CREATE INDEX IF NOT EXISTS indexed_proposition_effective_revision ON indexed_proposition(ledger_id,effective_revision_id,proposition_id);
             CREATE INDEX IF NOT EXISTS indexed_proposition_latest_revision ON indexed_proposition(ledger_id,latest_revision_id,proposition_id);",
        )?;
        Ok(())
    }

    fn ensure_export_projected(&self, ledger: &[u8; 16]) -> Result<(), Error> {
        let projected: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM projected_export_object WHERE ledger_id=?",
            [ledger.as_slice()],
            |row| row.get(0),
        )?;
        if projected != 0 {
            return Ok(());
        }
        let canonical: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM protocol_object WHERE ledger_id=?",
            [ledger.as_slice()],
            |row| row.get(0),
        )?;
        if canonical == 0 {
            return Ok(());
        }
        self.rebuild_export_projected()
    }

    fn rebuild_export_projected(&self) -> Result<(), Error> {
        self.conn
            .execute_batch("DELETE FROM projected_export_object")?;
        self.conn.execute(
            "INSERT OR IGNORE INTO projected_export_object(ledger_id,object_id,content_hash,object_type)
             SELECT ledger_id,object_id,content_hash,object_type
             FROM protocol_object
             WHERE ledger_id IS NOT NULL AND length(ledger_id)>0",
            [],
        )?;
        if self.export_projected_matches_protocol()?
            && !self.export_projected_has_missing_dependency()?
        {
            return Ok(());
        }
        loop {
            let inserted = self.conn.execute(
                "INSERT OR IGNORE INTO projected_export_object(ledger_id,object_id,content_hash,object_type)
                 SELECT e.ledger_id,p.object_id,p.content_hash,p.object_type
                 FROM projected_export_object e
                 JOIN object_dependency d ON d.object_id=e.object_id
                 JOIN protocol_object p ON p.object_id=d.dependency_id
                 LEFT JOIN projected_export_object existing
                   ON existing.ledger_id=e.ledger_id
                  AND existing.object_id=p.object_id
                 WHERE existing.object_id IS NULL",
                [],
            )?;
            if inserted == 0 {
                break;
            }
        }
        Ok(())
    }

    fn export_projected_has_missing_dependency(&self) -> Result<bool, Error> {
        let missing: i64 = self.conn.query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM projected_export_object e
                JOIN object_dependency d ON d.object_id=e.object_id
                JOIN protocol_object p ON p.object_id=d.dependency_id
                LEFT JOIN projected_export_object existing
                  ON existing.ledger_id=e.ledger_id
                 AND existing.object_id=p.object_id
                WHERE existing.object_id IS NULL
                LIMIT 1
            )",
            [],
            |row| row.get(0),
        )?;
        Ok(missing != 0)
    }

    fn rebuild_domain_projecteds(&self) -> Result<(), Error> {
        self.conn.execute_batch("DELETE FROM projected_actor; DELETE FROM projected_key; DELETE FROM projected_binding; DELETE FROM projected_authority; DELETE FROM projected_revision; DELETE FROM projected_deliberation; DELETE FROM projected_deliberation_object; DELETE FROM projected_standing_change; DELETE FROM projected_lifecycle; DELETE FROM projected_attestation; DELETE FROM projected_invitation; DELETE FROM projected_relationship_target; DELETE FROM projected_provenance; DELETE FROM projected_pending; DELETE FROM projected_reconciliation; DELETE FROM projected_roster;")?;
        let mut statement = self.conn.prepare("SELECT object_id,object_type,payload,content_hash FROM protocol_object ORDER BY content_hash")?;
        let mut rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        rows.sort_by_key(|(_, object_type, _, content_hash)| {
            (projected_rank(object_type), content_hash.clone())
        });
        for (object_id, object_type, payload, content_hash) in rows {
            let value: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| Error::ProjectedMismatch)?;
            let body = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::ProjectedMismatch)?;
            match object_type.as_str() {
                "actor" => {
                    let actor_id = parse_object_id_text(value.get("id"))?;
                    self.conn.execute("INSERT INTO projected_actor(actor_id,actor_type,object_id,payload) VALUES(?,?,?,?)", params![actor_id.uuid().as_bytes(), body.get("actor_type").and_then(serde_json::Value::as_str).ok_or(Error::ProjectedMismatch)?, object_id, payload])?;
                }
                "key" => {
                    let key_id = parse_object_id_text(value.get("id"))?;
                    let public_key = body
                        .get("public_key")
                        .and_then(serde_json::Value::as_object)
                        .ok_or(Error::ProjectedMismatch)?;
                    let bytes = decode_b64url(
                        public_key
                            .get("bytes")
                            .and_then(serde_json::Value::as_str)
                            .ok_or(Error::ProjectedMismatch)?,
                    )
                    .ok_or(Error::ProjectedMismatch)?;
                    self.conn.execute("INSERT INTO projected_key(key_id,purpose,public_key,object_id,payload) VALUES(?,?,?,?,?)", params![key_id.uuid().as_bytes(), body.get("purpose").and_then(serde_json::Value::as_str).ok_or(Error::ProjectedMismatch)?, bytes, object_id, payload])?;
                }
                "actor_key_binding" => {
                    let binding_id = parse_object_id_text(value.get("id"))?;
                    let actor_id = parse_object_id_text(body.get("actor_id"))?;
                    let key_id = parse_object_id_text(body.get("key_id"))?;
                    self.conn.execute("INSERT INTO projected_binding(binding_id,actor_id,key_id,permitted_purpose,object_id,payload) VALUES(?,?,?,?,?,?)", params![binding_id.uuid().as_bytes(), actor_id.uuid().as_bytes(), key_id.uuid().as_bytes(), body.get("permitted_purpose").and_then(serde_json::Value::as_str).ok_or(Error::ProjectedMismatch)?, object_id, payload])?;
                }
                "authorization_grant" => {
                    let grant_id = parse_object_id_text(value.get("id"))?;
                    let receiving = parse_object_id_text(body.get("receiving_actor_id"))?;
                    let scope = fact_canonical::encode(
                        &serde_json::to_vec(body.get("scope").ok_or(Error::ProjectedMismatch)?)
                            .map_err(|_| Error::ProjectedMismatch)?,
                    )?;
                    let capabilities = body
                        .get("capabilities")
                        .and_then(serde_json::Value::as_array)
                        .ok_or(Error::ProjectedMismatch)?;
                    for capability in capabilities {
                        self.conn.execute("INSERT INTO projected_authority(grant_id,capability,receiving_actor_id,scope,revoked,object_id,payload) VALUES(?,?,?,?,?,?,?)", params![grant_id.uuid().as_bytes(), capability.as_str().ok_or(Error::ProjectedMismatch)?, receiving.uuid().as_bytes(), scope.as_slice(), 0i64, object_id, payload])?;
                    }
                }
                "authorization_revocation" => {
                    let revoked = parse_object_id_text(body.get("revoked_grant_id"))?;
                    self.conn.execute(
                        "UPDATE projected_authority SET revoked=1 WHERE grant_id=?",
                        [revoked.uuid().as_bytes()],
                    )?;
                }
                "revision" => {
                    let revision_id = parse_object_id_text(body.get("revision_id"))?;
                    let proposition_id = parse_object_id_text(body.get("proposition_id"))?;
                    let parent = body.get("parent_revision_id").and_then(|value| {
                        if value.is_null() {
                            None
                        } else {
                            parse_object_id_text(Some(value)).ok()
                        }
                    });
                    let content_hash = body
                        .get("content")
                        .and_then(|content| content.get("hash"))
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::ProjectedMismatch)?
                        .parse::<Hash>()
                        .map_err(|_| Error::ProjectedMismatch)?;
                    self.conn.execute("INSERT INTO projected_revision(revision_id,proposition_id,parent_revision_id,content_hash,object_id,payload) VALUES(?,?,?,?,?,?)", params![revision_id.uuid().as_bytes(), proposition_id.uuid().as_bytes(), parent.map(|id| id.uuid().as_bytes().to_vec()), content_hash.as_bytes(), object_id, payload])?;
                    if let Some(manifest) = body
                        .get("reconciliation_manifest")
                        .filter(|value| !value.is_null())
                        .and_then(serde_json::Value::as_object)
                    {
                        let affected =
                            parse_object_id_text(manifest.get("affected_proposition_id"))?;
                        let common =
                            parse_object_id_text(manifest.get("common_ancestor_revision_id"))?;
                        let conflict_hash = manifest
                            .get("conflict_set_hash")
                            .and_then(serde_json::Value::as_str)
                            .ok_or(Error::ProjectedMismatch)?
                            .parse::<Hash>()
                            .map_err(|_| Error::ProjectedMismatch)?;
                        let selected = manifest
                            .get("selected_revision_id")
                            .filter(|value| !value.is_null())
                            .map(|value| parse_object_id_text(Some(value)))
                            .transpose()?;
                        let result = manifest
                            .get("result_revision_id")
                            .filter(|value| !value.is_null())
                            .map(|value| parse_object_id_text(Some(value)))
                            .transpose()?;
                        self.conn.execute("INSERT INTO projected_reconciliation(revision_id,affected_proposition_id,common_ancestor_revision_id,conflict_set_hash,resolution_mode,selected_revision_id,result_revision_id,payload) VALUES(?,?,?,?,?,?,?,?)", params![revision_id.uuid().as_bytes(), affected.uuid().as_bytes(), common.uuid().as_bytes(), conflict_hash.as_bytes(), manifest.get("resolution_mode").and_then(serde_json::Value::as_str).ok_or(Error::ProjectedMismatch)?, selected.map(|id| id.uuid().as_bytes().to_vec()), result.map(|id| id.uuid().as_bytes().to_vec()), payload])?;
                    }
                }
                "deliberation" => {
                    let deliberation_id = parse_object_id_text(body.get("deliberation_id"))?;
                    let proposition_id = parse_object_id_text(body.get("proposition_id"))?;
                    let revision_id = parse_object_id_text(body.get("revision_id"))?;
                    self.conn.execute("INSERT INTO projected_deliberation(deliberation_id,proposition_id,revision_id,settled,object_id,payload) VALUES(?,?,?,?,?,?)", params![deliberation_id.uuid().as_bytes(), proposition_id.uuid().as_bytes(), revision_id.uuid().as_bytes(), 0i64, object_id, payload])?;
                    if let Some(roster) = body
                        .get("roster_governance")
                        .filter(|value| !value.is_null())
                        .and_then(serde_json::Value::as_object)
                    {
                        let source_ids = fact_canonical::encode(
                            &serde_json::to_vec(
                                roster
                                    .get("source_deliberation_ids")
                                    .ok_or(Error::ProjectedMismatch)?,
                            )
                            .map_err(|_| Error::ProjectedMismatch)?,
                        )?;
                        let selected_ids = fact_canonical::encode(
                            &serde_json::to_vec(
                                roster
                                    .get("selected_participants")
                                    .ok_or(Error::ProjectedMismatch)?,
                            )
                            .map_err(|_| Error::ProjectedMismatch)?,
                        )?;
                        self.conn.execute("INSERT INTO projected_roster(deliberation_id,selection_mode,source_deliberation_ids,selected_participant_ids,payload) VALUES(?,?,?,?,?)", params![deliberation_id.uuid().as_bytes(), roster.get("selection_mode").and_then(serde_json::Value::as_str).ok_or(Error::ProjectedMismatch)?, String::from_utf8(source_ids).map_err(|_| Error::ProjectedMismatch)?, String::from_utf8(selected_ids).map_err(|_| Error::ProjectedMismatch)?, payload])?;
                    }
                }
                "standing_participant_change" => {
                    self.project_standing_change(&object_id, &value, body, &payload)?;
                }
                "decision" | "deliberation_comment" | "deliberation_participant_change" => {
                    self.project_deliberation_object(
                        &object_id,
                        &object_type,
                        &value,
                        body,
                        &payload,
                    )?;
                }
                "settlement" => {
                    self.project_deliberation_object(
                        &object_id,
                        &object_type,
                        &value,
                        body,
                        &payload,
                    )?;
                    if let Ok(deliberation_id) = parse_object_id_text(body.get("deliberation_id")) {
                        self.conn.execute(
                            "UPDATE projected_deliberation SET settled=1 WHERE deliberation_id=?",
                            [deliberation_id.uuid().as_bytes()],
                        )?;
                    }
                }
                "identity_attestation" => {
                    self.project_attestation(&object_id, &value, body, &payload)?;
                }
                "participant_invitation" => {
                    self.project_invitation(&object_id, &value, body, &payload)?;
                }
                "protocol_relationship" | "application_relationship" => {
                    self.project_relationship_targets(&object_id, body)?;
                }
                "proposition_provenance" => {
                    self.project_provenance(&object_id, &value, body, &payload)?;
                }
                "key_lifecycle"
                | "actor_lifecycle"
                | "recovery_policy"
                | "invitation_lifecycle"
                | "proposition_lifecycle"
                | "delegation_revocation" => {
                    let target = [
                        "affected_actor_id",
                        "actor_id",
                        "invitation_id",
                        "proposition_id",
                        "revoked_grant_id",
                        "revoked_delegation_id",
                    ]
                    .iter()
                    .find_map(|field| body.get(*field).and_then(serde_json::Value::as_str));
                    let target_id = target
                        .and_then(|value| value.parse::<fact_core::ObjectId>().ok())
                        .map(|id| id.uuid().as_bytes().to_vec());
                    self.conn.execute("INSERT INTO projected_lifecycle(object_id,object_type,target_id,dimension,operation,effective_at,payload) VALUES(?,?,?,?,?,?,?)", params![object_id, object_type, target_id, body.get("dimension").and_then(serde_json::Value::as_str), body.get("operation").and_then(serde_json::Value::as_str).unwrap_or("update"), body.get("effective_at").and_then(serde_json::Value::as_str), payload])?;
                }
                _ => {}
            }
            let _ = content_hash;
        }
        Ok(())
    }

    fn apply_projected_mode(
        &self,
        objects: &[ValidatedObject],
        projected_mode: ProjectedMode,
    ) -> Result<(), Error> {
        match projected_mode {
            ProjectedMode::Defer => Ok(()),
            ProjectedMode::FullRebuild => self.rebuild_projecteds(),
            ProjectedMode::Incremental => {
                if self.project_incremental_objects(objects)? {
                    Ok(())
                } else {
                    self.rebuild_projecteds()
                }
            }
        }
    }

    fn project_incremental_objects(&self, objects: &[ValidatedObject]) -> Result<bool, Error> {
        let mut objects = objects.iter().collect::<Vec<_>>();
        objects.sort_by_key(|object| (projected_rank(&object.object_type), object.hash.hex()));
        for object in &objects {
            if !self.project_incremental_object(object)? {
                return Ok(false);
            }
        }
        if objects.len() > 128 {
            self.rebuild_export_projected()?;
        } else {
            for object in &objects {
                self.project_export_membership_for_object(object)?;
            }
        }
        let affected = self.affected_indexed_propositions_for_objects(&objects)?;
        self.refresh_indexed_propositions(&affected)?;
        Ok(true)
    }

    fn affected_indexed_propositions_for_objects(
        &self,
        objects: &[&ValidatedObject],
    ) -> Result<Vec<Vec<u8>>, Error> {
        let mut affected = std::collections::BTreeSet::<Vec<u8>>::new();
        for object in objects {
            self.collect_affected_indexed_proposition(&mut affected, &object.id)?;
        }
        Ok(affected.into_iter().collect())
    }

    fn collect_affected_indexed_proposition(
        &self,
        affected: &mut std::collections::BTreeSet<Vec<u8>>,
        object_id: &[u8],
    ) -> Result<(), Error> {
        let direct: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT object_id
                 FROM protocol_object
                 WHERE object_id=? AND object_type='proposition'",
                [object_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(proposition_id) = direct {
            affected.insert(proposition_id);
        }

        for sql in [
            "SELECT proposition_id FROM projected_revision WHERE object_id=?",
            "SELECT proposition_id FROM projected_deliberation WHERE object_id=?",
            "SELECT proposition_id FROM projected_standing_change WHERE object_id=?",
            "SELECT proposition_id FROM projected_provenance WHERE object_id=?",
            "SELECT affected_proposition_id FROM projected_reconciliation r JOIN projected_revision pr ON pr.revision_id=r.revision_id WHERE pr.object_id=?",
            "SELECT r.affected_proposition_id
             FROM projected_deliberation_object o
             JOIN projected_deliberation d ON d.deliberation_id=o.deliberation_id
             JOIN projected_reconciliation r ON r.revision_id=d.revision_id
             WHERE o.object_id=?",
            "SELECT d.proposition_id
             FROM projected_deliberation_object o
             JOIN projected_deliberation d ON d.deliberation_id=o.deliberation_id
             WHERE o.object_id=?",
            "SELECT COALESCE(i.proposition_id, d.proposition_id)
             FROM projected_invitation i
             LEFT JOIN projected_deliberation d ON d.deliberation_id=i.deliberation_id
             WHERE i.object_id=?",
            "SELECT l.target_id
             FROM projected_lifecycle l
             JOIN protocol_object p ON p.object_id=l.target_id
             WHERE l.object_id=? AND p.object_type='proposition'",
            "SELECT r.proposition_id
             FROM projected_lifecycle l
             JOIN projected_revision r ON r.revision_id=l.target_id
             WHERE l.object_id=?",
        ] {
            let mut statement = self.conn.prepare(sql)?;
            let rows = statement.query_map([object_id], |row| row.get::<_, Option<Vec<u8>>>(0))?;
            for row in rows {
                if let Some(proposition_id) = row? {
                    affected.insert(proposition_id);
                }
            }
        }
        Ok(())
    }

    fn refresh_indexed_propositions(&self, proposition_ids: &[Vec<u8>]) -> Result<(), Error> {
        if proposition_ids.is_empty() {
            return Ok(());
        }
        let mut delete_statement = self
            .conn
            .prepare("DELETE FROM indexed_proposition WHERE proposition_id=?")?;
        for proposition_id in proposition_ids {
            delete_statement.execute([proposition_id.as_slice()])?;
        }
        drop(delete_statement);

        let sql = format!(
                "WITH affected(proposition_id) AS (VALUES {values}),
                 revision_tips AS (
                    SELECT r.proposition_id,
                           r.revision_id
                    FROM projected_revision r
                    JOIN affected a ON a.proposition_id=r.proposition_id
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM projected_revision child
                        WHERE child.parent_revision_id=r.revision_id
                      )
                 ),
                 pending_candidates AS (
                    SELECT tip.proposition_id,
                           tip.revision_id,
                           d.deliberation_id
                    FROM revision_tips tip
                    LEFT JOIN projected_deliberation d
                      ON d.revision_id=tip.revision_id
                     AND d.settled=0
                    WHERE d.deliberation_id IS NOT NULL
                       OR NOT EXISTS (
                         SELECT 1
                         FROM projected_deliberation any_deliberation
                         WHERE any_deliberation.revision_id=tip.revision_id
                       )
                 ),
                 pending AS (
                    SELECT proposition_id,
                           CASE WHEN COUNT(*) = 1 THEN MAX(revision_id) ELSE NULL END AS revision_id,
                           CASE WHEN COUNT(*) = 1 THEN MAX(deliberation_id) ELSE NULL END AS deliberation_id,
                           COUNT(*) AS tip_count
                    FROM pending_candidates
                    GROUP BY proposition_id
                 ),
             pending_counts AS (
                SELECT pending.proposition_id,
                       COUNT(participant.actor_id) AS participant_count
                FROM pending
                LEFT JOIN projected_participant participant
                  ON participant.deliberation_id=pending.deliberation_id
                 AND participant.active=1
                GROUP BY pending.proposition_id
             )
             INSERT INTO indexed_proposition(
                proposition_id,
                ledger_id,
                status,
                effective_revision_id,
                effective_deliberation_id,
                settlement_id,
                withdrawal_status,
                archival_status,
                effective_reason,
                latest_revision_id,
                latest_revision_status,
                pending_revision_id,
                pending_deliberation_id,
                pending_participant_count,
                has_pending_revision,
                summary_text,
                summary_revision_id,
                indexed_version
             )
             SELECT p.object_id,
                    p.ledger_id,
                    e.status,
                    e.revision_id,
                    e.deliberation_id,
                    e.settlement_id,
                        e.withdrawal_status,
                        e.archival_status,
                        e.reason,
                        CASE
                          WHEN pending.tip_count > 1 THEN NULL
                          ELSE COALESCE(pending.revision_id, e.revision_id)
                        END,
                        CASE
                          WHEN pending.tip_count > 1 THEN 'ambiguous'
                          WHEN pending.revision_id IS NULL THEN e.status
                          ELSE 'pending'
                        END,
                        pending.revision_id,
                        pending.deliberation_id,
                        COALESCE(pending_counts.participant_count, 0),
                        CASE WHEN pending.tip_count IS NULL THEN 0 ELSE 1 END,
                        NULL,
                        CASE
                          WHEN pending.tip_count > 1 THEN e.revision_id
                          ELSE COALESCE(pending.revision_id, e.revision_id)
                        END,
                        'indexed-proposition-v0'
                 FROM affected a
             JOIN protocol_object p ON p.object_id=a.proposition_id
             JOIN projected_effective e ON e.proposition_id=p.object_id
             LEFT JOIN pending ON pending.proposition_id=p.object_id
             LEFT JOIN pending_counts ON pending_counts.proposition_id=p.object_id
             WHERE p.object_type='proposition'
               AND p.ledger_id IS NOT NULL",
            values = std::iter::repeat_n("(?)", proposition_ids.len())
                .collect::<Vec<_>>()
                .join(",")
        );
        let values = proposition_ids
            .iter()
            .map(|id| Value::Blob(id.clone()))
            .collect::<Vec<_>>();
        self.conn.execute(&sql, params_from_iter(values.iter()))?;
        let ledger_sql = format!(
            "WITH affected(proposition_id) AS (VALUES {values})
             SELECT DISTINCT p.ledger_id
             FROM affected a
             JOIN protocol_object p ON p.object_id=a.proposition_id
             WHERE p.object_type='proposition'
               AND p.ledger_id IS NOT NULL",
            values = std::iter::repeat_n("(?)", proposition_ids.len())
                .collect::<Vec<_>>()
                .join(",")
        );
        let ledgers = self
            .conn
            .prepare(&ledger_sql)?
            .query_map(params_from_iter(values.iter()), |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        self.refresh_indexed_proposition_meta_for_ledgers(&ledgers)?;
        Ok(())
    }

    fn project_export_membership_for_object(&self, object: &ValidatedObject) -> Result<(), Error> {
        if object.ledger.is_empty() {
            return Ok(());
        }
        self.conn.execute(
            "WITH RECURSIVE closure(object_id) AS (
                SELECT ?1
                UNION
                SELECT d.dependency_id
                FROM object_dependency d
                JOIN closure c ON d.object_id=c.object_id
             )
             INSERT OR IGNORE INTO projected_export_object(ledger_id,object_id,content_hash,object_type)
             SELECT ?2,p.object_id,p.content_hash,p.object_type
             FROM protocol_object p
             JOIN closure c ON p.object_id=c.object_id",
            params![object.id.as_slice(), object.ledger.as_slice()],
        )?;
        Ok(())
    }

    fn project_incremental_object(&self, object: &ValidatedObject) -> Result<bool, Error> {
        if !matches!(
            object.object_type.as_str(),
            "actor"
                | "key"
                | "actor_key_binding"
                | "authorization_grant"
                | "authorization_revocation"
                | "delegation"
                | "namespace_assertion"
                | "key_lifecycle"
                | "actor_lifecycle"
                | "recovery_policy"
                | "identity_attestation"
                | "participant_invitation"
                | "proposition"
                | "revision"
                | "deliberation"
                | "protocol_relationship"
                | "application_relationship"
                | "proposition_provenance"
                | "decision"
                | "deliberation_comment"
                | "deliberation_participant_change"
                | "settlement"
                | "standing_participant_change"
                | "invitation_lifecycle"
                | "proposition_lifecycle"
                | "delegation_revocation"
        ) {
            return Ok(false);
        }
        self.conn.execute(
            "INSERT OR REPLACE INTO projected_object(object_id,ledger_id,object_type,content_hash,payload) VALUES(?,?,?,?,?)",
            params![
                object.id.as_slice(),
                if object.ledger.is_empty() {
                    None
                } else {
                    Some(object.ledger.as_slice())
                },
                object.object_type.as_str(),
                object.hash.as_bytes(),
                object.canonical,
            ],
        )?;
        let value: serde_json::Value =
            serde_json::from_slice(&object.canonical).map_err(|_| Error::ProjectedMismatch)?;
        let body = value
            .get("body")
            .and_then(serde_json::Value::as_object)
            .ok_or(Error::ProjectedMismatch)?;
        match object.object_type.as_str() {
            "actor" => {
                let actor_id = parse_object_id_text(value.get("id"))?;
                self.conn.execute("INSERT OR REPLACE INTO projected_actor(actor_id,actor_type,object_id,payload) VALUES(?,?,?,?)", params![actor_id.uuid().as_bytes(), body.get("actor_type").and_then(serde_json::Value::as_str).ok_or(Error::ProjectedMismatch)?, object.id.as_slice(), object.canonical.as_slice()])?;
            }
            "key" => {
                let key_id = parse_object_id_text(value.get("id"))?;
                let public_key = body
                    .get("public_key")
                    .and_then(serde_json::Value::as_object)
                    .ok_or(Error::ProjectedMismatch)?;
                let bytes = decode_b64url(
                    public_key
                        .get("bytes")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::ProjectedMismatch)?,
                )
                .ok_or(Error::ProjectedMismatch)?;
                self.conn.execute("INSERT OR REPLACE INTO projected_key(key_id,purpose,public_key,object_id,payload) VALUES(?,?,?,?,?)", params![key_id.uuid().as_bytes(), body.get("purpose").and_then(serde_json::Value::as_str).ok_or(Error::ProjectedMismatch)?, bytes, object.id.as_slice(), object.canonical.as_slice()])?;
            }
            "actor_key_binding" => {
                let binding_id = parse_object_id_text(value.get("id"))?;
                let actor_id = parse_object_id_text(body.get("actor_id"))?;
                let key_id = parse_object_id_text(body.get("key_id"))?;
                self.conn.execute("INSERT OR REPLACE INTO projected_binding(binding_id,actor_id,key_id,permitted_purpose,object_id,payload) VALUES(?,?,?,?,?,?)", params![binding_id.uuid().as_bytes(), actor_id.uuid().as_bytes(), key_id.uuid().as_bytes(), body.get("permitted_purpose").and_then(serde_json::Value::as_str).ok_or(Error::ProjectedMismatch)?, object.id.as_slice(), object.canonical.as_slice()])?;
            }
            "authorization_grant" => {
                let grant_id = parse_object_id_text(value.get("id"))?;
                let receiving = parse_object_id_text(body.get("receiving_actor_id"))?;
                let scope = fact_canonical::encode(
                    &serde_json::to_vec(body.get("scope").ok_or(Error::ProjectedMismatch)?)
                        .map_err(|_| Error::ProjectedMismatch)?,
                )?;
                let capabilities = body
                    .get("capabilities")
                    .and_then(serde_json::Value::as_array)
                    .ok_or(Error::ProjectedMismatch)?;
                for capability in capabilities {
                    self.conn.execute("INSERT OR REPLACE INTO projected_authority(grant_id,capability,receiving_actor_id,scope,revoked,object_id,payload) VALUES(?,?,?,?,?,?,?)", params![grant_id.uuid().as_bytes(), capability.as_str().ok_or(Error::ProjectedMismatch)?, receiving.uuid().as_bytes(), scope.as_slice(), 0i64, object.id.as_slice(), object.canonical.as_slice()])?;
                }
            }
            "authorization_revocation" => {
                let revoked = parse_object_id_text(body.get("revoked_grant_id"))?;
                self.conn.execute(
                    "UPDATE projected_authority SET revoked=1 WHERE grant_id=?",
                    [revoked.uuid().as_bytes()],
                )?;
            }
            "key_lifecycle"
            | "actor_lifecycle"
            | "recovery_policy"
            | "invitation_lifecycle"
            | "proposition_lifecycle"
            | "delegation_revocation" => {
                let target = [
                    "affected_actor_id",
                    "actor_id",
                    "invitation_id",
                    "proposition_id",
                    "revoked_grant_id",
                    "revoked_delegation_id",
                ]
                .iter()
                .find_map(|field| body.get(*field).and_then(serde_json::Value::as_str));
                let target_id = target
                    .and_then(|value| value.parse::<fact_core::ObjectId>().ok())
                    .map(|id| id.uuid().as_bytes().to_vec());
                self.conn.execute("INSERT OR REPLACE INTO projected_lifecycle(object_id,object_type,target_id,dimension,operation,effective_at,payload) VALUES(?,?,?,?,?,?,?)", params![object.id.as_slice(), object.object_type.as_str(), target_id, body.get("dimension").and_then(serde_json::Value::as_str), body.get("operation").and_then(serde_json::Value::as_str).unwrap_or("update"), body.get("effective_at").and_then(serde_json::Value::as_str), object.canonical.as_slice()])?;
                if object.object_type == "proposition_lifecycle" {
                    let proposition = parse_object_id_text(body.get("proposition_id"))?;
                    let dimension = body
                        .get("dimension")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::ProjectedMismatch)?;
                    self.update_proposition_lifecycle_effective_state(proposition, dimension)?;
                }
            }
            "namespace_assertion" | "delegation" | "proposition" => {}
            "proposition_provenance" => {
                self.project_provenance(&object.id, &value, body, &object.canonical)?;
            }
            "identity_attestation" => {
                self.project_attestation(&object.id, &value, body, &object.canonical)?;
            }
            "participant_invitation" => {
                self.project_invitation(&object.id, &value, body, &object.canonical)?;
            }
            "revision" => {
                self.project_revision(&object.id, body, &object.canonical)?;
            }
            "deliberation" => {
                let deliberation =
                    self.project_deliberation(&object.id, body, &object.canonical)?;
                self.refresh_deliberation_consensus(deliberation)?;
            }
            "protocol_relationship" | "application_relationship" => {
                self.project_relationship_targets(&object.id, body)?;
            }
            "decision" => {
                self.project_deliberation_object(
                    &object.id,
                    &object.object_type,
                    &value,
                    body,
                    &object.canonical,
                )?;
                let deliberation = parse_object_id_text(body.get("deliberation_id"))?;
                self.refresh_deliberation_consensus(deliberation)?;
            }
            "deliberation_comment" | "deliberation_participant_change" => {
                self.project_deliberation_object(
                    &object.id,
                    object.object_type.as_str(),
                    &value,
                    body,
                    &object.canonical,
                )?;
                if object.object_type == "deliberation_participant_change" {
                    let deliberation = parse_object_id_text(body.get("deliberation_id"))?;
                    self.refresh_deliberation_consensus(deliberation)?;
                }
            }
            "settlement" => {
                self.project_deliberation_object(
                    &object.id,
                    object.object_type.as_str(),
                    &value,
                    body,
                    &object.canonical,
                )?;
                let deliberation = parse_object_id_text(body.get("deliberation_id"))?;
                let revision = parse_object_id_text(body.get("revision_id"))?;
                self.project_settlement_decision_dependencies(&object.id, deliberation)?;
                self.conn.execute(
                    "UPDATE projected_deliberation SET settled=1 WHERE deliberation_id=?",
                    [deliberation.uuid().as_bytes()],
                )?;
                self.refresh_deliberation_consensus(deliberation)?;
                self.refresh_effective_for_deliberation(deliberation)?;
                let affected_reconciliations = self
                    .conn
                    .prepare(
                        "SELECT affected_proposition_id
                         FROM projected_reconciliation
                         WHERE revision_id=?",
                    )?
                    .query_map([revision.uuid().as_bytes()], |row| {
                        projected_id(row.get(0)?, "invalid affected proposition ID")
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                for affected in affected_reconciliations {
                    self.refresh_effective_for_proposition(affected)?;
                }
            }
            "standing_participant_change" => {
                self.project_standing_change(&object.id, &value, body, &object.canonical)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn project_settlement_decision_dependencies(
        &self,
        settlement_id: &[u8],
        deliberation: fact_core::ObjectId,
    ) -> Result<(), Error> {
        let mut statement = self.conn.prepare(
            "SELECT p.object_id,p.ledger_id,p.payload
             FROM object_dependency d
             JOIN protocol_object p ON p.object_id=d.dependency_id
             WHERE d.object_id=? AND d.role='decision' AND p.object_type='decision'",
        )?;
        let rows = statement.query_map([settlement_id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in rows {
            let (object_id, ledger_id, payload) = row?;
            let value: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| Error::ProjectedMismatch)?;
            let body = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::ProjectedMismatch)?;
            if parse_object_id_text(body.get("deliberation_id"))? != deliberation {
                return Err(Error::ProjectedMismatch);
            }
            self.conn.execute(
                "INSERT OR REPLACE INTO projected_deliberation_object(object_id,ledger_id,deliberation_id,object_type,created_at,payload) VALUES(?,?,?,?,?,?)",
                params![
                    object_id,
                    ledger_id,
                    deliberation.uuid().as_bytes(),
                    "decision",
                    value
                        .get("created_at")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::ProjectedMismatch)?,
                    payload
                ],
            )?;
        }
        Ok(())
    }

    fn project_revision(
        &self,
        object_id: &[u8],
        body: &serde_json::Map<String, serde_json::Value>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let revision_id = parse_object_id_text(body.get("revision_id"))?;
        let proposition_id = parse_object_id_text(body.get("proposition_id"))?;
        let parent = body.get("parent_revision_id").and_then(|value| {
            if value.is_null() {
                None
            } else {
                parse_object_id_text(Some(value)).ok()
            }
        });
        let content_hash = body
            .get("content")
            .and_then(|content| content.get("hash"))
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::ProjectedMismatch)?
            .parse::<Hash>()
            .map_err(|_| Error::ProjectedMismatch)?;
        self.conn.execute("INSERT OR REPLACE INTO projected_revision(revision_id,proposition_id,parent_revision_id,content_hash,object_id,payload) VALUES(?,?,?,?,?,?)", params![revision_id.uuid().as_bytes(), proposition_id.uuid().as_bytes(), parent.map(|id| id.uuid().as_bytes().to_vec()), content_hash.as_bytes(), object_id, payload])?;
        self.conn.execute(
            "INSERT OR IGNORE INTO projected_effective(proposition_id,status,reason,projected_version) VALUES(?,'pending','no-valid-settlement','effective-v0')",
            [proposition_id.uuid().as_bytes()],
        )?;
        if let Some(manifest) = body
            .get("reconciliation_manifest")
            .filter(|value| !value.is_null())
            .and_then(serde_json::Value::as_object)
        {
            let affected = parse_object_id_text(manifest.get("affected_proposition_id"))?;
            let common = parse_object_id_text(manifest.get("common_ancestor_revision_id"))?;
            let conflict_hash = manifest
                .get("conflict_set_hash")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::ProjectedMismatch)?
                .parse::<Hash>()
                .map_err(|_| Error::ProjectedMismatch)?;
            let selected = manifest
                .get("selected_revision_id")
                .filter(|value| !value.is_null())
                .map(|value| parse_object_id_text(Some(value)))
                .transpose()?;
            let result = manifest
                .get("result_revision_id")
                .filter(|value| !value.is_null())
                .map(|value| parse_object_id_text(Some(value)))
                .transpose()?;
            self.conn.execute("INSERT OR REPLACE INTO projected_reconciliation(revision_id,affected_proposition_id,common_ancestor_revision_id,conflict_set_hash,resolution_mode,selected_revision_id,result_revision_id,payload) VALUES(?,?,?,?,?,?,?,?)", params![revision_id.uuid().as_bytes(), affected.uuid().as_bytes(), common.uuid().as_bytes(), conflict_hash.as_bytes(), manifest.get("resolution_mode").and_then(serde_json::Value::as_str).ok_or(Error::ProjectedMismatch)?, selected.map(|id| id.uuid().as_bytes().to_vec()), result.map(|id| id.uuid().as_bytes().to_vec()), payload])?;
        }
        Ok(())
    }

    fn project_deliberation(
        &self,
        object_id: &[u8],
        body: &serde_json::Map<String, serde_json::Value>,
        payload: &[u8],
    ) -> Result<fact_core::ObjectId, Error> {
        let deliberation_id = parse_object_id_text(body.get("deliberation_id"))?;
        let proposition_id = parse_object_id_text(body.get("proposition_id"))?;
        let revision_id = parse_object_id_text(body.get("revision_id"))?;
        self.conn.execute("INSERT OR REPLACE INTO projected_deliberation(deliberation_id,proposition_id,revision_id,settled,object_id,payload) VALUES(?,?,?,?,?,?)", params![deliberation_id.uuid().as_bytes(), proposition_id.uuid().as_bytes(), revision_id.uuid().as_bytes(), 0i64, object_id, payload])?;
        if let Some(roster) = body
            .get("roster_governance")
            .filter(|value| !value.is_null())
            .and_then(serde_json::Value::as_object)
        {
            let source_ids = fact_canonical::encode(
                &serde_json::to_vec(
                    roster
                        .get("source_deliberation_ids")
                        .ok_or(Error::ProjectedMismatch)?,
                )
                .map_err(|_| Error::ProjectedMismatch)?,
            )?;
            let selected_ids = fact_canonical::encode(
                &serde_json::to_vec(
                    roster
                        .get("selected_participants")
                        .ok_or(Error::ProjectedMismatch)?,
                )
                .map_err(|_| Error::ProjectedMismatch)?,
            )?;
            self.conn.execute("INSERT OR REPLACE INTO projected_roster(deliberation_id,selection_mode,source_deliberation_ids,selected_participant_ids,payload) VALUES(?,?,?,?,?)", params![deliberation_id.uuid().as_bytes(), roster.get("selection_mode").and_then(serde_json::Value::as_str).ok_or(Error::ProjectedMismatch)?, String::from_utf8(source_ids).map_err(|_| Error::ProjectedMismatch)?, String::from_utf8(selected_ids).map_err(|_| Error::ProjectedMismatch)?, payload])?;
        }
        Ok(deliberation_id)
    }

    fn project_attestation(
        &self,
        object_id: &[u8],
        value: &serde_json::Value,
        body: &serde_json::Map<String, serde_json::Value>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let ledger = parse_object_id_text(value.get("ledger_id"))?;
        let subject = parse_object_id_text(body.get("subject_id"))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO projected_attestation(object_id,ledger_id,subject_type,subject_id,claim_type,created_at,payload) VALUES(?,?,?,?,?,?,?)",
            params![
                object_id,
                ledger.uuid().as_bytes(),
                body.get("subject_type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::ProjectedMismatch)?,
                subject.uuid().as_bytes(),
                body.get("claim_type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::ProjectedMismatch)?,
                value
                    .get("created_at")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::ProjectedMismatch)?,
                payload
            ],
        )?;
        Ok(())
    }

    fn project_invitation(
        &self,
        object_id: &[u8],
        value: &serde_json::Value,
        body: &serde_json::Map<String, serde_json::Value>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let ledger = parse_object_id_text(value.get("ledger_id"))?;
        let proposition = body
            .get("proposition_id")
            .and_then(|value| (!value.is_null()).then_some(value))
            .map(|value| parse_object_id_text(Some(value)))
            .transpose()?;
        let deliberation = body
            .get("deliberation_id")
            .and_then(|value| (!value.is_null()).then_some(value))
            .map(|value| parse_object_id_text(Some(value)))
            .transpose()?;
        let invited = parse_object_id_text(body.get("invited_actor_id"))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO projected_invitation(object_id,ledger_id,proposition_id,deliberation_id,invited_actor_id,created_at,payload) VALUES(?,?,?,?,?,?,?)",
            params![
                object_id,
                ledger.uuid().as_bytes(),
                proposition.map(|id| id.uuid().as_bytes().to_vec()),
                deliberation.map(|id| id.uuid().as_bytes().to_vec()),
                invited.uuid().as_bytes(),
                value
                    .get("created_at")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::ProjectedMismatch)?,
                payload
            ],
        )?;
        Ok(())
    }

    fn project_provenance(
        &self,
        object_id: &[u8],
        value: &serde_json::Value,
        body: &serde_json::Map<String, serde_json::Value>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let ledger = parse_object_id_text(value.get("ledger_id"))?;
        let proposition = parse_object_id_text(body.get("proposition_id"))?;
        let source_ledger = parse_object_id_text(body.get("source_ledger_id"))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO projected_provenance(object_id,ledger_id,proposition_id,source_ledger_id,copy_mode,payload) VALUES(?,?,?,?,?,?)",
            params![
                object_id,
                ledger.uuid().as_bytes(),
                proposition.uuid().as_bytes(),
                source_ledger.uuid().as_bytes(),
                body.get("copy_mode")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::ProjectedMismatch)?,
                payload
            ],
        )?;
        Ok(())
    }

    fn project_standing_change(
        &self,
        object_id: &[u8],
        value: &serde_json::Value,
        body: &serde_json::Map<String, serde_json::Value>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let ledger = parse_object_id_text(value.get("ledger_id"))?;
        let proposition = parse_object_id_text(body.get("proposition_id"))?;
        let participant = parse_object_id_text(body.get("participant_actor_id"))?;
        let changed_by = parse_object_id_text(body.get("changed_by_actor_id"))?;
        let predecessor = body
            .get("predecessor_change_id")
            .and_then(|value| (!value.is_null()).then_some(value))
            .map(|value| parse_object_id_text(Some(value)))
            .transpose()?;
        self.conn.execute("INSERT OR REPLACE INTO projected_standing_change(object_id,ledger_id,proposition_id,participant_actor_id,operation,predecessor_change_id,changed_by_actor_id,payload) VALUES(?,?,?,?,?,?,?,?)", params![object_id, ledger.uuid().as_bytes(), proposition.uuid().as_bytes(), participant.uuid().as_bytes(), body.get("operation").and_then(serde_json::Value::as_str).ok_or(Error::ProjectedMismatch)?, predecessor.map(|id| id.uuid().as_bytes().to_vec()), changed_by.uuid().as_bytes(), payload])?;
        Ok(())
    }

    fn project_relationship_targets(
        &self,
        object_id: &[u8],
        body: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), Error> {
        self.conn.execute(
            "DELETE FROM projected_relationship_target WHERE object_id=?",
            [object_id],
        )?;
        let targets = body
            .get("target_object_ids")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::ProjectedMismatch)?;
        for target in targets {
            let target = parse_object_id_text(Some(target))?;
            self.conn.execute(
                "INSERT OR REPLACE INTO projected_relationship_target(object_id,target_object_id) VALUES(?,?)",
                params![object_id, target.uuid().as_bytes()],
            )?;
        }
        Ok(())
    }

    fn project_deliberation_object(
        &self,
        object_id: &[u8],
        object_type: &str,
        value: &serde_json::Value,
        body: &serde_json::Map<String, serde_json::Value>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let ledger = parse_object_id_text(value.get("ledger_id"))?;
        let deliberation = parse_object_id_text(body.get("deliberation_id"))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO projected_deliberation_object(object_id,ledger_id,deliberation_id,object_type,created_at,payload) VALUES(?,?,?,?,?,?)",
            params![
                object_id,
                ledger.uuid().as_bytes(),
                deliberation.uuid().as_bytes(),
                object_type,
                value
                    .get("created_at")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::ProjectedMismatch)?,
                payload
            ],
        )?;
        Ok(())
    }

    /// Reconstruct the decision state for every deliberation from canonical
    /// object payloads. This is intentionally a disposable read model: the
    /// returned consensus is never written back into protocol objects.
    pub fn rebuild_consensus(&self) -> Result<Vec<DeliberationProjected>, Error> {
        self.conn.execute_batch("DELETE FROM projected_consensus; DELETE FROM projected_participant; DELETE FROM projected_decision; DELETE FROM projected_pending;")?;
        let mut statement = self.conn.prepare(
            "SELECT object_id,object_type,payload FROM protocol_object WHERE object_type IN ('deliberation','deliberation_participant_change','decision','settlement') ORDER BY content_hash",
        )?;
        let rows = statement.query_map([], |row| {
            let id: Vec<u8> = row.get(0)?;
            let object_type: String = row.get(1)?;
            let payload: Vec<u8> = row.get(2)?;
            Ok((id, object_type, payload))
        })?;
        let mut deliberations = std::collections::HashMap::new();
        let mut proposition_by_deliberation = std::collections::HashMap::new();
        let mut decisions_by_deliberation = std::collections::HashMap::<
            fact_core::ObjectId,
            Vec<(
                fact_core::ObjectId,
                fact_core::ObjectId,
                fact_state::DecisionValue,
                Vec<fact_core::ObjectId>,
            )>,
        >::new();
        let mut changes_by_deliberation = std::collections::HashMap::<
            fact_core::ObjectId,
            Vec<fact_state::ParticipantChange>,
        >::new();
        let mut settlements_by_deliberation_revision = std::collections::HashMap::<
            (fact_core::ObjectId, fact_core::ObjectId),
            Vec<(
                fact_core::ObjectId,
                Vec<fact_state::SettlementDecisionRef>,
                fact_state::SettlementOutcome,
            )>,
        >::new();
        for row in rows {
            let (id, object_type, payload) = row?;
            let id: [u8; 16] = id.try_into().map_err(|_| Error::StateProjected)?;
            let object_id = fact_core::ObjectId::from_str(&uuid::Uuid::from_bytes(id).to_string())
                .map_err(|_| Error::StateProjected)?;
            let value: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| Error::StateProjected)?;
            let body = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::StateProjected)?;
            match object_type.as_str() {
                "deliberation" => {
                    let deliberation_id = parse_object_id(body.get("deliberation_id"))?;
                    let proposition_id = parse_object_id(body.get("proposition_id"))?;
                    let revision_id = parse_object_id(body.get("revision_id"))?;
                    let participants = body
                        .get("initial_participants")
                        .and_then(serde_json::Value::as_array)
                        .ok_or(Error::StateProjected)?
                        .iter()
                        .map(|participant| {
                            parse_object_id(
                                participant
                                    .as_object()
                                    .and_then(|participant| participant.get("actor_id")),
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    deliberations.insert(deliberation_id, (revision_id, participants));
                    proposition_by_deliberation.insert(deliberation_id, proposition_id);
                }
                "decision" => {
                    let deliberation_id = parse_object_id(body.get("deliberation_id"))?;
                    let participant = parse_object_id(body.get("participant_actor_id"))?;
                    let value = match body.get("value").and_then(serde_json::Value::as_str) {
                        Some("accepted") => fact_state::DecisionValue::Accepted,
                        Some("rejected") => fact_state::DecisionValue::Rejected,
                        _ => return Err(Error::StateProjected),
                    };
                    let supersedes = body
                        .get("supersedes_decision_ids")
                        .and_then(serde_json::Value::as_array)
                        .ok_or(Error::StateProjected)?
                        .iter()
                        .map(|id| parse_object_id(Some(id)))
                        .collect::<Result<Vec<_>, _>>()?;
                    decisions_by_deliberation
                        .entry(deliberation_id)
                        .or_default()
                        .push((object_id, participant, value, supersedes));
                }
                "deliberation_participant_change" => {
                    let deliberation_id = parse_object_id(body.get("deliberation_id"))?;
                    let actor = parse_object_id(body.get("participant_actor_id"))?;
                    let operation = match body.get("operation").and_then(serde_json::Value::as_str)
                    {
                        Some("join") => fact_state::ParticipantOperation::Join,
                        Some("leave") => fact_state::ParticipantOperation::Leave,
                        _ => return Err(Error::StateProjected),
                    };
                    let predecessor = body
                        .get("predecessor_change_id")
                        .and_then(|value| (!value.is_null()).then_some(value))
                        .map(|value| parse_object_id(Some(value)))
                        .transpose()?;
                    changes_by_deliberation
                        .entry(deliberation_id)
                        .or_default()
                        .push(fact_state::ParticipantChange {
                            id: object_id,
                            actor,
                            operation,
                            predecessors: predecessor.into_iter().collect(),
                        });
                }
                "settlement" => {
                    let deliberation_id = parse_object_id(body.get("deliberation_id"))?;
                    let revision_id = parse_object_id(body.get("revision_id"))?;
                    let outcome = match body.get("outcome").and_then(serde_json::Value::as_str) {
                        Some("accepted") => fact_state::SettlementOutcome::Accepted,
                        Some("rejected") => fact_state::SettlementOutcome::Rejected,
                        _ => return Err(Error::StateProjected),
                    };
                    let refs = body
                        .get("decision_refs")
                        .and_then(serde_json::Value::as_array)
                        .ok_or(Error::StateProjected)?
                        .iter()
                        .map(|reference| {
                            let reference = reference.as_object().ok_or(Error::StateProjected)?;
                            Ok(fact_state::SettlementDecisionRef {
                                decision_id: parse_object_id(reference.get("decision_id"))?,
                                participant: parse_object_id(
                                    reference.get("participant_actor_id"),
                                )?,
                                content_hash: reference
                                    .get("content_hash")
                                    .and_then(serde_json::Value::as_str)
                                    .ok_or(Error::StateProjected)?
                                    .parse::<Hash>()
                                    .map_err(|_| Error::StateProjected)?,
                            })
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                    settlements_by_deliberation_revision
                        .entry((deliberation_id, revision_id))
                        .or_default()
                        .push((object_id, refs, outcome));
                }
                _ => return Err(Error::StateProjected),
            }
        }
        let mut valid_settlements = std::collections::HashMap::new();
        let mut output = Vec::new();
        for (deliberation_id, (revision_id, participants)) in deliberations {
            let local_changes = changes_by_deliberation
                .remove(&deliberation_id)
                .unwrap_or_default();
            let local_decisions = decisions_by_deliberation
                .remove(&deliberation_id)
                .unwrap_or_default()
                .into_iter()
                .map(
                    |(id, participant, value, supersedes)| fact_state::Decision {
                        id,
                        participant,
                        revision: revision_id,
                        value,
                        supersedes,
                    },
                )
                .collect::<Vec<_>>();
            let evaluation = fact_state::evaluate_unanimity_with_changes(
                &participants,
                &local_changes,
                revision_id,
                &local_decisions,
            )
            .map_err(|_| Error::StateProjected)?;
            let active_participants =
                fact_state::replay_participants(&participants, &local_changes)
                    .map_err(|_| Error::StateProjected)?
                    .active
                    .into_iter()
                    .collect::<Vec<_>>();
            for participant in &evaluation.participants {
                self.conn.execute("INSERT INTO projected_participant(deliberation_id,actor_id,active,source_object_id,projected_version) VALUES(?,?,?,?,?)", params![deliberation_id.uuid().as_bytes(), participant.0.uuid().as_bytes(), if active_participants.contains(participant.0) { 1i64 } else { 0i64 }, Option::<Vec<u8>>::None, "participants-v0"])?;
            }
            for decision in &local_decisions {
                let supersedes = fact_canonical::encode(
                    &serde_json::to_vec(
                        &decision
                            .supersedes
                            .iter()
                            .map(|id| id.to_string())
                            .collect::<Vec<_>>(),
                    )
                    .map_err(|_| Error::StateProjected)?,
                )?;
                self.conn.execute("INSERT INTO projected_decision(decision_id,deliberation_id,participant_actor_id,value,supersedes,payload) SELECT ?,?,?,?,?,payload FROM protocol_object WHERE object_id=?", params![decision.id.uuid().as_bytes(), deliberation_id.uuid().as_bytes(), decision.participant.uuid().as_bytes(), format!("{:?}", decision.value).to_ascii_lowercase(), supersedes, decision.id.uuid().as_bytes()])?;
            }
            for (settlement_id, refs, outcome) in settlements_by_deliberation_revision
                .remove(&(deliberation_id, revision_id))
                .unwrap_or_default()
            {
                fact_state::validate_settlement_witness(
                    &active_participants,
                    revision_id,
                    &local_decisions,
                    &refs,
                    outcome,
                )
                .map_err(|_| Error::StateProjected)?;
                valid_settlements.insert((deliberation_id, revision_id), settlement_id);
            }
            let consensus = format!("{:?}", evaluation.consensus).to_ascii_lowercase();
            if consensus != "accepted" && consensus != "rejected" {
                self.conn.execute("INSERT INTO projected_pending(pending_id,object_id,kind,reason,payload) SELECT ?,object_id,?,?,payload FROM protocol_object WHERE object_id=?", params![deliberation_id.uuid().as_bytes(), "consensus", consensus, deliberation_id.uuid().as_bytes()])?;
            }
            output.push(DeliberationProjected {
                deliberation_id,
                revision_id,
                participant_count: evaluation.participants.len(),
                applicable_decision_count: evaluation.applicable_decisions.len(),
                consensus,
            });
        }
        output.sort_by_key(|projected| projected.deliberation_id);
        for projected in &output {
            self.conn.execute(
                "INSERT INTO projected_consensus(deliberation_id,revision_id,participant_count,applicable_decision_count,consensus,projected_version) VALUES(?,?,?,?,?,?)",
                params![
                    projected.deliberation_id.uuid().as_bytes(),
                    projected.revision_id.uuid().as_bytes(),
                    projected.participant_count as i64,
                    projected.applicable_decision_count as i64,
                    projected.consensus,
                    "consensus-v0"
                ],
            )?;
        }
        self.conn.execute_batch("DELETE FROM projected_effective; INSERT INTO projected_effective(proposition_id,status,revision_id,deliberation_id,settlement_id,reason,projected_version) SELECT proposition_id,'pending',NULL,NULL,NULL,'no-valid-settlement','effective-v0' FROM projected_revision GROUP BY proposition_id;")?;
        let mut effective_candidates = std::collections::HashMap::<
            fact_core::ObjectId,
            Vec<(
                String,
                fact_core::ObjectId,
                fact_core::ObjectId,
                fact_core::ObjectId,
            )>,
        >::new();
        for projected in &output {
            if !valid_settlements.contains_key(&(projected.deliberation_id, projected.revision_id))
                || !matches!(projected.consensus.as_str(), "accepted" | "rejected")
            {
                continue;
            }
            let proposition = *proposition_by_deliberation
                .get(&projected.deliberation_id)
                .ok_or(Error::StateProjected)?;
            effective_candidates.entry(proposition).or_default().push((
                projected.consensus.clone(),
                projected.revision_id,
                projected.deliberation_id,
                *valid_settlements
                    .get(&(projected.deliberation_id, projected.revision_id))
                    .ok_or(Error::StateProjected)?,
            ));
        }
        let revision_parents = self
            .conn
            .prepare("SELECT revision_id,parent_revision_id FROM projected_revision")?
            .query_map([], |row| {
                let revision = projected_id(row.get(0)?, "invalid revision ID")?;
                let parent = row
                    .get::<_, Option<Vec<u8>>>(1)?
                    .map(|bytes| projected_id(bytes, "invalid parent revision ID"))
                    .transpose()?;
                Ok((revision, parent))
            })?
            .collect::<Result<std::collections::HashMap<_, _>, _>>()?;
        for (proposition, candidates) in &effective_candidates {
            let maximal = candidates
                .iter()
                .filter(|candidate| {
                    !candidates.iter().any(|other| {
                        candidate.1 != other.1
                            && revision_is_ancestor(&revision_parents, candidate.1, other.1)
                    })
                })
                .collect::<Vec<_>>();
            let compatible_parallel_outcome = maximal.len() > 1
                && maximal
                    .iter()
                    .all(|candidate| candidate.0 == maximal[0].0 && candidate.1 == maximal[0].1);
            let status = if maximal.len() == 1 || compatible_parallel_outcome {
                maximal[0].0.clone()
            } else {
                "conflict".to_owned()
            };
            let conflict_ancestor = (maximal.len() > 1 && !compatible_parallel_outcome)
                .then(|| last_common_settled_ancestor(&revision_parents, candidates, &maximal))
                .flatten();
            let (revision, deliberation, settlement) =
                if maximal.len() == 1 || compatible_parallel_outcome {
                    (
                        Some(maximal[0].1.uuid().as_bytes().to_vec()),
                        Some(maximal[0].2.uuid().as_bytes().to_vec()),
                        Some(maximal[0].3.uuid().as_bytes().to_vec()),
                    )
                } else if let Some(ancestor) = conflict_ancestor {
                    (
                        Some(ancestor.1.uuid().as_bytes().to_vec()),
                        Some(ancestor.2.uuid().as_bytes().to_vec()),
                        Some(ancestor.3.uuid().as_bytes().to_vec()),
                    )
                } else {
                    (None, None, None)
                };
            self.conn.execute(
                "UPDATE projected_effective SET status=?,revision_id=?,deliberation_id=?,settlement_id=?,reason=?,projected_version=? WHERE proposition_id=?",
                params![status, revision, deliberation, settlement, if maximal.len() == 1 { "valid-settlement" } else if compatible_parallel_outcome { "compatible-parallel-settlements" } else { "multiple-settled-outcomes" }, "effective-v0", proposition.uuid().as_bytes()],
            )?;
        }
        let accepted_reconciliations = self
            .conn
            .prepare(
                "SELECT r.affected_proposition_id,r.common_ancestor_revision_id,r.resolution_mode,r.selected_revision_id,r.result_revision_id
                 FROM projected_reconciliation r
                 JOIN projected_revision pr ON pr.revision_id=r.revision_id
                 JOIN projected_effective e ON e.proposition_id=pr.proposition_id
                 WHERE e.status='accepted' AND e.revision_id=r.revision_id
                 ORDER BY r.conflict_set_hash,r.revision_id",
            )?
            .query_map([], |row| {
                Ok(ReconciliationEffectiveCandidate {
                    affected_proposition: projected_id(
                        row.get(0)?,
                        "invalid reconciliation affected proposition ID",
                    )?,
                    common_ancestor: projected_id(
                        row.get(1)?,
                        "invalid reconciliation common ancestor revision ID",
                    )?,
                    resolution_mode: row.get(2)?,
                    selected_revision: row
                        .get::<_, Option<Vec<u8>>>(3)?
                        .map(|bytes| projected_id(bytes, "invalid selected revision ID"))
                        .transpose()?,
                    result_revision: row
                        .get::<_, Option<Vec<u8>>>(4)?
                        .map(|bytes| projected_id(bytes, "invalid result revision ID"))
                        .transpose()?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut reconciliations_by_affected = std::collections::HashMap::<
            fact_core::ObjectId,
            Vec<ReconciliationEffectiveCandidate>,
        >::new();
        for reconciliation in accepted_reconciliations {
            reconciliations_by_affected
                .entry(reconciliation.affected_proposition)
                .or_default()
                .push(reconciliation);
        }
        for (affected, reconciliations) in reconciliations_by_affected {
            let unique_outcomes = reconciliations
                .iter()
                .map(|reconciliation| {
                    (
                        reconciliation.resolution_mode.as_str(),
                        reconciliation.selected_revision,
                        reconciliation.result_revision,
                        reconciliation.common_ancestor,
                    )
                })
                .collect::<std::collections::HashSet<_>>();
            if unique_outcomes.len() > 1 {
                self.conn.execute(
                    "UPDATE projected_effective SET status='conflict',reason='multiple-reconciliation-outcomes',projected_version='effective-v0' WHERE proposition_id=?",
                    [affected.uuid().as_bytes()],
                )?;
                continue;
            }
            let reconciliation = reconciliations.first().ok_or(Error::StateProjected)?;
            let Some(target_revision) = (match reconciliation.resolution_mode.as_str() {
                "select" => reconciliation.selected_revision,
                "derive" => reconciliation.result_revision,
                "reject-all" => Some(reconciliation.common_ancestor),
                _ => None,
            }) else {
                continue;
            };
            let Some((_, revision, deliberation, settlement)) =
                effective_candidates.get(&affected).and_then(|candidates| {
                    candidates.iter().find(|candidate| {
                        candidate.0 == "accepted" && candidate.1 == target_revision
                    })
                })
            else {
                continue;
            };
            let reason = match reconciliation.resolution_mode.as_str() {
                "select" => "reconciliation-select",
                "derive" => "reconciliation-derive",
                "reject-all" => "reconciliation-reject-all",
                _ => continue,
            };
            self.conn.execute(
                "UPDATE projected_effective SET status='accepted',revision_id=?,deliberation_id=?,settlement_id=?,reason=?,projected_version='effective-v0' WHERE proposition_id=?",
                params![
                    revision.uuid().as_bytes(),
                    deliberation.uuid().as_bytes(),
                    settlement.uuid().as_bytes(),
                    reason,
                    affected.uuid().as_bytes()
                ],
            )?;
        }
        self.rebuild_lifecycle_effective_state()?;
        Ok(output)
    }

    fn refresh_effective_for_deliberation(
        &self,
        deliberation_id: fact_core::ObjectId,
    ) -> Result<(), Error> {
        let proposition = self
            .conn
            .query_row(
                "SELECT proposition_id FROM projected_deliberation WHERE deliberation_id=?",
                [deliberation_id.uuid().as_bytes()],
                |row| projected_id(row.get(0)?, "invalid proposition ID"),
            )
            .optional()?
            .ok_or(Error::StateProjected)?;
        self.refresh_effective_for_proposition(proposition)
    }

    fn refresh_effective_for_proposition(
        &self,
        proposition: fact_core::ObjectId,
    ) -> Result<(), Error> {
        self.conn.execute(
            "INSERT OR IGNORE INTO projected_effective(proposition_id,status,reason,projected_version) VALUES(?,'pending','no-valid-settlement','effective-v0')",
            [proposition.uuid().as_bytes()],
        )?;
        self.conn.execute(
            "UPDATE projected_effective
             SET status='pending',
                 revision_id=NULL,
                 deliberation_id=NULL,
                 settlement_id=NULL,
                 reason='no-valid-settlement',
                 projected_version='effective-v0'
             WHERE proposition_id=?",
            [proposition.uuid().as_bytes()],
        )?;
        let rows = self
            .conn
            .prepare(
                "SELECT d.deliberation_id,d.revision_id,c.consensus,s.object_id,s.payload
                 FROM projected_deliberation d
                 JOIN projected_consensus c ON c.deliberation_id=d.deliberation_id
                 JOIN projected_deliberation_object s
                   ON s.deliberation_id=d.deliberation_id
                  AND s.object_type='settlement'
                 JOIN protocol_object p ON p.object_id=s.object_id
                 WHERE d.proposition_id=?
                 ORDER BY p.content_hash",
            )?
            .query_map([proposition.uuid().as_bytes()], |row| {
                Ok((
                    projected_id(row.get(0)?, "invalid deliberation ID")?,
                    projected_id(row.get(1)?, "invalid revision ID")?,
                    row.get::<_, String>(2)?,
                    projected_id(row.get(3)?, "invalid settlement ID")?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut candidates = Vec::new();
        for (deliberation, revision, consensus, settlement, payload) in rows {
            if !matches!(consensus.as_str(), "accepted" | "rejected") {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| Error::StateProjected)?;
            let body = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::StateProjected)?;
            if parse_object_id(body.get("revision_id"))? != revision {
                continue;
            }
            candidates.push((consensus, revision, deliberation, settlement));
        }
        if candidates.is_empty() {
            return Ok(());
        }
        let revision_parents = self
            .conn
            .prepare("SELECT revision_id,parent_revision_id FROM projected_revision")?
            .query_map([], |row| {
                let revision = projected_id(row.get(0)?, "invalid revision ID")?;
                let parent = row
                    .get::<_, Option<Vec<u8>>>(1)?
                    .map(|bytes| projected_id(bytes, "invalid parent revision ID"))
                    .transpose()?;
                Ok((revision, parent))
            })?
            .collect::<Result<std::collections::HashMap<_, _>, _>>()?;
        self.apply_effective_candidates(proposition, &revision_parents, &candidates)?;
        self.apply_reconciliation_effective_for_proposition(proposition, &candidates)
    }

    fn apply_effective_candidates(
        &self,
        proposition: fact_core::ObjectId,
        revision_parents: &std::collections::HashMap<
            fact_core::ObjectId,
            Option<fact_core::ObjectId>,
        >,
        candidates: &[(
            String,
            fact_core::ObjectId,
            fact_core::ObjectId,
            fact_core::ObjectId,
        )],
    ) -> Result<(), Error> {
        let maximal = candidates
            .iter()
            .filter(|candidate| {
                !candidates.iter().any(|other| {
                    candidate.1 != other.1
                        && revision_is_ancestor(revision_parents, candidate.1, other.1)
                })
            })
            .collect::<Vec<_>>();
        let compatible_parallel_outcome = maximal.len() > 1
            && maximal
                .iter()
                .all(|candidate| candidate.0 == maximal[0].0 && candidate.1 == maximal[0].1);
        let status = if maximal.len() == 1 || compatible_parallel_outcome {
            maximal[0].0.clone()
        } else {
            "conflict".to_owned()
        };
        let conflict_ancestor = (maximal.len() > 1 && !compatible_parallel_outcome)
            .then(|| last_common_settled_ancestor(revision_parents, candidates, &maximal))
            .flatten();
        let (revision, deliberation, settlement) =
            if maximal.len() == 1 || compatible_parallel_outcome {
                (
                    Some(maximal[0].1.uuid().as_bytes().to_vec()),
                    Some(maximal[0].2.uuid().as_bytes().to_vec()),
                    Some(maximal[0].3.uuid().as_bytes().to_vec()),
                )
            } else if let Some(ancestor) = conflict_ancestor {
                (
                    Some(ancestor.1.uuid().as_bytes().to_vec()),
                    Some(ancestor.2.uuid().as_bytes().to_vec()),
                    Some(ancestor.3.uuid().as_bytes().to_vec()),
                )
            } else {
                (None, None, None)
            };
        self.conn.execute(
            "UPDATE projected_effective SET status=?,revision_id=?,deliberation_id=?,settlement_id=?,reason=?,projected_version=? WHERE proposition_id=?",
            params![
                status,
                revision,
                deliberation,
                settlement,
                if maximal.len() == 1 {
                    "valid-settlement"
                } else if compatible_parallel_outcome {
                    "compatible-parallel-settlements"
                } else {
                    "multiple-settled-outcomes"
                },
                "effective-v0",
                proposition.uuid().as_bytes()
            ],
        )?;
        Ok(())
    }

    fn apply_reconciliation_effective_for_proposition(
        &self,
        proposition: fact_core::ObjectId,
        candidates: &[(
            String,
            fact_core::ObjectId,
            fact_core::ObjectId,
            fact_core::ObjectId,
        )],
    ) -> Result<(), Error> {
        let reconciliations = self
            .conn
            .prepare(
                "SELECT r.common_ancestor_revision_id,r.resolution_mode,r.selected_revision_id,r.result_revision_id
                 FROM projected_reconciliation r
                 JOIN projected_revision pr ON pr.revision_id=r.revision_id
                 JOIN projected_effective e ON e.proposition_id=pr.proposition_id
                 WHERE r.affected_proposition_id=?
                   AND e.status='accepted'
                   AND e.revision_id=r.revision_id
                 ORDER BY r.conflict_set_hash,r.revision_id",
            )?
            .query_map([proposition.uuid().as_bytes()], |row| {
                Ok(ReconciliationEffectiveCandidate {
                    affected_proposition: proposition,
                    common_ancestor: projected_id(
                        row.get(0)?,
                        "invalid reconciliation common ancestor revision ID",
                    )?,
                    resolution_mode: row.get(1)?,
                    selected_revision: row
                        .get::<_, Option<Vec<u8>>>(2)?
                        .map(|bytes| projected_id(bytes, "invalid selected revision ID"))
                        .transpose()?,
                    result_revision: row
                        .get::<_, Option<Vec<u8>>>(3)?
                        .map(|bytes| projected_id(bytes, "invalid result revision ID"))
                        .transpose()?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if reconciliations.is_empty() {
            return Ok(());
        }
        let unique_outcomes = reconciliations
            .iter()
            .map(|reconciliation| {
                (
                    reconciliation.resolution_mode.as_str(),
                    reconciliation.selected_revision,
                    reconciliation.result_revision,
                    reconciliation.common_ancestor,
                )
            })
            .collect::<std::collections::HashSet<_>>();
        if unique_outcomes.len() > 1 {
            self.conn.execute(
                "UPDATE projected_effective SET status='conflict',reason='multiple-reconciliation-outcomes',projected_version='effective-v0' WHERE proposition_id=?",
                [proposition.uuid().as_bytes()],
            )?;
            return Ok(());
        }
        let reconciliation = reconciliations.first().ok_or(Error::StateProjected)?;
        let Some(target_revision) = (match reconciliation.resolution_mode.as_str() {
            "select" => reconciliation.selected_revision,
            "derive" => reconciliation.result_revision,
            "reject-all" => Some(reconciliation.common_ancestor),
            _ => None,
        }) else {
            return Ok(());
        };
        let Some((_, revision, deliberation, settlement)) = candidates
            .iter()
            .find(|candidate| candidate.0 == "accepted" && candidate.1 == target_revision)
        else {
            return Ok(());
        };
        let reason = match reconciliation.resolution_mode.as_str() {
            "select" => "reconciliation-select",
            "derive" => "reconciliation-derive",
            "reject-all" => "reconciliation-reject-all",
            _ => return Ok(()),
        };
        self.conn.execute(
            "UPDATE projected_effective SET status='accepted',revision_id=?,deliberation_id=?,settlement_id=?,reason=?,projected_version='effective-v0' WHERE proposition_id=?",
            params![
                revision.uuid().as_bytes(),
                deliberation.uuid().as_bytes(),
                settlement.uuid().as_bytes(),
                reason,
                proposition.uuid().as_bytes()
            ],
        )?;
        Ok(())
    }

    fn refresh_deliberation_consensus(
        &self,
        deliberation_id: fact_core::ObjectId,
    ) -> Result<(), Error> {
        let (revision_id, participants, deliberation_payload): (
            fact_core::ObjectId,
            Vec<fact_core::ObjectId>,
            Vec<u8>,
        ) = self
            .conn
            .query_row(
                "SELECT revision_id,payload FROM projected_deliberation WHERE deliberation_id=?",
                [deliberation_id.uuid().as_bytes()],
                |row| {
                    let revision_id = projected_id(row.get(0)?, "invalid revision ID")?;
                    let payload: Vec<u8> = row.get(1)?;
                    let value: serde_json::Value =
                        serde_json::from_slice(&payload).map_err(|_| {
                            rusqlite::Error::InvalidColumnType(
                                1,
                                "payload".into(),
                                rusqlite::types::Type::Blob,
                            )
                        })?;
                    let body = value
                        .get("body")
                        .and_then(serde_json::Value::as_object)
                        .ok_or_else(|| {
                            rusqlite::Error::InvalidColumnType(
                                1,
                                "payload".into(),
                                rusqlite::types::Type::Blob,
                            )
                        })?;
                    let participants = body
                        .get("initial_participants")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| {
                            rusqlite::Error::InvalidColumnType(
                                1,
                                "payload".into(),
                                rusqlite::types::Type::Blob,
                            )
                        })?
                        .iter()
                        .map(|participant| {
                            parse_object_id(
                                participant
                                    .as_object()
                                    .and_then(|participant| participant.get("actor_id")),
                            )
                            .map_err(|_| {
                                rusqlite::Error::InvalidColumnType(
                                    1,
                                    "payload".into(),
                                    rusqlite::types::Type::Blob,
                                )
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok((revision_id, participants, payload))
                },
            )
            .optional()?
            .ok_or(Error::StateProjected)?;
        let _ = deliberation_payload;
        let changes = self.deliberation_participant_changes(deliberation_id)?;
        let decisions = self.deliberation_decisions(deliberation_id, revision_id)?;
        let evaluation = fact_state::evaluate_unanimity_with_changes(
            &participants,
            &changes,
            revision_id,
            &decisions,
        )
        .map_err(|_| Error::StateProjected)?;
        let active_participants = fact_state::replay_participants(&participants, &changes)
            .map_err(|_| Error::StateProjected)?
            .active
            .into_iter()
            .collect::<Vec<_>>();
        self.conn.execute(
            "DELETE FROM projected_participant WHERE deliberation_id=?",
            [deliberation_id.uuid().as_bytes()],
        )?;
        self.conn.execute(
            "DELETE FROM projected_decision WHERE deliberation_id=?",
            [deliberation_id.uuid().as_bytes()],
        )?;
        self.conn.execute(
            "DELETE FROM projected_consensus WHERE deliberation_id=?",
            [deliberation_id.uuid().as_bytes()],
        )?;
        self.conn.execute(
            "DELETE FROM projected_pending WHERE pending_id=?",
            [deliberation_id.uuid().as_bytes()],
        )?;
        for participant in &evaluation.participants {
            self.conn.execute("INSERT INTO projected_participant(deliberation_id,actor_id,active,source_object_id,projected_version) VALUES(?,?,?,?,?)", params![deliberation_id.uuid().as_bytes(), participant.0.uuid().as_bytes(), if active_participants.contains(participant.0) { 1i64 } else { 0i64 }, Option::<Vec<u8>>::None, "participants-v0"])?;
        }
        for decision in &decisions {
            let supersedes = fact_canonical::encode(
                &serde_json::to_vec(
                    &decision
                        .supersedes
                        .iter()
                        .map(|id| id.to_string())
                        .collect::<Vec<_>>(),
                )
                .map_err(|_| Error::StateProjected)?,
            )?;
            self.conn.execute("INSERT INTO projected_decision(decision_id,deliberation_id,participant_actor_id,value,supersedes,payload) SELECT ?,?,?,?,?,payload FROM protocol_object WHERE object_id=?", params![decision.id.uuid().as_bytes(), deliberation_id.uuid().as_bytes(), decision.participant.uuid().as_bytes(), format!("{:?}", decision.value).to_ascii_lowercase(), supersedes, decision.id.uuid().as_bytes()])?;
        }
        let consensus = format!("{:?}", evaluation.consensus).to_ascii_lowercase();
        if consensus != "accepted" && consensus != "rejected" {
            self.conn.execute("INSERT INTO projected_pending(pending_id,object_id,kind,reason,payload) SELECT ?,object_id,?,?,payload FROM protocol_object WHERE object_id=?", params![deliberation_id.uuid().as_bytes(), "consensus", consensus, deliberation_id.uuid().as_bytes()])?;
        }
        self.conn.execute(
            "INSERT INTO projected_consensus(deliberation_id,revision_id,participant_count,applicable_decision_count,consensus,projected_version) VALUES(?,?,?,?,?,?)",
            params![
                deliberation_id.uuid().as_bytes(),
                revision_id.uuid().as_bytes(),
                evaluation.participants.len() as i64,
                evaluation.applicable_decisions.len() as i64,
                consensus,
                "consensus-v0"
            ],
        )?;
        Ok(())
    }

    fn deliberation_participant_changes(
        &self,
        deliberation_id: fact_core::ObjectId,
    ) -> Result<Vec<fact_state::ParticipantChange>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT object_id,payload
             FROM projected_deliberation_object
             WHERE deliberation_id=? AND object_type='deliberation_participant_change'
             ORDER BY object_id",
        )?;
        let rows = statement.query_map([deliberation_id.uuid().as_bytes()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut changes = Vec::new();
        for row in rows {
            let (id, payload) = row?;
            let id: [u8; 16] = id.try_into().map_err(|_| Error::StateProjected)?;
            let id = fact_core::ObjectId::from_str(&uuid::Uuid::from_bytes(id).to_string())
                .map_err(|_| Error::StateProjected)?;
            let value: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| Error::StateProjected)?;
            let body = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::StateProjected)?;
            let actor = parse_object_id(body.get("participant_actor_id"))?;
            let operation = match body.get("operation").and_then(serde_json::Value::as_str) {
                Some("join") => fact_state::ParticipantOperation::Join,
                Some("leave") => fact_state::ParticipantOperation::Leave,
                _ => return Err(Error::StateProjected),
            };
            let predecessor = body
                .get("predecessor_change_id")
                .and_then(|value| (!value.is_null()).then_some(value))
                .map(|value| parse_object_id(Some(value)))
                .transpose()?;
            changes.push(fact_state::ParticipantChange {
                id,
                actor,
                operation,
                predecessors: predecessor.into_iter().collect(),
            });
        }
        Ok(changes)
    }

    fn deliberation_decisions(
        &self,
        deliberation_id: fact_core::ObjectId,
        revision_id: fact_core::ObjectId,
    ) -> Result<Vec<fact_state::Decision>, Error> {
        let mut statement = self.conn.prepare(
            "SELECT object_id,payload
             FROM projected_deliberation_object
             WHERE deliberation_id=? AND object_type='decision'
             ORDER BY object_id",
        )?;
        let rows = statement.query_map([deliberation_id.uuid().as_bytes()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut decisions = Vec::new();
        for row in rows {
            let (id, payload) = row?;
            let id: [u8; 16] = id.try_into().map_err(|_| Error::StateProjected)?;
            let id = fact_core::ObjectId::from_str(&uuid::Uuid::from_bytes(id).to_string())
                .map_err(|_| Error::StateProjected)?;
            let value: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| Error::StateProjected)?;
            let body = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::StateProjected)?;
            let participant = parse_object_id(body.get("participant_actor_id"))?;
            let value = match body.get("value").and_then(serde_json::Value::as_str) {
                Some("accepted") => fact_state::DecisionValue::Accepted,
                Some("rejected") => fact_state::DecisionValue::Rejected,
                _ => return Err(Error::StateProjected),
            };
            let supersedes = body
                .get("supersedes_decision_ids")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::StateProjected)?
                .iter()
                .map(|id| parse_object_id(Some(id)))
                .collect::<Result<Vec<_>, _>>()?;
            decisions.push(fact_state::Decision {
                id,
                participant,
                revision: revision_id,
                value,
                supersedes,
            });
        }
        Ok(decisions)
    }

    fn rebuild_lifecycle_effective_state(&self) -> Result<(), Error> {
        let mut transitions = std::collections::HashMap::<
            (fact_core::ObjectId, String),
            Vec<(fact_core::ObjectId, String, Vec<fact_core::ObjectId>)>,
        >::new();
        let mut statement = self.conn.prepare(
            "SELECT object_id,payload FROM protocol_object WHERE object_type='proposition_lifecycle'",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (id, payload) = row?;
            let id: [u8; 16] = id.try_into().map_err(|_| Error::StateProjected)?;
            let id = fact_core::ObjectId::from_str(&uuid::Uuid::from_bytes(id).to_string())
                .map_err(|_| Error::StateProjected)?;
            let value: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| Error::StateProjected)?;
            let body = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::StateProjected)?;
            let proposition = parse_object_id(body.get("proposition_id"))?;
            let dimension = body
                .get("dimension")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::StateProjected)?
                .to_owned();
            let operation = body
                .get("operation")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::StateProjected)?
                .to_owned();
            let predecessors = body
                .get("predecessor_ids")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::StateProjected)?
                .iter()
                .map(|value| parse_object_id(Some(value)))
                .collect::<Result<Vec<_>, _>>()?;
            transitions
                .entry((proposition, dimension))
                .or_default()
                .push((id, operation, predecessors));
        }
        for ((proposition, dimension), values) in transitions {
            let ids: std::collections::HashSet<_> = values.iter().map(|(id, _, _)| *id).collect();
            let referenced: std::collections::HashSet<_> = values
                .iter()
                .flat_map(|(_, _, predecessors)| predecessors.iter().copied())
                .collect();
            if referenced.iter().any(|id| !ids.contains(id)) {
                return Err(Error::StateProjected);
            }
            let tips = values
                .iter()
                .filter(|(id, _, _)| !referenced.contains(id))
                .collect::<Vec<_>>();
            let column = match dimension.as_str() {
                "withdrawal" => "withdrawal_status",
                "archival" => "archival_status",
                _ => return Err(Error::StateProjected),
            };
            let (status, reason) = if tips.len() != 1 {
                ("conflict", "multiple-lifecycle-tips")
            } else {
                match (dimension.as_str(), tips[0].1.as_str()) {
                    ("withdrawal", "withdraw") => ("withdrawn", "lifecycle-withdraw"),
                    ("withdrawal", "restore") => ("active", "lifecycle-restore"),
                    ("archival", "archive") => ("archived", "lifecycle-archive"),
                    ("archival", "unarchive") => ("visible", "lifecycle-unarchive"),
                    _ => return Err(Error::StateProjected),
                }
            };
            self.conn.execute(
                &format!(
                    "UPDATE projected_effective SET {column}=?,reason=?,projected_version=? WHERE proposition_id=?"
                ),
                params![status, reason, "effective-v0", proposition.uuid().as_bytes()],
            )?;
        }
        Ok(())
    }

    fn update_proposition_lifecycle_effective_state(
        &self,
        proposition: fact_core::ObjectId,
        dimension: &str,
    ) -> Result<(), Error> {
        let mut statement = self.conn.prepare(
            "SELECT object_id,payload
             FROM projected_lifecycle
             WHERE object_type='proposition_lifecycle'
               AND target_id=?
               AND dimension=?",
        )?;
        let rows = statement
            .query_map(params![proposition.uuid().as_bytes(), dimension], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
        let mut values = Vec::new();
        for row in rows {
            let (id, payload) = row?;
            let id: [u8; 16] = id.try_into().map_err(|_| Error::StateProjected)?;
            let id = fact_core::ObjectId::from_str(&uuid::Uuid::from_bytes(id).to_string())
                .map_err(|_| Error::StateProjected)?;
            let value: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| Error::StateProjected)?;
            let body = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::StateProjected)?;
            let operation = body
                .get("operation")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::StateProjected)?
                .to_owned();
            let predecessors = body
                .get("predecessor_ids")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::StateProjected)?
                .iter()
                .map(|value| parse_object_id(Some(value)))
                .collect::<Result<Vec<_>, _>>()?;
            values.push((id, operation, predecessors));
        }
        let ids: std::collections::HashSet<_> = values.iter().map(|(id, _, _)| *id).collect();
        let referenced: std::collections::HashSet<_> = values
            .iter()
            .flat_map(|(_, _, predecessors)| predecessors.iter().copied())
            .collect();
        if referenced.iter().any(|id| !ids.contains(id)) {
            return Err(Error::StateProjected);
        }
        let tips = values
            .iter()
            .filter(|(id, _, _)| !referenced.contains(id))
            .collect::<Vec<_>>();
        let column = match dimension {
            "withdrawal" => "withdrawal_status",
            "archival" => "archival_status",
            _ => return Err(Error::StateProjected),
        };
        let (status, reason) = if tips.len() != 1 {
            ("conflict", "multiple-lifecycle-tips")
        } else {
            match (dimension, tips[0].1.as_str()) {
                ("withdrawal", "withdraw") => ("withdrawn", "lifecycle-withdraw"),
                ("withdrawal", "restore") => ("active", "lifecycle-restore"),
                ("archival", "archive") => ("archived", "lifecycle-archive"),
                ("archival", "unarchive") => ("visible", "lifecycle-unarchive"),
                _ => return Err(Error::StateProjected),
            }
        };
        let updated = self.conn.execute(
            &format!(
                "UPDATE projected_effective SET {column}=?,reason=?,projected_version=? WHERE proposition_id=?"
            ),
            params![status, reason, "effective-v0", proposition.uuid().as_bytes()],
        )?;
        if updated != 1 {
            return Err(Error::StateProjected);
        }
        Ok(())
    }

    /// Insert a complete bundle atomically. Dependencies may refer to any
    /// frame in the bundle, including frames which themselves refer back.
    pub fn insert_verified_bundle(&self, objects: &[Vec<u8>]) -> Result<Vec<Hash>, Error> {
        self.insert_verified_bundle_with_projected_mode(objects, ProjectedMode::Defer)
    }

    /// Insert a complete bundle from borrowed object frames.
    pub fn insert_verified_bundle_slices(&self, objects: &[&[u8]]) -> Result<Vec<Hash>, Error> {
        self.insert_verified_bundle_slices_with_projected_mode(objects, ProjectedMode::Defer)
    }

    /// Insert a complete verified bundle and explicitly choose when
    /// projected read models are refreshed.
    pub fn insert_verified_bundle_with_projected_mode(
        &self,
        objects: &[Vec<u8>],
        projected_mode: ProjectedMode,
    ) -> Result<Vec<Hash>, Error> {
        self.insert_bundle(objects, false, projected_mode)
    }

    /// Insert a complete verified bundle from borrowed object frames and
    /// explicitly choose when projected read models are refreshed.
    pub fn insert_verified_bundle_slices_with_projected_mode(
        &self,
        objects: &[&[u8]],
        projected_mode: ProjectedMode,
    ) -> Result<Vec<Hash>, Error> {
        self.insert_bundle(objects, false, projected_mode)
    }

    /// Insert a bundle and require every action object to pass causal-point
    /// authorization before the transaction commits.
    pub fn insert_authorized_bundle(&self, objects: &[Vec<u8>]) -> Result<Vec<Hash>, Error> {
        self.insert_authorized_bundle_with_projected_mode(objects, ProjectedMode::FullRebuild)
    }

    /// Insert an authorized bundle from borrowed object frames.
    pub fn insert_authorized_bundle_slices(&self, objects: &[&[u8]]) -> Result<Vec<Hash>, Error> {
        self.insert_authorized_bundle_slices_with_projected_mode(
            objects,
            ProjectedMode::FullRebuild,
        )
    }

    /// Insert an authorized bundle and explicitly choose when projected read
    /// models are refreshed.
    pub fn insert_authorized_bundle_with_projected_mode(
        &self,
        objects: &[Vec<u8>],
        projected_mode: ProjectedMode,
    ) -> Result<Vec<Hash>, Error> {
        self.insert_bundle(objects, true, projected_mode)
    }

    /// Insert an authorized bundle from borrowed object frames and explicitly
    /// choose when projected read models are refreshed.
    pub fn insert_authorized_bundle_slices_with_projected_mode(
        &self,
        objects: &[&[u8]],
        projected_mode: ProjectedMode,
    ) -> Result<Vec<Hash>, Error> {
        self.insert_bundle(objects, true, projected_mode)
    }

    fn insert_bundle<T: AsRef<[u8]>>(
        &self,
        objects: &[T],
        enforce_authorization: bool,
        projected_mode: ProjectedMode,
    ) -> Result<Vec<Hash>, Error> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let mut staged = std::collections::HashMap::new();
            for object in objects {
                let object = object.as_ref();
                let cose = fact_crypto::decode_sign1(object)?;
                let canonical = fact_canonical::encode(&cose.payload)?;
                if canonical != cose.payload {
                    return Err(Error::PayloadMismatch);
                }
                let object_type = fact_schema::validate_envelope(&canonical)?;
                let value: serde_json::Value =
                    serde_json::from_slice(&canonical).map_err(|_| Error::Metadata)?;
                let map = value.as_object().ok_or(Error::Metadata)?;
                let id = uuid_bytes(map, "id")?.to_vec();
                let ledger = if object_type.ledger_scoped() {
                    uuid_bytes(map, "ledger_id")?.to_vec()
                } else {
                    Vec::new()
                };
                let hash = Hash::digest(&canonical);
                if staged
                    .insert(
                        id,
                        (
                            hash.as_bytes().to_vec(),
                            if ledger.is_empty() {
                                None
                            } else {
                                Some(ledger)
                            },
                        ),
                    )
                    .is_some()
                {
                    return Err(Error::Duplicate);
                }
            }
            for object in objects {
                self.stage_ledger_from_genesis(object.as_ref())?;
            }
            for object in objects {
                self.stage_key_material(object.as_ref())?;
            }
            let validated = objects
                .iter()
                .map(|object| self.validate_object(object.as_ref(), Some(&staged)))
                .collect::<Result<Vec<_>, _>>()?;
            for object in &validated {
                self.insert_validated_object(object, false)?;
            }
            for object in &validated {
                self.insert_dependencies(object)?;
            }
            for object in &validated {
                self.validate_cross_object_semantics(object)?;
            }
            if enforce_authorization {
                let bootstrap_ids = bootstrap_cycle_ids(&validated)?;
                for object in &validated {
                    if !bootstrap_ids.contains(&object.id) {
                        self.authorize_object(&object.cose)?;
                    }
                }
            }
            self.apply_projected_mode(&validated, projected_mode)?;
            Ok(validated.into_iter().map(|object| object.hash).collect())
        })();
        match result {
            Ok(hashes) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(hashes)
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Validate the canonical envelope and exact embedded COSE payload before
    /// making the object visible in the canonical SQLite layer.
    pub fn insert_verified_object(&self, cose_bytes: &[u8]) -> Result<Hash, Error> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = self.insert_verified_object_in_transaction(cose_bytes);
        match result {
            Ok(hash) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(hash)
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn insert_verified_object_in_transaction(&self, cose_bytes: &[u8]) -> Result<Hash, Error> {
        self.stage_ledger_from_genesis(cose_bytes)?;
        self.stage_key_material(cose_bytes)?;
        let object = self.validate_object(cose_bytes, None)?;
        self.validate_cross_object_semantics(&object)?;
        let hash = object.hash;
        self.insert_validated_object(&object, true)?;
        Ok(hash)
    }

    pub fn insert_authorized_object(&self, cose_bytes: &[u8]) -> Result<Hash, Error> {
        self.insert_authorized_object_at(cose_bytes, Some(fact_state::TrustedTime::system()))
    }

    pub fn insert_authorized_object_at(
        &self,
        cose_bytes: &[u8],
        trusted_time: Option<fact_state::TrustedTime>,
    ) -> Result<Hash, Error> {
        self.insert_authorized_object_at_with_projected_mode(
            cose_bytes,
            trusted_time,
            ProjectedMode::FullRebuild,
        )
    }

    pub fn insert_authorized_object_with_projected_mode(
        &self,
        cose_bytes: &[u8],
        projected_mode: ProjectedMode,
    ) -> Result<Hash, Error> {
        self.insert_authorized_object_at_with_projected_mode(
            cose_bytes,
            Some(fact_state::TrustedTime::system()),
            projected_mode,
        )
    }

    pub fn insert_authorized_object_at_with_projected_mode(
        &self,
        cose_bytes: &[u8],
        trusted_time: Option<fact_state::TrustedTime>,
        projected_mode: ProjectedMode,
    ) -> Result<Hash, Error> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.stage_key_material(cose_bytes)?;
            let object = self.validate_object(cose_bytes, None)?;
            self.validate_cross_object_semantics(&object)?;
            self.insert_validated_object(&object, true)?;
            self.authorize_object_at(cose_bytes, trusted_time)?;
            self.apply_projected_mode(std::slice::from_ref(&object), projected_mode)?;
            Ok(object.hash)
        })();
        match result {
            Ok(hash) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(hash)
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Evaluate an already assembled signed object's authorization using only
    /// its causal dependency closure. This is intentionally separate from
    /// projected rebuilds: a later revocation outside the closure cannot
    /// retroactively change the result for this object.
    pub fn authorize_object(&self, cose_bytes: &[u8]) -> Result<(), Error> {
        self.authorize_object_at(cose_bytes, Some(fact_state::TrustedTime::system()))
    }

    pub fn authorize_object_at(
        &self,
        cose_bytes: &[u8],
        trusted_time: Option<fact_state::TrustedTime>,
    ) -> Result<(), Error> {
        let cose = fact_crypto::decode_sign1(cose_bytes)?;
        let canonical = fact_canonical::encode(&cose.payload)?;
        if canonical != cose.payload {
            return Err(Error::PayloadMismatch);
        }
        let root: serde_json::Value =
            serde_json::from_slice(&canonical).map_err(|_| Error::Metadata)?;
        let root_object = root.as_object().ok_or(Error::Metadata)?;
        let root_type = root_object
            .get("object_type")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Metadata)?;
        let root_id = parse_object_id_text(root_object.get("id"))?;
        let mut closure = std::collections::HashMap::<Vec<u8>, serde_json::Value>::new();
        let mut pending = vec![(root_id.uuid().as_bytes().to_vec(), root.clone())];
        while let Some((id, value)) = pending.pop() {
            if closure.contains_key(&id) {
                continue;
            }
            let dependencies = value
                .get("dependencies")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::InvalidLineage)?;
            for dependency in dependencies {
                let dependency_id = parse_object_id_text(dependency.get("object_id"))?;
                if closure.contains_key(dependency_id.uuid().as_bytes().as_slice()) {
                    continue;
                }
                let payload: Vec<u8> = self
                    .conn
                    .query_row(
                        "SELECT payload FROM protocol_object WHERE object_id=?",
                        [dependency_id.uuid().as_bytes()],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or(Error::MissingDependency)?;
                let dependency_value: serde_json::Value =
                    serde_json::from_slice(&payload).map_err(|_| Error::Metadata)?;
                pending.push((dependency_id.uuid().as_bytes().to_vec(), dependency_value));
            }
            closure.insert(id, value);
        }
        if root_type == "invitation_lifecycle" {
            let body = root_object
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::Metadata)?;
            if body.get("operation").and_then(serde_json::Value::as_str) == Some("decline") {
                let invitation_id = parse_object_id_text(body.get("invitation_id"))?;
                let invitation = closure
                    .get(invitation_id.uuid().as_bytes().as_slice())
                    .and_then(|value| value.get("body"))
                    .and_then(serde_json::Value::as_object)
                    .ok_or(Error::InvalidLineage)?;
                if invitation.get("invited_actor_id") != root_object.get("actor_id") {
                    return Err(Error::Unauthorized);
                }
                return Ok(());
            }
        }
        let ledger = parse_object_id_text(root_object.get("ledger_id"))?;
        let actor = parse_object_id_text(root_object.get("actor_id"))?;
        let ancestors = closure
            .keys()
            .filter_map(|id| uuid::Uuid::from_slice(id).ok())
            .filter_map(|uuid| uuid.to_string().parse::<fact_core::ObjectId>().ok())
            .collect::<std::collections::HashSet<_>>();
        let mut authorities = Vec::new();
        let mut delegations = Vec::new();
        for value in closure.values() {
            let Some(object) = value.as_object() else {
                continue;
            };
            let object_type = object
                .get("object_type")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::Metadata)?;
            if object_type == "delegation" {
                let body = object
                    .get("body")
                    .and_then(serde_json::Value::as_object)
                    .ok_or(Error::Metadata)?;
                delegations.push(fact_state::Delegation {
                    id: parse_object_id_text(object.get("id"))?,
                    delegator: parse_object_id_text(body.get("delegator_actor_id"))?,
                    delegatee: parse_object_id_text(body.get("delegatee_actor_id"))?,
                    capability: parse_capability(
                        body.get("capability").ok_or(Error::InvalidLineage)?,
                    )?,
                    scope: parse_scope(body.get("scope"), Some(&closure))?,
                    parent_delegation_id: parse_optional_object_id_text(
                        body.get("parent_delegation_id"),
                    )?,
                    redelegable: body
                        .get("redelegable")
                        .and_then(serde_json::Value::as_bool)
                        .ok_or(Error::InvalidLineage)?,
                    revoked_by: Vec::new(),
                    validity: parse_validity(body.get("validity"))?,
                });
                continue;
            }
            if object_type != "authorization_grant" {
                continue;
            }
            let body = object
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::Metadata)?;
            let id = parse_object_id_text(object.get("id"))?;
            let receiving = parse_object_id_text(body.get("receiving_actor_id"))?;
            let scope = parse_scope(body.get("scope"), Some(&closure))?;
            let capabilities = body
                .get("capabilities")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::InvalidLineage)?;
            for capability in capabilities {
                authorities.push(fact_state::Authority {
                    id,
                    actor: receiving,
                    capability: parse_capability(capability)?,
                    scope: scope.clone(),
                    revoked_by: Vec::new(),
                    validity: parse_validity(body.get("validity"))?,
                });
            }
        }
        for value in closure.values() {
            let Some(object) = value.as_object() else {
                continue;
            };
            let object_type = object
                .get("object_type")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::Metadata)?;
            if object_type != "authorization_revocation" && object_type != "delegation_revocation" {
                continue;
            }
            let body = object
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::Metadata)?;
            let revoked = if object_type == "authorization_revocation" {
                parse_object_id_text(body.get("revoked_grant_id"))?
            } else {
                parse_object_id_text(body.get("revoked_delegation_id"))?
            };
            let revocation = parse_object_id_text(object.get("id"))?;
            if object_type == "authorization_revocation" {
                for authority in &mut authorities {
                    if authority.id == revoked {
                        authority.revoked_by.push(revocation);
                    }
                }
            } else {
                for delegation in &mut delegations {
                    if delegation.id == revoked {
                        delegation.revoked_by.push(revocation);
                    }
                }
            }
        }
        if root_type == "delegation" {
            let body = root_object
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::Metadata)?;
            let delegator = parse_object_id_text(body.get("delegator_actor_id"))?;
            if delegator != actor {
                return Err(Error::Unauthorized);
            }
            let delegation = delegations
                .iter()
                .find(|delegation| delegation.id == root_id)
                .ok_or(Error::InvalidLineage)?;
            if !fact_state::validate_delegation_chain_at(
                delegation,
                &delegations,
                &authorities,
                &ancestors,
                &ancestors,
                trusted_time,
            ) {
                return match fact_state::evaluate_validity(
                    delegation.validity.as_ref(),
                    trusted_time,
                ) {
                    fact_state::TemporalStatus::TimeUncertain => Err(Error::TimeUncertain),
                    _ => Err(Error::Unauthorized),
                };
            }
        }
        let descriptor = action_descriptor(root_type, root_object, &closure, ledger)?;
        let Some((capability, target, administration)) = descriptor else {
            return Ok(());
        };
        let action = fact_state::AuthorizedAction {
            actor,
            ledger,
            capability,
            target,
            ancestors,
            is_administration: administration,
        };
        match fact_state::authorize_with_delegations_at(
            &action,
            &authorities,
            &delegations,
            &action.ancestors,
            trusted_time,
        ) {
            fact_state::Authorization::Authorized => Ok(()),
            fact_state::Authorization::DependencyBlocked => Err(Error::MissingDependency),
            fact_state::Authorization::TimeUncertain => Err(Error::TimeUncertain),
            fact_state::Authorization::Unauthorized | fact_state::Authorization::Conflict => {
                Err(Error::Unauthorized)
            }
        }
    }

    fn validate_object(
        &self,
        cose_bytes: &[u8],
        staged: Option<&StagedObjects>,
    ) -> Result<ValidatedObject, Error> {
        let cose = fact_crypto::decode_sign1(cose_bytes)?;
        let canonical = fact_canonical::encode(&cose.payload)?;
        if canonical != cose.payload {
            return Err(Error::PayloadMismatch);
        }
        let object_type = fact_schema::validate_envelope(&canonical)?;
        let hash = fact_core::Hash::digest(&canonical);
        let value: serde_json::Value =
            serde_json::from_slice(&canonical).map_err(|_| Error::Metadata)?;
        let object = value.as_object().ok_or(Error::Metadata)?;
        let id = uuid_bytes(object, "id")?;
        let ledger = if object_type.ledger_scoped() {
            uuid_bytes(object, "ledger_id")?.to_vec()
        } else {
            Vec::new()
        };
        if !ledger.is_empty()
            && self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM ledger WHERE ledger_id=?)",
                [ledger.as_slice()],
                |row| row.get::<_, i64>(0),
            )? == 0
        {
            return Err(Error::MissingLedger);
        }
        let mut dependencies = Vec::new();
        let mut dependency_ids = std::collections::HashSet::new();
        for dependency in object
            .get("dependencies")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidDependency)?
        {
            let dependency = dependency.as_object().ok_or(Error::InvalidDependency)?;
            if dependency
                .keys()
                .any(|key| !["object_id", "content_hash", "role"].contains(&key.as_str()))
            {
                return Err(Error::InvalidDependency);
            }
            let dependency_id = uuid_bytes(dependency, "object_id")?.to_vec();
            if !dependency_ids.insert(dependency_id.clone()) {
                return Err(Error::InvalidDependency);
            }
            let content_hash = dependency
                .get("content_hash")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidDependency)?
                .parse::<Hash>()
                .map_err(|_| Error::InvalidDependency)?;
            let role = dependency
                .get("role")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidDependency)?;
            if !valid_dependency_role(role) {
                return Err(Error::InvalidDependency);
            }
            if dependency_id == id {
                return Err(Error::InvalidDependency);
            }
            let stored =
                if let Some(stored) = staged.and_then(|items| items.get(&dependency_id).cloned()) {
                    Some(stored)
                } else {
                    self.conn
                        .query_row(
                            "SELECT content_hash, ledger_id FROM protocol_object WHERE object_id=?",
                            [dependency_id.as_slice()],
                            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get(1)?)),
                        )
                        .optional()?
                };
            let Some((stored_hash, dependency_ledger)) = stored else {
                return Err(Error::MissingDependency);
            };
            if stored_hash != content_hash.as_bytes() {
                return Err(Error::DependencyHashMismatch);
            }
            if !ledger.is_empty()
                && dependency_ledger
                    .as_deref()
                    .is_some_and(|dependency_ledger| {
                        !dependency_ledger.is_empty() && dependency_ledger != ledger.as_slice()
                    })
                && object_type.as_str() != "proposition_provenance"
            {
                return Err(Error::InvalidDependency);
            }
            dependencies.push((dependency_id, content_hash, role.to_owned()));
        }
        let actor = uuid_bytes(object, "actor_id")?;
        let key = uuid_bytes(object, "signing_key_id")?;
        let required_key_purpose = if object_type.as_str() == "key_lifecycle"
            && object
                .get("body")
                .and_then(serde_json::Value::as_object)
                .and_then(|body| body.get("operation"))
                .and_then(serde_json::Value::as_str)
                == Some("recover")
        {
            "recovery"
        } else {
            "signing"
        };
        let schema = object
            .get("schema_version")
            .and_then(|v| v.as_str())
            .ok_or(Error::Metadata)?;
        let public_key: Vec<u8> = self
            .conn
            .query_row(
                "SELECT public_key FROM key_material WHERE key_id=?",
                [key.as_slice()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::MissingKey)?;
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| Error::InvalidPublicKey)?;
        if let Some(key_payload) = self
            .conn
            .query_row(
                "SELECT payload FROM protocol_key WHERE object_id=?",
                [key.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            let key_value: serde_json::Value =
                serde_json::from_slice(&key_payload).map_err(|_| Error::Metadata)?;
            let key_body = key_value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::Metadata)?;
            if key_body.get("purpose").and_then(serde_json::Value::as_str)
                != Some(required_key_purpose)
            {
                return Err(Error::InvalidSignature);
            }
            let encoded = key_body
                .get("public_key")
                .and_then(|value| value.get("bytes"))
                .and_then(serde_json::Value::as_str)
                .and_then(decode_b64url)
                .ok_or(Error::InvalidPublicKey)?;
            if encoded.as_slice() != public_key {
                return Err(Error::InvalidSignature);
            }
        }
        let actor_exists: i64 = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_actor WHERE object_id=?)",
            [actor.as_slice()],
            |row| row.get(0),
        )?;
        if actor_exists != 0
            && !matches!(object_type.as_str(), "actor" | "key" | "actor_key_binding")
        {
            let binding_count: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM protocol_actor_key_binding WHERE json_extract(payload,'$.body.actor_id')=? AND json_extract(payload,'$.body.key_id')=? AND json_extract(payload,'$.body.permitted_purpose')=?",
                params![uuid::Uuid::from_slice(&actor).map_err(|_| Error::InvalidUuid("actor_id"))?.to_string(), uuid::Uuid::from_slice(&key).map_err(|_| Error::InvalidUuid("signing_key_id"))?.to_string(), required_key_purpose],
                |row| row.get(0),
            )?;
            if binding_count == 0 {
                return Err(Error::InvalidSignature);
            }
            if object_type.as_str() != "key_lifecycle" {
                let created_at = object
                    .get("created_at")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::Metadata)?;
                let actor_text = uuid::Uuid::from_slice(&actor)
                    .map_err(|_| Error::InvalidUuid("actor_id"))?
                    .to_string();
                let key_text = uuid::Uuid::from_slice(&key)
                    .map_err(|_| Error::InvalidUuid("signing_key_id"))?
                    .to_string();
                let mut statement = self.conn.prepare(
                    "SELECT payload FROM protocol_object
                     WHERE object_type='key_lifecycle'
                       AND json_extract(payload,'$.body.affected_actor_id')=?
                       AND json_extract(payload,'$.body.old_key_id')=?
                       AND json_extract(payload,'$.body.operation') IN ('rotate','recover','revoke')",
                )?;
                let lifecycles = statement.query_map(params![actor_text, key_text], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?;
                for lifecycle in lifecycles {
                    let lifecycle = lifecycle?;
                    let value: serde_json::Value =
                        serde_json::from_slice(&lifecycle).map_err(|_| Error::Metadata)?;
                    let effective_at = value
                        .get("body")
                        .and_then(|body| body.get("effective_at"))
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::Metadata)?;
                    if created_at >= effective_at {
                        return Err(Error::Unauthorized);
                    }
                }
            }
        }
        let protected_ledger = if ledger.is_empty() {
            None
        } else {
            Some(
                ledger
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidUuid("ledger_id"))?,
            )
        };
        fact_crypto::validate_protocol_protected(
            &cose,
            public_key,
            object_type.as_str(),
            schema,
            protected_ledger,
        )?;
        fact_crypto::verify_sign1(public_key, &cose).map_err(|_| Error::InvalidSignature)?;
        Ok(ValidatedObject {
            id: id.to_vec(),
            ledger,
            object_type: object_type.as_str().to_owned(),
            schema: schema.to_owned(),
            actor: actor.to_vec(),
            key: key.to_vec(),
            canonical,
            hash,
            cose: cose_bytes.to_vec(),
            dependencies,
        })
    }

    /// Make public keys carried by key objects available to the same atomic
    /// import that verifies their signatures. A key object may be the first
    /// object seen by a fresh store, so requiring callers to pre-register its
    /// material would make exact identity-bundle import impossible.
    fn stage_key_material(&self, cose_bytes: &[u8]) -> Result<(), Error> {
        let cose = fact_crypto::decode_sign1(cose_bytes)?;
        let canonical = fact_canonical::encode(&cose.payload)?;
        if canonical != cose.payload {
            return Err(Error::PayloadMismatch);
        }
        let object_type = fact_schema::validate_envelope(&canonical)?;
        if object_type.as_str() != "key" {
            return Ok(());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&canonical).map_err(|_| Error::Metadata)?;
        let object = value.as_object().ok_or(Error::Metadata)?;
        let key_id = uuid_bytes(object, "id")?;
        let body = object
            .get("body")
            .and_then(serde_json::Value::as_object)
            .ok_or(Error::Metadata)?;
        let public_key = body
            .get("public_key")
            .and_then(|value| value.get("bytes"))
            .and_then(serde_json::Value::as_str)
            .and_then(decode_b64url)
            .ok_or(Error::InvalidPublicKey)?;
        if public_key.len() != 32 {
            return Err(Error::InvalidPublicKey);
        }
        let existing: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT public_key FROM key_material WHERE key_id=?",
                [key_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != public_key {
                return Err(Error::InvalidSignature);
            }
        } else {
            self.conn.execute(
                "INSERT INTO key_material(key_id,public_key) VALUES(?,?)",
                params![key_id.as_slice(), public_key],
            )?;
        }
        Ok(())
    }

    /// A genesis object carries the authoritative namespace needed to create
    /// the local ledger record. Stage that record inside the same transaction
    /// as the object import so a complete genesis bundle is self-bootstrapping
    /// while a failed validation leaves no partially visible ledger.
    fn stage_ledger_from_genesis(&self, cose_bytes: &[u8]) -> Result<(), Error> {
        let cose = fact_crypto::decode_sign1(cose_bytes)?;
        let canonical = fact_canonical::encode(&cose.payload)?;
        if canonical != cose.payload {
            return Err(Error::PayloadMismatch);
        }
        let object_type = fact_schema::validate_envelope(&canonical)?;
        if object_type.as_str() != "genesis" {
            return Ok(());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&canonical).map_err(|_| Error::Metadata)?;
        let object = value.as_object().ok_or(Error::Metadata)?;
        let ledger = uuid_bytes(object, "ledger_id")?;
        let namespace = object
            .get("body")
            .and_then(serde_json::Value::as_object)
            .and_then(|body| body.get("namespace"))
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Metadata)?;
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT namespace FROM ledger WHERE ledger_id=?",
                [ledger.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(existing) if existing != namespace => Err(Error::InvalidNamespace),
            Some(_) => Ok(()),
            None => self.create_ledger(&ledger, namespace),
        }
    }

    fn insert_validated_object(
        &self,
        object: &ValidatedObject,
        include_dependencies: bool,
    ) -> Result<(), Error> {
        self.insert_object(
            &object.id,
            &object.ledger,
            &object.object_type,
            &object.schema,
            &object.actor,
            &object.key,
            &object.canonical,
            &object.hash,
            &object.cose,
        )?;
        let table = format!("protocol_{}", object.object_type);
        self.conn.execute(
            &format!(
                "INSERT INTO {table}(object_id,ledger_id,content_hash,payload) VALUES(?,?,?,?)"
            ),
            params![
                object.id.as_slice(),
                object.ledger.as_slice(),
                object.hash.as_bytes(),
                object.canonical.as_slice()
            ],
        )?;
        self.note_search_bearing_object(object)?;
        if matches!(
            object.object_type.as_str(),
            "protocol_relationship" | "application_relationship"
        ) {
            let value: serde_json::Value =
                serde_json::from_slice(&object.canonical).map_err(|_| Error::Metadata)?;
            let body = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::Metadata)?;
            let source = uuid_bytes(body, "source_object_id")?;
            let targets = body
                .get("target_object_ids")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::Metadata)?;
            let target_bytes =
                fact_canonical::encode(&serde_json::to_vec(targets).map_err(|_| Error::Metadata)?)?;
            self.conn.execute(
                "INSERT INTO protocol_relationship(object_id,ledger_id,object_type,source_object_id,relationship,target_object_ids,payload) VALUES(?,?,?,?,?,?,?)",
                params![
                    object.id.as_slice(),
                    object.ledger.as_slice(),
                    object.object_type,
                    source.as_slice(),
                    body.get("relationship")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::Metadata)?,
                    target_bytes,
                    object.canonical.as_slice()
                ],
            )?;
        }
        if include_dependencies {
            self.insert_dependencies(object)?;
        }
        Ok(())
    }

    fn insert_dependencies(&self, object: &ValidatedObject) -> Result<(), Error> {
        for (dependency_id, dependency_hash, role) in &object.dependencies {
            self.conn.execute(
                "INSERT INTO object_dependency(object_id,dependency_id,content_hash,role) VALUES(?,?,?,?)",
                params![object.id.as_slice(), dependency_id, dependency_hash.as_bytes(), role],
            )?;
        }
        Ok(())
    }

    fn validate_cross_object_semantics(&self, object: &ValidatedObject) -> Result<(), Error> {
        let value: serde_json::Value =
            serde_json::from_slice(&object.canonical).map_err(|_| Error::Metadata)?;
        let body = value
            .get("body")
            .and_then(serde_json::Value::as_object)
            .ok_or(Error::Metadata)?;
        match object.object_type.as_str() {
            "actor_key_binding" => {
                let actor = parse_object_id_text(body.get("actor_id"))?;
                let key = parse_object_id_text(body.get("key_id"))?;
                if self.load_type(actor)? != "actor" || self.load_type(key)? != "key" {
                    return Err(Error::InvalidLineage);
                }
                let (_, key_body) = self.load_body(key)?;
                if key_body.get("purpose") != body.get("permitted_purpose") {
                    return Err(Error::InvalidLineage);
                }
                let predecessor = body
                    .get("predecessor_binding_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                    .map(|value| parse_object_id_text(Some(value)))
                    .transpose()?;
                if let Some(predecessor) = predecessor {
                    let (predecessor_type, predecessor_body) = self.load_body(predecessor)?;
                    if predecessor_type != "actor_key_binding"
                        || parse_object_id_text(predecessor_body.get("actor_id"))? != actor
                        || !self
                            .causal_closure_for_object(object)?
                            .contains(&predecessor)
                    {
                        return Err(Error::InvalidLineage);
                    }
                }
            }
            "identity_attestation" => {
                let subject_type = body
                    .get("subject_type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?;
                let subject = parse_object_id_text(body.get("subject_id"))?;
                let expected_type = match subject_type {
                    "actor" => "actor",
                    "key" => "key",
                    _ => return Err(Error::InvalidLineage),
                };
                if self.load_type(subject)? != expected_type
                    || self.load_type(object_id_from_bytes(&object.actor)?)? != "actor"
                {
                    return Err(Error::InvalidLineage);
                }
                parse_validity(body.get("validity"))?.ok_or(Error::InvalidLineage)?;
            }
            "authorization_grant" => {
                let granting = parse_object_id_text(body.get("granting_actor_id"))?;
                let receiving = parse_object_id_text(body.get("receiving_actor_id"))?;
                if self.load_type(granting)? != "actor"
                    || self.load_type(receiving)? != "actor"
                    || granting != object_id_from_bytes(&object.actor)?
                {
                    return Err(Error::InvalidLineage);
                }
                if let Some(predecessor) = body
                    .get("predecessor_grant_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                    .map(|value| parse_object_id_text(Some(value)))
                    .transpose()?
                {
                    let (predecessor_type, predecessor_body) = self.load_body(predecessor)?;
                    if predecessor_type != "authorization_grant"
                        || parse_object_id_text(predecessor_body.get("granting_actor_id"))?
                            != granting
                        || !self
                            .causal_closure_for_object(object)?
                            .contains(&predecessor)
                    {
                        return Err(Error::InvalidLineage);
                    }
                }
            }
            "authorization_revocation" => {
                let revoked = parse_object_id_text(body.get("revoked_grant_id"))?;
                if self.load_type(revoked)? != "authorization_grant"
                    || !self.causal_closure_for_object(object)?.contains(&revoked)
                {
                    return Err(Error::InvalidLineage);
                }
                self.validate_authorization_reference(object, body)?;
            }
            "delegation" => {
                let delegator = parse_object_id_text(body.get("delegator_actor_id"))?;
                let delegatee = parse_object_id_text(body.get("delegatee_actor_id"))?;
                if delegator == delegatee
                    || self.load_type(delegator)? != "actor"
                    || self.load_type(delegatee)? != "actor"
                    || delegator != object_id_from_bytes(&object.actor)?
                {
                    return Err(Error::InvalidLineage);
                }
            }
            "delegation_revocation" => {
                let revoked = parse_object_id_text(body.get("revoked_delegation_id"))?;
                if self.load_type(revoked)? != "delegation"
                    || !self.causal_closure_for_object(object)?.contains(&revoked)
                {
                    return Err(Error::InvalidLineage);
                }
                self.validate_authorization_reference(object, body)?;
            }
            "actor_lifecycle" => {
                let affected = parse_object_id_text(body.get("affected_actor_id"))?;
                if self.load_type(affected)? != "actor"
                    || body.get("operation").and_then(serde_json::Value::as_str) != Some("retire")
                {
                    return Err(Error::InvalidLineage);
                }
                self.validate_authorization_reference(object, body)?;
            }
            "key_lifecycle" => {
                let affected = parse_object_id_text(body.get("affected_actor_id"))?;
                let old_key = parse_object_id_text(body.get("old_key_id"))?;
                if self.load_type(affected)? != "actor" || self.load_type(old_key)? != "key" {
                    return Err(Error::InvalidLineage);
                }
                let (_, old_key_body) = self.load_body(old_key)?;
                if old_key_body
                    .get("purpose")
                    .and_then(serde_json::Value::as_str)
                    != Some("signing")
                {
                    return Err(Error::InvalidLineage);
                }
                let operation = body
                    .get("operation")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?;
                let new_key = body
                    .get("new_key_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                    .map(|value| parse_object_id_text(Some(value)))
                    .transpose()?;
                if matches!(operation, "rotate" | "recover") {
                    let new_key = new_key.ok_or(Error::InvalidLineage)?;
                    if self.load_type(new_key)? != "key" {
                        return Err(Error::InvalidLineage);
                    }
                    let (_, new_key_body) = self.load_body(new_key)?;
                    if new_key_body
                        .get("purpose")
                        .and_then(serde_json::Value::as_str)
                        != Some("signing")
                    {
                        return Err(Error::InvalidLineage);
                    }
                } else if operation == "revoke" {
                    if new_key.is_some() {
                        return Err(Error::InvalidLineage);
                    }
                } else {
                    return Err(Error::InvalidLineage);
                }
                let closure = self.causal_closure_for_object(object)?;
                if let Some(predecessor) = body
                    .get("predecessor_lifecycle_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                    .map(|value| parse_object_id_text(Some(value)))
                    .transpose()?
                {
                    let (predecessor_type, predecessor_body) = self.load_body(predecessor)?;
                    if predecessor_type != "key_lifecycle"
                        || parse_object_id_text(predecessor_body.get("affected_actor_id"))?
                            != affected
                        || !closure.contains(&predecessor)
                    {
                        return Err(Error::InvalidLineage);
                    }
                }
                if operation == "recover" {
                    let signing_key = object_id_from_bytes(&object.key)?;
                    let policy = closure.iter().filter_map(|id| {
                        (self.load_type(*id).ok().as_deref() == Some("recovery_policy"))
                            .then(|| self.load_body(*id).ok())
                            .flatten()
                            .and_then(|(_, policy)| {
                                (parse_object_id_text(policy.get("actor_id")).ok()
                                    == Some(affected)
                                    && parse_object_id_text(policy.get("recovery_key_id")).ok()
                                        == Some(signing_key))
                                .then_some(policy)
                            })
                    });
                    if policy.count() == 0 {
                        return Err(Error::InvalidLineage);
                    }
                }
                self.validate_authorization_reference(object, body)?;
            }
            "recovery_policy" => {
                let actor = parse_object_id_text(body.get("actor_id"))?;
                let recovery_key = parse_object_id_text(body.get("recovery_key_id"))?;
                if self.load_type(actor)? != "actor" || self.load_type(recovery_key)? != "key" {
                    return Err(Error::InvalidLineage);
                }
                let (_, key_body) = self.load_body(recovery_key)?;
                if key_body.get("purpose").and_then(serde_json::Value::as_str) != Some("recovery") {
                    return Err(Error::InvalidLineage);
                }
                let bound: i64 = self.conn.query_row(
                    "SELECT COUNT(*) FROM protocol_actor_key_binding WHERE json_extract(payload,'$.body.actor_id')=? AND json_extract(payload,'$.body.key_id')=? AND json_extract(payload,'$.body.permitted_purpose')='recovery'",
                    params![actor.to_string(), recovery_key.to_string()],
                    |row| row.get(0),
                )?;
                if bound == 0 {
                    return Err(Error::InvalidLineage);
                }
                let closure = self.causal_closure_for_object(object)?;
                let prior_ids: std::collections::HashSet<_> = closure
                    .iter()
                    .filter(|id| self.load_type(**id).ok().as_deref() == Some("recovery_policy"))
                    .filter_map(|id| {
                        self.load_body(*id).ok().and_then(|(_, prior)| {
                            (parse_object_id_text(prior.get("actor_id")).ok() == Some(actor))
                                .then_some(*id)
                        })
                    })
                    .collect();
                let referenced: std::collections::HashSet<_> = prior_ids
                    .iter()
                    .filter_map(|id| {
                        self.load_body(*id).ok().and_then(|(_, prior)| {
                            prior
                                .get("predecessor_policy_id")
                                .and_then(|value| (!value.is_null()).then_some(value))
                                .and_then(|value| parse_object_id_text(Some(value)).ok())
                        })
                    })
                    .collect();
                let tips: std::collections::HashSet<_> =
                    prior_ids.difference(&referenced).copied().collect();
                let predecessor = body
                    .get("predecessor_policy_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                    .map(|value| parse_object_id_text(Some(value)))
                    .transpose()?;
                match predecessor {
                    None if !tips.is_empty() => return Err(Error::InvalidLineage),
                    Some(id) if tips != [id].into_iter().collect() || !closure.contains(&id) => {
                        return Err(Error::InvalidLineage)
                    }
                    _ => {}
                }
            }
            "proposition" => {
                let proposition_id = parse_object_id_text(body.get("proposition_id"))?;
                let revision_id = parse_object_id_text(body.get("initial_revision_id"))?;
                let deliberation_id = parse_object_id_text(body.get("initial_deliberation_id"))?;
                let (revision_type, revision) = self.load_body(revision_id)?;
                let (deliberation_type, deliberation) = self.load_body(deliberation_id)?;
                if revision_type != "revision"
                    || deliberation_type != "deliberation"
                    || parse_object_id_text(revision.get("proposition_id"))? != proposition_id
                    || parse_object_id_text(deliberation.get("proposition_id"))? != proposition_id
                    || !revision
                        .get("parent_revision_id")
                        .is_some_and(serde_json::Value::is_null)
                    || parse_object_id_text(body.get("initial_revision_id"))?
                        != parse_object_id_text(deliberation.get("revision_id"))?
                {
                    return Err(Error::InvalidLineage);
                }
            }
            "namespace_assertion" => {
                let authority = parse_object_id_text(body.get("naming_authority_actor_id"))?;
                let target = parse_object_id_text(body.get("target_id"))?;
                if self.load_type(authority)? != "actor" {
                    return Err(Error::InvalidLineage);
                }
                let target_type = body
                    .get("target_type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?;
                if target_type == "ledger" {
                    if target != object_id_from_bytes(&object.ledger)? {
                        return Err(Error::InvalidLineage);
                    }
                } else if self.load_type(target)? != target_type {
                    return Err(Error::InvalidLineage);
                }
                let predecessors = body
                    .get("supersedes")
                    .and_then(|value| (!value.is_null()).then_some(value))
                    .map(|value| value.as_array().ok_or(Error::InvalidLineage))
                    .transpose()?
                    .map_or(&[] as &[serde_json::Value], |value| value.as_slice());
                for predecessor in predecessors {
                    let predecessor = parse_object_id_text(Some(predecessor))?;
                    let (predecessor_type, predecessor_body) = self.load_body(predecessor)?;
                    if predecessor_type != "namespace_assertion"
                        || predecessor_body.get("namespace") != body.get("namespace")
                        || predecessor_body.get("target_type") != body.get("target_type")
                        || predecessor_body.get("target_id") != body.get("target_id")
                        || !self
                            .causal_closure_for_object(object)?
                            .contains(&predecessor)
                    {
                        return Err(Error::InvalidLineage);
                    }
                }
            }
            "proposition_provenance" => {
                let proposition = parse_object_id_text(body.get("proposition_id"))?;
                let source_ledger = parse_object_id_text(body.get("source_ledger_id"))?;
                let source_proposition = parse_object_id_text(body.get("source_proposition_id"))?;
                let source_revision = parse_object_id_text(body.get("source_revision_id"))?;
                let destination_ledger = object_id_from_bytes(&object.ledger)?;
                if self.load_type(proposition)? != "proposition"
                    || source_ledger == destination_ledger
                    || source_proposition == proposition
                    || self.load_type(source_proposition)? != "proposition"
                    || self.load_type(source_revision)? != "revision"
                {
                    return Err(Error::InvalidLineage);
                }
                let (_, source_revision_body) = self.load_body(source_revision)?;
                if parse_object_id_text(source_revision_body.get("proposition_id"))?
                    != source_proposition
                    || body
                        .get("source_content_hash")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| value.parse::<Hash>().ok())
                        .is_none()
                {
                    return Err(Error::InvalidLineage);
                }
                if body.get("copy_mode").and_then(serde_json::Value::as_str) == Some("snapshot")
                    && body
                        .get("source_object_bundle")
                        .and_then(serde_json::Value::as_str)
                        .and_then(decode_b64url)
                        .is_none()
                {
                    return Err(Error::InvalidLineage);
                }
            }
            "proposition_lifecycle" => {
                let proposition = parse_object_id_text(body.get("proposition_id"))?;
                if self.load_type(proposition)? != "proposition" {
                    return Err(Error::InvalidLineage);
                }
                let dimension = body
                    .get("dimension")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?;
                let operation = body
                    .get("operation")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?;
                let valid_operation = match dimension {
                    "withdrawal" => matches!(operation, "withdraw" | "restore"),
                    "archival" => matches!(operation, "archive" | "unarchive"),
                    _ => false,
                };
                if !valid_operation {
                    return Err(Error::InvalidLineage);
                }
                let closure = self.causal_closure_for_object(object)?;
                let prior_ids: std::collections::HashSet<_> = closure
                    .iter()
                    .filter(|id| {
                        self.load_type(**id).ok().as_deref() == Some("proposition_lifecycle")
                    })
                    .filter_map(|id| {
                        self.load_body(*id).ok().and_then(|(_, prior)| {
                            (parse_object_id_text(prior.get("proposition_id")).ok()
                                == Some(proposition)
                                && prior.get("dimension").and_then(serde_json::Value::as_str)
                                    == Some(dimension))
                            .then_some(*id)
                        })
                    })
                    .collect();
                let referenced: std::collections::HashSet<_> = prior_ids
                    .iter()
                    .flat_map(|id| {
                        self.load_body(*id)
                            .ok()
                            .and_then(|(_, prior)| prior.get("predecessor_ids").cloned())
                            .and_then(|value| value.as_array().cloned())
                            .unwrap_or_default()
                    })
                    .filter_map(|id| parse_object_id_text(Some(&id)).ok())
                    .collect();
                let tips: std::collections::HashSet<_> =
                    prior_ids.difference(&referenced).copied().collect();
                let predecessors: std::collections::HashSet<_> = body
                    .get("predecessor_ids")
                    .and_then(serde_json::Value::as_array)
                    .ok_or(Error::InvalidLineage)?
                    .iter()
                    .map(|id| parse_object_id_text(Some(id)))
                    .collect::<Result<_, _>>()?;
                if (!prior_ids.is_empty() && predecessors.is_empty())
                    || predecessors != tips
                    || predecessors.iter().any(|id| !closure.contains(id))
                {
                    return Err(Error::InvalidLineage);
                }
                for predecessor in &predecessors {
                    let (prior_type, prior) = self.load_body(*predecessor)?;
                    if prior_type != "proposition_lifecycle"
                        || parse_object_id_text(prior.get("proposition_id"))? != proposition
                        || prior.get("dimension").and_then(serde_json::Value::as_str)
                            != Some(dimension)
                    {
                        return Err(Error::InvalidLineage);
                    }
                }
                self.validate_authorization_reference(object, body)?;
            }
            "protocol_relationship" => {
                let source_id = parse_object_id_text(body.get("source_object_id"))?;
                let source_type = self.load_type(source_id)?;
                let relationship = body
                    .get("relationship")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?;
                if relationship != "protocol:references" {
                    return Err(Error::InvalidLineage);
                }
                let targets = body
                    .get("target_object_ids")
                    .and_then(serde_json::Value::as_array)
                    .ok_or(Error::InvalidLineage)?;
                let target_ids = targets
                    .iter()
                    .map(|target| parse_object_id_text(Some(target)))
                    .collect::<Result<Vec<_>, _>>()?;
                self.validate_relationship_edge(
                    source_id,
                    &source_type,
                    relationship,
                    &target_ids,
                    Some(&self.load_ledger(source_id)?),
                )?;
            }
            "revision" => {
                self.validate_embedded_relationships(
                    object.id.as_slice(),
                    "revision",
                    body,
                    &object.ledger,
                )?;
                let proposition_id = parse_object_id_text(body.get("proposition_id"))?;
                let (_, proposition) = self.load_body(proposition_id)?;
                let purpose = proposition
                    .get("purpose")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?;
                let has_manifest = body
                    .get("reconciliation_manifest")
                    .is_some_and(|manifest| !manifest.is_null());
                if (purpose == "reconciliation") != has_manifest {
                    return Err(Error::InvalidLineage);
                }
                if let Some(parent) = body
                    .get("parent_revision_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                {
                    let parent_id = parse_object_id_text(Some(parent))?;
                    let (parent_type, parent_body) = self.load_body(parent_id)?;
                    if parent_type != "revision"
                        || parse_object_id_text(parent_body.get("proposition_id"))?
                            != proposition_id
                    {
                        return Err(Error::InvalidLineage);
                    }
                    let current_hash = body
                        .get("content")
                        .and_then(|content| content.get("hash"))
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::InvalidLineage)?;
                    let parent_hash = parent_body
                        .get("content")
                        .and_then(|content| content.get("hash"))
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::InvalidLineage)?;
                    if current_hash == parent_hash {
                        return Err(Error::InvalidLineage);
                    }
                }
            }
            "deliberation" => {
                let proposition_id = parse_object_id_text(body.get("proposition_id"))?;
                let revision_id = parse_object_id_text(body.get("revision_id"))?;
                let (_, proposition) = self.load_body(proposition_id)?;
                let (revision_type, revision) = self.load_body(revision_id)?;
                if revision_type != "revision"
                    || parse_object_id_text(revision.get("proposition_id"))? != proposition_id
                {
                    return Err(Error::InvalidLineage);
                }
                let purpose = proposition
                    .get("purpose")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?;
                let has_roster = body
                    .get("roster_governance")
                    .is_some_and(|roster| !roster.is_null());
                if (purpose == "reconciliation") != has_roster {
                    return Err(Error::InvalidLineage);
                }
                if purpose == "reconciliation" {
                    let manifest = revision
                        .get("reconciliation_manifest")
                        .and_then(|manifest| (!manifest.is_null()).then_some(manifest))
                        .and_then(serde_json::Value::as_object)
                        .ok_or(Error::InvalidLineage)?;
                    let mut manifest_ids = manifest
                        .get("conflicts")
                        .and_then(serde_json::Value::as_array)
                        .ok_or(Error::InvalidLineage)?
                        .iter()
                        .map(|conflict| {
                            parse_object_id_text(
                                conflict
                                    .as_object()
                                    .and_then(|conflict| conflict.get("deliberation_id")),
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    manifest_ids.sort();
                    manifest_ids.dedup();
                    let roster_ids = body
                        .get("roster_governance")
                        .and_then(serde_json::Value::as_object)
                        .and_then(|roster| roster.get("source_deliberation_ids"))
                        .and_then(serde_json::Value::as_array)
                        .ok_or(Error::InvalidLineage)?
                        .iter()
                        .map(|id| parse_object_id_text(Some(id)))
                        .collect::<Result<Vec<_>, _>>()?;
                    if roster_ids != manifest_ids {
                        return Err(Error::InvalidLineage);
                    }
                    self.validate_reconciliation_roster(object, body, manifest, &manifest_ids)?;
                }
            }
            "standing_participant_change" => {
                let proposition_id = parse_object_id_text(body.get("proposition_id"))?;
                let participant = parse_object_id_text(body.get("participant_actor_id"))?;
                let changed_by = parse_object_id_text(body.get("changed_by_actor_id"))?;
                let envelope_actor = object_id_from_bytes(&object.actor)?;
                if self.load_type(proposition_id)? != "proposition"
                    || self.load_type(participant)? != "actor"
                    || self.load_type(changed_by)? != "actor"
                    || changed_by != envelope_actor
                {
                    return Err(Error::InvalidLineage);
                }
                let operation = body
                    .get("operation")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?;
                let predecessor = body
                    .get("predecessor_change_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                    .map(|value| parse_object_id_text(Some(value)))
                    .transpose()?;
                let closure = self.causal_closure_for_object(object)?;
                let mut changes = Vec::new();
                for id in &closure {
                    if self.load_type(*id).ok().as_deref() != Some("standing_participant_change") {
                        continue;
                    }
                    let (_, prior) = self.load_body(*id)?;
                    if parse_object_id_text(prior.get("proposition_id"))? == proposition_id
                        && parse_object_id_text(prior.get("participant_actor_id"))? == participant
                    {
                        changes.push((*id, prior));
                    }
                }
                let referenced: std::collections::HashSet<_> = changes
                    .iter()
                    .filter_map(|(_, prior)| {
                        prior
                            .get("predecessor_change_id")
                            .and_then(|value| (!value.is_null()).then_some(value))
                            .and_then(|value| parse_object_id_text(Some(value)).ok())
                    })
                    .collect();
                let tips: Vec<_> = changes
                    .iter()
                    .map(|(id, _)| *id)
                    .filter(|id| !referenced.contains(id))
                    .collect();
                match predecessor {
                    None if !changes.is_empty() => return Err(Error::InvalidLineage),
                    None => {}
                    Some(predecessor)
                        if tips.len() != 1
                            || tips[0] != predecessor
                            || !closure.contains(&predecessor) =>
                    {
                        return Err(Error::InvalidLineage);
                    }
                    Some(_) => {}
                }
                let currently_joined = predecessor
                    .and_then(|id| changes.iter().find(|(change_id, _)| *change_id == id))
                    .and_then(|(_, prior)| prior.get("operation"))
                    .and_then(serde_json::Value::as_str)
                    == Some("join");
                match (operation, currently_joined) {
                    ("join", true) | ("leave", false) => return Err(Error::InvalidLineage),
                    ("join", false) | ("leave", true) => {}
                    _ => return Err(Error::InvalidLineage),
                }
                if changed_by == participant
                    && !body
                        .get("authorization_ref")
                        .is_some_and(serde_json::Value::is_null)
                {
                    return Err(Error::InvalidLineage);
                }
                if changed_by != participant
                    && body
                        .get("authorization_ref")
                        .is_some_and(serde_json::Value::is_null)
                {
                    return Err(Error::Unauthorized);
                }
                if let Some(authorization_ref) = body
                    .get("authorization_ref")
                    .and_then(|value| (!value.is_null()).then_some(value))
                    .map(|value| parse_object_id_text(Some(value)))
                    .transpose()?
                {
                    if !closure.contains(&authorization_ref) {
                        return Err(Error::InvalidLineage);
                    }
                    let authorization_type = self.load_type(authorization_ref)?;
                    if !matches!(
                        authorization_type.as_str(),
                        "authorization_grant" | "delegation"
                    ) {
                        return Err(Error::InvalidLineage);
                    }
                }
            }
            "settlement" => {
                let deliberation_id = parse_object_id_text(body.get("deliberation_id"))?;
                let revision_id = parse_object_id_text(body.get("revision_id"))?;
                let (deliberation_type, deliberation) = self.load_body(deliberation_id)?;
                if deliberation_type != "deliberation"
                    || parse_object_id_text(deliberation.get("revision_id"))? != revision_id
                {
                    return Err(Error::InvalidLineage);
                }
                self.validate_settlement_witness_object(object, body)?;
            }
            "decision" => {
                let deliberation_id = parse_object_id_text(body.get("deliberation_id"))?;
                let participant = parse_object_id_text(body.get("participant_actor_id"))?;
                let (deliberation_type, deliberation) = self.load_body(deliberation_id)?;
                if deliberation_type != "deliberation" {
                    return Err(Error::InvalidLineage);
                }
                let active =
                    self.active_participants_at_object(deliberation_id, &deliberation, object)?;
                if !active.contains(&participant) {
                    return Err(Error::InvalidLineage);
                }
                if object_id_from_bytes(&object.actor)? != participant {
                    return Err(Error::InvalidLineage);
                }
                let closure = self.causal_closure_for_object(object)?;
                if self.closure_contains_settlement_for_deliberation(&closure, deliberation_id)? {
                    return Err(Error::InvalidLineage);
                }
                let supersedes = body
                    .get("supersedes_decision_ids")
                    .and_then(serde_json::Value::as_array)
                    .ok_or(Error::InvalidLineage)?;
                let participant_decisions = closure
                    .iter()
                    .filter(|id| self.load_type(**id).ok().as_deref() == Some("decision"))
                    .filter_map(|id| {
                        let decision_body = self.load_body(*id).ok()?.1;
                        (parse_object_id_text(decision_body.get("deliberation_id")).ok()
                            == Some(deliberation_id)
                            && parse_object_id_text(decision_body.get("participant_actor_id")).ok()
                                == Some(participant))
                        .then_some(*id)
                    })
                    .collect::<std::collections::HashSet<_>>();
                let referenced = participant_decisions
                    .iter()
                    .filter_map(|id| self.load_body(*id).ok())
                    .flat_map(|(_, decision_body)| {
                        decision_body
                            .get("supersedes_decision_ids")
                            .and_then(serde_json::Value::as_array)
                            .cloned()
                            .unwrap_or_default()
                    })
                    .map(|id| parse_object_id_text(Some(&id)))
                    .collect::<Result<std::collections::HashSet<_>, _>>()?;
                let tips = participant_decisions
                    .difference(&referenced)
                    .copied()
                    .collect::<std::collections::HashSet<_>>();
                let superseded = supersedes
                    .iter()
                    .map(|id| parse_object_id_text(Some(id)))
                    .collect::<Result<std::collections::HashSet<_>, _>>()?;
                if superseded != tips || superseded.iter().any(|id| !closure.contains(id)) {
                    return Err(Error::InvalidLineage);
                }
            }
            "deliberation_participant_change" => {
                let deliberation_id = parse_object_id_text(body.get("deliberation_id"))?;
                let participant = parse_object_id_text(body.get("participant_actor_id"))?;
                let changed_by = parse_object_id_text(body.get("changed_by_actor_id"))?;
                let (deliberation_type, deliberation) = self.load_body(deliberation_id)?;
                if deliberation_type != "deliberation" {
                    return Err(Error::InvalidLineage);
                }
                let closure = self.causal_closure_for_object(object)?;
                if changed_by != object_id_from_bytes(&object.actor)?
                    || self.load_type(changed_by)? != "actor"
                    || self.load_type(participant)? != "actor"
                {
                    return Err(Error::InvalidLineage);
                }
                let authorization_ref = body
                    .get("authorization_ref")
                    .and_then(|value| (!value.is_null()).then_some(value))
                    .map(|value| parse_object_id_text(Some(value)))
                    .transpose()?;
                if changed_by == participant {
                    if authorization_ref.is_some() {
                        return Err(Error::InvalidLineage);
                    }
                } else {
                    let authorization_ref = authorization_ref.ok_or(Error::Unauthorized)?;
                    if !closure.contains(&authorization_ref)
                        || !matches!(
                            self.load_type(authorization_ref)?.as_str(),
                            "authorization_grant" | "delegation"
                        )
                    {
                        return Err(Error::InvalidLineage);
                    }
                }
                if self.closure_contains_settlement_for_deliberation(&closure, deliberation_id)? {
                    return Err(Error::InvalidLineage);
                }
                let active =
                    self.active_participants_at_object(deliberation_id, &deliberation, object)?;
                if body.get("operation").and_then(serde_json::Value::as_str) == Some("join") {
                    let join_policy = deliberation
                        .get("join_policy")
                        .and_then(serde_json::Value::as_object)
                        .ok_or(Error::InvalidLineage)?;
                    let mode = join_policy
                        .get("mode")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::InvalidLineage)?;
                    let invitation_id = body
                        .get("invitation_id")
                        .and_then(|value| (!value.is_null()).then_some(value))
                        .map(|value| parse_object_id_text(Some(value)))
                        .transpose()?;
                    if mode == "closed" {
                        return Err(Error::InvalidLineage);
                    }
                    if mode == "invitation" && invitation_id.is_none() {
                        return Err(Error::InvalidLineage);
                    }
                    if let Some(invitation_id) = invitation_id {
                        let (invitation_type, invitation) = self.load_body(invitation_id)?;
                        let invitation_scope_matches = if let Some(target_deliberation) = invitation
                            .get("deliberation_id")
                            .and_then(|value| (!value.is_null()).then_some(value))
                        {
                            parse_object_id_text(Some(target_deliberation))? == deliberation_id
                        } else if let Some(target_proposition) = invitation
                            .get("proposition_id")
                            .and_then(|value| (!value.is_null()).then_some(value))
                        {
                            parse_object_id_text(Some(target_proposition))?
                                == parse_object_id_text(deliberation.get("proposition_id"))?
                        } else {
                            false
                        };
                        if invitation_type != "participant_invitation"
                            || parse_object_id_text(invitation.get("invited_actor_id"))?
                                != participant
                            || !invitation_scope_matches
                        {
                            return Err(Error::InvalidLineage);
                        }
                        let closure = self.causal_closure_for_object(object)?;
                        if closure.iter().any(|id| {
                            self.load_type(*id).ok().as_deref() == Some("invitation_lifecycle")
                                && self.load_body(*id).ok().and_then(|(_, body)| {
                                    parse_object_id_text(body.get("invitation_id")).ok()
                                }) == Some(invitation_id)
                        }) {
                            return Err(Error::InvalidLineage);
                        }
                        if closure.iter().any(|id| {
                            self.load_type(*id).ok().as_deref()
                                == Some("deliberation_participant_change")
                                && self.load_body(*id).ok().and_then(|(_, body)| {
                                    parse_object_id_text(body.get("invitation_id")).ok()
                                }) == Some(invitation_id)
                        }) {
                            return Err(Error::InvalidLineage);
                        }
                    }
                    if mode == "attested" {
                        self.validate_attested_admission(object, body, participant, join_policy)?;
                    }
                    if body
                        .get("authorization_ref")
                        .is_some_and(|value| value.is_null())
                        && mode != "open"
                        && mode != "attested"
                    {
                        return Err(Error::Unauthorized);
                    }
                    if body
                        .get("authorization_ref")
                        .is_some_and(|value| value.is_null())
                        && object_id_from_bytes(&object.actor)? != participant
                    {
                        return Err(Error::Unauthorized);
                    }
                }
                match body.get("operation").and_then(serde_json::Value::as_str) {
                    Some("join") if active.contains(&participant) => {
                        return Err(Error::InvalidLineage);
                    }
                    Some("leave") if !active.contains(&participant) => {
                        return Err(Error::InvalidLineage);
                    }
                    Some("leave")
                        if closure.iter().any(|id| {
                            self.load_type(*id).ok().as_deref() == Some("decision")
                                && self.load_body(*id).ok().and_then(|(_, body)| {
                                    parse_object_id_text(body.get("deliberation_id")).ok()
                                }) == Some(deliberation_id)
                                && self.load_body(*id).ok().and_then(|(_, body)| {
                                    parse_object_id_text(body.get("participant_actor_id")).ok()
                                }) == Some(participant)
                        }) =>
                    {
                        return Err(Error::InvalidLineage);
                    }
                    Some("join") | Some("leave") => {}
                    _ => return Err(Error::InvalidLineage),
                }
            }
            "participant_invitation" => {
                let invitation_id = parse_object_id_text(body.get("invitation_id"))?;
                let inviting = parse_object_id_text(body.get("inviting_actor_id"))?;
                let invited = parse_object_id_text(body.get("invited_actor_id"))?;
                if self.load_type(inviting)? != "actor"
                    || self.load_type(invited)? != "actor"
                    || inviting != object_id_from_bytes(&object.actor)?
                {
                    return Err(Error::InvalidLineage);
                }
                parse_validity(body.get("validity"))?;
                if let Some(proposition) = body
                    .get("proposition_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                {
                    let proposition_id = parse_object_id_text(Some(proposition))?;
                    if self.load_type(proposition_id)? != "proposition" {
                        return Err(Error::InvalidLineage);
                    }
                }
                if let Some(deliberation) = body
                    .get("deliberation_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                {
                    let deliberation_id = parse_object_id_text(Some(deliberation))?;
                    if self.load_type(deliberation_id)? != "deliberation" {
                        return Err(Error::InvalidLineage);
                    }
                }
                if let Some(predecessor) = body
                    .get("predecessor_invitation_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                {
                    let predecessor_id = parse_object_id_text(Some(predecessor))?;
                    let (predecessor_type, predecessor_body) = self.load_body(predecessor_id)?;
                    if predecessor_type != "participant_invitation"
                        || (predecessor_body.get("proposition_id") != body.get("proposition_id"))
                        || (predecessor_body.get("deliberation_id") != body.get("deliberation_id"))
                        || predecessor_body.get("invited_actor_id") != body.get("invited_actor_id")
                        || predecessor_body.get("inviting_actor_id")
                            != body.get("inviting_actor_id")
                    {
                        return Err(Error::InvalidLineage);
                    }
                    if !self
                        .causal_closure_for_object(object)?
                        .contains(&predecessor_id)
                    {
                        return Err(Error::InvalidLineage);
                    }
                }
                if invitation_id != object_id_from_bytes(&object.id)? {
                    return Err(Error::InvalidLineage);
                }
            }
            "invitation_lifecycle" => {
                let invitation_id = parse_object_id_text(body.get("invitation_id"))?;
                if self.load_type(invitation_id)? != "participant_invitation" {
                    return Err(Error::InvalidLineage);
                }
                if !self
                    .causal_closure_for_object(object)?
                    .contains(&invitation_id)
                {
                    return Err(Error::InvalidLineage);
                }
                self.validate_invitation_lifecycle(object, invitation_id, body)?;
            }
            "deliberation_comment" => {
                let deliberation_id = parse_object_id_text(body.get("deliberation_id"))?;
                let (deliberation_type, deliberation) = self.load_body(deliberation_id)?;
                if deliberation_type != "deliberation" {
                    return Err(Error::InvalidLineage);
                }
                if !self
                    .active_participants_at_object(deliberation_id, &deliberation, object)?
                    .contains(&object_id_from_bytes(&object.actor)?)
                {
                    return Err(Error::Unauthorized);
                }
                let closure = self.causal_closure_for_object(object)?;
                let has_settlement =
                    self.closure_contains_settlement_for_deliberation(&closure, deliberation_id)?;
                let phase = body
                    .get("comment_phase")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?;
                let closed = deliberation
                    .get("comments_closed_on_settlement")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(Error::InvalidLineage)?;
                if (phase == "post-settlement") != has_settlement
                    || (phase == "post-settlement" && closed)
                {
                    return Err(Error::InvalidLineage);
                }
            }
            "application_relationship"
                if body.get("shared").and_then(serde_json::Value::as_bool) == Some(false) =>
            {
                return Err(Error::PolicyRejected);
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_embedded_relationships(
        &self,
        source_id: &[u8],
        source_type: &str,
        body: &serde_json::Map<String, serde_json::Value>,
        source_ledger: &[u8],
    ) -> Result<(), Error> {
        let Some(relationships) = body
            .get("relationships")
            .and_then(serde_json::Value::as_array)
        else {
            return Ok(());
        };
        let source_id: [u8; 16] = source_id
            .try_into()
            .map_err(|_| Error::InvalidUuid("source_object_id"))?;
        let source_id =
            fact_core::ObjectId::from_str(&uuid::Uuid::from_bytes(source_id).to_string())
                .map_err(|_| Error::InvalidUuid("source_object_id"))?;
        for relationship in relationships {
            let relationship = relationship.as_object().ok_or(Error::InvalidLineage)?;
            let name = relationship
                .get("relationship")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidLineage)?;
            let targets = relationship
                .get("targets")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::InvalidLineage)?;
            let target_ids = targets
                .iter()
                .map(|target| parse_object_id_text(Some(target)))
                .collect::<Result<Vec<_>, _>>()?;
            self.validate_relationship_edge(
                source_id,
                source_type,
                name,
                &target_ids,
                Some(source_ledger),
            )?;
        }
        Ok(())
    }

    fn validate_relationship_edge(
        &self,
        source_id: fact_core::ObjectId,
        source_type: &str,
        relationship: &str,
        targets: &[fact_core::ObjectId],
        source_ledger: Option<&[u8]>,
    ) -> Result<(), Error> {
        let (allowed_sources, allowed_targets, minimum, maximum) =
            relationship_rule(relationship).ok_or(Error::InvalidLineage)?;
        if !allowed_sources.contains(&source_type) && !allowed_sources.contains(&"any")
            || targets.len() < minimum
            || maximum.is_some_and(|maximum| targets.len() > maximum)
        {
            return Err(Error::InvalidLineage);
        }
        let mut seen = std::collections::HashSet::new();
        for target_id in targets {
            if *target_id == source_id || !seen.insert(*target_id) {
                return Err(Error::InvalidLineage);
            }
            let target_type = self.load_type(*target_id)?;
            if !allowed_targets.contains(&target_type.as_str()) && !allowed_targets.contains(&"any")
            {
                return Err(Error::InvalidLineage);
            }
            let target_ledger = self.load_ledger(*target_id)?;
            let source_ledger = source_ledger
                .map(ToOwned::to_owned)
                .unwrap_or(self.load_ledger(source_id)?);
            if target_ledger != source_ledger && relationship != "protocol:references" {
                return Err(Error::InvalidLineage);
            }
        }
        Ok(())
    }

    fn load_type(&self, id: fact_core::ObjectId) -> Result<String, Error> {
        self.conn
            .query_row(
                "SELECT object_type FROM protocol_object WHERE object_id=?",
                [id.uuid().as_bytes()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::MissingDependency)
    }

    fn load_ledger(&self, id: fact_core::ObjectId) -> Result<Vec<u8>, Error> {
        self.conn
            .query_row(
                "SELECT COALESCE(ledger_id, X'') FROM protocol_object WHERE object_id=?",
                [id.uuid().as_bytes()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::MissingDependency)
    }

    fn validate_settlement_witness_object(
        &self,
        object: &ValidatedObject,
        body: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), Error> {
        self.validate_settlement_witness(body, &self.causal_closure_for_object(object)?)
    }

    fn validate_settlement_witness_by_id(
        &self,
        settlement_id: fact_core::ObjectId,
        body: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), Error> {
        self.validate_settlement_witness(body, &self.causal_closure_ids(settlement_id)?)
    }

    fn validate_settlement_witness(
        &self,
        body: &serde_json::Map<String, serde_json::Value>,
        closure: &std::collections::HashSet<fact_core::ObjectId>,
    ) -> Result<(), Error> {
        let deliberation_id = parse_object_id_text(body.get("deliberation_id"))?;
        let revision_id = parse_object_id_text(body.get("revision_id"))?;
        let (deliberation_type, deliberation) = self.load_body(deliberation_id)?;
        if deliberation_type != "deliberation"
            || parse_object_id_text(deliberation.get("revision_id"))? != revision_id
        {
            return Err(Error::InvalidLineage);
        }
        if body.get("decision_rule") != deliberation.get("decision_rule") {
            return Err(Error::InvalidLineage);
        }
        let initial = deliberation
            .get("initial_participants")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?
            .iter()
            .map(|participant| {
                parse_object_id_text(
                    participant
                        .as_object()
                        .and_then(|participant| participant.get("actor_id")),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut changes = Vec::new();
        let mut decisions = Vec::new();
        for id in closure {
            match self.load_type(*id).ok().as_deref() {
                Some("deliberation_participant_change") => {
                    let (_, change) = self.load_body(*id)?;
                    if parse_object_id_text(change.get("deliberation_id"))? != deliberation_id {
                        continue;
                    }
                    let operation =
                        match change.get("operation").and_then(serde_json::Value::as_str) {
                            Some("join") => fact_state::ParticipantOperation::Join,
                            Some("leave") => fact_state::ParticipantOperation::Leave,
                            _ => return Err(Error::InvalidLineage),
                        };
                    let predecessor = change
                        .get("predecessor_change_id")
                        .and_then(|value| (!value.is_null()).then_some(value))
                        .map(|value| parse_object_id_text(Some(value)))
                        .transpose()?;
                    changes.push(fact_state::ParticipantChange {
                        id: *id,
                        actor: parse_object_id_text(change.get("participant_actor_id"))?,
                        operation,
                        predecessors: predecessor.into_iter().collect(),
                    });
                }
                Some("decision") => {
                    let (_, decision) = self.load_body(*id)?;
                    if parse_object_id_text(decision.get("deliberation_id"))? != deliberation_id {
                        continue;
                    }
                    let value = match decision.get("value").and_then(serde_json::Value::as_str) {
                        Some("accepted") => fact_state::DecisionValue::Accepted,
                        Some("rejected") => fact_state::DecisionValue::Rejected,
                        _ => return Err(Error::InvalidLineage),
                    };
                    let supersedes = decision
                        .get("supersedes_decision_ids")
                        .and_then(serde_json::Value::as_array)
                        .ok_or(Error::InvalidLineage)?
                        .iter()
                        .map(|id| parse_object_id_text(Some(id)))
                        .collect::<Result<Vec<_>, _>>()?;
                    decisions.push(fact_state::Decision {
                        id: *id,
                        participant: parse_object_id_text(decision.get("participant_actor_id"))?,
                        revision: revision_id,
                        value,
                        supersedes,
                    });
                }
                _ => {}
            }
        }
        let active = fact_state::replay_participants(&initial, &changes)
            .map_err(|_| Error::InvalidLineage)?
            .active;
        let refs = body
            .get("decision_refs")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?
            .iter()
            .map(|reference| {
                let reference = reference.as_object().ok_or(Error::InvalidLineage)?;
                Ok(fact_state::SettlementDecisionRef {
                    decision_id: parse_object_id_text(reference.get("decision_id"))?,
                    participant: parse_object_id_text(reference.get("participant_actor_id"))?,
                    content_hash: reference
                        .get("content_hash")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::InvalidLineage)?
                        .parse::<Hash>()
                        .map_err(|_| Error::InvalidLineage)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        for reference in &refs {
            if !closure.contains(&reference.decision_id) {
                return Err(Error::InvalidLineage);
            }
            let stored_hash: Vec<u8> = self
                .conn
                .query_row(
                    "SELECT content_hash FROM protocol_object WHERE object_id=?",
                    [reference.decision_id.uuid().as_bytes()],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(Error::MissingDependency)?;
            if stored_hash != reference.content_hash.as_bytes() {
                return Err(Error::DependencyHashMismatch);
            }
        }
        let settlement_point = body
            .get("causal_settlement_point")
            .and_then(serde_json::Value::as_object)
            .and_then(|point| point.get("object_id"))
            .map(|point| parse_object_id_text(Some(point)))
            .transpose()?
            .ok_or(Error::InvalidLineage)?;
        if !closure.contains(&settlement_point) {
            return Err(Error::InvalidLineage);
        }
        let outcome = match body.get("outcome").and_then(serde_json::Value::as_str) {
            Some("accepted") => fact_state::SettlementOutcome::Accepted,
            Some("rejected") => fact_state::SettlementOutcome::Rejected,
            _ => return Err(Error::InvalidLineage),
        };
        let evaluation = fact_state::validate_settlement_witness(
            &active.iter().copied().collect::<Vec<_>>(),
            revision_id,
            &decisions,
            &refs,
            outcome,
        )
        .map_err(|_| Error::InvalidLineage)?;
        let count = |field: &str| {
            body.get(field)
                .and_then(serde_json::Value::as_i64)
                .ok_or(Error::InvalidLineage)
        };
        if count("participant_count")? != active.len() as i64
            || count("decided_count")? != evaluation.applicable_decisions.len() as i64
            || count("accepted_count")?
                != evaluation
                    .participants
                    .values()
                    .filter(|result| **result == fact_state::ParticipantResult::Accepted)
                    .count() as i64
            || count("rejected_count")?
                != evaluation
                    .participants
                    .values()
                    .filter(|result| **result == fact_state::ParticipantResult::Rejected)
                    .count() as i64
        {
            return Err(Error::InvalidLineage);
        }
        Ok(())
    }

    fn validate_reconciliation_roster(
        &self,
        object: &ValidatedObject,
        deliberation_body: &serde_json::Map<String, serde_json::Value>,
        manifest: &serde_json::Map<String, serde_json::Value>,
        source_ids: &[fact_core::ObjectId],
    ) -> Result<(), Error> {
        let roster = deliberation_body
            .get("roster_governance")
            .and_then(serde_json::Value::as_object)
            .ok_or(Error::InvalidLineage)?;
        let candidates = roster
            .get("candidate_union")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?;
        let mut expected_union = std::collections::BTreeMap::<
            fact_core::ObjectId,
            std::collections::BTreeSet<fact_core::ObjectId>,
        >::new();
        for source_id in source_ids {
            let (_, source_body) = self.load_body(*source_id)?;
            let initial = source_body
                .get("initial_participants")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::InvalidLineage)?
                .iter()
                .map(|participant| {
                    parse_object_id_text(
                        participant
                            .as_object()
                            .and_then(|participant| participant.get("actor_id")),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let settlement_id = manifest
                .get("conflicts")
                .and_then(serde_json::Value::as_array)
                .and_then(|conflicts| {
                    conflicts.iter().find_map(|conflict| {
                        let conflict = conflict.as_object()?;
                        (parse_object_id_text(conflict.get("deliberation_id")).ok()
                            == Some(*source_id))
                        .then(|| parse_object_id_text(conflict.get("settlement_id")))
                    })
                })
                .ok_or(Error::InvalidLineage)??;
            let (settlement_type, settlement) = self.load_body(settlement_id)?;
            if settlement_type != "settlement"
                || parse_object_id_text(settlement.get("deliberation_id"))? != *source_id
            {
                return Err(Error::InvalidLineage);
            }
            self.validate_settlement_witness_by_id(settlement_id, &settlement)?;
            let causal_ids = self.causal_closure_ids(settlement_id)?;
            let mut frontier_change_ids = std::collections::HashSet::new();
            for causal_id in &causal_ids {
                let (causal_type, causal_body) = self.load_body(*causal_id)?;
                if causal_type == "deliberation_participant_change"
                    && parse_object_id_text(causal_body.get("deliberation_id"))? == *source_id
                {
                    frontier_change_ids.insert(*causal_id);
                }
            }
            let evidence = candidates
                .iter()
                .filter_map(|candidate| candidate.as_object())
                .filter_map(|candidate| {
                    let actor = parse_object_id_text(candidate.get("actor_id")).ok()?;
                    let memberships = candidate
                        .get("source_memberships")
                        .and_then(serde_json::Value::as_array)?;
                    memberships.iter().find_map(|membership| {
                        let membership = membership.as_object()?;
                        (parse_object_id_text(membership.get("deliberation_id")).ok()
                            == Some(*source_id))
                        .then(|| (actor, membership.get("membership_evidence")))
                    })
                })
                .collect::<Vec<_>>();
            let changes = evidence
                .iter()
                .flat_map(|(_, evidence)| {
                    evidence
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flat_map(|entries| entries.iter())
                })
                .filter_map(|entry| {
                    let entry = entry.as_object()?;
                    let object_id = parse_object_id_text(entry.get("object_id")).ok()?;
                    if object_id == *source_id {
                        return None;
                    }
                    Some(object_id)
                })
                .collect::<Vec<_>>();
            let evidenced_ids: std::collections::HashSet<_> = evidence
                .iter()
                .flat_map(|(_, evidence)| {
                    evidence
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flat_map(|entries| entries.iter())
                })
                .map(|entry| {
                    entry
                        .as_object()
                        .ok_or(Error::InvalidLineage)
                        .and_then(|entry| parse_object_id_text(entry.get("object_id")))
                })
                .collect::<Result<_, _>>()?;
            let expected_evidence = frontier_change_ids
                .iter()
                .copied()
                .chain(std::iter::once(*source_id))
                .collect::<std::collections::HashSet<_>>();
            if evidenced_ids != expected_evidence {
                return Err(Error::InvalidLineage);
            }
            let mut participant_changes = Vec::new();
            for change_id in changes {
                let (change_type, change_body) = self.load_body(change_id)?;
                if change_type != "deliberation_participant_change"
                    || parse_object_id_text(change_body.get("deliberation_id"))? != *source_id
                {
                    return Err(Error::InvalidLineage);
                }
                let operation = match change_body
                    .get("operation")
                    .and_then(serde_json::Value::as_str)
                {
                    Some("join") => fact_state::ParticipantOperation::Join,
                    Some("leave") => fact_state::ParticipantOperation::Leave,
                    _ => return Err(Error::InvalidLineage),
                };
                let predecessor = change_body
                    .get("predecessor_change_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                    .map(|value| parse_object_id_text(Some(value)))
                    .transpose()?;
                participant_changes.push(fact_state::ParticipantChange {
                    id: change_id,
                    actor: parse_object_id_text(change_body.get("participant_actor_id"))?,
                    operation,
                    predecessors: predecessor.into_iter().collect(),
                });
            }
            let active = fact_state::replay_participants(&initial, &participant_changes)
                .map_err(|_| Error::InvalidLineage)?
                .active;
            let active: std::collections::BTreeSet<_> = active.into_iter().collect();
            for actor in &active {
                expected_union.entry(*actor).or_default().insert(*source_id);
            }
            for (actor, evidence) in evidence {
                if !active.contains(&actor) {
                    return Err(Error::InvalidLineage);
                }
                let evidence = evidence
                    .and_then(serde_json::Value::as_array)
                    .ok_or(Error::InvalidLineage)?;
                if !evidence.iter().any(|entry| {
                    entry
                        .as_object()
                        .and_then(|entry| parse_object_id_text(entry.get("object_id")).ok())
                        == Some(*source_id)
                }) {
                    return Err(Error::InvalidLineage);
                }
                for entry in evidence {
                    let entry = entry.as_object().ok_or(Error::InvalidLineage)?;
                    let object_id = parse_object_id_text(entry.get("object_id"))?;
                    let expected_hash = entry
                        .get("content_hash")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::InvalidLineage)?
                        .parse::<Hash>()
                        .map_err(|_| Error::InvalidLineage)?;
                    let stored_hash: Vec<u8> = self
                        .conn
                        .query_row(
                            "SELECT content_hash FROM protocol_object WHERE object_id=?",
                            [object_id.uuid().as_bytes()],
                            |row| row.get(0),
                        )
                        .optional()?
                        .ok_or(Error::MissingDependency)?;
                    if stored_hash != expected_hash.as_bytes() {
                        return Err(Error::DependencyHashMismatch);
                    }
                }
            }
        }
        let mut serialized = std::collections::BTreeMap::new();
        for candidate in candidates {
            let candidate = candidate.as_object().ok_or(Error::InvalidLineage)?;
            let actor = parse_object_id_text(candidate.get("actor_id"))?;
            let memberships = candidate
                .get("source_memberships")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::InvalidLineage)?;
            let ids = memberships
                .iter()
                .map(|membership| {
                    parse_object_id_text(
                        membership
                            .as_object()
                            .and_then(|membership| membership.get("deliberation_id")),
                    )
                })
                .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
            serialized.insert(actor, ids);
        }
        if serialized != expected_union {
            return Err(Error::InvalidLineage);
        }
        let selection_mode = roster
            .get("selection_mode")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::InvalidLineage)?;
        let selected_ids: std::collections::HashSet<_> = roster
            .get("selected_participants")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?
            .iter()
            .map(|entry| {
                parse_object_id_text(entry.as_object().and_then(|entry| entry.get("actor_id")))
            })
            .collect::<Result<_, _>>()?;
        for selected in roster
            .get("selected_participants")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?
        {
            let selected = selected.as_object().ok_or(Error::InvalidLineage)?;
            let actor = parse_object_id_text(selected.get("actor_id"))?;
            self.validate_roster_admission_evidence(object, deliberation_body, actor, selected)?;
        }
        let exclusions = roster
            .get("excluded_candidates")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?;
        let excluded_reasons = exclusions
            .iter()
            .map(|entry| {
                let entry = entry.as_object().ok_or(Error::InvalidLineage)?;
                Ok((
                    parse_object_id_text(entry.get("actor_id"))?,
                    entry
                        .get("reason")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::InvalidLineage)?,
                ))
            })
            .collect::<Result<std::collections::HashMap<_, _>, Error>>()?;
        let target_closure = self.causal_closure_for_object(object)?;
        let mut eligible = std::collections::HashSet::new();
        for actor in expected_union.keys() {
            if self.load_type(*actor).ok().as_deref() != Some("actor") {
                if !excluded_reasons.contains_key(actor) {
                    return Err(Error::InvalidLineage);
                }
                continue;
            }
            let retired = target_closure.iter().any(|id| {
                self.load_type(*id).ok().as_deref() == Some("actor_lifecycle")
                    && self.load_body(*id).ok().is_some_and(|(_, body)| {
                        body.get("operation").and_then(serde_json::Value::as_str) == Some("retire")
                            && parse_object_id_text(body.get("affected_actor_id")).ok()
                                == Some(*actor)
                    })
            });
            if retired {
                if excluded_reasons.get(actor) != Some(&"retired") {
                    return Err(Error::InvalidLineage);
                }
            } else {
                eligible.insert(*actor);
            }
        }
        if selection_mode == "union_eligible" {
            if selected_ids != eligible
                || excluded_reasons
                    .keys()
                    .any(|actor| eligible.contains(actor))
            {
                return Err(Error::InvalidLineage);
            }
        } else {
            if selected_ids
                .iter()
                .any(|actor| expected_union.contains_key(actor) && !eligible.contains(actor))
            {
                return Err(Error::InvalidLineage);
            }
            for actor in &eligible {
                if !selected_ids.contains(actor)
                    && excluded_reasons.get(actor) != Some(&"governance_excluded")
                {
                    return Err(Error::InvalidLineage);
                }
            }
            for actor in &selected_ids {
                if !expected_union.contains_key(actor) {
                    let selected = roster
                        .get("selected_participants")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|entries| {
                            entries.iter().find(|entry| {
                                parse_object_id_text(
                                    entry.as_object().and_then(|entry| entry.get("actor_id")),
                                )
                                .ok()
                                    == Some(*actor)
                            })
                        })
                        .and_then(serde_json::Value::as_object)
                        .and_then(|entry| entry.get("selection_basis"))
                        .and_then(serde_json::Value::as_str);
                    if selected != Some("governance_selected")
                        || self.load_type(*actor).ok().as_deref() != Some("actor")
                    {
                        return Err(Error::InvalidLineage);
                    }
                }
            }
        }
        let authority = roster
            .get("selection_authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(Error::InvalidLineage)?;
        let authority_actor = parse_object_id_text(authority.get("actor_id"))?;
        let authorization_ref = parse_object_id_text(authority.get("authorization_ref"))?;
        if self.load_type(authority_actor).ok().as_deref() != Some("actor")
            || self.load_type(authorization_ref).is_err()
        {
            return Err(Error::InvalidLineage);
        }
        if !target_closure.contains(&authorization_ref) {
            return Err(Error::InvalidLineage);
        }
        let (authority_type, authority_body) = self.load_body(authorization_ref)?;
        let (receiving_actor, capability, scope) = match authority_type.as_str() {
            "authorization_grant" => (
                parse_object_id_text(authority_body.get("receiving_actor_id"))?,
                authority_body
                    .get("capabilities")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|capabilities| {
                        capabilities
                            .iter()
                            .any(|capability| capability.as_str() == Some("deliberate"))
                    }),
                authority_body.get("scope"),
            ),
            "delegation" => (
                parse_object_id_text(authority_body.get("delegatee_actor_id"))?,
                authority_body
                    .get("capability")
                    .and_then(serde_json::Value::as_str)
                    == Some("deliberate"),
                authority_body.get("scope"),
            ),
            _ => return Err(Error::InvalidLineage),
        };
        if receiving_actor != authority_actor || !capability {
            return Err(Error::Unauthorized);
        }
        let scope = scope
            .and_then(serde_json::Value::as_object)
            .ok_or(Error::InvalidLineage)?;
        let proposition_id = parse_object_id_text(deliberation_body.get("proposition_id"))?;
        let revision_id = parse_object_id_text(deliberation_body.get("revision_id"))?;
        let deliberation_id = parse_object_id_text(deliberation_body.get("deliberation_id"))?;
        let scope_matches = match scope.get("type").and_then(serde_json::Value::as_str) {
            Some("ledger") => true,
            Some("proposition") => {
                parse_object_id_text(scope.get("id")).ok() == Some(proposition_id)
            }
            Some("revision") => parse_object_id_text(scope.get("id")).ok() == Some(revision_id),
            Some("deliberation") => {
                parse_object_id_text(scope.get("id")).ok() == Some(deliberation_id)
            }
            _ => false,
        };
        if !scope_matches {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn validate_roster_admission_evidence(
        &self,
        object: &ValidatedObject,
        deliberation_body: &serde_json::Map<String, serde_json::Value>,
        participant: fact_core::ObjectId,
        selected: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), Error> {
        let join_policy = deliberation_body
            .get("join_policy")
            .and_then(serde_json::Value::as_object)
            .ok_or(Error::InvalidLineage)?;
        let mode = join_policy
            .get("mode")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::InvalidLineage)?;
        let evidence = selected
            .get("admission_evidence")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?;
        if mode != "attested" {
            return Ok(());
        }
        let requirements = join_policy
            .get("attestation_requirements")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?;
        let envelope: serde_json::Value =
            serde_json::from_slice(&object.canonical).map_err(|_| Error::Metadata)?;
        let joined_at = envelope
            .get("created_at")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Metadata)
            .and_then(|value| {
                fact_core::timestamp_millis(value).map_err(|_| Error::InvalidLineage)
            })?;
        let direct: std::collections::HashMap<_, _> = object
            .dependencies
            .iter()
            .filter_map(|(id, hash, _)| {
                uuid::Uuid::from_slice(id)
                    .ok()
                    .and_then(|id| id.to_string().parse::<fact_core::ObjectId>().ok())
                    .map(|id| (id, *hash))
            })
            .collect();
        let mut observed = Vec::new();
        for entry in evidence {
            let entry = entry.as_object().ok_or(Error::InvalidLineage)?;
            let evidence_id = parse_object_id_text(entry.get("object_id"))?;
            let evidence_hash = entry
                .get("content_hash")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidLineage)?
                .parse::<Hash>()
                .map_err(|_| Error::InvalidLineage)?;
            if direct.get(&evidence_id) != Some(&evidence_hash)
                || self.load_type(evidence_id)? != "identity_attestation"
            {
                return Err(Error::InvalidLineage);
            }
            let (_, attestation) = self.load_body(evidence_id)?;
            if attestation
                .get("subject_type")
                .and_then(serde_json::Value::as_str)
                != Some("actor")
                || parse_object_id_text(attestation.get("subject_id"))? != participant
            {
                return Err(Error::InvalidLineage);
            }
            let issuer = self.load_actor_id(evidence_id)?;
            if self.load_type(issuer)? != "actor" {
                return Err(Error::InvalidLineage);
            }
            let validity =
                parse_validity(attestation.get("validity"))?.ok_or(Error::InvalidLineage)?;
            if validity
                .valid_from_millis
                .is_some_and(|from| from > joined_at)
                || validity
                    .expires_at_millis
                    .is_some_and(|expires| joined_at >= expires)
            {
                return Err(Error::InvalidLineage);
            }
            observed.push((
                issuer,
                attestation
                    .get("claim_type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?
                    .to_owned(),
            ));
        }
        for requirement in requirements {
            let requirement = requirement.as_object().ok_or(Error::InvalidLineage)?;
            let claim_type = requirement
                .get("claim_type")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidLineage)?;
            let issuers = requirement
                .get("permitted_issuers")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::InvalidLineage)?
                .iter()
                .map(|issuer| parse_object_id_text(Some(issuer)))
                .collect::<Result<std::collections::HashSet<_>, _>>()?;
            let minimum = requirement
                .get("minimum_count")
                .and_then(serde_json::Value::as_u64)
                .ok_or(Error::InvalidLineage)? as usize;
            if observed
                .iter()
                .filter(|(issuer, claim)| *claim == claim_type && issuers.contains(issuer))
                .count()
                < minimum
            {
                return Err(Error::InvalidLineage);
            }
        }
        Ok(())
    }

    fn validate_authorization_reference(
        &self,
        object: &ValidatedObject,
        body: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), Error> {
        let Some(reference) = body
            .get("authorization_ref")
            .and_then(|value| (!value.is_null()).then_some(value))
        else {
            return Ok(());
        };
        let reference = parse_object_id_text(Some(reference))?;
        let direct = object.dependencies.iter().any(|(id, _, _)| {
            uuid::Uuid::from_slice(id)
                .ok()
                .and_then(|id| id.to_string().parse::<fact_core::ObjectId>().ok())
                == Some(reference)
        });
        if !direct {
            return Err(Error::InvalidLineage);
        }
        if !matches!(
            self.load_type(reference)?.as_str(),
            "authorization_grant" | "delegation"
        ) {
            return Err(Error::InvalidLineage);
        }
        Ok(())
    }

    fn validate_attested_admission(
        &self,
        object: &ValidatedObject,
        body: &serde_json::Map<String, serde_json::Value>,
        participant: fact_core::ObjectId,
        join_policy: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), Error> {
        let requirements = join_policy
            .get("attestation_requirements")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?;
        if requirements.is_empty() {
            return Err(Error::InvalidLineage);
        }
        let evidence = body
            .get("admission_evidence")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?;
        if evidence.is_empty() {
            return Err(Error::InvalidLineage);
        }
        if self.load_type(participant)? != "actor" {
            return Err(Error::InvalidLineage);
        }
        let envelope: serde_json::Value =
            serde_json::from_slice(&object.canonical).map_err(|_| Error::Metadata)?;
        let joined_at = envelope
            .get("created_at")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Metadata)?;
        let joined_at =
            fact_core::timestamp_millis(joined_at).map_err(|_| Error::InvalidLineage)?;
        let direct_dependencies = object
            .dependencies
            .iter()
            .map(|(id, hash, _)| {
                let id = uuid::Uuid::from_slice(id)
                    .map_err(|_| Error::InvalidUuid("dependency.object_id"))?
                    .to_string()
                    .parse::<fact_core::ObjectId>()
                    .map_err(|_| Error::InvalidUuid("dependency.object_id"))?;
                Ok((id, *hash))
            })
            .collect::<Result<std::collections::HashMap<_, _>, Error>>()?;
        let mut admissible = self.causal_closure_for_object(object)?;
        admissible.extend(direct_dependencies.keys().copied());
        let mut observed = Vec::new();
        for evidence in evidence {
            let evidence = evidence.as_object().ok_or(Error::InvalidLineage)?;
            let evidence_id = parse_object_id_text(evidence.get("object_id"))?;
            let evidence_hash = evidence
                .get("content_hash")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidLineage)?
                .parse::<Hash>()
                .map_err(|_| Error::InvalidLineage)?;
            if !admissible.contains(&evidence_id)
                || direct_dependencies.get(&evidence_id) != Some(&evidence_hash)
            {
                return Err(Error::InvalidLineage);
            }
            let payload: Vec<u8> = self
                .conn
                .query_row(
                    "SELECT payload FROM protocol_object WHERE object_id=?",
                    [evidence_id.uuid().as_bytes()],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(Error::MissingDependency)?;
            if Hash::digest(&payload) != evidence_hash {
                return Err(Error::DependencyHashMismatch);
            }
            let value: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| Error::Metadata)?;
            let map = value.as_object().ok_or(Error::Metadata)?;
            let evidence_body = map
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::Metadata)?;
            if map.get("object_type").and_then(serde_json::Value::as_str)
                != Some("identity_attestation")
                || evidence_body
                    .get("subject_type")
                    .and_then(serde_json::Value::as_str)
                    != Some("actor")
                || parse_object_id_text(evidence_body.get("subject_id"))? != participant
            {
                return Err(Error::InvalidLineage);
            }
            let issuer = parse_object_id_text(map.get("actor_id"))?;
            if self.load_type(issuer)? != "actor" {
                return Err(Error::InvalidLineage);
            }
            let claim_type = evidence_body
                .get("claim_type")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidLineage)?;
            let validity =
                parse_validity(evidence_body.get("validity"))?.ok_or(Error::InvalidLineage)?;
            if validity
                .valid_from_millis
                .is_some_and(|from| from > joined_at)
                || validity
                    .expires_at_millis
                    .is_some_and(|expires| joined_at >= expires)
            {
                return Err(Error::InvalidLineage);
            }
            observed.push((evidence_id, issuer, claim_type.to_owned()));
        }
        for requirement in requirements {
            let requirement = requirement.as_object().ok_or(Error::InvalidLineage)?;
            let claim_type = requirement
                .get("claim_type")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidLineage)?;
            let issuers = requirement
                .get("permitted_issuers")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::InvalidLineage)?
                .iter()
                .map(|issuer| parse_object_id_text(Some(issuer)))
                .collect::<Result<std::collections::HashSet<_>, _>>()?;
            let minimum = requirement
                .get("minimum_count")
                .and_then(serde_json::Value::as_u64)
                .ok_or(Error::InvalidLineage)? as usize;
            let count = observed
                .iter()
                .filter(|(_, issuer, claim)| claim == claim_type && issuers.contains(issuer))
                .count();
            if count < minimum {
                return Err(Error::InvalidLineage);
            }
        }
        Ok(())
    }

    fn load_body(
        &self,
        id: fact_core::ObjectId,
    ) -> Result<(String, serde_json::Map<String, serde_json::Value>), Error> {
        let (object_type, payload): (String, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT object_type,payload FROM protocol_object WHERE object_id=?",
                [id.uuid().as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(Error::MissingDependency)?;
        let value: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|_| Error::Metadata)?;
        let body = value
            .get("body")
            .and_then(serde_json::Value::as_object)
            .ok_or(Error::Metadata)?
            .clone();
        Ok((object_type, body))
    }

    fn load_actor_id(&self, id: fact_core::ObjectId) -> Result<fact_core::ObjectId, Error> {
        let bytes: Vec<u8> = self.conn.query_row(
            "SELECT actor_id FROM protocol_object WHERE object_id=?",
            [id.uuid().as_bytes()],
            |row| row.get(0),
        )?;
        object_id_from_bytes(&bytes)
    }

    fn causal_closure_ids(
        &self,
        root: fact_core::ObjectId,
    ) -> Result<std::collections::HashSet<fact_core::ObjectId>, Error> {
        let mut closure = std::collections::HashSet::new();
        let mut pending = vec![root];
        while let Some(id) = pending.pop() {
            if !closure.insert(id) {
                continue;
            }
            let mut statement = self
                .conn
                .prepare("SELECT dependency_id FROM object_dependency WHERE object_id=?")?;
            let dependencies = statement
                .query_map([id.uuid().as_bytes()], |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            "invalid dependency ID length".into(),
                        )
                    })?;
                    uuid::Uuid::from_bytes(bytes)
                        .to_string()
                        .parse::<fact_core::ObjectId>()
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Blob,
                                Box::new(error),
                            )
                        })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            pending.extend(dependencies);
        }
        Ok(closure)
    }

    fn causal_closure_for_object(
        &self,
        object: &ValidatedObject,
    ) -> Result<std::collections::HashSet<fact_core::ObjectId>, Error> {
        let mut closure = std::collections::HashSet::new();
        for (dependency_id, _, _) in &object.dependencies {
            let id = uuid::Uuid::from_slice(dependency_id)
                .map_err(|_| Error::InvalidUuid("dependency.object_id"))?
                .to_string()
                .parse::<fact_core::ObjectId>()
                .map_err(|_| Error::InvalidUuid("dependency.object_id"))?;
            closure.insert(id);
            closure.extend(self.causal_closure_ids(id)?);
        }
        Ok(closure)
    }

    fn validate_invitation_lifecycle(
        &self,
        object: &ValidatedObject,
        invitation_id: fact_core::ObjectId,
        body: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), Error> {
        let (_, invitation) = self.load_body(invitation_id)?;
        let actor = uuid::Uuid::from_slice(&object.actor)
            .map_err(|_| Error::InvalidUuid("actor_id"))?
            .to_string()
            .parse::<fact_core::ObjectId>()
            .map_err(|_| Error::InvalidUuid("actor_id"))?;
        let operation = body
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::InvalidLineage)?;
        let invited = parse_object_id_text(invitation.get("invited_actor_id"))?;
        match operation {
            "decline" if actor != invited => return Err(Error::Unauthorized),
            "decline" | "revoke" | "supersede" => {}
            _ => return Err(Error::InvalidLineage),
        }
        let closure = self.causal_closure_for_object(object)?;
        let mut lifecycle_ids = std::collections::HashSet::new();
        let mut referenced = std::collections::HashSet::new();
        for id in &closure {
            if self.load_type(*id).ok().as_deref() != Some("invitation_lifecycle") {
                continue;
            }
            let (_, lifecycle) = self.load_body(*id)?;
            if parse_object_id_text(lifecycle.get("invitation_id"))? != invitation_id {
                continue;
            }
            lifecycle_ids.insert(*id);
            for predecessor in lifecycle
                .get("predecessor_lifecycle_ids")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::InvalidLineage)?
            {
                referenced.insert(parse_object_id_text(Some(predecessor))?);
            }
        }
        let tips: std::collections::HashSet<_> =
            lifecycle_ids.difference(&referenced).copied().collect();
        let predecessors = body
            .get("predecessor_lifecycle_ids")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?
            .iter()
            .map(|predecessor| parse_object_id_text(Some(predecessor)))
            .collect::<Result<std::collections::HashSet<_>, _>>()?;
        if predecessors != tips {
            return Err(Error::InvalidLineage);
        }
        if predecessors.iter().any(|id| !closure.contains(id)) {
            return Err(Error::InvalidLineage);
        }
        Ok(())
    }

    fn active_participants_at_object(
        &self,
        deliberation_id: fact_core::ObjectId,
        deliberation: &serde_json::Map<String, serde_json::Value>,
        object: &ValidatedObject,
    ) -> Result<std::collections::HashSet<fact_core::ObjectId>, Error> {
        let initial = deliberation
            .get("initial_participants")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::InvalidLineage)?
            .iter()
            .map(|participant| {
                parse_object_id_text(
                    participant
                        .as_object()
                        .and_then(|participant| participant.get("actor_id")),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let changes = self
            .causal_closure_for_object(object)?
            .into_iter()
            .filter(|id| {
                self.load_type(*id).ok().as_deref() == Some("deliberation_participant_change")
            })
            .map(|id| {
                let (_, body) = self.load_body(id)?;
                if parse_object_id_text(body.get("deliberation_id"))? != deliberation_id {
                    return Err(Error::InvalidLineage);
                }
                let operation = match body.get("operation").and_then(serde_json::Value::as_str) {
                    Some("join") => fact_state::ParticipantOperation::Join,
                    Some("leave") => fact_state::ParticipantOperation::Leave,
                    _ => return Err(Error::InvalidLineage),
                };
                let predecessor = body
                    .get("predecessor_change_id")
                    .and_then(|value| (!value.is_null()).then_some(value))
                    .map(|value| parse_object_id_text(Some(value)))
                    .transpose()?;
                Ok(fact_state::ParticipantChange {
                    id,
                    actor: parse_object_id_text(body.get("participant_actor_id"))?,
                    operation,
                    predecessors: predecessor.into_iter().collect(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(fact_state::replay_participants(&initial, &changes)
            .map_err(|_| Error::InvalidLineage)?
            .active
            .into_iter()
            .collect())
    }

    fn closure_contains_settlement_for_deliberation(
        &self,
        closure: &std::collections::HashSet<fact_core::ObjectId>,
        deliberation_id: fact_core::ObjectId,
    ) -> Result<bool, Error> {
        for id in closure {
            if self.load_type(*id).ok().as_deref() != Some("settlement") {
                continue;
            }
            let (_, settlement) = self.load_body(*id)?;
            if parse_object_id_text(settlement.get("deliberation_id"))? == deliberation_id {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn object_id_from_bytes(bytes: &[u8]) -> Result<fact_core::ObjectId, Error> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::InvalidUuid("object_id"))?;
    uuid::Uuid::from_bytes(bytes)
        .to_string()
        .parse::<fact_core::ObjectId>()
        .map_err(|_| Error::InvalidUuid("object_id"))
}

type RelationshipRule = (
    &'static [&'static str],
    &'static [&'static str],
    usize,
    Option<usize>,
);

fn relationship_rule(name: &str) -> Option<RelationshipRule> {
    Some(match name {
        "protocol:parent-revision" => (&["revision"], &["revision"], 1, Some(1)),
        "protocol:supersedes" => (
            &[
                "decision",
                "namespace_assertion",
                "recovery_policy",
                "participant_invitation",
                "invitation_lifecycle",
                "key_lifecycle",
                "actor_lifecycle",
                "proposition_lifecycle",
            ],
            &[
                "decision",
                "namespace_assertion",
                "recovery_policy",
                "participant_invitation",
                "invitation_lifecycle",
                "key_lifecycle",
                "actor_lifecycle",
                "proposition_lifecycle",
            ],
            1,
            None,
        ),
        "protocol:extends" => (&["deliberation"], &["deliberation"], 1, Some(1)),
        "protocol:derived-from" => (&["revision"], &["revision"], 1, None),
        "protocol:reconciles" => (
            &["revision"],
            &["revision", "deliberation", "settlement"],
            2,
            None,
        ),
        "protocol:copies" => (&["proposition_provenance"], &["revision"], 1, Some(1)),
        "protocol:references" => (&["any"], &["any"], 0, None),
        "protocol:revokes" => (
            &[
                "authorization_revocation",
                "delegation_revocation",
                "key_lifecycle",
                "actor_lifecycle",
                "invitation_lifecycle",
                "proposition_lifecycle",
            ],
            &["any"],
            1,
            Some(1),
        ),
        "protocol:supersedes-authorization" => (
            &["authorization_grant", "delegation"],
            &["authorization_grant", "delegation"],
            1,
            Some(1),
        ),
        "protocol:delegates-to" => (&["delegation"], &["actor"], 1, Some(1)),
        "protocol:attests-to" => (&["identity_attestation"], &["actor", "key"], 1, Some(1)),
        "protocol:binds-key" => (&["actor_key_binding"], &["key"], 1, Some(1)),
        "protocol:invites" => (&["participant_invitation"], &["actor"], 1, Some(1)),
        "protocol:joins" => (
            &["deliberation_participant_change"],
            &["deliberation"],
            1,
            Some(1),
        ),
        "protocol:settles" => (&["settlement"], &["deliberation"], 1, Some(1)),
        _ => return None,
    })
}

fn valid_dependency_role(role: &str) -> bool {
    if role.is_empty() {
        return false;
    }
    let bytes = role.as_bytes();
    let mut previous_separator = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_separator = false;
        } else if (byte == b'.' || byte == b'_' || byte == b'-')
            && index > 0
            && index + 1 < bytes.len()
            && !previous_separator
        {
            previous_separator = true;
        } else {
            return false;
        }
    }
    true
}

fn projected_rank(object_type: &str) -> u8 {
    match object_type {
        "actor" => 0,
        "key" => 1,
        "actor_key_binding" => 2,
        "authorization_grant" | "delegation" => 3,
        "namespace_assertion" => 4,
        "proposition" => 5,
        "revision" => 6,
        "deliberation" => 7,
        "participant_invitation" => 8,
        "standing_participant_change" | "deliberation_participant_change" => 9,
        "decision" | "deliberation_comment" => 10,
        "settlement" => 11,
        "authorization_revocation" | "delegation_revocation" => 12,
        "key_lifecycle"
        | "recovery_policy"
        | "actor_lifecycle"
        | "invitation_lifecycle"
        | "proposition_lifecycle" => 13,
        _ => 14,
    }
}

fn projected_id(
    bytes: Vec<u8>,
    message: &'static str,
) -> Result<fact_core::ObjectId, rusqlite::Error> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, message.into())
    })?;
    fact_core::ObjectId::from_str(&uuid::Uuid::from_bytes(bytes).to_string()).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            "invalid projected UUID".into(),
        )
    })
}

fn object_reference_match(
    row: &rusqlite::Row<'_>,
) -> Result<ObjectReferenceMatch, rusqlite::Error> {
    let object_id: Vec<u8> = row.get(0)?;
    let content_hash: Vec<u8> = row.get(1)?;
    let object_type: String = row.get(2)?;
    let ledger_id: Vec<u8> = row.get(3)?;
    let object_id = uuid::Uuid::from_slice(&object_id).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    })?;
    let content_hash: [u8; 32] = content_hash.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Blob,
            "invalid hash length".into(),
        )
    })?;
    Ok(ObjectReferenceMatch {
        object_id,
        content_hash: Hash::from_bytes(content_hash),
        object_type,
        ledger_id,
    })
}

fn object_payload_row(row: &rusqlite::Row<'_>) -> Result<ObjectPayloadRow, rusqlite::Error> {
    let object_id: Vec<u8> = row.get(0)?;
    let content_hash: Vec<u8> = row.get(1)?;
    let object_type: String = row.get(2)?;
    let payload: Vec<u8> = row.get(3)?;
    Ok(ObjectPayloadRow {
        object_id: uuid::Uuid::from_slice(&object_id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?,
        content_hash: Hash::from_bytes(content_hash.try_into().map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Blob,
                "invalid hash length".into(),
            )
        })?),
        object_type,
        payload,
    })
}

fn object_summary_row(row: &rusqlite::Row<'_>) -> Result<ObjectSummaryRow, rusqlite::Error> {
    let object_id: Vec<u8> = row.get(0)?;
    let content_hash: Vec<u8> = row.get(1)?;
    let object_type: String = row.get(2)?;
    Ok(ObjectSummaryRow {
        object_id: uuid::Uuid::from_slice(&object_id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?,
        content_hash: Hash::from_bytes(content_hash.try_into().map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Blob,
                "invalid hash length".into(),
            )
        })?),
        object_type,
    })
}

fn default_proposition_row(
    row: &rusqlite::Row<'_>,
) -> Result<PropositionListProjected, rusqlite::Error> {
    let proposition_id = projected_uuid(row.get(0)?, "invalid proposition ID")?;
    let status: String = row.get(1)?;
    let revision_id = optional_projected_uuid(row.get(2)?)?;
    let deliberation_id = optional_projected_uuid(row.get(3)?)?;
    let settlement_id = optional_projected_uuid(row.get(4)?)?;
    let withdrawal_status: String = row.get(5)?;
    let archival_status: String = row.get(6)?;
    let latest_revision_id = optional_projected_uuid(row.get(7)?)?;
    let latest_revision_status: String = row.get(8)?;
    let summary_text: Option<String> = row.get(9)?;
    let summary_revision_payload: Option<Vec<u8>> = row.get(10)?;
    let pending_revision_id = optional_projected_uuid(row.get(11)?)?;
    let pending_deliberation_id = optional_projected_uuid(row.get(12)?)?;
    let pending_participant_count = row.get::<_, i64>(13)? as usize;
    let current_actor_pending = row.get::<_, i64>(14)? != 0;
    let has_pending_revision = row.get::<_, i64>(15)? != 0;
    Ok(PropositionListProjected {
        proposition_id,
        status: status.clone(),
        revision_id,
        deliberation_id,
        settlement_id,
        effective_status: status.clone(),
        latest_revision_id,
        latest_revision_status,
        pending_revision_id,
        pending_deliberation_id,
        pending_participant_count,
        current_actor_pending,
        has_pending_revision,
        summary_text,
        summary_revision_payload,
        withdrawal_status,
        archival_status,
    })
}

fn indexed_proposition_rows_match(
    indexed: &PropositionListProjected,
    legacy: &PropositionListProjected,
) -> bool {
    indexed.status == legacy.status
        && indexed.revision_id == legacy.revision_id
        && indexed.deliberation_id == legacy.deliberation_id
        && indexed.settlement_id == legacy.settlement_id
        && indexed.effective_status == legacy.effective_status
        && indexed.latest_revision_id == legacy.latest_revision_id
        && indexed.latest_revision_status == legacy.latest_revision_status
        && indexed.pending_revision_id == legacy.pending_revision_id
        && indexed.pending_deliberation_id == legacy.pending_deliberation_id
        && indexed.pending_participant_count == legacy.pending_participant_count
        && indexed.current_actor_pending == legacy.current_actor_pending
        && indexed.has_pending_revision == legacy.has_pending_revision
        && indexed.withdrawal_status == legacy.withdrawal_status
        && indexed.archival_status == legacy.archival_status
}

fn indexed_proposition_metadata_row(
    row: &rusqlite::Row<'_>,
) -> Result<IndexedPropositionMetadata, rusqlite::Error> {
    Ok(IndexedPropositionMetadata {
        proposition_id: projected_uuid(row.get(0)?, "invalid proposition ID")?,
        status: row.get(1)?,
        effective_reason: row.get(2)?,
        effective_revision_id: optional_projected_uuid(row.get(3)?)?,
        effective_deliberation_id: optional_projected_uuid(row.get(4)?)?,
        settlement_id: optional_projected_uuid(row.get(5)?)?,
        latest_revision_id: optional_projected_uuid(row.get(6)?)?,
        latest_revision_status: row.get(7)?,
        pending_revision_id: optional_projected_uuid(row.get(8)?)?,
        pending_deliberation_id: optional_projected_uuid(row.get(9)?)?,
        pending_participant_count: row.get::<_, i64>(10)? as usize,
        current_actor_pending: row.get::<_, i64>(11)? != 0,
        has_pending_revision: row.get::<_, i64>(12)? != 0,
        withdrawal_status: row.get(13)?,
        archival_status: row.get(14)?,
    })
}

fn push_page_values(values: &mut Vec<Value>, offset: usize, limit: Option<usize>) {
    if let Some(limit) = limit {
        values.push(Value::Integer(limit.min(i64::MAX as usize) as i64));
        values.push(Value::Integer(offset.min(i64::MAX as usize) as i64));
    }
}

fn decision_row(row: &rusqlite::Row<'_>) -> Result<DecisionRow, rusqlite::Error> {
    Ok(DecisionRow {
        decision_id: projected_uuid(row.get(0)?, "invalid decision ID")?,
        deliberation_id: projected_uuid(row.get(1)?, "invalid deliberation ID")?,
        participant_actor_id: projected_uuid(row.get(2)?, "invalid participant actor ID")?,
        value: row.get(3)?,
        content_hash: Hash::from_bytes(row.get::<_, Vec<u8>>(4)?.try_into().map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Blob,
                "invalid content hash length".into(),
            )
        })?),
        payload: row.get(5)?,
        cose: row.get(6)?,
    })
}

fn effective_projected_row(row: &rusqlite::Row<'_>) -> Result<EffectiveProjected, rusqlite::Error> {
    Ok(EffectiveProjected {
        proposition_id: projected_id(row.get(0)?, "invalid proposition ID")?,
        status: row.get(1)?,
        revision_id: optional_projected_id(row.get(2)?)?,
        deliberation_id: optional_projected_id(row.get(3)?)?,
        settlement_id: optional_projected_id(row.get(4)?)?,
        withdrawal_status: row.get(5)?,
        archival_status: row.get(6)?,
        reason: row.get(7)?,
    })
}

fn tag_extension_row(row: &rusqlite::Row<'_>) -> Result<TagExtensionRow, rusqlite::Error> {
    let payload: Vec<u8> = row.get(5)?;
    let value: serde_json::Value = serde_json::from_slice(&payload).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Blob, Box::new(error))
    })?;
    let tags = value
        .get("body")
        .and_then(|body| body.get("tags"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            rusqlite::Error::InvalidColumnType(5, "payload".into(), rusqlite::types::Type::Blob)
        })?
        .iter()
        .map(|tag| {
            tag.as_str().map(str::to_owned).ok_or_else(|| {
                rusqlite::Error::InvalidColumnType(5, "payload".into(), rusqlite::types::Type::Blob)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TagExtensionRow {
        event_id: projected_uuid(row.get(0)?, "invalid tag event ID")?,
        ledger_id: projected_uuid(row.get(1)?, "invalid tag ledger ID")?,
        proposition_id: projected_uuid(row.get(2)?, "invalid tag target ID")?,
        operation: row.get(3)?,
        created_at: row.get(4)?,
        tags,
        payload,
    })
}

fn parse_tag_extension_event_payload(payload: &[u8]) -> Result<TagExtensionEventInput, Error> {
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(|_| Error::Metadata)?;
    if value.get("schema").and_then(serde_json::Value::as_str) != Some("facts-extension-event-v0")
        || value.get("extension").and_then(serde_json::Value::as_str) != Some("fact.tags")
        || value.get("target_type").and_then(serde_json::Value::as_str) != Some("proposition")
    {
        return Err(Error::Metadata);
    }
    let tags = value
        .get("body")
        .and_then(|body| body.get("tags"))
        .and_then(serde_json::Value::as_array)
        .ok_or(Error::Metadata)?
        .iter()
        .map(|tag| tag.as_str().map(str::to_owned).ok_or(Error::Metadata))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TagExtensionEventInput {
        event_id: uuid::Uuid::parse_str(
            value
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::Metadata)?,
        )
        .map_err(|_| Error::Metadata)?,
        ledger_id: uuid::Uuid::parse_str(
            value
                .get("ledger_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::Metadata)?,
        )
        .map_err(|_| Error::Metadata)?,
        proposition_id: uuid::Uuid::parse_str(
            value
                .get("target_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::Metadata)?,
        )
        .map_err(|_| Error::Metadata)?,
        actor_id: uuid::Uuid::parse_str(
            value
                .get("actor_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::Metadata)?,
        )
        .map_err(|_| Error::Metadata)?,
        signing_key_id: uuid::Uuid::parse_str(
            value
                .get("signing_key_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::Metadata)?,
        )
        .map_err(|_| Error::Metadata)?,
        operation: value
            .get("event_type")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Metadata)?
            .to_owned(),
        tags,
        created_at: value
            .get("created_at")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Metadata)?
            .to_owned(),
    })
}

fn directory_extension_row(
    row: &rusqlite::Row<'_>,
) -> Result<DirectoryExtensionRow, rusqlite::Error> {
    let payload: Vec<u8> = row.get(5)?;
    let event = parse_directory_extension_event_payload(&payload).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Blob, Box::new(error))
    })?;
    Ok(DirectoryExtensionRow {
        event_id: projected_uuid(row.get(0)?, "invalid directory event ID")?,
        ledger_id: projected_uuid(row.get(1)?, "invalid directory ledger ID")?,
        target_actor_id: projected_uuid(row.get(2)?, "invalid directory target actor ID")?,
        target_key_id: event.target_key_id,
        operation: row.get(3)?,
        display_name: event.display_name,
        alias: event.alias,
        actor_type: event.actor_type,
        role: event.role,
        source: event.source,
        verified_by: event.verified_by,
        created_at: row.get(4)?,
        payload,
    })
}

fn projected_directory_row(
    row: &rusqlite::Row<'_>,
) -> Result<ProjectedDirectoryRow, rusqlite::Error> {
    Ok(ProjectedDirectoryRow {
        ledger_id: projected_uuid(row.get(0)?, "invalid directory ledger ID")?,
        target_actor_id: projected_uuid(row.get(1)?, "invalid directory actor ID")?,
        target_key_id: optional_projected_uuid(row.get(2)?)?,
        display_name: row.get(3)?,
        alias: row.get(4)?,
        actor_type: row.get(5)?,
        role: row.get(6)?,
        source: row.get(7)?,
        verified_by: row.get(8)?,
        event_id: projected_uuid(row.get(9)?, "invalid directory event ID")?,
        payload: row.get(10)?,
    })
}

fn directory_extension_payload(input: &DirectoryExtensionEventInput) -> Result<Vec<u8>, Error> {
    fact_canonical::encode(
        &serde_json::to_vec(&serde_json::json!({
            "schema": "facts-extension-event-v0",
            "extension": "fact.directory",
            "event_id": input.event_id,
            "ledger_id": input.ledger_id,
            "target_type": "actor",
            "target_id": input.target_actor_id,
            "event_type": input.operation,
            "actor_id": input.actor_id,
            "signing_key_id": input.signing_key_id,
            "created_at": input.created_at,
            "body": {
                "actor_id": input.target_actor_id,
                "key_id": input.target_key_id,
                "display_name": input.display_name,
                "alias": input.alias,
                "actor_type": input.actor_type,
                "role": input.role,
                "source": input.source,
                "verified_by": input.verified_by,
                "updated_at": input.created_at,
            },
        }))
        .map_err(|_| Error::Metadata)?,
    )
    .map_err(Into::into)
}

fn parse_directory_extension_event_payload(
    payload: &[u8],
) -> Result<DirectoryExtensionEventInput, Error> {
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(|_| Error::Metadata)?;
    if value.get("schema").and_then(serde_json::Value::as_str) != Some("facts-extension-event-v0")
        || value.get("extension").and_then(serde_json::Value::as_str) != Some("fact.directory")
        || value.get("target_type").and_then(serde_json::Value::as_str) != Some("actor")
    {
        return Err(Error::Metadata);
    }
    let body = value
        .get("body")
        .and_then(serde_json::Value::as_object)
        .ok_or(Error::Metadata)?;
    let optional_string = |key: &str| {
        body.get(key)
            .and_then(|value| match value {
                serde_json::Value::Null => None,
                other => other.as_str(),
            })
            .map(str::to_owned)
    };
    let optional_uuid = |key: &str| -> Result<Option<uuid::Uuid>, Error> {
        body.get(key)
            .and_then(|value| match value {
                serde_json::Value::Null => None,
                other => other.as_str(),
            })
            .map(uuid::Uuid::parse_str)
            .transpose()
            .map_err(|_| Error::Metadata)
    };
    Ok(DirectoryExtensionEventInput {
        event_id: parse_json_uuid(&value, "event_id")?,
        ledger_id: parse_json_uuid(&value, "ledger_id")?,
        actor_id: parse_json_uuid(&value, "actor_id")?,
        signing_key_id: parse_json_uuid(&value, "signing_key_id")?,
        target_actor_id: parse_json_uuid(&value, "target_id")?,
        target_key_id: optional_uuid("key_id")?,
        operation: value
            .get("event_type")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Metadata)?
            .to_owned(),
        display_name: optional_string("display_name"),
        alias: optional_string("alias"),
        actor_type: optional_string("actor_type"),
        role: optional_string("role"),
        source: optional_string("source"),
        verified_by: optional_string("verified_by"),
        created_at: value
            .get("created_at")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Metadata)?
            .to_owned(),
    })
}

fn parse_json_uuid(value: &serde_json::Value, key: &str) -> Result<uuid::Uuid, Error> {
    uuid::Uuid::parse_str(
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Metadata)?,
    )
    .map_err(|_| Error::Metadata)
}

fn lifecycle_row(row: &rusqlite::Row<'_>) -> Result<LifecycleRow, rusqlite::Error> {
    Ok(LifecycleRow {
        object_id: projected_uuid(row.get(0)?, "invalid lifecycle object ID")?,
        object_type: row.get(1)?,
        target_id: optional_projected_uuid(row.get(2)?)?,
        dimension: row.get(3)?,
        operation: row.get(4)?,
        payload: row.get(5)?,
    })
}

fn deliberation_row(row: &rusqlite::Row<'_>) -> Result<DeliberationRow, rusqlite::Error> {
    Ok(DeliberationRow {
        deliberation_id: projected_uuid(row.get(0)?, "invalid deliberation ID")?,
        proposition_id: projected_uuid(row.get(1)?, "invalid proposition ID")?,
        revision_id: projected_uuid(row.get(2)?, "invalid revision ID")?,
        settled: row.get::<_, i64>(3)? != 0,
        content_hash: Hash::from_bytes(row.get::<_, Vec<u8>>(4)?.try_into().map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Blob,
                "invalid content hash length".into(),
            )
        })?),
        object_id: projected_uuid(row.get(5)?, "invalid deliberation object ID")?,
        payload: row.get(6)?,
    })
}

/// Parses `reference` as a (possibly partial) canonical dashed-UUID prefix and
/// returns the inclusive `[low, high]` 16-byte range that matches every
/// `object_id` sharing that prefix. Dashes are only accepted at the exact
/// positions a canonical UUID string has them (8, 13, 18, 23); any other
/// character outside `[0-9a-f-]` at a non-dash position means the reference
/// cannot match any object_id, so `None` is returned. This lets the caller
/// use an indexed `BETWEEN` range scan on the `object_id` primary key instead
/// of a computed per-row expression that defeats the index.
fn uuid_hex_prefix_range(reference: &str) -> Option<([u8; 16], [u8; 16])> {
    const DASH_POSITIONS: [usize; 4] = [8, 13, 18, 23];
    let mut hex = String::with_capacity(32);
    for (position, character) in reference.chars().enumerate() {
        if hex.len() == 32 {
            break;
        }
        if DASH_POSITIONS.contains(&position) {
            if character != '-' {
                return None;
            }
            continue;
        }
        if !character.is_ascii_hexdigit() {
            return None;
        }
        hex.push(character);
    }
    if hex.is_empty() {
        return None;
    }
    hex_prefix_range::<16>(&hex)
}

fn split_uuid_reference_parts(reference: &str) -> Option<(String, String)> {
    let (head, tail) = reference.split_once('-')?;
    if head.len() != 5 || tail.len() != 5 {
        return None;
    }
    if !head.chars().all(|character| character.is_ascii_hexdigit())
        || !tail.chars().all(|character| character.is_ascii_hexdigit())
    {
        return None;
    }
    Some((head.to_owned(), tail.to_owned()))
}

fn uuid_tail_prefix_matches(id: uuid::Uuid, tail: &str) -> bool {
    id.simple().to_string()[20..].starts_with(tail)
}

/// Returns the inclusive `[low, high]` byte range of length `N` that matches
/// every value whose hex representation starts with `hex_prefix`. `hex_prefix`
/// must already be validated as containing only hex digits.
fn hex_prefix_range<const N: usize>(hex_prefix: &str) -> Option<([u8; N], [u8; N])> {
    if hex_prefix.is_empty() || hex_prefix.len() > N * 2 {
        return None;
    }
    let mut low_hex = hex_prefix.to_owned();
    let mut high_hex = hex_prefix.to_owned();
    while low_hex.len() < N * 2 {
        low_hex.push('0');
        high_hex.push('f');
    }
    let mut low = [0u8; N];
    let mut high = [0u8; N];
    for index in 0..N {
        low[index] = u8::from_str_radix(&low_hex[index * 2..index * 2 + 2], 16).ok()?;
        high[index] = u8::from_str_radix(&high_hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some((low, high))
}

fn projected_uuid(bytes: Vec<u8>, message: &'static str) -> Result<uuid::Uuid, rusqlite::Error> {
    Ok(projected_id(bytes, message)?.uuid())
}

fn optional_projected_uuid(bytes: Option<Vec<u8>>) -> Result<Option<uuid::Uuid>, rusqlite::Error> {
    bytes
        .map(|bytes| projected_uuid(bytes, "invalid projected ID"))
        .transpose()
}

fn proposition_activity_from_projecteds(
    revisions: &[RevisionProjectedRow],
    deliberations: &[DeliberationProjectedRow],
    consensus_by_deliberation: &std::collections::HashMap<uuid::Uuid, ConsensusProjectedRow>,
    active_participants: &std::collections::HashMap<
        uuid::Uuid,
        std::collections::HashSet<uuid::Uuid>,
    >,
    decisions: &std::collections::HashMap<uuid::Uuid, std::collections::HashSet<uuid::Uuid>>,
    actor: Option<uuid::Uuid>,
    summary_revision_id: Option<uuid::Uuid>,
) -> (PropositionActivityProjected, Option<uuid::Uuid>) {
    let revision_ids = revisions
        .iter()
        .map(|revision| revision.revision_id)
        .collect::<std::collections::HashSet<_>>();
    let parents = revisions
        .iter()
        .filter_map(|revision| {
            revision
                .parent_revision_id
                .map(|parent| (parent, revision.revision_id))
        })
        .collect::<Vec<_>>();
    let tips = revision_ids
        .iter()
        .filter(|id| !parents.iter().any(|(parent, _)| parent == *id))
        .copied()
        .collect::<Vec<_>>();
    let mut pending_revision_id = None;
    let mut pending_deliberation_id = None;
    let mut pending_participant_count = 0;
    let mut current_actor_pending = false;
    let mut has_pending_revision = false;
    let mut tip_statuses = Vec::new();

    for tip in &tips {
        let tip_deliberations = deliberations
            .iter()
            .filter(|deliberation| deliberation.revision_id == *tip)
            .collect::<Vec<_>>();
        let status = match tip_deliberations.as_slice() {
            [] => "awaiting-deliberation".to_owned(),
            [deliberation] => {
                let deliberation_id = deliberation.deliberation_id;
                if !deliberation.settled {
                    let active = active_participants.get(&deliberation_id);
                    let decided = decisions.get(&deliberation_id);
                    let unresolved = active.map_or(0, |active| {
                        active
                            .iter()
                            .filter(|actor| decided.is_none_or(|decided| !decided.contains(actor)))
                            .count()
                    });
                    pending_revision_id = Some(*tip);
                    pending_deliberation_id = Some(deliberation_id);
                    pending_participant_count = unresolved;
                    current_actor_pending = actor.is_some_and(|actor| {
                        active.is_some_and(|active| active.contains(&actor))
                            && decided.is_none_or(|decided| !decided.contains(&actor))
                    });
                    "pending".to_owned()
                } else {
                    consensus_by_deliberation
                        .get(&deliberation_id)
                        .filter(|consensus| consensus.revision_id == *tip)
                        .map_or_else(
                            || "settled".to_owned(),
                            |consensus| consensus.consensus.clone(),
                        )
                }
            }
            _ => "ambiguous".to_owned(),
        };
        if matches!(status.as_str(), "pending" | "awaiting-deliberation") {
            has_pending_revision = true;
            if status == "awaiting-deliberation" {
                pending_revision_id = Some(*tip);
                current_actor_pending = actor.is_some();
            }
        }
        tip_statuses.push((*tip, status));
    }

    let (latest_revision_id, latest_revision_status) = if tips.len() == 1 {
        tip_statuses
            .into_iter()
            .next()
            .map_or((None, "missing".to_owned()), |(id, status)| {
                (Some(id), status)
            })
    } else if tips.is_empty() {
        (None, "missing".to_owned())
    } else {
        (None, "ambiguous".to_owned())
    };
    if tips.len() != 1 {
        pending_revision_id = None;
        pending_deliberation_id = None;
        pending_participant_count = 0;
        current_actor_pending = false;
    }

    (
        PropositionActivityProjected {
            latest_revision_id,
            latest_revision_status,
            pending_revision_id,
            pending_deliberation_id,
            pending_participant_count,
            current_actor_pending,
            has_pending_revision,
        },
        summary_revision_id.or(latest_revision_id),
    )
}

fn last_common_settled_ancestor(
    parents: &std::collections::HashMap<fact_core::ObjectId, Option<fact_core::ObjectId>>,
    candidates: &[(
        String,
        fact_core::ObjectId,
        fact_core::ObjectId,
        fact_core::ObjectId,
    )],
    maximal: &[&(
        String,
        fact_core::ObjectId,
        fact_core::ObjectId,
        fact_core::ObjectId,
    )],
) -> Option<(
    String,
    fact_core::ObjectId,
    fact_core::ObjectId,
    fact_core::ObjectId,
)> {
    candidates
        .iter()
        .filter(|candidate| {
            maximal.iter().all(|tip| {
                candidate.1 == tip.1 || revision_is_ancestor(parents, candidate.1, tip.1)
            })
        })
        .max_by_key(|candidate| revision_depth(parents, candidate.1))
        .cloned()
}

fn revision_depth(
    parents: &std::collections::HashMap<fact_core::ObjectId, Option<fact_core::ObjectId>>,
    revision: fact_core::ObjectId,
) -> usize {
    let mut current = revision;
    let mut depth = 0;
    while let Some(Some(parent)) = parents.get(&current) {
        depth += 1;
        current = *parent;
    }
    depth
}

fn revision_is_ancestor(
    parents: &std::collections::HashMap<fact_core::ObjectId, Option<fact_core::ObjectId>>,
    ancestor: fact_core::ObjectId,
    descendant: fact_core::ObjectId,
) -> bool {
    let mut current = descendant;
    while let Some(Some(parent)) = parents.get(&current) {
        if *parent == ancestor {
            return true;
        }
        current = *parent;
    }
    false
}

fn optional_projected_id(
    bytes: Option<Vec<u8>>,
) -> Result<Option<fact_core::ObjectId>, rusqlite::Error> {
    bytes
        .map(|bytes| projected_id(bytes, "invalid projected ID"))
        .transpose()
}

fn parse_object_id_text(value: Option<&serde_json::Value>) -> Result<fact_core::ObjectId, Error> {
    value
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::InvalidLineage)?
        .parse::<fact_core::ObjectId>()
        .map_err(|_| Error::InvalidLineage)
}

fn parse_optional_object_id_text(
    value: Option<&serde_json::Value>,
) -> Result<Option<fact_core::ObjectId>, Error> {
    match value {
        Some(value) if value.is_null() => Ok(None),
        Some(value) => Ok(Some(parse_object_id_text(Some(value))?)),
        None => Err(Error::InvalidLineage),
    }
}

fn bootstrap_cycle_ids(
    objects: &[ValidatedObject],
) -> Result<std::collections::HashSet<Vec<u8>>, Error> {
    let mut ids = std::collections::HashSet::new();
    for object in objects
        .iter()
        .filter(|object| object.object_type == "genesis")
    {
        ids.insert(object.id.clone());
        for (dependency_id, _, _) in &object.dependencies {
            if objects.iter().any(|candidate| {
                candidate.id == *dependency_id
                    && matches!(
                        candidate.object_type.as_str(),
                        "actor"
                            | "key"
                            | "actor_key_binding"
                            | "authorization_grant"
                            | "namespace_assertion"
                    )
            }) {
                ids.insert(dependency_id.clone());
            }
        }
        let value: serde_json::Value =
            serde_json::from_slice(&object.canonical).map_err(|_| Error::Metadata)?;
        let body = value
            .get("body")
            .and_then(serde_json::Value::as_object)
            .ok_or(Error::Metadata)?;
        let root_grant = parse_object_id_text(body.get("root_grant"))?;
        if objects
            .iter()
            .any(|candidate| candidate.id.as_slice() == root_grant.uuid().as_bytes())
        {
            ids.insert(root_grant.uuid().as_bytes().to_vec());
        }
    }
    Ok(ids)
}

fn parse_capability(value: &serde_json::Value) -> Result<fact_state::Capability, Error> {
    match value.as_str().ok_or(Error::InvalidLineage)? {
        "propose" => Ok(fact_state::Capability::Propose),
        "deliberate" => Ok(fact_state::Capability::Deliberate),
        "invite" => Ok(fact_state::Capability::Invite),
        "comment" => Ok(fact_state::Capability::Comment),
        "accept" => Ok(fact_state::Capability::Accept),
        "reject" => Ok(fact_state::Capability::Reject),
        "withdraw" => Ok(fact_state::Capability::Withdraw),
        "archive" => Ok(fact_state::Capability::Archive),
        "admin" => Ok(fact_state::Capability::Admin),
        _ => Err(Error::InvalidLineage),
    }
}

fn parse_validity(
    value: Option<&serde_json::Value>,
) -> Result<Option<fact_state::ValidityWindow>, Error> {
    let Some(value) = value else { return Ok(None) };
    if value.is_null() {
        return Ok(None);
    }
    let object = value.as_object().ok_or(Error::InvalidLineage)?;
    let from = object
        .get("valid_from")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::InvalidLineage)?;
    let expires = match object.get("expires_at") {
        Some(v) if v.is_null() => None,
        Some(v) => Some(v.as_str().ok_or(Error::InvalidLineage)?),
        None => return Err(Error::InvalidLineage),
    };
    Ok(Some(fact_state::ValidityWindow {
        valid_from_millis: Some(
            fact_core::timestamp_millis(from).map_err(|_| Error::InvalidLineage)?,
        ),
        expires_at_millis: expires
            .map(|s| fact_core::timestamp_millis(s).map_err(|_| Error::InvalidLineage))
            .transpose()?,
    }))
}

fn parse_scope(
    value: Option<&serde_json::Value>,
    closure: Option<&std::collections::HashMap<Vec<u8>, serde_json::Value>>,
) -> Result<fact_state::Scope, Error> {
    let scope = value
        .and_then(serde_json::Value::as_object)
        .ok_or(Error::InvalidLineage)?;
    match scope
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::InvalidLineage)?
    {
        "ledger" => Ok(fact_state::Scope::Ledger),
        "namespace" => Ok(fact_state::Scope::Namespace(
            scope
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidLineage)?
                .to_owned(),
        )),
        "proposition" => Ok(fact_state::Scope::Proposition(parse_object_id_text(
            scope.get("id"),
        )?)),
        "revision" => {
            let revision = parse_object_id_text(scope.get("id"))?;
            let Some(closure) = closure else {
                return Ok(fact_state::Scope::Revision(revision));
            };
            let Some(value) = closure.get(revision.uuid().as_bytes().as_slice()) else {
                return Ok(fact_state::Scope::Revision(revision));
            };
            let proposition = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .and_then(|body| body.get("proposition_id"))
                .map(|value| parse_object_id_text(Some(value)))
                .transpose()?;
            Ok(
                proposition.map_or(fact_state::Scope::Revision(revision), |proposition| {
                    fact_state::Scope::RevisionIn {
                        revision,
                        proposition,
                    }
                }),
            )
        }
        "deliberation" => {
            let deliberation = parse_object_id_text(scope.get("id"))?;
            let Some(closure) = closure else {
                return Ok(fact_state::Scope::Deliberation(deliberation));
            };
            let Some(value) = closure.get(deliberation.uuid().as_bytes().as_slice()) else {
                return Ok(fact_state::Scope::Deliberation(deliberation));
            };
            let Some(body) = value.get("body").and_then(serde_json::Value::as_object) else {
                return Ok(fact_state::Scope::Deliberation(deliberation));
            };
            let proposition = parse_object_id_text(body.get("proposition_id"))?;
            let revision = parse_object_id_text(body.get("revision_id"))?;
            Ok(fact_state::Scope::DeliberationIn {
                deliberation,
                proposition,
                revision,
            })
        }
        "actor" => Ok(fact_state::Scope::Actor(parse_object_id_text(
            scope.get("id"),
        )?)),
        "capability_class" => Ok(fact_state::Scope::CapabilityClass(parse_capability(
            scope.get("capability").ok_or(Error::InvalidLineage)?,
        )?)),
        _ => Err(Error::InvalidLineage),
    }
}

fn action_descriptor(
    object_type: &str,
    object: &serde_json::Map<String, serde_json::Value>,
    closure: &std::collections::HashMap<Vec<u8>, serde_json::Value>,
    ledger: fact_core::ObjectId,
) -> Result<Option<(fact_state::Capability, fact_state::Target, bool)>, Error> {
    let body = object
        .get("body")
        .and_then(serde_json::Value::as_object)
        .ok_or(Error::Metadata)?;
    let object_id = parse_object_id_text(object.get("id"))?;
    let target_for_deliberation =
        |deliberation_id: fact_core::ObjectId| -> Result<fact_state::Target, Error> {
            let value = closure
                .get(deliberation_id.uuid().as_bytes().as_slice())
                .ok_or(Error::InvalidLineage)?;
            let body = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::InvalidLineage)?;
            Ok(fact_state::Target::Deliberation {
                ledger,
                proposition: parse_object_id_text(body.get("proposition_id"))?,
                revision: parse_object_id_text(body.get("revision_id"))?,
                deliberation: deliberation_id,
            })
        };
    let target_for_invitation =
        |invitation_id: fact_core::ObjectId| -> Result<fact_state::Target, Error> {
            let value = closure
                .get(invitation_id.uuid().as_bytes().as_slice())
                .ok_or(Error::InvalidLineage)?;
            let body = value
                .get("body")
                .and_then(serde_json::Value::as_object)
                .ok_or(Error::InvalidLineage)?;
            if let Some(proposition) = body.get("proposition_id") {
                return Ok(fact_state::Target::Proposition {
                    ledger,
                    proposition: parse_object_id_text(Some(proposition))?,
                });
            }
            let deliberation = parse_object_id_text(body.get("deliberation_id"))?;
            target_for_deliberation(deliberation)
        };
    let result = match object_type {
        "proposition" => Some((
            fact_state::Capability::Propose,
            fact_state::Target::Ledger(ledger),
            false,
        )),
        "revision" => Some((
            fact_state::Capability::Propose,
            fact_state::Target::Revision {
                ledger,
                proposition: parse_object_id_text(body.get("proposition_id"))?,
                revision: parse_object_id_text(body.get("revision_id"))?,
            },
            false,
        )),
        "deliberation" => Some((
            fact_state::Capability::Deliberate,
            fact_state::Target::Revision {
                ledger,
                proposition: parse_object_id_text(body.get("proposition_id"))?,
                revision: parse_object_id_text(body.get("revision_id"))?,
            },
            false,
        )),
        "decision" => {
            let deliberation = parse_object_id_text(body.get("deliberation_id"))?;
            let capability = match body.get("value").and_then(serde_json::Value::as_str) {
                Some("accepted") => fact_state::Capability::Accept,
                Some("rejected") => fact_state::Capability::Reject,
                _ => return Err(Error::InvalidLineage),
            };
            Some((capability, target_for_deliberation(deliberation)?, false))
        }
        "deliberation_comment" => Some((
            fact_state::Capability::Comment,
            target_for_deliberation(parse_object_id_text(body.get("deliberation_id"))?)?,
            false,
        )),
        "standing_participant_change" => Some((
            fact_state::Capability::Deliberate,
            fact_state::Target::Proposition {
                ledger,
                proposition: parse_object_id_text(body.get("proposition_id"))?,
            },
            false,
        )),
        "deliberation_participant_change" => {
            let participant = parse_object_id_text(body.get("participant_actor_id"))?;
            let operation = body
                .get("operation")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidLineage)?;
            let self_change = body
                .get("authorization_ref")
                .is_some_and(serde_json::Value::is_null)
                && parse_object_id_text(object.get("actor_id"))? == participant;
            if self_change && matches!(operation, "join" | "leave") {
                None
            } else {
                Some((
                    fact_state::Capability::Deliberate,
                    target_for_deliberation(parse_object_id_text(body.get("deliberation_id"))?)?,
                    false,
                ))
            }
        }
        "participant_invitation" => {
            if let Some(proposition) = body.get("proposition_id") {
                Some((
                    fact_state::Capability::Invite,
                    fact_state::Target::Proposition {
                        ledger,
                        proposition: parse_object_id_text(Some(proposition))?,
                    },
                    false,
                ))
            } else {
                let deliberation = parse_object_id_text(body.get("deliberation_id"))?;
                Some((
                    fact_state::Capability::Invite,
                    target_for_deliberation(deliberation)?,
                    false,
                ))
            }
        }
        "invitation_lifecycle" => {
            let operation = body
                .get("operation")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::InvalidLineage)?;
            if operation == "decline" {
                None
            } else {
                Some((
                    fact_state::Capability::Invite,
                    target_for_invitation(parse_object_id_text(body.get("invitation_id"))?)?,
                    false,
                ))
            }
        }
        "authorization_grant"
        | "authorization_revocation"
        | "delegation"
        | "delegation_revocation" => Some((
            fact_state::Capability::Admin,
            fact_state::Target::Administration {
                ledger,
                capability: fact_state::Capability::Admin,
            },
            true,
        )),
        "namespace_assertion" => Some((
            fact_state::Capability::Admin,
            fact_state::Target::Namespace(
                body.get("namespace")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::InvalidLineage)?
                    .to_owned(),
            ),
            true,
        )),
        "key_lifecycle" | "actor_lifecycle" => {
            let affected = parse_object_id_text(body.get("affected_actor_id"))?;
            let self_authorized = parse_object_id_text(object.get("actor_id"))? == affected
                && body
                    .get("authorization_ref")
                    .is_some_and(serde_json::Value::is_null);
            if self_authorized {
                None
            } else {
                Some((
                    fact_state::Capability::Admin,
                    fact_state::Target::Actor {
                        ledger,
                        actor: affected,
                    },
                    true,
                ))
            }
        }
        "proposition_lifecycle" => {
            let capability = match body.get("operation").and_then(serde_json::Value::as_str) {
                Some("withdraw") | Some("restore") => fact_state::Capability::Withdraw,
                Some("archive") | Some("unarchive") => fact_state::Capability::Archive,
                _ => return Err(Error::InvalidLineage),
            };
            Some((
                capability,
                fact_state::Target::Proposition {
                    ledger,
                    proposition: parse_object_id_text(body.get("proposition_id"))?,
                },
                false,
            ))
        }
        _ => None,
    };
    let _ = object_id;
    Ok(result)
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
    if bits >= 6 || accumulator != 0 {
        None
    } else {
        Some(output)
    }
}

fn unique_tokens(mut tokens: Vec<String>) -> Vec<String> {
    tokens.sort();
    tokens.dedup();
    tokens
}

fn token_frequencies(tokens: &[String]) -> BTreeMap<String, u64> {
    let mut frequencies = BTreeMap::new();
    for token in tokens {
        *frequencies.entry(token.clone()).or_default() += 1;
    }
    frequencies
}

fn parse_term_frequencies(text: &str) -> Result<BTreeMap<String, u64>, Error> {
    serde_json::from_str(text).map_err(|_| Error::SearchIndex("invalid term frequencies"))
}

fn serialize_search_score(score: f64) -> String {
    let scaled = round_half_even(score * 1_000_000.0) as u64;
    let integer = scaled / 1_000_000;
    let fraction = scaled % 1_000_000;
    if fraction == 0 {
        return integer.to_string();
    }
    let mut fraction = format!("{fraction:06}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!("{integer}.{fraction}")
}

fn round_half_even(value: f64) -> f64 {
    let floor = value.floor();
    let fraction = value - floor;
    if fraction < 0.5 {
        floor
    } else if fraction > 0.5 {
        floor + 1.0
    } else if (floor as u64) & 1 == 0 {
        floor
    } else {
        floor + 1.0
    }
}

fn valid_namespace(namespace: &str) -> bool {
    if namespace.is_empty() {
        return false;
    }
    let bytes = namespace.as_bytes();
    if bytes[0] == b'.'
        || bytes[0] == b'/'
        || bytes[0] == b'-'
        || bytes[bytes.len() - 1] == b'.'
        || bytes[bytes.len() - 1] == b'/'
        || bytes[bytes.len() - 1] == b'-'
    {
        return false;
    }
    let mut previous_separator = false;
    for byte in bytes {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_separator = false;
        } else if (*byte == b'.' || *byte == b'/' || *byte == b'-') && !previous_separator {
            previous_separator = true;
        } else {
            return false;
        }
    }
    true
}
use rusqlite::OptionalExtension;

fn uuid_bytes(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<[u8; 16], Error> {
    let text = object
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(Error::InvalidUuid(field))?;
    let uuid = uuid::Uuid::parse_str(text).map_err(|_| Error::InvalidUuid(field))?;
    if uuid.get_version_num() != 7
        || uuid.get_variant() != uuid::Variant::RFC4122
        || uuid.to_string() != text
    {
        return Err(Error::InvalidUuid(field));
    }
    Ok(*uuid.as_bytes())
}

fn parse_object_id(value: Option<&serde_json::Value>) -> Result<fact_core::ObjectId, Error> {
    value
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::StateProjected)?
        .parse::<fact_core::ObjectId>()
        .map_err(|_| Error::StateProjected)
}
fn make_signed(key: &fact_crypto::SigningKey, value: serde_json::Value) -> Result<Vec<u8>, Error> {
    let payload =
        fact_canonical::encode(&serde_json::to_vec(&value).map_err(|_| Error::Metadata)?)?;
    let object = value.as_object().ok_or(Error::Metadata)?;
    let object_type = object
        .get("object_type")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::Metadata)?;
    let schema = object
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::Metadata)?;
    let ledger = object
        .get("ledger_id")
        .map(|value| {
            value
                .as_str()
                .ok_or(Error::Metadata)
                .and_then(|value| uuid::Uuid::parse_str(value).map_err(|_| Error::Metadata))
                .map(|value| *value.as_bytes())
        })
        .transpose()?;
    let protected = fact_crypto::protocol_protected(key.public_key(), object_type, schema, ledger);
    Ok(fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected, &payload, key,
    )))
}
fn b64url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char)
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 63) as usize] as char)
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_reference_resolution_matches_uuid_and_hash_prefixes() {
        let store = Store::open_memory().unwrap();
        let ledger = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000001").unwrap();
        let actor = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000002").unwrap();
        let key = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000003").unwrap();
        let proposition = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000004").unwrap();
        let revision = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000005").unwrap();
        let proposition_hash = [0xab; 32];
        let revision_hash = [0xcd; 32];
        store
            .create_ledger(ledger.as_bytes(), "resolver.example")
            .unwrap();
        for (object_id, object_type, content_hash) in [
            (proposition, "proposition", proposition_hash),
            (revision, "revision", revision_hash),
        ] {
            store
                .conn
                .execute(
                    "INSERT INTO protocol_object(object_id,ledger_id,object_type,schema_version,actor_id,signing_key_id,payload,content_hash,cose) VALUES(?,?,?,?,?,?,?,?,?)",
                    params![
                        object_id.as_bytes(),
                        ledger.as_bytes(),
                        object_type,
                        "0",
                        actor.as_bytes(),
                        key.as_bytes(),
                        b"{}",
                        content_hash.as_slice(),
                        b"cose",
                    ],
                )
                .unwrap();
        }

        let ambiguous = store
            .resolve_object_reference(ledger.as_bytes(), "01900000-0000", &[])
            .unwrap();
        assert_eq!(ambiguous.len(), 2);

        let propositions = store
            .resolve_object_reference(ledger.as_bytes(), "01900000-0000", &["proposition"])
            .unwrap();
        assert_eq!(propositions.len(), 1);
        assert_eq!(propositions[0].object_id, proposition);

        let hash_matches = store
            .resolve_object_reference(ledger.as_bytes(), "abab", &[])
            .unwrap();
        assert_eq!(hash_matches.len(), 1);
        assert_eq!(
            hash_matches[0].content_hash,
            Hash::from_bytes(proposition_hash)
        );

        assert!(store
            .resolve_object_reference(ledger.as_bytes(), "abab%", &[])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn object_reference_resolution_accepts_split_uuid_short_refs() {
        let store = Store::open_memory().unwrap();
        let ledger = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000001").unwrap();
        let actor = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000002").unwrap();
        let key = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000003").unwrap();
        let first = uuid::Uuid::parse_str("019fb594-bf37-72c3-8c1e-3c8c9254fc4a").unwrap();
        let second = uuid::Uuid::parse_str("019fb594-bf37-76f1-9184-758b0fad5164").unwrap();

        for (object_id, object_type, content_hash) in [
            (first, "revision", numbered_hash(11)),
            (second, "revision", numbered_hash(12)),
        ] {
            store
                .conn
                .execute(
                    "INSERT INTO protocol_object(object_id,ledger_id,object_type,schema_version,actor_id,signing_key_id,payload,content_hash,cose) VALUES(?,?,?,?,?,?,?,?,?)",
                    params![
                        object_id.as_bytes(),
                        ledger.as_bytes(),
                        object_type,
                        "0",
                        actor.as_bytes(),
                        key.as_bytes(),
                        b"{}",
                        content_hash.as_bytes(),
                        b"cose",
                    ],
                )
                .unwrap();
        }

        let leading = store
            .resolve_object_reference(ledger.as_bytes(), "019fb594-bf3", &[])
            .unwrap();
        assert_eq!(leading.len(), 2);

        let first_split = store
            .resolve_object_reference(ledger.as_bytes(), "019fb-3c8c9", &[])
            .unwrap();
        assert_eq!(first_split.len(), 1);
        assert_eq!(first_split[0].object_id, first);

        let second_split = store
            .resolve_object_reference(ledger.as_bytes(), "019fb-758b0", &[])
            .unwrap();
        assert_eq!(second_split.len(), 1);
        assert_eq!(second_split[0].object_id, second);
    }

    #[test]
    fn object_dependency_listing_includes_transitive_neutral_dependencies() {
        let store = Store::open_memory().unwrap();
        let ledger = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000101").unwrap();
        let actor = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000102").unwrap();
        let key = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000103").unwrap();
        let root = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000104").unwrap();
        let neutral = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000105").unwrap();
        let neutral_leaf = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000106").unwrap();
        let unrelated = uuid::Uuid::parse_str("01900000-0000-7000-8000-000000000107").unwrap();
        let root_hash = numbered_hash(101);
        let neutral_hash = numbered_hash(102);
        let neutral_leaf_hash = numbered_hash(103);
        let unrelated_hash = numbered_hash(104);
        store
            .create_ledger(ledger.as_bytes(), "closure.example")
            .unwrap();
        let insert_object = |object_id: uuid::Uuid,
                             ledger_id: Option<&[u8]>,
                             content_hash: Hash| {
            store
                    .conn
                    .execute(
                        "INSERT INTO protocol_object(object_id,ledger_id,object_type,schema_version,actor_id,signing_key_id,payload,content_hash,cose) VALUES(?,?,?,?,?,?,?,?,?)",
                        params![
                            object_id.as_bytes(),
                            ledger_id,
                            "actor",
                            "0",
                            actor.as_bytes(),
                            key.as_bytes(),
                            b"{}",
                            content_hash.as_bytes(),
                            b"cose",
                        ],
                    )
                    .unwrap();
        };
        insert_object(root, Some(ledger.as_bytes()), root_hash);
        insert_object(neutral, None, neutral_hash);
        insert_object(neutral_leaf, None, neutral_leaf_hash);
        insert_object(unrelated, None, unrelated_hash);
        for (object_id, dependency_id, dependency_hash) in [
            (root, neutral, neutral_hash),
            (neutral, neutral_leaf, neutral_leaf_hash),
        ] {
            store
                .conn
                .execute(
                    "INSERT INTO object_dependency(object_id,dependency_id,content_hash,role) VALUES(?,?,?,?)",
                    params![
                        object_id.as_bytes(),
                        dependency_id.as_bytes(),
                        dependency_hash.as_bytes(),
                        "required-dependency",
                    ],
                )
                .unwrap();
        }

        let objects = store
            .list_objects_with_dependencies(ledger.as_bytes())
            .unwrap();
        let export_projected_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM projected_export_object WHERE ledger_id=?",
                [ledger.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(export_projected_count, 3);
        let ids = objects
            .iter()
            .map(|(object_id, _, _)| *object_id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&root));
        assert!(ids.contains(&neutral));
        assert!(ids.contains(&neutral_leaf));
        assert!(!ids.contains(&unrelated));

        let first_page = store
            .list_objects_with_dependencies_page(ledger.as_bytes(), None, 2)
            .unwrap();
        assert_eq!(first_page.len(), 2);
        let second_page = store
            .list_objects_with_dependencies_page(
                ledger.as_bytes(),
                Some(&first_page.last().unwrap().1),
                2,
            )
            .unwrap();
        assert_eq!(second_page.len(), 1);
        assert_eq!(
            first_page
                .iter()
                .chain(second_page.iter())
                .map(|(object_id, _, _)| *object_id)
                .collect::<std::collections::HashSet<_>>(),
            ids
        );
    }

    #[test]
    fn search_index_persists_across_reopen() {
        let path =
            std::env::temp_dir().join(format!("fact-search-index-{}.sqlite", uuid::Uuid::now_v7()));
        let ledger = uuid::Uuid::now_v7();
        let actor = uuid::Uuid::now_v7();
        let key_id = uuid::Uuid::now_v7();
        let hash = numbered_hash(500);
        {
            let store = Store::open(&path).unwrap();
            let index_count: i64 = store
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_index_list('search_document') WHERE name='search_document_ledger_type_hash'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(index_count, 1);
            let ledger_hash_index_count: i64 = store
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_index_list('protocol_object') WHERE name='protocol_object_ledger_hash'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(ledger_hash_index_count, 1);
            store
                .create_ledger(ledger.as_bytes(), "search.example")
                .unwrap();
            let context = ProtocolPayloadContext {
                ledger,
                actor,
                key_id,
            };
            let revision_id = uuid::Uuid::now_v7();
            let markdown = b"# Durable Search\nPersistent index content.\n";
            insert_protocol_payload_with_hash(
                &store,
                context,
                revision_id,
                "revision",
                hash,
                serde_json::json!({
                    "body":{
                        "proposition_id":uuid::Uuid::now_v7(),
                        "revision_id":revision_id,
                        "parent_revision_id":null,
                        "content":{
                            "media_type":"text/markdown; charset=utf-8; variant=fact-v0",
                            "bytes":b64url(markdown),
                            "hash":Hash::digest(markdown).hex()
                        }
                    }
                }),
            );
            store.refresh_search_index_meta(ledger.as_bytes()).unwrap();
            assert!(store.search_index_status(ledger.as_bytes()).unwrap().stale);
            let hits = store
                .search_markdown_index(ledger.as_bytes(), "persistent", 10)
                .unwrap();
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].content_hash, hash);
            assert!(!store.search_index_status(ledger.as_bytes()).unwrap().stale);
        }
        {
            let store = Store::open(&path).unwrap();
            let status = store.search_index_status(ledger.as_bytes()).unwrap();
            assert_eq!(status.canonical_document_count, 1);
            assert_eq!(status.indexed_document_count, 1);
            assert!(!status.stale);
            let hits = store
                .search_markdown_index(ledger.as_bytes(), "persistent", 10)
                .unwrap();
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].content_hash, hash);
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn effective_revision_status_rows_chunks_large_id_sets() {
        let store = Store::open_memory().unwrap();
        let ledger = uuid::Uuid::now_v7();
        let actor = uuid::Uuid::now_v7();
        let key_id = uuid::Uuid::now_v7();
        store
            .create_ledger(ledger.as_bytes(), "revision-chunks.example")
            .unwrap();
        let context = ProtocolPayloadContext {
            ledger,
            actor,
            key_id,
        };
        let mut revision_ids = Vec::new();
        for index in 0..1_200 {
            let proposition_id = uuid::Uuid::now_v7();
            let revision_id = uuid::Uuid::now_v7();
            revision_ids.push(revision_id);
            let markdown = format!("# Chunk {index}\n");
            let markdown_bytes = markdown.as_bytes();
            insert_protocol_payload(
                &store,
                context,
                revision_id,
                "revision",
                10_000 + index,
                serde_json::json!({
                    "body":{
                        "proposition_id":proposition_id,
                        "revision_id":revision_id,
                        "parent_revision_id":null,
                        "content":{
                            "media_type":"text/markdown; charset=utf-8; variant=fact-v0",
                            "bytes":b64url(markdown_bytes),
                            "hash":Hash::digest(markdown_bytes).hex()
                        }
                    }
                }),
            );
            let hash = numbered_hash(10_000 + index);
            store
                .conn
                .execute(
                    "INSERT INTO projected_revision(revision_id,proposition_id,parent_revision_id,content_hash,object_id,payload) VALUES(?,?,?,?,?,?)",
                    params![
                        revision_id.as_bytes(),
                        proposition_id.as_bytes(),
                        Option::<&[u8]>::None,
                        hash.as_bytes(),
                        revision_id.as_bytes(),
                        b"{}",
                    ],
                )
                .unwrap();
            store
                .conn
                .execute(
                    "INSERT INTO projected_effective(proposition_id,status,revision_id,deliberation_id,settlement_id,reason,projected_version) VALUES(?,?,?,?,?,?,?)",
                    params![
                        proposition_id.as_bytes(),
                        "accepted",
                        revision_id.as_bytes(),
                        Option::<&[u8]>::None,
                        Option::<&[u8]>::None,
                        "test",
                        1_i64,
                    ],
                )
                .unwrap();
        }

        let rows = store
            .effective_revision_status_rows(ledger.as_bytes(), &revision_ids)
            .unwrap();
        assert_eq!(rows.len(), revision_ids.len());
        assert!(rows.iter().all(|row| row.status == "accepted"));
        assert_eq!(
            rows.iter()
                .map(|row| row.revision_id)
                .collect::<std::collections::HashSet<_>>(),
            revision_ids
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
        );
    }

    #[test]
    fn search_markdown_index_limits_candidate_rows_before_ranking() {
        let store = Store::open_memory().unwrap();
        let ledger = uuid::Uuid::now_v7();
        let actor = uuid::Uuid::now_v7();
        let key_id = uuid::Uuid::now_v7();
        store
            .create_ledger(ledger.as_bytes(), "bounded-search.example")
            .unwrap();
        let context = ProtocolPayloadContext {
            ledger,
            actor,
            key_id,
        };
        for index in 0..1_200 {
            let revision_id = uuid::Uuid::now_v7();
            let proposition_id = uuid::Uuid::now_v7();
            let markdown = format!("# Search {index}\ncommon candidate content {index}\n");
            let markdown_bytes = markdown.as_bytes();
            insert_protocol_payload(
                &store,
                context,
                revision_id,
                "revision",
                20_000 + index,
                serde_json::json!({
                    "body":{
                        "proposition_id":proposition_id,
                        "revision_id":revision_id,
                        "parent_revision_id":null,
                        "content":{
                            "media_type":"text/markdown; charset=utf-8; variant=fact-v0",
                            "bytes":b64url(markdown_bytes),
                            "hash":Hash::digest(markdown_bytes).hex()
                        }
                    }
                }),
            );
        }

        store.refresh_search_index_meta(ledger.as_bytes()).unwrap();
        #[cfg(debug_assertions)]
        Store::reset_debug_metrics();
        let hits = store
            .search_markdown_index_by_type(ledger.as_bytes(), "common", 7, &["revision"])
            .unwrap();
        assert_eq!(hits.len(), 7);
        #[cfg(debug_assertions)]
        assert_eq!(Store::debug_metrics().search_index_candidate_rows, 7);
    }

    #[test]
    fn deliberation_read_helpers_use_projected_relationships() {
        let store = Store::open_memory().unwrap();
        let ledger = uuid::Uuid::now_v7();
        let actor = uuid::Uuid::now_v7();
        let key_id = uuid::Uuid::now_v7();
        let proposition = uuid::Uuid::now_v7();
        let revision = uuid::Uuid::now_v7();
        let deliberation = uuid::Uuid::now_v7();
        let decision = uuid::Uuid::now_v7();
        let comment = uuid::Uuid::now_v7();
        let change = uuid::Uuid::now_v7();
        let settlement = uuid::Uuid::now_v7();
        let context = ProtocolPayloadContext {
            ledger,
            actor,
            key_id,
        };
        store
            .create_ledger(ledger.as_bytes(), "deliberation-read.example")
            .unwrap();
        insert_protocol_payload(
            &store,
            context,
            revision,
            "revision",
            610,
            serde_json::json!({
                "id": revision,
                "ledger_id": ledger,
                "actor_id": actor,
                "created_at": "2026-08-02T00:00:00.000Z",
                "body": {
                    "revision_id": revision,
                    "proposition_id": proposition,
                    "parent_revision_id": null,
                    "content": {
                        "media_type":"text/markdown; charset=utf-8; variant=fact-v0",
                        "bytes": b64url(b"# Projected\n"),
                        "hash": Hash::digest(b"# Projected\n").hex()
                    }
                }
            }),
        );
        insert_protocol_payload(
            &store,
            context,
            deliberation,
            "deliberation",
            611,
            serde_json::json!({
                "id": deliberation,
                "ledger_id": ledger,
                "actor_id": actor,
                "created_at": "2026-08-02T00:00:01.000Z",
                "body": {
                    "deliberation_id": deliberation,
                    "proposition_id": proposition,
                    "revision_id": revision,
                    "initial_participants": [{"actor_id": actor, "carried_decision_id": null}],
                    "roster_governance": null
                }
            }),
        );
        insert_protocol_payload(
            &store,
            context,
            decision,
            "decision",
            612,
            serde_json::json!({
                "id": decision,
                "ledger_id": ledger,
                "actor_id": actor,
                "created_at": "2026-08-02T00:00:02.000Z",
                "body": {
                    "deliberation_id": deliberation,
                    "participant_actor_id": actor,
                    "value": "accepted",
                    "supersedes_decision_ids": []
                }
            }),
        );
        insert_protocol_payload(
            &store,
            context,
            comment,
            "deliberation_comment",
            613,
            serde_json::json!({
                "id": comment,
                "ledger_id": ledger,
                "actor_id": actor,
                "created_at": "2026-08-02T00:00:03.000Z",
                "body": {
                    "deliberation_id": deliberation,
                    "parent_comment_id": null,
                    "content": {
                        "media_type":"text/markdown; charset=utf-8; variant=fact-v0",
                        "bytes": b64url(b"Projected comment\n"),
                        "hash": Hash::digest(b"Projected comment\n").hex()
                    }
                }
            }),
        );
        store.rebuild_domain_projecteds().unwrap();
        store.rebuild_consensus().unwrap();
        insert_protocol_payload(
            &store,
            context,
            settlement,
            "settlement",
            614,
            serde_json::json!({
                "id": settlement,
                "ledger_id": ledger,
                "actor_id": actor,
                "created_at": "2026-08-02T00:00:04.000Z",
                "body": {
                    "deliberation_id": deliberation,
                    "revision_id": revision,
                    "outcome": "accepted"
                }
            }),
        );
        insert_protocol_payload(
            &store,
            context,
            change,
            "deliberation_participant_change",
            615,
            serde_json::json!({
                "id": change,
                "ledger_id": ledger,
                "actor_id": actor,
                "created_at": "2026-08-02T00:00:04.000Z",
                "body": {
                    "deliberation_id": deliberation,
                    "participant_actor_id": actor,
                    "operation": "join",
                    "predecessor_change_id": null
                }
            }),
        );
        store.rebuild_domain_projecteds().unwrap();

        let deliberations = store
            .list_deliberation_projecteds_by_proposition(ledger.as_bytes(), proposition.as_bytes())
            .unwrap();
        assert_eq!(deliberations.len(), 1);
        assert_eq!(deliberations[0].deliberation_id, deliberation);
        assert_eq!(
            store
                .deliberation_id_for_revision(
                    ledger.as_bytes(),
                    proposition.as_bytes(),
                    revision.as_bytes()
                )
                .unwrap(),
            vec![deliberation]
        );
        let comments = store
            .list_objects_by_deliberation(
                ledger.as_bytes(),
                deliberation.as_bytes(),
                "deliberation_comment",
            )
            .unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].object_id, comment);
        let bulk_comments = store
            .list_objects_by_deliberations(
                ledger.as_bytes(),
                &[deliberation, uuid::Uuid::now_v7()],
                "deliberation_comment",
            )
            .unwrap();
        assert_eq!(bulk_comments.len(), 1);
        assert_eq!(bulk_comments[0].object_id, comment);
        let changes = store
            .list_objects_by_deliberation(
                ledger.as_bytes(),
                deliberation.as_bytes(),
                "deliberation_participant_change",
            )
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].object_id, change);
        let participants = store
            .participant_decisions_for_deliberation(ledger.as_bytes(), deliberation.as_bytes())
            .unwrap();
        assert_eq!(participants.len(), 1);
        assert_eq!(participants[0].actor_id, actor);
        assert!(participants[0].active);
        assert_eq!(participants[0].decision.as_deref(), Some("accepted"));
        let decisions = store
            .list_decision_rows_by_deliberation(ledger.as_bytes(), deliberation.as_bytes())
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].decision_id, decision);
        let settlements = store
            .list_settlement_payloads_by_deliberations(ledger.as_bytes(), &[deliberation])
            .unwrap();
        assert_eq!(settlements.len(), 1);
        assert_eq!(settlements[0].object_id, settlement);
        assert!(store
            .list_settlement_payloads_by_deliberations(ledger.as_bytes(), &[uuid::Uuid::now_v7()])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn object_family_read_helpers_filter_without_full_ledger_scans() {
        let store = Store::open_memory().unwrap();
        let ledger = uuid::Uuid::now_v7();
        let actor = uuid::Uuid::now_v7();
        let key_id = uuid::Uuid::now_v7();
        let source = uuid::Uuid::now_v7();
        let target = uuid::Uuid::now_v7();
        let relationship = uuid::Uuid::now_v7();
        let attestation = uuid::Uuid::now_v7();
        let invitation = uuid::Uuid::now_v7();
        let lifecycle = uuid::Uuid::now_v7();
        let authority = uuid::Uuid::now_v7();
        let context = ProtocolPayloadContext {
            ledger,
            actor,
            key_id,
        };
        store
            .create_ledger(ledger.as_bytes(), "object-family-read.example")
            .unwrap();
        insert_protocol_payload(
            &store,
            context,
            relationship,
            "protocol_relationship",
            700,
            serde_json::json!({
                "id": relationship,
                "ledger_id": ledger,
                "object_type": "protocol_relationship",
                "actor_id": actor,
                "created_at": "2026-08-02T00:00:00.000Z",
                "body": {
                    "source_object_id": source,
                    "relationship": "protocol:references",
                    "relationship_version": 0,
                    "target_object_ids": [target]
                }
            }),
        );
        insert_protocol_payload(
            &store,
            context,
            attestation,
            "identity_attestation",
            701,
            serde_json::json!({
                "id": attestation,
                "ledger_id": ledger,
                "object_type": "identity_attestation",
                "actor_id": actor,
                "created_at": "2026-08-02T00:00:01.000Z",
                "body": {
                    "subject_type": "actor",
                    "subject_id": actor,
                    "claim_type": "display-name",
                    "claims": {"name": "Example"},
                    "evidence_hash": null,
                    "validity": {"valid_from": "2026-08-02T00:00:01.000Z", "expires_at": null}
                }
            }),
        );
        insert_protocol_payload(
            &store,
            context,
            invitation,
            "participant_invitation",
            702,
            serde_json::json!({
                "id": invitation,
                "ledger_id": ledger,
                "object_type": "participant_invitation",
                "actor_id": actor,
                "created_at": "2026-08-02T00:00:02.000Z",
                "body": {
                    "invitation_id": invitation,
                    "proposition_id": source,
                    "inviting_actor_id": actor,
                    "invited_actor_id": target,
                    "participation_type": "standing",
                    "constraints": {},
                    "validity": null,
                    "predecessor_invitation_id": null
                }
            }),
        );
        insert_protocol_payload(
            &store,
            context,
            lifecycle,
            "invitation_lifecycle",
            703,
            serde_json::json!({
                "id": lifecycle,
                "ledger_id": ledger,
                "object_type": "invitation_lifecycle",
                "actor_id": actor,
                "created_at": "2026-08-02T00:00:03.000Z",
                "body": {
                    "invitation_id": invitation,
                    "operation": "decline",
                    "predecessor_lifecycle_ids": [],
                    "reason": "test"
                }
            }),
        );
        insert_protocol_payload(
            &store,
            context,
            authority,
            "authorization_grant",
            704,
            serde_json::json!({
                "id": authority,
                "ledger_id": ledger,
                "object_type": "authorization_grant",
                "actor_id": actor,
                "created_at": "2026-08-02T00:00:04.000Z",
                "body": {
                    "grant_id": authority,
                    "granting_actor_id": actor,
                    "receiving_actor_id": target,
                    "capabilities": ["comment", "deliberate"],
                    "scope": {"type": "ledger"},
                    "validity": null,
                    "constraints": {},
                    "predecessor_grant_id": null
                }
            }),
        );
        let relationship_payload = store.get_payload(relationship.as_bytes()).unwrap().unwrap();
        store
            .conn
            .execute(
                "INSERT INTO protocol_relationship(object_id,ledger_id,object_type,source_object_id,relationship,target_object_ids,payload) VALUES(?,?,?,?,?,?,?)",
                params![
                    relationship.as_bytes(),
                    ledger.as_bytes(),
                    "protocol_relationship",
                    source.as_bytes(),
                    "protocol:references",
                    fact_canonical::encode(
                        &serde_json::to_vec(&serde_json::json!([target])).unwrap()
                    )
                    .unwrap(),
                    relationship_payload,
                ],
            )
            .unwrap();

        store.rebuild_domain_projecteds().unwrap();
        let relationships = store
            .list_relationship_payloads(
                ledger.as_bytes(),
                Some(source.as_bytes()),
                Some("protocol:references"),
                Some(target.as_bytes()),
            )
            .unwrap();
        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0].object_id, relationship);
        assert!(store
            .list_relationship_payloads(
                ledger.as_bytes(),
                Some(source.as_bytes()),
                Some("protocol:references"),
                Some(actor.as_bytes()),
            )
            .unwrap()
            .is_empty());
        let attestations = store
            .list_identity_attestation_payloads(
                ledger.as_bytes(),
                Some("actor"),
                Some(actor.as_bytes()),
                Some("display-name"),
            )
            .unwrap();
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].object_id, attestation);
        assert!(store
            .list_identity_attestation_payloads(
                ledger.as_bytes(),
                Some("key"),
                Some(actor.as_bytes()),
                Some("display-name"),
            )
            .unwrap()
            .is_empty());
        let invitations = store
            .list_invitation_payloads(
                ledger.as_bytes(),
                Some(source.as_bytes()),
                None,
                Some(target.as_bytes()),
            )
            .unwrap();
        assert_eq!(invitations.len(), 1);
        assert_eq!(invitations[0].object_id, invitation);
        assert!(store
            .list_invitation_payloads(
                ledger.as_bytes(),
                Some(target.as_bytes()),
                None,
                Some(target.as_bytes()),
            )
            .unwrap()
            .is_empty());
        let lifecycles = store
            .list_lifecycle_rows(
                ledger.as_bytes(),
                "invitation_lifecycle",
                Some(invitation.as_bytes()),
            )
            .unwrap();
        assert_eq!(lifecycles.len(), 1);
        assert_eq!(lifecycles[0].object_id, lifecycle);
        assert_eq!(lifecycles[0].target_id, Some(invitation));
        assert_eq!(lifecycles[0].operation, "decline");
        let authority_grants = store
            .list_authority_grant_payloads(ledger.as_bytes(), target.as_bytes(), "comment")
            .unwrap();
        assert_eq!(authority_grants.len(), 1);
        assert_eq!(authority_grants[0].object_id, authority);
        assert!(store
            .list_authority_grant_payloads(ledger.as_bytes(), actor.as_bytes(), "comment")
            .unwrap()
            .is_empty());
        let plan = store
            .conn
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT a.object_id,p.content_hash,'authorization_grant',a.payload
                 FROM projected_authority a
                 JOIN protocol_object p ON p.object_id=a.object_id
                 WHERE p.ledger_id=? AND a.receiving_actor_id=? AND a.capability=? AND a.revoked=0
                 ORDER BY a.object_id",
            )
            .unwrap()
            .query_map(
                params![ledger.as_bytes(), target.as_bytes(), "comment"],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|detail| detail.contains("projected_authority_actor_capability")),
            "authority lookup should use receiving-actor/capability index, got plan: {plan:?}"
        );
    }

    #[test]
    fn action_descriptor_separates_comments_and_participant_changes() {
        let ledger = fact_core::ObjectId::new_v7();
        let proposition = fact_core::ObjectId::new_v7();
        let revision = fact_core::ObjectId::new_v7();
        let deliberation = fact_core::ObjectId::new_v7();
        let actor = fact_core::ObjectId::new_v7();
        let action = fact_core::ObjectId::new_v7();
        let deliberation_value = serde_json::json!({
            "body": {
                "proposition_id": proposition,
                "revision_id": revision
            }
        });
        let mut closure = std::collections::HashMap::new();
        closure.insert(deliberation.uuid().as_bytes().to_vec(), deliberation_value);

        let comment = serde_json::json!({
            "id": action,
            "body": {"deliberation_id": deliberation}
        });
        let (capability, _, _) = action_descriptor(
            "deliberation_comment",
            comment.as_object().unwrap(),
            &closure,
            ledger,
        )
        .unwrap()
        .unwrap();
        assert_eq!(capability, fact_state::Capability::Comment);

        let self_join = serde_json::json!({
            "id": action,
            "actor_id": actor,
            "body": {
                "deliberation_id": deliberation,
                "participant_actor_id": actor,
                "operation": "join",
                "authorization_ref": null
            }
        });
        assert!(action_descriptor(
            "deliberation_participant_change",
            self_join.as_object().unwrap(),
            &closure,
            ledger,
        )
        .unwrap()
        .is_none());

        let structural = serde_json::json!({
            "id": action,
            "actor_id": actor,
            "body": {
                "deliberation_id": deliberation,
                "participant_actor_id": actor,
                "operation": "leave",
                "authorization_ref": fact_core::ObjectId::new_v7()
            }
        });
        let (capability, target, _) = action_descriptor(
            "deliberation_participant_change",
            structural.as_object().unwrap(),
            &closure,
            ledger,
        )
        .unwrap()
        .unwrap();
        assert_eq!(capability, fact_state::Capability::Deliberate);
        assert!(matches!(target, fact_state::Target::Deliberation { .. }));
    }

    #[test]
    fn verified_insert_preserves_exact_payload() {
        let store = Store::open_memory().unwrap();
        let key = fact_crypto::SigningKey::from_seed(&[7u8; 32]).unwrap();
        let signing_key_id = uuid::Uuid::now_v7();
        let value = serde_json::json!({
            "id": uuid::Uuid::now_v7().to_string(),
            "object_type": "actor",
            "schema_version": "0",
            "actor_id": uuid::Uuid::now_v7().to_string(),
            "signing_key_id": signing_key_id.to_string(),
            "created_at": "2026-07-27T12:00:00.000Z",
            "dependencies": [],
            "body": {
                "actor_type": "agent",
                "bootstrap_key_id": uuid::Uuid::now_v7().to_string(),
                "bootstrap_binding_id": uuid::Uuid::now_v7().to_string()
            }
        });
        let payload = fact_canonical::encode(&serde_json::to_vec(&value).unwrap()).unwrap();
        let protected = fact_crypto::protocol_protected(key.public_key(), "actor", "0", None);
        let cose = fact_crypto::encode_sign1(&fact_crypto::sign1(&protected, &payload, &key));
        store
            .register_key(signing_key_id.as_bytes(), &key.public_key())
            .unwrap();
        let hash = store.insert_verified_object(&cose).unwrap();
        let id = uuid::Uuid::parse_str(value["id"].as_str().unwrap()).unwrap();
        assert_eq!(
            store.get_payload(id.as_bytes()).unwrap(),
            Some(payload.clone())
        );
        assert_eq!(hash, fact_core::Hash::digest(&payload));
        let dependent = |dependency: serde_json::Value| {
            let value = serde_json::json!({
                "id": uuid::Uuid::now_v7().to_string(),
                "object_type": "actor",
                "schema_version": "0",
                "actor_id": uuid::Uuid::now_v7().to_string(),
                "signing_key_id": signing_key_id.to_string(),
                "created_at": "2026-07-27T12:00:00.000Z",
                "dependencies": [dependency],
                "body": {
                    "actor_type": "agent",
                    "bootstrap_key_id": uuid::Uuid::now_v7().to_string(),
                    "bootstrap_binding_id": uuid::Uuid::now_v7().to_string()
                }
            });
            let payload = fact_canonical::encode(&serde_json::to_vec(&value).unwrap()).unwrap();
            let protected = fact_crypto::protocol_protected(key.public_key(), "actor", "0", None);
            fact_crypto::encode_sign1(&fact_crypto::sign1(&protected, &payload, &key))
        };
        let missing = dependent(serde_json::json!({
            "object_id": uuid::Uuid::now_v7(),
            "content_hash": "00".repeat(32),
            "role": "required-dependency"
        }));
        assert!(matches!(
            store.insert_verified_object(&missing),
            Err(Error::MissingDependency)
        ));
        let before: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM protocol_object", [], |row| row.get(0))
            .unwrap();
        assert!(matches!(
            store.insert_verified_bundle(std::slice::from_ref(&missing)),
            Err(Error::MissingDependency)
        ));
        let after: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM protocol_object", [], |row| row.get(0))
            .unwrap();
        assert_eq!(before, after);
        let wrong_hash = dependent(serde_json::json!({
            "object_id": value["id"].clone(),
            "content_hash": "00".repeat(32),
            "role": "required-dependency"
        }));
        assert!(matches!(
            store.insert_verified_object(&wrong_hash),
            Err(Error::DependencyHashMismatch)
        ));
        let mut mutated = cose;
        let last = mutated.len() - 1;
        mutated[last] ^= 1;
        assert!(matches!(
            store.insert_verified_object(&mutated),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn bootstrap_creates_signed_authority_cycle_atomically() {
        let store = Store::open_memory().unwrap();
        let result = store
            .bootstrap_ledger(
                "example.test",
                "2026-07-27T12:00:00.000Z",
                [3u8; 32],
                [8u8; 16],
            )
            .unwrap();
        assert_eq!(result.object_hashes.len(), 6);
        assert_eq!(result.cose_objects.len(), 6);
        assert_eq!(store.list_ledgers().unwrap().len(), 1);
        let metadata = store.list_ledger_metadata().unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].0, result.ledger_id.to_string());
        assert_eq!(metadata[0].1, "example.test");
        assert!(metadata[0].2.is_some());
        store.rebuild_projecteds().unwrap();
        assert!(store.rebuild_consensus().unwrap().is_empty());
        let consensus_count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM projected_consensus", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(consensus_count, 0);
        let projected_count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM projected_object", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(projected_count, 6);
        let backup_path =
            std::env::temp_dir().join(format!("fact-backup-{}.sqlite", uuid::Uuid::now_v7()));
        store.backup_to(&backup_path).unwrap();
        let restored = Store::open(&backup_path).unwrap();
        assert_eq!(restored.list_ledgers().unwrap().len(), 1);
        assert_eq!(
            restored
                .list_objects(result.ledger_id.as_bytes())
                .unwrap()
                .len(),
            3
        );
        let mut restored_in_place = Store::open_memory().unwrap();
        restored_in_place.restore_from(&backup_path).unwrap();
        assert_eq!(restored_in_place.list_ledgers().unwrap().len(), 1);
        assert_eq!(
            restored_in_place
                .list_objects(result.ledger_id.as_bytes())
                .unwrap()
                .len(),
            3
        );
        std::fs::remove_file(backup_path).unwrap();
        for (table, expected) in [
            ("projected_actor", 1),
            ("projected_key", 1),
            ("projected_binding", 1),
            ("projected_authority", 1),
        ] {
            let count: i64 = store
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, expected, "domain projected {table}");
        }
        for table in [
            "protocol_actor",
            "protocol_key",
            "protocol_actor_key_binding",
            "protocol_authorization_grant",
            "protocol_namespace_assertion",
            "protocol_genesis",
        ] {
            let count: i64 = store
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 1, "typed table {table}");
        }
        let genesis = fact_crypto::decode_sign1(result.cose_objects.last().unwrap()).unwrap();
        assert!(fact_crypto::verify_sign1(
            fact_crypto::SigningKey::from_seed(&[3u8; 32])
                .unwrap()
                .public_key(),
            &genesis
        )
        .is_ok());
        let failed = store.bootstrap_ledger("broken.test", "not-a-timestamp", [3u8; 32], [8u8; 16]);
        assert!(failed.is_err());
        assert_eq!(store.list_ledgers().unwrap().len(), 1);
    }

    #[test]
    fn fresh_store_import_stages_key_material_from_identity_bundle() {
        let source = Store::open_memory().unwrap();
        let bootstrap = source
            .bootstrap_ledger(
                "import.example",
                "2026-07-27T12:00:00.000Z",
                [33u8; 32],
                [34u8; 16],
            )
            .unwrap();
        assert_eq!(
            source
                .list_objects_with_dependencies(bootstrap.ledger_id.as_bytes())
                .unwrap()
                .len(),
            6
        );
        let destination = Store::open_memory().unwrap();
        destination
            .insert_verified_bundle(&bootstrap.cose_objects)
            .unwrap();
        destination.rebuild_projecteds().unwrap();
        assert!(destination.rebuild_consensus().is_ok());
        assert_eq!(
            destination
                .list_objects(bootstrap.ledger_id.as_bytes())
                .unwrap()
                .len(),
            3
        );
        let key_material: i64 = destination
            .conn
            .query_row("SELECT COUNT(*) FROM key_material", [], |row| row.get(0))
            .unwrap();
        assert_eq!(key_material, 1);
        assert_eq!(
            destination.list_ledger_metadata().unwrap()[0].1,
            "import.example"
        );
    }

    #[test]
    fn migration_upgrades_legacy_projection_and_rebuilds_it() {
        let path = std::env::temp_dir().join(format!(
            "fact-legacy-migration-{}.sqlite",
            uuid::Uuid::now_v7()
        ));
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE schema_migration(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
                     INSERT INTO schema_migration(version, applied_at) VALUES(1, '2026-07-27T00:00:00.000Z');
                     CREATE TABLE projection_effective(
                         proposition_id BLOB PRIMARY KEY,
                         status TEXT NOT NULL,
                         revision_id BLOB,
                         deliberation_id BLOB,
                         settlement_id BLOB,
                         reason TEXT NOT NULL,
                         projection_version TEXT NOT NULL
                     );
                     INSERT INTO projection_effective(
                         proposition_id,
                         status,
                         revision_id,
                         deliberation_id,
                         settlement_id,
                         reason,
                         projection_version
                     ) VALUES (
                         X'00000000000000000000000000000001',
                         'pending',
                         NULL,
                         NULL,
                         NULL,
                         'legacy-row',
                         'effective-v0'
                     );",
                )
                .unwrap();
        }

        let store = Store::open(&path).unwrap();
        let markers = store
            .conn
            .prepare("SELECT version FROM schema_migration ORDER BY version")
            .unwrap()
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(markers, vec![1, 2]);
        for column in ["withdrawal_status", "archival_status"] {
            let present: i64 = store
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('projected_effective') WHERE name=?",
                    [column],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(present, 1, "upgraded column {column}");
        }
        let legacy_table_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='projection_effective'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_table_count, 0);
        let legacy_row_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM projected_effective WHERE reason='legacy-row' AND projected_version='effective-v0'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_row_count, 1);

        let bootstrap = store
            .bootstrap_ledger(
                "legacy.example",
                "2026-07-27T12:00:00.000Z",
                [19u8; 32],
                [23u8; 16],
            )
            .unwrap();
        store.rebuild_projecteds().unwrap();
        let projected_count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM projected_object", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(projected_count, bootstrap.object_hashes.len() as i64);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn wal_reopen_recovers_uncommitted_writer_transaction() {
        let path =
            std::env::temp_dir().join(format!("fact-wal-recovery-{}.sqlite", uuid::Uuid::now_v7()));
        {
            let store = Store::open(&path).unwrap();
            store
                .conn
                .execute_batch("BEGIN IMMEDIATE; INSERT INTO object_receipt(receipt_id,object_id,content_hash,disposition_code,evaluated_at,payload) VALUES(X'00000000000000000000000000000000',X'00000000000000000000000000000000',zeroblob(32),'accepted','2026-07-27T12:00:00.000Z',X'00');")
                .unwrap();
        }
        let reopened = Store::open(&path).unwrap();
        let integrity: String = reopened
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        let receipts: i64 = reopened
            .conn
            .query_row("SELECT COUNT(*) FROM object_receipt", [], |row| row.get(0))
            .unwrap();
        assert_eq!(receipts, 0);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn durability_policy_selects_sqlite_synchronous_mode() {
        let normal = Store::open_memory_with_durability(Durability::Normal).unwrap();
        let normal_mode: i64 = normal
            .conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(normal_mode, 1);

        let full = Store::open_memory_with_durability(Durability::Full).unwrap();
        let full_mode: i64 = full
            .conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(full_mode, 2);
    }

    #[test]
    fn consensus_projected_rebuilds_from_deliberation_and_decision_objects() {
        let store = Store::open_memory().unwrap();
        let key = fact_crypto::SigningKey::from_seed(&[11u8; 32]).unwrap();
        let key_id = uuid::Uuid::now_v7();
        let ledger = uuid::Uuid::now_v7();
        let actor = uuid::Uuid::now_v7();
        let deliberation_id = uuid::Uuid::now_v7();
        let proposition_id = uuid::Uuid::now_v7();
        let revision_id = uuid::Uuid::now_v7();
        store
            .create_ledger(ledger.as_bytes(), "example.test")
            .unwrap();
        store
            .register_key(key_id.as_bytes(), &key.public_key())
            .unwrap();
        let signed = |id: uuid::Uuid, object_type: &str, body: serde_json::Value| {
            let value = serde_json::json!({
                "id":id.to_string(),
                "ledger_id":ledger.to_string(),
                "object_type":object_type,
                "schema_version":"0",
                "actor_id":actor.to_string(),
                "signing_key_id":key_id.to_string(),
                "created_at":"2026-07-27T12:00:00.000Z",
                "dependencies":[],
                "body":body
            });
            let payload = fact_canonical::encode(&serde_json::to_vec(&value).unwrap()).unwrap();
            let protected = fact_crypto::protocol_protected(
                key.public_key(),
                object_type,
                "0",
                Some(*ledger.as_bytes()),
            );
            fact_crypto::encode_sign1(&fact_crypto::sign1(&protected, &payload, &key))
        };
        let signed_with_dependencies =
            |id: uuid::Uuid,
             object_type: &str,
             body: serde_json::Value,
             dependencies: Vec<(&Vec<u8>, &str)>| {
                let base = signed(id, object_type, body);
                let decoded = fact_crypto::decode_sign1(&base).unwrap();
                let mut value: serde_json::Value =
                    serde_json::from_slice(&decoded.payload).unwrap();
                value["dependencies"] = serde_json::json!(dependencies
                    .iter()
                    .map(|(dependency, role)| {
                        let payload = &fact_crypto::decode_sign1(dependency).unwrap().payload;
                        serde_json::json!({
                            "object_id": serde_json::from_slice::<serde_json::Value>(payload).unwrap()["id"].clone(),
                            "content_hash": Hash::digest(payload).hex(),
                            "role": role
                        })
                    })
                    .collect::<Vec<_>>());
                let payload = fact_canonical::encode(&serde_json::to_vec(&value).unwrap()).unwrap();
                let protected = fact_crypto::protocol_protected(
                    key.public_key(),
                    object_type,
                    "0",
                    Some(*ledger.as_bytes()),
                );
                fact_crypto::encode_sign1(&fact_crypto::sign1(&protected, &payload, &key))
            };
        let content = b"# Fact\n";
        let proposition = signed(
            proposition_id,
            "proposition",
            serde_json::json!({
                "proposition_id":proposition_id.to_string(),
                "purpose":"knowledge",
                "initial_revision_id":revision_id.to_string(),
                "initial_deliberation_id":deliberation_id.to_string()
            }),
        );
        let revision = signed(
            revision_id,
            "revision",
            serde_json::json!({
                "proposition_id":proposition_id.to_string(),
                "revision_id":revision_id.to_string(),
                "parent_revision_id":null,
                "content":{"media_type":"text/markdown; charset=utf-8; variant=fact-v0","bytes":b64url(content),"hash":Hash::digest(content).hex()},
                "relationships":[],
                "reconciliation_manifest":null
            }),
        );
        let deliberation = signed(
            deliberation_id,
            "deliberation",
            serde_json::json!({
                "deliberation_id":deliberation_id.to_string(),
                "proposition_id":proposition_id.to_string(),
                "revision_id":revision_id.to_string(),
                "extends_deliberation_id":null,
                "decision_rule":{"id":"unanimity","version":0,"parameters":{}},
                "join_policy":{"policy_version":0,"mode":"open","attestation_requirements":[]},
                "initial_participants":[{"actor_id":actor.to_string(),"carried_decision_id":null}],
                "roster_governance":null,
                "opening_actor_id":actor.to_string(),
                "comments_closed_on_settlement":true
            }),
        );
        store
            .insert_verified_bundle(&[proposition.clone(), revision.clone(), deliberation.clone()])
            .unwrap();
        let decision_id = uuid::Uuid::now_v7();
        let decision = signed_with_dependencies(
            decision_id,
            "decision",
            serde_json::json!({
                "deliberation_id":deliberation_id.to_string(),
                "participant_actor_id":actor.to_string(),
                "value":"accepted",
                "supersedes_decision_ids":[],
                "authorization_ref":null
            }),
            vec![(&deliberation, "deliberation")],
        );
        let decision_hash = store.insert_verified_object(&decision).unwrap();
        let settlement = signed_with_dependencies(
            uuid::Uuid::now_v7(),
            "settlement",
            serde_json::json!({
                "deliberation_id":deliberation_id.to_string(),
                "revision_id":revision_id.to_string(),
                "decision_rule":{"id":"unanimity","version":0,"parameters":{}},
                "decision_refs":[{"decision_id":decision_id.to_string(),"participant_actor_id":actor.to_string(),"content_hash":decision_hash.hex()}],
                "participant_count":1,
                "decided_count":1,
                "accepted_count":1,
                "rejected_count":0,
                "outcome":"accepted",
                "causal_settlement_point":{"object_id":decision_id.to_string()},
                "producer_type":"participant",
                "producer_id":actor.to_string()
            }),
            vec![(&decision, "decision"), (&deliberation, "deliberation")],
        );
        store.insert_verified_object(&settlement).unwrap();
        let projecteds = store.rebuild_consensus().unwrap();
        assert_eq!(projecteds.len(), 1);
        assert_eq!(projecteds[0].participant_count, 1);
        assert_eq!(projecteds[0].applicable_decision_count, 1);
        assert_eq!(projecteds[0].consensus, "accepted");
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM projected_consensus", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
        let participant_rows: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM projected_participant", [], |row| {
                row.get(0)
            })
            .unwrap();
        let decision_rows: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM projected_decision", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(participant_rows, 1);
        assert_eq!(decision_rows, 1);
        let pending_rows: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM projected_pending", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(pending_rows, 0);
        store.rebuild_projecteds().unwrap();
        let effective: (String, Vec<u8>) = store
            .conn
            .query_row(
                "SELECT status,revision_id FROM projected_effective WHERE proposition_id=?",
                [proposition_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(effective.0, "accepted");
        assert_eq!(effective.1, revision_id.as_bytes());
        let indexed: (String, Vec<u8>, String, i64, String) = store
            .conn
            .query_row(
                "SELECT status,latest_revision_id,latest_revision_status,has_pending_revision,indexed_version
                 FROM indexed_proposition
                 WHERE proposition_id=?",
                [proposition_id.as_bytes()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(indexed.0, "accepted");
        assert_eq!(indexed.1, revision_id.as_bytes());
        assert_eq!(indexed.2, "accepted");
        assert_eq!(indexed.3, 0);
        assert_eq!(indexed.4, "indexed-proposition-v0");

        let second_deliberation_id = uuid::Uuid::now_v7();
        let second_deliberation = signed_with_dependencies(
            second_deliberation_id,
            "deliberation",
            serde_json::json!({
                "deliberation_id":second_deliberation_id.to_string(),
                "proposition_id":proposition_id.to_string(),
                "revision_id":revision_id.to_string(),
                "extends_deliberation_id":null,
                "decision_rule":{"id":"unanimity","version":0,"parameters":{}},
                "join_policy":{"policy_version":0,"mode":"open","attestation_requirements":[]},
                "initial_participants":[{"actor_id":actor.to_string(),"carried_decision_id":null}],
                "roster_governance":null,
                "opening_actor_id":actor.to_string(),
                "comments_closed_on_settlement":true
            }),
            vec![(&proposition, "proposition"), (&revision, "revision")],
        );
        store.insert_verified_object(&second_deliberation).unwrap();
        let second_decision_id = uuid::Uuid::now_v7();
        let second_decision = signed_with_dependencies(
            second_decision_id,
            "decision",
            serde_json::json!({
                "deliberation_id":second_deliberation_id.to_string(),
                "participant_actor_id":actor.to_string(),
                "value":"accepted",
                "supersedes_decision_ids":[],
                "authorization_ref":null
            }),
            vec![(&second_deliberation, "deliberation")],
        );
        let second_decision_hash = store.insert_verified_object(&second_decision).unwrap();
        let second_settlement = signed_with_dependencies(
            uuid::Uuid::now_v7(),
            "settlement",
            serde_json::json!({
                "deliberation_id":second_deliberation_id.to_string(),
                "revision_id":revision_id.to_string(),
                "decision_rule":{"id":"unanimity","version":0,"parameters":{}},
                "decision_refs":[{"decision_id":second_decision_id.to_string(),"participant_actor_id":actor.to_string(),"content_hash":second_decision_hash.hex()}],
                "participant_count":1,
                "decided_count":1,
                "accepted_count":1,
                "rejected_count":0,
                "outcome":"accepted",
                "causal_settlement_point":{"object_id":second_decision_id.to_string()},
                "producer_type":"participant",
                "producer_id":actor.to_string()
            }),
            vec![
                (&second_decision, "decision"),
                (&second_deliberation, "deliberation"),
            ],
        );
        store.insert_verified_object(&second_settlement).unwrap();
        store.rebuild_projecteds().unwrap();
        let compatible_effective: (String, Vec<u8>, String) = store
            .conn
            .query_row(
                "SELECT status,revision_id,reason FROM projected_effective WHERE proposition_id=?",
                [proposition_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(compatible_effective.0, "accepted");
        assert_eq!(compatible_effective.1, revision_id.as_bytes());
        assert_eq!(compatible_effective.2, "compatible-parallel-settlements");

        let replica = Store::open_memory().unwrap();
        replica
            .create_ledger(ledger.as_bytes(), "example.test")
            .unwrap();
        replica
            .register_key(key_id.as_bytes(), &key.public_key())
            .unwrap();
        replica
            .insert_verified_bundle(&[proposition, revision, deliberation, decision, settlement])
            .unwrap();
        replica.rebuild_projecteds().unwrap();
        let replica_effective: (String, Vec<u8>) = replica
            .conn
            .query_row(
                "SELECT status,revision_id FROM projected_effective WHERE proposition_id=?",
                [proposition_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(replica_effective, effective);
    }

    #[test]
    fn bundle_resolves_forward_dependencies_before_writing_edges() {
        let store = Store::open_memory().unwrap();
        let key = fact_crypto::SigningKey::from_seed(&[19u8; 32]).unwrap();
        let key_id = uuid::Uuid::now_v7();
        store
            .register_key(key_id.as_bytes(), &key.public_key())
            .unwrap();
        let actor = |id: uuid::Uuid, dependency: Option<(uuid::Uuid, Hash)>| {
            let dependencies = dependency
                .map(|(object_id, hash)| {
                    serde_json::json!([{
                        "object_id": object_id.to_string(),
                        "content_hash": hash.hex(),
                        "role": "required-dependency"
                    }])
                })
                .unwrap_or_else(|| serde_json::json!([]));
            make_signed(&key, serde_json::json!({
                "id": id.to_string(), "object_type": "actor", "schema_version": "0",
                "actor_id": uuid::Uuid::now_v7().to_string(), "signing_key_id": key_id.to_string(),
                "created_at": "2026-07-27T12:00:00.000Z", "dependencies": dependencies,
                "body": {"actor_type":"agent", "bootstrap_key_id":uuid::Uuid::now_v7().to_string(), "bootstrap_binding_id":uuid::Uuid::now_v7().to_string()}
            })).unwrap()
        };
        let base_id = uuid::Uuid::now_v7();
        let base = actor(base_id, None);
        let base_payload = fact_crypto::decode_sign1(&base).unwrap().payload;
        let base_hash = Hash::digest(&base_payload);
        let dependent_id = uuid::Uuid::now_v7();
        let dependent = actor(dependent_id, Some((base_id, base_hash)));
        let hashes = store
            .insert_verified_bundle(&[dependent.clone(), base.clone()])
            .unwrap();
        assert_eq!(hashes.len(), 2);
        let edge_count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM object_dependency", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(edge_count, 1);

        let store = Store::open_memory().unwrap();
        store
            .register_key(key_id.as_bytes(), &key.public_key())
            .unwrap();
        let hashes = store
            .insert_verified_bundle_slices(&[dependent.as_slice(), base.as_slice()])
            .unwrap();
        assert_eq!(hashes.len(), 2);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn projected_mode_controls_verified_bundle_rebuilds() {
        let store = Store::open_memory().unwrap();
        let key = fact_crypto::SigningKey::from_seed(&[23u8; 32]).unwrap();
        let key_id = uuid::Uuid::now_v7();
        store
            .register_key(key_id.as_bytes(), &key.public_key())
            .unwrap();
        let actor = |id: uuid::Uuid| {
            make_signed(
                &key,
                serde_json::json!({
                    "id": id.to_string(),
                    "object_type": "actor",
                    "schema_version": "0",
                    "actor_id": uuid::Uuid::now_v7().to_string(),
                    "signing_key_id": key_id.to_string(),
                    "created_at": "2026-07-27T12:00:00.000Z",
                    "dependencies": [],
                    "body": {
                        "actor_type": "agent",
                        "bootstrap_key_id": uuid::Uuid::now_v7().to_string(),
                        "bootstrap_binding_id": uuid::Uuid::now_v7().to_string()
                    }
                }),
            )
            .unwrap()
        };

        Store::reset_debug_metrics();
        store
            .insert_verified_bundle_with_projected_mode(
                &[actor(uuid::Uuid::now_v7())],
                ProjectedMode::Defer,
            )
            .unwrap();
        assert_eq!(Store::debug_metrics().projected_rebuilds, 0);

        Store::reset_debug_metrics();
        store
            .insert_verified_bundle_with_projected_mode(
                &[actor(uuid::Uuid::now_v7())],
                ProjectedMode::FullRebuild,
            )
            .unwrap();
        assert_eq!(Store::debug_metrics().projected_rebuilds, 1);

        Store::reset_debug_metrics();
        let incremental_actor = uuid::Uuid::now_v7();
        store
            .insert_verified_bundle_with_projected_mode(
                &[actor(incremental_actor)],
                ProjectedMode::Incremental,
            )
            .unwrap();
        assert_eq!(Store::debug_metrics().projected_rebuilds, 0);
        let projected: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM projected_actor WHERE actor_id=?",
                [incremental_actor.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(projected, 1);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn incremental_projected_mode_refreshes_indexed_proposition() {
        let store = Store::open_memory().unwrap();
        let key = fact_crypto::SigningKey::from_seed(&[29u8; 32]).unwrap();
        let key_id = uuid::Uuid::now_v7();
        let ledger = uuid::Uuid::now_v7();
        let actor = uuid::Uuid::now_v7();
        let proposition_id = uuid::Uuid::now_v7();
        let revision_id = uuid::Uuid::now_v7();
        let deliberation_id = uuid::Uuid::now_v7();
        store
            .create_ledger(ledger.as_bytes(), "indexed-incremental.test")
            .unwrap();
        store
            .register_key(key_id.as_bytes(), &key.public_key())
            .unwrap();
        let signed = |id: uuid::Uuid, object_type: &str, body: serde_json::Value| {
            make_signed(
                &key,
                serde_json::json!({
                    "id": id.to_string(),
                    "ledger_id": ledger.to_string(),
                    "object_type": object_type,
                    "schema_version": "0",
                    "actor_id": actor.to_string(),
                    "signing_key_id": key_id.to_string(),
                    "created_at": "2026-07-27T12:00:00.000Z",
                    "dependencies": [],
                    "body": body
                }),
            )
            .unwrap()
        };
        let content = b"# Indexed\n";
        let proposition = signed(
            proposition_id,
            "proposition",
            serde_json::json!({
                "proposition_id": proposition_id.to_string(),
                "purpose": "knowledge",
                "initial_revision_id": revision_id.to_string(),
                "initial_deliberation_id": deliberation_id.to_string()
            }),
        );
        let revision = signed(
            revision_id,
            "revision",
            serde_json::json!({
                "proposition_id": proposition_id.to_string(),
                "revision_id": revision_id.to_string(),
                "parent_revision_id": null,
                "content": {
                    "media_type": "text/markdown; charset=utf-8; variant=fact-v0",
                    "bytes": b64url(content),
                    "hash": Hash::digest(content).hex()
                },
                "relationships": [],
                "reconciliation_manifest": null
            }),
        );
        let deliberation = signed(
            deliberation_id,
            "deliberation",
            serde_json::json!({
                "deliberation_id": deliberation_id.to_string(),
                "proposition_id": proposition_id.to_string(),
                "revision_id": revision_id.to_string(),
                "extends_deliberation_id": null,
                "decision_rule": {"id": "unanimity", "version": 0, "parameters": {}},
                "join_policy": {"policy_version": 0, "mode": "open", "attestation_requirements": []},
                "initial_participants": [{"actor_id": actor.to_string(), "carried_decision_id": null}],
                "roster_governance": null,
                "opening_actor_id": actor.to_string(),
                "comments_closed_on_settlement": true
            }),
        );

        Store::reset_debug_metrics();
        store
            .insert_verified_bundle_with_projected_mode(
                &[proposition, revision, deliberation],
                ProjectedMode::Incremental,
            )
            .unwrap();
        assert_eq!(Store::debug_metrics().projected_rebuilds, 0);
        let indexed: (String, Vec<u8>, Vec<u8>, i64, i64) = store
            .conn
            .query_row(
                "SELECT status,latest_revision_id,pending_deliberation_id,pending_participant_count,has_pending_revision
                 FROM indexed_proposition
                 WHERE proposition_id=?",
                [proposition_id.as_bytes()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(indexed.0, "pending");
        assert_eq!(indexed.1, revision_id.as_bytes());
        assert_eq!(indexed.2, deliberation_id.as_bytes());
        assert_eq!(indexed.3, 1);
        assert_eq!(indexed.4, 1);
        let metadata = store
            .indexed_proposition_metadata(
                ledger.as_bytes(),
                proposition_id.as_bytes(),
                Some(actor.as_bytes()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(metadata.latest_revision_id, Some(revision_id));
        assert_eq!(metadata.latest_revision_status, "pending");
        assert_eq!(metadata.pending_revision_id, Some(revision_id));
        assert_eq!(metadata.pending_deliberation_id, Some(deliberation_id));
        assert_eq!(metadata.pending_participant_count, 1);
        assert!(metadata.current_actor_pending);
        assert!(store
            .check_indexed_proposition_consistency(ledger.as_bytes(), Some(actor.as_bytes()))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn authorization_uses_only_causal_grants() {
        let store = Store::open_memory().unwrap();
        let bootstrap = store
            .bootstrap_ledger(
                "example.test",
                "2026-07-27T12:00:00.000Z",
                [21u8; 32],
                [22u8; 16],
            )
            .unwrap();
        let key = fact_crypto::SigningKey::from_seed(&[21u8; 32]).unwrap();
        let grant_bytes = &bootstrap.cose_objects[3];
        let grant_hash = Hash::digest(&fact_crypto::decode_sign1(grant_bytes).unwrap().payload);
        let grant_id = uuid::Uuid::now_v7();
        let grant = make_signed(
            &key,
            serde_json::json!({
                "id":grant_id,"ledger_id":bootstrap.ledger_id,"object_type":"authorization_grant","schema_version":"0",
                "actor_id":bootstrap.actor_id,"signing_key_id":bootstrap.key_id,"created_at":"2026-07-27T12:00:01.000Z",
                "dependencies":[{"object_id":bootstrap.cose_objects[3].as_slice(),"content_hash":grant_hash.hex(),"role":"admin-authority"}],
                "body":{"grant_id":grant_id,"granting_actor_id":bootstrap.actor_id,"receiving_actor_id":bootstrap.actor_id,"capabilities":["propose"],"scope":{"type":"ledger"},"validity":null,"constraints":{},"predecessor_grant_id":null}
            }),
        )
        .unwrap();
        // Replace the binary object_id placeholder with the canonical grant ID.
        let grant_value: serde_json::Value =
            serde_json::from_slice(&fact_crypto::decode_sign1(&grant).unwrap().payload).unwrap();
        let mut grant_value = grant_value;
        grant_value["dependencies"][0]["object_id"] = serde_json::json!(
            serde_json::from_slice::<serde_json::Value>(
                &fact_crypto::decode_sign1(grant_bytes).unwrap().payload
            )
            .unwrap()["id"]
        );
        let grant = make_signed(&key, grant_value).unwrap();
        store.authorize_object(&grant).unwrap();
        store.insert_verified_object(&grant).unwrap();
        let grant_hash = dependency_hash_for_test(&grant);
        let proposition_id = uuid::Uuid::now_v7();
        let revision_id = uuid::Uuid::now_v7();
        let deliberation_id = uuid::Uuid::now_v7();
        let proposition = make_signed(
            &key,
            serde_json::json!({
                "id":proposition_id,"ledger_id":bootstrap.ledger_id,"object_type":"proposition","schema_version":"0",
                "actor_id":bootstrap.actor_id,"signing_key_id":bootstrap.key_id,"created_at":"2026-07-27T12:00:02.000Z",
                "dependencies":[{"object_id":grant_id,"content_hash":grant_hash.hex(),"role":"propose-authority"}],
                "body":{"proposition_id":proposition_id,"purpose":"knowledge","initial_revision_id":revision_id,"initial_deliberation_id":deliberation_id}
            }),
        ).unwrap();
        let revision = make_signed(
            &key,
            serde_json::json!({
                "id":revision_id,"ledger_id":bootstrap.ledger_id,"object_type":"revision","schema_version":"0",
                "actor_id":bootstrap.actor_id,"signing_key_id":bootstrap.key_id,"created_at":"2026-07-27T12:00:02.000Z",
                "dependencies":[],"body":{"proposition_id":proposition_id,"revision_id":revision_id,"parent_revision_id":null,
                "content":{"media_type":"text/markdown; charset=utf-8; variant=fact-v0","bytes":b64url(b"# Fact\n"),"hash":Hash::digest(b"# Fact\n").hex()},"relationships":[],"reconciliation_manifest":null}
            }),
        ).unwrap();
        let deliberation = make_signed(
            &key,
            serde_json::json!({
                "id":deliberation_id,"ledger_id":bootstrap.ledger_id,"object_type":"deliberation","schema_version":"0",
                "actor_id":bootstrap.actor_id,"signing_key_id":bootstrap.key_id,"created_at":"2026-07-27T12:00:02.000Z",
                "dependencies":[],"body":{"deliberation_id":deliberation_id,"proposition_id":proposition_id,"revision_id":revision_id,
                "extends_deliberation_id":null,"decision_rule":{"id":"unanimity","version":0,"parameters":{}},"join_policy":{"policy_version":0,"mode":"open","attestation_requirements":[]},
                "initial_participants":[{"actor_id":bootstrap.actor_id,"carried_decision_id":null}],"roster_governance":null,"opening_actor_id":bootstrap.actor_id,"comments_closed_on_settlement":true}
            }),
        ).unwrap();
        store
            .insert_verified_bundle(&[proposition.clone(), revision, deliberation])
            .unwrap();
        let mut unauthorized_value: serde_json::Value =
            serde_json::from_slice(&fact_crypto::decode_sign1(&proposition).unwrap().payload)
                .unwrap();
        let unauthorized_id = uuid::Uuid::now_v7();
        unauthorized_value["id"] = serde_json::json!(unauthorized_id);
        unauthorized_value["body"]["proposition_id"] = serde_json::json!(unauthorized_id);
        unauthorized_value["dependencies"] = serde_json::json!([]);
        let unauthorized = make_signed(&key, unauthorized_value).unwrap();
        assert!(matches!(
            store.authorize_object(&unauthorized),
            Err(Error::Unauthorized)
        ));
        let before: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM protocol_object", [], |row| row.get(0))
            .unwrap();
        assert!(matches!(
            store.insert_authorized_bundle(std::slice::from_ref(&unauthorized)),
            Err(Error::Unauthorized | Error::InvalidLineage)
        ));
        let after: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM protocol_object", [], |row| row.get(0))
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn consensus_rebuild_groups_inputs_per_deliberation() {
        let store = Store::open_memory().unwrap();
        let ledger = uuid::Uuid::now_v7();
        let actor = uuid::Uuid::now_v7();
        let key_id = uuid::Uuid::now_v7();
        let context = ProtocolPayloadContext {
            ledger,
            actor,
            key_id,
        };
        store
            .create_ledger(ledger.as_bytes(), "grouping.example")
            .unwrap();
        for index in 0..24 {
            let proposition_id = uuid::Uuid::now_v7();
            let revision_id = uuid::Uuid::now_v7();
            let deliberation_id = uuid::Uuid::now_v7();
            let decision_id = uuid::Uuid::now_v7();
            let settlement_id = uuid::Uuid::now_v7();
            insert_protocol_payload(
                &store,
                context,
                proposition_id,
                "proposition",
                index * 5,
                serde_json::json!({
                    "body":{
                        "proposition_id":proposition_id,
                        "purpose":"knowledge",
                        "initial_revision_id":revision_id,
                        "initial_deliberation_id":deliberation_id
                    }
                }),
            );
            insert_protocol_payload(
                &store,
                context,
                revision_id,
                "revision",
                index * 5 + 1,
                serde_json::json!({
                    "body":{
                        "proposition_id":proposition_id,
                        "revision_id":revision_id,
                        "parent_revision_id":null
                    }
                }),
            );
            insert_protocol_payload(
                &store,
                context,
                deliberation_id,
                "deliberation",
                index * 5 + 2,
                serde_json::json!({
                    "body":{
                        "deliberation_id":deliberation_id,
                        "proposition_id":proposition_id,
                        "revision_id":revision_id,
                        "initial_participants":[{"actor_id":actor}]
                    }
                }),
            );
            let decision_hash = numbered_hash(index * 5 + 3);
            insert_protocol_payload(
                &store,
                context,
                decision_id,
                "decision",
                index * 5 + 3,
                serde_json::json!({
                    "body":{
                        "deliberation_id":deliberation_id,
                        "participant_actor_id":actor,
                        "value":"accepted",
                        "supersedes_decision_ids":[]
                    }
                }),
            );
            insert_protocol_payload(
                &store,
                context,
                settlement_id,
                "settlement",
                index * 5 + 4,
                serde_json::json!({
                    "body":{
                        "deliberation_id":deliberation_id,
                        "revision_id":revision_id,
                        "outcome":"accepted",
                        "decision_refs":[{
                            "decision_id":decision_id,
                            "participant_actor_id":actor,
                            "content_hash":decision_hash.hex()
                        }]
                    }
                }),
            );
        }

        let projecteds = store.rebuild_consensus().unwrap();
        assert_eq!(projecteds.len(), 24);
        assert!(projecteds
            .iter()
            .all(|projected| projected.consensus == "accepted"
                && projected.participant_count == 1
                && projected.applicable_decision_count == 1));
        let rows: (i64, i64, i64) = store
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM projected_consensus),(SELECT COUNT(*) FROM projected_participant),(SELECT COUNT(*) FROM projected_decision)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(rows, (24, 24, 24));
    }

    #[test]
    fn indexed_proposition_preserves_ambiguous_pending_revision_tips() {
        let store = Store::open_memory().unwrap();
        let ledger = uuid::Uuid::now_v7();
        let actor = uuid::Uuid::now_v7();
        let key_id = uuid::Uuid::now_v7();
        let proposition = uuid::Uuid::now_v7();
        let effective_revision = uuid::Uuid::now_v7();
        let first_tip = uuid::Uuid::now_v7();
        let second_tip = uuid::Uuid::now_v7();
        let first_deliberation = uuid::Uuid::now_v7();
        let second_deliberation = uuid::Uuid::now_v7();
        let context = ProtocolPayloadContext {
            ledger,
            actor,
            key_id,
        };
        store
            .create_ledger(ledger.as_bytes(), "ambiguous-indexed.example")
            .unwrap();
        insert_protocol_payload(
            &store,
            context,
            proposition,
            "proposition",
            30_000,
            serde_json::json!({
                "body": {
                    "proposition_id": proposition,
                    "purpose": "knowledge",
                    "initial_revision_id": effective_revision,
                    "initial_deliberation_id": null
                }
            }),
        );
        for (index, revision, parent) in [
            (30_001, effective_revision, None),
            (30_002, first_tip, Some(effective_revision)),
            (30_003, second_tip, Some(effective_revision)),
        ] {
            insert_protocol_payload(
                &store,
                context,
                revision,
                "revision",
                index,
                serde_json::json!({
                    "body": {
                        "proposition_id": proposition,
                        "revision_id": revision,
                        "parent_revision_id": parent,
                        "content": {
                            "media_type": "text/markdown; charset=utf-8; variant=fact-v0",
                            "bytes": b64url(format!("# Revision {index}\n").as_bytes()),
                            "hash": Hash::digest(format!("# Revision {index}\n").as_bytes()).hex()
                        },
                        "relationships": [],
                        "reconciliation_manifest": null
                    }
                }),
            );
            store
                .conn
                .execute(
                    "INSERT INTO projected_revision(revision_id,proposition_id,parent_revision_id,content_hash,object_id,payload) VALUES(?,?,?,?,?,?)",
                    params![
                        revision.as_bytes(),
                        proposition.as_bytes(),
                        parent.map(|id| id.as_bytes().to_vec()),
                        numbered_hash(index).as_bytes(),
                        revision.as_bytes(),
                        b"{}",
                    ],
                )
                .unwrap();
        }
        for (index, deliberation, revision) in [
            (30_004, first_deliberation, first_tip),
            (30_005, second_deliberation, second_tip),
        ] {
            insert_protocol_payload(
                &store,
                context,
                deliberation,
                "deliberation",
                index,
                serde_json::json!({
                    "body": {
                        "deliberation_id": deliberation,
                        "proposition_id": proposition,
                        "revision_id": revision,
                        "initial_participants": [{"actor_id": actor, "carried_decision_id": null}]
                    }
                }),
            );
            store
                .conn
                .execute(
                    "INSERT INTO projected_deliberation(deliberation_id,proposition_id,revision_id,settled,object_id,payload) VALUES(?,?,?,?,?,?)",
                    params![
                        deliberation.as_bytes(),
                        proposition.as_bytes(),
                        revision.as_bytes(),
                        0_i64,
                        deliberation.as_bytes(),
                        b"{}",
                    ],
                )
                .unwrap();
            store
                .conn
                .execute(
                    "INSERT INTO projected_participant(deliberation_id,actor_id,active,source_object_id,projected_version) VALUES(?,?,?,?,?)",
                    params![
                        deliberation.as_bytes(),
                        actor.as_bytes(),
                        1_i64,
                        Option::<&[u8]>::None,
                        "participants-v0",
                    ],
                )
                .unwrap();
        }
        store
            .conn
            .execute(
                "INSERT INTO projected_effective(proposition_id,status,revision_id,deliberation_id,settlement_id,reason,projected_version) VALUES(?,?,?,?,?,?,?)",
                params![
                    proposition.as_bytes(),
                    "accepted",
                    effective_revision.as_bytes(),
                    Option::<&[u8]>::None,
                    Option::<&[u8]>::None,
                    "test",
                    "effective-v0",
                ],
            )
            .unwrap();

        store.rebuild_indexed_propositions().unwrap();
        assert_ambiguous_indexed_metadata(&store, ledger, actor, proposition);

        store
            .conn
            .execute(
                "UPDATE indexed_proposition SET latest_revision_id=?,latest_revision_status='pending',pending_revision_id=?,pending_deliberation_id=?,pending_participant_count=1,has_pending_revision=1 WHERE proposition_id=?",
                params![
                    first_tip.as_bytes(),
                    first_tip.as_bytes(),
                    first_deliberation.as_bytes(),
                    proposition.as_bytes(),
                ],
            )
            .unwrap();
        store
            .refresh_indexed_propositions(&[proposition.as_bytes().to_vec()])
            .unwrap();
        assert_ambiguous_indexed_metadata(&store, ledger, actor, proposition);
        assert!(store
            .check_indexed_proposition_consistency(ledger.as_bytes(), Some(actor.as_bytes()))
            .unwrap()
            .is_empty());
    }

    fn assert_ambiguous_indexed_metadata(
        store: &Store,
        ledger: uuid::Uuid,
        actor: uuid::Uuid,
        proposition: uuid::Uuid,
    ) {
        let metadata = store
            .indexed_proposition_metadata(
                ledger.as_bytes(),
                proposition.as_bytes(),
                Some(actor.as_bytes()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(metadata.latest_revision_id, None);
        assert_eq!(metadata.latest_revision_status, "ambiguous");
        assert_eq!(metadata.pending_revision_id, None);
        assert_eq!(metadata.pending_deliberation_id, None);
        assert_eq!(metadata.pending_participant_count, 0);
        assert!(!metadata.current_actor_pending);
        assert!(metadata.has_pending_revision);
    }

    #[derive(Clone, Copy)]
    struct ProtocolPayloadContext {
        ledger: uuid::Uuid,
        actor: uuid::Uuid,
        key_id: uuid::Uuid,
    }

    fn insert_protocol_payload(
        store: &Store,
        context: ProtocolPayloadContext,
        object_id: uuid::Uuid,
        object_type: &str,
        hash_seed: usize,
        payload: serde_json::Value,
    ) {
        insert_protocol_payload_with_hash(
            store,
            context,
            object_id,
            object_type,
            numbered_hash(hash_seed),
            payload,
        );
    }

    fn insert_protocol_payload_with_hash(
        store: &Store,
        context: ProtocolPayloadContext,
        object_id: uuid::Uuid,
        object_type: &str,
        content_hash: Hash,
        payload: serde_json::Value,
    ) {
        store
            .conn
            .execute(
                "INSERT INTO protocol_object(object_id,ledger_id,object_type,schema_version,actor_id,signing_key_id,payload,content_hash,cose) VALUES(?,?,?,?,?,?,?,?,?)",
                params![
                    object_id.as_bytes(),
                    context.ledger.as_bytes(),
                    object_type,
                    "0",
                    context.actor.as_bytes(),
                    context.key_id.as_bytes(),
                    serde_json::to_vec(&payload).unwrap(),
                    content_hash.as_bytes(),
                    b"cose",
                ],
            )
            .unwrap();
    }

    fn numbered_hash(seed: usize) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&(seed as u64).to_be_bytes());
        Hash::from_bytes(bytes)
    }

    fn dependency_hash_for_test(cose: &[u8]) -> Hash {
        Hash::digest(&fact_crypto::decode_sign1(cose).unwrap().payload)
    }
}
