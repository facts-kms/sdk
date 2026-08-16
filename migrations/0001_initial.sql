CREATE TABLE IF NOT EXISTS schema_migration (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger (
    ledger_id BLOB PRIMARY KEY,
    namespace TEXT NOT NULL,
    protocol_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS protocol_object (
    object_id BLOB PRIMARY KEY,
    ledger_id BLOB,
    object_type TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    actor_id BLOB NOT NULL,
    signing_key_id BLOB NOT NULL,
    payload BLOB NOT NULL,
    content_hash BLOB NOT NULL UNIQUE,
    cose BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS object_dependency (
    object_id BLOB NOT NULL REFERENCES protocol_object(object_id),
    dependency_id BLOB NOT NULL,
    content_hash BLOB NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY(object_id, dependency_id)
);

CREATE TABLE IF NOT EXISTS key_material (
    key_id BLOB PRIMARY KEY,
    public_key BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS protocol_relationship (
    object_id BLOB PRIMARY KEY REFERENCES protocol_object(object_id),
    ledger_id BLOB,
    object_type TEXT NOT NULL,
    source_object_id BLOB NOT NULL,
    relationship TEXT NOT NULL,
    target_object_ids BLOB NOT NULL,
    payload BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS object_receipt (
    receipt_id BLOB PRIMARY KEY,
    object_id BLOB NOT NULL,
    content_hash BLOB NOT NULL,
    disposition_code TEXT NOT NULL,
    evaluated_at TEXT NOT NULL,
    payload BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS projected_object (
    object_id BLOB PRIMARY KEY,
    ledger_id BLOB,
    object_type TEXT NOT NULL,
    content_hash BLOB NOT NULL,
    payload BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS projected_consensus (
    deliberation_id BLOB PRIMARY KEY,
    revision_id BLOB NOT NULL,
    participant_count INTEGER NOT NULL,
    applicable_decision_count INTEGER NOT NULL,
    consensus TEXT NOT NULL,
    projected_version TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS protocol_object_ledger ON protocol_object(ledger_id);
CREATE INDEX IF NOT EXISTS protocol_object_type ON protocol_object(object_type);
CREATE INDEX IF NOT EXISTS protocol_relationship_source ON protocol_relationship(source_object_id);

CREATE TABLE IF NOT EXISTS projected_actor (
    actor_id BLOB PRIMARY KEY,
    actor_type TEXT NOT NULL,
    object_id BLOB NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projected_key (
    key_id BLOB PRIMARY KEY,
    purpose TEXT NOT NULL,
    public_key BLOB NOT NULL,
    object_id BLOB NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projected_binding (
    binding_id BLOB PRIMARY KEY,
    actor_id BLOB NOT NULL,
    key_id BLOB NOT NULL,
    permitted_purpose TEXT NOT NULL,
    object_id BLOB NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projected_authority (
    grant_id BLOB NOT NULL,
    capability TEXT NOT NULL,
    receiving_actor_id BLOB NOT NULL,
    scope TEXT NOT NULL,
    revoked INTEGER NOT NULL,
    object_id BLOB NOT NULL,
    payload BLOB NOT NULL,
    PRIMARY KEY(grant_id, capability)
);
CREATE TABLE IF NOT EXISTS projected_revision (
    revision_id BLOB PRIMARY KEY,
    proposition_id BLOB NOT NULL,
    parent_revision_id BLOB,
    content_hash BLOB NOT NULL,
    object_id BLOB NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projected_deliberation (
    deliberation_id BLOB PRIMARY KEY,
    proposition_id BLOB NOT NULL,
    revision_id BLOB NOT NULL,
    settled INTEGER NOT NULL,
    object_id BLOB NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projected_standing_change (
    object_id BLOB PRIMARY KEY,
    ledger_id BLOB NOT NULL,
    proposition_id BLOB NOT NULL,
    participant_actor_id BLOB NOT NULL,
    operation TEXT NOT NULL,
    predecessor_change_id BLOB,
    changed_by_actor_id BLOB NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projected_participant (
    deliberation_id BLOB NOT NULL,
    actor_id BLOB NOT NULL,
    active INTEGER NOT NULL,
    source_object_id BLOB,
    projected_version TEXT NOT NULL,
    PRIMARY KEY(deliberation_id, actor_id)
);
CREATE TABLE IF NOT EXISTS projected_decision (
    decision_id BLOB PRIMARY KEY,
    deliberation_id BLOB NOT NULL,
    participant_actor_id BLOB NOT NULL,
    value TEXT NOT NULL,
    supersedes TEXT NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projected_lifecycle (
    object_id BLOB PRIMARY KEY,
    object_type TEXT NOT NULL,
    target_id BLOB,
    dimension TEXT,
    operation TEXT NOT NULL,
    effective_at TEXT,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projected_pending (
    pending_id BLOB PRIMARY KEY,
    object_id BLOB NOT NULL,
    kind TEXT NOT NULL,
    reason TEXT NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projected_reconciliation (
    revision_id BLOB PRIMARY KEY,
    affected_proposition_id BLOB NOT NULL,
    common_ancestor_revision_id BLOB NOT NULL,
    conflict_set_hash BLOB NOT NULL,
    resolution_mode TEXT NOT NULL,
    selected_revision_id BLOB,
    result_revision_id BLOB,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projected_roster (
    deliberation_id BLOB PRIMARY KEY,
    selection_mode TEXT NOT NULL,
    source_deliberation_ids TEXT NOT NULL,
    selected_participant_ids TEXT NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projected_effective (
    proposition_id BLOB PRIMARY KEY,
    status TEXT NOT NULL,
    revision_id BLOB,
    deliberation_id BLOB,
    settlement_id BLOB,
    withdrawal_status TEXT NOT NULL DEFAULT 'active',
    archival_status TEXT NOT NULL DEFAULT 'visible',
    reason TEXT NOT NULL,
    projected_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS indexed_proposition (
    proposition_id BLOB PRIMARY KEY,
    ledger_id BLOB NOT NULL,
    status TEXT NOT NULL,
    effective_revision_id BLOB,
    effective_deliberation_id BLOB,
    settlement_id BLOB,
    withdrawal_status TEXT NOT NULL,
    archival_status TEXT NOT NULL,
    effective_reason TEXT NOT NULL,
    latest_revision_id BLOB,
    latest_revision_status TEXT NOT NULL,
    pending_revision_id BLOB,
    pending_deliberation_id BLOB,
    pending_participant_count INTEGER NOT NULL,
    has_pending_revision INTEGER NOT NULL,
    summary_text TEXT,
    summary_revision_id BLOB,
    indexed_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS indexed_proposition_default_list
ON indexed_proposition(ledger_id, status, withdrawal_status, archival_status, proposition_id);
CREATE INDEX IF NOT EXISTS indexed_proposition_ledger_proposition
ON indexed_proposition(ledger_id, proposition_id);
CREATE INDEX IF NOT EXISTS indexed_proposition_lifecycle_list
ON indexed_proposition(ledger_id, withdrawal_status, archival_status, proposition_id);
CREATE INDEX IF NOT EXISTS indexed_proposition_pending_list
ON indexed_proposition(ledger_id, has_pending_revision, proposition_id);
CREATE INDEX IF NOT EXISTS indexed_proposition_effective_revision
ON indexed_proposition(ledger_id, effective_revision_id, proposition_id);
CREATE INDEX IF NOT EXISTS indexed_proposition_latest_revision
ON indexed_proposition(ledger_id, latest_revision_id, proposition_id);

CREATE TABLE IF NOT EXISTS indexed_proposition_meta (
    ledger_id BLOB PRIMARY KEY,
    proposition_count INTEGER NOT NULL,
    effective_count INTEGER NOT NULL,
    indexed_count INTEGER NOT NULL,
    stale_count INTEGER NOT NULL,
    indexed_version TEXT NOT NULL,
    refreshed_at TEXT NOT NULL
);
