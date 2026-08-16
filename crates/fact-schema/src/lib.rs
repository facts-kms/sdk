use serde_json::Value;
use std::collections::HashSet;
use std::str::FromStr;

pub const OBJECT_TYPES: [&str; 27] = [
    "genesis",
    "namespace_assertion",
    "actor",
    "key",
    "actor_key_binding",
    "key_lifecycle",
    "recovery_policy",
    "actor_lifecycle",
    "identity_attestation",
    "authorization_grant",
    "authorization_revocation",
    "delegation",
    "delegation_revocation",
    "proposition",
    "revision",
    "deliberation",
    "standing_participant_change",
    "deliberation_participant_change",
    "participant_invitation",
    "invitation_lifecycle",
    "decision",
    "deliberation_comment",
    "settlement",
    "proposition_lifecycle",
    "protocol_relationship",
    "application_relationship",
    "proposition_provenance",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectType(&'static str);
impl ObjectType {
    pub fn as_str(self) -> &'static str {
        self.0
    }
    pub fn ledger_scoped(self) -> bool {
        !matches!(self.0, "actor" | "key" | "actor_key_binding")
    }
}
impl std::str::FromStr for ObjectType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        OBJECT_TYPES
            .iter()
            .find(|x| **x == s)
            .copied()
            .map(Self)
            .ok_or(Error::UnknownType)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid canonical payload: {0}")]
    Canonical(#[from] fact_canonical::Error),
    #[error("payload is not an object")]
    NotObject,
    #[error("missing envelope field: {0}")]
    Missing(&'static str),
    #[error("unknown object type")]
    UnknownType,
    #[error("schema_version must be exactly 0")]
    Version,
    #[error("ledger_id is forbidden for ledger-neutral object")]
    ForbiddenLedger,
    #[error("ledger_id is required for ledger-scoped object")]
    MissingLedger,
    #[error("envelope contains unknown fields")]
    UnknownField,
    #[error("envelope field has the wrong type: {0}")]
    WrongType(&'static str),
    #[error("invalid UUIDv7 in field: {0}")]
    InvalidUuid(&'static str),
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("body is missing required field: {0}")]
    MissingBodyField(&'static str),
    #[error("invalid body field: {0}")]
    InvalidBody(&'static str),
    #[error("body contains unknown field: {0}")]
    UnknownBodyField(String),
}

pub fn validate_envelope(bytes: &[u8]) -> Result<ObjectType, Error> {
    let canonical = fact_canonical::encode(bytes)?;
    let v: Value = serde_json::from_slice(&canonical).map_err(|_| Error::NotObject)?;
    let o = v.as_object().ok_or(Error::NotObject)?;
    const REQUIRED: &[&str] = &[
        "id",
        "object_type",
        "schema_version",
        "actor_id",
        "signing_key_id",
        "created_at",
        "dependencies",
        "body",
    ];
    for k in REQUIRED {
        if !o.contains_key(*k) {
            return Err(Error::Missing(k));
        }
    }
    let t = o
        .get("object_type")
        .and_then(Value::as_str)
        .ok_or(Error::UnknownType)?
        .parse::<ObjectType>()?;
    if o.get("schema_version").and_then(Value::as_str) != Some("0") {
        return Err(Error::Version);
    }
    let has = o.contains_key("ledger_id");
    if t.ledger_scoped() && !has {
        return Err(Error::MissingLedger);
    }
    if !t.ledger_scoped() && has {
        return Err(Error::ForbiddenLedger);
    }
    let allowed = if t.ledger_scoped() {
        [
            "id",
            "ledger_id",
            "object_type",
            "schema_version",
            "actor_id",
            "signing_key_id",
            "created_at",
            "dependencies",
            "body",
        ]
        .as_slice()
    } else {
        REQUIRED
    };
    if o.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(Error::UnknownField);
    }
    for field in ["id", "actor_id", "signing_key_id"] {
        let s = o
            .get(field)
            .and_then(Value::as_str)
            .ok_or(Error::WrongType(field))?;
        s.parse::<fact_core::ObjectId>()
            .map_err(|_| Error::InvalidUuid(field))?;
    }
    if let Some(ledger) = o.get("ledger_id") {
        let s = ledger.as_str().ok_or(Error::WrongType("ledger_id"))?;
        s.parse::<fact_core::ObjectId>()
            .map_err(|_| Error::InvalidUuid("ledger_id"))?;
    }
    if o.get("created_at").and_then(Value::as_str).is_none() {
        return Err(Error::WrongType("created_at"));
    }
    fact_core::validate_timestamp(o["created_at"].as_str().unwrap())
        .map_err(|_| Error::InvalidTimestamp)?;
    let dependencies = o["dependencies"]
        .as_array()
        .ok_or(Error::WrongType("dependencies"))?;
    let mut dependency_ids = HashSet::new();
    for dependency in dependencies {
        let dependency = dependency
            .as_object()
            .ok_or(Error::WrongType("dependencies"))?;
        if dependency
            .keys()
            .any(|key| !["object_id", "content_hash", "role"].contains(&key.as_str()))
        {
            return Err(Error::UnknownField);
        }
        let dependency_id = dependency
            .get("object_id")
            .and_then(Value::as_str)
            .ok_or(Error::WrongType("dependencies.object_id"))?;
        dependency_id
            .parse::<fact_core::ObjectId>()
            .map_err(|_| Error::InvalidUuid("dependencies.object_id"))?;
        if !dependency_ids.insert(dependency_id) {
            return Err(Error::InvalidBody("dependencies.duplicate"));
        }
        dependency
            .get("content_hash")
            .and_then(Value::as_str)
            .ok_or(Error::WrongType("dependencies.content_hash"))?
            .parse::<fact_core::Hash>()
            .map_err(|_| Error::InvalidBody("dependencies.content_hash"))?;
        let role = dependency
            .get("role")
            .and_then(Value::as_str)
            .ok_or(Error::WrongType("dependencies.role"))?;
        if !valid_dependency_role(role) {
            return Err(Error::InvalidBody("dependencies.role"));
        }
    }
    if !o["body"].is_object() {
        return Err(Error::WrongType("body"));
    }
    validate_body(t, o["body"].as_object().unwrap())?;
    let body_identity_field = match t.as_str() {
        "proposition" => Some("proposition_id"),
        "revision" => Some("revision_id"),
        "deliberation" => Some("deliberation_id"),
        "participant_invitation" => Some("invitation_id"),
        _ => None,
    };
    if let Some(field) = body_identity_field {
        if o["body"].get(field) != o.get("id") {
            return Err(Error::InvalidBody("body.envelope_id"));
        }
    }
    if t.as_str() == "genesis" {
        let body = o["body"].as_object().unwrap();
        if body.get("ledger_id") != o.get("ledger_id") {
            return Err(Error::InvalidBody("genesis.ledger_id"));
        }
        if body.get("bootstrap_actor") != o.get("actor_id") {
            return Err(Error::InvalidBody("genesis.bootstrap_actor"));
        }
        if body.get("bootstrap_key") != o.get("signing_key_id") {
            return Err(Error::InvalidBody("genesis.bootstrap_key"));
        }
    }
    let identity_body_field = match t.as_str() {
        "authorization_grant" => Some("grant_id"),
        "proposition" => Some("proposition_id"),
        "revision" => Some("revision_id"),
        "deliberation" => Some("deliberation_id"),
        "participant_invitation" => Some("invitation_id"),
        _ => None,
    };
    if let Some(field) = identity_body_field {
        let body = o["body"].as_object().unwrap();
        if body.get(field) != o.get("id") {
            return Err(Error::InvalidBody(field));
        }
    }
    Ok(t)
}

fn validate_body(t: ObjectType, body: &serde_json::Map<String, Value>) -> Result<(), Error> {
    let required: &[&str] = match t.0 {
        "genesis" => &[
            "ledger_id",
            "protocol_version",
            "parameters",
            "namespace",
            "bootstrap_actor",
            "bootstrap_key",
            "bootstrap_binding",
            "root_grant",
            "nonce",
            "initial_namespace_assertion",
        ],
        "namespace_assertion" => &[
            "namespace",
            "target_type",
            "target_id",
            "naming_authority_actor_id",
            "validity",
            "supersedes",
        ],
        "actor" => &["actor_type", "bootstrap_key_id", "bootstrap_binding_id"],
        "key" => &["public_key", "purpose"],
        "actor_key_binding" => &[
            "actor_id",
            "key_id",
            "permitted_purpose",
            "predecessor_binding_id",
        ],
        "key_lifecycle" => &[
            "operation",
            "affected_actor_id",
            "old_key_id",
            "predecessor_lifecycle_id",
            "effective_at",
            "authorization_ref",
        ],
        "recovery_policy" => &[
            "actor_id",
            "recovery_key_id",
            "policy_version",
            "effective_at",
            "predecessor_policy_id",
        ],
        "actor_lifecycle" => &[
            "affected_actor_id",
            "operation",
            "effective_at",
            "authorization_ref",
        ],
        "identity_attestation" => &[
            "subject_type",
            "subject_id",
            "claim_type",
            "claims",
            "evidence_hash",
            "validity",
        ],
        "authorization_grant" => &[
            "grant_id",
            "granting_actor_id",
            "receiving_actor_id",
            "capabilities",
            "scope",
            "validity",
            "constraints",
            "predecessor_grant_id",
        ],
        "authorization_revocation" => &[
            "revoked_grant_id",
            "effective_at",
            "reason",
            "authorization_ref",
        ],
        "delegation" => &[
            "delegator_actor_id",
            "delegatee_actor_id",
            "capability",
            "scope",
            "validity",
            "parent_delegation_id",
            "redelegable",
            "constraints",
        ],
        "delegation_revocation" => &[
            "revoked_delegation_id",
            "effective_at",
            "reason",
            "authorization_ref",
        ],
        "proposition" => &[
            "proposition_id",
            "purpose",
            "initial_revision_id",
            "initial_deliberation_id",
        ],
        "revision" => &[
            "proposition_id",
            "revision_id",
            "parent_revision_id",
            "content",
            "relationships",
            "reconciliation_manifest",
        ],
        "deliberation" => &[
            "deliberation_id",
            "proposition_id",
            "revision_id",
            "extends_deliberation_id",
            "decision_rule",
            "join_policy",
            "initial_participants",
            "roster_governance",
            "opening_actor_id",
            "comments_closed_on_settlement",
        ],
        "standing_participant_change" => &[
            "proposition_id",
            "participant_actor_id",
            "operation",
            "predecessor_change_id",
            "changed_by_actor_id",
            "authorization_ref",
        ],
        "deliberation_participant_change" => &[
            "deliberation_id",
            "participant_actor_id",
            "operation",
            "invitation_id",
            "admission_evidence",
            "carried_decision_id",
            "predecessor_change_id",
            "changed_by_actor_id",
            "authorization_ref",
        ],
        "participant_invitation" => &[
            "invitation_id",
            "inviting_actor_id",
            "invited_actor_id",
            "participation_type",
            "constraints",
            "validity",
            "predecessor_invitation_id",
        ],
        "invitation_lifecycle" => &[
            "invitation_id",
            "operation",
            "predecessor_lifecycle_ids",
            "reason",
            "authorization_ref",
        ],
        "decision" => &[
            "deliberation_id",
            "participant_actor_id",
            "value",
            "supersedes_decision_ids",
            "authorization_ref",
        ],
        "deliberation_comment" => &[
            "deliberation_id",
            "content",
            "parent_comment_id",
            "comment_phase",
        ],
        "settlement" => &[
            "deliberation_id",
            "revision_id",
            "decision_rule",
            "decision_refs",
            "participant_count",
            "decided_count",
            "accepted_count",
            "rejected_count",
            "outcome",
            "causal_settlement_point",
            "producer_type",
            "producer_id",
        ],
        "proposition_lifecycle" => &[
            "proposition_id",
            "dimension",
            "operation",
            "predecessor_ids",
            "authorization_ref",
            "reason",
        ],
        "protocol_relationship" => &[
            "source_object_id",
            "relationship",
            "target_object_ids",
            "relationship_version",
        ],
        "application_relationship" => &[
            "source_object_id",
            "relationship",
            "target_object_ids",
            "metadata",
            "shared",
        ],
        "proposition_provenance" => &[
            "proposition_id",
            "source_ledger_id",
            "source_proposition_id",
            "source_revision_id",
            "source_content_hash",
            "source_object_bundle",
            "copy_mode",
        ],
        _ => return Err(Error::UnknownType),
    };
    for field in required {
        if !body.contains_key(*field) {
            return Err(Error::MissingBodyField(field));
        }
    }
    let optional: &[&str] = match t.as_str() {
        "participant_invitation" => &["proposition_id", "deliberation_id"],
        "key_lifecycle" => &["new_key_id"],
        _ => &[],
    };
    if let Some(unknown) = body
        .keys()
        .find(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(Error::UnknownBodyField(unknown.clone()));
    }
    match t.as_str() {
        "actor" => {
            enum_string(
                body,
                "actor_type",
                &["human", "agent", "service", "organization"],
            )?;
            object_id_string(body, "bootstrap_key_id")?;
            object_id_string(body, "bootstrap_binding_id")?;
        }
        "key" => {
            let public = body
                .get("public_key")
                .and_then(Value::as_object)
                .ok_or(Error::InvalidBody("public_key"))?;
            if public
                .keys()
                .any(|k| !["algorithm", "bytes", "fingerprint"].contains(&k.as_str()))
            {
                return Err(Error::InvalidBody("public_key.fields"));
            }
            let algorithm = public
                .get("algorithm")
                .and_then(Value::as_str)
                .ok_or(Error::InvalidBody("public_key.algorithm"))?;
            if !matches!(algorithm, "Ed25519" | "X25519") {
                return Err(Error::InvalidBody("public_key.algorithm"));
            }
            let bytes = decode_base64url(
                public
                    .get("bytes")
                    .and_then(Value::as_str)
                    .ok_or(Error::InvalidBody("public_key.bytes"))?,
            )
            .ok_or(Error::InvalidBody("public_key.bytes"))?;
            if bytes.len() != 32 {
                return Err(Error::InvalidBody("public_key.bytes"));
            }
            let fingerprint = public
                .get("fingerprint")
                .and_then(Value::as_str)
                .ok_or(Error::InvalidBody("public_key.fingerprint"))?;
            if fingerprint != fact_core::Hash::digest(&bytes).hex() {
                return Err(Error::InvalidBody("public_key.fingerprint"));
            }
            let purpose = enum_string(body, "purpose", &["signing", "recovery", "encryption"])?;
            if (purpose == "encryption") != (algorithm == "X25519") {
                return Err(Error::InvalidBody("purpose.algorithm"));
            }
        }
        "actor_key_binding" => {
            object_id_string(body, "actor_id")?;
            object_id_string(body, "key_id")?;
            enum_string(
                body,
                "permitted_purpose",
                &["signing", "recovery", "encryption"],
            )?;
        }
        "genesis" => {
            if body.get("protocol_version").and_then(Value::as_str) != Some("0") {
                return Err(Error::InvalidBody("protocol_version"));
            }
            let parameters = serde_json::json!({"consensus_rule":"unanimity-v0","namespace_profile":"facts-namespace-v0","content_profile":"facts-protocol-markdown-v0"});
            if body.get("parameters") != Some(&parameters) {
                return Err(Error::InvalidBody("parameters"));
            }
            let namespace = body
                .get("namespace")
                .and_then(Value::as_str)
                .ok_or(Error::InvalidBody("namespace"))?;
            if !valid_namespace(namespace) {
                return Err(Error::InvalidBody("namespace"));
            }
            for field in [
                "ledger_id",
                "bootstrap_actor",
                "bootstrap_key",
                "bootstrap_binding",
                "root_grant",
                "initial_namespace_assertion",
            ] {
                object_id_string(body, field)?
            }
            let nonce = decode_base64url(
                body.get("nonce")
                    .and_then(Value::as_str)
                    .ok_or(Error::InvalidBody("nonce"))?,
            )
            .ok_or(Error::InvalidBody("nonce"))?;
            if nonce.len() < 16 {
                return Err(Error::InvalidBody("nonce"));
            }
        }
        "namespace_assertion" => {
            if !valid_namespace(string_field(body, "namespace")?) {
                return Err(Error::InvalidBody("namespace"));
            }
            enum_string(
                body,
                "target_type",
                &[
                    "ledger",
                    "actor",
                    "proposition",
                    "revision",
                    "deliberation",
                    "key",
                ],
            )?;
            object_id_string(body, "target_id")?;
            object_id_string(body, "naming_authority_actor_id")?;
            validate_validity(body.get("validity").unwrap(), "validity", false)?;
            nullable_id_array(body, "supersedes", false)?;
        }
        "key_lifecycle" => {
            let operation = enum_string(body, "operation", &["rotate", "revoke", "recover"])?;
            object_id_string(body, "affected_actor_id")?;
            object_id_string(body, "old_key_id")?;
            let has_new = body.get("new_key_id").is_some_and(|v| !v.is_null());
            if matches!(operation, "rotate" | "recover") != has_new {
                return Err(Error::InvalidBody("new_key_id"));
            }
            if has_new {
                object_id_string(body, "new_key_id")?;
            }
            nullable_object_id(body, "predecessor_lifecycle_id")?;
            validate_timestamp_field(body, "effective_at")?;
            nullable_object_id(body, "authorization_ref")?;
        }
        "recovery_policy" => {
            object_id_string(body, "actor_id")?;
            object_id_string(body, "recovery_key_id")?;
            if body.get("policy_version").and_then(Value::as_i64) != Some(0) {
                return Err(Error::InvalidBody("policy_version"));
            }
            validate_timestamp_field(body, "effective_at")?;
            nullable_object_id(body, "predecessor_policy_id")?;
        }
        "actor_lifecycle" => {
            object_id_string(body, "affected_actor_id")?;
            enum_string(body, "operation", &["retire"])?;
            validate_timestamp_field(body, "effective_at")?;
            object_id_string(body, "authorization_ref")?;
        }
        "identity_attestation" => {
            enum_string(body, "subject_type", &["actor", "key"])?;
            object_id_string(body, "subject_id")?;
            nonempty_string(body, "claim_type")?;
            let claims = body
                .get("claims")
                .and_then(Value::as_object)
                .ok_or(Error::InvalidBody("claims"))?;
            if claims.is_empty()
                || claims.values().any(|value| {
                    !(value.is_null() || value.is_boolean() || value.is_i64() || value.is_string())
                })
            {
                return Err(Error::InvalidBody("claims"));
            }
            nullable_hash(body, "evidence_hash")?;
            validate_validity(body.get("validity").unwrap(), "validity", false)?;
        }
        "authorization_grant" => {
            object_id_string(body, "grant_id")?;
            object_id_string(body, "granting_actor_id")?;
            object_id_string(body, "receiving_actor_id")?;
            validate_capabilities(body.get("capabilities").unwrap())?;
            validate_scope(body.get("scope").unwrap())?;
            nullable_validity(body, "validity")?;
            require_object(body, "constraints")?;
            nullable_object_id(body, "predecessor_grant_id")?;
        }
        "authorization_revocation" | "delegation_revocation" => {
            object_id_string(
                body,
                if t.as_str() == "authorization_revocation" {
                    "revoked_grant_id"
                } else {
                    "revoked_delegation_id"
                },
            )?;
            validate_timestamp_field(body, "effective_at")?;
            nonempty_string(body, "reason")?;
            object_id_string(body, "authorization_ref")?;
        }
        "delegation" => {
            object_id_string(body, "delegator_actor_id")?;
            object_id_string(body, "delegatee_actor_id")?;
            if body.get("delegator_actor_id") == body.get("delegatee_actor_id") {
                return Err(Error::InvalidBody("delegation.actors"));
            }
            capability_string(body, "capability")?;
            validate_scope(body.get("scope").unwrap())?;
            nullable_validity(body, "validity")?;
            nullable_object_id(body, "parent_delegation_id")?;
            if !body.get("redelegable").is_some_and(Value::is_boolean) {
                return Err(Error::InvalidBody("redelegable"));
            }
            require_object(body, "constraints")?;
        }
        "proposition" => {
            for field in [
                "proposition_id",
                "initial_revision_id",
                "initial_deliberation_id",
            ] {
                object_id_string(body, field)?;
            }
            enum_string(body, "purpose", &["knowledge", "reconciliation"])?;
        }
        "revision" => {
            object_id_string(body, "proposition_id")?;
            object_id_string(body, "revision_id")?;
            nullable_object_id(body, "parent_revision_id")?;
            validate_content(body.get("content").ok_or(Error::InvalidBody("content"))?)?;
            validate_relationship_refs(
                body.get("relationships")
                    .ok_or(Error::InvalidBody("relationships"))?,
            )?;
            if let Some(manifest) = body.get("reconciliation_manifest") {
                if !manifest.is_null() {
                    validate_reconciliation_manifest(manifest)?;
                }
            }
        }
        "deliberation" => {
            for field in [
                "deliberation_id",
                "proposition_id",
                "revision_id",
                "opening_actor_id",
            ] {
                object_id_string(body, field)?;
            }
            nullable_object_id(body, "extends_deliberation_id")?;
            let rule = body
                .get("decision_rule")
                .ok_or(Error::InvalidBody("decision_rule"))?;
            if rule != &serde_json::json!({"id":"unanimity","version":0,"parameters":{}}) {
                return Err(Error::InvalidBody("decision_rule"));
            }
            let join = body
                .get("join_policy")
                .and_then(Value::as_object)
                .ok_or(Error::InvalidBody("join_policy"))?;
            if join.keys().any(|k| {
                !["policy_version", "mode", "attestation_requirements"].contains(&k.as_str())
            }) {
                return Err(Error::InvalidBody("join_policy.fields"));
            }
            if join.get("policy_version").and_then(Value::as_i64) != Some(0) {
                return Err(Error::InvalidBody("join_policy.policy_version"));
            }
            let mode = join
                .get("mode")
                .and_then(Value::as_str)
                .ok_or(Error::InvalidBody("join_policy.mode"))?;
            if !["closed", "invitation", "open", "attested"].contains(&mode) {
                return Err(Error::InvalidBody("join_policy.mode"));
            }
            if !join
                .get("attestation_requirements")
                .is_some_and(Value::is_array)
            {
                return Err(Error::InvalidBody("join_policy.attestation_requirements"));
            }
            validate_attestation_requirements(
                join["attestation_requirements"].as_array().unwrap(),
            )?;
            if mode == "attested"
                && join["attestation_requirements"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            {
                return Err(Error::InvalidBody("join_policy.attestation_requirements"));
            }
            if mode != "attested"
                && !join["attestation_requirements"]
                    .as_array()
                    .is_some_and(Vec::is_empty)
            {
                return Err(Error::InvalidBody("join_policy.attestation_requirements"));
            }
            let participants = body
                .get("initial_participants")
                .and_then(Value::as_array)
                .ok_or(Error::InvalidBody("initial_participants"))?;
            if participants.is_empty() {
                return Err(Error::InvalidBody("initial_participants"));
            }
            let mut ids = HashSet::new();
            let mut participant_ids = Vec::with_capacity(participants.len());
            for participant in participants {
                let p = participant
                    .as_object()
                    .ok_or(Error::InvalidBody("initial_participants"))?;
                if !exact_fields(p, &["actor_id", "carried_decision_id"]) {
                    return Err(Error::InvalidBody("initial_participants.fields"));
                }
                let id = p
                    .get("actor_id")
                    .and_then(Value::as_str)
                    .ok_or(Error::InvalidBody("initial_participants.actor_id"))?
                    .parse::<fact_core::ObjectId>()
                    .map_err(|_| Error::InvalidBody("initial_participants.actor_id"))?;
                if !ids.insert(id) {
                    return Err(Error::InvalidBody("initial_participants"));
                }
                participant_ids.push(id);
                if let Some(carried) = p.get("carried_decision_id") {
                    if !carried.is_null() {
                        carried
                            .as_str()
                            .ok_or(Error::InvalidBody("carried_decision_id"))?
                            .parse::<fact_core::ObjectId>()
                            .map_err(|_| Error::InvalidBody("carried_decision_id"))?;
                    }
                }
            }
            if let Some(roster) = body.get("roster_governance") {
                if !roster.is_null() {
                    validate_roster_governance(roster, &participant_ids)?;
                }
            }
        }
        "decision" => {
            object_id_string(body, "deliberation_id")?;
            object_id_string(body, "participant_actor_id")?;
            enum_string(body, "value", &["accepted", "rejected"])?;
            let decisions = body
                .get("supersedes_decision_ids")
                .and_then(Value::as_array)
                .ok_or(Error::InvalidBody("supersedes_decision_ids"))?;
            let mut ids = HashSet::new();
            for d in decisions {
                let s = d
                    .as_str()
                    .ok_or(Error::InvalidBody("supersedes_decision_ids"))?;
                let id = s
                    .parse::<fact_core::ObjectId>()
                    .map_err(|_| Error::InvalidBody("supersedes_decision_ids"))?;
                if !ids.insert(id) {
                    return Err(Error::InvalidBody("supersedes_decision_ids"));
                }
            }
        }
        "standing_participant_change" => {
            object_id_string(body, "proposition_id")?;
            object_id_string(body, "participant_actor_id")?;
            enum_string(body, "operation", &["join", "leave"])?;
            nullable_object_id(body, "predecessor_change_id")?;
            object_id_string(body, "changed_by_actor_id")?;
            nullable_object_id(body, "authorization_ref")?;
        }
        "deliberation_participant_change" => {
            object_id_string(body, "deliberation_id")?;
            object_id_string(body, "participant_actor_id")?;
            enum_string(body, "operation", &["join", "leave"])?;
            nullable_object_id(body, "invitation_id")?;
            validate_evidence_array(body.get("admission_evidence").unwrap())?;
            nullable_object_id(body, "carried_decision_id")?;
            nullable_object_id(body, "predecessor_change_id")?;
            object_id_string(body, "changed_by_actor_id")?;
            nullable_object_id(body, "authorization_ref")?;
        }
        "deliberation_comment" => {
            object_id_string(body, "deliberation_id")?;
            nullable_object_id(body, "parent_comment_id")?;
            enum_string(
                body,
                "comment_phase",
                &["pre-settlement", "post-settlement"],
            )?;
            validate_content(body.get("content").ok_or(Error::InvalidBody("content"))?)?;
        }
        "participant_invitation" => {
            object_id_string(body, "invitation_id")?;
            object_id_string(body, "inviting_actor_id")?;
            object_id_string(body, "invited_actor_id")?;
            if body
                .get("participation_type")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(Error::InvalidBody("participation_type"));
            }
            if body.get("proposition_id").is_some_and(Value::is_null)
                || body.get("deliberation_id").is_some_and(Value::is_null)
            {
                return Err(Error::InvalidBody("invitation.scope"));
            }
            let has_proposition = body
                .get("proposition_id")
                .is_some_and(|value| !value.is_null());
            let has_deliberation = body
                .get("deliberation_id")
                .is_some_and(|value| !value.is_null());
            if has_proposition == has_deliberation {
                return Err(Error::InvalidBody("invitation.scope"));
            }
            if has_proposition {
                object_id_string(body, "proposition_id")?;
            } else {
                object_id_string(body, "deliberation_id")?;
            }
            if let Some(predecessor) = body.get("predecessor_invitation_id") {
                if !predecessor.is_null() {
                    object_id_value(Some(predecessor), "predecessor_invitation_id")?;
                }
            }
        }
        "invitation_lifecycle" => {
            object_id_string(body, "invitation_id")?;
            enum_string(body, "operation", &["decline", "revoke", "supersede"])?;
            id_array(
                body.get("predecessor_lifecycle_ids").unwrap(),
                "predecessor_lifecycle_ids",
                false,
            )?;
            nonempty_string(body, "reason")?;
            object_id_string(body, "authorization_ref")?;
        }
        "settlement" => {
            object_id_string(body, "deliberation_id")?;
            object_id_string(body, "revision_id")?;
            let rule = body
                .get("decision_rule")
                .ok_or(Error::InvalidBody("decision_rule"))?;
            if rule != &serde_json::json!({"id":"unanimity","version":0,"parameters":{}}) {
                return Err(Error::InvalidBody("decision_rule"));
            }
            let refs = body
                .get("decision_refs")
                .and_then(Value::as_array)
                .ok_or(Error::InvalidBody("decision_refs"))?;
            if refs.is_empty() {
                return Err(Error::InvalidBody("decision_refs"));
            }
            let mut ids = HashSet::new();
            let mut participants = HashSet::new();
            let mut previous = None;
            for r in refs {
                let x = r.as_object().ok_or(Error::InvalidBody("decision_refs"))?;
                let decision = x
                    .get("decision_id")
                    .and_then(Value::as_str)
                    .ok_or(Error::InvalidBody("decision_refs.decision_id"))?
                    .parse::<fact_core::ObjectId>()
                    .map_err(|_| Error::InvalidBody("decision_refs.decision_id"))?;
                if !ids.insert(decision) {
                    return Err(Error::InvalidBody("decision_refs"));
                }
                let participant = object_id_from_value(
                    x.get("participant_actor_id"),
                    "decision_refs.participant_actor_id",
                )?;
                if !participants.insert(participant)
                    || previous.is_some_and(|prior| (participant, decision) <= prior)
                {
                    return Err(Error::InvalidBody("decision_refs"));
                }
                previous = Some((participant, decision));
                if x.get("content_hash")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<fact_core::Hash>().ok())
                    .is_none()
                {
                    return Err(Error::InvalidBody("decision_refs.content_hash"));
                }
            }
            let pc = nonnegative_count(body, "participant_count")?;
            let dc = nonnegative_count(body, "decided_count")?;
            let ac = nonnegative_count(body, "accepted_count")?;
            let rc = nonnegative_count(body, "rejected_count")?;
            if pc == 0 || dc != pc || ac + rc != dc {
                return Err(Error::InvalidBody("settlement.counts"));
            }
            let outcome = enum_string(body, "outcome", &["accepted", "rejected"])?;
            if (outcome == "accepted") != (rc == 0) {
                return Err(Error::InvalidBody("settlement.outcome"));
            }
            if !body
                .get("causal_settlement_point")
                .is_some_and(Value::is_object)
            {
                return Err(Error::InvalidBody("causal_settlement_point"));
            }
            enum_string(body, "producer_type", &["participant", "coordinator"])?;
            object_id_string(body, "producer_id")?;
        }
        "proposition_lifecycle" => {
            object_id_string(body, "proposition_id")?;
            let dimension = enum_string(body, "dimension", &["withdrawal", "archival"])?;
            let operation = enum_string(
                body,
                "operation",
                &["withdraw", "restore", "archive", "unarchive"],
            )?;
            let valid = matches!(
                (dimension, operation),
                ("withdrawal", "withdraw" | "restore") | ("archival", "archive" | "unarchive")
            );
            if !valid {
                return Err(Error::InvalidBody("operation"));
            }
            id_array(
                body.get("predecessor_ids").unwrap(),
                "predecessor_ids",
                false,
            )?;
            object_id_string(body, "authorization_ref")?;
            nonempty_string(body, "reason")?;
        }
        "protocol_relationship" => {
            object_id_string(body, "source_object_id")?;
            let relationship = nonempty_string(body, "relationship")?;
            if body.get("relationship_version").and_then(Value::as_i64) != Some(0) {
                return Err(Error::InvalidBody("relationship_version"));
            }
            if !relationship.starts_with("protocol:") || !valid_protocol_relationship(relationship)
            {
                return Err(Error::InvalidBody("relationship"));
            }
            let targets = body
                .get("target_object_ids")
                .ok_or(Error::InvalidBody("target_object_ids"))?;
            id_array(targets, "target_object_ids", true)?;
            validate_relationship_cardinality(relationship, targets.as_array().unwrap().len())?;
        }
        "application_relationship" => {
            object_id_string(body, "source_object_id")?;
            let relationship = nonempty_string(body, "relationship")?;
            if relationship.starts_with("protocol:") {
                return Err(Error::InvalidBody("relationship"));
            }
            id_array(
                body.get("target_object_ids").unwrap(),
                "target_object_ids",
                false,
            )?;
            require_object(body, "metadata")?;
            if !body.get("shared").is_some_and(Value::is_boolean) {
                return Err(Error::InvalidBody("shared"));
            }
        }
        "proposition_provenance" => {
            object_id_string(body, "proposition_id")?;
            object_id_string(body, "source_ledger_id")?;
            object_id_string(body, "source_proposition_id")?;
            object_id_string(body, "source_revision_id")?;
            validate_hash_string(body, "source_content_hash")?;
            enum_string(body, "copy_mode", &["snapshot", "reference"])?;
            let bundle = body.get("source_object_bundle").unwrap();
            if body.get("copy_mode").and_then(Value::as_str) == Some("snapshot") {
                if bundle.is_null() || !bundle.is_string() {
                    return Err(Error::InvalidBody("source_object_bundle"));
                }
            } else if !bundle.is_null() && !bundle.is_string() {
                return Err(Error::InvalidBody("source_object_bundle"));
            }
        }
        _ => {}
    }
    Ok(())
}

fn valid_protocol_relationship(name: &str) -> bool {
    matches!(
        name,
        "protocol:parent-revision"
            | "protocol:supersedes"
            | "protocol:extends"
            | "protocol:derived-from"
            | "protocol:reconciles"
            | "protocol:copies"
            | "protocol:references"
            | "protocol:revokes"
            | "protocol:supersedes-authorization"
            | "protocol:delegates-to"
            | "protocol:attests-to"
            | "protocol:binds-key"
            | "protocol:invites"
            | "protocol:joins"
            | "protocol:settles"
    )
}

fn validate_relationship_cardinality(name: &str, count: usize) -> Result<(), Error> {
    let valid = match name {
        "protocol:parent-revision"
        | "protocol:extends"
        | "protocol:copies"
        | "protocol:revokes"
        | "protocol:supersedes-authorization"
        | "protocol:delegates-to"
        | "protocol:attests-to"
        | "protocol:binds-key"
        | "protocol:invites"
        | "protocol:joins"
        | "protocol:settles" => count == 1,
        "protocol:reconciles" => count >= 2,
        _ => count >= 1,
    };
    valid
        .then_some(())
        .ok_or(Error::InvalidBody("relationship.cardinality"))
}

fn validate_relationship_refs(value: &Value) -> Result<(), Error> {
    let refs = value
        .as_array()
        .ok_or(Error::InvalidBody("relationships"))?;
    for reference in refs {
        let object = reference
            .as_object()
            .ok_or(Error::InvalidBody("relationships"))?;
        if object
            .keys()
            .any(|key| !["relationship", "targets"].contains(&key.as_str()))
        {
            return Err(Error::InvalidBody("relationships.fields"));
        }
        let relationship = object
            .get("relationship")
            .and_then(Value::as_str)
            .ok_or(Error::InvalidBody("relationships.relationship"))?;
        if relationship.starts_with("protocol:") && !valid_protocol_relationship(relationship) {
            return Err(Error::InvalidBody("relationships.relationship"));
        }
        let targets = object
            .get("targets")
            .ok_or(Error::InvalidBody("relationships.targets"))?;
        id_array(targets, "relationships.targets", true)?;
        if relationship.starts_with("protocol:") {
            validate_relationship_cardinality(relationship, targets.as_array().unwrap().len())?;
        }
    }
    Ok(())
}

fn enum_string<'a>(
    body: &'a serde_json::Map<String, Value>,
    field: &'static str,
    allowed: &[&str],
) -> Result<&'a str, Error> {
    let value = body
        .get(field)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidBody(field))?;
    if allowed.contains(&value) {
        Ok(value)
    } else {
        Err(Error::InvalidBody(field))
    }
}

fn string_field<'a>(
    body: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, Error> {
    body.get(field)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidBody(field))
}

fn nonempty_string<'a>(
    body: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, Error> {
    let value = string_field(body, field)?;
    if value.is_empty() {
        Err(Error::InvalidBody(field))
    } else {
        Ok(value)
    }
}

fn capability_string<'a>(
    body: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, Error> {
    enum_string(
        body,
        field,
        &[
            "propose",
            "deliberate",
            "invite",
            "comment",
            "accept",
            "reject",
            "withdraw",
            "archive",
            "admin",
        ],
    )
}

fn validate_capabilities(value: &Value) -> Result<(), Error> {
    let values = value.as_array().ok_or(Error::InvalidBody("capabilities"))?;
    if values.is_empty() {
        return Err(Error::InvalidBody("capabilities"));
    }
    let mut seen = HashSet::new();
    for value in values {
        let capability = value.as_str().ok_or(Error::InvalidBody("capabilities"))?;
        if ![
            "propose",
            "deliberate",
            "invite",
            "comment",
            "accept",
            "reject",
            "withdraw",
            "archive",
            "admin",
        ]
        .contains(&capability)
            || !seen.insert(capability)
        {
            return Err(Error::InvalidBody("capabilities"));
        }
    }
    Ok(())
}

fn validate_scope(value: &Value) -> Result<(), Error> {
    let scope = value.as_object().ok_or(Error::InvalidBody("scope"))?;
    let kind = scope
        .get("type")
        .and_then(Value::as_str)
        .ok_or(Error::InvalidBody("scope.type"))?;
    let allowed: &[&str] = match kind {
        "ledger" => &["type"],
        "namespace" => &["type", "name"],
        "proposition" | "revision" | "deliberation" | "actor" => &["type", "id"],
        "capability_class" => &["type", "capability"],
        _ => return Err(Error::InvalidBody("scope.type")),
    };
    if scope.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(Error::InvalidBody("scope.fields"));
    }
    match kind {
        "namespace" => {
            if !valid_namespace(string_from_object(scope, "name")?) {
                return Err(Error::InvalidBody("scope.name"));
            }
        }
        "proposition" | "revision" | "deliberation" | "actor" => {
            object_id_from_value(scope.get("id"), "scope.id")?;
        }
        "capability_class" => {
            capability_from_value(scope.get("capability"), "scope.capability")?;
        }
        _ => {}
    }
    Ok(())
}

fn string_from_object<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, Error> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidBody(field))
}

fn object_id_from_value(
    value: Option<&Value>,
    field: &'static str,
) -> Result<fact_core::ObjectId, Error> {
    value
        .and_then(Value::as_str)
        .ok_or(Error::InvalidBody(field))?
        .parse::<fact_core::ObjectId>()
        .map_err(|_| Error::InvalidBody(field))
}

fn capability_from_value(value: Option<&Value>, field: &'static str) -> Result<(), Error> {
    let capability = value
        .and_then(Value::as_str)
        .ok_or(Error::InvalidBody(field))?;
    if [
        "propose",
        "deliberate",
        "invite",
        "comment",
        "accept",
        "reject",
        "withdraw",
        "archive",
        "admin",
    ]
    .contains(&capability)
    {
        Ok(())
    } else {
        Err(Error::InvalidBody(field))
    }
}

fn require_object(body: &serde_json::Map<String, Value>, field: &'static str) -> Result<(), Error> {
    if body.get(field).is_some_and(Value::is_object) {
        Ok(())
    } else {
        Err(Error::InvalidBody(field))
    }
}

fn validate_timestamp_field(
    body: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), Error> {
    fact_core::validate_timestamp(string_field(body, field)?).map_err(|_| Error::InvalidBody(field))
}

fn validate_validity(value: &Value, field: &'static str, nullable: bool) -> Result<(), Error> {
    if nullable && value.is_null() {
        return Ok(());
    }
    let validity = value.as_object().ok_or(Error::InvalidBody(field))?;
    if validity
        .keys()
        .any(|key| !["valid_from", "expires_at"].contains(&key.as_str()))
    {
        return Err(Error::InvalidBody(field));
    }
    let valid_from = validity
        .get("valid_from")
        .and_then(Value::as_str)
        .ok_or(Error::InvalidBody(field))?;
    fact_core::validate_timestamp(valid_from).map_err(|_| Error::InvalidBody(field))?;
    if let Some(expires_at) = validity.get("expires_at") {
        if !expires_at.is_null() {
            let expires_at = expires_at.as_str().ok_or(Error::InvalidBody(field))?;
            fact_core::validate_timestamp(expires_at).map_err(|_| Error::InvalidBody(field))?;
            if expires_at <= valid_from {
                return Err(Error::InvalidBody(field));
            }
        }
    }
    Ok(())
}

fn nullable_validity(
    body: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), Error> {
    validate_validity(body.get(field).unwrap(), field, true)
}

fn nullable_id_array(
    body: &serde_json::Map<String, Value>,
    field: &'static str,
    nonempty: bool,
) -> Result<(), Error> {
    if body.get(field).is_some_and(Value::is_null) {
        return Ok(());
    }
    id_array(body.get(field).unwrap(), field, nonempty)
}

fn id_array(value: &Value, field: &'static str, nonempty: bool) -> Result<(), Error> {
    let values = value.as_array().ok_or(Error::InvalidBody(field))?;
    if nonempty && values.is_empty() {
        return Err(Error::InvalidBody(field));
    }
    let mut seen = HashSet::new();
    for value in values {
        let id = value
            .as_str()
            .ok_or(Error::InvalidBody(field))?
            .parse::<fact_core::ObjectId>()
            .map_err(|_| Error::InvalidBody(field))?;
        if !seen.insert(id) {
            return Err(Error::InvalidBody(field));
        }
    }
    Ok(())
}

fn validate_hash_string(
    body: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), Error> {
    let hash = string_field(body, field)?;
    hash.parse::<fact_core::Hash>()
        .map_err(|_| Error::InvalidBody(field))
        .map(|_| ())
}

fn nullable_hash(body: &serde_json::Map<String, Value>, field: &'static str) -> Result<(), Error> {
    if let Some(value) = body.get(field) {
        if !value.is_null() {
            value
                .as_str()
                .ok_or(Error::InvalidBody(field))?
                .parse::<fact_core::Hash>()
                .map_err(|_| Error::InvalidBody(field))?;
        }
    }
    Ok(())
}

fn validate_evidence_array(value: &Value) -> Result<(), Error> {
    let values = value
        .as_array()
        .ok_or(Error::InvalidBody("admission_evidence"))?;
    let mut seen = HashSet::new();
    for value in values {
        let object = value
            .as_object()
            .ok_or(Error::InvalidBody("admission_evidence"))?;
        if object
            .keys()
            .any(|key| !["object_id", "content_hash"].contains(&key.as_str()))
        {
            return Err(Error::InvalidBody("admission_evidence"));
        }
        let id = object_id_from_value(object.get("object_id"), "admission_evidence.object_id")?;
        let hash = object
            .get("content_hash")
            .and_then(Value::as_str)
            .ok_or(Error::InvalidBody("admission_evidence.content_hash"))?
            .parse::<fact_core::Hash>()
            .map_err(|_| Error::InvalidBody("admission_evidence.content_hash"))?;
        let key = (id, hash);
        if !seen.insert(key) {
            return Err(Error::InvalidBody("admission_evidence"));
        }
    }
    Ok(())
}

fn validate_attestation_requirements(values: &[Value]) -> Result<(), Error> {
    let mut seen = HashSet::new();
    for value in values {
        let object = value
            .as_object()
            .ok_or(Error::InvalidBody("attestation_requirements"))?;
        if !exact_fields(
            object,
            &["claim_type", "permitted_issuers", "minimum_count"],
        ) {
            return Err(Error::InvalidBody("attestation_requirements.fields"));
        }
        let claim_type = object
            .get("claim_type")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(Error::InvalidBody("attestation_requirements.claim_type"))?;
        let issuers = object
            .get("permitted_issuers")
            .and_then(Value::as_array)
            .filter(|values| !values.is_empty())
            .ok_or(Error::InvalidBody(
                "attestation_requirements.permitted_issuers",
            ))?;
        let mut issuer_ids = HashSet::new();
        for issuer in issuers {
            let id =
                object_id_from_value(Some(issuer), "attestation_requirements.permitted_issuers")?;
            if !issuer_ids.insert(id) {
                return Err(Error::InvalidBody(
                    "attestation_requirements.permitted_issuers",
                ));
            }
        }
        let minimum_count = object
            .get("minimum_count")
            .and_then(Value::as_i64)
            .filter(|value| *value >= 1)
            .ok_or(Error::InvalidBody("attestation_requirements.minimum_count"))?;
        let mut issuer_fingerprint = issuer_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        issuer_fingerprint.sort();
        if !seen.insert((claim_type.to_owned(), issuer_fingerprint, minimum_count)) {
            return Err(Error::InvalidBody("attestation_requirements"));
        }
    }
    Ok(())
}
fn object_id_string(
    body: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), Error> {
    let value = body
        .get(field)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidBody(field))?;
    value
        .parse::<fact_core::ObjectId>()
        .map_err(|_| Error::InvalidBody(field))
        .map(|_| ())
}
fn object_id_value(value: Option<&Value>, field: &'static str) -> Result<(), Error> {
    let value = value
        .and_then(Value::as_str)
        .ok_or(Error::InvalidBody(field))?;
    value
        .parse::<fact_core::ObjectId>()
        .map_err(|_| Error::InvalidBody(field))
        .map(|_| ())
}
fn nullable_object_id(
    body: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), Error> {
    if let Some(v) = body.get(field) {
        if !v.is_null() {
            object_id_value(Some(v), field)?
        }
    }
    Ok(())
}
fn nonnegative_count(
    body: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<u64, Error> {
    body.get(field)
        .and_then(Value::as_u64)
        .ok_or(Error::InvalidBody(field))
}
fn validate_content(value: &Value) -> Result<(), Error> {
    let content = value.as_object().ok_or(Error::InvalidBody("content"))?;
    if content.get("media_type").and_then(Value::as_str)
        != Some("text/markdown; charset=utf-8; variant=fact-v0")
    {
        return Err(Error::InvalidBody("content.media_type"));
    }
    let bytes = decode_base64url(
        content
            .get("bytes")
            .and_then(Value::as_str)
            .ok_or(Error::InvalidBody("content.bytes"))?,
    )
    .ok_or(Error::InvalidBody("content.bytes"))?;
    fact_canonical::validate_canonical_markdown(&bytes)
        .map_err(|_| Error::InvalidBody("content.bytes"))?;
    if content.get("hash").and_then(Value::as_str)
        != Some(fact_core::Hash::digest(&bytes).hex().as_str())
    {
        return Err(Error::InvalidBody("content.hash"));
    }
    Ok(())
}
fn valid_namespace(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'/' | b'-')
        })
        && !s.starts_with('.')
        && !s.starts_with('/')
        && !s.starts_with('-')
        && !s.ends_with('.')
        && !s.ends_with('/')
        && !s.ends_with('-')
        && !s.contains("..")
        && !s.contains("//")
        && !s.contains("--")
}
fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    if input.contains('=')
        || !input
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return None;
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u8;
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 6 || acc != 0 {
        None
    } else {
        Some(out)
    }
}

fn valid_dependency_role(role: &str) -> bool {
    if role.is_empty() {
        return false;
    }
    let bytes = role.as_bytes();
    let mut separator = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            separator = false;
        } else if (byte == b'.' || byte == b'_' || byte == b'-')
            && index > 0
            && index + 1 < bytes.len()
            && !separator
        {
            separator = true;
        } else {
            return false;
        }
    }
    true
}

fn exact_fields(object: &serde_json::Map<String, Value>, fields: &[&str]) -> bool {
    object.len() == fields.len() && object.keys().all(|key| fields.contains(&key.as_str()))
}

fn validate_reconciliation_manifest(value: &Value) -> Result<(), Error> {
    let manifest = value
        .as_object()
        .ok_or(Error::InvalidBody("reconciliation_manifest"))?;
    if !exact_fields(
        manifest,
        &[
            "affected_proposition_id",
            "common_ancestor_revision_id",
            "conflicts",
            "conflict_set_hash",
            "detector_actor_id",
            "resolution_mode",
            "selected_revision_id",
            "result_revision_id",
        ],
    ) {
        return Err(Error::InvalidBody("reconciliation_manifest.fields"));
    }
    for field in [
        "affected_proposition_id",
        "common_ancestor_revision_id",
        "detector_actor_id",
    ] {
        object_id_string(manifest, field)?;
    }
    validate_hash_string(manifest, "conflict_set_hash")?;
    let conflicts = manifest
        .get("conflicts")
        .and_then(Value::as_array)
        .ok_or(Error::InvalidBody("reconciliation_manifest.conflicts"))?;
    if conflicts.is_empty() {
        return Err(Error::InvalidBody("reconciliation_manifest.conflicts"));
    }
    let mut previous = None;
    for conflict in conflicts {
        let conflict = conflict
            .as_object()
            .ok_or(Error::InvalidBody("reconciliation_manifest.conflict"))?;
        if !exact_fields(
            conflict,
            &["revision_id", "deliberation_id", "settlement_id", "outcome"],
        ) {
            return Err(Error::InvalidBody(
                "reconciliation_manifest.conflict.fields",
            ));
        }
        object_id_string(conflict, "revision_id")?;
        object_id_string(conflict, "deliberation_id")?;
        let revision = conflict["revision_id"]
            .as_str()
            .unwrap()
            .parse::<fact_core::ObjectId>()
            .map_err(|_| Error::InvalidBody("reconciliation_manifest.revision_id"))?;
        let deliberation = conflict["deliberation_id"]
            .as_str()
            .unwrap()
            .parse::<fact_core::ObjectId>()
            .map_err(|_| Error::InvalidBody("reconciliation_manifest.deliberation_id"))?;
        enum_string(conflict, "outcome", &["accepted", "rejected"])?;
        object_id_string(conflict, "settlement_id")?;
        if previous.is_some_and(|(old_revision, old_deliberation)| {
            (revision, deliberation) <= (old_revision, old_deliberation)
        }) {
            return Err(Error::InvalidBody(
                "reconciliation_manifest.conflicts.order",
            ));
        }
        previous = Some((revision, deliberation));
    }
    let mode = enum_string(
        manifest,
        "resolution_mode",
        &["select", "derive", "reject-all"],
    )?;
    let selected = manifest
        .get("selected_revision_id")
        .is_some_and(|value| !value.is_null());
    let result = manifest
        .get("result_revision_id")
        .is_some_and(|value| !value.is_null());
    if selected {
        nullable_object_id(manifest, "selected_revision_id")?;
    }
    if result {
        nullable_object_id(manifest, "result_revision_id")?;
    }
    if (mode == "select") != (selected && !result)
        || (mode == "derive") != (result && !selected)
        || (mode == "reject-all") != (!selected && !result)
    {
        return Err(Error::InvalidBody("reconciliation_manifest.resolution"));
    }
    Ok(())
}

fn validate_evidence(value: &Value, field: &'static str) -> Result<(), Error> {
    let evidence = value.as_array().ok_or(Error::InvalidBody(field))?;
    let mut ids = HashSet::new();
    for entry in evidence {
        let entry = entry.as_object().ok_or(Error::InvalidBody(field))?;
        if !exact_fields(entry, &["object_id", "content_hash"]) {
            return Err(Error::InvalidBody(field));
        }
        object_id_string(entry, "object_id")?;
        let id = entry["object_id"]
            .as_str()
            .unwrap()
            .parse::<fact_core::ObjectId>()
            .map_err(|_| Error::InvalidBody(field))?;
        validate_hash_string(entry, "content_hash")?;
        if !ids.insert(id) {
            return Err(Error::InvalidBody(field));
        }
    }
    Ok(())
}

fn validate_roster_governance(
    value: &Value,
    initial_participants: &[fact_core::ObjectId],
) -> Result<(), Error> {
    let roster = value
        .as_object()
        .ok_or(Error::InvalidBody("roster_governance"))?;
    if !exact_fields(
        roster,
        &[
            "schema_version",
            "selection_mode",
            "source_deliberation_ids",
            "candidate_union",
            "excluded_candidates",
            "selected_participants",
            "selection_authority",
        ],
    ) {
        return Err(Error::InvalidBody("roster_governance.fields"));
    }
    if roster.get("schema_version").and_then(Value::as_i64) != Some(0) {
        return Err(Error::InvalidBody("roster_governance.schema_version"));
    }
    let selection_mode = enum_string(roster, "selection_mode", &["union_eligible", "explicit"])?;
    let source_ids = roster
        .get("source_deliberation_ids")
        .and_then(Value::as_array)
        .ok_or(Error::InvalidBody(
            "roster_governance.source_deliberation_ids",
        ))?;
    if source_ids.is_empty() {
        return Err(Error::InvalidBody(
            "roster_governance.source_deliberation_ids",
        ));
    }
    validate_sorted_ids(source_ids, "roster_governance.source_deliberation_ids")?;
    let source_id_set = source_ids
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(Error::InvalidBody(
                    "roster_governance.source_deliberation_ids",
                ))?
                .parse::<fact_core::ObjectId>()
                .map_err(|_| Error::InvalidBody("roster_governance.source_deliberation_ids"))
        })
        .collect::<Result<HashSet<_>, _>>()?;
    let candidates = roster
        .get("candidate_union")
        .and_then(Value::as_array)
        .ok_or(Error::InvalidBody("roster_governance.candidate_union"))?;
    let mut candidate_ids = Vec::with_capacity(candidates.len());
    for entry in candidates {
        let entry = entry
            .as_object()
            .ok_or(Error::InvalidBody("roster_governance.candidate_union"))?;
        if !exact_fields(entry, &["actor_id", "source_memberships"]) {
            return Err(Error::InvalidBody("roster_governance.candidate"));
        }
        let actor_id = entry
            .get("actor_id")
            .and_then(Value::as_str)
            .ok_or(Error::InvalidBody("roster_governance.candidate.actor_id"))?;
        candidate_ids.push(
            actor_id
                .parse::<fact_core::ObjectId>()
                .map_err(|_| Error::InvalidBody("roster_governance.candidate.actor_id"))?,
        );
        let memberships = entry
            .get("source_memberships")
            .and_then(Value::as_array)
            .ok_or(Error::InvalidBody("roster_governance.source_memberships"))?;
        if memberships.is_empty() {
            return Err(Error::InvalidBody("roster_governance.source_memberships"));
        }
        let mut membership_ids = Vec::with_capacity(memberships.len());
        for membership in memberships {
            let membership = membership
                .as_object()
                .ok_or(Error::InvalidBody("roster_governance.source_membership"))?;
            if !exact_fields(membership, &["deliberation_id", "membership_evidence"]) {
                return Err(Error::InvalidBody("roster_governance.source_membership"));
            }
            let deliberation_id = membership
                .get("deliberation_id")
                .and_then(Value::as_str)
                .ok_or(Error::InvalidBody("roster_governance.deliberation_id"))?;
            membership_ids.push(
                deliberation_id
                    .parse::<fact_core::ObjectId>()
                    .map_err(|_| Error::InvalidBody("roster_governance.deliberation_id"))?,
            );
            if !source_id_set.contains(membership_ids.last().unwrap()) {
                return Err(Error::InvalidBody(
                    "roster_governance.source_membership.scope",
                ));
            }
            validate_evidence(
                membership.get("membership_evidence").unwrap(),
                "roster_governance.membership_evidence",
            )?;
        }
        if membership_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::InvalidBody(
                "roster_governance.source_memberships.order",
            ));
        }
    }
    if candidate_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::InvalidBody(
            "roster_governance.candidate_union.order",
        ));
    }
    let candidate_id_set: HashSet<_> = candidate_ids.iter().copied().collect();
    let mut excluded_ids = HashSet::new();
    for entry in roster
        .get("excluded_candidates")
        .and_then(Value::as_array)
        .ok_or(Error::InvalidBody("roster_governance.excluded_candidates"))?
    {
        let entry = entry
            .as_object()
            .ok_or(Error::InvalidBody("roster_governance.excluded_candidate"))?;
        if !exact_fields(entry, &["actor_id", "reason", "evidence"]) {
            return Err(Error::InvalidBody("roster_governance.excluded_candidate"));
        }
        let excluded_id = entry
            .get("actor_id")
            .and_then(Value::as_str)
            .ok_or(Error::InvalidBody("roster_governance.excluded_candidate"))?
            .parse::<fact_core::ObjectId>()
            .map_err(|_| Error::InvalidBody("roster_governance.excluded_candidate"))?;
        if !excluded_ids.insert(excluded_id) || !candidate_id_set.contains(&excluded_id) {
            return Err(Error::InvalidBody("roster_governance.excluded_candidate"));
        }
        let reason = enum_string(
            entry,
            "reason",
            &[
                "retired",
                "removed",
                "unauthorized",
                "admission_failed",
                "governance_excluded",
            ],
        )?;
        if selection_mode == "union_eligible" && reason == "governance_excluded" {
            return Err(Error::InvalidBody(
                "roster_governance.excluded_candidate.reason",
            ));
        }
        validate_evidence(
            entry.get("evidence").unwrap(),
            "roster_governance.exclusion_evidence",
        )?;
    }
    let selected = roster
        .get("selected_participants")
        .and_then(Value::as_array)
        .ok_or(Error::InvalidBody(
            "roster_governance.selected_participants",
        ))?;
    if selected.is_empty() {
        return Err(Error::InvalidBody(
            "roster_governance.selected_participants",
        ));
    }
    let mut selected_ids = Vec::new();
    let mut selected_bases = Vec::new();
    for entry in selected {
        let entry = entry
            .as_object()
            .ok_or(Error::InvalidBody("roster_governance.selected_participant"))?;
        if !exact_fields(
            entry,
            &[
                "actor_id",
                "selection_basis",
                "source_deliberation_ids",
                "admission_evidence",
            ],
        ) {
            return Err(Error::InvalidBody("roster_governance.selected_participant"));
        }
        object_id_string(entry, "actor_id")?;
        selected_ids.push(
            entry["actor_id"]
                .as_str()
                .unwrap()
                .parse::<fact_core::ObjectId>()
                .map_err(|_| Error::InvalidBody("roster_governance.actor_id"))?,
        );
        let selection_basis = enum_string(
            entry,
            "selection_basis",
            &["source_union", "governance_selected"],
        )?;
        selected_bases.push(selection_basis);
        let ids = entry
            .get("source_deliberation_ids")
            .and_then(Value::as_array)
            .ok_or(Error::InvalidBody("roster_governance.selected_source_ids"))?;
        validate_sorted_ids(ids, "roster_governance.selected_source_ids")?;
        let selected_source_ids = ids
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or(Error::InvalidBody("roster_governance.selected_source_ids"))?
                    .parse::<fact_core::ObjectId>()
                    .map_err(|_| Error::InvalidBody("roster_governance.selected_source_ids"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if selected_source_ids
            .iter()
            .any(|id| !source_id_set.contains(id))
            || (selection_basis == "source_union" && selected_source_ids.is_empty())
            || (selection_basis == "governance_selected" && selection_mode != "explicit")
        {
            return Err(Error::InvalidBody(
                "roster_governance.selected_source_ids.scope",
            ));
        }
        validate_evidence(
            entry.get("admission_evidence").unwrap(),
            "roster_governance.admission_evidence",
        )?;
        if selection_basis == "governance_selected"
            && entry["admission_evidence"]
                .as_array()
                .is_some_and(Vec::is_empty)
        {
            return Err(Error::InvalidBody("roster_governance.admission_evidence"));
        }
    }
    if selected_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::InvalidBody(
            "roster_governance.selected_participants.order",
        ));
    }
    let mut expected = initial_participants.to_vec();
    expected.sort();
    if selected_ids != expected {
        return Err(Error::InvalidBody(
            "roster_governance.selected_participants.mismatch",
        ));
    }
    let selected_set: HashSet<_> = selected_ids.iter().copied().collect();
    if excluded_ids.iter().any(|id| selected_set.contains(id)) {
        return Err(Error::InvalidBody(
            "roster_governance.excluded_candidate.selected",
        ));
    }
    if selection_mode == "union_eligible"
        && selected_bases.iter().any(|basis| *basis != "source_union")
    {
        return Err(Error::InvalidBody(
            "roster_governance.selected_participant.selection_basis",
        ));
    }
    let authority = roster
        .get("selection_authority")
        .and_then(Value::as_object)
        .ok_or(Error::InvalidBody("roster_governance.selection_authority"))?;
    if !exact_fields(authority, &["actor_id", "authorization_ref"]) {
        return Err(Error::InvalidBody("roster_governance.selection_authority"));
    }
    object_id_string(authority, "actor_id")?;
    object_id_string(authority, "authorization_ref")?;
    Ok(())
}

fn validate_sorted_ids(values: &[Value], field: &'static str) -> Result<(), Error> {
    let mut ids = Vec::new();
    for value in values {
        let text = value.as_str().ok_or(Error::InvalidBody(field))?;
        ids.push(
            text.parse::<fact_core::ObjectId>()
                .map_err(|_| Error::InvalidBody(field))?,
        );
    }
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::InvalidBody(field));
    }
    Ok(())
}

/// Generate one deterministic valid canonical envelope for each registered
/// object type. The values are fixed so the conformance runner can compare
/// exact bytes and hashes across processes and implementations.
pub fn generated_positive_fixture(object_type: &str) -> Result<Vec<u8>, Error> {
    let mut sequence = 0u8;
    let mut id = || {
        sequence = sequence.wrapping_add(1);
        fixture_uuid(sequence)
    };
    let object_id = id();
    let other = id();
    let actor = id();
    let key = id();
    let validity = serde_json::json!({"valid_from":"2026-07-27T12:00:00.000Z","expires_at":null});
    let content_bytes = b"# Fact\n";
    let content = serde_json::json!({
        "media_type":"text/markdown; charset=utf-8; variant=fact-v0",
        "hash":fact_core::Hash::digest(content_bytes).hex(),
        "bytes":fixture_b64(content_bytes)
    });
    let body = match object_type {
        "genesis" => {
            serde_json::json!({"ledger_id":object_id,"protocol_version":"0","parameters":{"consensus_rule":"unanimity-v0","namespace_profile":"facts-namespace-v0","content_profile":"facts-protocol-markdown-v0"},"namespace":"example.test","bootstrap_actor":actor,"bootstrap_key":key,"bootstrap_binding":other,"root_grant":id(),"nonce":fixture_b64(&[1u8;16]),"initial_namespace_assertion":id()})
        }
        "namespace_assertion" => {
            serde_json::json!({"namespace":"example.test","target_type":"ledger","target_id":object_id,"naming_authority_actor_id":actor,"validity":validity,"supersedes":null})
        }
        "actor" => {
            serde_json::json!({"actor_type":"agent","bootstrap_key_id":key,"bootstrap_binding_id":other})
        }
        "key" => {
            let bytes = [1u8; 32];
            serde_json::json!({"public_key":{"algorithm":"Ed25519","bytes":fixture_b64(&bytes),"fingerprint":fact_core::Hash::digest(&bytes).hex()},"purpose":"signing"})
        }
        "actor_key_binding" => {
            serde_json::json!({"actor_id":actor,"key_id":key,"permitted_purpose":"signing","predecessor_binding_id":null})
        }
        "key_lifecycle" => {
            serde_json::json!({"operation":"rotate","affected_actor_id":actor,"old_key_id":key,"new_key_id":other,"predecessor_lifecycle_id":null,"effective_at":"2026-07-27T12:00:00.000Z","authorization_ref":null})
        }
        "recovery_policy" => {
            serde_json::json!({"actor_id":actor,"recovery_key_id":key,"policy_version":0,"effective_at":"2026-07-27T12:00:00.000Z","predecessor_policy_id":null})
        }
        "actor_lifecycle" => {
            serde_json::json!({"affected_actor_id":actor,"operation":"retire","effective_at":"2026-07-27T12:00:00.000Z","authorization_ref":object_id})
        }
        "identity_attestation" => {
            serde_json::json!({"subject_type":"actor","subject_id":actor,"claim_type":"display-name","claims":{"name":"Example"},"evidence_hash":null,"validity":validity})
        }
        "authorization_grant" => {
            serde_json::json!({"grant_id":object_id,"granting_actor_id":actor,"receiving_actor_id":other,"capabilities":["comment"],"scope":{"type":"ledger"},"validity":null,"constraints":{},"predecessor_grant_id":null})
        }
        "authorization_revocation" => {
            serde_json::json!({"revoked_grant_id":object_id,"effective_at":"2026-07-27T12:00:00.000Z","reason":"because","authorization_ref":other})
        }
        "delegation" => {
            serde_json::json!({"delegator_actor_id":actor,"delegatee_actor_id":other,"capability":"comment","scope":{"type":"ledger"},"validity":null,"parent_delegation_id":null,"redelegable":false,"constraints":{}})
        }
        "delegation_revocation" => {
            serde_json::json!({"revoked_delegation_id":object_id,"effective_at":"2026-07-27T12:00:00.000Z","reason":"because","authorization_ref":other})
        }
        "proposition" => {
            serde_json::json!({"proposition_id":object_id,"purpose":"knowledge","initial_revision_id":other,"initial_deliberation_id":key})
        }
        "revision" => {
            serde_json::json!({"proposition_id":object_id,"revision_id":other,"parent_revision_id":null,"content":content,"relationships":[],"reconciliation_manifest":null})
        }
        "deliberation" => {
            serde_json::json!({"deliberation_id":object_id,"proposition_id":other,"revision_id":key,"extends_deliberation_id":null,"decision_rule":{"id":"unanimity","version":0,"parameters":{}},"join_policy":{"policy_version":0,"mode":"open","attestation_requirements":[]},"initial_participants":[{"actor_id":actor,"carried_decision_id":null}],"roster_governance":null,"opening_actor_id":actor,"comments_closed_on_settlement":true})
        }
        "standing_participant_change" => {
            serde_json::json!({"proposition_id":object_id,"participant_actor_id":actor,"operation":"join","predecessor_change_id":null,"changed_by_actor_id":actor,"authorization_ref":null})
        }
        "deliberation_participant_change" => {
            serde_json::json!({"deliberation_id":object_id,"participant_actor_id":actor,"operation":"join","invitation_id":null,"admission_evidence":[],"carried_decision_id":null,"predecessor_change_id":null,"changed_by_actor_id":actor,"authorization_ref":null})
        }
        "participant_invitation" => {
            serde_json::json!({"invitation_id":object_id,"proposition_id":other,"inviting_actor_id":actor,"invited_actor_id":key,"participation_type":"standing","constraints":{},"validity":null,"predecessor_invitation_id":null})
        }
        "invitation_lifecycle" => {
            serde_json::json!({"invitation_id":object_id,"operation":"decline","predecessor_lifecycle_ids":[],"reason":"because","authorization_ref":other})
        }
        "decision" => {
            serde_json::json!({"deliberation_id":object_id,"participant_actor_id":actor,"value":"accepted","supersedes_decision_ids":[],"authorization_ref":null})
        }
        "deliberation_comment" => {
            serde_json::json!({"deliberation_id":object_id,"content":content,"parent_comment_id":null,"comment_phase":"pre-settlement"})
        }
        "settlement" => {
            serde_json::json!({"deliberation_id":object_id,"revision_id":other,"decision_rule":{"id":"unanimity","version":0,"parameters":{}},"decision_refs":[{"decision_id":key,"participant_actor_id":actor,"content_hash":"00".repeat(32)}],"participant_count":1,"decided_count":1,"accepted_count":1,"rejected_count":0,"outcome":"accepted","causal_settlement_point":{"object_id":object_id},"producer_type":"participant","producer_id":actor})
        }
        "proposition_lifecycle" => {
            serde_json::json!({"proposition_id":object_id,"dimension":"withdrawal","operation":"withdraw","predecessor_ids":[other],"authorization_ref":key,"reason":"because"})
        }
        "protocol_relationship" => {
            serde_json::json!({"source_object_id":object_id,"relationship":"protocol:references","target_object_ids":[other],"relationship_version":0})
        }
        "application_relationship" => {
            serde_json::json!({"source_object_id":object_id,"relationship":"related-to","target_object_ids":[],"metadata":{},"shared":false})
        }
        "proposition_provenance" => {
            serde_json::json!({"proposition_id":object_id,"source_ledger_id":other,"source_proposition_id":actor,"source_revision_id":key,"source_content_hash":"00".repeat(32),"source_object_bundle":"AA","copy_mode":"snapshot"})
        }
        _ => return Err(Error::UnknownType),
    };
    let envelope_id = match object_type {
        "authorization_grant" => body["grant_id"].as_str().unwrap(),
        "proposition" => body["proposition_id"].as_str().unwrap(),
        "revision" => body["revision_id"].as_str().unwrap(),
        "deliberation" => body["deliberation_id"].as_str().unwrap(),
        "participant_invitation" => body["invitation_id"].as_str().unwrap(),
        _ => &object_id,
    };
    let value = if ObjectType::from_str(object_type)?.ledger_scoped() {
        serde_json::json!({"id":envelope_id,"ledger_id":object_id,"object_type":object_type,"schema_version":"0","actor_id":actor,"signing_key_id":key,"created_at":"2026-07-27T12:00:00.000Z","dependencies":[],"body":body})
    } else {
        serde_json::json!({"id":envelope_id,"object_type":object_type,"schema_version":"0","actor_id":actor,"signing_key_id":key,"created_at":"2026-07-27T12:00:00.000Z","dependencies":[],"body":body})
    };
    let bytes = fact_canonical::encode(&serde_json::to_vec(&value).map_err(|_| Error::NotObject)?)?;
    validate_envelope(&bytes)?;
    Ok(bytes)
}

fn fixture_uuid(sequence: u8) -> String {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&[0x01, 0x90, 0x00, 0x00, 0x00, 0x00, 0x70, sequence]);
    bytes[8..].copy_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, sequence]);
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn fixture_b64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        output.push(TABLE[((n >> 18) & 63) as usize] as char);
        output.push(TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(n & 63) as usize] as char);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> String {
        uuid::Uuid::now_v7().to_string()
    }

    fn envelope(object_type: &str, body: Value) -> Vec<u8> {
        let object_id = body
            .get(match object_type {
                "authorization_grant" => "grant_id",
                "proposition" => "proposition_id",
                "revision" => "revision_id",
                "deliberation" => "deliberation_id",
                "participant_invitation" => "invitation_id",
                _ => "__none__",
            })
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(id);
        let value = serde_json::json!({
            "id": object_id,
            "ledger_id": id(),
            "object_type": object_type,
            "schema_version": "0",
            "actor_id": id(),
            "signing_key_id": id(),
            "created_at": "2026-07-27T12:00:00.000Z",
            "dependencies": [],
            "body": body,
        });
        fact_canonical::encode(&serde_json::to_vec(&value).unwrap()).unwrap()
    }
    #[test]
    fn validates_typed_key_and_fingerprint() {
        let key_bytes = vec![1u8; 32];
        let key_id = id();
        let actor_id = id();
        let object_id = id();
        let value = serde_json::json!({"id":object_id,"object_type":"key","schema_version":"0","actor_id":actor_id,"signing_key_id":key_id,"created_at":"2026-07-27T12:00:00.000Z","dependencies":[],"body":{"public_key":{"algorithm":"Ed25519","bytes":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","fingerprint":fact_core::Hash::digest(&key_bytes).hex()},"purpose":"signing"}});
        let canonical = fact_canonical::encode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(validate_envelope(&canonical).unwrap().as_str(), "key");
        let mut invalid = value;
        invalid["body"]["public_key"]["fingerprint"] = Value::String("00".repeat(32));
        let bytes = fact_canonical::encode(&serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(matches!(
            validate_envelope(&bytes),
            Err(Error::InvalidBody("public_key.fingerprint"))
        ));
    }

    #[test]
    fn validates_typed_proposition_deliberation_decision_and_settlement() {
        let proposition = serde_json::json!({
            "proposition_id": id(),
            "purpose": "knowledge",
            "initial_revision_id": id(),
            "initial_deliberation_id": id(),
        });
        assert_eq!(
            validate_envelope(&envelope("proposition", proposition))
                .unwrap()
                .as_str(),
            "proposition"
        );

        let roster_actor = id();
        let deliberation = serde_json::json!({
            "deliberation_id": id(),
            "proposition_id": id(),
            "revision_id": id(),
            "extends_deliberation_id": null,
            "decision_rule": {"id":"unanimity","version":0,"parameters":{}},
            "join_policy": {"policy_version":0,"mode":"open","attestation_requirements":[]},
            "initial_participants": [{"actor_id":roster_actor,"carried_decision_id":null}],
            "roster_governance": null,
            "opening_actor_id": id(),
            "comments_closed_on_settlement": true,
        });
        assert!(validate_envelope(&envelope("deliberation", deliberation.clone())).is_ok());

        let decision_id = id();
        let decision = serde_json::json!({
            "deliberation_id": id(),
            "participant_actor_id": id(),
            "value": "accepted",
            "supersedes_decision_ids": [],
            "authorization_ref": null,
        });
        assert!(validate_envelope(&envelope("decision", decision)).is_ok());

        let settlement = serde_json::json!({
            "deliberation_id": id(),
            "revision_id": id(),
            "decision_rule": {"id":"unanimity","version":0,"parameters":{}},
            "decision_refs": [{"decision_id":decision_id,"participant_actor_id":id(),"content_hash":"00".repeat(32)}],
            "participant_count": 1,
            "decided_count": 1,
            "accepted_count": 1,
            "rejected_count": 0,
            "outcome": "accepted",
            "causal_settlement_point": {"object_id":id()},
            "producer_type": "participant",
            "producer_id": id(),
        });
        assert!(validate_envelope(&envelope("settlement", settlement)).is_ok());

        let conflict_revision = id();
        let conflict_deliberation = id();
        let manifest = serde_json::json!({
            "affected_proposition_id":id(), "common_ancestor_revision_id":id(),
            "conflicts":[{"revision_id":conflict_revision,"deliberation_id":conflict_deliberation,"settlement_id":id(),"outcome":"accepted"}],
            "conflict_set_hash":"00".repeat(32), "detector_actor_id":id(), "resolution_mode":"reject-all", "selected_revision_id":null, "result_revision_id":null
        });
        let revision = serde_json::json!({"proposition_id":id(),"revision_id":id(),"parent_revision_id":null,"content":serde_json::json!({"media_type":"text/markdown; charset=utf-8; variant=fact-v0","hash":fact_core::Hash::digest(b"# Fact\n").hex(),"bytes":test_b64(b"# Fact\n")}),"relationships":[],"reconciliation_manifest":manifest.clone()});
        assert!(validate_envelope(&envelope("revision", revision)).is_ok());

        let roster = serde_json::json!({
            "schema_version":0,"selection_mode":"union_eligible","source_deliberation_ids":[conflict_deliberation],
            "candidate_union":[{"actor_id":roster_actor,"source_memberships":[{"deliberation_id":conflict_deliberation,"membership_evidence":[{"object_id":id(),"content_hash":"00".repeat(32)}]}]}],
            "excluded_candidates":[],"selected_participants":[{"actor_id":roster_actor,"selection_basis":"source_union","source_deliberation_ids":[conflict_deliberation],"admission_evidence":[]}],
            "selection_authority":{"actor_id":id(),"authorization_ref":id()}
        });
        let mut reconciliation_deliberation = deliberation;
        reconciliation_deliberation["roster_governance"] = roster;
        assert!(validate_envelope(&envelope(
            "deliberation",
            reconciliation_deliberation.clone()
        ))
        .is_ok());
        let mut invalid_roster = reconciliation_deliberation["roster_governance"].clone();
        invalid_roster["selected_participants"][0]["selection_basis"] =
            Value::String("governance_selected".to_owned());
        let mut invalid_deliberation = reconciliation_deliberation.clone();
        invalid_deliberation["roster_governance"] = invalid_roster;
        assert!(validate_envelope(&envelope("deliberation", invalid_deliberation)).is_err());
        let mut invalid_admission = reconciliation_deliberation.clone();
        invalid_admission["roster_governance"]["selection_mode"] =
            Value::String("explicit".to_owned());
        invalid_admission["roster_governance"]["selected_participants"][0]["selection_basis"] =
            Value::String("governance_selected".to_owned());
        assert!(validate_envelope(&envelope("deliberation", invalid_admission)).is_err());
        let mut invalid_manifest = manifest;
        invalid_manifest["resolution_mode"] = serde_json::json!("select");
        let invalid_revision = serde_json::json!({"proposition_id":id(),"revision_id":id(),"parent_revision_id":null,"content":serde_json::json!({"media_type":"text/markdown; charset=utf-8; variant=fact-v0","hash":fact_core::Hash::digest(b"# Fact\n").hex(),"bytes":test_b64(b"# Fact\n")}),"relationships":[],"reconciliation_manifest":invalid_manifest});
        assert!(validate_envelope(&envelope("revision", invalid_revision)).is_err());
    }

    fn test_b64(bytes: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = ((chunk[0] as u32) << 16)
                | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
                | chunk.get(2).copied().unwrap_or(0) as u32;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(TABLE[((n >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(TABLE[(n & 63) as usize] as char);
            }
        }
        out
    }

    fn new_id() -> String {
        id()
    }

    fn valid_body_for(object_type: &str) -> Value {
        let id = id();
        let other = new_id();
        let actor = new_id();
        let key = new_id();
        let validity = serde_json::json!({
            "valid_from": "2026-07-27T12:00:00.000Z",
            "expires_at": null
        });
        let content_bytes = b"# Fact\n";
        let content = serde_json::json!({
            "media_type": "text/markdown; charset=utf-8; variant=fact-v0",
            "hash": fact_core::Hash::digest(content_bytes).hex(),
            "bytes": test_b64(content_bytes)
        });
        match object_type {
            "genesis" => serde_json::json!({
                "ledger_id": id,
                "protocol_version": "0",
                "parameters": {"consensus_rule":"unanimity-v0","namespace_profile":"facts-namespace-v0","content_profile":"facts-protocol-markdown-v0"},
                "namespace": "example.test",
                "bootstrap_actor": actor,
                "bootstrap_key": key,
                "bootstrap_binding": other,
                "root_grant": new_id(),
                "nonce": test_b64(&[1u8;16]),
                "initial_namespace_assertion": new_id()
            }),
            "namespace_assertion" => {
                serde_json::json!({"namespace":"example.test","target_type":"ledger","target_id":id,"naming_authority_actor_id":actor,"validity":validity,"supersedes":null})
            }
            "actor" => {
                serde_json::json!({"actor_type":"agent","bootstrap_key_id":key,"bootstrap_binding_id":other})
            }
            "key" => {
                let bytes = [1u8; 32];
                serde_json::json!({"public_key":{"algorithm":"Ed25519","bytes":test_b64(&bytes),"fingerprint":fact_core::Hash::digest(&bytes).hex()},"purpose":"signing"})
            }
            "actor_key_binding" => {
                serde_json::json!({"actor_id":actor,"key_id":key,"permitted_purpose":"signing","predecessor_binding_id":null})
            }
            "key_lifecycle" => {
                serde_json::json!({"operation":"rotate","affected_actor_id":actor,"old_key_id":key,"new_key_id":other,"predecessor_lifecycle_id":null,"effective_at":"2026-07-27T12:00:00.000Z","authorization_ref":null})
            }
            "recovery_policy" => {
                serde_json::json!({"actor_id":actor,"recovery_key_id":key,"policy_version":0,"effective_at":"2026-07-27T12:00:00.000Z","predecessor_policy_id":null})
            }
            "actor_lifecycle" => {
                serde_json::json!({"affected_actor_id":actor,"operation":"retire","effective_at":"2026-07-27T12:00:00.000Z","authorization_ref":id})
            }
            "identity_attestation" => {
                serde_json::json!({"subject_type":"actor","subject_id":actor,"claim_type":"display-name","claims":{"name":"Example"},"evidence_hash":null,"validity":validity})
            }
            "authorization_grant" => {
                serde_json::json!({"grant_id":id,"granting_actor_id":actor,"receiving_actor_id":other,"capabilities":["comment"],"scope":{"type":"ledger"},"validity":null,"constraints":{},"predecessor_grant_id":null})
            }
            "authorization_revocation" => {
                serde_json::json!({"revoked_grant_id":id,"effective_at":"2026-07-27T12:00:00.000Z","reason":"because","authorization_ref":other})
            }
            "delegation" => {
                serde_json::json!({"delegator_actor_id":actor,"delegatee_actor_id":other,"capability":"comment","scope":{"type":"ledger"},"validity":null,"parent_delegation_id":null,"redelegable":false,"constraints":{}})
            }
            "delegation_revocation" => {
                serde_json::json!({"revoked_delegation_id":id,"effective_at":"2026-07-27T12:00:00.000Z","reason":"because","authorization_ref":other})
            }
            "proposition" => {
                serde_json::json!({"proposition_id":id,"purpose":"knowledge","initial_revision_id":other,"initial_deliberation_id":key})
            }
            "revision" => {
                serde_json::json!({"proposition_id":id,"revision_id":other,"parent_revision_id":null,"content":content,"relationships":[],"reconciliation_manifest":null})
            }
            "deliberation" => {
                serde_json::json!({"deliberation_id":id,"proposition_id":other,"revision_id":key,"extends_deliberation_id":null,"decision_rule":{"id":"unanimity","version":0,"parameters":{}},"join_policy":{"policy_version":0,"mode":"open","attestation_requirements":[]},"initial_participants":[{"actor_id":actor,"carried_decision_id":null}],"roster_governance":null,"opening_actor_id":actor,"comments_closed_on_settlement":true})
            }
            "standing_participant_change" => {
                serde_json::json!({"proposition_id":id,"participant_actor_id":actor,"operation":"join","predecessor_change_id":null,"changed_by_actor_id":actor,"authorization_ref":null})
            }
            "deliberation_participant_change" => {
                serde_json::json!({"deliberation_id":id,"participant_actor_id":actor,"operation":"join","invitation_id":null,"admission_evidence":[],"carried_decision_id":null,"predecessor_change_id":null,"changed_by_actor_id":actor,"authorization_ref":null})
            }
            "participant_invitation" => {
                serde_json::json!({"invitation_id":id,"proposition_id":other,"inviting_actor_id":actor,"invited_actor_id":key,"participation_type":"standing","constraints":{},"validity":null,"predecessor_invitation_id":null})
            }
            "invitation_lifecycle" => {
                serde_json::json!({"invitation_id":id,"operation":"decline","predecessor_lifecycle_ids":[],"reason":"because","authorization_ref":other})
            }
            "decision" => {
                serde_json::json!({"deliberation_id":id,"participant_actor_id":actor,"value":"accepted","supersedes_decision_ids":[],"authorization_ref":null})
            }
            "deliberation_comment" => {
                serde_json::json!({"deliberation_id":id,"content":content,"parent_comment_id":null,"comment_phase":"pre-settlement"})
            }
            "settlement" => {
                serde_json::json!({"deliberation_id":id,"revision_id":other,"decision_rule":{"id":"unanimity","version":0,"parameters":{}},"decision_refs":[{"decision_id":key,"participant_actor_id":actor,"content_hash":"00".repeat(32)}],"participant_count":1,"decided_count":1,"accepted_count":1,"rejected_count":0,"outcome":"accepted","causal_settlement_point":{"object_id":id},"producer_type":"participant","producer_id":actor})
            }
            "proposition_lifecycle" => {
                serde_json::json!({"proposition_id":id,"dimension":"withdrawal","operation":"withdraw","predecessor_ids":[other],"authorization_ref":key,"reason":"because"})
            }
            "protocol_relationship" => {
                serde_json::json!({"source_object_id":id,"relationship":"protocol:references","target_object_ids":[other],"relationship_version":0})
            }
            "application_relationship" => {
                serde_json::json!({"source_object_id":id,"relationship":"related-to","target_object_ids":[],"metadata":{},"shared":false})
            }
            "proposition_provenance" => {
                serde_json::json!({"proposition_id":id,"source_ledger_id":other,"source_proposition_id":actor,"source_revision_id":key,"source_content_hash":"00".repeat(32),"source_object_bundle":"AA","copy_mode":"snapshot"})
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn every_registered_object_type_has_a_valid_positive_body_fixture() {
        for name in OBJECT_TYPES {
            let object_type = name.parse::<ObjectType>().unwrap();
            let body = valid_body_for(name);
            validate_body(object_type, body.as_object().unwrap())
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
    }

    #[test]
    fn generated_positive_fixtures_are_byte_stable() {
        for name in OBJECT_TYPES {
            assert_eq!(
                generated_positive_fixture(name).unwrap(),
                generated_positive_fixture(name).unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn every_registered_object_type_rejects_unknown_body_fields() {
        for name in OBJECT_TYPES {
            let object_type = name.parse::<ObjectType>().unwrap();
            let mut body = valid_body_for(name);
            body.as_object_mut()
                .unwrap()
                .insert("unexpected_field".into(), Value::Bool(true));
            assert!(
                matches!(
                    validate_body(object_type, body.as_object().unwrap()),
                    Err(Error::UnknownBodyField(_))
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn attested_join_policy_requires_exact_nonempty_requirements() {
        let mut body = valid_body_for("deliberation");
        let issuer = id();
        body["join_policy"] = serde_json::json!({
            "policy_version": 0,
            "mode": "attested",
            "attestation_requirements": [{
                "claim_type": "employment",
                "permitted_issuers": [issuer],
                "minimum_count": 1
            }]
        });
        validate_body("deliberation".parse().unwrap(), body.as_object().unwrap()).unwrap();
        body["join_policy"]["attestation_requirements"][0]["minimum_count"] = serde_json::json!(0);
        assert!(validate_body("deliberation".parse().unwrap(), body.as_object().unwrap()).is_err());
    }

    #[test]
    fn rejects_invalid_typed_consensus_shapes() {
        let mut body = serde_json::json!({
            "deliberation_id": id(),
            "revision_id": id(),
            "decision_rule": {"id":"unanimity","version":0,"parameters":{}},
            "decision_refs": [{"decision_id":id(),"participant_actor_id":id(),"content_hash":"00".repeat(32)}],
            "participant_count": 2,
            "decided_count": 1,
            "accepted_count": 1,
            "rejected_count": 0,
            "outcome": "accepted",
            "causal_settlement_point": {"object_id":id()},
            "producer_type": "participant",
            "producer_id": id(),
        });
        assert!(matches!(
            validate_envelope(&envelope("settlement", body.take()),),
            Err(Error::InvalidBody("settlement.counts"))
        ));
    }

    #[test]
    fn rejects_unknown_and_wrong_cardinality_protocol_relationships() {
        let target_a = id();
        let mut revision = valid_body_for("revision");
        revision["relationships"] = serde_json::json!([
            {"relationship":"protocol:unknown","targets":[target_a]}
        ]);
        assert!(matches!(
            validate_body("revision".parse().unwrap(), revision.as_object().unwrap()),
            Err(Error::InvalidBody("relationships.relationship"))
        ));
        let mut relationship = valid_body_for("protocol_relationship");
        relationship["relationship"] = serde_json::json!("protocol:parent-revision");
        relationship["target_object_ids"] = serde_json::json!([target_a, id()]);
        assert!(matches!(
            validate_body(
                "protocol_relationship".parse().unwrap(),
                relationship.as_object().unwrap()
            ),
            Err(Error::InvalidBody("relationship.cardinality"))
        ));
    }

    #[test]
    fn body_identity_must_match_envelope_identity() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&generated_positive_fixture("revision").unwrap()).unwrap();
        value["body"]["revision_id"] = serde_json::json!(id());
        let bytes = fact_canonical::encode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            validate_envelope(&bytes),
            Err(Error::InvalidBody("body.envelope_id"))
        ));
    }
}
