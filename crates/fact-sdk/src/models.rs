//! Shared SDK models.

pub type ObjectId = fact_core::ObjectId;
pub type LedgerId = fact_core::ObjectId;
pub type ContentHash = fact_core::Hash;
pub type Timestamp = String;
pub type Base64UrlBytes = String;
pub type MarkdownBytes = Vec<u8>;
pub type JsonObject = serde_json::Map<String, serde_json::Value>;
pub type Reference = String;
pub type Capability = String;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DependencyRef {
    pub object_id: String,
    pub content_hash: String,
    pub role: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Content {
    pub media_type: String,
    pub bytes: Base64UrlBytes,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ValidityWindow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<Timestamp>,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ProtocolEnvelope<TBody> {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_id: Option<String>,
    pub object_type: String,
    pub schema_version: String,
    pub actor_id: String,
    pub signing_key_id: String,
    pub created_at: Timestamp,
    pub dependencies: Vec<DependencyRef>,
    pub body: TBody,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct OperationReceipt {
    pub object_id: String,
    pub content_hash: String,
    pub object_type: String,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SignedObject {
    pub object_id: String,
    pub content_hash: String,
    pub object_type: String,
    pub canonical_payload: Vec<u8>,
    pub cose: Vec<u8>,
}

macro_rules! body_models {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
            pub struct $name {
                #[serde(flatten)]
                pub fields: serde_json::Map<String, serde_json::Value>,
            }
        )+
    };
}

body_models!(
    GenesisBody,
    NamespaceAssertionBody,
    ActorBody,
    KeyBody,
    ActorKeyBindingBody,
    KeyLifecycleBody,
    RecoveryPolicyBody,
    ActorLifecycleBody,
    IdentityAttestationBody,
    AuthorizationGrantBody,
    AuthorizationRevocationBody,
    DelegationBody,
    DelegationRevocationBody,
    PropositionBody,
    RevisionBody,
    DeliberationBody,
    StandingParticipantChangeBody,
    DeliberationParticipantChangeBody,
    ParticipantInvitationBody,
    InvitationLifecycleBody,
    DecisionBody,
    DeliberationCommentBody,
    SettlementBody,
    PropositionLifecycleBody,
    ProtocolRelationshipBody,
    ApplicationRelationshipBody,
    PropositionProvenanceBody,
);

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ObjectSummary {
    pub object_id: String,
    pub content_hash: String,
    pub object_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SearchHit {
    pub content_hash: String,
    pub score: String,
    pub extraction_profile: String,
}
