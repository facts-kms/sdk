//! Participant invitation workflows.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    directory::resolve_directory_actor_reference,
    environment::LedgerEntry,
    models::{ParticipantInvitationBody, ProtocolEnvelope},
    proposition::{
        dependency_hash, dependency_value, parse_uuid7, resolve_any_proposition_item,
        signed_envelope,
    },
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct InvitationResult {
    pub created: bool,
    pub object_type: String,
    pub invitation_id: uuid::Uuid,
    pub invited_actor_id: uuid::Uuid,
    pub content_hash: String,
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct ListInvitationsFilter {
    pub proposition_id: Option<uuid::Uuid>,
    pub deliberation_id: Option<uuid::Uuid>,
    pub invited_actor_id: Option<uuid::Uuid>,
    pub lifecycle_status: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct InvitationLifecycleResult {
    pub created: bool,
    pub object_type: String,
    pub lifecycle_id: uuid::Uuid,
    pub invitation_id: uuid::Uuid,
    pub operation: String,
    pub content_hash: String,
}

pub fn create_invitation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    invited_actor: &str,
) -> Result<InvitationResult> {
    let runtime = production_runtime();
    create_invitation_with_runtime(entry, seed, reference, invited_actor, runtime.as_ref())
}

pub fn create_invitation_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    invited_actor: &str,
    runtime: &dyn SdkRuntime,
) -> Result<InvitationResult> {
    ensure_writable(entry)?;
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let invited_actor = resolve_directory_actor_reference(entry, invited_actor)?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let item = resolve_any_proposition_item(&store, ledger, reference)?;
    let deliberation_id = item
        .deliberation_id
        .ok_or_else(|| Error::MissingObject("proposition has no deliberation".into()))?;
    let deliberation = store
        .get_cose_by_id(ledger.as_bytes(), deliberation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("deliberation object is unavailable".into()))?;
    let invitation_id = runtime.next_uuid_v7()?;
    let invitation = signed_envelope(
        invitation_id,
        ledger,
        "participant_invitation",
        actor,
        key_id,
        serde_json::json!({
            "invitation_id":invitation_id,
            "proposition_id":item.proposition_id,
            "inviting_actor_id":actor,
            "invited_actor_id":invited_actor,
            "participation_type":"standing",
            "constraints":{},
            "validity":null,
            "predecessor_invitation_id":null
        }),
        vec![dependency_value(&deliberation, "deliberation")?],
        &key,
        runtime,
    )?;
    let hash = dependency_hash(&invitation)?;
    store.insert_authorized_object_with_projected_mode(
        &invitation,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(InvitationResult {
        created: true,
        object_type: "participant_invitation".into(),
        invitation_id,
        invited_actor_id: invited_actor,
        content_hash: hash.hex(),
    })
}

pub fn read_invitation(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<ProtocolEnvelope<ParticipantInvitationBody>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let invitation_id = resolve_invitation(&store, ledger, reference)?;
    let payload = store
        .get_payload(invitation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("participant invitation payload missing".into()))?;
    serde_json::from_slice(&payload).map_err(Into::into)
}

pub fn list_invitations(
    entry: &LedgerEntry,
    filter: ListInvitationsFilter,
) -> Result<Vec<ProtocolEnvelope<ParticipantInvitationBody>>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let rows = store.list_invitation_payloads(
        ledger.as_bytes(),
        filter.proposition_id.as_ref().map(uuid::Uuid::as_bytes),
        filter.deliberation_id.as_ref().map(uuid::Uuid::as_bytes),
        filter.invited_actor_id.as_ref().map(uuid::Uuid::as_bytes),
    )?;
    let lifecycle_status = if filter.lifecycle_status.is_some() {
        let invitation_ids = rows.iter().map(|row| row.object_id).collect::<Vec<_>>();
        invitation_lifecycle_statuses_for(&store, ledger, &invitation_ids)?
    } else {
        BTreeMap::new()
    };
    let mut invitations = Vec::new();
    for row in rows {
        let envelope: ProtocolEnvelope<ParticipantInvitationBody> =
            serde_json::from_slice(&row.payload)?;
        if let Some(expected) = filter.lifecycle_status.as_deref() {
            let status = lifecycle_status
                .get(&row.object_id)
                .map(String::as_str)
                .unwrap_or("active");
            if status != expected {
                continue;
            }
        }
        invitations.push(envelope);
    }
    invitations.sort_by(|left, right| left.created_at.cmp(&right.created_at));
    Ok(invitations)
}

pub fn update_invitation_lifecycle(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    invitation_reference: &str,
    operation: &str,
    reason: &str,
) -> Result<InvitationLifecycleResult> {
    let runtime = production_runtime();
    update_invitation_lifecycle_with_runtime(
        entry,
        seed,
        invitation_reference,
        operation,
        reason,
        runtime.as_ref(),
    )
}

pub fn update_invitation_lifecycle_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    invitation_reference: &str,
    operation: &str,
    reason: &str,
    runtime: &dyn SdkRuntime,
) -> Result<InvitationLifecycleResult> {
    ensure_writable(entry)?;
    if !matches!(operation, "decline" | "revoke" | "supersede") {
        return Err(Error::Validation(format!(
            "unsupported invitation lifecycle operation {operation}"
        )));
    }
    if reason.is_empty() {
        return Err(Error::Validation("reason is required".into()));
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let invitation_id = resolve_invitation(&store, ledger, invitation_reference)?;
    let invitation = store
        .get_cose_by_id(ledger.as_bytes(), invitation_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("participant invitation is unavailable".into()))?;
    let predecessors = invitation_lifecycle_tips(&store, ledger, invitation_id)?;
    let mut dependencies = vec![dependency_value(&invitation, "participant-invitation")?];
    for predecessor in &predecessors {
        let predecessor_object = store
            .get_cose_by_id(ledger.as_bytes(), predecessor.as_bytes())?
            .ok_or_else(|| {
                Error::MissingObject("invitation lifecycle predecessor missing".into())
            })?;
        dependencies.push(dependency_value(
            &predecessor_object,
            "invitation-lifecycle-predecessor",
        )?);
    }
    let lifecycle_id = runtime.next_uuid_v7()?;
    let lifecycle = signed_envelope(
        lifecycle_id,
        ledger,
        "invitation_lifecycle",
        actor,
        key_id,
        serde_json::json!({
            "invitation_id":invitation_id,
            "operation":operation,
            "predecessor_lifecycle_ids":predecessors,
            "reason":reason,
            "authorization_ref":invitation_id
        }),
        dependencies,
        &key,
        runtime,
    )?;
    let hash = dependency_hash(&lifecycle)?;
    store.insert_authorized_object_with_projected_mode(
        &lifecycle,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(InvitationLifecycleResult {
        created: true,
        object_type: "invitation_lifecycle".into(),
        lifecycle_id,
        invitation_id,
        operation: operation.into(),
        content_hash: hash.hex(),
    })
}

pub(crate) fn resolve_invitation(
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
        _ => Err(Error::AmbiguousReference(invitation_reference.to_owned())),
    }
}

fn invitation_lifecycle_tips(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    invitation_id: uuid::Uuid,
) -> Result<Vec<uuid::Uuid>> {
    Ok(store.invitation_lifecycle_tip_ids(ledger.as_bytes(), invitation_id.as_bytes())?)
}

fn invitation_lifecycle_statuses_for(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    invitation_ids: &[uuid::Uuid],
) -> Result<BTreeMap<uuid::Uuid, String>> {
    let rows = store.list_lifecycle_rows_for_targets(
        ledger.as_bytes(),
        "invitation_lifecycle",
        invitation_ids,
    )?;
    invitation_lifecycle_statuses_from_rows(rows)
}

fn invitation_lifecycle_statuses_from_rows(
    rows: Vec<fact_store::LifecycleRow>,
) -> Result<BTreeMap<uuid::Uuid, String>> {
    let mut statuses = BTreeMap::new();
    for (invitation_id, tips) in invitation_lifecycle_tips_by_invitation(rows)? {
        let status = match tips.as_slice() {
            [] => "active",
            [(_, operation)] => operation.as_str(),
            _ => "conflict",
        };
        statuses.insert(invitation_id, status.to_owned());
    }
    Ok(statuses)
}

fn invitation_lifecycle_tips_by_invitation(
    rows: Vec<fact_store::LifecycleRow>,
) -> Result<BTreeMap<uuid::Uuid, Vec<(uuid::Uuid, String)>>> {
    let mut entries = BTreeMap::<uuid::Uuid, Vec<(uuid::Uuid, String, Vec<uuid::Uuid>)>>::new();
    for row in rows {
        let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
        let Some(invitation_id) = row
            .target_id
            .or_else(|| body_uuid(&value["body"], "invitation_id"))
        else {
            continue;
        };
        let predecessors = value["body"]["predecessor_lifecycle_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str())
            .filter_map(|value| uuid::Uuid::parse_str(value).ok())
            .collect::<Vec<_>>();
        entries.entry(invitation_id).or_default().push((
            row.object_id,
            row.operation,
            predecessors,
        ));
    }
    Ok(entries
        .into_iter()
        .map(|(invitation_id, values)| {
            let referenced = values
                .iter()
                .flat_map(|(_, _, predecessors)| predecessors.iter().copied())
                .collect::<BTreeSet<_>>();
            let tips = values
                .into_iter()
                .filter(|(id, _, _)| !referenced.contains(id))
                .map(|(id, operation, _)| (id, operation))
                .collect::<Vec<_>>();
            (invitation_id, tips)
        })
        .collect())
}

fn body_uuid(value: &serde_json::Value, field: &str) -> Option<uuid::Uuid> {
    value
        .get(field)
        .and_then(|value| (!value.is_null()).then_some(value))
        .and_then(serde_json::Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
}

#[cfg(test)]
fn body_map_uuid(
    body: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Option<uuid::Uuid> {
    body.get(field)
        .and_then(|value| (!value.is_null()).then_some(value))
        .and_then(serde_json::Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
}

fn ensure_writable(entry: &LedgerEntry) -> Result<()> {
    if entry.read_only {
        Err(Error::ReadOnlyLedger)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        directory::{add_directory_entry, DirectoryAddInput},
        proposition::create_proposition,
        workflow::{create_ledger, BootstrapLedgerInput},
    };

    fn entry() -> (tempfile::TempDir, LedgerEntry, [u8; 32]) {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("test.sqlite");
        let seed = [41; 32];
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.invitation-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce: [42; 16],
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
    fn invitation_create_read_list_and_lifecycle_work() {
        let (_temp, entry, seed) = entry();
        let proposition =
            create_proposition(&entry, &seed, b"# Invite\n\nBring someone in.\n", None).unwrap();

        fact_store::Store::reset_debug_metrics();
        let invitation = create_invitation(
            &entry,
            &seed,
            &proposition.proposition_id.to_string(),
            &entry.actor_id,
        )
        .unwrap();
        assert_eq!(invitation.object_type, "participant_invitation");
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);

        let read = read_invitation(&entry, &invitation.invitation_id.to_string()).unwrap();
        assert_eq!(read.id, invitation.invitation_id.to_string());
        assert_eq!(
            body_map_uuid(&read.body.fields, "invited_actor_id").unwrap(),
            parse_uuid7(&entry.actor_id, "actor").unwrap()
        );

        fact_store::Store::reset_debug_metrics();
        let listed = list_invitations(
            &entry,
            ListInvitationsFilter {
                proposition_id: Some(proposition.proposition_id),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(fact_store::Store::debug_metrics().list_lifecycle_rows, 0);

        fact_store::Store::reset_debug_metrics();
        let declined = update_invitation_lifecycle(
            &entry,
            &seed,
            &invitation.invitation_id.to_string(),
            "decline",
            "not now",
        )
        .unwrap();
        assert_eq!(declined.operation, "decline");
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.projected_rebuilds, 0);
        assert_eq!(metrics.list_lifecycle_rows, 0);

        fact_store::Store::reset_debug_metrics();
        let declined_list = list_invitations(
            &entry,
            ListInvitationsFilter {
                lifecycle_status: Some("decline".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(declined_list.len(), 1);
        assert_eq!(fact_store::Store::debug_metrics().list_lifecycle_rows, 1);

        fact_store::Store::reset_debug_metrics();
        let unfiltered_list = list_invitations(&entry, ListInvitationsFilter::default()).unwrap();
        assert_eq!(unfiltered_list.len(), 1);
        assert_eq!(fact_store::Store::debug_metrics().list_lifecycle_rows, 0);

        fact_store::Store::reset_debug_metrics();
        let superseded = update_invitation_lifecycle(
            &entry,
            &seed,
            &invitation.invitation_id.to_string(),
            "supersede",
            "sent a replacement",
        )
        .unwrap();
        assert_eq!(superseded.operation, "supersede");
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.projected_rebuilds, 0);
        assert_eq!(metrics.list_lifecycle_rows, 0);

        let read_only = LedgerEntry {
            read_only: true,
            ..entry.clone()
        };
        assert!(matches!(
            create_invitation(
                &read_only,
                &seed,
                &proposition.proposition_id.to_string(),
                &entry.actor_id,
            ),
            Err(Error::ReadOnlyLedger)
        ));
        assert!(matches!(
            update_invitation_lifecycle(
                &read_only,
                &seed,
                &invitation.invitation_id.to_string(),
                "revoke",
                "closed",
            ),
            Err(Error::ReadOnlyLedger)
        ));
    }

    #[test]
    fn invitation_create_resolves_directory_alias_for_actor() {
        let (_temp, entry, seed) = entry();
        let proposition =
            create_proposition(&entry, &seed, b"# Invite\n\nAlias participant.\n", None).unwrap();
        let directory_entry = add_directory_entry(
            &entry,
            &seed,
            DirectoryAddInput {
                display_name: "Claude Agent".into(),
                actor_id: None,
                key_id: None,
                alias: Some("claude".into()),
                actor_type: Some("agent".into()),
                role: Some("review".into()),
                source: None,
                verified_by: None,
                with_identity: true,
                seed: Some([43; 32]),
            },
        )
        .unwrap();

        let invitation = create_invitation(
            &entry,
            &seed,
            &proposition.proposition_id.to_string(),
            "claude",
        )
        .unwrap();

        assert_eq!(invitation.invited_actor_id, directory_entry.actor_id);
        let read = read_invitation(&entry, &invitation.invitation_id.to_string()).unwrap();
        assert_eq!(
            body_map_uuid(&read.body.fields, "invited_actor_id").unwrap(),
            directory_entry.actor_id
        );
    }
}
