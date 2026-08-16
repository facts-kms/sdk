//! Identity and authorization workflows.

use crate::{
    environment::LedgerEntry,
    models::OperationReceipt,
    proposition::{base64url, dependency_hash, dependency_value, parse_uuid7, signed_envelope},
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

const IDENTITY_OBJECT_TYPES: &[&str] = &[
    "actor",
    "key",
    "actor_key_binding",
    "key_lifecycle",
    "recovery_policy",
    "actor_lifecycle",
];

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ImportIdentityResult {
    pub imported: usize,
    pub recognized: bool,
    pub authority_granted: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ExportIdentityResult {
    pub exported: bool,
    pub objects: usize,
    pub private_key_material: bool,
    #[serde(skip_serializing)]
    pub bundle: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CreateIdentityInput {
    pub namespace: String,
    pub seed: [u8; 32],
    pub actor_type: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CreateIdentityResult {
    pub created: bool,
    pub ledger_id: uuid::Uuid,
    pub actor_id: uuid::Uuid,
    pub key_id: uuid::Uuid,
    pub binding_id: uuid::Uuid,
    pub receipts: Vec<OperationReceipt>,
    pub private_key_material: String,
    #[serde(skip_serializing)]
    pub cose_objects: Vec<Vec<u8>>,
    #[serde(skip_serializing)]
    pub bundle: Vec<u8>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct IdentityGrantResult {
    pub created: bool,
    pub recognized: bool,
    pub authority_granted: bool,
    pub actor_id: uuid::Uuid,
    pub grant_id: uuid::Uuid,
    pub capabilities: Vec<String>,
    pub content_hash: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct IdentityRevocationResult {
    pub created: bool,
    pub object_type: String,
    pub revocation_id: uuid::Uuid,
    pub revoked_grant_id: uuid::Uuid,
    pub content_hash: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct IdentityRotationResult {
    pub created: bool,
    pub object_type: String,
    pub operation: String,
    pub actor_id: uuid::Uuid,
    pub old_key_id: uuid::Uuid,
    pub key_id: uuid::Uuid,
    pub binding_id: uuid::Uuid,
    pub lifecycle_id: uuid::Uuid,
    pub private_key_material: String,
    #[serde(skip_serializing)]
    pub new_seed: [u8; 32],
}

pub fn import_identity(entry: &LedgerEntry, bundle_bytes: &[u8]) -> Result<ImportIdentityResult> {
    let bundle = fact_commitment::decode_bundle(bundle_bytes)
        .map_err(|error| Error::Sync(error.to_string()))?;
    let mut identity_objects = Vec::new();
    for object in bundle.objects {
        let value = fact_crypto::decode_sign1(&object)?.payload;
        let value: serde_json::Value = serde_json::from_slice(&value)?;
        match value["object_type"].as_str() {
            Some(kind) if IDENTITY_OBJECT_TYPES.contains(&kind) => identity_objects.push(object),
            Some(other) => {
                return Err(Error::Validation(format!(
                    "identity bundle contains ledger object {other}"
                )));
            }
            None => {
                return Err(Error::Validation(
                    "identity bundle object has no type".into(),
                ))
            }
        }
    }
    let store = fact_store::Store::open(&entry.database)?;
    let mut new_identity_objects = Vec::new();
    for object in identity_objects {
        let value: serde_json::Value =
            serde_json::from_slice(&fact_crypto::decode_sign1(&object)?.payload)?;
        let id = value["id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .ok_or_else(|| Error::Validation("identity bundle object has invalid id".into()))?;
        if store.get_cose_by_id_any(id.as_bytes())?.is_none() {
            new_identity_objects.push(object);
        }
    }
    let imported = if new_identity_objects.is_empty() {
        0
    } else {
        store.insert_verified_bundle(&new_identity_objects)?.len()
    };
    Ok(ImportIdentityResult {
        imported,
        recognized: false,
        authority_granted: false,
    })
}

pub fn export_identity(entry: &LedgerEntry) -> Result<ExportIdentityResult> {
    let store = fact_store::Store::open(&entry.database)?;
    let objects = store
        .list_identity_objects()?
        .into_iter()
        .filter(|(_, _, object_type)| IDENTITY_OBJECT_TYPES.contains(&object_type.as_str()))
        .filter_map(|(id, hash, _)| {
            store
                .get_cose_by_id_any(id.as_bytes())
                .ok()
                .flatten()
                .map(|bytes| (hash, bytes))
        })
        .collect::<Vec<_>>();
    let bundle = encode_identity_bundle(&objects)?;
    Ok(ExportIdentityResult {
        exported: true,
        objects: objects.len(),
        private_key_material: false,
        bundle,
    })
}

pub fn create_identity(
    store: &fact_store::Store,
    input: CreateIdentityInput,
) -> Result<CreateIdentityResult> {
    let runtime = production_runtime();
    create_identity_with_runtime(store, input, runtime.as_ref())
}

pub fn create_identity_with_runtime(
    store: &fact_store::Store,
    input: CreateIdentityInput,
    runtime: &dyn SdkRuntime,
) -> Result<CreateIdentityResult> {
    let ledger_id = runtime.next_uuid_v7()?;
    let actor_id = runtime.next_uuid_v7()?;
    let key_id = runtime.next_uuid_v7()?;
    let binding_id = runtime.next_uuid_v7()?;
    let key = fact_crypto::SigningKey::from_seed(&input.seed)?;
    store.create_ledger(ledger_id.as_bytes(), &input.namespace)?;
    let actor = signed_identity_envelope(
        actor_id,
        "actor",
        actor_id,
        key_id,
        serde_json::json!({
            "actor_type":input.actor_type,
            "bootstrap_key_id":key_id,
            "bootstrap_binding_id":binding_id
        }),
        Vec::new(),
        &key,
        runtime,
    )?;
    let key_object = signed_identity_envelope(
        key_id,
        "key",
        actor_id,
        key_id,
        serde_json::json!({
            "public_key":{
                "algorithm":"Ed25519",
                "bytes":base64url(&key.public_key()),
                "fingerprint":key.fingerprint().hex()
            },
            "purpose":"signing"
        }),
        Vec::new(),
        &key,
        runtime,
    )?;
    let binding = signed_identity_envelope(
        binding_id,
        "actor_key_binding",
        actor_id,
        key_id,
        serde_json::json!({
            "actor_id":actor_id,
            "key_id":key_id,
            "permitted_purpose":"signing",
            "predecessor_binding_id":null
        }),
        Vec::new(),
        &key,
        runtime,
    )?;
    let cose_objects = vec![actor, key_object, binding];
    let hashes = store.insert_verified_bundle(&cose_objects)?;
    let receipts = cose_objects
        .iter()
        .zip(hashes.iter())
        .map(|(bytes, hash)| {
            let cose = fact_crypto::decode_sign1(bytes)?;
            let value: serde_json::Value = serde_json::from_slice(&cose.payload)?;
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
    let bundle_objects = hashes
        .iter()
        .copied()
        .zip(cose_objects.iter().cloned())
        .collect::<Vec<_>>();
    let bundle = encode_identity_bundle(&bundle_objects)?;
    Ok(CreateIdentityResult {
        created: true,
        ledger_id,
        actor_id,
        key_id,
        binding_id,
        receipts,
        private_key_material: "stored locally".into(),
        cose_objects,
        bundle,
    })
}

pub fn create_identity_grant(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    actor_text: &str,
    capabilities: &[String],
) -> Result<IdentityGrantResult> {
    let runtime = production_runtime();
    create_identity_grant_with_runtime(entry, seed, actor_text, capabilities, runtime.as_ref())
}

pub fn create_identity_grant_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    actor_text: &str,
    capabilities: &[String],
    runtime: &dyn SdkRuntime,
) -> Result<IdentityGrantResult> {
    ensure_writable(entry)?;
    if capabilities.is_empty() || capabilities.iter().any(|capability| capability.is_empty()) {
        return Err(Error::Validation(
            "at least one nonempty capability is required".into(),
        ));
    }
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let receiving_actor = match parse_uuid7(actor_text, "recognized actor") {
        Ok(actor_id) => actor_id,
        Err(_) => crate::directory::resolve_directory_reference(entry, actor_text)?.actor_id,
    };
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let identity = store
        .get_cose_by_id_any(receiving_actor.as_bytes())?
        .ok_or_else(|| Error::MissingObject("recognized actor identity is not imported".into()))?;
    let identity_value: serde_json::Value =
        serde_json::from_slice(&fact_crypto::decode_sign1(&identity)?.payload)?;
    if identity_value["object_type"] != "actor" {
        return Err(Error::Validation(
            "recognized identity reference is not an actor object".into(),
        ));
    }
    let (_, root_grant) = root_grant(&store, ledger)?;
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
            "receiving_actor_id":receiving_actor,
            "capabilities":capabilities,
            "scope":{"type":"ledger"},
            "validity":null,
            "constraints":{},
            "predecessor_grant_id":null
        }),
        vec![dependency_value(&root_grant, "admin-authority")?],
        &key,
        runtime,
    )?;
    let hash = dependency_hash(&grant)?;
    store.insert_authorized_object_with_projected_mode(
        &grant,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(IdentityGrantResult {
        created: true,
        recognized: true,
        authority_granted: true,
        actor_id: receiving_actor,
        grant_id,
        capabilities: capabilities.to_vec(),
        content_hash: hash.hex(),
    })
}

pub fn revoke_identity_grant(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    reason: &str,
) -> Result<IdentityRevocationResult> {
    let runtime = production_runtime();
    revoke_identity_grant_with_runtime(entry, seed, reference, reason, runtime.as_ref())
}

pub fn revoke_identity_grant_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    reason: &str,
    runtime: &dyn SdkRuntime,
) -> Result<IdentityRevocationResult> {
    ensure_writable(entry)?;
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let revoked_grant_id = resolve_authorization_grant(&store, ledger, reference)?;
    let revoked_grant = store
        .get_cose_by_id(ledger.as_bytes(), revoked_grant_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("authorization grant object is unavailable".into()))?;
    let (root_grant_id, root_grant) = root_grant(&store, ledger)?;
    let revocation_id = runtime.next_uuid_v7()?;
    let revocation = signed_envelope(
        revocation_id,
        ledger,
        "authorization_revocation",
        actor,
        key_id,
        serde_json::json!({
            "revoked_grant_id":revoked_grant_id,
            "effective_at":runtime.timestamp(),
            "reason":reason,
            "authorization_ref":root_grant_id
        }),
        vec![
            dependency_value(&revoked_grant, "revoked-grant")?,
            dependency_value(&root_grant, "admin-authority")?,
        ],
        &key,
        runtime,
    )?;
    let hash = dependency_hash(&revocation)?;
    store.insert_authorized_object_with_projected_mode(
        &revocation,
        fact_store::ProjectedMode::Incremental,
    )?;
    Ok(IdentityRevocationResult {
        created: true,
        object_type: "authorization_revocation".into(),
        revocation_id,
        revoked_grant_id,
        content_hash: hash.hex(),
    })
}

pub fn rotate_identity_key(entry: &LedgerEntry, seed: &[u8; 32]) -> Result<IdentityRotationResult> {
    let runtime = production_runtime();
    rotate_identity_key_with_runtime(entry, seed, runtime.as_ref())
}

pub fn rotate_identity_key_with_runtime(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    runtime: &dyn SdkRuntime,
) -> Result<IdentityRotationResult> {
    ensure_writable(entry)?;
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let actor = parse_uuid7(&entry.actor_id, "actor")?;
    let old_key_id = parse_uuid7(&entry.key_id, "key_id")?;
    let old_key = fact_crypto::SigningKey::from_seed(seed)?;
    let store = fact_store::Store::open(&entry.database)?;
    let old_binding_id = current_actor_binding(&store, actor, old_key_id)?;
    let old_binding = store
        .get_cose_by_id_any(old_binding_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("current actor binding is unavailable".into()))?;

    let new_seed = runtime.seed()?;
    let new_key = fact_crypto::SigningKey::from_seed(&new_seed)?;
    let new_key_id = runtime.next_uuid_v7()?;
    let new_binding_id = runtime.next_uuid_v7()?;
    let lifecycle_id = runtime.next_uuid_v7()?;
    let key_object = signed_identity_envelope(
        new_key_id,
        "key",
        actor,
        old_key_id,
        serde_json::json!({
            "public_key": {
                "algorithm":"Ed25519",
                "bytes":base64url(&new_key.public_key()),
                "fingerprint":new_key.fingerprint().hex()
            },
            "purpose":"signing"
        }),
        Vec::new(),
        &old_key,
        runtime,
    )?;
    let binding = signed_identity_envelope(
        new_binding_id,
        "actor_key_binding",
        actor,
        old_key_id,
        serde_json::json!({
            "actor_id":actor,
            "key_id":new_key_id,
            "permitted_purpose":"signing",
            "predecessor_binding_id":old_binding_id
        }),
        vec![dependency_value(&old_binding, "predecessor-binding")?],
        &old_key,
        runtime,
    )?;
    let lifecycle = signed_envelope(
        lifecycle_id,
        ledger,
        "key_lifecycle",
        actor,
        old_key_id,
        serde_json::json!({
            "operation":"rotate",
            "affected_actor_id":actor,
            "old_key_id":old_key_id,
            "new_key_id":new_key_id,
            "predecessor_lifecycle_id":null,
            "effective_at":runtime.timestamp(),
            "authorization_ref":null
        }),
        vec![
            dependency_value(&old_binding, "old-binding")?,
            dependency_value(&key_object, "new-key")?,
            dependency_value(&binding, "new-binding")?,
        ],
        &old_key,
        runtime,
    )?;
    store.insert_verified_bundle_with_projected_mode(
        &[key_object, binding, lifecycle],
        fact_store::ProjectedMode::Incremental,
    )?;

    Ok(IdentityRotationResult {
        created: true,
        object_type: "key_lifecycle".into(),
        operation: "rotate".into(),
        actor_id: actor,
        old_key_id,
        key_id: new_key_id,
        binding_id: new_binding_id,
        lifecycle_id,
        private_key_material: "stored locally".into(),
        new_seed,
    })
}

fn current_actor_binding(
    store: &fact_store::Store,
    actor: uuid::Uuid,
    key_id: uuid::Uuid,
) -> Result<uuid::Uuid> {
    let actor_text = actor.to_string();
    let key_text = key_id.to_string();
    store
        .list_identity_objects()?
        .into_iter()
        .filter(|(_, _, object_type)| object_type == "actor_key_binding")
        .filter_map(|(id, _, _)| {
            let payload = store.get_payload(id.as_bytes()).ok().flatten()?;
            let value = serde_json::from_slice::<serde_json::Value>(&payload).ok()?;
            let body = value.get("body")?;
            (body.get("actor_id").and_then(serde_json::Value::as_str) == Some(actor_text.as_str())
                && body.get("key_id").and_then(serde_json::Value::as_str)
                    == Some(key_text.as_str())
                && body
                    .get("permitted_purpose")
                    .and_then(serde_json::Value::as_str)
                    == Some("signing"))
            .then_some(id)
        })
        .next()
        .ok_or_else(|| Error::MissingObject("current signing key has no actor binding".into()))
}

fn resolve_authorization_grant(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    reference: &str,
) -> Result<uuid::Uuid> {
    let grants = store
        .resolve_object_reference(ledger.as_bytes(), reference, &["authorization_grant"])?
        .into_iter()
        .collect::<Vec<_>>();
    match grants.as_slice() {
        [grant] => Ok(grant.object_id),
        [] => Err(Error::MissingObject(format!(
            "no authorization grant matches reference {reference}"
        ))),
        _ => Err(Error::AmbiguousReference(reference.to_owned())),
    }
}

pub(crate) fn root_grant(
    store: &fact_store::Store,
    ledger: uuid::Uuid,
) -> Result<(uuid::Uuid, Vec<u8>)> {
    let root_grant_id = store
        .genesis_root_grant_id(ledger.as_bytes())?
        .ok_or_else(|| Error::MissingObject("ledger genesis has no root grant".into()))?;
    let root_grant = store
        .get_cose_by_id(ledger.as_bytes(), root_grant_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject("root grant object is unavailable".into()))?;
    Ok((root_grant_id, root_grant))
}

fn encode_identity_bundle(objects: &[(fact_core::Hash, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut objects = objects.to_vec();
    objects.sort_by_key(|(hash, _)| *hash);
    let manifest = fact_canonical::encode(&serde_json::to_vec(&serde_json::json!({
        "schema":"facts-protocol-bundle-v0",
        "protocol_version":0,
        "bundle_id":fact_commitment::deterministic_bundle_id(&objects),
        "object_count":objects.len(),
        "ledger_id":null,
        "objects":objects.iter().map(|(hash, bytes)| {
            let id = fact_crypto::decode_sign1(bytes).ok()
                .and_then(|cose| serde_json::from_slice::<serde_json::Value>(&cose.payload).ok())
                .and_then(|value| value.get("id").and_then(serde_json::Value::as_str).map(str::to_owned));
            serde_json::json!({"object_id":id,"content_hash":hash.hex()})
        }).collect::<Vec<_>>(),
        "dependency_refs":[],
        "sender_signature":null,
        "expected_commitment_hash":null,
        "base_commitment_hash":null
    }))?)?;
    fact_commitment::encode_bundle(&manifest, &objects)
        .map_err(|error| Error::Sync(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn signed_identity_envelope(
    id: uuid::Uuid,
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
        "object_type":object_type,
        "schema_version":"0",
        "actor_id":actor.to_string(),
        "signing_key_id":key_id.to_string(),
        "created_at":runtime.timestamp(),
        "dependencies":dependencies,
        "body":body
    });
    let payload = fact_canonical::encode(&serde_json::to_vec(&value)?)?;
    let protected = fact_crypto::protocol_protected(key.public_key(), object_type, "0", None);
    Ok(fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected, &payload, key,
    )))
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
    use crate::workflow::{create_ledger, BootstrapLedgerInput};

    #[test]
    fn create_identity_builds_importable_actor_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let identity_store = fact_store::Store::open(temp.path().join("identity.sqlite")).unwrap();
        let identity = create_identity(
            &identity_store,
            CreateIdentityInput {
                namespace: "local.identity.test".into(),
                seed: [11; 32],
                actor_type: "human".into(),
            },
        )
        .unwrap();
        assert!(identity.created);
        assert_eq!(identity.receipts.len(), 3);
        assert_eq!(identity.cose_objects.len(), 3);
        assert!(!identity.bundle.is_empty());
        assert_eq!(identity_store.list_identity_objects().unwrap().len(), 3);

        let main = entry_with_seed(&temp, "main", [7; 32], [9; 16]);
        let imported = import_identity(&main, &identity.bundle).unwrap();
        assert_eq!(imported.imported, 3);
        let grant = create_identity_grant(
            &main,
            &[7; 32],
            &identity.actor_id.to_string(),
            &["propose".into()],
        )
        .unwrap();
        assert_eq!(grant.actor_id, identity.actor_id);
        assert_eq!(grant.capabilities, vec!["propose"]);
    }

    fn entry_with_seed(
        temp: &tempfile::TempDir,
        name: &str,
        seed: [u8; 32],
        nonce: [u8; 16],
    ) -> LedgerEntry {
        let database = temp.path().join(format!("{name}.sqlite"));
        let store = fact_store::Store::open(&database).unwrap();
        let bootstrap = create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: format!("local.{name}"),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce,
            },
        )
        .unwrap();
        LedgerEntry {
            name: name.into(),
            ledger_id: bootstrap.ledger_id,
            database,
            actor_id: bootstrap.actor_id,
            key_id: bootstrap.key_id,
            seed_file: temp.path().join(format!("{name}.seed")),
            read_only: false,
        }
    }

    #[test]
    fn identity_export_import_grant_and_revoke_work() {
        let temp = tempfile::tempdir().unwrap();
        let main = entry_with_seed(&temp, "main", [61; 32], [62; 16]);
        let target = entry_with_seed(&temp, "target", [63; 32], [64; 16]);

        let exported = export_identity(&target).unwrap();
        assert!(exported.exported);
        assert!(exported.objects >= 3);
        assert!(!exported.private_key_material);
        assert!(serde_json::to_value(&exported)
            .unwrap()
            .get("bundle")
            .is_none());

        let imported = import_identity(&main, &exported.bundle).unwrap();
        assert!(imported.imported >= 3);
        assert!(!imported.recognized);
        assert!(!imported.authority_granted);

        let main_seed = [61; 32];
        fact_store::Store::reset_debug_metrics();
        let grant = create_identity_grant(
            &main,
            &main_seed,
            &target.actor_id,
            &["comment".into(), "invite".into()],
        )
        .unwrap();
        assert_eq!(grant.actor_id.to_string(), target.actor_id);
        assert_eq!(grant.capabilities, ["comment", "invite"]);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.projected_rebuilds, 0);
        assert_eq!(metrics.list_object_payloads_by_type, 0);

        fact_store::Store::reset_debug_metrics();
        let revoked =
            revoke_identity_grant(&main, &main_seed, &grant.grant_id.to_string(), "test").unwrap();
        assert_eq!(revoked.object_type, "authorization_revocation");
        assert_eq!(revoked.revoked_grant_id, grant.grant_id);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.projected_rebuilds, 0);
        assert_eq!(metrics.list_object_payloads_by_type, 0);
    }

    #[test]
    fn identity_rotation_returns_private_seed_out_of_json_and_checks_read_only() {
        let temp = tempfile::tempdir().unwrap();
        let entry = entry_with_seed(&temp, "rotate", [65; 32], [66; 16]);
        let historical = crate::proposition::create_proposition(
            &entry,
            &[65; 32],
            b"# Before Rotation\n\nHistorical signature.\n",
            None,
        )
        .unwrap();
        fact_store::Store::reset_debug_metrics();
        let rotation = rotate_identity_key(&entry, &[65; 32]).unwrap();
        assert_eq!(rotation.object_type, "key_lifecycle");
        assert_eq!(rotation.operation, "rotate");
        assert_eq!(rotation.actor_id.to_string(), entry.actor_id);
        assert_ne!(rotation.old_key_id, rotation.key_id);
        assert_ne!(rotation.new_seed, [0; 32]);
        assert_eq!(fact_store::Store::debug_metrics().projected_rebuilds, 0);
        let value = serde_json::to_value(&rotation).unwrap();
        assert!(value.get("new_seed").is_none());

        assert!(matches!(
            crate::proposition::create_proposition(
                &entry,
                &[65; 32],
                b"# Rejected Old Key\n\nOld key should no longer authorize new actions.\n",
                None,
            ),
            Err(Error::Store(fact_store::Error::Unauthorized))
        ));

        let rotated_entry = LedgerEntry {
            key_id: rotation.key_id.to_string(),
            ..entry.clone()
        };
        let after_rotation = crate::proposition::create_proposition(
            &rotated_entry,
            &rotation.new_seed,
            b"# After Rotation\n\nNew key preserves actor authority.\n",
            None,
        )
        .unwrap();
        assert_eq!(after_rotation.status, "pending");

        let store = fact_store::Store::open(&entry.database).unwrap();
        let historical_bytes = store
            .get_cose_by_id_any(historical.proposition_id.as_bytes())
            .unwrap()
            .unwrap();
        fact_crypto::decode_sign1(&historical_bytes).unwrap();

        let read_only = LedgerEntry {
            read_only: true,
            ..entry.clone()
        };
        assert!(matches!(
            rotate_identity_key(&read_only, &[65; 32]),
            Err(Error::ReadOnlyLedger)
        ));
        assert!(matches!(
            create_identity_grant(&read_only, &[65; 32], &entry.actor_id, &["comment".into()]),
            Err(Error::ReadOnlyLedger)
        ));
        assert!(matches!(
            revoke_identity_grant(
                &read_only,
                &[65; 32],
                &rotation.lifecycle_id.to_string(),
                "no"
            ),
            Err(Error::ReadOnlyLedger)
        ));
    }
}
