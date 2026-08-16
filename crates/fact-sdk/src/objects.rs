//! Low-level signed object helpers.

use crate::{
    models::{ObjectSummary, SignedObject},
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ActorObjectInput {
    pub actor_id: uuid::Uuid,
    pub signing_key_id: uuid::Uuid,
    pub bootstrap_key_id: uuid::Uuid,
    pub bootstrap_binding_id: uuid::Uuid,
    pub actor_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct KeyObjectInput {
    pub key_id: uuid::Uuid,
    pub actor_id: uuid::Uuid,
    pub signing_key_id: uuid::Uuid,
    pub public_key: Vec<u8>,
    pub purpose: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ActorKeyBindingObjectInput {
    pub binding_id: uuid::Uuid,
    pub actor_id: uuid::Uuid,
    pub signing_key_id: uuid::Uuid,
    pub key_id: uuid::Uuid,
    pub permitted_purpose: String,
    pub predecessor_binding_id: Option<uuid::Uuid>,
}

/// Build a signed actor object without importing it.
pub fn create_actor_object(
    input: ActorObjectInput,
    signing_key: &fact_crypto::SigningKey,
) -> Result<SignedObject> {
    let runtime = production_runtime();
    create_actor_object_with_runtime(input, signing_key, runtime.as_ref())
}

pub fn create_actor_object_with_runtime(
    input: ActorObjectInput,
    signing_key: &fact_crypto::SigningKey,
    runtime: &dyn SdkRuntime,
) -> Result<SignedObject> {
    sign_object(
        serde_json::json!({
            "id": input.actor_id,
            "object_type": "actor",
            "schema_version": "0",
            "actor_id": input.actor_id,
            "signing_key_id": input.signing_key_id,
            "created_at": runtime.timestamp(),
            "dependencies": [],
            "body": {
                "actor_type": input.actor_type,
                "bootstrap_key_id": input.bootstrap_key_id,
                "bootstrap_binding_id": input.bootstrap_binding_id
            }
        }),
        signing_key,
    )
}

/// Build a signed key object without importing it.
pub fn create_key_object(
    input: KeyObjectInput,
    signing_key: &fact_crypto::SigningKey,
) -> Result<SignedObject> {
    let runtime = production_runtime();
    create_key_object_with_runtime(input, signing_key, runtime.as_ref())
}

pub fn create_key_object_with_runtime(
    input: KeyObjectInput,
    signing_key: &fact_crypto::SigningKey,
    runtime: &dyn SdkRuntime,
) -> Result<SignedObject> {
    let algorithm = match input.public_key.len() {
        32 => "Ed25519",
        _ => {
            return Err(Error::Validation(
                "public key must be 32 bytes for Ed25519".into(),
            ));
        }
    };
    sign_object(
        serde_json::json!({
            "id": input.key_id,
            "object_type": "key",
            "schema_version": "0",
            "actor_id": input.actor_id,
            "signing_key_id": input.signing_key_id,
            "created_at": runtime.timestamp(),
            "dependencies": [],
            "body": {
                "public_key": {
                    "algorithm": algorithm,
                    "bytes": b64url(&input.public_key),
                    "fingerprint": fact_core::Hash::digest(&input.public_key).hex()
                },
                "purpose": input.purpose
            }
        }),
        signing_key,
    )
}

/// Build a signed actor-key binding object without importing it.
pub fn create_actor_key_binding_object(
    input: ActorKeyBindingObjectInput,
    signing_key: &fact_crypto::SigningKey,
) -> Result<SignedObject> {
    let runtime = production_runtime();
    create_actor_key_binding_object_with_runtime(input, signing_key, runtime.as_ref())
}

pub fn create_actor_key_binding_object_with_runtime(
    input: ActorKeyBindingObjectInput,
    signing_key: &fact_crypto::SigningKey,
    runtime: &dyn SdkRuntime,
) -> Result<SignedObject> {
    sign_object(
        serde_json::json!({
            "id": input.binding_id,
            "object_type": "actor_key_binding",
            "schema_version": "0",
            "actor_id": input.actor_id,
            "signing_key_id": input.signing_key_id,
            "created_at": runtime.timestamp(),
            "dependencies": [],
            "body": {
                "actor_id": input.actor_id,
                "key_id": input.key_id,
                "permitted_purpose": input.permitted_purpose,
                "predecessor_binding_id": input.predecessor_binding_id
            }
        }),
        signing_key,
    )
}

/// Build a canonical signed protocol object from a JSON envelope value.
pub fn sign_object(
    envelope: serde_json::Value,
    signing_key: &fact_crypto::SigningKey,
) -> Result<SignedObject> {
    let raw =
        serde_json::to_vec(&envelope).map_err(|error| Error::Validation(error.to_string()))?;
    let canonical_payload = fact_canonical::encode(&raw)?;
    let object_type = fact_schema::validate_envelope(&canonical_payload)?;
    let object = serde_json::from_slice::<serde_json::Value>(&canonical_payload)
        .map_err(|error| Error::Validation(error.to_string()))?;
    let object_id = object
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Validation("missing object id".into()))?
        .to_owned();
    let content_hash = fact_core::Hash::digest(&canonical_payload);
    let protected = fact_crypto::protocol_protected(
        signing_key.public_key(),
        object_type.as_str(),
        "0",
        object
            .get("ledger_id")
            .and_then(serde_json::Value::as_str)
            .map(parse_uuid_bytes)
            .transpose()?,
    );
    let cose = fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected,
        &canonical_payload,
        signing_key,
    ));
    Ok(SignedObject {
        object_id,
        content_hash: content_hash.hex(),
        object_type: object_type.as_str().to_owned(),
        canonical_payload,
        cose,
    })
}

/// Validate a signed object and import it into a store.
pub fn import_authorized_object(store: &fact_store::Store, cose: &[u8]) -> Result<ObjectSummary> {
    let content_hash = store.insert_authorized_object_with_projected_mode(
        cose,
        fact_store::ProjectedMode::Incremental,
    )?;
    let decoded = fact_crypto::decode_sign1(cose)?;
    let value: serde_json::Value = serde_json::from_slice(&decoded.payload)
        .map_err(|error| Error::Validation(error.to_string()))?;
    let object_id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Validation("missing object id".into()))?
        .to_owned();
    let object_type = value
        .get("object_type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Validation("missing object type".into()))?
        .to_owned();
    Ok(ObjectSummary {
        object_id,
        content_hash: content_hash.hex(),
        object_type,
    })
}

/// Export a signed object by ledger and object ID.
pub fn export_object_by_id(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
    object_id: uuid::Uuid,
) -> Result<Vec<u8>> {
    store
        .get_cose_by_id(ledger_id.as_bytes(), object_id.as_bytes())?
        .ok_or_else(|| Error::MissingObject(object_id.to_string()))
}

/// Export a signed object by ledger and content hash.
pub fn export_object_by_hash(
    store: &fact_store::Store,
    ledger_id: uuid::Uuid,
    hash: fact_core::Hash,
) -> Result<Vec<u8>> {
    store
        .get_cose_by_hash(ledger_id.as_bytes(), &hash)?
        .ok_or_else(|| Error::MissingObject(hash.hex()))
}

fn parse_uuid_bytes(value: &str) -> Result<[u8; 16]> {
    Ok(uuid::Uuid::parse_str(value)?.into_bytes())
}

fn b64url(bytes: &[u8]) -> String {
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

    #[test]
    fn identity_object_builders_create_schema_valid_signed_objects() {
        let seed = [42; 32];
        let key = fact_crypto::SigningKey::from_seed(&seed).unwrap();
        let actor_id = uuid::Uuid::now_v7();
        let key_id = uuid::Uuid::now_v7();
        let binding_id = uuid::Uuid::now_v7();

        let actor = create_actor_object(
            ActorObjectInput {
                actor_id,
                signing_key_id: key_id,
                bootstrap_key_id: key_id,
                bootstrap_binding_id: binding_id,
                actor_type: "agent".into(),
            },
            &key,
        )
        .unwrap();
        assert_eq!(actor.object_type, "actor");

        let key_object = create_key_object(
            KeyObjectInput {
                key_id,
                actor_id,
                signing_key_id: key_id,
                public_key: key.public_key().to_vec(),
                purpose: "signing".into(),
            },
            &key,
        )
        .unwrap();
        assert_eq!(key_object.object_type, "key");

        let binding = create_actor_key_binding_object(
            ActorKeyBindingObjectInput {
                binding_id,
                actor_id,
                signing_key_id: key_id,
                key_id,
                permitted_purpose: "signing".into(),
                predecessor_binding_id: None,
            },
            &key,
        )
        .unwrap();
        assert_eq!(binding.object_type, "actor_key_binding");
    }
}
