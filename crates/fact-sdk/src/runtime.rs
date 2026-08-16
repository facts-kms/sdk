//! Runtime services for canonical SDK operations.
//!
//! Production callers use [`ProductionRuntime`] through the normal SDK APIs.
//! [`DeterministicRuntime`] is explicit test/simulation support. It uses real
//! cryptography with deterministic entropy; it must not be treated as a secure
//! production entropy source.

use crate::{Error, Result};
#[cfg(any(test, feature = "deterministic-runtime"))]
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[cfg(any(test, feature = "deterministic-runtime"))]
use std::sync::Mutex;

pub type Runtime = Arc<dyn SdkRuntime>;

pub trait SdkRuntime: Send + Sync {
    fn now(&self) -> time::OffsetDateTime;
    fn fill_bytes(&self, output: &mut [u8]) -> Result<()>;

    fn next_uuid_v7(&self) -> Result<uuid::Uuid> {
        let now = self.now();
        let millis = now.unix_timestamp_nanos() / 1_000_000;
        if millis < 0 {
            return Err(Error::Validation(
                "UUIDv7 runtime clock must be at or after Unix epoch".into(),
            ));
        }
        let mut bytes = [0u8; 10];
        self.fill_bytes(&mut bytes)?;
        Ok(uuid::Builder::from_unix_timestamp_millis(millis as u64, &bytes).into_uuid())
    }

    fn timestamp(&self) -> String {
        timestamp_string(self.now())
    }

    fn seed(&self) -> Result<[u8; 32]> {
        let mut seed = [0u8; 32];
        self.fill_bytes(&mut seed)?;
        Ok(seed)
    }

    fn nonce(&self) -> Result<[u8; 16]> {
        let mut nonce = [0u8; 16];
        self.fill_bytes(&mut nonce)?;
        Ok(nonce)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProductionRuntime;

impl ProductionRuntime {
    pub fn shared() -> Runtime {
        Arc::new(Self)
    }
}

impl SdkRuntime for ProductionRuntime {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }

    fn fill_bytes(&self, output: &mut [u8]) -> Result<()> {
        for chunk in output.chunks_mut(32) {
            let random = rand::random::<[u8; 32]>();
            chunk.copy_from_slice(&random[..chunk.len()]);
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "deterministic-runtime"))]
#[derive(Clone, Debug)]
pub struct DeterministicRuntime {
    inner: Arc<Mutex<DeterministicState>>,
}

#[cfg(any(test, feature = "deterministic-runtime"))]
#[derive(Clone, Debug)]
struct DeterministicState {
    seed: Vec<u8>,
    counter: u64,
    now: time::OffsetDateTime,
}

#[cfg(any(test, feature = "deterministic-runtime"))]
impl DeterministicRuntime {
    pub fn new(seed: impl AsRef<[u8]>, start: time::OffsetDateTime) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DeterministicState {
                seed: seed.as_ref().to_vec(),
                counter: 0,
                now: start,
            })),
        }
    }

    pub fn shared(seed: impl AsRef<[u8]>, start: time::OffsetDateTime) -> Runtime {
        Arc::new(Self::new(seed, start))
    }

    pub fn set_time(&self, time: time::OffsetDateTime) -> Result<()> {
        self.inner
            .lock()
            .map_err(|_| Error::Message("deterministic runtime lock poisoned".into()))?
            .now = time;
        Ok(())
    }

    pub fn advance(&self, duration: time::Duration) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| Error::Message("deterministic runtime lock poisoned".into()))?;
        inner.now += duration;
        Ok(())
    }
}

#[cfg(any(test, feature = "deterministic-runtime"))]
impl SdkRuntime for DeterministicRuntime {
    fn now(&self) -> time::OffsetDateTime {
        self.inner
            .lock()
            .expect("deterministic runtime lock should not be poisoned")
            .now
    }

    fn fill_bytes(&self, output: &mut [u8]) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| Error::Message("deterministic runtime lock poisoned".into()))?;
        let mut offset = 0;
        while offset < output.len() {
            let mut hasher = Sha256::new();
            hasher.update(b"facts-sdk-deterministic-runtime-v0");
            hasher.update(&inner.seed);
            hasher.update(inner.counter.to_be_bytes());
            let block = hasher.finalize();
            inner.counter = inner.counter.checked_add(1).ok_or_else(|| {
                Error::Validation("deterministic entropy counter overflow".into())
            })?;
            let take = (output.len() - offset).min(block.len());
            output[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
        }
        Ok(())
    }
}

pub fn production_runtime() -> Runtime {
    ProductionRuntime::shared()
}

pub fn timestamp_string(now: time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, path::Path};

    fn start() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[test]
    fn deterministic_runtime_replays_uuid_and_entropy_sequences() {
        let first = DeterministicRuntime::new(b"seed", start());
        let second = DeterministicRuntime::new(b"seed", start());
        let first_ids = (0..4)
            .map(|_| first.next_uuid_v7().unwrap())
            .collect::<Vec<_>>();
        let second_ids = (0..4)
            .map(|_| second.next_uuid_v7().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(first_ids, second_ids);
        assert_eq!(
            first_ids
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            4
        );
        assert!(first_ids.iter().all(|id| id.get_version_num() == 7));
    }

    #[test]
    fn deterministic_runtime_seed_and_time_affect_uuid_sequence() {
        let first = DeterministicRuntime::new(b"seed", start());
        let different_seed = DeterministicRuntime::new(b"other", start());
        assert_ne!(
            first.next_uuid_v7().unwrap(),
            different_seed.next_uuid_v7().unwrap()
        );

        let runtime = DeterministicRuntime::new(b"seed", start());
        let before = runtime.next_uuid_v7().unwrap();
        runtime.advance(time::Duration::days(2)).unwrap();
        let after = runtime.next_uuid_v7().unwrap();
        assert_ne!(
            before.get_timestamp().unwrap(),
            after.get_timestamp().unwrap()
        );
    }

    #[test]
    fn deterministic_runtime_replays_workflow_cose_bytes() {
        let first = run_deterministic_workflow(b"scenario-seed");
        let second = run_deterministic_workflow(b"scenario-seed");
        assert_eq!(first.objects, second.objects);
        assert_eq!(first.ledger_id, second.ledger_id);
        assert_eq!(first.actor_id, second.actor_id);
        assert_eq!(first.initial_seed, second.initial_seed);

        let different = run_deterministic_workflow(b"different-scenario-seed");
        assert_ne!(first.objects, different.objects);
        assert_ne!(first.initial_seed, different.initial_seed);
    }

    #[test]
    fn deterministic_runtime_clock_advances_only_future_objects() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeterministicRuntime::new(b"clock-seed", start());
        let entry = init_entry(temp.path(), &runtime);
        let seed = std::fs::read(&entry.seed_file).unwrap().try_into().unwrap();
        let proposition = crate::proposition::create_proposition_with_runtime(
            &entry,
            &seed,
            b"# Clock\n\nInitial content.\n",
            None,
            &runtime,
        )
        .unwrap();
        let initial_revision = stored_cose(&entry, proposition.revision_id);
        let initial_payload = payload_value(&initial_revision);
        assert_eq!(initial_payload["created_at"], "2023-11-14T22:13:20.000Z");

        runtime.advance(time::Duration::days(2)).unwrap();
        let update = crate::proposition::update_proposition_content_with_runtime(
            &entry,
            &seed,
            &proposition.proposition_id.to_string(),
            b"# Clock\n\nUpdated content.\n",
            &runtime,
        )
        .unwrap();
        let initial_after_advance = stored_cose(&entry, proposition.revision_id);
        assert_eq!(initial_revision, initial_after_advance);

        let update_payload = payload_value(&stored_cose(&entry, update.revision_id));
        assert_eq!(update_payload["created_at"], "2023-11-16T22:13:20.000Z");
    }

    #[test]
    fn production_default_apis_create_valid_signed_objects() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("production.sqlite");
        let initialized = crate::environment::init_ledger_database(
            &database,
            "local.production-runtime-test",
            Some([44; 32]),
        )
        .unwrap();
        let entry = crate::environment::LedgerEntry {
            name: "production".into(),
            ledger_id: initialized.ledger_id.clone(),
            database,
            actor_id: initialized.actor_id,
            key_id: initialized.key_id,
            seed_file: temp.path().join("seed"),
            read_only: false,
        };
        let proposition = crate::proposition::create_proposition(
            &entry,
            &[44; 32],
            b"# Production\n\nDefault runtime path.\n",
            None,
        )
        .unwrap();
        assert_eq!(proposition.proposition_id.get_version_num(), 7);
        assert_eq!(proposition.revision_id.get_version_num(), 7);
        assert_eq!(proposition.deliberation_id.get_version_num(), 7);

        let store = fact_store::Store::open(&entry.database).unwrap();
        for object in store
            .list_object_summaries(uuid::Uuid::parse_str(&entry.ledger_id).unwrap().as_bytes())
            .unwrap()
        {
            let bytes = store
                .get_cose_by_id_any(object.object_id.as_bytes())
                .unwrap()
                .unwrap();
            let payload = fact_crypto::decode_sign1(&bytes).unwrap().payload;
            fact_schema::validate_envelope(&payload).unwrap();
        }
    }

    #[derive(Debug)]
    struct WorkflowBytes {
        ledger_id: String,
        actor_id: String,
        initial_seed: [u8; 32],
        objects: Vec<(String, Vec<u8>)>,
    }

    fn run_deterministic_workflow(seed: &[u8]) -> WorkflowBytes {
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeterministicRuntime::new(seed, start());
        let entry = init_entry(temp.path(), &runtime);
        let initial_seed = std::fs::read(&entry.seed_file).unwrap().try_into().unwrap();
        let proposition = crate::proposition::create_proposition_with_runtime(
            &entry,
            &initial_seed,
            b"# Deterministic\n\nInitial content.\n",
            None,
            &runtime,
        )
        .unwrap();
        runtime.advance(time::Duration::days(1)).unwrap();
        crate::proposition::update_proposition_content_with_runtime(
            &entry,
            &initial_seed,
            &proposition.proposition_id.to_string(),
            b"# Deterministic\n\nUpdated content.\n",
            &runtime,
        )
        .unwrap();
        runtime.advance(time::Duration::days(1)).unwrap();
        crate::proposition::accept_proposition_with_runtime(
            &entry,
            &initial_seed,
            Some(&proposition.proposition_id.to_string()),
            &runtime,
        )
        .unwrap();
        runtime.advance(time::Duration::days(1)).unwrap();
        crate::identity::rotate_identity_key_with_runtime(&entry, &initial_seed, &runtime).unwrap();
        let objects = collect_cose(&entry);
        WorkflowBytes {
            ledger_id: entry.ledger_id,
            actor_id: entry.actor_id,
            initial_seed,
            objects,
        }
    }

    fn init_entry(root: &Path, runtime: &DeterministicRuntime) -> crate::environment::LedgerEntry {
        let database = root.join("test.sqlite");
        let initialized = crate::environment::init_ledger_database_with_runtime(
            &database,
            "local.deterministic-runtime-test",
            None,
            runtime,
        )
        .unwrap();
        let seed_file = root.join("seed");
        std::fs::write(&seed_file, initialized.seed).unwrap();
        crate::environment::LedgerEntry {
            name: "test".into(),
            ledger_id: initialized.ledger_id,
            database,
            actor_id: initialized.actor_id,
            key_id: initialized.key_id,
            seed_file,
            read_only: false,
        }
    }

    fn collect_cose(entry: &crate::environment::LedgerEntry) -> Vec<(String, Vec<u8>)> {
        let ledger = uuid::Uuid::parse_str(&entry.ledger_id).unwrap();
        let store = fact_store::Store::open(&entry.database).unwrap();
        let mut objects = BTreeMap::new();
        for object in store.list_object_summaries(ledger.as_bytes()).unwrap() {
            objects.insert(
                object.object_id.to_string(),
                store
                    .get_cose_by_id(ledger.as_bytes(), object.object_id.as_bytes())
                    .unwrap()
                    .unwrap(),
            );
        }
        for (id, _, _) in store.list_identity_objects().unwrap() {
            objects.insert(
                id.to_string(),
                store.get_cose_by_id_any(id.as_bytes()).unwrap().unwrap(),
            );
        }
        objects.into_iter().collect()
    }

    fn stored_cose(entry: &crate::environment::LedgerEntry, id: uuid::Uuid) -> Vec<u8> {
        let store = fact_store::Store::open(&entry.database).unwrap();
        store.get_cose_by_id_any(id.as_bytes()).unwrap().unwrap()
    }

    fn payload_value(cose: &[u8]) -> serde_json::Value {
        serde_json::from_slice(&fact_crypto::decode_sign1(cose).unwrap().payload).unwrap()
    }
}
