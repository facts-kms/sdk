use crate::{
    runtime::{production_runtime, SdkRuntime},
    Error, Result,
};
use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

/// A local ledger registered in a user's Fact environment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct LedgerEntry {
    pub name: String,
    pub ledger_id: String,
    pub database: PathBuf,
    pub actor_id: String,
    pub key_id: String,
    pub seed_file: PathBuf,
    pub read_only: bool,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct CatalogEntry {
    ledger_id: String,
    database: PathBuf,
    actor_id: String,
    key_id: String,
    seed_file: PathBuf,
    #[serde(default)]
    read_only: bool,
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct CatalogFile {
    ledgers: BTreeMap<String, CatalogEntry>,
}

/// A named remote ledger service endpoint.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RemoteEntry {
    pub name: String,
    pub url: String,
    #[serde(skip_serializing)]
    pub bearer_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RemoteMutationResult {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub scope: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct InitLedgerResult {
    pub initialized: bool,
    pub ledger_id: String,
    pub genesis_id: String,
    pub actor_id: String,
    pub key_id: String,
    pub namespace: String,
    #[serde(skip_serializing)]
    pub seed: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct EnvironmentLedgerResult {
    pub name: String,
    pub ledger_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(default)]
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct LedgerListItem {
    pub name: String,
    pub ledger_id: String,
    pub active: bool,
    pub read_only: bool,
    pub remote_count: usize,
    pub synchronization: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DeleteLedgerResult {
    pub deleted: bool,
    pub name: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct RemoteConfig {
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bearer_token: Option<String>,
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct RemoteFile {
    remotes: BTreeMap<String, RemoteConfig>,
}

/// Filesystem paths that make up a local Fact user environment.
#[derive(Clone, Debug)]
pub struct UserEnvironment {
    pub catalog: PathBuf,
    pub identity_dir: PathBuf,
    pub ledger_dir: PathBuf,
    pub active_file: PathBuf,
    pub remote_file: PathBuf,
}

impl UserEnvironment {
    /// Build a user environment rooted at a specific directory.
    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            catalog: root.join("catalog.toml"),
            identity_dir: root.join("identities"),
            ledger_dir: root.join("ledgers"),
            active_file: root.join("active"),
            remote_file: root.join("remotes.toml"),
        }
    }

    /// Return the root directory for this user environment.
    pub fn root(&self) -> PathBuf {
        self.catalog
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    /// Discover the user environment from `FACT_HOME`, `$PWD/.facts`, `XDG_DATA_HOME`, or `HOME`.
    pub fn discover() -> Result<Self> {
        let root = if let Some(value) = env::var_os("FACT_HOME") {
            PathBuf::from(value)
        } else if let Ok(current_dir) = env::current_dir() {
            let local = current_dir.join(".facts");
            if local.is_dir() {
                local
            } else if let Some(value) = env::var_os("XDG_DATA_HOME") {
                PathBuf::from(value).join("fact")
            } else if let Some(value) = env::var_os("HOME") {
                PathBuf::from(value).join(".local/share/fact")
            } else {
                return Err(Error::Message("FACT_HOME or HOME must be set".into()));
            }
        } else if let Some(value) = env::var_os("XDG_DATA_HOME") {
            PathBuf::from(value).join("fact")
        } else if let Some(value) = env::var_os("HOME") {
            PathBuf::from(value).join(".local/share/fact")
        } else {
            return Err(Error::Message("FACT_HOME or HOME must be set".into()));
        };
        Ok(Self::from_root(root))
    }

    /// Ensure directories for identities and ledgers exist.
    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.identity_dir)?;
        fs::create_dir_all(&self.ledger_dir)?;
        Ok(())
    }

    /// Return the active local ledger name, if one is configured.
    pub fn active_name(&self) -> Result<Option<String>> {
        match fs::read_to_string(&self.active_file) {
            Ok(value) => Ok(Some(value.trim().to_owned()).filter(|value| !value.is_empty())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Set the active local ledger name.
    pub fn set_active(&self, name: &str) -> Result<()> {
        self.ensure_dirs()?;
        fs::write(&self.active_file, format!("{name}\n"))?;
        Ok(())
    }

    /// Load the local ledger catalog.
    pub fn load(&self) -> Result<BTreeMap<String, LedgerEntry>> {
        let text = match fs::read_to_string(&self.catalog) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(error) => return Err(error.into()),
        };
        let file: CatalogFile = toml::from_str(&text)?;
        let entries = file
            .ledgers
            .into_iter()
            .map(|(name, value)| {
                if !valid_name(&name) {
                    return Err(Error::Validation(format!(
                        "invalid ledger name in catalog: {name}"
                    )));
                }
                Ok((
                    name.clone(),
                    LedgerEntry {
                        name,
                        ledger_id: value.ledger_id,
                        database: value.database,
                        actor_id: value.actor_id,
                        key_id: value.key_id,
                        seed_file: value.seed_file,
                        read_only: value.read_only,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        for entry in entries.values() {
            if entry.ledger_id.is_empty()
                || entry.database.as_os_str().is_empty()
                || (!entry.read_only
                    && (entry.actor_id.is_empty()
                        || entry.key_id.is_empty()
                        || entry.seed_file.as_os_str().is_empty()))
            {
                return Err(Error::Validation(format!(
                    "incomplete catalog entry {}",
                    entry.name
                )));
            }
        }
        Ok(entries)
    }

    /// Save the local ledger catalog.
    pub fn save(&self, entries: &BTreeMap<String, LedgerEntry>) -> Result<()> {
        self.ensure_dirs()?;
        let file = CatalogFile {
            ledgers: entries
                .values()
                .map(|entry| {
                    (
                        entry.name.clone(),
                        CatalogEntry {
                            ledger_id: entry.ledger_id.clone(),
                            database: entry.database.clone(),
                            actor_id: entry.actor_id.clone(),
                            key_id: entry.key_id.clone(),
                            seed_file: entry.seed_file.clone(),
                            read_only: entry.read_only,
                        },
                    )
                })
                .collect(),
        };
        for entry in entries.values() {
            if !valid_name(&entry.name) {
                return Err(Error::Validation(format!(
                    "invalid ledger name: {}",
                    entry.name
                )));
            }
        }
        fs::write(&self.catalog, toml::to_string_pretty(&file)?)?;
        Ok(())
    }

    /// Resolve a requested or active local ledger.
    pub fn resolve(&self, requested: Option<&str>) -> Result<LedgerEntry> {
        let entries = self.load()?;
        let name = requested
            .map(str::to_owned)
            .or(self.active_name()?)
            .ok_or_else(|| Error::Message("no active ledger; run `fact init`".into()))?;
        entries
            .get(&name)
            .cloned()
            .ok_or_else(|| Error::Message(format!("unknown ledger: {name}")))
    }

    /// Load configured remotes.
    pub fn load_remotes(&self) -> Result<BTreeMap<String, RemoteEntry>> {
        let text = match fs::read_to_string(&self.remote_file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(error) => return Err(error.into()),
        };
        let file: RemoteFile = toml::from_str(&text)?;
        let remotes = file
            .remotes
            .into_iter()
            .map(|(name, value)| {
                if !valid_name(&name) || value.url.is_empty() {
                    return Err(Error::Validation(format!("invalid remote entry: {name}")));
                }
                Ok((
                    name.clone(),
                    RemoteEntry {
                        name,
                        url: value.url,
                        bearer_token: value.bearer_token,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        if remotes.values().any(|remote| remote.url.is_empty()) {
            return Err(Error::Validation(
                "remote catalog contains an empty URL".into(),
            ));
        }
        Ok(remotes)
    }

    /// Save configured remotes.
    pub fn save_remotes(&self, remotes: &BTreeMap<String, RemoteEntry>) -> Result<()> {
        self.ensure_dirs()?;
        let file = RemoteFile {
            remotes: remotes
                .values()
                .map(|remote| {
                    (
                        remote.name.clone(),
                        RemoteConfig {
                            url: remote.url.clone(),
                            bearer_token: remote.bearer_token.clone(),
                        },
                    )
                })
                .collect(),
        };
        for remote in remotes.values() {
            if !valid_name(&remote.name) || remote.url.is_empty() {
                return Err(Error::Validation(
                    "remote names must be valid and URLs must be nonempty".into(),
                ));
            }
        }
        fs::write(&self.remote_file, toml::to_string_pretty(&file)?)?;
        Ok(())
    }

    /// Write an identity seed with restrictive permissions on Unix.
    pub fn write_seed(&self, path: &Path, seed: &[u8; 32]) -> Result<()> {
        self.ensure_dirs()?;
        let mut file = fs::File::create(path)?;
        file.write_all(hex::encode(seed).as_bytes())?;
        file.write_all(b"\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Read the signing seed for a writable local ledger.
    pub fn read_seed(&self, entry: &LedgerEntry) -> Result<[u8; 32]> {
        if entry.read_only {
            return Err(Error::ReadOnlyLedger);
        }
        let bytes = hex::decode(fs::read_to_string(&entry.seed_file)?.trim())?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| Error::Validation("identity seed must be 32 bytes".into()))
    }
}

/// Validate a local ledger or remote name.
pub fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Resolve a requested or active ledger from a local environment.
pub fn active_ledger(
    environment: &UserEnvironment,
    requested: Option<&str>,
) -> Result<LedgerEntry> {
    environment.resolve(requested)
}

/// Create an initialized ledger database at an explicit path.
pub fn init_ledger_database(
    path: &Path,
    namespace: &str,
    seed: Option<[u8; 32]>,
) -> Result<InitLedgerResult> {
    let runtime = production_runtime();
    init_ledger_database_with_runtime(path, namespace, seed, runtime.as_ref())
}

/// Create an initialized ledger database using an explicit runtime.
pub fn init_ledger_database_with_runtime(
    path: &Path,
    namespace: &str,
    seed: Option<[u8; 32]>,
    runtime: &dyn SdkRuntime,
) -> Result<InitLedgerResult> {
    let seed = match seed {
        Some(seed) => seed,
        None => runtime.seed()?,
    };
    let store = fact_store::Store::open(path)?;
    let bootstrap = store.bootstrap_ledger_with_ids(
        namespace,
        &runtime.timestamp(),
        seed,
        runtime.nonce()?,
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
    Ok(InitLedgerResult {
        initialized: true,
        ledger_id: bootstrap.ledger_id.to_string(),
        genesis_id: bootstrap.genesis_id.to_string(),
        actor_id: bootstrap.actor_id.to_string(),
        key_id: bootstrap.key_id.to_string(),
        namespace: namespace.to_owned(),
        seed,
    })
}

/// Ensure a named local user ledger exists in the environment.
pub fn ensure_user_ledger(
    environment: &UserEnvironment,
    name: &str,
) -> Result<(LedgerEntry, bool)> {
    let runtime = production_runtime();
    ensure_user_ledger_with_runtime(environment, name, runtime.as_ref())
}

/// Ensure a named local user ledger exists using an explicit runtime for creation.
pub fn ensure_user_ledger_with_runtime(
    environment: &UserEnvironment,
    name: &str,
    runtime: &dyn SdkRuntime,
) -> Result<(LedgerEntry, bool)> {
    if !valid_name(name) {
        return Err(Error::Validation(
            "ledger name must contain only letters, numbers, '-' or '_'".into(),
        ));
    }
    let mut entries = environment.load()?;
    if let Some(entry) = entries.get(name) {
        return Ok((entry.clone(), false));
    }
    environment.ensure_dirs()?;
    let seed = runtime.seed()?;
    let database = environment.ledger_dir.join(format!("{name}.sqlite"));
    let initialized = init_ledger_database_with_runtime(
        &database,
        &format!("local.{name}"),
        Some(seed),
        runtime,
    )?;
    let seed_file = environment
        .identity_dir
        .join(format!("{}.seed", initialized.actor_id));
    environment.write_seed(&seed_file, &seed)?;
    let entry = LedgerEntry {
        name: name.to_owned(),
        ledger_id: initialized.ledger_id,
        database,
        actor_id: initialized.actor_id,
        key_id: initialized.key_id,
        seed_file,
        read_only: false,
    };
    entries.insert(name.to_owned(), entry.clone());
    environment.save(&entries)?;
    Ok((entry, true))
}

/// Set and return the active ledger.
pub fn use_ledger(environment: &UserEnvironment, name: &str) -> Result<EnvironmentLedgerResult> {
    let entry = environment
        .load()?
        .get(name)
        .cloned()
        .ok_or_else(|| Error::MissingObject(format!("unknown ledger: {name}")))?;
    environment.set_active(name)?;
    Ok(EnvironmentLedgerResult {
        name: entry.name,
        ledger_id: entry.ledger_id,
        actor_id: None,
        read_only: entry.read_only,
        remote: None,
        active: true,
    })
}

/// List local ledgers in an environment with display metadata.
pub fn list_ledgers(environment: &UserEnvironment) -> Result<Vec<LedgerListItem>> {
    let entries = environment.load()?;
    let active = environment.active_name()?;
    let remote_count = environment.load_remotes()?.len();
    Ok(entries
        .values()
        .map(|entry| LedgerListItem {
            name: entry.name.clone(),
            ledger_id: entry.ledger_id.clone(),
            active: active.as_deref() == Some(entry.name.as_str()),
            read_only: entry.read_only,
            remote_count,
            synchronization: "local-only".into(),
        })
        .collect())
}

/// Delete a local ledger and its private seed when present.
pub fn delete_ledger(
    environment: &UserEnvironment,
    name: &str,
    force: bool,
) -> Result<DeleteLedgerResult> {
    if !force {
        return Err(Error::Validation("ledger delete requires --force".into()));
    }
    let mut entries = environment.load()?;
    let entry = entries
        .remove(name)
        .ok_or_else(|| Error::MissingObject(format!("unknown ledger: {name}")))?;
    if environment.active_name()?.as_deref() == Some(name) {
        match fs::remove_file(&environment.active_file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if entry.database.exists() {
        fs::remove_file(&entry.database)?;
    }
    if entry.seed_file.exists() {
        fs::remove_file(&entry.seed_file)?;
    }
    environment.save(&entries)?;
    Ok(DeleteLedgerResult {
        deleted: true,
        name: name.to_owned(),
    })
}

/// Register a decoded bundle or snapshot as a read-only local ledger.
pub fn clone_read_only_ledger_from_objects(
    environment: &UserEnvironment,
    name: &str,
    ledger_id: &str,
    objects: &[Vec<u8>],
    remote: Option<&str>,
) -> Result<LedgerEntry> {
    if !valid_name(name) {
        return Err(Error::Validation(
            "ledger name must contain only letters, numbers, '-' or '_'".into(),
        ));
    }
    let ledger = crate::proposition::parse_uuid7(ledger_id, "ledger")?;
    let mut entries = environment.load()?;
    if entries.contains_key(name) {
        return Err(Error::Conflict(format!("ledger already exists: {name}")));
    }
    environment.ensure_dirs()?;
    let database = environment.ledger_dir.join(format!("{name}.sqlite"));
    let store = fact_store::Store::open(&database)?;
    let (identity_objects, ledger_objects) = split_clone_objects(objects)?;
    if !identity_objects.is_empty() {
        store.insert_verified_bundle_with_projected_mode(
            &identity_objects,
            fact_store::ProjectedMode::Incremental,
        )?;
    }
    store.insert_authorized_bundle_with_projected_mode(
        &ledger_objects,
        fact_store::ProjectedMode::Incremental,
    )?;
    let entry = LedgerEntry {
        name: name.to_owned(),
        ledger_id: ledger.to_string(),
        database,
        actor_id: String::new(),
        key_id: String::new(),
        seed_file: PathBuf::new(),
        read_only: true,
    };
    entries.insert(name.to_owned(), entry.clone());
    environment.save(&entries)?;
    if let Some(remote) = remote {
        let mut remotes = environment.load_remotes()?;
        remotes.entry(name.to_owned()).or_insert(RemoteEntry {
            name: name.to_owned(),
            url: remote.to_owned(),
            bearer_token: None,
        });
        environment.save_remotes(&remotes)?;
    }
    Ok(entry)
}

type CloneObjectSplit = (Vec<Vec<u8>>, Vec<Vec<u8>>);

fn split_clone_objects(objects: &[Vec<u8>]) -> Result<CloneObjectSplit> {
    let mut identity_objects = Vec::new();
    let mut ledger_objects = Vec::new();
    for object in objects {
        let cose = fact_crypto::decode_sign1(object)?;
        let canonical = fact_canonical::encode(&cose.payload)?;
        if canonical != cose.payload {
            return Err(Error::Validation(
                "clone object payload is not canonical".into(),
            ));
        }
        let object_type = fact_schema::validate_envelope(&canonical)?;
        if object_type.ledger_scoped() {
            ledger_objects.push(object.clone());
        } else {
            identity_objects.push(object.clone());
        }
    }
    if ledger_objects.is_empty() {
        return Err(Error::Validation(
            "clone source does not contain ledger-scoped objects".into(),
        ));
    }
    Ok((identity_objects, ledger_objects))
}

/// Register an existing Fact ledger database as a read-only local ledger.
pub fn register_read_only_ledger_database(
    environment: &UserEnvironment,
    name: &str,
    database: &Path,
    requested_ledger: Option<&str>,
) -> Result<LedgerEntry> {
    if !valid_name(name) {
        return Err(Error::Validation(
            "ledger name must contain only letters, numbers, '-' or '_'".into(),
        ));
    }
    if !database.exists() {
        return Err(Error::Validation(format!(
            "ledger database does not exist: {}",
            database.display()
        )));
    }
    if !database.is_file() {
        return Err(Error::Validation(format!(
            "ledger database path is not a file: {}",
            database.display()
        )));
    }
    let database = fs::canonicalize(database)?;
    let store = fact_store::Store::open(&database)?;
    let ledgers = store.list_ledger_metadata()?;
    let ledger_id = match (requested_ledger, ledgers.as_slice()) {
        (Some(ledger), _) => {
            let ledger = crate::proposition::parse_uuid7(ledger, "ledger")?;
            let ledger = ledger.to_string();
            if ledgers.iter().any(|(candidate, _, _)| candidate == &ledger) {
                ledger
            } else {
                return Err(Error::MissingObject(format!(
                    "ledger {ledger} is not present in {}",
                    database.display()
                )));
            }
        }
        (None, []) => {
            return Err(Error::Validation(
                "database does not contain a Fact ledger".into(),
            ))
        }
        (None, [(ledger, _, _)]) => ledger.clone(),
        (None, _) => {
            return Err(Error::Validation(
                "database contains multiple Fact ledgers; pass --ledger LEDGER_ID".into(),
            ))
        }
    };
    let mut entries = environment.load()?;
    if entries.contains_key(name) {
        return Err(Error::Conflict(format!("ledger already exists: {name}")));
    }
    let entry = LedgerEntry {
        name: name.to_owned(),
        ledger_id,
        database,
        actor_id: String::new(),
        key_id: String::new(),
        seed_file: PathBuf::new(),
        read_only: true,
    };
    entries.insert(name.to_owned(), entry.clone());
    environment.save(&entries)?;
    Ok(entry)
}

/// Decode signed objects from a FACTBNDL or FACTSNAP byte stream.
pub fn decode_clone_source_objects(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    if bytes.starts_with(b"FACTBNDL") {
        fact_commitment::decode_bundle(bytes)
            .map(|bundle| bundle.objects)
            .map_err(|error| Error::Sync(error.to_string()))
    } else if bytes.starts_with(b"FACTSNAP") {
        fact_commitment::decode_snapshot(bytes)
            .map(|snapshot| snapshot.objects)
            .map_err(|error| Error::Sync(error.to_string()))
    } else {
        Err(Error::Validation(
            "clone source must be a FACTBNDL or FACTSNAP file or HTTP URL".into(),
        ))
    }
}

/// Resolve the ledger ID contained in a clone source or require one for URLs.
pub fn clone_source_ledger_id(source: &str, requested: Option<&str>) -> Result<String> {
    if is_remote_url(source) {
        return requested
            .map(str::to_owned)
            .ok_or_else(|| Error::Validation("remote clone requires --ledger LEDGER_ID".into()));
    }
    let bytes = fs::read(source)?;
    let manifest = if bytes.starts_with(b"FACTBNDL") {
        fact_commitment::decode_bundle(&bytes)
            .map(|bundle| bundle.manifest)
            .map_err(|error| Error::Sync(error.to_string()))?
    } else if bytes.starts_with(b"FACTSNAP") {
        fact_commitment::decode_snapshot(&bytes)
            .map(|snapshot| snapshot.manifest)
            .map_err(|error| Error::Sync(error.to_string()))?
    } else {
        return Err(Error::Validation(
            "clone source must be a FACTBNDL or FACTSNAP file or HTTP URL".into(),
        ));
    };
    let manifest_value: serde_json::Value = serde_json::from_slice(&manifest)?;
    manifest_value["ledger_id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::Validation(
                "bundle manifest does not identify a ledger; pass --ledger LEDGER_ID".into(),
            )
        })
}

/// Pick a portable default name for a clone source.
pub fn clone_source_name(environment: &UserEnvironment, source: &str) -> Result<String> {
    let raw = if is_remote_url(source) {
        "clone".to_owned()
    } else {
        Path::new(source)
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("clone")
            .to_owned()
    };
    let mut name = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    if name.is_empty() {
        name = "clone".to_owned();
    }
    if !environment.load()?.contains_key(&name) {
        return Ok(name);
    }
    name.push('-');
    name.push_str(&uuid::Uuid::now_v7().to_string()[..8]);
    Ok(name)
}

/// Identify remote clone sources.
pub fn is_remote_url(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}

/// List remotes configured in a local environment.
pub fn list_remotes(environment: &UserEnvironment) -> Result<Vec<RemoteEntry>> {
    Ok(environment.load_remotes()?.into_values().collect())
}

/// Add a named remote to a local environment.
pub fn add_remote(
    environment: &UserEnvironment,
    name: &str,
    url: &str,
) -> Result<RemoteMutationResult> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(Error::Validation(
            "remote URL must use http:// or https://".into(),
        ));
    }
    let mut remotes = environment.load_remotes()?;
    if remotes.contains_key(name) {
        return Err(Error::Conflict(format!("remote already exists: {name}")));
    }
    remotes.insert(
        name.to_owned(),
        RemoteEntry {
            name: name.to_owned(),
            url: url.to_owned(),
            bearer_token: None,
        },
    );
    environment.save_remotes(&remotes)?;
    Ok(RemoteMutationResult {
        name: name.to_owned(),
        old_name: None,
        new_name: None,
        url: Some(url.to_owned()),
        scope: "local-environment".into(),
    })
}

/// Remove a named remote from a local environment.
pub fn remove_remote(environment: &UserEnvironment, name: &str) -> Result<RemoteMutationResult> {
    let mut remotes = environment.load_remotes()?;
    remotes
        .remove(name)
        .ok_or_else(|| Error::MissingObject(format!("unknown remote: {name}")))?;
    environment.save_remotes(&remotes)?;
    Ok(RemoteMutationResult {
        name: name.to_owned(),
        old_name: None,
        new_name: None,
        url: None,
        scope: "local-environment".into(),
    })
}

/// Rename a configured remote.
pub fn rename_remote(
    environment: &UserEnvironment,
    old_name: &str,
    new_name: &str,
) -> Result<RemoteMutationResult> {
    if !valid_name(new_name) {
        return Err(Error::Validation("invalid new remote name".into()));
    }
    let mut remotes = environment.load_remotes()?;
    let remote = remotes
        .remove(old_name)
        .ok_or_else(|| Error::MissingObject(format!("unknown remote: {old_name}")))?;
    if remotes.contains_key(new_name) {
        return Err(Error::Conflict(format!(
            "remote already exists: {new_name}"
        )));
    }
    remotes.insert(
        new_name.to_owned(),
        RemoteEntry {
            name: new_name.to_owned(),
            url: remote.url,
            bearer_token: remote.bearer_token,
        },
    );
    environment.save_remotes(&remotes)?;
    Ok(RemoteMutationResult {
        name: new_name.to_owned(),
        old_name: Some(old_name.to_owned()),
        new_name: Some(new_name.to_owned()),
        url: None,
        scope: "local-environment".into(),
    })
}

/// Store or replace the bearer token remembered for a configured remote.
pub fn set_remote_bearer_token(
    environment: &UserEnvironment,
    name: &str,
    bearer_token: Option<String>,
) -> Result<RemoteMutationResult> {
    let mut remotes = environment.load_remotes()?;
    let remote = remotes
        .get_mut(name)
        .ok_or_else(|| Error::MissingObject(format!("unknown remote: {name}")))?;
    remote.bearer_token = bearer_token;
    let url = remote.url.clone();
    environment.save_remotes(&remotes)?;
    Ok(RemoteMutationResult {
        name: name.to_owned(),
        old_name: None,
        new_name: None,
        url: Some(url),
        scope: "remote".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_env(temp: &tempfile::TempDir) -> UserEnvironment {
        UserEnvironment {
            catalog: temp.path().join("catalog.toml"),
            active_file: temp.path().join("active"),
            identity_dir: temp.path().join("identities"),
            ledger_dir: temp.path().join("ledgers"),
            remote_file: temp.path().join("remotes.toml"),
        }
    }

    #[test]
    fn valid_names_are_portable_identifiers() {
        assert!(valid_name("default"));
        assert!(valid_name("team_1"));
        assert!(valid_name("team-1"));
        assert!(!valid_name(""));
        assert!(!valid_name("team one"));
        assert!(!valid_name("../team"));
    }

    #[test]
    fn environment_round_trips_catalog_and_remotes() {
        let temp = tempfile::tempdir().unwrap();
        let env = UserEnvironment {
            catalog: temp.path().join("catalog.toml"),
            identity_dir: temp.path().join("identities"),
            ledger_dir: temp.path().join("ledgers"),
            active_file: temp.path().join("active"),
            remote_file: temp.path().join("remotes.toml"),
        };
        let entry = LedgerEntry {
            name: "default".into(),
            ledger_id: uuid::Uuid::now_v7().to_string(),
            database: temp.path().join("default.sqlite"),
            actor_id: uuid::Uuid::now_v7().to_string(),
            key_id: uuid::Uuid::now_v7().to_string(),
            seed_file: temp.path().join("seed"),
            read_only: false,
        };
        let mut ledgers = BTreeMap::new();
        ledgers.insert(entry.name.clone(), entry.clone());
        env.save(&ledgers).unwrap();
        env.set_active("default").unwrap();
        assert_eq!(env.resolve(None).unwrap(), entry);

        let mut remotes = BTreeMap::new();
        remotes.insert(
            "origin".into(),
            RemoteEntry {
                name: "origin".into(),
                url: "https://example.test".into(),
                bearer_token: None,
            },
        );
        env.save_remotes(&remotes).unwrap();
        assert_eq!(env.load_remotes().unwrap(), remotes);
    }

    #[test]
    fn remote_workflows_validate_and_mutate_catalog() {
        let temp = tempfile::tempdir().unwrap();
        let env = test_env(&temp);

        let added = add_remote(&env, "origin", "https://example.test/facts").unwrap();
        assert_eq!(added.name, "origin");
        assert_eq!(list_remotes(&env).unwrap().len(), 1);
        assert!(matches!(
            add_remote(&env, "bad", "file:///tmp/facts"),
            Err(Error::Validation(_))
        ));

        let renamed = rename_remote(&env, "origin", "backup").unwrap();
        assert_eq!(renamed.old_name.as_deref(), Some("origin"));
        assert_eq!(renamed.new_name.as_deref(), Some("backup"));
        assert_eq!(list_remotes(&env).unwrap()[0].name, "backup");

        let removed = remove_remote(&env, "backup").unwrap();
        assert_eq!(removed.name, "backup");
        assert!(list_remotes(&env).unwrap().is_empty());

        add_remote(&env, "auth", "https://example.test/facts").unwrap();
        set_remote_bearer_token(&env, "auth", Some("secret-token".into())).unwrap();
        let remote = env.load_remotes().unwrap().remove("auth").unwrap();
        assert_eq!(remote.bearer_token.as_deref(), Some("secret-token"));
        assert!(!serde_json::to_string(&remote)
            .unwrap()
            .contains("secret-token"));
        set_remote_bearer_token(&env, "auth", None).unwrap();
        assert_eq!(
            env.load_remotes()
                .unwrap()
                .remove("auth")
                .unwrap()
                .bearer_token,
            None
        );
    }

    #[test]
    fn ledger_workflows_create_use_list_delete_and_initialize() {
        let temp = tempfile::tempdir().unwrap();
        let env = test_env(&temp);

        let (entry, created) = ensure_user_ledger(&env, "default").unwrap();
        assert!(created);
        assert!(!entry.read_only);
        assert!(entry.database.exists());
        assert!(entry.seed_file.exists());

        let active = use_ledger(&env, "default").unwrap();
        assert_eq!(active.name, "default");
        assert!(active.active);
        assert_eq!(
            active_ledger(&env, None).unwrap().ledger_id,
            entry.ledger_id
        );

        let listed = list_ledgers(&env).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].active);

        let explicit = temp.path().join("explicit.sqlite");
        let initialized =
            init_ledger_database(&explicit, "local.explicit", Some([71; 32])).unwrap();
        assert!(initialized.initialized);
        assert_eq!(initialized.namespace, "local.explicit");
        assert_eq!(initialized.seed, [71; 32]);

        let deleted = delete_ledger(&env, "default", true).unwrap();
        assert!(deleted.deleted);
        assert!(!entry.database.exists());
        assert!(!entry.seed_file.exists());
        assert!(list_ledgers(&env).unwrap().is_empty());
    }

    #[test]
    fn clone_source_helpers_and_read_only_registration_work() {
        let temp = tempfile::tempdir().unwrap();
        let env = test_env(&temp);
        let (source, _) = ensure_user_ledger(&env, "source").unwrap();
        let bundle_path = temp.path().join("source.bundle");
        let bundle = encode_test_bundle(&source);
        fs::write(&bundle_path, &bundle).unwrap();

        assert_eq!(
            clone_source_ledger_id(bundle_path.to_str().unwrap(), None).unwrap(),
            source.ledger_id
        );
        assert!(clone_source_name(&env, bundle_path.to_str().unwrap())
            .unwrap()
            .starts_with("source-"));
        let objects = decode_clone_source_objects(&bundle).unwrap();
        let cloned =
            clone_read_only_ledger_from_objects(&env, "copy", &source.ledger_id, &objects, None)
                .unwrap();
        assert!(cloned.read_only);
        assert_eq!(cloned.ledger_id, source.ledger_id);
    }

    #[test]
    fn existing_database_registration_is_read_only_and_validated() {
        let temp = tempfile::tempdir().unwrap();
        let env = test_env(&temp);
        let (source, _) = ensure_user_ledger(&env, "source").unwrap();

        let registered =
            register_read_only_ledger_database(&env, "attached", &source.database, None).unwrap();
        assert!(registered.read_only);
        assert_eq!(registered.ledger_id, source.ledger_id);
        assert_eq!(
            registered.database,
            fs::canonicalize(&source.database).unwrap()
        );
        assert!(registered.actor_id.is_empty());
        assert!(registered.seed_file.as_os_str().is_empty());

        assert!(matches!(
            register_read_only_ledger_database(&env, "attached", &source.database, None),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            register_read_only_ledger_database(
                &env,
                "missing",
                &temp.path().join("missing.sqlite"),
                None
            ),
            Err(Error::Validation(_))
        ));

        let empty = temp.path().join("empty.sqlite");
        let _ = fact_store::Store::open(&empty).unwrap();
        assert!(matches!(
            register_read_only_ledger_database(&env, "empty", &empty, None),
            Err(Error::Validation(_))
        ));
    }

    #[test]
    fn existing_database_registration_requires_ledger_for_multi_ledger_database() {
        let temp = tempfile::tempdir().unwrap();
        let env = test_env(&temp);
        let database = temp.path().join("multi.sqlite");
        let first = init_ledger_database(&database, "local.first", Some([11; 32])).unwrap();
        let second = init_ledger_database(&database, "local.second", Some([12; 32])).unwrap();

        assert!(matches!(
            register_read_only_ledger_database(&env, "multi", &database, None),
            Err(Error::Validation(_))
        ));
        assert!(matches!(
            register_read_only_ledger_database(
                &env,
                "multi",
                &database,
                Some(&uuid::Uuid::now_v7().to_string())
            ),
            Err(Error::MissingObject(_))
        ));

        let registered =
            register_read_only_ledger_database(&env, "multi", &database, Some(&second.ledger_id))
                .unwrap();
        assert_eq!(registered.ledger_id, second.ledger_id);
        assert_ne!(registered.ledger_id, first.ledger_id);
    }

    fn encode_test_bundle(entry: &LedgerEntry) -> Vec<u8> {
        let ledger = uuid::Uuid::parse_str(&entry.ledger_id).unwrap();
        let store = fact_store::Store::open(&entry.database).unwrap();
        let objects = store
            .list_objects_with_dependencies(ledger.as_bytes())
            .unwrap()
            .into_iter()
            .map(|(object_id, hash, _)| {
                let bytes = store
                    .get_cose_by_id_any(object_id.as_bytes())
                    .unwrap()
                    .unwrap();
                (hash, bytes)
            })
            .collect::<Vec<_>>();
        let manifest = fact_canonical::encode(&serde_json::to_vec(&serde_json::json!({
            "schema":"facts-protocol-bundle-v0",
            "protocol_version":0,
            "bundle_id":fact_commitment::deterministic_bundle_id(&objects),
            "object_count":objects.len(),
            "ledger_id":entry.ledger_id,
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
        })).unwrap()).unwrap();
        fact_commitment::encode_bundle(&manifest, &objects).unwrap()
    }
}
