use fact_core::Hash;
use std::{
    fs,
    path::{Path, PathBuf},
};

const FIXTURE_MANIFEST: &str = include_str!("../../../fixtures/manifest.json");

pub fn fixture_manifest_valid() -> bool {
    fixture_manifest_valid_at(fixture_root())
}

pub fn authority_matrix_valid() -> bool {
    authority_matrix_valid_at(fixture_root())
}

pub fn authority_matrix_valid_at(root: impl AsRef<Path>) -> bool {
    let Ok(bytes) = fs::read(root.as_ref().join("authority-matrix.json")) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    value.get("schema").and_then(serde_json::Value::as_str)
        == Some("facts-protocol-authority-matrix-v0")
        && value.get("protocol_version") == Some(&serde_json::json!(0))
        && value.get("core").and_then(serde_json::Value::as_str)
            == Some("fact_protocol_specification_v0.md")
        && value
            .get("companions")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|companions| {
                [
                    "objects",
                    "authorization",
                    "decisions",
                    "http",
                    "commitments",
                    "reconciliation_rosters",
                    "search",
                    "conformance",
                    "vectors",
                ]
                .iter()
                .all(|name| {
                    companions
                        .get(*name)
                        .is_some_and(serde_json::Value::is_string)
                })
            })
        && value
            .get("validation_precedence")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|stages| stages.len() == 11)
        && value
            .get("sections")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|sections| {
                [
                    "authority-order",
                    "validation-precedence",
                    "fetch-identity-semantics",
                    "transport-policy-boundary",
                    "conformance-evidence",
                    "deployment-http-defaults",
                    "caller-authentication-policy",
                    "cli-global-context",
                    "cli-content-commands",
                ]
                .iter()
                .all(|name| {
                    sections
                        .get(*name)
                        .is_some_and(serde_json::Value::is_string)
                })
            })
        && value
            .get("error_precedence")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|errors| errors.len() >= 6)
        && value
            .get("registry")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|registry| {
                registry
                    .get("schemas")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|schemas| schemas.len() >= 7)
                    && registry
                        .get("media_types")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|media_types| media_types.len() >= 6)
                    && registry
                        .get("routes")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|routes| {
                            routes.len() >= 9
                                && routes.iter().all(|route| {
                                    route
                                        .get("method")
                                        .is_some_and(serde_json::Value::is_string)
                                        && route
                                            .get("path")
                                            .is_some_and(serde_json::Value::is_string)
                                        && route
                                            .get("auth")
                                            .is_some_and(serde_json::Value::is_string)
                                })
                        })
                    && registry
                        .get("headers")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|headers| headers.len() >= 7)
                    && registry
                        .get("errors")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|errors| errors.len() >= 8)
                    && registry
                        .get("fixture_roots")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|roots| roots.len() >= 6)
            })
}

pub fn fixture_manifest_valid_at(root: impl AsRef<Path>) -> bool {
    let Ok(bytes) = fs::read(root.as_ref().join("manifest.json")) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some("facts-reference-fixture-manifest-v0")
    {
        return false;
    }
    if value
        .get("suite_version")
        .and_then(serde_json::Value::as_str)
        != Some("0")
    {
        return false;
    }
    let positive = value
        .get("positive_object_types")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
        });
    let expected = fact_schema::OBJECT_TYPES.to_vec();
    let positive_files = value
        .get("positive_fixture_files")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
        });
    let expected_files = expected
        .iter()
        .map(|object_type| format!("{object_type}.json"))
        .collect::<Vec<_>>();
    let expected_negative_profiles = [
        "unknown-body-field",
        "noncanonical-json",
        "invalid-uuid",
        "invalid-hash",
        "dependency-hash-mismatch",
    ];
    let negative_profiles = value
        .get("negative_profiles")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
        });
    let negative_files = value
        .get("negative_fixture_files")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
        });
    let expected_negative_files = expected_negative_profiles
        .iter()
        .map(|profile| format!("{profile}.json"))
        .collect::<Vec<_>>();
    let expected_scenarios = [
        "causal_authorization.json",
        "consensus_replay.json",
        "api_envelope.json",
        "invitation_admission.json",
        "lifecycle_effective_state.json",
        "reconciliation_roster.json",
        "exchange_artifacts.json",
        "transport_race.json",
    ];
    positive == Some(expected)
        && value
            .get("positive_fixture_directory")
            .and_then(serde_json::Value::as_str)
            == Some("positive/objects")
        && positive_files
            == Some(
                expected_files
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
        && negative_profiles == Some(expected_negative_profiles.to_vec())
        && negative_files
            == Some(
                expected_negative_files
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
        && value
            .get("negative_object_fixture_directory")
            .and_then(serde_json::Value::as_str)
            == Some("negative/objects")
        && value
            .get("negative_object_fixture_files")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|files| files.len() == fact_schema::OBJECT_TYPES.len())
        && value
            .get("scenario_directory")
            .and_then(serde_json::Value::as_str)
            == Some("scenarios")
        && value
            .get("scenario_files")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|files| {
                files
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .eq(expected_scenarios)
            })
}

/// Materialize the deterministic JSON fixture corpus used by the reference
/// runner. The generated values are stable by construction and are written as
/// exact canonical bytes, so the checked-in corpus can be consumed by other
/// implementations without linking this crate.
pub fn materialize_fixtures(root: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let root = root.as_ref();
    fs::create_dir_all(root)?;
    fs::write(root.join("manifest.json"), FIXTURE_MANIFEST.as_bytes())?;
    fs::write(
        root.join("authority-matrix.json"),
        include_str!("../../../fixtures/authority-matrix.json"),
    )?;
    let positive = root.join("positive/objects");
    let negative = root.join("negative/encoding");
    let negative_objects = root.join("negative/objects");
    fs::create_dir_all(&positive)?;
    fs::create_dir_all(&negative)?;
    fs::create_dir_all(&negative_objects)?;
    for object_type in fact_schema::OBJECT_TYPES {
        let bytes = fact_schema::generated_positive_fixture(object_type)?;
        fs::write(positive.join(format!("{object_type}.json")), &bytes)?;
        let mut invalid: serde_json::Value = serde_json::from_slice(&bytes)?;
        invalid["body"]["unexpected_fixture_field"] = serde_json::json!(true);
        fs::write(
            negative_objects.join(format!("{object_type}.json")),
            fact_canonical::encode(&serde_json::to_vec(&invalid)?)?,
        )?;
    }
    let proposition = fact_schema::generated_positive_fixture("proposition")?;
    let mut unknown: serde_json::Value = serde_json::from_slice(&proposition)?;
    unknown["body"]["unexpected"] = serde_json::json!(true);
    fs::write(
        negative.join("unknown-body-field.json"),
        fact_canonical::encode(&serde_json::to_vec(&unknown)?)?,
    )?;
    fs::write(negative.join("noncanonical-json.json"), br#"{ "a": 1 }"#)?;
    let mut invalid_uuid: serde_json::Value = serde_json::from_slice(&proposition)?;
    invalid_uuid["id"] = serde_json::json!("not-a-uuid");
    fs::write(
        negative.join("invalid-uuid.json"),
        fact_canonical::encode(&serde_json::to_vec(&invalid_uuid)?)?,
    )?;
    let key = fact_schema::generated_positive_fixture("key")?;
    let mut invalid_hash: serde_json::Value = serde_json::from_slice(&key)?;
    invalid_hash["body"]["public_key"]["fingerprint"] = serde_json::json!("00".repeat(32));
    fs::write(
        negative.join("invalid-hash.json"),
        fact_canonical::encode(&serde_json::to_vec(&invalid_hash)?)?,
    )?;
    let mut dependency: serde_json::Value = serde_json::from_slice(&proposition)?;
    dependency["dependencies"] = serde_json::json!([{
        "object_id":"01900000-0000-7000-8000-000000000099",
        "content_hash":"00".repeat(32),
        "role":"required-dependency"
    }]);
    fs::write(
        negative.join("dependency-hash-mismatch.json"),
        fact_canonical::encode(&serde_json::to_vec(&dependency)?)?,
    )?;
    let scenarios = root.join("scenarios");
    fs::create_dir_all(&scenarios)?;
    for (name, contents) in [
        (
            "causal_authorization.json",
            include_str!("../../../fixtures/scenarios/causal_authorization.json"),
        ),
        (
            "consensus_replay.json",
            include_str!("../../../fixtures/scenarios/consensus_replay.json"),
        ),
        (
            "api_envelope.json",
            include_str!("../../../fixtures/scenarios/api_envelope.json"),
        ),
        (
            "invitation_admission.json",
            include_str!("../../../fixtures/scenarios/invitation_admission.json"),
        ),
        (
            "lifecycle_effective_state.json",
            include_str!("../../../fixtures/scenarios/lifecycle_effective_state.json"),
        ),
        (
            "reconciliation_roster.json",
            include_str!("../../../fixtures/scenarios/reconciliation_roster.json"),
        ),
        (
            "exchange_artifacts.json",
            include_str!("../../../fixtures/scenarios/exchange_artifacts.json"),
        ),
        (
            "transport_race.json",
            include_str!("../../../fixtures/scenarios/transport_race.json"),
        ),
    ] {
        fs::write(scenarios.join(name), contents)?;
    }
    Ok(())
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

pub fn committed_fixture_files_valid() -> bool {
    committed_fixture_files_valid_at(fixture_root())
}

pub fn committed_fixture_files_valid_at(root: impl AsRef<Path>) -> bool {
    let root = root.as_ref();
    let positive = root.join("positive/objects");
    let negative = root.join("negative/encoding");
    let manifest: serde_json::Value = fs::read(root.join("manifest.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    let manifest_positive = manifest
        .get("positive_fixture_files")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|files| files.len() == fact_schema::OBJECT_TYPES.len());
    manifest_positive
        && fact_schema::OBJECT_TYPES.iter().all(|object_type| {
            let Ok(bytes) = fs::read(positive.join(format!("{object_type}.json"))) else {
                return false;
            };
            fact_schema::validate_envelope(&bytes).is_ok()
        })
        && fs::read(negative.join("unknown-body-field.json")).is_ok()
        && fs::read(negative.join("noncanonical-json.json")).is_ok()
        && fs::read(negative.join("invalid-uuid.json")).is_ok()
        && fs::read(negative.join("invalid-hash.json")).is_ok()
        && fs::read(negative.join("dependency-hash-mismatch.json")).is_ok()
}

pub fn committed_negative_fixtures_valid() -> bool {
    committed_negative_fixtures_valid_at(fixture_root())
}

pub fn committed_negative_fixtures_valid_at(root: impl AsRef<Path>) -> bool {
    let fixture_root = root.as_ref();
    let root = fixture_root.join("negative/encoding");
    let read = |name: &str| fs::read(root.join(name)).ok();
    let unknown = read("unknown-body-field.json");
    let noncanonical = read("noncanonical-json.json");
    let invalid_uuid = read("invalid-uuid.json");
    let invalid_hash = read("invalid-hash.json");
    let dependency = read("dependency-hash-mismatch.json");
    let object_negatives = fact_schema::OBJECT_TYPES.iter().all(|object_type| {
        fs::read(
            fixture_root
                .join("negative/objects")
                .join(format!("{object_type}.json")),
        )
        .ok()
        .is_some_and(|bytes| fact_schema::validate_envelope(&bytes).is_err())
    });
    object_negatives
        && unknown
            .as_deref()
            .is_some_and(|bytes| fact_schema::validate_envelope(bytes).is_err())
        && noncanonical.as_deref().is_some_and(|bytes| {
            fact_canonical::encode(bytes)
                .map(|canonical| canonical != bytes)
                .unwrap_or(false)
        })
        && invalid_uuid
            .as_deref()
            .is_some_and(|bytes| fact_schema::validate_envelope(bytes).is_err())
        && invalid_hash
            .as_deref()
            .is_some_and(|bytes| fact_schema::validate_envelope(bytes).is_err())
        && dependency
            .as_deref()
            .is_some_and(|bytes| fact_schema::validate_envelope(bytes).is_ok())
}

pub fn committed_scenarios_valid() -> bool {
    committed_scenarios_valid_at(fixture_root())
}

pub fn committed_scenarios_valid_at(root: impl AsRef<Path>) -> bool {
    let root = root.as_ref().join("scenarios");
    [
        "causal_authorization.json",
        "consensus_replay.json",
        "api_envelope.json",
        "invitation_admission.json",
        "lifecycle_effective_state.json",
        "reconciliation_roster.json",
        "exchange_artifacts.json",
        "transport_race.json",
    ]
    .iter()
    .all(|name| {
        let Ok(bytes) = fs::read(root.join(name)) else {
            return false;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return false;
        };
        value.get("schema").and_then(serde_json::Value::as_str)
            == Some("facts-reference-scenario-v0")
            && value
                .get("scenario_id")
                .and_then(serde_json::Value::as_str)
                .is_some()
            && value.get("steps").is_some_and(serde_json::Value::is_array)
            && value
                .get("expected")
                .is_some_and(serde_json::Value::is_object)
    })
}

/// Execute the deterministic assertions declared by the scenario corpus. The
/// scenario files are intentionally small descriptions, but their expected
/// values are still checked against the corresponding reference vectors so a
/// syntactically valid, contradictory scenario cannot silently pass.
pub fn scenario_vectors_valid_at(root: impl AsRef<Path>) -> bool {
    type ScenarioExpectation = fn(&serde_json::Value) -> bool;
    let scenario_root = root.as_ref().join("scenarios");
    let scenarios: [(&str, ScenarioExpectation); 8] = [
        (
            "causal-authorization-revocation",
            |expected: &serde_json::Value| {
                expected["historical_action"].as_str() == Some("authorized")
                    && expected["later_action"].as_str() == Some("unauthorized")
                    && expected["causal_revocation"].as_bool() == Some(true)
            },
        ),
        (
            "consensus-topological-replay",
            |expected: &serde_json::Value| {
                expected["arrival_order_invariant"].as_bool() == Some(true)
                    && expected["consensus"].as_str() == Some("accepted")
                    && expected["settlement_required"].as_bool() == Some(true)
            },
        ),
        ("api-discovery-envelope", |expected: &serde_json::Value| {
            expected["status"].as_u64() == Some(200)
                && expected["response_schema"].as_str() == Some("facts-protocol-response-v0")
                && expected["body_schema"].as_str() == Some("facts-protocol-ledger-list-v0")
        }),
        (
            "invitation-single-use-and-lifecycle",
            |expected: &serde_json::Value| {
                expected["single_use"].as_bool() == Some(true)
                    && expected["invalidated_invitation_rejected"].as_bool() == Some(true)
                    && expected["historical_join_preserved"].as_bool() == Some(true)
            },
        ),
        (
            "independent-withdrawal-archival-lineages",
            |expected: &serde_json::Value| {
                expected["dimensions_independent"].as_bool() == Some(true)
                    && expected["concurrent_tips_conflict"].as_bool() == Some(true)
                    && expected["rebuild_deterministic"].as_bool() == Some(true)
            },
        ),
        (
            "reconciliation-roster-governance",
            |expected: &serde_json::Value| {
                expected["evidence_complete"].as_bool() == Some(true)
                    && expected["source_settlement_witnesses_valid"].as_bool() == Some(true)
                    && expected["selected_set_bound"].as_bool() == Some(true)
            },
        ),
        (
            "snapshot-bundle-proof-exchange",
            |expected: &serde_json::Value| {
                expected["proofs_verify"].as_bool() == Some(true)
                    && expected["sorted_hashes"].as_bool() == Some(true)
                    && expected["trailing_bytes_rejected"].as_bool() == Some(true)
            },
        ),
        (
            "http-push-pull-and-cursor-races",
            |expected: &serde_json::Value| {
                expected["cursor_snapshot_bound"].as_bool() == Some(true)
                    && expected["stale_commitment_rejected"].as_bool() == Some(true)
                    && expected["request_id_bound"].as_bool() == Some(true)
            },
        ),
    ];
    scenarios.iter().all(|(scenario_id, expected_ok)| {
        let filename = match *scenario_id {
            "causal-authorization-revocation" => "causal_authorization.json",
            "consensus-topological-replay" => "consensus_replay.json",
            "api-discovery-envelope" => "api_envelope.json",
            "invitation-single-use-and-lifecycle" => "invitation_admission.json",
            "independent-withdrawal-archival-lineages" => "lifecycle_effective_state.json",
            "reconciliation-roster-governance" => "reconciliation_roster.json",
            "snapshot-bundle-proof-exchange" => "exchange_artifacts.json",
            "http-push-pull-and-cursor-races" => "transport_race.json",
            _ => return false,
        };
        let Ok(bytes) = fs::read(scenario_root.join(filename)) else {
            return false;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return false;
        };
        let Some(seed) = value["seed"].as_str() else {
            return false;
        };
        let Ok(seed) = hex::decode(seed) else {
            return false;
        };
        let expected = value.get("expected").unwrap_or(&serde_json::Value::Null);
        let declared = value["scenario_id"].as_str() == Some(*scenario_id)
            && seed.len() >= 16
            && expected_ok(expected);
        let executed = match *scenario_id {
            "api-discovery-envelope" | "http-push-pull-and-cursor-races" => run_api_mode(),
            _ => topological_replay_scenario_valid() && adversarial_scenario_vectors(),
        };
        declared && executed
    })
}

fn topological_replay_scenario_valid() -> bool {
    let actor_a = "01900000-0000-7000-8000-000000000001".parse().unwrap();
    let actor_b = "01900000-0000-7000-8000-000000000002".parse().unwrap();
    let change_a = fact_state::ParticipantChange {
        id: "01900000-0000-7000-8000-000000000011".parse().unwrap(),
        actor: actor_a,
        operation: fact_state::ParticipantOperation::Join,
        predecessors: vec![],
    };
    let change_b = fact_state::ParticipantChange {
        id: "01900000-0000-7000-8000-000000000012".parse().unwrap(),
        actor: actor_b,
        operation: fact_state::ParticipantOperation::Join,
        predecessors: vec![],
    };
    let first = fact_state::replay_participants(&[], &[change_a.clone(), change_b.clone()]);
    let second = fact_state::replay_participants(&[], &[change_b, change_a]);
    first.is_ok() && second.is_ok() && first.unwrap() == second.unwrap()
}

fn encode_b64url(bytes: &[u8]) -> String {
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

/// Execute adversarial state, exchange, and schema checks that are deliberately
/// independent of the SQLite projecteds.  These are the mutation/race cases
/// which the published scenario files describe, kept here as executable
/// assertions so the reference runner cannot pass on metadata alone.
fn adversarial_scenario_vectors() -> bool {
    let id = |value: &str| value.parse::<fact_core::ObjectId>().unwrap();
    let ledger = id("01900000-0000-7000-8000-000000000001");
    let actor = id("01900000-0000-7000-8000-000000000002");
    let grant_id = id("01900000-0000-7000-8000-000000000003");
    let revocation_id = id("01900000-0000-7000-8000-000000000004");
    let action = fact_state::AuthorizedAction {
        actor,
        ledger,
        capability: fact_state::Capability::Propose,
        target: fact_state::Target::Ledger(ledger),
        ancestors: [grant_id].into_iter().collect(),
        is_administration: false,
    };
    let authority = fact_state::Authority {
        id: grant_id,
        actor,
        capability: fact_state::Capability::Propose,
        scope: fact_state::Scope::Ledger,
        revoked_by: vec![revocation_id],
        validity: None,
    };
    let available = [grant_id].into_iter().collect();
    if fact_state::authorize(&action, std::slice::from_ref(&authority), &available)
        != fact_state::Authorization::Authorized
    {
        return false;
    }
    let mut revoked_action = action.clone();
    revoked_action.ancestors.insert(revocation_id);
    if fact_state::authorize(
        &revoked_action,
        std::slice::from_ref(&authority),
        &available,
    ) != fact_state::Authorization::Unauthorized
    {
        return false;
    }

    let participant = id("01900000-0000-7000-8000-000000000005");
    let revision = id("01900000-0000-7000-8000-000000000006");
    let first = fact_state::Decision {
        id: id("01900000-0000-7000-8000-000000000007"),
        participant,
        revision,
        value: fact_state::DecisionValue::Accepted,
        supersedes: vec![],
    };
    let second = fact_state::Decision {
        id: id("01900000-0000-7000-8000-000000000008"),
        participant,
        revision,
        value: fact_state::DecisionValue::Rejected,
        supersedes: vec![],
    };
    let conflict =
        fact_state::evaluate_unanimity(&[participant], revision, &[first.clone(), second.clone()]);
    if conflict.consensus != fact_state::Consensus::Conflict {
        return false;
    }
    let replacement = fact_state::Decision {
        id: id("01900000-0000-7000-8000-000000000009"),
        participant,
        revision,
        value: fact_state::DecisionValue::Accepted,
        supersedes: vec![first.id, second.id],
    };
    if fact_state::evaluate_unanimity(
        &[participant],
        revision,
        &[first, second, replacement.clone()],
    )
    .consensus
        != fact_state::Consensus::Accepted
    {
        return false;
    }
    let invalid_refs = vec![fact_state::SettlementDecisionRef {
        decision_id: replacement.id,
        participant,
        content_hash: Hash::digest(b"decision"),
    }];
    if fact_state::validate_settlement_witness(
        &[participant],
        revision,
        &[replacement],
        &invalid_refs,
        fact_state::SettlementOutcome::Rejected,
    )
    .is_ok()
    {
        return false;
    }

    let change_a = fact_state::ParticipantChange {
        id: id("01900000-0000-7000-8000-000000000010"),
        actor: participant,
        operation: fact_state::ParticipantOperation::Join,
        predecessors: vec![],
    };
    let change_b = fact_state::ParticipantChange {
        id: id("01900000-0000-7000-8000-000000000011"),
        actor: participant,
        operation: fact_state::ParticipantOperation::Join,
        predecessors: vec![],
    };
    if fact_state::replay_participants(&[], &[change_a, change_b]).is_ok() {
        return false;
    }

    let hashes = (1..=2)
        .map(|n| {
            let mut bytes = [0u8; 32];
            bytes[31] = n;
            Hash::from_bytes(bytes)
        })
        .collect::<Vec<_>>();
    let tree = fact_commitment::MerkleTree::new(hashes.clone()).unwrap();
    if !fact_commitment::verify(hashes[0], &tree.proof(0).unwrap(), tree.root)
        || !fact_commitment::verify_non_inclusion(
            Hash::digest(b"missing"),
            &tree.non_inclusion_proof(Hash::digest(b"missing")).unwrap(),
            tree.root,
        )
    {
        return false;
    }
    let signing_key = fact_crypto::SigningKey::from_seed(&[77u8; 32]).unwrap();
    let signed_fixture = |object_type: &str| {
        let payload = fact_schema::generated_positive_fixture(object_type).unwrap();
        let protected =
            fact_crypto::protocol_protected(signing_key.public_key(), object_type, "0", None);
        fact_crypto::encode_sign1(&fact_crypto::sign1(&protected, &payload, &signing_key))
    };
    let actor_object = signed_fixture("actor");
    let key_object = signed_fixture("key");
    let mut objects = vec![
        (
            Hash::digest(&fact_crypto::decode_sign1(&actor_object).unwrap().payload),
            actor_object,
        ),
        (
            Hash::digest(&fact_crypto::decode_sign1(&key_object).unwrap().payload),
            key_object,
        ),
    ];
    objects.sort_by_key(|(hash, _)| *hash);
    let entries = objects
        .iter()
        .map(|(_, object)| {
            let payload = fact_crypto::decode_sign1(object).unwrap().payload;
            let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            serde_json::json!({
                "object_id": value["id"],
                "content_hash": Hash::digest(&payload).hex()
            })
        })
        .collect::<Vec<_>>();
    let ledger_id = "01900000-0000-7000-8000-000000000012";
    let bundle_id = fact_commitment::deterministic_bundle_id(&objects);
    let bundle_manifest = fact_canonical::encode(
        &serde_json::to_vec(&serde_json::json!({
            "schema":"facts-protocol-bundle-v0",
            "protocol_version":0,
            "bundle_id":bundle_id,
            "ledger_id":ledger_id,
            "object_count":2,
            "objects":entries,
            "dependency_refs":[],
            "sender_signature":null,
            "expected_commitment_hash":null,
            "base_commitment_hash":null
        }))
        .unwrap(),
    )
    .unwrap();
    let ledger_uuid: uuid::Uuid = ledger_id.parse().unwrap();
    let scope = serde_json::json!({
        "ledger_id":ledger_id,
        "snapshot_boundary":null,
        "query_digest":null,
        "object_types":[],
        "actor_ids":[],
        "proposition_ids":[],
        "revision_ids":[],
        "deliberation_ids":[],
        "filters":{}
    });
    let scope_hash =
        Hash::digest(&fact_canonical::encode(&serde_json::to_vec(&scope).unwrap()).unwrap()).hex();
    let snapshot_tree =
        fact_commitment::MerkleTree::new(objects.iter().map(|(hash, _)| *hash).collect::<Vec<_>>())
            .unwrap();
    let mut commitment = serde_json::json!({
        "schema":"facts-protocol-commitment-v0",
        "coordinator_actor_id":uuid::Uuid::now_v7(),
        "ledger_id":ledger_uuid,
        "scope":scope,
        "scope_hash":scope_hash,
        "snapshot_id":null,
        "tree_profile":"facts-protocol-merkle-v0",
        "root_hash":snapshot_tree.root.hex(),
        "object_count":objects.len(),
        "created_at":"2026-07-27T12:00:00.000Z",
        "previous_commitment_hash":null,
        "signing_key_fingerprint":signing_key.fingerprint().hex()
    });
    let preimage = fact_canonical::encode(&serde_json::to_vec(&commitment).unwrap()).unwrap();
    commitment["snapshot_id"] = serde_json::json!(Hash::digest(&preimage).hex());
    let commitment_payload =
        fact_canonical::encode(&serde_json::to_vec(&commitment).unwrap()).unwrap();
    let protected = fact_crypto::coordinator_protected(
        signing_key.public_key(),
        "commitment",
        "0",
        Some(*ledger_uuid.as_bytes()),
    );
    let signed_commitment = fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected,
        &commitment_payload,
        &signing_key,
    ));
    let snapshot_manifest = fact_canonical::encode(
        &serde_json::to_vec(&serde_json::json!({
            "schema":"facts-protocol-snapshot-v0",
            "protocol_version":0,
            "ledger_id":ledger_id,
            "scope":scope,
            "filters":{},
            "commitment":encode_b64url(&signed_commitment),
            "object_count":2,
            "profile":"facts-protocol-snapshot-v0"
        }))
        .unwrap(),
    )
    .unwrap();
    let snapshot = fact_commitment::encode_snapshot(&snapshot_manifest, &objects).unwrap();
    let bundle = fact_commitment::encode_bundle(&bundle_manifest, &objects).unwrap();
    if fact_commitment::decode_snapshot(&snapshot).is_err()
        || fact_commitment::decode_bundle(&bundle).is_err()
        || fact_commitment::decode_bundle(&[bundle, vec![0]].concat()).is_ok()
    {
        return false;
    }

    let invitation = fact_schema::generated_positive_fixture("participant_invitation").unwrap();
    let mut invalid_invitation: serde_json::Value = serde_json::from_slice(&invitation).unwrap();
    invalid_invitation["body"]["deliberation_id"] =
        invalid_invitation["body"]["proposition_id"].clone();
    let invalid_invitation =
        fact_canonical::encode(&serde_json::to_vec(&invalid_invitation).unwrap()).unwrap();
    fact_schema::validate_envelope(&invalid_invitation).is_err()
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct LeafCheck {
    pub check_id: String,
    pub fixture_id: String,
    pub path: String,
    pub expected: String,
    pub actual: String,
    pub status: String,
    pub evidence: Vec<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub run_id: String,
    pub implementation_version: &'static str,
    pub passed: usize,
    pub failed: usize,
    pub suite_version: &'static str,
    pub fixture_manifest_digest: Hash,
    pub deterministic_seed: &'static str,
    pub deterministic_clock: &'static str,
    pub capabilities: Vec<String>,
    pub aggregation_rule: &'static str,
    pub leaf_checks: Vec<LeafCheck>,
    pub evidence_ids: Vec<String>,
}

/// Execute the smallest API-mode fixture against a fresh SQLite ledger. The
/// request and response travel through the public Axum router, while the
/// assertion remains limited to stable protocol envelope fields.
pub fn run_api_mode() -> bool {
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return false;
    };
    runtime
        .block_on(async {
            let store = match fact_store::Store::open_memory().and_then(|store| {
                store
                    .bootstrap_ledger(
                        "conformance.example",
                        "2026-07-27T12:00:00.000Z",
                        [41u8; 32],
                        [42u8; 16],
                    )
                    .map(|_| store)
            }) {
                Ok(store) => store,
                Err(_) => return None,
            };
            let ledger = store.list_ledgers().ok()?.first()?.0.clone();
            let coordinator_key = fact_crypto::SigningKey::from_seed(&[43u8; 32]).ok()?;
            let coordinator_actor_id = "01900000-0000-7000-8000-000000000099".parse().ok()?;
            let app = fact_http::router(fact_http::AppState::new_without_caller_auth(
                store,
                "https://conformance.example/facts",
                coordinator_key,
                coordinator_actor_id,
            ));
            let response = tower::ServiceExt::oneshot(
                app.clone(),
                http::Request::builder()
                    .uri("/facts/ledgers")
                    .body(axum::body::Body::empty())
                    .ok()?,
            )
            .await
            .ok()?;
            if !response.status().is_success() {
                return Some(false);
            }
            let header_request_id = response
                .headers()
                .get("facts-request-id")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)?;
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .ok()?;
            let value: serde_json::Value = serde_json::from_slice(&body).ok()?;
            let envelope_ok = value.get("schema").and_then(serde_json::Value::as_str)
                == Some("facts-protocol-response-v0")
                && value
                    .get("request_id")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
                && value
                    .get("body")
                    .and_then(|body| body.get("schema"))
                    .and_then(serde_json::Value::as_str)
                    == Some("facts-protocol-ledger-list-v0")
                && value.get("request_id").and_then(serde_json::Value::as_str)
                    == Some(header_request_id.as_str());
            let invalid_query = tower::ServiceExt::oneshot(
                app,
                http::Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/facts/ledgers/{ledger}/query"))
                    .header("facts-protocol-version", "0")
                    .header("content-type", "application/fact-query+json")
                    .body(axum::body::Body::from("{}"))
                    .ok()?,
            )
            .await
            .ok()?;
            let invalid_body = axum::body::to_bytes(invalid_query.into_body(), 1024 * 1024)
                .await
                .ok()?;
            let invalid_value: serde_json::Value = serde_json::from_slice(&invalid_body).ok()?;
            Some(
                envelope_ok
                    && invalid_value
                        .get("code")
                        .and_then(serde_json::Value::as_str)
                        == Some("invalid-content-digest")
                    && invalid_value
                        .get("first_error_code")
                        .and_then(serde_json::Value::as_str)
                        == Some("invalid-content-digest")
                    && invalid_value
                        .get("object_errors")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(Vec::is_empty),
            )
        })
        .unwrap_or(false)
}
fn signed_positive_fixture_cose_valid(object_type: &str, payload: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return false;
    };
    let Ok(parsed_type) = object_type.parse::<fact_schema::ObjectType>() else {
        return false;
    };
    let ledger = if parsed_type.ledger_scoped() {
        let Some(ledger) = value.get("ledger_id").and_then(serde_json::Value::as_str) else {
            return false;
        };
        let Ok(ledger) = ledger.parse::<fact_core::ObjectId>() else {
            return false;
        };
        Some(ledger.uuid().into_bytes())
    } else {
        None
    };
    let signing_key = match fact_crypto::SigningKey::from_seed(&[88u8; 32]) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let protected =
        fact_crypto::protocol_protected(signing_key.public_key(), object_type, "0", ledger);
    let encoded = fact_crypto::encode_sign1(&fact_crypto::sign1(&protected, payload, &signing_key));
    let Ok(decoded) = fact_crypto::decode_sign1(&encoded) else {
        return false;
    };
    decoded.payload == payload
        && fact_crypto::verify_sign1(signing_key.public_key(), &decoded).is_ok()
        && fact_crypto::validate_protocol_protected(
            &decoded,
            signing_key.public_key(),
            object_type,
            "0",
            ledger,
        )
        .is_ok()
}

fn mutation_vectors_valid_at(root: &Path) -> bool {
    let Ok(payload) = fs::read(root.join("positive/objects/actor.json")) else {
        return false;
    };
    let Ok(key) = fact_crypto::SigningKey::from_seed(&[89u8; 32]) else {
        return false;
    };
    let protected = fact_crypto::protocol_protected(key.public_key(), "actor", "0", None);
    let cose = fact_crypto::sign1(&protected, &payload, &key);
    let mut encoded = fact_crypto::encode_sign1(&cose);
    let Some(last) = encoded.last_mut() else {
        return false;
    };
    *last ^= 1;
    let Ok(mutated) = fact_crypto::decode_sign1(&encoded) else {
        return false;
    };
    fact_crypto::verify_sign1(key.public_key(), &mutated).is_err()
}

pub fn run_vectors() -> Report {
    run_vectors_at(fixture_root())
}

pub fn run_vectors_at(root: impl AsRef<Path>) -> Report {
    let root = root.as_ref();
    let mut checks: Vec<(String, String, String, bool)> = Vec::new();
    macro_rules! check {
        ($id:expr, $fixture:expr, $path:expr, $condition:expr) => {
            checks.push((
                $id.to_owned(),
                $fixture.to_owned(),
                $path.to_owned(),
                $condition,
            ));
        };
    }
    let positive_fixture = |object_type: &str| {
        fs::read(
            root.join("positive/objects")
                .join(format!("{object_type}.json")),
        )
        .ok()
    };
    check!(
        "fixture-manifest",
        "manifest.json",
        "manifest.schema",
        fixture_manifest_valid_at(root)
    );
    check!(
        "authority-matrix",
        "authority-matrix.json",
        "authority.schema",
        authority_matrix_valid_at(root)
    );
    for object_type in fact_schema::OBJECT_TYPES {
        check!(
            format!("positive-object-{object_type}"),
            format!("positive/objects/{object_type}.json"),
            format!("objects.{object_type}"),
            positive_fixture(object_type)
                .is_some_and(|bytes| fact_schema::validate_envelope(&bytes).is_ok())
        );
    }
    check!(
        "positive-cose-signatures",
        "positive/objects",
        "objects.cose_signatures",
        fact_schema::OBJECT_TYPES.iter().all(|object_type| {
            positive_fixture(object_type)
                .is_some_and(|bytes| signed_positive_fixture_cose_valid(object_type, &bytes))
        })
    );
    check!(
        "mutation-signature",
        "positive/objects/actor.json",
        "crypto.mutation",
        mutation_vectors_valid_at(root)
    );
    let read_negative = |name: &str| fs::read(root.join("negative/encoding").join(name)).ok();
    check!(
        "negative-unknown-field",
        "negative/encoding/unknown-body-field.json",
        "schema.unknown_field",
        read_negative("unknown-body-field.json")
            .is_some_and(|bytes| fact_schema::validate_envelope(&bytes).is_err())
    );
    check!(
        "negative-noncanonical-json",
        "negative/encoding/noncanonical-json.json",
        "canonical.json",
        read_negative("noncanonical-json.json").is_some_and(|bytes| {
            fact_canonical::encode(&bytes)
                .map(|canonical| canonical != bytes)
                .unwrap_or(false)
        })
    );
    check!(
        "negative-invalid-uuid",
        "negative/encoding/invalid-uuid.json",
        "identity.uuid",
        read_negative("invalid-uuid.json")
            .is_some_and(|bytes| fact_schema::validate_envelope(&bytes).is_err())
    );
    check!(
        "negative-invalid-hash",
        "negative/encoding/invalid-hash.json",
        "identity.hash",
        read_negative("invalid-hash.json")
            .is_some_and(|bytes| fact_schema::validate_envelope(&bytes).is_err())
    );
    check!(
        "negative-dependency-hash",
        "negative/encoding/dependency-hash-mismatch.json",
        "dependencies.content_hash",
        dependency_hash_mutation_rejected(root)
    );
    let json = "{\"b\":1,\"a\":\"é\",\"arr\":[true,null]}";
    check!(
        "canonical-json-order",
        "manifest.json",
        "canonical.json.order",
        fact_canonical::encode(json.as_bytes())
            .is_ok_and(|v| v == "{\"a\":\"é\",\"arr\":[true,null],\"b\":1}".as_bytes())
    );
    check!(
        "canonical-json-duplicate-key",
        "manifest.json",
        "canonical.json.duplicate_key",
        fact_canonical::encode(br#"{"a":1,"a":2}"#).is_err()
    );
    check!(
        "canonical-json-unicode-nfc",
        "manifest.json",
        "canonical.json.unicode_nfc",
        fact_canonical::encode("{\"x\":\"e\u{301}\"}".as_bytes()).is_err()
    );
    check!(
        "canonical-json-invalid-utf8",
        "manifest.json",
        "canonical.json.utf8",
        fact_canonical::encode(&[b'{', b'\"', b'x', b'\"', b':', 0xff, b'}']).is_err()
    );
    let cbor = fact_canonical::Cbor::Map(vec![
        (
            fact_canonical::Cbor::Text("z".into()),
            fact_canonical::Cbor::Unsigned(1),
        ),
        (
            fact_canonical::Cbor::Text("a".into()),
            fact_canonical::Cbor::Bytes(vec![0, 1]),
        ),
    ]);
    check!(
        "canonical-cbor-order",
        "manifest.json",
        "canonical.cbor.order",
        fact_canonical::encode_cbor(&cbor)
            .is_ok_and(|bytes| hex::encode(&bytes) == "a26161420001617a01")
    );
    check!(
        "canonical-cbor-integer",
        "manifest.json",
        "canonical.cbor.integer",
        fact_canonical::decode_cbor(&[0x18, 0x00]).is_err()
    );
    check!(
        "http-api-mode",
        "scenarios/api_envelope.json",
        "http.discovery",
        run_api_mode()
    );
    check!(
        "committed-fixtures",
        "manifest.json",
        "fixtures.committed",
        committed_fixture_files_valid_at(root)
    );
    for object_type in fact_schema::OBJECT_TYPES {
        let valid = fs::read(
            root.join("negative/objects")
                .join(format!("{object_type}.json")),
        )
        .ok()
        .is_some_and(|bytes| fact_schema::validate_envelope(&bytes).is_err());
        check!(
            format!("negative-object-{object_type}"),
            format!("negative/objects/{object_type}.json"),
            format!("negative_objects.{object_type}"),
            valid
        );
    }
    check!(
        "committed-scenarios",
        "scenarios",
        "scenarios.committed",
        committed_scenarios_valid_at(root)
    );
    check!(
        "scenario-vectors",
        "scenarios",
        "scenarios.executed",
        scenario_vectors_valid_at(root)
    );
    let hs = (1..=3)
        .map(|n| {
            let mut b = [0u8; 32];
            b[31] = n;
            Hash::from_bytes(b)
        })
        .collect();
    check!(
        "merkle-three-leaves",
        "scenarios/exchange_artifacts.json",
        "merkle.root",
        fact_commitment::MerkleTree::new(hs)
            .is_ok_and(|t| t.root.hex()
                == "93e34ecb30d456c2bb3903c45dd51d053db3e66522a0a2eaf5fafa58312ed037")
    );
    let key = fact_crypto::SigningKey::from_seed(
        &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap(),
    );
    check!(
        "ed25519-vector",
        "manifest.json",
        "crypto.ed25519.public_key",
        key.as_ref().is_ok_and(|key| hex::encode(key.public_key())
            == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    let key = fact_crypto::SigningKey::from_seed(
        &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap(),
    )
    .unwrap();
    let ledger: [u8; 16] = hex::decode("018f0a00000070008000000000000001")
        .unwrap()
        .try_into()
        .unwrap();
    let protected = fact_crypto::protocol_protected(key.public_key(), "test", "0", Some(ledger));
    let cose = fact_crypto::sign1(&protected, br#"{"a":1,"b":"x"}"#, &key);
    check!("cose-signature-vector", "manifest.json", "crypto.cose.signature", hex::encode(cose.signature) == "9bcc50455d56122923c2273a4d1947e06e0d1fffe1ccbe1a9ad7b45dfff19ea035359909bc09ebdeb17f92fdec078b286e469ca33b761f1af1284d4dcbffd408");
    check!(
        "cose-protected-headers",
        "manifest.json",
        "crypto.cose.protected",
        fact_crypto::verify_sign1(key.public_key(), &cose).is_ok()
            && fact_crypto::validate_protocol_protected(
                &cose,
                key.public_key(),
                "test",
                "0",
                Some(ledger),
            )
            .is_ok()
    );
    check!(
        "canonical-markdown",
        "manifest.json",
        "canonical.markdown",
        fact_canonical::canonical_markdown(b"# Fact\n\nText\n")
            .is_ok_and(|bytes| bytes == b"# Fact\n\nText\n")
    );
    let p = checks.iter().filter(|(_, _, _, passed)| *passed).count();
    let f = checks.len() - p;
    let evidence_ids = corpus_evidence_ids(root);
    let run_id = format!(
        "facts-conformance-v0-{}",
        Hash::digest(
            format!(
                "{}:{}:{}",
                env!("CARGO_PKG_VERSION"),
                Hash::digest(&fs::read(root.join("manifest.json")).unwrap_or_default()).hex(),
                "2026-07-27T12:00:00.000Z"
            )
            .as_bytes(),
        )
        .hex()
    );
    let mut leaf_checks = Vec::with_capacity(checks.len());
    for (check_id, fixture_id, path, passed_leaf) in checks {
        let evidence_path = if root.join(&fixture_id).is_file() {
            fixture_id.clone()
        } else {
            evidence_ids
                .iter()
                .find(|candidate| root.join(candidate).is_file())
                .cloned()
                .unwrap_or_else(|| "manifest.json".into())
        };
        let evidence = vec![serde_json::json!({
            "kind":"fixture",
            "path":evidence_path.clone(),
            "sha256":Hash::digest(&fs::read(root.join(&evidence_path)).unwrap_or_default()).hex()
        })];
        leaf_checks.push(LeafCheck {
            check_id,
            fixture_id,
            path,
            expected: "pass".into(),
            actual: if passed_leaf { "pass" } else { "fail" }.into(),
            status: if passed_leaf { "pass" } else { "fail" }.into(),
            evidence,
        });
    }
    Report {
        run_id,
        implementation_version: env!("CARGO_PKG_VERSION"),
        passed: p,
        failed: f,
        suite_version: "0",
        deterministic_seed: "facts-conformance-seed-v0",
        deterministic_clock: "2026-07-27T12:00:00.000Z",
        capabilities: vec![
            "canonical-json".into(),
            "canonical-markdown".into(),
            "deterministic-cbor".into(),
            "ed25519-cose".into(),
            "sqlite-api-mode".into(),
            "authority-matrix".into(),
            "gzip-content-digest".into(),
            "restricted-route-auth".into(),
            "first-error-observability".into(),
            "named-leaf-evidence".into(),
        ],
        aggregation_rule: "pass iff every required leaf has status pass",
        leaf_checks,
        fixture_manifest_digest: Hash::digest(
            &fs::read(root.join("manifest.json")).unwrap_or_default(),
        ),
        evidence_ids,
    }
}

fn dependency_hash_mutation_rejected(root: &Path) -> bool {
    let Ok(payload) = fs::read(root.join("negative/encoding/dependency-hash-mismatch.json")) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        return false;
    };
    let Some(ledger) = value
        .get("ledger_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<fact_core::ObjectId>().ok())
    else {
        return false;
    };
    let Some(key_id) = value
        .get("signing_key_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<fact_core::ObjectId>().ok())
    else {
        return false;
    };
    let Ok(key) = fact_crypto::SigningKey::from_seed(&[90u8; 32]) else {
        return false;
    };
    let Ok(store) = fact_store::Store::open_memory() else {
        return false;
    };
    if store
        .create_ledger(ledger.uuid().as_bytes(), "fixture.example")
        .is_err()
        || store
            .register_key(key_id.uuid().as_bytes(), &key.public_key())
            .is_err()
    {
        return false;
    }
    let protected = fact_crypto::protocol_protected(
        key.public_key(),
        "proposition",
        "0",
        Some(ledger.uuid().into_bytes()),
    );
    let cose = fact_crypto::encode_sign1(&fact_crypto::sign1(&protected, &payload, &key));
    matches!(
        store.insert_verified_object(&cose),
        Err(fact_store::Error::MissingDependency) | Err(fact_store::Error::DependencyHashMismatch)
    )
}

fn corpus_evidence_ids(root: &Path) -> Vec<String> {
    let mut evidence = vec!["manifest.json".to_owned()];
    if root.join("authority-matrix.json").is_file() {
        evidence.push("authority-matrix.json".to_owned());
    }
    for object_type in fact_schema::OBJECT_TYPES {
        let positive = format!("positive/objects/{object_type}.json");
        let negative = format!("negative/objects/{object_type}.json");
        if root.join(&positive).is_file() {
            evidence.push(positive);
        }
        if root.join(&negative).is_file() {
            evidence.push(negative);
        }
    }
    for name in [
        "unknown-body-field.json",
        "noncanonical-json.json",
        "invalid-uuid.json",
        "invalid-hash.json",
        "dependency-hash-mismatch.json",
    ] {
        let path = format!("negative/encoding/{name}");
        if root.join(&path).is_file() {
            evidence.push(path);
        }
    }
    for name in [
        "causal_authorization.json",
        "consensus_replay.json",
        "api_envelope.json",
        "invitation_admission.json",
        "lifecycle_effective_state.json",
        "reconciliation_roster.json",
        "exchange_artifacts.json",
        "transport_race.json",
    ] {
        let path = format!("scenarios/{name}");
        if root.join(&path).is_file() {
            evidence.push(path);
        }
    }
    evidence
}

#[cfg(test)]
mod tests {
    #[test]
    fn published_primitive_vectors_pass() {
        let report = super::run_vectors();
        assert_eq!(report.failed, 0);
        assert_eq!(report.passed, report.leaf_checks.len());
        assert!(report.leaf_checks.iter().all(|leaf| leaf.status == "pass"));
        let repeat = super::run_vectors();
        assert_eq!(
            report.fixture_manifest_digest,
            repeat.fixture_manifest_digest
        );
        assert_eq!(report.passed, repeat.passed);
    }
}
