//! Conformance runner and fixture materialization helpers.

use crate::Result;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ConformanceLeafCheck {
    pub check_id: String,
    pub fixture_id: String,
    pub path: String,
    pub expected: String,
    pub actual: String,
    pub status: String,
    pub evidence: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ConformanceReport {
    pub run_id: String,
    pub implementation_version: String,
    pub passed: usize,
    pub failed: usize,
    pub status: String,
    pub suite_version: String,
    pub fixture_manifest_digest: String,
    pub deterministic_seed: String,
    pub deterministic_clock: String,
    pub capabilities: Vec<String>,
    pub aggregation_rule: String,
    pub leaf_checks: Vec<ConformanceLeafCheck>,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MaterializeConformanceResult {
    pub materialized: bool,
    pub path: PathBuf,
}

/// Run the protocol conformance vector suite.
pub fn run_conformance(path: Option<&Path>) -> ConformanceReport {
    let report = path.map_or_else(
        fact_conformance::run_vectors,
        fact_conformance::run_vectors_at,
    );
    ConformanceReport {
        run_id: report.run_id,
        implementation_version: report.implementation_version.to_owned(),
        passed: report.passed,
        failed: report.failed,
        status: if report.failed == 0 { "pass" } else { "fail" }.to_owned(),
        suite_version: report.suite_version.to_owned(),
        fixture_manifest_digest: report.fixture_manifest_digest.hex(),
        deterministic_seed: report.deterministic_seed.to_owned(),
        deterministic_clock: report.deterministic_clock.to_owned(),
        capabilities: report.capabilities,
        aggregation_rule: report.aggregation_rule.to_owned(),
        leaf_checks: report
            .leaf_checks
            .into_iter()
            .map(|check| ConformanceLeafCheck {
                check_id: check.check_id,
                fixture_id: check.fixture_id,
                path: check.path,
                expected: check.expected,
                actual: check.actual,
                status: check.status,
                evidence: check.evidence,
            })
            .collect(),
        evidence_ids: report.evidence_ids,
    }
}

/// Materialize the conformance fixture corpus under `path`.
pub fn materialize_conformance(path: impl AsRef<Path>) -> Result<MaterializeConformanceResult> {
    let path = path.as_ref();
    fact_conformance::materialize_fixtures(path)
        .map_err(|error| crate::Error::Validation(error.to_string()))?;
    Ok(MaterializeConformanceResult {
        materialized: true,
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance_report_is_serializable_and_passing() {
        let report = run_conformance(None);

        assert_eq!(report.status, "pass");
        assert_eq!(report.failed, 0);
        assert_eq!(report.leaf_checks.len(), report.passed);
        assert!(serde_json::to_value(&report).unwrap()["fixture_manifest_digest"].is_string());
    }

    #[test]
    fn materialize_conformance_writes_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let result = materialize_conformance(dir.path()).unwrap();

        assert!(result.materialized);
        assert_eq!(result.path, dir.path());
        assert!(dir.path().join("manifest.json").is_file());
    }
}
