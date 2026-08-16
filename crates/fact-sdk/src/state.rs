//! Local projected rebuild helpers.

use crate::Result;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct StateRebuildResult {
    pub rebuilt: bool,
    pub deliberations: usize,
    pub effective_propositions: usize,
}

pub fn rebuild_state_at(path: impl AsRef<Path>) -> Result<StateRebuildResult> {
    let store = fact_store::Store::open(path)?;
    rebuild_state(&store)
}

pub fn rebuild_state(store: &fact_store::Store) -> Result<StateRebuildResult> {
    store.rebuild_projecteds()?;
    Ok(StateRebuildResult {
        rebuilt: true,
        deliberations: store.count_consensus_projecteds()?,
        effective_propositions: store.count_effective_projecteds()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{create_ledger, BootstrapLedgerInput};

    #[test]
    fn rebuild_state_reports_projected_counts() {
        let store = fact_store::Store::open_memory().unwrap();
        create_ledger(
            &store,
            BootstrapLedgerInput {
                namespace: "local.state-sdk-test".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed: [121; 32],
                nonce: [122; 16],
            },
        )
        .unwrap();
        fact_store::Store::reset_debug_metrics();
        let result = rebuild_state(&store).unwrap();
        assert!(result.rebuilt);
        assert_eq!(result.deliberations, 0);
        assert_eq!(result.effective_propositions, 0);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.projected_rebuilds, 1);
        assert_eq!(metrics.list_effective_state, 0);
    }
}
