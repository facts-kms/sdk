//! Commitment and proof helpers.

use crate::Result;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CommitmentResult {
    pub root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CommitmentVerificationResult {
    pub valid: bool,
    pub root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct InclusionProofStep {
    pub sibling: String,
    pub sibling_left: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct InclusionProofResult {
    pub proof_type: String,
    pub root: String,
    pub target: String,
    pub index: usize,
    pub steps: Vec<InclusionProofStep>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct NonInclusionProofResult {
    pub proof_type: String,
    pub root: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right: Option<String>,
}

pub fn create_commitment(hashes: Vec<fact_core::Hash>) -> Result<CommitmentResult> {
    let tree = fact_commitment::MerkleTree::new(hashes)?;
    Ok(CommitmentResult {
        root: tree.root.hex(),
    })
}

pub fn verify_commitment(
    hashes: Vec<fact_core::Hash>,
    expected: fact_core::Hash,
) -> Result<CommitmentVerificationResult> {
    let tree = fact_commitment::MerkleTree::new(hashes)?;
    Ok(CommitmentVerificationResult {
        valid: tree.root == expected,
        root: tree.root.hex(),
    })
}

pub fn create_inclusion_proof(
    hashes: Vec<fact_core::Hash>,
    target: fact_core::Hash,
) -> Result<InclusionProofResult> {
    let tree = fact_commitment::MerkleTree::new(hashes)?;
    let index = tree
        .leaves
        .iter()
        .position(|hash| *hash == target)
        .ok_or_else(|| crate::Error::MissingObject("target hash is not present".into()))?;
    let steps = tree
        .proof(index)?
        .into_iter()
        .map(|step| InclusionProofStep {
            sibling: step.sibling.hex(),
            sibling_left: step.sibling_left,
        })
        .collect();
    Ok(InclusionProofResult {
        proof_type: "inclusion".into(),
        root: tree.root.hex(),
        target: target.hex(),
        index,
        steps,
    })
}

pub fn create_non_inclusion_proof(
    hashes: Vec<fact_core::Hash>,
    target: fact_core::Hash,
) -> Result<NonInclusionProofResult> {
    let tree = fact_commitment::MerkleTree::new(hashes)?;
    let proof = tree.non_inclusion_proof(target)?;
    Ok(NonInclusionProofResult {
        proof_type: "non-inclusion".into(),
        root: tree.root.hex(),
        target: target.hex(),
        left: proof.left.as_ref().map(|(hash, _)| hash.hex()),
        right: proof.right.as_ref().map(|(hash, _)| hash.hex()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_and_proofs_are_stable() {
        let hashes = ["00".repeat(32), "11".repeat(32), "33".repeat(32)]
            .into_iter()
            .map(|value| value.parse::<fact_core::Hash>().unwrap())
            .collect::<Vec<_>>();
        let commitment = create_commitment(hashes.clone()).unwrap();
        let expected = commitment.root.parse::<fact_core::Hash>().unwrap();
        assert!(verify_commitment(hashes.clone(), expected).unwrap().valid);

        let inclusion = create_inclusion_proof(hashes.clone(), hashes[1]).unwrap();
        assert_eq!(inclusion.proof_type, "inclusion");
        assert_eq!(inclusion.index, 1);
        assert!(!inclusion.steps.is_empty());

        let missing = "22".repeat(32).parse::<fact_core::Hash>().unwrap();
        let exclusion = create_non_inclusion_proof(hashes, missing).unwrap();
        assert_eq!(exclusion.proof_type, "non-inclusion");
        assert!(exclusion.left.is_some() || exclusion.right.is_some());
    }
}
