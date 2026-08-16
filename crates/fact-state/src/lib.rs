use fact_core::{Hash, ObjectId};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionValue {
    Accepted,
    Rejected,
}
#[derive(Clone, Debug)]
pub struct Decision {
    pub id: ObjectId,
    pub participant: ObjectId,
    pub revision: ObjectId,
    pub value: DecisionValue,
    pub supersedes: Vec<ObjectId>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParticipantResult {
    Accepted,
    Rejected,
    Undecided,
    Conflict,
    Divergent,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consensus {
    Accepted,
    Rejected,
    Undecided,
    Conflict,
    Divergent,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub consensus: Consensus,
    pub participants: HashMap<ObjectId, ParticipantResult>,
    pub applicable_decisions: Vec<ObjectId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementDecisionRef {
    pub decision_id: ObjectId,
    pub participant: ObjectId,
    pub content_hash: Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementOutcome {
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementWitnessError {
    EmptyParticipants,
    DuplicateParticipant,
    DuplicateDecision,
    MissingDecision,
    ExtraDecision,
    ParticipantMismatch,
    CountMismatch,
    InvalidOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParticipantOperation {
    Join,
    Leave,
}

#[derive(Clone, Debug)]
pub struct ParticipantChange {
    pub id: ObjectId,
    pub actor: ObjectId,
    pub operation: ParticipantOperation,
    pub predecessors: Vec<ObjectId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantState {
    pub active: HashSet<ObjectId>,
    pub tips: HashMap<ObjectId, HashSet<ObjectId>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParticipantReplayError {
    DuplicateInitial,
    DuplicateChange,
    UnknownPredecessor,
    InvalidTransition,
    ConflictingTip,
    CyclicChanges,
}

/// Replay membership changes by causal predecessors rather than input order.
/// Each change must name every current tip for its actor; concurrent same-actor
/// changes therefore remain an explicit conflict instead of being ordered by
/// timestamps or object IDs.
pub fn replay_participants(
    initial: &[ObjectId],
    changes: &[ParticipantChange],
) -> Result<ParticipantState, ParticipantReplayError> {
    let mut active = HashSet::new();
    for actor in initial {
        if !active.insert(*actor) {
            return Err(ParticipantReplayError::DuplicateInitial);
        }
    }
    let mut all_ids = HashSet::new();
    for change in changes {
        if !all_ids.insert(change.id) {
            return Err(ParticipantReplayError::DuplicateChange);
        }
    }
    let mut processed = HashSet::new();
    let mut tips: HashMap<ObjectId, HashSet<ObjectId>> = HashMap::new();
    while processed.len() < changes.len() {
        let mut progress = false;
        for change in changes {
            if processed.contains(&change.id) {
                continue;
            }
            if change
                .predecessors
                .iter()
                .any(|id| !all_ids.contains(id) || !processed.contains(id))
            {
                continue;
            }
            let current = tips.get(&change.actor).cloned().unwrap_or_default();
            let predecessors: HashSet<_> = change.predecessors.iter().copied().collect();
            if predecessors != current {
                return Err(ParticipantReplayError::ConflictingTip);
            }
            let is_active = active.contains(&change.actor);
            match change.operation {
                ParticipantOperation::Join if is_active => {
                    return Err(ParticipantReplayError::InvalidTransition)
                }
                ParticipantOperation::Leave if !is_active => {
                    return Err(ParticipantReplayError::InvalidTransition)
                }
                ParticipantOperation::Join => {
                    active.insert(change.actor);
                }
                ParticipantOperation::Leave => {
                    active.remove(&change.actor);
                }
            }
            let mut new_tips = HashSet::new();
            new_tips.insert(change.id);
            tips.insert(change.actor, new_tips);
            processed.insert(change.id);
            progress = true;
        }
        if !progress {
            if changes
                .iter()
                .any(|change| change.predecessors.iter().any(|id| !all_ids.contains(id)))
            {
                return Err(ParticipantReplayError::UnknownPredecessor);
            }
            return Err(ParticipantReplayError::CyclicChanges);
        }
    }
    Ok(ParticipantState { active, tips })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    Propose,
    Deliberate,
    Invite,
    Comment,
    Accept,
    Reject,
    Withdraw,
    Archive,
    Admin,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Ledger,
    Namespace(String),
    Proposition(ObjectId),
    Revision(ObjectId),
    RevisionIn {
        revision: ObjectId,
        proposition: ObjectId,
    },
    Deliberation(ObjectId),
    DeliberationIn {
        deliberation: ObjectId,
        proposition: ObjectId,
        revision: ObjectId,
    },
    Actor(ObjectId),
    CapabilityClass(Capability),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Ledger(ObjectId),
    Namespace(String),
    Proposition {
        ledger: ObjectId,
        proposition: ObjectId,
    },
    Revision {
        ledger: ObjectId,
        proposition: ObjectId,
        revision: ObjectId,
    },
    Deliberation {
        ledger: ObjectId,
        proposition: ObjectId,
        revision: ObjectId,
        deliberation: ObjectId,
    },
    Actor {
        ledger: ObjectId,
        actor: ObjectId,
    },
    Administration {
        ledger: ObjectId,
        capability: Capability,
    },
}
#[derive(Clone, Debug)]
pub struct Authority {
    pub id: ObjectId,
    pub actor: ObjectId,
    pub capability: Capability,
    pub scope: Scope,
    pub revoked_by: Vec<ObjectId>,
    pub validity: Option<ValidityWindow>,
}

#[derive(Clone, Debug)]
pub struct Delegation {
    pub id: ObjectId,
    pub delegator: ObjectId,
    pub delegatee: ObjectId,
    pub capability: Capability,
    pub scope: Scope,
    pub parent_delegation_id: Option<ObjectId>,
    pub redelegable: bool,
    pub revoked_by: Vec<ObjectId>,
    pub validity: Option<ValidityWindow>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedTime {
    pub now_millis: i64,
    pub uncertainty_millis: i64,
}
impl TrustedTime {
    pub fn new(now_millis: i64, uncertainty_millis: i64) -> Self {
        Self {
            now_millis,
            uncertainty_millis,
        }
    }
    pub fn system() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self::new(now.as_millis() as i64, 300_000)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidityWindow {
    pub valid_from_millis: Option<i64>,
    pub expires_at_millis: Option<i64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporalStatus {
    Unbounded,
    Active,
    NotYetValid,
    Expired,
    TimeUncertain,
}
pub fn evaluate_validity(
    window: Option<&ValidityWindow>,
    time: Option<TrustedTime>,
) -> TemporalStatus {
    let Some(window) = window else {
        return TemporalStatus::Unbounded;
    };
    let Some(time) = time else {
        return TemporalStatus::TimeUncertain;
    };
    let d = time.uncertainty_millis.max(0);
    if let Some(from) = window.valid_from_millis {
        if time.now_millis < from.saturating_sub(d) {
            return TemporalStatus::NotYetValid;
        }
        if time.now_millis <= from.saturating_add(d) {
            return TemporalStatus::TimeUncertain;
        }
    }
    if let Some(to) = window.expires_at_millis {
        if time.now_millis >= to.saturating_add(d) {
            return TemporalStatus::Expired;
        }
        if time.now_millis >= to.saturating_sub(d) {
            return TemporalStatus::TimeUncertain;
        }
    }
    TemporalStatus::Active
}
#[derive(Clone, Debug)]
pub struct AuthorizedAction {
    pub actor: ObjectId,
    pub ledger: ObjectId,
    pub capability: Capability,
    pub target: Target,
    pub ancestors: HashSet<ObjectId>,
    pub is_administration: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authorization {
    Authorized,
    Unauthorized,
    DependencyBlocked,
    Conflict,
    TimeUncertain,
}

pub fn scope_contains(
    scope: &Scope,
    target: &Target,
    ledger: ObjectId,
    is_administration: bool,
) -> bool {
    if !target_ledger_matches(target, ledger) {
        return false;
    }
    match (scope, target) {
        (Scope::Ledger, Target::Ledger(l)) => *l == ledger,
        (Scope::Ledger, Target::Namespace(_)) => true,
        (Scope::Ledger, Target::Proposition { ledger: l, .. }) => *l == ledger,
        (Scope::Ledger, Target::Revision { ledger: l, .. }) => *l == ledger,
        (Scope::Ledger, Target::Deliberation { ledger: l, .. }) => *l == ledger,
        (Scope::Ledger, Target::Actor { ledger: l, .. }) => *l == ledger,
        (Scope::Ledger, Target::Administration { ledger: l, .. }) => *l == ledger,
        (Scope::Namespace(a), Target::Namespace(b)) => a == b,
        (
            Scope::Namespace(_),
            Target::Proposition { .. }
            | Target::Revision { .. }
            | Target::Deliberation { .. }
            | Target::Actor { .. }
            | Target::Ledger(_)
            | Target::Administration { .. },
        ) => false,
        (Scope::Proposition(p), Target::Proposition { proposition, .. }) => p == proposition,
        (
            Scope::Proposition(p),
            Target::Revision { proposition, .. } | Target::Deliberation { proposition, .. },
        ) => p == proposition,
        (Scope::Revision(r), Target::Revision { revision, .. })
        | (Scope::RevisionIn { revision: r, .. }, Target::Revision { revision, .. }) => {
            r == revision
        }
        (Scope::Revision(r), Target::Deliberation { revision, .. })
        | (Scope::RevisionIn { revision: r, .. }, Target::Deliberation { revision, .. }) => {
            r == revision
        }
        (Scope::Deliberation(d), Target::Deliberation { deliberation, .. })
        | (
            Scope::DeliberationIn {
                deliberation: d, ..
            },
            Target::Deliberation { deliberation, .. },
        ) => d == deliberation,
        (Scope::Actor(a), Target::Actor { actor, .. }) => a == actor,
        (Scope::CapabilityClass(a), Target::Administration { capability, .. }) => {
            is_administration && a == capability
        }
        _ => false,
    }
}
fn target_ledger_matches(target: &Target, ledger: ObjectId) -> bool {
    match target {
        Target::Ledger(l) => *l == ledger,
        Target::Namespace(_) => true,
        Target::Proposition { ledger: l, .. }
        | Target::Revision { ledger: l, .. }
        | Target::Deliberation { ledger: l, .. }
        | Target::Actor { ledger: l, .. }
        | Target::Administration { ledger: l, .. } => *l == ledger,
    }
}
pub fn authorize(
    action: &AuthorizedAction,
    authorities: &[Authority],
    available: &HashSet<ObjectId>,
) -> Authorization {
    authorize_at(action, authorities, available, None)
}

pub fn authorize_at(
    action: &AuthorizedAction,
    authorities: &[Authority],
    available: &HashSet<ObjectId>,
    trusted_time: Option<TrustedTime>,
) -> Authorization {
    let mut found = false;
    let mut time_uncertain = false;
    for authority in authorities {
        if !available.contains(&authority.id)
            || !action.ancestors.contains(&authority.id)
            || authority.actor != action.actor
            || authority.capability != action.capability
            || !scope_contains(
                &authority.scope,
                &action.target,
                action.ledger,
                action.is_administration,
            )
        {
            continue;
        }
        match evaluate_validity(authority.validity.as_ref(), trusted_time) {
            TemporalStatus::Active | TemporalStatus::Unbounded => {}
            TemporalStatus::TimeUncertain => {
                time_uncertain = true;
                continue;
            }
            TemporalStatus::NotYetValid | TemporalStatus::Expired => continue,
        }
        if authority
            .revoked_by
            .iter()
            .any(|r| action.ancestors.contains(r))
        {
            continue;
        }
        found = true;
    }
    if found {
        Authorization::Authorized
    } else if authorities
        .iter()
        .any(|a| !available.contains(&a.id) && action.ancestors.contains(&a.id))
    {
        Authorization::DependencyBlocked
    } else if time_uncertain {
        Authorization::TimeUncertain
    } else {
        Authorization::Unauthorized
    }
}

/// Evaluate direct grants and explicit delegation chains at one causal point.
/// Delegations never widen capability or scope, and a later revocation is
/// irrelevant unless the revocation itself is in the action's closure.
pub fn authorize_with_delegations(
    action: &AuthorizedAction,
    authorities: &[Authority],
    delegations: &[Delegation],
    available: &HashSet<ObjectId>,
) -> Authorization {
    authorize_with_delegations_at(action, authorities, delegations, available, None)
}

pub fn authorize_with_delegations_at(
    action: &AuthorizedAction,
    authorities: &[Authority],
    delegations: &[Delegation],
    available: &HashSet<ObjectId>,
    trusted_time: Option<TrustedTime>,
) -> Authorization {
    let mut matches = 0usize;
    let mut time_uncertain = false;
    for authority in authorities {
        if available.contains(&authority.id)
            && action.ancestors.contains(&authority.id)
            && authority.actor == action.actor
            && authority.capability == action.capability
            && scope_contains(
                &authority.scope,
                &action.target,
                action.ledger,
                action.is_administration,
            )
            && !authority
                .revoked_by
                .iter()
                .any(|id| action.ancestors.contains(id))
        {
            match evaluate_validity(authority.validity.as_ref(), trusted_time) {
                TemporalStatus::Active | TemporalStatus::Unbounded => {}
                TemporalStatus::TimeUncertain => {
                    time_uncertain = true;
                    continue;
                }
                TemporalStatus::NotYetValid | TemporalStatus::Expired => continue,
            }
            matches += 1;
        }
    }
    for delegation in delegations {
        let mut visiting = HashSet::new();
        if delegation.delegatee == action.actor
            && delegation.capability == action.capability
            && scope_contains(
                &delegation.scope,
                &action.target,
                action.ledger,
                action.is_administration,
            )
            && delegation_chain_valid(
                delegation,
                delegations,
                authorities,
                available,
                &action.ancestors,
                &mut visiting,
                trusted_time,
                &mut time_uncertain,
            )
        {
            matches += 1;
        }
    }
    if matches > 0 {
        Authorization::Authorized
    } else if authorities.iter().any(|authority| {
        action.ancestors.contains(&authority.id) && !available.contains(&authority.id)
    }) || delegations.iter().any(|delegation| {
        action.ancestors.contains(&delegation.id) && !available.contains(&delegation.id)
    }) {
        Authorization::DependencyBlocked
    } else if time_uncertain {
        Authorization::TimeUncertain
    } else {
        Authorization::Unauthorized
    }
}

#[allow(clippy::too_many_arguments)]
fn delegation_chain_valid(
    delegation: &Delegation,
    delegations: &[Delegation],
    authorities: &[Authority],
    available: &HashSet<ObjectId>,
    ancestors: &HashSet<ObjectId>,
    visiting: &mut HashSet<ObjectId>,
    trusted_time: Option<TrustedTime>,
    time_uncertain: &mut bool,
) -> bool {
    if !available.contains(&delegation.id)
        || !ancestors.contains(&delegation.id)
        || delegation
            .revoked_by
            .iter()
            .any(|id| ancestors.contains(id))
        || !visiting.insert(delegation.id)
    {
        return false;
    }
    match evaluate_validity(delegation.validity.as_ref(), trusted_time) {
        TemporalStatus::Active | TemporalStatus::Unbounded => {}
        TemporalStatus::TimeUncertain => {
            *time_uncertain = true;
            return false;
        }
        TemporalStatus::NotYetValid | TemporalStatus::Expired => return false,
    }
    let valid = if let Some(parent_id) = delegation.parent_delegation_id {
        let Some(parent) = delegations
            .iter()
            .find(|candidate| candidate.id == parent_id)
        else {
            return false;
        };
        parent.redelegable
            && parent.delegatee == delegation.delegator
            && parent.capability == delegation.capability
            && scope_contains_scope(&parent.scope, &delegation.scope)
            && delegation_chain_valid(
                parent,
                delegations,
                authorities,
                available,
                ancestors,
                visiting,
                trusted_time,
                time_uncertain,
            )
    } else {
        authorities.iter().any(|authority| {
            available.contains(&authority.id)
                && ancestors.contains(&authority.id)
                && authority.actor == delegation.delegator
                && authority.capability == delegation.capability
                && scope_contains_scope(&authority.scope, &delegation.scope)
                && !authority.revoked_by.iter().any(|id| ancestors.contains(id))
                && matches!(
                    evaluate_validity(authority.validity.as_ref(), trusted_time),
                    TemporalStatus::Active | TemporalStatus::Unbounded
                )
        })
    };
    visiting.remove(&delegation.id);
    valid
}

/// Validate a delegation's authority chain independently of the eventual
/// delegated action. This is used when authorizing the delegation object
/// itself, so a malformed or over-broad child cannot become authority merely
/// because its creator holds unrelated administrative power.
pub fn validate_delegation_chain(
    delegation: &Delegation,
    delegations: &[Delegation],
    authorities: &[Authority],
    available: &HashSet<ObjectId>,
    ancestors: &HashSet<ObjectId>,
) -> bool {
    validate_delegation_chain_at(
        delegation,
        delegations,
        authorities,
        available,
        ancestors,
        None,
    )
}

pub fn validate_delegation_chain_at(
    delegation: &Delegation,
    delegations: &[Delegation],
    authorities: &[Authority],
    available: &HashSet<ObjectId>,
    ancestors: &HashSet<ObjectId>,
    trusted_time: Option<TrustedTime>,
) -> bool {
    let mut time_uncertain = false;
    delegation_chain_valid(
        delegation,
        delegations,
        authorities,
        available,
        ancestors,
        &mut HashSet::new(),
        trusted_time,
        &mut time_uncertain,
    )
}

fn scope_contains_scope(parent: &Scope, child: &Scope) -> bool {
    match (parent, child) {
        (Scope::Ledger, _) => true,
        (Scope::Namespace(a), Scope::Namespace(b)) => a == b,
        (Scope::Proposition(a), Scope::Proposition(b)) => a == b,
        (Scope::Proposition(parent), Scope::RevisionIn { proposition, .. })
        | (Scope::Proposition(parent), Scope::DeliberationIn { proposition, .. }) => {
            parent == proposition
        }
        (Scope::Revision(a), Scope::Revision(b)) => a == b,
        (Scope::Revision(parent), Scope::RevisionIn { revision, .. }) => parent == revision,
        (Scope::Revision(parent), Scope::DeliberationIn { revision, .. }) => parent == revision,
        (
            Scope::RevisionIn {
                revision: parent, ..
            },
            Scope::RevisionIn { revision, .. },
        ) => parent == revision,
        (
            Scope::RevisionIn {
                revision: parent,
                proposition,
            },
            Scope::DeliberationIn {
                revision,
                proposition: child,
                ..
            },
        ) => parent == revision && proposition == child,
        (Scope::Deliberation(a), Scope::Deliberation(b)) => a == b,
        (
            Scope::DeliberationIn {
                deliberation: parent,
                ..
            },
            Scope::DeliberationIn { deliberation, .. },
        ) => parent == deliberation,
        (Scope::Actor(a), Scope::Actor(b)) => a == b,
        (Scope::CapabilityClass(a), Scope::CapabilityClass(b)) => a == b,
        _ => false,
    }
}

/// Evaluate unanimity over an explicit participant set and revision frontier.
/// No receipt order or mutable "current decision" projected participates in
/// this calculation: a decision tip exists only when a later decision names it
/// in its supersession set.
pub fn evaluate_unanimity(
    participants: &[ObjectId],
    revision: ObjectId,
    decisions: &[Decision],
) -> Evaluation {
    let active: HashSet<_> = participants.iter().copied().collect();
    let relevant: Vec<&Decision> = decisions
        .iter()
        .filter(|d| active.contains(&d.participant) && d.revision == revision)
        .collect();
    let superseded: HashSet<_> = relevant
        .iter()
        .flat_map(|d| d.supersedes.iter().copied())
        .collect();
    let mut by_participant: HashMap<ObjectId, Vec<&Decision>> = HashMap::new();
    for d in relevant.iter().filter(|d| !superseded.contains(&d.id)) {
        by_participant.entry(d.participant).or_default().push(d);
    }
    let mut results = HashMap::new();
    let mut applicable = Vec::new();
    for participant in participants {
        let tips = by_participant.get(participant).cloned().unwrap_or_default();
        let result = if tips.is_empty() {
            ParticipantResult::Undecided
        } else if tips.len() > 1 {
            ParticipantResult::Conflict
        } else {
            applicable.push(tips[0].id);
            match tips[0].value {
                DecisionValue::Accepted => ParticipantResult::Accepted,
                DecisionValue::Rejected => ParticipantResult::Rejected,
            }
        };
        results.insert(*participant, result);
    }
    let consensus = if results.values().any(|r| *r == ParticipantResult::Divergent) {
        Consensus::Divergent
    } else if results.values().any(|r| *r == ParticipantResult::Conflict) {
        Consensus::Conflict
    } else if results.values().any(|r| *r == ParticipantResult::Undecided) {
        Consensus::Undecided
    } else if results.values().any(|r| *r == ParticipantResult::Rejected) {
        Consensus::Rejected
    } else {
        Consensus::Accepted
    };
    applicable.sort();
    Evaluation {
        consensus,
        participants: results,
        applicable_decisions: applicable,
    }
}

pub fn evaluate_unanimity_with_changes(
    initial: &[ObjectId],
    changes: &[ParticipantChange],
    revision: ObjectId,
    decisions: &[Decision],
) -> Result<Evaluation, ParticipantReplayError> {
    let state = replay_participants(initial, changes)?;
    let mut participants = state.active.into_iter().collect::<Vec<_>>();
    participants.sort();
    Ok(evaluate_unanimity(&participants, revision, decisions))
}

/// Verify that a settlement's explicit decision references reproduce the
/// decision state at its declared causal frontier. Content hashes are carried
/// through the witness for exact-object verification by the store; this pure
/// function validates the state relationships and counts.
pub fn validate_settlement_witness(
    participants: &[ObjectId],
    revision: ObjectId,
    decisions: &[Decision],
    refs: &[SettlementDecisionRef],
    outcome: SettlementOutcome,
) -> Result<Evaluation, SettlementWitnessError> {
    if participants.is_empty() {
        return Err(SettlementWitnessError::EmptyParticipants);
    }
    let mut participant_set = HashSet::new();
    if participants.iter().any(|id| !participant_set.insert(*id)) {
        return Err(SettlementWitnessError::DuplicateParticipant);
    }
    let evaluation = evaluate_unanimity(participants, revision, decisions);
    if evaluation.participants.values().any(|result| {
        matches!(
            result,
            ParticipantResult::Conflict | ParticipantResult::Undecided
        )
    }) {
        return Err(SettlementWitnessError::MissingDecision);
    }
    let mut decision_set = HashSet::new();
    if refs
        .iter()
        .any(|reference| !decision_set.insert(reference.decision_id))
    {
        return Err(SettlementWitnessError::DuplicateDecision);
    }
    if refs.len() != participants.len() {
        return Err(SettlementWitnessError::CountMismatch);
    }
    let expected: HashSet<_> = evaluation.applicable_decisions.iter().copied().collect();
    for reference in refs {
        if !expected.contains(&reference.decision_id) {
            return Err(SettlementWitnessError::ExtraDecision);
        }
        let decision = decisions
            .iter()
            .find(|decision| decision.id == reference.decision_id)
            .ok_or(SettlementWitnessError::MissingDecision)?;
        if decision.participant != reference.participant {
            return Err(SettlementWitnessError::ParticipantMismatch);
        }
    }
    let accepted = evaluation
        .participants
        .values()
        .filter(|result| **result == ParticipantResult::Accepted)
        .count();
    let rejected = evaluation
        .participants
        .values()
        .filter(|result| **result == ParticipantResult::Rejected)
        .count();
    if accepted + rejected != participants.len() {
        return Err(SettlementWitnessError::CountMismatch);
    }
    match outcome {
        SettlementOutcome::Accepted if accepted != participants.len() || rejected != 0 => {
            Err(SettlementWitnessError::InvalidOutcome)
        }
        SettlementOutcome::Rejected if rejected == 0 => Err(SettlementWitnessError::InvalidOutcome),
        _ => Ok(evaluation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id() -> ObjectId {
        ObjectId::new_v7()
    }
    fn d(p: ObjectId, r: ObjectId, v: DecisionValue, supersedes: Vec<ObjectId>) -> Decision {
        Decision {
            id: id(),
            participant: p,
            revision: r,
            value: v,
            supersedes,
        }
    }

    #[test]
    fn participant_replay_is_invariant_to_topological_order() {
        let a = id();
        let b = id();
        let join_a = ParticipantChange {
            id: id(),
            actor: a,
            operation: ParticipantOperation::Join,
            predecessors: vec![],
        };
        let join_b = ParticipantChange {
            id: id(),
            actor: b,
            operation: ParticipantOperation::Join,
            predecessors: vec![],
        };
        let first = replay_participants(&[], &[join_a.clone(), join_b.clone()]).unwrap();
        let second = replay_participants(&[], &[join_b, join_a.clone()]).unwrap();
        assert_eq!(first.active, second.active);

        let leave = ParticipantChange {
            id: id(),
            actor: a,
            operation: ParticipantOperation::Leave,
            predecessors: vec![join_a.id],
        };
        let state = replay_participants(&[], &[join_a.clone(), leave]).unwrap();
        assert!(!state.active.contains(&a));
    }

    #[test]
    fn participant_replay_rejects_same_actor_conflicting_tips() {
        let actor = id();
        let first = ParticipantChange {
            id: id(),
            actor,
            operation: ParticipantOperation::Join,
            predecessors: vec![],
        };
        let second = ParticipantChange {
            id: id(),
            actor,
            operation: ParticipantOperation::Join,
            predecessors: vec![],
        };
        assert_eq!(
            replay_participants(&[], &[first, second]),
            Err(ParticipantReplayError::ConflictingTip)
        );
    }

    #[test]
    fn settlement_witness_matches_applicable_decisions() {
        let revision = id();
        let a = id();
        let b = id();
        let first = d(a, revision, DecisionValue::Accepted, vec![]);
        let second = d(b, revision, DecisionValue::Accepted, vec![]);
        let refs = vec![
            SettlementDecisionRef {
                decision_id: first.id,
                participant: a,
                content_hash: Hash::digest(b"a"),
            },
            SettlementDecisionRef {
                decision_id: second.id,
                participant: b,
                content_hash: Hash::digest(b"b"),
            },
        ];
        let evaluation = validate_settlement_witness(
            &[a, b],
            revision,
            &[first, second],
            &refs,
            SettlementOutcome::Accepted,
        )
        .unwrap();
        assert_eq!(evaluation.consensus, Consensus::Accepted);
    }

    #[test]
    fn settlement_witness_rejects_conflicts_and_bad_outcome() {
        let revision = id();
        let participant = id();
        let first = d(participant, revision, DecisionValue::Accepted, vec![]);
        let second = d(participant, revision, DecisionValue::Rejected, vec![]);
        let refs = vec![SettlementDecisionRef {
            decision_id: first.id,
            participant,
            content_hash: Hash::digest(b"a"),
        }];
        assert_eq!(
            validate_settlement_witness(
                &[participant],
                revision,
                &[first.clone(), second],
                &refs,
                SettlementOutcome::Accepted,
            ),
            Err(SettlementWitnessError::MissingDecision)
        );
        let replacement = d(
            participant,
            revision,
            DecisionValue::Accepted,
            vec![first.id],
        );
        let refs = vec![SettlementDecisionRef {
            decision_id: replacement.id,
            participant,
            content_hash: Hash::digest(b"replacement"),
        }];
        assert_eq!(
            validate_settlement_witness(
                &[participant],
                revision,
                &[first, replacement],
                &refs,
                SettlementOutcome::Rejected,
            ),
            Err(SettlementWitnessError::InvalidOutcome)
        );
    }
    #[test]
    fn unanimous_acceptance() {
        let (a, b, r) = (id(), id(), id());
        let result = evaluate_unanimity(
            &[a, b],
            r,
            &[
                d(a, r, DecisionValue::Accepted, vec![]),
                d(b, r, DecisionValue::Accepted, vec![]),
            ],
        );
        assert_eq!(result.consensus, Consensus::Accepted);
    }
    #[test]
    fn rejection_prevents_acceptance() {
        let (a, b, r) = (id(), id(), id());
        let result = evaluate_unanimity(
            &[a, b],
            r,
            &[
                d(a, r, DecisionValue::Accepted, vec![]),
                d(b, r, DecisionValue::Rejected, vec![]),
            ],
        );
        assert_eq!(result.consensus, Consensus::Rejected);
    }
    #[test]
    fn supersession_replaces_tip() {
        let (a, r) = (id(), id());
        let first = d(a, r, DecisionValue::Rejected, vec![]);
        let second = d(a, r, DecisionValue::Accepted, vec![first.id]);
        let second_id = second.id;
        let result = evaluate_unanimity(&[a], r, &[first, second]);
        assert_eq!(result.consensus, Consensus::Accepted);
        assert_eq!(result.applicable_decisions, vec![second_id]);
    }
    #[test]
    fn concurrent_tips_conflict() {
        let (a, r) = (id(), id());
        let result = evaluate_unanimity(
            &[a],
            r,
            &[
                d(a, r, DecisionValue::Accepted, vec![]),
                d(a, r, DecisionValue::Rejected, vec![]),
            ],
        );
        assert_eq!(result.consensus, Consensus::Conflict);
    }
    #[test]
    fn other_revision_does_not_count() {
        let (a, r1, r2) = (id(), id(), id());
        let result = evaluate_unanimity(&[a], r1, &[d(a, r2, DecisionValue::Accepted, vec![])]);
        assert_eq!(result.consensus, Consensus::Undecided);
    }

    #[test]
    fn authorization_is_causal_and_scope_exact() {
        let (actor, ledger, proposition, grant_id, action_id) = (id(), id(), id(), id(), id());
        let grant = Authority {
            id: grant_id,
            actor,
            capability: Capability::Accept,
            scope: Scope::Proposition(proposition),
            revoked_by: vec![],
            validity: None,
        };
        let mut ancestors = HashSet::from([grant_id]);
        let action = AuthorizedAction {
            actor,
            ledger,
            capability: Capability::Accept,
            target: Target::Proposition {
                ledger,
                proposition,
            },
            ancestors: ancestors.clone(),
            is_administration: false,
        };
        assert_eq!(
            authorize(
                &action,
                std::slice::from_ref(&grant),
                &HashSet::from([grant_id])
            ),
            Authorization::Authorized
        );
        let other = id();
        let wrong_target = AuthorizedAction {
            target: Target::Proposition {
                ledger,
                proposition: other,
            },
            ..action.clone()
        };
        assert_eq!(
            authorize(
                &wrong_target,
                std::slice::from_ref(&grant),
                &HashSet::from([grant_id])
            ),
            Authorization::Unauthorized
        );
        let revocation = id();
        ancestors.insert(revocation);
        let revoked = Authority {
            revoked_by: vec![revocation],
            ..grant
        };
        let historical = AuthorizedAction {
            ancestors: HashSet::from([grant_id]),
            ..action.clone()
        };
        assert_eq!(
            authorize(
                &historical,
                std::slice::from_ref(&revoked),
                &HashSet::from([grant_id])
            ),
            Authorization::Authorized
        );
        let current = AuthorizedAction {
            ancestors,
            ..action
        };
        assert_eq!(
            authorize(&current, &[revoked], &HashSet::from([grant_id, revocation])),
            Authorization::Unauthorized
        );
        let _ = action_id;
    }

    #[test]
    fn new_hire_can_contribute_without_governance_authority() {
        let (actor, ledger, proposition, revision, deliberation) = (id(), id(), id(), id(), id());
        let grants = [
            Authority {
                id: id(),
                actor,
                capability: Capability::Propose,
                scope: Scope::Ledger,
                revoked_by: vec![],
                validity: None,
            },
            Authority {
                id: id(),
                actor,
                capability: Capability::Comment,
                scope: Scope::Proposition(proposition),
                revoked_by: vec![],
                validity: None,
            },
            Authority {
                id: id(),
                actor,
                capability: Capability::Deliberate,
                scope: Scope::Deliberation(deliberation),
                revoked_by: vec![],
                validity: None,
            },
        ];
        let available = grants.iter().map(|grant| grant.id).collect::<HashSet<_>>();
        let ancestors = available.clone();
        let action = |capability, target, is_administration| AuthorizedAction {
            actor,
            ledger,
            capability,
            target,
            ancestors: ancestors.clone(),
            is_administration,
        };
        assert_eq!(
            authorize(
                &action(Capability::Propose, Target::Ledger(ledger), false),
                &grants,
                &available,
            ),
            Authorization::Authorized
        );
        assert_eq!(
            authorize(
                &action(
                    Capability::Comment,
                    Target::Proposition {
                        ledger,
                        proposition
                    },
                    false,
                ),
                &grants,
                &available,
            ),
            Authorization::Authorized
        );
        assert_eq!(
            authorize(
                &action(
                    Capability::Deliberate,
                    Target::Deliberation {
                        ledger,
                        proposition,
                        revision,
                        deliberation,
                    },
                    false,
                ),
                &grants,
                &available,
            ),
            Authorization::Authorized
        );
        assert_eq!(
            authorize(
                &action(
                    Capability::Accept,
                    Target::Proposition {
                        ledger,
                        proposition
                    },
                    false,
                ),
                &grants,
                &available,
            ),
            Authorization::Unauthorized
        );
        assert_eq!(
            authorize(
                &action(
                    Capability::Admin,
                    Target::Administration {
                        ledger,
                        capability: Capability::Admin,
                    },
                    true,
                ),
                &grants,
                &available,
            ),
            Authorization::Unauthorized
        );
    }

    #[test]
    fn duplicate_matching_authorities_are_redundant_not_conflicting() {
        let (actor, ledger, proposition, revision) = (id(), id(), id(), id());
        let grants = [
            Authority {
                id: id(),
                actor,
                capability: Capability::Deliberate,
                scope: Scope::Ledger,
                revoked_by: vec![],
                validity: None,
            },
            Authority {
                id: id(),
                actor,
                capability: Capability::Deliberate,
                scope: Scope::Ledger,
                revoked_by: vec![],
                validity: None,
            },
        ];
        let available = grants.iter().map(|grant| grant.id).collect::<HashSet<_>>();
        let action = AuthorizedAction {
            actor,
            ledger,
            capability: Capability::Deliberate,
            target: Target::Revision {
                ledger,
                proposition,
                revision,
            },
            ancestors: available.clone(),
            is_administration: false,
        };

        assert_eq!(
            authorize(&action, &grants, &available),
            Authorization::Authorized
        );
        assert_eq!(
            authorize_with_delegations(&action, &grants, &[], &available),
            Authorization::Authorized
        );
    }

    #[test]
    fn delegation_requires_exact_parent_and_redelegation_permission() {
        let (delegator, delegatee, third, ledger, proposition) = (id(), id(), id(), id(), id());
        let grant_id = id();
        let delegation_id = id();
        let child_id = id();
        let grant = Authority {
            id: grant_id,
            actor: delegator,
            capability: Capability::Comment,
            scope: Scope::Proposition(proposition),
            revoked_by: vec![],
            validity: None,
        };
        let delegation = Delegation {
            id: delegation_id,
            delegator,
            delegatee,
            capability: Capability::Comment,
            scope: Scope::Proposition(proposition),
            parent_delegation_id: None,
            redelegable: true,
            revoked_by: vec![],
            validity: None,
        };
        let child = Delegation {
            id: child_id,
            delegator: delegatee,
            delegatee: third,
            capability: Capability::Comment,
            scope: Scope::Proposition(proposition),
            parent_delegation_id: Some(delegation_id),
            redelegable: false,
            revoked_by: vec![],
            validity: None,
        };
        let action = AuthorizedAction {
            actor: third,
            ledger,
            capability: Capability::Comment,
            target: Target::Proposition {
                ledger,
                proposition,
            },
            ancestors: HashSet::from([grant_id, delegation_id, child_id]),
            is_administration: false,
        };
        assert_eq!(
            authorize_with_delegations(
                &action,
                std::slice::from_ref(&grant),
                &[delegation.clone(), child.clone()],
                &action.ancestors,
            ),
            Authorization::Authorized
        );

        let mut blocked_child = child;
        blocked_child.parent_delegation_id = None;
        blocked_child.delegator = third;
        assert_eq!(
            authorize_with_delegations(
                &action,
                std::slice::from_ref(&grant),
                &[delegation, blocked_child],
                &action.ancestors,
            ),
            Authorization::Unauthorized
        );
    }

    #[test]
    fn administration_scope_does_not_authorize_ordinary_use() {
        let (actor, ledger, grant_id) = (id(), id(), id());
        let authority = Authority {
            id: grant_id,
            actor,
            capability: Capability::Admin,
            scope: Scope::CapabilityClass(Capability::Accept),
            revoked_by: vec![],
            validity: None,
        };
        let action = AuthorizedAction {
            actor,
            ledger,
            capability: Capability::Admin,
            target: Target::Administration {
                ledger,
                capability: Capability::Accept,
            },
            ancestors: HashSet::from([grant_id]),
            is_administration: true,
        };
        assert_eq!(
            authorize(&action, &[authority], &HashSet::from([grant_id])),
            Authorization::Authorized
        );
    }

    #[test]
    fn validity_requires_trusted_time_and_respects_uncertainty() {
        let window = ValidityWindow {
            valid_from_millis: Some(1_000),
            expires_at_millis: Some(5_000),
        };
        assert_eq!(
            evaluate_validity(Some(&window), None),
            TemporalStatus::TimeUncertain
        );
        assert_eq!(
            evaluate_validity(Some(&window), Some(TrustedTime::new(500, 100))),
            TemporalStatus::NotYetValid
        );
        assert_eq!(
            evaluate_validity(Some(&window), Some(TrustedTime::new(1_050, 100))),
            TemporalStatus::TimeUncertain
        );
        assert_eq!(
            evaluate_validity(Some(&window), Some(TrustedTime::new(3_000, 100))),
            TemporalStatus::Active
        );
        assert_eq!(
            evaluate_validity(Some(&window), Some(TrustedTime::new(5_050, 100))),
            TemporalStatus::TimeUncertain
        );
        assert_eq!(
            evaluate_validity(Some(&window), Some(TrustedTime::new(5_100, 0))),
            TemporalStatus::Expired
        );
    }

    #[test]
    fn bounded_authority_is_time_uncertain_without_clock() {
        let (actor, ledger, proposition, grant_id) = (id(), id(), id(), id());
        let grant = Authority {
            id: grant_id,
            actor,
            capability: Capability::Accept,
            scope: Scope::Proposition(proposition),
            revoked_by: vec![],
            validity: Some(ValidityWindow {
                valid_from_millis: Some(1),
                expires_at_millis: None,
            }),
        };
        let action = AuthorizedAction {
            actor,
            ledger,
            capability: Capability::Accept,
            target: Target::Proposition {
                ledger,
                proposition,
            },
            ancestors: HashSet::from([grant_id]),
            is_administration: false,
        };
        assert_eq!(
            authorize_with_delegations(&action, &[grant], &[], &action.ancestors),
            Authorization::TimeUncertain
        );
    }

    #[test]
    fn contextual_scopes_allow_only_same_proposition_and_revision() {
        let proposition = id();
        let revision = id();
        let deliberation = id();
        assert!(scope_contains_scope(
            &Scope::Proposition(proposition),
            &Scope::RevisionIn {
                revision,
                proposition
            }
        ));
        assert!(scope_contains_scope(
            &Scope::RevisionIn {
                revision,
                proposition
            },
            &Scope::DeliberationIn {
                deliberation,
                proposition,
                revision
            }
        ));
        assert!(!scope_contains_scope(
            &Scope::Proposition(proposition),
            &Scope::RevisionIn {
                revision,
                proposition: id()
            }
        ));
    }
}
