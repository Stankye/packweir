//! License observations and operator policy. This is not a legal-obligation engine.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use spdx::{
    Expression,
    expression::{ExprNode, Operator},
};
use std::collections::BTreeSet;

pub const SCANCODE_VERSION: &str = "32.5.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicensePolicy {
    /// Atomic SPDX requirements, including any WITH exception. Boolean expressions belong in findings.
    pub allowed: Vec<String>,
    #[serde(default)]
    pub denied: Vec<String>,
    /// Explicitly tolerate files with no detected license. Never authorizes arbitrary LicenseRef values.
    #[serde(default)]
    pub allow_unknown: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseDecision {
    Allowed,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpressionAssessment {
    pub expression: String,
    pub decision: LicenseDecision,
    pub requirements: Vec<String>,
    /// One policy-acceptable branch. This records a policy evaluation, not a legal election.
    pub acceptable_branch: Option<Vec<String>>,
    pub unknown_requirements: Vec<String>,
}

impl LicensePolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.allowed.is_empty() && self.allowed.len() <= 256 && self.denied.len() <= 256,
            "license policy needs 1..=256 allowed requirements and at most 256 denied requirements"
        );
        let mut allowed = BTreeSet::new();
        for value in &self.allowed {
            ensure!(
                allowed.insert(atomic(value)?),
                "duplicate allowed license requirement"
            );
        }
        let mut denied = BTreeSet::new();
        for value in &self.denied {
            ensure!(
                denied.insert(atomic(value)?),
                "duplicate denied license requirement"
            );
        }
        ensure!(
            allowed.is_disjoint(&denied),
            "license requirements cannot be both allowed and denied"
        );
        Ok(())
    }

    pub fn assess(&self, value: &str) -> Result<ExpressionAssessment> {
        ensure!(value.len() <= 4096, "license expression exceeds limit");
        let expression = Expression::parse(value)?;
        ensure!(
            expression.requirements().count() <= 256,
            "license expression term limit exceeded"
        );
        let allowed = self
            .allowed
            .iter()
            .map(|v| atomic(v))
            .collect::<Result<BTreeSet<_>>>()?;
        let denied = self
            .denied
            .iter()
            .map(|v| atomic(v))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut stack: Vec<Option<Vec<String>>> = Vec::new();
        let mut requirements = BTreeSet::new();
        let mut unknown = BTreeSet::new();
        for node in expression.iter() {
            match node {
                ExprNode::Req(term) => {
                    let name = term.req.to_string();
                    let custom = matches!(term.req.license, spdx::LicenseItem::Other(_))
                        || matches!(term.req.addition, Some(spdx::AdditionItem::Other(_)));
                    if custom && !allowed.contains(&name) && !denied.contains(&name) {
                        unknown.insert(name.clone());
                    }
                    requirements.insert(name.clone());
                    stack.push(
                        (allowed.contains(&name) && !denied.contains(&name)).then_some(vec![name]),
                    );
                }
                ExprNode::Op(operator) => {
                    let right = stack
                        .pop()
                        .ok_or_else(|| anyhow::anyhow!("invalid SPDX expression stack"))?;
                    let left = stack
                        .pop()
                        .ok_or_else(|| anyhow::anyhow!("invalid SPDX expression stack"))?;
                    let branch = match operator {
                        Operator::And => match (left, right) {
                            (Some(mut a), Some(b)) => {
                                a.extend(b);
                                Some(a)
                            }
                            _ => None,
                        },
                        Operator::Or => match (left, right) {
                            (Some(a), Some(b)) => Some(if a.len() <= b.len() { a } else { b }),
                            (Some(a), None) | (None, Some(a)) => Some(a),
                            _ => None,
                        },
                    };
                    stack.push(branch);
                }
            }
        }
        let mut branch = stack.pop().flatten();
        if let Some(values) = &mut branch {
            values.sort();
            values.dedup();
        }
        let decision = if branch.is_some() {
            LicenseDecision::Allowed
        } else {
            // Evaluate with unresolved custom requirements tentatively accepted: only then can
            // those unknown terms, rather than a definite policy rejection, explain the result.
            let could_resolve = expression.evaluate(|term| {
                let name = term.to_string();
                !denied.contains(&name) && (allowed.contains(&name) || unknown.contains(&name))
            });
            if could_resolve && !unknown.is_empty() {
                LicenseDecision::Unknown
            } else {
                LicenseDecision::Denied
            }
        };
        Ok(ExpressionAssessment {
            expression: expression.to_string(),
            decision,
            requirements: requirements.into_iter().collect(),
            acceptable_branch: branch,
            unknown_requirements: unknown.into_iter().collect(),
        })
    }
}

fn atomic(value: &str) -> Result<String> {
    ensure!(
        !value.is_empty() && value.len() <= 512,
        "invalid license policy requirement length"
    );
    let parsed = Expression::parse(value)?;
    let mut terms = parsed.iter();
    let Some(ExprNode::Req(term)) = terms.next() else {
        anyhow::bail!("license policy entries must be atomic SPDX requirements");
    };
    ensure!(
        terms.next().is_none(),
        "license policy entries must not contain AND/OR operators"
    );
    Ok(term.req.to_string())
}

/// Compare ScanCode's aggregate with independent detections without flattening OR choices.
/// Bounded monotone DNF canonicalization also handles order, duplication, and absorption.
pub(crate) fn conjunction_equivalent(aggregate: &str, detected: &[String]) -> Result<bool> {
    ensure!(
        !detected.is_empty() && detected.len() <= 256,
        "license detection coverage missing or excessive"
    );
    let mut conjunction = BTreeSet::from([BTreeSet::new()]);
    for expression in detected {
        conjunction = join(conjunction, normal_form(expression)?, true)?;
    }
    Ok(conjunction == normal_form(aggregate)?)
}

pub(crate) fn equivalent(left: &str, right: &str) -> Result<bool> {
    Ok(normal_form(left)? == normal_form(right)?)
}

type Branches = BTreeSet<BTreeSet<String>>;
fn normal_form(value: &str) -> Result<Branches> {
    ensure!(value.len() <= 4096, "license expression exceeds limit");
    let expression = Expression::parse(value)?;
    ensure!(
        expression.requirements().count() <= 256,
        "license expression term limit exceeded"
    );
    let mut stack = Vec::new();
    for node in expression.iter() {
        match node {
            ExprNode::Req(term) => {
                stack.push(BTreeSet::from([BTreeSet::from([term.req.to_string()])]))
            }
            ExprNode::Op(op) => {
                let right = stack
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("invalid SPDX expression stack"))?;
                let left = stack
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("invalid SPDX expression stack"))?;
                stack.push(join(left, right, *op == Operator::And)?);
            }
        }
    }
    stack
        .pop()
        .ok_or_else(|| anyhow::anyhow!("empty SPDX expression"))
}
fn join(left: Branches, right: Branches, and: bool) -> Result<Branches> {
    ensure!(
        left.len().saturating_mul(right.len()) <= 1024,
        "license expression alternative limit exceeded"
    );
    let candidates: Branches = if and {
        left.iter()
            .flat_map(|a| right.iter().map(move |b| a.union(b).cloned().collect()))
            .collect()
    } else {
        left.union(&right).cloned().collect()
    };
    ensure!(
        candidates.len() <= 1024,
        "license expression alternative limit exceeded"
    );
    Ok(candidates
        .iter()
        .filter(|branch| {
            !candidates
                .iter()
                .any(|other| other.len() < branch.len() && other.is_subset(branch))
        })
        .cloned()
        .collect())
}
