//! The shared scenario, the attack list, and what a result means.
//!
//! In every format a root grants `read_file` under `/data`, and each hop narrows
//! the path by one level. The leaf then asks to read a file inside its own scope.

use serde::{Deserialize, Serialize};

pub const TOOL: &str = "read_file";

pub fn scope_at(hops: usize) -> String {
    let mut path = String::from("/data");
    for hop in 1..hops {
        path.push_str(&format!("/h{hop}"));
    }
    path
}

pub fn file_in_scope(hops: usize) -> String {
    format!("{}/file.csv", scope_at(hops))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attack {
    HonestRequest,
    ArgumentOutOfScope,
    PathTraversal,
    ToolNotGranted,
    WidenedHop,
    EditedLink,
    RemovedLink,
    UnknownRoot,
    Expired,
    OutlivesParent,
    StolenChain,
    ProofForOtherArguments,
    ReplayedRequest,
    RevokedAncestor,
    DepthLimitExceeded,
}

pub const ATTACKS: [Attack; 15] = [
    Attack::HonestRequest,
    Attack::ArgumentOutOfScope,
    Attack::PathTraversal,
    Attack::ToolNotGranted,
    Attack::WidenedHop,
    Attack::EditedLink,
    Attack::RemovedLink,
    Attack::UnknownRoot,
    Attack::Expired,
    Attack::OutlivesParent,
    Attack::StolenChain,
    Attack::ProofForOtherArguments,
    Attack::ReplayedRequest,
    Attack::RevokedAncestor,
    Attack::DepthLimitExceeded,
];

impl Attack {
    pub fn title(self) -> &'static str {
        match self {
            Attack::HonestRequest => "Honest request (must be allowed)",
            Attack::ArgumentOutOfScope => "Argument outside the granted scope",
            Attack::PathTraversal => "Path that climbs out of scope with ../",
            Attack::ToolNotGranted => "Tool that was never granted",
            Attack::WidenedHop => "A hop grants more than it received",
            Attack::EditedLink => "A signed link is edited",
            Attack::RemovedLink => "A middle link is removed",
            Attack::UnknownRoot => "Chain from a root the verifier doesn't trust",
            Attack::Expired => "Expired token",
            Attack::OutlivesParent => "A hop outlives its parent",
            Attack::StolenChain => "Stolen chain used without the holder's key",
            Attack::ProofForOtherArguments => "Proof for one argument used for another",
            Attack::ReplayedRequest => "The same valid request sent twice",
            Attack::RevokedAncestor => "A parent token has been revoked",
            Attack::DepthLimitExceeded => "Delegation past a depth limit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allowed,
    Blocked,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcedBy {
    /// The library's verifier does this on its own.
    Library,
    /// The library gives you the parts, and you write the check.
    YourCode,
    /// Nobody enforced anything.
    Nothing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub verdict: Verdict,
    pub enforced_by: EnforcedBy,
    /// The library's own error text, or why the attack doesn't apply.
    pub detail: String,
}

impl Outcome {
    pub fn from_result<T, E: std::fmt::Display>(result: Result<T, E>) -> Outcome {
        match result {
            Ok(_) => Outcome::allowed("accepted"),
            Err(error) => Outcome::blocked(error.to_string()),
        }
    }

    pub fn allowed(detail: impl Into<String>) -> Outcome {
        Outcome {
            verdict: Verdict::Allowed,
            enforced_by: EnforcedBy::Nothing,
            detail: detail.into(),
        }
    }

    pub fn blocked(detail: impl Into<String>) -> Outcome {
        Outcome {
            verdict: Verdict::Blocked,
            enforced_by: EnforcedBy::Library,
            detail: detail.into(),
        }
    }

    pub fn blocked_by_your_code(detail: impl Into<String>) -> Outcome {
        Outcome {
            verdict: Verdict::Blocked,
            enforced_by: EnforcedBy::YourCode,
            detail: detail.into(),
        }
    }

    pub fn not_applicable(detail: impl Into<String>) -> Outcome {
        Outcome {
            verdict: Verdict::NotApplicable,
            enforced_by: EnforcedBy::Nothing,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Timing {
    pub hops: usize,
    pub bytes: usize,
    pub median_us: f64,
    pub p99_us: f64,
}

/// One token format under test.
pub trait Format {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    /// What this format does and doesn't set out to do, in its own terms.
    fn notes(&self) -> &'static str;
    fn run(&self, attack: Attack) -> Outcome;
    fn measure(&self, hops: usize, runs: usize) -> Timing;
}

pub fn base64_len(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}

/// Times `work`, and returns the median and 99th percentile in microseconds.
pub fn time_runs(runs: usize, mut work: impl FnMut()) -> (f64, f64) {
    let mut samples: Vec<u128> = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = std::time::Instant::now();
        work();
        samples.push(start.elapsed().as_nanos());
    }
    samples.sort_unstable();
    (
        samples[runs / 2] as f64 / 1000.0,
        samples[runs * 99 / 100] as f64 / 1000.0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_narrows_with_each_hop() {
        assert_eq!(scope_at(1), "/data");
        assert_eq!(scope_at(3), "/data/h1/h2");
        assert_eq!(file_in_scope(3), "/data/h1/h2/file.csv");
    }

    #[test]
    fn every_attack_has_a_distinct_title() {
        let mut titles: Vec<_> = ATTACKS.iter().map(|a| a.title()).collect();
        titles.sort_unstable();
        titles.dedup();
        assert_eq!(titles.len(), ATTACKS.len());
    }

    #[test]
    fn base64_rounds_up_to_whole_groups() {
        assert_eq!(base64_len(3), 4);
        assert_eq!(base64_len(4), 8);
    }

    #[test]
    fn timing_reports_order_statistics() {
        let (median, p99) = time_runs(100, || {});
        assert!(median <= p99);
    }
}
