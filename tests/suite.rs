use agent_authz_bench::formats::tenuo::Tenuo;
use agent_authz_bench::model::{ATTACKS, Attack, EnforcedBy, Format, Verdict};

fn expect(format: &dyn Format, expected: &[(Attack, Verdict, EnforcedBy)]) {
    assert_eq!(expected.len(), ATTACKS.len(), "every attack needs a result");
    for (attack, verdict, enforced_by) in expected {
        let outcome = format.run(*attack);
        assert_eq!(
            (outcome.verdict, outcome.enforced_by),
            (*verdict, *enforced_by),
            "{} / {:?}: {}",
            format.name(),
            attack,
            outcome.detail
        );
    }
}

#[test]
fn tenuo_results_have_not_changed() {
    use Attack::*;
    use EnforcedBy::*;
    expect(
        &Tenuo,
        &[
            (HonestRequest, Verdict::Allowed, Nothing),
            (ArgumentOutOfScope, Verdict::Blocked, Library),
            (PathTraversal, Verdict::Blocked, Library),
            (ToolNotGranted, Verdict::Blocked, Library),
            (WidenedHop, Verdict::Blocked, Library),
            (EditedLink, Verdict::Blocked, Library),
            (RemovedLink, Verdict::Blocked, Library),
            (UnknownRoot, Verdict::Blocked, Library),
            (Expired, Verdict::Blocked, Library),
            (OutlivesParent, Verdict::Blocked, Library),
            (StolenChain, Verdict::Blocked, Library),
            (ProofForOtherArguments, Verdict::Blocked, Library),
            (ReplayedRequest, Verdict::Blocked, YourCode),
            (RevokedAncestor, Verdict::Blocked, Library),
            (DepthLimitExceeded, Verdict::Blocked, Library),
        ],
    );
}

#[test]
fn tenuo_timing_covers_the_chain() {
    let timing = Tenuo.measure(3, 5);
    assert!(timing.bytes > Tenuo.measure(1, 5).bytes);
}
