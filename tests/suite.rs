use agent_authz_bench::formats::biscuit::BiscuitFormat;
use agent_authz_bench::formats::tenuo::Tenuo;
use agent_authz_bench::formats::ucan::Ucan;
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

#[test]
fn biscuit_results_have_not_changed() {
    use Attack::*;
    use EnforcedBy::*;
    expect(
        &BiscuitFormat,
        &[
            (HonestRequest, Verdict::Allowed, Nothing),
            (ArgumentOutOfScope, Verdict::Blocked, Library),
            (PathTraversal, Verdict::Allowed, Nothing),
            (ToolNotGranted, Verdict::Blocked, Library),
            (WidenedHop, Verdict::Blocked, Library),
            (EditedLink, Verdict::Blocked, Library),
            (RemovedLink, Verdict::Blocked, Library),
            (UnknownRoot, Verdict::Blocked, Library),
            (Expired, Verdict::Blocked, Library),
            (OutlivesParent, Verdict::Blocked, Library),
            (StolenChain, Verdict::Allowed, Nothing),
            (ProofForOtherArguments, Verdict::NotApplicable, Nothing),
            (ReplayedRequest, Verdict::Allowed, Nothing),
            (RevokedAncestor, Verdict::Blocked, YourCode),
            (DepthLimitExceeded, Verdict::Allowed, Nothing),
        ],
    );
}

fn ucan_expectations() -> Vec<(Attack, Verdict, EnforcedBy)> {
    use Attack::*;
    use EnforcedBy::*;
    vec![
        (HonestRequest, Verdict::Allowed, Nothing),
        (ArgumentOutOfScope, Verdict::Blocked, Library),
        (PathTraversal, Verdict::Allowed, Nothing),
        (ToolNotGranted, Verdict::Blocked, Library),
        (WidenedHop, Verdict::Blocked, Library),
        (EditedLink, Verdict::Blocked, Library),
        (RemovedLink, Verdict::Blocked, Library),
        (UnknownRoot, Verdict::Blocked, Library),
        (Expired, Verdict::Blocked, Library),
        (OutlivesParent, Verdict::Blocked, Library),
        (StolenChain, Verdict::Blocked, Library),
        (ProofForOtherArguments, Verdict::Blocked, Library),
        (ReplayedRequest, Verdict::Blocked, Library),
        (RevokedAncestor, Verdict::Blocked, YourCode),
        (DepthLimitExceeded, Verdict::Allowed, Nothing),
    ]
}

#[test]
fn ucan_ed25519_results_have_not_changed() {
    let format = Ucan {
        label: "UCAN Ed25519",
        generate: || pq_ucan::crypto::ed25519::Ed25519Keypair::generate(&mut pq_ucan::rng::system()),
    };
    expect(&format, &ucan_expectations());
}

#[test]
fn ucan_ml_dsa_results_have_not_changed() {
    let format = Ucan {
        label: "UCAN ML-DSA-65",
        generate: || {
            pq_ucan::crypto::ml_dsa::MlDsaKeypair::generate(pq_ucan::crypto::Algorithm::MlDsa65)
                .unwrap()
        },
    };
    expect(&format, &ucan_expectations());
}
