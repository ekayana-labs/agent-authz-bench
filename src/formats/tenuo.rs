use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use tenuo::constraints::{ConstraintSet, ConstraintValue, Subpath};
use tenuo::crypto::{Signature, SigningKey};
use tenuo::payload::WarrantPayload;
use tenuo::planes::Authorizer;
use tenuo::revocation::SignedRevocationList;
use tenuo::warrant::Warrant;
use tenuo::wire;

use crate::model::{
    Attack, Format, Outcome, TOOL, Timing, Verdict, file_in_scope, scope_at, time_runs,
};

const HOPS: usize = 3;
const TTL: Duration = Duration::from_secs(600);

pub struct Tenuo;

fn limits(path: &str) -> ConstraintSet {
    ConstraintSet::from_iter(vec![(
        "path".to_string(),
        Subpath::new(path).unwrap().into(),
    )])
}

fn args(path: &str) -> HashMap<String, ConstraintValue> {
    HashMap::from([(
        "path".to_string(),
        ConstraintValue::String(path.to_string()),
    )])
}

struct Chain {
    keys: Vec<SigningKey>,
    warrants: Vec<Warrant>,
}

impl Chain {
    fn new(hops: usize, max_depth: Option<u32>) -> Chain {
        let keys: Vec<SigningKey> = (0..=hops).map(|_| SigningKey::generate()).collect();
        let mut root = Warrant::builder()
            .capability(TOOL, limits(&scope_at(1)))
            .ttl(TTL)
            .holder(keys[1].public_key());
        if let Some(depth) = max_depth {
            root = root.max_depth(depth);
        }
        let mut warrants = vec![root.build(&keys[0]).unwrap()];
        for hop in 1..hops {
            let next = warrants[hop - 1]
                .attenuate()
                .capability(TOOL, limits(&scope_at(hop + 1)))
                .holder(keys[hop + 1].public_key())
                .build(&keys[hop])
                .unwrap();
            warrants.push(next);
        }
        Chain { keys, warrants }
    }

    fn holder(&self) -> &SigningKey {
        self.keys.last().unwrap()
    }

    fn proof(&self, signer: &SigningKey, tool: &str, path: &str) -> Signature {
        self.warrants
            .last()
            .unwrap()
            .sign(signer, tool, &args(path))
            .unwrap()
    }

    fn authorizer(&self) -> Authorizer {
        Authorizer::new().with_trusted_root(self.keys[0].public_key())
    }

    fn check(&self, tool: &str, path: &str, proof: &Signature) -> Outcome {
        Outcome::from_result(self.authorizer().check_chain(
            &self.warrants,
            tool,
            &args(path),
            Some(proof),
            &[],
        ))
    }

    fn check_as_of(&self, path: &str, as_of: i64) -> Outcome {
        let leaf = self.warrants.last().unwrap();
        let request = args(path);
        let proof = leaf
            .sign_with_timestamp(self.holder(), TOOL, &request, Some(as_of))
            .unwrap();
        Outcome::from_result(self.authorizer().check_chain_with_pop_args_as_of(
            &self.warrants,
            TOOL,
            &request,
            &request,
            Some(&proof),
            &[],
            as_of,
        ))
    }
}

/// What a dishonest hop can do without the builder: edit the payload and sign it itself.
fn craft(
    warrant: &Warrant,
    signer: &SigningKey,
    edit: impl FnOnce(&mut WarrantPayload),
) -> Warrant {
    let mut crafted = warrant.clone();
    edit(&mut crafted.payload);
    let mut bytes = Vec::new();
    ciborium::into_writer(&crafted.payload, &mut bytes).unwrap();
    crafted.payload_bytes = bytes;
    crafted.signature = signer.sign(&crafted.signature_preimage());
    crafted
}

/// A check that crafting alone doesn't cause a rejection, so a block means the attack did it.
fn control_must_pass(outcome: Outcome) {
    assert_eq!(outcome.verdict, Verdict::Allowed, "control: {outcome:?}");
}

fn widened_hop() -> Outcome {
    let mut chain = Chain::new(HOPS, None);
    let last = HOPS - 1;
    chain.warrants[last] = craft(&chain.warrants[last], &chain.keys[last], |_| {});
    let path = file_in_scope(HOPS);
    let proof = chain.proof(chain.holder(), TOOL, &path);
    control_must_pass(chain.check(TOOL, &path, &proof));

    chain.warrants[last] = craft(&chain.warrants[last], &chain.keys[last], |payload| {
        payload.tools.insert(TOOL.to_string(), limits("/data"));
    });
    let wider = "/data/other.csv";
    let proof = chain.proof(chain.holder(), TOOL, wider);
    chain.check(TOOL, wider, &proof)
}

fn edited_link() -> Outcome {
    let chain = Chain::new(HOPS, None);
    let path = file_in_scope(HOPS);
    let proof = chain.proof(chain.holder(), TOOL, &path);
    let mut bytes = wire::encode(&chain.warrants[1]).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    let edited = match wire::decode(&bytes) {
        Ok(warrant) => warrant,
        Err(error) => return Outcome::blocked(error.to_string()),
    };
    let warrants = vec![chain.warrants[0].clone(), edited, chain.warrants[2].clone()];
    Outcome::from_result(chain.authorizer().check_chain(
        &warrants,
        TOOL,
        &args(&path),
        Some(&proof),
        &[],
    ))
}

fn removed_link() -> Outcome {
    let mut chain = Chain::new(HOPS, None);
    let path = file_in_scope(HOPS);
    let proof = chain.proof(chain.holder(), TOOL, &path);
    chain.warrants.remove(1);
    chain.check(TOOL, &path, &proof)
}

fn unknown_root() -> Outcome {
    let chain = Chain::new(HOPS, None);
    let path = file_in_scope(HOPS);
    let proof = chain.proof(chain.holder(), TOOL, &path);
    let other = Authorizer::new().with_trusted_root(SigningKey::generate().public_key());
    Outcome::from_result(other.check_chain(&chain.warrants, TOOL, &args(&path), Some(&proof), &[]))
}

fn outlives_parent() -> Outcome {
    let mut chain = Chain::new(HOPS, None);
    let last = HOPS - 1;
    let parent_expiry = chain.warrants[last - 1].payload.expires_at;
    chain.warrants[last] = craft(&chain.warrants[last], &chain.keys[last], |payload| {
        payload.expires_at = parent_expiry + 3600;
    });
    chain.check_as_of(&file_in_scope(HOPS), parent_expiry as i64 + 60)
}

fn revoked_ancestor() -> Outcome {
    let chain = Chain::new(HOPS, None);
    let path = file_in_scope(HOPS);
    let proof = chain.proof(chain.holder(), TOOL, &path);
    let list_key = SigningKey::generate();
    let list = SignedRevocationList::builder()
        .revoke(chain.warrants[0].id().to_string())
        .version(1)
        .build(&list_key)
        .unwrap();
    let mut authorizer = chain.authorizer();
    authorizer
        .set_revocation_list(list, &list_key.public_key())
        .unwrap();
    Outcome::from_result(authorizer.check_chain(
        &chain.warrants,
        TOOL,
        &args(&path),
        Some(&proof),
        &[],
    ))
}

/// Builds a hop past the limit by giving the builder a copy of the parent with a
/// larger limit. The copy's signed bytes don't change, so the link still holds.
fn past_depth_limit(limit: u32) -> Outcome {
    let mut chain = Chain::new(2, Some(limit));
    let leaf_key = SigningKey::generate();
    let parent = &chain.warrants[1];
    let mut roomy = parent.clone();
    roomy.payload.max_depth = 64;
    let next = roomy
        .attenuate()
        .capability(TOOL, limits(&scope_at(3)))
        .holder(leaf_key.public_key())
        .build(&chain.keys[2]);
    let next = match next {
        Ok(next) => next,
        Err(error) => return Outcome::blocked(format!("the builder refused: {error}")),
    };
    let next = craft(&next, &chain.keys[2], |payload| {
        payload.max_depth = limit as u8;
    });
    chain.warrants.push(next);
    chain.keys.push(leaf_key);
    let path = file_in_scope(3);
    let proof = chain.proof(chain.holder(), TOOL, &path);
    chain.check(TOOL, &path, &proof)
}

fn depth_limit() -> Outcome {
    control_must_pass(past_depth_limit(2));
    past_depth_limit(1)
}

impl Format for Tenuo {
    fn name(&self) -> &'static str {
        "Tenuo warrants"
    }

    fn version(&self) -> &'static str {
        "tenuo 0.3.5"
    }

    fn notes(&self) -> &'static str {
        "Paths use the Subpath constraint. Signed revocation lists need a list issuer you run or buy."
    }

    fn run(&self, attack: Attack) -> Outcome {
        let chain = Chain::new(HOPS, None);
        let path = file_in_scope(HOPS);
        let holder = chain.holder();
        match attack {
            Attack::HonestRequest => chain.check(TOOL, &path, &chain.proof(holder, TOOL, &path)),
            Attack::ArgumentOutOfScope => {
                let outside = "/etc/passwd";
                chain.check(TOOL, outside, &chain.proof(holder, TOOL, outside))
            }
            Attack::PathTraversal => {
                let sneaky = format!("{}/../../../etc/passwd", scope_at(HOPS));
                chain.check(TOOL, &sneaky, &chain.proof(holder, TOOL, &sneaky))
            }
            Attack::ToolNotGranted => chain.check(
                "delete_file",
                &path,
                &chain.proof(holder, "delete_file", &path),
            ),
            Attack::WidenedHop => widened_hop(),
            Attack::EditedLink => edited_link(),
            Attack::RemovedLink => removed_link(),
            Attack::UnknownRoot => unknown_root(),
            Attack::Expired => {
                let later = Utc::now().timestamp() + TTL.as_secs() as i64 + 3600;
                chain.check_as_of(&path, later)
            }
            Attack::OutlivesParent => outlives_parent(),
            Attack::StolenChain => {
                let thief = SigningKey::generate();
                chain.check(TOOL, &path, &chain.proof(&thief, TOOL, &path))
            }
            Attack::ProofForOtherArguments => {
                let other = format!("{}/other.csv", scope_at(HOPS));
                chain.check(TOOL, &other, &chain.proof(holder, TOOL, &path))
            }
            Attack::ReplayedRequest => {
                let proof = chain.proof(holder, TOOL, &path);
                control_must_pass(chain.check(TOOL, &path, &proof));
                control_must_pass(chain.check(TOOL, &path, &proof));
                let leaf = chain.warrants.last().unwrap();
                let mut seen = std::collections::HashSet::new();
                seen.insert(leaf.dedup_key(TOOL, &args(&path)));
                if seen.contains(&leaf.dedup_key(TOOL, &args(&path))) {
                    Outcome::blocked_by_your_code(
                        "the verifier accepts a repeat inside the proof's time window; dedup_key lets you reject it",
                    )
                } else {
                    Outcome::allowed("accepted")
                }
            }
            Attack::RevokedAncestor => revoked_ancestor(),
            Attack::DepthLimitExceeded => depth_limit(),
        }
    }

    fn measure(&self, hops: usize, runs: usize) -> Timing {
        let chain = Chain::new(hops, None);
        let path = file_in_scope(hops);
        let request = args(&path);
        let proof = chain.proof(chain.holder(), TOOL, &path);
        let bytes = wire::encode_stack(&wire::WarrantStack::new(chain.warrants.clone())).unwrap();
        let authorizer = chain.authorizer();
        let (median_us, p99_us) = time_runs(runs, || {
            let stack = wire::decode_stack(&bytes).unwrap();
            authorizer
                .check_chain(&stack.0, TOOL, &request, Some(&proof), &[])
                .unwrap();
        });
        Timing {
            hops,
            bytes: bytes.len() + proof.to_bytes().len(),
            median_us,
            p99_us,
        }
    }
}
