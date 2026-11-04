use pq_ucan::command::Command;
use pq_ucan::crypto::Signer;
use pq_ucan::delegation::{Delegation, Subject};
use pq_ucan::did::Did;
use pq_ucan::invocation::Invocation;
use pq_ucan::nonce::Nonce;
use pq_ucan::policy::{Pattern, Policy, Selector, Statement};
use pq_ucan::time::Timestamp;
use pq_ucan::validate::{MemoryReplayGuard, MemoryStore, Validator};
use pq_ucan::{Cid, Ipld};

use crate::model::{
    Attack, Format, Outcome, TOOL, Timing, file_in_scope, flip_each_byte, scope_at, time_runs,
};

const HOPS: usize = 3;
const NOW: i64 = 1_800_000_000;
const TTL: u32 = 600;

pub struct Ucan<S> {
    pub label: &'static str,
    pub generate: fn() -> S,
}

fn now() -> Timestamp {
    Timestamp::from_unix(NOW).unwrap()
}

fn command(tool: &str) -> Command {
    Command::parse(&format!("/mcp/{tool}")).unwrap()
}

fn path_policy(scope: &str) -> Policy {
    Policy::new(vec![Statement::Like(
        Selector::parse(".path").unwrap(),
        Pattern::parse(&format!("{scope}/*")),
    )])
}

struct Chain<S> {
    keys: Vec<S>,
    delegations: Vec<Delegation>,
}

fn delegation<S: Signer>(
    subject: Did,
    audience: Did,
    scope: &str,
    signer: &S,
    expires: Timestamp,
) -> Delegation {
    let mut rng = pq_ucan::rng::system();
    Delegation::builder(audience, Subject::Did(subject), command(TOOL))
        .policy(path_policy(scope))
        .nonce(Nonce::random(&mut rng))
        .expires_at(expires)
        .sign(signer)
        .unwrap()
}

impl<S: Signer> Chain<S> {
    fn new(generate: fn() -> S, hops: usize) -> Chain<S> {
        let keys: Vec<S> = (0..=hops).map(|_| generate()).collect();
        let expires = now().plus_seconds(TTL);
        let delegations = (0..hops)
            .map(|hop| {
                delegation(
                    keys[0].did(),
                    keys[hop + 1].did(),
                    &scope_at(hop + 1),
                    &keys[hop],
                    expires,
                )
            })
            .collect();
        Chain { keys, delegations }
    }

    fn invoke_as(&self, signer: &impl Signer, tool: &str, path: &str) -> Invocation {
        let mut rng = pq_ucan::rng::system();
        let mut builder = Invocation::builder(self.keys[0].did(), command(tool))
            .arg("path", Ipld::String(path.to_owned()));
        for link in &self.delegations {
            builder = builder.proof(*link.cid());
        }
        builder
            .nonce(Nonce::random(&mut rng))
            .expires_at(now().plus_seconds(60))
            .sign(signer)
            .unwrap()
    }

    fn invoke(&self, tool: &str, path: &str) -> Invocation {
        self.invoke_as(self.keys.last().unwrap(), tool, path)
    }

    fn store(&self) -> MemoryStore {
        let mut store = MemoryStore::new();
        for link in &self.delegations {
            store.insert(link.clone());
        }
        store
    }

    fn check(&self, invocation: &Invocation) -> Outcome {
        self.check_at(invocation, now())
    }

    fn check_at(&self, invocation: &Invocation, at: Timestamp) -> Outcome {
        let store = self.store();
        let result = Validator::new(&store, at)
            .executor(&self.keys[0].did())
            .validate(invocation);
        Outcome::from_result(result)
    }
}

fn widened_hop<S: Signer>(generate: fn() -> S) -> Outcome {
    let mut chain = Chain::new(generate, HOPS);
    chain.delegations[2] = delegation(
        chain.keys[0].did(),
        chain.keys[3].did(),
        "/data",
        &chain.keys[2],
        now().plus_seconds(TTL),
    );
    chain.check(&chain.invoke(TOOL, "/data/other.csv"))
}

fn edited_link<S: Signer>(generate: fn() -> S) -> Outcome {
    let chain = Chain::new(generate, HOPS);
    let invocation = chain.invoke(TOOL, &file_in_scope(HOPS));
    let root = chain.keys[0].did();
    flip_each_byte(chain.delegations[1].bytes(), |edited| {
        let Ok(link) = Delegation::decode(edited) else {
            return false;
        };
        let mut store = chain.store();
        store.remove(chain.delegations[1].cid());
        store.insert(link);
        Validator::new(&store, now())
            .executor(&root)
            .validate(&invocation)
            .is_ok()
    })
}

fn removed_link<S: Signer>(generate: fn() -> S) -> Outcome {
    let mut chain = Chain::new(generate, HOPS);
    chain.delegations.remove(1);
    chain.check(&chain.invoke(TOOL, &file_in_scope(HOPS)))
}

fn unknown_root<S: Signer>(generate: fn() -> S) -> Outcome {
    let trusted = generate().did();
    let chain = Chain::new(generate, HOPS);
    let invocation = chain.invoke(TOOL, &file_in_scope(HOPS));
    let store = chain.store();
    Outcome::from_result(
        Validator::new(&store, now())
            .executor(&trusted)
            .validate(&invocation),
    )
}

fn outlives_parent<S: Signer>(generate: fn() -> S) -> Outcome {
    let mut chain = Chain::new(generate, HOPS);
    chain.delegations[2] = delegation(
        chain.keys[0].did(),
        chain.keys[3].did(),
        &scope_at(3),
        &chain.keys[2],
        now().plus_seconds(TTL + 3600),
    );
    let at = now().plus_seconds(TTL + 1800);
    let mut rng = pq_ucan::rng::system();
    let mut builder = Invocation::builder(chain.keys[0].did(), command(TOOL))
        .arg("path", Ipld::String(file_in_scope(HOPS)));
    for link in &chain.delegations {
        builder = builder.proof(*link.cid());
    }
    let invocation = builder
        .nonce(Nonce::random(&mut rng))
        .expires_at(at.plus_seconds(60))
        .sign(chain.keys.last().unwrap())
        .unwrap();
    chain.check_at(&invocation, at)
}

fn edited_arguments<S: Signer>(generate: fn() -> S) -> Outcome {
    let chain = Chain::new(generate, HOPS);
    let original = file_in_scope(HOPS);
    let other = original.replace("file", "evil");
    let invocation = chain.invoke(TOOL, &original);
    let bytes = invocation.bytes().to_vec();
    let at = bytes
        .windows(original.len())
        .position(|window| window == original.as_bytes())
        .expect("the argument is in the invocation");
    let mut edited = bytes;
    edited[at..at + other.len()].copy_from_slice(other.as_bytes());
    match Invocation::decode(&edited) {
        Ok(invocation) => chain.check(&invocation),
        Err(error) => Outcome::blocked(error.to_string()),
    }
}

fn replayed<S: Signer>(generate: fn() -> S) -> Outcome {
    let chain = Chain::new(generate, HOPS);
    let invocation = chain.invoke(TOOL, &file_in_scope(HOPS));
    let store = chain.store();
    let mut guard = MemoryReplayGuard::new();
    let root = chain.keys[0].did();
    Validator::new(&store, now())
        .executor(&root)
        .replay_guard(&mut guard)
        .validate(&invocation)
        .expect("the first request is honest");
    let mut result = Outcome::from_result(
        Validator::new(&store, now())
            .executor(&root)
            .replay_guard(&mut guard)
            .validate(&invocation),
    );
    result.detail = format!("{}; needs the optional replay guard", result.detail);
    result
}

fn revoked_ancestor<S: Signer>(generate: fn() -> S) -> Outcome {
    let chain = Chain::new(generate, HOPS);
    let revoked: Cid = *chain.delegations[0].cid();
    let invocation = chain.invoke(TOOL, &file_in_scope(HOPS));
    if invocation.proofs().contains(&revoked) {
        Outcome::blocked_by_your_code(
            "the validator has no revocation store in this version; you check proof CIDs against your list first",
        )
    } else {
        Outcome::allowed("accepted")
    }
}

impl<S: Signer> Format for Ucan<S> {
    fn name(&self) -> &'static str {
        self.label
    }

    fn version(&self) -> &'static str {
        "pq-ucan 0.1.2"
    }

    fn notes(&self) -> &'static str {
        "Paths use the UCAN policy language's glob match, which treats a path as plain text. pq-ucan is maintained by the authors of this benchmark."
    }

    fn run(&self, attack: Attack) -> Outcome {
        let chain = Chain::new(self.generate, HOPS);
        let path = file_in_scope(HOPS);
        match attack {
            Attack::HonestRequest => chain.check(&chain.invoke(TOOL, &path)),
            Attack::ArgumentOutOfScope => chain.check(&chain.invoke(TOOL, "/etc/passwd")),
            Attack::PathTraversal => {
                let sneaky = format!("{}/../../../etc/passwd", scope_at(HOPS));
                let mut result = chain.check(&chain.invoke(TOOL, &sneaky));
                result.detail =
                    "accepted: the glob compares text, so normalise paths before checking"
                        .to_owned();
                result
            }
            Attack::ToolNotGranted => chain.check(&chain.invoke("delete_file", &path)),
            Attack::WidenedHop => widened_hop(self.generate),
            Attack::EditedLink => edited_link(self.generate),
            Attack::RemovedLink => removed_link(self.generate),
            Attack::UnknownRoot => unknown_root(self.generate),
            Attack::Expired => {
                let later = now().plus_seconds(TTL + 3600);
                chain.check_at(&chain.invoke(TOOL, &path), later)
            }
            Attack::OutlivesParent => outlives_parent(self.generate),
            Attack::StolenChain => {
                let thief = (self.generate)();
                chain.check(&chain.invoke_as(&thief, TOOL, &path))
            }
            Attack::ProofForOtherArguments => edited_arguments(self.generate),
            Attack::ReplayedRequest => replayed(self.generate),
            Attack::RevokedAncestor => revoked_ancestor(self.generate),
            Attack::DepthLimitExceeded => {
                let long = Chain::new(self.generate, 12);
                let mut result = long.check(&long.invoke(TOOL, &file_in_scope(12)));
                result.detail = "accepted: UCAN has no depth limit".to_owned();
                result
            }
        }
    }

    fn measure(&self, hops: usize, runs: usize) -> Timing {
        let chain = Chain::new(self.generate, hops);
        let invocation = chain.invoke(TOOL, &file_in_scope(hops));
        let links: Vec<Vec<u8>> = chain
            .delegations
            .iter()
            .map(|link| link.bytes().to_vec())
            .collect();
        let call = invocation.bytes().to_vec();
        let root = chain.keys[0].did();
        let (median_us, p99_us) = time_runs(runs, || {
            let mut store = MemoryStore::new();
            for link in &links {
                store.insert(Delegation::decode(link).unwrap());
            }
            let parsed = Invocation::decode(&call).unwrap();
            Validator::new(&store, now())
                .executor(&root)
                .validate(&parsed)
                .unwrap();
        });
        Timing {
            hops,
            bytes: links.iter().map(Vec::len).sum::<usize>() + call.len(),
            median_us,
            p99_us,
        }
    }
}
