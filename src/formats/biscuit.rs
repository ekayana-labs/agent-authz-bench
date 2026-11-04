use std::time::{Duration, SystemTime};

use biscuit_auth::builder::{Algorithm, BlockBuilder};
use biscuit_auth::macros::{authorizer, biscuit};
use biscuit_auth::{Biscuit, KeyPair, PublicKey};

use crate::model::{
    Attack, Format, Outcome, TOOL, Timing, file_in_scope, flip_each_byte, scope_at, time_runs,
};

const HOPS: usize = 3;
const TTL: Duration = Duration::from_secs(600);

pub struct BiscuitFormat;

fn now() -> SystemTime {
    SystemTime::now()
}

fn narrowing_block(prefix: &str) -> BlockBuilder {
    BlockBuilder::new()
        .code(format!(
            r#"check if resource($r), $r.starts_with("{prefix}/");"#
        ))
        .unwrap()
}

struct Token {
    root: KeyPair,
    biscuit: Biscuit,
}

impl Token {
    fn new(hops: usize, expires: SystemTime) -> Token {
        let root = KeyPair::new_with_algorithm(Algorithm::Ed25519);
        let scope = scope_at(1);
        let prefix = format!("{scope}/");
        let mut biscuit = biscuit!(
            r#"
            right({TOOL});
            check if resource($r), $r.starts_with({prefix});
            check if time($t), $t < {expires};
            "#
        )
        .build(&root)
        .unwrap();
        for hop in 1..hops {
            biscuit = biscuit.append(narrowing_block(&scope_at(hop + 1))).unwrap();
        }
        Token { root, biscuit }
    }

    fn fresh(hops: usize) -> Token {
        Token::new(hops, now() + TTL)
    }

    fn bytes(&self) -> Vec<u8> {
        self.biscuit.to_vec().unwrap()
    }

    fn public(&self) -> PublicKey {
        self.root.public()
    }
}

fn check_bytes(
    bytes: &[u8],
    key: PublicKey,
    tool: &str,
    path: &str,
    at: SystemTime,
) -> Result<(), String> {
    let parsed = Biscuit::from(bytes, key).map_err(|e| format!("{e:?}"))?;
    let path = path.to_owned();
    let tool = tool.to_owned();
    let mut decision = authorizer!(
        r#"
        resource({path});
        operation({tool});
        time({at});
        allow if right($o), operation($o);
        "#
    )
    .build(&parsed)
    .map_err(|e| format!("{e:?}"))?;
    decision.authorize().map_err(|e| format!("{e:?}"))?;
    Ok(())
}

fn read_varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0_u64;
    for shift in 0..10 {
        let byte = *bytes.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << (shift * 7);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

const BLOCKS_FIELD: u64 = 3;

/// Deletes one attenuation block from the protobuf, leaving everything else as is.
fn without_block(bytes: &[u8], index: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0;
    let mut seen = 0;
    while at < bytes.len() {
        let start = at;
        let tag = read_varint(bytes, &mut at).expect("a valid token");
        match tag & 7 {
            0 => {
                read_varint(bytes, &mut at).expect("a valid token");
            }
            2 => {
                let length = read_varint(bytes, &mut at).expect("a valid token") as usize;
                at += length;
            }
            other => panic!("unexpected wire type {other}"),
        }
        let is_block = tag >> 3 == BLOCKS_FIELD;
        if !(is_block && seen == index) {
            out.extend_from_slice(&bytes[start..at]);
        }
        if is_block {
            seen += 1;
        }
    }
    out
}

fn outcome(result: Result<(), String>) -> Outcome {
    Outcome::from_result(result)
}

fn widened_hop() -> Outcome {
    let token = Token::fresh(2);
    let hostile = BlockBuilder::new()
        .code(format!(
            r#"right("{TOOL}"); resource("/data/other.csv"); check if true;"#
        ))
        .unwrap();
    let biscuit = token.biscuit.append(hostile).unwrap();
    outcome(check_bytes(
        &biscuit.to_vec().unwrap(),
        token.public(),
        TOOL,
        "/data/other.csv",
        now(),
    ))
}

fn edited_link() -> Outcome {
    let token = Token::fresh(HOPS);
    let path = file_in_scope(HOPS);
    flip_each_byte(&token.bytes(), |edited| {
        check_bytes(edited, token.public(), TOOL, &path, now()).is_ok()
    })
}

fn removed_link() -> Outcome {
    let token = Token::fresh(HOPS);
    let bytes = token.bytes();
    let keep_all = without_block(&bytes, usize::MAX);
    assert_eq!(keep_all, bytes, "the edit itself must not change anything");
    outcome(check_bytes(
        &without_block(&bytes, 0),
        token.public(),
        TOOL,
        &file_in_scope(HOPS),
        now(),
    ))
}

fn outlives_parent() -> Outcome {
    let token = Token::new(2, now() + TTL);
    let later = now() + TTL + Duration::from_secs(3600);
    let hostile = BlockBuilder::new()
        .code(format!(r#"time({}); check if true;"#, unix_literal(later)))
        .unwrap();
    let biscuit = token.biscuit.append(hostile).unwrap();
    outcome(check_bytes(
        &biscuit.to_vec().unwrap(),
        token.public(),
        TOOL,
        &file_in_scope(2),
        later,
    ))
}

fn unix_literal(time: SystemTime) -> String {
    let seconds = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let days = seconds / 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    let rest = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn revoked_ancestor() -> Outcome {
    let token = Token::fresh(HOPS);
    let revoked = token.biscuit.revocation_identifiers()[0].clone();
    let presented = Biscuit::from(token.bytes(), token.public()).unwrap();
    if presented.revocation_identifiers().contains(&revoked) {
        Outcome::blocked_by_your_code(
            "revocation_identifiers gives each block's ID; you keep and check the list",
        )
    } else {
        Outcome::allowed("accepted")
    }
}

impl Format for BiscuitFormat {
    fn name(&self) -> &'static str {
        "Biscuit"
    }

    fn version(&self) -> &'static str {
        "biscuit-auth 6.0.0"
    }

    fn notes(&self) -> &'static str {
        "A bearer token by design: anyone holding it can use it and attenuate it. Paths are checked with starts_with, one of several ways to write this in Datalog. Revocation is a documented non-goal of the library, which exposes block IDs for you to check."
    }

    fn run(&self, attack: Attack) -> Outcome {
        let token = Token::fresh(HOPS);
        let bytes = token.bytes();
        let path = file_in_scope(HOPS);
        let check = |tool: &str, path: &str, at: SystemTime| {
            outcome(check_bytes(&bytes, token.public(), tool, path, at))
        };
        match attack {
            Attack::HonestRequest => check(TOOL, &path, now()),
            Attack::ArgumentOutOfScope => check(TOOL, "/etc/passwd", now()),
            Attack::PathTraversal => {
                let sneaky = format!("{}/../../../etc/passwd", scope_at(HOPS));
                let mut result = check(TOOL, &sneaky, now());
                result.detail =
                    "accepted: starts_with compares text, so normalise paths before checking"
                        .to_owned();
                result
            }
            Attack::ToolNotGranted => check("delete_file", &path, now()),
            Attack::WidenedHop => widened_hop(),
            Attack::EditedLink => edited_link(),
            Attack::RemovedLink => removed_link(),
            Attack::UnknownRoot => {
                let other = KeyPair::new_with_algorithm(Algorithm::Ed25519).public();
                outcome(check_bytes(&bytes, other, TOOL, &path, now()))
            }
            Attack::Expired => check(TOOL, &path, now() + TTL + Duration::from_secs(3600)),
            Attack::OutlivesParent => outlives_parent(),
            Attack::StolenChain => {
                let mut result = check(TOOL, &path, now());
                result.detail =
                    "accepted: a bearer token has no holder key to check, by design".to_owned();
                result
            }
            Attack::ProofForOtherArguments => {
                Outcome::not_applicable("no per-request proof; the token isn't tied to arguments")
            }
            Attack::ReplayedRequest => {
                let mut result = check(TOOL, &path, now());
                result.detail =
                    "accepted: no per-request proof, so requests can't be told apart".to_owned();
                result
            }
            Attack::RevokedAncestor => revoked_ancestor(),
            Attack::DepthLimitExceeded => {
                let long = Token::fresh(12);
                let mut result = outcome(check_bytes(
                    &long.bytes(),
                    long.public(),
                    TOOL,
                    &file_in_scope(12),
                    now(),
                ));
                result.detail = "accepted: the token can't carry a depth limit; a verifier can use block_count itself".to_owned();
                result
            }
        }
    }

    fn measure(&self, hops: usize, runs: usize) -> Timing {
        let token = Token::fresh(hops);
        let bytes = token.bytes();
        let path = file_in_scope(hops);
        let key = token.public();
        let (median_us, p99_us) = time_runs(runs, || {
            check_bytes(&bytes, key, TOOL, &path, now()).unwrap();
        });
        Timing {
            hops,
            bytes: bytes.len(),
            median_us,
            p99_us,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_written_correctly() {
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(unix_literal(time), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn removing_a_block_changes_the_bytes() {
        let bytes = Token::fresh(HOPS).bytes();
        assert_ne!(without_block(&bytes, 0), bytes);
    }
}
