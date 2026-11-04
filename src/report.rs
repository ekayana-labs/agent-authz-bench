//! Writes results as JSON and Markdown. There are no scores or rankings on purpose.

use serde::{Deserialize, Serialize};

use crate::model::{ATTACKS, Attack, EnforcedBy, Format, Outcome, Timing, Verdict, base64_len};

pub const HOPS: [usize; 4] = [1, 3, 5, 8];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatResult {
    pub name: String,
    pub version: String,
    pub notes: String,
    pub runs: usize,
    pub outcomes: Vec<(Attack, Outcome)>,
    pub timings: Vec<Timing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub date: String,
    pub machine: String,
    pub os: String,
    pub rustc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Results {
    pub environment: Environment,
    pub formats: Vec<FormatResult>,
}

pub fn run_format(format: &dyn Format, runs: usize) -> FormatResult {
    FormatResult {
        name: format.name().to_owned(),
        version: format.version().to_owned(),
        notes: format.notes().to_owned(),
        runs,
        outcomes: ATTACKS
            .iter()
            .map(|attack| (*attack, format.run(*attack)))
            .collect(),
        timings: HOPS
            .iter()
            .map(|hops| format.measure(*hops, runs))
            .collect(),
    }
}

fn cell(outcome: &Outcome) -> &'static str {
    match (outcome.verdict, outcome.enforced_by) {
        (Verdict::Allowed, _) => "Allowed",
        (Verdict::Blocked, EnforcedBy::YourCode) => "Blocked, with your code",
        (Verdict::Blocked, _) => "Blocked",
        (Verdict::NotApplicable, _) => "n/a",
    }
}

/// Links, how many PERMIT vectors have that many links, and their median chain plus proof size.
const IETF_SIZES: [(usize, usize, usize); 4] =
    [(1, 17, 1201), (2, 30, 2369), (3, 6, 3109), (9, 1, 7675)];

fn ietf_section() -> String {
    let mut out = String::from(
        "\n## IETF draft format, size only\n\ndraft-niyikiza-oauth-attenuating-agent-tokens-02 isn't in the tables above. A verifier we wrote would test our reading of the draft rather than the format, and independent verifiers aren't wired in yet. These are chain plus proof sizes in compact JWT form, from the draft's PERMIT vectors in Tenuo's repository (`tests/vectors/aat-jws-vectors.json` at commit 597d88c4). The vectors use varied limits, so they don't line up row by row with the table above.\n\n| Links | Vectors | Median size |\n|---:|---:|---:|\n",
    );
    for (links, vectors, median) in IETF_SIZES {
        out.push_str(&format!("| {links} | {vectors} | {median} bytes |\n"));
    }
    out
}

const LONGEST_WORD: usize = 60;

/// Post-quantum DIDs run to thousands of characters and say nothing useful in a table.
fn shorten(word: &str) -> String {
    if word.chars().count() <= LONGEST_WORD {
        return word.to_owned();
    }
    let start: String = word.chars().take(24).collect();
    format!("{start}…")
}

fn escape(text: &str) -> String {
    let short: Vec<String> = text.split(' ').map(shorten).collect();
    short.join(" ").replace('|', "\\|").replace('\n', " ")
}

pub fn to_markdown(results: &Results) -> String {
    let mut out = String::from("# Results\n\n");
    let env = &results.environment;
    out.push_str(&format!(
        "Run on {} on {}, {}, with {}. These are not scores: read [METHOD.md](METHOD.md) first.\n\n",
        env.date, env.machine, env.os, env.rustc
    ));

    out.push_str("## Attacks\n\n| Attack |");
    for format in &results.formats {
        out.push_str(&format!(" {} |", format.name));
    }
    out.push_str("\n|---|");
    out.push_str(&"---|".repeat(results.formats.len()));
    out.push('\n');
    for (row, attack) in ATTACKS.iter().enumerate() {
        out.push_str(&format!("| {} |", attack.title()));
        for format in &results.formats {
            out.push_str(&format!(" {} |", cell(&format.outcomes[row].1)));
        }
        out.push('\n');
    }

    out.push_str(
        "\n## Size and check time\n\nThe same one-tool scenario in each format, with minimal limits. Times cover decoding, every signature and the policy check, and exclude the network. Size is everything the verifier needs, as base64. Biscuit has no per-request proof, so it checks one signature fewer and sends less.\n\n",
    );
    out.push_str(
        "| Format | Hops | Size | Median | 99th percentile | Runs |\n|---|---:|---:|---:|---:|---:|\n",
    );
    for format in &results.formats {
        for timing in &format.timings {
            out.push_str(&format!(
                "| {} | {} | {} bytes | {:.0} µs | {:.0} µs | {} |\n",
                format.name,
                timing.hops,
                base64_len(timing.bytes),
                timing.median_us,
                timing.p99_us,
                format.runs
            ));
        }
    }

    out.push_str(&ietf_section());

    out.push_str("\n## Why each result happened\n");
    for format in &results.formats {
        out.push_str(&format!(
            "\n### {} ({})\n\n{}\n\n| Attack | Result | Reason |\n|---|---|---|\n",
            format.name, format.version, format.notes
        ));
        for (attack, outcome) in &format.outcomes {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                attack.title(),
                cell(outcome),
                escape(&outcome.detail)
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Results {
        Results {
            environment: Environment {
                date: "2026-11-04".into(),
                machine: "test".into(),
                os: "test".into(),
                rustc: "test".into(),
            },
            formats: vec![FormatResult {
                name: "F".into(),
                version: "1".into(),
                notes: "note".into(),
                runs: 1,
                outcomes: ATTACKS
                    .iter()
                    .map(|attack| (*attack, Outcome::blocked("a | b")))
                    .collect(),
                timings: vec![Timing {
                    hops: 3,
                    bytes: 3,
                    median_us: 1.0,
                    p99_us: 2.0,
                }],
            }],
        }
    }

    #[test]
    fn the_report_has_every_attack_and_no_ranking() {
        let text = to_markdown(&sample());
        for attack in ATTACKS {
            assert!(text.contains(attack.title()));
        }
        assert!(!text.to_lowercase().contains("score:"));
        assert!(!text.to_lowercase().contains("winner"));
    }

    #[test]
    fn table_separators_are_escaped() {
        assert!(to_markdown(&sample()).contains("a \\| b"));
    }

    #[test]
    fn very_long_words_are_cut_and_others_kept() {
        let did = format!("did:key:{}", "z".repeat(5000));
        let short = escape(&format!("audience {did} is wrong"));
        assert!(short.starts_with("audience did:key:"));
        assert!(short.ends_with("… is wrong"));
        assert!(short.len() < 60);
    }

    #[test]
    fn cells_say_who_enforced_it() {
        assert_eq!(cell(&Outcome::blocked("x")), "Blocked");
        assert_eq!(
            cell(&Outcome::blocked_by_your_code("x")),
            "Blocked, with your code"
        );
        assert_eq!(cell(&Outcome::allowed("x")), "Allowed");
        assert_eq!(cell(&Outcome::not_applicable("x")), "n/a");
    }
}
