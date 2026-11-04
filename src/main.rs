use std::process::Command;

use agent_authz_bench::formats::biscuit::BiscuitFormat;
use agent_authz_bench::formats::tenuo::Tenuo;
use agent_authz_bench::formats::ucan::Ucan;
use agent_authz_bench::model::Format;
use agent_authz_bench::report::{Environment, Results, run_format, to_markdown};
use pq_ucan::crypto::Algorithm;
use pq_ucan::crypto::ed25519::Ed25519Keypair;
use pq_ucan::crypto::ml_dsa::MlDsaKeypair;

const RUNS: usize = 3000;
const SLOW_RUNS: usize = 300;

fn output_of(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn machine() -> String {
    let brand = output_of("sysctl", &["-n", "machdep.cpu.brand_string"]);
    if brand == "unknown" {
        output_of("uname", &["-m"])
    } else {
        brand
    }
}

fn main() -> std::io::Result<()> {
    let out_dir = std::env::args().nth(1).unwrap_or_else(|| ".".to_owned());
    let ed25519 = Ucan {
        label: "UCAN Ed25519",
        generate: || Ed25519Keypair::generate(&mut pq_ucan::rng::system()),
    };
    let ml_dsa = Ucan {
        label: "UCAN ML-DSA-65",
        generate: || MlDsaKeypair::generate(Algorithm::MlDsa65).unwrap(),
    };
    let fast: [&dyn Format; 3] = [&BiscuitFormat, &Tenuo, &ed25519];

    let mut formats: Vec<_> = fast.iter().map(|f| run_format(*f, RUNS)).collect();
    formats.push(run_format(&ml_dsa, SLOW_RUNS));

    let results = Results {
        environment: Environment {
            date: output_of("date", &["+%Y-%m-%d"]),
            machine: machine(),
            os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            rustc: output_of("rustc", &["--version"]),
        },
        formats,
    };

    std::fs::write(
        format!("{out_dir}/results.json"),
        serde_json::to_string_pretty(&results)?,
    )?;
    std::fs::write(format!("{out_dir}/RESULTS.md"), to_markdown(&results))?;
    println!("wrote {out_dir}/RESULTS.md and {out_dir}/results.json");
    Ok(())
}
