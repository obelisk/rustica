use anyhow::{Context, Result};
use cargo_lock::Lockfile;
use chrono::{DateTime, Utc};
use clap::Parser;
use reqwest::Client;
use serde::Deserialize;
use std::cmp::Ordering;
use std::path::PathBuf;
use std::process::ExitCode;
use tokio::time::{sleep, Duration};

const USER_AGENT: &str = "cargo-lock-age-check/1.0";

// All these packages if they are too new or not found
const EXEMPTIONS: &[&str] = &["rustica", "rustica-agent", "rustica-agent-cli", "rustica-agent-gui", "rustica-tools", "sshcerts"];

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Path to Cargo.lock
    cargo_lock: PathBuf,

    /// Return non-zero if any package is older than this many days
    #[arg(long)]
    min_age_days: Option<i64>,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Include crates whose publish date could not be determined
    #[arg(long)]
    include_missing: bool,
}

#[derive(Debug)]
struct PackageInfo {
    name: String,
    version: String,
    published_at: Option<DateTime<Utc>>,
}

impl PackageInfo {
    fn age_days(&self) -> Option<i64> {
        self.published_at.map(|published| {
            let now = Utc::now();
            (now - published).num_days()
        })
    }
}

#[derive(Debug, Deserialize)]
struct CratesIoResponse {
    version: VersionInfo,
}

#[derive(Debug, Deserialize)]
struct VersionInfo {
    created_at: String,
}

async fn fetch_publish_date(
    client: &Client,
    crate_name: &str,
    version: &str,
) -> Option<DateTime<Utc>> {
    let url = format!("https://crates.io/api/v1/crates/{}/{}", crate_name, version);

    let response = client.get(url).send().await.ok()?;

    if !response.status().is_success() {
        return None;
    }

    let body: CratesIoResponse = response.json().await.ok()?;

    DateTime::parse_from_rfc3339(&body.version.created_at)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(has_old_packages) => {
            if has_old_packages {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("ERROR: {:#}", err);
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<bool> {
    let args = Args::parse();

    let lockfile = Lockfile::load(&args.cargo_lock)
        .with_context(|| format!("failed to load lockfile: {}", args.cargo_lock.display()))?;

    let client = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(args.timeout))
        .build()
        .with_context(|| "failed to build HTTP client".to_string())?;

    let mut packages = Vec::new();

    println!(
        "Checking publish dates for {} packages from {}...",
        lockfile.packages.len(),
        args.cargo_lock.display()
    );

    for pkg in &lockfile.packages {
        println!("Checking crate {} {}", pkg.name, pkg.version);

        if EXEMPTIONS.contains(&pkg.name.as_str()) {
            println!("  Skipping {} since it's on the exemption list", pkg.name);
            continue;
        }

        let name = pkg.name.to_string();
        let version = pkg.version.to_string();

        let published_at = fetch_publish_date(&client, &name, &version).await;

        packages.push(PackageInfo {
            name,
            version,
            published_at,
        });

        // Try to avoid crates.io rate limits.
        sleep(Duration::from_millis(25)).await;
    }

    if !args.include_missing {
        packages.retain(|p| p.published_at.is_some());
    }

    packages.sort_by(|a, b| match (&a.published_at, &b.published_at) {
        (Some(a_dt), Some(b_dt)) => a_dt.cmp(b_dt),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    });

    println!();

    for pkg in &packages {
        match pkg.published_at {
            Some(published_at) => {
                let age = pkg.age_days().unwrap_or(-1);

                println!(
                    "{} | {:>14} | {} {}",
                    published_at.date_naive(),
                    format!("{age} days old"),
                    pkg.name,
                    pkg.version
                );
            }
            None => {
                println!("UNKNOWN DATE | ??? days old | {} {}", pkg.name, pkg.version);
            }
        }
    }

    let mut too_old = Vec::new();

    if let Some(min_age_days) = args.min_age_days {
        for pkg in &packages {
            if let Some(age_days) = pkg.age_days() {
                if age_days < min_age_days {
                    too_old.push((pkg, age_days));
                }
            } else {
                // If we don't know the age, and --include-missing is set, consider it too new
                if args.include_missing {
                    too_old.push((pkg, -1));
                }
            }
        }
    }

    if !too_old.is_empty() {
        eprintln!(
            "\nERROR: {} package(s) newer than --min-age-days={}\n",
            too_old.len(),
            args.min_age_days.unwrap()
        );

        for (pkg, age_days) in &too_old {
            eprintln!("  {} {} ({} days old)", pkg.name, pkg.version, age_days);
        }

        return Ok(true);
    }

    Ok(false)
}
