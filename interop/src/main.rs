use clap::{CommandFactory, Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::Termination;

mod holder;
mod issuer;
mod verify;

#[derive(Parser)]
#[command(version, about, long_about = None, multicall = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Issue {
        issuer_priv: PathBuf,
        #[arg(long = "nonces")]
        nonces: Option<PathBuf>,
        #[arg(long = "time")]
        time: Option<u64>,
    },
    Present {
        holder_priv: PathBuf,
        #[arg(long = "issuer")]
        issuer_pub: PathBuf,
        #[arg(value_enum, long = "issuer-key")]
        issuer_key: KeyFetch,
        #[arg(long = "disclosure_list")]
        disclosure_list: Option<PathBuf>,
        #[arg(long = "disclosure_all")]
        disclosure_all: Option<bool>,
        #[arg(long = "time")]
        time: Option<u64>,
    },
    Verify {
        #[arg(long = "issuer")]
        issuer_pub: PathBuf,
        #[arg(value_enum, long = "issuer-key")]
        issuer_key: KeyFetch,
        #[arg(long = "audience")]
        audience: Option<String>,
        #[arg(long = "time")]
        time: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
#[repr(u8)]
pub enum KeyFetch {
    Ignore,
    Fetch,
    Cache,
}

fn main() -> std::process::ExitCode {
    let argv0 = std::env::args().next().and_then(|p| Path::new(&p).file_name().map(|f| f.to_owned())).unwrap_or_default();
    let args: Vec<String> = std::iter::once((argv0.to_string_lossy().into_owned())).chain(std::env::args().skip(1)).collect();
    let cli = Cli::parse_from(args);

    let r = match cli.command {
        Commands::Issue { issuer_priv, nonces, time } => issuer::issue(issuer_priv, nonces, time),
        Commands::Present {
            holder_priv,
            issuer_pub,
            issuer_key,
            disclosure_list,
            disclosure_all,
            time,
        } => holder::present(holder_priv, issuer_pub, issuer_key, disclosure_list, disclosure_all, time),
        Commands::Verify {
            issuer_pub,
            issuer_key,
            audience,
            time,
        } => verify::verify(issuer_pub, issuer_key, audience, time),
    };
    if let Err(e) = &r {
        eprintln!("{e}");
    }
    r.report()
}
