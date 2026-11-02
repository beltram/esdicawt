//! The `issue`, `present`, `verify` and `target` programs described in `draft-ietf-spice-sd-cwt/interop/INTEROP.md`.
//!
//! A single binary called either through a symlink named after the program (multicall, as the interop harness does)
//! or with the program as first argument, e.g. `interop present holder_priv.pem --issuer issuer_pub.pem`.

use clap::{Args, Parser, Subcommand};
use std::{path::PathBuf, process::ExitCode};

mod holder;
mod issuer;
mod keys;
mod token;
mod verify;

pub const TARGET: &str = "esdicawt";

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Issues a SD-CWT from the claims set (CBOR map) on stdin
    Issue(IssueArgs),
    /// Presents the SD-CWT on stdin in a SD-KBT
    Present(PresentArgs),
    /// Verifies the SD-KBT on stdin and outputs the validated claims set
    Verify(VerifyArgs),
    /// Outputs the short name of the implementation
    Target,
}

#[derive(Args)]
pub struct IssueArgs {
    /// PEM-encoded private key of the Issuer (Ed25519, P-256 or P-384)
    pub issuer_priv: PathBuf,
    /// CSV of `hex(sha256(cbor([key, value])))` (or a decoy index) and the salt to use for it
    #[arg(long)]
    pub nonces: Option<PathBuf>,
    /// Verifies the time claims of the claims set as if it were this time (seconds since epoch)
    #[arg(long)]
    pub time: Option<u64>,
    /// Key identifier, in the protected header (not part of INTEROP.md)
    #[arg(long, default_value = "https://issuer.example/cose-key3")]
    pub kid: String,
}

#[derive(Args)]
pub struct PresentArgs {
    /// PEM-encoded private key of the Holder (Ed25519, P-256 or P-384)
    pub holder_priv: PathBuf,
    /// PEM-encoded public key of the Issuer
    #[arg(long)]
    pub issuer: Option<PathBuf>,
    #[arg(value_enum, long = "issuer-key")]
    pub issuer_key: Option<KeyFetch>,
    /// CBOR array of the salts of the disclosures to present
    #[arg(long = "disclosure_list", alias = "disclosure-list")]
    pub disclosure_list: Option<PathBuf>,
    /// Presents all the disclosures
    #[arg(long = "disclose_all", alias = "disclosure_all")]
    pub disclose_all: bool,
    /// CBOR array of the salts of the disclosures to AEAD encrypt (unsupported)
    #[arg(long = "encrypt_list")]
    pub encrypt_list: Option<PathBuf>,
    #[arg(long = "aead-key")]
    pub aead_key: Option<PathBuf>,
    #[arg(long = "aead-key-context")]
    pub aead_key_context: Option<String>,
    #[arg(long = "aead-nonces")]
    pub aead_nonces: Option<PathBuf>,
    /// Audience of the SD-KBT
    #[arg(long, default_value = "https://verifier.example/app")]
    pub audience: String,
    /// Verifies the time claims and issues the SD-KBT as if it were this time (seconds since epoch)
    #[arg(long)]
    pub time: Option<u64>,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// PEM-encoded public key of the Issuer
    #[arg(long)]
    pub issuer: Option<PathBuf>,
    #[arg(value_enum, long = "issuer-key")]
    pub issuer_key: Option<KeyFetch>,
    /// Expected audience of the SD-KBT
    #[arg(long)]
    pub audience: Option<String>,
    /// Hex encoded AEAD key, may be repeated (unsupported)
    #[arg(long = "aead-key")]
    pub aead_key: Vec<PathBuf>,
    /// Verifies the time claims as if it were this time (seconds since epoch)
    #[arg(long)]
    pub time: Option<u64>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum KeyFetch {
    Ignore,
    Fetch,
    Cache,
}

/// Exit code when the input is invalid or a verification fails
const EXIT_FAILURE: u8 = 1;
/// Exit code when the requested feature is not supported by esdicawt
const EXIT_UNSUPPORTED: u8 = 2;

fn main() -> ExitCode {
    let mut args = std::env::args_os().collect::<Vec<_>>();
    let argv0 = args
        .first()
        .and_then(|p| std::path::Path::new(p).file_name())
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    // multicall: called through a symlink named after the program
    if let (true, Some(first)) = (["issue", "present", "verify", "target"].contains(&argv0.as_str()), args.first_mut()) {
        *first = argv0.into();
        args.insert(0, "interop".into());
    }
    let cli = Cli::parse_from(args);

    let result = match cli.command {
        Commands::Issue(args) => issuer::issue(args),
        Commands::Present(args) => holder::present(args),
        Commands::Verify(args) => verify::verify(args),
        Commands::Target => token::write_stdout(TARGET.as_bytes()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            if e.downcast_ref::<token::Unsupported>().is_some() {
                ExitCode::from(EXIT_UNSUPPORTED)
            } else {
                ExitCode::from(EXIT_FAILURE)
            }
        }
    }
}
