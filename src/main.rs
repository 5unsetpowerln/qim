//! Command line interface.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::builder::PossibleValuesParser;
use clap::{Parser, Subcommand};
use qim::image;
use qim::{audit, profiles, run};

#[derive(Parser)]
#[command(name = "qim", about = "Quarantined Installation Monitor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage base guest images
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Run a command in a guest and collect what it did
    Run {
        /// The guest's profile; its image for the host's current pacman state is built first if needed
        #[arg(long, default_value = "default", value_parser = PossibleValuesParser::new(profiles::names()))]
        profile: String,
        /// Output directory (must not exist)
        #[arg(long)]
        output: PathBuf,
        /// Seconds before the command is killed
        #[arg(long, default_value_t = 3600)]
        timeout: u64,
        /// Guest memory in MiB
        #[arg(long, default_value_t = 8192)]
        memory: u64,
        #[arg(long, default_value_t = 8)]
        cpus: u32,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
    /// Convert a guest audit log and the host's network records into events.json (docs/events.md)
    Convert {
        audit_log: PathBuf,
        /// The DNS record (dns.log of a run); without it, the dns list is empty
        #[arg(long, value_name = "FILE")]
        dns: Option<PathBuf>,
        /// The packet record (packets.log of a run); without it, the wire list is empty
        #[arg(long, value_name = "FILE")]
        packets: Option<PathBuf>,
        /// Write to this file instead of standard output
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ImageCommand {
    /// Build the base image of a profile for the host's current pacman state (if it does not exist yet)
    Build {
        #[arg(long, default_value = "default", value_parser = PossibleValuesParser::new(profiles::names()))]
        profile: String,
    },
}

fn main() -> ExitCode {
    image::catch_signals();
    match execute(Cli::parse().command) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("qim: {message}");
            let Some(signal) = image::caught_signal() else {
                return ExitCode::FAILURE;
            };
            // Everything is cleaned up; die by the signal so that the caller sees it,
            // as Python does after a KeyboardInterrupt.
            // SAFETY: restoring the default action and raising a signal have no preconditions.
            unsafe {
                libc::signal(signal, libc::SIG_DFL);
                libc::raise(signal);
            }
            // Still here as PID 1 of a container, which ignores default-action signals.
            ExitCode::from(128 + signal as u8)
        }
    }
}

fn execute(command: Commands) -> Result<ExitCode, String> {
    match command {
        Commands::Image { command: ImageCommand::Build { profile } } => {
            println!("{}", image::ensure(&profile)?.display());
            Ok(ExitCode::SUCCESS)
        }
        Commands::Run { profile, output, timeout, memory, cpus, command } => {
            let base = image::ensure(&profile)?;
            Ok(ExitCode::from(run::run(&base, &command, &output, timeout, memory, cpus)?))
        }
        Commands::Convert { audit_log, dns, packets, output } => {
            let open = |path: &Path| {
                let file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
                Ok::<_, String>(BufReader::with_capacity(1 << 20, file))
            };
            let dns = dns.as_deref().map(open).transpose()?;
            let packets = packets.as_deref().map(open).transpose()?;
            let events = audit::dump(&audit::convert(open(&audit_log)?, dns, packets)?);
            match output {
                Some(path) => fs::write(&path, events).map_err(|error| format!("{}: {error}", path.display()))?,
                None => io::stdout().write_all(events.as_bytes()).map_err(|error| format!("standard output: {error}"))?,
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
