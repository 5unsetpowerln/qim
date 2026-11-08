//! Command line interface.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::builder::PossibleValuesParser;
use clap::{Parser, Subcommand};
use qim::image::{self, Date};
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
        /// Base image name (see qim image build)
        #[arg(long)]
        image: String,
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
    /// Convert a guest audit log into events.json (docs/events.md)
    Convert {
        audit_log: PathBuf,
        /// Write to this file instead of standard output
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ImageCommand {
    /// Build a base image from a dated Arch Linux Archive snapshot
    Build {
        #[arg(long, default_value = "default", value_parser = PossibleValuesParser::new(profiles::names()))]
        profile: String,
        /// Snapshot date YYYY-MM-DD (default: yesterday, UTC)
        #[arg(long, value_parser = Date::parse)]
        date: Option<Date>,
        /// Image name (default: <profile>-<date>)
        #[arg(long)]
        name: Option<String>,
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
        Commands::Image { command: ImageCommand::Build { profile, date, name } } => {
            let date = date.unwrap_or_else(|| image::default_date(Date::today()));
            println!("{}", image::build(&profile, date, name.as_deref())?.display());
            Ok(ExitCode::SUCCESS)
        }
        Commands::Run { image: image_name, output, timeout, memory, cpus, command } => {
            Ok(ExitCode::from(run::run(&image_name, &command, &output, timeout, memory, cpus)?))
        }
        Commands::Convert { audit_log, output } => {
            let log = File::open(&audit_log).map_err(|error| format!("{}: {error}", audit_log.display()))?;
            let events = audit::dump(&audit::convert(BufReader::with_capacity(1 << 20, log))?);
            match output {
                Some(path) => fs::write(&path, events).map_err(|error| format!("{}: {error}", path.display()))?,
                None => io::stdout().write_all(events.as_bytes()).map_err(|error| format!("standard output: {error}"))?,
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
