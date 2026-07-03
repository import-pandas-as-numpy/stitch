#![forbid(unsafe_code)]

mod cli;
mod event;
mod input;
mod output;
mod query;
mod runtime;
mod sigma;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::input::DiscoveryConfig;
use crate::runtime::{CommandOutcome, RunError};

fn main() -> ExitCode {
    match run() {
        Ok(outcome) => {
            if let Some(message) = outcome.message {
                println!("{message}");
            }
            if let Some(diagnostic) = outcome.diagnostic {
                eprintln!("{diagnostic}");
            }

            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<CommandOutcome, RunError> {
    let cli = Cli::parse();
    let discovery = DiscoveryConfig::try_from(&cli.common)?;

    match &cli.command {
        Command::Hunt(command) => runtime::run_hunt(command, &discovery, &cli.common),
        Command::Search(command) => runtime::run_search(command, &discovery, &cli.common),
        Command::Dump(command) => runtime::run_dump(command, &discovery, &cli.common),
    }
}
