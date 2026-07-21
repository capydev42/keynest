use anyhow::Result;
use clap::Parser;
use std::process::ExitCode;

mod auth;
mod cli;
mod commands;

use cli::Cli;
use commands::Command;

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();
    cli.command.run(cli.store)
}
