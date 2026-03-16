use anyhow::Result;
use clap::Parser;

mod auth;
mod cli;
mod commands;

use cli::Cli;
use commands::Command;

fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.command.run(cli.store)
}
