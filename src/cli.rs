use clap::{Parser, Subcommand};

use crate::commands::{
    Command, exec::ExecCommand, export::ExportCommand, get::GetCommand, import::ImportCommand,
    info::InfoCommand, init::InitCommand, list::ListCommand, rekey::RekeyCommand,
    remove::RemoveCommand, set::SetCommand, update::UpdateCommand,
};

#[derive(Parser)]
#[command(name = "keynest")]
#[command(
    version,
    about = "Simple, offline, cross-platform secrets manager written in Rust."
)]
pub struct Cli {
    /// Path to the keynest storage file
    #[arg(long, global = true, value_name = "PATH", env = "KEYNEST_PATH")]
    pub store: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Init(InitCommand),
    Get(GetCommand),
    Set(SetCommand),
    Update(UpdateCommand),
    List(ListCommand),
    Remove(RemoveCommand),
    Info(InfoCommand),
    Rekey(RekeyCommand),
    Exec(ExecCommand),
    Import(ImportCommand),
    Export(ExportCommand),
}

impl Command for Commands {
    fn run(self, store: Option<std::path::PathBuf>) -> anyhow::Result<()> {
        match self {
            Commands::Init(cmd) => cmd.run(store),
            Commands::Get(cmd) => cmd.run(store),
            Commands::Set(cmd) => cmd.run(store),
            Commands::Update(cmd) => cmd.run(store),
            Commands::List(cmd) => cmd.run(store),
            Commands::Remove(cmd) => cmd.run(store),
            Commands::Info(cmd) => cmd.run(store),
            Commands::Rekey(cmd) => cmd.run(store),
            Commands::Exec(cmd) => cmd.run(store),
            Commands::Import(cmd) => cmd.run(store),
            Commands::Export(cmd) => cmd.run(store),
        }
    }
}
