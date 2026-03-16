use anyhow::Result;
use clap::Args;

use super::super::auth;
use crate::commands::Command;
use crate::commands::common::{print_json, resolve_storage};
use keynest::Keynest;

#[derive(Args)]
#[command(after_help = "\
Examples:
  keynest info                                   Show keystore information (version, algorithm, KDF parameters)
  keynest info --json                            Output information as JSON")]
pub struct InfoCommand {
    /// Output as JSON
    #[arg(long, short = 'j')]
    pub json: bool,
}

impl Command for InfoCommand {
    fn run(self, store: Option<std::path::PathBuf>) -> Result<()> {
        let password = auth::read_password()?;
        let storage = resolve_storage(store)?;
        let kn = Keynest::open_with_storage(password, storage.clone())?;
        let info = kn.info()?;

        if self.json {
            print_json(&info);
        } else {
            println!("{info}");
        }

        Ok(())
    }
}
