use anyhow::Result;
use clap::Args;

use super::super::auth;
use crate::commands::Command;
use crate::commands::common::resolve_storage;
use keynest::Keynest;

#[derive(Args)]
#[command(
    arg_required_else_help = true,
    after_help = "\
Examples:
  keynest remove api_key                         Remove a secret from the keystore"
)]
pub struct RemoveCommand {
    pub key: String,
}

impl Command for RemoveCommand {
    fn run(self, store: Option<std::path::PathBuf>) -> Result<()> {
        let password = auth::read_password()?;
        let storage = resolve_storage(store)?;
        let mut kn = Keynest::open_with_storage(password, storage)?;
        kn.remove(&self.key)?;
        kn.save()?;
        println!("Removed '{}'", self.key);

        Ok(())
    }
}
