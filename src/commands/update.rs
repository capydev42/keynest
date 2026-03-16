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
  keynest update api_key \"new_secret\"          Update an existing secret value"
)]
pub struct UpdateCommand {
    pub key: String,
    pub new_value: String,
}

impl Command for UpdateCommand {
    fn run(self, store: Option<std::path::PathBuf>) -> Result<()> {
        let password = auth::read_password()?;
        let storage = resolve_storage(store)?;
        let mut kn = Keynest::open_with_storage(password, storage)?;
        kn.update(&self.key, &self.new_value)?;
        kn.save()?;
        println!("secret '{}' updated.", self.key);

        Ok(())
    }
}
