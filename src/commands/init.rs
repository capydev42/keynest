use anyhow::Result;
use clap::Args;

use super::super::auth;
use crate::commands::Command;
use crate::commands::common::{Argon2Args, resolve_storage};
use keynest::Keynest;

#[derive(Args)]
#[command(after_help = "\
Examples:
  keynest init                                      Initialize a new keystore with default settings
  keynest init --argon-mem 131072                 Initialize with higher memory cost (128 MiB)
  keynest init --argon-time 5 --argon-mem 65536   Initialize with custom Argon2 parameters")]
pub struct InitCommand {
    #[command(flatten)]
    pub argon2: Argon2Args,
}

impl Command for InitCommand {
    fn run(self, store: Option<std::path::PathBuf>) -> Result<()> {
        let password = auth::read_password()?;
        let kdf = self.argon2.to_kdf_params()?;
        let storage = resolve_storage(store)?;

        Keynest::init_with_storage_and_kdf(password, storage, kdf)?;
        println!("keystore initialized");

        Ok(())
    }
}
