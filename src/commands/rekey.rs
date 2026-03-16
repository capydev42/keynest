use anyhow::Result;
use clap::Args;

use super::super::auth;
use crate::commands::Command;
use crate::commands::common::{Argon2Args, resolve_storage};
use keynest::Keynest;

#[derive(Args)]
#[command(after_help = "\
Examples:
  keynest rekey                                  Change the keystore password
  keynest rekey --argon-mem 131072              Change password and upgrade memory cost")]
pub struct RekeyCommand {
    #[command(flatten)]
    pub argon2: Argon2Args,
}

impl Command for RekeyCommand {
    fn run(self, store: Option<std::path::PathBuf>) -> Result<()> {
        let password = auth::read_password()?;
        let storage = resolve_storage(store)?;
        let mut kn = Keynest::open_with_storage(password, storage)?;

        let new_password = auth::read_new_password_with_confirmation()?;
        let kdf = self.argon2.to_kdf_params()?;
        kn.rekey(new_password, kdf)?;

        println!("store successfully rekeyed");

        Ok(())
    }
}
