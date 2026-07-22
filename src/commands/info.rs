use anyhow::Result;
use clap::Args;
use std::process::ExitCode;

use super::super::auth;
use crate::commands::Command;
use crate::commands::common::{print_json, resolve_existing_storage};
use keynest::Keynest;

#[derive(Args)]
#[command(after_help = "\
Examples:
  keynest info                                   Show keystore information (version, algorithm, KDF parameters)
  keynest info --json                            Output information as JSON
  keynest info --no-decrypt                      Show header metadata without the password (omits created date and secret count)")]
pub struct InfoCommand {
    /// Output as JSON
    #[arg(long, short = 'j')]
    pub json: bool,

    /// Show header metadata without decrypting (no password required)
    #[arg(long = "no-decrypt")]
    pub no_decrypt: bool,
}

impl Command for InfoCommand {
    fn run(self, store: Option<std::path::PathBuf>) -> Result<ExitCode> {
        let storage = resolve_existing_storage(store)?;

        if self.no_decrypt {
            let info = Keynest::inspect_header(&storage)?;
            if self.json {
                print_json(&info);
            } else {
                println!("{info}");
            }
            return Ok(ExitCode::SUCCESS);
        }

        let password = auth::read_password()?;
        let kn = Keynest::open_with_storage(password, storage)?;
        let info = kn.info()?;

        if self.json {
            print_json(&info);
        } else {
            println!("{info}");
        }

        Ok(ExitCode::SUCCESS)
    }
}
