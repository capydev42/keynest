use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use super::super::auth;
use crate::commands::Command;
use crate::commands::common::resolve_storage;
use keynest::Keynest;

#[derive(Args)]
#[command(
    arg_required_else_help = false,
    after_help = "\
Examples:
  keynest set api_key \"secret123\"              Store a secret from command line argument
  keynest set api_key --file secret.txt         Store a secret from a file
  keynest set api_key --prompt                   Store a secret from interactive prompt"
)]
pub struct SetCommand {
    pub key: String,
    pub value: Option<String>,

    /// Prompt for secret value
    #[arg(long = "prompt")]
    pub prompt: bool,

    /// Read secret from file
    #[arg(long = "file")]
    pub file: Option<PathBuf>,
}

impl Command for SetCommand {
    fn run(self, store: Option<std::path::PathBuf>) -> Result<()> {
        if self.prompt && self.value.is_some() {
            anyhow::bail!("cannot use value argument together with --prompt");
        }

        let secret = if self.prompt {
            rpassword::prompt_password("Secret: ")?
        } else if let Some(path) = self.file {
            std::fs::read_to_string(&path)?
        } else {
            self.value.ok_or_else(|| {
                anyhow::anyhow!("secret value required: provide as argument, --prompt, or --file")
            })?
        };

        if secret.trim().is_empty() {
            anyhow::bail!("secret value cannot be empty");
        }

        let password = auth::read_password()?;
        let storage = resolve_storage(store)?;
        let mut kn = Keynest::open_with_storage(password, storage)?;
        kn.set(&self.key, &secret)?;
        kn.save()?;
        println!("stored secret '{}'", self.key);

        Ok(())
    }
}
