use anyhow::Result;
use clap::Args;

use super::super::auth;
use crate::commands::Command;
use crate::commands::common::{copy_to_clipboard, print_json, print_plain, resolve_storage};
use keynest::Keynest;

#[derive(Args)]
#[command(
    arg_required_else_help = true,
    after_help = "\
Examples:
  keynest get api_key                              Display the secret value on stdout
  keynest get api_key --clip                       Copy the secret to clipboard (auto-clears after 15 seconds)
  keynest get api_key -c --timeout 30              Copy the secret to clipboard with custom timeout
  keynest get api_key --json                       Output the secret as JSON (includes key and value)"
)]
pub struct GetCommand {
    pub key: String,

    /// Copy secret to clipboard
    #[arg(long, short = 'c')]
    pub clip: bool,

    /// Seconds before clipboard is cleared (default: 15, min: 1)
    #[arg(long = "timeout", default_value_t = 15)]
    pub timeout: u64,

    /// Output as JSON
    #[arg(long, short = 'j')]
    pub json: bool,
}

impl Command for GetCommand {
    fn run(self, store: Option<std::path::PathBuf>) -> Result<()> {
        if self.timeout == 0 {
            anyhow::bail!("timeout must be greater than 0");
        }

        let password = auth::read_password()?;
        let storage = resolve_storage(store)?;
        let kn = Keynest::open_with_storage(password, storage)?;

        match kn.get(&self.key) {
            Some(secret) => {
                if self.clip {
                    copy_to_clipboard(secret, self.timeout)?;
                } else if self.json {
                    print_json(&serde_json::json!({"key": self.key, "value": secret}));
                } else {
                    print_plain(&secret);
                }
            }
            None => {
                eprintln!("key not found: {}", self.key);
                std::process::exit(1);
            }
        }

        Ok(())
    }
}
