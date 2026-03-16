use anyhow::Result;
use clap::Args;

use super::super::auth;
use crate::commands::Command;
use crate::commands::common::{print_json, resolve_storage};
use keynest::Keynest;

#[derive(Args)]
#[command(
    arg_required_else_help = false,
    after_help = "\
Examples:
  keynest list                                   List all secret keys
  keynest list --all                            List all secrets with timestamps
  keynest list --json                           List all keys as JSON array
  keynest list --all --json                    List all secrets with timestamps as JSON"
)]
pub struct ListCommand {
    /// Print names and secrets
    #[arg(required = false, short, long, default_value_t = false)]
    pub all: bool,

    /// Output as JSON
    #[arg(long, short = 'j')]
    pub json: bool,
}

impl Command for ListCommand {
    fn run(self, store: Option<std::path::PathBuf>) -> Result<()> {
        let password = auth::read_password()?;
        let storage = resolve_storage(store)?;
        let kn = Keynest::open_with_storage(password, storage)?;

        if self.json {
            if self.all {
                let entries: Vec<_> = kn
                    .list_all()
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "key": e.key(),
                            "updated": e.updated()
                        })
                    })
                    .collect();
                print_json(&entries);
            } else {
                let keys: Vec<&str> = kn.list().iter().map(|s| s.as_str()).collect();
                print_json(&keys);
            }
        } else if self.all {
            let entries = kn.list_all();

            if entries.is_empty() {
                println!("No secrets stored.");
                return Ok(());
            }

            let key_width = entries
                .iter()
                .map(|e| e.key().len())
                .chain(std::iter::once("Key".len()))
                .max()
                .unwrap();

            let updated_width = entries
                .iter()
                .map(|e| e.updated().len())
                .chain(std::iter::once("Updated".len()))
                .max()
                .unwrap();

            println!("{:<key_width$}  {:<updated_width$}", "Key", "Updated");
            println!("{:-<key_width$}  {:-<updated_width$}", "", "");

            for e in entries {
                println!("{:<key_width$}  {:<updated_width$}", e.key(), e.updated());
            }
        } else {
            for secret_key in kn.list() {
                println!("{secret_key}");
            }
        }

        Ok(())
    }
}
