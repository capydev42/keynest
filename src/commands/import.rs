use anyhow::Result;
use clap::{Args, ValueEnum};
use std::collections::HashMap;
use std::io::Cursor;
use std::path::PathBuf;

use super::super::auth;
use crate::commands::Command;
use crate::commands::common::resolve_storage;
use dotenvy::from_read_iter as parse_env_dotenv;
use keynest::Keynest;

#[derive(Debug, Clone, ValueEnum)]
pub enum ImportFormat {
    Env,
    Json,
}

impl ImportFormat {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "env" => Some(ImportFormat::Env),
            "json" => Some(ImportFormat::Json),
            _ => None,
        }
    }
}

#[derive(Args)]
#[command(
    arg_required_else_help = true,
    after_help = "\
 Examples:
   keynest import .env                     Import from .env file
   keynest import secrets.json             Import from JSON file
   keynest import --format env file.txt     Import from file with explicit format
   keynest import --overwrite .env          Overwrite existing secrets
   keynest import --prefix API_ .env        Only import secrets with this prefix"
)]
pub struct ImportCommand {
    /// File to import (format auto-detected from extension)
    pub file: PathBuf,

    /// Import format (env or json)
    #[arg(long = "format", value_enum)]
    pub format: Option<ImportFormat>,

    /// Overwrite existing secrets
    #[arg(long = "overwrite")]
    pub overwrite: bool,

    /// Only import secrets with this prefix
    #[arg(long = "prefix")]
    pub prefix: Option<String>,
}

impl Command for ImportCommand {
    fn run(self, store: Option<PathBuf>) -> Result<()> {
        let format = self
            .format
            .or_else(|| {
                self.file
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .and_then(ImportFormat::from_extension)
            })
            .ok_or_else(|| {
                anyhow::anyhow!("cannot detect format from file extension; use --format")
            })?;

        let content = std::fs::read_to_string(&self.file)?;

        let secrets: HashMap<String, String> = match format {
            ImportFormat::Env => {
                let cursor = Cursor::new(content.as_bytes());
                let iter = parse_env_dotenv(cursor);
                iter.collect::<Result<Vec<_>, _>>()?.into_iter().collect()
            }
            ImportFormat::Json => serde_json::from_str(&content)?,
        };

        if secrets.is_empty() {
            println!("No secrets found in file");
            return Ok(());
        }

        let password = auth::read_password()?;
        let storage = resolve_storage(store)?;
        let mut kn = Keynest::open_with_storage(password, storage)?;

        let mut imported = 0;
        let mut skipped = 0;
        let mut filtered = 0;

        for (key, value) in secrets {
            if let Some(ref prefix) = self.prefix {
                if !key.starts_with(prefix) {
                    filtered += 1;
                    continue;
                }
            }

            if kn.get(&key).is_some() {
                if self.overwrite {
                    kn.update(&key, &value)?;
                    imported += 1;
                } else {
                    skipped += 1;
                }
            } else {
                kn.set(&key, &value)?;
                imported += 1;
            }
        }

        kn.save()?;

        println!("Imported {imported} secret(s)");
        if skipped > 0 {
            println!("Skipped {skipped} existing secret(s) (use --overwrite to replace)");
        }
        if filtered > 0 {
            println!("Filtered {filtered} secret(s) by prefix");
        }

        Ok(())
    }
}
