use anyhow::Result;
use clap::{Args, ValueEnum};
use std::collections::HashMap;
use std::fmt::Write;
use std::path::PathBuf;

use super::super::auth;
use crate::commands::Command;
use crate::commands::common::resolve_storage;
use keynest::Keynest;

#[derive(Debug, Clone, ValueEnum)]
pub enum ExportFormat {
    Env,
    Json,
}

impl ExportFormat {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "env" => Some(ExportFormat::Env),
            "json" => Some(ExportFormat::Json),
            _ => None,
        }
    }
}

#[derive(Args)]
#[command(
    arg_required_else_help = false,
    after_help = "\
 Examples:
   keynest export                         Export all secrets to stdout (JSON)
   keynest export .env                    Export as .env file (format from extension)
   keynest export --format env            Export as env format to stdout
   keynest export --format json file.json Export as JSON to file"
)]
pub struct ExportCommand {
    /// Output file (format auto-detected from extension, or use --format)
    pub file: Option<PathBuf>,

    /// Export format (env or json)
    #[arg(long = "format", value_enum)]
    pub format: Option<ExportFormat>,

    /// Only export secrets with this prefix
    #[arg(long = "prefix")]
    pub prefix: Option<String>,
}

impl Command for ExportCommand {
    fn run(self, store: Option<PathBuf>) -> Result<()> {
        let password = auth::read_password()?;
        let storage = resolve_storage(store)?;
        let kn = Keynest::open_with_storage(password, storage)?;

        let keys: Vec<&String> = kn.list();

        let filtered_keys: Vec<&String> = if let Some(ref prefix) = self.prefix {
            keys.into_iter().filter(|k| k.starts_with(prefix)).collect()
        } else {
            keys
        };

        if filtered_keys.is_empty() {
            println!("No secrets to export");
            return Ok(());
        }

        let format = self
            .format
            .or_else(|| {
                self.file
                    .as_ref()
                    .and_then(|p| p.extension()?.to_str())
                    .and_then(ExportFormat::from_extension)
            })
            .unwrap_or(ExportFormat::Json);

        match format {
            ExportFormat::Env => {
                let output = format_as_env(&kn, &filtered_keys)?;
                if let Some(ref path) = self.file {
                    std::fs::write(path, &output)?;
                } else {
                    println!("{output}");
                }
            }
            ExportFormat::Json => {
                let output = format_as_json(&kn, &filtered_keys)?;
                if let Some(ref path) = self.file {
                    std::fs::write(path, &output)?;
                } else {
                    println!("{output}");
                }
            }
        }

        Ok(())
    }
}

fn format_as_env(kn: &Keynest, keys: &[&String]) -> Result<String> {
    let mut output = String::new();
    for key in keys {
        if let Some(value) = kn.get(key) {
            writeln!(&mut output, "{}={}", key, escape_env_value(value))?;
        }
    }
    Ok(output)
}

fn escape_env_value(value: &str) -> String {
    if value.contains(' ')
        || value.contains('"')
        || value.contains('\'')
        || value.contains('\n')
        || value.contains('\\')
    {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

fn format_as_json(kn: &Keynest, keys: &[&String]) -> Result<String> {
    let map: HashMap<&str, &str> = keys
        .iter()
        .filter_map(|k| kn.get(k).map(|v| (k.as_str(), v)))
        .collect();
    Ok(serde_json::to_string_pretty(&map)?)
}
