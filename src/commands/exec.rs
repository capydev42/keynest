use anyhow::Result;
use clap::Args;

use super::super::auth;
use crate::commands::common::resolve_storage;
use keynest::Keynest;

fn to_env_name(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            'a'..='z' => c.to_ascii_uppercase(),
            'A'..='Z' | '0'..='9' => c,
            _ => '_',
        })
        .collect()
}

fn apply_prefix(prefix: Option<&str>, mut key: String) -> String {
    if let Some(p) = prefix {
        if !key.starts_with(p) {
            key = format!("{p}{key}");
        }
    }
    key
}

fn shell_escape(value: &str) -> String {
    if cfg!(windows) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

#[derive(Args)]
#[command(after_help = "\
Examples:
  keynest exec -- docker compose up                Run command with all secrets as env vars
  keynest exec --only API_KEY -- curl api.example.com  Run command with specific secret
  keynest exec --prefix MY_ -- env                 Show env vars with prefix
  keynest exec --print                             Preview environment variables")]
pub struct ExecCommand {
    /// Only export specific keys
    #[arg(long, value_delimiter = ',')]
    pub only: Option<Vec<String>>,

    /// Prefix environment variables
    #[arg(long)]
    pub prefix: Option<String>,

    /// Print env instead of executing command
    #[arg(long)]
    pub print: bool,

    /// Command to run
    #[arg(trailing_var_arg = true)]
    pub cmd: Vec<String>,
}

impl crate::commands::Command for ExecCommand {
    fn run(self, store: Option<std::path::PathBuf>) -> Result<()> {
        let password = auth::read_password()?;
        let storage = resolve_storage(store)?;
        let kn = Keynest::open_with_storage(password, storage)?;

        let keys: Vec<String> = if let Some(ref only) = self.only {
            only.clone()
        } else {
            kn.list().iter().map(|s| s.to_string()).collect()
        };

        if self.print {
            for key in &keys {
                let secret = kn
                    .get(key)
                    .ok_or_else(|| anyhow::anyhow!("key not found: {key}"))?;

                let env_key = apply_prefix(self.prefix.as_deref(), to_env_name(key));

                println!("{}={}", env_key, shell_escape(secret));
            }
            return Ok(());
        }

        if !self.print && self.cmd.is_empty() {
            anyhow::bail!("command is required (use -- <cmd>)");
        }

        let mut cmd = std::process::Command::new(&self.cmd[0]);
        cmd.args(&self.cmd[1..]);

        for key in &keys {
            let secret = kn
                .get(key)
                .ok_or_else(|| anyhow::anyhow!("key not found: {key}"))?;

            let env_key = apply_prefix(self.prefix.as_deref(), to_env_name(key));

            cmd.env(env_key, secret);
        }

        let status = cmd.status()?;

        std::process::exit(status.code().unwrap_or(1));
    }
}
