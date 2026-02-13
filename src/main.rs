use anyhow::Result;
use clap::{Parser, Subcommand};
mod auth;
use keynest::{KdfParams, Keynest, Storage, default_storage};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
struct Argon2Args {
    /// Argon2 memory cost in KiB (default: 65536)
    #[arg(long = "argon-mem")]
    mem_cost_kib: Option<u32>,

    /// Argon2 time cost / iterations (default: 3)
    #[arg(long = "argon-time")]
    time_cost: Option<u32>,

    /// Argon2 parallelism (default: 1)
    #[arg(long = "argon-parallelism")]
    parallelism: Option<u32>,
}

impl Argon2Args {
    fn to_kdf_params(&self) -> anyhow::Result<KdfParams> {
        let default = KdfParams::default();

        KdfParams::new(
            self.mem_cost_kib.unwrap_or(default.mem_cost_kib()),
            self.time_cost.unwrap_or(default.time_cost()),
            self.parallelism.unwrap_or(default.parallelism()),
        )
    }
}

fn resolve_storage(path: Option<PathBuf>) -> Result<Storage> {
    match path {
        Some(p) => Ok(Storage::new(p)),
        None => default_storage(),
    }
}

#[derive(Debug, Parser)]
#[command(name = "keynest")]
#[command(
    version,
    about = "Simple, offline, cross-platform secrets manager written in Rust."
)]
struct Cli {
    ///Path to the keynest storage file
    #[arg(long, global = true, value_name = "PATH", env = "KEYNEST_PATH")]
    store: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initializes the secret storage
    Init {
        #[command(flatten)]
        argon2: Argon2Args,
    },

    /// Stores a secret by name
    #[command(arg_required_else_help = true)]
    Set { key: String, value: String },

    /// Retrieves secret by name
    #[command(arg_required_else_help = true)]
    Get { key: String },

    /// Updates existing secret value by name
    #[command(arg_required_else_help = true)]
    Update { key: String, new_value: String },

    /// Lists all stored secrets
    #[command(arg_required_else_help = false)]
    List {
        #[arg(required = false, short, long, default_value_t = false)]
        /// Print names and secrets
        all: bool,
    },

    /// Removes secrets by name
    #[command(arg_required_else_help = true)]
    Remove { key: String },

    /// Shows information about the store
    Info,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let password = auth::read_password()?;
    match args.command {
        Commands::Init { argon2 } => {
            let kdf = argon2.to_kdf_params()?;
            let storage = resolve_storage(args.store.clone())?;
            Keynest::init_with_storage_and_kdf(password, storage, kdf)?;
            println!("keystore initialized");
        }
        Commands::Set { key, value } => {
            let storage = resolve_storage(args.store.clone())?;
            let mut kn = Keynest::open_with_storage(password, storage)?;
            kn.set(&key, &value)?;
            kn.save()?;
            println!("stored secret '{key}'");
        }
        Commands::Update { key, new_value } => {
            let storage = resolve_storage(args.store.clone())?;
            let mut kn = Keynest::open_with_storage(password, storage)?;
            kn.update(&key, &new_value)?;
            kn.save()?;
            println!("secret '{key}' updated.");
        }
        Commands::Get { key } => {
            let storage = resolve_storage(args.store.clone())?;
            let kn = Keynest::open_with_storage(password, storage)?;
            match kn.get(&key) {
                Some(secret) => println!("{secret}"),
                None => println!("key not found"),
            }
        }
        Commands::List { all } => {
            let storage = resolve_storage(args.store.clone())?;
            let kn = Keynest::open_with_storage(password, storage)?;
            if all {
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
        }
        Commands::Remove { key } => {
            let storage = resolve_storage(args.store.clone())?;
            let mut kn = Keynest::open_with_storage(password, storage)?;
            kn.remove(&key)?;
            match kn.save() {
                Ok(_) => println!("key : '{key}' removed successfully"),
                Err(e) => panic!("Error at removing key : '{key}', {e}"),
            }
        }

        Commands::Info => {
            let storage = resolve_storage(args.store.clone())?;
            let kn = Keynest::open_with_storage(password, storage.clone())?;
            let info = kn.info()?;
            println!("{info}");
        }
    }

    Ok(())
}
