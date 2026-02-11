use anyhow::Result;
use clap::{Parser, Subcommand};
mod auth;
use keynest::{KdfParams, Keynest};

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

#[derive(Debug, Parser)]
#[command(name = "keynest")]
#[command(
    version,
    about = "Simple, offline, cross-platform secrets manager written in Rust."
)]
struct Cli {
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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let password = auth::read_password()?;
    match args.command {
        Commands::Init { argon2 } => {
            let kdf = argon2.to_kdf_params()?;
            Keynest::init_with_kdf(password, kdf)?;
            println!("Keystore initialized");
        }
        Commands::Set { key, value } => {
            let mut kn = Keynest::open(password)?;
            kn.set(&key, &value)?;
            kn.save()?;
            println!("Stored secret '{key}'");
        }
        Commands::Update { key, new_value } => {
            let mut kn = Keynest::open(password)?;
            kn.update(&key, &new_value)?;
            kn.save()?;
            println!("Secret '{key}' updated.");
        }
        Commands::Get { key } => {
            let kn = Keynest::open(password)?;
            match kn.get(&key) {
                Some(secret) => println!("{secret}"),
                None => println!("Key not found"),
            }
        }
        Commands::List { all } => {
            let kn = Keynest::open(password)?;
            if all {
                println!("Name: \t\t\t Value: \t\t\t Updated:");

                for secret_entry in kn.list_all() {
                    println!(
                        "{}\t\t\t {} \t\t\t {}",
                        secret_entry.key(),
                        secret_entry.value(),
                        secret_entry.updated()
                    );
                }
            } else {
                for secret_key in kn.list() {
                    println!("{secret_key}");
                }
            }
        }
        Commands::Remove { key } => {
            let mut kn = Keynest::open(password)?;
            kn.remove(&key)?;
            match kn.save() {
                Ok(_) => println!("Key : '{key}' removed sucessfully"),
                Err(e) => panic!("Error at removing key : '{key}', {e}"),
            }
        }
    }

    Ok(())
}
