use anyhow::Result;
use clap::Args;
use keynest::{KdfParams, Storage, default_storage};
use serde::Serialize;
use std::fmt::Display;
use std::path::PathBuf;

pub fn print_json<T: Serialize>(value: &T) {
    println!("{}", serde_json::to_string_pretty(value).unwrap());
}

pub fn print_plain<T: Display>(value: &T) {
    println!("{value}");
}

pub fn resolve_storage(path: Option<PathBuf>) -> Result<Storage> {
    match path {
        Some(p) => Ok(Storage::new(p)),
        None => default_storage(),
    }
}

#[derive(Debug, Args)]
pub struct Argon2Args {
    /// Argon2 memory cost in KiB (default: 65536)
    #[arg(long = "argon-mem")]
    pub mem_cost_kib: Option<u32>,

    /// Argon2 time cost / iterations (default: 3)
    #[arg(long = "argon-time")]
    pub time_cost: Option<u32>,

    /// Argon2 parallelism (default: 1)
    #[arg(long = "argon-parallelism")]
    pub parallelism: Option<u32>,
}

impl Argon2Args {
    pub fn to_kdf_params(&self) -> anyhow::Result<KdfParams> {
        let default = KdfParams::default();

        KdfParams::new(
            self.mem_cost_kib.unwrap_or(default.mem_cost_kib()),
            self.time_cost.unwrap_or(default.time_cost()),
            self.parallelism.unwrap_or(default.parallelism()),
        )
    }
}

pub fn copy_to_clipboard(secret: &str, timeout: u64) -> anyhow::Result<()> {
    use arboard::Clipboard;
    use std::{thread::sleep, time::Duration};

    let mut cb = Clipboard::new()?;
    let old = cb.get_text().ok();

    cb.set_text(secret.to_string())?;

    eprintln!("Secret copied to clipboard for {timeout}s");
    eprintln!("Press Ctrl+C to clear early");

    let old_clip = old.clone();
    ctrlc::set_handler(move || {
        if let Ok(mut cb) = Clipboard::new() {
            let _ = cb.set_text(old_clip.clone().unwrap_or_default());
        }
        sleep(Duration::from_millis(100));
        std::process::exit(0);
    })?;

    let had_old = old.is_some();
    sleep(Duration::from_secs(timeout));

    let mut cb = Clipboard::new()?;
    cb.set_text(old.unwrap_or_default())?;

    eprintln!("Clipboard {}", if had_old { "restored" } else { "cleared" });

    Ok(())
}
