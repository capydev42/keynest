use anyhow::Result;
use std::path::PathBuf;

pub trait Command {
    fn run(self, store: Option<PathBuf>) -> Result<()>;
}

pub mod common;
pub mod exec;
pub mod export;
pub mod get;
pub mod import;
pub mod info;
pub mod init;
pub mod list;
pub mod rekey;
pub mod remove;
pub mod set;
pub mod update;
