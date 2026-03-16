use anyhow::Result;
use std::path::PathBuf;

pub trait Command {
    fn run(self, store: Option<PathBuf>) -> Result<()>;
}

pub mod common;
pub mod get;
pub mod info;
pub mod init;
pub mod list;
pub mod rekey;
pub mod remove;
pub mod set;
pub mod update;
