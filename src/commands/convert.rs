use std::path::PathBuf;

use anyhow::Result;

use crate::{ecosystem, oxfile};

pub(crate) fn run(input: PathBuf, out: PathBuf, env: Option<String>) -> Result<()> {
    let specs = ecosystem::load_with_profile(&input, env.as_deref())?;
    oxfile::write_from_specs(&out, &specs)?;
    println!("Converted {} -> {}", input.display(), out.display());

    Ok(())
}
