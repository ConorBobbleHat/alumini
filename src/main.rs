use anyhow::{anyhow, Result};
use nix::unistd::{fork, ForkResult};

mod parse_coff;
mod child_process;
mod parent_process;

fn main() -> Result<()> {
    let input_path = std::env::args()
        .nth(1)
        .expect("Usage: alumini [executable]");

    let coff_bytes = std::fs::read(input_path)?;

    let (_, coff) = parse_coff::COFFFile::parse(&coff_bytes)
        .map_err(|e| anyhow!("Error parsing go32 COFF executable: {e}"))?;

    // Enough parsing - let's load this thing!
    match unsafe { fork() } {
        Ok(ForkResult::Child) => child_process::child_main(coff, coff_bytes),
        Ok(ForkResult::Parent { child }) => { parent_process::parent_main(child) },
        Err(e) => Err(anyhow!("Error invoking fork: {e}")),
    }?;

    Ok(())
}
