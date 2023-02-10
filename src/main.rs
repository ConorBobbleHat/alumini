use std::process::ExitCode;

use anyhow::{anyhow, Result};
use nix::unistd::{fork, ForkResult};
use parse_coff::SectionTypeFlags;

mod child_process;
mod parent_process;
mod parent_utils;
mod parse_coff;

fn wrapped_main() -> Result<ExitCode> {
    pretty_env_logger::init();
    
    let input_path = std::env::args()
        .nth(1)
        .expect("Usage: alumini <executable> [executable arguments]");

    let coff_bytes = std::fs::read(input_path)?;

    let (_, coff) = parse_coff::COFFFile::parse(&coff_bytes)
        .map_err(|e| anyhow!("Error parsing go32 COFF executable: {e}"))?;

    // Find the program break so the parent knows where it is
    let bss_section = coff
        .sections
        .iter()
        .find(|x| x.header.flags.contains(SectionTypeFlags::BSS))
        .expect("Executable contains no bss segment?");

    let program_break = (bss_section.header.virtual_address + bss_section.header.size + 8) & !7;

    // Enough parsing - let's load this thing!
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            child_process::child_main(coff, coff_bytes)?;
            panic!("Returned from child_main");
        }
        Ok(ForkResult::Parent { child }) => {
            let exit_code = parent_process::parent_main(child, program_break)?;
            return Ok(ExitCode::from(exit_code));
        }
        Err(e) => Err(anyhow!("Error invoking fork: {e}")),
    }
}

fn main() -> ExitCode {
    match wrapped_main() {
        Ok(exit_code) => exit_code,
        Err(e) => panic!("{}", e)
    }
}
