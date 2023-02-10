use std::process::ExitCode;

use anyhow::{anyhow, Result};
use nix::unistd::{fork, ForkResult};
use parse_coff::{COFFHeader, SectionTypeFlags};
use parse_mz::MZFile;

mod child_process;
mod parent_process;
mod parent_utils;
mod parse_coff;
mod parse_mz;

fn wrapped_main() -> Result<ExitCode> {
    pretty_env_logger::init();

    let input_path = std::env::args()
        .nth(1)
        .expect("Usage: alumini <executable> [executable arguments]");

    let file_bytes = std::fs::read(input_path)?;

    let coff_bytes = match &file_bytes[..2] {
        COFFHeader::DJGPP_MAGIC => &file_bytes,

        MZFile::MAGIC => {
            let (_, mz) = MZFile::parse(&file_bytes)
                .map_err(|e| anyhow!("Error parsing MZ executable: {e}"))?;

            let mut mz_end = mz.header.pages as usize * 512;
            if mz.header.extra_bytes != 0 {
                mz_end += mz.header.extra_bytes as usize;
                mz_end -= 512;
            }

            // Yoink the COFF file out from its EXE-extender wrapper
            &file_bytes[mz_end..]
        }

        _ => panic!("Unknown executable format"),
    };

    let (_, coff) = parse_coff::COFFFile::parse(coff_bytes)
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
            Ok(ExitCode::from(exit_code))
        }
        Err(e) => Err(anyhow!("Error invoking fork: {e}")),
    }
}

fn main() -> ExitCode {
    match wrapped_main() {
        Ok(exit_code) => exit_code,
        Err(e) => panic!("{}", e),
    }
}
