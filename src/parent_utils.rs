use anyhow::Result;
use nix::{sys::ptrace, unistd::Pid};
use std::ffi::c_void;

pub fn read_bytes(child: Pid, addr: u32, size: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(size + 3);

    let num_reads_required = (size + 3) / 4;
    for i in 0..num_reads_required {
        let w = ptrace::read(child, (addr + i as u32 * 4) as *mut c_void)?;

        let bytes_to_append = std::cmp::min(size - bytes.len(), 4);
        let bytes_to_append = &i32::to_le_bytes(w)[..bytes_to_append];
        bytes.extend(bytes_to_append);
    }

    Ok(bytes)
}

pub fn write_bytes(child: Pid, addr: u32, bytes: &[u8]) -> Result<()> {
    for (i, word_bytes) in bytes.chunks(4).enumerate() {
        let indexed_addr = (addr + i as u32 * 4) as *mut c_void;

        let d = if word_bytes.len() == 4 {
            i32::from_le_bytes(word_bytes.try_into().unwrap()) // safe here - we just did a length check
        } else {
            let existing_word = i32::to_le_bytes(ptrace::read(child, indexed_addr)?);

            let mixed_word = [word_bytes, &existing_word[word_bytes.len()..]].concat();
            i32::from_le_bytes(mixed_word.try_into().unwrap())
        };

        unsafe { ptrace::write(child, indexed_addr, d as *mut c_void)? };
    }

    Ok(())
}

pub fn read_null_terminated_string(child: Pid, addr: u32) -> Result<String> {
    let mut bytes = Vec::new();
    let mut i = 0;

    loop {
        let w = ptrace::read(child, (addr + i * 4) as *mut c_void)?;
        let w_bytes = i32::to_le_bytes(w);

        // Does this word have the null terminator?
        if let Some(pos) = w_bytes.iter().position(|&x| x == 0) {
            bytes.extend(&w_bytes[..pos]); // don't copy the null terminator into the string itself
            break;
        } else {
            bytes.extend(w_bytes);
        }

        i += 1;
    }

    Ok(String::from_utf8(bytes)?)
}
