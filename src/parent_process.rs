use std::{
    collections::HashMap,
    ffi::c_void,
    fs::{File, OpenOptions},
    hash::Hash,
    io::{Read, Write},
    os::linux::fs::MetadataExt,
};

use log::{info, warn, debug};
use num_derive::FromPrimitive;

use anyhow::{anyhow, Result};
use nix::{
    sys::{
        ptrace,
        signal::Signal,
        wait::{wait, WaitStatus},
    },
    unistd::Pid,
};
use num_traits::FromPrimitive;

// encoding for x86's INT opcode
const INT_OPCODE: u8 = 0xcd;

#[derive(FromPrimitive, Debug)]
enum Int21Services {
    Close = 0x3e,
    Read = 0x3f,
    Write = 0x40,
    Exit = 0x4c,
    Sbrk = 0x4a,
    TurboAssist = 0xff,
}

#[derive(FromPrimitive, Debug)]
enum TurboServices {
    Open = 2,
    Fstat = 3,
}

bitflags::bitflags! {
    struct OpenBitflags: u32 {
        const READ = 0x001;
        const WRITE = 0x02;
        const UNKNOWN_ONE = 0x4000;
        const CREATE = 0x300;
    }
}

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

            let mixed_word = [&word_bytes, &existing_word[word_bytes.len()..]].concat();
            let mixed_word = i32::from_le_bytes(mixed_word.try_into().unwrap());
            mixed_word
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

pub fn parent_main(child: Pid, program_break: u32) -> Result<u8> {
    // Wait for the child to send us a signal that it's ready to be traced
    wait()?;
    ptrace::cont(child, None)?;

    let mut open_file_handles: HashMap<u32, File> = HashMap::new();
    let mut program_break = program_break;

    loop {
        match wait() {
            Ok(WaitStatus::Stopped(_, signal)) => {
                match signal {
                    Signal::SIGSEGV => {
                        // DOS handles interrupts using int 21h Linux doesn't.
                        // This means trying to call interrupt 0x21 will cause our process to segfault as it tries to load
                        // a handler that doesn't exist. Let's catch and work around this.
                        let regs = ptrace::getregs(child)?;

                        let executing_instruction =
                            i32::to_le_bytes(ptrace::read(child, regs.eip as *mut c_void)?);

                        if executing_instruction[0] == INT_OPCODE {
                            // TODO: other services to implement?
                            if executing_instruction[1] != 0x21 {
                                panic!(
                                    "Unimplemented interrupt number: {:#x}",
                                    executing_instruction[1]
                                );
                            }

                            // AH contains service number
                            let ah = ((regs.eax & 0xff00) >> 8) as u8;

                            match FromPrimitive::from_u8(ah) {
                                Some(Int21Services::Close) => {
                                    handle_close(child, &mut open_file_handles)?
                                }
                                Some(Int21Services::Read) => {
                                    handle_read(child, &mut open_file_handles)?
                                }
                                Some(Int21Services::Write) => {
                                    handle_write(child, &mut open_file_handles)?
                                }
                                Some(Int21Services::Sbrk) => {
                                    handle_brk_sbrk(child, &mut program_break)?
                                }
                                Some(Int21Services::TurboAssist) => {
                                    let service = (regs.eax & 0xff) as u8;
                                    match FromPrimitive::from_u8(service) {
                                        Some(TurboServices::Open) => {
                                            handle_turbo_open(child, &mut open_file_handles)?
                                        }
                                        Some(TurboServices::Fstat) => {
                                            handle_turbo_fstat(child, &mut open_file_handles)?
                                        }
                                        None => panic!("Unknown turbo assist service {}", service),
                                    }
                                }

                                Some(Int21Services::Exit) => {
                                    let exit_code: u8 = regs.ebx.try_into()?;
                                    return Ok(exit_code);
                                }

                                None => {
                                    panic!("Unknown 0x21 service number called: {:#x}", ah)
                                }
                            };

                            // Step over the segfaulting instruction
                            // We need to fetch the registers again as a handler may have mutated them
                            let mut regs = ptrace::getregs(child)?;
                            regs.eip += 2;
                            ptrace::setregs(child, regs)?;
                            ptrace::cont(child, None)?;
                        } else {
                            panic!("[ERROR] Segfault at {:#x}", regs.eip);
                        }
                    }

                    _ => {
                        info!("Stopped with signal {}, continuing", signal);
                        ptrace::cont(child, Some(signal))?;
                    }
                }
            }
            Ok(status) => {
                info!("Received status {:?}; continuing", status);
                ptrace::cont(child, None)?;
            }
            Err(e) => Err(anyhow!("wait() error: {e}"))?,
        }
    }
}

fn handle_brk_sbrk(child: Pid, program_break: &mut u32) -> Result<()> {
    let mut regs = ptrace::getregs(child)?;

    match (regs.eax & 0xff) as u8 {
        0 => {
            // BRK
            todo!("brk");
        }
        _ => {
            // SBRK
            debug!(
                "sbrk({:#x}). Returning {:#x}",
                regs.ebx, *program_break
            );

            let offset = regs.ebx;
            regs.eax = (*program_break) as i32;
            ptrace::setregs(child, regs)?;

            *program_break = (*program_break as i64 + offset as i64).try_into()?;
        }
    }

    Ok(())
}

fn handle_close(child: Pid, open_file_handles: &mut HashMap<u32, File>) -> Result<()> {
    let mut regs = ptrace::getregs(child)?;

    let fd = regs.ebx as u32;

    let f = open_file_handles.remove(&fd);

    if let Some(f) = f {
        debug!("close({})", fd);

        // Rust should do this for us automatically
        // But to make it clear what's happening: dropping the file closes it
        drop(f);
    } else {
        warn!("close({}); bad file descriptor", fd);
    };

    regs.eax = 0;
    ptrace::setregs(child, regs)?;

    Ok(())
}

fn handle_read(child: Pid, open_file_handles: &mut HashMap<u32, File>) -> Result<()> {
    let mut regs = ptrace::getregs(child)?;

    let fd = regs.ebx as u32;
    let size: usize = regs.ecx.try_into()?;
    let out_ptr = regs.edx as u32;

    debug!("read({}, {:#x}, {:#x})", fd, size, out_ptr);

    let f = open_file_handles
        .get_mut(&fd)
        .ok_or_else(|| anyhow!("Attempt to read unknown fd {}", fd))?;

    let mut buf = vec![0u8; size];
    let bytes_read = f.read(&mut buf)?;

    write_bytes(child, out_ptr, &buf[..bytes_read])?;

    regs.eax = bytes_read.try_into()?;
    ptrace::setregs(child, regs)?;

    Ok(())
}

fn handle_write(child: Pid, open_file_handles: &mut HashMap<u32, File>) -> Result<()> {
    let regs = ptrace::getregs(child)?;

    let fd: u32 = regs.ebx as u32;
    let bytes_to_write: usize = regs.ecx.try_into()?;
    let mem_pointer: u32 = regs.edx as u32;

    let string_bytes = read_bytes(child, mem_pointer, bytes_to_write)?;

    debug!("Write {} bytes to fd {}", bytes_to_write, fd);

    match fd {
        1 => {
            // stdout
            std::io::stdout().write_all(&string_bytes)?;
        }

        2 => {
            // stderr
            std::io::stderr().write_all(&string_bytes)?;
        }

        fd => {
            let f = open_file_handles
                .get_mut(&fd)
                .ok_or_else(|| anyhow!("Attempt to write to unknown fd {}", fd))?;

            f.write(&string_bytes)?;
        }
    }

    // TODO: allll the flags need set

    Ok(())
}

fn handle_turbo_open(child: Pid, open_file_handles: &mut HashMap<u32, File>) -> Result<()> {
    let mut regs = ptrace::getregs(child)?;

    let filename_ptr: u32 = regs.ebx as u32;
    let filename = read_null_terminated_string(child, filename_ptr)?;

    let flags = OpenBitflags::from_bits(regs.ecx as u32)
        .ok_or_else(|| anyhow!("Unexpected flags passed to open: {:#x}", regs.ecx))?;

    // TODO: honor this in any way
    let mode: u32 = regs.edx as u32;

    debug!("open({:?}, {:?}, {:#x})", filename, flags, mode);

    let f = OpenOptions::new()
        .read(flags.contains(OpenBitflags::READ))
        .write(flags.contains(OpenBitflags::WRITE))
        .create(flags.contains(OpenBitflags::CREATE))
        .open(filename)?;

    let new_fd = open_file_handles.keys().max().unwrap_or(&2) + 1;
    open_file_handles.insert(new_fd, f);

    // Handle return values
    regs.eax = new_fd as i32;
    ptrace::setregs(child, regs)?;

    Ok(())
}

#[repr(C)]
#[derive(Debug)]
struct FStat32 {
    st_dev: u16,
    st_ino: u16,
    st_mode: u16,
    st_nlink: u16,
    st_uid: u16,
    st_gid: u16,
    st_rdev: u16,
    st_align_word32: u16,
    st_size: u32,
    st_atime: u32,
    st_mtime: u32,
    st_ctime: u32,
    st_blksize: u32,
}

fn handle_turbo_fstat(child: Pid, open_file_handles: &mut HashMap<u32, File>) -> Result<()> {
    let mut regs = ptrace::getregs(child)?;

    let fd = regs.ebx as u32;
    let return_ptr = regs.ecx as u32;

    debug!("fstat({}, {:#x})", fd, return_ptr);

    let f = open_file_handles
        .get(&fd)
        .ok_or_else(|| anyhow!("Attempt to fstat unknown fd {}", fd))?;

    let metadata = f.metadata()?;

    let fstat_struct = FStat32 {
        st_dev: metadata.st_dev().try_into()?,
        st_ino: 42, // 64-bit inode is frequently too large for a 16-bit field; fake it for now
        st_mode: metadata.st_mode().try_into()?,
        st_nlink: metadata.st_nlink().try_into()?,
        st_uid: 42,
        st_gid: 42,
        st_rdev: metadata.st_rdev().try_into()?,
        st_align_word32: 0,
        st_size: metadata.st_size().try_into()?,
        st_atime: metadata.st_atime().try_into()?,
        st_mtime: metadata.st_mtime().try_into()?,
        st_ctime: metadata.st_ctime().try_into()?,
        st_blksize: 4096,
    };

    let fstat_bytes = unsafe {
        std::slice::from_raw_parts(
            (&fstat_struct as *const FStat32) as *const u8,
            std::mem::size_of::<FStat32>(),
        )
    };

    write_bytes(child, return_ptr, fstat_bytes)?;

    // a-okay!
    regs.eax = 0;
    ptrace::setregs(child, regs)?;

    Ok(())
}
