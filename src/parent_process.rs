use std::{ffi::c_void, io::Write};

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
    Write = 0x40,
    Sbrk = 0x4a,
    TurboAssist = 0xff,
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

pub fn parent_main(child: Pid) -> Result<()> {
    println!("Hello from parent! Child is {}", child);

    // Wait for the child to send us a signal that it's ready to be traced
    wait()?;
    ptrace::step(child, None)?;

    loop {
        match wait() {
            Ok(WaitStatus::Stopped(_, signal)) => {
                match signal {
                    Signal::SIGSEGV => {
                        // DOS handles interrupts using int 21h Linux doesn't.
                        // This means trying to call interrupt 0x21 will cause our process to segfault as it tries to load
                        // a handler that doesn't exist. Let's catch and work around this.
                        let mut regs = ptrace::getregs(child)?;

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
                                Some(Int21Services::Write) => handle_write(child)?,
                                Some(Int21Services::Sbrk) => handle_sbrk(child)?,
                                Some(Int21Services::TurboAssist) => {
                                    let service = regs.eax & 0xff;
                                    match service {
                                        _ => panic!("Unknown turbo assist service {}", service)
                                    }
                                }
                                None => {
                                    println!("{}", regs.eax);
                                    panic!("Unknown 0x21 service number called: {:#x}", ah)
                                },
                            };

                            // Step over the segfaulting instruction
                            regs.eip += 2;
                            ptrace::setregs(child, regs)?;
                            ptrace::cont(child, None)?;
                        } else {
                            panic!("[ERROR] Segfault at {:#x}", regs.eip);
                        }
                    }

                    /*Signal::SIGTRAP => {
                        let regs = ptrace::getregs(child)?;

                        println!("[DEBUG] executing at {:#x}", regs.eip);
                        ptrace::cont(child, None)?;
                    }*/
                    _ => {
                        println!("[INFO] stopped with signal {}, continuing", signal);
                        ptrace::cont(child, Some(signal))?;
                    }
                }
            }
            Ok(status) => {
                println!("[INFO] received status {:?}; continuing", status);
                ptrace::cont(child, None)?;
            }
            Err(e) => Err(anyhow!("wait() error: {e}"))?,
        }
    }
}

fn handle_sbrk(child: Pid) -> Result<()> {
    println!("[WARNING] Received brk / sbrk request; TODO");
    
    Ok(())
}

fn handle_write(child: Pid) -> Result<()> {
    let regs = ptrace::getregs(child)?;
    
    let fd: u32 = regs.ebx.try_into()?;
    let bytes_to_write: usize = regs.ecx.try_into()?;
    let mem_pointer: u32 = regs.edx as u32;

    let string_bytes = read_bytes(child, mem_pointer, bytes_to_write)?;
    
    match fd {
        1 => {
            // stdout
            std::io::stdout().write_all(&string_bytes)?;
        },
        2 => {
            // stderr
            std::io::stderr().write_all(&string_bytes)?;
        },
        _ => panic!("Attempted to write to unknown file descriptor {}", fd)
    }

    // TODO: allll the flags need set
    
    Ok(())
}