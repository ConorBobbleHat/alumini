use anyhow::Result;
use nix::sys::ptrace;

use mmap::{MapOption, MemoryMap};
use std::{arch::asm, os::unix::prelude::OsStrExt, path::Path};
use x86::segmentation::SegmentSelector;

use crate::parse_coff::{COFFFile, SectionTypeFlags};

const STACK_ADDR: usize = 0xc0000000;
const STACK_SIZE: usize = 0x100000;

const ALLOC_SIZE: usize = 0x100000;

pub fn child_main(coff: COFFFile, coff_bytes: &[u8]) -> Result<()> {
    ptrace::traceme()?;

    let mut mappings = Vec::new();

    // Heavily adapted from https://fasterthanli.me/series/making-our-own-executable-packer/part-2
    for section in &coff.sections {
        let section_addr: usize = section.header.virtual_address.try_into().unwrap();
        let section_size: usize = section.header.size.try_into().unwrap();

        let page_size = page_size::get();
        let section_addr_aligned = section_addr & !(page_size - 1);
        let section_size_aligned = section_size + (section_addr - section_addr_aligned);
        let section_addr_aligned = section_addr_aligned as *mut u8;

        let mut options = vec![
            MapOption::MapReadable,
            MapOption::MapWritable,
            MapOption::MapAddr(section_addr_aligned),
        ];

        if section.header.flags.contains(SectionTypeFlags::TEXT) {
            options.push(MapOption::MapExecutable);
        };

        let map = MemoryMap::new(section_size_aligned, &options)?;
        mappings.push(map); // dropping the map unmaps it - so let's hang onto it!

        // Actually copy the data from the COFF file
        let dest = unsafe { std::slice::from_raw_parts_mut(section_addr as *mut u8, section_size) };
        if section.header.flags.contains(SectionTypeFlags::BSS) {
            dest.fill(0); // BSS data is uninitalized, and should be zero-filled
        } else {
            dest.copy_from_slice(
                &coff_bytes[section.header.section_data_offset.try_into().unwrap()..]
                    [..section_size],
            );
        }
    }

    // Map an extra area in to act as a stack ...
    let stack_top: *const u8 = (STACK_ADDR - STACK_SIZE) as _;

    let stack_map = MemoryMap::new(
        STACK_SIZE,
        &[
            MapOption::MapReadable,
            MapOption::MapWritable,
            MapOption::MapAddr(stack_top),
        ],
    )?;

    mappings.push(stack_map); // dropping the map unmaps it - so let's hang onto it!

    // ... and one for allocated memory
    // TODO: actually allocate this on the fly
    let bss_section = coff
        .sections
        .iter()
        .find(|x| x.header.flags.contains(SectionTypeFlags::BSS))
        .expect("Executable contains no bss segment?");

    let program_break = ((bss_section.header.virtual_address + bss_section.header.size + 8) & !7)
        & !(page_size::get() as u32 - 1);

    let alloc_map = MemoryMap::new(
        ALLOC_SIZE,
        &[
            MapOption::MapReadable,
            MapOption::MapWritable,
            MapOption::MapAddr(program_break as *const u8),
        ],
    )?;

    mappings.push(alloc_map);

    // Construct both a null-terminated array of all our arguments concatenated together
    // and an array of pointers pointing to each of our individual arguments (argv)
    let mut args = std::env::args().skip(1); // skip our program name
    let num_args = args.len();

    let prog_name = args.nth(0).unwrap(); // safe; we got this far
    let prog_name = Path::new(&prog_name).file_name().unwrap();
    
    let other_args: Vec<_> = args.collect();
    let other_arg_lengths: Vec<_> = other_args.iter().map(|x| x.len()).collect();

    let mut arg_bytes = Vec::new();
    let mut arg_ptrs = Vec::new();

    arg_bytes.extend(prog_name.as_bytes());
    arg_bytes.push(0);

    for arg in other_args {
        arg_bytes.extend(arg.as_bytes());
        arg_bytes.push(0);
    }

    let mut arg_arr_ptr = arg_bytes.as_ptr() as usize;
    arg_ptrs.extend(usize::to_le_bytes(arg_arr_ptr));
    arg_arr_ptr += prog_name.as_bytes().len() + 1;

    for len in other_arg_lengths {
        arg_ptrs.extend(usize::to_le_bytes(arg_arr_ptr));
        arg_arr_ptr += len + 1;
    }

    let argv = arg_ptrs;
    let argc = num_args;

    unsafe {
        // WHAT ENVIRONMENT A GO32 PROGRAM STARTS TO:
        // EAX: some processed version of g_core?
        // EBX: _ScreenPrimary
        // ECX: ??; we use as jump address
        // EDX: a pointer to prog_info
        // EDI: transfer buffer pointer
        // EBP: _ScreenSecondary
        // GS: a segment that's set to map linearly
        // arguments to _main on the stack

        // Let's run this thing!
        // Unwrap is safe here - if it doesn't have an optional header, it isn't an executable
        let fn_ptr: fn() = std::mem::transmute(coff.optional_header.unwrap().entry_address);

        // https://stackoverflow.com/questions/5599400/where-linux-sets-its-kernel-and-user-space-segment-selector-values
        // we want GS to be __USER_DS (0x7b, or, (5 << 3) + 3)) to ensure it's mapped linearly, as go32 expects
        x86::segmentation::load_gs(SegmentSelector::new(5, x86::Ring::Ring3));

        asm!(
            "xor edx, edx",         // clear prog_info pointer
            "xor edi, edi",         // clear transfer buffer pointer to use backup IPC method
            "mov esp, 0xc0000000",  // setup stack
            "push 0x41414141",      // ?
            "push eax",             // argv
            "push ebx",             // argc
            "mov esi, 42",          // pid
            "jmp ecx",
            in("eax") argv.as_ptr(),
            in("ebx") argc,
            in("ecx") fn_ptr,
        );
    };

    Ok(())
}
