use std::arch::asm;

use anyhow::{anyhow, Result};
use mmap::{MapOption, MemoryMap};
use x86::segmentation::SegmentSelector;

use crate::parse_coff::SectionTypeFlags;

mod parse_coff;

#[repr(C)]
struct ProgInfo {
    size: u32,
    primary_screen_address: u32,
    secondary_screen_address: u32,
    transfer_buffer_address: u32,
    transfer_buffer_size: u32,
    pid: u32,
    master_interrupt_control_base: u8,
    slave_interrupt_control_base: u8,
    linear_memory_selector: u16,
    stub_info_address: u32,
    psp_address: u32,
    run_mode: u16,
    run_mode_info: u16,
}

const STACK_ADDR: usize = 0xc0000000;
const STACK_SIZE: usize = 0x100000;

fn main() -> Result<()> {
    let input_path = std::env::args()
        .nth(1)
        .expect("Usage: alumini [executable]");

    let coff_bytes = std::fs::read(input_path)?;

    let (_, coff) = parse_coff::COFFFile::parse(&coff_bytes)
        .map_err(|e| anyhow!("Error parsing go32 COFF executable: {e}"))?;

    // Enough parsing - let's load this thing!
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

    // Map an extra area in to act as a stack
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

    unsafe {
        // WHAT ENVIRONMENT A GO32 PROGRAM STARTS TO:
        // EAX: some processed version of g_core?
        // EBX: _ScreenPrimary
        // ECX: ??
        // EDX: a pointer to prog_info
        // EDI: transfer buffer pointer
        // EBP: _ScreenSecondary
        // GS: a segment that's set to map linearly
        // arguments to _main on the stack

        // Let's run this thing!
        // Unwrap is safe here - if it doesn't have an optional header, it isn't an executable
        let fn_ptr: fn() = std::mem::transmute(coff.optional_header.unwrap().entry_address);

        let prog_info = ProgInfo {
            size: std::mem::size_of::<ProgInfo>() as u32,
            primary_screen_address: 0,
            secondary_screen_address: 0,
            transfer_buffer_address: 0,
            transfer_buffer_size: 0,
            pid: 42,
            master_interrupt_control_base: 0,
            slave_interrupt_control_base: 0,
            linear_memory_selector: 0,
            stub_info_address: 0,
            psp_address: 0,
            run_mode: 0,
            run_mode_info: 0,
        };

        let prog_ptr = &prog_info as *const ProgInfo;
        let prog_ptr = prog_ptr as *const u8;

        // https://stackoverflow.com/questions/5599400/where-linux-sets-its-kernel-and-user-space-segment-selector-values
        // we want GS to be __USER_DS (0x7b, or, (5 << 3) + 3)) to ensure it's mapped linearly, as go32 expects
        x86::segmentation::load_gs(SegmentSelector::new(5, x86::Ring::Ring3));

        let arg1 = &[b'C', b'C', b'1', b'P', b'S', b'X', 0]; // TODO: generate dynamically
        let arg2 = &[b'-', b'h', 0, 0, 0, 0, 0];

        let argv = &[arg1, arg2];

        asm!("mov ecx, 0", out("ecx") _);

        // Set EDX to a pointer to prog_info
        asm!("nop", in("edx") prog_ptr);

        // Setup the stack
        // WARNING: attempting to extensively use local variables past here will result in a bad time!
        // TODO: any way to avoid this?
        asm!("mov esp, 0xc0000000");

        // Arguments to _main
        asm!("push 0x41414141"); // ?
        asm!("push {}", in(reg) argv); // argv
        asm!("push 2"); // argc

        asm!("int3");
        asm!("jmp {}", in(reg) fn_ptr);
    }

    Ok(())
}
