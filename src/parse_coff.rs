use nom::{
    error::context,
    number::complete::{le_u16, le_u32}, bytes::complete::{tag, take}, multi::count,
};

use bitflags::bitflags;

pub type Input<'a> = &'a [u8];
pub type Result<'a, O> = nom::IResult<Input<'a>, O, nom::error::VerboseError<Input<'a>>>;

#[derive(Debug)]
pub struct COFFFile {
    header: COFFHeader,
    optional_header: Option<COFFOptionalHeader>,
    sections: Vec<COFFSection>,
}

impl COFFFile {
    pub fn parse(i: Input) -> Result<Self> {
        let (i, header) = COFFHeader::parse(i)?;

        let (i, optional_header) = if header.optional_header_size != 0 {
            let (i, oh) = COFFOptionalHeader::parse(i)?;
            (i, Some(oh))
        } else {
            (i, None)
        };

        let (i, sections) = count(COFFSection::parse, header.number_sections as usize)(i)?;

        // TODO: read symbols, line numbers, relocations, etc.

        Ok((i, Self { header, optional_header, sections }))
    }
}

#[derive(Debug)]
struct COFFHeader {
    number_sections: u16,
    creation_timestamp: u32,
    symbol_table_pointer: u32,
    number_symbols: u32,
    optional_header_size: u16,
    flags: u16,
}

impl COFFHeader {
    const DJGPP_MAGIC: &'static [u8] = &[0x4c, 0x01];

    pub fn parse(i: Input) -> Result<Self> {
        let (i, _) = context("Magic", tag(Self::DJGPP_MAGIC))(i)?;

        let (i, number_sections) = context("number_sections", le_u16)(i)?;
        let (i, creation_timestamp) = context("creation_timestamp", le_u32)(i)?;
        let (i, symbol_table_pointer) = context("symbol_table_pointer", le_u32)(i)?;
        let (i, number_symbols) = context("number_symbols", le_u32)(i)?;
        let (i, optional_header_size) = context("optional_header_size", le_u16)(i)?;
        let (i, flags) = context("flags", le_u16)(i)?;

        let ret = Self {
            number_sections,
            creation_timestamp,
            symbol_table_pointer,
            number_symbols,
            optional_header_size,
            flags,
        };

        Ok((i, ret))
    }
}

#[derive(Debug)]
struct COFFOptionalHeader {
    magic: u16,
    version_stamp: u16,
    text_size: u32,
    data_size: u32,
    bss_size: u32,
    entry_address: u32,
    text_start: u32,
    data_start: u32
}

impl COFFOptionalHeader {
    pub fn parse(i: Input) -> Result<Self> {
        let (i, magic) = context("magic", le_u16)(i)?;
        let (i, version_stamp) = context("version_stamp", le_u16)(i)?;
        let (i, text_size) = context("text_size", le_u32)(i)?;
        let (i, data_size) = context("data_size", le_u32)(i)?;
        let (i, bss_size) = context("bss_size", le_u32)(i)?;
        let (i, entry_address) = context("entry_address", le_u32)(i)?;
        let (i, text_start) = context("text_start", le_u32)(i)?;
        let (i, data_start) = context("data_start", le_u32)(i)?;
        

        let ret = Self {
            magic,
            version_stamp,
            text_size,
            data_size,
            bss_size,
            entry_address,
            text_start,
            data_start
        };

        Ok((i, ret))
    }
}

#[derive(Debug)]
struct COFFSection {
    header: COFFSectionHeader
}

impl COFFSection {
    pub fn parse(i: Input) -> Result<Self> {
        let (i, header) = COFFSectionHeader::parse(i)?;

        Ok((i, Self { header }))
    }
}

#[derive(Debug)]
struct COFFSectionHeader {
    section_name: [u8; 8],
    physical_address: u32,
    virtual_address: u32,
    size: u32,
    section_data_offset: u32,
    section_relocations_offset: u32,
    section_line_number_offset: u32,
    num_relocations: u16,
    num_line_number_entries: u16,
    flags: SectionTypeFlags
}

bitflags! {
    struct SectionTypeFlags: u32 {
        const TEXT = 0x0020;
        const DATA = 0x0040;
        const BSS = 0x0080;
    }
}

impl COFFSectionHeader {
    pub fn parse(i: Input) -> Result<Self> {
        let (i, section_name) = context("section_name", take(8u32))(i)?;
        let (i, physical_address) = context("physical_address", le_u32)(i)?;
        let (i, virtual_address) = context("virtual_address", le_u32)(i)?;
        let (i, size) = context("size", le_u32)(i)?;
        let (i, section_data_offset) = context("section_data_offset", le_u32)(i)?;
        let (i, section_relocations_offset) = context("section_relocations_offset", le_u32)(i)?;
        let (i, section_line_number_offset) = context("section_line_number_offset", le_u32)(i)?;
        let (i, num_line_number_entries) = context("num_line_number_entries", le_u16)(i)?;
        let (i, num_relocations) = context("num_relocations", le_u16)(i)?;
        let (i, flags) = context("flags", le_u32)(i)?;

        let ret = Self {
            section_name: section_name.try_into().unwrap(), // unwrapping here is safe - nom will have errored if we didn't get 8 bytes
            physical_address,
            virtual_address,
            size,
            section_data_offset,
            section_relocations_offset,
            section_line_number_offset,
            num_relocations,
            num_line_number_entries,
            flags: SectionTypeFlags::from_bits_truncate(flags)
        };

        Ok((i, ret))
    }
}