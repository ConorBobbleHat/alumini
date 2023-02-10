use nom::{
    bytes::complete::tag,
    error::context,
    multi::many0,
    number::complete::{le_i16, le_u16},
};

pub type Input<'a> = &'a [u8];
pub type Result<'a, O> = nom::IResult<Input<'a>, O, nom::error::VerboseError<Input<'a>>>;

// Taken from https://wiki.osdev.org/MZ and https://moddingwiki.shikadi.net/wiki/EXE_Format
#[derive(Debug)]
pub struct MZFile {
    pub header: MZFileHeader,
    pub relocations: Vec<MZRelocation>,
    pub code: Vec<u8>,
}

#[derive(Debug)]
pub struct MZFileHeader {
    pub extra_bytes: u16,
    pub pages: u16,
    pub relocation_items: u16,
    pub header_size: u16,
    pub min_allocation: u16,
    pub max_allocation: u16,
    pub initial_ss: i16,
    pub initial_sp: u16,
    pub checksum: u16,
    pub initial_ip: u16,
    pub initial_cs: i16,
    pub relocation_table_offset: u16,
    pub overlay: u16,
}

#[derive(Debug)]
pub struct MZRelocation {
    pub offset: u16,
    pub segment: u16,
}

impl MZFile {
    pub const MAGIC: &'static [u8] = &[0x4d, 0x5a]; // MZ

    pub fn parse(i: Input) -> Result<Self> {
        let full_input = i;

        let (i, _) = context("Magic", tag(Self::MAGIC))(i)?;

        // step 1: parse the header
        let (i, extra_bytes) = context("extra_bytes", le_u16)(i)?;
        let (i, pages) = context("pages", le_u16)(i)?;
        let (i, relocation_items) = context("relocation_items", le_u16)(i)?;
        let (i, header_size) = context("header_size", le_u16)(i)?;
        let (i, min_allocation) = context("min_allocation", le_u16)(i)?;
        let (i, max_allocation) = context("max_allocation", le_u16)(i)?;
        let (i, initial_ss) = context("initial_ss", le_i16)(i)?;
        let (i, initial_sp) = context("initial_sp", le_u16)(i)?;
        let (i, checksum) = context("checksum", le_u16)(i)?;
        let (i, initial_ip) = context("initial_ip", le_u16)(i)?;
        let (i, initial_cs) = context("initial_cs", le_i16)(i)?;
        let (i, relocation_table_offset) = context("relocation_table_offset", le_u16)(i)?;
        let (i, overlay) = context("overlay", le_u16)(i)?;

        let header = MZFileHeader {
            extra_bytes,
            pages,
            relocation_items,
            header_size,
            min_allocation,
            max_allocation,
            initial_ss,
            initial_sp,
            checksum,
            initial_ip,
            initial_cs,
            relocation_table_offset,
            overlay,
        };

        // step 2: parse relocations
        let relocation_table: &[u8] =
            &full_input[relocation_table_offset as usize..][..relocation_items as usize * 4];
        let (_, relocations) = many0(MZRelocation::parse)(relocation_table)?;

        // step 3: extract code
        let code = full_input[(header_size as usize) * 16..].to_vec();

        Ok((
            i,
            Self {
                header,
                relocations,
                code,
            },
        ))
    }
}

impl MZRelocation {
    pub fn parse(i: Input) -> Result<Self> {
        let (i, offset) = context("offset", le_u16)(i)?;
        let (i, segment) = context("segment", le_u16)(i)?;

        Ok((i, Self { offset, segment }))
    }
}
