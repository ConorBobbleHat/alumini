use anyhow::{anyhow, Result};

mod parse_coff;

fn main() -> Result<()> {
    let input_path = std::env::args()
        .nth(1)
        .expect("Usage: alumini [executable]");

    let input_bytes = std::fs::read(input_path)?;

    // map_err and formatting the returned error means we don't try and return a local
    let (_, coff) = parse_coff::COFFFile::parse(&input_bytes)
        .map_err(|e| anyhow!("Error parsing go32 COFF executable: {e}"))?;

    println!("{:#?}", coff);

    Ok(())
}
